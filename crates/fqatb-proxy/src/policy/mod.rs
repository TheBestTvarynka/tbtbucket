//! Allow-only permissions of access tokens.
//!
//! A [`Policy`] is a list of [`Rule`]s.
//! A request is allowed when at least one rule matches it, and the first matching rule decides which Bitbucket token forwards it.
//! A rule's branch conditions only limit the actions they can apply to: `branch` limits branch actions, and `source` and
//! `target` limit pull request and comment actions.
//! The document format and its semantics are described in `docs/access-model.md`.

mod action;
mod pattern;

use std::collections::BTreeSet;

pub(crate) use action::{Action, ActionPattern, BranchScope, UnknownAction};
pub(crate) use pattern::{BranchPattern, InvalidPattern, ProjectPattern, RepositoryPattern};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The only policy format version.
const VERSION: u32 = 1;

/// A validated policy with compiled patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "PolicySpec", into = "PolicySpec")]
pub(crate) struct Policy {
    rules: Vec<Rule>,
}

/// One grant: a set of actions on a set of repositories, optionally limited to branch patterns.
#[derive(Debug, Clone)]
pub(crate) struct Rule {
    bitbucket_token: Uuid,
    actions: Vec<ActionPattern>,
    project: ProjectPattern,
    repository: RepositoryPattern,
    branches: BranchConditions,
}

/// Branch conditions of a rule; every present condition that applies to the request's action must hold.
#[derive(Debug, Clone, Default)]
pub(crate) struct BranchConditions {
    pub(crate) branch: Option<Vec<BranchPattern>>,
    pub(crate) source: Option<Vec<BranchPattern>>,
    pub(crate) target: Option<Vec<BranchPattern>>,
}

/// What a request does, as far as rules are concerned.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Request<'a> {
    pub(crate) action: Action,
    pub(crate) project: &'a str,
    pub(crate) repository: &'a str,
    /// The branch being created, deleted or pushed.
    pub(crate) branch: Option<&'a str>,
    /// The source branch of the pull request.
    pub(crate) source: Option<&'a str>,
    /// The target branch of the pull request.
    pub(crate) target: Option<&'a str>,
}

impl Policy {
    pub(crate) fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Returns the first rule that allows the request, with its index.
    pub(crate) fn matching_rule(&self, request: &Request<'_>) -> Option<(usize, &Rule)> {
        self.candidate_rules(request.action, request.project, request.repository)
            .find(|(_, rule)| rule.branches.are_satisfied_by(request))
    }

    /// Returns the rules that cover the action on the repository, ignoring their branch conditions.
    ///
    /// The first one decides which Bitbucket token looks up data the branch conditions need.
    pub(crate) fn candidate_rules<'s, 'r>(
        &'s self,
        action: Action,
        project: &'r str,
        repository: &'r str,
    ) -> impl Iterator<Item = (usize, &'s Rule)> + use<'s, 'r> {
        self.rules
            .iter()
            .enumerate()
            .filter(move |(_, rule)| rule.covers(action, project, repository))
    }

    /// Returns the first rule that allows every branch change of a Git push, with its index.
    ///
    /// Each change is an action and the branch it applies to; the rule must allow it together with `branch:git` on
    /// that branch.
    pub(crate) fn git_push_rule(
        &self,
        project: &str,
        repository: &str,
        changes: &[(Action, &str)],
    ) -> Option<(usize, &Rule)> {
        self.git_push_candidates(project, repository).find(|(_, rule)| {
            changes
                .iter()
                .all(|&(action, branch)| rule.allows_git_change(action, project, repository, branch))
        })
    }

    /// Returns the rules that let Git pushes reach the repository at all, ignoring their branch conditions.
    pub(crate) fn git_push_candidates<'s, 'r>(
        &'s self,
        project: &'r str,
        repository: &'r str,
    ) -> impl Iterator<Item = (usize, &'s Rule)> + use<'s, 'r> {
        self.candidate_rules(Action::BranchGit, project, repository)
    }

    /// Returns the first rule that covers any of the actions on the repository, ignoring its branch conditions.
    pub(crate) fn first_rule_covering(
        &self,
        actions: &[Action],
        project: &str,
        repository: &str,
    ) -> Option<(usize, &Rule)> {
        self.rules
            .iter()
            .enumerate()
            .find(|(_, rule)| actions.iter().any(|&action| rule.covers(action, project, repository)))
    }

    /// Returns the IDs of every Bitbucket token the rules use.
    pub(crate) fn bitbucket_tokens(&self) -> BTreeSet<Uuid> {
        self.rules.iter().map(|rule| rule.bitbucket_token).collect()
    }
}

impl Rule {
    pub(crate) fn bitbucket_token(&self) -> Uuid {
        self.bitbucket_token
    }

    /// Whether the rule allows a Git push to change `branch` with `action`: it needs both the action and
    /// `branch:git`, each with its branch conditions satisfied.
    pub(crate) fn allows_git_change(&self, action: Action, project: &str, repository: &str, branch: &str) -> bool {
        [action, Action::BranchGit].into_iter().all(|action| {
            let request = Request {
                action,
                project,
                repository,
                branch: Some(branch),
                source: None,
                target: None,
            };
            self.covers(action, project, repository) && self.branches.are_satisfied_by(&request)
        })
    }

    fn covers(&self, action: Action, project: &str, repository: &str) -> bool {
        self.actions.iter().any(|pattern| pattern.matches(action))
            && self.project.matches(project)
            && self.repository.matches(repository)
    }
}

impl BranchConditions {
    /// Checks the conditions that apply to the request's action; the others do not limit it.
    ///
    /// A condition that applies fails when the request does not carry the branch it constrains.
    fn are_satisfied_by(&self, request: &Request<'_>) -> bool {
        return match request.action.branch_scope() {
            BranchScope::None => true,
            BranchScope::Branch => satisfied(self.branch.as_deref(), request.branch),
            BranchScope::PullRequest => {
                satisfied(self.source.as_deref(), request.source) && satisfied(self.target.as_deref(), request.target)
            }
        };

        fn satisfied(condition: Option<&[BranchPattern]>, branch: Option<&str>) -> bool {
            match (condition, branch) {
                (None, _) => true,
                (Some(_), None) => false,
                (Some(patterns), Some(branch)) => patterns.iter().any(|pattern| pattern.matches(branch)),
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.branch.is_none() && self.source.is_none() && self.target.is_none()
    }
}

/// Why a policy document was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PolicyError {
    #[error("unsupported policy version {0}")]
    UnsupportedVersion(u32),

    #[error("policy has no rules")]
    NoRules,

    /// `rule` is 1-based, as shown to people.
    #[error("rule {rule} is invalid")]
    Rule {
        rule: usize,
        #[source]
        error: RuleError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RuleError {
    #[error("rule has no actions")]
    NoActions,

    #[error(transparent)]
    UnknownAction(#[from] UnknownAction),

    #[error("invalid project pattern")]
    Project(#[source] InvalidPattern),

    #[error("invalid repository pattern")]
    Repository(#[source] InvalidPattern),

    #[error("invalid `{condition}` branch pattern")]
    Branch {
        condition: &'static str,
        #[source]
        error: InvalidPattern,
    },

    #[error("`{0}` branch condition has no patterns")]
    EmptyBranchCondition(&'static str),

    /// The condition would have no effect, which is almost certainly not what was meant.
    #[error("`{0}` branch condition applies to none of the rule's actions")]
    ConditionWithoutActions(&'static str),
}

/// The serialized form of a [`Policy`], before validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicySpec {
    pub(crate) version: u32,
    pub(crate) rules: Vec<RuleSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleSpec {
    pub(crate) bitbucket_token: Uuid,
    pub(crate) actions: Vec<String>,
    pub(crate) project: String,
    pub(crate) repository: String,
    #[serde(default, skip_serializing_if = "BranchSpec::is_empty")]
    pub(crate) branches: BranchSpec,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BranchSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) branch: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) source: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) target: Option<Vec<String>>,
}

impl PolicySpec {
    pub(crate) fn new(rules: Vec<RuleSpec>) -> Self {
        Self {
            version: VERSION,
            rules,
        }
    }
}

impl BranchSpec {
    fn is_empty(&self) -> bool {
        self.branch.is_none() && self.source.is_none() && self.target.is_none()
    }
}

impl TryFrom<PolicySpec> for Policy {
    type Error = PolicyError;

    fn try_from(spec: PolicySpec) -> Result<Self, Self::Error> {
        if spec.version != VERSION {
            return Err(PolicyError::UnsupportedVersion(spec.version));
        }

        if spec.rules.is_empty() {
            return Err(PolicyError::NoRules);
        }

        let rules = spec
            .rules
            .into_iter()
            .enumerate()
            .map(|(idx, rule)| Rule::try_from(rule).map_err(|error| PolicyError::Rule { rule: idx + 1, error }))
            .collect::<Result<_, _>>()?;

        Ok(Self { rules })
    }
}

impl TryFrom<RuleSpec> for Rule {
    type Error = RuleError;

    fn try_from(spec: RuleSpec) -> Result<Self, Self::Error> {
        if spec.actions.is_empty() {
            return Err(RuleError::NoActions);
        }

        let actions = spec
            .actions
            .iter()
            .map(|action| action.parse())
            .collect::<Result<Vec<ActionPattern>, _>>()?;

        let project = ProjectPattern::new(&spec.project).map_err(RuleError::Project)?;
        let repository = RepositoryPattern::new(&spec.repository).map_err(RuleError::Repository)?;

        let branches = BranchConditions {
            branch: compile_condition("branch", spec.branches.branch)?,
            source: compile_condition("source", spec.branches.source)?,
            target: compile_condition("target", spec.branches.target)?,
        };

        let conditions = [
            ("branch", branches.branch.is_some(), BranchScope::Branch),
            ("source", branches.source.is_some(), BranchScope::PullRequest),
            ("target", branches.target.is_some(), BranchScope::PullRequest),
        ];
        for (condition, present, scope) in conditions {
            let applies = actions
                .iter()
                .flat_map(|pattern| pattern.actions())
                .any(|action| action.branch_scope() == scope);

            if present && !applies {
                return Err(RuleError::ConditionWithoutActions(condition));
            }
        }

        return Ok(Self {
            bitbucket_token: spec.bitbucket_token,
            actions,
            project,
            repository,
            branches,
        });

        fn compile_condition(
            condition: &'static str,
            patterns: Option<Vec<String>>,
        ) -> Result<Option<Vec<BranchPattern>>, RuleError> {
            let Some(patterns) = patterns else {
                return Ok(None);
            };

            if patterns.is_empty() {
                return Err(RuleError::EmptyBranchCondition(condition));
            }

            patterns
                .iter()
                .map(|pattern| BranchPattern::new(pattern).map_err(|error| RuleError::Branch { condition, error }))
                .collect::<Result<_, _>>()
                .map(Some)
        }
    }
}

impl From<Policy> for PolicySpec {
    fn from(policy: Policy) -> Self {
        Self::new(policy.rules.into_iter().map(RuleSpec::from).collect())
    }
}

impl From<Rule> for RuleSpec {
    fn from(rule: Rule) -> Self {
        let patterns = |patterns: Option<Vec<BranchPattern>>| {
            patterns.map(|patterns| patterns.iter().map(|pattern| pattern.as_str().to_owned()).collect())
        };

        Self {
            bitbucket_token: rule.bitbucket_token,
            actions: rule.actions.iter().map(ActionPattern::to_string).collect(),
            project: rule.project.as_str().to_owned(),
            repository: rule.repository.as_str().to_owned(),
            branches: if rule.branches.is_empty() {
                BranchSpec::default()
            } else {
                BranchSpec {
                    branch: patterns(rule.branches.branch),
                    source: patterns(rule.branches.source),
                    target: patterns(rule.branches.target),
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const PR_TOKEN: Uuid = Uuid::from_u128(1);
    const READ_TOKEN: Uuid = Uuid::from_u128(2);

    fn policy(value: serde_json::Value) -> Policy {
        serde_json::from_value(value).unwrap()
    }

    fn rejection(value: serde_json::Value) -> PolicyError {
        let spec: PolicySpec = serde_json::from_value(value).unwrap();
        Policy::try_from(spec).unwrap_err()
    }

    fn request(action: Action) -> Request<'static> {
        Request {
            action,
            project: "PROJ",
            repository: "api",
            branch: None,
            source: None,
            target: None,
        }
    }

    /// Returns the Bitbucket token of the matching rule, if any.
    fn decide(policy: &Policy, request: Request<'_>) -> Option<Uuid> {
        policy.matching_rule(&request).map(|(_, rule)| rule.bitbucket_token())
    }

    #[test]
    fn default_deny() {
        let policy = policy(json!({ "version": 1, "rules": [
            { "bitbucket_token": PR_TOKEN, "actions": ["repo:read"], "project": "PROJ", "repository": "api" }
        ] }));

        assert_eq!(decide(&policy, request(Action::RepoRead)), Some(PR_TOKEN));
        assert_eq!(decide(&policy, request(Action::PrMerge)), None);
        assert_eq!(
            decide(
                &policy,
                Request {
                    project: "OTHER",
                    ..request(Action::RepoRead)
                }
            ),
            None
        );
        assert_eq!(
            decide(
                &policy,
                Request {
                    repository: "web",
                    ..request(Action::RepoRead)
                }
            ),
            None
        );
    }

    #[test]
    fn create_and_edit_from_feature_branches() {
        // Reading and branch-limited writing share one rule: the source condition only limits the pull request actions.
        let policy = policy(json!({ "version": 1, "rules": [
            { "bitbucket_token": PR_TOKEN, "actions": ["repo:read", "pr:create", "pr:update"], "project": "PROJ", "repository": "api",
              "branches": { "source": ["feature/**"] } }
        ] }));
        let from = |source| Request {
            source: Some(source),
            target: Some("main"),
            ..request(Action::PrCreate)
        };

        assert!(decide(&policy, from("feature/login")).is_some());
        assert!(decide(&policy, from("feature/a/b")).is_some());
        assert!(decide(&policy, from("bugfix/login")).is_none());
        assert!(
            decide(
                &policy,
                Request {
                    action: Action::PrUpdate,
                    ..from("feature/x")
                }
            )
            .is_some()
        );
        assert!(
            decide(
                &policy,
                Request {
                    action: Action::PrMerge,
                    ..from("feature/x")
                }
            )
            .is_none()
        );
        assert!(decide(&policy, request(Action::RepoRead)).is_some());
    }

    #[test]
    fn missing_branch_fails_the_condition() {
        let policy = policy(json!({ "version": 1, "rules": [
            { "bitbucket_token": PR_TOKEN, "actions": ["pr:create"], "project": "PROJ", "repository": "api",
              "branches": { "target": ["main"] } }
        ] }));

        assert!(decide(&policy, request(Action::PrCreate)).is_none());
        assert!(
            decide(
                &policy,
                Request {
                    target: Some("main"),
                    ..request(Action::PrCreate)
                }
            )
            .is_some()
        );
    }

    #[test]
    fn all_conditions_must_hold() {
        let policy = policy(json!({ "version": 1, "rules": [
            { "bitbucket_token": PR_TOKEN, "actions": ["pr:merge"], "project": "PROJ", "repository": "api",
              "branches": { "source": ["release/*"], "target": ["main", "develop"] } }
        ] }));
        let merge = |source, target| Request {
            source: Some(source),
            target: Some(target),
            ..request(Action::PrMerge)
        };

        assert!(decide(&policy, merge("release/1.0", "main")).is_some());
        assert!(decide(&policy, merge("release/1.0", "develop")).is_some());
        assert!(decide(&policy, merge("release/1.0", "staging")).is_none());
        assert!(decide(&policy, merge("release/1.0/hotfix", "main")).is_none());
    }

    #[test]
    fn wildcards_and_project_globs() {
        let policy = policy(json!({ "version": 1, "rules": [
            { "bitbucket_token": PR_TOKEN, "actions": ["pr:*", "pr_comment:*"], "project": "PROJ", "repository": "*" }
        ] }));

        assert!(
            decide(
                &policy,
                Request {
                    repository: "web",
                    ..request(Action::PrMerge)
                }
            )
            .is_some()
        );
        assert!(decide(&policy, request(Action::PrCommentDelete)).is_some());
        assert!(
            decide(
                &policy,
                Request {
                    project: "proj",
                    ..request(Action::PrMerge)
                }
            )
            .is_some()
        );
        assert!(decide(&policy, request(Action::RepoRead)).is_none());
        assert!(decide(&policy, request(Action::BranchCreate)).is_none());
    }

    #[test]
    fn first_matching_rule_chooses_the_bitbucket_token() {
        let policy = policy(json!({ "version": 1, "rules": [
            { "bitbucket_token": READ_TOKEN, "actions": ["repo:read"], "project": "PROJ", "repository": "docs" },
            { "bitbucket_token": PR_TOKEN, "actions": ["repo:read", "pr:create"], "project": "PROJ", "repository": "*" }
        ] }));

        assert_eq!(
            decide(
                &policy,
                Request {
                    repository: "docs",
                    ..request(Action::RepoRead)
                }
            ),
            Some(READ_TOKEN)
        );
        assert_eq!(decide(&policy, request(Action::RepoRead)), Some(PR_TOKEN));
        assert_eq!(
            policy
                .matching_rule(&Request {
                    repository: "docs",
                    ..request(Action::RepoRead)
                })
                .map(|(idx, _)| idx),
            Some(0)
        );
        assert_eq!(policy.bitbucket_tokens(), BTreeSet::from([PR_TOKEN, READ_TOKEN]));
    }

    #[test]
    fn candidates_ignore_branch_conditions() {
        let policy = policy(json!({ "version": 1, "rules": [
            { "bitbucket_token": READ_TOKEN, "actions": ["pr:merge"], "project": "PROJ", "repository": "api",
              "branches": { "target": ["main"] } },
            { "bitbucket_token": PR_TOKEN, "actions": ["pr:merge"], "project": "PROJ", "repository": "api",
              "branches": { "target": ["develop"] } }
        ] }));

        let candidates: Vec<_> = policy
            .candidate_rules(Action::PrMerge, "PROJ", "api")
            .map(|(_, rule)| rule.bitbucket_token())
            .collect();
        assert_eq!(candidates, [READ_TOKEN, PR_TOKEN]);
        assert_eq!(
            decide(
                &policy,
                Request {
                    target: Some("develop"),
                    ..request(Action::PrMerge)
                }
            ),
            Some(PR_TOKEN)
        );
    }

    #[test]
    fn branch_condition_for_branch_actions() {
        let policy = policy(json!({ "version": 1, "rules": [
            { "bitbucket_token": PR_TOKEN, "actions": ["branch:create", "branch:git"], "project": "PROJ", "repository": "api",
              "branches": { "branch": ["bot/**"] } }
        ] }));

        assert!(
            decide(
                &policy,
                Request {
                    branch: Some("bot/update-deps"),
                    ..request(Action::BranchCreate)
                }
            )
            .is_some()
        );
        assert!(
            decide(
                &policy,
                Request {
                    branch: Some("main"),
                    ..request(Action::BranchGit)
                }
            )
            .is_none()
        );
        assert!(
            decide(
                &policy,
                Request {
                    branch: Some("bot/x"),
                    ..request(Action::BranchDelete)
                }
            )
            .is_none()
        );
    }

    #[test]
    fn round_trips_through_json() {
        let document = json!({ "version": 1, "rules": [
            { "bitbucket_token": PR_TOKEN, "actions": ["pr:*", "repo:read"], "project": "PROJ", "repository": "api-*" },
            { "bitbucket_token": READ_TOKEN, "actions": ["pr:create"], "project": "*", "repository": "web",
              "branches": { "source": ["feature/**"], "target": ["main"] } }
        ] });

        assert_eq!(serde_json::to_value(policy(document.clone())).unwrap(), document);
    }

    #[test]
    fn rejects_invalid_documents() {
        let rule = |extra: serde_json::Value| {
            let mut rule = json!({ "bitbucket_token": PR_TOKEN, "actions": ["pr:create"], "project": "PROJ", "repository": "api" });
            rule.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            json!({ "version": 1, "rules": [rule] })
        };
        let rule_error = |error: PolicyError| match error {
            PolicyError::Rule { rule: 1, error } => error,
            other => panic!("expected an error in rule 1, got {other:?}"),
        };

        assert_eq!(
            rejection(json!({ "version": 2, "rules": [] })),
            PolicyError::UnsupportedVersion(2)
        );
        assert_eq!(rejection(json!({ "version": 1, "rules": [] })), PolicyError::NoRules);
        assert_eq!(
            rule_error(rejection(rule(json!({ "actions": [] })))),
            RuleError::NoActions
        );
        assert!(matches!(
            rule_error(rejection(rule(json!({ "actions": ["pr:approve"] })))),
            RuleError::UnknownAction(_)
        ));
        assert!(matches!(
            rule_error(rejection(rule(json!({ "project": "" })))),
            RuleError::Project(_)
        ));
        assert!(matches!(
            rule_error(rejection(rule(json!({ "project": "~alice" })))),
            RuleError::Project(InvalidPattern::PersonalProject(_))
        ));
        assert!(matches!(
            rule_error(rejection(rule(json!({ "repository": "a[" })))),
            RuleError::Repository(_)
        ));
        assert_eq!(
            rule_error(rejection(rule(json!({ "branches": { "source": [] } })))),
            RuleError::EmptyBranchCondition("source")
        );
        assert!(matches!(
            rule_error(rejection(rule(json!({ "branches": { "source": ["feature/["] } })))),
            RuleError::Branch {
                condition: "source",
                ..
            }
        ));
    }

    /// The rule from the admin panel: read everything, and work on pull requests only between matching branches.
    #[test]
    fn conditions_limit_only_their_actions() {
        let policy = policy(json!({ "version": 1, "rules": [
            { "bitbucket_token": PR_TOKEN,
              "actions": ["repo:read", "branch:create", "branch:delete", "pr:*", "pr_comment:create", "pr_comment:update"],
              "project": "WKN", "repository": "ironrdp",
              "branches": { "source": ["worktree/*"], "target": ["master", "worktree-*"] } }
        ] }));
        let on = |action| Request {
            project: "WKN",
            repository: "ironrdp",
            ..request(action)
        };
        let pull_request = |action, source, target| Request {
            source: Some(source),
            target: Some(target),
            ..on(action)
        };

        assert!(decide(&policy, on(Action::RepoRead)).is_some());
        assert!(decide(&policy, pull_request(Action::PrCreate, "worktree/rdp", "master")).is_some());
        assert!(decide(&policy, pull_request(Action::PrMerge, "worktree/rdp", "worktree-next")).is_some());
        assert!(decide(&policy, pull_request(Action::PrCommentCreate, "worktree/rdp", "master")).is_some());
        assert!(decide(&policy, pull_request(Action::PrMerge, "feature/x", "master")).is_none());
        assert!(decide(&policy, pull_request(Action::PrCreate, "worktree/rdp", "release")).is_none());
        assert!(decide(&policy, pull_request(Action::PrCommentDelete, "worktree/rdp", "master")).is_none());

        // Without a `branch` condition, branch actions are not limited by the pull request conditions.
        let branch = |action, branch| Request {
            branch: Some(branch),
            ..on(action)
        };
        assert!(decide(&policy, branch(Action::BranchCreate, "anything")).is_some());
        assert!(decide(&policy, branch(Action::BranchGit, "anything")).is_none());
    }

    #[test]
    fn rejects_conditions_without_actions() {
        let with = |actions: serde_json::Value, branches: serde_json::Value| {
            let spec: PolicySpec = serde_json::from_value(json!({ "version": 1, "rules": [
                { "bitbucket_token": PR_TOKEN, "actions": actions, "project": "PROJ", "repository": "api", "branches": branches }
            ] }))
            .unwrap();
            Policy::try_from(spec)
        };
        let error = |result: Result<Policy, PolicyError>| match result {
            Err(PolicyError::Rule { error, .. }) => error,
            other => panic!("expected a rule error, got {other:?}"),
        };

        assert_eq!(
            error(with(json!(["repo:read"]), json!({ "source": ["feature/**"] }))),
            RuleError::ConditionWithoutActions("source")
        );
        assert_eq!(
            error(with(json!(["pr:create", "repo:read"]), json!({ "branch": ["bot/**"] }))),
            RuleError::ConditionWithoutActions("branch")
        );
        assert_eq!(
            error(with(
                json!(["branch:create"]),
                json!({ "branch": ["bot/**"], "target": ["main"] })
            )),
            RuleError::ConditionWithoutActions("target")
        );
        assert!(with(json!(["repo:read", "branch:delete"]), json!({ "branch": ["bot/**"] })).is_ok());
        assert!(
            with(
                json!(["pr_comment:*"]),
                json!({ "source": ["feature/**"], "target": ["main"] })
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_unknown_fields() {
        let result: Result<Policy, _> = serde_json::from_value(json!({ "version": 1, "rules": [
            { "bitbucket_token": PR_TOKEN, "actions": ["repo:read"], "project": "PROJ", "repository": "api", "effect": "deny" }
        ] }));

        assert!(result.is_err());
    }

    #[test]
    fn git_pushes_need_branch_git_and_the_branch_action() {
        const BOT_TOKEN: Uuid = Uuid::from_u128(3);
        let policy = policy(json!({ "version": 1, "rules": [
            { "bitbucket_token": READ_TOKEN, "actions": ["repo:read", "branch:create"], "project": "PROJ", "repository": "api" },
            { "bitbucket_token": BOT_TOKEN, "actions": ["branch:create", "branch:git"], "project": "PROJ", "repository": "api",
              "branches": { "branch": ["bot/**"] } },
            { "bitbucket_token": PR_TOKEN, "actions": ["branch:*"], "project": "PROJ", "repository": "api",
              "branches": { "branch": ["release/*"] } }
        ] }));
        let push = |changes: &[(Action, &str)]| {
            policy
                .git_push_rule("PROJ", "api", changes)
                .map(|(_, rule)| rule.bitbucket_token())
        };

        // Rule 1 has no branch:git, so it allows no Git push even though it allows creating any branch.
        assert_eq!(push(&[(Action::BranchCreate, "bot/deps")]), Some(BOT_TOKEN));
        assert_eq!(push(&[(Action::BranchCreate, "main")]), None);

        // branch:* includes branch:git.
        assert_eq!(push(&[(Action::BranchDelete, "release/1")]), Some(PR_TOKEN));
        // Rule 2 cannot delete.
        assert_eq!(push(&[(Action::BranchDelete, "bot/deps")]), None);

        // Every change must be allowed by one rule, and the first such rule wins.
        assert_eq!(
            push(&[(Action::BranchCreate, "bot/a"), (Action::BranchCreate, "bot/b")]),
            Some(BOT_TOKEN)
        );
        assert_eq!(
            push(&[(Action::BranchCreate, "bot/a"), (Action::BranchCreate, "release/1")]),
            None
        );

        assert!(
            policy
                .git_push_rule("PROJ", "web", &[(Action::BranchCreate, "bot/a")])
                .is_none()
        );
        assert_eq!(
            policy
                .git_push_candidates("PROJ", "api")
                .map(|(idx, _)| idx)
                .collect::<Vec<_>>(),
            [1, 2]
        );
    }

    #[test]
    fn first_rule_covering_ignores_branch_conditions() {
        let policy = policy(json!({ "version": 1, "rules": [
            { "bitbucket_token": PR_TOKEN, "actions": ["pr:create"], "project": "PROJ", "repository": "api" },
            { "bitbucket_token": READ_TOKEN, "actions": ["branch:create", "branch:git"], "project": "PROJ", "repository": "api",
              "branches": { "branch": ["bot/**"] } }
        ] }));

        let first = |actions: &[Action]| policy.first_rule_covering(actions, "PROJ", "api").map(|(idx, _)| idx);
        assert_eq!(first(&[Action::RepoRead, Action::BranchGit]), Some(1));
        assert_eq!(first(&[Action::RepoRead]), None);
    }
}
