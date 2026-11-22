//! Decides whether a classified Bitbucket request is allowed, and with which Bitbucket token it is forwarded.

use std::sync::Arc;

use axum::http::{HeaderMap, Method};
use secret::Secret;
use tracing::debug;
use uuid::Uuid;

use crate::Result;
use crate::bitbucket::classify::{BranchSource, Classified};
use crate::bitbucket::client::BitbucketClient;
use crate::bitbucket::refs::{PullRequestBranches, PullRequestRefs, branch_name};
use crate::db::{AccessToken, BitbucketTokenDb};
use crate::policy::{Policy, Request, Rule};

/// The outcome of checking a request against an access token's policy.
pub(crate) enum Decision {
    Allow(Allowed),
    /// The reason is shown to the client.
    Deny(String),
}

pub(crate) struct Allowed {
    /// Index of the rule that allowed the request.
    pub(crate) rule: usize,
    pub(crate) bitbucket_token_id: Uuid,
    pub(crate) bitbucket_token: Secret<String>,
}

/// Branch attributes collected for one policy check.
#[derive(Default)]
struct Branches {
    branch: Option<String>,
    source: Option<String>,
    target: Option<String>,
}

pub(crate) struct ProxyService<D> {
    db: Arc<D>,
    client: BitbucketClient,
}

impl<D> ProxyService<D> {
    pub(crate) fn new(db: Arc<D>, client: BitbucketClient) -> Self {
        Self { db, client }
    }

    /// Forwards an allowed request to Bitbucket; see [`BitbucketClient::forward`].
    pub(crate) async fn forward(
        &self,
        method: Method,
        path_and_query: &str,
        headers: HeaderMap,
        body: reqwest::Body,
        bitbucket_token: &Secret<String>,
    ) -> std::result::Result<reqwest::Response, reqwest::Error> {
        self.client
            .forward(method, path_and_query, headers, body, bitbucket_token)
            .await
    }
}

impl<D: BitbucketTokenDb> ProxyService<D> {
    /// Checks the request against the token's policy.
    ///
    /// `body` must be present when the request's branches come from its body.
    pub(crate) async fn authorize(
        &self,
        token: &AccessToken,
        request: &Classified,
        body: Option<&[u8]>,
    ) -> Result<Decision> {
        let policy = &token.policy;
        let (project, repository) = (request.project.as_str(), request.repository.as_str());
        let body = body.unwrap_or_default();

        // Each entry is one set of branch attributes that must be allowed; a retargeted pull request needs two.
        let checks: Vec<Branches> = match request.branches {
            BranchSource::None => vec![Branches::default()],
            BranchSource::BodyBranchName => match branch_name(body) {
                Ok(branch) => vec![Branches {
                    branch: Some(branch),
                    ..Branches::default()
                }],
                Err(error) => return Ok(Decision::Deny(format!("request body is invalid: {error}"))),
            },
            BranchSource::BodyPullRequestRefs => {
                match PullRequestRefs::parse(body).and_then(|refs| refs.branches(project, repository)) {
                    Ok(branches) => vec![branches.into()],
                    Err(error) => return Ok(Decision::Deny(format!("request body is invalid: {error}"))),
                }
            }
            BranchSource::PullRequest(id) | BranchSource::PullRequestUpdate(id) => {
                let existing = match self.pull_request_branches(policy, request, id).await? {
                    Ok(branches) => branches,
                    Err(reason) => return Ok(Decision::Deny(reason)),
                };

                let new_target = if matches!(request.branches, BranchSource::PullRequestUpdate(_)) {
                    match PullRequestRefs::parse(body).and_then(|refs| refs.target(project, repository)) {
                        Ok(target) => target.filter(|target| *target != existing.target),
                        Err(error) => return Ok(Decision::Deny(format!("request body is invalid: {error}"))),
                    }
                } else {
                    None
                };

                match new_target {
                    // Moving a pull request needs permission for both its current and its new target.
                    Some(new_target) => vec![
                        Branches {
                            source: Some(existing.source.clone()),
                            target: Some(new_target),
                            branch: None,
                        },
                        existing.into(),
                    ],
                    None => vec![existing.into()],
                }
            }
        };

        let mut allowed_by = None;
        for branches in &checks {
            let check = Request {
                action: request.action,
                project,
                repository,
                branch: branches.branch.as_deref(),
                source: branches.source.as_deref(),
                target: branches.target.as_deref(),
            };

            match policy.matching_rule(&check) {
                Some((idx, rule)) => {
                    allowed_by.get_or_insert((idx, rule.bitbucket_token()));
                }
                None => return Ok(Decision::Deny(denial(&check))),
            }
        }

        let (rule, bitbucket_token_id) = allowed_by.expect("there is at least one check");
        self.allow(rule, bitbucket_token_id).await
    }

    /// Allows a request that the rule at index `rule` matched, with that rule's Bitbucket token.
    pub(crate) async fn allow_with_rule(&self, rule: usize, matched: &Rule) -> Result<Decision> {
        self.allow(rule, matched.bitbucket_token()).await
    }

    async fn allow(&self, rule: usize, bitbucket_token_id: Uuid) -> Result<Decision> {
        let Some(bitbucket_token) = self.db.bitbucket_token(bitbucket_token_id).await? else {
            return Ok(Decision::Deny(
                "the Bitbucket token of the matching rule no longer exists".to_owned(),
            ));
        };

        Ok(Decision::Allow(Allowed {
            rule,
            bitbucket_token_id,
            bitbucket_token: bitbucket_token.token,
        }))
    }

    /// Looks up the branches of an existing pull request with the Bitbucket token of the first rule that could allow
    /// the request.
    async fn pull_request_branches(
        &self,
        policy: &Policy,
        request: &Classified,
        id: u64,
    ) -> Result<std::result::Result<PullRequestBranches, String>> {
        let (project, repository) = (request.project.as_str(), request.repository.as_str());

        let Some((_, rule)) = policy.candidate_rules(request.action, project, repository).next() else {
            return Ok(Err(format!(
                "access token does not allow {} on {project}/{repository}",
                request.action
            )));
        };

        let Some(bitbucket_token) = self.db.bitbucket_token(rule.bitbucket_token()).await? else {
            return Ok(Err(
                "the Bitbucket token of the matching rule no longer exists".to_owned()
            ));
        };

        let body = match self
            .client
            .pull_request(&bitbucket_token.token, project, repository, id)
            .await
        {
            Ok(body) => body,
            Err(error) => {
                debug!(%error, pull_request = id, "Pull request lookup failed");
                return Ok(Err(format!("pull request {id} could not be looked up")));
            }
        };

        Ok(PullRequestRefs::parse(&body)
            .and_then(|refs| refs.branches(project, repository))
            .map_err(|error| format!("pull request {id} cannot be checked: {error}")))
    }
}

impl From<PullRequestBranches> for Branches {
    fn from(branches: PullRequestBranches) -> Self {
        Self {
            branch: None,
            source: Some(branches.source),
            target: Some(branches.target),
        }
    }
}

fn denial(check: &Request<'_>) -> String {
    let mut reason = format!(
        "access token does not allow {} on {}/{}",
        check.action, check.project, check.repository
    );

    if let Some(branch) = check.branch {
        reason.push_str(&format!(" for branch {branch}"));
    }
    if let (Some(source), Some(target)) = (check.source, check.target) {
        reason.push_str(&format!(" from {source} to {target}"));
    }

    reason
}
