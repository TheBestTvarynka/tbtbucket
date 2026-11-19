use std::fmt;
use std::str::FromStr;

/// An operation on Bitbucket, independent of whether it arrives over REST or Git.
///
/// See the Actions section of `docs/access-model.md` for the endpoints behind each action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Action {
    /// Every read: code, commits, tags, branches, pull requests and their comments.
    RepoRead,
    BranchCreate,
    BranchDelete,
    BranchPush,
    TagCreate,
    TagPush,
    TagDelete,
    PrCreate,
    PrUpdate,
    PrReview,
    PrMerge,
    PrDecline,
    PrReopen,
    PrDelete,
    PrCommentCreate,
    PrCommentUpdate,
    PrCommentDelete,
}

/// The branch attributes a request for an action carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BranchScope {
    /// No single branch is involved.
    None,
    /// The branch being created, deleted or pushed.
    Branch,
    /// The source and target branches of a pull request.
    PullRequest,
}

impl Action {
    pub(crate) const ALL: [Self; 17] = [
        Self::RepoRead,
        Self::BranchCreate,
        Self::BranchDelete,
        Self::BranchPush,
        Self::TagCreate,
        Self::TagPush,
        Self::TagDelete,
        Self::PrCreate,
        Self::PrUpdate,
        Self::PrReview,
        Self::PrMerge,
        Self::PrDecline,
        Self::PrReopen,
        Self::PrDelete,
        Self::PrCommentCreate,
        Self::PrCommentUpdate,
        Self::PrCommentDelete,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::RepoRead => "repo:read",
            Self::BranchCreate => "branch:create",
            Self::BranchDelete => "branch:delete",
            Self::BranchPush => "branch:push",
            Self::TagCreate => "tag:create",
            Self::TagPush => "tag:push",
            Self::TagDelete => "tag:delete",
            Self::PrCreate => "pr:create",
            Self::PrUpdate => "pr:update",
            Self::PrReview => "pr:review",
            Self::PrMerge => "pr:merge",
            Self::PrDecline => "pr:decline",
            Self::PrReopen => "pr:reopen",
            Self::PrDelete => "pr:delete",
            Self::PrCommentCreate => "pr_comment:create",
            Self::PrCommentUpdate => "pr_comment:update",
            Self::PrCommentDelete => "pr_comment:delete",
        }
    }

    /// The resource part of the name, before `:`.
    pub(crate) fn resource(self) -> &'static str {
        self.name().split_once(':').expect("every action name has a resource").0
    }

    pub(crate) fn branch_scope(self) -> BranchScope {
        match self {
            Self::BranchCreate | Self::BranchDelete | Self::BranchPush => BranchScope::Branch,
            Self::PrCreate
            | Self::PrUpdate
            | Self::PrReview
            | Self::PrMerge
            | Self::PrDecline
            | Self::PrReopen
            | Self::PrDelete
            | Self::PrCommentCreate
            | Self::PrCommentUpdate
            | Self::PrCommentDelete => BranchScope::PullRequest,
            Self::RepoRead | Self::TagCreate | Self::TagPush | Self::TagDelete => BranchScope::None,
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Action {
    type Err = UnknownAction;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|action| action.name() == name)
            .ok_or_else(|| UnknownAction(name.to_owned()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown action `{0}`")]
pub(crate) struct UnknownAction(pub(crate) String);

/// An action, or every action on one resource, such as `pr:*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActionPattern {
    Exact(Action),
    /// Every action whose [`Action::resource`] is the given one.
    Resource(&'static str),
}

impl ActionPattern {
    pub(crate) fn matches(self, action: Action) -> bool {
        match self {
            Self::Exact(expected) => expected == action,
            Self::Resource(resource) => action.resource() == resource,
        }
    }

    /// Every action the pattern covers.
    pub(crate) fn actions(self) -> impl Iterator<Item = Action> {
        Action::ALL.into_iter().filter(move |&action| self.matches(action))
    }
}

impl fmt::Display for ActionPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(action) => f.write_str(action.name()),
            Self::Resource(resource) => write!(f, "{resource}:*"),
        }
    }
}

impl FromStr for ActionPattern {
    type Err = UnknownAction;

    fn from_str(pattern: &str) -> Result<Self, Self::Err> {
        if let Some(resource) = pattern.strip_suffix(":*") {
            return Action::ALL
                .into_iter()
                .map(Action::resource)
                .find(|&known| known == resource)
                .map(Self::Resource)
                .ok_or_else(|| UnknownAction(pattern.to_owned()));
        }

        pattern.parse().map(Self::Exact)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for action in Action::ALL {
            assert_eq!(action.name().parse::<Action>().unwrap(), action);
            assert_eq!(action.to_string(), action.name());
        }
    }

    #[test]
    fn resource_wildcards_do_not_overlap() {
        let pr: ActionPattern = "pr:*".parse().unwrap();

        assert!(pr.matches(Action::PrMerge));
        assert!(!pr.matches(Action::PrCommentCreate));
        assert_eq!(pr.actions().count(), 7);
        assert_eq!("pr_comment:*".parse::<ActionPattern>().unwrap().actions().count(), 3);
        assert_eq!(pr.to_string(), "pr:*");
    }

    #[test]
    fn rejects_unknown_patterns() {
        for pattern in [
            "pr:approve",
            "pr:read",
            "branch:read",
            "pr",
            "*",
            "issue:*",
            "pr:**",
            "",
        ] {
            assert!(pattern.parse::<ActionPattern>().is_err(), "{pattern}");
        }
    }
}
