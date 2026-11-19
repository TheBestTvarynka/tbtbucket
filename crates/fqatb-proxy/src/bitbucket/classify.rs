//! Maps Bitbucket Data Center REST requests to actions.
//!
//! The endpoint table follows the Actions section of `docs/access-model.md`, checked against `10.2.swagger.v3.json`.
//! Anything not listed is unsupported, and therefore denied.

use axum::http::Method;
use percent_encoding::percent_decode_str;

use crate::policy::Action;

/// A request the proxy knows how to check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Classified {
    pub(crate) action: Action,
    pub(crate) project: String,
    pub(crate) repository: String,
    pub(crate) branches: BranchSource,
}

/// Where the branch attributes of a request come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BranchSource {
    /// The request carries no branch attributes.
    None,
    /// The `name` field of the JSON body, for branch creation and deletion.
    BodyBranchName,
    /// The `fromRef` and `toRef` fields of the JSON body, for a new pull request.
    BodyPullRequestRefs,
    /// The source and target branches of an existing pull request.
    PullRequest(u64),
    /// An existing pull request, whose target branch the JSON body may change.
    PullRequestUpdate(u64),
}

/// Why a request cannot be checked, and is therefore denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Unsupported {
    #[error("path is malformed")]
    MalformedPath,

    #[error("Git over HTTPS is not supported yet")]
    Git,

    #[error("personal repositories are not supported yet")]
    PersonalRepository,

    #[error("endpoint is not supported")]
    Endpoint,
}

#[cfg(test)]
impl BranchSource {
    /// The branch scope of the actions this source serves.
    pub(crate) fn scope(self) -> crate::policy::BranchScope {
        use crate::policy::BranchScope;

        match self {
            Self::None => BranchScope::None,
            Self::BodyBranchName => BranchScope::Branch,
            Self::BodyPullRequestRefs | Self::PullRequest(_) | Self::PullRequestUpdate(_) => BranchScope::PullRequest,
        }
    }
}

/// Classifies a request by method and raw, still percent-encoded, path.
pub(crate) fn classify(method: &Method, raw_path: &str) -> Result<Classified, Unsupported> {
    let segments = normalize(raw_path)?;
    let segments: Vec<&str> = segments.iter().map(String::as_str).collect();

    match segments.as_slice() {
        ["scm", ..] => Err(Unsupported::Git),
        [
            "rest",
            plugin @ ("api" | "branch-utils" | "comment-likes" | "jira" | "insights"),
            "1.0" | "latest",
            "projects",
            project,
            "repos",
            repository,
            tail @ ..,
        ] => {
            if project.starts_with('~') {
                return Err(Unsupported::PersonalRepository);
            }

            let (action, branches) = match *plugin {
                "api" => classify_api(method, tail),
                "branch-utils" => classify_branch_utils(method, tail),
                "comment-likes" => classify_comment_likes(method, tail),
                "jira" => classify_jira(method, tail),
                _ => classify_insights(method, tail),
            }
            .ok_or(Unsupported::Endpoint)?;

            Ok(Classified {
                action,
                project: (*project).to_owned(),
                repository: (*repository).to_owned(),
                branches,
            })
        }
        _ => Err(Unsupported::Endpoint),
    }
}

/// Splits the path into decoded segments, rejecting anything that could be read differently by Bitbucket.
///
/// Percent-encoding is decoded exactly once.
/// Encoded slashes and backslashes, `.` and `..` segments, and empty segments are rejected; a single trailing slash is ignored.
fn normalize(raw_path: &str) -> Result<Vec<String>, Unsupported> {
    let path = raw_path.strip_prefix('/').ok_or(Unsupported::MalformedPath)?;
    let path = path.strip_suffix('/').unwrap_or(path);

    if path.is_empty() {
        return Err(Unsupported::MalformedPath);
    }

    path.split('/')
        .map(|segment| {
            let decoded = percent_decode_str(segment)
                .decode_utf8()
                .map_err(|_| Unsupported::MalformedPath)?;

            if decoded.is_empty() || decoded == "." || decoded == ".." || decoded.contains(['/', '\\']) {
                return Err(Unsupported::MalformedPath);
            }

            Ok(decoded.into_owned())
        })
        .collect()
}

/// `/rest/api/{version}/projects/{key}/repos/{slug}/…`
fn classify_api(method: &Method, tail: &[&str]) -> Option<(Action, BranchSource)> {
    use BranchSource as B;

    let get = *method == Method::GET;

    let classified = match tail {
        [] if get => (Action::RepoRead, B::None),
        ["browse" | "files" | "commits" | "diff" | "tags" | "last-modified", ..] if get => (Action::RepoRead, B::None),
        ["raw" | "compare", _, ..] if get => (Action::RepoRead, B::None),
        ["changes" | "participants" | "default-branch" | "ref-change-activities"] if get => (Action::RepoRead, B::None),
        ["ref-change-activities", "branches"] if get => (Action::RepoRead, B::None),

        ["branches"] if get => (Action::RepoRead, B::None),
        ["branches", "default"] if get => (Action::RepoRead, B::None),
        ["branches"] if *method == Method::POST => (Action::BranchCreate, B::BodyBranchName),

        ["pull-requests"] if get => (Action::RepoRead, B::None),
        ["pull-requests"] if *method == Method::POST => (Action::PrCreate, B::BodyPullRequestRefs),

        // `{id}.diff` and `{id}.patch` render the whole pull request as text.
        ["pull-requests", file] if get && pull_request_file(file).is_some() => (Action::RepoRead, B::None),

        ["pull-requests", id, tail @ ..] => {
            let id = pull_request_id(id)?;
            classify_pull_request(method, id, tail)?
        }

        _ => return None,
    };

    Some(classified)
}

/// `/rest/api/{version}/projects/{key}/repos/{slug}/pull-requests/{id}/…`
fn classify_pull_request(method: &Method, id: u64, tail: &[&str]) -> Option<(Action, BranchSource)> {
    use BranchSource as B;

    let pull_request = B::PullRequest(id);
    let get = *method == Method::GET;

    let classified = match (tail, method) {
        ([], _) if get => (Action::RepoRead, B::None),
        ([], &Method::PUT) => (Action::PrUpdate, B::PullRequestUpdate(id)),
        ([], &Method::DELETE) => (Action::PrDelete, pull_request),

        (["activities" | "changes" | "commits"], _) if get => (Action::RepoRead, B::None),
        (["diff" | "diff-stats-summary", ..], _) if get => (Action::RepoRead, B::None),
        // `GET …/merge` only checks whether the pull request can be merged.
        // Reading never depends on branches: `repo:read` covers every read in the repository.
        (["merge"], _) if get => (Action::RepoRead, B::None),
        (["merge-base" | "commit-message-suggestion" | "participants" | "review" | "auto-merge"], _) if get => {
            (Action::RepoRead, B::None)
        }

        // Adding and removing reviewers edits the pull request; the body names a user, not branches.
        (["participants"], &Method::POST | &Method::DELETE) => (Action::PrUpdate, pull_request),

        (["merge"], &Method::POST) => (Action::PrMerge, pull_request),
        (["decline"], &Method::POST) => (Action::PrDecline, pull_request),
        (["reopen"], &Method::POST) => (Action::PrReopen, pull_request),
        (["approve"], &Method::POST | &Method::DELETE) => (Action::PrReview, pull_request),
        (["participants", _], &Method::PUT | &Method::DELETE) => (Action::PrReview, pull_request),
        // Completes the token's own review, publishing its pending comments, or discards it.
        (["review"], &Method::PUT | &Method::DELETE) => (Action::PrReview, pull_request),

        (["comments" | "blocker-comments"], _) if get => (Action::RepoRead, B::None),
        (["comments" | "blocker-comments"], &Method::POST) => (Action::PrCommentCreate, pull_request),
        // A comment's reactions: not in the published API description, but served by Bitbucket and used by its UI.
        // Like the `comment-likes` reactions, adding and removing the token's own reaction needs `pr_comment:create`.
        (["comments", comment, "reactions"], _) => {
            pull_request_id(comment)?;
            match *method {
                Method::GET => (Action::RepoRead, B::None),
                Method::POST => (Action::PrCommentCreate, pull_request),
                _ => return None,
            }
        }
        (["comments", comment, "reactions", _], &Method::PUT | &Method::DELETE) => {
            pull_request_id(comment)?;
            (Action::PrCommentCreate, pull_request)
        }
        (["comments" | "blocker-comments", comment], _) => {
            comment.parse::<u64>().ok()?;
            match *method {
                Method::GET => (Action::RepoRead, B::None),
                Method::PUT => (Action::PrCommentUpdate, pull_request),
                Method::DELETE => (Action::PrCommentDelete, pull_request),
                _ => return None,
            }
        }

        _ => return None,
    };

    Some(classified)
}

/// `/rest/branch-utils/{version}/projects/{key}/repos/{slug}/…`
fn classify_branch_utils(method: &Method, tail: &[&str]) -> Option<(Action, BranchSource)> {
    match (tail, method) {
        (["branches"], &Method::POST) => Some((Action::BranchCreate, BranchSource::BodyBranchName)),
        (["branches"], &Method::DELETE) => Some((Action::BranchDelete, BranchSource::BodyBranchName)),
        (["branches", "info", _], &Method::GET) => Some((Action::RepoRead, BranchSource::None)),
        _ => None,
    }
}

/// `/rest/comment-likes/{version}/projects/{key}/repos/{slug}/…`
///
/// A reaction is the token's own lightweight comment, so adding and removing one both need `pr_comment:create`.
/// Reactions on commit comments are not supported.
fn classify_comment_likes(method: &Method, tail: &[&str]) -> Option<(Action, BranchSource)> {
    match (tail, method) {
        (["pull-requests", id, "comments", comment, "reactions", _], &Method::PUT | &Method::DELETE) => {
            let id = pull_request_id(id)?;
            pull_request_id(comment)?;
            Some((Action::PrCommentCreate, BranchSource::PullRequest(id)))
        }
        _ => None,
    }
}

/// `/rest/jira/{version}/projects/{key}/repos/{slug}/…`
fn classify_jira(method: &Method, tail: &[&str]) -> Option<(Action, BranchSource)> {
    match (tail, method) {
        (["pull-requests", id, "issues"], &Method::GET) => {
            pull_request_id(id)?;
            Some((Action::RepoRead, BranchSource::None))
        }
        _ => None,
    }
}

/// `/rest/insights/{version}/projects/{key}/repos/{slug}/…`: Code Insights reports and annotations on commits.
fn classify_insights(method: &Method, tail: &[&str]) -> Option<(Action, BranchSource)> {
    match (tail, method) {
        (["commits", _, "reports" | "annotations", ..], &Method::GET) => Some((Action::RepoRead, BranchSource::None)),
        _ => None,
    }
}

/// The pull request ID in `{id}.diff` or `{id}.patch`.
fn pull_request_file(segment: &str) -> Option<u64> {
    let id = segment
        .strip_suffix(".diff")
        .or_else(|| segment.strip_suffix(".patch"))?;
    pull_request_id(id)
}

fn pull_request_id(segment: &str) -> Option<u64> {
    // `u64::from_str` accepts a leading `+`, which Bitbucket would not read as the same ID.
    if segment.is_empty() || !segment.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    segment.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPO: &str = "/rest/api/latest/projects/PROJ/repos/api";

    fn ok(method: Method, path: &str) -> (Action, BranchSource) {
        let classified = classify(&method, path).unwrap_or_else(|error| panic!("{method} {path}: {error}"));
        assert_eq!(
            (classified.project.as_str(), classified.repository.as_str()),
            ("PROJ", "api"),
            "{path}"
        );
        assert_eq!(
            classified.branches.scope(),
            classified.action.branch_scope(),
            "{method} {path}"
        );
        (classified.action, classified.branches)
    }

    fn denied(method: Method, path: &str) -> Unsupported {
        match classify(&method, path) {
            Ok(classified) => panic!("{method} {path} should be denied, got {classified:?}"),
            Err(error) => error,
        }
    }

    #[test]
    fn repository_reads() {
        for tail in [
            "",
            "/browse",
            "/browse/src/main.rs",
            "/raw/README.md",
            "/files",
            "/files/src",
            "/commits",
            "/commits/abc123",
            "/commits/abc123/changes",
            "/compare/changes",
            "/compare/diff/src/lib.rs",
            "/diff",
            "/diff/src/lib.rs",
            "/tags",
            "/tags/v1.0",
            "/changes",
            "/last-modified",
            "/last-modified/src",
            "/participants",
            "/default-branch",
            "/branches/default",
            "/ref-change-activities",
            "/ref-change-activities/branches",
            "/commits/abc123/comments",
            "/commits/abc123/comments/5",
            "/commits/abc123/builds",
            "/commits/abc123/pull-requests",
            "/pull-requests/42.diff",
            "/pull-requests/42.patch",
            "/pull-requests/42/merge-base",
            "/pull-requests/42/commit-message-suggestion",
            "/pull-requests/42/participants",
            "/pull-requests/42/review",
            "/pull-requests/42/auto-merge",
            "/pull-requests/42/comments/182860/reactions",
        ] {
            assert_eq!(
                ok(Method::GET, &format!("{REPO}{tail}")),
                (Action::RepoRead, BranchSource::None),
                "{tail}"
            );
        }
    }

    #[test]
    fn branches() {
        assert_eq!(
            ok(Method::GET, &format!("{REPO}/branches")),
            (Action::RepoRead, BranchSource::None)
        );
        assert_eq!(
            ok(Method::POST, &format!("{REPO}/branches")),
            (Action::BranchCreate, BranchSource::BodyBranchName)
        );

        let utils = "/rest/branch-utils/1.0/projects/PROJ/repos/api/branches";
        assert_eq!(
            ok(Method::POST, utils),
            (Action::BranchCreate, BranchSource::BodyBranchName)
        );
        assert_eq!(
            ok(Method::DELETE, utils),
            (Action::BranchDelete, BranchSource::BodyBranchName)
        );
        assert_eq!(
            ok(Method::GET, &format!("{utils}/info/abc123")),
            (Action::RepoRead, BranchSource::None)
        );
    }

    #[test]
    fn pull_requests() {
        let pr = format!("{REPO}/pull-requests/42");
        let existing = BranchSource::PullRequest(42);

        let cases = [
            (
                Method::GET,
                format!("{REPO}/pull-requests"),
                Action::RepoRead,
                BranchSource::None,
            ),
            (
                Method::POST,
                format!("{REPO}/pull-requests"),
                Action::PrCreate,
                BranchSource::BodyPullRequestRefs,
            ),
            (Method::GET, pr.clone(), Action::RepoRead, BranchSource::None),
            (
                Method::PUT,
                pr.clone(),
                Action::PrUpdate,
                BranchSource::PullRequestUpdate(42),
            ),
            (Method::DELETE, pr.clone(), Action::PrDelete, existing),
            (
                Method::GET,
                format!("{pr}/activities"),
                Action::RepoRead,
                BranchSource::None,
            ),
            (
                Method::GET,
                format!("{pr}/changes"),
                Action::RepoRead,
                BranchSource::None,
            ),
            (
                Method::GET,
                format!("{pr}/commits"),
                Action::RepoRead,
                BranchSource::None,
            ),
            (
                Method::GET,
                format!("{pr}/diff/src/lib.rs"),
                Action::RepoRead,
                BranchSource::None,
            ),
            (
                Method::GET,
                format!("{pr}/diff-stats-summary/src"),
                Action::RepoRead,
                BranchSource::None,
            ),
            (Method::GET, format!("{pr}/merge"), Action::RepoRead, BranchSource::None),
            (Method::POST, format!("{pr}/merge"), Action::PrMerge, existing),
            (Method::POST, format!("{pr}/decline"), Action::PrDecline, existing),
            (Method::POST, format!("{pr}/reopen"), Action::PrReopen, existing),
            (Method::POST, format!("{pr}/approve"), Action::PrReview, existing),
            (Method::DELETE, format!("{pr}/approve"), Action::PrReview, existing),
            (
                Method::PUT,
                format!("{pr}/participants/alice"),
                Action::PrReview,
                existing,
            ),
            (
                Method::DELETE,
                format!("{pr}/participants/alice"),
                Action::PrReview,
                existing,
            ),
            (
                Method::GET,
                format!("{pr}/comments"),
                Action::RepoRead,
                BranchSource::None,
            ),
            (
                Method::POST,
                format!("{pr}/comments"),
                Action::PrCommentCreate,
                existing,
            ),
            (
                Method::GET,
                format!("{pr}/comments/7"),
                Action::RepoRead,
                BranchSource::None,
            ),
            (
                Method::PUT,
                format!("{pr}/comments/7"),
                Action::PrCommentUpdate,
                existing,
            ),
            (
                Method::DELETE,
                format!("{pr}/comments/7"),
                Action::PrCommentDelete,
                existing,
            ),
            (
                Method::GET,
                format!("{pr}/blocker-comments"),
                Action::RepoRead,
                BranchSource::None,
            ),
            (
                Method::POST,
                format!("{pr}/blocker-comments"),
                Action::PrCommentCreate,
                existing,
            ),
            (
                Method::PUT,
                format!("{pr}/blocker-comments/7"),
                Action::PrCommentUpdate,
                existing,
            ),
            (
                Method::DELETE,
                format!("{pr}/blocker-comments/7"),
                Action::PrCommentDelete,
                existing,
            ),
            (Method::POST, format!("{pr}/participants"), Action::PrUpdate, existing),
            (Method::DELETE, format!("{pr}/participants"), Action::PrUpdate, existing),
            (
                Method::POST,
                format!("{pr}/comments/7/reactions"),
                Action::PrCommentCreate,
                existing,
            ),
            (
                Method::PUT,
                format!("{pr}/comments/7/reactions/heart"),
                Action::PrCommentCreate,
                existing,
            ),
            (
                Method::DELETE,
                format!("{pr}/comments/7/reactions/heart"),
                Action::PrCommentCreate,
                existing,
            ),
            (Method::PUT, format!("{pr}/review"), Action::PrReview, existing),
            (Method::DELETE, format!("{pr}/review"), Action::PrReview, existing),
        ];

        for (method, path, action, branches) in cases {
            assert_eq!(ok(method.clone(), &path), (action, branches), "{method} {path}");
        }
    }

    #[test]
    fn other_plugins() {
        let reaction =
            "/rest/comment-likes/latest/projects/PROJ/repos/api/pull-requests/42/comments/7/reactions/thumbsup";
        for method in [Method::PUT, Method::DELETE] {
            assert_eq!(
                ok(method, reaction),
                (Action::PrCommentCreate, BranchSource::PullRequest(42))
            );
        }

        for path in [
            "/rest/jira/1.0/projects/PROJ/repos/api/pull-requests/42/issues",
            "/rest/insights/latest/projects/PROJ/repos/api/commits/abc123/reports",
            "/rest/insights/latest/projects/PROJ/repos/api/commits/abc123/reports/sonar",
            "/rest/insights/latest/projects/PROJ/repos/api/commits/abc123/reports/sonar/annotations",
            "/rest/insights/latest/projects/PROJ/repos/api/commits/abc123/annotations",
        ] {
            assert_eq!(ok(Method::GET, path), (Action::RepoRead, BranchSource::None), "{path}");
        }

        for (method, path) in [
            (Method::GET, reaction),
            (
                Method::PUT,
                "/rest/comment-likes/latest/projects/PROJ/repos/api/commits/abc/comments/7/reactions/thumbsup",
            ),
            (
                Method::PUT,
                "/rest/comment-likes/latest/projects/PROJ/repos/api/pull-requests/x/comments/7/reactions/thumbsup",
            ),
            (
                Method::PUT,
                "/rest/insights/latest/projects/PROJ/repos/api/commits/abc123/reports/sonar",
            ),
            (
                Method::POST,
                "/rest/insights/latest/projects/PROJ/repos/api/commits/abc123/reports/sonar/annotations",
            ),
            (
                Method::GET,
                "/rest/jira/1.0/projects/PROJ/repos/api/pull-requests/x/issues",
            ),
            (
                Method::GET,
                "/rest/build-status/latest/projects/PROJ/repos/api/commits/abc123",
            ),
        ] {
            assert_eq!(denied(method.clone(), path), Unsupported::Endpoint, "{method} {path}");
        }
    }

    #[test]
    fn api_versions_are_equivalent() {
        for version in ["1.0", "latest"] {
            assert_eq!(
                ok(
                    Method::POST,
                    &format!("/rest/api/{version}/projects/PROJ/repos/api/pull-requests/1/merge")
                )
                .0,
                Action::PrMerge
            );
        }

        assert_eq!(
            denied(Method::GET, "/rest/api/2.0/projects/PROJ/repos/api"),
            Unsupported::Endpoint
        );
    }

    #[test]
    fn denies_endpoints_outside_the_table() {
        for (method, path) in [
            // Repository administration.
            (Method::PUT, REPO.to_owned()),
            (Method::POST, REPO.to_owned()),
            (Method::DELETE, REPO.to_owned()),
            // Writes on read-only paths.
            (Method::PUT, format!("{REPO}/browse/README.md")),
            (Method::POST, format!("{REPO}/tags")),
            (Method::POST, format!("{REPO}/commits/abc123/comments")),
            // Commits through comments, and token management.
            (
                Method::POST,
                format!("{REPO}/pull-requests/1/comments/2/apply-suggestion"),
            ),
            (
                Method::PUT,
                "/rest/access-tokens/latest/projects/PROJ/repos/api".to_owned(),
            ),
            // Cross-repository listings.
            (Method::GET, "/rest/api/latest/dashboard/pull-requests".to_owned()),
            (Method::GET, "/rest/api/latest/inbox/pull-requests".to_owned()),
            (Method::GET, "/rest/api/latest/projects/PROJ".to_owned()),
            (Method::GET, "/rest/api/latest/projects/PROJ/repos".to_owned()),
            // Wrong methods and shapes.
            (Method::PATCH, format!("{REPO}/pull-requests/1")),
            (Method::POST, format!("{REPO}/pull-requests/1/comments/2")),
            (Method::GET, format!("{REPO}/pull-requests/abc")),
            (Method::GET, format!("{REPO}/pull-requests/+1")),
            (Method::GET, format!("{REPO}/pull-requests/.diff")),
            (Method::GET, format!("{REPO}/pull-requests/1.txt")),
            (Method::PUT, format!("{REPO}/pull-requests/1.diff")),
            (Method::POST, format!("{REPO}/pull-requests/1/auto-merge")),
            (Method::POST, format!("{REPO}/pull-requests/1/watch")),
            (Method::PUT, format!("{REPO}/default-branch")),
            (Method::PUT, format!("{REPO}/branches/default")),
            (Method::DELETE, format!("{REPO}/commits/abc123/comments/5")),
            (Method::PUT, format!("{REPO}/pull-requests/1/comments/2/reactions")),
            (Method::GET, format!("{REPO}/pull-requests/1/comments/x/reactions")),
            (
                Method::GET,
                format!("{REPO}/pull-requests/1/comments/2/reactions/thumbsup"),
            ),
            (Method::DELETE, format!("{REPO}/pull-requests/1/comments/2/reactions")),
            (
                Method::PUT,
                format!("{REPO}/pull-requests/1/comments/x/reactions/heart"),
            ),
            (
                Method::PUT,
                format!("{REPO}/pull-requests/1/blocker-comments/2/reactions/heart"),
            ),
            (Method::GET, format!("{REPO}/pull-requests/1/comments/x")),
            (Method::GET, format!("{REPO}/raw")),
            (Method::GET, format!("{REPO}/settings/pull-requests")),
            // Not the REST API.
            (Method::GET, "/projects/PROJ/repos/api/browse".to_owned()),
        ] {
            assert_eq!(denied(method.clone(), &path), Unsupported::Endpoint, "{method} {path}");
        }
    }

    #[test]
    fn denies_git_and_personal_repositories() {
        assert_eq!(denied(Method::GET, "/scm/proj/api.git/info/refs"), Unsupported::Git);
        assert_eq!(
            denied(Method::GET, "/rest/api/latest/projects/~alice/repos/dotfiles"),
            Unsupported::PersonalRepository
        );
        assert_eq!(
            denied(Method::GET, "/rest/api/latest/projects/%7Ealice/repos/dotfiles"),
            Unsupported::PersonalRepository
        );
    }

    #[test]
    fn normalization() {
        // Decoding happens exactly once.
        let classified = classify(&Method::GET, "/rest/api/latest/projects/PROJ/repos/my%20repo").unwrap();
        assert_eq!(classified.repository, "my repo");
        let classified = classify(&Method::GET, "/rest/api/latest/projects/PROJ/repos/a%2541").unwrap();
        assert_eq!(classified.repository, "a%41");

        // A single trailing slash is ignored.
        assert_eq!(
            ok(Method::POST, &format!("{REPO}/pull-requests/1/merge/")).0,
            Action::PrMerge
        );

        for path in [
            "/rest/api/latest/projects/PROJ/repos/api/pull-requests%2F1/merge",
            "/rest/api/latest/projects/PROJ/repos/api%2fx/pull-requests",
            "/rest/api/latest/projects/PROJ/repos/other/../api/pull-requests/1/merge",
            "/rest/api/latest/projects/PROJ/repos/api/./pull-requests",
            "/rest/api/latest/projects/PROJ/repos/api/%2e%2e/x",
            "/rest/api/latest/projects/PROJ/repos/api//pull-requests",
            "/rest//api/latest/projects/PROJ/repos/api",
            "/rest/api/latest/projects/PROJ/repos/api/pull-requests/1/merge//",
            "/rest/api/latest/projects/PROJ/repos/api%5Cx",
            "/rest/api/latest/projects/PROJ/repos/%FF",
            "rest/api/latest/projects/PROJ/repos/api",
            "/",
            "",
        ] {
            assert_eq!(denied(Method::POST, path), Unsupported::MalformedPath, "{path}");
        }
    }
}
