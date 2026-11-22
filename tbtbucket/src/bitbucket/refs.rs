//! Branch references in Bitbucket request and response bodies.
//!
//! Pull requests name their branches in `fromRef` and `toRef`, as `{ "id": "refs/heads/…", "repository": { … } }`.
//! Branch creation and deletion name the branch in `name`.

use serde::Deserialize;

/// The source and target branches of a pull request, by short name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PullRequestBranches {
    pub(crate) source: String,
    pub(crate) target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RefError {
    #[error("body is not a valid JSON object")]
    InvalidJson,

    #[error("body has no `{0}`")]
    Missing(&'static str),

    #[error("`{0}` is not a branch")]
    NotABranch(String),

    #[error("`{0}` belongs to another repository, which is not supported yet")]
    OtherRepository(&'static str),
}

/// The parts of a pull request, or of a request that creates or updates one, that name its branches.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PullRequestRefs {
    from_ref: Option<Ref>,
    to_ref: Option<Ref>,
}

#[derive(Debug, Deserialize)]
struct Ref {
    id: Option<String>,
    repository: Option<RefRepository>,
}

#[derive(Debug, Deserialize)]
struct RefRepository {
    slug: Option<String>,
    project: Option<RefProject>,
}

#[derive(Debug, Deserialize)]
struct RefProject {
    key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BranchBody {
    name: Option<String>,
}

impl PullRequestRefs {
    pub(crate) fn parse(body: &[u8]) -> Result<Self, RefError> {
        serde_json::from_slice(body).map_err(|_| RefError::InvalidJson)
    }

    /// Returns both branches, which must belong to the repository the request is for.
    pub(crate) fn branches(&self, project: &str, repository: &str) -> Result<PullRequestBranches, RefError> {
        let from_ref = self.from_ref.as_ref().ok_or(RefError::Missing("fromRef"))?;
        let to_ref = self.to_ref.as_ref().ok_or(RefError::Missing("toRef"))?;

        Ok(PullRequestBranches {
            source: from_ref.branch("fromRef", project, repository)?,
            target: to_ref.branch("toRef", project, repository)?,
        })
    }

    /// Returns the target branch if the body sets one, as an update that retargets a pull request does.
    pub(crate) fn target(&self, project: &str, repository: &str) -> Result<Option<String>, RefError> {
        self.to_ref
            .as_ref()
            .map(|to_ref| to_ref.branch("toRef", project, repository))
            .transpose()
    }
}

impl Ref {
    fn branch(&self, field: &'static str, project: &str, repository: &str) -> Result<String, RefError> {
        if let Some(ref_repository) = &self.repository {
            let same_repository = ref_repository
                .slug
                .as_deref()
                .is_some_and(|slug| slug.eq_ignore_ascii_case(repository))
                && ref_repository
                    .project
                    .as_ref()
                    .and_then(|ref_project| ref_project.key.as_deref())
                    .is_some_and(|key| key.eq_ignore_ascii_case(project));

            if !same_repository {
                return Err(RefError::OtherRepository(field));
            }
        }

        let id = self.id.as_deref().ok_or(RefError::Missing(field))?;
        short_branch_name(id)
    }
}

/// Returns the branch named in the `name` field of a branch creation or deletion body.
pub(crate) fn branch_name(body: &[u8]) -> Result<String, RefError> {
    let body: BranchBody = serde_json::from_slice(body).map_err(|_| RefError::InvalidJson)?;
    let name = body.name.ok_or(RefError::Missing("name"))?;
    short_branch_name(&name)
}

/// `refs/heads/feature/x` and `feature/x` both name the branch `feature/x`; other refs are not branches.
fn short_branch_name(reference: &str) -> Result<String, RefError> {
    let name = match reference.strip_prefix("refs/heads/") {
        Some(name) => name,
        None if reference.starts_with("refs/") => return Err(RefError::NotABranch(reference.to_owned())),
        None => reference,
    };

    if name.is_empty() {
        return Err(RefError::NotABranch(reference.to_owned()));
    }

    Ok(name.to_owned())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn refs(value: serde_json::Value) -> PullRequestRefs {
        PullRequestRefs::parse(value.to_string().as_bytes()).unwrap()
    }

    fn reference(id: &str, project: &str, slug: &str) -> serde_json::Value {
        json!({ "id": id, "displayId": id, "repository": { "slug": slug, "project": { "key": project } } })
    }

    #[test]
    fn pull_request_branches() {
        let body = refs(json!({
            "title": "Login",
            "fromRef": reference("refs/heads/feature/login", "PROJ", "api"),
            "toRef": reference("refs/heads/main", "proj", "api"),
        }));

        assert_eq!(
            body.branches("PROJ", "api").unwrap(),
            PullRequestBranches {
                source: "feature/login".to_owned(),
                target: "main".to_owned(),
            }
        );
    }

    #[test]
    fn refs_without_repository_belong_to_the_request_repository() {
        let body = refs(json!({ "fromRef": { "id": "refs/heads/a" }, "toRef": { "id": "b" } }));

        assert_eq!(body.branches("PROJ", "api").unwrap().target, "b");
    }

    #[test]
    fn rejects_forks_and_other_repositories() {
        let from_fork = refs(json!({
            "fromRef": reference("refs/heads/feature/x", "~ALICE", "api"),
            "toRef": reference("refs/heads/main", "PROJ", "api"),
        }));
        assert_eq!(
            from_fork.branches("PROJ", "api"),
            Err(RefError::OtherRepository("fromRef"))
        );

        let other_repository = refs(json!({
            "fromRef": reference("refs/heads/feature/x", "PROJ", "api"),
            "toRef": reference("refs/heads/main", "PROJ", "web"),
        }));
        assert_eq!(
            other_repository.branches("PROJ", "api"),
            Err(RefError::OtherRepository("toRef"))
        );

        let no_project =
            refs(json!({ "fromRef": { "id": "a", "repository": { "slug": "api" } }, "toRef": { "id": "b" } }));
        assert_eq!(
            no_project.branches("PROJ", "api"),
            Err(RefError::OtherRepository("fromRef"))
        );
    }

    #[test]
    fn rejects_missing_and_non_branch_refs() {
        assert_eq!(
            refs(json!({ "toRef": { "id": "main" } })).branches("PROJ", "api"),
            Err(RefError::Missing("fromRef"))
        );
        assert_eq!(
            refs(json!({ "fromRef": { "id": "refs/tags/v1" }, "toRef": { "id": "main" } })).branches("PROJ", "api"),
            Err(RefError::NotABranch("refs/tags/v1".to_owned()))
        );
        assert_eq!(
            refs(json!({ "fromRef": { "id": "refs/heads/" }, "toRef": { "id": "main" } })).branches("PROJ", "api"),
            Err(RefError::NotABranch("refs/heads/".to_owned()))
        );
        assert_eq!(PullRequestRefs::parse(b"not json").unwrap_err(), RefError::InvalidJson);
    }

    #[test]
    fn update_target_is_optional() {
        assert_eq!(
            refs(json!({ "title": "New title", "version": 3 })).target("PROJ", "api"),
            Ok(None)
        );
        assert_eq!(
            refs(json!({ "version": 3, "toRef": { "id": "refs/heads/develop" } })).target("PROJ", "api"),
            Ok(Some("develop".to_owned()))
        );
    }

    #[test]
    fn branch_names() {
        assert_eq!(
            branch_name(br#"{"name":"bot/deps","startPoint":"main"}"#).unwrap(),
            "bot/deps"
        );
        assert_eq!(
            branch_name(br#"{"name":"refs/heads/bot/deps","dryRun":false}"#).unwrap(),
            "bot/deps"
        );
        assert_eq!(
            branch_name(br#"{"name":"refs/tags/v1"}"#),
            Err(RefError::NotABranch("refs/tags/v1".to_owned()))
        );
        assert_eq!(branch_name(br#"{"startPoint":"main"}"#), Err(RefError::Missing("name")));
        assert_eq!(branch_name(b""), Err(RefError::InvalidJson));
    }
}
