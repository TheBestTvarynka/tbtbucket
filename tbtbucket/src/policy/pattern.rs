use std::fmt;

use globset::{GlobBuilder, GlobMatcher};

/// A glob that keeps its source text, so that a policy serializes back to what was written.
#[derive(Debug, Clone)]
struct Glob {
    source: String,
    matcher: GlobMatcher,
}

impl Glob {
    fn new(source: &str, case_insensitive: bool) -> Result<Self, InvalidPattern> {
        if source.trim().is_empty() {
            return Err(InvalidPattern::Empty);
        }

        if source.trim() != source {
            return Err(InvalidPattern::SurroundingWhitespace(source.to_owned()));
        }

        let matcher = GlobBuilder::new(source)
            .literal_separator(true)
            .case_insensitive(case_insensitive)
            .backslash_escape(true)
            .build()
            .map_err(|error| InvalidPattern::Syntax(source.to_owned(), error.kind().to_string()))?
            .compile_matcher();

        Ok(Self {
            source: source.to_owned(),
            matcher,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum InvalidPattern {
    #[error("pattern is empty")]
    Empty,

    #[error("pattern `{0}` has leading or trailing whitespace")]
    SurroundingWhitespace(String),

    #[error("pattern `{0}` is invalid: {1}")]
    Syntax(String, String),

    #[error("project pattern `{0}` names a personal project, which is not supported yet")]
    PersonalProject(String),
}

/// A project key pattern, compared case-insensitively, as Bitbucket does.
///
/// Personal projects (`~user`) are rejected, because they are not supported yet.
#[derive(Debug, Clone)]
pub(crate) struct ProjectPattern(Glob);

impl ProjectPattern {
    pub(crate) fn new(source: &str) -> Result<Self, InvalidPattern> {
        if source.starts_with('~') {
            return Err(InvalidPattern::PersonalProject(source.to_owned()));
        }

        Glob::new(source, true).map(Self)
    }

    pub(crate) fn matches(&self, project_key: &str) -> bool {
        // A `*` pattern must never reach personal projects, even once they are supported.
        !project_key.starts_with('~') && self.0.matcher.is_match(project_key)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0.source
    }
}

/// A repository slug pattern.
#[derive(Debug, Clone)]
pub(crate) struct RepositoryPattern(Glob);

impl RepositoryPattern {
    pub(crate) fn new(source: &str) -> Result<Self, InvalidPattern> {
        Glob::new(source, false).map(Self)
    }

    pub(crate) fn matches(&self, slug: &str) -> bool {
        self.0.matcher.is_match(slug)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0.source
    }
}

/// A branch name pattern, matched against short names such as `feature/login`.
///
/// `*` matches within one `/`-separated segment, and `**` matches across segments.
#[derive(Debug, Clone)]
pub(crate) struct BranchPattern(Glob);

impl BranchPattern {
    pub(crate) fn new(source: &str) -> Result<Self, InvalidPattern> {
        Glob::new(source, false).map(Self)
    }

    pub(crate) fn matches(&self, branch: &str) -> bool {
        self.0.matcher.is_match(branch)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0.source
    }
}

impl fmt::Display for BranchPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_globs_respect_segments() {
        let one = BranchPattern::new("release/*").unwrap();
        let any = BranchPattern::new("release/**").unwrap();

        assert!(one.matches("release/1.0"));
        assert!(!one.matches("release/1.0/hotfix"));
        assert!(any.matches("release/1.0"));
        assert!(any.matches("release/1.0/hotfix"));
        assert!(!any.matches("releases/1.0"));
        assert!(!one.matches("Release/1.0"));

        let feature = BranchPattern::new("feature/**").unwrap();
        assert!(!feature.matches("feature"));
        assert!(!feature.matches("my-feature/x"));

        let exact = BranchPattern::new("main").unwrap();
        assert!(exact.matches("main"));
        assert!(!exact.matches("main2"));
        assert!(!exact.matches("x/main"));
    }

    #[test]
    fn project_keys_are_case_insensitive() {
        let project = ProjectPattern::new("PROJ").unwrap();

        assert!(project.matches("PROJ"));
        assert!(project.matches("proj"));
        assert!(!project.matches("PROJECT"));
    }

    #[test]
    fn personal_projects_are_never_matched() {
        assert!(matches!(
            ProjectPattern::new("~alice"),
            Err(InvalidPattern::PersonalProject(_))
        ));
        assert!(!ProjectPattern::new("*").unwrap().matches("~alice"));
    }

    #[test]
    fn rejects_invalid_patterns() {
        for source in ["", " ", " main", "main ", "release/[", "{a,b"] {
            assert!(BranchPattern::new(source).is_err(), "{source:?}");
        }
    }

    #[test]
    fn repository_slugs_match_whole_names() {
        let repo = RepositoryPattern::new("api-*").unwrap();

        assert!(repo.matches("api-gateway"));
        assert!(!repo.matches("legacy-api-gateway"));
    }
}
