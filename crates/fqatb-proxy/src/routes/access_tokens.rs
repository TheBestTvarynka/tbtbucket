//! Issuing and removing access tokens.
//!
//! The page lives in the admin panel, while the actions it performs through htmx live under [`API_PATH`].
//! Rules are edited as cards in one form; each card's fields are named `rule.{key}.{field}`,
//! where `key` identifies the card, so that cards can be added and removed in any order.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::routing::{delete, get, post};
use axum::{Form, Router};
use time::OffsetDateTime;
use tracing::info;
use uuid::Uuid;

use super::auth::AuthSession;
use super::{LifetimeOption, form_token_expiry, lifetime_options, utc_minutes};
use crate::db::AccessTokenSummary;
use crate::policy::{InvalidPattern, Policy, PolicyError, PolicySpec, RuleError, RuleSpec};
use crate::services::{AccessTokenRejection, DEFAULT_TOKEN_LIFETIME_DAYS, MAX_ACCESS_TOKEN_NAME_LEN};
use crate::state::AppState;
use crate::{Error, Result};

pub(super) const PAGE_PATH: &str = "/webapp/access_tokens";
const API_PATH: &str = "/fgatbapi/access_tokens";
const API_TOKEN_PATH: &str = "/fgatbapi/access_tokens/{id}";
const API_RULE_PATH: &str = "/fgatbapi/access_tokens/rules";

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route(PAGE_PATH, get(page))
        .route(API_PATH, post(create))
        .route(API_RULE_PATH, post(new_rule))
        .route(API_TOKEN_PATH, delete(remove))
}

/// A group of related actions, shown as one row of checkboxes.
struct ActionGroup {
    label: &'static str,
    /// What the group covers, shown after its checkboxes.
    note: Option<&'static str>,
    actions: &'static [ActionOption],
    /// Whether the row carries the branch pattern input that limits its actions.
    branch_pattern: bool,
    /// Shown in a tooltip on a help icon next to the checkboxes.
    help: Option<&'static str>,
    /// Asked before unchecking one of the group's actions, for actions that a token is rarely useful without.
    uncheck_confirmation: Option<&'static str>,
}

struct ActionOption {
    name: &'static str,
    label: &'static str,
}

/// The action checked on a new rule card.
const DEFAULT_ACTION: &str = "repo:read";

/// Actions offered in the form.
///
/// Tag actions (`tag:*`) are left out: tags are only changed with Git pushes, which are not forwarded yet.
const ACTION_GROUPS: &[ActionGroup] = &[
    ActionGroup {
        label: "Repository",
        note: Some("(all commits, branches, PRs and their comments)"),
        actions: &[ActionOption {
            name: "repo:read",
            label: "read",
        }],
        branch_pattern: false,
        help: Some(
            "Most clients read before they change anything: they load a pull request, its diff and its comments \
             before they update, review, comment on or merge it. Reading covers all of that, and branch patterns \
             never limit it. Without it, those requests are denied, so the token is rarely useful.",
        ),
        uncheck_confirmation: Some(
            "Without Repository: read, the client cannot read anything in this repository: commits, branches, \
             pull requests, their diffs and comments. Those requests will be denied.\n\nUncheck it anyway?",
        ),
    },
    ActionGroup {
        label: "Branches",
        note: None,
        actions: &[
            ActionOption {
                name: "branch:create",
                label: "create",
            },
            ActionOption {
                name: "branch:delete",
                label: "delete",
            },
            ActionOption {
                name: "branch:push",
                label: "Allow Git",
            },
        ],
        branch_pattern: true,
        help: Some(
            "Allow Git lets the client push to the branches that match the pattern with Git over HTTPS, \
             force pushes included. Creating and deleting a branch by pushing also needs create and delete. \
             The proxy does not forward Git over HTTPS yet; until it does, this option has no effect.",
        ),
        uncheck_confirmation: None,
    },
    ActionGroup {
        label: "Pull requests",
        note: None,
        actions: &[
            ActionOption {
                name: "pr:create",
                label: "create",
            },
            ActionOption {
                name: "pr:update",
                label: "update",
            },
            ActionOption {
                name: "pr:review",
                label: "review",
            },
            ActionOption {
                name: "pr:merge",
                label: "merge",
            },
            ActionOption {
                name: "pr:decline",
                label: "decline",
            },
            ActionOption {
                name: "pr:reopen",
                label: "reopen",
            },
            ActionOption {
                name: "pr:delete",
                label: "delete",
            },
        ],
        branch_pattern: false,
        help: None,
        uncheck_confirmation: None,
    },
    ActionGroup {
        label: "PR comments",
        note: None,
        actions: &[
            ActionOption {
                name: "pr_comment:create",
                label: "create",
            },
            ActionOption {
                name: "pr_comment:update",
                label: "update",
            },
            ActionOption {
                name: "pr_comment:delete",
                label: "delete",
            },
        ],
        branch_pattern: false,
        help: None,
        uncheck_confirmation: None,
    },
];

/// The whole page.
#[derive(Template, WebTemplate)]
#[template(path = "access_tokens.html")]
struct AccessTokensPage {
    issued: Option<IssuedView>,
    form: FormView,
    error: Option<String>,
    bitbucket_tokens: Vec<BitbucketTokenOption>,
    action_groups: &'static [ActionGroup],
    tokens: Vec<TokenRow>,
}

/// The issued token, the form and the list, swapped in after a create attempt.
#[derive(Template, WebTemplate)]
#[template(path = "partials/access_tokens_section.html")]
struct AccessTokensSection {
    issued: Option<IssuedView>,
    form: FormView,
    error: Option<String>,
    bitbucket_tokens: Vec<BitbucketTokenOption>,
    action_groups: &'static [ActionGroup],
    tokens: Vec<TokenRow>,
}

impl From<AccessTokensSection> for AccessTokensPage {
    fn from(section: AccessTokensSection) -> Self {
        Self {
            issued: section.issued,
            form: section.form,
            error: section.error,
            bitbucket_tokens: section.bitbucket_tokens,
            action_groups: section.action_groups,
            tokens: section.tokens,
        }
    }
}

/// One empty rule card, appended to the form.
#[derive(Template, WebTemplate)]
#[template(path = "partials/access_token_rule.html")]
struct RuleCard {
    rule: RuleView,
    bitbucket_tokens: Vec<BitbucketTokenOption>,
    action_groups: &'static [ActionGroup],
}

/// The list alone, swapped in after a removal.
#[derive(Template, WebTemplate)]
#[template(path = "partials/access_tokens_list.html")]
struct AccessTokensList {
    tokens: Vec<TokenRow>,
}

/// A newly issued token, shown once.
struct IssuedView {
    name: String,
    token: String,
}

struct FormView {
    name: String,
    /// The lifetime in days, one of [`crate::services::TOKEN_LIFETIMES_DAYS`].
    expiry: String,
    rules: Vec<RuleView>,
}

impl FormView {
    fn empty() -> Self {
        Self {
            name: String::new(),
            expiry: DEFAULT_TOKEN_LIFETIME_DAYS.to_string(),
            // Rule cards appear only once the admin adds one, so that the page stays short when only managing tokens.
            rules: Vec::new(),
        }
    }

    fn expiry_options(&self) -> Vec<LifetimeOption> {
        lifetime_options(&self.expiry)
    }
}

/// A rule card, as typed in the form.
struct RuleView {
    /// Identifies the card among the form fields; letters and digits only.
    key: String,
    bitbucket_token: String,
    actions: Vec<String>,
    project: String,
    repository: String,
    /// Comma-separated globs.
    branch: String,
    source: String,
    target: String,
}

impl RuleView {
    fn empty() -> Self {
        Self {
            key: Uuid::new_v4().simple().to_string(),
            bitbucket_token: String::new(),
            actions: Vec::new(),
            project: String::new(),
            repository: String::new(),
            branch: String::new(),
            source: String::new(),
            target: String::new(),
        }
    }

    /// A new rule card, with reading checked: few clients work without it.
    fn new_card() -> Self {
        Self {
            actions: vec![DEFAULT_ACTION.to_owned()],
            ..Self::empty()
        }
    }

    fn has_action(&self, name: &str) -> bool {
        self.actions.iter().any(|action| action == name)
    }

    fn uses_bitbucket_token(&self, id: &Uuid) -> bool {
        self.bitbucket_token == id.to_string()
    }
}

struct BitbucketTokenOption {
    id: Uuid,
    name: String,
}

/// A token as shown in the list.
struct TokenRow {
    id: Uuid,
    name: String,
    created_at: String,
    expires_at: String,
    expired: bool,
}

impl TokenRow {
    fn new(token: AccessTokenSummary, now: OffsetDateTime) -> Self {
        Self {
            id: token.id,
            name: token.name,
            created_at: utc_minutes(token.created_at),
            expires_at: utc_minutes(token.expires_at),
            expired: !(now < token.expires_at),
        }
    }
}

async fn page(_auth: AuthSession, State(state): State<AppState>) -> Result<AccessTokensPage> {
    Ok(section(&state, None, FormView::empty(), None).await?.into())
}

async fn new_rule(_auth: AuthSession, State(state): State<AppState>) -> Result<RuleCard> {
    Ok(RuleCard {
        rule: RuleView::new_card(),
        bitbucket_tokens: bitbucket_token_options(&state).await?,
        action_groups: ACTION_GROUPS,
    })
}

async fn create(
    _auth: AuthSession,
    State(state): State<AppState>,
    Form(fields): Form<Vec<(String, String)>>,
) -> Result<Response> {
    let form = parse_form(fields);

    let validated = form_token_expiry(&form.expiry, OffsetDateTime::now_utc())
        .and_then(|expires_at| Ok((build_policy(&form.rules)?, expires_at)));
    let (policy, expires_at) = match validated {
        Ok(validated) => validated,
        Err(message) => return rejected(&state, form, message).await,
    };
    let rules = policy.rules().len();

    match state.access_token_service.issue(&form.name, policy, expires_at).await {
        Ok(issued) => {
            let name = form.name.trim().to_owned();
            info!(access_token_id = %issued.id, %name, rules, %expires_at, "Access token issued");

            let issued = IssuedView {
                name,
                token: issued.token.as_ref().clone(),
            };
            Ok(section(&state, Some(issued), FormView::empty(), None)
                .await?
                .into_response())
        }
        Err(Error::InvalidAccessToken(rejection)) => {
            let message = match rejection {
                AccessTokenRejection::EmptyName => "Enter a name for the token".to_owned(),
                AccessTokenRejection::NameTooLong => {
                    format!("The name must be at most {MAX_ACCESS_TOKEN_NAME_LEN} characters long")
                }
                AccessTokenRejection::NameTaken => "An access token with this name already exists".to_owned(),
                AccessTokenRejection::AlreadyExpired => "The expiration date must be in the future".to_owned(),
                AccessTokenRejection::UnknownBitbucketToken => {
                    "A selected Bitbucket token no longer exists; reload the page".to_owned()
                }
            };
            rejected(&state, form, message).await
        }
        Err(error) => Err(error),
    }
}

/// Removes the token and returns the updated list.
///
/// Removing a token that no longer exists is not an error, so a repeated request still shows the current list.
async fn remove(_auth: AuthSession, State(state): State<AppState>, Path(id): Path<Uuid>) -> Result<AccessTokensList> {
    if state.access_token_service.remove(id).await? {
        info!(access_token_id = %id, "Access token removed");
    }

    Ok(AccessTokensList {
        tokens: token_rows(&state).await?,
    })
}

async fn rejected(state: &AppState, form: FormView, message: String) -> Result<Response> {
    let section = section(state, None, form, Some(message)).await?;
    Ok((StatusCode::UNPROCESSABLE_ENTITY, section).into_response())
}

async fn section(
    state: &AppState,
    issued: Option<IssuedView>,
    form: FormView,
    error: Option<String>,
) -> Result<AccessTokensSection> {
    Ok(AccessTokensSection {
        issued,
        form,
        error,
        bitbucket_tokens: bitbucket_token_options(state).await?,
        action_groups: ACTION_GROUPS,
        tokens: token_rows(state).await?,
    })
}

async fn bitbucket_token_options(state: &AppState) -> Result<Vec<BitbucketTokenOption>> {
    let tokens = state.bitbucket_token_service.list().await?;
    Ok(tokens
        .into_iter()
        .map(|token| BitbucketTokenOption {
            id: token.id,
            name: token.name,
        })
        .collect())
}

async fn token_rows(state: &AppState) -> Result<Vec<TokenRow>> {
    let now = OffsetDateTime::now_utc();
    let tokens = state.access_token_service.list().await?;
    Ok(tokens.into_iter().map(|token| TokenRow::new(token, now)).collect())
}

/// Collects the form fields, keeping rule cards in the order they appear.
fn parse_form(fields: Vec<(String, String)>) -> FormView {
    let mut form = FormView {
        name: String::new(),
        expiry: String::new(),
        rules: Vec::new(),
    };

    for (key, value) in fields {
        match key.as_str() {
            "name" => form.name = value,
            "expiry" => form.expiry = value,
            _ => {
                let Some((rule_key, field)) = key.strip_prefix("rule.").and_then(|rest| rest.split_once('.')) else {
                    continue;
                };

                // Keys come from the client, and they are echoed back into field names.
                if rule_key.is_empty() || !rule_key.chars().all(|c| c.is_ascii_alphanumeric()) {
                    continue;
                }

                let rule = match form.rules.iter().position(|rule| rule.key == rule_key) {
                    Some(idx) => &mut form.rules[idx],
                    None => {
                        form.rules.push(RuleView {
                            key: rule_key.to_owned(),
                            ..RuleView::empty()
                        });
                        form.rules.last_mut().expect("a rule was just pushed")
                    }
                };

                match field {
                    "bitbucket_token" => rule.bitbucket_token = value,
                    "actions" => rule.actions.push(value),
                    "project" => rule.project = value,
                    "repository" => rule.repository = value,
                    "branch" => rule.branch = value,
                    "source" => rule.source = value,
                    "target" => rule.target = value,
                    _ => {}
                }
            }
        }
    }

    form
}

/// Builds and validates the policy, with messages that point at the rule card to fix.
fn build_policy(rules: &[RuleView]) -> std::result::Result<Policy, String> {
    if rules.is_empty() {
        return Err("Add at least one rule".to_owned());
    }

    let mut specs = Vec::with_capacity(rules.len());
    for (idx, rule) in rules.iter().enumerate() {
        let number = idx + 1;

        let bitbucket_token = Uuid::parse_str(rule.bitbucket_token.trim())
            .map_err(|_| format!("Rule {number}: choose a Bitbucket token"))?;

        if rule.actions.is_empty() {
            return Err(format!("Rule {number}: select at least one action"));
        }

        specs.push(RuleSpec {
            bitbucket_token,
            actions: rule.actions.clone(),
            project: rule.project.trim().to_owned(),
            repository: rule.repository.trim().to_owned(),
            branches: crate::policy::BranchSpec {
                branch: globs(&rule.branch),
                source: globs(&rule.source),
                target: globs(&rule.target),
            },
        });
    }

    return Policy::try_from(PolicySpec::new(specs)).map_err(|error| match error {
        PolicyError::Rule { rule, error } => format!("Rule {rule}: {}", rule_error_message(error)),
        PolicyError::NoRules => "Add at least one rule".to_owned(),
        PolicyError::UnsupportedVersion(_) => "The permissions could not be saved".to_owned(),
    });

    fn globs(text: &str) -> Option<Vec<String>> {
        let globs: Vec<String> = text
            .split(',')
            .map(str::trim)
            .filter(|glob| !glob.is_empty())
            .map(str::to_owned)
            .collect();

        (!globs.is_empty()).then_some(globs)
    }
}

/// Explains why a rule is invalid, in words that fit both the form and the management API.
pub(super) fn rule_error_message(error: RuleError) -> String {
    match error {
        RuleError::NoActions => "select at least one action".to_owned(),
        RuleError::UnknownAction(unknown) => format!("unknown action {}", unknown.0),
        RuleError::Project(InvalidPattern::Empty) => "enter a project key or pattern".to_owned(),
        RuleError::Repository(InvalidPattern::Empty) => "enter a repository slug or pattern".to_owned(),
        RuleError::Project(error) => format!("invalid project: {error}"),
        RuleError::Repository(error) => format!("invalid repository: {error}"),
        RuleError::Branch { condition, error } => format!("invalid {condition} branch: {error}"),
        RuleError::EmptyBranchCondition(condition) => format!("enter at least one {condition} branch pattern"),
        RuleError::ConditionWithoutActions("branch") => {
            "the branch pattern only limits branch create, delete and Git pushes; select one of them or clear the pattern"
                .to_owned()
        }
        RuleError::ConditionWithoutActions(condition) => format!(
            "{condition} branches only limit pull request and comment actions; select one of them or clear the field"
        ),
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use secret::Secret;
    use uuid::Uuid;

    use crate::routes::testing::*;
    use crate::state::AppState;

    const ACCESS_TOKENS: &str = "/fgatbapi/access_tokens";

    async fn add_bitbucket_token(state: &AppState, name: &str) -> Uuid {
        state
            .bitbucket_token_service
            .add(name, Secret::new(format!("ATBB-{name}")))
            .await
            .unwrap()
    }

    fn create_request(cookie: &str, fields: &[(&str, &str)]) -> Request<Body> {
        with_form(
            authenticated(Request::post(ACCESS_TOKENS), cookie).header("hx-request", "true"),
            fields,
        )
    }

    /// Extracts the one-time token from the rendered section.
    fn issued_token(html: &str) -> &str {
        let start = html.find("fgatb_").expect("the token is shown");
        let end = html[start..].find('"').unwrap();
        &html[start..start + end]
    }

    /// Whether the first checkbox for `action` carries the `checked` attribute.
    ///
    /// The attribute is matched as a whole word, since scripts in the same tag mention `this.checked`.
    fn is_checked(html: &str, action: &str) -> bool {
        let value = format!(r#"value="{action}""#);
        let start = html[..html.find(&value).expect("the checkbox is rendered")]
            .rfind("<input")
            .unwrap();
        let end = start + html[start..].find('>').unwrap();
        html[start..end].split_whitespace().any(|word| word == "checked")
    }

    /// Whether the creation form is shown, and the button that opens it hidden.
    fn form_is_open(html: &str) -> bool {
        let tag = |start: &str| {
            let start = html.find(start).expect("the element is rendered");
            &html[start..start + html[start..].find('>').unwrap()]
        };
        // The `hidden` attribute comes last; scripts inside the tags mention `.hidden` too.
        let form_hidden = tag(r#"<form id="access-token-form""#).trim_end().ends_with(" hidden");
        let button_hidden = tag(r#"class="add-token""#).trim_end().ends_with("hidden");
        assert_ne!(
            form_hidden, button_hidden,
            "exactly one of the form and its button is shown"
        );
        !form_hidden
    }

    #[tokio::test]
    async fn page_requires_session() {
        let (app, _state) = setup().await;

        let response = send(&app, get("/webapp/access_tokens")).await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(location(&response), "/webapp/login");
    }

    #[tokio::test]
    async fn page_asks_for_a_bitbucket_token_first() {
        let (app, _state, cookie) = setup_logged_in().await;

        let html = body_text(send(&app, with_cookie(Request::get("/webapp/access_tokens"), &cookie)).await).await;

        assert!(html.contains(r#"<a href="/webapp/access_tokens">/access_tokens</a>"#));
        assert!(html.contains("Add a Bitbucket token"));
        assert!(!html.contains(r#"hx-post="/fgatbapi/access_tokens""#));
        assert!(html.contains("No tokens found"));
    }

    #[tokio::test]
    async fn create_shows_token_once_and_lists_it() {
        let (app, state, cookie) = setup_logged_in().await;
        let read = add_bitbucket_token(&state, "read").await.to_string();
        let write = add_bitbucket_token(&state, "write").await.to_string();

        let html = body_text(send(&app, with_cookie(Request::get("/webapp/access_tokens"), &cookie)).await).await;
        assert!(html.contains(r#"hx-post="/fgatbapi/access_tokens""#));
        assert!(html.contains(">Add access token</button>"));
        assert!(html.contains(r#"<p class="page-hint">Access tokens are what clients use"#));
        assert!(!form_is_open(&html), "the form opens with Add access token");
        // Rule cards only appear once the admin adds one.
        assert!(!html.contains(r#"class="rule-card""#));
        assert!(html.contains("Add a rule to choose what the token allows."));
        for option in [
            r#"<option value="1">1 day</option>"#,
            r#"<option value="7">7 days</option>"#,
            r#"<option value="30" selected>30 days</option>"#,
            r#"<option value="90">90 days</option>"#,
        ] {
            assert!(html.contains(option), "{option}");
        }
        assert_eq!(
            html.matches("<option value=").count(),
            4,
            "only the presets are offered"
        );
        assert!(!html.contains("expires_on"));

        let response = send(
            &app,
            create_request(
                &cookie,
                &[
                    ("name", "release-bot"),
                    ("expiry", "30"),
                    ("rule.a1.bitbucket_token", &read),
                    ("rule.a1.actions", "repo:read"),
                    ("rule.a1.project", "PROJ"),
                    ("rule.a1.repository", "docs"),
                    ("rule.b2.bitbucket_token", &write),
                    ("rule.b2.actions", "pr:create"),
                    ("rule.b2.actions", "pr:update"),
                    ("rule.b2.project", "PROJ"),
                    ("rule.b2.repository", "api"),
                    ("rule.b2.source", " feature/**, bugfix/* "),
                ],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let html = body_text(response).await;

        let token = issued_token(&html).to_owned();
        assert_eq!(html.matches(&token).count(), 1);
        assert!(html.contains("<td>release-bot</td>"));
        assert!(html.contains(r#"value="""#), "the form is cleared");
        assert!(!form_is_open(&html), "the form closes once the token is issued");

        let authenticated = state.access_token_service.authenticate(&token).await.unwrap().unwrap();
        assert_eq!(authenticated.name, "release-bot");
        let policy = serde_json::to_value(&authenticated.policy).unwrap();
        assert_eq!(policy["rules"][0]["repository"], "docs");
        assert_eq!(
            policy["rules"][1]["branches"]["source"],
            serde_json::json!(["feature/**", "bugfix/*"])
        );

        // The token is never shown again.
        let page = body_text(send(&app, with_cookie(Request::get("/webapp/access_tokens"), &cookie)).await).await;
        assert!(!page.contains("fgatb_"));
        assert!(page.contains("<td>release-bot</td>"));
    }

    #[tokio::test]
    async fn create_rejects_invalid_input_and_keeps_it() {
        let (app, state, cookie) = setup_logged_in().await;
        let read = add_bitbucket_token(&state, "read").await.to_string();
        let base = |extra: &[(&'static str, &'static str)]| {
            let mut fields = vec![
                ("name", "ci"),
                ("expiry", "7"),
                ("rule.k1.project", "PROJ"),
                ("rule.k1.repository", "api"),
                ("rule.k1.actions", "repo:read"),
            ];
            fields.extend_from_slice(extra);
            fields
        };

        let cases: Vec<(Vec<(&str, &str)>, &str)> = vec![
            (base(&[]), "Rule 1: choose a Bitbucket token"),
            (
                base(&[("rule.k1.source", "feature/**")]),
                "Rule 1: source branches only limit pull request and comment actions",
            ),
            (base(&[("expiry", "custom")]), "Choose when the token expires"),
            (base(&[("expiry", "14")]), "Choose when the token expires"),
            (vec![("name", "ci"), ("expiry", "7")], "Add at least one rule"),
        ];

        for (mut fields, message) in cases {
            let has_rule = fields.iter().any(|(key, _)| key.starts_with("rule."));
            if has_rule && message != "Rule 1: choose a Bitbucket token" {
                fields.push(("rule.k1.bitbucket_token", &read));
            }

            let response = send(&app, create_request(&cookie, &fields)).await;
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "{message}");
            let html = body_text(response).await;
            assert!(html.contains(message), "{message}: {html}");
            assert!(form_is_open(&html), "{message}: the form stays open to show the error");
            assert!(!html.contains("fgatb_"));
            if fields.iter().any(|(key, _)| key.starts_with("rule.")) {
                assert!(html.contains(r#"name="rule.k1.project" value="PROJ""#), "{message}");
                assert!(is_checked(&html, "repo:read"), "{message}");
            }
        }

        assert!(state.access_token_service.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn every_preset_sets_the_lifetime() {
        let (app, state, cookie) = setup_logged_in().await;
        let read = add_bitbucket_token(&state, "read").await.to_string();

        for days in ["1", "7", "30", "90"] {
            let before = time::OffsetDateTime::now_utc();
            let name = format!("token-{days}");
            let fields = [
                ("name", name.as_str()),
                ("expiry", days),
                ("rule.x.bitbucket_token", read.as_str()),
                ("rule.x.actions", "repo:read"),
                ("rule.x.project", "PROJ"),
                ("rule.x.repository", "api"),
            ];
            assert_eq!(
                send(&app, create_request(&cookie, &fields)).await.status(),
                StatusCode::OK
            );

            let token = state
                .access_token_service
                .list()
                .await
                .unwrap()
                .into_iter()
                .find(|token| token.name == name)
                .unwrap();
            let lifetime = token.expires_at - before;
            let expected = time::Duration::days(days.parse().unwrap());
            assert!(
                expected - time::Duration::minutes(1) < lifetime && lifetime < expected + time::Duration::minutes(1),
                "{days}: {lifetime}"
            );
        }
    }

    #[tokio::test]
    async fn new_rule_card_and_remove() {
        let (app, state, cookie) = setup_logged_in().await;
        let read = add_bitbucket_token(&state, "read").await.to_string();

        let response = send(
            &app,
            with_cookie(Request::post("/fgatbapi/access_tokens/rules"), &cookie),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let card = body_text(response).await;
        assert!(card.starts_with(r#"<fieldset class="rule-card">"#));
        assert!(card.contains(&format!(r#"<option value="{read}">read</option>"#)));

        let fields = [
            ("name", "ci"),
            ("expiry", "90"),
            ("rule.x.bitbucket_token", read.as_str()),
            ("rule.x.actions", "repo:read"),
            ("rule.x.project", "*"),
            ("rule.x.repository", "*"),
        ];
        send(&app, create_request(&cookie, &fields)).await;
        let id = state.access_token_service.list().await.unwrap()[0].id;

        let response = send(
            &app,
            authenticated(Request::delete(format!("{ACCESS_TOKENS}/{id}")), &cookie)
                .header("hx-request", "true")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_text(response).await.contains("No tokens found"));
        assert!(state.access_token_service.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn bitbucket_token_removal_warns_and_cascades() {
        let (app, state, cookie) = setup_logged_in().await;
        let read = add_bitbucket_token(&state, "read").await;

        let fields = [
            ("name", "ci"),
            ("expiry", "7"),
            ("rule.x.bitbucket_token", &*read.to_string()),
            ("rule.x.actions", "repo:read"),
            ("rule.x.project", "PROJ"),
            ("rule.x.repository", "api"),
        ];
        send(&app, create_request(&cookie, &fields)).await;

        let page = body_text(send(&app, with_cookie(Request::get("/webapp/bitbucket_tokens"), &cookie)).await).await;
        assert!(page.contains("These access tokens use it and will be removed too: &#34;ci&#34;."));

        let response = send(
            &app,
            authenticated(Request::delete(format!("/fgatbapi/bitbucket_tokens/{read}")), &cookie)
                .header("hx-request", "true")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.access_token_service.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn api_requires_session() {
        let (app, state) = setup().await;

        let response = send(
            &app,
            with_form(
                Request::post(ACCESS_TOKENS).header("hx-request", "true"),
                &[("name", "ci"), ("expiry", "7")],
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(state.access_token_service.list().await.unwrap().is_empty());
    }

    /// One card can grant reading and branch-limited writing together.
    #[tokio::test]
    async fn create_with_reading_and_branch_limited_actions() {
        let (app, state, cookie) = setup_logged_in().await;
        let personal = add_bitbucket_token(&state, "personal").await.to_string();

        let mut fields = vec![
            ("name", "sspi-rs-dev"),
            ("expiry", "90"),
            ("rule.r1.bitbucket_token", personal.as_str()),
            ("rule.r1.project", "WKN"),
            ("rule.r1.repository", "ironrdp"),
            ("rule.r1.source", "worktree/*"),
            ("rule.r1.target", "master,worktree-*"),
            ("rule.r1.branch", ""),
        ];
        for action in [
            "repo:read",
            "branch:create",
            "branch:delete",
            "pr:create",
            "pr:update",
            "pr:review",
            "pr:merge",
            "pr:decline",
            "pr:reopen",
            "pr:delete",
            "pr_comment:create",
            "pr_comment:update",
        ] {
            fields.push(("rule.r1.actions", action));
        }

        let response = send(&app, create_request(&cookie, &fields)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let token = issued_token(&body_text(response).await).to_owned();

        let policy = state
            .access_token_service
            .authenticate(&token)
            .await
            .unwrap()
            .unwrap()
            .policy;
        let policy = serde_json::to_value(&policy).unwrap();
        assert_eq!(
            policy["rules"][0]["branches"],
            serde_json::json!({ "source": ["worktree/*"], "target": ["master", "worktree-*"] })
        );
    }

    #[tokio::test]
    async fn new_rule_card_reads_by_default_and_explains_why() {
        let (app, state, cookie) = setup_logged_in().await;
        add_bitbucket_token(&state, "read").await;

        let card = body_text(
            send(
                &app,
                with_cookie(Request::post("/fgatbapi/access_tokens/rules"), &cookie),
            )
            .await,
        )
        .await;

        assert!(is_checked(&card, "repo:read"));
        for action in ["branch:create", "pr:create", "pr_comment:create"] {
            assert!(!is_checked(&card, action), "{action}");
        }

        // Unchecking reading asks first, and only reading does.
        assert_eq!(card.matches("data-uncheck-confirmation=").count(), 1);
        assert!(
            card.contains(r#"data-uncheck-confirmation="Without Repository: read, the client cannot read anything"#)
        );
        assert!(card.contains("Uncheck it anyway?"));

        assert!(card.contains(r#"data-tooltip="Most clients read before they change anything"#));
    }

    /// The default only applies to new cards: a rule submitted without reading comes back without it.
    #[tokio::test]
    async fn rejected_rules_keep_reading_unchecked() {
        let (app, state, cookie) = setup_logged_in().await;
        add_bitbucket_token(&state, "read").await;

        let response = send(
            &app,
            create_request(
                &cookie,
                &[
                    ("name", "ci"),
                    ("expiry", "7"),
                    ("rule.k1.project", "PROJ"),
                    ("rule.k1.repository", "api"),
                    ("rule.k1.actions", "pr:create"),
                ],
            ),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let html = body_text(response).await;
        assert!(!is_checked(&html, "repo:read"));
        assert!(is_checked(&html, "pr:create"));
    }

    #[tokio::test]
    async fn git_pushes_are_offered_with_branch_actions() {
        let (app, state, cookie) = setup_logged_in().await;
        let token = add_bitbucket_token(&state, "write").await.to_string();

        let card = body_text(
            send(
                &app,
                with_cookie(Request::post("/fgatbapi/access_tokens/rules"), &cookie),
            )
            .await,
        )
        .await;
        let branches_row = card
            .split(r#"<div class="action-group">"#)
            .find(|row| row.contains("Branches"))
            .unwrap();
        assert!(branches_row.contains(r#"value="branch:push""#));
        assert!(branches_row.contains("> Allow Git</label>"));
        assert!(branches_row.contains(r#"data-tooltip="Allow Git lets the client push to the branches that match the pattern with Git over HTTPS, force pushes included."#));
        assert!(!is_checked(&card, "branch:push"));
        assert_eq!(card.matches(r#"class="help-icon""#).count(), 2);

        // A rule with only Git pushes is valid, and the branch pattern limits it.
        let response = send(
            &app,
            create_request(
                &cookie,
                &[
                    ("name", "pusher"),
                    ("expiry", "7"),
                    ("rule.g.bitbucket_token", &token),
                    ("rule.g.project", "PROJ"),
                    ("rule.g.repository", "api"),
                    ("rule.g.actions", "branch:push"),
                    ("rule.g.branch", "bot/**"),
                ],
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let token = issued_token(&body_text(response).await).to_owned();
        let policy = state
            .access_token_service
            .authenticate(&token)
            .await
            .unwrap()
            .unwrap()
            .policy;
        let policy = serde_json::to_value(&policy).unwrap();
        assert_eq!(policy["rules"][0]["actions"], serde_json::json!(["branch:push"]));
        assert_eq!(policy["rules"][0]["branches"]["branch"], serde_json::json!(["bot/**"]));
    }

    #[tokio::test]
    async fn branch_pattern_sits_with_branch_actions() {
        let (app, state, cookie) = setup_logged_in().await;
        add_bitbucket_token(&state, "read").await;

        let card = body_text(
            send(
                &app,
                with_cookie(Request::post("/fgatbapi/access_tokens/rules"), &cookie),
            )
            .await,
        )
        .await;

        let branches_row = card
            .split(r#"<div class="action-group">"#)
            .find(|row| row.contains("Branches"))
            .unwrap();
        assert!(branches_row.contains(r#"value="branch:create""#));
        assert!(branches_row.contains(r#"class="branch-pattern""#));
        assert!(card.contains("(all commits, branches, PRs and their comments)"));
        for removed in ["branch:read", "pr:read", "pr_comment:read"] {
            assert!(!card.contains(removed), "{removed}");
        }
    }
}
