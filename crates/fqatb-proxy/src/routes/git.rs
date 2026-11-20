//! Git over HTTPS through the proxy: fetches and pushes under `/scm/…`.
//!
//! Fetches are checked by their repository alone and streamed both ways.
//! A push is checked by the ref commands at the start of its body; the pack after them is streamed to Bitbucket
//! without being held.
//! Errors are plain text, which Git shows to the user as `remote: …`, and a denied push is answered in Git's own
//! report format, so `git push` names the denied ref.

use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse as _, Response};
use futures_util::{StreamExt as _, stream};
use tracing::{debug, error, warn};

use super::proxy::{internal_error, upstream_response};
use crate::bitbucket::git::{
    GitRequest, GitService, MAX_PUSH_HEAD_LEN, PushHead, PushHeadError, RefCommand, classify, parse_push_head,
    push_denial_report,
};
use crate::db::AccessToken;
use crate::error::report;
use crate::policy::{Action, Request as PolicyRequest};
use crate::services::{Allowed, Decision};
use crate::state::AppState;

pub(super) async fn git(state: &AppState, token: &AccessToken, request: Request) -> Response {
    let (parts, body) = request.into_parts();

    let git = match classify(&parts.method, parts.uri.path(), parts.uri.query()) {
        Ok(git) => git,
        Err(unsupported) => {
            warn!(access_token_id = %token.id, method = %parts.method, path = parts.uri.path(), reason = %unsupported, "Denied unsupported Git request");
            return git_error(StatusCode::FORBIDDEN, &format!("{unsupported}"));
        }
    };

    match git.service {
        GitService::Fetch | GitService::PushAdvertisement => {
            let decision = match decide_without_commands(state, token, &git).await {
                Ok(decision) => decision,
                Err(error) => return internal_error(&error),
            };
            let forwarded = reqwest::Body::wrap_stream(body.into_data_stream());
            respond(state, token, &git, decision, parts, forwarded).await
        }
        GitService::Push => push(state, token, &git, parts, body).await,
    }
}

/// Fetches need `repo:read`; the refs a push starts from need `repo:read` or `branch:git`.
async fn decide_without_commands(state: &AppState, token: &AccessToken, git: &GitRequest) -> crate::Result<Decision> {
    let policy = &token.policy;
    let (project, repository) = (git.project.as_str(), git.repository.as_str());

    let matched = match git.service {
        GitService::Fetch => policy.matching_rule(&PolicyRequest {
            action: Action::RepoRead,
            project,
            repository,
            branch: None,
            source: None,
            target: None,
        }),
        _ => policy.first_rule_covering(&[Action::RepoRead, Action::BranchGit], project, repository),
    };

    match matched {
        Some((idx, rule)) => state.proxy_service.allow_with_rule(idx, rule).await,
        None if git.service == GitService::Fetch => Ok(Decision::Deny(format!(
            "access token does not allow {} on {project}/{repository}",
            Action::RepoRead
        ))),
        None => Ok(Decision::Deny(format!(
            "access token does not allow Git pushes to {project}/{repository}"
        ))),
    }
}

async fn push(state: &AppState, token: &AccessToken, git: &GitRequest, parts: Parts, body: Body) -> Response {
    // Git does not compress push requests, and the commands could not be read if it did.
    if parts
        .headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|encoding| encoding != "identity")
    {
        return git_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "compressed push requests are not supported",
        );
    }

    let mut stream = body.into_data_stream();
    let mut received = Vec::new();
    let head = loop {
        match parse_push_head(&received) {
            Ok(Some(head)) => break head,
            Ok(None) if MAX_PUSH_HEAD_LEN < received.len() => {
                return git_error(StatusCode::PAYLOAD_TOO_LARGE, "push updates too many refs at once");
            }
            Ok(None) => match stream.next().await {
                Some(Ok(chunk)) => received.extend_from_slice(&chunk),
                Some(Err(error)) => {
                    debug!(error = report(&error), "Reading the push request failed");
                    return git_error(StatusCode::BAD_REQUEST, "push request ended early");
                }
                None => return git_error(StatusCode::BAD_REQUEST, "push request ended early"),
            },
            Err(error @ (PushHeadError::Malformed | PushHeadError::NoCommands | PushHeadError::SignedPush)) => {
                warn!(access_token_id = %token.id, project = git.project, repository = git.repository, reason = %error, "Denied Git push");
                return git_error(StatusCode::FORBIDDEN, &error.to_string());
            }
        }
    };

    let decision = match decide_push(state, token, git, &head).await {
        Ok(decision) => decision,
        Err(error) => return internal_error(&error),
    };

    let allowed = match decision {
        PushDecision::Allow(allowed) => allowed,
        PushDecision::Deny { refname, reason } => {
            warn!(
                access_token_id = %token.id,
                project = git.project,
                repository = git.repository,
                refname,
                %reason,
                "Denied Git push"
            );

            // Git sends the whole pack before it reads the response, so it is read and dropped first.
            while let Some(Ok(_)) = stream.next().await {}

            return match push_denial_report(&head, &refname, &reason) {
                Some(report) => (
                    [
                        (
                            header::CONTENT_TYPE,
                            HeaderValue::from_static("application/x-git-receive-pack-result"),
                        ),
                        (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
                    ],
                    report,
                )
                    .into_response(),
                None => git_error(StatusCode::FORBIDDEN, &reason),
            };
        }
    };

    // What was read to find the commands goes first, then the rest of the pack as it arrives.
    let forwarded = stream::once(async move { Ok::<_, axum::Error>(Bytes::from(received)) }).chain(stream);
    respond(
        state,
        token,
        git,
        Decision::Allow(allowed),
        parts,
        reqwest::Body::wrap_stream(forwarded),
    )
    .await
}

enum PushDecision {
    Allow(Allowed),
    /// The push is denied as a whole; `refname` is the ref the reason is about.
    Deny {
        refname: String,
        reason: String,
    },
}

/// Finds the first rule that allows every command of the push, or the reason, naming one ref, that none does.
async fn decide_push(
    state: &AppState,
    token: &AccessToken,
    git: &GitRequest,
    head: &PushHead,
) -> crate::Result<PushDecision> {
    let policy = &token.policy;
    let (project, repository) = (git.project.as_str(), git.repository.as_str());
    let deny = |command: &RefCommand, reason: String| PushDecision::Deny {
        refname: command.refname.clone(),
        reason,
    };

    let mut changes = Vec::with_capacity(head.commands.len());
    for command in &head.commands {
        match command.change().requirement() {
            Some((action, _, branch)) => changes.push((action, branch)),
            None => {
                return Ok(deny(
                    command,
                    "only branches can be pushed through the proxy".to_owned(),
                ));
            }
        }
    }

    if let Some((idx, rule)) = policy.git_push_rule(project, repository, &changes) {
        return Ok(match state.proxy_service.allow_with_rule(idx, rule).await? {
            Decision::Allow(allowed) => PushDecision::Allow(allowed),
            Decision::Deny(reason) => deny(&head.commands[0], reason),
        });
    }

    // Explain the denial with the first rule that could have allowed the push.
    let Some((_, candidate)) = policy.git_push_candidates(project, repository).next() else {
        return Ok(deny(
            &head.commands[0],
            format!("access token does not allow Git pushes to {project}/{repository}"),
        ));
    };

    for command in &head.commands {
        let (action, verb, branch) = command
            .change()
            .requirement()
            .expect("every command is a branch change by now");
        if !candidate.allows_git_change(action, project, repository, branch) {
            return Ok(deny(
                command,
                format!("access token does not allow Git to {verb} branch {branch}"),
            ));
        }
    }

    // The first candidate allows every command on its own, so the push needs refs from other rules too.
    Ok(deny(
        &head.commands[0],
        "no single rule of the access token allows every ref of this push; push them separately".to_owned(),
    ))
}

async fn respond(
    state: &AppState,
    token: &AccessToken,
    git: &GitRequest,
    decision: Decision,
    parts: Parts,
    forwarded: reqwest::Body,
) -> Response {
    let allowed = match decision {
        Decision::Allow(allowed) => allowed,
        Decision::Deny(reason) => {
            warn!(access_token_id = %token.id, project = git.project, repository = git.repository, service = ?git.service, %reason, "Denied Git request");
            return git_error(StatusCode::FORBIDDEN, &reason);
        }
    };

    debug!(
        access_token_id = %token.id,
        project = git.project,
        repository = git.repository,
        service = ?git.service,
        rule = allowed.rule + 1,
        bitbucket_token_id = %allowed.bitbucket_token_id,
        "Allowed Git request"
    );

    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or(parts.uri.path(), |value| value.as_str())
        .to_owned();

    match state
        .proxy_service
        .forward(
            parts.method,
            &path_and_query,
            parts.headers,
            forwarded,
            &allowed.bitbucket_token,
        )
        .await
    {
        Ok(upstream) => upstream_response(upstream),
        Err(error) => {
            error!(error = report(&error), "Forwarding Git to Bitbucket failed");
            git_error(StatusCode::BAD_GATEWAY, "Bitbucket is unreachable")
        }
    }
}

/// A plain-text error, which Git prints as `remote: <message>`.
fn git_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        format!("{message}\n"),
    )
        .into_response()
}
