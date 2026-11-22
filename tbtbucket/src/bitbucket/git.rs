//! Git over HTTPS: which repository a request is for, what a push changes, and how a denied push is reported.
//!
//! See the Git over HTTPS section of `docs/access-model.md`.

use axum::http::Method;

use super::classify::{Unsupported, normalize};
use crate::policy::Action;

/// Largest command list read from the head of a push, before the pack.
///
/// A command is about a hundred bytes, so this fits thousands of refs.
pub(crate) const MAX_PUSH_HEAD_LEN: usize = 1024 * 1024;

/// A Git request for one repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitRequest {
    pub(crate) project: String,
    pub(crate) repository: String,
    pub(crate) service: GitService,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GitService {
    /// `info/refs?service=git-upload-pack` and `git-upload-pack`: clone, fetch, pull and `ls-remote`.
    Fetch,
    /// `info/refs?service=git-receive-pack`: the refs a push starts from.
    PushAdvertisement,
    /// `git-receive-pack`: the ref commands, then the pack.
    Push,
}

/// Classifies a request under `/scm/{project}/{repository}[.git]/…` by method, raw path and raw query.
pub(crate) fn classify(method: &Method, raw_path: &str, query: Option<&str>) -> Result<GitRequest, Unsupported> {
    let segments = normalize(raw_path)?;
    let segments: Vec<&str> = segments.iter().map(String::as_str).collect();

    let ["scm", project, repository, tail @ ..] = segments.as_slice() else {
        return Err(Unsupported::Endpoint);
    };

    if project.starts_with('~') {
        return Err(Unsupported::PersonalRepository);
    }

    let repository = repository.strip_suffix(".git").unwrap_or(repository);
    if repository.is_empty() {
        return Err(Unsupported::MalformedPath);
    }

    let service = match (tail, method) {
        (["info", "refs"], &Method::GET) => match service_parameter(query) {
            Some("git-upload-pack") => GitService::Fetch,
            Some("git-receive-pack") => GitService::PushAdvertisement,
            // Without `service`, Git falls back to the dumb protocol, which Bitbucket does not serve either.
            _ => return Err(Unsupported::Endpoint),
        },
        (["git-upload-pack"], &Method::POST) => GitService::Fetch,
        (["git-receive-pack"], &Method::POST) => GitService::Push,
        _ => return Err(Unsupported::Endpoint),
    };

    Ok(GitRequest {
        project: (*project).to_owned(),
        repository: repository.to_owned(),
        service,
    })
}

fn service_parameter(query: Option<&str>) -> Option<&str> {
    query?.split('&').find_map(|pair| pair.strip_prefix("service="))
}

/// One `<old-id> <new-id> <ref>` command of a push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefCommand {
    pub(crate) old_id: String,
    pub(crate) new_id: String,
    pub(crate) refname: String,
}

/// What a command does, as far as rules are concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefChange<'a> {
    /// Creating or updating a branch, force pushes included.
    WriteBranch(&'a str),
    DeleteBranch(&'a str),
    /// A tag or any other ref, which is never allowed.
    Other,
}

impl RefCommand {
    pub(crate) fn change(&self) -> RefChange<'_> {
        let Some(branch) = self.refname.strip_prefix("refs/heads/") else {
            return RefChange::Other;
        };

        if is_zero_id(&self.new_id) {
            RefChange::DeleteBranch(branch)
        } else {
            RefChange::WriteBranch(branch)
        }
    }
}

impl<'a> RefChange<'a> {
    /// The action and branch a rule must allow, together with `branch:git`, and a verb for messages.
    pub(crate) fn requirement(self) -> Option<(Action, &'static str, &'a str)> {
        match self {
            Self::WriteBranch(branch) => Some((Action::BranchCreate, "push to", branch)),
            Self::DeleteBranch(branch) => Some((Action::BranchDelete, "delete", branch)),
            Self::Other => None,
        }
    }
}

fn is_zero_id(id: &str) -> bool {
    id.bytes().all(|byte| byte == b'0')
}

/// The head of a push request: the ref commands and the capabilities the client asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PushHead {
    pub(crate) commands: Vec<RefCommand>,
    pub(crate) capabilities: Vec<String>,
}

impl PushHead {
    fn has_capability(&self, name: &str) -> bool {
        self.capabilities.iter().any(|capability| capability == name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum PushHeadError {
    #[error("push request is malformed")]
    Malformed,

    #[error("push has no ref updates")]
    NoCommands,

    #[error("signed pushes are not supported")]
    SignedPush,
}

/// Parses the commands at the start of a `git-receive-pack` request body.
///
/// Returns `Ok(None)` while `body` ends before the flush packet that closes the command list.
/// Leading `shallow` lines, sent by shallow clones, are skipped.
pub(crate) fn parse_push_head(body: &[u8]) -> Result<Option<PushHead>, PushHeadError> {
    let mut rest = body;
    let mut commands = Vec::new();
    let mut capabilities = Vec::new();

    loop {
        let Some((packet, remaining)) = next_packet(rest)? else {
            return Ok(None);
        };
        rest = remaining;

        let Some(line) = packet else {
            // The flush packet ends the command list.
            if commands.is_empty() {
                return Err(PushHeadError::NoCommands);
            }
            return Ok(Some(PushHead { commands, capabilities }));
        };

        let (line, line_capabilities) = match line.iter().position(|&byte| byte == 0) {
            Some(nul) => (&line[..nul], Some(&line[nul + 1..])),
            None => (line, None),
        };
        let line = std::str::from_utf8(line).map_err(|_| PushHeadError::Malformed)?;
        let line = line.strip_suffix('\n').unwrap_or(line);

        if line.starts_with("shallow ") && commands.is_empty() {
            continue;
        }
        if line.starts_with("push-cert") {
            return Err(PushHeadError::SignedPush);
        }

        let mut parts = line.splitn(3, ' ');
        let (Some(old_id), Some(new_id), Some(refname)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(PushHeadError::Malformed);
        };
        if !(is_object_id(old_id) && is_object_id(new_id)) || refname.is_empty() {
            return Err(PushHeadError::Malformed);
        }

        if let Some(line_capabilities) = line_capabilities {
            let line_capabilities = std::str::from_utf8(line_capabilities).map_err(|_| PushHeadError::Malformed)?;
            capabilities.extend(line_capabilities.split_whitespace().map(str::to_owned));
        }

        commands.push(RefCommand {
            old_id: old_id.to_owned(),
            new_id: new_id.to_owned(),
            refname: refname.to_owned(),
        });
    }
}

/// SHA-1 or SHA-256 object IDs in lowercase hex.
fn is_object_id(id: &str) -> bool {
    matches!(id.len(), 40 | 64) && id.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Splits the next pkt-line off `data`: `Some(None)` is a flush packet, and `None` means more data is needed.
#[expect(
    clippy::type_complexity,
    reason = "a private helper whose shape the doc comment explains"
)]
fn next_packet(data: &[u8]) -> Result<Option<(Option<&[u8]>, &[u8])>, PushHeadError> {
    let Some(length) = data.get(..4) else {
        return Ok(None);
    };
    let length = std::str::from_utf8(length).map_err(|_| PushHeadError::Malformed)?;
    let length = usize::from_str_radix(length, 16).map_err(|_| PushHeadError::Malformed)?;

    match length {
        0 => Ok(Some((None, &data[4..]))),
        // Delimiter and response-end packets do not occur in a push request.
        1..=4 => Err(PushHeadError::Malformed),
        _ => match data.get(4..length) {
            Some(payload) => Ok(Some((Some(payload), &data[length..]))),
            None => Ok(None),
        },
    }
}

/// The response to a push that is denied as a whole, in Git's own report format when the client asked for it.
///
/// `git push` then shows every ref as rejected, with `reason` next to `denied_ref` and the message on its terminal.
/// Returns `None` when the client did not ask for a report, so that a plain error is answered instead.
pub(crate) fn push_denial_report(head: &PushHead, denied_ref: &str, reason: &str) -> Option<Vec<u8>> {
    if !(head.has_capability("report-status") || head.has_capability("report-status-v2")) {
        return None;
    }

    let mut report = Vec::new();
    // The proxy never unpacks anything, so there is no unpacking error to report.
    report.extend(packet(b"unpack ok\n"));
    for command in &head.commands {
        let status = if command.refname == denied_ref {
            format!("ng {} {reason}\n", command.refname)
        } else {
            format!("ng {} push denied as a whole\n", command.refname)
        };
        report.extend(packet(status.as_bytes()));
    }
    report.extend(FLUSH);

    let band_size = if head.has_capability("side-band-64k") {
        65515
    } else if head.has_capability("side-band") {
        995
    } else {
        return Some(report);
    };

    // With a side band, the report travels on band 1 and messages for the terminal on band 2.
    let mut response = Vec::new();
    let message = format!("access token denied the push: {reason}\n");
    response.extend(packet(&[&[2], message.as_bytes()].concat()));
    for chunk in report.chunks(band_size) {
        response.extend(packet(&[&[1], chunk].concat()));
    }
    response.extend(FLUSH);

    Some(response)
}

const FLUSH: &[u8] = b"0000";

fn packet(payload: &[u8]) -> Vec<u8> {
    let mut packet = format!("{:04x}", payload.len() + 4).into_bytes();
    packet.extend_from_slice(payload);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = "1111111111111111111111111111111111111111";
    const NEW: &str = "2222222222222222222222222222222222222222";
    const ZERO: &str = "0000000000000000000000000000000000000000";

    fn git(method: Method, path: &str, query: Option<&str>) -> Result<GitRequest, Unsupported> {
        classify(&method, path, query)
    }

    fn push_body(lines: &[&str]) -> Vec<u8> {
        let mut body = Vec::new();
        for line in lines {
            body.extend(packet(line.as_bytes()));
        }
        body.extend(FLUSH);
        body.extend(b"PACK\0\0\0\x02rest of the pack");
        body
    }

    #[test]
    fn classifies_smart_http_requests() {
        let fetch = git(
            Method::GET,
            "/scm/PROJ/api.git/info/refs",
            Some("service=git-upload-pack"),
        )
        .unwrap();
        assert_eq!(
            fetch,
            GitRequest {
                project: "PROJ".to_owned(),
                repository: "api".to_owned(),
                service: GitService::Fetch,
            }
        );

        for (method, path, query, service) in [
            (
                Method::POST,
                "/scm/proj/api.git/git-upload-pack",
                None,
                GitService::Fetch,
            ),
            (
                Method::GET,
                "/scm/proj/api/info/refs",
                Some("service=git-upload-pack"),
                GitService::Fetch,
            ),
            (
                Method::GET,
                "/scm/proj/api.git/info/refs",
                Some("service=git-receive-pack"),
                GitService::PushAdvertisement,
            ),
            (
                Method::POST,
                "/scm/proj/api.git/git-receive-pack",
                None,
                GitService::Push,
            ),
        ] {
            let request = git(method.clone(), path, query).unwrap();
            assert_eq!(request.repository, "api", "{path}");
            assert_eq!(request.service, service, "{method} {path}");
        }
    }

    #[test]
    fn denies_everything_else_under_scm() {
        for (method, path, query) in [
            (Method::GET, "/scm/proj/api.git/info/refs", None),
            (
                Method::GET,
                "/scm/proj/api.git/info/refs",
                Some("service=git-upload-archive"),
            ),
            (Method::GET, "/scm/proj/api.git/HEAD", None),
            (Method::GET, "/scm/proj/api.git/objects/info/packs", None),
            (Method::POST, "/scm/proj/api.git/info/lfs/objects/batch", None),
            (Method::GET, "/scm/proj/api.git/git-upload-pack", None),
            (Method::POST, "/scm/proj/api.git/git-upload-archive", None),
            (Method::GET, "/scm/proj", None),
        ] {
            assert_eq!(
                git(method.clone(), path, query),
                Err(Unsupported::Endpoint),
                "{method} {path}"
            );
        }

        assert_eq!(
            git(Method::POST, "/scm/~alice/dotfiles.git/git-upload-pack", None),
            Err(Unsupported::PersonalRepository)
        );
        assert_eq!(
            git(Method::POST, "/scm/proj/api.git/../web.git/git-upload-pack", None),
            Err(Unsupported::MalformedPath)
        );
        assert_eq!(
            git(Method::POST, "/scm/proj/.git/git-upload-pack", None),
            Err(Unsupported::MalformedPath)
        );
    }

    #[test]
    fn parses_push_commands() {
        let body = push_body(&[
            &format!("{OLD} {NEW} refs/heads/main\0 report-status side-band-64k agent=git/2.56.0\n"),
            &format!("{ZERO} {NEW} refs/heads/feature/x\n"),
            &format!("{OLD} {ZERO} refs/heads/old\n"),
            &format!("{ZERO} {NEW} refs/tags/v1\n"),
        ]);

        let head = parse_push_head(&body).unwrap().unwrap();
        assert_eq!(
            head.capabilities,
            ["report-status", "side-band-64k", "agent=git/2.56.0"]
        );
        let changes: Vec<_> = head.commands.iter().map(RefCommand::change).collect();
        assert_eq!(
            changes,
            [
                RefChange::WriteBranch("main"),
                RefChange::WriteBranch("feature/x"),
                RefChange::DeleteBranch("old"),
                RefChange::Other,
            ]
        );
    }

    #[test]
    fn parsing_waits_for_the_whole_command_list() {
        let body = push_body(&[&format!("{OLD} {NEW} refs/heads/main\0report-status\n")]);
        let flush = body.windows(4).position(|window| window == FLUSH).unwrap();

        for end in [0, 3, 4, 20, flush, flush + 3] {
            assert_eq!(parse_push_head(&body[..end]), Ok(None), "{end}");
        }
        assert!(parse_push_head(&body[..flush + 4]).unwrap().is_some());
    }

    #[test]
    fn parses_shallow_lines_and_sha256_ids() {
        let old = "a".repeat(64);
        let new = "b".repeat(64);
        let body = push_body(&[
            &format!("shallow {OLD}\n"),
            &format!("{old} {new} refs/heads/main\0report-status\n"),
        ]);

        let head = parse_push_head(&body).unwrap().unwrap();
        assert_eq!(head.commands[0].change(), RefChange::WriteBranch("main"));
    }

    #[test]
    fn rejects_malformed_and_unsupported_pushes() {
        for (body, error) in [
            (push_body(&[]), PushHeadError::NoCommands),
            (push_body(&["push-cert\0report-status\n"]), PushHeadError::SignedPush),
            (push_body(&[&format!("{OLD} {NEW}\n")]), PushHeadError::Malformed),
            (
                push_body(&[&format!("{OLD} xyz refs/heads/main\n")]),
                PushHeadError::Malformed,
            ),
            (push_body(&[&format!("{OLD} {NEW} \n")]), PushHeadError::Malformed),
            (b"zzzz".to_vec(), PushHeadError::Malformed),
            (b"0001".to_vec(), PushHeadError::Malformed),
        ] {
            assert_eq!(
                parse_push_head(&body),
                Err(error),
                "{:?}",
                String::from_utf8_lossy(&body)
            );
        }
    }

    fn head(capabilities: &str) -> PushHead {
        parse_push_head(&push_body(&[
            &format!("{OLD} {NEW} refs/heads/main\0{capabilities}\n"),
            &format!("{ZERO} {NEW} refs/heads/bot/x\n"),
        ]))
        .unwrap()
        .unwrap()
    }

    /// Splits pkt-lines into their payloads, with `None` for flush packets, checking every length on the way.
    fn packets(mut data: &[u8]) -> Vec<Option<Vec<u8>>> {
        let mut packets = Vec::new();
        while !data.is_empty() {
            let (packet, rest) = next_packet(data).unwrap().expect("a whole packet");
            packets.push(packet.map(<[u8]>::to_vec));
            data = rest;
        }
        packets
    }

    fn lines(lines: &[&str]) -> Vec<Option<Vec<u8>>> {
        lines
            .iter()
            .map(|line| (!line.is_empty()).then(|| line.as_bytes().to_vec()))
            .collect()
    }

    #[test]
    fn denial_report_without_side_band() {
        let report = push_denial_report(&head("report-status"), "refs/heads/main", "not allowed").unwrap();

        assert_eq!(
            packets(&report),
            lines(&[
                "unpack ok\n",
                "ng refs/heads/main not allowed\n",
                "ng refs/heads/bot/x push denied as a whole\n",
                "",
            ])
        );
    }

    #[test]
    fn denial_report_on_side_band() {
        let report = push_denial_report(&head("report-status-v2 side-band-64k"), "refs/heads/main", "no").unwrap();
        let bands = packets(&report);

        assert_eq!(bands.len(), 3);
        assert_eq!(
            bands[0].as_deref(),
            Some(&b"\x02access token denied the push: no\n"[..])
        );
        let report = bands[1]
            .as_deref()
            .unwrap()
            .strip_prefix(&[1])
            .expect("the report is on band 1");
        assert_eq!(
            packets(report),
            lines(&[
                "unpack ok\n",
                "ng refs/heads/main no\n",
                "ng refs/heads/bot/x push denied as a whole\n",
                "",
            ])
        );
        assert_eq!(bands[2], None);
    }

    #[test]
    fn no_report_unless_asked_for() {
        assert!(push_denial_report(&head("side-band-64k"), "refs/heads/main", "no").is_none());
    }
}
