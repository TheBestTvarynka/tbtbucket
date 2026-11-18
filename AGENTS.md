
# FGAT Bitbucket

Fine grained access tokens for Bitbucket.
This project is a proxy server for the Bitbucket service.
The main goal is to intercept client requests, check for access and permissions to send this request, and proxy or deny the request.

## Writing for the repository

Committed text (code, comments, docs, commit messages) and PR titles and descriptions never refer to work stages, decision identifiers, agent roles, sessions or planning documents.
State rationale, not history.

## Rust

Write Rust with the `rust-style` skill.
Library crates expose typed errors, not `anyhow`; see `STYLE.md` § Error types.
Think before silencing a lint, then use `#[expect(<lint>, reason = "...")]` so the suppression explains itself and expires when it stops being needed.
