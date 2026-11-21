
# Tbtbucket

Fine-grained access tokens for Bitbucket.
This project is a proxy server for the Bitbucket service.
The proxy's main task is to generate access tokens, intercept client requests, check access and permissions, and proxy or deny them.
The main goal is to allow AI agents and API clients to work with Bitbucket repositories and projects while minimizing the risk of harmful requests.

## Writing for the repository

Committed text (code, comments, docs, commit messages) and PR titles and descriptions never refer to work stages, decision identifiers, agent roles, sessions or planning documents.
State rationale, not history.

## Rust

Write Rust with the `rust-style` skill.
Library crates expose typed errors; see `STYLE.md` § Error types.
Think before silencing a lint, then use `#[expect(<lint>, reason = "...")]` so the suppression explains itself and expires when it stops being needed.
