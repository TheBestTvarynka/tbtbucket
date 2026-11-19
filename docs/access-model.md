# Access model

The proxy sits in front of a Bitbucket Data Center server.
Clients call it exactly as they would call Bitbucket, but authenticate with an access token issued by the proxy.
For every request, the proxy decides whether the access token allows it, and if so, forwards it to Bitbucket with a stored Bitbucket token.

This document defines access tokens, their permissions, and how a request is turned into a permission check.
It targets the Bitbucket Data Center REST API first and is designed to cover Git over HTTPS without format changes.

## Terms

- **Bitbucket token**: a Bitbucket Data Center HTTP access token, stored encrypted in the `bitbucket_tokens` table and managed in the admin panel.
  It is never given to clients.
- **Access token**: a token issued by the proxy (`fgatb_…`) and given to clients.
  It carries a policy and may use several Bitbucket tokens.
- **Policy**: the permissions of an access token, as a list of rules.
- **Rule**: one grant: a set of actions on a set of repositories, optionally limited to branch patterns, executed with one Bitbucket token.
- **Action**: an operation in neutral terms, such as `pr:create`, independent of whether it arrives over REST or Git.

## Access tokens

### Format

```text
fgatb_<base64url(id ‖ secret ‖ tag)>
```

| Part | Size | Content |
| --- | --- | --- |
| `id` | 16 bytes | The access token UUID, as stored in `access_tokens.id`. |
| `secret` | 32 bytes | Random bytes from the operating system RNG. |
| `tag` | 32 bytes | `HMAC-SHA256(token_mac_key, id ‖ secret)`. |

The payload is 80 bytes, encoded as unpadded URL-safe base64 (107 characters), so a token is 113 characters long.

`token_mac_key` is derived from the master key (`FQATB_ENCRYPTION_KEY`) with HKDF-SHA256, using its own hardcoded salt, like the database and session ciphers.
Changing the master key therefore invalidates every access token, as it invalidates all other encrypted data.

### Verification

A presented token is accepted only if every step succeeds, in this order:

1. It starts with `fgatb_` and the rest decodes to exactly 80 bytes.
2. The tag matches `HMAC-SHA256(token_mac_key, id ‖ secret)`, compared in constant time.
3. A row with `id` exists in `access_tokens`.
4. `SHA-256(secret)` equals `secret_hash`, compared in constant time.
5. `expires_at` is in the future.

The two checks protect against different leaks:

- The tag makes guessed or forged tokens fail at step 2, without touching the database.
  Someone holding a copy of the database cannot mint tokens, because the MAC key is not stored there.
- The secret hash makes tokens minted with a leaked MAC key fail at step 4, because a valid `secret` is needed for an existing `id`.

SHA-256 is used instead of Argon2 because the secret is 256 random bits: a slow hash adds no protection against guessing, while it would add tens of milliseconds to every proxied request.

The full token is shown once, right after creation, and never stored.
A lost token cannot be recovered and is replaced by creating a new one.

### Storage

```sql
CREATE TABLE access_tokens (
    id          TEXT PRIMARY KEY NOT NULL,     -- UUID, also embedded in the token
    name        TEXT NOT NULL UNIQUE,
    secret_hash BLOB NOT NULL,                 -- SHA-256 of the secret part, stored as is
    permissions BLOB NOT NULL,                 -- policy JSON, encrypted with the database cipher and bound to the row ID
    created_at  TEXT NOT NULL CHECK (/* RFC 3339 UTC with whole seconds */),
    expires_at  TEXT NOT NULL CHECK (/* RFC 3339 UTC with whole seconds */)
) STRICT;

-- Which Bitbucket tokens each access token's policy uses.
-- The policy is encrypted, so the database cannot look inside it; this table is derived from the policy whenever it is written.
CREATE TABLE access_token_bitbucket_tokens (
    access_token_id    TEXT NOT NULL REFERENCES access_tokens (id) ON DELETE CASCADE,
    bitbucket_token_id TEXT NOT NULL REFERENCES bitbucket_tokens (id) ON DELETE CASCADE,
    PRIMARY KEY (access_token_id, bitbucket_token_id)
) STRICT;
```

`secret_hash` is stored unencrypted for the same reason as the admin password hash: it is a one-way hash of a high-entropy secret.
Identifiers in the link table are stored as is, like every other identifier.

### Lifetime

Every access token expires.
The admin panel offers presets of 7, 30 and 90 days and a custom date.
Expired tokens are rejected and stay listed as expired until removed.

### Removing a Bitbucket token

Removing a Bitbucket token also removes every access token whose policy uses it, because such a policy can no longer be executed as written.
Before removal, the admin panel lists the affected access tokens by name and asks for confirmation.

Both deletions happen in one transaction:

```sql
DELETE FROM access_tokens
WHERE id IN (SELECT access_token_id FROM access_token_bitbucket_tokens WHERE bitbucket_token_id = ?);

DELETE FROM bitbucket_tokens WHERE id = ?;
```

SQLite enforces foreign keys only when `PRAGMA foreign_keys = ON` is set on the connection.
sqlx sets it on every connection by default, and the pool must not turn it off.

## Permissions

### Policy document

Everything is denied unless a rule allows it.
There are no deny rules.

```jsonc
{
  "version": 1,
  "rules": [
    {
      "bitbucket_token": "6f1c2a9e-3d7b-4c55-9a51-1f0e8d2b7c44",
      "actions": ["pr:read", "pr:create", "pr:update"],
      "project": "PROJ",
      "repository": "api",
      "branches": {
        "source": ["feature/**"],
        "target": ["main", "release/*"]
      }
    }
  ]
}
```

| Field | Required | Meaning |
| --- | --- | --- |
| `version` | yes | Format version, so that older documents keep parsing after the format evolves. |
| `rules[].bitbucket_token` | yes | ID of the Bitbucket token that executes requests allowed by this rule. |
| `rules[].actions` | yes | Actions or action wildcards, such as `pr:*`. |
| `rules[].project` | yes | Project key or glob. Compared case-insensitively. |
| `rules[].repository` | yes | Repository slug or glob. |
| `rules[].branches.branch` | no | Globs for the branch an action works on, such as the branch being created or pushed. |
| `rules[].branches.source` | no | Globs for a pull request's source branch. |
| `rules[].branches.target` | no | Globs for a pull request's target branch. |

### Matching

A rule matches a request when all of these hold:

- the action is listed in `actions`, directly or through a wildcard;
- `project` and `repository` match;
- every branch condition the rule declares is satisfied by the request.

A branch condition is satisfied if the request carries that branch and the branch matches at least one of the globs.
If the request does not carry the branch at all, the condition fails, so a rule with a `source` condition never allows `repo:read`.
Saving a policy rejects rules whose branch conditions cannot apply to any of their actions.

A request is allowed when at least one rule matches.

### Choosing the Bitbucket token

The first matching rule, in document order, decides which Bitbucket token forwards the request.
This lets one access token read one repository with one Bitbucket token and work on pull requests in another repository with a different one.

Some checks need data from Bitbucket before the rules can be evaluated, such as the branches of an existing pull request.
The proxy fetches that data with the Bitbucket token of the first rule whose action, project and repository match, ignoring branch conditions.
If Bitbucket refuses the lookup, the request is denied.

### Branch patterns

Branches are compared by short name: `feature/login`, not `refs/heads/feature/login`.
In globs, `*` matches within one `/`-separated segment and `**` matches across segments.
`release/*` matches `release/1.0` but not `release/1.0/hotfix`; `release/**` matches both.

### Examples

Create and edit, but not merge, pull requests in `PROJ/api` from `feature/` branches:

```json
{ "version": 1, "rules": [
  { "bitbucket_token": "<pr-token>", "actions": ["pr:read", "pr:create", "pr:update"],
    "project": "PROJ", "repository": "api", "branches": { "source": ["feature/**"] } }
] }
```

Work with pull requests and their comments in one repository:

```json
{ "bitbucket_token": "<pr-token>", "actions": ["pr:*", "pr_comment:*"], "project": "PROJ", "repository": "api" }
```

Work with pull requests in every repository of a project:

```json
{ "bitbucket_token": "<pr-token>", "actions": ["pr:*", "pr_comment:*"], "project": "PROJ", "repository": "*" }
```

Read and create pull request comments, without editing or deleting them:

```json
{ "bitbucket_token": "<pr-token>", "actions": ["pr:read", "pr_comment:read", "pr_comment:create"], "project": "PROJ", "repository": "*" }
```

Read everything in a repository, but write only `bot/` branches and pull requests from them:

```json
{ "version": 1, "rules": [
  { "bitbucket_token": "<read-token>", "actions": ["repo:read", "branch:read", "pr:read"],
    "project": "PROJ", "repository": "api" },
  { "bitbucket_token": "<write-token>", "actions": ["branch:create", "branch:push"],
    "project": "PROJ", "repository": "api", "branches": { "branch": ["bot/**"] } },
  { "bitbucket_token": "<write-token>", "actions": ["pr:create", "pr:update"],
    "project": "PROJ", "repository": "api", "branches": { "source": ["bot/**"] } }
] }
```

Read one repository with one Bitbucket token and manage pull requests in another with a different one:

```json
{ "version": 1, "rules": [
  { "bitbucket_token": "<read-token>", "actions": ["repo:read", "branch:read", "pr:read"],
    "project": "PROJ", "repository": "docs" },
  { "bitbucket_token": "<pr-token>", "actions": ["pr:read", "pr:create", "pr:update"],
    "project": "PROJ", "repository": "api" }
] }
```

## Actions

Paths are relative to `/rest`, with `{repo}` standing for `api/{version}/projects/{projectKey}/repos/{repositorySlug}`.
They follow the Bitbucket Data Center 10.2 REST API, whose OpenAPI description is `10.2.swagger.v3.json` in the repository root.

| Action | Endpoints | Branch attributes |
| --- | --- | --- |
| `repo:read` | `GET {repo}`, and `GET` only on its `browse`, `raw`, `files`, `commits`, `compare`, `diff` and `tags` subtrees; other methods on these paths, such as creating tags or posting build statuses, are not `repo:read` | – |
| `branch:read` | `GET {repo}/branches`, `GET branch-utils/{version}/…/branches/info/{commitId}` | – |
| `branch:create` | `POST {repo}/branches`, `POST branch-utils/{version}/…/branches` | `branch` from `name` in the body |
| `branch:delete` | `DELETE branch-utils/{version}/…/branches` | `branch` from `name` in the body |
| `pr:read` | `GET {repo}/pull-requests`, `GET {repo}/pull-requests/{id}` and its `activities`, `changes`, `commits`, `diff`, `merge` (merge check) | – |
| `pr:create` | `POST {repo}/pull-requests` | `source` and `target` from `fromRef` and `toRef` in the body |
| `pr:update` | `PUT {repo}/pull-requests/{id}` | `source` and `target` of the existing pull request, and `target` from `toRef` in the body if it changes |
| `pr:review` | `PUT`, `DELETE {repo}/pull-requests/{id}/participants/{userSlug}`, `POST`, `DELETE {repo}/pull-requests/{id}/approve` | `source` and `target` of the existing pull request |
| `pr:merge` | `POST {repo}/pull-requests/{id}/merge` | `source` and `target` of the existing pull request |
| `pr:decline` | `POST {repo}/pull-requests/{id}/decline` | `source` and `target` of the existing pull request |
| `pr:reopen` | `POST {repo}/pull-requests/{id}/reopen` | `source` and `target` of the existing pull request |
| `pr:delete` | `DELETE {repo}/pull-requests/{id}` | `source` and `target` of the existing pull request |
| `pr_comment:read` | `GET {repo}/pull-requests/{id}/comments[/{commentId}]`, `GET …/blocker-comments[/{commentId}]` | `source` and `target` of the existing pull request |
| `pr_comment:create` | `POST {repo}/pull-requests/{id}/comments`, `POST …/blocker-comments` | `source` and `target` of the existing pull request |
| `pr_comment:update` | `PUT {repo}/pull-requests/{id}/comments/{commentId}`, `PUT …/blocker-comments/{commentId}` | `source` and `target` of the existing pull request |
| `pr_comment:delete` | `DELETE {repo}/pull-requests/{id}/comments/{commentId}`, `DELETE …/blocker-comments/{commentId}` | `source` and `target` of the existing pull request |
| `branch:push` | Git push, see [Git over HTTPS](#git-over-https) | `branch` from the pushed ref |
| `tag:create`, `tag:push`, `tag:delete` | Git push, see [Git over HTTPS](#git-over-https) | – |

Any request that does not match a row is denied, including endpoints that share a path with an allowed one.
In particular, these are denied:

- `PUT`, `POST` and `DELETE {repo}`, which update, fork and delete the repository;
- `access-tokens/{version}/…`, which manage Bitbucket tokens and would let a client escalate its access;
- `PUT {repo}/browse/{path}`, which edits a file and commits it to a branch;
- `{repo}/pull-requests/{id}/comments/{commentId}/apply-suggestion`, which commits to the source branch;
- `comment-likes/{version}/…` reactions;
- `api/{version}/dashboard/pull-requests` and `api/{version}/inbox/pull-requests`, which list pull requests across repositories and cannot be limited to the repositories a policy names.

Pull requests whose `fromRef.repository` differs from the repository in the URL, such as pull requests from forks, are denied.

## Request handling

### Authentication

The proxy accepts credentials the way Bitbucket Data Center does, so existing clients only change the token:

- `Authorization: Bearer <access token>`;
- `Authorization: Basic base64(<any username>:<access token>)`, which Git clients use.

A missing, malformed, unknown or expired token yields `401 Unauthorized`.

### Path normalization

The path is normalized before classification, because two spellings of one endpoint must never classify differently:

- `/rest/api/1.0/…` and `/rest/api/latest/…` are equivalent, as are the other REST plugins' version segments;
- percent-encoding is decoded exactly once, and paths containing encoded slashes (`%2F`) or `..` segments are rejected;
- repeated slashes are collapsed and a trailing slash is ignored;
- project keys are compared case-insensitively.

### Classification and attributes

The normalized request is classified into an action, a project, a repository and the branch attributes it needs, according to [Actions](#actions).
Branch attributes come from:

- the request body, read into memory up to a size limit, for requests that create something;
- the existing pull request, fetched from Bitbucket and briefly cached, for requests on an existing pull request.

A pull request's target branch changes only through `pr:update`, which is itself checked, so a cached pull request cannot be used to bypass a rule.

### Forwarding

An allowed request is forwarded with these changes:

- `Authorization` is replaced with `Bearer <Bitbucket token>` of the chosen rule;
- the `Cookie` header is removed entirely, which drops the admin session cookie if a browser sent one;
- `Set-Cookie` headers are removed from the response, so that Bitbucket's own session cookies cannot authenticate later requests under a different Bitbucket token.

The response body is streamed back unchanged.

### Errors

Denied requests use Bitbucket's error format, so clients report them like any other Bitbucket error:

```json
{ "errors": [{ "context": null, "message": "access token does not allow pr:merge on PROJ/api", "exceptionName": null }] }
```

Each decision is logged with the access token ID, the action, the resource, the branch attributes and the rule that matched, if any.

## Git over HTTPS

Bitbucket Data Center serves Git at `/scm/{projectKey}/{repositorySlug}.git/…`.

- Fetching (`info/refs?service=git-upload-pack` and `git-upload-pack`) is `repo:read`.
- Pushing (`info/refs?service=git-receive-pack` and `git-receive-pack`) starts with one command per ref, `<old-id> <new-id> <ref>`, before the pack data.
  Each command becomes one check:

  | Ref | Old ID | New ID | Action |
  | --- | --- | --- | --- |
  | `refs/heads/<branch>` | zero | any | `branch:create` |
  | `refs/heads/<branch>` | any | zero | `branch:delete` |
  | `refs/heads/<branch>` | non-zero | non-zero | `branch:push` |
  | `refs/tags/<tag>` | zero | any | `tag:create` |
  | `refs/tags/<tag>` | any | zero | `tag:delete` |
  | `refs/tags/<tag>` | non-zero | non-zero | `tag:push` |
  | anything else | | | denied |

  A push is allowed only if every command is.
  Telling a force push from a fast-forward needs the commit graph, so force pushes are left to Bitbucket's own branch permissions.

The actions and branch conditions above already describe these checks, so supporting Git changes the classifier but not the policy format.

## Not yet supported

- Personal repositories (`/projects/~{userSlug}/…`, `/scm/~{userSlug}/…`).
  They are meant to be allowed only by rules that name the `~{userSlug}` project explicitly, never through a `*` project glob.
  Until then they are denied.
- Git over HTTPS.
- Pull requests from forks.
- Response rewriting.
  Bitbucket responses contain absolute links to the Bitbucket server; clients that follow them bypass the proxy and fail to authenticate there.
