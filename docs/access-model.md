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

`token_mac_key` is derived from the master key (`FGATB_ENCRYPTION_KEY`) with HKDF-SHA256, using its own hardcoded salt, like the database and session ciphers.
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
The admin panel offers lifetimes of 1, 7, 30 and 90 days.
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
      "actions": ["pr:create", "pr:update"],
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
| `rules[].project` | yes | Project key or glob. Compared case-insensitively. Personal projects (`~user`) are not accepted yet. |
| `rules[].repository` | yes | Repository slug or glob. |
| `rules[].branches.branch` | no | Globs for the branch an action works on, such as the branch being created or pushed. |
| `rules[].branches.source` | no | Globs for a pull request's source branch. |
| `rules[].branches.target` | no | Globs for a pull request's target branch. |

### Matching

A rule matches a request when all of these hold:

- the action is listed in `actions`, directly or through a wildcard;
- `project` and `repository` match;
- every branch condition the rule declares that applies to the action is satisfied by the request.

Branch conditions only limit the actions they apply to:

- `branch` applies to `branch:create`, `branch:delete` and `branch:git`;
- `source` and `target` apply to every `pr:*` and `pr_comment:*` action;
- nothing applies to `repo:read`, which is never limited by branches.

So one rule can allow reading everything in a repository and, at the same time, writing only to matching branches.

A condition that applies is satisfied if the request carries that branch and the branch matches at least one of the globs.
If the request does not carry the branch, the condition fails.
Saving a policy rejects a rule with a branch condition that applies to none of its actions, since that condition would have no effect.

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

Read everything in `PROJ/api`, and create and edit, but not merge, pull requests from `feature/` branches:

```json
{ "version": 1, "rules": [
  { "bitbucket_token": "<pr-token>", "actions": ["repo:read", "pr:create", "pr:update"],
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
{ "bitbucket_token": "<pr-token>", "actions": ["repo:read", "pr_comment:create"], "project": "PROJ", "repository": "*" }
```

Read everything in a repository, but write only `bot/` branches, through the REST API and Git pushes, and pull requests from them:

```json
{ "version": 1, "rules": [
  { "bitbucket_token": "<write-token>", "actions": ["repo:read", "branch:create", "branch:git", "pr:create", "pr:update"],
    "project": "PROJ", "repository": "api", "branches": { "branch": ["bot/**"], "source": ["bot/**"] } }
] }
```

Read one repository with one Bitbucket token and manage pull requests in another with a different one:

```json
{ "version": 1, "rules": [
  { "bitbucket_token": "<read-token>", "actions": ["repo:read"],
    "project": "PROJ", "repository": "docs" },
  { "bitbucket_token": "<pr-token>", "actions": ["repo:read", "pr:create", "pr:update"],
    "project": "PROJ", "repository": "api" }
] }
```

## Actions

Paths are relative to `/rest`, with `{repo}` standing for `api/{version}/projects/{projectKey}/repos/{repositorySlug}`.
They follow the Bitbucket Data Center 10.2 REST API, whose OpenAPI description is `10.2.swagger.v3.json` in the repository root.

| Action | Endpoints | Branch attributes |
| --- | --- | --- |
| `repo:read` | Every read in the repository: `GET {repo}`; `GET` on its `browse`, `raw`, `files`, `commits` (including commit comments, builds and deployments), `compare`, `diff`, `last-modified` and `tags` subtrees; `GET {repo}/changes`, `participants`, `default-branch`, `branches/default`, `ref-change-activities` and `ref-change-activities/branches`; `GET {repo}/branches` and `GET branch-utils/{version}/…/branches/info/{commitId}`; `GET {repo}/pull-requests`, `GET {repo}/pull-requests/{id}`, `{id}.diff` and `{id}.patch`, and its `activities`, `changes`, `commits`, `diff`, `diff-stats-summary`, `merge` (merge check), `merge-base`, `commit-message-suggestion`, `participants`, `review` and `auto-merge`; `GET` on its `comments` and `blocker-comments`; `GET jira/{version}/…/pull-requests/{id}/issues`; `GET insights/{version}/…/commits/{commitId}/reports` and `…/annotations` subtrees; Git fetches, see [Git over HTTPS](#git-over-https). Other methods on these paths, such as creating tags or posting build statuses, are not `repo:read`. | – |
| `branch:create` | `POST {repo}/branches`, `POST branch-utils/{version}/…/branches`; with `branch:git`, Git pushes that create or update a branch | `branch` from `name` in the body, or from the pushed ref |
| `branch:delete` | `DELETE branch-utils/{version}/…/branches`; with `branch:git`, Git pushes that delete a branch | `branch` from `name` in the body, or from the pushed ref |
| `branch:git` | Nothing on its own: it lets the rule's `branch:create` and `branch:delete` apply to Git pushes, see [Git over HTTPS](#git-over-https) | `branch` from the pushed ref |
| `pr:create` | `POST {repo}/pull-requests` | `source` and `target` from `fromRef` and `toRef` in the body |
| `pr:update` | `PUT {repo}/pull-requests/{id}`; `POST`, `DELETE {repo}/pull-requests/{id}/participants`, which add and remove reviewers | `source` and `target` of the existing pull request, and `target` from `toRef` in the body if it changes |
| `pr:review` | `PUT`, `DELETE {repo}/pull-requests/{id}/participants/{userSlug}`, `POST`, `DELETE {repo}/pull-requests/{id}/approve`, `PUT`, `DELETE {repo}/pull-requests/{id}/review`, which complete the token's own review or discard it | `source` and `target` of the existing pull request |
| `pr:merge` | `POST {repo}/pull-requests/{id}/merge` | `source` and `target` of the existing pull request |
| `pr:decline` | `POST {repo}/pull-requests/{id}/decline` | `source` and `target` of the existing pull request |
| `pr:reopen` | `POST {repo}/pull-requests/{id}/reopen` | `source` and `target` of the existing pull request |
| `pr:delete` | `DELETE {repo}/pull-requests/{id}` | `source` and `target` of the existing pull request |
| `pr_comment:create` | `POST {repo}/pull-requests/{id}/comments`, `POST …/blocker-comments`; `PUT`, `DELETE comment-likes/{version}/…/pull-requests/{id}/comments/{commentId}/reactions/{emoticon}`, since a reaction is the token's own lightweight comment | `source` and `target` of the existing pull request |
| `pr_comment:update` | `PUT {repo}/pull-requests/{id}/comments/{commentId}`, `PUT …/blocker-comments/{commentId}` | `source` and `target` of the existing pull request |
| `pr_comment:delete` | `DELETE {repo}/pull-requests/{id}/comments/{commentId}`, `DELETE …/blocker-comments/{commentId}` | `source` and `target` of the existing pull request |

Any request that does not match a row is denied, including endpoints that share a path with an allowed one.
In particular, these are denied:

- `PUT`, `POST` and `DELETE {repo}`, which update, fork and delete the repository;
- `access-tokens/{version}/…`, which manage Bitbucket tokens and would let a client escalate its access;
- `PUT {repo}/browse/{path}`, which edits a file and commits it to a branch;
- `{repo}/pull-requests/{id}/comments/{commentId}/apply-suggestion`, which commits to the source branch;
- reactions on commit comments, and writes on commit comments;
- `{repo}/pull-requests/{id}/auto-merge` and `…/watch` writes;
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
- percent-encoding is decoded exactly once, and paths containing encoded slashes or backslashes, `.` or `..` segments, or empty segments (repeated slashes) are rejected rather than rewritten, because the original path is what Bitbucket receives;
- a single trailing slash is ignored;
- project keys are compared case-insensitively.

### Classification and attributes

The normalized request is classified into an action, a project, a repository and the branch attributes it needs, according to [Actions](#actions).
Branch attributes come from:

- the request body, read into memory up to 1 MiB, for requests that create a branch or pull request, delete a branch, or update a pull request;
- the existing pull request, fetched from Bitbucket on every request, for requests on an existing pull request.

Updating a pull request may move it to another target branch, given in `toRef` of the body.
Such an update must be allowed for both the current and the new target.
The other bodies stream through without being read.

### Forwarding

An allowed request is forwarded to the server at `FGATB_BITBUCKET_URL`, with its path and query unchanged, and with these changes:

- `Authorization` is replaced with `Bearer <Bitbucket token>` of the chosen rule;
- the `Cookie` header is removed entirely, which drops the admin session cookie if a browser sent one;
- `Set-Cookie` headers are removed from the response, so that Bitbucket's own session cookies cannot authenticate later requests under a different Bitbucket token.

Connection-specific headers are dropped in both directions, and redirects are passed to the client rather than followed.
The response body is streamed back unchanged.

### Errors

Denied requests use Bitbucket's error format, so clients report them like any other Bitbucket error:

```json
{ "errors": [{ "context": null, "message": "access token does not allow pr:merge on PROJ/api", "exceptionName": null }] }
```

A missing or invalid token yields `401 Unauthorized` with `WWW-Authenticate: Basic realm="Bitbucket"`, so that Git clients ask for credentials.

Denied requests are logged as warnings with the access token ID, the action, the resource and the reason.
Allowed requests are logged at debug level with the rule that matched and the Bitbucket token used.

## Git over HTTPS

Bitbucket Data Center serves Git at `/scm/{projectKey}/{repositorySlug}.git/…`, with or without the `.git` suffix.
The project and repository in that path select the rules, like the `{repo}` part of a REST path does.

### Fetching

Cloning, fetching, pulling and `ls-remote` go through `git-upload-pack`:
`GET …/info/refs?service=git-upload-pack` advertises the refs and `POST …/git-upload-pack` sends the objects.
Both are `repo:read`, whatever the client asks for: shallow and partial clones, pull request refs such as `refs/pull-requests/1/from`, and Git protocol version 2 alike.
Fetches are never limited by branches, since a client can ask for any object reachable in the repository.

### Pushing

Pushes go through `git-receive-pack`: `GET …/info/refs?service=git-receive-pack` advertises the refs, then `POST …/git-receive-pack` sends one command per ref, `<old-id> <new-id> <ref>`, followed by the pack.
The proxy reads the commands, checks them, and streams the pack to Bitbucket without holding it.

Each command needs a rule that has `branch:git`, whose `branch` condition, if any, matches the branch, and that has:

| Ref | Command | Action |
| --- | --- | --- |
| `refs/heads/<branch>` | old ID is zero: creates the branch | `branch:create` |
| `refs/heads/<branch>` | neither ID is zero: updates the branch, force pushes included | `branch:create` |
| `refs/heads/<branch>` | new ID is zero: deletes the branch | `branch:delete` |
| `refs/tags/<tag>`, or any other ref | | denied |

Updating a branch needs `branch:create` because a client that may push commits to a new branch has no reason to be kept from updating it.
Telling a force push from a fast-forward would need the commit graph, so force pushes are left to Bitbucket's own branch permissions.

One push is one request, forwarded with one Bitbucket token, so it is allowed by the first rule that allows every command in it, and that rule's Bitbucket token forwards it.
If no single rule allows every command, the push is denied as a whole, naming a ref the first candidate rule does not allow; pushing the refs separately lets each find its own rule.
`git push --atomic` needs nothing more: every command is checked either way.

`GET …/info/refs?service=git-receive-pack` reveals nothing a fetch would not, so it needs `repo:read` or `branch:git`.

### Authentication and errors

Git sends no credentials on its first request.
The proxy answers it with `401` and `WWW-Authenticate: Basic realm="Bitbucket"`, Git asks its credential helper or prompts, and retries with the access token as the Basic password; the username is ignored.
`http.extraHeader="Authorization: Bearer fgatb_…"` works too and suits CI.

The status tells Git what to do with the credentials:

- `401` for a missing, invalid, expired or removed access token: Git's credential helper forgets it, and Git asks again;
- `403` for a valid access token that does not allow the request: the credentials are kept, and Git reports the error.

A denied push is answered in Git's own report format with `ng <ref> <reason>` for the denied ref, so `git push` names the ref and the reason, and nothing is pushed.

### Out of scope

Git LFS, Git over SSH, `git archive --remote` and personal repositories (`/scm/~{userSlug}/…`) are not supported, and are denied.

## Not yet supported

- Personal repositories (`/projects/~{userSlug}/…`, `/scm/~{userSlug}/…`).
  They are meant to be allowed only by rules that name the `~{userSlug}` project explicitly, never through a `*` project glob.
  Until then they are denied, and project patterns starting with `~` are rejected when a policy is saved.
- Pull requests from forks.
- Caching pull request lookups.
  Every request on an existing pull request fetches it from Bitbucket first.
- Response rewriting.
  Bitbucket responses contain absolute links to the Bitbucket server; clients that follow them bypass the proxy and fail to authenticate there.
