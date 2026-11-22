# Usage

This guide assumes the proxy is running and you are logged in to the admin panel.
If not, start with [`GETTING_STARTED.md`](GETTING_STARTED.md).

The examples use `https://proxy.example.com` as the proxy address.
Replace it with your own.

- [Bitbucket tokens](#bitbucket-tokens)
- [Access tokens](#access-tokens)
- [Git over HTTPS](#git-over-https)
- [Management tokens](#management-tokens)

## Bitbucket tokens

The proxy forwards every allowed request to Bitbucket with a real Bitbucket token.
Clients never see these tokens.
Add at least one before you issue access tokens.

### Create a token in Bitbucket

Bitbucket offers [HTTP access tokens](https://confluence.atlassian.com/bitbucketserver102/http-access-tokens-1791787433.html) at three levels:

- **Personal:** your avatar → **Manage account** → **HTTP access tokens** → **Create token**.
  It works in every project and repository you can access.
- **Project:** project settings → **HTTP access tokens**.
  It works only in that project.
- **Repository:** repository settings → **HTTP access tokens**.
  It works only in that repository.

Choose the permissions the clients need:

- **Read** is enough for reading code, pull requests and comments, and for cloning.
- **Write** is needed for creating branches, pushing, and working with pull requests and comments.

An access token can never do more than its Bitbucket token allows.
The proxy narrows that access down; it never widens it.

Copy the token: Bitbucket shows it only once.

### Add it to the proxy

1. Open **/bitbucket_tokens** in the admin panel.
2. Enter a **Name**, such as `personal-write`.
   You will pick tokens by this name later.
3. Paste the token into **Token**.
4. Click **Add token**.

The proxy stores the token encrypted.

To remove a token, click **Remove** next to it.
Every access token that uses it is removed too.
The confirmation lists them.

## Access tokens

An access token is what you give to a client: an AI agent, a script, CI, or `git`.
Its rules say exactly what the client may do.
Everything else is denied.

### Create an access token

1. Open **/access_tokens** in the admin panel.
2. Click **Add access token**.
3. Enter a **Name**, such as `review-bot`.
4. Choose when it **Expires**: in 1, 7, 30 or 90 days.
5. Click **Add rule** and fill in the rule.
   Add more rules if needed.
6. Click **Create access token**.
7. Copy the token.
   It starts with `fgatb_`.
   It is shown only once.

You cannot edit an access token.
To change its rules, create a new one and remove the old one.

### Fill in a rule

Each rule has:

- **Bitbucket token:** the token that forwards the requests this rule allows.
- **Project:** a project key, such as `PROJ`, or `*` for every project.
- **Repository:** a repository slug, such as `api`, or `*` for every repository.
  Patterns work too, such as `api-*`.
- **Actions:** what the client may do there.

| Group | Action | Allows |
| --- | --- | --- |
| Repository | read | Read commits, branches, files, pull requests and their comments. Clone and fetch with Git. |
| Branches | create | Create branches. |
| Branches | delete | Delete branches. |
| Branches | Allow Git | Lets **create** and **delete** also work with `git push`. See [Git over HTTPS](#git-over-https). |
| Pull requests | create, update, review, merge, decline, reopen, delete | Each one allows that pull request action. **review** covers approving and requesting changes. |
| PR comments | create, update, delete | Each one allows that comment action. **create** also covers reactions. |

**Repository: read** is checked by default.
Keep it: most clients read a pull request before they change it.
Without it, the token is rarely useful.

### Limit branches

Branch patterns are optional.
Without them, an action works on every branch.

- The field next to **Branches** limits branch create, delete and Git pushes, such as `bot/**`.
- **Source branches** and **Target branches** limit pull request and comment actions.
  For example, source `feature/**` and target `main`.
- Reading is never limited by branches.

Pattern rules:

- Separate several patterns with commas: `main, release/*`.
- `*` matches within one `/` segment: `release/*` matches `release/1.0`, but not `release/1.0/hotfix`.
- `**` matches across segments: `release/**` matches both.

### Use several rules

A request is allowed if any rule allows it.
Use several rules to:

- give different access in different repositories;
- use a different Bitbucket token for some repositories.

When more than one rule allows a request, the first one picks the Bitbucket token.

### Examples

A review bot that reads and comments on pull requests in every repository of `PROJ`:

- Project `PROJ`, repository `*`.
- Repository: read; Pull requests: review; PR comments: create, update.

An agent that works on its own branches in `PROJ/api` and opens pull requests into `main`:

- Project `PROJ`, repository `api`.
- Repository: read.
- Branches: create, delete, Allow Git; pattern `bot/**`.
- Pull requests: create, update; source `bot/**`, target `main`.

### Use the token

Point the client at the proxy instead of Bitbucket.
For example, use `https://proxy.example.com/rest/api/latest/...` instead of `https://bitbucket.example.com/rest/api/latest/...`.

Send the access token the same way as a Bitbucket token:

- as a header: `Authorization: Bearer fgatb_…`;
- or as the password of Basic authentication, with any username.

If a request is not allowed, the proxy answers with `403` and an error that says why.

To revoke a token, click **Remove** next to it on **/access_tokens**.
Clients lose access immediately.

## Git over HTTPS

Use the proxy in the clone URL.
The path is the same as on Bitbucket:

```sh
git clone https://proxy.example.com/scm/PROJ/api.git
```

To switch an existing clone to the proxy:

```sh
git remote set-url origin https://proxy.example.com/scm/PROJ/api.git
```

### Permissions

| Operation | Needs |
| --- | --- |
| Clone, fetch, pull | Repository: read |
| Push to a new or existing branch, force push included | Branches: create and Allow Git, for a matching branch |
| Delete a branch with `git push --delete` | Branches: delete and Allow Git, for a matching branch |

- One rule must allow every branch of a push.
  If it does not, the whole push is rejected, and `git push` shows the branch and the reason.
- Pushing tags is always rejected.
- Git LFS and Git over SSH are not supported.

### Give the token to Git

Pick one of these options.

**Type it when Git asks.**
Git asks for a username and password.
Enter any username and the access token as the password.
Your credential helper, if you have one, remembers it.

**Read it from an environment variable.**
This keeps the token out of files and command lines.
It suits AI agents and CI.
Set these variables where the client runs:

```sh
export FGATB_TOKEN=fgatb_…
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0=credential.https://proxy.example.com.helper
export GIT_CONFIG_VALUE_0=
export GIT_CONFIG_KEY_1=credential.https://proxy.example.com.helper
export GIT_CONFIG_VALUE_1='!f() { test "$1" = get && echo username=git && echo "password=$FGATB_TOKEN"; }; f'
```

The empty helper first turns off your usual credential helpers for the proxy.
The second one answers with `$FGATB_TOKEN`.

**Add it to your Git config.**
To make the environment variable option permanent, add the same helper to `~/.gitconfig`:

```sh
git config --global --add credential.https://proxy.example.com.helper ''
git config --global --add credential.https://proxy.example.com.helper '!f() { test "$1" = get && echo username=git && echo "password=$FGATB_TOKEN"; }; f'
```

Git then uses the token wherever `FGATB_TOKEN` is set.

**Store it in a file.**
`git credential-store` keeps the token in a plain-text file:

```sh
git config --global credential.https://proxy.example.com.helper 'store --file ~/.config/tbtbucket/credentials'
```

Git saves the token there the first time you enter it.
Make sure only you can read the file.

**Send it as a header for one command.**

```sh
git -c http.extraHeader="Authorization: Bearer fgatb_…" clone https://proxy.example.com/scm/PROJ/api.git
```

Put `-c` before `clone`: `git clone -c …` saves the header in the new repository's `.git/config`.
The token is visible in the process list while Git runs, so prefer the environment variable option on shared machines.

### Trust the proxy's certificate

If your proxy's certificate is signed by your own CA, Git must trust that CA:

```sh
git config --global http.https://proxy.example.com/.sslCAInfo /path/to/ca.crt
```

The environment variable option can set it too, as one more `GIT_CONFIG_KEY_n`.

### When Git fails

- **Authentication failed:** the token is wrong, expired or removed.
  Git forgets the stored token and asks again.
- **`remote: access token does not allow …`:** the token is valid, but a rule is missing.
  Add it in a new access token.

## Management tokens

Management tokens let scripts add and remove Bitbucket tokens and access tokens without the admin panel.
For example, a script can issue a short-lived access token for each agent task and remove it afterwards.

1. Open **/management_tokens** in the admin panel.
2. Click **Add management token**.
3. Enter a **Name** and choose when it **Expires**.
4. Click **Create management token**.
5. Copy the token.
   It starts with `fgatbm_`.
   It is shown only once.

Send it to the management API as a header:

```sh
curl -H "Authorization: Bearer fgatbm_…" https://proxy.example.com/fgatbapi/v1/access_tokens
```

A management token can manage Bitbucket tokens and access tokens.
It cannot create or remove management tokens: only the admin panel can.
It does not work as an access token.

Keep management tokens safe: anyone with one can issue access tokens.

See [`management-api.md`](management-api.md) for every endpoint, with examples.
