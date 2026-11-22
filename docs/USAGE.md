# Usage

## TLS

The proxy terminates TLS itself, with HTTP/2 and HTTP/1.1, when both `FGATB_TLS_CERT` and `FGATB_TLS_KEY` are set:

```bash
FGATB_TLS_CERT=/etc/tbtbucket/fullchain.pem FGATB_TLS_KEY=/etc/tbtbucket/privkey.pem FGATB_LISTEN_ADDR=0.0.0.0:443 ... cargo run
```

Send the process `SIGHUP` after renewing the certificate to load the new files without a restart.
If they fail to load, the error is logged and the current certificate stays in use.

Without them the proxy serves plain HTTP and warns about it on start-up.
Use that only for local development: clients would send access tokens and the admin password in clear text.
Setting only one of the two variables is an error.

The admin panel is served under `/webapp/`; its home page is `/webapp/management_tokens`.
On first start-up, open `/webapp/signup` to set the admin password, then log in with it at `/webapp/login`.
Until the password is set, anyone who can reach the panel can claim it, so keep the proxy private until then.
Its actions are served under `/fgatbapi/`, for example Bitbucket token management at `/webapp/bitbucket_tokens`.
The session cookie covers both prefixes, so it is scoped to `/`.
It is marked `Secure`, so browsers only keep it over HTTPS, or over plain HTTP when the panel is opened as `localhost`.

## Access tokens

1. Add one or more Bitbucket HTTP access tokens at `/webapp/bitbucket_tokens`.
   They are stored encrypted and only ever sent to the Bitbucket server, never to clients.
2. Issue an access token at `/webapp/access_tokens`.
   Each rule grants actions on matching projects and repositories, optionally only for matching branches, and names the Bitbucket token that carries out the requests it allows.
   The token is shown once, right after it is issued.
3. Point the Bitbucket client at the proxy instead of the Bitbucket server, and give it the access token where it would take a Bitbucket HTTP access token, either as `Authorization: Bearer fgatb_…` or as the password of Basic authentication.

Everything outside `/webapp/`, `/fgatbapi/` and `/health` is the Bitbucket-compatible API.
Requests that the token does not allow, or that the proxy does not support yet, are denied with Bitbucket's error format.
Removing a Bitbucket token also removes every access token that uses it.

See [`docs/access-model.md`](access-model.md) for the token format, the rule format and the supported endpoints.

## Git over HTTPS

Use the proxy in the clone URL, with the same path as on Bitbucket:

```sh
git clone https://proxy.example.com/scm/PROJ/repo.git
```

When Git asks for credentials, give any username and the access token as the password.
For CI, pass the token in a header so Git never prompts:

```sh
git -c http.extraHeader="Authorization: Bearer fgatb_…" clone https://proxy.example.com/scm/PROJ/repo.git
```

| Operation | Needs on the repository |
| --- | --- |
| Clone, fetch, pull, `ls-remote` | Repository: read |
| Push to a new or existing branch, force pushes included | Allow Git and create, for a matching branch |
| Delete a branch | Allow Git and delete, for a matching branch |

- All refs of one push must be allowed by a single rule, which also picks the Bitbucket token; otherwise the whole push is rejected, and `git push` names the ref and the reason.
- Pushes of tags and other refs that are not branches are always rejected.
- Git LFS, Git over SSH and personal repositories (`/scm/~user/…`) are not supported.
- An unknown or expired token makes Git report an authentication failure and discard the stored credentials; a token that lacks a permission is refused without touching them.

See [Git over HTTPS](access-model.md#git-over-https) in the access model for how pushes are checked.

## Management API

Scripts can manage Bitbucket tokens and access tokens without the admin panel, through the JSON API under `/fgatbapi/v1/`.

1. Issue a management token at `/webapp/management_tokens`; it is shown once, right after it is issued.
2. Send it as `Authorization: Bearer fgatbm_…` to list, add and remove Bitbucket tokens at `/fgatbapi/v1/bitbucket_tokens` and access tokens at `/fgatbapi/v1/access_tokens`.

See [`docs/management-api.md`](management-api.md) for every endpoint, with examples.
