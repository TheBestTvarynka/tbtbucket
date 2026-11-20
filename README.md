# fgat-bitbucket

Missing fine-frained access tokens for Bitckuket

## Running

The proxy is configured through environment variables:

| Variable | Required | Description |
| --- | --- | --- |
| `FQATB_ENCRYPTION_KEY` | yes | 32-byte master key as 64 hex characters, for example from `openssl rand -hex 32`. The database and session encryption keys and the access token signing key are derived from it. |
| `FQATB_BITBUCKET_URL` | yes | Base URL of the Bitbucket Data Center server that requests are forwarded to, such as `https://bitbucket.example.com`. |
| `FQATB_BITBUCKET_CA_CERT` | no | Path to a PEM file with the CA certificates that issued the Bitbucket server's certificate, for a server whose certificate the system does not trust. When set, only these CAs are trusted for Bitbucket. |
| `FQATB_LISTEN_ADDR` | no | Address to listen on, `127.0.0.1:8080` by default. |
| `FQATB_TLS_CERT` | no | Path to the PEM certificate chain, leaf certificate first. Set together with `FQATB_TLS_KEY` to serve HTTPS. |
| `FQATB_TLS_KEY` | no | Path to the PEM private key (PKCS#8, PKCS#1 or SEC1) for `FQATB_TLS_CERT`. |
| `FQATB_DATABASE_URL` | no | SQLite database URL, `sqlite://fqatb.db` by default. The file is created and migrated on start-up. |
| `FGATB_LOGGING` | no | Log filter in the [`EnvFilter` syntax](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives), `trace` by default. For example, `info` or `info,fqatb_proxy=debug`. |

```bash
FQATB_ENCRYPTION_KEY=$(openssl rand -hex 32) FQATB_BITBUCKET_URL=https://bitbucket.example.com cargo run
```

Keep the encryption key: losing or changing it invalidates every encrypted value in the database and every access token.

### TLS

The proxy terminates TLS itself, with HTTP/2 and HTTP/1.1, when both `FQATB_TLS_CERT` and `FQATB_TLS_KEY` are set:

```bash
FQATB_TLS_CERT=/etc/fqatb/fullchain.pem FQATB_TLS_KEY=/etc/fqatb/privkey.pem FQATB_LISTEN_ADDR=0.0.0.0:443 ... cargo run
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

See [`docs/access-model.md`](docs/access-model.md) for the token format, the rule format and the supported endpoints.
