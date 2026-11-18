# fgat-bitbucket
Missing fine-frained access tokens for Bitckuket

## Running

The proxy is configured through environment variables:

| Variable | Required | Description |
| --- | --- | --- |
| `FQATB_ENCRYPTION_KEY` | yes | 32-byte master key as 64 hex characters, for example from `openssl rand -hex 32`. The database and session encryption keys are derived from it. |
| `FQATB_LISTEN_ADDR` | no | Address to listen on, `127.0.0.1:8080` by default. |
| `FQATB_DATABASE_URL` | no | SQLite database URL, `sqlite://fqatb.db` by default. The file is created and migrated on start-up. |
| `RUST_LOG` | no | Log filter, `info` by default. |

```sh
FQATB_ENCRYPTION_KEY=$(openssl rand -hex 32) cargo run
```

Keep the encryption key: losing or changing it invalidates every encrypted value in the database.

The admin panel is served under `/webapp/`.
On first start-up, open `/webapp/signup` to set the admin password, then log in with it at `/webapp/login`.
Until the password is set, anyone who can reach the panel can claim it, so keep the proxy private until then.
Its session cookie is marked `Secure`, so the panel must be served over HTTPS or from `localhost`.
