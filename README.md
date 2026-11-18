# fgat-bitbucket
Missing fine-frained access tokens for Bitckuket

## Running

The proxy is configured through environment variables:

| Variable | Required | Description |
| --- | --- | --- |
| `FQATB_ENCRYPTION_KEY` | yes | 32-byte master key as 64 hex characters, for example from `openssl rand -hex 32`. The database and session encryption keys are derived from it. |
| `FQATB_ADMIN_PASSWORD` | on first start-up | Admin panel passphrase, at least 12 characters. It is hashed with Argon2id and ignored once the admin exists. |
| `FQATB_LISTEN_ADDR` | no | Address to listen on, `127.0.0.1:8080` by default. |
| `FQATB_DATABASE_URL` | no | SQLite database URL, `sqlite://fqatb.db` by default. The file is created and migrated on start-up. |
| `RUST_LOG` | no | Log filter, `info` by default. |

```sh
FQATB_ENCRYPTION_KEY=$(openssl rand -hex 32) FQATB_ADMIN_PASSWORD='a long passphrase' cargo run
```

Keep the encryption key: losing or changing it invalidates every encrypted value in the database.

The admin panel is served under `/webapp/`.
Its session cookie is marked `Secure`, so the panel must be served over HTTPS or from `localhost`.
