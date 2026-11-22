
# Getting started

## Installation

The whole proxy is just one executable file.
You have two options on how to ontain it:

1. Download it from the release artifacts: [https://github.com/TheBestTvarynka/tbtbucket/releases](https://github.com/TheBestTvarynka/tbtbucket/releases).
2. Build it from the sourse code:
   ```bash
   cargo install --git https://github.com/TheBestTvarynka/tbtbucket.git --root ./custom_dir
   ```

## Environment

The proxy is configured through environment variables:

| Variable | Required | Description |
| --- | --- | --- |
| `FGATB_ENCRYPTION_KEY` | yes | 32-byte master key as 64 hex characters, for example from `openssl rand -hex 32`. The database and session encryption keys and the access token signing key are derived from it. |
| `FGATB_BITBUCKET_URL` | yes | Base URL of the Bitbucket Data Center server that requests are forwarded to, such as `https://bitbucket.example.com`. |
| `FGATB_BITBUCKET_CA_CERT` | no | Path to a PEM file with the CA certificates that issued the Bitbucket server's certificate, for a server whose certificate the system does not trust. When set, only these CAs are trusted for Bitbucket. |
| `FGATB_LISTEN_ADDR` | no | Address to listen on, `127.0.0.1:8080` by default. |
| `FGATB_TLS_CERT` | no | Path to the PEM certificate chain, leaf certificate first. Set together with `FGATB_TLS_KEY` to serve HTTPS. |
| `FGATB_TLS_KEY` | no | Path to the PEM private key (PKCS#8, PKCS#1 or SEC1) for `FGATB_TLS_CERT`. |
| `FGATB_DATABASE_URL` | no | SQLite database URL, `sqlite://tbtbucket.db` by default. The file is created and migrated on start-up. |
| `FGATB_LOGGING` | no | Log filter in the [`EnvFilter` syntax](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives), `trace` by default. For example, `info` or `info,tbtbucket=debug`. |

```bash
FGATB_ENCRYPTION_KEY=$(openssl rand -hex 32) FGATB_BITBUCKET_URL=https://bitbucket.example.com cargo run
```

## The very first run

1. Start the proxy.
2. Open the proxy webapp: `<FGATB_LISTEN_ADDR>/webapp/`
3. On the first run (and only on the first one), the proxy will ask to create the password.
   It is the admin password for accessing the admin panel (proxy webapp).
4. After succesfull login, you can start configuring your Bitbucket and access tokens.

Continue with [`USAGE.md`](USAGE.md) to configure Bitbucket tokens and access tokens, and to point clients and Git at the proxy.
