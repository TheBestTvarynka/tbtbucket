mod app;
mod health;

use std::env;
use std::net::SocketAddr;

use anyhow::Context as _;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:8080";
const DEFAULT_DATABASE_URL: &str = "sqlite://fqatb.db";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let listen_addr: SocketAddr = env::var("FQATB_LISTEN_ADDR")
        .as_deref()
        .unwrap_or(DEFAULT_LISTEN_ADDR)
        .parse()
        .context("invalid listen address")?;

    let database_url =
        env::var("FQATB_DATABASE_URL").unwrap_or_else(|_| DEFAULT_DATABASE_URL.to_owned());

    let db = {
        let options = database_url
            .parse::<SqliteConnectOptions>()
            .context("invalid database URL")?
            .create_if_missing(true);

        SqlitePoolOptions::new()
            .connect_with(options)
            .await
            .context("failed to open database")?
    };

    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind {listen_addr}"))?;

    info!(%listen_addr, "Listening");

    axum::serve(listener, app::router(app::AppState { db: db.clone() }))
        .with_graceful_shutdown(async {
            // If the signal handler cannot be installed, the server keeps running until killed.
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!(%error, "Failed to listen for shutdown signal");
                std::future::pending::<()>().await;
            }
        })
        .await
        .context("server failed")?;

    db.close().await;

    info!("Shut down");

    Ok(())
}
