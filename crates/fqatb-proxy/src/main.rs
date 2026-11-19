mod bitbucket;
mod config;
mod crypto;
mod db;
mod error;
mod logging;
mod policy;
mod routes;
mod services;
mod state;

use std::sync::Arc;

use anyhow::Context as _;
use tokio::net::TcpListener;
use tracing::info;

use crate::config::Config;
pub(crate) use crate::error::{Error, Result};
use crate::state::ServerState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::init_tracing();

    let config = Config::from_env()?;
    let listen_addr = config.listen_addr;

    let state = Arc::new(
        ServerState::new(config)
            .await
            .context("failed to initialize server state")?,
    );

    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind {listen_addr}"))?;

    info!(%listen_addr, "Listening");

    axum::serve(listener, routes::router(Arc::clone(&state)))
        .with_graceful_shutdown(async {
            // If the signal handler cannot be installed, the server keeps running until killed.
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!(%error, "Failed to listen for shutdown signal");
                std::future::pending::<()>().await;
            }
        })
        .await
        .context("server failed")?;

    state.db.close().await;

    info!("Shut down");

    Ok(())
}
