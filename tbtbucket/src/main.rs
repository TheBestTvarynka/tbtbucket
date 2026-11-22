mod bitbucket;
mod config;
mod crypto;
mod db;
mod error;
mod logging;
mod policy;
mod routes;
mod server;
mod services;
mod state;

use std::sync::Arc;

use anyhow::Context as _;
use tracing::info;

use crate::config::Config;
pub(crate) use crate::error::{Error, Result};
use crate::state::ServerState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::init_tracing();

    let mut config = Config::from_env()?;
    let listen_addr = config.listen_addr;
    let tls = config.tls.take();

    let state = Arc::new(
        ServerState::new(config)
            .await
            .context("failed to initialize server state")?,
    );

    server::serve(routes::router(Arc::clone(&state)), listen_addr, tls.as_ref()).await?;

    state.db.close().await;

    info!("Shut down");

    Ok(())
}
