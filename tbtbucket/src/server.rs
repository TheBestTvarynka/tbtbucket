//! Serves the router over HTTPS, or over plain HTTP when no certificate is configured.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context as _;
use axum::Router;
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use tracing::{error, info, warn};

use crate::config::TlsConfig;

/// How long in-flight requests may take to finish after a shutdown signal.
const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(30);

/// Serves `router` on `listen_addr` until Ctrl+C, terminating TLS itself when `tls` is set.
pub(crate) async fn serve(router: Router, listen_addr: SocketAddr, tls: Option<&TlsConfig>) -> anyhow::Result<()> {
    let handle = Handle::new();
    tokio::spawn(shut_down_on_ctrl_c(handle.clone()));

    let service = router.into_make_service();

    match tls {
        Some(tls) => {
            let config = RustlsConfig::from_pem_file(&tls.cert_path, &tls.key_path)
                .await
                .with_context(|| {
                    format!(
                        "failed to load the TLS certificate {} and key {}",
                        tls.cert_path.display(),
                        tls.key_path.display()
                    )
                })?;

            #[cfg(unix)]
            tokio::spawn(reload_on_sighup(
                config.clone(),
                tls.cert_path.clone(),
                tls.key_path.clone(),
            ));

            tokio::spawn(log_listening(handle.clone(), "https"));

            axum_server::bind_rustls(listen_addr, config)
                .handle(handle)
                .serve(service)
                .await
        }
        None => {
            warn!(
                "FGATB_TLS_CERT and FGATB_TLS_KEY are not set, serving plain HTTP; use it only for local development"
            );

            tokio::spawn(log_listening(handle.clone(), "http"));

            axum_server::bind(listen_addr).handle(handle).serve(service).await
        }
    }
    .with_context(|| format!("server on {listen_addr} failed"))
}

async fn log_listening(handle: Handle<SocketAddr>, scheme: &'static str) {
    if let Some(listen_addr) = handle.listening().await {
        info!(%listen_addr, scheme, "Listening");
    }
}

async fn shut_down_on_ctrl_c(handle: Handle<SocketAddr>) {
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            info!("Shutting down");
            handle.graceful_shutdown(Some(SHUTDOWN_GRACE_PERIOD));
        }
        // The server keeps running until killed.
        Err(error) => error!(%error, "Failed to listen for shutdown signal"),
    }
}

/// Reloads the certificate and key on `SIGHUP`, so a renewed certificate is picked up without a restart.
///
/// A file that fails to load is logged and the current certificate stays in use.
#[cfg(unix)]
async fn reload_on_sighup(config: RustlsConfig, cert_path: std::path::PathBuf, key_path: std::path::PathBuf) {
    use tokio::signal::unix::{SignalKind, signal};

    let mut hangups = match signal(SignalKind::hangup()) {
        Ok(hangups) => hangups,
        Err(error) => {
            error!(%error, "Failed to listen for SIGHUP, the TLS certificate is not reloadable");
            return;
        }
    };

    while hangups.recv().await.is_some() {
        match config.reload_from_pem_file(&cert_path, &key_path).await {
            Ok(()) => info!("Reloaded the TLS certificate"),
            Err(error) => error!(%error, "Failed to reload the TLS certificate, keeping the current one"),
        }
    }
}
