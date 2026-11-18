use tracing_subscriber::EnvFilter;

/// Installs the global subscriber, filtered by `RUST_LOG` (`info` by default).
pub(crate) fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
}
