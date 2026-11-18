use tracing_subscriber::EnvFilter;

/// Environment variable holding the log filter, in the `EnvFilter` directive syntax.
const LOGGING_ENV: &str = "FGATB_LOGGING";

const DEFAULT_FILTER: &str = "trace";

/// Installs the global subscriber, filtered by [`LOGGING_ENV`] (`trace` by default).
pub(crate) fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_env(LOGGING_ENV).unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER)))
        .init();
}
