//! Logging and tracing setup for Shield Core.

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize the tracing subscriber with JSON formatting.
///
/// Reads log level from RUST_LOG environment variable.
/// Defaults to `shield_core=info,tower_http=info`.
pub fn init() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("shield_core=info,tower_http=info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(true)
                .with_file(true)
                .with_line_number(true),
        )
        .init();
}

/// Initialize tracing for tests (human-readable format, no JSON).
#[cfg(test)]
pub fn _init_test() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("shield_core=debug")
        .try_init();
}
