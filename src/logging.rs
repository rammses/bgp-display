use std::path::PathBuf;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

/// Lag-detection thresholds (microseconds).
pub mod thresholds {
    /// UI draw taking longer than this triggers a WARN trace.
    pub const DRAW_WARN_US: u128 = 16_000; // 16 ms (60 fps budget)
    /// Event handler taking longer than this triggers a WARN trace.
    pub const EVENT_WARN_US: u128 = 5_000; // 5 ms
    /// SSH command taking longer than this triggers a WARN trace.
    pub const SSH_WARN_US: u128 = 10_000_000; // 10 s
    /// Data-fetch request taking longer than this triggers a WARN trace.
    pub const FETCH_WARN_US: u128 = 15_000_000; // 15 s
}

fn log_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("bgp-link-manager")
        .join("logs")
}

/// Returns the path to the active log directory (for display in UI).
pub fn log_path() -> PathBuf {
    log_dir()
}

/// Initialise file-based tracing.
///
/// Returns a [`WorkerGuard`] that **must** be held alive for the lifetime of
/// the program — dropping it flushes and shuts down the background writer.
///
/// Log level is controlled by `BGP_LM_LOG` env var (default: `info`).
/// Example: `BGP_LM_LOG=debug cargo run`
pub fn init() -> WorkerGuard {
    let dir = log_dir();
    std::fs::create_dir_all(&dir).ok();

    let file_appender = tracing_appender::rolling::daily(&dir, "bgp-link-manager.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let filter = EnvFilter::try_from_env("BGP_LM_LOG").unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(true)
        .with_thread_ids(true)
        .init();

    tracing::info!(
        log_dir = %dir.display(),
        "bgp-link-manager logging initialised"
    );

    guard
}
