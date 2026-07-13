//! Standalone `belayd` binary. The logic lives in `belayd::app` so
//! the unified `belay daemon` subcommand can reuse it; this bin just
//! delegates.
fn main() {
    belayd::app::run_daemon();
}
