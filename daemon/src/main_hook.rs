//! Standalone `belay-hook` binary — thin UDS client for the PreToolUse
//! hook. The logic lives in `belayd::app::run_hook` so the unified
//! `belay hook` subcommand can reuse it; this bin just delegates.
fn main() {
    // Standalone bin has no event positional → treat as PreToolUse (audit on).
    belayd::app::run_hook(None);
}
