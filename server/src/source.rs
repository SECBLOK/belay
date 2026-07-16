//! AGPL §13 "network use" source affordance.
//!
//! Belay is AGPL-3.0-or-later. Under §13 ("Remote Network Interaction"),
//! anyone who interacts with a *modified* version of this program over a
//! network must be offered a way to get that modified version's Corresponding
//! Source. `GET /api/source` is the machine-readable half of that affordance
//! (the dashboard footer link in `web/src/components/Sidebar.tsx` is the
//! human-facing half): a small, unauthenticated, side-effect-free route
//! reporting where the source for the running binary lives.
//!
//! Self-hosters who modify `belay serve` and expose it over a network must
//! update [`REPOSITORY_URL`] to point at their own published source, per §13.

use axum::response::Json;
use serde_json::{json, Value};

/// Canonical repository URL for this project (see `NOTICE`, `README.md`,
/// `CONTRIBUTING.md`). Self-hosters shipping a modified `belay serve` over a
/// network must point this at their own published source per AGPL §13.
pub const REPOSITORY_URL: &str = "https://github.com/SECBLOK/belay";

/// Git short-SHA this binary was built from, embedded by `build.rs` via
/// `git rev-parse --short HEAD`. Falls back to `"unknown"` when git is
/// unavailable at build time (e.g. building from a source tarball) — the
/// build itself never fails offline.
const GIT_SHA: &str = env!("BELAY_GIT_SHA");

/// GET /api/source — AGPL §13 network-use source affordance. Deliberately
/// unauthenticated: it must be reachable by anyone the running instance
/// serves over the network, not just logged-in operators.
pub async fn source_info() -> Json<Value> {
    Json(json!({
        "repository": REPOSITORY_URL,
        "version": env!("CARGO_PKG_VERSION"),
        "commit": GIT_SHA,
        "license": "AGPL-3.0-or-later",
    }))
}
