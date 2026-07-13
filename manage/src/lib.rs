//! Belay management library crate.
//!
//! Provides Rust ports of the Python management commands:
//! - `posture`: host/VPS security posture checks (Phase 12 Task 1)
//! - `detect`: AI-agent detection (Phase 12 Task 2 — stub only in Task 1)

pub mod detect;
pub mod evidence;
pub mod gates;
pub mod hermes;
pub mod monitor;
pub mod posture;
pub mod protect;
pub mod render;
pub mod setup;
pub mod wire;
