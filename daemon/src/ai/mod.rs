//! Off-by-default AI explainer (opt-in via the `ai` cargo feature).
//!
//! Modules so far: config (Task 1), the secret/host-path redactor (Task 2),
//! the grounded, schema-validated explainer trait + prompt builder (Task 3),
//! and the real rig-core-backed client (Task 4).

pub mod client_rig;
pub mod config;
pub mod explain;
pub mod redact;
pub mod secret;

pub use client_rig::RigClient;
pub use config::{AiConfig, AiMode};
pub use explain::{ai_explain, AiClient, AiError};
pub use redact::redact_action;
pub use secret::{ai_key_path, read_ai_key, write_ai_key};
