//! Daily call-count budget for the optional BYOK AI layer -- a spend
//! ceiling for the same reason codex-security ships a `maxCostUsd` kill
//! switch: an operator who wires up a cloud provider key has nothing between
//! them and an unbounded bill if something loops or misbehaves. The idea is
//! borrowed as a concept only; no code from that project was read or copied.
//!
//! ## What is actually metered, and why
//!
//! Belay is offline-first and never sees a provider's bill. None of the
//! `rig-core` provider clients this daemon talks to (see
//! `crate::ai::client_rig`) return token-usage or cost data back through the
//! `AiClient::complete` trait -- it hands back plain text only. Any dollar
//! figure this module reported would therefore be invented, not observed,
//! and a per-provider static rate table would just be a confident-looking
//! guess that goes stale the moment a provider reprices. Both are explicitly
//! things this ceiling must not do.
//!
//! A raw token count is not directly observable either, for the same
//! reason -- it could only be estimated from prompt/response character
//! counts. But every prompt this daemon builds is already size-capped at the
//! call site: `ai::explain::user_prompt` runs the action through
//! `redact::redact_action`, and the skill judge caps findings at
//! `skills::judge::MAX_FINDINGS_IN_PROMPT` and the manifest body at
//! `skills::judge::MAX_SKILL_MD_CHARS`. Per-call size is therefore already
//! bounded structurally, upstream of this module. The genuinely unbounded
//! variable is CALL FREQUENCY: nothing stops a misbehaving or looping agent
//! from repeatedly triggering the on-demand explainer, or driving repeated
//! skill installs (each a `skills::judge::judge_skill_gate` call), an
//! unbounded number of times in a day. A CALL-COUNT budget is the one
//! ceiling this daemon can enforce honestly -- every unit it counts is a
//! real, observed event (one call attempted), not an estimate layered on an
//! estimate.
//!
//! ## Window and persistence
//!
//! belayd is a long-running daemon (weeks between restarts), so a
//! process-local counter that resets on restart would be close to useless
//! as a ceiling -- an operator would only ever discover that the hard way,
//! mid-runaway-loop, right after a restart. The counter is therefore
//! persisted to disk (`~/.belay/ai_budget.json`) and keyed by a CALENDAR-DAY
//! window (UTC date), not a rolling 24h window: a calendar day is simpler to
//! reason about ("today's usage"), matches how an operator would describe
//! their own cap ("N AI calls a day"), and avoids the extra bookkeeping of a
//! sliding-window data structure for a value that is advisory -- the gate
//! decision it can ever influence is fail-closed to no-AI, never fail-open
//! to allow (see [`allow_call`]'s doc comment).
//!
//! ## Default
//!
//! [`DEFAULT_MAX_CALLS_PER_DAY`] is a conservative non-zero default, not
//! unlimited. The BYOK AI layer is already off by default
//! (`AiConfig::mode: Off`), and cloud mode already requires an explicit
//! `cloud_consent: true` -- an operator who reaches this code has already
//! made two deliberate opt-in decisions. A third IMPLICIT decision
//! (unlimited spend, forever, with no visible ceiling) is not the
//! conservative choice for a security product whose stated failure class is
//! "silently kept going past a boundary it should have stopped at." The
//! chosen value is generous for legitimate daily use (occasional "Explain
//! with AI" clicks plus skill-install judge calls) while still bounding a
//! runaway loop to a two-digit number of provider round-trips before it goes
//! quiet for the rest of the day. `0` means unlimited, for an operator who
//! wants the ceiling off entirely -- an explicit choice, not the default.

use crate::ai::config::AiConfig;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// See the module doc's "Default" section.
pub const DEFAULT_MAX_CALLS_PER_DAY: u32 = 200;

/// Result of a single check-and-record attempt against the persisted state.
/// `CappedFirst` vs `CappedRepeat` is the "log once" distinction: only the
/// call that FIRST observes the cap already reached (and flips `logged`)
/// gets `CappedFirst`; every call after that, for the rest of the day, gets
/// `CappedRepeat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BudgetOutcome {
    Allowed,
    CappedFirst,
    CappedRepeat,
}

/// Read-only snapshot of today's budget usage, for surfacing over IPC
/// (`get_ai_config`) so a reached cap is visible state, not a silent stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetStatus {
    /// `0` means unlimited (no cap enforced).
    pub max_calls_per_day: u32,
    pub calls_today: u32,
    pub capped: bool,
}

/// Persisted budget state. `date` is a `YYYY-MM-DD` UTC calendar date (the
/// same convention `host_config::rfc3339_utc` produces), so a stale file
/// from a previous day is detected by plain string inequality -- no
/// date-parsing dependency needed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct BudgetState {
    date: String,
    calls: u32,
    /// Whether the "cap reached" log line has already been emitted for
    /// `date`. Reset to `false` whenever the day rolls over, alongside
    /// `calls` -- see [`BudgetState::for_today`].
    #[serde(default)]
    logged: bool,
}

impl BudgetState {
    fn for_today(today: &str) -> BudgetState {
        BudgetState {
            date: today.to_string(),
            calls: 0,
            logged: false,
        }
    }

    /// Load from `path`, fail-soft to a fresh state for `today` when the
    /// file is missing, unparseable, or holds a stale (different) date --
    /// mirrors `AiConfig::load`'s fail-soft-never-panics posture.
    fn load(path: &Path, today: &str) -> BudgetState {
        let parsed = std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<BudgetState>(&bytes).ok());
        match parsed {
            Some(s) if s.date == today => s,
            _ => BudgetState::for_today(today),
        }
    }

    /// Atomic, owner-only (0600) write -- same pattern as
    /// `AiConfig::save`: write a sibling temp file, chmod it, then rename
    /// over the target, so the real path is never observable at a looser
    /// mode and a crash never leaves a truncated file at `path`.
    fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
        Ok(())
    }
}

fn default_budget_path() -> PathBuf {
    crate::paths::data_dir().join("ai_budget.json")
}

// Test-only per-thread override for the path `allow_call`/`status` resolve.
// Exists because those two are the PRODUCTION entry points with no
// path-injection parameter (by design -- callers just pass `cfg`), yet
// other, unrelated pre-existing tests in this crate (e.g.
// `ipc::tests::explain_action_dispatch_returns_wellformed_failsafe`) also
// exercise real production code that ends up calling `allow_call` against
// the REAL `~/.belay/ai_budget.json` whenever a developer's machine has a
// real `~/.belay/ai.json` with AI actually enabled -- which is exactly the
// case on the machine this was developed on. Without this seam, a wiring
// test that clears/restores the real file around its own two calls can
// still race an unrelated, budget-unaware test running concurrently on a
// different thread and touching the SAME real file, corrupting the wiring
// test's own count. A `#[tokio::test]` function (default `current_thread`
// flavor) runs its entire body, including every `.await`, on the single OS
// thread `libtest` assigned to it, so a `thread_local` override set at the
// top of the test and cleared at the end is invisible to every other
// concurrently-running test -- true isolation, not just a lock around a
// shared resource other code doesn't know to respect.
#[cfg(test)]
thread_local! {
    static TEST_PATH_OVERRIDE: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// RAII guard: while alive, [`allow_call`]/[`status`] on THIS thread resolve
/// `path` instead of the real `~/.belay/ai_budget.json`. Clears the override
/// on drop (including on an early return/panic) so a test never leaks state
/// that could affect a later test reusing the same worker thread.
#[cfg(test)]
pub(crate) struct TestBudgetPathGuard;

#[cfg(test)]
impl TestBudgetPathGuard {
    pub(crate) fn set(path: PathBuf) -> Self {
        TEST_PATH_OVERRIDE.with(|cell| *cell.borrow_mut() = Some(path));
        TestBudgetPathGuard
    }
}

#[cfg(test)]
impl Drop for TestBudgetPathGuard {
    fn drop(&mut self) {
        TEST_PATH_OVERRIDE.with(|cell| *cell.borrow_mut() = None);
    }
}

/// The path [`allow_call`]/[`status`] actually resolve for the CURRENT call:
/// the test-only thread-local override when one is set, else the real path.
fn resolve_path_for_current_call() -> PathBuf {
    #[cfg(test)]
    {
        if let Some(p) = TEST_PATH_OVERRIDE.with(|cell| cell.borrow().clone()) {
            return p;
        }
    }
    default_budget_path()
}

/// Today's UTC calendar date as `YYYY-MM-DD`. Reuses
/// `host_config::rfc3339_utc`'s integer Gregorian-calendar math (no new
/// date/time dependency) and takes just the date component.
fn today_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    crate::host_config::rfc3339_utc(secs)[..10].to_string()
}

/// Process-wide serialization for the read-modify-write in
/// [`check_and_record_at`]. Two AI calls landing on different threads at
/// once (e.g. an IPC `explain_action` racing a background skill-watch judge
/// tick) must not race and lose an increment.
static BUDGET_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Core check-and-increment against an explicit path/day, so unit tests can
/// drive every branch (allowed, first-capped, repeat-capped, day rollover)
/// deterministically without touching the real `~/.belay/ai_budget.json` or
/// the real clock. Production always goes through [`allow_call`].
fn check_and_record_at(cfg: &AiConfig, path: &Path, today: &str) -> BudgetOutcome {
    let limit = cfg.max_ai_calls_per_day;
    if limit == 0 {
        return BudgetOutcome::Allowed; // unlimited: never touches persisted state
    }
    let _guard = BUDGET_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut state = BudgetState::load(path, today);
    if state.calls < limit {
        state.calls += 1;
        let _ = state.save(path); // fail-soft: a save failure still allows this call
        BudgetOutcome::Allowed
    } else if !state.logged {
        state.logged = true;
        let _ = state.save(path);
        BudgetOutcome::CappedFirst
    } else {
        BudgetOutcome::CappedRepeat
    }
}

fn status_at(cfg: &AiConfig, path: &Path, today: &str) -> BudgetStatus {
    let limit = cfg.max_ai_calls_per_day;
    let calls_today = if limit == 0 {
        0
    } else {
        BudgetState::load(path, today).calls
    };
    BudgetStatus {
        max_calls_per_day: limit,
        calls_today,
        capped: limit != 0 && calls_today >= limit,
    }
}

/// Check the daily call budget against the real persisted state, recording
/// this call if it is allowed. Returns whether the caller may actually make
/// the provider call.
///
/// SECURITY-RELEVANT INVARIANT: this is advisory bookkeeping only. `false`
/// here must always be treated by the caller exactly like a disabled
/// config, a timeout, or a provider error -- degrade to no-AI (no
/// explanation shown, no judge downgrade applied), NEVER to a gate
/// decision. Both call sites in this crate (`ai::explain::ai_explain` and
/// `skills::judge::judge_skill_inner`) already collapse every failure mode
/// to `None`, and every consumer of `None` from those two already falls
/// back to the pre-existing static behavior (no explanation / static
/// verdict unchanged) -- this cap adds one more `None`-producing condition
/// to paths that were already fail-soft by construction, it never adds a
/// new way to succeed.
///
/// Logs a single clear line the FIRST time a call is blocked for the day
/// (via `BudgetOutcome::CappedFirst`); every subsequent blocked call that
/// day is silent (`BudgetOutcome::CappedRepeat`) so the cap's effect is
/// visible exactly once, not spammed into the daemon's own log output.
pub fn allow_call(cfg: &AiConfig) -> bool {
    match check_and_record_at(cfg, &resolve_path_for_current_call(), &today_utc()) {
        BudgetOutcome::Allowed => true,
        BudgetOutcome::CappedFirst => {
            eprintln!(
                "[belayd] AI call budget reached: {} calls used today (cap: {}/day). \
                 Further AI explain/skill-judge calls are disabled until the next UTC day. \
                 This never changes a gate decision -- it only stops AI-generated \
                 explanations and skill-judge downgrades; the underlying static verdict \
                 still applies.",
                cfg.max_ai_calls_per_day, cfg.max_ai_calls_per_day
            );
            false
        }
        BudgetOutcome::CappedRepeat => false,
    }
}

/// Read-only snapshot of today's budget usage against the real persisted
/// state -- never mutates the counter. Used by `ipc::get_ai_config` so the
/// cap and its current usage are visible to an operator, not silent.
pub fn status(cfg: &AiConfig) -> BudgetStatus {
    status_at(cfg, &resolve_path_for_current_call(), &today_utc())
}

/// A unique temp-file path for a budget-state file, so tests never collide
/// with each other or with the real `~/.belay/ai_budget.json`. Shared by
/// this module's own tests and the sibling `ai::explain` / `skills::judge`
/// wiring tests (via [`TestBudgetPathGuard`]).
#[cfg(test)]
pub(crate) fn unique_temp_path_for_test(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "belayd-ai-budget-test-{}-{}-{}.json",
        std::process::id(),
        suffix,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::config::AiMode;

    fn cfg_with_cap(max_ai_calls_per_day: u32) -> AiConfig {
        AiConfig {
            mode: AiMode::Local,
            max_ai_calls_per_day,
            ..AiConfig::default()
        }
    }

    fn temp_path(suffix: &str) -> PathBuf {
        unique_temp_path_for_test(suffix)
    }

    #[test]
    fn default_matches_config_default() {
        assert_eq!(AiConfig::default().max_ai_calls_per_day, DEFAULT_MAX_CALLS_PER_DAY);
    }

    #[test]
    fn unlimited_cap_always_allows_and_never_touches_state() {
        let path = temp_path("unlimited");
        let cfg = cfg_with_cap(0);
        for _ in 0..10 {
            assert_eq!(check_and_record_at(&cfg, &path, "2026-07-30"), BudgetOutcome::Allowed);
        }
        assert!(!path.exists(), "unlimited cap must never create persisted state");
    }

    #[test]
    fn under_cap_allows_and_increments() {
        let path = temp_path("under-cap");
        let cfg = cfg_with_cap(3);
        assert_eq!(check_and_record_at(&cfg, &path, "2026-07-30"), BudgetOutcome::Allowed);
        assert_eq!(check_and_record_at(&cfg, &path, "2026-07-30"), BudgetOutcome::Allowed);
        assert_eq!(check_and_record_at(&cfg, &path, "2026-07-30"), BudgetOutcome::Allowed);
        let state = BudgetState::load(&path, "2026-07-30");
        assert_eq!(state.calls, 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn at_cap_first_block_then_repeat_blocks_are_distinguished() {
        let path = temp_path("at-cap");
        let cfg = cfg_with_cap(2);
        assert_eq!(check_and_record_at(&cfg, &path, "2026-07-30"), BudgetOutcome::Allowed);
        assert_eq!(check_and_record_at(&cfg, &path, "2026-07-30"), BudgetOutcome::Allowed);
        // Third call: at the cap for the first time -> CappedFirst (log once).
        assert_eq!(
            check_and_record_at(&cfg, &path, "2026-07-30"),
            BudgetOutcome::CappedFirst,
            "the call that first observes the reached cap must be CappedFirst"
        );
        // Every call after that, same day: CappedRepeat, never CappedFirst
        // again -- this is what keeps the "log once" behavior from spamming.
        for _ in 0..5 {
            assert_eq!(
                check_and_record_at(&cfg, &path, "2026-07-30"),
                BudgetOutcome::CappedRepeat,
                "repeat blocked calls on the same day must never re-trigger CappedFirst"
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn day_rollover_resets_the_counter() {
        let path = temp_path("rollover");
        let cfg = cfg_with_cap(1);
        assert_eq!(check_and_record_at(&cfg, &path, "2026-07-30"), BudgetOutcome::Allowed);
        assert_eq!(
            check_and_record_at(&cfg, &path, "2026-07-30"),
            BudgetOutcome::CappedFirst,
            "second call same day is capped"
        );
        // New UTC day: counter resets, first call of the new day is Allowed
        // again, and the "log once" flag resets too (next block is
        // CappedFirst again, not a leftover CappedRepeat from yesterday).
        assert_eq!(
            check_and_record_at(&cfg, &path, "2026-07-31"),
            BudgetOutcome::Allowed,
            "a new calendar day must reset the counter"
        );
        assert_eq!(
            check_and_record_at(&cfg, &path, "2026-07-31"),
            BudgetOutcome::CappedFirst,
            "the log-once flag must also reset with the new day"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_or_missing_file_fails_soft_to_fresh_state() {
        let path = temp_path("corrupt");
        std::fs::write(&path, "not json at all {{{").unwrap();
        let cfg = cfg_with_cap(5);
        assert_eq!(check_and_record_at(&cfg, &path, "2026-07-30"), BudgetOutcome::Allowed);
        let state = BudgetState::load(&path, "2026-07-30");
        assert_eq!(state.calls, 1, "a garbage file must fail soft to a fresh count, never panic");
        let _ = std::fs::remove_file(&path);

        // Missing file entirely.
        let missing = temp_path("missing");
        assert_eq!(check_and_record_at(&cfg, &missing, "2026-07-30"), BudgetOutcome::Allowed);
        let _ = std::fs::remove_file(&missing);
    }

    #[test]
    fn status_is_read_only_and_reports_current_usage() {
        let path = temp_path("status");
        let cfg = cfg_with_cap(2);
        assert_eq!(check_and_record_at(&cfg, &path, "2026-07-30"), BudgetOutcome::Allowed);

        let s1 = status_at(&cfg, &path, "2026-07-30");
        assert_eq!(s1, BudgetStatus { max_calls_per_day: 2, calls_today: 1, capped: false });

        // Calling status again must NOT consume budget -- a second real call
        // must still be call #2, not #3.
        let s2 = status_at(&cfg, &path, "2026-07-30");
        assert_eq!(s2, s1, "status must be idempotent / read-only");

        assert_eq!(check_and_record_at(&cfg, &path, "2026-07-30"), BudgetOutcome::Allowed);
        let s3 = status_at(&cfg, &path, "2026-07-30");
        assert_eq!(s3, BudgetStatus { max_calls_per_day: 2, calls_today: 2, capped: true });
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn status_unlimited_reports_zero_and_never_capped() {
        let path = temp_path("status-unlimited");
        let cfg = cfg_with_cap(0);
        let s = status_at(&cfg, &path, "2026-07-30");
        assert_eq!(s, BudgetStatus { max_calls_per_day: 0, calls_today: 0, capped: false });
    }

    // ── `TestBudgetPathGuard` / `resolve_path_for_current_call` ────────────
    //
    // Direct coverage for the seam the `ai::explain` / `skills::judge`
    // wiring tests rely on: while a guard is alive on this thread,
    // `allow_call`/`status` (the real PRODUCTION entry points, not the
    // injectable `check_and_record_at`/`status_at`) resolve the overridden
    // path instead of the real `~/.belay/ai_budget.json`.

    #[test]
    fn resolve_path_for_current_call_uses_override_when_set_and_clears_on_drop() {
        let path = unique_temp_path_for_test("resolve-override");
        assert_ne!(
            resolve_path_for_current_call(), path,
            "no override set yet -> must resolve the real default path, not the temp one"
        );
        {
            let _guard = TestBudgetPathGuard::set(path.clone());
            assert_eq!(resolve_path_for_current_call(), path, "override must be honored while alive");
        }
        assert_ne!(
            resolve_path_for_current_call(), path,
            "override must be cleared once the guard drops"
        );
    }

    #[test]
    fn allow_call_and_status_use_the_overridden_path() {
        let path = unique_temp_path_for_test("override-wiring");
        let cfg = cfg_with_cap(1);
        let _guard = TestBudgetPathGuard::set(path.clone());

        assert!(allow_call(&cfg), "first call under the cap must be allowed");
        let s = status(&cfg);
        assert_eq!(s, BudgetStatus { max_calls_per_day: 1, calls_today: 1, capped: true });
        assert!(!allow_call(&cfg), "second call at the cap must be blocked");

        drop(_guard);
        // The overridden file must actually have been written to (not the
        // real one) -- proves the override was really in effect, not a
        // no-op.
        assert!(path.exists(), "the overridden path must have received the writes");
        let _ = std::fs::remove_file(&path);
    }
}
