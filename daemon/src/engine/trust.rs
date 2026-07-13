//! Per-agent trust scoring (Aegis-derived heuristic, MIT). Pure, no ML.
//!
//! A session accrues "demerits" from `ask`/`deny` verdicts, weighted by severity
//! and **decayed over time** (half-life) so old behaviour fades and a session can
//! earn its trust back. The decayed demerit total maps to a letter grade.
//!
//! This is a standalone scoring layer over the verdict stream; wiring it to the
//! audit log / IPC / GUI is a follow-up.

use crate::engine::types::{Decision, Severity};

/// Trust grade, ordered worst → best so `APlus` is the maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Grade {
    F,
    D,
    C,
    B,
    A,
    APlus,
}

/// A single past verdict with the unix-seconds timestamp it occurred at.
#[derive(Debug, Clone, Copy)]
pub struct VerdictEvent {
    pub decision: Decision,
    pub severity: Severity,
    pub ts: u64,
}

// Demerit decay half-life: a demerit loses half its weight every hour.
const HALF_LIFE_SECS: f64 = 3600.0;
// Base demerit per verdict (allow contributes nothing).
const DENY_WEIGHT: f64 = 25.0;
const ASK_WEIGHT: f64 = 5.0;

fn severity_mult(s: Severity) -> f64 {
    match s {
        Severity::Critical => 2.0,
        Severity::High => 1.5,
        Severity::Medium => 1.0,
        Severity::Low => 0.5,
        Severity::Info => 0.25,
    }
}

fn event_demerit(e: &VerdictEvent, now: u64) -> f64 {
    let base = match e.decision {
        Decision::Deny => DENY_WEIGHT,
        Decision::Ask => ASK_WEIGHT,
        Decision::Allow => 0.0,
    };
    if base == 0.0 {
        return 0.0;
    }
    let age = now.saturating_sub(e.ts) as f64;
    let decay = 0.5_f64.powf(age / HALF_LIFE_SECS);
    base * severity_mult(e.severity) * decay
}

/// Total decayed demerits across a session's verdict history, as of `now`.
pub fn demerits(events: &[VerdictEvent], now: u64) -> f64 {
    events.iter().map(|e| event_demerit(e, now)).sum()
}

/// Map a session's verdict history to a trust [`Grade`] (as of `now`).
///
/// Thresholds are on the decayed demerit total: 0 → A+, then widening bands so a
/// single benign `ask` barely moves the grade while sustained denies sink it.
pub fn trust_grade(events: &[VerdictEvent], now: u64) -> Grade {
    let d = demerits(events, now);
    if d <= 0.0 {
        Grade::APlus
    } else if d < 5.0 {
        Grade::A
    } else if d < 20.0 {
        Grade::B
    } else if d < 50.0 {
        Grade::C
    } else if d < 100.0 {
        Grade::D
    } else {
        Grade::F
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(decision: Decision, severity: Severity, ts: u64) -> VerdictEvent {
        VerdictEvent { decision, severity, ts }
    }

    #[test]
    fn clean_history_is_a_plus() {
        assert_eq!(trust_grade(&[], 10_000), Grade::APlus);
        let allows = [ev(Decision::Allow, Severity::Info, 9_000)];
        assert_eq!(trust_grade(&allows, 10_000), Grade::APlus);
    }

    #[test]
    fn repeated_critical_denies_drop_to_f() {
        let now = 100;
        let bad = [
            ev(Decision::Deny, Severity::Critical, now),
            ev(Decision::Deny, Severity::Critical, now),
            ev(Decision::Deny, Severity::Critical, now),
        ]; // 25 * 2.0 * 3 = 150 demerits (no decay) -> F
        assert_eq!(trust_grade(&bad, now), Grade::F);
    }

    #[test]
    fn a_single_recent_ask_is_only_a_minor_ding() {
        let now = 100;
        let one_ask = [ev(Decision::Ask, Severity::Low, now)]; // 5 * 0.5 = 2.5 -> A
        assert_eq!(trust_grade(&one_ask, now), Grade::A);
    }

    #[test]
    fn old_bad_behaviour_decays_back_toward_trust() {
        // A critical deny 10 half-lives (10h) ago: 50 * 0.5^10 ≈ 0.05 demerits -> A.
        let then = 0;
        let now = (HALF_LIFE_SECS as u64) * 10;
        let old = [ev(Decision::Deny, Severity::Critical, then)];
        assert!(trust_grade(&old, now) >= Grade::A, "old deny should decay back to ~clean");
    }

    #[test]
    fn grade_ordering() {
        assert!(Grade::APlus > Grade::F);
        assert!(Grade::B > Grade::C);
    }
}
