//! Stateful port of correlate.py: arm->sink + lethal trifecta + egress memory.
use crate::engine::rules::RuleHit;
use crate::engine::types::{Decision, SessionState, Severity};

pub fn correlate(hits: &[RuleHit], state: &SessionState) -> Vec<RuleHit> {
    let mut extra = Vec::new();
    let has_sink = hits.iter().any(|h| h.sink);
    if !state.armed.is_empty() && has_sink {
        let mut armed: Vec<&String> = state.armed.iter().collect();
        armed.sort();
        extra.push(RuleHit {
            id: "correlate.arm_sink".into(),
            category: "egress".into(),
            severity: Severity::Critical,
            decision: Decision::Deny,
            reason: format!("outbound action while session holds secrets {armed:?}"),
            sink: true,
            arms: None,
            ingest: false,
            owasp: None,
            atlas: None,
            explain: None,
        });
    }
    let trifecta_fired = !state.armed.is_empty() && has_sink;
    if state.untrusted_ingest && trifecta_fired {
        extra.push(RuleHit {
            id: "correlate.lethal_trifecta".into(),
            category: "egress".into(),
            severity: Severity::Critical,
            decision: Decision::Deny,
            reason: "lethal trifecta: untrusted content + secrets + exfil-capable action".into(),
            sink: true,
            arms: None,
            ingest: false,
            owasp: None,
            atlas: None,
            explain: None,
        });
    }
    // Alert-only: a session tainted by untrusted content ingest (possible
    // tool-result/prompt injection) then takes a genuinely risky action
    // (Ask/Deny). This never changes the verdict — `decision: Decision::Allow`
    // is load-bearing, since `resolve()` is most-restrictive-wins, an Allow
    // hit can only ever be a no-op on the final decision. It exists purely so
    // the audit trail records the correlation. Synthetic correlate.* hits are
    // excluded from the "risky action" scan so this can never self-trigger.
    // Suppressed when the lethal trifecta already fired for this event, so
    // the trifecta (which owns the secret-exfil case) is the only alert and
    // there is no double-alert; this bucket owns the other risky actions
    // (destructive/rce/etc.) that follow an injection.
    let has_risky_action = hits.iter().any(|h| {
        !h.id.starts_with("correlate.")
            && (h.decision == Decision::Ask || h.decision == Decision::Deny)
    });
    if state.untrusted_ingest && has_risky_action && !trifecta_fired {
        extra.push(RuleHit {
            id: "correlate.injection_to_action".into(),
            category: "recon".into(),
            severity: Severity::High,
            decision: Decision::Allow,
            reason: "risky action after untrusted-content ingest (possible tool-result injection)"
                .into(),
            sink: false,
            arms: None,
            ingest: false,
            owasp: None,
            atlas: None,
            explain: None,
        });
    }
    extra
}

pub fn apply_arming(hits: &[RuleHit], state: &mut SessionState) {
    for h in hits {
        if let Some(a) = &h.arms {
            state.armed.insert(a.clone());
        }
        // An untrusted-content ingest taints the session for the remainder of
        // its lifetime, enabling the lethal-trifecta correlation above.
        if h.ingest {
            state.untrusted_ingest = true;
        }
    }
}
