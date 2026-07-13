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
    if state.untrusted_ingest && !state.armed.is_empty() && has_sink {
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
