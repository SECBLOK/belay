//! Privacy-safe native notifications.
//!
//! The notification BODY uses the rule CATEGORY only — it never contains the
//! secret path, command, or argument that triggered the event.

/// Notification body uses the rule CATEGORY only — never the secret path/argument.
pub fn notification_copy(category: &str) -> (String, String) {
    let title = "Belay".to_string();
    let body = match category {
        "secrets" => "Blocked an attempt to read credentials".to_string(),
        "destructive" => "Blocked a destructive command".to_string(),
        "egress" => "Flagged an unusual outbound connection".to_string(),
        _ => "An agent action needs your review".to_string(),
    };
    (title, body)
}

/// Notification BODY for a single actionable row: prefer the daemon's curated,
/// path-free `explain.summary` when present; otherwise fall back to the privacy-
/// safe category one-liner. A blank/whitespace summary also falls back, so the
/// toast body is never empty. (Explain & Advise, Task 10.)
pub fn notification_copy_for(explain_summary: Option<&str>, category: &str) -> String {
    match explain_summary {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => notification_copy(category).1,
    }
}

/// Notify only when the window is not frontmost AND the event is actionable.
pub fn should_notify(frontmost: bool, actionable: bool) -> bool {
    !frontmost && actionable
}

/// One notification line for N simultaneous pending approvals.
pub fn digest_copy(n: usize) -> (String, String) {
    (
        "Belay".into(),
        format!("{n} agent actions need your review"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn copy_never_leaks_the_path() {
        let (_t, body) = notification_copy("secrets");
        assert!(!body.contains("/"));
        assert!(body.contains("credentials"));
    }
    #[test]
    fn only_notifies_when_backgrounded_and_actionable() {
        assert!(should_notify(false, true));
        assert!(!should_notify(true, true));
        assert!(!should_notify(false, false));
    }

    #[test]
    fn notification_prefers_explain_summary() {
        let copy = notification_copy_for(Some("Reads your .env secrets"), "secrets");
        assert_eq!(copy, "Reads your .env secrets");
        // Falls back to the category one-liner when no explain summary is present.
        assert!(notification_copy_for(None, "secrets")
            .to_lowercase()
            .contains("credential"));
        // Blank/whitespace summary also falls back (never an empty toast body).
        assert!(notification_copy_for(Some("  "), "secrets")
            .to_lowercase()
            .contains("credential"));
    }
}

#[cfg(test)]
mod digest_tests {
    use super::*;
    #[test]
    fn one_line_for_many() {
        let (_t, b) = digest_copy(3);
        assert!(b.contains("3"));
    }
}
