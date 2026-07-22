//! Locale-aware rendering of the rule catalogue's user-facing prose.
//!
//! The daemon already renders `reason` + `explain` server-side and already
//! knows the operator's locale (`host_config::locale`). This module makes that
//! rendering locale-aware: a `Verdict`'s prose is rewritten into the active
//! language just before it is serialized to the approval surface, so the GUI,
//! tray, toast, and every channel adapter receive already-translated strings.
//! The wire type stays `string`, so no surface has to change and a stale
//! desktop build can never receive an empty prompt — it just gets English.
//!
//! Translations are COMPILED IN via `include_str!` and never read from disk at
//! runtime: a translation file swappable after install would be a way to
//! rewrite the text of a security decision (make a deny read like an allow).
//!
//! Staleness is guarded twice. Each translation records `src_sha`, the hash of
//! the English prose it was made from. The coverage test refuses a build whose
//! translations don't match today's English; and at runtime, `localize`
//! recomputes the hash and falls back to English for any rule whose stored
//! `src_sha` no longer matches — a stale Chinese explanation of behaviour a
//! rule no longer has is worse than English, because the operator cannot tell
//! it is wrong.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::rules::Explain;
use super::types::Verdict;

const ZH_HANS_YAML: &str = include_str!("../../../rules/i18n/catalog.zh-Hans.yaml");

/// One rule's translated prose plus the hash of the English it was made from.
/// Every field defaults to empty so a partial entry still parses and falls back
/// to English field-by-field.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Translation {
    #[serde(default)]
    pub src_sha: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub what: String,
    #[serde(default)]
    pub why_risky: String,
    #[serde(default)]
    pub normal_use: String,
    #[serde(default)]
    pub suggested_action: String,
}

#[derive(Debug, Deserialize)]
struct RawCatalog {
    #[serde(default)]
    rules: HashMap<String, Translation>,
}

/// locale -> (rule id -> translation). English is the source locale and never
/// appears here. Parsed once; a malformed sidecar yields an empty map (fail to
/// English) rather than panicking the daemon.
static CATALOGS: LazyLock<HashMap<&'static str, HashMap<String, Translation>>> =
    LazyLock::new(|| {
        let mut m = HashMap::new();
        let zh: HashMap<String, Translation> = serde_yaml::from_str::<RawCatalog>(ZH_HANS_YAML)
            .map(|c| c.rules)
            .unwrap_or_default();
        m.insert("zh-Hans", zh);
        m
    });

/// The hash that ties a translation to the exact English it was made from.
/// SHA-256 (first 16 hex = 64 bits, ample to detect an edit) over the six prose
/// fields, NUL-separated so field boundaries can't be shifted by moving text
/// across them. A `None` explain hashes as five empty fields.
pub fn source_sha(reason: &str, explain: Option<&Explain>) -> String {
    let e = explain;
    let fields = [
        reason,
        e.map(|x| x.summary.as_str()).unwrap_or(""),
        e.map(|x| x.what.as_str()).unwrap_or(""),
        e.map(|x| x.why_risky.as_str()).unwrap_or(""),
        e.map(|x| x.normal_use.as_str()).unwrap_or(""),
        e.map(|x| x.suggested_action.as_str()).unwrap_or(""),
    ];
    let mut h = Sha256::new();
    for f in fields {
        h.update(f.as_bytes());
        h.update([0x1f]);
    }
    let full = format!("{:x}", h.finalize());
    full[..16].to_string()
}

/// The stored translation for a rule in a locale, if one exists. Does NOT check
/// staleness — callers that have the English source verify it themselves.
pub fn translation_for(id: &str, locale: &str) -> Option<&'static Translation> {
    CATALOGS.get(locale).and_then(|m| m.get(id))
}

/// Merge a translation over an English `Explain`, field by field: a non-empty
/// translated field wins, an empty one keeps the English. Never yields a blank
/// field where English had text.
fn merge_explain(en: &Explain, tr: &Translation) -> Explain {
    let pick = |t: &str, e: &str| if t.is_empty() { e.to_string() } else { t.to_string() };
    Explain {
        summary: pick(&tr.summary, &en.summary),
        what: pick(&tr.what, &en.what),
        why_risky: pick(&tr.why_risky, &en.why_risky),
        normal_use: pick(&tr.normal_use, &en.normal_use),
        suggested_action: pick(&tr.suggested_action, &en.suggested_action),
    }
}

/// Rewrite a verdict's prose into `locale`, in place. A no-op for the source
/// locale (`en`) or an unknown one. For the `explain` block (the rich prose)
/// the English source is present, so staleness is verified here and a stale
/// translation is skipped in favour of English. The composite `reason`
/// (`id:phrase; …`) is translated segment by segment on a best-effort basis —
/// the coverage test is what guarantees those are current.
pub fn localize(v: &mut Verdict, locale: &str) {
    if locale == "en" || !CATALOGS.contains_key(locale) {
        return;
    }

    // Rich explain: keyed by the winning rule, staleness-checked against the
    // English that is right here in the verdict.
    if let (Some(id), Some(en)) = (v.primary_rule.clone(), v.explain.clone()) {
        if let Some(tr) = translation_for(&id, locale) {
            if tr.src_sha == source_sha(&v_reason_for(&id, &v.reason), Some(&en)) {
                v.explain = Some(merge_explain(&en, tr));
            }
        }
    }

    // Composite reason: `id:phrase` segments joined by "; ". Translate each
    // phrase by its rule id; leave a segment untouched if it has no
    // translation or doesn't parse.
    v.reason = v
        .reason
        .split("; ")
        .map(|seg| match seg.split_once(':') {
            Some((id, phrase)) => {
                let t = translation_for(id, locale)
                    .map(|t| t.reason.as_str())
                    .filter(|s| !s.is_empty())
                    .unwrap_or(phrase);
                format!("{id}:{t}")
            }
            None => seg.to_string(),
        })
        .collect::<Vec<_>>()
        .join("; ");
}

/// Extract the English `reason` phrase for `id` out of the composite verdict
/// reason (`id:phrase; …`), so the explain staleness hash is computed over the
/// same reason the translation was authored against. Falls back to the whole
/// string if the id isn't found (single-rule verdicts, or an unexpected shape).
fn v_reason_for(id: &str, composite: &str) -> String {
    for seg in composite.split("; ") {
        if let Some((sid, phrase)) = seg.split_once(':') {
            if sid == id {
                return phrase.to_string();
            }
        }
    }
    composite.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::rules::RuleSet;

    fn catalog() -> RuleSet {
        RuleSet::load().expect("catalog loads")
    }

    /// THE load-bearing invariant. Every rule must have a translation for every
    /// shipped locale, and every translation must match the English it was made
    /// from. A stale Chinese explanation describing behaviour a rule no longer
    /// has is worse than English, because the operator cannot tell it is wrong.
    #[test]
    fn every_rule_is_translated_and_no_translation_is_stale() {
        let rs = catalog();
        for locale in crate::host_config::SUPPORTED_LOCALES
            .iter()
            .filter(|l| **l != "en")
        {
            for rule in &rs.rules {
                let (id, reason, explain) = rule.i18n_source();
                let tr = translation_for(id, locale).unwrap_or_else(|| {
                    panic!("rule {id} has no {locale} translation")
                });
                assert_eq!(
                    tr.src_sha,
                    source_sha(reason, explain),
                    "rule {id} changed since its {locale} translation was written \
                     — retranslate and update src_sha"
                );
            }
        }
    }

    /// The sidecar must not name rules that no longer exist (a rename leaves an
    /// orphan whose translation silently never renders).
    #[test]
    fn no_orphan_translations() {
        let rs = catalog();
        let ids: std::collections::HashSet<&str> =
            rs.rules.iter().map(|r| r.i18n_source().0).collect();
        for locale in crate::host_config::SUPPORTED_LOCALES {
            if let Some(m) = CATALOGS.get(locale) {
                for k in m.keys() {
                    assert!(ids.contains(k.as_str()), "orphan {locale} translation: {k}");
                }
            }
        }
    }

    /// Not a test — a generator. Prints, for every rule, a YAML skeleton entry
    /// carrying the correct `src_sha` and the English prose as the value to be
    /// replaced with a translation. Run with:
    ///   cargo test -p belayd dump_rule_i18n_skeleton -- --ignored --nocapture
    #[test]
    #[ignore]
    fn dump_rule_i18n_skeleton() {
        let rs = catalog();
        let y = |s: &str| serde_yaml::to_string(&s).unwrap().trim_end().to_string();
        println!("version: 1");
        println!("rules:");
        for rule in &rs.rules {
            let (id, reason, explain) = rule.i18n_source();
            println!("  {id}:");
            println!("    src_sha: {:?}", source_sha(reason, explain));
            println!("    reason: {}", y(reason));
            if let Some(e) = explain {
                println!("    summary: {}", y(&e.summary));
                println!("    what: {}", y(&e.what));
                println!("    why_risky: {}", y(&e.why_risky));
                println!("    normal_use: {}", y(&e.normal_use));
                println!("    suggested_action: {}", y(&e.suggested_action));
            }
        }
    }

    #[test]
    fn source_sha_changes_when_english_changes() {
        let e1 = Explain {
            summary: "a".into(),
            what: "b".into(),
            why_risky: "c".into(),
            normal_use: "d".into(),
            suggested_action: "e".into(),
        };
        let mut e2 = e1.clone();
        e2.summary = "A".into();
        assert_ne!(source_sha("r", Some(&e1)), source_sha("r", Some(&e2)));
        // Moving text across a field boundary must not collide.
        let e3 = Explain { summary: "ab".into(), what: "".into(), ..e1.clone() };
        let e4 = Explain { summary: "a".into(), what: "b".into(), ..e1.clone() };
        assert_ne!(source_sha("r", Some(&e3)), source_sha("r", Some(&e4)));
    }

    #[test]
    fn en_and_unknown_locale_are_noops() {
        let rs = catalog();
        let rule = rs.rules.iter().find(|r| r.i18n_source().2.is_some()).unwrap();
        let (id, reason, explain) = rule.i18n_source();
        let base = Verdict {
            decision: crate::engine::types::Decision::Ask,
            reason: format!("{id}:{reason}"),
            rules: vec![id.to_string()],
            severity: crate::engine::types::Severity::Info,
            primary_rule: Some(id.to_string()),
            category: None,
            owasp: None,
            atlas: None,
            explain: explain.cloned(),
        };
        for loc in ["en", "fr", "klingon"] {
            let mut v = base.clone();
            localize(&mut v, loc);
            assert_eq!(v.reason, base.reason, "locale {loc} must not touch reason");
            assert_eq!(v.explain, base.explain, "locale {loc} must not touch explain");
        }
    }

    /// End to end: a real rule localizes to Chinese and back-to-English on a
    /// stale hash.
    #[test]
    fn localize_translates_then_falls_back_when_stale() {
        let rs = catalog();
        let rule = rs.rules.iter().find(|r| r.i18n_source().2.is_some()).unwrap();
        let (id, reason, explain) = rule.i18n_source();
        let tr = translation_for(id, "zh-Hans").expect("has translation");

        let mut v = Verdict {
            decision: crate::engine::types::Decision::Ask,
            reason: format!("{id}:{reason}"),
            rules: vec![id.to_string()],
            severity: crate::engine::types::Severity::Info,
            primary_rule: Some(id.to_string()),
            category: None,
            owasp: None,
            atlas: None,
            explain: explain.cloned(),
        };
        localize(&mut v, "zh-Hans");
        // The explain summary is now the (non-empty) Chinese one.
        assert_eq!(v.explain.as_ref().unwrap().summary, tr.summary);
        assert!(!tr.summary.is_empty());
        // And the reason phrase was translated.
        assert_eq!(v.reason, format!("{id}:{}", tr.reason));

        // If the English drifts (verdict carries different English than the
        // translation was made from), the explain falls back to that English.
        let mut drifted = v.clone();
        drifted.explain = explain.cloned();
        if let Some(e) = drifted.explain.as_mut() {
            e.summary = "DRIFTED ENGLISH".into();
        }
        drifted.reason = format!("{id}:{reason}");
        localize(&mut drifted, "zh-Hans");
        assert_eq!(
            drifted.explain.as_ref().unwrap().summary,
            "DRIFTED ENGLISH",
            "a stale explain must fall back to the English in the verdict"
        );
    }
}
