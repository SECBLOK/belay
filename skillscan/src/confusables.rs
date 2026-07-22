//! Homoglyph / RTL-override detection for tool-poisoning (TP2). Uses the
//! `unicode-security` crate's mixed-script confusable detection, plus an explicit
//! bidi-control check.

use unicode_security::MixedScript;

const BIDI_CONTROLS: &[char] = &['\u{202A}','\u{202B}','\u{202C}','\u{202D}','\u{202E}','\u{2066}','\u{2067}','\u{2068}','\u{2069}'];

/// True if `s` contains a bidi-control (RTL-override etc.) character, or a
/// whitespace-delimited non-ASCII token that mixes scripts (e.g. Latin+Cyrillic
/// homoglyphs) — both classic tool-poisoning obfuscation techniques.
///
/// Note on the `unicode-security` API: `MixedScript::is_single_script` is
/// implemented for `&str` directly (per-string resolved-script-set check), not
/// for a `char`/`Chars` iterator — so the call below is `tok.is_single_script()`,
/// not `tok.chars().is_single_script()`.
pub fn has_confusable_or_rtl(s: &str) -> bool {
    if s.chars().any(|c| BIDI_CONTROLS.contains(&c)) { return true; }
    // Any non-ASCII whitespace-delimited token that is not single-script is suspicious.
    s.split_whitespace().any(|tok| !tok.is_ascii() && !tok.is_single_script())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plain_ascii_is_clean() { assert!(!has_confusable_or_rtl("read files")); }
    #[test]
    fn cyrillic_homoglyph_flagged() { assert!(has_confusable_or_rtl("re\u{0430}d")); } // U+0430 Cyrillic a
    #[test]
    fn rtl_override_flagged() { assert!(has_confusable_or_rtl("file\u{202E}gnp.exe")); }
}
