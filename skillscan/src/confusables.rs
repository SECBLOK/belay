//! Homoglyph / RTL-override detection for tool-poisoning (TP2). Uses the
//! `unicode-security` crate's mixed-script confusable detection, plus an explicit
//! bidi-control check, plus the Unicode Tags fold ("ASCII smuggling").

use unicode_security::MixedScript;

/// Folds the Unicode **Tags** block (U+E0000–U+E007F) back to the ASCII it
/// mirrors: U+E0020–U+E007E map to 0x20–0x7E by subtracting 0xE0000.
///
/// "ASCII smuggling" is a distinct carrier from the zero-width and bidi
/// characters handled elsewhere in this module: every ASCII character has an
/// invisible twin here, so a COMPLETE instruction can be written so that it
/// renders as nothing anywhere — editor, terminal, review UI — while many
/// models still read it as text.
///
/// Fold rather than strip. Stripping deletes the payload; folding recovers it
/// as ASCII so every existing rule matches it with no new pattern. The rules
/// were never wrong, they just never saw the input.
///
/// Emoji subdivision flags (U+1F3F4 + tag letters + U+E007F) are the one
/// legitimate modern use and appear in real docs, so a well-formed sequence
/// passes through untouched. Unicode deprecated tag characters for their
/// original language-tagging purpose, so nothing else benign remains.
///
/// Deliberately duplicated from `belayd::engine::rules::fold_tag_characters`:
/// skillscan is a leaf crate with no daemon dependency — the same trade-off
/// `daemon/src/mcp_scan.rs` documents for its injection regex. Keep the two in
/// sync if either changes.
pub fn fold_tag_characters(s: &str) -> String {
    if !s.chars().any(|c| matches!(c as u32, 0xE0000..=0xE007F)) {
        return s.to_string(); // overwhelmingly the common case
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\u{1F3F4}' {
            let mut j = i + 1;
            while j < chars.len() && matches!(chars[j] as u32, 0xE0020..=0xE007E) {
                j += 1;
            }
            if j > i + 1 && chars.get(j) == Some(&'\u{E007F}') {
                out.extend(&chars[i..=j]);
                i = j + 1;
                continue;
            }
        }
        match c as u32 {
            n @ 0xE0020..=0xE007E => out.push(char::from_u32(n - 0xE0000).unwrap_or(c)),
            0xE0000..=0xE007F => {}
            _ => out.push(c),
        }
        i += 1;
    }
    out
}

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
