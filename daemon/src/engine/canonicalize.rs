//! Wrapper/flag normalization for Belay's command gate.
//!
//! `canonicalize()` strips command wrappers and normalizes flag/spelling
//! variants so a dangerous invocation is recognized regardless of how it was
//! wrapped, quoted, or spelled out. It implements transforms 4-6 of the
//! six-transform design (transforms 1-2 are `rules::command_pre` —
//! invisible-strip + line-continuation fold; transform 3, whitespace-collapse,
//! runs *after* this module, not before it — see "Calling convention" below):
//!
//! 4. `strip_wrapper_prefixes` — `sudo`/`env`/`command`/`\cmd`/bare `VAR=val`
//!    wrappers, bounded.
//! 5. `unwrap_quoted_tokens`   — command-name-form (`'r'm` -> `rm`) and
//!    target-argument-form (`rm -rf "/"` -> `rm -rf /`) quote splicing.
//! 6. `normalize_flag_forms`  — long->short flag mapping, short-flag cluster
//!    merge, interpreter-version fold (`python3.11` -> `python`), and
//!    benign-preflag collapse (`python -u -c` -> `python -c`).
//!
//! A seventh, unnumbered transform — `$IFS`/`${IFS}` whitespace-substitution
//! folding — is included here too (not in `rules::norm_cmd`) precisely so it
//! does not interact with the data-region masking predicate upstream; see the
//! doc on [`fold_ifs`].
//!
//! # Calling convention — quote-intact input, BEFORE masking
//!
//! `RuleSet::haystacks` (`rules.rs`) calls `canonicalize(&pre)` where `pre` is
//! `rules::command_pre`'s output: invisible-stripped and line-continuation-
//! folded, but **not yet** run through `data_region::mask_data_regions` and
//! **not yet** whitespace-collapsed. Real quote characters and real newlines
//! are still present. This ordering is load-bearing (Task-3 fix): an earlier
//! version ran `canonicalize` on the already-masked, already-collapsed
//! haystack, where a disqualified data-consuming argument (one containing
//! `$`/backtick/paren — e.g. `$USER`) has its *content* left visible but its
//! enclosing quote delimiters masked to spaces. A quote-protected `;` inside
//! such an argument — `echo "$USER; rm -r -f /"` — then looked, by the time
//! `canonicalize` saw it, exactly like a bare unquoted `;`: the segment
//! splitter split a fake new segment there, put `rm` at that segment's
//! first-token position, and the flag-cluster-merge transform fabricated `rm
//! -rf /` out of text that was never anything but echoed data. Calling
//! `canonicalize` on the quote-intact `pre` instead means its splitter sees
//! the real quotes, correctly keeps the whole quoted argument as one segment
//! (first token `echo`, not `rm`), and never touches anything inside it — see
//! `fp_guard_quoted_semicolon_multiarg_in_echo_with_dollar` and its siblings
//! in `bypass_corpus::false_positive_guards`.
//!
//! `RuleSet::haystacks` then runs `data_region::mask_data_regions` and
//! whitespace-collapse over `canonicalize`'s *output* to produce
//! `hay_canonical` — masking still applies to the canonicalized text (so a
//! genuinely-executed `echo "$(rm -rf /)"` still denies), it just runs after
//! canonicalization rather than before it.
//!
//! Because `pre` is not yet whitespace-collapsed, this module's own
//! tokenizer/segment-splitter must treat runs of whitespace, and real
//! newlines, as ordinary separators — see "Position-scoping" below and
//! [`split_top_level_segments`]'s own doc.
//!
//! # Position-scoping — the safety invariant
//!
//! Every transform here touches only **the recognized command-name token (the
//! first non-wrapper token of a chaining-delimited segment) and the option/
//! argument tokens immediately following it** — never arbitrary later
//! positions in the haystack. Segments are split on the same shell-chaining
//! metacharacters `allowlist::has_shell_chaining` already checks for (`&&`,
//! `||`, `;`, `|`), plus a real top-level newline (also one of
//! `has_shell_chaining`'s metacharacters, and a real command separator in
//! every shell) — reusing that vocabulary rather than inventing a second one.
//! Quote-awareness (a delimiter inside a quoted span is never a real
//! delimiter) is what keeps a data argument (an `echo`/`printf` string, a
//! `git commit -m` message) safe from being rewritten: it is never at
//! first-token-of-segment position, so it is never touched, regardless of
//! what it contains. See `fp_guard_quote_spliced_warning_in_echo` in
//! `bypass_corpus::false_positive_guards` for the regression proof.
//!
//! # Match-both, never replace
//!
//! `RuleSet::haystacks` (`rules.rs`) builds `hay_canonical` from
//! `canonicalize(&pre)` for `Bash` tool calls, and `RuleSet::matches` denies
//! if **either** `hay_raw` or `hay_canonical` matches a rule — `hay_raw` is
//! always checked unmodified. Canonicalization is therefore strictly
//! additive: a bug here can only fail to add new coverage, never remove
//! existing coverage.
//!
//! # Fail-safe
//!
//! - **Size cap** ([`MAX_LEN`]): oversized input is returned unmodified —
//!   `hay_canonical` degenerates to a copy of `hay_raw`, so match-both still
//!   checks the raw string, just with no additional canonical-only coverage.
//! - **Wrapper-strip iteration cap** ([`WRAPPER_ITER_CAP`]): bounded so
//!   adversarial/malformed input cannot loop.
//! - **Per-transform independence**: every transform below is a no-op on
//!   ambiguous or unrecognized input rather than guessing — it leaves its
//!   input untouched and lets the rest of the pipeline continue.
//! - **No panics**: every transform operates on owned `String`/`Vec<String>`
//!   with plain character-level scanning, no indexing that can go
//!   out-of-bounds unchecked.
//! - **Idempotency**: `canonicalize(canonicalize(x)) == canonicalize(x)` is
//!   asserted in tests below — nothing here currently needs to call it twice,
//!   but nothing should behave differently if it does.
//!
//! See `docs/superpowers/specs/2026-07-17-command-gate-wrapper-normalization-design.md`
//! for the full design.

/// Input length cap (bytes). Oversized input skips canonicalization entirely
/// (fail-safe — `hay_raw` is still matched unmodified by `matches()`).
const MAX_LEN: usize = 8192;

/// Bound on how many wrapper "layers" (`sudo`, `env FOO=bar`, `command -p`,
/// `\cmd`, a bare `FOO=bar` assignment, stacked) `strip_wrapper_prefixes`
/// will peel off a single segment.
/// Hitting the cap simply stops stripping — whatever has been removed so far
/// is kept, the remainder is treated as the command-name token as-is.
const WRAPPER_ITER_CAP: usize = 8;

/// CPython flags that may sit between a folded interpreter name and a literal
/// `-c` token without blocking the benign-preflag collapse (transform 6.4).
/// Any token in this gap that is NOT in this list aborts the collapse for
/// that command (fail-safe — leaves the shape uncaught rather than risk
/// misclassifying an unfamiliar flag).
const PY_BENIGN_PREFLAGS: &[&str] = &[
    "-u", "-O", "-OO", "-B", "-E", "-S", "-I", "-b", "-bb", "-d", "-v", "-q", "-x",
];

/// Canonicalizes `pre` (`rules::command_pre`'s output — invisible-stripped,
/// line-continuation-folded; real quotes and real newlines still intact, NOT
/// yet data-region-masked or whitespace-collapsed — see this module's
/// "Calling convention" doc above for why that ordering is load-bearing) by
/// applying transforms 4-6 plus `$IFS` folding, position-scoped per the
/// module doc above. Returns `pre` unmodified if it exceeds [`MAX_LEN`].
pub(crate) fn canonicalize(pre: &str) -> String {
    if pre.len() > MAX_LEN {
        return pre.to_string();
    }
    let mut out = String::with_capacity(pre.len());
    for piece in split_top_level_segments(pre) {
        match piece {
            Piece::Segment(s) => out.push_str(&canonicalize_segment(s)),
            Piece::Delim(s) => out.push_str(s),
        }
    }
    out
}

/// One piece of a chaining-delimited command string: either a processable
/// segment (candidate for the transform pipeline) or a raw chaining
/// delimiter (`&&`, `||`, `;`, `|`, or a real top-level newline) copied
/// through unmodified.
///
/// `pub(crate)` so `engine::extract`'s position-scoping can walk the exact
/// same segment/delimiter sequence this module uses for its own transforms
/// (including telling a `|` delimiter apart from `;`/`&&`/newline, which the
/// heredoc pipe-target check needs) — see [`split_top_level_segments`]'s doc.
pub(crate) enum Piece<'a> {
    Segment(&'a str),
    Delim(&'a str),
}

/// Splits `s` into [`Piece`]s at top-level (outside any quoted span)
/// occurrences of `&&`, `||`, `;`, `|`, or a real newline — the same chaining
/// vocabulary `allowlist::has_shell_chaining` checks for (a newline is a
/// real top-level shell command separator, exactly like `;`). Quote-aware
/// (best-effort: an unbalanced quote simply means the rest of the string is
/// treated as one segment — fail-safe, never a panic, never wrong-direction
/// under-matching of raw text since `hay_raw` is always checked independently
/// regardless of how this splits).
///
/// Also escape-aware, outside single quotes: a `;`/`&`/`|` immediately
/// preceded by an odd number of consecutive unescaped `\` (see
/// [`is_backslash_escaped`]) is a literal character to the shell — `\;`,
/// `\|`, `\&` — never a real command separator, so it must not be read as
/// one. This applies in unquoted and double-quoted context (backslash
/// escaping is real there); inside a single-quoted span the loop below never
/// reaches this check at all, since the whole span is already skipped by the
/// quote-tracking branch above, matching single-quote semantics where `\` is
/// itself just a literal character. Escaping can only ever *suppress* a
/// split on what would otherwise look like a separator — a genuine top-level
/// separator is never backslash-escaped — so this can only add coverage
/// (skip a fake split), never remove a real one.
///
/// `s` is not necessarily whitespace-collapsed when this runs (see this
/// module's "Calling convention" doc), so a real, unquoted newline reaching
/// here must be recognized as its own delimiter rather than silently folded
/// into a segment — a segment spanning an unquoted newline would misattribute
/// the *second* physical command's first token to the position-scoping this
/// module depends on (see the module doc, "Position-scoping"). Runs of
/// ordinary whitespace *within* a segment need no special handling here:
/// [`canonicalize_segment`]'s `split_whitespace()` tokenizer already treats
/// any whitespace run (single space, multiple spaces, tabs) as one ordinary
/// token separator.
///
/// `pub(crate)`: `engine::extract` reuses this directly so its own notion of
/// "which segment does this byte position fall in" (needed to position-scope
/// inline-interpreter/heredoc extraction to a segment's actual command word,
/// never an embedded argument) never diverges from what `canonicalize()`
/// itself would compute for the same text.
pub(crate) fn split_top_level_segments(s: &str) -> Vec<Piece<'_>> {
    let chars: Vec<(usize, char)> = s.char_indices().collect();
    let just_chars: Vec<char> = chars.iter().map(|&(_, c)| c).collect();
    let mut pieces = Vec::new();
    let mut seg_start = 0usize;
    let mut quote: Option<char> = None;
    let mut idx = 0usize;

    while idx < chars.len() {
        let (byte_i, c) = chars[idx];

        if quote.is_none() && (c == '\'' || c == '"') {
            quote = Some(c);
            idx += 1;
            continue;
        }
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            idx += 1;
            continue;
        }

        let delim_chars: usize = if (c == '&' && next_char(&chars, idx) == Some('&'))
            || (c == '|' && next_char(&chars, idx) == Some('|'))
        {
            2
        } else if c == ';' || c == '|' || c == '\n' {
            1
        } else {
            0
        };

        if delim_chars > 0 && is_backslash_escaped(&just_chars, idx) {
            // A literal (escaped) separator — not a real delimiter. Leave it
            // as ordinary segment text and keep scanning.
            idx += 1;
            continue;
        }

        if delim_chars > 0 {
            let delim_start = byte_i;
            let delim_end = if delim_chars == 2 {
                let (b, ch) = chars[idx + 1];
                b + ch.len_utf8()
            } else {
                byte_i + c.len_utf8()
            };
            pieces.push(Piece::Segment(&s[seg_start..delim_start]));
            pieces.push(Piece::Delim(&s[delim_start..delim_end]));
            seg_start = delim_end;
            idx += delim_chars;
            continue;
        }

        idx += 1;
    }

    pieces.push(Piece::Segment(&s[seg_start..]));
    pieces
}

fn next_char(chars: &[(usize, char)], idx: usize) -> Option<char> {
    chars.get(idx + 1).map(|&(_, c)| c)
}

/// True if `chars[i]` is backslash-escaped: preceded by an odd number of
/// consecutive `\` characters. Mirrors `data_region::is_escaped` (same
/// odd-count-of-preceding-backslashes rule — two consecutive `\` are an
/// escaped `\` itself, even count, not escaped; three are an escaped `\`
/// plus an escaped delimiter, odd count, escaped; and so on). Kept as a
/// separate local copy rather than sharing code across modules: the two
/// callers scan different character slices (this one a plain `Vec<char>`
/// built from `split_top_level_segments`'s own `char_indices` pass, that one
/// `data_region`'s own scanner state) and the rule is small enough that a
/// shared abstraction would cost more than it saves.
fn is_backslash_escaped(chars: &[char], i: usize) -> bool {
    chars[..i].iter().rev().take_while(|&&c| c == '\\').count() % 2 == 1
}

/// Runs the full transform pipeline over one chaining-delimited segment,
/// preserving its exact leading/trailing whitespace. A whitespace-only or
/// empty segment (adjacent delimiters, or the empty span before/after a
/// leading/trailing delimiter) is returned unmodified.
fn canonicalize_segment(seg: &str) -> String {
    let leading_len = seg.len() - seg.trim_start().len();
    let trailing_len = seg.len() - seg.trim_end().len();
    if leading_len + trailing_len >= seg.len() {
        return seg.to_string(); // all-whitespace or empty segment
    }
    let leading = &seg[..leading_len];
    let trailing = &seg[seg.len() - trailing_len..];
    let core = &seg[leading_len..seg.len() - trailing_len];

    let mut tokens: Vec<String> = core.split_whitespace().map(String::from).collect();
    if let Some(cmd_i) = strip_wrapper_prefixes(&mut tokens) {
        unwrap_quoted_tokens(&mut tokens, cmd_i);
        normalize_flag_forms(&mut tokens, cmd_i);
    }

    format!("{leading}{}{trailing}", tokens.join(" "))
}

/// Transform 4 (+ `$IFS` folding, position-scoped to exactly the tokens this
/// function itself inspects): peels off recognized wrapper layers (`sudo
/// [flags]`, `env [ASSIGN|-flag]...`, `command [-p]`, a leading `\` escape, a
/// bare `VAR=val` temporary-environment-assignment token with no `env`
/// keyword) from the front of `tokens`, in a loop bounded by
/// [`WRAPPER_ITER_CAP`].
/// Before checking each candidate token against the wrapper table, folds any
/// `$IFS`/`${IFS}` occurrence within *that specific token* into real
/// whitespace (splicing the result back into `tokens` in place) — this is
/// exactly the token a real shell would treat as one word after `$IFS`
/// expansion, so folding it is position-scoped by construction: a token past
/// where this loop stops (e.g. an `echo` argument) is never inspected, so
/// never folded.
///
/// Returns the index of the resolved command-name token (`Some`), or `None`
/// only if `tokens` is empty (nothing to canonicalize in this segment).
///
/// `pub(crate)`: `engine::extract` calls this directly (via its own
/// `segment_command_word` helper) to resolve a segment's real command word
/// for position-scoping — the same `sudo`/`env`/`command`/`\`-wrapper
/// stripping and `$IFS` folding this module's own transforms rely on, so
/// extraction's notion of "what command is this segment actually running"
/// never diverges from canonicalize's.
pub(crate) fn strip_wrapper_prefixes(tokens: &mut Vec<String>) -> Option<usize> {
    if tokens.is_empty() {
        return None;
    }
    let mut i = 0usize;
    let mut iters = 0usize;
    loop {
        if i >= tokens.len() || iters >= WRAPPER_ITER_CAP {
            break;
        }
        iters += 1;
        fold_ifs_token_in_place(tokens, i);
        if i >= tokens.len() {
            break;
        }
        match wrapper_layer_len(tokens, i) {
            Some(n) => i += n,
            None => break,
        }
    }
    if i < tokens.len() {
        Some(i)
    } else {
        // Wrapper-stripping consumed every token (e.g. a bare "sudo" with
        // nothing after it) — fail-safe: treat the last token as the
        // command-name slot rather than panicking on out-of-bounds.
        tokens.len().checked_sub(1)
    }
}

/// How many tokens starting at `tokens[i]` one wrapper layer consumes, or
/// `None` if `tokens[i]` does not match any recognized wrapper form. A
/// leading backslash-escape (`\rm`) is rewritten in place (the backslash
/// dropped) and reported as consuming zero tokens — the next loop iteration
/// re-examines the same (now-rewritten) position, terminates naturally since
/// it no longer matches, and is still bounded by the caller's iteration cap
/// regardless.
fn wrapper_layer_len(tokens: &mut [String], i: usize) -> Option<usize> {
    let lower = tokens[i].to_ascii_lowercase();
    match lower.as_str() {
        "sudo" => {
            let mut n = 1;
            while i + n < tokens.len() && is_flag_shaped(&tokens[i + n]) {
                n += 1;
            }
            Some(n)
        }
        "command" => {
            let mut n = 1;
            if i + n < tokens.len() && tokens[i + n] == "-p" {
                n += 1;
            }
            Some(n)
        }
        "env" => {
            let mut n = 1;
            loop {
                if i + n >= tokens.len() {
                    break;
                }
                let tok = tokens[i + n].as_str();
                if is_env_assignment(tok) {
                    n += 1;
                } else if tok.starts_with('-') {
                    n += 1;
                    // Best-effort: a handful of env flags take a value
                    // (`-u NAME`, `-C dir`, `-S string`). If the following
                    // token doesn't itself look like another flag or
                    // assignment, treat it as that value and consume it too.
                    if matches!(tok, "-u" | "-C" | "-S")
                        && i + n < tokens.len()
                        && !tokens[i + n].starts_with('-')
                        && !is_env_assignment(&tokens[i + n])
                    {
                        n += 1;
                    }
                } else {
                    break;
                }
            }
            Some(n)
        }
        _ => {
            if let Some(rest) = tokens[i].strip_prefix('\\') {
                if rest
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphabetic() || c == '_')
                {
                    tokens[i] = rest.to_string();
                    return Some(0);
                }
            }
            // A bare `VAR=val` token (no `env` keyword) at command-word
            // position is the shell's own "temporary environment
            // assignment" prefix syntax — `FOO=bar rm -r -f /` really runs
            // `rm`, exactly like `env FOO=bar rm -r -f /` already does. The
            // outer loop calls this once per candidate position, so several
            // stacked bare assignments (`FOO=1 BAR=2 rm ...`) are peeled one
            // at a time, same as the `env` case's own repeatable pattern.
            // Position-scoped for free: this function only ever runs on
            // `tokens[i]` for `i` the outer loop has advanced to, which
            // starts at 0 and only ever reaches tokens the earlier wrapper
            // layers consumed — a `VAR=val` sitting later, inside a data
            // argument (e.g. `echo FOO=bar`), is never inspected because the
            // loop already stopped at the real (non-wrapper) command word
            // before reaching it.
            if is_env_assignment(&tokens[i]) {
                return Some(1);
            }
            None
        }
    }
}

fn is_flag_shaped(s: &str) -> bool {
    s.starts_with('-') && s.len() > 1
}

/// `NAME=value` shape: an identifier (`[A-Za-z_][A-Za-z0-9_]*`) followed by
/// `=`. Used to recognize inline env-var assignments both after the `env`
/// keyword (`env FOO=bar cmd`) and bare, with no keyword at all — the
/// shell's own temporary-environment-assignment prefix syntax
/// (`FOO=bar cmd`, see the `wrapper_layer_len` fallback arm above).
fn is_env_assignment(s: &str) -> bool {
    let Some(eq) = s.find('=') else {
        return false;
    };
    if eq == 0 {
        return false;
    }
    let name = &s[..eq];
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_alphabetic() || first == '_') && chars.all(|c| c.is_alphanumeric() || c == '_')
}

/// Folds `${IFS}` and bare `$IFS` (not immediately followed by an identifier
/// character, so `$IFSX` — a different variable — is left alone) into literal
/// spaces within `tokens[i]`, splicing the result back into `tokens` (which
/// may turn one token into several, since `$IFS` provides no real whitespace
/// until a real shell expands it at runtime).
///
/// Deliberately **not** folded globally over the whole haystack, and
/// deliberately **not** part of `rules::norm_cmd` (unlike line-continuation
/// folding): `$IFS` can appear inside a data-consuming argument's disqualified
/// (unmasked) content (see `data_region`'s bare-`$`-disqualifies rule) without
/// that argument becoming any less "merely echoed, never executed" — folding
/// it there would fabricate a false substring match out of separately-typed
/// data. Scoping this to only the tokens `strip_wrapper_prefixes` itself
/// inspects (the wrapper/command-name candidate slots) keeps it inert against
/// that class of false positive by construction, the same way transforms 4-6
/// are scoped.
fn fold_ifs_token_in_place(tokens: &mut Vec<String>, i: usize) {
    let folded = fold_ifs(&tokens[i]);
    if folded == tokens[i] {
        return;
    }
    let parts: Vec<String> = folded.split_whitespace().map(String::from).collect();
    if parts.is_empty() {
        tokens.remove(i);
        return;
    }
    tokens.splice(i..=i, parts);
}

fn fold_ifs(s: &str) -> String {
    let braced = s.replace("${IFS}", " ");
    let chars: Vec<char> = braced.chars().collect();
    let mut out = String::with_capacity(braced.len());
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '$'
            && chars.get(i + 1) == Some(&'I')
            && chars.get(i + 2) == Some(&'F')
            && chars.get(i + 3) == Some(&'S')
            && !matches!(chars.get(i + 4), Some(c) if c.is_alphanumeric() || *c == '_')
        {
            out.push(' ');
            i += 4;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Transform 5, command-name form only: strips `'`/`"` characters acting as
/// concatenation glue from `tokens[cmd_i]` — the position-scoped command-name
/// slot resolved by `strip_wrapper_prefixes`. Never applied anywhere else
/// (see module doc, "Position-scoping"). No-ops (fail-safe) if stripping
/// quotes would leave the token empty (a degenerate/ambiguous shape).
fn unwrap_quoted_tokens(tokens: &mut [String], cmd_i: usize) {
    let tok = &tokens[cmd_i];
    if !tok.contains('\'') && !tok.contains('"') {
        return;
    }
    let stripped: String = tok.chars().filter(|&c| c != '\'' && c != '"').collect();
    if stripped.is_empty() {
        return;
    }
    tokens[cmd_i] = stripped;
}

/// Transform 5, target-argument form: strips one layer of whole-token quote
/// wrapping (`"/"` -> `/`, `'~'` -> `~`, `"$HOME"` -> `$HOME`) from `tok`.
/// Only ever called on the single token immediately following a recognized
/// destructive command's flag cluster (currently: `rm`'s, from
/// `normalize_rm_flags`) — never scanned for elsewhere. Bounded to a handful
/// of unwrap layers as a defensive measure against pathological input; a
/// single layer covers every named target case.
fn unwrap_target_token_quotes(tok: &mut String) {
    for _ in 0..4 {
        let mut chars = tok.chars();
        let Some(first) = chars.next() else { break };
        let Some(last) = tok.chars().last() else {
            break;
        };
        if (first == '\'' || first == '"') && first == last && tok.chars().count() >= 2 {
            let inner: String = tok
                .chars()
                .skip(1)
                .take(tok.chars().count() - 2)
                .collect();
            if inner.is_empty() {
                break; // degenerate ("" / '') — no-op, fail-safe
            }
            *tok = inner;
            continue;
        }
        break;
    }
}

/// Transform 6: normalizes the command-name token (`tokens[cmd_i]`) and its
/// immediately-following option/argument tokens. Interpreter-version folding
/// applies to any recognized command name unconditionally (transform 6.3);
/// the rest is dispatched by the (already version-folded) command name — v1
/// scope is `rm` (6.1 long->short + 6.2 cluster merge, plus 5's
/// target-argument form) and `python` (6.4 benign-preflag collapse). Every
/// other command name is left untouched.
fn normalize_flag_forms(tokens: &mut Vec<String>, cmd_i: usize) {
    fold_interpreter_version(&mut tokens[cmd_i]);
    match tokens[cmd_i].to_ascii_lowercase().as_str() {
        "rm" => normalize_rm_flags(tokens, cmd_i),
        "python" => normalize_python_flags(tokens, cmd_i),
        _ => {}
    }
}

/// Transform 6.3: `python[0-9]+(\.[0-9]+)*` (any digit/dot-suffixed form,
/// including already-tolerated bare `python3`) -> `python`. Exact whole-token
/// match only (never a prefix match, so `python-config` is untouched).
fn fold_interpreter_version(tok: &mut String) {
    let lower = tok.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("python") else {
        return;
    };
    if rest.is_empty() {
        return; // already bare "python" (mod case) — nothing to fold
    }
    if rest.chars().all(|c| c.is_ascii_digit() || c == '.') && rest.chars().any(|c| c.is_ascii_digit()) {
        *tok = "python".to_string();
    }
}

/// Transforms 6.1 + 6.2 + 5(target-form), scoped to `rm` at `tokens[cmd_i]`:
/// maps recognized GNU long options to their short form, merges the
/// resulting contiguous run of single-dash single-letter flag tokens into one
/// clustered token (encountered order preserved — no canonical letter order
/// is imposed, matching the catalog pattern's own `-rf`/`-fr` alternation),
/// then unwraps one layer of whole-token quoting on the target token
/// immediately following the flag region, if any.
fn normalize_rm_flags(tokens: &mut Vec<String>, cmd_i: usize) {
    let mut j = cmd_i + 1;
    loop {
        if j >= tokens.len() {
            break;
        }
        if tokens[j] == "--recursive" {
            tokens[j] = "-r".to_string();
            j += 1;
            continue;
        }
        if tokens[j] == "--force" {
            tokens[j] = "-f".to_string();
            j += 1;
            continue;
        }
        if is_short_flag_cluster(&tokens[j]) {
            j += 1;
            continue;
        }
        break;
    }
    merge_flag_run(tokens, cmd_i + 1, j);

    // Target position: the first token after the (possibly just-merged) flag
    // region that is not itself flag-shaped.
    let mut t = cmd_i + 1;
    while t < tokens.len() && tokens[t].starts_with('-') {
        t += 1;
    }
    if t < tokens.len() {
        unwrap_target_token_quotes(&mut tokens[t]);
    }
}

/// True for a single-dash, letters-only flag token (`-r`, `-f`, `-rf`) —
/// never `--long-form` (a second leading `-` fails the `!rest.starts_with('-')`
/// check) and never a flag with a non-letter (a value-bearing short flag).
fn is_short_flag_cluster(s: &str) -> bool {
    match s.strip_prefix('-') {
        Some(rest) => !rest.is_empty() && !rest.starts_with('-') && rest.chars().all(|c| c.is_ascii_alphabetic()),
        None => false,
    }
}

/// Merges `tokens[start..end]` (assumed all short-flag-cluster-shaped, per
/// the caller's scan) into a single `-`-prefixed token, letters concatenated
/// in encountered order. A no-op when there are fewer than two tokens to
/// merge (nothing to gain — including when the range is already a single,
/// possibly-already-clustered token like `-rf`).
fn merge_flag_run(tokens: &mut Vec<String>, start: usize, end: usize) {
    if end <= start + 1 {
        return;
    }
    let mut merged = String::from("-");
    for t in &tokens[start..end] {
        if let Some(rest) = t.strip_prefix('-') {
            merged.push_str(rest);
        }
    }
    tokens.splice(start..end, std::iter::once(merged));
}

/// Transform 6.4: drops any run of benign CPython preflags
/// ([`PY_BENIGN_PREFLAGS`]) sitting between `python` (at `tokens[cmd_i]`) and
/// a literal `-c` token. No-ops (leaves everything untouched) the instant a
/// token in that gap is not in the allowlist, or no `-c` is found at all —
/// fail-safe, per the module doc.
fn normalize_python_flags(tokens: &mut Vec<String>, cmd_i: usize) {
    let mut j = cmd_i + 1;
    let mut dash_c = None;
    while j < tokens.len() {
        if tokens[j] == "-c" {
            dash_c = Some(j);
            break;
        }
        if !PY_BENIGN_PREFLAGS.contains(&tokens[j].as_str()) {
            break;
        }
        j += 1;
    }
    if let Some(c_pos) = dash_c {
        if c_pos > cmd_i + 1 {
            tokens.splice(cmd_i + 1..c_pos, std::iter::empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::canonicalize;

    #[test]
    fn multi_arg_short_flags_merge_rf_order() {
        assert_eq!(canonicalize("rm -r -f /"), "rm -rf /");
    }

    #[test]
    fn multi_arg_short_flags_merge_fr_order_preserves_encounter_order() {
        assert_eq!(canonicalize("rm -f -r /"), "rm -fr /");
    }

    #[test]
    fn gnu_long_options_fold_to_short_cluster() {
        assert_eq!(canonicalize("rm --recursive --force /"), "rm -rf /");
    }

    #[test]
    fn no_preserve_root_long_flag_is_left_alone() {
        // Not part of the rm long->short table — a different catalog pattern
        // already matches this literal substring; canonicalize must not
        // touch it (position-scoping no-ops on unrecognized long flags).
        let out = canonicalize("rm -rf --no-preserve-root /");
        assert!(out.contains("--no-preserve-root"));
    }

    #[test]
    fn versioned_python_dotted_folds_to_bare() {
        assert_eq!(
            canonicalize("python3.11 -c \"exec(x)\""),
            "python -c \"exec(x)\""
        );
    }

    #[test]
    fn versioned_python_bare_digit_also_folds() {
        // Already-tolerated by the catalog pattern (python\d?), but folding
        // it too is harmless and keeps the rule simple (per design).
        assert_eq!(canonicalize("python3 -c \"exec(x)\""), "python -c \"exec(x)\"");
    }

    #[test]
    fn extra_flag_before_dash_c_is_collapsed() {
        assert_eq!(
            canonicalize("python -u -c \"exec(x)\""),
            "python -c \"exec(x)\""
        );
    }

    #[test]
    fn multiple_benign_preflags_all_collapse() {
        assert_eq!(
            canonicalize("python -u -O -c \"exec(x)\""),
            "python -c \"exec(x)\""
        );
    }

    #[test]
    fn unrecognized_preflag_aborts_the_collapse() {
        // Fail-safe: an unfamiliar flag in the gap must not be silently
        // dropped — canonicalize no-ops rather than guess.
        let out = canonicalize("python --not-a-real-flag -c \"exec(x)\"");
        assert!(out.contains("--not-a-real-flag"));
    }

    #[test]
    fn intra_token_quote_splice_on_command_name_unwraps() {
        assert_eq!(canonicalize("'r'm -rf /"), "rm -rf /");
    }

    #[test]
    fn quoted_target_root_unwraps() {
        assert_eq!(canonicalize("rm -rf \"/\""), "rm -rf /");
    }

    #[test]
    fn quoted_target_dollar_home_unwraps() {
        assert_eq!(canonicalize("rm -rf \"$HOME\""), "rm -rf $HOME");
    }

    #[test]
    fn single_quoted_target_tilde_unwraps() {
        assert_eq!(canonicalize("rm -rf '~'"), "rm -rf ~");
    }

    #[test]
    fn wrapper_sudo_strip_lets_interpreter_fold_apply() {
        // Wrapper-stripping fixes zero corpus cases directly (the unanchored
        // matcher already sees through `sudo` on the raw string) — its job is
        // making sure interpreter-version-fold operates on the true
        // first-token command name, not on "sudo" itself.
        assert_eq!(
            canonicalize("sudo python3.11 -c \"exec(x)\""),
            "sudo python -c \"exec(x)\""
        );
    }

    #[test]
    fn wrapper_sudo_with_value_flag_partial_strip_is_a_documented_non_issue() {
        // `sudo -u root` — `-u` is flag-shaped, consumed, but `root` is not
        // (no dash), so the strip loop stops there per the design's own
        // wrapper table: "stops at the first non-flag token (a value like
        // `root` in `sudo -u root`...)". `root` becomes the (unrecognized)
        // command-name candidate, so no further transform fires — a partial
        // strip, not a correctness problem, since `rm -r -f /` is untouched
        // either way and the raw string is always checked too.
        assert_eq!(
            canonicalize("sudo -u root rm -r -f /"),
            "sudo -u root rm -r -f /"
        );
    }

    #[test]
    fn wrapper_sudo_with_no_value_flags_reaches_rm_multi_arg() {
        assert_eq!(canonicalize("sudo -n rm -r -f /"), "sudo -n rm -rf /");
    }

    #[test]
    fn wrapper_env_assignment_then_rm_multi_arg() {
        assert_eq!(
            canonicalize("env FOO=bar rm -r -f /"),
            "env FOO=bar rm -rf /"
        );
    }

    #[test]
    fn bare_env_assignment_prefix_then_rm_multi_arg() {
        // Task 2 fix 3: a bare `VAR=val` prefix — the shell's own temporary-
        // environment-assignment syntax, no `env` keyword needed — must be
        // stripped exactly like the `env FOO=bar` form above, so the real
        // command word (`rm`) is reached and its separated `-r -f` flags
        // still fold to `-rf`.
        assert_eq!(canonicalize("FOO=bar rm -r -f /"), "FOO=bar rm -rf /");
    }

    #[test]
    fn stacked_bare_env_assignments_then_rm_multi_arg() {
        assert_eq!(
            canonicalize("FOO=1 BAR=2 rm -r -f /"),
            "FOO=1 BAR=2 rm -rf /"
        );
    }

    #[test]
    fn bare_env_assignment_prefix_lets_interpreter_fold_apply() {
        assert_eq!(
            canonicalize("FOO=bar python3.11 -c \"exec(x)\""),
            "FOO=bar python -c \"exec(x)\""
        );
    }

    #[test]
    fn var_equals_not_at_command_word_position_is_left_alone() {
        // Position-scoping guard: a `VAR=val`-shaped token that is NOT at
        // command-word position (here, `echo`'s own data argument) must
        // never be stripped or otherwise touched — `strip_wrapper_prefixes`
        // only ever inspects tokens starting from index 0 and stops at the
        // first non-wrapper token, so it never reaches this one.
        assert_eq!(canonicalize("echo FOO=bar"), "echo FOO=bar");
    }

    #[test]
    fn wrapper_backslash_escape_then_interpreter_fold() {
        assert_eq!(
            canonicalize("\\python3.11 -c \"exec(x)\""),
            "python -c \"exec(x)\""
        );
    }

    #[test]
    fn ifs_folding_splits_a_single_glued_token_into_flags_and_target() {
        assert_eq!(canonicalize("rm${IFS}-rf${IFS}/"), "rm -rf /");
    }

    #[test]
    fn ifs_folding_does_not_conflate_a_different_variable() {
        // `$IFSX` names a different variable — must not be misread as `$IFS`
        // followed by literal `X`.
        let out = canonicalize("echo $IFSX");
        assert_eq!(out, "echo $IFSX");
    }

    #[test]
    fn chained_segment_after_semicolon_is_independently_canonicalized() {
        assert_eq!(canonicalize("true ; rm -r -f /"), "true ; rm -rf /");
    }

    #[test]
    fn chained_segment_after_double_ampersand_is_independently_canonicalized() {
        assert_eq!(
            canonicalize("git checkout main && rm -r -f /"),
            "git checkout main && rm -rf /"
        );
    }

    #[test]
    fn idempotent_on_multi_arg_short_flags() {
        let once = canonicalize("rm -r -f /");
        assert_eq!(canonicalize(&once), once);
    }

    #[test]
    fn idempotent_on_gnu_long_options() {
        let once = canonicalize("rm --recursive --force /");
        assert_eq!(canonicalize(&once), once);
    }

    #[test]
    fn idempotent_on_versioned_python_with_preflag() {
        let once = canonicalize("python3.11 -u -c \"exec(x)\"");
        assert_eq!(canonicalize(&once), once);
    }

    #[test]
    fn idempotent_on_quoted_target() {
        let once = canonicalize("rm -rf \"/\"");
        assert_eq!(canonicalize(&once), once);
    }

    #[test]
    fn idempotent_on_ifs_folded_command() {
        let once = canonicalize("rm${IFS}-rf${IFS}/");
        assert_eq!(canonicalize(&once), once);
    }

    #[test]
    fn idempotent_on_wrapper_stripped_input() {
        let once = canonicalize("sudo python3.11 -c \"exec(x)\"");
        assert_eq!(canonicalize(&once), once);
    }

    // ---- false-positive guard: position-scoping must hold -----------------

    #[test]
    fn quote_spliced_text_inside_echo_argument_is_left_untouched() {
        // The worked example from the design doc: a human-authored warning
        // string using intra-token-quote-splice style to *illustrate* a bad
        // command, inside `echo` data. `echo` is not a recognized wrapper and
        // not in the flag-normalization table, so position-scoping means
        // nothing past it is ever inspected — the split token must survive
        // byte-for-byte.
        let input = "echo \"never run 'r'm -rf / on prod\"";
        let out = canonicalize(input);
        assert_eq!(out, input, "position-scoping must leave data untouched");
        assert!(out.contains("'r'm"), "the split token must survive: {out:?}");
        assert!(
            !out.contains("run rm -rf"),
            "must not fabricate a contiguous rm-rf match out of data: {out:?}"
        );
    }

    #[test]
    fn ifs_inside_echo_argument_is_not_folded() {
        // Position-scoping applies to the $IFS fold too: `echo` occupies the
        // first-token slot, so a `$IFS` sitting in its *argument* (a later
        // token) must never be folded — only tokens strip_wrapper_prefixes
        // itself inspects (bounded by where the wrapper/command-name search
        // stops) are eligible.
        let input = "echo hi${IFS}there";
        assert_eq!(canonicalize(input), input);
    }

    // ---- Task-3 FP fix: quote-intact calling convention -------------------

    #[test]
    fn quoted_semicolon_inside_data_arg_is_not_a_segment_delimiter() {
        // The core invariant the Task-3 fix depends on: `canonicalize()` is
        // now called on the quote-intact `pre` stage (real quote characters
        // still present, before data-region masking would strip the
        // enclosing quotes to spaces). A `;` protected by a real enclosing
        // quote must never be read as a top-level segment delimiter — if it
        // were, the splitter would carve out a fake new segment starting
        // with `rm`, and the flag-cluster-merge transform would fabricate
        // `rm -rf /` out of text that is only ever echoed, never executed.
        // With the quote intact, the whole double-quoted argument stays one
        // segment (first token `echo`, not `rm`), so nothing inside it is
        // ever touched — byte-for-byte round-trip.
        let input = "echo \"$USER; rm -r -f /\"";
        assert_eq!(
            canonicalize(input),
            input,
            "a quote-protected `;` inside a data argument must not split a fake segment"
        );
    }

    #[test]
    fn quoted_semicolon_in_git_commit_message_is_not_a_segment_delimiter() {
        // Sibling of the above with a nested single-quote splice inside the
        // double-quoted message (`'r'm`) — must also survive byte-for-byte:
        // `git`, not `rm`, occupies the segment's first-token slot, so the
        // command-name-form quote-unwrap transform never even considers it.
        let input = "git commit -m \"fix: $USER reported a bug; 'r'm -rf / was suggested\"";
        assert_eq!(canonicalize(input), input);
    }

    #[test]
    fn top_level_newline_splits_into_independently_canonicalized_segments() {
        // `canonicalize()` now receives `pre` — not yet whitespace-collapsed
        // — so a real, unquoted newline must be recognized as its own
        // top-level segment delimiter (the same way `;` already is), or the
        // second physical command's first token would be misattributed away
        // from position-scoping. Sibling of the existing `;`/`&&`
        // chained-segment tests, with a real newline instead.
        assert_eq!(canonicalize("true\nrm -r -f /"), "true\nrm -rf /");
    }

    // ---- Task fix: backslash-escaped separators are not segment boundaries -

    #[test]
    fn backslash_escaped_semicolon_is_not_a_segment_delimiter() {
        // `\;` is a literal semicolon character to the shell, not a command
        // separator — the segment splitter must not carve a fake new
        // segment there. Without this, the splitter would put `rm` at a
        // (fabricated) segment's first-token position, and the multi-arg
        // flag-cluster merge would then rewrite `-r -f` into `-rf`,
        // producing a `destructive.rm_rf` match out of a single, harmless
        // `echo` invocation. `echo`, not a recognized wrapper or
        // flag-normalization target, is left completely untouched, so this
        // must round-trip byte-for-byte.
        let input = "echo foo\\; rm -r -f /";
        assert_eq!(
            canonicalize(input),
            input,
            "a backslash-escaped `;` must not split a fake segment: {input:?}"
        );
    }

    #[test]
    fn backslash_escaped_pipe_is_not_a_segment_delimiter() {
        // Sibling of the above with `\|` instead of `\;` — same mechanism,
        // different literal separator character.
        let input = "echo hi\\|rm -r -f /";
        assert_eq!(
            canonicalize(input),
            input,
            "a backslash-escaped `|` must not split a fake segment: {input:?}"
        );
    }

    #[test]
    fn unescaped_semicolon_still_splits_after_an_escaped_one() {
        // An escaped separator must only suppress a split on itself — a
        // later REAL, unescaped separator in the same string must still
        // split normally (this is what keeps the fix from ever weakening a
        // true positive).
        assert_eq!(
            canonicalize("echo foo\\; true ; rm -r -f /"),
            "echo foo\\; true ; rm -rf /"
        );
    }

    #[test]
    fn quoted_newline_is_not_a_segment_delimiter() {
        // Quote-awareness applies to the newline delimiter too: a real
        // newline inside a quoted data argument (e.g. a multi-line echo/git
        // commit message) must not be read as a top-level command separator
        // — `rm` never lands at any segment's first-token position, so its
        // flag cluster is never merged. (canonicalize_segment's tokenizer
        // still normalizes the newline to a single space during
        // reconstruction, the same way it already collapses any run of
        // whitespace between tokens — harmless, since both haystacks go
        // through their own whitespace-collapse regardless; what must hold
        // is that this stays ONE segment, not two.)
        let input = "echo \"line one\nrm -r -f /\"";
        let out = canonicalize(input);
        assert!(
            !out.contains("-rf"),
            "a quoted newline must not let the multi-arg flag-cluster merge fire: {out:?}"
        );
        assert!(out.starts_with("echo"), "must remain one segment: {out:?}");
    }

    #[test]
    fn unrelated_long_flag_is_never_conflated_with_force() {
        // `--force-with-lease` must never be rewritten as if it were `--force`
        // (exact whole-token equality only, never a prefix match) — and `git`
        // is not in the v1 command-normalization table at all, so this is
        // untouched either way.
        let out = canonicalize("git push --force-with-lease origin main");
        assert!(out.contains("--force-with-lease"));
    }

    #[test]
    fn safe_command_round_trips_unchanged() {
        assert_eq!(canonicalize("ls -la"), "ls -la");
        assert_eq!(canonicalize("cargo build --release"), "cargo build --release");
    }

    #[test]
    fn oversize_input_is_returned_unmodified() {
        let cmd = "echo ".to_string() + &"a".repeat(20_000);
        assert_eq!(canonicalize(&cmd), cmd);
    }
}
