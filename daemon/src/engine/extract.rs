//! Inline-script/heredoc body extraction for Belay's command gate.
//!
//! `extract_bodies` locates the *code* hidden one token-depth deeper than the
//! outer command shape — inside `bash -c "…"` / `sh -c '…'` / `python -c "…"`
//! / `node -e "…"` / `eval "…"` quoted arguments, and inside heredoc bodies
//! destined for one of those interpreters (`cat <<EOF | bash`,
//! `bash <<EOF`) — and returns each as its own [`ExtractedBody`]. `rules.rs`
//! then runs the *same* collapse+canonicalize+catalog-match pipeline against
//! each body as an additional haystack (match-many), so the
//! flag-separation/quoted-target bypass classes `canonicalize()` already
//! fixes at the outer level (`rm -r -f /` -> `rm -rf /`) are also caught
//! *inside* these bodies — something `canonicalize()`'s own position-scoping
//! (first token of a `;`/`&&`/`|`-delimited segment) structurally cannot
//! reach on its own, since inside `bash -c "rm -r -f /"` the segment's first
//! token is `bash`, not `rm`.
//!
//! # Scope — a narrow, explicit list of shapes, not a shell parser
//!
//! This does not tokenize the extracted body, does not understand
//! Python/JavaScript grammar, and never recurses into a second
//! interpreter/heredoc found inside an already-extracted body
//! (`bash -c "bash -c \"rm -r -f /\""` stays a permanent, documented miss —
//! see `bypass_corpus::inline_interpreter::inline_interpreter_double_wrapped_not_extracted`).
//! It extracts a **delimited span of text** (a quoted string, or a heredoc's
//! line-bounded body) with a small, bounded, single-pass scanner — the same
//! class of primitive `data_region.rs` already uses for its own quote-balance
//! tracking, not shared code (the two call sites' exact semantics diverge:
//! this one only ever wants "where does this quote end", not
//! `data_region`'s nested-substitution carve-out).
//!
//! # Position-scoping — an interpreter shape must be the segment's command word
//!
//! Masking (see "Calling convention" below) only blanks a narrow, explicit
//! list of data-consuming commands' arguments (`echo`/`printf`/`git commit
//! -m`/`git log --grep`) — it does not, and cannot, cover every command whose
//! arguments happen to be free text (`grep`, `find -name`, `rg`, `awk`,
//! `sed`, …). Before this fix, both detectors below searched for their shape
//! **anywhere** in the (masked) string, unanchored — so
//! `grep "bash -c 'rm -rf /'" log.txt` extracted `rm -rf /` as if `bash -c`
//! had actually been invoked, when it is really just `grep`'s search pattern,
//! never executed. That flipped an inert, already-`Allow` command (the same
//! payload unwrapped, `grep "rm -rf /" log.txt`, has always been `Allow` —
//! `grep`'s raw-match boundary is broken by the trailing quote) into a
//! false-positive `Deny`.
//!
//! The fix mirrors `canonicalize()`'s own position-scoping invariant exactly
//! (see `canonicalize`'s module doc, "Position-scoping"): an interpreter
//! shape only ever counts as a real invocation when it sits at the **command
//! word** of a `&&`/`||`/`;`/`|`/newline-delimited top-level segment — never
//! merely somewhere inside that segment's later tokens (another command's
//! argument). Both detectors below locate the top-level segment containing
//! the shape's match position (via `canonicalize::split_top_level_segments`,
//! reused verbatim so extraction's notion of "segment" never diverges from
//! canonicalize's own) and resolve that segment's command word (via
//! `canonicalize::strip_wrapper_prefixes`, so a `sudo`/`env`/`command`/`\`
//! -wrapped interpreter is still recognized, same as canonicalize's own
//! transforms):
//!
//! - **Inline `-c`/`-e`/`--eval`/`eval` bodies**: the segment's command word
//!   must itself be a recognized interpreter (`bash|sh|zsh|dash|python\d*|
//!   node|nodejs`) or the `eval` builtin. `grep "bash -c '…'"` — command word
//!   `grep` — extracts nothing; `bash -c "…"` — command word `bash` —
//!   extracts as before.
//! - **Heredoc bodies**: the command receiving the heredoc must be an
//!   interpreter — either directly (the containing segment's command word,
//!   `bash <<EOF`) or as a pipe target (`cat <<EOF | bash`: the containing
//!   segment's command word must be `cat`, connected by a literal `|`
//!   delimiter — not `;`/`&&`/newline — to a following segment whose own
//!   command word is the real interpreter). `grep bash <<EOF` — command word
//!   `grep`, "bash" is merely `grep`'s search-pattern argument, not a pipe
//!   target — extracts nothing.
//!
//! See `heredoc_destination_is_interpreter` and
//! `position_is_interpreter_command_word` below, and
//! `bypass_corpus::false_positive_guards` for the regression pins.
//!
//! # Calling convention — runs strictly after masking, on real newlines
//!
//! `RuleSet::haystacks_with_bodies` (`rules.rs`) calls
//! `extract_bodies(&masked)` where `masked` is
//! `data_region::mask_data_regions(&pre)`'s direct output: invisible-stripped
//! and line-continuation-folded (`command_pre`), then data-region-masked, but
//! **not yet** whitespace-collapsed — real newlines are still present, which
//! heredoc boundary detection needs (a heredoc's closing delimiter line is
//! indistinguishable from any other token once newlines are gone). Running
//! after masking means an inline-interpreter/heredoc shape sitting inertly
//! inside a masked data region (an `echo` argument, a `git commit -m`
//! message) is already blanked to spaces by the time this scanner runs, so it
//! can never be mistaken for a real invocation — see
//! `docs/superpowers/specs/2026-07-17-command-gate-inline-script-extraction-design.md`,
//! "Empirical grounding" and Owner Decision 3.
//!
//! # Match-many, never replace
//!
//! `RuleSet::matches` checks every extracted body's own raw+canonical form
//! **in addition to** `hay_raw`/`hay_canonical` — `hay_raw` is always matched
//! unmodified, so extraction is strictly additive: a bug here (a body that
//! fails to extract, or extracts wrong) can only fail to add coverage, never
//! remove coverage a raw match would otherwise have caught.
//!
//! # Fail-safe and bounds
//!
//! - **Input size cap** ([`MAX_INPUT_LEN`]): oversized input skips extraction
//!   entirely (returns no bodies) — mirrors `canonicalize::MAX_LEN`'s 8 KiB
//!   cap (kept as an independent constant here rather than sharing one,
//!   flagged for a later dedup pass if the two call sites' needs stay
//!   aligned).
//! - **Bodies-per-command cap** ([`MAX_BODIES`]): stops extracting once 8
//!   bodies have been found, across both inline and heredoc forms combined.
//! - **Per-body size cap** ([`MAX_BODY_LEN`]): an oversized single body is
//!   **dropped**, never truncated — truncation risks concealing a real match
//!   (cutting a token in half) or fabricating a spurious one (splicing two
//!   unrelated fragments at the cut point); dropping is always safe here
//!   specifically because extraction is purely additive — a dropped body just
//!   falls back to today's (pre-extraction) coverage for that one body.
//! - **Unterminated quote / unterminated heredoc**: skip that specific
//!   candidate, keep scanning for others in the same command.
//! - **No recursion**: `extract_bodies` is called exactly once per outer
//!   command; it is never called again on an already-extracted body's own
//!   text.
//! - **No panics**: pure `&str`/`String` operations; the interpreter/
//!   heredoc-open *detector* patterns are plain `regex::Regex` (no lookaround
//!   needed, so no `fancy_regex`, and the `regex` crate's automaton is
//!   linear-time regardless of input); the quoted-span/heredoc-body *extent*
//!   scanner is hand-written, bounded, single-pass, byte-indexed (safe for
//!   UTF-8: every byte this scanner treats as structural — `'`, `"`, `\`,
//!   `<`, `|`, `\n`, ASCII letters/digits — is a single-byte ASCII value, and
//!   no continuation/lead byte of a multi-byte UTF-8 sequence can ever equal
//!   one, so scanning at the byte level never misinterprets a multi-byte
//!   character and every index this module hands back to `&str` slicing sits
//!   on a valid char boundary).
//!
//! See `docs/superpowers/specs/2026-07-17-command-gate-inline-script-extraction-design.md`
//! for the full design (the "Extraction model", the accepted Owner
//! Decisions, and the corpus cases this feature graduates).
//!
//! # A third body source: resolved script files (`shape: "script_file"`)
//!
//! [`resolve_script_files`] (bottom of this file) closes the sibling
//! *write-then-run* bypass: an agent `Write`s a script whose bytes are never
//! scanned, then runs it via a syntactically-clean `bash x.sh`. It detects a
//! Bash segment that actually **executes a file** (`<interp> FILE`,
//! `.`/`source FILE`, or a direct `./x.sh`/`/abs/x.sh`/`dir/x.sh` command
//! word) using the exact same position-scoped segment/command-word machinery
//! this module already built for inline-body extraction, resolves the file
//! path (absolute as-is; relative joined against the hook's `cwd`, absent
//! `cwd` -> skip, fail-open), bounded-reads it, and — on success — emits it as
//! its own [`ExtractedBody`] (`shape: "script_file"`) into the *same* body
//! vector `RuleSet::matches` already runs through collapse+canonicalize+
//! match-many. A resolution failure of any kind (no `cwd` for a relative
//! path, nonexistent file, read error, oversized file, non-UTF-8 content)
//! degrades to "this file contributes no body" — never a panic, never a
//! change to the outer command's own raw/canonical match. See
//! `docs/superpowers/specs/2026-07-17-command-gate-script-file-resolution-design.md`
//! for the full design.

use std::sync::OnceLock;

use super::canonicalize::{self, Piece};

/// One recognized inline-interpreter or heredoc body extracted from a masked
/// (not yet whitespace-collapsed) Bash command string. `shape` is either
/// `"inline_interpreter"` or `"heredoc"` — the same bucket names the bypass
/// corpus uses, so a hit's `[matched inside extracted <shape> body]` reason
/// tag lines up with the corpus file it should be regression-pinned in.
pub(crate) struct ExtractedBody {
    pub(crate) text: String,
    pub(crate) shape: &'static str,
}

/// Bodies-per-command cap: stop extracting once this many bodies have been
/// found (inline + heredoc combined).
const MAX_BODIES: usize = 8;

/// Input size cap (bytes). Oversized input skips extraction entirely
/// (fail-safe — `hay_raw`/`hay_canonical` are matched independently of
/// whether extraction runs at all). Mirrors `canonicalize::MAX_LEN`.
const MAX_INPUT_LEN: usize = 8192;

/// Per-body size cap (bytes). An oversized single body is dropped, not
/// truncated (see module doc).
const MAX_BODY_LEN: usize = 8192;

/// Extracts every recognized inline-interpreter/heredoc body from `masked`
/// (the data-region-masked, not-yet-whitespace-collapsed command string —
/// see module doc, "Calling convention"). Never panics; every failure mode
/// (oversized input, an individual unterminated quote/heredoc, an oversized
/// individual body) degrades to "this candidate contributes nothing" rather
/// than aborting the whole scan.
pub(crate) fn extract_bodies(masked: &str) -> Vec<ExtractedBody> {
    if masked.len() > MAX_INPUT_LEN {
        return Vec::new();
    }
    let mut bodies = Vec::new();
    extract_inline_bodies(masked, &mut bodies);
    if bodies.len() < MAX_BODIES {
        extract_heredoc_bodies(masked, &mut bodies);
    }
    bodies
}

// ---- Position-scoping: segment/delimiter walk + command-word resolution --

/// One [`Piece`] from `canonicalize::split_top_level_segments`, with its
/// byte range within the original string recovered via pointer arithmetic
/// (safe: every `Piece` is, by construction, a direct sub-slice of the `&str`
/// passed to `split_top_level_segments`, so its start pointer always sits at
/// or after that string's own start pointer within the same allocation).
/// Keeping delimiters (not just segments) is what lets
/// `heredoc_destination_is_interpreter` tell a `|` pipe-target delimiter
/// apart from `;`/`&&`/newline.
struct ScopedPiece<'a> {
    text: &'a str,
    start: usize,
    is_segment: bool,
}

/// Walks `s` into [`ScopedPiece`]s — the same top-level `&&`/`||`/`;`/`|`
/// /newline split `canonicalize()` uses for its own position-scoping,
/// reused verbatim (see module doc, "Position-scoping") — in original order,
/// each tagged with its byte range in `s`.
fn scoped_pieces(s: &str) -> Vec<ScopedPiece<'_>> {
    let base = s.as_ptr() as usize;
    canonicalize::split_top_level_segments(s)
        .into_iter()
        .map(|p| match p {
            Piece::Segment(t) => ScopedPiece {
                text: t,
                start: t.as_ptr() as usize - base,
                is_segment: true,
            },
            Piece::Delim(t) => ScopedPiece {
                text: t,
                start: t.as_ptr() as usize - base,
                is_segment: false,
            },
        })
        .collect()
}

/// The resolved command-name token of one top-level segment — reuses
/// `canonicalize::strip_wrapper_prefixes` (see that function's doc) so a
/// `sudo`/`env`/`command`/`\`-wrapped interpreter is still recognized as
/// such. `None` for an all-whitespace/empty segment (nothing to check).
fn segment_command_word(seg: &str) -> Option<String> {
    let mut tokens: Vec<String> = seg.split_whitespace().map(String::from).collect();
    let cmd_i = canonicalize::strip_wrapper_prefixes(&mut tokens)?;
    tokens.get(cmd_i).cloned()
}

/// True if `pos` (a byte offset into the same string [`scoped_pieces`] was
/// built from) sits inside a top-level segment whose command word is itself
/// a recognized interpreter or the `eval` builtin — the position-scoping
/// gate for the inline `-c`/`-e`/`--eval`/`eval` detectors. `false` (and
/// therefore "do not extract") for a position that falls in no segment at
/// all (should not happen — every byte of `s` belongs to some segment — but
/// fail-safe rather than panic if it ever did) or whose segment's command
/// word is neither.
fn position_is_interpreter_command_word(pieces: &[ScopedPiece<'_>], pos: usize) -> bool {
    let Some(seg) = pieces
        .iter()
        .find(|p| p.is_segment && pos >= p.start && pos < p.start + p.text.len())
    else {
        return false;
    };
    segment_command_word(seg.text)
        .map(|w| is_recognized_interpreter(&w) || w.eq_ignore_ascii_case("eval"))
        .unwrap_or(false)
}

// ---- Form 1 + eval: inline-interpreter / eval quoted bodies --------------

/// `bash -c "…"` / `sh -c '…'` / `zsh -c "…"` / `dash -c "…"`.
fn shell_c_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r#"(?i)\b(?:bash|sh|zsh|dash)\b(?:[ \t]+-[A-Za-z][A-Za-z0-9-]*)*[ \t]+-c[ \t]*(['"])"#,
        )
        .expect("shell -c regex is valid")
    })
}

/// `python -c "…"` / `python3 -c "…"` / `python3.11 -c "…"` (any
/// digit/dot-suffixed version, mirroring `canonicalize::fold_interpreter_version`).
fn python_c_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r#"(?i)\bpython[0-9]*(?:\.[0-9]+)*\b(?:[ \t]+-[A-Za-z][A-Za-z0-9-]*)*[ \t]+-c[ \t]*(['"])"#,
        )
        .expect("python -c regex is valid")
    })
}

/// `node -e "…"` / `node --eval "…"` / `nodejs -e "…"`.
fn node_e_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r#"(?i)\b(?:node|nodejs)\b(?:[ \t]+-[A-Za-z][A-Za-z0-9-]*)*[ \t]+(?:-e|--eval)[ \t]*(['"])"#,
        )
        .expect("node -e regex is valid")
    })
}

/// `eval "…"` / `eval '…'` — the plain-literal-string case the pre-existing
/// `rce.decode_exec` pattern (`eval\s+"?\$\(`) does not cover (that pattern
/// only matches the `$(...)` form).
fn eval_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r#"(?i)\beval\b[ \t]*(['"])"#).expect("eval regex is valid")
    })
}

/// Runs all four inline-body detectors over `s`, pushing a recognized body
/// (shape `"inline_interpreter"`) for each match whose quoted argument is
/// well-terminated and not oversized. **Quoted-only** — an unquoted `-c`/`-e`
/// argument (no quote character immediately after the flag) simply never
/// matches these patterns, so it naturally yields zero bodies (Owner
/// Decision 4A) with no extra code needed. **Position-scoped** — a match is
/// only extracted when it sits at its enclosing top-level segment's actual
/// command word (see module doc, "Position-scoping"); an interpreter shape
/// sitting inertly inside another command's argument
/// (`grep "bash -c '…'" log.txt`) is rejected, never extracted.
fn extract_inline_bodies(s: &str, bodies: &mut Vec<ExtractedBody>) {
    let bytes = s.as_bytes();
    let pieces = scoped_pieces(s);
    for re in [shell_c_re(), python_c_re(), node_e_re(), eval_re()] {
        for caps in re.captures_iter(s) {
            if bodies.len() >= MAX_BODIES {
                return;
            }
            let whole = caps.get(0).expect("group 0 always present on a match");
            // Guards `eval_re` against firing inside `node --eval "…"`:
            // `-` is not a word character, so `\beval\b` alone is satisfied
            // right before the "eval" *inside* "--eval" too (a real word
            // boundary sits between the second `-` and `e`). Rejecting any
            // match immediately preceded by `-` (part of a longer flag
            // token, never a real `eval` invocation) closes that without a
            // lookbehind. Harmless for the other three detectors — none of
            // `bash`/`sh`/`zsh`/`dash`/`python*`/`node`/`nodejs` are ever
            // legitimately invoked as the tail of a `-flag` token.
            if whole.start() > 0 && bytes[whole.start() - 1] == b'-' {
                continue;
            }
            // Position-scoping (see module doc): reject a match that isn't
            // at its enclosing segment's actual command word.
            if !position_is_interpreter_command_word(&pieces, whole.start()) {
                continue;
            }
            let Some(qm) = caps.get(1) else { continue };
            let quote_open = qm.start();
            // ASCII by construction: the capture group only ever matches a
            // literal `'` or `"` byte.
            let quote_char = s.as_bytes()[quote_open] as char;
            let Some(quote_close) = find_quote_end(s, quote_open, quote_char) else {
                continue; // unterminated quote -> skip this candidate, keep scanning
            };
            let raw_body = &s[quote_open + 1..quote_close];
            if raw_body.len() > MAX_BODY_LEN {
                continue; // oversized -> drop, not truncate
            }
            // A double-quoted argument undergoes real backslash-escape
            // removal by the outer shell before the wrapped interpreter ever
            // sees it (`\"`, `` \` ``, `\$`, `\\`, and line-continuation) —
            // see `unescape_double_quoted`'s own doc for why this is
            // load-bearing, not cosmetic. A single-quoted argument gets none
            // of that: single quotes perform zero escape processing in a
            // real shell, so it is taken verbatim.
            let text = if quote_char == '"' {
                unescape_double_quoted(raw_body)
            } else {
                raw_body.to_string()
            };
            bodies.push(ExtractedBody {
                text,
                shape: "inline_interpreter",
            });
        }
    }
}

/// Finds the index of the quote character (matching `quote_char`, opened at
/// `quote_open`) that closes this quoted span, respecting backslash-escapes
/// inside a double-quoted span exactly like `data_region`'s own quote
/// tracking (single-quoted spans have no escaping at all — a `\` there is
/// just a literal character, never able to escape the closing `'`). `None`
/// on an unterminated quote (fail-safe — the caller skips this candidate).
fn find_quote_end(s: &str, quote_open: usize, quote_char: char) -> Option<usize> {
    let bytes = s.as_bytes();
    let qb = quote_char as u8;
    let mut i = quote_open + 1;
    while i < bytes.len() {
        if bytes[i] == qb && (qb == b'\'' || !is_escaped(bytes, i)) {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// True if `bytes[i]` is backslash-escaped: preceded by an odd number of
/// consecutive `\` bytes. Mirrors `data_region::is_escaped`'s rule exactly,
/// at byte granularity (safe for UTF-8 — see module doc).
fn is_escaped(bytes: &[u8], i: usize) -> bool {
    let mut count = 0usize;
    let mut j = i;
    while j > 0 && bytes[j - 1] == b'\\' {
        count += 1;
        j -= 1;
    }
    count % 2 == 1
}

/// Reverses the backslash-escaping a real shell performs while parsing a
/// double-quoted string, so an extracted double-quoted body reflects the
/// actual argument *value* the wrapped interpreter would receive — not the
/// outer shell's literal source text. Inside double quotes, a real shell
/// treats backslash as an escape character only before `$`, a backtick,
/// `"`, another backslash, or a real newline (line-continuation — both
/// characters are removed); a backslash before anything else is left as a
/// literal backslash (POSIX double-quote escaping rules). This composes with
/// `canonicalize()`'s target-argument quote-unwrap transform: without
/// unescaping, `sh -c "rm -rf \"/\""` would extract to the literal text
/// `rm -rf \"/\"` (backslashes still present), whose target token starts
/// with `\`, not a real quote character, so
/// `canonicalize::unwrap_target_token_quotes` would never recognize it as a
/// quoted target at all. Unescaping first produces `rm -rf "/"` (real quote
/// characters), which is exactly the string a real `sh -c` invocation would
/// actually receive as argv, and lets that existing transform fire —
/// extraction's whole contribution is making the body available as its own
/// first-token context; the actual quote-unwrap still comes from machinery
/// `canonicalize()` already has. Never applied to a single-quoted body (see
/// caller).
fn unescape_double_quoted(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '\\' {
            match chars.get(i + 1) {
                Some('$') | Some('`') | Some('"') | Some('\\') => {
                    out.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                Some('\r') if chars.get(i + 2) == Some(&'\n') => {
                    i += 3; // line continuation (CRLF): both chars removed
                    continue;
                }
                Some('\n') => {
                    i += 2; // line continuation: both chars removed
                    continue;
                }
                _ => {}
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

// ---- Form 3: heredoc bodies destined for a recognized interpreter --------

/// `<<[-]?(['"]?)DELIM\1` — matches a heredoc-open token anywhere in the
/// string. Group 1: the optional `-` (`<<-`, strips leading tabs on the
/// *closing* line only — see module doc and [`find_heredoc_body`]). Groups
/// 2/3/4: the delimiter word, whichever of the single-quoted/double-quoted/
/// unquoted forms matched (exactly one is ever `Some`). The delimiter is
/// restricted to a simple identifier shape (`[A-Za-z_][A-Za-z0-9_]*`) — a
/// deliberate, narrow v1 scope (real heredoc delimiters can technically be
/// almost anything); this only ever costs coverage on an exotic delimiter,
/// never adds a false positive.
fn heredoc_open_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r#"<<(-)?(?:'([A-Za-z_][A-Za-z0-9_]*)'|"([A-Za-z_][A-Za-z0-9_]*)"|([A-Za-z_][A-Za-z0-9_]*))"#,
        )
        .expect("heredoc-open regex is valid")
    })
}

/// True if `word` (already trimmed) names a recognized v1 interpreter —
/// Owner Decision 1B's list: `bash|sh|zsh|dash`, `node`/`nodejs`, or any
/// digit/dot-suffixed `python` form. Case-insensitive.
fn is_recognized_interpreter(word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let lower = word.to_ascii_lowercase();
    matches!(lower.as_str(), "bash" | "sh" | "zsh" | "dash" | "node" | "nodejs")
        || is_python_word(&lower)
}

fn is_python_word(lower: &str) -> bool {
    let Some(rest) = lower.strip_prefix("python") else {
        return false;
    };
    if rest.is_empty() {
        return true; // bare "python"
    }
    rest.chars().next().is_some_and(|c| c.is_ascii_digit())
        && rest.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Position-scoped: true if the command receiving the heredoc whose `<<`
/// token starts at `open_pos` is a recognized interpreter — either directly
/// (the containing top-level segment's own command word, `bash <<EOF`) or as
/// a pipe target (`cat <<EOF | bash`: the containing segment's command word
/// must be `cat`, connected by a literal `|` [`Piece::Delim`] — never
/// `;`/`&&`/newline — to the immediately following segment, whose own
/// command word must be the real interpreter). See module doc,
/// "Position-scoping". `grep bash <<EOF` — the containing (and only)
/// segment's command word is `grep`; `bash` is merely `grep`'s argument, not
/// a pipe target — matches neither shape, so this returns `false`, closing
/// the false positive naive token-before-`<<` scanning had.
fn heredoc_destination_is_interpreter(pieces: &[ScopedPiece<'_>], open_pos: usize) -> bool {
    let Some(k) = pieces
        .iter()
        .position(|p| p.is_segment && open_pos >= p.start && open_pos < p.start + p.text.len())
    else {
        return false;
    };
    let Some(word) = segment_command_word(pieces[k].text) else {
        return false;
    };
    if is_recognized_interpreter(&word) {
        return true;
    }
    if !word.eq_ignore_ascii_case("cat") {
        return false;
    }
    // Pipe-target shape: the piece immediately after this segment must be a
    // literal `|` delimiter (never `;`/`&&`/newline — those start a new,
    // unrelated command, not a pipe target), and the piece after *that* must
    // be a segment whose own command word is the real interpreter.
    let (Some(delim), Some(next_seg)) = (pieces.get(k + 1), pieces.get(k + 2)) else {
        return false;
    };
    if delim.is_segment || delim.text != "|" || !next_seg.is_segment {
        return false;
    }
    segment_command_word(next_seg.text)
        .is_some_and(|w| is_recognized_interpreter(&w))
}

/// Runs the heredoc-open detector over `s`, and for each match whose
/// destination is a recognized interpreter (position-scoped — see
/// [`heredoc_destination_is_interpreter`]), locates the body via
/// [`find_heredoc_body`] and pushes it (shape `"heredoc"`). A heredoc whose
/// destination is neither shape — most notably one redirected to a file
/// (`cat <<EOF > install.sh`), or one destined for a non-interpreter command
/// that merely has "bash"/etc. as a later argument (`grep bash <<EOF`) — is
/// left alone entirely: these are the false-positive guards the
/// `heredoc_redirected_to_file_not_extracted` and
/// `fp_guard_grep_word_bash_before_heredoc` corpus cases pin.
fn extract_heredoc_bodies(s: &str, bodies: &mut Vec<ExtractedBody>) {
    let pieces = scoped_pieces(s);
    for caps in heredoc_open_re().captures_iter(s) {
        if bodies.len() >= MAX_BODIES {
            return;
        }
        let whole = caps.get(0).expect("group 0 always present on a match");
        let dash = caps.get(1).is_some();
        let delim = caps
            .get(2)
            .or_else(|| caps.get(3))
            .or_else(|| caps.get(4))
            .map(|m| m.as_str())
            .unwrap_or("");
        if delim.is_empty() {
            continue;
        }

        if !heredoc_destination_is_interpreter(&pieces, whole.start()) {
            continue;
        }

        let line_end = s[whole.end()..]
            .find('\n')
            .map(|off| whole.end() + off)
            .unwrap_or(s.len());

        if line_end >= s.len() {
            continue; // heredoc-open is the last physical line -> no body possible
        }
        let body_start = line_end + 1;
        let Some((bs, be)) = find_heredoc_body(s, body_start, delim, dash) else {
            continue; // unterminated heredoc -> skip this one, keep scanning
        };
        let body_text = &s[bs..be];
        if body_text.len() > MAX_BODY_LEN {
            continue; // oversized -> drop, not truncate
        }
        bodies.push(ExtractedBody {
            text: body_text.to_string(),
            shape: "heredoc",
        });
    }
}

/// Scans forward from `body_start` for a line whose content — after
/// stripping a leading run of tabs when `strip_tabs` is set (the `<<-` form;
/// per the design, this strips leading tabs on the *closing* line only, not
/// every body line — a deliberate v1 simplification: the body is fed through
/// the same whitespace-collapse the rest of the pipeline already applies, so
/// per-line leading tabs elsewhere in the body carry no matching-relevant
/// information anyway) and a trailing `\r` (CRLF tolerance) — exactly equals
/// `delim`. Returns `Some((body_start, closing_line_start))` on success
/// (`closing_line_start` excludes the closing line itself, but *includes*
/// the final newline of the body's last content line, matching what a real
/// heredoc body actually contains), or `None` on an unterminated heredoc
/// (fail-safe — the caller skips this specific body and keeps scanning for
/// others).
fn find_heredoc_body(s: &str, body_start: usize, delim: &str, strip_tabs: bool) -> Option<(usize, usize)> {
    let mut line_start = body_start;
    loop {
        if line_start > s.len() {
            return None;
        }
        let line_end = match s[line_start..].find('\n') {
            Some(off) => line_start + off,
            None => s.len(),
        };
        let raw_line = &s[line_start..line_end];
        let candidate = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let trimmed = if strip_tabs {
            candidate.trim_start_matches('\t')
        } else {
            candidate
        };
        if trimmed == delim {
            return Some((body_start, line_start));
        }
        if line_end >= s.len() {
            return None; // reached end of input without finding the closer
        }
        line_start = line_end + 1;
    }
}

// ---- Referenced-script-file resolution (shape: "script_file") ------------

/// Max resolved-script-file bodies per command (design doc, Owner Decision 3
/// — "max script-files-per-command 8"). Deliberately a separate cap from
/// [`MAX_BODIES`], not a shared pool: this feature's bodies come from actual
/// filesystem reads, a categorically different (and more expensive) source
/// than the inline/heredoc bodies `MAX_BODIES` bounds.
const MAX_SCRIPT_FILES: usize = 8;

/// Per-file read cap in bytes (design doc, Owner Decision 3 — 256 KiB). An
/// oversized file is dropped, never truncated — same drop-not-truncate
/// reasoning [`MAX_BODY_LEN`] documents above: truncation risks concealing a
/// real match or fabricating a spurious one at the cut point, and dropping is
/// safe here specifically because resolution is purely additive (module doc,
/// "Match-many, never replace").
const MAX_SCRIPT_FILE_LEN: usize = 256 * 1024;

/// Recognized script-exec interpreters (design doc, "What counts as
/// executing a script file", form 1). A deliberately different list from
/// [`is_recognized_interpreter`] (the inline-body feature's own): this
/// feature additionally recognizes `ruby`/`perl`, which have no `-c`/`-e`
/// inline-body detector of their own, so there is no double-coverage concern
/// between the two features for those two names.
fn is_script_exec_interpreter(word: &str) -> bool {
    let lower = word.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "bash" | "sh" | "zsh" | "dash" | "node" | "nodejs" | "ruby" | "perl"
    ) || is_python_word(&lower)
}

/// A segment's resolved command word plus its remaining argument tokens.
/// `strip_wrapper_prefixes` mutates `tokens` in place (peeling recognized
/// `sudo`/`env`/`command`/`\`-wrapper layers) and returns the index of the
/// real command-name token; the args returned here are everything after that
/// index, so a wrapped interpreter's real file argument is still resolved
/// correctly (`sudo bash ./x.sh` sees command `bash`, args `["./x.sh"]`).
/// Mirrors [`segment_command_word`], extended to also keep the trailing
/// tokens. `None` for an all-whitespace/empty segment.
fn segment_command_and_args(seg: &str) -> Option<(String, Vec<String>)> {
    let mut tokens: Vec<String> = seg.split_whitespace().map(String::from).collect();
    let cmd_i = canonicalize::strip_wrapper_prefixes(&mut tokens)?;
    let cmd = tokens.get(cmd_i)?.clone();
    let args = tokens.get(cmd_i + 1..).map(|s| s.to_vec()).unwrap_or_default();
    Some((cmd, args))
}

/// True for a token that could plausibly be a real file-path operand: not a
/// `-flag`, and not a shell redirection operator (`<file`, `<<EOF`, `<<-EOF`,
/// `>out`, `>>out`, ...). Without this guard, `bash <<EOF` (a heredoc, whose
/// body extraction is the sibling inline/heredoc feature's job entirely) would
/// misread the heredoc-open token `<<EOF` itself as if it were a file
/// argument.
fn looks_like_file_operand(tok: &str) -> bool {
    !tok.is_empty() && !tok.starts_with('-') && !tok.starts_with('<') && !tok.starts_with('>')
}

/// A small per-interpreter allowlist of KNOWN value-taking flags for
/// [`detect_script_exec_file`]'s form-1 (interpreter + file) operand scan:
/// when one of these is seen, the NEXT token (its value) must be skipped too
/// before resuming the search for the first true file operand. Without this,
/// `python -W ignore evil.py` latches onto `ignore` (the flag's value) as if
/// it were the script — `evil.py` is never resolved/scanned. `=`-joined
/// forms (`-W=ignore`, `--require=./pre`) are already a single token (no
/// separate value token follows), so they need no extra skip — this table is
/// only consulted for a token that doesn't contain `=`.
///
/// Deliberately a small, explicit allowlist (design brief), not a full argv
/// parser: an unrecognized value-taking flag is a documented, narrower
/// residual gap — see `script_file_shape_tests::unrecognized_value_taking_flag_still_defeats_resolution_known_miss`.
///
/// - `python`/`python\d*`: `-W`, `-X`  (`-c` is inline — handled above this
///   loop already fires the step-aside `None`).
/// - `node`/`nodejs`: `-r`, `--require` (`-e`/`--eval` are inline).
/// - `ruby`: `-I`, `-r`, `-C` (`-e` is inline, but ruby has no sibling inline
///   extractor — same step-aside behavior either way).
/// - `perl`: `-I`, `-M` (`-e` is inline, same caveat as ruby).
/// - `bash`/`sh`/`zsh`/`dash`: `--rcfile`, `--init-file` (`-c` is inline).
fn is_known_value_flag(interpreter: &str, flag: &str) -> bool {
    if flag.contains('=') {
        return false;
    }
    let lower = interpreter.to_ascii_lowercase();
    if is_python_word(&lower) {
        return matches!(flag, "-W" | "-X");
    }
    match lower.as_str() {
        "node" | "nodejs" => matches!(flag, "-r" | "--require"),
        "ruby" => matches!(flag, "-I" | "-r" | "-C"),
        "perl" => matches!(flag, "-I" | "-M"),
        "bash" | "sh" | "zsh" | "dash" => matches!(flag, "--rcfile" | "--init-file"),
        _ => false,
    }
}

/// Detects one of the three recognized "executing a script file" segment
/// shapes (design doc, "What counts as executing a script file") and returns
/// the literal file-argument token as written in the segment (not yet
/// resolved to a filesystem path). `None` when this segment doesn't execute a
/// file at all — either not script-exec shaped, or an inline
/// `-c`/`-e`/`--eval` body that belongs to the sibling inline-body feature
/// instead (form 1 explicitly steps aside for it: "FILE is the first
/// non-flag operand that is not itself a `-c`/`-e`/`--eval` inline body").
fn detect_script_exec_file(seg: &str) -> Option<String> {
    let (cmd, args) = segment_command_and_args(seg)?;

    // Form 3: direct execution — the command word IS the file (contains a
    // `/`: `./x.sh`, `../tools/x.sh`, `/abs/x.sh`, `dir/x.sh`).
    if cmd.contains('/') {
        return Some(cmd);
    }

    // Form 2: sourced file — `. FILE` / `source FILE`.
    if cmd == "." || cmd.eq_ignore_ascii_case("source") {
        return args.into_iter().find(|a| looks_like_file_operand(a));
    }

    // Form 1: interpreter + file — the first non-flag, non-redirection
    // operand, UNLESS an inline `-c`/`-e`/`--eval` flag appears first (that
    // shape belongs to `extract_inline_bodies`, not here). A KNOWN
    // value-taking flag (`is_known_value_flag`) has its value token skipped
    // too, so `python -W ignore evil.py` still resolves to `evil.py`, not
    // `ignore` — see that function's own doc for the recognized set and the
    // documented residual gap for an unrecognized value-taking flag.
    if is_script_exec_interpreter(&cmd) {
        let mut i = 0usize;
        while i < args.len() {
            let a = &args[i];
            if a.eq_ignore_ascii_case("-c")
                || a.eq_ignore_ascii_case("-e")
                || a.eq_ignore_ascii_case("--eval")
            {
                return None; // inline body form, not file-exec — handled elsewhere
            }
            if is_known_value_flag(&cmd, a) {
                i += 2; // skip the flag AND its value token
                continue;
            }
            if looks_like_file_operand(a) {
                return Some(a.clone());
            }
            i += 1;
        }
    }
    None
}

/// Resolves a script-exec file argument to a concrete filesystem path: an
/// absolute path (`/abs/x.sh`) is used as-is; a relative one (`x.sh`,
/// `./x.sh`, `dir/x.sh`) is joined against `cwd`. `.`/`..` folding is left to
/// the OS's own path resolution inside [`std::fs::read`] — no manual
/// normalization is needed, and no traversal guard either: this function's
/// result is only ever *read* to scan its content, never used to write or
/// otherwise act (design doc, "Path resolution"). Returns `None` (skip,
/// fail-open) when the argument is relative and `cwd` is absent.
fn resolve_path(file_token: &str, cwd: Option<&str>) -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(file_token);
    if p.is_absolute() {
        return Some(p.to_path_buf());
    }
    let cwd = cwd?;
    Some(std::path::Path::new(cwd).join(p))
}

/// Bounded read: stats the resolved path FIRST (rejecting anything that
/// isn't a regular file, plus any already-oversized file, before ever
/// opening it), then reads through a `Take` adapter so the read itself can
/// never consume more than the cap even if the file grows between the stat
/// and the read. Any failure — nonexistent file, permission error, not a
/// regular file, oversized file, non-UTF-8 bytes — returns `None` ("no
/// body"), never a panic, never a change to the outer command's own
/// raw/canonical match (design doc, "Reading the file" / "False-positive and
/// fail-safe posture").
///
/// The stat-first ordering is load-bearing, not cosmetic: `std::fs::read`
/// opens the path and reads to EOF before this function ever gets to check
/// the length, and `read`/`open` on a non-regular file — a FIFO, or a
/// character device like `/dev/zero`/`/dev/urandom` — can block
/// indefinitely (a FIFO's `open` waits for a writer; `/dev/zero`'s `read`
/// never hits EOF). A trivially-triggered `bash /dev/zero` would hang the
/// whole `decide()` call, an availability DoS on the security-critical gate
/// path. `std::fs::metadata` only inspects the inode — it does not open the
/// file and cannot block on FIFO/device semantics — so `!meta.is_file()`
/// (true for directories, FIFOs, character/block devices, sockets alike)
/// rejects every non-regular-file shape up front, before any blocking
/// operation is even attempted.
fn read_bounded_script(path: &std::path::Path) -> Option<String> {
    use std::io::Read;
    let meta = std::fs::metadata(path).ok()?; // follows symlinks; ELOOP/ENOENT -> None
    if !meta.is_file() || meta.len() as usize > MAX_SCRIPT_FILE_LEN {
        return None; // dirs, char devices, FIFOs, oversize -> no body
    }
    let mut buf = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take((MAX_SCRIPT_FILE_LEN as u64) + 1) // defense-in-depth vs size changing between stat and read
        .read_to_end(&mut buf)
        .ok()?;
    if buf.len() > MAX_SCRIPT_FILE_LEN {
        return None; // drop, don't truncate
    }
    String::from_utf8(buf).ok() // UTF-8 required (as today)
}

/// Resolves and bounded-reads every script file a `masked` Bash command
/// actually *executes* — position-scoped detection of the three recognized
/// exec forms (see [`detect_script_exec_file`]) over the same top-level
/// segment walk [`scoped_pieces`] already provides — turning each into its
/// own [`ExtractedBody`] (`shape: "script_file"`).
///
/// `masked` must be `data_region::mask_data_regions`'s output (the same
/// masked-but-not-yet-collapsed string [`extract_bodies`] itself consumes —
/// see this module's "Calling convention" doc): a script-exec shape sitting
/// inertly inside a masked data region (an `echo` argument, a `git commit -m`
/// message) is already blanked to spaces by the time this scanner runs, so it
/// can never be mistaken for a real invocation — masking composes for free,
/// exactly like the inline-body feature (design doc, "False-positive and
/// fail-safe posture").
///
/// `cwd` is the hook payload's working directory (`tc.input["cwd"]`, threaded
/// in by `rules::haystacks_with_bodies`) — used only to resolve a *relative*
/// file argument; `None` means only absolute-path forms resolve (fail-open,
/// never a block — design doc, "Path resolution").
///
/// Every failure mode (path doesn't resolve, file doesn't exist, read error,
/// oversized file, non-UTF-8 content) degrades to "this file contributes no
/// body" — never a panic, never a change to the outer command's own
/// raw/canonical match. No recursion: a resolved script's own inner
/// executions are never followed (pinned v1 limitation, design doc, "Bounds").
pub(crate) fn resolve_script_files(masked: &str, cwd: Option<&str>) -> Vec<ExtractedBody> {
    if masked.len() > MAX_INPUT_LEN {
        return Vec::new();
    }
    let mut bodies = Vec::new();
    for piece in scoped_pieces(masked) {
        if bodies.len() >= MAX_SCRIPT_FILES {
            break;
        }
        if !piece.is_segment {
            continue;
        }
        let Some(file_token) = detect_script_exec_file(piece.text) else {
            continue;
        };
        let Some(path) = resolve_path(&file_token, cwd) else {
            continue;
        };
        let Some(text) = read_bounded_script(&path) else {
            continue;
        };
        bodies.push(ExtractedBody {
            text,
            shape: "script_file",
        });
    }
    bodies
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(bodies: &[ExtractedBody]) -> Vec<&str> {
        bodies.iter().map(|b| b.text.as_str()).collect()
    }

    // ---- inline-interpreter quoted bodies, per interpreter ---------------

    #[test]
    fn bash_c_double_quoted() {
        let bodies = extract_bodies(r#"bash -c "rm -r -f /""#);
        assert_eq!(texts(&bodies), vec!["rm -r -f /"]);
        assert_eq!(bodies[0].shape, "inline_interpreter");
    }

    #[test]
    fn sh_c_single_quoted() {
        let bodies = extract_bodies("sh -c 'rm -r -f /'");
        assert_eq!(texts(&bodies), vec!["rm -r -f /"]);
    }

    #[test]
    fn zsh_c_double_quoted() {
        let bodies = extract_bodies(r#"zsh -c "rm -r -f /""#);
        assert_eq!(texts(&bodies), vec!["rm -r -f /"]);
    }

    #[test]
    fn dash_c_double_quoted() {
        let bodies = extract_bodies(r#"dash -c "rm -r -f /""#);
        assert_eq!(texts(&bodies), vec!["rm -r -f /"]);
    }

    #[test]
    fn python_c_versioned_dotted() {
        let bodies = extract_bodies(r#"python3.11 -c "import os""#);
        assert_eq!(texts(&bodies), vec!["import os"]);
    }

    #[test]
    fn python_c_bare() {
        let bodies = extract_bodies(r#"python -c "import os""#);
        assert_eq!(texts(&bodies), vec!["import os"]);
    }

    #[test]
    fn node_dash_e_double_quoted() {
        let bodies = extract_bodies(r#"node -e "require('fs')""#);
        assert_eq!(texts(&bodies), vec!["require('fs')"]);
    }

    #[test]
    fn node_dash_dash_eval_single_quoted() {
        let bodies = extract_bodies("nodejs --eval 'require(\"fs\")'");
        assert_eq!(texts(&bodies), vec!["require(\"fs\")"]);
    }

    #[test]
    fn eval_double_quoted() {
        let bodies = extract_bodies(r#"eval "rm -r -f /""#);
        assert_eq!(texts(&bodies), vec!["rm -r -f /"]);
        assert_eq!(bodies[0].shape, "inline_interpreter");
    }

    #[test]
    fn eval_single_quoted() {
        let bodies = extract_bodies("eval 'rm -r -f /'");
        assert_eq!(texts(&bodies), vec!["rm -r -f /"]);
    }

    // ---- the double-quote unescape composition (needed for transform-5
    // target-quote-unwrap to fire inside an extracted body) ----------------

    #[test]
    fn double_quoted_body_unescapes_inner_escaped_quotes() {
        // sh -c "rm -rf \"/\""  (as real shell source text) -> the outer
        // shell removes the backslashes before `sh -c` ever sees them, so
        // the actual argument value is `rm -rf "/"` (real quote chars).
        let cmd = "sh -c \"rm -rf \\\"/\\\"\"";
        let bodies = extract_bodies(cmd);
        assert_eq!(texts(&bodies), vec!["rm -rf \"/\""]);
    }

    #[test]
    fn single_quoted_body_never_unescapes() {
        // Single quotes perform zero escape processing in a real shell — a
        // literal backslash inside one must survive byte-for-byte.
        let bodies = extract_bodies(r#"bash -c 'echo \"literal\"'"#);
        assert_eq!(texts(&bodies), vec![r#"echo \"literal\""#]);
    }

    // ---- unquoted -c: zero bodies (Owner Decision 4A) ---------------------

    #[test]
    fn unquoted_dash_c_yields_zero_bodies() {
        let bodies = extract_bodies("bash -c rm -rf /");
        assert!(bodies.is_empty());
    }

    // ---- unterminated quote: zero bodies, no panic -------------------------

    #[test]
    fn unterminated_double_quote_yields_zero_bodies() {
        let bodies = extract_bodies(r#"bash -c "rm -rf /"#);
        assert!(bodies.is_empty());
    }

    // ---- heredoc: piped and direct-stdin -----------------------------------

    #[test]
    fn heredoc_piped_to_bash() {
        let cmd = "cat <<EOF | bash\nrm -r -f /\nEOF";
        let bodies = extract_bodies(cmd);
        assert_eq!(texts(&bodies), vec!["rm -r -f /\n"]);
        assert_eq!(bodies[0].shape, "heredoc");
    }

    #[test]
    fn heredoc_direct_stdin() {
        let cmd = "bash <<EOF\nrm -r -f /\nEOF";
        let bodies = extract_bodies(cmd);
        assert_eq!(texts(&bodies), vec!["rm -r -f /\n"]);
    }

    #[test]
    fn heredoc_direct_stdin_versioned_python() {
        let cmd = "python3 <<EOF\nrm -r -f /\nEOF";
        let bodies = extract_bodies(cmd);
        assert_eq!(texts(&bodies), vec!["rm -r -f /\n"]);
    }

    // ---- quoted vs. unquoted heredoc delimiter: identical extraction ------

    #[test]
    fn heredoc_quoted_and_unquoted_delimiter_extract_identically() {
        let unquoted = extract_bodies("bash <<EOF\nrm -r -f /\nEOF");
        let single = extract_bodies("bash <<'EOF'\nrm -r -f /\nEOF");
        let double = extract_bodies("bash <<\"EOF\"\nrm -r -f /\nEOF");
        assert_eq!(texts(&unquoted), texts(&single));
        assert_eq!(texts(&unquoted), texts(&double));
    }

    // ---- `<<-` leading-tab stripping on the closing line -------------------

    #[test]
    fn heredoc_dash_strips_leading_tabs_on_closing_line_only() {
        let cmd = "bash <<-EOF\nrm -r -f /\n\t\tEOF";
        let bodies = extract_bodies(cmd);
        assert_eq!(texts(&bodies), vec!["rm -r -f /\n"]);
    }

    #[test]
    fn heredoc_without_dash_does_not_strip_leading_tabs() {
        // A tab-indented closing line does NOT match plain `<<EOF` (no `-`) —
        // this must be treated as unterminated (no bare "EOF"-only line
        // exists before end of input), not accidentally still matched.
        let cmd = "bash <<EOF\nrm -r -f /\n\tEOF";
        let bodies = extract_bodies(cmd);
        assert!(bodies.is_empty());
    }

    // ---- file-redirect exclusion: zero bodies ------------------------------

    #[test]
    fn heredoc_redirected_to_file_yields_zero_bodies() {
        let cmd = "cat <<EOF > install.sh\nrm -r -f \"$BUILD_DIR\"\nEOF";
        let bodies = extract_bodies(cmd);
        assert!(bodies.is_empty());
    }

    // ---- unterminated heredoc: zero bodies, no panic -----------------------

    #[test]
    fn unterminated_heredoc_yields_zero_bodies() {
        let cmd = "bash <<EOF\nrm -r -f /\n";
        let bodies = extract_bodies(cmd);
        assert!(bodies.is_empty());
    }

    // ---- bodies-per-command cap --------------------------------------------

    #[test]
    fn bodies_per_command_cap_stops_at_max_bodies() {
        let cmd: String = (1..=10)
            .map(|n| format!("eval \"{n}\" "))
            .collect::<Vec<_>>()
            .join("");
        let bodies = extract_bodies(&cmd);
        assert_eq!(bodies.len(), MAX_BODIES);
    }

    // ---- per-body size cap: drop, not truncate -----------------------------
    //
    // MAX_BODY_LEN and MAX_INPUT_LEN are deliberately the same bound (per the
    // design's Owner Decision 5 — both reuse the same 8 KiB constant), so a
    // single body sitting exactly at MAX_BODY_LEN, plus any wrapper syntax
    // around it, always pushes the *whole command* over MAX_INPUT_LEN first —
    // the two caps are a layered fail-safe, not independently reachable in
    // isolation. What matters observably (and what these tests pin) is the
    // "drop, not truncate" contract: an oversized body never comes back
    // truncated, and an ordinary body comfortably under both bounds is kept
    // byte-for-byte.

    #[test]
    fn oversized_body_is_dropped_not_truncated() {
        let big = "a".repeat(MAX_BODY_LEN + 1);
        let cmd = format!("bash -c \"{big}\"");
        let bodies = extract_bodies(&cmd);
        assert!(bodies.is_empty(), "an oversized body must never come back truncated");
    }

    #[test]
    fn large_body_under_cap_is_kept_intact() {
        let ok = "a".repeat(4000);
        let cmd = format!("bash -c \"{ok}\"");
        let bodies = extract_bodies(&cmd);
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].text, ok);
    }

    // ---- overall input size cap --------------------------------------------

    #[test]
    fn oversized_input_yields_zero_bodies() {
        let big = "a".repeat(MAX_INPUT_LEN + 1);
        let cmd = format!("bash -c \"{big}\"");
        let bodies = extract_bodies(&cmd);
        assert!(bodies.is_empty());
    }

    // ---- masked data-region text is never extracted (composition proof) ---

    #[test]
    fn masked_inline_shape_is_never_extracted() {
        // Simulates what `data_region::mask_data_regions` already produces
        // for `echo "run bash -c 'rm -rf /' now"` — the whole argument
        // blanked to spaces. Extraction must find nothing here (it never
        // re-derives "is this data or executed" on its own — see module
        // doc).
        let masked = "echo                                     ";
        let bodies = extract_bodies(masked);
        assert!(bodies.is_empty());
    }

    // ---- position-scoping: an interpreter shape embedded inside another
    // command's argument is never extracted (the false-positive fix) --------
    //
    // None of these commands are masked by `data_region::mask_data_regions`
    // (grep/find/rg are not data-consuming commands in its narrow list), so
    // the interpreter/eval shape text stays visible exactly as typed — the
    // only thing that must stop extraction here is position-scoping: the
    // shape sits inside `grep`'s/`find`'s/`rg`'s own argument, never at the
    // segment's actual command word. See module doc, "Position-scoping", and
    // the sibling `Allow` guards in `bypass_corpus::false_positive_guards`.

    #[test]
    fn grep_bash_c_embedded_in_quoted_arg_yields_zero_bodies() {
        let bodies = extract_bodies(r#"grep "bash -c 'rm -rf /'" log.txt"#);
        assert!(bodies.is_empty());
    }

    #[test]
    fn rg_eval_embedded_in_quoted_arg_yields_zero_bodies() {
        let bodies = extract_bodies(r#"rg 'eval "rm -r -f /"' ."#);
        assert!(bodies.is_empty());
    }

    #[test]
    fn find_name_bash_c_embedded_in_quoted_arg_yields_zero_bodies() {
        let bodies = extract_bodies(r#"find . -name "bash -c 'rm -r -f /'""#);
        assert!(bodies.is_empty());
    }

    #[test]
    fn grep_word_bash_before_heredoc_yields_zero_bodies() {
        // `bash` here is just `grep`'s search-pattern argument, not a pipe
        // target or a direct heredoc destination — the naive
        // token-immediately-before-`<<` check this replaces would have
        // wrongly recognized it as one.
        let cmd = "grep bash <<EOF\nrm -rf /\nEOF";
        let bodies = extract_bodies(cmd);
        assert!(bodies.is_empty());
    }

    // ---- position-scoping does not regress the true-positive shapes -------

    #[test]
    fn sudo_wrapped_bash_c_still_extracts() {
        // Reusing `canonicalize::strip_wrapper_prefixes` means a wrapped
        // interpreter is still recognized as the segment's command word.
        let bodies = extract_bodies(r#"sudo bash -c "rm -r -f /""#);
        assert_eq!(texts(&bodies), vec!["rm -r -f /"]);
    }

    #[test]
    fn bare_env_assignment_wrapped_bash_c_still_extracts() {
        // Task 2 fix 3: `strip_wrapper_prefixes` now also peels a bare
        // `VAR=val` prefix (no `env` keyword) — `segment_command_word` reuses
        // that same function, so a bare-env-wrapped interpreter is resolved
        // as the segment's command word here too, exactly like the `sudo`
        // case above. Before the fix, `FOO=bar` (not a recognized
        // interpreter) was the resolved command word, so this never
        // extracted at all — the outer command was Allow.
        let bodies = extract_bodies(r#"FOO=bar bash -c "rm -r -f /""#);
        assert_eq!(texts(&bodies), vec!["rm -r -f /"]);
    }
}

// ---- script-file detection: pure-logic shape tests (no filesystem I/O) ---
//
// Content-dependent (Deny/Allow via a real temp file) and cwd-plumbing tests
// live in `engine::script_file_tests` (dedicated temp-file tests — see that
// module's own doc for why they can't be pure-string `bypass_corpus::Case`s).
// These tests pin `detect_script_exec_file`'s shape recognition itself, plus
// `resolve_script_files`'s fail-open/bounds behavior wherever it's provable
// without touching the filesystem.
#[cfg(test)]
mod script_file_shape_tests {
    use super::*;

    // ---- form 1: interpreter + file ---------------------------------------

    #[test]
    fn interpreter_plus_file_detected() {
        assert_eq!(detect_script_exec_file("bash x.sh").as_deref(), Some("x.sh"));
        assert_eq!(
            detect_script_exec_file("python3 deploy.py").as_deref(),
            Some("deploy.py")
        );
        assert_eq!(detect_script_exec_file("node build.js").as_deref(), Some("build.js"));
        assert_eq!(detect_script_exec_file("ruby run.rb").as_deref(), Some("run.rb"));
        assert_eq!(detect_script_exec_file("perl run.pl").as_deref(), Some("run.pl"));
    }

    #[test]
    fn interpreter_with_flags_before_file_detected() {
        assert_eq!(detect_script_exec_file("bash -x script.sh").as_deref(), Some("script.sh"));
    }

    // ---- value-taking interpreter flags: the flag's VALUE must not defeat
    // form-1 file detection (Task 2 fix 2) -----------------------------------

    #[test]
    fn known_value_taking_flag_skips_its_value_before_taking_file() {
        // Before the fix, each of these latched onto the flag's own value
        // token (`ignore`, `lib`, `./pre`, `lib`, `myrc`) as if it were the
        // script — the real trailing file was never resolved/scanned.
        assert_eq!(
            detect_script_exec_file("python -W ignore evil.py").as_deref(),
            Some("evil.py")
        );
        assert_eq!(
            detect_script_exec_file("python3 -X utf8 evil.py").as_deref(),
            Some("evil.py")
        );
        assert_eq!(
            detect_script_exec_file("ruby -I lib evil.rb").as_deref(),
            Some("evil.rb")
        );
        assert_eq!(
            detect_script_exec_file("node -r ./pre evil.js").as_deref(),
            Some("evil.js")
        );
        assert_eq!(
            detect_script_exec_file("perl -I lib evil.pl").as_deref(),
            Some("evil.pl")
        );
        assert_eq!(
            detect_script_exec_file("bash --rcfile myrc script.sh").as_deref(),
            Some("script.sh")
        );
    }

    #[test]
    fn equals_joined_value_flag_is_a_single_token_no_extra_skip() {
        // `--require=./pre` (an `=`-joined form) already carries its value in
        // the same token — `is_known_value_flag` must not consume an
        // additional token after it (that would wrongly skip the real file).
        assert_eq!(
            detect_script_exec_file("node --require=./pre evil.js").as_deref(),
            Some("evil.js")
        );
    }

    #[test]
    fn unrecognized_value_taking_flag_still_defeats_resolution_known_miss() {
        // SHOULD BE: Some("evil.py"). `is_known_value_flag`'s allowlist is
        // deliberately small (design brief) — a value-taking interpreter
        // flag OUTSIDE it (here a made-up `-Z`, not one of the recognized
        // python flags) still gets its value token mistaken for "the file"
        // instead of the real trailing script path. This is a documented,
        // narrower residual gap (design brief), not a silent regression —
        // pinned as an inverted canary (mirrors `bypass_corpus`'s
        // `CaseStatus::KnownMiss` convention) so a future narrowing of the
        // allowlist is a visible, deliberate graduation of THIS test, not an
        // accidental behavior change nobody notices.
        assert_eq!(
            detect_script_exec_file("python -Z something evil.py").as_deref(),
            Some("something")
        );
    }

    #[test]
    fn interpreter_inline_dash_c_is_not_file_exec_form() {
        // Belongs to `extract_inline_bodies`, not this feature — a `-c`/`-e`/
        // `--eval` flag before any file operand means "no FILE here".
        assert!(detect_script_exec_file(r#"bash -c "rm -rf /""#).is_none());
        assert!(detect_script_exec_file("node -e \"code\"").is_none());
        assert!(detect_script_exec_file("node --eval \"code\"").is_none());
    }

    #[test]
    fn non_interpreter_command_yields_none() {
        assert!(detect_script_exec_file("rm -rf ./build").is_none());
        assert!(detect_script_exec_file("cat x.sh").is_none());
        assert!(detect_script_exec_file("grep bash x.sh").is_none());
    }

    #[test]
    fn heredoc_open_token_is_never_mistaken_for_a_file_operand() {
        // `bash <<EOF` — the heredoc-open token must not be read as a file
        // argument; that shape is the sibling heredoc-body feature's job.
        assert!(detect_script_exec_file("bash <<EOF").is_none());
    }

    // ---- form 2: sourced file ----------------------------------------------

    #[test]
    fn dot_and_source_forms_detected() {
        assert_eq!(detect_script_exec_file(". x.sh").as_deref(), Some("x.sh"));
        assert_eq!(detect_script_exec_file("source x.sh").as_deref(), Some("x.sh"));
        assert_eq!(detect_script_exec_file("SOURCE x.sh").as_deref(), Some("x.sh"));
    }

    // ---- form 3: direct execution -------------------------------------------

    #[test]
    fn direct_execution_forms_detected() {
        assert_eq!(detect_script_exec_file("./x.sh").as_deref(), Some("./x.sh"));
        assert_eq!(
            detect_script_exec_file("../tools/x.sh").as_deref(),
            Some("../tools/x.sh")
        );
        assert_eq!(detect_script_exec_file("/abs/x.sh").as_deref(), Some("/abs/x.sh"));
        assert_eq!(detect_script_exec_file("dir/x.sh").as_deref(), Some("dir/x.sh"));
    }

    #[test]
    fn sudo_wrapped_direct_execution_still_detected() {
        assert_eq!(detect_script_exec_file("sudo ./x.sh").as_deref(), Some("./x.sh"));
    }

    // ---- resolve_script_files: fail-open paths provable without I/O --------

    #[test]
    fn resolve_script_files_oversized_input_yields_zero_bodies() {
        let big = "a".repeat(MAX_INPUT_LEN + 1);
        let cmd = format!("bash {big}");
        assert!(resolve_script_files(&cmd, None).is_empty());
    }

    #[test]
    fn resolve_script_files_absent_cwd_skips_relative_path() {
        // No filesystem access happens here at all: `resolve_path` returns
        // `None` before any `std::fs::read` is attempted.
        assert!(resolve_script_files("bash x.sh", None).is_empty());
    }

    #[test]
    fn resolve_script_files_nonexistent_absolute_path_yields_zero_bodies_no_panic() {
        assert!(resolve_script_files("bash /no/such/file-belay-test.sh", None).is_empty());
    }

    #[test]
    fn resolve_script_files_masked_echo_argument_never_resolves() {
        // Simulates `mask_data_regions`'s output for `echo "run bash x.sh"` —
        // masking composes for free, exactly like the inline-body feature.
        let masked = "echo                    ";
        assert!(resolve_script_files(masked, None).is_empty());
    }

    // ---- read_bounded_script: non-regular-file DoS fix (Task 2 fix 1) ------
    //
    // A FIFO or a character device (`/dev/zero`, `/dev/urandom`) is what
    // actually triggers the hang this fix closes — `std::fs::read`, and even
    // a bare `open()`, can block indefinitely on either (a FIFO's `open`
    // waits for a writer; `/dev/zero` never reaches EOF). Neither is
    // reliably constructible from a portable `#[test]` without shelling out
    // or adding a POSIX-specific dependency, so a directory is used instead
    // — the design brief calls this out explicitly as "a portable proxy":
    // `std::fs::metadata` (which every one of these non-regular-file shapes
    // shares) reports `is_file() == false` for a directory exactly the same
    // way it does for a FIFO or a char device, so this test exercises the
    // very same `!meta.is_file()` rejection branch the fix added, without
    // needing the more exotic file type to prove it takes effect.

    #[test]
    fn read_bounded_script_rejects_directory_fast_no_hang() {
        let tmp = tempfile::tempdir().unwrap();
        let start = std::time::Instant::now();
        let result = read_bounded_script(tmp.path());
        let elapsed = start.elapsed();
        assert!(result.is_none(), "a directory is not a regular file and must yield no body");
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "read_bounded_script must reject a non-regular file via stat \
             before ever attempting a blocking read/open (took {elapsed:?})"
        );
    }

    #[test]
    fn resolve_script_files_directory_target_fast_no_hang() {
        // Same proof one layer up: the full `resolve_script_files` entry
        // point (detect -> resolve_path -> read_bounded_script) must also
        // return promptly and empty-handed for a script-exec shape whose
        // resolved path is a directory.
        let tmp = tempfile::tempdir().unwrap();
        let cmd = format!("bash {}", tmp.path().display());
        let start = std::time::Instant::now();
        let bodies = resolve_script_files(&cmd, None);
        let elapsed = start.elapsed();
        assert!(bodies.is_empty(), "a directory target must contribute no body");
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "resolve_script_files must never hang on a non-regular-file target (took {elapsed:?})"
        );
    }
}
