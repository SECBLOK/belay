//! Per-sweep history for the agent surface.
//!
//! The existing sweep path records POSITIVES ONLY: `watch::write_skill_audit_row`
//! appends to the audit log when something is detected or drifts, and a skill
//! that is examined and found clean writes nothing at all. That makes an
//! unreadable directory produce byte-identical output to a clean one, which is
//! exactly where a rug-pull hides, and it means no finding can honestly be
//! called resolved: it might be fixed, or it might have stopped being checked.
//!
//! This module records what a sweep EXAMINED and what it could not reach. It
//! decides nothing: verdicts come from the existing gate and judge paths, so it
//! adds no security logic and cannot change a deny outcome.

use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Why an item could not be examined. A CLOSED enum, not free text, so
/// coverage can be counted and asserted on rather than grepped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    PermissionDenied,
    NotFound,
    Unreadable,
    ParseError,
    TooLarge,
    SymlinkLoop,
    RootMissing,
}

impl SkipReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            SkipReason::PermissionDenied => "permission_denied",
            SkipReason::NotFound => "not_found",
            SkipReason::Unreadable => "unreadable",
            SkipReason::ParseError => "parse_error",
            SkipReason::TooLarge => "too_large",
            SkipReason::SymlinkLoop => "symlink_loop",
            SkipReason::RootMissing => "root_missing",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Skill,
    McpConfig,
    Plugin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Clean,
    Flagged,
    Quarantined,
}

/// One item the sweep actually looked at. `content_hash` keys identity to
/// CONTENT, not path, so a modified skill cannot look unchanged by keeping its
/// path and mtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Examined {
    pub kind: ItemKind,
    pub agent: String,
    pub name: String,
    pub path: String,
    pub content_hash: String,
    pub verdict: Verdict,
    #[serde(default)]
    pub rule_ids: Vec<String>,
}

/// One item the sweep could NOT look at. This is the field that makes
/// "unknown" honest instead of decorative.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skipped {
    pub kind: ItemKind,
    pub agent: String,
    pub path: String,
    pub reason: SkipReason,
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SweepRecord {
    pub sweep_id: String,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    /// One of: install_gate, watch, periodic, manual.
    ///
    /// A `String`, not `&'static str`: serde can serialize a `&'static str`
    /// but cannot deserialize into one (there is nothing for it to borrow
    /// from), and this type derives `Deserialize` to support the read path.
    /// Callers pass e.g. `"periodic".to_string()`.
    pub trigger: String,
    #[serde(default)]
    pub examined: Vec<Examined>,
    #[serde(default)]
    pub skipped: Vec<Skipped>,
}

/// Milliseconds since the Unix epoch, saturating to 0 if the clock is before it.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A sweep id that is unique, sortable and needs no new dependency. The epoch
/// millisecond of the sweep start, plus a process-local counter so two sweeps
/// starting in the same millisecond cannot collide.
pub fn next_sweep_id(started_at_ms: u64) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{started_at_ms:013}-{n:04}")
}

pub fn sweeps_path() -> PathBuf {
    crate::paths::data_dir().join("sweeps.ndjson")
}

/// Append one record. FAIL-SOFT by design: a history line is not worth taking
/// down the sweep that produced it, matching `watch::write_skill_audit_row`.
pub fn append(rec: &SweepRecord) {
    append_to(&sweeps_path(), rec);
}

/// Append one line. `belay sweep-now` (in-process in the CLI, see
/// `watch::run_recording_with_trigger`) and the daemon's own periodic loop
/// can both call this against the SAME file, so a single append here must be
/// ONE `write(2)` syscall, not two. `writeln!(f, "{line}")` on a `File` is
/// `Write::write_str(line)` followed by a SEPARATE `write_str("\n")` -- two
/// syscalls even though `line` is already a fully pre-serialized `String` --
/// which leaves a gap for another O_APPEND writer's own record to land
/// between the content and its trailing newline, merging two lines into one
/// unparseable line (proved by
/// `tests::concurrent_appends_from_many_threads_never_corrupt_a_line`, which
/// reliably corrupted rows under the old two-write version). Building the
/// complete content+newline into one `String` first and writing it with a
/// single `write_all` makes the append one syscall, and a single O_APPEND
/// write to a local regular file is atomic with respect to other O_APPEND
/// writers on Linux -- mirrors the identical fix already applied to
/// `AuditWriter::append` (see its comment) for the same reason. That
/// atomicity guarantee is argued for Linux specifically; this function is
/// not gated to it (the periodic-loop thread spawn in `app.rs` is
/// unconditional and `enumerate.rs` carries `#[cfg(windows)]` root paths),
/// so it also runs on Windows and potentially against network filesystems,
/// where the single-syscall-is-atomic argument is not established. That is
/// not a regression: one `write_all` is never worse than the old two-write
/// version on any platform, so this change is strictly an improvement
/// everywhere even where full atomicity is not guaranteed. No file lock
/// added: the race being closed here is this function doing two writes, not
/// the OS failing to serialize one.
pub(crate) fn append_to(path: &Path, rec: &SweepRecord) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut line = match serde_json::to_string(rec) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[belayd] sweep record serialize failed: {e}");
            return;
        }
    };
    line.push('\n');
    match std::fs::OpenOptions::new().create(true).append(true).open(path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(line.as_bytes()) {
                eprintln!("[belayd] sweep history append failed ({}): {e}", path.display());
            }
        }
        Err(e) => eprintln!("[belayd] sweep history open failed ({}): {e}", path.display()),
    }
}

/// Read every record. Returns the parsed records and the number of lines that
/// could not be parsed. A truncated line (power loss mid-append) must not make
/// the whole history unreadable, and it must be REPORTED rather than hidden.
pub fn read_all_from(path: &Path) -> (Vec<SweepRecord>, usize) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return (Vec::new(), 0);
    };
    let mut out = Vec::new();
    let mut bad = 0usize;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<SweepRecord>(line) {
            Ok(r) => out.push(r),
            Err(_) => bad += 1,
        }
    }
    (out, bad)
}

pub fn read_all() -> (Vec<SweepRecord>, usize) {
    read_all_from(&sweeps_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str) -> SweepRecord {
        SweepRecord {
            sweep_id: id.to_string(),
            started_at_ms: 1_000,
            finished_at_ms: 1_500,
            trigger: "periodic".to_string(),
            examined: vec![Examined {
                kind: ItemKind::Skill,
                agent: "claude".into(),
                name: "pdf-tools".into(),
                path: "/h/.claude/skills/pdf-tools/SKILL.md".into(),
                content_hash: "00000000deadbeef".into(),
                verdict: Verdict::Clean,
                rule_ids: vec![],
            }],
            skipped: vec![Skipped {
                kind: ItemKind::Skill,
                agent: "codex".into(),
                path: "/h/.codex/skills/x".into(),
                reason: SkipReason::PermissionDenied,
                detail: "opening SKILL.md: EACCES".into(),
            }],
        }
    }

    /// A record must survive a write/read round trip with every field intact.
    /// The skipped-list is the load-bearing part: if it is lost, "resolved"
    /// and "never looked" become indistinguishable again.
    #[test]
    fn a_record_round_trips_through_ndjson() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sweeps.ndjson");
        append_to(&path, &rec("s1"));
        append_to(&path, &rec("s2"));

        let (out, bad) = read_all_from(&path);
        assert_eq!(bad, 0, "no line should fail to parse");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].sweep_id, "s1");
        assert_eq!(out[1].sweep_id, "s2");
        assert_eq!(out[0].examined[0].content_hash, "00000000deadbeef");
        assert_eq!(out[0].skipped[0].reason.as_str(), "permission_denied");
        assert_eq!(out[0].skipped[0].detail, "opening SKILL.md: EACCES");
    }

    /// An unparseable line must be COUNTED and skipped, never silently dropped
    /// and never fatal. A truncated write (power loss mid-append) must not make
    /// the whole history unreadable.
    #[test]
    fn a_corrupt_line_is_counted_and_the_rest_still_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sweeps.ndjson");
        append_to(&path, &rec("good1"));
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .map(|mut f| {
                use std::io::Write as _;
                let _ = f.write_all(b"{\"sweep_id\": truncated\n");
            })
            .unwrap();
        append_to(&path, &rec("good2"));

        let (out, bad) = read_all_from(&path);
        assert_eq!(bad, 1, "the corrupt line must be counted, not hidden");
        assert_eq!(out.len(), 2, "the good lines must still parse");
    }

    /// Appending must never panic, even when the target is unwritable. Losing a
    /// history line must not take down the sweep that produced it.
    #[test]
    fn appending_to_an_unwritable_path_does_not_panic() {
        let path = std::path::Path::new("/proc/definitely/not/writable/sweeps.ndjson");
        append_to(path, &rec("s1"));
    }

    /// A missing file is an empty history, not an error.
    #[test]
    fn a_missing_history_file_reads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let (out, bad) = read_all_from(&dir.path().join("nope.ndjson"));
        assert!(out.is_empty());
        assert_eq!(bad, 0);
    }

    /// `belay sweep-now` runs in-process in the CLI, so a sweep it triggers can
    /// land at the exact moment the daemon's own periodic loop is mid-append to
    /// the SAME `sweeps.ndjson` (see `watch::run_recording_with_trigger`'s
    /// doc comment). Mirrors `audit::tests::concurrent_appends_from_many_threads_never_corrupt_a_row`,
    /// same technique (a `Barrier` maximizes the odds every thread's write
    /// overlaps) and the same underlying bug class: a multi-syscall append
    /// (`writeln!(f, "{line}")` is `write_str(line)` THEN `write_str("\n")` --
    /// two separate `write(2)` calls even though `line` is already a single
    /// pre-serialized `String`) lets one thread's newline land after another
    /// thread's next record starts, merging two lines into one unparseable
    /// line and leaving a stray blank line behind. A single `write_all` of the
    /// complete pre-formatted line (content + newline, ONE syscall) closes the
    /// gap the same way `AuditWriter::append` already had to.
    #[test]
    fn concurrent_appends_from_many_threads_never_corrupt_a_line() {
        let dir = std::env::temp_dir().join(format!("sweep-concurrent-{}.ndjson", std::process::id()));
        let p = dir.clone();
        let _ = std::fs::remove_file(&p);

        const N: usize = 64;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let p = p.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    // Padding widens the record so the write itself takes
                    // measurably longer to copy into the kernel, widening the
                    // window between the two `write_str` calls the old
                    // `writeln!` made per append -- the same reasoning as the
                    // audit-log test's padding comment.
                    let mut r = rec(&i.to_string());
                    r.examined[0].path = "x".repeat(400);
                    barrier.wait(); // maximize the odds every thread's write overlaps
                    append_to(&p, &r);
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let content = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        let mut seen = std::collections::HashSet::new();
        for line in &lines {
            let v: SweepRecord = serde_json::from_str(line).unwrap_or_else(|e| {
                panic!("line failed to parse as a SweepRecord (corrupted by a concurrent append): {e}\nline: {line}")
            });
            seen.insert(v.sweep_id);
        }
        assert_eq!(
            lines.len(),
            N,
            "expected exactly {N} lines, got {} -- some appends were merged or lost",
            lines.len()
        );
        assert_eq!(seen.len(), N, "every sweep_id must appear exactly once");
        let _ = std::fs::remove_file(&p);
    }
}
