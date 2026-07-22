//! Process-ancestry primitives for the GateGuard self-approval detector.
//!
//! The threat: the gated AI agent runs as the OWNER uid, so it passes the
//! control socket's `peer_uid == owner` check like any legitimate local
//! caller — nothing at the transport layer distinguishes "the human operator"
//! from "the agent, calling the resolve IPC on itself". Process ancestry is
//! the only signal available to tell them apart: a genuine human's resolving
//! process (desktop GUI, CLI) is never a descendant of the agent process that
//! asked the question, whereas an agent resolving its own parked ASK (directly
//! or via a spawned helper) always is.
//!
//! ## Fail-open, deliberately
//!
//! Every function here returns `Option` so the caller can distinguish a
//! confidently-determined answer from "couldn't tell". [`is_ancestor_of`]
//! returns `Some(true)` ONLY when the walk positively proves the lineage;
//! every other outcome — no match, a `/proc` read failing partway, running on
//! a platform with no `/proc` — is `Some(false)` or `None`, and BOTH must be
//! treated identically by callers: "not proven self-approval, do not block".
//! The one and only path a caller should treat as "this IS a self-approval"
//! is an explicit `Some(true)`.
// Only the Linux `/proc` reader uses std::fs; gating it keeps non-Linux builds
// warning-clean.
#[cfg(target_os = "linux")]
use std::fs;

/// Hard bound on how many parent hops [`is_ancestor_of`] will walk before
/// giving up. Real process trees (agent -> hook/mcp child -> ... -> resolver)
/// are only a few levels deep; 64 is generous headroom while still making a
/// pathological/cyclic `/proc` state (or a malicious peer trying to stall the
/// resolve path) terminate quickly rather than loop.
const MAX_ANCESTRY_HOPS: u32 = 64;

/// Parse the parent pid out of the raw contents of `/proc/<pid>/stat`.
///
/// The format is `pid (comm) state ppid ...` — but `comm` (the executable
/// basename, field 2) can itself contain spaces AND parentheses (e.g. a
/// process renamed via `prctl(PR_SET_NAME, ...)` to something adversarial),
/// so naively splitting on whitespace or the FIRST `)` misparses. The kernel
/// guarantees `comm` never contains a `)` followed by  " <state-char> " by
/// construction... except it doesn't guarantee that either in the general
/// case, so the robust parse is: find the LAST `)` in the line (that's the
/// unambiguous end of the comm field, since state/ppid/... — the numeric
/// fields — never contain parens), then take the 1st whitespace token after
/// it (the state char) and the 2nd (the ppid).
pub fn parse_ppid_from_stat(s: &str) -> Option<u32> {
    let close = s.rfind(')')?;
    let rest = s.get(close + 1..)?;
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?; // field 3: state char — skipped
    let ppid = fields.next()?; // field 4: ppid
    ppid.parse::<u32>().ok()
}

/// The parent pid of `pid`, or `None` if it cannot be determined (process
/// gone, unreadable, or — on every non-Linux target — simply unsupported).
#[cfg(target_os = "linux")]
pub fn parent_pid(pid: u32) -> Option<u32> {
    let contents = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_ppid_from_stat(&contents)
}

/// Windows: walk the Toolhelp process snapshot for `pid`'s parent.
///
/// Toolhelp is used rather than `NtQueryInformationProcess` because it needs no
/// process handle and therefore no extra privilege - the guard must work for an
/// unprivileged desktop app. `th32ParentProcessID` can name a pid that has since
/// exited and been recycled; that is acceptable here because the caller treats
/// ancestry as advisory and fails OPEN on anything inconclusive.
#[cfg(target_os = "windows")]
pub fn parent_pid(pid: u32) -> Option<u32> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut found = None;
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                if entry.th32ProcessID == pid {
                    found = Some(entry.th32ParentProcessID);
                    break;
                }
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
        // 0 is not a usable parent: treat it as unknown so the guard fails open
        // rather than matching every process through a bogus ancestor.
        found.filter(|p| *p > 0)
    }
}

/// macOS and anything else: no supported lookup, so ancestry is always
/// inconclusive. Callers fail open on `None`, so the guard simply never
/// engages there.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn parent_pid(_pid: u32) -> Option<u32> {
    None
}

/// Does `ancestor` sit somewhere in `pid`'s parent chain?
///
/// - `Some(true)` — positively proven: `ancestor` was found while walking up
///   from `pid`. This is the ONLY case a caller may treat as self-approval.
/// - `Some(false)` — the walk completed (reached a pid `<= 1`, or exhausted
///   the hop bound) without ever finding `ancestor`.
/// - `None` — inconclusive: a `/proc` read failed partway through the walk
///   (process exited mid-walk, permission denied, etc).
///
/// `ancestor <= 1` (pid 0/1 — kernel/init) is never treated as a match: an
/// unresolved/unknown gating pid must never accidentally "match" every
/// process on the system via init.
pub fn is_ancestor_of(ancestor: u32, pid: u32) -> Option<bool> {
    walk_ancestry(ancestor, pid, parent_pid)
}

/// The walk behind [`is_ancestor_of`], generic over the parent-lookup
/// function so it can be exercised deterministically in tests against a
/// synthetic chain instead of the real `/proc`.
fn walk_ancestry(ancestor: u32, pid: u32, lookup: impl Fn(u32) -> Option<u32>) -> Option<bool> {
    if ancestor <= 1 {
        return Some(false);
    }
    // A process is never its OWN ancestor, and that answer needs no walk. Two
    // reasons to settle it up front rather than walking:
    //   1. Linux chains terminate at init (pid 1) so the walk happens to return
    //      Some(false), but Windows does NOT reparent orphans - the chain often
    //      ends at a parent that has already exited and is no longer in the
    //      Toolhelp snapshot, so the walk returns an inconclusive None for a
    //      question that has a definite answer.
    //   2. Windows recycles pids, so a long walk could coincidentally meet this
    //      pid's number again and report a bogus Some(true).
    // This is NOT the self-approval check: "the resolver IS the gated agent" is
    // caught by respond_local's equality arm (see its test), which is precisely
    // why ancestry is expected to answer Some(false) here.
    if ancestor == pid {
        return Some(false);
    }
    let mut current = pid;
    for _ in 0..MAX_ANCESTRY_HOPS {
        if current <= 1 {
            return Some(false);
        }
        match lookup(current) {
            Some(parent) => {
                if parent == ancestor {
                    return Some(true);
                }
                current = parent;
            }
            None => return None, // read failed mid-walk — inconclusive, fail open
        }
    }
    // Bound exhausted without reaching <=1 or a match: treat as "not found"
    // rather than "inconclusive" — we got clean answers the whole way, we
    // just stopped looking. Fails open either way (both are non-blocking).
    Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn parse_ppid_handles_comm_with_spaces_and_parens() {
        // `comm` here is `weird )name` — contains both a space and a stray
        // `)` — the LAST `)` in the line is still the true end of the field.
        assert_eq!(
            parse_ppid_from_stat("1234 (weird )name) S 987 6 5 4 3 2"),
            Some(987)
        );
    }

    #[test]
    fn parse_ppid_handles_the_common_case() {
        assert_eq!(parse_ppid_from_stat("42 (bash) S 1 42 42 0 -1"), Some(1));
    }

    #[test]
    fn parse_ppid_rejects_garbage() {
        assert_eq!(parse_ppid_from_stat(""), None);
        assert_eq!(parse_ppid_from_stat("no parens here at all"), None);
        assert_eq!(parse_ppid_from_stat("1234 (ok) S notanumber"), None);
        assert_eq!(parse_ppid_from_stat("1234 (ok) S"), None); // no ppid field
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parent_pid_of_self_is_some() {
        assert!(parent_pid(std::process::id()).is_some());
    }

    /// Platforms with no supported ancestry lookup must stay inconclusive so the
    /// guard fails OPEN there. Windows is no longer one of them (it resolves
    /// parents via a Toolhelp snapshot), so the scope matches the stub's own cfg.
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    #[test]
    fn parent_pid_is_none_where_ancestry_is_unsupported() {
        assert_eq!(parent_pid(std::process::id()), None);
    }

    #[test]
    fn ancestor_zero_or_one_never_matches() {
        // Never treat kernel(0)/init(1) as "the agent" — even walking our
        // own live process, which genuinely descends from init, must not
        // report a match.
        assert_eq!(is_ancestor_of(0, std::process::id()), Some(false));
        assert_eq!(is_ancestor_of(1, std::process::id()), Some(false));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_child_process_is_detected_as_a_descendant() {
        let mut child = std::process::Command::new("sleep")
            .arg("2")
            .spawn()
            .expect("spawn sleep");
        let child_pid = child.id();
        // This test process is the direct (real, kernel-verified) parent of
        // `child` — proves the /proc walk works end-to-end, not just against
        // a synthetic chain.
        assert_eq!(is_ancestor_of(std::process::id(), child_pid), Some(true));
        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unrelated_real_process_is_not_a_descendant() {
        // pid 1 (init) is never a descendant of our own test process.
        assert_eq!(is_ancestor_of(std::process::id(), 1), Some(false));
    }

    #[test]
    fn walk_ancestry_finds_match_via_injected_lookup() {
        // Synthetic chain: 50 -> 40 -> 30 -> 20 -> 10 -> 1
        let mut chain: HashMap<u32, u32> = HashMap::new();
        chain.insert(50, 40);
        chain.insert(40, 30);
        chain.insert(30, 20);
        chain.insert(20, 10);
        chain.insert(10, 1);
        assert_eq!(
            walk_ancestry(20, 50, move |p| chain.get(&p).copied()),
            Some(true)
        );
    }

    #[test]
    fn walk_ancestry_completes_clean_without_a_match() {
        let mut chain: HashMap<u32, u32> = HashMap::new();
        chain.insert(50, 40);
        chain.insert(40, 1);
        assert_eq!(
            walk_ancestry(999, 50, move |p| chain.get(&p).copied()),
            Some(false)
        );
    }

    #[test]
    fn walk_ancestry_is_inconclusive_when_a_read_fails_partway() {
        // Lookup succeeds once (50 -> 40) then fails (simulates a `/proc`
        // read that fails once the process has exited mid-walk).
        let lookup = |p: u32| if p == 50 { Some(40) } else { None };
        assert_eq!(walk_ancestry(999, 50, lookup), None);
    }

    #[test]
    fn walk_ancestry_bound_stops_before_a_match_beyond_the_hop_limit() {
        // A long, non-cyclic chain (never dips to <=1 within range) so the
        // ONLY thing that can stop the walk is the hop bound itself.
        let start = 10_300u32;
        let mut chain: HashMap<u32, u32> = HashMap::new();
        for p in (10_001..=start).rev() {
            chain.insert(p, p - 1);
        }
        let far_ancestor = start - 100; // 100 hops away — beyond the 64-hop bound
        let near_ancestor = start - 10; // 10 hops away — well within the bound

        let c1 = chain.clone();
        assert_eq!(
            walk_ancestry(far_ancestor, start, move |p| c1.get(&p).copied()),
            Some(false),
            "a match beyond the hop bound must not be found (proves it's bounded, not just correct)"
        );
        let c2 = chain.clone();
        assert_eq!(
            walk_ancestry(near_ancestor, start, move |p| c2.get(&p).copied()),
            Some(true),
            "sanity check: a match well within the bound must still be found"
        );
    }

    /// On Windows the guard was entirely inert because `parent_pid` always
    /// returned None, so `gating_pid` was never known and self-approval could
    /// never be detected. This proves the platform can now resolve a parent.
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_resolves_a_real_parent_pid() {
        let me = std::process::id();
        let parent = parent_pid(me);
        assert!(parent.is_some(), "parent of this process must be resolvable");
        assert_ne!(parent, Some(me), "a process is not its own parent");
        assert_ne!(parent, Some(0), "pid 0 is not a usable parent");
    }

    /// A spawned child's parent must be this process - the exact relationship
    /// the self-approval guard depends on.
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_child_reports_this_process_as_parent() {
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "ping -n 3 127.0.0.1 > NUL"])
            .spawn()
            .expect("spawn child");
        let got = parent_pid(child.id());
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(got, Some(std::process::id()));
    }
}
