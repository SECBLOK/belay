//! Pure-Rust host/installer environment detection.
//!
//! Patterns adapted (not copied) from CrowdStrike `falcon-installer` (MIT): the
//! installer detects the OS family and package manager and waits out an active
//! package-manager lock before touching the system. Belay follows the
//! **pure-Rust, no-shell-out** directive — everything here is file reads and
//! path-existence checks; we never `exec` `apt`/`dnf`/`lsb_release`/`getcap`.
//!
//! The detection results are advisory (used to phrase setup guidance and to
//! pre-check privileges before a kernel round-trip); they never gate safety
//! behaviour, so a false negative is harmless.

/// Parsed subset of `/etc/os-release`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OsInfo {
    /// The `ID=` field, lower-cased (e.g. `debian`, `ubuntu`, `fedora`, `arch`).
    pub id: String,
    /// The `VERSION_ID=` field, unquoted (e.g. `12`, `24.04`). May be empty
    /// (rolling distros such as Arch omit it).
    pub version_id: String,
    /// The `ID_LIKE=` field, lower-cased, space-separated families (e.g.
    /// "debian", "ubuntu debian"). Empty when absent.
    pub id_like: String,
    /// The `VERSION_CODENAME=` field, lower-cased (e.g. "noble", "bookworm",
    /// "kali-rolling"). Empty when absent.
    pub version_codename: String,
}

/// A supported system package manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkgManager {
    Apt,
    Dnf,
    Yum,
    Zypper,
    Pacman,
    Apk,
}

impl PkgManager {
    /// The canonical binary path checked for presence (no `exec`).
    fn probe_path(self) -> &'static str {
        match self {
            PkgManager::Apt => "/usr/bin/apt-get",
            PkgManager::Dnf => "/usr/bin/dnf",
            PkgManager::Yum => "/usr/bin/yum",
            PkgManager::Zypper => "/usr/bin/zypper",
            PkgManager::Pacman => "/usr/bin/pacman",
            PkgManager::Apk => "/sbin/apk",
        }
    }

    /// Human-readable name, for setup guidance messages.
    pub fn name(self) -> &'static str {
        match self {
            PkgManager::Apt => "apt",
            PkgManager::Dnf => "dnf",
            PkgManager::Yum => "yum",
            PkgManager::Zypper => "zypper",
            PkgManager::Pacman => "pacman",
            PkgManager::Apk => "apk",
        }
    }
}

/// Strip one layer of matching single/double quotes from an os-release value.
fn unquote(s: &str) -> &str {
    let s = s.trim();
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let (first, last) = (bytes[0], bytes[bytes.len() - 1]);
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &s[1..s.len() - 1];
        }
    }
    s
}

/// Parse the contents of an `/etc/os-release` file.
///
/// Only `ID` and `VERSION_ID` are extracted; unknown keys and comment/blank
/// lines are ignored. `ID` is lower-cased (the spec says it is already
/// lowercase, but we normalise defensively).
pub fn detect_os(release: &str) -> OsInfo {
    let mut info = OsInfo::default();
    for line in release.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "ID" => info.id = unquote(value).to_ascii_lowercase(),
            "VERSION_ID" => info.version_id = unquote(value).to_string(),
            "ID_LIKE" => info.id_like = unquote(value).to_ascii_lowercase(),
            "VERSION_CODENAME" => info.version_codename = unquote(value).to_ascii_lowercase(),
            _ => {}
        }
    }
    info
}

/// Detection order: prefer the modern manager when several are present
/// (dnf over yum, apt before rpm-family on hybrid systems). Returns the first
/// candidate whose probe path satisfies `exists`.
const PKG_MANAGER_ORDER: [PkgManager; 6] = [
    PkgManager::Apt,
    PkgManager::Dnf,
    PkgManager::Yum,
    PkgManager::Zypper,
    PkgManager::Pacman,
    PkgManager::Apk,
];

/// Core, testable package-manager detection: returns the first manager in
/// [`PKG_MANAGER_ORDER`] whose probe path satisfies `exists`.
fn detect_pkg_manager_with(exists: impl Fn(&str) -> bool) -> Option<PkgManager> {
    PKG_MANAGER_ORDER
        .iter()
        .copied()
        .find(|pm| exists(pm.probe_path()))
}

/// Detect the host package manager by binary presence (no `exec`).
pub fn detect_pkg_manager() -> Option<PkgManager> {
    detect_pkg_manager_with(|p| std::path::Path::new(p).exists())
}

// ──────────────────────────────────────────────────────────────────────────────
// CAP_NET_ADMIN pre-check (reads /proc/self/status — no `getcap`/`capsh`)
// ──────────────────────────────────────────────────────────────────────────────

/// Linux capability bit for `CAP_NET_ADMIN` (see `linux/capability.h`).
const CAP_NET_ADMIN_BIT: u32 = 12;

/// Extract the hex value following the `CapEff:` line in a `/proc/<pid>/status`
/// blob. Returns `None` if the line is absent or unparseable.
fn parse_cap_eff(status: &str) -> Option<u64> {
    let line = status.lines().find_map(|l| l.trim().strip_prefix("CapEff:"))?;
    u64::from_str_radix(line.trim(), 16).ok()
}

/// Does the given effective-capability bitmask include `CAP_NET_ADMIN`?
fn cap_eff_has_net_admin(cap_eff: u64) -> bool {
    cap_eff & (1u64 << CAP_NET_ADMIN_BIT) != 0
}

/// Tri-state CAP_NET_ADMIN check parsed from a `/proc/<pid>/status` blob.
/// `Some(true)`/`Some(false)` = definitive; `None` = could not determine.
fn cap_net_admin_status_from(status: &str) -> Option<bool> {
    parse_cap_eff(status).map(cap_eff_has_net_admin)
}

/// Whether the current process holds `CAP_NET_ADMIN`, as a tri-state.
///
/// `None` means we could not read/parse `/proc/self/status` — callers should
/// treat that as "unknown" and NOT pre-fail on it (avoids a false negative
/// blocking a legitimately-privileged daemon).
pub fn cap_net_admin_status() -> Option<bool> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    cap_net_admin_status_from(&status)
}

/// Convenience boolean form of [`cap_net_admin_status`] (unknown → `false`).
pub fn has_cap_net_admin() -> bool {
    cap_net_admin_status().unwrap_or(false)
}

// ──────────────────────────────────────────────────────────────────────────────
// Package-manager lock detection (falcon-installer pattern, pure file checks)
// ──────────────────────────────────────────────────────────────────────────────

/// How a package manager signals an in-progress operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockKind {
    /// `flock(2)`-style lock: the file always exists; busy ⇔ another process
    /// holds an exclusive advisory lock on it (dpkg, apt, rpm/dnf).
    Flock,
    /// Presence lock: the file's mere existence means an operation is running
    /// (pacman's `db.lck`).
    Presence,
}

/// Known package-manager lock files and how to interpret them.
const PKG_LOCK_FILES: &[(&str, LockKind)] = &[
    ("/var/lib/dpkg/lock-frontend", LockKind::Flock),
    ("/var/lib/dpkg/lock", LockKind::Flock),
    ("/var/lib/apt/lists/lock", LockKind::Flock),
    ("/var/lib/rpm/.rpm.lock", LockKind::Flock),
    ("/var/cache/dnf/metadata_lock.pid", LockKind::Flock),
    ("/var/lib/pacman/db.lck", LockKind::Presence),
];

/// Core, testable lock aggregation.
///
/// `present(path)` reports whether the lock file exists. `flock_busy(path)`
/// reports, for a flock-style lock, whether another process holds it:
/// `Some(true)` busy, `Some(false)` free, `None` undeterminable (e.g. the
/// daemon lacks permission to open the file → we do NOT treat that as busy).
fn pkg_manager_busy_with(
    present: impl Fn(&str) -> bool,
    flock_busy: impl Fn(&str) -> Option<bool>,
) -> bool {
    PKG_LOCK_FILES.iter().any(|&(path, kind)| match kind {
        LockKind::Presence => present(path),
        LockKind::Flock => present(path) && flock_busy(path) == Some(true),
    })
}

/// Try to determine whether a flock-style lock file is currently held by
/// another process, without blocking and without any `exec`.
///
/// Opens the file read-only and attempts a non-blocking exclusive `flock`. If
/// the attempt would block, the lock is held (`Some(true)`); if it succeeds we
/// immediately release and report free (`Some(false)`); if the file cannot be
/// opened we cannot tell (`None`).
#[cfg(unix)]
fn flock_held(path: &str) -> Option<bool> {
    use std::os::fd::AsRawFd;
    extern "C" {
        fn flock(fd: i32, operation: i32) -> i32;
    }
    const LOCK_EX: i32 = 2;
    const LOCK_UN: i32 = 8;
    const LOCK_NB: i32 = 4;

    let file = std::fs::File::open(path).ok()?;
    let fd = file.as_raw_fd();
    // SAFETY: fd is a valid open descriptor owned by `file` for this call.
    let rc = unsafe { flock(fd, LOCK_EX | LOCK_NB) };
    if rc == 0 {
        // We acquired it → nobody else held it. Release immediately.
        // SAFETY: same valid fd; unlocking our own advisory lock.
        unsafe { flock(fd, LOCK_UN) };
        Some(false)
    } else {
        match std::io::Error::last_os_error().raw_os_error() {
            // EWOULDBLOCK (11) / EAGAIN → held by another process.
            Some(11) => Some(true),
            _ => None,
        }
    }
}

/// Stub: no POSIX flock on Windows — lock files are never flock-held.
#[cfg(not(unix))]
fn flock_held(_path: &str) -> Option<bool> {
    None
}

/// Whether a system package manager appears to be mid-operation.
pub fn pkg_manager_busy() -> bool {
    pkg_manager_busy_with(|p| std::path::Path::new(p).exists(), flock_held)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_debian_os_release() {
        let release = "\
PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"
NAME=\"Debian GNU/Linux\"
VERSION_ID=\"12\"
VERSION=\"12 (bookworm)\"
ID=debian
HOME_URL=\"https://www.debian.org/\"";
        let info = detect_os(release);
        assert_eq!(info.id, "debian");
        assert_eq!(info.version_id, "12");
    }

    #[test]
    fn parses_id_like_and_codename() {
        let info = detect_os("ID=kali\nID_LIKE=debian\nVERSION_ID=\"2024.4\"\nVERSION_CODENAME=kali-rolling\n");
        assert_eq!(info.id, "kali");
        assert_eq!(info.id_like, "debian");
        assert_eq!(info.version_codename, "kali-rolling");
        // Ubuntu carries its codename too.
        let u = detect_os("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n");
        assert_eq!(u.id_like, "debian");
        assert_eq!(u.version_codename, "noble");
    }

    #[test]
    fn parses_ubuntu_and_unquotes() {
        let info = detect_os("ID=ubuntu\nVERSION_ID=\"24.04\"\n");
        assert_eq!(info.id, "ubuntu");
        assert_eq!(info.version_id, "24.04");
    }

    #[test]
    fn rolling_distro_without_version_id() {
        let info = detect_os("ID=arch\n# no VERSION_ID on a rolling release\n");
        assert_eq!(info.id, "arch");
        assert_eq!(info.version_id, "");
    }

    #[test]
    fn ignores_blank_comment_and_malformed_lines() {
        let info = detect_os("\n# comment\nnonsense-without-equals\nID=fedora\nVERSION_ID=40\n");
        assert_eq!(info.id, "fedora");
        assert_eq!(info.version_id, "40");
    }

    #[test]
    fn pkg_manager_detection_returns_first_present() {
        // Only dnf + yum present → dnf wins (earlier in order).
        let pm = detect_pkg_manager_with(|p| p == "/usr/bin/dnf" || p == "/usr/bin/yum");
        assert_eq!(pm, Some(PkgManager::Dnf));

        // Only apt present.
        let pm = detect_pkg_manager_with(|p| p == "/usr/bin/apt-get");
        assert_eq!(pm, Some(PkgManager::Apt));

        // None present.
        assert_eq!(detect_pkg_manager_with(|_| false), None);
    }

    #[test]
    fn cap_eff_net_admin_bit() {
        // CAP_NET_ADMIN is bit 12 → 0x1000.
        assert!(cap_eff_has_net_admin(0x1000));
        // Full capability set obviously includes it.
        assert!(cap_eff_has_net_admin(0x0000_03ff_ffff_ffff));
        // Empty / unrelated bits do not.
        assert!(!cap_eff_has_net_admin(0x0));
        assert!(!cap_eff_has_net_admin(0x0fff)); // bits 0..=11 only
    }

    #[test]
    fn parses_cap_eff_from_status_blob() {
        let status = "Name:\tdaemon\nUid:\t0\t0\t0\t0\nCapEff:\t0000000000001000\nSeccomp:\t0\n";
        assert_eq!(cap_net_admin_status_from(status), Some(true));

        let none_set = "Name:\tdaemon\nCapEff:\t0000000000000000\n";
        assert_eq!(cap_net_admin_status_from(none_set), Some(false));

        // Missing the line entirely → undeterminable.
        assert_eq!(cap_net_admin_status_from("Name:\tdaemon\n"), None);
    }

    #[test]
    fn pacman_presence_lock_means_busy() {
        // pacman db.lck present → busy regardless of flock.
        let busy = pkg_manager_busy_with(
            |p| p == "/var/lib/pacman/db.lck",
            |_| None,
        );
        assert!(busy);
    }

    #[test]
    fn dpkg_flock_busy_only_when_held() {
        // dpkg lock present AND held by another proc → busy.
        let held = pkg_manager_busy_with(
            |p| p == "/var/lib/dpkg/lock-frontend",
            |_| Some(true),
        );
        assert!(held);

        // dpkg lock present but free → not busy.
        let free = pkg_manager_busy_with(
            |p| p == "/var/lib/dpkg/lock-frontend",
            |_| Some(false),
        );
        assert!(!free);

        // Present but undeterminable (can't open) → NOT treated as busy.
        let unknown = pkg_manager_busy_with(
            |p| p == "/var/lib/dpkg/lock-frontend",
            |_| None,
        );
        assert!(!unknown);
    }

    #[test]
    fn no_locks_present_means_idle() {
        assert!(!pkg_manager_busy_with(|_| false, |_| Some(true)));
    }
}
