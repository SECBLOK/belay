//! SSH brute-force guard.
//!
//! The pure core (`BruteGuard::observe_line`) is always compiled and unit-testable
//! without any feature flags.  The actual ban enforcement — adding an IP to the
//! kernel nftables `sshd_bans` set — lives in a `#[cfg(fw)]` block.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use regex::Regex;

/// Compiled once. The pattern is a string literal that cannot fail at runtime,
/// so `expect` here is a compile-time invariant, not a runtime I/O fallibility.
static FAILED_LOGIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)").expect("static regex is valid")
});

/// Cap on distinct source IPs tracked at once. A wide botnet (many IPs, each
/// below threshold) would otherwise grow `counts` without bound. When the cap is
/// reached, entries whose window has already expired are evicted before insert.
const MAX_TRACKED_IPS: usize = 65_536;

/// Tracks per-IP failed-login counts and triggers a ban once the threshold is met.
///
/// # Algorithm
/// For each `observe_line` call a failed-password line is parsed.  Each IP's
/// `(count, first_seen)` entry is reset whenever:
/// - The window has expired since `first_seen`, or
/// - The threshold is met (entry is reset so the IP is not returned again on the
///   very next failure line — the caller is responsible for applying the ban).
pub struct BruteGuard {
    threshold: u32,
    window: Duration,
    /// Requested ban lifetime. NOTE: as of rustables 0.8 the kernel set element
    /// does not receive a TTL (the crate's `SetElement` has no timeout field), so
    /// bans persist until the `belay` table is flushed rather than expiring
    /// automatically. Kept so a future kernel/userspace eviction path can use it.
    pub ban_ttl: Duration,
    counts: HashMap<IpAddr, (u32, Instant)>,
}

impl BruteGuard {
    /// Create a new guard.
    ///
    /// - `threshold`: number of failed attempts within `window` before a ban.
    /// - `window`:    rolling time window.
    /// - `ban_ttl`:   requested ban lifetime. See the `ban_ttl` field note: the
    ///   kernel currently does not receive this TTL (rustables 0.8 limitation), so
    ///   bans persist until the table is flushed.
    pub fn new(threshold: u32, window: Duration, ban_ttl: Duration) -> Self {
        Self {
            threshold,
            window,
            ban_ttl,
            counts: HashMap::new(),
        }
    }

    /// Parse one log line and update internal state.
    ///
    /// Returns `Some(ip)` when the failure count for `ip` reaches `threshold`.
    /// The counter for that IP is then **reset** so subsequent lines do not
    /// keep re-triggering bans for the same burst.
    ///
    /// Returns `None` for non-failure lines and for lines below the threshold.
    pub fn observe_line(&mut self, line: &str, now: Instant) -> Option<IpAddr> {
        let caps = FAILED_LOGIN_RE.captures(line)?;
        let ip: IpAddr = caps.get(1)?.as_str().parse().ok()?;

        // Bound memory: if we're at the cap and this is a new IP, drop entries
        // whose window has already expired (they would reset on next sight anyway).
        if self.counts.len() >= MAX_TRACKED_IPS && !self.counts.contains_key(&ip) {
            let window = self.window;
            self.counts
                .retain(|_, (_, first_seen)| now.duration_since(*first_seen) <= window);
        }

        let entry = self.counts.entry(ip).or_insert((0, now));

        // Expire window.
        if now.duration_since(entry.1) > self.window {
            *entry = (0, now);
        }

        entry.0 += 1;

        if entry.0 >= self.threshold {
            // Reset so the next failure starts a fresh window.
            self.counts.remove(&ip);
            Some(ip)
        } else {
            None
        }
    }
}

// ─── Enforcement (firewall-gated) ────────────────────────────────────────────

#[cfg(fw)]
pub mod enforce {
    //! Background tailer for `/var/log/auth.log` that feeds `BruteGuard` and bans
    //! triggering IPs by adding them to the `sshd_bans` nftables set.
    use std::io::{self, BufRead};
    use std::time::{Duration, Instant};

    use super::BruteGuard;

    /// Tail `/var/log/auth.log`, calling `observe_line` for each new line.
    /// On threshold trip, add the IP to the `sshd_bans` set via `add_to_set`.
    ///
    /// This function blocks; run it in a dedicated thread/task.
    /// I/O errors are reported to stderr and the function continues (no `unwrap`/`expect`).
    pub fn run_tailer(mut guard: BruteGuard) {
        let path = "/var/log/auth.log";
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("sshguard: cannot open {path}: {e}");
                return;
            }
        };

        // Seek to end so we only see new lines.
        use std::io::Seek;
        let mut reader = {
            let mut f = file;
            if let Err(e) = f.seek(io::SeekFrom::End(0)) {
                eprintln!("sshguard: seek failed: {e}");
            }
            io::BufReader::new(f)
        };

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    // EOF — sleep briefly and retry (simple poll-based tail).
                    std::thread::sleep(Duration::from_millis(500));
                }
                Ok(_) => {
                    let now = Instant::now();
                    if let Some(ip) = guard.observe_line(line.trim_end(), now) {
                        let ttl = guard.ban_ttl;
                        if let Err(e) = crate::firewall::add_to_set("sshd_bans", ip, ttl) {
                            eprintln!("sshguard: failed to ban {ip}: {e}");
                        } else {
                            eprintln!("sshguard: banned {ip} for {}s", ttl.as_secs());
                        }
                    }
                }
                Err(e) => {
                    eprintln!("sshguard: read error: {e}");
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn bans_ip_after_threshold_failed_logins() {
        let mut g = BruteGuard::new(3, Duration::from_secs(60), Duration::from_secs(3600));
        let now = Instant::now();
        let line = "Failed password for root from 198.51.100.7 port 2222 ssh2";
        assert_eq!(g.observe_line(line, now), None); // 1
        assert_eq!(g.observe_line(line, now), None); // 2
        assert_eq!(
            g.observe_line(line, now),
            Some("198.51.100.7".parse().unwrap())
        ); // 3 -> ban
    }

    #[test]
    fn ignores_non_failure_lines() {
        let mut g = BruteGuard::new(1, Duration::from_secs(60), Duration::from_secs(60));
        assert_eq!(
            g.observe_line(
                "Accepted publickey for deploy from 10.0.0.2",
                Instant::now()
            ),
            None
        );
    }
}
