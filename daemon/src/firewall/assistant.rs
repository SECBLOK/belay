//! Firewall-setup assistant: observe listening ports, propose a least-privilege ruleset.
//!
//! # Usage
//! ```ignore
//! let ports = observe_listen_ports();
//! let rs = propose_ruleset(&ports, Some("203.0.113.9".parse().unwrap()));
//! let guard = apply_with_revert(&rs, Duration::from_secs(60), backend).await?;
//! // … operator verifies SSH still works …
//! guard.confirm();
//! ```

use std::net::IpAddr;

use super::detect::SystemProfile;
use super::ManagedRuleset;

// ──────────────────────────────────────────────────────────────────────────────
// observe_listen_ports
// ──────────────────────────────────────────────────────────────────────────────

/// Parse `/proc/net/tcp` and `/proc/net/tcp6` and return the set of local ports
/// whose sockets are in the LISTEN state (`0A` hex).
///
/// Fails soft: if the files are missing or malformed, returns whatever was
/// successfully parsed (may be empty). Never panics.
pub fn observe_listen_ports() -> Vec<u16> {
    let mut ports = Vec::new();
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(contents) = std::fs::read_to_string(path) {
            parse_proc_net_tcp(&contents, &mut ports);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Parse a single `/proc/net/tcp[6]` file and append LISTEN ports to `out`.
///
/// Each data line (after the header) has fields separated by whitespace.
/// Field 1 (0-indexed) is `local_address` in `HHHHHHHH:PPPP` form (hex).
/// Field 3 is the socket state; `0A` = TCP_LISTEN.
fn parse_proc_net_tcp(contents: &str, out: &mut Vec<u16>) {
    for line in contents.lines().skip(1) {
        // Split on whitespace; we need fields at indices 1 (local_address) and 3 (state).
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let state = fields[3];
        if state != "0A" {
            continue;
        }
        // local_address is "XXXXXXXX:PPPP" (IPv4) or "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:PPPP" (IPv6).
        let local_addr = fields[1];
        if let Some(port_hex) = local_addr.split(':').nth(1) {
            if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                out.push(port);
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// propose_ruleset
// ──────────────────────────────────────────────────────────────────────────────

/// Propose a least-privilege [`ManagedRuleset`] for the given listen ports.
///
/// - Port 22 (SSH) is **excluded** from `allow_ports`; it is covered by the
///   `ssh_source` exemption — opening port 22 to all IPs would be less secure.
/// - All other observed ports are allowed.
/// - `default_drop` is always `true`.
pub fn propose_ruleset(listen: &[u16], ssh_source: Option<IpAddr>) -> ManagedRuleset {
    let allow_ports: Vec<u16> = listen.iter().copied().filter(|&p| p != 22).collect();
    ManagedRuleset {
        allow_ports,
        ssh_source,
        default_drop: true,
    }
}

/// Propose a least-privilege [`ManagedRuleset`] from an auto-detected
/// [`SystemProfile`]: open every detected TCP + UDP listening port (so running
/// services are not locked out), minus 22 (covered by the SSH pin); pin the
/// detected SSH source; and default-drop the rest. This is the one-click
/// "Auto setup" path — same safety contract as [`propose_ruleset`].
pub fn propose_auto_ruleset(profile: &SystemProfile) -> ManagedRuleset {
    let mut allow_ports: Vec<u16> = profile
        .listen_tcp
        .iter()
        .chain(profile.listen_udp.iter())
        .copied()
        .filter(|&p| p != 22)
        .collect();
    allow_ports.sort_unstable();
    allow_ports.dedup();
    ManagedRuleset {
        allow_ports,
        ssh_source: profile.ssh_source,
        default_drop: true,
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_keeps_ssh_and_observed_ports_and_default_drops() {
        let rs = propose_ruleset(&[80, 443], Some("203.0.113.9".parse().unwrap()));
        assert!(rs.default_drop);
        assert!(rs.allow_ports.contains(&80) && rs.allow_ports.contains(&443));
        assert_eq!(rs.ssh_source, Some("203.0.113.9".parse().unwrap()));
        // Port 22 is covered by the ssh_source exemption, not blanket-opened.
        assert!(!rs.allow_ports.contains(&22));
    }

    #[test]
    fn proposal_filters_port_22_from_listen_list() {
        let rs = propose_ruleset(&[22, 80, 443], None);
        assert!(!rs.allow_ports.contains(&22));
        assert!(rs.allow_ports.contains(&80));
        assert!(rs.allow_ports.contains(&443));
        assert!(rs.default_drop);
    }

    #[test]
    fn auto_proposal_merges_tcp_udp_pins_ssh_and_default_drops() {
        let profile = SystemProfile {
            os: "Test OS".into(),
            listen_tcp: vec![22, 80, 443],
            listen_udp: vec![53, 443], // 443 dup across tcp+udp; 53 udp-only
            ssh_source: Some("203.0.113.9".parse().unwrap()),
        };
        let rs = propose_auto_ruleset(&profile);
        assert!(rs.default_drop);
        assert_eq!(rs.ssh_source, Some("203.0.113.9".parse().unwrap()));
        // 22 excluded (covered by ssh pin); tcp+udp merged & de-duped.
        assert_eq!(rs.allow_ports, vec![53, 80, 443]);
    }

    #[test]
    fn parse_proc_net_tcp_extracts_listen_ports() {
        // Synthetic /proc/net/tcp snippet; port 0050 hex = 80 decimal (LISTEN 0A),
        // port 01BB hex = 443 (LISTEN), port 0016 hex = 22 (LISTEN),
        // port 8000 = 32768 (ESTABLISHED 01 — must be ignored).
        let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
   2: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0
   3: 0100007F:8000 0200007F:C000 01 00000000:00000000 00:00000000 00000000  1000        0 12348 1 0000000000000000 20 4 24 10 -1
";
        let mut ports = Vec::new();
        parse_proc_net_tcp(sample, &mut ports);
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
        assert!(ports.contains(&22));
        assert!(
            !ports.contains(&32768),
            "ESTABLISHED sockets must not appear"
        );
    }
}
