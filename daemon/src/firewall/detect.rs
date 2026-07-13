//! Auto-setup detection — gather the host facts the one-click firewall needs.
//!
//! Pure Rust, `/proc`-only (no shell-outs). Every probe fails soft: a missing or
//! malformed source yields a default/empty value, never a panic.

use std::net::{IpAddr, Ipv4Addr};

use super::assistant::observe_listen_ports;

/// Facts detected from the host to drive a one-click least-privilege ruleset.
#[derive(Debug, Clone, Default)]
pub struct SystemProfile {
    /// `PRETTY_NAME` from /etc/os-release (informational, surfaced in the UI).
    pub os: String,
    /// TCP ports in LISTEN state.
    pub listen_tcp: Vec<u16>,
    /// UDP ports bound for receiving (unconnected).
    pub listen_udp: Vec<u16>,
    /// Operator's SSH origin: the remote IP of an established inbound connection
    /// to local port 22, if any. Pinned so applying default-drop never blocks the
    /// operator reconnecting (the current session is already covered by the
    /// allow-established rule).
    pub ssh_source: Option<IpAddr>,
}

/// Probe the host. Each field fails soft independently.
pub fn detect_system() -> SystemProfile {
    SystemProfile {
        os: detect_os(),
        listen_tcp: observe_listen_ports(),
        listen_udp: observe_listen_udp_ports(),
        ssh_source: detect_ssh_source(),
    }
}

/// `PRETTY_NAME="..."` from /etc/os-release, unquoted; empty if unavailable.
fn detect_os() -> String {
    let Ok(text) = std::fs::read_to_string("/etc/os-release") else {
        return String::new();
    };
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
            return v.trim().trim_matches('"').to_string();
        }
    }
    String::new()
}

/// UDP "listening" (unconnected) ports from /proc/net/udp[6] (state `07`).
pub fn observe_listen_udp_ports() -> Vec<u16> {
    let mut ports = Vec::new();
    for path in &["/proc/net/udp", "/proc/net/udp6"] {
        if let Ok(contents) = std::fs::read_to_string(path) {
            parse_proc_net_udp(&contents, &mut ports);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Append local ports of unconnected UDP sockets (state `07`) to `out`.
fn parse_proc_net_udp(contents: &str, out: &mut Vec<u16>) {
    for line in contents.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || f[3] != "07" {
            continue;
        }
        if let Some(port_hex) = f[1].split(':').nth(1) {
            if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                out.push(port);
            }
        }
    }
}

/// Remote IP of an ESTABLISHED inbound SSH connection (local port 22) from
/// /proc/net/tcp. IPv4 only (the common case); `None` if none is found.
pub fn detect_ssh_source() -> Option<IpAddr> {
    let contents = std::fs::read_to_string("/proc/net/tcp").ok()?;
    parse_ssh_source_v4(&contents)
}

/// Scan a /proc/net/tcp body for an ESTABLISHED (state `01`) socket whose LOCAL
/// port is 22 (`0016`), returning its remote IPv4 address.
fn parse_ssh_source_v4(contents: &str) -> Option<IpAddr> {
    for line in contents.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || f[3] != "01" {
            continue; // not ESTABLISHED
        }
        let local_port = f[1]
            .split(':')
            .nth(1)
            .and_then(|h| u16::from_str_radix(h, 16).ok());
        if local_port != Some(22) {
            continue;
        }
        if let Some(rem_hex) = f[2].split(':').next() {
            if let Some(ip) = parse_hex_ipv4(rem_hex) {
                return Some(IpAddr::V4(ip));
            }
        }
    }
    None
}

/// Parse an 8-hex-char /proc/net little-endian IPv4 address ("0100007F" → 127.0.0.1).
fn parse_hex_ipv4(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let v = u32::from_str_radix(hex, 16).ok()?;
    let [a, b, c, d] = v.to_le_bytes();
    Some(Ipv4Addr::new(a, b, c, d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_listen_ports_only_state_07() {
        // 0035 hex = 53 (DNS, state 07 = unconnected). Second line state 01 ignored.
        let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid
   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0
   1: 0100007F:0044 00000000:0000 01 00000000:00000000 00:00000000 00000000     0
";
        let mut out = Vec::new();
        parse_proc_net_udp(sample, &mut out);
        assert_eq!(out, vec![53]);
    }

    #[test]
    fn hex_ipv4_is_little_endian() {
        assert_eq!(
            parse_hex_ipv4("0100007F"),
            Some(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(
            parse_hex_ipv4("0200007F"),
            Some(Ipv4Addr::new(127, 0, 0, 2))
        );
        assert_eq!(parse_hex_ipv4("bad"), None);
    }

    #[test]
    fn ssh_source_is_remote_of_established_port_22() {
        // Line 0: LISTEN (0A) on :22 — ignored (no real remote).
        // Line 1: ESTABLISHED (01), local :22, remote 0200007F → 127.0.0.2.
        // Line 2: ESTABLISHED on a non-22 local port — ignored.
        let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0
   1: 0100007F:0016 0200007F:C000 01 00000000:00000000 00:00000000 00000000     0
   2: 0100007F:0050 0300007F:C001 01 00000000:00000000 00:00000000 00000000     0
";
        assert_eq!(
            parse_ssh_source_v4(sample),
            Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))
        );
    }
}
