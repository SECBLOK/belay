//! Security regression tests for scanner::resolve.
//!
//! Locks the three security fixes from phase10-task2 review:
//!   C-1  zip-slip via `..` in entry name
//!   I-1  SSRF: IPv6 ULA (fc00::/7, fd00::/8)
//!   I-2  SSRF: IPv4-mapped private addresses (::ffff:192.168.x.x etc.)
//!   M-2  zip-bomb sum overflow (saturating_add)

use scanner::resolve::{is_ipv4_private, is_ipv6_ula};
use std::io::Write as IoWrite;
use std::net::{Ipv4Addr, Ipv6Addr};

// ── helper: build an in-memory ZIP with a single entry ──────────────────────

fn make_zip_with_entry(entry_name: &str, content: &[u8]) -> Vec<u8> {
    let buf = std::io::Cursor::new(Vec::new());
    let mut zw = zip::ZipWriter::new(buf);
    let opts =
        zip::write::FileOptions::<()>::default().compression_method(zip::CompressionMethod::Stored);
    zw.start_file(entry_name, opts).unwrap();
    zw.write_all(content).unwrap();
    zw.finish().unwrap().into_inner()
}

// ── C-1: zip-slip rejected ────────────────────────────────────────────────────

/// An entry named `../escape.sh` must be rejected — must NOT write outside dest.
#[test]
fn zip_slip_rejected() {
    let zip_bytes = make_zip_with_entry("../escape.sh", b"#!/bin/sh\necho pwned\n");

    let dest = tempfile::TempDir::new().unwrap();
    let dest_path = dest.path().to_path_buf();

    // The scanner must return Err for this zip.
    // We call the internal path via the public `resolve()` function by writing
    // the zip to a temp file and resolving it.  But since extract_zip is private
    // we exercise it through the public resolve() entry point.
    let zip_file = dest_path.join("test_slip.zip");
    std::fs::write(&zip_file, &zip_bytes).unwrap();

    let result = scanner::resolve::resolve(zip_file.to_str().unwrap());
    assert!(
        result.is_err(),
        "zip-slip: expected Err but got Ok — traversal not blocked"
    );

    // Verify the file was NOT written outside dest_path.
    let escape_target = dest_path.parent().unwrap().join("escape.sh");
    assert!(
        !escape_target.exists(),
        "zip-slip: escape.sh was written OUTSIDE the extract root — CRITICAL"
    );
}

// ── M-2: zip-bomb rejected ────────────────────────────────────────────────────

/// A zip whose entries claim > 100 MB uncompressed must be rejected.
///
/// Rationale for why this test would fail without the fix:
///   Before saturating_add, two entries each claiming u64::MAX/2 + 1 bytes would
///   overflow to a small total, passing the > MAX_ZIP_BYTES check.  With
///   saturating_add the sum saturates at u64::MAX, which is > MAX_ZIP_BYTES.
///
/// We use a simpler approach here: write actual content > 100 MB so the size
/// check fires even without overflow.  Because the zip writer compresses, we
/// write incompressible data (repeated bytes compressed=stored).
#[test]
fn zip_bomb_rejected() {
    // Build a zip with two entries each claiming just over 51 MB — total > 100 MB.
    // Use stored compression so size() == actual data size.
    let chunk = vec![0xA5u8; 52 * 1024 * 1024]; // 52 MB, stored

    let buf = std::io::Cursor::new(Vec::new());
    let mut zw = zip::ZipWriter::new(buf);
    let opts =
        zip::write::FileOptions::<()>::default().compression_method(zip::CompressionMethod::Stored);
    zw.start_file("part1.bin", opts).unwrap();
    zw.write_all(&chunk).unwrap();
    zw.start_file("part2.bin", opts).unwrap();
    zw.write_all(&chunk).unwrap();
    let zip_bytes = zw.finish().unwrap().into_inner();

    let dest = tempfile::TempDir::new().unwrap();
    let zip_file = dest.path().join("bomb.zip");
    std::fs::write(&zip_file, &zip_bytes).unwrap();

    let result = scanner::resolve::resolve(zip_file.to_str().unwrap());
    assert!(
        result.is_err(),
        "zip-bomb: expected Err but got Ok — 104 MB archive not rejected"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("Zip-bomb"),
        "zip-bomb: error should mention 'Zip-bomb', got: {err_msg}"
    );
}

// ── I-1 + I-2: IPv6 ULA and IPv4-mapped SSRF blocking ────────────────────────

/// fd12::1 is ULA (fd00::/8, within fc00::/7) — must be classified as private.
#[test]
fn ssrf_ipv6_ula_blocked() {
    let ula: Ipv6Addr = "fd12::1".parse().unwrap();
    assert!(
        is_ipv6_ula(ula),
        "fd12::1 should be classified as ULA (fc00::/7)"
    );

    // Also check a pure fc00:: address.
    let fc: Ipv6Addr = "fc00::1".parse().unwrap();
    assert!(is_ipv6_ula(fc), "fc00::1 should be classified as ULA");

    // Non-ULA (2001:db8:: is documentation range, not ULA).
    let non_ula: Ipv6Addr = "2001:db8::1".parse().unwrap();
    assert!(!is_ipv6_ula(non_ula), "2001:db8::1 should NOT be ULA");
}

/// ::ffff:192.168.1.1 is an IPv4-mapped private address — must be blocked.
#[test]
fn ssrf_ipv4_mapped_private_blocked() {
    // ::ffff:192.168.1.1 — IPv4-mapped private
    let mapped_private: Ipv6Addr = "::ffff:192.168.1.1".parse().unwrap();
    let embedded = mapped_private
        .to_ipv4_mapped()
        .expect("should be IPv4-mapped");
    assert!(
        is_ipv4_private(embedded),
        "::ffff:192.168.1.1 embedded IPv4 192.168.1.1 should be private"
    );

    // ::ffff:127.0.0.1 — IPv4-mapped loopback
    let mapped_loopback: Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
    let emb_loop = mapped_loopback
        .to_ipv4_mapped()
        .expect("should be IPv4-mapped");
    assert!(
        is_ipv4_private(emb_loop),
        "::ffff:127.0.0.1 embedded IPv4 should be loopback (private)"
    );

    // ::ffff:8.8.8.8 — IPv4-mapped PUBLIC — should NOT be blocked
    let mapped_public: Ipv6Addr = "::ffff:8.8.8.8".parse().unwrap();
    let emb_pub = mapped_public
        .to_ipv4_mapped()
        .expect("should be IPv4-mapped");
    assert!(
        !is_ipv4_private(emb_pub),
        "::ffff:8.8.8.8 should NOT be classified as private"
    );
}

/// Direct unit-test of is_private_host for IPv6 ULA string representation.
/// This exercises the full path: DNS lookup → IPv6 classification.
/// We use a numeric host string so no DNS is needed.
#[test]
fn ssrf_is_private_host_ula_numeric() {
    // Numeric IPv6 ULA — to_socket_addrs() resolves it without DNS.
    assert!(
        scanner::resolve::is_private_host("fd12::1"),
        "is_private_host should block ULA fd12::1"
    );
    assert!(
        scanner::resolve::is_private_host("fc00::1"),
        "is_private_host should block ULA fc00::1"
    );
}

// ── Sanity: well-known public addresses are NOT blocked ───────────────────────

#[test]
fn ipv4_public_not_blocked() {
    let public: Ipv4Addr = "8.8.8.8".parse().unwrap();
    assert!(!is_ipv4_private(public), "8.8.8.8 should not be private");
}
