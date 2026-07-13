//! Secure input resolver: git, url, zip, dir, file -> (local_path, SourceType).
//!
//! Security guards implemented:
//! - SSRF: `is_private_host` checks loopback/link-local/private (IPv4 + IPv6 ULA +
//!   IPv4-mapped), fail-closed on error.
//! - Zip-slip: uses `ZipFile::enclosed_name()` (zip 2.x) — rejects any entry
//!   whose name is absolute, contains `..`-escaping, or otherwise unsafe.
//! - Zip-bomb: rejects archives with total uncompressed size > 100 MB (uses
//!   saturating_add to prevent integer overflow on malicious ZIP64 size claims).
//! - git clone: `--depth 1`, no shell interpolation (shell=false).
//!
//! # Deviation from Python oracle
//! The `http://`/`https://` non-git download branches (`_download_url` via httpx) are
//! NOT ported. Pulling in `reqwest::blocking` would force a large recompile that risks
//! exhausting the 315 MB of free disk space on this machine. The branch returns
//! `anyhow::bail!` instead.
//! TODO(phase10): port _download_url via reqwest blocking when disk allows.

use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::process::Command;

use serde::{Deserialize, Serialize};

const MAX_ZIP_BYTES: u64 = 100 * 1024 * 1024; // 100 MB

/// The origin type of a resolved scan input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceType {
    Git,
    Url,
    Zip,
    Dir,
    File,
}

/// Return `true` if `host` resolves to a private/loopback/link-local address.
///
/// Fail-closed: returns `true` (i.e. BLOCKED) on any resolution error.
/// Mirrors `resolve.py::is_private_host` exactly, including IPv6 ULA (fc00::/7)
/// and IPv4-mapped private addresses.
pub fn is_private_host(host: &str) -> bool {
    let addrs = match (host, 0u16).to_socket_addrs() {
        Ok(a) => a,
        Err(_) => return true, // fail-closed
    };
    for sock_addr in addrs {
        let ip = sock_addr.ip();
        let blocked = match ip {
            std::net::IpAddr::V4(v4) => is_ipv4_private(v4),
            std::net::IpAddr::V6(v6) => {
                // loopback (::1)
                v6.is_loopback()
                    // link-local fe80::/10
                    || is_ipv6_link_local(v6)
                    // ULA fc00::/7 (covers fd00::/8)
                    || is_ipv6_ula(v6)
                    // IPv4-mapped ::ffff:a.b.c.d — check the embedded IPv4
                    || v6.to_ipv4_mapped().map(is_ipv4_private).unwrap_or(false)
            }
        };
        if blocked {
            return true;
        }
    }
    false
}

/// Returns true if `addr` is a private, loopback, or link-local IPv4 address.
/// Extracted so the same logic applies to both direct IPv4 and IPv4-mapped IPv6.
pub fn is_ipv4_private(addr: std::net::Ipv4Addr) -> bool {
    addr.is_loopback() || addr.is_link_local() || addr.is_private()
}

/// IPv6 link-local: fe80::/10
fn is_ipv6_link_local(addr: std::net::Ipv6Addr) -> bool {
    let segments = addr.segments();
    (segments[0] & 0xffc0) == 0xfe80
}

/// IPv6 Unique Local Address (ULA): fc00::/7
/// Covers both fc00::/8 and fd00::/8.
/// `is_unique_local()` is nightly-only, so we implement the bit-mask manually.
pub fn is_ipv6_ula(addr: std::net::Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

/// Resolve `input` to a `(local_path, SourceType)` pair.
///
/// Mirrors `resolve.py::resolve` — see module doc for the URL-download deviation.
pub fn resolve(input: &str) -> anyhow::Result<(PathBuf, SourceType)> {
    let inp = input.trim();

    // --- Git URL ---
    if inp.ends_with(".git")
        || inp.starts_with("git@")
        || (inp.starts_with("http://") || inp.starts_with("https://")) && inp.ends_with(".git")
    {
        let dest = tempfile::Builder::new()
            .prefix("belay_git_")
            .tempdir()?
            .keep();
        clone_git(inp, &dest)?;
        return Ok((dest, SourceType::Git));
    }

    // --- ZIP URL (http/https + .zip in URL) ---
    if (inp.starts_with("http://") || inp.starts_with("https://")) && inp.contains(".zip") {
        // TODO(phase10): port _download_url via reqwest blocking when disk allows
        anyhow::bail!("remote URL fetch not yet ported (reqwest) — use git/zip/dir/file inputs");
    }

    // --- Other URL ---
    if inp.starts_with("http://") || inp.starts_with("https://") {
        // TODO(phase10): port _download_url via reqwest blocking when disk allows
        anyhow::bail!("remote URL fetch not yet ported (reqwest) — use git/zip/dir/file inputs");
    }

    // --- Local zip file ---
    if inp.ends_with(".zip") && std::path::Path::new(inp).is_file() {
        let zip_bytes = std::fs::read(inp)?;
        let dest = tempfile::Builder::new()
            .prefix("belay_zip_")
            .tempdir()?
            .keep();
        extract_zip(&zip_bytes, &dest)?;
        return Ok((dest, SourceType::Zip));
    }

    // --- Local directory ---
    if std::path::Path::new(inp).is_dir() {
        return Ok((PathBuf::from(inp), SourceType::Dir));
    }

    // --- Local file ---
    if std::path::Path::new(inp).is_file() {
        let dest = tempfile::Builder::new()
            .prefix("belay_file_")
            .tempdir()?
            .keep();
        let filename = std::path::Path::new(inp)
            .file_name()
            .unwrap_or(std::ffi::OsStr::new("file"));
        std::fs::copy(inp, dest.join(filename))?;
        return Ok((dest, SourceType::File));
    }

    anyhow::bail!("Cannot resolve input: {:?}", input)
}

/// Clone a git repo (depth 1, no shell) into `dest`.
fn clone_git(url: &str, dest: &std::path::Path) -> anyhow::Result<()> {
    let status = Command::new("git")
        .args(["clone", "--depth", "1", url, &dest.to_string_lossy()])
        .status()?;
    if !status.success() {
        anyhow::bail!("git clone failed for {:?}", url);
    }
    Ok(())
}

/// Extract zip bytes into `dest`, with zip-slip and zip-bomb guards.
/// Mirrors `resolve.py::_extract_zip`.
///
/// Zip-slip protection uses `ZipFile::enclosed_name()` (zip 2.x) which returns
/// `None` for any entry whose name is absolute, contains `..` sequences, or
/// otherwise escapes the archive root.  We reject such entries with an error
/// rather than silently skipping them.
///
/// Zip-bomb protection sums uncompressed sizes with `saturating_add` so that
/// malicious ZIP64 overflow-to-small-total tricks are impossible.
fn extract_zip(zip_bytes: &[u8], dest: &std::path::Path) -> anyhow::Result<()> {
    use std::io::Read;

    let cursor = std::io::Cursor::new(zip_bytes);
    let mut zf = zip::ZipArchive::new(cursor)?;

    // Zip-bomb check: sum of uncompressed sizes using saturating_add to prevent
    // integer overflow on crafted ZIP64 size fields.
    let total: u64 = (0..zf.len())
        .map(|i| zf.by_index(i).map(|f| f.size()).unwrap_or(0))
        .fold(0u64, |acc, sz| acc.saturating_add(sz));
    if total > MAX_ZIP_BYTES {
        anyhow::bail!(
            "Zip-bomb guard: uncompressed size {} > {}",
            total,
            MAX_ZIP_BYTES
        );
    }

    for i in 0..zf.len() {
        let mut member = zf.by_index(i)?;

        // Zip-slip check: enclosed_name() returns None for any unsafe path
        // (absolute, contains ".." escape, NUL bytes, etc.).
        let safe_rel = member
            .enclosed_name()
            .ok_or_else(|| anyhow::anyhow!("zip-slip guard: {:?} escapes root", member.name()))?;

        let target = dest.join(safe_rel);

        if member.is_dir() {
            std::fs::create_dir_all(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut data = Vec::new();
            member.read_to_end(&mut data)?;
            std::fs::write(&target, &data)?;
        }
    }

    Ok(())
}
