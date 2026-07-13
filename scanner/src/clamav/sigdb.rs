//! ClamAV hash-signature database (.hdb / .hsb) parser and matcher.
//!
//! `.hdb` line format: `MD5:filesize:MalwareName`
//! `.hsb` line format: `SHA256:filesize:MalwareName`
//!
//! Filesize is ignored for the MVP; entries are indexed by digest only.

use md5::Digest as Md5Digest;
use sha2::{Digest as Sha2Digest, Sha256};
use std::collections::HashMap;

use super::cvd::CvdEntry;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Decode a lowercase hex string into a fixed-size byte array.
/// Returns `None` if the string length or characters are wrong.
fn hex_to_bytes<const N: usize>(hex: &str) -> Option<[u8; N]> {
    if hex.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

#[inline]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ── SignatureDb ───────────────────────────────────────────────────────────────

/// In-memory signature database loaded from ClamAV `.hdb` and `.hsb` entries.
pub struct SignatureDb {
    md5: HashMap<[u8; 16], String>,
    sha256: HashMap<[u8; 32], String>,
}

impl SignatureDb {
    /// Build a `SignatureDb` from a slice of extracted CVD entries.
    ///
    /// Entries whose name ends in `.hdb` or `.hdu` are parsed as MD5 databases.
    /// Entries whose name ends in `.hsb` or `.hsu` are parsed as SHA-256 databases.
    /// Other entries are silently ignored.
    pub fn from_entries(entries: &[CvdEntry]) -> Self {
        let mut db = Self {
            md5: HashMap::new(),
            sha256: HashMap::new(),
        };

        for entry in entries {
            let name_lower = entry.name.to_ascii_lowercase();
            if name_lower.ends_with(".hdb") || name_lower.ends_with(".hdu") {
                db.ingest_hdb(&entry.data);
            } else if name_lower.ends_with(".hsb") || name_lower.ends_with(".hsu") {
                db.ingest_hsb(&entry.data);
            }
        }

        db
    }

    /// Parse an `.hdb` blob and insert entries into the MD5 map.
    fn ingest_hdb(&mut self, data: &[u8]) {
        let text = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => return,
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(3, ':');
            let hash_hex = match parts.next() {
                Some(h) => h,
                None => continue,
            };
            // skip filesize field
            let _ = parts.next();
            let name = match parts.next() {
                Some(n) => n.trim().to_owned(),
                None => continue,
            };
            if let Some(digest) = hex_to_bytes::<16>(hash_hex) {
                self.md5.insert(digest, name);
            }
        }
    }

    /// Parse an `.hsb` blob and insert entries into the SHA-256 map.
    fn ingest_hsb(&mut self, data: &[u8]) {
        let text = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => return,
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(3, ':');
            let hash_hex = match parts.next() {
                Some(h) => h,
                None => continue,
            };
            // skip filesize field
            let _ = parts.next();
            let name = match parts.next() {
                Some(n) => n.trim().to_owned(),
                None => continue,
            };
            if let Some(digest) = hex_to_bytes::<32>(hash_hex) {
                self.sha256.insert(digest, name);
            }
        }
    }

    /// Check `data` against the loaded signatures.
    ///
    /// Computes both MD5 and SHA-256 of `data` and returns the malware name
    /// from whichever index matches first (MD5 checked first), or `None` if
    /// neither matches.
    pub fn match_bytes(&self, data: &[u8]) -> Option<&str> {
        // MD5 check
        let md5_digest: [u8; 16] = <md5::Md5 as Md5Digest>::digest(data).into();
        if let Some(name) = self.md5.get(&md5_digest) {
            return Some(name.as_str());
        }

        // SHA-256 check
        let sha256_digest: [u8; 32] = <Sha256 as Sha2Digest>::digest(data).into();
        if let Some(name) = self.sha256.get(&sha256_digest) {
            return Some(name.as_str());
        }

        None
    }

    /// Total number of signatures loaded (MD5 + SHA-256).
    pub fn len(&self) -> usize {
        self.md5.len() + self.sha256.len()
    }

    /// Returns `true` if no signatures are loaded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(name: &str, data: &[u8]) -> CvdEntry {
        CvdEntry {
            name: name.to_owned(),
            data: data.to_vec(),
        }
    }

    #[test]
    fn matches_known_md5_signature() {
        // Compute MD5 of our test bytes.
        let payload = b"EICAR-TEST-FILE";
        let digest = md5::Md5::digest(payload);
        let hex = format!("{:x}", digest);

        // Build a .hdb entry: MD5:size:Name
        let hdb_line = format!("{hex}:15:Eicar.Test.Malware\n");
        let entries = vec![make_entry("test.hdb", hdb_line.as_bytes())];

        let db = SignatureDb::from_entries(&entries);
        assert_eq!(db.len(), 1);
        assert_eq!(db.match_bytes(payload), Some("Eicar.Test.Malware"));
    }

    #[test]
    fn matches_known_sha256_signature() {
        // Compute SHA-256 of our test bytes and build a .hsb entry: SHA256:size:Name
        let payload = b"EICAR-TEST-FILE";
        let digest = sha2::Sha256::digest(payload);
        let hex = format!("{:x}", digest);

        let hsb_line = format!("{hex}:15:Eicar.Sha256.Malware\n");
        let entries = vec![make_entry("test.hsb", hsb_line.as_bytes())];

        let db = SignatureDb::from_entries(&entries);
        assert_eq!(db.len(), 1);
        assert_eq!(db.match_bytes(payload), Some("Eicar.Sha256.Malware"));
    }

    #[test]
    fn clean_bytes_do_not_match() {
        let hdb_line = "aabbccddeeff00112233445566778899:0:SomeMalware\n";
        let entries = vec![make_entry("sigs.hdb", hdb_line.as_bytes())];
        let db = SignatureDb::from_entries(&entries);

        // These bytes have a different MD5 — should not match.
        assert_eq!(db.match_bytes(b"clean file content"), None);
    }
}
