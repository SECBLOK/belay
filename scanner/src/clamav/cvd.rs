//! ClamAV CVD (ClamAV Virus Database) file parser.
//!
//! A CVD file begins with a 512-byte ASCII header of the form:
//! `ClamAV-VDB:<build time>:<version>:<num sigs>:<flevel>:<MD5>:<dsig>:<builder>:<build secs>`
//! followed by a gzip-compressed tar archive containing the signature files.

use std::io::Read;

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum CvdError {
    TooShort,
    BadMagic,
    BadField(String),
    BombLimit(String),
    Io(String),
}

impl std::fmt::Display for CvdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CvdError::TooShort => write!(f, "CVD header too short"),
            CvdError::BadMagic => write!(f, "CVD header does not start with 'ClamAV-VDB:'"),
            CvdError::BadField(s) => write!(f, "CVD bad field: {s}"),
            CvdError::BombLimit(s) => write!(f, "CVD extraction limit exceeded: {s}"),
            CvdError::Io(s) => write!(f, "CVD I/O error: {s}"),
        }
    }
}

impl std::error::Error for CvdError {}

// ── Header ───────────────────────────────────────────────────────────────────

/// Parsed fields from the CVD 512-byte ASCII header.
#[derive(Debug, PartialEq, Eq)]
pub struct CvdHeader {
    pub version: u32,
    pub sig_count: u32,
    pub builder: String,
}

const MAGIC: &str = "ClamAV-VDB:";
const HEADER_LEN: usize = 512;

/// Parse the 512-byte CVD header from the raw bytes of a `.cvd` file.
///
/// Returns `CvdError::TooShort` if fewer than 512 bytes are provided,
/// `CvdError::BadMagic` if the magic prefix is absent, and
/// `CvdError::BadField` for any parse failure on the colon-delimited fields.
pub fn parse_header(raw: &[u8]) -> Result<CvdHeader, CvdError> {
    if raw.len() < HEADER_LEN {
        return Err(CvdError::TooShort);
    }

    let header_str = std::str::from_utf8(&raw[..HEADER_LEN]).map_err(|_| CvdError::BadMagic)?;

    if !header_str.starts_with(MAGIC) {
        return Err(CvdError::BadMagic);
    }

    // Strip the magic prefix then split on ':'.
    // The build-time field (the first field after the magic) may itself contain
    // colons (e.g. "01 Jan 2024 00:00:00 +0000"), so we CANNOT use a fixed left
    // index for the numeric fields.  Instead we split on ALL ':' and index from
    // the right:
    //   rindex 0 = build secs
    //   rindex 1 = builder
    //   rindex 2 = dsig
    //   rindex 3 = md5
    //   rindex 4 = flevel
    //   rindex 5 = num sigs
    //   rindex 6 = version
    //   rindex 7+ = build time (may span many colon-separated tokens)
    let rest = &header_str[MAGIC.len()..];
    // Trim trailing whitespace (the 512-byte header is space-padded).
    let rest = rest.trim_end();
    let fields: Vec<&str> = rest.split(':').collect();

    // We need at least 8 tokens (version, num_sigs, flevel, md5, dsig, builder,
    // build_secs — all after the build-time which may be multi-token).
    if fields.len() < 8 {
        return Err(CvdError::BadField(format!(
            "expected at least 8 colon-delimited tokens, got {}",
            fields.len()
        )));
    }

    let n = fields.len();
    // version is at rindex 6 (i.e. fields[n-7])
    let version_str = fields[n - 7].trim();
    let version = version_str
        .parse::<u32>()
        .map_err(|_| CvdError::BadField(format!("version not a u32: '{version_str}'")))?;

    // num_sigs is at rindex 5 (fields[n-6])
    let sig_count_str = fields[n - 6].trim();
    let sig_count = sig_count_str
        .parse::<u32>()
        .map_err(|_| CvdError::BadField(format!("sig_count not a u32: '{sig_count_str}'")))?;

    // builder is at rindex 1 (fields[n-2])
    let builder = fields[n - 2].trim().to_owned();

    Ok(CvdHeader {
        version,
        sig_count,
        builder,
    })
}

// ── Extraction ───────────────────────────────────────────────────────────────

/// Limits applied during CVD body extraction to prevent decompression bombs.
pub struct ExtractLimits {
    /// Maximum total decompressed bytes across all entries.
    pub max_total: u64,
    /// Maximum number of archive entries (files).
    pub max_files: usize,
    /// Maximum decompressed size for a single entry.
    pub max_file: u64,
}

impl Default for ExtractLimits {
    fn default() -> Self {
        Self {
            max_total: 2 * 1024 * 1024 * 1024, // 2 GiB
            max_files: 200_000,
            max_file: 256 * 1024 * 1024, // 256 MiB
        }
    }
}

/// A single extracted file from a CVD archive.
pub struct CvdEntry {
    pub name: String,
    pub data: Vec<u8>,
}

/// Extract all entries from a CVD file (header + gzip-compressed tar body).
///
/// Enforces `limits` to guard against decompression bombs:
/// - Aborts with `CvdError::BombLimit` if any single entry exceeds `max_file`.
/// - Aborts with `CvdError::BombLimit` if the total decompressed size exceeds `max_total`.
/// - Aborts with `CvdError::BombLimit` if the number of entries exceeds `max_files`.
pub fn extract_entries(raw: &[u8], limits: &ExtractLimits) -> Result<Vec<CvdEntry>, CvdError> {
    // Validate the header first.
    parse_header(raw)?;

    // The body starts right after the 512-byte header.
    let body = &raw[HEADER_LEN..];

    // Wrap body in a GzDecoder capped at max_total to prevent unbounded allocation.
    let gz = flate2::read::GzDecoder::new(body);
    let capped = gz.take(limits.max_total);
    let mut archive = tar::Archive::new(capped);

    let entries = archive.entries().map_err(|e| CvdError::Io(e.to_string()))?;

    let mut out: Vec<CvdEntry> = Vec::new();
    let mut total_bytes: u64 = 0;

    for entry_result in entries {
        let entry = entry_result.map_err(|e| CvdError::Io(e.to_string()))?;

        // Check file count limit.
        if out.len() >= limits.max_files {
            return Err(CvdError::BombLimit(format!(
                "entry count exceeds max_files ({})",
                limits.max_files
            )));
        }

        let name = entry
            .path()
            .map_err(|e| CvdError::Io(e.to_string()))?
            .to_string_lossy()
            .into_owned();

        // Read up to max_file + 1 bytes to detect oversized entries.
        let mut buf = Vec::new();
        entry
            .take(limits.max_file.saturating_add(1))
            .read_to_end(&mut buf)
            .map_err(|e| CvdError::Io(e.to_string()))?;

        if buf.len() as u64 > limits.max_file {
            return Err(CvdError::BombLimit(format!(
                "entry '{name}' exceeds max_file ({} bytes)",
                limits.max_file
            )));
        }

        total_bytes += buf.len() as u64;
        // Note: the GzDecoder is already capped at max_total via `.take()`,
        // but we also check here for a belt-and-suspenders guard.
        if total_bytes > limits.max_total {
            return Err(CvdError::BombLimit(format!(
                "total decompressed size exceeds max_total ({} bytes)",
                limits.max_total
            )));
        }

        out.push(CvdEntry { name, data: buf });
    }

    Ok(out)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal 512-byte CVD header with given field values.
    fn make_header(version: u32, sig_count: u32, builder: &str) -> Vec<u8> {
        // ClamAV-VDB:<build_time>:<version>:<num_sigs>:<flevel>:<md5>:<dsig>:<builder>:<build_secs>
        let s = format!(
            "ClamAV-VDB:01 Jan 2024 00:00:00 +0000:{version}:{sig_count}:90:d41d8cd98f00b204e9800998ecf8427e:sig:{builder}:1700000000",
        );
        let mut buf = s.into_bytes();
        // Pad to 512 bytes with spaces.
        buf.resize(HEADER_LEN, b' ');
        buf
    }

    #[test]
    fn parses_version_count_and_builder() {
        let raw = make_header(27110, 8_000_000, "neo");
        let hdr = parse_header(&raw).unwrap();
        assert_eq!(hdr.version, 27110);
        assert_eq!(hdr.sig_count, 8_000_000);
        assert_eq!(hdr.builder, "neo");
    }

    #[test]
    fn rejects_short_input() {
        let raw = b"ClamAV-VDB:short";
        assert_eq!(parse_header(raw), Err(CvdError::TooShort));
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut raw = vec![0u8; HEADER_LEN];
        raw[..5].copy_from_slice(b"WRONG");
        assert_eq!(parse_header(&raw), Err(CvdError::BadMagic));
    }

    // ── Task-2 tests ──────────────────────────────────────────────────────────

    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    /// Build a minimal CVD blob: 512-byte header + gzip-compressed tar
    /// containing the given `files` as `(name, content)` pairs.
    fn make_cvd_blob(files: &[(&str, &[u8])]) -> Vec<u8> {
        // Build tar in memory.
        let mut tar_buf: Vec<u8> = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            for (name, content) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, name, *content).unwrap();
            }
            builder.finish().unwrap();
        }

        // Gzip-compress the tar.
        let mut gz_buf: Vec<u8> = Vec::new();
        {
            let mut enc = GzEncoder::new(&mut gz_buf, Compression::default());
            enc.write_all(&tar_buf).unwrap();
            enc.finish().unwrap();
        }

        // Prepend a valid 512-byte header.
        let mut blob = make_header(1, 1, "test");
        blob.extend_from_slice(&gz_buf);
        blob
    }

    #[test]
    fn extracts_named_entries_from_gz_tar_body() {
        let blob = make_cvd_blob(&[
            ("main.hdb", b"abc123:100:Eicar.Test"),
            ("daily.hsb", b"def456:200:SomeVirus"),
        ]);

        let entries = extract_entries(&blob, &ExtractLimits::default()).unwrap();
        assert_eq!(entries.len(), 2);

        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"main.hdb"));
        assert!(names.contains(&"daily.hsb"));

        let hdb = entries.iter().find(|e| e.name == "main.hdb").unwrap();
        assert_eq!(&hdb.data, b"abc123:100:Eicar.Test");
    }

    #[test]
    fn aborts_when_file_count_exceeds_limit() {
        // Create a blob with 3 entries but limit to 2.
        let blob = make_cvd_blob(&[
            ("a.hdb", b"sig1:1:Malware.A"),
            ("b.hdb", b"sig2:2:Malware.B"),
            ("c.hdb", b"sig3:3:Malware.C"),
        ]);

        let limits = ExtractLimits {
            max_files: 2,
            ..Default::default()
        };

        let result = extract_entries(&blob, &limits);
        assert!(matches!(result, Err(CvdError::BombLimit(_))));
    }
}
