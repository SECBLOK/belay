//! Bounded archive extraction: zip / tar / gzip (and tar.gz), zip-bomb-guarded.
//!
//! Pure Rust, no shell-outs — used by `analyzers::malware::scan_malware_pass`
//! to recurse the byte-level malware pass into archive members instead of
//! hash/YARA-scanning the compressed container bytes directly. Findings on
//! inner members reference `outer_path!/inner_path` (see the `!/` separator
//! convention documented on [`extract_bounded`]'s caller in `malware.rs`).
//!
//! # Zip-bomb guard
//! [`extract_bounded`] bounds both the *number* of members extracted
//! (`max_files`) and the cumulative *bytes* extracted (`max_total`), using
//! `saturating_add` throughout (mirrors the guard already used by
//! `resolve::extract_zip` and `analyzers::malware::scan_malware_pass`, see
//! commit 92e1581). Critically, a member's declared size (from a zip central
//! directory entry or tar header) is untrusted: even after that declared size
//! passes the budget check, the actual read is *also* capped at the
//! remaining budget via `Read::take`, so a member whose header lies about
//! being small cannot decompress an unbounded amount of data into memory.

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// True if `bytes` looks like a zip, tar, or gzip archive by magic-byte
/// sniffing (`infer`), independent of any file extension. Used by
/// `analyzers::malware::scan_malware_pass` to route a file to
/// [`extract_bounded`] instead of hash/YARA-scanning it directly — a renamed
/// archive (e.g. zip bytes saved as `payload.dat`) must still be recursed
/// into, exactly like the rest of the malware pass never trusts a file
/// extension (see that module's doc comment).
pub fn is_archive_bytes(bytes: &[u8]) -> bool {
    infer::archive::is_zip(bytes) || infer::archive::is_tar(bytes) || infer::archive::is_gz(bytes)
}

/// Which container format an archive file was identified as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContainerKind {
    Zip,
    Tar,
    Gz,
}

/// Read up to `n` bytes from the start of `path`. Used to independently
/// re-check the raw zip magic bytes in [`detect_container_kind`]'s fallback
/// below, since `infer::get_from_path` only ever hands back its single
/// winning matcher's `Type`, not the underlying bytes it sniffed.
fn read_head(path: &Path, n: u64) -> std::io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut buf = Vec::new();
    file.take(n).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Identify `path`'s container format. Magic bytes first (`infer::get_from_path`,
/// which sniffs up to 8 KiB), falling back to the file extension only when
/// magic sniffing is inconclusive (e.g. a tiny/truncated file with too few
/// bytes for a magic match).
fn detect_container_kind(path: &Path) -> Option<ContainerKind> {
    if let Ok(Some(ty)) = infer::get_from_path(path) {
        match ty.mime_type() {
            "application/zip" => return Some(ContainerKind::Zip),
            "application/x-tar" => return Some(ContainerKind::Tar),
            "application/gzip" => return Some(ContainerKind::Gz),
            _ => {}
        }
    }

    // Zip-based document container fallback: `infer::get_from_path` returns
    // only the FIRST matcher that fires, and infer registers its OOXML/ODF/
    // EPUB document matchers before the generic zip matcher — so a real
    // `.docx`/`.xlsx`/`.pptx`/`.odt`/`.epub` (all zip containers under the
    // hood) resolves to a document MIME above, never `application/zip`, and
    // the exact-MIME match falls through to `_ => {}`. That must not mean
    // "not an archive": re-read the head bytes directly and check the raw
    // zip magic, independent of which document type infer decided this is,
    // so these containers still get extracted and their members scanned
    // instead of the whole file silently evading the malware pass.
    if let Ok(head) = read_head(path, 8192) {
        if infer::archive::is_zip(&head) {
            return Some(ContainerKind::Zip);
        }
    }

    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.ends_with(".zip") {
        Some(ContainerKind::Zip)
    } else if name.ends_with(".tar") {
        Some(ContainerKind::Tar)
    } else if name.ends_with(".gz") || name.ends_with(".tgz") {
        Some(ContainerKind::Gz)
    } else {
        None
    }
}

/// Extract archive members into memory, bounded. Returns `(inner_relative_path,
/// bytes)` pairs. Enforces `max_files` and cumulative `max_total` bytes
/// (zip-bomb guard). Never panics on a malformed archive — returns whatever
/// it safely extracted (possibly empty). No shell-out.
pub fn extract_bounded(path: &Path, max_files: usize, max_total: u64) -> Vec<(String, Vec<u8>)> {
    let kind = match detect_container_kind(path) {
        Some(k) => k,
        None => return Vec::new(),
    };

    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    match kind {
        ContainerKind::Zip => extract_zip_bounded(file, max_files, max_total),
        ContainerKind::Tar => extract_tar_bounded(file, max_files, max_total),
        ContainerKind::Gz => extract_gz_bounded(path, file, max_files, max_total),
    }
}

/// Reject any tar/zip member path that is absolute or escapes the archive
/// root via a `..` component. Zip uses `ZipFile::enclosed_name()` for this
/// (see below); tar has no equivalent built-in check on the in-memory path
/// returned by `Entry::path()`, so this helper covers both.
fn is_safe_relative(p: &Path) -> bool {
    !p.is_absolute()
        && !p
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
}

/// Bounded zip extraction. `reader` must be `Read + Seek` (zip's central
/// directory is read from the end of the stream), which a plain `File` is.
fn extract_zip_bounded<R: Read + std::io::Seek>(
    reader: R,
    max_files: usize,
    max_total: u64,
) -> Vec<(String, Vec<u8>)> {
    let mut pairs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut total: u64 = 0;

    let mut zf = match zip::ZipArchive::new(reader) {
        Ok(z) => z,
        Err(_) => return pairs, // malformed archive: fail-soft, no panic
    };

    for i in 0..zf.len() {
        if pairs.len() >= max_files {
            break;
        }

        let mut member = match zf.by_index(i) {
            Ok(m) => m,
            Err(_) => continue, // fail-soft per-member
        };

        if member.is_dir() {
            continue;
        }

        // Zip-slip guard: `enclosed_name()` returns `None` for any entry
        // whose name is absolute or escapes the root via `..` (mirrors
        // `resolve::extract_zip`).
        let safe_rel = match member.enclosed_name() {
            Some(p) => p.to_string_lossy().replace('\\', "/"),
            None => continue,
        };

        // Bomb guard: the member's declared (uncompressed) size is
        // untrusted, but it's still the first line of defense — a header
        // that honestly declares a size that would blow the remaining
        // budget stops the whole pass rather than being partially read.
        let declared_len = member.size();
        if total.saturating_add(declared_len) > max_total {
            break;
        }

        // Second line of defense: cap the actual read at the remaining
        // budget regardless of what the header claimed, so a lying header
        // cannot OOM us.
        let remaining = max_total.saturating_sub(total);
        let mut buf = Vec::new();
        if (&mut member).take(remaining).read_to_end(&mut buf).is_err() {
            continue; // fail-soft per-member
        }

        total += buf.len() as u64;
        pairs.push((safe_rel, buf));
    }

    pairs
}

/// Bounded tar extraction. `reader` only needs `Read` (streaming — used both
/// for a bare `.tar` file and for a `.tar.gz` stream piped through
/// `GzDecoder`).
fn extract_tar_bounded<R: Read>(
    reader: R,
    max_files: usize,
    max_total: u64,
) -> Vec<(String, Vec<u8>)> {
    let mut pairs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut total: u64 = 0;

    let mut archive = tar::Archive::new(reader);
    let entries = match archive.entries() {
        Ok(e) => e,
        Err(_) => return pairs, // malformed archive: fail-soft, no panic
    };

    for entry in entries {
        if pairs.len() >= max_files {
            break;
        }

        let mut entry = match entry {
            Ok(e) => e,
            Err(_) => continue, // fail-soft per-entry (e.g. truncated header)
        };

        if entry.header().entry_type().is_dir() {
            continue;
        }

        let raw_path = match entry.path() {
            Ok(p) => p.into_owned(),
            Err(_) => continue,
        };
        if !is_safe_relative(&raw_path) {
            continue; // path-traversal guard: no abs paths, no ".."
        }
        let safe_rel = raw_path.to_string_lossy().replace('\\', "/");

        let declared_len = entry.size();
        if total.saturating_add(declared_len) > max_total {
            break;
        }

        let remaining = max_total.saturating_sub(total);
        let mut buf = Vec::new();
        if (&mut entry).take(remaining).read_to_end(&mut buf).is_err() {
            continue; // fail-soft per-entry
        }

        total += buf.len() as u64;
        pairs.push((safe_rel, buf));
    }

    pairs
}

/// Bounded gzip extraction. Sniffs a bounded prefix of the decompressed
/// stream to tell tar.gz apart from a plain single-file .gz (see module
/// docs): if the decompressed bytes look like a tar (magic at offset 257),
/// re-decompress from scratch and recurse into [`extract_tar_bounded`];
/// otherwise the whole decompressed blob becomes one member named after
/// `path` with a trailing `.gz` stripped.
fn extract_gz_bounded(
    path: &Path,
    file: File,
    max_files: usize,
    max_total: u64,
) -> Vec<(String, Vec<u8>)> {
    if max_files == 0 {
        return Vec::new();
    }

    // A tar header's "ustar" magic lives at offset 257 within the first
    // 512-byte block, so 512 bytes is always enough to sniff it, bounded
    // regardless of what the gzip stream claims to decompress to.
    let mut sniff = Vec::new();
    let sniff_ok = flate2::read::GzDecoder::new(file)
        .take(512)
        .read_to_end(&mut sniff)
        .is_ok();

    if sniff_ok && infer::archive::is_tar(&sniff) {
        // The sniff reader already consumed part of the decompressed
        // stream and `GzDecoder<File>` isn't seekable, so re-open fresh.
        let fresh = match File::open(path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        return extract_tar_bounded(flate2::read::GzDecoder::new(fresh), max_files, max_total);
    }

    let fresh = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let mut buf = Vec::new();
    if flate2::read::GzDecoder::new(fresh)
        .take(max_total)
        .read_to_end(&mut buf)
        .is_err()
    {
        return Vec::new(); // fail-soft: not a valid gzip stream
    }

    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "member".to_owned());
    let member_name = name.strip_suffix(".gz").unwrap_or(&name).to_owned();

    vec![(member_name, buf)]
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// Build a zip at `path` containing `entries` (name, contents), all
    /// stored uncompressed (the crate only enables the `deflate` feature,
    /// but `Stored` needs no feature and keeps fixture bytes predictable).
    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = std::fs::File::create(path).unwrap();
        let mut zw = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, data) in entries {
            zw.start_file(*name, options).unwrap();
            zw.write_all(data).unwrap();
        }
        zw.finish().unwrap();
    }

    /// A zip whose members would exceed `max_total` in aggregate: the sum of
    /// bytes actually returned must stay within the cap, and extraction must
    /// not panic / OOM.
    #[test]
    fn extract_bounded_caps_total_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = dir.path().join("bomb.zip");

        let chunk = vec![b'A'; 100];
        let entries: Vec<(&str, &[u8])> = vec![
            ("a.bin", chunk.as_slice()),
            ("b.bin", chunk.as_slice()),
            ("c.bin", chunk.as_slice()),
            ("d.bin", chunk.as_slice()),
            ("e.bin", chunk.as_slice()),
        ];
        write_zip(&zip_path, &entries);

        let small_cap: u64 = 250; // < 5 * 100, forces the bomb guard to trip
        let extracted = extract_bounded(&zip_path, 1000, small_cap);

        let summed: u64 = extracted.iter().map(|(_, b)| b.len() as u64).sum();
        assert!(
            summed <= small_cap,
            "summed extracted bytes {summed} exceeded max_total {small_cap}"
        );
        // The guard must have actually stopped extraction short of all 5
        // members (proves this isn't vacuously true from an empty result).
        assert!(
            extracted.len() < entries.len(),
            "expected the bomb guard to stop before all {} members were extracted, got {}",
            entries.len(),
            extracted.len()
        );
    }

    /// A tar.gz round-trip: members inside the decompressed tar stream must
    /// be recovered (exercises the tar-inside-gz sniff branch).
    #[test]
    fn tar_gz_members_extracted() {
        let dir = tempfile::tempdir().unwrap();
        let tar_gz_path = dir.path().join("bundle.tar.gz");

        let gz_file = std::fs::File::create(&tar_gz_path).unwrap();
        let encoder = flate2::write::GzEncoder::new(gz_file, flate2::Compression::default());
        let mut tar_builder = tar::Builder::new(encoder);

        let data = b"hello from inside a tar.gz";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, "inner/hello.txt", &data[..])
            .unwrap();
        let encoder = tar_builder.into_inner().unwrap();
        encoder.finish().unwrap();

        let extracted = extract_bounded(&tar_gz_path, 100, 10 * 1024 * 1024);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0].0, "inner/hello.txt");
        assert_eq!(extracted[0].1, data);
    }
}
