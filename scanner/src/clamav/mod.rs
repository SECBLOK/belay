//! ClamAV-format support (clean-room implementation).
//!
//! These parsers read ClamAV's publicly documented on-disk *formats*: the
//! 512-byte CVD container header and the hash-signature line formats
//! (`MD5:size:name`, `SHA256:size:name`, `.hdb`/`.hsb`). They are an
//! INDEPENDENT Rust implementation written from the format documentation and
//! the observed byte layout — they are NOT derived from, and NOT a translation
//! of, ClamAV's GPL-2.0 source code (e.g. `cvd.c`, `readdb.c`,
//! `matcher-hash.c`). No ClamAV source, struct layouts, constant tables, or
//! comments are copied, and no ClamAV signature database is bundled.
//!
//! A file format is a functional fact, not copyrightable expression, so an
//! independent reimplementation carries no GPL-2.0 obligation. This module is
//! therefore distributable under the project's AGPL-3.0-or-later license.
pub mod cvd;
pub mod sigdb;
