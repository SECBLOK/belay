//! redb-backed CVE store: upsert and load CVEs keyed by NVD product name.

use std::path::Path;

use redb::{Database, ReadableDatabase, TableDefinition};

use super::nvd_parse::StoredCve;

// ---------------------------------------------------------------------------
// Table definition
// ---------------------------------------------------------------------------

/// Table mapping `product_name -> JSON-encoded Vec<StoredCve>`.
const CVES_BY_PRODUCT: TableDefinition<&str, &[u8]> = TableDefinition::new("cves_by_product");

// ---------------------------------------------------------------------------
// NvdStore
// ---------------------------------------------------------------------------

/// Handle to the local NVD CVE database.
pub struct NvdStore {
    db: Database,
}

impl NvdStore {
    /// Open (or create) the redb database at `path`.
    pub fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let db = Database::create(path)?;
        Ok(Self { db })
    }
}

// ---------------------------------------------------------------------------
// upsert_cve
// ---------------------------------------------------------------------------

/// Upsert `cve` under `product` in the store.
///
/// If an entry for `product` already exists, the existing list is loaded,
/// any entry with the same `cve_id` is replaced, and the result is written
/// back. If no existing entry is found the CVE is inserted as the sole entry.
pub fn upsert_cve(
    store: &NvdStore,
    product: &str,
    cve: StoredCve,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load existing records for this product (may be empty on fresh store).
    let mut existing = load_product(store, product)?;

    // Replace or append.
    match existing.iter().position(|c| c.cve_id == cve.cve_id) {
        Some(idx) => existing[idx] = cve,
        None => existing.push(cve),
    }

    let bytes = serde_json::to_vec(&existing)?;

    let write_txn = store.db.begin_write()?;
    {
        let mut table = write_txn.open_table(CVES_BY_PRODUCT)?;
        table.insert(product, bytes.as_slice())?;
    }
    write_txn.commit()?;

    Ok(())
}

// ---------------------------------------------------------------------------
// load_product
// ---------------------------------------------------------------------------

/// Load all stored CVEs for `product`.
///
/// Returns an empty `Vec` if the table does not yet exist (fresh database) or
/// if no entry for `product` is found.
pub fn load_product(
    store: &NvdStore,
    product: &str,
) -> Result<Vec<StoredCve>, Box<dyn std::error::Error>> {
    let read_txn = store.db.begin_read()?;

    let table = match read_txn.open_table(CVES_BY_PRODUCT) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };

    match table.get(product)? {
        None => Ok(vec![]),
        Some(guard) => {
            let bytes = guard.value();
            let records: Vec<StoredCve> = serde_json::from_slice(bytes)?;
            Ok(records)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests for 15.3
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vuln::nvd::CpeMatch;

    fn make_stored_cve(id: &str, product: &str) -> StoredCve {
        StoredCve {
            cve_id: id.to_string(),
            description: "test".to_string(),
            cvss3_score: Some(7.5),
            cvss3_severity: "HIGH".to_string(),
            cwe_id: "CWE-79".to_string(),
            is_kev: false,
            cpe_matches: vec![CpeMatch {
                product: product.to_string(),
                exact_version: None,
                version_start: None,
                version_start_including: false,
                version_end: None,
                version_end_including: false,
            }],
        }
    }

    #[test]
    fn upsert_then_load_round_trips_and_fresh_store_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = NvdStore::open(&dir.path().join("t.redb")).unwrap();
        assert!(load_product(&store, "nginx").unwrap().is_empty());
        upsert_cve(&store, "nginx", make_stored_cve("CVE-2022-0001", "nginx")).unwrap();
        let got = load_product(&store, "nginx").unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].cve_id, "CVE-2022-0001");
    }
}
