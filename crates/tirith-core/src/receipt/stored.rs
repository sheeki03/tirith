//! Bounded read-only receipt inventory and cached-download verification.
//! These functions return stored records, never signing or execution authority.
use super::{ArtifactScanReceipt, Receipt};
use crate::util::dirfd::{file_generation, DirCapability};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::io::Read;

const MAX_RECEIPT_BYTES: u64 = 1024 * 1024;
const MAX_INVENTORY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;
// Matches the remote-script download producer's accepted body ceiling.
const MAX_CACHED_SCRIPT_BYTES: u64 = 10 * 1024 * 1024;

pub fn load_download(id: &str) -> Result<Receipt, &'static str> {
    load(id, |receipt: &Receipt| &receipt.sha256)
}
pub fn list_download() -> Result<Vec<Receipt>, &'static str> {
    list(|receipt: &Receipt| &receipt.sha256)
}
pub fn load_artifact(id: &str) -> Result<ArtifactScanReceipt, &'static str> {
    load(id, |receipt: &ArtifactScanReceipt| &receipt.receipt_id)
}
pub fn list_artifact() -> Result<Vec<ArtifactScanReceipt>, &'static str> {
    list(|receipt: &ArtifactScanReceipt| &receipt.receipt_id)
}

pub fn verify_download(receipt: &Receipt) -> Result<bool, &'static str> {
    if !valid_id(&receipt.sha256) {
        return Err(
            "invalid sha256: expected 64 lowercase hexadecimal characters for cached content.",
        );
    }
    let Some(directory) = directory("cache")? else {
        return Ok(false);
    };
    let mut file =
        match directory.open_child_file(&receipt.sha256, MAX_CACHED_SCRIPT_BYTES) {
            Ok(file) => file,
            Err(crate::util::OpenRegularError::NotFound) => return Ok(false),
            Err(_) => return Err(
                "Cached content is unreadable, not a regular file, or exceeds the download limit.",
            ),
        };
    let before = file_generation(&file).map_err(|_| "Cached content identity is unavailable.")?;
    let mut reader = (&mut file).take(MAX_CACHED_SCRIPT_BYTES + 1);
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    let mut total = 0;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| "Cached content could not be read completely.")?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > MAX_CACHED_SCRIPT_BYTES {
            return Err("Cached content exceeds the download limit.");
        }
        hash.update(&buffer[..count]);
    }
    if total != before.size
        || file_generation(&file).map_err(|_| "Cached content identity is unavailable.")? != before
    {
        return Err("Cached content changed during verification.");
    }
    let visible = directory
        .open_child_file(&receipt.sha256, MAX_CACHED_SCRIPT_BYTES)
        .map_err(|_| "Cached content changed during verification.")?;
    if file_generation(&visible).map_err(|_| "Cached content identity is unavailable.")? != before {
        return Err("Cached content changed during verification.");
    }
    Ok(hex::encode(hash.finalize()) == receipt.sha256)
}

fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn directory(leaf: &str) -> Result<Option<DirCapability>, &'static str> {
    let path = crate::policy::data_dir()
        .ok_or("Receipt storage is unavailable.")?
        .join(leaf);
    match DirCapability::open_root(&path) {
        Ok(directory) => Ok(Some(directory)),
        Err(_)
            if std::fs::symlink_metadata(&path)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(_) => Err("Receipt storage is unreadable or its native identity is unavailable."),
    }
}

fn read(directory: &DirCapability, name: &str) -> Result<Vec<u8>, &'static str> {
    let mut file = directory
        .open_child_file(name, MAX_RECEIPT_BYTES)
        .map_err(|_| "Receipt is unreadable, not a regular file, or exceeds the read limit.")?;
    let before = file_generation(&file).map_err(|_| "Receipt identity is unavailable.")?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Receipt could not be read completely.")?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES
        || file_generation(&file).map_err(|_| "Receipt identity is unavailable.")? != before
    {
        return Err("Receipt changed during reading or exceeds the read limit.");
    }
    Ok(bytes)
}

fn load<T: DeserializeOwned>(
    id: &str,
    identity: impl FnOnce(&T) -> &str,
) -> Result<T, &'static str> {
    if !valid_id(id) {
        return Err("invalid sha256 receipt ID: expected 64 lowercase hexadecimal characters.");
    }
    let directory = directory("receipts")?.ok_or("Receipt storage is absent.")?;
    let bytes = read(&directory, &format!("{id}.json"))?;
    let receipt: T = serde_json::from_slice(&bytes)
        .map_err(|_| "Receipt has an unsupported or invalid format.")?;
    if identity(&receipt) != id {
        return Err(
            "Receipt identity mismatch: stored content does not match the requested identity.",
        );
    }
    Ok(receipt)
}

fn list<T: DeserializeOwned>(identity: impl Fn(&T) -> &str) -> Result<Vec<T>, &'static str> {
    let Some(directory) = directory("receipts")? else {
        return Ok(Vec::new());
    };
    let (entries, truncated) = directory
        .read_entries(MAX_ENTRIES)
        .map_err(|_| "Receipt inventory could not be read.")?;
    if truncated {
        return Err("Receipt inventory exceeds the entry limit; select a receipt by ID.");
    }
    let mut receipts = Vec::new();
    let mut total = 0;
    for entry in entries {
        let Some(name) = entry.name else {
            continue;
        };
        let Some(id) = name.strip_suffix(".json").filter(|id| valid_id(id)) else {
            continue;
        };
        let bytes = read(&directory, &name)?;
        total += bytes.len() as u64;
        if total > MAX_INVENTORY_BYTES {
            return Err("Receipt inventory exceeds the byte limit; select a receipt by ID.");
        }
        // Multiple receipt schemas share this private directory. A different
        // kind is not a corrupted receipt of the requested kind.
        if let Ok(receipt) = serde_json::from_slice::<T>(&bytes) {
            if identity(&receipt) != id {
                return Err(
                    "Receipt inventory identity mismatch: stored content does not match its filename.",
                );
            }
            receipts.push(receipt);
        } else if serde_json::from_slice::<Receipt>(&bytes).is_err()
            && serde_json::from_slice::<ArtifactScanReceipt>(&bytes).is_err()
        {
            return Err("Receipt inventory contains an invalid or unsupported record; select a receipt by ID.");
        }
    }
    Ok(receipts)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_receipt() -> Receipt {
        serde_json::from_value(serde_json::json!({
            "url":"https://example.test/install", "final_url":null, "redirects":[],
            "sha256":"a".repeat(64), "size":3,"domains_referenced":[],"paths_referenced":[],
            "analysis_method":"static","privilege":"user","timestamp":"2026-09-12T00:00:00Z",
            "cwd":null,"git_repo":null,"git_branch":null
        }))
        .unwrap()
    }
    #[test]
    fn edited_ids_cannot_select_or_substitute_receipts() {
        let fixture = tempfile::tempdir().unwrap();
        let mut environment = tirith_test_support::GlobalStateGuard::new().unwrap();
        environment.set_env("XDG_DATA_HOME", fixture.path());
        environment.set_env("LOCALAPPDATA", fixture.path());
        environment.set_env("APPDATA", fixture.path());
        let dir = crate::policy::data_dir().unwrap().join("receipts");
        std::fs::create_dir_all(&dir).unwrap();
        assert!(load::<Receipt>("../../secret", |r| &r.sha256).is_err());
        let receipt = test_receipt();
        let id = "b".repeat(64);
        std::fs::write(
            dir.join(format!("{id}.json")),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        assert!(load::<Receipt>(&id, |r| &r.sha256)
            .unwrap_err()
            .contains("identity"));
        assert!(list::<Receipt>(|r| &r.sha256)
            .unwrap_err()
            .contains("identity"));
    }

    #[test]
    fn invalid_inventory_is_not_reported_as_an_empty_history() {
        let _environment = tirith_test_support::GlobalStateGuard::new().unwrap();
        let directory = crate::policy::data_dir().unwrap().join("receipts");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(format!("{}.json", "a".repeat(64)));
        std::fs::write(&path, br#"{"unsupported_secret":"never-print-this"}"#).unwrap();
        let error = list_download().unwrap_err();
        assert!(error.contains("invalid or unsupported"));
        assert!(!error.contains("never-print-this"));
        std::fs::write(&path, b"invalid JSON").unwrap();
        assert!(list_artifact().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn receipt_reader_refuses_symlinks_and_oversized_files() {
        use std::os::unix::fs::symlink;
        let fixture = tempfile::tempdir().unwrap();
        let root = DirCapability::open_root(fixture.path()).unwrap();
        std::fs::write(fixture.path().join("real.json"), b"{}").unwrap();
        symlink("real.json", fixture.path().join("alias.json")).unwrap();
        assert!(read(&root, "alias.json").is_err());
        let file = std::fs::File::create(fixture.path().join("large.json")).unwrap();
        file.set_len(MAX_RECEIPT_BYTES + 1).unwrap();
        assert!(read(&root, "large.json").is_err());
    }
    #[test]
    fn cached_verification_is_bounded_and_checks_original_content() {
        let _environment = tirith_test_support::GlobalStateGuard::new().unwrap();
        let mut receipt = test_receipt();
        receipt.sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into();
        assert!(!verify_download(&receipt).unwrap());
        let directory = crate::policy::data_dir().unwrap().join("cache");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(&receipt.sha256);
        std::fs::write(&path, b"abc").unwrap();
        assert!(verify_download(&receipt).unwrap());
        std::fs::write(&path, b"abd").unwrap();
        assert!(!verify_download(&receipt).unwrap());
        std::fs::File::create(&path)
            .unwrap()
            .set_len(MAX_CACHED_SCRIPT_BYTES + 1)
            .unwrap();
        assert!(verify_download(&receipt).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            std::fs::remove_file(&path).unwrap();
            let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            // SAFETY: name is NUL-terminated, mode contains ordinary owner permissions.
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            assert!(verify_download(&receipt).is_err());
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink("missing", &path).unwrap();
            assert!(verify_download(&receipt).is_err());
        }
    }
}
