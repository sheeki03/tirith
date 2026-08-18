//! Trusted issuer keys for task-authorization receipt v2.
//!
//! This keyring is intentionally separate from command-card approval trust.
//! Gateway receipt verification reads only this owner-controlled file and never
//! consults repository configuration, request metadata, or environment keys.

use std::collections::BTreeMap;
use std::fmt;
#[cfg(unix)]
use std::fs::File;
use std::io::Read as _;
use std::path::Path;

#[cfg(test)]
use std::path::PathBuf;

use serde::Deserialize;

const KEYRING_FILENAME: &str = "task-receipt-issuers.json";
const KEYRING_SCHEMA_VERSION: u16 = 1;
const KEYRING_READ_CAP: u64 = 256 * 1024;

#[derive(Debug)]
pub(crate) enum TrustedReceiptKeyringError {
    StateDirectoryUnavailable,
    UnsafePermissions,
    InvalidFile,
    ReadFailed,
    Malformed,
    InvalidKey,
    #[cfg(not(unix))]
    UnsupportedPlatform,
}

impl fmt::Display for TrustedReceiptKeyringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::StateDirectoryUnavailable => {
                "trusted receipt issuer state directory is unavailable"
            }
            Self::UnsafePermissions => {
                "trusted receipt issuer keyring has unsafe ownership or permissions"
            }
            Self::InvalidFile => "trusted receipt issuer keyring is not a bounded regular file",
            Self::ReadFailed => "trusted receipt issuer keyring could not be read safely",
            Self::Malformed => "trusted receipt issuer keyring is malformed",
            Self::InvalidKey => "trusted receipt issuer keyring contains an invalid issuer key",
            #[cfg(not(unix))]
            Self::UnsupportedPlatform => {
                "trusted receipt issuer keyring is unsupported on this platform"
            }
        })
    }
}

impl std::error::Error for TrustedReceiptKeyringError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringWire {
    schema_version: u16,
    issuers: BTreeMap<String, String>,
}

/// Immutable trusted issuer keys loaded through an owner-only, no-follow file
/// boundary. Missing keyring means no trusted issuers, not a fallback to another
/// trust store.
pub(crate) struct TrustedReceiptIssuerKeyring {
    keys: BTreeMap<String, [u8; 32]>,
}

impl TrustedReceiptIssuerKeyring {
    pub(crate) fn load_default() -> Result<Self, TrustedReceiptKeyringError> {
        let state = tirith_core::policy::state_dir()
            .ok_or(TrustedReceiptKeyringError::StateDirectoryUnavailable)?;
        Self::load_path(&state.join(KEYRING_FILENAME))
    }

    pub(crate) fn keys(&self) -> &BTreeMap<String, [u8; 32]> {
        &self.keys
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub(crate) fn issuer_key_ids(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }

    fn load_path(path: &Path) -> Result<Self, TrustedReceiptKeyringError> {
        load_owner_only_keyring(path)
    }

    #[cfg(test)]
    pub(crate) fn load_for_test(path: PathBuf) -> Result<Self, TrustedReceiptKeyringError> {
        Self::load_path(&path)
    }
}

#[cfg(unix)]
fn load_owner_only_keyring(
    path: &Path,
) -> Result<TrustedReceiptIssuerKeyring, TrustedReceiptKeyringError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Component;

    let expected_uid = unsafe { libc::geteuid() };
    if !path.is_absolute() {
        return Err(TrustedReceiptKeyringError::UnsafePermissions);
    }
    let parent = path
        .parent()
        .ok_or(TrustedReceiptKeyringError::InvalidFile)?;
    let file_name = path
        .file_name()
        .ok_or(TrustedReceiptKeyringError::InvalidFile)?;

    let root_name = CString::new("/").expect("root path contains no NUL");
    let root_fd = unsafe {
        libc::open(
            root_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(TrustedReceiptKeyringError::ReadFailed);
    }
    let mut directory = unsafe { File::from_raw_fd(root_fd) };
    validate_keyring_directory(&directory, expected_uid, parent == Path::new("/"))?;

    let normal_components = parent.components().filter_map(|component| match component {
        Component::RootDir => None,
        Component::Normal(component) => Some(Ok(component)),
        Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
            Some(Err(TrustedReceiptKeyringError::UnsafePermissions))
        }
    });
    let components = normal_components.collect::<Result<Vec<_>, _>>()?;
    for (index, component) in components.iter().enumerate() {
        let component = CString::new(component.as_bytes())
            .map_err(|_| TrustedReceiptKeyringError::InvalidFile)?;
        let next_fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next_fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(TrustedReceiptIssuerKeyring {
                    keys: BTreeMap::new(),
                });
            }
            return Err(TrustedReceiptKeyringError::UnsafePermissions);
        }
        let next = unsafe { File::from_raw_fd(next_fd) };
        validate_keyring_directory(&next, expected_uid, index + 1 == components.len())?;
        directory = next;
    }

    let file_name =
        CString::new(file_name.as_bytes()).map_err(|_| TrustedReceiptKeyringError::InvalidFile)?;
    let file_fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            file_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if file_fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(TrustedReceiptIssuerKeyring {
                keys: BTreeMap::new(),
            });
        }
        return Err(TrustedReceiptKeyringError::InvalidFile);
    }
    let mut file = unsafe { File::from_raw_fd(file_fd) };
    let metadata = file
        .metadata()
        .map_err(|_| TrustedReceiptKeyringError::ReadFailed)?;
    if !metadata.is_file() || metadata.len() > KEYRING_READ_CAP || metadata.nlink() != 1 {
        return Err(TrustedReceiptKeyringError::InvalidFile);
    }
    if metadata.uid() != expected_uid || metadata.mode() & 0o077 != 0 {
        return Err(TrustedReceiptKeyringError::UnsafePermissions);
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(KEYRING_READ_CAP + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TrustedReceiptKeyringError::ReadFailed)?;
    if bytes.len() as u64 > KEYRING_READ_CAP {
        return Err(TrustedReceiptKeyringError::InvalidFile);
    }
    parse_keyring(&bytes)
}

#[cfg(unix)]
fn validate_keyring_directory(
    directory: &File,
    expected_uid: u32,
    is_keyring_parent: bool,
) -> Result<(), TrustedReceiptKeyringError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = directory
        .metadata()
        .map_err(|_| TrustedReceiptKeyringError::ReadFailed)?;
    if !metadata.is_dir() {
        return Err(TrustedReceiptKeyringError::InvalidFile);
    }
    let owner_is_trusted = metadata.uid() == expected_uid || metadata.uid() == 0;
    let root_sticky_directory = metadata.uid() == 0
        && metadata.mode() & libc::S_ISVTX as u32 != 0
        && metadata.mode() & 0o022 != 0;
    if !owner_is_trusted || (metadata.mode() & 0o022 != 0 && !root_sticky_directory) {
        return Err(TrustedReceiptKeyringError::UnsafePermissions);
    }
    if is_keyring_parent && (metadata.uid() != expected_uid || metadata.mode() & 0o077 != 0) {
        return Err(TrustedReceiptKeyringError::UnsafePermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn load_owner_only_keyring(
    _path: &Path,
) -> Result<TrustedReceiptIssuerKeyring, TrustedReceiptKeyringError> {
    Err(TrustedReceiptKeyringError::UnsupportedPlatform)
}

fn parse_keyring(bytes: &[u8]) -> Result<TrustedReceiptIssuerKeyring, TrustedReceiptKeyringError> {
    let text = std::str::from_utf8(bytes).map_err(|_| TrustedReceiptKeyringError::Malformed)?;
    let value = tirith_core::mcp_lock::parse_json_no_duplicates(text)
        .map_err(|_| TrustedReceiptKeyringError::Malformed)?;
    let wire: KeyringWire =
        serde_json::from_value(value).map_err(|_| TrustedReceiptKeyringError::Malformed)?;
    if wire.schema_version != KEYRING_SCHEMA_VERSION || wire.issuers.len() > 256 {
        return Err(TrustedReceiptKeyringError::Malformed);
    }

    let mut keys = BTreeMap::new();
    for (declared_id, encoded) in wire.issuers {
        let decoded = tirith_core::command_card::hex_decode(&encoded)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            .ok_or(TrustedReceiptKeyringError::InvalidKey)?;
        if ed25519_dalek::VerifyingKey::from_bytes(&decoded).is_err()
            || tirith_core::command_card::key_id_for_pubkey(&decoded) != declared_id
        {
            return Err(TrustedReceiptKeyringError::InvalidKey);
        }
        keys.insert(declared_id, decoded);
    }
    Ok(TrustedReceiptIssuerKeyring { keys })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[cfg(unix)]
    fn write_keyring(path: &Path, value: &serde_json::Value) {
        use std::os::unix::fs::PermissionsExt as _;
        let mut file = File::create(path).unwrap();
        file.write_all(serde_json::to_string(value).unwrap().as_bytes())
            .unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(unix)]
    fn make_owner_private(path: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn loads_only_owner_private_self_identifying_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::fs::canonicalize(dir.path())
            .unwrap()
            .join(KEYRING_FILENAME);
        make_owner_private(path.parent().unwrap());
        let public = ed25519_dalek::SigningKey::from_bytes(&[17_u8; 32])
            .verifying_key()
            .to_bytes();
        let key_id = tirith_core::command_card::key_id_for_pubkey(&public);
        write_keyring(
            &path,
            &serde_json::json!({
                "schema_version": 1,
                "issuers": { (key_id.clone()): tirith_core::command_card::hex_encode(&public) }
            }),
        );
        let loaded = TrustedReceiptIssuerKeyring::load_for_test(path).unwrap();
        assert_eq!(loaded.keys().get(&key_id), Some(&public));
    }

    #[test]
    #[cfg(unix)]
    fn rejects_symlink_and_group_readable_keyrings() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        make_owner_private(&root);
        let target = root.join("target.json");
        write_keyring(
            &target,
            &serde_json::json!({"schema_version": 1, "issuers": {}}),
        );
        let link = root.join(KEYRING_FILENAME);
        symlink(&target, &link).unwrap();
        assert!(matches!(
            TrustedReceiptIssuerKeyring::load_for_test(link),
            Err(TrustedReceiptKeyringError::InvalidFile)
        ));

        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            TrustedReceiptIssuerKeyring::load_for_test(target),
            Err(TrustedReceiptKeyringError::UnsafePermissions)
        ));
    }

    #[test]
    #[cfg(unix)]
    fn rejects_symlinked_or_non_private_keyring_parent() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let real_parent = root.join("repo-controlled-state");
        std::fs::create_dir(&real_parent).unwrap();
        std::fs::set_permissions(&real_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        write_keyring(
            &real_parent.join(KEYRING_FILENAME),
            &serde_json::json!({"schema_version": 1, "issuers": {}}),
        );

        let linked_parent = root.join("tirith");
        symlink(&real_parent, &linked_parent).unwrap();
        assert!(matches!(
            TrustedReceiptIssuerKeyring::load_for_test(linked_parent.join(KEYRING_FILENAME)),
            Err(TrustedReceiptKeyringError::UnsafePermissions)
        ));

        let loose_parent = root.join("loose-state");
        std::fs::create_dir(&loose_parent).unwrap();
        std::fs::set_permissions(&loose_parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        write_keyring(
            &loose_parent.join(KEYRING_FILENAME),
            &serde_json::json!({"schema_version": 1, "issuers": {}}),
        );
        assert!(matches!(
            TrustedReceiptIssuerKeyring::load_for_test(loose_parent.join(KEYRING_FILENAME)),
            Err(TrustedReceiptKeyringError::UnsafePermissions)
        ));
    }

    #[test]
    #[cfg(unix)]
    fn absent_keyring_is_an_explicit_empty_trust_set() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        make_owner_private(&root);
        let loaded =
            TrustedReceiptIssuerKeyring::load_for_test(root.join(KEYRING_FILENAME)).unwrap();
        assert!(loaded.is_empty());
        assert!(loaded.issuer_key_ids().is_empty());
    }
}
