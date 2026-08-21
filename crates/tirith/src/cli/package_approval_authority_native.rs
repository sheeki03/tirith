//! Shared native filesystem and executable-identity checks for both sides of
//! the package-approval authority boundary.

use std::fmt;

#[cfg(unix)]
use std::collections::BTreeMap;
#[cfg(unix)]
use std::io::Read as _;
#[cfg(unix)]
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
pub(crate) const TRUSTED_KEYS_PATH: &str =
    "/Library/Application Support/Tirith/package-approval/trusted-keys";
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) const TRUSTED_KEYS_PATH: &str = "/etc/tirith/package-approval/trusted-keys";

#[cfg(unix)]
const PUBLIC_KEY_CAP: u64 = 128;
#[cfg(unix)]
const MAX_TRUSTED_KEYS: usize = 32;

#[derive(Debug)]
pub(crate) struct NativeAuthorityError(String);

impl NativeAuthorityError {
    pub(crate) fn blocked(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

impl fmt::Display for NativeAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "blocked_native: {}", self.0)
    }
}

impl std::error::Error for NativeAuthorityError {}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) fn validate_root_owned_executable(path: &Path) -> Result<(), NativeAuthorityError> {
    use std::os::unix::fs::MetadataExt as _;

    validate_admin_hierarchy(path.parent().unwrap_or(Path::new("/")), 0)?;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| NativeAuthorityError::blocked("native authority executable is unavailable"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
        || metadata.nlink() != 1
    {
        return Err(NativeAuthorityError::blocked(
            "native authority executable identity or permissions are unsafe",
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn validate_admin_hierarchy(
    path: &Path,
    expected_uid: u32,
) -> Result<(), NativeAuthorityError> {
    use std::os::unix::fs::MetadataExt as _;

    if !path.is_absolute() {
        return Err(NativeAuthorityError::blocked(
            "native authority path is not absolute",
        ));
    }
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        current.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&current).map_err(|_| {
            NativeAuthorityError::blocked("native authority hierarchy is unavailable")
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != expected_uid
            || metadata.mode() & 0o022 != 0
        {
            return Err(NativeAuthorityError::blocked(
                "native authority hierarchy is not administrator-protected",
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn load_trusted_keys(
    directory: &Path,
    expected_uid: u32,
) -> Result<BTreeMap<String, [u8; 32]>, NativeAuthorityError> {
    use std::os::unix::fs::MetadataExt as _;

    validate_admin_hierarchy(directory, expected_uid)?;
    let entries = std::fs::read_dir(directory)
        .map_err(|_| NativeAuthorityError::blocked("trusted authority keyring is unavailable"))?;
    let mut paths = Vec::new();
    for entry in entries {
        paths.push(
            entry
                .map_err(|_| NativeAuthorityError::blocked("trusted authority keyring changed"))?
                .path(),
        );
        if paths.len() > MAX_TRUSTED_KEYS {
            return Err(NativeAuthorityError::blocked(
                "trusted authority keyring exceeds its key limit",
            ));
        }
    }
    paths.sort();

    let mut keys = BTreeMap::new();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".pub"))
            .filter(|name| {
                name.len() == 16
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
            .ok_or_else(|| {
                NativeAuthorityError::blocked("trusted authority keyring contains an invalid entry")
            })?;
        let mut file = open_no_follow(&path, PUBLIC_KEY_CAP)?;
        let metadata = file.metadata().map_err(|_| {
            NativeAuthorityError::blocked("trusted authority key metadata is unavailable")
        })?;
        if metadata.uid() != expected_uid || metadata.mode() & 0o022 != 0 || metadata.nlink() != 1 {
            return Err(NativeAuthorityError::blocked(
                "trusted authority key permissions are unsafe",
            ));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|_| {
            NativeAuthorityError::blocked("trusted authority key could not be read")
        })?;
        let public: [u8; 32] = bytes.try_into().map_err(|_| {
            NativeAuthorityError::blocked("trusted authority public key has the wrong size")
        })?;
        if ed25519_dalek::VerifyingKey::from_bytes(&public).is_err()
            || tirith_core::command_card::key_id_for_pubkey(&public) != name
        {
            return Err(NativeAuthorityError::blocked(
                "trusted authority public key is invalid or mislabeled",
            ));
        }
        keys.insert(name.to_string(), public);
    }
    if keys.is_empty() {
        return Err(NativeAuthorityError::blocked(
            "trusted package approval authority has no installed public key",
        ));
    }
    Ok(keys)
}

#[cfg(unix)]
pub(crate) fn open_no_follow(path: &Path, cap: u64) -> Result<std::fs::File, NativeAuthorityError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| NativeAuthorityError::blocked("native authority file could not be opened"))?;
    let metadata = file
        .metadata()
        .map_err(|_| NativeAuthorityError::blocked("native authority file metadata failed"))?;
    if !metadata.is_file() || metadata.len() > cap {
        return Err(NativeAuthorityError::blocked(
            "native authority file is not a bounded regular file",
        ));
    }
    Ok(file)
}
