//! Shared native filesystem and executable-identity checks for both sides of
//! the package-approval authority boundary.

use std::fmt;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::path::{Path, PathBuf};

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

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
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
