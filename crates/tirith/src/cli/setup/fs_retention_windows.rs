//! Existing log handle denies rename/delete sharing while preserving old audit
//! writers' read/write sharing and LockFileEx serialization.
use super::*;

pub(crate) struct InPlaceLease {
    parent: ValidatedParent,
    path: PathBuf,
    file: fs::File,
    identity: (u64, u64),
}

pub(crate) fn open_existing_in_place(
    path: &Path,
    scope: &Path,
) -> Result<(fs::File, InPlaceLease), String> {
    let parent = validated_parent(path, scope, false)?.ok_or("audit parent is absent")?;
    let actual = parent
        .path
        .join(path.file_name().ok_or("audit log has no filename")?);
    let encoded = wide(&actual);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(encoded.as_ptr()),
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|error| format!("open retained audit log: {error}"))?;
    let file = OwnedHandle(handle).into_file();
    let info = handle_information(handle, &actual)?;
    if !path_rules::attributes_are_safe(info.dwFileAttributes, false)
        || info.nNumberOfLinks != 1
        || !owner_only_security_descriptor(&security_descriptor(handle, &actual)?)
    {
        return Err(
            "audit retention requires a private current-user-owned single-link non-reparse file"
                .into(),
        );
    }
    let identity = (
        u64::from(info.dwVolumeSerialNumber),
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    );
    let lease = InPlaceLease {
        parent,
        path: actual,
        file: file.try_clone().map_err(|error| error.to_string())?,
        identity,
    };
    lease.validate(identity)?;
    Ok((file, lease))
}

impl InPlaceLease {
    pub(crate) fn validate(&self, identity: (u64, u64)) -> Result<(), String> {
        if identity != self.identity {
            return Err("audit file identity does not match retained lease".into());
        }
        let parent = self
            .parent
            .handles
            .last()
            .ok_or("audit parent lease disappeared")?;
        let parent_path = final_path(parent.0)?;
        if !path_rules::final_path_within(&self.parent.root_final, &parent_path) {
            return Err("audit parent moved outside its retained scope".into());
        }
        let handle = HANDLE(self.file.as_raw_handle());
        let info = handle_information(handle, &self.path)?;
        let observed = (
            u64::from(info.dwVolumeSerialNumber),
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        );
        if observed != identity
            || !path_rules::attributes_are_safe(info.dwFileAttributes, false)
            || info.nNumberOfLinks != 1
            || !owner_only_security_descriptor(&security_descriptor(handle, &self.path)?)
        {
            return Err("audit file identity or privacy changed during retention".into());
        }
        Ok(())
    }
}
