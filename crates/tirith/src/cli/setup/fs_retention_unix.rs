//! Retained parent plus an existing read/write inode for audit's native lock.
use super::*;

pub(crate) struct InPlaceLease {
    parent: ScopedParent,
    path: PathBuf,
    scope: PathBuf,
    file: fs::File,
    identity: (u64, u64),
}

pub(crate) fn open_existing_in_place(
    path: &Path,
    scope: &Path,
) -> Result<(fs::File, InPlaceLease), String> {
    let parent = scoped_parent(path, scope, false)?.ok_or("audit parent is absent")?;
    let fd = unsafe {
        libc::openat(
            parent.dir.as_raw_fd(),
            parent.name.as_ptr(),
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(format!(
            "open retained audit log: {}",
            std::io::Error::last_os_error()
        ));
    }
    let file = unsafe { fs::File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(
            "audit retention requires a private current-user-owned single-link regular file".into(),
        );
    }
    let identity = (metadata.dev(), metadata.ino());
    let lease = InPlaceLease {
        parent,
        path: path.into(),
        scope: scope.into(),
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
        let current =
            scoped_parent(&self.path, &self.scope, false)?.ok_or("audit parent disappeared")?;
        let held = self
            .parent
            .dir
            .metadata()
            .map_err(|error| error.to_string())?;
        let live = current.dir.metadata().map_err(|error| error.to_string())?;
        if (held.dev(), held.ino()) != (live.dev(), live.ino()) {
            return Err("audit parent was rebound during retention".into());
        }
        let mut named: libc::stat = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::fstatat(
                self.parent.dir.as_raw_fd(),
                self.parent.name.as_ptr(),
                &mut named,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        let metadata = self.file.metadata().map_err(|error| error.to_string())?;
        if result != 0
            || (named.st_dev as u64, named.st_ino as u64) != identity
            || !metadata.is_file()
            || (metadata.dev(), metadata.ino()) != identity
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || named.st_mode & libc::S_IFMT != libc::S_IFREG
        {
            return Err("audit file identity or privacy changed during retention".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn retained_audit_handle_refuses_rebound_path_and_hardlinks() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("log.jsonl");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let (file, lease) = open_existing_in_place(&path, root.path()).unwrap();
        let identity = lease.identity;
        lease.validate(identity).unwrap();
        fs::rename(&path, root.path().join("old")).unwrap();
        fs::write(&path, "competitor").unwrap();
        assert!(lease.validate(identity).is_err());
        assert_eq!(file.metadata().unwrap().len(), 3);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&path, root.path().join("alias")).unwrap();
        assert!(open_existing_in_place(&path, root.path()).is_err());
    }
}
