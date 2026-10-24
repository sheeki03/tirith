//! Narrow Linux tmpfs ACL-absence proof after an unsupported POSIX ACL read.
//!
//! EOPNOTSUPP alone is insufficient: an LSM may return it before the VFS checks
//! inode ACL support. On tmpfs, shmem_listxattr -> simple_xattr_list lists both
//! cached POSIX ACL names without filtering them. Require that independent
//! successful absence observation on the same metadata-admitted descriptor.
//! Other filesystems can enforce different ACL models and remain unsupported.
//! Kernel reader and listing contracts (stable Linux v6.12.76):
//! https://github.com/gregkh/linux/blob/v6.12.76/fs/posix_acl.c#L1105
//! https://github.com/gregkh/linux/blob/v6.12.76/fs/xattr.c#L1242
//! https://github.com/gregkh/linux/blob/v6.12.76/mm/shmem.c#L3849

use std::ffi::CStr;
use std::fs::{File, Metadata, OpenOptions};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

const TMPFS_MAGIC: i128 = 0x0102_1994;
const ATTRIBUTE_LIMIT: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl From<&Metadata> for Identity {
    fn from(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            size: metadata.len(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

struct AdmittedObject<'a> {
    file: File,
    path: &'a Path,
    identity: Identity,
}

impl<'a> AdmittedObject<'a> {
    fn open(path: &'a Path, directory: bool, admitted: &Metadata) -> Result<Self, String> {
        if (directory && !admitted.is_dir()) || (!directory && !admitted.is_file()) {
            return Err("tmpfs ACL proof requires the admitted file or directory type".into());
        }
        let identity = Identity::from(admitted);
        require_visible_identity(path, &identity)?;
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(
            libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK
                | if directory { libc::O_DIRECTORY } else { 0 },
        );
        let file = options
            .open(path)
            .map_err(|error| format!("open admitted object for tmpfs ACL proof: {error}"))?;
        let object = Self {
            file,
            path,
            identity,
        };
        object.revalidate()?;
        Ok(object)
    }

    fn revalidate(&self) -> Result<(), String> {
        let metadata = self
            .file
            .metadata()
            .map_err(|error| format!("recheck tmpfs ACL descriptor: {error}"))?;
        if Identity::from(&metadata) != self.identity {
            return Err("admitted object changed during tmpfs ACL proof".into());
        }
        require_visible_identity(self.path, &self.identity)
    }

    fn require_tmpfs(&self) -> Result<(), String> {
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: the descriptor is retained and the output has statfs layout.
        if unsafe { libc::fstatfs(self.file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
            return Err(format!(
                "inspect filesystem for tmpfs ACL proof: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: successful fstatfs initialized its complete output structure.
        let filesystem = unsafe { filesystem.assume_init() };
        // GNU uses a signed fs word; musl uses an unsigned word. i128 admits
        // both without truncation or a target-specific redundant cast.
        require_tmpfs_type(i128::from(filesystem.f_type))
    }

    fn require_unsupported_read(&self, attribute: &CStr) -> Result<(), String> {
        if !matches!(
            attribute.to_bytes(),
            b"system.posix_acl_access" | b"system.posix_acl_default"
        ) {
            return Err("tmpfs ACL proof requires a fixed POSIX ACL attribute".into());
        }
        let mut value = vec![0u8; ATTRIBUTE_LIMIT];
        // SAFETY: the retained descriptor, C string, and output buffer are live.
        let result = unsafe {
            libc::fgetxattr(
                self.file.as_raw_fd(),
                attribute.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        let error = if result < 0 {
            std::io::Error::last_os_error().raw_os_error()
        } else {
            None
        };
        require_unsupported_result(result, error)
    }

    fn require_no_acl_names(&self) -> Result<(), String> {
        let mut names = vec![0u8; ATTRIBUTE_LIMIT];
        // SAFETY: the retained descriptor and bounded writable buffer are live.
        let result = unsafe {
            libc::flistxattr(
                self.file.as_raw_fd(),
                names.as_mut_ptr().cast(),
                names.len(),
            )
        };
        if result < 0 {
            return Err(format!(
                "list attributes for tmpfs ACL proof: {}",
                std::io::Error::last_os_error()
            ));
        }
        let length = usize::try_from(result)
            .map_err(|_| "invalid tmpfs attribute-list length".to_string())?;
        if length > names.len() {
            return Err("tmpfs attribute list exceeded its bound".into());
        }
        validate_absent_acl_names(&names[..length])
    }
}

fn require_visible_identity(path: &Path, identity: &Identity) -> Result<(), String> {
    let visible = std::fs::symlink_metadata(path)
        .map_err(|error| format!("recheck pathname for tmpfs ACL proof: {error}"))?;
    if (!visible.is_file() && !visible.is_dir()) || Identity::from(&visible) != *identity {
        return Err("pathname no longer identifies the admitted object for tmpfs ACL proof".into());
    }
    Ok(())
}

fn require_tmpfs_type(filesystem_type: i128) -> Result<(), String> {
    if filesystem_type != TMPFS_MAGIC {
        return Err("unsupported POSIX ACL lookup outside proved tmpfs semantics".into());
    }
    Ok(())
}

fn require_unsupported_result(result: libc::ssize_t, error: Option<i32>) -> Result<(), String> {
    if result != -1 || error != Some(libc::EOPNOTSUPP) {
        return Err("POSIX ACL lookup changed while binding the tmpfs descriptor".into());
    }
    Ok(())
}

fn validate_absent_acl_names(names: &[u8]) -> Result<(), String> {
    if names.is_empty() {
        return Ok(());
    }
    if names.len() > ATTRIBUTE_LIMIT || names.last() != Some(&0) {
        return Err("malformed or oversized tmpfs attribute list".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for name in names[..names.len() - 1].split(|byte| *byte == 0) {
        if name.is_empty() || name.len() > 255 || !seen.insert(name) {
            return Err("malformed tmpfs attribute name list".into());
        }
        if matches!(
            name,
            b"system.posix_acl_access" | b"system.posix_acl_default"
        ) {
            return Err("tmpfs still exposes a POSIX ACL that could not be inspected".into());
        }
    }
    Ok(())
}

pub(super) fn verify_absence(
    path: &Path,
    directory: bool,
    admitted: &Metadata,
    attribute: &CStr,
) -> Result<(), String> {
    // `admitted` must come from the caller's completed owner/mode validation,
    // never a fresh snapshot taken only after the unsupported lookup.
    let object = AdmittedObject::open(path, directory, admitted)?;
    object.require_tmpfs()?;
    object.require_unsupported_read(attribute)?;
    object.require_no_acl_names()?;
    object.revalidate()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn tmpfs_fixture() -> tempfile::TempDir {
        let temp = tempfile::Builder::new()
            .prefix("tirith-acl-")
            .tempdir_in("/dev/shm")
            .expect("private native tmpfs fixture");
        let metadata = std::fs::symlink_metadata(temp.path()).unwrap();
        AdmittedObject::open(temp.path(), true, &metadata)
            .unwrap()
            .require_tmpfs()
            .expect("/dev/shm must be native tmpfs for this Linux control");
        temp
    }

    #[test]
    fn unsupported_errno_and_filesystem_gate_are_exact() {
        require_tmpfs_type(TMPFS_MAGIC).unwrap();
        for fs_type in [0, 0x6969, 0x794c_7630, 0x6573_5546, 0xff53_4d42] {
            assert!(require_tmpfs_type(fs_type).is_err());
        }
        require_unsupported_result(-1, Some(libc::EOPNOTSUPP)).unwrap();
        for error in [
            None,
            Some(libc::ENODATA),
            Some(libc::EACCES),
            Some(libc::EPERM),
            Some(libc::EIO),
            Some(libc::ERANGE),
            Some(libc::EBADF),
        ] {
            assert!(require_unsupported_result(-1, error).is_err());
        }
        for result in [-2, 0, 4] {
            assert!(require_unsupported_result(result, Some(libc::EOPNOTSUPP)).is_err());
        }
    }

    #[test]
    fn acl_name_listing_requires_complete_unambiguous_absence() {
        for names in [
            b"".as_slice(),
            b"security.selinux\0user.note\0",
            b"user.system.posix_acl_access\0system.posix_acl_access_suffix\0",
        ] {
            validate_absent_acl_names(names).unwrap();
        }
        for names in [
            b"\0".as_slice(),
            b"user.note",
            b"user.note\0\0",
            b"user.note\0user.note\0",
            b"system.posix_acl_access\0",
            b"user.note\0system.posix_acl_default\0",
        ] {
            assert!(validate_absent_acl_names(names).is_err());
        }
        let mut long_name = vec![b'x'; 256];
        long_name.push(0);
        assert!(validate_absent_acl_names(&long_name).is_err());
        assert!(validate_absent_acl_names(&vec![0; ATTRIBUTE_LIMIT + 1]).is_err());
    }

    #[test]
    fn native_tmpfs_file_and_directory_list_absence_on_held_objects() {
        let temp = tmpfs_fixture();
        let path = temp.path().join("ordinary");
        std::fs::write(&path, b"inert native ACL control").unwrap();
        for (path, directory) in [(path.as_path(), false), (temp.path(), true)] {
            let metadata = std::fs::symlink_metadata(path).unwrap();
            let object = AdmittedObject::open(path, directory, &metadata).unwrap();
            object.require_tmpfs().unwrap();
            object.require_no_acl_names().unwrap();
            object.revalidate().unwrap();
        }
    }

    #[test]
    fn caller_admitted_generation_cannot_be_replaced_after_acl_failure() {
        let temp = tmpfs_fixture();
        let path = temp.path().join("admitted");
        std::fs::write(&path, b"old").unwrap();
        let admitted = std::fs::symlink_metadata(&path).unwrap();
        std::fs::rename(&path, temp.path().join("retained-old")).unwrap();
        std::fs::write(&path, b"new").unwrap();
        assert!(AdmittedObject::open(&path, false, &admitted).is_err());
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(temp.path().join("retained-old"), &path).unwrap();
        assert!(AdmittedObject::open(&path, false, &admitted).is_err());
    }

    #[test]
    fn held_object_refuses_type_path_and_permission_generation_drift() {
        let temp = tmpfs_fixture();
        let path = temp.path().join("admitted");
        std::fs::write(&path, b"same").unwrap();
        let admitted = std::fs::symlink_metadata(&path).unwrap();
        assert!(AdmittedObject::open(&path, true, &admitted).is_err());
        let object = AdmittedObject::open(&path, false, &admitted).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(object.revalidate().is_err());
        let admitted = std::fs::symlink_metadata(&path).unwrap();
        let object = AdmittedObject::open(&path, false, &admitted).unwrap();
        std::fs::rename(&path, temp.path().join("retained-old")).unwrap();
        std::fs::write(&path, b"same").unwrap();
        assert!(object.revalidate().is_err());
    }

    #[test]
    fn native_listing_errors_are_not_absence() {
        let temp = tmpfs_fixture();
        let metadata = std::fs::symlink_metadata(temp.path()).unwrap();
        // O_PATH allows identity queries but not flistxattr: this exercises an
        // actual kernel error without closing/reusing another owner's fd.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(temp.path())
            .unwrap();
        let object = AdmittedObject {
            file,
            path: temp.path(),
            identity: Identity::from(&metadata),
        };
        object.require_tmpfs().unwrap();
        assert!(object.require_no_acl_names().is_err());
        assert!(object
            .require_unsupported_read(c"system.posix_acl_access")
            .is_err());
    }

    #[test]
    fn native_tmpfs_acl_names_cannot_be_hidden_by_unsupported_read_fallback() {
        let temp = tmpfs_fixture();
        let path = temp.path().join("with-acl");
        std::fs::write(&path, b"native ACL name control").unwrap();
        // A real named foreign write grant masked from current access; the
        // conservative policy must still inspect/reject it. ACL installation
        // is required for this control, with no silent unsupported-path skip.
        let foreign = unsafe { libc::geteuid() }.wrapping_add(31_337);
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, permission, id) in [
            (0x01u16, 7u16, u32::MAX),
            (0x02, 7, foreign),
            (0x04, 0, u32::MAX),
            (0x10, 0, u32::MAX),
            (0x20, 0, u32::MAX),
        ] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&permission.to_le_bytes());
            acl.extend_from_slice(&id.to_le_bytes());
        }
        for (path, directory, name) in [
            (path.as_path(), false, c"system.posix_acl_access"),
            (temp.path(), true, c"system.posix_acl_default"),
        ] {
            let file = File::open(path).unwrap();
            // SAFETY: the descriptor, C string, and ACL bytes are live.
            let result = unsafe {
                libc::fsetxattr(
                    file.as_raw_fd(),
                    name.as_ptr(),
                    acl.as_ptr().cast(),
                    acl.len(),
                    0,
                )
            };
            assert_eq!(
                result,
                0,
                "native ACL install: {}",
                std::io::Error::last_os_error()
            );
            let admitted = file.metadata().unwrap();
            let object = AdmittedObject::open(path, directory, &admitted).unwrap();
            object.require_tmpfs().unwrap();
            assert!(object.require_no_acl_names().is_err());
            assert!(verify_absence(path, directory, &admitted, name).is_err());
            let error = super::super::reject_unix_extended_acl(path, directory).unwrap_err();
            assert!(error.contains("mutation authority"), "{error}");
            // The bound caller must still use the normal ACL parser when the
            // attribute exists, including foreign grants masked by mode bits.
            let error = super::super::validate_unix_owner_and_mode(
                path,
                &admitted,
                unsafe { libc::geteuid() },
                directory,
            )
            .unwrap_err();
            assert!(error.to_string().contains("mutation authority"), "{error}");
        }
    }

    #[test]
    fn native_supported_self_acl_is_still_parsed_and_accepted() {
        let temp = tmpfs_fixture();
        let uid = unsafe { libc::geteuid() };
        let file = File::open(temp.path()).unwrap();
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, permission, id) in [
            (0x01u16, 7u16, u32::MAX),
            (0x02, 7, uid),
            (0x04, 0, u32::MAX),
            (0x10, 7, u32::MAX),
            (0x20, 0, u32::MAX),
        ] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&permission.to_le_bytes());
            acl.extend_from_slice(&id.to_le_bytes());
        }
        // SAFETY: the retained directory and fixed ACL buffers are live.
        let result = unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                c"system.posix_acl_default".as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        };
        assert_eq!(
            result,
            0,
            "native ACL install: {}",
            std::io::Error::last_os_error()
        );
        super::super::validate_unix_owner_and_mode(
            temp.path(),
            &file.metadata().unwrap(),
            uid,
            true,
        )
        .expect("a supported self-grant must use the normal ACL parser");
    }
}
