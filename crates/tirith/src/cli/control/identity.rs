//! Retained identities for owner-private control discovery and running code.
//! These guards contain paths and native handles, never browser credentials.
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

struct HeldDirectory {
    file: File,
    identity: (u64, u64),
}

/// Keep every directory handle alive, including ancestors. Windows handles
/// deny delete sharing; Unix additionally requires trusted ownership and modes.
/// A later check rejects rebinding of either the original alias or any object.
pub(crate) struct DirectoryIdentity {
    requested: PathBuf,
    canonical: PathBuf,
    held: Vec<HeldDirectory>,
    private_leaf: bool,
}

impl DirectoryIdentity {
    pub fn capture(path: &Path) -> Result<Self, String> {
        Self::capture_with_privacy(path, true)
    }

    /// Trusted, non-writable-by-others ancestry for an installation directory.
    /// Unlike service state, executable directories need not be mode 0700.
    pub(crate) fn capture_trusted(path: &Path) -> Result<Self, String> {
        Self::capture_with_privacy(path, false)
    }

    fn capture_with_privacy(path: &Path, private_leaf: bool) -> Result<Self, String> {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(
                "private control directory must be an absolute path without traversal".into(),
            );
        }
        let canonical = path
            .canonicalize()
            .map_err(|_| "cannot resolve private control directory")?;
        let held = capture_directories(&canonical, private_leaf)?;
        let result = Self {
            requested: path.into(),
            canonical,
            held,
            private_leaf,
        };
        result.revalidate()?;
        Ok(result)
    }

    /// Private live-process handoff evidence, never browser output or durable
    /// authority. Original handles MUST remain held until the receiver captures
    /// matching objects; after both close, inode/file-ID reuse invalidates proof.
    pub(crate) fn private_handoff_identity(&self) -> Result<serde_json::Value, String> {
        self.revalidate()?;
        Ok(serde_json::json!({
            "requested": self.requested, "canonical": self.canonical,
            "private_leaf": self.private_leaf,
            "ancestors": self.held.iter().map(|held| held.identity).collect::<Vec<_>>()
        }))
    }

    pub fn revalidate(&self) -> Result<(), String> {
        if self.requested.canonicalize().ok().as_ref() != Some(&self.canonical) {
            return Err("private control directory path changed; reopen the dashboard".into());
        }
        let current = capture_directories(&self.canonical, self.private_leaf)?;
        if current.len() != self.held.len() {
            return Err("private control directory ancestry changed".into());
        }
        for (index, (before, now)) in self.held.iter().zip(&current).enumerate() {
            native::validate_directory(
                &before.file,
                self.private_leaf && index + 1 == self.held.len(),
            )?;
            if native::identity(&before.file)? != before.identity || before.identity != now.identity
            {
                return Err(
                    "private control directory identity changed; reopen the dashboard".into(),
                );
            }
        }
        Ok(())
    }
}

fn capture_directories(path: &Path, private_leaf: bool) -> Result<Vec<HeldDirectory>, String> {
    let files = native::open_chain(path)?;
    let mut held = Vec::with_capacity(files.len());
    let count = files.len();
    for (index, file) in files.into_iter().enumerate() {
        native::validate_directory(&file, private_leaf && index + 1 == count)?;
        let identity = native::identity(&file)?;
        held.push(HeldDirectory { file, identity });
    }
    Ok(held)
}

#[derive(Clone, PartialEq, Eq, serde::Serialize)]
struct Generation {
    identity: (u64, u64),
    size: u64,
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    attributes: u64,
}

/// Hash one retained regular-file handle once. Subsequent request checks use
/// native object/generation metadata on both that handle and the current name.
/// Windows also retains a deny-write sharing lease, because its timestamps can
/// lag same-size writes. Atomic replacement remains allowed and is detected by
/// native identity; in-place updates wait for this service's handle to close.
/// This is an update guard, not a code signature or a defense against an owner
/// who can replace the process itself or forge filesystem metadata.
pub(crate) struct BinaryIdentity {
    path: PathBuf,
    file: File,
    generation: Generation,
    sha256: String,
}

impl BinaryIdentity {
    pub fn capture_current() -> Result<Self, String> {
        Self::capture(&std::env::current_exe().map_err(|_| "cannot locate running binary")?)
    }

    pub fn capture(path: &Path) -> Result<Self, String> {
        Self::capture_with_empty_input(path, false)
    }

    /// Retain an inert regular-file input with the same native generation and
    /// no-concurrent-writer rules. Empty hooks are valid; empty binaries are not.
    pub(crate) fn capture_input(path: &Path) -> Result<Self, String> {
        Self::capture_with_empty_input(path, true)
    }

    fn capture_with_empty_input(path: &Path, allow_empty: bool) -> Result<Self, String> {
        let mut file = open_binary_identity_file(path)?;
        let generation = native::generation(&file)?;
        if (!allow_empty && generation.size == 0) || generation.size > 512 * 1024 * 1024 {
            return Err("binary size exceeds identity limit".into());
        }
        let mut hash = Sha256::new();
        let mut reader = (&mut file).take(generation.size + 1);
        let mut buffer = [0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let count = reader
                .read(&mut buffer)
                .map_err(|_| "cannot hash running binary")?;
            if count == 0 {
                break;
            }
            total += count as u64;
            hash.update(&buffer[..count]);
        }
        if total != generation.size || native::generation(&file)? != generation {
            return Err("binary changed while its identity was captured".into());
        }
        let result = Self {
            path: path.into(),
            file,
            generation,
            sha256: format!("{:x}", hash.finalize()),
        };
        result.revalidate()?;
        Ok(result)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Private anonymous-pipe evidence under simultaneous retained handles.
    pub(crate) fn private_handoff_identity(&self) -> Result<serde_json::Value, String> {
        self.revalidate()?;
        Ok(
            serde_json::json!({"path": self.path, "generation": self.generation, "sha256": self.sha256}),
        )
    }

    pub fn revalidate(&self) -> Result<(), String> {
        let named = open_binary_identity_file(&self.path)
            .map_err(|_| "binary path changed; reopen the dashboard")?;
        if native::generation(&self.file)? != self.generation
            || native::generation(&named)? != self.generation
        {
            return Err("binary was updated or replaced; reopen the dashboard".into());
        }
        Ok(())
    }
}

fn open_binary_identity_file(path: &Path) -> Result<File, String> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
        };
        // CreateFileW's share contract rejects existing writable handles AND
        // writable mappings when FILE_SHARE_WRITE is absent. It also blocks new
        // writers until this retained handle closes. READ|DELETE keeps ordinary
        // readers and atomic replacement available; timestamps alone cannot
        // certify unchanged bytes on Windows.
        // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode((FILE_SHARE_READ | FILE_SHARE_DELETE).0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
            .open(path)
            .map_err(|_| "cannot retain a binary without concurrent write access")?;
        let generation = native::generation(&file)?;
        if generation.size > 512 * 1024 * 1024 {
            return Err("binary size exceeds identity limit".into());
        }
        Ok(file)
    }
    #[cfg(not(windows))]
    {
        tirith_core::util::open_read_no_follow_capped(path, 512 * 1024 * 1024)
            .map_err(|_| "cannot retain running binary".into())
    }
}

#[cfg(unix)]
mod native {
    use super::*;
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    pub fn open_chain(path: &Path) -> Result<Vec<File>, String> {
        let root = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if root < 0 {
            return Err("cannot retain filesystem root".into());
        }
        let mut files = vec![unsafe { File::from_raw_fd(root) }];
        for component in path.components() {
            let std::path::Component::Normal(name) = component else {
                if component == std::path::Component::RootDir {
                    continue;
                }
                return Err(
                    "private control directory contains unsupported path components".into(),
                );
            };
            let name = CString::new(name.as_bytes()).map_err(|_| "directory name contains NUL")?;
            let fd = unsafe {
                libc::openat(
                    files.last().unwrap().as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(
                    "cannot retain control directory ancestry without following links".into(),
                );
            }
            files.push(unsafe { File::from_raw_fd(fd) });
        }
        Ok(files)
    }

    pub fn validate_directory(file: &File, private: bool) -> Result<(), String> {
        let metadata = file
            .metadata()
            .map_err(|_| "cannot inspect control directory")?;
        let uid = unsafe { libc::geteuid() };
        if !metadata.is_dir() || ![0, uid].contains(&metadata.uid()) {
            return Err("control directory ancestry has an untrusted owner".into());
        }
        if private {
            if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
                return Err("control directory must be owned by the operator and private".into());
            }
        } else if metadata.mode() & 0o022 != 0 {
            // In a root-owned sticky directory (e.g. /tmp), another user may
            // create their own children but cannot remove a root/operator-owned
            // child. Every child here is independently ownership-checked.
            if metadata.uid() != 0 || metadata.mode() & 0o1000 == 0 {
                return Err("control directory ancestry is writable by another user".into());
            }
        }
        validate_acl(file, private)?;
        Ok(())
    }

    #[cfg(target_vendor = "apple")]
    fn validate_acl(file: &File, private: bool) -> Result<(), String> {
        use std::ffi::c_void;
        // Darwin extended ACL rights can widen mode bits. Inspect the same
        // retained descriptor; private roots may have no extra allow rights,
        // while ancestor ACLs may add read rights or deny entries only.
        unsafe extern "C" {
            fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut c_void;
            fn acl_get_entry(
                acl: *mut c_void,
                id: libc::c_int,
                entry: *mut *mut c_void,
            ) -> libc::c_int;
            fn acl_get_tag_type(entry: *mut c_void, tag: *mut libc::c_int) -> libc::c_int;
            fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> libc::c_int;
            fn acl_free(acl: *mut c_void) -> libc::c_int;
        }
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
        if acl.is_null() {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                return Ok(());
            }
            return Err("cannot inspect private directory ACL".into());
        }
        struct Acl(*mut c_void);
        impl Drop for Acl {
            fn drop(&mut self) {
                unsafe {
                    acl_free(self.0);
                }
            }
        }
        let acl = Acl(acl);
        const MUTATING: u64 = (1 << 2)
            | (1 << 4)
            | (1 << 5)
            | (1 << 6)
            | (1 << 8)
            | (1 << 10)
            | (1 << 12)
            | (1 << 13);
        for index in 0..256 {
            let mut entry = std::ptr::null_mut();
            if unsafe { acl_get_entry(acl.0, if index == 0 { 0 } else { -1 }, &mut entry) } != 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                    return Ok(());
                }
                return Err("cannot enumerate private directory ACL".into());
            }
            let mut tag = 0;
            let mut mask = 0;
            if unsafe { acl_get_tag_type(entry, &mut tag) } != 0
                || unsafe { acl_get_permset_mask_np(entry, &mut mask) } != 0
            {
                return Err("cannot inspect private directory ACL entry".into());
            }
            if tag == 1
                && (if private {
                    mask != 0
                } else {
                    mask & MUTATING != 0
                })
            {
                return Err(
                    "control directory ACL grants rights outside its approved mode bits".into(),
                );
            }
        }
        Err("private directory ACL exceeds inspection limit".into())
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn validate_acl(_: &File, _: bool) -> Result<(), String> {
        // POSIX access ACL named-user/group rights are intersected with the
        // mode's group-class mask, already required to have no write (or, on
        // the private root, no access) rights. Default ACLs do not grant access
        // to the existing directory; publications use exact private modes.
        Ok(())
    }

    #[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
    fn validate_acl(_: &File, _: bool) -> Result<(), String> {
        Err("control directory ACL verification is unsupported on this platform".into())
    }

    pub fn identity(file: &File) -> Result<(u64, u64), String> {
        let metadata = file
            .metadata()
            .map_err(|_| "cannot inspect native file identity")?;
        Ok((metadata.dev(), metadata.ino()))
    }

    pub fn generation(file: &File) -> Result<Generation, String> {
        let metadata = file
            .metadata()
            .map_err(|_| "cannot inspect binary generation")?;
        if !metadata.is_file() {
            return Err("binary is not a regular file".into());
        }
        Ok(Generation {
            identity: (metadata.dev(), metadata.ino()),
            size: metadata.len(),
            links: metadata.nlink(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
            attributes: u64::from(metadata.mode()),
        })
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FileBasicInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
    };

    fn handle(file: &File) -> HANDLE {
        HANDLE(file.as_raw_handle())
    }

    pub fn open_chain(path: &Path) -> Result<Vec<File>, String> {
        let mut current = PathBuf::new();
        let mut files = Vec::new();
        for component in path.components() {
            match component {
                std::path::Component::Prefix(_) => {
                    current.push(component.as_os_str());
                    continue;
                }
                std::path::Component::RootDir | std::path::Component::Normal(_) => {
                    current.push(component.as_os_str())
                }
                _ => return Err("control directory contains unsupported path components".into()),
            }
            let wide: Vec<u16> = current.as_os_str().encode_wide().chain(Some(0)).collect();
            let native = unsafe {
                CreateFileW(
                    PCWSTR(wide.as_ptr()),
                    (FILE_READ_ATTRIBUTES | READ_CONTROL).0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    None,
                )
            }
            .map_err(|_| "cannot retain control directory ancestry")?;
            let file = unsafe { File::from_raw_handle(native.0) };
            let info = information(&file)?;
            if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
                || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
            {
                return Err(
                    "control directory ancestry contains a non-directory or reparse point".into(),
                );
            }
            files.push(file);
        }
        if files.is_empty() {
            return Err("control directory has no native root".into());
        }
        Ok(files)
    }

    pub fn validate_directory(file: &File, private: bool) -> Result<(), String> {
        if private {
            super::super::super::setup::fs_helpers::validate_control_directory_handle(file)
        } else {
            super::super::super::setup::fs_helpers::validate_control_ancestor_handle(file)
        }
    }

    fn information(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION, String> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        unsafe { GetFileInformationByHandle(handle(file), &mut info) }
            .map_err(|_| "cannot inspect native file identity")?;
        Ok(info)
    }

    pub fn identity(file: &File) -> Result<(u64, u64), String> {
        let info = information(file)?;
        Ok((
            u64::from(info.dwVolumeSerialNumber),
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        ))
    }

    pub fn generation(file: &File) -> Result<Generation, String> {
        let info = information(file)?;
        if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_REPARSE_POINT.0)
            != 0
        {
            return Err("binary is not a regular file".into());
        }
        let mut basic = FILE_BASIC_INFO::default();
        unsafe {
            GetFileInformationByHandleEx(
                handle(file),
                FileBasicInfo,
                (&mut basic as *mut FILE_BASIC_INFO).cast(),
                std::mem::size_of::<FILE_BASIC_INFO>() as u32,
            )
        }
        .map_err(|_| "cannot inspect binary change generation")?;
        Ok(Generation {
            identity: identity(file)?,
            size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
            links: u64::from(info.nNumberOfLinks),
            modified: (basic.LastWriteTime, 0),
            changed: (basic.ChangeTime, 0),
            attributes: u64::from(info.dwFileAttributes),
        })
    }
}

#[cfg(not(any(unix, windows)))]
mod native {
    use super::*;
    pub fn open_chain(_: &Path) -> Result<Vec<File>, String> {
        Err("retained directory identities are unsupported".into())
    }
    pub fn validate_directory(_: &File, _: bool) -> Result<(), String> {
        Err("directory permissions are unsupported".into())
    }
    pub fn identity(_: &File) -> Result<(u64, u64), String> {
        Err("native file identity is unsupported".into())
    }
    pub fn generation(_: &File) -> Result<Generation, String> {
        Err("native file generation is unsupported".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(windows))]
    fn binary_guard_detects_replacement_and_same_size_in_place_edits() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("binary");
        std::fs::write(&path, b"original bytes").unwrap();
        let original = BinaryIdentity::capture(&path).unwrap();
        assert!(original.revalidate().is_ok());
        assert_eq!(
            original.sha256(),
            format!("{:x}", Sha256::digest(b"original bytes"))
        );
        std::fs::write(&path, b"modified bytes").unwrap();
        assert!(original.revalidate().is_err());
        let current = BinaryIdentity::capture(&path).unwrap();
        let replacement = temp.path().join("replacement");
        std::fs::write(&replacement, b"modified bytes").unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        assert!(current.revalidate().is_err());
    }

    #[test]
    #[cfg(windows)]
    fn binary_guard_excludes_in_place_writes_and_detects_atomic_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("binary");
        std::fs::write(&path, b"original bytes").unwrap();
        let original = BinaryIdentity::capture(&path).unwrap();
        assert!(std::fs::write(&path, b"modified bytes").is_err());
        assert!(original.revalidate().is_ok());
        assert_eq!(std::fs::read(&path).unwrap(), b"original bytes");
        let replacement = temp.path().join("replacement");
        std::fs::write(&replacement, b"original bytes").unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        assert!(
            original.revalidate().is_err(),
            "identical replacement is a new binary generation"
        );
        let current = BinaryIdentity::capture(&path).unwrap();
        assert_eq!(current.sha256(), original.sha256());
        drop(current);
        std::fs::write(&path, b"modified bytes").unwrap();
    }

    #[test]
    #[cfg(windows)]
    fn binary_guard_refuses_preexisting_writable_handles_and_mappings() {
        use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Memory::{
            CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_WRITE,
            MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READWRITE,
        };
        struct Mapping {
            view: MEMORY_MAPPED_VIEW_ADDRESS,
            _handle: OwnedHandle,
        }
        impl Drop for Mapping {
            fn drop(&mut self) {
                unsafe {
                    let _ = UnmapViewOfFile(self.view);
                }
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("binary");
        std::fs::write(&path, b"original bytes").unwrap();
        let writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(
            BinaryIdentity::capture(&path).is_err(),
            "existing writer must prevent capture"
        );
        let handle = unsafe {
            CreateFileMappingW(
                HANDLE(writer.as_raw_handle()),
                None,
                PAGE_READWRITE,
                0,
                0,
                PCWSTR::null(),
            )
        }
        .unwrap();
        let owned = unsafe { OwnedHandle::from_raw_handle(handle.0) };
        let view = unsafe { MapViewOfFile(HANDLE(owned.as_raw_handle()), FILE_MAP_WRITE, 0, 0, 0) };
        assert!(!view.Value.is_null());
        let mapping = Mapping {
            view,
            _handle: owned,
        };
        drop(writer);
        // Closing the original file handle does not erase the writable mapping
        // contract: capture must still refuse, even with unchanged timestamps.
        unsafe {
            mapping.view.Value.cast::<u8>().write(b'm');
        }
        assert!(
            BinaryIdentity::capture(&path).is_err(),
            "existing writable mapping must prevent capture"
        );
        drop(mapping);
        assert!(BinaryIdentity::capture(&path).is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn private_directory_rejects_unsafe_modes_and_rebound_ancestors() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("control");
        let root = parent.join("v1");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let identity = DirectoryIdentity::capture(&root).unwrap();
        assert!(identity.revalidate().is_ok());
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(identity.revalidate().is_err());
        assert!(DirectoryIdentity::capture(&root).is_err());
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(&parent, temp.path().join("old-control")).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(identity.revalidate().is_err());
        assert!(DirectoryIdentity::capture(&root).is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn directory_alias_retargeting_and_private_mode_drift_refuse() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("one");
        let second = temp.path().join("two");
        for path in [&first, &second] {
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(&first, &alias).unwrap();
        let identity = DirectoryIdentity::capture(&alias).unwrap();
        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&second, &alias).unwrap();
        assert!(identity.revalidate().is_err());
        let identity = DirectoryIdentity::capture(&first).unwrap();
        std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(identity.revalidate().is_err());
    }
}
