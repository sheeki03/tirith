//! Read-only retained native facts for private team selection. No credential
//! value, file path or private commitment is an execution/adoption authority.
use super::ConnectionError as E;
use crate::util::dirfd::{file_generation, file_identity, FileGeneration};
use std::fs::File;
use std::path::{Path, PathBuf};

pub(super) struct HeldPath {
    requested: PathBuf,
    anchor: PathBuf,
    canonical: PathBuf,
    dirs: Vec<(PathBuf, File, (u64, u64))>,
    private_parent: bool,
}
impl HeldPath {
    pub(super) fn capture(path: &Path, private_parent: bool) -> Result<Self, E> {
        if !path.is_absolute()
            || path.as_os_str().len() > 8192
            || path.components().count() > 128
            || path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(E::UnsafeStorage);
        }
        let mut anchor = path.parent().ok_or(E::UnsafeStorage)?.to_path_buf();
        loop {
            match std::fs::symlink_metadata(&anchor) {
                Ok(m) => {
                    if !m.is_dir() || m.file_type().is_symlink() {
                        return Err(E::UnsafeStorage);
                    }
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if !anchor.pop() {
                        return Err(E::UnsafeStorage);
                    }
                }
                Err(_) => return Err(E::UnsafeStorage),
            }
        }
        platform::validate_aliases(&anchor).map_err(|_| E::UnsafeStorage)?;
        let canonical = anchor.canonicalize().map_err(|_| E::UnsafeStorage)?;
        let mut paths: Vec<_> = canonical.ancestors().map(Path::to_path_buf).collect();
        paths.reverse();
        if paths.len() > 128 {
            return Err(E::UnsafeStorage);
        }
        let mut dirs = Vec::new();
        for p in paths {
            let f = if let Some((_, parent, _)) = dirs.last() {
                platform::directory_at(parent, &p)
            } else {
                platform::directory(&p)
            }
            .map_err(|_| E::UnsafeStorage)?;
            let id = file_identity(&f).map_err(|_| E::UnsafeStorage)?;
            dirs.push((p, f, id));
        }
        let held = Self {
            requested: path.to_path_buf(),
            anchor,
            canonical,
            dirs,
            private_parent,
        };
        held.revalidate()?;
        Ok(held)
    }
    pub(super) fn revalidate(&self) -> Result<(), E> {
        platform::validate_aliases(&self.anchor).map_err(|_| E::UnsafeStorage)?;
        if self
            .anchor
            .canonicalize()
            .map_err(|_| E::ChangedSelection)?
            != self.canonical
        {
            return Err(E::ChangedSelection);
        }
        for (index, (p, f, id)) in self.dirs.iter().enumerate() {
            platform::validate(
                f,
                true,
                self.private_parent
                    && self.anchor == self.requested.parent().unwrap()
                    && *p == self.canonical,
                index + 1 < self.dirs.len(),
            )
            .map_err(|_| E::UnsafeStorage)?;
            if file_identity(f).map_err(|_| E::ChangedSelection)? != *id
                || file_identity(
                    &(if index == 0 {
                        platform::directory(p)
                    } else {
                        platform::directory_at(&self.dirs[index - 1].1, p)
                    })
                    .map_err(|_| E::ChangedSelection)?,
                )
                .map_err(|_| E::ChangedSelection)?
                    != *id
            {
                return Err(E::ChangedSelection);
            }
        }
        // Missing descendants may be created by our contained transaction. Verify
        // each actual descendant afresh without following links, rather than requiring
        // the whole ancestor directory generation (which includes unrelated siblings).
        let suffix = self
            .requested
            .parent()
            .unwrap()
            .strip_prefix(&self.anchor)
            .map_err(|_| E::ChangedSelection)?;
        let mut p = self.anchor.clone();
        let mut missing = false;
        for component in suffix.components() {
            p.push(component);
            match platform::directory(&p) {
                Ok(f) => {
                    if missing {
                        return Err(E::ChangedSelection);
                    }
                    platform::validate(
                        &f,
                        true,
                        self.private_parent && p == self.requested.parent().unwrap(),
                        false,
                    )
                    .map_err(|_| E::UnsafeStorage)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => missing = true,
                Err(_) => return Err(E::UnsafeStorage),
            }
        }
        Ok(())
    }
    pub(super) fn open_file(&self, cap: usize) -> Result<File, crate::util::OpenRegularError> {
        use crate::util::OpenRegularError as O;
        let map = |e: std::io::Error| {
            if e.kind() == std::io::ErrorKind::NotFound {
                O::NotFound
            } else {
                O::Io(e)
            }
        };
        let mut parent = self
            .dirs
            .last()
            .ok_or(O::NotRegularFile)?
            .1
            .try_clone()
            .map_err(map)?;
        let mut path = self.canonical.clone();
        for component in self
            .requested
            .parent()
            .unwrap()
            .strip_prefix(&self.anchor)
            .map_err(|_| O::NotRegularFile)?
            .components()
        {
            path.push(component);
            let child = platform::directory_at(&parent, &path).map_err(map)?;
            platform::validate(
                &child,
                true,
                self.private_parent
                    && path
                        == self.canonical.join(
                            self.requested
                                .parent()
                                .unwrap()
                                .strip_prefix(&self.anchor)
                                .unwrap(),
                        ),
                false,
            )
            .map_err(|_| O::NotRegularFile)?;
            parent = child;
        }
        path.push(self.requested.file_name().ok_or(O::NotRegularFile)?);
        let file = platform::file_at(&parent, &path).map_err(map)?;
        let m = file.metadata().map_err(map)?;
        if !m.is_file() {
            return Err(O::NotRegularFile);
        }
        if m.len() > cap as u64 {
            return Err(O::TooLarge);
        }
        Ok(file)
    }
    pub(super) fn private_identity(&self) -> Vec<(u64, u64)> {
        self.dirs.iter().map(|x| x.2).collect()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Facts {
    generation: FileGeneration,
    security: Vec<u8>,
}
pub(super) fn facts(file: &File, private: bool) -> Result<Facts, E> {
    platform::validate(file, false, private, false).map_err(|_| E::UnsafeStorage)?;
    let g = file_generation(file).map_err(|_| E::UnsafeStorage)?;
    if g.links != 1 {
        return Err(E::UnsafeStorage);
    }
    Ok(Facts {
        generation: g,
        security: platform::security(file).map_err(|_| E::UnsafeStorage)?,
    })
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    pub(super) fn validate_aliases(path: &Path) -> Result<(), String> {
        // Permit only root-owned system aliases (for example macOS /var).
        // Every original ancestor is checked as well as the canonical chain;
        // a user-writable alias cannot select another credential generation.
        for ancestor in path.ancestors() {
            let m = std::fs::symlink_metadata(ancestor).map_err(|_| "alias metadata")?;
            if m.file_type().is_symlink() && m.uid() != 0 {
                return Err("mutable directory alias".into());
            }
            let resolved = ancestor.canonicalize().map_err(|_| "alias resolution")?;
            let file = directory(&resolved).map_err(|_| "alias directory")?;
            validate(&file, true, false, false)?;
        }
        Ok(())
    }
    pub(super) fn directory(path: &Path) -> std::io::Result<File> {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
    }
    fn child(parent: &File, path: &Path, dir: bool) -> std::io::Result<File> {
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(
            path.file_name()
                .ok_or_else(|| std::io::Error::other("missing component"))?
                .as_bytes(),
        )
        .map_err(|_| std::io::Error::other("component NUL"))?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK
                    | if dir { libc::O_DIRECTORY } else { 0 },
            )
        };
        if fd < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }
    pub(super) fn directory_at(parent: &File, path: &Path) -> std::io::Result<File> {
        child(parent, path, true)
    }
    pub(super) fn file_at(parent: &File, path: &Path) -> std::io::Result<File> {
        child(parent, path, false)
    }
    pub(super) fn security(file: &File) -> Result<Vec<u8>, String> {
        let m = file.metadata().map_err(|_| "metadata")?;
        Ok(format!("{}:{}:{}", m.uid(), m.gid(), m.mode()).into_bytes())
    }
    pub(super) fn validate(
        file: &File,
        directory: bool,
        private: bool,
        _has_child: bool,
    ) -> Result<(), String> {
        let m = file.metadata().map_err(|_| "metadata")?;
        let uid = unsafe { libc::geteuid() };
        if m.is_dir() != directory || (!directory && !m.is_file()) || ![0, uid].contains(&m.uid()) {
            return Err("type/owner".into());
        }
        if private {
            if m.uid() != uid || m.mode() & 0o077 != 0 {
                return Err("private mode".into());
            }
        } else if m.mode() & 0o022 != 0 && !(directory && m.uid() == 0 && m.mode() & 0o1000 != 0) {
            return Err("shared writer".into());
        }
        validate_acl(file, private)
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
}
#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Security::Authorization::*;
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::Storage::FileSystem::*;
    use windows_sys::Win32::System::SystemServices::*;

    pub(super) fn validate_aliases(path: &Path) -> Result<(), String> {
        use std::os::windows::fs::MetadataExt;
        for ancestor in path.ancestors() {
            let m = std::fs::symlink_metadata(ancestor).map_err(|_| "alias metadata")?;
            if m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err("reparse directory alias".into());
            }
        }
        Ok(())
    }
    pub(super) fn directory(path: &Path) -> std::io::Result<File> {
        // GENERIC_READ includes FILE_LIST_DIRECTORY: metadata-only access does not
        // reliably participate in Windows share-delete exclusion.
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }
    pub(super) fn directory_at(_: &File, path: &Path) -> std::io::Result<File> {
        directory(path)
    }
    pub(super) fn file_at(_: &File, path: &Path) -> std::io::Result<File> {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }
    pub(super) fn security(file: &File) -> Result<Vec<u8>, String> {
        use sha2::Digest;
        let mut descriptor = null_mut();
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS || descriptor.is_null() {
            return Err("security snapshot".into());
        }
        struct Descriptor(*mut c_void);
        impl Drop for Descriptor {
            fn drop(&mut self) {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
        let _held = Descriptor(descriptor);
        let length = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
        if length == 0 || length > 64 * 1024 {
            return Err("security bound".into());
        }
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err("file attributes".into());
        }
        let mut digest = sha2::Sha256::new();
        digest.update(info.dwFileAttributes.to_le_bytes());
        digest.update(unsafe { std::slice::from_raw_parts(descriptor.cast::<u8>(), length) });
        Ok(digest.finalize().to_vec())
    }
    pub(super) fn validate(
        file: &File,
        directory: bool,
        private: bool,
        has_child: bool,
    ) -> Result<(), String> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
            || unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
            || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        {
            return Err("native type".into());
        }
        let current = CurrentUserSid::load().map_err(|_| "current user")?;
        let system = well_known_sid(WinLocalSystemSid)?;
        let admins = well_known_sid(WinBuiltinAdministratorsSid)?;
        let mut descriptor = null_mut();
        let mut owner = null_mut();
        let mut dacl = null_mut();
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS || descriptor.is_null() {
            return Err("native security".into());
        }
        struct Descriptor(*mut c_void);
        impl Drop for Descriptor {
            fn drop(&mut self) {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
        let _held = Descriptor(descriptor);
        let installer =
            string_sid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")?;
        let approved = [current.sid, system.sid(), admins.sid(), installer.0];
        if private {
            let mut control = 0u16;
            let mut revision = 0u32;
            if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
                || control & SE_DACL_PROTECTED == 0
            {
                return Err("private dacl inheritance".into());
            }
        }
        let same =
            |a: PSID, b: PSID| !a.is_null() && !b.is_null() && unsafe { EqualSid(a, b) } != 0;
        if owner.is_null()
            || unsafe { IsValidSid(owner) } == 0
            || (if private {
                !same(owner, current.sid)
            } else {
                !approved.iter().any(|s| same(owner, *s))
            })
            || dacl.is_null()
            || unsafe { IsValidAcl(dacl) } == 0
        {
            return Err("owner/dacl".into());
        }
        let count = unsafe { (*dacl).AceCount } as u32;
        if count > 256 {
            return Err("acl bound".into());
        }
        for n in 0..count {
            let mut raw = null_mut();
            if unsafe { GetAce(dacl, n, &mut raw) } == 0 || raw.is_null() {
                return Err("ace".into());
            }
            let header = unsafe { &*raw.cast::<ACE_HEADER>() };
            if (header.AceSize as usize) < size_of::<ACE_HEADER>() {
                return Err("ace size".into());
            }
            if header.AceFlags as u32 & INHERIT_ONLY_ACE != 0 {
                continue;
            }
            if let Some((mask, sid)) = allowed_ace_mask_and_sid(raw, header)? {
                let forbidden = if private {
                    mask != 0 && !same(sid, current.sid)
                } else {
                    mask & (if directory && has_child {
                        0x520d0156u32 & !4
                    } else {
                        0x520d0156u32
                    }) != 0
                        && !approved.iter().any(|s| same(sid, *s))
                };
                if forbidden {
                    return Err("shared access".into());
                }
            }
        }
        Ok(())
    }
    struct TokenHandle(windows_sys::Win32::Foundation::HANDLE);

    impl Drop for TokenHandle {
        fn drop(&mut self) {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }

    struct CurrentUserSid {
        _storage: Vec<usize>,
        sid: windows_sys::Win32::Security::PSID,
    }

    impl CurrentUserSid {
        fn load() -> std::io::Result<Self> {
            use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE};
            use windows_sys::Win32::Security::{
                GetTokenInformation, IsValidSid, TokenUser, TOKEN_QUERY, TOKEN_USER,
            };
            use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

            let mut raw_token: HANDLE = std::ptr::null_mut();
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let token = TokenHandle(raw_token);
            let mut needed = 0u32;
            if unsafe {
                GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut needed)
            } != 0
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "TokenUser size query unexpectedly succeeded",
                ));
            }
            let size_error = std::io::Error::last_os_error();
            if size_error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
                || needed == 0
                || needed > 64 * 1024
            {
                return Err(size_error);
            }
            let word_size = std::mem::size_of::<usize>();
            let mut storage = vec![0usize; (needed as usize).div_ceil(word_size)];
            if unsafe {
                GetTokenInformation(
                    token.0,
                    TokenUser,
                    storage.as_mut_ptr().cast(),
                    needed,
                    &mut needed,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let token_user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
            if token_user.User.Sid.is_null() || unsafe { IsValidSid(token_user.User.Sid) } == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "current process token contains an invalid user SID",
                ));
            }
            Ok(Self {
                sid: token_user.User.Sid,
                _storage: storage,
            })
        }
    }

    fn allowed_ace_mask_and_sid(
        raw_ace: *mut c_void,
        header: &ACE_HEADER,
    ) -> Result<Option<(u32, PSID)>, String> {
        let ace_type = header.AceType as u32;
        match ace_type {
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {
                simple_allowed_ace_mask_and_sid(raw_ace, header).map(Some)
            }
            ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                object_allowed_ace_mask_and_sid(raw_ace, header).map(Some)
            }
            // ACCESS_ALLOWED_COMPOUND_ACE_TYPE. The obsolete compound representation
            // is not expected on filesystem DACLs and has different SID semantics;
            // fail closed instead of accidentally approving it.
            4 => Err("unsupported compound allow ACE in executable path DACL".to_string()),
            // Known deny, audit, alarm, mandatory-label, resource-attribute,
            // scoped-policy, process-trust, and access-filter ACEs do not grant DACL
            // write authority by themselves.
            1..=3 | 6..=8 | 10 | 12..=21 => Ok(None),
            // Future/unknown ACE formats fail closed; never guess that a new type is
            // non-granting at an executable boundary.
            other => Err(format!(
                "unsupported ACE type {other} in executable path DACL"
            )),
        }
    }

    fn simple_allowed_ace_mask_and_sid(
        raw_ace: *mut c_void,
        header: &ACE_HEADER,
    ) -> Result<(u32, PSID), String> {
        let bytes = raw_ace.cast::<u8>();
        let sid_offset = size_of::<ACE_HEADER>() + size_of::<u32>();
        if (header.AceSize as usize) < sid_offset {
            return Err("truncated simple allow ACE".to_string());
        }
        // SAFETY: mask fits by the size check; read permits any alignment.
        let mask: u32 =
            unsafe { std::ptr::read_unaligned(bytes.add(size_of::<ACE_HEADER>()).cast()) };
        Ok((
            mask,
            checked_ace_sid(bytes, header.AceSize as usize, sid_offset)?,
        ))
    }

    fn object_allowed_ace_mask_and_sid(
        raw_ace: *mut c_void,
        header: &ACE_HEADER,
    ) -> Result<(u32, PSID), String> {
        let bytes = raw_ace.cast::<u8>();
        // ACCESS_ALLOWED_*_OBJECT_ACE begins ACE_HEADER, Mask, Flags, optional
        // ObjectType GUID, optional InheritedObjectType GUID, then the SID.
        let fixed = size_of::<ACE_HEADER>() + size_of::<u32>() + size_of::<u32>();
        if (header.AceSize as usize) < fixed {
            return Err("truncated object allow ACE".to_string());
        }
        // SAFETY: fixed fields fit by the AceSize check; reads permit any alignment.
        let mask = unsafe { std::ptr::read_unaligned(bytes.add(size_of::<ACE_HEADER>()).cast()) };
        let flags: u32 = unsafe {
            std::ptr::read_unaligned(bytes.add(size_of::<ACE_HEADER>() + size_of::<u32>()).cast())
        };
        let mut sid_offset = fixed;
        if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
            sid_offset += size_of::<windows_sys::core::GUID>();
        }
        if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
            sid_offset += size_of::<windows_sys::core::GUID>();
        }
        Ok((
            mask,
            checked_ace_sid(bytes, header.AceSize as usize, sid_offset)?,
        ))
    }

    fn checked_ace_sid(bytes: *mut u8, ace_size: usize, sid_offset: usize) -> Result<PSID, String> {
        const SID_FIXED_BYTES: usize = 8;
        if sid_offset.saturating_add(SID_FIXED_BYTES) > ace_size {
            return Err("truncated allow ACE SID".to_string());
        }
        // SID layout starts Revision, SubAuthorityCount, six-byte IdentifierAuthority.
        // SAFETY: the fixed SID prefix fits by the check above.
        let subauthority_count = unsafe { *bytes.add(sid_offset + 1) } as usize;
        let sid_bytes = SID_FIXED_BYTES
            .checked_add(
                subauthority_count
                    .checked_mul(size_of::<u32>())
                    .ok_or_else(|| "allow ACE SID length overflow".to_string())?,
            )
            .ok_or_else(|| "allow ACE SID length overflow".to_string())?;
        if sid_offset.saturating_add(sid_bytes) > ace_size {
            return Err("allow ACE SID extends beyond AceSize".to_string());
        }
        // SAFETY: the entire SID representation is within the ACE.
        let sid: PSID = unsafe { bytes.add(sid_offset).cast() };
        if unsafe { IsValidSid(sid) } == 0 || unsafe { GetLengthSid(sid) } as usize != sid_bytes {
            return Err("invalid allow ACE SID".to_string());
        }
        Ok(sid)
    }

    struct LocalSid(PSID);
    impl Drop for LocalSid {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    fn string_sid(value: &str) -> Result<LocalSid, String> {
        let wide: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
        let mut sid = null_mut();
        if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 {
            return Err("fixed system SID".into());
        }
        Ok(LocalSid(sid))
    }
    struct SidBuffer {
        words: Vec<usize>,
        sid: PSID,
    }

    impl SidBuffer {
        fn sid(&self) -> PSID {
            let _keep_alive = &self.words;
            self.sid
        }
    }

    fn well_known_sid(sid_type: i32) -> Result<SidBuffer, String> {
        let word_count = SECURITY_MAX_SID_SIZE as usize / size_of::<usize>() + 1;
        let mut words = vec![0usize; word_count];
        let mut size = (words.len() * size_of::<usize>()) as u32;
        let sid = words.as_mut_ptr().cast();
        // SAFETY: the aligned buffer is at least SECURITY_MAX_SID_SIZE bytes.
        if unsafe { CreateWellKnownSid(sid_type, null_mut(), sid, &mut size) } == 0 {
            return Err(format!(
                "CreateWellKnownSid failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(SidBuffer { words, sid })
    }
}
#[cfg(not(any(unix, windows)))]
mod platform {
    use super::*;
    pub(super) fn validate_aliases(_: &Path) -> Result<(), String> {
        Err("unsupported".into())
    }
    pub(super) fn security(_: &File) -> Result<Vec<u8>, String> {
        Err("unsupported".into())
    }
    pub(super) fn directory(_: &Path) -> std::io::Result<File> {
        Err(std::io::Error::other("unsupported"))
    }
    pub(super) fn directory_at(_: &File, p: &Path) -> std::io::Result<File> {
        directory(p)
    }
    pub(super) fn file_at(_: &File, p: &Path) -> std::io::Result<File> {
        directory(p)
    }
    pub(super) fn validate(_: &File, _: bool, _: bool, _: bool) -> Result<(), String> {
        Err("unsupported".into())
    }
}
