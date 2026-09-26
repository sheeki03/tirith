//! Native ordinary-owner storage. Caller-owned directory handles stay retained
//! while SQLite operates; existing links/shared or foreign files are refused.
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

pub type FsResult<T> = Result<T, &'static str>;
pub type FileIdentity = (u64, u64);

pub fn ordinary_owner() -> FsResult<u32> {
    let uid = unsafe { libc::geteuid() };
    if uid == 0 || uid != unsafe { libc::getuid() } {
        return Err("ordinary_owner_required");
    }
    Ok(uid)
}

fn c_name(value: &std::ffi::OsStr) -> FsResult<CString> {
    CString::new(value.as_bytes()).map_err(|_| "invalid_path")
}

fn open_at(
    parent: &File,
    name: &std::ffi::OsStr,
    flags: i32,
    mode: libc::mode_t,
) -> FsResult<File> {
    let name = c_name(name)?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags,
            mode as libc::c_uint,
        )
    };
    if descriptor < 0 {
        return Err("private_file_unavailable");
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn same(a: &File, b: &File) -> FsResult<()> {
    let a = a.metadata().map_err(|_| "private_identity_unavailable")?;
    let b = b.metadata().map_err(|_| "private_identity_unavailable")?;
    if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
        return Err("private_identity_changed");
    }
    Ok(())
}

fn directory_metadata(file: &File, private: bool) -> FsResult<()> {
    let uid = ordinary_owner()?;
    let info = file
        .metadata()
        .map_err(|_| "private_identity_unavailable")?;
    let sticky_system = info.uid() == 0 && info.mode() & 0o1000 != 0;
    if !info.is_dir()
        || (private && (info.uid() != uid || info.mode() & 0o7077 != 0))
        || (!private && (info.uid() != 0 && info.uid() != uid))
        || (!private && info.mode() & 0o022 != 0 && !sticky_system)
    {
        return Err("unsafe_private_directory");
    }
    validate_acl(file, private)
}

fn file_metadata(file: &File, private: bool) -> FsResult<()> {
    let info = file
        .metadata()
        .map_err(|_| "private_identity_unavailable")?;
    if !info.is_file()
        || info.nlink() != 1
        || info.uid() != ordinary_owner()?
        || info.mode() & (if private { 0o7177 } else { 0o7022 }) != 0
    {
        return Err("unsafe_private_file");
    }
    validate_acl(file, private)
}

pub struct Directory {
    path: PathBuf,
    chain: Vec<File>,
}

impl Directory {
    pub fn open(path: &Path) -> FsResult<Self> {
        Self::open_with_leaf(path, true)
    }

    fn open_with_leaf(path: &Path, private: bool) -> FsResult<Self> {
        ordinary_owner()?;
        if !path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err("absolute_normal_path_required");
        }
        let fd = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err("private_directory_unavailable");
        }
        let mut chain = vec![unsafe { File::from_raw_fd(fd) }];
        directory_metadata(&chain[0], false)?;
        let names: Vec<_> = path
            .components()
            .filter_map(|part| match part {
                Component::Normal(name) => Some(name),
                _ => None,
            })
            .collect();
        if names.is_empty() {
            return Err("private_root_required");
        }
        for (index, name) in names.iter().enumerate() {
            let file = open_at(
                chain.last().expect("root exists"),
                name,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            )?;
            directory_metadata(&file, private && index + 1 == names.len())?;
            chain.push(file);
        }
        Ok(Self {
            path: path.into(),
            chain,
        })
    }

    pub fn create(path: &Path) -> FsResult<Self> {
        let parent = path.parent().ok_or("private_root_required")?;
        let held = Self::open_with_leaf(parent, false)?;
        let name = c_name(path.file_name().ok_or("private_root_required")?)?;
        if unsafe { libc::mkdirat(held.leaf().as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err("private_directory_exists_or_unavailable");
        }
        held.leaf().sync_all().map_err(|_| "storage_unavailable")?;
        held.revalidate_with_leaf(false)?;
        Self::open(path)
    }

    fn leaf(&self) -> &File {
        self.chain.last().expect("private leaf exists")
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn revalidate(&self) -> FsResult<()> {
        self.revalidate_with_leaf(true)
    }

    fn revalidate_with_leaf(&self, private: bool) -> FsResult<()> {
        let current = Self::open_with_leaf(&self.path, private)?;
        if current.chain.len() != self.chain.len() {
            return Err("private_identity_changed");
        }
        for (before, after) in self.chain.iter().zip(&current.chain) {
            same(before, after)?;
        }
        Ok(())
    }

    pub fn open_file(&self, name: &str, write: bool) -> FsResult<File> {
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            return Err("invalid_private_name");
        }
        self.revalidate()?;
        let file = open_at(
            self.leaf(),
            std::ffi::OsStr::new(name),
            (if write { libc::O_RDWR } else { libc::O_RDONLY })
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
            0,
        )?;
        file_metadata(&file, true)?;
        self.revalidate()?;
        Ok(file)
    }

    pub fn create_file(&self, name: &str) -> FsResult<File> {
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            return Err("invalid_private_name");
        }
        self.revalidate()?;
        let file = open_at(
            self.leaf(),
            std::ffi::OsStr::new(name),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )?;
        file_metadata(&file, true)?;
        file.sync_all().map_err(|_| "storage_unavailable")?;
        self.leaf().sync_all().map_err(|_| "storage_unavailable")?;
        self.revalidate()?;
        Ok(file)
    }

    /// Inspect the directory entry without opening or closing the target. A
    /// close of ANY descriptor for SQLite's inode releases this process's POSIX
    /// record locks, even when SQLite owns a different descriptor.
    fn stat_file(&self, name: &str) -> FsResult<Option<libc::stat>> {
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            return Err("invalid_private_name");
        }
        let name = c_name(std::ffi::OsStr::new(name))?;
        let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                self.leaf().as_raw_fd(),
                name.as_ptr(),
                info.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Ok(None)
            } else {
                Err("private_identity_unavailable")
            };
        }
        Ok(Some(unsafe { info.assume_init() }))
    }

    /// Preliminary inode admission only. The retained descriptor supplies the
    /// definitive metadata/ACL check before an SQLite connection is used.
    pub fn file_identity(&self, name: &str) -> FsResult<FileIdentity> {
        self.revalidate()?;
        let info = self.stat_file(name)?.ok_or("private_file_unavailable")?;
        stat_metadata(&info)?;
        self.revalidate()?;
        Ok(stat_identity(&info))
    }

    pub fn file_still_matches(&self, name: &str, held: &File) -> FsResult<()> {
        self.revalidate()?;
        file_metadata(held, true)?;
        let held = held
            .metadata()
            .map_err(|_| "private_identity_unavailable")?;
        let current = self.stat_file(name)?.ok_or("private_file_unavailable")?;
        stat_metadata(&current)?;
        if (held.dev(), held.ino()) != stat_identity(&current) {
            return Err("private_identity_changed");
        }
        self.revalidate()
    }

    pub fn inspect_optional_file(&self, name: &str) -> FsResult<()> {
        self.revalidate()?;
        let Some(before) = self.stat_file(name)? else {
            return Ok(());
        };
        stat_metadata(&before)?;
        // On macOS this is acl_get_link_np -> lstatx_np, not open/close.
        // Thus even an unsafe sidecar hardlinked to a live DB cannot drop locks.
        validate_acl_path(&self.path.join(name), true)?;
        let after = self.stat_file(name)?.ok_or("private_identity_changed")?;
        stat_metadata(&after)?;
        if stat_identity(&before) != stat_identity(&after) {
            return Err("private_identity_changed");
        }
        self.revalidate()
    }
}

// libc dev_t/ino_t have different native widths across Linux and macOS.
#[allow(clippy::unnecessary_cast)]
fn stat_identity(info: &libc::stat) -> FileIdentity {
    (info.st_dev as u64, info.st_ino as u64)
}

fn stat_metadata(info: &libc::stat) -> FsResult<()> {
    if info.st_mode & libc::S_IFMT != libc::S_IFREG
        || info.st_nlink != 1
        || info.st_uid != ordinary_owner()?
        || info.st_mode & 0o7177 != 0
    {
        return Err("unsafe_private_file");
    }
    Ok(())
}

/// Read a selected policy input without consulting runtime policy or following
/// links. Its parent need only be trusted; the input itself must be ordinary-owned.
pub fn read_input(path: &Path, cap: usize) -> FsResult<Vec<u8>> {
    let parent = Directory::open_with_leaf(path.parent().ok_or("invalid_path")?, false)?;
    let file = open_at(
        parent.leaf(),
        path.file_name().ok_or("invalid_path")?,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )?;
    file_metadata(&file, false)?;
    let before = file
        .metadata()
        .map_err(|_| "private_identity_unavailable")?;
    if before.len() > cap as u64 {
        return Err("input_too_large");
    }
    let mut bytes = Vec::new();
    (&file)
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "private_file_unavailable")?;
    let after = file
        .metadata()
        .map_err(|_| "private_identity_unavailable")?;
    if bytes.len() > cap
        || bytes.len() as u64 != before.len()
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err("private_identity_changed");
    }
    parent.revalidate_with_leaf(false)?;
    let current = open_at(
        parent.leaf(),
        path.file_name().ok_or("invalid_path")?,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )?;
    file_metadata(&current, false)?;
    same(&file, &current)?;
    Ok(bytes)
}

/// A failure keeps the newly created private file for explicit recovery. Never
/// unlink a pathname that another local administration action may have replaced.
pub fn write_new_secret(path: &Path, bytes: &[u8]) -> FsResult<()> {
    if bytes.len() > 4096 {
        return Err("credential_too_large");
    }
    let parent = Directory::open(path.parent().ok_or("invalid_path")?)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("invalid_path")?;
    let mut file = parent.create_file(name)?;
    file.write_all(bytes)
        .map_err(|_| "credential_write_failed")?;
    file.sync_all().map_err(|_| "credential_write_failed")?;
    parent
        .leaf()
        .sync_all()
        .map_err(|_| "credential_write_failed")?;
    parent.file_still_matches(name, &file)
}

#[cfg(target_os = "linux")]
fn validate_acl(_: &File, _: bool) -> FsResult<()> {
    // Named POSIX access ACL permissions are limited by the mode group mask.
    // Newly created private files use mode0600 regardless of inherited defaults.
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_acl_path(_: &Path, _: bool) -> FsResult<()> {
    // As for retained descriptors, the checked group mode mask bounds named ACLs.
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_acl(file: &File, private: bool) -> FsResult<()> {
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut std::ffi::c_void;
    }
    validate_acl_value(unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) }, private)
}

#[cfg(target_os = "macos")]
fn validate_acl_path(path: &Path, private: bool) -> FsResult<()> {
    unsafe extern "C" {
        fn acl_get_link_np(path: *const libc::c_char, kind: libc::c_int) -> *mut std::ffi::c_void;
    }
    let path = c_name(path.as_os_str())?;
    validate_acl_value(unsafe { acl_get_link_np(path.as_ptr(), 0x100) }, private)
}

#[cfg(target_os = "macos")]
fn validate_acl_value(raw: *mut std::ffi::c_void, private: bool) -> FsResult<()> {
    use std::ffi::c_void;
    unsafe extern "C" {
        fn acl_get_entry(acl: *mut c_void, id: libc::c_int, entry: *mut *mut c_void)
            -> libc::c_int;
        fn acl_get_tag_type(entry: *mut c_void, tag: *mut libc::c_int) -> libc::c_int;
        fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> libc::c_int;
        fn acl_free(acl: *mut c_void) -> libc::c_int;
    }
    if raw.is_null() {
        return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err("acl_unavailable")
        };
    }
    struct Acl(*mut c_void);
    impl Drop for Acl {
        fn drop(&mut self) {
            unsafe {
                acl_free(self.0);
            }
        }
    }
    let acl = Acl(raw);
    const MUTATING: u64 =
        (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 8) | (1 << 10) | (1 << 12) | (1 << 13);
    for index in 0..256 {
        let mut entry = std::ptr::null_mut();
        if unsafe { acl_get_entry(acl.0, if index == 0 { 0 } else { -1 }, &mut entry) } != 0 {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                Ok(())
            } else {
                Err("acl_unavailable")
            };
        }
        let (mut tag, mut mask) = (0, 0);
        if unsafe { acl_get_tag_type(entry, &mut tag) } != 0
            || unsafe { acl_get_permset_mask_np(entry, &mut mask) } != 0
        {
            return Err("acl_unavailable");
        }
        if tag == 1
            && (if private {
                mask != 0
            } else {
                mask & MUTATING != 0
            })
        {
            return Err("unsafe_private_acl");
        }
    }
    Err("acl_limit")
}
