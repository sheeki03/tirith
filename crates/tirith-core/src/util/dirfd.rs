//! Directory CAPABILITIES for walks that must not re-resolve a path component.
//!
//! A path-based walk checks `root/sub` with `lstat` and then re-opens `root/sub`
//! by name to read it. A local attacker who swaps `sub` for a symlink between
//! those two resolutions gets the walker to enumerate, and hash, whatever the
//! link points at. The window is as wide as whatever the walker did in between,
//! which for a deferred stack is the entire sibling subtree.
//!
//! [`DirCapability`] removes the second resolution. On unix a directory is
//! opened once with `O_DIRECTORY | O_NOFOLLOW` and the descriptor is RETAINED;
//! every later step is `fstatat` / `openat` relative to that descriptor with a
//! single safe name component. A component swapped after the fact is then
//! unreachable rather than merely unlikely, because the name is never resolved
//! from the filesystem root again.
//!
//! On a target without `openat` the same API is backed by path joins plus
//! `symlink_metadata`, which is the best available there; callers that need the
//! containment guarantee on those targets pair this with
//! [`super::canonical_within`].

use std::fs::File;
use std::path::{Path, PathBuf};

use super::OpenRegularError;

/// What a directory entry is, decided by an `lstat` that never follows a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum EntryKind {
    Directory,
    RegularFile,
    Symlink,
    /// A fifo, socket, device, or anything else this walk does not read.
    Other,
}

/// One directory entry as the capability saw it. `name` is `None` for a name
/// that is not valid UTF-8: such an entry can be REPORTED but never opened,
/// because it cannot be recorded or compared.
#[derive(Debug, Clone)]
pub(crate) struct DirEntryFacts {
    pub(crate) name: Option<String>,
    pub(crate) kind: EntryKind,
}

/// Why one entry could not be turned into a child capability.
#[derive(Debug)]
pub(crate) enum ChildError {
    /// The component is a symlink (or became one), so it was not followed.
    Symlink,
    /// The component is not a directory.
    NotADirectory,
    /// The name cannot be handed to the OS (an interior NUL, `.`, `..`, or a
    /// separator). Never produced by a real listing; refused rather than joined.
    UnsafeName,
    Io(std::io::Error),
}

/// A retained handle on one directory.
pub(crate) struct DirCapability {
    /// The APPARENT path, kept for reporting and for the non-unix fallback. On
    /// unix it is never used to resolve anything.
    path: PathBuf,
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
}

impl DirCapability {
    /// Open `path` as a directory capability. `O_NOFOLLOW` applies to the final
    /// component, so a symlinked root is refused rather than followed.
    pub(crate) fn open_root(path: &Path) -> Result<Self, ChildError> {
        #[cfg(unix)]
        {
            let raw = c_name_from_path(path)?;
            // SAFETY: the buffer is NUL-terminated and lives across the call.
            let fd = unsafe { libc::open(raw.as_ptr(), DIRECTORY_FLAGS) };
            if fd < 0 {
                return Err(classify_open_error(
                    std::io::Error::last_os_error(),
                    libc::AT_FDCWD,
                    &raw,
                ));
            }
            // SAFETY: open returned a fresh owned descriptor.
            let fd = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
            Ok(Self {
                path: path.to_path_buf(),
                fd,
            })
        }
        #[cfg(not(unix))]
        {
            let metadata = std::fs::symlink_metadata(path).map_err(ChildError::Io)?;
            if metadata.file_type().is_symlink() {
                return Err(ChildError::Symlink);
            }
            if !metadata.is_dir() {
                return Err(ChildError::NotADirectory);
            }
            Ok(Self {
                path: path.to_path_buf(),
            })
        }
    }

    /// The apparent path of this directory. On unix every component of it was
    /// opened with `O_NOFOLLOW` from the root down, so it is also the real one.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Descend into `name`, refusing a symlinked component without following it.
    pub(crate) fn open_child_directory(&self, name: &str) -> Result<Self, ChildError> {
        let child_path = self.path.join(name);
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;

            let raw = c_name_from_component(name)?;
            // SAFETY: `fd` is a live directory descriptor and `raw` is a
            // NUL-terminated single component.
            let fd = unsafe { libc::openat(self.fd.as_raw_fd(), raw.as_ptr(), DIRECTORY_FLAGS) };
            if fd < 0 {
                return Err(classify_open_error(
                    std::io::Error::last_os_error(),
                    self.fd.as_raw_fd(),
                    &raw,
                ));
            }
            // SAFETY: openat returned a fresh owned descriptor.
            let fd = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd) };
            Ok(Self {
                path: child_path,
                fd,
            })
        }
        #[cfg(not(unix))]
        {
            reject_unsafe_component(name)?;
            Self::open_root(&child_path)
        }
    }

    /// Open `name` as a regular file no larger than `cap` bytes, refusing a
    /// symlinked component. The type and size gate is an `fstat` of the OPEN
    /// descriptor, so a swap after the open cannot substitute another inode.
    pub(crate) fn open_child_file(&self, name: &str, cap: u64) -> Result<File, OpenRegularError> {
        #[cfg(unix)]
        {
            use std::os::fd::{AsRawFd as _, FromRawFd as _};

            let raw = c_name_from_component(name).map_err(|_| OpenRegularError::NotRegularFile)?;
            // O_NOFOLLOW so a symlinked component fails ELOOP; O_NONBLOCK so a
            // fifo planted at this name returns immediately instead of blocking
            // on a writer, and the post-open fstat then refuses it.
            let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
            // SAFETY: `fd` is live and `raw` is a NUL-terminated component.
            let opened = unsafe { libc::openat(self.fd.as_raw_fd(), raw.as_ptr(), flags) };
            if opened < 0 {
                let error = std::io::Error::last_os_error();
                return Err(match error.raw_os_error() {
                    Some(libc::ELOOP) => OpenRegularError::NotRegularFile,
                    Some(libc::ENOENT) => OpenRegularError::NotFound,
                    _ => OpenRegularError::Io(error),
                });
            }
            // SAFETY: openat returned a fresh owned descriptor.
            let file = unsafe { File::from_raw_fd(opened) };
            super::check_regular_capped(file, cap)
        }
        #[cfg(not(unix))]
        {
            reject_unsafe_component(name).map_err(|_| OpenRegularError::NotRegularFile)?;
            super::open_read_no_follow_capped(&self.path.join(name), cap)
        }
    }

    /// List this directory, stopping once `max_entries` names have been
    /// collected. The cap is enforced DURING the read rather than after it: the
    /// point of a cap is that a hostile directory cannot make the walker
    /// allocate an unbounded listing in the first place.
    ///
    /// The returned `bool` is true when the listing was truncated by the cap.
    pub(crate) fn read_entries(
        &self,
        max_entries: usize,
    ) -> std::io::Result<(Vec<DirEntryFacts>, bool)> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;

            let duplicated = self.fd.try_clone()?;
            let mut stream = DirStream::adopt(duplicated)?;
            let mut entries = Vec::new();
            let mut truncated = false;
            while let Some(raw) = stream.next_name()? {
                let bytes = raw.to_bytes();
                if bytes == b"." || bytes == b".." {
                    continue;
                }
                if entries.len() >= max_entries {
                    truncated = true;
                    break;
                }
                let name = std::str::from_utf8(bytes).ok().map(str::to_owned);
                // fstatat against the RETAINED descriptor, so the entry that is
                // classified is the entry this listing named.
                let kind = match stat_at(self.fd.as_raw_fd(), raw) {
                    Ok(status) => entry_kind_of(status.st_mode),
                    Err(_) => EntryKind::Other,
                };
                entries.push(DirEntryFacts { name, kind });
            }
            Ok((entries, truncated))
        }
        #[cfg(not(unix))]
        {
            let mut entries = Vec::new();
            let mut truncated = false;
            for entry in std::fs::read_dir(&self.path)? {
                let entry = entry?;
                if entries.len() >= max_entries {
                    truncated = true;
                    break;
                }
                let name = entry.file_name().to_str().map(str::to_owned);
                let kind = match std::fs::symlink_metadata(entry.path()) {
                    Ok(metadata) if metadata.file_type().is_symlink() => EntryKind::Symlink,
                    Ok(metadata) if metadata.is_dir() => EntryKind::Directory,
                    Ok(metadata) if metadata.is_file() => EntryKind::RegularFile,
                    Ok(_) => EntryKind::Other,
                    Err(_) => EntryKind::Other,
                };
                entries.push(DirEntryFacts { name, kind });
            }
            Ok((entries, truncated))
        }
    }
}

/// How many directory entries link to this open file. `None` on a target where
/// the count is not portably available, which callers must treat as "unknown"
/// rather than as one.
///
/// A second link means the same content is reachable under a name the walk never
/// saw, so a file hashed as part of an audited tree may in fact be a store the
/// audit promised never to read.
pub(crate) fn hard_link_count(file: &File) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        file.metadata().ok().map(|metadata| metadata.nlink())
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        None
    }
}

#[cfg(not(unix))]
fn reject_unsafe_component(name: &str) -> Result<(), ChildError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(ChildError::UnsafeName);
    }
    Ok(())
}

#[cfg(unix)]
const DIRECTORY_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// Name a refused open. The refusal already happened; this only decides WHICH
/// refusal to report, so a lost race here mislabels a rejection and can never
/// open anything.
///
/// The errno is not enough on its own: `O_NOFOLLOW | O_DIRECTORY` against a
/// symlink is `ELOOP` on Linux but `ENOTDIR` on macOS, so a plain errno match
/// would report a symlink as an ordinary non-directory on exactly the host this
/// product ships on most. An `AT_SYMLINK_NOFOLLOW` stat settles it.
#[cfg(unix)]
fn classify_open_error(error: std::io::Error, parent: i32, name: &std::ffi::CStr) -> ChildError {
    match error.raw_os_error() {
        // Some BSDs report EMLINK for the O_NOFOLLOW refusal.
        Some(libc::ELOOP) | Some(libc::EMLINK) => ChildError::Symlink,
        Some(libc::ENOTDIR) => match stat_at(parent, name) {
            Ok(status) if entry_kind_of(status.st_mode) == EntryKind::Symlink => {
                ChildError::Symlink
            }
            _ => ChildError::NotADirectory,
        },
        _ => ChildError::Io(error),
    }
}

#[cfg(unix)]
fn c_name_from_path(path: &Path) -> Result<std::ffi::CString, ChildError> {
    use std::os::unix::ffi::OsStrExt as _;
    std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| ChildError::UnsafeName)
}

#[cfg(unix)]
fn c_name_from_component(name: &str) -> Result<std::ffi::CString, ChildError> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(ChildError::UnsafeName);
    }
    std::ffi::CString::new(name).map_err(|_| ChildError::UnsafeName)
}

#[cfg(unix)]
fn entry_kind_of(mode: libc::mode_t) -> EntryKind {
    match mode & libc::S_IFMT {
        libc::S_IFLNK => EntryKind::Symlink,
        libc::S_IFDIR => EntryKind::Directory,
        libc::S_IFREG => EntryKind::RegularFile,
        _ => EntryKind::Other,
    }
}

#[cfg(unix)]
fn stat_at(parent: i32, name: &std::ffi::CStr) -> std::io::Result<libc::stat> {
    let mut buffer = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `parent` is live, `name` is NUL-terminated, and the output buffer
    // is writable for the whole call.
    let status = unsafe {
        libc::fstatat(
            parent,
            name.as_ptr(),
            buffer.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fstatat initialized the structure on success.
    Ok(unsafe { buffer.assume_init() })
}

/// Reset `errno` so a NULL `readdir` can be classified.
///
/// The symbol differs per libc, and on a platform this does not know how to
/// clear, a stale non-zero `errno` makes the read look failed. That is the
/// fail-closed direction: the walk reports an enumeration gap instead of
/// returning a listing it cannot vouch for.
#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
fn clear_errno() {
    // SAFETY: __errno_location returns this thread's errno slot.
    unsafe { *libc::__errno_location() = 0 };
}

#[cfg(all(
    unix,
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly"
    )
))]
fn clear_errno() {
    // SAFETY: __error returns this thread's errno slot.
    unsafe { *libc::__error() = 0 };
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly"
    ))
))]
fn clear_errno() {}

/// `fdopendir` takes ownership of the descriptor it is handed, so this wrapper
/// adopts an `OwnedFd` and releases it without a double close.
#[cfg(unix)]
struct DirStream(*mut libc::DIR);

#[cfg(unix)]
impl DirStream {
    fn adopt(fd: std::os::fd::OwnedFd) -> std::io::Result<Self> {
        use std::os::fd::AsRawFd as _;

        let raw = fd.as_raw_fd();
        // SAFETY: `raw` is a live directory descriptor this call takes over.
        let stream = unsafe { libc::fdopendir(raw) };
        if stream.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        // The stream owns the descriptor now; closedir will close it.
        std::mem::forget(fd);
        Ok(Self(stream))
    }

    fn next_name(&mut self) -> std::io::Result<Option<&std::ffi::CStr>> {
        // readdir returns NULL for both end-of-directory and error, so errno is
        // the only way to tell them apart, and that distinction is load-bearing:
        // a truncated listing would produce a silently partial audit.
        clear_errno();
        // SAFETY: the stream is live for the lifetime of this wrapper.
        let entry = unsafe { libc::readdir(self.0) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(0) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        // SAFETY: readdir returned a live entry owned by the stream, and the
        // borrow ends before the next readdir call.
        Ok(Some(unsafe {
            std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())
        }))
    }
}

#[cfg(unix)]
impl Drop for DirStream {
    fn drop(&mut self) {
        // SAFETY: the stream was created by fdopendir and is closed once.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listing_reports_every_entry_kind() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(root.path().join("sub")).expect("dir");
        std::fs::write(root.path().join("file"), b"x").expect("file");
        let capability = DirCapability::open_root(root.path()).expect("root");
        let (entries, truncated) = capability.read_entries(64).expect("listing");
        assert!(!truncated);
        let mut kinds: Vec<(String, EntryKind)> = entries
            .into_iter()
            .map(|entry| (entry.name.expect("utf8 name"), entry.kind))
            .collect();
        kinds.sort();
        assert_eq!(
            kinds,
            vec![
                ("file".to_string(), EntryKind::RegularFile),
                ("sub".to_string(), EntryKind::Directory),
            ]
        );
    }

    #[test]
    fn the_entry_cap_is_enforced_during_the_read() {
        let root = tempfile::tempdir().expect("tempdir");
        for index in 0..8 {
            std::fs::write(root.path().join(format!("f{index}")), b"x").expect("file");
        }
        let capability = DirCapability::open_root(root.path()).expect("root");
        let (entries, truncated) = capability.read_entries(3).expect("listing");
        assert_eq!(entries.len(), 3);
        assert!(truncated, "the cap must be reported, not silently applied");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_component_is_refused_rather_than_followed() {
        let root = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("tempdir");
        std::fs::write(outside.path().join("secret"), b"secret").expect("file");
        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).expect("symlink");
        let capability = DirCapability::open_root(root.path()).expect("root");
        assert!(matches!(
            capability.open_child_directory("link"),
            Err(ChildError::Symlink)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_swapped_component_cannot_be_reached_through_a_retained_descriptor() {
        let root = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("tempdir");
        std::fs::write(outside.path().join("PROOF"), b"outside").expect("file");
        let inner = root.path().join("sub");
        std::fs::create_dir(&inner).expect("dir");
        std::fs::write(inner.join("inside"), b"inside").expect("file");

        let capability = DirCapability::open_root(root.path()).expect("root");
        let child = capability.open_child_directory("sub").expect("descend");
        // The swap a path-based walk would follow on its next resolution.
        std::fs::remove_dir_all(&inner).expect("remove");
        std::os::unix::fs::symlink(outside.path(), &inner).expect("symlink");

        let (entries, _) = child.read_entries(64).expect("listing");
        let names: Vec<String> = entries.into_iter().filter_map(|entry| entry.name).collect();
        assert!(
            !names.iter().any(|name| name == "PROOF"),
            "the retained descriptor must never reach the swapped-in target: {names:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_hard_link_is_counted_from_the_open_descriptor() {
        let root = tempfile::tempdir().expect("tempdir");
        let target = root.path().join("target");
        std::fs::write(&target, b"x").expect("file");
        std::fs::hard_link(&target, root.path().join("alias")).expect("hard link");
        let capability = DirCapability::open_root(root.path()).expect("root");
        let file = capability.open_child_file("alias", 1024).expect("open");
        assert_eq!(hard_link_count(&file), Some(2));
    }
}
