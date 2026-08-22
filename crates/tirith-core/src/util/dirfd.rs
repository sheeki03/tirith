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
//! Windows uses retained directory handles plus `NtCreateFile` with
//! `OBJECT_ATTRIBUTES.RootDirectory`, and `NtQueryDirectoryFile` enumerates the
//! same retained handle. Targets without either primitive fail closed instead
//! of presenting a path-based fallback as a capability.

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

/// Stable identity of an object reached through an open filesystem handle.
///
/// Unix supplies `(st_dev, st_ino)`. Windows supplies the volume serial number
/// and the 64-bit file index returned by `GetFileInformationByHandle`. Both are
/// taken from the OPEN object, never from a pathname that can be rebound between
/// inspection and use.
pub(crate) type FileIdentity = (u64, u64);

pub(crate) fn file_identity(file: &File) -> std::io::Result<FileIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let metadata = file.metadata()?;
        Ok((metadata.dev(), metadata.ino()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };

        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the file handle is live and `info` is writable.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((
            u64::from(info.dwVolumeSerialNumber),
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        ))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err(unsupported_capability())
    }
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
    /// The apparent path, kept for reporting only. Capability operations never
    /// use it to resolve a child.
    path: PathBuf,
    #[cfg(unix)]
    fd: std::os::fd::OwnedFd,
    #[cfg(windows)]
    handle: File,
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
        #[cfg(windows)]
        {
            let handle = windows_open_root(path)?;
            Ok(Self {
                path: path.to_path_buf(),
                handle,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            Err(ChildError::Io(unsupported_capability()))
        }
    }

    /// The apparent path of this directory, used only in diagnostics.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Metadata for the retained directory itself, never for a freshly
    /// re-resolved pathname.
    pub(crate) fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        #[cfg(unix)]
        {
            let file = File::from(self.fd.try_clone()?);
            file.metadata()
        }
        #[cfg(windows)]
        {
            self.handle.metadata()
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(unsupported_capability())
        }
    }

    /// Stable identity of this retained directory handle.
    pub(crate) fn identity(&self) -> std::io::Result<FileIdentity> {
        #[cfg(unix)]
        {
            file_identity(&File::from(self.fd.try_clone()?))
        }
        #[cfg(windows)]
        {
            file_identity(&self.handle)
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(unsupported_capability())
        }
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
        #[cfg(windows)]
        {
            reject_unsafe_component(name)?;
            let handle = windows_open_relative(
                &self.handle,
                &self.path,
                name,
                windows_directory_access(),
                windows_directory_options(),
                windows_directory_attributes(),
            )
            .map_err(ChildError::Io)?;
            let facts = windows_handle_facts(&handle).map_err(ChildError::Io)?;
            if facts.reparse {
                return Err(ChildError::Symlink);
            }
            if !facts.directory {
                return Err(ChildError::NotADirectory);
            }
            Ok(Self {
                path: child_path,
                handle,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = child_path;
            let _ = name;
            Err(ChildError::Io(unsupported_capability()))
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
        #[cfg(windows)]
        {
            reject_unsafe_component(name).map_err(|_| OpenRegularError::NotRegularFile)?;
            let file = windows_open_relative(
                &self.handle,
                &self.path,
                name,
                windows_file_access(),
                windows_file_options(),
                windows_file_attributes(),
            )
            .map_err(classify_windows_file_error)?;
            let facts = windows_handle_facts(&file).map_err(OpenRegularError::Io)?;
            if facts.reparse || facts.directory {
                return Err(OpenRegularError::NotRegularFile);
            }
            super::check_regular_capped(file, cap)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = name;
            let _ = cap;
            Err(OpenRegularError::Io(unsupported_capability()))
        }
    }

    /// Re-open a descendant directory from this retained root, one no-follow
    /// component at a time. `relative` is the `/`-normalized spelling emitted
    /// by the capability walker itself.
    pub(crate) fn open_descendant_directory(&self, relative: &str) -> Result<Self, ChildError> {
        let mut components = relative.split('/').peekable();
        if components.peek().is_none() {
            return Err(ChildError::UnsafeName);
        }
        let mut current = None;
        for component in components {
            let parent = current.as_ref().unwrap_or(self);
            current = Some(parent.open_child_directory(component)?);
        }
        current.ok_or(ChildError::UnsafeName)
    }

    /// Re-open a descendant regular file from this retained root. Every parent
    /// is opened relative to the previously retained directory and the final
    /// component is opened no-follow and size-capped.
    pub(crate) fn open_descendant_file(
        &self,
        relative: &str,
        cap: u64,
    ) -> Result<File, OpenRegularError> {
        let mut components = relative.split('/').peekable();
        let Some(first) = components.next() else {
            return Err(OpenRegularError::NotRegularFile);
        };
        if components.peek().is_none() {
            return self.open_child_file(first, cap);
        }

        let mut current = self
            .open_child_directory(first)
            .map_err(child_as_file_error)?;
        while let Some(component) = components.next() {
            if components.peek().is_none() {
                return current.open_child_file(component, cap);
            }
            current = current
                .open_child_directory(component)
                .map_err(child_as_file_error)?;
        }
        Err(OpenRegularError::NotRegularFile)
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
            use std::os::fd::{AsRawFd as _, FromRawFd as _};

            // `dup`/`try_clone` shares one directory offset with the retained
            // descriptor. That made a second quiescence listing start at EOF.
            // Opening `.` relative to the retained descriptor creates a fresh
            // open-file description at offset zero without resolving any
            // attacker-controlled pathname component.
            let fresh =
                unsafe { libc::openat(self.fd.as_raw_fd(), c".".as_ptr(), DIRECTORY_FLAGS) };
            if fresh < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: openat returned a fresh owned descriptor.
            let fresh = unsafe { std::os::fd::OwnedFd::from_raw_fd(fresh) };
            let mut stream = DirStream::adopt(fresh)?;
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
        #[cfg(windows)]
        {
            windows_read_entries(&self.handle, max_entries)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = max_entries;
            Err(unsupported_capability())
        }
    }
}

fn child_as_file_error(error: ChildError) -> OpenRegularError {
    match error {
        ChildError::Symlink | ChildError::NotADirectory | ChildError::UnsafeName => {
            OpenRegularError::NotRegularFile
        }
        ChildError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
            OpenRegularError::NotFound
        }
        ChildError::Io(error) => OpenRegularError::Io(error),
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

#[cfg(windows)]
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

#[cfg(windows)]
#[derive(Clone, Copy)]
struct WindowsHandleFacts {
    directory: bool,
    reparse: bool,
}

#[cfg(windows)]
fn windows_handle_facts(file: &File) -> std::io::Result<WindowsHandleFacts> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the file handle is live and `info` is writable.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(WindowsHandleFacts {
        directory: info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
        reparse: info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
    })
}

#[cfg(windows)]
fn windows_open_root(path: &Path) -> Result<File, ChildError> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::FromRawHandle as _;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
        OPEN_EXISTING, SYNCHRONIZE,
    };

    let encoded = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: `encoded` is NUL-terminated and CreateFileW returns a fresh
    // handle on success.
    let raw = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(ChildError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: ownership of the newly opened handle transfers to `File`.
    let file = unsafe { File::from_raw_handle(raw) };
    let facts = windows_handle_facts(&file).map_err(ChildError::Io)?;
    if facts.reparse {
        return Err(ChildError::Symlink);
    }
    if !facts.directory {
        return Err(ChildError::NotADirectory);
    }
    Ok(file)
}

#[cfg(windows)]
fn windows_directory_access() -> u32 {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_TRAVERSE,
    };
    FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES
}

#[cfg(windows)]
fn windows_file_access() -> u32 {
    use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_READ, FILE_READ_ATTRIBUTES};
    FILE_GENERIC_READ | FILE_READ_ATTRIBUTES
}

#[cfg(windows)]
fn windows_directory_options() -> u32 {
    windows_sys::Wdk::Storage::FileSystem::FILE_DIRECTORY_FILE
}

#[cfg(windows)]
fn windows_file_options() -> u32 {
    windows_sys::Wdk::Storage::FileSystem::FILE_NON_DIRECTORY_FILE
}

#[cfg(windows)]
fn windows_directory_attributes() -> u32 {
    windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_DIRECTORY
}

#[cfg(windows)]
fn windows_file_attributes() -> u32 {
    windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL
}

#[cfg(windows)]
fn windows_open_relative(
    parent: &File,
    display_parent: &Path,
    name: &str,
    access: u32,
    options: u32,
    attributes: u32,
) -> std::io::Result<File> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use std::ptr::{null, null_mut};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        NtCreateFile, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    };
    use windows_sys::Win32::Foundation::{
        RtlNtStatusToDosError, HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    reject_unsafe_component(name).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unsafe Windows capability component",
        )
    })?;
    let mut encoded = std::ffi::OsStr::new(name).encode_wide().collect::<Vec<_>>();
    let length = u16::try_from(encoded.len() * std::mem::size_of::<u16>()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows capability component is too long",
        )
    })?;
    let unicode = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: encoded.as_mut_ptr(),
    };
    let attributes_block = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let mut status_block = IO_STATUS_BLOCK::default();
    let mut handle: HANDLE = null_mut();
    // SAFETY: every pointer references live storage, RootDirectory is a
    // retained directory handle, and ObjectName is one validated component.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access | SYNCHRONIZE,
            &attributes_block,
            &mut status_block,
            null(),
            attributes,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: translating an NTSTATUS has no memory preconditions.
        let code = unsafe { RtlNtStatusToDosError(status) };
        let source = std::io::Error::from_raw_os_error(code as i32);
        return Err(std::io::Error::new(
            source.kind(),
            format!(
                "open retained child {}: {source}",
                display_parent.join(name).display()
            ),
        ));
    }
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::other(
            "NtCreateFile returned no retained handle",
        ));
    }
    // SAFETY: ownership of the newly opened handle transfers to `File`.
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(windows)]
fn classify_windows_file_error(error: std::io::Error) -> OpenRegularError {
    if error.kind() == std::io::ErrorKind::NotFound {
        OpenRegularError::NotFound
    } else {
        OpenRegularError::Io(error)
    }
}

#[cfg(windows)]
fn windows_read_entries(
    directory: &File,
    max_entries: usize,
) -> std::io::Result<(Vec<DirEntryFacts>, bool)> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use std::ptr::{null, null_mut};
    use windows_sys::Wdk::Storage::FileSystem::{
        FileIdBothDirectoryInformation, NtQueryDirectoryFile, FILE_ID_BOTH_DIR_INFORMATION,
    };
    use windows_sys::Win32::Foundation::{RtlNtStatusToDosError, STATUS_NO_MORE_FILES};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    const BUFFER_SIZE: usize = 64 * 1024;
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut entries = Vec::new();
    let mut restart = true;
    loop {
        let mut io_status = IO_STATUS_BLOCK::default();
        // SAFETY: the directory handle is synchronous and retained; buffer and
        // status storage are live for the whole call.
        let status = unsafe {
            NtQueryDirectoryFile(
                directory.as_raw_handle(),
                null_mut(),
                None,
                null(),
                &mut io_status,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                FileIdBothDirectoryInformation,
                false,
                null(),
                restart,
            )
        };
        restart = false;
        if status == STATUS_NO_MORE_FILES {
            break;
        }
        if status < 0 {
            // SAFETY: pure status translation.
            let code = unsafe { RtlNtStatusToDosError(status) };
            return Err(std::io::Error::from_raw_os_error(code as i32));
        }
        let used = io_status.Information.min(buffer.len());
        if used == 0 {
            return Err(std::io::Error::other(
                "retained Windows directory enumeration made no progress",
            ));
        }
        let mut offset = 0usize;
        while offset < used {
            let name_offset = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFORMATION, FileName);
            let remaining = used.saturating_sub(offset);
            if remaining < name_offset + std::mem::size_of::<u16>() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "truncated retained Windows directory record",
                ));
            }
            // SAFETY: the kernel returned a chain of directory records inside
            // `used` bytes; unaligned read avoids assuming buffer alignment.
            let info = unsafe {
                std::ptr::read_unaligned(
                    buffer
                        .as_ptr()
                        .add(offset)
                        .cast::<FILE_ID_BOTH_DIR_INFORMATION>(),
                )
            };
            if name_offset.saturating_add(info.FileNameLength as usize) > remaining
                || info.FileNameLength as usize % std::mem::size_of::<u16>() != 0
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "malformed retained Windows directory record",
                ));
            }
            let name_bytes =
                &buffer[offset + name_offset..offset + name_offset + info.FileNameLength as usize];
            let wide_name = name_bytes
                .chunks_exact(std::mem::size_of::<u16>())
                .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
                .collect::<Vec<_>>();
            let os_name = OsString::from_wide(&wide_name);
            if os_name != "." && os_name != ".." {
                if entries.len() >= max_entries {
                    return Ok((entries, true));
                }
                let kind = if info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    EntryKind::Symlink
                } else if info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                    EntryKind::Directory
                } else {
                    EntryKind::RegularFile
                };
                entries.push(DirEntryFacts {
                    name: os_name.to_str().map(str::to_owned),
                    kind,
                });
            }
            if info.NextEntryOffset == 0 {
                break;
            }
            if info.NextEntryOffset as usize > remaining
                || (info.NextEntryOffset as usize) < name_offset
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "malformed retained Windows directory chain",
                ));
            }
            offset = offset.saturating_add(info.NextEntryOffset as usize);
        }
    }
    Ok((entries, false))
}

#[cfg(not(any(unix, windows)))]
fn unsupported_capability() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "retained directory capabilities are unavailable on this target",
    )
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

    #[test]
    fn a_retained_directory_can_be_reenumerated_from_the_beginning() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::write(root.path().join("first"), b"x").expect("file");
        let capability = DirCapability::open_root(root.path()).expect("root");

        let (first, truncated) = capability.read_entries(64).expect("first listing");
        assert!(!truncated);
        assert_eq!(
            first
                .into_iter()
                .filter_map(|entry| entry.name)
                .collect::<Vec<_>>(),
            vec!["first".to_string()]
        );

        std::fs::write(root.path().join("second"), b"x").expect("second file");
        let (second, truncated) = capability.read_entries(64).expect("second listing");
        assert!(!truncated);
        let mut names = second
            .into_iter()
            .filter_map(|entry| entry.name)
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, vec!["first".to_string(), "second".to_string()]);
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
