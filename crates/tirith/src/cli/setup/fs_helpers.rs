//! Filesystem helpers for `tirith setup` — atomic writes, hook scripts,
//! directory validation, CLI subprocess runner, and backup management.

#[path = "fs_retention_unix.rs"]
mod retention;
pub(crate) use retention::{open_existing_in_place, InPlaceLease};

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::{cell::RefCell, rc::Rc};

use fs2::FileExt;
use sha2::{Digest, Sha256};

use super::fs_transaction::PublicationOutcome;
pub(crate) use super::fs_transaction::{
    transactional_update, transactional_update_checked, FileUpdate, TransactionOutcome,
};

struct ScopedParent {
    dir: fs::File,
    name: CString,
}

fn c_name(name: &OsStr) -> Result<CString, String> {
    CString::new(name.as_bytes()).map_err(|_| "path component contains NUL".to_string())
}

fn absolute(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|e| format!("current_dir: {e}"))
    }
}

fn relative_components<'a>(path: &'a Path, root: &Path) -> Result<Vec<&'a OsStr>, String> {
    let relative = path.strip_prefix(root).map_err(|_| {
        format!(
            "{} is outside trusted setup root {}",
            path.display(),
            root.display()
        )
    })?;
    relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(name) => Ok(name),
            _ => Err(format!(
                "{} contains a non-normal path component",
                path.display()
            )),
        })
        .collect()
}

fn open_dir(path: &Path) -> Result<fs::File, String> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("{} contains NUL", path.display()))?;
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "open trusted root {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

fn open_dir_at(parent: &fs::File, name: &CString) -> std::io::Result<fs::File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
}

/// Open the destination parent beneath an explicitly trusted root. The root is
/// canonicalized once (allowing normal platform aliases such as macOS `/var`),
/// while every attacker-controlled descendant is traversed with `O_NOFOLLOW`.
fn scoped_parent(
    path: &Path,
    scope_root: &Path,
    create: bool,
) -> Result<Option<ScopedParent>, String> {
    let path = absolute(path)?;
    let root = absolute(scope_root)?;
    let components = relative_components(&path, &root)?;
    let (name, parents) = components
        .split_last()
        .ok_or_else(|| format!("{} names the trusted root, not a file", path.display()))?;

    let mut anchor = root.clone();
    let mut missing_root = Vec::new();
    while !anchor.exists() {
        let component = anchor
            .file_name()
            .ok_or_else(|| format!("cannot resolve trusted root {}", root.display()))?;
        missing_root.push(component.to_os_string());
        if !anchor.pop() {
            return Err(format!("cannot resolve trusted root {}", root.display()));
        }
    }
    let canonical_root = anchor
        .canonicalize()
        .map_err(|e| format!("canonicalize trusted root {}: {e}", anchor.display()))?;
    let mut dir = open_dir(&canonical_root)?;

    for component in missing_root
        .iter()
        .rev()
        .map(|part| part.as_os_str())
        .chain(parents.iter().copied())
    {
        let component = c_name(component)?;
        match open_dir_at(&dir, &component) {
            Ok(next) => dir = next,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
                let rc = unsafe { libc::mkdirat(dir.as_raw_fd(), component.as_ptr(), 0o755) };
                let created = rc == 0;
                if rc < 0 {
                    let mkdir_error = std::io::Error::last_os_error();
                    if mkdir_error.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(format!(
                            "create directory component {} below {}: {mkdir_error}",
                            component.to_string_lossy(),
                            canonical_root.display()
                        ));
                    }
                }
                if created {
                    // `mkdirat` only makes the entry visible. Persist the
                    // containing directory before descending so a crash cannot
                    // leave a published file whose newly-created ancestor was
                    // never committed to stable storage.
                    dir.sync_all().map_err(|error| {
                        format!(
                            "sync directory after creating component {} below {}: {error}",
                            component.to_string_lossy(),
                            canonical_root.display()
                        )
                    })?;
                }
                dir = open_dir_at(&dir, &component).map_err(|e| {
                    format!(
                        "open directory component {} below {} without following links: {e}",
                        component.to_string_lossy(),
                        canonical_root.display()
                    )
                })?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(format!(
                    "open directory component {} below {} without following links: {error}",
                    component.to_string_lossy(),
                    canonical_root.display()
                ));
            }
        }
    }

    Ok(Some(ScopedParent {
        dir,
        name: c_name(name)?,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StableFileState {
    identity: FileIdentity,
    size: u64,
    mode: u32,
    owner: u32,
    links: u64,
    digest: [u8; 32],
}

type CleanupFailures = Rc<RefCell<Vec<String>>>;

#[cfg(test)]
type BackupRetirementTestHook = RefCell<Option<Box<dyn FnMut(&Path)>>>;

#[cfg(test)]
thread_local! {
    static SCRUB_FAILURE_TEST_HOOK: RefCell<Option<&'static str>> = const { RefCell::new(None) };
    static BACKUP_RETIREMENT_TEST_HOOK: BackupRetirementTestHook = RefCell::new(None);
}

fn inject_scrub_failure(_label: &str) -> Result<(), String> {
    #[cfg(test)]
    if SCRUB_FAILURE_TEST_HOOK
        .with(|slot| slot.borrow().is_some_and(|target| _label.contains(target)))
    {
        return Err(format!("injected {_label} cleanup failure"));
    }
    Ok(())
}

fn scrub_guard_file(file: &mut fs::File, label: &str) -> Result<(), String> {
    inject_scrub_failure(label)?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect {label} before cleanup: {error}"))?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(format!(
            "refuse to scrub {label}: expected one regular-file link, observed {}",
            metadata.nlink()
        ));
    }
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } < 0 {
        return Err(format!(
            "restrict {label} before cleanup: {}",
            std::io::Error::last_os_error()
        ));
    }
    file.sync_all()
        .map_err(|error| format!("sync restricted {label}: {error}"))?;
    file.set_len(0)
        .map_err(|error| format!("scrub {label}: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("sync scrubbed {label}: {error}"))
}

fn open_stable_file_at(
    parent: &fs::File,
    name: &CStr,
) -> Result<Option<(fs::File, StableFileState)>, String> {
    open_stable_file_at_with_access(parent, name, libc::O_RDONLY)
}

fn open_stable_file_at_with_access(
    parent: &fs::File,
    name: &CStr,
    access: libc::c_int,
) -> Result<Option<(fs::File, StableFileState)>, String> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            access | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(format!(
            "open publication identity without following links: {error}"
        ));
    }
    stable_state_from_open_file(unsafe { fs::File::from_raw_fd(fd) }).map(Some)
}

fn stable_state_from_open_file(mut file: fs::File) -> Result<(fs::File, StableFileState), String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("seek publication identity: {error}"))?;
    let before = file
        .metadata()
        .map_err(|error| format!("inspect publication identity: {error}"))?;
    if !before.is_file() || before.len() > super::fs_transaction::MAX_SETUP_FILE_BYTES as u64 {
        return Err("publication identity is not a bounded regular file".into());
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(super::fs_transaction::MAX_SETUP_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read publication identity: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("reinspect publication identity: {error}"))?;
    if FileGeneration::from_metadata(&before) != FileGeneration::from_metadata(&after)
        || bytes.len() as u64 != after.len()
    {
        return Err("publication identity changed while it was inspected".into());
    }
    let state = StableFileState {
        identity: FileIdentity::from_metadata(&after),
        size: after.len(),
        mode: after.mode() & 0o7777,
        owner: after.uid(),
        links: after.nlink(),
        digest: Sha256::digest(&bytes).into(),
    };
    Ok((file, state))
}

fn stable_state_at(parent: &fs::File, name: &CStr) -> Result<Option<StableFileState>, String> {
    open_stable_file_at(parent, name).map(|opened| opened.map(|(_, state)| state))
}

fn stable_state_from_snapshot(snapshot: &PlatformSnapshot) -> Option<StableFileState> {
    let SnapshotGeneration::Present(generation) = &snapshot.generation else {
        return None;
    };
    let bytes = snapshot.bytes.as_ref()?;
    Some(StableFileState {
        identity: FileIdentity {
            device: generation.device,
            inode: generation.inode,
        },
        size: bytes.len() as u64,
        mode: snapshot.mode.unwrap_or(0) & 0o7777,
        owner: generation.owner,
        links: generation.links,
        digest: Sha256::digest(bytes).into(),
    })
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileGeneration {
    device: u64,
    inode: u64,
    size: u64,
    owner: u32,
    links: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn exchange_names(parent: &fs::File, left: &CStr, right: &CStr) -> Result<(), String> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            left.as_ptr(),
            parent.as_raw_fd(),
            right.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let result = unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            left.as_ptr(),
            parent.as_raw_fd(),
            right.as_ptr(),
            libc::RENAME_SWAP,
        )
    };
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    return Err("this Unix platform has no atomic pathname-exchange API".into());

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))]
    if result < 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

fn move_no_replace(parent: &fs::File, source: &CStr, destination: &CStr) -> Result<(), String> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let result = unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    return Err("this Unix platform has no atomic no-replace rename API".into());

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))]
    if result < 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

const BACKUP_MARKER: &str = ".tirith-backup-v2-";
const TOMBSTONE_MARKER: &str = ".tirith-setup-v2-";
const ARTIFACT_RETENTION_LIMIT: usize = 5;

fn hex_bytes(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn destination_tag(name: &CStr) -> String {
    let digest = Sha256::digest(name.to_bytes());
    hex_bytes(&digest[..16])
}

fn backup_binding(name: &CStr, state: &StableFileState) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"tirith-setup-backup-v2\0");
    hasher.update(name.to_bytes());
    hasher.update(state.identity.device.to_le_bytes());
    hasher.update(state.identity.inode.to_le_bytes());
    hasher.update(state.size.to_le_bytes());
    hasher.update(state.mode.to_le_bytes());
    hasher.update(state.owner.to_le_bytes());
    hasher.update(state.links.to_le_bytes());
    hasher.update(state.digest);
    hex_bytes(&hasher.finalize())
}

fn backup_name(name: &CStr, state: &StableFileState) -> CString {
    CString::new(format!(
        "{BACKUP_MARKER}{}-{}_{}_{}",
        destination_tag(name),
        chrono::Local::now().format("%Y%m%d-%H%M%S-%9f"),
        backup_binding(name, state),
        uuid::Uuid::new_v4().simple()
    ))
    .expect("generated backup name contains no NUL")
}

fn backup_name_matches(candidate: &CStr, destination: &CStr, state: &StableFileState) -> bool {
    let Ok(candidate) = candidate.to_str() else {
        return false;
    };
    let prefix = format!("{BACKUP_MARKER}{}-", destination_tag(destination));
    let Some(rest) = candidate.strip_prefix(&prefix) else {
        return false;
    };
    let mut fields = rest.split('_');
    let Some(timestamp) = fields.next() else {
        return false;
    };
    let Some(binding) = fields.next() else {
        return false;
    };
    let Some(nonce) = fields.next() else {
        return false;
    };
    fields.next().is_none()
        && timestamp.len() == 25
        && timestamp.as_bytes()[8] == b'-'
        && timestamp.as_bytes()[15] == b'-'
        && timestamp
            .bytes()
            .enumerate()
            .all(|(index, byte)| index == 8 || index == 15 || byte.is_ascii_digit())
        && binding == backup_binding(destination, state)
        && nonce.len() == 32
        && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
        && state.owner == unsafe { libc::geteuid() }
        && state.mode == 0o600
        && state.links == 1
}

fn tombstone_name(state: &StableFileState) -> CString {
    CString::new(format!(
        "{TOMBSTONE_MARKER}{:x}-{:x}-{}.tmp",
        state.identity.device,
        state.identity.inode,
        uuid::Uuid::new_v4().simple()
    ))
    .expect("generated tombstone name contains no NUL")
}

fn tombstone_name_matches(candidate: &CStr, state: &StableFileState) -> bool {
    let Ok(candidate) = candidate.to_str() else {
        return false;
    };
    let Some(rest) = candidate
        .strip_prefix(TOMBSTONE_MARKER)
        .and_then(|value| value.strip_suffix(".tmp"))
    else {
        return false;
    };
    let mut fields = rest.split('-');
    let parsed_device = fields
        .next()
        .and_then(|value| u64::from_str_radix(value, 16).ok());
    let parsed_inode = fields
        .next()
        .and_then(|value| u64::from_str_radix(value, 16).ok());
    let nonce = fields.next();
    let empty_digest: [u8; 32] = Sha256::digest([]).into();
    fields.next().is_none()
        && parsed_device == Some(state.identity.device)
        && parsed_inode == Some(state.identity.inode)
        && nonce.is_some_and(|value| {
            value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        && state.size == 0
        && state.mode == 0o600
        && state.owner == unsafe { libc::geteuid() }
        && state.links == 1
        && state.digest == empty_digest
}

#[cfg(target_os = "linux")]
fn errno_slot() -> Option<*mut libc::c_int> {
    Some(unsafe { libc::__errno_location() })
}

#[cfg(target_os = "android")]
fn errno_slot() -> Option<*mut libc::c_int> {
    Some(unsafe { libc::__errno() })
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn errno_slot() -> Option<*mut libc::c_int> {
    Some(unsafe { libc::__error() })
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
fn errno_slot() -> Option<*mut libc::c_int> {
    None
}

fn directory_names(directory: &fs::File) -> Result<Vec<CString>, String> {
    directory_names_bounded(directory, usize::MAX).map(|(names, _)| names)
}

fn directory_names_bounded(
    directory: &fs::File,
    limit: usize,
) -> Result<(Vec<CString>, bool), String> {
    let dot = c".";
    // `dup` would share the directory-stream offset with the long-lived
    // capability. Re-open `.` relative to that capability so every scan gets
    // an independent file description without re-resolving an external path.
    let duplicate = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if duplicate < 0 {
        return Err(format!(
            "duplicate transaction directory for enumeration: {}",
            std::io::Error::last_os_error()
        ));
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(duplicate);
        }
        return Err(format!("enumerate transaction directory: {error}"));
    }
    let mut names = Vec::new();
    loop {
        // POSIX distinguishes end-of-directory from an enumeration failure by
        // errno. Clear it immediately before `readdir` so a partial scan can
        // never be mistaken for a complete retention inventory.
        let errno = errno_slot();
        if let Some(errno) = errno {
            unsafe {
                *errno = 0;
            }
        }
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let readdir_errno = errno.map(|errno| unsafe { *errno }).unwrap_or_default();
            if unsafe { libc::closedir(stream) } < 0 {
                return Err(format!(
                    "close transaction-directory enumeration: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if readdir_errno != 0 {
                return Err(format!(
                    "enumerate transaction directory: {}",
                    std::io::Error::from_raw_os_error(readdir_errno)
                ));
            }
            return Ok((names, false));
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            if names.len() == limit {
                if unsafe { libc::closedir(stream) } < 0 {
                    return Err("cannot close bounded private directory inventory".into());
                }
                return Ok((names, true));
            }
            names.push(name.to_owned());
        }
    }
}

pub(crate) fn private_directory_names(
    directory: &Path,
    scope: &Path,
    limit: usize,
) -> Result<(Vec<OsString>, bool), String> {
    let Some(parent) = scoped_parent(&directory.join(".inventory"), scope, false)? else {
        return Ok((Vec::new(), false));
    };
    let metadata = parent
        .dir
        .metadata()
        .map_err(|_| "cannot inspect private journal directory")?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err("journal inventory requires a private current-user-owned directory".into());
    }
    let (names, limited) = directory_names_bounded(&parent.dir, limit)?;
    Ok((
        names
            .into_iter()
            .map(|name| OsStr::from_bytes(name.to_bytes()).to_owned())
            .collect(),
        limited,
    ))
}

fn normalize_tombstone_name(
    parent: &fs::File,
    current_name: &mut CString,
    file: &fs::File,
) -> Result<(), String> {
    let (_, state) = stable_state_from_open_file(
        file.try_clone()
            .map_err(|error| format!("clone scrubbed artifact handle: {error}"))?,
    )?;
    if tombstone_name_matches(current_name, &state) {
        return Ok(());
    }
    if state.size != 0 || state.mode != 0o600 || state.links != 1 {
        return Err("scrubbed artifact is not a reusable single-link tombstone".into());
    }
    if stable_state_at(parent, current_name)?.as_ref() != Some(&state) {
        return Err("scrubbed artifact pathname changed before tombstone normalization".into());
    }
    let normalized = tombstone_name(&state);
    move_no_replace(parent, current_name, &normalized)
        .map_err(|error| format!("normalize scrubbed artifact name: {error}"))?;
    if stable_state_at(parent, &normalized)?.as_ref() != Some(&state)
        || stable_state_at(parent, current_name)?.is_some()
    {
        let _ = move_no_replace(parent, &normalized, current_name);
        return Err("could not prove normalized tombstone identity".into());
    }
    parent
        .sync_all()
        .map_err(|error| format!("sync normalized tombstone name: {error}"))?;
    *current_name = normalized;
    Ok(())
}

impl FileGeneration {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            owner: metadata.uid(),
            links: metadata.nlink(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SnapshotGeneration {
    Absent,
    Present(FileGeneration),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlatformSnapshot {
    pub(crate) bytes: Option<Vec<u8>>,
    pub(crate) mode: Option<u32>,
    generation: SnapshotGeneration,
}

impl PlatformSnapshot {
    /// Validate privacy from the same retained-handle generation as the bytes.
    /// An absent destination is safe for a new private publication.
    pub(crate) fn require_private(&self) -> Result<(), String> {
        if let SnapshotGeneration::Present(generation) = &self.generation {
            if generation.owner != unsafe { libc::geteuid() }
                || generation.links != 1
                || self.mode.is_none_or(|mode| mode & 0o077 != 0)
            {
                return Err("private file must be current-user-owned, single-link and inaccessible to other users".into());
            }
        }
        Ok(())
    }

    fn absent() -> Self {
        Self {
            bytes: None,
            mode: None,
            generation: SnapshotGeneration::Absent,
        }
    }
}

fn snapshot_from_parent(
    parent: &ScopedParent,
    display_path: &Path,
) -> Result<PlatformSnapshot, String> {
    snapshot_from_parent_capped(
        parent,
        display_path,
        super::fs_transaction::MAX_SETUP_FILE_BYTES,
    )
}

fn snapshot_from_parent_capped(
    parent: &ScopedParent,
    display_path: &Path,
    limit: usize,
) -> Result<PlatformSnapshot, String> {
    // A non-cooperating writer may mutate while we read. Retry a bounded
    // number of times until the same handle has stable generation metadata
    // before and after the exact, capped read.
    for _ in 0..3 {
        let fd = unsafe {
            libc::openat(
                parent.dir.as_raw_fd(),
                parent.name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(PlatformSnapshot::absent());
            }
            if error.raw_os_error() == Some(libc::ELOOP) {
                return Err(format!(
                    "{} is a symlink — refusing to modify for safety",
                    display_path.display()
                ));
            }
            return Err(format!(
                "open {} without following links: {error}",
                display_path.display()
            ));
        }

        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        let before = file.metadata().map_err(|error| {
            format!(
                "stat {} through open handle: {error}",
                display_path.display()
            )
        })?;
        if !before.is_file() {
            return Err(format!(
                "{} is not a regular file — refusing for safety",
                display_path.display()
            ));
        }
        if before.nlink() != 1 {
            return Err(format!(
                "{} has {} hard links; refusing to replace a shared inode for safety",
                display_path.display(),
                before.nlink()
            ));
        }
        if before.len() > limit as u64 {
            return Err(format!(
                "{} exceeds setup file limit of {} bytes",
                display_path.display(),
                limit
            ));
        }

        let mut bytes = Vec::with_capacity(before.len() as usize);
        (&mut file)
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                format!(
                    "read {} through open handle: {error}",
                    display_path.display()
                )
            })?;
        if bytes.len() > limit {
            return Err(format!(
                "{} exceeds setup file limit of {} bytes",
                display_path.display(),
                limit
            ));
        }
        let after = file.metadata().map_err(|error| {
            format!(
                "restat {} through open handle: {error}",
                display_path.display()
            )
        })?;
        let before_generation = FileGeneration::from_metadata(&before);
        let after_generation = FileGeneration::from_metadata(&after);
        if before_generation == after_generation && bytes.len() as u64 == after.len() {
            return Ok(PlatformSnapshot {
                bytes: Some(bytes),
                mode: Some(after.mode() & 0o7777),
                generation: SnapshotGeneration::Present(after_generation),
            });
        }
    }

    Err(format!(
        "{} changed repeatedly while being read; retry setup",
        display_path.display()
    ))
}

pub(crate) fn read_snapshot_scoped(
    path: &Path,
    scope_root: &Path,
) -> Result<PlatformSnapshot, String> {
    let Some(parent) = scoped_parent(path, scope_root, false)? else {
        return Ok(PlatformSnapshot::absent());
    };
    snapshot_from_parent(&parent, path)
}

/// Read through the retained native boundary with a caller-selected smaller cap.
/// No parents are created. The normal snapshot still carries privacy and generation proof.
pub(crate) fn read_snapshot_scoped_capped(
    path: &Path,
    scope_root: &Path,
    limit: usize,
) -> Result<PlatformSnapshot, String> {
    let Some(parent) = scoped_parent(path, scope_root, false)? else {
        return Ok(PlatformSnapshot::absent());
    };
    snapshot_from_parent_capped(
        &parent,
        path,
        limit.min(super::fs_transaction::MAX_SETUP_FILE_BYTES),
    )
}

/// Read a setup-managed text file through the same root-confined, no-follow
/// boundary used for writes. Missing files or parents return `None` without
/// creating directories; unsafe components are errors even for dry runs and
/// idempotent early returns.
pub fn read_to_string_scoped(path: &Path, scope_root: &Path) -> Result<Option<String>, String> {
    read_snapshot_scoped(path, scope_root)?
        .bytes
        .map(|bytes| {
            String::from_utf8(bytes)
                .map_err(|error| format!("{} is not valid UTF-8: {error}", path.display()))
        })
        .transpose()
}

/// Create a private journal directory using the same no-follow parent walk as
/// setup files. Permissions are changed through the held directory descriptor.
pub(crate) fn ensure_private_directory(path: &Path, scope_root: &Path) -> Result<(), String> {
    let parent = scoped_parent(&path.join(".journal-entry"), scope_root, true)?
        .ok_or("cannot create private journal directory")?;
    let metadata = parent.dir.metadata().map_err(|e| e.to_string())?;
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err("private journal directory is not owned by the current operator".into());
    }
    if unsafe { libc::fchmod(parent.dir.as_raw_fd(), 0o700) } != 0 {
        return Err(format!(
            "make journal directory private: {}",
            std::io::Error::last_os_error()
        ));
    }
    parent
        .dir
        .sync_all()
        .map_err(|e| format!("sync private journal directory: {e}"))
}

/// Write `content` to `path` atomically via temp+rename.
///
/// Uses `O_EXCL` (`create_new`) to prevent clobbering stale temp files.
/// Retries up to 3 times on collision. If `path` already exists as a
/// regular file, its permissions are preserved; otherwise `mode` is used.
/// Refuses to overwrite a symlink target.
#[cfg(test)]
pub fn atomic_write(
    path: &Path,
    scope_root: &Path,
    content: &str,
    mode: u32,
) -> Result<(), String> {
    transactional_update(path, scope_root, false, |_| {
        Ok(FileUpdate::write_text(content.to_string(), mode))
    })?;
    Ok(())
}

fn open_lock_anchor(_scope_root: &Path) -> Result<fs::File, String> {
    // The scope root may be created by the first writer. Locking the nearest
    // existing ancestor is therefore unstable: a contender that starts after
    // that mkdir can select the new root while the first writer still locks
    // its former ancestor. The filesystem root is an immutable identity for
    // every absolute setup path, so first-run and steady-state writers always
    // rendezvous on the same kernel lock without creating a lock artifact.
    open_dir(Path::new("/"))
}

pub(crate) struct PlatformLock {
    _anchor: fs::File,
}

/// Per-operation execution lock, separate from the writer lock. It prevents an
/// apply/undo pair or two workers from interleaving one durable operation.
pub(crate) fn try_lock_operation(
    path: &Path,
    scope: &Path,
) -> Result<Option<PlatformLock>, String> {
    let parent =
        scoped_parent(path, scope, false)?.ok_or("operation journal directory is missing")?;
    let fd = unsafe {
        libc::openat(
            parent.dir.as_raw_fd(),
            parent.name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(format!(
            "open private operation lock: {}",
            std::io::Error::last_os_error()
        ));
    }
    let file = unsafe { fs::File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err("operation lock ownership or file identity is unsafe".into());
    }
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(PlatformLock { _anchor: file })),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(format!("lock operation: {error}")),
    }
}

pub(crate) struct PlatformTransaction {
    parent: ScopedParent,
    path: PathBuf,
    _lock: PlatformLock,
    cleanup_failures: CleanupFailures,
}

impl PlatformTransaction {
    pub(crate) fn lock(_path: &Path, scope_root: &Path) -> Result<PlatformLock, String> {
        Self::lock_for(_path, scope_root, super::fs_transaction::SETUP_LOCK_TIMEOUT)
    }

    pub(crate) fn lock_for(
        _path: &Path,
        scope_root: &Path,
        timeout: std::time::Duration,
    ) -> Result<PlatformLock, String> {
        let anchor = open_lock_anchor(scope_root)?;
        super::fs_transaction::wait_for_lock(timeout, || match anchor.try_lock_exclusive() {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(format!(
                "lock setup scope without creating a lock file: {error}"
            )),
        })?;
        Ok(PlatformLock { _anchor: anchor })
    }

    pub(crate) fn begin(
        path: &Path,
        scope_root: &Path,
        lock: PlatformLock,
    ) -> Result<Self, String> {
        let parent = scoped_parent(path, scope_root, true)?
            .ok_or_else(|| format!("cannot create parent for {}", path.display()))?;
        Ok(Self {
            parent,
            path: path.to_path_buf(),
            _lock: lock,
            cleanup_failures: Rc::new(RefCell::new(Vec::new())),
        })
    }

    #[cfg(test)]
    fn lock_is_contended(_path: &Path, scope_root: &Path) -> Result<bool, String> {
        let file = open_lock_anchor(scope_root)?;
        match file.try_lock_exclusive() {
            Ok(()) => {
                let _ = fs2::FileExt::unlock(&file);
                Ok(false)
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(true),
            Err(error) => Err(format!("probe setup destination lock: {error}")),
        }
    }

    pub(crate) fn read_snapshot(&self) -> Result<PlatformSnapshot, String> {
        snapshot_from_parent(&self.parent, &self.path)
    }

    pub(crate) fn take_cleanup_failures(&self) -> Vec<String> {
        std::mem::take(&mut *self.cleanup_failures.borrow_mut())
    }

    pub(crate) fn validate_snapshot(&self, expected: &PlatformSnapshot) -> Result<(), String> {
        let limit = expected.bytes.as_ref().map_or(0, Vec::len);
        let live = snapshot_from_parent_capped(&self.parent, &self.path, limit)?;
        if &live != expected {
            return Err(format!(
                "{} changed while setup was preparing the update; no changes were published",
                self.path.display()
            ));
        }
        Ok(())
    }

    fn create_empty_artifact(&self) -> Result<(CString, fs::File), String> {
        let provisional = CString::new(format!(
            ".tirith-setup-new-{}.tmp",
            uuid::Uuid::new_v4().simple()
        ))
        .expect("UUID provisional temp name contains no NUL");
        let fd = unsafe {
            libc::openat(
                self.parent.dir.as_raw_fd(),
                provisional.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(format!(
                "create exclusive temporary artifact below destination: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut file = unsafe { fs::File::from_raw_fd(fd) };
        let captured = file
            .try_clone()
            .map_err(|error| format!("clone provisional temp handle: {error}"))
            .and_then(stable_state_from_open_file);
        let (_, state) = match captured {
            Ok(captured) => captured,
            Err(error) => {
                let cleanup = scrub_guard_file(&mut file, "unvalidated temporary artifact")
                    .err()
                    .map(|cleanup| format!("; cleanup also failed: {cleanup}"))
                    .unwrap_or_default();
                return Err(format!(
                    "validate newly-created temporary artifact: {error}{cleanup}"
                ));
            }
        };
        let name = tombstone_name(&state);
        let establish = (|| {
            move_no_replace(&self.parent.dir, &provisional, &name)
                .map_err(|error| format!("establish provenance-bound temp name: {error}"))?;
            if stable_state_at(&self.parent.dir, &name)?.as_ref() != Some(&state)
                || stable_state_at(&self.parent.dir, &provisional)?.is_some()
            {
                return Err("could not prove newly-created temp provenance identity".into());
            }
            self.parent
                .dir
                .sync_all()
                .map_err(|error| format!("sync provenance-bound temp name: {error}"))
        })();
        if let Err(error) = establish {
            let cleanup = scrub_guard_file(&mut file, "uncommitted temporary artifact")
                .err()
                .map(|cleanup| format!("; cleanup also failed: {cleanup}"))
                .unwrap_or_default();
            return Err(format!("{error}{cleanup}"));
        }
        Ok((name, file))
    }

    /// Acquire one empty, provenance-bound artifact. Backups are created from
    /// this same bounded pool instead of allocating an independent file on
    /// every write. Backup and temp guards consume distinct slots, so an abort
    /// returns those same slots without growing the pool. After a durable
    /// publication, retention rotates an old exact backup into the slot that
    /// the committed backup consumed.
    fn acquire_empty_artifact(&self) -> Result<(CString, fs::File), String> {
        let mut tombstones = Vec::new();
        for name in directory_names(&self.parent.dir)? {
            if !name.to_bytes().starts_with(TOMBSTONE_MARKER.as_bytes()) {
                continue;
            }
            let Ok(Some((file, state))) =
                open_stable_file_at_with_access(&self.parent.dir, &name, libc::O_RDWR)
            else {
                // A prefix alone is not provenance and never grants reuse or
                // cleanup authority.
                continue;
            };
            if tombstone_name_matches(&name, &state) {
                tombstones.push((name, file));
            }
        }
        if tombstones.len() > ARTIFACT_RETENTION_LIMIT {
            return Err(format!(
                "provenance-bound setup tombstone limit ({ARTIFACT_RETENTION_LIMIT}) exceeded; refusing to continue until stale artifacts are reviewed"
            ));
        }
        if let Some(reusable) = tombstones.pop() {
            return Ok(reusable);
        }
        self.create_empty_artifact()
    }

    fn acquire_temp_artifact(&self) -> Result<(CString, fs::File), String> {
        self.acquire_empty_artifact()
    }

    pub(crate) fn prepare_temp<'a>(
        &'a self,
        bytes: &[u8],
        requested_mode: u32,
        preserve_existing_mode: bool,
        snapshot: &PlatformSnapshot,
        _keep_backup: Option<&BackupGuard>,
    ) -> Result<TempGuard<'a>, String> {
        let effective_mode = if preserve_existing_mode {
            snapshot.mode.unwrap_or(requested_mode)
        } else {
            requested_mode
        } & 0o7777;
        let (name, file) = self.acquire_temp_artifact()?;
        let mut guard = TempGuard {
            parent: &self.parent.dir,
            name,
            file: Some(file),
            state: None,
            armed: true,
            cleanup_failures: Rc::clone(&self.cleanup_failures),
        };
        let file = guard.file.as_mut().expect("new temp owns file");
        file.set_len(0)
            .map_err(|error| format!("reset reusable temporary file: {error}"))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| format!("rewind reusable temporary file: {error}"))?;
        file.write_all(bytes)
            .map_err(|error| format!("write temporary file: {error}"))?;
        if unsafe { libc::fchmod(file.as_raw_fd(), effective_mode as libc::mode_t) } < 0 {
            return Err(format!(
                "set temporary-file permissions: {}",
                std::io::Error::last_os_error()
            ));
        }
        file.sync_all()
            .map_err(|error| format!("sync temporary file before publication: {error}"))?;
        let synced_metadata = file
            .metadata()
            .map_err(|error| format!("inspect synced temporary file: {error}"))?;
        guard.state = Some(StableFileState {
            identity: FileIdentity::from_metadata(&synced_metadata),
            size: synced_metadata.len(),
            mode: synced_metadata.mode() & 0o7777,
            owner: synced_metadata.uid(),
            links: synced_metadata.nlink(),
            digest: Sha256::digest(bytes).into(),
        });
        Ok(guard)
    }

    pub(crate) fn publish(
        &self,
        mut temp: TempGuard<'_>,
        expected: &PlatformSnapshot,
        #[cfg(test)] test_hook: &mut impl FnMut(super::fs_transaction::TestStage) -> Result<(), String>,
    ) -> Result<PublicationGuard<'_>, String> {
        let expected_exists = expected.bytes.is_some();
        let private_path = self
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(OsStr::from_bytes(temp.name.to_bytes()));
        temp.validate_name()?;
        self.validate_snapshot(expected)?;
        let expected_state = stable_state_from_snapshot(expected);
        let held_original = if let Some(expected_state) = expected_state.as_ref() {
            Some(
                match open_stable_file_at_with_access(
                    &self.parent.dir,
                    &self.parent.name,
                    libc::O_RDWR,
                ) {
                    Ok(Some(held)) if &held.1 == expected_state => held,
                    Ok(Some(_)) => {
                        return Err(format!(
                            "{} changed before its recovery identity could be held",
                            self.path.display()
                        ))
                    }
                    Ok(None) => {
                        return Err(format!(
                            "{} disappeared before its recovery identity could be held",
                            self.path.display()
                        ))
                    }
                    Err(write_error) => {
                        // A read-only original can still be retained exactly; it
                        // simply cannot be scrubbed after the durability gate.
                        match open_stable_file_at(&self.parent.dir, &self.parent.name) {
                        Ok(Some(held)) if &held.1 == expected_state => held,
                        observed => {
                            return Err(format!(
                                "hold exact original {} for recovery ({write_error}); read-only fallback was {observed:?}",
                                self.path.display()
                            ))
                        }
                    }
                    }
                },
            )
        } else {
            None
        };
        #[cfg(test)]
        test_hook(super::fs_transaction::TestStage::PublicationReady)?;

        if expected_exists {
            let expected_state = expected_state.expect("existing snapshot has a stable state");
            let held_original = held_original.expect("existing snapshot has a held original");

            // An atomic exchange retains both pathname operands. That lets us
            // prove *after the syscall* that the installed inode is our exact
            // flushed temp and the displaced inode is the exact generation we
            // transformed. A pathname-only rename cannot provide this CAS
            // property because either name can be swapped after validation.
            exchange_names(&self.parent.dir, &temp.name, &self.parent.name).map_err(|error| {
                format!(
                    "publish {} by identity exchange: {error}",
                    self.path.display()
                )
            })?;
            let recovery = RecoveryIdentity {
                parent: &self.parent.dir,
                name: temp.name.clone(),
                display_path: private_path.clone(),
                file: held_original.0,
                state: expected_state.clone(),
            };

            let installed = match stable_state_at(&self.parent.dir, &self.parent.name) {
                Ok(state) => state,
                Err(error) => {
                    temp.armed = false;
                    return Ok(PublicationGuard::uncertain(
                        format!(
                            "published {} but could not verify the installed identity ({error}); retained the private entry at {} for manual recovery",
                            self.path.display(),
                            private_path.display()
                        ),
                        Some(recovery),
                    ));
                }
            };
            let displaced = match stable_state_at(&self.parent.dir, &temp.name) {
                Ok(state) => state,
                Err(error) => {
                    temp.armed = false;
                    return Ok(PublicationGuard::uncertain(
                        format!(
                            "published {} but could not verify its displaced identity at {} ({error}); retained both names for manual recovery",
                            self.path.display(),
                            private_path.display()
                        ),
                        Some(recovery),
                    ));
                }
            };
            let installed_matches = installed.as_ref() == temp.state.as_ref();
            let displaced_matches = displaced.as_ref() == Some(&expected_state);

            if !installed_matches || !displaced_matches {
                let rollback_safe = matches!(
                    (
                        stable_state_at(&self.parent.dir, &self.parent.name),
                        stable_state_at(&self.parent.dir, &temp.name),
                    ),
                    (Ok(live_installed), Ok(live_displaced))
                        if live_installed == installed && live_displaced == displaced
                );
                if rollback_safe
                    && exchange_names(&self.parent.dir, &temp.name, &self.parent.name).is_ok()
                {
                    let restored = stable_state_at(&self.parent.dir, &self.parent.name);
                    let replacement = stable_state_at(&self.parent.dir, &temp.name);
                    if restored.as_ref().is_ok_and(|state| state == &displaced)
                        && replacement.as_ref().is_ok_and(|state| state == &installed)
                    {
                        return Err(format!(
                            "{} or its prepared replacement changed at publication; restored the competing destination and published nothing",
                            self.path.display()
                        ));
                    }
                }
                temp.armed = false;
                return Ok(PublicationGuard::uncertain(
                    format!(
                        "{} or its prepared replacement changed at publication and rollback could not be proven; retained destination identity {:?} and private identity {:?} at {} for manual recovery",
                        self.path.display(),
                        installed,
                        displaced,
                        private_path.display()
                    ),
                    Some(recovery),
                ));
            }

            // Hold the exact displaced inode through the shared directory
            // fsync. Unix has no pathname-CAS unlink, so cleanup is never a
            // check-then-unlink: the durable commit retains this recovery
            // identity (or materializes it from this handle if its name moves).
            let recovery = match stable_state_at(&self.parent.dir, &temp.name) {
                Ok(Some(state)) if state == expected_state && recovery.state == state => recovery,
                observed => {
                    temp.armed = false;
                    return Ok(PublicationGuard::uncertain(
                        format!(
                            "published {} but could not retain the exact displaced identity ({observed:?}); private recovery name is {}",
                            self.path.display(),
                            private_path.display()
                        ),
                        Some(recovery),
                    ));
                }
            };
            let installed = RecoveryIdentity {
                parent: &self.parent.dir,
                name: self.parent.name.clone(),
                display_path: self.path.clone(),
                file: temp.file.take().expect("prepared temp handle remains held"),
                state: temp.state.clone().expect("prepared temp has stable state"),
            };
            temp.armed = false;
            Ok(PublicationGuard::with_recovery(recovery, installed))
        } else {
            // Move the prepared name atomically with no-replace semantics.
            // Unlike link+unlink, this leaves no duplicate name requiring an
            // unsafe check-then-path-delete cleanup.
            move_no_replace(&self.parent.dir, &temp.name, &self.parent.name).map_err(|error| {
                format!(
                    "publish {} atomically without replacement: {error}",
                    self.path.display()
                )
            })?;
            let installed = match stable_state_at(&self.parent.dir, &self.parent.name) {
                Ok(state) => state,
                Err(error) => {
                    let recovery = RecoveryIdentity {
                        parent: &self.parent.dir,
                        name: self.parent.name.clone(),
                        display_path: self.path.clone(),
                        file: temp.file.take().expect("prepared temp handle remains held"),
                        state: temp.state.clone().expect("prepared temp has stable state"),
                    };
                    temp.armed = false;
                    return Ok(PublicationGuard::uncertain(
                        format!(
                            "published new destination {} but could not verify its identity ({error}); prepared identity remains held for recovery",
                            self.path.display(),
                        ),
                        Some(recovery),
                    ));
                }
            };
            if installed.as_ref() != temp.state.as_ref() {
                // Roll back with another no-replace rename. No pathname is
                // ever deleted, even when the prepared source was swapped.
                if move_no_replace(&self.parent.dir, &self.parent.name, &temp.name).is_ok()
                    && stable_state_at(&self.parent.dir, &self.parent.name)
                        .as_ref()
                        .is_ok_and(Option::is_none)
                    && stable_state_at(&self.parent.dir, &temp.name)
                        .as_ref()
                        .is_ok_and(|state| state == &installed)
                {
                    return Err(format!(
                        "prepared replacement for {} changed at publication; restored the moved identity and published nothing",
                        self.path.display()
                    ));
                }
                let recovery = RecoveryIdentity {
                    parent: &self.parent.dir,
                    name: self.parent.name.clone(),
                    display_path: self.path.clone(),
                    file: temp.file.take().expect("prepared temp handle remains held"),
                    state: temp.state.clone().expect("prepared temp has stable state"),
                };
                temp.armed = false;
                return Ok(PublicationGuard::uncertain(
                    format!(
                        "prepared replacement for {} changed during publication; rollback could not be proven (destination {:?}); retained both names for manual recovery",
                        self.path.display(),
                        stable_state_at(&self.parent.dir, &self.parent.name)
                    ),
                    Some(recovery),
                ));
            }
            let installed = RecoveryIdentity {
                parent: &self.parent.dir,
                name: self.parent.name.clone(),
                display_path: self.path.clone(),
                file: temp.file.take().expect("prepared temp handle remains held"),
                state: temp.state.clone().expect("prepared temp has stable state"),
            };
            temp.armed = false;
            Ok(PublicationGuard::clean(installed))
        }
    }

    pub(crate) fn sync_parent(&self) -> Result<(), String> {
        self.parent
            .dir
            .sync_all()
            .map_err(|error| format!("sync destination directory after publication: {error}"))
    }

    pub(crate) fn create_backup(&self, snapshot: &PlatformSnapshot) -> Result<BackupGuard, String> {
        let bytes = snapshot
            .bytes
            .as_deref()
            .ok_or_else(|| "cannot back up an absent destination".to_string())?;
        let intended_state = StableFileState {
            identity: FileIdentity {
                device: 0,
                inode: 0,
            },
            size: bytes.len() as u64,
            // Backups may contain credentials even when the source file was
            // accidentally broad. Never carry source write/read exposure into
            // the recovery artifact.
            mode: 0o600,
            owner: unsafe { libc::geteuid() },
            links: 1,
            digest: Sha256::digest(bytes).into(),
        };
        // Consume one provenance-bound tombstone (or create one bounded empty
        // artifact) for the new backup. A committed update retires one old
        // exact backup after durable publication, restoring this pool slot.
        // An aborted update scrubs this guard back into the same slot.
        let (artifact_name, created_file) = self.acquire_empty_artifact()?;
        let parent = match self.parent.dir.try_clone() {
            Ok(parent) => parent,
            Err(error) => {
                let mut created_file = created_file;
                let cleanup = scrub_guard_file(&mut created_file, "unowned transaction backup")
                    .err()
                    .map(|cleanup| format!("; cleanup also failed: {cleanup}"))
                    .unwrap_or_default();
                return Err(format!("retain backup parent capability: {error}{cleanup}"));
            }
        };
        let artifact_path = self
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(OsStr::from_bytes(artifact_name.to_bytes()));
        let mut guard = BackupGuard {
            display_path: artifact_path,
            parent,
            name: artifact_name,
            file: Some(created_file),
            state: None,
            armed: true,
            cleanup_failures: Rc::clone(&self.cleanup_failures),
        };
        let file = guard.file.as_mut().expect("new backup owns file");
        file.write_all(bytes)
            .map_err(|error| format!("write backup from locked snapshot: {error}"))?;
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } < 0 {
            return Err(format!(
                "set backup permissions: {}",
                std::io::Error::last_os_error()
            ));
        }
        file.sync_all()
            .map_err(|error| format!("sync backup before update: {error}"))?;
        self.parent
            .dir
            .sync_all()
            .map_err(|error| format!("sync backup directory: {error}"))?;
        let (_, state) = stable_state_from_open_file(
            file.try_clone()
                .map_err(|error| format!("clone backup validation handle: {error}"))?,
        )?;
        let name = backup_name(&self.parent.name, &state);
        let intended_digest: [u8; 32] = Sha256::digest(bytes).into();
        if state.size != bytes.len() as u64
            || state.digest != intended_digest
            || state.mode != intended_state.mode
            || state.links != 1
            || state.owner != unsafe { libc::geteuid() }
        {
            return Err("new backup did not retain its exact intended generation".into());
        }

        move_no_replace(&self.parent.dir, &guard.name, &name)
            .map_err(|error| format!("establish provenance-bound backup name: {error}"))?;
        guard.name = name;
        guard.display_path = self
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(OsStr::from_bytes(guard.name.to_bytes()));
        if stable_state_at(&self.parent.dir, &guard.name)?.as_ref() != Some(&state)
            || !backup_name_matches(&guard.name, &self.parent.name, &state)
        {
            return Err("new backup did not retain its exact provenance-bound generation".into());
        }
        self.parent
            .dir
            .sync_all()
            .map_err(|error| format!("sync provenance-bound backup name: {error}"))?;
        guard.state = Some(state);
        Ok(guard)
    }

    pub(crate) fn cleanup_old_backups(&self, keep: Option<&BackupGuard>) -> Result<(), String> {
        inject_scrub_failure("retention inventory")?;
        let keep_name = keep.map(|guard| guard.name.as_bytes().to_vec());
        let mut backups = Vec::new();
        let mut tombstone_count = 0usize;
        for name in directory_names(&self.parent.dir)? {
            if name.to_bytes().starts_with(BACKUP_MARKER.as_bytes()) {
                let Ok(Some((file, state))) =
                    open_stable_file_at_with_access(&self.parent.dir, &name, libc::O_RDWR)
                else {
                    continue;
                };
                if backup_name_matches(&name, &self.parent.name, &state) {
                    backups.push((name, file, state));
                }
            } else if name.to_bytes().starts_with(TOMBSTONE_MARKER.as_bytes()) {
                let Ok(Some((_, state))) = open_stable_file_at(&self.parent.dir, &name) else {
                    continue;
                };
                if tombstone_name_matches(&name, &state) {
                    tombstone_count += 1;
                }
            }
        }
        if tombstone_count > ARTIFACT_RETENTION_LIMIT {
            return Err(format!(
                "{tombstone_count} exact temp tombstones remain (limit {ARTIFACT_RETENTION_LIMIT})"
            ));
        }

        backups.sort_by(|left, right| left.0.to_bytes().cmp(right.0.to_bytes()));
        let remove_count = backups.len().saturating_sub(ARTIFACT_RETENTION_LIMIT);
        let retirement_capacity = ARTIFACT_RETENTION_LIMIT - tombstone_count;
        let retirement_goal = remove_count.min(retirement_capacity);
        let mut removed = 0usize;
        for (mut name, mut file, state) in backups {
            if removed == retirement_goal {
                break;
            }
            if keep_name.as_deref() == Some(name.to_bytes()) {
                continue;
            }
            #[cfg(test)]
            BACKUP_RETIREMENT_TEST_HOOK.with(|slot| {
                if let Some(hook) = slot.borrow_mut().as_mut() {
                    let path = self
                        .path
                        .parent()
                        .unwrap_or_else(|| Path::new("."))
                        .join(OsStr::from_bytes(name.to_bytes()));
                    hook(&path);
                }
            });
            if stable_state_at(&self.parent.dir, &name)?.as_ref() != Some(&state) {
                return Err(format!(
                    "provenance-bound backup {} changed before retirement",
                    name.to_string_lossy()
                ));
            }
            let retired_name = tombstone_name(&state);
            move_no_replace(&self.parent.dir, &name, &retired_name).map_err(|error| {
                format!(
                    "retire provenance-bound backup {}: {error}",
                    name.to_string_lossy()
                )
            })?;
            if stable_state_at(&self.parent.dir, &retired_name)?.as_ref() != Some(&state)
                || stable_state_at(&self.parent.dir, &name)?.is_some()
            {
                let _ = move_no_replace(&self.parent.dir, &retired_name, &name);
                return Err(format!(
                    "could not prove identity while retiring backup {}",
                    name.to_string_lossy()
                ));
            }
            name = retired_name;
            scrub_guard_file(&mut file, "retired transaction backup")?;
            normalize_tombstone_name(&self.parent.dir, &mut name, &file)?;
            self.parent
                .dir
                .sync_all()
                .map_err(|error| format!("sync retired backup tombstone: {error}"))?;
            removed += 1;
        }
        if removed != remove_count {
            return Err(format!(
                "could retire only {removed} of {remove_count} provenance-bound backups without exceeding the tombstone limit"
            ));
        }
        Ok(())
    }
}

struct RecoveryIdentity<'a> {
    parent: &'a fs::File,
    name: CString,
    display_path: PathBuf,
    file: fs::File,
    state: StableFileState,
}

impl RecoveryIdentity<'_> {
    fn scrub_exact(&mut self) -> Result<(), String> {
        inject_scrub_failure("displaced identity")?;
        let (_, current) = stable_state_from_open_file(
            self.file
                .try_clone()
                .map_err(|error| format!("clone exact displaced identity: {error}"))?,
        )?;
        if current != self.state {
            return Err("exact displaced identity changed before scrub".into());
        }
        if current.links != 1 {
            return Err(format!(
                "exact displaced identity acquired {} hard links before scrub",
                current.links
            ));
        }
        if unsafe { libc::fchmod(self.file.as_raw_fd(), 0o600) } < 0 {
            return Err(format!(
                "restrict exact displaced identity before scrub: {}",
                std::io::Error::last_os_error()
            ));
        }
        self.file
            .sync_all()
            .map_err(|error| format!("sync restricted displaced identity: {error}"))?;
        self.file
            .set_len(0)
            .map_err(|error| format!("scrub exact displaced identity: {error}"))?;
        self.file
            .sync_all()
            .map_err(|error| format!("sync scrubbed displaced identity: {error}"))?;
        normalize_tombstone_name(self.parent, &mut self.name, &self.file)?;
        self.display_path = self
            .display_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(OsStr::from_bytes(self.name.to_bytes()));
        Ok(())
    }

    fn materialize_copy(&mut self) -> Result<PathBuf, String> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|error| format!("seek exact displaced recovery identity: {error}"))?;
        let mut bytes = Vec::with_capacity(self.state.size as usize);
        (&mut self.file)
            .take(super::fs_transaction::MAX_SETUP_FILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("read exact displaced recovery identity: {error}"))?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if bytes.len() as u64 != self.state.size || digest != self.state.digest {
            return Err("exact displaced recovery identity changed while held".into());
        }

        let name = CString::new(format!(
            ".tirith-recovery-{}",
            uuid::Uuid::new_v4().simple()
        ))
        .expect("UUID recovery name contains no NUL");
        let fd = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(format!(
                "create exclusive recovery copy: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut copy = unsafe { fs::File::from_raw_fd(fd) };
        let write_result = (|| {
            copy.write_all(&bytes)
                .map_err(|error| format!("write exact recovery copy: {error}"))?;
            if unsafe { libc::fchmod(copy.as_raw_fd(), self.state.mode as libc::mode_t) } < 0 {
                return Err(format!(
                    "set exact recovery-copy permissions: {}",
                    std::io::Error::last_os_error()
                ));
            }
            copy.sync_all()
                .map_err(|error| format!("sync exact recovery copy: {error}"))?;
            self.parent
                .sync_all()
                .map_err(|error| format!("sync exact recovery-copy directory entry: {error}"))
        })();
        if let Err(error) = write_result {
            let cleanup = scrub_guard_file(&mut copy, "partial recovery copy")
                .err()
                .map(|cleanup| format!("; cleanup also failed: {cleanup}"))
                .unwrap_or_default();
            return Err(format!("{error}{cleanup}"));
        }
        Ok(self
            .display_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(OsStr::from_bytes(name.to_bytes())))
    }

    fn ensure_recovery_path(&mut self) -> Result<PathBuf, String> {
        if stable_state_at(self.parent, &self.name)
            .as_ref()
            .is_ok_and(|state| state.as_ref() == Some(&self.state))
        {
            Ok(self.display_path.clone())
        } else {
            self.materialize_copy()
        }
    }
}

pub(crate) struct PublicationGuard<'a> {
    installed: Option<RecoveryIdentity<'a>>,
    recovery: Option<RecoveryIdentity<'a>>,
    terminal_error: Option<String>,
}

impl<'a> PublicationGuard<'a> {
    fn clean(installed: RecoveryIdentity<'a>) -> Self {
        Self {
            installed: Some(installed),
            recovery: None,
            terminal_error: None,
        }
    }

    fn with_recovery(recovery: RecoveryIdentity<'a>, installed: RecoveryIdentity<'a>) -> Self {
        Self {
            installed: Some(installed),
            recovery: Some(recovery),
            terminal_error: None,
        }
    }

    fn uncertain(message: String, recovery: Option<RecoveryIdentity<'a>>) -> Self {
        Self {
            installed: None,
            recovery,
            terminal_error: Some(message),
        }
    }

    pub(crate) fn retain_for_recovery(&mut self) -> String {
        let installed = self.installed.as_mut().map(|identity| {
            identity
                .ensure_recovery_path()
                .map(|path| format!("retained exact installed identity at {}", path.display()))
                .unwrap_or_else(|error| {
                    format!("could not materialize installed recovery: {error}")
                })
        });
        let exact = self.recovery.as_mut().map(|recovery| {
            recovery
                .ensure_recovery_path()
                .map(|path| format!("retained exact displaced recovery at {}", path.display()))
                .unwrap_or_else(|error| {
                    format!("could not materialize displaced recovery: {error}")
                })
        });
        match (&self.terminal_error, exact, installed) {
            (Some(error), Some(recovery), Some(installed)) => {
                format!("{error}; {recovery}; {installed}")
            }
            (Some(error), Some(recovery), None) => format!("{error}; {recovery}"),
            (Some(error), None, Some(installed)) => format!("{error}; {installed}"),
            (Some(error), None, None) => error.clone(),
            (None, Some(recovery), Some(installed)) => format!("{recovery}; {installed}"),
            (None, Some(recovery), None) => recovery,
            (None, None, Some(installed)) => installed,
            (None, None, None) => "new destination has no recovery identity".into(),
        }
    }

    pub(crate) fn finish_after_durability(mut self) -> Result<PublicationOutcome, String> {
        if let Some(error) = self.terminal_error.take() {
            let recovery = self.recovery.as_mut().map(|identity| {
                identity
                    .ensure_recovery_path()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|copy_error| format!("unavailable ({copy_error})"))
            });
            return Err(match recovery {
                Some(path) => format!("{error}; exact recovery: {path}"),
                None => error,
            });
        }
        if let Some(installed) = self.installed.as_mut() {
            let live = stable_state_at(installed.parent, &installed.name);
            if live.as_ref().is_err()
                || live.as_ref().ok().and_then(Option::as_ref) != Some(&installed.state)
            {
                let installed_recovery = installed
                    .ensure_recovery_path()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|error| format!("unavailable ({error})"));
                let displaced_recovery = self.recovery.as_mut().map(|identity| {
                    identity
                        .ensure_recovery_path()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|error| format!("unavailable ({error})"))
                });
                return Err(match displaced_recovery {
                    Some(displaced) => format!(
                        "installed destination identity changed before transaction completion; installed recovery: {installed_recovery}; displaced recovery: {displaced}"
                    ),
                    None => format!(
                        "installed destination identity changed before transaction completion; installed recovery: {installed_recovery}"
                    ),
                });
            }
        }
        let Some(recovery) = self.recovery.as_mut() else {
            return Ok(PublicationOutcome::Clean);
        };
        if let Err(scrub_error) = recovery.scrub_exact() {
            let path = recovery.ensure_recovery_path().map_err(|recovery_error| {
                format!(
                    "durable update could not safely scrub its displaced original ({scrub_error}) and could not retain an exact recovery copy ({recovery_error})"
                )
            })?;
            return Ok(PublicationOutcome::RecoveryRetained(format!(
                "durable update retained the exact displaced original at {} because cleanup failed: {scrub_error}",
                path.display()
            )));
        }
        Ok(PublicationOutcome::Clean)
    }
}

pub(crate) struct TempGuard<'a> {
    parent: &'a fs::File,
    name: CString,
    file: Option<fs::File>,
    state: Option<StableFileState>,
    armed: bool,
    cleanup_failures: CleanupFailures,
}

impl TempGuard<'_> {
    fn validate_name(&self) -> Result<(), String> {
        let expected = self
            .state
            .as_ref()
            .expect("prepared temp has a synced state");
        let live = stable_state_at(self.parent, &self.name)?;
        if live.as_ref() != Some(expected) {
            return Err(
                "temporary setup file changed before publication; refusing for safety".into(),
            );
        }
        Ok(())
    }
}

impl Drop for TempGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Scrub only the inode represented by our held capability. If an
            // attacker swaps the pathname, their file is never selected for
            // cleanup. The zero-length tombstone is intentionally retained.
            if let Some(file) = self.file.as_mut() {
                let cleanup = scrub_guard_file(file, "temporary setup identity")
                    .and_then(|()| normalize_tombstone_name(self.parent, &mut self.name, file));
                if let Err(error) = cleanup {
                    self.cleanup_failures.borrow_mut().push(error);
                }
            }
        }
    }
}

pub(crate) struct BackupGuard {
    display_path: PathBuf,
    parent: fs::File,
    name: CString,
    file: Option<fs::File>,
    state: Option<StableFileState>,
    armed: bool,
    cleanup_failures: CleanupFailures,
}

impl BackupGuard {
    fn validate(&self) -> Result<(), String> {
        let expected = self
            .state
            .as_ref()
            .ok_or_else(|| "backup has no captured stable generation".to_string())?;
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| "backup validation handle is unavailable".to_string())?;
        let (_, held) = stable_state_from_open_file(
            file.try_clone()
                .map_err(|error| format!("clone held backup handle: {error}"))?,
        )?;
        if &held != expected {
            return Err("backup bytes or metadata changed through its held handle".into());
        }
        if stable_state_at(&self.parent, &self.name)?.as_ref() != Some(expected) {
            return Err("backup pathname no longer identifies the exact created generation".into());
        }
        Ok(())
    }

    pub(crate) fn commit(&mut self) -> Result<(), String> {
        self.validate().map_err(|error| {
            format!(
                "backup {} changed before commit/announcement: {error}",
                self.display_path.display()
            )
        })?;
        self.armed = false;
        eprintln!("tirith: backup at {}", self.path().display());
        Ok(())
    }

    pub(crate) fn retain_for_recovery(&mut self) -> Result<PathBuf, String> {
        self.validate().map_err(|error| {
            format!(
                "backup {} cannot be announced as recovery: {error}",
                self.display_path.display()
            )
        })?;
        self.armed = false;
        Ok(self.path())
    }

    fn path(&self) -> PathBuf {
        self.display_path.clone()
    }
}

impl Drop for BackupGuard {
    fn drop(&mut self) {
        if self.armed {
            // As with temporary cleanup, scrub the exact held inode rather
            // than deleting whichever object later occupies the pathname.
            if let Some(file) = self.file.as_mut() {
                let cleanup = scrub_guard_file(file, "transaction backup identity")
                    .and_then(|()| normalize_tombstone_name(&self.parent, &mut self.name, file));
                if let Err(error) = cleanup {
                    self.cleanup_failures.borrow_mut().push(error);
                }
            }
        }
    }
}

/// Write a hook script with executable permissions.
///
/// - Hard-errors if `path` is a symlink (even with `--force`).
/// - If file exists with matching content: skip (but verify 0o755 mode).
/// - If file exists with different content: error without `--force`, overwrite with `--force`.
/// - After write, always enforce mode 0o755.
/// - Dry-run: print what would happen, write nothing.
pub fn write_hook_script(
    path: &Path,
    scope_root: &Path,
    content: &str,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    #[derive(Clone, Copy)]
    enum Action {
        UpToDate,
        FixMode,
        Write,
        WouldError,
    }
    let mut action = Action::Write;
    let outcome = transactional_update(path, scope_root, dry_run, |snapshot| {
        if let Some(existing) = snapshot.text(path)? {
            if existing == content {
                if snapshot.mode().unwrap_or(0) & 0o777 == 0o755 {
                    action = Action::UpToDate;
                    return Ok(FileUpdate::unchanged());
                }
                action = Action::FixMode;
                return Ok(FileUpdate::write_text(content.to_string(), 0o755).with_exact_mode());
            }
            if !force {
                if dry_run {
                    action = Action::WouldError;
                    return Ok(FileUpdate::unchanged());
                }
                return Err(format!(
                    "{} exists but content differs — use --force to update",
                    path.display()
                ));
            }
        }
        action = Action::Write;
        Ok(FileUpdate::write_text(content.to_string(), 0o755).with_exact_mode())
    })?;

    let completion = outcome.completion_annotation();
    match (action, outcome) {
        (Action::UpToDate, _) if dry_run => eprintln!(
            "[dry-run] would skip {} (already up to date)",
            path.display()
        ),
        (Action::UpToDate, _) => {
            eprintln!("tirith: {} already configured, up to date", path.display())
        }
        (Action::FixMode, TransactionOutcome::DryRunWouldWrite) => eprintln!(
            "[dry-run] would correct {} permissions to mode 0755",
            path.display()
        ),
        (Action::FixMode, _) if completion.is_some() => eprintln!(
            "tirith: {} already configured, fixed permissions{}",
            path.display(),
            completion.unwrap_or_default()
        ),
        (Action::WouldError, _) => eprintln!(
            "[dry-run] would error: {} exists but content differs — use --force to update",
            path.display()
        ),
        (Action::Write, TransactionOutcome::DryRunWouldWrite) => eprintln!(
            "[dry-run] would write {} ({} bytes, mode 0755)",
            path.display(),
            content.len()
        ),
        (Action::Write, _) if completion.is_some() => {
            eprintln!(
                "tirith: wrote {}{}",
                path.display(),
                completion.unwrap_or_default()
            )
        }
        _ => {}
    }
    Ok(())
}

/// Validate that `dir` stays within `scope_root` after canonicalization.
///
/// Walks up from `dir` to find the nearest existing ancestor, canonicalizes
/// it, and verifies it starts with the canonical `scope_root`. Also checks
/// each existing path component for symlinks within the scope.
pub fn validate_target_dir(dir: &Path, scope_root: Option<&Path>) -> Result<(), String> {
    let root = match scope_root {
        Some(r) => r,
        None => return Ok(()),
    };

    let root_canonical = root
        .canonicalize()
        .map_err(|e| format!("canonicalize {}: {e}", root.display()))?;

    let mut check = dir.to_path_buf();
    loop {
        if check.exists() {
            let canonical = check
                .canonicalize()
                .map_err(|e| format!("canonicalize {}: {e}", check.display()))?;
            if !canonical.starts_with(&root_canonical) {
                return Err(format!(
                    "{} resolves outside project root {} — refusing for safety",
                    dir.display(),
                    root.display()
                ));
            }
            break;
        }
        if !check.pop() {
            return Err(format!(
                "cannot resolve {} — no existing ancestor found",
                dir.display()
            ));
        }
    }

    // Each existing component must not be a symlink pointing back into scope.
    let mut path_so_far = PathBuf::new();
    for component in dir.components() {
        path_so_far.push(component);
        if path_so_far.exists() {
            if let Ok(meta) = fs::symlink_metadata(&path_so_far) {
                if meta.file_type().is_symlink() && path_so_far.starts_with(&root_canonical) {
                    return Err(format!(
                        "{} is a symlink inside project scope — refusing for safety",
                        path_so_far.display()
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Retire an obsolete content-addressed Codex gateway generation after its
/// registration has been replaced successfully. The exact old inode is moved
/// to an unpredictable provenance-bound tombstone through a held parent
/// capability, scrubbed, and left available to the bounded setup temp pool.
pub fn retire_codex_gateway_generation(path: &Path, scope_root: &Path) -> Result<(), String> {
    let lock = PlatformTransaction::lock(path, scope_root)?;
    let transaction = PlatformTransaction::begin(path, scope_root, lock)?;
    let snapshot = transaction.read_snapshot()?;
    let Some(bytes) = snapshot.bytes.as_deref() else {
        return Ok(());
    };
    let digest = Sha256::digest(bytes);
    let expected_name = format!("gateway-sha256-{}.yaml", hex_bytes(&digest));
    if path.file_name() != Some(OsStr::new(&expected_name)) {
        return Err(format!(
            "{} is not named for its exact gateway content; refusing retirement",
            path.display()
        ));
    }
    transaction.validate_snapshot(&snapshot)?;
    let expected_state = stable_state_from_snapshot(&snapshot)
        .ok_or_else(|| "gateway retirement snapshot has no stable file state".to_string())?;
    if expected_state.owner != unsafe { libc::geteuid() } || expected_state.links != 1 {
        return Err(format!(
            "{} is not a single-link current-user file; refusing retirement",
            path.display()
        ));
    }
    let (mut file, state) = open_stable_file_at_with_access(
        &transaction.parent.dir,
        &transaction.parent.name,
        libc::O_RDWR,
    )?
    .ok_or_else(|| format!("{} disappeared before retirement", path.display()))?;
    if state != expected_state {
        return Err(format!("{} changed before retirement", path.display()));
    }

    let mut retired_name = tombstone_name(&state);
    move_no_replace(
        &transaction.parent.dir,
        &transaction.parent.name,
        &retired_name,
    )
    .map_err(|error| format!("retire gateway generation {}: {error}", path.display()))?;
    if stable_state_at(&transaction.parent.dir, &retired_name)?.as_ref() != Some(&state)
        || stable_state_at(&transaction.parent.dir, &transaction.parent.name)?.is_some()
    {
        let _ = move_no_replace(
            &transaction.parent.dir,
            &retired_name,
            &transaction.parent.name,
        );
        return Err(format!(
            "could not prove the exact identity retired from {}",
            path.display()
        ));
    }
    scrub_guard_file(&mut file, "retired Codex gateway generation")?;
    normalize_tombstone_name(&transaction.parent.dir, &mut retired_name, &file)?;
    transaction
        .parent
        .dir
        .sync_all()
        .map_err(|error| format!("sync retired gateway generation: {error}"))?;
    Ok(())
}

/// Run Codex with an explicitly selected project working directory. Codex's
/// global `-C` option preserves its project/user configuration semantics while the
/// supervised child itself keeps a loader-safe working directory on Windows.
pub fn run_codex_cli_in_dir(
    cwd: &Path,
    cmd: &str,
    args: &[&str],
) -> Result<std::process::Output, String> {
    let executable = tirith_core::trusted_child::resolve_ambient(cmd)
        .map_err(|error| format!("{cmd} not found or untrusted: {error}"))?;
    let scoped_args = codex_scoped_args(cwd, args);
    run_cli_bounded(
        &executable,
        &scoped_args,
        tirith_core::trusted_child::ChildLimits::new(
            std::time::Duration::from_secs(30),
            4 * 1024 * 1024,
            4 * 1024 * 1024,
        ),
    )
}

fn codex_scoped_args(cwd: &Path, args: &[&str]) -> Vec<OsString> {
    let mut scoped = Vec::with_capacity(args.len() + 2);
    scoped.push(OsString::from("-C"));
    scoped.push(cwd.as_os_str().to_os_string());
    scoped.extend(args.iter().map(|arg| OsString::from(*arg)));
    scoped
}

fn run_cli_bounded<S: AsRef<OsStr>>(
    executable: &tirith_core::trusted_child::TrustedExecutable,
    args: &[S],
    limits: tirith_core::trusted_child::ChildLimits,
) -> Result<std::process::Output, String> {
    use tirith_core::trusted_child::{ChildOutcome, ChildSpec};

    let mut spec = ChildSpec::new(args.iter().map(AsRef::as_ref), limits).inherit_env(&[
        "HOME",
        "USER",
        "LOGNAME",
        "USERPROFILE",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "APPDATA",
        "LOCALAPPDATA",
        "CODEX_HOME",
        "SystemRoot",
        "WINDIR",
    ]);
    if let Some(path) = tirith_core::trusted_child::sanitized_ambient_path() {
        spec = spec.env("PATH", path);
    }
    match tirith_core::trusted_child::run(executable, &spec) {
        ChildOutcome::Completed {
            status,
            stdout,
            stderr,
        } => Ok(std::process::Output {
            status,
            stdout,
            stderr,
        }),
        ChildOutcome::SpawnError(reason) => Err(format!("failed to start: {reason}")),
        ChildOutcome::WaitError(reason) => Err(format!("wait failed: {reason}")),
        ChildOutcome::CleanupError(reason) => Err(format!("process-tree cleanup failed: {reason}")),
        ChildOutcome::Timeout {
            cleanup_succeeded: true,
        } => Err("timed out after 30s — check installation".into()),
        ChildOutcome::Timeout {
            cleanup_succeeded: false,
        } => Err("timed out and process-tree cleanup failed — check installation".into()),
        ChildOutcome::OutputLimitExceeded {
            cleanup_succeeded: true,
            ..
        } => Err("output limit exceeded — check installation".into()),
        ChildOutcome::OutputLimitExceeded {
            cleanup_succeeded: false,
            ..
        } => Err("output limit exceeded and process-tree cleanup failed".into()),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn smaller_snapshot_cap_is_enforced_before_read_and_preserves_private_proof() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("annotation.json");
        std::fs::write(&path, b"12345").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(super::read_snapshot_scoped_capped(&path, root.path(), 4).is_err());
        let exact = super::read_snapshot_scoped_capped(&path, root.path(), 5).unwrap();
        exact.require_private().unwrap();
        assert_eq!(exact.bytes.as_deref(), Some(&b"12345"[..]));
        std::os::unix::fs::symlink(&path, root.path().join("linked")).unwrap();
        assert!(
            super::read_snapshot_scoped_capped(&root.path().join("linked"), root.path(), 5)
                .is_err()
        );
        let absent = root.path().join("missing/entry");
        assert!(super::read_snapshot_scoped_capped(&absent, root.path(), 5)
            .unwrap()
            .bytes
            .is_none());
        assert!(!absent.parent().unwrap().exists());
    }
    use super::super::fs_transaction::{transactional_update_with_hook, FileUpdate, TestStage};
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn backup_paths(root: &Path) -> Vec<PathBuf> {
        let mut paths = fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .contains("tirith-backup")
            })
            .collect::<Vec<_>>();
        paths.sort();
        paths
    }

    fn temporary_setup_paths(root: &Path) -> Vec<PathBuf> {
        fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with(".tirith-setup-") && name.ends_with(".tmp")
            })
            .map(|entry| entry.path())
            .collect()
    }

    fn nonempty(paths: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
        paths
            .into_iter()
            .filter(|path| fs::metadata(path).is_ok_and(|metadata| metadata.len() != 0))
            .collect()
    }

    fn update_with_backup(path: &Path, root: &Path, content: &str) -> Result<(), String> {
        transactional_update(path, root, false, |_| {
            Ok(FileUpdate::write_text(content.to_string(), 0o644).with_backup(true))
        })?;
        Ok(())
    }

    #[test]
    fn cli_runner_preserves_short_legitimate_output() {
        let shell =
            tirith_core::trusted_child::TrustedExecutable::from_absolute(Path::new("/bin/sh"), &[])
                .unwrap();
        let output = run_cli_bounded(
            &shell,
            &["-c", "printf setup-ok"],
            tirith_core::trusted_child::ChildLimits::new(std::time::Duration::from_secs(2), 64, 64),
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"setup-ok");
    }

    #[test]
    fn cli_runner_rejects_output_over_its_bound() {
        let shell =
            tirith_core::trusted_child::TrustedExecutable::from_absolute(Path::new("/bin/sh"), &[])
                .unwrap();
        let error = run_cli_bounded(
            &shell,
            &["-c", "printf 12345"],
            tirith_core::trusted_child::ChildLimits::new(std::time::Duration::from_secs(2), 4, 64),
        )
        .unwrap_err();
        assert!(error.contains("output limit"));
    }

    #[test]
    fn codex_scope_uses_cli_cd_without_mutating_child_cwd() {
        let args = codex_scoped_args(Path::new("/tmp/codex-scope"), &["mcp", "list", "--json"]);
        assert_eq!(
            args,
            ["-C", "/tmp/codex-scope", "mcp", "list", "--json"]
                .into_iter()
                .map(OsString::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn atomic_write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        atomic_write(&path, dir.path(), "hello", 0o644).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn atomic_write_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        fs::write(&target, "original").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = atomic_write(&link, dir.path(), "evil", 0o644);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("symlink"));
        // Original untouched
        assert_eq!(fs::read_to_string(&target).unwrap(), "original");
    }

    #[test]
    fn atomic_write_preserves_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("strict.txt");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        atomic_write(&path, dir.path(), "new", 0o644).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        // Preserved existing 0o600, not overwritten with mode arg 0o644.
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn write_hook_script_skip_on_same_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hook.sh");
        fs::write(&path, "#!/bin/bash\necho hi").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();

        write_hook_script(&path, dir.path(), "#!/bin/bash\necho hi", false, false).unwrap();
    }

    #[test]
    fn write_hook_script_errors_on_different_content_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hook.sh");
        fs::write(&path, "old content").unwrap();

        let result = write_hook_script(&path, dir.path(), "new content", false, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("content differs"));
    }

    #[test]
    fn write_hook_script_overwrites_with_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hook.sh");
        fs::write(&path, "old content").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        write_hook_script(&path, dir.path(), "new content", true, false).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "new content");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn write_hook_script_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.sh");
        fs::write(&target, "original").unwrap();
        let link = dir.path().join("link.sh");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = write_hook_script(&link, dir.path(), "evil", true, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("symlink"));
    }

    #[test]
    fn write_hook_script_rejects_hardlinked_destination_without_touching_external_link() {
        let root = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let external_path = external.path().join("shared-hook.sh");
        let setup_path = root.path().join("hook.sh");
        fs::write(&external_path, "external-original").unwrap();
        fs::set_permissions(&external_path, fs::Permissions::from_mode(0o640)).unwrap();
        fs::hard_link(&external_path, &setup_path).unwrap();

        let error =
            write_hook_script(&setup_path, root.path(), "tirith-update", true, false).unwrap_err();

        assert!(error.contains("hard links"));
        assert_eq!(
            fs::read_to_string(&external_path).unwrap(),
            "external-original"
        );
        assert_eq!(
            fs::read_to_string(&setup_path).unwrap(),
            "external-original"
        );
        assert_eq!(
            fs::metadata(&external_path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert!(temporary_setup_paths(root.path()).is_empty());
        assert!(backup_paths(root.path()).is_empty());
    }

    #[test]
    fn write_hook_script_refuses_symlinked_parent_even_when_content_matches() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("hook.sh"), "expected").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("hooks")).unwrap();

        let result = write_hook_script(
            &root.path().join("hooks/hook.sh"),
            root.path(),
            "expected",
            false,
            true,
        );

        assert!(result.is_err(), "up-to-date/dry-run must validate parents");
        assert_eq!(
            fs::read_to_string(outside.path().join("hook.sh")).unwrap(),
            "expected"
        );
    }

    #[test]
    fn atomic_write_refuses_symlinked_parent_and_leaves_outside_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let linked_parent = dir.path().join("hooks");
        std::os::unix::fs::symlink(outside.path(), &linked_parent).unwrap();

        let result = atomic_write(
            &linked_parent.join("config.json"),
            dir.path(),
            "secret",
            0o600,
        );

        assert!(result.is_err());
        assert!(!outside.path().join("config.json").exists());
    }

    #[test]
    fn transaction_parent_swap_stays_bound_to_the_retained_directory() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let parent = root.path().join("hooks");
        let retained_parent = root.path().join("hooks-held");
        fs::create_dir(&parent).unwrap();
        let path = parent.join("config.json");
        fs::write(&path, "before").unwrap();
        let outside_path = outside.path().join("config.json");
        fs::write(&outside_path, "outside-sentinel").unwrap();

        let outcome = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o600)),
            |stage| {
                if stage == TestStage::PublicationReady {
                    fs::rename(&parent, &retained_parent).unwrap();
                    std::os::unix::fs::symlink(outside.path(), &parent).unwrap();
                }
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(outcome, TransactionOutcome::Written);
        assert_eq!(
            fs::read_to_string(retained_parent.join("config.json")).unwrap(),
            "after"
        );
        assert_eq!(
            fs::read_to_string(&outside_path).unwrap(),
            "outside-sentinel"
        );
        let outside_entries = fs::read_dir(outside.path())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            outside_entries.len(),
            1,
            "no temporary or backup artifact may be created through the replacement symlink"
        );
    }

    #[test]
    fn atomic_write_rejects_destination_outside_scope() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let path = outside.path().join("config.json");

        let result = atomic_write(&path, dir.path(), "secret", 0o600);

        assert!(result.is_err());
        assert!(!path.exists());
    }

    #[test]
    fn atomic_write_creates_nested_components_without_following_links() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("one").join("two").join("config.json");

        atomic_write(&path, dir.path(), "secret", 0o600).unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "secret");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn validate_target_dir_accepts_normal_path() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("subdir");
        validate_target_dir(&target, Some(dir.path())).unwrap();
    }

    #[test]
    fn validate_target_dir_rejects_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        let evil = tempfile::tempdir().unwrap();

        // Symlink inside dir pointing outside the scope must be rejected.
        let link = dir.path().join("escape");
        std::os::unix::fs::symlink(evil.path(), &link).unwrap();

        let target = link.join("subdir");
        let result = validate_target_dir(&target, Some(dir.path()));
        assert!(result.is_err());
    }

    #[test]
    fn provenance_bound_backup_retention_keeps_exactly_five() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, "zero").unwrap();
        update_with_backup(&path, dir.path(), "one").unwrap();
        update_with_backup(&path, dir.path(), "two").unwrap();
        assert_eq!(backup_paths(dir.path()).len(), 2);
        for index in 0..6 {
            update_with_backup(&path, dir.path(), &format!("value-{index}")).unwrap();
        }
        let retained = backup_paths(dir.path());
        assert_eq!(retained.len(), 5);
        assert!(retained
            .iter()
            .any(|backup| fs::read_to_string(backup).unwrap() == "value-4"));
    }

    #[test]
    fn backup_and_temp_retention_remain_bounded_over_the_same_lifecycle() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "zero").unwrap();

        for index in 0..30 {
            update_with_backup(&path, root.path(), &format!("value-{index}")).unwrap();
        }

        assert_eq!(backup_paths(root.path()).len(), ARTIFACT_RETENTION_LIMIT);
        let tombstones = fs::read_dir(root.path())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .into_iter()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(TOMBSTONE_MARKER)
            })
            .collect::<Vec<_>>();
        assert!(tombstones.len() <= ARTIFACT_RETENTION_LIMIT);
        assert!(tombstones.iter().all(|entry| {
            let metadata = entry.metadata().unwrap();
            metadata.len() == 0
                && metadata.permissions().mode() & 0o777 == 0o600
                && metadata.nlink() == 1
        }));
        assert_eq!(fs::read_to_string(path).unwrap(), "value-29");
    }

    #[test]
    fn failed_backup_transactions_return_their_slots_without_exceeding_the_cap() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "zero").unwrap();
        for index in 0..10 {
            update_with_backup(&path, root.path(), &format!("value-{index}")).unwrap();
        }

        for index in 0..20 {
            let error = transactional_update_with_hook(
                &path,
                root.path(),
                |_| {
                    Ok(
                        FileUpdate::write_text(format!("must-not-publish-{index}"), 0o600)
                            .with_backup(true),
                    )
                },
                |stage| {
                    if stage == TestStage::TempSynced {
                        return Err("injected failure after both guards were armed".into());
                    }
                    Ok(())
                },
            )
            .unwrap_err();
            assert!(error.contains("both guards were armed"));
        }

        assert_eq!(fs::read_to_string(&path).unwrap(), "value-9");
        assert_eq!(backup_paths(root.path()).len(), ARTIFACT_RETENTION_LIMIT);
        let tombstone_count = fs::read_dir(root.path())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .into_iter()
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(TOMBSTONE_MARKER)
            })
            .count();
        assert!(tombstone_count <= ARTIFACT_RETENTION_LIMIT);
    }

    #[test]
    fn backup_retirement_never_scrubs_a_pathname_swap() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "zero").unwrap();
        for index in 0..5 {
            update_with_backup(&path, root.path(), &format!("value-{index}")).unwrap();
        }

        let moved = root.path().join("attacker-moved-exact-backup");
        let moved_for_hook = moved.clone();
        BACKUP_RETIREMENT_TEST_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |candidate| {
                fs::rename(candidate, &moved_for_hook).unwrap();
                fs::write(candidate, "attacker-pathname-replacement").unwrap();
            }));
        });
        let result = transactional_update(&path, root.path(), false, |_| {
            Ok(FileUpdate::write_text("published".into(), 0o600).with_backup(true))
        });
        BACKUP_RETIREMENT_TEST_HOOK.with(|slot| *slot.borrow_mut() = None);

        assert_eq!(result.unwrap(), TransactionOutcome::WrittenWithRecovery);
        assert_eq!(fs::read_to_string(&path).unwrap(), "published");
        assert!(backup_paths(root.path()).into_iter().any(|candidate| {
            fs::read_to_string(candidate)
                .is_ok_and(|bytes| bytes == "attacker-pathname-replacement")
        }));
        assert!(!fs::read_to_string(moved).unwrap().is_empty());
    }

    #[test]
    fn backup_retention_never_touches_unproven_prefix_lookalikes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "zero").unwrap();
        let destination = CString::new("config.json").unwrap();
        let forged = root.path().join(format!(
            "{BACKUP_MARKER}{}-20260101-000000-000000000_{}_{}",
            destination_tag(&destination),
            "0".repeat(64),
            "a".repeat(32)
        ));
        fs::write(&forged, "attacker-owned-lookalike").unwrap();

        for index in 0..8 {
            update_with_backup(&path, root.path(), &format!("value-{index}")).unwrap();
        }

        assert_eq!(
            fs::read_to_string(&forged).unwrap(),
            "attacker-owned-lookalike"
        );
        assert_eq!(backup_paths(root.path()).len(), 6);
    }

    #[test]
    fn backup_retention_rejects_a_fully_bound_file_without_creation_mode() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "zero").unwrap();
        let staging = root.path().join("attacker-staging");
        fs::write(&staging, "attacker-owned-bound-lookalike").unwrap();
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o644)).unwrap();

        let (_, state) = stable_state_from_open_file(fs::File::open(&staging).unwrap()).unwrap();
        assert_eq!(state.mode, 0o644);
        let destination = CString::new("config.json").unwrap();
        let forged_name = backup_name(&destination, &state);
        assert_eq!(backup_binding(&destination, &state).len(), 64);
        assert!(!backup_name_matches(&forged_name, &destination, &state));
        let forged = root.path().join(OsStr::from_bytes(forged_name.to_bytes()));
        fs::rename(staging, &forged).unwrap();

        for index in 0..8 {
            update_with_backup(&path, root.path(), &format!("value-{index}")).unwrap();
        }

        assert_eq!(
            fs::read_to_string(&forged).unwrap(),
            "attacker-owned-bound-lookalike"
        );
        assert_eq!(
            fs::metadata(&forged).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(backup_paths(root.path()).len(), 6);
    }

    #[test]
    fn successful_updates_reuse_unix_tombstones_with_a_bound_of_five() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        for index in 0..20 {
            atomic_write(&path, root.path(), &format!("value-{index}"), 0o600).unwrap();
        }
        let tombstones = fs::read_dir(root.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(TOMBSTONE_MARKER)
            })
            .collect::<Vec<_>>();
        assert!(tombstones.len() <= ARTIFACT_RETENTION_LIMIT);
        assert!(tombstones.iter().all(|entry| {
            let metadata = entry.metadata().unwrap();
            metadata.len() == 0
                && metadata.permissions().mode() & 0o777 == 0o600
                && metadata.nlink() == 1
        }));
    }

    #[test]
    fn temp_retention_never_reuses_or_scrubs_prefix_only_lookalikes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        let forged = root
            .path()
            .join(".tirith-setup-v2-dead-beef-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.tmp");
        fs::write(&forged, "attacker-owned-lookalike").unwrap();

        for index in 0..10 {
            atomic_write(&path, root.path(), &format!("value-{index}"), 0o600).unwrap();
        }

        assert_eq!(
            fs::read_to_string(&forged).unwrap(),
            "attacker-owned-lookalike"
        );
        assert_eq!(fs::read_to_string(path).unwrap(), "value-9");
    }

    #[test]
    fn backup_uses_locked_snapshot_content_and_restrictive_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, "secret-data").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        update_with_backup(&path, dir.path(), "new-data").unwrap();
        let backup = backup_paths(dir.path()).pop().expect("backup created");
        assert_eq!(fs::read_to_string(&backup).unwrap(), "secret-data");
        assert_eq!(
            fs::metadata(backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn backup_generation_is_revalidated_before_commit() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let result = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o600).with_backup(true)),
            |stage| {
                if stage == TestStage::TempSynced {
                    let backup = backup_paths(root.path()).pop().unwrap();
                    fs::write(backup, "tampered-backup").unwrap();
                }
                Ok(())
            },
        );

        let error = result.unwrap_err();
        assert!(error.contains("backup") && error.contains("commit/announcement"));
        assert_eq!(fs::read_to_string(path).unwrap(), "after");
        assert!(backup_paths(root.path()).is_empty());
    }

    #[test]
    fn transaction_backup_and_retention_refuse_symlinked_parent() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let linked = root.path().join("configs");
        std::os::unix::fs::symlink(outside.path(), &linked).unwrap();
        fs::write(outside.path().join("config.json"), "outside-secret").unwrap();
        for i in 0..7 {
            fs::write(
                outside
                    .path()
                    .join(format!("config.json.tirith-backup-20260101-00000{i}")),
                format!("backup-{i}"),
            )
            .unwrap();
        }

        let path = linked.join("config.json");
        assert!(update_with_backup(&path, root.path(), "new").is_err());

        assert_eq!(
            fs::read_to_string(outside.path().join("config.json")).unwrap(),
            "outside-secret"
        );
        let backups = fs::read_dir(outside.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("tirith-backup")
            })
            .count();
        assert_eq!(backups, 7, "retention must not delete through the link");
    }

    #[test]
    fn dry_run_is_read_only_and_does_not_create_lock_or_parent() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("missing/config.json");
        let outcome = transactional_update(&path, root.path(), true, |_| {
            Ok(FileUpdate::write_text("planned".into(), 0o644))
        })
        .unwrap();
        assert_eq!(outcome, TransactionOutcome::DryRunWouldWrite);
        assert!(!root.path().join("missing").exists());
        assert!(!fs::read_dir(root.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".tirith-setup-lock-")
            }));
    }

    #[test]
    fn fifo_snapshot_is_rejected_without_blocking() {
        let root = tempfile::tempdir().unwrap();
        let fifo = root.path().join("config.json");
        let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        let started = std::time::Instant::now();
        let error = read_to_string_scoped(&fifo, root.path()).unwrap_err();
        assert!(error.contains("not a regular file"));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn oversized_snapshot_is_rejected_at_cap_plus_one() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("huge.json");
        fs::write(
            &path,
            vec![b'x'; super::super::fs_transaction::MAX_SETUP_FILE_BYTES + 1],
        )
        .unwrap();
        assert!(read_to_string_scoped(&path, root.path()).is_err());
    }

    #[test]
    fn transformed_payload_accepts_exact_cap() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("exact-cap.json");
        let payload = "x".repeat(super::super::fs_transaction::MAX_SETUP_FILE_BYTES);
        let outcome = transactional_update(&path, root.path(), false, |_| {
            Ok(FileUpdate::write_text(payload.clone(), 0o600))
        })
        .unwrap();
        assert_eq!(outcome, TransactionOutcome::Written);
        assert_eq!(fs::metadata(path).unwrap().len(), payload.len() as u64);
    }

    #[test]
    fn transformed_payload_rejects_cap_plus_one_before_live_side_effects() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("missing").join("too-large.json");
        let payload = "x".repeat(super::super::fs_transaction::MAX_SETUP_FILE_BYTES + 1);
        let error = transactional_update(&path, root.path(), false, |_| {
            Ok(FileUpdate::write_text(payload.clone(), 0o600).with_backup(true))
        })
        .unwrap_err();
        assert!(error.contains("setup file limit"));
        assert!(!root.path().join("missing").exists());
        assert!(backup_paths(root.path()).is_empty());
    }

    #[test]
    fn drifted_transform_is_recomputed_and_capped_before_artifacts() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "base").unwrap();
        let oversized = "x".repeat(super::super::fs_transaction::MAX_SETUP_FILE_BYTES + 1);
        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |snapshot| {
                if snapshot.text(&path)? == Some("base") {
                    Ok(FileUpdate::write_text("small".into(), 0o600).with_backup(true))
                } else {
                    Ok(FileUpdate::write_text(oversized.clone(), 0o600).with_backup(true))
                }
            },
            |stage| {
                if stage == TestStage::PreflightReady {
                    fs::write(&path, "drift").unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("setup file limit"));
        assert_eq!(fs::read_to_string(path).unwrap(), "drift");
        assert!(backup_paths(root.path()).is_empty());
        assert!(temporary_setup_paths(root.path()).is_empty());
    }

    #[test]
    fn transformed_payload_rejects_cap_plus_one_in_dry_run_without_side_effects() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("missing").join("too-large.json");
        let payload = "x".repeat(super::super::fs_transaction::MAX_SETUP_FILE_BYTES + 1);
        let error = transactional_update(&path, root.path(), true, |_| {
            Ok(FileUpdate::write_text(payload.clone(), 0o600))
        })
        .unwrap_err();
        assert!(error.contains("setup file limit"));
        assert!(!root.path().join("missing").exists());
    }

    #[test]
    fn precreated_regular_and_symlink_backup_names_are_never_overwritten() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "original").unwrap();
        let regular = root
            .path()
            .join("config.json.tirith-backup-99999999-999999-attacker");
        fs::write(&regular, "attacker-regular").unwrap();
        let target = root.path().join("outside-secret");
        fs::write(&target, "attacker-target").unwrap();
        let link = root
            .path()
            .join("config.json.tirith-backup-99999999-999999-symlink");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        update_with_backup(&path, root.path(), "updated").unwrap();
        assert_eq!(fs::read_to_string(regular).unwrap(), "attacker-regular");
        assert_eq!(fs::read_to_string(target).unwrap(), "attacker-target");
    }

    #[test]
    fn non_cooperating_generation_change_is_rejected_and_temp_is_scrubbed() {
        for (editor_bytes, expected_refusal) in [
            ("editor", "changed while setup"),
            ("editor-change", "exceeds setup file limit of 6 bytes"),
        ] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("config.json");
            fs::write(&path, "before").unwrap();
            let result = transactional_update_with_hook(
                &path,
                root.path(),
                |_| Ok(FileUpdate::write_text("ours".into(), 0o644)),
                |stage| {
                    if stage == TestStage::TempSynced {
                        fs::write(&path, editor_bytes).unwrap();
                    }
                    Ok(())
                },
            );
            let refusal = result.unwrap_err();
            assert!(refusal.contains(expected_refusal), "{refusal}");
            assert_eq!(fs::read_to_string(&path).unwrap(), editor_bytes);
            assert!(nonempty(temporary_setup_paths(root.path())).is_empty());
        }
    }

    #[test]
    fn swapped_temp_is_rejected_without_deleting_the_replacement() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let mut attacker_path = None;
        let result = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("ours".into(), 0o644)),
            |stage| {
                if stage == TestStage::TempSynced {
                    let temp = temporary_setup_paths(root.path()).pop().unwrap();
                    fs::remove_file(&temp).unwrap();
                    fs::write(&temp, "attacker-replacement").unwrap();
                    attacker_path = Some(temp);
                }
                Ok(())
            },
        );
        assert!(result.unwrap_err().contains("temporary setup file changed"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "before");
        assert_eq!(
            fs::read_to_string(attacker_path.unwrap()).unwrap(),
            "attacker-replacement"
        );
    }

    #[test]
    fn destination_swap_after_validation_is_detected_and_competitor_is_restored() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        let original_hold = root.path().join("original-held-by-writer");
        fs::write(&path, "original").unwrap();
        let original_identity = FileIdentity::from_metadata(&fs::metadata(&path).unwrap());
        let mut competitor_identity = None;

        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("tirith-update".into(), 0o644)),
            |stage| {
                if stage == TestStage::PublicationReady {
                    fs::rename(&path, &original_hold).unwrap();
                    fs::write(&path, "competing-writer").unwrap();
                    competitor_identity =
                        Some(FileIdentity::from_metadata(&fs::metadata(&path).unwrap()));
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("restored the competing destination"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "competing-writer");
        assert_eq!(
            FileIdentity::from_metadata(&fs::metadata(&path).unwrap()),
            competitor_identity.unwrap()
        );
        assert_eq!(fs::read_to_string(&original_hold).unwrap(), "original");
        assert_eq!(
            FileIdentity::from_metadata(&fs::metadata(&original_hold).unwrap()),
            original_identity
        );
        assert!(nonempty(temporary_setup_paths(root.path())).is_empty());
    }

    #[test]
    fn temp_swap_after_validation_never_publishes_attacker_identity() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        let held_prepared = root.path().join("prepared-held-by-writer");
        fs::write(&path, "original").unwrap();
        let original_identity = FileIdentity::from_metadata(&fs::metadata(&path).unwrap());
        let mut attacker_path = None;
        let mut attacker_identity = None;
        let mut prepared_identity = None;

        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("tirith-update".into(), 0o644)),
            |stage| {
                if stage == TestStage::PublicationReady {
                    let temp = temporary_setup_paths(root.path()).pop().unwrap();
                    prepared_identity =
                        Some(FileIdentity::from_metadata(&fs::metadata(&temp).unwrap()));
                    fs::rename(&temp, &held_prepared).unwrap();
                    fs::write(&temp, "attacker-temp").unwrap();
                    attacker_identity =
                        Some(FileIdentity::from_metadata(&fs::metadata(&temp).unwrap()));
                    attacker_path = Some(temp);
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("restored the competing destination"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "original");
        assert_eq!(
            FileIdentity::from_metadata(&fs::metadata(&path).unwrap()),
            original_identity
        );
        let attacker_path = attacker_path.unwrap();
        assert_eq!(fs::read_to_string(&attacker_path).unwrap(), "attacker-temp");
        assert_eq!(
            FileIdentity::from_metadata(&fs::metadata(attacker_path).unwrap()),
            attacker_identity.unwrap()
        );
        assert_eq!(fs::read_to_string(&held_prepared).unwrap(), "");
        assert_eq!(
            FileIdentity::from_metadata(&fs::metadata(held_prepared).unwrap()),
            prepared_identity.unwrap()
        );
    }

    #[test]
    fn expected_absent_race_never_overwrites_new_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        let result = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("ours".into(), 0o644)),
            |stage| {
                if stage == TestStage::SnapshotValidated {
                    fs::write(&path, "editor-created").unwrap();
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), "editor-created");
    }

    #[test]
    fn publication_failure_rolls_back_only_its_backup_and_temp() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let result = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("ours".into(), 0o644).with_backup(true)),
            |stage| {
                if stage == TestStage::SnapshotValidated {
                    fs::remove_file(&path).unwrap();
                    fs::create_dir(&path).unwrap();
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(nonempty(backup_paths(root.path())).is_empty());
        assert!(nonempty(temporary_setup_paths(root.path())).is_empty());
    }

    #[test]
    fn failure_after_temp_sync_scrubs_temp_and_transaction_backup() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o644).with_backup(true)),
            |stage| {
                if stage == TestStage::TempSynced {
                    return Err("injected failure after durable temp".into());
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.contains("injected failure"));
        assert_eq!(fs::read_to_string(path).unwrap(), "before");
        assert!(nonempty(backup_paths(root.path())).is_empty());
        assert!(nonempty(temporary_setup_paths(root.path())).is_empty());
    }

    #[test]
    fn guard_cleanup_failure_is_propagated_with_the_primary_error() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        SCRUB_FAILURE_TEST_HOOK.with(|slot| *slot.borrow_mut() = Some("temporary"));
        let result = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o600).with_backup(true)),
            |stage| {
                if stage == TestStage::TempSynced {
                    return Err("injected pre-publication failure".into());
                }
                Ok(())
            },
        );
        SCRUB_FAILURE_TEST_HOOK.with(|slot| *slot.borrow_mut() = None);

        let error = result.unwrap_err();
        assert!(error.contains("injected pre-publication failure"));
        assert!(error.contains("cleanup also failed"));
        assert_eq!(fs::read_to_string(path).unwrap(), "before");
    }

    #[test]
    fn displaced_scrub_failure_returns_written_with_recovery_never_clean() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        SCRUB_FAILURE_TEST_HOOK.with(|slot| *slot.borrow_mut() = Some("displaced"));
        let result = transactional_update(&path, root.path(), false, |_| {
            Ok(FileUpdate::write_text("after".into(), 0o600))
        });
        SCRUB_FAILURE_TEST_HOOK.with(|slot| *slot.borrow_mut() = None);

        assert_eq!(result.unwrap(), TransactionOutcome::WrittenWithRecovery);
        assert_eq!(fs::read_to_string(path).unwrap(), "after");
        assert_eq!(nonempty(temporary_setup_paths(root.path())).len(), 1);
    }

    #[test]
    fn retention_cleanup_failure_returns_written_with_recovery_never_clean() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "zero").unwrap();
        for index in 0..5 {
            update_with_backup(&path, root.path(), &format!("value-{index}")).unwrap();
        }
        SCRUB_FAILURE_TEST_HOOK.with(|slot| *slot.borrow_mut() = Some("retention inventory"));
        let result = transactional_update(&path, root.path(), false, |_| {
            Ok(FileUpdate::write_text("value-5".into(), 0o600).with_backup(true))
        });
        SCRUB_FAILURE_TEST_HOOK.with(|slot| *slot.borrow_mut() = None);

        assert_eq!(result.unwrap(), TransactionOutcome::WrittenWithRecovery);
        assert_eq!(fs::read_to_string(path).unwrap(), "value-5");
    }

    #[test]
    fn swapped_backup_cleanup_scrubs_only_the_held_identity() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        let held_backup = root.path().join("held-original-backup");
        fs::write(&path, "before-secret").unwrap();
        let mut attacker_backup = None;

        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o644).with_backup(true)),
            |stage| {
                if stage == TestStage::TempSynced {
                    let backup = backup_paths(root.path()).pop().unwrap();
                    fs::rename(&backup, &held_backup).unwrap();
                    fs::write(&backup, "attacker-backup").unwrap();
                    attacker_backup = Some(backup);
                    return Err("injected failure after backup swap".into());
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("injected failure"));
        assert_eq!(
            fs::read_to_string(attacker_backup.unwrap()).unwrap(),
            "attacker-backup"
        );
        assert_eq!(fs::read_to_string(held_backup).unwrap(), "");
        assert_eq!(fs::read_to_string(path).unwrap(), "before-secret");
    }

    #[test]
    fn post_publication_durability_failure_keeps_recovery_backup() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o644).with_backup(true)),
            |stage| {
                if stage == TestStage::Published {
                    return Err("injected directory durability failure".into());
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.contains("durability"));
        assert_eq!(fs::read_to_string(path).unwrap(), "after");
        assert_eq!(backup_paths(root.path()).len(), 1);
    }

    #[test]
    fn installed_name_swap_before_completion_is_detected_without_deleting_attacker() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        let moved_install = root.path().join("writer-moved-install");
        fs::write(&path, "before").unwrap();
        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o644).with_backup(true)),
            |stage| {
                if stage == TestStage::Published {
                    fs::rename(&path, &moved_install).unwrap();
                    fs::write(&path, "attacker").unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("installed destination identity changed"));
        assert_eq!(fs::read_to_string(path).unwrap(), "attacker");
        assert_eq!(fs::read_to_string(moved_install).unwrap(), "after");
        assert_eq!(backup_paths(root.path()).len(), 1);
    }

    fn wait_for_marker(path: &Path) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !path.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for subprocess marker {}",
                path.display()
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn subprocess_lock_child() {
        let Some(role) = std::env::var_os("TIRITH_SETUP_LOCK_CHILD_ROLE") else {
            return;
        };
        let root = PathBuf::from(std::env::var_os("TIRITH_SETUP_LOCK_ROOT").unwrap());
        let control = std::env::var_os("TIRITH_SETUP_LOCK_CONTROL")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.clone());
        let path = root.join("config.txt");
        match role.to_string_lossy().as_ref() {
            "holder" => {
                let entered = control.join("holder-entered");
                let release = control.join("release-holder");
                transactional_update_with_hook(
                    &path,
                    &root,
                    |snapshot| {
                        let mut content = snapshot.text(&path)?.unwrap_or("base").to_string();
                        content.push_str("-holder");
                        Ok(FileUpdate::write_text(content, 0o644))
                    },
                    |stage| {
                        if stage == TestStage::TempSynced {
                            fs::write(&entered, b"locked").unwrap();
                            wait_for_marker(&release);
                        }
                        Ok(())
                    },
                )
                .unwrap();
            }
            "contender" => {
                assert!(PlatformTransaction::lock_is_contended(&path, &root).unwrap());
                fs::write(control.join("contender-observed-lock"), b"contended").unwrap();
                transactional_update(&path, &root, false, |snapshot| {
                    let mut content = snapshot.text(&path)?.unwrap_or("base").to_string();
                    content.push_str("-contender");
                    Ok(FileUpdate::write_text(content, 0o644))
                })
                .unwrap();
            }
            other => panic!("unknown setup lock child role {other}"),
        }
    }

    #[test]
    fn cooperative_transactions_overlap_in_distinct_processes_and_recompute() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.txt");
        fs::write(&path, "base").unwrap();
        let test_binary = std::env::current_exe().unwrap();
        let test_name = "cli::setup::fs_helpers::tests::subprocess_lock_child";

        let mut holder = std::process::Command::new(&test_binary)
            .args(["--exact", test_name, "--nocapture"])
            .env("TIRITH_SETUP_LOCK_CHILD_ROLE", "holder")
            .env("TIRITH_SETUP_LOCK_ROOT", root.path())
            .spawn()
            .unwrap();
        wait_for_marker(&root.path().join("holder-entered"));

        let mut contender = std::process::Command::new(&test_binary)
            .args(["--exact", test_name, "--nocapture"])
            .env("TIRITH_SETUP_LOCK_CHILD_ROLE", "contender")
            .env("TIRITH_SETUP_LOCK_ROOT", root.path())
            .spawn()
            .unwrap();
        wait_for_marker(&root.path().join("contender-observed-lock"));
        assert!(
            holder.try_wait().unwrap().is_none(),
            "holder must still own the lock when the contender proves overlap"
        );
        assert!(
            contender.try_wait().unwrap().is_none(),
            "contender must be blocked until the holder publishes"
        );

        fs::write(root.path().join("release-holder"), b"release").unwrap();
        assert!(holder.wait().unwrap().success());
        assert!(contender.wait().unwrap().success());
        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("-holder") && content.contains("-contender"));
    }

    #[test]
    fn first_run_transactions_use_one_lock_identity_when_scope_starts_absent() {
        let control = tempfile::tempdir().unwrap();
        let root = control.path().join("missing").join("scope");
        let path = root.join("config.txt");
        let test_binary = std::env::current_exe().unwrap();
        let test_name = "cli::setup::fs_helpers::tests::subprocess_lock_child";

        let mut holder = std::process::Command::new(&test_binary)
            .args(["--exact", test_name, "--nocapture"])
            .env("TIRITH_SETUP_LOCK_CHILD_ROLE", "holder")
            .env("TIRITH_SETUP_LOCK_ROOT", &root)
            .env("TIRITH_SETUP_LOCK_CONTROL", control.path())
            .spawn()
            .unwrap();
        wait_for_marker(&control.path().join("holder-entered"));
        assert!(
            root.exists(),
            "holder must create the formerly missing scope"
        );

        let mut contender = std::process::Command::new(&test_binary)
            .args(["--exact", test_name, "--nocapture"])
            .env("TIRITH_SETUP_LOCK_CHILD_ROLE", "contender")
            .env("TIRITH_SETUP_LOCK_ROOT", &root)
            .env("TIRITH_SETUP_LOCK_CONTROL", control.path())
            .spawn()
            .unwrap();
        wait_for_marker(&control.path().join("contender-observed-lock"));
        assert!(holder.try_wait().unwrap().is_none());
        assert!(contender.try_wait().unwrap().is_none());

        fs::write(control.path().join("release-holder"), b"release").unwrap();
        assert!(holder.wait().unwrap().success());
        assert!(contender.wait().unwrap().success());
        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("-holder") && content.contains("-contender"));
    }

    #[test]
    fn cooperative_transactions_serialize_and_recompute() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.txt");
        fs::write(&path, "base").unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut threads = Vec::new();
        for suffix in ["-one", "-two"] {
            let path = path.clone();
            let root = root.path().to_path_buf();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                transactional_update(&path, &root, false, |snapshot| {
                    let mut content = snapshot.text(&path)?.unwrap().to_string();
                    content.push_str(suffix);
                    Ok(FileUpdate::write_text(content, 0o644))
                })
            }));
        }
        barrier.wait();
        for thread in threads {
            thread.join().unwrap().unwrap();
        }
        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("-one") && content.contains("-two"));
    }

    #[test]
    fn same_content_hook_mode_fix_is_atomic_and_dry_run_is_non_mutating() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("hook.sh");
        fs::write(&path, "hook").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        write_hook_script(&path, root.path(), "hook", false, true).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        write_hook_script(&path, root.path(), "hook", false, false).unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
}
