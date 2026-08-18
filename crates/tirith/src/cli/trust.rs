use std::fs;
use std::io::{self, BufRead, Read, Write};

use serde::{Deserialize, Serialize};

pub use tirith_core::policy::TrustScopeKind as ScopeKind;

/// Default TTL for a `trust add` with neither `--ttl` nor `--permanent`. Trust
/// expires by default; permanent trust must be chosen explicitly.
const DEFAULT_TTL: &str = "30d";
const TRUST_STORE_MAX_BYTES: u64 = 1024 * 1024;

/// A single entry in trust.json.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEntry {
    pub pattern: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_expires: Option<String>,
    pub added: String,
    pub source: String,
    /// Optional free-text reason recorded when the entry was added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The trust.json file format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustStore {
    pub version: u32,
    pub entries: Vec<TrustEntry>,
}

impl Default for TrustStore {
    fn default() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }
}

/// Classify how broad a trust pattern is.
pub fn classify_scope(pattern: &str) -> ScopeKind {
    tirith_core::policy::classify_trust_pattern(pattern)
}

/// A unified trust listing row shown by `trust list`.
#[derive(Debug, Clone, Serialize)]
struct TrustListRow {
    pattern: String,
    rule_id: Option<String>,
    source: String,
    expires: Option<String>,
    expired: bool,
    /// Machine-readable scope class.
    scope_kind: ScopeKind,
    /// One-line description of what the entry covers.
    scope_coverage: String,
    /// True when the entry is dangerously broad (wildcard / bare TLD).
    broad_warning: bool,
}

/// Print an error from a trust subcommand, with a "try --scope user" hint
/// when the error mentions "git repository" (i.e., `--scope repo` failed
/// because we are outside a git repo).
fn print_trust_error(subcmd: &str, err: &str, hint_pattern: Option<&str>) {
    eprintln!("{}", trust_error_line(subcmd, err));
    if err.contains("git repository") {
        if let Some(pattern) = hint_pattern {
            let display_pattern = human(pattern);
            let quoted = if display_pattern == pattern {
                tirith_core::safe_command::shell_single_quote(pattern)
                    .unwrap_or_else(|| "'[unsafe pattern]'".to_string())
            } else {
                "'[unsafe pattern]'".to_string()
            };
            eprintln!(
                "  try: tirith trust {} {} --scope user",
                human(subcmd),
                quoted
            );
        } else {
            eprintln!("  try: tirith trust {} --scope user", human(subcmd));
        }
    }
}

fn human(value: &str) -> String {
    super::sanitize_for_human_output(value, false)
}

fn human_multiline(value: &str) -> String {
    super::sanitize_for_human_output(value, true)
}

/// Render one trust-command error at the final human-output boundary. Both the
/// action and detail may originate outside the typed CLI path (library callers,
/// loaded parser diagnostics, environment-derived paths), so sanitize the
/// complete dynamic fields here instead of relying on validation upstream.
fn trust_error_line(action: &str, detail: &str) -> String {
    format!("tirith: trust {}: {}", human(action), human(detail))
}

fn unknown_scope_line(action: &str, scope: &str, allowed: &str) -> String {
    trust_error_line(action, &format!("unknown scope '{scope}' (use {allowed})"))
}

fn trust_prompt_line(domain: &str) -> String {
    format!(
        "Trust {}? [y/N/r(rule-scoped)/t(temporary 7d)] ",
        human(domain)
    )
}

/// Serialize `value` as pretty JSON to stdout. Returns `0` on success, `1` on a
/// serialization failure — surfaced as a non-zero exit so a consumer can tell
/// the output is incomplete rather than a misleading exit-0.
#[must_use]
fn print_json(value: &impl Serialize) -> i32 {
    match serde_json::to_string_pretty(value) {
        Ok(s) => {
            println!("{s}");
            0
        }
        Err(e) => {
            eprintln!(
                "tirith: JSON serialization failed: {}",
                human(&e.to_string())
            );
            1
        }
    }
}

/// Resolve the trust.json path for a given scope.
fn trust_store_path(scope: &str) -> Result<std::path::PathBuf, String> {
    match scope {
        "user" => {
            let config = tirith_core::policy::config_dir()
                .ok_or_else(|| "cannot determine config directory".to_string())?;
            Ok(config.join("trust.json"))
        }
        "repo" => {
            let repo_root = tirith_core::policy::find_repo_root(None)
                .ok_or_else(|| "not inside a git repository".to_string())?;
            Ok(repo_root.join(".tirith").join("trust.json"))
        }
        other => Err(format!("unknown scope: {other} (use 'user' or 'repo')")),
    }
}

/// Load the trust store from a path.
///
/// Returns `Ok(default)` if the file does not exist, or `Err` if the file
/// exists but cannot be parsed (prevents silent data loss on corruption).
fn load_store(path: &std::path::Path) -> Result<TrustStore, String> {
    let bytes = match tirith_core::util::read_text_no_follow_capped(path, TRUST_STORE_MAX_BYTES) {
        Ok(bytes) => bytes,
        Err(tirith_core::util::OpenRegularError::NotFound) => return Ok(TrustStore::default()),
        Err(tirith_core::util::OpenRegularError::NotRegularFile) => {
            return Err(format!(
                "refusing non-regular or symlinked trust store at {}",
                path.display()
            ))
        }
        Err(tirith_core::util::OpenRegularError::TooLarge) => {
            return Err(format!(
                "trust store at {} exceeds the {} byte limit",
                path.display(),
                TRUST_STORE_MAX_BYTES
            ))
        }
        Err(tirith_core::util::OpenRegularError::Io(error)) => {
            return Err(format!("cannot read {}: {error}", path.display()))
        }
    };
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("corrupt trust store at {}: {e}", path.display()))
}

/// Write a user trust store crash-atomically. Repo stores use the stronger
/// descriptor-relative implementation below.
fn write_store(path: &std::path::Path, store: &TrustStore) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create directory {}: {e}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(store)
        .map_err(|e| format!("failed to serialize trust store: {e}"))?;
    if json.len() as u64 > TRUST_STORE_MAX_BYTES {
        return Err(format!(
            "refusing to write trust store above the {TRUST_STORE_MAX_BYTES} byte limit"
        ));
    }
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(format!(
                "refusing non-regular or symlinked trust store at {}",
                path.display()
            ));
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| "trust store has no parent directory".to_string())?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("failed to create trust-store temp file: {e}"))?;
    tmp.write_all(&json)
        .and_then(|()| tmp.as_file().sync_all())
        .map_err(|e| format!("failed to write trust-store temp file: {e}"))?;
    tmp.persist(path)
        .map_err(|e| format!("failed to publish {}: {}", path.display(), e.error))?;
    Ok(())
}

/// repo-0233: cross-process lock for trust-store mutations. The mutation sites
/// load → modify → write; without a lock two processes lose each other's
/// entries. Returns a held lock file guard.
fn lock_trust_store(path: &std::path::Path) -> Result<std::fs::File, String> {
    use fs2::FileExt as _;
    let lock_path = path.with_extension("lock");
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create directory {}: {e}", parent.display()))?;
    }
    // The lock file carries no content; keep whatever is already there rather
    // than truncating a lock another process is holding.
    let file = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| format!("cannot open trust-store lock: {e}"))?;
    file.lock_exclusive()
        .map_err(|e| format!("cannot lock trust store: {e}"))?;
    Ok(file)
}

fn load_store_scoped(scope: &str, path: &std::path::Path) -> Result<TrustStore, String> {
    if scope == "repo" {
        load_repo_store(path)
    } else {
        load_store(path)
    }
}

fn write_store_scoped(
    scope: &str,
    path: &std::path::Path,
    store: &TrustStore,
) -> Result<(), String> {
    if scope == "repo" {
        write_repo_store(path, store)
    } else {
        write_store(path, store)
    }
}

#[cfg(unix)]
fn open_repo_trust_dir(path: &std::path::Path, create: bool) -> Result<std::fs::File, String> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt as _;

    let root = path
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or_else(|| "repo trust path is not <root>/.tirith/trust.json".to_string())?;
    // O_NOFOLLOW on the root too. Both callers derive it from
    // `find_repo_root(None)`, which starts at `std::env::current_dir()` —
    // `getcwd()`, whose result POSIX guarantees has no symlink components — and
    // then only ascends with `parent()`. So the root cannot be a symlink here
    // and this never costs a legitimate caller an ELOOP; it is free insurance
    // for any future caller that does not come from getcwd.
    let root_fd = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
        .map_err(|e| format!("cannot open repository root {}: {e}", root.display()))?;
    let name = CString::new(".tirith").expect("static component has no NUL");
    if create {
        let rc = unsafe { libc::mkdirat(root_fd.as_raw_fd(), name.as_ptr(), 0o755) };
        if rc != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(format!("cannot create repo .tirith directory: {error}"));
            }
        }
    }
    let fd = unsafe {
        libc::openat(
            root_fd.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "refusing repo trust path with a missing, symlinked, or non-directory .tirith component: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: `openat` returned a fresh owned descriptor.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn load_repo_store(path: &std::path::Path) -> Result<TrustStore, String> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};

    let dir = match open_repo_trust_dir(path, false) {
        Ok(dir) => dir,
        Err(error) => match path.parent().map(fs::symlink_metadata) {
            Some(Err(io_error)) if io_error.kind() == io::ErrorKind::NotFound => {
                return Ok(TrustStore::default())
            }
            _ => return Err(error),
        },
    };
    let name = CString::new("trust.json").expect("static component has no NUL");
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(TrustStore::default());
        }
        return Err(format!(
            "refusing repo trust store {}: {error}",
            path.display()
        ));
    }
    // SAFETY: `openat` returned a fresh owned descriptor.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot inspect repo trust store: {e}"))?;
    if !meta.is_file() {
        return Err("repo trust store is not a regular file".to_string());
    }
    if meta.len() > TRUST_STORE_MAX_BYTES {
        return Err(format!(
            "repo trust store exceeds the {TRUST_STORE_MAX_BYTES} byte limit"
        ));
    }
    let mut bytes = Vec::new();
    file.take(TRUST_STORE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read repo trust store: {e}"))?;
    if bytes.len() as u64 > TRUST_STORE_MAX_BYTES {
        return Err(format!(
            "repo trust store exceeds the {TRUST_STORE_MAX_BYTES} byte limit"
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("corrupt trust store at {}: {e}", path.display()))
}

#[cfg(unix)]
fn write_repo_store(path: &std::path::Path, store: &TrustStore) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};

    let dir = open_repo_trust_dir(path, true)?;
    let dest = CString::new("trust.json").expect("static component has no NUL");

    // Refuse an existing symlink, directory, FIFO, device, or socket. A later
    // destination swap is still safe: renameat replaces the directory entry and
    // never follows it.
    let existing_fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            dest.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if existing_fd >= 0 {
        // SAFETY: `openat` returned a fresh owned descriptor.
        let existing = unsafe { std::fs::File::from_raw_fd(existing_fd) };
        if !existing
            .metadata()
            .map_err(|e| format!("cannot inspect repo trust destination: {e}"))?
            .is_file()
        {
            return Err("repo trust destination is not a regular file".to_string());
        }
    } else {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(format!("refusing repo trust destination: {error}"));
        }
    }

    let bytes = serde_json::to_vec_pretty(store)
        .map_err(|e| format!("failed to serialize trust store: {e}"))?;
    if bytes.len() as u64 > TRUST_STORE_MAX_BYTES {
        return Err(format!(
            "refusing to write repo trust store above the {TRUST_STORE_MAX_BYTES} byte limit"
        ));
    }
    let temp_name = format!(".trust.json.{}.tmp", uuid::Uuid::new_v4());
    let temp = CString::new(temp_name.as_str()).expect("UUID temp name has no NUL");
    let temp_fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            temp.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o666,
        )
    };
    if temp_fd < 0 {
        return Err(format!(
            "cannot create repo trust temp file: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: `openat` returned a fresh owned descriptor.
    let mut temp_file = unsafe { std::fs::File::from_raw_fd(temp_fd) };
    let publish = temp_file
        .write_all(&bytes)
        .and_then(|()| temp_file.sync_all())
        .and_then(|()| {
            let rc = unsafe {
                libc::renameat(
                    dir.as_raw_fd(),
                    temp.as_ptr(),
                    dir.as_raw_fd(),
                    dest.as_ptr(),
                )
            };
            if rc == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
    if let Err(error) = publish {
        unsafe {
            libc::unlinkat(dir.as_raw_fd(), temp.as_ptr(), 0);
        }
        return Err(format!(
            "failed to atomically publish repo trust store: {error}"
        ));
    }
    dir.sync_all()
        .map_err(|e| format!("failed to sync repo trust directory: {e}"))?;
    Ok(())
}

#[cfg(windows)]
mod windows_repo_store {
    use super::{fs, io, Read, TrustStore, Write, TRUST_STORE_MAX_BYTES};
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, RawHandle};
    use std::path::{Path, PathBuf};

    use windows::core::{HRESULT, PCWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, HANDLE,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, FileDispositionInfo, GetFileInformationByHandle,
        GetFinalPathNameByHandleW, SetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        CREATE_NEW, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY,
        FILE_READ_ATTRIBUTES, FILE_RENAME_INFO_0, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
        OPEN_EXISTING,
    };

    struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        fn into_file(self) -> fs::File {
            let raw = self.0 .0 as RawHandle;
            std::mem::forget(self);
            // SAFETY: the handle is valid, uniquely owned, and forgotten above.
            unsafe { fs::File::from_raw_handle(raw) }
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: `OwnedHandle` owns exactly one live Win32 handle.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    struct RepoTrustDir {
        path: PathBuf,
        final_path: String,
        _root: OwnedHandle,
        directory: OwnedHandle,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct FileIdentity {
        volume: u32,
        index: u64,
        size: u64,
        last_write: u64,
        attributes: u32,
    }

    #[repr(C)]
    struct TrustRenameInfo {
        _anonymous: FILE_RENAME_INFO_0,
        _root_directory: HANDLE,
        _file_name_length: u32,
        _file_name: [u16; 10],
    }

    const TRUST_FILE_NAME_UTF16: [u16; 10] = [
        b't' as u16,
        b'r' as u16,
        b'u' as u16,
        b's' as u16,
        b't' as u16,
        b'.' as u16,
        b'j' as u16,
        b's' as u16,
        b'o' as u16,
        b'n' as u16,
    ];

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn is_win32(error: &windows::core::Error, code: u32) -> bool {
        error.code() == HRESULT::from_win32(code)
    }

    fn final_path(handle: HANDLE) -> Result<String, String> {
        let mut buffer = vec![0u16; 512];
        loop {
            let length =
                unsafe { GetFinalPathNameByHandleW(handle, &mut buffer, Default::default()) };
            if length == 0 {
                return Err(format!(
                    "cannot resolve path held by repo trust handle: {}",
                    io::Error::last_os_error()
                ));
            }
            if (length as usize) < buffer.len() {
                return Ok(String::from_utf16_lossy(&buffer[..length as usize]));
            }
            buffer.resize(length as usize + 1, 0);
        }
    }

    fn normalized_final_path(path: &str) -> String {
        let path = path.replace('/', "\\");
        let path = path
            .strip_prefix(r"\\?\UNC\")
            .map(|rest| format!(r"\\{rest}"))
            .or_else(|| path.strip_prefix(r"\\?\").map(str::to_owned))
            .unwrap_or(path);
        path.trim_end_matches('\\').to_lowercase()
    }

    fn is_exact_child(parent: &str, child: &str, name: &str) -> bool {
        let expected = format!("{}\\{}", normalized_final_path(parent), name.to_lowercase());
        normalized_final_path(child) == expected
    }

    fn inspect_directory(handle: HANDLE, path: &Path) -> Result<(), String> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        unsafe { GetFileInformationByHandle(handle, &mut info) }.map_err(|error| {
            format!(
                "cannot inspect repo trust directory {}: {error}",
                path.display()
            )
        })?;
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
        {
            return Err(format!(
                "refusing reparse or non-directory repo trust component {}",
                path.display()
            ));
        }
        Ok(())
    }

    fn open_directory(path: &Path) -> Result<Option<OwnedHandle>, String> {
        let path_wide = wide(path);
        let handle = match unsafe {
            CreateFileW(
                PCWSTR(path_wide.as_ptr()),
                (FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES).0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        } {
            Ok(handle) => handle,
            Err(error)
                if is_win32(&error, ERROR_FILE_NOT_FOUND.0)
                    || is_win32(&error, ERROR_PATH_NOT_FOUND.0) =>
            {
                return Ok(None);
            }
            Err(error) => {
                return Err(format!(
                    "cannot open repo trust directory {}: {error}",
                    path.display()
                ));
            }
        };
        let owned = OwnedHandle(handle);
        inspect_directory(handle, path)?;
        Ok(Some(owned))
    }

    fn split_path(path: &Path) -> Result<(&Path, &Path), String> {
        if path.file_name() != Some(std::ffi::OsStr::new("trust.json")) {
            return Err("repo trust path is not <root>/.tirith/trust.json".to_string());
        }
        let directory = path
            .parent()
            .filter(|parent| parent.file_name() == Some(std::ffi::OsStr::new(".tirith")))
            .ok_or_else(|| "repo trust path is not <root>/.tirith/trust.json".to_string())?;
        let root = directory
            .parent()
            .ok_or_else(|| "repo trust path is not <root>/.tirith/trust.json".to_string())?;
        Ok((root, directory))
    }

    fn open_repo_dir(path: &Path, create: bool) -> Result<Option<RepoTrustDir>, String> {
        let (root_path, directory_path) = split_path(path)?;
        let root = open_directory(root_path)?
            .ok_or_else(|| format!("repository root {} does not exist", root_path.display()))?;
        let root_final = final_path(root.0)?;

        let directory = match open_directory(directory_path)? {
            Some(directory) => directory,
            None if !create => return Ok(None),
            None => {
                let directory_wide = wide(directory_path);
                if let Err(error) =
                    unsafe { CreateDirectoryW(PCWSTR(directory_wide.as_ptr()), None) }
                {
                    if !is_win32(&error, ERROR_ALREADY_EXISTS.0) {
                        return Err(format!(
                            "cannot create repo trust directory {}: {error}",
                            directory_path.display()
                        ));
                    }
                }
                open_directory(directory_path)?.ok_or_else(|| {
                    format!(
                        "repo trust directory {} disappeared after creation",
                        directory_path.display()
                    )
                })?
            }
        };
        let directory_final = final_path(directory.0)?;
        if !is_exact_child(&root_final, &directory_final, ".tirith") {
            return Err(
                "repo trust directory resolves outside the held repository root".to_string(),
            );
        }
        Ok(Some(RepoTrustDir {
            path: directory_path.to_path_buf(),
            final_path: directory_final,
            _root: root,
            directory,
        }))
    }

    fn inspect_regular(handle: HANDLE, path: &Path) -> Result<FileIdentity, String> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        unsafe { GetFileInformationByHandle(handle, &mut info) }.map_err(|error| {
            format!("cannot inspect repo trust file {}: {error}", path.display())
        })?;
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0
        {
            return Err(format!(
                "refusing reparse or non-regular repo trust file {}",
                path.display()
            ));
        }
        Ok(FileIdentity {
            volume: info.dwVolumeSerialNumber,
            index: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
            size: ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64,
            last_write: ((info.ftLastWriteTime.dwHighDateTime as u64) << 32)
                | info.ftLastWriteTime.dwLowDateTime as u64,
            attributes: info.dwFileAttributes,
        })
    }

    fn open_regular_file(
        directory: &RepoTrustDir,
        path: &Path,
    ) -> Result<Option<(fs::File, FileIdentity)>, String> {
        let path_wide = wide(path);
        let handle = match unsafe {
            CreateFileW(
                PCWSTR(path_wide.as_ptr()),
                (FILE_GENERIC_READ | FILE_READ_ATTRIBUTES).0,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        } {
            Ok(handle) => handle,
            Err(error)
                if is_win32(&error, ERROR_FILE_NOT_FOUND.0)
                    || is_win32(&error, ERROR_PATH_NOT_FOUND.0) =>
            {
                return Ok(None);
            }
            Err(error) => {
                return Err(format!(
                    "refusing repo trust file {}: {error}",
                    path.display()
                ));
            }
        };
        let owned = OwnedHandle(handle);
        let identity = inspect_regular(handle, path)?;
        let file_final = final_path(handle)?;
        if !is_exact_child(&directory.final_path, &file_final, "trust.json") {
            return Err("repo trust file resolves outside the held .tirith directory".to_string());
        }
        Ok(Some((owned.into_file(), identity)))
    }

    fn mark_held_file_for_deletion(file: &fs::File) -> Result<(), String> {
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        unsafe {
            SetFileInformationByHandle(
                HANDLE(file.as_raw_handle()),
                FileDispositionInfo,
                (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        }
        .map_err(|error| format!("cannot remove exact repo trust temp identity: {error}"))
    }

    fn cleanup_suffix(file: &fs::File) -> String {
        mark_held_file_for_deletion(file)
            .err()
            .map(|error| format!("; exact-handle cleanup also failed: {error}"))
            .unwrap_or_default()
    }

    pub(super) fn load(path: &Path) -> Result<TrustStore, String> {
        let Some(directory) = open_repo_dir(path, false)? else {
            return Ok(TrustStore::default());
        };
        let Some((mut file, before)) = open_regular_file(&directory, path)? else {
            return Ok(TrustStore::default());
        };
        if before.size > TRUST_STORE_MAX_BYTES {
            return Err(format!(
                "repo trust store exceeds the {TRUST_STORE_MAX_BYTES} byte limit"
            ));
        }
        let mut bytes = Vec::with_capacity(before.size as usize);
        (&mut file)
            .take(TRUST_STORE_MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("cannot read repo trust store: {error}"))?;
        if bytes.len() as u64 > TRUST_STORE_MAX_BYTES {
            return Err(format!(
                "repo trust store exceeds the {TRUST_STORE_MAX_BYTES} byte limit"
            ));
        }
        let after = inspect_regular(HANDLE(file.as_raw_handle()), path)?;
        if before != after || bytes.len() as u64 != after.size {
            return Err("repo trust store changed while being read".to_string());
        }
        serde_json::from_slice(&bytes)
            .map_err(|error| format!("corrupt trust store at {}: {error}", path.display()))
    }

    pub(super) fn write(path: &Path, store: &TrustStore) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(store)
            .map_err(|error| format!("failed to serialize trust store: {error}"))?;
        if bytes.len() as u64 > TRUST_STORE_MAX_BYTES {
            return Err(format!(
                "refusing to write repo trust store above the {TRUST_STORE_MAX_BYTES} byte limit"
            ));
        }

        let directory = open_repo_dir(path, true)?
            .ok_or_else(|| "repo trust directory disappeared during creation".to_string())?;
        // Reject an existing reparse point or non-regular object. A later
        // destination swap is safe because publication replaces the directory
        // entry through the held temporary-file and parent-directory handles.
        drop(open_regular_file(&directory, path)?);

        let temp_name = format!(".trust.json.{}.tmp", uuid::Uuid::new_v4().simple());
        let temp_path = directory.path.join(&temp_name);
        let temp_wide = wide(&temp_path);
        let handle = unsafe {
            CreateFileW(
                PCWSTR(temp_wide.as_ptr()),
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES | DELETE).0,
                Default::default(),
                None,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .map_err(|error| format!("cannot create exclusive repo trust temp file: {error}"))?;
        let owned = OwnedHandle(handle);
        let temp_final = match final_path(handle) {
            Ok(path) => path,
            Err(error) => {
                let file = owned.into_file();
                let cleanup = cleanup_suffix(&file);
                return Err(format!("{error}{cleanup}"));
            }
        };
        if !is_exact_child(&directory.final_path, &temp_final, &temp_name) {
            let file = owned.into_file();
            let cleanup = cleanup_suffix(&file);
            return Err(format!(
                "repo trust temp file resolves outside the held .tirith directory{cleanup}"
            ));
        }
        let mut file = owned.into_file();
        if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
            let cleanup = cleanup_suffix(&file);
            return Err(format!(
                "failed to write and sync repo trust temp file: {error}{cleanup}"
            ));
        }
        let temp_identity = match inspect_regular(HANDLE(file.as_raw_handle()), &temp_path) {
            Ok(identity) => identity,
            Err(error) => {
                let cleanup = cleanup_suffix(&file);
                return Err(format!("{error}{cleanup}"));
            }
        };
        if temp_identity.size != bytes.len() as u64 {
            let cleanup = cleanup_suffix(&file);
            return Err(format!(
                "repo trust temp file size changed before publication{cleanup}"
            ));
        }

        let mut rename_mode = FILE_RENAME_INFO_0::default();
        rename_mode.ReplaceIfExists = true;
        let rename = TrustRenameInfo {
            _anonymous: rename_mode,
            _root_directory: directory.directory.0,
            _file_name_length: (TRUST_FILE_NAME_UTF16.len() * std::mem::size_of::<u16>()) as u32,
            _file_name: TRUST_FILE_NAME_UTF16,
        };
        // The Win32 wrapper (SetFileInformationByHandle + FileRenameInfo)
        // rejects a non-NULL RootDirectory with ERROR_INVALID_PARAMETER: it
        // accepts full destination paths only. The retained directory handle
        // IS the anchor of this publish (no by-name re-resolution), so call
        // the NT service directly — FileRenameInformation honors
        // handle-relative names, and TrustRenameInfo's layout doubles as the
        // kernel struct (the pinned layout test below covers the shared
        // offsets).
        let mut io_status = windows::Win32::System::IO::IO_STATUS_BLOCK::default();
        let status = unsafe {
            windows::Wdk::Storage::FileSystem::NtSetInformationFile(
                HANDLE(file.as_raw_handle()),
                &mut io_status,
                (&rename as *const TrustRenameInfo).cast(),
                std::mem::size_of::<TrustRenameInfo>() as u32,
                windows::Wdk::Storage::FileSystem::FileRenameInformation,
            )
        };
        if status.0 < 0 {
            let code = unsafe { windows::Win32::Foundation::RtlNtStatusToDosError(status) };
            let error = std::io::Error::from_raw_os_error(code as i32);
            let cleanup = cleanup_suffix(&file);
            return Err(format!(
                "failed to atomically publish repo trust store: {error}{cleanup}"
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows::Win32::Storage::FileSystem::FILE_RENAME_INFO;

        #[test]
        fn fixed_rename_buffer_matches_win32_header_layout() {
            assert_eq!(
                std::mem::offset_of!(TrustRenameInfo, _anonymous),
                std::mem::offset_of!(FILE_RENAME_INFO, Anonymous)
            );
            assert_eq!(
                std::mem::offset_of!(TrustRenameInfo, _root_directory),
                std::mem::offset_of!(FILE_RENAME_INFO, RootDirectory)
            );
            assert_eq!(
                std::mem::offset_of!(TrustRenameInfo, _file_name_length),
                std::mem::offset_of!(FILE_RENAME_INFO, FileNameLength)
            );
            assert_eq!(
                std::mem::offset_of!(TrustRenameInfo, _file_name),
                std::mem::offset_of!(FILE_RENAME_INFO, FileName)
            );
            assert_eq!(
                std::mem::size_of::<TrustRenameInfo>(),
                std::mem::offset_of!(FILE_RENAME_INFO, FileName)
                    + std::mem::size_of_val(&TRUST_FILE_NAME_UTF16)
            );
        }
    }
}

#[cfg(windows)]
fn load_repo_store(path: &std::path::Path) -> Result<TrustStore, String> {
    windows_repo_store::load(path)
}

#[cfg(windows)]
fn write_repo_store(path: &std::path::Path, store: &TrustStore) -> Result<(), String> {
    windows_repo_store::write(path, store)
}

#[cfg(all(not(unix), not(windows)))]
fn load_repo_store(path: &std::path::Path) -> Result<TrustStore, String> {
    let parent = path
        .parent()
        .ok_or_else(|| "repo trust path has no parent".to_string())?;
    match fs::symlink_metadata(parent) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(TrustStore::default()),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err("refusing symlinked or non-directory repo trust path".to_string())
        }
        Ok(_) => {}
        Err(error) => return Err(format!("cannot inspect repo trust directory: {error}")),
    }
    if matches!(fs::symlink_metadata(path), Err(error) if error.kind() == io::ErrorKind::NotFound) {
        return Ok(TrustStore::default());
    }
    Err(
        "repo-scoped trust requires descriptor-relative no-symlink filesystem operations, which are not available on this platform; use --scope user"
            .to_string(),
    )
}

#[cfg(all(not(unix), not(windows)))]
fn write_repo_store(path: &std::path::Path, store: &TrustStore) -> Result<(), String> {
    let _ = (path, store);
    Err(
        "repo-scoped trust requires descriptor-relative no-symlink filesystem operations, which are not available on this platform; use --scope user"
            .to_string(),
    )
}

/// Parse a duration string like "1h", "7d", "30d" into an expiry timestamp.
fn parse_ttl(ttl: &str) -> Result<String, String> {
    let ttl = ttl.trim();
    if ttl.is_empty() {
        return Err("empty TTL".to_string());
    }

    let (num_str, unit) = if let Some(n) = ttl.strip_suffix('d') {
        (n, "d")
    } else if let Some(n) = ttl.strip_suffix('h') {
        (n, "h")
    } else if let Some(n) = ttl.strip_suffix('m') {
        (n, "m")
    } else {
        return Err(format!(
            "unsupported TTL format: {ttl} (use e.g. 1h, 7d, 30d)"
        ));
    };

    let num: u64 = num_str
        .parse()
        .map_err(|_| format!("invalid TTL number: {num_str}"))?;
    if num == 0 {
        return Err("TTL must be > 0".to_string());
    }

    let multiplier: u64 = match unit {
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => unreachable!(),
    };

    let seconds = num
        .checked_mul(multiplier)
        .ok_or_else(|| format!("TTL value too large: {num}{unit}"))?;

    let seconds_i64 =
        i64::try_from(seconds).map_err(|_| format!("TTL value too large: {num}{unit}"))?;

    let expires = chrono::Utc::now() + chrono::Duration::seconds(seconds_i64);
    Ok(expires.to_rfc3339())
}

/// Check if an entry is expired. No `ttl_expires` (older/`--permanent` entries)
/// never expires; an unparseable `ttl_expires` is treated as NOT expired so a
/// malformed timestamp never silently revokes trust.
fn is_expired(entry: &TrustEntry) -> bool {
    if let Some(ref exp) = entry.ttl_expires {
        if let Ok(expiry) = chrono::DateTime::parse_from_rfc3339(exp) {
            return expiry < chrono::Utc::now();
        }
    }
    false
}

/// Format the time remaining until an RFC3339 expiry, e.g. "in 6d" / "in 2h".
/// Returns `None` for a permanent (no-TTL) entry, "expired" when already past.
fn humanize_expiry(ttl_expires: Option<&str>) -> Option<String> {
    let exp = ttl_expires?;
    let expiry = chrono::DateTime::parse_from_rfc3339(exp).ok()?;
    let now = chrono::Utc::now();
    let delta = expiry.signed_duration_since(now);
    if delta.num_seconds() <= 0 {
        return Some("expired".to_string());
    }
    let secs = delta.num_seconds();
    let human = if secs >= 86400 {
        format!("in {}d", secs / 86400)
    } else if secs >= 3600 {
        format!("in {}h", secs / 3600)
    } else if secs >= 60 {
        format!("in {}m", secs / 60)
    } else {
        format!("in {secs}s")
    };
    Some(human)
}

/// Validate a pattern for trust add.
fn validate_pattern(pattern: &str, policy: &tirith_core::policy::Policy) -> Result<(), String> {
    tirith_core::policy::validate_trust_pattern(pattern)?;
    if policy.is_blocklisted(pattern) {
        return Err(format!(
            "pattern '{pattern}' is in the blocklist and cannot be trusted"
        ));
    }
    Ok(())
}

/// `tirith trust add <pattern> [--rule <rule_id>] [--ttl <duration>]
/// [--permanent] [--broad] [--reason <text>] [--scope user|repo]`
#[allow(clippy::too_many_arguments)]
pub fn add(
    pattern: &str,
    rule_id: Option<&str>,
    ttl: Option<&str>,
    permanent: bool,
    broad: bool,
    reason: Option<&str>,
    scope: &str,
    json: bool,
) -> i32 {
    if let Some(rule_id) = rule_id {
        if human(rule_id) != rule_id {
            eprintln!("tirith: trust add: rule id contains unsafe display characters");
            return 1;
        }
    }
    if let Some(reason) = reason {
        if tirith_core::mcp::output_filter::sanitize_for_display(reason) != reason {
            eprintln!("tirith: trust add: reason contains unsafe display characters");
            return 1;
        }
    }
    // Validate against policy plus flat user/org blocklists loaded below.
    let mut policy = tirith_core::policy::Policy::discover(None);
    policy.load_user_lists();
    policy.load_org_lists(None);
    if let Err(e) = validate_pattern(pattern, &policy) {
        eprintln!("{}", trust_error_line("add", &e));
        return 1;
    }

    // --ttl and --permanent are mutually exclusive (clap enforces it too; guard
    // here for the library-call path).
    if permanent && ttl.is_some() {
        eprintln!("tirith: trust add: --permanent cannot be combined with --ttl");
        return 1;
    }

    // Narrow-trust-by-default: a broad pattern (domain/wildcard/bare-TLD) requires
    // an explicit `--broad` opt-in.
    let scope_kind = classify_scope(pattern);
    if scope_kind.is_broad() && !broad {
        eprintln!(
            "tirith: trust add: '{}' is a {} pattern — {}.",
            human(pattern),
            scope_kind.label(),
            scope_kind.coverage()
        );
        eprintln!(
            "  Trust the narrowest thing that works (a specific URL or path), \
             or pass --broad to accept this scope."
        );
        if scope_kind == ScopeKind::BareTld {
            eprintln!(
                "  Note: trusting a bare TLD allows EVERY host under '.{}' — \
                 this is almost never what you want.",
                human(pattern)
            );
        }
        return 1;
    }

    let path = match trust_store_path(scope) {
        Ok(p) => p,
        Err(e) => {
            print_trust_error("add", &e, Some(pattern));
            return 1;
        }
    };

    // repo-0233: hold the store lock across load → mutate → write.
    let _store_lock = match lock_trust_store(&path) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("tirith: trust store lock failed: {e}");
            return 1;
        }
    };
    let mut store = match load_store_scoped(scope, &path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", trust_error_line("add", &e));
            return 1;
        }
    };

    // Resolve the effective TTL:
    //   --permanent          -> no expiry
    //   --ttl <d>            -> that duration
    //   neither              -> DEFAULT_TTL (trust expires by default)
    let (ttl_expires, ttl_label): (Option<String>, Option<String>) = if permanent {
        (None, None)
    } else {
        let effective = ttl.unwrap_or(DEFAULT_TTL);
        match parse_ttl(effective) {
            Ok(exp) => (Some(exp), Some(effective.to_string())),
            Err(e) => {
                eprintln!("{}", trust_error_line("add", &e));
                return 1;
            }
        }
    };

    let entry = TrustEntry {
        pattern: pattern.to_string(),
        rule_id: rule_id.map(String::from),
        ttl_expires: ttl_expires.clone(),
        added: chrono::Utc::now().to_rfc3339(),
        source: "cli".to_string(),
        reason: reason.map(str::to_string),
    };

    store.entries.push(entry);

    if let Err(e) = write_store_scoped(scope, &path, &store) {
        eprintln!("{}", trust_error_line("add", &e));
        return 1;
    }

    tirith_core::audit::log_trust_change(pattern, rule_id, "add", ttl_expires.as_deref(), scope);

    if json {
        let out = serde_json::json!({
            "added": pattern,
            "scope": scope,
            "rule_id": rule_id,
            "scope_kind": scope_kind,
            "scope_coverage": scope_kind.coverage(),
            "ttl": ttl_label,
            "ttl_expires": ttl_expires,
            "permanent": permanent,
            "reason": reason,
        });
        return print_json(&out);
    }
    let ttl_note = match &ttl_label {
        Some(t) => format!(", ttl: {t}"),
        None => ", permanent (no expiry)".to_string(),
    };
    eprintln!(
        "tirith: trusted '{}' (scope: {}, {} pattern{})",
        human(pattern),
        human(scope),
        scope_kind.label(),
        human(&ttl_note)
    );
    if scope_kind.is_dangerous() {
        eprintln!(
            "  warning: this is a {} entry — {}.",
            scope_kind.label(),
            scope_kind.coverage()
        );
    }
    0
}

/// `tirith trust list [--rule <id>] [--json] [--expired] [--scope user|repo|all]`
pub fn list(rule_filter: Option<&str>, json: bool, show_expired: bool, scope: &str) -> i32 {
    if !matches!(scope, "user" | "repo" | "all") {
        eprintln!(
            "{}",
            unknown_scope_line("list", scope, "'user', 'repo', or 'all'")
        );
        return 1;
    }

    let mut rows: Vec<TrustListRow> = match collect_rows(scope, show_expired) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", trust_error_line("list", &e));
            return 1;
        }
    };

    if let Some(filter) = rule_filter {
        rows.retain(|r| {
            r.rule_id
                .as_ref()
                .map(|id| id.eq_ignore_ascii_case(filter))
                .unwrap_or(false)
        });
    }

    if json {
        return print_json(&rows);
    }
    if rows.is_empty() {
        eprintln!("tirith: no trust entries found");
    } else {
        let max_pat = rows
            .iter()
            .map(|r| human(&r.pattern).len())
            .max()
            .unwrap_or(7)
            .max(7);
        let max_src = rows
            .iter()
            .map(|r| human(&r.source).len())
            .max()
            .unwrap_or(6)
            .max(6);
        let max_rule = rows
            .iter()
            .map(|r| r.rule_id.as_ref().map(|s| human(s).len()).unwrap_or(1))
            .max()
            .unwrap_or(4)
            .max(4);
        // A '!' suffix marks a dangerously broad entry; size the SCOPE column
        // on the *rendered* string so the trailing '!' never breaks alignment.
        let scope_render = |row: &TrustListRow| -> String {
            if row.broad_warning {
                format!("{}!", row.scope_kind.label())
            } else {
                row.scope_kind.label().to_string()
            }
        };
        let max_scope = rows
            .iter()
            .map(|r| scope_render(r).len())
            .max()
            .unwrap_or(5)
            .max(5);

        eprintln!(
            "{:<max_pat$}  {:<max_rule$}  {:<max_scope$}  {:<max_src$}  EXPIRES",
            "PATTERN", "RULE", "SCOPE", "SOURCE"
        );
        let mut any_dangerous = false;
        for row in &rows {
            let pattern_display = human(&row.pattern);
            let rule_display = human(row.rule_id.as_deref().unwrap_or("-"));
            let source_display = human(&row.source);
            let expires_display = match (&row.expires, row.expired) {
                (Some(exp), true) => format!("{} (EXPIRED)", human(exp)),
                (Some(exp), false) => match humanize_expiry(Some(exp)) {
                    Some(h) => format!("{} ({})", human(exp), human(&h)),
                    None => human(exp),
                },
                (None, _) => "permanent".to_string(),
            };
            let scope_display = scope_render(row);
            if row.broad_warning {
                any_dangerous = true;
            }
            eprintln!(
                "{:<max_pat$}  {:<max_rule$}  {:<max_scope$}  {:<max_src$}  {}",
                pattern_display, rule_display, scope_display, source_display, expires_display
            );
        }
        if any_dangerous {
            eprintln!(
                "\ntirith: '!' marks dangerously broad entries (wildcard / bare TLD). \
                 Run 'tirith trust explain <pattern>' for detail."
            );
        }
    }

    0
}

/// Collect every trust-style row for the given scope. Shared by `list` and the
/// scope-visualisation paths. `show_expired` controls whether expired
/// TTL-bearing entries are included.
fn collect_rows(scope: &str, show_expired: bool) -> Result<Vec<TrustListRow>, String> {
    let mut rows: Vec<TrustListRow> = Vec::new();

    let scopes_to_load: Vec<&str> = match scope {
        "all" => vec!["user", "repo"],
        s => vec![s],
    };

    for s in &scopes_to_load {
        let path = match trust_store_path(s) {
            Ok(p) => p,
            Err(e) => {
                // "all" skips missing scopes (e.g., repo outside a git tree);
                // an explicit single scope is a hard error.
                if scope != "all" {
                    return Err(e);
                }
                continue;
            }
        };
        let store = load_store_scoped(s, &path)?;
        let source = format!("trust-{s}");
        for entry in &store.entries {
            let expired = is_expired(entry);
            if expired && !show_expired {
                continue;
            }
            rows.push(make_row(
                entry.pattern.clone(),
                entry.rule_id.clone(),
                source.clone(),
                entry.ttl_expires.clone(),
                expired,
            ));
        }
    }

    if scope == "all" {
        if let Some(config) = tirith_core::policy::config_dir() {
            let allowlist_path = config.join("allowlist");
            if let Ok(content) = fs::read_to_string(&allowlist_path) {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        rows.push(make_row(
                            line.to_string(),
                            None,
                            "allowlist-user".to_string(),
                            None,
                            false,
                        ));
                    }
                }
            }
        }

        if let Some(repo_root) = tirith_core::policy::find_repo_root(None) {
            let allowlist_path = repo_root.join(".tirith").join("allowlist");
            if let Ok(content) = fs::read_to_string(&allowlist_path) {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        rows.push(make_row(
                            line.to_string(),
                            None,
                            "allowlist-org".to_string(),
                            None,
                            false,
                        ));
                    }
                }
            }
        }

        let policy = tirith_core::policy::Policy::discover(None);
        for pattern in &policy.allowlist {
            // Skip patterns already surfaced from the flat allowlist files.
            if !rows
                .iter()
                .any(|r| r.pattern == *pattern && r.source.starts_with("allowlist"))
            {
                rows.push(make_row(
                    pattern.clone(),
                    None,
                    "policy".to_string(),
                    None,
                    false,
                ));
            }
        }
        for rule in &policy.allowlist_rules {
            for pattern in &rule.patterns {
                rows.push(make_row(
                    pattern.clone(),
                    Some(rule.rule_id.clone()),
                    "policy".to_string(),
                    None,
                    false,
                ));
            }
        }
    }

    Ok(rows)
}

/// Build a `TrustListRow`, computing the scope classification once.
fn make_row(
    pattern: String,
    rule_id: Option<String>,
    source: String,
    expires: Option<String>,
    expired: bool,
) -> TrustListRow {
    let scope_kind = classify_scope(&pattern);
    TrustListRow {
        pattern,
        rule_id,
        source,
        expires,
        expired,
        scope_kind,
        scope_coverage: scope_kind.coverage().to_string(),
        broad_warning: scope_kind.is_dangerous(),
    }
}

/// `tirith trust remove <pattern> [--rule <rule_id>] [--scope user|repo]`
pub fn remove(pattern: &str, rule_id: Option<&str>, scope: &str) -> i32 {
    let path = match trust_store_path(scope) {
        Ok(p) => p,
        Err(e) => {
            print_trust_error("remove", &e, Some(pattern));
            return 1;
        }
    };

    // repo-0233: hold the store lock across load → mutate → write.
    let _store_lock = match lock_trust_store(&path) {
        Ok(guard) => guard,
        Err(e) => {
            eprintln!("tirith: trust store lock failed: {e}");
            return 1;
        }
    };
    let mut store = match load_store_scoped(scope, &path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}", trust_error_line("remove", &e));
            return 1;
        }
    };
    let before_len = store.entries.len();

    store.entries.retain(|entry| {
        let pattern_matches = entry.pattern == pattern;
        let rule_matches = match (rule_id, &entry.rule_id) {
            (Some(filter), Some(entry_rule)) => filter.eq_ignore_ascii_case(entry_rule),
            (Some(_), None) => false,
            (None, _) => true,
        };
        !(pattern_matches && rule_matches)
    });

    let removed = before_len - store.entries.len();
    if removed == 0 {
        eprintln!(
            "tirith: trust remove: no matching entry found for '{}'",
            human(pattern)
        );
        return 1;
    }

    if let Err(e) = write_store_scoped(scope, &path, &store) {
        eprintln!("{}", trust_error_line("remove", &e));
        return 1;
    }

    tirith_core::audit::log_trust_change(pattern, rule_id, "remove", None, scope);

    eprintln!(
        "tirith: removed {removed} trust entry/entries for '{}' (scope: {})",
        human(pattern),
        human(scope)
    );
    0
}

/// Read and JSON-parse `last_trigger.json` from the data dir.
///
/// Shared by `last()` (interactive prompt) and `from_last_trigger()` (suggest
/// ready-to-run commands). Returns the parsed value so each caller can pull the
/// fields it needs without re-reading the file. `Ok(None)` means there is no
/// recent trigger on disk (missing file); `Err` is a real read/parse failure.
fn load_last_trigger_value() -> Result<Option<serde_json::Value>, String> {
    super::last_trigger::load_last_trigger_record()?
        .map(|record| {
            serde_json::to_value(record)
                .map_err(|e| format!("failed to project structured last trigger: {e}"))
        })
        .transpose()
}

/// Extract `(target, rule_id)` PAIRS from a parsed `last_trigger.json`.
///
/// Pairing is PER FINDING: each finding carries its OWN `rule_id` and its own
/// `evidence`, so a target pulled from a finding's evidence is paired with THAT
/// finding's `rule_id` — never the flat top-level `rule_ids` array. Pairing
/// against the top-level array would form a cartesian product, so for a
/// multi-finding trigger `--apply` could trust URL A under rule B even though
/// rule B fired for a DIFFERENT target.
///
/// Each target prefers a FULL URL when the evidence carries one (a `raw` string
/// with a scheme that parses) so the suggested trust can be narrow; it falls
/// back to a bare host/domain otherwise. Per-finding `raw` is read before
/// `raw_host`, mirroring how `last()` walks findings. A finding with no
/// extractable rule_id yields `(target, None)`. Results are de-duped on the full
/// `(target, rule_id)` pair, so the same URL flagged by two different rules
/// keeps both pairings.
fn extract_target_rule_pairs(val: &serde_json::Value) -> Vec<(String, Option<String>)> {
    let mut pairs: Vec<(String, Option<String>)> = Vec::new();
    let push = |t: String, rid: &Option<String>, pairs: &mut Vec<(String, Option<String>)>| {
        if t.is_empty() {
            return;
        }
        let pair = (t, rid.clone());
        if !pairs.contains(&pair) {
            pairs.push(pair);
        }
    };
    if let Some(findings) = val.get("findings").and_then(|v| v.as_array()) {
        for finding in findings {
            // THIS finding's own rule id — paired with every target it produces.
            let rule_id = finding
                .get("rule_id")
                .and_then(|v| v.as_str())
                .map(String::from);
            if let Some(evidence) = finding.get("evidence").and_then(|v| v.as_array()) {
                for ev in evidence {
                    if let Some(raw) = ev.get("raw").and_then(|v| v.as_str()) {
                        // Prefer the full URL when `raw` is one; else fall back
                        // to the bare host so we still have something to trust.
                        if raw.contains("://") && url::Url::parse(raw).is_ok() {
                            push(raw.to_string(), &rule_id, &mut pairs);
                        } else if let Some(host) = extract_host(raw) {
                            push(host, &rule_id, &mut pairs);
                        }
                    }
                    if let Some(host) = ev.get("raw_host").and_then(|v| v.as_str()) {
                        push(host.to_string(), &rule_id, &mut pairs);
                    }
                }
            }
        }
    }

    pairs
}

/// Normalize a per-finding target to the bare host `last()` displays and
/// prompts on. `extract_target_rule_pairs` may yield a FULL URL or a bare host;
/// `last()`'s `domains` list is always a bare host (via `extract_host` /
/// `raw_host`). Reduce a URL target to its host so a pair can be matched back to
/// the host the user was actually asked about; a target that is already a bare
/// host (or any non-URL) maps to itself.
fn target_host(target: &str) -> String {
    extract_host(target).unwrap_or_else(|| target.to_string())
}

/// The rule_id(s) that actually fired for a single host in the last trigger.
///
/// Reuses `extract_target_rule_pairs` (the same per-finding source
/// `from_last_trigger` uses) as the single source of truth, then keeps only the
/// rules whose finding targeted `host`, never the flat top-level `rule_ids`
/// array. This is what stops `last()`'s rule-scoped choice from granting one
/// host every rule in the whole verdict. Results are de-duped, preserving order.
fn rules_for_host(val: &serde_json::Value, host: &str) -> Vec<String> {
    let mut rules: Vec<String> = Vec::new();
    for (target, rule_id) in extract_target_rule_pairs(val) {
        if target_host(&target) != host {
            continue;
        }
        if let Some(rid) = rule_id {
            if !rules.contains(&rid) {
                rules.push(rid);
            }
        }
    }
    rules
}

/// Read + parse + extract in one step: per-finding `(target, rule_id)` pairs.
///
/// Each target prefers a full URL, else a bare domain (see
/// `extract_target_rule_pairs`). `Err` covers both "no recent trigger" (so
/// callers can print a friendly note) and real read/parse failures.
fn read_last_trigger() -> Result<Vec<(String, Option<String>)>, String> {
    match load_last_trigger_value()? {
        Some(val) => Ok(extract_target_rule_pairs(&val)),
        None => Err("no recent trigger found".into()),
    }
}

/// Build the ready-to-run `tirith trust add` suggestion lines for each
/// per-finding `(target, rule_id)` pair. A full-URL target is narrow, so it is
/// suggested without `--broad`; a bare domain needs `--broad` because
/// `trust add` rejects broad scopes without the opt-in (see `add()` /
/// `classify_scope`). Each pair carries ITS OWN rule id, so a rule is never
/// suggested for a target it didn't fire on.
fn suggestion_lines(pairs: &[(String, Option<String>)]) -> Vec<String> {
    pairs
        .iter()
        .map(|(target, rule_id)| {
            // A target that classifies as broad (bare domain/wildcard/TLD) needs
            // `--broad`; a full URL (or any narrow pattern) does not.
            let needs_broad = classify_scope(target).is_broad();
            format_add_line(target, rule_id.as_deref(), needs_broad)
        })
        .collect()
}

fn format_add_line(target: &str, rule_id: Option<&str>, needs_broad: bool) -> String {
    // The target is attacker-controlled (a URL/host pulled from the trigger's
    // finding evidence) and this line is printed for the operator to copy/paste
    // into a shell. If display sanitization would alter any character, emit only
    // a static manual-review note: silently stripping an escape, bidi control, or
    // forged newline could turn untrusted data into a different runnable trust
    // command. Benign shell metacharacters remain unchanged here and are protected
    // by the single-quote below.
    if human(target) != target {
        return "# trust this target manually with `tirith trust add` \
                (it contains characters unsafe to embed in a suggested command)."
            .to_string();
    }
    let Some(quoted) = tirith_core::safe_command::shell_single_quote(target) else {
        return "# trust this target manually with `tirith trust add` \
                (it contains characters unsafe to embed in a suggested command)."
            .to_string();
    };
    let broad = if needs_broad { " --broad" } else { "" };
    match rule_id {
        Some(rid) => {
            if human(rid) != rid {
                return "# trust this target manually with `tirith trust add` \
                        (its rule id contains characters unsafe to embed in a suggested command)."
                    .to_string();
            }
            let rid = if rid
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
                && !rid.is_empty()
            {
                rid.to_string()
            } else {
                let Some(quoted) = tirith_core::safe_command::shell_single_quote(rid) else {
                    return "# trust this target manually with `tirith trust add` \
                            (its rule id contains characters unsafe to embed in a suggested command)."
                        .to_string();
                };
                quoted
            };
            format!("tirith trust add {quoted}{broad} --rule {rid} --ttl {DEFAULT_TTL}")
        }
        None => format!("tirith trust add {quoted}{broad} --ttl {DEFAULT_TTL}"),
    }
}

/// `tirith trust from-last-trigger [--apply]` -- turn the most recent trigger
/// into trust commands. Default (suggest) prints ready-to-run `trust add`
/// lines so the operator can copy/paste the narrowest one; `--apply` runs them.
///
/// Print-only by default mirrors the codebase's `policy tune` stance: suggest,
/// don't mutate.
pub fn from_last_trigger(apply: bool) -> i32 {
    let pairs = match read_last_trigger() {
        Ok(v) => v,
        // A missing/empty trigger is not an error for this command -- it is the
        // common "nothing happened yet" case, so exit 0 with a friendly note.
        Err(e) if e == "no recent trigger found" => {
            eprintln!("tirith: no recent trigger to trust");
            return 0;
        }
        Err(e) => {
            eprintln!("{}", trust_error_line("from-last-trigger", &e));
            return 1;
        }
    };

    if pairs.is_empty() {
        eprintln!("tirith: no recent trigger to trust");
        return 0;
    }

    if !apply {
        eprintln!("Suggested trust commands (run the narrowest one that fits):");
        eprintln!();
        for line in suggestion_lines(&pairs) {
            println!("{}", human(&line));
        }
        eprintln!();
        eprintln!("Re-run with --apply to add these automatically.");
        return 0;
    }

    // --apply: actually add each per-finding entry, pairing each target with ITS
    // OWN rule id (never a rule that fired on a different target). A bare-domain
    // target is broad, so pass `broad = true`; a full-URL (narrow) one does not.
    let mut added = 0;
    let mut failed = 0;
    for (target, rule_id) in &pairs {
        let broad = classify_scope(target).is_broad();
        // Pass DEFAULT_TTL explicitly (not None) so the applied entry uses the
        // same source the printed suggestion's `--ttl {DEFAULT_TTL}` does. `add()`
        // would resolve None to DEFAULT_TTL anyway, but sharing the one constant
        // keeps suggest and apply from drifting on separate literals.
        if add(
            target,
            rule_id.as_deref(),
            Some(DEFAULT_TTL),
            false,
            broad,
            None,
            "user",
            false,
        ) == 0
        {
            added += 1;
        } else {
            failed += 1;
        }
    }

    eprintln!("tirith: added {added} trust entry/entries from last trigger");
    // A partial apply (some entries rejected by `add()`, e.g. a blocklisted or
    // control-char target) must NOT exit 0 and masquerade as a clean success --
    // surface the count and fail loud so the operator knows not every entry stuck.
    if failed > 0 {
        eprintln!("tirith: {failed} trust entry/entries could not be added");
        return 1;
    }
    0
}

/// `tirith trust last` -- show last trigger and offer to trust.
pub fn last() -> i32 {
    let val = match load_last_trigger_value() {
        Ok(Some(v)) => v,
        Ok(None) => {
            eprintln!("tirith: no recent trigger found");
            return 1;
        }
        Err(e) => {
            eprintln!("{}", trust_error_line("last", &e));
            return 1;
        }
    };

    if let Some(ts) = val.get("timestamp").and_then(|v| v.as_str()) {
        eprintln!("Last trigger at: {}", human(ts));
    }
    if let Some(cmd) = val.get("command_redacted").and_then(|v| v.as_str()) {
        eprintln!("Command: {}", human(cmd));
    }

    let mut domains: Vec<String> = Vec::new();
    if let Some(findings) = val.get("findings").and_then(|v| v.as_array()) {
        for finding in findings {
            if let Some(title) = finding.get("title").and_then(|v| v.as_str()) {
                eprintln!("  - {}", human(title));
            }
            if let Some(evidence) = finding.get("evidence").and_then(|v| v.as_array()) {
                for ev in evidence {
                    if let Some(raw) = ev.get("raw").and_then(|v| v.as_str()) {
                        if let Some(host) = extract_host(raw) {
                            if !domains.contains(&host) {
                                domains.push(host);
                            }
                        }
                    }
                    if let Some(host) = ev.get("raw_host").and_then(|v| v.as_str()) {
                        let h = host.to_string();
                        if !domains.contains(&h) {
                            domains.push(h);
                        }
                    }
                }
            }
        }
    }

    if domains.is_empty() {
        eprintln!("\ntirith: no domain/URL found in last trigger to trust");
        return 0;
    }

    for domain in &domains {
        let display_domain = human(domain);
        eprintln!();
        eprint!("{}", trust_prompt_line(domain));
        let _ = io::stderr().flush();

        let stdin = io::stdin();
        let mut line = String::new();
        if stdin.lock().read_line(&mut line).is_err() {
            continue;
        }
        let choice = line.trim().to_lowercase();

        match choice.as_str() {
            "y" | "yes" => {
                // A bare `y` trusts the whole domain — keep that affordance,
                // but it is a broad scope, so pass `broad = true` explicitly.
                add(domain, None, None, false, true, None, "user", false);
            }
            "r" | "rule" => {
                // Pair this host with ONLY the rule(s) that actually fired for
                // it (per-finding, from `extract_target_rule_pairs`), not every
                // top-level rule in the verdict. Trusting one host under a rule
                // that fired on a DIFFERENT target would be over-broad.
                let host_rules = rules_for_host(&val, domain);
                if host_rules.is_empty() {
                    eprintln!("tirith: no rule IDs for {display_domain}, adding global trust");
                    add(domain, None, None, false, true, None, "user", false);
                } else {
                    for rid in &host_rules {
                        // Rule-scoped trust is narrow by construction.
                        add(domain, Some(rid), None, false, true, None, "user", false);
                    }
                }
            }
            "t" | "temp" | "temporary" => {
                add(domain, None, Some("7d"), false, true, None, "user", false);
            }
            _ => {
                eprintln!("tirith: skipped {display_domain}");
            }
        }
    }

    0
}

/// `tirith trust gc [--expired] [--scope user|repo|all]`
///
/// `--expired` is the default and only collection mode today; it is accepted
/// explicitly so the command reads clearly and leaves room for future modes.
pub fn gc(expired: bool, scope: &str, json: bool) -> i32 {
    gc_with_action("gc", expired, scope, json)
}

/// `tirith trust prune` — spec-named alias for `gc` (M6 ch3). Both
/// invoke the same backing implementation; only the audit `trust_action`
/// field differs so an operator can tell which command the user actually
/// typed.
pub fn prune(expired: bool, scope: &str, json: bool) -> i32 {
    gc_with_action("prune", expired, scope, json)
}

fn gc_with_action(action_label: &str, expired: bool, scope: &str, json: bool) -> i32 {
    if !matches!(scope, "user" | "repo" | "all") {
        eprintln!(
            "{}",
            unknown_scope_line(action_label, scope, "'user', 'repo', or 'all'"),
        );
        return 1;
    }
    // `--expired` is currently the only mode; if a caller explicitly passes
    // nothing we still collect expired entries (documented default).
    let _ = expired;

    let scopes: Vec<&str> = match scope {
        "all" => vec!["user", "repo"],
        s => vec![s],
    };

    let mut total_removed = 0;
    let mut per_scope: Vec<(String, usize)> = Vec::new();

    for s in scopes {
        let path = match trust_store_path(s) {
            Ok(p) => p,
            Err(e) => {
                if scope != "all" {
                    print_trust_error(action_label, &e, None);
                    return 1;
                }
                continue;
            }
        };

        // repo-0233: hold the store lock across load → mutate → write.
        let _store_lock = match lock_trust_store(&path) {
            Ok(guard) => guard,
            Err(e) => {
                eprintln!("{}", trust_error_line(action_label, &e));
                return 1;
            }
        };
        let mut store = match load_store_scoped(s, &path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{}", trust_error_line(action_label, &e));
                return 1;
            }
        };
        let before = store.entries.len();
        // Capture removed entries so each lands in the audit log under the right
        // `trust_action` (M6 ch3) — otherwise gc/prune sweeps are invisible there.
        let expired_entries: Vec<TrustEntry> = store
            .entries
            .iter()
            .filter(|entry| is_expired(entry))
            .cloned()
            .collect();
        store.entries.retain(|entry| !is_expired(entry));
        let removed = before - store.entries.len();

        if removed > 0 {
            if let Err(e) = write_store_scoped(s, &path, &store) {
                eprintln!("{}", trust_error_line(action_label, &e));
                return 1;
            }
            for entry in &expired_entries {
                tirith_core::audit::log_trust_change(
                    &entry.pattern,
                    entry.rule_id.as_deref(),
                    action_label,
                    entry.ttl_expires.as_deref(),
                    s,
                );
            }
            if !json {
                eprintln!(
                    "tirith: {}: removed {removed} expired entries from {} scope",
                    human(action_label),
                    human(s),
                );
            }
        }

        per_scope.push((s.to_string(), removed));
        total_removed += removed;
    }

    if json {
        let out = serde_json::json!({
            "removed_total": total_removed,
            "by_scope": per_scope
                .iter()
                .map(|(s, n)| serde_json::json!({ "scope": s, "removed": n }))
                .collect::<Vec<_>>(),
        });
        return print_json(&out);
    }
    if total_removed == 0 {
        eprintln!("tirith: {}: no expired entries found", human(action_label));
    }

    0
}

// --- trust explain ---------------------------------------------------------

/// `tirith trust explain <pattern> [--scope ...]` — explain one trust entry:
/// what it covers, how broad it is, when it expires, and why it was added.
#[derive(Debug, Serialize)]
struct ExplainReport {
    pattern: String,
    /// True when no matching trust/allowlist entry exists.
    found: bool,
    /// One report per matching entry (a pattern may appear in several scopes).
    matches: Vec<ExplainMatch>,
}

#[derive(Debug, Serialize)]
struct ExplainMatch {
    source: String,
    rule_id: Option<String>,
    scope_kind: ScopeKind,
    scope_coverage: String,
    /// True when this entry is dangerously broad.
    broad_warning: bool,
    added: Option<String>,
    reason: Option<String>,
    ttl_expires: Option<String>,
    /// Human "in 6d" / "expired" / `None` for permanent.
    expires_in: Option<String>,
    expired: bool,
    permanent: bool,
}

/// `tirith trust explain <pattern>`.
pub fn explain(pattern: &str, scope: &str, json: bool) -> i32 {
    if !matches!(scope, "user" | "repo" | "all") {
        eprintln!(
            "{}",
            unknown_scope_line("explain", scope, "'user', 'repo', or 'all'")
        );
        return 1;
    }
    if pattern.is_empty() {
        eprintln!("tirith: trust explain: pattern must not be empty");
        return 1;
    }

    // Gather full entry detail (reason/added) from the trust stores, plus
    // bare allowlist/policy rows. Show expired entries too — `explain` is for
    // understanding an entry, including a stale one.
    let mut matches: Vec<ExplainMatch> = Vec::new();

    let scopes: Vec<&str> = match scope {
        "all" => vec!["user", "repo"],
        s => vec![s],
    };
    for s in &scopes {
        let path = match trust_store_path(s) {
            Ok(p) => p,
            Err(e) => {
                if scope != "all" {
                    print_trust_error("explain", &e, None);
                    return 1;
                }
                continue;
            }
        };
        let store = match load_store_scoped(s, &path) {
            Ok(st) => st,
            Err(e) => {
                eprintln!("{}", trust_error_line("explain", &e));
                return 1;
            }
        };
        for entry in &store.entries {
            if entry.pattern == pattern {
                let kind = classify_scope(&entry.pattern);
                matches.push(ExplainMatch {
                    source: format!("trust-{s}"),
                    rule_id: entry.rule_id.clone(),
                    scope_kind: kind,
                    scope_coverage: kind.coverage().to_string(),
                    broad_warning: kind.is_dangerous(),
                    added: Some(entry.added.clone()),
                    reason: entry.reason.clone(),
                    ttl_expires: entry.ttl_expires.clone(),
                    expires_in: humanize_expiry(entry.ttl_expires.as_deref()),
                    expired: is_expired(entry),
                    permanent: entry.ttl_expires.is_none(),
                });
            }
        }
    }

    // Also surface a match coming purely from policy / flat allowlist files.
    if scope == "all" {
        if let Ok(rows) = collect_rows("all", true) {
            for r in rows {
                let from_allowlist_or_policy =
                    r.source.starts_with("allowlist") || r.source == "policy";
                if r.pattern == pattern && from_allowlist_or_policy {
                    matches.push(ExplainMatch {
                        source: r.source,
                        rule_id: r.rule_id,
                        scope_kind: r.scope_kind,
                        scope_coverage: r.scope_coverage,
                        broad_warning: r.broad_warning,
                        added: None,
                        reason: None,
                        ttl_expires: None,
                        expires_in: None,
                        expired: false,
                        permanent: true,
                    });
                }
            }
        }
    }

    let report = ExplainReport {
        pattern: pattern.to_string(),
        found: !matches.is_empty(),
        matches,
    };

    if json {
        return print_json(&report);
    }

    if !report.found {
        // Still explain what *would* happen if this pattern were trusted.
        let kind = classify_scope(pattern);
        eprintln!(
            "tirith: '{}' is not currently trusted in scope '{}'.",
            human(pattern),
            human(scope)
        );
        eprintln!(
            "  If added, it would be a {} entry — {}.",
            kind.label(),
            kind.coverage()
        );
        if kind.is_broad() {
            eprintln!("  That is a broad scope; `trust add` would require --broad to accept it.");
        }
        return 0;
    }

    println!("trust explain: {}", human(pattern));
    for (i, m) in report.matches.iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!("  source:   {}", human(&m.source));
        println!(
            "  scope:    {} — {}",
            m.scope_kind.label(),
            human(&m.scope_coverage)
        );
        if let Some(rid) = &m.rule_id {
            println!("  rule:     {} (suppresses this rule only)", human(rid));
        } else {
            println!("  rule:     (global — suppresses every rule)");
        }
        if let Some(added) = &m.added {
            println!("  added:    {}", human(added));
        }
        match &m.reason {
            Some(r) => println!("  reason:   {}", human_multiline(r)),
            None => println!("  reason:   (none recorded)"),
        }
        match (&m.ttl_expires, m.permanent) {
            (_, true) => println!("  expires:  never (permanent)"),
            (Some(exp), false) => {
                let suffix = m
                    .expires_in
                    .as_deref()
                    .map(|h| format!(" ({h})"))
                    .unwrap_or_default();
                println!("  expires:  {}{}", human(exp), human(&suffix));
            }
            (None, false) => println!("  expires:  never (permanent)"),
        }
        if m.expired {
            println!("  status:   EXPIRED — run 'tirith trust gc --expired' to remove it");
        }
        if m.broad_warning {
            println!(
                "  warning:  dangerously broad — {}",
                m.scope_kind.coverage()
            );
        }
    }
    0
}

// --- trust diff ------------------------------------------------------------

/// File name for the append-only trust snapshot history used by `trust diff`.
const TRUST_HISTORY_FILE: &str = "trust-history.jsonl";
/// Hard cap on retained snapshot lines — keeps the file tiny and bounded.
const TRUST_HISTORY_MAX_LINES: usize = 64;

/// One observation of the full trust set, appended to the history file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TrustSnapshot {
    /// RFC3339 timestamp when this snapshot was recorded.
    recorded_at: String,
    /// Every trusted pattern at observation time, as `source\u{1f}pattern\u{1f}rule`.
    /// A stable, sorted, flattened key list — enough to diff set membership.
    entries: Vec<String>,
}

/// Resolve the trust snapshot history file path under the state dir.
fn trust_history_path() -> Option<std::path::PathBuf> {
    tirith_core::policy::state_dir().map(|d| d.join(TRUST_HISTORY_FILE))
}

/// Stable flattened key for one trust row: `source\u{1f}pattern\u{1f}rule`.
fn row_key(r: &TrustListRow) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}",
        r.source,
        r.pattern,
        r.rule_id.as_deref().unwrap_or("")
    )
}

/// Decompose a `row_key` back into `(source, pattern, rule)` for display.
fn split_key(key: &str) -> (String, String, Option<String>) {
    let mut it = key.split('\u{1f}');
    let source = it.next().unwrap_or("").to_string();
    let pattern = it.next().unwrap_or("").to_string();
    let rule = it.next().filter(|s| !s.is_empty()).map(String::from);
    (source, pattern, rule)
}

/// Build a snapshot of the current full trust set (all scopes, including
/// expired entries — diff cares about set membership, not expiry).
fn current_trust_snapshot() -> TrustSnapshot {
    let mut entries: Vec<String> = collect_rows("all", true)
        .unwrap_or_default()
        .iter()
        .map(row_key)
        .collect();
    entries.sort();
    entries.dedup();
    TrustSnapshot {
        recorded_at: chrono::Utc::now().to_rfc3339(),
        entries,
    }
}

/// Load all retained trust snapshots, oldest first (unparseable lines skipped).
/// Returns `(snapshots, read_error)`: a missing file → empty + `None`; a file
/// that exists but can't be read → empty + `Some(msg)` so `diff` can say "could
/// not read history" instead of falsely reporting "first observation".
fn load_trust_history() -> (Vec<TrustSnapshot>, Option<String>) {
    let Some(path) = trust_history_path() else {
        return (Vec::new(), None);
    };
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return (Vec::new(), None),
        Err(e) => {
            return (
                Vec::new(),
                Some(format!(
                    "could not read trust snapshot history at {} ({e}) — check file \
                     permissions; the diff below cannot use any earlier snapshot",
                    path.display()
                )),
            );
        }
    };
    let snapshots = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<TrustSnapshot>(l).ok())
        .collect();
    (snapshots, None)
}

/// Atomic write (temp file + rename) so a torn write can never leave a partial
/// snapshot history. Mirrors `threatdb_cmd::record_snapshot`.
fn atomic_write(dest: &std::path::Path, data: &[u8]) -> Result<(), String> {
    let parent = dest
        .parent()
        .ok_or_else(|| "cannot determine parent directory".to_string())?;
    fs::create_dir_all(parent).map_err(|e| format!("failed to create directory: {e}"))?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("failed to create temp file: {e}"))?;
    tmp.write_all(data)
        .map_err(|e| format!("failed to write temp file: {e}"))?;
    tmp.flush()
        .map_err(|e| format!("failed to flush temp file: {e}"))?;
    tmp.persist(dest)
        .map_err(|e| format!("failed to rename temp file: {e}"))?;
    Ok(())
}

/// Append `snapshot` to the trust history file if its entry set differs from
/// the most recent snapshot. Best-effort: any I/O error is silently ignored —
/// the history is a convenience for `diff`, never load-bearing for analysis.
fn record_trust_snapshot(snapshot: &TrustSnapshot) {
    let Some(path) = trust_history_path() else {
        return;
    };
    // Read-error note is irrelevant: recording rewrites the whole file regardless.
    let (mut history, _) = load_trust_history();
    // Dedup on entry set so an unchanged trust set doesn't append a line every call.
    if history
        .last()
        .map(|s| s.entries == snapshot.entries)
        .unwrap_or(false)
    {
        return;
    }
    history.push(snapshot.clone());
    if history.len() > TRUST_HISTORY_MAX_LINES {
        let drop = history.len() - TRUST_HISTORY_MAX_LINES;
        history.drain(0..drop);
    }
    let mut body = String::new();
    for s in &history {
        if let Ok(line) = serde_json::to_string(s) {
            body.push_str(&line);
            body.push('\n');
        }
    }
    let _ = atomic_write(&path, body.as_bytes());
}

/// Take a snapshot of the current trust set and fold it into the history file.
/// Called by the read-only `trust list` / `trust diff` paths so a diff trail
/// accrues over time without any extra user action.
pub fn snapshot_current_trust() {
    record_trust_snapshot(&current_trust_snapshot());
}

#[derive(Debug, Serialize)]
struct DiffEntry {
    pattern: String,
    source: String,
    rule_id: Option<String>,
    scope_kind: ScopeKind,
}

#[derive(Debug, Serialize)]
struct TrustDiffReport {
    /// RFC3339 time of the baseline snapshot, if one was found.
    baseline_recorded_at: Option<String>,
    /// Entries present now but not in the baseline.
    added: Vec<DiffEntry>,
    /// Entries present in the baseline but not now.
    removed: Vec<DiffEntry>,
    /// True when nothing changed.
    unchanged: bool,
    /// Set when the diff could not be produced against a real baseline.
    note: Option<String>,
}

fn diff_entry_of(key: &str) -> DiffEntry {
    let (source, pattern, rule_id) = split_key(key);
    let scope_kind = classify_scope(&pattern);
    DiffEntry {
        pattern,
        source,
        rule_id,
        scope_kind,
    }
}

/// `tirith trust audit` — show recorded trust-store mutations (M6 ch3).
///
/// Walks the audit-log JSONL and filters entries with
/// `entry_type == "trust_change"`. Optionally trims the window with
/// `--since <duration>` (e.g. `7d`, `24h`, `15m`).
pub fn audit(since: Option<&str>, json: bool) -> i32 {
    let cutoff = match since {
        Some(s) => match parse_relative_duration(s) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!(
                    "{}",
                    trust_error_line("audit", &format!("invalid --since value: {e}"))
                );
                return 1;
            }
        },
        None => None,
    };

    let Some(log_path) = tirith_core::audit::audit_log_path() else {
        eprintln!("tirith: trust audit: cannot resolve audit log path (no data dir)");
        return 1;
    };

    if !log_path.exists() {
        if json {
            // Same envelope shape as the normal path so consumers never special-case
            // "no log yet": `entries` always an array, `skipped_lines` always present.
            let _ = print_json(&serde_json::json!({"entries": [], "skipped_lines": 0_usize}));
        } else {
            eprintln!(
                "{}",
                trust_error_line(
                    "audit",
                    &format!("no audit log yet at {}", log_path.display())
                )
            );
        }
        return 0;
    }

    // Reuse the superset reader so missing fields on older entries parse cleanly.
    let result = match tirith_core::audit_aggregator::read_log(&log_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "{}",
                trust_error_line(
                    "audit",
                    &format!("cannot read audit log at {}: {e}", log_path.display())
                )
            );
            return 1;
        }
    };

    // Surface malformed-line skips so a corrupted log isn't invisible to an
    // operator chasing a missing entry. JSON shape includes it in the envelope below.
    if result.skipped_lines > 0 && !json {
        eprintln!(
            "{}",
            trust_error_line(
                "audit",
                &format!(
                    "skipped {} malformed audit log line(s) at {}",
                    result.skipped_lines,
                    log_path.display()
                )
            )
        );
    }

    #[derive(Serialize)]
    struct TrustAuditRow {
        timestamp: String,
        action: String,
        scope: String,
        pattern: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        rule_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        ttl_expires: Option<String>,
    }

    let mut rows: Vec<TrustAuditRow> = Vec::new();
    for entry in result.records {
        if entry.entry_type != "trust_change" {
            continue;
        }
        if let Some(cutoff_ts) = cutoff {
            if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&entry.timestamp) {
                if ts.to_utc() < cutoff_ts {
                    continue;
                }
            }
        }
        rows.push(TrustAuditRow {
            timestamp: entry.timestamp,
            action: entry.trust_action.unwrap_or_else(|| "?".to_string()),
            scope: entry.trust_scope.unwrap_or_else(|| "?".to_string()),
            pattern: entry.trust_pattern.unwrap_or_default(),
            rule_id: entry.trust_rule_id,
            ttl_expires: entry.trust_ttl_expires,
        });
    }

    if json {
        // Skipped-line count lets a JSON consumer detect a corrupted log without parsing stderr.
        return print_json(&serde_json::json!({
            "entries": rows,
            "skipped_lines": result.skipped_lines,
        }));
    }

    if rows.is_empty() {
        eprintln!("tirith: trust audit: no trust-store mutations recorded");
        return 0;
    }
    println!("{:<26} {:<8} {:<6} pattern", "timestamp", "action", "scope");
    for r in &rows {
        let rule_suffix = match &r.rule_id {
            Some(rid) => format!("  [rule: {rid}]"),
            None => String::new(),
        };
        println!(
            "{:<26} {:<8} {:<6} {}{}",
            human(&r.timestamp),
            human(&r.action),
            human(&r.scope),
            human(&r.pattern),
            human(&rule_suffix)
        );
    }
    0
}

/// Parse a relative-duration string (`7d`, `24h`, `15m`) into the UTC
/// timestamp that the duration is "ago from now".
fn parse_relative_duration(s: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let (num_str, unit) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| format!("missing unit suffix (use e.g. '7d', '24h', '15m'): {s}"))?,
    );
    let n: i64 = num_str
        .parse()
        .map_err(|_| format!("not a number: {num_str:?}"))?;
    let seconds = match unit {
        "d" => n.checked_mul(86_400),
        "h" => n.checked_mul(3_600),
        "m" => n.checked_mul(60),
        "s" => Some(n),
        other => {
            return Err(format!(
                "unknown duration unit {other:?} (use 'd', 'h', 'm', or 's')",
            ))
        }
    }
    .ok_or_else(|| format!("duration overflow: {s}"))?;
    Ok(chrono::Utc::now() - chrono::Duration::seconds(seconds))
}

/// `tirith trust diff` — show what changed in the trust set since the previous
/// recorded snapshot.
pub fn diff(json: bool) -> i32 {
    let (history, history_read_error) = load_trust_history();
    let current = current_trust_snapshot();

    // Baseline = the literal last recorded snapshot (not "last that differs"),
    // which keeps repeated `trust diff` calls idempotent.
    let baseline = history.last();

    let report = match baseline {
        None => TrustDiffReport {
            baseline_recorded_at: None,
            added: Vec::new(),
            removed: Vec::new(),
            unchanged: true,
            // A history file that exists but could not be read must not be
            // reported as "first observation" — surface the read failure.
            note: Some(history_read_error.clone().unwrap_or_else(|| {
                "No earlier trust snapshot to compare against — this is the first \
                 observation. Run a 'tirith trust' command again later to build a \
                 diff trail."
                    .to_string()
            })),
        },
        Some(base) => {
            let base_set: std::collections::BTreeSet<&String> = base.entries.iter().collect();
            let cur_set: std::collections::BTreeSet<&String> = current.entries.iter().collect();

            let added: Vec<DiffEntry> = cur_set
                .difference(&base_set)
                .map(|k| diff_entry_of(k))
                .collect();
            let removed: Vec<DiffEntry> = base_set
                .difference(&cur_set)
                .map(|k| diff_entry_of(k))
                .collect();
            let unchanged = added.is_empty() && removed.is_empty();
            TrustDiffReport {
                baseline_recorded_at: Some(base.recorded_at.clone()),
                added,
                removed,
                unchanged,
                note: None,
            }
        }
    };

    // Record the current snapshot AFTER computing the diff so the next `diff`
    // has a fresh baseline.
    record_trust_snapshot(&current);

    if json {
        return print_json(&report);
    }

    match &report.baseline_recorded_at {
        Some(ts) => println!("trust diff (since {})", human(ts)),
        None => println!("trust diff"),
    }
    if let Some(note) = &report.note {
        println!("  note: {}", human_multiline(note));
        return 0;
    }
    if report.unchanged {
        println!("  no changes since the last snapshot");
        return 0;
    }
    if !report.added.is_empty() {
        println!("  added ({}):", report.added.len());
        for e in &report.added {
            let rule = e
                .rule_id
                .as_deref()
                .map(|r| format!(" [rule: {r}]"))
                .unwrap_or_default();
            println!(
                "    + {} ({}, {}){}",
                human(&e.pattern),
                human(&e.source),
                e.scope_kind.label(),
                human(&rule)
            );
        }
    }
    if !report.removed.is_empty() {
        println!("  removed ({}):", report.removed.len());
        for e in &report.removed {
            let rule = e
                .rule_id
                .as_deref()
                .map(|r| format!(" [rule: {r}]"))
                .unwrap_or_default();
            println!(
                "    - {} ({}, {}){}",
                human(&e.pattern),
                human(&e.source),
                e.scope_kind.label(),
                human(&rule)
            );
        }
    }
    0
}

/// Extract a hostname from a URL string for trust prompts.
fn extract_host(raw: &str) -> Option<String> {
    // Only trust url::Url when the input has a scheme — schemeless inputs
    // parse into unusable shapes.
    if raw.contains("://") {
        if let Ok(parsed) = url::Url::parse(raw) {
            return parsed.host_str().map(String::from);
        }
    }
    // Schemeless fallback: take the prefix up to the first '/'.
    let candidate = raw.split('/').next()?;
    let candidate = candidate.trim();
    if candidate.contains('.') && !candidate.contains(' ') {
        let host = if let Some((h, port)) = candidate.rsplit_once(':') {
            if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() {
                h
            } else {
                candidate
            }
        } else {
            candidate
        };
        Some(host.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn repo_trust_dir_refuses_a_symlinked_tirith_component() {
        use std::os::unix::fs::symlink;

        // The root itself is opened O_NOFOLLOW as well, which costs nothing:
        // both callers derive it from find_repo_root(None) -> current_dir(),
        // and getcwd() never returns a path with symlink components.
        let holder = tempfile::tempdir().unwrap();
        let root = holder.path().join("checkout");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join(".tirith")).unwrap();
        open_repo_trust_dir(&root.join(".tirith").join("trust.json"), false)
            .expect("an ordinary repository root opens");

        // The component that carries repository content refuses a symlink.
        let hostile = holder.path().join("hostile");
        std::fs::create_dir(&hostile).unwrap();
        let swapped = holder.path().join("swapped");
        std::fs::create_dir(&swapped).unwrap();
        symlink(&hostile, swapped.join(".tirith")).unwrap();
        let error = open_repo_trust_dir(&swapped.join(".tirith").join("trust.json"), false)
            .expect_err("a symlinked .tirith component must be refused");
        assert!(error.contains("symlinked"), "unexpected error: {error}");
    }

    #[test]
    fn test_parse_ttl_days() {
        let result = parse_ttl("7d");
        assert!(result.is_ok());
        let expiry = chrono::DateTime::parse_from_rfc3339(&result.unwrap()).unwrap();
        let expected_min = chrono::Utc::now() + chrono::Duration::days(6);
        assert!(expiry > expected_min);
    }

    #[test]
    fn test_parse_ttl_hours() {
        let result = parse_ttl("1h");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_ttl_minutes() {
        let result = parse_ttl("30m");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_ttl_invalid() {
        assert!(parse_ttl("").is_err());
        assert!(parse_ttl("0d").is_err());
        assert!(parse_ttl("abc").is_err());
        assert!(parse_ttl("7x").is_err());
    }

    #[test]
    fn test_default_ttl_parses() {
        // The compiled-in default must always be a valid TTL.
        assert!(parse_ttl(DEFAULT_TTL).is_ok());
    }

    #[test]
    fn test_is_expired_no_ttl() {
        let entry = TrustEntry {
            pattern: "example.com".to_string(),
            rule_id: None,
            ttl_expires: None,
            added: chrono::Utc::now().to_rfc3339(),
            source: "cli".to_string(),
            reason: None,
        };
        assert!(!is_expired(&entry));
    }

    #[test]
    fn test_is_expired_future() {
        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        let entry = TrustEntry {
            pattern: "example.com".to_string(),
            rule_id: None,
            ttl_expires: Some(future.to_rfc3339()),
            added: chrono::Utc::now().to_rfc3339(),
            source: "cli".to_string(),
            reason: None,
        };
        assert!(!is_expired(&entry));
    }

    #[test]
    fn test_is_expired_past() {
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        let entry = TrustEntry {
            pattern: "example.com".to_string(),
            rule_id: None,
            ttl_expires: Some(past.to_rfc3339()),
            added: chrono::Utc::now().to_rfc3339(),
            source: "cli".to_string(),
            reason: None,
        };
        assert!(is_expired(&entry));
    }

    #[test]
    fn test_is_expired_unparseable_ttl_is_not_expired() {
        // A malformed timestamp must never silently revoke trust.
        let entry = TrustEntry {
            pattern: "example.com".to_string(),
            rule_id: None,
            ttl_expires: Some("not-a-timestamp".to_string()),
            added: chrono::Utc::now().to_rfc3339(),
            source: "cli".to_string(),
            reason: None,
        };
        assert!(!is_expired(&entry));
    }

    #[test]
    fn test_validate_pattern_empty() {
        let policy = tirith_core::policy::Policy::default();
        assert!(validate_pattern("", &policy).is_err());
    }

    #[test]
    fn test_validate_pattern_control_chars() {
        let policy = tirith_core::policy::Policy::default();
        assert!(validate_pattern("hello\x00world", &policy).is_err());
        assert!(validate_pattern("hello\x01world", &policy).is_err());
    }

    #[test]
    fn test_validate_pattern_rejects_tab_and_deceptive_unicode() {
        let policy = tirith_core::policy::Policy::default();
        assert!(validate_pattern("hello\tworld", &policy).is_err());
        assert!(validate_pattern("hello\u{202e}world", &policy).is_err());
        assert!(validate_pattern("hello\u{200b}world", &policy).is_err());
    }

    #[test]
    fn test_validate_pattern_blocklisted() {
        let policy = tirith_core::policy::Policy {
            blocklist: vec!["evil.com".to_string()],
            ..Default::default()
        };
        assert!(validate_pattern("evil.com", &policy).is_err());
    }

    #[test]
    fn test_validate_pattern_ok() {
        let policy = tirith_core::policy::Policy::default();
        assert!(validate_pattern("example.com", &policy).is_ok());
    }

    #[test]
    fn test_extract_host_full_url() {
        assert_eq!(
            extract_host("https://example.com/path"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_host_schemeless() {
        assert_eq!(
            extract_host("example.com/path"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_host_with_port() {
        assert_eq!(
            extract_host("example.com:8080/path"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_extract_host_no_dot() {
        assert_eq!(extract_host("localhost"), None);
    }

    #[test]
    fn test_store_roundtrip() {
        let _global = crate::cli::test_harness::ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");

        let store = TrustStore {
            version: 1,
            entries: vec![TrustEntry {
                pattern: "example.com".to_string(),
                rule_id: Some("shortened_url".to_string()),
                ttl_expires: None,
                added: "2026-04-03T12:00:00Z".to_string(),
                source: "cli".to_string(),
                reason: Some("internal mirror".to_string()),
            }],
        };

        write_store(&path, &store).unwrap();
        let loaded = load_store(&path).unwrap();

        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].pattern, "example.com");
        assert_eq!(loaded.entries[0].rule_id.as_deref(), Some("shortened_url"));
        assert_eq!(loaded.entries[0].reason.as_deref(), Some("internal mirror"));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn repo_store_roundtrip_is_atomic_and_leaves_no_temp_files() {
        let _global = crate::cli::test_harness::ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(".tirith/trust.json");
        assert!(load_repo_store(&path).unwrap().entries.is_empty());
        let store = TrustStore {
            version: 1,
            entries: vec![TrustEntry {
                pattern: "https://example.com/install.sh".into(),
                rule_id: None,
                ttl_expires: None,
                added: "2026-07-31T00:00:00Z".into(),
                source: "cli".into(),
                reason: None,
            }],
        };
        write_repo_store(&path, &store).unwrap();
        assert_eq!(load_repo_store(&path).unwrap().entries.len(), 1);
        write_repo_store(&path, &TrustStore::default()).unwrap();
        assert!(load_repo_store(&path).unwrap().entries.is_empty());
        let names: Vec<_> = fs::read_dir(root.path().join(".tirith"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("trust.json")]);
    }

    #[cfg(unix)]
    #[test]
    fn repo_store_rejects_symlinked_directory_component() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_store = outside.path().join("trust.json");
        fs::write(&outside_store, r#"{"version":1,"entries":[]}"#).unwrap();
        symlink(outside.path(), root.path().join(".tirith")).unwrap();
        let path = root.path().join(".tirith/trust.json");
        let before = fs::read(&outside_store).unwrap();

        assert!(load_repo_store(&path).is_err());
        assert!(write_repo_store(&path, &TrustStore::default()).is_err());
        assert_eq!(fs::read(&outside_store).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn repo_store_rejects_symlinked_destination() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), r#"{"version":1,"entries":[]}"#).unwrap();
        fs::create_dir(root.path().join(".tirith")).unwrap();
        let path = root.path().join(".tirith/trust.json");
        symlink(outside.path(), &path).unwrap();
        let before = fs::read(outside.path()).unwrap();

        assert!(load_repo_store(&path).is_err());
        assert!(write_repo_store(&path, &TrustStore::default()).is_err());
        assert_eq!(fs::read(outside.path()).unwrap(), before);
    }

    #[cfg(windows)]
    #[test]
    fn repo_store_rejects_windows_reparse_directory_component() {
        use std::os::windows::fs::symlink_dir;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_store = outside.path().join("trust.json");
        fs::write(&outside_store, r#"{"version":1,"entries":[]}"#).unwrap();
        if let Err(error) = symlink_dir(outside.path(), root.path().join(".tirith")) {
            if error.kind() == io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(1314)
            {
                return;
            }
            panic!("cannot create Windows directory symlink fixture: {error}");
        }
        let path = root.path().join(".tirith/trust.json");
        let before = fs::read(&outside_store).unwrap();

        assert!(load_repo_store(&path).is_err());
        assert!(write_repo_store(&path, &TrustStore::default()).is_err());
        assert_eq!(fs::read(&outside_store).unwrap(), before);
    }

    #[cfg(windows)]
    #[test]
    fn repo_store_rejects_windows_reparse_destination() {
        use std::os::windows::fs::symlink_file;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), r#"{"version":1,"entries":[]}"#).unwrap();
        fs::create_dir(root.path().join(".tirith")).unwrap();
        let path = root.path().join(".tirith/trust.json");
        if let Err(error) = symlink_file(outside.path(), &path) {
            if error.kind() == io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(1314)
            {
                return;
            }
            panic!("cannot create Windows file symlink fixture: {error}");
        }
        let before = fs::read(outside.path()).unwrap();

        assert!(load_repo_store(&path).is_err());
        assert!(write_repo_store(&path, &TrustStore::default()).is_err());
        assert_eq!(fs::read(outside.path()).unwrap(), before);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn repo_store_rejects_oversized_and_non_regular_files() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(".tirith")).unwrap();
        let path = root.path().join(".tirith/trust.json");
        fs::write(&path, vec![b'x'; TRUST_STORE_MAX_BYTES as usize + 1]).unwrap();
        assert!(load_repo_store(&path).is_err());

        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(load_repo_store(&path).is_err());
        assert!(write_repo_store(&path, &TrustStore::default()).is_err());
    }

    #[cfg(all(not(unix), not(windows)))]
    #[test]
    fn repo_store_is_empty_when_absent_and_mutation_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(".tirith/trust.json");
        assert!(load_repo_store(&path).unwrap().entries.is_empty());
        fs::create_dir(path.parent().unwrap()).unwrap();
        assert!(load_repo_store(&path).unwrap().entries.is_empty());
        assert!(write_repo_store(&path, &TrustStore::default()).is_err());
        assert!(!path.exists());

        fs::write(&path, br#"{"version":1,"entries":[]}"#).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(load_repo_store(&path).is_err());
        assert!(write_repo_store(&path, &TrustStore::default()).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn human_trust_fields_strip_terminal_forgery_but_json_stays_raw() {
        let raw = "safe\u{1b}]52;c;Y2xpcA\u{7}\u{1b}[2J\nFORGED\u{202e}\u{200b}";
        let one_line = human(raw);
        let multiline = human_multiline(raw);
        for rendered in [&one_line, &multiline] {
            assert!(!rendered.contains('\u{1b}'));
            assert!(!rendered.contains('\u{202e}'));
            assert!(!rendered.contains('\u{200b}'));
        }
        assert!(!one_line.contains('\n'));
        assert!(multiline.contains("\n  FORGED"));

        let structured = serde_json::to_string(&serde_json::json!({"pattern": raw})).unwrap();
        let decoded: serde_json::Value = serde_json::from_str(&structured).unwrap();
        assert_eq!(decoded["pattern"], raw);
        assert!(
            !structured.contains('\u{1b}'),
            "JSON must escape raw ESC bytes"
        );
    }

    fn assert_safe_single_line(rendered: &str) {
        for forbidden in ['\u{1b}', '\u{7}', '\u{202e}', '\u{200b}'] {
            assert!(
                !rendered.contains(forbidden),
                "forbidden terminal/deception character {forbidden:?} survived in {rendered:?}"
            );
        }
        assert!(
            !rendered.contains('\n'),
            "forged line survived: {rendered:?}"
        );
        assert!(!rendered.contains('\r'), "bare CR survived: {rendered:?}");
    }

    #[test]
    fn hostile_scope_action_and_prompt_are_safe_at_the_final_sink() {
        let hostile = "repo\u{1b}]52;c;Y2xpcA\u{7}\u{1b}[2J\nFORGED\u{202e}\u{200b}";
        let scope_line = unknown_scope_line(hostile, hostile, "'user', 'repo', or 'all'");
        let prompt = trust_prompt_line(hostile);
        assert_safe_single_line(&scope_line);
        assert_safe_single_line(&prompt);
        assert_eq!(
            unknown_scope_line("list", "staging", "'user', 'repo', or 'all'"),
            "tirith: trust list: unknown scope 'staging' (use 'user', 'repo', or 'all')"
        );
        assert_eq!(
            trust_prompt_line("example.com"),
            "Trust example.com? [y/N/r(rule-scoped)/t(temporary 7d)] "
        );
    }

    #[cfg(unix)]
    #[test]
    fn corrupt_store_error_sanitizes_hostile_path_and_parser_diagnostic_at_sink() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("trust\u{1b}]52;c;Y2xpcA\u{7}\nFORGED\u{202e}\u{200b}.json");
        fs::write(&path, b"{ definitely-not-json").unwrap();

        let error = load_store(&path).unwrap_err();
        let rendered = trust_error_line("list", &error);
        assert_safe_single_line(&rendered);
        assert!(rendered.contains("tirith: trust list: corrupt trust store at"));
        assert!(rendered.contains("definitely-not-json") || rendered.contains("key"));
    }

    #[test]
    fn test_load_legacy_store_without_reason() {
        // An older trust.json has no `reason` field — it must still load and
        // deserialize `reason` as None (backward compatibility).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");
        let legacy = r#"{
  "version": 1,
  "entries": [
    {
      "pattern": "old.example.com",
      "added": "2026-01-01T00:00:00Z",
      "source": "cli"
    }
  ]
}"#;
        fs::write(&path, legacy).unwrap();
        let loaded = load_store(&path).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].pattern, "old.example.com");
        assert!(loaded.entries[0].reason.is_none());
        assert!(loaded.entries[0].ttl_expires.is_none());
        // A legacy entry with no TTL is treated as permanent — never expired.
        assert!(!is_expired(&loaded.entries[0]));
    }

    #[test]
    fn test_gc_removes_expired() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.json");

        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        let future = chrono::Utc::now() + chrono::Duration::hours(1);

        let store = TrustStore {
            version: 1,
            entries: vec![
                TrustEntry {
                    pattern: "expired.com".to_string(),
                    rule_id: None,
                    ttl_expires: Some(past.to_rfc3339()),
                    added: chrono::Utc::now().to_rfc3339(),
                    source: "cli".to_string(),
                    reason: None,
                },
                TrustEntry {
                    pattern: "valid.com".to_string(),
                    rule_id: None,
                    ttl_expires: Some(future.to_rfc3339()),
                    added: chrono::Utc::now().to_rfc3339(),
                    source: "cli".to_string(),
                    reason: None,
                },
                TrustEntry {
                    pattern: "forever.com".to_string(),
                    rule_id: None,
                    ttl_expires: None,
                    added: chrono::Utc::now().to_rfc3339(),
                    source: "cli".to_string(),
                    reason: None,
                },
            ],
        };

        write_store(&path, &store).unwrap();

        let mut loaded = load_store(&path).unwrap();
        loaded.entries.retain(|e| !is_expired(e));
        write_store(&path, &loaded).unwrap();

        let after = load_store(&path).unwrap();
        assert_eq!(after.entries.len(), 2);
        assert!(after.entries.iter().any(|e| e.pattern == "valid.com"));
        assert!(after.entries.iter().any(|e| e.pattern == "forever.com"));
        assert!(!after.entries.iter().any(|e| e.pattern == "expired.com"));
    }

    // --- scope classification ---------------------------------------------

    #[test]
    fn test_classify_scope_exact_url() {
        assert_eq!(
            classify_scope("https://example.com/install.sh"),
            ScopeKind::Exact
        );
        assert_eq!(
            classify_scope("raw.githubusercontent.com/org/repo/main/get.sh"),
            ScopeKind::Exact
        );
    }

    #[test]
    fn test_classify_scope_domain() {
        assert_eq!(classify_scope("github.com"), ScopeKind::Domain);
        assert_eq!(classify_scope("api.github.com"), ScopeKind::Domain);
        assert_eq!(classify_scope("get.docker.com"), ScopeKind::Domain);
    }

    #[test]
    fn test_classify_scope_wildcard() {
        assert_eq!(classify_scope("*.example.com"), ScopeKind::Wildcard);
        assert_eq!(classify_scope("*.internal.corp.net"), ScopeKind::Wildcard);
    }

    #[test]
    fn test_classify_scope_bare_tld() {
        assert_eq!(classify_scope("com"), ScopeKind::BareTld);
        assert_eq!(classify_scope("dev"), ScopeKind::BareTld);
        assert_eq!(classify_scope("io"), ScopeKind::BareTld);
        assert_eq!(classify_scope("zip"), ScopeKind::BareTld);
        assert_eq!(classify_scope("co.uk"), ScopeKind::BareTld);
        // A wildcard over a bare TLD is the worst case — still bare-TLD.
        assert_eq!(classify_scope("*.com"), ScopeKind::BareTld);
    }

    #[test]
    fn test_classify_scope_substring() {
        // A non-domain, non-TLD bare token is a substring fragment.
        assert_eq!(classify_scope("get-pip"), ScopeKind::Substring);
    }

    #[test]
    fn test_scope_kind_broad_and_dangerous() {
        assert!(!ScopeKind::Exact.is_broad());
        assert!(ScopeKind::Substring.is_broad());
        assert!(ScopeKind::Domain.is_broad());
        assert!(ScopeKind::Wildcard.is_broad());
        assert!(ScopeKind::BareTld.is_broad());

        assert!(!ScopeKind::Domain.is_dangerous());
        assert!(ScopeKind::Wildcard.is_dangerous());
        assert!(ScopeKind::BareTld.is_dangerous());
    }

    #[test]
    fn test_humanize_expiry() {
        assert_eq!(humanize_expiry(None), None);
        let future = chrono::Utc::now() + chrono::Duration::days(6) + chrono::Duration::hours(2);
        let h = humanize_expiry(Some(&future.to_rfc3339())).unwrap();
        assert!(h.starts_with("in 6d"), "got {h}");
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        assert_eq!(
            humanize_expiry(Some(&past.to_rfc3339())),
            Some("expired".to_string())
        );
    }

    // --- trust diff snapshot keys -----------------------------------------

    #[test]
    fn test_row_key_roundtrip() {
        let row = make_row(
            "github.com".to_string(),
            Some("shortened_url".to_string()),
            "trust-user".to_string(),
            None,
            false,
        );
        let key = row_key(&row);
        let (source, pattern, rule) = split_key(&key);
        assert_eq!(source, "trust-user");
        assert_eq!(pattern, "github.com");
        assert_eq!(rule.as_deref(), Some("shortened_url"));
    }

    #[test]
    fn test_row_key_roundtrip_no_rule() {
        let row = make_row(
            "example.com".to_string(),
            None,
            "policy".to_string(),
            None,
            false,
        );
        let (source, pattern, rule) = split_key(&row_key(&row));
        assert_eq!(source, "policy");
        assert_eq!(pattern, "example.com");
        assert_eq!(rule, None);
    }

    #[test]
    fn test_diff_set_logic() {
        // Baseline has A and B; current has B and C.
        let base: std::collections::BTreeSet<&str> = ["A", "B"].into_iter().collect();
        let cur: std::collections::BTreeSet<&str> = ["B", "C"].into_iter().collect();
        let added: Vec<_> = cur.difference(&base).collect();
        let removed: Vec<_> = base.difference(&cur).collect();
        assert_eq!(added, vec![&"C"]);
        assert_eq!(removed, vec![&"A"]);
    }

    /// Plant a `last_trigger.json` under a temp data dir and run `f` with
    /// `data_dir()` pointed at it. Holds `ENV_LOCK` (process-global env mutation)
    /// and restores `XDG_DATA_HOME` / `APPDATA` on Drop. `data_dir()` honors
    /// `XDG_DATA_HOME` on Unix but `%APPDATA%` on Windows (etcetera), so set both.
    fn with_seeded_last_trigger<F: FnOnce()>(json: &str, f: F) {
        use crate::cli::test_harness::{EnvGuard, ENV_LOCK};
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().expect("tempdir");
        let _xdg = EnvGuard::set("XDG_DATA_HOME", dir.path());
        let _appdata = EnvGuard::set("APPDATA", dir.path());

        let tirith_data = dir.path().join("tirith");
        fs::create_dir_all(&tirith_data).expect("create data dir");
        fs::write(tirith_data.join("last_trigger.json"), json).expect("write last_trigger.json");

        f();
    }

    /// Same env isolation, but plant NO `last_trigger.json` (empty data dir).
    fn with_empty_data_dir<F: FnOnce()>(f: F) {
        use crate::cli::test_harness::{EnvGuard, ENV_LOCK};
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().expect("tempdir");
        let _xdg = EnvGuard::set("XDG_DATA_HOME", dir.path());
        let _appdata = EnvGuard::set("APPDATA", dir.path());
        f();
    }

    /// A full-URL evidence target is suggested NARROW: a copy/paste-ready
    /// `tirith trust add '<url>' --rule <rule_id> --ttl 30d` line (URL
    /// single-quoted) with NO `--broad`.
    #[test]
    fn from_last_trigger_suggests_narrow_url_without_broad() {
        let json = r#"{
            "rule_ids": ["shortened_url"],
            "severity": "high",
            "command_redacted": "curl https://example.com/install.sh | sh",
            "timestamp": "2026-06-10T00:00:00Z",
            "findings": [
                {
                    "rule_id": "shortened_url",
                    "title": "Shortened URL",
                    "evidence": [
                        { "raw": "https://example.com/install.sh" }
                    ]
                }
            ]
        }"#;

        with_seeded_last_trigger(json, || {
            // read_last_trigger prefers the FULL URL as the target and pairs it
            // with THAT finding's rule_id.
            let pairs = read_last_trigger().expect("read_last_trigger");
            assert_eq!(
                pairs,
                vec![(
                    "https://example.com/install.sh".to_string(),
                    Some("shortened_url".to_string())
                )]
            );

            // The suggested line is the narrow, single-quoted, no-`--broad` form.
            let lines = suggestion_lines(&pairs);
            let expected =
                "tirith trust add 'https://example.com/install.sh' --rule shortened_url --ttl 30d";
            assert!(
                lines.iter().any(|l| l == expected),
                "expected narrow single-quoted URL suggestion {expected:?}, got: {lines:?}"
            );
            assert!(
                lines.iter().all(|l| !l.contains("--broad")),
                "a full-URL target must NOT be suggested with --broad: {lines:?}"
            );

            // The real entry point runs clean in suggest (print-only) mode.
            assert_eq!(from_last_trigger(false), 0);
        });
    }

    /// A bare-domain target (only `raw_host`, no URL) needs `--broad` because
    /// `trust add` rejects broad scopes without the opt-in.
    #[test]
    fn from_last_trigger_bare_domain_gets_broad() {
        let json = r#"{
            "rule_ids": ["homograph"],
            "findings": [
                { "rule_id": "homograph", "title": "Homograph", "evidence": [ { "raw_host": "example.com" } ] }
            ]
        }"#;

        with_seeded_last_trigger(json, || {
            let pairs = read_last_trigger().expect("read_last_trigger");
            assert_eq!(
                pairs,
                vec![("example.com".to_string(), Some("homograph".to_string()))]
            );

            let lines = suggestion_lines(&pairs);
            let expected = "tirith trust add 'example.com' --broad --rule homograph --ttl 30d";
            assert!(
                lines.iter().any(|l| l == expected),
                "expected single-quoted bare-domain suggestion with --broad {expected:?}, got: {lines:?}"
            );
        });
    }

    /// F2 (P1): a MULTI-finding trigger must pair each target with ITS OWN
    /// finding's rule_id — never the cartesian product of all targets × all
    /// top-level `rule_ids`. Here finding A (rule `shortened_url`) fired for
    /// `https://a.example/x`, finding B (rule `plain_http_to_sink`) for
    /// `http://b.example/y`. The wrong (old) behavior would suggest trusting A
    /// under `plain_http_to_sink` and B under `shortened_url`.
    #[test]
    fn from_last_trigger_pairs_each_target_with_its_own_rule() {
        let json = r#"{
            "rule_ids": ["shortened_url", "plain_http_to_sink"],
            "findings": [
                {
                    "rule_id": "shortened_url",
                    "title": "Shortened URL",
                    "evidence": [ { "raw": "https://a.example/x" } ]
                },
                {
                    "rule_id": "plain_http_to_sink",
                    "title": "Plain HTTP",
                    "evidence": [ { "raw": "http://b.example/y" } ]
                }
            ]
        }"#;

        with_seeded_last_trigger(json, || {
            let pairs = read_last_trigger().expect("read_last_trigger");
            assert_eq!(
                pairs,
                vec![
                    (
                        "https://a.example/x".to_string(),
                        Some("shortened_url".to_string())
                    ),
                    (
                        "http://b.example/y".to_string(),
                        Some("plain_http_to_sink".to_string())
                    ),
                ],
                "each target must keep its own finding's rule_id (no cartesian product)"
            );

            let lines = suggestion_lines(&pairs);
            // Exactly the two correct pairings — and NO cross-paired line.
            assert!(
                lines.iter().any(|l| l
                    == "tirith trust add 'https://a.example/x' --rule shortened_url --ttl 30d"),
                "A must pair with shortened_url: {lines:?}"
            );
            assert!(
                lines.iter().any(|l| l
                    == "tirith trust add 'http://b.example/y' --rule plain_http_to_sink --ttl 30d"),
                "B must pair with plain_http_to_sink: {lines:?}"
            );
            assert_eq!(
                lines.len(),
                2,
                "exactly two lines, no cartesian product: {lines:?}"
            );
            assert!(
                !lines.iter().any(
                    |l| l.contains("'https://a.example/x'") && l.contains("plain_http_to_sink")
                ),
                "A must NOT be cross-paired with plain_http_to_sink: {lines:?}"
            );
            assert!(
                !lines
                    .iter()
                    .any(|l| l.contains("'http://b.example/y'") && l.contains("shortened_url")),
                "B must NOT be cross-paired with shortened_url: {lines:?}"
            );
        });
    }

    /// `--apply` must fail loud on a PARTIAL apply: if `add()` rejects even one
    /// entry, the command exits non-zero instead of 0, so a partial result never
    /// masquerades as a clean success. Here the first finding's target is a valid
    /// narrow URL (`add()` accepts it -> stored), while the second's `raw_host`
    /// carries a control byte (0x07 BEL) that `validate_pattern` rejects ->
    /// `add()` returns 1 for that entry. Both reach the apply loop, so one
    /// succeeds and one fails: the overall exit must be 1.
    #[test]
    fn from_last_trigger_apply_partial_failure_returns_one() {
        let json = "{\
            \"rule_ids\": [\"shortened_url\", \"homograph\"],\
            \"findings\": [\
                {\
                    \"rule_id\": \"shortened_url\",\
                    \"title\": \"Shortened URL\",\
                    \"evidence\": [ { \"raw\": \"https://good.example/install.sh\" } ]\
                },\
                {\
                    \"rule_id\": \"homograph\",\
                    \"title\": \"Homograph\",\
                    \"evidence\": [ { \"raw_host\": \"evil.example\\u0007\" } ]\
                }\
            ]\
        }";

        with_seeded_last_trigger(json, || {
            // Both targets survive extraction: the good URL and the control-char
            // host (raw_host is pushed verbatim, no validation at read time).
            let pairs = read_last_trigger().expect("read_last_trigger");
            assert_eq!(
                pairs,
                vec![
                    (
                        "https://good.example/install.sh".to_string(),
                        Some("shortened_url".to_string())
                    ),
                    (
                        "evil.example\u{0007}".to_string(),
                        Some("homograph".to_string())
                    ),
                ],
                "both entries must reach the apply loop so one can succeed and one fail"
            );

            // Suggest (print-only) still exits 0 -- it never calls `add()`.
            assert_eq!(from_last_trigger(false), 0);

            // --apply: the good URL is stored, the control-char host is rejected
            // by `validate_pattern` inside `add()`. A partial apply must exit 1.
            assert_eq!(
                from_last_trigger(true),
                1,
                "a partial apply (one entry rejected by add) must fail loud, not exit 0"
            );
        });
    }

    /// F1 (HIGH): the suggestion line is copy/paste-ready, so a hostile target
    /// carrying shell metacharacters must be single-quoted; a target that can't
    /// be safely quoted (newline) must NOT yield a runnable command.
    #[test]
    fn from_last_trigger_shell_quotes_hostile_target() {
        // `extract_host` is applied to a schemeless `raw`; use `raw_host` so the
        // hostile bytes survive verbatim into the suggested line.
        let json = r#"{
            "rule_ids": ["confusable_domain"],
            "findings": [
                {
                    "rule_id": "confusable_domain",
                    "title": "Confusable",
                    "evidence": [ { "raw_host": "evil.example/$(touch X)" } ]
                }
            ]
        }"#;
        with_seeded_last_trigger(json, || {
            let pairs = read_last_trigger().expect("read_last_trigger");
            let lines = suggestion_lines(&pairs);
            let line = lines
                .iter()
                .find(|l| l.contains("tirith trust add"))
                .expect("a suggestion line");
            assert!(
                line.contains("'evil.example/$(touch X)'"),
                "hostile target must be single-quoted so $(touch X) cannot execute: {line}"
            );
            assert!(
                !line.replace("'evil.example/$(touch X)'", "").contains("$("),
                "no bare $( may survive outside the quoted token: {line}"
            );
        });

        // A target with a newline cannot be single-quoted as one token → no
        // runnable command, just the safe manual-trust note.
        assert_eq!(
            format_add_line("evil.example/a\nrm -rf ~", Some("confusable_domain"), true),
            "# trust this target manually with `tirith trust add` \
             (it contains characters unsafe to embed in a suggested command)."
        );

        // ANSI/OSC and deceptive Unicode must never be silently stripped into a
        // different runnable trust command. The sink emits only the static,
        // non-runnable manual-review note.
        let osc = format_add_line(
            "evil.example/\u{1b}]0;pwned\u{7}\u{1b}[31m",
            Some("confusable_domain"),
            true,
        );
        assert_eq!(
            osc,
            "# trust this target manually with `tirith trust add` \
             (it contains characters unsafe to embed in a suggested command)."
        );
        assert_eq!(
            format_add_line(
                "evil.example/\u{202e}txt.exe\u{200b}",
                Some("confusable_domain"),
                true,
            ),
            "# trust this target manually with `tirith trust add` \
             (it contains characters unsafe to embed in a suggested command)."
        );
    }

    /// `last()`'s rule-scoped ("r") choice must trust a host under ONLY the
    /// rule(s) that fired for THAT host, never every top-level rule in the
    /// verdict. `rules_for_host` is the per-host lookup that branch uses; here
    /// finding A (rule `shortened_url`) fired for `a.example`, finding B (rule
    /// `plain_http_to_sink`) for `b.example`. The old `last()` would have added
    /// BOTH rules to BOTH hosts (over-broad). `rules_for_host` must return each
    /// host's own single rule.
    #[test]
    fn rules_for_host_returns_only_that_hosts_rules() {
        let val: serde_json::Value = serde_json::from_str(
            r#"{
            "rule_ids": ["shortened_url", "plain_http_to_sink"],
            "findings": [
                {
                    "rule_id": "shortened_url",
                    "title": "Shortened URL",
                    "evidence": [ { "raw": "https://a.example/x" } ]
                },
                {
                    "rule_id": "plain_http_to_sink",
                    "title": "Plain HTTP",
                    "evidence": [ { "raw": "http://b.example/y" } ]
                }
            ]
        }"#,
        )
        .unwrap();

        // The display loop / prompt key on the bare host (via `extract_host`).
        assert_eq!(rules_for_host(&val, "a.example"), vec!["shortened_url"]);
        assert_eq!(
            rules_for_host(&val, "b.example"),
            vec!["plain_http_to_sink"]
        );
        // A host that did not trigger gets no rules (falls back to global trust).
        assert!(rules_for_host(&val, "c.example").is_empty());
    }

    /// When ONE host triggers MULTIPLE rules, the rule-scoped choice must add
    /// each of that host's own rules (and de-dupe), not collapse to one.
    #[test]
    fn rules_for_host_returns_all_own_rules_deduped() {
        let val: serde_json::Value = serde_json::from_str(
            r#"{
            "rule_ids": ["shortened_url", "plain_http_to_sink", "homograph"],
            "findings": [
                {
                    "rule_id": "shortened_url",
                    "evidence": [ { "raw": "https://a.example/x" }, { "raw_host": "a.example" } ]
                },
                {
                    "rule_id": "plain_http_to_sink",
                    "evidence": [ { "raw": "http://a.example/y" } ]
                },
                {
                    "rule_id": "homograph",
                    "evidence": [ { "raw_host": "b.example" } ]
                }
            ]
        }"#,
        )
        .unwrap();

        // a.example fired on two distinct rules across its findings; both are
        // returned, de-duped despite the repeated `raw`/`raw_host` evidence.
        assert_eq!(
            rules_for_host(&val, "a.example"),
            vec!["shortened_url", "plain_http_to_sink"],
            "a host with multiple rules keeps all of its own rules, deduped"
        );
        // b.example's unrelated rule must NOT leak onto a.example.
        assert_eq!(rules_for_host(&val, "b.example"), vec!["homograph"]);
    }

    /// A finding with evidence but no `rule_id` yields a host with no rules, so
    /// the rule-scoped branch falls back to global trust for that host. (Mirrors
    /// the old "no rule IDs in last trigger" path, now scoped per-host.)
    #[test]
    fn rules_for_host_empty_when_finding_has_no_rule_id() {
        let val: serde_json::Value = serde_json::from_str(
            r#"{
            "findings": [
                { "title": "Mystery", "evidence": [ { "raw_host": "a.example" } ] }
            ]
        }"#,
        )
        .unwrap();
        assert!(rules_for_host(&val, "a.example").is_empty());
    }

    /// A missing/empty trigger is the common "nothing happened yet" case:
    /// `from_last_trigger` returns 0 (friendly note), not an error.
    #[test]
    fn from_last_trigger_missing_returns_zero() {
        with_empty_data_dir(|| {
            assert_eq!(from_last_trigger(false), 0);
            // read_last_trigger surfaces the no-trigger sentinel for callers.
            assert_eq!(
                read_last_trigger().unwrap_err(),
                "no recent trigger found".to_string()
            );
        });
    }

    /// The refactor must keep `last()` behavior identical: with no trigger on
    /// disk it still returns 1 (its non-interactive, stdin-free path).
    #[test]
    fn last_unchanged_without_trigger_returns_one() {
        with_empty_data_dir(|| {
            assert_eq!(last(), 1);
        });
    }
}
