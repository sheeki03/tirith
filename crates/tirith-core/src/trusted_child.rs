//! Trusted executable selection and bounded child-process supervision.
//!
//! Security-sensitive callers resolve an executable once, validate its absolute
//! identity, clear the ambient environment, and run it with explicit capture
//! limits. On Unix every child owns an anchored process group; on Windows every
//! child is created suspended, assigned to a kill-on-close Job Object, then
//! resumed. Completion, timeout, or output-flood cleanup therefore covers the
//! spawned Unix process group or Windows Job without risking numeric
//! process-group reuse. A Unix descendant that deliberately creates a new
//! session leaves that process-group boundary and is outside this trusted-child
//! contract.
//!
//! Unix embedding has one additional process-wide requirement: `SIGCHLD` must
//! retain its default disposition without `SA_NOCLDWAIT`, and no competing
//! waiter may reap a child owned by [`run`]. The supervisor checks the visible
//! disposition before spawning and again immediately before every numeric
//! signal, and revalidates direct-child ownership at the signal boundary. This
//! is the smallest portable anchor available on macOS and other Unix hosts
//! without a pidfd-like signal primitive. Code already executing in this same
//! process could still race the final check by changing signal state or calling
//! `waitpid`; such code already has Tirith's full process authority and is
//! outside the untrusted-child boundary.

use std::ffi::{OsStr, OsString};
use std::fmt;
#[cfg(any(target_os = "linux", not(unix)))]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
#[cfg(not(unix))]
use std::io::{Read as _, Seek as _};
#[cfg(target_os = "linux")]
use std::io::{Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
#[cfg(not(windows))]
use std::process::{Command, Stdio};
use std::sync::mpsc;
#[cfg(target_os = "linux")]
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(windows)]
mod windows;

#[cfg(any(target_os = "linux", not(unix)))]
use sha2::{Digest as _, Sha256};

/// Linux can bind a resolved executable to a private snapshot and fully sealed
/// anonymous launch descriptor before a security-sensitive caller performs
/// network I/O. The snapshot, descriptors, and temporary directory stay alive
/// together until every clone of [`TrustedExecutable`] is dropped.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct BoundExecutable {
    _directory: tempfile::TempDir,
    path: PathBuf,
    _file: File,
    sha256: [u8; 32],
    identity: UnixExecutableIdentity,
    /// Linux launches use this immutable, anonymous file description rather
    /// than reopening `path`. The complete seal set prevents another same-UID
    /// process from changing the bytes between verification and `execveat`.
    sealed_file: File,
    sealed_identity: UnixExecutableIdentity,
}

#[derive(Debug, Clone)]
pub struct TrustedExecutable {
    /// Absolute caller/PATH spelling retained for consumers that must preserve
    /// multicall or alias-sensitive invocation semantics. Trust and content
    /// binding always apply to the separately canonicalized `path`.
    invocation_path: PathBuf,
    path: PathBuf,
    #[cfg(unix)]
    identity: UnixExecutableIdentity,
    #[cfg(not(unix))]
    digest: [u8; 32],
    #[cfg(windows)]
    source: WindowsExecutableSource,
    #[cfg(windows)]
    provenance: WindowsTrustProvenance,
    #[cfg(target_os = "linux")]
    bound: Option<Arc<BoundExecutable>>,
}

impl PartialEq for TrustedExecutable {
    fn eq(&self, other: &Self) -> bool {
        if self.invocation_path != other.invocation_path || self.path != other.path {
            return false;
        }
        #[cfg(unix)]
        if self.identity != other.identity {
            return false;
        }
        #[cfg(not(unix))]
        if self.digest != other.digest {
            return false;
        }
        #[cfg(windows)]
        if self.source != other.source {
            return false;
        }
        #[cfg(windows)]
        if self.provenance != other.provenance {
            return false;
        }
        bound_state_eq(self, other)
    }
}

#[cfg(target_os = "linux")]
fn bound_state_eq(left: &TrustedExecutable, right: &TrustedExecutable) -> bool {
    match (&left.bound, &right.bound) {
        (None, None) => true,
        (Some(left), Some(right)) => left.path == right.path && left.sha256 == right.sha256,
        _ => false,
    }
}

#[cfg(not(target_os = "linux"))]
fn bound_state_eq(_: &TrustedExecutable, _: &TrustedExecutable) -> bool {
    true
}

impl Eq for TrustedExecutable {}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnixExecutableIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

/// How an absolute Windows executable was selected. The source is part of the
/// provenance decision: a PATH-discovered program needs installed provenance,
/// while a fixed absolute path/current image is explicit caller authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsExecutableSource {
    /// Caller supplied a fixed absolute path.
    ExplicitAbsolute,
    /// Program was selected from the process PATH.
    PathSearch,
    /// Program is the image already running this process.
    CurrentProcess,
    /// Caller selected from a fixed OS-owned candidate list.
    SystemCandidate,
}

/// Security-relevant owner class returned by the Windows ACL validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsOwnerClass {
    /// Owner SID matches the current process token's user.
    CurrentUser,
    /// Owner SID is LocalSystem.
    LocalSystem,
    /// Owner SID is the built-in Administrators group.
    Administrators,
    /// Owner SID is the Windows Modules Installer service.
    TrustedInstaller,
    /// Owner is present but outside the recognized provenance principals.
    Other,
}

/// Host facts consumed by the pure Windows trust policy. Keeping this decision
/// separate from Win32 collection makes every allow/deny branch host-testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsTrustFacts {
    /// A broad low-trust principal can replace the file or an ancestor.
    pub broad_write_access: bool,
    /// Owner of the executable itself.
    pub leaf_owner: WindowsOwnerClass,
    /// Every owner from the executable through its ancestor chain is recognized.
    pub owner_chain_trusted: bool,
    /// ACL and owner evidence establish a protected current-user install tree.
    ///
    /// The Windows collector derives this from the SAME ownership facts
    /// [`evaluate_windows_trust`] already requires before any source-specific
    /// branch runs (`owner_chain_trusted` plus a recognized `leaf_owner`), so at
    /// the `PathSearch` fallback it is true whenever that gate passed. In other
    /// words, an unsigned PATH executable outside a protected root is accepted
    /// on owner-chain evidence alone. `windows_provenance_is_system_helper_approved`
    /// still excludes [`WindowsTrustProvenance::SecureUserInstall`], so a
    /// security-sensitive helper does not inherit that acceptance. Narrowing
    /// this to independent install-tree evidence would refuse user-local
    /// installs (scoop, cargo, `%LOCALAPPDATA%\Programs`) that carry no
    /// signature, so it is a deliberate compatibility decision, not a cleanup.
    /// `windows_path_discovery_accepts_trusted_ownership_without_further_provenance`
    /// pins the current contract.
    pub secure_user_install: bool,
    /// Path is under a canonical Windows or Program Files root.
    pub protected_install_root: bool,
    /// Offline WinVerifyTrust policy accepted the image signature.
    pub authenticode_trusted: bool,
}

/// Provenance that authorized a Windows executable after ACL validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsTrustProvenance {
    /// Fixed absolute caller authority plus secure ownership.
    ExplicitAbsolute,
    /// Already-running image plus secure ownership.
    CurrentProcess,
    /// Fixed system candidate under a protected install root.
    SystemCandidate,
    /// Offline Authenticode verification authorized the image.
    Authenticode,
    /// Protected install root and owner chain authorized PATH selection.
    ProtectedInstall,
    /// Secure current-user installation authorized PATH selection.
    SecureUserInstall,
}

/// Decide whether collected Windows ACL/ownership/AuthentiCode evidence is
/// sufficient for the executable-selection source. Broadly writable paths are
/// never trusted, including when a file carries a valid signature: replacement
/// of the path would otherwise bypass the signature checked before launch.
pub fn evaluate_windows_trust(
    source: WindowsExecutableSource,
    facts: WindowsTrustFacts,
) -> Result<WindowsTrustProvenance, &'static str> {
    if facts.broad_write_access {
        return Err("executable or parent path grants broad write access");
    }
    if !facts.owner_chain_trusted || facts.leaf_owner == WindowsOwnerClass::Other {
        return Err("executable has an untrusted owner or ancestor owner");
    }
    match source {
        WindowsExecutableSource::ExplicitAbsolute => Ok(WindowsTrustProvenance::ExplicitAbsolute),
        WindowsExecutableSource::CurrentProcess => Ok(WindowsTrustProvenance::CurrentProcess),
        WindowsExecutableSource::SystemCandidate => {
            if facts.protected_install_root && facts.leaf_owner != WindowsOwnerClass::CurrentUser {
                Ok(WindowsTrustProvenance::SystemCandidate)
            } else if facts.authenticode_trusted {
                Ok(WindowsTrustProvenance::Authenticode)
            } else {
                Err("system candidate lacks protected-root or Authenticode provenance")
            }
        }
        WindowsExecutableSource::PathSearch => {
            if facts.authenticode_trusted {
                Ok(WindowsTrustProvenance::Authenticode)
            } else if facts.protected_install_root
                && facts.leaf_owner != WindowsOwnerClass::CurrentUser
            {
                Ok(WindowsTrustProvenance::ProtectedInstall)
            } else if facts.secure_user_install {
                Ok(WindowsTrustProvenance::SecureUserInstall)
            } else {
                Err("PATH executable lacks Authenticode or trusted install provenance")
            }
        }
    }
}

/// Whether already-collected Windows executable provenance is strong enough
/// for a security-sensitive helper selected from `PATH`. Authenticode binds the
/// image to a trusted publisher; protected-install provenance binds it to an
/// administrator-owned install root. A merely owner-only current-user install
/// remains replaceable by the same principal that controls the ambient PATH and
/// is therefore rejected at this boundary.
pub fn windows_provenance_is_system_helper_approved(provenance: WindowsTrustProvenance) -> bool {
    matches!(
        provenance,
        WindowsTrustProvenance::SystemCandidate
            | WindowsTrustProvenance::Authenticode
            | WindowsTrustProvenance::ProtectedInstall
    )
}

/// Pure Windows DACL access-mask classifier used by the platform collector.
/// Generic read includes `READ_CONTROL` and `SYNCHRONIZE`; neither is a mutation
/// right, so this intentionally checks only generic write and concrete replace /
/// metadata-write rights instead of intersecting a composite FILE_GENERIC_WRITE.
pub fn windows_access_mask_grants_replacement(mask: u32, leaf: bool) -> bool {
    const GENERIC_ALL: u32 = 0x1000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const DELETE: u32 = 0x0001_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const FILE_WRITE_DATA: u32 = 0x0000_0002;
    const FILE_APPEND_DATA: u32 = 0x0000_0004;
    const FILE_WRITE_EA: u32 = 0x0000_0010;
    const FILE_DELETE_CHILD: u32 = 0x0000_0040;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;

    let ownership_or_delete = GENERIC_ALL | DELETE | WRITE_DAC | WRITE_OWNER;
    let relevant = if leaf {
        ownership_or_delete
            | GENERIC_WRITE
            | FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_EA
            | FILE_DELETE_CHILD
            | FILE_WRITE_ATTRIBUTES
    } else {
        ownership_or_delete | FILE_DELETE_CHILD
    };
    mask & relevant != 0
}

#[derive(Debug)]
pub enum TrustedExecutableError {
    NotAbsolute(PathBuf),
    NotExecutable(PathBuf),
    NotFound(String),
    Untrusted { path: PathBuf, root: PathBuf },
    InvalidPath { path: PathBuf, reason: String },
}

impl fmt::Display for TrustedExecutableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAbsolute(path) => {
                write!(
                    f,
                    "trusted executable path is not absolute: {}",
                    path.display()
                )
            }
            Self::NotExecutable(path) => {
                write!(
                    f,
                    "trusted executable is not an executable file: {}",
                    path.display()
                )
            }
            Self::NotFound(name) => write!(f, "trusted executable not found: {name}"),
            Self::Untrusted { path, root } => write!(
                f,
                "untrusted executable {} is inside denied root {}",
                path.display(),
                root.display()
            ),
            Self::InvalidPath { path, reason } => {
                write!(f, "cannot validate executable {}: {reason}", path.display())
            }
        }
    }
}

impl std::error::Error for TrustedExecutableError {}

fn path_is_within(path: &Path, root: &Path) -> bool {
    #[cfg(windows)]
    {
        windows::path_is_within(path, root)
    }
    #[cfg(not(windows))]
    {
        path == root || path.starts_with(root)
    }
}

fn lexical_normalize(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() && !path.is_absolute() {
                    normalized.push(component.as_os_str());
                }
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

/// Return the denied root containing either the lexical selection path or any
/// filesystem-resolved prefix of it. Checking each existing prefix preserves
/// the origin evidence that full canonicalization loses when a symlink/reparse
/// point escapes the denied tree; it also resolves Windows 8.3 aliases.
fn denied_selection_origin(path: &Path, denied_roots: &[PathBuf]) -> Option<PathBuf> {
    let roots = denied_roots
        .iter()
        .map(|root| {
            let lexical = lexical_normalize(root);
            let canonical = root
                .canonicalize()
                .ok()
                .map(|canonical| lexical_normalize(&canonical));
            (root, lexical, canonical)
        })
        .collect::<Vec<_>>();
    let lexical_path = lexical_normalize(path);

    for (original, lexical_root, canonical_root) in &roots {
        if path_is_within(&lexical_path, lexical_root)
            || canonical_root
                .as_ref()
                .is_some_and(|root| path_is_within(&lexical_path, root))
        {
            return Some((*original).clone());
        }
    }

    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component.as_os_str());
        if !prefix.is_absolute() {
            continue;
        }
        let Ok(canonical_prefix) = prefix.canonicalize() else {
            continue;
        };
        let canonical_prefix = lexical_normalize(&canonical_prefix);
        for (original, lexical_root, canonical_root) in &roots {
            let resolved_root = canonical_root.as_ref().unwrap_or(lexical_root);
            if path_is_within(&canonical_prefix, resolved_root) {
                return Some((*original).clone());
            }
        }
    }
    None
}

impl TrustedExecutable {
    /// Validate an explicitly selected absolute executable. Symlinks are
    /// canonicalized for trust and content checks, while the selected absolute
    /// invocation path is retained separately for callers that must preserve
    /// multicall argv[0] semantics (for example `cargo -> rustup`).
    pub fn from_absolute(
        path: &Path,
        denied_roots: &[PathBuf],
    ) -> Result<Self, TrustedExecutableError> {
        Self::from_absolute_with_source(
            path,
            denied_roots,
            WindowsExecutableSource::ExplicitAbsolute,
        )
    }

    fn from_absolute_with_source(
        path: &Path,
        denied_roots: &[PathBuf],
        _source: WindowsExecutableSource,
    ) -> Result<Self, TrustedExecutableError> {
        if !path.is_absolute() {
            return Err(TrustedExecutableError::NotAbsolute(path.to_path_buf()));
        }
        // Reject attacker-controlled selection origin before following symlinks /
        // reparse points. Otherwise `repo/bin/tool -> C:\Windows\...\other.exe`
        // would canonicalize outside the denied root and let the repo substitute
        // an argument-incompatible trusted image for the requested helper name.
        if let Some(root) = denied_selection_origin(path, denied_roots) {
            return Err(TrustedExecutableError::Untrusted {
                path: path.to_path_buf(),
                root,
            });
        }
        let canonical = path
            .canonicalize()
            .map_err(|e| TrustedExecutableError::InvalidPath {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })?;
        if !crate::path_audit::is_executable_file(&canonical) {
            return Err(TrustedExecutableError::NotExecutable(canonical));
        }
        let invocation_location = path
            .parent()
            .and_then(|parent| parent.canonicalize().ok())
            .and_then(|parent| path.file_name().map(|name| parent.join(name)))
            .unwrap_or_else(|| path.to_path_buf());
        for root in denied_roots {
            let canonical_root = root.canonicalize().unwrap_or_else(|_| root.clone());
            let target_is_denied = path_is_within(&canonical, &canonical_root);
            let invocation_is_denied = path_is_within(&invocation_location, &canonical_root);
            if target_is_denied || invocation_is_denied {
                return Err(TrustedExecutableError::Untrusted {
                    path: if target_is_denied {
                        canonical
                    } else {
                        invocation_location
                    },
                    root: canonical_root,
                });
            }
        }
        #[cfg(unix)]
        {
            let identity = validate_unix_executable(&canonical)?;
            Ok(Self {
                invocation_path: path.to_path_buf(),
                path: canonical,
                identity,
                #[cfg(target_os = "linux")]
                bound: None,
            })
        }
        #[cfg(windows)]
        {
            let provenance =
                windows::validate_executable(&canonical, _source).map_err(|reason| {
                    TrustedExecutableError::InvalidPath {
                        path: canonical.clone(),
                        reason,
                    }
                })?;
            let digest = executable_digest(&canonical)?;
            Ok(Self {
                invocation_path: path.to_path_buf(),
                path: canonical,
                digest,
                source: _source,
                provenance,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let digest = executable_digest(&canonical)?;
            Ok(Self {
                invocation_path: path.to_path_buf(),
                path: canonical,
                digest,
            })
        }
    }

    /// Resolve `name` in an explicit PATH value. If the first executable hit is
    /// denied, fail closed rather than silently selecting a later binary whose
    /// behavior differs from normal shell resolution.
    pub fn resolve_on_path(
        name: &str,
        path_value: &OsStr,
        denied_roots: &[PathBuf],
    ) -> Result<Self, TrustedExecutableError> {
        for dir in std::env::split_paths(path_value) {
            if dir.as_os_str().is_empty() {
                continue;
            }
            let direct = dir.join(name);
            if crate::path_audit::is_executable_file(&direct) {
                return Self::from_absolute_or_canonical(
                    &direct,
                    denied_roots,
                    WindowsExecutableSource::PathSearch,
                );
            }
            #[cfg(windows)]
            for extension in windows_path_extensions() {
                let candidate = dir.join(format!("{name}{extension}"));
                if crate::path_audit::is_executable_file(&candidate) {
                    return Self::from_absolute_or_canonical(
                        &candidate,
                        denied_roots,
                        WindowsExecutableSource::PathSearch,
                    );
                }
            }
        }
        Err(TrustedExecutableError::NotFound(name.to_string()))
    }

    fn from_absolute_or_canonical(
        path: &Path,
        denied_roots: &[PathBuf],
        source: WindowsExecutableSource,
    ) -> Result<Self, TrustedExecutableError> {
        if path.is_absolute() {
            Self::from_absolute_with_source(path, denied_roots, source)
        } else {
            let absolute = std::env::current_dir()
                .map_err(|e| TrustedExecutableError::InvalidPath {
                    path: path.to_path_buf(),
                    reason: e.to_string(),
                })?
                .join(path);
            Self::from_absolute_with_source(&absolute, denied_roots, source)
        }
    }

    /// Resolve the first valid executable from fixed absolute candidates.
    pub fn from_system_candidates(candidates: &[&Path]) -> Result<Self, TrustedExecutableError> {
        for candidate in candidates {
            if let Ok(executable) = Self::from_absolute_with_source(
                candidate,
                &[],
                WindowsExecutableSource::SystemCandidate,
            ) {
                return Ok(executable);
            }
        }
        Err(TrustedExecutableError::NotFound(
            candidates
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(" or "),
        ))
    }

    pub fn current() -> Result<Self, TrustedExecutableError> {
        let path = std::env::current_exe().map_err(|e| TrustedExecutableError::InvalidPath {
            path: PathBuf::from("<current executable>"),
            reason: e.to_string(),
        })?;
        Self::from_absolute_with_source(&path, &[], WindowsExecutableSource::CurrentProcess)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-check the canonical executable immediately before a security-sensitive
    /// spawn. This detects replacement, permission/owner drift, and symlink
    /// retargeting between discovery and execution.
    pub fn revalidate(&self) -> Result<(), TrustedExecutableError> {
        #[cfg(target_os = "linux")]
        if let Some(bound) = &self.bound {
            let snapshot = open_snapshot_for_verification(&bound.path)?;
            verify_open_identity(&snapshot, bound.identity, &bound.path)?;
            let digest = hash_open_file(&snapshot, &bound.path)?;
            if digest != bound.sha256 {
                return Err(TrustedExecutableError::InvalidPath {
                    path: bound.path.clone(),
                    reason: "bound executable content changed before launch".to_string(),
                });
            }
            verify_open_identity(&bound.sealed_file, bound.sealed_identity, &bound.path)?;
            verify_required_seals(&bound.sealed_file, &bound.path)?;
            // File::try_clone shares an open-file-description offset on Unix.
            // Hash the held descriptor with read_at so concurrent launches from
            // clones cannot race one another's verification cursor.
            let sealed_digest = hash_open_file(&bound.sealed_file, &bound.path)?;
            if sealed_digest != bound.sha256 {
                return Err(TrustedExecutableError::InvalidPath {
                    path: bound.path.clone(),
                    reason: "sealed executable content changed before launch".to_string(),
                });
            }
            return Ok(());
        }
        let canonical =
            self.path
                .canonicalize()
                .map_err(|e| TrustedExecutableError::InvalidPath {
                    path: self.path.clone(),
                    reason: e.to_string(),
                })?;
        if canonical != self.path {
            return Err(TrustedExecutableError::InvalidPath {
                path: self.path.clone(),
                reason: format!("canonical identity changed to {}", canonical.display()),
            });
        }
        #[cfg(unix)]
        {
            let current = validate_unix_executable(&canonical)?;
            if current != self.identity {
                return Err(TrustedExecutableError::InvalidPath {
                    path: canonical,
                    reason: "executable identity changed after validation".to_string(),
                });
            }
        }
        #[cfg(not(unix))]
        {
            if !crate::path_audit::is_executable_file(&canonical) {
                return Err(TrustedExecutableError::NotExecutable(canonical));
            }
            #[cfg(windows)]
            {
                let provenance =
                    windows::validate_executable(&canonical, self.source).map_err(|reason| {
                        TrustedExecutableError::InvalidPath {
                            path: canonical.clone(),
                            reason,
                        }
                    })?;
                if provenance != self.provenance {
                    return Err(TrustedExecutableError::InvalidPath {
                        path: canonical,
                        reason: "executable provenance changed after validation".to_string(),
                    });
                }
            }
            if executable_digest(&canonical)? != self.digest {
                return Err(TrustedExecutableError::InvalidPath {
                    path: canonical,
                    reason: "executable contents changed after validation".to_string(),
                });
            }
        }
        Ok(())
    }

    /// Absolute path selected by the caller or explicit PATH lookup before
    /// canonicalizing the trusted target. Consumers may retain this spelling as
    /// argv metadata, but must launch through the canonical path or sealed file.
    pub fn invocation_path(&self) -> &Path {
        &self.invocation_path
    }

    /// Return the validated launch path. On Linux, content-bound security
    /// boundaries launch the held sealed descriptor returned internally by
    /// [`Self::bound_launch_fd`] rather than reopening this path.
    pub fn launch_path(&self) -> &Path {
        #[cfg(target_os = "linux")]
        if let Some(bound) = &self.bound {
            return bound.path.as_path();
        }
        self.path.as_path()
    }

    /// Return the immutable held executable descriptor for a Linux
    /// content-bound launch. The descriptor stays valid while `self` is alive;
    /// callers duplicate it into the child after `fork` and execute it with
    /// `execveat(AT_EMPTY_PATH)` so no pathname lookup can race verification.
    #[cfg(target_os = "linux")]
    pub fn bound_launch_fd(&self) -> Option<std::os::fd::RawFd> {
        use std::os::fd::AsRawFd as _;

        self.bound
            .as_ref()
            .map(|bound| bound.sealed_file.as_raw_fd())
    }

    /// On Linux, copy the selected executable into a private read-only snapshot
    /// and bind future launches to those exact bytes through a fully sealed
    /// anonymous descriptor. Same-UID path replacement or in-place mutation
    /// therefore cannot change the executed image. The source is opened without
    /// following links and its device/inode is checked against resolution before
    /// any byte is accepted, closing the resolve-to-copy replacement window.
    ///
    /// This is intentionally opt-in: callers that resolve an interpreter before
    /// a network request use it, while ordinary short-lived trusted-child calls
    /// retain their canonical-path behavior and avoid an unnecessary file copy.
    #[cfg(target_os = "linux")]
    pub fn bind_content(&self) -> Result<Self, TrustedExecutableError> {
        if self.bound.is_some() {
            return Ok(self.clone());
        }

        let mut source_options = OpenOptions::new();
        source_options.read(true);
        use std::os::unix::fs::OpenOptionsExt as _;
        source_options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut source = source_options.open(&self.path).map_err(|error| {
            TrustedExecutableError::InvalidPath {
                path: self.path.clone(),
                reason: format!("open executable for content binding: {error}"),
            }
        })?;
        verify_open_identity(&source, self.identity, &self.path)?;

        let temp_root = trusted_snapshot_temp_root()?;
        let directory = tempfile::Builder::new()
            .prefix("tirith-exec-")
            .tempdir_in(&temp_root)
            .map_err(|error| TrustedExecutableError::InvalidPath {
                path: temp_root.clone(),
                reason: format!("create private executable snapshot: {error}"),
            })?;
        std::fs::set_permissions(
            directory.path(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .map_err(|error| TrustedExecutableError::InvalidPath {
            path: directory.path().to_path_buf(),
            reason: format!("secure executable snapshot directory: {error}"),
        })?;

        let file_name =
            self.path
                .file_name()
                .ok_or_else(|| TrustedExecutableError::InvalidPath {
                    path: self.path.clone(),
                    reason: "executable has no file name".to_string(),
                })?;
        let snapshot_path = directory.path().join(file_name);
        let mut target_options = OpenOptions::new();
        target_options.write(true).read(true).create_new(true);
        target_options.mode(0o700).custom_flags(libc::O_CLOEXEC);
        let mut target = target_options.open(&snapshot_path).map_err(|error| {
            TrustedExecutableError::InvalidPath {
                path: snapshot_path.clone(),
                reason: format!("create executable content snapshot: {error}"),
            }
        })?;

        let sha256 = copy_and_hash(&mut source, &mut target, &self.path)?;
        target
            .sync_all()
            .map_err(|error| TrustedExecutableError::InvalidPath {
                path: snapshot_path.clone(),
                reason: format!("sync executable content snapshot: {error}"),
            })?;
        target
            .set_permissions(
                <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o500),
            )
            .map_err(|error| TrustedExecutableError::InvalidPath {
                path: snapshot_path.clone(),
                reason: format!("make executable content snapshot read-only: {error}"),
            })?;

        // Re-read both handles. A concurrent in-place source mutation must not be
        // accepted as a coherent binding, and the durable snapshot must contain
        // exactly the digest we recorded while copying.
        let source_sha256 = hash_open_file(&source, &self.path)?;
        if source_sha256 != sha256 {
            return Err(TrustedExecutableError::InvalidPath {
                path: self.path.clone(),
                reason: "executable content changed while it was being bound".to_string(),
            });
        }
        let snapshot_sha256 = hash_open_file(&target, &snapshot_path)?;
        if snapshot_sha256 != sha256 {
            return Err(TrustedExecutableError::InvalidPath {
                path: snapshot_path,
                reason: "executable snapshot digest changed before launch".to_string(),
            });
        }
        verify_open_identity(&source, self.identity, &self.path)?;

        let (sealed_file, sealed_identity) =
            create_sealed_executable(&mut target, &snapshot_path, sha256)?;
        let identity =
            executable_identity(&target).map_err(|error| TrustedExecutableError::InvalidPath {
                path: snapshot_path.clone(),
                reason: format!("identify executable content snapshot: {error}"),
            })?;
        let bound = BoundExecutable {
            _directory: directory,
            path: snapshot_path,
            _file: target,
            sha256,
            identity,
            sealed_file,
            sealed_identity,
        };
        Ok(Self {
            invocation_path: self.invocation_path.clone(),
            path: self.path.clone(),
            identity: self.identity,
            bound: Some(Arc::new(bound)),
        })
    }

    /// Content-bound execution is unsupported outside Linux because those
    /// launchers cannot execute the held, sealed bytes without reopening a path.
    /// Fail closed instead of presenting a weaker platform-dependent binding.
    #[cfg(not(target_os = "linux"))]
    pub fn bind_content(&self) -> Result<Self, TrustedExecutableError> {
        Err(TrustedExecutableError::InvalidPath {
            path: self.path.clone(),
            reason: "content-bound execution is unsupported on this platform".to_string(),
        })
    }

    /// Revalidate that the canonical executable still names the same file that
    /// was selected. Callers perform this immediately before spawn so replacing
    /// a PATH symlink or its target cannot silently change the chosen program.
    pub fn verify_identity(&self) -> Result<(), TrustedExecutableError> {
        self.revalidate()
    }

    /// Require this already-canonical executable to have an approved provenance
    /// for remote-script interpreter use. General trusted-child callers may use
    /// explicitly configured tools; forced interpreters have the narrower
    /// root-managed system contract documented by [`resolve_forced_interpreter`].
    pub fn require_forced_interpreter_provenance(self) -> Result<Self, TrustedExecutableError> {
        if root_managed_system_provenance_is_approved(self.invocation_path(), self.path()) {
            Ok(self)
        } else {
            Err(TrustedExecutableError::InvalidPath {
                path: self.path().to_path_buf(),
                reason: "forced interpreters must come from a root-owned, non-group/world-writable system bin directory"
                    .to_string(),
            })
        }
    }

    /// Require provenance strong enough to print this executable path into a
    /// command that will be evaluated after the current process exits. An
    /// absolute path closes ambient PATH lookup, but a same-UID owner could still
    /// replace a user-owned file between generation and evaluation. Only fixed,
    /// root-owned system-bin paths whose complete ancestor chain is not
    /// group/world-writable cross this delayed-reinvocation boundary.
    pub fn require_safe_reinvocation_provenance(self) -> Result<Self, TrustedExecutableError> {
        if root_managed_system_provenance_is_approved(self.invocation_path(), self.path()) {
            Ok(self)
        } else {
            Err(TrustedExecutableError::InvalidPath {
                path: self.path().to_path_buf(),
                reason: "delayed safe-command reinvocation requires a root-owned, non-group/world-writable system-bin path and ancestor chain"
                    .to_string(),
            })
        }
    }

    /// Whether this executable carries provenance strong enough for a helper
    /// that runs while Tirith is still deciding a security verdict.
    ///
    /// Unix requires a fixed, root-managed system/package-manager bin origin
    /// and a root-owned canonical target hierarchy. Windows accepts protected
    /// administrator installs and Authenticode, but not same-user-only PATH
    /// provenance. Other platforms fail closed.
    pub fn has_system_helper_provenance(&self) -> bool {
        #[cfg(unix)]
        {
            root_managed_system_provenance_is_approved(self.invocation_path(), self.path())
        }
        #[cfg(windows)]
        {
            windows_provenance_is_system_helper_approved(self.provenance)
        }
        #[cfg(not(any(unix, windows)))]
        {
            false
        }
    }

    /// Enforce [`Self::has_system_helper_provenance`] while retaining the
    /// validated executable identity for the eventual bounded spawn.
    pub fn require_system_helper_provenance(self) -> Result<Self, TrustedExecutableError> {
        if self.has_system_helper_provenance() {
            Ok(self)
        } else {
            Err(TrustedExecutableError::InvalidPath {
                path: self.path().to_path_buf(),
                reason: "untrusted executable provenance: pre-verdict helpers must be installed in an approved administrator-managed, non-writable system/package-manager bin tree on Unix, or have Authenticode/protected-install provenance on Windows; same-user-only PATH tools are not accepted"
                    .to_string(),
            })
        }
    }
}

#[cfg(target_os = "linux")]
const REQUIRED_EXECUTABLE_SEALS: libc::c_int =
    libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;

/// Copy a verified snapshot into an anonymous sealable file and permanently
/// revoke every byte-changing operation. A pathname snapshot owned by the same
/// uid can always be chmod'd and replaced; a fully sealed memfd cannot.
#[cfg(target_os = "linux")]
fn create_sealed_executable(
    source: &mut File,
    source_path: &Path,
    expected_sha256: [u8; 32],
) -> Result<(File, UnixExecutableIdentity), TrustedExecutableError> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::ffi::OsStrExt as _;

    source
        .rewind()
        .map_err(|error| TrustedExecutableError::InvalidPath {
            path: source_path.to_path_buf(),
            reason: format!("rewind executable snapshot for sealing: {error}"),
        })?;
    let name = std::ffi::CString::new(
        source_path
            .file_name()
            .unwrap_or_else(|| OsStr::new("tirith-bound-executable"))
            .as_bytes(),
    )
    .map_err(|_| TrustedExecutableError::InvalidPath {
        path: source_path.to_path_buf(),
        reason: "executable file name contains NUL".to_string(),
    })?;
    // SAFETY: `name` is a live NUL-terminated string and the flags are the
    // documented memfd_create bitset. The returned descriptor is uniquely owned.
    let base_flags = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;
    let mut raw_fd = unsafe { libc::memfd_create(name.as_ptr(), base_flags | libc::MFD_EXEC) };
    // MFD_EXEC was added after memfd sealing. Old kernels reject the unknown bit
    // with EINVAL but create executable memfds by default, so retry only for that
    // compatibility case. Modern no-exec-by-default hosts use the explicit flag.
    if raw_fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        raw_fd = unsafe { libc::memfd_create(name.as_ptr(), base_flags) };
    }
    if raw_fd < 0 {
        return Err(TrustedExecutableError::InvalidPath {
            path: source_path.to_path_buf(),
            reason: format!(
                "create sealable executable descriptor: {}",
                std::io::Error::last_os_error()
            ),
        });
    }
    // SAFETY: `raw_fd` was just returned by memfd_create and has no other owner.
    let mut sealed = unsafe { File::from_raw_fd(raw_fd) };
    let digest = copy_and_hash(source, &mut sealed, source_path)?;
    if digest != expected_sha256 {
        return Err(TrustedExecutableError::InvalidPath {
            path: source_path.to_path_buf(),
            reason: "executable changed while creating sealed launch descriptor".to_string(),
        });
    }
    if unsafe { libc::fchmod(sealed.as_raw_fd(), 0o500) } != 0 {
        return Err(TrustedExecutableError::InvalidPath {
            path: source_path.to_path_buf(),
            reason: format!(
                "make sealed executable descriptor executable: {}",
                std::io::Error::last_os_error()
            ),
        });
    }
    if unsafe {
        libc::fcntl(
            sealed.as_raw_fd(),
            libc::F_ADD_SEALS,
            REQUIRED_EXECUTABLE_SEALS,
        )
    } < 0
    {
        return Err(TrustedExecutableError::InvalidPath {
            path: source_path.to_path_buf(),
            reason: format!(
                "seal executable descriptor against mutation: {}",
                std::io::Error::last_os_error()
            ),
        });
    }
    verify_required_seals(&sealed, source_path)?;
    let identity =
        executable_identity(&sealed).map_err(|error| TrustedExecutableError::InvalidPath {
            path: source_path.to_path_buf(),
            reason: format!("identify sealed executable descriptor: {error}"),
        })?;
    Ok((sealed, identity))
}

#[cfg(target_os = "linux")]
fn verify_required_seals(file: &File, path: &Path) -> Result<(), TrustedExecutableError> {
    use std::os::fd::AsRawFd as _;

    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    if seals < 0 {
        return Err(TrustedExecutableError::InvalidPath {
            path: path.to_path_buf(),
            reason: format!(
                "inspect executable descriptor seals: {}",
                std::io::Error::last_os_error()
            ),
        });
    }
    if seals & REQUIRED_EXECUTABLE_SEALS != REQUIRED_EXECUTABLE_SEALS {
        return Err(TrustedExecutableError::InvalidPath {
            path: path.to_path_buf(),
            reason: "executable descriptor is missing immutable-content seals".to_string(),
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn trusted_snapshot_temp_root() -> Result<PathBuf, TrustedExecutableError> {
    let root = PathBuf::from("/tmp");
    root.canonicalize()
        .map_err(|error| TrustedExecutableError::InvalidPath {
            path: root,
            reason: format!("resolve executable snapshot root: {error}"),
        })
}

#[cfg(target_os = "linux")]
fn copy_and_hash(
    source: &mut File,
    target: &mut File,
    source_path: &Path,
) -> Result<[u8; 32], TrustedExecutableError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count =
            source
                .read(&mut buffer)
                .map_err(|error| TrustedExecutableError::InvalidPath {
                    path: source_path.to_path_buf(),
                    reason: format!("read executable while binding content: {error}"),
                })?;
        if count == 0 {
            break;
        }
        target.write_all(&buffer[..count]).map_err(|error| {
            TrustedExecutableError::InvalidPath {
                path: source_path.to_path_buf(),
                reason: format!("write executable content snapshot: {error}"),
            }
        })?;
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

#[cfg(target_os = "linux")]
fn hash_open_file(file: &File, path: &Path) -> Result<[u8; 32], TrustedExecutableError> {
    use std::os::unix::fs::FileExt as _;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut offset = 0u64;
    loop {
        let count = file.read_at(&mut buffer, offset).map_err(|error| {
            TrustedExecutableError::InvalidPath {
                path: path.to_path_buf(),
                reason: format!("read executable for content verification: {error}"),
            }
        })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        offset = offset.checked_add(count as u64).ok_or_else(|| {
            TrustedExecutableError::InvalidPath {
                path: path.to_path_buf(),
                reason: "executable length overflow during content verification".to_string(),
            }
        })?;
    }
    Ok(hasher.finalize().into())
}

#[cfg(not(unix))]
fn hash_open_file(file: &mut File, path: &Path) -> Result<[u8; 32], TrustedExecutableError> {
    file.rewind()
        .map_err(|error| TrustedExecutableError::InvalidPath {
            path: path.to_path_buf(),
            reason: format!("rewind executable for content verification: {error}"),
        })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count =
            file.read(&mut buffer)
                .map_err(|error| TrustedExecutableError::InvalidPath {
                    path: path.to_path_buf(),
                    reason: format!("read executable for content verification: {error}"),
                })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

/// Windows and other non-Unix hosts do not expose the Unix identity tuple used
/// below through stable `std` APIs. Hash the canonical file's bytes and recheck
/// them immediately before spawn so replacement or in-place modification is
/// still detected.
#[cfg(not(unix))]
fn executable_digest(path: &Path) -> Result<[u8; 32], TrustedExecutableError> {
    let mut file = File::open(path).map_err(|error| TrustedExecutableError::InvalidPath {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })?;
    hash_open_file(&mut file, path)
}

#[cfg(unix)]
fn validate_unix_executable(
    canonical: &Path,
) -> Result<UnixExecutableIdentity, TrustedExecutableError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata =
        std::fs::metadata(canonical).map_err(|e| TrustedExecutableError::InvalidPath {
            path: canonical.to_path_buf(),
            reason: e.to_string(),
        })?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        return Err(TrustedExecutableError::NotExecutable(
            canonical.to_path_buf(),
        ));
    }

    let effective_uid = unsafe { libc::geteuid() };
    validate_unix_owner_and_mode(canonical, &metadata, effective_uid, false)?;

    for parent in canonical.ancestors().skip(1) {
        let parent_metadata =
            std::fs::metadata(parent).map_err(|e| TrustedExecutableError::InvalidPath {
                path: parent.to_path_buf(),
                reason: e.to_string(),
            })?;
        validate_unix_owner_and_mode(parent, &parent_metadata, effective_uid, true)?;
    }

    Ok(UnixExecutableIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
        len: metadata.len(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    })
}

#[cfg(target_os = "linux")]
fn open_snapshot_for_verification(path: &Path) -> Result<File, TrustedExecutableError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .map_err(|error| TrustedExecutableError::InvalidPath {
            path: path.to_path_buf(),
            reason: format!("open bound executable for verification: {error}"),
        })
}

#[cfg(target_os = "linux")]
fn executable_identity(file: &File) -> std::io::Result<UnixExecutableIdentity> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "not an executable regular file",
        ));
    }
    Ok(UnixExecutableIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
        len: metadata.len(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    })
}

#[cfg(unix)]
fn validate_unix_owner_and_mode(
    path: &Path,
    metadata: &std::fs::Metadata,
    effective_uid: u32,
    directory: bool,
) -> Result<(), TrustedExecutableError> {
    use std::os::unix::fs::MetadataExt as _;

    if metadata.uid() != 0 && metadata.uid() != effective_uid {
        return Err(TrustedExecutableError::InvalidPath {
            path: path.to_path_buf(),
            reason: format!(
                "owner uid {} is neither root nor the current uid {}",
                metadata.uid(),
                effective_uid
            ),
        });
    }
    let world_writable = metadata.mode() & 0o002 != 0;
    // Owner identity does not make a group-write bit safe: another member of a
    // shared group can replace an entry in an euid-owned 0770/0775 directory.
    // Only root:root group-write is treated as administrative, since ordinary
    // principals cannot join gid 0. All other group-writable components fail.
    let root_group_writable = metadata.uid() == 0 && metadata.gid() == 0;
    let untrusted_group_writable = metadata.mode() & 0o020 != 0 && !root_group_writable;
    if world_writable || untrusted_group_writable {
        // A root-owned sticky directory (for example /tmp) protects entries
        // owned by another user. The resolver separately denies temp roots, but
        // this exception preserves explicitly selected tools under private temp
        // subdirectories in tests and other non-ambient callers.
        let protected_sticky_directory =
            directory && metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !protected_sticky_directory {
            return Err(TrustedExecutableError::InvalidPath {
                path: path.to_path_buf(),
                reason: "path component is writable by an untrusted group or by everyone"
                    .to_string(),
            });
        }
    }
    reject_unix_extended_acl(path, directory).map_err(|reason| {
        TrustedExecutableError::InvalidPath {
            path: path.to_path_buf(),
            reason,
        }
    })?;
    Ok(())
}

/// Reject filesystem ACLs that can grant mutation authority independently of
/// Unix owner/group/mode bits. Resolver tools and their trust store use this
/// deliberately conservative rule. Linux parses each POSIX ACL xattr (access,
/// plus default for directories) and rejects any entry that could hand write
/// authority to a principal other than root, the current effective user, or
/// the component owner; named-group write grants always fail and malformed
/// blobs fail closed. Base and mask entries mirror or restrict the mode bits
/// that were already validated, so they stay acceptable; this keeps hosts
/// that seed benign self-grants (GitHub runners place a default
/// `user:<login>:rwx` entry on /home) usable without admitting foreign
/// principals. macOS permits deny-only/read-only entries but rejects every
/// allow entry carrying a mutation right.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn reject_unix_extended_acl(path: &Path, directory: bool) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;

    const ACL_EA_VERSION: u32 = 0x0002;
    const ACL_USER_OBJ: u16 = 0x01;
    const ACL_USER: u16 = 0x02;
    const ACL_GROUP_OBJ: u16 = 0x04;
    const ACL_GROUP: u16 = 0x08;
    const ACL_MASK: u16 = 0x10;
    const ACL_OTHER: u16 = 0x20;
    const ACL_WRITE: u16 = 0x02;
    // One 4-byte header plus 8-byte entries; 64 KiB bounds hostile attribute
    // sizes far beyond any legitimate ACL.
    const MAX_ACL_BYTES: usize = 64 * 1024;

    let path_bytes = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "path contains an interior NUL while checking ACLs".to_string())?;
    let mut owner_uid = None;
    let mut names: Vec<&[u8]> = vec![b"system.posix_acl_access\0"];
    if directory {
        names.push(b"system.posix_acl_default\0");
    }
    for name in names {
        let label = std::str::from_utf8(&name[..name.len() - 1]).unwrap_or("POSIX ACL");
        let mut value = vec![0_u8; MAX_ACL_BYTES];
        // SAFETY: both strings are NUL-terminated and the output buffer is
        // writable for its full declared length.
        let size = unsafe {
            libc::getxattr(
                path_bytes.as_ptr(),
                name.as_ptr().cast::<libc::c_char>(),
                value.as_mut_ptr().cast::<libc::c_void>(),
                value.len(),
            )
        };
        if size < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENODATA) {
                continue;
            }
            // ERANGE lands here too: an attribute larger than the bound above
            // is not something this rule will vouch for.
            return Err(format!(
                "cannot verify path ACL attributes ({label}): {error}"
            ));
        }
        let value = &value[..size as usize];
        if value.len() < 4 || (value.len() - 4) % 8 != 0 {
            return Err(format!("path carries a malformed {label} attribute"));
        }
        let version = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
        if version != ACL_EA_VERSION {
            return Err(format!(
                "path carries an unsupported {label} version {version}"
            ));
        }
        for entry in value[4..].chunks_exact(8) {
            let tag = u16::from_le_bytes([entry[0], entry[1]]);
            let perm = u16::from_le_bytes([entry[2], entry[3]]);
            let id = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
            let acceptable = match tag {
                // Base entries restate the validated mode bits and the mask
                // only narrows named grants further.
                ACL_USER_OBJ | ACL_GROUP_OBJ | ACL_OTHER | ACL_MASK => true,
                ACL_USER => {
                    if perm & ACL_WRITE == 0 {
                        true
                    } else {
                        let owner = match owner_uid {
                            Some(owner) => owner,
                            None => {
                                let owner = std::fs::symlink_metadata(path)
                                    .map_err(|error| {
                                        format!("cannot verify path owner for ACL check: {error}")
                                    })?
                                    .uid();
                                owner_uid = Some(owner);
                                owner
                            }
                        };
                        // SAFETY: geteuid has no preconditions.
                        let euid = unsafe { libc::geteuid() };
                        id == 0 || id == euid || id == owner
                    }
                }
                // Named-group write reaches every unknown member of the group.
                ACL_GROUP => perm & ACL_WRITE == 0,
                _ => false,
            };
            if !acceptable {
                return Err(format!(
                    "path carries {label} entry (tag {tag:#x}, id {id}) that could widen \
                     mutation authority beyond the owner, root, and the current user; \
                     trusted paths must not grant write access to other principals"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(target_vendor = "apple")]
pub(crate) fn reject_unix_extended_acl(path: &Path, _directory: bool) -> Result<(), String> {
    use std::ffi::c_void;
    use std::os::unix::ffi::OsStrExt as _;

    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;
    const ACL_NEXT_ENTRY: libc::c_int = -1;
    const ACL_EXTENDED_ALLOW: libc::c_int = 1;
    const MUTATING_PERMISSIONS: u64 =
        (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 8) | (1 << 10) | (1 << 12) | (1 << 13);
    unsafe extern "C" {
        fn acl_get_file(path: *const libc::c_char, acl_type: libc::c_int) -> *mut c_void;
        fn acl_get_entry(
            acl: *mut c_void,
            entry_id: libc::c_int,
            entry: *mut *mut c_void,
        ) -> libc::c_int;
        fn acl_get_tag_type(entry: *mut c_void, tag_type: *mut libc::c_int) -> libc::c_int;
        fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> libc::c_int;
        fn acl_free(object: *mut c_void) -> libc::c_int;
    }

    let path_bytes = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "path contains an interior NUL while checking ACLs".to_string())?;
    // SAFETY: path_bytes is NUL-terminated and ACL_TYPE_EXTENDED is the native
    // macOS ACL type. A successful handle is released exactly once below.
    let acl = unsafe { acl_get_file(path_bytes.as_ptr(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = std::io::Error::last_os_error();
        // macOS reports ENOENT when the path exists but has no extended ACL.
        // That is the ordinary ACL-free case; every other lookup failure stays
        // fail-closed because it prevents us from ruling out hidden mutation
        // authority.
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(format!("cannot read path extended ACL: {error}",));
    }
    let inspection = (|| {
        let mut entry_id = ACL_FIRST_ENTRY;
        loop {
            let mut entry = std::ptr::null_mut();
            // SAFETY: acl is live and entry is a valid out-pointer.
            let status = unsafe { acl_get_entry(acl, entry_id, &mut entry) };
            if status != 0 {
                let error = std::io::Error::last_os_error();
                // Darwin returns zero for an entry and -1/EINVAL after the
                // final entry (unlike Linux's one/zero iterator convention).
                if error.raw_os_error() == Some(libc::EINVAL) {
                    return Ok(());
                } else {
                    return Err(format!("cannot enumerate path extended ACL: {error}"));
                }
            }
            let mut tag_type = 0;
            let mut permissions = 0_u64;
            // SAFETY: entry was returned by acl_get_entry and both output
            // pointers remain valid for the duration of each call.
            if unsafe { acl_get_tag_type(entry, &mut tag_type) } != 0
                || unsafe { acl_get_permset_mask_np(entry, &mut permissions) } != 0
            {
                return Err(format!(
                    "cannot inspect path extended ACL entry: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if tag_type == ACL_EXTENDED_ALLOW && permissions & MUTATING_PERMISSIONS != 0 {
                return Err(
                    "path ACL grants mutation rights outside Unix mode bits; trusted paths must not"
                        .to_string(),
                );
            }
            entry_id = ACL_NEXT_ENTRY;
        }
    })();
    // SAFETY: acl was returned by acl_get_file and has not been freed yet.
    unsafe {
        let _ = acl_free(acl);
    }
    inspection
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
pub(crate) fn reject_unix_extended_acl(_path: &Path, _directory: bool) -> Result<(), String> {
    Err("this Unix platform has no extended-ACL verifier; refusing trusted path".to_string())
}

#[cfg(target_os = "linux")]
fn verify_open_identity(
    file: &File,
    expected: UnixExecutableIdentity,
    path: &Path,
) -> Result<(), TrustedExecutableError> {
    let observed =
        executable_identity(file).map_err(|error| TrustedExecutableError::InvalidPath {
            path: path.to_path_buf(),
            reason: format!("identify open executable: {error}"),
        })?;
    if observed != expected {
        return Err(TrustedExecutableError::InvalidPath {
            path: path.to_path_buf(),
            reason: "executable identity changed before content binding".to_string(),
        });
    }
    Ok(())
}

/// Resolve a named installed tool without ever passing its bare name to the OS.
/// Project and temporary-directory candidates are rejected.
pub fn resolve_ambient(name: &str) -> Result<TrustedExecutable, TrustedExecutableError> {
    let path = std::env::var_os("PATH")
        .ok_or_else(|| TrustedExecutableError::NotFound(format!("{name} (PATH is unset)")))?;
    TrustedExecutable::resolve_on_path(name, &path, &ambient_denied_roots())
}

/// Resolve a helper that may run before Tirith has produced a security verdict.
/// The first executable PATH hit remains authoritative, but project/temp and
/// same-user-only installed tools fail closed instead of being executed or
/// silently skipped in favor of a different program.
pub fn resolve_system_helper(name: &str) -> Result<TrustedExecutable, TrustedExecutableError> {
    let path = std::env::var_os("PATH")
        .ok_or_else(|| TrustedExecutableError::NotFound(format!("{name} (PATH is unset)")))?;
    resolve_system_helper_on_path(name, &path)
}

/// Explicit-PATH variant of [`resolve_system_helper`] for deterministic callers
/// and regression tests.
pub fn resolve_system_helper_on_path(
    name: &str,
    path_value: &OsStr,
) -> Result<TrustedExecutable, TrustedExecutableError> {
    TrustedExecutable::resolve_on_path(name, path_value, &ambient_denied_roots())?
        .require_system_helper_provenance()
}

/// Resolve a forced remote-script interpreter from ambient `PATH`, but accept
/// the first hit only when its canonical executable has an approved installed
/// provenance. Project/temp checks alone are insufficient: a user-owned
/// `~/bin/bash` outside the current repository is still attacker-selectable.
///
/// Approved locations are fixed root-managed system binary directories. The
/// first executable hit is authoritative: an unapproved shadow fails closed
/// rather than falling through to a later system shell. User-owned package
/// manager trees are deliberately excluded because pathname shape and mode bits
/// do not prove provenance against a same-UID writer.
pub fn resolve_forced_interpreter(name: &str) -> Result<TrustedExecutable, TrustedExecutableError> {
    let path = std::env::var_os("PATH")
        .ok_or_else(|| TrustedExecutableError::NotFound(format!("{name} (PATH is unset)")))?;
    resolve_forced_interpreter_on_path(name, &path)
}

/// Explicit-PATH variant of [`resolve_forced_interpreter`] for deterministic
/// callers and regression tests.
pub fn resolve_forced_interpreter_on_path(
    name: &str,
    path_value: &OsStr,
) -> Result<TrustedExecutable, TrustedExecutableError> {
    TrustedExecutable::resolve_on_path(name, path_value, &ambient_denied_roots())?
        .require_forced_interpreter_provenance()
}

#[cfg(unix)]
const ROOT_MANAGED_SYSTEM_HELPER_BINS: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
    "/opt/local/bin",
    "/opt/local/sbin",
    "/run/current-system/sw/bin",
    "/nix/var/nix/profiles/default/bin",
];

#[cfg(unix)]
fn root_managed_system_helper_bin_is_allowlisted(path: &Path) -> bool {
    let path = lexical_normalize(path);
    ROOT_MANAGED_SYSTEM_HELPER_BINS
        .iter()
        .any(|configured_bin| path == lexical_normalize(Path::new(configured_bin)))
}

#[cfg(unix)]
fn root_managed_system_provenance_is_approved(
    invocation_path: &Path,
    canonical_path: &Path,
) -> bool {
    let Some(selected_parent) = invocation_path.parent() else {
        return false;
    };
    let selected_parent_lexical = lexical_normalize(selected_parent);
    let Ok(invocation_parent) = selected_parent.canonicalize() else {
        return false;
    };

    // Package-manager and NixOS origins are included only when both the exact
    // selected bin directory and the canonical target's complete hierarchy are
    // root-managed. Ordinary same-UID Homebrew, MacPorts, and per-user Nix
    // layouts therefore fail closed, while administrator-managed installs
    // retain legitimate behavior.
    if !root_managed_system_helper_bin_is_allowlisted(selected_parent) {
        return false;
    }
    for &configured_bin in ROOT_MANAGED_SYSTEM_HELPER_BINS {
        if selected_parent_lexical != lexical_normalize(Path::new(configured_bin)) {
            continue;
        }
        let Ok(bin) = Path::new(configured_bin).canonicalize() else {
            continue;
        };
        if invocation_parent == bin
            && root_managed_selection_chain_is_secure(Path::new(configured_bin))
            && root_managed_chain_is_secure(&invocation_parent)
            && root_managed_chain_is_secure(canonical_path)
        {
            return true;
        }
    }

    false
}

#[cfg(not(unix))]
fn root_managed_system_provenance_is_approved(
    _invocation_path: &Path,
    _canonical_path: &Path,
) -> bool {
    false
}

#[cfg(unix)]
fn root_managed_path_is_secure(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    metadata.uid() == 0
        && metadata.mode() & 0o022 == 0
        && reject_unix_extended_acl(path, metadata.is_dir()).is_ok()
}

#[cfg(unix)]
fn root_managed_chain_is_secure(path: &Path) -> bool {
    path.ancestors().all(root_managed_path_is_secure)
}

#[cfg(unix)]
fn root_managed_selection_chain_is_secure(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    path.ancestors().all(|component| {
        let Ok(metadata) = std::fs::symlink_metadata(component) else {
            return false;
        };
        if metadata.file_type().is_symlink() {
            // Link replacement is governed by its parent, which is another
            // element in this same lexical chain. The link itself must still
            // be administrator-owned; its conventional 0777 mode is not a
            // mutation grant on Unix.
            metadata.uid() == 0
        } else {
            metadata.uid() == 0
                && metadata.mode() & 0o022 == 0
                && reject_unix_extended_acl(component, metadata.is_dir()).is_ok()
        }
    })
}

#[cfg(all(test, unix))]
mod system_helper_provenance_tests {
    use super::root_managed_system_helper_bin_is_allowlisted;
    use std::path::Path;

    #[test]
    fn global_nix_bins_are_exact_allowlisted_origins() {
        assert!(root_managed_system_helper_bin_is_allowlisted(Path::new(
            "/run/current-system/sw/bin"
        )));
        assert!(root_managed_system_helper_bin_is_allowlisted(Path::new(
            "/nix/var/nix/profiles/default/bin"
        )));

        for rejected in [
            "/run/current-system/sw/bin/subdir",
            "/nix/var/nix/profiles/default/bin/subdir",
            "/home/alice/.nix-profile/bin",
            "/Users/alice/.nix-profile/bin",
            "/nix/var/nix/profiles/per-user/alice/profile/bin",
        ] {
            assert!(
                !root_managed_system_helper_bin_is_allowlisted(Path::new(rejected)),
                "non-global or non-exact Nix bin must not be allowlisted: {rejected}"
            );
        }
    }
}

/// Construct the PATH value a trusted child may inherit. Relative, denied, and
/// world-writable directories are omitted. This is explicit child data, not the
/// ambient PATH used again for selecting the primary executable.
pub fn sanitized_path(path_value: &OsStr, denied_roots: &[PathBuf]) -> OsString {
    let mut directories = Vec::new();
    for directory in std::env::split_paths(path_value) {
        if !directory.is_absolute() {
            continue;
        }
        if denied_selection_origin(&directory, denied_roots).is_some() {
            continue;
        }
        let canonical = match directory.canonicalize() {
            Ok(path) => path,
            Err(_) => continue,
        };
        if denied_roots.iter().any(|root| {
            let root = root.canonicalize().unwrap_or_else(|_| root.clone());
            path_is_within(&canonical, &root)
        }) {
            continue;
        }
        #[cfg(unix)]
        {
            let effective_uid = unsafe { libc::geteuid() };
            let trusted_hierarchy = canonical.ancestors().all(|component| {
                std::fs::metadata(component).ok().is_some_and(|metadata| {
                    validate_unix_owner_and_mode(component, &metadata, effective_uid, true).is_ok()
                })
            });
            if !trusted_hierarchy {
                continue;
            }
        }
        #[cfg(windows)]
        if !windows::validate_inherited_path_dir(&canonical) {
            continue;
        }
        directories.push(canonical);
    }
    std::env::join_paths(directories).unwrap_or_default()
}

pub fn sanitized_ambient_path() -> Option<OsString> {
    let path = std::env::var_os("PATH")?;
    Some(sanitized_path(&path, &ambient_denied_roots()))
}

#[cfg(windows)]
fn windows_path_extensions() -> Vec<String> {
    std::env::var("PATHEXT")
        .ok()
        .map(|value| {
            value
                .split(';')
                .filter(|extension| !extension.is_empty())
                .map(str::to_ascii_lowercase)
                .collect()
        })
        .unwrap_or_else(|| {
            [".com", ".exe", ".bat", ".cmd"]
                .into_iter()
                .map(str::to_string)
                .collect()
        })
}

/// Roots controlled by the current project/environment and therefore invalid
/// executable locations for security-sensitive helpers.
pub fn ambient_denied_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        let mut repository_root = None;
        for ancestor in cwd.ancestors() {
            if ancestor.join(".git").exists() {
                repository_root = Some(ancestor.to_path_buf());
                break;
            }
        }
        roots.push(repository_root.unwrap_or(cwd));
    }
    roots.push(std::env::temp_dir());
    // `std::env::temp_dir()` follows TMPDIR/TMP/TEMP and is therefore only an
    // additional denial hint, never the complete transient-root boundary. A
    // hostile environment could otherwise point TMPDIR at /tmp/A and PATH at
    // a distinct /tmp/B executable. Deny conventional OS transient roots
    // independently of the environment used to select the primary child.
    #[cfg(unix)]
    roots.extend(
        ["/tmp", "/var/tmp", "/dev/shm", "/run/user", "/var/folders"]
            .into_iter()
            .map(PathBuf::from),
    );
    #[cfg(windows)]
    roots.extend(trusted_windows_temp_roots());
    roots.sort();
    roots.dedup();
    roots
}

#[cfg(windows)]
fn trusted_windows_temp_roots() -> Vec<PathBuf> {
    use ::windows::Win32::System::Com::CoTaskMemFree;
    use ::windows::Win32::System::SystemInformation::GetWindowsDirectoryW;
    use ::windows::Win32::UI::Shell::{
        FOLDERID_LocalAppData, SHGetKnownFolderPath, KF_FLAG_DEFAULT,
    };
    use std::os::windows::ffi::OsStringExt as _;

    let mut roots = Vec::new();
    // SAFETY: the fixed folder ID is valid and Windows owns the returned
    // NUL-terminated allocation until CoTaskMemFree below.
    if let Ok(raw) = unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT, None) }
    {
        // SAFETY: a successful call returned a valid NUL-terminated allocation.
        let local = std::ffi::OsString::from_wide(unsafe { raw.as_wide() });
        // SAFETY: SHGetKnownFolderPath transfers one COM task allocation.
        unsafe { CoTaskMemFree(Some(raw.as_ptr().cast())) };
        roots.push(PathBuf::from(local).join("Temp"));
    }

    let mut buffer = vec![0_u16; 32 * 1024];
    // SAFETY: GetWindowsDirectoryW writes at most the supplied slice length.
    let length = unsafe { GetWindowsDirectoryW(Some(&mut buffer)) } as usize;
    if length > 0 && length < buffer.len() {
        roots.push(PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length])).join("Temp"));
    }
    roots
}

#[derive(Debug, Clone, Copy)]
pub struct ChildLimits {
    pub timeout: Duration,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
}

impl ChildLimits {
    pub const fn new(timeout: Duration, stdout_bytes: usize, stderr_bytes: usize) -> Self {
        Self {
            timeout,
            stdout_bytes,
            stderr_bytes,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChildSpec {
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
    cwd: Option<PathBuf>,
    limits: ChildLimits,
    /// Additional already-open capabilities that a Linux child must retain.
    ///
    /// The caller owns these descriptors and must keep their backing handles live
    /// until [`run`] returns. `run` validates each descriptor before spawning and
    /// clears only `FD_CLOEXEC` in the child. This is intentionally narrower than
    /// ambient descriptor inheritance: callers opt in one exact fd at a time.
    #[cfg(target_os = "linux")]
    inherited_fds: Vec<std::os::fd::RawFd>,
}

impl ChildSpec {
    pub fn new<I, S>(args: I, limits: ChildLimits) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        Self {
            args: args
                .into_iter()
                .map(|arg| arg.as_ref().to_os_string())
                .collect(),
            env: Vec::new(),
            cwd: None,
            limits,
            #[cfg(target_os = "linux")]
            inherited_fds: Vec::new(),
        }
    }

    pub fn env(mut self, name: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.env
            .push((name.as_ref().to_os_string(), value.as_ref().to_os_string()));
        self
    }

    pub fn inherit_env(mut self, names: &[&str]) -> Self {
        for name in names {
            if let Some(value) = std::env::var_os(name) {
                self.env.push((OsString::from(name), value));
            }
        }
        self
    }

    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Retain one exact Linux descriptor across the child exec boundary.
    ///
    /// This supports capability paths such as `/proc/self/fd/N` without asking a
    /// child to dereference its parent's procfs entries (which Yama, hidepid, or a
    /// procfs mount policy may forbid). The backing handle must outlive [`run`].
    #[cfg(target_os = "linux")]
    pub fn inherit_fd(mut self, fd: std::os::fd::RawFd) -> Self {
        if !self.inherited_fds.contains(&fd) {
            self.inherited_fds.push(fd);
        }
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureStream {
    Stdout,
    Stderr,
}

#[derive(Debug)]
pub enum ChildOutcome {
    Completed {
        status: ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    SpawnError(String),
    WaitError(String),
    /// The direct child reached a terminal state, but cleanup of its supervised
    /// process group/Job or capture workers could not be proven within the
    /// cleanup deadline.
    CleanupError(String),
    Timeout {
        cleanup_succeeded: bool,
    },
    OutputLimitExceeded {
        stream: CaptureStream,
        cleanup_succeeded: bool,
    },
}

enum ReaderMessage {
    Complete(CaptureStream, Vec<u8>),
    Limit(CaptureStream),
    Error(CaptureStream, String),
}

fn spawn_reader<R: std::io::Read + Send + 'static>(
    mut reader: R,
    stream: CaptureStream,
    cap: usize,
    sender: mpsc::Sender<ReaderMessage>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut output = Vec::with_capacity(cap.min(64 * 1024));
        let mut chunk = [0u8; 8192];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => {
                    let _ = sender.send(ReaderMessage::Complete(stream, output));
                    return;
                }
                Ok(count) if output.len().saturating_add(count) <= cap => {
                    output.extend_from_slice(&chunk[..count]);
                }
                Ok(_) => {
                    let _ = sender.send(ReaderMessage::Limit(stream));
                    return;
                }
                Err(error) => {
                    let _ = sender.send(ReaderMessage::Error(stream, error.to_string()));
                    return;
                }
            }
        }
    })
}

/// Execute a validated absolute program with an empty-by-default environment,
/// bounded output, and a wall-clock deadline.
#[cfg(windows)]
pub fn run(executable: &TrustedExecutable, spec: &ChildSpec) -> ChildOutcome {
    if let Err(error) = executable.revalidate() {
        return ChildOutcome::SpawnError(format!(
            "trusted executable failed pre-spawn revalidation: {error}"
        ));
    }
    windows::run(executable, spec)
}

/// Execute a validated absolute program with an empty-by-default environment,
/// bounded output, and a wall-clock deadline.
#[cfg(not(windows))]
pub fn run(executable: &TrustedExecutable, spec: &ChildSpec) -> ChildOutcome {
    if let Err(error) = executable.verify_identity() {
        return ChildOutcome::SpawnError(error.to_string());
    }
    #[cfg(target_os = "linux")]
    for fd in &spec.inherited_fds {
        // SAFETY: F_GETFD only inspects the caller-supplied descriptor number; no
        // pointer is dereferenced. A negative/closed descriptor is rejected.
        if *fd < 0 || unsafe { libc::fcntl(*fd, libc::F_GETFD) } < 0 {
            return ChildOutcome::SpawnError(format!(
                "inherited capability descriptor {fd} is not open: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    #[cfg(target_os = "linux")]
    let bound_fd = executable.bound_launch_fd();
    #[cfg(target_os = "linux")]
    let launch_program = bound_fd.map_or_else(
        || executable.launch_path().as_os_str().to_os_string(),
        |fd| OsString::from(format!("/proc/self/fd/{fd}")),
    );
    #[cfg(not(target_os = "linux"))]
    let launch_program = executable.launch_path().as_os_str().to_os_string();
    let mut command = Command::new(launch_program);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;

        // Execute only the verified canonical path (or sealed Linux descriptor),
        // but preserve the caller-selected spelling as argv[0]. Multicall and
        // proxy executables such as BusyBox and rustup select behavior from this
        // value; canonicalizing it would silently invoke the wrong program.
        command.arg0(executable.invocation_path());
    }
    command
        .args(&spec.args)
        .env_clear()
        .envs(spec.env.iter().cloned())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        // SAFETY: setpgid/fcntl are async-signal-safe. Every Unix child becomes
        // the leader of a private process group before exec. A Linux
        // content-bound launch also clears CLOEXEC on the already-sealed
        // descriptor so a shebang interpreter can reopen `/proc/self/fd/N`;
        // the child can observe that immutable descriptor but cannot change its
        // sealed bytes. Explicit capability descriptors use the same narrow
        // inheritance rule, preserving any descriptor flags other than CLOEXEC.
        #[cfg(target_os = "linux")]
        let inherited_fds = spec.inherited_fds.clone();
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                #[cfg(target_os = "linux")]
                if let Some(fd) = bound_fd {
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                #[cfg(target_os = "linux")]
                for fd in &inherited_fds {
                    let flags = libc::fcntl(*fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(*fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }

    #[cfg(unix)]
    if let Err(error) = ensure_unix_child_reaper_contract() {
        return ChildOutcome::SpawnError(format!(
            "Unix child supervision contract is unavailable before spawn: {error}"
        ));
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return ChildOutcome::SpawnError(error.to_string()),
    };
    #[cfg(unix)]
    let child_pid = child.id();
    #[cfg(unix)]
    if let Err(error) = ensure_unix_child_reaper_contract() {
        let cleanup_deadline = Instant::now() + PROCESS_TREE_CLEANUP_TIMEOUT;
        let cleanup = cleanup_unconfirmed_direct_child(&mut child, child_pid, cleanup_deadline);
        return ChildOutcome::SpawnError(format!(
            "Unix child supervision contract changed during spawn: {error}; {cleanup}"
        ));
    }
    #[cfg(unix)]
    let process_group_confirmation = match confirm_process_group(child_pid) {
        Ok(confirmation) => confirmation,
        Err(error) => {
            let cleanup_deadline = Instant::now() + PROCESS_TREE_CLEANUP_TIMEOUT;
            let cleanup = cleanup_unconfirmed_direct_child(&mut child, child_pid, cleanup_deadline);
            return ChildOutcome::SpawnError(format!(
                "child process-group confirmation failed: {error}; {cleanup}"
            ));
        }
    };
    #[cfg(unix)]
    let process_group = process_group_confirmation.process_group;
    let (sender, receiver) = mpsc::channel();
    #[cfg(unix)]
    let mut reader_workers = Vec::with_capacity(2);
    if let Some(stdout) = child.stdout.take() {
        let worker = spawn_reader(
            stdout,
            CaptureStream::Stdout,
            spec.limits.stdout_bytes,
            sender.clone(),
        );
        #[cfg(unix)]
        reader_workers.push((CaptureStream::Stdout, worker));
        #[cfg(not(unix))]
        drop(worker);
    }
    if let Some(stderr) = child.stderr.take() {
        let worker = spawn_reader(
            stderr,
            CaptureStream::Stderr,
            spec.limits.stderr_bytes,
            sender,
        );
        #[cfg(unix)]
        reader_workers.push((CaptureStream::Stderr, worker));
        #[cfg(not(unix))]
        drop(worker);
    }

    let deadline = Instant::now() + spec.limits.timeout;
    #[cfg(unix)]
    let mut direct_exit_observed = process_group_confirmation.direct_exit_observed;
    #[cfg(unix)]
    let mut capture = CaptureState::default();
    #[cfg(not(unix))]
    let mut status = None;
    #[cfg(not(unix))]
    let mut stdout = None;
    #[cfg(not(unix))]
    let mut stderr = None;
    loop {
        while let Ok(message) = receiver.try_recv() {
            #[cfg(unix)]
            {
                let cause = match &message {
                    ReaderMessage::Complete(..) => None,
                    ReaderMessage::Limit(stream) => Some(UnixFinishCause::OutputLimit(*stream)),
                    ReaderMessage::Error(stream, reason) => {
                        Some(UnixFinishCause::ReaderError(*stream, reason.clone()))
                    }
                };
                if let Err(error) = capture.record(message) {
                    return finish_unix_run(
                        UnixFinishContext {
                            child: &mut child,
                            child_pid,
                            process_group,
                            receiver: &receiver,
                            workers: &mut reader_workers,
                            capture: &mut capture,
                        },
                        UnixFinishCause::WaitError(error),
                    );
                }
                if let Some(cause) = cause {
                    return finish_unix_run(
                        UnixFinishContext {
                            child: &mut child,
                            child_pid,
                            process_group,
                            receiver: &receiver,
                            workers: &mut reader_workers,
                            capture: &mut capture,
                        },
                        cause,
                    );
                }
            }
            #[cfg(not(unix))]
            {
                match message {
                    ReaderMessage::Complete(CaptureStream::Stdout, bytes) => stdout = Some(bytes),
                    ReaderMessage::Complete(CaptureStream::Stderr, bytes) => stderr = Some(bytes),
                    ReaderMessage::Limit(stream) => {
                        let killed = child.kill().is_ok();
                        let reaped = child.wait().is_ok();
                        return ChildOutcome::OutputLimitExceeded {
                            stream,
                            cleanup_succeeded: killed && reaped,
                        };
                    }
                    ReaderMessage::Error(stream, reason) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return ChildOutcome::WaitError(format!("read {stream:?}: {reason}"));
                    }
                }
            }
        }

        #[cfg(unix)]
        {
            if !direct_exit_observed {
                match observe_child_exit_without_reaping(child_pid, true) {
                    Ok(observed) => direct_exit_observed = observed,
                    Err(error) => {
                        return finish_unix_run(
                            UnixFinishContext {
                                child: &mut child,
                                child_pid,
                                process_group,
                                receiver: &receiver,
                                workers: &mut reader_workers,
                                capture: &mut capture,
                            },
                            UnixFinishCause::WaitError(error.to_string()),
                        );
                    }
                }
            }
            if direct_exit_observed {
                // Do not wait for EOF first. A successful direct child may have
                // left a descendant holding either captured pipe. Signal the
                // still-anchored group, then reap and join the readers under one
                // bounded cleanup deadline.
                return finish_unix_run(
                    UnixFinishContext {
                        child: &mut child,
                        child_pid,
                        process_group,
                        receiver: &receiver,
                        workers: &mut reader_workers,
                        capture: &mut capture,
                    },
                    UnixFinishCause::DirectExit,
                );
            }
        }
        #[cfg(not(unix))]
        {
            if status.is_none() {
                match child.try_wait() {
                    Ok(Some(exit)) => status = Some(exit),
                    Ok(None) => {}
                    Err(error) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return ChildOutcome::WaitError(error.to_string());
                    }
                }
            }
            if let Some(exit_status) = status {
                match (stdout.take(), stderr.take()) {
                    (Some(stdout_bytes), Some(stderr_bytes)) => {
                        return ChildOutcome::Completed {
                            status: exit_status,
                            stdout: stdout_bytes,
                            stderr: stderr_bytes,
                        };
                    }
                    (pending_stdout, pending_stderr) => {
                        stdout = pending_stdout;
                        stderr = pending_stderr;
                    }
                }
            }
        }
        if Instant::now() >= deadline {
            #[cfg(unix)]
            return finish_unix_run(
                UnixFinishContext {
                    child: &mut child,
                    child_pid,
                    process_group,
                    receiver: &receiver,
                    workers: &mut reader_workers,
                    capture: &mut capture,
                },
                UnixFinishCause::Timeout,
            );
            #[cfg(not(unix))]
            {
                let killed = child.kill().is_ok();
                let reaped = child.wait().is_ok();
                return ChildOutcome::Timeout {
                    cleanup_succeeded: killed && reaped,
                };
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
const PROCESS_TREE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(unix)]
const PROCESS_GROUP_CONFIRMATION_TIMEOUT: Duration = Duration::from_millis(100);
#[cfg(unix)]
const PROCESS_GROUP_CONFIRMATION_POLL: Duration = Duration::from_millis(1);
#[cfg(unix)]
const PROCESS_GROUP_CONFIRMATION_ATTEMPTS: usize = 32;
#[cfg(any(unix, windows))]
const PROCESS_SUPERVISOR_POLL: Duration = Duration::from_millis(10);

#[cfg(any(unix, windows))]
enum ReaderTerminal {
    Complete(Vec<u8>),
    Limit,
    Error(String),
}

#[cfg(any(unix, windows))]
#[derive(Default)]
struct CaptureState {
    stdout: Option<ReaderTerminal>,
    stderr: Option<ReaderTerminal>,
}

#[cfg(any(unix, windows))]
impl CaptureState {
    fn record(&mut self, message: ReaderMessage) -> Result<(), String> {
        let (stream, terminal) = match message {
            ReaderMessage::Complete(stream, bytes) => (stream, ReaderTerminal::Complete(bytes)),
            ReaderMessage::Limit(stream) => (stream, ReaderTerminal::Limit),
            ReaderMessage::Error(stream, reason) => (stream, ReaderTerminal::Error(reason)),
        };
        let slot = match stream {
            CaptureStream::Stdout => &mut self.stdout,
            CaptureStream::Stderr => &mut self.stderr,
        };
        if slot.is_some() {
            return Err(format!("capture worker reported {stream:?} more than once"));
        }
        *slot = Some(terminal);
        Ok(())
    }

    fn all_terminal(&self) -> bool {
        self.stdout.is_some() && self.stderr.is_some()
    }

    fn first_limit(&self) -> Option<CaptureStream> {
        if matches!(self.stdout.as_ref(), Some(ReaderTerminal::Limit)) {
            Some(CaptureStream::Stdout)
        } else if matches!(self.stderr.as_ref(), Some(ReaderTerminal::Limit)) {
            Some(CaptureStream::Stderr)
        } else {
            None
        }
    }

    fn first_error(&self) -> Option<(CaptureStream, String)> {
        if let Some(ReaderTerminal::Error(reason)) = &self.stdout {
            return Some((CaptureStream::Stdout, reason.clone()));
        }
        if let Some(ReaderTerminal::Error(reason)) = &self.stderr {
            return Some((CaptureStream::Stderr, reason.clone()));
        }
        None
    }

    fn take_completed(&mut self) -> Option<(Vec<u8>, Vec<u8>)> {
        let stdout = match self.stdout.take()? {
            ReaderTerminal::Complete(bytes) => bytes,
            other => {
                self.stdout = Some(other);
                return None;
            }
        };
        let stderr = match self.stderr.take()? {
            ReaderTerminal::Complete(bytes) => bytes,
            other => {
                self.stdout = Some(ReaderTerminal::Complete(stdout));
                self.stderr = Some(other);
                return None;
            }
        };
        Some((stdout, stderr))
    }
}

#[cfg(unix)]
enum UnixFinishCause {
    DirectExit,
    Timeout,
    OutputLimit(CaptureStream),
    ReaderError(CaptureStream, String),
    WaitError(String),
}

#[cfg(unix)]
struct UnixFinishContext<'a> {
    child: &'a mut std::process::Child,
    child_pid: u32,
    process_group: u32,
    receiver: &'a mpsc::Receiver<ReaderMessage>,
    workers: &'a mut Vec<(CaptureStream, std::thread::JoinHandle<()>)>,
    capture: &'a mut CaptureState,
}

#[cfg(unix)]
fn validate_unix_child_reaper_contract(handler: usize, flags: libc::c_int) -> std::io::Result<()> {
    if flags & libc::SA_NOCLDWAIT != 0 {
        return Err(std::io::Error::other(
            "SIGCHLD has SA_NOCLDWAIT set; direct-child PID/PGID ownership cannot be retained",
        ));
    }
    if handler == libc::SIG_IGN {
        return Err(std::io::Error::other(
            "SIGCHLD is ignored; direct children may be auto-reaped",
        ));
    }
    if handler != libc::SIG_DFL {
        return Err(std::io::Error::other(
            "SIGCHLD has a non-default handler; exclusive direct-child reaping cannot be proven",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_unix_child_reaper_contract() -> std::io::Result<()> {
    // SAFETY: a null `act` makes `sigaction` a read-only query, and `current`
    // is valid writable storage for the returned process-wide disposition.
    let mut current = unsafe { std::mem::zeroed::<libc::sigaction>() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut current) } != 0 {
        return Err(std::io::Error::other(format!(
            "cannot inspect SIGCHLD disposition: {}",
            std::io::Error::last_os_error()
        )));
    }
    validate_unix_child_reaper_contract(current.sa_sigaction, current.sa_flags)
}

/// Observe the direct child with `WNOWAIT`. Keeping its zombie unreaped reserves
/// the numeric PID/PGID until the complete group has received its final signal,
/// preventing a negative-PID signal from reaching an unrelated reused group.
#[cfg(unix)]
fn observe_child_exit_without_reaping(child_pid: u32, nonblocking: bool) -> std::io::Result<bool> {
    let mut flags = libc::WEXITED | libc::WNOWAIT;
    if nonblocking {
        flags |= libc::WNOHANG;
    }
    loop {
        // SAFETY: `info` is valid writable storage and waitid does not retain it.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result =
            unsafe { libc::waitid(libc::P_PID, child_pid as libc::id_t, &mut info, flags) };
        if result == 0 {
            return Ok(!nonblocking || unsafe { info.si_pid() } != 0);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessGroupConfirmation {
    process_group: u32,
    /// `waitid(WNOWAIT)` observed the direct child in a terminal state, so its
    /// unreaped PID still anchors the numeric process-group ID against reuse.
    direct_exit_observed: bool,
}

#[cfg(unix)]
fn classify_process_group_confirmation(
    child_pid: u32,
    process_group: Option<libc::pid_t>,
    direct_exit_observed: bool,
) -> std::io::Result<ProcessGroupConfirmation> {
    match process_group {
        Some(process_group) if process_group == child_pid as libc::pid_t => {
            Ok(ProcessGroupConfirmation {
                process_group: child_pid,
                direct_exit_observed,
            })
        }
        Some(process_group) => Err(std::io::Error::other(format!(
            "child {child_pid} joined unexpected process group {process_group}"
        ))),
        None if direct_exit_observed => {
            // `Command::spawn` reports an error when the pre-exec `setpgid`
            // hook fails, so a successfully spawned child did lead this exact
            // group before it exited. Keeping the terminal child unreaped
            // reserves its PID and therefore its PGID until group cleanup has
            // been attempted. It is safe to retain that anchored identifier;
            // it is not safe to do so for a still-live or unowned PID.
            Ok(ProcessGroupConfirmation {
                process_group: child_pid,
                direct_exit_observed: true,
            })
        }
        None => Err(std::io::Error::other(format!(
            "child {child_pid} disappeared before process-group confirmation while still reported live"
        ))),
    }
}

#[cfg(unix)]
fn confirm_process_group_with<Probe, ObserveExit, Retry>(
    child_pid: u32,
    mut probe: Probe,
    mut observe_exit: ObserveExit,
    mut retry: Retry,
) -> std::io::Result<ProcessGroupConfirmation>
where
    Probe: FnMut() -> std::io::Result<Option<libc::pid_t>>,
    ObserveExit: FnMut() -> std::io::Result<bool>,
    Retry: FnMut() -> bool,
{
    loop {
        let process_group = probe()?;
        // Pair every numeric group observation with proof that the PID is still
        // our direct child. Besides making the exited-child fallback safe, this
        // prevents an externally reaped and reused PID from authorizing an
        // unrelated group that happens to carry the same number.
        let direct_exit_observed = observe_exit().map_err(|error| {
            std::io::Error::other(format!(
                "child {child_pid} direct-child terminal-state confirmation failed: {error}"
            ))
        })?;
        if process_group.is_some() || direct_exit_observed || !retry() {
            return classify_process_group_confirmation(
                child_pid,
                process_group,
                direct_exit_observed,
            );
        }
    }
}

#[cfg(unix)]
fn confirm_process_group(child_pid: u32) -> std::io::Result<ProcessGroupConfirmation> {
    let deadline = Instant::now() + PROCESS_GROUP_CONFIRMATION_TIMEOUT;
    let mut attempts = 1_usize;
    confirm_process_group_with(
        child_pid,
        || loop {
            // SAFETY: `getpgid` only reads kernel process metadata for the
            // direct child PID returned by `Command::spawn`.
            let process_group = unsafe { libc::getpgid(child_pid as libc::pid_t) };
            if process_group >= 0 {
                return Ok(Some(process_group));
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(None);
            }
            return Err(error);
        },
        || observe_child_exit_without_reaping(child_pid, true),
        || {
            if attempts >= PROCESS_GROUP_CONFIRMATION_ATTEMPTS || Instant::now() >= deadline {
                return false;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            std::thread::sleep(remaining.min(PROCESS_GROUP_CONFIRMATION_POLL));
            attempts += 1;
            true
        },
    )
}

#[cfg(unix)]
fn signal_process_group_with<Contract, Confirm, ObserveExit, Send>(
    child_pid: u32,
    process_group: u32,
    mut contract: Contract,
    mut confirm: Confirm,
    mut observe_exit: ObserveExit,
    mut send: Send,
) -> std::io::Result<()>
where
    Contract: FnMut() -> std::io::Result<()>,
    Confirm: FnMut() -> std::io::Result<ProcessGroupConfirmation>,
    ObserveExit: FnMut() -> std::io::Result<bool>,
    Send: FnMut(bool) -> std::io::Result<()>,
{
    contract()?;
    let confirmation = confirm()?;
    if confirmation.process_group != process_group {
        return Err(std::io::Error::other(format!(
            "child {child_pid} process group changed from {process_group} to {}",
            confirmation.process_group
        )));
    }
    // Re-observe after group confirmation. A competing waiter that consumed
    // the child between those operations yields ECHILD here and prevents the
    // numeric group signal. The process-wide contract is checked once more
    // immediately before the signal to catch SIG_IGN/SA_NOCLDWAIT drift.
    let final_exit_observed = observe_exit().map_err(|error| {
        std::io::Error::other(format!(
            "child {child_pid} lost its direct-child ownership anchor before process-group signal: {error}"
        ))
    })?;
    if confirmation.direct_exit_observed && !final_exit_observed {
        return Err(std::io::Error::other(format!(
            "child {child_pid} terminal-state ownership proof became inconsistent before process-group signal"
        )));
    }
    contract()?;
    send(final_exit_observed)
}

#[cfg(unix)]
fn signal_process_group(
    child_pid: u32,
    process_group: u32,
    signal: libc::c_int,
) -> std::io::Result<()> {
    signal_process_group_with(
        child_pid,
        process_group,
        ensure_unix_child_reaper_contract,
        || confirm_process_group(child_pid),
        || observe_child_exit_without_reaping(child_pid, true),
        |final_exit_observed| {
            if unsafe { libc::kill(-(process_group as libc::pid_t), signal) } == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            // Some Unix kernels do not count an exited, unreaped leader as a
            // signalable group member. ESRCH after the final WNOWAIT ownership
            // observation proves no signalable member remained while the
            // zombie still reserved this numeric PID/PGID.
            if final_exit_observed && error.raw_os_error() == Some(libc::ESRCH) {
                Ok(())
            } else {
                Err(error)
            }
        },
    )
}

#[cfg(unix)]
fn wait_for_process_group_disappearance(process_group: u32, deadline: Instant) -> bool {
    let mut consecutive_quiescent_snapshots = 0;
    loop {
        #[cfg(target_os = "linux")]
        let live_members = linux_process_group_has_live_members(process_group);
        #[cfg(target_os = "macos")]
        let live_members = macos_process_group_has_live_members(process_group);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let live_members: Option<bool> = None;

        match live_members {
            Some(false) => {
                // A process snapshot is not atomic with concurrent exit. Require
                // two complete, quiescent observations before treating only
                // orphaned zombies as gone. Zombies cannot execute or retain a
                // capture pipe, so their eventual PID-1 reap is bookkeeping.
                consecutive_quiescent_snapshots += 1;
                if consecutive_quiescent_snapshots >= 2 {
                    return true;
                }
            }
            Some(true) | None => consecutive_quiescent_snapshots = 0,
        }
        if unsafe { libc::kill(-(process_group as libc::pid_t), 0) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                return true;
            }
            if error.raw_os_error() != Some(libc::EPERM) {
                return false;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(PROCESS_SUPERVISOR_POLL);
    }
}

#[cfg(target_os = "linux")]
fn linux_process_group_has_live_members(process_group: u32) -> Option<bool> {
    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries {
        let entry = entry.ok()?;
        let name = entry.file_name();
        if name.to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        let stat = match std::fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        let (_, fields) = stat.rsplit_once(") ")?;
        let mut fields = fields.split_whitespace();
        let state = fields.next()?;
        let _parent_pid = fields.next()?;
        let group = fields.next()?.parse::<u32>().ok()?;
        if group == process_group && !matches!(state, "Z" | "X") {
            return Some(true);
        }
    }
    Some(false)
}

#[cfg(target_os = "macos")]
fn macos_process_group_has_live_members(process_group: u32) -> Option<bool> {
    const PROCESS_LIST_SLACK: usize = 64;
    const PROCESS_LIST_ATTEMPTS: usize = 3;

    let process_group_pid = libc::pid_t::try_from(process_group).ok()?;
    let mut capacity = usize::try_from(unsafe {
        libc::proc_listpgrppids(process_group_pid, std::ptr::null_mut(), 0)
    })
    .ok()?
    .checked_add(PROCESS_LIST_SLACK)?;
    for _ in 0..PROCESS_LIST_ATTEMPTS {
        let mut pids: Vec<libc::pid_t> = vec![0; capacity];
        let byte_capacity = pids.len().checked_mul(std::mem::size_of::<libc::pid_t>())?;
        let byte_capacity = libc::c_int::try_from(byte_capacity).ok()?;
        let count = unsafe {
            libc::proc_listpgrppids(
                process_group_pid,
                pids.as_mut_ptr().cast::<libc::c_void>(),
                byte_capacity,
            )
        };
        let count = usize::try_from(count).ok()?;
        if count >= pids.len() {
            capacity = capacity.checked_mul(2)?;
            continue;
        }

        for pid in pids.into_iter().take(count).filter(|pid| *pid > 0) {
            let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
            let expected = std::mem::size_of::<libc::proc_bsdinfo>();
            let read = unsafe {
                libc::proc_pidinfo(
                    pid,
                    libc::PROC_PIDTBSDINFO,
                    0,
                    info.as_mut_ptr().cast(),
                    libc::c_int::try_from(expected).ok()?,
                )
            };
            if read == 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ESRCH)
                    || error.kind() == std::io::ErrorKind::NotFound
                {
                    continue;
                }
                return None;
            }
            if usize::try_from(read).ok()? != expected {
                return None;
            }
            let info = unsafe { info.assume_init() };
            if info.pbi_pgid == process_group && info.pbi_status != libc::SZOMB {
                return Some(true);
            }
        }
        return Some(false);
    }
    None
}

#[cfg(unix)]
struct TreeTermination {
    signal_succeeded: bool,
    signal_error: Option<String>,
    status: Option<ExitStatus>,
    group_disappeared: bool,
    reap_error: Option<String>,
}

#[cfg(unix)]
impl TreeTermination {
    fn cleanup_confirmed(&self) -> bool {
        // The security invariant is the final supervised state: the direct
        // child was reaped and a complete host process snapshot (or ESRCH)
        // proved that its process group has no live members. On macOS, sending
        // SIGKILL to a fast-exited, zombie-only group can return EPERM even
        // though that final state is subsequently proven. Treating the signal
        // syscall itself as mandatory turns successful bounded commands into
        // CleanupError without strengthening descendant containment. A failed
        // signal while any member remains live is still rejected because
        // `group_disappeared` stays false.
        self.status.is_some() && self.group_disappeared && self.reap_error.is_none()
    }

    fn failure_reason(&self) -> String {
        let mut reasons = Vec::new();
        if !self.signal_succeeded {
            reasons.push(match &self.signal_error {
                Some(error) => format!("process-group signal refused or failed: {error}"),
                None => "process-group signal failed".to_string(),
            });
        }
        if self.status.is_none() {
            reasons.push("direct child was not reaped before the cleanup deadline".to_string());
        }
        if !self.group_disappeared {
            reasons.push("process group remained present at the cleanup deadline".to_string());
        }
        if let Some(error) = &self.reap_error {
            reasons.push(format!("direct-child reap failed: {error}"));
        }
        if reasons.is_empty() {
            "unknown process-tree cleanup failure".to_string()
        } else {
            reasons.join("; ")
        }
    }
}

#[cfg(unix)]
fn wait_for_direct_exit_and_reap(
    child: &mut std::process::Child,
    child_pid: u32,
    deadline: Instant,
) -> Option<Result<ExitStatus, String>> {
    loop {
        match observe_child_exit_without_reaping(child_pid, true) {
            Ok(true) => return Some(child.wait().map_err(|error| error.to_string())),
            Ok(false) => {}
            Err(error) => return Some(Err(error.to_string())),
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(PROCESS_SUPERVISOR_POLL);
    }
}

#[cfg(unix)]
fn signal_direct_child_with<Contract, ObserveExit, Send>(
    child_pid: u32,
    mut contract: Contract,
    mut observe_exit: ObserveExit,
    mut send: Send,
) -> std::io::Result<bool>
where
    Contract: FnMut() -> std::io::Result<()>,
    ObserveExit: FnMut() -> std::io::Result<bool>,
    Send: FnMut() -> std::io::Result<()>,
{
    contract()?;
    if observe_exit()? {
        return Ok(false);
    }
    // The second observation is the deterministic external-reaper seam: if a
    // waiter consumed this child after the first live proof, ECHILD prevents
    // `Child::kill` from using a stale numeric PID.
    if observe_exit().map_err(|error| {
        std::io::Error::other(format!(
            "child {child_pid} lost its direct-child ownership anchor before direct signal: {error}"
        ))
    })? {
        return Ok(false);
    }
    contract()?;
    send()?;
    Ok(true)
}

#[cfg(unix)]
fn signal_direct_child(child: &mut std::process::Child, child_pid: u32) -> std::io::Result<bool> {
    signal_direct_child_with(
        child_pid,
        ensure_unix_child_reaper_contract,
        || observe_child_exit_without_reaping(child_pid, true),
        || child.kill(),
    )
}

#[cfg(unix)]
struct UnconfirmedDirectCleanup {
    reaped: bool,
    signal_error: Option<String>,
}

#[cfg(unix)]
impl fmt::Display for UnconfirmedDirectCleanup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "direct-child cleanup succeeded: {}", self.reaped)?;
        if let Some(error) = &self.signal_error {
            write!(formatter, "; numeric direct-child signal refused: {error}")?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn cleanup_unconfirmed_direct_child(
    child: &mut std::process::Child,
    child_pid: u32,
    deadline: Instant,
) -> UnconfirmedDirectCleanup {
    let signal_error = signal_direct_child(child, child_pid)
        .err()
        .map(|error| error.to_string());
    let reaped = matches!(
        wait_for_direct_exit_and_reap(child, child_pid, deadline),
        Some(Ok(_))
    );
    UnconfirmedDirectCleanup {
        reaped,
        signal_error,
    }
}

#[cfg(unix)]
fn terminate_tree(
    child: &mut std::process::Child,
    child_pid: u32,
    process_group: u32,
    deadline: Instant,
) -> TreeTermination {
    // Reconfirm the process-wide reaper contract and exact WNOWAIT ownership
    // immediately before signalling. The group signal includes its leader, so
    // a second numeric `Child::kill` would add only another reuse race.
    let (signal_succeeded, signal_error) =
        match signal_process_group(child_pid, process_group, libc::SIGKILL) {
            Ok(()) => (true, None),
            Err(error) => (false, Some(error.to_string())),
        };
    let reaped = wait_for_direct_exit_and_reap(child, child_pid, deadline);
    let (status, reap_error) = match reaped {
        Some(Ok(status)) => (Some(status), None),
        Some(Err(error)) => (None, Some(error)),
        None => (None, None),
    };
    let group_disappeared = wait_for_process_group_disappearance(process_group, deadline);
    TreeTermination {
        signal_succeeded,
        signal_error,
        status,
        group_disappeared,
        reap_error,
    }
}

#[cfg(any(unix, windows))]
fn finish_reader_workers(
    receiver: &mpsc::Receiver<ReaderMessage>,
    workers: &mut Vec<(CaptureStream, std::thread::JoinHandle<()>)>,
    capture: &mut CaptureState,
    deadline: Instant,
) -> Result<(), String> {
    while !capture.all_terminal() {
        while let Ok(message) = receiver.try_recv() {
            capture.record(message)?;
        }
        if capture.all_terminal() {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            return Err("capture pipes did not close before the cleanup deadline".to_string());
        }
        match receiver.recv_timeout((deadline - now).min(PROCESS_SUPERVISOR_POLL)) {
            Ok(message) => capture.record(message)?,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("capture workers disconnected before reporting both streams".into());
            }
        }
    }

    while workers.iter().any(|(_, worker)| !worker.is_finished()) {
        if Instant::now() >= deadline {
            let stuck = workers
                .iter()
                .filter_map(|(stream, worker)| {
                    (!worker.is_finished()).then_some(format!("{stream:?}"))
                })
                .collect::<Vec<_>>()
                .join(", ");
            workers.clear();
            return Err(format!("capture worker join deadline expired for {stuck}"));
        }
        std::thread::sleep(PROCESS_SUPERVISOR_POLL);
    }

    for (stream, worker) in std::mem::take(workers) {
        if worker.join().is_err() {
            return Err(format!("{stream:?} capture worker panicked"));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn finish_unix_run(context: UnixFinishContext<'_>, cause: UnixFinishCause) -> ChildOutcome {
    let cleanup_deadline = Instant::now() + PROCESS_TREE_CLEANUP_TIMEOUT;
    let termination = terminate_tree(
        context.child,
        context.child_pid,
        context.process_group,
        cleanup_deadline,
    );
    let reader_cleanup = finish_reader_workers(
        context.receiver,
        context.workers,
        context.capture,
        cleanup_deadline,
    );
    let cleanup_succeeded = termination.cleanup_confirmed() && reader_cleanup.is_ok();

    let output_limit = match &cause {
        UnixFinishCause::OutputLimit(stream) => Some(*stream),
        _ => context.capture.first_limit(),
    };
    if let Some(stream) = output_limit {
        return ChildOutcome::OutputLimitExceeded {
            stream,
            cleanup_succeeded,
        };
    }
    if matches!(&cause, UnixFinishCause::Timeout) {
        return ChildOutcome::Timeout { cleanup_succeeded };
    }

    if !cleanup_succeeded {
        let mut reasons = Vec::new();
        match &cause {
            UnixFinishCause::ReaderError(stream, reason) => {
                reasons.push(format!("read {stream:?}: {reason}"));
            }
            UnixFinishCause::WaitError(reason) => reasons.push(format!("wait failed: {reason}")),
            UnixFinishCause::DirectExit
            | UnixFinishCause::Timeout
            | UnixFinishCause::OutputLimit(_) => {}
        }
        if !termination.cleanup_confirmed() {
            reasons.push(termination.failure_reason());
        }
        if let Err(reason) = &reader_cleanup {
            reasons.push(reason.clone());
        }
        return ChildOutcome::CleanupError(reasons.join("; "));
    }

    match cause {
        UnixFinishCause::ReaderError(stream, reason) => {
            return ChildOutcome::WaitError(format!("read {stream:?}: {reason}"));
        }
        UnixFinishCause::WaitError(reason) => return ChildOutcome::WaitError(reason),
        UnixFinishCause::DirectExit
        | UnixFinishCause::Timeout
        | UnixFinishCause::OutputLimit(_) => {}
    }
    if let Some((stream, reason)) = context.capture.first_error() {
        return ChildOutcome::WaitError(format!("read {stream:?}: {reason}"));
    }
    let Some(status) = termination.status else {
        return ChildOutcome::CleanupError("direct child was not reaped".to_string());
    };
    let Some((stdout, stderr)) = context.capture.take_completed() else {
        return ChildOutcome::CleanupError(
            "capture workers completed without two bounded output buffers".to_string(),
        );
    };
    ChildOutcome::Completed {
        status,
        stdout,
        stderr,
    }
}

#[cfg(all(test, unix))]
mod unix_cleanup_tests {
    use super::{
        confirm_process_group_with, signal_direct_child_with, signal_process_group_with,
        validate_unix_child_reaper_contract, ProcessGroupConfirmation, TreeTermination,
    };
    use std::collections::VecDeque;
    use std::os::unix::process::ExitStatusExt as _;

    fn exited_child(signal_succeeded: bool, group_disappeared: bool) -> TreeTermination {
        TreeTermination {
            signal_succeeded,
            signal_error: (!signal_succeeded).then(|| "test signal failure".to_string()),
            status: Some(std::process::ExitStatus::from_raw(0)),
            group_disappeared,
            reap_error: None,
        }
    }

    #[test]
    fn cleanup_accepts_failed_signal_after_no_live_group_is_proven() {
        assert!(exited_child(false, true).cleanup_confirmed());
    }

    #[test]
    fn cleanup_still_rejects_a_live_group_or_unreaped_child() {
        assert!(!exited_child(true, false).cleanup_confirmed());
        assert!(!exited_child(false, false).cleanup_confirmed());

        let unreaped = TreeTermination {
            signal_succeeded: true,
            signal_error: None,
            status: None,
            group_disappeared: true,
            reap_error: None,
        };
        assert!(!unreaped.cleanup_confirmed());
    }

    #[test]
    fn exited_child_is_accepted_with_an_unreaped_terminal_state() {
        let child_pid = 41_001;
        let confirmed = confirm_process_group_with(
            child_pid,
            || Ok(None),
            || Ok(true),
            || panic!("a terminal direct child must not retry"),
        )
        .expect("an exited direct child must retain its pre-exec group anchor");
        assert_eq!(
            confirmed,
            ProcessGroupConfirmation {
                process_group: child_pid,
                direct_exit_observed: true,
            }
        );
    }

    #[test]
    fn missing_live_snapshot_retries_until_terminal_proof_arrives() {
        let child_pid = 41_002;
        let mut groups = VecDeque::from([None, None]);
        let mut exits = VecDeque::from([false, true]);
        let mut retries = 0;
        let confirmed = confirm_process_group_with(
            child_pid,
            || Ok(groups.pop_front().expect("group probe sequence exhausted")),
            || Ok(exits.pop_front().expect("exit probe sequence exhausted")),
            || {
                retries += 1;
                true
            },
        )
        .expect("a later terminal snapshot must retain the anchored group");
        assert_eq!(retries, 1);
        assert_eq!(
            confirmed,
            ProcessGroupConfirmation {
                process_group: child_pid,
                direct_exit_observed: true,
            }
        );
    }

    #[test]
    fn missing_live_snapshot_retries_until_exact_group_appears() {
        let child_pid = 41_003;
        let mut groups = VecDeque::from([None, Some(child_pid as libc::pid_t)]);
        let mut exits = VecDeque::from([false, false]);
        let mut retries = 0;
        let confirmed = confirm_process_group_with(
            child_pid,
            || Ok(groups.pop_front().expect("group probe sequence exhausted")),
            || Ok(exits.pop_front().expect("exit probe sequence exhausted")),
            || {
                retries += 1;
                true
            },
        )
        .expect("the exact group must be accepted on a bounded retry");
        assert_eq!(retries, 1);
        assert_eq!(
            confirmed,
            ProcessGroupConfirmation {
                process_group: child_pid,
                direct_exit_observed: false,
            }
        );
    }

    #[test]
    fn unexpected_process_group_is_never_adopted() {
        let child_pid = 41_004;
        let unrelated_group = child_pid + 1;
        let error = confirm_process_group_with(
            child_pid,
            || Ok(Some(unrelated_group as libc::pid_t)),
            || Ok(false),
            || panic!("an unexpected process group must fail without retry"),
        )
        .expect_err("an unrelated group must never become a signal target");
        assert!(error
            .to_string()
            .contains(&format!("unexpected process group {unrelated_group}")));
    }

    #[test]
    fn unowned_pid_is_never_adopted() {
        let child_pid = 41_005;
        let error = confirm_process_group_with(
            child_pid,
            || Ok(Some(child_pid as libc::pid_t)),
            || Err(std::io::Error::from_raw_os_error(libc::ECHILD)),
            || panic!("an unowned PID must fail without retry"),
        )
        .expect_err("an unowned PID cannot safely anchor a process-group signal");
        assert!(error
            .to_string()
            .contains("terminal-state confirmation failed"));
    }

    #[test]
    fn live_missing_child_fails_when_retry_deadline_is_exhausted() {
        let child_pid = 41_006;
        let mut group_probes = 0;
        let mut exit_probes = 0;
        let mut retries = 0;
        let error = confirm_process_group_with(
            child_pid,
            || {
                group_probes += 1;
                Ok(None)
            },
            || {
                exit_probes += 1;
                Ok(false)
            },
            || {
                retries += 1;
                retries < 3
            },
        )
        .expect_err("a live missing group must fail closed at the retry deadline");
        assert_eq!(group_probes, 3);
        assert_eq!(exit_probes, 3);
        assert_eq!(retries, 3);
        assert!(error.to_string().contains("while still reported live"));
    }

    #[test]
    fn sigchld_contract_requires_default_waitable_children() {
        validate_unix_child_reaper_contract(libc::SIG_DFL, 0)
            .expect("the default waitable-child disposition is the contract");

        let ignored = validate_unix_child_reaper_contract(libc::SIG_IGN, 0)
            .expect_err("SIG_IGN auto-reaping must be rejected");
        assert!(ignored.to_string().contains("ignored"));

        let no_wait = validate_unix_child_reaper_contract(libc::SIG_DFL, libc::SA_NOCLDWAIT)
            .expect_err("SA_NOCLDWAIT must be rejected");
        assert!(no_wait.to_string().contains("SA_NOCLDWAIT"));

        let custom = validate_unix_child_reaper_contract(2, 0)
            .expect_err("a custom handler can reap behind the supervisor");
        assert!(custom.to_string().contains("non-default handler"));
    }

    #[test]
    fn external_reap_before_group_signal_never_reaches_numeric_send() {
        let child_pid = 41_007;
        let mut sends = 0;
        let error = signal_process_group_with(
            child_pid,
            child_pid,
            || Ok(()),
            || {
                Ok(ProcessGroupConfirmation {
                    process_group: child_pid,
                    direct_exit_observed: false,
                })
            },
            || Err(std::io::Error::from_raw_os_error(libc::ECHILD)),
            |_| {
                sends += 1;
                Ok(())
            },
        )
        .expect_err("an external reap must invalidate the group signal anchor");
        assert!(error
            .to_string()
            .contains("lost its direct-child ownership"));
        assert_eq!(sends, 0);
    }

    #[test]
    fn sigchld_contract_drift_before_group_signal_never_reaches_send() {
        let child_pid = 41_008;
        let mut contract_checks = 0;
        let mut sends = 0;
        let error = signal_process_group_with(
            child_pid,
            child_pid,
            || {
                contract_checks += 1;
                if contract_checks == 1 {
                    Ok(())
                } else {
                    Err(std::io::Error::other("SIGCHLD contract changed"))
                }
            },
            || {
                Ok(ProcessGroupConfirmation {
                    process_group: child_pid,
                    direct_exit_observed: false,
                })
            },
            || Ok(false),
            |_| {
                sends += 1;
                Ok(())
            },
        )
        .expect_err("a changed process-wide contract must refuse group signalling");
        assert_eq!(contract_checks, 2);
        assert_eq!(sends, 0);
        assert!(error.to_string().contains("contract changed"));
    }

    #[test]
    fn external_reap_before_direct_signal_never_reaches_child_kill() {
        let child_pid = 41_009;
        let mut observations = 0;
        let mut sends = 0;
        let error = signal_direct_child_with(
            child_pid,
            || Ok(()),
            || {
                observations += 1;
                if observations == 1 {
                    Ok(false)
                } else {
                    Err(std::io::Error::from_raw_os_error(libc::ECHILD))
                }
            },
            || {
                sends += 1;
                Ok(())
            },
        )
        .expect_err("a consumed direct child must invalidate Child::kill");
        assert_eq!(observations, 2);
        assert_eq!(sends, 0);
        assert!(error
            .to_string()
            .contains("lost its direct-child ownership"));
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod linux_acl_policy_tests {
    use super::reject_unix_extended_acl;
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Path;

    const ACL_USER_OBJ: u16 = 0x01;
    const ACL_USER: u16 = 0x02;
    const ACL_GROUP_OBJ: u16 = 0x04;
    const ACL_GROUP: u16 = 0x08;
    const ACL_MASK: u16 = 0x10;
    const ACL_OTHER: u16 = 0x20;

    fn acl_blob(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut blob = 2_u32.to_le_bytes().to_vec();
        for (tag, perm, id) in entries {
            blob.extend_from_slice(&tag.to_le_bytes());
            blob.extend_from_slice(&perm.to_le_bytes());
            blob.extend_from_slice(&id.to_le_bytes());
        }
        blob
    }

    fn set_default_acl(path: &Path, blob: &[u8]) {
        let path_bytes = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: both pointers reference live NUL-terminated / sized buffers.
        let status = unsafe {
            libc::setxattr(
                path_bytes.as_ptr(),
                c"system.posix_acl_default".as_ptr(),
                blob.as_ptr().cast(),
                blob.len(),
                0,
            )
        };
        assert_eq!(status, 0, "setxattr: {}", std::io::Error::last_os_error());
    }

    const UNDEFINED_ID: u32 = u32::MAX;

    #[test]
    fn default_acl_granting_current_user_write_is_accepted() {
        let temp = tempfile::tempdir().expect("tempdir");
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        // The shape GitHub runners seed on /home: a self-grant plus base entries.
        set_default_acl(
            temp.path(),
            &acl_blob(&[
                (ACL_USER_OBJ, 7, UNDEFINED_ID),
                (ACL_USER, 7, euid),
                (ACL_GROUP_OBJ, 5, UNDEFINED_ID),
                (ACL_MASK, 7, UNDEFINED_ID),
                (ACL_OTHER, 5, UNDEFINED_ID),
            ]),
        );
        reject_unix_extended_acl(temp.path(), true).expect("self-grant default ACL is benign");
    }

    #[test]
    fn default_acl_granting_foreign_user_write_is_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        // SAFETY: geteuid has no preconditions.
        let foreign = unsafe { libc::geteuid() }.wrapping_add(31_337);
        set_default_acl(
            temp.path(),
            &acl_blob(&[
                (ACL_USER_OBJ, 7, UNDEFINED_ID),
                (ACL_USER, 7, foreign),
                (ACL_GROUP_OBJ, 5, UNDEFINED_ID),
                (ACL_MASK, 7, UNDEFINED_ID),
                (ACL_OTHER, 5, UNDEFINED_ID),
            ]),
        );
        let reason = reject_unix_extended_acl(temp.path(), true)
            .expect_err("foreign write grant must stay rejected");
        assert!(reason.contains("mutation authority"), "{reason}");
    }

    #[test]
    fn default_acl_read_only_foreign_entries_are_accepted_but_group_write_is_not() {
        let temp = tempfile::tempdir().expect("tempdir");
        // SAFETY: geteuid has no preconditions.
        let foreign = unsafe { libc::geteuid() }.wrapping_add(31_337);
        set_default_acl(
            temp.path(),
            &acl_blob(&[
                (ACL_USER_OBJ, 7, UNDEFINED_ID),
                (ACL_USER, 5, foreign),
                (ACL_GROUP_OBJ, 5, UNDEFINED_ID),
                (ACL_MASK, 7, UNDEFINED_ID),
                (ACL_OTHER, 5, UNDEFINED_ID),
            ]),
        );
        reject_unix_extended_acl(temp.path(), true)
            .expect("read-only foreign entries add no mutation authority");

        set_default_acl(
            temp.path(),
            &acl_blob(&[
                (ACL_USER_OBJ, 7, UNDEFINED_ID),
                (ACL_GROUP_OBJ, 5, UNDEFINED_ID),
                (ACL_GROUP, 7, 12_345),
                (ACL_MASK, 7, UNDEFINED_ID),
                (ACL_OTHER, 5, UNDEFINED_ID),
            ]),
        );
        let reason = reject_unix_extended_acl(temp.path(), true)
            .expect_err("named-group write must stay rejected");
        assert!(reason.contains("mutation authority"), "{reason}");
    }
}
