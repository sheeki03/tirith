//! Content-addressed quarantine store for the package firewall (PR D1).
//!
//! The package firewall never installs the bytes a resolver downloaded directly:
//! it lands them in a quarantine, inspects them ([`crate::artifact::inspect`] in
//! D3), and only ever installs the exact, re-verified bytes from here (D4). This
//! module is the storage layer those later units stand on. It does no resolving,
//! no inspection, and no policy evaluation; it only stores, verifies, copies, and
//! garbage-collects content-addressed blobs.
//!
//! # Layout
//!
//! Under a single quarantine root (`data_dir()/quarantine` in production, an
//! explicit root in tests):
//!
//! ```text
//! <root>/blobs/sha256/<digest>                         immutable verified blob
//! <root>/transactions/<txn-id>/<validated-name>.whl    immutable copy of a blob
//! <root>/transactions/<txn-id>/.lock                    per-transaction file lock
//! ```
//!
//! * The **blob store** is keyed by the lowercase-hex SHA-256 of the content. A
//!   blob is written once, verified against the digest the caller expected, and
//!   thereafter treated as immutable (mode `0o400` on unix). Re-ingesting the same
//!   bytes is idempotent: an existing blob with the right digest is reused, never
//!   rewritten.
//! * A **transaction** is the per-install workspace. Each artifact is materialised
//!   as a *copy* of the blob under a validated `*.whl` filename, re-hashed after
//!   the copy so the file the installer later sees is provably the same content as
//!   the verified blob. The plan forbids a mutable hardlink here precisely so a
//!   later mutation of one name cannot silently change the other; an independent
//!   immutable copy has no shared inode to mutate.
//!
//! # Why a copy and a re-hash, not a hardlink
//!
//! D4 installs from the transaction file, re-binding the approval against its hash
//! immediately before launch (plan invariant 4). If the transaction entry shared
//! an inode with the blob (a hardlink), an attacker who could write the blob path
//! could mutate the installed bytes through the link after inspection. An
//! immutable `0o400` copy, re-hashed at copy time and re-hashed again at install
//! time, closes that: there is no shared mutable inode, and any drift is caught by
//! the re-hash.
//!
//! # Atomicity and TOCTOU
//!
//! Every publish writes a temp file *inside the destination directory* and then
//! `rename`s it onto the final name. A same-directory rename is atomic and stays
//! on one device, so a reader sees either no file or the whole file, never a torn
//! one, and there is no cross-device copy that a `rename` would reject. The temp
//! name is random ([`tempfile::NamedTempFile`] via
//! [`crate::util::write_file_atomic_0600`] for small control files; an explicit
//! `O_EXCL`-created temp for blob bodies), so there is no predictable path to
//! pre-create or race.
//!
//! Hashing is done from an open handle that was opened no-follow and `fstat`'d
//! (via [`crate::util::open_read_no_follow_capped`] + `try_clone`), mirroring the
//! single-handle pattern in [`crate::artifact::inspect`]: the bytes hashed are the
//! bytes of the inode we opened, so a path swap between open and hash cannot
//! substitute a different file.
//!
//! # Containment
//!
//! Transaction ids and filenames are validated to be a single safe path component
//! (no separators, no `..`, no NUL, no absolute drive), and every resolved path is
//! gated through [`crate::util::canonical_within`] against the canonical
//! quarantine root, so neither a crafted id nor a symlinked intermediate directory
//! can escape the store.
//!
//! # Permissions
//!
//! On unix the store directories are `0o700` and blob / transaction files are
//! `0o400` once published (a verified blob is immutable; only GC removes it). On
//! Windows the equivalent intent is a restrictive DACL (the owning user plus
//! `SYSTEM`); D4 additionally grants the install AppContainer SID *temporarily*
//! and revokes it after. That per-container grant is modelled here as a tracked
//! [`crate::capsule::windows::AclGrant`] list the executor applies and revokes,
//! the same pure-data pattern the Windows capsule backend uses, so no Win32 call
//! and no `windows`-crate dependency leak into `tirith-core`.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use fs2::FileExt;

use crate::artifact::archive::is_wheel_filename;
use crate::artifact::inspect::ARTIFACT_MAX_FILE_SIZE;
use crate::util::{
    self, canonical_within, create_dir_durable, open_read_no_follow_capped, HashOutcome,
    OpenRegularError,
};

/// The directory name under the quarantine root holding content-addressed blobs.
const BLOBS_DIR: &str = "blobs";
/// The hash-algorithm subdirectory under [`BLOBS_DIR`]. A sibling for a future
/// algorithm keeps the on-disk layout self-describing.
const SHA256_DIR: &str = "sha256";
/// The directory name under the quarantine root holding per-install transactions.
const TRANSACTIONS_DIR: &str = "transactions";
/// The per-transaction lock file name (held exclusively for the lease).
const LOCK_FILE: &str = ".lock";

/// Why a quarantine operation could not complete. Every variant is fail-closed:
/// the caller never proceeds with an unverified or mis-located artifact.
#[derive(Debug)]
pub enum QuarantineError {
    /// The quarantine root could not be resolved (`data_dir()` returned `None`).
    NoDataDir,
    /// A transaction id was not a single safe path component (empty, contained a
    /// path separator / `..` / NUL, or an absolute / drive-qualified form).
    InvalidTransactionId(String),
    /// A destination filename was not a single safe `*.whl` component.
    InvalidFilename(String),
    /// The bytes written hashed to a digest other than the one the caller said to
    /// expect: `{expected}` vs `{actual}`. The artifact is rejected, never stored.
    DigestMismatch { expected: String, actual: String },
    /// The source blob to copy into a transaction does not exist in the store.
    BlobNotFound(String),
    /// A resolved path escaped the canonical quarantine root (a crafted id or a
    /// symlinked intermediate directory). Fail-closed.
    PathEscape(PathBuf),
    /// The artifact exceeded [`ARTIFACT_MAX_FILE_SIZE`] while hashing, so it was
    /// never fully read or stored.
    TooLarge,
    /// An underlying filesystem error (open / write / rename / lock / stat).
    Io(std::io::Error),
}

impl std::fmt::Display for QuarantineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuarantineError::NoDataDir => {
                write!(
                    f,
                    "cannot resolve the tirith data directory for the quarantine"
                )
            }
            QuarantineError::InvalidTransactionId(id) => {
                write!(f, "invalid quarantine transaction id {id:?}")
            }
            QuarantineError::InvalidFilename(name) => {
                write!(f, "invalid quarantine artifact filename {name:?}")
            }
            QuarantineError::DigestMismatch { expected, actual } => {
                write!(
                    f,
                    "quarantine content hash mismatch: expected {expected}, got {actual}"
                )
            }
            QuarantineError::BlobNotFound(d) => {
                write!(f, "no quarantined blob for digest {d}")
            }
            QuarantineError::PathEscape(p) => {
                write!(f, "quarantine path escapes the store root: {}", p.display())
            }
            QuarantineError::TooLarge => write!(f, "artifact exceeds the quarantine size ceiling"),
            QuarantineError::Io(e) => write!(f, "quarantine I/O error: {e}"),
        }
    }
}

impl std::error::Error for QuarantineError {}

impl From<std::io::Error> for QuarantineError {
    fn from(e: std::io::Error) -> Self {
        QuarantineError::Io(e)
    }
}

/// A content-addressed quarantine store rooted at a single directory.
///
/// Construct with [`QuarantineStore::open`] in production (resolves
/// `data_dir()/quarantine`) or [`QuarantineStore::with_root`] in tests (an
/// explicit root). Opening creates the `blobs/sha256` and `transactions`
/// subtrees `0o700` (unix) if absent.
#[derive(Debug, Clone)]
pub struct QuarantineStore {
    root: PathBuf,
}

impl QuarantineStore {
    /// Open (creating if absent) the production quarantine under
    /// `data_dir()/quarantine`. Returns [`QuarantineError::NoDataDir`] when the
    /// data directory cannot be resolved.
    pub fn open() -> Result<Self, QuarantineError> {
        let base = crate::policy::data_dir().ok_or(QuarantineError::NoDataDir)?;
        Self::with_root(base.join("quarantine"))
    }

    /// Open (creating if absent) a quarantine rooted at an explicit directory.
    /// The `blobs/sha256` and `transactions` subtrees are created `0o700` on unix.
    pub fn with_root(root: PathBuf) -> Result<Self, QuarantineError> {
        let store = QuarantineStore { root };
        create_dir_durable(&store.root)?;
        harden_dir_perms(&store.root)?;
        create_dir_durable(&store.blobs_sha256_dir())?;
        harden_dir_perms(&store.blobs_dir())?;
        harden_dir_perms(&store.blobs_sha256_dir())?;
        create_dir_durable(&store.transactions_dir())?;
        harden_dir_perms(&store.transactions_dir())?;
        Ok(store)
    }

    /// The quarantine root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn blobs_dir(&self) -> PathBuf {
        self.root.join(BLOBS_DIR)
    }

    fn blobs_sha256_dir(&self) -> PathBuf {
        self.blobs_dir().join(SHA256_DIR)
    }

    fn transactions_dir(&self) -> PathBuf {
        self.root.join(TRANSACTIONS_DIR)
    }

    /// The content-addressed path a blob with `digest` (lowercase hex) lives at.
    /// Does not check existence.
    pub fn blob_path(&self, digest: &str) -> PathBuf {
        self.blobs_sha256_dir().join(digest)
    }

    /// Whether a verified blob for `digest` is present in the store.
    pub fn has_blob(&self, digest: &str) -> bool {
        if !is_hex_sha256(digest) {
            return false;
        }
        self.blob_path(digest).is_file()
    }

    /// Ingest `bytes` as a content-addressed blob, verifying the content hashes to
    /// `expected_digest` (lowercase hex). Idempotent: an existing blob with the
    /// right digest is reused without rewriting. Returns the digest on success
    /// (always `== expected_digest` normalised to lowercase).
    ///
    /// The body is written to a random `O_EXCL` temp *inside* the blob directory,
    /// fsync'd, re-hashed from its own no-follow handle, then atomically renamed
    /// onto the content-addressed name. A hash mismatch removes the temp and fails
    /// with [`QuarantineError::DigestMismatch`]; nothing is published.
    pub fn ingest_bytes(
        &self,
        bytes: &[u8],
        expected_digest: &str,
    ) -> Result<String, QuarantineError> {
        let expected = expected_digest.to_ascii_lowercase();
        if !is_hex_sha256(&expected) {
            return Err(QuarantineError::DigestMismatch {
                expected: expected_digest.to_string(),
                actual: "<not a sha256 hex string>".to_string(),
            });
        }
        let final_path = self.blob_path(&expected);
        // Idempotent fast path: an already-published blob is immutable, so if the
        // content-addressed name exists we trust it (its name IS its verified
        // hash) and skip the rewrite. A later install re-hashes regardless.
        if final_path.is_file() {
            return Ok(expected);
        }

        let blob_dir = self.blobs_sha256_dir();
        create_dir_durable(&blob_dir)?;
        // Write the body to a random temp INSIDE the destination directory so the
        // publish is a same-device, atomic rename and the temp name is not
        // predictable.
        let (mut tmp, tmp_path) = create_excl_temp(&blob_dir)?;
        let write_then_hash = (|| -> Result<String, QuarantineError> {
            use std::io::Write as _;
            tmp.write_all(bytes)?;
            tmp.sync_all()?;
            // Re-hash from a fresh no-follow handle on the temp we just wrote, so
            // the verified digest is over the bytes actually on disk.
            let actual = hash_file_no_follow(&tmp_path)?;
            if actual != expected {
                return Err(QuarantineError::DigestMismatch { expected, actual });
            }
            Ok(actual)
        })();
        let digest = match write_then_hash {
            Ok(d) => d,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(e);
            }
        };
        // Publish: atomic same-directory rename, then immutable perms + durability.
        std::fs::rename(&tmp_path, &final_path)?;
        harden_file_perms_immutable(&final_path)?;
        util::fsync_parent_dir_logged(&final_path, "quarantine blob publish");
        // Containment belt-and-braces: the published path must resolve inside root.
        if !canonical_within(&final_path, &self.root) {
            let _ = std::fs::remove_file(&final_path);
            return Err(QuarantineError::PathEscape(final_path));
        }
        Ok(digest)
    }

    /// Ingest an artifact already on disk at `src` whose content is expected to
    /// hash to `expected_digest`. Streams the bytes through a no-follow handle and
    /// re-hashes before publishing, identical verification to [`ingest_bytes`].
    pub fn ingest_file(
        &self,
        src: &Path,
        expected_digest: &str,
    ) -> Result<String, QuarantineError> {
        let bytes = match util::read_text_no_follow_capped(src, ARTIFACT_MAX_FILE_SIZE) {
            Ok(b) => b,
            Err(OpenRegularError::TooLarge) => return Err(QuarantineError::TooLarge),
            Err(OpenRegularError::Io(e)) => return Err(QuarantineError::Io(e)),
            Err(OpenRegularError::NotFound) | Err(OpenRegularError::NotRegularFile) => {
                return Err(QuarantineError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "source artifact is absent or not a regular file",
                )))
            }
        };
        self.ingest_bytes(&bytes, expected_digest)
    }

    /// Begin a transaction with the given id, acquiring an exclusive lease on it.
    /// The id must be a single safe path component. Creates
    /// `transactions/<id>/` `0o700` (unix) if absent and holds an exclusive lock
    /// on `transactions/<id>/.lock` for the lifetime of the returned
    /// [`QuarantineTransaction`]. Two concurrent leases of the same id cannot both
    /// be held.
    pub fn begin_transaction(
        &self,
        txn_id: &str,
    ) -> Result<QuarantineTransaction, QuarantineError> {
        validate_component(txn_id)
            .map_err(|_| QuarantineError::InvalidTransactionId(txn_id.to_string()))?;
        let dir = self.transactions_dir().join(txn_id);
        create_dir_durable(&dir)?;
        harden_dir_perms(&dir)?;
        if !canonical_within(&dir, &self.root) {
            return Err(QuarantineError::PathEscape(dir));
        }
        let lock_path = dir.join(LOCK_FILE);
        let lock_file = open_lock_file(&lock_path)?;
        // Exclusive lease: fail-closed if another holder has it (non-blocking try,
        // so a stuck holder does not hang an install).
        lock_file
            .try_lock_exclusive()
            .map_err(QuarantineError::Io)?;
        Ok(QuarantineTransaction {
            store: self.clone(),
            id: txn_id.to_string(),
            dir,
            _lock: lock_file,
        })
    }

    /// Garbage-collect transactions whose directory mtime is older than `max_age`,
    /// returning the number removed. A transaction currently leased by another
    /// process is skipped (its `.lock` is held), so GC never races a live install.
    /// Blobs are GC'd separately by [`gc_unreferenced_blobs`].
    pub fn gc_transactions(&self, max_age: Duration) -> Result<usize, QuarantineError> {
        let now = SystemTime::now();
        let mut removed = 0usize;
        let txns = self.transactions_dir();
        let entries = match std::fs::read_dir(&txns) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(QuarantineError::Io(e)),
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            // Containment: never recurse-remove anything that resolves outside root.
            if !canonical_within(&path, &self.root) {
                continue;
            }
            let aged_out = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .map(|age| age >= max_age)
                .unwrap_or(false);
            if !aged_out {
                continue;
            }
            // Skip a transaction another holder is leasing: a successful
            // non-blocking exclusive lock proves no live lease, then we drop it
            // and remove. If we cannot take the lock, a live install owns it.
            let lock_path = path.join(LOCK_FILE);
            let held = match open_lock_file(&lock_path) {
                Ok(f) => match f.try_lock_exclusive() {
                    Ok(()) => {
                        let _ = FileExt::unlock(&f);
                        false
                    }
                    Err(_) => true,
                },
                // No lock file (or unopenable): treat as not-leased and reclaim.
                Err(_) => false,
            };
            if held {
                continue;
            }
            if std::fs::remove_dir_all(&path).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Garbage-collect blobs whose digest is not in `referenced` (lowercase-hex
    /// digests still needed by live transactions / receipts), returning the number
    /// removed. The caller supplies the live set; this module does not track
    /// references itself.
    pub fn gc_unreferenced_blobs(
        &self,
        referenced: &std::collections::BTreeSet<String>,
    ) -> Result<usize, QuarantineError> {
        let mut removed = 0usize;
        let dir = self.blobs_sha256_dir();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(QuarantineError::Io(e)),
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            // Only ever touch well-formed content-addressed names we resolve inside
            // root; anything else is left alone (fail-safe).
            if !is_hex_sha256(name) || !canonical_within(&path, &self.root) {
                continue;
            }
            if referenced.contains(name) {
                continue;
            }
            if remove_immutable_file(&path).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

/// An open quarantine transaction holding an exclusive lease on its id.
///
/// Materialise artifacts into it with [`materialize_blob`]; the lease is released
/// when this value is dropped (the `.lock` handle unlocks on close).
#[derive(Debug)]
pub struct QuarantineTransaction {
    store: QuarantineStore,
    id: String,
    dir: PathBuf,
    /// Held for the lease; unlocked on drop.
    _lock: File,
}

impl QuarantineTransaction {
    /// The transaction id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The transaction directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The store this transaction belongs to, so the resolver (D2) can ingest a
    /// freshly downloaded wheel as a content-addressed blob while holding the
    /// transaction's lease. The store is a cheap handle clone; the lease that
    /// guards the install is this transaction value's lifetime, not the store's.
    pub fn store(&self) -> &QuarantineStore {
        &self.store
    }

    /// Copy the blob `digest` into this transaction under `filename`, returning the
    /// published path. `filename` must be a single safe `*.whl` component. The copy
    /// is an INDEPENDENT immutable file (no shared inode with the blob): the bytes
    /// are streamed from the blob through a no-follow handle, re-hashed, and only
    /// published (atomic same-dir rename, `0o400`) if the re-hash equals `digest`.
    pub fn materialize_blob(
        &self,
        digest: &str,
        filename: &str,
    ) -> Result<PathBuf, QuarantineError> {
        let digest = digest.to_ascii_lowercase();
        if !is_hex_sha256(&digest) {
            return Err(QuarantineError::BlobNotFound(digest));
        }
        validate_wheel_filename(filename)
            .map_err(|_| QuarantineError::InvalidFilename(filename.to_string()))?;
        let src = self.store.blob_path(&digest);
        if !src.is_file() {
            return Err(QuarantineError::BlobNotFound(digest));
        }
        // Stream the blob bytes from a no-follow handle (the source is our own
        // immutable blob, but reading no-follow keeps the contract uniform).
        let bytes = match util::read_text_no_follow_capped(&src, ARTIFACT_MAX_FILE_SIZE) {
            Ok(b) => b,
            Err(OpenRegularError::TooLarge) => return Err(QuarantineError::TooLarge),
            Err(OpenRegularError::Io(e)) => return Err(QuarantineError::Io(e)),
            Err(OpenRegularError::NotFound) | Err(OpenRegularError::NotRegularFile) => {
                return Err(QuarantineError::BlobNotFound(digest))
            }
        };
        let dest = self.dir.join(filename);
        if !canonical_within(&dest, &self.store.root) {
            return Err(QuarantineError::PathEscape(dest));
        }
        // Write a random temp INSIDE the transaction dir, fsync, re-hash, then
        // atomic same-dir rename onto the validated name.
        let (mut tmp, tmp_path) = create_excl_temp(&self.dir)?;
        let write_then_hash = (|| -> Result<(), QuarantineError> {
            use std::io::Write as _;
            tmp.write_all(&bytes)?;
            tmp.sync_all()?;
            let actual = hash_file_no_follow(&tmp_path)?;
            if actual != digest {
                return Err(QuarantineError::DigestMismatch {
                    expected: digest.clone(),
                    actual,
                });
            }
            Ok(())
        })();
        if let Err(e) = write_then_hash {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }
        std::fs::rename(&tmp_path, &dest)?;
        harden_file_perms_immutable(&dest)?;
        util::fsync_parent_dir_logged(&dest, "quarantine transaction publish");
        Ok(dest)
    }

    /// The Windows DACL grants D4 must apply to this transaction's directory before
    /// running the install in a container, and **revoke** afterwards: read+execute
    /// on the transaction dir for the install AppContainer's package SID (the SID is
    /// the container's, supplied and applied by the executor). Pure data (the
    /// executor maps each to `EXPLICIT_ACCESS_W` + `SetEntriesInAclW` +
    /// `SetNamedSecurityInfoW`), the same tracked-grant pattern the Windows capsule
    /// backend uses, so no `windows`-crate dependency leaks into `tirith-core`. A
    /// no-op (empty) on non-Windows targets.
    pub fn windows_container_grants(&self) -> Vec<crate::capsule::windows::AclGrant> {
        #[cfg(target_os = "windows")]
        {
            use crate::capsule::windows::{AclAccess, AclGrant};
            vec![AclGrant {
                path: self.dir.clone(),
                access: AclAccess::ReadExecute,
            }]
        }
        #[cfg(not(target_os = "windows"))]
        {
            Vec::new()
        }
    }
}

/// Whether `s` is a 64-character lowercase-hex SHA-256 string.
fn is_hex_sha256(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Validate that `name` is a single safe path component: non-empty, not `.`/`..`,
/// no path separator (either platform), no NUL, and not a Windows drive/UNC form.
fn validate_component(name: &str) -> Result<(), ()> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(());
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(());
    }
    // A drive-qualified ("C:foo") or otherwise colon-bearing name is rejected: it
    // is never a legitimate single component here and is a Windows path footgun.
    if name.contains(':') {
        return Err(());
    }
    // Defence in depth: the OS must agree it is exactly one normal component.
    let p = Path::new(name);
    let mut comps = p.components();
    match (comps.next(), comps.next()) {
        (Some(std::path::Component::Normal(c)), None) if c == name => Ok(()),
        _ => Err(()),
    }
}

/// Validate a destination filename: a single safe component AND a `*.whl` name.
fn validate_wheel_filename(name: &str) -> Result<(), ()> {
    validate_component(name)?;
    if is_wheel_filename(name) {
        Ok(())
    } else {
        Err(())
    }
}

/// Open (creating `0o600` on unix) the per-transaction lock file for an
/// `fs2` advisory lease.
fn open_lock_file(path: &Path) -> Result<File, QuarantineError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path).map_err(QuarantineError::Io)
}

/// Create a random `O_EXCL` temp file inside `dir` for an atomic same-dir publish,
/// returning the open handle and its path. Unix mode is `0o600` (tightened to
/// `0o400` on the published name). The random name comes from
/// [`tempfile::NamedTempFile`]; we keep the path and the file separately so the
/// caller can `rename` it (rather than letting the temp drop-delete).
fn create_excl_temp(dir: &Path) -> Result<(File, PathBuf), QuarantineError> {
    let tmp = tempfile::NamedTempFile::new_in(dir).map_err(QuarantineError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(QuarantineError::Io)?;
    }
    // Split into (file, path): `keep` disarms the drop-delete so the rename owns it.
    let (file, temp_path) = tmp.keep().map_err(|e| QuarantineError::Io(e.error))?;
    Ok((file, temp_path))
}

/// Hash the file at `path` from a no-follow, fstat'd handle (the single-handle
/// TOCTOU-safe pattern). Returns the lowercase-hex SHA-256.
fn hash_file_no_follow(path: &Path) -> Result<String, QuarantineError> {
    let handle = match open_read_no_follow_capped(path, ARTIFACT_MAX_FILE_SIZE) {
        Ok(f) => f,
        Err(OpenRegularError::TooLarge) => return Err(QuarantineError::TooLarge),
        Err(OpenRegularError::NotFound) | Err(OpenRegularError::NotRegularFile) => {
            return Err(QuarantineError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "temp blob vanished or is not a regular file before hashing",
            )))
        }
        Err(OpenRegularError::Io(e)) => return Err(QuarantineError::Io(e)),
    };
    match util::sha256_from_handle(handle, ARTIFACT_MAX_FILE_SIZE) {
        Ok(HashOutcome::Digest(hex)) => Ok(hex),
        Ok(HashOutcome::BudgetExceeded) => Err(QuarantineError::TooLarge),
        Err(e) => Err(QuarantineError::Io(e)),
    }
}

/// Apply the store directory perm policy: `0o700` on unix, best-effort no-op
/// elsewhere (the Windows DACL intent is carried by the tracked-grant model, not a
/// `std::fs` mode). A not-yet-existing dir is a caller bug; we only chmod present
/// directories.
fn harden_dir_perms(dir: &Path) -> Result<(), QuarantineError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if dir.is_dir() {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(QuarantineError::Io)?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// Tighten a published file to immutable (`0o400`) on unix; best-effort no-op
/// elsewhere. The file is content-addressed / re-verified, so making it read-only
/// stops an accidental in-place rewrite from going unnoticed.
fn harden_file_perms_immutable(path: &Path) -> Result<(), QuarantineError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))
            .map_err(QuarantineError::Io)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Remove an immutable (`0o400`) published file. On unix a `0o400` file in a
/// `0o700` directory is removable by the owner, but if a prior run left it
/// otherwise we relax the mode first so GC cannot get stuck.
fn remove_immutable_file(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::remove_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The lowercase-hex SHA-256 of `bytes`, computed independently of the store.
    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let d = Sha256::new().chain_update(bytes).finalize();
        hex::encode(d)
    }

    fn store() -> (tempfile::TempDir, QuarantineStore) {
        let tmp = tempfile::tempdir().unwrap();
        let store = QuarantineStore::with_root(tmp.path().join("q")).unwrap();
        (tmp, store)
    }

    #[test]
    fn ingest_then_blob_is_content_addressed_and_present() {
        let (_tmp, store) = store();
        let bytes = b"PK\x03\x04 fake wheel body";
        let digest = sha256_hex(bytes);
        let got = store.ingest_bytes(bytes, &digest).unwrap();
        assert_eq!(got, digest);
        assert!(store.has_blob(&digest));
        // The blob path is keyed by the digest and holds exactly the bytes.
        let stored = std::fs::read(store.blob_path(&digest)).unwrap();
        assert_eq!(stored, bytes);
    }

    #[test]
    fn ingest_is_idempotent() {
        let (_tmp, store) = store();
        let bytes = b"same bytes twice";
        let digest = sha256_hex(bytes);
        let first = store.ingest_bytes(bytes, &digest).unwrap();
        let second = store.ingest_bytes(bytes, &digest).unwrap();
        assert_eq!(first, second);
        assert!(store.has_blob(&digest));
    }

    #[test]
    fn ingest_rejects_digest_mismatch_and_stores_nothing() {
        let (_tmp, store) = store();
        let bytes = b"actual content";
        let lie = sha256_hex(b"different content");
        let err = store.ingest_bytes(bytes, &lie).unwrap_err();
        assert!(
            matches!(err, QuarantineError::DigestMismatch { .. }),
            "expected DigestMismatch, got {err:?}"
        );
        // Nothing published at the (lied-about) content-addressed name.
        assert!(!store.has_blob(&lie));
        // And no stray file under the blob dir.
        let blob_dir = store.root.join("blobs").join("sha256");
        let count = std::fs::read_dir(&blob_dir).unwrap().count();
        assert_eq!(count, 0, "a rejected ingest must leave no temp/blob behind");
    }

    #[test]
    fn ingest_file_streams_from_disk() {
        let (tmp, store) = store();
        let src = tmp.path().join("incoming.whl");
        let bytes = b"PK\x03\x04 on-disk wheel";
        std::fs::write(&src, bytes).unwrap();
        let digest = sha256_hex(bytes);
        let got = store.ingest_file(&src, &digest).unwrap();
        assert_eq!(got, digest);
        assert!(store.has_blob(&digest));
    }

    #[test]
    fn materialize_blob_makes_independent_immutable_copy() {
        let (_tmp, store) = store();
        let bytes = b"PK\x03\x04 wheel for txn";
        let digest = sha256_hex(bytes);
        store.ingest_bytes(bytes, &digest).unwrap();

        let txn = store.begin_transaction("txn-0001").unwrap();
        let dest = txn
            .materialize_blob(&digest, "pkg-1.0-py3-none-any.whl")
            .unwrap();
        // The materialised copy has the same bytes...
        assert_eq!(std::fs::read(&dest).unwrap(), bytes);
        // ...but is a DISTINCT inode from the blob (no hardlink): on unix the
        // device/inode pair differs, or at minimum it is not the same path.
        assert_ne!(dest, store.blob_path(&digest));
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let bmeta = std::fs::metadata(store.blob_path(&digest)).unwrap();
            let dmeta = std::fs::metadata(&dest).unwrap();
            assert_ne!(
                (bmeta.dev(), bmeta.ino()),
                (dmeta.dev(), dmeta.ino()),
                "transaction copy must not share the blob's inode"
            );
            // The published copy is read-only (immutable 0o400).
            assert_eq!(dmeta.mode() & 0o777, 0o400);
        }
    }

    #[test]
    fn materialize_rejects_non_wheel_and_traversal_names() {
        let (_tmp, store) = store();
        let bytes = b"PK\x03\x04 body";
        let digest = sha256_hex(bytes);
        store.ingest_bytes(bytes, &digest).unwrap();
        let txn = store.begin_transaction("txn-bad-names").unwrap();

        // Not a wheel.
        assert!(matches!(
            txn.materialize_blob(&digest, "evil.sh").unwrap_err(),
            QuarantineError::InvalidFilename(_)
        ));
        // Path traversal in the filename.
        assert!(matches!(
            txn.materialize_blob(&digest, "../escape.whl").unwrap_err(),
            QuarantineError::InvalidFilename(_)
        ));
        // Separator-bearing name.
        assert!(matches!(
            txn.materialize_blob(&digest, "sub/dir.whl").unwrap_err(),
            QuarantineError::InvalidFilename(_)
        ));
    }

    #[test]
    fn materialize_missing_blob_errors() {
        let (_tmp, store) = store();
        let txn = store.begin_transaction("txn-empty").unwrap();
        let absent = sha256_hex(b"never ingested");
        assert!(matches!(
            txn.materialize_blob(&absent, "pkg-1.0-py3-none-any.whl")
                .unwrap_err(),
            QuarantineError::BlobNotFound(_)
        ));
    }

    #[test]
    fn begin_transaction_rejects_bad_ids() {
        let (_tmp, store) = store();
        for bad in ["", ".", "..", "a/b", "a\\b", "C:txn", "x\0y"] {
            assert!(
                matches!(
                    store.begin_transaction(bad),
                    Err(QuarantineError::InvalidTransactionId(_))
                ),
                "id {bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn transaction_lease_is_exclusive() {
        let (_tmp, store) = store();
        let _held = store.begin_transaction("txn-lease").unwrap();
        // A second concurrent lease on the same id must fail (lock held).
        let second = store.begin_transaction("txn-lease");
        assert!(
            second.is_err(),
            "a held lease must block a second concurrent lease"
        );
    }

    #[test]
    fn transaction_lease_releases_on_drop() {
        let (_tmp, store) = store();
        {
            let _held = store.begin_transaction("txn-drop").unwrap();
        } // lease released here
          // Re-acquiring after drop succeeds.
        let again = store.begin_transaction("txn-drop");
        assert!(again.is_ok(), "lease must be re-acquirable after drop");
    }

    #[test]
    fn gc_transactions_removes_aged_unleased() {
        let (_tmp, store) = store();
        {
            let _txn = store.begin_transaction("old-txn").unwrap();
        }
        // max_age 0 makes every existing (unleased) txn eligible.
        let removed = store.gc_transactions(Duration::from_secs(0)).unwrap();
        assert_eq!(removed, 1);
        assert!(!store.transactions_dir().join("old-txn").exists());
    }

    #[test]
    fn gc_transactions_skips_live_lease() {
        let (_tmp, store) = store();
        let _live = store.begin_transaction("live-txn").unwrap();
        // Even with max_age 0 the leased txn is skipped (its lock is held).
        let removed = store.gc_transactions(Duration::from_secs(0)).unwrap();
        assert_eq!(removed, 0);
        assert!(store.transactions_dir().join("live-txn").exists());
    }

    #[test]
    fn gc_unreferenced_blobs_keeps_referenced() {
        let (_tmp, store) = store();
        let keep = b"keep me";
        let drop = b"drop me";
        let keep_d = sha256_hex(keep);
        let drop_d = sha256_hex(drop);
        store.ingest_bytes(keep, &keep_d).unwrap();
        store.ingest_bytes(drop, &drop_d).unwrap();

        let mut referenced = BTreeSet::new();
        referenced.insert(keep_d.clone());
        let removed = store.gc_unreferenced_blobs(&referenced).unwrap();
        assert_eq!(removed, 1);
        assert!(store.has_blob(&keep_d));
        assert!(!store.has_blob(&drop_d));
    }

    #[test]
    fn with_root_sets_unix_dir_perms_0700() {
        let (_tmp, store) = store();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for d in [
                store.root.clone(),
                store.root.join("blobs").join("sha256"),
                store.root.join("transactions"),
            ] {
                let mode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o700, "{} should be 0700", d.display());
            }
        }
    }

    #[test]
    fn paths_stay_within_root() {
        let (_tmp, store) = store();
        let bytes = b"contained";
        let digest = sha256_hex(bytes);
        store.ingest_bytes(bytes, &digest).unwrap();
        assert!(canonical_within(&store.blob_path(&digest), store.root()));
        let txn = store.begin_transaction("txn-contain").unwrap();
        let dest = txn
            .materialize_blob(&digest, "pkg-1.0-py3-none-any.whl")
            .unwrap();
        assert!(canonical_within(&dest, store.root()));
    }
}
