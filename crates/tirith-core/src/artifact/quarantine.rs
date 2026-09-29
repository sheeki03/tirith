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
//! `rename`s it onto the final name. On unix both creation and publication are
//! relative to a held directory descriptor. A same-directory rename is atomic
//! and stays on one device, so a reader sees either no file or the whole file,
//! never a torn one, and there is no cross-device copy that a `rename` would
//! reject. Temp names are random and exclusively created, so there is no
//! predictable path to pre-create or race.
//!
//! Hashing is done from the same no-follow regular-file handle used to write or
//! read the bytes, mirroring the single-handle pattern in
//! [`crate::artifact::inspect`]. A path swap cannot substitute a different file
//! between verification and publication.
//!
//! # Containment
//!
//! Transaction ids and filenames are validated to be a single safe path component
//! (no separators, no `..`, no NUL, no absolute drive). On unix, root/subtree
//! descriptors are opened no-follow and every security operation uses `*at`
//! syscalls relative to those descriptors. On Windows, validated non-reparse
//! directory handles are held without delete sharing, pinning their identities;
//! publication and GC detach are performed relative to those handles. Other
//! platforms fail closed at store construction.
//! The descriptor/handle identity is also checked against the visible path before
//! returning a path to a caller.
//!
//! # Permissions
//!
//! On unix the store directories are `0o700` and blob / transaction files are
//! `0o400` once published (a verified blob is immutable; only GC removes it). On
//! Windows uses a protected owner-only DACL on every store object; D4 additionally
//! grants the install AppContainer SID *temporarily* and revokes it after. That
//! per-container grant is modelled here as a tracked
//! [`crate::capsule::windows::AclGrant`] list the executor applies and revokes.

use std::fs::File;
use std::path::{Path, PathBuf};
#[cfg(any(unix, windows))]
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use fs2::FileExt;

use crate::artifact::archive::is_wheel_filename;
use crate::artifact::inspect::ARTIFACT_MAX_FILE_SIZE;
#[cfg(any(not(unix), test))]
use crate::util::canonical_within;
#[cfg(all(not(unix), not(windows)))]
use crate::util::create_dir_durable;
#[cfg(all(not(unix), not(windows)))]
use crate::util::open_read_no_follow_capped;
use crate::util::{self, HashOutcome, OpenRegularError};

/// The directory name under the quarantine root holding content-addressed blobs.
const BLOBS_DIR: &str = "blobs";
/// The hash-algorithm subdirectory under [`BLOBS_DIR`]. A sibling for a future
/// algorithm keeps the on-disk layout self-describing.
const SHA256_DIR: &str = "sha256";
/// The directory name under the quarantine root holding per-install transactions.
const TRANSACTIONS_DIR: &str = "transactions";
/// The per-transaction lock file name (held exclusively for the lease).
const LOCK_FILE: &str = ".lock";
/// Prefix for a transaction directory that GC has atomically detached from its
/// public id while retaining the old transaction's lease.
const GC_TOMBSTONE_PREFIX: &str = ".tirith-gc-";

#[cfg(test)]
type GcTestHook = Box<dyn FnMut(&str)>;

#[cfg(test)]
thread_local! {
    /// Runs after GC has detached the old transaction id but before it removes
    /// the tombstone. Tests use this seam to deterministically acquire a fresh
    /// lease for the same public id and prove GC cannot touch it.
    static GC_TOMBSTONE_TEST_HOOK: std::cell::RefCell<Option<GcTestHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(all(test, unix))]
thread_local! {
    /// Runs after GC has acquired the old transaction lease but before it
    /// revalidates and tombstones the public directory entry. Tests replace the
    /// entry here to prove GC will not detach or delete the replacement.
    static GC_PRE_TOMBSTONE_TEST_HOOK: std::cell::RefCell<Option<GcTestHook>> =
        std::cell::RefCell::new(None);
    /// Inject one `readdir` failure without relying on a particular filesystem.
    static READDIR_ERROR_TEST_HOOK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(all(test, windows))]
thread_local! {
    /// Lets the Windows collision regression prove the verifier observed an
    /// actual sharing violation before the winning publisher releases its handle.
    static WINDOWS_BLOB_REOPEN_SHARING_BARRIER:
        std::cell::RefCell<Option<std::sync::Arc<std::sync::Barrier>>> =
        const { std::cell::RefCell::new(None) };
}

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
    /// Stable directory capabilities for every security-sensitive store subtree.
    ///
    /// Path validation is not a durable authority: an attacker can replace a
    /// checked directory before a later path-based open.  Unix operations are
    /// therefore anchored to these descriptors for the entire store lifetime.
    #[cfg(unix)]
    secure_dirs: Arc<SecureStoreDirs>,
    /// Windows directory handles are opened without `FILE_SHARE_DELETE`, which
    /// pins each validated non-reparse directory against rename/replacement for
    /// the store lifetime and anchors handle-relative publication.
    #[cfg(windows)]
    secure_windows: Arc<WindowsSecureStoreDirs>,
}

#[cfg(unix)]
#[derive(Debug)]
struct SecureStoreDirs {
    root: File,
    blobs: File,
    blobs_sha256: File,
    transactions: File,
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsSecureStoreDirs {
    /// Every pre-root ancestor opened during traversal. Retaining these handles
    /// without delete sharing prevents an ancestor swap from redirecting later
    /// absolute-path opens beneath `root`.
    _root_ancestry: Vec<File>,
    root: File,
    blobs: File,
    blobs_sha256: File,
    transactions: File,
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
        #[cfg(unix)]
        {
            let (root, root_dir) = open_or_create_dir_path_no_symlinks(&root)?;
            harden_dir_handle(&root_dir)?;
            let blobs = open_or_create_dir_at(&root_dir, BLOBS_DIR)?;
            let blobs_sha256 = open_or_create_dir_at(&blobs, SHA256_DIR)?;
            let transactions = open_or_create_dir_at(&root_dir, TRANSACTIONS_DIR)?;
            Ok(QuarantineStore {
                root,
                secure_dirs: Arc::new(SecureStoreDirs {
                    root: root_dir,
                    blobs,
                    blobs_sha256,
                    transactions,
                }),
            })
        }

        #[cfg(windows)]
        {
            let (root, root_handle, root_ancestry) =
                open_or_create_windows_dir_path_no_reparse(&root)?;
            let blobs_path = root.join(BLOBS_DIR);
            let blobs = open_or_create_windows_secure_dir(&blobs_path)?;
            let blobs_sha256_path = blobs_path.join(SHA256_DIR);
            let blobs_sha256 = open_or_create_windows_secure_dir(&blobs_sha256_path)?;
            let transactions_path = root.join(TRANSACTIONS_DIR);
            let transactions = open_or_create_windows_secure_dir(&transactions_path)?;
            Ok(QuarantineStore {
                root,
                secure_windows: Arc::new(WindowsSecureStoreDirs {
                    _root_ancestry: root_ancestry,
                    root: root_handle,
                    blobs,
                    blobs_sha256,
                    transactions,
                }),
            })
        }

        #[cfg(all(not(unix), not(windows)))]
        {
            let _ = root;
            Err(QuarantineError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "secure quarantine filesystem operations are unavailable on this platform",
            )))
        }
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

    #[cfg(unix)]
    fn ensure_secure_paths(&self) -> Result<(), QuarantineError> {
        let blobs = self.blobs_dir();
        let blobs_sha256 = self.blobs_sha256_dir();
        let transactions = self.transactions_dir();
        for (path, handle) in [
            (&self.root, &self.secure_dirs.root),
            (&blobs, &self.secure_dirs.blobs),
            (&blobs_sha256, &self.secure_dirs.blobs_sha256),
            (&transactions, &self.secure_dirs.transactions),
        ] {
            if !path_matches_handle(path, handle)? {
                return Err(QuarantineError::PathEscape(path.to_path_buf()));
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    fn ensure_secure_paths(&self) -> Result<(), QuarantineError> {
        let blobs = self.blobs_dir();
        let blobs_sha256 = self.blobs_sha256_dir();
        let transactions = self.transactions_dir();
        for (path, handle) in [
            (&self.root, &self.secure_windows.root),
            (&blobs, &self.secure_windows.blobs),
            (&blobs_sha256, &self.secure_windows.blobs_sha256),
            (&transactions, &self.secure_windows.transactions),
        ] {
            if !windows_path_matches_handle(path, handle)? {
                return Err(QuarantineError::PathEscape(path.to_path_buf()));
            }
            windows_verify_owner_only_handle(handle)?;
        }
        Ok(())
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
        #[cfg(unix)]
        {
            if self.ensure_secure_paths().is_err() {
                return false;
            }
            open_regular_at(&self.secure_dirs.blobs_sha256, digest, false).is_ok()
        }
        #[cfg(windows)]
        {
            if self.ensure_secure_paths().is_err() {
                return false;
            }
            match open_windows_regular_no_reparse(&self.blob_path(digest), false) {
                Ok(file) => windows_verify_owner_only_handle(&file).is_ok(),
                Err(_) => false,
            }
        }
        #[cfg(all(not(unix), not(windows)))]
        {
            self.blob_path(digest).is_file()
        }
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
        if bytes.len() as u64 > ARTIFACT_MAX_FILE_SIZE {
            return Err(QuarantineError::TooLarge);
        }

        #[cfg(unix)]
        {
            self.ingest_bytes_unix(bytes, expected)
        }

        #[cfg(windows)]
        {
            self.ingest_bytes_windows(bytes, expected)
        }

        #[cfg(all(not(unix), not(windows)))]
        {
            let final_path = self.blob_path(&expected);
            // Idempotent fast path: an already-published blob is immutable (it was
            // written `0o400` and hardened by `harden_file_perms_immutable` on first
            // ingest), so if the content-addressed name exists we trust it by name --
            // the filename IS the verified hash -- and skip the rewrite WITHOUT
            // re-hashing here.
            //
            // LOAD-BEARING INVARIANT (do not relax): this fast path is safe ONLY
            // because every consumer re-hashes the blob from a FRESH no-follow handle
            // before it uses or installs the bytes. The two reaching sites:
            //   * `crate::artifact::firewall` re-hashes each blob immediately before
            //     evaluation and fails closed (`ArtifactDownloadIntegrityMismatch`,
            //     T1565) if it does not reproduce the approved digest.
            //   * `Self::materialize_blob` streams the blob through a no-follow handle
            //     and re-hashes before publishing the install copy.
            // If a future caller installs directly off `blob_path` without that
            // re-hash, move the verification here (re-hash on this branch) instead.
            match open_read_no_follow_capped(&final_path, ARTIFACT_MAX_FILE_SIZE) {
                Ok(_) => return Ok(expected),
                Err(OpenRegularError::NotFound) => {}
                Err(OpenRegularError::NotRegularFile) => {
                    return Err(QuarantineError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "quarantine blob destination is a symlink or non-regular file",
                    )))
                }
                Err(OpenRegularError::TooLarge) => return Err(QuarantineError::TooLarge),
                Err(OpenRegularError::Io(error)) => return Err(QuarantineError::Io(error)),
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
    }

    #[cfg(windows)]
    fn ingest_bytes_windows(
        &self,
        bytes: &[u8],
        expected: String,
    ) -> Result<String, QuarantineError> {
        self.ensure_secure_paths()?;
        let final_path = self.blob_path(&expected);

        // Existing content-addressed blobs are only accepted as regular,
        // non-reparse files. Every consumer independently re-hashes a fresh
        // handle before use, so the immutable name remains an idempotent fast
        // path here.
        match open_windows_regular_no_reparse(&final_path, true) {
            Ok(file) => {
                harden_windows_handle_owner_only(&file)?;
                return Ok(expected);
            }
            Err(OpenRegularError::NotFound) => {}
            Err(OpenRegularError::NotRegularFile) => {
                return Err(QuarantineError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "quarantine blob destination is a reparse point or non-regular file",
                )))
            }
            Err(OpenRegularError::TooLarge) => return Err(QuarantineError::TooLarge),
            Err(OpenRegularError::Io(error)) => return Err(QuarantineError::Io(error)),
        }

        let (mut temp_file, _temp_name) = create_windows_secure_temp(&self.blobs_sha256_dir())?;
        let prepare = (|| -> Result<String, QuarantineError> {
            use std::io::Write as _;

            temp_file.write_all(bytes)?;
            temp_file.sync_all()?;
            let actual = hash_regular_handle(&temp_file)?;
            if actual != expected {
                return Err(QuarantineError::DigestMismatch { expected, actual });
            }
            harden_windows_handle_owner_only(&temp_file)?;
            Ok(actual)
        })();
        let digest = match prepare {
            Ok(digest) => digest,
            Err(error) => {
                let _ = windows_delete_held_file(&temp_file);
                return Err(error);
            }
        };

        if let Err(rename_error) =
            windows_rename_held_file(&temp_file, &self.secure_windows.blobs_sha256, &digest)
        {
            let _ = windows_delete_held_file(&temp_file);
            // Another process may have won the same content-addressed publish,
            // or a verified blob may be open without delete sharing. Accept that
            // collision only after reopening the destination no-follow and
            // proving both its protected DACL and digest from the same handle.
            if windows_existing_blob_matches(&final_path, &digest)? {
                return Ok(digest);
            }
            return Err(QuarantineError::Io(rename_error));
        }
        drop(temp_file);
        // Publication has succeeded. Keep every remaining operation best-effort
        // so callers are never told the blob is absent after it became visible.
        util::fsync_parent_dir_logged(&final_path, "quarantine blob publish");
        Ok(digest)
    }

    #[cfg(unix)]
    fn ingest_bytes_unix(&self, bytes: &[u8], expected: String) -> Result<String, QuarantineError> {
        self.ensure_secure_paths()?;
        let blob_dir = &self.secure_dirs.blobs_sha256;
        match open_regular_at(blob_dir, &expected, false) {
            Ok(_) => return Ok(expected),
            Err(OpenRegularError::NotFound) => {}
            Err(OpenRegularError::NotRegularFile) => {
                return Err(QuarantineError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "quarantine blob destination is a symlink or non-regular file",
                )))
            }
            Err(OpenRegularError::TooLarge) => unreachable!("size cap was not requested"),
            Err(OpenRegularError::Io(error)) => return Err(QuarantineError::Io(error)),
        }

        let (mut temp_file, temp_name) = create_temp_at(blob_dir)?;
        let write_result = (|| -> Result<String, QuarantineError> {
            use std::io::Write as _;
            temp_file.write_all(bytes)?;
            temp_file.sync_all()?;
            let actual = hash_regular_handle(&temp_file)?;
            if actual != expected {
                return Err(QuarantineError::DigestMismatch { expected, actual });
            }
            harden_file_handle(&temp_file)?;
            Ok(actual)
        })();

        let digest = match write_result {
            Ok(digest) => digest,
            Err(error) => {
                let _ = unlink_file_at(blob_dir, &temp_name);
                return Err(error);
            }
        };
        if let Err(error) = rename_at(blob_dir, &temp_name, blob_dir, &digest) {
            let _ = unlink_file_at(blob_dir, &temp_name);
            return Err(QuarantineError::Io(error));
        }
        blob_dir.sync_all()?;
        self.ensure_secure_paths()?;
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

        #[cfg(unix)]
        {
            self.ensure_secure_paths()?;
            // All in-module creation and GC detachment take this capability-
            // bound parent lock before taking a transaction lease. That common
            // lock order closes the cooperative same-id replacement window
            // without trusting a replaceable lockfile pathname.
            let _parent_lock = lock_directory_exclusive(&self.secure_dirs.transactions)?;
            let dir_handle = open_or_create_dir_at(&self.secure_dirs.transactions, txn_id)?;
            let lock_file = open_lock_file_at(&dir_handle)?;
            lock_file
                .try_lock_exclusive()
                .map_err(QuarantineError::Io)?;
            let transaction = QuarantineTransaction {
                store: self.clone(),
                id: txn_id.to_string(),
                dir,
                dir_handle: Arc::new(dir_handle),
                _lock: lock_file,
            };
            transaction.ensure_secure_path()?;
            Ok(transaction)
        }

        #[cfg(windows)]
        {
            self.ensure_secure_paths()?;
            create_windows_dir_owner_only(&dir)?;
            // Do not rewrite an existing transaction DACL until its lease has
            // been acquired: a live installer may temporarily have a tracked
            // AppContainer grant on this directory.
            let dir_handle = Arc::new(open_windows_dir_no_reparse_with_options(
                &dir, false, true, false,
            )?);
            let lock_path = dir.join(LOCK_FILE);
            // A lease handle intentionally does not share deletion. This pins
            // the `.lock` directory entry so no peer can swap in another lock
            // inode while this lease is live.
            let lock_file = open_windows_lock_file(&lock_path, false)?;
            lock_file
                .try_lock_exclusive()
                .map_err(QuarantineError::Io)?;
            harden_windows_handle_owner_only(&dir_handle)?;
            harden_windows_handle_owner_only(&lock_file)?;
            let transaction = QuarantineTransaction {
                store: self.clone(),
                id: txn_id.to_string(),
                dir,
                dir_handle,
                _lock: lock_file,
            };
            transaction.ensure_secure_path()?;
            Ok(transaction)
        }

        #[cfg(all(not(unix), not(windows)))]
        {
            let _ = dir;
            Err(QuarantineError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "secure quarantine filesystem operations are unavailable on this platform",
            )))
        }
    }

    /// Garbage-collect transactions whose directory mtime is older than `max_age`,
    /// returning the number removed. A transaction currently leased by another
    /// process is skipped (its `.lock` is held), so GC never races a live install.
    /// Blobs are GC'd separately by [`gc_unreferenced_blobs`].
    pub fn gc_transactions(&self, max_age: Duration) -> Result<usize, QuarantineError> {
        #[cfg(unix)]
        {
            self.gc_transactions_unix(max_age)
        }

        #[cfg(windows)]
        {
            self.gc_transactions_windows(max_age)
        }

        #[cfg(all(not(unix), not(windows)))]
        {
            let now = SystemTime::now();
            let mut removed = 0usize;
            let txns = self.transactions_dir();
            let entries = match std::fs::read_dir(&txns) {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
                Err(e) => return Err(QuarantineError::Io(e)),
            };
            for entry in entries {
                let entry = entry.map_err(QuarantineError::Io)?;
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
                // Skip a transaction another holder is leasing. Once acquired, the
                // lock stays held until the old directory has been detached under a
                // randomized tombstone and fully removed; dropping it before
                // `remove_dir_all` would let a new lease race recursive deletion.
                let lock_path = path.join(LOCK_FILE);
                let lock = match open_lock_file(&lock_path) {
                    Ok(lock) if lock.try_lock_exclusive().is_ok() => lock,
                    Ok(_) => continue,
                    // No lock file (or unopenable): treat as not-leased and reclaim.
                    Err(_) => continue,
                };
                let tombstone = txns.join(gc_tombstone_name());
                if std::fs::rename(&path, &tombstone).is_err() {
                    continue;
                }
                #[cfg(test)]
                GC_TOMBSTONE_TEST_HOOK.with(|slot| {
                    if let Some(hook) = slot.borrow_mut().as_mut() {
                        hook(
                            path.file_name()
                                .and_then(|name| name.to_str())
                                .unwrap_or(""),
                        );
                    }
                });
                if std::fs::remove_dir_all(&tombstone).is_ok() {
                    removed += 1;
                }
                drop(lock);
            }
            Ok(removed)
        }
    }

    #[cfg(windows)]
    fn gc_transactions_windows(&self, max_age: Duration) -> Result<usize, QuarantineError> {
        self.ensure_secure_paths()?;
        let now = SystemTime::now();
        let mut removed = 0usize;
        let txns = self.transactions_dir();
        let entries = match std::fs::read_dir(&txns) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(QuarantineError::Io(error)),
        };

        for entry in entries {
            let entry = entry.map_err(QuarantineError::Io)?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if validate_component(name).is_err() {
                continue;
            }

            // DELETE access without delete sharing makes this an exact, pinned
            // rename/removal capability. A live transaction directory is already
            // held under the same no-delete-sharing rule, so opening it this way
            // fails and GC skips it before touching the lock.
            let transaction =
                match open_windows_dir_no_reparse_with_options(&path, false, true, true) {
                    Ok(directory) => directory,
                    Err(_) => continue,
                };
            let aged_out = transaction
                .metadata()
                .and_then(|metadata| metadata.modified())
                .map(|modified| {
                    // A modified time at or slightly AFTER `now` (NTFS timestamp
                    // granularity for a dir created microseconds ago, or a clock
                    // adjustment) makes `duration_since` error. Treat that as age
                    // zero rather than "unknown, skip": with `max_age == 0` every
                    // unleased txn is eligible by contract, and a positive
                    // threshold still (correctly) spares a brand-new directory.
                    now.duration_since(modified).unwrap_or(Duration::ZERO)
                })
                .map(|age| age >= max_age)
                .unwrap_or(false);
            if !aged_out {
                continue;
            }

            // Probe the lease to prove no other holder is mid-install, then
            // CLOSE it before the tombstone rename below.
            //
            // [MS-FSA] 2.1.5.14.11 fails a DirectoryFile FileRenameInformation
            // with STATUS_ACCESS_DENIED whenever 2.1.4.2's open-file census
            // finds ANY open handle to a child of that directory, and that
            // census has no FILE_SHARE_DELETE exemption — share-delete governs
            // the 2.1.4.1 check when OPENING a file, not the rename of its
            // parent. Holding `.lock` across the rename therefore failed every
            // directory rename and left GC silently collecting nothing.
            //
            // Exclusion does not depend on this handle. `transaction` is open
            // with DELETE and share = READ|WRITE only, so a concurrent same-id
            // `begin_transaction` cannot get past its own directory open
            // (STATUS_SHARING_VIOLATION, 2.1.4.1) for as long as the collector
            // holds it — that is the pin which keeps cleanup off a replacement
            // directory. Closing the lease also lets the content sweep below
            // actually unlink `.lock`, so the directory is genuinely empty when
            // its own delete is set (a directory delete hits the same census).
            {
                let lock = match open_windows_lock_file(&path.join(LOCK_FILE), true) {
                    Ok(lock) => lock,
                    Err(_) => continue,
                };
                if lock.try_lock_exclusive().is_err() {
                    continue;
                }
                harden_windows_handle_owner_only(&lock)?;
            }
            harden_windows_handle_owner_only(&transaction)?;

            let tombstone_name = gc_tombstone_name();
            if windows_rename_held_file(
                &transaction,
                &self.secure_windows.transactions,
                &tombstone_name,
            )
            .is_err()
            {
                continue;
            }
            let tombstone = txns.join(&tombstone_name);
            #[cfg(test)]
            GC_TOMBSTONE_TEST_HOOK.with(|slot| {
                if let Some(hook) = slot.borrow_mut().as_mut() {
                    hook(name);
                }
            });
            windows_remove_dir_contents(&tombstone)?;
            windows_delete_held_file(&transaction)?;
            drop(transaction);
            removed += 1;
        }
        self.ensure_secure_paths()?;
        Ok(removed)
    }

    #[cfg(unix)]
    fn gc_transactions_unix(&self, max_age: Duration) -> Result<usize, QuarantineError> {
        self.ensure_secure_paths()?;
        let now = SystemTime::now();
        let mut removed = 0usize;
        for name in read_dir_names(&self.secure_dirs.transactions)? {
            let Some(name) = name.to_str() else {
                continue;
            };
            if validate_component(name).is_err() {
                continue;
            }
            // Serialize every cooperative create/open/detach decision at the
            // retained parent capability. The fresh `.` descriptor owns an
            // independent flock, so this also serializes callers in this
            // process (a dup would share the lock state and would not).
            let parent_lock = lock_directory_exclusive(&self.secure_dirs.transactions)?;
            let transaction = match open_dir_at(&self.secure_dirs.transactions, name) {
                Ok(dir) => dir,
                Err(_) => continue,
            };
            let aged_out = transaction
                .metadata()
                .and_then(|metadata| metadata.modified())
                .map(|modified| {
                    // A modified time at or slightly AFTER `now` (NTFS timestamp
                    // granularity for a dir created microseconds ago, or a clock
                    // adjustment) makes `duration_since` error. Treat that as age
                    // zero rather than "unknown, skip": with `max_age == 0` every
                    // unleased txn is eligible by contract, and a positive
                    // threshold still (correctly) spares a brand-new directory.
                    now.duration_since(modified).unwrap_or(Duration::ZERO)
                })
                .map(|age| age >= max_age)
                .unwrap_or(false);
            if !aged_out {
                continue;
            }

            let lock = match open_lock_file_at(&transaction) {
                Ok(lock) => lock,
                Err(_) => continue,
            };
            if lock.try_lock_exclusive().is_err() {
                continue;
            }
            #[cfg(test)]
            GC_PRE_TOMBSTONE_TEST_HOOK.with(|slot| {
                if let Some(hook) = slot.borrow_mut().as_mut() {
                    hook(name);
                }
            });
            // The public name and its `.lock` must still identify the exact
            // directory and lease handles selected above. A non-cooperating
            // same-UID process may ignore the parent flock; revalidating here,
            // immediately before renameat, makes that replacement fail closed.
            if !dir_entry_matches_handle(&self.secure_dirs.transactions, name, &transaction)?
                || !file_entry_matches_handle(&transaction, LOCK_FILE, &lock)?
            {
                continue;
            }
            // Detach the public transaction id while its original lock is still
            // held. A concurrent begin can now create a new directory and lock
            // inode for `name`, but cleanup remains capability-bound to the old
            // directory under `tombstone` and cannot delete the new lease.
            let tombstone = gc_tombstone_name();
            rename_at(
                &self.secure_dirs.transactions,
                name,
                &self.secure_dirs.transactions,
                &tombstone,
            )?;
            // Prove the new tombstone name resolves to the same directory whose
            // lease is held. If an attacker won the tiny pre-rename syscall
            // window, leave the suspicious entry intact rather than granting
            // recursive-deletion authority over the wrong identity.
            if !dir_entry_matches_handle(&self.secure_dirs.transactions, &tombstone, &transaction)?
                || !file_entry_matches_handle(&transaction, LOCK_FILE, &lock)?
            {
                return Err(QuarantineError::PathEscape(
                    self.transactions_dir().join(&tombstone),
                ));
            }
            self.secure_dirs.transactions.sync_all()?;
            // A fresh same-id lease is now safe: all remaining cleanup is bound
            // to `transaction`, not to its former public name.
            drop(parent_lock);
            #[cfg(test)]
            GC_TOMBSTONE_TEST_HOOK.with(|slot| {
                if let Some(hook) = slot.borrow_mut().as_mut() {
                    hook(name);
                }
            });
            remove_dir_contents(&transaction)?;
            // Reacquire parent serialization and revalidate immediately before
            // the final name-based unlink. The old lock handle is deliberately
            // still held even though cleanup has unlinked its directory entry.
            let _parent_lock = lock_directory_exclusive(&self.secure_dirs.transactions)?;
            if !dir_entry_matches_handle(&self.secure_dirs.transactions, &tombstone, &transaction)?
            {
                return Err(QuarantineError::PathEscape(
                    self.transactions_dir().join(&tombstone),
                ));
            }
            if unlink_dir_at(&self.secure_dirs.transactions, &tombstone).is_ok() {
                self.secure_dirs.transactions.sync_all()?;
                removed += 1;
            }
            drop(lock);
            drop(transaction);
        }
        self.ensure_secure_paths()?;
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
        #[cfg(unix)]
        {
            self.ensure_secure_paths()?;
            let mut removed = 0usize;
            for name in read_dir_names(&self.secure_dirs.blobs_sha256)? {
                let Some(name) = name.to_str() else {
                    continue;
                };
                if !is_hex_sha256(name) || referenced.contains(name) {
                    continue;
                }
                if unlink_file_at(&self.secure_dirs.blobs_sha256, name).is_ok() {
                    removed += 1;
                }
            }
            self.ensure_secure_paths()?;
            Ok(removed)
        }

        #[cfg(not(unix))]
        {
            #[cfg(windows)]
            self.ensure_secure_paths()?;
            let mut removed = 0usize;
            let dir = self.blobs_sha256_dir();
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
                Err(e) => return Err(QuarantineError::Io(e)),
            };
            for entry in entries {
                let entry = entry.map_err(QuarantineError::Io)?;
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
            #[cfg(windows)]
            self.ensure_secure_paths()?;
            Ok(removed)
        }
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
    /// Stable capability for the transaction directory.  All materialization
    /// operations are relative to this handle, so renaming or replacing the
    /// visible path cannot redirect a write.
    #[cfg(unix)]
    dir_handle: Arc<File>,
    /// Held without delete sharing, pinning the validated transaction directory
    /// against rename or replacement and anchoring handle-relative publication.
    #[cfg(windows)]
    dir_handle: Arc<File>,
    /// Held for the lease; unlocked on drop.
    _lock: File,
}

impl QuarantineTransaction {
    #[cfg(unix)]
    fn ensure_secure_path(&self) -> Result<(), QuarantineError> {
        self.store.ensure_secure_paths()?;
        if !path_matches_handle(&self.dir, &self.dir_handle)? {
            return Err(QuarantineError::PathEscape(self.dir.clone()));
        }
        Ok(())
    }

    #[cfg(windows)]
    fn ensure_secure_path(&self) -> Result<(), QuarantineError> {
        self.store.ensure_secure_paths()?;
        if !windows_path_matches_handle(&self.dir, &self.dir_handle)? {
            return Err(QuarantineError::PathEscape(self.dir.clone()));
        }
        Ok(())
    }

    /// The transaction id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The transaction directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Re-check that the public transaction path still names the exact directory
    /// capability retained by this lease. Callers that must hand a pathname to an
    /// OS API use this as a fail-closed diagnostic; security-sensitive file I/O
    /// should use the descriptor-relative helpers on this value instead.
    pub fn verify_visible_identity(&self) -> Result<(), QuarantineError> {
        #[cfg(any(unix, windows))]
        {
            self.ensure_secure_path()
        }
        #[cfg(all(not(unix), not(windows)))]
        {
            Err(QuarantineError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "secure quarantine directory identity is unavailable on this platform",
            )))
        }
    }

    /// Duplicate the retained transaction-directory capability for a launcher.
    /// On Unix the launcher inherits this descriptor, `fchdir`s to the exact
    /// directory before containment, and uses relative artifact paths; on Windows
    /// the no-delete-sharing handle pins the directory while `CreateProcessW` uses
    /// its absolute paths.
    pub fn try_clone_dir_handle(&self) -> Result<File, QuarantineError> {
        #[cfg(any(unix, windows))]
        {
            self.ensure_secure_path()?;
            self.dir_handle.try_clone().map_err(QuarantineError::Io)
        }
        #[cfg(all(not(unix), not(windows)))]
        {
            Err(QuarantineError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "secure quarantine directory handles are unavailable on this platform",
            )))
        }
    }

    /// Pin an explicit set of transaction children across a package launch.
    /// Handles are returned in input order. Linux opens every bounded regular file
    /// no-follow relative to the retained transaction-directory descriptor, so a
    /// pathname replacement cannot redirect the launch input. Windows opens each
    /// child read-only, no-follow, and with read sharing only: writers, renames,
    /// and deletion remain blocked until the returned handles are dropped. The
    /// caller must perform its final approval/hash checks from these exact handles
    /// and retain them through the blocking child-process wait.
    pub fn pin_files_for_launch<'a>(
        &self,
        filenames: impl IntoIterator<Item = &'a str>,
    ) -> Result<Vec<File>, QuarantineError> {
        let filenames: Vec<&str> = filenames.into_iter().collect();
        for &filename in &filenames {
            validate_component(filename).map_err(|()| {
                QuarantineError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "launch-pinned quarantine filename is not one safe component",
                ))
            })?;
            if filename == LOCK_FILE {
                return Err(QuarantineError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "the transaction lock cannot be launch-pinned as an artifact",
                )));
            }
        }

        #[cfg(windows)]
        {
            self.ensure_secure_path()?;
            return filenames
                .into_iter()
                .map(|filename| open_windows_pinned_regular(&self.dir.join(filename)))
                .collect();
        }

        #[cfg(target_os = "linux")]
        {
            self.ensure_secure_path()?;
            let pins = filenames
                .into_iter()
                .map(
                    |filename| match open_regular_at(&self.dir_handle, filename, true) {
                        Ok(file) => Ok(file),
                        Err(OpenRegularError::TooLarge) => Err(QuarantineError::TooLarge),
                        Err(OpenRegularError::NotFound) => {
                            Err(QuarantineError::Io(std::io::Error::new(
                                std::io::ErrorKind::NotFound,
                                format!("launch-pinned quarantine file {filename:?} was not found"),
                            )))
                        }
                        Err(OpenRegularError::NotRegularFile) => {
                            Err(QuarantineError::Io(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!(
                                    "launch-pinned quarantine file {filename:?} is a symlink or non-regular file"
                                ),
                            )))
                        }
                        Err(OpenRegularError::Io(error)) => Err(QuarantineError::Io(error)),
                    },
                )
                .collect::<Result<Vec<_>, _>>()?;
            // The retained descriptor is the I/O authority, but keep the public
            // identity invariant too: callers also report the visible transaction
            // path and must fail if a same-UID peer replaced it during pinning.
            self.ensure_secure_path()?;
            Ok(pins)
        }

        #[cfg(all(not(windows), not(target_os = "linux")))]
        {
            Ok(Vec::new())
        }
    }

    /// Crash-atomically publish a small control file inside this transaction.
    /// The filename is one validated component. Unix writes and renames relative
    /// to the retained directory descriptor so an ancestor swap cannot redirect
    /// `approved.txt`; Windows publication is bound to the retained handle and its
    /// protected DACL by the platform helper.
    pub fn write_control_file_atomic_0600(
        &self,
        filename: &str,
        bytes: &[u8],
    ) -> Result<PathBuf, QuarantineError> {
        validate_component(filename).map_err(|_| {
            QuarantineError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "quarantine control filename is not one safe component",
            ))
        })?;
        if filename == LOCK_FILE {
            return Err(QuarantineError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "quarantine control file must not replace the transaction lock",
            )));
        }

        #[cfg(unix)]
        {
            use std::io::Write as _;

            self.ensure_secure_path()?;
            let (mut temp, temp_name) = create_temp_at(&self.dir_handle)?;
            let write_result = (|| -> std::io::Result<()> {
                temp.write_all(bytes)?;
                temp.sync_all()?;
                // Control files remain owner-readable/writable for a later atomic
                // refresh; unlike immutable wheels they are not content-addressed.
                use std::os::fd::AsRawFd as _;
                if unsafe { libc::fchmod(temp.as_raw_fd(), 0o600) } != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                rename_at(&self.dir_handle, &temp_name, &self.dir_handle, filename)?;
                self.dir_handle.sync_all()?;
                Ok(())
            })();
            if let Err(error) = write_result {
                let _ = unlink_file_at(&self.dir_handle, &temp_name);
                return Err(QuarantineError::Io(error));
            }
            self.ensure_secure_path()?;
            Ok(self.dir.join(filename))
        }

        #[cfg(windows)]
        {
            self.write_control_file_atomic_windows(filename, bytes)
        }

        #[cfg(all(not(unix), not(windows)))]
        {
            let path = self.dir.join(filename);
            util::write_file_atomic_0600(&path, bytes)?;
            Ok(path)
        }
    }

    #[cfg(windows)]
    fn write_control_file_atomic_windows(
        &self,
        filename: &str,
        bytes: &[u8],
    ) -> Result<PathBuf, QuarantineError> {
        use std::io::Write as _;

        self.ensure_secure_path()?;
        let path = self.dir.join(filename);
        let (mut temp_file, _temp_name) = create_windows_secure_temp(&self.dir)?;
        let prepare = (|| -> Result<(), QuarantineError> {
            temp_file.write_all(bytes)?;
            temp_file.sync_all()?;
            harden_windows_handle_owner_only(&temp_file)?;
            Ok(())
        })();
        if let Err(error) = prepare {
            let _ = windows_delete_held_file(&temp_file);
            return Err(error);
        }
        if let Err(error) = windows_rename_held_file(&temp_file, &self.dir_handle, filename) {
            let _ = windows_delete_held_file(&temp_file);
            return Err(QuarantineError::Io(error));
        }
        drop(temp_file);
        util::fsync_parent_dir_logged(&path, "quarantine control-file publish");
        Ok(path)
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

        #[cfg(unix)]
        {
            self.materialize_blob_unix(&digest, filename)
        }

        #[cfg(windows)]
        {
            self.materialize_blob_windows(&digest, filename)
        }

        #[cfg(all(not(unix), not(windows)))]
        {
            let src = self.store.blob_path(&digest);
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
    }

    #[cfg(windows)]
    fn materialize_blob_windows(
        &self,
        digest: &str,
        filename: &str,
    ) -> Result<PathBuf, QuarantineError> {
        use std::io::Read as _;

        self.ensure_secure_path()?;
        let src = self.store.blob_path(digest);
        let blob = match open_windows_regular_no_reparse(&src, true) {
            Ok(file) => file,
            Err(OpenRegularError::TooLarge) => return Err(QuarantineError::TooLarge),
            Err(OpenRegularError::Io(error)) => return Err(QuarantineError::Io(error)),
            Err(OpenRegularError::NotFound) | Err(OpenRegularError::NotRegularFile) => {
                return Err(QuarantineError::BlobNotFound(digest.to_string()))
            }
        };
        harden_windows_handle_owner_only(&blob)?;
        let mut bytes = Vec::new();
        blob.take(ARTIFACT_MAX_FILE_SIZE.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > ARTIFACT_MAX_FILE_SIZE {
            return Err(QuarantineError::TooLarge);
        }
        let dest = self.dir.join(filename);
        if windows_path_is_reparse_point(&dest)? {
            return Err(QuarantineError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "transaction destination is a reparse point",
            )));
        }

        let (mut temp_file, _temp_name) = create_windows_secure_temp(&self.dir)?;
        let prepare = (|| -> Result<(), QuarantineError> {
            use std::io::Write as _;

            temp_file.write_all(&bytes)?;
            temp_file.sync_all()?;
            let actual = hash_regular_handle(&temp_file)?;
            if actual != digest {
                return Err(QuarantineError::DigestMismatch {
                    expected: digest.to_string(),
                    actual,
                });
            }
            harden_windows_handle_owner_only(&temp_file)?;
            Ok(())
        })();
        if let Err(error) = prepare {
            let _ = windows_delete_held_file(&temp_file);
            return Err(error);
        }
        if let Err(error) = windows_rename_held_file(&temp_file, &self.dir_handle, filename) {
            let _ = windows_delete_held_file(&temp_file);
            return Err(QuarantineError::Io(error));
        }
        drop(temp_file);
        util::fsync_parent_dir_logged(&dest, "quarantine transaction publish");
        Ok(dest)
    }

    #[cfg(unix)]
    fn materialize_blob_unix(
        &self,
        digest: &str,
        filename: &str,
    ) -> Result<PathBuf, QuarantineError> {
        use std::io::Read as _;

        self.ensure_secure_path()?;

        match open_regular_at(&self.dir_handle, filename, false) {
            Ok(_) | Err(OpenRegularError::NotFound) => {}
            Err(OpenRegularError::NotRegularFile) => {
                return Err(QuarantineError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "transaction destination is a symlink or non-regular file",
                )))
            }
            Err(OpenRegularError::TooLarge) => unreachable!("size cap was not requested"),
            Err(OpenRegularError::Io(error)) => return Err(QuarantineError::Io(error)),
        }

        let blob = match open_regular_at(&self.store.secure_dirs.blobs_sha256, digest, false) {
            Ok(file) => file,
            Err(OpenRegularError::TooLarge) => return Err(QuarantineError::TooLarge),
            Err(OpenRegularError::Io(error)) => return Err(QuarantineError::Io(error)),
            Err(OpenRegularError::NotFound) | Err(OpenRegularError::NotRegularFile) => {
                return Err(QuarantineError::BlobNotFound(digest.to_string()))
            }
        };
        let mut bytes = Vec::new();
        blob.take(ARTIFACT_MAX_FILE_SIZE.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > ARTIFACT_MAX_FILE_SIZE {
            return Err(QuarantineError::TooLarge);
        }

        let (mut temp_file, temp_name) = create_temp_at(&self.dir_handle)?;
        let write_result = (|| -> Result<(), QuarantineError> {
            use std::io::Write as _;
            temp_file.write_all(&bytes)?;
            temp_file.sync_all()?;
            let actual = hash_regular_handle(&temp_file)?;
            if actual != digest {
                return Err(QuarantineError::DigestMismatch {
                    expected: digest.to_string(),
                    actual,
                });
            }
            harden_file_handle(&temp_file)?;
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = unlink_file_at(&self.dir_handle, &temp_name);
            return Err(error);
        }
        if let Err(error) = rename_at(&self.dir_handle, &temp_name, &self.dir_handle, filename) {
            let _ = unlink_file_at(&self.dir_handle, &temp_name);
            return Err(QuarantineError::Io(error));
        }
        self.dir_handle.sync_all()?;
        self.ensure_secure_path()?;
        Ok(self.dir.join(filename))
    }

    /// The tracked Windows grants D4 must apply before container launch and revoke
    /// afterwards. The transaction directory and every explicitly named launch
    /// child receive read+execute because each file has its own protected DACL and
    /// therefore cannot inherit the directory's AppContainer ACE. Call this only
    /// after [`pin_files_for_launch`](Self::pin_files_for_launch), retaining those
    /// handles through grant application, launch, wait, and revocation so the
    /// path-based ACL executor cannot be redirected to a replacement identity.
    /// Returns an empty list on non-Windows targets after validating all names.
    pub fn windows_container_grants<'a>(
        &self,
        filenames: impl IntoIterator<Item = &'a str>,
    ) -> Result<Vec<crate::capsule::windows::AclGrant>, QuarantineError> {
        let filenames: Vec<&str> = filenames.into_iter().collect();
        for &filename in &filenames {
            validate_component(filename).map_err(|()| {
                QuarantineError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Windows container-grant filename is not one safe component",
                ))
            })?;
            if filename == LOCK_FILE {
                return Err(QuarantineError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "the transaction lock cannot be granted to the install container",
                )));
            }
        }

        #[cfg(windows)]
        {
            use crate::capsule::windows::{AclAccess, AclGrant};

            self.ensure_secure_path()?;
            let mut grants = Vec::with_capacity(filenames.len() + 1);
            grants.push(AclGrant {
                path: self.dir.clone(),
                access: AclAccess::ReadExecute,
            });
            grants.extend(filenames.into_iter().map(|filename| AclGrant {
                path: self.dir.join(filename),
                access: AclAccess::ReadExecute,
            }));
            return Ok(grants);
        }
        #[cfg(not(windows))]
        {
            Ok(Vec::new())
        }
    }
}

#[cfg(unix)]
fn open_dir_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let dir = options.open(path)?;
    if !dir.metadata()?.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotADirectory,
            format!("{} is not a directory", path.display()),
        ));
    }
    Ok(dir)
}

#[cfg(unix)]
fn open_or_create_dir_path_no_symlinks(path: &Path) -> std::io::Result<(PathBuf, File)> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    // Darwin exposes these three root-owned compatibility aliases on every
    // standard installation. Resolve only the fixed, OS-owned aliases before the
    // descriptor walk; arbitrary caller-controlled symlinks remain forbidden.
    #[cfg(target_os = "macos")]
    let absolute = normalize_macos_system_root_alias(absolute)?;
    let mut current = open_dir_no_follow(Path::new("/"))?;
    let mut saw_component = false;
    for component in absolute.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::Normal(name) => {
                current = create_or_open_dir_at_os(&current, name)?;
                saw_component = true;
            }
            std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "quarantine root must not contain parent or platform-prefix components",
                ))
            }
        }
    }
    if !saw_component {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to use the filesystem root as the quarantine root",
        ));
    }
    Ok((absolute, current))
}

#[cfg(target_os = "macos")]
fn normalize_macos_system_root_alias(path: PathBuf) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::MetadataExt as _;

    for (alias, target) in [
        (Path::new("/var"), Path::new("/private/var")),
        (Path::new("/tmp"), Path::new("/private/tmp")),
        (Path::new("/etc"), Path::new("/private/etc")),
    ] {
        let Ok(suffix) = path.strip_prefix(alias) else {
            continue;
        };
        let link = std::fs::symlink_metadata(alias)?;
        if !link.file_type().is_symlink() || link.uid() != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "refusing unexpected macOS system alias identity at {}",
                    alias.display()
                ),
            ));
        }
        let resolved = std::fs::canonicalize(alias)?;
        let target_metadata = std::fs::metadata(target)?;
        if resolved != target || !target_metadata.is_dir() || target_metadata.uid() != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "refusing unexpected macOS system alias target for {}",
                    alias.display()
                ),
            ));
        }
        return Ok(target.join(suffix));
    }
    Ok(path)
}

#[cfg(unix)]
fn path_matches_handle(path: &Path, handle: &File) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    let link_metadata = std::fs::symlink_metadata(path)?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_dir() {
        return Ok(false);
    }
    let path_metadata = std::fs::metadata(path)?;
    let handle_metadata = handle.metadata()?;
    Ok(
        path_metadata.dev() == handle_metadata.dev()
            && path_metadata.ino() == handle_metadata.ino(),
    )
}

#[cfg(windows)]
fn windows_wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt as _;

    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

#[cfg(windows)]
struct WindowsTokenHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for WindowsTokenHandle {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
struct WindowsCurrentUserSid {
    _storage: Vec<usize>,
    sid: windows_sys::Win32::Security::PSID,
}

#[cfg(windows)]
impl WindowsCurrentUserSid {
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
        let token = WindowsTokenHandle(raw_token);
        let mut needed = 0u32;
        if unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut needed) }
            != 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "TokenUser size query unexpectedly succeeded",
            ));
        }
        let size_error = std::io::Error::last_os_error();
        if size_error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) || needed == 0 {
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

#[cfg(windows)]
struct WindowsOwnerOnlySecurity {
    _user: WindowsCurrentUserSid,
    acl: Vec<usize>,
    descriptor: windows_sys::Win32::Security::SECURITY_DESCRIPTOR,
}

#[cfg(windows)]
impl WindowsOwnerOnlySecurity {
    fn new() -> std::io::Result<Self> {
        use windows_sys::Win32::Security::{
            AddAccessAllowedAceEx, GetLengthSid, InitializeAcl, InitializeSecurityDescriptor,
            SetSecurityDescriptorControl, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
            ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE,
            SECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
        };
        use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
        use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

        let user = WindowsCurrentUserSid::load()?;
        let sid_size = unsafe { GetLengthSid(user.sid) } as usize;
        if sid_size == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let acl_bytes = std::mem::size_of::<ACL>()
            .checked_add(std::mem::size_of::<ACCESS_ALLOWED_ACE>() - std::mem::size_of::<u32>())
            .and_then(|size| size.checked_add(sid_size))
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Windows ACL size overflow")
            })?;
        let word_size = std::mem::size_of::<usize>();
        let mut acl = vec![0usize; acl_bytes.div_ceil(word_size)];
        let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
        if unsafe { InitializeAcl(acl_ptr, acl_bytes as u32, ACL_REVISION) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe {
            AddAccessAllowedAceEx(
                acl_ptr,
                ACL_REVISION,
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                FILE_ALL_ACCESS,
                user.sid,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }

        let mut descriptor = SECURITY_DESCRIPTOR::default();
        if unsafe {
            InitializeSecurityDescriptor(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                SECURITY_DESCRIPTOR_REVISION,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe {
            SetSecurityDescriptorOwner(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                user.sid,
                0,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe {
            SetSecurityDescriptorDacl(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                1,
                acl_ptr,
                0,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe {
            SetSecurityDescriptorControl(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                SE_DACL_PROTECTED,
                SE_DACL_PROTECTED,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            _user: user,
            acl,
            descriptor,
        })
    }

    fn security_attributes(&mut self) -> windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                as u32,
            lpSecurityDescriptor: (&mut self.descriptor
                as *mut windows_sys::Win32::Security::SECURITY_DESCRIPTOR)
                .cast(),
            bInheritHandle: 0,
        }
    }

    fn acl(&self) -> *const windows_sys::Win32::Security::ACL {
        self.acl.as_ptr().cast()
    }
}

#[cfg(windows)]
struct WindowsLocalSecurityDescriptor(windows_sys::Win32::Security::PSECURITY_DESCRIPTOR);

#[cfg(windows)]
impl Drop for WindowsLocalSecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(self.0.cast());
        }
    }
}

#[cfg(windows)]
fn windows_verify_owner_only_handle(file: &File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetLengthSid,
        GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
        IsValidSid, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION,
        DACL_SECURITY_INFORMATION, INHERITED_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        SE_DACL_PROTECTED,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

    let current_user = WindowsCurrentUserSid::load()?;
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    if descriptor.is_null() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows object has no security descriptor",
        ));
    }
    let _owned_descriptor = WindowsLocalSecurityDescriptor(descriptor);

    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if owner.is_null()
        || unsafe { IsValidSid(owner) } == 0
        || unsafe { EqualSid(owner, current_user.sid) } == 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows quarantine object is not owned by the current user",
        ));
    }

    let mut control = 0u16;
    let mut revision = 0u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if control & SE_DACL_PROTECTED == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows quarantine DACL is not protected from inheritance",
        ));
    }

    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    if dacl_present == 0 || dacl.is_null() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows quarantine object has an absent or null DACL",
        ));
    }
    let mut acl_info = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    if acl_info.AceCount != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows quarantine DACL is not owner-only",
        ));
    }
    let mut raw_ace = std::ptr::null_mut();
    if unsafe { GetAce(dacl, 0, &mut raw_ace) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
    if (header.AceSize as usize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows quarantine DACL contains a truncated access entry",
        ));
    }
    let expected_sid_size = unsafe { GetLengthSid(current_user.sid) } as usize;
    let required_ace_size = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart)
        .checked_add(expected_sid_size)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Windows ACE size overflow")
        })?;
    if (header.AceSize as usize) < required_ace_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows quarantine DACL contains a truncated owner SID",
        ));
    }
    let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
    if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8
        || ace.Header.AceFlags & INHERITED_ACE as u8 != 0
        || ace.Mask != FILE_ALL_ACCESS
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows quarantine DACL contains an unexpected access entry",
        ));
    }
    let ace_sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
    if unsafe { IsValidSid(ace_sid) } == 0 || unsafe { EqualSid(ace_sid, current_user.sid) } == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows quarantine DACL grants a principal other than its owner",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn harden_windows_handle_owner_only(file: &File) -> Result<(), QuarantineError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Security::Authorization::{SetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    let security = WindowsOwnerOnlySecurity::new().map_err(QuarantineError::Io)?;
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            security._user.sid,
            std::ptr::null_mut(),
            security.acl(),
            std::ptr::null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(QuarantineError::Io(std::io::Error::from_raw_os_error(
            status as i32,
        )));
    }
    windows_verify_owner_only_handle(file).map_err(QuarantineError::Io)
}

#[cfg(windows)]
fn create_windows_dir_owner_only(path: &Path) -> std::io::Result<bool> {
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS};
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    let mut security = WindowsOwnerOnlySecurity::new()?;
    let attributes = security.security_attributes();
    let wide = windows_wide(path);
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } != 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(code) if code == ERROR_ALREADY_EXISTS as i32 || code == ERROR_FILE_EXISTS as i32 => {
            Ok(false)
        }
        _ => Err(error),
    }
}

#[cfg(windows)]
fn open_or_create_windows_dir_path_no_reparse(
    path: &Path,
) -> std::io::Result<(PathBuf, File, Vec<File>)> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let normal_count = absolute
        .components()
        .filter(|component| matches!(component, std::path::Component::Normal(_)))
        .count();
    if normal_count == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to use a filesystem root as the quarantine root",
        ));
    }
    let mut current = PathBuf::new();
    let mut held = Vec::new();
    let mut normal_index = 0usize;
    let mut root = None;
    for component in absolute.components() {
        match component {
            std::path::Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            std::path::Component::RootDir => current.push(Path::new(r"\")),
            std::path::Component::CurDir => {}
            std::path::Component::Normal(name) => {
                current.push(name);
                normal_index += 1;
                if normal_index == normal_count {
                    create_windows_dir_owner_only(&current)?;
                    let root_handle =
                        open_windows_dir_no_reparse_with_options(&current, false, true, false)?;
                    harden_windows_handle_owner_only(&root_handle).map_err(
                        |error| match error {
                            QuarantineError::Io(error) => error,
                            other => std::io::Error::other(other.to_string()),
                        },
                    )?;
                    root = Some(root_handle);
                } else {
                    match std::fs::create_dir(&current) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(error) => return Err(error),
                    }
                    held.push(open_windows_dir_no_reparse(&current)?);
                }
            }
            std::path::Component::ParentDir => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "quarantine root must not contain parent components",
                ))
            }
        }
    }
    let root = root.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "quarantine root did not produce a directory handle",
        )
    })?;
    Ok((absolute, root, held))
}

#[cfg(windows)]
fn open_windows_dir_no_reparse(path: &Path) -> std::io::Result<File> {
    open_windows_dir_no_reparse_with_options(path, false, false, false)
}

#[cfg(windows)]
fn open_or_create_windows_secure_dir(path: &Path) -> std::io::Result<File> {
    create_windows_dir_owner_only(path)?;
    let directory = open_windows_dir_no_reparse_with_options(path, false, true, false)?;
    harden_windows_handle_owner_only(&directory).map_err(|error| match error {
        QuarantineError::Io(error) => error,
        other => std::io::Error::other(other.to_string()),
    })?;
    Ok(directory)
}

#[cfg(windows)]
fn open_windows_dir_no_reparse_with_options(
    path: &Path,
    share_delete: bool,
    security_write: bool,
    delete_access: bool,
) -> std::io::Result<File> {
    use std::os::windows::io::{FromRawHandle as _, RawHandle};
    use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, DELETE,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING, WRITE_DAC, WRITE_OWNER,
    };

    let mut desired_access = GENERIC_READ;
    if security_write {
        desired_access |= WRITE_DAC | WRITE_OWNER;
    }
    if delete_access {
        desired_access |= DELETE;
    }
    let mut share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;
    if share_delete {
        share_mode |= FILE_SHARE_DELETE;
    }
    let wide = windows_wide(path);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            desired_access,
            share_mode,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        let error = std::io::Error::last_os_error();
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(handle);
        }
        return Err(error);
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(handle);
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is a reparse point or non-directory", path.display()),
        ));
    }
    // SAFETY: `CreateFileW` returned a fresh owned handle, transferred to `File`.
    Ok(unsafe { File::from_raw_handle(handle as RawHandle) })
}

#[cfg(windows)]
fn windows_handle_identity(file: &File) -> std::io::Result<(u32, u64)> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((
        info.dwVolumeSerialNumber,
        ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
    ))
}

#[cfg(windows)]
fn windows_path_matches_handle(path: &Path, handle: &File) -> std::io::Result<bool> {
    let observed = open_windows_dir_no_reparse(path)?;
    Ok(windows_handle_identity(&observed)? == windows_handle_identity(handle)?)
}

#[cfg(windows)]
fn windows_path_is_reparse_point(path: &Path) -> std::io::Result<bool> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(windows)]
fn windows_validate_regular_handle(file: &File, path: &Path) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is a reparse point or non-regular file", path.display()),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn open_windows_regular_no_reparse(
    path: &Path,
    security_write: bool,
) -> Result<File, OpenRegularError> {
    use std::os::windows::io::{FromRawHandle as _, RawHandle};
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GENERIC_READ, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, OPEN_EXISTING, WRITE_DAC,
        WRITE_OWNER,
    };

    let mut desired_access = GENERIC_READ;
    if security_write {
        desired_access |= WRITE_DAC | WRITE_OWNER;
    }
    let wide = windows_wide(path);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            desired_access,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(code)
                if code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PATH_NOT_FOUND as i32 =>
            {
                Err(OpenRegularError::NotFound)
            }
            _ => Err(OpenRegularError::Io(error)),
        };
    }
    let file = unsafe { File::from_raw_handle(handle as RawHandle) };
    if let Err(error) = windows_validate_regular_handle(&file, path) {
        return if error.kind() == std::io::ErrorKind::InvalidData {
            Err(OpenRegularError::NotRegularFile)
        } else {
            Err(OpenRegularError::Io(error))
        };
    }
    let metadata = file.metadata().map_err(OpenRegularError::Io)?;
    if metadata.len() > ARTIFACT_MAX_FILE_SIZE {
        return Err(OpenRegularError::TooLarge);
    }
    Ok(file)
}

#[cfg(windows)]
fn windows_existing_blob_matches(path: &Path, expected: &str) -> Result<bool, QuarantineError> {
    use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;

    // A concurrent publisher retains a no-sharing temp handle for a few
    // instructions after rename. Retry briefly so its successful publication is
    // not misreported as our failure; the wait is bounded and never weakens the
    // exact-handle DACL or digest checks below.
    const REOPEN_ATTEMPTS: usize = 40;
    for attempt in 0..REOPEN_ATTEMPTS {
        let file = match open_windows_regular_no_reparse(path, false) {
            Ok(file) => file,
            Err(OpenRegularError::NotFound | OpenRegularError::NotRegularFile) => return Ok(false),
            Err(OpenRegularError::TooLarge) => return Err(QuarantineError::TooLarge),
            Err(OpenRegularError::Io(error))
                if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32)
                    && attempt + 1 < REOPEN_ATTEMPTS =>
            {
                #[cfg(test)]
                if let Some(barrier) =
                    WINDOWS_BLOB_REOPEN_SHARING_BARRIER.with(|slot| slot.borrow_mut().take())
                {
                    barrier.wait();
                }
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(OpenRegularError::Io(error)) => return Err(QuarantineError::Io(error)),
        };
        windows_verify_owner_only_handle(&file)?;
        let actual = hash_regular_handle(&file)?;
        if actual != expected {
            return Err(QuarantineError::DigestMismatch {
                expected: expected.to_string(),
                actual,
            });
        }
        return Ok(true);
    }
    Ok(false)
}

#[cfg(windows)]
fn open_windows_pinned_regular(path: &Path) -> Result<File, QuarantineError> {
    use std::os::windows::io::{FromRawHandle as _, RawHandle};
    use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, OPEN_EXISTING,
    };

    let wide = windows_wide(path);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(QuarantineError::Io(std::io::Error::last_os_error()));
    }
    let file = unsafe { File::from_raw_handle(handle as RawHandle) };
    windows_validate_regular_handle(&file, path).map_err(QuarantineError::Io)?;
    Ok(file)
}

#[cfg(windows)]
fn create_windows_secure_temp(dir: &Path) -> Result<(File, String), QuarantineError> {
    use std::os::windows::io::{FromRawHandle as _, RawHandle};
    use windows_sys::Win32::Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, CREATE_NEW, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
        WRITE_DAC, WRITE_OWNER,
    };

    for _ in 0..16 {
        let name = format!(".tirith-tmp-{}", uuid::Uuid::new_v4());
        let path = dir.join(&name);
        let mut security = WindowsOwnerOnlySecurity::new().map_err(QuarantineError::Io)?;
        let attributes = security.security_attributes();
        let wide = windows_wide(&path);
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER,
                0,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(code)
                    if code == ERROR_ALREADY_EXISTS as i32 || code == ERROR_FILE_EXISTS as i32 =>
                {
                    continue;
                }
                _ => return Err(QuarantineError::Io(error)),
            }
        }
        let file = unsafe { File::from_raw_handle(handle as RawHandle) };
        if let Err(error) = windows_validate_regular_handle(&file, &path) {
            let _ = windows_delete_held_file(&file);
            return Err(QuarantineError::Io(error));
        }
        if let Err(error) = harden_windows_handle_owner_only(&file) {
            let _ = windows_delete_held_file(&file);
            return Err(error);
        }
        return Ok((file, name));
    }
    Err(QuarantineError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique Windows quarantine temp file",
    )))
}

#[cfg(windows)]
fn open_windows_lock_file(path: &Path, share_delete: bool) -> Result<File, QuarantineError> {
    use std::os::windows::io::{FromRawHandle as _, RawHandle};
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_ALWAYS, WRITE_DAC, WRITE_OWNER,
    };

    let mut security = WindowsOwnerOnlySecurity::new().map_err(QuarantineError::Io)?;
    let attributes = security.security_attributes();
    let mut share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;
    if share_delete {
        share_mode |= FILE_SHARE_DELETE;
    }
    let wide = windows_wide(path);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER,
            share_mode,
            &attributes,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(QuarantineError::Io(std::io::Error::last_os_error()));
    }
    let file = unsafe { File::from_raw_handle(handle as RawHandle) };
    windows_validate_regular_handle(&file, path).map_err(QuarantineError::Io)?;
    Ok(file)
}

#[cfg(windows)]
fn windows_rename_held_file(file: &File, parent: &File, name: &str) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{FILE_RENAME_INFO, FILE_RENAME_INFO_0};

    validate_component(name).map_err(|()| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows handle-relative rename target is not one safe component",
        )
    })?;
    let wide_name: Vec<u16> = std::ffi::OsStr::new(name).encode_wide().collect();
    let name_bytes = wide_name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|size| u32::try_from(size).ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Windows rename target is too long",
            )
        })?;
    let buffer_bytes = std::mem::offset_of!(FILE_RENAME_INFO, FileName)
        .checked_add(name_bytes as usize)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Windows rename buffer size overflow",
            )
        })?
        .max(std::mem::size_of::<FILE_RENAME_INFO>());
    let buffer_bytes_u32 = u32::try_from(buffer_bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows rename buffer exceeds the Win32 size limit",
        )
    })?;
    let word_size = std::mem::size_of::<usize>();
    let mut buffer = vec![0usize; buffer_bytes.div_ceil(word_size)];
    let rename = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    let mut mode = FILE_RENAME_INFO_0::default();
    mode.ReplaceIfExists = true;
    unsafe {
        (*rename).Anonymous = mode;
        (*rename).RootDirectory = parent.as_raw_handle();
        (*rename).FileNameLength = name_bytes;
        std::ptr::copy_nonoverlapping(
            wide_name.as_ptr(),
            std::ptr::addr_of_mut!((*rename).FileName).cast::<u16>(),
            wide_name.len(),
        );
    }
    // The Win32 wrapper (SetFileInformationByHandle + FileRenameInfo) rejects a
    // non-NULL RootDirectory with ERROR_INVALID_PARAMETER: it accepts full
    // destination paths only. The retained parent handle IS the point of this
    // rename (no by-name re-resolution an attacker could redirect), so call
    // the NT service directly — its FileRenameInformation honors
    // handle-relative names, and this buffer layout doubles as the kernel
    // struct (the union's first byte is the BOOLEAN the kernel reads).
    let mut io_status = windows_sys::Win32::System::IO::IO_STATUS_BLOCK::default();
    let status = unsafe {
        windows_sys::Wdk::Storage::FileSystem::NtSetInformationFile(
            file.as_raw_handle(),
            &mut io_status,
            rename.cast(),
            buffer_bytes_u32,
            windows_sys::Wdk::Storage::FileSystem::FileRenameInformation,
        )
    };
    if status < 0 {
        let code = unsafe { windows_sys::Win32::Foundation::RtlNtStatusToDosError(status) };
        return Err(std::io::Error::from_raw_os_error(code as i32));
    }
    Ok(())
}

#[cfg(windows)]
fn windows_delete_held_file(file: &File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };

    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn open_windows_delete_regular(path: &Path) -> std::io::Result<File> {
    use std::os::windows::io::{FromRawHandle as _, RawHandle};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let wide = windows_wide(path);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            DELETE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_handle(handle as RawHandle) };
    windows_validate_regular_handle(&file, path)?;
    Ok(file)
}

#[cfg(windows)]
fn windows_remove_dir_contents(dir: &Path) -> Result<(), QuarantineError> {
    let entries = std::fs::read_dir(dir).map_err(QuarantineError::Io)?;
    for entry in entries {
        let entry = entry.map_err(QuarantineError::Io)?;
        let path = entry.path();
        // Transaction layout is deliberately flat. Open each enumerated child as
        // an exact no-reparse, non-directory DELETE capability; any directory,
        // junction, symlink, or other special object aborts cleanup and leaves the
        // detached tombstone for investigation instead of traversing it.
        let child = open_windows_delete_regular(&path).map_err(QuarantineError::Io)?;
        windows_delete_held_file(&child).map_err(QuarantineError::Io)?;
    }
    Ok(())
}

#[cfg(unix)]
fn component_cstring(name: &std::ffi::OsStr) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt as _;

    if name.is_empty() || name.as_bytes().contains(&b'/') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "descriptor-relative name is not one path component",
        ));
    }
    std::ffi::CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "descriptor-relative name contains NUL",
        )
    })
}

#[cfg(unix)]
fn open_dir_at(parent: &File, name: &str) -> std::io::Result<File> {
    open_dir_at_os(parent, std::ffi::OsStr::new(name))
}

#[cfg(unix)]
fn open_dir_at_os(parent: &File, name: &std::ffi::OsStr) -> std::io::Result<File> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    let name = component_cstring(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a fresh owned descriptor.
    let dir = unsafe { File::from_raw_fd(fd) };
    if !dir.metadata()?.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotADirectory,
            "descriptor-relative entry is not a directory",
        ));
    }
    Ok(dir)
}

#[cfg(unix)]
fn lock_directory_exclusive(directory: &File) -> std::io::Result<File> {
    // Re-open `.` instead of duping the capability: flock state follows the
    // open file description, so a fresh descriptor is required for independent
    // same-process callers to contend with one another.
    let lock = open_dir_at_os(directory, std::ffi::OsStr::new("."))?;
    lock.lock_exclusive()?;
    Ok(lock)
}

#[cfg(unix)]
fn same_unix_identity(left: &File, right: &File) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(unix)]
fn dir_entry_matches_handle(parent: &File, name: &str, expected: &File) -> std::io::Result<bool> {
    match open_dir_at(parent, name) {
        Ok(observed) => same_unix_identity(&observed, expected),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) || error.raw_os_error() == Some(libc::ELOOP) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn file_entry_matches_handle(parent: &File, name: &str, expected: &File) -> std::io::Result<bool> {
    match open_regular_at(parent, name, false) {
        Ok(observed) => same_unix_identity(&observed, expected),
        Err(OpenRegularError::NotFound)
        | Err(OpenRegularError::NotRegularFile)
        | Err(OpenRegularError::TooLarge) => Ok(false),
        Err(OpenRegularError::Io(error)) => Err(error),
    }
}

#[cfg(unix)]
fn open_or_create_dir_at(parent: &File, name: &str) -> std::io::Result<File> {
    let dir = create_or_open_dir_at_os(parent, std::ffi::OsStr::new(name))?;
    harden_dir_handle(&dir)?;
    parent.sync_all()?;
    Ok(dir)
}

#[cfg(unix)]
fn create_or_open_dir_at_os(parent: &File, name: &std::ffi::OsStr) -> std::io::Result<File> {
    use std::os::fd::AsRawFd as _;

    let name_c = component_cstring(name)?;
    let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) };
    let created = rc == 0;
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error);
        }
    }
    let dir = open_dir_at_os(parent, name)?;
    if created {
        parent.sync_all()?;
    }
    Ok(dir)
}

#[cfg(unix)]
fn harden_dir_handle(dir: &File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    if unsafe { libc::fchmod(dir.as_raw_fd(), 0o700) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn harden_file_handle(file: &File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    if unsafe { libc::fchmod(file.as_raw_fd(), 0o400) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn open_regular_at(
    parent: &File,
    name: &str,
    enforce_artifact_cap: bool,
) -> Result<File, OpenRegularError> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    let name = component_cstring(std::ffi::OsStr::new(name)).map_err(OpenRegularError::Io)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOENT) => Err(OpenRegularError::NotFound),
            Some(libc::ELOOP) | Some(libc::ENXIO) | Some(libc::ENODEV) => {
                Err(OpenRegularError::NotRegularFile)
            }
            _ => Err(OpenRegularError::Io(error)),
        };
    }
    // SAFETY: `openat` returned a fresh owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(OpenRegularError::Io)?;
    if !metadata.is_file() {
        return Err(OpenRegularError::NotRegularFile);
    }
    if enforce_artifact_cap && metadata.len() > ARTIFACT_MAX_FILE_SIZE {
        return Err(OpenRegularError::TooLarge);
    }
    Ok(file)
}

#[cfg(unix)]
fn create_temp_at(parent: &File) -> std::io::Result<(File, String)> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    for _ in 0..16 {
        let name = format!(".tirith-tmp-{}", uuid::Uuid::new_v4());
        let name_c = component_cstring(std::ffi::OsStr::new(&name))?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd >= 0 {
            // SAFETY: `openat` returned a fresh owned descriptor.
            return Ok((unsafe { File::from_raw_fd(fd) }, name));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique quarantine temp file",
    ))
}

#[cfg(any(unix, windows))]
fn hash_regular_handle(file: &File) -> Result<String, QuarantineError> {
    use std::io::{Seek as _, SeekFrom};

    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    match util::sha256_from_handle(reader, ARTIFACT_MAX_FILE_SIZE)? {
        HashOutcome::Digest(digest) => Ok(digest),
        HashOutcome::BudgetExceeded => Err(QuarantineError::TooLarge),
    }
}

#[cfg(unix)]
fn open_lock_file_at(parent: &File) -> std::io::Result<File> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    let name = component_cstring(std::ffi::OsStr::new(LOCK_FILE))?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a fresh owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "quarantine lock is not a regular file",
        ));
    }
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(file)
}

#[cfg(unix)]
fn rename_at(from_dir: &File, from: &str, to_dir: &File, to: &str) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    let from = component_cstring(std::ffi::OsStr::new(from))?;
    let to = component_cstring(std::ffi::OsStr::new(to))?;
    if unsafe {
        libc::renameat(
            from_dir.as_raw_fd(),
            from.as_ptr(),
            to_dir.as_raw_fd(),
            to.as_ptr(),
        )
    } == 0
    {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn unlink_file_at(parent: &File, name: &str) -> std::io::Result<()> {
    unlink_file_at_os(parent, std::ffi::OsStr::new(name))
}

#[cfg(unix)]
fn unlink_file_at_os(parent: &File, name: &std::ffi::OsStr) -> std::io::Result<()> {
    unlink_at_os(parent, name, 0)
}

#[cfg(unix)]
fn unlink_dir_at(parent: &File, name: &str) -> std::io::Result<()> {
    unlink_dir_at_os(parent, std::ffi::OsStr::new(name))
}

#[cfg(unix)]
fn unlink_dir_at_os(parent: &File, name: &std::ffi::OsStr) -> std::io::Result<()> {
    unlink_at_os(parent, name, libc::AT_REMOVEDIR)
}

#[cfg(unix)]
fn unlink_at_os(parent: &File, name: &std::ffi::OsStr, flags: i32) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    let name = component_cstring(name)?;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn gc_tombstone_name() -> String {
    format!("{GC_TOMBSTONE_PREFIX}{}", uuid::Uuid::new_v4())
}

#[cfg(all(unix, any(target_os = "linux", target_os = "emscripten")))]
fn readdir_errno_slot() -> Option<*mut libc::c_int> {
    Some(unsafe { libc::__errno_location() })
}

#[cfg(all(unix, target_os = "android"))]
fn readdir_errno_slot() -> Option<*mut libc::c_int> {
    Some(unsafe { libc::__errno() })
}

#[cfg(all(
    unix,
    any(target_os = "macos", target_os = "ios", target_os = "freebsd")
))]
fn readdir_errno_slot() -> Option<*mut libc::c_int> {
    Some(unsafe { libc::__error() })
}

#[cfg(all(unix, target_os = "dragonfly"))]
fn readdir_errno_slot() -> Option<*mut libc::c_int> {
    Some(unsafe { libc::__errno_location() })
}

#[cfg(all(unix, any(target_os = "openbsd", target_os = "netbsd")))]
fn readdir_errno_slot() -> Option<*mut libc::c_int> {
    Some(unsafe { libc::__errno() })
}

#[cfg(all(unix, any(target_os = "solaris", target_os = "illumos")))]
fn readdir_errno_slot() -> Option<*mut libc::c_int> {
    Some(unsafe { libc::___errno() })
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "emscripten",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "solaris",
        target_os = "illumos"
    ))
))]
fn readdir_errno_slot() -> Option<*mut libc::c_int> {
    None
}

#[cfg(unix)]
fn readdir_entry(stream: *mut libc::DIR) -> *mut libc::dirent {
    #[cfg(test)]
    if READDIR_ERROR_TEST_HOOK.with(std::cell::Cell::take) {
        if let Some(errno) = readdir_errno_slot() {
            unsafe {
                *errno = libc::EIO;
            }
        }
        return std::ptr::null_mut();
    }
    unsafe { libc::readdir(stream) }
}

#[cfg(unix)]
fn read_dir_names(dir: &File) -> std::io::Result<Vec<std::ffi::OsString>> {
    use std::ffi::CStr;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStringExt as _;

    let errno = readdir_errno_slot().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "secure directory enumeration cannot distinguish readdir failure from EOF on this Unix target",
        )
    })?;
    let dot = std::ffi::CString::new(".").expect("static component has no NUL");
    // Re-open `.` relative to the capability instead of `dup`ing it: a fresh
    // open file description has an independent directory offset, so concurrent
    // or repeated enumerations cannot make each other start at EOF.
    let directory_fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if directory_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let stream = unsafe { libc::fdopendir(directory_fd) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(directory_fd);
        }
        return Err(error);
    }

    let mut names = Vec::new();
    loop {
        // POSIX distinguishes EOF from a real enumeration failure through errno.
        // Clear it before every call so a partial scan cannot be reported as a
        // complete cleanup inventory.
        unsafe {
            *errno = 0;
        }
        let entry = readdir_entry(stream);
        if entry.is_null() {
            let readdir_errno = unsafe { *errno };
            if unsafe { libc::closedir(stream) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if readdir_errno != 0 {
                return Err(std::io::Error::from_raw_os_error(readdir_errno));
            }
            return Ok(names);
        }
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        names.push(std::ffi::OsString::from_vec(bytes.to_vec()));
    }
}

#[cfg(unix)]
fn remove_dir_contents(dir: &File) -> std::io::Result<()> {
    for name in read_dir_names(dir)? {
        match open_dir_at_os(dir, &name) {
            Ok(child) => {
                remove_dir_contents(&child)?;
                drop(child);
                unlink_dir_at_os(dir, &name)?;
            }
            Err(_) => unlink_file_at_os(dir, &name)?,
        }
    }
    Ok(())
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
#[cfg(all(not(unix), not(windows)))]
fn open_lock_file(path: &Path) -> Result<File, QuarantineError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create(true);
    opts.open(path).map_err(QuarantineError::Io)
}

/// Create a random `O_EXCL` temp file inside `dir` for an atomic same-dir publish,
/// returning the open handle and its path. Unix mode is `0o600` (tightened to
/// `0o400` on the published name). The random name comes from
/// [`tempfile::NamedTempFile`]; we keep the path and the file separately so the
/// caller can `rename` it (rather than letting the temp drop-delete).
#[cfg(all(not(unix), not(windows)))]
fn create_excl_temp(dir: &Path) -> Result<(File, PathBuf), QuarantineError> {
    let tmp = tempfile::NamedTempFile::new_in(dir).map_err(QuarantineError::Io)?;
    // Split into (file, path): `keep` disarms the drop-delete so the rename owns it.
    let (file, temp_path) = tmp.keep().map_err(|e| QuarantineError::Io(e.error))?;
    Ok((file, temp_path))
}

/// Hash the file at `path` from a no-follow, fstat'd handle (the single-handle
/// TOCTOU-safe pattern). Returns the lowercase-hex SHA-256.
#[cfg(all(not(unix), not(windows)))]
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

/// Unsupported-platform fallback for the directory permission hook. Unix and
/// Windows use descriptor/handle-specific hardening above.
#[cfg(all(not(unix), not(windows)))]
fn harden_dir_perms(dir: &Path) -> Result<(), QuarantineError> {
    let _ = dir;
    Ok(())
}

/// Unsupported-platform fallback for immutable-file permissions. Unix and
/// Windows use descriptor/handle-specific hardening above.
#[cfg(all(not(unix), not(windows)))]
fn harden_file_perms_immutable(path: &Path) -> Result<(), QuarantineError> {
    let _ = path;
    Ok(())
}

/// Non-Unix fallback for removing an immutable published file. Unix cleanup is
/// descriptor-relative and handled in the Unix store implementation above.
#[cfg(not(unix))]
fn remove_immutable_file(path: &Path) -> std::io::Result<()> {
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

    #[cfg(unix)]
    #[test]
    fn ingest_rejects_symlinked_blob_destination_without_touching_target() {
        use std::os::unix::fs::symlink;

        let (_tmp, store) = store();
        let bytes = b"new quarantined bytes";
        let digest = sha256_hex(bytes);
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), b"unchanged").unwrap();
        symlink(outside.path(), store.blob_path(&digest)).unwrap();

        assert!(store.ingest_bytes(bytes, &digest).is_err());
        assert_eq!(std::fs::read(outside.path()).unwrap(), b"unchanged");
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
    fn ingest_file_rejects_oversized_sparse_source_before_reading() {
        let (tmp, store) = store();
        let src = tmp.path().join("oversized.whl");
        let file = File::create(&src).unwrap();
        file.set_len(ARTIFACT_MAX_FILE_SIZE + 1).unwrap();
        drop(file);

        assert!(matches!(
            store.ingest_file(&src, &sha256_hex(b"irrelevant")),
            Err(QuarantineError::TooLarge)
        ));
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

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_launch_pins_preserve_input_order_content_and_digest_after_name_replacement() {
        use std::io::Read as _;

        let (_tmp, store) = store();
        let wheel_bytes = b"PK\x03\x04 Linux launch pin wheel";
        let wheel_digest = sha256_hex(wheel_bytes);
        store.ingest_bytes(wheel_bytes, &wheel_digest).unwrap();
        let transaction = store.begin_transaction("linux-launch-pins").unwrap();
        let wheel_name = "pkg-1.0-py3-none-any.whl";
        let wheel = transaction
            .materialize_blob(&wheel_digest, wheel_name)
            .unwrap();
        let approved_bytes = b"pkg==1.0 --hash=sha256:0123456789abcdef\n";
        let approved = transaction
            .write_control_file_atomic_0600("approved.txt", approved_bytes)
            .unwrap();

        let pins = transaction
            .pin_files_for_launch(["approved.txt", wheel_name])
            .unwrap();
        assert_eq!(pins.len(), 2);

        // Replacing both public names after pinning must not change the exact
        // objects consumed through the returned capabilities.
        std::fs::rename(&approved, transaction.dir().join("approved.displaced")).unwrap();
        std::fs::write(&approved, b"attacker replacement requirements").unwrap();
        std::fs::rename(&wheel, transaction.dir().join("wheel.displaced")).unwrap();
        std::fs::write(&wheel, b"attacker replacement wheel").unwrap();

        let mut observed = Vec::new();
        for mut pin in pins {
            let mut bytes = Vec::new();
            pin.read_to_end(&mut bytes).unwrap();
            observed.push(bytes);
        }
        assert_eq!(observed[0].as_slice(), approved_bytes);
        assert_eq!(observed[1].as_slice(), wheel_bytes);
        assert_eq!(sha256_hex(&observed[0]), sha256_hex(approved_bytes));
        assert_eq!(sha256_hex(&observed[1]), wheel_digest);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_launch_pins_reject_components_lock_symlink_fifo_and_oversize() {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::symlink;

        let (_tmp, store) = store();
        let transaction = store
            .begin_transaction("linux-launch-pin-rejections")
            .unwrap();

        for rejected in ["../approved.txt", ".lock"] {
            assert!(matches!(
                transaction.pin_files_for_launch([rejected]),
                Err(QuarantineError::Io(ref error))
                    if error.kind() == std::io::ErrorKind::InvalidInput
            ));
        }

        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), b"outside must not be opened").unwrap();
        symlink(outside.path(), transaction.dir().join("linked.whl")).unwrap();
        assert!(matches!(
            transaction.pin_files_for_launch(["linked.whl"]),
            Err(QuarantineError::Io(ref error))
                if error.kind() == std::io::ErrorKind::InvalidData
        ));
        assert_eq!(
            std::fs::read(outside.path()).unwrap(),
            b"outside must not be opened"
        );

        let fifo = transaction.dir().join("artifact.fifo");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            transaction.pin_files_for_launch(["artifact.fifo"]),
            Err(QuarantineError::Io(ref error))
                if error.kind() == std::io::ErrorKind::InvalidData
        ));

        let oversized = transaction.dir().join("oversized.whl");
        let oversized_file = File::create(&oversized).unwrap();
        oversized_file.set_len(ARTIFACT_MAX_FILE_SIZE + 1).unwrap();
        drop(oversized_file);
        assert!(matches!(
            transaction.pin_files_for_launch(["oversized.whl"]),
            Err(QuarantineError::TooLarge)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_launch_pins_reject_visible_transaction_directory_replacement() {
        let (tmp, store) = store();
        let transaction = store
            .begin_transaction("linux-launch-parent-replacement")
            .unwrap();
        transaction
            .write_control_file_atomic_0600("approved.txt", b"approved original")
            .unwrap();

        let public = transaction.dir().to_path_buf();
        let displaced = tmp.path().join("transaction-displaced");
        std::fs::rename(&public, &displaced).unwrap();
        std::fs::create_dir(&public).unwrap();
        std::fs::write(public.join("approved.txt"), b"attacker replacement").unwrap();

        assert!(matches!(
            transaction.pin_files_for_launch(["approved.txt"]),
            Err(QuarantineError::PathEscape(ref path)) if path == &public
        ));
        assert_eq!(
            std::fs::read(public.join("approved.txt")).unwrap(),
            b"attacker replacement"
        );
        assert_eq!(
            std::fs::read(displaced.join("approved.txt")).unwrap(),
            b"approved original"
        );
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

    #[cfg(unix)]
    #[test]
    fn with_root_rejects_preexisting_symlinked_security_directories() {
        use std::os::unix::fs::symlink;

        let base = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();

        let root_link = base.path().join("root-link");
        symlink(outside.path(), &root_link).unwrap();
        assert!(QuarantineStore::with_root(root_link).is_err());

        let ancestor_link = base.path().join("ancestor-link");
        symlink(outside.path(), &ancestor_link).unwrap();
        assert!(QuarantineStore::with_root(ancestor_link.join("q")).is_err());
        assert!(
            !outside.path().join("q").exists(),
            "initialization must not create a root through an intermediate symlink"
        );

        let root = base.path().join("q");
        std::fs::create_dir(&root).unwrap();
        symlink(outside.path(), root.join(BLOBS_DIR)).unwrap();
        assert!(QuarantineStore::with_root(root).is_err());
        assert!(
            std::fs::read_dir(outside.path()).unwrap().next().is_none(),
            "initialization must not create quarantine state through a symlink"
        );
    }

    #[cfg(unix)]
    #[test]
    fn transaction_rejects_symlinked_directory_and_lock_without_touching_targets() {
        use std::os::unix::fs::symlink;

        let (_tmp, store) = store();
        let outside = tempfile::tempdir().unwrap();
        symlink(
            outside.path(),
            store.transactions_dir().join("linked-transaction"),
        )
        .unwrap();
        assert!(store.begin_transaction("linked-transaction").is_err());
        assert!(
            std::fs::read_dir(outside.path()).unwrap().next().is_none(),
            "a symlinked transaction must not receive a lock file"
        );

        let lock_target = outside.path().join("lock-target");
        std::fs::write(&lock_target, b"unchanged").unwrap();
        let transaction = store.transactions_dir().join("linked-lock");
        std::fs::create_dir(&transaction).unwrap();
        symlink(&lock_target, transaction.join(LOCK_FILE)).unwrap();
        assert!(store.begin_transaction("linked-lock").is_err());
        assert_eq!(std::fs::read(&lock_target).unwrap(), b"unchanged");
    }

    #[cfg(unix)]
    #[test]
    fn store_rejects_visible_directory_replacement_after_open() {
        use std::os::unix::fs::symlink;

        let (tmp, store) = store();
        let original = store.transactions_dir();
        let displaced = tmp.path().join("transactions-displaced");
        let outside = tempfile::tempdir().unwrap();
        std::fs::rename(&original, &displaced).unwrap();
        symlink(outside.path(), &original).unwrap();

        assert!(matches!(
            store.begin_transaction("raced"),
            Err(QuarantineError::PathEscape(_))
        ));
        assert!(
            std::fs::read_dir(outside.path()).unwrap().next().is_none(),
            "a replacement path must not redirect descriptor-relative operations"
        );
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

    #[cfg(any(unix, windows))]
    #[test]
    fn gc_detaches_old_transaction_before_a_same_id_lease_can_restart() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let (_tmp, store) = store();
        {
            let old = store.begin_transaction("restartable").unwrap();
            std::fs::write(old.dir().join("old-only"), b"old").unwrap();
        }

        let replacement: Rc<RefCell<Option<QuarantineTransaction>>> = Rc::new(RefCell::new(None));
        let captured = Rc::clone(&replacement);
        let restart_store = store.clone();
        GC_TOMBSTONE_TEST_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |name| {
                assert_eq!(name, "restartable");
                let fresh = restart_store.begin_transaction(name).unwrap();
                std::fs::write(fresh.dir().join("new-only"), b"new").unwrap();
                *captured.borrow_mut() = Some(fresh);
            }));
        });

        let removed = store.gc_transactions(Duration::from_secs(0)).unwrap();
        GC_TOMBSTONE_TEST_HOOK.with(|slot| *slot.borrow_mut() = None);
        assert_eq!(removed, 1, "only the detached old identity is collected");
        assert!(
            replacement.borrow().is_some(),
            "the fresh lease remains held"
        );
        assert_eq!(
            std::fs::read(store.transactions_dir().join("restartable/new-only")).unwrap(),
            b"new"
        );
        assert!(!store
            .transactions_dir()
            .join("restartable/old-only")
            .exists());
    }

    #[cfg(unix)]
    #[test]
    fn gc_rejects_public_transaction_replacement_before_tombstone() {
        use std::cell::Cell;
        use std::rc::Rc;

        let (_tmp, store) = store();
        {
            let old = store.begin_transaction("replace-before-tombstone").unwrap();
            std::fs::write(old.dir().join("old-only"), b"old").unwrap();
        }

        let public = store.transactions_dir().join("replace-before-tombstone");
        let displaced = store.transactions_dir().join("displaced-old");
        let fired = Rc::new(Cell::new(false));
        let hook_fired = Rc::clone(&fired);
        let hook_public = public.clone();
        let hook_displaced = displaced.clone();
        GC_PRE_TOMBSTONE_TEST_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |name| {
                assert_eq!(name, "replace-before-tombstone");
                hook_fired.set(true);
                std::fs::rename(&hook_public, &hook_displaced).unwrap();
                std::fs::create_dir(&hook_public).unwrap();
                std::fs::write(hook_public.join("replacement-only"), b"replacement").unwrap();
            }));
        });

        let result = store.gc_transactions(Duration::from_secs(0));
        GC_PRE_TOMBSTONE_TEST_HOOK.with(|slot| *slot.borrow_mut() = None);
        let removed = result.unwrap();

        assert!(fired.get(), "the deterministic replacement seam must run");
        assert_eq!(removed, 0, "GC must not detach the replacement identity");
        assert_eq!(
            std::fs::read(public.join("replacement-only")).unwrap(),
            b"replacement"
        );
        assert_eq!(std::fs::read(displaced.join("old-only")).unwrap(), b"old");
        assert!(
            std::fs::read_dir(store.transactions_dir())
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(GC_TOMBSTONE_PREFIX)),
            "a failed identity check must not create a GC tombstone"
        );
    }

    #[cfg(unix)]
    #[test]
    fn directory_enumeration_propagates_readdir_failure() {
        let (_tmp, store) = store();
        READDIR_ERROR_TEST_HOOK.with(|hook| hook.set(true));
        let error = read_dir_names(&store.secure_dirs.transactions).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
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

    #[cfg(windows)]
    #[test]
    fn windows_blob_collision_reopens_and_accepts_only_the_exact_blob() {
        use std::io::Write as _;
        use std::sync::{Arc, Barrier};

        let (_tmp, store) = store();
        let bytes = b"concurrent idempotent Windows publication";
        let digest = sha256_hex(bytes);
        let final_path = store.blob_path(&digest);
        let (mut winning_handle, _temp_name) =
            create_windows_secure_temp(&store.blobs_sha256_dir()).unwrap();
        winning_handle.write_all(bytes).unwrap();
        winning_handle.sync_all().unwrap();
        assert_eq!(hash_regular_handle(&winning_handle).unwrap(), digest);
        harden_windows_handle_owner_only(&winning_handle).unwrap();
        windows_rename_held_file(&winning_handle, &store.secure_windows.blobs_sha256, &digest)
            .unwrap();

        // The successfully renamed handle still has no sharing. Prove the losing
        // publisher observes that real collision, waits, then reopens and verifies
        // the exact protected object after the winner releases its handle.
        let sharing_observed = Arc::new(Barrier::new(2));
        let verifier_barrier = Arc::clone(&sharing_observed);
        let verifier_path = final_path.clone();
        let verifier_digest = digest.clone();
        let verifier = std::thread::spawn(move || {
            WINDOWS_BLOB_REOPEN_SHARING_BARRIER.with(|slot| {
                *slot.borrow_mut() = Some(verifier_barrier);
            });
            windows_existing_blob_matches(&verifier_path, &verifier_digest)
        });
        sharing_observed.wait();
        drop(winning_handle);
        assert!(verifier.join().unwrap().unwrap());

        let wrong_digest = "0".repeat(64);
        assert!(matches!(
            windows_existing_blob_matches(&final_path, &wrong_digest),
            Err(QuarantineError::DigestMismatch { .. })
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_store_objects_have_protected_owner_only_dacls() {
        let (_tmp, store) = store();
        for directory in [
            &store.secure_windows.root,
            &store.secure_windows.blobs,
            &store.secure_windows.blobs_sha256,
            &store.secure_windows.transactions,
        ] {
            windows_verify_owner_only_handle(directory).unwrap();
        }

        let bytes = b"PK\x03\x04 Windows DACL test";
        let digest = sha256_hex(bytes);
        store.ingest_bytes(bytes, &digest).unwrap();
        let blob = open_windows_regular_no_reparse(&store.blob_path(&digest), false).unwrap();
        windows_verify_owner_only_handle(&blob).unwrap();
        drop(blob);

        let transaction = store.begin_transaction("windows-dacl").unwrap();
        windows_verify_owner_only_handle(&transaction.dir_handle).unwrap();
        windows_verify_owner_only_handle(&transaction._lock).unwrap();
        let wheel_name = "pkg-1.0-py3-none-any.whl";
        transaction.materialize_blob(&digest, wheel_name).unwrap();
        transaction
            .write_control_file_atomic_0600("approved.txt", b"approved")
            .unwrap();
        for file in transaction
            .pin_files_for_launch(["approved.txt", wheel_name])
            .unwrap()
        {
            windows_verify_owner_only_handle(&file).unwrap();
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_launch_pins_preserve_order_and_block_write_or_delete() {
        let (_tmp, store) = store();
        let bytes = b"PK\x03\x04 Windows launch pin test";
        let digest = sha256_hex(bytes);
        store.ingest_bytes(bytes, &digest).unwrap();
        let transaction = store.begin_transaction("windows-pins").unwrap();
        let wheel_name = "pkg-1.0-py3-none-any.whl";
        let wheel = transaction.materialize_blob(&digest, wheel_name).unwrap();
        let approved = transaction
            .write_control_file_atomic_0600("approved.txt", b"approved")
            .unwrap();

        let pins = transaction
            .pin_files_for_launch(["approved.txt", wheel_name])
            .unwrap();
        let grants = transaction
            .windows_container_grants(["approved.txt", wheel_name])
            .unwrap();
        assert_eq!(grants.len(), 3);
        assert_eq!(grants[0].path.as_path(), transaction.dir());
        assert_eq!(grants[1].path, approved);
        assert_eq!(grants[2].path, wheel);
        let approved_observed = open_windows_pinned_regular(&approved).unwrap();
        let wheel_observed = open_windows_pinned_regular(&wheel).unwrap();
        assert_eq!(
            windows_handle_identity(&pins[0]).unwrap(),
            windows_handle_identity(&approved_observed).unwrap()
        );
        assert_eq!(
            windows_handle_identity(&pins[1]).unwrap(),
            windows_handle_identity(&wheel_observed).unwrap()
        );
        drop(approved_observed);
        drop(wheel_observed);

        assert!(std::fs::OpenOptions::new()
            .write(true)
            .open(&wheel)
            .is_err());
        assert!(std::fs::remove_file(&wheel).is_err());
        drop(pins);
        assert!(std::fs::OpenOptions::new().write(true).open(&wheel).is_ok());
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

    #[cfg(unix)]
    #[test]
    fn materialize_rejects_symlinked_destination_without_touching_target() {
        use std::os::unix::fs::symlink;

        let (_tmp, store) = store();
        let bytes = b"PK\x03\x04 safe body";
        let digest = sha256_hex(bytes);
        store.ingest_bytes(bytes, &digest).unwrap();
        let transaction = store.begin_transaction("symlink-destination").unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), b"unchanged").unwrap();
        let filename = "pkg-1.0-py3-none-any.whl";
        symlink(outside.path(), transaction.dir().join(filename)).unwrap();

        assert!(transaction.materialize_blob(&digest, filename).is_err());
        assert_eq!(std::fs::read(outside.path()).unwrap(), b"unchanged");
    }

    #[cfg(windows)]
    #[test]
    fn materialize_rejects_windows_reparse_destination_without_touching_target() {
        use std::os::windows::fs::symlink_file;

        let (_tmp, store) = store();
        let bytes = b"PK\x03\x04 safe Windows body";
        let digest = sha256_hex(bytes);
        store.ingest_bytes(bytes, &digest).unwrap();
        let transaction = store
            .begin_transaction("windows-reparse-destination")
            .unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), b"unchanged").unwrap();
        let filename = "pkg-1.0-py3-none-any.whl";
        if let Err(error) = symlink_file(outside.path(), transaction.dir().join(filename)) {
            // Windows without Developer Mode or SeCreateSymbolicLinkPrivilege
            // cannot construct this adversarial fixture.
            if error.raw_os_error() == Some(1314) {
                return;
            }
            panic!("could not create Windows reparse fixture: {error}");
        }

        assert!(transaction.materialize_blob(&digest, filename).is_err());
        assert_eq!(std::fs::read(outside.path()).unwrap(), b"unchanged");
    }
}
