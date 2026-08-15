//! Contained install-from-digest for the package firewall (PR D4, CLI half).
//!
//! `tirith-core`'s [`tirith_core::artifact::install`] does the pure planning: it
//! re-binds the approval against the live threat DB (re-hashing every quarantine
//! blob), and produces a [`tirith_core::artifact::install::DigestInstallPlan`]
//! carrying the `approved.txt` text, the materialised wheel paths, and a
//! locked-down **deny-all-network** [`tirith_core::capsule::CapsuleSpec`]. This
//! module is the side-effecting half that the core crate cannot host (it needs the
//! OS capsule backends, which live in the CLI crate):
//!
//! 1. Write the plan's `approved.txt` through the retained quarantine-directory
//!    capability (atomic, `0o600`), giving pip the exact hash-pinned requirements
//!    file produced by the re-bind.
//! 2. Build the `python -I -m pip install --isolated --no-index --no-deps
//!    --require-hashes --no-cache-dir --force-reinstall --upgrade --target ...
//!    -r approved.txt` argv.
//! 3. Run the sealed interpreter through
//!    [`crate::cli::capsule::run_to_completion_bound_inputs`], passing every wheel,
//!    `approved.txt`, and the private pending target as held capabilities. Only a
//!    verified install is atomically published to the approved final name. An ancestor
//!    rename/replacement cannot redirect pip to attacker-controlled bytes. End-to-end
//!    enforcing execution is x86_64 Linux-only; every other platform or architecture
//!    **fails closed before pip starts** (cross-cutting invariant 2) rather than
//!    running uncontained. The non-executing analysis, approval, and environment-
//!    verification scopes are unchanged.
//!
//! # The grep-test invariant
//!
//! The plan requires that the install-from-digest path **never** calls the
//! uncontained [`crate::cli::install::ProcessInstallRunner`] (the analysis-path
//! runner that installs with the user's full privileges and no containment). That
//! holds here by construction: this module's only spawn is through the capsule
//! seam, and it does not name `ProcessInstallRunner` at all. A guard test
//! (`source_never_references_process_install_runner`) reads this file's source and
//! asserts the symbol is absent, so a future edit cannot silently route the
//! enforcing install through the uncontained runner.
//!
//! [`run_contained_install`] is the production side-effect seam called by
//! `tirith pkg install` on x86_64 Linux. Unsupported platforms and architectures
//! refuse before package execution. Platform-gated recovery helpers remain compiled
//! only on their owning targets; the module-level dead-code allowance covers those
//! narrow compatibility seams without weakening the launch path.
#![allow(dead_code)]

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Write as _;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd as _, FromRawFd as _};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt as _;

#[cfg(target_os = "linux")]
use fs2::FileExt as _;
#[cfg(target_os = "linux")]
use serde::Serialize;
#[cfg(target_os = "linux")]
use sha2::{Digest as _, Sha256};

use tirith_core::artifact::install::{
    verify_post_install_record_exact, DigestInstallPlan, ExpectedInstalledDistribution,
    InstallCommand, PostInstallIntegrity,
};
use tirith_core::artifact::quarantine::{QuarantineError, QuarantineTransaction};
use tirith_core::artifact::resolver::BoundResolverTools;
use tirith_core::policy::Policy;
use tirith_core::receipt::{
    ArtifactScanReceipt, CapsuleReceipt, PostInstallRecordSummary, ReceiptError,
    RecordedCommittedReceipt, RecordedReceipt, VerdictSummary,
};

use crate::cli::capsule::{self, BoundLaunchArg, BoundLaunchDirectory, BoundLaunchInput};

/// The file name of the generated requirements file written into the transaction
/// directory. A single safe component; pip reads it via `-r`.
const APPROVED_REQUIREMENTS_FILE: &str = "approved.txt";

#[cfg(test)]
thread_local! {
    /// Deterministic seam for replacing the visible quarantine path after the
    /// launcher capability has been cloned but before the final identity check.
    /// Production builds do not contain this hook.
    static PRE_BOUND_LAUNCH_TEST_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn invoke_pre_bound_launch_test_hook() {
    PRE_BOUND_LAUNCH_TEST_HOOK.with(|hook| {
        if let Some(mut hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

/// A capability-held, narrowly journaled install target.
///
/// Enforcing installs intentionally accept only a *new*, dedicated target. That
/// fail-closed restriction means rollback never needs to copy or reconstruct an
/// existing environment (which was both metadata-lossy and potentially as large as
/// `/usr` or a Homebrew prefix). On Linux, creation, identity checks, rollback, and
/// journaling are all relative to retained directory descriptors. Installation and
/// rollback stay under the private journal; commit alone uses an atomic no-replace
/// rename to publish the exact held target. Rollback never addresses the public name.
///
/// The journal is durable evidence, not recovery authority. If a process crashes
/// and leaves it behind, a later attempt refuses rather than trusting path-based or
/// same-UID-mutable recovery metadata. Target binding itself is Linux-only. The
/// complete enforcing install is narrower still: x86_64 Linux-only, because every
/// other architecture or operating system fails capsule coverage before pip starts.
#[derive(Debug)]
pub struct InstallTargetBinding {
    target: PathBuf,
    #[cfg(target_os = "linux")]
    parent_path: PathBuf,
    #[cfg(target_os = "linux")]
    target_name: OsString,
    #[cfg(target_os = "linux")]
    parent: File,
    #[cfg(target_os = "linux")]
    parent_dev: u64,
    #[cfg(target_os = "linux")]
    parent_ino: u64,
}

impl InstallTargetBinding {
    /// Bind the canonical target parent before resolution or approval. The final
    /// target must not exist; its UTF-8 component and parent identity are later
    /// included in the plan digest.
    pub fn bind(target: &Path) -> std::io::Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = target;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "enforcing package target binding is supported only on Linux",
            ))
        }

        #[cfg(target_os = "linux")]
        {
            let absolute = std::path::absolute(target)?;
            let parent = absolute.parent().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "refusing a filesystem root as an install target",
                )
            })?;
            let target_name = absolute.file_name().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "install target must end in one ordinary directory component",
                )
            })?;
            validate_relative_component(target_name)?;
            if target_name.to_str().is_none() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "install target component must be valid UTF-8 so approval binding is injective",
                ));
            }

            let parent_path = parent.canonicalize()?;
            let target = parent_path.join(target_name);
            let path_metadata = std::fs::symlink_metadata(&parent_path)?;
            if !path_metadata.is_dir() || path_metadata.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "install target parent {} is not an ordinary directory",
                        parent_path.display()
                    ),
                ));
            }
            use std::os::unix::fs::MetadataExt as _;
            let expected = (path_metadata.dev(), path_metadata.ino());
            let parent = open_directory_nofollow(&parent_path)?;
            let opened = file_identity(&parent)?;
            if opened != expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "install target parent changed while it was being bound (path {}:{}, opened {}:{}); re-run approval",
                        expected.0, expected.1, opened.0, opened.1
                    ),
                ));
            }
            if entry_identity_at(parent.as_raw_fd(), target_name)?.is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "refusing pre-existing install target {}; enforcing installs require a new dedicated directory",
                        target.display()
                    ),
                ));
            }
            Ok(Self {
                target,
                parent_path,
                target_name: target_name.to_os_string(),
                parent,
                parent_dev: opened.0,
                parent_ino: opened.1,
            })
        }
    }

    pub fn target(&self) -> &Path {
        &self.target
    }

    pub fn target_component(&self) -> &str {
        self.target
            .file_name()
            .and_then(OsStr::to_str)
            .expect("InstallTargetBinding accepted only a UTF-8 final component")
    }

    pub fn parent_identity(&self) -> String {
        #[cfg(target_os = "linux")]
        {
            format!("linux-devino-v1:{}:{}", self.parent_dev, self.parent_ino)
        }
        #[cfg(not(target_os = "linux"))]
        {
            "unsupported".to_string()
        }
    }

    #[cfg(target_os = "linux")]
    fn verify_visible_parent(&self) -> std::io::Result<()> {
        let visible = open_directory_nofollow(&self.parent_path)?;
        let identity = file_identity(&visible)?;
        if identity != (self.parent_dev, self.parent_ino) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "install target parent changed after approval binding (approved {}:{}, visible {}:{}); reapproval is required",
                    self.parent_dev, self.parent_ino, identity.0, identity.1
                ),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct EnvironmentCheckpoint {
    #[cfg(target_os = "linux")]
    target: PathBuf,
    #[cfg(target_os = "linux")]
    parent_path: PathBuf,
    #[cfg(target_os = "linux")]
    target_name: OsString,
    #[cfg(target_os = "linux")]
    parent: File,
    #[cfg(target_os = "linux")]
    parent_dev: u64,
    #[cfg(target_os = "linux")]
    parent_ino: u64,
    #[cfg(target_os = "linux")]
    target_handle: File,
    #[cfg(target_os = "linux")]
    target_dev: u64,
    #[cfg(target_os = "linux")]
    target_ino: u64,
    #[cfg(target_os = "linux")]
    journal_name: OsString,
    #[cfg(target_os = "linux")]
    journal: File,
    #[cfg(target_os = "linux")]
    _lock: File,
    private_target: PathBuf,
    #[cfg(target_os = "linux")]
    state: CheckpointState,
}

#[cfg(target_os = "linux")]
const CHECKPOINT_PENDING_TARGET: &str = "pending-target";

/// Publication is an irreversible boundary. In particular, an error after the
/// no-replace rename must never make Drop remove bytes now reachable at the
/// approved public target.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointState {
    Private,
    PublishedUnconfirmed,
    Committed,
    RolledBack,
    Retained,
}

#[cfg(all(test, target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckpointTestPoint {
    JournalBound,
    LockAcquired,
    PreparingDurable,
    PendingBound,
    ActiveDurable,
    BeforeReturn,
    BeforePublish,
    AfterPublish,
}

/// Test-only observer invoked at each checkpoint of the install sequence.
#[cfg(all(test, target_os = "linux"))]
type CheckpointTestHook = Box<dyn FnMut(CheckpointTestPoint) -> std::io::Result<()>>;

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    static CHECKPOINT_TEST_HOOK: std::cell::RefCell<Option<CheckpointTestHook>> =
        std::cell::RefCell::new(None);
}

#[cfg(all(test, target_os = "linux"))]
fn checkpoint_test_point(point: CheckpointTestPoint) -> std::io::Result<()> {
    CHECKPOINT_TEST_HOOK.with(|hook| match hook.borrow_mut().as_mut() {
        Some(hook) => hook(point),
        None => Ok(()),
    })
}

#[cfg(target_os = "linux")]
macro_rules! checkpoint_test_point {
    ($point:ident) => {{
        #[cfg(test)]
        {
            checkpoint_test_point(CheckpointTestPoint::$point)?;
        }
        #[cfg(not(test))]
        {
            let _ = stringify!($point);
        }
    }};
}

/// Cleans partially initialized private state on every ordinary `Err`; Drop is
/// the panic/unwind fallback. Unknown or changed identities are deliberately
/// retained instead of deleting a path-selected object.
#[cfg(target_os = "linux")]
struct CheckpointInitGuard<'a> {
    parent: &'a File,
    journal_name: OsString,
    journal_identity: Option<(u64, u64)>,
    journal: Option<File>,
    pending_identity: Option<(u64, u64)>,
    pending_created: bool,
    armed: bool,
}

#[cfg(target_os = "linux")]
impl<'a> CheckpointInitGuard<'a> {
    fn new(parent: &'a File, journal_name: OsString) -> Self {
        Self {
            parent,
            journal_name,
            journal_identity: None,
            journal: None,
            pending_identity: None,
            pending_created: false,
            armed: true,
        }
    }

    fn journal(&self) -> std::io::Result<&File> {
        self.journal
            .as_ref()
            .ok_or_else(|| std::io::Error::other("checkpoint journal capability is not bound"))
    }

    fn abort(&mut self) -> std::io::Result<()> {
        if !self.armed {
            return Ok(());
        }
        self.armed = false;

        let Some(expected_journal) = self.journal_identity else {
            return Err(std::io::Error::other(
                "checkpoint journal identity was not proven; retaining initialization residue",
            ));
        };
        if entry_identity_at(self.parent.as_raw_fd(), &self.journal_name)? != Some(expected_journal)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "checkpoint journal identity changed; retaining initialization residue",
            ));
        }
        let Some(journal) = self.journal.as_ref() else {
            unlinkat_component(
                self.parent.as_raw_fd(),
                &self.journal_name,
                libc::AT_REMOVEDIR,
            )?;
            self.parent.sync_all()?;
            return Ok(());
        };

        if self.pending_created {
            let Some(expected_pending) = self.pending_identity else {
                return Err(std::io::Error::other(
                    "private target identity was not proven; retaining initialization residue",
                ));
            };
            if entry_identity_at(journal.as_raw_fd(), OsStr::new(CHECKPOINT_PENDING_TARGET))?
                != Some(expected_pending)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "private target identity changed; retaining initialization residue",
                ));
            }
            unlinkat_component(
                journal.as_raw_fd(),
                OsStr::new(CHECKPOINT_PENDING_TARGET),
                libc::AT_REMOVEDIR,
            )?;
        }
        cleanup_checkpoint_journal(self.parent, journal, &self.journal_name)
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(target_os = "linux")]
impl Drop for CheckpointInitGuard<'_> {
    fn drop(&mut self) {
        let _ = self.abort();
    }
}

impl EnvironmentCheckpoint {
    pub fn begin(binding: &InstallTargetBinding) -> std::io::Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = binding;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "enforcing package installs require Linux held-target containment; refusing without a capability-bound target backend",
            ))
        }

        #[cfg(target_os = "linux")]
        {
            binding.verify_visible_parent()?;
            let target = binding.target.clone();
            let target_name = binding.target_name.clone();
            let parent = binding.parent.try_clone()?;
            if entry_identity_at(parent.as_raw_fd(), &target_name)?.is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "refusing pre-existing install target {}; enforcing installs require a new dedicated directory",
                        target.display()
                    ),
                ));
            }

            let journal_name = checkpoint_journal_name(&target);
            let journal_component = OsStr::new(&journal_name);
            mkdirat_component(parent.as_raw_fd(), journal_component, 0o700).map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!(
                            "refusing install because durable journal {} already exists; inspect the prior interrupted operation instead of recovering from mutable path metadata",
                            binding.parent_path.join(&journal_name).display()
                        ),
                    )
                } else {
                    error
                }
            })?;
            let mut initialization = CheckpointInitGuard::new(&parent, journal_name.clone());
            let initialized = (|| {
                let journal_identity = entry_identity_at(parent.as_raw_fd(), journal_component)?
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "new checkpoint journal disappeared before capability binding",
                        )
                    })?;
                initialization.journal_identity = Some(journal_identity);
                let journal = openat_directory(parent.as_raw_fd(), journal_component)?;
                if file_identity(&journal)? != journal_identity {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "new checkpoint journal changed before capability binding",
                    ));
                }
                initialization.journal = Some(journal);
                checkpoint_test_point!(JournalBound);
                parent.sync_all()?;

                let journal_fd = initialization.journal()?.as_raw_fd();
                let lock = create_file_at(journal_fd, OsStr::new("lock"), 0o600)?;
                lock.try_lock_exclusive().map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        format!("another installer holds the target journal lock: {error}"),
                    )
                })?;
                checkpoint_test_point!(LockAcquired);
                write_checkpoint_manifest(initialization.journal()?, &target, "preparing", None)?;
                initialization.journal()?.sync_all()?;
                parent.sync_all()?;
                checkpoint_test_point!(PreparingDurable);

                // Install into a private directory first. The approved public name
                // remains absent until commit publishes this exact entry with one
                // atomic no-replace rename.
                mkdirat_component(journal_fd, OsStr::new(CHECKPOINT_PENDING_TARGET), 0o700)?;
                initialization.pending_created = true;
                let pending_identity =
                    entry_identity_at(journal_fd, OsStr::new(CHECKPOINT_PENDING_TARGET))?
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::NotFound,
                                "private install target disappeared before capability binding",
                            )
                        })?;
                initialization.pending_identity = Some(pending_identity);
                let target_handle =
                    openat_directory(journal_fd, OsStr::new(CHECKPOINT_PENDING_TARGET))?;
                if file_identity(&target_handle)? != pending_identity {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "private install target changed before capability binding",
                    ));
                }
                capsule::preflight_owned_directory_cleanup(target_handle.as_raw_fd()).map_err(
                    |error| {
                        std::io::Error::new(
                            error.kind(),
                            format!(
                                "private install target cannot be cleaned with capability confinement: {error}"
                            ),
                        )
                    },
                )?;
                checkpoint_test_point!(PendingBound);
                target_handle.sync_all()?;

                let private_target = binding
                    .parent_path
                    .join(&journal_name)
                    .join(CHECKPOINT_PENDING_TARGET);
                let canonical_private = private_target.canonicalize()?;
                if canonical_private != private_target {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "private install target path changed during initialization",
                    ));
                }
                write_checkpoint_manifest(
                    initialization.journal()?,
                    &target,
                    "active-private",
                    Some(pending_identity),
                )?;
                initialization.journal()?.sync_all()?;
                parent.sync_all()?;
                checkpoint_test_point!(ActiveDurable);
                checkpoint_test_point!(BeforeReturn);
                Ok((lock, target_handle, pending_identity, private_target))
            })();

            let (lock, target_handle, (target_dev, target_ino), private_target) = match initialized
            {
                Ok(value) => value,
                Err(error) => {
                    let cleanup = initialization.abort();
                    return Err(match cleanup {
                            Ok(()) => error,
                            Err(cleanup_error) => std::io::Error::new(
                                error.kind(),
                                format!(
                                    "{error}; checkpoint initialization cleanup was not confirmed: {cleanup_error}"
                                ),
                            ),
                    });
                }
            };
            let journal = initialization
                .journal
                .take()
                .expect("successful initialization retained the journal capability");
            initialization.disarm();
            drop(initialization);

            Ok(Self {
                target,
                parent_path: binding.parent_path.clone(),
                target_name,
                parent,
                parent_dev: binding.parent_dev,
                parent_ino: binding.parent_ino,
                target_handle,
                target_dev,
                target_ino,
                journal_name,
                journal,
                _lock: lock,
                private_target,
                state: CheckpointState::Private,
            })
        }
    }

    /// Canonical private target path used only to rebase the capsule's approved
    /// write root. The approval, receipt, and final publication identity remain
    /// [`InstallTargetBinding::target`].
    pub fn install_path(&self) -> &Path {
        &self.private_target
    }

    /// Whether the atomic publication boundary was crossed. Callers must not
    /// invoke rollback after this becomes true, even when commit later reports a
    /// durability or identity-confirmation error.
    pub fn publication_crossed(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            matches!(
                self.state,
                CheckpointState::PublishedUnconfirmed | CheckpointState::Committed
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    #[cfg(target_os = "linux")]
    pub fn state(&self) -> CheckpointState {
        self.state
    }

    /// Duplicate the exact target-directory capability for the capsule launcher.
    pub fn try_clone_target_handle(&self) -> std::io::Result<std::fs::File> {
        #[cfg(target_os = "linux")]
        {
            self.verify_private_identity()?;
            self.target_handle.try_clone()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "held install targets are not implemented on this platform",
            ))
        }
    }

    /// Atomically publish the privately verified target without claiming that the
    /// mandatory linked committed receipt has been recorded yet.
    pub fn publish_verified(&mut self) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            match self.state {
                CheckpointState::Committed => return Ok(()),
                CheckpointState::PublishedUnconfirmed
                | CheckpointState::RolledBack
                | CheckpointState::Retained => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "checkpoint publication/identity is unconfirmed; manual verification is required",
                    ));
                }
                CheckpointState::Private => {}
            }
            self.verify_private_identity()?;
            self.verify_visible_parent_identity()?;
            self.target_handle.sync_all()?;
            write_checkpoint_manifest(
                &self.journal,
                &self.target,
                "publishing",
                Some((self.target_dev, self.target_ino)),
            )?;
            self.journal.sync_all()?;
            self.parent.sync_all()?;
            checkpoint_test_point!(BeforePublish);

            renameat2_noreplace_component(
                self.journal.as_raw_fd(),
                OsStr::new(CHECKPOINT_PENDING_TARGET),
                self.parent.as_raw_fd(),
                &self.target_name,
            )?;
            // The public namespace changed. Set this state before every further
            // fallible operation so neither caller nor Drop can roll it back.
            self.state = CheckpointState::PublishedUnconfirmed;
            checkpoint_test_point!(AfterPublish);
            self.verify_published_identity()?;
            self.parent.sync_all()?;
            write_checkpoint_manifest(
                &self.journal,
                &self.target,
                "published-verified",
                Some((self.target_dev, self.target_ino)),
            )?;
            self.journal.sync_all()?;
            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "held install targets are not implemented on this platform",
        ))
    }

    /// Mark publication committed only by consuming opaque proof that the linked
    /// committed receipt was durably saved and signed after its private predecessor.
    /// On success the ordinary receipt result is returned for user-facing reporting.
    pub fn confirm_committed(
        &mut self,
        proof: RecordedCommittedReceipt,
    ) -> std::io::Result<RecordedReceipt> {
        #[cfg(target_os = "linux")]
        {
            match self.state {
                CheckpointState::Committed => return Ok(proof.into_recorded()),
                CheckpointState::PublishedUnconfirmed => {}
                CheckpointState::Private
                | CheckpointState::RolledBack
                | CheckpointState::Retained => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "checkpoint cannot be committed before verified publication and its linked receipt",
                    ));
                }
            }
            self.verify_published_identity()?;
            self.target_handle.sync_all()?;
            self.parent.sync_all()?;
            write_checkpoint_manifest(
                &self.journal,
                &self.target,
                "committed",
                Some((self.target_dev, self.target_ino)),
            )?;
            self.journal.sync_all()?;
            self.state = CheckpointState::Committed;
            // Cleanup is intentionally post-commit and best-effort. If it is
            // interrupted, the tiny committed journal remains and a later attempt
            // fails closed; no environment tree is duplicated.
            let _ = cleanup_checkpoint_journal(&self.parent, &self.journal, &self.journal_name);
            Ok(proof.into_recorded())
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = proof;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "held install targets are not implemented on this platform",
            ))
        }
    }

    /// Remove the newly-created target without ever traversing its public path.
    pub fn rollback(&mut self) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            match self.state {
                CheckpointState::Committed | CheckpointState::RolledBack => return Ok(()),
                CheckpointState::PublishedUnconfirmed | CheckpointState::Retained => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "checkpoint is not privately rollback-safe; preserving all recovery state",
                    ));
                }
                CheckpointState::Private => {}
            }
            if let Err(error) = self.verify_private_identity() {
                self.state = CheckpointState::Retained;
                return Err(error);
            }
            write_checkpoint_manifest(
                &self.journal,
                &self.target,
                "rolling-back",
                Some((self.target_dev, self.target_ino)),
            )?;
            // Recursive cleanup walks only directories opened relative to the
            // retained target capability and never follows a path/symlink. Mark
            // Retained first so any failure preserves the remaining private tree.
            self.state = CheckpointState::Retained;
            capsule::remove_owned_directory_contents(self.target_handle.as_raw_fd())?;
            self.verify_private_identity()?;
            unlinkat_component(
                self.journal.as_raw_fd(),
                OsStr::new(CHECKPOINT_PENDING_TARGET),
                libc::AT_REMOVEDIR,
            )?;
            self.journal.sync_all()?;
            write_checkpoint_manifest(
                &self.journal,
                &self.target,
                "rolled-back",
                Some((self.target_dev, self.target_ino)),
            )?;
            self.journal.sync_all()?;
            cleanup_checkpoint_journal(&self.parent, &self.journal, &self.journal_name)?;
            self.state = CheckpointState::RolledBack;
            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "held install targets are not implemented on this platform",
        ))
    }

    #[cfg(target_os = "linux")]
    fn verify_private_identity(&self) -> std::io::Result<()> {
        let visible = entry_identity_at(
            self.journal.as_raw_fd(),
            OsStr::new(CHECKPOINT_PENDING_TARGET),
        )?;
        match visible {
            Some((dev, ino)) if dev == self.target_dev && ino == self.target_ino => Ok(()),
            Some((dev, ino)) => Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "private install target identity changed before commit/rollback (held {}:{}, visible {dev}:{ino}); preserving recovery state",
                    self.target_dev, self.target_ino
                ),
            )),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "private install target disappeared before commit/rollback; preserving recovery state",
            )),
        }
    }

    #[cfg(target_os = "linux")]
    fn verify_published_identity(&self) -> std::io::Result<()> {
        match entry_identity_at(self.parent.as_raw_fd(), &self.target_name)? {
            Some((dev, ino)) if dev == self.target_dev && ino == self.target_ino => Ok(()),
            Some((dev, ino)) => Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "published install target identity is unconfirmed (held {}:{}, visible {dev}:{ino}); manual verification is required",
                    self.target_dev, self.target_ino
                ),
            )),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "published install target disappeared before identity confirmation; manual verification is required",
            )),
        }?;
        self.verify_visible_parent_identity()?;
        let visible_target = open_directory_nofollow(&self.target).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!(
                    "approved public target {} cannot be opened without following links: {error}",
                    self.target.display()
                ),
            )
        })?;
        let visible_identity = file_identity(&visible_target)?;
        if visible_identity != (self.target_dev, self.target_ino) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "approved public target identity is unconfirmed (held {}:{}, visible {}:{}); manual verification is required",
                    self.target_dev, self.target_ino, visible_identity.0, visible_identity.1
                ),
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn verify_visible_parent_identity(&self) -> std::io::Result<()> {
        let visible = open_directory_nofollow(&self.parent_path).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!(
                    "approved target parent {} is no longer an ordinary visible directory: {error}",
                    self.parent_path.display()
                ),
            )
        })?;
        let identity = file_identity(&visible)?;
        if identity != (self.parent_dev, self.parent_ino) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "approved target parent identity changed (held {}:{}, visible {}:{}); refusing publication/confirmation",
                    self.parent_dev, self.parent_ino, identity.0, identity.1
                ),
            ));
        }
        Ok(())
    }
}

impl Drop for EnvironmentCheckpoint {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if self.state == CheckpointState::Private {
            let _ = self.rollback();
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
struct CheckpointManifest<'a> {
    version: u8,
    state: &'a str,
    target: String,
    target_dev: Option<u64>,
    target_ino: Option<u64>,
}

#[cfg(target_os = "linux")]
fn validate_relative_component(component: &OsStr) -> std::io::Result<()> {
    let bytes = component.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "install target must end in one ordinary directory component",
        ));
    }
    CString::new(bytes).map(|_| ()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "install target component contains NUL",
        )
    })
}

#[cfg(target_os = "linux")]
fn c_component(component: &OsStr) -> std::io::Result<CString> {
    validate_relative_component(component)?;
    CString::new(component.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "filesystem component contains NUL",
        )
    })
}

#[cfg(target_os = "linux")]
fn open_directory_nofollow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(target_os = "linux")]
fn openat_directory(dir_fd: i32, component: &OsStr) -> std::io::Result<File> {
    let component = c_component(component)?;
    // SAFETY: `dir_fd` is a live directory descriptor and `component` is a
    // NUL-terminated single component. The returned descriptor is uniquely owned.
    let fd = unsafe {
        libc::openat(
            dir_fd,
            component.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: `openat` returned a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(target_os = "linux")]
fn create_file_at(dir_fd: i32, component: &OsStr, mode: libc::mode_t) -> std::io::Result<File> {
    let component = c_component(component)?;
    // SAFETY: arguments are valid and the new descriptor is uniquely owned.
    let fd = unsafe {
        libc::openat(
            dir_fd,
            component.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: `openat` returned a new owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(target_os = "linux")]
fn mkdirat_component(dir_fd: i32, component: &OsStr, mode: libc::mode_t) -> std::io::Result<()> {
    let component = c_component(component)?;
    // SAFETY: `dir_fd` is a live directory and `component` is a safe C string.
    if unsafe { libc::mkdirat(dir_fd, component.as_ptr(), mode) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn renameat_component(
    old_dir_fd: i32,
    old_component: &OsStr,
    new_dir_fd: i32,
    new_component: &OsStr,
) -> std::io::Result<()> {
    let old_component = c_component(old_component)?;
    let new_component = c_component(new_component)?;
    // SAFETY: both directory descriptors are live and both names are single,
    // NUL-terminated components.
    if unsafe {
        libc::renameat(
            old_dir_fd,
            old_component.as_ptr(),
            new_dir_fd,
            new_component.as_ptr(),
        )
    } == 0
    {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn renameat2_noreplace_component(
    old_dir_fd: i32,
    old_component: &OsStr,
    new_dir_fd: i32,
    new_component: &OsStr,
) -> std::io::Result<()> {
    let old_component = c_component(old_component)?;
    let new_component = c_component(new_component)?;
    // SAFETY: both descriptors are retained directories and both names are
    // validated single components. RENAME_NOREPLACE atomically refuses a peer's
    // public entry instead of overwriting it.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            old_dir_fd,
            old_component.as_ptr(),
            new_dir_fd,
            new_component.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn unlinkat_component(dir_fd: i32, component: &OsStr, flags: i32) -> std::io::Result<()> {
    let component = c_component(component)?;
    // SAFETY: `dir_fd` is live and `component` is a single NUL-terminated name.
    if unsafe { libc::unlinkat(dir_fd, component.as_ptr(), flags) } == 0 {
        Ok(())
    } else {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(error)
        }
    }
}

#[cfg(target_os = "linux")]
fn entry_identity_at(dir_fd: i32, component: &OsStr) -> std::io::Result<Option<(u64, u64)>> {
    let component = c_component(component)?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat` points to valid writable storage and the other arguments are
    // valid. `AT_SYMLINK_NOFOLLOW` makes the observed final component authoritative.
    let rc = unsafe {
        libc::fstatat(
            dir_fd,
            component.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error);
    }
    // SAFETY: `fstatat` returned success and initialized `stat`.
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "install target exists but is not an ordinary directory",
        ));
    }
    Ok(Some((stat.st_dev, stat.st_ino)))
}

#[cfg(target_os = "linux")]
fn file_identity(file: &File) -> std::io::Result<(u64, u64)> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `file` owns a live descriptor and `stat` is writable storage.
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fstat` returned success and initialized `stat`.
    let stat = unsafe { stat.assume_init() };
    Ok((stat.st_dev, stat.st_ino))
}

#[cfg(target_os = "linux")]
fn checkpoint_journal_name(target: &Path) -> OsString {
    let digest = Sha256::digest(target.as_os_str().as_bytes());
    OsString::from(format!(".tirith-install-journal-{digest:x}"))
}

#[cfg(target_os = "linux")]
fn write_checkpoint_manifest(
    journal: &File,
    target: &Path,
    state: &str,
    identity: Option<(u64, u64)>,
) -> std::io::Result<()> {
    let manifest = CheckpointManifest {
        version: 1,
        state,
        target: target.to_string_lossy().into_owned(),
        target_dev: identity.map(|value| value.0),
        target_ino: identity.map(|value| value.1),
    };
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(std::io::Error::other)?;
    unlinkat_component(journal.as_raw_fd(), OsStr::new("manifest.tmp"), 0)?;
    let mut temporary = create_file_at(journal.as_raw_fd(), OsStr::new("manifest.tmp"), 0o600)?;
    temporary.write_all(&bytes)?;
    temporary.write_all(b"\n")?;
    temporary.sync_all()?;
    renameat_component(
        journal.as_raw_fd(),
        OsStr::new("manifest.tmp"),
        journal.as_raw_fd(),
        OsStr::new("manifest.json"),
    )?;
    journal.sync_all()
}

#[cfg(target_os = "linux")]
fn cleanup_checkpoint_journal(
    parent: &File,
    journal: &File,
    journal_name: &OsStr,
) -> std::io::Result<()> {
    let held_identity = file_identity(journal)?;
    if entry_identity_at(parent.as_raw_fd(), journal_name)? != Some(held_identity) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "visible checkpoint journal no longer identifies the retained journal; preserving recovery state",
        ));
    }
    unlinkat_component(journal.as_raw_fd(), OsStr::new("manifest.tmp"), 0)?;
    unlinkat_component(journal.as_raw_fd(), OsStr::new("manifest.json"), 0)?;
    unlinkat_component(journal.as_raw_fd(), OsStr::new("lock"), 0)?;
    journal.sync_all()?;
    if entry_identity_at(parent.as_raw_fd(), journal_name)? != Some(held_identity) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "checkpoint journal changed during cleanup; preserving the visible replacement",
        ));
    }
    unlinkat_component(parent.as_raw_fd(), journal_name, libc::AT_REMOVEDIR)?;
    parent.sync_all()
}

/// The outcome of a contained install-from-digest: the child's exit code plus the
/// honest capsule backend / coverage record, so the D6 receipt (and an audit line)
/// can state exactly what containment the install ran under.
#[derive(Debug, Clone)]
pub struct ContainedInstallOutcome {
    /// pip's exit code (0 on success).
    pub exit_code: i32,
    /// The capsule backend that contained the install (`"landlock-seccomp"`,
    /// `"seatbelt"`, `"appcontainer"`, or `"noop"`).
    pub backend_id: &'static str,
    /// A compact, secret-free description of the coverage actually enforced.
    pub coverage_summary: String,
    /// The honest per-capability coverage ledger the backend reported, carried
    /// structured (not just summarised) so the D6 receipt records the real flags.
    pub coverage: tirith_core::capsule::CapsuleCoverage,
    /// Present when the authenticated pip target ran but capsule supervision
    /// terminated it (for example on wall/output limits). Cleanup-confirmed
    /// termination is an outcome; unconfirmed cleanup is returned as the typed
    /// [`ContainedInstallError::CapsuleExecutedTerminated`] error instead.
    pub termination: Option<crate::cli::capsule::CapsuleTermination>,
    /// The threat-DB sequence the (re-validated) plan was bound to, carried through
    /// for the receipt.
    pub bound_db_sequence: u64,
    /// The absolute path of the `approved.txt` the install read (inside the
    /// transaction directory).
    pub approved_requirements_path: PathBuf,
    /// D5: the post-install RECORD verification over the just-installed
    /// distributions, run ONLY when the contained install exited cleanly
    /// (`exit_code == 0`). `None` when the install failed, since there is nothing
    /// trustworthy to verify. Its [`PostInstallIntegrity::verdict`] is folded into
    /// the install's overall result and recorded (with its coverage counters) in the
    /// D6 receipt; a strict integrity policy can make that verdict block.
    pub post_install: Option<PostInstallIntegrity>,
}

/// Why a contained install-from-digest could not run. Distinct from
/// [`tirith_core::artifact::install::InstallError`] (which is the planning/re-bind
/// failure surfaced before this module runs): this is a failure of the side-effect
/// half, writing `approved.txt` or the fail-closed capsule refusal.
#[derive(Debug)]
pub enum ContainedInstallError {
    /// The retained quarantine transaction could not publish `approved.txt`,
    /// duplicate its directory capability, or prove that its visible path still
    /// names the held directory identity. The install refuses before spawning.
    Quarantine(QuarantineError),
    /// The capsule refused before executing the install because the host backend
    /// could not deliver the required containment. The carried fields name the
    /// backend and its secret-free shortfall.
    CapsuleRefused {
        backend_id: &'static str,
        reason: String,
    },
    /// The authenticated pip target started, but capsule supervision had to
    /// terminate it and could not prove complete tree cleanup. This must never be
    /// reported as a pre-exec refusal because attacker-controlled code did run.
    CapsuleExecutedTerminated {
        backend_id: &'static str,
        termination: crate::cli::capsule::CapsuleTermination,
    },
    /// Retained resolver/interpreter/pip authority changed or could not be carried
    /// into the capsule launch.
    ToolBinding(String),
}

impl std::fmt::Display for ContainedInstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainedInstallError::Quarantine(e) => {
                write!(
                    f,
                    "refusing to install: the quarantine transaction is no longer trustworthy ({e})"
                )
            }
            ContainedInstallError::CapsuleRefused { reason, .. } => {
                write!(
                    f,
                    "refusing to install: the containment capsule is unavailable or degraded \
                     on this host ({reason})"
                )
            }
            ContainedInstallError::CapsuleExecutedTerminated {
                backend_id,
                termination,
            } => write!(
                f,
                "install target executed under {backend_id}, then capsule supervision terminated it: {} (cleanup confirmed={})",
                termination.reason, termination.cleanup_confirmed
            ),
            ContainedInstallError::ToolBinding(reason) => {
                write!(
                    f,
                    "refusing to install: retained tool/input binding failed ({reason})"
                )
            }
        }
    }
}

impl std::error::Error for ContainedInstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ContainedInstallError::Quarantine(error) => Some(error),
            ContainedInstallError::CapsuleRefused { .. }
            | ContainedInstallError::CapsuleExecutedTerminated { .. }
            | ContainedInstallError::ToolBinding(_) => None,
        }
    }
}

impl From<QuarantineError> for ContainedInstallError {
    fn from(error: QuarantineError) -> Self {
        ContainedInstallError::Quarantine(error)
    }
}

impl From<capsule::CapsuleExecutionError> for ContainedInstallError {
    fn from(error: capsule::CapsuleExecutionError) -> Self {
        match error {
            capsule::CapsuleExecutionError::RefusedBeforeExec(refused) => Self::CapsuleRefused {
                backend_id: refused.backend_id,
                reason: refused.reason,
            },
            capsule::CapsuleExecutionError::ExecutedTerminated {
                backend_id,
                termination,
            } => Self::CapsuleExecutedTerminated {
                backend_id,
                termination,
            },
        }
    }
}

/// Run a re-bound [`DigestInstallPlan`] as a contained `pip install`, then (on
/// success) verify the installed RECORD of the just-installed distributions.
///
/// `plan` is the verified plan from
/// [`tirith_core::artifact::install::rebind_for_install`] (the re-bind already
/// passed; the bytes are the approved bytes). `transaction` is the still-leased
/// quarantine transaction whose retained directory capability contains the plan's
/// wheels and receives `approved.txt` (the plan's spec already grants it read).
/// `tools` retains the exact sealed Python executable plus the attested pip tree;
/// the installer never resolves a bare `pip` on `PATH`. `target_environment` is the
/// approved final policy/publication path, while `target_install_path` and
/// `target_handle` identify the private checkpoint directory that receives bytes
/// before atomic publication. `installed_distributions` are the exact normalized
/// name and version identities expected from the locked wheels. Together they scope
/// D5 post-install verification. `policy` finalises that verdict, so strict
/// integrity policy can make a coverage gap or mismatch block.
///
/// This:
/// 1. Writes `plan.approved_requirements` to the held transaction capability as
///    `approved.txt` (atomic, `0o600`).
/// 2. Builds the pinned pip argv ([`InstallCommand::pip_install_args`]).
/// 3. Runs the sealed interpreter and sealed inputs through the capability-bound
///    capsule: insufficient coverage refuses BEFORE spawning, so the install never
///    runs uncontained.
/// 4. **D5:** if pip exited cleanly (`exit_code == 0`), runs
///    [`verify_post_install_record_exact`] over `installed_distributions` through
///    the retained target handle and carries the resulting [`PostInstallIntegrity`]
///    in the outcome. On a non-zero exit there is nothing trustworthy to verify, so
///    the post-install field stays `None`.
///
/// It NEVER calls [`crate::cli::install::ProcessInstallRunner`]; the only spawn is
/// [`capsule::run_to_completion_bound_inputs`]. That enforcing seam is x86_64
/// Linux-only and refuses every other platform or architecture before pip starts.
// Keep these capability and policy inputs explicit at this security boundary.
#[allow(clippy::too_many_arguments)]
pub fn run_contained_install(
    plan: &DigestInstallPlan,
    transaction: &QuarantineTransaction,
    tools: &BoundResolverTools,
    target_environment: &Path,
    target_install_path: &Path,
    target_handle: std::fs::File,
    installed_distributions: &[ExpectedInstalledDistribution],
    policy: &Policy,
    suppress_child_output: bool,
    task_denied_effects: &std::collections::BTreeSet<tirith_core::effects::CommandEffectKind>,
) -> Result<ContainedInstallOutcome, ContainedInstallError> {
    // C12: the last hop before the capsule launch re-asserts the decision the
    // caller already made, rather than re-deriving one. Re-deriving here would
    // let this site and `pkg.rs` disagree about the same install; asserting
    // catches a future caller that forgets the gate entirely. Under any mode
    // that is not enforcing, `denied_effects` is reported but never handed down
    // as a refusal, so this can only trip on a real enforcing denial that leaked
    // past the gate.
    if task_denied_effects.contains(&tirith_core::effects::CommandEffectKind::PackageInstall) {
        return Err(ContainedInstallError::ToolBinding(
            "task gate denied the package-install effect; refusing before the contained launch"
                .to_string(),
        ));
    }

    // 0. Revalidate the exact sealed uv/Python identities and bounded root-managed
    // pip tree before any launch preparation. A path-only interpreter check would
    // reopen the verify-to-exec race this enforcing surface exists to close.
    tools
        .revalidate_install_authority()
        .map_err(|error| ContainedInstallError::ToolBinding(error.to_string()))?;

    // 1. Publish approved.txt relative to the retained transaction capability. A
    //    lexical path check is not authority: an ancestor could be renamed after a
    //    check. The transaction helper writes + renames relative to the held
    //    directory and returns the public absolute path only for reporting.
    let approved_path = transaction.write_control_file_atomic_0600(
        APPROVED_REQUIREMENTS_FILE,
        plan.approved_requirements.as_bytes(),
    )?;

    // 2. The pinned pip argv reading that approved.txt. Unix resolves this relative
    //    name only after the trusted launcher has fchdir'd to the held directory;
    //    Windows keeps the transaction directory pinned against replacement for the
    //    absolute-path CreateProcess launch.
    #[cfg(unix)]
    let approved_argument = PathBuf::from(APPROVED_REQUIREMENTS_FILE);
    #[cfg(not(unix))]
    let approved_argument = approved_path.clone();
    let cmd = InstallCommand {
        approved_requirements_path: approved_argument,
        target_environment: target_environment.to_path_buf(),
    };
    let raw_args = cmd.pip_install_args();
    let mut args = Vec::with_capacity(raw_args.len());
    let mut target_values = 0usize;
    let mut approved_values = 0usize;
    for (index, arg) in raw_args.iter().enumerate() {
        if index > 0 && raw_args[index - 1] == "--target" {
            target_values += 1;
            args.push(BoundLaunchArg::TargetDirectory);
        } else if index > 0 && raw_args[index - 1] == "-r" {
            approved_values += 1;
            args.push(BoundLaunchArg::InputName(
                APPROVED_REQUIREMENTS_FILE.to_string(),
            ));
        } else {
            args.push(BoundLaunchArg::Literal(OsString::from(arg)));
        }
    }
    if target_values != 1 || approved_values != 1 {
        return Err(ContainedInstallError::ToolBinding(
            "pinned pip argv did not contain exactly one target and approved-input placeholder"
                .to_string(),
        ));
    }

    if plan.materialized.len() != plan.materialized_sha256.len() {
        return Err(QuarantineError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "install plan has no one-to-one materialized wheel digest binding",
        ))
        .into());
    }
    let mut launch_filenames = Vec::with_capacity(plan.materialized.len() + 1);
    launch_filenames.push(APPROVED_REQUIREMENTS_FILE.to_string());
    let mut unique_filenames = std::collections::BTreeSet::new();
    unique_filenames.insert(APPROVED_REQUIREMENTS_FILE.to_string());
    for path in &plan.materialized {
        let filename = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| {
                QuarantineError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "materialized wheel has no UTF-8 quarantine filename",
                ))
            })?;
        if !unique_filenames.insert(filename.to_string()) {
            return Err(ContainedInstallError::ToolBinding(format!(
                "duplicate sealed launch input name {filename:?}"
            )));
        }
        launch_filenames.push(filename.to_string());
    }

    // 3. Clone the exact directory capability, then perform one final public-path
    //    identity check immediately before launch. The capsule launcher receives
    //    both: on Unix it fchdir's through the fd and rebases the read grant to that
    //    identity; on Windows the no-delete-sharing handle remains live through the
    //    child. There is no path-only or degraded fallback.
    let launch_file_pins =
        transaction.pin_files_for_launch(launch_filenames.iter().map(String::as_str))?;
    if launch_file_pins.len() != launch_filenames.len() {
        return Err(ContainedInstallError::ToolBinding(
            "quarantine did not pin every sealed launch input".to_string(),
        ));
    }
    use sha2::Digest as _;
    let approved_sha256 = sha2::Sha256::digest(plan.approved_requirements.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut expected_hashes = Vec::with_capacity(plan.materialized_sha256.len() + 1);
    expected_hashes.push(approved_sha256);
    expected_hashes.extend(plan.materialized_sha256.iter().cloned());
    let inputs = launch_filenames
        .into_iter()
        .zip(launch_file_pins)
        .zip(expected_hashes)
        .map(|((name, source), expected_sha256)| BoundLaunchInput {
            name,
            source,
            expected_sha256,
        })
        .collect();
    #[cfg(target_os = "linux")]
    let verification_handle = target_handle
        .try_clone()
        .map_err(|error| ContainedInstallError::ToolBinding(error.to_string()))?;
    #[cfg(test)]
    invoke_pre_bound_launch_test_hook();
    let outcome = capsule::run_to_completion_bound_inputs(
        &plan.spec,
        tools.python(),
        &args,
        inputs,
        BoundLaunchDirectory {
            policy_root: target_environment.to_path_buf(),
            visible_path: target_install_path.to_path_buf(),
            handle: target_handle,
        },
        &[],
        if suppress_child_output {
            capsule::BoundOutputPresentation::Suppress
        } else {
            capsule::BoundOutputPresentation::ForwardSanitized
        },
    )
    .map_err(ContainedInstallError::from)?;

    // 4. D5 post-install RECORD verification, ONLY on a clean install. A failed pip
    //    run may have extracted nothing (or a partial tree), so there is nothing
    //    trustworthy to verify; the post-install field stays `None` and the caller
    //    reports the install failure on its own.
    let post_install = if outcome.exit_code == 0 {
        #[cfg(target_os = "linux")]
        let verification_root =
            PathBuf::from(format!("/proc/self/fd/{}", verification_handle.as_raw_fd()));
        #[cfg(not(target_os = "linux"))]
        let verification_root = target_install_path.to_path_buf();
        Some(verify_post_install_record_exact(
            &verification_root,
            installed_distributions,
            policy,
        ))
    } else {
        None
    };

    Ok(ContainedInstallOutcome {
        exit_code: outcome.exit_code,
        backend_id: outcome.backend_id,
        coverage_summary: outcome.coverage_summary(),
        coverage: outcome.coverage,
        termination: outcome.termination,
        bound_db_sequence: plan.bound_db_sequence,
        approved_requirements_path: approved_path,
        post_install,
    })
}

#[cfg(windows)]
fn verify_windows_launch_file_pins(
    plan: &DigestInstallPlan,
    handles: &[std::fs::File],
) -> Result<(), QuarantineError> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    use tirith_core::util::HashOutcome;

    if handles.len() != plan.materialized.len() + 1 {
        return Err(QuarantineError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows quarantine launch did not pin every approved input",
        )));
    }

    let mut approved = handles[0].try_clone()?;
    approved.seek(SeekFrom::Start(0))?;
    let mut approved_bytes = Vec::with_capacity(plan.approved_requirements.len());
    (&mut approved)
        .take(plan.approved_requirements.len().saturating_add(1) as u64)
        .read_to_end(&mut approved_bytes)?;
    if approved_bytes != plan.approved_requirements.as_bytes() {
        return Err(QuarantineError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "approved requirements changed before the Windows launch pin was acquired",
        )));
    }

    for (handle, expected) in handles[1..].iter().zip(&plan.materialized_sha256) {
        let mut reader = handle.try_clone()?;
        reader.seek(SeekFrom::Start(0))?;
        let actual = match tirith_core::util::sha256_from_handle(
            reader,
            tirith_core::artifact::inspect::ARTIFACT_MAX_FILE_SIZE,
        )? {
            HashOutcome::Digest(digest) => digest,
            HashOutcome::BudgetExceeded => return Err(QuarantineError::TooLarge),
        };
        if &actual != expected {
            return Err(QuarantineError::DigestMismatch {
                expected: expected.clone(),
                actual,
            });
        }
    }
    Ok(())
}

/// The already-redacted resolver / package-manager provenance the D6 receipt
/// records. The caller (D7's `tirith pkg install`) fills these from the D2 resolver
/// run, having stripped any index credential from the command strings; the receipt
/// stores them verbatim and NEVER re-derives them from the environment, so a
/// credential can never leak in through this seam.
#[derive(Debug, Clone, Default)]
pub struct ResolverProvenance {
    /// The resolver command line, redacted (e.g. `"uv pip compile --generate-hashes
    /// --no-build"`). No index URL with embedded credentials.
    pub resolver_command: String,
    /// The resolver tool version (e.g. `uv`'s `--version` output), redacted.
    pub resolver_version: String,
    /// The package-manager (pip) version, redacted.
    pub package_manager_version: String,
}

/// Build the private-verification D6 [`ArtifactScanReceipt`] for a completed
/// contained install. The caller records this while the checkpoint is still
/// private, publishes the exact target, then consumes the opaque signed-private
/// capability to derive and record the committed phase before confirming the
/// checkpoint.
///
/// This is the D6 seam D7 calls after [`run_contained_install`]: it composes the
/// receipt from
///
/// * the redacted policy posture hash ([`Policy::security_projection_hash`]),
/// * the threat-DB sequence the install bound to (`outcome.bound_db_sequence`),
/// * the redacted resolver / package-manager provenance (`provenance`),
/// * the capsule backend + honest coverage (`outcome.backend_id` /
///   `outcome.coverage`),
/// * every installed artifact sha256 (`artifact_sha256`),
/// * the post-install RECORD summary (`outcome.post_install`), and
/// * the finalised install `verdict` summary,
///
/// No secret or machine path is recorded: the artifacts are hashes only, the policy
/// is a redacted hash, the provenance strings are pre-redacted by the caller, and
/// the verdict is summarised without evidence text.
pub fn build_install_receipt(
    outcome: &ContainedInstallOutcome,
    policy: &Policy,
    provenance: &ResolverProvenance,
    artifact_sha256: Vec<String>,
    verdict: &tirith_core::verdict::Verdict,
) -> ArtifactScanReceipt {
    let post_install_record = outcome
        .post_install
        .as_ref()
        .map(|p| PostInstallRecordSummary {
            blocked: p.is_block(),
            distributions_verified: p.distributions_verified,
            distributions_not_found: p.distributions_not_found,
            records_missing: p.records_missing,
            hash_mismatches: p.hash_mismatches,
        });

    ArtifactScanReceipt::new(
        env!("CARGO_PKG_VERSION").to_string(),
        policy.security_projection_hash(),
        outcome.bound_db_sequence,
        provenance.resolver_command.clone(),
        provenance.resolver_version.clone(),
        provenance.package_manager_version.clone(),
        CapsuleReceipt {
            backend_id: outcome.backend_id.to_string(),
            coverage: outcome.coverage,
        },
        artifact_sha256,
        post_install_record,
        VerdictSummary::from_verdict(verdict),
    )
}

/// Compatibility helper for non-transactional tests and callers that only need
/// to record the private-verification phase. Enforcing `pkg install` uses
/// [`build_install_receipt`] directly so it can link a second committed receipt.
pub fn record_install_receipt(
    outcome: &ContainedInstallOutcome,
    policy: &Policy,
    provenance: &ResolverProvenance,
    artifact_sha256: Vec<String>,
    verdict: &tirith_core::verdict::Verdict,
    require_signature: bool,
) -> Result<RecordedReceipt, ReceiptError> {
    build_install_receipt(outcome, policy, provenance, artifact_sha256, verdict)
        .record(require_signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_core::artifact::quarantine::QuarantineStore;
    use tirith_core::capsule::CapsuleSpec;

    /// A directly-constructed [`DigestInstallPlan`] over one synthetic wheel in a
    /// real leased quarantine transaction. The core crate's own tests cover the
    /// re-bind that PRODUCES a plan from quarantined bytes; this CLI half needs the
    /// real transaction capability to exercise the atomic control-file write and
    /// capability-bound fail-closed launch.
    fn planned() -> (tempfile::TempDir, QuarantineTransaction, DigestInstallPlan) {
        let dir = tempfile::tempdir().unwrap();
        // macOS exposes /var through the root-owned /private/var alias. Feed the
        // canonical temp path to the descriptor-relative store so this test does
        // not depend on that platform alias.
        let root = dir.path().canonicalize().unwrap().join("quarantine");
        let store = QuarantineStore::with_root(root).unwrap();
        let transaction = store.begin_transaction("pkg-install-test").unwrap();
        let wheel_name = "demo-1.0-py3-none-any.whl";
        let wheel = transaction.dir().join(wheel_name);
        // A placeholder wheel file so the materialised path exists on disk.
        transaction
            .write_control_file_atomic_0600(wheel_name, b"PK\x03\x04 placeholder wheel bytes")
            .unwrap();
        #[cfg(unix)]
        let approved = format!("./{wheel_name} --hash=sha256:{}\n", "a".repeat(64));
        #[cfg(not(unix))]
        let approved = format!(
            "demo @ file://{} --hash=sha256:{}\n",
            wheel.display(),
            "a".repeat(64)
        );
        let mut spec = CapsuleSpec::locked_down();
        spec.network = tirith_core::capsule::NetworkPolicy::DenyAll;
        spec.filesystem
            .read_roots
            .push(transaction.dir().to_path_buf());
        let plan = DigestInstallPlan {
            approved_requirements: approved,
            materialized: vec![wheel],
            materialized_sha256: vec!["a".repeat(64)],
            spec,
            bound_db_sequence: 0,
        };
        (dir, transaction, plan)
    }

    #[test]
    fn writing_approved_txt_lands_the_requirements_in_the_txn_dir() {
        // We exercise the write half WITHOUT spawning: write approved.txt and check
        // it landed with the wheel reference + hash line. (The capsule spawn is
        // covered by the fail-closed test below, which needs no real interpreter.)
        let (_dir, transaction, plan) = planned();
        let approved_path = transaction
            .write_control_file_atomic_0600(
                APPROVED_REQUIREMENTS_FILE,
                plan.approved_requirements.as_bytes(),
            )
            .unwrap();
        let written = std::fs::read_to_string(&approved_path).unwrap();
        assert!(written.contains("demo-1.0-py3-none-any.whl"));
        assert!(written.contains("--hash=sha256:"));
        // The approved.txt is inside the transaction directory pip is granted to read.
        assert!(approved_path.starts_with(transaction.dir()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&approved_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "approved.txt must be 0600");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn install_target_binding_rejects_preexisting_entries_without_copying_or_mutation() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("venv");
        std::fs::create_dir_all(target.join("lib/python3.13/site-packages/demo")).unwrap();
        let original = target.join("lib/python3.13/site-packages/demo/__init__.py");
        std::fs::write(&original, b"safe = True\n").unwrap();

        let error = InstallTargetBinding::bind(&target)
            .expect_err("preexisting targets must fail closed before journaling");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&original).unwrap(), b"safe = True\n");
    }

    #[cfg(target_os = "linux")]
    fn with_checkpoint_hook<R>(
        hook: impl FnMut(CheckpointTestPoint) -> std::io::Result<()> + 'static,
        body: impl FnOnce() -> R,
    ) -> R {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                CHECKPOINT_TEST_HOOK.with(|slot| {
                    slot.borrow_mut().take();
                });
            }
        }
        CHECKPOINT_TEST_HOOK.with(|slot| {
            assert!(slot.borrow_mut().replace(Box::new(hook)).is_none());
        });
        let _reset = Reset;
        body()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn checkpoint_initialization_failures_clean_bound_private_state() {
        for failure_point in [
            CheckpointTestPoint::JournalBound,
            CheckpointTestPoint::LockAcquired,
            CheckpointTestPoint::PreparingDurable,
            CheckpointTestPoint::PendingBound,
            CheckpointTestPoint::ActiveDurable,
            CheckpointTestPoint::BeforeReturn,
        ] {
            let root = tempfile::tempdir().unwrap();
            let target = root.path().join("target");
            let journal = root.path().join(checkpoint_journal_name(&target));
            let binding = InstallTargetBinding::bind(&target).unwrap();
            let error = with_checkpoint_hook(
                move |point| {
                    if point == failure_point {
                        Err(std::io::Error::other(format!(
                            "injected checkpoint failure at {point:?}"
                        )))
                    } else {
                        Ok(())
                    }
                },
                || EnvironmentCheckpoint::begin(&binding).unwrap_err(),
            );
            assert!(error.to_string().contains("injected checkpoint failure"));
            assert!(!target.exists(), "public target must remain absent");
            assert!(
                !journal.exists(),
                "bound private residue must be removed after {failure_point:?}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_install_checkpoint_removes_only_its_new_held_target() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("new-target");
        let outside = root.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"keep").unwrap();
        let binding = InstallTargetBinding::bind(&target).unwrap();
        let mut checkpoint = EnvironmentCheckpoint::begin(&binding).unwrap();
        assert!(!target.exists(), "begin must not publish the final target");
        std::fs::write(
            checkpoint.install_path().join("evil.pth"),
            b"import payload\n",
        )
        .unwrap();
        std::fs::create_dir(checkpoint.install_path().join("nested")).unwrap();
        std::fs::write(checkpoint.install_path().join("nested/file"), b"partial").unwrap();
        std::os::unix::fs::symlink(&outside, checkpoint.install_path().join("outside-link"))
            .unwrap();

        checkpoint.rollback().unwrap();
        assert!(
            !target.exists(),
            "a partial newly-created target must be removed"
        );
        assert_eq!(std::fs::read(outside.join("sentinel")).unwrap(), b"keep");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_install_checkpoint_removes_mode_zero_tree_without_following_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("new-target");
        let journal = root.path().join(checkpoint_journal_name(&target));
        let outside = root.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"keep").unwrap();

        let binding = InstallTargetBinding::bind(&target).unwrap();
        let mut checkpoint = EnvironmentCheckpoint::begin(&binding).unwrap();
        let private = checkpoint.install_path().to_path_buf();
        let nested = private.join("cache/deep");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("large-payload"), b"partial package cache").unwrap();
        symlink(&outside, private.join("outside-link")).unwrap();

        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::set_permissions(
            nested.parent().unwrap(),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o000)).unwrap();

        checkpoint
            .rollback()
            .expect("held cleanup must normalize exact mode-zero directories");

        assert_eq!(checkpoint.state(), CheckpointState::RolledBack);
        assert!(
            !target.exists(),
            "rollback must never publish the final target"
        );
        assert!(
            !private.exists(),
            "the exact private target must be removed"
        );
        assert!(
            !journal.exists(),
            "completed rollback removes its small journal"
        );
        assert_eq!(
            std::fs::read(outside.join("sentinel")).unwrap(),
            b"keep",
            "descriptor cleanup must unlink, not follow, package-created symlinks"
        );
    }

    #[cfg(target_os = "linux")]
    fn signed_committed_receipt_proof(root: &Path) -> RecordedCommittedReceipt {
        use std::os::unix::fs::PermissionsExt as _;

        let config_dir = root.join("tirith");
        std::fs::create_dir_all(&config_dir).unwrap();
        let signing_key = config_dir.join("audit-signing.key");
        std::fs::write(&signing_key, [7u8; 32]).unwrap();
        std::fs::set_permissions(&signing_key, std::fs::Permissions::from_mode(0o600)).unwrap();

        build_install_receipt(
            &ok_outcome(),
            &Policy::default(),
            &ResolverProvenance::default(),
            vec!["a".repeat(64)],
            &allow_verdict(),
        )
        .record_private_signed()
        .expect("record signed private receipt")
        .prepare_committed()
        .expect("derive committed receipt from signed private proof")
        .record_signed()
        .expect("record signed committed receipt")
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn successful_install_checkpoint_keeps_the_new_environment() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _guards = [
            EnvGuard::set("XDG_DATA_HOME", root.path()),
            EnvGuard::set("XDG_CONFIG_HOME", root.path()),
            EnvGuard::set("XDG_STATE_HOME", root.path()),
            EnvGuard::set("APPDATA", root.path()),
            EnvGuard::set("LOCALAPPDATA", root.path()),
            EnvGuard::set("HOME", root.path()),
            EnvGuard::set("USERPROFILE", root.path()),
            EnvGuard::set("TIRITH_LOG", Path::new("1")),
        ];
        let target = root.path().join("venv");
        let binding = InstallTargetBinding::bind(&target).unwrap();
        let mut checkpoint = EnvironmentCheckpoint::begin(&binding).unwrap();
        let private_installed = checkpoint.install_path().join("installed.py");
        std::fs::write(&private_installed, b"verified = True\n").unwrap();
        assert!(!target.exists(), "target is private until commit");

        checkpoint.publish_verified().unwrap();
        assert_eq!(checkpoint.state(), CheckpointState::PublishedUnconfirmed);
        let proof = signed_committed_receipt_proof(root.path());
        let recorded = checkpoint.confirm_committed(proof).unwrap();
        assert!(recorded.signed);
        assert_eq!(checkpoint.state(), CheckpointState::Committed);
        assert_eq!(
            std::fs::read(target.join("installed.py")).unwrap(),
            b"verified = True\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn checkpoint_refuses_parent_replacement_after_approval_binding() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        let target = parent.join("target");
        let binding = InstallTargetBinding::bind(&target).unwrap();

        let displaced = root.path().join("parent-displaced");
        std::fs::rename(&parent, &displaced).unwrap();
        std::fs::create_dir(&parent).unwrap();
        let error = EnvironmentCheckpoint::begin(&binding)
            .expect_err("a different visible parent inode requires reapproval");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!parent.join("target").exists());
        assert!(!displaced.join("target").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn checkpoint_refuses_parent_replacement_after_private_begin() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        let target = parent.join("target");
        let binding = InstallTargetBinding::bind(&target).unwrap();
        let mut checkpoint = EnvironmentCheckpoint::begin(&binding).unwrap();
        std::fs::write(
            checkpoint.install_path().join("installed"),
            b"private bytes",
        )
        .unwrap();

        let displaced = root.path().join("parent-displaced");
        std::fs::rename(&parent, &displaced).unwrap();
        std::fs::create_dir(&parent).unwrap();
        std::fs::write(parent.join("sentinel"), b"replacement parent").unwrap();

        let error = checkpoint
            .publish_verified()
            .expect_err("publication must require the approved parent identity");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(checkpoint.state(), CheckpointState::Private);
        assert!(!checkpoint.publication_crossed());
        assert!(!parent.join("target").exists());
        assert!(!displaced.join("target").exists());

        checkpoint
            .rollback()
            .expect("held private state remains safely rollback-capable");
        assert_eq!(checkpoint.state(), CheckpointState::RolledBack);
        assert!(!parent.join("target").exists());
        assert!(!displaced.join("target").exists());
        assert_eq!(
            std::fs::read(parent.join("sentinel")).unwrap(),
            b"replacement parent"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn commit_noreplace_preserves_a_peer_public_target() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        let binding = InstallTargetBinding::bind(&target).unwrap();
        let mut checkpoint = EnvironmentCheckpoint::begin(&binding).unwrap();
        std::fs::write(
            checkpoint.install_path().join("partial"),
            b"held install output",
        )
        .unwrap();
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("sentinel"), b"peer").unwrap();

        let error = checkpoint
            .publish_verified()
            .expect_err("NOREPLACE publication must not overwrite a peer target");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(!checkpoint.publication_crossed());
        checkpoint.rollback().unwrap();
        assert_eq!(std::fs::read(target.join("sentinel")).unwrap(), b"peer");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn post_publish_identity_failure_never_rolls_back_public_bytes() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        let displaced = root.path().join("published-displaced");
        let binding = InstallTargetBinding::bind(&target).unwrap();
        let mut checkpoint = EnvironmentCheckpoint::begin(&binding).unwrap();
        std::fs::write(checkpoint.install_path().join("installed"), b"exact bytes").unwrap();
        let hook_target = target.clone();
        let hook_displaced = displaced.clone();
        let error = with_checkpoint_hook(
            move |point| {
                if point == CheckpointTestPoint::AfterPublish {
                    std::fs::rename(&hook_target, &hook_displaced)?;
                    std::fs::create_dir(&hook_target)?;
                    std::fs::write(hook_target.join("sentinel"), b"replacement")?;
                }
                Ok(())
            },
            || checkpoint.publish_verified().unwrap_err(),
        );
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
        ));
        assert_eq!(checkpoint.state(), CheckpointState::PublishedUnconfirmed);
        assert!(checkpoint.publication_crossed());
        assert!(checkpoint.rollback().is_err());
        assert_eq!(
            std::fs::read(target.join("sentinel")).unwrap(),
            b"replacement"
        );
        assert_eq!(
            std::fs::read(displaced.join("installed")).unwrap(),
            b"exact bytes"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parent_replacement_after_publish_retains_exact_displaced_target() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        let target = parent.join("target");
        let displaced = root.path().join("parent-displaced");
        let binding = InstallTargetBinding::bind(&target).unwrap();
        let mut checkpoint = EnvironmentCheckpoint::begin(&binding).unwrap();
        std::fs::write(checkpoint.install_path().join("installed"), b"exact bytes").unwrap();
        let hook_parent = parent.clone();
        let hook_displaced = displaced.clone();
        let error = with_checkpoint_hook(
            move |point| {
                if point == CheckpointTestPoint::AfterPublish {
                    std::fs::rename(&hook_parent, &hook_displaced)?;
                    std::fs::create_dir(&hook_parent)?;
                    std::fs::write(hook_parent.join("sentinel"), b"replacement parent")?;
                }
                Ok(())
            },
            || checkpoint.publish_verified().unwrap_err(),
        );

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(checkpoint.state(), CheckpointState::PublishedUnconfirmed);
        assert!(checkpoint.publication_crossed());
        assert!(checkpoint.rollback().is_err());
        assert!(
            !target.exists(),
            "the replacement parent has no approved target"
        );
        assert_eq!(
            std::fs::read(parent.join("sentinel")).unwrap(),
            b"replacement parent"
        );
        assert_eq!(
            std::fs::read(displaced.join("target/installed")).unwrap(),
            b"exact bytes"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn post_publish_error_retains_the_exact_public_target() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        let binding = InstallTargetBinding::bind(&target).unwrap();
        let mut checkpoint = EnvironmentCheckpoint::begin(&binding).unwrap();
        std::fs::write(checkpoint.install_path().join("installed"), b"exact bytes").unwrap();
        let error = with_checkpoint_hook(
            |point| {
                if point == CheckpointTestPoint::AfterPublish {
                    Err(std::io::Error::other("injected post-publish failure"))
                } else {
                    Ok(())
                }
            },
            || checkpoint.publish_verified().unwrap_err(),
        );
        assert!(error.to_string().contains("injected post-publish failure"));
        assert_eq!(checkpoint.state(), CheckpointState::PublishedUnconfirmed);
        assert!(checkpoint.rollback().is_err());
        assert_eq!(
            std::fs::read(target.join("installed")).unwrap(),
            b"exact bytes"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_replacement_is_retained_instead_of_recursively_deleted() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        let binding = InstallTargetBinding::bind(&target).unwrap();
        let mut checkpoint = EnvironmentCheckpoint::begin(&binding).unwrap();
        std::fs::write(
            checkpoint.install_path().join("partial"),
            b"held install output",
        )
        .unwrap();

        let private = checkpoint.install_path().to_path_buf();
        let displaced = private.with_file_name("pending-displaced");
        std::fs::rename(&private, &displaced).unwrap();
        std::fs::create_dir(&private).unwrap();
        std::fs::write(private.join("sentinel"), b"replacement").unwrap();

        let error = checkpoint
            .rollback()
            .expect_err("private identity drift must preserve both trees");
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::InvalidInput
        ));
        assert_eq!(
            std::fs::read(private.join("sentinel")).unwrap(),
            b"replacement"
        );
        assert_eq!(
            std::fs::read(displaced.join("partial")).unwrap(),
            b"held install output"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn journal_name_replacement_is_preserved_during_held_rollback() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        let journal = root.path().join(checkpoint_journal_name(&target));
        let displaced = root.path().join("journal-displaced");
        let binding = InstallTargetBinding::bind(&target).unwrap();
        let mut checkpoint = EnvironmentCheckpoint::begin(&binding).unwrap();
        std::fs::write(
            checkpoint.install_path().join("partial"),
            b"held install output",
        )
        .unwrap();

        std::fs::rename(&journal, &displaced).unwrap();
        std::fs::create_dir(&journal).unwrap();
        std::fs::write(journal.join("sentinel"), b"replacement journal").unwrap();

        let error = checkpoint
            .rollback()
            .expect_err("cleanup must not unlink a replacement journal name");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(checkpoint.state(), CheckpointState::Retained);
        assert!(!target.exists());
        assert_eq!(
            std::fs::read(journal.join("sentinel")).unwrap(),
            b"replacement journal"
        );
        assert!(
            displaced.join("manifest.json").exists(),
            "held journal remains as recovery evidence"
        );
        assert!(
            !displaced.join(CHECKPOINT_PENDING_TARGET).exists(),
            "only the exact held private target was removed"
        );
    }

    #[test]
    fn pip_argv_is_the_pinned_install_command() {
        // The argv this module would pass the interpreter is exactly the pinned set.
        let cmd = InstallCommand {
            approved_requirements_path: PathBuf::from("/q/txn/approved.txt"),
            target_environment: PathBuf::from("/dedicated-target"),
        };
        let args = cmd.pip_install_args();
        assert_eq!(&args[0..4], &["-I", "-m", "pip", "install"]);
        for flag in [
            "--isolated",
            "--no-index",
            "--no-deps",
            "--require-hashes",
            "--no-cache-dir",
            "--force-reinstall",
            "--upgrade",
        ] {
            assert!(args.iter().any(|a| a == flag), "missing {flag}");
        }
        let target_index = args.iter().position(|arg| arg == "--target").unwrap();
        assert_eq!(args[target_index + 1], "/dedicated-target");
    }

    #[test]
    fn capsule_error_conversion_preserves_pre_exec_refusal() {
        let error = ContainedInstallError::from(capsule::CapsuleExecutionError::RefusedBeforeExec(
            capsule::CapsuleRefused {
                backend_id: "landlock-seccomp",
                reason: "coverage unavailable".to_string(),
            },
        ));
        assert!(matches!(
            error,
            ContainedInstallError::CapsuleRefused {
                backend_id: "landlock-seccomp",
                reason,
            } if reason == "coverage unavailable"
        ));
    }

    #[test]
    fn capsule_error_conversion_preserves_executed_cleanup_failure() {
        let error =
            ContainedInstallError::from(capsule::CapsuleExecutionError::ExecutedTerminated {
                backend_id: "landlock-seccomp",
                termination: capsule::CapsuleTermination {
                    kind: capsule::CapsuleTerminationKind::CleanupFailure,
                    reason: "tree still live".to_string(),
                    cleanup_confirmed: false,
                },
            });
        assert!(matches!(
            error,
            ContainedInstallError::CapsuleExecutedTerminated {
                backend_id: "landlock-seccomp",
                termination: capsule::CapsuleTermination {
                    kind: capsule::CapsuleTerminationKind::CleanupFailure,
                    cleanup_confirmed: false,
                    ..
                },
            }
        ));
    }

    /// Guard the grep-test invariant: the enforcing install-from-digest source must
    /// never reference the uncontained `ProcessInstallRunner` as actual code.
    /// Reading our own source keeps a future edit from silently routing the
    /// contained install through the uncontained analysis runner.
    #[test]
    fn source_never_references_process_install_runner() {
        let src = include_str!("pkg_install.rs");
        const SYM: &str = "ProcessInstallRunner";
        // The symbol legitimately appears here in two NON-code forms: the doc
        // comments that explain the invariant, and the string literals in this very
        // test. Either is fine; a real CODE reference (a path/call/use) is not. So
        // every occurrence must be on a comment line OR be a quoted string-literal
        // occurrence (`"...ProcessInstallRunner..."`).
        for (i, line) in src.lines().enumerate() {
            if !line.contains(SYM) {
                continue;
            }
            let is_comment = line.trim_start().starts_with("//");
            let is_quoted =
                line.contains(&format!("\"{SYM}\"")) || line.contains(&format!("`{SYM}`"));
            assert!(
                is_comment || is_quoted,
                "line {} references {SYM} as code (not a comment or string literal): {line:?}",
                i + 1
            );
        }
    }

    // ── D6: record_install_receipt ──────────────────────────────────────────

    use crate::cli::test_harness::{EnvGuard, ENV_LOCK};
    use tirith_core::capsule::CapsuleCoverage;
    use tirith_core::verdict::{Action, Timings, Verdict};

    /// A clean Allow verdict for receipt tests.
    fn allow_verdict() -> Verdict {
        Verdict {
            action: Action::Allow,
            findings: vec![],
            tier_reached: 3,
            timings_ms: Timings::default(),
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
            agent_origin: None,
            manifest_allowed_match: None,
        }
    }

    /// A successful contained-install outcome with full coverage + a clean
    /// post-install record.
    fn ok_outcome() -> ContainedInstallOutcome {
        ContainedInstallOutcome {
            exit_code: 0,
            backend_id: "landlock-seccomp",
            coverage_summary: "fs+net+exec".to_string(),
            coverage: CapsuleCoverage {
                fs_read_enforced: true,
                fs_write_enforced: true,
                exec_limited: true,
                network_raw_denied: true,
                domain_proxy_enforced: false,
                resource_limits_enforced: true,
                env_isolated: true,
                handles_isolated: true,
            },
            termination: None,
            bound_db_sequence: 7,
            approved_requirements_path: PathBuf::from("/q/txn/approved.txt"),
            post_install: Some(PostInstallIntegrity {
                verdict: allow_verdict(),
                distributions_verified: 2,
                distributions_not_found: 0,
                records_missing: 0,
                hash_mismatches: 0,
            }),
        }
    }

    #[test]
    fn record_install_receipt_writes_redacted_receipt_with_coverage() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        // Isolate every dir env var data_dir()/config_dir() consults.
        let _g = [
            EnvGuard::set("XDG_DATA_HOME", root.path()),
            EnvGuard::set("XDG_CONFIG_HOME", root.path()),
            EnvGuard::set("XDG_STATE_HOME", root.path()),
            EnvGuard::set("APPDATA", root.path()),
            EnvGuard::set("LOCALAPPDATA", root.path()),
            EnvGuard::set("HOME", root.path()),
            EnvGuard::set("USERPROFILE", root.path()),
        ];
        std::env::set_var("TIRITH_LOG", "1");

        // A policy carrying a secret that must NOT reach the receipt's policy hash.
        let policy = Policy {
            policy_server_api_key: Some("ghp_SECRET_TOKEN_42".to_string()),
            ..Default::default()
        };

        let provenance = ResolverProvenance {
            resolver_command: "uv pip compile --generate-hashes --no-build".to_string(),
            resolver_version: "uv 0.4.0".to_string(),
            package_manager_version: "pip 24.0".to_string(),
        };
        let outcome = ok_outcome();
        let verdict = allow_verdict();

        // require_signature=false: unsigned (tamper-evident) anchor is acceptable.
        let recorded = record_install_receipt(
            &outcome,
            &policy,
            &provenance,
            vec!["a".repeat(64)],
            &verdict,
            false,
        )
        .expect("record_install_receipt should save + anchor");

        assert!(recorded.path.exists());
        let json = std::fs::read_to_string(&recorded.path).unwrap();
        // The receipt carries the redaction-safe fields...
        assert!(json.contains("\"engine_build_sha\""));
        assert!(json.contains("landlock-seccomp"));
        assert!(json.contains("\"threat_db_sequence\": 7"));
        assert!(json.contains("\"distributions_verified\": 2"));
        assert!(json.contains("\"network_raw_denied\": true"));
        assert!(json.contains("uv pip compile")); // pre-redacted provenance command
                                                  // ...and never the secret token (it is reduced to a policy HASH only).
        assert!(
            !json.contains("ghp_SECRET_TOKEN_42"),
            "the receipt must never serialize the policy server API key: {json}"
        );

        std::env::remove_var("TIRITH_LOG");
    }

    #[test]
    fn record_install_receipt_omits_post_install_on_failed_install() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _g = [
            EnvGuard::set("XDG_DATA_HOME", root.path()),
            EnvGuard::set("XDG_CONFIG_HOME", root.path()),
            EnvGuard::set("APPDATA", root.path()),
            EnvGuard::set("LOCALAPPDATA", root.path()),
            EnvGuard::set("HOME", root.path()),
            EnvGuard::set("USERPROFILE", root.path()),
        ];
        std::env::set_var("TIRITH_LOG", "1");

        let mut outcome = ok_outcome();
        outcome.exit_code = 1;
        outcome.post_install = None; // a failed install has nothing to verify

        let recorded = record_install_receipt(
            &outcome,
            &Policy::default(),
            &ResolverProvenance::default(),
            vec!["a".repeat(64)],
            &allow_verdict(),
            false,
        )
        .expect("record");
        let json = std::fs::read_to_string(&recorded.path).unwrap();
        // The post-install field is null when the install failed.
        assert!(
            json.contains("\"post_install_record\": null"),
            "a failed install records no post-install RECORD summary: {json}"
        );

        std::env::remove_var("TIRITH_LOG");
    }
}
