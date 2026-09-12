//! Shared retained-target checkpoint for closed contained package installers.
//! The wheel entrypoint retains its existing exact-envelope behavior. Npm uses
//! a typed staged authorization bound to its immutable complete leaf plan.
#![allow(dead_code)]

#[path = "npm_checkpoint_binding.rs"]
mod npm_binding;
#[cfg(target_os = "linux")]
use npm_binding::NpmReceiptBinding;

#[cfg(target_os = "linux")]
use crate::cli::capsule;
#[cfg(target_os = "linux")]
use fs2::FileExt as _;
#[cfg(target_os = "linux")]
use serde::Serialize;
#[cfg(target_os = "linux")]
use sha2::{Digest as _, Sha256};
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::ffi::OsStr;
#[cfg(target_os = "linux")]
use std::ffi::OsString;
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Write as _;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd as _, FromRawFd as _};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tirith_core::artifact::resolver::ResolverRequest;
use tirith_core::receipt::{RecordedCommittedReceipt, RecordedReceipt};
use tirith_core::task_boundary::{
    BoundaryOperation, PackageInstallPreparationBoundary, PackageOperationBinding,
    PackageTargetIdentity, TaskBoundaryEffectLease, TaskBoundaryPermit,
};

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
/// wheel execution remains x86_64 Linux-only. The separate closed npm contract
/// must establish its own qualified tool closure and native launcher coverage;
/// this shared checkpoint does not broaden either execution gate.
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

    /// Canonical, receipt-safe identity used by the package task boundary. The
    /// retained parent descriptor and final component remain the execution
    /// authority; the path digest prevents disclosure while still detecting an
    /// operation swap.
    pub fn package_target_identity(&self) -> PackageTargetIdentity {
        #[cfg(target_os = "linux")]
        let target_path_sha256 =
            tirith_core::command_card::sha256_hex(self.target.as_os_str().as_bytes());
        #[cfg(not(target_os = "linux"))]
        let target_path_sha256 =
            tirith_core::command_card::sha256_hex(self.target.to_string_lossy().as_bytes());

        PackageTargetIdentity::new(
            target_path_sha256,
            self.parent_identity(),
            self.target_component(),
        )
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
    task_authorization: Option<Arc<TaskBoundaryEffectLease<PackageInstallPreparationBoundary>>>,
    task_envelope: Option<tirith_core::task::TaskEnvelopeInput>,
    #[cfg(target_os = "linux")]
    npm_receipt_binding: Option<NpmReceiptBinding>,
    #[cfg(target_os = "linux")]
    state: CheckpointState,
}

impl std::fmt::Debug for EnvironmentCheckpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnvironmentCheckpoint")
            .field("private_target", &self.private_target)
            .field(
                "task_authorization_retained",
                &self.task_authorization.is_some(),
            )
            .finish_non_exhaustive()
    }
}

/// One-shot install-launch authority extracted from a still-live checkpoint.
/// Its fields are private and it is neither cloneable nor serializable, so a
/// package permit cannot be reduced to a reusable path or boolean.
pub struct AuthorizedInstallLaunch {
    target_install_path: PathBuf,
    target_handle: File,
    task_authorization: Arc<TaskBoundaryEffectLease<PackageInstallPreparationBoundary>>,
    task_envelope: tirith_core::task::TaskEnvelopeInput,
}

pub(crate) struct AuthorizedInstallLaunchParts {
    pub(crate) target_install_path: PathBuf,
    pub(crate) target_handle: File,
    pub(crate) task_authorization: Arc<TaskBoundaryEffectLease<PackageInstallPreparationBoundary>>,
    pub(crate) task_envelope: tirith_core::task::TaskEnvelopeInput,
}

impl AuthorizedInstallLaunch {
    pub(crate) fn into_parts(self) -> AuthorizedInstallLaunchParts {
        AuthorizedInstallLaunchParts {
            target_install_path: self.target_install_path,
            target_handle: self.target_handle,
            task_authorization: self.task_authorization,
            task_envelope: self.task_envelope,
        }
    }
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
    /// Begin the install-preparation side effect only with a consumed permit for
    /// this exact operation. The marker type prevents another owned boundary's
    /// token from reaching checkpoint creation, while the digest check prevents
    /// reuse for another package set or envelope.
    pub fn begin_authorized(
        binding: &InstallTargetBinding,
        permit: TaskBoundaryPermit<PackageInstallPreparationBoundary>,
        ecosystem: &str,
        request: &ResolverRequest,
        artifact_origins: &[String],
    ) -> std::io::Result<Self> {
        let target_identity = binding.package_target_identity();
        let package_binding =
            PackageOperationBinding::new(ecosystem, request, artifact_origins, &target_identity);
        let envelope =
            tirith_core::task_boundary::package_envelope(&package_binding).map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
            })?;
        let operation = BoundaryOperation {
            boundary: tirith_core::task_boundary::OwnedBoundary::PackageInstallPreparation,
            envelope: &envelope,
            adapter: tirith_core::task::IngressAdapter::Unattributed,
            boundary_effects: Default::default(),
        };
        let lease = permit
            .into_effect_lease_at(&operation, chrono::Utc::now())
            .map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("install-preparation authorization expired or changed: {error}"),
                )
            })?;
        let mut checkpoint = Self::begin(binding)?;
        checkpoint.task_authorization = Some(Arc::new(lease));
        checkpoint.task_envelope = Some(envelope);
        Ok(checkpoint)
    }

    /// Consume the one staged npm authorization for this exact held target.
    /// It already binds retained manifests, artifacts, policy and tool closure;
    /// never reconstruct a weaker wheel-style envelope from package strings.
    pub(crate) fn begin_npm_authorized(
        binding: &InstallTargetBinding,
        authorization: tirith_core::artifact::npm_install::NpmPreparationAuthorization,
    ) -> std::io::Result<Self> {
        if authorization.target_identity() != &binding.package_target_identity() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "staged npm authorization identifies a different target",
            ));
        }
        #[cfg(target_os = "linux")]
        let npm_operation_id = authorization.operation_id().to_owned();
        let (envelope, lease) = authorization.into_parts();
        let operation = BoundaryOperation {
            boundary: tirith_core::task_boundary::OwnedBoundary::PackageInstallPreparation,
            envelope: &envelope,
            adapter: tirith_core::task::IngressAdapter::Unattributed,
            boundary_effects: Default::default(),
        };
        lease
            .authorize_effect_at(&operation, chrono::Utc::now())
            .map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("staged npm authorization expired or changed: {error}"),
                )
            })?;
        // begin rechecks the retained parent and final absence before the first
        // journal/target write. All cleanup remains descriptor-confined here.
        let mut checkpoint = Self::begin(binding)?;
        checkpoint.task_authorization = Some(lease);
        checkpoint.task_envelope = Some(envelope);
        #[cfg(target_os = "linux")]
        {
            checkpoint.npm_receipt_binding = Some(NpmReceiptBinding::new(npm_operation_id));
        }
        Ok(checkpoint)
    }

    /// Untyped initialization is private so production callers cannot bypass
    /// [`Self::begin_authorized`]. Unit tests in this module exercise the
    /// descriptor/journal machinery directly through this inner seam.
    fn begin(binding: &InstallTargetBinding) -> std::io::Result<Self> {
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
                task_authorization: None,
                task_envelope: None,
                npm_receipt_binding: None,
                state: CheckpointState::Private,
            })
        }
    }

    /// Canonical private target path used only to rebase the capsule's approved
    /// write root. The approval, receipt, and final publication identity remain
    /// [`InstallTargetBinding::target`].
    #[cfg(test)]
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

    /// Move the retained task permit and a duplicate of the exact private
    /// target descriptor into the sole contained-spawn transaction. A second
    /// call fails, preventing retry or operation reuse without reauthorization.
    pub fn take_authorized_launch(&mut self) -> std::io::Result<AuthorizedInstallLaunch> {
        #[cfg(target_os = "linux")]
        {
            self.verify_private_identity()?;
            let target_handle = self.target_handle.try_clone()?;
            let task_authorization = self.task_authorization.take().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "install launch authorization was already consumed",
                )
            })?;
            let task_envelope = self.task_envelope.take().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "install launch operation binding was already consumed",
                )
            })?;
            Ok(AuthorizedInstallLaunch {
                target_install_path: self.private_target.clone(),
                target_handle,
                task_authorization,
                task_envelope,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "held authorized install launches are not implemented on this platform",
            ))
        }
    }

    /// Bind the exact prepared npm receipt before publication. The operation ID
    /// comes from the consumed preparation authorization, and the receipt values
    /// come from the core's opaque signed private-to-committed derivation.
    pub(crate) fn bind_npm_committed_receipt(
        &mut self,
        prepared: &tirith_core::receipt::PreparedCommittedReceipt,
    ) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            if self.state != CheckpointState::Private {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "npm receipt must be bound before checkpoint publication",
                ));
            }
            self.verify_private_identity()?;
            self.npm_receipt_binding
                .as_mut()
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "only npm preparation accepts an npm receipt binding",
                    )
                })?
                .bind_prepared(prepared.npm_operation_id(), prepared.receipt_id())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = prepared;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "held npm checkpoints are not implemented on this platform",
            ))
        }
    }

    /// Atomically publish the privately verified target without claiming that the
    /// mandatory linked committed receipt has been recorded yet.
    pub fn publish_verified(&mut self) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            if let Some(binding) = &self.npm_receipt_binding {
                binding.require_prepared()?;
            }
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
            if let Some(binding) = &self.npm_receipt_binding {
                binding.verify_committed(proof.receipt_id())?;
            }
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::cli::pkg_install::{
        build_install_receipt, ContainedInstallOutcome, ResolverProvenance,
    };
    use crate::cli::test_harness::{EnvGuard, ENV_LOCK};
    use tirith_core::artifact::install::PostInstallIntegrity;
    use tirith_core::capsule::CapsuleCoverage;
    use tirith_core::policy::Policy;
    use tirith_core::verdict::{Action, Timings, Verdict};
    fn preparation_permit(
        operation: &BoundaryOperation<'_>,
    ) -> TaskBoundaryPermit<PackageInstallPreparationBoundary> {
        tirith_core::task_boundary::prepare_locally_derived_boundary_authorization::<
            PackageInstallPreparationBoundary,
        >(
            operation,
            &tirith_core::web3_policy::TaskGatePolicy::default(),
            &tirith_core::task_analysis::TaskAnalysisContext::default(),
        )
        .unwrap()
        .consume_default(chrono::Utc::now())
        .unwrap()
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
    #[test]
    fn authorized_checkpoint_reconstructs_and_rejects_a_target_mutation() {
        let root = tempfile::tempdir().unwrap();
        let approved_target = root.path().join("approved");
        let changed_target = root.path().join("changed");
        let changed_journal = root.path().join(checkpoint_journal_name(&changed_target));
        let approved_binding = InstallTargetBinding::bind(&approved_target).unwrap();
        let changed_binding = InstallTargetBinding::bind(&changed_target).unwrap();
        let request = ResolverRequest::single("approved==1.0");
        let approved_identity = approved_binding.package_target_identity();
        let approved_package_binding =
            PackageOperationBinding::new("pip", &request, &[], &approved_identity);
        let approved_envelope =
            tirith_core::task_boundary::package_envelope(&approved_package_binding).unwrap();
        let approved_operation = BoundaryOperation {
            boundary: tirith_core::task_boundary::OwnedBoundary::PackageInstallPreparation,
            envelope: &approved_envelope,
            adapter: tirith_core::task::IngressAdapter::Unattributed,
            boundary_effects: Default::default(),
        };
        let permit = preparation_permit(&approved_operation);

        let changed_identity = changed_binding.package_target_identity();
        let changed_package_binding =
            PackageOperationBinding::new("pip", &request, &[], &changed_identity);
        let changed_envelope =
            tirith_core::task_boundary::package_envelope(&changed_package_binding).unwrap();
        let changed_operation = BoundaryOperation {
            boundary: tirith_core::task_boundary::OwnedBoundary::PackageInstallPreparation,
            envelope: &changed_envelope,
            adapter: tirith_core::task::IngressAdapter::Unattributed,
            boundary_effects: Default::default(),
        };
        let error =
            EnvironmentCheckpoint::begin_authorized(&changed_binding, permit, "pip", &request, &[])
                .expect_err("a permit for another target identity must be refused");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!approved_target.exists());
        assert!(!changed_target.exists());
        assert!(!changed_journal.exists());

        let permit = preparation_permit(&changed_operation);
        let mut checkpoint =
            EnvironmentCheckpoint::begin_authorized(&changed_binding, permit, "pip", &request, &[])
                .expect("the exact typed permit authorizes private checkpoint creation");
        let _launch = checkpoint
            .take_authorized_launch()
            .expect("the exact authorization reaches one launch transaction");
        let reused = match checkpoint.take_authorized_launch() {
            Ok(_) => panic!("the task permit must not authorize a retry"),
            Err(error) => error,
        };
        assert_eq!(reused.kind(), std::io::ErrorKind::PermissionDenied);
        checkpoint.rollback().unwrap();
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
}
