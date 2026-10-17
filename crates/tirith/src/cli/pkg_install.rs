//! Contained install-from-digest for the package firewall (PR D4, CLI half).
//!
//! Execution is currently disabled before install preparation by the shared
//! private-input qualification guard. The implementation below remains gated.
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
//!    rename/replacement cannot redirect pip to attacker-controlled bytes. The
//!    enforcing seam requires Linux private namespaces and complete native
//!    Landlock/seccomp coverage; unsupported or incomplete capability sets refuse
//!    before pip starts. Generic capsule coverage alone does not qualify the
//!    resolver, package runtime, approval authority, or publication transaction.
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
//! `tirith pkg install`. The private-input execution qualification guard currently
//! refuses this seam on every host before any install preparation or package execution.
//! Platform-gated recovery helpers remain compiled
//! only on their owning targets; the module-level dead-code allowance covers those
//! narrow compatibility seams without weakening the launch path.
#![allow(dead_code)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;

use tirith_core::artifact::install::{
    verify_post_install_record_exact, DigestInstallPlan, ExpectedInstalledDistribution,
    InstallCommand, PostInstallIntegrity,
};
use tirith_core::artifact::quarantine::{QuarantineError, QuarantineTransaction};
use tirith_core::artifact::resolver::BoundResolverTools;
use tirith_core::policy::Policy;
use tirith_core::receipt::{
    ArtifactScanReceipt, CapsuleReceipt, PostInstallRecordSummary, ReceiptError, RecordedReceipt,
    VerdictSummary,
};
use tirith_core::task_boundary::{
    BoundaryOperation, PackageInstallPreparationBoundary, TaskBoundaryEffectLease,
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

pub use crate::cli::package_checkpoint::{
    AuthorizedInstallLaunch, EnvironmentCheckpoint, InstallTargetBinding,
};

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

/// A completed contained install that still owns the exact, non-cloneable task
/// authorization. The caller must keep this transaction alive and recheck it at
/// each receipt/publication seam; extracting only the reportable outcome cannot
/// authorize any further side effect.
pub struct AuthorizedContainedInstallOutcome {
    outcome: ContainedInstallOutcome,
    authorization: Arc<TaskBoundaryEffectLease<PackageInstallPreparationBoundary>>,
    task_envelope: tirith_core::task::TaskEnvelopeInput,
}

impl AuthorizedContainedInstallOutcome {
    pub fn outcome(&self) -> &ContainedInstallOutcome {
        &self.outcome
    }

    pub fn authorize_effect_at(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), tirith_core::task_boundary::BoundaryAuthorizationError> {
        let operation = BoundaryOperation {
            boundary: tirith_core::task_boundary::OwnedBoundary::PackageInstallPreparation,
            envelope: &self.task_envelope,
            adapter: tirith_core::task::IngressAdapter::Unattributed,
            boundary_effects: Default::default(),
        };
        self.authorization.authorize_effect_at(&operation, now)
    }
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
/// [`capsule::run_to_completion_bound_inputs`]. That seam requires Linux private
/// namespaces, sealed capabilities, and complete native containment before pip starts.
// Keep these capability and policy inputs explicit at this security boundary.
#[allow(clippy::too_many_arguments)]
pub fn run_contained_install(
    plan: &DigestInstallPlan,
    transaction: &QuarantineTransaction,
    tools: &BoundResolverTools,
    target_environment: &Path,
    launch: AuthorizedInstallLaunch,
    installed_distributions: &[ExpectedInstalledDistribution],
    policy: &Policy,
    suppress_child_output: bool,
    task_denied_effects: &std::collections::BTreeSet<tirith_core::effects::CommandEffectKind>,
) -> Result<AuthorizedContainedInstallOutcome, ContainedInstallError> {
    // Refuse even an already-authorized internal caller before publishing
    // approved.txt, retaining package inputs, or launching the executor.
    capsule::require_private_input_execution_qualification().map_err(|error| {
        let refused = error.into_capsule_refusal(&plan.spec);
        ContainedInstallError::CapsuleRefused {
            backend_id: refused.backend_id,
            reason: refused.reason,
        }
    })?;
    let crate::cli::package_checkpoint::AuthorizedInstallLaunchParts {
        target_install_path,
        target_handle,
        task_authorization,
        task_envelope,
    } = launch.into_parts();
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
    let control_operation = BoundaryOperation {
        boundary: tirith_core::task_boundary::OwnedBoundary::PackageInstallPreparation,
        envelope: &task_envelope,
        adapter: tirith_core::task::IngressAdapter::Unattributed,
        boundary_effects: Default::default(),
    };
    task_authorization
        .authorize_effect_at(&control_operation, chrono::Utc::now())
        .map_err(|error| {
            ContainedInstallError::ToolBinding(format!(
                "package install authorization expired before control-file publication: {error}"
            ))
        })?;
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
    let outcome = run_authorized_install_capsule(
        &task_authorization,
        &task_envelope,
        &plan.spec,
        tools.python(),
        &args,
        inputs,
        BoundLaunchDirectory {
            policy_root: target_environment.to_path_buf(),
            visible_path: target_install_path.clone(),
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
        let verification_root = target_install_path;
        Some(verify_post_install_record_exact(
            &verification_root,
            installed_distributions,
            policy,
        ))
    } else {
        None
    };

    Ok(AuthorizedContainedInstallOutcome {
        outcome: ContainedInstallOutcome {
            exit_code: outcome.exit_code,
            backend_id: outcome.backend_id,
            coverage_summary: outcome.coverage_summary(),
            coverage: outcome.coverage,
            termination: outcome.termination,
            bound_db_sequence: plan.bound_db_sequence,
            approved_requirements_path: approved_path,
            post_install,
        },
        authorization: task_authorization,
        task_envelope,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_authorized_install_capsule(
    task_authorization: &TaskBoundaryEffectLease<PackageInstallPreparationBoundary>,
    task_envelope: &tirith_core::task::TaskEnvelopeInput,
    spec: &tirith_core::capsule::CapsuleSpec,
    program: &tirith_core::trusted_child::TrustedExecutable,
    args: &[BoundLaunchArg],
    inputs: Vec<BoundLaunchInput>,
    target: BoundLaunchDirectory,
    extra_env: &[(String, String)],
    output_presentation: capsule::BoundOutputPresentation,
) -> Result<capsule::CapsuleExecutionOutcome, capsule::CapsuleExecutionError> {
    let operation = BoundaryOperation {
        boundary: tirith_core::task_boundary::OwnedBoundary::PackageInstallPreparation,
        envelope: task_envelope,
        adapter: tirith_core::task::IngressAdapter::Unattributed,
        boundary_effects: Default::default(),
    };
    task_authorization
        .authorize_effect_at(&operation, chrono::Utc::now())
        .map_err(|error| {
            capsule::CapsuleExecutionError::from(capsule::CapsuleRefused {
                backend_id: "task-boundary",
                reason: format!("package install authorization expired or changed: {error}"),
            })
        })?;
    capsule::run_to_completion_bound_inputs(
        spec,
        program,
        args,
        inputs,
        target,
        extra_env,
        output_presentation,
    )
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
        policy.enforcement_projection_hash(),
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
    use tirith_core::task_boundary::TaskBoundaryPermit;

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
        let _log = EnvGuard::set("TIRITH_LOG", std::path::Path::new("1"));

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
        let _log = EnvGuard::set("TIRITH_LOG", std::path::Path::new("1"));

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
    }
}
