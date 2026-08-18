//! `tirith pkg install | verify-env | approve | receipt`, the package-firewall
//! CLI surface (PR D7).
//!
//! This is the operator-facing command that drives the D1-D6 machinery end to end:
//!
//! * **`pkg approve`** resolves a Python requirement set into the D1 quarantine (D2),
//!   firewalls + re-binds it (D3/D4), and prints the [`InstallPlanDigest`] the
//!   approval binds to, persisting an approval record keyed by that digest. It NEVER
//!   installs. The digest binds the WHOLE situation (artifact hashes, package set,
//!   interpreter, target env, platform tags, install-command semantics, redacted
//!   policy hash, threat-DB sequence, capsule backend, required coverage, expiry);
//!   the sorted SHA-set is a display label only.
//! * **`pkg install`** repeats the resolve + re-bind, re-derives the digest of the
//!   plan it is ABOUT to run, requires a matching un-expired approval record (or an
//!   explicit `--yes` for the unattended path), runs the contained install (D4,
//!   fail-closed under degraded coverage), verifies the installed RECORD (D5), and
//!   records a tamper-evident, Ed25519-mandatory receipt (D6).
//! * **`pkg verify-env`** runs the D5 post-install RECORD verification over an
//!   already-installed environment, without installing anything.
//! * **`pkg receipt`** lists and shows the D6 [`ArtifactScanReceipt`]s.
//!
//! # Distinct from `tirith install`
//!
//! `tirith install` (in [`crate::cli::install`]) is the ANALYSIS path: it inspects a
//! package-manager command and optionally runs the real, UNcontained install.
//! `tirith pkg install` is the ENFORCING path: it installs ONLY the inspected,
//! hash-pinned bytes, inside the capsule, and refuses on degraded coverage. The two
//! stay separate commands. This module reuses `tirith install`'s
//! `MISPLACED_TIRITH_FLAGS` footgun guard (a tirith-owned flag placed after the
//! trailing args would silently not affect tirith).
//!
//! # What is exercised by tests vs. at runtime
//!
//! The resolve + contained install need a real `uv` / `python` and the OS capsule
//! backend, so the full `pkg install` / `approve` flow is integration-only. The
//! unit-testable seams here (the misplaced-flag guard, the
//! [`InstallPlanDigest`]-from-plan construction, the approval-record save / load +
//! digest comparison, the `verify-env` fold, and the receipt rendering) have direct
//! tests in this module.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use fs2::FileExt as _;

use tirith_core::artifact::install::{
    installed_distribution_identities, installed_distribution_names, rebind_for_install,
    verify_post_install_record, DigestInstallPlan, ExpectedInstalledDistribution, InstallCommand,
    InstallError, InstallPlanDigest, InstallPlanInputs,
};
use tirith_core::artifact::quarantine::{QuarantineError, QuarantineStore, QuarantineTransaction};
use tirith_core::artifact::resolver::{
    enroll_resolver_tool, resolve_into_quarantine_with_bound_tools,
    validate_resolver_request_with_artifact_origins, BoundResolverTools, ResolvedSet,
    ResolverError, ResolverRequest, ResolverTools, PIP_TREE_BINDING_VERSION, PIP_TREE_MAX_BYTES,
    PIP_TREE_MAX_FILES, PIP_TREE_MAX_FILE_BYTES, PIP_TREE_MAX_PATH_BYTES,
};
use tirith_core::package_approval::{
    expiry_independent_plan, verify_package_approval, PackageApprovalError,
    PackageApprovalRecordV2, VerifiedPackageApproval,
};
use tirith_core::policy::Policy;
use tirith_core::receipt::ArtifactScanReceipt;
use tirith_core::task_analysis::TaskAnalysisContext;
use tirith_core::task_boundary::{
    BoundaryAuthorizationError, BoundaryMarker, BoundaryOperation, PackageApprovalBoundary,
    PackageInstallApprovalChannel, PackageInstallPreparationBoundary, PackageOperationBinding,
    PackageResolveBoundary, PendingBoundaryAuthorization, TaskBoundaryPermit,
};
use tirith_core::threatdb::ThreatDb;

use crate::cli::capsule::{self, DegradedPolicy};
#[cfg(test)]
use crate::cli::package_approval_authority::{NativeAuthorityError, PackageApprovalIssuer};
use crate::cli::package_approval_authority::{
    NativePackageApprovalAuthority, PackageApprovalAuthority, PackageApprovalKeyProvider,
};
use crate::cli::pkg_install::{
    build_install_receipt, run_contained_install, AuthorizedInstallLaunch, ContainedInstallError,
    EnvironmentCheckpoint, InstallTargetBinding, ResolverProvenance,
};

/// tirith-owned options that no package manager interprets. If one of these appears
/// AFTER the trailing requirement args it would silently not affect tirith (the same
/// footgun `tirith install` guards), so finding one trailing is a hard error. Shared
/// in spirit with [`crate::cli::install`]'s guard; kept local so the two surfaces
/// can carry their own flag sets.
const MISPLACED_TIRITH_FLAGS: &[&str] = &["--yes", "--allow-degraded", "--online"];

const MAX_PERSISTED_APPROVAL_RECORDS: usize = 256;

fn discover_pkg_enforcement_policy(cwd: Option<&str>) -> Policy {
    Policy::discover(cwd)
}

/// What the `pkg` command should do, parsed from the CLI. Mirrors the clap
/// subcommand in `main.rs`; kept here so the dispatch logic lives with the module.
#[derive(Debug, Clone)]
pub enum PkgAction {
    /// Resolve + firewall + approve, printing the plan digest; does NOT install.
    Approve {
        ecosystem: Ecosystem,
        requirements: Vec<String>,
        target: Option<PathBuf>,
        index_url: Vec<String>,
        artifact_origin: Vec<String>,
        json: bool,
    },
    /// Resolve + firewall + (with a matching approval or `--yes`) contained install.
    Install {
        ecosystem: Ecosystem,
        requirements: Vec<String>,
        target: Option<PathBuf>,
        index_url: Vec<String>,
        artifact_origin: Vec<String>,
        yes: bool,
        allow_degraded: bool,
        json: bool,
    },
    /// D5 post-install RECORD verification over an already-installed environment.
    VerifyEnv {
        target: PathBuf,
        packages: Vec<String>,
        json: bool,
    },
    /// Explicitly pin a user-writable uv/python executable by canonical path and
    /// SHA-256 in the owner-only operator trust store.
    TrustTool { path: PathBuf, json: bool },
    /// List / show the D6 tamper-evident receipts.
    Receipt { which: ReceiptQuery, json: bool },
}

/// Which receipt(s) `pkg receipt` reports.
#[derive(Debug, Clone)]
pub enum ReceiptQuery {
    /// All saved artifact-scan receipts, newest first.
    List,
    /// The newest saved artifact-scan receipt.
    Last,
    /// One receipt by its `receipt_id` (content hash).
    Show(String),
}

/// The ecosystem `pkg install` / `approve` enforce for. Only `pip` (Python wheels)
/// is enforced in v1; npm / cargo are deliberately refused here (their hardened
/// `.tgz` / `.crate` analysers do not exist yet, plan Stack D).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    /// Python wheels via the D2 `uv` + `pip` resolver. The only enforced ecosystem.
    Pip,
    /// npm, not enforced in v1 (resolve+inspect-metadata only lives behind hidden
    /// experimental flags; the firewall install path refuses it).
    Npm,
    /// cargo, not enforced in v1, as npm.
    Cargo,
}

impl Ecosystem {
    fn label(self) -> &'static str {
        match self {
            Ecosystem::Pip => "pip",
            Ecosystem::Npm => "npm",
            Ecosystem::Cargo => "cargo",
        }
    }
}

/// Entry point for `tirith pkg`. Returns a process exit code (0 success, 1 a
/// blocked / failed operation, 2 a usage error).
pub fn run(action: PkgAction) -> i32 {
    match action {
        PkgAction::Approve {
            ecosystem,
            requirements,
            target,
            index_url,
            artifact_origin,
            json,
        } => run_approve(
            ecosystem,
            &requirements,
            target,
            &index_url,
            &artifact_origin,
            json,
        ),
        PkgAction::Install {
            ecosystem,
            requirements,
            target,
            index_url,
            artifact_origin,
            yes,
            allow_degraded,
            json,
        } => run_install(
            ecosystem,
            &requirements,
            target,
            &index_url,
            &artifact_origin,
            yes,
            allow_degraded,
            json,
        ),
        PkgAction::VerifyEnv {
            target,
            packages,
            json,
        } => run_verify_env(&target, &packages, json),
        PkgAction::Receipt { which, json } => run_receipt(which, json),
        PkgAction::TrustTool { path, json } => run_trust_tool(&path, json),
    }
}

// ---------------------------------------------------------------------------
// Shared guards + plan preparation
// ---------------------------------------------------------------------------

/// Refuse a non-pip ecosystem (only Python is enforced in v1) and refuse a
/// misplaced tirith-owned flag in the requirement list. The check is presentation-
/// free so `--json` callers can emit one structured document without a preceding
/// human diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PkgPrecheckFailure {
    exit_code: i32,
    reason: String,
}

fn precheck(ecosystem: Ecosystem, requirements: &[String]) -> Option<PkgPrecheckFailure> {
    if ecosystem != Ecosystem::Pip {
        return Some(PkgPrecheckFailure {
            exit_code: 2,
            reason: format!(
                "only `pip` is enforced in this version; `{}` is not yet supported \
             (npm / cargo resolve-and-inspect lives behind hidden experimental flags and cannot \
             install). Use `tirith install {}` for analysis-only.",
                ecosystem.label(),
                ecosystem.label()
            ),
        });
    }
    if let Some(flag) = requirements
        .iter()
        .find(|a| MISPLACED_TIRITH_FLAGS.contains(&a.as_str()))
    {
        return Some(PkgPrecheckFailure {
            exit_code: 2,
            reason: format!(
                "`{flag}` is a tirith option and must come before the requirement list \
             (e.g. `tirith pkg install pip {flag} requests==2.31.0`). After the ecosystem, \
             arguments are package requirements, so a misplaced `{flag}` would not affect tirith."
            ),
        });
    }
    if requirements.is_empty() {
        return Some(PkgPrecheckFailure {
            exit_code: 2,
            reason: "no requirements given. try: tirith pkg install pip requests==2.31.0 --target .tirith-pkg"
                .to_string(),
        });
    }
    None
}

fn report_pkg_precheck_failure(
    command: &'static str,
    failure: &PkgPrecheckFailure,
    json: bool,
) -> i32 {
    if json {
        let value = serde_json::json!({
            "success": false,
            "command": command,
            "error_phase": "precheck",
            "target_executed": false,
            "target_published": false,
            "reason": failure.reason.as_str(),
        });
        let _ = write_json_document(std::io::stdout().lock(), &value);
    } else {
        eprintln!(
            "tirith pkg: {}",
            crate::cli::sanitize_for_human_output(&failure.reason, false)
        );
    }
    failure.exit_code
}

/// The interpreter + explicit dedicated target an install/approve binds to. The
/// target is never inferred from the interpreter prefix; enforcing installs require
/// a new `--target` directory whose canonical parent already exists.
#[derive(Debug)]
struct InstallTarget {
    interpreter: PathBuf,
    environment: PathBuf,
    extra_read_roots: Vec<PathBuf>,
    /// Retains the exact canonical parent identity selected before resolution.
    /// Checkpoint creation uses this descriptor rather than reopening the path.
    binding: InstallTargetBinding,
}

impl InstallTarget {
    /// Bind an explicit, dedicated pip target. Inferring a write root from
    /// `<python>/../..` can select `/usr`, `/opt/homebrew`, or another shared
    /// installation prefix and make rollback copy an enormous unrelated tree.
    fn from_binding(interpreter: PathBuf, binding: InstallTargetBinding) -> Self {
        let environment = binding.target().to_path_buf();

        // The interpreter prefix: `<prefix>/bin/python` -> `<prefix>`. Best-effort;
        // it is READ-only launch support and never becomes the install destination.
        let prefix = interpreter
            .parent()
            .and_then(|p| p.parent())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| {
                interpreter
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("/"))
            });
        InstallTarget {
            interpreter,
            environment,
            extra_read_roots: vec![prefix],
            binding,
        }
    }
}

/// Bind the exact target before task authorization. The retained descriptor is
/// then moved through resolver preparation and checkpoint creation, so neither
/// side-effect API can reconstruct authority from a mutable path.
fn bind_install_target(target: Option<PathBuf>) -> Result<InstallTargetBinding, String> {
    let target = target.ok_or_else(|| {
        "an explicit --target is required for enforcing installs; choose a new dedicated directory whose parent already exists"
            .to_string()
    })?;
    let binding = InstallTargetBinding::bind(&target)
        .map_err(|error| format!("cannot bind --target parent and final component: {error}"))?;
    if is_broad_install_target(binding.target()) {
        return Err(format!(
            "refusing broad/shared install target {}; choose a new dedicated package directory",
            binding.target().display()
        ));
    }
    Ok(binding)
}

fn is_broad_install_target(path: &Path) -> bool {
    if path.parent().is_none() {
        return true;
    }
    #[cfg(unix)]
    {
        [
            "/bin",
            "/etc",
            "/lib",
            "/lib64",
            "/opt",
            "/opt/homebrew",
            "/System",
            "/Library",
            "/usr",
            "/usr/local",
        ]
        .iter()
        .any(|root| path == Path::new(root))
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// The resolve + re-bind outcome shared by `approve` and `install`: the launch-ready
/// plan, the resolved set (for the digest's package list + the receipt's redacted
/// command), the install target, the threat-DB sequence, the selected capsule
/// backend, and the digest the operation binds to.
struct PreparedPlan {
    plan: DigestInstallPlan,
    resolved: ResolvedSet,
    target: InstallTarget,
    digest: InstallPlanDigest,
    txn: QuarantineTransaction,
    /// Retains the exact resolver and interpreter identities, including Linux
    /// sealed executable descriptors, through the offline install and receipt.
    tools: BoundResolverTools,
    /// Retained so the transaction's lease (and temp tree) outlive the install.
    _store: QuarantineStore,
}

/// Resolve `requirements` into the quarantine, firewall + re-bind them, and build
/// the [`InstallPlanDigest`] the operation binds to. `expiry` time-boxes the digest
/// (an empty string means none). Shared by `approve` (which stops after this and
/// prints the digest) and `install` (which proceeds to run the plan).
fn validated_resolver_request(
    requirements: &[String],
    index_url: &[String],
    artifact_origin: &[String],
) -> Result<ResolverRequest, PrepareError> {
    let request = ResolverRequest {
        requirements: requirements.to_vec(),
        index_urls: index_url.to_vec(),
        allowances: Default::default(),
    };
    // Pure parsing and policy checks run before a replayable authorization is
    // consumed. They perform no PATH lookup, quarantine mutation, DNS, or child
    // execution, so malformed input cannot burn a one-shot permit.
    validate_resolver_request_with_artifact_origins(&request, artifact_origin)
        .map_err(PrepareError::Resolver)?;
    Ok(request)
}

fn prepare_plan(
    request: &ResolverRequest,
    target_binding: InstallTargetBinding,
    artifact_origin: &[String],
    policy: &Policy,
    expiry: String,
    task_gate_binding: String,
) -> Result<PreparedPlan, PrepareError> {
    // Resolve uv + python by executable provenance (never a bare PATH name in the
    // child), with the locked-down default allowances (no sdist/VCS/editable/...).
    let discovered =
        ResolverTools::discover(&request.allowances).map_err(PrepareError::Resolver)?;
    // The target was capability-bound before authorization. Move that exact
    // descriptor through the resolver rather than reopening its path.
    let target = InstallTarget::from_binding(discovered.python.clone(), target_binding);
    let tools = BoundResolverTools::bind(&discovered).map_err(PrepareError::Resolver)?;

    // A fresh quarantine transaction under the real data dir. The id is a
    // timestamp-derived component; the store validates it.
    let store = QuarantineStore::open().map_err(PrepareError::Quarantine)?;
    let txn_id = new_transaction_id();
    let txn = store
        .begin_transaction(&txn_id)
        .map_err(PrepareError::Quarantine)?;

    // D2: resolve + download + ingest into the quarantine (re-hashing on the way in).
    let resolved = resolve_into_quarantine_with_bound_tools(request, &tools, &txn, artifact_origin)
        .map_err(PrepareError::Resolver)?;

    // The live threat DB sequence the plan binds to. `cached()` is the same DB the
    // rest of tirith consults; `None` is sequence 0.
    let db = ThreatDb::cached();
    let db_sequence = db.as_deref().map(|d| d.build_sequence()).unwrap_or(0);

    // D3/D4: firewall + re-bind. A swapped/missing blob or a now-known-malicious
    // wheel refuses here; a clean set yields the launch-ready plan.
    let plan = rebind_for_install(
        &resolved,
        &txn,
        policy,
        db.as_deref(),
        db_sequence,
        &target.environment,
        &target.extra_read_roots,
    )
    .map_err(PrepareError::Install)?;

    // The backend id is compile-target stable. Probe it with a target-free spec:
    // the approved target does not exist yet by contract, and filesystem-root
    // canonicalization belongs after EnvironmentCheckpoint has mkdirat-created and
    // retained that exact target. The digest separately binds plan.required_coverage.
    let backend = capsule::select_backend(&tirith_core::capsule::CapsuleSpec::locked_down());

    let digest = build_plan_digest(
        &plan,
        &resolved,
        &target,
        &tools,
        policy,
        backend.backend_id,
        expiry,
        task_gate_binding,
    );

    Ok(PreparedPlan {
        plan,
        resolved,
        target,
        digest,
        txn,
        tools,
        _store: store,
    })
}

/// The install resolver boundary consumes its permit at the networked plan
/// preparation seam. Approval uses [`AuthorizedPackageApprovalTransaction`]
/// instead because its permit must remain live through grant publication.
/// Keeping this trait private prevents an unrelated boundary token from being
/// accepted accidentally.
trait ResolverPreparationBoundary: BoundaryMarker {}

impl ResolverPreparationBoundary for PackageResolveBoundary {}

/// Consume a boundary-typed permit at the first resolver/quarantine/network
/// seam. The operation binding is checked again by the side-effect API rather
/// than relying on the caller to keep the right operation beside the token.
#[allow(clippy::too_many_arguments)]
fn prepare_plan_authorized<B: ResolverPreparationBoundary>(
    permit: TaskBoundaryPermit<B>,
    ecosystem: &str,
    request: &ResolverRequest,
    target_binding: InstallTargetBinding,
    artifact_origin: &[String],
    policy: &Policy,
    expiry: String,
    task_gate_binding: String,
) -> Result<PreparedPlan, PrepareError> {
    let target_identity = target_binding.package_target_identity();
    let package_binding =
        PackageOperationBinding::new(ecosystem, request, artifact_origin, &target_identity);
    let envelope = tirith_core::task_boundary::package_envelope(&package_binding)
        .map_err(|error| PrepareError::Authorization(error.to_string()))?;
    let operation = package_boundary_operation::<B>(&envelope);
    permit
        .authorize_effect_at(&operation, chrono::Utc::now())
        .map_err(|error| PrepareError::Authorization(error.to_string()))?;
    prepare_plan(
        request,
        target_binding,
        artifact_origin,
        policy,
        expiry,
        task_gate_binding,
    )
}

/// One PackageApproval permit retained across resolver/quarantine work and the
/// final durable approval-record publication. The transaction is non-cloneable
/// because its permit is non-cloneable; a failed or completed publication
/// cannot be retried through a reusable boolean authorization.
struct AuthorizedPackageApprovalTransaction {
    permit: TaskBoundaryPermit<PackageApprovalBoundary>,
    envelope: tirith_core::task::TaskEnvelopeInput,
}

impl AuthorizedPackageApprovalTransaction {
    fn new(
        permit: TaskBoundaryPermit<PackageApprovalBoundary>,
        envelope: tirith_core::task::TaskEnvelopeInput,
    ) -> Result<Self, PrepareError> {
        let operation = package_boundary_operation::<PackageApprovalBoundary>(&envelope);
        if !permit.binds_operation(&operation) {
            return Err(PrepareError::Authorization(
                "task boundary permit does not bind this exact package approval".to_string(),
            ));
        }
        Ok(Self { permit, envelope })
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare(
        self,
        ecosystem: &str,
        request: &ResolverRequest,
        target_binding: InstallTargetBinding,
        artifact_origin: &[String],
        policy: &Policy,
        expiry: String,
        task_gate_binding: String,
    ) -> Result<AuthorizedPreparedApproval, PrepareError> {
        let target_identity = target_binding.package_target_identity();
        let package_binding =
            PackageOperationBinding::new(ecosystem, request, artifact_origin, &target_identity);
        let actual_envelope = tirith_core::task_boundary::package_envelope(&package_binding)
            .map_err(|error| PrepareError::Authorization(error.to_string()))?;
        let actual_operation =
            package_boundary_operation::<PackageApprovalBoundary>(&actual_envelope);
        if actual_envelope != self.envelope || !self.permit.binds_operation(&actual_operation) {
            return Err(PrepareError::Authorization(
                "task boundary permit does not bind this exact package approval".to_string(),
            ));
        }
        let prepared = prepare_plan(
            request,
            target_binding,
            artifact_origin,
            policy,
            expiry,
            task_gate_binding,
        )?;
        Ok(AuthorizedPreparedApproval {
            authorization: self,
            prepared,
        })
    }
}

/// A prepared approval whose original typed authorization remains live. Only
/// consuming this value may publish the durable approval record.
struct AuthorizedPreparedApproval {
    authorization: AuthorizedPackageApprovalTransaction,
    prepared: PreparedPlan,
}

impl AuthorizedPreparedApproval {
    fn digest(&self) -> &InstallPlanDigest {
        &self.prepared.digest
    }

    fn publish(self) -> Result<(PreparedPlan, PathBuf), ApprovalPublishError> {
        self.publish_with_issuer(&NativePackageApprovalAuthority)
    }

    fn publish_with_issuer(
        mut self,
        authority: &dyn PackageApprovalAuthority,
    ) -> Result<(PreparedPlan, PathBuf), ApprovalPublishError> {
        let AuthorizedPackageApprovalTransaction { permit, envelope } = self.authorization;
        let operation = package_boundary_operation::<PackageApprovalBoundary>(&envelope);
        let record = authority
            .issue(&self.prepared.digest)
            .map_err(|error| ApprovalPublishError::NativeAuthority(error.to_string()))?;
        let requested = expiry_independent_plan(&self.prepared.digest)
            .map_err(|error| ApprovalPublishError::TrustVerification(error.to_string()))?;
        let trusted_keys = authority
            .trusted_keys()
            .map_err(|error| ApprovalPublishError::TrustVerification(error.to_string()))?;
        verify_package_approval(&record, &requested, &trusted_keys, chrono::Utc::now()).map_err(
            |error| {
                ApprovalPublishError::TrustVerification(format!(
                    "native authority proof did not verify: {error}"
                ))
            },
        )?;
        self.prepared.digest = record.digest().clone();
        let path = persist_approval_record_authorized(
            &record,
            permit,
            &operation,
            &trusted_keys,
            chrono::Utc::now(),
        )
        .map_err(ApprovalPublishError::RecordPersistence)?;
        Ok((self.prepared, path))
    }
}

#[derive(Debug)]
enum ApprovalPublishError {
    NativeAuthority(String),
    TrustVerification(String),
    RecordPersistence(String),
}

impl ApprovalPublishError {
    fn phase(&self) -> &'static str {
        match self {
            Self::NativeAuthority(_) => "native_authority",
            Self::TrustVerification(_) => "trust_verification",
            Self::RecordPersistence(_) => "record_persistence",
        }
    }
}

impl std::fmt::Display for ApprovalPublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NativeAuthority(reason)
            | Self::TrustVerification(reason)
            | Self::RecordPersistence(reason) => f.write_str(reason),
        }
    }
}

/// Build the [`InstallPlanDigest`] for a prepared plan: gather every binding input
/// the plan carries (artifact hashes, normalised packages, interpreter, target env,
/// platform tags, install-command semantics, redacted policy hash, DB sequence,
/// capsule backend, required coverage, expiry).
#[allow(clippy::too_many_arguments)]
fn build_plan_digest(
    plan: &DigestInstallPlan,
    resolved: &ResolvedSet,
    target: &InstallTarget,
    tools: &BoundResolverTools,
    policy: &Policy,
    capsule_backend: &str,
    expiry: String,
    task_gate_binding: String,
) -> InstallPlanDigest {
    let artifact_sha256: Vec<String> = resolved
        .artifacts
        .iter()
        .map(|a| a.sha256.clone())
        .collect();
    let normalized_packages = installed_distribution_names(resolved);
    let platform_tags = wheel_platform_tags(resolved);
    // The install-command semantics: the pinned argv WITHOUT the per-run approved.txt
    // path. A dummy InstallCommand suffices since the path is dropped anyway.
    let install_command_semantics = InstallCommand {
        approved_requirements_path: PathBuf::from("approved.txt"),
        target_environment: target.environment.clone(),
    }
    .pip_install_args_without_requirements_path();

    InstallPlanDigest::new(InstallPlanInputs {
        artifact_sha256,
        normalized_packages,
        interpreter: target.interpreter.clone(),
        interpreter_sha256: tools.python_sha256().to_string(),
        resolver: tools.uv().path().to_path_buf(),
        resolver_sha256: tools.uv_sha256().to_string(),
        resolver_version: tools.uv_version().to_string(),
        package_manager_version: tools.pip_version().to_string(),
        pip_tree_root: tools.pip_tree().root().to_path_buf(),
        pip_tree_sha256: tools.pip_tree().sha256().to_string(),
        pip_tree_binding_version: PIP_TREE_BINDING_VERSION,
        pip_tree_max_files: PIP_TREE_MAX_FILES,
        pip_tree_max_bytes: PIP_TREE_MAX_BYTES,
        pip_tree_max_file_bytes: PIP_TREE_MAX_FILE_BYTES,
        pip_tree_max_path_bytes: PIP_TREE_MAX_PATH_BYTES,
        pip_tree_files: tools.pip_tree().files(),
        pip_tree_bytes: tools.pip_tree().bytes(),
        target_environment: target.environment.clone(),
        target_parent_identity: target.binding.parent_identity(),
        target_component: target.binding.target_component().to_string(),
        platform_tags,
        install_command_semantics,
        policy_projection_hash: policy.enforcement_projection_hash(),
        threat_db_sequence: plan.bound_db_sequence,
        capsule_backend: capsule_backend.to_string(),
        required_coverage: plan.spec.required_coverage(),
        task_gate_binding,
        expiry,
    })
}

/// The sorted, de-duplicated platform tags of the resolved wheels (the third,
/// dash-joined field of a `name-version-pytag-abitag-platformtag.whl` filename). A
/// wheel with no parseable tag contributes nothing. Bound into the digest so an
/// approval for one platform's wheels does not authorise another's.
fn wheel_platform_tags(resolved: &ResolvedSet) -> Vec<String> {
    let mut tags: Vec<String> = resolved
        .artifacts
        .iter()
        .filter_map(|a| platform_tag_of(&a.wheel_filename))
        .collect();
    tags.sort();
    tags.dedup();
    tags
}

/// Extract the `{pytag}-{abitag}-{platformtag}` compatibility tag from a wheel
/// filename. A wheel is `{distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl`;
/// the last three dash-separated fields before `.whl` are the compatibility tag.
/// Returns `None` for a filename that does not have at least the 5 required fields.
fn platform_tag_of(filename: &str) -> Option<String> {
    let stem = filename.strip_suffix(".whl")?;
    let parts: Vec<&str> = stem.split('-').collect();
    // distribution, version, [build], python, abi, platform => at least 5 fields.
    if parts.len() < 5 {
        return None;
    }
    let n = parts.len();
    Some(format!(
        "{}-{}-{}",
        parts[n - 3],
        parts[n - 2],
        parts[n - 1]
    ))
}

/// A fresh, path-safe transaction id derived from the current time + a random
/// suffix, so concurrent installs do not collide on a transaction directory.
fn new_transaction_id() -> String {
    let now = chrono::Utc::now().format("%Y%m%dT%H%M%S");
    let rnd: u32 = rand_u32();
    format!("pkg-{now}-{rnd:08x}")
}

/// A small non-crypto random for the transaction id suffix (uniqueness, not
/// security; the quarantine is content-addressed). Uses the process + time so a
/// dependency on a RNG crate is unnecessary.
fn rand_u32() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    nanos ^ (std::process::id().wrapping_mul(2654435761))
}

/// Why preparing a plan failed. Each maps to a fail-closed refusal (no installable
/// plan is produced).
enum PrepareError {
    Resolver(ResolverError),
    Quarantine(QuarantineError),
    Install(InstallError),
    Authorization(String),
}

impl std::fmt::Display for PrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrepareError::Resolver(e) => write!(f, "resolve failed: {e}"),
            PrepareError::Quarantine(e) => write!(f, "quarantine error: {e}"),
            PrepareError::Install(e) => write!(f, "{e}"),
            PrepareError::Authorization(reason) => write!(f, "task authorization failed: {reason}"),
        }
    }
}

// ---------------------------------------------------------------------------
// resolver tool enrollment
// ---------------------------------------------------------------------------

fn run_trust_tool(path: &Path, json: bool) -> i32 {
    match enroll_resolver_tool(path) {
        Ok(canonical) => {
            if json {
                let out = serde_json::json!({
                    "trusted": true,
                    "canonical_path": canonical.display().to_string(),
                    "binding": "sha256",
                });
                let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), &out);
                println!();
            } else {
                eprintln!(
                    "tirith pkg trust-tool: enrolled canonical path + SHA-256 for {}",
                    canonical.display()
                );
            }
            0
        }
        Err(error) => {
            eprintln!("tirith pkg trust-tool: {error}");
            1
        }
    }
}

// ---------------------------------------------------------------------------
// C12: the owned package transitions
// ---------------------------------------------------------------------------

/// Construct the exact package operation that both authorization and the
/// eventual side-effect API bind. Package behavior comes from
/// [`tirith_core::task::ProposedAction::PackageInstall`]; the approval boundary
/// adds only the transition-owned PolicyChange caused by publishing a durable
/// authorization grant.
fn package_boundary_operation<B: BoundaryMarker>(
    envelope: &tirith_core::task::TaskEnvelopeInput,
) -> BoundaryOperation<'_> {
    let boundary_effects =
        if B::BOUNDARY == tirith_core::task_boundary::OwnedBoundary::PackageApproval {
            // The approval record is a durable authorization grant consumed by a
            // later install, not merely an incidental file. PackageInstall
            // inference supplies PersistenceChange; this boundary-owned effect
            // additionally lets policy classify the grant as a policy change.
            [tirith_core::effects::CommandEffectKind::PolicyChange]
                .into_iter()
                .collect()
        } else {
            Default::default()
        };
    BoundaryOperation {
        boundary: B::BOUNDARY,
        envelope,
        // An argv identifies no origin. Claiming one would be a lie the
        // provenance model exists to prevent.
        adapter: tirith_core::task::IngressAdapter::Unattributed,
        boundary_effects,
    }
}

/// Prepare a typed authorization for a locally derived package operation. No
/// schema-v2 provider exists on this compatibility path, so a policy that
/// requires provenance fails closed before a pending permit can be returned.
fn prepare_package_boundary_authorization<B: BoundaryMarker>(
    operation: &BoundaryOperation<'_>,
    policy: &Policy,
) -> Result<PendingBoundaryAuthorization<B>, BoundaryAuthorizationError> {
    let authorization =
        tirith_core::task_boundary::prepare_locally_derived_boundary_authorization::<B>(
            operation,
            &policy.task_gate,
            &TaskAnalysisContext::default(),
        );
    let assessment = match &authorization {
        Ok(pending) => Some(pending.assessment()),
        Err(error) => error.assessment(),
    };
    if let Some(assessment) = assessment {
        if let Err(error) = tirith_core::audit::log_task_boundary_assessment(assessment) {
            tirith_core::audit::audit_diagnostic(format!(
                "task-boundary audit append failed: {error}"
            ));
        }
    }
    authorization
}

/// Report a task-gate refusal on a `pkg` subcommand.
fn report_task_gate_refusal(
    command: &str,
    assessment: &tirith_core::task_boundary::BoundaryAssessment,
    reason: &str,
    json: bool,
) -> i32 {
    if json {
        let out = serde_json::json!({
            "refused": true,
            "stage": "task_gate",
            "boundary": assessment.boundary.token(),
            "reason": reason,
            "task_decision": assessment.projection(),
        });
        let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), &out);
        println!();
    } else {
        eprintln!("tirith pkg {command}: refused before any network or install step: {reason}");
    }
    1
}

fn report_task_authorization_error(
    command: &str,
    boundary: tirith_core::task_boundary::OwnedBoundary,
    error: &BoundaryAuthorizationError,
    json: bool,
) -> i32 {
    if let Some(assessment) = error.assessment() {
        let reason = assessment
            .refusal(false)
            .unwrap_or("task boundary authorization was refused");
        return report_task_gate_refusal(command, assessment, reason, json);
    }
    let reason = error.to_string();
    if json {
        let out = serde_json::json!({
            "refused": true,
            "stage": "task_gate",
            "boundary": boundary.token(),
            "reason": reason,
        });
        let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), &out);
        println!();
    } else {
        eprintln!("tirith pkg {command}: refused before any network or install step: {reason}");
    }
    1
}

// ---------------------------------------------------------------------------
// pkg approve
// ---------------------------------------------------------------------------

fn report_approve_error(phase: &'static str, reason: &str, json: bool, exit_code: i32) -> i32 {
    if json {
        let value = approve_error_json(phase, reason);
        let _ = write_json_document(std::io::stdout().lock(), &value);
    } else {
        let reason = crate::cli::sanitize_for_human_output(reason, false);
        eprintln!("tirith pkg approve: {reason}");
    }
    exit_code
}

fn approve_error_json(phase: &'static str, reason: &str) -> serde_json::Value {
    serde_json::json!({
        "success": false,
        "command": "approve",
        "error_phase": phase,
        "target_executed": false,
        "target_published": false,
        "reason": reason,
    })
}

fn report_approve_authorization_error(error: &BoundaryAuthorizationError, json: bool) -> i32 {
    let reason = error
        .assessment()
        .and_then(|assessment| assessment.refusal(false))
        .map(str::to_string)
        .unwrap_or_else(|| error.to_string());
    report_approve_error("task_gate", &reason, json, 1)
}

fn run_approve(
    ecosystem: Ecosystem,
    requirements: &[String],
    target: Option<PathBuf>,
    index_url: &[String],
    artifact_origin: &[String],
    json: bool,
) -> i32 {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return report_approve_error(
            "native_authority",
            "blocked_native: package approvals are redeemable only on x86_64 Linux",
            json,
            1,
        );
    }
    if let Some(failure) = precheck(ecosystem, requirements) {
        return report_approve_error("precheck", &failure.reason, json, failure.exit_code);
    }
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    // Enforcement uses the full discovered policy, including configured remote
    // sources. A remote refusal must happen before resolver or quarantine work.
    let policy = discover_pkg_enforcement_policy(cwd.as_deref());
    let request = match validated_resolver_request(requirements, index_url, artifact_origin) {
        Ok(request) => request,
        Err(error) => {
            return report_approve_error("request_validation", &error.to_string(), json, 1);
        }
    };
    let target_binding = match bind_install_target(target) {
        Ok(binding) => binding,
        Err(error) => {
            return report_approve_error(
                "target_binding",
                &format!("unsafe install target: {error}"),
                json,
                1,
            );
        }
    };

    // C12: derive a non-cloneable authorization for the exact approval
    // operation. `approve` has no separate human gate, so RequireApproval is a
    // typed refusal. A provenance requirement also refuses because this local
    // argv path has no schema-v2 receipt provider.
    let target_identity = target_binding.package_target_identity();
    let package_binding = PackageOperationBinding::new(
        ecosystem.label(),
        &request,
        artifact_origin,
        &target_identity,
    );
    let envelope = match tirith_core::task_boundary::package_envelope(&package_binding) {
        Ok(envelope) => envelope,
        Err(error) => {
            return report_approve_error("operation_binding", &error.to_string(), json, 1);
        }
    };
    let operation = package_boundary_operation::<PackageApprovalBoundary>(&envelope);
    let pending = match prepare_package_boundary_authorization::<PackageApprovalBoundary>(
        &operation, &policy,
    ) {
        Ok(pending) => pending,
        Err(error) => return report_approve_authorization_error(&error, json),
    };
    let task_gate_binding =
        tirith_core::task_boundary::ceiling_binding(&pending.assessment().decision);
    // Replay state (when a future v2 provider supplies it) is consumed at the
    // last possible point before PATH lookup, quarantine creation, DNS, or a
    // resolver child. Receipt-less decisions do not open the replay ledger.
    if !pending.binds_operation(&operation) {
        return report_approve_authorization_error(
            &BoundaryAuthorizationError::EnvelopeMismatch,
            json,
        );
    }
    let permit = match pending.consume_default_for_operation(&operation, chrono::Utc::now()) {
        Ok(permit) => permit,
        Err(error) => return report_approve_authorization_error(&error, json),
    };

    let approval = match AuthorizedPackageApprovalTransaction::new(permit, envelope) {
        Ok(approval) => approval,
        Err(error) => {
            return report_approve_error("approval_transaction", &error.to_string(), json, 1);
        }
    };
    let prepared = match approval.prepare(
        ecosystem.label(),
        &request,
        target_binding,
        artifact_origin,
        &policy,
        String::new(),
        task_gate_binding,
    ) {
        Ok(prepared) => prepared,
        Err(error) => return report_approve_error("plan_preparation", &error.to_string(), json, 1),
    };

    let approval_projection =
        match tirith_core::package_approval::package_approval_plan_projection(prepared.digest()) {
            Ok(projection) => projection,
            Err(error) => {
                return report_approve_error("plan_preparation", &error.to_string(), json, 1)
            }
        };
    // Keep stdout machine-stable in JSON mode, but always render the exact
    // canonical plan to the operator channel. The privileged helper renders
    // these same bytes independently before it can sign.
    eprintln!("tirith pkg approve: exact plan awaiting privileged confirmation:");
    eprintln!("{approval_projection}");

    // The typed approval transaction survives resolver/quarantine work and is
    // consumed only by the final durable grant publication.
    match prepared.publish() {
        Ok((prepared, path)) => {
            if json {
                let out = serde_json::json!({
                    "approved": true,
                    "plan_digest": prepared.digest.plan_digest,
                    "artifact_set_label": prepared.digest.artifact_set_label(),
                    "packages": prepared.digest.normalized_packages,
                    "interpreter": prepared.digest.interpreter,
                    "target_environment": prepared.digest.target_environment,
                    "threat_db_sequence": prepared.digest.threat_db_sequence,
                    "capsule_backend": prepared.digest.capsule_backend,
                    "expiry": prepared.digest.expiry,
                    "record_path": path.display().to_string(),
                });
                let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), &out);
                println!();
            } else {
                eprintln!("tirith pkg approve: approved install plan");
                eprintln!("  plan digest:  {}", prepared.digest.plan_digest);
                eprintln!("  artifacts:    {}", prepared.digest.artifact_set_label());
                eprintln!(
                    "  packages:     {}",
                    prepared.digest.normalized_packages.join(", ")
                );
                eprintln!("  interpreter:  {}", prepared.digest.interpreter);
                eprintln!("  target env:   {}", prepared.digest.target_environment);
                eprintln!("  DB sequence:  {}", prepared.digest.threat_db_sequence);
                eprintln!("  capsule:      {}", prepared.digest.capsule_backend);
                eprintln!("  expires:      {}", prepared.digest.expiry);
                eprintln!(
                    "  run: tirith pkg install {} --target {} {}",
                    ecosystem.label(),
                    prepared.target.environment.display(),
                    requirements.join(" ")
                );
            }
            0
        }
        Err(error) => report_approve_error(error.phase(), &error.to_string(), json, 1),
    }
}

// ---------------------------------------------------------------------------
// pkg install
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn run_install(
    ecosystem: Ecosystem,
    requirements: &[String],
    target: Option<PathBuf>,
    index_url: &[String],
    artifact_origin: &[String],
    yes: bool,
    allow_degraded: bool,
    json: bool,
) -> i32 {
    if let Some(failure) = precheck(ecosystem, requirements) {
        return report_pkg_precheck_failure("install", &failure, json);
    }
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    let policy = discover_pkg_enforcement_policy(cwd.as_deref());
    let request = match validated_resolver_request(requirements, index_url, artifact_origin) {
        Ok(request) => request,
        Err(error) => {
            return report_install_failure(
                "plan_preparation",
                &error.to_string(),
                false,
                false,
                json,
                1,
            );
        }
    };
    let target_binding = match bind_install_target(target) {
        Ok(binding) => binding,
        Err(error) => {
            return report_install_failure(
                "target_binding",
                &format!("unsafe install target: {error}"),
                false,
                false,
                json,
                1,
            );
        }
    };

    // An install's digest is NOT time-boxed by itself (the install happens now); the
    // approval record it must match carries the expiry. So the install builds the
    // digest with no expiry and looks for a matching approval (whose own expiry is
    // checked). This keeps "the bytes/situation I am about to install" stable while
    // the approval governs the time window.
    // C12: same typed network-egress transition, before the resolver runs. This
    // local argv path has no v2 authorization provider, so provenance-required
    // policy fails closed here rather than silently falling back to assessment.
    let target_identity = target_binding.package_target_identity();
    let package_binding = PackageOperationBinding::new(
        ecosystem.label(),
        &request,
        artifact_origin,
        &target_identity,
    );
    let envelope = match tirith_core::task_boundary::package_envelope(&package_binding) {
        Ok(envelope) => envelope,
        Err(error) => {
            return report_install_failure(
                "task_authorization",
                &error.to_string(),
                false,
                false,
                json,
                1,
            );
        }
    };
    let resolve_operation = package_boundary_operation::<PackageResolveBoundary>(&envelope);
    let pending_resolve = match prepare_package_boundary_authorization::<PackageResolveBoundary>(
        &resolve_operation,
        &policy,
    ) {
        Ok(pending) => pending,
        Err(error) => {
            return report_task_authorization_error(
                "install",
                tirith_core::task_boundary::OwnedBoundary::PackageResolve,
                &error,
                json,
            );
        }
    };
    let task_gate_binding =
        tirith_core::task_boundary::ceiling_binding(&pending_resolve.assessment().decision);
    if !pending_resolve.binds_operation(&resolve_operation) {
        return report_task_authorization_error(
            "install",
            tirith_core::task_boundary::OwnedBoundary::PackageResolve,
            &BoundaryAuthorizationError::EnvelopeMismatch,
            json,
        );
    }
    let resolve_permit = match pending_resolve
        .consume_default_for_operation(&resolve_operation, chrono::Utc::now())
    {
        Ok(permit) => permit,
        Err(error) => {
            return report_task_authorization_error(
                "install",
                tirith_core::task_boundary::OwnedBoundary::PackageResolve,
                &error,
                json,
            );
        }
    };

    let prepared = match prepare_plan_authorized(
        resolve_permit,
        ecosystem.label(),
        &request,
        target_binding,
        artifact_origin,
        &policy,
        String::new(),
        task_gate_binding,
    ) {
        Ok(p) => p,
        Err(e) => {
            return report_install_failure(
                "plan_preparation",
                &e.to_string(),
                false,
                false,
                json,
                1,
            );
        }
    };

    let envelope = match tirith_core::task_boundary::package_install_plan_envelope(&prepared.digest)
    {
        Ok(envelope) => envelope,
        Err(error) => {
            return report_install_failure(
                "task_authorization",
                &error.to_string(),
                false,
                false,
                json,
                1,
            );
        }
    };

    let preparation_operation =
        package_boundary_operation::<PackageInstallPreparationBoundary>(&envelope);
    // C12: derive the policy decision before selecting an approval channel.
    // `--yes` remains the package command's unattended business confirmation,
    // but it can never satisfy a task-policy RequireApproval decision. Only an
    // authentic schema-v2 native-authority record can mint that typed channel.
    let pending_preparation = match prepare_package_boundary_authorization::<
        PackageInstallPreparationBoundary,
    >(&preparation_operation, &policy)
    {
        Ok(pending) => pending,
        Err(error) => {
            return report_task_authorization_error(
                "install",
                tirith_core::task_boundary::OwnedBoundary::PackageInstallPreparation,
                &error,
                json,
            );
        }
    };
    let preparation_denied_effects = pending_preparation.assessment().enforced_denied_effects();
    let pending_preparation = if yes {
        match accept_unattended_preparation(pending_preparation) {
            Ok(pending) => pending,
            Err(error) => {
                return report_task_authorization_error(
                    "install",
                    tirith_core::task_boundary::OwnedBoundary::PackageInstallPreparation,
                    &error,
                    json,
                )
            }
        }
    } else {
        let verified = match approval_status(&prepared.digest) {
            ApprovalStatus::Valid(approval) => *approval,
            ApprovalStatus::Missing => {
                return report_install_failure(
                    "approval",
                    &format!(
                        "no authentic matching approval for plan {}; run `tirith pkg approve {} {}` first, or pass --yes only when task policy does not require approval",
                        prepared.digest.plan_digest,
                        ecosystem.label(),
                        requirements.join(" ")
                    ),
                    false,
                    false,
                    json,
                    1,
                );
            }
            ApprovalStatus::Expired => {
                return report_install_failure(
                    "approval",
                    &format!(
                        "the signed approval for plan {} has expired; re-run `tirith pkg approve`",
                        prepared.digest.plan_digest
                    ),
                    false,
                    false,
                    json,
                    1,
                );
            }
            ApprovalStatus::BlockedNative(reason) => {
                return report_install_failure("approval", &reason, false, false, json, 1);
            }
        };
        let approval_channel = match PackageInstallApprovalChannel::from_native_authority(
            verified,
            &preparation_operation,
        ) {
            Ok(approval) => approval,
            Err(error) => {
                return report_task_authorization_error(
                    "install",
                    tirith_core::task_boundary::OwnedBoundary::PackageInstallPreparation,
                    &error,
                    json,
                );
            }
        };
        match pending_preparation.with_package_install_approval(approval_channel) {
            Ok(pending) => pending,
            Err(error) => {
                return report_task_authorization_error(
                    "install",
                    tirith_core::task_boundary::OwnedBoundary::PackageInstallPreparation,
                    &error,
                    json,
                );
            }
        }
    };
    // The contained install (D4) always fails closed. `--allow-degraded` remains a
    // compatibility flag but cannot weaken the enforcing package path; analysis-only
    // execution is a separate command.
    let degraded_policy = if allow_degraded {
        DegradedPolicy::AllowDegraded
    } else {
        DegradedPolicy::FailClosed
    };

    let installed_distributions = installed_distribution_identities(&prepared.resolved);
    if !pending_preparation.binds_operation(&preparation_operation) {
        return report_task_authorization_error(
            "install",
            tirith_core::task_boundary::OwnedBoundary::PackageInstallPreparation,
            &BoundaryAuthorizationError::EnvelopeMismatch,
            json,
        );
    }
    let preparation_permit = match pending_preparation
        .consume_default_for_operation(&preparation_operation, chrono::Utc::now())
    {
        Ok(permit) => permit,
        Err(error) => {
            return report_task_authorization_error(
                "install",
                tirith_core::task_boundary::OwnedBoundary::PackageInstallPreparation,
                &error,
                json,
            );
        }
    };
    // Atomically create and retain the new dedicated target before pip gets write
    // access. The narrow journal remains live through RECORD verification and
    // mandatory signed-receipt recording; every safely recoverable failed gate
    // removes only this newly created target.
    let mut environment_checkpoint = match EnvironmentCheckpoint::begin_authorized(
        &prepared.target.binding,
        preparation_permit,
        ecosystem.label(),
        &request,
        artifact_origin,
    ) {
        Ok(checkpoint) => checkpoint,
        Err(e) => {
            return report_install_failure(
                "target_checkpoint",
                &format!(
                    "cannot checkpoint target environment {}: {e}; refusing before pip runs",
                    prepared.target.environment.display()
                ),
                false,
                false,
                json,
                1,
            );
        }
    };
    let authorized_launch = match environment_checkpoint.take_authorized_launch() {
        Ok(launch) => launch,
        Err(error) => {
            let rollback = environment_checkpoint.rollback();
            return report_install_failure(
                "target_capability",
                &format!(
                    "cannot retain exact target capability: {error}; rollback result: {rollback:?}"
                ),
                false,
                environment_checkpoint.publication_crossed(),
                json,
                1,
            );
        }
    };
    let outcome = match run_contained_install_with_policy(
        &prepared.plan,
        &prepared.txn,
        &prepared.tools,
        &prepared.target.environment,
        authorized_launch,
        &installed_distributions,
        &policy,
        json,
        degraded_policy,
        &preparation_denied_effects,
    ) {
        Ok(o) => o,
        Err(e) => {
            if matches!(
                &e,
                ContainedInstallError::CapsuleExecutedTerminated {
                    termination: capsule::CapsuleTermination {
                        cleanup_confirmed: false,
                        ..
                    },
                    ..
                }
            ) {
                // The target definitely executed and its process tree is not proven
                // gone. Do not let Drop delete or rename files underneath a possibly
                // live process; retain the fail-closed journal for manual recovery.
                std::mem::forget(environment_checkpoint);
                report_contained_install_error(&e, json);
                return 1;
            }
            if let Err(rollback_error) = environment_checkpoint.rollback() {
                return report_install_failure(
                    "rollback_after_contained_failure",
                    &format!(
                        "{e}; failed to remove private target environment {}: {rollback_error}",
                        prepared.target.environment.display()
                    ),
                    matches!(e, ContainedInstallError::CapsuleExecutedTerminated { .. }),
                    environment_checkpoint.publication_crossed(),
                    json,
                    1,
                );
            }
            report_contained_install_error(&e, json);
            return 1;
        }
    };

    // The redacted resolver / package-manager provenance for the receipt. The
    // command strings carry only the flags, never an index credential (the resolver
    // already refuses creds-in-URL; we record the fixed command shape).
    let provenance = ResolverProvenance {
        resolver_command: "uv pip compile --generate-hashes --no-build".to_string(),
        resolver_version: prepared.tools.uv_version().to_string(),
        package_manager_version: prepared.tools.pip_version().to_string(),
    };
    let artifact_sha256: Vec<String> = prepared
        .resolved
        .artifacts
        .iter()
        .map(|a| a.sha256.clone())
        .collect();

    // The finalised install verdict the receipt attests: the post-install RECORD
    // verdict when the install ran to completion, else a synthesized Block (a failed
    // install did not produce a trustworthy environment).
    let verdict = enforcing_install_verdict(&outcome);

    // D6 phase 1: while the target is still private and rollback-safe, record a
    // signed receipt for the exact contained execution + RECORD verdict. This is
    // deliberately NOT publication proof.
    let private_receipt =
        build_install_receipt(&outcome, &policy, &provenance, artifact_sha256, &verdict);
    let private_receipt_id = private_receipt.receipt_id.clone();
    let private_recorded = private_receipt.record_private_signed();
    let private_report = InstallReport::from_recorded_ref(
        &outcome,
        private_recorded.as_ref().map(|proof| proof.recorded()),
        false,
    );

    if !private_report.ready_for_publication() {
        if let Err(rollback_error) = environment_checkpoint.rollback() {
            return report_install_transaction_failure(
                "private_rollback",
                &format!(
                    "failed to remove the private target after an enforcing gate failed: {rollback_error}"
                ),
                environment_checkpoint.publication_crossed(),
                &private_receipt_id,
                None,
                "private_verified",
                json,
            );
        }
        return report_install_outcome(
            &prepared.digest,
            &outcome,
            private_recorded.map(|proof| proof.into_recorded()),
            false,
            json,
        );
    }
    let private_recorded = match private_recorded {
        Ok(proof) => proof,
        Err(error) => {
            // `ready_for_publication` above rejects every receipt error. Retain a
            // defensive fail-closed branch in case that reporting invariant ever
            // changes.
            let _ = environment_checkpoint.rollback();
            return report_install_outcome(&prepared.digest, &outcome, Err(error), false, json);
        }
    };

    // D6 phase 2: publish the exact held private target with NOREPLACE, verify its
    // public identity, fsync the parent, and durably mark it published-but-awaiting
    // its linked receipt. A pre-rename failure is rollback-safe; any post-rename
    // failure remains PublishedUnconfirmed and must never be auto-rolled back.
    if let Err(publish_error) = environment_checkpoint.publish_verified() {
        let crossed = environment_checkpoint.publication_crossed();
        let rollback_detail = if crossed {
            String::new()
        } else {
            match environment_checkpoint.rollback() {
                Ok(()) => "; private rollback confirmed".to_string(),
                Err(error) => format!("; private rollback was not confirmed: {error}"),
            }
        };
        return report_install_transaction_failure(
            "target_publication",
            &format!("{publish_error}{rollback_detail}"),
            crossed,
            &private_receipt_id,
            None,
            "private_verified",
            json,
        );
    }

    let committed_receipt = match private_recorded.prepare_committed() {
        Ok(receipt) => receipt,
        Err(error) => {
            return report_install_transaction_failure(
                "committed_receipt_build",
                &error.to_string(),
                true,
                &private_receipt_id,
                None,
                "private_verified",
                json,
            )
        }
    };
    let committed_receipt_id = committed_receipt.receipt_id().to_string();
    let committed_recorded = match committed_receipt.record_signed() {
        Ok(recorded) => recorded,
        Err(error) => {
            return report_install_transaction_failure(
                "committed_receipt",
                &error.to_string(),
                true,
                &private_receipt_id,
                Some(&committed_receipt_id),
                "private_verified",
                json,
            )
        }
    };

    // Only the linked, signed committed receipt lets the checkpoint transition
    // from PublishedUnconfirmed to Committed and release its recovery journal.
    let committed_recorded = match environment_checkpoint.confirm_committed(committed_recorded) {
        Ok(recorded) => Ok(recorded),
        Err(error) => {
            return report_install_transaction_failure(
                "commit_confirmation",
                &error.to_string(),
                true,
                &private_receipt_id,
                Some(&committed_receipt_id),
                "committed",
                json,
            )
        }
    };

    report_install_outcome(&prepared.digest, &outcome, committed_recorded, true, json)
}

/// Compatibility wrapper for the historical `--allow-degraded` flag. Enforcing
/// package installs now always use the same capability-bound, fail-closed D4/D5
/// path; the flag cannot select an uncontained execution branch.
#[allow(clippy::too_many_arguments)]
fn run_contained_install_with_policy(
    plan: &DigestInstallPlan,
    transaction: &QuarantineTransaction,
    tools: &BoundResolverTools,
    target_environment: &Path,
    authorized_launch: AuthorizedInstallLaunch,
    installed_distributions: &[ExpectedInstalledDistribution],
    policy: &Policy,
    json: bool,
    degraded_policy: DegradedPolicy,
    task_denied_effects: &std::collections::BTreeSet<tirith_core::effects::CommandEffectKind>,
) -> Result<crate::cli::pkg_install::ContainedInstallOutcome, ContainedInstallError> {
    let _ = degraded_policy;
    run_contained_install(
        plan,
        transaction,
        tools,
        target_environment,
        authorized_launch,
        installed_distributions,
        policy,
        json,
        task_denied_effects,
    )
}

fn report_contained_install_error(error: &ContainedInstallError, json: bool) {
    if !json {
        eprintln!("tirith pkg install: {error}");
        return;
    }
    let value = contained_install_error_json(error);
    let _ = write_json_document(std::io::stdout().lock(), &value);
}

fn contained_install_error_json(error: &ContainedInstallError) -> serde_json::Value {
    match error {
        ContainedInstallError::CapsuleRefused { backend_id, reason } => serde_json::json!({
            "success": false,
            "error_phase": "refused_before_exec",
            "target_executed": false,
            "backend": backend_id,
            "reason": reason,
        }),
        ContainedInstallError::CapsuleExecutedTerminated {
            backend_id,
            termination,
        } => serde_json::json!({
            "success": false,
            "error_phase": "executed_then_terminated",
            "target_executed": true,
            "backend": backend_id,
            "termination_kind": format!("{:?}", termination.kind),
            "reason": termination.reason,
            "cleanup_confirmed": termination.cleanup_confirmed,
        }),
        other => serde_json::json!({
            "success": false,
            "error_phase": "pre_exec_input_binding",
            "target_executed": false,
            "reason": other.to_string(),
        }),
    }
}

fn install_failure_json(
    phase: &'static str,
    reason: &str,
    target_executed: bool,
    target_published: bool,
) -> serde_json::Value {
    serde_json::json!({
        "success": false,
        "error_phase": phase,
        "target_executed": target_executed,
        "target_published": target_published,
        "reason": reason,
    })
}

#[allow(clippy::too_many_arguments)]
fn report_install_failure(
    phase: &'static str,
    reason: &str,
    target_executed: bool,
    target_published: bool,
    json: bool,
    exit_code: i32,
) -> i32 {
    if json {
        let value = install_failure_json(phase, reason, target_executed, target_published);
        let _ = write_json_document(std::io::stdout().lock(), &value);
    } else {
        eprintln!(
            "tirith pkg install: {}: {}",
            crate::cli::sanitize_for_human_output(phase, false),
            crate::cli::sanitize_for_human_output(reason, false)
        );
    }
    exit_code
}

/// Emit one terminal-safe human diagnostic or one parseable JSON document for a
/// checkpoint/receipt failure after the contained target has executed. Child
/// output is suppressed in JSON mode, so this remains the command's sole stdout
/// document even when pip produced arbitrary bytes.
#[allow(clippy::too_many_arguments)]
fn report_install_transaction_failure(
    phase: &'static str,
    reason: &str,
    target_published: bool,
    private_receipt_id: &str,
    committed_receipt_id: Option<&str>,
    receipt_publication_state: &'static str,
    json: bool,
) -> i32 {
    if json {
        let value = serde_json::json!({
            "success": false,
            "error_phase": phase,
            "target_executed": true,
            "target_published": target_published,
            "receipt_publication_state": receipt_publication_state,
            "private_receipt_id": private_receipt_id,
            "committed_receipt_id": committed_receipt_id,
            "reason": reason,
        });
        let _ = write_json_document(std::io::stdout().lock(), &value);
    } else {
        eprintln!(
            "tirith pkg install: {}: {}",
            crate::cli::sanitize_for_human_output(phase, false),
            crate::cli::sanitize_for_human_output(reason, false)
        );
        eprintln!(
            "  publication: {}",
            if target_published {
                "published but not fully confirmed; recovery journal retained"
            } else {
                "not published"
            }
        );
        eprintln!("  private receipt: {private_receipt_id}");
        if let Some(receipt_id) = committed_receipt_id {
            eprintln!("  committed receipt: {receipt_id}");
        }
    }
    1
}

/// A synthesized Block verdict for a `pkg install` whose pip run exited non-zero:
/// there is no trustworthy installed environment, so the install is reported as
/// blocked in the receipt even though no rule fired.
fn failed_install_verdict(exit_code: i32) -> tirith_core::verdict::Verdict {
    use tirith_core::verdict::{Action, Timings, Verdict};
    let _ = exit_code;
    Verdict {
        action: Action::Block,
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

/// The receipt must attest the enforcing result, not merely the policy severity of
/// an individual RECORD finding. Missing distributions, missing RECORD files, hash
/// mismatches, and zero verified distributions are all incomplete verification and
/// therefore Block for `pkg install`.
fn enforcing_install_verdict(
    outcome: &crate::cli::pkg_install::ContainedInstallOutcome,
) -> tirith_core::verdict::Verdict {
    let Some(post) = outcome.post_install.as_ref() else {
        return failed_install_verdict(outcome.exit_code);
    };
    let mut verdict = post.verdict.clone();
    if outcome.exit_code != 0 || !post.is_complete() || post.hash_mismatches > 0 {
        verdict.action = tirith_core::verdict::Action::Block;
    }
    verdict
}

/// The honest, redaction-safe projection of an install outcome + receipt status that
/// both the human banner and the `--json` output are rendered from. Built purely from
/// the outcome and the receipt record so it is unit-testable without capturing stderr
/// (the IM7/IM8 fixes live here): the install-completed-but-not-fully-verified wording
/// (RECORD hash mismatches / missing RECORDs) and the receipt anchor state (signed /
/// tamper-evident / saved-but-unanchored) are decided once, here.
struct InstallReport {
    install_ok: bool,
    post_blocked: bool,
    publication_committed: bool,
    success: bool,
    /// RECORD-listed files whose on-disk bytes did not match (the install-time tamper
    /// signal). `hash_mismatches > 0` makes the enforcing install fail closed (IM8), so a
    /// `success` install always carries 0 here; the count is still surfaced (in JSON and
    /// on the failure path) for the audit trail.
    hash_mismatches: usize,
    /// Expected distributions that could not be located at all. Any non-zero value
    /// means no integrity claim can be made for those packages.
    distributions_not_found: usize,
    /// Located distributions whose RECORD was actually checked.
    distributions_verified: usize,
    /// Located distributions with no RECORD file (a coverage gap).
    records_missing: usize,
    receipt_path: Option<String>,
    /// Whether the receipt's audit-chain anchor was ed25519-SIGNED.
    signed: bool,
    /// `Some(reason)` when the receipt was SAVED but its chain anchor could NOT be
    /// appended (the unsigned Windows degrade): the receipt is NOT tamper-evident-
    /// chained, so the banner must not claim it is.
    anchor_warning: Option<String>,
    receipt_error: Option<String>,
}

impl InstallReport {
    fn from_outcome(
        outcome: &crate::cli::pkg_install::ContainedInstallOutcome,
        recorded: &Result<
            tirith_core::receipt::RecordedReceipt,
            tirith_core::receipt::ReceiptError,
        >,
        publication_committed: bool,
    ) -> Self {
        Self::from_recorded_ref(outcome, recorded.as_ref(), publication_committed)
    }

    fn from_recorded_ref(
        outcome: &crate::cli::pkg_install::ContainedInstallOutcome,
        recorded: Result<
            &tirith_core::receipt::RecordedReceipt,
            &tirith_core::receipt::ReceiptError,
        >,
        publication_committed: bool,
    ) -> Self {
        let install_ok = outcome.exit_code == 0;
        let post_blocked = outcome
            .post_install
            .as_ref()
            .map(|p| p.is_block() || !p.is_complete() || p.hash_mismatches > 0)
            .unwrap_or(false);
        let hash_mismatches = outcome
            .post_install
            .as_ref()
            .map(|p| p.hash_mismatches)
            .unwrap_or(0);
        let records_missing = outcome
            .post_install
            .as_ref()
            .map(|p| p.records_missing)
            .unwrap_or(0);
        let distributions_not_found = outcome
            .post_install
            .as_ref()
            .map(|p| p.distributions_not_found)
            .unwrap_or(0);
        let distributions_verified = outcome
            .post_install
            .as_ref()
            .map(|p| p.distributions_verified)
            .unwrap_or(0);
        // The enforcing path requires complete proof, not merely the absence of a
        // policy-level Block. A clean pip exit with zero located distributions is not
        // verification, and neither is a located distribution whose RECORD is absent.
        let verification_complete = outcome
            .post_install
            .as_ref()
            .is_some_and(|post| post.is_complete() && post.hash_mismatches == 0);
        let receipt_signed = recorded.is_ok_and(|receipt| receipt.signed);
        let success = install_ok
            && !post_blocked
            && receipt_signed
            && verification_complete
            && publication_committed;
        let (receipt_path, signed, anchor_warning, receipt_error) = match recorded {
            Ok(r) if r.signed => (
                Some(r.path.display().to_string()),
                true,
                r.anchor_warning.clone(),
                None,
            ),
            Ok(r) => (
                Some(r.path.display().to_string()),
                false,
                r.anchor_warning.clone(),
                Some("mandatory install receipt was not signed".to_string()),
            ),
            Err(e) => (None, false, None, Some(e.to_string())),
        };
        InstallReport {
            install_ok,
            post_blocked,
            publication_committed,
            success,
            hash_mismatches,
            distributions_not_found,
            distributions_verified,
            records_missing,
            receipt_path,
            signed,
            anchor_warning,
            receipt_error,
        }
    }

    /// Whether the post-install RECORD check found no tamper signal and no coverage
    /// gap. Only a clean check earns the word "verified" (IM8).
    fn record_integrity_clean(&self) -> bool {
        self.distributions_verified > 0
            && self.distributions_not_found == 0
            && self.hash_mismatches == 0
            && self.records_missing == 0
    }

    /// Every enforcing gate that must pass while the checkpoint is still private.
    /// Publication is deliberately excluded so callers can decide whether to cross
    /// the irreversible rename only after the signed private receipt exists.
    fn ready_for_publication(&self) -> bool {
        self.install_ok
            && !self.post_blocked
            && self.signed
            && self.receipt_error.is_none()
            && self.record_integrity_clean()
    }

    fn to_json(
        &self,
        digest: &InstallPlanDigest,
        outcome: &crate::cli::pkg_install::ContainedInstallOutcome,
    ) -> serde_json::Value {
        serde_json::json!({
            "installed": self.install_ok,
            "post_install_blocked": self.post_blocked,
            "plan_digest": digest.plan_digest,
            "exit_code": outcome.exit_code,
            "capsule_backend": outcome.backend_id,
            "coverage": outcome.coverage_summary,
            "target_executed": true,
            "target_published": self.publication_committed,
            "receipt_publication_state": if self.publication_committed { "committed" } else { "private_verified" },
            "capsule_termination_kind": outcome.termination.as_ref().map(|termination| format!("{:?}", termination.kind)),
            "capsule_termination_reason": outcome.termination.as_ref().map(|termination| termination.reason.as_str()),
            "capsule_cleanup_confirmed": outcome.termination.as_ref().map(|termination| termination.cleanup_confirmed),
            "receipt_path": self.receipt_path,
            "receipt_signed": self.signed,
            "receipt_anchor_warning": self.anchor_warning,
            "receipt_error": self.receipt_error,
            "record_hash_mismatches": self.hash_mismatches,
            "record_distributions_verified": self.distributions_verified,
            "record_distributions_not_found": self.distributions_not_found,
            "record_records_missing": self.records_missing,
            "success": self.success,
        })
    }
}

/// Serialize exactly one JSON value followed by one newline. Keeping JSON output
/// behind a writer seam lets the package-install regression prove that arbitrary
/// contained-child bytes cannot create a second document or corrupt this one.
fn write_json_document(
    mut writer: impl std::io::Write,
    value: &serde_json::Value,
) -> std::io::Result<()> {
    serde_json::to_writer_pretty(&mut writer, value).map_err(std::io::Error::other)?;
    writer.write_all(b"\n")
}

/// Report the install outcome + receipt status, returning the process exit code.
fn report_install_outcome(
    digest: &InstallPlanDigest,
    outcome: &crate::cli::pkg_install::ContainedInstallOutcome,
    recorded: Result<tirith_core::receipt::RecordedReceipt, tirith_core::receipt::ReceiptError>,
    publication_committed: bool,
    json: bool,
) -> i32 {
    let report = InstallReport::from_outcome(outcome, &recorded, publication_committed);

    if json {
        let out = report.to_json(digest, outcome);
        let _ = write_json_document(std::io::stdout().lock(), &out);
    } else if report.success {
        // A successful enforcing install necessarily has complete RECORD coverage,
        // no mismatch, a signed linked receipt, and confirmed publication.
        debug_assert!(report.record_integrity_clean());
        debug_assert!(report.signed);
        debug_assert!(report.publication_committed);
        eprintln!("tirith pkg install: install complete and verified");
        eprintln!("  plan digest: {}", digest.plan_digest);
        eprintln!("  capsule:     {}", outcome.backend_id);
        eprintln!("  coverage:    {}", outcome.coverage_summary);
        // Word the receipt line from the REAL anchor state: signed > tamper-evident >
        // saved-but-unanchored. An anchor_warning means the chain anchor never landed,
        // so the receipt is not tamper-evident-chained.
        match &report.anchor_warning {
            Some(reason) => eprintln!(
                "  receipt:     {} (saved but NOT audit-anchored: {reason})",
                report.receipt_path.as_deref().unwrap_or("<unsaved>")
            ),
            None => eprintln!(
                "  receipt:     {} ({})",
                report.receipt_path.as_deref().unwrap_or("<unsaved>"),
                if report.signed {
                    "signed"
                } else {
                    "tamper-evident"
                }
            ),
        }
    } else {
        eprintln!("tirith pkg install: install did NOT complete cleanly");
        if !report.install_ok {
            eprintln!("  pip exit code: {}", outcome.exit_code);
        }
        if let Some(termination) = &outcome.termination {
            eprintln!(
                "  capsule terminated the executed target: {} (cleanup confirmed={})",
                termination.reason, termination.cleanup_confirmed
            );
        }
        if report.post_blocked {
            eprintln!("  post-install RECORD verification blocked the install");
        }
        if report.hash_mismatches > 0 {
            eprintln!(
                "  post-install RECORD integrity violation: {} installed file(s) do not match \
                 the RECORD pip wrote (install-time tampering); refusing (fail closed)",
                report.hash_mismatches
            );
        }
        if report.distributions_not_found > 0 {
            eprintln!(
                "  post-install verification incomplete: {} expected distribution(s) were not found; refusing (fail closed)",
                report.distributions_not_found
            );
        }
        if report.records_missing > 0 {
            eprintln!(
                "  post-install verification incomplete: {} distribution(s) had no RECORD; refusing (fail closed)",
                report.records_missing
            );
        }
        if report.distributions_verified == 0 {
            eprintln!(
                "  post-install verification checked zero distributions; refusing (fail closed)"
            );
        }
        if let Some(err) = &report.receipt_error {
            eprintln!("  receipt: {err}");
        }
    }

    if report.success {
        0
    } else {
        1
    }
}

// ---------------------------------------------------------------------------
// pkg verify-env
// ---------------------------------------------------------------------------

fn run_verify_env(target: &Path, packages: &[String], json: bool) -> i32 {
    if packages.is_empty() {
        eprintln!(
            "tirith pkg verify-env: no package names given. \
             try: tirith pkg verify-env --target .venv requests flask"
        );
        return 2;
    }
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    let policy = Policy::discover_local_only(cwd.as_deref());

    // Normalise the given names with the SAME PEP 503 normaliser the install scope
    // uses, so a name spelled differently than the on-disk dist-info still matches.
    let names: Vec<String> = packages
        .iter()
        .map(|p| tirith_core::artifact::normalize_project_name_public(p))
        .collect();

    let result = verify_post_install_record(target, &names, &policy);
    let incomplete = !result.is_complete();
    let blocked = result.is_block() || incomplete;
    let effective_action = if incomplete {
        tirith_core::verdict::Action::Block
    } else {
        result.verdict.action
    };

    if json {
        let out = serde_json::json!({
            "target": target.display().to_string(),
            "blocked": blocked,
            "verification_incomplete": incomplete,
            "distributions_verified": result.distributions_verified,
            "distributions_not_found": result.distributions_not_found,
            "records_missing": result.records_missing,
            "hash_mismatches": result.hash_mismatches,
            "action": format!("{effective_action:?}"),
            "rule_ids": result
                .verdict
                .findings
                .iter()
                .map(|f| f.rule_id.to_string())
                .collect::<Vec<_>>(),
        });
        let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), &out);
        println!();
    } else {
        eprintln!("tirith pkg verify-env: {}", target.display());
        eprintln!("  verified:    {}", result.distributions_verified);
        eprintln!("  not found:   {}", result.distributions_not_found);
        eprintln!("  no RECORD:   {}", result.records_missing);
        eprintln!("  mismatches:  {}", result.hash_mismatches);
        eprintln!("  verdict:     {effective_action:?}");
        if blocked {
            eprintln!("  the installed environment FAILED complete RECORD integrity verification");
        }
    }

    if blocked {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// pkg receipt
// ---------------------------------------------------------------------------

fn run_receipt(which: ReceiptQuery, json: bool) -> i32 {
    match which {
        ReceiptQuery::List => match ArtifactScanReceipt::list() {
            Ok(receipts) => {
                if json {
                    let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), &receipts);
                    println!();
                } else if receipts.is_empty() {
                    eprintln!("tirith pkg receipt: no artifact-scan receipts found");
                } else {
                    for r in &receipts {
                        print_receipt_summary(r);
                    }
                }
                0
            }
            Err(e) => {
                eprintln!("tirith pkg receipt: {e}");
                1
            }
        },
        ReceiptQuery::Last => match ArtifactScanReceipt::list() {
            Ok(receipts) => match receipts.first() {
                Some(r) => {
                    print_receipt_full(r, json);
                    0
                }
                None => {
                    eprintln!("tirith pkg receipt: no artifact-scan receipts found");
                    1
                }
            },
            Err(e) => {
                eprintln!("tirith pkg receipt: {e}");
                1
            }
        },
        ReceiptQuery::Show(id) => match ArtifactScanReceipt::load(&id) {
            Ok(r) => {
                print_receipt_full(&r, json);
                // A content-hash mismatch means the saved file was edited.
                if !r.content_hash_matches() {
                    eprintln!(
                        "  WARNING: this receipt's stored id does not match its content \
                         (the file may have been edited)"
                    );
                    return 1;
                }
                0
            }
            Err(e) => {
                eprintln!("tirith pkg receipt: {e}");
                1
            }
        },
    }
}

fn print_receipt_summary(r: &ArtifactScanReceipt) {
    eprintln!(
        "  {} {} {} {} artifact(s) {}",
        tirith_core::receipt::short_hash(&r.receipt_id),
        r.verdict.action,
        r.capsule.backend_id,
        r.artifact_sha256.len(),
        r.timestamp
    );
}

fn print_receipt_full(r: &ArtifactScanReceipt, json: bool) {
    if json {
        let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), r);
        println!();
        return;
    }
    eprintln!("tirith pkg receipt: {}", r.receipt_id);
    eprintln!("  schema:        {}", r.schema);
    eprintln!("  tirith:        {}", r.tirith_version);
    eprintln!("  engine SHA:    {}", r.engine_build_sha);
    eprintln!("  policy hash:   {}", r.policy_hash);
    eprintln!("  DB sequence:   {}", r.threat_db_sequence);
    eprintln!("  resolver:      {}", r.resolver_command);
    eprintln!("  capsule:       {}", r.capsule.backend_id);
    eprintln!("  artifacts:     {}", r.artifact_sha256.len());
    eprintln!("  verdict:       {}", r.verdict.action);
    eprintln!("  when:          {}", r.timestamp);
    eprintln!(
        "  content valid: {}",
        if r.content_hash_matches() {
            "yes"
        } else {
            "NO (edited?)"
        }
    );
}

// ---------------------------------------------------------------------------
// approval record persistence
// ---------------------------------------------------------------------------

/// Publish a schema-v2 signed record atomically (0600), consuming the exact
/// typed permit at the write API itself. The surrounding transaction keeps this
/// permit live across resolver/quarantine and native-authority work.
fn persist_approval_record_authorized(
    record: &PackageApprovalRecordV2,
    permit: TaskBoundaryPermit<PackageApprovalBoundary>,
    operation: &BoundaryOperation<'_>,
    trusted_keys: &std::collections::BTreeMap<String, [u8; 32]>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<PathBuf, String> {
    permit
        .authorize_effect_at(operation, now)
        .map_err(|error| format!("task authorization expired before publication: {error}"))?;
    with_approval_store_lock(|dir| {
        let path = persist_approval_record_bytes_unlocked(record, dir)?;
        collect_expired_approval_records_unlocked(dir, trusted_keys, now);
        Ok(path)
    })
}

#[cfg(test)]
fn persist_approval_record_bytes(record: &PackageApprovalRecordV2) -> Result<PathBuf, String> {
    with_approval_store_lock(|dir| persist_approval_record_bytes_unlocked(record, dir))
}

fn persist_approval_record_bytes_unlocked(
    record: &PackageApprovalRecordV2,
    dir: &Path,
) -> Result<PathBuf, String> {
    let requested = expiry_independent_plan(record.digest()).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{}.json", requested.plan_digest));
    let json = record
        .to_json_pretty()
        .map_err(|e| format!("serialize: {e}"))?;
    tirith_core::util::write_file_atomic_0600(&path, json.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    Ok(path)
}

fn with_approval_store_lock<T>(f: impl FnOnce(&Path) -> Result<T, String>) -> Result<T, String> {
    let dir = approvals_dir().ok_or("cannot determine approvals directory")?;
    tirith_core::util::create_dir_durable(&dir).map_err(|e| format!("create dir: {e}"))?;
    let lock_path = dir.join(".approval-store.lock");
    let mut options = std::fs::OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let lock = options
        .open(&lock_path)
        .map_err(|error| format!("open approval-store lock: {error}"))?;
    lock.lock_exclusive()
        .map_err(|error| format!("lock approval store: {error}"))?;
    let result = f(&dir);
    let _ = fs2::FileExt::unlock(&lock);
    result
}

/// Best-effort, bounded garbage collection. A file is removed only after its
/// signed record verifies under the native trust roots as an expired approval,
/// and only when its filename matches the expiry-independent requested plan.
/// Malformed, untrusted, or concurrently changed records are never deleted.
fn collect_expired_approval_records_unlocked(
    dir: &Path,
    trusted_keys: &std::collections::BTreeMap<String, [u8; 32]>,
    now: chrono::DateTime<chrono::Utc>,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.take(MAX_PERSISTED_APPROVAL_RECORDS) {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let Ok(destination) = tirith_core::util::ContainedAtomicFile::prepare(dir, &path, false)
        else {
            continue;
        };
        let Ok(content) = destination.read_capped(128 * 1024) else {
            continue;
        };
        let Ok(record) = PackageApprovalRecordV2::from_json(&content) else {
            continue;
        };
        let Ok(requested) = expiry_independent_plan(record.digest()) else {
            continue;
        };
        if path.file_name().and_then(|name| name.to_str())
            != Some(&format!("{}.json", requested.plan_digest))
        {
            continue;
        }
        if matches!(
            verify_package_approval(&record, &requested, trusted_keys, now),
            Err(PackageApprovalError::Expired)
        ) {
            let _ = destination.remove_if_contents(&content);
        }
    }
}

#[cfg(test)]
fn load_approval_record(plan_digest: &str) -> Option<PackageApprovalRecordV2> {
    let dir = approvals_dir()?;
    let path = dir.join(format!("{plan_digest}.json"));
    let mut file = tirith_core::util::open_read_no_follow_capped(&path, 128 * 1024).ok()?;
    let mut content = Vec::new();
    file.read_to_end(&mut content).ok()?;
    PackageApprovalRecordV2::from_json(&content).ok()
}

/// The directory persisted approvals live in.
fn approvals_dir() -> Option<PathBuf> {
    tirith_core::policy::data_dir().map(|d| d.join("approvals"))
}

/// The authorisation state of an install plan against the persisted approvals.
enum ApprovalStatus {
    /// A matching, fresh approval signed by the native authority exists.
    Valid(Box<VerifiedPackageApproval>),
    /// No approval record matches this plan digest.
    Missing,
    /// A matching record exists but it has expired.
    Expired,
    /// The platform-native authority or its admin-protected trust hierarchy is
    /// unavailable. There is deliberately no weaker fallback.
    BlockedNative(String),
}

/// Decide whether `digest` (the plan about to run) is authorised by a saved
/// approval. The install builds its digest with NO expiry, so the lookup keys on the
/// install digest's `plan_digest`, and the SAVED record's expiry is what gates the
/// time window.
fn approval_status(digest: &InstallPlanDigest) -> ApprovalStatus {
    approval_status_with(digest, &NativePackageApprovalAuthority, chrono::Utc::now())
}

fn approval_status_with(
    digest: &InstallPlanDigest,
    key_provider: &dyn PackageApprovalKeyProvider,
    now: chrono::DateTime<chrono::Utc>,
) -> ApprovalStatus {
    let trusted_keys = match key_provider.trusted_keys() {
        Ok(keys) => keys,
        Err(error) => return ApprovalStatus::BlockedNative(error.to_string()),
    };
    let Some(dir) = approvals_dir() else {
        return ApprovalStatus::BlockedNative(
            "blocked_native: cannot determine the package approval store".to_string(),
        );
    };
    let requested = match expiry_independent_plan(digest) {
        Ok(requested) => requested,
        Err(_) => return ApprovalStatus::Missing,
    };
    let path = dir.join(format!("{}.json", requested.plan_digest));
    let mut file = match tirith_core::util::open_read_no_follow_capped(&path, 128 * 1024) {
        Ok(file) => file,
        Err(tirith_core::util::OpenRegularError::NotFound) => {
            return ApprovalStatus::Missing;
        }
        Err(_) => {
            return ApprovalStatus::BlockedNative(
                "blocked_native: package approval record could not be read safely".to_string(),
            );
        }
    };
    let mut content = Vec::new();
    if file.read_to_end(&mut content).is_err() {
        return ApprovalStatus::BlockedNative(
            "blocked_native: package approval record changed while reading".to_string(),
        );
    }
    let Ok(record) = PackageApprovalRecordV2::from_json(&content) else {
        return ApprovalStatus::Missing;
    };
    match verify_package_approval(&record, &requested, &trusted_keys, now) {
        Ok(approval) => ApprovalStatus::Valid(Box::new(approval)),
        Err(PackageApprovalError::Expired) => ApprovalStatus::Expired,
        Err(_) => ApprovalStatus::Missing,
    }
}

fn accept_unattended_preparation(
    pending: PendingBoundaryAuthorization<PackageInstallPreparationBoundary>,
) -> Result<
    PendingBoundaryAuthorization<PackageInstallPreparationBoundary>,
    BoundaryAuthorizationError,
> {
    if pending.requires_approval() {
        Err(BoundaryAuthorizationError::ApprovalRequired)
    } else {
        Ok(pending)
    }
}

/// Whether two plan digests bind the SAME install situation ignoring the expiry
/// field. The install builds its digest with no expiry; the approval record carries
/// one; everything else must match exactly for the approval to authorise the
/// install.
///
/// Compared by blanking the two excluded fields and leaning on the derived
/// `PartialEq`, NOT by enumerating the binding fields here. A hand-written list
/// silently stops covering a field the moment [`InstallPlanDigest`] grows one,
/// and that is exactly how `task_gate_binding` came to be written into the
/// digest and never checked when an approval was redeemed. A field added in
/// future is therefore bound by default; the failure direction if it should not
/// have been is a re-approval, not an unbound install.
#[cfg(test)]
fn same_plan_modulo_expiry(a: &InstallPlanDigest, b: &InstallPlanDigest) -> bool {
    // `plan_digest` is derived from every other field, so comparing it would be
    // circular; `expiry` is the one binding input the install deliberately does
    // not carry.
    let situation = |digest: &InstallPlanDigest| {
        let mut copy = digest.clone();
        copy.plan_digest.clear();
        copy.expiry.clear();
        copy
    };
    situation(a) == situation(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_harness::{EnvGuard, ENV_LOCK};
    use tirith_core::capsule::CapsuleSpec;

    #[test]
    fn approve_failures_share_one_stable_json_dto() {
        for phase in [
            "precheck",
            "request_validation",
            "target_binding",
            "operation_binding",
            "task_gate",
            "approval_transaction",
            "plan_preparation",
            "native_authority",
            "trust_verification",
            "record_persistence",
        ] {
            let value = approve_error_json(phase, "refused");
            assert_eq!(value["success"], false);
            assert_eq!(value["command"], "approve");
            assert_eq!(value["error_phase"], phase);
            assert_eq!(value["target_executed"], false);
            assert_eq!(value["target_published"], false);
            assert_eq!(value["reason"], "refused");
            assert_eq!(value.as_object().unwrap().len(), 6);
        }
    }

    /// A digest for tests, with a given expiry, built from fixed inputs so two
    /// digests differ only where a test changes them.
    fn plan_inputs_with_expiry(expiry: &str) -> InstallPlanInputs {
        InstallPlanInputs {
            artifact_sha256: vec!["a".repeat(64)],
            normalized_packages: vec!["requests".to_string()],
            interpreter: PathBuf::from("/venv/bin/python"),
            interpreter_sha256: "b".repeat(64),
            resolver: PathBuf::from("/usr/bin/uv"),
            resolver_sha256: "c".repeat(64),
            resolver_version: "uv 1.2.3".to_string(),
            package_manager_version: "24.0".to_string(),
            pip_tree_root: PathBuf::from("/usr/lib/python3/site-packages/pip"),
            pip_tree_sha256: "d".repeat(64),
            pip_tree_binding_version: PIP_TREE_BINDING_VERSION,
            pip_tree_max_files: PIP_TREE_MAX_FILES,
            pip_tree_max_bytes: PIP_TREE_MAX_BYTES,
            pip_tree_max_file_bytes: PIP_TREE_MAX_FILE_BYTES,
            pip_tree_max_path_bytes: PIP_TREE_MAX_PATH_BYTES,
            pip_tree_files: 100,
            pip_tree_bytes: 10_000,
            target_environment: PathBuf::from("/venv"),
            target_parent_identity: "linux-devino-v1:1:2".to_string(),
            target_component: "venv".to_string(),
            platform_tags: vec!["py3-none-any".to_string()],
            install_command_semantics: InstallCommand {
                approved_requirements_path: PathBuf::from("approved.txt"),
                target_environment: PathBuf::from("/venv"),
            }
            .pip_install_args_without_requirements_path(),
            policy_projection_hash: "deadbeef".repeat(8),
            threat_db_sequence: 3,
            capsule_backend: "landlock-seccomp".to_string(),
            required_coverage: CapsuleSpec::locked_down().required_coverage(),
            task_gate_binding: "task_gate:v1:mode=off;denied=".to_string(),
            expiry: expiry.to_string(),
        }
    }

    fn digest_with_expiry(expiry: &str) -> InstallPlanDigest {
        InstallPlanDigest::new(plan_inputs_with_expiry(expiry))
    }

    struct TestAuthority {
        signing_key: ed25519_dalek::SigningKey,
    }

    impl TestAuthority {
        fn new() -> Self {
            Self {
                signing_key: ed25519_dalek::SigningKey::from_bytes(&[73_u8; 32]),
            }
        }

        fn record(&self, digest: &InstallPlanDigest) -> PackageApprovalRecordV2 {
            let (digest, issued, expires) = if digest.expiry.is_empty() {
                let issued = chrono::Utc::now();
                let expires = issued + chrono::Duration::minutes(30);
                let mut stamped = digest.clone();
                stamped.expiry = expires.to_rfc3339();
                stamped.plan_digest = stamped.compute_plan_digest();
                (stamped, issued, expires)
            } else {
                let expires = chrono::DateTime::parse_from_rfc3339(&digest.expiry)
                    .unwrap()
                    .with_timezone(&chrono::Utc);
                let issued = expires - chrono::Duration::minutes(30);
                (digest.clone(), issued, expires)
            };
            PackageApprovalRecordV2::issue(
                digest,
                &issued.to_rfc3339(),
                &expires.to_rfc3339(),
                &self.signing_key,
            )
            .unwrap()
        }
    }

    impl PackageApprovalIssuer for TestAuthority {
        fn issue(
            &self,
            digest: &InstallPlanDigest,
        ) -> Result<PackageApprovalRecordV2, NativeAuthorityError> {
            Ok(self.record(digest))
        }
    }

    impl PackageApprovalKeyProvider for TestAuthority {
        fn trusted_keys(
            &self,
        ) -> Result<std::collections::BTreeMap<String, [u8; 32]>, NativeAuthorityError> {
            let public = self.signing_key.verifying_key().to_bytes();
            let key_id = tirith_core::command_card::key_id_for_pubkey(&public);
            Ok(std::collections::BTreeMap::from([(key_id, public)]))
        }
    }

    fn save_signed_for_test(digest: &InstallPlanDigest) -> Result<PathBuf, String> {
        persist_approval_record_bytes(&TestAuthority::new().record(digest))
    }

    fn approval_status_for_test(digest: &InstallPlanDigest) -> ApprovalStatus {
        let now = chrono::DateTime::parse_from_rfc3339("2098-12-31T23:59:59Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        approval_status_with(digest, &TestAuthority::new(), now)
    }

    fn test_package_envelope(requirements: &[String]) -> tirith_core::task::TaskEnvelopeInput {
        let request = ResolverRequest {
            requirements: requirements.to_vec(),
            index_urls: Vec::new(),
            allowances: Default::default(),
        };
        let target = tirith_core::task_boundary::PackageTargetIdentity::new(
            "ab".repeat(32),
            "linux-devino-v1:1:2",
            "target",
        );
        let binding = PackageOperationBinding::new(Ecosystem::Pip.label(), &request, &[], &target);
        tirith_core::task_boundary::package_envelope(&binding).unwrap()
    }

    fn package_ceiling<B: BoundaryMarker>(requirements: &[String], policy: &Policy) -> String {
        let envelope = test_package_envelope(requirements);
        let operation = package_boundary_operation::<B>(&envelope);
        let pending = prepare_package_boundary_authorization::<B>(&operation, policy).unwrap();
        tirith_core::task_boundary::ceiling_binding(&pending.assessment().decision)
    }

    #[test]
    fn locally_derived_pkg_authorization_fails_closed_when_provenance_is_required() {
        let requirements = ["requests==2.31.0".to_string()];
        let envelope = test_package_envelope(&requirements);
        let operation = package_boundary_operation::<PackageResolveBoundary>(&envelope);
        let policy = Policy {
            task_gate: tirith_core::web3_policy::TaskGatePolicy {
                mode: tirith_core::web3_policy::TaskGateMode::Enforce,
                effects_requiring_verified_provenance: [
                    tirith_core::effects::CommandEffectKind::NetworkEgress,
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            },
            ..Policy::default()
        };

        assert!(matches!(
            prepare_package_boundary_authorization::<PackageResolveBoundary>(&operation, &policy),
            Err(BoundaryAuthorizationError::SchemaV2Required)
        ));
    }

    #[test]
    fn remote_policy_failure_denies_pkg_before_any_package_side_effect() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let root = tempfile::tempdir().unwrap();
        let policy_dir = root.path().join(".tirith");
        std::fs::create_dir_all(&policy_dir).unwrap();
        std::fs::write(
            policy_dir.join("policy.yaml"),
            "policy_fetch_fail_mode: closed\n",
        )
        .unwrap();
        let data_dir = root.path().join("data");
        let _guards = [
            EnvGuard::set("TIRITH_POLICY_ROOT", root.path()),
            EnvGuard::set("TIRITH_SERVER_URL", Path::new("http://127.0.0.1:1")),
            EnvGuard::set("TIRITH_API_KEY", Path::new("test-only-key")),
            EnvGuard::set("XDG_DATA_HOME", &data_dir),
        ];
        let policy = discover_pkg_enforcement_policy(root.path().to_str());
        assert_eq!(policy.path.as_deref(), Some("fail-closed"));

        let envelope = test_package_envelope(&["requests==2.31.0".to_string()]);
        let operation = package_boundary_operation::<PackageResolveBoundary>(&envelope);
        assert!(
            prepare_package_boundary_authorization::<PackageResolveBoundary>(&operation, &policy,)
                .is_err()
        );
        assert!(!approvals_dir().unwrap().exists());
    }

    #[test]
    fn unattended_yes_cannot_satisfy_task_policy_require_approval() {
        let requirements = ["requests==2.31.0".to_string()];
        let mut envelope = test_package_envelope(&requirements);
        envelope
            .actions
            .push(tirith_core::task::ProposedAction::Narrative {
                text: "intentionally incomplete package preparation".to_string(),
            });
        let operation = package_boundary_operation::<PackageInstallPreparationBoundary>(&envelope);
        let policy = Policy {
            task_gate: tirith_core::web3_policy::TaskGatePolicy {
                mode: tirith_core::web3_policy::TaskGateMode::Enforce,
                action_incomplete_analysis:
                    tirith_core::web3_policy::Web3GuardAction::RequireApproval,
                ..Default::default()
            },
            ..Policy::default()
        };
        let pending = prepare_package_boundary_authorization::<PackageInstallPreparationBoundary>(
            &operation, &policy,
        )
        .unwrap();
        assert!(pending.requires_approval());
        assert!(matches!(
            accept_unattended_preparation(pending),
            Err(BoundaryAuthorizationError::ApprovalRequired)
        ));
    }

    #[test]
    fn package_approval_denied_persistence_never_creates_a_grant_record() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _guards = isolate(root.path());
        let requirements = ["requests==2.31.0".to_string()];
        let envelope = test_package_envelope(&requirements);
        let operation = package_boundary_operation::<PackageApprovalBoundary>(&envelope);
        assert!(operation
            .boundary_effects
            .contains(&tirith_core::effects::CommandEffectKind::PolicyChange));
        let policy = Policy {
            task_gate: tirith_core::web3_policy::TaskGatePolicy {
                mode: tirith_core::web3_policy::TaskGateMode::Enforce,
                effects_denied_for_untrusted_sources: [
                    tirith_core::effects::CommandEffectKind::PersistenceChange,
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            },
            ..Policy::default()
        };

        let error = match prepare_package_boundary_authorization::<PackageApprovalBoundary>(
            &operation, &policy,
        ) {
            Ok(_) => panic!("persistence denial unexpectedly authorized an approval record"),
            Err(error) => error,
        };
        let assessment = error.assessment().expect("denial assessment");
        assert!(assessment
            .decision
            .inferred_effects
            .contains(&tirith_core::effects::CommandEffectKind::PersistenceChange));
        assert!(assessment
            .decision
            .inferred_effects
            .contains(&tirith_core::effects::CommandEffectKind::PolicyChange));
        assert!(!approvals_dir().unwrap().exists());
    }

    #[test]
    fn package_approval_transaction_rejects_a_changed_package_set() {
        let approved_envelope = test_package_envelope(&["requests==2.31.0".to_string()]);
        let approved_operation =
            package_boundary_operation::<PackageApprovalBoundary>(&approved_envelope);
        let permit = prepare_package_boundary_authorization::<PackageApprovalBoundary>(
            &approved_operation,
            &Policy::default(),
        )
        .unwrap()
        .consume_default_for_operation(&approved_operation, chrono::Utc::now())
        .unwrap();
        let changed_envelope = test_package_envelope(&["urllib3==2.2.0".to_string()]);

        assert!(matches!(
            AuthorizedPackageApprovalTransaction::new(permit, changed_envelope),
            Err(PrepareError::Authorization(_))
        ));
    }

    #[test]
    fn approval_record_effect_api_rejects_changed_operation_without_writing() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _guards = isolate(root.path());
        let approved_envelope = test_package_envelope(&["requests==2.31.0".to_string()]);
        let approved_operation =
            package_boundary_operation::<PackageApprovalBoundary>(&approved_envelope);
        let permit = prepare_package_boundary_authorization::<PackageApprovalBoundary>(
            &approved_operation,
            &Policy::default(),
        )
        .unwrap()
        .consume_default_for_operation(&approved_operation, chrono::Utc::now())
        .unwrap();
        let changed_envelope = test_package_envelope(&["urllib3==2.2.0".to_string()]);
        let changed_operation =
            package_boundary_operation::<PackageApprovalBoundary>(&changed_envelope);
        let record = TestAuthority::new().record(&digest_with_expiry("2099-01-01T00:00:00+00:00"));

        let trusted_keys = TestAuthority::new().trusted_keys().unwrap();
        assert!(persist_approval_record_authorized(
            &record,
            permit,
            &changed_operation,
            &trusted_keys,
            chrono::Utc::now(),
        )
        .is_err());
        assert!(!approvals_dir().unwrap().exists());
    }

    #[cfg(target_os = "linux")]
    fn resolver_permit(
        request: &ResolverRequest,
        artifact_origins: &[String],
        target: &InstallTargetBinding,
    ) -> TaskBoundaryPermit<PackageResolveBoundary> {
        let target_identity = target.package_target_identity();
        let binding = PackageOperationBinding::new(
            Ecosystem::Pip.label(),
            request,
            artifact_origins,
            &target_identity,
        );
        let envelope = tirith_core::task_boundary::package_envelope(&binding).unwrap();
        let operation = package_boundary_operation::<PackageResolveBoundary>(&envelope);
        prepare_package_boundary_authorization::<PackageResolveBoundary>(
            &operation,
            &Policy::default(),
        )
        .unwrap()
        .consume_default_for_operation(&operation, chrono::Utc::now())
        .unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolver_preparation_reconstructs_and_rejects_an_index_mutation() {
        let root = tempfile::tempdir().unwrap();
        let target_path = root.path().join("target");
        let target = InstallTargetBinding::bind(&target_path).unwrap();
        let original = validated_resolver_request(
            &["demo==1.0".to_string()],
            &["https://index.example/simple".to_string()],
            &[],
        )
        .unwrap();
        let permit = resolver_permit(&original, &[], &target);
        let changed = validated_resolver_request(
            &["demo==1.0".to_string()],
            &["https://other.example/simple".to_string()],
            &[],
        )
        .unwrap();

        let result = prepare_plan_authorized(
            permit,
            Ecosystem::Pip.label(),
            &changed,
            target,
            &[],
            &Policy::default(),
            String::new(),
            String::new(),
        );
        assert!(matches!(result, Err(PrepareError::Authorization(_))));
        assert!(!target_path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolver_preparation_reconstructs_and_rejects_an_artifact_origin_mutation() {
        let root = tempfile::tempdir().unwrap();
        let target_path = root.path().join("target");
        let target = InstallTargetBinding::bind(&target_path).unwrap();
        let request = validated_resolver_request(&["demo==1.0".to_string()], &[], &[]).unwrap();
        let approved_origins = ["https://cdn.example/wheels".to_string()];
        let permit = resolver_permit(&request, &approved_origins, &target);
        let changed_origins = ["https://other.example/wheels".to_string()];

        let result = prepare_plan_authorized(
            permit,
            Ecosystem::Pip.label(),
            &request,
            target,
            &changed_origins,
            &Policy::default(),
            String::new(),
            String::new(),
        );
        assert!(matches!(result, Err(PrepareError::Authorization(_))));
        assert!(!target_path.exists());
    }

    // ── precheck / misplaced-flag guard ─────────────────────────────────────

    #[test]
    fn precheck_refuses_non_pip_ecosystem() {
        assert_eq!(
            precheck(Ecosystem::Npm, &["lodash".to_string()]).map(|failure| failure.exit_code),
            Some(2)
        );
        assert_eq!(
            precheck(Ecosystem::Cargo, &["serde".to_string()]).map(|failure| failure.exit_code),
            Some(2)
        );
    }

    #[test]
    fn precheck_refuses_misplaced_tirith_flag_after_requirements() {
        // A tirith-owned flag trailing the requirement list is a hard error (it would
        // not affect tirith), mirroring `tirith install`'s guard.
        for flag in MISPLACED_TIRITH_FLAGS {
            let reqs = vec!["requests".to_string(), flag.to_string()];
            assert_eq!(
                precheck(Ecosystem::Pip, &reqs).map(|failure| failure.exit_code),
                Some(2),
                "trailing {flag} must be refused"
            );
        }
    }

    #[test]
    fn precheck_refuses_empty_requirements() {
        assert_eq!(
            precheck(Ecosystem::Pip, &[]).map(|failure| failure.exit_code),
            Some(2)
        );
    }

    #[test]
    fn precheck_allows_a_clean_pip_requirement() {
        assert_eq!(
            precheck(Ecosystem::Pip, &["requests==2.31.0".to_string()]),
            None
        );
    }

    // ── platform tag extraction ─────────────────────────────────────────────

    #[test]
    fn platform_tag_of_extracts_the_compat_tag() {
        assert_eq!(
            platform_tag_of("requests-2.31.0-py3-none-any.whl").as_deref(),
            Some("py3-none-any")
        );
        assert_eq!(
            platform_tag_of("numpy-1.26.0-cp311-cp311-manylinux_2_17_x86_64.whl").as_deref(),
            Some("cp311-cp311-manylinux_2_17_x86_64")
        );
        // A build tag is present: still the LAST three fields.
        assert_eq!(
            platform_tag_of("foo-1.0-1-py3-none-any.whl").as_deref(),
            Some("py3-none-any")
        );
        // Too few fields -> None.
        assert_eq!(platform_tag_of("not-a-wheel.whl"), None);
        assert_eq!(platform_tag_of("plainfile.txt"), None);
    }

    // ── approval record persistence + matching ──────────────────────────────

    /// Isolate the data dir so the approvals dir is under a tempdir.
    fn isolate(root: &Path) -> Vec<EnvGuard> {
        vec![
            EnvGuard::set("XDG_DATA_HOME", root),
            EnvGuard::set("XDG_CONFIG_HOME", root),
            EnvGuard::set("XDG_STATE_HOME", root),
            EnvGuard::set("APPDATA", root),
            EnvGuard::set("LOCALAPPDATA", root),
            EnvGuard::set("HOME", root),
            EnvGuard::set("USERPROFILE", root),
        ]
    }

    #[test]
    fn approval_round_trips_and_matches_install_digest() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _g = isolate(root.path());

        // Approve a plan with a far-future expiry.
        let approved = digest_with_expiry("2099-01-01T00:00:00+00:00");
        let path = save_signed_for_test(&approved).unwrap();
        assert!(path.exists());

        // The install builds the SAME situation with NO expiry.
        let install_digest = digest_with_expiry("");
        // The two ids differ (expiry differs) but bind the same situation.
        assert_ne!(approved.plan_digest, install_digest.plan_digest);
        assert!(same_plan_modulo_expiry(&approved, &install_digest));

        // The install is authorised by the saved approval.
        assert!(matches!(
            approval_status_for_test(&install_digest),
            ApprovalStatus::Valid(_)
        ));

        // Loadable directly, too.
        let requested = expiry_independent_plan(&approved).unwrap();
        let loaded = load_approval_record(&requested.plan_digest).unwrap();
        assert_eq!(loaded.digest(), &approved);
        assert!(loaded.digest().digest_matches());
    }

    #[test]
    fn approval_missing_when_no_record() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _g = isolate(root.path());
        let install_digest = digest_with_expiry("");
        assert!(matches!(
            approval_status_for_test(&install_digest),
            ApprovalStatus::Missing
        ));
    }

    #[test]
    fn legacy_unsigned_v1_record_never_authorizes() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _g = isolate(root.path());
        let approved = digest_with_expiry("2099-01-01T00:00:00+00:00");
        let requested = expiry_independent_plan(&approved).unwrap();
        let dir = approvals_dir().unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(format!("{}.json", requested.plan_digest)),
            serde_json::to_vec(&serde_json::json!({ "digest": approved })).unwrap(),
        )
        .unwrap();

        assert!(matches!(
            approval_status_for_test(&digest_with_expiry("")),
            ApprovalStatus::Missing
        ));
    }

    #[test]
    fn approval_expired_is_detected() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _g = isolate(root.path());

        // An already-expired approval.
        let approved = digest_with_expiry("2000-01-01T00:00:00+00:00");
        save_signed_for_test(&approved).unwrap();

        let install_digest = digest_with_expiry("");
        assert!(same_plan_modulo_expiry(&approved, &install_digest));
        assert!(matches!(
            approval_status_for_test(&install_digest),
            ApprovalStatus::Expired
        ));
    }

    #[test]
    fn verified_plan_proof_cannot_authorize_a_relabelled_install_operation() {
        let requested = digest_with_expiry("");
        let authority = TestAuthority::new();
        let record = authority.record(&requested);
        let trusted_keys = authority.trusted_keys().unwrap();
        let verified =
            verify_package_approval(&record, &requested, &trusted_keys, chrono::Utc::now())
                .unwrap();
        let canonical =
            tirith_core::task_boundary::package_install_plan_envelope(&requested).unwrap();
        let mut relabelled = canonical.clone();
        relabelled.actions[0] = tirith_core::task::ProposedAction::PackageInstall {
            ecosystem: "pip".to_string(),
            package: "attacker-controlled".to_string(),
        };
        let relabelled_operation =
            package_boundary_operation::<PackageInstallPreparationBoundary>(&relabelled);

        assert!(matches!(
            PackageInstallApprovalChannel::from_native_authority(verified, &relabelled_operation),
            Err(BoundaryAuthorizationError::ApprovalMismatch)
        ));

        let verified =
            verify_package_approval(&record, &requested, &trusted_keys, chrono::Utc::now())
                .unwrap();
        let canonical_operation =
            package_boundary_operation::<PackageInstallPreparationBoundary>(&canonical);
        PackageInstallApprovalChannel::from_native_authority(verified, &canonical_operation)
            .expect("the exact canonical signed-plan operation must authorize");
    }

    #[test]
    fn renewed_approval_atomically_replaces_the_expiry_independent_key() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _g = isolate(root.path());
        let first = digest_with_expiry("2099-01-01T00:00:00+00:00");
        let second = digest_with_expiry("2099-01-01T00:10:00+00:00");
        let first_path = save_signed_for_test(&first).unwrap();
        let second_path = save_signed_for_test(&second).unwrap();
        assert_eq!(first_path, second_path);
        let requested = expiry_independent_plan(&first).unwrap();
        assert_eq!(
            first_path.file_name().unwrap().to_string_lossy(),
            format!("{}.json", requested.plan_digest)
        );
        let loaded = load_approval_record(&requested.plan_digest).unwrap();
        assert_eq!(loaded.digest(), &second);
        assert_eq!(
            std::fs::read_dir(approvals_dir().unwrap())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
                .count(),
            1
        );
    }

    #[test]
    fn approval_does_not_match_a_different_situation() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _g = isolate(root.path());

        // Approve one situation.
        let approved = digest_with_expiry("2099-01-01T00:00:00+00:00");
        save_signed_for_test(&approved).unwrap();

        // A DIFFERENT install: a different interpreter. Build it by hand.
        let mut other_inputs = plan_inputs_with_expiry("");
        other_inputs.interpreter = PathBuf::from("/attacker/python");
        let other = InstallPlanDigest::new(other_inputs);
        assert!(!same_plan_modulo_expiry(&approved, &other));
        // No matching approval for the changed situation.
        assert!(matches!(
            approval_status_for_test(&other),
            ApprovalStatus::Missing
        ));
    }

    /// The task-gate ceiling is part of the binding, not decoration.
    ///
    /// `approve` records the ceiling that was in force when the human said yes
    /// (`run_approve` -> `ceiling_binding`); `install` re-derives it from the
    /// policy in force at install time (`run_install`). If the operator relaxes
    /// the gate in between, the approval must die. The two strings are built the
    /// way the two commands build them, through a real boundary evaluation, so a
    /// change to what the ceiling means breaks this test rather than sliding past
    /// it.
    #[test]
    fn a_relaxed_task_gate_invalidates_an_approval_taken_under_a_stricter_one() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _g = isolate(root.path());

        let requirements = ["requests==2.31.0".to_string()];
        let enforcing = Policy {
            task_gate: tirith_core::web3_policy::TaskGatePolicy {
                mode: tirith_core::web3_policy::TaskGateMode::Enforce,
                ..Default::default()
            },
            ..Policy::default()
        };
        let approved_under = package_ceiling::<PackageApprovalBoundary>(&requirements, &enforcing);
        let installed_under =
            package_ceiling::<PackageResolveBoundary>(&requirements, &Policy::default());
        assert_ne!(
            approved_under, installed_under,
            "the ceiling must differ, or this test proves nothing"
        );

        let mut approved_inputs = plan_inputs_with_expiry("2099-01-01T00:00:00+00:00");
        approved_inputs.task_gate_binding = approved_under;
        let approved = InstallPlanDigest::new(approved_inputs);
        save_signed_for_test(&approved).unwrap();

        let mut install_inputs = plan_inputs_with_expiry("");
        install_inputs.task_gate_binding = installed_under;
        let install_digest = InstallPlanDigest::new(install_inputs);

        assert!(
            !same_plan_modulo_expiry(&approved, &install_digest),
            "an approval taken under an enforcing gate matched an install under a relaxed one"
        );
        assert!(matches!(
            approval_status_for_test(&install_digest),
            ApprovalStatus::Missing
        ));
    }

    /// The same ceiling still authorises: the check above must not have made
    /// every approval unredeemable.
    #[test]
    fn an_unchanged_task_gate_still_authorises_the_install() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _g = isolate(root.path());

        let approved = digest_with_expiry("2099-01-01T00:00:00+00:00");
        save_signed_for_test(&approved).unwrap();
        assert!(matches!(
            approval_status_for_test(&digest_with_expiry("")),
            ApprovalStatus::Valid(_)
        ));
    }

    #[test]
    fn approval_with_advanced_db_sequence_does_not_match() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _g = isolate(root.path());

        // Approve bound to DB sequence 3.
        let approved = digest_with_expiry("2099-01-01T00:00:00+00:00");
        save_signed_for_test(&approved).unwrap();

        // Install plan now bound to DB sequence 4 (a newer DB) -> not authorised.
        let mut install_inputs = plan_inputs_with_expiry("");
        install_inputs.threat_db_sequence = 4;
        let install_digest = InstallPlanDigest::new(install_inputs);
        assert!(matches!(
            approval_status_for_test(&install_digest),
            ApprovalStatus::Missing
        ));
    }

    #[test]
    fn edited_approval_record_is_rejected() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _g = isolate(root.path());

        // Save a valid approval, then EDIT the saved file to swap the interpreter
        // while leaving the stored plan_digest stale.
        let approved = digest_with_expiry("2099-01-01T00:00:00+00:00");
        let path = save_signed_for_test(&approved).unwrap();
        let mut record: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        record["digest"]["interpreter"] = "/attacker/python".into();
        // Write the tampered record back (stale digest and signature, changed
        // interpreter).
        std::fs::write(&path, serde_json::to_string_pretty(&record).unwrap()).unwrap();

        // The install for the ORIGINAL situation must NOT be authorised: the tampered
        // record fails digest_matches() and is skipped.
        let install_digest = digest_with_expiry("");
        assert!(matches!(
            approval_status_for_test(&install_digest),
            ApprovalStatus::Missing
        ));
    }

    // ── failed-install verdict ──────────────────────────────────────────────

    #[test]
    fn failed_install_verdict_blocks() {
        let v = failed_install_verdict(1);
        assert_eq!(v.action, tirith_core::verdict::Action::Block);
        assert!(v.findings.is_empty());
    }

    #[test]
    fn contained_install_error_json_distinguishes_execution_phase() {
        let refused = ContainedInstallError::CapsuleRefused {
            backend_id: "landlock-seccomp",
            reason: "coverage unavailable".to_string(),
        };
        let refused_json = contained_install_error_json(&refused);
        assert_eq!(refused_json["target_executed"], false);
        assert_eq!(refused_json["error_phase"], "refused_before_exec");

        let executed = ContainedInstallError::CapsuleExecutedTerminated {
            backend_id: "landlock-seccomp",
            termination: capsule::CapsuleTermination {
                kind: capsule::CapsuleTerminationKind::CleanupFailure,
                reason: "tree still live".to_string(),
                cleanup_confirmed: false,
            },
        };
        let executed_json = contained_install_error_json(&executed);
        assert_eq!(executed_json["target_executed"], true);
        assert_eq!(executed_json["error_phase"], "executed_then_terminated");
        assert_eq!(executed_json["cleanup_confirmed"], false);
    }

    #[test]
    fn install_outcome_json_preserves_cleanup_confirmed_termination() {
        let mut outcome = outcome_with_post(128, 0, 0);
        outcome.termination = Some(capsule::CapsuleTermination {
            kind: capsule::CapsuleTerminationKind::WallClock,
            reason: "wall deadline exceeded".to_string(),
            cleanup_confirmed: true,
        });
        let recorded = Err(tirith_core::receipt::ReceiptError::Io(
            std::io::Error::other("not recorded after terminated install"),
        ));
        let report = InstallReport::from_outcome(&outcome, &recorded, true);
        let json = report.to_json(&digest_with_expiry(""), &outcome);
        assert_eq!(json["target_executed"], true);
        assert_eq!(json["capsule_termination_kind"], "WallClock");
        assert_eq!(json["capsule_cleanup_confirmed"], true);
        assert_eq!(json["success"], false);
    }

    // ── install target derivation ───────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn install_target_uses_explicit_target_dir() {
        let parent = tempfile::tempdir().unwrap();
        let requested = parent.path().join("dedicated-target");
        let binding = bind_install_target(Some(requested.clone())).unwrap();
        let t = InstallTarget::from_binding(PathBuf::from("/opt/py/bin/python3"), binding);
        assert_eq!(t.interpreter, PathBuf::from("/opt/py/bin/python3"));
        assert_eq!(
            t.environment,
            parent
                .path()
                .canonicalize()
                .unwrap()
                .join("dedicated-target")
        );
        // The interpreter prefix is a read root.
        assert!(t.extra_read_roots.contains(&PathBuf::from("/opt/py")));
        assert!(!requested.exists(), "derivation must not create the target");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn install_target_never_defaults_to_interpreter_prefix() {
        let error = bind_install_target(None)
            .expect_err("enforcing installs require an explicit dedicated target");
        assert!(error.contains("explicit --target is required"));
    }

    // ── install reporting (IM7 / IM8) ───────────────────────────────────────

    use tirith_core::capsule::CapsuleCoverage;
    use tirith_core::receipt::RecordedReceipt;

    /// A contained-install outcome with a clean post-install RECORD result and a given
    /// exit code, for the reporting tests.
    fn outcome_with_post(
        exit_code: i32,
        hash_mismatches: usize,
        records_missing: usize,
    ) -> crate::cli::pkg_install::ContainedInstallOutcome {
        use tirith_core::artifact::install::PostInstallIntegrity;
        use tirith_core::verdict::{Action, Timings, Verdict};
        let verdict = Verdict {
            // A RECORD mismatch maps to Warn (Medium, uncorroborated) -> not a Block.
            action: Action::Warn,
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
        };
        crate::cli::pkg_install::ContainedInstallOutcome {
            exit_code,
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
                verdict,
                distributions_verified: 1,
                distributions_not_found: 0,
                records_missing,
                hash_mismatches,
            }),
        }
    }

    /// A saved receipt record with the given signed / anchor_warning state.
    fn recorded_ok(signed: bool, anchor_warning: Option<String>) -> RecordedReceipt {
        RecordedReceipt {
            path: PathBuf::from("/data/receipts/abc.json"),
            signed,
            anchor_warning,
        }
    }

    #[test]
    fn install_report_unsigned_anchor_is_surfaced_and_fails_closed() {
        // IM7/D6: an unsigned saved-but-unanchored receipt must not be reported as
        // tamper-evident/chained and cannot authorize publication. The warning and
        // mandatory-signature failure both reach JSON.
        let outcome = outcome_with_post(0, 0, 0);
        let recorded = Ok(recorded_ok(
            false,
            Some("audit log lock unavailable on this platform".to_string()),
        ));
        let report = InstallReport::from_outcome(&outcome, &recorded, true);
        assert!(!report.success);
        assert!(!report.ready_for_publication());
        assert_eq!(
            report.anchor_warning.as_deref(),
            Some("audit log lock unavailable on this platform")
        );

        let digest = digest_with_expiry("");
        let json = report.to_json(&digest, &outcome);
        // The warning is surfaced in JSON, NOT dropped.
        assert_eq!(
            json["receipt_anchor_warning"],
            serde_json::json!("audit log lock unavailable on this platform")
        );
        assert_eq!(json["receipt_signed"], serde_json::json!(false));
        assert_eq!(
            json["receipt_error"],
            serde_json::json!("mandatory install receipt was not signed")
        );
    }

    #[test]
    fn install_report_clean_signed_receipt_has_no_anchor_warning() {
        // The normal path: a signed, fully-anchored, clean-RECORD install.
        let outcome = outcome_with_post(0, 0, 0);
        let recorded = Ok(recorded_ok(true, None));
        let report = InstallReport::from_outcome(&outcome, &recorded, true);
        assert!(report.success);
        assert!(report.signed);
        assert!(report.anchor_warning.is_none());
        assert!(report.record_integrity_clean());
    }

    #[test]
    fn private_verified_report_is_ready_but_cannot_claim_success() {
        let outcome = outcome_with_post(0, 0, 0);
        let recorded = Ok(recorded_ok(true, None));
        let report = InstallReport::from_outcome(&outcome, &recorded, false);

        assert!(report.ready_for_publication());
        assert!(report.record_integrity_clean());
        assert!(!report.publication_committed);
        assert!(!report.success);

        let json = report.to_json(&digest_with_expiry(""), &outcome);
        assert_eq!(json["target_published"], false);
        assert_eq!(json["receipt_publication_state"], "private_verified");
        assert_eq!(json["success"], false);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pkg_json_is_one_document_with_benign_or_hostile_child_streams_suppressed() {
        let cases: &[(&[u8], &[u8], &str)] = &[
            (
                b"PIP_BENIGN_STDOUT_SENTINEL\n",
                b"PIP_BENIGN_STDERR_SENTINEL\n",
                "PIP_BENIGN_",
            ),
            (
                b"PIP_HOSTILE_STDOUT_SENTINEL\x1b]52;c;Zm9yZ2Vk\x07",
                b"PIP_HOSTILE_STDERR_SENTINEL\n",
                "PIP_HOSTILE_",
            ),
        ];

        for &(child_stdout, child_stderr, forbidden_marker) in cases {
            // This is the same suppression/action seam used after the real bounded
            // child is drained: hostile output still changes the typed outcome,
            // while neither hostile nor benign stream bytes are presented.
            let suppressed = capsule::test_suppress_bound_child_output(child_stdout, child_stderr);
            let mut outcome = outcome_with_post(suppressed.exit_code, 0, 0);
            outcome.backend_id = suppressed.backend_id;
            outcome.coverage = suppressed.coverage;
            outcome.termination = suppressed.termination;
            if outcome.exit_code != 0 {
                outcome.post_install = None;
            }

            let recorded = Ok(recorded_ok(true, None));
            let report = InstallReport::from_outcome(&outcome, &recorded, outcome.exit_code == 0);
            let value = report.to_json(&digest_with_expiry(""), &outcome);
            let mut rendered = Vec::new();
            write_json_document(&mut rendered, &value).unwrap();

            let text = String::from_utf8(rendered.clone()).unwrap();
            assert!(
                !text.contains(forbidden_marker),
                "contained child bytes must not enter the JSON envelope"
            );
            let mut documents =
                serde_json::Deserializer::from_slice(&rendered).into_iter::<serde_json::Value>();
            let parsed = documents
                .next()
                .expect("one JSON document")
                .expect("the sole document is parseable");
            assert!(
                documents.next().is_none(),
                "JSON mode must emit exactly one document"
            );
            assert_eq!(parsed, value);
        }
    }

    #[test]
    fn early_pkg_json_failure_is_exactly_one_document() {
        let early = install_failure_json(
            "target_checkpoint",
            "PIP_EARLY_FAILURE_SENTINEL",
            false,
            false,
        );
        let mut rendered = Vec::new();
        write_json_document(&mut rendered, &early).unwrap();
        let mut documents =
            serde_json::Deserializer::from_slice(&rendered).into_iter::<serde_json::Value>();
        assert_eq!(documents.next().unwrap().unwrap(), early);
        assert!(
            documents.next().is_none(),
            "an early --json failure must also be exactly one document"
        );
    }

    #[test]
    fn install_report_record_hash_mismatch_fails_closed() {
        // IM8: a post-install RECORD hash mismatch on the ENFORCING install is install-time
        // tampering (a RECORD-listed file changed after pip wrote RECORD), so the install
        // fails CLOSED (success=false, exit 1) even though the finding is Medium. The count
        // is still surfaced for the audit trail.
        let outcome = outcome_with_post(0, 2, 0);
        let recorded = Ok(recorded_ok(true, None));
        let report = InstallReport::from_outcome(&outcome, &recorded, true);
        assert!(
            !report.success,
            "a RECORD hash mismatch must fail the enforcing install closed (IM8)"
        );
        assert!(!report.record_integrity_clean());

        let digest = digest_with_expiry("");
        let json = report.to_json(&digest, &outcome);
        assert_eq!(json["record_hash_mismatches"], serde_json::json!(2));
        assert_eq!(json["success"], serde_json::json!(false));
    }

    #[test]
    fn install_report_missing_record_fails_closed() {
        // A missing RECORD is incomplete verification. The package may have landed,
        // but an enforcing install must restore the checkpoint rather than call it a
        // success.
        let outcome = outcome_with_post(0, 0, 1);
        let recorded = Ok(recorded_ok(true, None));
        let report = InstallReport::from_outcome(&outcome, &recorded, true);
        assert!(
            !report.success,
            "a missing RECORD must fail the enforcing install closed"
        );
        assert!(report.post_blocked);
        assert!(!report.record_integrity_clean());

        let digest = digest_with_expiry("");
        let json = report.to_json(&digest, &outcome);
        assert_eq!(json["record_records_missing"], serde_json::json!(1));
        assert_eq!(json["success"], serde_json::json!(false));
    }

    #[test]
    fn install_report_missing_distribution_fails_closed_and_receipt_verdict_blocks() {
        let mut outcome = outcome_with_post(0, 0, 0);
        let post = outcome.post_install.as_mut().unwrap();
        post.distributions_verified = 0;
        post.distributions_not_found = 1;
        let recorded = Ok(recorded_ok(true, None));

        let report = InstallReport::from_outcome(&outcome, &recorded, true);
        assert!(!report.success);
        assert!(report.post_blocked);
        assert!(!report.record_integrity_clean());
        assert_eq!(report.distributions_not_found, 1);
        assert_eq!(
            enforcing_install_verdict(&outcome).action,
            tirith_core::verdict::Action::Block,
            "the signed receipt must attest the enforcing Block, not an empty Allow"
        );

        let digest = digest_with_expiry("");
        let json = report.to_json(&digest, &outcome);
        assert_eq!(json["record_distributions_not_found"], serde_json::json!(1));
        assert_eq!(json["success"], serde_json::json!(false));
    }

    #[test]
    fn verify_env_returns_nonzero_when_expected_distribution_is_absent() {
        let target = tempfile::tempdir().unwrap();
        let packages = vec!["definitely-not-installed".to_string()];
        assert_eq!(
            run_verify_env(target.path(), &packages, false),
            1,
            "an empty Allow verdict must not turn incomplete verification into success"
        );
    }

    #[test]
    fn install_report_receipt_error_fails_the_install() {
        // A receipt that failed to record (e.g. mandatory signature unavailable, IM1)
        // makes the whole install report a failure (success=false, exit 1).
        let outcome = outcome_with_post(0, 0, 0);
        let recorded = Err(tirith_core::receipt::ReceiptError::SignatureRequiredButUnavailable);
        let report = InstallReport::from_outcome(&outcome, &recorded, true);
        assert!(!report.success, "an unrecordable receipt fails the install");
        assert!(report.receipt_error.is_some());

        let digest = digest_with_expiry("");
        let json = report.to_json(&digest, &outcome);
        assert_eq!(json["success"], serde_json::json!(false));
        assert!(json["receipt_error"].is_string());
    }
}
