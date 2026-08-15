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

use std::path::{Path, PathBuf};

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
use tirith_core::policy::Policy;
use tirith_core::receipt::ArtifactScanReceipt;
use tirith_core::threatdb::ThreatDb;

use crate::cli::capsule::{self, DegradedPolicy};
use crate::cli::pkg_install::{
    build_install_receipt, run_contained_install, ContainedInstallError, EnvironmentCheckpoint,
    InstallTargetBinding, ResolverProvenance,
};

/// tirith-owned options that no package manager interprets. If one of these appears
/// AFTER the trailing requirement args it would silently not affect tirith (the same
/// footgun `tirith install` guards), so finding one trailing is a hard error. Shared
/// in spirit with [`crate::cli::install`]'s guard; kept local so the two surfaces
/// can carry their own flag sets.
const MISPLACED_TIRITH_FLAGS: &[&str] = &["--yes", "--allow-degraded", "--online"];

/// The default approval lifetime when `pkg approve` does not get an explicit window:
/// short, so a stale approval cannot be redeemed long after the situation it was
/// bound to. 30 minutes.
const DEFAULT_APPROVAL_TTL_SECS: i64 = 30 * 60;

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
    fn derive_from_interpreter(
        interpreter: PathBuf,
        target: Option<PathBuf>,
    ) -> Result<Self, String> {
        let target = target.ok_or_else(|| {
            "an explicit --target is required for enforcing installs; choose a new dedicated directory whose parent already exists"
                .to_string()
        })?;
        let binding = InstallTargetBinding::bind(&target)
            .map_err(|error| format!("cannot bind --target parent and final component: {error}"))?;
        let environment = binding.target().to_path_buf();
        if is_broad_install_target(&environment) {
            return Err(format!(
                "refusing broad/shared install target {}; choose a new dedicated package directory",
                environment.display()
            ));
        }

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
        Ok(InstallTarget {
            interpreter,
            environment,
            extra_read_roots: vec![prefix],
            binding,
        })
    }
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
fn prepare_plan(
    requirements: &[String],
    target: Option<PathBuf>,
    index_url: &[String],
    artifact_origin: &[String],
    policy: &Policy,
    expiry: String,
    task_gate_binding: String,
) -> Result<PreparedPlan, PrepareError> {
    // Resolve uv + python by executable provenance (never a bare PATH name in the
    // child), with the locked-down default allowances (no sdist/VCS/editable/...).
    let request = ResolverRequest {
        requirements: requirements.to_vec(),
        index_urls: index_url.to_vec(),
        allowances: Default::default(),
    };
    // Parse and policy-check all attacker-controlled strings before PATH lookup,
    // quarantine creation, broker binding, DNS, or child execution.
    validate_resolver_request_with_artifact_origins(&request, artifact_origin)
        .map_err(PrepareError::Resolver)?;
    let discovered =
        ResolverTools::discover(&request.allowances).map_err(PrepareError::Resolver)?;
    // Bind the target parent and final component before any resolver/version child
    // runs, so approval authority cannot race with tool probing or network resolve.
    let target = InstallTarget::derive_from_interpreter(discovered.python.clone(), target)
        .map_err(PrepareError::Target)?;
    let tools = BoundResolverTools::bind(&discovered).map_err(PrepareError::Resolver)?;

    // A fresh quarantine transaction under the real data dir. The id is a
    // timestamp-derived component; the store validates it.
    let store = QuarantineStore::open().map_err(PrepareError::Quarantine)?;
    let txn_id = new_transaction_id();
    let txn = store
        .begin_transaction(&txn_id)
        .map_err(PrepareError::Quarantine)?;

    // D2: resolve + download + ingest into the quarantine (re-hashing on the way in).
    let resolved =
        resolve_into_quarantine_with_bound_tools(&request, &tools, &txn, artifact_origin)
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
        policy_projection_hash: policy.security_projection_hash(),
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
    Target(String),
}

impl std::fmt::Display for PrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrepareError::Resolver(e) => write!(f, "resolve failed: {e}"),
            PrepareError::Quarantine(e) => write!(f, "quarantine error: {e}"),
            PrepareError::Install(e) => write!(f, "{e}"),
            PrepareError::Target(reason) => write!(f, "unsafe install target: {reason}"),
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

/// Evaluate one owned package boundary.
///
/// The effects come from [`tirith_core::task::ProposedAction::PackageInstall`],
/// which already derives package install, network egress, and filesystem write;
/// there is no second deriver here. The policy is the offline operator-only one
/// the caller already discovered, so a repository cannot weaken its own install.
fn evaluate_package_boundary(
    boundary: tirith_core::task_boundary::OwnedBoundary,
    ecosystem: Ecosystem,
    requirements: &[String],
    policy: &Policy,
) -> tirith_core::task_boundary::BoundaryAssessment {
    let envelope = tirith_core::task_boundary::package_envelope(ecosystem.label(), requirements);
    let operation = tirith_core::task_boundary::BoundaryOperation {
        boundary,
        envelope: &envelope,
        // An argv identifies no origin. Claiming one would be a lie the
        // provenance model exists to prevent.
        adapter: tirith_core::task::IngressAdapter::Unattributed,
        boundary_effects: Default::default(),
    };
    tirith_core::task_boundary::evaluate(&operation, &policy.task_gate)
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

// ---------------------------------------------------------------------------
// pkg approve
// ---------------------------------------------------------------------------

fn run_approve(
    ecosystem: Ecosystem,
    requirements: &[String],
    target: Option<PathBuf>,
    index_url: &[String],
    artifact_origin: &[String],
    json: bool,
) -> i32 {
    if let Some(failure) = precheck(ecosystem, requirements) {
        return report_pkg_precheck_failure("approve", &failure, json);
    }
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    // Operator policy only (offline / local-only), so a repo-scoped policy cannot
    // weaken the approval; the resolver never reads repo-local pip/uv config.
    let policy = Policy::discover_local_only(cwd.as_deref());

    // C12: the owned network-egress transition. `prepare_plan` does PATH
    // lookup, quarantine creation, broker binding, DNS, and resolver child
    // execution, so the gate has to sit here: one line later and packages have
    // already been fetched. `approve` has no separate human gate of its own to
    // satisfy a required approval, so it passes `false`.
    let task_assessment = evaluate_package_boundary(
        tirith_core::task_boundary::OwnedBoundary::PackageApproval,
        ecosystem,
        requirements,
        &policy,
    );
    if let Some(reason) = task_assessment.refusal(false) {
        return report_task_gate_refusal("approve", &task_assessment, reason, json);
    }

    let expiry =
        (chrono::Utc::now() + chrono::Duration::seconds(DEFAULT_APPROVAL_TTL_SECS)).to_rfc3339();
    let prepared = match prepare_plan(
        requirements,
        target,
        index_url,
        artifact_origin,
        &policy,
        expiry,
        tirith_core::task_boundary::ceiling_binding(&task_assessment.decision),
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("tirith pkg approve: {e}");
            return 1;
        }
    };

    // Persist the approval record keyed by the plan digest, so `pkg install` can
    // verify a matching approval exists.
    match ApprovalRecord::from_digest(&prepared.digest).save() {
        Ok(path) => {
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
        Err(e) => {
            eprintln!("tirith pkg approve: could not save approval record: {e}");
            1
        }
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
    let policy = Policy::discover_local_only(cwd.as_deref());

    // An install's digest is NOT time-boxed by itself (the install happens now); the
    // approval record it must match carries the expiry. So the install builds the
    // digest with no expiry and looks for a matching approval (whose own expiry is
    // checked). This keeps "the bytes/situation I am about to install" stable while
    // the approval governs the time window.
    // C12: same owned network-egress transition, before the resolver runs.
    let network_assessment = evaluate_package_boundary(
        tirith_core::task_boundary::OwnedBoundary::PackageResolve,
        ecosystem,
        requirements,
        &policy,
    );
    if let Some(reason) = network_assessment.refusal(false) {
        return report_task_gate_refusal("install", &network_assessment, reason, json);
    }

    let prepared = match prepare_plan(
        requirements,
        target,
        index_url,
        artifact_origin,
        &policy,
        String::new(),
        tirith_core::task_boundary::ceiling_binding(&network_assessment.decision),
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

    // Authorisation: a matching, un-expired approval record, or an explicit `--yes`
    // (the unattended path). `--yes` is recorded honestly: the receipt's verdict +
    // chain still attest the install, but no prior human approval gate was crossed.
    if !yes {
        match approval_status(&prepared.digest) {
            ApprovalStatus::Valid => {}
            ApprovalStatus::Missing => {
                return report_install_failure(
                    "approval",
                    &format!(
                        "no matching approval for plan {}; run `tirith pkg approve {} {}` first, or pass --yes to install unattended",
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
                        "the approval for plan {} has expired; re-run `tirith pkg approve`",
                        prepared.digest.plan_digest
                    ),
                    false,
                    false,
                    json,
                    1,
                );
            }
        }
    }

    // C12: the owned install-preparation transition. Everything irreversible
    // about the install starts at `EnvironmentCheckpoint::begin` below, which
    // creates and retains the target environment before pip gets write access,
    // so the second gate sits above it. Unlike the resolve gate this site HAS
    // crossed a human gate already: either a matching un-expired approval record
    // was just validated, or the operator passed `--yes` for the unattended
    // path, so a required approval is satisfied rather than refused.
    let preparation_assessment = evaluate_package_boundary(
        tirith_core::task_boundary::OwnedBoundary::PackageInstallPreparation,
        ecosystem,
        requirements,
        &policy,
    );
    if let Some(reason) = preparation_assessment.refusal(true) {
        return report_task_gate_refusal("install", &preparation_assessment, reason, json);
    }

    // The contained install (D4) always fails closed. `--allow-degraded` remains a
    // compatibility flag but cannot weaken the enforcing package path; analysis-only
    // execution is a separate command.
    let degraded_policy = if allow_degraded {
        DegradedPolicy::AllowDegraded
    } else {
        DegradedPolicy::FailClosed
    };

    let installed_distributions = installed_distribution_identities(&prepared.resolved);
    // Atomically create and retain the new dedicated target before pip gets write
    // access. The narrow journal remains live through RECORD verification and
    // mandatory signed-receipt recording; every safely recoverable failed gate
    // removes only this newly created target.
    let mut environment_checkpoint = match EnvironmentCheckpoint::begin(&prepared.target.binding) {
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
    let target_handle = match environment_checkpoint.try_clone_target_handle() {
        Ok(handle) => handle,
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
    let target_install_path = environment_checkpoint.install_path().to_path_buf();
    let outcome = match run_contained_install_with_policy(
        &prepared.plan,
        &prepared.txn,
        &prepared.tools,
        &prepared.target.environment,
        &target_install_path,
        target_handle,
        &installed_distributions,
        &policy,
        json,
        degraded_policy,
        &preparation_assessment.enforced_denied_effects(),
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
    target_install_path: &Path,
    target_handle: std::fs::File,
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
        target_install_path,
        target_handle,
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

/// A persisted approval: the [`InstallPlanDigest`] an operator approved, saved under
/// `data_dir()/approvals/<plan_digest>.json`. `pkg install` re-derives the plan
/// digest of what it is about to run and looks up a matching, un-expired record.
///
/// The record IS the digest (serialized): saving the whole digest means the install
/// can re-validate `digest_matches()` AND the expiry, so an edited record (a swapped
/// interpreter with a stale digest) is rejected.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ApprovalRecord {
    digest: InstallPlanDigest,
}

impl ApprovalRecord {
    fn from_digest(digest: &InstallPlanDigest) -> Self {
        ApprovalRecord {
            digest: digest.clone(),
        }
    }

    /// Save the record atomically (0600) under `data_dir()/approvals/<digest>.json`.
    fn save(&self) -> Result<PathBuf, String> {
        let dir = approvals_dir().ok_or("cannot determine approvals directory")?;
        tirith_core::util::create_dir_durable(&dir).map_err(|e| format!("create dir: {e}"))?;
        let path = dir.join(format!("{}.json", self.digest.plan_digest));
        let json = serde_json::to_string_pretty(self).map_err(|e| format!("serialize: {e}"))?;
        tirith_core::util::write_file_atomic_0600(&path, json.as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        Ok(path)
    }

    /// Load the approval record for a plan digest, if one exists. Used by tests to
    /// assert a saved record round-trips by id; the runtime authorisation path
    /// ([`approval_status`]) scans the approvals directory instead, because the
    /// install digest differs from the approval digest by the expiry field and so
    /// cannot key directly on the approval's id.
    #[cfg(test)]
    fn load(plan_digest: &str) -> Option<Self> {
        let dir = approvals_dir()?;
        let path = dir.join(format!("{plan_digest}.json"));
        let content = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }
}

/// The directory persisted approvals live in.
fn approvals_dir() -> Option<PathBuf> {
    tirith_core::policy::data_dir().map(|d| d.join("approvals"))
}

/// The authorisation state of an install plan against the persisted approvals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalStatus {
    /// A matching, un-expired, content-consistent approval exists.
    Valid,
    /// No approval record matches this plan digest.
    Missing,
    /// A matching record exists but it has expired.
    Expired,
}

/// Decide whether `digest` (the plan about to run) is authorised by a saved
/// approval. The install builds its digest with NO expiry, so the lookup keys on the
/// install digest's `plan_digest`, and the SAVED record's expiry is what gates the
/// time window.
fn approval_status(digest: &InstallPlanDigest) -> ApprovalStatus {
    // The install digest has empty expiry; an approval record's digest carries a real
    // expiry, so the two `plan_digest`s differ by the expiry field. Recompute the
    // install digest's id WITH each candidate expiry would be circular; instead the
    // approval record stores the full digest, and we match on every binding field
    // EXCEPT expiry, then check the record's expiry.
    //
    // We do this by scanning the approvals dir for a record whose digest equals the
    // install digest on all fields but expiry. In practice there is at most one such
    // record per situation; the install digest's own id is recomputed with the
    // record's expiry to confirm the binding is intact.
    let Some(dir) = approvals_dir() else {
        return ApprovalStatus::Missing;
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return ApprovalStatus::Missing;
    };
    let now = chrono::Utc::now().to_rfc3339();
    let mut saw_expired_match = false;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(record) = serde_json::from_str::<ApprovalRecord>(&content) else {
            continue;
        };
        // The record must be internally consistent (no edited binding field), and it
        // must bind the SAME situation as the install plan (every field but expiry).
        if !record.digest.digest_matches() {
            continue;
        }
        if !same_plan_modulo_expiry(&record.digest, digest) {
            continue;
        }
        if record.digest.is_expired_at(&now) {
            saw_expired_match = true;
            continue;
        }
        return ApprovalStatus::Valid;
    }
    if saw_expired_match {
        ApprovalStatus::Expired
    } else {
        ApprovalStatus::Missing
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
        let path = ApprovalRecord::from_digest(&approved).save().unwrap();
        assert!(path.exists());

        // The install builds the SAME situation with NO expiry.
        let install_digest = digest_with_expiry("");
        // The two ids differ (expiry differs) but bind the same situation.
        assert_ne!(approved.plan_digest, install_digest.plan_digest);
        assert!(same_plan_modulo_expiry(&approved, &install_digest));

        // The install is authorised by the saved approval.
        assert_eq!(approval_status(&install_digest), ApprovalStatus::Valid);

        // Loadable directly, too.
        let loaded = ApprovalRecord::load(&approved.plan_digest).unwrap();
        assert_eq!(loaded.digest, approved);
        assert!(loaded.digest.digest_matches());
    }

    #[test]
    fn approval_missing_when_no_record() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _g = isolate(root.path());
        let install_digest = digest_with_expiry("");
        assert_eq!(approval_status(&install_digest), ApprovalStatus::Missing);
    }

    #[test]
    fn approval_expired_is_detected() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _g = isolate(root.path());

        // An already-expired approval.
        let approved = digest_with_expiry("2000-01-01T00:00:00+00:00");
        ApprovalRecord::from_digest(&approved).save().unwrap();

        let install_digest = digest_with_expiry("");
        assert!(same_plan_modulo_expiry(&approved, &install_digest));
        assert_eq!(approval_status(&install_digest), ApprovalStatus::Expired);
    }

    #[test]
    fn approval_does_not_match_a_different_situation() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _g = isolate(root.path());

        // Approve one situation.
        let approved = digest_with_expiry("2099-01-01T00:00:00+00:00");
        ApprovalRecord::from_digest(&approved).save().unwrap();

        // A DIFFERENT install: a different interpreter. Build it by hand.
        let mut other_inputs = plan_inputs_with_expiry("");
        other_inputs.interpreter = PathBuf::from("/attacker/python");
        let other = InstallPlanDigest::new(other_inputs);
        assert!(!same_plan_modulo_expiry(&approved, &other));
        // No matching approval for the changed situation.
        assert_eq!(approval_status(&other), ApprovalStatus::Missing);
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
        let ceiling = |policy: &Policy, boundary| {
            tirith_core::task_boundary::ceiling_binding(
                &evaluate_package_boundary(boundary, Ecosystem::Pip, &requirements, policy)
                    .decision,
            )
        };
        let approved_under = ceiling(
            &enforcing,
            tirith_core::task_boundary::OwnedBoundary::PackageApproval,
        );
        let installed_under = ceiling(
            &Policy::default(),
            tirith_core::task_boundary::OwnedBoundary::PackageResolve,
        );
        assert_ne!(
            approved_under, installed_under,
            "the ceiling must differ, or this test proves nothing"
        );

        let mut approved_inputs = plan_inputs_with_expiry("2099-01-01T00:00:00+00:00");
        approved_inputs.task_gate_binding = approved_under;
        let approved = InstallPlanDigest::new(approved_inputs);
        ApprovalRecord::from_digest(&approved).save().unwrap();

        let mut install_inputs = plan_inputs_with_expiry("");
        install_inputs.task_gate_binding = installed_under;
        let install_digest = InstallPlanDigest::new(install_inputs);

        assert!(
            !same_plan_modulo_expiry(&approved, &install_digest),
            "an approval taken under an enforcing gate matched an install under a relaxed one"
        );
        assert_eq!(approval_status(&install_digest), ApprovalStatus::Missing);
    }

    /// The same ceiling still authorises: the check above must not have made
    /// every approval unredeemable.
    #[test]
    fn an_unchanged_task_gate_still_authorises_the_install() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _g = isolate(root.path());

        let approved = digest_with_expiry("2099-01-01T00:00:00+00:00");
        ApprovalRecord::from_digest(&approved).save().unwrap();
        assert_eq!(
            approval_status(&digest_with_expiry("")),
            ApprovalStatus::Valid
        );
    }

    #[test]
    fn approval_with_advanced_db_sequence_does_not_match() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _g = isolate(root.path());

        // Approve bound to DB sequence 3.
        let approved = digest_with_expiry("2099-01-01T00:00:00+00:00");
        ApprovalRecord::from_digest(&approved).save().unwrap();

        // Install plan now bound to DB sequence 4 (a newer DB) -> not authorised.
        let mut install_inputs = plan_inputs_with_expiry("");
        install_inputs.threat_db_sequence = 4;
        let install_digest = InstallPlanDigest::new(install_inputs);
        assert_eq!(approval_status(&install_digest), ApprovalStatus::Missing);
    }

    #[test]
    fn edited_approval_record_is_rejected() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _g = isolate(root.path());

        // Save a valid approval, then EDIT the saved file to swap the interpreter
        // while leaving the stored plan_digest stale.
        let approved = digest_with_expiry("2099-01-01T00:00:00+00:00");
        let path = ApprovalRecord::from_digest(&approved).save().unwrap();
        let mut record: ApprovalRecord =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        record.digest.interpreter = "/attacker/python".to_string();
        // Write the tampered record back (stale digest, changed interpreter).
        std::fs::write(&path, serde_json::to_string_pretty(&record).unwrap()).unwrap();

        // The install for the ORIGINAL situation must NOT be authorised: the tampered
        // record fails digest_matches() and is skipped.
        let install_digest = digest_with_expiry("");
        assert_eq!(approval_status(&install_digest), ApprovalStatus::Missing);
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
        let t = InstallTarget::derive_from_interpreter(
            PathBuf::from("/opt/py/bin/python3"),
            Some(requested.clone()),
        )
        .unwrap();
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
        let error =
            InstallTarget::derive_from_interpreter(PathBuf::from("/opt/py/bin/python3"), None)
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
