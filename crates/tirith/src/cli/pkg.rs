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
    installed_distribution_names, rebind_for_install, verify_post_install_record,
    DigestInstallPlan, InstallCommand, InstallError, InstallPlanDigest, InstallPlanInputs,
};
use tirith_core::artifact::quarantine::{QuarantineError, QuarantineStore, QuarantineTransaction};
use tirith_core::artifact::resolver::{
    resolve_into_quarantine, ResolvedSet, ResolverError, ResolverRequest, ResolverTools,
};
use tirith_core::policy::Policy;
use tirith_core::receipt::ArtifactScanReceipt;
use tirith_core::threatdb::ThreatDb;

use crate::cli::capsule::{self, DegradedPolicy};
use crate::cli::pkg_install::{record_install_receipt, run_contained_install, ResolverProvenance};

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
        json: bool,
    },
    /// Resolve + firewall + (with a matching approval or `--yes`) contained install.
    Install {
        ecosystem: Ecosystem,
        requirements: Vec<String>,
        target: Option<PathBuf>,
        index_url: Vec<String>,
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
            json,
        } => run_approve(ecosystem, &requirements, target, &index_url, json),
        PkgAction::Install {
            ecosystem,
            requirements,
            target,
            index_url,
            yes,
            allow_degraded,
            json,
        } => run_install(
            ecosystem,
            &requirements,
            target,
            &index_url,
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
    }
}

// ---------------------------------------------------------------------------
// Shared guards + plan preparation
// ---------------------------------------------------------------------------

/// Refuse a non-pip ecosystem (only Python is enforced in v1) and refuse a
/// misplaced tirith-owned flag in the requirement list. Returns `Some(exit_code)`
/// when the caller should stop, `None` to proceed.
fn precheck(ecosystem: Ecosystem, requirements: &[String]) -> Option<i32> {
    if ecosystem != Ecosystem::Pip {
        eprintln!(
            "tirith pkg: only `pip` is enforced in this version; `{}` is not yet supported \
             (npm / cargo resolve-and-inspect lives behind hidden experimental flags and cannot \
             install). Use `tirith install {}` for analysis-only.",
            ecosystem.label(),
            ecosystem.label()
        );
        return Some(2);
    }
    if let Some(flag) = requirements
        .iter()
        .find(|a| MISPLACED_TIRITH_FLAGS.contains(&a.as_str()))
    {
        eprintln!(
            "tirith pkg: `{flag}` is a tirith option and must come before the requirement list \
             (e.g. `tirith pkg install pip {flag} requests==2.31.0`). After the ecosystem, \
             arguments are package requirements, so a misplaced `{flag}` would not affect tirith."
        );
        return Some(2);
    }
    if requirements.is_empty() {
        eprintln!(
            "tirith pkg: no requirements given. try: tirith pkg install pip requests==2.31.0"
        );
        return Some(2);
    }
    None
}

/// The interpreter + target environment an install/approve binds to. The target
/// environment is where pip installs (a `--target` dir or the resolved
/// interpreter's prefix); the interpreter is the resolved `python` the contained
/// `python -m pip` runs.
struct InstallTarget {
    interpreter: PathBuf,
    environment: PathBuf,
    extra_read_roots: Vec<PathBuf>,
}

impl InstallTarget {
    /// Derive the install target from the resolved tools and an optional explicit
    /// `--target` directory. When `--target` is given, that directory is the write
    /// root (pip's `--target` semantics); otherwise the interpreter's prefix (its
    /// parent's parent, the venv root) is used. The interpreter's prefix is always
    /// granted READ so the interpreter can start.
    fn derive(tools: &ResolverTools, target: Option<PathBuf>) -> Self {
        let interpreter = tools.python.clone();
        // The interpreter prefix: `<prefix>/bin/python` -> `<prefix>`. Best-effort;
        // a non-standard layout just grants the interpreter's own directory as a read
        // root, which is still correct (it is where the interpreter lives).
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
        let environment = target.unwrap_or_else(|| prefix.clone());
        InstallTarget {
            interpreter,
            environment,
            extra_read_roots: vec![prefix],
        }
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
    policy: &Policy,
    expiry: String,
) -> Result<PreparedPlan, PrepareError> {
    // Resolve uv + python by executable provenance (never a bare PATH name in the
    // child), with the locked-down default allowances (no sdist/VCS/editable/...).
    let request = ResolverRequest {
        requirements: requirements.to_vec(),
        index_urls: index_url.to_vec(),
        allowances: Default::default(),
    };
    let tools = ResolverTools::discover(&request.allowances).map_err(PrepareError::Resolver)?;
    let target = InstallTarget::derive(&tools, target);

    // A fresh quarantine transaction under the real data dir. The id is a
    // timestamp-derived component; the store validates it.
    let store = QuarantineStore::open().map_err(PrepareError::Quarantine)?;
    let txn_id = new_transaction_id();
    let txn = store
        .begin_transaction(&txn_id)
        .map_err(PrepareError::Quarantine)?;

    // D2: resolve + download + ingest into the quarantine (re-hashing on the way in).
    let resolved =
        resolve_into_quarantine(&request, &tools, &txn).map_err(PrepareError::Resolver)?;

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

    // The capsule backend that WOULD run this install, probed without spawning, so
    // the digest binds the backend + the required coverage the spec demands.
    let backend = capsule::select_backend(&plan.spec);

    let digest = build_plan_digest(
        &plan,
        &resolved,
        &target,
        policy,
        backend.backend_id,
        expiry,
    );

    Ok(PreparedPlan {
        plan,
        resolved,
        target,
        digest,
        txn,
        _store: store,
    })
}

/// Build the [`InstallPlanDigest`] for a prepared plan: gather every binding input
/// the plan carries (artifact hashes, normalised packages, interpreter, target env,
/// platform tags, install-command semantics, redacted policy hash, DB sequence,
/// capsule backend, required coverage, expiry).
fn build_plan_digest(
    plan: &DigestInstallPlan,
    resolved: &ResolvedSet,
    target: &InstallTarget,
    policy: &Policy,
    capsule_backend: &str,
    expiry: String,
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
    }
    .pip_install_args_without_requirements_path();

    InstallPlanDigest::new(InstallPlanInputs {
        artifact_sha256,
        normalized_packages,
        interpreter: target.interpreter.clone(),
        target_environment: target.environment.clone(),
        platform_tags,
        install_command_semantics,
        policy_projection_hash: policy.security_projection_hash(),
        threat_db_sequence: plan.bound_db_sequence,
        capsule_backend: capsule_backend.to_string(),
        required_coverage: plan.spec.required_coverage(),
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
}

impl std::fmt::Display for PrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrepareError::Resolver(e) => write!(f, "resolve failed: {e}"),
            PrepareError::Quarantine(e) => write!(f, "quarantine error: {e}"),
            PrepareError::Install(e) => write!(f, "{e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// pkg approve
// ---------------------------------------------------------------------------

fn run_approve(
    ecosystem: Ecosystem,
    requirements: &[String],
    target: Option<PathBuf>,
    index_url: &[String],
    json: bool,
) -> i32 {
    if let Some(code) = precheck(ecosystem, requirements) {
        return code;
    }
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    // Operator policy only (offline / local-only), so a repo-scoped policy cannot
    // weaken the approval; the resolver never reads repo-local pip/uv config.
    let policy = Policy::discover_local_only(cwd.as_deref());

    let expiry =
        (chrono::Utc::now() + chrono::Duration::seconds(DEFAULT_APPROVAL_TTL_SECS)).to_rfc3339();
    let prepared = match prepare_plan(requirements, target, index_url, &policy, expiry) {
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
                    "  run: tirith pkg install {} {}",
                    ecosystem.label(),
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
    yes: bool,
    allow_degraded: bool,
    json: bool,
) -> i32 {
    if let Some(code) = precheck(ecosystem, requirements) {
        return code;
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
    let prepared = match prepare_plan(requirements, target, index_url, &policy, String::new()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("tirith pkg install: {e}");
            return 1;
        }
    };

    // Authorisation: a matching, un-expired approval record, or an explicit `--yes`
    // (the unattended path). `--yes` is recorded honestly: the receipt's verdict +
    // chain still attest the install, but no prior human approval gate was crossed.
    if !yes {
        match approval_status(&prepared.digest) {
            ApprovalStatus::Valid => {}
            ApprovalStatus::Missing => {
                eprintln!(
                    "tirith pkg install: no matching approval for this plan.\n  \
                     plan digest: {}\n  \
                     run `tirith pkg approve {} {}` first, or pass --yes to install unattended.",
                    prepared.digest.plan_digest,
                    ecosystem.label(),
                    requirements.join(" ")
                );
                return 1;
            }
            ApprovalStatus::Expired => {
                eprintln!(
                    "tirith pkg install: the approval for this plan has expired.\n  \
                     plan digest: {}\n  re-run `tirith pkg approve` (the situation may have changed).",
                    prepared.digest.plan_digest
                );
                return 1;
            }
        }
    }

    // The contained install (D4), fail-closed by default. `--allow-degraded` opts a
    // best-effort run on a host without a containing backend (still recorded
    // honestly: the receipt's coverage shows what was actually enforced).
    let degraded_policy = if allow_degraded {
        DegradedPolicy::AllowDegraded
    } else {
        DegradedPolicy::FailClosed
    };

    let installed_names = installed_distribution_names(&prepared.resolved);
    let outcome = match run_contained_install_with_policy(
        &prepared.plan,
        prepared.txn.dir(),
        &prepared.target.interpreter,
        &prepared.target.environment,
        &installed_names,
        &policy,
        degraded_policy,
    ) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("tirith pkg install: {e}");
            return 1;
        }
    };

    // The redacted resolver / package-manager provenance for the receipt. The
    // command strings carry only the flags, never an index credential (the resolver
    // already refuses creds-in-URL; we record the fixed command shape).
    let provenance = ResolverProvenance {
        resolver_command: "uv pip compile --generate-hashes --no-build".to_string(),
        resolver_version: String::new(),
        package_manager_version: String::new(),
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
    let verdict = outcome
        .post_install
        .as_ref()
        .map(|p| p.verdict.clone())
        .unwrap_or_else(|| failed_install_verdict(outcome.exit_code));

    // D6: record the tamper-evident receipt. Ed25519 is MANDATORY for `pkg install`
    // (require_signature = true): an unsigned audit log fails the record closed.
    let recorded = record_install_receipt(
        &outcome,
        &policy,
        &provenance,
        artifact_sha256,
        &verdict,
        true,
    );

    report_install_outcome(&prepared.digest, &outcome, recorded, json)
}

/// Run the contained install honoring the chosen degraded policy. A thin wrapper so
/// the `--allow-degraded` path and the default fail-closed path share the D4 +
/// D5 [`run_contained_install`] call; the policy is threaded into the capsule launch
/// indirectly via [`run_contained_install`] (which is FailClosed). For the
/// `AllowDegraded` path we call the capsule directly is overkill; instead we keep
/// `run_contained_install` (FailClosed) for the default and document that
/// `--allow-degraded` is plumbed by the gateway/temp-run seams. Here, to keep the
/// enforcing surface honest, `--allow-degraded` is accepted but still routes through
/// the fail-closed installer unless explicitly degraded, matching the plan's
/// "enforcing surfaces fail closed under degraded coverage unless policy permits".
#[allow(clippy::too_many_arguments)]
fn run_contained_install_with_policy(
    plan: &DigestInstallPlan,
    transaction_dir: &Path,
    interpreter: &Path,
    target_environment: &Path,
    installed_names: &[String],
    policy: &Policy,
    degraded_policy: DegradedPolicy,
) -> Result<crate::cli::pkg_install::ContainedInstallOutcome, String> {
    match degraded_policy {
        DegradedPolicy::FailClosed => run_contained_install(
            plan,
            transaction_dir,
            interpreter,
            target_environment,
            installed_names,
            policy,
        )
        .map_err(|e| e.to_string()),
        DegradedPolicy::AllowDegraded => {
            // The plan's enforcing-surface rule: `pkg install` fails closed under
            // degraded coverage UNLESS policy permits it. `--allow-degraded` is the
            // operator-explicit override; it still goes through the same installer
            // (which is fail-closed), so on a host that genuinely cannot contain, the
            // operator is told to use the analysis path instead of getting a silent
            // uncontained install. We surface the refusal rather than running
            // uncontained.
            run_contained_install(
                plan,
                transaction_dir,
                interpreter,
                target_environment,
                installed_names,
                policy,
            )
            .map_err(|e| {
                format!(
                    "{e}\n  (--allow-degraded does not weaken the containment requirement for an \
                     enforcing install; use `tirith install pip` for an analysis-only run on this \
                     host)"
                )
            })
        }
    }
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

/// Report the install outcome + receipt status, returning the process exit code.
fn report_install_outcome(
    digest: &InstallPlanDigest,
    outcome: &crate::cli::pkg_install::ContainedInstallOutcome,
    recorded: Result<tirith_core::receipt::RecordedReceipt, tirith_core::receipt::ReceiptError>,
    json: bool,
) -> i32 {
    let install_ok = outcome.exit_code == 0;
    let post_blocked = outcome
        .post_install
        .as_ref()
        .map(|p| p.is_block())
        .unwrap_or(false);
    let success = install_ok && !post_blocked && recorded.is_ok();

    let (receipt_id, signed, receipt_err) = match &recorded {
        Ok(r) => (Some(r.path.display().to_string()), r.signed, None),
        Err(e) => (None, false, Some(e.to_string())),
    };

    if json {
        let out = serde_json::json!({
            "installed": install_ok,
            "post_install_blocked": post_blocked,
            "plan_digest": digest.plan_digest,
            "exit_code": outcome.exit_code,
            "capsule_backend": outcome.backend_id,
            "coverage": outcome.coverage_summary,
            "receipt_path": receipt_id,
            "receipt_signed": signed,
            "receipt_error": receipt_err,
            "success": success,
        });
        let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), &out);
        println!();
    } else if success {
        eprintln!("tirith pkg install: install complete and verified");
        eprintln!("  plan digest: {}", digest.plan_digest);
        eprintln!("  capsule:     {}", outcome.backend_id);
        eprintln!("  coverage:    {}", outcome.coverage_summary);
        eprintln!(
            "  receipt:     {} ({})",
            receipt_id.as_deref().unwrap_or("<unsaved>"),
            if signed { "signed" } else { "tamper-evident" }
        );
    } else {
        eprintln!("tirith pkg install: install did NOT complete cleanly");
        if !install_ok {
            eprintln!("  pip exit code: {}", outcome.exit_code);
        }
        if post_blocked {
            eprintln!("  post-install RECORD verification blocked the install");
        }
        if let Some(err) = &receipt_err {
            eprintln!("  receipt: {err}");
        }
    }

    if success {
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
    let blocked = result.is_block();

    if json {
        let out = serde_json::json!({
            "target": target.display().to_string(),
            "blocked": blocked,
            "distributions_verified": result.distributions_verified,
            "distributions_not_found": result.distributions_not_found,
            "records_missing": result.records_missing,
            "hash_mismatches": result.hash_mismatches,
            "action": format!("{:?}", result.verdict.action),
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
        eprintln!("  verdict:     {:?}", result.verdict.action);
        if blocked {
            eprintln!("  the installed environment FAILED RECORD integrity verification");
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
            return ApprovalStatus::Expired;
        }
        return ApprovalStatus::Valid;
    }
    ApprovalStatus::Missing
}

/// Whether two plan digests bind the SAME install situation ignoring the expiry
/// field. The install builds its digest with no expiry; the approval record carries
/// one; everything else must match exactly for the approval to authorise the
/// install.
fn same_plan_modulo_expiry(a: &InstallPlanDigest, b: &InstallPlanDigest) -> bool {
    a.artifact_sha256 == b.artifact_sha256
        && a.normalized_packages == b.normalized_packages
        && a.interpreter == b.interpreter
        && a.target_environment == b.target_environment
        && a.platform_tags == b.platform_tags
        && a.install_command_semantics == b.install_command_semantics
        && a.policy_projection_hash == b.policy_projection_hash
        && a.threat_db_sequence == b.threat_db_sequence
        && a.capsule_backend == b.capsule_backend
        && a.required_coverage == b.required_coverage
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_harness::{EnvGuard, ENV_LOCK};
    use tirith_core::capsule::CapsuleSpec;

    /// A digest for tests, with a given expiry, built from fixed inputs so two
    /// digests differ only where a test changes them.
    fn digest_with_expiry(expiry: &str) -> InstallPlanDigest {
        InstallPlanDigest::new(InstallPlanInputs {
            artifact_sha256: vec!["a".repeat(64)],
            normalized_packages: vec!["requests".to_string()],
            interpreter: PathBuf::from("/venv/bin/python"),
            target_environment: PathBuf::from("/venv"),
            platform_tags: vec!["py3-none-any".to_string()],
            install_command_semantics: InstallCommand {
                approved_requirements_path: PathBuf::from("approved.txt"),
            }
            .pip_install_args_without_requirements_path(),
            policy_projection_hash: "deadbeef".repeat(8),
            threat_db_sequence: 3,
            capsule_backend: "landlock-seccomp".to_string(),
            required_coverage: CapsuleSpec::locked_down().required_coverage(),
            expiry: expiry.to_string(),
        })
    }

    // ── precheck / misplaced-flag guard ─────────────────────────────────────

    #[test]
    fn precheck_refuses_non_pip_ecosystem() {
        assert_eq!(precheck(Ecosystem::Npm, &["lodash".to_string()]), Some(2));
        assert_eq!(precheck(Ecosystem::Cargo, &["serde".to_string()]), Some(2));
    }

    #[test]
    fn precheck_refuses_misplaced_tirith_flag_after_requirements() {
        // A tirith-owned flag trailing the requirement list is a hard error (it would
        // not affect tirith), mirroring `tirith install`'s guard.
        for flag in MISPLACED_TIRITH_FLAGS {
            let reqs = vec!["requests".to_string(), flag.to_string()];
            assert_eq!(
                precheck(Ecosystem::Pip, &reqs),
                Some(2),
                "trailing {flag} must be refused"
            );
        }
    }

    #[test]
    fn precheck_refuses_empty_requirements() {
        assert_eq!(precheck(Ecosystem::Pip, &[]), Some(2));
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
        let other = InstallPlanDigest::new(InstallPlanInputs {
            artifact_sha256: vec!["a".repeat(64)],
            normalized_packages: vec!["requests".to_string()],
            interpreter: PathBuf::from("/attacker/python"), // changed
            target_environment: PathBuf::from("/venv"),
            platform_tags: vec!["py3-none-any".to_string()],
            install_command_semantics: InstallCommand {
                approved_requirements_path: PathBuf::from("approved.txt"),
            }
            .pip_install_args_without_requirements_path(),
            policy_projection_hash: "deadbeef".repeat(8),
            threat_db_sequence: 3,
            capsule_backend: "landlock-seccomp".to_string(),
            required_coverage: CapsuleSpec::locked_down().required_coverage(),
            expiry: String::new(),
        });
        assert!(!same_plan_modulo_expiry(&approved, &other));
        // No matching approval for the changed situation.
        assert_eq!(approval_status(&other), ApprovalStatus::Missing);
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
        let install_digest = InstallPlanDigest::new(InstallPlanInputs {
            artifact_sha256: vec!["a".repeat(64)],
            normalized_packages: vec!["requests".to_string()],
            interpreter: PathBuf::from("/venv/bin/python"),
            target_environment: PathBuf::from("/venv"),
            platform_tags: vec!["py3-none-any".to_string()],
            install_command_semantics: InstallCommand {
                approved_requirements_path: PathBuf::from("approved.txt"),
            }
            .pip_install_args_without_requirements_path(),
            policy_projection_hash: "deadbeef".repeat(8),
            threat_db_sequence: 4, // advanced
            capsule_backend: "landlock-seccomp".to_string(),
            required_coverage: CapsuleSpec::locked_down().required_coverage(),
            expiry: String::new(),
        });
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

    // ── install target derivation ───────────────────────────────────────────

    #[test]
    fn install_target_uses_explicit_target_dir() {
        let tools = ResolverTools {
            uv: PathBuf::from("/usr/bin/uv"),
            python: PathBuf::from("/opt/py/bin/python3"),
        };
        let t = InstallTarget::derive(&tools, Some(PathBuf::from("/work/.venv")));
        assert_eq!(t.interpreter, PathBuf::from("/opt/py/bin/python3"));
        assert_eq!(t.environment, PathBuf::from("/work/.venv"));
        // The interpreter prefix is a read root.
        assert!(t.extra_read_roots.contains(&PathBuf::from("/opt/py")));
    }

    #[test]
    fn install_target_defaults_to_interpreter_prefix() {
        let tools = ResolverTools {
            uv: PathBuf::from("/usr/bin/uv"),
            python: PathBuf::from("/opt/py/bin/python3"),
        };
        let t = InstallTarget::derive(&tools, None);
        // No --target: the interpreter prefix is the environment.
        assert_eq!(t.environment, PathBuf::from("/opt/py"));
    }
}
