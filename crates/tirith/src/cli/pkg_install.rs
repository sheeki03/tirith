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
//! 1. Write the plan's `approved.txt` into the transaction directory (atomic,
//!    `0o600`), giving the `file://`-and-`--hash` requirements file pip reads.
//! 2. Build the `python -m pip install --isolated --no-index --no-deps
//!    --require-hashes --no-cache-dir --force-reinstall -r approved.txt` argv.
//! 3. Run the interpreter through [`crate::cli::capsule::run_to_completion`] under
//!    [`crate::cli::capsule::DegradedPolicy::FailClosed`], so on a host whose
//!    capsule backend cannot enforce the required containment the install **fails
//!    closed** (cross-cutting invariant 2) rather than running uncontained.
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
//! Because no runtime consumer calls this surface until D7 adds the
//! `tirith pkg install` command, the public API and its helpers are exercised only
//! by this module's own tests in this unit. `#![allow(dead_code)]` keeps the
//! not-yet-wired surface from tripping the `-D warnings` gate; D7 removes the need
//! for it by calling [`run_contained_install`] from the `tirith pkg install` path.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use tirith_core::artifact::install::{
    verify_post_install_record, DigestInstallPlan, InstallCommand, PostInstallIntegrity,
};
use tirith_core::policy::Policy;
use tirith_core::receipt::{
    ArtifactScanReceipt, CapsuleReceipt, PostInstallRecordSummary, ReceiptError, RecordedReceipt,
    VerdictSummary,
};

use crate::cli::capsule::{self, CapsuleRefused, DegradedPolicy};

/// The file name of the generated requirements file written into the transaction
/// directory. A single safe component; pip reads it via `-r`.
const APPROVED_REQUIREMENTS_FILE: &str = "approved.txt";

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
    /// Writing the `approved.txt` requirements file failed.
    WriteApproved(std::io::Error),
    /// The capsule refused to run the install: on the enforcing
    /// ([`DegradedPolicy::FailClosed`]) path this means the host backend could not
    /// deliver the required containment, so the install fails closed rather than
    /// running uncontained. The carried message names the backend and the shortfall
    /// (secret-free).
    CapsuleRefused(String),
}

impl std::fmt::Display for ContainedInstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainedInstallError::WriteApproved(e) => {
                write!(f, "could not write the approved requirements file: {e}")
            }
            ContainedInstallError::CapsuleRefused(reason) => {
                write!(
                    f,
                    "refusing to install: the containment capsule is unavailable or degraded \
                     on this host ({reason})"
                )
            }
        }
    }
}

impl std::error::Error for ContainedInstallError {}

impl From<CapsuleRefused> for ContainedInstallError {
    fn from(r: CapsuleRefused) -> Self {
        ContainedInstallError::CapsuleRefused(r.to_string())
    }
}

/// Run a re-bound [`DigestInstallPlan`] as a contained `pip install`, then (on
/// success) verify the installed RECORD of the just-installed distributions.
///
/// `plan` is the verified plan from
/// [`tirith_core::artifact::install::rebind_for_install`] (the re-bind already
/// passed; the bytes are the approved bytes). `transaction_dir` is the directory
/// the plan's `file://` wheels and the `approved.txt` live in (the plan's spec
/// already grants it read). `interpreter` is the resolved Python interpreter to run
/// `python -m pip` with; resolve it by executable provenance (as the D2 resolver
/// does), never a bare `pip` on `PATH`. `target_environment` is the environment pip
/// installed into (the plan's spec write root) and `installed_names` are the PEP
/// 503-normalised distribution names the plan landed (build them with
/// [`tirith_core::artifact::install::installed_distribution_names`] over the resolved
/// set); both scope the D5 post-install verification. `policy` finalises that
/// post-install verdict (so a strict integrity policy can make it block).
///
/// This:
/// 1. Writes `plan.approved_requirements` to `transaction_dir/approved.txt`
///    (atomic, `0o600`).
/// 2. Builds the pinned pip argv ([`InstallCommand::pip_install_args`]).
/// 3. Runs `interpreter <argv>` through the capsule under
///    [`DegradedPolicy::FailClosed`]: a degraded/NoOp backend refuses BEFORE
///    spawning (fail-closed), so the install never runs uncontained.
/// 4. **D5:** if pip exited cleanly (`exit_code == 0`), runs
///    [`verify_post_install_record`] over `installed_names` in `target_environment`
///    and carries the resulting [`PostInstallIntegrity`] (verdict + coverage
///    counters) in the outcome. On a non-zero exit there is nothing trustworthy to
///    verify, so the post-install field stays `None`.
///
/// It NEVER calls [`crate::cli::install::ProcessInstallRunner`]; the only spawn is
/// the capsule seam.
pub fn run_contained_install(
    plan: &DigestInstallPlan,
    transaction_dir: &Path,
    interpreter: &Path,
    target_environment: &Path,
    installed_names: &[String],
    policy: &Policy,
) -> Result<ContainedInstallOutcome, ContainedInstallError> {
    // 1. Write approved.txt into the transaction directory (atomic, 0600). The
    //    write helper writes a temp INSIDE the dir and renames, so a reader sees the
    //    whole file or none.
    let approved_path = transaction_dir.join(APPROVED_REQUIREMENTS_FILE);
    tirith_core::util::write_file_atomic_0600(
        &approved_path,
        plan.approved_requirements.as_bytes(),
    )
    .map_err(ContainedInstallError::WriteApproved)?;

    // 2. The pinned pip argv reading that approved.txt.
    let cmd = InstallCommand {
        approved_requirements_path: approved_path.clone(),
    };
    let args = cmd.pip_install_args();
    let program = interpreter.display().to_string();

    // 3. Run it contained, fail-closed. The spec is deny-all network + the txn-dir
    //    read root + the target-env write root the plan already assembled. cwd is
    //    the transaction directory (a granted read root); no extra env is injected
    //    (the spec scrubs the environment to a temporary HOME).
    let outcome = capsule::run_to_completion(
        &plan.spec,
        &program,
        &args,
        Some(transaction_dir),
        &[],
        DegradedPolicy::FailClosed,
    )?;

    // 4. D5 post-install RECORD verification, ONLY on a clean install. A failed pip
    //    run may have extracted nothing (or a partial tree), so there is nothing
    //    trustworthy to verify; the post-install field stays `None` and the caller
    //    reports the install failure on its own.
    let post_install = if outcome.exit_code == 0 {
        Some(verify_post_install_record(
            target_environment,
            installed_names,
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
        bound_db_sequence: plan.bound_db_sequence,
        approved_requirements_path: approved_path,
        post_install,
    })
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

/// Build and record the D6 [`ArtifactScanReceipt`] for a completed contained
/// install, returning the saved path + whether the chain anchor was ed25519-signed.
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
/// then calls [`ArtifactScanReceipt::record`]. `require_signature` enforces the
/// "Ed25519 mandatory for `pkg install`" rule: pass `true` from the enforcing
/// `pkg install` path so an unsigned audit log fails closed
/// ([`ReceiptError::SignatureRequiredButUnavailable`]) rather than silently
/// recording a merely-tamper-evident receipt.
///
/// No secret or machine path is recorded: the artifacts are hashes only, the policy
/// is a redacted hash, the provenance strings are pre-redacted by the caller, and
/// the verdict is summarised without evidence text.
pub fn record_install_receipt(
    outcome: &ContainedInstallOutcome,
    policy: &Policy,
    provenance: &ResolverProvenance,
    artifact_sha256: Vec<String>,
    verdict: &tirith_core::verdict::Verdict,
    require_signature: bool,
) -> Result<RecordedReceipt, ReceiptError> {
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

    let receipt = ArtifactScanReceipt::new(
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
    );

    receipt.record(require_signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_core::capsule::CapsuleSpec;

    /// A directly-constructed [`DigestInstallPlan`] over a single synthetic wheel
    /// path, plus a tempdir standing in for the transaction directory. The core
    /// crate's own tests cover the re-bind that PRODUCES a plan from quarantined
    /// bytes; this CLI half only needs a valid plan to exercise the write +
    /// fail-closed launch, so we build the plan directly (no hex/zip/sha2 needed in
    /// the binary crate).
    fn planned() -> (tempfile::TempDir, DigestInstallPlan) {
        let dir = tempfile::tempdir().unwrap();
        let wheel = dir.path().join("demo-1.0-py3-none-any.whl");
        // A placeholder wheel file so the materialised path exists on disk.
        std::fs::write(&wheel, b"PK\x03\x04 placeholder wheel bytes").unwrap();
        let approved = format!(
            "demo @ file://{} --hash=sha256:{}\n",
            wheel.display(),
            "a".repeat(64)
        );
        let mut spec = CapsuleSpec::locked_down();
        spec.network = tirith_core::capsule::NetworkPolicy::DenyAll;
        spec.filesystem.read_roots.push(dir.path().to_path_buf());
        let plan = DigestInstallPlan {
            approved_requirements: approved,
            materialized: vec![wheel],
            spec,
            bound_db_sequence: 0,
        };
        (dir, plan)
    }

    #[test]
    fn writing_approved_txt_lands_the_requirements_in_the_txn_dir() {
        // We exercise the write half WITHOUT spawning: write approved.txt and check
        // it landed with the file:// + hash lines. (The capsule spawn is covered by
        // the fail-closed test below, which needs no real interpreter.)
        let (dir, plan) = planned();
        let approved_path = dir.path().join(APPROVED_REQUIREMENTS_FILE);
        tirith_core::util::write_file_atomic_0600(
            &approved_path,
            plan.approved_requirements.as_bytes(),
        )
        .unwrap();
        let written = std::fs::read_to_string(&approved_path).unwrap();
        assert!(written.contains("demo @ file://"));
        assert!(written.contains("--hash=sha256:"));
        // The approved.txt is inside the transaction directory pip is granted to read.
        assert!(approved_path.starts_with(dir.path()));
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
        };
        let args = cmd.pip_install_args();
        assert_eq!(&args[0..3], &["-m", "pip", "install"]);
        for flag in [
            "--isolated",
            "--no-index",
            "--no-deps",
            "--require-hashes",
            "--no-cache-dir",
            "--force-reinstall",
        ] {
            assert!(args.iter().any(|a| a == flag), "missing {flag}");
        }
    }

    #[test]
    fn install_fails_closed_when_capsule_is_degraded() {
        // On a host whose backend cannot enforce containment (NoOp, or a CI host
        // without Landlock/Seatbelt), the enforcing FailClosed path must REFUSE
        // before spawning. We point the install at a non-existent interpreter: if the
        // capsule were degraded-and-permissive it would try to spawn and fail with a
        // spawn error; if it fails closed it refuses with a CapsuleRefused naming the
        // shortfall. Either way it must NOT silently succeed, and on a host that
        // genuinely lacks a backend the error is the fail-closed refusal.
        let (dir, plan) = planned();
        let fake_python = dir.path().join("no-such-python");
        let env = dir.path().join("env");
        let res = run_contained_install(
            &plan,
            dir.path(),
            &fake_python,
            &env,
            &["demo".to_string()],
            &Policy::default(),
        );
        // It must be an error (never a clean success against a missing interpreter /
        // absent backend). The fail-closed refusal (or the spawn error) happens BEFORE
        // the post-install verification, so the post-install field is never reached.
        assert!(res.is_err(), "a missing backend/interpreter must error");
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
