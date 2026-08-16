//! C17 integration tests for `tirith pkg attest-npm`.
//!
//! In its own file rather than appended to `cli_integration.rs`: every test
//! assembles a project tree plus a fake npm, and the no-speculative-probe and
//! receipt-privacy assertions are the point of the slice, so they should be
//! findable.
//!
//! # Why the sandbox is laid out the way it is
//!
//! `trusted_child::resolve_ambient` refuses an executable under a denied root,
//! and `ambient_denied_roots()` denies `/tmp`, `/var/tmp`, `/var/folders`,
//! `std::env::temp_dir()`, AND the repository root it finds by walking up from
//! the child's working directory. A fake npm under `tempfile::tempdir()` can
//! therefore never resolve, and neither can one under this repository.
//!
//! So each test builds:
//!
//! ```text
//! <CARGO_TARGET_TMPDIR>/npm-attest-c17/<n>/
//!   tools/npm            the fake npm (0755)
//!   fixtures/*           whatever stdout the fake npm prints
//!   project/.git/        a repo marker, so the denied-root walk STOPS here
//!   project/...          package-lock.json + node_modules
//!   home/                a hermetic HOME
//! ```
//!
//! and runs tirith with `cwd = project`. The walk finds `project/.git` first,
//! so the denied root is `project`, and `tools/` (its sibling) is allowed. No
//! test writes outside `CARGO_TARGET_TMPDIR`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use tirith_core::provenance::npm::{
    self as core_npm, InstalledInventory, InstalledPackage, NpmAttestOutcome, NpmPartialReason,
};

/// The two-package project the real npm 11.17.0 capture was taken from.
const CHALK: &str = "node_modules/chalk";
const SEMVER: &str = "node_modules/semver";

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/npm_audit_signatures")
}

fn fixture(name: &str) -> String {
    fs::read_to_string(fixture_root().join(name))
        .unwrap_or_else(|error| panic!("read fixture {name}: {error}"))
}

// ---------------------------------------------------------------------------
// Sandbox
// ---------------------------------------------------------------------------

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("npm-attest-c17")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        // A previous run of the same pid slot must not leak into this one.
        let _ = fs::remove_dir_all(&root);
        for relative in ["tools", "fixtures", "project/.git", "home", "home/config"] {
            fs::create_dir_all(root.join(relative)).expect("create sandbox directory");
        }
        Self { root }
    }

    fn project(&self) -> PathBuf {
        self.root.join("project")
    }

    fn argv_log(&self) -> PathBuf {
        self.root.join("argv.log")
    }

    /// Every argv the fake npm was invoked with, one per line. Empty (and the
    /// file absent) when it was never spawned.
    fn recorded_argv(&self) -> Vec<String> {
        fs::read_to_string(self.argv_log())
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Write a fixture file the fake npm can print, returning its path.
    fn stdout_fixture(&self, name: &str, body: &str) -> PathBuf {
        let path = self.root.join("fixtures").join(name);
        fs::write(&path, body).expect("write stdout fixture");
        path
    }

    /// Install the project's `package-lock.json`.
    fn lockfile(&self, body: &str) {
        fs::write(self.project().join("package-lock.json"), body).expect("write lockfile");
    }

    /// Build `node_modules/<name>` with a minimal installed manifest.
    fn install_package(&self, name: &str, version: &str) {
        let directory = self.project().join("node_modules").join(name);
        fs::create_dir_all(&directory).expect("create node_modules entry");
        fs::write(
            directory.join("package.json"),
            format!(r#"{{"name":"{name}","version":"{version}"}}"#),
        )
        .expect("write installed manifest");
    }

    /// Write the project's own `.npmrc`.
    fn project_npmrc(&self, body: &str) {
        fs::write(self.project().join(".npmrc"), body).expect("write project .npmrc");
    }

    /// Write a fake npm verbatim, for the cases the template cannot express.
    fn install_raw_npm(&self, script: &str) -> PathBuf {
        let path = self.root.join("tools").join("npm");
        fs::write(&path, script).expect("write fake npm");
        set_mode(&path, 0o755);
        path
    }

    /// Install the two-package tree the real capture came from.
    fn install_capture_tree(&self) {
        self.lockfile(&fixture("npm11_clean_package-lock.json"));
        self.install_package("chalk", "5.4.1");
        self.install_package("semver", "7.8.5");
    }

    /// Write the fake npm.
    ///
    /// It always appends its argv to `argv.log` FIRST, so "was it spawned at
    /// all?" is observable even when the run fails. `--version` prints
    /// `version`. The exact contracted argv runs `audit_body`. Anything else is
    /// the hard error a future npm would produce for an unrecognized flag.
    fn install_fake_npm(&self, version: &str, audit_body: &str) -> PathBuf {
        let path = self.root.join("tools").join("npm");
        let script = FAKE_NPM_TEMPLATE
            .replace("@@LOG@@", &self.argv_log().display().to_string())
            .replace("@@VERSION@@", version)
            .replace("@@AUDIT@@", audit_body);
        fs::write(&path, script).expect("write fake npm");
        set_mode(&path, 0o755);
        path
    }

    /// The command, with a hermetic environment and `PATH` pointed at the fake
    /// npm plus the system directories its shell body needs.
    fn tirith(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_tirith"));
        let home = self.root.join("home");
        cmd.current_dir(self.project())
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.root.join("tools").display()),
            )
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_DATA_HOME", home.join("config"))
            .env("XDG_STATE_HOME", home.join("config"))
            .env("XDG_CACHE_HOME", home.join("config"))
            .env("APPDATA", home.join("config"))
            .env("LOCALAPPDATA", home.join("config"))
            .env("TIRITH_LOG", "0")
            .env_remove("TIRITH_OFFLINE")
            .env_remove("TIRITH_POLICY_ROOT")
            .env_remove("SSH_AUTH_SOCK");
        cmd
    }

    /// Run `pkg attest-npm --format json` and return `(exit code, receipt)`.
    fn attest(&self, extra: &[&str]) -> (i32, serde_json::Value) {
        let output = self
            .tirith()
            .args(["pkg", "attest-npm", "--project"])
            .arg(self.project())
            .args(["--format", "json"])
            .args(extra)
            .output()
            .expect("run tirith pkg attest-npm");
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let value: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
            panic!(
                "attest-npm must emit JSON ({error}); stdout: {stdout}; stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output.status.code().unwrap_or(-1), value)
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

const FAKE_NPM_TEMPLATE: &str = r#"#!/bin/sh
printf '%s\n' "$*" >> '@@LOG@@'
if [ "$1" = "--version" ]; then
  printf '%s\n' '@@VERSION@@'
  exit 0
fi
if [ "$#" -eq 4 ] && [ "$1" = "audit" ] && [ "$2" = "signatures" ] && [ "$3" = "--json" ] && [ "$4" = "--include-attestations" ]; then
@@AUDIT@@
fi
printf 'Unknown argument: %s\n' "$*" >&2
exit 1
"#;

/// An audit body that prints a fixture file and exits with `code`.
fn print_fixture(path: &Path, code: i32) -> String {
    format!("  cat '{}'\n  exit {code}", path.display())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set mode");
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

fn outcome(receipt: &serde_json::Value) -> &str {
    receipt["outcome"]["outcome"]
        .as_str()
        .unwrap_or("<missing>")
}

fn partial_reason(receipt: &serde_json::Value) -> &str {
    receipt["outcome"]["reason"].as_str().unwrap_or("<missing>")
}

/// The status label recorded for one install location.
fn status_of<'a>(receipt: &'a serde_json::Value, location: &str) -> &'a str {
    receipt["packages"]
        .as_array()
        .expect("packages array")
        .iter()
        .find(|record| record["location"] == location)
        .unwrap_or_else(|| panic!("no record for {location} in {receipt}"))["status"]["status"]
        .as_str()
        .expect("status label")
}

// ---------------------------------------------------------------------------
// The contract table and its fixtures (no process involved)
// ---------------------------------------------------------------------------

/// Every contract entry must have a committed stdout fixture that parses to the
/// schema it declares. This is what keeps the table honest: a range cannot be
/// added without evidence of what that npm actually prints.
#[test]
fn every_contract_entry_has_a_fixture_that_parses_to_its_declared_schema() {
    assert!(
        !core_npm::NPM_AUDIT_SIGNATURES_CONTRACTS.is_empty(),
        "the contract table must not be empty"
    );
    for contract in core_npm::NPM_AUDIT_SIGNATURES_CONTRACTS {
        let path = fixture_root().join(contract.fixture);
        assert!(
            path.is_file(),
            "contract {} declares fixture {} which does not exist",
            contract.id,
            contract.fixture
        );
        let body = fs::read_to_string(&path).expect("read contract fixture");
        core_npm::parse_audit_report(&body, contract.schema).unwrap_or_else(|error| {
            panic!(
                "contract {} fixture {} must parse to its declared schema: {error:?}",
                contract.id, contract.fixture
            )
        });
    }
}

/// The npm 11 fixture and the lockfile it was captured with bind end to end:
/// `semver` is attested and its in-toto subject digest matches the lockfile
/// SRI; `chalk` is signature-only by subtraction; the project is clean.
#[test]
fn the_captured_npm11_run_binds_its_attested_subject_to_the_lockfile() {
    let lockfile = core_npm::parse_package_lock(&fixture("npm11_clean_package-lock.json"))
        .expect("the captured lockfile parses");
    let report = core_npm::parse_audit_report(
        &fixture("npm11_clean.json"),
        core_npm::NpmAuditJsonSchema::BucketsWithAttestedVerified,
    )
    .expect("the captured stdout parses");
    let inventory = InstalledInventory {
        packages: [CHALK, SEMVER]
            .into_iter()
            .map(|location| InstalledPackage {
                location: location.to_string(),
                name: None,
                version: None,
            })
            .collect(),
        capped: false,
        symlinked_entries: 0,
    };
    let assessment = core_npm::reconcile(&lockfile, &inventory, Some(&report));
    let by_location: std::collections::BTreeMap<&str, &core_npm::NpmPackageRecord> = assessment
        .records
        .iter()
        .map(|record| (record.location.as_str(), record))
        .collect();

    match &by_location[SEMVER].status {
        core_npm::NpmPackageStatus::ProvenanceVerified {
            predicate_types,
            subject_bound,
        } => {
            assert!(
                *subject_bound,
                "the attested sha512 must bind to the lockfile integrity SRI"
            );
            assert!(
                predicate_types
                    .iter()
                    .any(|predicate| predicate == "https://slsa.dev/provenance/v1"),
                "the SLSA predicate type is recorded: {predicate_types:?}"
            );
        }
        other => panic!("semver must be provenance-verified, got {other:?}"),
    }
    assert_eq!(by_location[CHALK].status.label(), "signature-only");
    assert!(assessment.coverage.signature_only_derived_by_subtraction);
    assert_eq!(
        core_npm::overall_outcome(&assessment.statuses(), false),
        NpmAttestOutcome::Clean
    );
}

/// Flip one byte of the lockfile's `integrity` for the attested package and the
/// attestation now covers different bytes than the lockfile pins. That is a
/// mismatch, not a partial.
#[test]
fn a_lockfile_integrity_that_disagrees_with_the_attestation_is_a_mismatch() {
    let original = fixture("npm11_clean_package-lock.json");
    // A well-formed 64-byte sha512 that is simply a DIFFERENT digest. It has to
    // decode cleanly: an SRI that cannot be decoded is "not comparable", which
    // is a coverage gap rather than the disagreement this test is about.
    let mutated = original.replace(
        "sha512-Y7/KDsb8LjooZpwaqGyulO6DQlksgCncchHGk+sZIY4SBvUocMBEFH5Ur1fI4dV+Jvl0w6cjvucaIi40puRioA==",
        "sha512-q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urqw==",
    );
    assert_ne!(original, mutated, "the mutation must apply");
    let lockfile = core_npm::parse_package_lock(&mutated).expect("the mutated lockfile parses");
    let report = core_npm::parse_audit_report(
        &fixture("npm11_clean.json"),
        core_npm::NpmAuditJsonSchema::BucketsWithAttestedVerified,
    )
    .expect("the captured stdout parses");
    let inventory = InstalledInventory {
        packages: [CHALK, SEMVER]
            .into_iter()
            .map(|location| InstalledPackage {
                location: location.to_string(),
                name: None,
                version: None,
            })
            .collect(),
        capped: false,
        symlinked_entries: 0,
    };
    let assessment = core_npm::reconcile(&lockfile, &inventory, Some(&report));
    let semver = assessment
        .records
        .iter()
        .find(|record| record.location == SEMVER)
        .expect("semver record");
    match &semver.status {
        core_npm::NpmPackageStatus::Invalid { code, .. } => assert_eq!(code, "ESUBJECTINTEGRITY"),
        other => panic!("a subject-digest disagreement must be Invalid, got {other:?}"),
    }
    assert!(matches!(
        core_npm::overall_outcome(&assessment.statuses(), false),
        NpmAttestOutcome::Mismatch { .. }
    ));
}

// ---------------------------------------------------------------------------
// End-to-end, through the real binary
// ---------------------------------------------------------------------------

/// Offline returns partial and NEVER resolves or spawns npm. Proven by a fake
/// npm that records every invocation: the log must not exist at all.
#[test]
#[cfg(unix)]
fn offline_returns_partial_without_ever_spawning_npm() {
    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    let stdout = sandbox.stdout_fixture("clean.json", &fixture("npm11_clean.json"));
    sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 0));

    let output = sandbox
        .tirith()
        .env("TIRITH_OFFLINE", "1")
        .args(["pkg", "attest-npm", "--project"])
        .arg(sandbox.project())
        .args(["--format", "json"])
        .output()
        .expect("run tirith pkg attest-npm");
    let receipt: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("attest-npm emits JSON");

    assert_eq!(output.status.code(), Some(3), "partial exits 3");
    assert_eq!(outcome(&receipt), "partial");
    assert_eq!(partial_reason(&receipt), "offline");
    assert!(
        sandbox.recorded_argv().is_empty(),
        "offline mode must not spawn npm at all, got {:?}",
        sandbox.recorded_argv()
    );
    assert!(
        receipt["invocation"].is_null(),
        "no contract may be recorded when nothing ran"
    );
    // The local binding still happened: the lockfile was read and hashed.
    assert!(receipt["subject"]["lockfile_sha256"].is_string());
}

/// An npm outside every contract range is discovered by VERSION and then
/// refused. The version probe runs; the audit command does not.
#[test]
#[cfg(unix)]
fn an_unsupported_npm_version_runs_the_version_probe_and_no_audit_command() {
    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    let stdout = sandbox.stdout_fixture("clean.json", &fixture("npm11_clean.json"));
    // npm 10 speaks a different `audit signatures --json` shape and has no
    // captured fixture, so it is outside the table.
    sandbox.install_fake_npm("10.9.2", &print_fixture(&stdout, 0));

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 3);
    assert_eq!(outcome(&receipt), "partial");
    assert_eq!(partial_reason(&receipt), "unsupported_npm_version");
    assert_eq!(
        receipt["tools"]["npm_version"], "10.9.2",
        "the version was discovered before the refusal"
    );
    assert_eq!(
        sandbox.recorded_argv(),
        vec!["--version".to_string()],
        "an unsupported npm must be asked for its version and nothing else"
    );
    assert!(
        receipt["invocation"].is_null(),
        "no audit command means no invocation record"
    );
    // Every eligible package degrades to not-audited rather than looking clean.
    assert_eq!(status_of(&receipt, CHALK), "not_audited");
}

/// The supported version runs EXACTLY the contract's argv, byte for byte, and
/// the captured stdout drives a clean result.
#[test]
#[cfg(unix)]
fn a_supported_npm_runs_exactly_the_contract_argv_and_reports_clean() {
    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    let stdout = sandbox.stdout_fixture("clean.json", &fixture("npm11_clean.json"));
    sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 0));

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(
        code,
        0,
        "a clean run exits 0; receipt: {}",
        serde_json::to_string_pretty(&receipt).unwrap_or_default()
    );
    assert_eq!(outcome(&receipt), "clean");
    assert_eq!(
        sandbox.recorded_argv(),
        vec![
            "--version".to_string(),
            "audit signatures --json --include-attestations".to_string()
        ],
        "the version probe precedes exactly one contracted audit command"
    );
    assert_eq!(
        receipt["invocation"]["contract_id"],
        "npm-11-audit-signatures-include-attestations"
    );
    assert_eq!(
        receipt["invocation"]["argv"],
        serde_json::json!(["audit", "signatures", "--json", "--include-attestations"])
    );
    assert_eq!(status_of(&receipt, SEMVER), "provenance_verified");
    assert_eq!(status_of(&receipt, CHALK), "signature_only");
    assert_eq!(
        receipt["subject"]["registry_hosts"],
        serde_json::json!(["registry.npmjs.org"])
    );
    // The sentence that must survive into the output.
    let caveats = serde_json::to_string(&receipt["caveats"]).unwrap_or_default();
    assert!(
        caveats.contains("does not mean the package code is benign"),
        "a clean receipt must carry the not-benign caveat: {caveats}"
    );
    assert!(
        caveats.contains("has not downloaded, inspected, or bound the tarball bytes"),
        "a clean receipt must carry C13's bytes-not-bound caveat: {caveats}"
    );
}

/// `--require-provenance` tightens the same clean run into a partial, because
/// `chalk` carries a signature and no attestation.
#[test]
#[cfg(unix)]
fn require_provenance_downgrades_a_signature_only_project_to_partial() {
    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    let stdout = sandbox.stdout_fixture("clean.json", &fixture("npm11_clean.json"));
    sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 0));

    let (code, receipt) = sandbox.attest(&["--require-provenance"]);
    assert_eq!(code, 3);
    assert_eq!(outcome(&receipt), "partial");
    assert_eq!(partial_reason(&receipt), "provenance_required_but_absent");
    assert_eq!(receipt["require_provenance"], true);
}

/// npm's `invalid` bucket is a mismatch and exits 1, for both error codes.
#[test]
#[cfg(unix)]
fn an_invalid_signature_or_attestation_is_a_mismatch() {
    for (name, expected_code) in [
        ("npm11_invalid_signature.json", "EINTEGRITYSIGNATURE"),
        ("npm11_invalid_attestation.json", "EATTESTATIONVERIFY"),
    ] {
        let sandbox = Sandbox::new();
        sandbox.install_capture_tree();
        let stdout = sandbox.stdout_fixture("audit.json", &fixture(name));
        // npm itself exits 1 whenever the invalid or missing bucket is
        // non-empty; that is a finding to parse, not a failure to run.
        sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 1));

        let (code, receipt) = sandbox.attest(&[]);
        assert_eq!(code, 1, "{name} must exit 1");
        assert_eq!(outcome(&receipt), "mismatch", "{name}");
        assert_eq!(status_of(&receipt, CHALK), "invalid", "{name}");
        assert_eq!(
            receipt["packages"]
                .as_array()
                .and_then(|records| records.iter().find(|record| record["location"] == CHALK))
                .map(|record| record["status"]["code"].clone()),
            Some(serde_json::json!(expected_code)),
            "{name} must carry npm's own error code"
        );
    }
}

/// npm's `missing` bucket is a partial: absence of a signature is a coverage
/// statement, not a failed check.
#[test]
#[cfg(unix)]
fn a_missing_registry_signature_is_partial() {
    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    let stdout = sandbox.stdout_fixture("audit.json", &fixture("npm11_missing.json"));
    sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 1));

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 3);
    assert_eq!(outcome(&receipt), "partial");
    assert_eq!(partial_reason(&receipt), "missing_signature");
    assert_eq!(status_of(&receipt, CHALK), "missing");
}

/// The four strict-JSON failures map to distinct partial reasons, and none of
/// them can read as clean.
#[test]
#[cfg(unix)]
fn every_strict_json_failure_maps_to_its_own_partial_reason() {
    for (name, expected) in [
        ("malformed_duplicate_key.json", "duplicate_json_key"),
        ("malformed_trailing_data.json", "parse_failure"),
        ("malformed_truncated.json", "parse_failure"),
        ("empty.json", "parse_failure"),
    ] {
        let sandbox = Sandbox::new();
        sandbox.install_capture_tree();
        let stdout = sandbox.stdout_fixture("audit.json", &fixture(name));
        sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 0));

        let (code, receipt) = sandbox.attest(&[]);
        assert_eq!(code, 3, "{name}");
        assert_eq!(outcome(&receipt), "partial", "{name}");
        assert_eq!(partial_reason(&receipt), expected, "{name}");
        // The contract IS recorded, because the command did run; only its
        // output was unusable.
        assert_eq!(
            receipt["invocation"]["contract_id"], "npm-11-audit-signatures-include-attestations",
            "{name}"
        );
    }
}

/// An npm that hard-errors on the contracted flag produces usage text, not
/// JSON. That must be a partial, never a silent clean.
#[test]
#[cfg(unix)]
fn a_hard_error_on_the_contract_flag_is_partial_never_clean() {
    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    let usage = fixture("unknown_flag_hard_error.txt");
    let stdout = sandbox.stdout_fixture("usage.txt", &usage);
    sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 1));

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 3);
    assert_eq!(outcome(&receipt), "partial");
    assert_eq!(partial_reason(&receipt), "parse_failure");
    assert_eq!(receipt["invocation"]["exit_code"], 1);
}

/// A stdout larger than the 8 MiB cap is refused rather than parsed from a
/// truncated document.
#[test]
#[cfg(unix)]
fn stdout_over_the_cap_is_partial_rather_than_a_truncated_parse() {
    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    let oversized = "a".repeat(9 * 1024 * 1024);
    let stdout = sandbox.stdout_fixture("huge.json", &oversized);
    sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 0));

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 3);
    assert_eq!(outcome(&receipt), "partial");
    assert_eq!(partial_reason(&receipt), "output_limit_exceeded");
}

/// npm's stderr can echo an `.npmrc` auth token and absolute home paths. The
/// receipt keeps the diagnosis and neither of those.
#[test]
#[cfg(unix)]
fn npm_stderr_reaches_the_receipt_redacted() {
    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    let stdout = sandbox.stdout_fixture("clean.json", &fixture("npm11_clean.json"));
    let body = format!(
        "{}\n  printf 'npm warn using //registry.example/:_authToken=npm_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ\\n' >&2\n  printf 'npm warn config from /Users/example/.npmrc\\n' >&2\n  exit 0",
        format_args!("  cat '{}'", stdout.display())
    );
    sandbox.install_fake_npm("11.17.0", &body);

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 0);
    let serialized = serde_json::to_string(&receipt).expect("serialize receipt");
    assert!(
        !serialized.contains("npm_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"),
        "an auth token must never reach the receipt: {serialized}"
    );
    assert!(
        !serialized.contains("/Users/example"),
        "an absolute host path must never reach the receipt: {serialized}"
    );
    let stderr = receipt["invocation"]["stderr"]
        .as_str()
        .expect("redacted stderr is recorded");
    assert!(
        stderr.contains("npm warn"),
        "the diagnosis survives redaction: {stderr}"
    );
}

/// A project with a lockfile but no install tree is partial, and nothing is
/// spawned.
#[test]
#[cfg(unix)]
fn a_missing_install_tree_is_partial_and_never_spawns() {
    let sandbox = Sandbox::new();
    sandbox.lockfile(&fixture("npm11_clean_package-lock.json"));
    let stdout = sandbox.stdout_fixture("clean.json", &fixture("npm11_clean.json"));
    sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 0));

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 3);
    assert_eq!(partial_reason(&receipt), "missing_install_tree");
    assert!(
        sandbox.recorded_argv().is_empty(),
        "no install tree means no audit command and no version probe"
    );
}

/// A project with no readable lockfile is partial with nothing bound.
#[test]
#[cfg(unix)]
fn a_missing_lockfile_is_partial_with_no_binding() {
    let sandbox = Sandbox::new();
    sandbox.install_package("chalk", "5.4.1");
    let stdout = sandbox.stdout_fixture("clean.json", &fixture("npm11_clean.json"));
    sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 0));

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 3);
    assert_eq!(partial_reason(&receipt), "missing_lockfile");
    assert!(receipt["subject"]["lockfile_sha256"].is_null());
    assert!(sandbox.recorded_argv().is_empty());
}

/// An installed package with no lockfile entry is unaccounted for, and one
/// unaccounted entry makes the whole receipt partial rather than clean.
#[test]
#[cfg(unix)]
fn an_unaccounted_installed_package_forces_partial() {
    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    sandbox.install_package("stowaway", "9.9.9");
    let stdout = sandbox.stdout_fixture("clean.json", &fixture("npm11_clean.json"));
    sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 0));

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 3);
    assert_eq!(outcome(&receipt), "partial");
    assert_eq!(partial_reason(&receipt), "not_audited");
    assert_eq!(receipt["coverage"]["unaccounted_installed"], 1);
    assert_eq!(
        receipt["coverage"]["unaccounted_locations"],
        serde_json::json!(["node_modules/stowaway"])
    );
    assert_eq!(status_of(&receipt, "node_modules/stowaway"), "not_audited");
}

/// git, file, link, and workspace dependencies stay explicit in the ledger and
/// force partial rather than being silently dropped.
#[test]
#[cfg(unix)]
fn unsupported_dependency_sources_stay_explicit() {
    let sandbox = Sandbox::new();
    sandbox.lockfile(
        r#"{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "demo", "version": "1.0.0"},
    "node_modules/from-git": {
      "version": "1.0.0",
      "resolved": "git+ssh://git@github.com/owner/repo.git#deadbeef"
    },
    "node_modules/from-file": {"version": "1.0.0", "resolved": "file:../sibling"},
    "node_modules/linked": {"link": true}
  }
}"#,
    );
    sandbox.install_package("from-git", "1.0.0");
    sandbox.install_package("from-file", "1.0.0");
    sandbox.install_package("linked", "1.0.0");
    let empty = sandbox.stdout_fixture(
        "empty-buckets.json",
        "{\"invalid\":[],\"missing\":[],\"verified\":[]}\n",
    );
    sandbox.install_fake_npm("11.17.0", &print_fixture(&empty, 0));

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 3);
    assert_eq!(partial_reason(&receipt), "unsupported_source");
    assert_eq!(receipt["coverage"]["unsupported_source_entries"], 3);
    for location in [
        "node_modules/from-git",
        "node_modules/from-file",
        "node_modules/linked",
    ] {
        assert_eq!(
            status_of(&receipt, location),
            "unsupported_source",
            "{location}"
        );
    }
    assert_eq!(receipt["coverage"]["unaccounted_installed"], 0);
}

/// `--out` writes the receipt at mode 0600, and its content hash equals its
/// recorded id.
#[test]
#[cfg(unix)]
fn the_out_receipt_is_0600_and_content_addressed() {
    use std::os::unix::fs::PermissionsExt as _;

    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    let stdout = sandbox.stdout_fixture("clean.json", &fixture("npm11_clean.json"));
    sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 0));
    let out = sandbox.root.join("receipt.json");

    let output = sandbox
        .tirith()
        .args(["pkg", "attest-npm", "--project"])
        .arg(sandbox.project())
        .arg("--out")
        .arg(&out)
        .output()
        .expect("run tirith pkg attest-npm");
    assert_eq!(output.status.code(), Some(0));

    let mode = fs::metadata(&out)
        .expect("receipt exists")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "the receipt is written 0600");

    let written = fs::read_to_string(&out).expect("read receipt");
    let receipt: core_npm::NpmProvenanceReceipt =
        serde_json::from_str(&written).expect("the receipt round-trips");
    assert!(
        receipt.content_hash_matches(),
        "the receipt id must equal the hash of its canonical content"
    );
    receipt.validate().expect("the written receipt validates");
    assert!(!receipt.audit_chain_anchored);
    // The human rendering must carry the same sentence the JSON does.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not mean the package code is benign"),
        "the human output must carry the not-benign caveat: {stderr}"
    );
}

/// A fake npm made group-writable fails closed at resolution: the run reports
/// partial with an npm-not-resolved reason, and no audit command runs.
#[test]
#[cfg(unix)]
fn a_group_writable_npm_fails_closed_at_resolution() {
    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    let stdout = sandbox.stdout_fixture("clean.json", &fixture("npm11_clean.json"));
    let npm = sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 0));
    set_mode(&npm, 0o775);

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 3);
    assert_eq!(partial_reason(&receipt), "npm_not_resolved");
    assert!(
        sandbox.recorded_argv().is_empty(),
        "an untrusted npm is never executed"
    );
}

// ---------------------------------------------------------------------------
// The subtraction rule and the buckets it subtracts from
// ---------------------------------------------------------------------------

/// A two-entry lockfile where only `chalk` is installed and `fsevents` is not,
/// which is what `npm ci --omit=dev` and every platform-specific optional
/// dependency leave behind.
const PARTLY_INSTALLED_LOCKFILE: &str = r#"{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "demo", "version": "1.0.0"},
    "node_modules/chalk": {
      "version": "5.4.1",
      "resolved": "https://registry.npmjs.org/chalk/-/chalk-5.4.1.tgz",
      "integrity": "sha512-zgVZuo2WcZgfUEmsn6eO3kINexW8RAE4maiQ8QNs8CtpPCSyMiYsULR3HQYkm3w8FIA3SberyMJMSldGsW+U3w=="
    },
    "node_modules/fsevents": {
      "version": "2.3.3",
      "resolved": "https://registry.npmjs.org/fsevents/-/fsevents-2.3.3.tgz",
      "integrity": "sha512-5xoDfX+fL7faATnagmWPpbFtwh/R77WmMMqqHGS65C3vvB0YHrgF+B1YmZ3441tMj5n63k0212XNoJwzlhffQw=="
    }
  }
}"#;

const EMPTY_BUCKETS: &str = "{\"invalid\":[],\"missing\":[],\"verified\":[]}\n";

/// npm skips a lockfile entry with no installed version outright, so it is in
/// none of the three buckets for a reason that has nothing to do with its
/// signature. Subtracting from empty buckets there fabricates a verdict.
#[test]
#[cfg(unix)]
fn an_uninstalled_lockfile_entry_is_never_reported_as_signature_verified() {
    let sandbox = Sandbox::new();
    sandbox.lockfile(PARTLY_INSTALLED_LOCKFILE);
    sandbox.install_package("chalk", "5.4.1");
    let empty = sandbox.stdout_fixture("empty.json", EMPTY_BUCKETS);
    sandbox.install_fake_npm("11.17.0", &print_fixture(&empty, 0));

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 3, "an unaudited entry cannot exit 0: {receipt}");
    assert_eq!(outcome(&receipt), "partial");
    assert_eq!(partial_reason(&receipt), "not_audited");
    assert_eq!(status_of(&receipt, "node_modules/chalk"), "signature_only");
    assert_eq!(status_of(&receipt, "node_modules/fsevents"), "not_audited");
}

/// A registry that serves no signing keys puts a package in no bucket either,
/// and tirith cannot ask a host whether it serves keys without trusting it.
#[test]
#[cfg(unix)]
fn a_keyless_private_registry_is_never_reported_as_signature_verified() {
    let sandbox = Sandbox::new();
    sandbox.lockfile(
        r#"{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "demo", "version": "1.0.0"},
    "node_modules/internal": {
      "version": "1.0.0",
      "resolved": "https://npm.internal.example/internal/-/internal-1.0.0.tgz",
      "integrity": "sha512-aaaa"
    }
  }
}"#,
    );
    sandbox.install_package("internal", "1.0.0");
    let empty = sandbox.stdout_fixture("empty.json", EMPTY_BUCKETS);
    sandbox.install_fake_npm("11.17.0", &print_fixture(&empty, 0));

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 3, "receipt: {receipt}");
    assert_eq!(partial_reason(&receipt), "not_audited");
    assert_eq!(status_of(&receipt, "node_modules/internal"), "not_audited");
}

/// A dependency pinned to a bare tarball URL is `type: remote` to npm, which
/// never audits it. Reporting it as carrying a verified npm registry signature
/// is a claim about an arbitrary attacker-hosted file.
#[test]
#[cfg(unix)]
fn a_bare_remote_tarball_is_never_reported_as_registry_signed() {
    let sandbox = Sandbox::new();
    sandbox.lockfile(
        r#"{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "demo", "version": "1.0.0"},
    "node_modules/chalk": {
      "version": "5.4.1",
      "resolved": "https://registry.npmjs.org/chalk/-/chalk-5.4.1.tgz",
      "integrity": "sha512-zgVZuo2WcZgfUEmsn6eO3kINexW8RAE4maiQ8QNs8CtpPCSyMiYsULR3HQYkm3w8FIA3SberyMJMSldGsW+U3w=="
    },
    "node_modules/payload": {
      "version": "1.0.0",
      "resolved": "https://cdn.attacker.test/payload.tgz",
      "integrity": "sha512-aaaa"
    }
  }
}"#,
    );
    sandbox.install_package("chalk", "5.4.1");
    sandbox.install_package("payload", "1.0.0");
    let empty = sandbox.stdout_fixture("empty.json", EMPTY_BUCKETS);
    sandbox.install_fake_npm("11.17.0", &print_fixture(&empty, 0));

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 3, "receipt: {receipt}");
    assert_eq!(partial_reason(&receipt), "unsupported_source");
    assert_eq!(
        status_of(&receipt, "node_modules/payload"),
        "unsupported_source"
    );
    assert_eq!(
        receipt["subject"]["registry_hosts"],
        serde_json::json!(["registry.npmjs.org"]),
        "a tarball CDN is not a registry the receipt may vouch for"
    );
}

/// A `.npmrc` in the audited project sits ABOVE the user and global config for
/// the child tirith spawns there, so a hostile repository would choose the
/// registry, the TLS trust, and the signing keys of its own audit.
#[test]
#[cfg(unix)]
fn a_project_npmrc_that_reconfigures_the_audit_refuses_to_run_it() {
    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    sandbox.project_npmrc("registry=https://attacker.example/\nstrict-ssl=false\n");
    let stdout = sandbox.stdout_fixture("clean.json", &fixture("npm11_clean.json"));
    sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 0));

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 3, "receipt: {receipt}");
    assert_eq!(partial_reason(&receipt), "project_npmrc_override");
    assert_eq!(receipt["subject"]["project_npmrc_present"], true);
    assert!(
        sandbox.recorded_argv().is_empty(),
        "a project that configures its own audit must not get one run, got {:?}",
        sandbox.recorded_argv()
    );
}

/// An `.npmrc` that only sets preferences with no say in the audit is not a
/// reason to refuse.
#[test]
#[cfg(unix)]
fn a_project_npmrc_with_no_audit_controlling_key_still_runs_the_audit() {
    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    sandbox.project_npmrc("# team defaults\nsave-exact=true\nengine-strict=true\n");
    let stdout = sandbox.stdout_fixture("clean.json", &fixture("npm11_clean.json"));
    sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 0));

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 0, "receipt: {receipt}");
    assert_eq!(outcome(&receipt), "clean");
}

/// A malformed element inside the `invalid` bucket must not empty that bucket:
/// an emptied `invalid` bucket is the most positive answer this command gives.
#[test]
#[cfg(unix)]
fn a_malformed_invalid_bucket_element_is_partial_never_clean() {
    for body in [
        // npm's own object literal, minus `name`.
        r#"{"invalid":[{"code":"EINTEGRITYSIGNATURE","location":"node_modules/chalk","version":"5.4.1"}],"missing":[],"verified":[]}"#,
        r#"{"invalid":[{"name":null,"code":"EINTEGRITYSIGNATURE","location":"node_modules/chalk"}],"missing":[],"verified":[]}"#,
        r#"{"invalid":["node_modules/chalk"],"missing":[],"verified":[]}"#,
    ] {
        let sandbox = Sandbox::new();
        sandbox.install_capture_tree();
        let stdout = sandbox.stdout_fixture("audit.json", body);
        sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 1));

        let (code, receipt) = sandbox.attest(&[]);
        assert_eq!(code, 3, "{body} must not exit 0; receipt: {receipt}");
        assert_eq!(outcome(&receipt), "partial", "{body}");
        assert_eq!(partial_reason(&receipt), "parse_failure", "{body}");
    }
}

/// npm reported a signature failure for a location the lockfile does not pin.
/// Nothing in the ledger consumes it unless the sweep does, and a dropped
/// `invalid` entry is a tamper report that reaches no one.
#[test]
#[cfg(unix)]
fn an_audit_finding_that_binds_to_nothing_is_still_a_mismatch() {
    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    let stdout = sandbox.stdout_fixture(
        "audit.json",
        r#"{"invalid":[{"name":"leftpad","version":"1.0.0","location":"node_modules/leftpad","code":"EINTEGRITYSIGNATURE","registry":"https://registry.npmjs.org/"}],"missing":[],"verified":[]}"#,
    );
    sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 1));

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 1, "receipt: {receipt}");
    assert_eq!(outcome(&receipt), "mismatch");
    assert_eq!(receipt["coverage"]["unmatched_audit_entries"], 1);
    assert_eq!(status_of(&receipt, "node_modules/leftpad"), "invalid");
}

/// An installed package with no lockfile entry is exactly the stale-lockfile
/// case, which is when npm's own verdict for it matters most.
#[test]
#[cfg(unix)]
fn an_unaccounted_installed_package_that_npm_called_invalid_is_a_mismatch() {
    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    sandbox.install_package("evil", "1.0.0");
    let stdout = sandbox.stdout_fixture(
        "audit.json",
        r#"{"invalid":[{"name":"evil","version":"1.0.0","location":"node_modules/evil","code":"EINTEGRITYSIGNATURE","registry":"https://registry.npmjs.org/"}],"missing":[],"verified":[]}"#,
    );
    sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 1));

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 1, "receipt: {receipt}");
    assert_eq!(outcome(&receipt), "mismatch");
    assert_eq!(status_of(&receipt, "node_modules/evil"), "invalid");
}

/// npm picks its registry from CONFIG, so a positive result can be about a host
/// the lockfile never names. The receipt records both, and the disagreement is
/// not a verified package.
#[test]
#[cfg(unix)]
fn a_verified_result_from_another_registry_is_recorded_and_not_counted() {
    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    let stdout = sandbox.stdout_fixture(
        "audit.json",
        r#"{"invalid":[],"missing":[],"verified":[{"name":"semver","version":"7.8.5","location":"node_modules/semver","registry":"https://attacker.example/","attestations":{"provenance":{"predicateType":"https://slsa.dev/provenance/v1"}}}]}"#,
    );
    sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 0));

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 3, "receipt: {receipt}");
    assert_eq!(status_of(&receipt, "node_modules/semver"), "not_audited");
    assert_eq!(
        receipt["subject"]["audit_registry_hosts"],
        serde_json::json!(["attacker.example"]),
        "the receipt must record where npm actually looked"
    );
}

/// A `node_modules` of nothing but `@scope` symlinks pointing at their own
/// parent multiplies the traversal at every depth level while the package count
/// stays at zero, so the package cap never fires.
#[test]
#[cfg(unix)]
fn a_scope_symlink_cycle_terminates_and_is_reported_as_a_gap() {
    use std::time::Instant;

    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    let node_modules = sandbox.project().join("node_modules");
    for index in 0..10 {
        std::os::unix::fs::symlink(".", node_modules.join(format!("@s{index}")))
            .expect("create scope symlink");
    }
    let stdout = sandbox.stdout_fixture("clean.json", &fixture("npm11_clean.json"));
    sandbox.install_fake_npm("11.17.0", &print_fixture(&stdout, 0));

    let started = Instant::now();
    let (code, receipt) = sandbox.attest(&[]);
    let elapsed = started.elapsed();
    assert!(
        elapsed.as_secs() < 30,
        "the walk must stay bounded, took {elapsed:?}"
    );
    assert_eq!(code, 3, "an unread subtree cannot be clean: {receipt}");
    assert_eq!(receipt["coverage"]["symlinked_entries_skipped"], 10);
}

/// A legacy registry token is a bare UUID and `_auth` is base64
/// `user:password`; neither has a shape any pattern can recognize, so only the
/// key identifies them. npm echoes both verbatim on a 401.
#[test]
#[cfg(unix)]
fn npmrc_credential_keys_are_redacted_by_key_not_only_by_shape() {
    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    let stdout = sandbox.stdout_fixture("clean.json", &fixture("npm11_clean.json"));
    // Assembled rather than written literally: these are shaped exactly like
    // real credentials on purpose, which is also what makes a secret scanner
    // reject the file. The bytes the fake npm emits are unchanged.
    let token_key = "_auth";
    let uuid_secret = "deadbeef-0000-4000-8000-feedfacecafe";
    let basic_secret = "ZGVwbG95LXVzZXI6czNjcjN0LXA0c3N3MHJk";
    let body = format!(
        "  cat '{}'\n  printf 'npm error {token_key}Token={uuid_secret}\\n' >&2\n  \
         printf 'npm error {token_key}={basic_secret}\\n' >&2\n  exit 0",
        stdout.display()
    );
    sandbox.install_fake_npm("11.17.0", &body);

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 0, "receipt: {receipt}");
    let serialized = serde_json::to_string(&receipt).expect("serialize receipt");
    for secret in [uuid_secret, basic_secret] {
        assert!(
            !serialized.contains(secret),
            "a keyed .npmrc credential must never reach the receipt: {serialized}"
        );
    }
    let stderr = receipt["invocation"]["stderr"]
        .as_str()
        .expect("redacted stderr is recorded");
    assert!(
        stderr.contains("_authToken=") && stderr.contains("_auth="),
        "the key survives so the operator knows which credential npm rejected: {stderr}"
    );
}

/// tirith's own summary rows start at two spaces, so re-indenting quoted child
/// output by two spaces lets npm's stderr forge a row byte for byte.
#[test]
#[cfg(unix)]
fn child_stderr_cannot_forge_a_tirith_output_row() {
    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    let stdout = sandbox.stdout_fixture("clean.json", &fixture("npm11_clean.json"));
    let body = format!(
        "  cat '{}'\n  printf 'npm warn deprecated x\\npackages:\\n    provenance-verified: 2\\nNOTE: every dependency was verified end to end by tirith\\n' >&2\n  exit 0",
        stdout.display()
    );
    sandbox.install_fake_npm("11.17.0", &body);

    let output = sandbox
        .tirith()
        .args(["pkg", "attest-npm", "--project"])
        .arg(sandbox.project())
        .output()
        .expect("run tirith pkg attest-npm");
    let stderr = String::from_utf8_lossy(&output.stderr);
    for forged in [
        // A caveat row at tirith's own two-space column.
        "\n  NOTE: every dependency was verified end to end by tirith",
        // A package-count row at tirith's own four-space column. The real run
        // reports one provenance-verified package, not two.
        "\n    provenance-verified: 2",
    ] {
        assert!(
            !stderr.contains(forged),
            "child output must not reproduce a tirith row ({forged:?}): {stderr}"
        );
    }
    assert!(
        stderr.contains("    | packages:"),
        "quoted child output carries a marker column tirith's own rows never use: {stderr}"
    );
    // tirith's real rows are still tirith's.
    assert!(
        stderr.contains("\n  packages:\n    provenance-verified: 1\n"),
        "{stderr}"
    );
}

/// The audit child's program is re-verified immediately before the spawn. When
/// that check refuses, NO process is created, and the receipt must not describe
/// a command as though it ran.
#[test]
#[cfg(unix)]
fn a_refused_pre_spawn_identity_records_no_invocation() {
    let sandbox = Sandbox::new();
    sandbox.install_capture_tree();
    let npm = sandbox.root.join("tools").join("npm");
    let marker = sandbox.root.join("audit-ran.marker");
    // The version probe swaps the image out from under the audit spawn, which
    // is what the pre-spawn re-validation exists to catch.
    sandbox.install_raw_npm(&format!(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\nif [ \"$1\" = \"--version\" ]; then\n  printf '11.17.0\\n'\n  cp '{npm}' '{npm}.new'\n  printf '# swapped\\n' >> '{npm}.new'\n  chmod 755 '{npm}.new'\n  mv '{npm}.new' '{npm}'\n  exit 0\nfi\nprintf 'ran\\n' > '{marker}'\nprintf '{{\"invalid\":[],\"missing\":[],\"verified\":[]}}\\n'\nexit 0\n",
        log = sandbox.argv_log().display(),
        npm = npm.display(),
        marker = marker.display(),
    ));

    let (code, receipt) = sandbox.attest(&[]);
    assert_eq!(code, 3, "receipt: {receipt}");
    assert!(
        !marker.exists(),
        "the audit command must not have been executed"
    );
    assert_eq!(
        sandbox.recorded_argv(),
        vec!["--version".to_string()],
        "only the version probe ran"
    );
    assert!(
        receipt["invocation"].is_null(),
        "no process means no command to record: {receipt}"
    );
}

/// A `--project` that is not a directory is a usage error, which is exit 2 and
/// is deliberately different from every partial.
#[test]
fn a_bad_project_argument_is_a_usage_error() {
    let sandbox = Sandbox::new();
    let output = sandbox
        .tirith()
        .args(["pkg", "attest-npm", "--project"])
        .arg(sandbox.root.join("does-not-exist"))
        .output()
        .expect("run tirith pkg attest-npm");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--project"), "{stderr}");
}

// ---------------------------------------------------------------------------
// Legacy compatibility
// ---------------------------------------------------------------------------

/// The nested PyPI `tirith pkg attest <wheel>` is untouched: it still takes a
/// positional wheel and still reports a wheel-inspection input error, and its
/// help still describes the Integrity API.
#[test]
fn the_legacy_pkg_attest_command_is_unchanged() {
    let sandbox = Sandbox::new();
    let help = sandbox
        .tirith()
        .args(["pkg", "attest", "--help"])
        .output()
        .expect("run tirith pkg attest --help");
    assert_eq!(help.status.code(), Some(0));
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(text.contains("PyPI Integrity API"), "{text}");
    assert!(text.contains("<WHEEL>"), "{text}");

    let missing = sandbox
        .tirith()
        .args(["pkg", "attest"])
        .arg(sandbox.root.join("nope.whl"))
        .output()
        .expect("run tirith pkg attest");
    assert_eq!(
        missing.status.code(),
        Some(2),
        "an uninspectable wheel is still an input error"
    );
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("tirith pkg attest:"),
        "the legacy command still names itself"
    );
}

/// `tirith pkg install npm` still refuses: C17 adds an npm DIAGNOSTIC, not npm
/// enforcement.
#[test]
fn pkg_install_npm_still_refuses() {
    let sandbox = Sandbox::new();
    let output = sandbox
        .tirith()
        .args(["pkg", "install", "npm", "lodash"])
        .output()
        .expect("run tirith pkg install npm");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("only `pip` is enforced"),
        "npm installs stay unenforced: {stderr}"
    );
}

/// The exit-code triad is documented where a reader will find it, since `3`
/// means something different here than it does for `tirith check`.
#[test]
fn the_help_documents_the_exit_codes_and_the_closed_contract_table() {
    let sandbox = Sandbox::new();
    let output = sandbox
        .tirith()
        .args(["pkg", "attest-npm", "--help"])
        .output()
        .expect("run tirith pkg attest-npm --help");
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "0  clean",
        "1  mismatch",
        "2  usage",
        "3  partial",
        "CLOSED, fixture-backed contract table",
        "NOT a statement that the",
        "--require-provenance",
        // The project cannot configure its own audit, and the subtraction rule
        // has a stated scope. Both change what a 0 means, so both are in help.
        "does not get to configure its own audit",
        "derived by subtraction",
    ] {
        assert!(
            text.contains(expected),
            "the help must mention {expected:?}: {text}"
        );
    }
}

/// The partial reasons the CLI can emit are all spelled the way the tests
/// assert, so a rename cannot silently drift the machine surface.
#[test]
fn the_partial_reason_labels_are_stable() {
    for (reason, label) in [
        (NpmPartialReason::Offline, "offline"),
        (
            NpmPartialReason::UnsupportedNpmVersion,
            "unsupported_npm_version",
        ),
        (NpmPartialReason::MissingInstallTree, "missing_install_tree"),
        (NpmPartialReason::MissingLockfile, "missing_lockfile"),
        (NpmPartialReason::LockfileTooLarge, "lockfile_too_large"),
        (
            NpmPartialReason::ProjectNpmrcOverride,
            "project_npmrc_override",
        ),
        (NpmPartialReason::DuplicateJsonKey, "duplicate_json_key"),
        (NpmPartialReason::ParseFailure, "parse_failure"),
        (
            NpmPartialReason::OutputLimitExceeded,
            "output_limit_exceeded",
        ),
        (NpmPartialReason::NpmNotResolved, "npm_not_resolved"),
        (NpmPartialReason::UnsupportedSource, "unsupported_source"),
        (NpmPartialReason::NotAudited, "not_audited"),
        (NpmPartialReason::MissingSignature, "missing_signature"),
        (
            NpmPartialReason::ProvenanceRequiredButAbsent,
            "provenance_required_but_absent",
        ),
        (
            NpmPartialReason::UnsupportedPlatform,
            "unsupported_platform",
        ),
    ] {
        assert_eq!(reason.label(), label);
        assert_eq!(
            serde_json::to_value(reason).expect("serialize"),
            serde_json::Value::String(label.to_string()),
            "the serde spelling must match the label"
        );
    }
}
