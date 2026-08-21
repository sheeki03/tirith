//! C14 — `tirith capsule run --preset untrusted-project` CLI contract.
//!
//! The exit gate has two halves and this file is deliberately arranged around
//! them.
//!
//! The first half is host-independent and runs everywhere, including this
//! repository's macOS dev host: a host that cannot deliver a required control
//! REFUSES before any copy or spawn, names the control, records a `refused`
//! receipt, and never reports a contained result. Input handling, receipt
//! shape, receipt privacy, spec derivation, and the no-fallback structure are
//! all provable without a working sandbox.
//!
//! The second half is the enforcing behaviour, which is only meaningful on an
//! x86_64 Linux host with a usable Landlock ABI. Those tests probe the backend
//! first and skip with an explicit message when the host cannot deliver the
//! coverage, mirroring the guard `cli_integration.rs` already uses for the
//! production capsule receipt.

use std::path::Path;
use std::process::Command;

use tirith_core::capsule::ResourceLimits;

/// Hermetic invocation: no ambient policy, no network, and a redirected data
/// directory on every platform's strategy so a test never writes into the real
/// one.
fn tirith(state: &Path, cwd: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tirith"));
    cmd.env("TIRITH_OFFLINE", "1")
        .env("TIRITH_LOG", "0")
        .env("HOME", state)
        .env("USERPROFILE", state)
        .env("XDG_DATA_HOME", state.join("data"))
        .env("XDG_CONFIG_HOME", state.join("config"))
        .env("XDG_STATE_HOME", state.join("state"))
        .env("APPDATA", state.join("appdata"))
        .env("LOCALAPPDATA", state.join("localappdata"))
        .current_dir(cwd);
    for key in [
        "TIRITH",
        "TIRITH_POLICY_ROOT",
        "TIRITH_API_KEY",
        "TIRITH_SERVER_URL",
    ] {
        cmd.env_remove(key);
    }
    cmd
}

struct Fixture {
    _base: tempfile::TempDir,
    state: std::path::PathBuf,
    project: std::path::PathBuf,
    receipt: std::path::PathBuf,
}

fn fixture() -> Fixture {
    let base = tempfile::tempdir().expect("tempdir");
    let state = base.path().join("state");
    let project = base.path().join("project");
    std::fs::create_dir_all(state.join("data")).expect("state dir");
    std::fs::create_dir_all(project.join("src")).expect("project dir");
    std::fs::write(project.join("README.md"), "take-home exercise\n").expect("readme");
    std::fs::write(project.join("src/main.rs"), "fn main() {}\n").expect("main");
    let receipt = base.path().join("receipt.json");
    Fixture {
        _base: base,
        state,
        project,
        receipt,
    }
}

fn run(fixture: &Fixture, extra: &[&str]) -> (i32, String, String) {
    let output = tirith(&fixture.state, &fixture.project)
        .args(["capsule", "run"])
        .args(extra)
        .output()
        .expect("run tirith capsule run");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

fn run_json(fixture: &Fixture, extra: &[&str]) -> (i32, serde_json::Value) {
    let mut args: Vec<&str> = vec!["--format", "json"];
    args.extend_from_slice(extra);
    let (code, stdout, stderr) = run(fixture, &args);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
        panic!("expected JSON output, got {stdout:?} / {stderr:?}: {error}")
    });
    (code, value)
}

/// Whether this host can actually deliver the preset's controls. Everything in
/// the enforcing half of this file is conditioned on it.
fn host_can_enforce_the_preset(project: &Path) -> bool {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        use tirith_core::capsule::linux::LandlockSeccompCapsule;
        use tirith_core::capsule::{Capsule as _, CapsuleSpec};

        // The output and wall dimensions are parent-owned, exactly as
        // `supervised_stdin_plan` strips them before probing the backend.
        let mut spec = CapsuleSpec::untrusted_project(project, &[]);
        spec.resources.max_output_bytes = None;
        spec.resources.wall_clock_seconds = None;
        let available = LandlockSeccompCapsule.available_coverage(&spec);
        !available.is_degraded_against(&spec.required_coverage())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = project;
        false
    }
}

// ---------------------------------------------------------------------------
// Input handling: a usage error is not a containment decision
// ---------------------------------------------------------------------------

#[test]
fn an_unknown_preset_is_a_usage_error_and_writes_no_receipt() {
    let fixture = fixture();
    let (code, _, stderr) = run(
        &fixture,
        &[
            "--preset",
            "totally-contained-trust-me",
            "--project",
            fixture.project.to_str().expect("utf8"),
            "--receipt",
            fixture.receipt.to_str().expect("utf8"),
            "--",
            "echo",
            "hi",
        ],
    );
    assert_eq!(code, 2, "unknown preset must be a usage error: {stderr}");
    assert!(stderr.contains("untrusted-project"));
    assert!(
        !fixture.receipt.exists(),
        "a usage error must not fabricate a run receipt"
    );
}

#[test]
fn a_missing_argv_is_refused_by_the_parser() {
    let fixture = fixture();
    let (code, _, _) = run(
        &fixture,
        &["--project", fixture.project.to_str().expect("utf8")],
    );
    assert_eq!(code, 2, "the preset has nothing to run without an argv");
}

#[test]
fn a_nonexistent_project_is_a_usage_error() {
    let fixture = fixture();
    let missing = fixture.project.join("does-not-exist");
    let (code, _, stderr) = run(
        &fixture,
        &[
            "--project",
            missing.to_str().expect("utf8"),
            "--",
            "echo",
            "hi",
        ],
    );
    assert_eq!(code, 2);
    assert!(stderr.contains("--project"));
}

// ---------------------------------------------------------------------------
// The refusal path, which is the whole contract on any host that cannot enforce
// ---------------------------------------------------------------------------

#[test]
fn a_host_that_cannot_enforce_refuses_and_never_claims_containment() {
    let fixture = fixture();
    if host_can_enforce_the_preset(&fixture.project) {
        eprintln!("skipping preset refusal assertion: this host CAN enforce the preset");
        return;
    }

    let (code, value) = run_json(
        &fixture,
        &[
            "--project",
            fixture.project.to_str().expect("utf8"),
            "--receipt",
            fixture.receipt.to_str().expect("utf8"),
            "--",
            "echo",
            "hi",
        ],
    );
    assert_eq!(
        code, 1,
        "a refusal is a Tirith decision, not a child status"
    );
    assert_eq!(value["status"], "refused");
    assert_eq!(value["tirith_decision"], "refused_before_launch");
    assert!(value["child_exit_code"].is_null());
    // The refusal names the control that could not be achieved, not a shrug.
    let reason = value["reason"]
        .as_str()
        .expect("a refusal carries a reason");
    assert!(
        reason.contains("missing:") || reason.contains("Linux"),
        "refusal must name the specific control: {reason}"
    );
    // Never a contained claim, and never an achieved-coverage claim.
    let achieved = &value["achieved_coverage"];
    for flag in [
        "fs_read_enforced",
        "fs_write_enforced",
        "network_raw_denied",
        "resource_limits_enforced",
    ] {
        assert_eq!(achieved[flag], false, "{flag} claimed on a refused run");
    }
    assert!(
        value["project_input_digest"].is_null() && value["project_output_digest"].is_null(),
        "a refusal must not report tree digests: nothing was copied"
    );
}

#[test]
fn the_refusal_receipt_is_content_addressed_signed_shape_and_tamper_evident() {
    let fixture = fixture();
    if host_can_enforce_the_preset(&fixture.project) {
        eprintln!("skipping refusal receipt assertion: this host CAN enforce the preset");
        return;
    }
    let (_, value) = run_json(
        &fixture,
        &[
            "--project",
            fixture.project.to_str().expect("utf8"),
            "--receipt",
            fixture.receipt.to_str().expect("utf8"),
            "--",
            "echo",
            "hi",
        ],
    );
    assert!(
        fixture.receipt.exists(),
        "a refusal still writes a receipt; receipt_error={:?}",
        value.get("receipt_error")
    );

    let bytes = std::fs::read(&fixture.receipt).expect("read receipt");
    let receipt: tirith_core::capsule_receipt::CapsuleRunReceipt =
        serde_json::from_slice(&bytes).expect("receipt parses");
    assert_eq!(receipt.receipt_id, value["receipt_id"].as_str().unwrap());
    assert!(receipt.content_hash_matches());
    receipt.validate().expect("a refusal receipt is coherent");
    assert_eq!(
        receipt.status,
        tirith_core::capsule_receipt::CapsuleRunStatus::Refused
    );
    assert_eq!(receipt.subject.preset, "untrusted-project");
    assert_eq!(receipt.subject.argv_len, 2);
    assert_eq!(receipt.subject.argv_digest.len(), 64);
    // Reused verbatim from the shared catalogue, never restated.
    assert_eq!(receipt.evidence.limits, ResourceLimits::conservative());

    // A single edited byte of content breaks the content address.
    let mut tampered = receipt.clone();
    tampered.evidence.cleanup_confirmed = !tampered.evidence.cleanup_confirmed;
    assert!(!tampered.content_hash_matches());
    assert!(tampered.validate().is_err());
}

#[test]
fn the_receipt_records_an_argv_digest_and_no_argv_no_secret_no_host_path() {
    let fixture = fixture();
    if host_can_enforce_the_preset(&fixture.project) {
        eprintln!("skipping receipt privacy assertion: this host CAN enforce the preset");
        return;
    }
    // A deliberately secret-shaped argument that must not survive into the file.
    let secret = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB";
    let (_, _) = run_json(
        &fixture,
        &[
            "--project",
            fixture.project.to_str().expect("utf8"),
            "--receipt",
            fixture.receipt.to_str().expect("utf8"),
            "--",
            "deploy-tool",
            "--token",
            secret,
        ],
    );
    let text = std::fs::read_to_string(&fixture.receipt).expect("read receipt");
    assert!(!text.contains(secret), "the receipt leaked an argv secret");
    assert!(!text.contains("deploy-tool"), "the receipt leaked the argv");
    assert!(
        !text.contains(fixture.project.to_str().expect("utf8")),
        "the receipt leaked a host path"
    );
    assert!(text.contains("argv_digest"));
}

#[test]
fn a_project_that_is_a_denied_root_is_refused_before_any_copy() {
    // `--project ~` and `--project ~/.ssh` must never be copied: the preset's
    // deny catalogue covers the home-anchored credential stores, and an allow
    // root that overlaps a deny root is rejected in either direction.
    let fixture = fixture();
    let Some(home) = home_directory() else {
        eprintln!("skipping denied-root assertion: no authenticated home on this host");
        return;
    };
    let (code, value) = run_json(
        &fixture,
        &[
            "--project",
            home.to_str().expect("utf8"),
            "--receipt",
            fixture.receipt.to_str().expect("utf8"),
            "--",
            "echo",
            "hi",
        ],
    );
    assert_eq!(code, 1);
    assert_eq!(value["status"], "refused");
    let reason = value["reason"].as_str().expect("a reason");
    assert!(
        reason.contains("denies by default") || reason.contains("overlaps deny root"),
        "the denied-root refusal must say so: {reason}"
    );
}

#[test]
fn the_denied_root_refusal_receipt_carries_no_host_path() {
    // The refusal reason is built from a filesystem-policy error that displays
    // both roots, so this is the receipt most likely to name the operator's
    // account, their home layout, and which credential stores exist there.
    let fixture = fixture();
    let Some(home) = home_directory() else {
        eprintln!("skipping denied-root privacy assertion: no authenticated home on this host");
        return;
    };
    let (_, _) = run_json(
        &fixture,
        &[
            "--project",
            home.to_str().expect("utf8"),
            "--receipt",
            fixture.receipt.to_str().expect("utf8"),
            "--",
            "echo",
            "hi",
        ],
    );
    let text = std::fs::read_to_string(&fixture.receipt).expect("read receipt");
    assert!(
        !text.contains(home.to_str().expect("utf8")),
        "the receipt leaked the operator's home path: {text}"
    );
    for prefix in ["/Users/", "/home/", "/tmp/", "/private/"] {
        assert!(
            !text.contains(prefix),
            "the receipt leaked a host path starting {prefix}: {text}"
        );
    }
    let receipt: tirith_core::capsule_receipt::CapsuleRunReceipt =
        serde_json::from_str(&text).expect("receipt parses");
    let reason = receipt.evidence.reason.expect("a refusal keeps its reason");
    assert!(
        reason.contains("denies by default"),
        "the redaction must not eat the sentence: {reason}"
    );
}

#[test]
fn the_preset_binds_the_project_copy_by_descriptor_not_by_pathname() {
    // The held copy is the preset's only writable grant AND the child's working
    // directory. Handing the launcher its PATHNAME would re-resolve it twice
    // after the parent's identity proof (once for chdir, once for the Landlock
    // rule), which is the swap window the whole held-directory machinery exists
    // to close.
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli/capsule_run.rs");
    let text = std::fs::read_to_string(&source).expect("read capsule_run.rs");
    assert!(
        text.contains("run_to_completion_bound_work_directory"),
        "the preset must launch through the descriptor-bound entry point"
    );
    assert!(
        !text.contains("run_to_completion_os("),
        "the preset must not launch through the pathname-cwd entry point"
    );
}

#[cfg(unix)]
fn home_directory() -> Option<std::path::PathBuf> {
    // The authenticated OS home, matching what `deny_default_paths` anchors to.
    // Deliberately not `$HOME`: the test harness redirects that.
    tirith_core::capsule::try_deny_default_paths()
        .ok()?
        .into_iter()
        .find(|path| path.file_name().is_some_and(|name| name == ".ssh"))?
        .parent()
        .map(std::path::Path::to_path_buf)
        .filter(|path| path.is_dir())
}

#[cfg(not(unix))]
fn home_directory() -> Option<std::path::PathBuf> {
    std::env::var_os("USERPROFILE").map(std::path::PathBuf::from)
}

#[test]
fn an_unwritable_receipt_path_is_reported_and_never_reads_as_success() {
    // The receipt is the durable record of a containment claim. If the operator
    // asked for a file and it could not be written, the command must say so
    // rather than print a receipt id over nothing.
    let fixture = fixture();
    let non_directory = fixture.project.join("not-a-directory");
    std::fs::write(&non_directory, "blocks receipt parent creation\n")
        .expect("write non-directory parent");
    let unwritable = non_directory.join("run.json");
    let (code, value) = run_json(
        &fixture,
        &[
            "--project",
            fixture.project.to_str().expect("utf8"),
            "--receipt",
            unwritable.to_str().expect("utf8"),
            "--",
            "echo",
            "hi",
        ],
    );
    assert_ne!(code, 0, "an unrecorded receipt must never exit 0");
    assert!(
        value["receipt_error"].is_string(),
        "the receipt failure must be reported: {value}"
    );
    assert!(value["receipt_path"].is_null());
    assert!(!unwritable.exists());
}

// ---------------------------------------------------------------------------
// Structural: no degraded fallback, and the preset is not reachable elsewhere
// ---------------------------------------------------------------------------

#[test]
fn the_preset_surface_never_names_the_degraded_policy() {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli/capsule_run.rs");
    let text = std::fs::read_to_string(&source).expect("read capsule_run.rs");
    // Deliberately scanned RAW, comments included, exactly like the repo-wide
    // scan in owned_boundary_enforcement.rs. A prose mention of the permissive
    // policy is still a mention, and keeping the two scans identical means this
    // file cannot pass while the repo-wide one fails.
    assert!(
        !text.contains("DegradedPolicy::AllowDegraded"),
        "the preset must never name, let alone construct, an uncontained degraded run"
    );
    assert!(
        text.contains("DegradedPolicy::FailClosed"),
        "the preset must launch through the fail-closed policy"
    );
}

#[test]
fn temp_run_cannot_select_the_preset() {
    // `temp-run` is explicitly not a boundary and passes AllowDegraded. The
    // preset must not be reachable through it, or a fail-closed promise would
    // be satisfiable by a best-effort surface.
    let fixture = fixture();
    let output = tirith(&fixture.state, &fixture.project)
        .args([
            "temp-run",
            "--preset",
            "untrusted-project",
            "--",
            "echo",
            "hi",
        ])
        .output()
        .expect("run tirith temp-run");
    assert_eq!(
        output.status.code(),
        Some(2),
        "temp-run must reject a --preset flag it does not have"
    );
}

#[test]
fn the_help_states_the_platform_limit_and_the_absence_of_domain_allow_listing() {
    let fixture = fixture();
    let output = tirith(&fixture.state, &fixture.project)
        .args(["capsule", "run", "--help"])
        .output()
        .expect("run capsule run --help");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("FAIL-CLOSED"));
    assert!(text.contains("x86_64 Linux"));
    assert!(
        text.contains("Domain allow-listing is NOT offered"),
        "help must not imply an egress capability the product does not have"
    );
    assert!(text.contains("REFUSES before anything is copied or spawned"));
}

// ---------------------------------------------------------------------------
// The enforcing half: only meaningful where the host can actually contain
// ---------------------------------------------------------------------------

#[test]
fn a_capable_host_contains_the_run_and_reports_a_faithful_diff() {
    let fixture = fixture();
    if !host_can_enforce_the_preset(&fixture.project) {
        eprintln!(
            "skipping contained preset run: this host lacks required Landlock/seccomp coverage"
        );
        return;
    }
    let (code, value) = run_json(
        &fixture,
        &[
            "--project",
            fixture.project.to_str().expect("utf8"),
            "--receipt",
            fixture.receipt.to_str().expect("utf8"),
            "--",
            "/bin/sh",
            "-c",
            "printf marker > written.txt",
        ],
    );
    assert_eq!(code, 0, "a clean contained run exits 0: {value}");
    assert_eq!(value["status"], "contained");
    assert_eq!(value["tirith_decision"], "target_completed");
    assert_eq!(value["child_exit_code"], 0);
    assert_eq!(value["cleanup_confirmed"], true);
    assert_eq!(value["achieved_coverage"]["network_raw_denied"], true);
    assert_eq!(value["achieved_coverage"]["fs_write_enforced"], true);
    // The child wrote inside the COPY, so the diff sees it and the operator's
    // own tree does not.
    let added = value["diff"]["added"]
        .as_array()
        .expect("an added bucket")
        .iter()
        .filter_map(|entry| entry.as_str())
        .collect::<Vec<_>>();
    assert!(
        added.contains(&"written.txt"),
        "diff missed the write: {value}"
    );
    assert!(
        !fixture.project.join("written.txt").exists(),
        "the preset wrote into the operator's real project tree"
    );
    assert_ne!(
        value["project_input_digest"], value["project_output_digest"],
        "a write must change the output tree digest"
    );
}

#[test]
fn a_capable_host_separates_the_child_status_from_the_tirith_decision() {
    let fixture = fixture();
    if !host_can_enforce_the_preset(&fixture.project) {
        eprintln!("skipping contained failing-child run: this host lacks required coverage");
        return;
    }
    let (code, value) = run_json(
        &fixture,
        &[
            "--project",
            fixture.project.to_str().expect("utf8"),
            "--",
            "/bin/sh",
            "-c",
            "exit 7",
        ],
    );
    assert_eq!(code, 3, "a contained run with a failing child is exit 3");
    assert_eq!(value["status"], "contained");
    assert_eq!(value["child_exit_code"], 7);
    assert_eq!(value["tirith_decision"], "target_completed");
}

#[test]
fn a_capable_host_denies_the_sensitive_roots_and_the_inherited_environment() {
    let fixture = fixture();
    if !host_can_enforce_the_preset(&fixture.project) {
        eprintln!("skipping denial assertions: this host lacks required coverage");
        return;
    }
    let home = home_directory().expect("an authenticated home on a capable host");
    // Every denial is proved by the CHILD's own exit status, so the evidence
    // survives the ephemeral copy being removed. A distinct code per denial
    // says which one leaked if this ever regresses.
    let probe = format!(
        "[ -z \"${{GITHUB_TOKEN:-}}\" ] || exit 9; \
         cat \"{project}/README.md\" >/dev/null 2>&1 && exit 10; \
         ls \"{home}/.ssh\" >/dev/null 2>&1 && exit 11; \
         exit 0",
        project = fixture.project.display(),
        home = home.display(),
    );
    let output = tirith(&fixture.state, &fixture.project)
        .env("GITHUB_TOKEN", "ghp_test_value_must_not_reach_the_child")
        .args([
            "capsule",
            "run",
            "--format",
            "json",
            "--project",
            fixture.project.to_str().expect("utf8"),
            "--",
            "/bin/sh",
            "-c",
            &probe,
        ])
        .output()
        .expect("run contained denial probe");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json output");
    assert_eq!(value["status"], "contained");
    assert_eq!(
        value["child_exit_code"], 0,
        "a denial leaked into the contained child: 9=env, 10=real project tree, 11=home .ssh"
    );
}

#[test]
fn the_receipt_names_the_parent_enforced_dimensions_rather_than_claiming_the_backend() {
    // No OS backend enforces `max_output_bytes` or `wall_clock_seconds`; the
    // parent supervisor does. The receipt must say so by name, or a reader
    // would attribute two parent-owned controls to the sandbox. The kill
    // BEHAVIOUR itself is owned by the capsule supervisor's own tests.
    let fixture = fixture();
    let (_, value) = run_json(
        &fixture,
        &[
            "--project",
            fixture.project.to_str().expect("utf8"),
            "--",
            "/bin/sh",
            "-c",
            "true",
        ],
    );
    assert_eq!(value["parent_enforced_dimensions"][0], "max_output_bytes");
    assert_eq!(value["parent_enforced_dimensions"][1], "wall_clock_seconds");
    assert_eq!(value["limits"]["wall_clock_seconds"], 300);
    assert_eq!(value["limits"]["max_output_bytes"], 16 * 1024 * 1024);
    assert!(value["termination_kind"].is_null());
}

#[cfg(unix)]
#[test]
fn a_configured_signing_key_produces_a_verifiable_receipt_signature() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = fixture();
    if !host_can_enforce_the_preset(&fixture.project) {
        eprintln!(
            "skipping signed contained receipt: this host lacks required Landlock/seccomp coverage"
        );
        return;
    }
    let config = fixture.state.join("config").join("tirith");
    std::fs::create_dir_all(&config).expect("config dir");
    let signing = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let key_path = config.join("audit-signing.key");
    std::fs::write(&key_path, signing.to_bytes()).expect("write signing key");
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod signing key");

    let (_, value) = run_json(
        &fixture,
        &[
            "--project",
            fixture.project.to_str().expect("utf8"),
            "--receipt",
            fixture.receipt.to_str().expect("utf8"),
            "--",
            "echo",
            "hi",
        ],
    );
    assert_eq!(value["receipt_signed"], true);

    let bytes = std::fs::read(&fixture.receipt).expect("read receipt");
    let receipt: tirith_core::capsule_receipt::CapsuleRunReceipt =
        serde_json::from_slice(&bytes).expect("receipt parses");
    assert!(
        receipt.signature_verifies(&signing.verifying_key().to_bytes()),
        "the receipt signature must verify against the configured audit key"
    );

    // The signature binds the canonical payload, so a content edit invalidates
    // it. Do not flip `status` to Contained: a successful `echo` already has
    // that status, which would be a no-op and keep the signature valid.
    let mut tampered = receipt;
    tampered.tirith_version.push_str("-tampered");
    assert!(!tampered.signature_verifies(&signing.verifying_key().to_bytes()));
}
