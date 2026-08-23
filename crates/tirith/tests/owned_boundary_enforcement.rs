//! C12: enforcement at the Tirith-OWNED irreversible transitions.
//!
//! Every test here proves ORDER, not a return value. A gate that refuses after
//! the side effect has already happened is not a gate, so each case runs the
//! same command twice: once with the task gate off, to show what the boundary
//! reaches when nothing stops it, and once with it enforcing, to show that the
//! same evidence is now absent. Asserting only the enforcing run would pass
//! against a gate placed anywhere, including after the transition.
//!
//! Nothing here touches the network. The control runs are steered into an
//! offline refusal that is emitted from BEYOND the gate, so its presence is the
//! evidence that the boundary was crossed.

use std::fs;
use std::process::Command;

fn tirith() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tirith"));
    cmd.env("TIRITH_LOG", "0").env("TIRITH_OFFLINE", "1");
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

/// A working directory whose discovered policy is `policy_yaml`, plus an
/// isolated HOME and XDG tree so no ambient operator policy or data directory
/// leaks in.
struct Workspace {
    dir: tempfile::TempDir,
}

impl Workspace {
    fn new(policy_yaml: Option<&str>) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        if let Some(policy) = policy_yaml {
            let tirith_dir = dir.path().join(".tirith");
            fs::create_dir_all(&tirith_dir).expect("create .tirith");
            fs::write(tirith_dir.join("policy.yaml"), policy).expect("write policy");
        }
        fs::create_dir_all(dir.path().join("home")).expect("create home");
        Self { dir }
    }

    fn home(&self) -> std::path::PathBuf {
        self.dir.path().join("home")
    }

    fn command(&self) -> Command {
        let mut cmd = tirith();
        let home = self.home();
        cmd.current_dir(self.dir.path())
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_DATA_HOME", home.join("data"))
            .env("XDG_STATE_HOME", home.join("state"))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("USERPROFILE", &home)
            .env("APPDATA", home.join("appdata"))
            .env("LOCALAPPDATA", home.join("localappdata"));
        cmd
    }

    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let output = self.command().args(args).output().expect("run tirith");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }

    /// Run a fetch-shaped command against a closed loopback port. The explicit
    /// private-fetch allowance makes the URL valid, while clearing every proxy
    /// spelling ensures the control can never send bytes beyond loopback.
    #[cfg(unix)]
    fn run_local_fetch(&self, args: &[&str]) -> (i32, String, String) {
        let mut command = self.command();
        command.env("TIRITH_PRIVATE_FETCH_ALLOW", "localhost");
        for key in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        ] {
            command.env_remove(key);
        }
        let output = command.args(args).output().expect("run tirith");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }

    /// Opt into the registry path while keeping ambient proxies out of the
    /// experiment. Enforcing tests must refuse before this can issue HTTP.
    fn run_online(&self, args: &[&str]) -> (i32, String, String) {
        let mut command = self.command();
        command.env_remove("TIRITH_OFFLINE");
        for key in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        ] {
            command.env_remove(key);
        }
        let output = command.args(args).output().expect("run tirith");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }
}

/// Denies the one effect every guarded boundary in these tests actually has.
const DENY_NETWORK: &str =
    "task_gate:\n  mode: enforce\n  effects_denied_for_untrusted_sources:\n    - network_egress\n";

/// Records the decision without acting on it. The gateway's `warn_action`
/// defaults to `deny`, so if observe mode leaked into the verdict at all these
/// commands would start failing.
const OBSERVE_NETWORK: &str =
    "task_gate:\n  mode: observe\n  effects_denied_for_untrusted_sources:\n    - network_egress\n";

/// Populated denial sets with no mode chosen. `task::decide` still computes a
/// non-empty denial set here, so this is the configuration that catches a gate
/// keyed on the set instead of the mode.
const OFF_BUT_POPULATED: &str =
    "task_gate:\n  effects_denied_for_untrusted_sources:\n    - network_egress\n";

/// Denies the effect only the SPAWN has. `tirith install`'s analysis reaches a
/// registry but installs nothing, so this passes its first gate and is refused
/// at its second.
const DENY_PACKAGE_INSTALL: &str =
    "task_gate:\n  mode: enforce\n  effects_denied_for_untrusted_sources:\n    - package_install\n";

// ---------------------------------------------------------------------------
// tirith run: deny before download
// ---------------------------------------------------------------------------

/// Pure URL syntax validation deliberately precedes task authorization so an
/// invalid request can never consume a one-time receipt. The boundary controls
/// use the same valid loopback URL on a closed port; reaching its download
/// failure proves the authorization boundary was crossed without external I/O.
#[cfg(unix)]
const PURE_URL_REJECTED: &str = "fetch URL must use http:// or https://";
#[cfg(unix)]
const DOWNLOAD_REACHED: &str = "download failed:";
#[cfg(unix)]
const LOCAL_REMOTE_URL: &str = "http://localhost:0/install.sh";

#[cfg(unix)]
#[test]
fn run_without_the_gate_rejects_an_invalid_request_in_pure_preflight() {
    let workspace = Workspace::new(None);
    let (_, _, stderr) = workspace.run(&["run", "ftp://example.com/install.sh", "--no-exec"]);
    assert!(
        stderr.contains(PURE_URL_REJECTED),
        "the pure preflight contract drifted: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn run_without_the_gate_reaches_the_authorized_download_boundary() {
    let workspace = Workspace::new(None);
    let (_, _, stderr) = workspace.run_local_fetch(&["run", LOCAL_REMOTE_URL, "--no-exec"]);
    assert!(
        stderr.contains(DOWNLOAD_REACHED),
        "the control never crossed the authorization boundary: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn run_denies_a_valid_request_before_dns_or_download() {
    let workspace = Workspace::new(Some(DENY_NETWORK));
    let (code, _, stderr) = workspace.run_local_fetch(&["run", LOCAL_REMOTE_URL, "--no-exec"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("task gate refused before any download"),
        "stderr: {stderr}"
    );
    assert!(
        !stderr.contains(DOWNLOAD_REACHED),
        "the download boundary ran before the gate refused: {stderr}"
    );
}

/// `tirith install url <URL>` is the SAME download-and-launch transition with a
/// different spelling: it ends in the same `runner::run_with_verified_executor`.
/// A gate that covers one and not the other is a gate an agent walks around by
/// swapping two words, so the control and the enforcing case are asserted for
/// both commands, not just for `tirith run`.
#[cfg(unix)]
#[test]
fn install_url_without_the_gate_rejects_an_invalid_request_in_pure_preflight() {
    let workspace = Workspace::new(None);
    let (_, _, stderr) = workspace.run(&["install", "--no-exec", "url", "ftp://example.com/i.sh"]);
    assert!(
        stderr.contains(PURE_URL_REJECTED),
        "the pure preflight contract drifted: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn install_url_without_the_gate_reaches_the_authorized_download_boundary() {
    let workspace = Workspace::new(None);
    let (_, _, stderr) =
        workspace.run_local_fetch(&["install", "--no-exec", "url", "http://localhost:0/i.sh"]);
    assert!(
        stderr.contains(DOWNLOAD_REACHED),
        "the control never crossed the authorization boundary: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn install_url_denies_a_valid_request_before_dns_or_download() {
    let workspace = Workspace::new(Some(DENY_NETWORK));
    let (code, _, stderr) =
        workspace.run_local_fetch(&["install", "--no-exec", "url", "http://localhost:0/i.sh"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("task gate refused at the remote_script_run boundary before any download"),
        "stderr: {stderr}"
    );
    assert!(
        !stderr.contains(DOWNLOAD_REACHED),
        "the download boundary ran before the gate refused: {stderr}"
    );
    // The refusal precedes the preflight report too, so a refused transaction
    // publishes no analysis of a URL it never fetched.
    assert!(
        !stderr.contains("preflight analysis of install URL"),
        "the refusal came after the preflight report: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn install_url_under_observe_mode_reaches_the_authorized_download_boundary() {
    let workspace = Workspace::new(Some(OBSERVE_NETWORK));
    let (_, _, stderr) =
        workspace.run_local_fetch(&["install", "--no-exec", "url", "http://localhost:0/i.sh"]);
    assert!(
        stderr.contains(DOWNLOAD_REACHED),
        "observe mode enforced before the download boundary: {stderr}"
    );
    assert!(!stderr.contains("task gate refused"), "stderr: {stderr}");
}

#[cfg(unix)]
#[test]
fn run_under_observe_mode_reaches_the_authorized_download_boundary() {
    let workspace = Workspace::new(Some(OBSERVE_NETWORK));
    let (_, _, stderr) = workspace.run_local_fetch(&["run", LOCAL_REMOTE_URL, "--no-exec"]);
    assert!(
        stderr.contains(DOWNLOAD_REACHED),
        "observe mode enforced before the download boundary: {stderr}"
    );
    assert!(!stderr.contains("task gate refused"), "stderr: {stderr}");
}

#[cfg(unix)]
#[test]
fn run_with_a_populated_denial_set_but_no_mode_is_inert() {
    let workspace = Workspace::new(Some(OFF_BUT_POPULATED));
    let (_, _, stderr) = workspace.run_local_fetch(&["run", LOCAL_REMOTE_URL, "--no-exec"]);
    assert!(
        stderr.contains(DOWNLOAD_REACHED),
        "a default-off gate enforced before the download boundary: {stderr}"
    );
}

#[cfg(windows)]
#[test]
fn windows_refuses_the_unavailable_remote_script_surfaces() {
    let workspace = Workspace::new(None);
    let (run_code, _, run_stderr) =
        workspace.run(&["run", "https://example.invalid/install.sh", "--no-exec"]);
    assert_eq!(run_code, 2, "stderr: {run_stderr}");
    assert!(
        run_stderr.contains("unrecognized subcommand"),
        "the unavailable run surface must be rejected by the parser: {run_stderr}"
    );

    let (install_code, _, install_stderr) = workspace.run(&[
        "install",
        "--no-exec",
        "url",
        "https://example.invalid/install.sh",
    ]);
    assert_eq!(install_code, 2, "stderr: {install_stderr}");
    assert!(
        install_stderr.contains("url form is only available on Unix"),
        "the unsupported install-url surface must fail explicitly: {install_stderr}"
    );
}

// ---------------------------------------------------------------------------
// tirith pkg approve: deny before resolver network
// ---------------------------------------------------------------------------

/// `prepare_plan` starts with `ResolverTools::discover`, so any message about a
/// resolver tool proves the boundary was crossed: PATH lookup happened, and the
/// quarantine transaction and network resolve are the next statements.
fn reached_prepare_plan(stderr: &str) -> bool {
    stderr.contains("resolver tool") || stderr.contains("resolve failed") || stderr.contains("uv")
}

#[test]
fn pkg_approve_without_the_gate_reaches_plan_preparation() {
    let workspace = Workspace::new(None);
    let target = workspace.dir.path().join("approved-target");
    let target = target.to_string_lossy();
    let (_, _, stderr) = workspace.run(&[
        "pkg",
        "approve",
        "pip",
        "requests==2.31.0",
        "--target",
        &target,
    ]);
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        assert!(
            stderr.contains("package approvals are redeemable only on x86_64 Linux"),
            "the native capability refusal drifted: {stderr}"
        );
        return;
    }
    assert!(
        reached_prepare_plan(&stderr),
        "the control must reach prepare_plan: {stderr}"
    );
}

#[test]
fn pkg_approve_denies_before_any_resolver_or_quarantine_work() {
    let workspace = Workspace::new(Some(DENY_NETWORK));
    let target = workspace.dir.path().join("approved-target");
    let target = target.to_string_lossy();
    let (code, _, stderr) = workspace.run(&[
        "pkg",
        "approve",
        "pip",
        "requests==2.31.0",
        "--target",
        &target,
    ]);
    assert_eq!(code, 1);
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        assert!(
            stderr.contains("package approvals are redeemable only on x86_64 Linux"),
            "the native capability refusal drifted: {stderr}"
        );
        assert!(collect_paths(&workspace.home().join("data")).is_empty());
        return;
    }
    assert!(
        stderr.contains("refused before any network or install step"),
        "stderr: {stderr}"
    );
    assert!(
        !reached_prepare_plan(&stderr),
        "plan preparation ran before the gate refused: {stderr}"
    );
    // `prepare_plan` opens the quarantine store and begins a `pkg-` transaction
    // under the data directory. Nothing may exist there.
    let data = workspace.home().join("data");
    let transactions = collect_paths(&data)
        .into_iter()
        .filter(|path| path.contains("pkg-"))
        .collect::<Vec<_>>();
    assert!(
        transactions.is_empty(),
        "a quarantine transaction was created despite the refusal: {transactions:?}"
    );
}

#[test]
fn pkg_approve_json_reports_the_refusal_as_structured_output() {
    let workspace = Workspace::new(Some(DENY_NETWORK));
    let target = workspace.dir.path().join("approved-target");
    let target = target.to_string_lossy();
    let (code, stdout, _) = workspace.run(&[
        "pkg",
        "approve",
        "pip",
        "requests==2.31.0",
        "--target",
        &target,
        "--format",
        "json",
    ]);
    assert_eq!(code, 1);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("json output");
    assert_eq!(json["success"], false);
    assert_eq!(json["command"], "approve");
    assert_eq!(
        json["error_phase"],
        if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            "task_gate"
        } else {
            "native_authority"
        }
    );
    assert_eq!(json["target_executed"], false);
    assert_eq!(json["target_published"], false);
    assert!(json["reason"]
        .as_str()
        .is_some_and(|reason| !reason.is_empty()));
}

// ---------------------------------------------------------------------------
// tirith install: deny before registry network and before spawn
// ---------------------------------------------------------------------------

#[test]
fn offline_install_does_not_invent_a_network_boundary_or_execution_outcome() {
    let workspace = Workspace::new(Some(DENY_NETWORK));
    let (code, stdout, stderr) = workspace.run(&[
        "install",
        "--no-exec",
        "--format",
        "json",
        "npm",
        "left-pad",
    ]);
    assert_eq!(code, 0);
    assert!(
        !stderr.contains("package_manager_network"),
        "stderr: {stderr}"
    );
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("analysis envelope");
    assert_eq!(json["outcome"], serde_json::Value::Null);
}

#[test]
fn online_install_denies_an_exact_registry_request_before_http_or_output() {
    let workspace = Workspace::new(Some(DENY_NETWORK));
    let (code, stdout, stderr) = workspace.run_online(&[
        "install",
        "--online",
        "--no-exec",
        "--format",
        "json",
        "npm",
        "left-pad@1.3.0",
    ]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains(
            "task gate refused at the package_manager_network boundary before any registry request"
        ),
        "stderr: {stderr}"
    );
    assert!(
        stdout.trim().is_empty(),
        "a refused registry request emitted an analysis envelope it never produced: {stdout}"
    );
}

/// Property 3 of the exit gate: a check-only path never records an action as
/// executed. `--no-exec` reaches the analysis, prints the envelope, and the
/// outcome stays null.
#[test]
fn a_check_only_install_never_records_an_execution() {
    let workspace = Workspace::new(None);
    let (_, stdout, _) = workspace.run(&[
        "install",
        "--no-exec",
        "--format",
        "json",
        "npm",
        "left-pad",
    ]);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("json envelope");
    assert_eq!(json["outcome"], serde_json::Value::Null);
    assert_eq!(json["status"], "not_run");
}

/// The two `tirith install` gates must ask DIFFERENT questions, or the second
/// is shadowed by the first and never runs. Analysis reaches a registry and
/// installs nothing, so a policy that denies only `package_install` has to leave
/// it alone.
#[test]
fn a_spawn_only_denial_leaves_the_analysis_gate_alone() {
    let workspace = Workspace::new(Some(DENY_PACKAGE_INSTALL));
    let (_, stdout, stderr) = workspace.run(&[
        "install",
        "--no-exec",
        "--format",
        "json",
        "npm",
        "left-pad",
    ]);
    assert!(
        !stderr.contains("package_manager_network"),
        "the analysis gate refused an operation that installs nothing: {stderr}"
    );
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("the analysis envelope must still be emitted");
    assert_eq!(json["outcome"], serde_json::Value::Null);
}

/// The execution gate itself: denying `package_install` stops the run before
/// the manager is spawned, and nothing is recorded as executed.
///
/// The reach of this test depends on the host. `tirith install` resolves and
/// fingerprints the package-manager executable BEFORE any gate runs, and
/// refuses with exit 2 when that executable sits under a group- or
/// world-writable path, which is common for a Homebrew or nvm `npm`. On such a
/// host the spawn gate is unreachable by construction, so the assertion narrows
/// to what remains provable: nothing ran. Where the executable does bind, the
/// full refusal is asserted.
#[test]
fn install_denies_before_the_manager_is_spawned_and_records_no_execution() {
    let workspace = Workspace::new(Some(DENY_PACKAGE_INSTALL));
    let (code, stdout, stderr) = workspace.run(&["install", "--format", "json", "npm", "left-pad"]);
    let executable_never_bound = stderr.contains("untrusted or unresolved");
    if !executable_never_bound {
        assert_eq!(code, 1, "stderr: {stderr}");
        assert!(
            !stderr.contains("package_manager_network"),
            "the analysis gate fired, so this proves nothing about the spawn gate: {stderr}"
        );
        assert!(
            stderr.contains("task gate refused at the package_manager_execution boundary before"),
            "stderr: {stderr}"
        );
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("the analysis envelope must still be emitted");
        assert_eq!(json["outcome"], serde_json::Value::Null);
    }
    assert!(
        !stdout.contains("\"ran\": true") && !stdout.contains("\"ran\":true"),
        "a refused install recorded an execution: {stdout}"
    );
}

#[test]
fn install_under_observe_mode_still_analyzes() {
    let workspace = Workspace::new(Some(OBSERVE_NETWORK));
    let (_, stdout, stderr) = workspace.run(&[
        "install",
        "--no-exec",
        "--format",
        "json",
        "npm",
        "left-pad",
    ]);
    assert!(!stderr.contains("task gate refused"), "stderr: {stderr}");
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("observe mode must still produce an envelope");
    assert_eq!(json["kind"], "install");
}

// ---------------------------------------------------------------------------
// Tirith-owned config write: deny before the final rename
// ---------------------------------------------------------------------------

#[test]
fn policy_init_writes_its_file_when_the_gate_is_off() {
    let workspace = Workspace::new(None);
    let (code, _, stderr) = workspace.run(&["policy", "init", "--minimal"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(workspace.dir.path().join(".tirith/policy.yaml").exists());
}

#[test]
fn a_denied_config_write_leaves_no_file_behind() {
    let workspace = Workspace::new(None);
    deny_persistence_in_operator_policy(&workspace);

    let (code, _, stderr) = workspace.run(&["policy", "init", "--minimal"]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(
        stderr.contains("task gate refused this configuration write"),
        "stderr: {stderr}"
    );
    assert!(
        !workspace.dir.path().join(".tirith/policy.yaml").exists(),
        "the file was published despite the refusal"
    );
}

/// `.tirith/mcp.lock` is the file `tirith mcp verify` gates drift against and
/// the file the gateway reads to decide which server descriptors are approved.
/// Re-baselining it is a Tirith-owned configuration write in exactly the sense
/// `tirith policy init` is, so the same enforcing policy has to stop both. It
/// was reachable while `policy init` was refused, which is the gap this pins.
#[test]
fn mcp_lock_writes_its_baseline_when_the_gate_is_off() {
    let workspace = Workspace::new(None);
    fs::create_dir_all(workspace.dir.path().join(".git")).expect("create .git");
    let (code, _, stderr) = workspace.run(&["mcp", "lock"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(workspace.dir.path().join(".tirith/mcp.lock").exists());
}

#[test]
fn a_denied_mcp_lock_leaves_no_baseline_behind() {
    let workspace = Workspace::new(None);
    fs::create_dir_all(workspace.dir.path().join(".git")).expect("create .git");
    deny_persistence_in_operator_policy(&workspace);

    let (code, _, stderr) = workspace.run(&["mcp", "lock"]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(
        stderr.contains("task gate refused this configuration write"),
        "stderr: {stderr}"
    );
    assert!(
        !workspace.dir.path().join(".tirith/mcp.lock").exists(),
        "the MCP baseline was published despite the refusal"
    );
}

/// The MCP policy scaffold lives under the same `.tirith/` and was written
/// through the same ungated primitive.
#[test]
fn a_denied_mcp_policy_init_leaves_no_scaffold_behind() {
    let workspace = Workspace::new(None);
    fs::create_dir_all(workspace.dir.path().join(".git")).expect("create .git");
    deny_persistence_in_operator_policy(&workspace);

    let (code, _, stderr) = workspace.run(&["mcp", "policy", "init"]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(
        stderr.contains("task gate refused this configuration write"),
        "stderr: {stderr}"
    );
    assert!(
        !workspace
            .dir
            .path()
            .join(".tirith/mcp-policy.yaml.example")
            .exists(),
        "the scaffold was published despite the refusal"
    );
}

/// Supply the enforcing gate through the OPERATOR policy. A repository must not
/// get to authorise the writes that govern it, so every gated config write
/// discovers its policy offline and repo-local YAML is not consulted.
fn deny_persistence_in_operator_policy(workspace: &Workspace) {
    let config = if cfg!(windows) {
        workspace.home().join("appdata/tirith")
    } else {
        workspace.home().join("config/tirith")
    };
    fs::create_dir_all(&config).expect("create config dir");
    fs::write(
        config.join("policy.yaml"),
        "task_gate:\n  mode: enforce\n  effects_denied_for_untrusted_sources:\n    - persistence_change\n",
    )
    .expect("write operator policy");
}

// ---------------------------------------------------------------------------
// Compatibility: the slice ships inert
// ---------------------------------------------------------------------------

/// The C00 compatibility guard for this slice: with no policy anywhere, every
/// boundary behaves exactly as it did before C12. `TaskGatePolicy::mode`
/// defaults to `Off`, so none of these can refuse.
#[test]
fn the_default_installation_is_unaffected_at_every_boundary() {
    let workspace = Workspace::new(None);
    fs::create_dir_all(workspace.dir.path().join(".git")).expect("create .git");
    for args in [
        vec!["run", "ftp://example.com/install.sh", "--no-exec"],
        vec!["install", "--no-exec", "npm", "left-pad"],
        vec!["install", "--no-exec", "url", "ftp://example.com/i.sh"],
        vec!["policy", "init", "--minimal", "--force"],
        vec!["commands", "init", "--force"],
        vec!["mcp", "lock"],
        vec!["mcp", "policy", "init", "--force"],
    ] {
        let (_, stdout, stderr) = workspace.run(&args);
        assert!(
            !stderr.contains("task gate") && !stdout.contains("\"stage\": \"task_gate\""),
            "the default policy refused {args:?}: {stderr}{stdout}"
        );
    }
    let target = workspace.dir.path().join("approved-target");
    let target = target.to_string_lossy();
    let (_, stdout, stderr) = workspace.run(&[
        "pkg",
        "approve",
        "pip",
        "requests==2.31.0",
        "--target",
        &target,
    ]);
    assert!(
        !stderr.contains("task gate") && !stdout.contains("\"error_phase\": \"task_gate\""),
        "the default policy refused pkg approve: {stderr}{stdout}"
    );
}

// ---------------------------------------------------------------------------
// The MCP gateway: deny before pending registration and before upstream bytes
// ---------------------------------------------------------------------------

/// Drive one guarded `tools/call` through a live gateway and report what the
/// upstream actually received.
///
/// The stub upstream appends every line it reads to a log file, so the log is
/// direct evidence of what crossed the transport rather than an inference from
/// the gateway's own response.
///
/// Unix-only: the stub is a `/bin/sh` script, matching the existing gateway
/// end-to-end test in `cli_integration.rs`.
#[cfg(unix)]
fn drive_guarded_call(policy_yaml: Option<&str>, command: &str) -> (String, String) {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::Duration;

    let workspace = Workspace::new(policy_yaml);
    let upstream_log = workspace.dir.path().join("upstream.log");

    let stub_path = workspace.dir.path().join("stub_upstream.sh");
    let stub = format!(
        r#"#!/bin/sh
set -u
LOG={log}
IFS= read -r line1
printf '%s\n' "$line1" >> "$LOG"
initialize_id=$(printf '%s\n' "$line1" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p')
printf '%s\n' "{{\"jsonrpc\":\"2.0\",\"id\":${{initialize_id}},\"result\":{{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{{}},\"serverInfo\":{{\"name\":\"stub\",\"version\":\"0.0.1\"}}}}}}"
while IFS= read -r line; do
    printf '%s\n' "$line" >> "$LOG"
    request_id=$(printf '%s\n' "$line" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p')
    if [ -n "$request_id" ]; then
        printf '%s\n' "{{\"jsonrpc\":\"2.0\",\"id\":${{request_id}},\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":\"upstream ran it\"}}],\"isError\":false}}}}"
    fi
done
"#,
        log = upstream_log.display()
    );
    fs::write(&stub_path, stub).expect("write stub");
    let mut perms = fs::metadata(&stub_path).expect("stub perms").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&stub_path, perms).expect("chmod stub");

    let config_path = workspace.dir.path().join("gateway.yaml");
    fs::write(
        &config_path,
        "guarded_tools:\n  - pattern: \"^Bash$\"\n    command_paths: [\"/arguments/command\"]\n    shell: posix\npolicy:\n  warn_action: forward\n  fail_mode: open\n  timeout_ms: 10000\n  max_message_bytes: 1048576\n",
    )
    .expect("write gateway config");

    let mut child = workspace
        .command()
        .args([
            "gateway",
            "run",
            "--upstream-bin",
            stub_path.to_str().expect("utf-8 stub path"),
            "--config",
            config_path.to_str().expect("utf-8 config path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gateway");

    let mut child_stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if tx.send(line).is_err() {
                return;
            }
        }
    });

    writeln!(
        child_stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-11-25","capabilities":{{}},"clientInfo":{{"name":"test","version":"1.0"}}}}}}"#
    )
    .expect("write initialize");
    let call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "Bash", "arguments": {"command": command}},
    });
    writeln!(child_stdin, "{call}").expect("write tools/call");

    let mut responses = Vec::new();
    for _ in 0..2 {
        match rx.recv_timeout(Duration::from_secs(20)) {
            Ok(Ok(line)) => responses.push(line),
            _ => break,
        }
    }
    drop(child_stdin);
    let _ = child.wait();
    let _ = reader.join();

    let call_response = responses
        .into_iter()
        .find(|line| line.contains("\"id\":2"))
        .unwrap_or_default();
    let upstream_saw = fs::read_to_string(&upstream_log).unwrap_or_default();
    (call_response, upstream_saw)
}

/// The control. Without a task gate the same call reaches the upstream, so the
/// enforcing case below is a statement about the gate and not about the stub.
#[cfg(unix)]
#[test]
fn a_guarded_call_reaches_the_upstream_when_the_gate_is_off() {
    let (response, upstream_saw) =
        drive_guarded_call(None, "forge script Deploy.s.sol --broadcast");
    assert!(
        upstream_saw.contains("tools/call"),
        "the control never reached the upstream, so nothing below proves a gate: {upstream_saw}"
    );
    assert!(
        !response.contains("task_gate_denied"),
        "the default policy refused: {response}"
    );
}

/// The exit gate's first property at the gateway: no upstream byte, and no
/// pending registration, because the refusal happens before both.
#[cfg(unix)]
#[test]
fn a_guarded_call_is_denied_before_any_byte_reaches_the_upstream() {
    let (response, upstream_saw) =
        drive_guarded_call(Some(DENY_NETWORK), "forge script Deploy.s.sol --broadcast");
    let json: serde_json::Value =
        serde_json::from_str(response.trim()).unwrap_or_else(|_| panic!("response: {response}"));
    assert_eq!(json["result"]["isError"], true, "response: {response}");
    assert_eq!(
        json["result"]["structuredContent"]["task_gate_denied"], true,
        "the refusal did not come from the task gate: {response}"
    );
    // The proof: the upstream saw the initialize handshake and NOTHING else.
    assert!(
        !upstream_saw.contains("tools/call"),
        "the guarded call was forwarded before the gate refused it: {upstream_saw}"
    );
    // A refused call is answered, so it was never left in the pending table
    // waiting for a response that will not come.
    assert_eq!(json["id"], 2, "response: {response}");
}

/// Observe mode records and forwards. The gateway config here leaves
/// `warn_action` at its `deny` default, so if observe recording were
/// implemented by raising the verdict action this call would be blocked.
#[cfg(unix)]
#[test]
fn observe_mode_does_not_become_enforcement_through_warn_action() {
    let (response, upstream_saw) = drive_guarded_call(
        Some(OBSERVE_NETWORK),
        "forge script Deploy.s.sol --broadcast",
    );
    assert!(
        upstream_saw.contains("tools/call"),
        "observe mode stopped the call: {upstream_saw} / {response}"
    );
    assert!(
        !response.contains("task_gate_denied"),
        "observe mode denied: {response}"
    );
}

// ---------------------------------------------------------------------------
// The degraded-run invariant
// ---------------------------------------------------------------------------

/// `DegradedPolicy::AllowDegraded` runs a program fully UNCONTAINED on a host
/// whose backend cannot deliver the spec. A surface holding an enforcing task
/// decision must never reach it, or a decision that tightened the capsule would
/// be satisfied by no capsule at all.
///
/// The invariant is structural today: `pkg install` launches through
/// `run_to_completion_bound_inputs`, whose API has no degraded mode at all, and
/// `tirith run` passes `FailClosed`. This scan pins that by refusing any NEW
/// file from naming `AllowDegraded`, so wiring a future enforcing surface to it
/// fails here instead of silently running attacker code uncontained.
#[test]
fn only_the_declared_best_effort_surfaces_name_the_degraded_policy() {
    let source_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let permitted = [
        // The one real best-effort surface, which prints an honest banner.
        "temp_run.rs",
        // Defines the policy and its guard.
        "capsule.rs",
        // Maps the historical `--allow-degraded` flag; the value is discarded
        // before the launch, which always fails closed.
        "pkg.rs",
    ];
    let mut offenders = Vec::new();
    for path in collect_paths(&source_root) {
        if !path.ends_with(".rs") {
            continue;
        }
        let contents = fs::read_to_string(&path).unwrap_or_default();
        if !contents.contains("DegradedPolicy::AllowDegraded") {
            continue;
        }
        let name = std::path::Path::new(&path)
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default();
        if !permitted.contains(&name.as_str()) {
            offenders.push(path);
        }
    }
    assert!(
        offenders.is_empty(),
        "a new surface reaches the uncontained degraded run: {offenders:?}"
    );
}

/// Every regular file beneath `root`, as display strings. Missing roots yield
/// an empty list so a test can assert "nothing was created here".
fn collect_paths(root: &std::path::Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                found.push(path.display().to_string());
            }
        }
    }
    found
}
