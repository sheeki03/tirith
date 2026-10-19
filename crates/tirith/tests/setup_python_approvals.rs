#![cfg(unix)]

use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tirith_test_support::GlobalStateGuard;

const WARNING_COMMAND: &str = "curl https://bit.ly/tirith-hook-approval-regression";
const CLEAN_COMMAND: &str = "printf '%s\\n' tirith-hook-approval-regression";
const CRITICAL_COMMAND: &str = "curl http://169.254.169.254/latest/meta-data/";

#[derive(Clone, Copy, Debug)]
enum Host {
    Claude,
    WorktreeClaude,
    Grok,
    Cline,
    ClineBatch,
    OpenHands,
    Kiro,
    Copilot,
    Gemini,
}

struct Adapter {
    host: Host,
    path: PathBuf,
}

impl Adapter {
    fn protocol(&self) -> &str {
        match self.host {
            Host::Claude | Host::WorktreeClaude => "claude-code",
            Host::Grok => "grok-build",
            Host::Cline | Host::ClineBatch => "cline",
            Host::OpenHands => "openhands",
            Host::Kiro => "kiro",
            Host::Copilot => "copilot-cli",
            Host::Gemini => "gemini-cli",
        }
    }

    fn payload(&self, command: &str) -> Value {
        match self.host {
            Host::Claude | Host::WorktreeClaude => json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
            }),
            Host::Grok => json!({
                "hook_event_name": "pre_tool_use",
                "tool_name": "run_terminal_command",
                "tool_input": {"command": command},
            }),
            Host::Cline => json!({
                "hookName": "PreToolUse",
                "preToolUse": {
                    "toolName": "execute_command",
                    "parameters": {"command": command, "shell": "bash"},
                },
            }),
            Host::ClineBatch => json!({
                "hookName": "PreToolUse",
                "preToolUse": {
                    "toolName": "run_commands",
                    "parameters": {
                        "shell": "bash",
                        "commands": [CLEAN_COMMAND, command],
                    },
                },
            }),
            Host::OpenHands => json!({
                "event_type": "PreToolUse",
                "tool_name": "terminal",
                "tool_input": {"command": command, "is_input": false},
            }),
            Host::Kiro => json!({
                "hook_event_name": "preToolUse",
                "tool_name": "execute_bash",
                "tool_input": {"command": command},
            }),
            Host::Copilot => json!({
                "toolName": "bash",
                "toolArgs": json!({"command": command}).to_string(),
            }),
            Host::Gemini => json!({
                "hook_event_name": "BeforeTool",
                "tool_name": "run_shell_command",
                "tool_input": {"command": command},
            }),
        }
    }

    fn run(
        &self,
        state: &GlobalStateGuard,
        checker: &Path,
        command: &str,
        fail_open: bool,
        warn_action: &str,
        mutation: Option<&str>,
    ) -> Output {
        self.run_with_warn_action(
            state,
            checker,
            command,
            fail_open,
            Some(warn_action),
            mutation,
        )
    }

    /// Like `run`, with `None` leaving TIRITH_HOOK_WARN_ACTION unset.
    fn run_with_warn_action(
        &self,
        state: &GlobalStateGuard,
        checker: &Path,
        command: &str,
        fail_open: bool,
        warn_action: Option<&str>,
        mutation: Option<&str>,
    ) -> Output {
        let mut process = Command::new("python3");
        state.apply_to_command(&mut process);
        process
            .arg(&self.path)
            .env("TIRITH_BIN", checker)
            .env("TIRITH_HOOK_PROTOCOL", self.protocol())
            .env("TIRITH_FAIL_OPEN", if fail_open { "1" } else { "0" })
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match warn_action {
            Some(value) => process.env("TIRITH_HOOK_WARN_ACTION", value),
            None => process.env_remove("TIRITH_HOOK_WARN_ACTION"),
        };
        if let Some(mutation) = mutation {
            process.env("TIRITH_TEST_APPROVAL_MUTATION", mutation);
        }
        let mut child = process.spawn().expect("launch generated Python adapter");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&self.payload(command)).unwrap())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn assert_denied(&self, output: &Output, expected: bool) {
        if matches!(self.host, Host::Kiro) {
            assert_eq!(
                output.status.code(),
                Some(if expected { 2 } else { 0 }),
                "{:?}: {output:?}",
                self.host
            );
            return;
        }
        assert_eq!(
            output.status.code(),
            Some(if expected && matches!(self.host, Host::OpenHands) {
                2
            } else {
                0
            }),
            "{:?}: {output:?}",
            self.host
        );
        if output.stdout.is_empty() {
            assert!(!expected, "{:?}: {output:?}", self.host);
            return;
        }
        let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
        if !expected {
            self.assert_no_approval(&decision, output);
        }
        let denied = match self.host {
            Host::Claude | Host::WorktreeClaude => {
                decision["hookSpecificOutput"]["permissionDecision"] == "deny"
            }
            Host::Cline | Host::ClineBatch => decision["cancel"]
                .as_bool()
                .expect("Cline cancellation decision"),
            Host::Grok | Host::OpenHands | Host::Gemini => decision["decision"] == "deny",
            Host::Copilot => decision["permissionDecision"] == "deny",
            Host::Kiro => unreachable!(),
        };
        assert_eq!(denied, expected, "{:?}: {output:?}", self.host);
    }

    /// A command Tirith lets through is never an explicit approval: an allow
    /// would skip the host's own permission prompt (Claude Code documents
    /// "allow" as skipping it), making a flagged command less gated than a
    /// clean one.
    fn assert_no_approval(&self, decision: &Value, output: &Output) {
        let explicit = match self.host {
            Host::Claude | Host::WorktreeClaude => {
                decision["hookSpecificOutput"].get("permissionDecision")
            }
            Host::Grok | Host::OpenHands | Host::Gemini => decision.get("decision"),
            Host::Copilot => decision.get("permissionDecision"),
            Host::Cline | Host::ClineBatch | Host::Kiro => None,
        };
        assert!(
            explicit.is_none(),
            "{:?}: an allowed command must carry no permission decision: {output:?}",
            self.host
        );
    }
}

fn state() -> GlobalStateGuard {
    let mut state = GlobalStateGuard::new().unwrap();
    state.remove_env("TIRITH_POLICY_ROOT");
    state.set_env("TIRITH_OFFLINE", "1");
    state.set_env("TIRITH_LOG", "0");
    // macOS's system Python caches bytecode under $HOME/Library/Caches; a
    // late-exiting telemetry child would recreate the removed temp root.
    state.set_env("PYTHONDONTWRITEBYTECODE", "1");
    // Match existing setup integration fixtures: prefer the root-managed Unix
    // interpreter, not a developer package-manager prefix with writable groups.
    let path = format!(
        "/usr/bin:/bin:{}",
        std::env::var("PATH").unwrap_or_default()
    );
    state.set_env("PATH", path);
    std::fs::create_dir(state.roots().cwd.join(".git")).unwrap();
    // Make the real Linux xdg-user-dir helper resolve the same isolated
    // Documents directory as Cline's macOS fallback.
    std::fs::write(
        state.roots().xdg_config.join("user-dirs.dirs"),
        "XDG_DOCUMENTS_DIR=\"$HOME/Documents\"\n",
    )
    .unwrap();
    state
}

fn adapters(state: &GlobalStateGuard) -> Vec<Adapter> {
    let mut adapters = Vec::new();
    for (tool, scope, host, relative_path) in [
        (
            "claude-code",
            "project",
            Host::Claude,
            ".claude/hooks/tirith-check.py",
        ),
        (
            "grok-build",
            "project",
            Host::Grok,
            ".grok/hooks/tirith-check.py",
        ),
        (
            "openhands",
            "project",
            Host::OpenHands,
            ".openhands/hooks/tirith-check.py",
        ),
        ("kiro", "project", Host::Kiro, ".kiro/hooks/kiro-hook.py"),
        (
            "copilot-cli",
            "project",
            Host::Copilot,
            ".github/hooks/copilot-cli-hook.py",
        ),
        (
            "gemini-cli",
            "project",
            Host::Gemini,
            ".gemini/hooks/tirith-security-guard-gemini.py",
        ),
        (
            "cline",
            "user",
            Host::Cline,
            "Documents/Cline/Hooks/tirith-check.py",
        ),
    ] {
        let mut setup = Command::new(env!("CARGO_BIN_EXE_tirith"));
        state.apply_to_command(&mut setup);
        let output = setup
            .args(["setup", tool, "--scope", scope, "--update-configs"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{tool}: {output:?}");
        let root = if scope == "user" {
            &state.roots().home
        } else {
            &state.roots().cwd
        };
        adapters.push(Adapter {
            host,
            path: root.join(relative_path),
        });
    }
    adapters.push(Adapter {
        host: Host::ClineBatch,
        path: state
            .roots()
            .home
            .join("Documents/Cline/Hooks/tirith-check.py"),
    });
    let worktree_hook =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.claude/hooks/tirith-check.py");
    if worktree_hook.is_file() {
        adapters.push(Adapter {
            host: Host::WorktreeClaude,
            path: worktree_hook,
        });
    }
    adapters
}

fn user_policy(severity: &str, approvals: bool) {
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    let mut policy = format!("paranoia: 4\nseverity_overrides:\n  shortened_url: {severity}\n");
    if approvals {
        policy.push_str(
            "approval_rules:\n  - rule_ids: [shortened_url, metadata_endpoint]\n    timeout_secs: 30\n    fallback: block\n",
        );
    }
    std::fs::write(config.join("policy.yaml"), policy).unwrap();
}

fn check(state: &GlobalStateGuard, command: &str) -> (Output, Value) {
    check_with_env(state, command, &[])
}

fn check_with_env(
    state: &GlobalStateGuard,
    command: &str,
    env: &[(&str, &str)],
) -> (Output, Value) {
    let mut check = Command::new(env!("CARGO_BIN_EXE_tirith"));
    state.apply_to_command(&mut check);
    check.envs(env.iter().copied());
    let output = check
        .args([
            "check",
            "--json",
            "--non-interactive",
            "--no-daemon",
            "--shell",
            "posix",
            "--",
            command,
        ])
        .output()
        .unwrap();
    let value = serde_json::from_slice(&output.stdout).expect("real public check JSON");
    (output, value)
}

#[test]
fn installed_python_adapters_preserve_warnings_and_blocks_but_deny_active_approval() {
    let state = state();
    let adapters = adapters(&state);
    let checker = Path::new(env!("CARGO_BIN_EXE_tirith"));
    user_policy("LOW", false);
    let (warning_output, warning) = check(&state, WARNING_COMMAND);
    assert_eq!(warning_output.status.code(), Some(2));
    assert_eq!(warning["action"], "warn");
    assert_eq!(warning["requires_approval"], false);
    assert!(warning["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| { finding["rule_id"] == "shortened_url" && finding["severity"] == "LOW" }));
    for adapter in &adapters {
        adapter.assert_denied(
            &adapter.run(&state, checker, WARNING_COMMAND, false, "allow", None),
            false,
        );
        adapter.assert_denied(
            &adapter.run(&state, checker, WARNING_COMMAND, true, "deny", None),
            true,
        );
    }

    user_policy("LOW", true);
    let (approval_output, approval) = check(&state, WARNING_COMMAND);
    assert_eq!(approval_output.status.code(), Some(2));
    assert_eq!(approval["action"], warning["action"]);
    assert_eq!(approval["findings"], warning["findings"]);
    assert_eq!(approval["requires_approval"], true);
    assert_eq!(approval["approval_rule"], "shortened_url");
    for adapter in &adapters {
        for fail_open in [false, true] {
            adapter.assert_denied(
                &adapter.run(&state, checker, WARNING_COMMAND, fail_open, "allow", None),
                true,
            );
        }
    }

    let (critical_output, critical) = check(&state, CRITICAL_COMMAND);
    assert_eq!(critical_output.status.code(), Some(1));
    assert_eq!(critical["action"], "block");
    assert!(critical["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| {
            finding["rule_id"] == "metadata_endpoint" && finding["severity"] == "CRITICAL"
        }));
    for adapter in &adapters {
        adapter.assert_denied(
            &adapter.run(&state, checker, CRITICAL_COMMAND, true, "allow", None),
            true,
        );
    }
}

#[test]
fn installed_python_adapters_answer_warnings_without_approving_them() {
    let state = state();
    let adapters = adapters(&state);
    let checker = Path::new(env!("CARGO_BIN_EXE_tirith"));
    user_policy("LOW", false);
    let (warning_output, warning) = check(&state, WARNING_COMMAND);
    assert_eq!(warning_output.status.code(), Some(2));
    assert_eq!(warning["requires_approval"], false);

    // The default (unset, empty or "allow") passes the warning on with no
    // permission decision, through the fields each host shows the user or
    // the agent, so the host applies its own permission rules.
    for warn_action in [None, Some(""), Some("allow"), Some("ALLOW")] {
        for adapter in &adapters {
            let output = adapter.run_with_warn_action(
                &state,
                checker,
                WARNING_COMMAND,
                false,
                warn_action,
                None,
            );
            adapter.assert_denied(&output, false);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            match adapter.host {
                Host::Claude | Host::WorktreeClaude => {
                    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
                    for message in [
                        &decision["systemMessage"],
                        &decision["hookSpecificOutput"]["additionalContext"],
                    ] {
                        let message = message.as_str().expect("warning for user and model");
                        assert!(message.contains("[LOW]"), "{message}");
                        assert!(message.contains("(shortened_url)"), "{message}");
                    }
                    assert_eq!(
                        decision["hookSpecificOutput"]["hookEventName"],
                        "PreToolUse"
                    );
                }
                Host::Grok => {
                    assert!(stdout.trim().is_empty(), "{output:?}");
                    assert!(stderr.contains("shortened_url"), "{output:?}");
                }
                Host::Cline | Host::ClineBatch => {
                    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
                    assert_eq!(decision["cancel"], false);
                    assert!(decision["contextModification"]
                        .as_str()
                        .unwrap()
                        .contains("shortened_url"));
                }
                Host::OpenHands => {
                    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
                    assert!(decision["additionalContext"]
                        .as_str()
                        .unwrap()
                        .contains("shortened_url"));
                }
                Host::Copilot | Host::Gemini => assert!(stdout.trim().is_empty(), "{output:?}"),
                Host::Kiro => {}
            }
        }
    }

    // "ask" asks where the host has a confirmation prompt, and is denied with
    // interactive-shell guidance where it has none.
    for adapter in &adapters {
        let output = adapter.run(&state, checker, WARNING_COMMAND, true, "ask", None);
        match adapter.host {
            Host::Claude | Host::WorktreeClaude => {
                assert!(output.status.success(), "{output:?}");
                let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
                let specific = &decision["hookSpecificOutput"];
                assert_eq!(specific["permissionDecision"], "ask", "{decision}");
                assert!(specific["permissionDecisionReason"]
                    .as_str()
                    .unwrap()
                    .contains("shortened_url"));
                assert!(specific["additionalContext"]
                    .as_str()
                    .unwrap()
                    .contains("shortened_url"));
            }
            Host::Copilot => {
                let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(decision["permissionDecision"], "ask", "{decision}");
                assert!(decision["permissionDecisionReason"]
                    .as_str()
                    .unwrap()
                    .contains("Shortened URL"));
            }
            _ => {
                adapter.assert_denied(&output, true);
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(text.contains("TIRITH_HOOK_WARN_ACTION=ask"), "{output:?}");
                assert!(text.contains("interactive shell"), "{output:?}");
            }
        }
    }

    // An unrecognized value fails closed and names the valid values, even
    // when the operator fails open on checker errors.
    for warn_action in ["block", "allow-auto", "warn"] {
        for adapter in &adapters {
            for fail_open in [false, true] {
                let output = adapter.run(
                    &state,
                    checker,
                    WARNING_COMMAND,
                    fail_open,
                    warn_action,
                    None,
                );
                adapter.assert_denied(&output, true);
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(
                    text.contains("valid values: allow, ask, deny"),
                    "{output:?}"
                );
                assert!(text.contains(warn_action), "{output:?}");
            }
        }
    }

    // A clean command is unaffected by the warn action, valid or not.
    for warn_action in ["ask", "deny", "block"] {
        for adapter in &adapters {
            adapter.assert_denied(
                &adapter.run(&state, checker, CLEAN_COMMAND, false, warn_action, None),
                false,
            );
        }
    }
}

#[test]
fn installed_python_adapters_require_confirmation_for_otherwise_allowed_findings() {
    let state = state();
    let adapters = adapters(&state);
    let checker = Path::new(env!("CARGO_BIN_EXE_tirith"));
    user_policy("INFO", false);
    let (allow_output, allow) = check(&state, WARNING_COMMAND);
    assert_eq!(allow_output.status.code(), Some(0));
    assert_eq!(allow["action"], "allow");
    assert_eq!(allow["requires_approval"], false);
    for adapter in &adapters {
        adapter.assert_denied(
            &adapter.run(&state, checker, WARNING_COMMAND, false, "allow", None),
            false,
        );
    }

    user_policy("INFO", true);
    let (approval_output, approval) = check(&state, WARNING_COMMAND);
    assert_eq!(approval_output.status.code(), Some(2));
    assert_eq!(approval["action"], "warn");
    assert_eq!(approval["requires_approval"], true);
    for adapter in &adapters {
        adapter.assert_denied(
            &adapter.run(&state, checker, WARNING_COMMAND, true, "allow", None),
            true,
        );
    }
}

fn damaged_checker(state: &GlobalStateGuard, command: &str, response: &Output) -> PathBuf {
    let checker = state.roots().root.join("check-contract-mutation.py");
    // Capture the actual CLI bytes before fault injection. Re-running a cold
    // debug scanner inside each host's fixed deadline conflates response damage
    // with checker timeout; the latter may legitimately use explicit fail-open.
    // Mutations still retain the real findings and approval/exit contract.
    std::fs::write(checker.with_extension("stdout"), &response.stdout).unwrap();
    std::fs::write(checker.with_extension("stderr"), &response.stderr).unwrap();
    std::fs::write(
        checker.with_extension("status"),
        response.status.code().unwrap().to_string(),
    )
    .unwrap();
    std::fs::write(checker.with_extension("command"), command).unwrap();
    if command != CLEAN_COMMAND {
        // Cline batches inspect a harmless prefix first. Keep its actual Allow
        // response separate so approval on the second command cannot be faked
        // by incorrectly feeding that response to the first.
        let (clean, _) = check(state, CLEAN_COMMAND);
        std::fs::write(checker.with_extension("clean.stdout"), &clean.stdout).unwrap();
        std::fs::write(checker.with_extension("clean.stderr"), &clean.stderr).unwrap();
        std::fs::write(
            checker.with_extension("clean.status"),
            clean.status.code().unwrap().to_string(),
        )
        .unwrap();
        std::fs::write(checker.with_extension("clean.command"), CLEAN_COMMAND).unwrap();
    }
    std::fs::write(
        &checker,
        r#"#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

source = str(Path(__file__).with_suffix(""))
if sys.argv[-1] != Path(source + ".command").read_text():
    clean_command = Path(source + ".clean.command")
    if clean_command.is_file() and sys.argv[-1] == clean_command.read_text():
        source += ".clean"
    else:
        raise SystemExit("response mutation received an uncaptured command")
output = Path(source + ".stdout").read_bytes()
error_output = Path(source + ".stderr").read_bytes()
exit_code = int(Path(source + ".status").read_text())
if sys.argv[1:2] == ["check"]:
    verdict = json.loads(output)
    mutation = os.environ["TIRITH_TEST_APPROVAL_MUTATION"]
    if mutation.startswith("warn-ack"):
        verdict["action"] = "warn_ack"
        verdict["requires_approval"] = True
        exit_code = 3
        if mutation == "warn-ack-absent":
            del verdict["requires_approval"]
        elif mutation == "warn-ack-false":
            verdict["requires_approval"] = False
    if mutation == "absent":
        del verdict["requires_approval"]
    elif mutation == "string":
        verdict["requires_approval"] = "false"
    elif mutation == "integer":
        verdict["requires_approval"] = 0
    elif mutation == "null":
        verdict["requires_approval"] = None
    elif mutation in ("context", "warn-ack-context"):
        verdict["findings"] = [None, 1, {"title": [], "severity": {}}]
        verdict["approval_rule"] = {}
        verdict["approval_description"] = []
    elif mutation == "nonobject":
        verdict = [verdict]
    output = json.dumps(verdict).encode()
    if mutation in ("invalid-json", "warn-ack-invalid-json"):
        output = b"{" + output
    elif mutation in ("empty", "warn-ack-empty"):
        output = b""
    elif mutation == "warn-ack-nested":
        output = b"[" * 1100 + output + b"]" * 1100
    elif mutation == "warn-ack-invalid-utf8":
        output = b"\xff" + output
sys.stdout.buffer.write(output)
sys.stderr.buffer.write(error_output)
sys.exit(exit_code)
"#,
    )
    .unwrap();
    std::fs::set_permissions(&checker, std::fs::Permissions::from_mode(0o700)).unwrap();
    checker
}

#[test]
fn damaged_python_checker_contract_uses_only_explicit_checker_error_fail_open() {
    let state = state();
    let adapters = adapters(&state);
    user_policy("LOW", false);
    for command in [CLEAN_COMMAND, WARNING_COMMAND] {
        let (output, value) = check(&state, command);
        assert_eq!(
            output.status.code(),
            Some(if command == CLEAN_COMMAND { 0 } else { 2 })
        );
        assert_eq!(value["requires_approval"], false);
        let checker = damaged_checker(&state, command, &output);
        for mutation in [
            "absent",
            "string",
            "integer",
            "null",
            "nonobject",
            "invalid-json",
            "empty",
        ] {
            for adapter in &adapters {
                for fail_open in [false, true] {
                    adapter.assert_denied(
                        &adapter.run(
                            &state,
                            &checker,
                            command,
                            fail_open,
                            "allow",
                            Some(mutation),
                        ),
                        !fail_open,
                    );
                }
            }
        }
    }
}

#[test]
fn damaged_python_checker_output_cannot_relax_a_denying_verdict() {
    let state = state();
    let adapters = adapters(&state);
    user_policy("LOW", false);
    let (output, value) = check(&state, WARNING_COMMAND);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(value["requires_approval"], false);
    let checker = damaged_checker(&state, WARNING_COMMAND, &output);
    // The operator gates warnings (deny, ask, or an unrecognized value), so a
    // damaged warning response stays denied even with TIRITH_FAIL_OPEN=1, as
    // the shell and TypeScript adapters do.
    for mutation in [
        "absent",
        "string",
        "integer",
        "null",
        "nonobject",
        "invalid-json",
        "empty",
    ] {
        for adapter in &adapters {
            for warn_action in ["deny", "DENY", "ask", "block"] {
                adapter.assert_denied(
                    &adapter.run(
                        &state,
                        &checker,
                        WARNING_COMMAND,
                        true,
                        warn_action,
                        Some(mutation),
                    ),
                    true,
                );
            }
        }
    }

    // A block is a verdict, not a checker error, even when its output is lost.
    let (output, value) = check(&state, CRITICAL_COMMAND);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(value["action"], "block");
    let checker = damaged_checker(&state, CRITICAL_COMMAND, &output);
    for mutation in ["intact", "empty", "invalid-json", "nonobject"] {
        for adapter in &adapters {
            adapter.assert_denied(
                &adapter.run(
                    &state,
                    &checker,
                    CRITICAL_COMMAND,
                    true,
                    "allow",
                    Some(mutation),
                ),
                true,
            );
        }
    }
}

#[test]
fn python_adapters_deny_deferred_blocks_even_with_fail_open() {
    let state = state();
    let adapters = adapters(&state);
    user_policy("HIGH", false);
    let (output, value) = check_with_env(&state, WARNING_COMMAND, &[("TIRITH_DEFER", "1")]);
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    assert_eq!(value["action"], "block");
    assert!(value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["rule_id"] == "shortened_url" && finding["severity"] == "HIGH"));
    let checker = damaged_checker(&state, WARNING_COMMAND, &output);
    for mutation in ["intact", "empty", "invalid-json"] {
        for adapter in &adapters {
            for fail_open in [false, true] {
                adapter.assert_denied(
                    &adapter.run(
                        &state,
                        &checker,
                        WARNING_COMMAND,
                        fail_open,
                        "allow",
                        Some(mutation),
                    ),
                    true,
                );
            }
        }
    }
}

#[test]
fn python_adapters_allow_a_policy_honored_bypass() {
    let state = state();
    let adapters = adapters(&state);
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        config.join("policy.yaml"),
        "allow_bypass_env: true\nallow_bypass_env_noninteractive: true\n",
    )
    .unwrap();
    // Replay the real honored-bypass response (as 0.4.x adapters saw exit 0)
    // so the host deadline cannot turn a cold checker into a timeout denial.
    let (output, value) = check_with_env(&state, CRITICAL_COMMAND, &[("TIRITH", "0")]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(value["action"], "allow");
    assert_eq!(value["bypass_requested"], true);
    assert_eq!(value["bypass_honored"], true);
    assert_eq!(value["requires_approval"], false);
    let checker = damaged_checker(&state, CRITICAL_COMMAND, &output);
    for adapter in &adapters {
        adapter.assert_denied(
            &adapter.run(
                &state,
                &checker,
                CRITICAL_COMMAND,
                false,
                "allow",
                Some("intact"),
            ),
            false,
        );
    }
}

#[test]
fn active_python_approval_cannot_become_checker_fail_open_when_context_is_damaged() {
    let state = state();
    let adapters = adapters(&state);
    user_policy("LOW", true);
    let (output, verdict) = check(&state, WARNING_COMMAND);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(verdict["requires_approval"], true);
    let checker = damaged_checker(&state, WARNING_COMMAND, &output);
    for adapter in &adapters {
        adapter.assert_denied(
            &adapter.run(
                &state,
                &checker,
                WARNING_COMMAND,
                true,
                "allow",
                Some("context"),
            ),
            true,
        );
    }
}

#[test]
fn python_mandatory_acknowledgement_denies_even_with_damaged_output_and_fail_open() {
    let state = state();
    let adapters = adapters(&state);
    user_policy("LOW", false);
    let (output, verdict) = check(&state, WARNING_COMMAND);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(verdict["action"], "warn");
    assert_eq!(verdict["requires_approval"], false);
    let checker = damaged_checker(&state, WARNING_COMMAND, &output);
    for mutation in [
        "warn-ack",
        "warn-ack-absent",
        "warn-ack-false",
        "warn-ack-invalid-json",
        "warn-ack-empty",
        "warn-ack-context",
        "warn-ack-nested",
        "warn-ack-invalid-utf8",
    ] {
        for adapter in &adapters {
            for fail_open in [false, true] {
                adapter.assert_denied(
                    &adapter.run(
                        &state,
                        &checker,
                        WARNING_COMMAND,
                        fail_open,
                        "allow",
                        Some(mutation),
                    ),
                    true,
                );
            }
        }
    }
}

#[test]
fn installed_python_adapters_enforce_real_strict_warn_policy_for_natural_low_warning() {
    let state = state();
    let adapters = adapters(&state);
    let checker = Path::new(env!("CARGO_BIN_EXE_tirith"));
    let command = "curl https://example.com/wallet/0x742d35Cc6634C0532925a3b844Bc8e7595f0bEb8";
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    for strict_warn in [false, true] {
        std::fs::write(
            config.join("policy.yaml"),
            format!("paranoia: 4\nstrict_warn: {strict_warn}\n"),
        )
        .unwrap();
        let (output, verdict) = check(&state, command);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(verdict["action"], "warn");
        assert_eq!(verdict["requires_approval"], strict_warn);
        assert!(verdict.get("approval_rule").is_none());
        assert!(verdict["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["rule_id"] == "web3_address_in_url" && finding["severity"] == "LOW"
            }));
        for adapter in &adapters {
            adapter.assert_denied(
                &adapter.run(&state, checker, command, true, "allow", None),
                strict_warn,
            );
        }
    }
}
