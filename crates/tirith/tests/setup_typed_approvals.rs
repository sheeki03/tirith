use serde_json::Value;
use std::io::Write as _;
use std::process::{Command, Stdio};
use tirith_test_support::GlobalStateGuard;

const WARNING_COMMAND: &str =
    "curl https://example.com/address/0x1234567890abcdef1234567890abcdef12345678";
const CLEAN_COMMAND: &str = "printf clean";
const CRITICAL_COMMAND: &str = "printf '%s' '-----BEGIN RSA PRIVATE KEY-----'";
const BASE_POLICY: &str = "paranoia: 4\n";
const STRICT_WARN_POLICY: &str = "paranoia: 4\nstrict_warn: true\n";
const APPROVAL_POLICY: &str = "paranoia: 4\napproval_rules:\n  - rule_ids: [web3_address_in_url]\n    timeout_secs: 1\n    fallback: allow\n";
const INFO_POLICY: &str = "paranoia: 4\nseverity_overrides:\n  web3_address_in_url: info\n";
const INFO_APPROVAL_POLICY: &str = "paranoia: 4\nseverity_overrides:\n  web3_address_in_url: info\napproval_rules:\n  - rule_ids: [web3_address_in_url]\n    timeout_secs: 1\n    fallback: allow\n";

// Like the existing JS conformance suites, import the exact asset bytes as an
// ES module. The .ts assets deliberately contain valid JavaScript; no type
// stripping, source rewriting, or third-party TypeScript loader is needed.
const HOST_CALLBACK_RUNNER: &str = r#"
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";

// Completed-response cases replay bytes produced by the real CLI before the
// callback starts. The separate live mode forwards the shipped invocation and
// deadline unchanged, and records whether it actually produced a verdict.
const captured = JSON.parse(process.env.TIRITH_TEST_CAPTURED_RESPONSE);
const live = process.env.TIRITH_TEST_CHECK_TRANSPORT === "live";
const mutation = process.env.TIRITH_TEST_RESPONSE_MUTATION;
assert(!live || mutation === "none", "live checker responses must not be mutated");
const acknowledgement = mutation.startsWith("warn_ack");
const jsonFault = acknowledgement ? mutation.slice("warn_ack".length + 1) : mutation;
const realExecFileSync = childProcess.execFileSync;
const checks = [];
const alterResponse = (stdout) => {
  if (mutation === "none") return stdout;
  if (jsonFault === "invalid_json") return "{";
  const response = JSON.parse(stdout);
  if (acknowledgement) {
    response.action = "warn_ack";
    response.requires_approval = true;
  }
  if (jsonFault === "absent") delete response.requires_approval;
  if (jsonFault === "non_boolean") response.requires_approval = "false";
  return JSON.stringify(response);
};
childProcess.execFileSync = (file, args, options) => {
  if (args[0] !== "check") return realExecFileSync(file, args, options);
  const observed = {
    file, args, input: options.input ?? null,
    timeout: options.timeout, encoding: options.encoding,
    integration: options.env?.TIRITH_INTEGRATION,
  };
  checks.push(observed);
  if (live) {
    try {
      const stdout = realExecFileSync(file, args, options);
      observed.response = { status: 0, stdout };
      return stdout;
    } catch (error) {
      observed.response = {
        status: error.status ?? null, stdout: error.stdout?.toString() ?? "",
        stderr: error.stderr?.toString() ?? "", code: error.code ?? null,
        signal: error.signal ?? null, killed: error.killed ?? false,
      };
      throw error;
    }
  }
  const stdout = alterResponse(captured.stdout);
  const status = acknowledgement && captured.status === 2 ? 3 : captured.status;
  if (status !== 0) {
    throw Object.assign(new Error("captured real checker response"), {
      status, stdout, stderr: captured.stderr,
    });
  }
  return stdout;
};
syncBuiltinESMExports();

const host = process.env.TIRITH_TEST_HOST;
let source = await readFile(process.env.TIRITH_TEST_ASSET, "utf8");
if (host !== "openclaw") {
  source = source
    .replace('"__TIRITH_BIN__"', JSON.stringify(process.env.TIRITH_BIN))
    .replace('"__TIRITH_INTEGRATION__"', JSON.stringify(host));
}
const moduleUrl = `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
const guard = (await import(moduleUrl)).default;
let callback;
const api = {
  on(name, handler) {
    if (name === (host === "openclaw" ? "before_tool_call" : "tool_call")) {
      callback = handler;
    }
  },
};
if (host === "openclaw") guard.register(api); else guard(api);
const toolName = process.env.TIRITH_TEST_TOOL;
const command = process.env.TIRITH_TEST_COMMAND;
const event = host === "openclaw"
  ? { toolName, params: { command } }
  : { toolName, input: { command } };
const result = await callback(event, {});
// Check outside the callback so the host's legitimate fail-open handler cannot
// swallow a harness assertion. Replaying a gate for a different command, or
// allowing without consulting the checker, must never satisfy these tests.
assert.equal(checks.length, toolName === "read" ? 0 : 1, `${host}/${toolName}: check count`);
for (const check of checks) {
  if (live) {
    const response = check.response;
    const context = `${host}/${toolName}: live checker must complete within the shipped deadline; `
      + `an unavailable checker is not approval coverage: ${JSON.stringify(response)}`;
    assert.equal(response.signal ?? null, null, context);
    assert.equal(response.killed ?? false, false, context);
    assert.notEqual(response.code, "ETIMEDOUT", context);
    assert.equal(response.status, captured.status, context);
    const actual = JSON.parse(response.stdout);
    const expected = JSON.parse(captured.stdout);
    for (const field of ["action", "requires_approval", "findings", "approval_rule"]) {
      assert.deepEqual(actual[field], expected[field], `${context}; field=${field}`);
    }
  }
}
process.stdout.write(JSON.stringify(result === undefined ? null : result));
"#;

fn node_available(state: &GlobalStateGuard) -> bool {
    let mut command = Command::new("node");
    state.apply_to_command(&mut command);
    match command.arg("--version").output() {
        Ok(output) => {
            assert!(output.status.success(), "Node failed to start: {output:?}");
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping typed approval callbacks: Node is not installed");
            false
        }
        Err(error) => panic!("start Node: {error}"),
    }
}

fn write_user_policy(yaml: &str) {
    let directory = tirith_core::policy::config_dir().expect("isolated user config directory");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("policy.yaml"), yaml).unwrap();
}

struct CheckedCommand {
    command: String,
    status: i32,
    stdout: String,
    stderr: String,
}

fn check(state: &GlobalStateGuard, command: &str) -> (CheckedCommand, Value) {
    let mut binary = Command::new(env!("CARGO_BIN_EXE_tirith"));
    state.apply_to_command(&mut binary);
    let mut child = binary
        .args(["check", "--json", "--non-interactive", "--shell", "posix"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(command.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let verdict = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "real checker returned invalid JSON: {error}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (
        CheckedCommand {
            command: command.to_owned(),
            status: output
                .status
                .code()
                .expect("real checker must exit normally"),
            stdout: String::from_utf8(output.stdout).unwrap(),
            stderr: String::from_utf8(output.stderr).unwrap(),
        },
        verdict,
    )
}

fn callback_command(
    state: &GlobalStateGuard,
    host: &str,
    tool: &str,
    checked: &CheckedCommand,
    warn_action: &str,
    fail_open: bool,
) -> Command {
    let asset = if host == "openclaw" {
        "openclaw-tirith-guard.ts"
    } else {
        "tirith-guard.ts"
    };
    let mut node = Command::new("node");
    state.apply_to_command(&mut node);
    node.args(["--input-type=module", "-e", HOST_CALLBACK_RUNNER])
        .env("TIRITH_BIN", env!("CARGO_BIN_EXE_tirith"))
        .env("TIRITH_SHELL", "posix")
        .env("TIRITH_BASH_SHELL", "posix")
        .env("TIRITH_HOOK_WARN_ACTION", warn_action)
        .env("TIRITH_FAIL_OPEN", if fail_open { "1" } else { "0" })
        .env("TIRITH_TEST_HOST", host)
        .env("TIRITH_TEST_TOOL", tool)
        .env("TIRITH_TEST_COMMAND", &checked.command)
        .env("TIRITH_TEST_RESPONSE_MUTATION", "none")
        .env("TIRITH_TEST_CHECK_TRANSPORT", "completed")
        .env(
            "TIRITH_TEST_CAPTURED_RESPONSE",
            serde_json::json!({
                "status": checked.status,
                "stdout": checked.stdout,
                "stderr": checked.stderr,
            })
            .to_string(),
        )
        .env(
            "TIRITH_TEST_ASSET",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("assets/hooks")
                .join(asset),
        )
        .stdin(Stdio::null());
    node
}

fn run_callback(mut node: Command, host: &str, tool: &str) -> Value {
    let output = node.output().unwrap();
    assert!(
        output.status.success(),
        "{host}/{tool} callback failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{host}/{tool} callback returned invalid JSON: {error}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn callback(
    state: &GlobalStateGuard,
    host: &str,
    tool: &str,
    checked: &CheckedCommand,
    warn_action: &str,
    fail_open: bool,
    mutation: &str,
) -> Value {
    let mut node = callback_command(state, host, tool, checked, warn_action, fail_open);
    node.env("TIRITH_TEST_RESPONSE_MUTATION", mutation);
    run_callback(node, host, tool)
}

fn assert_blocked(host: &str, result: Value) {
    assert_eq!(result["block"], true, "{host}: {result}");
    let reason_field = if host == "openclaw" {
        "blockReason"
    } else {
        "reason"
    };
    assert!(result[reason_field].is_string(), "{host}: {result}");
}

// Capture once per command/policy, then exercise every host setting with that
// completed response. The CLI still discovers the real isolated user policy;
// only subprocess scheduling is removed from this decision-contract matrix.
fn exercise_host(host: &str) {
    let mut state = GlobalStateGuard::new().unwrap();
    state.remove_env("TIRITH_POLICY_ROOT");
    if !node_available(&state) {
        return;
    }
    let tools: &[&str] = if host == "openclaw" {
        &["exec", "bash"]
    } else {
        &["bash"]
    };

    write_user_policy(BASE_POLICY);
    let (warning_response, warning) = check(&state, WARNING_COMMAND);
    assert_eq!(warning_response.status, 2, "{warning}");
    assert_eq!(warning["action"], "warn", "{warning}");
    assert_eq!(warning["requires_approval"], false, "{warning}");
    assert!(
        warning["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["rule_id"] == "web3_address_in_url"
                && finding["severity"] == "LOW")
    );
    let (critical_response, critical) = check(&state, CRITICAL_COMMAND);
    assert_eq!(critical_response.status, 1, "{critical}");
    assert_eq!(critical["action"], "block", "{critical}");
    assert_eq!(critical["requires_approval"], false, "{critical}");
    assert!(critical["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["severity"] == "CRITICAL"));
    for tool in tools {
        for fail_open in [false, true] {
            assert!(callback(
                &state,
                host,
                tool,
                &warning_response,
                "allow",
                fail_open,
                "none"
            )
            .is_null());
            assert_blocked(
                host,
                callback(
                    &state,
                    host,
                    tool,
                    &critical_response,
                    "allow",
                    fail_open,
                    "none",
                ),
            );
        }
        assert_blocked(
            host,
            callback(&state, host, tool, &warning_response, "deny", true, "none"),
        );
    }

    write_user_policy(APPROVAL_POLICY);
    let (approval_response, approval) = check(&state, WARNING_COMMAND);
    assert_eq!(approval_response.status, 2, "{approval}");
    assert_eq!(approval["action"], warning["action"], "{approval}");
    assert_eq!(approval["findings"], warning["findings"], "{approval}");
    assert_eq!(approval["requires_approval"], true, "{approval}");
    for tool in tools {
        for fail_open in [false, true] {
            assert_blocked(
                host,
                callback(
                    &state,
                    host,
                    tool,
                    &approval_response,
                    "allow",
                    fail_open,
                    "none",
                ),
            );
        }
    }
    assert!(callback(
        &state,
        host,
        "read",
        &approval_response,
        "allow",
        true,
        "none"
    )
    .is_null());

    // User strict-warn acknowledgement gates JSON without changing the
    // standalone warning exit code. This scenario uses unmodified CLI output.
    write_user_policy(STRICT_WARN_POLICY);
    let (acknowledgement_response, acknowledgement) = check(&state, WARNING_COMMAND);
    assert_eq!(acknowledgement_response.status, 2, "{acknowledgement}");
    assert_eq!(acknowledgement["action"], "warn", "{acknowledgement}");
    assert_eq!(
        acknowledgement["requires_approval"], true,
        "{acknowledgement}"
    );
    for tool in tools {
        for fail_open in [false, true] {
            assert_blocked(
                host,
                callback(
                    &state,
                    host,
                    tool,
                    &acknowledgement_response,
                    "allow",
                    fail_open,
                    "none",
                ),
            );
        }
    }

    // Info-only evidence allows without a gate. A required confirmation is
    // normalized to Warn/rc2 so it cannot masquerade as executable Allow.
    write_user_policy(INFO_POLICY);
    let (info_response, info) = check(&state, WARNING_COMMAND);
    assert_eq!(info_response.status, 0, "{info}");
    assert_eq!(info["action"], "allow", "{info}");
    assert_eq!(info["requires_approval"], false, "{info}");
    for tool in tools {
        assert!(callback(&state, host, tool, &info_response, "allow", true, "none").is_null());
    }
    write_user_policy(INFO_APPROVAL_POLICY);
    let (approval_response, approval) = check(&state, WARNING_COMMAND);
    assert_eq!(approval_response.status, 2, "{approval}");
    assert_eq!(approval["action"], "warn", "{approval}");
    assert_eq!(approval["findings"], info["findings"], "{approval}");
    assert_eq!(approval["requires_approval"], true, "{approval}");
    for tool in tools {
        for fail_open in [false, true] {
            assert_blocked(
                host,
                callback(
                    &state,
                    host,
                    tool,
                    &approval_response,
                    "allow",
                    fail_open,
                    "none",
                ),
            );
        }
    }

    // Mandatory-field and JSON faults follow checker-error policy, but can
    // never turn an existing critical denial into permission.
    write_user_policy(BASE_POLICY);
    let (clean_response, clean) = check(&state, CLEAN_COMMAND);
    assert_eq!(clean_response.status, 0, "{clean}");
    assert_eq!(clean["action"], "allow", "{clean}");
    assert_eq!(clean["requires_approval"], false, "{clean}");
    for mutation in ["absent", "non_boolean", "invalid_json"] {
        for response in [&clean_response, &warning_response] {
            assert_blocked(
                host,
                callback(&state, host, tools[0], response, "allow", false, mutation),
            );
            assert!(callback(&state, host, tools[0], response, "allow", true, mutation).is_null());
        }
        assert_blocked(
            host,
            callback(
                &state,
                host,
                tools[0],
                &critical_response,
                "allow",
                true,
                mutation,
            ),
        );
        assert_blocked(
            host,
            callback(
                &state,
                host,
                tools[0],
                &warning_response,
                "deny",
                true,
                mutation,
            ),
        );
    }

    // Project a real engine warning onto the explicit WarnAck/rc3 contract.
    // The exit status must retain the gate even when its JSON cannot express it.
    for mutation in [
        "warn_ack",
        "warn_ack_absent",
        "warn_ack_non_boolean",
        "warn_ack_invalid_json",
    ] {
        for tool in tools {
            for fail_open in [false, true] {
                assert_blocked(
                    host,
                    callback(
                        &state,
                        host,
                        tool,
                        &warning_response,
                        "allow",
                        fail_open,
                        mutation,
                    ),
                );
            }
        }
    }
}

#[test]
fn pi_cli_callback_enforces_real_user_approval_gates() {
    exercise_host("pi-cli");
}

#[test]
fn prime_agent_callback_enforces_real_user_approval_gates() {
    exercise_host("prime-agent");
}

#[test]
fn omp_callback_enforces_real_user_approval_gates() {
    exercise_host("omp");
}

#[test]
fn openclaw_callbacks_enforce_real_user_approval_gates() {
    exercise_host("openclaw");
}

#[test]
fn typed_callbacks_complete_real_checks_with_shipped_deadlines() {
    let mut state = GlobalStateGuard::new().unwrap();
    state.remove_env("TIRITH_POLICY_ROOT");
    if !node_available(&state) {
        return;
    }

    // Keep a separate end-to-end proof: the exact shipped callbacks launch the
    // real executable with their original argv/stdin and deadline. No capture
    // is returned in live mode. Each cold subprocess must finish and match the
    // real producer's action, findings, approval gate, and exit status before
    // its host decision is asserted. Timeout/fail-open is never counted as a
    // passing approval case. This runtime proof remains load-sensitive; the
    // complete decision matrix above does not depend on subprocess deadlines.
    for (policy, requires_approval) in [(BASE_POLICY, false), (APPROVAL_POLICY, true)] {
        write_user_policy(policy);
        let (response, verdict) = check(&state, WARNING_COMMAND);
        assert_eq!(response.status, 2, "{verdict}");
        assert_eq!(verdict["action"], "warn", "{verdict}");
        assert_eq!(verdict["requires_approval"], requires_approval, "{verdict}");
        for (host, tool) in [
            ("pi-cli", "bash"),
            ("prime-agent", "bash"),
            ("omp", "bash"),
            ("openclaw", "exec"),
            ("openclaw", "bash"),
        ] {
            let mut node = callback_command(&state, host, tool, &response, "allow", true);
            node.env("TIRITH_TEST_CHECK_TRANSPORT", "live");
            let result = run_callback(node, host, tool);
            if requires_approval {
                assert_blocked(host, result);
            } else {
                assert!(result.is_null(), "{host}/{tool}: {result}");
            }
        }
    }
}
