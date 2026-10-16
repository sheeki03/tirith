//! Exercise installed editor hooks and the non-interactive zsh guard against
//! the real checker and isolated operator policy. Fault cases corrupt real
//! checker responses, rather than substituting a canned verdict.
#![cfg(unix)]

use serde_json::{json, Value};
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const TIRITH: &str = env!("CARGO_BIN_EXE_tirith");
const WARNING_COMMAND: &str = "printf '%s\\n' https://github.com:8443/api";
const CLEAN_COMMAND: &str = "printf safe";
const SYSTEM_DIRS: [&str; 6] = [
    "/usr/bin",
    "/bin",
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/run/current-system/sw/bin",
    "/nix/var/nix/profiles/default/bin",
];

fn system_binary(name: &str) -> Option<PathBuf> {
    SYSTEM_DIRS.iter().find_map(|directory| {
        let path = Path::new(directory).join(name);
        fs::metadata(&path)
            .ok()
            .filter(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
            .map(|_| path)
    })
}

fn quote(path: &Path) -> String {
    format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"))
}

struct Workspace {
    root: tempfile::TempDir,
    home: PathBuf,
    work: PathBuf,
    python: PathBuf,
    bash: PathBuf,
}

impl Workspace {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let work = root.path().join("work");
        for directory in [
            home.clone(),
            work.clone(),
            home.join("config/tirith"),
            root.path().join("tmp"),
        ] {
            fs::create_dir_all(directory).unwrap();
        }
        // Stop repository discovery before it can leave the isolated fixture.
        fs::create_dir(work.join(".git")).unwrap();
        Self {
            root,
            home,
            work,
            python: system_binary("python3").expect("shell hook tests require Python 3"),
            bash: system_binary("bash").expect("shell hook tests require bash"),
        }
    }

    fn command(&self, executable: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = Command::new(executable);
        command
            .env_clear()
            .current_dir(&self.work)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join("config"))
            .env("XDG_DATA_HOME", self.home.join("data"))
            .env("XDG_STATE_HOME", self.home.join("state"))
            .env("XDG_CACHE_HOME", self.home.join("cache"))
            .env("TMPDIR", self.root.path().join("tmp"))
            .env("PATH", SYSTEM_DIRS.join(":"))
            .env("SHELL", &self.bash)
            .env("TERM", "dumb")
            .env("NO_COLOR", "1")
            .env("TIRITH_OFFLINE", "1")
            .env("TIRITH_LOG", "0")
            .env("TIRITH_HOOK_WARN_ACTION", "allow");
        command
    }

    fn policy(&self, severity: &str, approval: bool) {
        let mut policy =
            format!("paranoia: 3\nseverity_overrides:\n  non_standard_port: {severity}\n");
        if approval {
            // Even a permissive timeout fallback cannot grant a non-interactive
            // integration permission before a human has approved the command.
            policy.push_str(
                "approval_rules:\n  - rule_ids: [non_standard_port]\n    timeout_secs: 1\n    fallback: allow\n",
            );
        }
        fs::write(self.home.join("config/tirith/policy.yaml"), policy).unwrap();
    }

    fn setup(&self, host: Host, zshenv: bool) -> PathBuf {
        let mut command = self.command(TIRITH);
        command.args(["setup", host.name(), "--scope", host.scope()]);
        if zshenv {
            command.arg("--install-zshenv");
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "setup {}: {output:?}", host.name());
        host.hook_path(self)
    }

    fn check(&self, host: &str, command: &str, expected_rc: i32, approval: bool, severity: &str) {
        let output = with_stdin(
            self.command(TIRITH).env("TIRITH_INTEGRATION", host).args([
                "check",
                "--json",
                "--no-daemon",
                "--non-interactive",
                "--shell",
                "posix",
            ]),
            command.as_bytes(),
        );
        assert_eq!(
            output.status.code(),
            Some(expected_rc),
            "{host}: {output:?}"
        );
        let verdict: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(verdict["requires_approval"].as_bool(), Some(approval));
        assert!(
            verdict["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|finding| {
                    finding["rule_id"] == "non_standard_port"
                        && finding["severity"]
                            .as_str()
                            .is_some_and(|value| value.eq_ignore_ascii_case(severity))
                }),
            "{verdict}"
        );
    }

    fn hook(
        &self,
        host: Host,
        path: &Path,
        command: &str,
        fail_open: bool,
        warn_action: &str,
    ) -> Output {
        let mut process = self.command(&self.bash);
        process
            .arg(path)
            .env("TIRITH_HOOK_WARN_ACTION", warn_action);
        if fail_open {
            process.env("TIRITH_FAIL_OPEN", "1");
        }
        with_stdin(
            &mut process,
            &serde_json::to_vec(&host.input(command)).unwrap(),
        )
    }

    fn zsh(&self, shell: &Path, command: &str, fail_open: bool) -> Output {
        let mut process = self.command(shell);
        process.args(["-lc", command]).env("ZDOTDIR", &self.home);
        if fail_open {
            process.env("TIRITH_FAIL_OPEN", "1");
        }
        // The approval-check protocol deliberately ignores command stdin. A
        // clean stdin payload must not replace the actual argv execution string.
        with_stdin(&mut process, b"printf clean-stdin\n")
    }

    fn fault_proxy(&self) -> PathBuf {
        let script = self.root.path().join("response_fault.py");
        fs::write(&script, RESPONSE_FAULT).unwrap();
        let wrapper = self.root.path().join("checker-response-fault");
        fs::write(
            &wrapper,
            format!(
                "#!{}\nexec {} -I -S {} \"$@\"\n",
                self.bash.display(),
                quote(&self.python),
                quote(&script)
            ),
        )
        .unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
        wrapper
    }

    fn fault_environment(&self, command: &mut Command, fault: &str) {
        command
            .env("TIRITH_TEST_REAL_BIN", TIRITH)
            .env("TIRITH_TEST_METADATA_FAULT", fault)
            .env(
                "TIRITH_TEST_CHECK_EVIDENCE",
                self.root.path().join("real-check.json"),
            )
            .env(
                "TIRITH_TEST_INJECTION_MARKER",
                self.root.path().join("json-must-not-execute"),
            );
    }
}

fn with_stdin(command: &mut Command, input: &[u8]) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Host {
    Cursor,
    Vscode,
    Windsurf,
}

const HOSTS: [Host; 3] = [Host::Cursor, Host::Vscode, Host::Windsurf];

impl Host {
    fn name(self) -> &'static str {
        match self {
            Self::Cursor => "cursor",
            Self::Vscode => "vscode",
            Self::Windsurf => "windsurf",
        }
    }

    fn scope(self) -> &'static str {
        match self {
            Self::Vscode => "project",
            _ => "user",
        }
    }

    fn hook_path(self, workspace: &Workspace) -> PathBuf {
        match self {
            Self::Cursor => workspace.home.join(".cursor/hooks/tirith-hook.sh"),
            Self::Vscode => workspace.work.join(".vscode/hooks/tirith-hook.sh"),
            Self::Windsurf => workspace
                .home
                .join(".codeium/windsurf/hooks/tirith-hook.sh"),
        }
    }

    fn input(self, command: &str) -> Value {
        match self {
            Self::Cursor => json!({"command": command}),
            Self::Vscode => json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": command},
            }),
            Self::Windsurf => json!({"tool_info": {"command_line": command}}),
        }
    }

    fn assert_permission(self, output: &Output, allowed: bool) {
        match self {
            Self::Windsurf => assert_eq!(
                output.status.code(),
                Some(if allowed { 0 } else { 2 }),
                "{output:?}"
            ),
            Self::Cursor => {
                assert!(output.status.success(), "{output:?}");
                let response: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(
                    response["permission"],
                    if allowed { "allow" } else { "deny" },
                    "{response}"
                );
            }
            Self::Vscode => {
                assert!(output.status.success(), "{output:?}");
                if output.stdout.is_empty() {
                    assert!(
                        allowed,
                        "a denied command must return a permission decision"
                    );
                } else {
                    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
                    if allowed {
                        // Never an explicit allow: VS Code's own confirmation
                        // rules decide, exactly as for a clean command.
                        assert!(
                            response["hookSpecificOutput"]
                                .get("permissionDecision")
                                .is_none(),
                            "{response}"
                        );
                    } else {
                        assert_eq!(
                            response["hookSpecificOutput"]["permissionDecision"], "deny",
                            "{response}"
                        );
                    }
                }
            }
        }
    }

    /// The text a host shows for a decision: stdout JSON and stderr together.
    fn decision_text(output: &Output) -> String {
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }
}

#[test]
fn installed_shell_hooks_answer_warnings_without_approving_them() {
    for host in HOSTS {
        let workspace = Workspace::new();
        workspace.policy("LOW", false);
        let hook = workspace.setup(host, false);
        workspace.check(host.name(), WARNING_COMMAND, 2, false, "LOW");

        // Default: no approval. VS Code gets the warning for the user and the
        // model with no permissionDecision; Cursor, which must always answer
        // with a permission, gets the same "allow" a clean command gets, with
        // the findings for the user and the agent; Windsurf exits 0 as for a
        // clean command, findings on stderr.
        for warn_action in ["", "allow", "Allow"] {
            let output = workspace.hook(host, &hook, WARNING_COMMAND, false, warn_action);
            host.assert_permission(&output, true);
            match host {
                Host::Vscode => {
                    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
                    for message in [
                        &response["systemMessage"],
                        &response["hookSpecificOutput"]["additionalContext"],
                    ] {
                        let message = message.as_str().expect("warning for user and model");
                        assert!(message.contains("(non_standard_port)"), "{message}");
                        assert!(message.contains("[LOW]"), "{message}");
                    }
                }
                Host::Cursor => {
                    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
                    for field in ["user_message", "agent_message"] {
                        assert!(
                            response[field].as_str().unwrap().contains("[LOW]"),
                            "{response}"
                        );
                    }
                }
                Host::Windsurf => {
                    assert!(String::from_utf8_lossy(&output.stderr).contains("[LOW]"));
                }
            }
        }

        // ask: VS Code and Cursor ask the user; Windsurf has no prompt and
        // denies with interactive-shell guidance.
        let output = workspace.hook(host, &hook, WARNING_COMMAND, true, "ask");
        match host {
            Host::Vscode => {
                let response: Value = serde_json::from_slice(&output.stdout).unwrap();
                let specific = &response["hookSpecificOutput"];
                assert_eq!(specific["permissionDecision"], "ask", "{response}");
                assert!(specific["permissionDecisionReason"]
                    .as_str()
                    .unwrap()
                    .contains("non_standard_port"));
            }
            Host::Cursor => {
                let response: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(response["permission"], "ask", "{response}");
                assert!(response["user_message"].as_str().unwrap().contains("[LOW]"));
            }
            Host::Windsurf => {
                host.assert_permission(&output, false);
                let text = Host::decision_text(&output);
                assert!(text.contains("TIRITH_HOOK_WARN_ACTION=ask"), "{text}");
                assert!(text.contains("interactive shell"), "{text}");
            }
        }

        // An unrecognized value fails closed and names the valid values.
        for warn_action in ["block", "allow-auto"] {
            for fail_open in [false, true] {
                let output = workspace.hook(host, &hook, WARNING_COMMAND, fail_open, warn_action);
                host.assert_permission(&output, false);
                let text = Host::decision_text(&output);
                assert!(text.contains("valid values: allow, ask, deny"), "{text}");
                assert!(text.contains(warn_action), "{text}");
            }
        }
        // A clean command is unaffected by the warn action.
        for warn_action in ["ask", "deny", "block"] {
            host.assert_permission(
                &workspace.hook(host, &hook, CLEAN_COMMAND, false, warn_action),
                true,
            );
        }
    }
}

#[test]
fn installed_shell_hooks_honor_real_operator_approval_without_warning_or_failure_bypass() {
    for host in HOSTS {
        let workspace = Workspace::new();
        workspace.policy("LOW", false);
        let hook = workspace.setup(host, false);
        host.assert_permission(
            &workspace.hook(host, &hook, CLEAN_COMMAND, false, "allow"),
            true,
        );
        workspace.check(host.name(), WARNING_COMMAND, 2, false, "LOW");
        host.assert_permission(
            &workspace.hook(host, &hook, WARNING_COMMAND, false, "allow"),
            true,
        );
        host.assert_permission(
            &workspace.hook(host, &hook, WARNING_COMMAND, false, "deny"),
            false,
        );

        workspace.policy("LOW", true);
        workspace.check(host.name(), WARNING_COMMAND, 2, true, "LOW");
        for fail_open in [false, true] {
            host.assert_permission(
                &workspace.hook(host, &hook, WARNING_COMMAND, fail_open, "allow"),
                false,
            );
        }

        // A real strict-warning policy also requires host acknowledgement,
        // without changing the standalone non-interactive check's rc2.
        workspace.policy("LOW", false);
        let policy_path = workspace.home.join("config/tirith/policy.yaml");
        let policy = fs::read_to_string(&policy_path).unwrap();
        fs::write(&policy_path, format!("{policy}strict_warn: true\n")).unwrap();
        workspace.check(host.name(), WARNING_COMMAND, 2, true, "LOW");
        for fail_open in [false, true] {
            host.assert_permission(
                &workspace.hook(host, &hook, WARNING_COMMAND, fail_open, "allow"),
                false,
            );
        }

        workspace.policy("CRITICAL", true);
        host.assert_permission(
            &workspace.hook(host, &hook, WARNING_COMMAND, true, "allow"),
            false,
        );
    }
}

#[test]
fn installed_shell_hooks_reject_malformed_approval_metadata_unless_operator_fails_open() {
    for host in HOSTS {
        let workspace = Workspace::new();
        workspace.policy("LOW", false);
        let hook = workspace.setup(host, false);
        let proxy = workspace.fault_proxy();
        for command in [CLEAN_COMMAND, WARNING_COMMAND] {
            for fault in ["missing", "null", "string", "number", "shell_expression"] {
                for fail_open in [false, true] {
                    let mut process = workspace.command(&workspace.bash);
                    process.arg(&hook).env("TIRITH_BIN", &proxy);
                    workspace.fault_environment(&mut process, fault);
                    if fail_open {
                        process.env("TIRITH_FAIL_OPEN", "1");
                    }
                    let output = with_stdin(
                        &mut process,
                        &serde_json::to_vec(&host.input(command)).unwrap(),
                    );
                    host.assert_permission(&output, fail_open);
                    let original: Value = serde_json::from_slice(
                        &fs::read(workspace.root.path().join("real-check.json")).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(original["requires_approval"].as_bool(), Some(false));
                    assert!(!workspace.root.path().join("json-must-not-execute").exists());
                }
                if command == WARNING_COMMAND {
                    // A gated warning (deny, ask, or an unrecognized value)
                    // stays denied when its response is damaged.
                    for warn_action in ["DENY", "ask", "block"] {
                        let mut process = workspace.command(&workspace.bash);
                        process
                            .arg(&hook)
                            .env("TIRITH_BIN", &proxy)
                            .env("TIRITH_FAIL_OPEN", "1")
                            .env("TIRITH_HOOK_WARN_ACTION", warn_action);
                        workspace.fault_environment(&mut process, fault);
                        let output = with_stdin(
                            &mut process,
                            &serde_json::to_vec(&host.input(command)).unwrap(),
                        );
                        host.assert_permission(&output, false);
                    }
                }
            }
        }
    }
}

#[test]
fn installed_shell_hooks_deny_warning_acknowledgement_even_with_fail_open_or_corrupt_metadata() {
    for host in HOSTS {
        let workspace = Workspace::new();
        workspace.policy("LOW", false);
        let hook = workspace.setup(host, false);
        workspace.check(host.name(), WARNING_COMMAND, 2, false, "LOW");
        let proxy = workspace.fault_proxy();
        for fault in ["warn_ack", "warn_ack_missing", "warn_ack_malformed"] {
            for fail_open in [false, true] {
                let mut process = workspace.command(&workspace.bash);
                process.arg(&hook).env("TIRITH_BIN", &proxy);
                workspace.fault_environment(&mut process, fault);
                if fail_open {
                    process.env("TIRITH_FAIL_OPEN", "1");
                }
                let output = with_stdin(
                    &mut process,
                    &serde_json::to_vec(&host.input(WARNING_COMMAND)).unwrap(),
                );
                host.assert_permission(&output, false);
                let original: Value = serde_json::from_slice(
                    &fs::read(workspace.root.path().join("real-check.json")).unwrap(),
                )
                .unwrap();
                assert_eq!(original["requires_approval"].as_bool(), Some(false));
            }
        }
    }
}

#[test]
fn installed_shell_hooks_deny_deferred_blocks_and_allow_an_honored_bypass() {
    for host in HOSTS {
        let workspace = Workspace::new();
        workspace.policy("HIGH", false);
        let hook = workspace.setup(host, false);
        // TIRITH_DEFER=1 records a non-critical block for review and exits 4.
        let output = with_stdin(
            workspace.command(TIRITH).env("TIRITH_DEFER", "1").args([
                "check",
                "--json",
                "--no-daemon",
                "--non-interactive",
                "--shell",
                "posix",
            ]),
            WARNING_COMMAND.as_bytes(),
        );
        assert_eq!(output.status.code(), Some(4), "{}: {output:?}", host.name());
        for fail_open in [false, true] {
            let mut process = workspace.command(&workspace.bash);
            process.arg(&hook).env("TIRITH_DEFER", "1");
            if fail_open {
                process.env("TIRITH_FAIL_OPEN", "1");
            }
            host.assert_permission(
                &with_stdin(
                    &mut process,
                    &serde_json::to_vec(&host.input(WARNING_COMMAND)).unwrap(),
                ),
                false,
            );
        }

        // A policy-honored TIRITH=0 bypass emits the allow envelope, as 0.4.x
        // adapters relied on; without the request the block still stands.
        workspace.policy("CRITICAL", false);
        let policy_path = workspace.home.join("config/tirith/policy.yaml");
        let policy = fs::read_to_string(&policy_path).unwrap();
        fs::write(
            &policy_path,
            format!("{policy}allow_bypass_env: true\nallow_bypass_env_noninteractive: true\n"),
        )
        .unwrap();
        let mut process = workspace.command(&workspace.bash);
        process.arg(&hook).env("TIRITH", "0");
        host.assert_permission(
            &with_stdin(
                &mut process,
                &serde_json::to_vec(&host.input(WARNING_COMMAND)).unwrap(),
            ),
            true,
        );
        host.assert_permission(
            &workspace.hook(host, &hook, WARNING_COMMAND, true, "allow"),
            false,
        );
    }
}

#[test]
fn installed_vscode_hook_denies_a_shell_tool_call_without_a_string_command() {
    let workspace = Workspace::new();
    workspace.policy("LOW", false);
    let hook = workspace.setup(Host::Vscode, false);
    // Telemetry may still call the binary; only a `check` marks the run, and
    // answers with a clean verdict.
    let marker = workspace.root.path().join("checker-ran");
    let recorder = workspace.root.path().join("recording-checker");
    fs::write(
        &recorder,
        format!(
            "#!{}\nif [ \"$1\" = check ]; then\n  : > {}\n  printf '%s\\n' '{}'\nfi\nexit 0\n",
            workspace.bash.display(),
            quote(&marker),
            json!({"action": "allow", "requires_approval": false, "findings": []}),
        ),
    )
    .unwrap();
    fs::set_permissions(&recorder, fs::Permissions::from_mode(0o700)).unwrap();
    let run = |payload: &Value, fail_open: bool| {
        let mut process = workspace.command(&workspace.bash);
        process.arg(&hook).env("TIRITH_BIN", &recorder);
        if fail_open {
            process.env("TIRITH_FAIL_OPEN", "1");
        }
        with_stdin(&mut process, &serde_json::to_vec(payload).unwrap())
    };

    let shell_call = |tool_input: Value| json!({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": tool_input});
    let mut payloads = [
        json!({}),
        json!("printf safe"),
        json!(null),
        json!({"command": ["printf", "safe"]}),
        json!({"command": null}),
        json!({"command": 7}),
        json!({"command": " \n "}),
        json!({"commandLine": "printf safe"}),
    ]
    .map(shell_call)
    .to_vec();
    payloads.push(json!({"hook_event_name": "PreToolUse", "tool_name": "Bash"}));
    for payload in &payloads {
        let output = run(payload, false);
        Host::Vscode.assert_permission(&output, false);
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            response["hookSpecificOutput"]["permissionDecisionReason"],
            "tirith: no command found in hook input — blocked for safety",
            "{payload}"
        );
        // Like an unparseable payload, an operator's fail-open allows it.
        Host::Vscode.assert_permission(&run(payload, true), true);
        assert!(!marker.exists(), "{payload}: no command to check");
    }

    // Calls the hook does not guard stay silent allows.
    for payload in [
        json!({"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {}}),
        json!({"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {}}),
    ] {
        let output = run(&payload, false);
        assert!(output.status.success(), "{payload}: {output:?}");
        assert!(output.stdout.is_empty(), "{payload}: {output:?}");
    }
    assert!(!marker.exists());

    // A real command is still checked.
    Host::Vscode.assert_permission(
        &run(&shell_call(json!({"command": CLEAN_COMMAND})), false),
        true,
    );
    assert!(marker.exists());
}

#[test]
fn installed_zshenv_allows_an_honored_bypass_and_refuses_an_unhonored_one() {
    let Some(zsh) = system_binary("zsh") else {
        eprintln!("skipping non-interactive zsh guard: zsh is unavailable");
        return;
    };
    let workspace = Workspace::new();
    workspace.policy("CRITICAL", false);
    workspace.setup(Host::Cursor, true);
    let marker = workspace.root.path().join("command-output");
    let command = format!("{WARNING_COMMAND} > {}", quote(&marker));
    let run = |bypass: bool| {
        let mut process = workspace.command(&zsh);
        process
            .args(["-lc", &command])
            .env("ZDOTDIR", &workspace.home);
        if bypass {
            process.env("TIRITH", "0");
        }
        with_stdin(&mut process, b"printf clean-stdin\n")
    };
    let temp_entries = || {
        fs::read_dir(workspace.root.path().join("tmp"))
            .unwrap()
            .count()
    };
    let policy_path = workspace.home.join("config/tirith/policy.yaml");
    let blocking_policy = fs::read_to_string(&policy_path).unwrap();

    let output = run(false);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(!marker.exists());

    // The policy honors TIRITH=0 for non-interactive callers, so the guard must
    // read the checker's no-approval metadata and run the command.
    fs::write(
        &policy_path,
        format!("{blocking_policy}allow_bypass_env: true\nallow_bypass_env_noninteractive: true\n"),
    )
    .unwrap();
    let output = run(true);
    assert!(output.status.success(), "{output:?}");
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("invalid approval metadata"),
        "{output:?}"
    );
    assert_eq!(fs::read(&marker).unwrap(), b"https://github.com:8443/api\n");
    fs::remove_file(&marker).unwrap();
    assert_eq!(temp_entries(), 0, "approval metadata must be cleaned up");
    // The grant covers only a requested bypass.
    let output = run(false);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(!marker.exists());

    // Without the non-interactive grant, the requested bypass is refused.
    fs::write(
        &policy_path,
        format!("{blocking_policy}allow_bypass_env: true\n"),
    )
    .unwrap();
    let output = run(true);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(!marker.exists());
    assert_eq!(temp_entries(), 0, "approval metadata must be cleaned up");
}

#[test]
fn installed_shell_hooks_never_import_python_modules_from_the_working_directory() {
    for host in HOSTS {
        let workspace = Workspace::new();
        workspace.policy("LOW", false);
        let hook = workspace.setup(host, false);
        let marker = workspace.root.path().join("planted-json-imported");
        // The hook runs with the agent's project as its working directory. A
        // json.py planted there must never shadow the standard library module.
        fs::write(
            workspace.work.join("json.py"),
            format!(
                "import pathlib\npathlib.Path({}).touch()\n",
                serde_json::to_string(marker.to_str().unwrap()).unwrap()
            ),
        )
        .unwrap();
        for (command, warn_action, allowed) in [
            (CLEAN_COMMAND, "allow", true),
            (WARNING_COMMAND, "allow", true),
            (WARNING_COMMAND, "deny", false),
        ] {
            host.assert_permission(
                &workspace.hook(host, &hook, command, false, warn_action),
                allowed,
            );
            assert!(
                !marker.exists(),
                "{}: planted json.py was imported for {command:?}/{warn_action}",
                host.name()
            );
        }
    }
}

#[test]
fn installed_zshenv_allows_false_warning_but_denies_pending_approval_and_critical() {
    let Some(zsh) = system_binary("zsh") else {
        eprintln!("skipping non-interactive zsh guard: zsh is unavailable");
        return;
    };
    let workspace = Workspace::new();
    workspace.policy("LOW", false);
    workspace.setup(Host::Cursor, true);
    let marker = workspace.root.path().join("command's output");
    let clean = format!("{CLEAN_COMMAND} > {}", quote(&marker));
    let output = workspace.zsh(&zsh, &clean, false);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(fs::read(&marker).unwrap(), b"safe");
    fs::remove_file(&marker).unwrap();
    let command = format!("{WARNING_COMMAND} > {}", quote(&marker));
    workspace.check("cursor", &command, 2, false, "LOW");
    let output = workspace.zsh(&zsh, &command, false);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(fs::read(&marker).unwrap(), b"https://github.com:8443/api\n");
    fs::remove_file(&marker).unwrap();

    workspace.policy("LOW", true);
    workspace.check("cursor", &command, 2, true, "LOW");
    for fail_open in [false, true] {
        let output = workspace.zsh(&zsh, &command, fail_open);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(!marker.exists());
    }
    workspace.policy("CRITICAL", true);
    let output = workspace.zsh(&zsh, &command, true);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(!marker.exists());
    assert_eq!(
        fs::read_dir(workspace.root.path().join("tmp"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn installed_zshenv_denies_corrupt_literal_metadata_without_interpreting_it() {
    let Some(zsh) = system_binary("zsh") else {
        eprintln!("skipping non-interactive zsh guard: zsh is unavailable");
        return;
    };
    let workspace = Workspace::new();
    workspace.policy("LOW", false);
    workspace.setup(Host::Cursor, true);
    let proxy = workspace.fault_proxy();
    let zshenv = workspace.home.join(".zshenv");
    // Point the installed guard at a response-corrupting transport that still
    // calls the actual checker. This is fault injection, not a source assertion.
    let installed = fs::read_to_string(&zshenv).unwrap();
    let injected = installed
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("_tirith_bin=") {
                format!("  _tirith_bin={}", quote(&proxy))
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&zshenv, format!("{injected}\n")).unwrap();
    let marker = workspace.root.path().join("command-output");
    for checked_command in [CLEAN_COMMAND, WARNING_COMMAND] {
        let command = format!("{checked_command} > {}", quote(&marker));
        for fault in [
            "missing",
            "string",
            "duplicate",
            "shell_expression",
            "public_permissions",
            "symlink",
            "fifo",
            "hardlink",
            "oversized",
        ] {
            let mut process = workspace.command(&zsh);
            process
                .args(["-lc", &command])
                .env("ZDOTDIR", &workspace.home);
            workspace.fault_environment(&mut process, fault);
            let output = with_stdin(&mut process, b"printf clean-stdin\n");
            assert_eq!(output.status.code(), Some(1), "{fault}: {output:?}");
            let original =
                fs::read_to_string(workspace.root.path().join("real-check.json")).unwrap();
            assert_eq!(
                original
                    .lines()
                    .filter_map(|line| line.strip_prefix("TIRITH_REQUIRES_APPROVAL="))
                    .collect::<Vec<_>>(),
                ["no"]
            );
            assert!(!marker.exists());
            assert!(!workspace.root.path().join("json-must-not-execute").exists());
            assert_eq!(
                fs::read_dir(workspace.root.path().join("tmp"))
                    .unwrap()
                    .count(),
                0
            );
        }
    }
}

const RESPONSE_FAULT: &str = r#"import json
import os
import pathlib
import shlex
import subprocess
import sys

args = sys.argv[1:]
result = subprocess.run([os.environ['TIRITH_TEST_REAL_BIN'], *args],
                        input=sys.stdin.buffer.read(), stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, check=False)
output = result.stdout
returncode = result.returncode
if args and args[0] == 'check' and result.returncode in (0, 2):
    fault = os.environ['TIRITH_TEST_METADATA_FAULT']
    marker = shlex.quote(os.environ['TIRITH_TEST_INJECTION_MARKER'])
    expression = '$(touch ' + marker + ')'
    if '--json' in args:
        pathlib.Path(os.environ['TIRITH_TEST_CHECK_EVIDENCE']).write_bytes(output)
        document = json.loads(output)
        if fault.startswith('warn_ack'):
            returncode = 3
            document['requires_approval'] = True
            if fault == 'warn_ack_missing':
                del document['requires_approval']
        elif fault == 'missing':
            del document['requires_approval']
        else:
            document['requires_approval'] = {
                'null': None, 'string': 'false', 'number': 0,
                'shell_expression': expression,
            }[fault]
        output = b'{' if fault == 'warn_ack_malformed' else json.dumps(document).encode()
    elif '--approval-check' in args:
        path = pathlib.Path(output.decode().splitlines()[0])
        original = path.read_text()
        pathlib.Path(os.environ['TIRITH_TEST_CHECK_EVIDENCE']).write_text(original)
        if fault == 'public_permissions':
            path.chmod(0o644)
        elif fault in ('symlink', 'hardlink'):
            target = pathlib.Path(os.environ['TIRITH_TEST_CHECK_EVIDENCE']).with_suffix('.env')
            if target.exists():
                target.unlink()
            target.write_text(original)
            target.chmod(0o600)
            if fault == 'symlink':
                path.unlink()
                path.symlink_to(target)
            else:
                target.unlink()
                os.link(path, target)
        elif fault == 'fifo':
            path.unlink()
            os.mkfifo(path, 0o600)
        elif fault == 'oversized':
            path.write_text(original + 'X' * 2048)
        else:
            lines = [line for line in original.splitlines()
                     if not line.startswith('TIRITH_REQUIRES_APPROVAL=')]
            if fault == 'duplicate':
                lines += ['TIRITH_REQUIRES_APPROVAL=yes', 'TIRITH_REQUIRES_APPROVAL=no']
            elif fault != 'missing':
                value = expression if fault == 'shell_expression' else 'false'
                lines.append('TIRITH_REQUIRES_APPROVAL=' + value)
            path.write_text('\n'.join(lines) + '\n')
sys.stdout.buffer.write(output)
sys.stderr.buffer.write(result.stderr)
sys.exit(returncode)
"#;
