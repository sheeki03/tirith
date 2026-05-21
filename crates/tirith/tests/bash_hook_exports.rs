//! Tests for the bash hook's effective-state exports and `tirith doctor`'s
//! rendering of them.
//!
//! The hook exports two public env vars so that `tirith doctor` — a child
//! process that cannot read the parent shell's locals — can truthfully
//! report the live state of the parent shell:
//!
//! * `TIRITH_BASH_EFFECTIVE_MODE` ∈ {`enter`, `preexec`, `disabled`}
//! * `TIRITH_BASH_EFFECTIVE_PROTECTION` ∈ {`blocks`, `warn-only`, `disabled`}
//!
//! Both exports are gated on interactive shells (`[[ $- == *i* ]]`) so that
//! a non-interactive `source` does not leak a misleading status into child
//! processes.

#![cfg(unix)]

use std::process::Command;

fn hook_path() -> String {
    format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// Split `extra_env` into a session-local shell prelude and real process env
/// vars. `_TIRITH_TEST_*` overrides MUST be session-local: the hook
/// deliberately unsets exported (env-inherited) `_TIRITH_TEST_*` values —
/// treating them as attacker-controllable — and honors only session-local ones.
fn split_test_env(extra_env: &[(&str, &str)]) -> (String, Vec<(String, String)>) {
    let mut prelude = String::new();
    let mut env_vars = Vec::new();
    for (k, v) in extra_env {
        if k.starts_with("_TIRITH_TEST_") {
            prelude.push_str(&format!("{k}='{v}'; "));
        } else {
            env_vars.push((k.to_string(), v.to_string()));
        }
    }
    (prelude, env_vars)
}

/// Source the hook inside a clean, interactive bash subshell with a fresh
/// state dir and print the two exported vars in `key=value` form.
fn source_hook_and_dump_exports(extra_env: &[(&str, &str)]) -> String {
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let hook = hook_path();
    let (prelude, env_vars) = split_test_env(extra_env);
    let script = format!(
        "{prelude}source '{hook}' 2>/dev/null; \
         printf 'MODE=%s\\nPROT=%s\\n' \
           \"${{TIRITH_BASH_EFFECTIVE_MODE:-}}\" \
           \"${{TIRITH_BASH_EFFECTIVE_PROTECTION:-}}\""
    );

    // Start from a minimal env so user shell config cannot influence results.
    let mut cmd = Command::new("bash");
    cmd.args(["--norc", "--noprofile", "-i", "-c", &script])
        .env_clear()
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("XDG_STATE_HOME", tmpdir.path());
    for (k, v) in &env_vars {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("failed to run bash");
    assert!(
        out.status.success(),
        "bash exited non-zero: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn hook_exports_enter_by_default_outside_ssh() {
    // Skip the startup health gate: in a non-PTY `bash -i -c` — including on
    // macOS's ancient /bin/bash 3.2, which CI runs — `bind -x` may not register,
    // so the gate would degrade enter->preexec. This test verifies *mode
    // resolution* (enter is the default outside SSH), independent of bind-x
    // viability; the PTY conformance harness covers actual delivery.
    let out = source_hook_and_dump_exports(&[("_TIRITH_TEST_SKIP_HEALTH", "1")]);
    assert!(
        out.contains("MODE=enter"),
        "expected MODE=enter, got:\n{out}"
    );
    assert!(
        out.contains("PROT=blocks"),
        "expected PROT=blocks, got:\n{out}"
    );
}

#[test]
fn hook_exports_preexec_warn_only_when_mode_requested() {
    let out = source_hook_and_dump_exports(&[("TIRITH_BASH_MODE", "preexec")]);
    assert!(
        out.contains("MODE=preexec"),
        "expected MODE=preexec, got:\n{out}"
    );
    assert!(
        out.contains("PROT=warn-only"),
        "expected PROT=warn-only, got:\n{out}"
    );
}

#[test]
fn hook_exports_preexec_in_ssh_sessions() {
    let out = source_hook_and_dump_exports(&[("SSH_CONNECTION", "1.2.3.4 1 5.6.7.8 22")]);
    assert!(
        out.contains("MODE=preexec"),
        "SSH sessions should resolve to preexec, got:\n{out}"
    );
    assert!(
        out.contains("PROT=warn-only"),
        "SSH preexec should report warn-only protection, got:\n{out}"
    );
}

#[test]
fn hook_does_not_export_in_noninteractive_shell() {
    // No `-i` flag: the hook must be a no-op and must NOT leak status vars
    // into child processes. Otherwise a scripted `source` would mislead a
    // later `tirith doctor` into claiming the shell is protected.
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let hook = hook_path();
    let script = format!(
        "source '{hook}' 2>/dev/null; \
         printf 'MODE=%s\\nPROT=%s\\n' \
           \"${{TIRITH_BASH_EFFECTIVE_MODE:-unset}}\" \
           \"${{TIRITH_BASH_EFFECTIVE_PROTECTION:-unset}}\""
    );

    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env_clear()
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("XDG_STATE_HOME", tmpdir.path())
        .output()
        .expect("failed to run bash");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("MODE=unset"),
        "non-interactive hook must not export MODE, got:\n{stdout}"
    );
    assert!(
        stdout.contains("PROT=unset"),
        "non-interactive hook must not export PROT, got:\n{stdout}"
    );
}

// Doctor is driven entirely off env vars, so we seed them directly and
// assert the formatted output splits "requested" (user-set knobs) from
// "effective" (live hook-exported state).

fn doctor_stdout(env: &[(&str, &str)]) -> String {
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let bin = env!("CARGO_BIN_EXE_tirith");

    // Run doctor as a direct child of bash so the ancestor-walking
    // `detect_shell` sees bash, even when the test harness (cargo/zsh) is
    // its own ancestor. Never use bash `exec` here — it replaces bash
    // in place and tirith's parent becomes the harness again.
    let export_lines: Vec<String> = env
        .iter()
        .map(|(k, v)| format!("export {k}={}", shell_quote(v)))
        .collect();
    let bash_script = format!("{}\n'{bin}' doctor", export_lines.join("\n"));

    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &bash_script])
        .env_clear()
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("XDG_STATE_HOME", tmpdir.path())
        .output()
        .expect("failed to run doctor");
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn shell_quote(s: &str) -> String {
    // Single-quote wrap only; test values never contain single quotes.
    format!("'{s}'")
}

#[test]
fn doctor_shows_effective_state_when_hook_loaded() {
    let stdout = doctor_stdout(&[
        ("TIRITH_BASH_MODE", "preexec"),
        ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ("TIRITH_BASH_EFFECTIVE_MODE", "preexec"),
        ("TIRITH_BASH_EFFECTIVE_PROTECTION", "blocks"),
    ]);
    assert!(
        stdout.contains("requested mode:       preexec"),
        "requested mode missing, got:\n{stdout}"
    );
    assert!(
        stdout.contains("requested enforce:    on"),
        "requested enforce should be on, got:\n{stdout}"
    );
    assert!(
        stdout.contains("bash mode:            preexec"),
        "effective bash mode missing, got:\n{stdout}"
    );
    assert!(
        stdout.contains("effective protection: blocks"),
        "effective protection missing, got:\n{stdout}"
    );
}

#[test]
fn doctor_distinguishes_requested_from_effective_on_degrade() {
    // User requested enforcement but the live hook reports warn-only —
    // simulates a mid-session degrade. Doctor must not paper over the
    // mismatch.
    let stdout = doctor_stdout(&[
        ("TIRITH_BASH_MODE", "preexec"),
        ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ("TIRITH_BASH_EFFECTIVE_MODE", "preexec"),
        ("TIRITH_BASH_EFFECTIVE_PROTECTION", "warn-only"),
    ]);
    assert!(
        stdout.contains("requested enforce:    on"),
        "requested enforce should still read on, got:\n{stdout}"
    );
    assert!(
        stdout.contains("effective protection: warn-only"),
        "effective protection should report the live degraded value, got:\n{stdout}"
    );
}

#[test]
fn doctor_reports_not_loaded_when_exports_absent() {
    // User set a bash knob (signalling they care about bash) but the hook
    // hasn't exported effective state — e.g. the shell was spawned
    // non-interactively so the hook no-op'd.
    let stdout = doctor_stdout(&[("TIRITH_BASH_MODE", "enter")]);
    assert!(
        stdout.contains("bash hook:            not loaded in this process"),
        "expected not-loaded marker, got:\n{stdout}"
    );
    // Must not claim an effective protection when nothing exported.
    assert!(
        !stdout.contains("effective protection:"),
        "should not print effective protection when hook not loaded, got:\n{stdout}"
    );
    // Requested mode must still render so the user sees their own setting.
    assert!(
        stdout.contains("requested mode:       enter"),
        "requested mode should echo the user's env var, got:\n{stdout}"
    );
}

#[test]
fn doctor_default_requested_mode_shown_when_env_unset() {
    // TIRITH_BASH_MODE unset but hook exports present (default enter mode).
    let stdout = doctor_stdout(&[
        ("TIRITH_BASH_EFFECTIVE_MODE", "enter"),
        ("TIRITH_BASH_EFFECTIVE_PROTECTION", "blocks"),
    ]);
    assert!(
        stdout.contains("requested mode:       (default)"),
        "unset mode should render as (default), got:\n{stdout}"
    );
    assert!(
        stdout.contains("bash mode:            enter"),
        "effective mode missing, got:\n{stdout}"
    );
}

/// Source the hook in an interactive subshell, run `body`, then dump the two
/// effective-state exports. Like `source_hook_and_dump_exports`, but lets a
/// test drive a state transition (e.g. a degrade) before the dump.
fn source_hook_run_and_dump(extra_env: &[(&str, &str)], body: &str) -> String {
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let hook = hook_path();
    let (prelude, env_vars) = split_test_env(extra_env);
    let script = format!(
        "{prelude}source '{hook}' 2>/dev/null; {body}; \
         printf 'MODE=%s\\nPROT=%s\\n' \
           \"${{TIRITH_BASH_EFFECTIVE_MODE:-}}\" \
           \"${{TIRITH_BASH_EFFECTIVE_PROTECTION:-}}\""
    );

    let mut cmd = Command::new("bash");
    cmd.args(["--norc", "--noprofile", "-i", "-c", &script])
        .env_clear()
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("XDG_STATE_HOME", tmpdir.path());
    for (k, v) in &env_vars {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("failed to run bash");
    assert!(
        out.status.success(),
        "bash exited non-zero: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// #111: an enter->preexec auto-degrade must refresh the exported effective
/// state, so a child `tirith doctor` after a degrade reports the truth instead
/// of the stale `enter`/`blocks` values exported at shell startup.
#[test]
fn degrade_to_preexec_reexports_effective_state() {
    // `_TIRITH_TEST_SKIP_HEALTH=1` keeps the hook in enter mode — it would
    // otherwise auto-degrade at the startup health gate in a non-PTY shell, so
    // the explicit degrade below would not be the transition under test.
    let out = source_hook_run_and_dump(
        &[("_TIRITH_TEST_SKIP_HEALTH", "1")],
        "_tirith_degrade_to_preexec degrade-test",
    );
    assert!(
        out.contains("MODE=preexec"),
        "degrade must re-export TIRITH_BASH_EFFECTIVE_MODE=preexec, got:\n{out}"
    );
    assert!(
        out.contains("PROT=warn-only"),
        "degrade must re-export TIRITH_BASH_EFFECTIVE_PROTECTION=warn-only, got:\n{out}"
    );
}
