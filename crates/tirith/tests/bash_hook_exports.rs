//! Tests for the bash hook's effective-state exports, the non-exported
//! `TIRITH_STATUS` prompt indicator, and `tirith doctor`'s rendering of them.
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
//!
//! `TIRITH_STATUS` — the opt-in prompt indicator — is by contrast a plain,
//! **non-exported** shell variable. The prompt that reads it runs *in* the
//! interactive shell, so it never needs to be in the environment; and a
//! non-interactive child process has no tirith protection, so it must not
//! inherit a status that would misrepresent it. The tests below assert both
//! that the in-shell value is correct and that a child process does *not*
//! inherit it.

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

/// Seed the bash enter-mode capability cache under `state_dir/tirith` with
/// `verdict` (`works` / `broken`), keyed to the `$BASH_VERSION` and `$BASH` a
/// bare `Command::new("bash")` will report — both read in one invocation.
fn seed_capability_cache(state_dir: &std::path::Path, verdict: &str) {
    let (bash_version, bash_path) = {
        let out = Command::new("bash")
            .args(["-c", "printf '%s\\n%s' \"$BASH_VERSION\" \"$BASH\""])
            .output()
            .expect("query bash identity");
        let text = String::from_utf8_lossy(&out.stdout);
        let mut lines = text.lines();
        (
            lines.next().unwrap_or_default().trim().to_string(),
            lines.next().unwrap_or_default().trim().to_string(),
        )
    };
    let cache_dir = state_dir.join("tirith");
    std::fs::create_dir_all(&cache_dir).unwrap();
    // Schema 1 mirrors cli::bash_capability::CACHE_SCHEMA; tirith_version blank
    // (the hook only enforces a version match when a sibling `.hooks-version`
    // exists, and the hook is sourced from assets/ which has none).
    std::fs::write(
        cache_dir.join("bash-enter-capability"),
        format!(
            "schema=1\ntirith_version=\nshell=bash\nbash_version={bash_version}\n\
             bash_path={bash_path}\nenter_capability={verdict}\nreason=seeded by test\n"
        ),
    )
    .unwrap();
}

/// Source the hook inside a clean, interactive bash subshell with a fresh
/// state dir and print the two exported vars in `key=value` form.
///
/// When `capability` is `Some`, the enter-mode capability cache is seeded with
/// that verdict before the hook is sourced, so the hook's default-mode decision
/// (issue #111) can be steered deterministically.
fn source_hook_and_dump_exports(capability: Option<&str>, extra_env: &[(&str, &str)]) -> String {
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    if let Some(v) = capability {
        seed_capability_cache(tmpdir.path(), v);
    }
    let hook = hook_path();
    let (prelude, env_vars) = split_test_env(extra_env);
    // `source` and the `printf` dump are one compound line, so the report is
    // emitted even if enter mode installs a `bind -x` Enter override.
    let script = format!(
        "{prelude}source '{hook}' 2>/dev/null; \
         printf 'MODE=%s\\nPROT=%s\\nSTATUS=%s\\n' \
           \"${{TIRITH_BASH_EFFECTIVE_MODE:-}}\" \
           \"${{TIRITH_BASH_EFFECTIVE_PROTECTION:-}}\" \
           \"${{TIRITH_STATUS:-}}\""
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
fn hook_exports_enter_when_capability_cache_proves_it() {
    // Issue #111: enter mode is the default only when the capability self-test
    // has proven `bind -x` delivery works for this bash. Seed a `works` verdict
    // and the hook must resolve to enter mode.
    //
    // `_TIRITH_TEST_SKIP_HEALTH=1` skips the startup health gate: in a non-PTY
    // `bash -i -c` — including macOS's ancient /bin/bash 3.2 on CI — `bind -x`
    // may not register, so the gate would degrade enter->preexec. This test
    // verifies *mode resolution*, not bind-x viability; the PTY conformance
    // harness covers actual delivery.
    let out = source_hook_and_dump_exports(Some("works"), &[("_TIRITH_TEST_SKIP_HEALTH", "1")]);
    assert!(
        out.contains("MODE=enter"),
        "a `works` capability cache must resolve to enter mode, got:\n{out}"
    );
    assert!(
        out.contains("PROT=blocks"),
        "enter mode must report blocks protection, got:\n{out}"
    );
}

#[test]
fn hook_exports_preexec_by_default_without_capability_proof() {
    // Issue #111: with no capability cache, the hook must NOT default into
    // enter mode — it falls back to the safe default, preexec (warn-only).
    let out = source_hook_and_dump_exports(None, &[]);
    assert!(
        out.contains("MODE=preexec"),
        "with no capability cache the hook must default to preexec, got:\n{out}"
    );
    assert!(
        out.contains("PROT=warn-only"),
        "the preexec fallback must report warn-only protection, got:\n{out}"
    );
}

#[test]
fn hook_exports_preexec_when_capability_cache_says_broken() {
    // A `broken` verdict must also keep the hook in preexec.
    let out = source_hook_and_dump_exports(Some("broken"), &[]);
    assert!(
        out.contains("MODE=preexec"),
        "a `broken` capability cache must resolve to preexec, got:\n{out}"
    );
}

#[test]
fn hook_exports_preexec_warn_only_when_mode_requested() {
    let out = source_hook_and_dump_exports(None, &[("TIRITH_BASH_MODE", "preexec")]);
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
    // SSH forces preexec even when the capability cache says enter `works`.
    let out =
        source_hook_and_dump_exports(Some("works"), &[("SSH_CONNECTION", "1.2.3.4 1 5.6.7.8 22")]);
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
         printf 'MODE=%s\\nPROT=%s\\nSTATUS=%s\\n' \
           \"${{TIRITH_BASH_EFFECTIVE_MODE:-unset}}\" \
           \"${{TIRITH_BASH_EFFECTIVE_PROTECTION:-unset}}\" \
           \"${{TIRITH_STATUS:-unset}}\""
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
    assert!(
        stdout.contains("STATUS=unset"),
        "non-interactive hook must not set TIRITH_STATUS — invariant (g), got:\n{stdout}"
    );
}

// --- TIRITH_STATUS: the opt-in prompt indicator (non-exported) ------------

#[test]
fn hook_exports_status_blocks_in_enter_mode() {
    // A proven-`works` capability cache resolves to enter mode, which blocks.
    // `TIRITH_STATUS` is the prompt-facing contract and must read `blocks`. It
    // is a non-exported shell variable; the dump `printf` reads it in-shell.
    let out = source_hook_and_dump_exports(Some("works"), &[("_TIRITH_TEST_SKIP_HEALTH", "1")]);
    assert!(
        out.contains("STATUS=blocks"),
        "enter mode must set TIRITH_STATUS=blocks, got:\n{out}"
    );
}

#[test]
fn hook_exports_status_warn_only_in_plain_preexec() {
    // With no capability proof the hook falls back to preexec warn-only; the
    // status is `warn-only`, NOT `degraded` — a shell that simply starts in
    // warn-only has not been downgraded. (`TIRITH_STATUS` is a non-exported
    // shell variable; the dump `printf` reads it in the same shell.)
    let out = source_hook_and_dump_exports(None, &[]);
    assert!(
        out.contains("STATUS=warn-only"),
        "plain preexec must set TIRITH_STATUS=warn-only, got:\n{out}"
    );
    assert!(
        !out.contains("STATUS=degraded"),
        "a shell that starts in preexec is warn-only, not degraded, got:\n{out}"
    );
}

/// `TIRITH_STATUS` must NOT be exported: a non-interactive child process — one
/// the hook never protects — must not inherit the parent interactive shell's
/// status. The variable exists only for a prompt segment, which runs *in* the
/// interactive shell and reads a non-exported variable fine.
///
/// This guards the P2 leak: before the fix the hook `export`ed `TIRITH_STATUS`,
/// so `bash -i` (status set) spawning `bash -c 'echo $TIRITH_STATUS'` printed
/// the parent's `warn-only` into an unprotected child.
#[test]
fn status_is_not_exported_to_child_processes() {
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let hook = hook_path();
    // An interactive bash sources the hook (which sets TIRITH_STATUS), then
    // spawns a *non-interactive* child bash and asks the child to print what,
    // if anything, it inherited. The child must see the empty fallback.
    let script = format!(
        "source '{hook}' 2>/dev/null; \
         printf 'PARENT=%s\\n' \"${{TIRITH_STATUS:-unset}}\"; \
         bash --norc --noprofile -c 'printf \"CHILD=[%s]\\n\" \"${{TIRITH_STATUS:-}}\"'"
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-i", "-c", &script])
        .env_clear()
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("XDG_STATE_HOME", tmpdir.path())
        .output()
        .expect("failed to run bash");
    assert!(
        out.status.success(),
        "bash exited non-zero: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The parent interactive shell does have a status set — proving the test
    // is not vacuous (the hook ran and set the variable).
    assert!(
        stdout.contains("PARENT=warn-only") || stdout.contains("PARENT=blocks"),
        "anti-vacuous: the parent interactive shell must have TIRITH_STATUS set, got:\n{stdout}"
    );
    // The non-interactive child must NOT have inherited it.
    assert!(
        stdout.contains("CHILD=[]"),
        "TIRITH_STATUS must not be exported — a non-interactive child must not \
         inherit it, got:\n{stdout}"
    );
}

// NOTE: the preexec-enforcement TIRITH_STATUS cases (enforcement engaging ->
// `blocks`; a hostile history config refusing enforcement -> `degraded`) live
// in `bash_preexec_enforce.rs`. Enforcement only engages when bash has a
// working interactive history, which requires the stdin-fed harness there —
// the `bash -i -c` subshell this file uses has no usable history.

/// A runtime enter->preexec auto-degrade must flip `TIRITH_STATUS` to
/// `degraded` so an opt-in prompt indicator reflects the downgrade.
#[test]
fn degrade_to_preexec_exports_status_degraded() {
    let out = source_hook_run_and_dump(
        &[("_TIRITH_TEST_SKIP_HEALTH", "1")],
        "_tirith_degrade_to_preexec degrade-test",
    );
    assert!(
        out.contains("STATUS=degraded"),
        "a runtime degrade must set TIRITH_STATUS=degraded, got:\n{out}"
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
         printf 'MODE=%s\\nPROT=%s\\nSTATUS=%s\\n' \
           \"${{TIRITH_BASH_EFFECTIVE_MODE:-}}\" \
           \"${{TIRITH_BASH_EFFECTIVE_PROTECTION:-}}\" \
           \"${{TIRITH_STATUS:-}}\""
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
