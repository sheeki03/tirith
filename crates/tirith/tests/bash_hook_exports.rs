//! Tests for the bash hook's effective-state exports, the non-exported
//! `TIRITH_STATUS` prompt indicator, and `tirith doctor`'s rendering.
//!
//! The hook exports `TIRITH_BASH_EFFECTIVE_MODE` ∈ {enter, preexec, disabled}
//! and `TIRITH_BASH_EFFECTIVE_PROTECTION` ∈ {blocks, warn-only, disabled} so a
//! child `tirith doctor` (which can't read the parent's locals) can report the
//! live state. Both are gated on interactive shells so a non-interactive
//! `source` doesn't leak a misleading status into children.
//!
//! `TIRITH_STATUS` (the opt-in prompt indicator) is by contrast a NON-exported
//! shell variable — the prompt reads it in-shell, and a non-interactive child
//! has no protection, so it must not inherit it. Tests assert both the in-shell
//! value and that a child does NOT inherit it.

#![cfg(unix)]

use std::process::Command;

fn hook_path() -> String {
    format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// Split `extra_env` into a session-local shell prelude and real env vars.
/// `_TIRITH_TEST_*` MUST be session-local: the hook unsets exported (inherited)
/// `_TIRITH_TEST_*` values as attacker-controllable and honors only local ones.
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
/// `verdict` (`works`/`broken`), keyed to the `$BASH_VERSION` and `$BASH` a bare
/// `Command::new("bash")` reports.
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
    // (version match is only enforced with a sibling `.hooks-version`, which
    // assets/ lacks).
    std::fs::write(
        cache_dir.join("bash-enter-capability"),
        format!(
            "schema=1\ntirith_version=\nshell=bash\nbash_version={bash_version}\n\
             bash_path={bash_path}\nenter_capability={verdict}\nreason=seeded by test\n"
        ),
    )
    .unwrap();
}

/// Source the hook in a clean interactive bash subshell with a fresh state dir
/// and print the exported vars as `key=value`. When `capability` is `Some`, the
/// cache is seeded with that verdict first so the default-mode decision
/// (issue #111) is deterministic.
fn source_hook_and_dump_exports(capability: Option<&str>, extra_env: &[(&str, &str)]) -> String {
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    if let Some(v) = capability {
        seed_capability_cache(tmpdir.path(), v);
    }
    let hook = hook_path();
    let (prelude, env_vars) = split_test_env(extra_env);
    // `source` + `printf` on one compound line, so the report is emitted even if
    // enter mode installs a `bind -x` Enter override.
    let script = format!(
        "{prelude}source '{hook}' 2>/dev/null; \
         printf 'MODE=%s\\nPROT=%s\\nSTATUS=%s\\n' \
           \"${{TIRITH_BASH_EFFECTIVE_MODE:-}}\" \
           \"${{TIRITH_BASH_EFFECTIVE_PROTECTION:-}}\" \
           \"${{TIRITH_STATUS:-}}\""
    );

    // Minimal env so user shell config can't influence results.
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
    // #111: enter mode is the default only with a proven `works` capability.
    // `_TIRITH_TEST_SKIP_HEALTH=1` skips the startup health gate (in a non-PTY
    // `bash -i -c` `bind -x` may not register, degrading enter->preexec); this
    // tests mode resolution, not bind-x viability (the PTY harness covers that).
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
    // #111: with no capability cache, the hook must NOT default to enter — it
    // falls back to the safe default, preexec (warn-only).
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
    // No `-i`: the hook must no-op and not leak status vars into children, else
    // a scripted `source` would mislead a later `tirith doctor`.
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

// --- TIRITH_STATUS: the opt-in prompt indicator (non-exported) ---

#[test]
fn hook_exports_status_blocks_in_enter_mode() {
    // A proven-`works` cache resolves to enter mode (blocks), so the prompt-facing
    // `TIRITH_STATUS` must read `blocks`.
    let out = source_hook_and_dump_exports(Some("works"), &[("_TIRITH_TEST_SKIP_HEALTH", "1")]);
    assert!(
        out.contains("STATUS=blocks"),
        "enter mode must set TIRITH_STATUS=blocks, got:\n{out}"
    );
}

#[test]
fn hook_exports_status_warn_only_in_plain_preexec() {
    // No capability proof → preexec warn-only. Status is `warn-only`, NOT
    // `degraded` — starting in warn-only is not a downgrade.
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

/// `TIRITH_STATUS` must NOT be exported: a non-interactive child (never
/// protected) must not inherit the parent's status. P2 leak guard — before the
/// fix the hook `export`ed it, leaking `warn-only` into an unprotected child.
#[test]
fn status_is_not_exported_to_child_processes() {
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let hook = hook_path();
    // Interactive bash sources the hook (sets TIRITH_STATUS), then spawns a
    // non-interactive child that prints what it inherited (must be empty).
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
    // Anti-vacuous: the parent shell has a status set (the hook ran).
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

// NOTE: the preexec-enforcement TIRITH_STATUS cases (`blocks` / `degraded`)
// live in `bash_preexec_enforce.rs` — enforcement needs a working interactive
// history (the stdin-fed harness there), which `bash -i -c` lacks.

/// A runtime enter->preexec auto-degrade must flip `TIRITH_STATUS` to `degraded`.
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

// Doctor is driven off env vars; seed them directly and assert the output
// splits "requested" (user knobs) from "effective" (live hook-exported state).

fn doctor_stdout(env: &[(&str, &str)]) -> String {
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let bin = env!("CARGO_BIN_EXE_tirith");

    // Run doctor as a direct child of bash so ancestor-walking `detect_shell`
    // sees bash. Never use bash `exec` — it replaces bash and tirith's parent
    // becomes the harness again.
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
    // Single-quote wrap; test values never contain single quotes.
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
    // User requested enforcement but the live hook reports warn-only (mid-session
    // degrade); doctor must not paper over the mismatch.
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
    // User set a bash knob but the hook exported no effective state (e.g. the
    // shell was non-interactive, so the hook no-op'd).
    let stdout = doctor_stdout(&[("TIRITH_BASH_MODE", "enter")]);
    assert!(
        stdout.contains("bash hook:            not loaded in this process"),
        "expected not-loaded marker, got:\n{stdout}"
    );
    // No effective protection claimed when nothing exported.
    assert!(
        !stdout.contains("effective protection:"),
        "should not print effective protection when hook not loaded, got:\n{stdout}"
    );
    // Requested mode still renders so the user sees their setting.
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

/// Like `source_hook_and_dump_exports`, but runs `body` (e.g. a degrade) before
/// the dump so a test can drive a state transition.
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
/// state, so a child `tirith doctor` reports the truth, not the stale startup
/// `enter`/`blocks` values.
#[test]
fn degrade_to_preexec_reexports_effective_state() {
    // `_TIRITH_TEST_SKIP_HEALTH=1` keeps the hook in enter mode (else it would
    // auto-degrade at the startup gate, so the explicit degrade below wouldn't
    // be the transition under test).
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
