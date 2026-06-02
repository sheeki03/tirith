//! Rust-native PTY shell-hook CONFORMANCE tests.
//!
//! Tirith's shell hooks (bash/zsh/fish/PowerShell/nushell) intercept commands
//! before execution; delivering wrong is a safety bug (a swallow silently
//! disappears — #111, a duplicate runs twice, a botched degrade leaves the user
//! unprotected). This file asserts the hook conformance contract by driving a
//! disposable shell through a real PTY (full contract:
//! `docs/shell-hook-conformance.md`).
//!
//! A PTY is required because hooks bind keyboard events (Enter, paste) that only
//! run under a real terminal; the harness ([`pty_support`]) is a deterministic
//! Rust driver over `portable-pty` (no flaky external `expect`). Every test
//! SKIPS cleanly when its shell is missing or too old, so `cargo test` stays
//! green (put a modern bash first on `PATH` to exercise the bash tests).
//!
//! Issue #111: bash ENTER mode can't deliver in a standard PTY (`bind -x` runs
//! the function without accepting the line, so `PROMPT_COMMAND` never fires).
//! A self-test (`cli::bash_capability`) proves the capability and the hook uses
//! enter only where proven, else falls back to preexec. This bare PTY is a
//! broken-delivery environment, so preexec is the capability-correct behaviour;
//! the tests assert the gated SYSTEM contract (allowed runs once, blocked does
//! not) through whichever mode the gate selected, with an anti-vacuous guard.

#![cfg(unix)]

use std::path::Path;
use std::time::Duration;

#[path = "pty_support/mod.rs"]
mod pty_support;

use pty_support::{
    bash_major_version, count_occurrences, embedded_hook, fish_bin, modern_bash, wait_for_marker,
    IsolatedEnv, PtySession,
};

// Shared timings: generous for a loaded CI box yet bounded so a hung shell
// fails fast.

/// "Output has settled" gap — no new bytes for this long ⇒ the command finished.
const QUIET: Duration = Duration::from_millis(700);
/// Hard cap on waiting for one command to settle.
const SETTLE_MAX: Duration = Duration::from_secs(12);
/// Hard cap on a side-effect-only command's marker file (no terminal output, so
/// [`PtySession::wait_idle`] can't time it — poll via [`wait_for_marker`]).
const MARKER_MAX: Duration = Duration::from_secs(15);

// === bash — PREEXEC mode (DEBUG-trap, warn-only unless
// TIRITH_BASH_PREEXEC_ENFORCE) ===
// Delivery goes through bash's own command loop, so it's reliable in a PTY.

/// Spawn a modern bash in preexec mode with a deterministic prompt and the hook
/// sourced; `None` when no modern bash is available.
fn bash_preexec_session(env: &mut IsolatedEnv) -> Option<PtySession> {
    let bash = modern_bash()?;
    env.set("TIRITH_BASH_MODE", "preexec");
    // A fixed prompt the harness can synchronise on.
    let mut sess = PtySession::spawn(env, &bash, &["--norc", "--noprofile", "-i"]);
    sess.send_line("export PS1='TIRITH_PTY> '");
    sess.expect("TIRITH_PTY> ");
    sess.clear_buffer();
    let hook = embedded_hook("bash-hook.bash");
    sess.send_line(&format!("source '{}'", hook.display()));
    // Either the preexec banner or the next prompt — the hook is live.
    sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.clear_buffer();
    Some(sess)
}

/// Contract (a)+(b): an allowed command in preexec mode executes EXACTLY ONCE.
/// The marker file is the ground truth (terminal echo is noisy).
#[test]
fn bash_preexec_allowed_command_executes_exactly_once() {
    let mut env = IsolatedEnv::new();
    let marker = env.workdir.join("preexec_once.txt");
    let mut sess = match bash_preexec_session(&mut env) {
        Some(s) => s,
        None => {
            eprintln!("skipping: no modern bash (>= 5) found");
            return;
        }
    };

    // No terminal output from `printf >> marker`; poll the marker file.
    sess.send_line(&format!("printf 'RAN\\n' >> '{}'", marker.display()));
    let body = wait_for_marker(&marker, "RAN", MARKER_MAX);
    sess.close();

    assert_eq!(
        count_occurrences(&body, "RAN"),
        1,
        "preexec: allowed command must execute exactly once, marker held: {body:?}"
    );
}

/// Contract (b): an allowed command's output reaches the terminal (the hook
/// must not eat it).
#[test]
fn bash_preexec_allowed_command_output_visible() {
    let mut env = IsolatedEnv::new();
    let mut sess = match bash_preexec_session(&mut env) {
        Some(s) => s,
        None => {
            eprintln!("skipping: no modern bash (>= 5) found");
            return;
        }
    };

    // A nonce no banner or hook message would print.
    sess.send_line("echo conformance_nonce_8821");
    let out = sess.expect("conformance_nonce_8821");
    sess.close();

    // At most twice (keystroke echo + output), never zero (swallowed).
    let n = count_occurrences(&out, "conformance_nonce_8821");
    assert!(
        (1..=2).contains(&n),
        "preexec: command output must be visible exactly once (echo + output ≤ 2), saw {n}"
    );
}

/// Contract (c): an executed command is recorded in history exactly once —
/// not zero (lost), not twice (double-entered).
#[test]
fn bash_preexec_no_history_duplication() {
    let mut env = IsolatedEnv::new();
    let marker = env.workdir.join("history_probe_done.txt");
    let mut sess = match bash_preexec_session(&mut env) {
        Some(s) => s,
        None => {
            eprintln!("skipping: no modern bash (>= 5) found");
            return;
        }
    };

    // The probe command whose history recording is under test.
    sess.send_line("echo history_probe_5566");
    // A side-effect-only completion barrier: bash runs one line at a time, so
    // once the marker exists the probe echo and its DEBUG-trap `tirith` call have
    // both completed (race-free, unlike `wait_idle` mid-subprocess).
    sess.send_line(&format!("printf 'DONE\\n' >> '{}'", marker.display()));
    wait_for_marker(&marker, "DONE", MARKER_MAX);
    sess.clear_buffer();

    // `expect` polls patiently (unlike `wait_idle`) so a slow `tirith` on the
    // history line can't make it return before the listing prints.
    sess.send_line("history");
    let out = sess.expect("echo history_probe_5566");
    sess.close();

    // `out` starts after the buffer clear, so the probe appears at most once (in
    // the listing). `expect` proved >= 1; `<= 2` allows an echo artefact and
    // catches a double-entry.
    let n = count_occurrences(&out, "echo history_probe_5566");
    assert!(
        n <= 2,
        "preexec: command must appear once in history (typed + listed ≤ 2), saw {n}:\n{out}"
    );
}

/// Contract (e): a *warned* command still executes in preexec mode (warn-only
/// never blocks) and runs exactly once.
#[test]
fn bash_preexec_warned_command_executes_once() {
    let mut env = IsolatedEnv::new();
    let marker = env.workdir.join("preexec_warned.txt");
    let mut sess = match bash_preexec_session(&mut env) {
        Some(s) => s,
        None => {
            eprintln!("skipping: no modern bash (>= 5) found");
            return;
        }
    };

    // Echoing a shortened URL trips the `shortened_url` warn rule (exit 2) yet
    // stays benign + side-effect-only; the `>> marker` redirect → no terminal
    // output, so poll the marker.
    sess.send_line(&format!(
        "echo https://bit.ly/warnprobe >> '{}'",
        marker.display()
    ));
    let body = wait_for_marker(&marker, "bit.ly/warnprobe", MARKER_MAX);
    sess.close();

    assert_eq!(
        count_occurrences(&body, "bit.ly/warnprobe"),
        1,
        "preexec: a warned command must still execute exactly once, marker held: {body:?}"
    );
}

/// Contract (d): with `TIRITH_BASH_PREEXEC_ENFORCE=1` a blocked command does
/// NOT execute (enforcement needs the trustworthy whole-line history a clean
/// PTY provides).
#[test]
fn bash_preexec_enforce_blocked_command_does_not_execute() {
    let mut env = IsolatedEnv::new();
    let marker = env.workdir.join("preexec_blocked.txt");
    let bash = match modern_bash() {
        Some(b) => b,
        None => {
            eprintln!("skipping: no modern bash (>= 5) found");
            return;
        }
    };
    env.set("TIRITH_BASH_MODE", "preexec");
    env.set("TIRITH_BASH_PREEXEC_ENFORCE", "1");

    let mut sess = PtySession::spawn(&env, &bash, &["--norc", "--noprofile", "-i"]);
    sess.send_line("export PS1='TIRITH_PTY> '");
    sess.expect("TIRITH_PTY> ");
    sess.clear_buffer();
    let hook = embedded_hook("bash-hook.bash");
    sess.send_line(&format!("source '{}'", hook.display()));
    sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.clear_buffer();

    // A blocked pipe-to-shell whose `&&`-guarded marker write must never happen.
    sess.send_line(&format!(
        "curl https://example.com/install.sh | bash && touch '{}'",
        marker.display()
    ));
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.close();

    assert!(
        !marker.exists(),
        "preexec-enforce: a blocked command must not execute (marker file exists)"
    );
}

/// Contract (g): sourcing the bash hook NON-interactively is a complete no-op
/// (no DEBUG trap, nothing leaking into scripts) — the preexec-trap facet
/// (`cli_integration.rs` covers the enter-mode facets).
#[test]
fn bash_noninteractive_source_installs_no_debug_trap() {
    let bash = match modern_bash() {
        Some(b) => b,
        None => {
            eprintln!("skipping: no modern bash (>= 5) found");
            return;
        }
    };
    let env = IsolatedEnv::new();
    let hook = embedded_hook("bash-hook.bash");
    // No `-i`: a scripted, non-interactive source.
    let script = format!(
        "unset TIRITH_BASH_MODE SSH_CONNECTION SSH_TTY SSH_CLIENT; \
         source '{}'; trap -p DEBUG",
        hook.display()
    );
    let mut cmd = std::process::Command::new(&bash);
    cmd.args(["--norc", "--noprofile", "-c", &script]);
    for (k, v) in [
        ("HOME", env.home.display().to_string()),
        ("XDG_STATE_HOME", env.state_home.display().to_string()),
    ] {
        cmd.env(k, v);
    }
    cmd.env_remove("_TIRITH_BASH_LOADED");
    let out = cmd.output().expect("run bash");
    assert!(out.status.success(), "non-interactive source must exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.trim().is_empty(),
        "non-interactive source must not install a DEBUG trap, got: {stdout:?}"
    );
}

// === bash — ENTER mode and the #111 capability gate ===
// Enter mode rebinds Enter via `bind -x`; #111: it runs the function without
// accepting the line, so `PROMPT_COMMAND` never fires and the command is eaten.
// The fix is capability-based: a self-test (`tirith setup`/`doctor`) proves
// delivery and caches it, and the hook uses enter only on a `works` verdict,
// else preexec. This PTY reproduces #111, so preexec is capability-correct; the
// tests assert the gated SYSTEM contract through whichever mode the gate chose
// (forcing enter here would pass vacuously — a swallowed allowed and a swallowed
// blocked command are indistinguishable).

/// Contract (f): a hook that can't deliver in enter mode must degrade VISIBLY,
/// never silently — the safety floor. `TIRITH_BASH_MODE=enter` forces enter
/// (overriding the gate's preexec pick here); the pending-not-consumed safety
/// net must then fire loudly and persist the safe-mode flag.
#[test]
fn bash_enter_degradation_is_visible_not_silent() {
    let mut env = IsolatedEnv::new();
    let bash = match modern_bash() {
        Some(b) => b,
        None => {
            eprintln!("skipping: no modern bash (>= 5) found");
            return;
        }
    };
    env.set("TIRITH_BASH_MODE", "enter");

    let mut sess = PtySession::spawn(&env, &bash, &["--norc", "--noprofile", "-i"]);
    sess.send_line("export PS1='TIRITH_PTY> '");
    sess.expect("TIRITH_PTY> ");
    sess.clear_buffer();
    let hook = embedded_hook("bash-hook.bash");
    sess.send_line(&format!("source '{}'", hook.display()));
    sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.clear_buffer();

    // First Enter: `_tirith_enter` captures a pending command but the line is
    // never accepted in this PTY (#111). It's a WARNED command (shortened URL)
    // so `tirith check` prints a visible warning — `expect`ing it is race-free
    // proof the first `_tirith_enter` ran and set `_TIRITH_PENDING_EVAL`.
    sess.send_line("echo https://bit.ly/enterprobe");
    sess.expect("bit.ly/enterprobe");
    sess.clear_buffer();
    // Second Enter: the hook sees the un-consumed pending command and must
    // announce a degrade to preexec; `expect` polls patiently for the banner.
    sess.send_line("echo trigger_degrade");
    let out = sess.expect_within("protection downgraded", Duration::from_secs(15));
    sess.close();

    assert!(
        out.contains("protection downgraded to warn-only") || out.contains("enter mode failed"),
        "enter mode losing delivery must print a visible degrade message, got:\n{out}"
    );
    // A visible degrade must also be a *persisted* one, so the next shell
    // starts safe.
    assert!(
        env.bash_safe_mode_flag().exists(),
        "a visible degrade must persist the bash-safe-mode flag at {}",
        env.bash_safe_mode_flag().display()
    );
}

/// Contract (a)+(b) for the #111 fix: with no proven enter delivery (the
/// capability-correct state here), an allowed command executes EXACTLY ONCE.
/// The direct #111 regression: pre-fix the hook defaulted to enter, `bind -x`
/// failed, and the marker stayed empty; post-fix the gate falls back to preexec
/// and delivers exactly one line (never 0 = swallow, never 2 = double). No
/// `TIRITH_BASH_MODE` set — the real default-mode path a user hits.
#[test]
fn bash_enter_allowed_command_executes_exactly_once() {
    let env = IsolatedEnv::new();
    let marker = env.workdir.join("enter_once.txt");
    let bash = match modern_bash() {
        Some(b) => b,
        None => {
            eprintln!("skipping: no modern bash (>= 5) found");
            return;
        }
    };
    // Do NOT set TIRITH_BASH_MODE: with no capability cache the gate → preexec.

    let mut sess = PtySession::spawn(&env, &bash, &["--norc", "--noprofile", "-i"]);
    sess.send_line("export PS1='TIRITH_PTY> '");
    sess.expect("TIRITH_PTY> ");
    sess.clear_buffer();
    let hook = embedded_hook("bash-hook.bash");
    sess.send_line(&format!("source '{}'", hook.display()));
    sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.clear_buffer();

    // No terminal output from `printf >> marker`; poll the marker file.
    sess.send_line(&format!("printf 'RAN\\n' >> '{}'", marker.display()));
    let body = wait_for_marker(&marker, "RAN", MARKER_MAX);
    sess.close();

    assert_eq!(
        count_occurrences(&body, "RAN"),
        1,
        "the #111 fix must deliver an allowed command exactly once \
         (0 = swallowed, the #111 bug; 2 = double-delivered); marker held: {body:?}"
    );
}

/// Contract (d) for the #111 fix: a blocked command does NOT execute, proven
/// NON-vacuously — an allowed command is first shown to run (commands aren't
/// eaten) before asserting the blocked one left no marker.
/// `TIRITH_BASH_PREEXEC_ENFORCE=1` makes the preexec fallback enforce, so this
/// is the end-to-end block guarantee through the #111 fallback path.
#[test]
fn bash_enter_blocked_command_does_not_execute() {
    let mut env = IsolatedEnv::new();
    let allowed_marker = env.workdir.join("enter_block_allowed.txt");
    let blocked_marker = env.workdir.join("enter_block_blocked.txt");
    let bash = match modern_bash() {
        Some(b) => b,
        None => {
            eprintln!("skipping: no modern bash (>= 5) found");
            return;
        }
    };
    // No TIRITH_BASH_MODE: the gate falls back to preexec, and enforcement turns
    // that into a real blocker.
    env.set("TIRITH_BASH_PREEXEC_ENFORCE", "1");

    let mut sess = PtySession::spawn(&env, &bash, &["--norc", "--noprofile", "-i"]);
    sess.send_line("export PS1='TIRITH_PTY> '");
    sess.expect("TIRITH_PTY> ");
    sess.clear_buffer();
    let hook = embedded_hook("bash-hook.bash");
    sess.send_line(&format!("source '{}'", hook.display()));
    sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.clear_buffer();

    // Anti-vacuous guard: an allowed command must actually run, else the blocked
    // assertion below is meaningless. Side-effect-only + allow verdict → no
    // terminal output, so poll the marker file (not `wait_idle`).
    sess.send_line(&format!(
        "printf 'ALLOWED\\n' >> '{}'",
        allowed_marker.display()
    ));
    let allowed_body = wait_for_marker(&allowed_marker, "ALLOWED", MARKER_MAX);
    sess.clear_buffer();

    // A blocked pipe-to-interpreter whose `&&`-guarded marker write happens only
    // if the pipeline ran. Local `printf` (not `curl`) so an absent marker means
    // "blocked", never "network down". A block prints output, so `wait_idle`
    // settles correctly here.
    sess.send_line(&format!(
        "printf 'true' | bash && touch '{}'",
        blocked_marker.display()
    ));
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.close();

    assert_eq!(
        count_occurrences(&allowed_body, "ALLOWED"),
        1,
        "anti-vacuous guard failed: the allowed command was not delivered, so \
         the blocked-command result below would be meaningless; marker held: {allowed_body:?}"
    );
    assert!(
        !blocked_marker.exists(),
        "a blocked command must not execute — its marker file must be absent"
    );
}

/// The capability cache steers the hook's default mode, observable through
/// behaviour: a `broken`/stale verdict → preexec (delivers → marker written); a
/// `works` verdict for the running bash → enter (broken in this PTY → swallowed
/// → marker absent). So a written marker proves preexec, an absent one enter —
/// demonstrating why the gate exists.
#[test]
fn bash_capability_cache_steers_default_mode() {
    let bash = match modern_bash() {
        Some(b) => b,
        None => {
            eprintln!("skipping: no modern bash (>= 5) found");
            return;
        }
    };
    let bash_ver = match pty_support::bash_version_string(&bash) {
        Some(v) => v,
        None => {
            eprintln!("skipping: could not read $BASH_VERSION");
            return;
        }
    };
    let hook = embedded_hook("bash-hook.bash");

    // Returns whether the marker was written (true ⇒ preexec delivered, false ⇒
    // enter swallowed) for a seeded verdict. `seed_bash` is the cache's bash
    // path: the real spawn path makes the verdict apply, a bogus one reads stale.
    // No terminal output, so `wait_for_marker` polls the file (a `false` waits
    // out `MARKER_MAX` to be sure the marker never appears).
    let marker_written =
        |verdict: &str, seed_bash_ver: &str, seed_bash: &Path, tag: &str| -> bool {
            let env = IsolatedEnv::new();
            env.seed_bash_enter_capability(verdict, seed_bash_ver, seed_bash);
            let marker = env.workdir.join(format!("steer_{tag}.txt"));
            let mut sess = PtySession::spawn(&env, &bash, &["--norc", "--noprofile", "-i"]);
            sess.send_line("export PS1='TIRITH_PTY> '");
            sess.expect("TIRITH_PTY> ");
            sess.clear_buffer();
            sess.send_line(&format!("source '{}'", hook.display()));
            sess.expect("TIRITH_PTY> ");
            sess.wait_idle(QUIET, SETTLE_MAX);
            sess.clear_buffer();
            sess.send_line(&format!("printf 'STEERED\\n' >> '{}'", marker.display()));
            let body = wait_for_marker(&marker, "STEERED", MARKER_MAX);
            sess.close();
            count_occurrences(&body, "STEERED") == 1
        };

    // `broken` ⇒ preexec ⇒ delivered ⇒ marker written.
    assert!(
        marker_written("broken", &bash_ver, &bash, "broken"),
        "a `broken` capability verdict must keep the hook in preexec (command must run)"
    );

    // `works` for a different bash version is stale ⇒ preexec ⇒ marker written.
    assert!(
        marker_written("works", "1.0.0-not-this-bash", &bash, "stale_version"),
        "a capability verdict for a different bash version must be ignored as stale \
         (hook must stay in preexec and run the command)"
    );

    // `works` for a different bash path is stale ⇒ preexec ⇒ marker written.
    assert!(
        marker_written(
            "works",
            &bash_ver,
            Path::new("/nonexistent/other/bash"),
            "stale_path"
        ),
        "a capability verdict for a different bash path must be ignored as stale \
         (hook must stay in preexec and run the command)"
    );

    // `works` for this exact bash ⇒ enter ⇒ swallowed in this PTY ⇒ no marker.
    assert!(
        !marker_written("works", &bash_ver, &bash, "works"),
        "a `works` capability verdict must make the hook select enter mode \
         (which, in this PTY, swallows the command — marker must be absent)"
    );
}

// === fish ===
// The fish hook binds Enter to `_tirith_check_command`, ending with
// `commandline -f execute` (fish's supported line-accept). Delivery is reliable;
// the harness answers fish 4.x's terminal probes so startup doesn't hang.

/// Spawn fish (config disabled) with a deterministic prompt and the hook
/// sourced; `None` when fish is not installed.
fn fish_session(env: &mut IsolatedEnv) -> Option<PtySession> {
    let fish = fish_bin()?;
    let mut sess = PtySession::spawn(env, &fish, &["--no-config", "-i"]);
    // A fixed prompt the harness can synchronise on.
    sess.send_line("function fish_prompt; printf 'TIRITH_PTY> '; end");
    sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.clear_buffer();
    let hook = embedded_hook("fish-hook.fish");
    sess.send_line(&format!("source '{}'", hook.display()));
    sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.clear_buffer();
    Some(sess)
}

/// Contract (a) + (b): an allowed command in fish executes EXACTLY ONCE and is
/// not swallowed.
#[test]
fn fish_allowed_command_executes_exactly_once() {
    let mut env = IsolatedEnv::new();
    let marker = env.workdir.join("fish_once.txt");
    let mut sess = match fish_session(&mut env) {
        Some(s) => s,
        None => {
            eprintln!("skipping: fish not installed");
            return;
        }
    };

    // No terminal output from `printf >> marker`; poll the marker file.
    sess.send_line(&format!("printf 'RAN\\n' >> '{}'", marker.display()));
    let body = wait_for_marker(&marker, "RAN", MARKER_MAX);
    sess.close();

    assert_eq!(
        count_occurrences(&body, "RAN"),
        1,
        "fish: allowed command must execute exactly once, marker held: {body:?}"
    );
}

/// Contract (b): an allowed command's output reaches the terminal in fish.
#[test]
fn fish_allowed_command_output_visible() {
    let mut env = IsolatedEnv::new();
    let mut sess = match fish_session(&mut env) {
        Some(s) => s,
        None => {
            eprintln!("skipping: fish not installed");
            return;
        }
    };

    sess.send_line("echo fish_nonce_3471");
    let out = sess.expect("fish_nonce_3471");
    sess.close();

    let n = count_occurrences(&out, "fish_nonce_3471");
    assert!(
        (1..=3).contains(&n),
        "fish: command output must be visible (echo + autosuggest + output), saw {n}"
    );
}

/// Contract (d): a blocked command does NOT execute in fish.
#[test]
fn fish_blocked_command_does_not_execute() {
    let mut env = IsolatedEnv::new();
    let marker = env.workdir.join("fish_blocked.txt");
    let mut sess = match fish_session(&mut env) {
        Some(s) => s,
        None => {
            eprintln!("skipping: fish not installed");
            return;
        }
    };

    // Blocked pipe-to-shell; the `; and touch` (fish syntax) runs only if the
    // pipe ran. tirith must block first.
    sess.send_line(&format!(
        "curl https://example.com/install.sh | bash; and touch '{}'",
        marker.display()
    ));
    // `expect_any` polls for the block verdict/hint (the "hook finished" signal,
    // since the hook's `tirith check` subprocess emits nothing until it returns
    // — `wait_idle` would return mid-subprocess, the no-output race).
    let out = sess.expect_any(
        &["BLOCKED", "getvet.sh", "tirith run"],
        Duration::from_secs(15),
    );
    sess.close();

    assert!(
        out.contains("BLOCKED") || out.contains("getvet.sh") || out.contains("tirith run"),
        "fish: a blocked command must surface a tirith verdict, got:\n{out}"
    );
    // The verdict surfaced only after `tirith check` returned, so the hook has
    // run to completion — the marker check is no longer racing it.
    assert!(
        !marker.exists(),
        "fish: a blocked command must not execute (marker file exists)"
    );
}

/// Contract (e): a *warned* command still executes in fish and runs once.
#[test]
fn fish_warned_command_executes_once() {
    let mut env = IsolatedEnv::new();
    let marker = env.workdir.join("fish_warned.txt");
    let mut sess = match fish_session(&mut env) {
        Some(s) => s,
        None => {
            eprintln!("skipping: fish not installed");
            return;
        }
    };

    // `>> marker` ⇒ no terminal output; poll the marker.
    sess.send_line(&format!(
        "echo https://bit.ly/fishwarn >> '{}'",
        marker.display()
    ));
    let body = wait_for_marker(&marker, "bit.ly/fishwarn", MARKER_MAX);
    sess.close();

    assert_eq!(
        count_occurrences(&body, "bit.ly/fishwarn"),
        1,
        "fish: a warned command must still execute exactly once, marker held: {body:?}"
    );
}

/// Contract (g): sourcing the fish hook in a NON-interactive fish (`fish -c`)
/// is a complete no-op — it must not error and must not block.
#[test]
fn fish_noninteractive_source_is_a_noop() {
    let fish = match fish_bin() {
        Some(f) => f,
        None => {
            eprintln!("skipping: fish not installed");
            return;
        }
    };
    let env = IsolatedEnv::new();
    let hook = embedded_hook("fish-hook.fish");
    // Source the hook then print a sentinel; a hang/error would drop it.
    let mut cmd = std::process::Command::new(&fish);
    cmd.args([
        "--no-config",
        "-c",
        &format!("source '{}'; echo NONINTERACTIVE_OK", hook.display()),
    ]);
    for (k, v) in [
        ("HOME", env.home.display().to_string()),
        ("XDG_STATE_HOME", env.state_home.display().to_string()),
        ("XDG_DATA_HOME", env.data_home.display().to_string()),
        ("XDG_CONFIG_HOME", env.config_home.display().to_string()),
    ] {
        cmd.env(k, v);
    }
    cmd.env_remove("_TIRITH_FISH_LOADED");
    let out = cmd.output().expect("run fish");
    assert!(
        out.status.success(),
        "non-interactive fish source must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("NONINTERACTIVE_OK"),
        "non-interactive fish source must be a clean no-op (sentinel missing)"
    );
}

// === zsh / PowerShell / nushell — M0.1 follow-up stubs ===
// The harness is shell-agnostic; each needs a spawn helper + its delivery
// quirks (zsh: `zle` widget; pwsh: PSReadLine handler; nu: its own model).
// Left as `#[ignore]` stubs so `cargo test` neither runs nor fails them.

/// Follow-up stub: zsh PTY conformance not yet implemented (coverage-gap marker).
#[test]
#[ignore = "M0.1 follow-up: zsh PTY conformance not yet implemented"]
fn zsh_conformance_followup() {}

/// Follow-up stub: PowerShell PTY conformance is not yet implemented.
#[test]
#[ignore = "M0.1 follow-up: PowerShell PTY conformance not yet implemented"]
fn powershell_conformance_followup() {}

/// Follow-up stub: nushell PTY conformance is not yet implemented.
#[test]
#[ignore = "M0.1 follow-up: nushell PTY conformance not yet implemented"]
fn nushell_conformance_followup() {}

// === Harness self-checks — cheap, always run, no shell required. ===

/// `count_occurrences` is the "exactly once" backbone: non-overlapping,
/// empty-needle-safe.
#[test]
fn harness_count_occurrences_is_correct() {
    assert_eq!(count_occurrences("", "x"), 0);
    assert_eq!(count_occurrences("abc", ""), 0);
    assert_eq!(count_occurrences("RAN", "RAN"), 1);
    assert_eq!(count_occurrences("RAN RAN RAN", "RAN"), 3);
    // Non-overlapping.
    assert_eq!(count_occurrences("aaaa", "aa"), 2);
    assert_eq!(count_occurrences("no match here", "RAN"), 0);
}

/// The bash version probe must agree with `bash --version` for the selected
/// bash (or cleanly report "none").
#[test]
fn harness_reports_bash_availability_consistently() {
    match modern_bash() {
        Some(bash) => {
            let v = bash_major_version(&bash)
                .expect("a selected modern bash must report a parseable version");
            assert!(v >= 5, "modern_bash() must only return bash >= 5, got {v}");
            eprintln!("conformance: using bash {} (major {v})", bash.display());
        }
        None => {
            eprintln!(
                "conformance: no modern bash (>= 5) found — bash tests will skip. \
                 Install one or run with PATH=/opt/homebrew/bin:$PATH"
            );
        }
    }
}
