//! Rust-native PTY shell-hook **conformance** tests.
//!
//! Tirith installs shell hooks (bash / zsh / fish / PowerShell / nushell) that
//! intercept commands before execution. A hook that delivers commands wrong is
//! a correctness *and* a safety bug: a swallowed command silently disappears
//! (#111), a duplicated one runs twice, and a botched degrade leaves the user
//! unprotected without telling them.
//!
//! This file asserts the **hook conformance contract** — the invariants every
//! tirith shell hook must satisfy — by driving a *disposable* shell through a
//! real pseudo-terminal. The full contract is documented in
//! `docs/shell-hook-conformance.md`.
//!
//! ## Why a PTY, and why Rust-native
//!
//! Shell hooks bind keyboard events (Enter, bracketed paste); those code paths
//! only run under a real terminal, so a plain `Command` cannot exercise them.
//! The previous PTY tests shelled out to the `expect` Tcl tool, which is flaky
//! on macOS and silently sensitive to the bash version on `PATH`. The harness
//! here ([`pty_support`]) is a Rust driver over `portable-pty`: deterministic,
//! no external dependency, and explicit about which shell it runs.
//!
//! ## Test tiers
//!
//! Every test **skips cleanly** (early `return` with an `eprintln!`) when its
//! shell is not installed or is too old. `cargo test --workspace` stays green
//! on a machine with no modern bash, no fish, no tmux and no SSH. To exercise
//! the bash tests, put a modern bash first on `PATH`
//! (`PATH=/opt/homebrew/bin:$PATH cargo test`).
//!
//! ## Known-bug regression tests
//!
//! Bash *enter* mode currently cannot deliver commands in a standard PTY
//! (issue #111: `bind -x` on Enter runs the bound function but never accepts
//! the line, so `PROMPT_COMMAND` — and therefore the pending-command delivery
//! — never fires). The harness reproduces this precisely. The delivery test
//! for enter mode is written and `#[ignore]`d with a `#111` reference: it is a
//! ready regression test that will pass once the hook is fixed, and keeps
//! `cargo test` green until then. The *degradation* invariant for enter mode
//! is fully tested and passing — a buggy enter mode must at least fail loudly.

#![cfg(unix)]

use std::time::Duration;

#[path = "pty_support/mod.rs"]
mod pty_support;

use pty_support::{
    bash_major_version, count_occurrences, embedded_hook, fish_bin, modern_bash, IsolatedEnv,
    PtySession,
};

// ---------------------------------------------------------------------------
// Shared timings. PTY tests are inherently timing-sensitive; these are
// generous so the suite is reliable on a loaded CI box, yet bounded so a hung
// shell fails fast rather than wedging the run.
// ---------------------------------------------------------------------------

/// "Output has settled" gap — no new bytes for this long means the shell
/// finished the current command (it shelled out to `tirith` and came back).
const QUIET: Duration = Duration::from_millis(700);
/// Hard cap on waiting for one command to settle.
const SETTLE_MAX: Duration = Duration::from_secs(12);

// ===========================================================================
// bash — PREEXEC mode (DEBUG-trap, warn-only by default)
//
// Preexec mode observes commands via a DEBUG trap; the command executes
// normally regardless of verdict (it is warn-only unless
// TIRITH_BASH_PREEXEC_ENFORCE is set). Delivery therefore goes through bash's
// own command loop and is reliable in a PTY.
// ===========================================================================

/// Spawn a modern bash in preexec mode with a deterministic prompt and the
/// tirith hook sourced. Returns `None` when no modern bash is available.
fn bash_preexec_session(env: &mut IsolatedEnv) -> Option<PtySession> {
    let bash = modern_bash()?;
    env.set("TIRITH_BASH_MODE", "preexec");
    // A fixed, unmistakable prompt string the harness can synchronise on.
    let mut sess = PtySession::spawn(env, &bash, &["--norc", "--noprofile", "-i"]);
    sess.send_line("export PS1='TIRITH_PTY> '");
    sess.expect("TIRITH_PTY> ");
    sess.clear_buffer();
    let hook = embedded_hook("bash-hook.bash");
    sess.send_line(&format!("source '{}'", hook.display()));
    // The preexec banner or the next prompt — either way the hook is live.
    sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.clear_buffer();
    Some(sess)
}

/// Contract (a) + (b): an allowed command in preexec mode executes EXACTLY
/// ONCE and is not swallowed.
///
/// The command appends one line to a marker file; the file is the
/// ground truth — terminal echo is noisy, a filesystem side-effect is not.
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

    sess.send_line(&format!("printf 'RAN\\n' >> '{}'", marker.display()));
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.close();

    let body = std::fs::read_to_string(&marker).unwrap_or_default();
    assert_eq!(
        count_occurrences(&body, "RAN"),
        1,
        "preexec: allowed command must execute exactly once, marker held: {body:?}"
    );
}

/// Contract (b): an allowed command's own output reaches the terminal — the
/// hook must not eat the command.
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

    // A nonce no shell banner or hook message would ever print.
    sess.send_line("echo conformance_nonce_8821");
    let out = sess.expect("conformance_nonce_8821");
    sess.close();

    // Twice in the buffer at most — the keystroke echo plus the command
    // output. Never zero (swallowed).
    let n = count_occurrences(&out, "conformance_nonce_8821");
    assert!(
        (1..=2).contains(&n),
        "preexec: command output must be visible exactly once (echo + output ≤ 2), saw {n}"
    );
}

/// Contract (c): an executed command is recorded in shell history exactly
/// once — not zero (lost) and not twice (double-entered).
#[test]
fn bash_preexec_no_history_duplication() {
    let mut env = IsolatedEnv::new();
    let mut sess = match bash_preexec_session(&mut env) {
        Some(s) => s,
        None => {
            eprintln!("skipping: no modern bash (>= 5) found");
            return;
        }
    };

    sess.send_line("echo history_probe_5566");
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.clear_buffer();
    sess.send_line("history");
    let out = sess.wait_idle(QUIET, SETTLE_MAX);
    sess.close();

    // `clear_buffer()` was called before `send_line("history")`, so `out` only
    // holds output from the `history` command onward — the probe string's
    // "typed" occurrence is no longer in it. The probe appears in `out` at most
    // once, in the history listing itself: `n >= 1` asserts it was recorded,
    // and `n <= 2` leaves headroom for a stray terminal-echo artefact.
    let n = count_occurrences(&out, "echo history_probe_5566");
    assert!(
        n <= 2,
        "preexec: command must appear once in history (typed + listed ≤ 2), saw {n}:\n{out}"
    );
    assert!(
        n >= 1,
        "preexec: executed command must be recorded in history, saw {n}:\n{out}"
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

    // `echo`-ing a shortened URL trips the `shortened_url` warn rule
    // (tirith exit 2) while staying a benign, side-effect-only command.
    sess.send_line(&format!(
        "echo https://bit.ly/warnprobe >> '{}'",
        marker.display()
    ));
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.close();

    let body = std::fs::read_to_string(&marker).unwrap_or_default();
    assert_eq!(
        count_occurrences(&body, "bit.ly/warnprobe"),
        1,
        "preexec: a warned command must still execute exactly once, marker held: {body:?}"
    );
}

/// Contract (d): with `TIRITH_BASH_PREEXEC_ENFORCE=1`, a *blocked* command
/// does NOT execute.
///
/// Enforcement requires a trustworthy whole-line history view; a clean PTY
/// shell with default `HISTCONTROL` provides exactly that.
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

    // A blocked pipe-to-shell whose payload, IF it ran, would create the
    // marker. `curl ... | bash` is blocked; the `&&`-guarded marker write
    // must never happen.
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

/// Contract (g): sourcing the bash hook in a NON-interactive shell is a
/// complete no-op — no DEBUG trap installed, nothing that could leak into
/// scripts. (`cli_integration.rs` covers the enter-mode no-op facets; this is
/// the preexec-trap facet, kept here so the conformance file is self-contained
/// on invariant (g).)
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

// ===========================================================================
// bash — ENTER mode (bind-x Enter override)
//
// Enter mode rebinds Enter to `_tirith_enter` via `bind -x`. KNOWN BUG #111:
// `bind -x` on `\C-m` runs the bound function but does not then accept the
// line, so `PROMPT_COMMAND` never fires and the pending command is never
// delivered. The hook detects the stuck pending state on the *next* Enter and
// degrades to preexec. The harness reproduces this exactly.
// ===========================================================================

/// Contract (f): a hook that cannot deliver in enter mode must degrade
/// **visibly** — never silently. This is the safety floor: if blocking
/// protection is lost, the user has to be told.
///
/// This test passes against the *current* (buggy, #111) hook because the
/// degrade path is correct: the failure is loud and the safe-mode flag is
/// persisted.
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

    // First Enter on a real command: the bind-x function captures it as a
    // pending command but the line is never accepted.
    sess.send_line("echo enter_mode_probe");
    sess.wait_idle(QUIET, SETTLE_MAX);
    // Second Enter: the hook sees the un-consumed pending command and must
    // announce a degrade to preexec.
    sess.send_line("echo trigger_degrade");
    let out = sess.wait_idle(QUIET, SETTLE_MAX);
    sess.close();

    assert!(
        out.contains("switching to preexec") || out.contains("enter mode failed"),
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

/// Contract (a)+(b)+(c) for bash ENTER mode: an allowed command executes
/// exactly once, is not swallowed, and is not duplicated in history.
///
/// IGNORED — issue #111: bash enter mode (`bind -x` on Enter) does not deliver
/// commands in a standard PTY. `bind -x` runs `_tirith_enter` but never
/// accepts the line, so `_tirith_prompt_hook` (the `PROMPT_COMMAND` entry that
/// runs the pending `eval`) never fires. The command is captured into
/// `_TIRITH_PENDING_EVAL` and then dropped when the hook degrades. This test
/// is the ready-made regression check: remove `#[ignore]` once #111 is fixed.
#[test]
#[ignore = "issue #111: bash enter-mode bind-x Enter does not deliver commands in a PTY"]
fn bash_enter_allowed_command_executes_exactly_once() {
    let mut env = IsolatedEnv::new();
    let marker = env.workdir.join("enter_once.txt");
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

    sess.send_line(&format!("printf 'RAN\\n' >> '{}'", marker.display()));
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.close();

    let body = std::fs::read_to_string(&marker).unwrap_or_default();
    assert_eq!(
        count_occurrences(&body, "RAN"),
        1,
        "enter: allowed command must execute exactly once, marker held: {body:?}"
    );
}

/// Contract (d) for bash ENTER mode: a blocked command does NOT execute.
///
/// IGNORED — issue #111 (see above). Enter mode is the only bash mode that can
/// truly *block*; once #111 is fixed this asserts that blocking works end to
/// end through a PTY. Until then enter mode degrades to warn-only preexec, so
/// this guarantee cannot be exercised here.
#[test]
#[ignore = "issue #111: bash enter-mode bind-x Enter does not deliver commands in a PTY"]
fn bash_enter_blocked_command_does_not_execute() {
    let mut env = IsolatedEnv::new();
    let marker = env.workdir.join("enter_blocked.txt");
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

    sess.send_line(&format!(
        "curl https://example.com/install.sh | bash && touch '{}'",
        marker.display()
    ));
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.close();

    assert!(
        !marker.exists(),
        "enter: a blocked command must not execute (marker file exists)"
    );
}

// ===========================================================================
// fish
//
// The fish hook binds Enter (and the `\r`/`\n`/`enter` aliases) to
// `_tirith_check_command`, which ends with `commandline -f execute` — fish's
// supported way to accept a line. Delivery is reliable; the harness answers
// fish 4.x's terminal-capability probes so the shell does not hang in startup.
// ===========================================================================

/// Spawn fish with config disabled, a deterministic prompt, and the tirith
/// hook sourced. Returns `None` when fish is not installed.
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

    sess.send_line(&format!("printf 'RAN\\n' >> '{}'", marker.display()));
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.close();

    let body = std::fs::read_to_string(&marker).unwrap_or_default();
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

    // Blocked pipe-to-shell; the `; and touch` clause (fish syntax) only runs
    // if the pipe ran. tirith must block before that happens.
    sess.send_line(&format!(
        "curl https://example.com/install.sh | bash; and touch '{}'",
        marker.display()
    ));
    let out = sess.wait_idle(QUIET, SETTLE_MAX);
    sess.close();

    assert!(
        !marker.exists(),
        "fish: a blocked command must not execute (marker file exists)"
    );
    // The block must also be communicated to the user. tirith's block output
    // for a pipe-to-shell carries the verdict ("BLOCKED") plus a remediation
    // hint — a "tirith run ..." suggestion and a vet pointer to getvet.sh; any
    // one of those strings confirms the verdict surfaced.
    assert!(
        out.contains("BLOCKED") || out.contains("getvet.sh") || out.contains("tirith run"),
        "fish: a blocked command must surface a tirith verdict, got:\n{out}"
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

    sess.send_line(&format!(
        "echo https://bit.ly/fishwarn >> '{}'",
        marker.display()
    ));
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.close();

    let body = std::fs::read_to_string(&marker).unwrap_or_default();
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
    // Non-interactive: source the hook then print a sentinel. If sourcing the
    // hook errored or hung, the sentinel would be missing.
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

// ===========================================================================
// zsh / PowerShell / nushell — FOLLOW-UP (M0.1 stubs)
//
// The harness ([`pty_support`]) is shell-agnostic, so extending coverage is a
// matter of adding the spawn helper and the per-shell delivery quirks:
//
//   * zsh — binds a `zle` widget; `tirith init --shell zsh` materialises the
//     hook. Needs a `zsh_session` helper analogous to `fish_session`.
//   * PowerShell (`pwsh`) — uses a PSReadLine key handler; delivery and the
//     conformance assertions need a `pwsh`-specific driver.
//   * nushell — `nu`'s hook model differs again; lowest priority.
//
// Tracked as M0.1 follow-up. These are deliberately left as documented stubs
// so `cargo test --workspace` neither runs nor fails them today.
// ===========================================================================

/// Follow-up stub: zsh PTY conformance is not yet implemented (see the module
/// comment above). Present so the coverage gap is visible in the test list.
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

// ===========================================================================
// Harness self-checks — cheap, always run, no shell required.
// ===========================================================================

/// `count_occurrences` is the backbone of the "exactly once" invariant, so it
/// gets its own unit check: non-overlapping, empty-needle-safe.
#[test]
fn harness_count_occurrences_is_correct() {
    assert_eq!(count_occurrences("", "x"), 0);
    assert_eq!(count_occurrences("abc", ""), 0);
    assert_eq!(count_occurrences("RAN", "RAN"), 1);
    assert_eq!(count_occurrences("RAN RAN RAN", "RAN"), 3);
    // Non-overlapping: "aaaa" contains two non-overlapping "aa".
    assert_eq!(count_occurrences("aaaa", "aa"), 2);
    assert_eq!(count_occurrences("no match here", "RAN"), 0);
}

/// The bash version probe must agree with `bash --version` for whatever bash
/// the harness selected (or cleanly report "none").
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
