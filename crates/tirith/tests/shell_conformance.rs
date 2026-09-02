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
    wait_for_marker_count, zsh_bin, IsolatedEnv, PtySession,
};

// Shared timings: generous for a loaded CI box yet bounded so a hung shell
// fails fast.

/// "Output has settled" gap — no new bytes for this long ⇒ the command finished.
const QUIET: Duration = Duration::from_millis(700);
/// Hard cap on waiting for one command to settle.
///
/// Raised from 12s on evidence, not theory. `wait_idle` returns as soon as
/// output goes quiet, so this looks like it should only bound a continuously
/// streaming command, and reverting it to 12s was tried: the flakes came
/// straight back (2, 0, then 1 failure over three runs, against 0, 0, 0 at
/// 60s). Under a 35-binary parallel suite the settle poll itself does not get
/// scheduled often enough to observe quiet inside 12s, so the cap fires while
/// the shell is merely descheduled.
const SETTLE_MAX: Duration = Duration::from_secs(60);
/// Hard cap on a side-effect-only command's marker file (no terminal output, so
/// [`PtySession::wait_idle`] can't time it — poll via [`wait_for_marker`]).
///
/// This bounds how long a real interactive shell may take to run a hook that
/// shells out to a DEBUG-build `tirith`, while the whole workspace suite runs
/// 35 test binaries at once. At its previous 15s it was measuring machine load
/// rather than shell behaviour: this file failed a varying handful of tests on
/// each parallel run and passed alone, and the tell was an EMPTY marker, so the
/// poll had given up before the side effect landed rather than the side effect
/// being wrong.
///
/// It is deliberately NOT split into a shorter "expect absence" variant. Some
/// callers wait this out precisely to conclude a marker never appears, and for
/// those a short timeout risks a wrong PASS, which is far worse than a slow
/// test. The passing path is unaffected either way: it returns the moment the
/// marker appears. `wait_for_marker` also cannot use the idle deadline that
/// `expect_within` now uses, because an empty file offers no progress signal to
/// reset against.
const MARKER_MAX: Duration = Duration::from_secs(90);

/// Return `(confirmed, unresolved)` from the newest valid fixed-slot ledger.
/// This independently verifies that a PTY command crossed the durable receipt
/// boundary instead of merely exercising the hook's legacy fallback.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn strict_ledger_counts(env: &IsolatedEnv) -> (usize, usize) {
    const MAGIC: &[u8; 8] = b"TIRXST02";
    const HEADER_LEN: usize = 8 + 8 + 32;
    const SLOT_SIZE: usize = 4 * 1024 * 1024;

    let bytes = std::fs::read(env.strict_execution_ledger_path())
        .expect("protocol-v3 hook must create its strict execution ledger");
    let mut ledgers = Vec::new();
    for offset in [0, SLOT_SIZE] {
        let Some(header) = bytes.get(offset..offset + HEADER_LEN) else {
            continue;
        };
        if &header[..8] != MAGIC {
            continue;
        }
        let length = u64::from_le_bytes(header[8..16].try_into().expect("slot length")) as usize;
        if length == 0 || length > SLOT_SIZE - HEADER_LEN {
            continue;
        }
        let Some(payload) = bytes.get(offset + HEADER_LEN..offset + HEADER_LEN + length) else {
            continue;
        };
        // The writer's own reader rejects a slot whose payload digest differs
        // from the header's, so this independent check has to apply the same
        // rule — otherwise a newer slot with valid JSON and a bad digest could
        // be selected here and never by the product.
        {
            use sha2::{Digest as _, Sha256};

            let digest = Sha256::digest(payload);
            if digest.as_slice() != &header[16..HEADER_LEN] {
                continue;
            }
        }
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) {
            ledgers.push(value);
        }
    }
    let ledger = ledgers
        .into_iter()
        .max_by_key(|value| value["generation"].as_u64().unwrap_or(0))
        .expect("at least one strict execution slot must contain valid JSON");
    let confirmed = ledger["confirmed"]
        .as_array()
        .expect("strict ledger confirmed records")
        .len();
    let unresolved = ledger["unresolved"]
        .as_array()
        .expect("strict ledger unresolved records")
        .len();
    (confirmed, unresolved)
}

/// Number of typed events persisted in the session record.
///
/// This is the store `MassFileDeletion` and the other correlation rules read,
/// and it is NOT the strict execution ledger: a receipt and a typed event are
/// written by different paths. Asserting only on the ledger would let a change
/// that persists an observation without committing a receipt pass while the
/// original bug (#188, a tab completion counted as an executed deletion) came
/// straight back.
fn session_typed_event_count(env: &IsolatedEnv) -> usize {
    let path = env.session_record_path();
    let Ok(bytes) = std::fs::read(&path) else {
        // No session record yet is the strongest possible form of "nothing was
        // observed", so it counts as zero rather than failing the read.
        return 0;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        panic!("session record at {} must be valid JSON", path.display());
    };
    value["typed_events"]
        .as_array()
        .map(|events| events.len())
        .unwrap_or(0)
}

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

/// Issue #176 startup boundary: sourcing on one compound line remains
/// truthfully `off`, but the first real prompt must capture and chain DEBUG and
/// publish plain preexec as live `warn-only` before accepting another line.
/// Exercise both the system Bash (3.2 on macOS) and a distinct modern Bash when
/// they are available.
fn assert_bash_preexec_warn_only_after_prompt(bash: &Path) {
    let mut env = IsolatedEnv::new();
    env.set("TIRITH_BASH_MODE", "preexec");
    let mut sess = PtySession::spawn(&env, bash, &["--norc", "--noprofile", "-i"]);
    sess.send_line("export PS1='TIRITH_PTY> '");
    sess.expect("TIRITH_PTY> ");
    sess.clear_buffer();

    let hook = embedded_hook("bash-hook.bash");
    sess.send_line(&format!("source '{}'", hook.display()));
    sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.clear_buffer();

    sess.send_line(
        "printf 'LIVE_MODE=%s LIVE_PROT=%s LIVE_STATUS=%s\\n' \
         \"$TIRITH_BASH_EFFECTIVE_MODE\" \
         \"$TIRITH_BASH_EFFECTIVE_PROTECTION\" \"$TIRITH_STATUS\"",
    );
    let output = sess.expect("LIVE_MODE=preexec LIVE_PROT=warn-only LIVE_STATUS=warn-only");
    sess.close();
    assert!(
        output.contains("LIVE_MODE=preexec LIVE_PROT=warn-only LIVE_STATUS=warn-only"),
        "the first prompt must activate warn-only preexec for {}:\n{output}",
        bash.display()
    );
}

#[test]
fn bash_preexec_reports_warn_only_after_first_prompt() {
    let system_bash = Path::new("/bin/bash");
    if system_bash.is_file() {
        assert_bash_preexec_warn_only_after_prompt(system_bash);
    }

    if let Some(modern) = modern_bash() {
        let same_as_system =
            std::fs::canonicalize(&modern).ok() == std::fs::canonicalize(system_bash).ok();
        if !same_as_system {
            assert_bash_preexec_warn_only_after_prompt(&modern);
        }
    }
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

/// Issue #176: modern Bash must bracket array-valued PROMPT_COMMAND entries,
/// decide each typed line once, and keep lazy extdebug out of allowed function
/// bodies and prompt functions. A blocked function/pipeline line must still be
/// skipped, then Tirith-owned extdebug must be released at the next prompt.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn bash_preexec_enforce_functions_prompt_array_and_receipt_cardinality() {
    let mut env = IsolatedEnv::new();
    let allowed = env.workdir.join("bash-function-allowed.txt");
    let pipeline = env.workdir.join("bash-pipeline-allowed.txt");
    let blocked = env.workdir.join("bash-function-blocked.txt");
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

    // Define both prompt and user functions before the hook exists. The array
    // form is Bash 5+ and must retain the user's first-to-last ordering.
    sess.send_line(&format!(
        "PROMPT_ORDER=; PROMPT_CHECK=0; \
         prompt_first() {{ local seen=$?; PROMPT_ORDER=\"${{PROMPT_ORDER}}1\"; \
           if [[ \"$PROMPT_CHECK\" == 1 ]]; then printf 'PROMPT_ARRAY_STATUS=%s\\n' \"$seen\"; fi; \
           return \"$seen\"; }}; \
         prompt_second() {{ PROMPT_ORDER=\"${{PROMPT_ORDER}}2\"; \
           if [[ \"$PROMPT_CHECK\" == 1 ]]; then \
             printf 'PROMPT_ARRAY_ORDER=%s\\n' \"$PROMPT_ORDER\"; \
             if shopt -q extdebug; then printf 'PROMPT_EXTDEBUG=on\\n'; \
             else printf 'PROMPT_EXTDEBUG=off\\n'; fi; fi; }}; \
         benign_fn() {{ printf 'RAN\\n' >> '{}'; }}; \
         PROMPT_COMMAND=(prompt_first prompt_second)",
        allowed.display()
    ));
    sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.clear_buffer();

    let hook = embedded_hook("bash-hook.bash");
    sess.send_line(&format!("source '{}'", hook.display()));
    sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.clear_buffer();

    // One composite typed line, one receipt. The first user prompt function
    // must still observe `false`'s status and the array order must remain 1,2.
    sess.send_line("PROMPT_ORDER=; PROMPT_CHECK=1; false");
    let mut prompt_output = sess.expect("PROMPT_ARRAY_ORDER=12");
    // `expect` returns through the matched token. Collect the remainder too:
    // the extdebug assertion is intentionally emitted after the order token.
    prompt_output.push_str(&sess.expect("TIRITH_PTY> "));
    sess.wait_idle(QUIET, SETTLE_MAX);
    assert!(
        prompt_output.contains("PROMPT_ARRAY_STATUS=1"),
        "the first user prompt command must see the typed line's status:\n{prompt_output}"
    );
    assert!(
        prompt_output.contains("PROMPT_EXTDEBUG=off"),
        "allowed lines must leave extdebug off before prompt functions:\n{prompt_output}"
    );
    assert_eq!(
        strict_ledger_counts(&env),
        (0, 1),
        "one composite typed line, not its prompt functions, must create one unresolved receipt"
    );
    sess.clear_buffer();

    // Calling a benign pre-existing function is one top-level decision and
    // one receipt; its body and both prompt functions produce no extras.
    sess.send_line("benign_fn");
    let allowed_body = wait_for_marker(&allowed, "RAN", MARKER_MAX);
    let function_output = sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    assert_eq!(count_occurrences(&allowed_body, "RAN"), 1);
    assert!(
        function_output.contains("PROMPT_EXTDEBUG=off"),
        "extdebug must remain off across an allowed function body:\n{function_output}"
    );
    assert_eq!(
        strict_ledger_counts(&env),
        (0, 2),
        "the benign function call must add exactly one top-level receipt"
    );
    sess.clear_buffer();

    // Pipeline segments can run in Bash subshells. They reuse the parent
    // whole-line decision and must not each mint a receipt.
    sess.send_line(&format!(
        "printf 'PIPELINE_RAN\\n' | tee '{}' >/dev/null",
        pipeline.display()
    ));
    let pipeline_body = wait_for_marker(&pipeline, "PIPELINE_RAN", MARKER_MAX);
    let pipeline_output = sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    assert_eq!(count_occurrences(&pipeline_body, "PIPELINE_RAN"), 1);
    assert_eq!(
        strict_ledger_counts(&env),
        (0, 3),
        "an allowed pipeline must add exactly one top-level receipt"
    );
    sess.clear_buffer();

    // The dangerous function definition and invocation are one typed line;
    // the complete line contains the pipe-to-interpreter and must be stopped
    // before the function body can create its sentinel.
    sess.send_line(&format!(
        "evil_fn() {{ printf 'touch {}\\n' | bash; }}; evil_fn",
        blocked.display()
    ));
    let blocked_output = sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    assert!(
        !blocked.exists(),
        "the blocked function/pipeline line must not execute"
    );
    assert!(
        blocked_output.contains("BLOCKED"),
        "the refusal must be visible, got:\n{blocked_output}"
    );
    assert!(
        blocked_output.contains("PROMPT_EXTDEBUG=off"),
        "Tirith-owned extdebug must be released before prompt functions:\n{blocked_output}"
    );
    assert_eq!(
        strict_ledger_counts(&env),
        (0, 3),
        "blocked and automatic prompt/nested commands must not add receipts"
    );

    let all_output = format!("{prompt_output}{function_output}{pipeline_output}{blocked_output}");
    assert!(
        !all_output.contains("tirith: no issues"),
        "clean hook checks must stay silent:\n{all_output}"
    );
    assert!(
        !all_output.contains("history no longer matches BASH_COMMAND")
            && !all_output.contains("protection downgraded"),
        "function or prompt execution must not degrade enforcement:\n{all_output}"
    );

    // Removing the guards is an explicit trust-boundary loss. The mutation
    // line itself was decided while the boundary was intact, then the first
    // automatic prompt function must trigger a visible downgrade without
    // being receipted. Subsequent warn-only function calls stay usable but no
    // longer claim durable typed-line evidence.
    sess.clear_buffer();
    sess.send_line("PROMPT_COMMAND=(prompt_first prompt_second)");
    let degrade_output = sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    assert!(
        degrade_output
            .contains("PROMPT_COMMAND no longer contains Tirith's prompt-boundary guards")
            && degrade_output.contains("protection downgraded"),
        "prompt-guard loss must be visible:\n{degrade_output}"
    );
    assert_eq!(
        strict_ledger_counts(&env),
        (0, 4),
        "only the user-typed guard mutation, not its automatic prompt functions, may add a receipt"
    );
    sess.clear_buffer();

    sess.send_line("benign_fn");
    let post_degrade_body = wait_for_marker_count(&allowed, "RAN", 2, MARKER_MAX);
    let post_degrade_output = sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    assert_eq!(
        count_occurrences(&post_degrade_body, "RAN"),
        2,
        "warn-only degradation must not break later shell functions"
    );
    assert_eq!(
        strict_ledger_counts(&env),
        (0, 4),
        "post-degrade warn-only and prompt/nested commands must not mint trusted receipts"
    );
    assert!(
        post_degrade_output.contains("PROMPT_EXTDEBUG=off")
            && !post_degrade_output.contains("tirith: no issues"),
        "post-degrade prompt state must remain clean and silent:\n{post_degrade_output}"
    );
    sess.close();
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

/// Receipt registration redirects into files returned by `mktemp`, so they
/// must explicitly override a user's `noclobber` option. Otherwise an
/// interactive shell silently loses protocol-v3 evidence before any command is
/// checked.
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn bash_noclobber_keeps_protocol_v3_registration() {
    let mut env = IsolatedEnv::new();
    let bash = match modern_bash() {
        Some(bash) => bash,
        None => {
            eprintln!("skipping: no modern bash (>= 5) found");
            return;
        }
    };
    env.set("TIRITH_BASH_MODE", "preexec");

    let mut sess = PtySession::spawn(&env, &bash, &["--norc", "--noprofile", "-i"]);
    sess.send_line("export PS1='TIRITH_PTY> '; set -o noclobber");
    sess.expect("TIRITH_PTY> ");
    sess.clear_buffer();
    let hook = embedded_hook("bash-hook.bash");
    sess.send_line(&format!("source '{}'", hook.display()));
    sess.expect("TIRITH_PTY> ");
    sess.clear_buffer();
    sess.send_line("printf 'TIRITH_NOCLOBBER_PROTOCOL<%s>\\n' \"$_TIRITH_RECEIPT_PROTOCOL\"");
    let output = sess.expect("TIRITH_NOCLOBBER_PROTOCOL<3>");
    sess.close();

    assert!(
        output.contains("TIRITH_NOCLOBBER_PROTOCOL<3>"),
        "bash noclobber must not disable receipt registration, got:\n{output}"
    );
}

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
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        sess.send_line("printf 'TIRITH_PROTOCOL=%s\\n' \"$_TIRITH_RECEIPT_PROTOCOL\"");
        sess.expect("TIRITH_PROTOCOL=3");
        sess.wait_idle(QUIET, SETTLE_MAX);
        sess.clear_buffer();
        let (confirmed, unresolved) = strict_ledger_counts(env);
        assert_eq!(
            confirmed, 0,
            "a shell line must not be mislabeled as kernel-confirmed execution"
        );
        assert!(
            unresolved >= 1,
            "fish protocol-v3 probe must create durable shell-boundary evidence"
        );
    }
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

/// Issue #188: Fish completion must remain an editor-only action. Completing an
/// `rm` operand may inspect several matching names, but it must not commit a
/// shell execution receipt (and therefore must not persist deletion events that
/// can accumulate into `MassFileDeletion`).
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn fish_rm_tab_completion_does_not_persist_execution() {
    let mut env = IsolatedEnv::new();
    for name in [
        "fish-delete-a.dmg",
        "fish-delete-b.zip",
        "fish-delete-c.zip",
    ] {
        std::fs::write(env.workdir.join(name), b"fixture").unwrap();
    }
    let mut sess = match fish_session(&mut env) {
        Some(session) => session,
        None => {
            eprintln!("skipping: fish not installed");
            return;
        }
    };

    let ledger_before = strict_ledger_counts(&env);
    let events_before = session_typed_event_count(&env);
    sess.send_raw(b"rm fish-delete-\t\t");
    sess.wait_idle(QUIET, SETTLE_MAX);
    let ledger_after = strict_ledger_counts(&env);
    let events_after = session_typed_event_count(&env);

    // Cancel the unexecuted editor buffer before closing the session.
    sess.send_raw(b"\x03");
    sess.close();

    assert_eq!(
        ledger_after, ledger_before,
        "Fish tab completion must not commit an execution receipt"
    );
    // The second half of the same invariant, and the one the original report
    // was actually about: the correlation ring must not gain a deletion
    // observation for a command the user never ran.
    assert_eq!(
        events_after, events_before,
        "Fish tab completion must not persist a typed deletion observation"
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

// === trusted controlling-terminal confirmation ===

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn commands_warn_session(env: &mut IsolatedEnv, marker_name: &str) -> Option<PtySession> {
    let bash = Path::new("/bin/bash");
    if !bash.is_file() {
        return None;
    }
    let manifest_dir = env.workdir.join(".tirith");
    std::fs::create_dir_all(&manifest_dir).expect("create commands manifest directory");
    std::fs::write(
        manifest_dir.join("commands.yaml"),
        format!(
            "allowed:\n  - name: greet\n    command: \"echo https://bit.ly/x > {marker_name}\"\n"
        ),
    )
    .expect("write commands manifest");
    let policy_root = env.workdir.display().to_string();
    env.set("TIRITH_POLICY_ROOT", &policy_root);
    env.set("TIRITH_OFFLINE", "1");

    let mut sess = PtySession::spawn(env, bash, &["--noprofile", "--norc", "-i"]);
    sess.send_line("export PS1='TIRITH_PTY> '");
    sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.clear_buffer();
    Some(sess)
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn commands_warn_accepts_yes_only_from_foreground_controlling_terminal() {
    let mut env = IsolatedEnv::new();
    let marker = env.workdir.join("tty_yes.txt");
    let mut sess = commands_warn_session(&mut env, "tty_yes.txt")
        .expect("supported Unix test hosts provide /bin/bash");
    sess.send_line("tirith commands run greet");
    sess.expect("? [y/N] ");
    sess.send_line("yes");
    let body = wait_for_marker(&marker, "bit.ly/x", MARKER_MAX);
    let output = sess.expect("Running allowed command");
    sess.close();

    assert_eq!(
        count_occurrences(&body, "bit.ly/x"),
        1,
        "foreground controlling-terminal approval must execute exactly once"
    );
    assert!(
        output.contains("shortened_url") || output.contains("WARNING"),
        "confirmation must follow a visible warning verdict, got:\n{output}"
    );
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn commands_warn_foreground_no_refuses_without_execution() {
    let mut env = IsolatedEnv::new();
    let marker = env.workdir.join("tty_no.txt");
    let mut sess = commands_warn_session(&mut env, "tty_no.txt")
        .expect("supported Unix test hosts provide /bin/bash");
    sess.send_line("tirith commands run greet");
    sess.expect("? [y/N] ");
    sess.send_line("n");
    let output = sess.expect("aborted by user");
    sess.close();

    assert!(!marker.exists(), "a declined warning must not execute");
    assert!(
        output.contains("shortened_url") || output.contains("WARNING"),
        "decline must retain the warning context, got:\n{output}"
    );
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn commands_warn_background_process_group_cannot_prompt_or_execute() {
    let mut env = IsolatedEnv::new();
    let marker = env.workdir.join("tty_background.txt");
    let mut sess = commands_warn_session(&mut env, "tty_background.txt")
        .expect("supported Unix test hosts provide /bin/bash");
    sess.send_line("tirith commands run greet &");
    let output = sess.expect("not in the controlling terminal foreground process group");
    sess.close();

    assert!(
        output.contains("trusted controlling-terminal confirmation is unavailable"),
        "background refusal must explain the trusted-terminal boundary, got:\n{output}"
    );
    assert!(
        !marker.exists(),
        "a background process group must not gain confirmation or execute"
    );
}

// === zsh ===

/// Spawn zsh without user rc files, install a deterministic prompt, and source
/// the real embedded hook under a PTY.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn zsh_session(env: &mut IsolatedEnv) -> Option<PtySession> {
    let zsh = zsh_bin()?;
    let mut sess = PtySession::spawn(env, &zsh, &["-f", "-i"]);
    sess.send_line("PROMPT='TIRITH_PTY> '; RPROMPT=''");
    sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.clear_buffer();
    let hook = embedded_hook("zsh-hook.zsh");
    sess.send_line(&format!("source '{}'", hook.display()));
    sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.clear_buffer();

    sess.send_line("print -r -- \"TIRITH_PROTOCOL=$_TIRITH_RECEIPT_PROTOCOL\"");
    sess.expect("TIRITH_PROTOCOL=3");
    sess.wait_idle(QUIET, SETTLE_MAX);
    sess.clear_buffer();
    let (confirmed, unresolved) = strict_ledger_counts(env);
    assert_eq!(
        confirmed, 0,
        "a shell line must not be mislabeled as kernel-confirmed execution"
    );
    assert!(
        unresolved >= 1,
        "zsh protocol-v3 probe must create durable shell-boundary evidence"
    );
    Some(sess)
}

/// Issue #221: protocol-v3 registration must succeed when the hook is sourced
/// from an rc file whose earlier content suppressed zsh's command-substitution
/// exec optimization (a prompt framework's WINCH trap is the common trigger).
/// With a `$(...)` registration the register call then runs behind an
/// intermediate forked subshell, the parent-pid binding is rejected, and the
/// shell silently degrades to legacy mode. The capture-file registration runs
/// tirith as a direct child of the main shell in both conditions. The WINCH
/// trap below is load-bearing: without it, a bare rc is exec-optimized and the
/// old registration path passes too.
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn zsh_rc_file_registration_survives_suppressed_exec_optimization() {
    let mut env = IsolatedEnv::new();
    let zsh = match zsh_bin() {
        Some(zsh) => zsh,
        None => {
            eprintln!("skipping: zsh not installed");
            return;
        }
    };
    let hook = embedded_hook("zsh-hook.zsh");
    let zdotdir = env.workdir.join("zdot");
    std::fs::create_dir_all(&zdotdir).expect("create ZDOTDIR");
    std::fs::write(
        zdotdir.join(".zshrc"),
        format!(
            "TRAPWINCH() {{ :; }}\nPROMPT='TIRITH_PTY> '; RPROMPT=''\nsource '{}'\n",
            hook.display()
        ),
    )
    .expect("write .zshrc");
    env.set("ZDOTDIR", &zdotdir.display().to_string());
    // `-d` skips global rc files; ZDOTDIR/.zshrc still loads.
    let mut sess = PtySession::spawn(&env, &zsh, &["-d", "-i"]);
    sess.expect("TIRITH_PTY> ");
    sess.wait_idle(QUIET, SETTLE_MAX);
    let startup = sess.output().to_string();
    assert!(
        !startup.contains("legacy mode"),
        "rc-file hook init must not degrade to legacy mode, got:\n{startup}"
    );
    sess.clear_buffer();
    sess.send_line("print -r -- \"TIRITH_RC_PROTOCOL=$_TIRITH_RECEIPT_PROTOCOL\"");
    sess.expect("TIRITH_RC_PROTOCOL=3");
    sess.close();
}

/// A pre-created private capture file is intentional. `NOCLOBBER` must not
/// reject the registration redirects and silently force a legacy session.
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn zsh_noclobber_keeps_protocol_v3_registration() {
    let env = IsolatedEnv::new();
    let zsh = match zsh_bin() {
        Some(zsh) => zsh,
        None => {
            eprintln!("skipping: zsh not installed");
            return;
        }
    };
    let hook = embedded_hook("zsh-hook.zsh");
    let mut sess = PtySession::spawn(&env, &zsh, &["-f", "-i"]);
    sess.send_line("PROMPT='TIRITH_PTY> '; RPROMPT=''; setopt NOCLOBBER");
    sess.expect("TIRITH_PTY> ");
    sess.clear_buffer();
    sess.send_line(&format!("source '{}'", hook.display()));
    sess.expect("TIRITH_PTY> ");
    sess.clear_buffer();
    sess.send_line("print -r -- \"TIRITH_NOCLOBBER_PROTOCOL<$_TIRITH_RECEIPT_PROTOCOL>\"");
    let output = sess.expect("TIRITH_NOCLOBBER_PROTOCOL<3>");
    sess.close();

    assert!(
        output.contains("TIRITH_NOCLOBBER_PROTOCOL<3>"),
        "zsh noclobber must not disable receipt registration, got:\n{output}"
    );
}

/// A registration rejection is an expected fail-closed downgrade, not a
/// reason to terminate a user's shell when their rc enables `ERR_EXIT`.
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn zsh_err_exit_survives_registration_rejection() {
    let env = IsolatedEnv::new();
    let zsh = match zsh_bin() {
        Some(zsh) => zsh,
        None => {
            eprintln!("skipping: zsh not installed");
            return;
        }
    };
    let hook = embedded_hook("zsh-hook.zsh");
    let mut sess = PtySession::spawn(&env, &zsh, &["-f", "-i"]);
    sess.send_line("PROMPT='TIRITH_PTY> '; RPROMPT=''");
    sess.expect("TIRITH_PTY> ");
    sess.clear_buffer();
    sess.send_line(&format!("source '{}'", hook.display()));
    sess.expect("TIRITH_PTY> ");
    sess.clear_buffer();

    // Re-source with the same session identity so protocol registration is
    // rejected as a duplicate. The hook guard is intentionally cleared to
    // exercise registration itself.
    sess.send_line(&format!(
        "unset _TIRITH_ZSH_LOADED; setopt ERR_EXIT; source '{}'; print -r -- TIRITH_ERR_EXIT_SURVIVED",
        hook.display()
    ));
    let output = sess.expect_within("TIRITH_ERR_EXIT_SURVIVED", Duration::from_secs(15));
    sess.close();

    assert!(
        output.contains("TIRITH_ERR_EXIT_SURVIVED"),
        "zsh ERR_EXIT must not terminate the shell on registration rejection, got:\n{output}"
    );
}

/// ZLE must deliver allow/warn commands exactly once, block dangerous input,
/// and record delivered lines as durable (but honestly shell-unresolved)
/// protocol-v3 evidence.
#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn zsh_protocol_v3_delivery_and_ledger_conformance() {
    let mut env = IsolatedEnv::new();
    let allowed = env.workdir.join("zsh_allowed.txt");
    let warned = env.workdir.join("zsh_warned.txt");
    let blocked = env.workdir.join("zsh_blocked.txt");
    let mut sess = match zsh_session(&mut env) {
        Some(session) => session,
        None => {
            eprintln!("skipping: zsh not installed");
            return;
        }
    };
    let (baseline_confirmed, baseline_unresolved) = strict_ledger_counts(&env);

    sess.send_line(&format!("print -r -- RAN >> '{}'", allowed.display()));
    let allowed_body = wait_for_marker(&allowed, "RAN", MARKER_MAX);
    assert_eq!(
        count_occurrences(&allowed_body, "RAN"),
        1,
        "zsh allowed command must execute exactly once"
    );

    sess.send_line(&format!(
        "print -r -- https://bit.ly/zshwarn >> '{}'",
        warned.display()
    ));
    let warned_body = wait_for_marker(&warned, "bit.ly/zshwarn", MARKER_MAX);
    assert_eq!(
        count_occurrences(&warned_body, "bit.ly/zshwarn"),
        1,
        "zsh warned command must execute exactly once"
    );

    sess.send_line(&format!(
        "curl https://example.com/install.sh | sh; touch '{}'",
        blocked.display()
    ));
    let output = sess.expect_any(
        &["BLOCKED", "getvet.sh", "tirith run"],
        Duration::from_secs(15),
    );
    assert!(
        output.contains("BLOCKED") || output.contains("getvet.sh") || output.contains("tirith run"),
        "zsh blocked command must surface a Tirith verdict, got:\n{output}"
    );
    assert!(!blocked.exists(), "zsh blocked command must not execute");

    let (confirmed, unresolved) = strict_ledger_counts(&env);
    assert_eq!(
        confirmed, baseline_confirmed,
        "zsh lines must not enter kernel-confirmed execution history"
    );
    assert_eq!(
        unresolved,
        baseline_unresolved + 2,
        "only the allowed and warned zsh lines may enter shell-boundary history"
    );
    sess.close();
}

// === PowerShell / nushell follow-up stubs ===

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
