//! Tests for the bash hook's preexec enforcement path.
//!
//! Each test drives an interactive bash subshell with a fake `tirith` on PATH
//! that logs its invocations and returns exit codes by input pattern, then
//! asserts on side effects (sentinel files a blocked command would create) plus
//! the invocation log.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn hook_path() -> String {
    format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// Build a fake tirith binary that logs its args to `log_path` and exits by
/// input token: `BLOCK_TOKEN` → 1, `WARN_TOKEN` → 2, `BADRC_TOKEN` → 99, else 0.
fn install_fake_tirith(bin_dir: &Path, log_path: &Path) {
    fs::create_dir_all(bin_dir).unwrap();
    let script = format!(
        r#"#!/bin/bash
printf '%s\n' "$*" >> {log}
case "$*" in
  *BLOCK_TOKEN*)  exit 1 ;;
  *WARN_TOKEN*)   exit 2 ;;
  *BADRC_TOKEN*)  exit 99 ;;
esac
# Mirror the real CLI's clean-result text unless the shell hook's exported
# suppression marker reached this child process (issue #175).
if [[ "${{_TIRITH_HOOK:-0}}" != "1" && "${{_TIRITH_BASH_INTERNAL:-0}}" != "1" ]]; then
  printf 'tirith: no issues\n'
fi
exit 0
"#,
        log = shell_escape(log_path.to_string_lossy().as_ref()),
    );
    let bin = bin_dir.join("tirith");
    fs::write(&bin, script).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
}

fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Run a fully-formed bash script against a fake `tirith` binary. Returns
/// `(stdout, stderr, tirith_invocations)`.
fn run_bash_script(script: &str, env_vars: &[(&str, &str)]) -> (String, String, Vec<String>) {
    let tmpdir = tempfile::tempdir().unwrap();
    let bin_dir = tmpdir.path().join("bin");
    let log_path = tmpdir.path().join("tirith.log");
    install_fake_tirith(&bin_dir, &log_path);

    let mut cmd = Command::new("bash");
    cmd.args(["--norc", "--noprofile", "-i"])
        .env_clear()
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("XDG_STATE_HOME", tmpdir.path())
        .env("TMPDIR_FOR_TESTS", tmpdir.path())
        .env_remove("TIRITH_BASH_MODE")
        .env_remove("TIRITH_BASH_PREEXEC_ENFORCE")
        .env_remove("_TIRITH_BASH_LOADED")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env_vars {
        cmd.env(k, v);
    }

    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();

    let invocations = if log_path.exists() {
        fs::read_to_string(&log_path)
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    } else {
        Vec::new()
    };

    // Keep tmpdir alive till after we read the log.
    drop(tmpdir);

    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        invocations,
    )
}

/// Run a bash script against the hook with enforcement controls. Returns
/// `(stdout, stderr, tirith_invocations)`.
fn run_bash(script: &str, env_vars: &[(&str, &str)]) -> (String, String, Vec<String>) {
    let hook = hook_path();
    let full_script = format!("source '{hook}'\n{script}\n");
    run_bash_script(&full_script, env_vars)
}

fn sentinel_path(root: &Path, name: &str) -> PathBuf {
    root.join(name)
}

/// Helper that runs `run_bash` but pre-creates a sentinel-tracking tmpdir so
/// the test can inspect side-effects of commands that should or should not
/// have executed.
fn run_with_sentinels(
    script_template: &str,
    env_vars: &[(&str, &str)],
) -> (String, String, Vec<String>, PathBuf) {
    let sentinel_dir = tempfile::tempdir().unwrap().keep();
    let script = script_template.replace("{sentinels}", &sentinel_dir.display().to_string());
    let (stdout, stderr, inv) = run_bash(&script, env_vars);
    (stdout, stderr, inv, sentinel_dir)
}

#[test]
fn enforce_blocks_bare_command_with_rc1() {
    let (_out, _err, invocations, sentinel_dir) = run_with_sentinels(
        r#"
# Drive the block via a command that would create the sentinel if it ever
# executed. Avoid `blocked && touch ...` here because Linux bash can leave the
# interactive preexec path waiting after extdebug skips the left-hand side.
sh -c 'touch {sentinels}/should_not_exist' BLOCK_TOKEN-one
echo clean_post_block && touch {sentinels}/clean_ran
"#,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );

    assert!(
        !sentinel_path(&sentinel_dir, "should_not_exist").exists(),
        "blocked command must not have run; invocations: {invocations:#?}"
    );
    assert!(
        sentinel_path(&sentinel_dir, "clean_ran").exists(),
        "clean command after a block must still run; invocations: {invocations:#?}"
    );
    // Tirith was invoked at least once on the blocked line.
    assert!(
        invocations.iter().any(|i| i.contains("BLOCK_TOKEN-one")),
        "fake tirith did not see the blocked line: {invocations:#?}"
    );
    let _ = fs::remove_dir_all(&sentinel_dir);
}

#[test]
fn enforce_blocks_whole_pipeline() {
    // A blocked producer must keep the downstream `sh` segment from running.
    // `printf` (not a real network client) so an unexpected execute fails fast.
    let (_out, _err, invocations, sentinel_dir) = run_with_sentinels(
        r#"
printf BLOCK_TOKEN-pipe | sh -c 'touch {sentinels}/pipe_leaked'
"#,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );

    assert!(
        !sentinel_path(&sentinel_dir, "pipe_leaked").exists(),
        "downstream pipeline segment ran despite block; invocations: {invocations:#?}"
    );
    let _ = fs::remove_dir_all(&sentinel_dir);
}

#[test]
fn enforce_blocks_whole_sequence() {
    // When the second segment of `touch ; sh -c ... BLOCK` blocks, the whole
    // typed line must skip. (Avoid `blocked && touch ...` — it hangs on Linux CI
    // under extdebug.)
    let (_out, _err, invocations, sentinel_dir) = run_with_sentinels(
        r#"
touch {sentinels}/ls_ran; sh -c 'touch {sentinels}/curl_ran' BLOCK_TOKEN-seq
"#,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );

    assert!(
        !sentinel_path(&sentinel_dir, "curl_ran").exists(),
        "second segment ran despite block; invocations: {invocations:#?}"
    );
    // With whole-line fail-closed, the ls must also not touch its sentinel.
    assert!(
        !sentinel_path(&sentinel_dir, "ls_ran").exists(),
        "leading segment ran under whole-line block; invocations: {invocations:#?}"
    );
    let _ = fs::remove_dir_all(&sentinel_dir);
}

#[test]
fn enforce_allows_clean_commands() {
    let (out, err, invocations, sentinel_dir) = run_with_sentinels(
        r#"
echo clean_one && touch {sentinels}/one
echo clean_two && touch {sentinels}/two
"#,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );

    assert!(sentinel_path(&sentinel_dir, "one").exists());
    assert!(sentinel_path(&sentinel_dir, "two").exists());
    // Tirith was called for each command.
    assert!(invocations.iter().any(|i| i.contains("clean_one")));
    assert!(invocations.iter().any(|i| i.contains("clean_two")));
    assert!(
        !out.contains("tirith: no issues") && !err.contains("tirith: no issues"),
        "the hook marker must suppress clean-result spam; stdout={out:?}, stderr={err:?}"
    );
    let _ = fs::remove_dir_all(&sentinel_dir);
}

#[test]
fn enforce_keeps_allowed_function_top_level_and_extdebug_lazy() {
    let (stdout, stderr, invocations, _tmp) = run_with_sentinels(
        r#"
benign_fn() { printf 'FUNCTION_BODY_RAN\n'; }
benign_fn
printf 'PROT=%s STATUS=%s ENFORCE=%s OWNS=%s\n' \
  "$TIRITH_BASH_EFFECTIVE_PROTECTION" "$TIRITH_STATUS" \
  "$_TIRITH_PREEXEC_ENFORCE" "$_TIRITH_OWNS_EXTDEBUG" >&2
if shopt -q extdebug; then printf 'EXTDEBUG=on\n' >&2; else printf 'EXTDEBUG=off\n' >&2; fi
"#,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );

    assert!(
        stdout.contains("FUNCTION_BODY_RAN"),
        "an allowed function body must execute; stdout={stdout:?}, stderr={stderr:?}"
    );
    assert!(
        stderr.contains("PROT=blocks STATUS=blocks ENFORCE=1 OWNS=0")
            && stderr.contains("EXTDEBUG=off"),
        "allowed lines must leave lazy extdebug off without degrading: {stderr}"
    );
    assert!(
        !stderr.contains("history no longer matches BASH_COMMAND")
            && !stderr.contains("protection downgraded"),
        "function internals must not be mistaken for typed lines: {stderr}"
    );
    let invocation_count = invocations
        .iter()
        .filter(|line| line.ends_with("-- benign_fn"))
        .count();
    assert_eq!(
        invocation_count, 1,
        "one typed function call must produce one decision, got {invocations:#?}"
    );
}

#[test]
fn enforce_blocks_malicious_function_line_before_body_runs() {
    let (_stdout, stderr, invocations, sentinel_dir) = run_with_sentinels(
        r#"
malicious_fn() { touch {sentinels}/function_body_ran; }; malicious_fn BLOCK_TOKEN-function
"#,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );

    assert!(
        !sentinel_path(&sentinel_dir, "function_body_ran").exists(),
        "the complete typed function line must be decided before its body runs; stderr={stderr:?}, invocations={invocations:#?}"
    );
    let matching_decisions = invocations
        .iter()
        .filter(|line| line.contains("malicious_fn") && line.contains("BLOCK_TOKEN-function"))
        .count();
    assert_eq!(
        matching_decisions, 1,
        "the fake checker must receive the complete typed function line exactly once: {invocations:#?}"
    );
    let _ = fs::remove_dir_all(&sentinel_dir);
}

#[test]
fn enforce_brackets_prompt_function_without_scanning_or_degrading_it() {
    let hook = hook_path();
    let script = format!(
        r#"
PROMPT_RUNS=0
prompt_fn() {{ PROMPT_RUNS=$((PROMPT_RUNS + 1)); }}
PROMPT_COMMAND=prompt_fn
source '{hook}'
printf 'PROMPT_RUNS=%s PROT=%s STATUS=%s ENFORCE=%s\n' \
  "$PROMPT_RUNS" "$TIRITH_BASH_EFFECTIVE_PROTECTION" "$TIRITH_STATUS" \
  "$_TIRITH_PREEXEC_ENFORCE" >&2
"#
    );
    let (_stdout, stderr, invocations) = run_bash_script(
        &script,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );

    assert!(
        stderr.contains("PROT=blocks STATUS=blocks ENFORCE=1"),
        "PROMPT_COMMAND must leave enforcement active: {stderr}"
    );
    assert!(
        !stderr.contains("history no longer matches BASH_COMMAND")
            && !stderr.contains("protection downgraded"),
        "prompt functions must not trigger history drift: {stderr}"
    );
    assert!(
        invocations
            .iter()
            .all(|line| !line.ends_with("-- prompt_fn")),
        "automatic prompt functions must not be scanned or receipted: {invocations:#?}"
    );
}

#[test]
fn prompt_owned_extdebug_degrades_before_the_next_user_command() {
    let hook = hook_path();
    let script = format!(
        r#"
ARM_EXTDEBUG=0
prompt_fn() {{
  if [[ "$ARM_EXTDEBUG" == "1" ]]; then shopt -s extdebug; fi
  true
}}
PROMPT_COMMAND=prompt_fn
source '{hook}'
ARM_EXTDEBUG=1
:
printf 'PROT=%s STATUS=%s ENFORCE=%s OWNS=%s\n' \
  "$TIRITH_BASH_EFFECTIVE_PROTECTION" "$TIRITH_STATUS" \
  "$_TIRITH_PREEXEC_ENFORCE" "$_TIRITH_OWNS_EXTDEBUG" >&2
if shopt -q extdebug; then printf 'PROMPT_OWNED_EXTDEBUG=on\n' >&2; else printf 'PROMPT_OWNED_EXTDEBUG=off\n' >&2; fi
"#
    );
    let (_stdout, stderr, invocations) = run_bash_script(
        &script,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );

    assert!(
        stderr.contains("extdebug became enabled by prompt code outside Tirith")
            && stderr.contains("PROT=warn-only STATUS=degraded ENFORCE=0 OWNS=0")
            && stderr.contains("PROMPT_OWNED_EXTDEBUG=on"),
        "prompt-owned extdebug must be preserved and disable blocking before another user command: {stderr}"
    );
    assert!(
        invocations
            .iter()
            .all(|line| !line.ends_with("-- prompt_fn")),
        "the prompt function must never be scanned as typed input: {invocations:#?}"
    );
}

#[test]
fn prompt_string_guards_preserve_order_and_previous_status() {
    let hook = hook_path();
    let script = format!(
        r#"
PROMPT_ORDER=""
PROMPT_AFTER_HOOK=0
prompt_first() {{
  local seen=$?
  PROMPT_ORDER="${{PROMPT_ORDER}}1"
  [[ "$PROMPT_AFTER_HOOK" == "1" ]] && printf 'FIRST_STATUS=%s\n' "$seen" >&2
  return "$seen"
}}
prompt_second() {{ PROMPT_ORDER="${{PROMPT_ORDER}}2"; }}
PROMPT_COMMAND='prompt_first;prompt_second'
source '{hook}'
PROMPT_AFTER_HOOK=1
false
printf 'PROMPT_ORDER_SUFFIX=%s\n' "${{PROMPT_ORDER:${{#PROMPT_ORDER}}-2}}" >&2
"#
    );
    let (_stdout, stderr, _invocations) = run_bash_script(
        &script,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );

    assert!(
        stderr.contains("FIRST_STATUS=1"),
        "the first user PROMPT_COMMAND must see the typed command status: {stderr}"
    );
    assert!(
        stderr.contains("PROMPT_ORDER_SUFFIX=12"),
        "prompt command ordering must remain stable: {stderr}"
    );
}

#[test]
fn prompt_array_is_wrapped_only_when_bash_executes_every_element() {
    let hook = hook_path();
    let script = format!(
        r#"
prompt_first() {{ :; }}
prompt_second() {{ :; }}
PROMPT_COMMAND=(prompt_first prompt_second)
source '{hook}'
if (( BASH_VERSINFO[0] > 5 || (BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] >= 1) )); then
  array_supported=1
else
  array_supported=0
fi
if [[ "${{PROMPT_COMMAND[1]:-}}" == "$_TIRITH_PREEXEC_BOOTSTRAP_COMMAND" ]]; then bootstrap_ok=1; else bootstrap_ok=0; fi
printf 'ARRAY_SUPPORTED=%s LEN=%s PC0=%s PC2=%s PC3=%s PC4=%s BOOTSTRAP=%s ENFORCE=%s GUARDS=%s\n' \
  "$array_supported" "${{#PROMPT_COMMAND[@]}}" \
  "${{PROMPT_COMMAND[0]:-}}" "${{PROMPT_COMMAND[2]:-}}" \
  "${{PROMPT_COMMAND[3]:-}}" "${{PROMPT_COMMAND[4]:-}}" "$bootstrap_ok" \
  "$_TIRITH_PREEXEC_ENFORCE" "$_TIRITH_PREEXEC_PROMPT_GUARDS" >&2
[[ "$array_supported" == "0" ]] && printf 'UNSUPPORTED_PC1=%s\n' "${{PROMPT_COMMAND[1]:-}}" >&2
"#
    );
    let (_stdout, stderr, _invocations) = run_bash_script(
        &script,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );

    if stderr.contains("ARRAY_SUPPORTED=1") {
        assert!(
            stderr.contains(
                "LEN=5 PC0=_tirith_preexec_prompt_begin PC2=prompt_first PC3=prompt_second PC4=_tirith_preexec_prompt_end BOOTSTRAP=1 ENFORCE=1 GUARDS=1"
            ),
            "supported PROMPT_COMMAND arrays must retain order inside the guards: {stderr}"
        );
    } else {
        assert!(
            stderr.contains(
                "ARRAY_SUPPORTED=0 LEN=2 PC0=prompt_first PC2= PC3= PC4= BOOTSTRAP=0 ENFORCE=0 GUARDS=0"
            ) && stderr.contains("UNSUPPORTED_PC1=prompt_second")
                && stderr.contains("PROMPT_COMMAND is readonly, associative, coercing, unsupported"),
            "Bash without array PROMPT_COMMAND execution must preserve the array and refuse enforcement visibly: {stderr}"
        );
    }
}

#[test]
fn readonly_prompt_command_visibly_refuses_enforcement() {
    let hook = hook_path();
    let script = format!(
        r#"
USER_TRAP_COUNT=0
trap 'USER_TRAP_COUNT=$((USER_TRAP_COUNT + 1)); true' DEBUG
PROMPT_COMMAND=':'
readonly PROMPT_COMMAND
source '{hook}'
USER_TRAP_COUNT=0
echo after_refusal
printf 'PROT=%s STATUS=%s ENFORCE=%s OWNS=%s\n' \
  "$TIRITH_BASH_EFFECTIVE_PROTECTION" "$TIRITH_STATUS" \
  "$_TIRITH_PREEXEC_ENFORCE" "$_TIRITH_OWNS_EXTDEBUG" >&2
printf 'USER_TRAP_AFTER_REFUSAL=%s\n' "$USER_TRAP_COUNT" >&2
trap -p DEBUG >&2
"#
    );
    let (_stdout, stderr, _invocations) = run_bash_script(
        &script,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );

    assert!(
        stderr.contains("PROMPT_COMMAND is readonly")
            && stderr.contains("PROT=off STATUS=degraded ENFORCE=0 OWNS=0")
            && stderr.contains("trap -- 'USER_TRAP_COUNT=$((USER_TRAP_COUNT + 1)); true' DEBUG"),
        "unsafe prompt bracketing must fail visibly without replacing the user trap or touching extdebug: {stderr}"
    );
    let count = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("USER_TRAP_AFTER_REFUSAL="))
        .next_back()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    assert!(
        count >= 1,
        "the preserved user DEBUG trap must still run: {stderr}"
    );
}

#[test]
fn removed_prompt_guards_degrade_but_functions_continue_without_prompt_scans() {
    let hook = hook_path();
    let script = format!(
        r#"
PROMPT_RUNS=0
prompt_fn() {{ PROMPT_RUNS=$((PROMPT_RUNS + 1)); }}
benign_after_degrade() {{ printf 'POST_DEGRADE_FUNCTION_RAN\n'; }}
PROMPT_COMMAND=prompt_fn
source '{hook}'
PROMPT_COMMAND=prompt_fn
benign_after_degrade
printf 'POST_PROT=%s STATUS=%s ENFORCE=%s OWNS=%s\n' \
  "$TIRITH_BASH_EFFECTIVE_PROTECTION" "$TIRITH_STATUS" \
  "$_TIRITH_PREEXEC_ENFORCE" "$_TIRITH_OWNS_EXTDEBUG" >&2
if shopt -q extdebug; then printf 'POST_EXTDEBUG=on\n' >&2; else printf 'POST_EXTDEBUG=off\n' >&2; fi
"#
    );
    let (stdout, stderr, invocations) = run_bash_script(
        &script,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );

    assert!(stdout.contains("POST_DEGRADE_FUNCTION_RAN"));
    assert!(
        stderr.contains("PROMPT_COMMAND no longer contains Tirith's prompt-boundary guards")
            && stderr.contains("POST_PROT=warn-only STATUS=degraded ENFORCE=0 OWNS=0")
            && stderr.contains("POST_EXTDEBUG=off"),
        "guard loss must degrade visibly, restore debugger state, and keep functions usable: {stderr}"
    );
    assert!(
        invocations
            .iter()
            .all(|line| !line.ends_with("-- prompt_fn")),
        "automatic prompt functions must not become warn-only scans after degradation: {invocations:#?}"
    );
}

#[test]
fn enforce_treats_warn_rc2_as_allow() {
    let (_out, _err, _inv, sentinel_dir) = run_with_sentinels(
        r#"
echo WARN_TOKEN && touch {sentinels}/warn_ran
"#,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );
    assert!(
        sentinel_path(&sentinel_dir, "warn_ran").exists(),
        "warn verdict (rc 2) must not block execution"
    );
    let _ = fs::remove_dir_all(&sentinel_dir);
}

#[test]
fn unexpected_rc_blocks_then_degrades_session() {
    let (_out, stderr, _inv, sentinel_dir) = run_with_sentinels(
        r#"
echo BADRC_TOKEN-first && touch {sentinels}/badrc_ran
echo post_degrade && touch {sentinels}/post_ran
printf 'POST_PROT=%s STATUS=%s ENFORCE=%s OWNS=%s\n' \
  "$TIRITH_BASH_EFFECTIVE_PROTECTION" "$TIRITH_STATUS" \
  "$_TIRITH_PREEXEC_ENFORCE" "$_TIRITH_OWNS_EXTDEBUG" >&2
if shopt -q extdebug; then printf 'POST_EXTDEBUG=on\n' >&2; else printf 'POST_EXTDEBUG=off\n' >&2; fi
"#,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );

    assert!(
        !sentinel_path(&sentinel_dir, "badrc_ran").exists(),
        "command that triggered unexpected rc should have been blocked"
    );
    assert!(
        sentinel_path(&sentinel_dir, "post_ran").exists(),
        "post-degrade commands must still run (session is now warn-only)"
    );
    assert!(
        stderr.contains("preexec enforcement failed unexpectedly"),
        "expected unexpected-rc banner on stderr, got: {stderr}"
    );
    assert!(
        stderr.contains("POST_PROT=warn-only STATUS=degraded ENFORCE=0 OWNS=0")
            && stderr.contains("POST_EXTDEBUG=off"),
        "the first post-degrade prompt must release Tirith-owned extdebug: {stderr}"
    );
    let _ = fs::remove_dir_all(&sentinel_dir);
}

#[test]
fn hostile_histcontrol_ignorespace_refuses_enforcement() {
    let (_out, stderr, _inv, sentinel_dir) = run_with_sentinels(
        r#"
echo BLOCK_TOKEN-ignorespace && touch {sentinels}/ran_anyway
"#,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
            ("HISTCONTROL", "ignorespace"),
        ],
    );

    // With ignorespace set at install, enforcement is refused (warn-only); a
    // block rc is NOT enforced.
    assert!(
        sentinel_path(&sentinel_dir, "ran_anyway").exists(),
        "warn-only must allow the command to run even if tirith returns 1"
    );
    // The one-shot degrade banner: headline + hostile-history detail line.
    assert!(
        stderr.contains("protection downgraded to warn-only"),
        "expected the consolidated degrade headline, got: {stderr}"
    );
    assert!(
        stderr.contains("preexec enforcement could not engage"),
        "expected the install-time refusal detail line, got: {stderr}"
    );
    let _ = fs::remove_dir_all(&sentinel_dir);
}

#[test]
fn hostile_histignore_refuses_enforcement() {
    let (_out, stderr, _inv, sentinel_dir) = run_with_sentinels(
        r#"
echo BLOCK_TOKEN-histignore && touch {sentinels}/ran_anyway
"#,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
            ("HISTIGNORE", "ls:cd:pwd"),
        ],
    );
    assert!(sentinel_path(&sentinel_dir, "ran_anyway").exists());
    assert!(stderr.contains("protection downgraded to warn-only"));
    assert!(stderr.contains("preexec enforcement could not engage"));
    let _ = fs::remove_dir_all(&sentinel_dir);
}

#[test]
fn hostile_ignoredups_refuses_enforcement() {
    let (_out, stderr, _inv, sentinel_dir) = run_with_sentinels(
        r#"
echo BLOCK_TOKEN-ignoredups && touch {sentinels}/ran_anyway
"#,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
            ("HISTCONTROL", "ignoredups"),
        ],
    );
    assert!(sentinel_path(&sentinel_dir, "ran_anyway").exists());
    assert!(stderr.contains("protection downgraded to warn-only"));
    assert!(stderr.contains("preexec enforcement could not engage"));
    let _ = fs::remove_dir_all(&sentinel_dir);
}

#[test]
fn enforce_off_preserves_warn_only_behavior() {
    let (_out, _err, invocations, sentinel_dir) = run_with_sentinels(
        r#"
echo BLOCK_TOKEN-noenforce && touch {sentinels}/ran_in_warn_only
"#,
        &[("TIRITH_BASH_MODE", "preexec")],
    );
    assert!(
        sentinel_path(&sentinel_dir, "ran_in_warn_only").exists(),
        "without TIRITH_BASH_PREEXEC_ENFORCE, a block rc must not stop execution"
    );
    // Warn-only path still invokes tirith check with --warn-only flag.
    assert!(
        invocations.iter().any(|i| i.contains("--warn-only")),
        "warn-only path should pass --warn-only to tirith; invocations: {invocations:#?}"
    );
    let _ = fs::remove_dir_all(&sentinel_dir);
}

#[test]
fn enforcement_exports_blocks_protection() {
    let (_out, stderr, _inv, _tmp) = run_with_sentinels(
        r#"
printf 'PROT=%s\n' "$TIRITH_BASH_EFFECTIVE_PROTECTION" >&2
printf 'STATUS=%s\n' "$TIRITH_STATUS" >&2
"#,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );
    assert!(
        stderr.contains("PROT=blocks"),
        "expected PROT=blocks, got stderr: {stderr}"
    );
    // The prompt indicator (non-exported shell var, read in the same shell) also
    // reports `blocks` once enforcement engages (it starts warn-only, upgrades).
    // This fake binary does not negotiate receipt protocol v3; that separately
    // degrades durable execution evidence, not the hook's blocking ability.
    assert!(
        stderr.contains("STATUS=blocks"),
        "engaged enforcement must set TIRITH_STATUS=blocks, got stderr: {stderr}"
    );
    assert!(
        stderr.contains("execution receipts unavailable")
            && stderr.contains("execution evidence is degraded"),
        "receipt evidence loss must remain visible without relabeling blocking protection: {stderr}"
    );
    let _ = fs::remove_dir_all(&_tmp);
}

#[test]
fn hostile_config_exports_warn_only() {
    let (_out, stderr, _inv, _tmp) = run_with_sentinels(
        r#"
printf 'PROT=%s\n' "$TIRITH_BASH_EFFECTIVE_PROTECTION" >&2
printf 'STATUS=%s\n' "$TIRITH_STATUS" >&2
"#,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
            ("HISTCONTROL", "ignorespace"),
        ],
    );
    assert!(
        stderr.contains("PROT=warn-only"),
        "hostile install-time config must export warn-only, got: {stderr}"
    );
    // Blocking was requested but hostile history refused it — that downgrade
    // surfaces to the prompt indicator as `degraded`, distinct from a shell that
    // simply starts in warn-only.
    assert!(
        stderr.contains("STATUS=degraded"),
        "enforcement refused by hostile history must set TIRITH_STATUS=degraded, got: {stderr}"
    );
    assert!(
        stderr.contains("execution receipts unavailable")
            && stderr.contains("execution evidence is degraded"),
        "receipt evidence loss must remain visible without relabeling warn-only protection: {stderr}"
    );
    let _ = fs::remove_dir_all(&_tmp);
}

#[test]
fn exported_internal_marker_does_not_disable_interception() {
    // `_TIRITH_BASH_INTERNAL` is the first line of `_tirith_preexec`. Tirith
    // only ever passes it as a command prefix on its own child invocations, so
    // an interactive shell that STARTS with it exported was handed it by
    // something else — a wrapper script, an `ssh SendEnv`, a direnv file, a
    // compromised parent. Honouring it there would silently switch off command
    // interception for the entire session.
    let (_out, _err, invocations, sentinel_dir) = run_with_sentinels(
        r#"
sh -c 'touch {sentinels}/poisoned_leak' BLOCK_TOKEN-internal
"#,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
            ("_TIRITH_BASH_INTERNAL", "1"),
        ],
    );

    assert!(
        !sentinel_path(&sentinel_dir, "poisoned_leak").exists(),
        "an inherited _TIRITH_BASH_INTERNAL must not disable the preexec scan; invocations: {invocations:#?}"
    );
    assert!(
        invocations
            .iter()
            .any(|i| i.contains("BLOCK_TOKEN-internal")),
        "tirith must still be consulted for the blocked line: {invocations:#?}"
    );
    let _ = fs::remove_dir_all(&sentinel_dir);
}

#[test]
fn exported_decision_cache_cannot_preseed_an_allow() {
    // The per-line decision cache is keyed on a small integer (`BASH_LINENO`),
    // so a guessable pre-seeded `allow` must not survive into the session. Try
    // the low line ids a fresh interactive shell actually uses.
    for guessed_line_id in ["0", "1", "2", "3"] {
        let (_out, _err, invocations, sentinel_dir) = run_with_sentinels(
            r#"
sh -c 'touch {sentinels}/cache_leak' BLOCK_TOKEN-cache
"#,
            &[
                ("TIRITH_BASH_MODE", "preexec"),
                ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
                ("_tirith_last_key", guessed_line_id),
                ("_tirith_last_rc", "0"),
            ],
        );
        assert!(
            !sentinel_path(&sentinel_dir, "cache_leak").exists(),
            "pre-seeded allow for line id {guessed_line_id} bypassed the scan; invocations: {invocations:#?}"
        );
        let _ = fs::remove_dir_all(&sentinel_dir);
    }
}

#[test]
fn exported_hook_state_is_cleared_but_session_local_state_is_kept() {
    // Only the ENVIRONMENT copy is untrusted. A value assigned inside the
    // session (no export) is the shell's own state and must survive, which is
    // what keeps the `_TIRITH_TEST_*` overrides and in-shell latches working.
    let hook = hook_path();
    let (_out, stderr, _inv) = run_bash_script(
        format!(
            r#"
_TIRITH_PREEXEC_WARNED=session_local
source '{hook}'
printf 'INTERNAL=[%s] LASTKEY=[%s] PREVTRAP=[%s] WARNED=[%s]\n' \
  "${{_TIRITH_BASH_INTERNAL:-}}" "${{_tirith_last_key:-}}" \
  "${{_TIRITH_PREV_DEBUG_TRAP:-}}" "$_TIRITH_PREEXEC_WARNED" >&2
            "#
        )
        .as_str(),
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("_TIRITH_BASH_INTERNAL", "1"),
            ("_tirith_last_key", "7"),
            (
                "_TIRITH_PREV_DEBUG_TRAP",
                "touch /tmp/tirith-should-never-run",
            ),
        ],
    );
    // The internal marker reads back as a session-local `0` rather than unset:
    // the scan path restores it to its captured previous value. What matters is
    // that the inherited `1` is gone and nothing re-exports it.
    assert!(
        stderr.contains("INTERNAL=[0] LASTKEY=[] PREVTRAP=[] WARNED=[session_local]")
            || stderr.contains("INTERNAL=[] LASTKEY=[] PREVTRAP=[] WARNED=[session_local]"),
        "inherited hook state must be dropped while session-local state is preserved, got: {stderr}"
    );
}

#[test]
fn debug_trap_chains_user_trap() {
    // A DEBUG trap installed BEFORE sourcing the hook must be wrapped, not clobbered.
    let (_out, stderr, _inv, _tmp) = run_with_sentinels(
        r#"
USER_TRAP_COUNT=0
trap 'USER_TRAP_COUNT=$((USER_TRAP_COUNT + 1)); if [[ "$BASH_COMMAND" == *"trap -p DEBUG"* ]]; then printf "CAPTURE_NOISE\n"; fi; true' DEBUG
# Re-source hook AFTER the user's DEBUG trap so we verify the wrap path.
unset _TIRITH_BASH_LOADED
source '__HOOK__'
# Discard every fire caused by re-sourcing itself. Only post-install commands
# count, so a clobbered (rather than chained) user trap cannot pass vacuously.
USER_TRAP_COUNT=0
echo chain_test_one
echo chain_test_two
printf 'USER_TRAP_COUNT=%s\n' "$USER_TRAP_COUNT" >&2
"#
        .replace("__HOOK__", &hook_path())
        .as_str(),
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );
    // The user's trap must have fired at least twice (once per echo; can be
    // higher due to DEBUG firing on sub-expressions).
    let count: u32 = stderr
        .lines()
        .filter_map(|l| l.strip_prefix("USER_TRAP_COUNT="))
        .next_back()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert!(
        count >= 2,
        "user DEBUG trap must chain through trampoline, got count={count}, stderr={stderr}"
    );
}

#[test]
fn chained_debug_trap_that_returns_early_still_reaches_the_scan() {
    // A DEBUG trap body is normally evaluated at the top level, where `return`
    // is a no-op, so real handlers use it as an early exit. `bash-preexec.sh`
    // — the base of oh-my-bash, Atuin and iTerm2 shell integration — opens with
    // exactly this shape. Evaluated inline it would return from Tirith's own
    // trampoline before the scan, silently disabling the session.
    //
    // This containment is a bash >= 5 guarantee. On bash 3.2 the trampoline
    // cannot reliably install over a pre-existing DEBUG trap whose bare body
    // returns, so Tirith detects the lost trap and degrades to `off` with a
    // banner (see the lost-trap test) rather than silently scanning nothing —
    // but it cannot hold the whole-line block there. Enter mode, the default
    // and recommended mode, is bash 5+ only, and the real bash-preexec wraps
    // its return in its own function, which is contained on every version.
    if spawned_bash_major() < 5 {
        eprintln!("skipping: needs bash >= 5 (spawned bash is older)");
        return;
    }
    for user_trap in [
        r#"[[ -n "$_BP_INTERACTIVE" ]] || return 0"#,
        "return",
        "if true; then return 1; fi",
    ] {
        let script = format!(
            r#"
trap '{user_trap}' DEBUG
unset _TIRITH_BASH_LOADED
source '{hook}'
sh -c 'touch {{sentinels}}/early_return_leak' BLOCK_TOKEN-early-return
"#,
            hook = hook_path(),
        );
        let (_out, _err, invocations, sentinel_dir) = run_with_sentinels(
            &script,
            &[
                ("TIRITH_BASH_MODE", "preexec"),
                ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
            ],
        );
        assert!(
            !sentinel_path(&sentinel_dir, "early_return_leak").exists(),
            "chained DEBUG trap {user_trap:?} bypassed the scan; invocations: {invocations:#?}"
        );
        assert!(
            invocations
                .iter()
                .any(|i| i.contains("BLOCK_TOKEN-early-return")),
            "tirith was never consulted behind {user_trap:?}: {invocations:#?}"
        );
        let _ = fs::remove_dir_all(&sentinel_dir);
    }
}

#[test]
fn install_debug_trap_is_idempotent() {
    let (_out, stderr, _inv, _tmp) = run_with_sentinels(
        r#"
_tirith_install_debug_trap
_tirith_install_debug_trap
_tirith_install_debug_trap
trap -p DEBUG | grep -c '_tirith_debug_trampoline' >&2
"#,
        &[("TIRITH_BASH_MODE", "preexec")],
    );
    assert!(
        stderr.contains("1\n") || stderr.ends_with("1\n") || stderr.contains("\n1"),
        "trap -p DEBUG should show exactly one trampoline ref, got: {stderr}"
    );
}

#[test]
fn replacing_tirith_debug_trap_mid_session_turns_protection_off_visibly() {
    // Once another tool owns the DEBUG trap, bash calls that tool and not
    // Tirith, so the command genuinely cannot be blocked any more. What must
    // never happen is the silent version: a shell that keeps reporting
    // protection while scanning nothing. `trap -p DEBUG` reads back empty
    // inside a function, so ownership is proven by the trampoline's own
    // per-prompt heartbeat rather than by re-reading the trap.
    for tamper in ["trap 'true' DEBUG", "trap - DEBUG"] {
        let (_out, stderr, _inv, sentinel_dir) = run_with_sentinels(
            &format!(
                r#"
{tamper}
sh -c 'touch {{sentinels}}/after_trap_theft' BLOCK_TOKEN-trap-theft
"#
            ),
            &[
                ("TIRITH_BASH_MODE", "preexec"),
                ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
            ],
        );
        assert!(
            stderr.contains("protection is OFF for this shell")
                && stderr.contains("replaced or removed Tirith's DEBUG trap"),
            "{tamper:?} must announce the loss of interception, got: {stderr}"
        );
        let _ = fs::remove_dir_all(&sentinel_dir);
    }
}

#[test]
fn losing_the_trap_is_announced_even_after_an_earlier_warn_only_downgrade() {
    // Two degrade tiers, two banners. A session that already dropped to
    // warn-only (and consumed that latch) and THEN loses its DEBUG trap goes
    // from "warns" to "nothing", which is the transition a user most needs to
    // hear about. A shared latch made it the one that stayed silent.
    let (_out, stderr, _inv, sentinel_dir) = run_with_sentinels(
        r#"
echo BADRC_TOKEN-first
trap 'true' DEBUG
echo BLOCK_TOKEN-after-theft
"#,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );
    assert!(
        stderr.contains("protection downgraded to warn-only"),
        "the first degrade must still print its banner: {stderr}"
    );
    assert!(
        stderr.contains("protection is OFF for this shell"),
        "the later loss of the trap must print ITS banner too: {stderr}"
    );
    let _ = fs::remove_dir_all(&sentinel_dir);
}

#[test]
fn warn_only_scan_falls_back_to_a_plain_check_when_the_receipt_path_fails() {
    // In warn-only mode the receipt-enabled check writes its stdout to a
    // capture file, so when that path fails the user has seen nothing and the
    // command runs anyway. The plain scan is the only thing the mode offers;
    // it must still happen, and the receipt loss must be said once.
    let (_out, stderr, invocations, sentinel_dir) = run_with_sentinels(
        r#"
# Pretend the startup probe negotiated protocol 3 with a valid parent context,
# then hand the receipt path a fake tirith that returns no receipt frame.
_TIRITH_RECEIPT_PROTOCOL=3
_TIRITH_PREEXEC_RECEIPTS_TRUSTED=1
_TIRITH_RECEIPT_SHELL_PID=$$
echo WARN_TOKEN-fallback
"#,
        &[("TIRITH_BASH_MODE", "preexec")],
    );
    assert!(
        invocations
            .iter()
            .any(|i| i.contains("--execution-receipt") && i.contains("WARN_TOKEN-fallback")),
        "the receipt-enabled check must have been attempted first: {invocations:#?}"
    );
    assert!(
        invocations
            .iter()
            .any(|i| i.contains("--warn-only") && i.contains("WARN_TOKEN-fallback")),
        "a failed receipt path must fall back to a plain warn-only scan: {invocations:#?}"
    );
    assert!(
        stderr.contains("execution receipts unavailable"),
        "the receipt loss must be announced: {stderr}"
    );
    let _ = fs::remove_dir_all(&sentinel_dir);
}

#[test]
fn reinstalling_the_tirith_trampoline_is_not_treated_as_a_loss() {
    // Idempotent re-installation, and any wrapper that chains through
    // `_tirith_debug_trampoline`, keep the heartbeat alive. Neither is tampering.
    let (_out, stderr, invocations, sentinel_dir) = run_with_sentinels(
        r#"
trap '_tirith_debug_trampoline' DEBUG
sh -c 'touch {sentinels}/reinstall_leak' BLOCK_TOKEN-reinstall
"#,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );
    assert!(
        !stderr.contains("protection is OFF for this shell"),
        "re-installing Tirith's own trampoline must not report a lost trap, got: {stderr}"
    );
    assert!(
        !sentinel_path(&sentinel_dir, "reinstall_leak").exists(),
        "enforcement must survive an idempotent re-install; invocations: {invocations:#?}"
    );
    let _ = fs::remove_dir_all(&sentinel_dir);
}

#[test]
fn extdebug_left_alone_when_user_enabled_it_first() {
    let hook = hook_path();
    let (_out, stderr, _inv) = run_bash_script(
        format!(
            r#"
shopt -s extdebug
source '{hook}'
printf 'OWNS=%s PROT=%s STATUS=%s ENFORCE=%s\n' \
  "$_TIRITH_OWNS_EXTDEBUG" "$TIRITH_BASH_EFFECTIVE_PROTECTION" \
  "$TIRITH_STATUS" "$_TIRITH_PREEXEC_ENFORCE" >&2
if shopt -q extdebug; then printf 'EXTDEBUG=on\n' >&2; else printf 'EXTDEBUG=off\n' >&2; fi
            "#
        )
        .as_str(),
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );
    assert!(
        stderr.contains("OWNS=0 PROT=off STATUS=degraded ENFORCE=0")
            && stderr.contains("EXTDEBUG=on")
            && stderr.contains("extdebug is already user-enabled"),
        "tirith must preserve user extdebug and refuse interception visibly, got: {stderr}"
    );
}

#[test]
fn mid_session_ignorespace_does_not_bypass_via_stale_cache() {
    // Attack shape: a clean command caches an allow keyed by the typed line, the
    // user enables HISTCONTROL=ignorespace, then a leading-space `curl
    // BLOCK_TOKEN` is filtered out of history so history_index doesn't advance.
    // The hook must detect drift and block. Both the fake `curl` (by drift
    // detection) and the downstream `&& touch` (by the LINENO-keyed cross-path
    // pin) must be skipped.
    let tmpdir = tempfile::tempdir().unwrap();
    let bin_dir = tmpdir.path().join("bin");
    let log_path = tmpdir.path().join("tirith.log");
    install_fake_tirith(&bin_dir, &log_path);

    let curl_sentinel = tmpdir.path().join("curl_actually_ran");
    let touch_sentinel = tmpdir.path().join("downstream_touch_ran");
    let curl_script = format!(
        "#!/bin/bash\ntouch {}\n",
        shell_escape(curl_sentinel.to_string_lossy().as_ref())
    );
    fs::write(bin_dir.join("curl"), curl_script).unwrap();
    fs::set_permissions(bin_dir.join("curl"), fs::Permissions::from_mode(0o755)).unwrap();

    let hook = hook_path();
    let script = format!(
        "source '{hook}'\n\
         echo first_clean_one\n\
         export HISTCONTROL=ignorespace\n\
         \x20curl BLOCK_TOKEN-bypass && touch {touch}\n",
        touch = touch_sentinel.display()
    );

    let mut child = Command::new("bash")
        .args(["--norc", "--noprofile", "-i"])
        .env_clear()
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("XDG_STATE_HOME", tmpdir.path())
        .env("TIRITH_BASH_MODE", "preexec")
        .env("TIRITH_BASH_PREEXEC_ENFORCE", "1")
        .env_remove("_TIRITH_BASH_LOADED")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    assert!(
        !curl_sentinel.exists(),
        "filtered curl must not bypass enforcement via stale-index cache; stderr: {stderr}"
    );
    assert!(
        !touch_sentinel.exists(),
        "downstream segment of drift-blocked line must also be skipped \
         (LINENO-keyed cross-path pin); stderr: {stderr}"
    );
    assert!(
        stderr.contains("bash history no longer matches BASH_COMMAND"),
        "expected drift banner on bypass attempt, got: {stderr}"
    );
}

#[test]
fn warn_only_does_not_dedupe_identical_commands_across_prompts() {
    // Warn-only previously deduped against `_tirith_last_cmd` across prompts; with
    // the per-typed-line cache key, each prompt gets its own scan even for
    // identical text. Runs under hostile HISTCONTROL=ignorespace to hit the
    // install-time-degraded warn-only branch.
    let (_out, _err, invocations, _tmp) = run_with_sentinels(
        r#"
 echo repeated_cmd
 echo repeated_cmd
"#,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
            ("HISTCONTROL", "ignorespace"),
        ],
    );

    let scan_count = invocations
        .iter()
        .filter(|i| i.contains("--warn-only") && i.contains("repeated_cmd"))
        .count();
    assert!(
        scan_count >= 2,
        "warn-only must scan each prompt's repeated command (got {scan_count}); \
         invocations: {invocations:#?}"
    );
    let _ = fs::remove_dir_all(&_tmp);
}

#[test]
fn install_time_hostile_config_uses_bash_command_for_warn_only() {
    // When enforcement is refused at install time (hostile history), the
    // warn-only scan target must be BASH_COMMAND, not the stale history_line —
    // else DETECTED banners reference whatever history entry 1 surfaces.
    let (_out, _err, invocations, _tmp) = run_with_sentinels(
        r#"
 echo from_user_command
"#,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
            ("HISTCONTROL", "ignorespace"),
        ],
    );

    // The warn-only target is the actual user command, not stale history entry 1.
    assert!(
        invocations
            .iter()
            .any(|i| i.contains("--warn-only") && i.contains("from_user_command")),
        "warn-only scan must target BASH_COMMAND under hostile install-time config; \
         invocations: {invocations:#?}"
    );
}

#[test]
fn post_degrade_warn_only_scans_bash_command_not_history() {
    // After a BADRC degrade, the warn-only path passes BASH_COMMAND to tirith,
    // not the stale history_line.
    let (_out, _err, invocations, _tmp) = run_with_sentinels(
        r#"
echo BADRC_TOKEN-drop
echo post_scan_target
"#,
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );

    // The post-degrade invocation should see `echo post_scan_target` with `--warn-only`.
    let post_warn_only_invocations: Vec<&String> = invocations
        .iter()
        .filter(|i| i.contains("--warn-only") && i.contains("post_scan_target"))
        .collect();
    assert!(
        !post_warn_only_invocations.is_empty(),
        "post-degrade invocation missing --warn-only + BASH_COMMAND target; got: {invocations:#?}"
    );
}

// === Enter-mode capability cache — mode-decision sharp edges (issue #111) ===
//
// The hook reads `bash-enter-capability` at startup to decide enter-vs-preexec.
// `TIRITH_BASH_EFFECTIVE_MODE` is set during sourcing, so reading it does not
// depend on `bind -x` *delivery* — but it does depend on `bind -x` *installing*:
// on enter mode the hook binds `\C-m` then health-checks via `bind -X`, and
// macOS bash 3.2 does NOT honour `bind -x` here, so the gate degrades to preexec.
//
// These tests verify the cache *reader*, not bind-x viability, so the
// `EFFMODE=<enter>` ones pass `_TIRITH_TEST_SKIP_HEALTH=1` (the test-only gate
// bypass) to stay green on bash 3.2; real delivery is the PTY harness's job.
// Preexec-fallback tests (`broken`/`absent`/`stale`) need no override.
//
// They also pin the reader against the bash history configs that historically
// perturbed the hook (HISTCONTROL/HISTIGNORE/HISTTIMEFORMAT/pre-set IFS/extdebug)
// — none affect a file read, but the reader uses `wc` and an `IFS='='` loop.

/// The hook's test-only switch bypassing `_tirith_startup_health_check` (see
/// `_TIRITH_TEST_SKIP_HEALTH` in `bash-hook.bash`), so capability-cache tests
/// verify mode resolution without needing `bind -x` to install (bash 3.2).
///
/// CRITICAL: must be delivered as a session-local shell variable, never an env
/// var — the hook unsets any EXPORTED `_TIRITH_TEST_*` (treating it as
/// attacker-controllable). `split_test_env` enforces this.
const SKIP_HEALTH: (&str, &str) = ("_TIRITH_TEST_SKIP_HEALTH", "1");

/// Split `extra_env` into a session-local shell prelude (`_TIRITH_TEST_*`, which
/// must be session-local — see [`SKIP_HEALTH`]) and real process env vars.
/// Mirrors `split_test_env` in `bash_hook_exports.rs`.
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

/// `($BASH_VERSION, $BASH)` for the bash a bare `Command::new("bash")` runs. The
/// capability cache is keyed on both, so a seeded cache must record the exact
/// values the spawned bash reports.
/// Major version of the bash a bare `Command::new("bash")` runs. The DEBUG-trap
/// tests that depend on bash >= 5 semantics use this to skip on the macOS
/// runner's system bash 3.2, the same way the PTY suite gates on `modern_bash`.
fn spawned_bash_major() -> u32 {
    let (version, _) = spawned_bash_identity();
    version
        .split('.')
        .next()
        .and_then(|major| major.parse().ok())
        .unwrap_or(0)
}

fn spawned_bash_identity() -> (String, String) {
    let out = Command::new("bash")
        .args(["-c", "printf '%s\\n%s' \"$BASH_VERSION\" \"$BASH\""])
        .output()
        .expect("query bash identity");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines();
    let version = lines.next().unwrap_or_default().trim().to_string();
    let path = lines.next().unwrap_or_default().trim().to_string();
    (version, path)
}

/// Build a `bash-enter-capability` cache file under `state_dir/tirith` for the
/// running bash, with the given verdict. `state_dir` must match the
/// `XDG_STATE_HOME` passed to the shell.
fn seed_capability_cache(state_dir: &Path, verdict: &str) {
    let (bash_version, bash_path) = spawned_bash_identity();
    let cache_dir = state_dir.join("tirith");
    fs::create_dir_all(&cache_dir).unwrap();
    // Schema 2 mirrors cli::bash_capability::CACHE_SCHEMA and binds the bash
    // binary's mtime+size fingerprint (repo-0211). Blank tirith_version: the
    // hook only enforces a version match when a sibling `.hooks-version`
    // exists, which the assets/ hook lacks.
    let fingerprint = bash_fingerprint(&bash_path);
    let body = format!(
        "schema=2\ntirith_version=\nshell=bash\nbash_version={bash_version}\n\
         bash_path={bash_path}\nbash_fingerprint={fingerprint}\n\
         enter_capability={verdict}\nreason=seeded by test\n"
    );
    fs::write(cache_dir.join("bash-enter-capability"), body).unwrap();
}

/// mtime-secs:size fingerprint, matching cli::bash_capability (repo-0211).
fn bash_fingerprint(bash_path: &str) -> String {
    let meta = std::fs::metadata(bash_path).expect("stat bash");
    let secs = meta
        .modified()
        .expect("mtime")
        .duration_since(std::time::UNIX_EPOCH)
        .expect("epoch")
        .as_secs();
    format!("{secs}:{}", meta.len())
}

/// Run the hook in a fresh interactive bash with `XDG_STATE_HOME` at a temp dir,
/// optionally seeding the capability cache first. Returns `(stdout, stderr)`.
///
/// `source` and the mode `printf` are kept on ONE readline unit: once enter mode
/// installs its `bind -x` Enter override, a subsequent stdin line would be
/// swallowed in this non-PTY shell, so the report must be on the line already
/// accepted before `bind -x` existed.
fn run_hook_with_capability(verdict: Option<&str>, env_vars: &[(&str, &str)]) -> (String, String) {
    // `TempDir` (not `.keep()`) so the dir is removed on return.
    let state = tempfile::tempdir().unwrap();
    let state_path = state.path();
    if let Some(v) = verdict {
        seed_capability_cache(state_path, v);
    }

    let hook = hook_path();
    // `_TIRITH_TEST_*` overrides must be session-local (see `split_test_env`);
    // the prelude is on the same physical line as `source`.
    let (prelude, real_env) = split_test_env(env_vars);
    let full_script = format!(
        "{prelude}source '{hook}'; printf 'EFFMODE=<%s>\\n' \"$TIRITH_BASH_EFFECTIVE_MODE\"\n"
    );

    let bin_dir = state_path.join("fakebin");
    let log_path = state_path.join("tirith.log");
    install_fake_tirith(&bin_dir, &log_path);

    let mut cmd = Command::new("bash");
    cmd.args(["--norc", "--noprofile", "-i"])
        .env_clear()
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("XDG_STATE_HOME", state_path)
        .env_remove("TIRITH_BASH_MODE")
        .env_remove("TIRITH_BASH_PREEXEC_ENFORCE")
        .env_remove("SSH_CONNECTION")
        .env_remove("SSH_TTY")
        .env_remove("SSH_CLIENT")
        .env_remove("_TIRITH_BASH_LOADED")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in &real_env {
        cmd.env(k, v);
    }

    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(full_script.as_bytes())
        .unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();

    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn capability_works_cache_selects_enter_mode() {
    // A fresh `works` verdict selects enter mode. `SKIP_HEALTH` bypasses the
    // health gate so this holds on any bash (incl. bash 3.2).
    let (stdout, _stderr) = run_hook_with_capability(Some("works"), &[SKIP_HEALTH]);
    assert!(
        stdout.contains("EFFMODE=<enter>"),
        "a fresh `works` capability cache must select enter mode, stdout: {stdout}"
    );
}

#[test]
fn capability_broken_cache_falls_back_to_preexec() {
    let (stdout, _stderr) = run_hook_with_capability(Some("broken"), &[]);
    assert!(
        stdout.contains("EFFMODE=<preexec>"),
        "a `broken` capability cache must fall back to preexec, stdout: {stdout}"
    );
}

#[test]
fn capability_absent_cache_falls_back_to_preexec() {
    let (stdout, _stderr) = run_hook_with_capability(None, &[]);
    assert!(
        stdout.contains("EFFMODE=<preexec>"),
        "with no capability cache the hook must fall back to preexec, stdout: {stdout}"
    );
}

#[test]
fn capability_cache_read_survives_hostile_histcontrol() {
    // HISTCONTROL=ignorespace gates preexec enforcement but must not affect the
    // capability-cache read: a `works` verdict still selects enter.
    let (stdout, _stderr) = run_hook_with_capability(
        Some("works"),
        &[("HISTCONTROL", "ignorespace"), SKIP_HEALTH],
    );
    assert!(
        stdout.contains("EFFMODE=<enter>"),
        "HISTCONTROL must not perturb the capability-cache mode decision, stdout: {stdout}"
    );
}

#[test]
fn capability_cache_read_survives_histignore() {
    let (stdout, _stderr) =
        run_hook_with_capability(Some("works"), &[("HISTIGNORE", "ls:cd:pwd"), SKIP_HEALTH]);
    assert!(
        stdout.contains("EFFMODE=<enter>"),
        "HISTIGNORE must not perturb the capability-cache mode decision, stdout: {stdout}"
    );
}

#[test]
fn capability_cache_read_survives_histtimeformat_and_preset_ifs() {
    // The reader sets `IFS` locally per-read, so a pre-set `IFS`/`HISTTIMEFORMAT`
    // must not break its `IFS='='` loop / `wc`.
    let (stdout, _stderr) = run_hook_with_capability(
        Some("works"),
        &[("HISTTIMEFORMAT", "%F %T "), ("IFS", ":"), SKIP_HEALTH],
    );
    assert!(
        stdout.contains("EFFMODE=<enter>"),
        "a pre-set IFS / HISTTIMEFORMAT must not break the cache reader, stdout: {stdout}"
    );
}

#[test]
fn capability_cache_decision_independent_of_preset_extdebug() {
    // A user-enabled `extdebug` must not change the decision (passed via BASHOPTS,
    // which bash applies at startup).
    let (stdout, _stderr) =
        run_hook_with_capability(Some("works"), &[("BASHOPTS", "extdebug"), SKIP_HEALTH]);
    assert!(
        stdout.contains("EFFMODE=<enter>"),
        "a pre-enabled extdebug must not change the capability decision, stdout: {stdout}"
    );
}

#[test]
fn capability_cache_read_survives_set_plus_o_history() {
    // `set +o history` before sourcing must not change the decision — the reader
    // does not touch history. `TempDir` (not `.keep()`) cleans up on return.
    let state = tempfile::tempdir().unwrap();
    let state_path = state.path();
    seed_capability_cache(state_path, "works");

    let hook = hook_path();
    // Disable history first, then set the session-local skip override + source +
    // report on one line (so enter mode's `bind -x` cannot swallow the report).
    let (skip_key, skip_val) = SKIP_HEALTH;
    let full_script = format!(
        "set +o history\n\
         {skip_key}='{skip_val}'; source '{hook}'; \
         printf 'EFFMODE=<%s>\\n' \"$TIRITH_BASH_EFFECTIVE_MODE\"\n"
    );

    let bin_dir = state_path.join("fakebin");
    let log_path = state_path.join("tirith.log");
    install_fake_tirith(&bin_dir, &log_path);

    let mut cmd = Command::new("bash");
    cmd.args(["--norc", "--noprofile", "-i"])
        .env_clear()
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("XDG_STATE_HOME", state_path)
        .env_remove("TIRITH_BASH_MODE")
        .env_remove("TIRITH_BASH_PREEXEC_ENFORCE")
        .env_remove("SSH_CONNECTION")
        .env_remove("SSH_TTY")
        .env_remove("SSH_CLIENT")
        .env_remove("_TIRITH_BASH_LOADED")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(full_script.as_bytes())
        .unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("EFFMODE=<enter>"),
        "`set +o history` must not break the capability-cache mode decision, stdout: {stdout}"
    );
}

#[test]
fn capability_broken_cache_with_preexec_enforce_still_blocks() {
    // #111 fallback: with no `works` cache the hook drops to preexec, and
    // `TIRITH_BASH_PREEXEC_ENFORCE=1` makes that preexec block.
    let (_stdout, _stderr, _invocations, sentinel_dir) = run_with_sentinels(
        "touch {sentinels}/should_not_exist_BLOCK_TOKEN\n",
        &[("TIRITH_BASH_PREEXEC_ENFORCE", "1")],
    );
    // run_bash has no capability cache → preexec fallback → enforcement blocks.
    let blocked = sentinel_path(&sentinel_dir, "should_not_exist_BLOCK_TOKEN");
    assert!(
        !blocked.exists(),
        "with no `works` cache + enforce=1, a blocked command must not execute"
    );
    let _ = fs::remove_dir_all(&sentinel_dir);
}

#[test]
fn capability_stale_cache_falls_back_and_installs_debug_trap() {
    // A stale `works` verdict (wrong bash version) forces the preexec fallback,
    // which must still install the DEBUG trap. `TempDir` cleans up on return.
    let state = tempfile::tempdir().unwrap();
    let state_path = state.path();
    // Seed `works` for a NON-running bash version (only the version is stale, so
    // the hook treats it as stale and falls back to preexec).
    let (_bash_version, bash_path) = spawned_bash_identity();
    let cache_dir = state_path.join("tirith");
    fs::create_dir_all(&cache_dir).unwrap();
    fs::write(
        cache_dir.join("bash-enter-capability"),
        format!(
            "schema=2\ntirith_version=\nshell=bash\nbash_version=0.0.0-stale\n\
             bash_path={bash_path}\nenter_capability=works\nreason=stale\n"
        ),
    )
    .unwrap();

    let hook = hook_path();
    // `source` + first report on one line, consistent with the other helpers.
    let full_script = format!(
        "source '{hook}'; printf 'EFFMODE=<%s>\\n' \"$TIRITH_BASH_EFFECTIVE_MODE\"\n\
         trap -p DEBUG | grep -q _tirith_debug_trampoline && \
           printf 'DEBUG_TRAP=installed\\n' || printf 'DEBUG_TRAP=missing\\n'\n"
    );

    let bin_dir = state_path.join("fakebin");
    let log_path = state_path.join("tirith.log");
    install_fake_tirith(&bin_dir, &log_path);

    let mut cmd = Command::new("bash");
    cmd.args(["--norc", "--noprofile", "-i"])
        .env_clear()
        .env("HOME", std::env::var("HOME").unwrap_or_default())
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("XDG_STATE_HOME", state_path)
        .env_remove("TIRITH_BASH_MODE")
        .env_remove("TIRITH_BASH_PREEXEC_ENFORCE")
        .env_remove("SSH_CONNECTION")
        .env_remove("SSH_TTY")
        .env_remove("SSH_CLIENT")
        .env_remove("_TIRITH_BASH_LOADED")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(full_script.as_bytes())
        .unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("EFFMODE=<preexec>"),
        "a stale `works` verdict (wrong bash version) must fall back to preexec, stdout: {stdout}"
    );
    assert!(
        stdout.contains("DEBUG_TRAP=installed"),
        "the preexec fallback must install the DEBUG trap, stdout: {stdout}"
    );
}
