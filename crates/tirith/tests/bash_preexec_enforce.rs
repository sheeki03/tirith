//! Phase 1 tests for the bash hook's preexec enforcement path.
//!
//! These tests drive an interactive bash subshell with a fake `tirith` binary
//! on PATH that records its invocations and returns exit codes based on input
//! pattern. The hook is sourced, user commands are fed via a here-doc, and we
//! assert on side effects (sentinel files that a blocked command would have
//! created) plus the invocation log from the fake tirith.

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

/// Build a fake tirith binary that writes its args to `log_path` and exits
/// with a code determined by the input:
///  - contains `BLOCK_TOKEN`  → exit 1
///  - contains `WARN_TOKEN`   → exit 2
///  - contains `BADRC_TOKEN`  → exit 99
///  - else                    → exit 0
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

/// Run a bash script against the hook with enforcement controls. Returns
/// (stdout, stderr, tirith_invocations).
fn run_bash(script: &str, env_vars: &[(&str, &str)]) -> (String, String, Vec<String>) {
    let tmpdir = tempfile::tempdir().unwrap();
    let bin_dir = tmpdir.path().join("bin");
    let log_path = tmpdir.path().join("tirith.log");
    install_fake_tirith(&bin_dir, &log_path);

    let hook = hook_path();
    let full_script = format!("source '{hook}'\n{script}\n");

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
        .write_all(full_script.as_bytes())
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

// ─── Enforcement-on: block path ────────────────────────────────────

#[test]
fn enforce_blocks_bare_command_with_rc1() {
    let (_out, _err, invocations, sentinel_dir) = run_with_sentinels(
        r#"
# Each command is a separate prompt cycle so history advances normally.
curl BLOCK_TOKEN-one && touch {sentinels}/should_not_exist
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
    // curl triggers a block; the downstream `sh` segment must also not run.
    let (_out, _err, invocations, sentinel_dir) = run_with_sentinels(
        r#"
curl BLOCK_TOKEN-pipe | sh -c 'touch {sentinels}/pipe_leaked'
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
    // `ls ; curl BLOCK` — when the second segment blocks, the whole line must
    // skip. The cache key is the same history index, so both DEBUG fires
    // return 1.
    let (_out, _err, invocations, sentinel_dir) = run_with_sentinels(
        r#"
ls / >/dev/null && touch {sentinels}/ls_ran; curl BLOCK_TOKEN-seq && touch {sentinels}/curl_ran
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

// ─── Enforcement-on: allow / warn paths ────────────────────────────

#[test]
fn enforce_allows_clean_commands() {
    let (_out, _err, invocations, sentinel_dir) = run_with_sentinels(
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
    let _ = fs::remove_dir_all(&sentinel_dir);
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

// ─── Enforcement-on: unexpected-rc degrade ─────────────────────────

#[test]
fn unexpected_rc_blocks_then_degrades_session() {
    let (_out, stderr, _inv, sentinel_dir) = run_with_sentinels(
        r#"
echo BADRC_TOKEN-first && touch {sentinels}/badrc_ran
echo post_degrade && touch {sentinels}/post_ran
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
    let _ = fs::remove_dir_all(&sentinel_dir);
}

// ─── Install-time hostile-history detection ────────────────────────

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

    // With ignorespace set at install, enforcement is refused and the session
    // stays warn-only. A block rc from tirith is NOT enforced.
    assert!(
        sentinel_path(&sentinel_dir, "ran_anyway").exists(),
        "warn-only must allow the command to run even if tirith returns 1"
    );
    assert!(
        stderr.contains("cannot enable preexec enforcement"),
        "expected install-time refusal message, got: {stderr}"
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
    assert!(stderr.contains("cannot enable preexec enforcement"));
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
    assert!(stderr.contains("cannot enable preexec enforcement"));
    let _ = fs::remove_dir_all(&sentinel_dir);
}

// ─── Enforcement-off (default): warn-only preserved ────────────────

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

// ─── Effective-state exports ───────────────────────────────────────

#[test]
fn enforcement_exports_blocks_protection() {
    let (_out, stderr, _inv, _tmp) = run_with_sentinels(
        r#"
printf 'PROT=%s\n' "$TIRITH_BASH_EFFECTIVE_PROTECTION" >&2
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
    let _ = fs::remove_dir_all(&_tmp);
}

#[test]
fn hostile_config_exports_warn_only() {
    let (_out, stderr, _inv, _tmp) = run_with_sentinels(
        r#"
printf 'PROT=%s\n' "$TIRITH_BASH_EFFECTIVE_PROTECTION" >&2
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
    let _ = fs::remove_dir_all(&_tmp);
}

// ─── DEBUG trap chaining ───────────────────────────────────────────

#[test]
fn debug_trap_chains_user_trap() {
    // User installs a DEBUG trap BEFORE sourcing the hook. Tirith must wrap,
    // not clobber it.
    let (_out, stderr, _inv, _tmp) = run_with_sentinels(
        r#"
USER_TRAP_COUNT=0
trap 'USER_TRAP_COUNT=$((USER_TRAP_COUNT + 1))' DEBUG
# Re-source hook AFTER the user's DEBUG trap so we verify the wrap path.
unset _TIRITH_BASH_LOADED
source '__HOOK__'
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
    // The user's trap must have fired at least twice (once per echo command).
    // The exact count can be higher due to DEBUG firing on sub-expressions.
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

// ─── extdebug ownership ────────────────────────────────────────────

#[test]
fn extdebug_left_alone_when_user_enabled_it_first() {
    let (_out, stderr, _inv, _tmp) = run_with_sentinels(
        r#"
shopt -s extdebug
unset _TIRITH_BASH_LOADED
source '__HOOK__'
printf 'OWNS=%s\n' "$_TIRITH_OWNS_EXTDEBUG" >&2
"#
        .replace("__HOOK__", &hook_path())
        .as_str(),
        &[
            ("TIRITH_BASH_MODE", "preexec"),
            ("TIRITH_BASH_PREEXEC_ENFORCE", "1"),
        ],
    );
    assert!(
        stderr.contains("OWNS=0"),
        "tirith must not claim ownership of user-enabled extdebug, got: {stderr}"
    );
}

// ─── Mid-session HISTCONTROL bypass (regression for P1 review finding) ──

#[test]
fn mid_session_ignorespace_does_not_bypass_via_stale_cache() {
    // Reproducer for the P1 manual-review finding: with enforcement on,
    // (1) a clean command produces a cached allow keyed by the current
    // line, then (2) the user enables HISTCONTROL=ignorespace, then (3) a
    // leading-space `curl BLOCK_TOKEN-...` is filtered out of history, so
    // history_index does not advance. The hook MUST detect drift before
    // honoring the cache and block the new command instead of returning
    // the cached allow.
    //
    // We install a fake `curl` shim and a downstream `&& touch` segment.
    // Both must be skipped — the curl by drift-detection, the touch by
    // the LINENO-keyed cross-path pin so the rest of the same typed line
    // stays blocked even though the session has flipped to warn-only.
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
    // Regression for the P3 manual-review finding: in warn-only mode the
    // hook used to dedupe against `_tirith_last_cmd` regardless of which
    // prompt it came from, so running the same command twice in a row only
    // produced a single tirith invocation. With the per-typed-line cache
    // key folded in, each prompt should get its own scan even if the
    // command text is identical.
    //
    // Ran under install-time-hostile HISTCONTROL=ignorespace so the path
    // exercised is the install-time-degraded warn-only branch (the same
    // one the reviewer reproduced).
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
    // Regression for the P2 review finding: when enforcement is refused at
    // install time because history is hostile, the warn-only scan target must
    // be BASH_COMMAND (not the stale history_line). Otherwise the DETECTED
    // banners reference whatever history 1 happens to surface, which is by
    // construction not what the user just ran.
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

    // Tirith was invoked in warn-only mode and its target was the actual user
    // command, not whatever stale entry history 1 returned.
    assert!(
        invocations
            .iter()
            .any(|i| i.contains("--warn-only") && i.contains("from_user_command")),
        "warn-only scan must target BASH_COMMAND under hostile install-time config; \
         invocations: {invocations:#?}"
    );
}

// ─── Warn-only post-degrade scan target ────────────────────────────

#[test]
fn post_degrade_warn_only_scans_bash_command_not_history() {
    // Trigger a degrade via BADRC, then run a new command. The degraded
    // warn-only path should pass BASH_COMMAND (which lacks any `| foo` tail)
    // to tirith rather than the stale history_line.
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

    // After degrade the warn-only scan uses BASH_COMMAND. The post-degrade
    // invocation should see `echo post_scan_target` as-is, and the fake
    // tirith should have been called with `--warn-only`.
    let post_warn_only_invocations: Vec<&String> = invocations
        .iter()
        .filter(|i| i.contains("--warn-only") && i.contains("post_scan_target"))
        .collect();
    assert!(
        !post_warn_only_invocations.is_empty(),
        "post-degrade invocation missing --warn-only + BASH_COMMAND target; got: {invocations:#?}"
    );
}
