//! Help output and CLI regression tests.
//!
//! Verifies that all subcommands have examples in --help, that flag
//! conflicts are enforced, JSON envelopes are stable, and error
//! messages include corrective suggestions.

use std::process::Command;

fn tirith() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tirith"))
}

/// Verify a subcommand's --help contains an "Examples:" section with expected content.
fn assert_help_has_examples(args: &[&str], expected_substring: &str) {
    let out = tirith().args(args).output().expect("failed to run tirith");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Examples:"),
        "{args:?} --help should contain Examples section, got:\n{stdout}"
    );
    assert!(
        stdout.contains(expected_substring),
        "{args:?} --help should contain {expected_substring:?}, got:\n{stdout}"
    );
}

// --- Help examples exist on every subcommand ---

macro_rules! help_example_tests {
    ( $( $(#[$meta:meta])* $name:ident => ( [ $($arg:expr),+ ], $expected:expr ) ; )+ ) => {
        $(
            $(#[$meta])*
            #[test]
            fn $name() {
                assert_help_has_examples(&[$($arg),+], $expected);
            }
        )+
    };
}

help_example_tests! {
    help_check      => (["check", "--help"], "tirith check --format json");
    help_paste      => (["paste", "--help"], "tirith paste");
    #[cfg(unix)]
    help_run        => (["run", "--help"], "tirith run");
    help_score      => (["score", "--help"], "tirith score");
    help_diff       => (["diff", "--help"], "tirith diff");
    help_explain    => (["explain", "--help"], "tirith explain --rule");
    help_why        => (["why", "--help"], "tirith why");
    help_scan       => (["scan", "--help"], "tirith scan");
    #[cfg(unix)]
    help_fetch      => (["fetch", "--help"], "tirith fetch");
    help_setup      => (["setup", "--help"], "tirith setup claude-code");
    help_init       => (["init", "--help"], "tirith init --shell");
    help_doctor     => (["doctor", "--help"], "tirith doctor --fix");
    help_warnings   => (["warnings", "--help"], "tirith warnings");
    help_policy     => (["policy", "--help"], "tirith policy init");
    help_audit      => (["audit", "--help"], "tirith audit export");
    help_trust      => (["trust", "--help"], "tirith trust add");
    help_receipt    => (["receipt", "--help"], "tirith receipt");
    help_checkpoint => (["checkpoint", "--help"], "tirith checkpoint create");
    help_threat_db  => (["threat-db", "--help"], "tirith threat-db update");
    help_daemon     => (["daemon", "--help"], "tirith daemon start");
    help_gateway    => (["gateway", "--help"], "tirith gateway");
    help_license    => (["license", "--help"], "tirith license");
    help_mcp_server => (["mcp-server", "--help"], "tirith mcp-server");
}

#[test]
fn help_root_lists_subcommands() {
    let out = tirith().args(["--help"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Core subcommands are visible
    assert!(stdout.contains("check"));
    assert!(stdout.contains("scan"));
    assert!(stdout.contains("setup"));
    assert!(stdout.contains("doctor"));
    assert!(stdout.contains("mcp-server"));
    // hook-event should be hidden
    assert!(
        !stdout.contains("hook-event"),
        "hook-event should be hidden from top-level help"
    );
}

#[test]
fn help_check_shows_format_flag() {
    let out = tirith().args(["check", "--help"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--format"));
    assert!(stdout.contains("human, json"));
    // --json should be hidden
    assert!(
        !stdout.contains("  --json"),
        "--json should be hidden from help"
    );
}

#[test]
fn help_scan_shows_sarif_format() {
    let out = tirith().args(["scan", "--help"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("human, json, sarif"));
}

// --- Clap conflict behavior tests ---

#[test]
fn conflict_json_and_format() {
    let out = tirith()
        .args(["check", "--json", "--format", "json", "--", "echo", "hi"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "should fail on --json + --format conflict"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot be used with"),
        "should mention conflict: {stderr}"
    );
}

#[test]
fn conflict_warnings_summary_and_format() {
    let out = tirith()
        .args(["warnings", "--summary", "--format", "json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot be used with"));
}

#[test]
fn conflict_doctor_fix_and_format() {
    let out = tirith()
        .args(["doctor", "--fix", "--format", "json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot be used with"));
}

#[test]
fn conflict_doctor_reset_and_format() {
    let out = tirith()
        .args(["doctor", "--reset-bash-safe-mode", "--format", "json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot be used with"));
}

#[test]
fn conflict_scan_json_and_sarif() {
    let out = tirith()
        .args(["scan", "--json", "--sarif", "./"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot be used with"));
}

#[test]
fn json_alias_works_alone() {
    let out = tirith()
        .args(["check", "--json", "--", "echo", "hello"])
        .output()
        .unwrap();
    assert!(out.status.success(), "exit: {:?}", out.status.code());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("schema_version"),
        "should produce JSON: {stdout}"
    );
}

// --- Error message regression tests ---

#[test]
fn setup_unknown_tool_suggests() {
    let out = tirith().args(["setup", "claud-code"]).output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("did you mean: tirith setup claude-code"),
        "should suggest closest match: {stderr}"
    );
}

#[test]
fn init_unsupported_shell_suggests() {
    let out = tirith().args(["init", "--shell", "tcsh"]).output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("try:"),
        "should include try: suggestion: {stderr}"
    );
}

// --- JSON envelope stability ---
// Note: `tirith score` does local URL analysis only (no network call).

#[test]
fn json_envelope_check() {
    let out = tirith()
        .args(["check", "--format", "json", "--", "echo", "hello"])
        .output()
        .unwrap();
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("check --format json should produce valid JSON");
    assert_eq!(json["schema_version"], 3);
    assert!(json["action"].is_string());
    assert!(json["findings"].is_array());
    assert!(json["timings_ms"].is_object());
}

#[test]
fn json_envelope_score() {
    let out = tirith()
        .args(["score", "--format", "json", "https://example.com"])
        .output()
        .unwrap();
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("score --format json should produce valid JSON");
    assert!(json["url"].is_string());
    assert!(json["score"].is_number());
    assert!(json["risk_level"].is_string());
    assert!(json["findings"].is_array());
}

// --- Format equivalence ---
// `tirith score` is deterministic (local URL analysis, no network).

#[test]
fn format_json_and_json_flag_equivalent_score() {
    let out_flag = tirith()
        .args(["score", "--json", "https://example.com"])
        .output()
        .unwrap();
    let out_format = tirith()
        .args(["score", "--format", "json", "https://example.com"])
        .output()
        .unwrap();
    let j1: serde_json::Value = serde_json::from_slice(&out_flag.stdout).unwrap();
    let j2: serde_json::Value = serde_json::from_slice(&out_format.stdout).unwrap();
    assert_eq!(j1["url"], j2["url"]);
    assert_eq!(j1["score"], j2["score"]);
    assert_eq!(j1["risk_level"], j2["risk_level"]);
    assert_eq!(j1["findings"], j2["findings"]);
}

// --- Additional coverage tests ---

#[test]
fn format_human_explicit_matches_default() {
    let out_default = tirith()
        .args(["check", "--", "echo", "hello"])
        .output()
        .unwrap();
    let out_explicit = tirith()
        .args(["check", "--format", "human", "--", "echo", "hello"])
        .output()
        .unwrap();
    assert_eq!(out_default.status.code(), out_explicit.status.code());
    assert!(out_default.stdout.is_empty());
    assert!(out_explicit.stdout.is_empty());
}

#[test]
fn no_color_suppresses_ansi_in_check() {
    let out = tirith()
        .env("NO_COLOR", "1")
        .args([
            "check",
            "--format",
            "human",
            "--",
            "curl",
            "https://example.com/install.sh",
            "|",
            "bash",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("\x1b["),
        "NO_COLOR=1 should suppress all ANSI escape codes, got: {stderr}"
    );
}

#[test]
fn suggest_closest_no_match_for_distant_query() {
    let out = tirith().args(["setup", "zzzzz"]).output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("did you mean"),
        "should NOT suggest for distant queries: {stderr}"
    );
    assert!(stderr.contains("unknown tool"));
}

#[test]
fn paste_conflict_json_and_format() {
    let out = tirith()
        .args(["paste", "--json", "--format", "json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot be used with"));
}
