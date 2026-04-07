//! Snapshot tests for `--help` output of all visible subcommands.
//! Uses `insta` for snapshot management.
//!
//! After intentional help text changes, run `cargo insta review` to accept.

use std::process::Command;

fn tirith() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tirith"))
}

fn snapshot_help(args: &[&str], name: &str) {
    let out = tirith().args(args).output().expect("failed to run tirith");
    let stdout = String::from_utf8_lossy(&out.stdout);
    insta::assert_snapshot!(name, stdout.to_string());
}

/// Generate a `#[test] fn help_<name>()` that snapshots `tirith <subcmd> --help`.
macro_rules! help_snapshot_tests {
    ( $( $(#[$meta:meta])* $name:ident => [ $($arg:expr),+ ] ; )+ ) => {
        $(
            $(#[$meta])*
            #[test]
            fn $name() {
                snapshot_help(&[$($arg),+], stringify!($name));
            }
        )+
    };
}

help_snapshot_tests! {
    help_root       => ["--help"];
    help_check      => ["check", "--help"];
    help_paste      => ["paste", "--help"];
    #[cfg(unix)]
    help_run        => ["run", "--help"];
    help_score      => ["score", "--help"];
    help_diff       => ["diff", "--help"];
    help_explain    => ["explain", "--help"];
    help_why        => ["why", "--help"];
    help_scan       => ["scan", "--help"];
    #[cfg(unix)]
    help_fetch      => ["fetch", "--help"];
    help_setup      => ["setup", "--help"];
    help_init       => ["init", "--help"];
    help_doctor     => ["doctor", "--help"];
    help_warnings   => ["warnings", "--help"];
    help_policy     => ["policy", "--help"];
    help_audit      => ["audit", "--help"];
    help_trust      => ["trust", "--help"];
    help_receipt    => ["receipt", "--help"];
    help_checkpoint => ["checkpoint", "--help"];
    help_threat_db  => ["threat-db", "--help"];
    help_daemon     => ["daemon", "--help"];
    help_gateway    => ["gateway", "--help"];
    help_license    => ["license", "--help"];
    help_mcp_server => ["mcp-server", "--help"];
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
    // --json alone should succeed (exit 0 = allow for a safe command)
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
// The URL is analyzed for homograph/punycode/shortener patterns, not fetched.

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
    // Compare non-dynamic fields
    assert_eq!(j1["url"], j2["url"]);
    assert_eq!(j1["score"], j2["score"]);
    assert_eq!(j1["risk_level"], j2["risk_level"]);
    assert_eq!(j1["findings"], j2["findings"]);
}

// --- Additional coverage tests ---

#[test]
fn format_human_explicit_matches_default() {
    // --format human should behave identically to no --format flag
    let out_default = tirith()
        .args(["check", "--", "echo", "hello"])
        .output()
        .unwrap();
    let out_explicit = tirith()
        .args(["check", "--format", "human", "--", "echo", "hello"])
        .output()
        .unwrap();
    assert_eq!(out_default.status.code(), out_explicit.status.code());
    // Both should produce no stdout (human output goes to stderr for check)
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
    // "zzzzz" is too far from any known tool
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
    // Verify --json + --format conflict on a different subcommand (not just check)
    let out = tirith()
        .args(["paste", "--json", "--format", "json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot be used with"));
}
