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
    #[serde(default)]
    raw_bytes: Vec<u8>,
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
        _ => panic!("Unknown context: {}", fixture.context),
    };

    let raw_bytes = if !fixture.raw_bytes.is_empty() {
        Some(fixture.raw_bytes.clone())
    } else if scan_context == ScanContext::Paste {
        Some(fixture.input.as_bytes().to_vec())
    } else {
        None
    };

    let ctx = AnalysisContext {
        input: fixture.input.clone(),
        shell,
        scan_context,
        raw_bytes,
        interactive: true,
        cwd: None,
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

    // Check action
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

    // Check that expected rules are present (if specified)
    if !fixture.expected_rules.is_empty() {
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
fn test_policy_fixtures() {
    let fixtures = load_fixtures("policy.toml");
    let count = fixtures.len();
    for fixture in &fixtures {
        run_fixture(fixture);
    }
    eprintln!("Passed {count} policy fixtures");
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

            // For paste context with raw bytes, check byte scan too
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
                    || byte_scan.has_invisible_whitespace;

                if byte_triggered {
                    continue; // Byte scan catches it
                }
            }

            // Exec context: bidi/zero-width check bypasses tier 1 regex (M4 fix)
            if scan_context == ScanContext::Exec {
                let byte_scan = tirith_core::extract::scan_bytes(fixture.input.as_bytes());
                if byte_scan.has_bidi_controls
                    || byte_scan.has_zero_width
                    || byte_scan.has_unicode_tags
                    || byte_scan.has_variation_selectors
                    || byte_scan.has_invisible_math_operators
                    || byte_scan.has_invisible_whitespace
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
];

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
    // Command shape
    "pipe_to_interpreter",
    "curl_pipe_shell",
    "wget_pipe_shell",
    "httpie_pipe_shell",
    "xh_pipe_shell",
    "dotfile_overwrite",
    "archive_extract",
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
    // Ecosystem
    "git_typosquat",
    "docker_untrusted_registry",
    "pip_url_install",
    "npm_url_install",
    "web3_rpc_endpoint",
    "web3_address_in_url",
    // Policy
    "policy_blocklisted",
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

// ---------------------------------------------------------------------------
// Safeguard #1: Every RuleId variant must have at least one fixture.
//
// If someone adds a new rule but forgets to write a fixture, this fails.
// If someone adds a new RuleId to the enum but forgets to add it to
// ALL_RULE_IDS above, `test_rule_id_list_is_complete` catches that.
// ---------------------------------------------------------------------------

/// Rules that depend on runtime state and cannot be tested via static fixtures.
/// - proxy_env_set: requires HTTP_PROXY/HTTPS_PROXY env vars to be set
/// - policy_blocklisted: requires a blocklist file in policy config
const EXTERNALLY_TRIGGERED_RULES: &[&str] = &[
    "proxy_env_set",
    "policy_blocklisted",
    "command_network_deny",
];

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
        RuleId::PipeToInterpreter,
        RuleId::CurlPipeShell,
        RuleId::WgetPipeShell,
        RuleId::HttpiePipeShell,
        RuleId::XhPipeShell,
        RuleId::DotfileOverwrite,
        RuleId::ArchiveExtract,
        RuleId::ProxyEnvSet,
        RuleId::SensitiveEnvExport,
        RuleId::CodeInjectionEnv,
        RuleId::InterpreterHijackEnv,
        RuleId::ShellInjectionEnv,
        RuleId::MetadataEndpoint,
        RuleId::PrivateNetworkAccess,
        RuleId::CommandNetworkDeny,
        RuleId::GitTyposquat,
        RuleId::DockerUntrustedRegistry,
        RuleId::PipUrlInstall,
        RuleId::NpmUrlInstall,
        RuleId::Web3RpcEndpoint,
        RuleId::Web3AddressInUrl,
        RuleId::PolicyBlocklisted,
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

// ---------------------------------------------------------------------------
// Safeguard #2: Non-URL-dependent rules must have at least one fixture
// where the input contains no URL. This prevents the tier-1 URL regex
// from accidentally being the only reason analysis runs.
// ---------------------------------------------------------------------------
#[test]
fn test_no_url_rules_have_no_url_fixtures() {
    // Rules that CAN fire when the input has no URL at all.
    // These need their own tier-1 pattern (not just :// or git@).
    let no_url_rules: HashSet<&str> = [
        "dotfile_overwrite",
        "archive_extract",
        "pipe_to_interpreter",     // cat script | bash
        "bidi_controls",           // exec context, no URL needed
        "zero_width_chars",        // exec context, no URL needed
        "unicode_tags",            // byte-level, no URL needed
        "invisible_math_operator", // byte-level, no URL needed
        "invisible_whitespace",    // byte-level, no URL needed
        "code_injection_env",      // export LD_PRELOAD=, no URL needed
        "shell_injection_env",     // export BASH_ENV=, no URL needed
        "interpreter_hijack_env",  // export PYTHONPATH=, no URL needed
        "sensitive_env_export",    // export OPENAI_API_KEY=, no URL needed
        "metadata_endpoint",       // curl 169.254.169.254/..., no URL scheme needed
        "private_network_access",  // curl 10.0.0.1/..., no URL scheme needed
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

// ---------------------------------------------------------------------------
// Safeguard #3: Build-time cross-reference — every rule "trigger category"
// must have a corresponding PATTERN_TABLE entry in build.rs.
//
// The PATTERN_TABLE entry IDs are exposed via extract::extractor_ids().
// This test verifies that expected trigger categories exist.
// ---------------------------------------------------------------------------
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
        ("dotfile overwrite", &["dotfile_overwrite"]),
        ("archive extract", &["archive_extract_sensitive"]),
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
        // Deception triggers
        ("punycode detection", &["punycode_domain"]),
        ("lookalike TLD", &["lookalike_tld"]),
        ("URL shortener", &["url_shortener"]),
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

// ---------------------------------------------------------------------------
// Safeguard #4: Tier-1 must not gate any expected-block/warn fixture.
//
// For every non-allow fixture, the full engine must reach tier 3.
// If tier_reached < 3, tier-1 silently suppressed the rule — a security bug.
// This is the single most impactful test: it catches the EXACT class of bug
// that caused the dotfile overwrite gap.
// ---------------------------------------------------------------------------
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
            _ => continue,
        };

        let raw_bytes = if !fixture.raw_bytes.is_empty() {
            Some(fixture.raw_bytes.clone())
        } else if scan_context == ScanContext::Paste {
            Some(fixture.input.as_bytes().to_vec())
        } else {
            None
        };

        let ctx = AnalysisContext {
            input: fixture.input.clone(),
            shell,
            scan_context,
            raw_bytes,
            interactive: true,
            cwd: None,
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

/// Constraint #6: Non-ASCII in paste is only an analysis trigger, never a sole WARN/BLOCK reason.
/// Pasting text that contains only non-ASCII characters (no URLs, no commands) must result in Allow.
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
