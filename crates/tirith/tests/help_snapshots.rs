//! Help output and CLI regression tests.
//!
//! Verifies that all subcommands have examples in --help, that flag
//! conflicts are enforced, JSON envelopes are stable, and error
//! messages include corrective suggestions.

use std::process::Command;

fn tirith() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tirith"))
}

/// Verify a subcommand's --help contains an "Examples:" section with expected content.
fn assert_help_has_examples(args: &[&str], expected_substring: &str) {
    let out = tirith().args(args).output().expect("failed to run tirith");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Examples:"),
        "{args:?} --help should contain Examples section, got:\n{stdout}"
    );
    assert!(
        stdout.contains(expected_substring),
        "{args:?} --help should contain {expected_substring:?}, got:\n{stdout}"
    );
}

macro_rules! help_example_tests {
    ( $( $(#[$meta:meta])* $name:ident => ( [ $($arg:expr),+ ], $expected:expr ) ; )+ ) => {
        $(
            $(#[$meta])*
            #[test]
            fn $name() {
                assert_help_has_examples(&[$($arg),+], $expected);
            }
        )+
    };
}

help_example_tests! {
    help_check      => (["check", "--help"], "tirith check --format json");
    help_paste      => (["paste", "--help"], "tirith paste");
    #[cfg(unix)]
    help_run        => (["run", "--help"], "tirith run");
    help_install    => (["install", "--help"], "tirith install npm left-pad");
    help_score      => (["score", "--help"], "tirith score");
    help_score_explain => (["score", "--help"], "tirith score --explain");
    help_policy_tune => (["policy", "tune", "--help"], "tirith policy tune --from-audit");
    help_diff       => (["diff", "--help"], "tirith diff");
    help_explain    => (["explain", "--help"], "tirith explain --rule");
    help_why        => (["why", "--help"], "tirith why");
    help_scan       => (["scan", "--help"], "tirith scan");
    #[cfg(unix)]
    help_fetch      => (["fetch", "--help"], "tirith fetch");
    help_fix        => (["fix", "--help"], "tirith fix --");
    help_setup      => (["setup", "--help"], "tirith setup claude-code");
    help_init       => (["init", "--help"], "tirith init --shell");
    // M8 ch6 — `--prompt-status` flag and `tirith prompt-status` subcommand.
    help_init_prompt_status_flag => (["init", "--help"], "tirith init --shell zsh --prompt-status");
    help_prompt_status            => (["prompt-status", "--help"], "tirith prompt-status --short");
    help_prompt_status_json       => (["prompt-status", "--help"], "tirith prompt-status --json");
    help_doctor     => (["doctor", "--help"], "tirith doctor --fix");
    help_warnings   => (["warnings", "--help"], "tirith warnings");
    help_policy     => (["policy", "--help"], "tirith policy init");
    help_audit      => (["audit", "--help"], "tirith audit export");
    help_trust      => (["trust", "--help"], "tirith trust add");
    help_receipt    => (["receipt", "--help"], "tirith receipt");
    help_checkpoint => (["checkpoint", "--help"], "tirith checkpoint create");
    help_threat_db  => (["threat-db", "--help"], "tirith threat-db update");
    help_threat_db_explain => (["threat-db", "explain", "--help"], "tirith threat-db explain react");
    help_threat_db_sources => (["threat-db", "sources", "--help"], "tirith threat-db sources");
    help_threat_db_health  => (["threat-db", "health", "--help"], "tirith threat-db health");
    help_threat_db_diff    => (["threat-db", "diff", "--help"], "tirith threat-db diff --since");
    help_package          => (["package", "--help"], "tirith package risk npm react");
    help_package_risk     => (["package", "risk", "--help"], "tirith package risk pypi reqeusts");
    help_package_explain  => (["package", "explain", "--help"], "tirith package explain npm express");
    help_ecosystem        => (["ecosystem", "--help"], "tirith ecosystem scan");
    help_ecosystem_scan   => (["ecosystem", "scan", "--help"], "tirith ecosystem scan --online ./my-project");
    help_daemon     => (["daemon", "--help"], "tirith daemon start");
    help_gateway    => (["gateway", "--help"], "tirith gateway");
    help_license    => (["license", "--help"], "tirith license");
    help_mcp_server => (["mcp-server", "--help"], "tirith mcp-server");
    help_mcp        => (["mcp", "--help"], "tirith mcp lock");
    help_mcp_lock   => (["mcp", "lock", "--help"], "tirith mcp lock --format json");
    help_mcp_verify => (["mcp", "verify", "--help"], "tirith mcp verify --format json");
    help_mcp_diff   => (["mcp", "diff", "--help"], "tirith mcp diff --format json");
    help_mcp_policy => (["mcp", "policy", "--help"], "tirith mcp policy init");
    help_mcp_policy_init => (["mcp", "policy", "init", "--help"], "tirith mcp policy init --format json");
    help_mcp_explain     => (["mcp", "explain", "--help"], "tirith mcp explain my-server");
    help_mcp_permissions => (["mcp", "permissions", "--help"], "tirith mcp permissions");
    help_agent_current   => (["agent", "current", "--help"], "tirith agent current");
    help_agent_block     => (["agent", "block", "--help"], "tirith agent block --kind agent --tool untrusted-tool");
    help_explain_finding => (["explain", "--help"], "tirith explain --finding evt-abc:0");
    help_verify_self => (["verify-self", "--help"], "tirith verify-self --format json");
    help_update     => (["update", "--help"], "tirith update --verify");
    help_update_rollback => (["update", "--help"], "tirith update --rollback");
    help_version    => (["version", "--help"], "tirith version --provenance");
    help_lab        => (["lab", "--help"], "tirith lab --filter powershell");
    help_view       => (["view", "--help"], "tirith view /var/log/system.log");
    help_output     => (["output", "--help"], "tirith output wrap on | off | status");
    help_output_wrap => (["output", "wrap", "--help"], "tirith output wrap on");
    help_share      => (["share", "--help"], "tirith share --target llm");
    help_redact     => (["redact", "--help"], "tirith redact --audience slack");
    help_clipboard       => (["clipboard", "--help"], "tirith clipboard copy ./snippet.sh");
    help_clipboard_copy  => (["clipboard", "copy", "--help"], "tirith clipboard copy ./snippet.sh");
    help_clipboard_scan  => (["clipboard", "scan", "--help"], "tirith clipboard scan");
    help_clipboard_guard => (["clipboard", "guard", "--help"], "tirith clipboard guard install-service");
    // M7 ch5 — `tirith logs scan|summarize|redact`.
    help_logs            => (["logs", "--help"], "tirith logs scan ./error.log");
    help_logs_scan       => (["logs", "scan", "--help"], "tirith logs scan ./error.log");
    help_logs_summarize  => (["logs", "summarize", "--help"], "tirith logs summarize --safe-for-agent --max-lines 100 ./build.log");
    help_logs_redact     => (["logs", "redact", "--help"], "tirith logs redact --audience llm ./error.log");
    // M7 ch4 — `gateway run --filter-output` and `mcp-server
    // --sanitize-tool-output`. Pin both to the help output so a future
    // re-organization that drops the flags is caught here.
    help_gateway_run_filter_output    => (["gateway", "run", "--help"], "--filter-output");
    help_gateway_run_filter_output_ex => (["gateway", "run", "--help"], "tirith gateway run --filter-output");
    help_mcp_server_sanitize          => (["mcp-server", "--help"], "--sanitize-tool-output");
    help_mcp_server_sanitize_ex       => (["mcp-server", "--help"], "tirith mcp-server --sanitize-tool-output");
    // M8 ch1 — `tirith context status|guard|label`.
    help_context         => (["context", "--help"], "tirith context status");
    help_context_status  => (["context", "status", "--help"], "tirith context status");
    help_context_guard   => (["context", "guard", "--help"], "tirith context guard on");
    help_context_label   => (["context", "label", "--help"], "tirith context label kube:prod-us-east critical --scope user");
    // M8 ch2 — `tirith ssh guard|label`.
    help_ssh             => (["ssh", "--help"], "tirith ssh guard on");
    help_ssh_guard       => (["ssh", "guard", "--help"], "tirith ssh guard on");
    help_ssh_label       => (["ssh", "label", "--help"], "tirith ssh label payments-prod-01 critical --scope user");
    // M8 ch3 — `tirith iac guard|check-plan|require-plan-before-apply`.
    help_iac             => (["iac", "--help"], "tirith iac guard on");
    help_iac_guard       => (["iac", "guard", "--help"], "tirith iac guard on");
    help_iac_check_plan  => (["iac", "check-plan", "--help"], "tirith iac check-plan tfplan");
    help_iac_require_plan_before_apply => (["iac", "require-plan-before-apply", "--help"], "tirith iac require-plan-before-apply on");
    // M8 ch4 — `tirith sudo guard|session|require-reason`.
    help_sudo                  => (["sudo", "--help"], "tirith sudo guard on");
    help_sudo_guard            => (["sudo", "guard", "--help"], "tirith sudo guard on");
    help_sudo_session          => (["sudo", "session", "--help"], "tirith sudo session start --ttl 30m --reason");
    help_sudo_require_reason   => (["sudo", "require-reason", "--help"], "tirith sudo require-reason on");
    // M8 ch5 — `tirith devcontainer guard|inject` and `tirith codespaces setup|inject`.
    help_devcontainer          => (["devcontainer", "--help"], "tirith devcontainer guard on");
    help_devcontainer_guard    => (["devcontainer", "guard", "--help"], "tirith devcontainer guard on");
    help_devcontainer_inject   => (["devcontainer", "inject", "--help"], "tirith devcontainer inject");
    help_codespaces            => (["codespaces", "--help"], "tirith codespaces setup");
    help_codespaces_setup      => (["codespaces", "setup", "--help"], "tirith codespaces setup");
    help_codespaces_inject     => (["codespaces", "inject", "--help"], "tirith codespaces inject");
    // M9 ch1 — `tirith hygiene scan|fix`.
    help_hygiene               => (["hygiene", "--help"], "tirith hygiene scan");
    help_hygiene_scan          => (["hygiene", "scan", "--help"], "tirith hygiene scan --json");
    help_hygiene_fix           => (["hygiene", "fix", "--help"], "tirith hygiene fix --dry-run");
    // M9 ch2 — `tirith persistence scan|watch|diff`.
    help_persistence           => (["persistence", "--help"], "tirith persistence scan");
    help_persistence_scan      => (["persistence", "scan", "--help"], "tirith persistence scan --json");
    help_persistence_watch     => (["persistence", "watch", "--help"], "tirith persistence watch --interval 30");
    help_persistence_diff      => (["persistence", "diff", "--help"], "tirith persistence diff --json");
    // M9 ch3 — `tirith aliases scan|explain`.
    help_aliases               => (["aliases", "--help"], "tirith aliases scan");
    help_aliases_scan          => (["aliases", "scan", "--help"], "tirith aliases scan --include-runtime");
    help_aliases_explain       => (["aliases", "explain", "--help"], "tirith aliases explain git");
    // M9 ch4 — `tirith env guard|diff|explain`.
    help_env                   => (["env", "--help"], "tirith env guard on");
    help_env_guard             => (["env", "guard", "--help"], "tirith env guard status --json");
    help_env_diff              => (["env", "diff", "--help"], "tirith env diff --reset");
    help_env_explain           => (["env", "explain", "--help"], "tirith env explain AWS_SECRET_ACCESS_KEY");
    // M9 ch5 — `tirith exec check|provenance` and `tirith path audit|watch|which`.
    help_exec                  => (["exec", "--help"], "tirith exec check kubectl");
    help_exec_check            => (["exec", "check", "--help"], "tirith exec check git --json");
    help_exec_provenance       => (["exec", "provenance", "--help"], "tirith exec provenance /tmp/installer");
    help_path                  => (["path", "--help"], "tirith path audit");
    help_path_audit            => (["path", "audit", "--help"], "tirith path audit --json");
    help_path_watch            => (["path", "watch", "--help"], "tirith path watch --interval 30");
    help_path_which            => (["path", "which", "--help"], "tirith path which git --secure");
    // M9 ch6 — `tirith hooks scan|guard|explain`.
    help_hooks                 => (["hooks", "--help"], "tirith hooks scan");
    help_hooks_scan            => (["hooks", "scan", "--help"], "tirith hooks scan --json");
    help_hooks_guard           => (["hooks", "guard", "--help"], "tirith hooks guard on");
    help_hooks_explain         => (["hooks", "explain", "--help"], "tirith hooks explain pre-commit");
    // M10 ch1 — `tirith preview` blast-radius simulator.
    help_preview               => (["preview", "--help"], "tirith preview -- \"rm -rf ./dist\"");
    // M10 ch2 — `tirith watch` post-run diff. Two spellings, one impl: pin both
    // the top-level shortcut and the namespaced `checkpoint watch` form.
    help_watch                 => (["watch", "--help"], "tirith watch -- npm install left-pad");
    help_checkpoint_watch      => (["checkpoint", "watch", "--help"], "tirith watch -- npm install left-pad");
}

#[test]
fn help_root_lists_subcommands() {
    let out = tirith().args(["--help"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("check"));
    assert!(stdout.contains("scan"));
    assert!(stdout.contains("setup"));
    assert!(stdout.contains("doctor"));
    assert!(stdout.contains("mcp-server"));
    assert!(stdout.contains("verify-self"));
    assert!(stdout.contains("update"));
    assert!(stdout.contains("version"));
    assert!(stdout.contains("package"));
    // hook-event is an internal subcommand and must not surface here.
    assert!(
        !stdout.contains("hook-event"),
        "hook-event should be hidden from top-level help"
    );
}

#[test]
fn help_check_shows_format_flag() {
    let out = tirith().args(["check", "--help"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--format"));
    assert!(stdout.contains("human, json"));
    // --json is an alias; only --format should be documented.
    assert!(
        !stdout.contains("  --json"),
        "--json should be hidden from help"
    );
}

#[test]
fn help_scan_shows_sarif_format() {
    let out = tirith().args(["scan", "--help"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("human, json, sarif"));
}

#[test]
fn help_policy_init_documents_templates() {
    let out = tirith()
        .args(["policy", "init", "--help"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("--template"),
        "policy init --help should document --template: {stdout}"
    );
    for name in ["individual", "ci-strict", "ai-agent-heavy"] {
        assert!(
            stdout.contains(name),
            "policy init --help should list the {name} template: {stdout}"
        );
    }
}

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
fn conflict_doctor_compat_and_fix() {
    let out = tirith()
        .args(["doctor", "--compat", "--fix"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "--compat must conflict with --fix");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot be used with"));
}

#[test]
fn conflict_doctor_compat_and_simulate_enter() {
    let out = tirith()
        .args(["doctor", "--compat", "--simulate-enter"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "--compat must conflict with --simulate-enter"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot be used with"));
}

#[test]
fn conflict_doctor_compat_and_reset() {
    let out = tirith()
        .args(["doctor", "--compat", "--reset-bash-safe-mode"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "--compat must conflict with --reset-bash-safe-mode"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot be used with"));
}

#[test]
fn doctor_compat_allows_format_json() {
    // --compat is explicitly compatible with --format json (machine-readable
    // compatibility report). This must NOT be a conflict.
    let out = tirith()
        .args(["doctor", "--compat", "--format", "json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "doctor --compat --format json should succeed, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("doctor --compat --format json should produce valid JSON");
    assert!(json["version"].is_string());
    assert!(json["detected_shell"].is_string());
    assert!(
        json["shell_tools"].is_array(),
        "compat JSON must carry a shell_tools array"
    );
    assert!(
        json["shadow_binaries"].is_array(),
        "compat JSON must carry a shadow_binaries array"
    );
}

#[test]
fn doctor_compat_human_has_expected_sections() {
    let out = tirith().args(["doctor", "--compat"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for section in [
        "tirith compatibility report",
        "Shell hook mode",
        "Install checks",
        "Shell tool detection",
    ] {
        assert!(
            stdout.contains(section),
            "compat report missing section {section:?}, got:\n{stdout}"
        );
    }
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

// `tirith score` does purely local URL analysis with no network call, so
// its JSON output is deterministic.

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
    assert_eq!(j1["url"], j2["url"]);
    assert_eq!(j1["score"], j2["score"]);
    assert_eq!(j1["risk_level"], j2["risk_level"]);
    assert_eq!(j1["findings"], j2["findings"]);
}

#[test]
fn format_human_explicit_matches_default() {
    let out_default = tirith()
        .args(["check", "--", "echo", "hello"])
        .output()
        .unwrap();
    let out_explicit = tirith()
        .args(["check", "--format", "human", "--", "echo", "hello"])
        .output()
        .unwrap();
    assert_eq!(out_default.status.code(), out_explicit.status.code());
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
    let out = tirith()
        .args(["paste", "--json", "--format", "json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot be used with"));
}

#[test]
fn help_mcp_diff_documents_exit_codes() {
    // `tirith mcp diff` exits 0 on a normal run (whether drift is present
    // or not — `diff` is informational, not gating), but exits 2 on usage
    // errors (no lockfile, malformed lockfile, unresolvable repo root).
    // The help string must spell both out so the documented contract
    // matches the integration tests in `cli_integration::mcp_diff_*`.
    let out = tirith().args(["mcp", "diff", "--help"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        stdout.contains("Exit codes:"),
        "mcp diff --help must document its exit codes, got:\n{stdout}"
    );
    assert!(
        stdout.contains("0  normal"),
        "mcp diff --help must document exit 0 as normal, got:\n{stdout}"
    );
    // Normalize whitespace so the help-formatter's reflow does not break the
    // substring assertion — the contract is "drift presence does not affect
    // the exit code", not the exact phrasing.
    let collapsed: String = stdout.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        collapsed.contains("whether drift is present or not"),
        "mcp diff --help must note that 0 covers both drift and no-drift, got:\n{stdout}"
    );
    assert!(
        stdout.contains("2  usage error"),
        "mcp diff --help must document exit 2 on usage error, got:\n{stdout}"
    );
}
