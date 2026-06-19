//! Help output and CLI regression tests: every subcommand has --help examples,
//! flag conflicts are enforced, JSON envelopes are stable, and error messages
//! include corrective suggestions.

use std::process::Command;

fn tirith() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tirith"))
}

/// Verify a subcommand's --help contains an "Examples:" section with expected
/// content. The expected substring is whitespace-normalized on both sides so a
/// clap line-wrap mid-phrase can't false-fail in CI.
fn assert_help_has_examples(args: &[&str], expected_substring: &str) {
    let out = tirith().args(args).output().expect("failed to run tirith");
    // R19-N2: assert success FIRST — a `--help` that errored (exit 2) would
    // otherwise pass the content checks vacuously on an empty body.
    assert!(
        out.status.success(),
        "{args:?} --help should exit successfully (clap --help exits 0), got status {:?}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Examples:"),
        "{args:?} --help should contain Examples section, got:\n{stdout}"
    );
    let stdout_normalized: String = stdout.split_whitespace().collect::<Vec<_>>().join(" ");
    let expected_normalized: String = expected_substring
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        stdout_normalized.contains(&expected_normalized),
        "{args:?} --help should contain {expected_substring:?} (whitespace-normalized), got:\n{stdout}"
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
    help_init_prompt_status_flag => (["init", "--help"], "tirith init --shell zsh --prompt-status");
    help_prompt_status            => (["prompt-status", "--help"], "tirith prompt-status --short");
    help_prompt_status_json       => (["prompt-status", "--help"], "tirith prompt-status --json");
    help_doctor     => (["doctor", "--help"], "tirith doctor --fix");
    help_warnings   => (["warnings", "--help"], "tirith warnings");
    help_policy     => (["policy", "--help"], "tirith policy init");
    help_ai                => (["ai", "--help"], "tirith ai diff");
    help_ai_scan           => (["ai", "scan", "--help"], "tirith ai scan");
    help_ai_diff           => (["ai", "diff", "--help"], "tirith ai diff --json");
    help_ai_quarantine     => (["ai", "quarantine", "--help"], "tirith ai quarantine .cursorrules --move --yes");
    help_ai_explain_config => (["ai", "explain-config", "--help"], "tirith ai explain-config CLAUDE.md");
    help_ai_snapshot       => (["ai", "snapshot", "--help"], "tirith ai snapshot --update");
    help_rule          => (["rule", "--help"], "tirith rule validate");
    help_rule_test     => (["rule", "test", "--help"], "tirith rule test --rule block-unknown-curl-to-shell");
    help_rule_validate => (["rule", "validate", "--help"], "tirith rule validate --path .tirith/policy.yaml");
    help_rule_explain  => (["rule", "explain", "--help"], "tirith rule explain --rule block-unknown-curl-to-shell");
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
    help_package_inspect  => (["package", "inspect", "--help"], "tirith package inspect --artifact-set ./downloaded-wheels/");
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
    help_update     => (["update", "--help"], "tirith update --allow-unsigned");
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
    // `clipboard watch` must also be advertised in the PARENT clipboard help.
    help_clipboard_watch_in_parent => (["clipboard", "--help"], "tirith clipboard watch");
    help_clipboard_watch => (["clipboard", "watch", "--help"], "tirith clipboard watch --json");
    help_logs            => (["logs", "--help"], "tirith logs scan ./error.log");
    help_logs_scan       => (["logs", "scan", "--help"], "tirith logs scan ./error.log");
    help_logs_summarize  => (["logs", "summarize", "--help"], "tirith logs summarize --safe-for-agent --max-lines 100 ./build.log");
    help_logs_redact     => (["logs", "redact", "--help"], "tirith logs redact --audience llm ./error.log");
    help_gateway_run_filter_output    => (["gateway", "run", "--help"], "--filter-output");
    help_gateway_run_filter_output_ex => (["gateway", "run", "--help"], "tirith gateway run --filter-output");
    help_mcp_server_sanitize          => (["mcp-server", "--help"], "--sanitize-tool-output");
    help_mcp_server_sanitize_ex       => (["mcp-server", "--help"], "tirith mcp-server --sanitize-tool-output");
    help_context         => (["context", "--help"], "tirith context status");
    help_context_status  => (["context", "status", "--help"], "tirith context status");
    help_context_guard   => (["context", "guard", "--help"], "tirith context guard on");
    help_context_label   => (["context", "label", "--help"], "tirith context label kube:prod-us-east critical --scope user");
    help_ssh             => (["ssh", "--help"], "tirith ssh guard on");
    help_ssh_guard       => (["ssh", "guard", "--help"], "tirith ssh guard on");
    help_ssh_label       => (["ssh", "label", "--help"], "tirith ssh label payments-prod-01 critical --scope user");
    help_iac             => (["iac", "--help"], "tirith iac guard on");
    help_iac_guard       => (["iac", "guard", "--help"], "tirith iac guard on");
    help_iac_check_plan  => (["iac", "check-plan", "--help"], "tirith iac check-plan tfplan");
    help_iac_require_plan_before_apply => (["iac", "require-plan-before-apply", "--help"], "tirith iac require-plan-before-apply on");
    help_sudo                  => (["sudo", "--help"], "tirith sudo guard on");
    help_sudo_guard            => (["sudo", "guard", "--help"], "tirith sudo guard on");
    help_sudo_session          => (["sudo", "session", "--help"], "tirith sudo session start --ttl 30m --reason");
    help_sudo_require_reason   => (["sudo", "require-reason", "--help"], "tirith sudo require-reason on");
    help_devcontainer          => (["devcontainer", "--help"], "tirith devcontainer guard on");
    help_devcontainer_guard    => (["devcontainer", "guard", "--help"], "tirith devcontainer guard on");
    help_devcontainer_inject   => (["devcontainer", "inject", "--help"], "tirith devcontainer inject");
    help_codespaces            => (["codespaces", "--help"], "tirith codespaces setup");
    help_codespaces_setup      => (["codespaces", "setup", "--help"], "tirith codespaces setup");
    help_codespaces_inject     => (["codespaces", "inject", "--help"], "tirith codespaces inject");
    help_hygiene               => (["hygiene", "--help"], "tirith hygiene scan");
    help_hygiene_scan          => (["hygiene", "scan", "--help"], "tirith hygiene scan --json");
    help_hygiene_fix           => (["hygiene", "fix", "--help"], "tirith hygiene fix --dry-run");
    help_persistence           => (["persistence", "--help"], "tirith persistence scan");
    help_persistence_scan      => (["persistence", "scan", "--help"], "tirith persistence scan --json");
    help_persistence_watch     => (["persistence", "watch", "--help"], "tirith persistence watch --interval 30");
    help_persistence_diff      => (["persistence", "diff", "--help"], "tirith persistence diff --json");
    help_aliases               => (["aliases", "--help"], "tirith aliases scan");
    help_aliases_scan          => (["aliases", "scan", "--help"], "tirith aliases scan --include-runtime");
    help_aliases_explain       => (["aliases", "explain", "--help"], "tirith aliases explain git");
    help_env                   => (["env", "--help"], "tirith env guard on");
    help_env_guard             => (["env", "guard", "--help"], "tirith env guard status --json");
    help_env_diff              => (["env", "diff", "--help"], "tirith env diff --reset");
    help_env_explain           => (["env", "explain", "--help"], "tirith env explain AWS_SECRET_ACCESS_KEY");
    help_exec                  => (["exec", "--help"], "tirith exec check kubectl");
    help_exec_check            => (["exec", "check", "--help"], "tirith exec check git --json");
    help_exec_provenance       => (["exec", "provenance", "--help"], "tirith exec provenance /tmp/installer");
    help_path                  => (["path", "--help"], "tirith path audit");
    help_path_audit            => (["path", "audit", "--help"], "tirith path audit --json");
    help_path_watch            => (["path", "watch", "--help"], "tirith path watch --interval 30");
    help_path_which            => (["path", "which", "--help"], "tirith path which git --secure");
    help_hooks                 => (["hooks", "--help"], "tirith hooks scan");
    help_hooks_scan            => (["hooks", "scan", "--help"], "tirith hooks scan --json");
    help_hooks_guard           => (["hooks", "guard", "--help"], "tirith hooks guard on");
    help_hooks_explain         => (["hooks", "explain", "--help"], "tirith hooks explain pre-commit");
    help_preview               => (["preview", "--help"], "tirith preview -- \"rm -rf ./dist\"");
    // `watch` has two spellings, one impl: pin the shortcut and `checkpoint watch`.
    help_watch                 => (["watch", "--help"], "tirith watch -- npm install left-pad");
    help_checkpoint_watch      => (["checkpoint", "watch", "--help"], "tirith watch -- npm install left-pad");
    help_taint                 => (["taint", "--help"], "tirith taint list");
    help_taint_list            => (["taint", "list", "--help"], "tirith taint list --json");
    help_taint_explain         => (["taint", "explain", "--help"], "tirith taint explain ./install.sh");
    help_taint_clear           => (["taint", "clear", "--help"], "tirith taint clear ./install.sh --yes");
    help_intend                => (["intend", "--help"], "tirith intend \"install a formatter\" -- \"curl https://x/install.sh | bash\"");
    help_baseline              => (["baseline", "--help"], "tirith baseline learn");
    help_baseline_learn        => (["baseline", "learn", "--help"], "tirith baseline learn --json");
    help_baseline_status       => (["baseline", "status", "--help"], "tirith baseline status --json");
    help_baseline_reset        => (["baseline", "reset", "--help"], "tirith baseline reset --yes");
    help_temp_run              => (["temp-run", "--help"], "tirith temp-run -- ./script.sh");
    help_command_card          => (["command-card", "--help"], "tirith command-card sign --key ed25519-priv.bin install-card.json");
    help_command_card_create   => (["command-card", "create", "--help"], "tirith command-card create --command 'curl -fsSL https://example.com/install.sh | sh' > card.json");
    help_command_card_sign     => (["command-card", "sign", "--help"], "tirith command-card sign --key ed25519-priv.bin install-card.json");
    help_command_card_verify   => (["command-card", "verify", "--help"], "tirith command-card verify install-card.json");
    // `command-card fetch` is #[cfg(unix)] (unix-only runner path), so gate the
    // snapshot to match.
    #[cfg(unix)]
    help_command_card_fetch    => (["command-card", "fetch", "--help"], "tirith command-card fetch https://example.com/install-card.json");
    help_commands              => (["commands", "--help"], "tirith commands run test");
    help_commands_init         => (["commands", "init", "--help"], "tirith commands init");
    help_commands_list         => (["commands", "list", "--help"], "tirith commands list");
    help_commands_run          => (["commands", "run", "--help"], "tirith commands run test");
    help_commands_check        => (["commands", "check", "--help"], "tirith commands check -- \"npm run build\"");
    help_canary                => (["canary", "--help"], "tirith canary create aws-like");
    help_canary_create         => (["canary", "create", "--help"], "tirith canary create github-like --callback-url https://my-host.example/hit");
    help_canary_status         => (["canary", "status", "--help"], "tirith canary status");
    help_canary_list           => (["canary", "list", "--help"], "tirith canary list");
    help_canary_prune          => (["canary", "prune", "--help"], "tirith canary prune a1b2c3d4e5f6 --yes");
    help_canary_rotate         => (["canary", "rotate", "--help"], "tirith canary rotate a1b2c3d4e5f6");
    help_secret                => (["secret", "--help"], "tirith secret rotate github");
    help_secret_triage         => (["secret", "triage", "--help"], "tirith secret triage --json");
    help_secret_rotate         => (["secret", "rotate", "--help"], "tirith secret rotate github");
    help_secret_revoke         => (["secret", "revoke", "--help"], "tirith secret revoke --provider aws");

    help_incident              => (["incident", "--help"], "tirith incident start --reason");
    help_incident_start        => (["incident", "start", "--help"], "tirith incident start --reason");
    help_incident_stop         => (["incident", "stop", "--help"], "tirith incident stop --yes");
    help_incident_status       => (["incident", "status", "--help"], "tirith incident status");
    help_incident_report       => (["incident", "report", "--help"], "tirith incident report --out");
    help_onboard               => (["onboard", "--help"], "tirith onboard --json");
    help_dashboard             => (["dashboard", "--help"], "tirith dashboard serve --port 8765");
    help_dashboard_export      => (["dashboard", "export", "--help"], "tirith dashboard export --out .");
    help_dashboard_serve       => (["dashboard", "serve", "--help"], "tirith dashboard serve --port 8765");
}

/// Pin the `tirith secret` honesty contract: every surface must state it does
/// NOT rotate/revoke and makes zero network calls. Matches collapse whitespace
/// first so a clap line-wrap can't split a phrase mid-break.
#[test]
fn help_secret_states_assistant_only_and_no_network() {
    for args in [
        &["secret", "--help"][..],
        &["secret", "triage", "--help"][..],
        &["secret", "rotate", "--help"][..],
        &["secret", "revoke", "--help"][..],
    ] {
        let out = tirith().args(args).output().expect("failed to run tirith");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let lower = stdout.to_ascii_lowercase();
        let collapsed: String = lower.split_whitespace().collect::<Vec<_>>().join(" ");
        // CodeRabbit R15 #7: require the negation ADJACENT to the rotate/revoke
        // claim (the contiguous banner phrase), so three independent substring
        // checks can't pass while the banner is removed.
        assert!(
            collapsed.contains("does not perform rotation or revocation"),
            "{args:?} --help must carry the contiguous 'tirith does NOT perform rotation or \
             revocation' honesty banner (negation adjacent to the rotate/revoke claim), got:\n{stdout}"
        );
        // Require a negation adjacent to "network" (CodeRabbit R7 #10: every
        // accepted phrasing must carry the literal token "network", else the
        // assertion could pass with no mention of network at all).
        assert!(
            collapsed.contains("zero network")
                || collapsed.contains("no network")
                || collapsed.contains("never makes network")
                || collapsed.contains("makes no network")
                || collapsed.contains("does not make network"),
            "{args:?} --help must state it makes NO network calls (a negation adjacent to \
             'network'), got:\n{stdout}"
        );
    }
}

/// Pin the two `tirith incident` guarantees in help: (1) it adds NO new rule
/// IDs, and (2) `stop` is always recoverable (lockout safety). Matches use
/// single unsplittable tokens to survive clap's line-wrapping.
#[test]
fn help_incident_states_no_new_rules_and_lockout_safety() {
    let top = tirith()
        .args(["incident", "--help"])
        .output()
        .expect("failed to run tirith");
    let top_out = String::from_utf8_lossy(&top.stdout);
    // CodeRabbit R7 #11: require the "id" qualifier ("no new rule id" matches
    // both "ID" and "IDs"); normalize whitespace so a wrap can't split it.
    let top_collapsed: String = top_out
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        top_collapsed.contains("no new rule id"),
        "incident --help must state it adds no new rule IDs (with the ID qualifier), got:\n{top_out}"
    );
    assert!(
        top_out.contains("FAIL-CLOSED") || top_out.to_ascii_lowercase().contains("fail-closed"),
        "incident --help must state it forces fail-closed, got:\n{top_out}"
    );
    // Both the top-level and the `stop` help carry the lockout-safety note.
    for args in [
        &["incident", "--help"][..],
        &["incident", "stop", "--help"][..],
    ] {
        let out = tirith().args(args).output().expect("failed to run tirith");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let collapsed: String = stdout
            .to_ascii_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        // F13: require the SPECIFIC lockout/recoverability wording — bare
        // "always" is too generic and could let the safety note go missing.
        assert!(
            collapsed.contains("lockout safety")
                && (collapsed.contains("recoverable") || collapsed.contains("always succeeds")),
            "{args:?} --help must carry the explicit lockout-safety + recoverability note, \
             got:\n{stdout}"
        );
    }
}

/// The unknown-provider error must list all 11 valid providers.
#[test]
fn secret_rotate_unknown_provider_lists_all_eleven() {
    let out = tirith()
        .args(["secret", "rotate", "definitely-not-a-provider"])
        .output()
        .expect("failed to run tirith");
    assert_eq!(out.status.code(), Some(2), "unknown provider must exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    for p in [
        "aws",
        "github",
        "npm",
        "pypi",
        "cargo",
        "stripe",
        "slack",
        "openai",
        "anthropic",
        "gcp",
        "azure",
    ] {
        assert!(
            stderr.contains(p),
            "unknown-provider error must list '{p}', got:\n{stderr}"
        );
    }
}

/// Pin the `temp-run` honesty wording: it is NOT a sandbox and runs with full
/// privileges.
#[test]
fn help_temp_run_states_not_a_sandbox() {
    let out = tirith()
        .args(["temp-run", "--help"])
        .output()
        .expect("failed to run tirith");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.to_lowercase().contains("not a sandbox"),
        "temp-run --help must say it is NOT a sandbox, got:\n{stdout}"
    );
    assert!(
        stdout.contains("full user privileges"),
        "temp-run --help must say the command runs with full user privileges, got:\n{stdout}"
    );
    assert!(
        stdout.contains("keychain"),
        "temp-run --help must warn the command can read the keychain, got:\n{stdout}"
    );
}

#[test]
fn help_intend_documents_exit_codes() {
    // `intend` never blocks but exits non-zero on mismatch; the help must spell
    // the codes out to match the integration tests.
    let out = tirith().args(["intend", "--help"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Exit codes"),
        "intend --help must document its exit codes, got:\n{stdout}"
    );
    assert!(
        stdout.contains("1  at least one mismatch"),
        "intend --help must document exit 1 on mismatch, got:\n{stdout}"
    );
    // The honesty caveat: never blocks.
    let collapsed: String = stdout.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        collapsed.contains("NEVER blocks") || collapsed.contains("never blocks"),
        "intend --help must state it never blocks, got:\n{stdout}"
    );
}

/// CodeRabbit PR #132 R20 (F6): the AI-quarantine help must use the
/// platform-neutral `<cache-dir>/…` placeholder, not the Linux-only `~/.cache/…`
/// literal. Pin both help surfaces that mention the path.
#[test]
fn help_ai_quarantine_path_is_platform_neutral() {
    for args in [&["ai", "--help"][..], &["ai", "quarantine", "--help"][..]] {
        let out = tirith().args(args).output().expect("failed to run tirith");
        assert!(out.status.success(), "{args:?} --help should exit 0");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("<cache-dir>/tirith/quarantine"),
            "{args:?} --help must use the platform-neutral <cache-dir>/tirith/quarantine path, got:\n{stdout}"
        );
        assert!(
            !stdout.contains("~/.cache/tirith/quarantine"),
            "{args:?} --help must NOT hardcode the Linux-only ~/.cache/tirith/quarantine path, got:\n{stdout}"
        );
    }
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
    // `mcp diff` exits 0 on a normal run (drift or not) and 2 on usage errors;
    // the help must spell both out to match cli_integration::mcp_diff_*.
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
    // Normalize whitespace so the help-formatter's reflow can't break the match.
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
