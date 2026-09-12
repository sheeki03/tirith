//! Compatibility and resolver coverage for policy diagnostics. Every subprocess
//! uses isolated policy, user, cache, audit and runtime directories.
use std::process::{Command, Output};

use serde_json::Value;
use tirith_test_support::GlobalStateGuard;

fn run(state: &GlobalStateGuard, flags: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tirith"));
    state.apply_to_command(&mut command);
    command
        .current_dir(&state.roots().cwd)
        .args(["policy", "effective"])
        .args(flags)
        .output()
        .unwrap()
}

fn json(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn org_policy(state: &GlobalStateGuard, yaml: &str) {
    let dir = state.roots().policy.join(".tirith");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("policy.yaml"), yaml).unwrap();
}

#[test]
fn legacy_offline_default_and_explicit_runtime_have_honest_coverage() {
    let mut state = GlobalStateGuard::new().unwrap();
    org_policy(&state, "fail_mode: open\npolicy_fetch_fail_mode: closed\n");
    // Deliberately invalid transport: deterministic refusal without a socket.
    state.set_env("TIRITH_SERVER_URL", "http://127.0.0.1:1");
    state.set_env("TIRITH_API_KEY", "fixture-key");
    let default = json(&run(&state, &["--json"]));
    let offline = json(&run(&state, &["--local-only", "--format", "json"]));
    assert_eq!(default, offline);
    assert_eq!(default["resolution"]["mode"], "local_only");
    assert_eq!(
        default["resolution"]["remote_configuration_resolved"],
        false
    );
    assert_eq!(default["policy"]["fail_mode"], "open");

    let runtime = json(&run(&state, &["--runtime", "--json"]));
    assert_eq!(runtime["resolution"]["mode"], "runtime");
    assert_eq!(runtime["policy"]["fail_mode"], "closed");
    assert!(runtime["policy"]["custom_rules"]
        .as_array()
        .unwrap()
        .iter()
        .any(|rule| rule["id"] == "tirith-effective-policy-unavailable"));
    assert!(!run(&state, &["--runtime", "--local-only"]).status.success());
    let human = run(&state, &[]);
    assert!(human.stdout.is_empty());
    assert!(String::from_utf8_lossy(&human.stderr).contains("local-only diagnostic"));
}

#[test]
fn primary_source_matches_resolved_user_policy_when_repository_tightens() {
    let mut state = GlobalStateGuard::new().unwrap();
    state.remove_env("TIRITH_POLICY_ROOT");
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join("policy.yaml"), "paranoia: 2\n").unwrap();
    std::fs::write(config.join("blocklist"), "user-denial.example\n").unwrap();
    let repo = state.roots().cwd.join(".tirith");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(state.roots().cwd.join(".git")).unwrap();
    std::fs::write(
        repo.join("policy.yaml"),
        "allowlist: [hostile.example]\nparanoia: 3\n",
    )
    .unwrap();
    let output = json(&run(&state, &["--runtime", "--json"]));
    assert_eq!(output["scope"], "user");
    assert!(
        std::path::Path::new(output["source_path"].as_str().unwrap())
            .ends_with(std::path::Path::new("tirith").join("policy.yaml"))
    );
    assert_eq!(output["policy"]["paranoia"], 3);
    assert_eq!(
        output["policy"]["blocklist"],
        serde_json::json!(["user-denial.example"])
    );
    assert_eq!(output["policy"]["allowlist"], serde_json::json!([]));
    assert!(output["neutralized_fields"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("allowlist")));
}

#[test]
fn credentials_are_hidden_and_custom_redaction_cannot_corrupt_envelope() {
    let state = GlobalStateGuard::new().unwrap();
    org_policy(
        &state,
        r#"
policy_server_api_key: arbitrary-unrecognizable-secret
webhooks:
  - url: https://example.com/hook
    headers:
      Authorization: another-arbitrary-secret
dlp_custom_patterns: ['.+']
"#,
    );
    let output = run(&state, &["--json"]);
    let value = json(&output);
    let rendered = String::from_utf8(output.stdout).unwrap();
    assert!(!rendered.contains("arbitrary-unrecognizable-secret"));
    assert!(!rendered.contains("another-arbitrary-secret"));
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["scope"], "org");
    assert_eq!(value["resolution"]["mode"], "local_only");
    assert_eq!(value["resolution"]["effective_fail_mode"], "open");
    assert_eq!(
        value["resolution"]["policy_posture_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(value["resolution"]["policy_is_redacted_display"], true);
}

#[test]
fn credential_redaction_does_not_depend_on_custom_patterns() {
    let state = GlobalStateGuard::new().unwrap();
    org_policy(&state, "policy_server_api_key: arbitrary-unrecognizable-secret\nwebhooks:\n  - url: https://example.com/hook\n    headers:\n      X-Credential: another-arbitrary-secret\n");
    let output = json(&run(&state, &["--json"]));
    assert_eq!(output["policy"]["policy_server_api_key"], "[REDACTED]");
    assert_eq!(
        output["policy"]["webhooks"][0]["headers"]["X-Credential"],
        "[REDACTED]"
    );
}

#[test]
fn dynamic_map_keys_are_redacted_without_dropping_colliding_entries() {
    let state = GlobalStateGuard::new().unwrap();
    let token = format!("ghp_{}", "A".repeat(36));
    org_policy(
        &state,
        &format!(
            r#"
dlp_custom_patterns: ['customer-[0-9]+']
web3_guard:
  selector_aliases:
    hardhat:
      customer-123: mainnet
      customer-456: testnet
context_destructive_verbs:
  customer-789: [delete]
webhooks:
  - url: https://example.com/hook
    headers:
      {token}: hidden
"#
        ),
    );
    let output = run(&state, &["--json"]);
    let value = json(&output);
    let aliases = value["policy"]["web3_guard"]["selector_aliases"]["hardhat"]
        .as_object()
        .unwrap();
    assert_eq!(aliases.len(), 2);
    assert!(aliases.values().any(|value| value == "mainnet"));
    assert!(aliases.values().any(|value| value == "testnet"));
    let human = run(&state, &[]);
    for rendered in [&output.stdout, &human.stderr] {
        let rendered = String::from_utf8_lossy(rendered);
        for secret in [
            "customer-123",
            "customer-456",
            "customer-789",
            token.as_str(),
        ] {
            assert!(!rendered.contains(secret), "secret map key in output");
        }
        assert!(rendered.contains("[REDACTED:custom]"));
    }
}
