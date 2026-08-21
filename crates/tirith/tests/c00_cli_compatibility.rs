//! C00 CLI compatibility and benign Web3 negative corpus.
//!
//! Every subprocess gets test-owned user/config/data/state/cache/runtime,
//! AppData, policy, audit, receipt, credential, and ThreatDB roots.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Output};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ContractCase {
    name: String,
    command: String,
    expected_exit: i32,
    expected_action: String,
    #[serde(default)]
    expected_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CliContracts {
    legacy_command: Vec<ContractCase>,
    benign_web3: Vec<ContractCase>,
}

fn fixture() -> CliContracts {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/c00/cli-contracts.toml");
    let text = std::fs::read_to_string(path).expect("read C00 CLI contract fixture");
    toml::from_str(&text).expect("parse C00 CLI contract fixture")
}

fn run_check(command: &str) -> Output {
    let root = tempfile::Builder::new()
        .prefix("tirith-c00-cli-")
        .tempdir()
        .expect("create hermetic C00 root");
    for relative in [
        "config",
        "data",
        "state",
        "cache",
        "runtime",
        "appdata",
        "localappdata",
        "policy",
        "audit",
        "receipts",
        "db",
    ] {
        std::fs::create_dir_all(root.path().join(relative)).expect("create hermetic C00 directory");
    }

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tirith"));
    cmd.current_dir(root.path())
        .env("HOME", root.path())
        .env("USERPROFILE", root.path())
        .env("XDG_CONFIG_HOME", root.path().join("config"))
        .env("XDG_DATA_HOME", root.path().join("data"))
        .env("XDG_STATE_HOME", root.path().join("state"))
        .env("XDG_CACHE_HOME", root.path().join("cache"))
        .env("XDG_RUNTIME_DIR", root.path().join("runtime"))
        .env("APPDATA", root.path().join("appdata"))
        .env("LOCALAPPDATA", root.path().join("localappdata"))
        .env("TIRITH_LOG", "0")
        .env("TIRITH_OFFLINE", "1")
        .args(["check", "--shell", "posix", "--json", "--", command]);

    for key in [
        "TIRITH",
        "TIRITH_API_KEY",
        "TIRITH_SERVER_URL",
        "TIRITH_LICENSE",
        "TIRITH_POLICY_ROOT",
        "TIRITH_THREATDB_PATH",
        "TIRITH_THREATDB_SUPPLEMENTAL_PATH",
        "TIRITH_AUDIT_DEBUG",
        "TIRITH_DEFER",
        "TIRITH_INTERACTIVE",
        "TIRITH_ALLOW_HTTP",
        "TIRITH_ALLOW_PRIVATE_FETCH",
        "TIRITH_PRIVATE_FETCH_ALLOW",
        "TIRITH_CANARY_TOKEN",
        "TIRITH_SESSION_ID",
        "TIRITH_INTEGRATION",
        "TIRITH_INTEGRATION_VERSION",
    ] {
        cmd.env_remove(key);
    }

    cmd.output().expect("run hermetic tirith check")
}

fn run_case(case: &ContractCase) -> serde_json::Value {
    let output = run_check(&case.command);
    assert_eq!(
        output.status.code(),
        Some(case.expected_exit),
        "{} exit contract changed; stderr: {}",
        case.name,
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{} no longer emitted command JSON: {error}; stdout: {}; stderr: {}",
            case.name,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(json["schema_version"], 3, "{} schema changed", case.name);
    assert_eq!(
        json["action"], case.expected_action,
        "{} action contract changed: {json}",
        case.name
    );
    json
}

#[test]
fn legacy_command_json_and_exit_contract_is_frozen() {
    let fixture = fixture();

    for case in &fixture.legacy_command {
        let json = run_case(case);
        let expected_keys: BTreeSet<String> = case.expected_keys.iter().cloned().collect();
        let actual_keys: BTreeSet<String> = json
            .as_object()
            .expect("command JSON object")
            .keys()
            .cloned()
            .collect();
        assert_eq!(
            actual_keys, expected_keys,
            "{} command JSON top-level keys changed",
            case.name
        );
        assert!(json["findings"].is_array(), "{} findings array", case.name);
        assert!(json["tier_reached"].is_number(), "{} tier", case.name);
    }
}

#[test]
fn benign_web3_negative_corpus_remains_non_blocking() {
    let fixture = fixture();
    assert!(
        fixture.benign_web3.len() >= 17,
        "the C00 corpus must keep every declared benign family"
    );
    for case in &fixture.benign_web3 {
        let json = run_case(case);
        for finding in json["findings"].as_array().expect("findings array") {
            let blocking_severity = finding["severity"].as_str().is_some_and(|severity| {
                severity.eq_ignore_ascii_case("high") || severity.eq_ignore_ascii_case("critical")
            });
            assert!(
                !blocking_severity,
                "benign fixture {} gained a blocking-severity finding: {finding}",
                case.name
            );
        }
    }
}
