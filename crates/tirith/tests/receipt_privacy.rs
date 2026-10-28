use serde_json::Value;
use std::process::{Command, Output};
use tirith_core::receipt::{ArtifactScanReceipt, CapsuleReceipt, VerdictSummary};
use tirith_test_support::GlobalStateGuard;

fn run(state: &GlobalStateGuard, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tirith"));
    state.apply_to_command(&mut command);
    command
        .current_dir(&state.roots().cwd)
        .args(args)
        .output()
        .unwrap()
}

fn policy(state: &GlobalStateGuard, pattern: &str) {
    let dir = state.roots().policy.join(".tirith");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("policy.yaml"),
        format!("dlp_custom_patterns: ['{pattern}']\n"),
    )
    .unwrap();
}

fn save(value: &Value, id: &str) -> (std::path::PathBuf, Vec<u8>) {
    let directory = tirith_core::policy::data_dir().unwrap().join("receipts");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(format!("{id}.json"));
    let bytes = serde_json::to_vec_pretty(value).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    (path, bytes)
}

#[test]
fn saved_download_receipt_routes_use_current_privacy_without_changing_storage() {
    let state = GlobalStateGuard::new().unwrap();
    policy(&state, "receipt-private");
    let id = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let value = serde_json::json!({
        "url":"https://user:password@example.test/receipt-private?token=receipt-private#secret",
        "final_url":null,"redirects":[],"sha256":id,"size":3,
        "domains_referenced":["receipt-private.example.test"],"paths_referenced":["/receipt-private/key"],
        "analysis_method":"receipt-private","privilege":"user","timestamp":"2026-09-12T00:00:00Z",
        "cwd":"/receipt-private/private","git_repo":null,"git_branch":"receipt-private"
    });
    let (path, original) = save(&value, id);
    let cache = tirith_core::policy::data_dir().unwrap().join("cache");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join(id), b"abc").unwrap();
    for args in [
        vec!["receipt", "last", "--json"],
        vec!["receipt", "list", "--json"],
        vec!["receipt", "verify", id, "--json"],
        vec!["receipt", "last"],
        vec!["receipt", "list"],
    ] {
        let output = run(&state, &args);
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            for secret in ["receipt-private", "user:password", "token=", "#secret"] {
                assert!(!text.contains(secret), "{args:?}: leaked {secret}");
            }
        }
        if args.contains(&"--json") {
            let result: Value = serde_json::from_slice(&output.stdout).unwrap();
            let result = if result.is_array() {
                &result[0]
            } else {
                &result
            };
            assert_eq!(result["sha256"], id);
            assert!(result.get("cwd").is_none());
            if args.contains(&"verify") {
                assert_eq!(result["valid"], true);
            }
        }
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
}

#[test]
fn canonical_artifact_json_is_unchanged_or_explicitly_refused_under_tighter_privacy() {
    let state = GlobalStateGuard::new().unwrap();
    let receipt = ArtifactScanReceipt::new(
        "0.4.2".into(),
        "a".repeat(64),
        5,
        "uv receipt-private-index".into(),
        "0.8.22".into(),
        "25.1".into(),
        CapsuleReceipt {
            backend_id: "noop".into(),
            coverage: tirith_core::capsule::CapsuleCoverage::NONE,
        },
        vec!["b".repeat(64)],
        None,
        VerdictSummary {
            action: "Allow".into(),
            rule_ids: vec![],
            finding_count: 0,
        },
    );
    let id = &receipt.receipt_id;
    let canonical = serde_json::to_value(&receipt).unwrap();
    let (path, original) = save(&canonical, id);
    let initial = run(&state, &["pkg", "receipt", "show", id, "--format", "json"]);
    assert!(
        initial.status.success(),
        "{}",
        String::from_utf8_lossy(&initial.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&initial.stdout).unwrap(),
        canonical
    );
    let mut expected_bytes = serde_json::to_vec_pretty(&receipt).unwrap();
    expected_bytes.push(b'\n');
    assert_eq!(
        initial.stdout, expected_bytes,
        "canonical JSON field order changed"
    );
    policy(&state, ".+");
    for query in [vec!["show", id.as_str()], vec!["last"], vec!["list"]] {
        let mut args = vec!["pkg", "receipt"];
        args.extend(&query);
        args.extend(["--format", "json"]);
        let refused = run(&state, &args);
        assert_eq!(refused.status.code(), Some(1));
        assert!(refused.stdout.is_empty());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("display-json"));
        *args.last_mut().unwrap() = "display-json";
        let displayed = run(&state, &args);
        assert!(
            displayed.status.success(),
            "{}",
            String::from_utf8_lossy(&displayed.stderr)
        );
        let shown: Value = serde_json::from_slice(&displayed.stdout).unwrap();
        let shown = if shown.is_array() { &shown[0] } else { &shown };
        assert_eq!(shown["kind"], "artifact_receipt_display");
        assert_eq!(shown["canonical_receipt_id"], *id);
        assert_eq!(shown["stored_content_hash_matches"], true);
        assert_eq!(shown["signature_verification"], "not_performed");
        assert_eq!(shown["receipt"]["verdict"]["action"], "Allow");
        assert_eq!(shown["receipt"]["capsule"]["backend_id"], "noop");
        assert!(!shown.to_string().contains("receipt-private-index"));
        assert!(serde_json::from_value::<ArtifactScanReceipt>(shown.clone()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
}

#[test]
fn receipt_read_budget_refuses_without_raw_content() {
    let state = GlobalStateGuard::new().unwrap();
    let id = "c".repeat(64);
    let (path, _) = save(&serde_json::json!({"private":"never-print-this"}), &id);
    std::fs::File::create(&path)
        .unwrap()
        .set_len(1024 * 1024 + 1)
        .unwrap();
    for args in [
        vec!["receipt", "verify", &id, "--json"],
        vec!["pkg", "receipt", "show", &id, "--format", "display-json"],
    ] {
        let refused = run(&state, &args);
        assert_eq!(refused.status.code(), Some(1));
        assert!(refused.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&refused.stderr).contains("never-print-this"));
    }
}
