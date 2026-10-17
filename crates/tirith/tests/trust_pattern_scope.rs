//! #271: a `*` after a host is not a wildcard. `trust add` refuses it with a
//! hint instead of recording a grant that is reported effective but never
//! matches, and the host grant the hint names covers that registry's images
//! without reaching a lookalike host or a path that merely contains it. Every
//! subprocess uses isolated user, policy, cache and state directories.
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use tirith_test_support::GlobalStateGuard;

fn tirith(state: &GlobalStateGuard, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tirith"));
    state.apply_to_command(&mut command);
    command
        .current_dir(&state.roots().cwd)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn check(state: &GlobalStateGuard, input: &str) -> (String, Vec<String>) {
    let output = tirith(
        state,
        &[
            "check",
            "--json",
            "--non-interactive",
            "--shell",
            "posix",
            "--",
            input,
        ],
    );
    let json: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{input}: {error}: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let rules = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["rule_id"].as_str().unwrap().to_string())
        .collect();
    (json["action"].as_str().unwrap().to_string(), rules)
}

fn assert_registry_warning(state: &GlobalStateGuard, input: &str) {
    let (action, rules) = check(state, input);
    assert_eq!(action, "warn", "{input}: {rules:?}");
    assert!(
        rules.iter().any(|rule| rule == "docker_untrusted_registry"),
        "{input}: {rules:?}"
    );
}

#[test]
fn trust_add_refuses_a_star_after_a_host_and_names_the_host_grant() {
    let state = GlobalStateGuard::new().unwrap();
    for pattern in [
        "registry.example.com/*",
        "https://registry.example.com/*",
        "registry.example.com/team/*",
    ] {
        let output = tirith(
            &state,
            &[
                "trust",
                "add",
                pattern,
                "--broad",
                "--rule",
                "docker_untrusted_registry",
            ],
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{pattern}: {stderr}");
        assert!(
            stderr.contains("'registry.example.com' with --broad"),
            "{pattern}: {stderr}"
        );
    }
    for pattern in ["*registry.example.com", "registry.*.com"] {
        let output = tirith(
            &state,
            &[
                "trust",
                "add",
                pattern,
                "--broad",
                "--rule",
                "docker_untrusted_registry",
            ],
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{pattern}: {stderr}");
        assert!(stderr.contains("leading '*.' label"), "{pattern}: {stderr}");
    }
    // Nothing was recorded by the refused patterns.
    assert_registry_warning(
        &state,
        "docker pull registry.example.com/group/image:latest",
    );

    let output = tirith(
        &state,
        &[
            "trust",
            "add",
            "registry.example.com",
            "--broad",
            "--rule",
            "docker_untrusted_registry",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for input in [
        "docker pull registry.example.com/group/image:latest",
        "docker pull registry.example.com/image:1.0",
    ] {
        let (action, rules) = check(&state, input);
        assert_eq!(action, "allow", "{input}: {rules:?}");
    }
    for input in [
        "docker pull evil.example/registry.example.com/image:latest",
        "docker pull registry.example.com.evil.example/x:1",
    ] {
        assert_registry_warning(&state, input);
    }
}

/// CORE-5: a `host/*` entry that 0.4.x stored in the legacy trust store never
/// matched. `trust list` and `trust migrate` name the exact remedy instead of
/// a generic "invalid", migrate converts nothing on the operator's behalf, and
/// running the named remedy gives the host grant that does match.
#[test]
fn legacy_star_grant_reports_the_remedy_and_the_remedy_works() {
    let state = GlobalStateGuard::new().unwrap();
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        config.join("trust.json"),
        r#"{"version":1,"entries":[{"pattern":"registry.example.com/*","rule_id":"docker_untrusted_registry","ttl_expires":null,"added":"2026-01-01T00:00:00Z","source":"cli"}]}"#,
    )
    .unwrap();
    let remove = "tirith trust remove 'registry.example.com/*' --rule 'docker_untrusted_registry' --scope user";
    let add = "tirith trust add 'registry.example.com' --broad --rule 'docker_untrusted_registry'";

    // The dead entry never allowed anything.
    assert_registry_warning(
        &state,
        "docker pull registry.example.com/group/image:latest",
    );

    let listed = tirith(&state, &["trust", "list", "--scope", "user"]);
    let stderr = String::from_utf8_lossy(&listed.stderr);
    assert!(listed.status.success(), "{stderr}");
    assert!(stderr.contains("wildcard_never_matches"), "{stderr}");
    assert!(stderr.contains(remove) && stderr.contains(add), "{stderr}");
    assert!(!stderr.contains("use tirith trust migrate"), "{stderr}");

    let migrated = tirith(&state, &["trust", "migrate", "--scope", "user"]);
    let stderr = String::from_utf8_lossy(&migrated.stderr);
    assert!(migrated.status.success(), "{stderr}");
    assert!(stderr.contains("1 legacy entry left in place"), "{stderr}");
    assert!(stderr.contains(remove) && stderr.contains(add), "{stderr}");
    let json = tirith(&state, &["trust", "migrate", "--scope", "user", "--json"]);
    let value: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(
        value["skipped"][0]["state_reason"],
        "wildcard_never_matches"
    );
    assert!(value["migrated_ids"].as_array().unwrap().is_empty());
    // Still nothing allowed: migrate did not convert the entry.
    assert_registry_warning(
        &state,
        "docker pull registry.example.com/group/image:latest",
    );

    let explained = tirith(&state, &["trust", "explain", "registry.example.com/*"]);
    let stderr = String::from_utf8_lossy(&explained.stderr);
    assert!(explained.status.success(), "{stderr}");
    assert!(stderr.contains(remove), "{stderr}");
    assert!(stderr.contains("Target pattern:"), "{stderr}");

    // Run the remedy exactly as printed.
    let removed = tirith(
        &state,
        &[
            "trust",
            "remove",
            "registry.example.com/*",
            "--rule",
            "docker_untrusted_registry",
            "--scope",
            "user",
        ],
    );
    assert!(
        removed.status.success(),
        "{}",
        String::from_utf8_lossy(&removed.stderr)
    );
    let added = tirith(
        &state,
        &[
            "trust",
            "add",
            "registry.example.com",
            "--broad",
            "--rule",
            "docker_untrusted_registry",
        ],
    );
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    let (action, rules) = check(
        &state,
        "docker pull registry.example.com/group/image:latest",
    );
    assert_eq!(action, "allow", "{rules:?}");
    assert_registry_warning(&state, "docker pull registry.example.com.evil.example/x:1");
    let listed = tirith(&state, &["trust", "list", "--scope", "user"]);
    let stderr = String::from_utf8_lossy(&listed.stderr);
    assert!(!stderr.contains("wildcard_never_matches"), "{stderr}");
}

/// CORE-5: `policy validate` reports a `host/*` allowlist entry (which never
/// matches) with the entry that does, as a warning, instead of "valid".
#[test]
fn policy_validate_reports_star_allowlist_entries_with_the_host_entry() {
    let state = GlobalStateGuard::new().unwrap();
    let path = state.roots().cwd.join("policy.yaml");
    std::fs::write(
        &path,
        "allowlist:\n  - registry.example.com/*\nblocklist:\n  - '*.bad.example'\n",
    )
    .unwrap();
    let path = path.to_str().unwrap();
    let output = tirith(&state, &["policy", "validate", path]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "warnings only: {stderr}");
    assert!(!stderr.contains("valid, no issues"), "{stderr}");
    // Human output names the problem with fixed text only (policy values are
    // never echoed there); the entry and its replacement are in --json.
    assert_eq!(
        stderr
            .matches("allowlist or blocklist entry never matches: its '*' is not a wildcard")
            .count(),
        2,
        "{stderr}"
    );
    assert!(!stderr.contains("registry.example.com"), "{stderr}");
    let json = tirith(&state, &["policy", "validate", path, "--json"]);
    let value: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(value["valid"], true);
    assert_eq!(value["warning_count"], 2);
    let messages: Vec<&str> = value["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|issue| issue["message"].as_str().unwrap())
        .collect();
    assert!(
        messages.iter().any(|m| m
            .contains("allowlist entry 'registry.example.com/*' never matches")
            && m.contains("use 'registry.example.com'")),
        "{messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("use 'bad.example' to block")),
        "{messages:?}"
    );

    std::fs::write(path, "allowlist:\n  - registry.example.com\n").unwrap();
    let output = tirith(&state, &["policy", "validate", path]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("valid, no issues"), "{stderr}");
}
