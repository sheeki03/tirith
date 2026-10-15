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
