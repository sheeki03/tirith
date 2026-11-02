//! Agent-workload corpus regression (`tests/fixtures/agent_corpus.json`).
//!
//! Every row runs through the real binary the way an agent integration calls
//! it (`check --json --non-interactive --shell posix --offline`, plus
//! `--no-daemon`), in a fresh home with no threat DB and no package-lookup
//! cache, so the result is deterministic and offline. Ordinary agent commands
//! must not be hard-blocked (`at_most`), and no attack may fall below the
//! verdict it reached when this corpus was adopted (`at_least`). Each
//! exception carries its reason in the data file.
//!
//! Unix only: the corpus is POSIX shell text with home-relative paths; the
//! changed shapes are also pinned by golden fixtures that run everywhere.
#![cfg(unix)]

use std::path::Path;
use std::process::{Command, Stdio};

#[derive(serde::Deserialize)]
struct Corpus {
    rows: Vec<Row>,
}

#[derive(serde::Deserialize)]
struct Row {
    id: String,
    expected: String,
    cmd: String,
    #[serde(default)]
    at_least: Option<String>,
    #[serde(default)]
    at_most: Option<String>,
    #[serde(default)]
    why: Option<String>,
}

fn rank(action: &str) -> u8 {
    match action {
        "allow" => 0,
        "warn" | "warn_ack" => 1,
        "block" => 2,
        other => panic!("unknown action {other:?}"),
    }
}

fn check(home: &Path, cwd: &Path, command: &str) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tirith"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("TIRITH") {
            cmd.env_remove(key);
        }
    }
    let out = cmd
        .args([
            "check",
            "--json",
            "--non-interactive",
            "--no-daemon",
            "--offline",
            "--shell",
            "posix",
            "--",
            command,
        ])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("XDG_RUNTIME_DIR", home.join("runtime"))
        .env("TIRITH_LOG", "0")
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .expect("run tirith check");
    let verdict: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|error| {
        panic!(
            "{command:?}: no JSON verdict ({error}); rc {:?}, stderr {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let action = verdict["action"].as_str().expect("action").to_string();
    let expected_rc = match rank(&action) {
        0 => 0,
        1 => 2,
        _ => 1,
    };
    assert_eq!(
        out.status.code(),
        Some(expected_rc),
        "{command:?}: exit code does not match action {action}"
    );
    action
}

#[test]
fn agent_corpus_benign_commands_are_not_blocked_and_attacks_keep_their_verdict() {
    let corpus: Corpus = serde_json::from_str(include_str!("fixtures/agent_corpus.json"))
        .expect("agent corpus JSON");
    assert!(corpus.rows.len() >= 90, "corpus truncated");

    let home = tempfile::tempdir().expect("home");
    for dir in ["config", "data", "state", "cache", "runtime"] {
        std::fs::create_dir_all(home.path().join(dir)).expect("home dir");
    }
    let cwd = tempfile::tempdir().expect("cwd");

    let rows = &corpus.rows;
    let workers = 4;
    let actions: Vec<(usize, String)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|worker| {
                let (home, cwd) = (home.path(), cwd.path());
                scope.spawn(move || {
                    rows.iter()
                        .enumerate()
                        .filter(|(index, _)| index % workers == worker)
                        .map(|(index, row)| (index, check(home, cwd, &row.cmd)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("worker"))
            .collect()
    });

    let mut failures = Vec::new();
    for (index, action) in actions {
        let row = &rows[index];
        match row.expected.as_str() {
            "attack" => {
                let floor = row.at_least.as_deref().expect("attack row needs at_least");
                assert!(
                    floor != "allow" || row.why.is_some(),
                    "{}: an allow floor needs a reason",
                    row.id
                );
                if rank(&action) < rank(floor) {
                    failures.push(format!(
                        "{} attack {action} (needs at least {floor}): {:?}",
                        row.id, row.cmd
                    ));
                }
            }
            "benign" => {
                let ceiling = row.at_most.as_deref().expect("benign row needs at_most");
                assert!(
                    ceiling != "block" || row.why.is_some(),
                    "{}: a block ceiling needs a reason",
                    row.id
                );
                if rank(&action) > rank(ceiling) {
                    failures.push(format!(
                        "{} benign {action} (at most {ceiling}): {:?}",
                        row.id, row.cmd
                    ));
                }
            }
            other => panic!("{}: unknown expectation {other}", row.id),
        }
    }
    assert!(
        failures.is_empty(),
        "agent corpus regressions:\n  {}",
        failures.join("\n  ")
    );
}
