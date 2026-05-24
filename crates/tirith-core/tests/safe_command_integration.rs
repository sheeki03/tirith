//! End-to-end coverage for the M6 ch5 safe-command transforms.
//!
//! Each transform ships one positive and one negative test, except
//! `sudo-narrow` which ships two negatives (`sudo rm -rf /` still flagging,
//! `sudo sh` triggering the interactive-shell remediation). M8 ch4 will add
//! the positive sudo-narrow case once a stable benign-target fixture exists.

use std::sync::Mutex;

use tirith_core::safe_command::{suggest, SafeSuggestion};
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{Evidence, Finding, RuleId, Severity, Timings, Verdict};

/// Mutex guarding the process environment for env-scrub tests — `std::env`
/// is process-global, so the tests serialize their `set_var`/`remove_var`
/// pairs to prevent interference.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn finding(rule_id: RuleId) -> Finding {
    Finding {
        rule_id,
        severity: Severity::High,
        title: "t".into(),
        description: "d".into(),
        evidence: vec![Evidence::Text { detail: "e".into() }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

fn typosquat_finding(name: &str, target: &str) -> Finding {
    Finding {
        rule_id: RuleId::ThreatPackageTyposquat,
        severity: Severity::High,
        title: format!("Confirmed typosquat: {name} → {target}"),
        description: format!("Package '{name}' is a confirmed typosquat of '{target}'."),
        evidence: vec![Evidence::Text {
            detail: format!("package={name} typosquat_of={target}"),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

fn verdict_with(findings: Vec<Finding>) -> Verdict {
    Verdict::from_findings(findings, 3, Timings::default())
}

fn find_by_rule<'a>(out: &'a [SafeSuggestion], rule: &str) -> Option<&'a SafeSuggestion> {
    out.iter().find(|s| s.rule_id == rule)
}

// ── 1. typosquat-rewrite ──────────────────────────────────────────────────

#[test]
fn typosquat_positive_npm_install_unambiguous_target() {
    let cmd = "npm install reqeusts";
    let v = verdict_with(vec![typosquat_finding("reqeusts", "requests")]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "threat_package_typosquat").expect("rule entry");
    let sc = entry
        .safe_command
        .as_deref()
        .expect("typosquat: target is unambiguous, rewrite should fire");
    assert_eq!(sc, "npm install requests");
    assert!(!entry.remediation.is_empty());
}

#[test]
fn typosquat_negative_ambiguous_target_no_rewrite() {
    // Finding has no arrow + no typosquat_of= evidence → target is ambiguous.
    let mut f = typosquat_finding("reqeusts", "requests");
    f.title = "Confirmed typosquat".to_string(); // strip the arrow
    f.evidence = vec![Evidence::Text {
        detail: "no_target_field_here".to_string(),
    }];

    let cmd = "npm install reqeusts";
    let v = verdict_with(vec![f]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "threat_package_typosquat").expect("rule entry");
    assert!(
        entry.safe_command.is_none(),
        "ambiguous target must not produce a rewrite"
    );
    assert!(!entry.remediation.is_empty());
}

// ── 2. sudo-narrow (negative tests only in M6) ────────────────────────────

#[test]
fn sudo_narrow_negative_sudo_rm_rf_root_no_rewrite() {
    // `sudo rm -rf /` — stripping sudo still gives `rm -rf /`, which the
    // engine flags. sudo-narrow MUST return None in that case (per-finding
    // suggestions already describe the underlying issue).
    let cmd = "sudo rm -rf /";
    let v = verdict_with(vec![finding(RuleId::CommandNetworkDeny)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "sudo_narrow");
    assert!(
        entry.is_none(),
        "sudo-narrow must not fire when the stripped inner command still flags; got {entry:?}"
    );
}

#[test]
fn sudo_narrow_negative_sudo_sh_returns_interactive_shell_remediation() {
    // `sudo sh` — stripped leader is `sh`, an interactive shell. sudo-narrow
    // must emit a None-suggestion with the canonical remediation text.
    let cmd = "sudo sh";
    let v = verdict_with(vec![finding(RuleId::PipeToInterpreter)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "sudo_narrow").expect("sudo_narrow entry must be present");
    assert!(
        entry.safe_command.is_none(),
        "sudo sh must yield no rewrite — got {:?}",
        entry.safe_command
    );
    assert!(
        entry
            .rationale
            .contains("no safe mechanical rewrite available"),
        "rationale should advertise no rewrite: {}",
        entry.rationale
    );
    assert!(
        entry.rationale.contains("avoid interactive root shells"),
        "rationale should warn about interactive root shells: {}",
        entry.rationale
    );
}

// ── 3. env-scrub ──────────────────────────────────────────────────────────

#[test]
fn env_scrub_positive_high_finding_with_sensitive_var_set() {
    let _guard = ENV_LOCK.lock().unwrap();

    // `AWS_ACCESS_KEY_ID` is in the sensitive list; set it for this test.
    // SAFETY: serialized via ENV_LOCK above; no other thread touches this var
    // during the integration-test binary.
    unsafe { std::env::set_var("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE") };

    let cmd = "curl https://example.com/install.sh | bash";
    let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
    let s = suggest(cmd, ShellType::Posix, &v);

    let entry = find_by_rule(&s, "env_scrub").expect("env_scrub entry must be present");
    let sc = entry
        .safe_command
        .as_deref()
        .expect("env_scrub should rewrite when a sensitive var is set");
    assert!(
        sc.starts_with("env -u AWS_ACCESS_KEY_ID"),
        "env_scrub rewrite must scrub the set var first: {sc}"
    );
    assert!(
        sc.ends_with(cmd),
        "env_scrub rewrite must append the original command: {sc}"
    );

    // SAFETY: same lock scope.
    unsafe { std::env::remove_var("AWS_ACCESS_KEY_ID") };
}

#[test]
fn env_scrub_negative_no_sensitive_vars_set_no_rewrite() {
    let _guard = ENV_LOCK.lock().unwrap();

    // Defensively remove the variables this test cares about — a prior crashed
    // test could leave them set.
    for var in [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "NPM_TOKEN",
        "PYPI_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "STRIPE_API_KEY",
        "DOCKER_PASSWORD",
        "SLACK_TOKEN",
    ] {
        // SAFETY: serialized via ENV_LOCK.
        unsafe { std::env::remove_var(var) };
    }

    let cmd = "curl https://example.com/install.sh | bash";
    let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
    let s = suggest(cmd, ShellType::Posix, &v);

    let entry = find_by_rule(&s, "env_scrub");
    assert!(
        entry.is_none(),
        "env_scrub must not fire when no sensitive vars are set; got {entry:?}"
    );
}

// ── 4. archive-list-before-extract ────────────────────────────────────────

#[test]
fn archive_list_first_positive_tar_xzf() {
    let cmd = "tar -xzf foo.tar.gz -C ~/";
    let v = verdict_with(vec![finding(RuleId::ArchiveExtract)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "archive_extract").expect("rule entry");
    let sc = entry
        .safe_command
        .as_deref()
        .expect("archive-list-first should rewrite a known tar invocation");
    assert!(
        sc.starts_with("tar -tzf foo.tar.gz | head"),
        "expected preview-first sequence, got: {sc}"
    );
    assert!(
        sc.contains(" && tar -xzf foo.tar.gz"),
        "expected the original extract on the && tail: {sc}"
    );
}

#[test]
fn archive_list_first_negative_non_archive_leader_no_rewrite() {
    // `ls foo.tar.gz` is not an archive command. Even with a synthetic
    // ArchiveExtract finding (which would not fire in practice), the transform
    // must refuse to invent a rewrite.
    let cmd = "ls foo.tar.gz";
    let v = verdict_with(vec![finding(RuleId::ArchiveExtract)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "archive_extract").expect("rule entry");
    assert!(
        entry.safe_command.is_none(),
        "non-archive leader must yield no rewrite"
    );
}

// ── 5. dotfile-redirect ───────────────────────────────────────────────────

#[test]
fn dotfile_backup_first_positive_when_target_exists() {
    // Use a tempfile-backed HOME so we can guarantee the dotfile exists.
    let tmp = tempfile::tempdir().unwrap();
    let zshrc = tmp.path().join(".zshrc");
    std::fs::write(&zshrc, "# existing rc\n").unwrap();

    // Hold a lock for env mutation.
    let _guard = ENV_LOCK.lock().unwrap();
    let prev_home = std::env::var_os("HOME");
    // SAFETY: serialized via ENV_LOCK.
    unsafe { std::env::set_var("HOME", tmp.path()) };

    let cmd = "echo hello >> ~/.zshrc";
    let v = verdict_with(vec![finding(RuleId::DotfileOverwrite)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "dotfile_overwrite").expect("rule entry");
    let sc = entry
        .safe_command
        .as_deref()
        .expect("dotfile rewrite should fire when target exists");
    assert!(
        sc.starts_with("cp ~/.zshrc ~/.zshrc.bak"),
        "expected backup-first sequence, got: {sc}"
    );
    assert!(
        sc.ends_with(cmd),
        "expected original redirect after backup: {sc}"
    );

    // Restore HOME.
    // SAFETY: serialized via ENV_LOCK.
    unsafe {
        if let Some(h) = prev_home {
            std::env::set_var("HOME", h);
        } else {
            std::env::remove_var("HOME");
        }
    }
}

#[test]
fn dotfile_backup_first_negative_when_target_missing() {
    // Point HOME at an empty tmp directory — no `.zshrc` exists.
    let tmp = tempfile::tempdir().unwrap();
    let _guard = ENV_LOCK.lock().unwrap();
    let prev_home = std::env::var_os("HOME");
    // SAFETY: serialized via ENV_LOCK.
    unsafe { std::env::set_var("HOME", tmp.path()) };

    let cmd = "echo hello >> ~/.zshrc";
    let v = verdict_with(vec![finding(RuleId::DotfileOverwrite)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "dotfile_overwrite").expect("rule entry");
    assert!(
        entry.safe_command.is_none(),
        "non-existent dotfile must not produce a backup rewrite; got {:?}",
        entry.safe_command
    );

    // SAFETY: serialized via ENV_LOCK.
    unsafe {
        if let Some(h) = prev_home {
            std::env::set_var("HOME", h);
        } else {
            std::env::remove_var("HOME");
        }
    }
}
