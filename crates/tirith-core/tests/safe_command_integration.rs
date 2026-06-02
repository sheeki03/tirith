//! End-to-end coverage for the M6 ch5 safe-command transforms. Each transform
//! ships a positive and a negative; `sudo-narrow` ships four (two M6 negatives
//! plus the M8 ch4 deferred positive and an interactive-shell-invariant negative).

use tirith_core::safe_command::{suggest, SafeSuggestion};
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{Evidence, Finding, RuleId, Severity, Timings, Verdict};

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
    // Stripping sudo still leaves a flagged `rm -rf /`, so sudo-narrow returns None.
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
    // Stripped leader `sh` is an interactive shell → None-suggestion + remediation.
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

// ── 2a. sudo-narrow (M8 ch4 deferred POSITIVE) ───────────────────────────
//
// The M6 ch5 positive was deferred for lack of a stable benign-target fixture.
// `sudo apt update` is the textbook case: `apt update` alone is Allow, so
// `build_sudo_narrow_suggestion`'s re-analysis of the stripped inner command
// produces the rewrite.

#[test]
fn sudo_narrow_positive_sudo_apt_update_strips_sudo() {
    // Inner `apt update` is Allow and `apt` is not a shell → rewrite to bare command.
    let cmd = "sudo apt update";
    // Any finding triggers the command-shape transforms.
    let v = verdict_with(vec![finding(RuleId::CommandNetworkDeny)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "sudo_narrow")
        .expect("sudo_narrow entry must be present for sudo apt update");
    let sc = entry
        .safe_command
        .as_deref()
        .expect("sudo apt update: stripped leader is benign, rewrite should fire");
    assert_eq!(
        sc, "apt update",
        "sudo-narrow should emit the bare inner command, got: {sc}"
    );
    assert!(
        entry.rationale.contains("safe to run without sudo"),
        "rationale should explain the strip: {}",
        entry.rationale
    );
}

// ── 2b. sudo-narrow (M8 ch4 NEGATIVE — interactive shell invariant) ──────
//
// Pins the M6 ch5 invariant — an interactive-shell leader NEVER yields a
// mechanical rewrite — this time driven by the M8 ch4 `SudoShellSpawn` finding
// to confirm the new sudo rules did not loosen it.

#[test]
fn sudo_narrow_negative_sudo_shell_spawn_keeps_no_rewrite() {
    let cmd = "sudo sh";
    let v = verdict_with(vec![finding(RuleId::SudoShellSpawn)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "sudo_narrow")
        .expect("sudo_narrow entry must be present for sudo sh + SudoShellSpawn");
    assert!(
        entry.safe_command.is_none(),
        "sudo sh + SudoShellSpawn must NOT mechanically rewrite — got {:?}",
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
        "rationale should mention interactive root shells: {}",
        entry.rationale
    );
}

// ── 3. env-scrub ──────────────────────────────────────────────────────────

// env_scrub end-to-end tests were dropped: they need `std::env::set_var`, whose
// libc environ mutation is not thread-safe on macOS/Windows even under our
// `ENV_LOCK`. Coverage is preserved by the `safe_command::tests`
// `is_simple_command_for_env_scrub` and `build_env_scrub_suggestion_*`
// direct-call unit tests, which avoid touching the real environment.

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
    // Preview uses universal `tar -tf` (magic-byte auto-detect), not `-tzf`,
    // so it works for every .tar.* variant.
    assert!(
        sc.starts_with("tar -tf foo.tar.gz | head"),
        "expected preview-first sequence with `tar -tf`, got: {sc}"
    );
    assert!(
        sc.contains(" && tar -xzf foo.tar.gz"),
        "expected the original extract on the && tail: {sc}"
    );
}

#[test]
fn archive_list_first_positive_tar_bz2_uses_universal_tf() {
    // .tar.bz2 must NOT use `-tjf` either — the universal `tar -tf` form
    // covers it via tar's magic-byte auto-detection.
    let cmd = "tar -xjf foo.tar.bz2";
    let v = verdict_with(vec![finding(RuleId::ArchiveExtract)]);
    let s = suggest(cmd, ShellType::Posix, &v);
    let entry = find_by_rule(&s, "archive_extract").expect("rule entry");
    let sc = entry.safe_command.as_deref().expect("rewrite expected");
    assert!(
        sc.starts_with("tar -tf foo.tar.bz2 | head"),
        "expected universal `tar -tf` preview for bz2, got: {sc}"
    );
}

#[test]
fn archive_list_first_negative_non_archive_leader_no_rewrite() {
    // `ls` is not an archive leader, so even a synthetic ArchiveExtract finding
    // must not produce a rewrite.
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

// dotfile-redirect end-to-end tests were dropped for the same libc-environ race
// as env_scrub (they had to set `HOME`). Structural correctness is pinned by the
// `dotfile_redirect_target` and `rewrite_dotfile_backup_first` unit tests in
// `safe_command::tests`; only the on-disk existence check loses dedicated coverage.
