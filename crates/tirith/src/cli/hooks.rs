//! `tirith hooks scan|guard|explain` (M9 ch6).
//!
//! Thin presenter over [`tirith_core::repo_hooks`] (inventory + classification
//! live in the library): output, the `policy.hooks_guard_enabled` toggle, and
//! body redaction.
//!
//! - `scan` — inventory + risk-classify every hook/automation surface in the
//!   repo (static read only; never executes a hook). Exit 1 if any High/Critical.
//! - `guard on|off|status` — flip `policy.hooks_guard_enabled` (append-or-rewrite
//!   one line, like `tirith env guard`); ON makes the exec path warn when a
//!   hook-triggering command runs in a repo whose hooks network/read-creds/sudo.
//! - `explain <name>` — show every matching surface's body, CREDENTIAL-REDACTED,
//!   plus findings.

use std::io::Write;
use std::path::PathBuf;

use tirith_core::policy::{self as policy_mod, Policy};
use tirith_core::redact::redact;
use tirith_core::repo_hooks::{self, HookCategory, RepoHookEntry, RepoHookFinding, RepoHookScan};
use tirith_core::verdict::Severity;

use super::write_json_stdout;

/// `tirith hooks scan` — inventory + classify. Exit 1 if any High/Critical.
pub fn scan(json: bool) -> i32 {
    let scan = repo_hooks::scan_for_cwd();
    let any_high = scan.has_high();

    if json {
        let body = scan_json_body(&scan);
        if !write_json_stdout(&body, "tirith hooks scan: failed to write JSON output") {
            return 1;
        }
    } else {
        print_human_scan(&scan);
    }

    if any_high {
        1
    } else {
        0
    }
}

fn print_human_scan(scan: &RepoHookScan) {
    let (hooks_n, automation_n) = scan.category_counts();
    match &scan.repo_root {
        Some(root) => eprintln!("tirith hooks: scanning {root}"),
        None => {
            eprintln!("tirith hooks: no repository / scan root found (no .git boundary).");
            return;
        }
    }
    eprintln!(
        "  {} surface(s): {hooks_n} hook, {automation_n} automation.\n",
        scan.entries.len()
    );

    if scan.entries.is_empty() {
        eprintln!("tirith hooks: no hooks or automation surfaces found.");
        return;
    }

    // Hooks (the auto-exec attack surface) first, then automation.
    print_category(scan, HookCategory::Hook, "Hooks (auto-executed):");
    print_category(scan, HookCategory::Automation, "Automation (run by hand):");

    let findings: Vec<&RepoHookFinding> = scan.all_findings();
    if findings.is_empty() {
        eprintln!("\ntirith hooks: no risky hooks / automation detected.");
        return;
    }
    let high = findings.iter().filter(|f| f.is_high()).count();
    eprintln!(
        "\ntirith hooks: {} finding(s) ({high} high).\n",
        findings.len()
    );
    for f in &findings {
        print_one_finding(f);
    }
    eprintln!("Run `tirith hooks explain <name>` to see a surface's body (redacted) + analysis.");
}

fn print_category(scan: &RepoHookScan, category: HookCategory, header: &str) {
    let in_cat: Vec<&RepoHookEntry> = scan
        .entries
        .iter()
        .filter(|e| e.category == category)
        .collect();
    if in_cat.is_empty() {
        return;
    }
    eprintln!("{header}");
    for e in in_cat {
        let risk = match e.max_severity() {
            Some(sev) => format!("[{}]", severity_label(sev)),
            None => "[clean]".to_string(),
        };
        eprintln!(
            "  {:<10} {:<22} {:<8} {}",
            e.provider.as_str(),
            e.name,
            risk,
            e.source_path.display(),
        );
    }
    eprintln!();
}

/// `tirith hooks guard on|off|status` — flip / report `policy.hooks_guard_enabled`.
pub fn guard(action: &str, json: bool) -> i32 {
    let enable = match action {
        "on" | "enable" | "true" => true,
        "off" | "disable" | "false" => false,
        "status" => return guard_status(json),
        other => {
            eprintln!("tirith hooks guard: unknown action '{other}' (expected on|off|status)");
            return 2;
        }
    };

    let target_path = match resolve_policy_path_for_guard() {
        Ok(p) => p,
        Err(code) => return code,
    };

    if let Err(e) = update_policy_guard_key(&target_path, enable) {
        eprintln!(
            "tirith hooks guard: failed to update {}: {e}",
            target_path.display()
        );
        return 1;
    }

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "hooks_guard_enabled": enable,
            "policy_path": target_path.display().to_string(),
        });
        if !write_json_stdout(&out, "tirith hooks guard: failed to write JSON output") {
            return 1;
        }
    } else {
        eprintln!(
            "tirith hooks guard: {} (written to {})",
            if enable { "ON" } else { "OFF" },
            target_path.display(),
        );
    }
    0
}

fn guard_status(json: bool) -> i32 {
    let policy = Policy::discover_partial(None);
    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "hooks_guard_enabled": policy.hooks_guard_enabled,
            "policy_path": policy.path,
        });
        if !write_json_stdout(&out, "tirith hooks guard: failed to write JSON output") {
            return 1;
        }
    } else {
        eprintln!(
            "tirith hooks guard: {}",
            if policy.hooks_guard_enabled {
                "ON"
            } else {
                "OFF"
            }
        );
        if !policy.hooks_guard_enabled {
            eprintln!(
                "  (when ON, `git commit` / `npm install` / `direnv allow` in a repo whose \
                 triggered hooks make a network call, read credentials, or use sudo will WARN.)"
            );
        }
    }
    0
}

fn resolve_policy_path_for_guard() -> Result<PathBuf, i32> {
    if let Some(existing) = policy_mod::discover_local_policy_path(None) {
        return Ok(existing);
    }
    let user = policy_mod::config_dir().ok_or_else(|| {
        eprintln!("tirith hooks guard: could not resolve user config dir");
        1
    })?;
    Ok(user.join("policy.yaml"))
}

/// Idempotently set the `hooks_guard_enabled` line (append-or-rewrite, never
/// touching other lines; mirrors `cli::env_guard::update_policy_guard_key`).
fn update_policy_guard_key(path: &std::path::Path, enable: bool) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let new_line = format!("hooks_guard_enabled: {enable}");

    let mut out = String::new();
    let mut replaced = false;
    for line in existing.lines() {
        if line.trim_start().starts_with("hooks_guard_enabled:") {
            out.push_str(&new_line);
            out.push('\n');
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&new_line);
        out.push('\n');
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(out.as_bytes())
}

/// `tirith hooks explain <name>` — show a surface's redacted body + analysis.
/// Exit 0 (informational), or 2 if the name is unknown.
pub fn explain(name: &str, json: bool) -> i32 {
    let matches = repo_hooks::explain_for_cwd(name);

    if json {
        let body = explain_json_body(name, &matches);
        if !write_json_stdout(&body, "tirith hooks explain: failed to write JSON output") {
            return 1;
        }
    } else {
        print_human_explain(name, &matches);
    }

    if matches.is_empty() {
        2
    } else {
        0
    }
}

fn print_human_explain(name: &str, matches: &[RepoHookEntry]) {
    if matches.is_empty() {
        eprintln!("tirith hooks: no hook or automation surface named `{name}` found.");
        eprintln!("  (run `tirith hooks scan` to list every surface in this repo.)");
        return;
    }

    eprintln!(
        "tirith hooks explain `{name}`: {} surface(s).\n",
        matches.len()
    );
    for e in matches {
        eprintln!(
            "  {} ({}) — {}",
            e.name,
            e.provider.as_str(),
            e.source_path.display(),
        );
        if e.body.trim().is_empty() {
            eprintln!("    body: (empty / not captured)");
        } else {
            // Redact before display — a hook body may inline a secret.
            let redacted = redact(&e.body);
            for line in redacted.lines() {
                eprintln!("    | {line}");
            }
        }
        eprintln!();
    }

    let findings: Vec<&RepoHookFinding> = matches.iter().flat_map(|e| e.findings.iter()).collect();
    if findings.is_empty() {
        eprintln!("Analysis: no risk rules fired for `{name}`.");
        return;
    }
    eprintln!("Analysis — {} finding(s):", findings.len());
    for f in &findings {
        print_one_finding(f);
    }
}

fn print_one_finding(f: &RepoHookFinding) {
    eprintln!(
        "  [{}] {}\n      surface:  {} ({})\n      location: {}\n      detail:   {}\n",
        severity_label(f.severity),
        f.rule_id,
        f.name,
        f.provider.as_str(),
        f.location,
        f.detail,
    );
}

fn severity_label(sev: Severity) -> &'static str {
    match sev {
        Severity::Info => "INFO",
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    }
}

fn scan_json_body(scan: &RepoHookScan) -> serde_json::Value {
    let findings = scan.all_findings();
    let high = findings.iter().filter(|f| f.is_high()).count();
    let (hooks_n, automation_n) = scan.category_counts();
    serde_json::json!({
        "schema_version": 1,
        "repo_root": scan.repo_root,
        "total_surfaces": scan.entries.len(),
        "hook_count": hooks_n,
        "automation_count": automation_n,
        "total_findings": findings.len(),
        "high_or_critical": high,
        "surfaces": scan.entries.iter().map(hook_entry_json).collect::<Vec<_>>(),
        "findings": findings,
    })
}

fn explain_json_body(name: &str, matches: &[RepoHookEntry]) -> serde_json::Value {
    let findings: Vec<&RepoHookFinding> = matches.iter().flat_map(|e| e.findings.iter()).collect();
    serde_json::json!({
        "schema_version": 1,
        "name": name,
        "found": !matches.is_empty(),
        "surfaces": matches.iter().map(hook_entry_json).collect::<Vec<_>>(),
        "findings": findings,
    })
}

/// Serialize an entry for JSON, body credential-redacted (it can inline a secret).
fn hook_entry_json(e: &RepoHookEntry) -> serde_json::Value {
    serde_json::json!({
        "name": e.name,
        "category": e.category.as_str(),
        "provider": e.provider.as_str(),
        "source_path": e.source_path.display().to_string(),
        "git_events": e.git_events,
        "body": redact(&e.body),
        "findings": e.findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_core::repo_hooks::{HookProvider, RepoHookEntry};

    fn sample_entry(name: &str, body: &str) -> RepoHookEntry {
        RepoHookEntry {
            name: name.to_string(),
            category: HookCategory::Hook,
            provider: HookProvider::Husky,
            source_path: std::path::PathBuf::from("/repo/.husky/pre-commit"),
            body: body.to_string(),
            git_events: vec![name.to_string()],
            findings: vec![],
        }
    }

    #[test]
    fn scan_json_body_redacts_body() {
        let scan = RepoHookScan {
            repo_root: Some("/repo".to_string()),
            entries: vec![sample_entry(
                "pre-commit",
                "cat ~/.aws/credentials AKIAIOSFODNN7EXAMPLE",
            )],
        };
        let body = scan_json_body(&scan);
        assert_eq!(body["total_surfaces"], 1);
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(
            !serialized.contains("AKIAIOSFODNN7EXAMPLE"),
            "hook body must be credential-redacted in JSON, got {serialized}"
        );
    }

    #[test]
    fn explain_json_body_marks_found() {
        let matches = vec![sample_entry("pre-commit", "npm test")];
        let body = explain_json_body("pre-commit", &matches);
        assert_eq!(body["found"], true);
        assert_eq!(body["name"], "pre-commit");

        let body2 = explain_json_body("nope", &[]);
        assert_eq!(body2["found"], false);
    }

    #[test]
    fn guard_unknown_action_returns_2() {
        assert_eq!(guard("bogus", false), 2);
    }

    #[test]
    fn update_policy_guard_key_appends_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, "paranoia: 2\nfail_mode: open\n").unwrap();

        update_policy_guard_key(&path, true).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("hooks_guard_enabled: true"), "{content}");
        assert!(content.contains("paranoia: 2"), "other lines preserved");

        update_policy_guard_key(&path, false).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("hooks_guard_enabled: false"), "{content}");
        assert_eq!(
            content.matches("hooks_guard_enabled:").count(),
            1,
            "must not duplicate the key"
        );
    }
}
