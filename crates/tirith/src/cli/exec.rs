//! `tirith exec check|provenance` (M9 ch5) — the COLD, off-hot-path provenance
//! surface. `check <bin>` resolves a bare name on `$PATH` (first hit) and reports
//! provenance + shadowing; `provenance <path>` inspects a path directly. Both run
//! the expensive probes (stat, `file --brief`, `codesign`) that NEVER run on the
//! engine hot path — see [`tirith_core::exec_provenance`].

use std::io::Write;
use std::path::{Path, PathBuf};

use tirith_core::exec_provenance::{self, Provenance};
use tirith_core::path_audit;
use tirith_core::policy::{self as policy_mod, Policy};
use tirith_core::verdict::{Finding, Severity};

use super::write_json_stdout;

/// `tirith exec guard on|off|status` — flip / report `policy.exec_guard_enabled`.
///
/// When ON, the exec hot path runs the three cheap leader-provenance rules
/// (`ExecInTmp`, `ExecInRepoBin`, `PathWritableDirBeforeSystem`); off by default.
/// Mirrors `tirith hooks guard` (append-or-rewrite one line in local `policy.yaml`, 0600).
pub fn guard(action: &str, json: bool) -> i32 {
    let enable = match action {
        "on" | "enable" | "true" => true,
        "off" | "disable" | "false" => false,
        "status" => return guard_status(json),
        other => {
            eprintln!("tirith exec guard: unknown action '{other}' (expected on|off|status)");
            return 2;
        }
    };

    let target_path = match resolve_policy_path_for_guard() {
        Ok(p) => p,
        Err(code) => return code,
    };

    if let Err(e) = update_policy_guard_key(&target_path, enable) {
        eprintln!(
            "tirith exec guard: failed to update {}: {e}",
            target_path.display()
        );
        return 1;
    }

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "exec_guard_enabled": enable,
            "policy_path": target_path.display().to_string(),
        });
        if !write_json_stdout(&out, "tirith exec guard: failed to write JSON output") {
            return 1;
        }
    } else {
        eprintln!(
            "tirith exec guard: {} (written to {})",
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
            "exec_guard_enabled": policy.exec_guard_enabled,
            "policy_path": policy.path,
        });
        if !write_json_stdout(&out, "tirith exec guard: failed to write JSON output") {
            return 1;
        }
    } else {
        eprintln!(
            "tirith exec guard: {}",
            if policy.exec_guard_enabled {
                "ON"
            } else {
                "OFF"
            }
        );
        if !policy.exec_guard_enabled {
            eprintln!(
                "  (when ON, a command whose leader resolves under /tmp, inside the repo, or \
                 from a user-writable PATH dir ahead of the system path will WARN on the exec \
                 hot path. Run `tirith exec check <bin>` for the full cold provenance.)"
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
        eprintln!("tirith exec guard: could not resolve user config dir");
        1
    })?;
    Ok(user.join("policy.yaml"))
}

/// Idempotently set the `exec_guard_enabled` line in a policy YAML, leaving
/// other lines untouched (mirrors `cli::hooks::update_policy_guard_key`).
fn update_policy_guard_key(path: &std::path::Path, enable: bool) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let new_line = format!("exec_guard_enabled: {enable}");

    let mut out = String::new();
    let mut replaced = false;
    for line in existing.lines() {
        if line.trim_start().starts_with("exec_guard_enabled:") {
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

/// `tirith exec check <bin>` — resolve `bin` on `$PATH`, report provenance +
/// shadowing. Exit 1 on any High finding, 0 otherwise, 2 if `bin` does not resolve.
pub fn check(bin: &str, json: bool) -> i32 {
    let path_value = std::env::var("PATH").unwrap_or_default();
    let hits = path_audit::which_all(bin, &path_value);

    let Some(first) = hits.first().cloned() else {
        if json {
            let body = serde_json::json!({
                "schema_version": 1,
                "command": bin,
                "resolved": false,
                "message": "not found on PATH",
            });
            let _ = write_json_stdout(&body, "tirith exec check: failed to write JSON output");
        } else {
            eprintln!("tirith exec check: `{bin}` was not found on $PATH.");
        }
        return 2;
    };

    let prov = exec_provenance::provenance_of(&first);
    let mut findings = prov.findings();
    if let Some(shadow) = exec_provenance::shadow_finding(bin, &first) {
        findings.push(shadow);
    }

    if json {
        let body = serde_json::json!({
            "schema_version": 1,
            "command": bin,
            "resolved": true,
            "resolved_path": first.display().to_string(),
            "all_path_hits": hits.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "provenance": prov,
            "findings": findings,
        });
        if !write_json_stdout(&body, "tirith exec check: failed to write JSON output") {
            return 1;
        }
    } else {
        print_human_check(bin, &first, &hits, &prov, &findings);
    }

    exit_for(&findings)
}

/// `tirith exec provenance <path>` — inspect a path's provenance. Exit 1 on a
/// High finding, 0 otherwise, 2 if the path is not a file.
pub fn provenance(path: &str, json: bool) -> i32 {
    let p = expand_path(path);
    let prov = exec_provenance::provenance_of(&p);

    if !prov.exists {
        if json {
            let body = serde_json::json!({
                "schema_version": 1,
                "path": p.display().to_string(),
                "exists": false,
            });
            let _ = write_json_stdout(&body, "tirith exec provenance: failed to write JSON output");
        } else {
            eprintln!(
                "tirith exec provenance: `{}` is not a regular file.",
                p.display()
            );
        }
        return 2;
    }

    let findings = prov.findings();

    if json {
        let body = serde_json::json!({
            "schema_version": 1,
            "path": p.display().to_string(),
            "provenance": prov,
            "findings": findings,
        });
        if !write_json_stdout(&body, "tirith exec provenance: failed to write JSON output") {
            return 1;
        }
    } else {
        print_human_provenance(&prov, &findings);
    }

    exit_for(&findings)
}

/// Expand a leading `~/` against the home dir; otherwise return the path as-is.
fn expand_path(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

/// Exit 1 when any High/Critical finding is present, else 0.
fn exit_for(findings: &[Finding]) -> i32 {
    let high = findings
        .iter()
        .any(|f| matches!(f.severity, Severity::High | Severity::Critical));
    if high {
        1
    } else {
        0
    }
}

fn print_human_check(
    bin: &str,
    resolved: &Path,
    hits: &[PathBuf],
    prov: &Provenance,
    findings: &[Finding],
) {
    eprintln!("tirith exec check `{bin}`:");
    eprintln!("  resolves to: {}", resolved.display());
    if hits.len() > 1 {
        eprintln!("  also on PATH ({} total):", hits.len());
        for h in hits.iter().skip(1) {
            eprintln!("    {}", h.display());
        }
    }
    print_provenance_body(prov);
    print_findings(findings);
}

fn print_human_provenance(prov: &Provenance, findings: &[Finding]) {
    eprintln!("tirith exec provenance `{}`:", prov.path);
    print_provenance_body(prov);
    print_findings(findings);
}

fn print_provenance_body(prov: &Provenance) {
    eprintln!(
        "  package manager: {}",
        prov.package_owner
            .as_ref()
            .map(|o| format!("{} ({})", o.manager, o.root))
            .unwrap_or_else(|| "none (not under a known install root)".to_string())
    );
    eprintln!("  signature: {}", prov.signature.as_str());
    eprintln!(
        "  file type: {}",
        prov.file_type.as_deref().unwrap_or("unknown")
    );
    if let Some(mode) = &prov.mode {
        eprintln!(
            "  mode: {mode}{}",
            if prov.world_writable {
                " (WORLD-WRITABLE)"
            } else {
                ""
            }
        );
    }
    if let Some(secs) = prov.modified_secs_ago {
        eprintln!(
            "  modified: {secs}s ago{}",
            if prov.recently_modified {
                " (RECENT — within 5 min)"
            } else {
                ""
            }
        );
    }
}

fn print_findings(findings: &[Finding]) {
    if findings.is_empty() {
        eprintln!("  no provenance concerns.");
        return;
    }
    eprintln!("\n  {} finding(s):", findings.len());
    for f in findings {
        eprintln!("    [{}] {} — {}", f.severity, f.rule_id, f.title);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_path_handles_tilde_and_plain() {
        assert_eq!(expand_path("/usr/bin/git"), PathBuf::from("/usr/bin/git"));
        if let Some(home) = home::home_dir() {
            assert_eq!(expand_path("~/bin/x"), home.join("bin/x"));
        }
    }

    #[test]
    fn exit_for_high_is_1_else_0() {
        let high = vec![Finding {
            rule_id: tirith_core::verdict::RuleId::ExecWorldWritable,
            severity: Severity::High,
            title: "t".into(),
            description: "d".into(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }];
        assert_eq!(exit_for(&high), 1);
        assert_eq!(exit_for(&[]), 0);
    }

    #[test]
    fn check_nonexistent_command_exits_2() {
        // A command guaranteed not on PATH → exit 2 (not resolved).
        assert_eq!(check("tirith-no-such-bin-xyz-9999", true), 2);
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
        assert!(content.contains("exec_guard_enabled: true"), "{content}");
        assert!(content.contains("paranoia: 2"), "other lines preserved");

        // Flip off — must REPLACE the existing line, not duplicate it.
        update_policy_guard_key(&path, false).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("exec_guard_enabled: false"), "{content}");
        assert_eq!(
            content.matches("exec_guard_enabled:").count(),
            1,
            "must not duplicate the key"
        );

        // The written YAML must deserialize back into the field the engine
        // reads at its tier-1 force-past gate (`policy.exec_guard_enabled`).
        update_policy_guard_key(&path, true).unwrap();
        let yaml = std::fs::read_to_string(&path).unwrap();
        let parsed = Policy::try_parse_yaml(&yaml).expect("policy YAML must parse");
        assert!(
            parsed.exec_guard_enabled,
            "exec_guard_enabled must round-trip to the engine-readable Policy"
        );
    }
}
