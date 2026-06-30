//! `tirith hygiene scan|fix` (M9 ch1).
//!
//! Thin presenter over [`tirith_core::hygiene`]. Detection lives entirely in
//! the library; this module is output + the (chmod-only) fixer.
//!
//! ## `scan`
//!
//! Walks `~/.ssh`, `~/.aws`, `~/.kube/config`, `~/.npmrc`, `~/.pypirc`,
//! `~/.gitconfig`, the common shell histories, and the current repo root for
//! stray `*.dump` / `*.sql` / `*.env*` files. Prints findings (human or JSON).
//!
//! Exit codes:
//! - `0` — no High/Critical finding (clean, or only Medium/Low).
//! - `1` — at least one High/Critical finding.
//!
//! ## `fix`
//!
//! **chmod-only.** The ONLY automated remediation is `chmod 0600` on a
//! loose-permission file ([`FixKind::Chmod`]). Content/location findings
//! ([`FixKind::Manual`]) are reported but NEVER auto-applied — tirith never
//! moves, edits, or deletes a file.
//!
//! - `--dry-run` — show what *would* change; apply nothing.
//! - default — per-finding interactive confirmation (via the shared
//!   [`crate::cli::confirm`] helper, which is TTY-gated).
//! - `--yes` — apply every chmod fix without prompting.
//!
//! Exit codes:
//! - `0` — nothing to fix, or all applicable fixes applied / dry-run completed.
//! - `1` — at least one chmod fix failed to apply.

use tirith_core::hygiene::{self, FixKind, HygieneFinding};
use tirith_core::verdict::Severity;

use super::{confirm, write_json_stdout};

/// `tirith hygiene scan` — walk the sensitive paths and report findings.
/// Exit 1 if any High/Critical finding is present, else 0.
pub fn scan(json: bool) -> i32 {
    let findings = hygiene::scan();
    let any_high = findings.iter().any(HygieneFinding::is_high);

    if json {
        let body = scan_json_body(&findings);
        if !write_json_stdout(&body, "tirith hygiene scan: failed to write JSON output") {
            return 1;
        }
    } else {
        print_human_scan(&findings);
    }

    if any_high {
        1
    } else {
        0
    }
}

/// `tirith hygiene fix` — apply chmod-only remediations.
///
/// `dry_run` shows what would change without applying. `yes` skips the
/// per-finding confirmation. `json` emits a machine-readable result.
pub fn fix(dry_run: bool, yes: bool, json: bool) -> i32 {
    let findings = hygiene::scan();

    // Partition into auto-fixable (chmod) vs manual.
    let fixable: Vec<&HygieneFinding> = findings
        .iter()
        .filter(|f| matches!(f.fix_kind, FixKind::Chmod { .. }))
        .collect();
    let manual: Vec<&HygieneFinding> = findings
        .iter()
        .filter(|f| matches!(f.fix_kind, FixKind::Manual))
        .collect();

    let mut results: Vec<FixResult> = Vec::new();
    let mut had_error = false;

    for f in &fixable {
        let FixKind::Chmod { mode } = f.fix_kind else {
            continue;
        };

        // The scanned path is untrusted (a repo-root stray file can be
        // attacker-named); sanitize the DISPLAY copy. `apply_chmod` still uses the
        // real `f.path`.
        let path = super::sanitize_for_human_output(&f.path.display().to_string(), false);

        if dry_run {
            results.push(FixResult::would_chmod(f, mode));
            if !json {
                eprintln!(
                    "would chmod {:04o} {}  ({} → {})",
                    mode, path, f.actual, f.expected
                );
            }
            continue;
        }

        // Per-finding confirmation unless --yes. `confirm` is TTY-gated and
        // returns false in a non-interactive context without --yes.
        let prompt = format!("chmod {mode:04o} {path}?");
        if !confirm(&prompt, yes) {
            results.push(FixResult::skipped(f, mode));
            if !json {
                eprintln!("skipped {path}");
            }
            continue;
        }

        match apply_chmod(&f.path, mode) {
            Ok(()) => {
                results.push(FixResult::applied(f, mode));
                if !json {
                    eprintln!("chmod {mode:04o} {path}");
                }
            }
            Err(e) => {
                had_error = true;
                results.push(FixResult::failed(f, mode, &e.to_string()));
                if !json {
                    eprintln!("FAILED chmod {mode:04o} {path}: {e}");
                }
            }
        }
    }

    if json {
        let body = fix_json_body(dry_run, &results, &manual);
        if !write_json_stdout(&body, "tirith hygiene fix: failed to write JSON output") {
            return 1;
        }
    } else {
        print_human_fix_summary(dry_run, &results, &manual);
    }

    if had_error {
        1
    } else {
        0
    }
}

// ─── chmod application ───────────────────────────────────────────────────────

/// Apply a chmod to `path`. On non-Unix this is a no-op success (perm rules
/// never fire there, so this branch is unreachable in practice).
#[cfg(unix)]
fn apply_chmod(path: &std::path::Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn apply_chmod(_path: &std::path::Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

// ─── human output ────────────────────────────────────────────────────────────

fn print_human_scan(findings: &[HygieneFinding]) {
    if findings.is_empty() {
        eprintln!("tirith hygiene: no issues found.");
        return;
    }

    let high = findings.iter().filter(|f| f.is_high()).count();
    let total = findings.len();
    eprintln!("tirith hygiene: {total} issue(s) found ({high} high/critical).\n");

    for f in findings {
        let auto = match f.fix_kind {
            FixKind::Chmod { mode } => format!("auto-fixable (chmod {mode:04o})"),
            FixKind::Manual => "manual fix".to_string(),
        };
        eprintln!(
            "  [{}] {}  ({})\n      path:     {}\n      expected: {}\n      actual:   {}\n      fix:      {}\n      {}\n",
            severity_label(f.severity),
            f.rule_id,
            f.category.as_str(),
            super::sanitize_for_human_output(&f.path.display().to_string(), false),
            f.expected,
            f.actual,
            f.fix_suggestion,
            auto,
        );
    }

    if findings
        .iter()
        .any(|f| matches!(f.fix_kind, FixKind::Chmod { .. }))
    {
        eprintln!("Run `tirith hygiene fix` to apply chmod fixes (interactive), or `--dry-run` to preview.");
    }
}

fn print_human_fix_summary(dry_run: bool, results: &[FixResult], manual: &[&HygieneFinding]) {
    let applied = results.iter().filter(|r| r.status == "applied").count();
    let would = results.iter().filter(|r| r.status == "would_chmod").count();
    let skipped = results.iter().filter(|r| r.status == "skipped").count();
    let failed = results.iter().filter(|r| r.status == "failed").count();

    if dry_run {
        eprintln!("\ntirith hygiene fix (dry-run): {would} chmod fix(es) would be applied.");
    } else {
        eprintln!("\ntirith hygiene fix: {applied} applied, {skipped} skipped, {failed} failed.");
    }

    if !manual.is_empty() {
        eprintln!(
            "\n{} finding(s) need a manual fix (tirith never moves/edits/deletes files):",
            manual.len()
        );
        for f in manual {
            eprintln!(
                "  [{}] {}\n      {}",
                severity_label(f.severity),
                super::sanitize_for_human_output(&f.path.display().to_string(), false),
                f.fix_suggestion
            );
        }
    }
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

// ─── JSON output ─────────────────────────────────────────────────────────────

fn scan_json_body(findings: &[HygieneFinding]) -> serde_json::Value {
    let high = findings.iter().filter(|f| f.is_high()).count();
    serde_json::json!({
        "schema_version": 1,
        "total": findings.len(),
        "high_or_critical": high,
        "findings": findings,
    })
}

/// One row of the `fix` result, JSON-serializable and reused by the human
/// summary's status tally.
#[derive(serde::Serialize)]
struct FixResult {
    rule_id: String,
    path: String,
    /// `applied` | `would_chmod` | `skipped` | `failed`.
    status: &'static str,
    mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl FixResult {
    fn base(f: &HygieneFinding, mode: u32, status: &'static str) -> Self {
        FixResult {
            rule_id: f.rule_id.to_string(),
            path: f.path.display().to_string(),
            status,
            mode: format!("{mode:04o}"),
            error: None,
        }
    }
    fn applied(f: &HygieneFinding, mode: u32) -> Self {
        Self::base(f, mode, "applied")
    }
    fn would_chmod(f: &HygieneFinding, mode: u32) -> Self {
        Self::base(f, mode, "would_chmod")
    }
    fn skipped(f: &HygieneFinding, mode: u32) -> Self {
        Self::base(f, mode, "skipped")
    }
    fn failed(f: &HygieneFinding, mode: u32, error: &str) -> Self {
        let mut r = Self::base(f, mode, "failed");
        r.error = Some(error.to_string());
        r
    }
}

fn fix_json_body(
    dry_run: bool,
    results: &[FixResult],
    manual: &[&HygieneFinding],
) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "dry_run": dry_run,
        "chmod_results": results,
        "manual_findings": manual,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn apply_chmod_sets_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, b"x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        apply_chmod(&path, 0o600).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn scan_json_body_counts_high() {
        // Empty input → zero counts, well-formed envelope.
        let body = scan_json_body(&[]);
        assert_eq!(body["total"], 0);
        assert_eq!(body["high_or_critical"], 0);
        assert!(body["findings"].is_array());
    }

    #[test]
    fn fix_json_body_shape() {
        let body = fix_json_body(true, &[], &[]);
        assert_eq!(body["dry_run"], true);
        assert!(body["chmod_results"].is_array());
        assert!(body["manual_findings"].is_array());
    }
}
