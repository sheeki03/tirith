//! `tirith preview -- "<cmd>"` — blast-radius simulator for `rm` / `mv` /
//! `chmod -R` / `find … -delete` / `rsync --delete`.
//!
//! Walks the filesystem (capped at depth 5 / 100k files), expands globs against
//! cwd, and reports file/dir/symlink counts, largest file, repo-escape, and
//! system-path writes.
//!
//! It does NOT execute the command and is NOT a sandbox. It is the ONLY surface
//! that walks the filesystem — the `tirith check` hot path never does; it runs
//! only the cheap string-shape subset (`blast_radius::cheap_check`).

use std::io::Write;
use std::path::PathBuf;

use tirith_core::blast_radius::{self, BlastReport};
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{action_from_findings, Action, Finding};

/// Entry point. `command` is the destructive command to simulate (already
/// joined from the trailing var-args). `json` selects machine output.
///
/// Exit codes follow the standard tirith convention derived from the merged
/// findings: 0 on Allow (no findings), 1 on Block (a High-severity finding
/// fired — e.g. system-path / outside-repo / a present-and-empty `$VAR/` glob),
/// 2 on Warn (Medium — `find -delete` / `rsync --delete` / symlinks). Info
/// findings (large file count, and an ABSENT-var `$VAR/` glob that tirith cannot
/// confirm is unset in the shell — see F2) do not change the exit code.
pub fn run(command: &str, json: bool) -> i32 {
    let command = command.trim();
    if command.is_empty() {
        eprintln!("tirith preview: no command given (usage: tirith preview -- \"rm -rf ./dist\")");
        return 2;
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cwd_str = cwd.display().to_string();
    let repo_root = tirith_core::policy::find_repo_root(Some(&cwd_str));

    let env_map = blast_radius::env_snapshot();

    // The full filesystem-walking simulation — the expensive surface only
    // `tirith preview` may run.
    let report = blast_radius::simulate(
        command,
        ShellType::Posix,
        &cwd,
        repo_root.as_deref(),
        &env_map,
    );

    // Merge the simulator-only findings with the cheap string-shape findings so
    // the preview surfaces the full picture.
    let mut findings = blast_radius::report_findings(&report);
    findings.extend(blast_radius::cheap_check(
        command,
        ShellType::Posix,
        &env_map,
    ));
    dedup_findings(&mut findings);

    let action = action_from_findings(&findings);

    if json {
        return emit_json(command, &report, repo_root.as_deref(), &findings, action);
    }

    print_human(command, &report, repo_root.is_some(), &findings, action);
    action.exit_code()
}

fn print_human(
    command: &str,
    report: &BlastReport,
    has_repo_root: bool,
    findings: &[Finding],
    action: Action,
) {
    let banner = match action {
        Action::Allow => "tirith preview: no blast-radius concerns",
        Action::Warn | Action::WarnAck => "tirith preview: review before running",
        Action::Block => "tirith preview: HIGH-IMPACT — do not run without review",
    };
    println!("{banner}");
    println!("  command: {command}");
    println!();

    let suffix = if report.walk_truncated { "+" } else { "" };
    println!("  files:    {}{suffix}", report.file_count);
    println!("  dirs:     {}{suffix}", report.dir_count);
    println!("  symlinks: {}", report.symlink_count);
    if let Some((path, size)) = &report.largest_file {
        println!("  largest:  {path} ({})", human_size(*size));
    }
    if report.glob_expansion_count > 0 {
        println!(
            "  glob expanded to: {} path(s)",
            report.glob_expansion_count
        );
    }

    let outside = if report.unsafe_empty_var_glob {
        "yes (empty-variable path collapses to root)"
    } else if report.paths_outside_repo {
        if has_repo_root {
            "yes"
        } else {
            "yes (above current directory; no repo root found)"
        }
    } else {
        "no"
    };
    println!("  outside repo: {outside}");
    println!(
        "  writes system path: {}",
        if report.writes_system_path {
            "yes"
        } else {
            "no"
        }
    );

    if report.walk_truncated {
        println!();
        println!(
            "  note: walk stopped at the depth-{}/{}-file cap; counts are lower bounds.",
            blast_radius::MAX_WALK_DEPTH,
            blast_radius::MAX_FILE_COUNT
        );
    }

    if report.walk_errors > 0 {
        println!();
        println!(
            "  note: {} path(s) could not be read (permission denied / I/O error); \
             counts are LOWER BOUNDS — the real blast radius may be larger.",
            report.walk_errors
        );
    }

    if !findings.is_empty() {
        println!();
        for f in findings {
            println!("  [{}] {} — {}", f.severity, f.rule_id, f.title);
            println!("    {}", f.description);
        }
    }

    println!();
    println!("  note: this is a filesystem-impact preview only. tirith preview does NOT run the");
    println!(
        "        command and is NOT a sandbox — it reads the disk to count impact, then exits."
    );
}

fn emit_json(
    command: &str,
    report: &BlastReport,
    repo_root: Option<&std::path::Path>,
    findings: &[Finding],
    action: Action,
) -> i32 {
    #[derive(serde::Serialize)]
    struct Out<'a> {
        schema_version: u32,
        command: &'a str,
        repo_root: Option<String>,
        action: Action,
        report: &'a BlastReport,
        findings: &'a [Finding],
        /// Honesty-of-claim marker: this surface walks the filesystem but is
        /// not a sandbox. Mirrors the M10 ch6 `isolation_kind` discipline.
        analysis_kind: &'static str,
    }
    let out = Out {
        schema_version: 1,
        command,
        repo_root: repo_root.map(|p| p.display().to_string()),
        action,
        report,
        findings,
        analysis_kind: "filesystem_impact_preview_not_a_sandbox",
    };
    let mut stdout = std::io::stdout().lock();
    if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
        eprintln!("tirith preview: failed to write JSON output");
        return 1;
    }
    action.exit_code()
}

/// Drop duplicate `(rule_id)` findings in place, keeping the first occurrence.
fn dedup_findings(findings: &mut Vec<Finding>) {
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert(f.rule_id));
}

/// Human-friendly byte size (e.g. `1.2 MiB`).
fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn empty_command_exits_two() {
        assert_eq!(run("   ", false), 2);
    }

    #[test]
    fn human_size_formats() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(1536), "1.5 KiB");
    }

    #[test]
    fn preview_relative_dist_is_clean_exit() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".git")).unwrap();
        let dist = dir.path().join("dist");
        fs::create_dir_all(&dist).unwrap();
        fs::write(dist.join("a.js"), b"x").unwrap();

        let _guard = crate::cli::preview::tests::CwdGuard::enter(dir.path());
        let code = run("rm -rf ./dist", false);
        assert_eq!(code, 0, "repo-relative delete should be clean");
    }

    #[test]
    fn preview_empty_var_glob_absent_is_advisory() {
        // F2: an ABSENT var (possibly a benign shell-local) is ambiguous, so
        // BlastEmptyVarGlob fires at Info, not Block. A PRESENT-and-empty var is
        // unambiguously High (unit-tested in blast_radius.rs).
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".git")).unwrap();
        let _guard = CwdGuard::enter(dir.path());
        let code = run("rm -rf \"$TIRITH_PREVIEW_UNSET/\"", false);
        assert_eq!(
            code,
            Action::Allow.exit_code(),
            "an absent (possibly shell-local) empty-var glob is advisory, not a block"
        );
    }

    #[test]
    fn preview_find_delete_warns() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join("f.txt"), b"x").unwrap();
        let _guard = CwdGuard::enter(dir.path());
        let code = run("find . -type f -delete", false);
        assert_eq!(
            code,
            Action::Warn.exit_code(),
            "find -delete is Medium → warn"
        );
    }

    /// RAII current-dir guard. `tirith preview` resolves globs / repo root from
    /// the process cwd, so these tests must chdir. The crate-wide env lock keeps
    /// concurrent cwd-mutating tests from racing.
    pub(crate) struct CwdGuard {
        prev: PathBuf,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl CwdGuard {
        pub(crate) fn enter(to: &std::path::Path) -> Self {
            // A process-global lock so cwd-mutating tests in this module never
            // run concurrently (cwd is process-global, like std::env).
            static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let lock = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prev = std::env::current_dir().unwrap();
            // Canonicalize so macOS `/var` → `/private/var` symlink does not
            // make the repo-root `starts_with` check fail.
            let to = to.canonicalize().unwrap_or_else(|_| to.to_path_buf());
            std::env::set_current_dir(&to).unwrap();
            CwdGuard { prev, _lock: lock }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.prev);
        }
    }
}
