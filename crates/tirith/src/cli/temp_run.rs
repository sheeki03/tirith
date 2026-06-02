//! `tirith temp-run` — run a command in a throwaway temp directory and diff
//! its filesystem impact (M10 ch6, design-decision D1).
//!
//! HONESTY-OF-CLAIM (the dominant requirement): `temp-run` is **file isolation
//! only — NOT a sandbox and NOT a security boundary**. The command runs with
//! the user's FULL privileges (keychain, ssh keys, cloud creds, network); the
//! only thing constrained is the working directory (a fresh `mkdtemp`), so
//! writes land there and we can diff them. Runtime sandboxing is an explicit
//! tirith non-goal (see `docs/threat-model.md`) and this does not contradict it.
//!
//! Pure Rust, no shell-out, for portability:
//!   * `--copy-repo` walks via `walkdir` + `fs::copy`, filtering `.git/` — not
//!     `cp -R --exclude` (a GNU-only extension absent on BSD/macOS).
//!   * `--strip-env` uses `env_clear()` + an explicit allowlist — not
//!     `env -i NAME …` (the bare-name form is non-portable across coreutils/BSD).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use crate::cli::{confirm, write_json_stdout};

/// The single honesty banner reused across help text and every human output
/// surface. Pinned by `help_snapshots.rs::help_temp_run` and
/// `docs/threat-model.md` so the three never drift.
pub const NOT_A_SANDBOX_BANNER: &str = "\
file isolation only; not a sandbox. The command runs with full user privileges \
and can read your keychain, ssh keys, AWS creds, and the network. Use this for \
filesystem-impact preview ONLY.";

/// String form of [`IsolationKind::FileOnlyNotASandbox`], kept `pub` for
/// external consumers / threat-model wording. The
/// `isolation_kind_const_matches_enum` test pins it to the enum so the honesty
/// marker has one source of truth.
#[allow(dead_code)]
pub const ISOLATION_KIND: &str = "file_only_not_a_sandbox";

/// The honesty-of-claim contract as a TYPE (type-design #1): the only
/// representable value is the not-a-sandbox one and the serde rename pins the
/// wire string, so a future edit cannot drop or change the `isolation_kind`
/// marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum IsolationKind {
    #[serde(rename = "file_only_not_a_sandbox")]
    FileOnlyNotASandbox,
}

/// Environment variables preserved under `--strip-env`. Deliberately tiny — a
/// convenience knob, NOT a secret-scrubbing security control.
const STRIP_ENV_ALLOWLIST: [&str; 5] = ["HOME", "PATH", "USER", "LANG", "TERM"];

/// Cap on files copied / inventoried so a giant tree can't hang the command.
const MAX_FILES: usize = 100_000;

/// `tirith temp-run -- <cmd>` — mkdtemp, optionally seed it, run the command
/// there with the user's full privileges, diff the temp dir, then prompt to
/// keep or delete it. NOT a sandbox (see [`NOT_A_SANDBOX_BANNER`]). Returns the
/// child's exit code, or 2 on a usage / setup / spawn failure; the diff never
/// overrides it.
pub fn run(command: &[String], copy_repo: bool, strip_env: bool, json: bool) -> i32 {
    let command_str = command.join(" ");
    if command_str.trim().is_empty() {
        eprintln!(
            "tirith temp-run: no command given \
             (usage: tirith temp-run -- ./script.sh)"
        );
        return 2;
    }

    // The TempDir handle stays alive for the whole function so its Drop never
    // fires mid-run or mid-diff; we delete only at the end, on confirmation.
    let temp = match tempfile::Builder::new()
        .prefix("tirith-temp-run-")
        .tempdir()
    {
        Ok(t) => t,
        Err(e) => {
            eprintln!("tirith temp-run: failed to create temp directory: {e}");
            return 2;
        }
    };
    let temp_path = temp.path().to_path_buf();

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    // Optionally seed the temp dir with a .git-stripped copy of the repo.
    let copied = if copy_repo {
        match copy_repo_into(&cwd, &temp_path) {
            Ok(n) => Some(n),
            Err(e) => {
                eprintln!("tirith temp-run: failed to copy repo: {e}");
                return 2;
            }
        }
    } else {
        None
    };

    if !json {
        print_preamble(&command_str, &temp_path, copy_repo, strip_env, copied);
    }

    // Baseline inventory AFTER seeding so `--copy-repo` files aren't "new".
    let before = inventory(&temp_path);

    let exit_code = match run_in_dir(&command_str, &temp_path, strip_env) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("tirith temp-run: failed to run command: {e}");
            return 2;
        }
    };

    let after = inventory(&temp_path);
    let (new_files, modified_files) = diff_inventories(&before, &after, &temp_path);

    // Decide keep-vs-delete BEFORE moving the TempDir handle. Non-interactive
    // (or "no") keeps the dir; interactive "yes" deletes it.
    let delete = confirm(
        &format!("tirith temp-run: delete temp dir {}?", temp_path.display()),
        false,
    );

    let kept_path = if delete {
        drop(temp); // dropping the handle removes the directory
        None
    } else {
        // Persist past Drop and surface the path for review.
        let persisted = temp.keep();
        Some(persisted)
    };

    if json {
        emit_json(
            &command_str,
            exit_code,
            copy_repo,
            strip_env,
            copied,
            &new_files,
            &modified_files,
            kept_path.as_deref(),
        );
    } else {
        print_result(exit_code, &new_files, &modified_files, kept_path.as_deref());
    }

    exit_code
}

/// Print the up-front honesty banner and run plan (human mode).
fn print_preamble(
    command_str: &str,
    temp_path: &Path,
    copy_repo: bool,
    strip_env: bool,
    copied: Option<usize>,
) {
    let s = tirith_core::style::Stream::Stdout;
    println!(
        "{} {}",
        tirith_core::style::bold("temp-run:", s),
        command_str
    );
    println!("  {}", tirith_core::style::red(NOT_A_SANDBOX_BANNER, s));
    println!("  temp dir: {}", temp_path.display());
    if copy_repo {
        match copied {
            Some(n) => println!("  seeded:   copied {n} file(s) from the repo (.git excluded)"),
            None => println!("  seeded:   repo copy"),
        }
    } else {
        println!("  seeded:   empty (pass --copy-repo to copy the repo, .git excluded)");
    }
    if strip_env {
        println!(
            "  env:      stripped to allowlist [{}] (convenience, NOT secret scrubbing)",
            STRIP_ENV_ALLOWLIST.join(", ")
        );
    } else {
        println!("  env:      inherited in full (pass --strip-env to trim to an allowlist)");
    }
    println!();
}

/// Print the post-run filesystem diff and the keep/delete outcome (human mode).
fn print_result(
    exit_code: i32,
    new_files: &[String],
    modified_files: &[String],
    kept_path: Option<&Path>,
) {
    println!("  exit code: {exit_code}");
    print_list_section("new files", new_files);
    print_list_section("modified files", modified_files);
    match kept_path {
        Some(p) => println!("\n  kept temp dir: {}", p.display()),
        None => println!("\n  temp dir deleted"),
    }
}

fn print_list_section(label: &str, items: &[String]) {
    if items.is_empty() {
        println!("\n  {label}: none");
    } else {
        println!("\n  {label} ({}):", items.len());
        for i in items {
            println!("    {i}");
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_json(
    command_str: &str,
    exit_code: i32,
    copy_repo: bool,
    strip_env: bool,
    copied: Option<usize>,
    new_files: &[String],
    modified_files: &[String],
    kept_path: Option<&Path>,
) {
    let json_val = serde_json::json!({
        // Load-bearing honesty field, emitted through the typed enum so it
        // cannot drift (type-design #1).
        "isolation_kind": IsolationKind::FileOnlyNotASandbox,
        "not_a_sandbox": true,
        "disclaimer": NOT_A_SANDBOX_BANNER,
        "command": command_str,
        "exit_code": exit_code,
        "copy_repo": copy_repo,
        "files_copied": copied,
        "strip_env": strip_env,
        "env_allowlist": if strip_env { STRIP_ENV_ALLOWLIST.to_vec() } else { Vec::new() },
        "new_files": new_files,
        "modified_files": modified_files,
        "temp_dir_kept": kept_path.is_some(),
        "temp_dir": kept_path.map(|p| p.display().to_string()),
    });
    write_json_stdout(&json_val, "tirith temp-run: failed to write JSON output");
}

/// Run `command_str` through the platform shell with cwd set to `dir`. With
/// `strip_env`, the child env is cleared and rebuilt from the allowlist.
/// Returns the child's exit code (128 if signal-killed). NOT isolation —
/// the command runs with the user's full privileges.
fn run_in_dir(command_str: &str, dir: &Path, strip_env: bool) -> std::io::Result<i32> {
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(command_str);
        c
    } else {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        let mut c = Command::new(shell);
        c.arg("-c").arg(command_str);
        c
    };
    cmd.current_dir(dir);

    if strip_env {
        // Portable env trimming (NOT `env -i NAME …` — the bare-name form is
        // non-portable): clear, then re-add only the set allowlist values.
        cmd.env_clear();
        for key in STRIP_ENV_ALLOWLIST {
            if let Some(val) = std::env::var_os(key) {
                cmd.env(key, val);
            }
        }
    }

    let status = cmd.status()?;
    Ok(status.code().unwrap_or(128))
}

/// Copy the repo at `src` into `dst`, excluding any `.git` component. Returns
/// the count of regular files copied; symlinks are skipped (this is an impact
/// preview, not a faithful mirror).
fn copy_repo_into(src: &Path, dst: &Path) -> std::io::Result<usize> {
    use walkdir::WalkDir;

    let mut copied = 0usize;
    for entry in WalkDir::new(src)
        .follow_links(false)
        .into_iter()
        // Prune `.git` directories wholesale so we never descend into them.
        .filter_entry(|e| !(e.file_type().is_dir() && e.file_name().to_str() == Some(".git")))
    {
        if copied >= MAX_FILES {
            break;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        // Belt-and-suspenders: skip any `.git` component (e.g. a submodule
        // `.git` file) that slipped past the prune.
        if path
            .components()
            .any(|c| c.as_os_str().to_str() == Some(".git"))
        {
            continue;
        }
        let rel = match path.strip_prefix(src) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if rel.as_os_str().is_empty() {
            continue; // the root itself
        }
        let target = dst.join(rel);
        let ft = entry.file_type();
        if ft.is_dir() {
            std::fs::create_dir_all(&target)?;
        } else if ft.is_file() {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(path, &target)?;
            copied += 1;
        }
        // Symlinks and other special files are intentionally skipped.
    }
    Ok(copied)
}

/// Inventory regular files under `root` as a `path -> mtime` map, capped at
/// [`MAX_FILES`]. Symlinks are recorded by their own metadata (not followed).
fn inventory(root: &Path) -> BTreeMap<String, SystemTime> {
    use walkdir::WalkDir;

    let mut out = BTreeMap::new();
    for entry in WalkDir::new(root).follow_links(false) {
        if out.len() >= MAX_FILES {
            break;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        // Record non-directories (incl. symlinks) so a new symlink is diffed.
        if !meta.is_dir() {
            if let Ok(mtime) = meta.modified() {
                out.insert(entry.path().to_string_lossy().into_owned(), mtime);
            }
        }
    }
    out
}

/// Diff two inventories into `(new_files, modified_files)`, with both lists
/// sorted and paths rendered relative to `root` for readable output.
fn diff_inventories(
    before: &BTreeMap<String, SystemTime>,
    after: &BTreeMap<String, SystemTime>,
    root: &Path,
) -> (Vec<String>, Vec<String>) {
    let rel = |p: &str| -> String {
        Path::new(p)
            .strip_prefix(root)
            .map(|r| r.to_string_lossy().into_owned())
            .unwrap_or_else(|_| p.to_string())
    };

    let mut new_files: Vec<String> = after
        .keys()
        .filter(|p| !before.contains_key(*p))
        .map(|p| rel(p))
        .collect();
    new_files.sort();

    let mut modified_files: Vec<String> = after
        .iter()
        .filter_map(|(p, mtime_after)| {
            before
                .get(p)
                .filter(|mtime_before| *mtime_before != mtime_after)
                .map(|_| rel(p))
        })
        .collect();
    modified_files.sort();

    (new_files, modified_files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn banner_states_not_a_sandbox_and_full_privileges() {
        assert!(NOT_A_SANDBOX_BANNER.contains("not a sandbox"));
        assert!(NOT_A_SANDBOX_BANNER.contains("full user privileges"));
        assert!(NOT_A_SANDBOX_BANNER.contains("keychain"));
        assert_eq!(ISOLATION_KIND, "file_only_not_a_sandbox");
    }

    #[test]
    fn isolation_kind_const_matches_enum() {
        // The typed enum and the string const must serialize to the SAME wire
        // value so the honesty contract has one source of truth (type-design #1).
        let serialized =
            serde_json::to_value(IsolationKind::FileOnlyNotASandbox).expect("serialize enum");
        assert_eq!(serialized, serde_json::Value::String(ISOLATION_KIND.into()));
    }

    #[test]
    fn copy_repo_excludes_git_directory() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();

        fs::create_dir_all(src.path().join(".git/objects")).unwrap();
        fs::write(src.path().join(".git/config"), b"[core]").unwrap();
        fs::write(src.path().join(".git/objects/abc"), b"obj").unwrap();
        fs::create_dir_all(src.path().join("src")).unwrap();
        fs::write(src.path().join("src/main.rs"), b"fn main() {}").unwrap();
        fs::write(src.path().join("README.md"), b"# hi").unwrap();

        let copied = copy_repo_into(src.path(), dst.path()).unwrap();
        assert_eq!(copied, 2, "should copy main.rs and README.md only");
        assert!(dst.path().join("src/main.rs").is_file());
        assert!(dst.path().join("README.md").is_file());
        assert!(
            !dst.path().join(".git").exists(),
            ".git must be excluded from the copy"
        );
    }

    #[test]
    fn diff_reports_new_and_modified_files() {
        let root = tempfile::tempdir().unwrap();
        let before = inventory(root.path());
        assert!(before.is_empty());

        fs::write(root.path().join("created.txt"), b"new").unwrap();
        let after = inventory(root.path());

        let (new_files, modified_files) = diff_inventories(&before, &after, root.path());
        assert_eq!(new_files, vec!["created.txt".to_string()]);
        assert!(modified_files.is_empty());
    }
}
