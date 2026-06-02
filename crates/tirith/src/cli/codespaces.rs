//! `tirith codespaces setup|inject` (M8 ch5).
//!
//! Codespaces-specific wrappers around `devcontainer_writer`; a distinct command
//! surface from `tirith devcontainer` over the same file.
//!
//! - `setup` — write `.devcontainer/devcontainer.json` if absent (tirith hook +
//!   `TIRITH_DEVCONTAINER=1`) and add a `.tirith/` entry to `.gitignore`.
//! - `inject` — alias of `tirith devcontainer inject`.

use std::io::Write;
use std::path::Path;

use tirith_core::devcontainer_writer::{
    default_devcontainer_json, ensure_gitignore_entry, find_devcontainer_json, inject_tirith_hook,
};

use super::devcontainer::report_outcome;

/// `tirith codespaces setup [--path <dir>]` — bootstrap a devcontainer.json with
/// the tirith hook + `.tirith/` ignore entry.
pub fn setup(path: Option<&Path>, json: bool) -> i32 {
    let cwd = match path {
        Some(p) => p.to_path_buf(),
        None => match std::env::current_dir() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("tirith codespaces setup: cannot resolve cwd: {e}");
                return 1;
            }
        },
    };

    let target = find_devcontainer_json(&cwd).unwrap_or_else(|| default_devcontainer_json(&cwd));
    let outcome = inject_tirith_hook(&target, true);
    let injected_code = report_outcome("codespaces setup", &outcome, json);
    if injected_code != 0 {
        return injected_code;
    }

    // .gitignore entry.
    let gitignore_added = match ensure_gitignore_entry(&cwd) {
        Ok(added) => added,
        Err(e) => {
            eprintln!("tirith codespaces setup: could not update .gitignore: {e}");
            return 1;
        }
    };

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "gitignore_updated": gitignore_added,
            "gitignore_path": cwd.join(".gitignore").display().to_string(),
        });
        let mut stdout = std::io::stdout().lock();
        if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
            return 1;
        }
    } else if gitignore_added {
        eprintln!(
            "tirith codespaces setup: added `.tirith/` entry to {}",
            cwd.join(".gitignore").display()
        );
    } else {
        eprintln!(
            "tirith codespaces setup: `.tirith/` already present in {}",
            cwd.join(".gitignore").display()
        );
    }

    0
}

/// `tirith codespaces inject [--path <dir>]` — alias of `tirith devcontainer inject`.
pub fn inject(path: Option<&Path>, create: bool, json: bool) -> i32 {
    super::devcontainer::inject(path, create, json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn setup_creates_devcontainer_and_gitignore() {
        let dir = tempdir().unwrap();
        let code = setup(Some(dir.path()), false);
        assert_eq!(code, 0);
        let dc = dir.path().join(".devcontainer/devcontainer.json");
        assert!(dc.is_file());
        let gi = dir.path().join(".gitignore");
        let body = std::fs::read_to_string(&gi).unwrap();
        assert!(body.contains(".tirith/"));
    }

    #[test]
    fn setup_idempotent_second_run() {
        let dir = tempdir().unwrap();
        let _ = setup(Some(dir.path()), false);
        let code = setup(Some(dir.path()), false);
        assert_eq!(code, 0);
    }
}
