//! M11 ch2 — `tirith commands init|list|run|check`.
//!
//! A thin CLI over the repo command manifest (`.tirith/commands.yaml`,
//! [`tirith_core::commands_manifest`]). The manifest is SUPPRESSION-BOUNDED: it
//! can suppress only the Info `repo_command_unknown` annotation for an exact
//! `allowed[]` match, and ELEVATE via a blocking `repo_command_dangerous_pattern`
//! on a `dangerous[]` glob match. It can NEVER weaken a real engine finding —
//! see the module doc on `commands_manifest`.
//!
//! - `init` — write the starter manifest to `<repo>/.tirith/commands.yaml`.
//! - `list` — print the catalogued `allowed[]` / `dangerous[]` entries.
//! - `run` — look up an `allowed[]` entry by name and execute its command, but
//!   ONLY after re-checking it through the engine (an allowed entry that the
//!   engine flags High/Critical is refused — the manifest cannot bypass
//!   detection here either).
//! - `check` — evaluate an arbitrary command against the manifest + engine
//!   (delegates to `tirith check`).

use std::process::Command;

use tirith_core::commands_manifest::{CommandsManifest, ManifestError};

/// `tirith commands init` — write the starter `.tirith/commands.yaml`.
///
/// Refuses to overwrite an existing file unless `force` is set (so a hand-
/// edited manifest is never clobbered by accident).
pub fn init(force: bool, json: bool) -> i32 {
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());

    let path = match tirith_core::commands_manifest::init_manifest_path(cwd.as_deref()) {
        Some(p) => p,
        None => {
            emit_error(
                json,
                "tirith commands init",
                "could not resolve a target directory for .tirith/commands.yaml",
            );
            return 1;
        }
    };

    if path.exists() && !force {
        emit_error(
            json,
            "tirith commands init",
            &format!(
                "{} already exists; pass --force to overwrite",
                path.display()
            ),
        );
        return 1;
    }

    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            emit_error(
                json,
                "tirith commands init",
                &format!("create {}: {e}", parent.display()),
            );
            return 1;
        }
    }

    if let Err(e) = std::fs::write(&path, tirith_core::commands_manifest::STARTER_MANIFEST) {
        emit_error(
            json,
            "tirith commands init",
            &format!("write {}: {e}", path.display()),
        );
        return 1;
    }

    if json {
        let v = serde_json::json!({
            "written": path.display().to_string(),
            "forced": force,
        });
        super::write_json_stdout(&v, "tirith commands init: failed to write JSON output");
    } else {
        println!("Wrote starter command manifest to {}", path.display());
        eprintln!("Edit it, then `tirith commands list` to review the catalogue.");
    }
    0
}

/// `tirith commands list` — print the manifest's catalogue.
pub fn list(json: bool) -> i32 {
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());

    let manifest = match CommandsManifest::discover(cwd.as_deref()) {
        Ok(Some(m)) => m,
        Ok(None) => {
            if json {
                let v = serde_json::json!({ "manifest": null, "allowed": [], "dangerous": [] });
                super::write_json_stdout(&v, "tirith commands list: failed to write JSON output");
            } else {
                println!(
                    "No .tirith/commands.yaml found for this repo. Run `tirith commands init` to create one."
                );
            }
            return 0;
        }
        Err(e) => {
            emit_error(json, "tirith commands list", &manifest_err(&e));
            return 1;
        }
    };

    if json {
        let allowed: Vec<_> = manifest
            .allowed
            .iter()
            .map(|e| serde_json::json!({ "name": e.name, "command": e.command }))
            .collect();
        let dangerous: Vec<_> = manifest
            .dangerous
            .iter()
            .map(|e| serde_json::json!({ "pattern": e.pattern, "action": "block" }))
            .collect();
        let v = serde_json::json!({ "allowed": allowed, "dangerous": dangerous });
        super::write_json_stdout(&v, "tirith commands list: failed to write JSON output");
    } else {
        if manifest.allowed.is_empty() {
            println!("allowed: (none)");
        } else {
            println!("allowed:");
            for e in &manifest.allowed {
                println!("  {:<16} {}", e.name, e.command);
            }
        }
        if manifest.dangerous.is_empty() {
            println!("dangerous: (none)");
        } else {
            println!("dangerous:");
            for e in &manifest.dangerous {
                println!("  block   {}", e.pattern);
            }
        }
    }
    0
}

/// `tirith commands run <name>` — execute the `allowed[]` command named
/// `name`, after re-checking it through the engine.
///
/// SECURITY: being in `allowed[]` only suppresses the `repo_command_unknown`
/// annotation; it does NOT make a command safe to run blindly. We run the
/// resolved command back through `tirith check` first and REFUSE to execute if
/// the engine blocks it (a `dangerous[]` match or any real High/Critical
/// finding). This keeps the "manifest cannot bypass detection" invariant on the
/// execution path too.
pub fn run(name: &str, json: bool) -> i32 {
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());

    let manifest = match CommandsManifest::discover(cwd.as_deref()) {
        Ok(Some(m)) => m,
        Ok(None) => {
            emit_error(
                json,
                "tirith commands run",
                "no .tirith/commands.yaml found for this repo (run `tirith commands init`)",
            );
            return 1;
        }
        Err(e) => {
            emit_error(json, "tirith commands run", &manifest_err(&e));
            return 1;
        }
    };

    let entry = match manifest.allowed.iter().find(|e| e.name == name) {
        Some(e) => e,
        None => {
            let names: Vec<&str> = manifest.allowed.iter().map(|e| e.name.as_str()).collect();
            emit_error(
                json,
                "tirith commands run",
                &format!(
                    "no allowed command named '{name}'. Available: {}",
                    if names.is_empty() {
                        "(none)".to_string()
                    } else {
                        names.join(", ")
                    }
                ),
            );
            return 1;
        }
    };
    let command = entry.command.clone();

    // Re-check the resolved command through the engine. The manifest CANNOT
    // bypass detection: if the engine blocks (dangerous match, High/Critical
    // finding), we refuse to run it.
    let verdict = analyze_command(&command, cwd.as_deref());
    if verdict.action == tirith_core::verdict::Action::Block {
        // Audit the refusal so the blocked attempt is traceable.
        let _ = tirith_core::audit::log_verdict(&verdict, &command, None, None, &[]);
        emit_error(
            json,
            "tirith commands run",
            &format!(
                "refusing to run '{name}' ({command}): tirith blocked it. \
                 Inspect with `tirith commands check -- \"{command}\"`."
            ),
        );
        return verdict.action.exit_code();
    }

    // Audit the (allowed, non-blocked) run before executing it.
    let _ = tirith_core::audit::log_verdict(&verdict, &command, None, None, &[]);

    if json {
        let v = serde_json::json!({
            "running": name,
            "command": command,
        });
        super::write_json_stdout(&v, "tirith commands run: failed to write JSON output");
    } else {
        eprintln!("Running allowed command '{name}': {command}");
    }

    match run_shell_command(&command) {
        Ok(code) => code,
        Err(e) => {
            emit_error(
                json,
                "tirith commands run",
                &format!("failed to spawn command: {e}"),
            );
            1
        }
    }
}

/// `tirith commands check -- "<cmd>"` — evaluate `cmd` against the manifest +
/// the full engine. Delegates to `tirith check`, which wires the manifest
/// (`repo_command_unknown` / `repo_command_dangerous_pattern`) into its normal
/// analysis. Exit code is the engine's action exit code.
pub fn check(cmd: &str, shell: &str, json: bool) -> i32 {
    // Reuse the exact `tirith check` path so manifest + engine semantics are
    // identical to a normal shell-hook check (no second, divergent code path).
    super::check::run(
        cmd, shell, json, /* non_interactive */ false, /* interactive_flag */ false,
        /* approval_check */ false, /* strict_warn */ false, /* no_daemon */ true,
        /* warn_only */ false, /* offline */ false,
        /* suggest_safe_command */ false, /* card */ None,
    )
}

/// The [`ShellType`](tirith_core::tokenize::ShellType) the safety re-check must
/// tokenize with: it MUST match the shell `run_shell_command` actually executes
/// (`cmd /C` on Windows, `$SHELL -c` → POSIX elsewhere). Analyzing a command
/// with the wrong shell can mis-tokenize pipes/operators and miss findings.
#[cfg(windows)]
const RUN_SHELL: tirith_core::tokenize::ShellType = tirith_core::tokenize::ShellType::Cmd;
#[cfg(not(windows))]
const RUN_SHELL: tirith_core::tokenize::ShellType = tirith_core::tokenize::ShellType::Posix;

/// Analyze `command` through the engine for `commands run`'s safety re-check.
fn analyze_command(command: &str, cwd: Option<&str>) -> tirith_core::verdict::Verdict {
    use tirith_core::engine::{self, AnalysisContext};
    use tirith_core::extract::ScanContext;

    let ctx = AnalysisContext {
        input: command.to_string(),
        // Match the shell that will actually run the command (see RUN_SHELL).
        shell: RUN_SHELL,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: false,
        cwd: cwd.map(str::to_string),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
    };
    engine::analyze(&ctx)
}

/// Run `command` through the platform shell, inheriting stdio. Returns the
/// child's exit code (128 if killed by a signal with no code).
fn run_shell_command(command: &str) -> std::io::Result<i32> {
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(command);
        c
    } else {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        let mut c = Command::new(shell);
        c.arg("-c").arg(command);
        c
    };
    let status = cmd.status()?;
    Ok(status.code().unwrap_or(128))
}

/// Human-readable rendering of a manifest load error.
fn manifest_err(e: &ManifestError) -> String {
    format!("could not load .tirith/commands.yaml: {e}")
}

/// Emit an error to stderr (human) or as a JSON `{"error": ...}` object.
fn emit_error(json: bool, ctx: &str, msg: &str) {
    if json {
        let v = serde_json::json!({ "error": msg });
        super::write_json_stdout(&v, &format!("{ctx}: failed to write JSON output"));
    } else {
        eprintln!("{ctx}: {msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::RUN_SHELL;
    use tirith_core::tokenize::ShellType;

    #[test]
    fn run_shell_matches_execution_platform() {
        // The `commands run` safety re-check must tokenize with the SAME shell
        // `run_shell_command` executes: `cmd /C` on Windows, `$SHELL -c` (POSIX)
        // elsewhere. A mismatch (e.g. always-Posix) can mis-tokenize and miss
        // findings on Windows.
        #[cfg(windows)]
        assert_eq!(RUN_SHELL, ShellType::Cmd);
        #[cfg(not(windows))]
        assert_eq!(RUN_SHELL, ShellType::Posix);
    }
}
