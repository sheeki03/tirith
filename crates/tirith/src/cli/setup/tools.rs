//! Per-tool setup implementations.
//!
//! Each function configures tirith protection for a specific AI coding tool:
//! hook scripts, JSON config merges, MCP registration, and zshenv guard.

use super::merge;
use super::run_impl::{copy_gateway_config, Scope, SetupOpts};
use super::{fs_helpers, zshenv};
use serde_json::json;

pub fn setup_claude_code(opts: &SetupOpts) -> Result<(), String> {
    let home = home::home_dir().ok_or_else(|| "could not determine home directory".to_string())?;
    let target = match opts.scope {
        Scope::Project => std::env::current_dir()
            .map_err(|e| format!("current_dir: {e}"))?
            .join(".claude"),
        Scope::User => home.join(".claude"),
    };

    let scope_root = match opts.scope {
        Scope::Project => Some(std::env::current_dir().map_err(|e| format!("current_dir: {e}"))?),
        Scope::User => Some(home.clone()),
    };
    fs_helpers::validate_target_dir(&target, scope_root.as_deref())?;

    let hooks_dir = target.join("hooks");
    if !opts.dry_run {
        std::fs::create_dir_all(&hooks_dir)
            .map_err(|e| format!("create {}: {e}", hooks_dir.display()))?;
    }

    // Step 1: Write tirith-check.py hook (Python hook doesn't use __TIRITH_BIN__ placeholder)
    let hook_path = hooks_dir.join("tirith-check.py");
    let hook_content = crate::assets::TIRITH_CHECK_PY;
    fs_helpers::write_hook_script(&hook_path, hook_content, opts.force, opts.dry_run)?;

    // Step 2: Merge settings.json with PreToolUse hook
    let settings_path = target.join("settings.json");
    let hook_command = match opts.scope {
        Scope::Project => {
            r#"python3 "${CLAUDE_PROJECT_DIR:-.}/.claude/hooks/tirith-check.py""#.to_string()
        }
        Scope::User => r#"python3 "$HOME/.claude/hooks/tirith-check.py""#.to_string(),
    };
    merge::merge_claude_settings(&settings_path, &hook_command, opts.force, opts.dry_run)?;

    // Step 3: --with-mcp support
    if opts.with_mcp {
        match opts.scope {
            Scope::Project => {
                let cwd = std::env::current_dir().map_err(|e| format!("current_dir: {e}"))?;
                let mcp_path = cwd.join(".mcp.json");
                merge::merge_mcp_json(
                    &mcp_path,
                    "tirith",
                    json!({
                        "command": opts.tirith_bin,
                        "args": ["mcp-server"]
                    }),
                    opts.force,
                    opts.dry_run,
                )?;
            }
            Scope::User => {
                // Merge directly into ~/.claude/settings.json mcpServers.
                // We avoid `claude mcp add` because it hangs when called from
                // within an active Claude Code session (subprocess deadlock).
                merge::merge_claude_mcp_server(
                    &settings_path,
                    "tirith",
                    json!({
                        "command": opts.tirith_bin,
                        "args": ["mcp-server"]
                    }),
                    opts.force,
                    opts.dry_run,
                )?;
            }
        }
    }

    // Step 4: Install shell hook (eval "$(tirith init)" in shell profile)
    if let Err(e) =
        super::shell_profile::install_shell_hook(&opts.tirith_bin, opts.force, opts.dry_run)
    {
        // Non-fatal: shell hook is best-effort — print warning but don't fail setup
        eprintln!("tirith: WARNING: {e}");
    }

    // Summary
    eprintln!();
    eprintln!("tirith: Claude Code setup complete");
    eprintln!("  Run `tirith doctor` to verify your configuration.");
    Ok(())
}

pub fn setup_codex(opts: &SetupOpts) -> Result<(), String> {
    // 1. Copy gateway YAML
    let gateway_path = copy_gateway_config(opts.force, opts.dry_run)?;

    // 2. Register via codex mcp add
    let gw_path_str = gateway_path.display().to_string();
    let tirith_bin = &opts.tirith_bin;
    let add_args: Vec<&str> = vec![
        "mcp",
        "add",
        "tirith-gateway",
        "--",
        tirith_bin,
        "gateway",
        "run",
        "--upstream-bin",
        tirith_bin,
        "--upstream-arg",
        "mcp-server",
        "--config",
        &gw_path_str,
    ];

    if opts.dry_run {
        eprintln!("[dry-run] would run: codex {}", add_args.join(" "));
        eprintln!("  (cannot check existing registrations in dry-run mode)");
    } else {
        let get_out = fs_helpers::run_cli("codex", &["mcp", "get", "tirith-gateway"])?;

        let exists = if get_out.status.success() {
            true
        } else {
            let stderr = String::from_utf8_lossy(&get_out.stderr).to_lowercase();
            if stderr.contains("not found") || stderr.contains("does not exist") {
                false
            } else {
                return Err(format!(
                    "codex mcp get failed unexpectedly: {}",
                    String::from_utf8_lossy(&get_out.stderr).trim()
                ));
            }
        };

        if exists && !opts.force {
            // Drift detection via structured JSON
            let json_out =
                fs_helpers::run_cli("codex", &["mcp", "get", "--json", "tirith-gateway"]);
            let expected_args: Vec<&str> = vec![
                "gateway",
                "run",
                "--upstream-bin",
                tirith_bin,
                "--upstream-arg",
                "mcp-server",
                "--config",
                &gw_path_str,
            ];
            let config_matches = match json_out {
                Ok(ref out) if out.status.success() => {
                    match serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                        Ok(val) => {
                            let cmd = val.get("command").and_then(|v| v.as_str());
                            let args: Option<Vec<&str>> = val
                                .get("args")
                                .and_then(|v| v.as_array())
                                .map(|a| a.iter().filter_map(|v| v.as_str()).collect());
                            Some(
                                cmd == Some(tirith_bin)
                                    && args.as_deref() == Some(expected_args.as_slice()),
                            )
                        }
                        Err(_) => None,
                    }
                }
                _ => None,
            };
            match config_matches {
                Some(true) => {
                    eprintln!("tirith: tirith-gateway already registered with codex, up to date");
                }
                Some(false) => {
                    return Err(
                        "tirith-gateway registered with codex but config differs — use --force to update".into(),
                    );
                }
                None => {
                    return Err(
                        "cannot verify tirith-gateway config with codex — use --force to re-register".into(),
                    );
                }
            }
        } else {
            if exists {
                let _ = fs_helpers::run_cli("codex", &["mcp", "remove", "tirith-gateway"]);
            }
            let add_out = fs_helpers::run_cli("codex", &add_args)?;
            if !add_out.status.success() {
                let stderr = String::from_utf8_lossy(&add_out.stderr);
                return Err(format!(
                    "codex mcp add failed (exit {}): {}",
                    add_out.status.code().unwrap_or(-1),
                    stderr.trim()
                ));
            }
            eprintln!("tirith: registered tirith-gateway with codex");
        }
    }

    // 3. Install shell hook
    if let Err(e) =
        super::shell_profile::install_shell_hook(&opts.tirith_bin, opts.force, opts.dry_run)
    {
        eprintln!("tirith: WARNING: {e}");
    }

    // 4. Offer zshenv guard
    zshenv::offer_zshenv_guard(
        opts.install_zshenv,
        opts.force,
        opts.dry_run,
        &opts.tirith_bin,
    )?;

    // Summary
    eprintln!();
    eprintln!("tirith: Codex setup complete");
    eprintln!("  Run `tirith doctor` to verify your configuration.");
    Ok(())
}

pub fn setup_cursor(opts: &SetupOpts) -> Result<(), String> {
    let home = home::home_dir().ok_or_else(|| "could not determine home directory".to_string())?;
    let target = match opts.scope {
        Scope::Project => std::env::current_dir()
            .map_err(|e| format!("current_dir: {e}"))?
            .join(".cursor"),
        Scope::User => home.join(".cursor"),
    };

    let scope_root = match opts.scope {
        Scope::Project => Some(std::env::current_dir().map_err(|e| format!("current_dir: {e}"))?),
        Scope::User => Some(home.clone()),
    };
    fs_helpers::validate_target_dir(&target, scope_root.as_deref())?;

    let hooks_dir = target.join("hooks");
    if !opts.dry_run {
        std::fs::create_dir_all(&hooks_dir)
            .map_err(|e| format!("create {}: {e}", hooks_dir.display()))?;
    }

    // Write cursor hook script
    let hook_path = hooks_dir.join("tirith-hook.sh");
    let hook_content = crate::assets::CURSOR_HOOK_SH.replace("__TIRITH_BIN__", &opts.tirith_bin);
    fs_helpers::write_hook_script(&hook_path, &hook_content, opts.force, opts.dry_run)?;

    // Merge hooks.json with beforeShellExecution entry
    let hooks_json_path = target.join("hooks.json");
    let hook_cmd = match opts.scope {
        Scope::Project => "hooks/tirith-hook.sh".to_string(),
        Scope::User => {
            let h = home.join(".cursor").join("hooks").join("tirith-hook.sh");
            h.display().to_string()
        }
    };
    merge::merge_hooks_json(
        &hooks_json_path,
        "beforeShellExecution",
        json!({
            "command": hook_cmd,
            "type": "command",
            "timeout": 15
        }),
        "tirith-hook",
        opts.force,
        opts.dry_run,
        true, // Cursor requires "version": 1
    )?;

    // Copy gateway config + merge MCP JSON
    let gateway_path = copy_gateway_config(opts.force, opts.dry_run)?;
    let gw_path_str = gateway_path.display().to_string();
    let mcp_json_path = target.join("mcp.json");
    merge::merge_mcp_json(
        &mcp_json_path,
        "tirith-gateway",
        json!({
            "command": opts.tirith_bin,
            "args": [
                "gateway", "run",
                "--upstream-bin", opts.tirith_bin,
                "--upstream-arg", "mcp-server",
                "--config", gw_path_str
            ]
        }),
        opts.force,
        opts.dry_run,
    )?;

    // Install shell hook
    if let Err(e) =
        super::shell_profile::install_shell_hook(&opts.tirith_bin, opts.force, opts.dry_run)
    {
        eprintln!("tirith: WARNING: {e}");
    }

    // Offer zshenv guard
    zshenv::offer_zshenv_guard(
        opts.install_zshenv,
        opts.force,
        opts.dry_run,
        &opts.tirith_bin,
    )?;

    // Summary
    eprintln!();
    eprintln!("tirith: Cursor setup complete");
    eprintln!("  Run `tirith doctor` to verify your configuration.");
    Ok(())
}

pub fn setup_vscode(opts: &SetupOpts) -> Result<(), String> {
    let cwd = std::env::current_dir().map_err(|e| format!("current_dir: {e}"))?;
    let target = cwd.join(".vscode");

    fs_helpers::validate_target_dir(&target, Some(&cwd))?;

    let hooks_dir = target.join("hooks");
    if !opts.dry_run {
        std::fs::create_dir_all(&hooks_dir)
            .map_err(|e| format!("create {}: {e}", hooks_dir.display()))?;
    }

    // Write vscode hook script
    let hook_path = hooks_dir.join("tirith-hook.sh");
    let hook_content = crate::assets::VSCODE_HOOK_SH.replace("__TIRITH_BIN__", &opts.tirith_bin);
    fs_helpers::write_hook_script(&hook_path, &hook_content, opts.force, opts.dry_run)?;

    // Merge settings.json with managed-block hook entry
    let settings_path = target.join("settings.json");
    let hook_cmd = "hooks/tirith-hook.sh".to_string(); // VS Code is project-only
    merge::merge_vscode_settings(&settings_path, &hook_cmd, opts.force, opts.dry_run)?;

    // Copy gateway config + merge MCP JSON
    // VS Code uses "servers" as the top-level key (not "mcpServers") and requires "type": "stdio"
    let gateway_path = copy_gateway_config(opts.force, opts.dry_run)?;
    let gw_path_str = gateway_path.display().to_string();
    let mcp_json_path = cwd.join(".vscode").join("mcp.json");
    merge::merge_mcp_json_with_key(
        &mcp_json_path,
        "tirith-gateway",
        json!({
            "type": "stdio",
            "command": opts.tirith_bin,
            "args": [
                "gateway", "run",
                "--upstream-bin", opts.tirith_bin,
                "--upstream-arg", "mcp-server",
                "--config", gw_path_str
            ]
        }),
        "servers",
        opts.force,
        opts.dry_run,
    )?;

    // Install shell hook
    if let Err(e) =
        super::shell_profile::install_shell_hook(&opts.tirith_bin, opts.force, opts.dry_run)
    {
        eprintln!("tirith: WARNING: {e}");
    }

    // Offer zshenv guard
    zshenv::offer_zshenv_guard(
        opts.install_zshenv,
        opts.force,
        opts.dry_run,
        &opts.tirith_bin,
    )?;

    // Summary
    eprintln!();
    eprintln!("tirith: VS Code setup complete");
    eprintln!("  Run `tirith doctor` to verify your configuration.");
    Ok(())
}

pub fn setup_gemini_cli(opts: &SetupOpts) -> Result<(), String> {
    let home = home::home_dir().ok_or_else(|| "could not determine home directory".to_string())?;

    let (target, scope_root) = match opts.scope {
        Scope::Project => {
            let cwd = std::env::current_dir().map_err(|e| format!("current_dir: {e}"))?;
            (cwd.join(".gemini"), Some(cwd))
        }
        Scope::User => {
            if let Some(cli_home) = std::env::var_os("GEMINI_CLI_HOME") {
                let base = std::path::PathBuf::from(cli_home);
                (base.join(".gemini"), None)
            } else {
                (home.join(".gemini"), Some(home.clone()))
            }
        }
    };

    fs_helpers::validate_target_dir(&target, scope_root.as_deref())?;

    let hooks_dir = target.join("hooks");
    if !opts.dry_run {
        std::fs::create_dir_all(&hooks_dir)
            .map_err(|e| format!("create {}: {e}", hooks_dir.display()))?;
    }

    // Step 1: Write tirith-security-guard-gemini.py
    let hook_path = hooks_dir.join("tirith-security-guard-gemini.py");
    let hook_content = crate::assets::GEMINI_HOOK_PY;
    fs_helpers::write_hook_script(&hook_path, hook_content, opts.force, opts.dry_run)?;

    // Step 2: Merge settings.json with BeforeTool hook
    let settings_path = target.join("settings.json");
    let hook_command = match opts.scope {
        Scope::Project => {
            r#"python3 "$GEMINI_PROJECT_DIR/.gemini/hooks/tirith-security-guard-gemini.py""#
                .to_string()
        }
        Scope::User => {
            let abs = hooks_dir.join("tirith-security-guard-gemini.py");
            format!(r#"python3 "{}""#, abs.display())
        }
    };
    merge::merge_gemini_settings(&settings_path, &hook_command, opts.force, opts.dry_run)?;

    // Step 3: --with-mcp support
    if opts.with_mcp {
        merge::merge_mcp_json_with_key(
            &settings_path,
            "tirith",
            json!({
                "command": opts.tirith_bin,
                "args": ["mcp-server"]
            }),
            "mcpServers",
            opts.force,
            opts.dry_run,
        )?;
    }

    // Step 4: Install shell hook
    if let Err(e) =
        super::shell_profile::install_shell_hook(&opts.tirith_bin, opts.force, opts.dry_run)
    {
        eprintln!("tirith: WARNING: {e}");
    }

    // Summary
    eprintln!();
    eprintln!("tirith: Gemini CLI setup complete");
    eprintln!("  Run `tirith doctor` to verify your configuration.");
    Ok(())
}

pub fn setup_pi_cli(opts: &SetupOpts) -> Result<(), String> {
    let home = home::home_dir().ok_or_else(|| "could not determine home directory".to_string())?;

    let (target, scope_root) = match opts.scope {
        Scope::Project => {
            let cwd = std::env::current_dir().map_err(|e| format!("current_dir: {e}"))?;
            (cwd.join(".pi"), Some(cwd))
        }
        Scope::User => {
            if let Some(agent_dir) = std::env::var_os("PI_CODING_AGENT_DIR") {
                (std::path::PathBuf::from(agent_dir), None)
            } else {
                (home.join(".pi").join("agent"), Some(home.clone()))
            }
        }
    };

    fs_helpers::validate_target_dir(&target, scope_root.as_deref())?;

    let extensions_dir = target.join("extensions");
    if !opts.dry_run {
        std::fs::create_dir_all(&extensions_dir)
            .map_err(|e| format!("create {}: {e}", extensions_dir.display()))?;
    }

    // Step 1: Write tirith-guard.ts
    let guard_path = extensions_dir.join("tirith-guard.ts");
    let guard_content = crate::assets::TIRITH_GUARD_TS;
    fs_helpers::write_hook_script(&guard_path, guard_content, opts.force, opts.dry_run)?;

    // Step 2: Install shell hook
    if let Err(e) =
        super::shell_profile::install_shell_hook(&opts.tirith_bin, opts.force, opts.dry_run)
    {
        eprintln!("tirith: WARNING: {e}");
    }

    // Summary
    eprintln!();
    eprintln!("tirith: Pi CLI setup complete");
    eprintln!("  Run `tirith doctor` to verify your configuration.");
    Ok(())
}

pub fn setup_windsurf(opts: &SetupOpts) -> Result<(), String> {
    let home = home::home_dir().ok_or_else(|| "could not determine home directory".to_string())?;
    let target = home.join(".codeium").join("windsurf");

    fs_helpers::validate_target_dir(&target, Some(&home))?;

    let hooks_dir = target.join("hooks");
    if !opts.dry_run {
        std::fs::create_dir_all(&hooks_dir)
            .map_err(|e| format!("create {}: {e}", hooks_dir.display()))?;
    }

    // Write windsurf hook script
    let hook_path = hooks_dir.join("tirith-hook.sh");
    let hook_content = crate::assets::WINDSURF_HOOK_SH.replace("__TIRITH_BIN__", &opts.tirith_bin);
    fs_helpers::write_hook_script(&hook_path, &hook_content, opts.force, opts.dry_run)?;

    // Merge hooks.json with pre_run_command entry (absolute path for user-global)
    let hooks_json_path = target.join("hooks.json");
    let hook_cmd = hooks_dir.join("tirith-hook.sh").display().to_string();
    merge::merge_hooks_json(
        &hooks_json_path,
        "pre_run_command",
        json!({
            "command": hook_cmd,
            "show_output": true
        }),
        "tirith-hook",
        opts.force,
        opts.dry_run,
        false, // Windsurf doesn't require "version" key
    )?;

    // Copy gateway config + merge MCP JSON
    let gateway_path = copy_gateway_config(opts.force, opts.dry_run)?;
    let gw_path_str = gateway_path.display().to_string();
    let mcp_json_path = target.join("mcp_config.json");
    merge::merge_mcp_json(
        &mcp_json_path,
        "tirith-gateway",
        json!({
            "command": opts.tirith_bin,
            "args": [
                "gateway", "run",
                "--upstream-bin", opts.tirith_bin,
                "--upstream-arg", "mcp-server",
                "--config", gw_path_str
            ]
        }),
        opts.force,
        opts.dry_run,
    )?;

    // Install shell hook
    if let Err(e) =
        super::shell_profile::install_shell_hook(&opts.tirith_bin, opts.force, opts.dry_run)
    {
        eprintln!("tirith: WARNING: {e}");
    }

    // Offer zshenv guard
    zshenv::offer_zshenv_guard(
        opts.install_zshenv,
        opts.force,
        opts.dry_run,
        &opts.tirith_bin,
    )?;

    // Summary
    eprintln!();
    eprintln!("tirith: Windsurf setup complete");
    eprintln!("  Run `tirith doctor` to verify your configuration.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RAII guard that restores (or removes) an env var on Drop,
    /// so panics inside test closures can't leak env state.
    struct EnvGuard {
        key: &'static str,
        old: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, val: &std::path::Path) -> Self {
            let old = std::env::var_os(key);
            unsafe { std::env::set_var(key, val) };
            Self { key, old }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.old {
                Some(h) => unsafe { std::env::set_var(self.key, h) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    /// Run `f` with HOME pointed at a fresh temp dir, holding the shared
    /// HOME_LOCK so parallel tests (including zshenv's) don't race on env vars.
    /// Uses catch_unwind so HOME is restored even if `f` panics.
    /// Tolerates a poisoned mutex so one panic doesn't cascade to all later tests.
    fn with_fake_home<F: std::panic::UnwindSafe + FnOnce(&std::path::Path) -> R, R>(f: F) -> R {
        let _lock = super::super::HOME_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let _home_guard = EnvGuard::set("HOME", tmp.path());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(tmp.path())));
        match result {
            Ok(v) => v,
            Err(e) => std::panic::resume_unwind(e),
        }
    }

    /// GEMINI_CLI_HOME env override: writes to $GEMINI_CLI_HOME/.gemini/...
    /// and uses scope_root=None (skips containment check), which allows the
    /// target dir to be outside $HOME (e.g., in /tmp).
    #[test]
    fn gemini_cli_home_env_override_writes_correct_path() {
        with_fake_home(|_home| {
            let dir = tempfile::tempdir().unwrap();
            let _env = EnvGuard::set("GEMINI_CLI_HOME", dir.path());

            let opts = SetupOpts {
                scope: Scope::User,
                with_mcp: false,
                install_zshenv: false,
                dry_run: false,
                force: false,
                tirith_bin: "tirith".to_string(),
            };

            setup_gemini_cli(&opts).unwrap();

            // Hook written to $GEMINI_CLI_HOME/.gemini/hooks/tirith-security-guard-gemini.py
            let hook_path = dir
                .path()
                .join(".gemini")
                .join("hooks")
                .join("tirith-security-guard-gemini.py");
            assert!(
                hook_path.exists(),
                "hook at $GEMINI_CLI_HOME/.gemini/hooks/"
            );

            // Settings written to $GEMINI_CLI_HOME/.gemini/settings.json
            let settings_path = dir.path().join(".gemini").join("settings.json");
            assert!(
                settings_path.exists(),
                "settings at $GEMINI_CLI_HOME/.gemini/"
            );

            // Settings contain the absolute hook command path (quoted for spaces)
            let content = std::fs::read_to_string(&settings_path).unwrap();
            let abs_hook = hook_path.display().to_string();
            assert!(
                content.contains(&abs_hook),
                "settings reference absolute path to hook"
            );
        });
    }

    /// PI_CODING_AGENT_DIR env override: writes to $PI_CODING_AGENT_DIR/extensions/...
    /// and uses scope_root=None (skips containment check).
    #[test]
    fn pi_coding_agent_dir_env_override_writes_correct_path() {
        with_fake_home(|_home| {
            let dir = tempfile::tempdir().unwrap();
            let _env = EnvGuard::set("PI_CODING_AGENT_DIR", dir.path());

            let opts = SetupOpts {
                scope: Scope::User,
                with_mcp: false,
                install_zshenv: false,
                dry_run: false,
                force: false,
                tirith_bin: "tirith".to_string(),
            };

            setup_pi_cli(&opts).unwrap();

            // Guard written to $PI_CODING_AGENT_DIR/extensions/tirith-guard.ts
            let guard_path = dir.path().join("extensions").join("tirith-guard.ts");
            assert!(
                guard_path.exists(),
                "guard at $PI_CODING_AGENT_DIR/extensions/"
            );
        });
    }

    /// Validates that env-overridden paths skip the containment check
    /// (scope_root=None). Without None, a temp dir outside $HOME would fail.
    #[test]
    fn env_override_skips_containment_check() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join(".gemini");

        // With scope_root=None, validation always passes
        fs_helpers::validate_target_dir(&target, None).unwrap();

        // With a scope_root that doesn't contain the target, it would fail
        let unrelated = tempfile::tempdir().unwrap();
        let result = fs_helpers::validate_target_dir(&target, Some(unrelated.path()));
        assert!(
            result.is_err(),
            "containment check should fail when target is outside scope_root"
        );
    }
}
