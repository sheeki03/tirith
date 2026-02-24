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

    // Write tirith-check.py hook (Python hook doesn't use __TIRITH_BIN__ placeholder)
    let hook_path = hooks_dir.join("tirith-check.py");
    let hook_content = crate::assets::TIRITH_CHECK_PY;
    fs_helpers::write_hook_script(&hook_path, hook_content, opts.force, opts.dry_run)?;

    // Merge settings.json with PreToolUse hook
    let settings_path = target.join("settings.json");
    let hook_command = match opts.scope {
        Scope::Project => {
            r#"python3 "${CLAUDE_PROJECT_DIR:-.}/.claude/hooks/tirith-check.py""#.to_string()
        }
        Scope::User => r#"python3 "$HOME/.claude/hooks/tirith-check.py""#.to_string(),
    };
    merge::merge_claude_settings(&settings_path, &hook_command, opts.force, opts.dry_run)?;

    // --with-mcp support
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
                setup_claude_user_mcp(opts)?;
            }
        }
    }

    eprintln!("tirith: Claude Code setup complete");
    Ok(())
}

/// Handle `--with-mcp --scope user` for Claude Code via CLI subprocess.
fn setup_claude_user_mcp(opts: &SetupOpts) -> Result<(), String> {
    if opts.dry_run {
        eprintln!(
            "[dry-run] would run: claude mcp add --scope user --transport stdio tirith -- {} mcp-server",
            opts.tirith_bin
        );
        eprintln!("  (cannot check existing registrations in dry-run mode)");
        return Ok(());
    }

    // Pre-check
    let list_out = fs_helpers::run_cli("claude", &["mcp", "list", "--scope", "user"])?;
    if !list_out.status.success() {
        return Err(format!(
            "claude mcp list failed: {}",
            String::from_utf8_lossy(&list_out.stderr).trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&list_out.stdout);
    let exists = stdout
        .lines()
        .any(|l| l.trim() == "tirith" || l.trim().starts_with("tirith "));

    if exists && !opts.force {
        // Drift detection: get config and compare
        let get_out = fs_helpers::run_cli("claude", &["mcp", "get", "--scope", "user", "tirith"]);
        let config_matches = match get_out {
            Ok(ref out) if out.status.success() => {
                let stdout_str = String::from_utf8_lossy(&out.stdout);
                match serde_json::from_str::<serde_json::Value>(stdout_str.trim()) {
                    Ok(val) => {
                        let cmd = val.get("command").and_then(|v| v.as_str());
                        let args: Option<Vec<&str>> = val
                            .get("args")
                            .and_then(|v| v.as_array())
                            .map(|a| a.iter().filter_map(|v| v.as_str()).collect());
                        Some(
                            cmd == Some(&opts.tirith_bin)
                                && args.as_deref() == Some(&["mcp-server"]),
                        )
                    }
                    Err(_) => None,
                }
            }
            _ => None,
        };
        match config_matches {
            Some(true) => {
                eprintln!("tirith: tirith MCP server already registered with claude, up to date");
            }
            Some(false) => {
                return Err(
                    "tirith MCP server registered with claude but config differs — use --force to update".into(),
                );
            }
            None => {
                return Err(
                    "cannot verify tirith MCP config with claude — use --force to re-register"
                        .into(),
                );
            }
        }
    } else {
        // exists + force: remove then add; !exists: just add
        if exists {
            let _ = fs_helpers::run_cli("claude", &["mcp", "remove", "--scope", "user", "tirith"]);
        }
        let add_out = fs_helpers::run_cli(
            "claude",
            &[
                "mcp",
                "add",
                "--scope",
                "user",
                "--transport",
                "stdio",
                "tirith",
                "--",
                &opts.tirith_bin,
                "mcp-server",
            ],
        )?;
        if !add_out.status.success() {
            return Err(format!(
                "claude mcp add failed: {}",
                String::from_utf8_lossy(&add_out.stderr).trim()
            ));
        }
        eprintln!("tirith: registered tirith MCP server with claude");
    }

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

    // 3. Offer zshenv guard
    zshenv::offer_zshenv_guard(
        opts.install_zshenv,
        opts.force,
        opts.dry_run,
        &opts.tirith_bin,
    )?;

    eprintln!("tirith: Codex setup complete");
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

    // Offer zshenv guard
    zshenv::offer_zshenv_guard(
        opts.install_zshenv,
        opts.force,
        opts.dry_run,
        &opts.tirith_bin,
    )?;

    eprintln!("tirith: Cursor setup complete");
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
    let gateway_path = copy_gateway_config(opts.force, opts.dry_run)?;
    let gw_path_str = gateway_path.display().to_string();
    let mcp_json_path = cwd.join(".vscode").join("mcp.json");
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

    // Offer zshenv guard
    zshenv::offer_zshenv_guard(
        opts.install_zshenv,
        opts.force,
        opts.dry_run,
        &opts.tirith_bin,
    )?;

    eprintln!("tirith: VS Code setup complete");
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

    // Offer zshenv guard
    zshenv::offer_zshenv_guard(
        opts.install_zshenv,
        opts.force,
        opts.dry_run,
        &opts.tirith_bin,
    )?;

    eprintln!("tirith: Windsurf setup complete");
    Ok(())
}
