//! Per-tool setup: hook scripts, JSON config merges, MCP registration, and
//! zshenv guard for each AI coding tool.

use super::fs_helpers;
use super::merge;
use super::run_impl::{copy_gateway_config, Scope, SetupOpts};
#[cfg(unix)]
use super::zshenv;
use serde_json::{json, Value};

#[cfg(unix)]
fn offer_zshenv_guard_for_opts(opts: &SetupOpts) -> Result<(), String> {
    let zshenv_tirith_bin =
        super::run_impl::resolve_tirith_bin_for_zshenv(&opts.tirith_bin, opts.dry_run)?;
    zshenv::offer_zshenv_guard(
        opts.install_zshenv,
        opts.force,
        opts.dry_run,
        &zshenv_tirith_bin,
    )
}

fn codex_mcp_get_reports_missing(stderr: &str) -> bool {
    let stderr = stderr.to_lowercase();
    stderr.contains("not found")
        || stderr.contains("does not exist")
        || stderr.contains("no mcp server named")
}

fn codex_mcp_config_matches(value: &Value, expected_command: &str, expected_args: &[&str]) -> bool {
    // Codex CLI 0.x exposed command/args at the top level; current versions
    // nest them under `transport`. Accept either shape.
    let config = value.get("transport").unwrap_or(value);
    let command = config.get("command").and_then(Value::as_str);
    let args: Option<Vec<&str>> = config
        .get("args")
        .and_then(Value::as_array)
        .and_then(|values| values.iter().map(Value::as_str).collect());
    command == Some(expected_command) && args.as_deref() == Some(expected_args)
}

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

    // The Python hook is used verbatim — no __TIRITH_BIN__ placeholder.
    let hook_path = hooks_dir.join("tirith-check.py");
    let hook_content = crate::assets::TIRITH_CHECK_PY;
    fs_helpers::write_hook_script(&hook_path, hook_content, opts.force, opts.dry_run)?;

    if opts.update_configs {
        eprintln!();
        eprintln!("tirith: Claude Code hook scripts refreshed");
        return Ok(());
    }

    let settings_path = target.join("settings.json");
    let hook_command = match opts.scope {
        Scope::Project => {
            r#"python3 "${CLAUDE_PROJECT_DIR:-.}/.claude/hooks/tirith-check.py""#.to_string()
        }
        Scope::User => r#"python3 "$HOME/.claude/hooks/tirith-check.py""#.to_string(),
    };
    merge::merge_claude_settings(&settings_path, &hook_command, opts.force, opts.dry_run)?;

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
                // Merge directly into ~/.claude/settings.json mcpServers — avoid
                // `claude mcp add`, which deadlocks inside an active CC session.
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

    if let Err(e) =
        super::shell_profile::install_shell_hook(&opts.tirith_bin, opts.force, opts.dry_run)
    {
        // Shell hook failure is best-effort — warn but don't fail setup.
        eprintln!("tirith: WARNING: {e}");
    }

    eprintln!();
    eprintln!("tirith: Claude Code setup complete");
    eprintln!("  Run `tirith doctor` to verify your configuration.");
    Ok(())
}

pub fn setup_codex(opts: &SetupOpts) -> Result<(), String> {
    let gateway_path = copy_gateway_config(opts.force, opts.dry_run)?;

    if opts.update_configs {
        eprintln!();
        eprintln!("tirith: Codex gateway config refreshed");
        return Ok(());
    }

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
            let stderr = String::from_utf8_lossy(&get_out.stderr);
            if codex_mcp_get_reports_missing(&stderr) {
                false
            } else {
                return Err(format!(
                    "codex mcp get failed unexpectedly: {}",
                    stderr.trim()
                ));
            }
        };

        if exists && !opts.force {
            // Drift detection: compare existing registration's command+args
            // with what we would write, via `codex mcp get --json`.
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
                    match serde_json::from_slice::<Value>(&out.stdout) {
                        Ok(val) => Some(codex_mcp_config_matches(
                            &val,
                            tirith_bin,
                            expected_args.as_slice(),
                        )),
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

    if let Err(e) =
        super::shell_profile::install_shell_hook(&opts.tirith_bin, opts.force, opts.dry_run)
    {
        eprintln!("tirith: WARNING: {e}");
    }

    #[cfg(unix)]
    offer_zshenv_guard_for_opts(opts)?;

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

    let hook_path = hooks_dir.join("tirith-hook.sh");
    let hook_content = crate::assets::CURSOR_HOOK_SH.replace("__TIRITH_BIN__", &opts.tirith_bin);
    fs_helpers::write_hook_script(&hook_path, &hook_content, opts.force, opts.dry_run)?;

    // Gateway config is refreshed in both full and --update-configs modes.
    let gateway_path = copy_gateway_config(opts.force, opts.dry_run)?;

    if opts.update_configs {
        eprintln!();
        eprintln!("tirith: Cursor hook scripts and gateway config refreshed");
        return Ok(());
    }

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

    if let Err(e) =
        super::shell_profile::install_shell_hook(&opts.tirith_bin, opts.force, opts.dry_run)
    {
        eprintln!("tirith: WARNING: {e}");
    }

    #[cfg(unix)]
    offer_zshenv_guard_for_opts(opts)?;

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

    let hook_path = hooks_dir.join("tirith-hook.sh");
    let hook_content = crate::assets::VSCODE_HOOK_SH.replace("__TIRITH_BIN__", &opts.tirith_bin);
    fs_helpers::write_hook_script(&hook_path, &hook_content, opts.force, opts.dry_run)?;

    let gateway_path = copy_gateway_config(opts.force, opts.dry_run)?;

    if opts.update_configs {
        eprintln!();
        eprintln!("tirith: VS Code hook scripts and gateway config refreshed");
        return Ok(());
    }

    let settings_path = target.join("settings.json");
    // VS Code is project-only, so the hook command is a relative path.
    let hook_cmd = "hooks/tirith-hook.sh".to_string();
    merge::merge_vscode_settings(&settings_path, &hook_cmd, opts.force, opts.dry_run)?;

    // VS Code uses "servers" as the top-level key (not "mcpServers") and
    // requires "type": "stdio" — see merge_mcp_json_with_key callsite.
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

    if let Err(e) =
        super::shell_profile::install_shell_hook(&opts.tirith_bin, opts.force, opts.dry_run)
    {
        eprintln!("tirith: WARNING: {e}");
    }

    #[cfg(unix)]
    offer_zshenv_guard_for_opts(opts)?;

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

    let hook_path = hooks_dir.join("tirith-security-guard-gemini.py");
    let hook_content = crate::assets::GEMINI_HOOK_PY;
    fs_helpers::write_hook_script(&hook_path, hook_content, opts.force, opts.dry_run)?;

    if opts.update_configs {
        eprintln!();
        eprintln!("tirith: Gemini CLI hook scripts refreshed");
        return Ok(());
    }

    let settings_path = target.join("settings.json");
    let hook_command = match opts.scope {
        Scope::Project => {
            r#"python3 "$GEMINI_PROJECT_DIR/.gemini/hooks/tirith-security-guard-gemini.py""#
                .to_string()
        }
        Scope::User => {
            let abs = hooks_dir.join("tirith-security-guard-gemini.py");
            format!(
                "python3 {}",
                super::shell_profile::shell_quote(&abs.display().to_string(), "bash")
            )
        }
    };
    merge::merge_gemini_settings(&settings_path, &hook_command, opts.force, opts.dry_run)?;

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

    if let Err(e) =
        super::shell_profile::install_shell_hook(&opts.tirith_bin, opts.force, opts.dry_run)
    {
        eprintln!("tirith: WARNING: {e}");
    }

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

    let guard_path = extensions_dir.join("tirith-guard.ts");
    let guard_content = crate::assets::TIRITH_GUARD_TS;
    fs_helpers::write_hook_script(&guard_path, guard_content, opts.force, opts.dry_run)?;

    if opts.update_configs {
        eprintln!();
        eprintln!("tirith: Pi CLI hook scripts refreshed");
        return Ok(());
    }

    if let Err(e) =
        super::shell_profile::install_shell_hook(&opts.tirith_bin, opts.force, opts.dry_run)
    {
        eprintln!("tirith: WARNING: {e}");
    }

    eprintln!();
    eprintln!("tirith: Pi CLI setup complete");
    eprintln!("  Run `tirith doctor` to verify your configuration.");
    Ok(())
}

pub fn setup_openclaw(opts: &SetupOpts) -> Result<(), String> {
    let home = home::home_dir().ok_or_else(|| "could not determine home directory".to_string())?;

    let (target, scope_root) = match opts.scope {
        Scope::Project => {
            let cwd = std::env::current_dir().map_err(|e| format!("current_dir: {e}"))?;
            (cwd.join(".openclaw"), Some(cwd))
        }
        Scope::User => {
            if let Some(state_dir) = std::env::var_os("OPENCLAW_STATE_DIR")
                .or_else(|| std::env::var_os("CLAWDBOT_STATE_DIR"))
            {
                let mut p = std::path::PathBuf::from(&state_dir);
                if let Some(s) = state_dir.to_str() {
                    if let Some(rest) = s.strip_prefix("~/").or_else(|| s.strip_prefix("~\\")) {
                        p = home.join(rest);
                    } else if s == "~" {
                        p = home.clone();
                    }
                }
                if p.is_relative() {
                    if let Ok(cwd) = std::env::current_dir() {
                        p = cwd.join(p);
                    }
                }
                (p, None)
            } else {
                (home.join(".openclaw"), Some(home.clone()))
            }
        }
    };

    fs_helpers::validate_target_dir(&target, scope_root.as_deref())?;

    let extensions_dir = target.join("extensions").join("tirith-security");
    if !opts.dry_run {
        std::fs::create_dir_all(&extensions_dir)
            .map_err(|e| format!("create {}: {e}", extensions_dir.display()))?;
    }

    let guard_path = extensions_dir.join("index.ts");
    let guard_content = crate::assets::OPENCLAW_GUARD_TS;
    fs_helpers::write_hook_script(&guard_path, guard_content, opts.force, opts.dry_run)?;

    if opts.update_configs {
        eprintln!();
        eprintln!("tirith: OpenClaw hook scripts refreshed");
        return Ok(());
    }

    if let Err(e) =
        super::shell_profile::install_shell_hook(&opts.tirith_bin, opts.force, opts.dry_run)
    {
        eprintln!("tirith: WARNING: {e}");
    }

    eprintln!();
    eprintln!("tirith: OpenClaw setup complete");
    eprintln!("  Extension installed to: {}", extensions_dir.display());
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

    let hook_path = hooks_dir.join("tirith-hook.sh");
    let hook_content = crate::assets::WINDSURF_HOOK_SH.replace("__TIRITH_BIN__", &opts.tirith_bin);
    fs_helpers::write_hook_script(&hook_path, &hook_content, opts.force, opts.dry_run)?;

    let gateway_path = copy_gateway_config(opts.force, opts.dry_run)?;

    if opts.update_configs {
        eprintln!();
        eprintln!("tirith: Windsurf hook scripts and gateway config refreshed");
        return Ok(());
    }

    // Windsurf is user-global, so hooks.json references an absolute path.
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

    if let Err(e) =
        super::shell_profile::install_shell_hook(&opts.tirith_bin, opts.force, opts.dry_run)
    {
        eprintln!("tirith: WARNING: {e}");
    }

    #[cfg(unix)]
    offer_zshenv_guard_for_opts(opts)?;

    eprintln!();
    eprintln!("tirith: Windsurf setup complete");
    eprintln!("  Run `tirith doctor` to verify your configuration.");
    Ok(())
}

pub fn setup_copilot_cli(opts: &SetupOpts) -> Result<(), String> {
    // Copilot CLI loads .github/hooks/*.json from the cwd with no walk-up;
    // require a git repo so doctor detection has a stable root.
    let repo_root = tirith_core::policy::find_repo_root(None).ok_or_else(|| {
        "tirith setup copilot-cli requires being run inside a git repository — \
         Copilot CLI loads hooks from the repo root"
            .to_string()
    })?;

    fs_helpers::validate_target_dir(&repo_root, Some(&repo_root))?;

    let hooks_dir = repo_root.join(".github").join("hooks");
    if !opts.dry_run {
        std::fs::create_dir_all(&hooks_dir)
            .map_err(|e| format!("create {}: {e}", hooks_dir.display()))?;
    }

    let hook_path = hooks_dir.join("copilot-cli-hook.py");
    fs_helpers::write_hook_script(
        &hook_path,
        crate::assets::COPILOT_HOOK_PY,
        opts.force,
        opts.dry_run,
    )?;

    // Tirith owns this file entirely (no merge) — we rewrite on every setup.
    let config_path = hooks_dir.join("tirith-security.json");
    let config = serde_json::json!({
        "version": 1,
        "hooks": {
            "preToolUse": [
                {
                    "type": "command",
                    "bash": "python3 .github/hooks/copilot-cli-hook.py",
                    "timeoutSec": 30
                }
            ]
        }
    });
    let config_str =
        serde_json::to_string_pretty(&config).map_err(|e| format!("serialize: {e}"))?;
    write_owned_json(&config_path, &config_str, opts.force, opts.dry_run)?;

    if opts.update_configs {
        eprintln!();
        eprintln!("tirith: Copilot CLI hook scripts and config refreshed");
        return Ok(());
    }

    if let Err(e) =
        super::shell_profile::install_shell_hook(&opts.tirith_bin, opts.force, opts.dry_run)
    {
        eprintln!("tirith: WARNING: {e}");
    }

    eprintln!();
    eprintln!("tirith: Copilot CLI setup complete");
    eprintln!("  Hook config: {}", config_path.display());
    eprintln!("  IMPORTANT: Copilot CLI loads hooks from the current working directory.");
    eprintln!(
        "  Always launch `copilot` from the repository root ({}) so the hook is loaded.",
        repo_root.display()
    );
    eprintln!("  Run `tirith doctor` to verify your configuration.");
    Ok(())
}

pub fn setup_kiro(opts: &SetupOpts) -> Result<(), String> {
    let home = home::home_dir().ok_or_else(|| "could not determine home directory".to_string())?;

    // Project scope: walk up for an existing .kiro/ and honor it, else create
    // one at cwd. User scope: always ~/.kiro.
    let (kiro_root, scope_root, created_new_workspace) = match opts.scope {
        Scope::Project => {
            let cwd = std::env::current_dir().map_err(|e| format!("current_dir: {e}"))?;
            match tirith_core::policy::find_workspace_kiro_dir(&cwd) {
                Some(parent) => (parent.join(".kiro"), Some(parent), false),
                None => (cwd.join(".kiro"), Some(cwd), true),
            }
        }
        Scope::User => (home.join(".kiro"), Some(home.clone()), false),
    };

    fs_helpers::validate_target_dir(&kiro_root, scope_root.as_deref())?;

    let hooks_dir = kiro_root.join("hooks");
    let agents_dir = kiro_root.join("agents");
    if !opts.dry_run {
        std::fs::create_dir_all(&hooks_dir)
            .map_err(|e| format!("create {}: {e}", hooks_dir.display()))?;
        std::fs::create_dir_all(&agents_dir)
            .map_err(|e| format!("create {}: {e}", agents_dir.display()))?;
    }

    let hook_path = hooks_dir.join("kiro-hook.py");
    fs_helpers::write_hook_script(
        &hook_path,
        crate::assets::KIRO_HOOK_PY,
        opts.force,
        opts.dry_run,
    )?;

    // Absolute hook paths in both scopes (Kiro doesn't document agent-relative
    // resolution). tools=["*"] keeps default tool access; includeMcpJson keeps
    // the user's MCP servers.
    let agent_path = agents_dir.join("tirith-security.json");
    let quoted = super::shell_profile::shell_quote(&hook_path.display().to_string(), "bash");
    let command = format!("python3 {quoted}");
    let agent = serde_json::json!({
        "description": "Tirith security guard: intercepts execute_bash tool calls and blocks dangerous commands.",
        "tools": ["*"],
        "includeMcpJson": true,
        "hooks": {
            "preToolUse": [
                {
                    "matcher": "execute_bash",
                    "command": command
                }
            ]
        }
    });
    let agent_str = serde_json::to_string_pretty(&agent).map_err(|e| format!("serialize: {e}"))?;
    write_owned_json(&agent_path, &agent_str, opts.force, opts.dry_run)?;

    if opts.update_configs {
        eprintln!();
        eprintln!("tirith: Kiro hook scripts and agent refreshed");
        return Ok(());
    }

    if let Err(e) =
        super::shell_profile::install_shell_hook(&opts.tirith_bin, opts.force, opts.dry_run)
    {
        eprintln!("tirith: WARNING: {e}");
    }

    eprintln!();
    eprintln!("tirith: Kiro CLI setup complete");
    eprintln!("  Agent file: {}", agent_path.display());
    if created_new_workspace {
        eprintln!(
            "  Note: created a new Kiro workspace rooted at {} (no ancestor .kiro/ found).",
            kiro_root
                .parent()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        );
    }
    if matches!(opts.scope, Scope::Project) {
        eprintln!("  Note: project-scope agent uses an absolute hook path (machine-specific).");
        eprintln!(
            "  Add {} and {} to .gitignore for shared repos, or prefer --scope user.",
            agent_path.display(),
            hook_path.display()
        );
    }
    eprintln!("  To use: kiro-cli --agent tirith-security  (or merge the hooks block from");
    eprintln!(
        "  {} into your existing custom agent).",
        agent_path.display()
    );
    eprintln!("  Run `tirith doctor` to verify your configuration.");
    Ok(())
}

/// Write a tirith-owned JSON config file with drift detection.
/// Used for files where tirith owns the entire file (no merge with user content).
fn write_owned_json(
    path: &std::path::Path,
    content: &str,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    if path.exists() {
        let existing =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        if existing == content {
            eprintln!("tirith: {} already configured, up to date", path.display());
            return Ok(());
        }
        if !force {
            if dry_run {
                eprintln!(
                    "[dry-run] would error: {} exists with different content — use --force to update",
                    path.display()
                );
                return Ok(());
            }
            return Err(format!(
                "{} exists with different content — use --force to update",
                path.display()
            ));
        }
        if !dry_run {
            fs_helpers::create_backup(path, true)?;
        }
    }
    if dry_run {
        eprintln!(
            "[dry-run] would write {} ({} bytes)",
            path.display(),
            content.len()
        );
        return Ok(());
    }
    fs_helpers::atomic_write(path, content, 0o644)?;
    eprintln!("tirith: wrote {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_harness::{with_fake_env, EnvGuard};

    #[test]
    fn codex_mcp_get_reports_missing_accepts_known_cli_messages() {
        // Legacy Codex CLI variants:
        assert!(codex_mcp_get_reports_missing(
            "error: MCP server tirith-gateway not found"
        ));
        assert!(codex_mcp_get_reports_missing(
            "tirith-gateway does not exist"
        ));
        // Current Codex CLI message (the bug report case):
        assert!(codex_mcp_get_reports_missing(
            "Error: No MCP server named 'tirith-gateway' found."
        ));
        // Unrelated error must NOT be classified as missing-server:
        assert!(!codex_mcp_get_reports_missing(
            "permission denied reading codex config"
        ));
    }

    #[test]
    fn codex_mcp_config_matches_current_transport_shape() {
        let value = json!({
            "name": "tirith-gateway",
            "transport": {
                "type": "stdio",
                "command": "tirith",
                "args": [
                    "gateway", "run",
                    "--upstream-bin", "tirith",
                    "--upstream-arg", "mcp-server",
                    "--config", "/Users/example/.config/tirith/gateway.yaml"
                ]
            }
        });
        let expected_args = [
            "gateway",
            "run",
            "--upstream-bin",
            "tirith",
            "--upstream-arg",
            "mcp-server",
            "--config",
            "/Users/example/.config/tirith/gateway.yaml",
        ];
        assert!(codex_mcp_config_matches(&value, "tirith", &expected_args));
    }

    #[test]
    fn codex_mcp_config_matches_legacy_top_level_shape() {
        let value = json!({
            "command": "tirith",
            "args": ["gateway", "run"]
        });
        let expected_args = ["gateway", "run"];
        assert!(codex_mcp_config_matches(&value, "tirith", &expected_args));
    }

    #[test]
    fn codex_mcp_config_rejects_drift() {
        let value = json!({
            "name": "tirith-gateway",
            "transport": {
                "type": "stdio",
                "command": "tirith",
                "args": ["gateway", "run", "--config", "/old/path.yaml"]
            }
        });
        let expected_args = ["gateway", "run", "--config", "/new/path.yaml"];
        assert!(!codex_mcp_config_matches(&value, "tirith", &expected_args));
    }

    #[cfg(unix)]
    fn write_fake_codex(bin_dir: &std::path::Path, script: &str) {
        use std::os::unix::fs::PermissionsExt;
        let codex = bin_dir.join("codex");
        std::fs::write(&codex, script).unwrap();
        let mut perms = std::fs::metadata(&codex).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&codex, perms).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn setup_codex_registers_when_current_cli_reports_missing_server() {
        with_fake_env(false, |home, _cwd| {
            // Pin XDG_CONFIG_HOME so the gateway path (<XDG>/tirith/gateway.yaml)
            // the assertion below checks is deterministic.
            let xdg = home.join(".config");
            let _xdg = EnvGuard::set("XDG_CONFIG_HOME", &xdg);

            let bin_dir = tempfile::tempdir().unwrap();
            let log_path = home.join("codex.log");
            let _path = EnvGuard::set("PATH", bin_dir.path());
            let _log = EnvGuard::set("CODEX_LOG", &log_path);
            let _shell = EnvGuard::set("SHELL", std::path::Path::new("/bin/zsh"));

            write_fake_codex(
                bin_dir.path(),
                // Literal r#"..."# — Rust raw strings can't interpolate; don't
                // "simplify" into a heredoc expecting Rust-side substitution.
                r#"#!/bin/sh
printf '%s\n' "$*" >> "$CODEX_LOG"
if [ "$1" = "mcp" ] && [ "$2" = "get" ] && [ "$3" = "tirith-gateway" ]; then
  echo "Error: No MCP server named 'tirith-gateway' found." >&2
  exit 1
fi
if [ "$1" = "mcp" ] && [ "$2" = "add" ]; then
  exit 0
fi
echo "unexpected codex args: $*" >&2
exit 64
"#,
            );

            let mut opts = opts_for(Scope::User);
            opts.tirith_bin = "/bin/tirith".to_string();

            setup_codex(&opts).unwrap();

            let log = std::fs::read_to_string(&log_path).unwrap();
            assert!(
                log.contains("mcp get tirith-gateway"),
                "should probe for existing registration; log: {log}"
            );
            // Full mcp add invocation (catches argument drift, not just
            // "add was called"). Gateway path is XDG-deterministic above.
            let expected_gateway = xdg.join("tirith/gateway.yaml");
            let expected_add = format!(
                "mcp add tirith-gateway -- /bin/tirith gateway run \
                 --upstream-bin /bin/tirith --upstream-arg mcp-server \
                 --config {}",
                expected_gateway.display()
            );
            assert!(
                log.contains(&expected_add),
                "setup must register with full expected args; \
                 expected: {expected_add}\nlog: {log}"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn setup_codex_accepts_current_transport_json_as_up_to_date() {
        with_fake_env(false, |home, _cwd| {
            let xdg = home.join(".config");
            let _xdg = EnvGuard::set("XDG_CONFIG_HOME", &xdg);

            let bin_dir = tempfile::tempdir().unwrap();
            let log_path = home.join("codex.log");
            let _path = EnvGuard::set("PATH", bin_dir.path());
            let _log = EnvGuard::set("CODEX_LOG", &log_path);
            let _shell = EnvGuard::set("SHELL", std::path::Path::new("/bin/zsh"));

            // The fake script splices $XDG_CONFIG_HOME at shell-execution time;
            // it must stay a raw string (the test relies on the spawned shell's
            // $XDG_CONFIG_HOME matching what etcetera computes in setup_codex).
            write_fake_codex(
                bin_dir.path(),
                r#"#!/bin/sh
printf '%s\n' "$*" >> "$CODEX_LOG"
if [ "$1" = "mcp" ] && [ "$2" = "get" ] && [ "$3" = "tirith-gateway" ]; then
  echo "tirith-gateway"
  exit 0
fi
if [ "$1" = "mcp" ] && [ "$2" = "get" ] && [ "$3" = "--json" ] && [ "$4" = "tirith-gateway" ]; then
  printf '%s%s%s\n' '{"name":"tirith-gateway","transport":{"type":"stdio","command":"/bin/tirith","args":["gateway","run","--upstream-bin","/bin/tirith","--upstream-arg","mcp-server","--config","' "$XDG_CONFIG_HOME" '/tirith/gateway.yaml"]}}'
  exit 0
fi
echo "unexpected codex args: $*" >&2
exit 64
"#,
            );

            let mut opts = opts_for(Scope::User);
            opts.tirith_bin = "/bin/tirith".to_string();

            setup_codex(&opts).unwrap();

            let log = std::fs::read_to_string(&log_path).unwrap();
            assert!(log.contains("mcp get tirith-gateway"));
            assert!(log.contains("mcp get --json tirith-gateway"));
            assert!(
                !log.contains("mcp add"),
                "up-to-date transport config must not be re-registered; log: {log}"
            );
        });
    }

    /// GEMINI_CLI_HOME env override: writes to $GEMINI_CLI_HOME/.gemini/...
    /// and uses scope_root=None (skips containment check), which allows the
    /// target dir to be outside $HOME (e.g., in /tmp).
    #[test]
    fn gemini_cli_home_env_override_writes_correct_path() {
        with_fake_env(false, |_home, _cwd| {
            let dir = tempfile::tempdir().unwrap();
            let _env = EnvGuard::set("GEMINI_CLI_HOME", dir.path());

            let opts = SetupOpts {
                scope: Scope::User,
                with_mcp: false,
                install_zshenv: false,
                dry_run: false,
                force: false,
                tirith_bin: "tirith".to_string(),
                update_configs: false,
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

            // Settings contain the absolute hook command path (quoted for spaces).
            // On Windows, path separators in JSON vs display() may differ, so
            // only check on Unix where the formats are guaranteed to match.
            #[cfg(unix)]
            {
                let content = std::fs::read_to_string(&settings_path).unwrap();
                let abs_hook = hook_path.display().to_string();
                assert!(
                    content.contains(&abs_hook),
                    "settings reference absolute path to hook"
                );
            }
        });
    }

    /// PI_CODING_AGENT_DIR env override: writes to $PI_CODING_AGENT_DIR/extensions/...
    /// and uses scope_root=None (skips containment check).
    #[test]
    fn pi_coding_agent_dir_env_override_writes_correct_path() {
        with_fake_env(false, |_home, _cwd| {
            let dir = tempfile::tempdir().unwrap();
            let _env = EnvGuard::set("PI_CODING_AGENT_DIR", dir.path());

            let opts = SetupOpts {
                scope: Scope::User,
                with_mcp: false,
                install_zshenv: false,
                dry_run: false,
                force: false,
                tirith_bin: "tirith".to_string(),
                update_configs: false,
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

    fn opts_for(scope: Scope) -> SetupOpts {
        SetupOpts {
            scope,
            with_mcp: false,
            install_zshenv: false,
            dry_run: false,
            force: false,
            tirith_bin: "tirith".to_string(),
            update_configs: false,
        }
    }

    /// Strip surrounding single quotes (POSIX `shell_quote` style).
    fn unquote_posix(s: &str) -> String {
        let trimmed = s.trim();
        if trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2 {
            trimmed[1..trimmed.len() - 1].replace("'\\''", "'")
        } else {
            trimmed.to_string()
        }
    }

    #[test]
    fn setup_copilot_cli_writes_both_files_in_project() {
        with_fake_env(true, |_home, cwd| {
            let cwd = cwd.expect("cwd set");
            // Fake the cwd into a git repo so find_repo_root resolves here.
            std::fs::create_dir_all(cwd.join(".git")).unwrap();
            // Descend into a subdirectory — setup must still write at repo root.
            let subdir = cwd.join("sub").join("dir");
            std::fs::create_dir_all(&subdir).unwrap();
            std::env::set_current_dir(&subdir).unwrap();

            setup_copilot_cli(&opts_for(Scope::Project)).unwrap();

            let hook = cwd.join(".github/hooks/copilot-cli-hook.py");
            let cfg = cwd.join(".github/hooks/tirith-security.json");
            assert!(hook.exists(), "hook at repo root, not subdir");
            assert!(cfg.exists(), "config at repo root, not subdir");
            assert!(
                !subdir.join(".github").exists(),
                "must NOT create .github under subdir"
            );

            let raw = std::fs::read_to_string(&cfg).unwrap();
            let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(v["version"], 1);
            let entry = &v["hooks"]["preToolUse"][0];
            assert_eq!(entry["type"], "command");
            assert_eq!(
                entry["bash"], "python3 .github/hooks/copilot-cli-hook.py",
                "relative bash path, not absolute"
            );
            assert_eq!(entry["timeoutSec"], 30);
            assert!(
                entry.get("cwd").is_none(),
                "no cwd field — Copilot loads relative to its own cwd"
            );
        });
    }

    #[test]
    fn setup_copilot_cli_errors_outside_git_repo() {
        with_fake_env(true, |_home, _cwd| {
            let result = setup_copilot_cli(&opts_for(Scope::Project));
            assert!(result.is_err(), "expected Err");
            let msg = result.unwrap_err();
            assert!(
                msg.contains("requires being run inside a git repository"),
                "expected git-repo message, got: {msg}"
            );
        });
    }

    #[test]
    fn setup_kiro_user_scope_writes_hook_and_agent() {
        with_fake_env(false, |home, _cwd| {
            setup_kiro(&opts_for(Scope::User)).unwrap();

            // Chained single-component `.join`s so Windows separators match
            // production; an embedded-slash path would mix `\` and `/`.
            let hook = home.join(".kiro").join("hooks").join("kiro-hook.py");
            let agent = home
                .join(".kiro")
                .join("agents")
                .join("tirith-security.json");
            assert!(hook.exists(), "hook at ~/.kiro/hooks/");
            assert!(agent.exists(), "agent at ~/.kiro/agents/");

            let raw = std::fs::read_to_string(&agent).unwrap();
            let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(v["tools"], serde_json::json!(["*"]));
            assert_eq!(v["includeMcpJson"], true);
            let entry = &v["hooks"]["preToolUse"][0];
            assert_eq!(entry["matcher"], "execute_bash");

            let cmd = entry["command"].as_str().expect("command is string");
            let prefix = "python3 ";
            assert!(
                cmd.starts_with(prefix),
                "command should start with `python3 `, got: {cmd}"
            );
            let path_part = unquote_posix(&cmd[prefix.len()..]);
            let expected = hook.display().to_string();
            assert_eq!(
                path_part, expected,
                "command path (after unquote) must equal absolute hook path"
            );
        });
    }

    #[test]
    fn setup_kiro_project_scope_uses_absolute_command() {
        with_fake_env(true, |_home, cwd| {
            let cwd = cwd.expect("cwd set");
            setup_kiro(&opts_for(Scope::Project)).unwrap();

            let agent = cwd.join(".kiro/agents/tirith-security.json");
            assert!(agent.exists());
            let raw = std::fs::read_to_string(&agent).unwrap();
            let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
            let cmd = v["hooks"]["preToolUse"][0]["command"]
                .as_str()
                .expect("command is string");
            let prefix = "python3 ";
            assert!(
                cmd.starts_with(prefix),
                "command starts with python3: {cmd}"
            );
            let path_part = unquote_posix(&cmd[prefix.len()..]);
            let path = std::path::Path::new(&path_part);
            assert!(
                path.is_absolute(),
                "command path must be absolute, got: {path_part}"
            );
            // Resolve symlinks on both sides — macOS /var vs /private/var trips this.
            let canon_cmd = path.canonicalize().expect("canonicalize cmd path");
            let canon_cwd = cwd.canonicalize().expect("canonicalize cwd");
            assert!(
                canon_cmd.starts_with(&canon_cwd),
                "absolute path must be under tempdir cwd. cmd canon: {} ; cwd canon: {}",
                canon_cmd.display(),
                canon_cwd.display()
            );
        });
    }

    #[test]
    fn setup_kiro_project_honors_ancestor_kiro_dir() {
        with_fake_env(true, |_home, cwd| {
            let cwd = cwd.expect("cwd set");
            std::fs::create_dir_all(cwd.join(".kiro")).unwrap();
            let subdir = cwd.join("sub").join("dir");
            std::fs::create_dir_all(&subdir).unwrap();
            std::env::set_current_dir(&subdir).unwrap();

            setup_kiro(&opts_for(Scope::Project)).unwrap();

            let agent_at_root = cwd.join(".kiro/agents/tirith-security.json");
            let agent_at_subdir = subdir.join(".kiro/agents/tirith-security.json");
            assert!(agent_at_root.exists(), "agent must land at ancestor .kiro/");
            assert!(
                !agent_at_subdir.exists(),
                "must NOT create nested .kiro/ at subdir"
            );
        });
    }

    #[test]
    fn setup_kiro_project_creates_new_kiro_dir_when_none_upward() {
        with_fake_env(true, |_home, cwd| {
            let cwd = cwd.expect("cwd set");
            setup_kiro(&opts_for(Scope::Project)).unwrap();
            assert!(
                cwd.join(".kiro/agents/tirith-security.json").exists(),
                "creates new .kiro/ at cwd when no ancestor exists"
            );
        });
    }
}
