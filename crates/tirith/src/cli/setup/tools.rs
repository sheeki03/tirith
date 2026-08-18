//! Per-tool setup: hook scripts, JSON config merges, MCP registration, and
//! zshenv guard for each AI coding tool.

use super::fs_helpers;
use super::merge;
use super::run_impl::{
    copy_gateway_config, path_to_utf8, publish_codex_gateway_config, retire_codex_gateway_config,
    Scope, SetupOpts,
};
#[cfg(unix)]
use super::zshenv;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

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
    let stderr = stderr.trim().trim_end_matches('.').to_ascii_lowercase();
    matches!(
        stderr.as_str(),
        "error: mcp server tirith-gateway not found"
            | "mcp server tirith-gateway not found"
            | "tirith-gateway does not exist"
            | "error: no mcp server named 'tirith-gateway' found"
            | "no mcp server named 'tirith-gateway' found"
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RestorableCodexMcpRegistration {
    command: String,
    args: Vec<String>,
}

impl RestorableCodexMcpRegistration {
    /// Normalize the complete effective Codex registration into the exact
    /// subset that `codex mcp add NAME -- COMMAND ARGS...` can recreate. Refuse
    /// forced mutation before removal when any effective field cannot be
    /// restored through that CLI surface.
    fn from_effective(value: &Value) -> Result<Self, String> {
        let registration = value
            .as_object()
            .ok_or_else(|| "registration is not a JSON object".to_string())?;
        const REGISTRATION_FIELDS: &[&str] = &[
            "auth_status",
            "disabled_reason",
            "enabled",
            "name",
            "startup_timeout_sec",
            "tool_timeout_sec",
            "transport",
        ];
        if let Some(field) = registration
            .keys()
            .find(|key| !REGISTRATION_FIELDS.contains(&key.as_str()))
        {
            return Err(format!("unsupported registration field {field:?}"));
        }
        if registration.get("name").and_then(Value::as_str) != Some("tirith-gateway") {
            return Err("registration name is not tirith-gateway".into());
        }
        if registration.get("enabled").and_then(Value::as_bool) != Some(true) {
            return Err("registration is not enabled".into());
        }
        for field in ["disabled_reason", "startup_timeout_sec", "tool_timeout_sec"] {
            if registration
                .get(field)
                .is_some_and(|value| !value.is_null())
            {
                return Err(format!("registration field {field:?} is not restorable"));
            }
        }

        let transport = registration
            .get("transport")
            .and_then(Value::as_object)
            .ok_or_else(|| "registration transport is not an object".to_string())?;
        const TRANSPORT_FIELDS: &[&str] = &["args", "command", "cwd", "env", "env_vars", "type"];
        if let Some(field) = transport
            .keys()
            .find(|key| !TRANSPORT_FIELDS.contains(&key.as_str()))
        {
            return Err(format!("unsupported transport field {field:?}"));
        }
        if transport.get("type").and_then(Value::as_str) != Some("stdio") {
            return Err("registration transport is not stdio".into());
        }
        if transport.get("cwd").is_some_and(|value| !value.is_null()) {
            return Err("registration cwd override is not restorable".into());
        }
        if transport.get("env").is_some_and(|value| {
            !value.is_null() && !value.as_object().is_some_and(serde_json::Map::is_empty)
        }) {
            return Err("registration environment is not restorable".into());
        }
        if transport
            .get("env_vars")
            .is_some_and(|value| !value.is_null() && !value.as_array().is_some_and(Vec::is_empty))
        {
            return Err("registration inherited environment is not restorable".into());
        }

        let command = transport
            .get("command")
            .and_then(Value::as_str)
            .ok_or_else(|| "registration command is not a string".to_string())?
            .to_string();
        let args = transport
            .get("args")
            .and_then(Value::as_array)
            .ok_or_else(|| "registration args are not an array".to_string())?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToString::to_string)
                    .ok_or_else(|| "registration arg is not a string".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { command, args })
    }

    fn add_args(&self) -> Vec<String> {
        let mut args = vec![
            "mcp".to_string(),
            "add".to_string(),
            "tirith-gateway".to_string(),
            "--".to_string(),
            self.command.clone(),
        ];
        args.extend(self.args.iter().cloned());
        args
    }

    fn managed_gateway_config_path(&self) -> Option<PathBuf> {
        if self.args.len() != 8
            || self.args[0] != "gateway"
            || self.args[1] != "run"
            || self.args[2] != "--upstream-bin"
            || self.args[3] != self.command
            || self.args[4] != "--upstream-arg"
            || self.args[5] != "mcp-server"
            || self.args[6] != "--config"
        {
            return None;
        }
        Some(PathBuf::from(&self.args[7]))
    }
}

fn codex_mcp_config_matches(value: &Value, expected_command: &str, expected_args: &[&str]) -> bool {
    let Ok(registration) = RestorableCodexMcpRegistration::from_effective(value) else {
        return false;
    };
    registration.command == expected_command
        && registration
            .args
            .iter()
            .map(String::as_str)
            .eq(expected_args.iter().copied())
}

fn codex_mcp_output_error(action: &str, output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    format!(
        "codex mcp {action} failed (exit {}): {}",
        output.status.code().unwrap_or(-1),
        stderr.trim()
    )
}

fn run_codex_mcp_add<F>(
    run_cli: &mut F,
    cwd: &Path,
    registration: &RestorableCodexMcpRegistration,
) -> Result<(), String>
where
    F: FnMut(&Path, &str, &[&str]) -> Result<std::process::Output, String>,
{
    let owned_args = registration.add_args();
    let args: Vec<&str> = owned_args.iter().map(String::as_str).collect();
    let output = run_cli(cwd, "codex", &args)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(codex_mcp_output_error("add", &output))
    }
}

fn remove_codex_mcp_registration<F>(
    run_cli: &mut F,
    cwd: &Path,
    allow_missing: bool,
) -> Result<(), String>
where
    F: FnMut(&Path, &str, &[&str]) -> Result<std::process::Output, String>,
{
    let output = run_cli(cwd, "codex", &["mcp", "remove", "tirith-gateway"])?;
    if output.status.success()
        || (allow_missing
            && codex_mcp_get_reports_missing(&String::from_utf8_lossy(&output.stderr)))
    {
        Ok(())
    } else {
        Err(codex_mcp_output_error("remove", &output))
    }
}

fn query_codex_mcp_registration<F>(run_cli: &mut F, cwd: &Path) -> Result<Option<Value>, String>
where
    F: FnMut(&Path, &str, &[&str]) -> Result<std::process::Output, String>,
{
    let output = run_cli(cwd, "codex", &["mcp", "get", "--json", "tirith-gateway"])?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if codex_mcp_get_reports_missing(&stderr) {
            return Ok(None);
        }
        return Err(codex_mcp_output_error("get --json", &output));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("codex mcp get --json returned invalid JSON: {error}"))
        .map(Some)
}

fn read_codex_mcp_registration<F>(run_cli: &mut F, cwd: &Path) -> Result<Value, String>
where
    F: FnMut(&Path, &str, &[&str]) -> Result<std::process::Output, String>,
{
    query_codex_mcp_registration(run_cli, cwd)?
        .ok_or_else(|| "codex mcp get --json reported that tirith-gateway is missing".to_string())
}

fn restore_codex_mcp_registration<F>(
    run_cli: &mut F,
    writable_cwd: &Path,
    previous: &RestorableCodexMcpRegistration,
) -> Result<(), String>
where
    F: FnMut(&Path, &str, &[&str]) -> Result<std::process::Output, String>,
{
    if let Some(value) = query_codex_mcp_registration(run_cli, writable_cwd)? {
        if RestorableCodexMcpRegistration::from_effective(&value)
            .is_ok_and(|current| &current == previous)
        {
            return Ok(());
        }
        remove_codex_mcp_registration(run_cli, writable_cwd, true)?;
    }
    run_codex_mcp_add(run_cli, writable_cwd, previous)?;
    let restored_value = read_codex_mcp_registration(run_cli, writable_cwd)?;
    let restored = RestorableCodexMcpRegistration::from_effective(&restored_value)
        .map_err(|error| format!("restored registration is not safely verifiable: {error}"))?;
    if &restored != previous {
        return Err("restored registration differs from the pre-mutation snapshot".into());
    }
    Ok(())
}

fn remove_new_codex_registration_if_proven<F>(
    run_cli: &mut F,
    writable_cwd: &Path,
    intended: &RestorableCodexMcpRegistration,
) -> Result<(), String>
where
    F: FnMut(&Path, &str, &[&str]) -> Result<std::process::Output, String>,
{
    let Some(value) = query_codex_mcp_registration(run_cli, writable_cwd)? else {
        return Ok(());
    };
    let effective = RestorableCodexMcpRegistration::from_effective(&value)
        .map_err(|error| format!("refusing unsnapshotted removal: {error}"))?;
    if &effective != intended {
        return Err(
            "refusing unsnapshotted removal because the effective registration is not exactly the one this setup attempted to create"
                .into(),
        );
    }
    remove_codex_mcp_registration(run_cli, writable_cwd, true)?;
    match query_codex_mcp_registration(run_cli, writable_cwd)? {
        None => Ok(()),
        Some(_) => Err("new registration still exists after rollback removal".into()),
    }
}

/// Select a canonical filesystem root as a project-neutral Codex working
/// directory. Codex still loads its user configuration from HOME/CODEX_HOME,
/// but cannot inherit a `.codex/config.toml` from the caller's repository
/// hierarchy while setup snapshots or mutates the writable user layer.
fn codex_isolated_cwd() -> Result<PathBuf, String> {
    let current = std::env::current_dir().map_err(|error| format!("current_dir: {error}"))?;
    let root = current
        .ancestors()
        .last()
        .ok_or_else(|| "current directory has no filesystem root".to_string())?;
    let root = root
        .canonicalize()
        .map_err(|error| format!("canonicalize Codex isolation root: {error}"))?;
    let metadata = std::fs::symlink_metadata(&root)
        .map_err(|error| format!("inspect Codex isolation root: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("Codex isolation root is not a canonical directory".into());
    }
    Ok(root)
}

fn verify_codex_effective_snapshot<F>(
    run_cli: &mut F,
    effective_cwd: &Path,
    expected: &Option<Value>,
) -> Result<(), String>
where
    F: FnMut(&Path, &str, &[&str]) -> Result<std::process::Output, String>,
{
    let actual = query_codex_mcp_registration(run_cli, effective_cwd)?;
    if &actual == expected {
        Ok(())
    } else {
        Err("effective registration differs from the pre-mutation snapshot".into())
    }
}

fn codex_failure_with_rollback<F>(
    run_cli: &mut F,
    writable_cwd: &Path,
    effective_cwd: &Path,
    effective_before: &Option<Value>,
    previous: Option<&RestorableCodexMcpRegistration>,
    intended: &RestorableCodexMcpRegistration,
    failure: String,
) -> String
where
    F: FnMut(&Path, &str, &[&str]) -> Result<std::process::Output, String>,
{
    let writable_rollback = if let Some(previous) = previous {
        restore_codex_mcp_registration(run_cli, writable_cwd, previous).map(|()| {
            "the previous registration was restored and verified at the writable layer".to_string()
        })
    } else {
        remove_new_codex_registration_if_proven(run_cli, writable_cwd, intended).map(|()| {
            "the attempted new writable-layer registration was absent or safely removed".to_string()
        })
    };
    let effective_rollback =
        verify_codex_effective_snapshot(run_cli, effective_cwd, effective_before);
    match (writable_rollback, effective_rollback) {
        (Ok(writable_note), Ok(())) => format!(
            "{failure}; {writable_note}; the caller-visible effective registration was restored and verified"
        ),
        (writable, effective) => {
            let writable = writable
                .err()
                .map(|error| format!("writable-layer rollback: {error}"))
                .unwrap_or_else(|| "writable-layer rollback verified".to_string());
            let effective = effective
                .err()
                .map(|error| format!("effective-state rollback: {error}"))
                .unwrap_or_else(|| "effective-state rollback verified".to_string());
            format!(
                "{failure}; automatic rollback could not prove both required states ({writable}; {effective}). Restore tirith-gateway manually before retrying"
            )
        }
    }
}

fn codex_failure_after_optional_mutation<F>(
    run_cli: &mut F,
    writable_cwd: &Path,
    effective_cwd: &Path,
    effective_before: &Option<Value>,
    mutation_previous: Option<&Option<RestorableCodexMcpRegistration>>,
    intended: &RestorableCodexMcpRegistration,
    failure: String,
) -> String
where
    F: FnMut(&Path, &str, &[&str]) -> Result<std::process::Output, String>,
{
    match mutation_previous {
        Some(previous) => codex_failure_with_rollback(
            run_cli,
            writable_cwd,
            effective_cwd,
            effective_before,
            previous.as_ref(),
            intended,
            failure,
        ),
        None => failure,
    }
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
        Scope::Project => std::env::current_dir().map_err(|e| format!("current_dir: {e}"))?,
        Scope::User => home.clone(),
    };
    fs_helpers::validate_target_dir(&target, Some(&scope_root))?;

    let hooks_dir = target.join("hooks");

    // The Python hook is used verbatim — no __TIRITH_BIN__ placeholder.
    let hook_path = hooks_dir.join("tirith-check.py");
    let hook_content = crate::assets::TIRITH_CHECK_PY;
    fs_helpers::write_hook_script(
        &hook_path,
        &scope_root,
        hook_content,
        opts.force,
        opts.dry_run,
    )?;

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
    merge::merge_claude_settings(
        &settings_path,
        &scope_root,
        &hook_command,
        opts.force,
        opts.dry_run,
    )?;

    if opts.with_mcp {
        match opts.scope {
            Scope::Project => {
                let cwd = std::env::current_dir().map_err(|e| format!("current_dir: {e}"))?;
                let mcp_path = cwd.join(".mcp.json");
                merge::merge_mcp_json(
                    &mcp_path,
                    &cwd,
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
                    &scope_root,
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
    setup_codex_with_runner(opts, fs_helpers::run_codex_cli_in_dir)
}

fn setup_codex_with_runner<F>(opts: &SetupOpts, mut run_cli: F) -> Result<(), String>
where
    F: FnMut(&Path, &str, &[&str]) -> Result<std::process::Output, String>,
{
    setup_codex_with_runner_and_publisher(opts, &mut run_cli, publish_codex_gateway_config)
}

fn setup_codex_with_runner_and_publisher<F, P>(
    opts: &SetupOpts,
    mut run_cli: F,
    publish_gateway: P,
) -> Result<(), String>
where
    F: FnMut(&Path, &str, &[&str]) -> Result<std::process::Output, String>,
    P: FnOnce(bool) -> Result<PathBuf, String>,
{
    let gateway_path = publish_gateway(opts.dry_run)?;
    if opts.update_configs {
        eprintln!();
        eprintln!("tirith: Codex gateway generation published");
        return Ok(());
    }

    // Publish and byte-verify an immutable generation before any registration
    // can make it live. Later failures may leave an unused content-addressed
    // file, but no active registration can point to stale or missing bytes.
    let gw_path_str = path_to_utf8(&gateway_path, "Codex gateway")?;
    let tirith_bin = &opts.tirith_bin;
    let intended = RestorableCodexMcpRegistration {
        command: tirith_bin.clone(),
        args: vec![
            "gateway".to_string(),
            "run".to_string(),
            "--upstream-bin".to_string(),
            tirith_bin.clone(),
            "--upstream-arg".to_string(),
            "mcp-server".to_string(),
            "--config".to_string(),
            gw_path_str,
        ],
    };
    let expected_args: Vec<&str> = intended.args.iter().map(String::as_str).collect();
    let add_args = intended.add_args();

    let effective_cwd = std::env::current_dir().map_err(|error| format!("current_dir: {error}"))?;
    let writable_cwd = codex_isolated_cwd()?;
    let mut effective_before: Option<Value> = None;
    let mut mutation_previous: Option<Option<RestorableCodexMcpRegistration>> = None;
    if opts.dry_run {
        eprintln!("[dry-run] would run: codex {}", add_args.join(" "));
        eprintln!("  (cannot check existing registrations in dry-run mode)");
    } else {
        // Snapshot the caller-visible effective state and the writable user
        // layer independently. The isolated root cwd prevents a project Codex
        // config from masking the layer that `mcp remove/add` actually mutates.
        effective_before = query_codex_mcp_registration(&mut run_cli, &effective_cwd).map_err(
            |error| {
                format!(
                    "cannot query the caller-visible tirith-gateway state before mutation; no registration changes were made: {error}"
                )
            },
        )?;
        let writable_value = query_codex_mcp_registration(&mut run_cli, &writable_cwd).map_err(|error| {
            format!(
                "cannot query tirith-gateway from the isolated user configuration scope for a safe pre-mutation snapshot; no registration changes were made: {error}"
            )
        })?;
        if effective_before != writable_value {
            return Err(
                "the caller-visible tirith-gateway registration differs from the isolated writable user layer, indicating a higher-precedence project registration; no registration changes were made. Remove or reconcile the project entry before retrying"
                    .into(),
            );
        }
        let exists = writable_value.is_some();

        if exists && !opts.force {
            let config_matches = writable_value.as_ref().is_some_and(|value| {
                codex_mcp_config_matches(value, tirith_bin, expected_args.as_slice())
            });
            if config_matches {
                eprintln!("tirith: tirith-gateway already registered with codex, up to date");
            } else {
                return Err(
                    "tirith-gateway registered with codex but config differs — use --force to update"
                        .into(),
                );
            }
        } else {
            let previous = writable_value
                .as_ref()
                .map(RestorableCodexMcpRegistration::from_effective)
                .transpose()
                .map_err(|error| {
                    format!(
                        "cannot safely replace the existing tirith-gateway registration because its complete effective state cannot be restored; no registration changes were made: {error}"
                    )
                })?;

            if exists {
                if let Err(error) =
                    remove_codex_mcp_registration(&mut run_cli, &writable_cwd, false)
                {
                    return Err(codex_failure_with_rollback(
                        &mut run_cli,
                        &writable_cwd,
                        &effective_cwd,
                        &effective_before,
                        previous.as_ref(),
                        &intended,
                        error,
                    ));
                }
            }
            if let Err(error) = run_codex_mcp_add(&mut run_cli, &writable_cwd, &intended) {
                return Err(codex_failure_with_rollback(
                    &mut run_cli,
                    &writable_cwd,
                    &effective_cwd,
                    &effective_before,
                    previous.as_ref(),
                    &intended,
                    error,
                ));
            }

            // Prove the exact writable-layer result first, then independently
            // prove the effective result in the caller's original repository.
            for (scope, cwd) in [
                ("isolated writable layer", writable_cwd.as_path()),
                ("caller-visible effective state", effective_cwd.as_path()),
            ] {
                let verification =
                    read_codex_mcp_registration(&mut run_cli, cwd).and_then(|value| {
                        let effective = RestorableCodexMcpRegistration::from_effective(&value)
                            .map_err(|error| format!("{scope} registration is unsafe: {error}"))?;
                        if effective == intended {
                            Ok(())
                        } else {
                            Err(format!(
                            "{scope} registration differs from the intended command and arguments"
                        ))
                        }
                    });
                if let Err(error) = verification {
                    return Err(codex_failure_with_rollback(
                        &mut run_cli,
                        &writable_cwd,
                        &effective_cwd,
                        &effective_before,
                        previous.as_ref(),
                        &intended,
                        format!(
                            "codex did not report the complete expected tirith-gateway configuration after registration: {error}"
                        ),
                    ));
                }
            }
            mutation_previous = Some(previous);
            eprintln!("tirith: registered tirith-gateway with codex");
        }
    }

    #[cfg(unix)]
    if let Err(error) = offer_zshenv_guard_for_opts(opts) {
        return Err(codex_failure_after_optional_mutation(
            &mut run_cli,
            &writable_cwd,
            &effective_cwd,
            &effective_before,
            mutation_previous.as_ref(),
            &intended,
            format!("zshenv guard setup failed after Codex registration: {error}"),
        ));
    }

    if !opts.dry_run {
        if let Some(previous_gateway) = mutation_previous
            .as_ref()
            .and_then(Option::as_ref)
            .and_then(RestorableCodexMcpRegistration::managed_gateway_config_path)
        {
            if let Err(error) = retire_codex_gateway_config(&previous_gateway, &gateway_path) {
                // Registration already points at the byte-verified new
                // generation. Never roll it back to an artifact whose
                // retirement may have begun; retain/report the old artifact
                // when cleanup cannot be proven.
                eprintln!(
                    "tirith: WARNING: could not retire previous Codex gateway generation: {error}"
                );
            }
        }
    }

    if let Err(e) =
        super::shell_profile::install_shell_hook(&opts.tirith_bin, opts.force, opts.dry_run)
    {
        eprintln!("tirith: WARNING: {e}");
    }

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
        Scope::Project => std::env::current_dir().map_err(|e| format!("current_dir: {e}"))?,
        Scope::User => home.clone(),
    };
    fs_helpers::validate_target_dir(&target, Some(&scope_root))?;

    let hooks_dir = target.join("hooks");

    let hook_path = hooks_dir.join("tirith-hook.sh");
    let hook_content = crate::assets::CURSOR_HOOK_SH.replace("__TIRITH_BIN__", &opts.tirith_bin);
    fs_helpers::write_hook_script(
        &hook_path,
        &scope_root,
        &hook_content,
        opts.force,
        opts.dry_run,
    )?;

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
            path_to_utf8(&h, "Cursor hook")?
        }
    };
    merge::merge_hooks_json(
        &hooks_json_path,
        &scope_root,
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

    let gw_path_str = path_to_utf8(&gateway_path, "Cursor gateway")?;
    let mcp_json_path = target.join("mcp.json");
    merge::merge_mcp_json(
        &mcp_json_path,
        &scope_root,
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

    let hook_path = hooks_dir.join("tirith-hook.sh");
    let hook_content = crate::assets::VSCODE_HOOK_SH.replace("__TIRITH_BIN__", &opts.tirith_bin);
    fs_helpers::write_hook_script(&hook_path, &cwd, &hook_content, opts.force, opts.dry_run)?;

    let gateway_path = copy_gateway_config(opts.force, opts.dry_run)?;

    if opts.update_configs {
        eprintln!();
        eprintln!("tirith: VS Code hook scripts and gateway config refreshed");
        return Ok(());
    }

    let settings_path = target.join("settings.json");
    // VS Code is project-only, so the hook command is a relative path.
    let hook_cmd = "hooks/tirith-hook.sh".to_string();
    merge::merge_vscode_settings(&settings_path, &cwd, &hook_cmd, opts.force, opts.dry_run)?;

    // VS Code uses "servers" as the top-level key (not "mcpServers") and
    // requires "type": "stdio" — see merge_mcp_json_with_key callsite.
    let gw_path_str = path_to_utf8(&gateway_path, "VS Code gateway")?;
    let mcp_json_path = cwd.join(".vscode").join("mcp.json");
    merge::merge_mcp_json_with_key(
        &mcp_json_path,
        &cwd,
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

    let (target, validation_root, write_root) = match opts.scope {
        Scope::Project => {
            let cwd = std::env::current_dir().map_err(|e| format!("current_dir: {e}"))?;
            (cwd.join(".gemini"), Some(cwd.clone()), cwd)
        }
        Scope::User => {
            if let Some(cli_home) = std::env::var_os("GEMINI_CLI_HOME") {
                let base = std::path::PathBuf::from(cli_home);
                (base.join(".gemini"), None, base)
            } else {
                (home.join(".gemini"), Some(home.clone()), home.clone())
            }
        }
    };

    fs_helpers::validate_target_dir(&target, validation_root.as_deref())?;

    let hooks_dir = target.join("hooks");

    let hook_path = hooks_dir.join("tirith-security-guard-gemini.py");
    let hook_content = crate::assets::GEMINI_HOOK_PY;
    fs_helpers::write_hook_script(
        &hook_path,
        &write_root,
        hook_content,
        opts.force,
        opts.dry_run,
    )?;

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
            let abs = path_to_utf8(&abs, "Gemini hook")?;
            format!(
                "python3 {}",
                super::shell_profile::shell_quote(&abs, "bash")
            )
        }
    };
    merge::merge_gemini_settings(
        &settings_path,
        &write_root,
        &hook_command,
        opts.force,
        opts.dry_run,
    )?;

    if opts.with_mcp {
        merge::merge_mcp_json_with_key(
            &settings_path,
            &write_root,
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

    let (target, validation_root, write_root) = match opts.scope {
        Scope::Project => {
            let cwd = std::env::current_dir().map_err(|e| format!("current_dir: {e}"))?;
            (cwd.join(".pi"), Some(cwd.clone()), cwd)
        }
        Scope::User => {
            if let Some(agent_dir) = std::env::var_os("PI_CODING_AGENT_DIR") {
                let target = std::path::PathBuf::from(agent_dir);
                (target.clone(), None, target)
            } else {
                (
                    home.join(".pi").join("agent"),
                    Some(home.clone()),
                    home.clone(),
                )
            }
        }
    };

    fs_helpers::validate_target_dir(&target, validation_root.as_deref())?;

    let extensions_dir = target.join("extensions");

    let guard_path = extensions_dir.join("tirith-guard.ts");
    let guard_content = crate::assets::TIRITH_GUARD_TS;
    fs_helpers::write_hook_script(
        &guard_path,
        &write_root,
        guard_content,
        opts.force,
        opts.dry_run,
    )?;

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

    let (target, validation_root, write_root) = match opts.scope {
        Scope::Project => {
            let cwd = std::env::current_dir().map_err(|e| format!("current_dir: {e}"))?;
            (cwd.join(".openclaw"), Some(cwd.clone()), cwd)
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
                (p.clone(), None, p)
            } else {
                (home.join(".openclaw"), Some(home.clone()), home.clone())
            }
        }
    };

    fs_helpers::validate_target_dir(&target, validation_root.as_deref())?;

    let extensions_dir = target.join("extensions").join("tirith-security");

    let guard_path = extensions_dir.join("index.ts");
    let guard_content = crate::assets::OPENCLAW_GUARD_TS;
    fs_helpers::write_hook_script(
        &guard_path,
        &write_root,
        guard_content,
        opts.force,
        opts.dry_run,
    )?;

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

    let hook_path = hooks_dir.join("tirith-hook.sh");
    let hook_content = crate::assets::WINDSURF_HOOK_SH.replace("__TIRITH_BIN__", &opts.tirith_bin);
    fs_helpers::write_hook_script(&hook_path, &home, &hook_content, opts.force, opts.dry_run)?;

    let gateway_path = copy_gateway_config(opts.force, opts.dry_run)?;

    if opts.update_configs {
        eprintln!();
        eprintln!("tirith: Windsurf hook scripts and gateway config refreshed");
        return Ok(());
    }

    // Windsurf is user-global, so hooks.json references an absolute path.
    let hooks_json_path = target.join("hooks.json");
    let hook_cmd = path_to_utf8(&hooks_dir.join("tirith-hook.sh"), "Windsurf hook")?;
    merge::merge_hooks_json(
        &hooks_json_path,
        &home,
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

    let gw_path_str = path_to_utf8(&gateway_path, "Windsurf gateway")?;
    let mcp_json_path = target.join("mcp_config.json");
    merge::merge_mcp_json(
        &mcp_json_path,
        &home,
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

    let hook_path = hooks_dir.join("copilot-cli-hook.py");
    fs_helpers::write_hook_script(
        &hook_path,
        &repo_root,
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
    write_owned_json(
        &config_path,
        &repo_root,
        &config_str,
        opts.force,
        opts.dry_run,
    )?;

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
    let write_root = scope_root.as_deref().expect("all Kiro scopes have a root");

    let hook_path = hooks_dir.join("kiro-hook.py");
    fs_helpers::write_hook_script(
        &hook_path,
        write_root,
        crate::assets::KIRO_HOOK_PY,
        opts.force,
        opts.dry_run,
    )?;

    // Absolute hook paths in both scopes (Kiro doesn't document agent-relative
    // resolution). tools=["*"] keeps default tool access; includeMcpJson keeps
    // the user's MCP servers.
    let agent_path = agents_dir.join("tirith-security.json");
    let hook_path_text = path_to_utf8(&hook_path, "Kiro hook")?;
    let quoted = super::shell_profile::shell_quote(&hook_path_text, "bash");
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
    write_owned_json(
        &agent_path,
        write_root,
        &agent_str,
        opts.force,
        opts.dry_run,
    )?;

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
    scope_root: &std::path::Path,
    content: &str,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    let outcome = fs_helpers::transactional_update(path, scope_root, dry_run, |snapshot| {
        let mut backup = false;
        if let Some(existing) = snapshot.text(path)? {
            if existing == content {
                eprintln!("tirith: {} already configured, up to date", path.display());
                return Ok(fs_helpers::FileUpdate::unchanged());
            }
            if !force {
                if dry_run {
                    eprintln!(
                        "[dry-run] would error: {} exists with different content — use --force to update",
                        path.display()
                    );
                    return Ok(fs_helpers::FileUpdate::unchanged());
                }
                return Err(format!(
                    "{} exists with different content — use --force to update",
                    path.display()
                ));
            }
            backup = true;
        }
        if dry_run {
            eprintln!(
                "[dry-run] would write {} ({} bytes)",
                path.display(),
                content.len()
            );
        }
        Ok(fs_helpers::FileUpdate::write_text(content.to_string(), 0o644).with_backup(backup))
    })?;
    if let Some(annotation) = outcome.completion_annotation() {
        eprintln!("tirith: wrote {}{annotation}", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_harness::{with_fake_env, CwdGuard, EnvGuard};

    #[cfg(unix)]
    #[test]
    fn owned_json_up_to_date_and_dry_run_refuse_symlinked_parent() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("agents")).unwrap();
        std::fs::write(outside.path().join("config.json"), "expected").unwrap();
        let path = root.path().join("agents/config.json");

        for dry_run in [false, true] {
            let result = write_owned_json(&path, root.path(), "expected", false, dry_run);
            assert!(
                result.is_err(),
                "dry_run={dry_run} bypassed parent validation"
            );
        }
        assert_eq!(
            std::fs::read_to_string(outside.path().join("config.json")).unwrap(),
            "expected"
        );
    }

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
        assert!(!codex_mcp_get_reports_missing(
            "codex config file not found"
        ));
        assert!(!codex_mcp_get_reports_missing(
            "MCP server another-name not found"
        ));
    }

    #[test]
    fn codex_mcp_config_matches_current_transport_shape() {
        let value = json!({
            "name": "tirith-gateway",
            "enabled": true,
            "disabled_reason": null,
            "startup_timeout_sec": null,
            "tool_timeout_sec": null,
            "auth_status": "unsupported",
            "transport": {
                "type": "stdio",
                "command": "tirith",
                "args": [
                    "gateway", "run",
                    "--upstream-bin", "tirith",
                    "--upstream-arg", "mcp-server",
                    "--config", "/Users/example/.config/tirith/gateway.yaml"
                ],
                "env": null,
                "env_vars": [],
                "cwd": null
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
    fn codex_mcp_config_rejects_incomplete_legacy_shape() {
        let value = json!({
            "command": "tirith",
            "args": ["gateway", "run"]
        });
        let expected_args = ["gateway", "run"];
        assert!(!codex_mcp_config_matches(&value, "tirith", &expected_args));
    }

    #[test]
    fn codex_mcp_config_rejects_drift() {
        let value = json!({
            "name": "tirith-gateway",
            "enabled": true,
            "transport": {
                "type": "stdio",
                "command": "tirith",
                "args": ["gateway", "run", "--config", "/old/path.yaml"]
            }
        });
        let expected_args = ["gateway", "run", "--config", "/new/path.yaml"];
        assert!(!codex_mcp_config_matches(&value, "tirith", &expected_args));
    }

    #[test]
    fn codex_mcp_config_rejects_disabled_or_poisoned_registration() {
        let expected_args = ["gateway", "run"];
        let baseline = json!({
            "name": "tirith-gateway",
            "enabled": true,
            "disabled_reason": null,
            "startup_timeout_sec": null,
            "tool_timeout_sec": null,
            "auth_status": "unsupported",
            "transport": {
                "type": "stdio",
                "command": "tirith",
                "args": expected_args,
                "env": null,
                "env_vars": [],
                "cwd": null
            }
        });
        assert!(codex_mcp_config_matches(
            &baseline,
            "tirith",
            &expected_args
        ));

        for (field, value) in [
            ("enabled", json!(false)),
            ("startup_timeout_sec", json!(0)),
            ("tool_timeout_sec", json!(0)),
            ("unexpected", json!(true)),
        ] {
            let mut poisoned = baseline.clone();
            poisoned[field] = value;
            assert!(
                !codex_mcp_config_matches(&poisoned, "tirith", &expected_args),
                "accepted poisoned outer field {field}"
            );
        }

        for (field, value) in [
            ("type", json!("streamable_http")),
            ("env", json!({"TIRITH_GATEWAY_DEPTH": "1"})),
            ("env_vars", json!(["TIRITH_GATEWAY_DEPTH"])),
            ("cwd", json!("/tmp/attacker")),
            ("unexpected", json!(true)),
        ] {
            let mut poisoned = baseline.clone();
            poisoned["transport"][field] = value;
            assert!(
                !codex_mcp_config_matches(&poisoned, "tirith", &expected_args),
                "accepted poisoned transport field {field}"
            );
        }
    }

    #[cfg(unix)]
    fn process_output(
        code: i32,
        stdout: impl Into<Vec<u8>>,
        stderr: impl Into<Vec<u8>>,
    ) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    #[cfg(unix)]
    fn codex_stdio_config(command: &str, args: &[&str]) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "name": "tirith-gateway",
            "enabled": true,
            "disabled_reason": null,
            "startup_timeout_sec": null,
            "tool_timeout_sec": null,
            "auth_status": "unsupported",
            "transport": {
                "type": "stdio",
                "command": command,
                "args": args,
                "env": null,
                "env_vars": [],
                "cwd": null
            }
        }))
        .unwrap()
    }

    #[cfg(unix)]
    fn expected_codex_gateway_path() -> PathBuf {
        super::super::run_impl::codex_gateway_config_location()
            .unwrap()
            .1
    }

    #[cfg(unix)]
    fn codex_gateway_path_for_bytes(parent: &Path, bytes: &[u8]) -> PathBuf {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(bytes);
        let digest = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        parent.join(format!("gateway-sha256-{digest}.yaml"))
    }

    #[cfg(unix)]
    #[test]
    fn setup_codex_rejects_non_utf8_gateway_path_before_cli_mutation() {
        use std::os::unix::ffi::OsStringExt;

        with_fake_env(false, |home, _cwd| {
            let config_name = std::ffi::OsString::from_vec(b"config-\xff".to_vec());
            let config_root = home.join(config_name);
            let gateway_path = config_root.join("tirith").join("gateway-test.yaml");
            let mut opts = opts_for(Scope::User);
            opts.tirith_bin = "/bin/tirith".to_string();

            let mut called = false;
            let error = setup_codex_with_runner_and_publisher(
                &opts,
                |_cwd, _command, _args| {
                    called = true;
                    panic!("Codex CLI must not run for an unrepresentable gateway path")
                },
                |dry_run| {
                    super::super::run_impl::publish_codex_gateway_config_at(
                        &config_root,
                        &gateway_path,
                        dry_run,
                    )
                },
            )
            .unwrap_err();

            assert!(error.contains("not valid UTF-8"), "{error}");
            assert!(error.contains("cannot be persisted"), "{error}");
            assert!(!called, "Codex mutation/query ran before path rejection");
            assert!(
                !config_root.exists(),
                "gateway publication touched the filesystem before path rejection"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn setup_codex_registers_when_current_cli_reports_missing_server() {
        with_fake_env(false, |home, _cwd| {
            // Pin XDG_CONFIG_HOME so the gateway path (<XDG>/tirith/gateway.yaml)
            // the assertion below checks is deterministic.
            let xdg = home.join(".config");
            let _xdg = EnvGuard::set("XDG_CONFIG_HOME", &xdg);

            let _shell = EnvGuard::set("SHELL", std::path::Path::new("/bin/zsh"));

            let mut opts = opts_for(Scope::User);
            opts.tirith_bin = "/bin/tirith".to_string();

            let expected_gateway = expected_codex_gateway_path();
            let verified_config = serde_json::to_vec(&json!({
                "name": "tirith-gateway",
                "enabled": true,
                "disabled_reason": null,
                "startup_timeout_sec": null,
                "tool_timeout_sec": null,
                "auth_status": "unsupported",
                "transport": {
                    "type": "stdio",
                    "command": "/bin/tirith",
                    "args": [
                        "gateway", "run", "--upstream-bin", "/bin/tirith",
                        "--upstream-arg", "mcp-server", "--config",
                        expected_gateway.display().to_string()
                    ],
                    "env": null,
                    "env_vars": [],
                    "cwd": null
                }
            }))
            .unwrap();

            let mut calls = Vec::<Vec<String>>::new();
            let mut json_gets = 0usize;
            setup_codex_with_runner(&opts, |_cwd, command, args| {
                assert_eq!(command, "codex");
                calls.push(args.iter().map(|arg| (*arg).to_string()).collect());
                if args.starts_with(&["mcp", "add", "tirith-gateway"]) {
                    assert_eq!(
                        std::fs::read_to_string(&expected_gateway).unwrap(),
                        crate::assets::GATEWAY_YAML,
                        "registration must not become live before the immutable gateway bytes publish"
                    );
                    return Ok(process_output(0, Vec::new(), Vec::new()));
                }
                if args == ["mcp", "get", "--json", "tirith-gateway"] {
                    json_gets += 1;
                    return if json_gets <= 2 {
                        Ok(process_output(
                            1,
                            Vec::new(),
                            b"Error: No MCP server named 'tirith-gateway' found.\n".to_vec(),
                        ))
                    } else {
                        Ok(process_output(0, verified_config.clone(), Vec::new()))
                    };
                }
                panic!("unexpected codex args: {args:?}");
            })
            .unwrap();

            assert!(
                calls
                    .iter()
                    .filter(|args| {
                        args.as_slice() == ["mcp", "get", "--json", "tirith-gateway"]
                    })
                    .count()
                    == 4,
                "should snapshot both scopes and verify both scopes; calls: {calls:?}"
            );
            // Full mcp add invocation (catches argument drift, not just
            // "add was called"). Gateway path is XDG-deterministic above.
            let expected_add = vec![
                "mcp".to_string(),
                "add".to_string(),
                "tirith-gateway".to_string(),
                "--".to_string(),
                "/bin/tirith".to_string(),
                "gateway".to_string(),
                "run".to_string(),
                "--upstream-bin".to_string(),
                "/bin/tirith".to_string(),
                "--upstream-arg".to_string(),
                "mcp-server".to_string(),
                "--config".to_string(),
                expected_gateway.display().to_string(),
            ];
            assert!(
                calls.contains(&expected_add),
                "setup must register with full expected args; \
                 expected: {expected_add:?}\ncalls: {calls:?}"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn setup_codex_publishes_new_generation_before_registration_and_retires_old_after_success() {
        with_fake_env(false, |home, _project_cwd| {
            let xdg = home.join(".config");
            let _xdg = EnvGuard::set("XDG_CONFIG_HOME", &xdg);
            let mut opts = opts_for(Scope::User);
            opts.force = true;
            opts.tirith_bin = "/bin/tirith".to_string();

            let gateway_parent = xdg.join("tirith");
            std::fs::create_dir_all(&gateway_parent).unwrap();
            let old_bytes = b"version: 1\nrules: []\n";
            let old_gateway = codex_gateway_path_for_bytes(&gateway_parent, old_bytes);
            std::fs::write(&old_gateway, old_bytes).unwrap();
            let current_gateway = expected_codex_gateway_path();
            assert_ne!(old_gateway, current_gateway);

            let old_gateway_arg = old_gateway.display().to_string();
            let previous = codex_stdio_config(
                "/opt/old-tirith",
                &[
                    "gateway",
                    "run",
                    "--upstream-bin",
                    "/opt/old-tirith",
                    "--upstream-arg",
                    "mcp-server",
                    "--config",
                    old_gateway_arg.as_str(),
                ],
            );
            let current_gateway_arg = current_gateway.display().to_string();
            let intended = codex_stdio_config(
                "/bin/tirith",
                &[
                    "gateway",
                    "run",
                    "--upstream-bin",
                    "/bin/tirith",
                    "--upstream-arg",
                    "mcp-server",
                    "--config",
                    current_gateway_arg.as_str(),
                ],
            );
            let mut json_gets = 0usize;
            setup_codex_with_runner(&opts, |_cwd, command, args| {
                assert_eq!(command, "codex");
                match args {
                    ["mcp", "get", "--json", "tirith-gateway"] => {
                        json_gets += 1;
                        let value = if json_gets <= 2 {
                            previous.clone()
                        } else {
                            intended.clone()
                        };
                        Ok(process_output(0, value, Vec::new()))
                    }
                    ["mcp", "remove", "tirith-gateway"] => {
                        Ok(process_output(0, Vec::new(), Vec::new()))
                    }
                    ["mcp", "add", "tirith-gateway", ..] => {
                        assert!(
                            old_gateway.exists(),
                            "old generation retired before success"
                        );
                        assert_eq!(
                            std::fs::read_to_string(&current_gateway).unwrap(),
                            crate::assets::GATEWAY_YAML,
                            "new generation must be complete before registration"
                        );
                        Ok(process_output(0, Vec::new(), Vec::new()))
                    }
                    _ => panic!("unexpected codex args: {args:?}"),
                }
            })
            .unwrap();

            assert_eq!(json_gets, 4);
            assert!(!old_gateway.exists(), "old generation was not retired");
            assert_eq!(
                std::fs::read_to_string(current_gateway).unwrap(),
                crate::assets::GATEWAY_YAML
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn setup_codex_publication_failure_precedes_every_registration_call() {
        with_fake_env(false, |home, _cwd| {
            let _xdg = EnvGuard::set("XDG_CONFIG_HOME", &home.join(".config"));
            let gateway = expected_codex_gateway_path();
            std::fs::create_dir_all(gateway.parent().unwrap()).unwrap();
            std::fs::write(&gateway, "tampered bytes at digest-derived path").unwrap();
            let mut opts = opts_for(Scope::User);
            opts.force = true;
            opts.tirith_bin = "/bin/tirith".to_string();

            let error = setup_codex_with_runner(&opts, |_cwd, _command, args| {
                panic!("registration CLI called after failed gateway publication: {args:?}")
            })
            .unwrap_err();

            assert!(
                error.contains("content-addressed gateway generation"),
                "{error}"
            );
            assert_eq!(
                std::fs::read_to_string(gateway).unwrap(),
                "tampered bytes at digest-derived path"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn setup_codex_refuses_project_masking_before_user_layer_mutation() {
        with_fake_env(true, |home, project_cwd| {
            let project_cwd = project_cwd.expect("test requested an isolated project cwd");
            let _xdg = EnvGuard::set("XDG_CONFIG_HOME", &home.join(".config"));
            let mut opts = opts_for(Scope::User);
            opts.force = true;
            opts.tirith_bin = "/bin/tirith".to_string();

            let project = codex_stdio_config("/project/poisoned-tirith", &["mcp-server"]);
            let user = codex_stdio_config("/opt/user-tirith", &["mcp-server"]);
            let isolated = codex_isolated_cwd().unwrap();
            let mut calls = Vec::<(PathBuf, Vec<String>)>::new();
            let error = setup_codex_with_runner(&opts, |cwd, command, args| {
                assert_eq!(command, "codex");
                calls.push((
                    cwd.to_path_buf(),
                    args.iter().map(|arg| (*arg).to_string()).collect(),
                ));
                match args {
                    ["mcp", "get", "--json", "tirith-gateway"] if cwd == project_cwd => {
                        Ok(process_output(0, project.clone(), Vec::new()))
                    }
                    ["mcp", "get", "--json", "tirith-gateway"] if cwd == isolated.as_path() => {
                        Ok(process_output(0, user.clone(), Vec::new()))
                    }
                    _ => panic!(
                        "mutation attempted while project config masked user layer: {args:?}"
                    ),
                }
            })
            .unwrap_err();

            assert!(
                error.contains("higher-precedence project registration"),
                "{error}"
            );
            assert_eq!(
                calls.len(),
                2,
                "only the two read-only snapshots are allowed"
            );
            assert!(calls
                .iter()
                .all(|(_, args)| args == &["mcp", "get", "--json", "tirith-gateway"]));
        });
    }

    #[cfg(unix)]
    #[test]
    fn setup_codex_rolls_back_user_layer_when_identical_project_mask_survives_update() {
        with_fake_env(true, |home, project_cwd| {
            let project_cwd = project_cwd.expect("test requested an isolated project cwd");
            let _xdg = EnvGuard::set("XDG_CONFIG_HOME", &home.join(".config"));
            let mut opts = opts_for(Scope::User);
            opts.force = true;
            opts.tirith_bin = "/bin/tirith".to_string();

            let previous = codex_stdio_config("/opt/old-tirith", &["mcp-server"]);
            let gateway = expected_codex_gateway_path().display().to_string();
            let intended = codex_stdio_config(
                "/bin/tirith",
                &[
                    "gateway",
                    "run",
                    "--upstream-bin",
                    "/bin/tirith",
                    "--upstream-arg",
                    "mcp-server",
                    "--config",
                    gateway.as_str(),
                ],
            );
            let isolated = codex_isolated_cwd().unwrap();
            let mut writable_gets = 0usize;
            let mut effective_gets = 0usize;
            let mut removes = 0usize;
            let error = setup_codex_with_runner(&opts, |cwd, command, args| {
                assert_eq!(command, "codex");
                match args {
                    ["mcp", "get", "--json", "tirith-gateway"] if cwd == project_cwd => {
                        effective_gets += 1;
                        Ok(process_output(0, previous.clone(), Vec::new()))
                    }
                    ["mcp", "get", "--json", "tirith-gateway"] if cwd == isolated.as_path() => {
                        writable_gets += 1;
                        let value = match writable_gets {
                            1 | 4 => previous.clone(),
                            2 | 3 => intended.clone(),
                            _ => panic!("unexpected writable JSON read {writable_gets}"),
                        };
                        Ok(process_output(0, value, Vec::new()))
                    }
                    ["mcp", "remove", "tirith-gateway"] if cwd == isolated.as_path() => {
                        removes += 1;
                        Ok(process_output(0, Vec::new(), Vec::new()))
                    }
                    args if args.starts_with(&["mcp", "add", "tirith-gateway"])
                        && cwd == isolated.as_path() =>
                    {
                        Ok(process_output(0, Vec::new(), Vec::new()))
                    }
                    _ => panic!("unexpected codex call in masked rollback: {cwd:?} {args:?}"),
                }
            })
            .unwrap_err();

            assert!(error.contains("caller-visible effective state"), "{error}");
            assert!(
                error.contains("previous registration was restored"),
                "{error}"
            );
            assert!(
                error.contains("effective registration was restored"),
                "{error}"
            );
            assert_eq!(writable_gets, 4);
            assert_eq!(effective_gets, 3);
            assert_eq!(removes, 2);
        });
    }

    #[cfg(unix)]
    #[test]
    fn setup_codex_aborts_on_unrelated_not_found_without_mutation() {
        with_fake_env(false, |home, _cwd| {
            let xdg = home.join(".config");
            let gateway = xdg.join("tirith/gateway.yaml");
            std::fs::create_dir_all(gateway.parent().unwrap()).unwrap();
            std::fs::write(&gateway, "old gateway bytes").unwrap();
            let _xdg = EnvGuard::set("XDG_CONFIG_HOME", &xdg);
            let mut opts = opts_for(Scope::User);
            opts.force = true;
            opts.tirith_bin = "/bin/tirith".to_string();

            let mut calls = Vec::<Vec<String>>::new();
            let error = setup_codex_with_runner(&opts, |_cwd, command, args| {
                assert_eq!(command, "codex");
                calls.push(args.iter().map(|arg| (*arg).to_string()).collect());
                match args {
                    ["mcp", "get", "--json", "tirith-gateway"] => Ok(process_output(
                        1,
                        Vec::new(),
                        b"codex config file not found".to_vec(),
                    )),
                    _ => panic!("mutation attempted after unrelated query error: {args:?}"),
                }
            })
            .unwrap_err();

            assert!(error.contains("caller-visible"), "{error}");
            assert!(
                error.contains("no registration changes were made"),
                "{error}"
            );
            assert_eq!(calls.len(), 1);
            assert_eq!(
                std::fs::read_to_string(gateway).unwrap(),
                "old gateway bytes"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn setup_codex_does_not_remove_unsnapshotted_registration_without_exact_proof() {
        with_fake_env(false, |home, _cwd| {
            let _xdg = EnvGuard::set("XDG_CONFIG_HOME", &home.join(".config"));
            let _shell = EnvGuard::set("SHELL", std::path::Path::new("/bin/zsh"));
            let mut opts = opts_for(Scope::User);
            opts.tirith_bin = "/bin/tirith".to_string();

            let poisoned = serde_json::to_vec(&json!({
                "name": "tirith-gateway",
                "enabled": false,
                "transport": {
                    "type": "stdio",
                    "command": "/bin/tirith",
                    "args": []
                }
            }))
            .unwrap();
            let effective_cwd = std::env::current_dir().unwrap();
            let writable_cwd = codex_isolated_cwd().unwrap();
            assert_ne!(effective_cwd, writable_cwd);
            let mut effective_gets = 0usize;
            let mut writable_gets = 0usize;
            let mut calls = Vec::<Vec<String>>::new();
            let result = setup_codex_with_runner(&opts, |cwd, command, args| {
                assert_eq!(command, "codex");
                calls.push(args.iter().map(|arg| (*arg).to_string()).collect());
                match args {
                    ["mcp", "add", "tirith-gateway", ..] => {
                        assert_eq!(cwd, writable_cwd);
                        Ok(process_output(0, Vec::new(), Vec::new()))
                    }
                    ["mcp", "get", "--json", "tirith-gateway"] => {
                        if cwd == effective_cwd {
                            effective_gets += 1;
                            Ok(process_output(
                                1,
                                Vec::new(),
                                b"Error: No MCP server named 'tirith-gateway' found.".to_vec(),
                            ))
                        } else {
                            assert_eq!(cwd, writable_cwd);
                            writable_gets += 1;
                            if writable_gets == 1 {
                                Ok(process_output(
                                    1,
                                    Vec::new(),
                                    b"Error: No MCP server named 'tirith-gateway' found.".to_vec(),
                                ))
                            } else {
                                Ok(process_output(0, poisoned.clone(), Vec::new()))
                            }
                        }
                    }
                    _ => panic!("unexpected codex args: {args:?}"),
                }
            });

            let error = result.unwrap_err();
            assert!(
                error.contains("did not report the complete expected"),
                "{error}"
            );
            assert!(error.contains("refusing unsnapshotted removal"), "{error}");
            assert_eq!(effective_gets, 2);
            assert_eq!(writable_gets, 3);
            assert!(!calls
                .iter()
                .any(|args| args == &["mcp", "remove", "tirith-gateway"]));
        });
    }

    #[cfg(unix)]
    #[test]
    fn setup_codex_force_restores_existing_registration_after_add_runner_error() {
        with_fake_env(false, |home, _cwd| {
            let xdg = home.join(".config");
            let gateway = xdg.join("tirith/gateway.yaml");
            std::fs::create_dir_all(gateway.parent().unwrap()).unwrap();
            std::fs::write(&gateway, "old gateway bytes").unwrap();
            let _xdg = EnvGuard::set("XDG_CONFIG_HOME", &xdg);
            let _shell = EnvGuard::set("SHELL", std::path::Path::new("/bin/zsh"));
            let mut opts = opts_for(Scope::User);
            opts.force = true;
            opts.tirith_bin = "/bin/tirith".to_string();

            let previous = codex_stdio_config("/opt/old-tirith", &["mcp-server"]);
            let mut json_gets = 0usize;
            let mut calls = Vec::<Vec<String>>::new();
            let result = setup_codex_with_runner(&opts, |_cwd, command, args| {
                assert_eq!(command, "codex");
                calls.push(args.iter().map(|arg| (*arg).to_string()).collect());
                match args {
                    ["mcp", "get", "--json", "tirith-gateway"] => {
                        json_gets += 1;
                        match json_gets {
                            1 | 2 | 4 | 5 => Ok(process_output(0, previous.clone(), Vec::new())),
                            3 => Ok(process_output(
                                1,
                                Vec::new(),
                                b"No MCP server named 'tirith-gateway' found.".to_vec(),
                            )),
                            _ => panic!("unexpected JSON read {json_gets}"),
                        }
                    }
                    ["mcp", "remove", "tirith-gateway"] => {
                        Ok(process_output(0, Vec::new(), Vec::new()))
                    }
                    ["mcp", "add", "tirith-gateway", "--", "/bin/tirith", ..] => {
                        Err("simulated add spawn failure".into())
                    }
                    args if args
                        == [
                            "mcp",
                            "add",
                            "tirith-gateway",
                            "--",
                            "/opt/old-tirith",
                            "mcp-server",
                        ] =>
                    {
                        Ok(process_output(0, Vec::new(), Vec::new()))
                    }
                    _ => panic!("unexpected codex args: {args:?}"),
                }
            });

            let error = result.unwrap_err();
            assert!(error.contains("simulated add spawn failure"), "{error}");
            assert!(
                error.contains("previous registration was restored"),
                "{error}"
            );
            assert!(calls.iter().any(|args| {
                args == &[
                    "mcp",
                    "add",
                    "tirith-gateway",
                    "--",
                    "/opt/old-tirith",
                    "mcp-server",
                ]
            }));
            assert_eq!(
                std::fs::read_to_string(gateway).unwrap(),
                "old gateway bytes",
                "gateway bytes must not publish before registration succeeds"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn setup_codex_force_restores_existing_registration_after_verification_mismatch() {
        with_fake_env(false, |home, _cwd| {
            let xdg = home.join(".config");
            let gateway = xdg.join("tirith/gateway.yaml");
            std::fs::create_dir_all(gateway.parent().unwrap()).unwrap();
            std::fs::write(&gateway, "old gateway bytes").unwrap();
            let _xdg = EnvGuard::set("XDG_CONFIG_HOME", &xdg);
            let _shell = EnvGuard::set("SHELL", std::path::Path::new("/bin/zsh"));
            let mut opts = opts_for(Scope::User);
            opts.force = true;
            opts.tirith_bin = "/bin/tirith".to_string();

            let previous = codex_stdio_config("/opt/old-tirith", &["mcp-server"]);
            let poisoned = codex_stdio_config("/bin/tirith", &["gateway", "run"]);
            let mut json_gets = 0usize;
            let mut calls = Vec::<Vec<String>>::new();
            let result = setup_codex_with_runner(&opts, |_cwd, command, args| {
                assert_eq!(command, "codex");
                calls.push(args.iter().map(|arg| (*arg).to_string()).collect());
                match args {
                    ["mcp", "get", "--json", "tirith-gateway"] => {
                        json_gets += 1;
                        let config = match json_gets {
                            1 | 2 | 5 | 6 => previous.clone(),
                            3 | 4 => poisoned.clone(),
                            _ => panic!("unexpected JSON read {json_gets}"),
                        };
                        Ok(process_output(0, config, Vec::new()))
                    }
                    ["mcp", "remove", "tirith-gateway"] => {
                        Ok(process_output(0, Vec::new(), Vec::new()))
                    }
                    ["mcp", "add", "tirith-gateway", ..] => {
                        Ok(process_output(0, Vec::new(), Vec::new()))
                    }
                    _ => panic!("unexpected codex args: {args:?}"),
                }
            });

            let error = result.unwrap_err();
            assert!(
                error.contains("did not report the complete expected"),
                "{error}"
            );
            assert!(
                error.contains("previous registration was restored"),
                "{error}"
            );
            assert_eq!(
                json_gets, 6,
                "both snapshots, failed writable verification, rollback inspection, writable restore verification, effective restore verification"
            );
            assert_eq!(
                calls
                    .iter()
                    .filter(|args| args.as_slice() == ["mcp", "remove", "tirith-gateway"])
                    .count(),
                2,
                "replacement removal plus rollback cleanup"
            );
            assert_eq!(
                std::fs::read_to_string(gateway).unwrap(),
                "old gateway bytes",
                "gateway bytes must remain unchanged on verification rollback"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn setup_codex_restores_registration_and_gateway_after_zshenv_failure() {
        with_fake_env(false, |home, _cwd| {
            let xdg = home.join(".config");
            let gateway = xdg.join("tirith/gateway.yaml");
            std::fs::create_dir_all(gateway.parent().unwrap()).unwrap();
            std::fs::write(&gateway, "old gateway bytes").unwrap();
            std::fs::write(
                home.join(".zshenv"),
                "# BEGIN tirith-guard v1\ncorrupted without end\n",
            )
            .unwrap();
            let _xdg = EnvGuard::set("XDG_CONFIG_HOME", &xdg);
            let mut opts = opts_for(Scope::User);
            opts.force = true;
            opts.install_zshenv = true;
            opts.tirith_bin = "/bin/tirith".to_string();

            let previous = codex_stdio_config("/opt/old-tirith", &["mcp-server"]);
            let gateway_string = expected_codex_gateway_path().display().to_string();
            let intended = codex_stdio_config(
                "/bin/tirith",
                &[
                    "gateway",
                    "run",
                    "--upstream-bin",
                    "/bin/tirith",
                    "--upstream-arg",
                    "mcp-server",
                    "--config",
                    gateway_string.as_str(),
                ],
            );
            let mut json_gets = 0usize;
            let mut removes = 0usize;
            let result = setup_codex_with_runner(&opts, |_cwd, command, args| {
                assert_eq!(command, "codex");
                match args {
                    ["mcp", "get", "--json", "tirith-gateway"] => {
                        json_gets += 1;
                        let config = match json_gets {
                            1 | 2 | 6 | 7 => previous.clone(),
                            3..=5 => intended.clone(),
                            _ => panic!("unexpected JSON read {json_gets}"),
                        };
                        Ok(process_output(0, config, Vec::new()))
                    }
                    ["mcp", "remove", "tirith-gateway"] => {
                        removes += 1;
                        Ok(process_output(0, Vec::new(), Vec::new()))
                    }
                    ["mcp", "add", "tirith-gateway", ..] => {
                        Ok(process_output(0, Vec::new(), Vec::new()))
                    }
                    _ => panic!("unexpected codex args: {args:?}"),
                }
            });

            let error = result.unwrap_err();
            assert!(error.contains("zshenv guard setup failed"), "{error}");
            assert!(
                error.contains("previous registration was restored"),
                "{error}"
            );
            assert_eq!(json_gets, 7);
            assert_eq!(removes, 2);
            assert_eq!(
                std::fs::read_to_string(gateway).unwrap(),
                "old gateway bytes"
            );
            assert_eq!(
                std::fs::read_to_string(home.join(".zshenv")).unwrap(),
                "# BEGIN tirith-guard v1\ncorrupted without end\n"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn setup_codex_force_refuses_unrestorable_registration_before_remove() {
        with_fake_env(false, |home, _cwd| {
            let xdg = home.join(".config");
            let gateway = xdg.join("tirith/gateway.yaml");
            std::fs::create_dir_all(gateway.parent().unwrap()).unwrap();
            std::fs::write(&gateway, "old gateway bytes").unwrap();
            let _xdg = EnvGuard::set("XDG_CONFIG_HOME", &xdg);
            let _shell = EnvGuard::set("SHELL", std::path::Path::new("/bin/zsh"));
            let mut opts = opts_for(Scope::User);
            opts.force = true;
            opts.tirith_bin = "/bin/tirith".to_string();

            let mut previous: Value =
                serde_json::from_slice(&codex_stdio_config("/opt/old-tirith", &["mcp-server"]))
                    .unwrap();
            previous["transport"]["env"] = json!({"SECRET": "value"});
            let previous = serde_json::to_vec(&previous).unwrap();
            let mut calls = Vec::<Vec<String>>::new();
            let result = setup_codex_with_runner(&opts, |_cwd, command, args| {
                assert_eq!(command, "codex");
                calls.push(args.iter().map(|arg| (*arg).to_string()).collect());
                match args {
                    ["mcp", "get", "--json", "tirith-gateway"] => {
                        Ok(process_output(0, previous.clone(), Vec::new()))
                    }
                    _ => panic!("mutation attempted for unrestorable config: {args:?}"),
                }
            });

            let error = result.unwrap_err();
            assert!(error.contains("cannot be restored"), "{error}");
            assert!(!calls
                .iter()
                .any(|args| { matches!(args.get(1).map(String::as_str), Some("remove" | "add")) }));
            assert_eq!(
                std::fs::read_to_string(gateway).unwrap(),
                "old gateway bytes",
                "gateway bytes must remain unchanged when snapshot is unrestorable"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn setup_codex_force_restores_snapshot_after_remove_failure() {
        with_fake_env(false, |home, _cwd| {
            let _xdg = EnvGuard::set("XDG_CONFIG_HOME", &home.join(".config"));
            let _shell = EnvGuard::set("SHELL", std::path::Path::new("/bin/zsh"));
            let mut opts = opts_for(Scope::User);
            opts.force = true;
            opts.tirith_bin = "/bin/tirith".to_string();

            let previous = codex_stdio_config("/opt/old-tirith", &["mcp-server"]);
            let mut removes = 0usize;
            let result = setup_codex_with_runner(&opts, |_cwd, command, args| {
                assert_eq!(command, "codex");
                match args {
                    ["mcp", "get", "--json", "tirith-gateway"] => {
                        Ok(process_output(0, previous.clone(), Vec::new()))
                    }
                    ["mcp", "remove", "tirith-gateway"] => {
                        removes += 1;
                        Ok(process_output(
                            1,
                            Vec::new(),
                            b"simulated remove failure".to_vec(),
                        ))
                    }
                    _ => panic!("unexpected codex args: {args:?}"),
                }
            });

            let error = result.unwrap_err();
            assert!(error.contains("simulated remove failure"), "{error}");
            assert!(
                error.contains("previous registration was restored"),
                "{error}"
            );
            assert_eq!(
                removes, 1,
                "rollback must recognize the unchanged snapshot without a second removal"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn setup_codex_accepts_current_transport_json_as_up_to_date() {
        with_fake_env(false, |home, _cwd| {
            let xdg = home.join(".config");
            let _xdg = EnvGuard::set("XDG_CONFIG_HOME", &xdg);

            let _shell = EnvGuard::set("SHELL", std::path::Path::new("/bin/zsh"));

            let mut opts = opts_for(Scope::User);
            opts.tirith_bin = "/bin/tirith".to_string();

            let expected_gateway = expected_codex_gateway_path();
            let config = serde_json::to_vec(&json!({
                "name": "tirith-gateway",
                "enabled": true,
                "disabled_reason": null,
                "startup_timeout_sec": null,
                "tool_timeout_sec": null,
                "auth_status": "unsupported",
                "transport": {
                    "type": "stdio",
                    "command": "/bin/tirith",
                    "args": [
                        "gateway", "run", "--upstream-bin", "/bin/tirith",
                        "--upstream-arg", "mcp-server", "--config",
                        expected_gateway.display().to_string()
                    ],
                    "env": null,
                    "env_vars": [],
                    "cwd": null
                }
            }))
            .unwrap();
            let mut calls = Vec::<Vec<String>>::new();
            setup_codex_with_runner(&opts, |_cwd, command, args| {
                assert_eq!(command, "codex");
                calls.push(args.iter().map(|arg| (*arg).to_string()).collect());
                match args {
                    ["mcp", "get", "--json", "tirith-gateway"] => {
                        Ok(process_output(0, config.clone(), Vec::new()))
                    }
                    _ => panic!("unexpected codex args: {args:?}"),
                }
            })
            .unwrap();

            assert!(calls
                .iter()
                .any(|args| args == &["mcp", "get", "--json", "tirith-gateway"]));
            assert!(
                !calls
                    .iter()
                    .any(|args| args.starts_with(&["mcp".to_string(), "add".to_string()])),
                "up-to-date transport config must not be re-registered; calls: {calls:?}"
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
            let _cwd = CwdGuard::set(&subdir);

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
            let _cwd = CwdGuard::set(&subdir);

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
