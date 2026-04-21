//! `tirith setup <tool>` — automated tool integration.
//!
//! Configures tirith protection for AI coding tools (Claude Code, Codex,
//! Cursor, VS Code, Windsurf) by writing hook scripts, merging JSON configs,
//! and registering MCP servers.

// Conditional fs_helpers: Unix version uses PermissionsExt for chmod,
// Windows version uses no-op permission shims (NTFS ACLs are default-secure).
#[cfg_attr(unix, path = "fs_helpers.rs")]
#[cfg_attr(not(unix), path = "fs_helpers_windows.rs")]
mod fs_helpers;

mod merge;
mod shell_profile;
mod tools;

// zshenv is inherently Unix-specific (zsh configuration)
#[cfg(unix)]
mod zshenv;

pub use self::run_impl::run;

mod run_impl {
    use super::fs_helpers;
    use etcetera::BaseStrategy;
    use std::path::PathBuf;

    /// All tools recognized by `tirith setup`.
    const KNOWN_TOOLS: &[&str] = &[
        "claude-code",
        "codex",
        "copilot-cli",
        "cursor",
        "gemini-cli",
        "kiro",
        "openclaw",
        "pi-cli",
        "vscode",
        "windsurf",
    ];

    /// Build an error message for an unrecognized tool name, with a
    /// Levenshtein-based "did you mean" suggestion when close enough.
    fn unknown_tool_error(tool: &str) -> String {
        let mut msg = format!(
            "unknown tool '{tool}' — expected one of: {}",
            KNOWN_TOOLS.join(", ")
        );
        if let Some(suggestion) = crate::cli::suggest_closest(tool, KNOWN_TOOLS, 3) {
            msg.push_str(&format!("\n  did you mean: tirith setup {suggestion}?"));
        }
        msg
    }

    /// Scope of the setup operation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Scope {
        Project,
        User,
    }

    /// Options threaded through all setup helpers.
    pub struct SetupOpts {
        pub scope: Scope,
        pub with_mcp: bool,
        pub install_zshenv: bool,
        pub dry_run: bool,
        pub force: bool,
        /// `"tirith"` (portable) when on PATH, or absolute path as fallback.
        pub tirith_bin: String,
        /// When true, only refresh embedded hook scripts and gateway config.
        /// Skips MCP registration, shell profile installation, and zshenv setup.
        pub update_configs: bool,
    }

    /// Entry point for `tirith setup <tool>`.
    pub fn run(
        tool: &str,
        scope: Option<&str>,
        with_mcp: bool,
        install_zshenv: bool,
        dry_run: bool,
        force: bool,
        update_configs: bool,
    ) -> i32 {
        match run_inner(
            tool,
            scope,
            with_mcp,
            install_zshenv,
            dry_run,
            force,
            update_configs,
        ) {
            Ok(()) => {
                if tirith_core::threatdb::ThreatDb::cached().is_none() {
                    eprintln!();
                    eprintln!(
                        "Optional: Run 'tirith threat-db update' to enable malicious package detection."
                    );
                }
                0
            }
            Err(msg) => {
                eprintln!("tirith: {msg}");
                1
            }
        }
    }

    fn run_inner(
        tool: &str,
        scope: Option<&str>,
        with_mcp: bool,
        install_zshenv: bool,
        dry_run: bool,
        force: bool,
        update_configs: bool,
    ) -> Result<(), String> {
        // --with-mcp only supported for claude-code and gemini-cli;
        // other tools include MCP configuration automatically or don't support it.
        if with_mcp && tool != "claude-code" && tool != "gemini-cli" {
            return Err(
                "--with-mcp is only supported for claude-code and gemini-cli (other tools register MCP automatically or don't support it)"
                    .into(),
            );
        }

        let scope = resolve_scope(tool, scope)?;

        let tirith_bin = resolve_tirith_bin(dry_run)?;

        // Most hook scripts are Python; codex/pi-cli/openclaw use TypeScript or
        // the codex CLI instead.
        if tool != "codex" && tool != "pi-cli" && tool != "openclaw" {
            check_binary_on_path("python3", dry_run)?;
        }

        if tool == "codex" {
            check_binary_on_path("codex", dry_run)?;
        }

        if install_zshenv {
            check_binary_on_path("zsh", dry_run)?;
        }

        // --update-configs implies --force: refreshing implies overwriting stale files.
        let effective_force = force || update_configs;

        let opts = SetupOpts {
            scope,
            with_mcp,
            install_zshenv,
            dry_run,
            force: effective_force,
            tirith_bin,
            update_configs,
        };

        match tool {
            "claude-code" => setup_claude_code(&opts),
            "codex" => setup_codex(&opts),
            "copilot-cli" => setup_copilot_cli(&opts),
            "cursor" => setup_cursor(&opts),
            "gemini-cli" => setup_gemini_cli(&opts),
            "kiro" => setup_kiro(&opts),
            "openclaw" => setup_openclaw(&opts),
            "pi-cli" => setup_pi_cli(&opts),
            "vscode" => setup_vscode(&opts),
            "windsurf" => setup_windsurf(&opts),
            _ => Err(unknown_tool_error(tool)),
        }
    }

    /// Resolve scope for a given tool, applying defaults and validation.
    pub(super) fn resolve_scope(tool: &str, scope: Option<&str>) -> Result<Scope, String> {
        match tool {
            "claude-code" | "cursor" | "gemini-cli" | "kiro" | "openclaw" | "pi-cli" => {
                match scope {
                    Some("project") | None => Ok(Scope::Project),
                    Some("user") => Ok(Scope::User),
                    Some(other) => Err(format!(
                        "invalid scope '{other}' — expected 'project' or 'user'\n  try: tirith setup {tool} --scope project"
                    )),
                }
            }
            "vscode" => match scope {
                Some("project") | None => Ok(Scope::Project),
                Some("user") => Err(
                    "VS Code user settings use JSONC — run tirith setup vscode in your project directory instead, or configure manually".into(),
                ),
                Some(other) => Err(format!(
                    "invalid scope '{other}' — expected 'project'\n  try: tirith setup vscode --scope project"
                )),
            },
            "copilot-cli" => match scope {
                Some("project") | None => Ok(Scope::Project),
                Some("user") => Err(
                    "Copilot CLI loads hooks from the repo root — project-only. Omit --scope or use --scope project".into(),
                ),
                Some(other) => Err(format!(
                    "invalid scope '{other}' — expected 'project'\n  try: tirith setup copilot-cli --scope project"
                )),
            },
            "codex" => match scope {
                Some("project") => Err("Codex is always user-global — omit --scope or use --scope user".into()),
                Some("user") | None => Ok(Scope::User),
                Some(other) => Err(format!(
                    "invalid scope '{other}' — expected 'user'\n  try: tirith setup codex --scope user"
                )),
            },
            "windsurf" => match scope {
                Some("project") => Err("Windsurf is always user-global — omit --scope or use --scope user".into()),
                Some("user") | None => Ok(Scope::User),
                Some(other) => Err(format!(
                    "invalid scope '{other}' — expected 'user'\n  try: tirith setup windsurf --scope user"
                )),
            },
            _ => Err(unknown_tool_error(tool)),
        }
    }

    /// Resolve the tirith binary path for use in generated configs and hooks.
    ///
    /// 1. If `command -v tirith` succeeds, use the portable name `"tirith"`.
    /// 2. If not on PATH, check `current_exe()` — use absolute path + warning.
    /// 3. If neither: hard error (or placeholder in dry-run).
    fn resolve_tirith_bin(dry_run: bool) -> Result<String, String> {
        if is_on_path("tirith") {
            return Ok("tirith".into());
        }

        // Fallback: use current_exe() as an absolute path.
        if let Ok(exe) = std::env::current_exe() {
            if let Some(name) = exe.file_name() {
                if name == "tirith" {
                    let abs = exe.display().to_string();
                    eprintln!(
                        "tirith: WARNING: tirith is not on PATH — using absolute path {abs} in generated configs. \
                         Run `tirith setup <tool> --force` after adding tirith to PATH to switch to portable mode."
                    );
                    return Ok(abs);
                }
            }
        }

        if dry_run {
            eprintln!(
                "tirith: WARNING: tirith not found — previewing with portable name 'tirith' (actual setup would fail)"
            );
            Ok("tirith".into())
        } else {
            Err("tirith binary not found — ensure tirith is installed and on PATH".into())
        }
    }

    /// Check that a binary is available on PATH.
    /// In dry-run mode, warn but don't fail.
    fn check_binary_on_path(name: &str, dry_run: bool) -> Result<(), String> {
        let found = is_on_path(name);

        if !found {
            if dry_run {
                eprintln!("tirith: WARNING: {name} not found on PATH");
                Ok(())
            } else {
                Err(format!("{name} is required — install {name} and retry"))
            }
        } else {
            Ok(())
        }
    }

    /// Check if a binary is on PATH (cross-platform).
    fn is_on_path(name: &str) -> bool {
        #[cfg(unix)]
        {
            std::process::Command::new("sh")
                .args(["-c", &format!("command -v '{name}' >/dev/null 2>&1")])
                .status()
                .is_ok_and(|s| s.success())
        }
        #[cfg(not(unix))]
        {
            std::process::Command::new("where.exe")
                .arg(name)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        }
    }

    /// Copy the embedded gateway config to `~/.config/tirith/gateway.yaml`.
    /// Returns the absolute path to the written file.
    pub(crate) fn copy_gateway_config(force: bool, dry_run: bool) -> Result<PathBuf, String> {
        let base = etcetera::choose_base_strategy()
            .map_err(|e| format!("could not determine config directory: {e}"))?;
        let config_dir = base.config_dir().join("tirith");
        let gateway_path = config_dir.join("gateway.yaml");

        let content = crate::assets::GATEWAY_YAML;

        if gateway_path.exists() {
            let existing = std::fs::read_to_string(&gateway_path)
                .map_err(|e| format!("read {}: {e}", gateway_path.display()))?;
            if existing == content {
                eprintln!(
                    "tirith: {} already configured, up to date",
                    gateway_path.display()
                );
                return Ok(gateway_path);
            }
            if !force {
                if dry_run {
                    eprintln!(
                        "[dry-run] would error: {} exists but content differs — use --force to update",
                        gateway_path.display()
                    );
                    return Ok(gateway_path);
                }
                return Err(format!(
                    "{} exists but content differs — use --force to update",
                    gateway_path.display()
                ));
            }
        }

        if dry_run {
            eprintln!(
                "[dry-run] would write {} ({} bytes)",
                gateway_path.display(),
                content.len()
            );
            return Ok(gateway_path);
        }

        std::fs::create_dir_all(&config_dir)
            .map_err(|e| format!("create {}: {e}", config_dir.display()))?;
        fs_helpers::atomic_write(&gateway_path, content, 0o644)?;
        eprintln!("tirith: wrote {}", gateway_path.display());
        Ok(gateway_path)
    }

    pub(crate) fn setup_claude_code(opts: &SetupOpts) -> Result<(), String> {
        super::tools::setup_claude_code(opts)
    }

    fn setup_codex(opts: &SetupOpts) -> Result<(), String> {
        super::tools::setup_codex(opts)
    }

    fn setup_copilot_cli(opts: &SetupOpts) -> Result<(), String> {
        super::tools::setup_copilot_cli(opts)
    }

    fn setup_cursor(opts: &SetupOpts) -> Result<(), String> {
        super::tools::setup_cursor(opts)
    }

    fn setup_vscode(opts: &SetupOpts) -> Result<(), String> {
        super::tools::setup_vscode(opts)
    }

    fn setup_gemini_cli(opts: &SetupOpts) -> Result<(), String> {
        super::tools::setup_gemini_cli(opts)
    }

    fn setup_kiro(opts: &SetupOpts) -> Result<(), String> {
        super::tools::setup_kiro(opts)
    }

    fn setup_openclaw(opts: &SetupOpts) -> Result<(), String> {
        super::tools::setup_openclaw(opts)
    }

    fn setup_pi_cli(opts: &SetupOpts) -> Result<(), String> {
        super::tools::setup_pi_cli(opts)
    }

    fn setup_windsurf(opts: &SetupOpts) -> Result<(), String> {
        super::tools::setup_windsurf(opts)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn resolve_scope_rejects_user_for_copilot_cli() {
            let result = resolve_scope("copilot-cli", Some("user"));
            assert!(result.is_err(), "expected Err");
            let msg = result.unwrap_err();
            assert!(
                msg.contains("project") && msg.contains("repo root"),
                "expected project-only/repo-root message, got: {msg}"
            );
        }

        #[test]
        fn resolve_scope_accepts_project_for_copilot_cli() {
            assert_eq!(
                resolve_scope("copilot-cli", Some("project")).unwrap(),
                Scope::Project
            );
            assert_eq!(resolve_scope("copilot-cli", None).unwrap(), Scope::Project);
        }

        #[test]
        fn resolve_scope_accepts_both_for_kiro() {
            assert_eq!(resolve_scope("kiro", None).unwrap(), Scope::Project);
            assert_eq!(
                resolve_scope("kiro", Some("project")).unwrap(),
                Scope::Project
            );
            assert_eq!(resolve_scope("kiro", Some("user")).unwrap(), Scope::User);
        }
    }
}
