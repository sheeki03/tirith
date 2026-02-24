//! `tirith setup <tool>` — automated tool integration.
//!
//! Configures tirith protection for AI coding tools (Claude Code, Codex,
//! Cursor, VS Code, Windsurf) by writing hook scripts, merging JSON configs,
//! and registering MCP servers.

#[cfg(unix)]
mod fs_helpers;
#[cfg(unix)]
mod merge;
#[cfg(unix)]
mod tools;
#[cfg(unix)]
mod zshenv;

#[cfg(unix)]
#[allow(unused_imports)]
pub use self::run_impl::run;

#[cfg(not(unix))]
pub fn run(
    _tool: &str,
    _scope: Option<&str>,
    _with_mcp: bool,
    _install_zshenv: bool,
    _dry_run: bool,
    _force: bool,
) -> i32 {
    eprintln!("tirith setup is not supported on this platform");
    1
}

#[cfg(unix)]
mod run_impl {
    use super::fs_helpers;
    use etcetera::BaseStrategy;
    use std::path::PathBuf;

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
    }

    /// Entry point for `tirith setup <tool>`.
    pub fn run(
        tool: &str,
        scope: Option<&str>,
        with_mcp: bool,
        install_zshenv: bool,
        dry_run: bool,
        force: bool,
    ) -> i32 {
        match run_inner(tool, scope, with_mcp, install_zshenv, dry_run, force) {
            Ok(()) => 0,
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
    ) -> Result<(), String> {
        // --with-mcp is only valid for claude-code
        if with_mcp && tool != "claude-code" {
            return Err("--with-mcp is only supported for claude-code".into());
        }

        // Resolve and validate scope per tool
        let scope = resolve_scope(tool, scope)?;

        // Preflight: resolve tirith binary
        let tirith_bin = resolve_tirith_bin(dry_run)?;

        // Preflight: python3 check (all tools except codex)
        if tool != "codex" {
            check_binary_on_path("python3", dry_run)?;
        }

        // Preflight: tool-specific binary checks
        match tool {
            "codex" => {
                check_binary_on_path("codex", dry_run)?;
            }
            "claude-code" if with_mcp && scope == Scope::User => {
                check_binary_on_path("claude", dry_run)?;
            }
            _ => {}
        }

        // Preflight: zsh check when --install-zshenv
        if install_zshenv {
            check_binary_on_path("zsh", dry_run)?;
        }

        let opts = SetupOpts {
            scope,
            with_mcp,
            install_zshenv,
            dry_run,
            force,
            tirith_bin,
        };

        match tool {
            "claude-code" => setup_claude_code(&opts),
            "codex" => setup_codex(&opts),
            "cursor" => setup_cursor(&opts),
            "vscode" => setup_vscode(&opts),
            "windsurf" => setup_windsurf(&opts),
            _ => Err(format!(
                "unknown tool '{tool}' — expected one of: claude-code, codex, cursor, vscode, windsurf"
            )),
        }
    }

    /// Resolve scope for a given tool, applying defaults and validation.
    fn resolve_scope(tool: &str, scope: Option<&str>) -> Result<Scope, String> {
        match tool {
            "claude-code" | "cursor" => match scope {
                Some("project") | None => Ok(Scope::Project),
                Some("user") => Ok(Scope::User),
                Some(other) => Err(format!("invalid scope '{other}' — expected 'project' or 'user'")),
            },
            "vscode" => match scope {
                Some("project") | None => Ok(Scope::Project),
                Some("user") => Err(
                    "VS Code user settings use JSONC — run tirith setup vscode in your project directory instead, or configure manually".into(),
                ),
                Some(other) => Err(format!("invalid scope '{other}' — expected 'project' or 'user'")),
            },
            "codex" => match scope {
                Some("project") => Err("Codex is always user-global — omit --scope or use --scope user".into()),
                Some("user") | None => Ok(Scope::User),
                Some(other) => Err(format!("invalid scope '{other}' — expected 'user'")),
            },
            "windsurf" => match scope {
                Some("project") => Err("Windsurf is always user-global — omit --scope or use --scope user".into()),
                Some("user") | None => Ok(Scope::User),
                Some(other) => Err(format!("invalid scope '{other}' — expected 'user'")),
            },
            _ => Err(format!(
                "unknown tool '{tool}' — expected one of: claude-code, codex, cursor, vscode, windsurf"
            )),
        }
    }

    /// Resolve the tirith binary path for use in generated configs and hooks.
    ///
    /// 1. If `command -v tirith` succeeds, use the portable name `"tirith"`.
    /// 2. If not on PATH, check `current_exe()` — use absolute path + warning.
    /// 3. If neither: hard error (or placeholder in dry-run).
    fn resolve_tirith_bin(dry_run: bool) -> Result<String, String> {
        // Check if tirith is on PATH via `command -v`
        if std::process::Command::new("sh")
            .args(["-c", "command -v tirith >/dev/null 2>&1"])
            .status()
            .is_ok_and(|s| s.success())
        {
            return Ok("tirith".into());
        }

        // Not on PATH — try current_exe()
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

        // Neither found
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
        // Use `command -v` via sh to check PATH without relying on --version support
        let found = std::process::Command::new("sh")
            .args(["-c", &format!("command -v '{name}' >/dev/null 2>&1")])
            .status()
            .is_ok_and(|s| s.success());

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

    /// Copy the embedded gateway config to `~/.config/tirith/gateway.yaml`.
    /// Returns the absolute path to the written file.
    pub(crate) fn copy_gateway_config(force: bool, dry_run: bool) -> Result<PathBuf, String> {
        let base = etcetera::choose_base_strategy()
            .map_err(|e| format!("could not determine config directory: {e}"))?;
        let config_dir = base.config_dir().join("tirith");
        let gateway_path = config_dir.join("gateway.yaml");

        let content = crate::assets::GATEWAY_YAML;

        // Check existing
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

    // ── Tool-specific setup functions (delegated to tools.rs) ──────────

    pub(crate) fn setup_claude_code(opts: &SetupOpts) -> Result<(), String> {
        super::tools::setup_claude_code(opts)
    }

    fn setup_codex(opts: &SetupOpts) -> Result<(), String> {
        super::tools::setup_codex(opts)
    }

    fn setup_cursor(opts: &SetupOpts) -> Result<(), String> {
        super::tools::setup_cursor(opts)
    }

    fn setup_vscode(opts: &SetupOpts) -> Result<(), String> {
        super::tools::setup_vscode(opts)
    }

    fn setup_windsurf(opts: &SetupOpts) -> Result<(), String> {
        super::tools::setup_windsurf(opts)
    }
}
