//! `tirith setup <tool>` — automated tool integration.
//!
//! Configures tirith protection for AI coding tools (Claude Code, Codex,
//! Cursor, VS Code, Windsurf) by writing hook scripts, merging JSON configs,
//! and registering MCP servers.

// Unix fs_helpers uses PermissionsExt for chmod; Windows uses no-op shims.
#[cfg_attr(unix, path = "fs_helpers.rs")]
#[cfg_attr(not(unix), path = "fs_helpers_windows.rs")]
mod fs_helpers;

mod merge;
mod shell_profile;
mod tools;

#[cfg(unix)]
mod zshenv;

pub use self::run_impl::run;

mod run_impl {
    use super::fs_helpers;
    use etcetera::BaseStrategy;
    #[cfg(unix)]
    use std::path::Path;
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
        // --with-mcp only applies to claude-code and gemini-cli.
        if with_mcp && tool != "claude-code" && tool != "gemini-cli" {
            return Err(
                "--with-mcp is only supported for claude-code and gemini-cli (other tools register MCP automatically or don't support it)"
                    .into(),
            );
        }

        let scope = resolve_scope(tool, scope)?;

        let tirith_bin = resolve_tirith_bin(dry_run)?;

        // Most hook scripts are Python; codex/pi-cli/openclaw are not.
        if tool != "codex" && tool != "pi-cli" && tool != "openclaw" {
            check_binary_on_path("python3", dry_run)?;
        }

        if tool == "codex" {
            check_binary_on_path("codex", dry_run)?;
        }

        if install_zshenv {
            check_binary_on_path("zsh", dry_run)?;
        }

        // --update-configs implies --force (refreshing overwrites stale files).
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

    /// Resolve the tirith binary path for generated configs/hooks: portable `"tirith"` if
    /// on PATH, else absolute `current_exe()` + warning, else hard error (placeholder in dry-run).
    fn resolve_tirith_bin(dry_run: bool) -> Result<String, String> {
        if is_on_path("tirith") {
            return Ok("tirith".into());
        }

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

    /// Resolve a tirith path suitable for `~/.zshenv`. `.zshenv` runs before PATH setup
    /// (`.zprofile`/`.zshrc` haven't run in a non-interactive `zsh -lc`), so resolve a
    /// stable executable path rather than relying on PATH state.
    #[cfg(unix)]
    pub(super) fn resolve_tirith_bin_for_zshenv(
        tirith_bin: &str,
        dry_run: bool,
    ) -> Result<String, String> {
        choose_zshenv_tirith_bin(
            find_executable_on_path("tirith"),
            current_tirith_exe(),
            tirith_bin,
            dry_run,
        )
    }

    /// Pure-function core of [`resolve_tirith_bin_for_zshenv`], taking the candidate
    /// sources as inputs so it is unit-testable without process-global state.
    #[cfg(unix)]
    fn choose_zshenv_tirith_bin(
        path_candidate: Option<PathBuf>,
        current_exe: Option<PathBuf>,
        tirith_bin: &str,
        dry_run: bool,
    ) -> Result<String, String> {
        if let Some(path) = path_candidate {
            // If the PATH entry is a `#!` wrapper (e.g. the npm JS launcher), prefer the
            // running native binary the wrapper exec'd into (npm shadow-detection bug class).
            if is_script_wrapper(&path) {
                if let Some(exe) = current_exe {
                    return Ok(exe.display().to_string());
                }
            }
            return Ok(path.display().to_string());
        }
        if let Some(exe) = current_exe {
            return Ok(exe.display().to_string());
        }
        if Path::new(tirith_bin).is_absolute() {
            return Ok(tirith_bin.to_string());
        }
        if dry_run {
            eprintln!(
                "tirith: WARNING: tirith not found — previewing zshenv guard with portable name 'tirith' (actual setup would fail)"
            );
            Ok("tirith".into())
        } else {
            Err("tirith binary not found — ensure tirith is installed and on PATH before installing zshenv guard".into())
        }
    }

    #[cfg(unix)]
    fn current_tirith_exe() -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        if exe.file_name()? == "tirith" {
            Some(exe)
        } else {
            None
        }
    }

    #[cfg(unix)]
    fn find_executable_on_path(name: &str) -> Option<PathBuf> {
        let path_var = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(name);
            if !is_executable_file(&candidate) {
                continue;
            }
            // Canonicalize so a symlink on PATH resolves to its real path before the
            // caller compares against `current_exe()` (npm-shadow equality-bug class).
            return candidate.canonicalize().ok().or(Some(candidate));
        }
        None
    }

    #[cfg(unix)]
    fn is_executable_file(path: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        let Ok(metadata) = std::fs::metadata(path) else {
            return false;
        };
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    }

    #[cfg(unix)]
    fn is_script_wrapper(path: &Path) -> bool {
        // `read` not `read_exact`: a 1-byte file is not a wrapper but read_exact errors on it.
        use std::io::Read;
        let Ok(mut file) = std::fs::File::open(path) else {
            return false;
        };
        let mut bytes = [0u8; 2];
        file.read(&mut bytes)
            .map(|n| n == 2 && &bytes == b"#!")
            .unwrap_or(false)
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

        #[cfg(unix)]
        fn write_executable(path: &Path, content: &str) {
            use std::os::unix::fs::PermissionsExt;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(path, content).unwrap();
            let mut perms = std::fs::metadata(path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(path, perms).unwrap();
        }

        #[cfg(unix)]
        #[test]
        fn zshenv_resolver_prefers_executable_path_over_portable_name() {
            let dir = tempfile::tempdir().unwrap();
            let tirith = dir.path().join("tirith");
            write_executable(&tirith, "");
            let resolved =
                choose_zshenv_tirith_bin(Some(tirith.clone()), None, "tirith", false).unwrap();
            assert_eq!(resolved, tirith.display().to_string());
        }

        #[cfg(unix)]
        #[test]
        fn zshenv_resolver_uses_current_exe_when_path_entry_is_script_wrapper() {
            let dir = tempfile::tempdir().unwrap();
            let wrapper = dir.path().join("tirith");
            let native = dir.path().join("native").join("tirith");
            write_executable(&wrapper, "#!/usr/bin/env node\n");
            write_executable(&native, "");
            let resolved =
                choose_zshenv_tirith_bin(Some(wrapper), Some(native.clone()), "tirith", false)
                    .unwrap();
            assert_eq!(resolved, native.display().to_string());
        }

        #[cfg(unix)]
        #[test]
        fn zshenv_resolver_keeps_absolute_fallback() {
            let resolved =
                choose_zshenv_tirith_bin(None, None, "/opt/custom/bin/tirith", false).unwrap();
            assert_eq!(resolved, "/opt/custom/bin/tirith");
        }

        #[cfg(unix)]
        #[test]
        fn zshenv_resolver_allows_portable_name_in_dry_run() {
            let resolved = choose_zshenv_tirith_bin(None, None, "tirith", true).unwrap();
            assert_eq!(resolved, "tirith");
        }

        #[cfg(unix)]
        #[test]
        fn find_executable_on_path_canonicalizes_symlink() {
            use crate::cli::test_harness::{with_fake_env, EnvGuard};
            use std::os::unix;
            with_fake_env(false, |_home, _cwd| {
                let target_dir = tempfile::tempdir().unwrap();
                let link_dir = tempfile::tempdir().unwrap();
                let real_tirith = target_dir.path().join("tirith");
                write_executable(&real_tirith, "");

                let symlink_tirith = link_dir.path().join("tirith");
                unix::fs::symlink(&real_tirith, &symlink_tirith).unwrap();

                let _path = EnvGuard::set("PATH", link_dir.path());
                let found = find_executable_on_path("tirith")
                    .expect("symlink on PATH should be discoverable");
                let expected = real_tirith
                    .canonicalize()
                    .expect("real tirith path canonicalizes");
                assert_eq!(
                    found, expected,
                    "symlink must resolve to canonical real path"
                );
            });
        }

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
