//! `tirith setup <tool>` — automated tool integration.
//!
//! Configures tirith protection for AI coding tools (Claude Code, Codex,
//! Cursor, VS Code, Windsurf) by writing hook scripts, merging JSON configs,
//! and registering MCP servers.

// Unix fs_helpers uses PermissionsExt for chmod; Windows uses no-op shims.
#[cfg_attr(unix, path = "fs_helpers.rs")]
#[cfg_attr(not(unix), path = "fs_helpers_windows.rs")]
mod fs_helpers;

mod fs_transaction;

// Compile Windows containment/ACL policy tests on Unix CI as pure tests.
#[cfg(all(test, unix))]
#[path = "fs_helpers_windows_path.rs"]
mod fs_helpers_windows_path;

mod merge;
mod shell_profile;
mod tools;

#[cfg(unix)]
mod zshenv;

pub use self::run_impl::run;

mod run_impl {
    use super::fs_helpers;
    use etcetera::BaseStrategy;
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    use std::path::{Path, PathBuf};

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
        "prime-agent",
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
        /// A validated absolute invocation path for the current executable:
        /// preferably its stable package-manager alias, otherwise its canonical
        /// target. Setup never persists a bare command name.
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
        // --with-mcp applies to claude-code, gemini-cli, and prime-agent.
        if with_mcp && tool != "claude-code" && tool != "gemini-cli" && tool != "prime-agent" {
            return Err(
                "--with-mcp is only supported for claude-code, gemini-cli, and prime-agent (other tools register MCP automatically or don't support it)"
                    .into(),
            );
        }

        let scope = resolve_scope(tool, scope)?;

        let tirith_bin = resolve_tirith_bin(dry_run)?;

        // Most hook scripts are Python; codex/pi-cli/openclaw are not.
        if tool != "codex" && tool != "pi-cli" && tool != "prime-agent" && tool != "openclaw" {
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
            "prime-agent" => setup_prime_agent(&opts),
            "vscode" => setup_vscode(&opts),
            "windsurf" => setup_windsurf(&opts),
            _ => Err(unknown_tool_error(tool)),
        }
    }

    /// Resolve scope for a given tool, applying defaults and validation.
    pub(super) fn resolve_scope(tool: &str, scope: Option<&str>) -> Result<Scope, String> {
        match tool {
            "claude-code" | "cursor" | "gemini-cli" | "kiro" | "openclaw" | "pi-cli" | "prime-agent" => {
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

    /// Resolve the tirith binary path for generated configs/hooks. Prefer a
    /// stable absolute PATH alias (for example Homebrew's `bin/tirith`) only
    /// when it currently resolves to the exact executable identity that entered
    /// setup. This lets package-manager upgrades retarget the stable alias
    /// without leaving generated configuration pinned to a removed version.
    fn resolve_tirith_bin(_dry_run: bool) -> Result<String, String> {
        let current = tirith_core::trusted_child::TrustedExecutable::current().map_err(|error| {
            format!(
                "running tirith executable could not be validated for generated security configuration: {error}"
            )
        })?;
        let stable_alias = stable_current_alias_on_path(&current);
        choose_generated_tirith_bin(Some(&current), stable_alias.as_ref())
    }

    fn choose_generated_tirith_bin(
        current: Option<&tirith_core::trusted_child::TrustedExecutable>,
        stable_alias: Option<&tirith_core::trusted_child::TrustedExecutable>,
    ) -> Result<String, String> {
        if let Some(current) = current {
            current.revalidate().map_err(|error| {
                format!("running tirith executable changed during setup validation: {error}")
            })?;

            if let Some(alias) = stable_alias {
                let freshly_resolved_alias =
                    tirith_core::trusted_child::TrustedExecutable::from_absolute(
                        alias.invocation_path(),
                        &[],
                    )
                    .ok();
                let alias_is_current = alias.invocation_path().is_absolute()
                    && alias.path() == current.path()
                    && alias.revalidate().is_ok();
                let freshly_resolves_to_current = freshly_resolved_alias
                    .as_ref()
                    .is_some_and(|fresh| fresh.path() == current.path());
                let current_identity_is_still_valid = current.revalidate().is_ok();
                if alias_is_current
                    && freshly_resolves_to_current
                    && current_identity_is_still_valid
                {
                    // A non-UTF-8 alias cannot be persisted exactly. It is safe
                    // to ignore it and use the canonical target when that target
                    // has a lossless text representation.
                    if let Some(alias) = alias.invocation_path().to_str() {
                        return Ok(alias.to_owned());
                    }
                }
            }
            return path_to_utf8(current.path(), "running tirith executable");
        }

        Err(
            "running tirith executable could not be validated for generated security configuration"
                .into(),
        )
    }

    fn stable_current_alias_on_path(
        current: &tirith_core::trusted_child::TrustedExecutable,
    ) -> Option<tirith_core::trusted_child::TrustedExecutable> {
        let path_value = std::env::var_os("PATH")?;
        let candidate = tirith_core::trusted_child::TrustedExecutable::resolve_on_path(
            "tirith",
            &path_value,
            &tirith_core::trusted_child::ambient_denied_roots(),
        )
        .ok()?;
        let selected_parent = candidate.invocation_path().parent()?;
        let current_dir = std::env::current_dir().ok()?;
        let selected_path_entry = std::env::split_paths(&path_value).find(|directory| {
            let absolute = if directory.is_absolute() {
                directory.clone()
            } else {
                current_dir.join(directory)
            };
            absolute == selected_parent
        })?;
        (selected_path_entry.is_absolute()
            && candidate.invocation_path().is_absolute()
            && candidate.path() == current.path())
        .then_some(candidate)
    }

    /// Convert a native path only at a text-based configuration boundary.
    /// Lossy conversion can change the executable or file identity that setup
    /// validated, so paths that cannot be represented exactly must fail closed.
    pub(super) fn path_to_utf8(path: &Path, role: &str) -> Result<String, String> {
        path.to_str().map(str::to_owned).ok_or_else(|| {
            format!(
                "{role} path is not valid UTF-8 and cannot be persisted without changing its identity: {}",
                path.display()
            )
        })
    }

    /// Resolve a tirith path suitable for `~/.zshenv`. `.zshenv` runs before PATH setup
    /// (`.zprofile`/`.zshrc` haven't run in a non-interactive `zsh -lc`), so resolve a
    /// stable executable path rather than relying on PATH state.
    #[cfg(unix)]
    pub(super) fn resolve_tirith_bin_for_zshenv(
        tirith_bin: &str,
        _dry_run: bool,
    ) -> Result<String, String> {
        let current = tirith_core::trusted_child::TrustedExecutable::current().map_err(|error| {
            format!("running tirith executable could not be validated for zshenv enforcement: {error}")
        })?;
        let stable_alias = if Path::new(tirith_bin).is_absolute() {
            tirith_core::trusted_child::TrustedExecutable::from_absolute(
                Path::new(tirith_bin),
                &tirith_core::trusted_child::ambient_denied_roots(),
            )
            .ok()
        } else {
            None
        };
        choose_generated_tirith_bin(Some(&current), stable_alias.as_ref())
    }

    /// Test seam for the fail-closed zshenv fallback behavior when no validated
    /// executable identity is available.
    #[cfg(all(test, unix))]
    fn choose_zshenv_tirith_bin(
        _path_candidate: Option<PathBuf>,
        current_exe: Option<PathBuf>,
        _tirith_bin: &str,
        _dry_run: bool,
    ) -> Result<String, String> {
        // The running executable is the only candidate whose identity was
        // established by the invocation that entered setup. Never let a
        // repository-prepended PATH replace it with an unrelated native binary
        // that would then be baked into every non-interactive zsh invocation.
        if let Some(exe) = current_exe {
            return path_to_utf8(&exe, "running tirith executable for zshenv");
        }
        Err("running tirith executable could not be validated for zshenv enforcement".into())
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
            if name == "zsh" {
                return super::zshenv::trusted_zsh_executable().is_ok();
            }
            // Inspect PATH entries directly. Invoking a PATH-resolved shell to
            // ask it about another executable would run attacker-controlled
            // code before setup establishes the requested guard.
            find_executable_on_path(name).is_some()
        }
        #[cfg(not(unix))]
        {
            // Resolve the requested executable itself through the trusted-path
            // policy. Invoking ambient `where.exe` would execute a second,
            // repository-searchable program before setup installs any guard.
            tirith_core::trusted_child::resolve_ambient(name).is_ok()
        }
    }

    fn gateway_config_location() -> Result<(PathBuf, PathBuf), String> {
        let base = etcetera::choose_base_strategy()
            .map_err(|e| format!("could not determine config directory: {e}"))?;
        let config_root = base.config_dir();
        let gateway_path = config_root.join("tirith").join("gateway.yaml");
        Ok((config_root, gateway_path))
    }

    /// Return the immutable, content-addressed gateway path used by Codex.
    /// A registration never points at the legacy mutable `gateway.yaml`, so a
    /// future setup can publish and validate a new generation before making it
    /// live.
    pub(crate) fn codex_gateway_config_location() -> Result<(PathBuf, PathBuf), String> {
        let (config_root, legacy_path) = gateway_config_location()?;
        let digest = Sha256::digest(crate::assets::GATEWAY_YAML.as_bytes());
        let mut digest_hex = String::with_capacity(digest.len() * 2);
        for byte in digest {
            let _ = write!(&mut digest_hex, "{byte:02x}");
        }
        let gateway_path = legacy_path
            .parent()
            .ok_or_else(|| "gateway config path has no parent".to_string())?
            .join(format!("gateway-sha256-{digest_hex}.yaml"));
        Ok((config_root, gateway_path))
    }

    /// Publish and then re-read Codex's content-addressed gateway generation.
    /// Existing content at the same digest-derived name is never overwritten:
    /// different bytes indicate tampering or a hash collision and fail closed.
    pub(crate) fn publish_codex_gateway_config(dry_run: bool) -> Result<PathBuf, String> {
        let (config_root, gateway_path) = codex_gateway_config_location()?;
        publish_codex_gateway_config_at(&config_root, &gateway_path, dry_run)
    }

    pub(super) fn publish_codex_gateway_config_at(
        config_root: &Path,
        gateway_path: &Path,
        dry_run: bool,
    ) -> Result<PathBuf, String> {
        // Codex persists this path as text in its registration. Reject an
        // unrepresentable identity before transactional_update can create any
        // parent or generation file.
        path_to_utf8(gateway_path, "Codex gateway")?;
        let content = crate::assets::GATEWAY_YAML;
        let outcome = fs_helpers::transactional_update(
            gateway_path,
            config_root,
            dry_run,
            |snapshot| {
                match snapshot.text(gateway_path)? {
                    Some(existing) if existing == content => {
                        Ok(fs_helpers::FileUpdate::unchanged())
                    }
                    Some(_) => Err(format!(
                        "content-addressed gateway generation {} exists with different bytes; refusing to overwrite it",
                        gateway_path.display()
                    )),
                    None => {
                        if dry_run {
                            eprintln!(
                                "[dry-run] would publish immutable gateway config {} ({} bytes)",
                                gateway_path.display(),
                                content.len()
                            );
                        }
                        Ok(fs_helpers::FileUpdate::write_text(content.to_string(), 0o644))
                    }
                }
            },
        )?;
        if !dry_run {
            let published = fs_helpers::read_to_string_scoped(gateway_path, config_root)?;
            if published.as_deref() != Some(content) {
                return Err(format!(
                    "published gateway generation {} could not be verified byte-for-byte",
                    gateway_path.display()
                ));
            }
        }
        if let Some(annotation) = outcome.completion_annotation() {
            eprintln!(
                "tirith: published immutable gateway config {}{annotation}",
                gateway_path.display()
            );
        }
        Ok(gateway_path.to_path_buf())
    }

    /// Retire only a prior Tirith-managed content-addressed generation. Legacy
    /// `gateway.yaml` remains shared by other integrations and is deliberately
    /// not removed here.
    pub(crate) fn retire_codex_gateway_config(
        previous: &Path,
        current: &Path,
    ) -> Result<(), String> {
        if previous == current {
            return Ok(());
        }
        let (config_root, managed_current) = codex_gateway_config_location()?;
        let managed_parent = managed_current
            .parent()
            .ok_or_else(|| "Codex gateway path has no parent".to_string())?;
        if previous.parent() != Some(managed_parent) {
            return Ok(());
        }
        fs_helpers::retire_codex_gateway_generation(previous, &config_root)
    }

    /// Copy the embedded gateway config to `~/.config/tirith/gateway.yaml`.
    /// Returns the absolute path to the written file.
    pub(crate) fn copy_gateway_config(force: bool, dry_run: bool) -> Result<PathBuf, String> {
        let (config_root, gateway_path) = gateway_config_location()?;

        let content = crate::assets::GATEWAY_YAML;

        let outcome = fs_helpers::transactional_update(
            &gateway_path,
            &config_root,
            dry_run,
            |snapshot| {
                if let Some(existing) = snapshot.text(&gateway_path)? {
                    if existing == content {
                        eprintln!(
                            "tirith: {} already configured, up to date",
                            gateway_path.display()
                        );
                        return Ok(fs_helpers::FileUpdate::unchanged());
                    }
                    if !force {
                        if dry_run {
                            eprintln!(
                                "[dry-run] would error: {} exists but content differs — use --force to update",
                                gateway_path.display()
                            );
                            return Ok(fs_helpers::FileUpdate::unchanged());
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
                }
                Ok(fs_helpers::FileUpdate::write_text(
                    content.to_string(),
                    0o644,
                ))
            },
        )?;
        if let Some(annotation) = outcome.completion_annotation() {
            eprintln!("tirith: wrote {}{annotation}", gateway_path.display());
        }
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

    fn setup_prime_agent(opts: &SetupOpts) -> Result<(), String> {
        super::tools::setup_prime_agent(opts)
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
        #[test]
        fn gateway_up_to_date_and_dry_run_refuse_symlinked_config_dir() {
            use crate::cli::test_harness::{with_fake_env, EnvGuard};

            with_fake_env(false, |home, _cwd| {
                let config_root = home.join(".config");
                std::fs::create_dir_all(&config_root).unwrap();
                let outside = tempfile::tempdir().unwrap();
                std::fs::write(
                    outside.path().join("gateway.yaml"),
                    crate::assets::GATEWAY_YAML,
                )
                .unwrap();
                std::os::unix::fs::symlink(outside.path(), config_root.join("tirith")).unwrap();
                let _xdg = EnvGuard::set("XDG_CONFIG_HOME", &config_root);

                for dry_run in [false, true] {
                    let result = copy_gateway_config(false, dry_run);
                    assert!(
                        result.is_err(),
                        "dry_run={dry_run} bypassed parent validation"
                    );
                }
            });
        }

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
        fn generated_tirith_bin_is_canonical_absolute_current_identity() {
            let dir = tempfile::tempdir().unwrap();
            let current_path = dir.path().join("installed").join("tirith");
            write_executable(&current_path, "trusted current executable");
            let current =
                tirith_core::trusted_child::TrustedExecutable::from_absolute(&current_path, &[])
                    .unwrap();

            let resolved = choose_generated_tirith_bin(Some(&current), None).unwrap();
            assert_eq!(resolved, current.path().display().to_string());
            assert!(Path::new(&resolved).is_absolute());
            assert_ne!(resolved, "tirith");
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn generated_tirith_bin_rejects_non_utf8_executable_identity() {
            use std::os::unix::ffi::OsStringExt;

            let dir = tempfile::tempdir().unwrap();
            let name = std::ffi::OsString::from_vec(b"tirith-\xff".to_vec());
            let current_path = dir.path().join(name);
            write_executable(&current_path, "trusted current executable");
            let current =
                tirith_core::trusted_child::TrustedExecutable::from_absolute(&current_path, &[])
                    .unwrap();

            let error = choose_generated_tirith_bin(Some(&current), None).unwrap_err();
            assert!(error.contains("not valid UTF-8"), "{error}");
            assert!(error.contains("cannot be persisted"), "{error}");
        }

        #[cfg(unix)]
        #[test]
        fn generated_config_path_rejects_non_utf8_identity_without_filesystem_fixture() {
            use std::os::unix::ffi::OsStringExt;

            // APFS rejects invalid UTF-8 names before a real-file fixture can
            // reach the persistence boundary. A synthetic native path tests
            // that boundary portably across Unix hosts.
            let path = PathBuf::from(std::ffi::OsString::from_vec(
                b"/tmp/tirith-generated-\xff".to_vec(),
            ));
            let error = path_to_utf8(&path, "running tirith executable").unwrap_err();
            assert!(error.contains("not valid UTF-8"), "{error}");
            assert!(error.contains("cannot be persisted"), "{error}");
        }

        #[cfg(unix)]
        #[test]
        fn generated_tirith_bin_prefers_validated_stable_alias() {
            use std::os::unix::fs::symlink;

            let dir = tempfile::tempdir().unwrap();
            let current_path = dir.path().join("installed").join("tirith");
            let path_spelling = dir.path().join("path-bin").join("tirith");
            write_executable(&current_path, "trusted current executable");
            std::fs::create_dir_all(path_spelling.parent().unwrap()).unwrap();
            symlink(&current_path, &path_spelling).unwrap();
            let current =
                tirith_core::trusted_child::TrustedExecutable::from_absolute(&current_path, &[])
                    .unwrap();
            let candidate =
                tirith_core::trusted_child::TrustedExecutable::from_absolute(&path_spelling, &[])
                    .unwrap();

            assert_eq!(candidate.path(), current.path());
            let resolved = choose_generated_tirith_bin(Some(&current), Some(&candidate)).unwrap();
            assert_eq!(resolved, path_spelling.display().to_string());
            assert!(Path::new(&resolved).is_absolute());
            assert_ne!(resolved, "tirith");
        }

        #[cfg(unix)]
        #[test]
        fn generated_tirith_bin_stable_alias_survives_upgrade_retarget() {
            use std::os::unix::fs::symlink;

            let dir = tempfile::tempdir().unwrap();
            let v1 = dir.path().join("versions/v1/tirith");
            let v2 = dir.path().join("versions/v2/tirith");
            let stable = dir.path().join("bin/tirith");
            write_executable(&v1, "trusted current executable v1");
            write_executable(&v2, "trusted current executable v2");
            std::fs::create_dir_all(stable.parent().unwrap()).unwrap();
            symlink(&v1, &stable).unwrap();

            let current_v1 =
                tirith_core::trusted_child::TrustedExecutable::from_absolute(&v1, &[]).unwrap();
            let alias_v1 =
                tirith_core::trusted_child::TrustedExecutable::from_absolute(&stable, &[]).unwrap();
            let persisted_v1 =
                choose_generated_tirith_bin(Some(&current_v1), Some(&alias_v1)).unwrap();
            assert_eq!(persisted_v1, stable.display().to_string());

            std::fs::remove_file(&stable).unwrap();
            symlink(&v2, &stable).unwrap();
            let current_v2 =
                tirith_core::trusted_child::TrustedExecutable::from_absolute(&v2, &[]).unwrap();
            let alias_v2 =
                tirith_core::trusted_child::TrustedExecutable::from_absolute(&stable, &[]).unwrap();
            let persisted_v2 =
                choose_generated_tirith_bin(Some(&current_v2), Some(&alias_v2)).unwrap();

            assert_eq!(persisted_v2, persisted_v1);
            assert_ne!(persisted_v2, current_v2.path().display().to_string());
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn generated_tirith_bin_ignores_non_utf8_alias_when_canonical_is_utf8() {
            use std::os::unix::ffi::OsStringExt;
            use std::os::unix::fs::symlink;

            let dir = tempfile::tempdir().unwrap();
            let current_path = dir.path().join("installed/tirith");
            write_executable(&current_path, "trusted current executable");
            let alias_name = std::ffi::OsString::from_vec(b"tirith-\xff".to_vec());
            let alias_path = dir.path().join("bin").join(alias_name);
            std::fs::create_dir_all(alias_path.parent().unwrap()).unwrap();
            symlink(&current_path, &alias_path).unwrap();
            let current =
                tirith_core::trusted_child::TrustedExecutable::from_absolute(&current_path, &[])
                    .unwrap();
            let alias =
                tirith_core::trusted_child::TrustedExecutable::from_absolute(&alias_path, &[])
                    .unwrap();

            let resolved = choose_generated_tirith_bin(Some(&current), Some(&alias)).unwrap();
            assert_eq!(resolved, current.path().display().to_string());
        }

        #[test]
        fn generated_tirith_bin_never_falls_back_to_bare_name() {
            assert!(choose_generated_tirith_bin(None, None).is_err());
            // Whether the RUNNING binary validates depends on the host: CI
            // runners execute tests from checkout/build directories owned by a
            // different principal, which the ancestor-ownership validation
            // rightly refuses. Either outcome upholds the contract: a valid
            // current exe resolves to an absolute path, and an invalid one
            // surfaces the validation refusal — never a bare name on PATH.
            match resolve_tirith_bin(true) {
                Ok(resolved) => assert!(
                    Path::new(&resolved).is_absolute(),
                    "resolved bin must be an absolute path: {resolved}"
                ),
                Err(error) => assert!(
                    error.contains("could not be validated"),
                    "resolution may fail only by refusing validation: {error}"
                ),
            }
        }

        #[cfg(windows)]
        #[test]
        fn binary_check_never_executes_current_directory_where_exe() {
            use crate::cli::test_harness::{with_fake_env, EnvGuard};

            with_fake_env(true, |_home, cwd| {
                let cwd = cwd.unwrap();
                std::fs::copy(std::env::current_exe().unwrap(), cwd.join("where.exe")).unwrap();
                let _path = EnvGuard::set("PATH", Path::new(""));

                assert!(!is_on_path("tirith-definitely-missing-tool.exe"));
            });
        }

        #[cfg(unix)]
        #[test]
        fn zshenv_resolver_rejects_path_only_candidate_without_current_identity() {
            let dir = tempfile::tempdir().unwrap();
            let tirith = dir.path().join("tirith");
            write_executable(&tirith, "");
            assert!(choose_zshenv_tirith_bin(Some(tirith), None, "tirith", false).is_err());
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
        fn zshenv_resolver_rejects_non_utf8_executable_identity() {
            use std::os::unix::ffi::OsStringExt;

            let path = PathBuf::from(std::ffi::OsString::from_vec(
                b"/tmp/tirith-zshenv-\xff".to_vec(),
            ));
            let error = choose_zshenv_tirith_bin(None, Some(path), "tirith", false).unwrap_err();
            assert!(error.contains("not valid UTF-8"), "{error}");
            assert!(error.contains("cannot be persisted"), "{error}");
        }

        #[cfg(unix)]
        #[test]
        fn zshenv_resolver_ignores_poisoned_native_path_when_current_exe_is_known() {
            let dir = tempfile::tempdir().unwrap();
            let attacker = dir.path().join("repo-bin").join("tirith");
            let current = dir.path().join("installed").join("tirith");
            write_executable(&attacker, "native attacker placeholder");
            write_executable(&current, "trusted current executable placeholder");

            let resolved = choose_zshenv_tirith_bin(
                Some(attacker.clone()),
                Some(current.clone()),
                "tirith",
                false,
            )
            .unwrap();

            assert_eq!(resolved, current.display().to_string());
            assert_ne!(resolved, attacker.display().to_string());
        }

        #[cfg(unix)]
        #[test]
        fn zshenv_resolver_rejects_unvalidated_absolute_fallback() {
            assert!(choose_zshenv_tirith_bin(None, None, "/opt/custom/bin/tirith", false).is_err());
            assert!(choose_zshenv_tirith_bin(None, None, "tirith", true).is_err());
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
