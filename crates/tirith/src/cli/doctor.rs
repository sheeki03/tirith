use std::path::PathBuf;

pub fn run(json: bool, reset_bash_safe_mode: bool) -> i32 {
    if reset_bash_safe_mode {
        return reset_safe_mode();
    }

    let info = gather_info();

    if json {
        match serde_json::to_string_pretty(&info) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("tirith: JSON serialization failed: {e}");
                return 1;
            }
        }
    } else {
        print_human(&info);
    }
    0
}

#[derive(serde::Serialize)]
struct DoctorInfo {
    version: String,
    binary_path: String,
    detected_shell: String,
    interactive: bool,
    hook_dir: Option<String>,
    hooks_materialized: bool,
    shell_profile: Option<String>,
    hook_configured: bool,
    bash_safe_mode: bool,
    policy_paths: Vec<String>,
    policy_root_env: Option<String>,
    data_dir: Option<String>,
    log_path: Option<String>,
    last_trigger_path: Option<String>,
    /// Whether cloaking detection is available on this platform (Unix-only, ADR-8).
    cloaking_available: bool,
    /// Whether webhook dispatch is available on this platform (Unix-only, ADR-8).
    webhooks_available: bool,
}

fn gather_info() -> DoctorInfo {
    let binary_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let detected_shell = crate::cli::init::detect_shell().to_string();
    let interactive = is_terminal::is_terminal(std::io::stderr());

    let hook_dir = crate::cli::init::find_hook_dir_readonly();
    let hooks_materialized = hook_dir
        .as_ref()
        .map(|d| {
            // If the hook dir is inside the data dir, it was materialized
            if let Some(data) = tirith_core::policy::data_dir() {
                d.starts_with(&data)
            } else {
                false
            }
        })
        .unwrap_or(false);

    // Check if shell profile has tirith init configured
    let (shell_profile, hook_configured) = check_shell_profile(&detected_shell);

    // Check if bash safe-mode flag exists (persistent preexec fallback)
    let bash_safe_mode = tirith_core::policy::state_dir()
        .map(|d| d.join("bash-safe-mode").exists())
        .unwrap_or(false);

    let data_dir = tirith_core::policy::data_dir();
    let log_path = data_dir.as_ref().map(|d| d.join("log.jsonl"));
    let last_trigger_path = data_dir.as_ref().map(|d| d.join("last_trigger.json"));

    let mut policy_paths = Vec::new();
    // User-level policy
    if let Some(config) = tirith_core::policy::config_dir() {
        for ext in &["policy.yaml", "policy.yml"] {
            let user_policy = config.join(ext);
            if user_policy.exists() {
                policy_paths.push(user_policy.display().to_string());
                break;
            }
        }
    }
    // TIRITH_POLICY_ROOT override
    let policy_root_env = std::env::var("TIRITH_POLICY_ROOT").ok();
    if let Some(ref root) = policy_root_env {
        let tirith_dir = PathBuf::from(root).join(".tirith");
        for ext in &["policy.yaml", "policy.yml"] {
            let p = tirith_dir.join(ext);
            if p.exists() {
                policy_paths.push(p.display().to_string());
                break;
            }
        }
    }

    DoctorInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        binary_path,
        detected_shell,
        interactive,
        hook_dir: hook_dir.map(|d| d.display().to_string()),
        hooks_materialized,
        shell_profile: shell_profile.map(|p| p.display().to_string()),
        hook_configured,
        bash_safe_mode,
        policy_paths,
        policy_root_env,
        data_dir: data_dir.map(|d| d.display().to_string()),
        log_path: log_path.map(|p| p.display().to_string()),
        last_trigger_path: last_trigger_path.map(|p| p.display().to_string()),
        cloaking_available: cfg!(unix),
        webhooks_available: cfg!(unix),
    }
}

fn print_human(info: &DoctorInfo) {
    println!("tirith {}", info.version);
    println!("  binary:       {}", info.binary_path);
    println!("  shell:        {}", info.detected_shell);
    println!("  interactive:  {}", info.interactive);
    println!(
        "  hook dir:     {}",
        info.hook_dir.as_deref().unwrap_or("not found")
    );
    println!("  materialized: {}", info.hooks_materialized);
    println!(
        "  profile:      {}",
        info.shell_profile.as_deref().unwrap_or("not found")
    );
    if info.hook_configured {
        println!("  hook status:  configured");
    } else {
        println!("  hook status:  NOT CONFIGURED");
        println!();
        println!("  WARNING: tirith shell hook is not configured!");
        println!("  Commands will NOT be intercepted until you add to your shell profile:");
        println!();
        match info.detected_shell.as_str() {
            "zsh" => {
                println!("    echo 'eval \"$(tirith init --shell zsh)\"' >> ~/.zshrc");
                println!("    source ~/.zshrc");
            }
            "bash" => {
                println!("    echo 'eval \"$(tirith init --shell bash)\"' >> ~/.bashrc");
                println!("    source ~/.bashrc");
            }
            "fish" => {
                println!(
                    "    echo 'tirith init --shell fish | source' >> ~/.config/fish/config.fish"
                );
                println!("    source ~/.config/fish/config.fish");
            }
            "nushell" => {
                println!("    # First, materialize hooks:");
                println!("    tirith init --shell nushell");
                println!("    # Then add to ~/.config/nushell/config.nu:");
                if let Some(ref dir) = info.hook_dir {
                    // Escape for Nushell double-quoted string: \ → \\, " → \"
                    let escaped = dir.replace('\\', r"\\").replace('"', r#"\""#);
                    println!(r#"    source "{escaped}/lib/nushell-hook.nu""#);
                } else {
                    println!("    source <hook-dir>/lib/nushell-hook.nu");
                    println!(
                        "    # (run 'tirith init --shell nushell' first to determine the path)"
                    );
                }
            }
            _ => {
                println!("    eval \"$(tirith init)\"");
            }
        }
        println!();
    }
    if info.bash_safe_mode {
        println!("  bash mode:    SAFE MODE (preexec fallback — previous enter-mode failure)");
        println!("                Reset: tirith doctor --reset-bash-safe-mode");
    } else {
        println!("  bash mode:    normal");
    }
    if info.policy_paths.is_empty() {
        println!("  policies:     (none found)");
    } else {
        for (i, p) in info.policy_paths.iter().enumerate() {
            if i == 0 {
                println!("  policies:     {p}");
            } else {
                println!("                {p}");
            }
        }
    }
    if let Some(ref root) = info.policy_root_env {
        println!("  policy root:  {root} (TIRITH_POLICY_ROOT)");
    }
    println!(
        "  data dir:     {}",
        info.data_dir.as_deref().unwrap_or("not found")
    );
    println!(
        "  log path:     {}",
        info.log_path.as_deref().unwrap_or("not found")
    );
    println!(
        "  last trigger: {}",
        info.last_trigger_path.as_deref().unwrap_or("not found")
    );
    println!(
        "  cloaking:     {}",
        if info.cloaking_available {
            "available"
        } else {
            "not available (Unix-only)"
        }
    );
    println!(
        "  webhooks:     {}",
        if info.webhooks_available {
            "available"
        } else {
            "not available (Unix-only)"
        }
    );

    // License key format diagnostics
    use tirith_core::license::KeyFormatStatus;
    match tirith_core::license::key_format_status() {
        KeyFormatStatus::LegacyUnsigned => {
            println!("  license key:  WARNING: Using unsigned license key. Signed tokens will be required in a future release.");
        }
        KeyFormatStatus::LegacyInvalid => {
            println!("  license key:  WARNING: Invalid legacy license format. Key will not be recognized.");
        }
        KeyFormatStatus::Malformed => {
            println!("  license key:  WARNING: License key appears malformed (bad signed token structure).");
        }
        KeyFormatStatus::SignedStructural => {
            println!("  license key:  signed (structural check passed)");
        }
        KeyFormatStatus::NoKey => {
            println!("  license key:  not found");
        }
    }
}

/// Check if the user's shell profile contains tirith init configuration.
/// Returns (profile_path, is_configured).
fn check_shell_profile(shell: &str) -> (Option<PathBuf>, bool) {
    let home = match home::home_dir() {
        Some(h) => h,
        None => return (None, false),
    };

    // Determine which profile files to check based on shell
    let profile_candidates: Vec<PathBuf> = match shell {
        "zsh" => vec![
            home.join(".zshrc"),
            home.join(".zshenv"),
            home.join(".zprofile"),
        ],
        "bash" => vec![
            home.join(".bashrc"),
            home.join(".bash_profile"),
            home.join(".profile"),
        ],
        "fish" => {
            let mut candidates = vec![home.join(".config/fish/config.fish")];
            let conf_d = home.join(".config/fish/conf.d");
            if let Ok(entries) = std::fs::read_dir(&conf_d) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) == Some("fish") {
                        candidates.push(path);
                    }
                }
            }
            candidates
        }
        "powershell" | "pwsh" => {
            // PowerShell profile locations vary; check common ones
            let docs = home.join("Documents");
            vec![
                docs.join("PowerShell/Microsoft.PowerShell_profile.ps1"),
                docs.join("WindowsPowerShell/Microsoft.PowerShell_profile.ps1"),
                home.join(".config/powershell/Microsoft.PowerShell_profile.ps1"),
            ]
        }
        "nushell" | "nu" => {
            let xdg = std::env::var("XDG_CONFIG_HOME")
                .ok()
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".config"));
            vec![xdg.join("nushell/config.nu")]
        }
        _ => return (None, false),
    };

    // Check ALL candidates — don't early-return on first existing profile
    let mut first_existing = None;
    for profile in &profile_candidates {
        if profile.exists() {
            if first_existing.is_none() {
                first_existing = Some(profile.clone());
            }
            match std::fs::read_to_string(profile) {
                Ok(contents) => {
                    let configured = contents.contains("tirith init")
                        || contents.contains("tirith-hook")
                        || contents.contains("_tirith_");
                    if configured {
                        return (Some(profile.clone()), true);
                    }
                }
                Err(e) => {
                    eprintln!(
                        "tirith: doctor: cannot read profile {}: {e}",
                        profile.display()
                    );
                }
            }
        }
    }

    let primary = first_existing.or_else(|| profile_candidates.into_iter().next());
    (primary, false)
}

fn reset_safe_mode() -> i32 {
    let state_dir = match tirith_core::policy::state_dir() {
        Some(d) => d,
        None => {
            eprintln!("tirith: could not determine state directory");
            return 1;
        }
    };

    let flag = state_dir.join("bash-safe-mode");
    if flag.exists() {
        match std::fs::remove_file(&flag) {
            Ok(()) => {
                println!("tirith: bash safe-mode flag removed");
                println!("  Next shell will attempt enter mode again.");
                0
            }
            Err(e) => {
                eprintln!("tirith: failed to remove {}: {e}", flag.display());
                1
            }
        }
    } else {
        println!("tirith: no bash safe-mode flag found (enter mode is already enabled)");
        0
    }
}
