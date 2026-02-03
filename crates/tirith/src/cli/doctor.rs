use std::path::PathBuf;

pub fn run(json: bool) -> i32 {
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
    policy_paths: Vec<String>,
    policy_root_env: Option<String>,
    data_dir: Option<String>,
    log_path: Option<String>,
    last_trigger_path: Option<String>,
}

fn gather_info() -> DoctorInfo {
    let binary_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let detected_shell = detect_shell().to_string();
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
        policy_paths,
        policy_root_env,
        data_dir: data_dir.map(|d| d.display().to_string()),
        log_path: log_path.map(|p| p.display().to_string()),
        last_trigger_path: last_trigger_path.map(|p| p.display().to_string()),
    }
}

fn print_human(info: &DoctorInfo) {
    eprintln!("tirith {}", info.version);
    eprintln!("  binary:       {}", info.binary_path);
    eprintln!("  shell:        {}", info.detected_shell);
    eprintln!("  interactive:  {}", info.interactive);
    eprintln!(
        "  hook dir:     {}",
        info.hook_dir.as_deref().unwrap_or("not found")
    );
    eprintln!("  materialized: {}", info.hooks_materialized);
    eprintln!(
        "  profile:      {}",
        info.shell_profile.as_deref().unwrap_or("not found")
    );
    if info.hook_configured {
        eprintln!("  hook status:  configured");
    } else {
        eprintln!("  hook status:  NOT CONFIGURED");
        eprintln!();
        eprintln!("  WARNING: tirith shell hook is not configured!");
        eprintln!("  Commands will NOT be intercepted until you add to your shell profile:");
        eprintln!();
        match info.detected_shell.as_str() {
            "zsh" => {
                eprintln!("    echo 'eval \"$(tirith init)\"' >> ~/.zshrc");
                eprintln!("    source ~/.zshrc");
            }
            "bash" => {
                eprintln!("    echo 'eval \"$(tirith init)\"' >> ~/.bashrc");
                eprintln!("    source ~/.bashrc");
            }
            "fish" => {
                eprintln!("    echo 'tirith init | source' >> ~/.config/fish/config.fish");
                eprintln!("    source ~/.config/fish/config.fish");
            }
            _ => {
                eprintln!("    eval \"$(tirith init)\"");
            }
        }
        eprintln!();
    }
    if info.policy_paths.is_empty() {
        eprintln!("  policies:     (none found)");
    } else {
        for (i, p) in info.policy_paths.iter().enumerate() {
            if i == 0 {
                eprintln!("  policies:     {p}");
            } else {
                eprintln!("                {p}");
            }
        }
    }
    if let Some(ref root) = info.policy_root_env {
        eprintln!("  policy root:  {root} (TIRITH_POLICY_ROOT)");
    }
    eprintln!(
        "  data dir:     {}",
        info.data_dir.as_deref().unwrap_or("not found")
    );
    eprintln!(
        "  log path:     {}",
        info.log_path.as_deref().unwrap_or("not found")
    );
    eprintln!(
        "  last trigger: {}",
        info.last_trigger_path.as_deref().unwrap_or("not found")
    );
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
        "fish" => vec![home.join(".config/fish/config.fish")],
        "powershell" | "pwsh" => {
            // PowerShell profile locations vary; check common ones
            let docs = home.join("Documents");
            vec![
                docs.join("PowerShell/Microsoft.PowerShell_profile.ps1"),
                docs.join("WindowsPowerShell/Microsoft.PowerShell_profile.ps1"),
                home.join(".config/powershell/Microsoft.PowerShell_profile.ps1"),
            ]
        }
        _ => return (None, false),
    };

    // Find the first existing profile and check if it contains tirith init
    for profile in &profile_candidates {
        if profile.exists() {
            if let Ok(contents) = std::fs::read_to_string(profile) {
                // Check for various forms of tirith init
                let configured = contents.contains("tirith init")
                    || contents.contains("tirith-hook")
                    || contents.contains("_tirith_");
                return (Some(profile.clone()), configured);
            }
        }
    }

    // Return the primary profile path even if it doesn't exist
    let primary = profile_candidates.into_iter().next();
    (primary, false)
}

fn detect_shell() -> &'static str {
    if let Ok(shell) = std::env::var("SHELL") {
        if shell.contains("zsh") {
            return "zsh";
        }
        if shell.contains("bash") {
            return "bash";
        }
        if shell.contains("fish") {
            return "fish";
        }
    }
    #[cfg(windows)]
    return "powershell";
    #[cfg(not(windows))]
    "bash"
}
