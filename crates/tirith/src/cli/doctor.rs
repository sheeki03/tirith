use std::collections::HashMap;
use std::path::PathBuf;

pub fn run(json: bool, reset_bash_safe_mode: bool, fix: bool, yes: bool) -> i32 {
    if reset_bash_safe_mode {
        return reset_safe_mode();
    }

    if fix {
        return run_fix(yes);
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

fn confirm(prompt: &str) -> bool {
    eprint!("{prompt} [y/N] ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    matches!(input.trim(), "y" | "Y" | "yes" | "Yes")
}

fn run_fix(yes: bool) -> i32 {
    let mut fixed = 0;

    // 1. Shell hooks: if not installed, run init logic
    if !hooks_installed() {
        println!("Fix: Install shell hooks");
        if yes || confirm("  Install hooks?") {
            let rc = crate::cli::init::run(None);
            if rc == 0 {
                println!("  Hooks installed.");
                fixed += 1;
            } else {
                eprintln!("  Hook installation failed (exit code {rc}).");
            }
        }
    }

    // 2. Hook assets: if stale, re-materialize embedded hooks
    if hooks_stale() {
        println!("Fix: Re-materialize stale hook assets");
        if yes || confirm("  Re-materialize hooks?") {
            // find_hook_dir() materializes as a side effect when needed
            match crate::cli::init::find_hook_dir() {
                Some(dir) => {
                    println!("  Hooks materialized to {}.", dir.display());
                    fixed += 1;
                }
                None => {
                    eprintln!("  Failed to materialize hooks.");
                }
            }
        }
    }

    // 3. Policy: if no policy found, create a starter policy
    if policy_missing() {
        println!("Fix: Create starter policy");
        if yes || confirm("  Create .tirith/policy.yaml?") {
            match create_default_policy() {
                Ok(path) => {
                    println!("  Created {}", path.display());
                    fixed += 1;
                }
                Err(e) => {
                    eprintln!("  Failed to create policy: {e}");
                }
            }
        }
    }

    // 4. AI tool setup: detect installed tools and offer to configure
    #[cfg(unix)]
    {
        let tools = detect_ai_tools();
        if !tools.is_empty() {
            println!("Fix: Configure tirith for AI coding tools");
            for tool in &tools {
                if yes || confirm(&format!("  Configure tirith for {tool}?")) {
                    let rc = crate::cli::setup::run(tool, None, false, false, false, false, false);
                    if rc == 0 {
                        println!("  Configured {tool}.");
                        fixed += 1;
                    } else {
                        eprintln!("  Failed to configure {tool}.");
                    }
                }
            }
        }
    }

    // 5. Bash safe-mode: if active, offer to clear
    if bash_safe_mode_active() {
        println!("Fix: Clear bash safe-mode flag");
        if yes || confirm("  Clear safe-mode?") {
            if let Some(state) = tirith_core::policy::state_dir() {
                let flag = state.join("bash-safe-mode");
                match std::fs::remove_file(&flag) {
                    Ok(()) => {
                        println!("  Safe-mode flag removed. Next shell will attempt enter mode.");
                        fixed += 1;
                    }
                    Err(e) => {
                        eprintln!("  Failed to remove safe-mode flag: {e}");
                    }
                }
            }
        }
    }

    if fixed == 0 {
        println!("tirith: no issues to fix");
    } else {
        println!("tirith: fixed {fixed} issue(s)");
    }
    0
}

/// Check whether shell hooks are configured in the user's profile.
fn hooks_installed() -> bool {
    let shell = crate::cli::init::detect_shell().to_string();
    let (_profile, configured) = check_shell_profile(&shell);
    configured
}

/// Check whether materialized hook assets exist but are stale (version mismatch).
fn hooks_stale() -> bool {
    let hook_dir = match crate::cli::init::find_hook_dir_readonly() {
        Some(d) => d,
        None => return false, // no hooks at all; hooks_installed() handles that
    };

    // Only check staleness for materialized (data-dir) hooks
    let data_dir = match tirith_core::policy::data_dir() {
        Some(d) => d,
        None => return false,
    };
    if !hook_dir.starts_with(&data_dir) {
        return false; // system/homebrew hooks, not our concern
    }

    let version_path = hook_dir.join(".hooks-version");
    let current_version = env!("CARGO_PKG_VERSION");
    match std::fs::read_to_string(&version_path) {
        Ok(v) => v.trim() != current_version,
        Err(_) => true, // no version file means stale
    }
}

/// Check whether any policy file can be discovered.
fn policy_missing() -> bool {
    // Check TIRITH_POLICY_ROOT
    if let Ok(root) = std::env::var("TIRITH_POLICY_ROOT") {
        let tirith_dir = PathBuf::from(&root).join(".tirith");
        for ext in &["policy.yaml", "policy.yml"] {
            if tirith_dir.join(ext).exists() {
                return false;
            }
        }
    }

    // Check walk-up discovery (local-only, no network fetch)
    let policy = tirith_core::policy::Policy::discover_partial(None);
    policy.path.is_none()
}

/// Detect installed AI coding tools by checking for their config directories.
#[cfg(unix)]
fn detect_ai_tools() -> Vec<&'static str> {
    let mut tools = Vec::new();
    let home = match home::home_dir() {
        Some(h) => h,
        None => return tools,
    };

    if home.join(".claude").exists() {
        tools.push("claude-code");
    }
    if home.join(".cursor").exists() {
        tools.push("cursor");
    }
    if home.join(".vscode").exists() {
        tools.push("vscode");
    }
    if home.join(".codeium").exists() {
        tools.push("windsurf");
    }

    tools
}

fn bash_safe_mode_active() -> bool {
    tirith_core::policy::state_dir()
        .map(|d| d.join("bash-safe-mode").exists())
        .unwrap_or(false)
}

/// Create a minimal starter policy at .tirith/policy.yaml in the repo root,
/// or fall back to the user config dir.
fn create_default_policy() -> Result<PathBuf, String> {
    let content = "\
# tirith policy — see https://github.com/anthropics/tirith for options
fail_mode: open
allow_bypass_env: true
paranoia: 1
strict_warn: false
allowlist: []
blocklist: []
";

    // Try repo root first
    if let Some(repo_root) = tirith_core::policy::find_repo_root(None) {
        let policy_dir = repo_root.join(".tirith");
        if std::fs::create_dir_all(&policy_dir).is_ok() {
            let path = policy_dir.join("policy.yaml");
            return std::fs::write(&path, content)
                .map(|()| path)
                .map_err(|e| e.to_string());
        }
    }

    // Fall back to user config dir
    if let Some(config) = tirith_core::policy::config_dir() {
        if std::fs::create_dir_all(&config).is_ok() {
            let path = config.join("policy.yaml");
            return std::fs::write(&path, content)
                .map(|()| path)
                .map_err(|e| e.to_string());
        }
    }

    Err("could not determine a location for policy file".to_string())
}

/// Detection gap analysis: what findings are hidden by the current paranoia level.
#[derive(Debug, Clone, serde::Serialize)]
struct DetectionGapInfo {
    total_commands: usize,
    blocked: usize,
    warned: usize,
    records_analyzed: usize,
    records_with_raw: usize,
    records_without_raw: usize,
    total_findings: usize,
    raw_total_findings: usize,
    hidden_findings: usize,
    hidden_top_rules: Vec<(String, usize)>,
    current_paranoia: u8,
}

/// Analyze audit log data from the last 7 days to show detection coverage gaps.
///
/// For each verdict record that has `raw_rule_ids`, computes the multiset diff
/// (raw minus effective) to find exactly which rules were suppressed by paranoia
/// filtering. Records without `raw_rule_ids` (legacy, pre-upgrade) are counted
/// but skipped in the delta computation.
fn check_detection_gaps() -> Option<DetectionGapInfo> {
    let data_dir = tirith_core::policy::data_dir()?;
    let log_path = data_dir.join("log.jsonl");
    if !log_path.exists() {
        return None;
    }

    let read_result = match tirith_core::audit_aggregator::read_log(&log_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "tirith: doctor: cannot read audit log {}: {e}",
                log_path.display()
            );
            return None;
        }
    };
    if read_result.records.is_empty() {
        return None;
    }

    // Filter to verdict entries from the last 7 days
    let seven_days_ago = chrono::Utc::now() - chrono::Duration::days(7);
    let since_str = seven_days_ago.to_rfc3339();

    let filter = tirith_core::audit_aggregator::AuditFilter {
        since: Some(since_str),
        entry_type: Some("verdict".to_string()),
        ..Default::default()
    };
    let verdicts = tirith_core::audit_aggregator::filter_records(&read_result.records, &filter);
    if verdicts.is_empty() {
        return None;
    }

    let total_commands = verdicts.len();
    let blocked = verdicts
        .iter()
        .filter(|r| r.action.eq_ignore_ascii_case("Block"))
        .count();
    let warned = verdicts
        .iter()
        .filter(|r| {
            r.action.eq_ignore_ascii_case("Warn") || r.action.eq_ignore_ascii_case("WarnAck")
        })
        .count();

    let mut records_with_raw = 0usize;
    let mut records_without_raw = 0usize;
    let mut total_findings = 0usize;
    let mut raw_total_findings_analyzed = 0usize; // only from records with raw data
    let mut hidden_findings = 0usize;
    let mut hidden_rule_counts: HashMap<String, usize> = HashMap::new();

    for record in &verdicts {
        total_findings += record.rule_ids.len();

        match record.raw_rule_ids {
            Some(ref raw_ids) => {
                records_with_raw += 1;
                raw_total_findings_analyzed += raw_ids.len();

                // Multiset diff: raw_rule_ids minus rule_ids
                let mut effective_counts: HashMap<&str, u32> = HashMap::new();
                for rid in &record.rule_ids {
                    *effective_counts.entry(rid.as_str()).or_insert(0) += 1;
                }
                for raw_rid in raw_ids {
                    match effective_counts.get_mut(raw_rid.as_str()) {
                        Some(count) if *count > 0 => {
                            *count -= 1; // matched, not hidden
                        }
                        _ => {
                            hidden_findings += 1;
                            *hidden_rule_counts.entry(raw_rid.clone()).or_insert(0) += 1;
                        }
                    }
                }
            }
            None => {
                records_without_raw += 1;
            }
        }
    }

    let records_analyzed = records_with_raw;

    let mut hidden_top_rules: Vec<(String, usize)> = hidden_rule_counts.into_iter().collect();
    hidden_top_rules.sort_by(|a, b| b.1.cmp(&a.1));
    hidden_top_rules.truncate(5);

    // Get current paranoia level (local-only, no network fetch)
    let cwd = std::env::current_dir().ok();
    let cwd_str = cwd.as_ref().and_then(|p| p.to_str());
    let policy = tirith_core::policy::Policy::discover_partial(cwd_str);
    let current_paranoia = policy.paranoia;

    Some(DetectionGapInfo {
        total_commands,
        blocked,
        warned,
        records_analyzed,
        records_with_raw,
        records_without_raw,
        total_findings,
        raw_total_findings: raw_total_findings_analyzed,
        hidden_findings,
        hidden_top_rules,
        current_paranoia,
    })
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
    /// Other `tirith` binaries found on PATH that shadow or conflict with this one.
    shadow_binaries: Vec<String>,
    /// Detection gap analysis from audit log data.
    #[serde(skip_serializing_if = "Option::is_none")]
    detection_gaps: Option<DetectionGapInfo>,
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

    let shadow_binaries = super::find_shadow_binaries();
    let detection_gaps = check_detection_gaps();

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
        shadow_binaries,
        detection_gaps,
    }
}

fn print_human(info: &DoctorInfo) {
    println!("tirith {}", info.version);
    println!("  binary:       {}", info.binary_path);
    if !info.shadow_binaries.is_empty() {
        println!();
        println!("  WARNING: other 'tirith' binaries found on PATH:");
        for shadow in &info.shadow_binaries {
            println!("    - {shadow}");
        }
        println!("  These may shadow this binary and cause unexpected behavior.");
        println!("  Check with: which -a tirith");
        println!();
    }
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

    // Detection gap analysis
    if let Some(ref gaps) = info.detection_gaps {
        println!();
        println!("Detection coverage (last 7 days)");
        println!(
            "  {} commands scanned, {} blocked, {} warned",
            gaps.total_commands, gaps.blocked, gaps.warned
        );
        println!(
            "  {} of {} records have full detection data{}",
            gaps.records_with_raw,
            gaps.total_commands,
            if gaps.records_without_raw > 0 {
                format!(" ({} legacy, pre-upgrade)", gaps.records_without_raw)
            } else {
                String::new()
            }
        );

        if gaps.hidden_findings == 0 && gaps.records_with_raw > 0 {
            println!(
                "  No hidden findings — detection coverage is complete at current paranoia level"
            );
        } else if gaps.hidden_findings == 0 && gaps.records_with_raw == 0 {
            println!(
                "  No raw detection data available (all records are pre-upgrade). Cannot assess hidden findings."
            );
        } else {
            let pct = if gaps.raw_total_findings > 0 {
                // raw_total_findings is scoped to analyzed records (those with raw_rule_ids)
                (gaps.hidden_findings as f64 / gaps.raw_total_findings as f64 * 100.0) as usize
            } else {
                0
            };
            println!(
                "  Hidden: {} findings detected but not surfaced ({}% of raw detections in {} analyzed records)",
                gaps.hidden_findings, pct, gaps.records_analyzed
            );
            if !gaps.hidden_top_rules.is_empty() {
                let top_str: Vec<String> = gaps
                    .hidden_top_rules
                    .iter()
                    .map(|(rule, count)| format!("{rule} ({count})"))
                    .collect();
                println!("  Top hidden: {}", top_str.join(", "));
            }
        }

        // Paranoia guidance text — mark the current level
        println!();
        println!("  Paranoia levels:");
        let levels: [(u8, &str, &str); 3] = [
            (1, "1-2", "Medium+ only — hides Low and Info findings"),
            (3, "3", "Low+ — shows low-severity security patterns"),
            (4, "4", "All — full detection visibility"),
        ];
        for (threshold, label, desc) in &levels {
            let marker = if (*threshold <= 2 && gaps.current_paranoia <= 2)
                || (*threshold > 2 && gaps.current_paranoia == *threshold)
            {
                " (current)"
            } else {
                ""
            };
            println!("    {label}{marker}: {desc}");
        }

        if gaps.hidden_findings > 0 {
            let next_level = match gaps.current_paranoia {
                1 | 2 => 3,
                3 => 4,
                _ => gaps.current_paranoia, // already max
            };
            println!();
            if next_level > gaps.current_paranoia {
                println!(
                    "  \u{2192} Set 'paranoia: {}' in .tirith/policy.yaml to surface these detections",
                    next_level
                );
            }
        }
    }

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
