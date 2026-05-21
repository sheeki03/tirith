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

fn confirm(prompt: &str, yes: bool) -> bool {
    crate::cli::confirm(prompt, yes)
}

fn run_fix(yes: bool) -> i32 {
    let mut fixed = 0;

    if !hooks_installed() {
        println!("Fix: Install shell hooks");
        if confirm("  Install hooks?", yes) {
            let rc = crate::cli::init::run(None);
            if rc == 0 {
                println!("  Hooks installed.");
                fixed += 1;
            } else {
                eprintln!("  Hook installation failed (exit code {rc}).");
            }
        }
    }

    if hooks_stale() {
        println!("Fix: Re-materialize stale hook assets");
        if confirm("  Re-materialize hooks?", yes) {
            // find_hook_dir() materializes as a side effect when needed.
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

    if policy_missing() {
        println!("Fix: Create starter policy");
        if confirm("  Create .tirith/policy.yaml?", yes) {
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

    #[cfg(unix)]
    {
        let tools = detect_ai_tools();
        if !tools.is_empty() {
            println!("Fix: Configure tirith for AI coding tools");
            for tool in &tools {
                if confirm(&format!("  Configure tirith for {}?", tool.name), yes) {
                    let rc = crate::cli::setup::run(
                        tool.name,
                        tool.configured_scope,
                        false,
                        false,
                        false,
                        false,
                        false,
                    );
                    if rc == 0 {
                        println!("  Configured {}.", tool.name);
                        fixed += 1;
                    } else {
                        eprintln!("  Failed to configure {}.", tool.name);
                    }
                }
            }
        }
    }

    if let Some(tdb) = gather_threat_db_info() {
        if !tdb.installed || tdb.stale || tdb.signature_valid == Some(false) || tdb.error.is_some()
        {
            let reason = if !tdb.installed {
                "not installed"
            } else if tdb.signature_valid == Some(false) {
                "invalid signature"
            } else if tdb.error.is_some() {
                "load error"
            } else {
                "stale"
            };
            println!("Fix: Download threat DB ({reason})");
            if confirm("  Download threat DB?", yes) {
                let force = tdb.signature_valid == Some(false) || tdb.error.is_some();
                let rc = crate::cli::threatdb_cmd::update(force, false);
                if rc == 0 {
                    println!("  Threat DB downloaded.");
                    fixed += 1;
                } else {
                    eprintln!("  Threat DB download failed.");
                }
            }
        }
    }

    if bash_safe_mode_active() {
        println!("Fix: Clear bash safe-mode flag");
        if confirm("  Clear safe-mode?", yes) {
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

/// Check whether any policy file can be discovered, using the same local
/// discovery the engine uses (TIRITH_POLICY_ROOT, walk-up to the `.git`
/// boundary, then the user config dir). Existence-based: no network fetch.
fn policy_missing() -> bool {
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    tirith_core::policy::discover_local_policy_path(cwd.as_deref()).is_none()
}

/// Build the de-duplicated list of policy paths `doctor` should display. The
/// first entry (if any) is the policy the engine would actually load. A second
/// entry can appear only for a present-but-shadowed user-config-dir policy — a
/// `TIRITH_POLICY_ROOT` policy, when present, has top resolution priority, so it
/// is always the active first entry and never a shadowed one.
fn collect_policy_paths(cwd: Option<&str>) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();

    // The active policy is the first entry; `paths` is empty here, so the dedup
    // guard the later push sites use is not needed.
    if let Some(active) = tirith_core::policy::discover_local_policy_path(cwd) {
        paths.push(active.display().to_string());
    }
    if let Some(config) = tirith_core::policy::config_dir() {
        for ext in &["policy.yaml", "policy.yml"] {
            let p = config.join(ext);
            if p.exists() {
                let s = p.display().to_string();
                if !paths.contains(&s) {
                    paths.push(s);
                }
                break;
            }
        }
    }
    if let Ok(root) = std::env::var("TIRITH_POLICY_ROOT") {
        let tirith_dir = PathBuf::from(&root).join(".tirith");
        for ext in &["policy.yaml", "policy.yml"] {
            let p = tirith_dir.join(ext);
            if p.exists() {
                let s = p.display().to_string();
                if !paths.contains(&s) {
                    paths.push(s);
                }
                break;
            }
        }
    }
    paths
}

/// One detected AI coding tool. `configured_scope` carries the scope at
/// which a tirith-managed file was found (so `--fix` can pass it through to
/// `setup::run`); `None` means we found a coarse "tool installed but tirith
/// not configured yet" signal and `--fix` should bootstrap with the tool's
/// default scope.
#[cfg(unix)]
#[derive(Debug, PartialEq, Eq)]
struct DetectedTool {
    name: &'static str,
    configured_scope: Option<&'static str>,
}

/// Detect installed AI coding tools by checking for their config directories.
#[cfg(unix)]
fn detect_ai_tools() -> Vec<DetectedTool> {
    let home = match home::home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    let cwd = std::env::current_dir().ok();
    detect_ai_tools_with(&home, cwd.as_deref())
}

/// Inner implementation parameterized on home and cwd for testability.
#[cfg(unix)]
fn detect_ai_tools_with(
    home: &std::path::Path,
    cwd: Option<&std::path::Path>,
) -> Vec<DetectedTool> {
    let mut tools = Vec::new();

    if home.join(".claude").exists() {
        tools.push(DetectedTool {
            name: "claude-code",
            configured_scope: None,
        });
    }
    if home.join(".cursor").exists() {
        tools.push(DetectedTool {
            name: "cursor",
            configured_scope: None,
        });
    }
    if home.join(".vscode").exists() {
        tools.push(DetectedTool {
            name: "vscode",
            configured_scope: None,
        });
    }
    if home.join(".codeium").exists() {
        tools.push(DetectedTool {
            name: "windsurf",
            configured_scope: None,
        });
    }

    // Copilot CLI: only push when our managed file is at the repo root, to
    // avoid false-positive matches on every GitHub repo.
    if tirith_core::policy::find_repo_root(None)
        .map(|r| r.join(".github/hooks/tirith-security.json").exists())
        .unwrap_or(false)
    {
        tools.push(DetectedTool {
            name: "copilot-cli",
            configured_scope: Some("project"),
        });
    }

    // Kiro: precedence-ordered, single winner.
    //   1. project configured
    //   2. user configured
    //   3. project bootstrap
    //   4. user bootstrap
    let project_kiro_dir = cwd.and_then(tirith_core::policy::find_workspace_kiro_dir);
    let project_managed = project_kiro_dir
        .as_ref()
        .map(|d| d.join(".kiro/agents/tirith-security.json").exists())
        .unwrap_or(false);
    let user_managed = home.join(".kiro/agents/tirith-security.json").exists();
    let user_kiro = home.join(".kiro").exists();

    if project_managed {
        tools.push(DetectedTool {
            name: "kiro",
            configured_scope: Some("project"),
        });
    } else if user_managed {
        tools.push(DetectedTool {
            name: "kiro",
            configured_scope: Some("user"),
        });
    } else if project_kiro_dir.is_some() || user_kiro {
        // Bootstrap: workspace `.kiro/` or `~/.kiro/` exists with no managed
        // file. Both bootstrap branches collapse into one push because they
        // both pass `configured_scope: None` to setup (which then defaults
        // to project scope). The project-vs-user precedence only matters for
        // the configured cases above.
        tools.push(DetectedTool {
            name: "kiro",
            configured_scope: None,
        });
    }

    tools
}

fn bash_safe_mode_active() -> bool {
    tirith_core::policy::state_dir()
        .map(|d| d.join("bash-safe-mode").exists())
        .unwrap_or(false)
}

/// Match the truthy values the bash hook accepts for `TIRITH_BASH_*` boolean
/// env vars: `1`, `true`, `yes`, `on` (case-insensitive).
fn env_is_truthy(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// True when a persisted bash safe-mode flag exists but `TIRITH_BASH_MODE=enter`
/// overrides it, so the hook re-attempts enter mode on every new shell despite
/// the recorded prior failure. Exact, case-sensitive match — mirrors the hook's
/// `[[ "$_TIRITH_BASH_MODE" == "enter" ]]`.
fn safe_mode_overridden_by_env(bash_safe_mode: bool, requested_mode: Option<&str>) -> bool {
    bash_safe_mode && requested_mode == Some("enter")
}

/// Create a minimal starter policy at .tirith/policy.yaml in the repo root,
/// or fall back to the user config dir.
fn create_default_policy() -> Result<PathBuf, String> {
    let content = "\
# tirith policy — see https://github.com/sheeki03/tirith for options
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
            if path.exists() {
                return Err(format!(
                    "policy already exists at {} — not overwriting",
                    path.display()
                ));
            }
            return std::fs::write(&path, content)
                .map(|()| path)
                .map_err(|e| e.to_string());
        }
    }

    // Fall back to user config dir
    if let Some(config) = tirith_core::policy::config_dir() {
        if std::fs::create_dir_all(&config).is_ok() {
            let path = config.join("policy.yaml");
            if path.exists() {
                return Err(format!(
                    "policy already exists at {} — not overwriting",
                    path.display()
                ));
            }
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
    // Scoped only to records with raw data — legacy pre-upgrade rows are excluded.
    let mut raw_total_findings_analyzed = 0usize;
    let mut hidden_findings = 0usize;
    let mut hidden_rule_counts: HashMap<String, usize> = HashMap::new();

    for record in &verdicts {
        total_findings += record.rule_ids.len();

        match record.raw_rule_ids {
            Some(ref raw_ids) => {
                records_with_raw += 1;
                raw_total_findings_analyzed += raw_ids.len();

                // Multiset diff: raw_rule_ids minus rule_ids — an unmatched
                // raw entry means paranoia filtering suppressed it.
                let mut effective_counts: HashMap<&str, u32> = HashMap::new();
                for rid in &record.rule_ids {
                    *effective_counts.entry(rid.as_str()).or_insert(0) += 1;
                }
                for raw_rid in raw_ids {
                    match effective_counts.get_mut(raw_rid.as_str()) {
                        Some(count) if *count > 0 => {
                            *count -= 1;
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
    hidden_top_rules.sort_by_key(|r| std::cmp::Reverse(r.1));
    hidden_top_rules.truncate(5);

    // discover_partial is local-only so doctor never triggers a network fetch.
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
    /// Requested bash mode from `TIRITH_BASH_MODE` env var (empty = default).
    #[serde(skip_serializing_if = "Option::is_none")]
    bash_requested_mode: Option<String>,
    /// Requested preexec enforcement from `TIRITH_BASH_PREEXEC_ENFORCE` env var.
    #[serde(skip_serializing_if = "Option::is_none")]
    bash_requested_enforce: Option<String>,
    /// Require-enter strict mode from `TIRITH_BASH_REQUIRE_ENTER` env var.
    #[serde(skip_serializing_if = "Option::is_none")]
    bash_requested_require_enter: Option<String>,
    /// Effective bash mode exported by the hook (`TIRITH_BASH_EFFECTIVE_MODE`).
    /// Absent means the hook was not sourced in this process.
    #[serde(skip_serializing_if = "Option::is_none")]
    bash_effective_mode: Option<String>,
    /// Effective protection exported by the hook (`TIRITH_BASH_EFFECTIVE_PROTECTION`).
    #[serde(skip_serializing_if = "Option::is_none")]
    bash_effective_protection: Option<String>,
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
    /// Threat intelligence database status.
    #[serde(skip_serializing_if = "Option::is_none")]
    threat_db: Option<ThreatDbDoctorInfo>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ThreatDbDoctorInfo {
    installed: bool,
    path: Option<String>,
    age_hours: Option<f64>,
    total_entries: Option<u32>,
    signature_valid: Option<bool>,
    stale: bool,
    error: Option<String>,
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
            // Hook dir inside data_dir means it was materialized (vs system/homebrew).
            if let Some(data) = tirith_core::policy::data_dir() {
                d.starts_with(&data)
            } else {
                false
            }
        })
        .unwrap_or(false);

    let (shell_profile, hook_configured) = check_shell_profile(&detected_shell);

    let bash_safe_mode = tirith_core::policy::state_dir()
        .map(|d| d.join("bash-safe-mode").exists())
        .unwrap_or(false);

    // Raw env vars the user may have set (requested state).
    let bash_requested_mode = std::env::var("TIRITH_BASH_MODE")
        .ok()
        .filter(|s| !s.is_empty());
    let bash_requested_enforce = std::env::var("TIRITH_BASH_PREEXEC_ENFORCE")
        .ok()
        .filter(|s| !s.is_empty());
    let bash_requested_require_enter = std::env::var("TIRITH_BASH_REQUIRE_ENTER")
        .ok()
        .filter(|s| !s.is_empty());

    // Live state vars exported by the hook (effective state). Absence means the
    // bash hook was not sourced in this process.
    let bash_effective_mode = std::env::var("TIRITH_BASH_EFFECTIVE_MODE")
        .ok()
        .filter(|s| !s.is_empty());
    let bash_effective_protection = std::env::var("TIRITH_BASH_EFFECTIVE_PROTECTION")
        .ok()
        .filter(|s| !s.is_empty());

    let data_dir = tirith_core::policy::data_dir();
    let log_path = data_dir.as_ref().map(|d| d.join("log.jsonl"));
    let last_trigger_path = data_dir.as_ref().map(|d| d.join("last_trigger.json"));

    let policy_cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    let policy_paths = collect_policy_paths(policy_cwd.as_deref());
    let policy_root_env = std::env::var("TIRITH_POLICY_ROOT").ok();

    let shadow_binaries = super::find_shadow_binaries();
    let detection_gaps = check_detection_gaps();
    let threat_db = gather_threat_db_info();

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
        bash_requested_mode,
        bash_requested_enforce,
        bash_requested_require_enter,
        bash_effective_mode,
        bash_effective_protection,
        policy_paths,
        policy_root_env,
        data_dir: data_dir.map(|d| d.display().to_string()),
        log_path: log_path.map(|p| p.display().to_string()),
        last_trigger_path: last_trigger_path.map(|p| p.display().to_string()),
        cloaking_available: cfg!(unix),
        webhooks_available: cfg!(unix),
        shadow_binaries,
        detection_gaps,
        threat_db,
    }
}

fn gather_threat_db_info() -> Option<ThreatDbDoctorInfo> {
    use tirith_core::threatdb::ThreatDb;

    let db_path = ThreatDb::default_path()?;
    if !db_path.exists() {
        return Some(ThreatDbDoctorInfo {
            installed: false,
            path: Some(db_path.display().to_string()),
            age_hours: None,
            total_entries: None,
            signature_valid: None,
            stale: true,
            error: None,
        });
    }

    match ThreatDb::load_from_path(&db_path, 0) {
        Ok(db) => {
            let sig_valid = db.verify_signature().is_ok();
            let stats = db.stats();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let age_secs = now.saturating_sub(stats.build_timestamp);
            let age_hours = age_secs as f64 / 3600.0;
            let total = stats.package_count
                + stats.hostname_count
                + stats.ip_count
                + stats.typosquat_count
                + stats.popular_count;

            let policy = tirith_core::policy::Policy::discover(None);
            let stale_hours = policy.threat_intel.auto_update_hours;
            let is_stale = if stale_hours == 0 {
                false
            } else {
                age_hours > (stale_hours as f64 * 2.0)
            };

            Some(ThreatDbDoctorInfo {
                installed: true,
                path: Some(db_path.display().to_string()),
                age_hours: Some(age_hours),
                total_entries: Some(total),
                signature_valid: Some(sig_valid),
                stale: is_stale,
                error: None,
            })
        }
        Err(e) => Some(ThreatDbDoctorInfo {
            installed: true,
            path: Some(db_path.display().to_string()),
            age_hours: None,
            total_entries: None,
            signature_valid: None,
            stale: true,
            error: Some(format!("{e}")),
        }),
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
        println!("  Check with: {}", super::tirith_path_lookup_command());
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
    // Bash-only block: show requested vs effective state so mid-session
    // degrades and env misconfigurations are legible. Also shown whenever any
    // bash-related env var is present, so users who source the hook from a
    // non-bash parent (e.g. a zsh login shell that spawns bash) still get the
    // right diagnostics.
    let has_any_bash_env = info.bash_requested_mode.is_some()
        || info.bash_requested_enforce.is_some()
        || info.bash_requested_require_enter.is_some()
        || info.bash_effective_mode.is_some()
        || info.bash_effective_protection.is_some();
    if info.detected_shell == "bash" || has_any_bash_env {
        let requested_mode = info.bash_requested_mode.as_deref().unwrap_or("(default)");
        let requested_enforce = if info
            .bash_requested_enforce
            .as_deref()
            .map(env_is_truthy)
            .unwrap_or(false)
        {
            "on"
        } else {
            "off"
        };
        let require_enter = if info
            .bash_requested_require_enter
            .as_deref()
            .map(env_is_truthy)
            .unwrap_or(false)
        {
            "on"
        } else {
            "off"
        };
        println!("  requested mode:       {requested_mode}");
        println!("  requested enforce:    {requested_enforce}");
        println!("  require-enter:        {require_enter}");

        match (
            info.bash_effective_mode.as_deref(),
            info.bash_effective_protection.as_deref(),
        ) {
            (Some(mode), Some(protection)) => {
                println!("  bash mode:            {mode}");
                println!("  effective protection: {protection}");
            }
            _ => {
                println!("  bash hook:            not loaded in this process");
            }
        }

        if info.bash_safe_mode {
            println!("  safe mode:            on (previous enter-mode failure)");
            println!("                        Reset: tirith doctor --reset-bash-safe-mode");
        } else {
            println!("  safe mode:            off");
        }
        if safe_mode_overridden_by_env(info.bash_safe_mode, info.bash_requested_mode.as_deref()) {
            println!(
                "  warning:              TIRITH_BASH_MODE=enter overrides the safe-mode flag —"
            );
            println!(
                "                        enter mode is re-attempted (and may keep failing) on"
            );
            println!(
                "                        every new shell. Unset TIRITH_BASH_MODE to honor the"
            );
            println!("                        recorded failure and stay in preexec.");
        }
    } else if info.bash_safe_mode {
        // Non-bash shell but safe-mode flag exists: still surface it.
        println!("  bash safe mode:       on (Reset: tirith doctor --reset-bash-safe-mode)");
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

    if let Some(ref tdb) = info.threat_db {
        if !tdb.installed {
            println!("  threat DB:    not installed — run 'tirith threat-db update'");
        } else if let Some(ref err) = tdb.error {
            println!("  threat DB:    ERROR: {err}");
            println!("                re-download with 'tirith threat-db update --force'");
        } else if tdb.signature_valid == Some(false) {
            println!(
                "  threat DB:    INVALID SIGNATURE — re-download with 'tirith threat-db update --force'"
            );
        } else if tdb.stale {
            let age_str = match tdb.age_hours {
                Some(h) if h < 48.0 => format!("{:.0}h old", h),
                Some(h) => format!("{:.0}d old", h / 24.0),
                None => "unknown age".to_string(),
            };
            println!("  threat DB:    STALE ({age_str}) — run 'tirith threat-db update'");
        } else {
            let path = tdb.path.as_deref().unwrap_or("unknown");
            let age_str = match tdb.age_hours {
                Some(h) if h < 1.0 => format!("{:.0}m old", h * 60.0),
                Some(h) if h < 48.0 => format!("{:.0}h old", h),
                Some(h) => format!("{:.0}d old", h / 24.0),
                None => "unknown age".to_string(),
            };
            let total = tdb.total_entries.unwrap_or(0);
            let sig = if tdb.signature_valid == Some(true) {
                "signature ok"
            } else {
                "signature unknown"
            };
            println!("  threat DB:    {path} ({age_str}, {total} entries, {sig})");
        }
    } else {
        println!("  threat DB:    not available");
    }

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
                // Scoped to analyzed records (those with raw_rule_ids), not the full set.
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
                _ => gaps.current_paranoia,
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

    use tirith_core::license::KeyFormatStatus;
    match tirith_core::license::key_format_status() {
        KeyFormatStatus::LegacyUnsigned => {
            println!(
                "  license key:  WARNING: Using unsigned legacy license key. Official v0.3.0+ releases require signed tokens, so this key is ignored for tier verification."
            );
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

    // Scan ALL candidates — a profile can exist without containing the hook,
    // so the first existing file is not necessarily the configured one.
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

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use crate::cli::test_harness::{with_fake_env, EnvGuard};

    fn first_kiro(tools: &[DetectedTool]) -> Option<&DetectedTool> {
        tools.iter().find(|t| t.name == "kiro")
    }

    fn count_named(tools: &[DetectedTool], name: &str) -> usize {
        tools.iter().filter(|t| t.name == name).count()
    }

    #[test]
    fn detect_ai_tools_passes_kiro_user_scope() {
        with_fake_env(true, |home, cwd| {
            let cwd = cwd.expect("cwd set");
            std::fs::create_dir_all(home.join(".kiro/agents")).unwrap();
            std::fs::write(home.join(".kiro/agents/tirith-security.json"), "{}").unwrap();

            let tools = detect_ai_tools_with(home, Some(cwd));
            let k = first_kiro(&tools).expect("kiro detected");
            assert_eq!(k.configured_scope, Some("user"));
            assert_eq!(count_named(&tools, "kiro"), 1, "exactly one kiro entry");
        });
    }

    #[test]
    fn detect_ai_tools_passes_kiro_project_scope() {
        with_fake_env(true, |home, cwd| {
            let cwd = cwd.expect("cwd set");
            std::fs::create_dir_all(cwd.join(".kiro/agents")).unwrap();
            std::fs::write(cwd.join(".kiro/agents/tirith-security.json"), "{}").unwrap();

            let tools = detect_ai_tools_with(home, Some(cwd));
            let k = first_kiro(&tools).expect("kiro detected");
            assert_eq!(k.configured_scope, Some("project"));
            assert_eq!(count_named(&tools, "kiro"), 1);
        });
    }

    #[test]
    fn detect_ai_tools_passes_kiro_project_scope_from_subdir() {
        with_fake_env(true, |home, cwd| {
            let cwd = cwd.expect("cwd set");
            std::fs::create_dir_all(cwd.join(".kiro/agents")).unwrap();
            std::fs::write(cwd.join(".kiro/agents/tirith-security.json"), "{}").unwrap();
            let subdir = cwd.join("sub").join("dir");
            std::fs::create_dir_all(&subdir).unwrap();

            let tools = detect_ai_tools_with(home, Some(&subdir));
            let k = first_kiro(&tools).expect("kiro detected from subdir");
            assert_eq!(k.configured_scope, Some("project"));
        });
    }

    #[test]
    fn detect_ai_tools_kiro_user_bootstrap_only() {
        with_fake_env(true, |home, cwd| {
            let cwd = cwd.expect("cwd set");
            std::fs::create_dir_all(home.join(".kiro")).unwrap();
            let tools = detect_ai_tools_with(home, Some(cwd));
            let k = first_kiro(&tools).expect("kiro bootstrap");
            assert_eq!(k.configured_scope, None);
            assert_eq!(count_named(&tools, "kiro"), 1);
        });
    }

    #[test]
    fn detect_ai_tools_kiro_project_bootstrap_from_subdir() {
        with_fake_env(true, |home, cwd| {
            let cwd = cwd.expect("cwd set");
            // Workspace .kiro/ but no managed file — bootstrap path.
            std::fs::create_dir_all(cwd.join(".kiro")).unwrap();
            let subdir = cwd.join("sub").join("dir");
            std::fs::create_dir_all(&subdir).unwrap();

            let tools = detect_ai_tools_with(home, Some(&subdir));
            let k = first_kiro(&tools).expect("kiro project-bootstrap");
            assert_eq!(k.configured_scope, None);
            assert_eq!(count_named(&tools, "kiro"), 1);
        });
    }

    #[test]
    fn detect_ai_tools_kiro_project_bootstrap_beats_user_bootstrap() {
        with_fake_env(true, |home, cwd| {
            let cwd = cwd.expect("cwd set");
            std::fs::create_dir_all(home.join(".kiro")).unwrap();
            std::fs::create_dir_all(cwd.join(".kiro")).unwrap();
            // Neither has a managed file
            let tools = detect_ai_tools_with(home, Some(cwd));
            let k = first_kiro(&tools).expect("kiro detected");
            assert_eq!(
                k.configured_scope, None,
                "bootstrap (no managed file) is the right verdict"
            );
            assert_eq!(
                count_named(&tools, "kiro"),
                1,
                "exactly one entry, not duplicate project+user bootstrap"
            );
        });
    }

    #[test]
    fn detect_ai_tools_kiro_prefers_project_over_user() {
        with_fake_env(true, |home, cwd| {
            let cwd = cwd.expect("cwd set");
            std::fs::create_dir_all(home.join(".kiro/agents")).unwrap();
            std::fs::write(home.join(".kiro/agents/tirith-security.json"), "{}").unwrap();
            std::fs::create_dir_all(cwd.join(".kiro/agents")).unwrap();
            std::fs::write(cwd.join(".kiro/agents/tirith-security.json"), "{}").unwrap();

            let tools = detect_ai_tools_with(home, Some(cwd));
            let k = first_kiro(&tools).expect("kiro detected");
            assert_eq!(k.configured_scope, Some("project"));
            assert_eq!(count_named(&tools, "kiro"), 1);
        });
    }

    /// Regression for the fix in policy.rs::find_workspace_kiro_dir: when cwd
    /// is *under* $HOME and only `~/.kiro/agents/tirith-security.json` exists
    /// (no project workspace), detection must report user-scope. Without the
    /// home-exclusion, find_workspace_kiro_dir would walk up to $HOME, find
    /// `~/.kiro/`, and incorrectly classify it as a project workspace.
    #[test]
    fn detect_ai_tools_does_not_classify_home_kiro_as_project() {
        with_fake_env(true, |home, _cwd| {
            // User-scope managed file at ~/.kiro/agents/tirith-security.json.
            std::fs::create_dir_all(home.join(".kiro/agents")).unwrap();
            std::fs::write(home.join(".kiro/agents/tirith-security.json"), "{}").unwrap();

            // Cwd is a subdirectory *inside* HOME — no project .kiro/ anywhere.
            let project = home.join("projects").join("myrepo");
            std::fs::create_dir_all(&project).unwrap();

            let tools = detect_ai_tools_with(home, Some(&project));
            let k = first_kiro(&tools).expect("kiro detected");
            assert_eq!(
                k.configured_scope,
                Some("user"),
                "user-scope agent must NOT be misclassified as project just because cwd is under $HOME"
            );
            assert_eq!(count_named(&tools, "kiro"), 1);
        });
    }

    /// Regression: even WITHOUT a managed file, a cwd under $HOME must not
    /// pick up `~/.kiro/` as a project-bootstrap signal — that should fire
    /// the user-bootstrap branch, not project-bootstrap.
    #[test]
    fn detect_ai_tools_home_kiro_only_is_user_bootstrap_not_project() {
        with_fake_env(true, |home, _cwd| {
            // Only ~/.kiro/ exists, no managed file.
            std::fs::create_dir_all(home.join(".kiro")).unwrap();

            // Cwd inside $HOME with no project .kiro/.
            let project = home.join("projects").join("myrepo");
            std::fs::create_dir_all(&project).unwrap();

            let tools = detect_ai_tools_with(home, Some(&project));
            let k = first_kiro(&tools).expect("kiro bootstrap");
            assert_eq!(
                k.configured_scope, None,
                "bootstrap entry, not configured project"
            );
            // Sanity: ensure we collapsed to one entry (no duplicate project+user).
            assert_eq!(count_named(&tools, "kiro"), 1);
        });
    }

    #[test]
    fn detect_ai_tools_kiro_prefers_user_over_bootstrap() {
        with_fake_env(true, |home, cwd| {
            let cwd = cwd.expect("cwd set");
            std::fs::create_dir_all(home.join(".kiro/agents")).unwrap();
            std::fs::write(home.join(".kiro/agents/tirith-security.json"), "{}").unwrap();
            // No project workspace
            let tools = detect_ai_tools_with(home, Some(cwd));
            let k = first_kiro(&tools).expect("kiro detected");
            assert_eq!(k.configured_scope, Some("user"));
            assert_eq!(count_named(&tools, "kiro"), 1);
        });
    }

    // --- collect_policy_paths (#112) ---------------------------------------
    //
    // Every test isolates BOTH `TIRITH_POLICY_ROOT` and `XDG_CONFIG_HOME`:
    // `with_fake_env` fakes `$HOME` but not those, and a machine-level
    // `XDG_CONFIG_HOME`/`TIRITH_POLICY_ROOT` would otherwise leak into the
    // assertions. cwd is passed explicitly so process cwd is never relied on.

    #[test]
    fn collect_policy_paths_finds_repo_root_policy() {
        with_fake_env(true, |_home, cwd| {
            let cwd = cwd.expect("cwd set");
            let _root = EnvGuard::remove("TIRITH_POLICY_ROOT");
            let _xdg = EnvGuard::remove("XDG_CONFIG_HOME");
            std::fs::create_dir_all(cwd.join(".git")).unwrap();
            std::fs::create_dir_all(cwd.join(".tirith")).unwrap();
            std::fs::write(cwd.join(".tirith/policy.yaml"), "fail_mode: open\n").unwrap();

            let expected = cwd.join(".tirith/policy.yaml").display().to_string();
            assert_eq!(
                collect_policy_paths(cwd.to_str()),
                vec![expected],
                "doctor must list the repo-root policy",
            );
        });
    }

    #[test]
    fn collect_policy_paths_walks_up_from_subdir() {
        with_fake_env(true, |_home, cwd| {
            let cwd = cwd.expect("cwd set");
            let _root = EnvGuard::remove("TIRITH_POLICY_ROOT");
            let _xdg = EnvGuard::remove("XDG_CONFIG_HOME");
            std::fs::create_dir_all(cwd.join(".git")).unwrap();
            std::fs::create_dir_all(cwd.join(".tirith")).unwrap();
            std::fs::write(cwd.join(".tirith/policy.yaml"), "fail_mode: open\n").unwrap();
            let subdir = cwd.join("src/inner");
            std::fs::create_dir_all(&subdir).unwrap();

            let expected = cwd.join(".tirith/policy.yaml").display().to_string();
            assert_eq!(
                collect_policy_paths(subdir.to_str()),
                vec![expected],
                "walk-up from a subdir must surface the repo-root policy",
            );
        });
    }

    #[test]
    fn collect_policy_paths_finds_cwd_policy_without_git() {
        with_fake_env(true, |_home, cwd| {
            let cwd = cwd.expect("cwd set");
            let _root = EnvGuard::remove("TIRITH_POLICY_ROOT");
            let _xdg = EnvGuard::remove("XDG_CONFIG_HOME");
            // `tirith policy init` run outside a git repo (e.g. in $HOME) writes
            // cwd/.tirith/policy.yaml with no .git boundary — the literal #112 repro.
            std::fs::create_dir_all(cwd.join(".tirith")).unwrap();
            std::fs::write(cwd.join(".tirith/policy.yaml"), "fail_mode: open\n").unwrap();

            let expected = cwd.join(".tirith/policy.yaml").display().to_string();
            assert_eq!(
                collect_policy_paths(cwd.to_str()),
                vec![expected],
                "a cwd-local policy with no .git must still be listed (#112 repro)",
            );
        });
    }

    #[test]
    fn collect_policy_paths_finds_user_config_policy_and_dedups() {
        with_fake_env(true, |home, cwd| {
            let cwd = cwd.expect("cwd set");
            let _root = EnvGuard::remove("TIRITH_POLICY_ROOT");
            let _xdg = EnvGuard::remove("XDG_CONFIG_HOME");
            // Only the user config dir has a policy; cwd has none.
            let config = home.join(".config/tirith");
            std::fs::create_dir_all(&config).unwrap();
            std::fs::write(config.join("policy.yaml"), "fail_mode: open\n").unwrap();

            let expected = config.join("policy.yaml").display().to_string();
            let paths = collect_policy_paths(cwd.to_str());
            assert_eq!(
                paths.len(),
                1,
                "active policy == user config policy must dedup to one entry: {paths:?}",
            );
            assert_eq!(paths, vec![expected]);
        });
    }

    #[test]
    fn collect_policy_paths_empty_when_no_policy() {
        with_fake_env(true, |_home, cwd| {
            let cwd = cwd.expect("cwd set");
            let _root = EnvGuard::remove("TIRITH_POLICY_ROOT");
            let _xdg = EnvGuard::remove("XDG_CONFIG_HOME");
            // Empty cwd tempdir, no .git, fake $HOME has no config policy.
            assert!(
                collect_policy_paths(cwd.to_str()).is_empty(),
                "no policy anywhere must yield an empty list",
            );
        });
    }

    #[test]
    fn safe_mode_overridden_only_when_flag_and_enter() {
        assert!(safe_mode_overridden_by_env(true, Some("enter")));
        assert!(!safe_mode_overridden_by_env(false, Some("enter"))); // no flag
        assert!(!safe_mode_overridden_by_env(true, Some("preexec"))); // not enter
        assert!(!safe_mode_overridden_by_env(true, None)); // env unset
        assert!(!safe_mode_overridden_by_env(true, Some("Enter"))); // case-sensitive
    }
}
