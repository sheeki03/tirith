use std::collections::HashMap;
use std::path::PathBuf;

#[allow(clippy::too_many_arguments)]
pub fn run(
    json: bool,
    reset_bash_safe_mode: bool,
    fix: bool,
    yes: bool,
    simulate_enter: bool,
    compat: bool,
    bundle: bool,
) -> i32 {
    if reset_bash_safe_mode {
        return reset_safe_mode();
    }

    if simulate_enter {
        return run_simulate_enter();
    }

    if fix {
        return run_fix(yes);
    }

    if compat {
        return run_compat(json);
    }

    if bundle {
        return run_bundle(json);
    }

    // A plain `tirith doctor` refreshes the bash enter-mode capability cache as
    // a side effect: the PTY self-test is cheap, timeout-bound, and keeps the
    // cache the hook reads at startup current. Skipped in JSON mode so machine
    // consumers get a fast, side-effect-free report.
    #[cfg(unix)]
    if !json && crate::cli::init::detect_shell() == "bash" {
        let _ = crate::cli::bash_capability::run_and_cache();
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
    /// Live protection status exported by the hook as `TIRITH_STATUS`
    /// (`blocks` / `warn-only` / `degraded` / `off`). `degraded` specifically
    /// means protection was downgraded from a stronger level during this
    /// session. Absent means no tirith hook was sourced in this process.
    #[serde(skip_serializing_if = "Option::is_none")]
    tirith_status: Option<String>,
    /// Cached bash enter-mode delivery capability verdict (`works` / `broken` /
    /// `inconclusive`), as recorded by the last self-test. Absent when no
    /// capability cache has been written yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    bash_enter_capability: Option<String>,
    /// Whether the cached capability verdict is for the running bash — a
    /// `false` here means the cache is stale (a different bash) and the hook
    /// will ignore it.
    #[serde(skip_serializing_if = "Option::is_none")]
    bash_enter_capability_fresh: Option<bool>,
    /// Human-readable reason recorded with the cached capability verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    bash_enter_capability_reason: Option<String>,
    /// The tirith version that wrote the cached capability verdict (diagnostic
    /// only — not part of freshness; see `cli::bash_capability`).
    #[serde(skip_serializing_if = "Option::is_none")]
    bash_enter_capability_tirith_version: Option<String>,
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

    // `TIRITH_STATUS` is the cross-shell live protection indicator exported by
    // every tirith hook (bash, zsh, fish, PowerShell, nushell). Absence means
    // no tirith hook ran in the process that invoked `doctor` — typically a
    // non-interactive subshell.
    let tirith_status = std::env::var("TIRITH_STATUS")
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

    // Cached bash enter-mode delivery verdict (issue #111). Read-only here —
    // the cache is written by the self-test in `--simulate-enter` and by a
    // plain `tirith doctor` run; this just surfaces it.
    let (
        bash_enter_capability,
        bash_enter_capability_fresh,
        bash_enter_capability_reason,
        bash_enter_capability_tirith_version,
    ) = {
        #[cfg(unix)]
        {
            match crate::cli::bash_capability::read_cache() {
                Some(decision) => {
                    let token = match decision.capability {
                        crate::cli::bash_capability::EnterCapability::Works => "works",
                        crate::cli::bash_capability::EnterCapability::Broken => "broken",
                        crate::cli::bash_capability::EnterCapability::Inconclusive => {
                            "inconclusive"
                        }
                    };
                    let fresh = crate::cli::bash_capability::decision_is_fresh(&decision);
                    let reason = if decision.reason.is_empty() {
                        None
                    } else {
                        Some(decision.reason.clone())
                    };
                    let writer = if decision.tirith_version.is_empty() {
                        None
                    } else {
                        Some(decision.tirith_version.clone())
                    };
                    (Some(token.to_string()), Some(fresh), reason, writer)
                }
                None => (None, None, None, None),
            }
        }
        #[cfg(not(unix))]
        {
            (None, None, None, None)
        }
    };

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
        tirith_status,
        bash_enter_capability,
        bash_enter_capability_fresh,
        bash_enter_capability_reason,
        bash_enter_capability_tirith_version,
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

// --- Compatibility report (`tirith doctor --compat`) -----------------------
//
// A focused, static shell/terminal compatibility view. It reuses the existing
// `gather_info()` machinery rather than re-deriving install state, and adds
// best-effort detection of co-installed shell tools that historically interact
// with shell hooks. It introspects NOTHING about the parent shell's live
// state — a child process cannot — it only consumes what the hook exports.

/// One co-installed shell tool that historically interacts with shell hooks.
/// `on_path` and `in_profile` are independent best-effort signals; presence is
/// reported honestly without claiming a definite conflict.
#[derive(Debug, Clone, serde::Serialize)]
struct ShellToolPresence {
    name: &'static str,
    /// The tool's binary was found on `PATH`.
    on_path: bool,
    /// The tool's name appeared in the detected shell's profile file(s).
    in_profile: bool,
    /// Why this tool can interact with shell hooks (advisory, not a verdict).
    note: &'static str,
}

/// Shell tools known to install their own preexec/precmd/keymap integrations,
/// which can interleave with tirith's hook. `(binary, note)`.
const KNOWN_SHELL_TOOLS: &[(&str, &str)] = &[
    (
        "atuin",
        "rebinds Enter / Up and installs preexec hooks (history)",
    ),
    ("starship", "installs precmd/preexec prompt hooks"),
    ("fzf", "installs key bindings and a completion widget"),
    ("zoxide", "installs a chpwd/precmd hook (directory jumping)"),
    ("direnv", "installs a precmd/chpwd hook (per-dir env)"),
    ("mise", "installs a precmd/chpwd hook (runtime/env manager)"),
    (
        "asdf",
        "sources shims and shell functions (version manager)",
    ),
];

/// True when `binary` resolves on `PATH` via the shell's own lookup.
fn tool_on_path(binary: &str) -> bool {
    let lookup = {
        #[cfg(unix)]
        {
            std::process::Command::new("sh")
                .args(["-c", &format!("command -v {binary} >/dev/null 2>&1")])
                .status()
        }
        #[cfg(not(unix))]
        {
            std::process::Command::new("where.exe")
                .arg(binary)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
        }
    };
    lookup.map(|s| s.success()).unwrap_or(false)
}

/// True when `tool` is mentioned in any existing profile file for `shell`.
/// Best-effort: a missing or unreadable profile simply yields `false`.
fn tool_in_profile(tool: &str, profile: Option<&std::path::Path>) -> bool {
    let profile = match profile {
        Some(p) => p,
        None => return false,
    };
    match std::fs::read_to_string(profile) {
        Ok(contents) => contents.contains(tool),
        Err(_) => false,
    }
}

/// Detect co-installed shell tools that interact with hooks. Only tools with
/// at least one positive signal (on PATH or in the profile) are returned.
fn detect_shell_tool_conflicts(profile: Option<&std::path::Path>) -> Vec<ShellToolPresence> {
    KNOWN_SHELL_TOOLS
        .iter()
        .filter_map(|(name, note)| {
            let on_path = tool_on_path(name);
            let in_profile = tool_in_profile(name, profile);
            if on_path || in_profile {
                Some(ShellToolPresence {
                    name,
                    on_path,
                    in_profile,
                    note,
                })
            } else {
                None
            }
        })
        .collect()
}

/// Machine-readable compatibility report for `tirith doctor --compat --format json`.
#[derive(serde::Serialize)]
struct CompatReport {
    version: String,
    binary_path: String,
    detected_shell: String,
    interactive: bool,
    /// Requested bash mode (`TIRITH_BASH_MODE`); absent = default.
    #[serde(skip_serializing_if = "Option::is_none")]
    bash_requested_mode: Option<String>,
    /// Effective bash mode exported by the hook; absent = hook not sourced here.
    #[serde(skip_serializing_if = "Option::is_none")]
    bash_effective_mode: Option<String>,
    /// Effective protection exported by the hook.
    #[serde(skip_serializing_if = "Option::is_none")]
    bash_effective_protection: Option<String>,
    /// Live cross-shell protection status exported as `TIRITH_STATUS`
    /// (`blocks` / `warn-only` / `degraded` / `off`).
    #[serde(skip_serializing_if = "Option::is_none")]
    tirith_status: Option<String>,
    /// Cached bash enter-mode delivery capability verdict (issue #111).
    #[serde(skip_serializing_if = "Option::is_none")]
    bash_enter_capability: Option<String>,
    /// Whether the cached enter-capability verdict is for the running bash.
    #[serde(skip_serializing_if = "Option::is_none")]
    bash_enter_capability_fresh: Option<bool>,
    bash_safe_mode: bool,
    hook_dir: Option<String>,
    hooks_materialized: bool,
    /// Materialized hook assets exist but are a stale version.
    hooks_stale: bool,
    shell_profile: Option<String>,
    hook_configured: bool,
    /// Other `tirith` binaries on PATH that may shadow this one.
    shadow_binaries: Vec<String>,
    policy_paths: Vec<String>,
    /// Threat-DB status (reused verbatim from the standard doctor report).
    #[serde(skip_serializing_if = "Option::is_none")]
    threat_db: Option<ThreatDbDoctorInfo>,
    /// Co-installed shell tools that historically interact with hooks.
    shell_tools: Vec<ShellToolPresence>,
}

/// Build the compat report from the shared `gather_info()` state plus
/// shell-tool conflict detection.
fn gather_compat() -> CompatReport {
    let info = gather_info();
    let profile = info.shell_profile.as_ref().map(std::path::PathBuf::from);
    let shell_tools = detect_shell_tool_conflicts(profile.as_deref());

    CompatReport {
        version: info.version,
        binary_path: info.binary_path,
        detected_shell: info.detected_shell,
        interactive: info.interactive,
        bash_requested_mode: info.bash_requested_mode,
        bash_effective_mode: info.bash_effective_mode,
        bash_effective_protection: info.bash_effective_protection,
        tirith_status: info.tirith_status,
        bash_enter_capability: info.bash_enter_capability,
        bash_enter_capability_fresh: info.bash_enter_capability_fresh,
        bash_safe_mode: info.bash_safe_mode,
        hook_dir: info.hook_dir,
        hooks_materialized: info.hooks_materialized,
        hooks_stale: hooks_stale(),
        shell_profile: info.shell_profile,
        hook_configured: info.hook_configured,
        shadow_binaries: info.shadow_binaries,
        policy_paths: info.policy_paths,
        threat_db: info.threat_db,
        shell_tools,
    }
}

/// `tirith doctor --compat`: print a focused shell/terminal compatibility
/// report. Human-readable by default; `--format json` emits `CompatReport`.
fn run_compat(json: bool) -> i32 {
    let report = gather_compat();
    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("tirith: JSON serialization failed: {e}");
                return 1;
            }
        }
    } else {
        print_compat_human(&report);
    }
    0
}

// --- Diagnostic bundle (`tirith doctor --bundle`) --------------------------
//
// Roadmap item #25. Produces a single redacted text file a user can attach to
// a bug report: doctor info, tirith + hook versions, shell / mode / effective
// protection, hook-chain state, policy discovery, threat-DB status, and a
// curated slice of the environment. `--redacted-report` and `--shell-trace`
// are aliases for the same output.
//
// Redaction is the load-bearing safety property and is deliberately layered:
//
//   1. The environment section emits only a CURATED ALLOWLIST of variable
//      names — never the whole environment — so an unrelated `AWS_SECRET…`
//      or `OPENAI_API_KEY` is never even a candidate for inclusion.
//   2. Every value that *is* emitted is still run through `redact_secrets`,
//      which masks anything that looks like a token/secret. Defense in depth:
//      even an allowlisted var (or a free-text field) cannot leak a secret.
//   3. As the final pass over the fully-assembled text, the literal
//      home-directory path is replaced with `~`, so absolute paths in the
//      report do not reveal the account's username.

/// Environment variables relevant to a tirith diagnostics bundle. ONLY these
/// names are emitted — the bundle never dumps the full environment. Anything
/// not on this list (cloud credentials, API keys, unrelated app secrets) is
/// excluded by construction. Values are still scrubbed by `redact_secrets`.
const BUNDLE_ENV_ALLOWLIST: &[&str] = &[
    // Shell identity / interactivity.
    "SHELL",
    "TERM",
    "TERM_PROGRAM",
    "COLORTERM",
    // SSH presence affects bash mode selection (preexec under SSH).
    "SSH_CONNECTION",
    "SSH_TTY",
    "SSH_CLIENT",
    // tirith's own knobs and state contract.
    "TIRITH_BASH_MODE",
    "TIRITH_BASH_PREEXEC_ENFORCE",
    "TIRITH_BASH_REQUIRE_ENTER",
    "TIRITH_BASH_EFFECTIVE_MODE",
    "TIRITH_BASH_EFFECTIVE_PROTECTION",
    "TIRITH_STATUS",
    "TIRITH_OFFLINE",
    "TIRITH_OUTPUT",
    "TIRITH_SHELL_DIR",
    "TIRITH_POLICY_ROOT",
    "TIRITH_LOG",
    "TIRITH_SESSION_ID",
    // XDG base dirs change where tirith looks for state/config/data.
    "XDG_STATE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    // History config that gates preexec enforcement.
    "HISTCONTROL",
    "HISTIGNORE",
];

/// Mask the literal home-directory path wherever it appears in `text`,
/// replacing it with `~`. The bundle is full of absolute paths (hook dir,
/// policy paths, data dir); without this they would spell out the account
/// username. Applied as the very last pass over the assembled report.
///
/// Returns the input unchanged when the home directory cannot be determined.
fn redact_home_path(text: &str, home: Option<&std::path::Path>) -> String {
    let home = match home {
        Some(h) => h.to_string_lossy().into_owned(),
        None => return text.to_string(),
    };
    // An empty or `/` home would turn the replacement into nonsense — skip.
    if home.is_empty() || home == "/" {
        return text.to_string();
    }
    // Strip one trailing separator so both `/Users/alice` and `/Users/alice/`
    // forms collapse onto `~` consistently.
    let trimmed = home.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() {
        return text.to_string();
    }
    text.replace(trimmed, "~")
}

/// Heuristically mask secret-looking values in a single line of bundle text.
///
/// This is the second redaction layer (after the env allowlist): it scrubs any
/// `key=value` / `key: value` pair whose key OR value looks credential-bearing.
/// Conservative by design — for a diagnostic bundle, a false-positive redaction
/// is harmless, a missed secret is not.
fn redact_secrets(line: &str) -> String {
    // Split on the first `=` or `:` so we can inspect key and value separately.
    let (key, sep, value) = if let Some(idx) = line.find('=') {
        (&line[..idx], '=', &line[idx + 1..])
    } else if let Some(idx) = line.find(": ") {
        (&line[..idx], ':', &line[idx + 2..])
    } else {
        return line.to_string();
    };

    let key_l = key.to_ascii_lowercase();
    let key_signals_secret = ["token", "secret", "password", "passwd", "api_key", "apikey"]
        .iter()
        .any(|m| key_l.contains(m))
        // `*_key` / `*-key` but not the benign `keyboard`, `keymap`, etc.
        || key_l.ends_with("key")
        || key_l.ends_with("_key")
        || key_l.ends_with("-key");

    let trimmed_value = value.trim();
    let value_signals_secret = looks_like_secret(trimmed_value);

    if key_signals_secret || value_signals_secret {
        // `key` carries any leading indentation already, so reuse it verbatim
        // and only swap the value. The separator form is preserved.
        if sep == ':' {
            format!("{key}: <redacted>")
        } else {
            format!("{key}=<redacted>")
        }
    } else {
        line.to_string()
    }
}

/// True when `value` looks like a token / secret: a long unbroken run of
/// base64/hex-ish characters, or a well-known credential prefix. Short or
/// obviously non-secret values (paths, numbers, words) return false.
fn looks_like_secret(value: &str) -> bool {
    if value.is_empty() || value == "<redacted>" {
        return false;
    }
    // Well-known credential prefixes — flag regardless of length.
    const SECRET_PREFIXES: &[&str] = &[
        "sk-",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "xox",
        "AKIA",
        "ASIA",
        "AIza",
        "ya29.",
        "eyJ", // JWT
    ];
    if SECRET_PREFIXES.iter().any(|p| value.starts_with(p)) {
        return true;
    }
    // A long unbroken high-entropy-looking run (no spaces, no path separators):
    // 24+ chars drawn only from the base64url / hex alphabet.
    if value.len() >= 24
        && !value.contains([' ', '/', '\\'])
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '_' | '-' | '=' | '.'))
        // …and it actually mixes character classes, so a long plain word or a
        // long path-free filename does not trip it.
        && value.chars().any(|c| c.is_ascii_digit())
        && value.chars().any(|c| c.is_ascii_alphabetic())
    {
        return true;
    }
    false
}

/// Assemble the full diagnostic bundle as a single redacted text blob.
///
/// `home` is threaded in (rather than read inside) so tests can drive the
/// home-path redaction deterministically.
fn build_bundle_text(home: Option<&std::path::Path>) -> String {
    let info = gather_info();
    let compat = gather_compat();
    let now = chrono::Utc::now().to_rfc3339();

    let mut out = String::new();
    let mut line = |s: String| {
        out.push_str(&s);
        out.push('\n');
    };

    line("tirith diagnostic bundle".to_string());
    line(format!("generated: {now}"));
    line(
        "This report is redacted: secrets, tokens, and your home-directory path \
         have been masked."
            .to_string(),
    );
    line("Safe to attach to a bug report. Review it before sharing if unsure.".to_string());
    line(String::new());

    line("== tirith ==".to_string());
    line(format!("version:        {}", info.version));
    line(format!("binary:         {}", info.binary_path));
    line(format!("os:             {}", std::env::consts::OS));
    line(format!("arch:           {}", std::env::consts::ARCH));
    if info.shadow_binaries.is_empty() {
        line("shadow binaries: none on PATH".to_string());
    } else {
        line(format!(
            "shadow binaries: {} on PATH (may shadow this binary)",
            info.shadow_binaries.len()
        ));
        for s in &info.shadow_binaries {
            line(format!("  - {s}"));
        }
    }
    line(String::new());

    line("== shell & protection ==".to_string());
    line(format!("detected shell: {}", info.detected_shell));
    line(format!("interactive:    {}", info.interactive));
    line(format!(
        "live status:    {} (TIRITH_STATUS)",
        info.tirith_status.as_deref().unwrap_or("(hook not loaded)")
    ));
    line(format!(
        "requested mode: {}",
        info.bash_requested_mode.as_deref().unwrap_or("(default)")
    ));
    line(format!(
        "effective mode: {}",
        info.bash_effective_mode
            .as_deref()
            .unwrap_or("(hook not loaded)")
    ));
    line(format!(
        "protection:     {}",
        info.bash_effective_protection
            .as_deref()
            .unwrap_or("(hook not loaded)")
    ));
    line(format!("bash safe mode: {}", info.bash_safe_mode));
    line(format!(
        "enter capability: {} (fresh: {})",
        info.bash_enter_capability
            .as_deref()
            .unwrap_or("not tested"),
        info.bash_enter_capability_fresh
            .map(|b| b.to_string())
            .unwrap_or_else(|| "n/a".to_string()),
    ));
    if let Some(reason) = info.bash_enter_capability_reason.as_deref() {
        line(format!("  capability reason: {reason}"));
    }
    line(String::new());

    line("== hook chain ==".to_string());
    line(format!(
        "hook dir:       {}",
        info.hook_dir.as_deref().unwrap_or("not found")
    ));
    line(format!("materialized:   {}", info.hooks_materialized));
    line(format!("hooks stale:    {}", compat.hooks_stale));
    line(format!(
        "shell profile:  {}",
        info.shell_profile.as_deref().unwrap_or("not found")
    ));
    line(format!("profile wired:  {}", info.hook_configured));
    if compat.shell_tools.is_empty() {
        line("co-installed hook tools: none detected".to_string());
    } else {
        line("co-installed hook tools (may interleave with tirith's hook):".to_string());
        for t in &compat.shell_tools {
            let signals = match (t.on_path, t.in_profile) {
                (true, true) => "on PATH, in profile",
                (true, false) => "on PATH",
                (false, true) => "in profile",
                (false, false) => "detected",
            };
            line(format!("  - {} ({})", t.name, signals));
        }
    }
    line(String::new());

    line("== policy ==".to_string());
    if info.policy_paths.is_empty() {
        line("policy discovery: no policy found (built-in defaults apply)".to_string());
    } else {
        line("policy discovery:".to_string());
        for p in &info.policy_paths {
            line(format!("  - {p}"));
        }
    }
    if let Some(root) = info.policy_root_env.as_deref() {
        line(format!("TIRITH_POLICY_ROOT: {root}"));
    }
    line(format!(
        "data dir:       {}",
        info.data_dir.as_deref().unwrap_or("not found")
    ));
    line(String::new());

    line("== threat database ==".to_string());
    match &info.threat_db {
        None => line("threat DB:      not available on this platform".to_string()),
        Some(tdb) if !tdb.installed => line("threat DB:      not installed".to_string()),
        Some(tdb) => {
            line(format!("installed:      {}", tdb.installed));
            if let Some(age) = tdb.age_hours {
                line(format!("age:            {age:.1}h"));
            }
            if let Some(total) = tdb.total_entries {
                line(format!("entries:        {total}"));
            }
            line(format!(
                "signature:      {}",
                match tdb.signature_valid {
                    Some(true) => "valid",
                    Some(false) => "INVALID",
                    None => "unknown",
                }
            ));
            line(format!("stale:          {}", tdb.stale));
            if let Some(err) = tdb.error.as_deref() {
                line(format!("error:          {err}"));
            }
        }
    }
    line(String::new());

    line("== environment (curated, redacted) ==".to_string());
    line("Only tirith-relevant variables are listed; values are secret-scrubbed.".to_string());
    let mut any_env = false;
    for name in BUNDLE_ENV_ALLOWLIST {
        if let Ok(value) = std::env::var(name) {
            if value.is_empty() {
                continue;
            }
            any_env = true;
            // `redact_secrets` scrubs the value if it (or the key) looks
            // credential-bearing — a second layer behind the allowlist.
            line(redact_secrets(&format!("{name}={value}")));
        }
    }
    if !any_env {
        line("(none of the curated variables are set)".to_string());
    }
    line(String::new());

    line("== end of bundle ==".to_string());

    // Final pass: mask the literal home-directory path everywhere it appears.
    redact_home_path(&out, home)
}

/// Write `text` to a freshly-created, randomly-named bundle file in `dir` and
/// return the path it landed at.
///
/// The filename is *random*, not a predictable `tirith-bundle-<timestamp>`:
/// `tempfile::Builder` creates the file with `O_EXCL`, so an attacker cannot
/// pre-create the path as a symlink and redirect the write, and two runs in the
/// same second cannot collide or clobber. The `tirith-bundle-` prefix is purely
/// cosmetic — the security comes entirely from the random suffix and the
/// exclusive create. On Unix the file handle is chmod'd to `0600` *before* the
/// content is written, so the redacted-but-still-diagnostic bundle is never
/// even briefly world-readable. `keep()` persists the temp file at its existing
/// random path (it is deliberately NOT `persist()`ed onto a predictable name —
/// that would reintroduce the symlink/TOCTOU hole). Mirrors the safe-write
/// style of `bash_capability::write_cache`.
fn write_bundle_file(dir: &std::path::Path, text: &str) -> std::io::Result<PathBuf> {
    let mut tmp = tempfile::Builder::new()
        .prefix("tirith-bundle-")
        .suffix(".txt")
        .tempfile_in(dir)?;
    // Tighten permissions on the open handle before writing any content, so the
    // bundle is never momentarily readable by other users.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    use std::io::Write;
    tmp.write_all(text.as_bytes())?;
    tmp.flush()?;
    // `keep()` disarms the auto-delete and hands back the file's *current*
    // (random) path — exactly what we print. No rename onto a guessable name.
    let (_file, path) = tmp.keep().map_err(|e| e.error)?;
    Ok(path)
}

/// `tirith doctor --bundle`: write the redacted diagnostic bundle to a file
/// and print its path. With `--format json`, prints `{"bundle_path": "..."}`.
fn run_bundle(json: bool) -> i32 {
    let home = home::home_dir();
    let text = build_bundle_text(home.as_deref());

    // Write into the tirith state dir, which already exists for any configured
    // install; fall back to the system temp dir if it cannot be determined.
    let dir = tirith_core::policy::state_dir().unwrap_or_else(std::env::temp_dir);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("tirith: could not create {}: {e}", dir.display());
        return 1;
    }

    let path = match write_bundle_file(&dir, &text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("tirith: could not write bundle into {}: {e}", dir.display());
            return 1;
        }
    };

    if json {
        // The path itself can contain the home dir; redact it the same way the
        // bundle body is redacted so the JSON is as safe as the file.
        let shown = redact_home_path(&path.display().to_string(), home.as_deref());
        match serde_json::to_string_pretty(&serde_json::json!({ "bundle_path": shown })) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("tirith: JSON serialization failed: {e}");
                return 1;
            }
        }
    } else {
        println!("tirith: diagnostic bundle written to:");
        println!("  {}", path.display());
        println!();
        println!("The bundle is redacted (secrets, tokens, and your home-directory path");
        println!("are masked) and safe to attach to a bug report. Review it before");
        println!("sharing if you want to be sure.");
    }
    0
}

/// The `protection status:` line for `tirith doctor --compat`, derived from the
/// hook-exported `TIRITH_STATUS` value. `None` when the line should be omitted.
///
/// `TIRITH_STATUS` is exported by *every* tirith shell hook — bash, zsh, fish,
/// PowerShell, nushell — so this status MUST be surfaced regardless of the
/// detected shell. It was previously printed only inside the bash-only branch,
/// which silently dropped it for, e.g., a zsh session with
/// `TIRITH_STATUS=degraded`. A `degraded` status gets an explicit callout; an
/// unset variable yields `None` (the rest of the report still indicates the
/// hook was not loaded).
fn compat_protection_status_line(status: Option<&str>) -> Option<String> {
    match status {
        Some("degraded") => Some(
            "  protection status:    DEGRADED (downgraded to warn-only this session)".to_string(),
        ),
        Some(status) => Some(format!("  protection status:    {status}")),
        None => None,
    }
}

/// Render the full `tirith doctor --compat` human report into a string.
///
/// Returning a `String` (rather than printing directly) keeps the report
/// unit-testable — in particular the F3 property that `TIRITH_STATUS` is
/// surfaced for *non-bash* shells, which a stdout-only function could not be
/// asserted on without process plumbing.
fn format_compat_human(r: &CompatReport) -> String {
    let mut out = String::new();
    let mut line = |s: &str| {
        out.push_str(s);
        out.push('\n');
    };

    line("tirith compatibility report");
    line("");
    line(&format!("tirith {}", r.version));
    line(&format!("  binary:        {}", r.binary_path));
    line(&format!("  shell:         {}", r.detected_shell));
    line(&format!("  interactive:   {}", r.interactive));
    line("");

    // Shell mode / protection. Bash is the only shell with a requested-vs-
    // effective split today; for other shells we just report what (if
    // anything) the hook exported into this process.
    line("Shell hook mode");
    // Live cross-shell protection status, from the hook-exported
    // `TIRITH_STATUS`. Emitted unconditionally — every shell's hook exports it,
    // so it must not be gated behind the bash-only branch below.
    if let Some(status_line) = compat_protection_status_line(r.tirith_status.as_deref()) {
        line(&status_line);
    }
    if r.detected_shell == "bash"
        || r.bash_requested_mode.is_some()
        || r.bash_effective_mode.is_some()
    {
        let requested = r.bash_requested_mode.as_deref().unwrap_or("(default)");
        line(&format!("  requested bash mode:  {requested}"));
        match (
            r.bash_effective_mode.as_deref(),
            r.bash_effective_protection.as_deref(),
        ) {
            (Some(mode), Some(protection)) => {
                line(&format!("  effective bash mode:  {mode}"));
                line(&format!("  effective protection: {protection}"));
            }
            _ => {
                line("  effective bash mode:  hook not loaded in this process");
            }
        }
        match r.bash_enter_capability.as_deref() {
            Some(verdict) => {
                let fresh = r.bash_enter_capability_fresh.unwrap_or(false);
                if fresh {
                    line(&format!(
                        "  enter capability:     {verdict} (self-test verdict)"
                    ));
                } else {
                    line(&format!(
                        "  enter capability:     {verdict} (STALE — measured on a different bash)"
                    ));
                }
            }
            None => {
                line("  enter capability:     not tested — run tirith doctor --simulate-enter");
            }
        }
        line(&format!(
            "  bash safe mode:       {}",
            if r.bash_safe_mode { "on" } else { "off" }
        ));
    } else {
        line(&format!(
            "  (no bash-specific mode state — detected shell is {})",
            r.detected_shell
        ));
    }
    line("");

    // Install checks.
    line("Install checks");
    let shadow_status = if r.shadow_binaries.is_empty() {
        "no shadowing tirith binaries on PATH".to_string()
    } else {
        format!(
            "{} shadowing binary/binaries on PATH",
            r.shadow_binaries.len()
        )
    };
    line(&format!("  PATH shadowing:       {shadow_status}"));
    for shadow in &r.shadow_binaries {
        line(&format!("    - {shadow}"));
    }
    line(&format!(
        "  shell profile:        {}",
        r.shell_profile.as_deref().unwrap_or("not found")
    ));
    line(&format!(
        "  profile wiring:       {}",
        if r.hook_configured {
            "tirith hook configured"
        } else {
            "NOT configured — commands are not intercepted"
        }
    ));
    line(&format!(
        "  hook dir:             {}",
        r.hook_dir.as_deref().unwrap_or("not found")
    ));
    let hook_freshness = if !r.hooks_materialized {
        "system/packaged hooks (not materialized)"
    } else if r.hooks_stale {
        "STALE — re-run tirith init (or tirith doctor --fix)"
    } else {
        "materialized, up to date"
    };
    line(&format!("  materialized hooks:   {hook_freshness}"));
    if r.policy_paths.is_empty() {
        line("  policy discovery:     no policy found (built-in defaults apply)");
    } else {
        for (i, p) in r.policy_paths.iter().enumerate() {
            if i == 0 {
                line(&format!("  policy discovery:     {p}"));
            } else {
                line(&format!("                        {p}"));
            }
        }
    }
    match &r.threat_db {
        Some(tdb) if !tdb.installed => {
            line("  threat DB:            not installed");
        }
        Some(tdb) if tdb.error.is_some() => {
            line(&format!(
                "  threat DB:            error: {}",
                tdb.error.as_deref().unwrap_or("unknown")
            ));
        }
        Some(tdb) if tdb.signature_valid == Some(false) => {
            line("  threat DB:            invalid signature");
        }
        Some(tdb) if tdb.stale => {
            line("  threat DB:            installed but stale");
        }
        Some(_) => {
            line("  threat DB:            installed, current");
        }
        None => {
            line("  threat DB:            not available");
        }
    }
    line("");

    // Conflict detection — honest about being best-effort.
    line("Shell tool detection");
    if r.shell_tools.is_empty() {
        line("  no known hook-interacting shell tools detected");
    } else {
        line("  detected co-installed shell tools that interact with shell hooks.");
        line("  presence does not necessarily mean a conflict — tirith's hooks are");
        line("  designed to coexist. Listed for awareness:");
        for tool in &r.shell_tools {
            let signals = match (tool.on_path, tool.in_profile) {
                (true, true) => "on PATH, in shell profile",
                (true, false) => "on PATH",
                (false, true) => "in shell profile",
                (false, false) => "detected",
            };
            line(&format!("    - {} ({})", tool.name, signals));
            line(&format!("        {}", tool.note));
        }
    }

    out
}

fn print_compat_human(r: &CompatReport) {
    print!("{}", format_compat_human(r));
}

/// Render the cross-shell `protection status:` line from the hook-exported
/// `TIRITH_STATUS` value. A `degraded` status gets an explicit, unmistakable
/// callout — the whole point of the indicator is that a downgrade is never
/// something the reader has to infer.
fn print_protection_status(status: Option<&str>) {
    match status {
        Some("blocks") => {
            println!("  protection:   blocks (a dangerous command is stopped before it runs)");
        }
        Some("warn-only") => {
            println!("  protection:   warn-only (commands are checked but NOT blocked)");
        }
        Some("degraded") => {
            println!("  protection:   DEGRADED — downgraded to warn-only this session");
            println!();
            println!("  WARNING: tirith protection was downgraded mid-session.");
            println!("  Commands are still checked, but a dangerous one is NO LONGER blocked.");
            println!("  Restart your shell to recover full protection. See the bash section");
            println!("  below (and 'tirith doctor --bundle' for a full diagnostic report).");
            println!();
        }
        Some("off") => {
            println!("  protection:   off (the tirith hook installed nothing in this shell)");
        }
        Some(other) => {
            // Forward-compatible: an unrecognised value is shown verbatim
            // rather than silently dropped.
            println!("  protection:   {other}");
        }
        None => {
            // No hook ran in the invoking process — usually a non-interactive
            // subshell. The bash block below prints the fuller "not loaded"
            // diagnostic; here we stay quiet to avoid a redundant line.
        }
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
    // Cross-shell live protection status, from the hook-exported
    // `TIRITH_STATUS`. A degraded session is called out explicitly here so the
    // reader never has to infer it from `effective protection: warn-only`.
    print_protection_status(info.tirith_status.as_deref());
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

        // Cached bash enter-mode delivery capability (issue #111). The hook
        // selects enter mode (blocking) by default only when this verdict is
        // `works` and fresh; otherwise it falls back to preexec (warn-only).
        match info.bash_enter_capability.as_deref() {
            Some(verdict) => {
                let fresh = info.bash_enter_capability_fresh.unwrap_or(false);
                let writer = info
                    .bash_enter_capability_tirith_version
                    .as_deref()
                    .map(|v| format!(", tirith {v}"))
                    .unwrap_or_default();
                if fresh {
                    println!("  enter capability:     {verdict} (self-test verdict{writer})");
                } else {
                    println!(
                        "  enter capability:     {verdict} (STALE — measured on a different bash{writer})"
                    );
                    println!("                        Re-test: tirith doctor --simulate-enter");
                }
                if let Some(reason) = info.bash_enter_capability_reason.as_deref() {
                    println!("                        {reason}");
                }
            }
            None => {
                println!("  enter capability:     not tested — run tirith doctor --simulate-enter");
            }
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

/// `tirith doctor --simulate-enter`: run the bash enter-mode delivery
/// self-test, print a verdict, and cache the result for the hook to read.
///
/// The self-test spawns a disposable bash through a PTY, sources the real hook
/// in enter mode, and verifies that an allowed command is delivered exactly
/// once AND that a command tirith would block is actually stopped. Enter mode
/// is the only bash mode that can truly block, but `bind -x` on Enter does not
/// reliably accept the line in every environment (issue #111) — this proves
/// whether it works *here* rather than guessing from the bash version.
#[cfg(unix)]
fn run_simulate_enter() -> i32 {
    println!("tirith: running bash enter-mode delivery self-test...");
    let outcome = crate::cli::bash_capability::run_and_cache();

    if let Some(v) = &outcome.bash_version {
        println!("  bash version:   {v}");
    }
    if let Some(p) = &outcome.bash_path {
        println!("  bash binary:    {}", p.display());
    }
    println!("  enter delivery: {}", outcome.capability.describe());
    println!("  detail:         {}", outcome.reason);

    match &outcome.cache_path {
        Some(path) => println!("  cached to:      {}", path.display()),
        None => println!("  cache:          NOT written (hook keeps its safe default)"),
    }

    println!();
    // Enter mode is only actually enabled for new shells when BOTH the verdict
    // is `works` AND the cache was written — the hook reads the cache file, so
    // a failed write means new shells still fall back to preexec.
    if outcome.capability.enables_enter() && outcome.cache_path.is_some() {
        println!("tirith: enter mode (blocking) is enabled for bash in new shells.");
    } else if outcome.capability.enables_enter() {
        println!("tirith: enter-mode delivery works here, but the capability cache could not");
        println!("        be written — new shells will fall back to preexec until it can be.");
    } else {
        println!("tirith: bash will use preexec mode (warn-only). For blocking, set");
        println!("        TIRITH_BASH_PREEXEC_ENFORCE=1 in a clean-history shell, or run");
        println!("        tirith on a shell where enter-mode delivery works.");
    }
    0
}

/// Non-Unix stub: enter mode and its `bind -x` machinery are Unix-only.
#[cfg(not(unix))]
fn run_simulate_enter() -> i32 {
    println!("tirith: --simulate-enter is only meaningful on Unix (bash enter mode)");
    0
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

    // --- compat report: shell-tool conflict detection ----------------------

    #[test]
    fn tool_in_profile_detects_mention() {
        let tmp = tempfile::tempdir().unwrap();
        let profile = tmp.path().join(".zshrc");
        std::fs::write(
            &profile,
            "eval \"$(tirith init --shell zsh)\"\neval \"$(starship init zsh)\"\n",
        )
        .unwrap();
        assert!(
            tool_in_profile("starship", Some(&profile)),
            "starship init line must be detected in the profile"
        );
        assert!(
            !tool_in_profile("atuin", Some(&profile)),
            "atuin is absent from the profile and must not be detected"
        );
    }

    #[test]
    fn tool_in_profile_handles_missing_profile() {
        // No profile path, and a non-existent path, both yield false rather
        // than erroring — detection is best-effort.
        assert!(!tool_in_profile("starship", None));
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist");
        assert!(!tool_in_profile("starship", Some(&missing)));
    }

    #[test]
    fn detect_shell_tool_conflicts_reports_only_profile_hits_when_offline_of_path() {
        // A tool mentioned only in the profile (not on PATH) must still be
        // surfaced, with `in_profile` true and `on_path` reflecting reality.
        let tmp = tempfile::tempdir().unwrap();
        let profile = tmp.path().join(".bashrc");
        std::fs::write(&profile, "eval \"$(zoxide init bash)\"\n").unwrap();

        let found = detect_shell_tool_conflicts(Some(&profile));
        let zoxide = found.iter().find(|t| t.name == "zoxide");
        assert!(
            zoxide.is_some(),
            "zoxide mentioned in profile must be reported, got: {found:?}"
        );
        assert!(
            zoxide.unwrap().in_profile,
            "zoxide must be flagged as present in the profile"
        );
        // A tool that is neither on PATH nor in the profile must be absent.
        assert!(
            !found.iter().any(|t| t.name == "direnv" && !t.on_path),
            "direnv with no signal at all must not appear"
        );
    }

    #[test]
    fn known_shell_tools_covers_the_documented_set() {
        // The compat report promises detection of these specific tools; guard
        // against an accidental removal from the table.
        let names: Vec<&str> = KNOWN_SHELL_TOOLS.iter().map(|(n, _)| *n).collect();
        for expected in [
            "atuin", "starship", "fzf", "zoxide", "direnv", "mise", "asdf",
        ] {
            assert!(
                names.contains(&expected),
                "{expected} must be in the known shell-tool table"
            );
        }
    }

    // --- protection-status rendering --------------------------------------

    #[test]
    fn print_protection_status_does_not_panic_on_any_input() {
        // Smoke: every variant (including an unknown value and None) renders
        // without panicking. The content assertions live in the integration
        // tests; this just guards the match arms.
        for s in [
            Some("blocks"),
            Some("warn-only"),
            Some("degraded"),
            Some("off"),
            Some("future-value"),
            None,
        ] {
            print_protection_status(s);
        }
    }

    // --- bundle redaction: home-directory path ----------------------------

    #[test]
    fn redact_home_path_masks_the_literal_home_dir() {
        let home = std::path::Path::new("/Users/alice");
        let text = "hook dir: /Users/alice/.local/share/tirith/shell\npolicy: /Users/alice/.tirith/policy.yaml";
        let red = redact_home_path(text, Some(home));
        assert!(
            !red.contains("/Users/alice"),
            "the literal home path must not survive redaction, got:\n{red}"
        );
        assert!(
            red.contains("~/.local/share/tirith/shell"),
            "paths under home must be rewritten to ~, got:\n{red}"
        );
    }

    #[test]
    fn redact_home_path_handles_trailing_slash_and_degenerate_homes() {
        // A trailing separator on the home value must still collapse to `~`.
        let red = redact_home_path("x /home/bob/y", Some(std::path::Path::new("/home/bob/")));
        assert_eq!(red, "x ~/y");
        // A `/` or empty home must be a no-op — never rewrite every `/`.
        let untouched = "/usr/bin/tirith";
        assert_eq!(
            redact_home_path(untouched, Some(std::path::Path::new("/"))),
            untouched
        );
        assert_eq!(redact_home_path(untouched, None), untouched);
    }

    // --- bundle redaction: secrets / tokens -------------------------------

    #[test]
    fn redact_secrets_masks_secret_named_keys() {
        for line in [
            "GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "MY_API_KEY=whatever-value-here",
            "db_password=hunter2",
            "Some Secret: still-masked",
        ] {
            let red = redact_secrets(line);
            assert!(
                red.contains("<redacted>"),
                "a secret-named key must be masked: {line} -> {red}"
            );
        }
    }

    #[test]
    fn redact_secrets_masks_token_shaped_values() {
        // Even a benign-looking key must be scrubbed when the *value* looks
        // like a credential.
        for line in [
            "TIRITH_SESSION_ID=ghp_0123456789abcdef0123456789abcdef0123",
            "FOO=AKIAIOSFODNN7EXAMPLE",
            "BAR=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefpracticallyajwt",
            "BAZ=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
        ] {
            let red = redact_secrets(line);
            assert!(
                red.contains("<redacted>"),
                "a token-shaped value must be masked: {line} -> {red}"
            );
        }
    }

    #[test]
    fn redact_secrets_leaves_benign_diagnostic_lines_intact() {
        // The bundle is full of benign key=value lines — they must survive.
        for line in [
            "detected shell: bash",
            "TIRITH_BASH_MODE=preexec",
            "effective mode: enter",
            "interactive:    true",
            "TERM=xterm-256color",
            "bash safe mode: false",
        ] {
            assert_eq!(
                redact_secrets(line),
                line,
                "benign diagnostic line must not be redacted: {line}"
            );
        }
    }

    #[test]
    fn looks_like_secret_does_not_flag_ordinary_values() {
        // Short values, words, numbers, and paths must NOT look like secrets.
        for v in [
            "preexec",
            "bash",
            "true",
            "1",
            "xterm-256color",
            "/Users/alice/.local/state/tirith",
            "warn-only",
        ] {
            assert!(
                !looks_like_secret(v),
                "{v:?} must not be classified as a secret"
            );
        }
    }

    // --- bundle assembly: end-to-end redaction ----------------------------

    /// The load-bearing safety test: the assembled bundle must NOT contain a
    /// secret-shaped value placed in an allowlisted env var, and must NOT
    /// contain the literal home-directory path.
    #[test]
    fn build_bundle_text_redacts_secrets_and_home_path() {
        with_fake_env(false, |home, _cwd| {
            // `TIRITH_SESSION_ID` is on the env allowlist, so it WILL be
            // emitted — but its value here is token-shaped, so the value
            // layer must scrub it.
            let secret = "ghp_DEADBEEFdeadbeef0123456789abcdef0123";
            let _sid = EnvGuard::set("TIRITH_SESSION_ID", std::path::Path::new(secret));
            // A genuinely secret-named var that is NOT on the allowlist must
            // never appear at all (allowlist layer).
            let _leak = EnvGuard::set(
                "AWS_SECRET_ACCESS_KEY",
                std::path::Path::new("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"),
            );

            let text = build_bundle_text(Some(home));

            assert!(
                !text.contains(secret),
                "a token-shaped value in an allowlisted env var must be redacted, got:\n{text}"
            );
            assert!(
                text.contains("TIRITH_SESSION_ID=<redacted>"),
                "the scrubbed var must still be listed (with a redacted value), got:\n{text}"
            );
            assert!(
                !text.contains("AWS_SECRET_ACCESS_KEY"),
                "a non-allowlisted secret var must not appear in the bundle at all, got:\n{text}"
            );
            assert!(
                !text.contains("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"),
                "a non-allowlisted secret value must never leak, got:\n{text}"
            );
            // The literal home-directory path must be masked everywhere.
            let home_str = home.to_string_lossy();
            assert!(
                !text.contains(home_str.as_ref()),
                "the literal home path {home_str} must not survive in the bundle, got:\n{text}"
            );
        });
    }

    #[test]
    fn build_bundle_text_has_the_documented_sections() {
        with_fake_env(false, |home, _cwd| {
            let text = build_bundle_text(Some(home));
            for section in [
                "tirith diagnostic bundle",
                "== tirith ==",
                "== shell & protection ==",
                "== hook chain ==",
                "== policy ==",
                "== threat database ==",
                "== environment (curated, redacted) ==",
                "== end of bundle ==",
            ] {
                assert!(
                    text.contains(section),
                    "bundle missing section {section:?}, got:\n{text}"
                );
            }
        });
    }

    /// True when `name` has the predictable `tirith-bundle-<UTC-timestamp>.txt`
    /// shape the F2 fix eliminates — `tirith-bundle-` + `YYYYMMDDTHHMMSSZ` (8
    /// digits, `T`, 6 digits, `Z`) + `.txt`. The new code must NOT produce a
    /// name of this form; it uses a random `tempfile` suffix instead.
    fn is_predictable_timestamp_bundle_name(name: &str) -> bool {
        let Some(mid) = name
            .strip_prefix("tirith-bundle-")
            .and_then(|s| s.strip_suffix(".txt"))
        else {
            return false;
        };
        let bytes = mid.as_bytes();
        // YYYYMMDD (8) + 'T' + HHMMSS (6) + 'Z' == 16 chars exactly.
        bytes.len() == 16
            && bytes[..8].iter().all(u8::is_ascii_digit)
            && bytes[8] == b'T'
            && bytes[9..15].iter().all(u8::is_ascii_digit)
            && bytes[15] == b'Z'
    }

    #[test]
    fn is_predictable_timestamp_bundle_name_recognises_the_old_format() {
        // Sanity-check the matcher itself so the F2 test below cannot pass
        // vacuously: the OLD predictable name must be recognised, a random one
        // must not.
        assert!(is_predictable_timestamp_bundle_name(
            "tirith-bundle-20260522T143000Z.txt"
        ));
        assert!(!is_predictable_timestamp_bundle_name(
            "tirith-bundle-a9Xk2Q.txt"
        ));
        assert!(!is_predictable_timestamp_bundle_name("tirith-bundle-.txt"));
        assert!(!is_predictable_timestamp_bundle_name("unrelated.txt"));
    }

    /// F2: the diagnostic bundle must be written to a *random*, non-predictable
    /// path (no symlink/TOCTOU hole) and the file must be mode `0600`.
    #[test]
    fn write_bundle_file_uses_a_random_name_and_tight_mode() {
        let dir = tempfile::tempdir().expect("bundle dir");
        let body = "tirith diagnostic bundle\n== end of bundle ==\n";

        let path = write_bundle_file(dir.path(), body).expect("bundle write");

        // The file exists, is inside the requested dir, and round-trips.
        assert!(path.exists(), "bundle file must exist after the write");
        assert_eq!(
            path.parent(),
            Some(dir.path()),
            "bundle must land in the requested directory"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read bundle"),
            body,
            "bundle content must round-trip"
        );

        // The filename must NOT be the predictable timestamp form — that
        // predictable path is exactly the symlink/TOCTOU hole F2 closes.
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("bundle file name");
        assert!(
            !is_predictable_timestamp_bundle_name(name),
            "bundle filename {name:?} must not be the predictable \
             tirith-bundle-<timestamp>.txt form"
        );
        // A random tempfile name keeps the cosmetic prefix + .txt suffix.
        assert!(
            name.starts_with("tirith-bundle-") && name.ends_with(".txt"),
            "bundle name {name:?} should keep the tirith-bundle- prefix and .txt suffix"
        );

        // Two writes in the same dir must not collide — the random suffix and
        // O_EXCL create guarantee distinct files.
        let path2 = write_bundle_file(dir.path(), body).expect("second bundle write");
        assert_ne!(
            path, path2,
            "consecutive bundle writes must produce distinct random paths"
        );

        // On Unix the file must be mode 0600 — the bundle is redacted but a
        // diagnostic file still must not be group/world-readable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("bundle metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "bundle file must be mode 0600, got {mode:o}");
        }
    }

    /// Build a minimal `CompatReport` for the given shell and `TIRITH_STATUS`,
    /// with every other field at a benign default. Used by the F3 tests.
    fn compat_report_for(detected_shell: &str, tirith_status: Option<&str>) -> CompatReport {
        CompatReport {
            version: "0.0.0-test".to_string(),
            binary_path: "/tmp/tirith".to_string(),
            detected_shell: detected_shell.to_string(),
            interactive: false,
            bash_requested_mode: None,
            bash_effective_mode: None,
            bash_effective_protection: None,
            tirith_status: tirith_status.map(str::to_string),
            bash_enter_capability: None,
            bash_enter_capability_fresh: None,
            bash_safe_mode: false,
            hook_dir: None,
            hooks_materialized: false,
            hooks_stale: false,
            shell_profile: None,
            hook_configured: false,
            shadow_binaries: Vec::new(),
            policy_paths: Vec::new(),
            threat_db: None,
            shell_tools: Vec::new(),
        }
    }

    /// F3: `tirith doctor --compat` must surface `TIRITH_STATUS` for a
    /// **non-bash** shell. The status line was previously printed only inside
    /// the bash-only branch, so a `SHELL=/bin/zsh TIRITH_STATUS=degraded`
    /// invocation silently dropped it. `TIRITH_STATUS` is exported by the zsh,
    /// fish, and PowerShell hooks too, so the line must not be bash-gated.
    #[test]
    fn compat_human_surfaces_tirith_status_for_non_bash_shell() {
        for shell in ["zsh", "fish", "powershell", "nushell"] {
            let report = compat_report_for(shell, Some("degraded"));
            let out = format_compat_human(&report);
            assert!(
                out.contains("protection status:    DEGRADED"),
                "TIRITH_STATUS=degraded must be surfaced for a non-bash shell ({shell}); \
                 got:\n{out}"
            );
            // The bash-only block must NOT have run for a non-bash shell with
            // no bash env — the status line is the *only* protection signal.
            assert!(
                out.contains(&format!(
                    "no bash-specific mode state — detected shell is {shell}"
                )),
                "a non-bash shell with no bash env must take the non-bash branch ({shell}); \
                 got:\n{out}"
            );
        }
    }

    /// A plain (non-degraded) status is surfaced verbatim for a non-bash shell.
    #[test]
    fn compat_human_surfaces_plain_status_for_non_bash_shell() {
        let report = compat_report_for("zsh", Some("warn-only"));
        let out = format_compat_human(&report);
        assert!(
            out.contains("protection status:    warn-only"),
            "a non-degraded TIRITH_STATUS must still be surfaced for zsh; got:\n{out}"
        );
    }

    /// When `TIRITH_STATUS` is unset the compat report stays correct: no
    /// `protection status:` line, and no panic / stray formatting.
    #[test]
    fn compat_human_omits_status_line_when_unset() {
        let report = compat_report_for("zsh", None);
        let out = format_compat_human(&report);
        assert!(
            !out.contains("protection status:"),
            "no protection-status line should appear when TIRITH_STATUS is unset; got:\n{out}"
        );
        // The report is still well-formed and reaches the install-checks block.
        assert!(
            out.contains("Install checks"),
            "report must be complete; got:\n{out}"
        );
    }

    /// `compat_protection_status_line` is shell-independent by construction —
    /// it never consults a shell. This pins the F3 fix at the unit level.
    #[test]
    fn compat_protection_status_line_is_shell_independent() {
        assert_eq!(
            compat_protection_status_line(Some("degraded")).as_deref(),
            Some("  protection status:    DEGRADED (downgraded to warn-only this session)")
        );
        assert_eq!(
            compat_protection_status_line(Some("blocks")).as_deref(),
            Some("  protection status:    blocks")
        );
        assert_eq!(compat_protection_status_line(None), None);
    }

    #[test]
    fn bundle_env_allowlist_excludes_known_secret_holders() {
        // Defense-in-depth check: the curated allowlist must never name a
        // variable that conventionally holds a credential.
        for forbidden in [
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "NPM_TOKEN",
        ] {
            assert!(
                !BUNDLE_ENV_ALLOWLIST.contains(&forbidden),
                "{forbidden} must NOT be on the bundle env allowlist"
            );
        }
    }
}
