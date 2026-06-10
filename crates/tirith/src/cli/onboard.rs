//! `tirith onboard` — M13 ch1 onboarding wizard.
//!
//! Read-only detection of the developer's environment (shell, IDE/AI configs,
//! package managers, lockfiles, CI, MCP configs, tirith install state) that
//! prints a report and recommends a shipping policy template
//! (`individual` / `startup` / `ci-strict` / `ai-agent-heavy`) plus next
//! actions. Reuses existing helpers (`init::detect_shell`,
//! `doctor::check_shell_profile`, `policy::discover_local_policy_path`,
//! `path_audit::which_all`).
//!
//! `--apply` (off by default) performs the recommended SAFE actions with
//! per-step stdin confirmation, refusing non-interactively (it prints what it
//! WOULD do) so a piped/CI run never silently mutates the tree.

use std::path::{Path, PathBuf};

use crate::cli::policy::PolicyTemplate;

/// Repo-local MCP config files `onboard` probes for. Mirrors core's
/// (crate-private) `mcp_lock::MCP_CONFIG_RELATIVE_PATHS`; kept explicit so
/// discovery stays bounded.
const MCP_CONFIG_RELATIVE_PATHS: &[&str] = &[
    // Bare repo-root MCP configs.
    "mcp.json",
    ".mcp.json",
    "mcp_settings.json",
    // IDE host-directory variants.
    ".vscode/mcp.json",
    ".cursor/mcp.json",
    ".windsurf/mcp.json",
    ".cline/mcp_settings.json",
    ".amazonq/mcp.json",
    ".continue/mcp.json",
    ".kiro/settings/mcp.json",
];

/// Package managers `onboard` looks for on `PATH`. `(binary, label)`.
const PACKAGE_MANAGERS: &[(&str, &str)] = &[
    ("npm", "npm"),
    ("pnpm", "pnpm"),
    ("yarn", "yarn"),
    ("cargo", "cargo"),
    ("pip", "pip"),
    ("uv", "uv"),
    ("go", "go"),
];

/// Lockfiles `onboard` looks for in the repo root. `(relative_path, label)`.
const LOCKFILES: &[(&str, &str)] = &[
    ("package-lock.json", "package-lock.json"),
    ("pnpm-lock.yaml", "pnpm-lock.yaml"),
    ("yarn.lock", "yarn.lock"),
    ("Cargo.lock", "Cargo.lock"),
    ("requirements.txt", "requirements.txt"),
    ("uv.lock", "uv.lock"),
    ("go.sum", "go.sum"),
];

/// Schema version of the `onboard --json` envelope. Stable; bump on breaking changes.
const ONBOARD_SCHEMA_VERSION: u32 = 1;

/// The detection report `onboard` builds and (optionally) serializes to JSON.
/// Naming/casing mirror the other `--json` surfaces. `recommended_template`
/// carries the canonical template NAME so a consumer can feed it back into
/// `tirith policy init --template <name>`.
#[derive(Debug, Clone, serde::Serialize)]
struct OnboardReport {
    schema_version: u32,
    cwd: String,
    /// The repo root walked up to (the `.git` boundary), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    repo_root: Option<String>,
    /// Requested mode bias (`repo` / `team` / `ai-agent-heavy`), or `auto`.
    requested_mode: String,
    detected_shell: String,
    ide_configs: Vec<String>,
    ai_config_files: Vec<String>,
    /// Package managers on `PATH` (PATH-dependent — not asserted in tests).
    package_managers: Vec<String>,
    lockfiles: Vec<String>,
    /// `true` when `.github/workflows/` holds at least one `*.yml`/`*.yaml`.
    ci_detected: bool,
    /// MCP config files (repo-local plus the home Windsurf config).
    mcp_configs: Vec<String>,
    tirith: TirithState,
    recommended_template: String,
    recommendation_reason: String,
    next_actions: Vec<String>,
}

/// tirith's own install state, surfaced read-only (never materializes hooks).
#[derive(Debug, Clone, serde::Serialize)]
struct TirithState {
    hook_installed: bool,
    policy_present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_path: Option<String>,
}

/// `tirith onboard` entry point.
///
/// * `mode` — `Some("repo"|"team"|"ai-agent-heavy")` biases the recommendation,
///   `None` = auto-detect.
/// * `apply` — `false` reports only; `true` performs the recommended SAFE
///   actions with per-step stdin confirmation (refuses non-interactively).
/// * `json` — emit the detection + recommendation as a JSON object.
///
/// `--json` and `--apply` are `conflicts_with` at the clap level (rejected at
/// parse time), so the combination never reaches here.
pub fn run(mode: Option<&str>, apply: bool, json: bool) -> i32 {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cwd_str = cwd.display().to_string();

    // Repo root: walk up to `.git`, falling back to cwd (mirrors `policy::init`).
    let repo_root = tirith_core::policy::find_repo_root(Some(&cwd_str));
    let detect_root = repo_root.clone().unwrap_or_else(|| cwd.clone());

    let report = gather_report(&cwd, &detect_root, repo_root.as_deref(), mode);

    if json {
        // Broken-pipe-safe: a failed write exits non-zero rather than pairing
        // truncated JSON with a success code.
        if !crate::cli::write_json_stdout(&report, "tirith onboard: failed to write JSON output") {
            return 2;
        }
        return 0;
    }

    print_human(&report);

    if apply {
        return apply_actions(&report);
    }
    // Discoverability: `--apply` already performs the steps, but the report never
    // named it, so users didn't know it existed.
    crate::cli::note("Run `tirith onboard --apply` to perform the recommended safe actions.");
    0
}

/// Build the full detection report for `detect_root` (repo root or cwd),
/// biased by the requested `mode`.
fn gather_report(
    cwd: &Path,
    detect_root: &Path,
    repo_root: Option<&Path>,
    mode: Option<&str>,
) -> OnboardReport {
    let detected_shell = crate::cli::init::detect_shell().to_string();

    let ide_configs = detect_dirs(detect_root, &[".cursor", ".vscode"]);
    let ai_config_files = detect_ai_config(detect_root);
    let package_managers = detect_package_managers();
    let lockfiles = detect_lockfiles(detect_root);
    let ci_detected = detect_ci(detect_root);
    let mcp_configs = detect_mcp_configs(detect_root);
    let tirith = detect_tirith_state(cwd, &detected_shell);

    let requested_mode = mode.unwrap_or("auto").to_string();

    let signals = RecommendationSignals {
        mode,
        ai_config_count: ai_config_files.len(),
        mcp_config_count: mcp_configs.len(),
        ci_detected,
    };
    let (recommended_template, recommendation_reason) = recommend_template(&signals);
    let next_actions = build_next_actions(&tirith, recommended_template);

    OnboardReport {
        schema_version: ONBOARD_SCHEMA_VERSION,
        cwd: cwd.display().to_string(),
        repo_root: repo_root.map(|p| p.display().to_string()),
        requested_mode,
        detected_shell,
        ide_configs,
        ai_config_files,
        package_managers,
        lockfiles,
        ci_detected,
        mcp_configs,
        tirith,
        recommended_template: recommended_template.canonical_name().to_string(),
        recommendation_reason,
        next_actions,
    }
}

/// Return the subset of `names` that exist as directories directly under `root`.
fn detect_dirs(root: &Path, names: &[&str]) -> Vec<String> {
    names
        .iter()
        .filter(|name| root.join(name).is_dir())
        .map(|name| (*name).to_string())
        .collect()
}

/// Root-level AI agent-instruction basenames `onboard` probes for. Mirrors the
/// AI-config surface `tirith ai` / the `aifile` rules act on, so the
/// recommendation isn't undercounted; each entry is verified against the
/// canonical [`tirith_core::rules::aifile::is_ai_config_file`] (pinned by
/// `ai_config_basenames_are_canonical`). MCP server configs are DELIBERATELY
/// excluded — counted separately via `detect_mcp_configs` to avoid double-count.
const AI_CONFIG_BASENAMES: &[&str] = &[
    "CLAUDE.md",
    "AGENTS.md",
    "AGENTS.override.md",
    ".cursorrules",
    ".cursorignore",
    ".clinerules",
    ".roorules",
    ".windsurfrules",
    ".goosehints",
    "copilot-instructions.md",
    "GEMINI.md",
    "QWEN.md",
    "llms.txt",
    "llms-full.txt",
];

/// Detect AI-config files / directories across the full agent-instruction
/// surface `tirith ai` / the `aifile` rules treat as AI config (not just the
/// `CLAUDE.md`/`.cursorrules`/`AGENTS.md` trio), so the auto recommendation
/// isn't undercounted: the [`AI_CONFIG_BASENAMES`] root files (each gated
/// through the canonical classifier), `.github/copilot-instructions.md`, themed
/// `.clinerules-*`/`.roorules-*`, `.claude/`, and any `.cursor/rules/` entry.
fn detect_ai_config(root: &Path) -> Vec<String> {
    use tirith_core::rules::aifile;

    let mut found = Vec::new();

    // Root-level files, gated through the canonical AI-config predicate so this
    // detector can't drift from what the rest of the tool treats as AI config.
    for name in AI_CONFIG_BASENAMES {
        let path = root.join(name);
        if path.is_file() && aifile::is_ai_config_file(&path) {
            found.push((*name).to_string());
        }
    }

    // Copilot's repo-scoped instructions live under `.github/`.
    let gh_copilot = root.join(".github").join("copilot-instructions.md");
    if gh_copilot.is_file() {
        found.push(".github/copilot-instructions.md".to_string());
    }

    // Themed `.clinerules-<theme>` / `.roorules-<mode>` at the root — glob via
    // `read_dir` rather than enumerating themes.
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let lower = name.to_ascii_lowercase();
            if (lower.starts_with(".clinerules-") || lower.starts_with(".roorules-"))
                && entry.path().is_file()
                && aifile::is_ai_config_file(&entry.path())
            {
                found.push(name.into_owned());
            }
        }
    }

    if root.join(".claude").is_dir() {
        found.push(".claude/".to_string());
    }
    // `.cursor/rules/*` — any entry counts as a signal.
    let cursor_rules = root.join(".cursor").join("rules");
    if cursor_rules.is_dir() {
        let has_entry = std::fs::read_dir(&cursor_rules)
            .map(|mut entries| entries.next().is_some())
            .unwrap_or(false);
        if has_entry {
            found.push(".cursor/rules/".to_string());
        }
    }
    // Sort for a STABLE order (R19-N1): the `read_dir`-driven themed-rules glob
    // is OS-order-dependent, so without this the `--json` array could reorder.
    found.sort();
    found
}

/// Detect which package managers are on `PATH` via `path_audit::which_all` (no
/// shelling out). PATH-dependent, so tests do NOT assert on this list.
fn detect_package_managers() -> Vec<String> {
    let path_value = std::env::var("PATH").unwrap_or_default();
    PACKAGE_MANAGERS
        .iter()
        .filter(|(binary, _)| !tirith_core::path_audit::which_all(binary, &path_value).is_empty())
        .map(|(_, label)| (*label).to_string())
        .collect()
}

/// Detect lockfiles present at the repo root.
fn detect_lockfiles(root: &Path) -> Vec<String> {
    LOCKFILES
        .iter()
        .filter(|(rel, _)| root.join(rel).is_file())
        .map(|(_, label)| (*label).to_string())
        .collect()
}

/// `true` when `.github/workflows/` holds at least one `*.yml` / `*.yaml` file.
fn detect_ci(root: &Path) -> bool {
    let workflows = root.join(".github").join("workflows");
    let entries = match std::fs::read_dir(&workflows) {
        Ok(e) => e,
        Err(_) => return false,
    };
    entries.flatten().any(|entry| {
        // Only a REGULAR FILE counts — a dir named like `pipeline.yaml` must not
        // flip detection (R22). IO errors are treated conservatively as non-CI.
        if !entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            return false;
        }
        entry
            .path()
            .extension()
            .and_then(|e| e.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml"))
            .unwrap_or(false)
    })
}

/// Resolve the user's home dir env-first (`$HOME` / `%USERPROFILE%`) over
/// `home::home_dir()`.
///
/// `home::home_dir()` can fall back to `getpwuid_r` (macOS), returning the real
/// passwd home and making the MCP scan ([`detect_mcp_configs`]) impossible to
/// isolate in tests. Reading the env first keeps production identical while
/// letting tests point at a temp home on every OS.
fn home_base() -> Option<PathBuf> {
    #[cfg(unix)]
    let env_home = std::env::var_os("HOME");
    #[cfg(not(unix))]
    let env_home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"));

    env_home
        // Only honor an ABSOLUTE override; a relative `HOME=.` would make the MCP
        // scan probe a cwd-relative `.codeium/...` and fabricate a signal (R12-5).
        .filter(|h| !h.is_empty() && Path::new(h).is_absolute())
        .map(PathBuf::from)
        .or_else(home::home_dir)
        // Final guard: the home base must be ABSOLUTE. `home::home_dir()` can
        // also yield an empty (MSRV) or relative path; this closes both holes
        // regardless of which source produced the value.
        .filter(|p| p.is_absolute())
}

/// Detect MCP config files: the repo-local surface joined onto `root`, plus the
/// home-relative Windsurf config. The home base is resolved via [`home_base`]
/// (env-first) so the scan is isolatable in tests on every OS (R11-3).
fn detect_mcp_configs(root: &Path) -> Vec<String> {
    let mut found: Vec<String> = MCP_CONFIG_RELATIVE_PATHS
        .iter()
        .filter(|rel| root.join(rel).is_file())
        .map(|rel| (*rel).to_string())
        .collect();

    if let Some(home) = home_base() {
        let windsurf = home
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json");
        if windsurf.is_file() {
            found.push(windsurf.display().to_string());
        }
    }
    // Sort for a STABLE order (R19-N1) so the serialized array is deterministic
    // regardless of how the home windsurf path interleaves.
    found.sort();
    found
}

/// Surface tirith's install state read-only: shell-hook wiring (via
/// `doctor::check_shell_profile`) and policy discoverability from `cwd`. Never
/// materializes hooks.
fn detect_tirith_state(cwd: &Path, detected_shell: &str) -> TirithState {
    let (_profile, hook_installed) =
        crate::cli::doctor::check_shell_profile(detected_shell, "tirith: onboard:");
    let cwd_str = cwd.display().to_string();
    let policy_path = tirith_core::policy::discover_local_policy_path(Some(&cwd_str));
    TirithState {
        hook_installed,
        policy_present: policy_path.is_some(),
        policy_path: policy_path.map(|p| p.display().to_string()),
    }
}

/// Inputs to the template recommendation — a struct so the mapping is
/// unit-testable without a filesystem.
struct RecommendationSignals<'a> {
    mode: Option<&'a str>,
    ai_config_count: usize,
    mcp_config_count: usize,
    ci_detected: bool,
}

/// Map detections → a shipping template, biased by `mode`.
///
/// Priority:
///   1. An explicit `--repo|--team|--ai-agent-heavy` mode wins outright.
///   2. Heavy AI-config / MCP presence → `ai-agent-heavy`.
///   3. A CI repo (`.github/workflows`) → `ci-strict`.
///   4. Otherwise → `individual`.
fn recommend_template(signals: &RecommendationSignals) -> (PolicyTemplate, String) {
    // 1. Explicit mode bias.
    match signals.mode {
        Some("ai-agent-heavy") => {
            return (
                PolicyTemplate::AiAgentHeavy,
                "requested --ai-agent-heavy".to_string(),
            );
        }
        Some("team") => {
            return (
                PolicyTemplate::Startup,
                "requested --team (balanced shared defaults for a human team)".to_string(),
            );
        }
        Some("repo") => {
            // A "repo" bias still respects a CI signal (ci-strict), else individual.
            if signals.ci_detected {
                return (
                    PolicyTemplate::CiStrict,
                    "requested --repo and a .github/workflows CI pipeline is present".to_string(),
                );
            }
            return (
                PolicyTemplate::Individual,
                "requested --repo with no CI pipeline detected".to_string(),
            );
        }
        _ => {}
    }

    // 2. Auto: heavy AI-agent surface.
    if signals.ai_config_count >= 2 || signals.mcp_config_count >= 1 {
        return (
            PolicyTemplate::AiAgentHeavy,
            format!(
                "{} AI-config file(s) and {} MCP config(s) detected — an AI-agent-heavy environment",
                signals.ai_config_count, signals.mcp_config_count
            ),
        );
    }

    // 3. Auto: CI repo.
    if signals.ci_detected {
        return (
            PolicyTemplate::CiStrict,
            "a .github/workflows CI pipeline is present".to_string(),
        );
    }

    // 4. Auto: default.
    (
        PolicyTemplate::Individual,
        "no CI or heavy AI-agent signals — sensible single-developer defaults".to_string(),
    )
}

/// Build the ordered next-actions list from tirith's state and the template.
fn build_next_actions(tirith: &TirithState, template: PolicyTemplate) -> Vec<String> {
    let mut actions = Vec::new();
    if !tirith.hook_installed {
        actions.push(
            "run `tirith init` and add the printed line to your shell profile to install the hook"
                .to_string(),
        );
    }
    if !tirith.policy_present {
        actions.push(format!(
            "run `tirith policy init --template {}`",
            template.canonical_name()
        ));
    }
    if actions.is_empty() {
        actions.push(
            "tirith is already set up here — run `tirith doctor` to confirm protection status"
                .to_string(),
        );
    }
    actions
}

/// Print the human-readable detection report.
fn print_human(report: &OnboardReport) {
    println!("tirith onboard — environment detection");
    println!("  directory:   {}", report.cwd);
    if let Some(root) = &report.repo_root {
        println!("  repo root:   {root}");
    }
    if report.requested_mode != "auto" {
        println!("  mode bias:   --{}", report.requested_mode);
    }
    println!("  shell:       {}", report.detected_shell);
    println!("  IDE configs: {}", fmt_list(&report.ide_configs));
    println!("  AI configs:  {}", fmt_list(&report.ai_config_files));
    println!("  pkg mgrs:    {}", fmt_list(&report.package_managers));
    println!("  lockfiles:   {}", fmt_list(&report.lockfiles));
    println!(
        "  CI:          {}",
        if report.ci_detected {
            ".github/workflows present"
        } else {
            "none"
        }
    );
    println!("  MCP configs: {}", fmt_list(&report.mcp_configs));
    println!();

    println!("tirith status");
    println!(
        "  shell hook:  {}",
        if report.tirith.hook_installed {
            "installed"
        } else {
            "not installed"
        }
    );
    match &report.tirith.policy_path {
        Some(p) => println!("  policy:      {p}"),
        None => println!("  policy:      none"),
    }
    println!();

    println!(
        "Recommended policy template: {}",
        report.recommended_template
    );
    println!("  why: {}", report.recommendation_reason);
    println!();
    println!("Next steps:");
    for (i, action) in report.next_actions.iter().enumerate() {
        println!("  {}. {action}", i + 1);
    }
}

/// Render a string list for the human report, or `(none)` when empty.
fn fmt_list(items: &[String]) -> String {
    if items.is_empty() {
        "(none)".to_string()
    } else {
        items.join(", ")
    }
}

/// `--apply`: perform the recommended SAFE actions with per-step stdin
/// confirmation. Refuses (exit 1) when stdin/stderr aren't a TTY so a piped/CI
/// run doesn't look like a success. Only invokes safe ops (`policy init`,
/// `init`); never overwrites an existing policy without confirmation.
fn apply_actions(report: &OnboardReport) -> i32 {
    apply_actions_with_interactivity(report, is_tty_pair())
}

/// [`apply_actions`] with the interactivity decision INJECTED — split out
/// (R15) so the non-interactive refusal path is unit-testable deterministically
/// regardless of the runner's ambient TTY.
fn apply_actions_with_interactivity(report: &OnboardReport, interactive: bool) -> i32 {
    println!();

    // Idempotency: with hook AND policy already present there is nothing to do,
    // so `--apply` is a no-op REGARDLESS of TTY — return success BEFORE the
    // non-interactive refusal (else a piped CI run on a configured repo would
    // exit 1 and masquerade as failure, R12-6).
    let needs_hook = !report.tirith.hook_installed;
    let needs_policy = !report.tirith.policy_present;
    if !needs_hook && !needs_policy {
        println!("tirith onboard: no actions applied.");
        return 0;
    }

    if !interactive {
        // Non-interactive: refuse rather than silently mutate; exit NON-ZERO so a
        // CI/piped `--apply` doesn't look like a success (finding N).
        eprintln!("tirith onboard --apply: not an interactive terminal — refusing to act.");
        eprintln!("  Re-run interactively to apply, or perform these steps yourself:");
        for action in &report.next_actions {
            eprintln!("    - {action}");
        }
        return 1;
    }

    let mut performed = 0;
    // Set when a step fails, so the exit code propagates it rather than masking
    // it as success (finding N).
    let mut failed = false;

    // 1. Install the shell hook (idempotent; `init` prints the eval line and
    //    materializes assets — it does not edit the profile).
    if !report.tirith.hook_installed
        && confirm_stdin("Show the `tirith init` shell-hook line to install?")
    {
        let rc = crate::cli::init::run(None, false);
        if rc == 0 {
            println!(
                "  Add the line above to your shell profile, then restart your shell or `source` it."
            );
            performed += 1;
        } else {
            eprintln!("  `tirith init` failed (exit code {rc}).");
            failed = true;
        }
    }

    // 2. Create the recommended policy — only when none exists (never clobber).
    if report.tirith.policy_present {
        println!(
            "  A policy already exists at {} — leaving it untouched.",
            report.tirith.policy_path.as_deref().unwrap_or("<unknown>")
        );
    } else if confirm_stdin(&format!(
        "Run `tirith policy init --template {}`?",
        report.recommended_template
    )) {
        // `policy::init` is no-clobber without --force, safe even if a policy
        // raced in after detection.
        let rc = crate::cli::policy::init(false, false, Some(&report.recommended_template));
        if rc == 0 {
            performed += 1;
        } else {
            eprintln!("  `tirith policy init` failed (exit code {rc}).");
            failed = true;
        }
    }

    if performed == 0 {
        println!("tirith onboard: no actions applied.");
    } else {
        println!("tirith onboard: applied {performed} action(s).");
    }
    // Propagate any step failure as a non-zero exit.
    if failed {
        1
    } else {
        0
    }
}

/// Interactive `[y/N]` prompt reading a line from stdin. The prompt goes to
/// STDERR (the stream [`is_tty_pair`] gates on) so it stays visible when stdout
/// is redirected (R8); a non-`y`/`yes` answer or read error declines.
fn confirm_stdin(prompt: &str) -> bool {
    use std::io::Write;
    eprint!("{prompt} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut input = String::new();
    match std::io::stdin().read_line(&mut input) {
        Ok(_) => matches!(input.trim(), "y" | "Y" | "yes" | "Yes"),
        Err(e) => {
            eprintln!("tirith onboard: could not read confirmation input: {e}");
            false
        }
    }
}

/// `--apply` needs BOTH stdin and stderr to be a TTY — the same pair
/// `tirith fix` gates its interactive rewrite on.
fn is_tty_pair() -> bool {
    is_terminal::is_terminal(std::io::stdin()) && is_terminal::is_terminal(std::io::stderr())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recommend_explicit_modes_win() {
        let ai = recommend_template(&RecommendationSignals {
            mode: Some("ai-agent-heavy"),
            ai_config_count: 0,
            mcp_config_count: 0,
            ci_detected: false,
        });
        assert_eq!(ai.0, PolicyTemplate::AiAgentHeavy);

        // `--team` maps to the balanced `startup` preset, not the CI one (finding M).
        let team = recommend_template(&RecommendationSignals {
            mode: Some("team"),
            ai_config_count: 0,
            mcp_config_count: 0,
            ci_detected: false,
        });
        assert_eq!(team.0, PolicyTemplate::Startup);

        // `--repo` respects a CI signal but otherwise picks individual.
        let repo_ci = recommend_template(&RecommendationSignals {
            mode: Some("repo"),
            ai_config_count: 0,
            mcp_config_count: 0,
            ci_detected: true,
        });
        assert_eq!(repo_ci.0, PolicyTemplate::CiStrict);
        let repo_plain = recommend_template(&RecommendationSignals {
            mode: Some("repo"),
            ai_config_count: 5,
            mcp_config_count: 5,
            ci_detected: false,
        });
        assert_eq!(
            repo_plain.0,
            PolicyTemplate::Individual,
            "an explicit --repo bias must not be overridden by auto AI-agent signals"
        );
    }

    #[test]
    fn recommend_auto_prioritizes_ai_then_ci_then_individual() {
        // 2+ AI configs → ai-agent-heavy, even with CI.
        let ai = recommend_template(&RecommendationSignals {
            mode: None,
            ai_config_count: 2,
            mcp_config_count: 0,
            ci_detected: true,
        });
        assert_eq!(ai.0, PolicyTemplate::AiAgentHeavy);

        // A single MCP config alone is enough for ai-agent-heavy.
        let mcp = recommend_template(&RecommendationSignals {
            mode: None,
            ai_config_count: 0,
            mcp_config_count: 1,
            ci_detected: false,
        });
        assert_eq!(mcp.0, PolicyTemplate::AiAgentHeavy);

        // CI without a heavy AI surface → ci-strict.
        let ci = recommend_template(&RecommendationSignals {
            mode: None,
            ai_config_count: 1,
            mcp_config_count: 0,
            ci_detected: true,
        });
        assert_eq!(ci.0, PolicyTemplate::CiStrict);

        // Nothing notable → individual.
        let individual = recommend_template(&RecommendationSignals {
            mode: None,
            ai_config_count: 0,
            mcp_config_count: 0,
            ci_detected: false,
        });
        assert_eq!(individual.0, PolicyTemplate::Individual);
    }

    #[test]
    fn next_actions_reflect_install_state() {
        // Fresh machine: both hook and policy actions.
        let fresh = build_next_actions(
            &TirithState {
                hook_installed: false,
                policy_present: false,
                policy_path: None,
            },
            PolicyTemplate::Individual,
        );
        assert!(fresh.iter().any(|a| a.contains("tirith init")));
        assert!(fresh
            .iter()
            .any(|a| a.contains("tirith policy init --template individual")));

        // Fully set up: a single "already set up" line.
        let done = build_next_actions(
            &TirithState {
                hook_installed: true,
                policy_present: true,
                policy_path: Some("/repo/.tirith/policy.yaml".to_string()),
            },
            PolicyTemplate::CiStrict,
        );
        assert_eq!(done.len(), 1);
        assert!(done[0].contains("already set up"));
    }

    /// Minimal [`OnboardReport`] for `apply_actions` tests, varying only the
    /// install state that drives the idempotency / refusal decision.
    fn report_with_state(hook_installed: bool, policy_present: bool) -> OnboardReport {
        OnboardReport {
            schema_version: ONBOARD_SCHEMA_VERSION,
            cwd: ".".to_string(),
            repo_root: None,
            requested_mode: "auto".to_string(),
            detected_shell: "bash".to_string(),
            ide_configs: vec![],
            ai_config_files: vec![],
            package_managers: vec![],
            lockfiles: vec![],
            ci_detected: false,
            mcp_configs: vec![],
            tirith: TirithState {
                hook_installed,
                policy_present,
                policy_path: policy_present.then(|| "/repo/.tirith/policy.yaml".to_string()),
            },
            recommended_template: "individual".to_string(),
            recommendation_reason: "test".to_string(),
            next_actions: vec!["do a thing".to_string()],
        }
    }

    /// R12-6: a non-interactive `--apply` on an already-configured repo is a
    /// NO-OP → exit 0, not the refusal (exit 1). `interactive = false` makes it
    /// deterministic regardless of the runner's TTY (R15).
    #[test]
    fn apply_actions_noop_when_already_configured_returns_zero() {
        let report = report_with_state(true, true);
        assert_eq!(
            apply_actions_with_interactivity(&report, false),
            0,
            "an already-configured repo has nothing to apply — must exit 0 even non-interactively"
        );
    }

    /// R12-6 (converse): with a mutating step to do (hook missing), a
    /// non-interactive apply still refuses → exit 1. Proves the no-op
    /// short-circuit fires ONLY when nothing is needed.
    #[test]
    fn apply_actions_noninteractive_with_work_returns_one() {
        // Policy present but hook missing → a real step remains → refusal (exit 1).
        let report = report_with_state(false, true);
        assert_eq!(
            apply_actions_with_interactivity(&report, false),
            1,
            "a non-interactive --apply with work to do must refuse (exit 1)"
        );
    }

    /// R7-5: every [`AI_CONFIG_BASENAMES`] entry must be recognised by the
    /// canonical AI-config classifier, so the two can't silently diverge.
    #[test]
    fn ai_config_basenames_are_canonical() {
        use tirith_core::rules::aifile;
        for name in AI_CONFIG_BASENAMES {
            assert!(
                aifile::is_ai_config_file(Path::new(name)),
                "{name:?} is in AI_CONFIG_BASENAMES but is NOT recognised by the canonical \
                 is_ai_config_file — the onboard detector has drifted from the product's set"
            );
        }
    }

    /// R7-5: the AI-config detector covers the broader surface, not just the
    /// `CLAUDE.md`/`.cursorrules`/`AGENTS.md` trio — with 2+ such files the AUTO
    /// recommendation must reach `ai-agent-heavy`.
    #[test]
    fn detect_ai_config_recognizes_broader_signals() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        // None of these three is in the original trio (pre-R7-5 counted ZERO).
        std::fs::write(root.join("copilot-instructions.md"), "# copilot\n").unwrap();
        std::fs::write(root.join(".clinerules"), "rules\n").unwrap();
        std::fs::write(root.join(".clinerules-security"), "themed\n").unwrap();

        let found = detect_ai_config(root);
        assert!(
            found.iter().any(|f| f == "copilot-instructions.md"),
            "copilot-instructions.md must be detected as AI config, got: {found:?}"
        );
        assert!(
            found.iter().any(|f| f == ".clinerules"),
            ".clinerules must be detected as AI config, got: {found:?}"
        );
        assert!(
            found.iter().any(|f| f == ".clinerules-security"),
            "themed .clinerules-* must be detected as AI config, got: {found:?}"
        );

        // The broadened count (>= 2) drives the AUTO recommendation to ai-agent-heavy.
        let (template, _why) = recommend_template(&RecommendationSignals {
            mode: None,
            ai_config_count: found.len(),
            mcp_config_count: 0,
            ci_detected: false,
        });
        assert_eq!(
            template,
            PolicyTemplate::AiAgentHeavy,
            "a repo with multiple broader AI-config signals must recommend ai-agent-heavy"
        );
    }

    /// R19-N1: `ai_config_files` must be SORTED so the `--json` report is
    /// deterministic — the `read_dir`-driven themed-rules glob is OS-order
    /// dependent. Plant a multi-file tree spanning all three code paths.
    #[test]
    fn detect_ai_config_is_sorted_for_stable_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        // Basename-loop entries (natural order differs from sorted order).
        std::fs::write(root.join("CLAUDE.md"), "x\n").unwrap();
        std::fs::write(root.join(".cursorrules"), "x\n").unwrap();
        std::fs::write(root.join("AGENTS.md"), "x\n").unwrap();
        // read_dir-driven themed rules — the non-deterministic source.
        std::fs::write(root.join(".clinerules-security"), "x\n").unwrap();
        std::fs::write(root.join(".clinerules-perf"), "x\n").unwrap();
        std::fs::write(root.join(".roorules-review"), "x\n").unwrap();
        // Directory-signal entries appended after the loops.
        std::fs::create_dir_all(root.join(".claude")).unwrap();
        std::fs::create_dir_all(root.join(".cursor").join("rules")).unwrap();
        std::fs::write(root.join(".cursor").join("rules").join("a.mdc"), "rule\n").unwrap();

        let found = detect_ai_config(root);
        let mut sorted = found.clone();
        sorted.sort();
        assert_eq!(
            found, sorted,
            "ai_config_files must be returned in sorted order for deterministic JSON, got: {found:?}"
        );
        // Sanity: the tree populated all three paths.
        assert!(found.iter().any(|f| f == "CLAUDE.md"));
        assert!(found.iter().any(|f| f == ".clinerules-security"));
        assert!(found.iter().any(|f| f == ".claude/"));
        assert!(found.iter().any(|f| f == ".cursor/rules/"));
    }

    /// R19-N1: `mcp_configs` is likewise returned sorted, so the `--json` array
    /// is deterministic.
    #[test]
    fn detect_mcp_configs_is_sorted_for_stable_json() {
        let repo = tempfile::tempdir().expect("repo");
        let root = repo.path();
        // Plant configs whose table order is NOT sorted order.
        std::fs::write(root.join("mcp.json"), "{}\n").unwrap();
        std::fs::create_dir_all(root.join(".vscode")).unwrap();
        std::fs::write(root.join(".vscode").join("mcp.json"), "{}\n").unwrap();
        std::fs::create_dir_all(root.join(".cursor")).unwrap();
        std::fs::write(root.join(".cursor").join("mcp.json"), "{}\n").unwrap();

        // Isolate the home base so a runner's real ~/.codeium can't leak in.
        let home = tempfile::tempdir().expect("home");
        let _guard = HomeGuard::set(home.path());

        let found = detect_mcp_configs(root);
        let mut sorted = found.clone();
        sorted.sort();
        assert_eq!(
            found, sorted,
            "mcp_configs must be returned in sorted order for deterministic JSON, got: {found:?}"
        );
        assert!(
            found.len() >= 3,
            "expected the three planted repo-local MCP configs, got: {found:?}"
        );
    }

    /// R7-5: `.github/copilot-instructions.md` is also a recognised AI signal.
    #[test]
    fn detect_ai_config_finds_github_copilot_instructions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir_all(root.join(".github")).unwrap();
        std::fs::write(
            root.join(".github").join("copilot-instructions.md"),
            "# copilot\n",
        )
        .unwrap();

        let found = detect_ai_config(root);
        assert!(
            found.iter().any(|f| f == ".github/copilot-instructions.md"),
            ".github/copilot-instructions.md must be detected, got: {found:?}"
        );
    }

    /// F3: `detect_ci` counts only REGULAR FILES under `.github/workflows/` — a
    /// dir named `pipeline.yaml` must not flip detection. Both halves covered.
    #[test]
    fn detect_ci_requires_regular_file_not_directory() {
        // Half 1: a real workflow FILE → CI detected.
        let with_file = tempfile::tempdir().expect("tempdir");
        let wf = with_file.path().join(".github").join("workflows");
        std::fs::create_dir_all(&wf).unwrap();
        std::fs::write(wf.join("ci.yml"), "on: push\n").unwrap();
        assert!(
            detect_ci(with_file.path()),
            "a real *.yml workflow FILE must be detected as CI"
        );

        // Half 2: the workflows dir holds ONLY a `pipeline.yaml/` dir → NOT CI.
        let dir_only = tempfile::tempdir().expect("tempdir");
        let wf2 = dir_only.path().join(".github").join("workflows");
        std::fs::create_dir_all(wf2.join("pipeline.yaml")).unwrap();
        assert!(
            !detect_ci(dir_only.path()),
            "a DIRECTORY named *.yaml under workflows must NOT be counted as CI"
        );
    }

    /// F3 (no-regression): a missing `.github/workflows/` dir still reads as
    /// non-CI (the IO-error branch).
    #[test]
    fn detect_ci_absent_workflows_dir_is_not_ci() {
        let empty = tempfile::tempdir().expect("tempdir");
        assert!(
            !detect_ci(empty.path()),
            "no .github/workflows dir must read as non-CI"
        );
    }

    // `HOME` / `USERPROFILE` are process-global; reuse the crate-wide
    // `test_harness::{ENV_LOCK, EnvGuard}` every env-mutating test serialises on
    // so the R11-3 temp-home tests don't race. `HomeGuard` holds the lock plus an
    // `EnvGuard` per var, restoring both on Drop.
    use crate::cli::test_harness::{EnvGuard, ENV_LOCK};

    struct HomeGuard {
        // Teardown order is enforced by the `Drop` impl (env guards before the
        // lock), not field order — each field is an `Option` so `drop` can
        // `.take()` them one at a time.
        home: Option<EnvGuard>,
        userprofile: Option<EnvGuard>,
        lock: Option<std::sync::MutexGuard<'static, ()>>,
    }

    impl HomeGuard {
        /// Point BOTH `HOME` and `USERPROFILE` at `dir` so [`home_base`] resolves
        /// there on every OS. Holds `ENV_LOCK`; `EnvGuard`s restore on Drop.
        fn set(dir: &Path) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let home = EnvGuard::set("HOME", dir);
            let userprofile = EnvGuard::set("USERPROFILE", dir);
            Self {
                home: Some(home),
                userprofile: Some(userprofile),
                lock: Some(lock),
            }
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            // Restore the env vars FIRST, release the lock LAST — so no other
            // env-mutating test observes HOME/USERPROFILE before they're restored.
            drop(self.home.take());
            drop(self.userprofile.take());
            drop(self.lock.take());
        }
    }

    /// R11-3: [`home_base`] resolves from the env, NOT the OS passwd entry, so
    /// the MCP scan is isolatable on every OS. Also the ABSOLUTE half of R12-5.
    #[test]
    fn home_base_resolves_from_env() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _guard = HomeGuard::set(dir.path());
        assert_eq!(
            home_base(),
            Some(dir.path().to_path_buf()),
            "home_base must honor the HOME/USERPROFILE env override"
        );
    }

    /// R12-5: a RELATIVE `$HOME`/`%USERPROFILE%` must NOT be returned — it would
    /// make the MCP scan probe a cwd-relative `.codeium/...`. Falls back to
    /// `home::home_dir()` instead.
    #[test]
    fn home_base_rejects_relative_home() {
        // Hold the lock and override BOTH vars so a panic can't leak the relative
        // env into a sibling test (guards restore on Drop).
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _home = EnvGuard::set("HOME", Path::new("relative-home"));
        let _userprofile = EnvGuard::set("USERPROFILE", Path::new("relative-home"));

        let base = home_base();

        // Must not echo back the relative override; the fallback must be absolute.
        assert_ne!(
            base.as_deref(),
            Some(Path::new("relative-home")),
            "home_base must not return a relative HOME/USERPROFILE override"
        );
        if let Some(p) = &base {
            assert!(
                p.is_absolute(),
                "home_base fallback must be absolute, got {p:?}"
            );
        }
    }

    /// R11-3: an EMPTY `HOME`/`USERPROFILE` is treated as unset (a naive
    /// `var_os` would return `Some("")` and anchor the scan at a bogus path), so
    /// `home_base` falls back to an absolute path or `None`, never `Some("")`.
    #[test]
    fn home_base_treats_empty_env_as_unset() {
        // Hold the lock and override BOTH vars to empty (guards restore on Drop).
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _home = EnvGuard::set("HOME", Path::new(""));
        let _userprofile = EnvGuard::set("USERPROFILE", Path::new(""));

        let base = home_base();

        assert_ne!(
            base.as_deref(),
            Some(Path::new("")),
            "home_base must not return an empty path for an empty HOME/USERPROFILE"
        );
        if let Some(p) = &base {
            assert!(
                !p.as_os_str().is_empty(),
                "home_base fallback must be a non-empty path, got {p:?}"
            );
        }
    }

    /// R11-3 (the core fix): the home-relative Windsurf MCP config is detected
    /// under the ENV-resolved home, and an empty repo yields ZERO regardless of
    /// the host's real `~/.codeium` — keeping the integration test deterministic.
    #[test]
    fn detect_mcp_configs_uses_env_home_for_windsurf() {
        let repo = tempfile::tempdir().expect("repo");

        // Case 1: isolated home WITHOUT a windsurf config → zero MCP configs.
        let home_absent = tempfile::tempdir().expect("home_absent");
        {
            let _guard = HomeGuard::set(home_absent.path());
            let found = detect_mcp_configs(repo.path());
            assert!(
                found.is_empty(),
                "an isolated home with no windsurf config must yield 0 MCP configs \
                 (host's real ~/.codeium must not leak in), got: {found:?}"
            );
        }

        // Case 2: plant the windsurf config UNDER the isolated home → detected.
        let home_present = tempfile::tempdir().expect("home_present");
        let windsurf_dir = home_present.path().join(".codeium").join("windsurf");
        std::fs::create_dir_all(&windsurf_dir).unwrap();
        let windsurf_cfg = windsurf_dir.join("mcp_config.json");
        std::fs::write(&windsurf_cfg, "{}\n").unwrap();
        {
            let _guard = HomeGuard::set(home_present.path());
            let found = detect_mcp_configs(repo.path());
            assert!(
                found
                    .iter()
                    .any(|f| f == &windsurf_cfg.display().to_string()),
                "a windsurf MCP config under the isolated home must be detected, got: {found:?}"
            );
        }
    }
}
