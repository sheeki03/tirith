//! `tirith ecosystem scan` — supply-chain risk scan of a project's dependency
//! manifests. The directory-level companion to [`crate::package_risk`]: it
//! discovers every dependency a project *declares* and scores each with the
//! same deterministic factor engine (no model, reproducible by hand).
//!
//! It discovers manifests via a bounded walk, parses declared dependencies
//! (parsers never execute the manifest or reach the network), scores each
//! through [`package_risk::score_package`] (with an opt-in `--online`
//! registry pass), and folds in slopsquat detection — see [`slopsquat`].
//!
//! Output is a [`Verdict`] of [`Finding`]s like the detection engine
//! (explainable, audit-loggable, policy-aware), reusing the existing
//! package-supply-chain [`RuleId`]s rather than inventing new ones.
//!
//! Every function is pure and total except the filesystem walk and the
//! opt-in registry fetch; given the same inputs the verdict is reproducible.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::package_risk::{
    self, ApiSignals, ContentSignals, NameVsPopular, PackageSignals, RiskBreakdown,
};
use crate::threatdb::{Ecosystem, ThreatDb};
use crate::verdict::{Action, Evidence, Finding, RuleId, Severity, Timings, Verdict};

/// Maximum directory depth the manifest walk descends.
pub const MAX_WALK_DEPTH: usize = 6;

/// Hard cap on directory entries examined during the walk.
pub const MAX_WALK_ENTRIES: usize = 50_000;

/// Hard cap on declared dependencies scored in a single run. Excess is still
/// parsed; scoring stops at the cap and the summary records the truncation.
pub const MAX_DEPENDENCIES: usize = 5_000;

/// Default cap on installed-tree entries (one entry = one installed package
/// directory). Configurable via `--max-installed-entries`; `0` means unbounded.
pub const DEFAULT_MAX_INSTALLED_ENTRIES: usize = 5_000;

/// Directory names never descended into — build output and vendored trees hold
/// installed content, not declared manifests, and would dominate the walk.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    ".git",
    "vendor",
    "site-packages",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".cargo",
];

/// A dependency-manifest file format `ecosystem scan` understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestKind {
    /// npm `package.json` — `dependencies` + `devDependencies` maps.
    NpmPackageJson,
    /// npm `package-lock.json` — the fully-resolved tree (covers transitives).
    NpmPackageLock,
    /// Python `requirements.txt` — one requirement specifier per line.
    PyRequirementsTxt,
    /// Python `pyproject.toml` — PEP 621 + Poetry dependency tables.
    PyPyprojectToml,
    /// Rust `Cargo.toml` — `[dependencies]` and friends.
    CargoToml,
    /// Go `go.mod` — `require` directives.
    GoMod,
    /// Ruby `Gemfile` — `gem "name"` directives.
    RubyGemfile,
}

impl ManifestKind {
    /// The ecosystem a manifest of this kind declares packages for.
    pub fn ecosystem(self) -> Ecosystem {
        match self {
            ManifestKind::NpmPackageJson | ManifestKind::NpmPackageLock => Ecosystem::Npm,
            ManifestKind::PyRequirementsTxt | ManifestKind::PyPyprojectToml => Ecosystem::PyPI,
            ManifestKind::CargoToml => Ecosystem::Crates,
            ManifestKind::GoMod => Ecosystem::Go,
            ManifestKind::RubyGemfile => Ecosystem::RubyGems,
        }
    }

    /// A stable, human / machine label for the manifest format.
    pub fn label(self) -> &'static str {
        match self {
            ManifestKind::NpmPackageJson => "package.json",
            ManifestKind::NpmPackageLock => "package-lock.json",
            ManifestKind::PyRequirementsTxt => "requirements.txt",
            ManifestKind::PyPyprojectToml => "pyproject.toml",
            ManifestKind::CargoToml => "Cargo.toml",
            ManifestKind::GoMod => "go.mod",
            ManifestKind::RubyGemfile => "Gemfile",
        }
    }

    /// Classify a file name as a known manifest, if it is one.
    /// `requirements.txt` matching is loosened to any `requirements*.txt`.
    pub fn from_file_name(name: &str) -> Option<ManifestKind> {
        match name {
            "package.json" => Some(ManifestKind::NpmPackageJson),
            "package-lock.json" => Some(ManifestKind::NpmPackageLock),
            "pyproject.toml" => Some(ManifestKind::PyPyprojectToml),
            "Cargo.toml" => Some(ManifestKind::CargoToml),
            "go.mod" => Some(ManifestKind::GoMod),
            "Gemfile" => Some(ManifestKind::RubyGemfile),
            other => {
                if other.starts_with("requirements") && other.ends_with(".txt") {
                    Some(ManifestKind::PyRequirementsTxt)
                } else {
                    None
                }
            }
        }
    }
}

/// A discovered manifest file on disk.
#[derive(Debug, Clone)]
pub struct DiscoveredManifest {
    /// Absolute or scan-root-relative path to the manifest file.
    pub path: PathBuf,
    /// Which manifest format it is.
    pub kind: ManifestKind,
}

/// Walk `root` and return every dependency manifest found, bounded by
/// [`MAX_WALK_DEPTH`] and [`MAX_WALK_ENTRIES`]. [`SKIP_DIRS`] are not
/// descended; reads only directory entries, never file content. A file `root`
/// returns that single manifest. Result is sorted by path for determinism.
pub fn discover_manifests(root: &Path) -> Vec<DiscoveredManifest> {
    let mut found: Vec<DiscoveredManifest> = Vec::new();

    // A file root: classify it directly.
    if root.is_file() {
        if let Some(kind) = root
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(ManifestKind::from_file_name)
        {
            found.push(DiscoveredManifest {
                path: root.to_path_buf(),
                kind,
            });
        }
        return found;
    }

    // Iterative walk with an explicit work stack (no recursion, so depth is a
    // hard bound and a deep tree cannot blow the stack). Sorted before return.
    let mut examined = 0usize;
    let mut queue: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = queue.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            examined += 1;
            if examined > MAX_WALK_ENTRIES {
                found.sort_by(|a, b| a.path.cmp(&b.path));
                return found;
            }
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if SKIP_DIRS.iter().any(|d| *d == name) {
                    continue;
                }
                if depth < MAX_WALK_DEPTH {
                    queue.push((path, depth + 1));
                }
            } else if file_type.is_file() {
                if let Some(kind) = entry
                    .file_name()
                    .to_str()
                    .and_then(ManifestKind::from_file_name)
                {
                    found.push(DiscoveredManifest { path, kind });
                }
            }
        }
    }

    found.sort_by(|a, b| a.path.cmp(&b.path));
    found
}

/// One dependency a manifest declares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeclaredDependency {
    /// The package name as written in the manifest.
    pub name: String,
    /// The ecosystem the manifest is for.
    #[serde(serialize_with = "serialize_ecosystem")]
    pub ecosystem: Ecosystem,
    /// The version / version-range string as written, when the manifest gives one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Whether the manifest declares this as a development-only dependency.
    pub dev: bool,
}

fn serialize_ecosystem<S: serde::Serializer>(eco: &Ecosystem, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&eco.to_string())
}

/// Parse a manifest's text into the dependencies it declares. Total, never
/// panics. `Some(deps)` (possibly empty) means it parsed; `None` means the
/// manifest is malformed (a structured JSON/TOML that could not be parsed).
/// Line-based formats have no malformed state and always return `Some`.
pub fn parse_manifest(kind: ManifestKind, text: &str) -> Option<Vec<DeclaredDependency>> {
    match kind {
        ManifestKind::NpmPackageJson => parse_package_json(text),
        ManifestKind::NpmPackageLock => parse_package_lock(text),
        ManifestKind::PyRequirementsTxt => Some(parse_requirements_txt(text)),
        ManifestKind::PyPyprojectToml => parse_pyproject_toml(text),
        ManifestKind::CargoToml => parse_cargo_toml(text),
        ManifestKind::GoMod => Some(parse_go_mod(text)),
        ManifestKind::RubyGemfile => Some(parse_gemfile(text)),
    }
}

/// npm `package.json`: `dependencies`, `devDependencies`, `optionalDependencies`,
/// `peerDependencies`. `devDependencies` are tagged `dev = true`. `None` on
/// invalid JSON.
fn parse_package_json(text: &str) -> Option<Vec<DeclaredDependency>> {
    let json = serde_json::from_str::<serde_json::Value>(text).ok()?;
    let mut out = Vec::new();
    for (field, dev) in [
        ("dependencies", false),
        ("optionalDependencies", false),
        ("peerDependencies", false),
        ("devDependencies", true),
    ] {
        if let Some(map) = json.get(field).and_then(|v| v.as_object()) {
            for (name, ver) in map {
                let name = name.trim();
                if name.is_empty() {
                    continue;
                }
                out.push(DeclaredDependency {
                    name: name.to_string(),
                    ecosystem: Ecosystem::Npm,
                    version: ver.as_str().map(str::to_string).filter(|s| !s.is_empty()),
                    dev,
                });
            }
        }
    }
    Some(out)
}

/// npm `package-lock.json`: the fully-resolved tree. v2/v3 keys `packages` by
/// install path; v1 keys `dependencies` by name. Both are read to cover the
/// transitive closure.
fn parse_package_lock(text: &str) -> Option<Vec<DeclaredDependency>> {
    let json = serde_json::from_str::<serde_json::Value>(text).ok()?;
    let mut seen: BTreeSet<(String, Option<String>)> = BTreeSet::new();
    let mut out = Vec::new();

    // lockfile v2 / v3 — `packages` keyed by install path.
    if let Some(packages) = json.get("packages").and_then(|v| v.as_object()) {
        for (path_key, meta) in packages {
            // The root package is keyed by the empty string — skip it.
            let Some(name) = package_lock_name_from_path(path_key) else {
                continue;
            };
            let version = meta
                .get("version")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let dev = meta.get("dev").and_then(|v| v.as_bool()).unwrap_or(false);
            if seen.insert((name.clone(), version.clone())) {
                out.push(DeclaredDependency {
                    name,
                    ecosystem: Ecosystem::Npm,
                    version,
                    dev,
                });
            }
        }
    }

    // lockfile v1 — `dependencies` keyed by name (recursively nested).
    if let Some(deps) = json.get("dependencies").and_then(|v| v.as_object()) {
        collect_lock_v1_deps(deps, &mut seen, &mut out);
    }

    Some(out)
}

/// Extract the package name from a `package-lock.json` v2/v3 path key — the
/// segment after the LAST `node_modules/`. The empty (root) key yields `None`.
fn package_lock_name_from_path(path_key: &str) -> Option<String> {
    if path_key.is_empty() {
        return None;
    }
    let tail = match path_key.rsplit_once("node_modules/") {
        Some((_, tail)) => tail,
        None => path_key,
    };
    let tail = tail.trim_matches('/');
    if tail.is_empty() {
        return None;
    }
    Some(tail.to_string())
}

/// Recursively collect a lockfile-v1 `dependencies` tree.
fn collect_lock_v1_deps(
    deps: &serde_json::Map<String, serde_json::Value>,
    seen: &mut BTreeSet<(String, Option<String>)>,
    out: &mut Vec<DeclaredDependency>,
) {
    for (name, meta) in deps {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let version = meta
            .get("version")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let dev = meta.get("dev").and_then(|v| v.as_bool()).unwrap_or(false);
        if seen.insert((name.to_string(), version.clone())) {
            out.push(DeclaredDependency {
                name: name.to_string(),
                ecosystem: Ecosystem::Npm,
                version,
                dev,
            });
        }
        if let Some(nested) = meta.get("dependencies").and_then(|v| v.as_object()) {
            collect_lock_v1_deps(nested, seen, out);
        }
    }
}

/// Python `requirements.txt`: one PEP 508 specifier per line. Comments, blank
/// lines, and pip option lines (`-r`, `--index-url`, `-e`, …) are skipped; the
/// bare distribution name is extracted.
fn parse_requirements_txt(text: &str) -> Vec<DeclaredDependency> {
    let mut out = Vec::new();
    for raw_line in text.lines() {
        // Strip an inline comment, then trim.
        let line = match raw_line.split_once(" #") {
            Some((before, _)) => before,
            None => raw_line,
        };
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // pip directive lines (`-r other.txt`, `--index-url ...`, `-e .`).
        if line.starts_with('-') {
            continue;
        }
        // A bare URL / VCS install (`git+https://…`) has no PyPI name to score.
        if line.contains("://") {
            continue;
        }
        if let Some(name) = python_requirement_name(line) {
            out.push(DeclaredDependency {
                name,
                ecosystem: Ecosystem::PyPI,
                version: None,
                dev: false,
            });
        }
    }
    out
}

/// Extract the bare distribution name from a PEP 508 requirement line,
/// cutting at the first version operator, extras bracket, env-marker, or space.
fn python_requirement_name(line: &str) -> Option<String> {
    let name_end = line
        .find(|c: char| {
            matches!(
                c,
                '=' | '<' | '>' | '!' | '~' | '[' | ';' | ' ' | '\t' | '@' | '('
            )
        })
        .unwrap_or(line.len());
    let name = line[..name_end].trim();
    if name.is_empty() || !is_plausible_package_name(name) {
        None
    } else {
        Some(name.to_string())
    }
}

/// Python `pyproject.toml`: PEP 621 `[project].dependencies` /
/// `[project.optional-dependencies]`, plus Poetry's
/// `[tool.poetry.dependencies]` / `[tool.poetry.group.*.dependencies]`.
fn parse_pyproject_toml(text: &str) -> Option<Vec<DeclaredDependency>> {
    let doc = toml::from_str::<toml::Value>(text).ok()?;
    let mut out = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    let mut push = |name: &str, dev: bool, out: &mut Vec<DeclaredDependency>| {
        let name = name.trim();
        if name.is_empty() || !is_plausible_package_name(name) {
            return;
        }
        // `python` is the interpreter constraint in Poetry tables, not a dep.
        if name.eq_ignore_ascii_case("python") {
            return;
        }
        if seen.insert(name.to_lowercase()) {
            out.push(DeclaredDependency {
                name: name.to_string(),
                ecosystem: Ecosystem::PyPI,
                version: None,
                dev,
            });
        }
    };

    // PEP 621 `[project].dependencies` — an array of requirement strings.
    if let Some(deps) = doc
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_array())
    {
        for item in deps {
            if let Some(req) = item.as_str() {
                if let Some(name) = python_requirement_name(req) {
                    push(&name, false, &mut out);
                }
            }
        }
    }
    // PEP 621 `[project.optional-dependencies]` — a table of named arrays.
    if let Some(groups) = doc
        .get("project")
        .and_then(|p| p.get("optional-dependencies"))
        .and_then(|d| d.as_table())
    {
        for arr in groups.values() {
            if let Some(items) = arr.as_array() {
                for item in items {
                    if let Some(req) = item.as_str() {
                        if let Some(name) = python_requirement_name(req) {
                            push(&name, true, &mut out);
                        }
                    }
                }
            }
        }
    }

    // Poetry `[tool.poetry.dependencies]` — a table keyed by name.
    let poetry = doc.get("tool").and_then(|t| t.get("poetry"));
    if let Some(deps) = poetry
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_table())
    {
        for name in deps.keys() {
            push(name, false, &mut out);
        }
    }
    // Poetry dev groups + legacy `[tool.poetry.dev-dependencies]`.
    if let Some(groups) = poetry
        .and_then(|p| p.get("group"))
        .and_then(|g| g.as_table())
    {
        for group in groups.values() {
            if let Some(deps) = group.get("dependencies").and_then(|d| d.as_table()) {
                for name in deps.keys() {
                    push(name, true, &mut out);
                }
            }
        }
    }
    if let Some(deps) = poetry
        .and_then(|p| p.get("dev-dependencies"))
        .and_then(|d| d.as_table())
    {
        for name in deps.keys() {
            push(name, true, &mut out);
        }
    }

    Some(out)
}

/// Rust `Cargo.toml`: `[dependencies]`, `[build-dependencies]`,
/// `[dev-dependencies]`, and the same three under any `[target.*]` table.
fn parse_cargo_toml(text: &str) -> Option<Vec<DeclaredDependency>> {
    let doc = toml::from_str::<toml::Value>(text).ok()?;
    let mut out = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    let mut collect =
        |table: Option<&toml::Value>, dev: bool, out: &mut Vec<DeclaredDependency>| {
            let Some(table) = table.and_then(|t| t.as_table()) else {
                return;
            };
            for (name, spec) in table {
                let name = name.trim();
                if name.is_empty() || !is_plausible_package_name(name) {
                    continue;
                }
                // A `package = "real-name"` rename: score the real crate name.
                let real_name = spec
                    .as_table()
                    .and_then(|t| t.get("package"))
                    .and_then(|p| p.as_str())
                    .unwrap_or(name);
                if !is_plausible_package_name(real_name) {
                    continue;
                }
                let version = spec.as_str().map(str::to_string).or_else(|| {
                    spec.as_table()
                        .and_then(|t| t.get("version"))
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                });
                if seen.insert(real_name.to_string()) {
                    out.push(DeclaredDependency {
                        name: real_name.to_string(),
                        ecosystem: Ecosystem::Crates,
                        version,
                        dev,
                    });
                }
            }
        };

    collect(doc.get("dependencies"), false, &mut out);
    collect(doc.get("build-dependencies"), false, &mut out);
    collect(doc.get("dev-dependencies"), true, &mut out);

    // `[target.<cfg>.dependencies]` and friends.
    if let Some(targets) = doc.get("target").and_then(|t| t.as_table()) {
        for target in targets.values() {
            collect(target.get("dependencies"), false, &mut out);
            collect(target.get("build-dependencies"), false, &mut out);
            collect(target.get("dev-dependencies"), true, &mut out);
        }
    }

    Some(out)
}

/// Go `go.mod`: `require` directives, both single-line and block form. The
/// module path is taken as the package name.
fn parse_go_mod(text: &str) -> Vec<DeclaredDependency> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut in_require_block = false;

    for raw in text.lines() {
        // Strip a trailing `// comment`.
        let line = match raw.split_once("//") {
            Some((before, _)) => before,
            None => raw,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if in_require_block {
            if line == ")" {
                in_require_block = false;
                continue;
            }
            if let Some(dep) = go_mod_require_entry(line) {
                if seen.insert(dep.name.clone()) {
                    out.push(dep);
                }
            }
            continue;
        }
        if line == "require (" || line.starts_with("require (") {
            in_require_block = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix("require ") {
            if let Some(dep) = go_mod_require_entry(rest.trim()) {
                if seen.insert(dep.name.clone()) {
                    out.push(dep);
                }
            }
        }
    }
    out
}

/// Parse one `go.mod` require entry (`module version`); the caller already
/// stripped any trailing `// indirect` comment.
fn go_mod_require_entry(entry: &str) -> Option<DeclaredDependency> {
    let mut parts = entry.split_whitespace();
    let module = parts.next()?;
    if module.is_empty() || module == "(" {
        return None;
    }
    let version = parts.next().map(str::to_string);
    Some(DeclaredDependency {
        name: module.to_string(),
        ecosystem: Ecosystem::Go,
        version,
        dev: false,
    })
}

/// Ruby `Gemfile`: `gem "name"` directives. A gem inside a `group :development`
/// / `:test` block is tagged `dev = true`.
fn parse_gemfile(text: &str) -> Vec<DeclaredDependency> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    // Stack of open `… do` blocks; bool = is-dev-group. EVERY do/end is tracked
    // (not only `group`) so a nested non-dev block closing inside a dev group
    // does not wrongly clear the dev tag.
    let mut block_stack: Vec<bool> = Vec::new();

    for raw in text.lines() {
        // Strip a `#` comment.
        let line = match raw.split_once('#') {
            Some((before, _)) => before,
            None => raw,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "end" {
            block_stack.pop();
            continue;
        }
        if line.ends_with(" do") || line == "do" {
            let is_dev_group = line.strip_prefix("group ").is_some_and(|rest| {
                let lower = rest.to_lowercase();
                lower.contains("development") || lower.contains("test")
            });
            block_stack.push(is_dev_group);
            continue;
        }
        if let Some(name) = gemfile_gem_name(line) {
            if seen.insert(name.clone()) {
                out.push(DeclaredDependency {
                    name,
                    ecosystem: Ecosystem::RubyGems,
                    version: None,
                    dev: block_stack.iter().any(|&is_dev| is_dev),
                });
            }
        }
    }
    out
}

/// Extract the gem name from a `gem "name", ...` Gemfile line.
fn gemfile_gem_name(line: &str) -> Option<String> {
    let rest = line.strip_prefix("gem ")?.trim_start();
    let (quote, after) = match rest.chars().next()? {
        '"' => ('"', &rest[1..]),
        '\'' => ('\'', &rest[1..]),
        _ => return None,
    };
    let name = after.split(quote).next()?.trim();
    if name.is_empty() || !is_plausible_package_name(name) {
        None
    } else {
        Some(name.to_string())
    }
}

/// `true` when `name` is shaped like a real package name. Deliberately
/// permissive — it rejects only clearly-not-a-name strings.
fn is_plausible_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 214 {
        return false;
    }
    // ASCII alphanumerics plus the separators ecosystems allow (scopes and Go
    // module paths legitimately contain `/`).
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '/' | '+'))
}

/// The deterministic slopsquat verdict for one dependency.
///
/// *Slopsquatting* is a plausible-but-fake package name an LLM is likely to
/// hallucinate. This is advisory, not confirmed-malicious, so it is
/// conservative: it fires only when a name is unknown to the threat DB AND
/// looks AI-hallucinated AND sits near a real popular name.
///
/// The enum makes the two valid states the only representable ones:
/// `Suspicious` always carries its reasons and anchor, so [`findings_for`]
/// needs no fallback for a missing anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlopsquatAssessment {
    /// The dependency is not slopsquat-suspicious.
    Clear,
    /// The dependency is slopsquat-suspicious.
    Suspicious {
        /// Inspectable, plain-language reasons the heuristic fired; non-empty.
        reasons: Vec<String>,
        /// The real popular package the suspicious name sits near (always present).
        near_popular: String,
    },
}

impl SlopsquatAssessment {
    /// The not-suspicious verdict.
    fn clear() -> Self {
        SlopsquatAssessment::Clear
    }

    /// `true` when the dependency is slopsquat-suspicious.
    pub fn is_suspicious(&self) -> bool {
        matches!(self, SlopsquatAssessment::Suspicious { .. })
    }
}

// Hand-written `Serialize` preserves the pre-enum `--format json` shape:
// `{"suspicious": bool, "reasons": [...], "near_popular": "…"}` (the last only
// when suspicious), so a report consumer sees no change.
impl Serialize for SlopsquatAssessment {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        match self {
            SlopsquatAssessment::Clear => {
                let mut st = serializer.serialize_struct("SlopsquatAssessment", 2)?;
                st.serialize_field("suspicious", &false)?;
                st.serialize_field("reasons", &Vec::<String>::new())?;
                st.end()
            }
            SlopsquatAssessment::Suspicious {
                reasons,
                near_popular,
            } => {
                let mut st = serializer.serialize_struct("SlopsquatAssessment", 3)?;
                st.serialize_field("suspicious", &true)?;
                st.serialize_field("reasons", reasons)?;
                st.serialize_field("near_popular", near_popular)?;
                st.end()
            }
        }
    }
}

/// Common English words an LLM strings together when hallucinating a
/// descriptive-but-fake package name (`aws-helper-utils`, `data-parser-tool`).
/// A name built mostly from these generic words — and unknown to the threat
/// DB — has the textbook slopsquat shape.
const HALLUCINATION_FILLER_WORDS: &[&str] = &[
    "helper",
    "helpers",
    "utils",
    "util",
    "utility",
    "utilities",
    "tool",
    "tools",
    "toolkit",
    "lib",
    "libs",
    "library",
    "core",
    "common",
    "shared",
    "client",
    "sdk",
    "api",
    "wrapper",
    "manager",
    "handler",
    "parser",
    "builder",
    "factory",
    "service",
    "services",
    "provider",
    "adapter",
    "connector",
    "plugin",
    "module",
    "framework",
    "engine",
    "kit",
    "starter",
    "boot",
    "easy",
    "simple",
    "fast",
    "smart",
    "auto",
    "pro",
    "plus",
    "extended",
    "enhanced",
    "advanced",
    "modern",
    "official",
    "secure",
    "async",
    "data",
    "json",
    "http",
    "rest",
    "config",
];

/// Ecosystem-language prefixes an LLM tacks onto a hallucinated name
/// (`python-requests-helper`, `node-fetch-utils`, `go-redis-client`).
const HALLUCINATION_LANG_PREFIXES: &[&str] = &[
    "python", "py", "node", "js", "nodejs", "go", "golang", "rust", "ruby", "rb", "java",
];

/// Assess whether a declared dependency is slopsquat-suspicious. Pure and
/// total; the DB is consulted read-only (no network/filesystem).
///
/// All three layers required:
/// 1. Unknown to the threat DB (known-popular / confirmed-typosquat names are
///    handled by their own stronger findings).
/// 2. AI-hallucinated name shape (see [`hallucinated_name_shape`]).
/// 3. Near a real popular name — one edit away, or embedding a popular name as
///    a `-`/`_` token (the `<popular>-helper` shape).
pub fn slopsquat(
    name: &str,
    name_vs_popular: &NameVsPopular,
    db: Option<&ThreatDb>,
    ecosystem: Ecosystem,
) -> SlopsquatAssessment {
    // Layer 1 — must be unknown (known-popular / confirmed-typosquat names are
    // real or covered elsewhere).
    match name_vs_popular {
        NameVsPopular::KnownPopular => return SlopsquatAssessment::clear(),
        NameVsPopular::NearPopular { .. } | NameVsPopular::Unknown => {}
    }

    let mut reasons: Vec<String> = Vec::new();

    // Layer 2 — does the NAME look AI-hallucinated?
    let shape = hallucinated_name_shape(name);
    if let Some(reason) = &shape {
        reasons.push(reason.clone());
    }

    // Layer 3 — is it NEAR a real popular name?
    let mut near_popular: Option<String> = None;
    if let NameVsPopular::NearPopular { popular_name, .. } = name_vs_popular {
        near_popular = Some(popular_name.clone());
        reasons.push(format!(
            "the name is one edit from the real popular package '{popular_name}'"
        ));
    } else if let Some(token_hit) = popular_token_in_name(name, db, ecosystem) {
        reasons.push(format!(
            "the name embeds the real popular package '{token_hit}' as a word — \
             the shape of a hallucinated companion package"
        ));
        near_popular = Some(token_hit);
    }

    // Fire only when BOTH a hallucinated shape AND a near-popular anchor are
    // present — either alone is too weak (keeps false positives low). When both
    // hold, `near_popular` is `Some` by construction.
    match (shape.is_some(), near_popular) {
        (true, Some(near_popular)) => SlopsquatAssessment::Suspicious {
            reasons,
            near_popular,
        },
        _ => SlopsquatAssessment::Clear,
    }
}

/// If `name` is shaped like an AI-hallucinated package name, return a
/// plain-language reason; otherwise `None`. Three recognised shapes: a
/// language prefix on a descriptive name, mostly-filler-word tokens, or an
/// unusually long multi-segment name (4+ tokens).
fn hallucinated_name_shape(name: &str) -> Option<String> {
    let lower = name.to_lowercase();
    // Tokenize on package-name separators, dropping any scope.
    let bare = lower.rsplit('/').next().unwrap_or(&lower);
    let tokens: Vec<&str> = bare
        .split(['-', '_', '.'])
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.len() < 2 {
        // A single-token name is not a composed, descriptive shape.
        return None;
    }

    let filler_count = tokens
        .iter()
        .filter(|t| HALLUCINATION_FILLER_WORDS.contains(t))
        .count();
    let lang_prefix = tokens
        .first()
        .map(|t| HALLUCINATION_LANG_PREFIXES.contains(t))
        .unwrap_or(false);

    // Shape A — a language prefix on a multi-token descriptive name.
    if lang_prefix && tokens.len() >= 3 {
        return Some(format!(
            "the name begins with the language prefix '{}' and stacks {} descriptive \
             tokens — a shape LLMs produce for plausible-but-fake packages",
            tokens[0],
            tokens.len()
        ));
    }

    // Shape B — most tokens are generic filler words.
    if tokens.len() >= 2 && filler_count >= 2 && filler_count * 2 >= tokens.len() {
        return Some(format!(
            "{filler_count} of the name's {} tokens are generic filler words \
             ({}) — the hallmark of an LLM-generated descriptive name",
            tokens.len(),
            tokens
                .iter()
                .filter(|t| HALLUCINATION_FILLER_WORDS.contains(t))
                .copied()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    // Shape C — 4+ tokens with at least one filler word (a filler word is also
    // required because real packages are occasionally long).
    if tokens.len() >= 4 && filler_count >= 1 {
        return Some(format!(
            "the name stacks {} '-'/'_'-separated tokens including filler words — \
             real packages are rarely this descriptively long",
            tokens.len()
        ));
    }

    None
}

/// If one of `name`'s `-`/`_` tokens is itself a known-popular package (and the
/// whole name is not that package), return it. Catches the `<popular>-helper`
/// slopsquat shape; the token must be >= 3 chars so short tokens don't match.
fn popular_token_in_name(name: &str, db: Option<&ThreatDb>, eco: Ecosystem) -> Option<String> {
    let db = db?;
    let lower = name.to_lowercase();
    let bare = lower.rsplit('/').next().unwrap_or(&lower);
    let tokens: Vec<&str> = bare.split(['-', '_']).filter(|t| t.len() >= 3).collect();
    // A single-token name *is* its token, not an embedding — require composition.
    if tokens.len() < 2 {
        return None;
    }
    for token in tokens {
        if token == bare {
            continue;
        }
        if db.is_popular_package(eco, token) {
            return Some(token.to_string());
        }
    }
    None
}

/// A complete, explainable risk assessment of one declared dependency.
#[derive(Debug, Clone, Serialize)]
pub struct DependencyAssessment {
    /// The dependency as declared in the manifest.
    pub dependency: DeclaredDependency,
    /// The manifest file the dependency was declared in (scan-root-relative
    /// when the scan was given a directory).
    pub manifest: String,
    /// The deterministic `package_risk` factor breakdown for this package.
    pub risk: RiskBreakdown,
    /// The slopsquat heuristic verdict.
    pub slopsquat: SlopsquatAssessment,
    /// `true` when a policy allowlist entry suppressed this dependency's
    /// findings (the assessment is still reported, for transparency).
    pub allowlisted: bool,
}

/// Build the [`Finding`]s a single [`DependencyAssessment`] produces, reusing
/// the existing package-supply-chain [`RuleId`]s. An allowlisted dependency
/// produces no findings. `policy` carries the `package_policy` thresholds for
/// the `PackagePolicy*` rule paths (`&Policy::default()` keeps the baseline).
pub fn findings_for(
    assessment: &DependencyAssessment,
    policy: &crate::policy::Policy,
) -> Vec<Finding> {
    if assessment.allowlisted {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let dep = &assessment.dependency;
    let manifest = &assessment.manifest;

    // 1 — confirmed malicious typosquat from the threat DB; stands alone.
    if let Some(target) = &assessment.risk.malicious_typosquat_of {
        findings.push(Finding {
            rule_id: RuleId::ThreatPackageTyposquat,
            severity: Severity::High,
            title: format!("Confirmed typosquat dependency: {} → {}", dep.name, target),
            description: format!(
                "The {} dependency '{}' declared in {} is a confirmed typosquat of the \
                 popular package '{}' (source: local threat database). Risk score \
                 {}/100 ({}).",
                dep.ecosystem,
                dep.name,
                manifest,
                target,
                assessment.risk.score,
                assessment.risk.risk_level,
            ),
            evidence: vec![Evidence::Text {
                detail: format!(
                    "manifest={manifest} package={} ecosystem={} typosquat_of={target}",
                    dep.name, dep.ecosystem
                ),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
        return findings;
    }

    // 2 — slopsquat-suspicious (AI-hallucinated name near a popular package).
    // The `Suspicious` variant carries the anchor and reasons directly.
    if let SlopsquatAssessment::Suspicious {
        reasons,
        near_popular,
    } = &assessment.slopsquat
    {
        findings.push(Finding {
            rule_id: RuleId::ThreatSuspiciousPackage,
            severity: Severity::Medium,
            title: format!(
                "Possible slopsquat dependency: {} (near '{}')",
                dep.name, near_popular
            ),
            description: format!(
                "The {} dependency '{}' declared in {} is not a known-real package and its \
                 name is shaped like an AI-hallucinated ('slopsquat') name sitting near the \
                 real package '{}'. {}. Verify the package is intentional and exists on its \
                 registry before trusting it. Risk score {}/100 ({}).",
                dep.ecosystem,
                dep.name,
                manifest,
                near_popular,
                reasons.join("; "),
                assessment.risk.score,
                assessment.risk.risk_level,
            ),
            evidence: vec![Evidence::Text {
                detail: format!(
                    "manifest={manifest} package={} ecosystem={} near_popular={near_popular} \
                     reasons=[{}]",
                    dep.name,
                    dep.ecosystem,
                    reasons.join(" | "),
                ),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
        return findings;
    }

    // 3 — name resembles a popular package (one edit) with no slopsquat shape
    // and no DB typosquat record. The weakest signal.
    if let NameVsPopular::NearPopular {
        popular_name,
        distance,
    } = &assessment.risk.name_vs_popular
    {
        findings.push(Finding {
            rule_id: RuleId::ThreatPackageSimilarName,
            severity: Severity::Medium,
            title: format!(
                "Dependency name similar to popular package: {} ≈ {}",
                dep.name, popular_name
            ),
            description: format!(
                "The {} dependency '{}' declared in {} is within edit distance {} of the \
                 popular package '{}'. This may be a typosquat or a coincidence — verify the \
                 name is intentional. Risk score {}/100 ({}).",
                dep.ecosystem,
                dep.name,
                manifest,
                distance,
                popular_name,
                assessment.risk.score,
                assessment.risk.risk_level,
            ),
            evidence: vec![Evidence::Text {
                detail: format!(
                    "manifest={manifest} package={} ecosystem={} similar_to={popular_name} \
                     distance={distance}",
                    dep.name, dep.ecosystem
                ),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
        return findings;
    }

    // 4 — provenance-only risk (PR #121 fix-list item 2): when no name-shape
    // signal fires but the deterministic score reaches High/Critical purely
    // from registry provenance, the package is risky on registry data alone
    // and must still emit a finding. Thresholds read from
    // `policy.package_policy.*_effective()`; score >= block → High, warn ≤
    // score < block → Medium.
    let warn_score = policy.package_policy.warn_aggregate_score_effective();
    let block_score = policy.package_policy.block_aggregate_score_effective();
    let score = assessment.risk.score;
    let risk_level = assessment.risk.risk_level;
    if score >= warn_score {
        let severity = if score >= block_score {
            Severity::High
        } else {
            Severity::Medium
        };
        // Name the contributing factors, in display order, so the description
        // points at hand-verifiable evidence.
        let factor_labels: Vec<&str> = assessment
            .risk
            .factors
            .iter()
            .filter(|f| f.points > 0)
            .map(|f| f.label.as_str())
            .collect();
        let factor_summary = if factor_labels.is_empty() {
            "registry-API provenance signals".to_string()
        } else {
            factor_labels.join(", ")
        };
        findings.push(Finding {
            rule_id: RuleId::ThreatSuspiciousPackage,
            severity,
            title: format!(
                "High-risk provenance for {} dependency: {} ({}/100, {})",
                dep.ecosystem, dep.name, assessment.risk.score, risk_level,
            ),
            description: format!(
                "The {} dependency '{}' declared in {} has elevated provenance risk \
                 (score {}/100, {}) driven by registry signals rather than a known-bad \
                 name: {}. Review the factor breakdown — run `tirith package explain \
                 {} {}` — and verify the package is intentional before installing.",
                dep.ecosystem,
                dep.name,
                manifest,
                assessment.risk.score,
                risk_level,
                factor_summary,
                dep.ecosystem,
                dep.name,
            ),
            evidence: vec![Evidence::Text {
                detail: format!(
                    "manifest={manifest} package={} ecosystem={} risk_score={} \
                     risk_level={} factors=[{}]",
                    dep.name, dep.ecosystem, assessment.risk.score, risk_level, factor_summary,
                ),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }

    findings
}

/// Emit `PackagePolicy*` findings for one dependency assessment. Signals are
/// read from the `ApiProvenance` on the breakdown so the scan path's evidence
/// matches the `install_txn` path's.
fn policy_findings_for_assessment(
    assessment: &DependencyAssessment,
    policy: &crate::policy::Policy,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let dep = &assessment.dependency;
    let manifest = &assessment.manifest;
    let pp = &policy.package_policy;
    let provenance: Option<&package_risk::ApiProvenance> = match &assessment.risk.api_signals {
        package_risk::ApiSignals::Available { provenance } => Some(provenance),
        _ => None,
    };

    // `PackagePolicyTyposquatDistance` is an OFFLINE gate (reads
    // `name_vs_popular`, no registry call). Emit it BEFORE the `Some(prov)`
    // gate so a degraded `--online` scan still surfaces typosquat findings; the
    // API-backed gates below all require provenance.
    if let Some(max_dist) = pp.block_typosquat_distance {
        if let package_risk::NameVsPopular::NearPopular {
            popular_name,
            distance,
        } = &assessment.risk.name_vs_popular
        {
            if (*distance as u32) <= max_dist {
                out.push(Finding {
                    rule_id: RuleId::PackagePolicyTyposquatDistance,
                    severity: Severity::High,
                    title: format!(
                        "Typosquat distance below policy threshold: {} '{}' ≈ '{}'",
                        dep.ecosystem, dep.name, popular_name,
                    ),
                    description: format!(
                        "Dependency '{}' declared in {manifest} is edit-distance {distance} from \
                         the popular {} package '{popular_name}', at or below the policy \
                         threshold {max_dist}.",
                        dep.name, dep.ecosystem,
                    ),
                    evidence: vec![Evidence::Text {
                        detail: format!(
                            "manifest={manifest} package={} ecosystem={} similar_to={popular_name} \
                             distance={distance} threshold={max_dist}",
                            dep.name, dep.ecosystem,
                        ),
                    }],
                    human_view: None,
                    agent_view: None,
                    mitre_id: None,
                    custom_rule_id: None,
                });
            }
        }
    }

    let Some(prov) = provenance else {
        return out;
    };

    // PackagePolicyNotFound — registry-confirmed 404 + block_not_found
    if pp.block_not_found
        && matches!(
            prov.package_existence,
            package_risk::PackageExistence::NotFound
        )
    {
        out.push(Finding {
            rule_id: RuleId::PackagePolicyNotFound,
            severity: Severity::High,
            title: format!(
                "Package not found: {} '{}' (policy block_not_found)",
                dep.ecosystem, dep.name
            ),
            description: format!(
                "Dependency '{}' declared in {manifest} was not found in the {} registry \
                 (HTTP 404). Policy `block_not_found: true` requires this to block.",
                dep.name, dep.ecosystem,
            ),
            evidence: vec![Evidence::Text {
                detail: format!(
                    "manifest={manifest} package={} ecosystem={} existence=not_found",
                    dep.name, dep.ecosystem
                ),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }

    // PackagePolicyNewerThanDays — package_age_days vs thresholds
    if let Some(age_days) = prov.package_age_days {
        let warn_d = pp.warn_newer_than_days;
        let block_d = pp.block_newer_than_days;
        let (fired, sev) = match (block_d, warn_d) {
            (Some(b), _) if (age_days as u32) <= b => (true, Severity::High),
            (_, Some(w)) if (age_days as u32) <= w => (true, Severity::Medium),
            _ => (false, Severity::Medium),
        };
        if fired {
            out.push(Finding {
                rule_id: RuleId::PackagePolicyNewerThanDays,
                severity: sev,
                title: format!(
                    "Dependency newer than policy threshold: {} '{}' ({} day{})",
                    dep.ecosystem,
                    dep.name,
                    age_days,
                    if age_days == 1 { "" } else { "s" },
                ),
                description: format!(
                    "Dependency '{}' declared in {manifest} was first published {age_days} day(s) \
                     ago — trips warn_newer_than_days={:?} / block_newer_than_days={:?}.",
                    dep.name, warn_d, block_d,
                ),
                evidence: vec![Evidence::Text {
                    detail: format!(
                        "manifest={manifest} package={} ecosystem={} package_age_days={age_days} \
                         warn_threshold={warn_d:?} block_threshold={block_d:?}",
                        dep.name, dep.ecosystem,
                    ),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }

    // PackagePolicyLowDownloads
    if let (Some(dl), Some(low)) = (prov.recent_downloads, pp.warn_low_downloads_below) {
        if dl <= low as u64 {
            out.push(Finding {
                rule_id: RuleId::PackagePolicyLowDownloads,
                severity: Severity::Medium,
                title: format!(
                    "Dependency has low recent downloads: {} '{}' ({})",
                    dep.ecosystem, dep.name, dl,
                ),
                description: format!(
                    "Dependency '{}' declared in {manifest} reports {dl} recent downloads, at or \
                     below the policy threshold {low}.",
                    dep.name,
                ),
                evidence: vec![Evidence::Text {
                    detail: format!(
                        "manifest={manifest} package={} ecosystem={} recent_downloads={dl} threshold={low}",
                        dep.name, dep.ecosystem,
                    ),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }

    // PackagePolicyUnknownPackageWithInstallScripts
    if pp.block_install_scripts_for_unknown_packages
        && matches!(
            assessment.risk.name_vs_popular,
            package_risk::NameVsPopular::Unknown
        )
    {
        if let Some(iss) = prov.install_script_signals.as_ref() {
            if iss.has_network_call || iss.has_shell_spawn {
                out.push(Finding {
                    rule_id: RuleId::PackagePolicyUnknownPackageWithInstallScripts,
                    severity: Severity::High,
                    title: format!(
                        "Unknown {} dependency ships install-time scripts: '{}'",
                        dep.ecosystem, dep.name,
                    ),
                    description: format!(
                        "Dependency '{}' declared in {manifest} is not a known-popular {} name and \
                         its install scripts include a network call or shell spawn.",
                        dep.name, dep.ecosystem,
                    ),
                    evidence: vec![Evidence::Text {
                        detail: format!(
                            "manifest={manifest} package={} ecosystem={} has_network_call={} has_shell_spawn={}",
                            dep.name, dep.ecosystem, iss.has_network_call, iss.has_shell_spawn,
                        ),
                    }],
                    human_view: None,
                    agent_view: None,
                    mitre_id: None,
                    custom_rule_id: None,
                });
            }
        }
    }

    // PackageOsvAdvisoryActive — severity driven by `block_osv_min_cvss`: a
    // CVSS at/above the threshold elevates to High, else Medium.
    if let Some(advs) = prov.osv_advisories.as_ref() {
        if !advs.is_empty() {
            let min_block_cvss = pp.block_osv_min_cvss_effective();
            let max_cvss = advs.iter().filter_map(|a| a.cvss).fold(0.0_f32, f32::max);
            let severity = if max_cvss >= min_block_cvss {
                Severity::High
            } else {
                Severity::Medium
            };
            let ids: Vec<&str> = advs.iter().take(3).map(|a| a.id.as_str()).collect();
            out.push(Finding {
                rule_id: RuleId::PackageOsvAdvisoryActive,
                severity,
                title: format!(
                    "Active OSV advisory for {} dependency: {} ({} advisory)",
                    dep.ecosystem,
                    dep.name,
                    advs.len(),
                ),
                description: format!(
                    "Dependency '{}' declared in {manifest} matches {} OSV advisory record(s): \
                     {}. Highest CVSS in the set: {max_cvss}. Policy `block_osv_min_cvss = \
                     {min_block_cvss}` — severity is {} when the highest CVSS meets/exceeds the \
                     threshold.",
                    dep.name,
                    advs.len(),
                    ids.join(", "),
                    if matches!(severity, Severity::High) {
                        "High"
                    } else {
                        "Medium"
                    },
                ),
                evidence: vec![Evidence::Text {
                    detail: format!(
                        "manifest={manifest} package={} ecosystem={} max_cvss={max_cvss} \
                         threshold={min_block_cvss} advisories={}",
                        dep.name,
                        dep.ecosystem,
                        ids.join(","),
                    ),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }

    // PackagePolicyTyposquatDistance is emitted at the top of this function
    // BEFORE the `Some(prov)` gate — see the comment there for rationale.

    out
}

/// Why `ecosystem scan` could not score a manifest, or a note about a partial
/// result. Surfaced in the report so a scan is honest about its coverage.
#[derive(Debug, Clone, Serialize)]
pub struct ScanNote {
    /// The manifest the note concerns, when it concerns one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<String>,
    /// The human-readable note.
    pub note: String,
}

/// The complete result of an `ecosystem scan`.
#[derive(Debug, Clone, Serialize)]
pub struct EcosystemScanReport {
    /// The scan root (directory or file) the scan was given.
    pub scan_root: String,
    /// Which mode the scan ran in — `"manifests"`, `"installed"`, or
    /// `"specific_lockfile"`. The two CLI surfaces emit byte-identical output.
    pub mode: &'static str,
    /// The manifest files discovered and parsed.
    pub manifests: Vec<String>,
    /// Total declared dependencies discovered across all manifests.
    pub dependency_count: usize,
    /// The per-dependency assessments, in a stable order.
    pub assessments: Vec<DependencyAssessment>,
    /// Whether the registry-API (`--online`) signals were used.
    pub online: bool,
    /// Notes about coverage — unreadable manifests, truncation, missing DB.
    pub notes: Vec<ScanNote>,
    /// The verdict: every finding from every non-allowlisted dependency.
    pub verdict: Verdict,
}

/// How a scan resolves the registry-API state per dependency. Supplied by the
/// CLI layer so the core stays free of network / env knowledge.
pub enum OnlineMode<'a> {
    /// Offline scan — API signals are [`ApiSignals::NotComputed`].
    Off,
    /// `--online` scan — the (offline-safe) closure resolves each
    /// `(ecosystem, name)` to its [`ApiSignals`], called at most once per package.
    Resolver(&'a dyn Fn(Ecosystem, &str) -> ApiSignals),
}

/// What an `ecosystem_scan` operates on. The engine has one entry point
/// ([`scan`]); the mode picks which inputs feed the per-package scoring loop.
/// Two CLI surfaces share `scan` and differ only in the mode they pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ScanMode {
    /// Walk the project root for dependency *manifests* (the shipping behavior).
    #[default]
    Manifests,
    /// Walk *installed* trees (`node_modules`, `site-packages`, `vendor`,
    /// `Cargo.lock`) — what is actually on disk, which can drift from intent.
    Installed,
    /// Parse the given file directly as a lockfile (the `package scan
    /// --lockfile <path>` form).
    SpecificLockfile(PathBuf),
}

impl ScanMode {
    /// The short, stable label for `--format json`'s top-level `mode` field.
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanMode::Manifests => "manifests",
            ScanMode::Installed => "installed",
            ScanMode::SpecificLockfile(_) => "specific_lockfile",
        }
    }
}

/// Inputs to [`scan`] — a struct so the signature stays stable.
pub struct ScanRequest<'a> {
    /// The directory or single manifest file to scan.
    pub root: &'a Path,
    /// The loaded threat DB, or `None` (scan still runs; signals fall back to
    /// "unknown" and a note is added).
    pub db: Option<&'a ThreatDb>,
    /// The registry-API resolution mode.
    pub online: OnlineMode<'a>,
    /// `true` when a `(ecosystem, name)` pair is allowlisted and suppressed.
    pub is_allowlisted: &'a dyn Fn(Ecosystem, &str) -> bool,
    /// Which input the scan operates on. Defaults to [`ScanMode::Manifests`].
    pub mode: ScanMode,
    /// Cap on installed entries in [`ScanMode::Installed`]; `0` = unbounded.
    /// Ignored for the other modes.
    pub installed_max_entries: usize,
    /// The active policy for the `PackagePolicy*` rule paths and the
    /// configurable thresholds. `None` keeps the `Policy::default()` baseline.
    pub policy: Option<&'a crate::policy::Policy>,
}

/// Run an `ecosystem scan` over `request.root` and return the full report.
/// The single entry point: discovers manifests, parses and scores every
/// dependency, folds in [`slopsquat`], and assembles a [`Verdict`]. Never
/// panics; a malformed manifest is skipped with a note.
pub fn scan(request: &ScanRequest) -> EcosystemScanReport {
    let mut notes: Vec<ScanNote> = Vec::new();

    if request.db.is_none() {
        notes.push(ScanNote {
            manifest: None,
            note: "the local threat database is not installed — popular-package and \
                   typosquat signals are unavailable, so scoring is weaker. Run \
                   `tirith threat-db update` to install it."
                .to_string(),
        });
    }

    let root_display = request.root.display().to_string();

    // Dispatch on mode → (manifest_labels, declared_deps). Downstream scoring +
    // verdict assembly is mode-independent (the byte-identical-JSON invariant).
    let (mut manifest_labels, mut declared) = match &request.mode {
        ScanMode::Manifests => collect_from_manifests(request, &mut notes),
        ScanMode::Installed => collect_from_installed_tree(request, &mut notes),
        ScanMode::SpecificLockfile(path) => collect_from_specific_lockfile(path, &mut notes),
    };

    // Stable order across runs and CLI surfaces — sort again at the dispatch
    // boundary so we don't rely on per-walker ordering.
    manifest_labels.sort();
    manifest_labels.dedup();
    declared.sort_by(|(a, am), (b, bm)| {
        am.cmp(bm)
            .then_with(|| a.ecosystem.to_string().cmp(&b.ecosystem.to_string()))
            .then_with(|| a.name.cmp(&b.name))
    });

    let dependency_count = declared.len();
    let truncated = declared.len() > MAX_DEPENDENCIES;
    if truncated {
        notes.push(ScanNote {
            manifest: None,
            note: format!(
                "{} dependencies declared; scoring was capped at {MAX_DEPENDENCIES}.",
                declared.len()
            ),
        });
        declared.truncate(MAX_DEPENDENCIES);
    }

    // Score each dependency; the registry-API resolver is memoized per package.
    let online = matches!(request.online, OnlineMode::Resolver(_));
    let mut api_cache: std::collections::HashMap<(Ecosystem, String), ApiSignals> =
        std::collections::HashMap::new();
    let mut assessments: Vec<DependencyAssessment> = Vec::new();

    for (dep, manifest) in declared {
        let assessment = assess_dependency(&dep, &manifest, request, &mut api_cache);
        assessments.push(assessment);
    }

    // On `--online`, surface how many deps could not get provenance — a
    // fully-degraded online scan would otherwise look clean. A representative
    // reason is carried so the note is actionable without one line per dep.
    if online {
        let unavailable: Vec<&DependencyAssessment> = assessments
            .iter()
            .filter(|a| matches!(a.risk.api_signals, ApiSignals::Unavailable { .. }))
            .collect();
        if !unavailable.is_empty() {
            let sample_reason = unavailable.iter().find_map(|a| match &a.risk.api_signals {
                ApiSignals::Unavailable { reason } => Some(reason.clone()),
                _ => None,
            });
            let note = match sample_reason {
                Some(reason) => format!(
                    "registry-API provenance was unavailable for {} of {} dependency/dependencies \
                     — the --online half of the scan was degraded for them (e.g. {reason}). \
                     Those packages were scored with offline signals only.",
                    unavailable.len(),
                    assessments.len(),
                ),
                None => format!(
                    "registry-API provenance was unavailable for {} of {} dependency/dependencies \
                     — the --online half of the scan was degraded for them; they were scored \
                     with offline signals only.",
                    unavailable.len(),
                    assessments.len(),
                ),
            };
            notes.push(ScanNote {
                manifest: None,
                note,
            });
        }
    }

    // Assemble the verdict: every finding from every assessment.
    let default_policy = crate::policy::Policy::default();
    let effective_policy = request.policy.unwrap_or(&default_policy);
    let mut findings: Vec<Finding> = Vec::new();
    for assessment in &assessments {
        findings.extend(findings_for(assessment, effective_policy));
        // Policy-driven per-dependency rules; allowlisted assessments suppress
        // these too, matching `findings_for`.
        if !assessment.allowlisted {
            findings.extend(policy_findings_for_assessment(assessment, effective_policy));
        }
    }
    // tier_reached is 3 — `ecosystem scan` does the full analysis.
    let verdict = Verdict::from_findings(findings, 3, Timings::default());

    EcosystemScanReport {
        scan_root: root_display,
        manifests: manifest_labels,
        dependency_count,
        assessments,
        online,
        notes,
        verdict,
        mode: request.mode.as_str(),
    }
}

// Per-mode collectors all return (manifest_labels, declared_deps) in the same
// shape so the downstream scoring loop is mode-independent.

/// Walk `request.root` for dependency manifests and parse each one — the
/// shipping `ecosystem scan` behavior.
fn collect_from_manifests(
    request: &ScanRequest,
    notes: &mut Vec<ScanNote>,
) -> (Vec<String>, Vec<(DeclaredDependency, String)>) {
    let manifests = discover_manifests(request.root);
    if manifests.is_empty() {
        notes.push(ScanNote {
            manifest: None,
            note: "no dependency manifests found (looked for package.json, \
                   package-lock.json, requirements*.txt, pyproject.toml, Cargo.toml, \
                   go.mod, Gemfile)."
                .to_string(),
        });
    }

    let mut declared: Vec<(DeclaredDependency, String)> = Vec::new();
    let mut manifest_labels: Vec<String> = Vec::new();
    for manifest in &manifests {
        let rel = relative_label(request.root, &manifest.path);
        manifest_labels.push(rel.clone());
        parse_one_manifest(manifest, &rel, &mut declared, notes);
    }
    (manifest_labels, declared)
}

/// Read a single lockfile by path (the `--lockfile <path>` form). An
/// unrecognized file produces a note rather than an empty scan.
fn collect_from_specific_lockfile(
    path: &Path,
    notes: &mut Vec<ScanNote>,
) -> (Vec<String>, Vec<(DeclaredDependency, String)>) {
    if !path.exists() {
        notes.push(ScanNote {
            manifest: None,
            note: format!("lockfile not found: {}", path.display()),
        });
        return (Vec::new(), Vec::new());
    }
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        notes.push(ScanNote {
            manifest: None,
            note: format!("lockfile has no readable file name: {}", path.display()),
        });
        return (Vec::new(), Vec::new());
    };
    let Some(kind) = ManifestKind::from_file_name(name) else {
        notes.push(ScanNote {
            manifest: None,
            note: format!(
                "lockfile '{}' is not a recognized manifest format (expected one of \
                 package.json, package-lock.json, requirements*.txt, pyproject.toml, \
                 Cargo.toml, go.mod, Gemfile).",
                path.display()
            ),
        });
        return (Vec::new(), Vec::new());
    };
    let discovered = DiscoveredManifest {
        path: path.to_path_buf(),
        kind,
    };
    let label = path.display().to_string();
    let mut declared: Vec<(DeclaredDependency, String)> = Vec::new();
    parse_one_manifest(&discovered, &label, &mut declared, notes);
    (vec![label], declared)
}

/// Walk installed-tree directories under `request.root` and synthesize
/// per-package declarations. Looks for `node_modules/` (npm), `site-packages/`
/// `.dist-info/METADATA` (PyPI), `vendor/` (Go), and the root `Cargo.lock`
/// (Rust). Respects `request.installed_max_entries`, noting any truncation.
fn collect_from_installed_tree(
    request: &ScanRequest,
    notes: &mut Vec<ScanNote>,
) -> (Vec<String>, Vec<(DeclaredDependency, String)>) {
    let mut declared: Vec<(DeclaredDependency, String)> = Vec::new();
    let mut manifest_labels: Vec<String> = Vec::new();
    let cap = if request.installed_max_entries == 0 {
        usize::MAX
    } else {
        request.installed_max_entries
    };
    let mut truncated_at: Option<usize> = None;

    let label_for = |p: &Path| -> String { relative_label(request.root, p) };

    // npm: node_modules/<scope?>/<pkg>/package.json
    let node_modules = request.root.join("node_modules");
    if node_modules.is_dir() {
        walk_node_modules(
            &node_modules,
            cap,
            &mut declared,
            &mut manifest_labels,
            &mut truncated_at,
            &label_for,
        );
    }

    // PyPI: site-packages/<dist>.dist-info/METADATA (the CLI passes
    // `VIRTUAL_ENV` as the scan root separately).
    for sp in find_site_packages_dirs(request.root) {
        if truncated_at.is_some() {
            break;
        }
        walk_site_packages(
            &sp,
            cap,
            &mut declared,
            &mut manifest_labels,
            &mut truncated_at,
            &label_for,
        );
    }

    // Go: vendor/<host>/<owner>/<mod>/
    if truncated_at.is_none() {
        let vendor = request.root.join("vendor");
        if vendor.is_dir() {
            walk_vendor_go(
                &vendor,
                cap,
                &mut declared,
                &mut manifest_labels,
                &mut truncated_at,
                &label_for,
            );
        }
    }

    // Rust: Cargo.lock at the workspace root
    if truncated_at.is_none() {
        let lock = request.root.join("Cargo.lock");
        if lock.is_file() {
            if let Ok(text) = std::fs::read_to_string(&lock) {
                let label = label_for(&lock);
                manifest_labels.push(label.clone());
                for dep in parse_cargo_lock(&text) {
                    if declared.len() >= cap {
                        truncated_at = Some(cap);
                        break;
                    }
                    declared.push((dep, label.clone()));
                }
            }
        }
    }

    if let Some(at) = truncated_at {
        notes.push(ScanNote {
            manifest: None,
            note: format!(
                "results truncated at {at} installed entries; pass \
                 `--max-installed-entries 0` to disable the cap (slow)."
            ),
        });
    }

    if declared.is_empty() && manifest_labels.is_empty() {
        notes.push(ScanNote {
            manifest: None,
            note: "no installed-tree packages found under the scan root (looked for \
                   node_modules/, site-packages/, vendor/ for Go modules, and Cargo.lock)."
                .to_string(),
        });
    }

    (manifest_labels, declared)
}

/// Parse one [`DiscoveredManifest`] into `out`, recording a note on any read
/// or parse failure so a partly-broken project still reports.
fn parse_one_manifest(
    manifest: &DiscoveredManifest,
    rel: &str,
    out: &mut Vec<(DeclaredDependency, String)>,
    notes: &mut Vec<ScanNote>,
) {
    let text = match std::fs::read_to_string(&manifest.path) {
        Ok(t) => t,
        Err(e) => {
            notes.push(ScanNote {
                manifest: Some(rel.to_string()),
                note: format!("could not read manifest: {e}"),
            });
            return;
        }
    };
    match parse_manifest(manifest.kind, &text) {
        None => {
            notes.push(ScanNote {
                manifest: Some(rel.to_string()),
                note: format!(
                    "the {} manifest could not be parsed (malformed JSON / TOML) — \
                     its dependencies were not assessed.",
                    manifest.kind.label()
                ),
            });
        }
        Some(deps) => {
            if deps.is_empty() {
                notes.push(ScanNote {
                    manifest: Some(rel.to_string()),
                    note: "the manifest parsed but declares no dependencies.".to_string(),
                });
            }
            for dep in deps {
                out.push((dep, rel.to_string()));
            }
        }
    }
}

/// Walk `node_modules/` for installed npm packages, handling both bare and
/// scoped (`@scope/<pkg>`) layouts.
fn walk_node_modules(
    root: &Path,
    cap: usize,
    declared: &mut Vec<(DeclaredDependency, String)>,
    manifest_labels: &mut Vec<String>,
    truncated_at: &mut Option<usize>,
    label_for: &dyn Fn(&Path) -> String,
) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(root)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect()
        })
        .unwrap_or_default();
    entries.sort();
    for entry in entries {
        if truncated_at.is_some() {
            return;
        }
        let dir_name = match entry.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if dir_name == ".bin" || dir_name == ".cache" {
            continue;
        }
        if dir_name.starts_with('@') {
            // Scoped: recurse one level.
            let mut sub: Vec<PathBuf> = std::fs::read_dir(&entry)
                .map(|rd| {
                    rd.filter_map(Result::ok)
                        .map(|e| e.path())
                        .filter(|p| p.is_dir())
                        .collect()
                })
                .unwrap_or_default();
            sub.sort();
            for s in sub {
                if truncated_at.is_some() {
                    return;
                }
                read_node_package(&s, cap, declared, manifest_labels, truncated_at, label_for);
            }
        } else {
            read_node_package(
                &entry,
                cap,
                declared,
                manifest_labels,
                truncated_at,
                label_for,
            );
        }
    }
}

/// Read one installed npm package's `package.json` and emit a single
/// [`DeclaredDependency`] for that package (NOT its sub-dependencies — each
/// installed package is itself one entry).
fn read_node_package(
    pkg_dir: &Path,
    cap: usize,
    declared: &mut Vec<(DeclaredDependency, String)>,
    manifest_labels: &mut Vec<String>,
    truncated_at: &mut Option<usize>,
    label_for: &dyn Fn(&Path) -> String,
) {
    if declared.len() >= cap {
        *truncated_at = Some(cap);
        return;
    }
    let manifest = pkg_dir.join("package.json");
    if !manifest.is_file() {
        return;
    }
    let Ok(text) = std::fs::read_to_string(&manifest) else {
        return;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        return;
    };
    let name = json
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty() && is_plausible_package_name(s));
    let Some(name) = name else { return };
    let version = json
        .get("version")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .filter(|s| !s.is_empty());
    let label = label_for(&manifest);
    manifest_labels.push(label.clone());
    declared.push((
        DeclaredDependency {
            name: name.to_string(),
            ecosystem: Ecosystem::Npm,
            version,
            dev: false,
        },
        label,
    ));
}

/// Find `site-packages` directories under `root` (well-defined venv layouts,
/// so the walk is not bounded further).
fn find_site_packages_dirs(root: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    // <root>/site-packages and the Windows-venv <root>/Lib/site-packages.
    let candidates: Vec<PathBuf> = vec![
        root.join("site-packages"),
        root.join("Lib").join("site-packages"),
    ];
    for c in candidates {
        if c.is_dir() {
            found.push(c);
        }
    }
    // <root>/lib/python*/site-packages
    let lib = root.join("lib");
    if lib.is_dir() {
        if let Ok(rd) = std::fs::read_dir(&lib) {
            let mut subs: Vec<PathBuf> = rd
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.is_dir()
                        && p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.starts_with("python"))
                })
                .collect();
            subs.sort();
            for s in subs {
                let sp = s.join("site-packages");
                if sp.is_dir() {
                    found.push(sp);
                }
            }
        }
    }
    found
}

/// Walk a `site-packages` directory for `*.dist-info/METADATA` entries.
fn walk_site_packages(
    root: &Path,
    cap: usize,
    declared: &mut Vec<(DeclaredDependency, String)>,
    manifest_labels: &mut Vec<String>,
    truncated_at: &mut Option<usize>,
    label_for: &dyn Fn(&Path) -> String,
) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(root)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.is_dir()
                        && p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.ends_with(".dist-info"))
                })
                .collect()
        })
        .unwrap_or_default();
    entries.sort();
    for dist_info in entries {
        if truncated_at.is_some() {
            return;
        }
        if declared.len() >= cap {
            *truncated_at = Some(cap);
            return;
        }
        let metadata = dist_info.join("METADATA");
        if !metadata.is_file() {
            continue;
        }
        let Some((name, version)) = read_dist_info_metadata(&metadata) else {
            continue;
        };
        let label = label_for(&metadata);
        manifest_labels.push(label.clone());
        declared.push((
            DeclaredDependency {
                name,
                ecosystem: Ecosystem::PyPI,
                version,
                dev: false,
            },
            label,
        ));
    }
}

/// Parse a PEP 566 METADATA file's `Name:` and `Version:` headers.
fn read_dist_info_metadata(path: &Path) -> Option<(String, Option<String>)> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    // Headers stop at the first blank line; the body is unneeded description.
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line.strip_prefix("Name:") {
            let val = rest.trim();
            if !val.is_empty() && is_plausible_package_name(val) {
                name = Some(val.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("Version:") {
            let val = rest.trim();
            if !val.is_empty() {
                version = Some(val.to_string());
            }
        }
    }
    name.map(|n| (n, version))
}

/// Walk `vendor/` for vendored Go modules (`host/owner/repo`-shaped names).
fn walk_vendor_go(
    root: &Path,
    cap: usize,
    declared: &mut Vec<(DeclaredDependency, String)>,
    manifest_labels: &mut Vec<String>,
    truncated_at: &mut Option<usize>,
    label_for: &dyn Fn(&Path) -> String,
) {
    // Prefer the authoritative `modules.txt` when present; otherwise treat any
    // dir three deep under `vendor/` as a candidate module.
    let modules_txt = root.join("modules.txt");
    if modules_txt.is_file() {
        let text = std::fs::read_to_string(&modules_txt).unwrap_or_default();
        let label = label_for(&modules_txt);
        manifest_labels.push(label.clone());
        for line in text.lines() {
            let trimmed = line.trim();
            // `# host/owner/mod v1.2.3` is a module header line.
            let Some(rest) = trimmed.strip_prefix("# ") else {
                continue;
            };
            let mut parts = rest.split_whitespace();
            let Some(module) = parts.next() else { continue };
            if module.is_empty() || !is_plausible_package_name(module) {
                continue;
            }
            let version = parts.next().map(str::to_string);
            if declared.len() >= cap {
                *truncated_at = Some(cap);
                return;
            }
            declared.push((
                DeclaredDependency {
                    name: module.to_string(),
                    ecosystem: Ecosystem::Go,
                    version,
                    dev: false,
                },
                label.clone(),
            ));
        }
        return;
    }
    // Fallback: walk depth-3 directories under `vendor/`.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for host in read_sorted_dirs(root) {
        if truncated_at.is_some() {
            return;
        }
        for owner in read_sorted_dirs(&host) {
            if truncated_at.is_some() {
                return;
            }
            for mod_dir in read_sorted_dirs(&owner) {
                if declared.len() >= cap {
                    *truncated_at = Some(cap);
                    return;
                }
                let rel = match mod_dir.strip_prefix(root) {
                    Ok(p) => p.display().to_string(),
                    Err(_) => continue,
                };
                if !seen.insert(rel.clone()) {
                    continue;
                }
                let label = label_for(&mod_dir);
                manifest_labels.push(label.clone());
                declared.push((
                    DeclaredDependency {
                        name: rel,
                        ecosystem: Ecosystem::Go,
                        version: None,
                        dev: false,
                    },
                    label,
                ));
            }
        }
    }
}

/// Sorted list of immediate subdirectories of `p`.
fn read_sorted_dirs(p: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(p)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|x| x.is_dir())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// Parse a `Cargo.lock` into one [`DeclaredDependency`] per `[[package]]`.
fn parse_cargo_lock(text: &str) -> Vec<DeclaredDependency> {
    let Ok(doc) = toml::from_str::<toml::Value>(text) else {
        return Vec::new();
    };
    let mut out: Vec<DeclaredDependency> = Vec::new();
    let mut seen: BTreeSet<(String, Option<String>)> = BTreeSet::new();
    let Some(packages) = doc.get("package").and_then(|p| p.as_array()) else {
        return out;
    };
    for pkg in packages {
        let Some(name) = pkg.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        if !is_plausible_package_name(name) {
            continue;
        }
        let version = pkg
            .get("version")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .filter(|s| !s.is_empty());
        if seen.insert((name.to_string(), version.clone())) {
            out.push(DeclaredDependency {
                name: name.to_string(),
                ecosystem: Ecosystem::Crates,
                version,
                dev: false,
            });
        }
    }
    out
}

/// Score one declared dependency into a [`DependencyAssessment`].
fn assess_dependency(
    dep: &DeclaredDependency,
    manifest: &str,
    request: &ScanRequest,
    api_cache: &mut std::collections::HashMap<(Ecosystem, String), ApiSignals>,
) -> DependencyAssessment {
    let name_vs_popular = package_risk::classify_name(request.db, dep.ecosystem, &dep.name);
    let malicious_typosquat_of = request
        .db
        .and_then(|db| db.check_typosquat(dep.ecosystem, &dep.name))
        .map(|ts| ts.target_name);

    // Registry-API signals — only on an `--online` scan, memoized per package.
    let api = match &request.online {
        OnlineMode::Off => ApiSignals::offline(),
        OnlineMode::Resolver(resolve) => {
            let key = (dep.ecosystem, dep.name.clone());
            api_cache
                .entry(key)
                .or_insert_with(|| resolve(dep.ecosystem, &dep.name))
                .clone()
        }
    };

    let signals = PackageSignals {
        ecosystem: dep.ecosystem,
        name: dep.name.clone(),
        // Manifest-declared version, carried through to OSV correlation.
        version: dep.version.clone(),
        threat_db_missing: request.db.is_none(),
        name_vs_popular: name_vs_popular.clone(),
        malicious_typosquat_of,
        // A manifest scan never has package content on disk, so content signals
        // are always NotInspected (use `package risk --path` to inspect content).
        content_signals: ContentSignals::NotInspected,
        api,
    };
    let risk = package_risk::score_package(&signals);

    let slopsquat = slopsquat(&dep.name, &name_vs_popular, request.db, dep.ecosystem);

    let allowlisted = (request.is_allowlisted)(dep.ecosystem, &dep.name);

    DependencyAssessment {
        dependency: dep.clone(),
        manifest: manifest.to_string(),
        risk,
        slopsquat,
        allowlisted,
    }
}

/// A scan-root-relative label for a manifest path, falling back to the full
/// path when it is not under the root.
fn relative_label(root: &Path, manifest: &Path) -> String {
    // When the root is a file, the manifest *is* the root.
    if root.is_file() {
        return manifest.display().to_string();
    }
    manifest
        .strip_prefix(root)
        .map(|rel| rel.display().to_string())
        .unwrap_or_else(|_| manifest.display().to_string())
}

impl EcosystemScanReport {
    /// The action the verdict resolved to.
    pub fn action(&self) -> Action {
        self.verdict.action
    }

    /// Count of dependencies whose findings were suppressed by an allowlist.
    pub fn allowlisted_count(&self) -> usize {
        self.assessments.iter().filter(|a| a.allowlisted).count()
    }

    /// The highest risk score across all assessed dependencies (0 when none).
    pub fn max_risk_score(&self) -> u32 {
        self.assessments
            .iter()
            .map(|a| a.risk.score)
            .max()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_kind_classifies_known_filenames() {
        assert_eq!(
            ManifestKind::from_file_name("package.json"),
            Some(ManifestKind::NpmPackageJson)
        );
        assert_eq!(
            ManifestKind::from_file_name("Cargo.toml"),
            Some(ManifestKind::CargoToml)
        );
        assert_eq!(
            ManifestKind::from_file_name("requirements-dev.txt"),
            Some(ManifestKind::PyRequirementsTxt)
        );
        assert_eq!(ManifestKind::from_file_name("README.md"), None);
        assert_eq!(ManifestKind::from_file_name("config.toml"), None);
    }

    #[test]
    fn manifest_kind_maps_to_ecosystem() {
        assert_eq!(ManifestKind::CargoToml.ecosystem(), Ecosystem::Crates);
        assert_eq!(ManifestKind::GoMod.ecosystem(), Ecosystem::Go);
        assert_eq!(ManifestKind::PyPyprojectToml.ecosystem(), Ecosystem::PyPI);
    }

    #[test]
    fn parse_package_json_extracts_deps_and_dev_deps() {
        let text = r#"{
            "name": "app",
            "dependencies": { "react": "^18.0.0", "lodash": "4.17.21" },
            "devDependencies": { "jest": "^29.0.0" }
        }"#;
        let deps = parse_package_json(text).expect("valid JSON parses");
        assert_eq!(deps.len(), 3);
        let react = deps.iter().find(|d| d.name == "react").unwrap();
        assert!(!react.dev);
        assert_eq!(react.version.as_deref(), Some("^18.0.0"));
        let jest = deps.iter().find(|d| d.name == "jest").unwrap();
        assert!(jest.dev, "devDependencies must be tagged dev");
    }

    #[test]
    fn parse_package_json_handles_malformed() {
        // Malformed JSON → `None` (the manifest could not be parsed).
        assert!(parse_package_json("{not json").is_none());
        assert!(parse_package_json("").is_none());
        // Valid JSON with no dependency fields → `Some(empty)`: it parsed, it
        // just declares nothing.
        assert_eq!(parse_package_json(r#"{"name":"x"}"#), Some(Vec::new()));
    }

    #[test]
    fn parse_package_lock_v3_reads_packages_map() {
        let text = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "root" },
                "node_modules/lodash": { "version": "4.17.21" },
                "node_modules/jest": { "version": "29.0.0", "dev": true },
                "node_modules/a/node_modules/@scope/b": { "version": "1.0.0" }
            }
        }"#;
        let deps = parse_package_lock(text).expect("valid lockfile JSON parses");
        assert!(deps.iter().any(|d| d.name == "lodash"));
        assert!(deps.iter().any(|d| d.name == "jest" && d.dev));
        // The deepest path key resolves to the scoped name after the last
        // `node_modules/`.
        assert!(
            deps.iter().any(|d| d.name == "@scope/b"),
            "nested scoped package must be extracted: {deps:?}"
        );
        // The root entry ("") must NOT appear.
        assert!(!deps.iter().any(|d| d.name.is_empty()));
    }

    #[test]
    fn parse_package_lock_v1_reads_dependencies_tree() {
        let text = r#"{
            "lockfileVersion": 1,
            "dependencies": {
                "express": {
                    "version": "4.18.2",
                    "dependencies": { "accepts": { "version": "1.3.8" } }
                }
            }
        }"#;
        let deps = parse_package_lock(text).expect("valid lockfile JSON parses");
        assert!(deps.iter().any(|d| d.name == "express"));
        assert!(
            deps.iter().any(|d| d.name == "accepts"),
            "nested v1 deps must be collected"
        );
    }

    #[test]
    fn package_lock_name_from_path_handles_all_forms() {
        assert_eq!(
            package_lock_name_from_path("node_modules/lodash").as_deref(),
            Some("lodash")
        );
        assert_eq!(
            package_lock_name_from_path("node_modules/a/node_modules/@s/b").as_deref(),
            Some("@s/b")
        );
        assert_eq!(package_lock_name_from_path(""), None);
    }

    #[test]
    fn parse_requirements_txt_extracts_bare_names() {
        let text = "\
# a comment
requests>=2.28.0
flask[async]==3.0.0
django ; python_version < \"3.9\"

-r other-requirements.txt
--index-url https://pypi.org/simple
numpy  # inline comment
git+https://github.com/x/y.git
";
        let deps = parse_requirements_txt(text);
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"flask"), "extras must be stripped");
        assert!(names.contains(&"django"), "env markers must be stripped");
        assert!(names.contains(&"numpy"), "inline comment must be stripped");
        // pip directives and VCS installs must NOT yield a name.
        assert!(!names.iter().any(|n| n.contains("other-requirements")));
        assert!(!names.iter().any(|n| n.contains("github")));
    }

    #[test]
    fn python_requirement_name_strips_specifiers() {
        assert_eq!(
            python_requirement_name("requests>=2.0").as_deref(),
            Some("requests")
        );
        assert_eq!(
            python_requirement_name("flask[async]").as_deref(),
            Some("flask")
        );
        assert_eq!(
            python_requirement_name("pkg @ file:///x").as_deref(),
            Some("pkg")
        );
        assert_eq!(python_requirement_name(""), None);
    }

    #[test]
    fn parse_pyproject_pep621_dependencies() {
        let text = r#"
[project]
name = "app"
dependencies = ["requests>=2.0", "click"]

[project.optional-dependencies]
dev = ["pytest>=7.0", "black"]
"#;
        let deps = parse_pyproject_toml(text).expect("valid TOML parses");
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"click"));
        let pytest = deps.iter().find(|d| d.name == "pytest").unwrap();
        assert!(pytest.dev, "optional-dependencies are dev-tagged");
    }

    #[test]
    fn parse_pyproject_poetry_dependencies() {
        let text = r#"
[tool.poetry.dependencies]
python = "^3.10"
requests = "^2.28"

[tool.poetry.group.dev.dependencies]
pytest = "^7.0"
"#;
        let deps = parse_pyproject_toml(text).expect("valid TOML parses");
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"requests"));
        assert!(
            !names.contains(&"python"),
            "the python interpreter constraint is not a dependency"
        );
        let pytest = deps.iter().find(|d| d.name == "pytest").unwrap();
        assert!(pytest.dev, "poetry dev group must be dev-tagged");
    }

    #[test]
    fn parse_pyproject_handles_malformed() {
        // Malformed TOML → `None` (the manifest could not be parsed).
        assert!(parse_pyproject_toml("[[[not toml").is_none());
    }

    #[test]
    fn parse_cargo_toml_extracts_all_dep_tables() {
        let text = r#"
[package]
name = "app"

[dependencies]
serde = "1.0"
tokio = { version = "1", features = ["full"] }

[dev-dependencies]
criterion = "0.5"

[build-dependencies]
cc = "1.0"
"#;
        let deps = parse_cargo_toml(text).expect("valid TOML parses");
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"serde"));
        assert!(names.contains(&"tokio"));
        assert!(names.contains(&"cc"));
        let criterion = deps.iter().find(|d| d.name == "criterion").unwrap();
        assert!(criterion.dev);
    }

    #[test]
    fn parse_cargo_toml_resolves_package_rename() {
        // `[dependencies] foo = { package = "real-crate" }` — the real crate
        // name must be scored, not the table key.
        let text = r#"
[dependencies]
foo = { version = "1", package = "real-crate" }
"#;
        let deps = parse_cargo_toml(text).expect("valid TOML parses");
        assert!(
            deps.iter().any(|d| d.name == "real-crate"),
            "the renamed-to crate must be scored: {deps:?}"
        );
        assert!(!deps.iter().any(|d| d.name == "foo"));
    }

    #[test]
    fn parse_cargo_toml_reads_target_specific_deps() {
        let text = r#"
[target.'cfg(unix)'.dependencies]
libc = "0.2"
"#;
        let deps = parse_cargo_toml(text).expect("valid TOML parses");
        assert!(deps.iter().any(|d| d.name == "libc"));
    }

    #[test]
    fn parse_go_mod_reads_block_and_single_require() {
        let text = "\
module example.com/app

go 1.21

require github.com/pkg/errors v0.9.1

require (
    github.com/spf13/cobra v1.7.0
    golang.org/x/sync v0.3.0 // indirect
)
";
        let deps = parse_go_mod(text);
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"github.com/pkg/errors"));
        assert!(names.contains(&"github.com/spf13/cobra"));
        assert!(
            names.contains(&"golang.org/x/sync"),
            "the // indirect comment must be stripped, name kept"
        );
    }

    #[test]
    fn parse_gemfile_reads_gem_directives_and_groups() {
        let text = "\
source 'https://rubygems.org'

gem 'rails', '~> 7.0'
gem \"puma\"

group :development, :test do
  gem 'rspec'
end
";
        let deps = parse_gemfile(text);
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"rails"));
        assert!(names.contains(&"puma"));
        let rspec = deps.iter().find(|d| d.name == "rspec").unwrap();
        assert!(rspec.dev, "a gem in a :test group must be dev-tagged");
    }

    #[test]
    fn parse_gemfile_nested_non_dev_group_keeps_dev_tag() {
        // A non-dev group nested inside a `:development` group: its closing
        // `end` must not clear the dev tag of gems that follow it but are
        // still inside the outer dev group.
        let text = "\
group :development do
  gem 'beforegem'
  group :assets do
    gem 'innergem'
  end
  gem 'aftergem'
end
gem 'toplevelgem'
";
        let deps = parse_gemfile(text);
        let dev = |n: &str| deps.iter().find(|d| d.name == n).unwrap().dev;
        assert!(dev("beforegem"), "a gem before the nested group is dev");
        assert!(
            dev("aftergem"),
            "a gem after a nested non-dev group, still inside :development, must stay dev-tagged"
        );
        assert!(!dev("toplevelgem"), "a top-level gem is not dev");
    }

    #[test]
    fn plausible_package_name_rejects_garbage() {
        assert!(is_plausible_package_name("react"));
        assert!(is_plausible_package_name("@scope/pkg"));
        assert!(is_plausible_package_name("github.com/x/y"));
        assert!(!is_plausible_package_name(""));
        assert!(!is_plausible_package_name("has spaces"));
        assert!(!is_plausible_package_name("{table}"));
    }

    #[test]
    fn hallucinated_shape_flags_lang_prefix_descriptive_name() {
        let shape = hallucinated_name_shape("python-requests-helper");
        assert!(shape.is_some(), "lang prefix + descriptive name is a shape");
        assert!(shape.unwrap().contains("python"));
    }

    #[test]
    fn hallucinated_shape_flags_filler_word_stack() {
        let shape = hallucinated_name_shape("data-utils-helper");
        assert!(
            shape.is_some(),
            "a name that is mostly filler words is a shape"
        );
    }

    #[test]
    fn hallucinated_shape_ignores_normal_names() {
        // Real, normal package names must NOT match a hallucinated shape.
        assert!(hallucinated_name_shape("lodash").is_none());
        assert!(hallucinated_name_shape("react").is_none());
        assert!(hallucinated_name_shape("left-pad").is_none());
        assert!(hallucinated_name_shape("body-parser").is_none());
    }

    #[test]
    fn hallucinated_shape_flags_long_descriptive_name() {
        // 4+ tokens with a filler word.
        let shape = hallucinated_name_shape("acme-data-sync-helper-module");
        assert!(shape.is_some());
    }

    #[test]
    fn slopsquat_clear_for_known_popular() {
        let a = slopsquat("react", &NameVsPopular::KnownPopular, None, Ecosystem::Npm);
        assert_eq!(
            a,
            SlopsquatAssessment::Clear,
            "a known-popular package is never slopsquat"
        );
    }

    #[test]
    fn slopsquat_clear_for_normal_unknown_name() {
        // Unknown, but a normal single-token name and no popular anchor.
        let a = slopsquat(
            "mycompanyinternal",
            &NameVsPopular::Unknown,
            None,
            Ecosystem::Npm,
        );
        assert!(
            !a.is_suspicious(),
            "an unknown name with no hallucinated shape and no anchor is not slopsquat"
        );
    }

    #[test]
    fn slopsquat_fires_on_hallucinated_shape_near_popular() {
        // Hallucinated shape (lang prefix + descriptive) AND near a popular
        // package (edit-distance near-miss supplied as the classification).
        let near = NameVsPopular::NearPopular {
            popular_name: "requests".to_string(),
            distance: 1,
        };
        let a = slopsquat("python-requests-helper", &near, None, Ecosystem::PyPI);
        match a {
            SlopsquatAssessment::Suspicious {
                reasons,
                near_popular,
            } => {
                assert_eq!(near_popular, "requests");
                assert!(!reasons.is_empty());
            }
            SlopsquatAssessment::Clear => {
                panic!("hallucinated shape + near-popular anchor must fire")
            }
        }
    }

    #[test]
    fn slopsquat_does_not_fire_on_shape_alone() {
        // A hallucinated shape but NO popular anchor (Unknown, no DB) must not
        // fire — the anchor is required to keep false positives down.
        let a = slopsquat(
            "data-utils-helper",
            &NameVsPopular::Unknown,
            None,
            Ecosystem::Npm,
        );
        assert!(
            !a.is_suspicious(),
            "a hallucinated shape with no popular anchor must not fire"
        );
    }

    #[test]
    fn slopsquat_does_not_fire_on_anchor_alone() {
        // A near-popular miss but a NORMAL (non-hallucinated) name must not
        // fire as slopsquat — that is the plain `similar_name` case.
        let near = NameVsPopular::NearPopular {
            popular_name: "lodash".to_string(),
            distance: 1,
        };
        let a = slopsquat("lodahs", &near, None, Ecosystem::Npm);
        assert!(
            !a.is_suspicious(),
            "a near-miss with a normal name shape is similar_name, not slopsquat"
        );
    }

    fn assessment_with(
        name: &str,
        name_vs_popular: NameVsPopular,
        malicious_typosquat_of: Option<String>,
        slop: SlopsquatAssessment,
        allowlisted: bool,
    ) -> DependencyAssessment {
        let signals = PackageSignals {
            ecosystem: Ecosystem::Npm,
            name: name.to_string(),
            version: None,
            threat_db_missing: false,
            name_vs_popular,
            malicious_typosquat_of,
            content_signals: ContentSignals::NotInspected,
            api: ApiSignals::offline(),
        };
        DependencyAssessment {
            dependency: DeclaredDependency {
                name: name.to_string(),
                ecosystem: Ecosystem::Npm,
                version: None,
                dev: false,
            },
            manifest: "package.json".to_string(),
            risk: package_risk::score_package(&signals),
            slopsquat: slop,
            allowlisted,
        }
    }

    #[test]
    fn findings_for_allowlisted_dependency_are_suppressed() {
        let a = assessment_with(
            "evil-pkg",
            NameVsPopular::NearPopular {
                popular_name: "react".to_string(),
                distance: 1,
            },
            Some("react".to_string()),
            SlopsquatAssessment::clear(),
            /* allowlisted = */ true,
        );
        let policy = crate::policy::Policy::default();
        assert!(
            findings_for(&a, &policy).is_empty(),
            "an allowlisted dependency must yield no findings"
        );
    }

    #[test]
    fn findings_for_confirmed_typosquat_is_high() {
        let a = assessment_with(
            "raect",
            NameVsPopular::NearPopular {
                popular_name: "react".to_string(),
                distance: 1,
            },
            Some("react".to_string()),
            SlopsquatAssessment::clear(),
            false,
        );
        let policy = crate::policy::Policy::default();
        let findings = findings_for(&a, &policy);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::ThreatPackageTyposquat);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn findings_for_slopsquat_is_medium_suspicious_package() {
        let slop = SlopsquatAssessment::Suspicious {
            reasons: vec!["test reason".to_string()],
            near_popular: "requests".to_string(),
        };
        let a = assessment_with(
            "python-requests-helper",
            NameVsPopular::Unknown,
            None,
            slop,
            false,
        );
        let policy = crate::policy::Policy::default();
        let findings = findings_for(&a, &policy);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::ThreatSuspiciousPackage);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].title.contains("slopsquat"));
    }

    #[test]
    fn findings_for_similar_name_only_is_medium() {
        let a = assessment_with(
            "lodahs",
            NameVsPopular::NearPopular {
                popular_name: "lodash".to_string(),
                distance: 1,
            },
            None,
            SlopsquatAssessment::clear(),
            false,
        );
        let policy = crate::policy::Policy::default();
        let findings = findings_for(&a, &policy);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::ThreatPackageSimilarName);
    }

    #[test]
    fn findings_for_clean_dependency_are_empty() {
        let a = assessment_with(
            "react",
            NameVsPopular::KnownPopular,
            None,
            SlopsquatAssessment::clear(),
            false,
        );
        let policy = crate::policy::Policy::default();
        assert!(findings_for(&a, &policy).is_empty());
    }

    #[test]
    fn findings_for_provenance_only_high_risk_emits_finding() {
        // PR #121 fix-list item 2 regression pin — a dependency with no
        // name-shape risk but a High/Critical provenance score MUST emit a
        // finding (previously it produced none). The fully-loaded provenance
        // stacks enough points to cross the High threshold.
        #[allow(deprecated)]
        let provenance = package_risk::ApiProvenance {
            source: "npm".to_string(),
            package_age_days: Some(1),
            latest_version_age_days: Some(0),
            ownership_transferred: Some(true),
            version_spike: Some(true),
            recent_downloads: Some(3),
            has_source_repo: Some(false),
            yanked_or_deprecated: true,
            latest_version: Some("9.9.9".to_string()),
            ..Default::default()
        };
        let signals = PackageSignals {
            ecosystem: Ecosystem::Npm,
            name: "totally-unknown-pkg".to_string(),
            version: None,
            threat_db_missing: false,
            name_vs_popular: NameVsPopular::Unknown,
            malicious_typosquat_of: None,
            content_signals: ContentSignals::NotInspected,
            api: ApiSignals::Available { provenance },
        };
        let breakdown = package_risk::score_package(&signals);
        assert!(
            matches!(breakdown.risk_level, "high" | "critical"),
            "test fixture must produce a High/Critical score for the \
             provenance-only path to exercise: score={} level={}",
            breakdown.score,
            breakdown.risk_level,
        );
        let assessment = DependencyAssessment {
            dependency: DeclaredDependency {
                name: "totally-unknown-pkg".to_string(),
                ecosystem: Ecosystem::Npm,
                version: None,
                dev: false,
            },
            manifest: "package.json".to_string(),
            risk: breakdown,
            slopsquat: SlopsquatAssessment::clear(),
            allowlisted: false,
        };
        let policy = crate::policy::Policy::default();
        let findings = findings_for(&assessment, &policy);
        assert!(
            !findings.is_empty(),
            "provenance-only High/Critical risk MUST emit a finding"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::ThreatSuspiciousPackage),
            "expected a ThreatSuspiciousPackage finding, got {:?}",
            findings.iter().map(|f| f.rule_id).collect::<Vec<_>>(),
        );
        // M6 ch7: severity is High when score >= block_aggregate_score (76)
        // and Medium when warn_aggregate_score <= score < block_aggregate_score
        // (51..76). Both fire — the test only pins that *something* fires.
        assert!(
            findings.iter().any(|f| matches!(
                f.severity,
                Severity::Medium | Severity::High | Severity::Critical
            )),
            "provenance-only finding must be Medium+, got {:?}",
            findings.iter().map(|f| f.severity).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn findings_for_low_or_medium_risk_with_no_name_shape_emits_nothing() {
        // The provenance-only fall-through fires ONLY on High/Critical; a
        // Low/Medium score with no name-shape signal stays clean (keeps the
        // threshold conservative).
        let signals = PackageSignals {
            ecosystem: Ecosystem::Npm,
            name: "ordinary-pkg".to_string(),
            version: None,
            threat_db_missing: false,
            name_vs_popular: NameVsPopular::Unknown,
            malicious_typosquat_of: None,
            content_signals: ContentSignals::NotInspected,
            api: ApiSignals::offline(), // offline → no api factors
        };
        let breakdown = package_risk::score_package(&signals);
        assert!(
            matches!(breakdown.risk_level, "low" | "medium"),
            "offline + unknown name must score Low/Medium: score={} level={}",
            breakdown.score,
            breakdown.risk_level,
        );
        let assessment = DependencyAssessment {
            dependency: DeclaredDependency {
                name: "ordinary-pkg".to_string(),
                ecosystem: Ecosystem::Npm,
                version: None,
                dev: false,
            },
            manifest: "package.json".to_string(),
            risk: breakdown,
            slopsquat: SlopsquatAssessment::clear(),
            allowlisted: false,
        };
        let policy = crate::policy::Policy::default();
        assert!(
            findings_for(&assessment, &policy).is_empty(),
            "Low/Medium provenance-only score with no name-shape signal must \
             not emit a finding"
        );
    }

    #[test]
    fn typosquat_policy_fires_when_api_signals_unavailable() {
        // Regression: the offline PackagePolicyTyposquatDistance gate used to be
        // skipped when api_signals was not Available, losing typosquat findings
        // on a degraded `--online` scan. Pin that it fires regardless of API state.
        let signals = PackageSignals {
            ecosystem: Ecosystem::Npm,
            name: "reaqt".to_string(),
            version: None,
            threat_db_missing: false,
            name_vs_popular: NameVsPopular::NearPopular {
                popular_name: "react".to_string(),
                distance: 1,
            },
            malicious_typosquat_of: None,
            content_signals: ContentSignals::NotInspected,
            // Critically, the registry call FAILED — we have no provenance.
            api: ApiSignals::unavailable("simulated network timeout"),
        };
        let breakdown = package_risk::score_package(&signals);
        let assessment = DependencyAssessment {
            dependency: DeclaredDependency {
                name: "reaqt".to_string(),
                ecosystem: Ecosystem::Npm,
                version: None,
                dev: false,
            },
            manifest: "package.json".to_string(),
            risk: breakdown,
            slopsquat: SlopsquatAssessment::clear(),
            allowlisted: false,
        };
        // Configure a typosquat-distance policy threshold.
        let mut policy = crate::policy::Policy::default();
        policy.package_policy.block_typosquat_distance = Some(2);

        let findings = policy_findings_for_assessment(&assessment, &policy);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::PackagePolicyTyposquatDistance),
            "PackagePolicyTyposquatDistance must fire even when API is \
             unavailable — got rule_ids: {:?}",
            findings.iter().map(|f| f.rule_id).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn scan_discovers_and_scores_a_temp_project() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"react":"^18.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[dependencies]\nserde = \"1.0\"\n",
        )
        .unwrap();

        let never_allowlisted = |_eco: Ecosystem, _name: &str| false;
        let request = ScanRequest {
            root: dir.path(),
            db: None,
            online: OnlineMode::Off,
            is_allowlisted: &never_allowlisted,
            mode: ScanMode::Manifests,
            installed_max_entries: DEFAULT_MAX_INSTALLED_ENTRIES,
            policy: None,
        };
        let report = scan(&request);
        assert_eq!(report.manifests.len(), 2, "both manifests discovered");
        assert_eq!(report.dependency_count, 2);
        assert!(!report.online);
        // With no threat DB, names classify as Unknown — no findings, but a
        // note about the missing DB is present.
        assert!(report
            .notes
            .iter()
            .any(|n| n.note.contains("threat database")));
    }

    #[test]
    fn scan_skips_node_modules_and_target() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("package.json"), r#"{"dependencies":{}}"#).unwrap();
        // A manifest *inside* node_modules must NOT be discovered.
        let nm = dir.path().join("node_modules").join("dep");
        std::fs::create_dir_all(&nm).unwrap();
        std::fs::write(nm.join("package.json"), r#"{"dependencies":{}}"#).unwrap();

        let manifests = discover_manifests(dir.path());
        assert_eq!(
            manifests.len(),
            1,
            "node_modules must be skipped: {manifests:?}"
        );
    }

    #[test]
    fn scan_of_single_manifest_file_works() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("Cargo.toml");
        std::fs::write(&manifest, "[dependencies]\nserde = \"1\"\n").unwrap();

        let manifests = discover_manifests(&manifest);
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].kind, ManifestKind::CargoToml);
    }

    #[test]
    fn scan_handles_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let never_allowlisted = |_eco: Ecosystem, _name: &str| false;
        let request = ScanRequest {
            root: dir.path(),
            db: None,
            online: OnlineMode::Off,
            is_allowlisted: &never_allowlisted,
            mode: ScanMode::Manifests,
            installed_max_entries: DEFAULT_MAX_INSTALLED_ENTRIES,
            policy: None,
        };
        let report = scan(&request);
        assert_eq!(report.dependency_count, 0);
        assert_eq!(report.verdict.action, Action::Allow);
        assert!(report
            .notes
            .iter()
            .any(|n| n.note.contains("no dependency manifests")));
    }

    #[test]
    fn scan_allowlist_suppresses_findings() {
        // A near-popular dependency would normally yield a finding; an
        // allowlist predicate matching it suppresses the finding but the
        // assessment is still reported.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"my-internal-pkg":"1.0.0"}}"#,
        )
        .unwrap();
        let allow_all = |_eco: Ecosystem, _name: &str| true;
        let request = ScanRequest {
            root: dir.path(),
            db: None,
            online: OnlineMode::Off,
            is_allowlisted: &allow_all,
            mode: ScanMode::Manifests,
            installed_max_entries: DEFAULT_MAX_INSTALLED_ENTRIES,
            policy: None,
        };
        let report = scan(&request);
        assert_eq!(report.allowlisted_count(), 1);
        assert!(report.verdict.findings.is_empty());
    }

    #[test]
    fn scan_online_resolver_is_memoized_per_package() {
        use std::cell::RefCell;
        // The same package declared in two manifests must trigger the
        // resolver at most once.
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"shared-dep":"1.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            sub.join("package.json"),
            r#"{"dependencies":{"shared-dep":"1.0.0"}}"#,
        )
        .unwrap();

        let calls = RefCell::new(0usize);
        let resolver = |_eco: Ecosystem, _name: &str| {
            *calls.borrow_mut() += 1;
            ApiSignals::offline()
        };
        let never_allowlisted = |_eco: Ecosystem, _name: &str| false;
        let request = ScanRequest {
            root: dir.path(),
            db: None,
            online: OnlineMode::Resolver(&resolver),
            is_allowlisted: &never_allowlisted,
            mode: ScanMode::Manifests,
            installed_max_entries: DEFAULT_MAX_INSTALLED_ENTRIES,
            policy: None,
        };
        let report = scan(&request);
        assert!(report.online);
        assert_eq!(report.dependency_count, 2, "declared in two manifests");
        assert_eq!(
            *calls.borrow(),
            1,
            "the resolver must be memoized per distinct package"
        );
    }

    // Installed-tree mode fixtures live here (not in tests/fixtures/, which is
    // the command-line `tirith check` format). Signed-threat-DB block fixtures
    // are exercised by the integration tests in cli_integration.rs.

    fn never_allow(_eco: Ecosystem, _name: &str) -> bool {
        false
    }

    #[test]
    fn installed_mode_positive_node_modules_surfaces_assessment() {
        // Without a threat DB no name-based finding fires, but the package must
        // still surface as a DeclaredDependency with mode "installed". The
        // BLOCK side is in cli_integration.rs (signed threat-DB fixture).
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("node_modules").join("evil-package");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            r#"{"name":"evil-package","version":"1.0.0"}"#,
        )
        .unwrap();

        let request = ScanRequest {
            root: dir.path(),
            db: None,
            online: OnlineMode::Off,
            is_allowlisted: &never_allow,
            mode: ScanMode::Installed,
            installed_max_entries: DEFAULT_MAX_INSTALLED_ENTRIES,
            policy: None,
        };
        let report = scan(&request);
        assert_eq!(report.mode, "installed");
        assert_eq!(report.dependency_count, 1);
        assert_eq!(report.assessments[0].dependency.name, "evil-package");
        assert_eq!(
            report.assessments[0].dependency.version,
            Some("1.0.0".to_string())
        );
        assert_eq!(report.assessments[0].dependency.ecosystem, Ecosystem::Npm);
    }

    #[test]
    fn installed_mode_clean_node_modules_allows() {
        // Three benign packages in node_modules — none known-malicious, none
        // slopsquat-shaped → verdict ALLOW. The wider integration suite uses
        // the signed test threat DB to verify the BLOCK side of this case.
        let dir = tempfile::tempdir().unwrap();
        for (pkg, version) in [
            ("react", "18.2.0"),
            ("left-pad", "1.3.0"),
            ("lodash", "4.17.21"),
        ] {
            let p = dir.path().join("node_modules").join(pkg);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(
                p.join("package.json"),
                format!(r#"{{"name":"{pkg}","version":"{version}"}}"#),
            )
            .unwrap();
        }

        let request = ScanRequest {
            root: dir.path(),
            db: None,
            online: OnlineMode::Off,
            is_allowlisted: &never_allow,
            mode: ScanMode::Installed,
            installed_max_entries: DEFAULT_MAX_INSTALLED_ENTRIES,
            policy: None,
        };
        let report = scan(&request);
        assert_eq!(report.mode, "installed");
        assert_eq!(report.dependency_count, 3);
        assert_eq!(
            report.verdict.action,
            Action::Allow,
            "three benign packages must ALLOW; findings: {:?}",
            report.verdict.findings,
        );
    }

    #[test]
    fn specific_lockfile_with_named_dep_surfaces_assessment() {
        // A package-lock.json that pins a package by name is parsed via
        // SpecificLockfile mode and surfaces one DeclaredDependency per
        // resolved package. mode field reads "specific_lockfile".
        let dir = tempfile::tempdir().unwrap();
        let lockfile = dir.path().join("package-lock.json");
        std::fs::write(
            &lockfile,
            r#"{
              "name": "demo",
              "lockfileVersion": 3,
              "packages": {
                "": {"name":"demo","version":"1.0.0"},
                "node_modules/evil-package": {"version":"1.0.0"}
              }
            }"#,
        )
        .unwrap();

        let request = ScanRequest {
            root: &lockfile,
            db: None,
            online: OnlineMode::Off,
            is_allowlisted: &never_allow,
            mode: ScanMode::SpecificLockfile(lockfile.clone()),
            installed_max_entries: DEFAULT_MAX_INSTALLED_ENTRIES,
            policy: None,
        };
        let report = scan(&request);
        assert_eq!(report.mode, "specific_lockfile");
        assert_eq!(report.dependency_count, 1);
        assert_eq!(report.assessments[0].dependency.name, "evil-package");
    }

    #[test]
    fn specific_lockfile_clean_allows() {
        // Same shape as above but with clean dependencies → ALLOW.
        let dir = tempfile::tempdir().unwrap();
        let lockfile = dir.path().join("package-lock.json");
        std::fs::write(
            &lockfile,
            r#"{
              "name": "demo",
              "lockfileVersion": 3,
              "packages": {
                "": {"name":"demo","version":"1.0.0"},
                "node_modules/react": {"version":"18.2.0"},
                "node_modules/lodash": {"version":"4.17.21"}
              }
            }"#,
        )
        .unwrap();

        let request = ScanRequest {
            root: &lockfile,
            db: None,
            online: OnlineMode::Off,
            is_allowlisted: &never_allow,
            mode: ScanMode::SpecificLockfile(lockfile.clone()),
            installed_max_entries: DEFAULT_MAX_INSTALLED_ENTRIES,
            policy: None,
        };
        let report = scan(&request);
        assert_eq!(report.mode, "specific_lockfile");
        assert_eq!(report.dependency_count, 2);
        assert_eq!(
            report.verdict.action,
            Action::Allow,
            "two clean deps in a lockfile must ALLOW: {:?}",
            report.verdict.findings,
        );
    }

    #[test]
    fn installed_mode_respects_max_entries_cap() {
        // Five packages under node_modules, cap at 2 → only 2 scored, and a
        // truncation note recorded.
        let dir = tempfile::tempdir().unwrap();
        for name in ["a-pkg", "b-pkg", "c-pkg", "d-pkg", "e-pkg"] {
            let p = dir.path().join("node_modules").join(name);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(
                p.join("package.json"),
                format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
            )
            .unwrap();
        }

        let request = ScanRequest {
            root: dir.path(),
            db: None,
            online: OnlineMode::Off,
            is_allowlisted: &never_allow,
            mode: ScanMode::Installed,
            // The MIN_INSTALLED_ENTRIES check lives at the CLI; the engine
            // accepts any non-zero cap.
            installed_max_entries: 2,
            policy: None,
        };
        let report = scan(&request);
        assert_eq!(
            report.dependency_count, 2,
            "the cap must stop the walk early"
        );
        assert!(
            report.notes.iter().any(|n| n.note.contains("truncated")),
            "a truncation note must be recorded: {:?}",
            report.notes
        );
    }

    #[test]
    fn installed_mode_reads_dist_info_metadata() {
        // A synthetic site-packages with one `.dist-info/METADATA` entry must
        // be discovered as a PyPI dependency.
        let dir = tempfile::tempdir().unwrap();
        let dist = dir
            .path()
            .join("site-packages")
            .join("flask-3.0.0.dist-info");
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::write(
            dist.join("METADATA"),
            "Metadata-Version: 2.1\nName: flask\nVersion: 3.0.0\n\nA tiny WSGI framework.\n",
        )
        .unwrap();

        let request = ScanRequest {
            root: dir.path(),
            db: None,
            online: OnlineMode::Off,
            is_allowlisted: &never_allow,
            mode: ScanMode::Installed,
            installed_max_entries: DEFAULT_MAX_INSTALLED_ENTRIES,
            policy: None,
        };
        let report = scan(&request);
        assert_eq!(report.dependency_count, 1);
        assert_eq!(report.assessments[0].dependency.name, "flask");
        assert_eq!(report.assessments[0].dependency.ecosystem, Ecosystem::PyPI);
    }

    #[test]
    fn installed_mode_parses_cargo_lock_at_root() {
        // A workspace Cargo.lock at the scan root must be picked up in
        // installed mode and emit one DeclaredDependency per `[[package]]`.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.lock"),
            r#"version = 3
[[package]]
name = "anyhow"
version = "1.0.86"

[[package]]
name = "thiserror"
version = "1.0.61"
"#,
        )
        .unwrap();

        let request = ScanRequest {
            root: dir.path(),
            db: None,
            online: OnlineMode::Off,
            is_allowlisted: &never_allow,
            mode: ScanMode::Installed,
            installed_max_entries: DEFAULT_MAX_INSTALLED_ENTRIES,
            policy: None,
        };
        let report = scan(&request);
        assert_eq!(
            report.dependency_count, 2,
            "Cargo.lock declares two packages: {:?}",
            report.assessments
        );
        for a in &report.assessments {
            assert_eq!(a.dependency.ecosystem, Ecosystem::Crates);
        }
    }

    #[test]
    fn specific_lockfile_with_unrecognized_file_records_note() {
        // A bogus path passed via SpecificLockfile must surface a note rather
        // than crash. A piped consumer sees mode=specific_lockfile and
        // dependency_count=0, plus an explanatory note.
        let dir = tempfile::tempdir().unwrap();
        let bogus = dir.path().join("not-a-lockfile.json");
        std::fs::write(&bogus, "{}").unwrap();

        let request = ScanRequest {
            root: &bogus,
            db: None,
            online: OnlineMode::Off,
            is_allowlisted: &never_allow,
            mode: ScanMode::SpecificLockfile(bogus.clone()),
            installed_max_entries: DEFAULT_MAX_INSTALLED_ENTRIES,
            policy: None,
        };
        let report = scan(&request);
        assert_eq!(report.mode, "specific_lockfile");
        assert_eq!(report.dependency_count, 0);
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.note.contains("not a recognized manifest format")),
            "must record a 'not recognized' note for an unknown file: {:?}",
            report.notes
        );
    }
}
