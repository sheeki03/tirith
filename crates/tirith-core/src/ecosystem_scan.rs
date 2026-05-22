//! `tirith ecosystem scan` — supply-chain risk scan of a project's dependency
//! manifests.
//!
//! This is the directory-level companion to [`crate::package_risk`]: where
//! `package risk` scores **one** package by name, `ecosystem scan` discovers
//! every dependency a project *declares* (across npm / Python / Rust / and
//! more) and scores each one with the **same deterministic factor engine**.
//! There is no model and no learned weight here either — every score is the
//! `package_risk` factor sum, reproducible by hand.
//!
//! ## What it does
//!
//! 1. **Discovers manifests.** A bounded directory walk finds dependency
//!    manifests by their well-known names — `package.json`,
//!    `package-lock.json`, `requirements.txt`, `pyproject.toml`, `Cargo.toml`,
//!    `go.mod`, `Gemfile`. See [`discover_manifests`].
//! 2. **Parses declared dependencies.** Each manifest format has a small,
//!    total parser that extracts `(ecosystem, name)` pairs. Parsers never
//!    execute the manifest and never reach the network.
//! 3. **Scores each dependency.** Every declared package is run through
//!    [`package_risk::score_package`] with offline signals (the threat-DB
//!    `popular` / `typosquat` data). An opt-in `--online` pass adds the
//!    registry-API provenance signals — gated exactly as `package risk` is.
//! 4. **Folds in slopsquat detection.** *Slopsquatting* is the registration of
//!    a plausible-but-fake package name that LLMs tend to hallucinate. A
//!    dependency is flagged slopsquat-suspicious when it is **not** a
//!    known-real / known-popular package, its name is *shaped like* an
//!    AI-hallucinated name, and it sits near a real popular name. The signal
//!    is built entirely from local threat-DB data plus the `package_risk`
//!    name signal — see [`slopsquat`].
//!
//! ## Output: the Verdict / Finding model
//!
//! `ecosystem scan` produces a [`Verdict`] of [`Finding`]s, exactly like the
//! detection engine — so the result is explainable, audit-loggable, and
//! policy-aware (an allowlisted package is suppressed). It reuses the existing
//! package-supply-chain [`RuleId`]s ([`RuleId::ThreatPackageTyposquat`],
//! [`RuleId::ThreatPackageSimilarName`], [`RuleId::ThreatSuspiciousPackage`])
//! rather than inventing new ones: a manifest scan is not a new *kind* of
//! supply-chain risk, it is the same risks found by walking a project instead
//! of one `install` command.
//!
//! ## Determinism
//!
//! Every function here is a pure, total function of its inputs except the
//! filesystem walk and the opt-in registry fetch. Given the same manifests
//! and the same threat DB, the verdict is byte-for-byte reproducible.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::package_risk::{
    self, ApiSignals, ContentSignals, NameVsPopular, PackageSignals, RiskBreakdown,
};
use crate::threatdb::{Ecosystem, ThreatDb};
use crate::verdict::{Action, Evidence, Finding, RuleId, Severity, Timings, Verdict};

/// Maximum directory depth the manifest walk descends. Manifests live at a
/// project root or shallowly nested (a workspace member, a sub-package); a
/// deep walk would mostly traverse `node_modules` / `target` and is bounded
/// out instead.
pub const MAX_WALK_DEPTH: usize = 6;

/// Hard cap on directory entries examined during the walk, so a pathological
/// tree can never stall the scan.
pub const MAX_WALK_ENTRIES: usize = 50_000;

/// Hard cap on declared dependencies scored in a single run. A manifest with
/// more entries than this is still parsed; scoring stops at the cap and the
/// summary records the truncation.
pub const MAX_DEPENDENCIES: usize = 5_000;

/// Directory names never descended into — build output and vendored trees
/// hold installed *content*, not a project's declared manifests, and would
/// otherwise dominate the walk.
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

// ===========================================================================
// manifest discovery
// ===========================================================================

/// A dependency-manifest file format `ecosystem scan` understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestKind {
    /// npm `package.json` — `dependencies` + `devDependencies` maps.
    NpmPackageJson,
    /// npm `package-lock.json` — the fully-resolved `packages` / `dependencies`
    /// tree (covers transitive dependencies the manifest alone does not).
    NpmPackageLock,
    /// Python `requirements.txt` — one requirement specifier per line.
    PyRequirementsTxt,
    /// Python `pyproject.toml` — PEP 621 `[project].dependencies` and the
    /// Poetry `[tool.poetry.dependencies]` table.
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
    ///
    /// `requirements.txt` matching is loosened to any `requirements*.txt`
    /// (e.g. `requirements-dev.txt`) since split requirement files are common.
    fn from_file_name(name: &str) -> Option<ManifestKind> {
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
/// [`MAX_WALK_DEPTH`] and [`MAX_WALK_ENTRIES`].
///
/// Build-output and vendored directories ([`SKIP_DIRS`]) are not descended.
/// The walk reads only directory entries — never file content. When `root` is
/// itself a manifest file, that single manifest is returned. The result is
/// sorted by path so a scan is deterministic regardless of `read_dir` order.
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
    // hard, observable bound and a deep tree cannot blow the stack). The walk
    // order is unspecified — the result is sorted by path before returning, so
    // a scan is deterministic regardless.
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
                // Never descend a build-output / vendored tree, and never a
                // hidden directory other than the ones explicitly handled.
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

// ===========================================================================
// manifest parsing — declared dependencies
// ===========================================================================

/// One dependency a manifest declares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeclaredDependency {
    /// The package name as written in the manifest.
    pub name: String,
    /// The ecosystem the manifest is for.
    #[serde(serialize_with = "serialize_ecosystem")]
    pub ecosystem: Ecosystem,
    /// The version / version-range string as written, when the manifest gives
    /// one (a `package-lock.json` resolves to an exact version; a bare
    /// `requirements.txt` line may give none).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Whether the manifest declares this as a development-only dependency.
    pub dev: bool,
}

fn serialize_ecosystem<S: serde::Serializer>(eco: &Ecosystem, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&eco.to_string())
}

/// Parse a manifest's text into the dependencies it declares.
///
/// Total and side-effect-free: a malformed manifest yields an empty list, not
/// an error and not a panic — a scan over a partly-broken project still
/// reports on the manifests it could read.
pub fn parse_manifest(kind: ManifestKind, text: &str) -> Vec<DeclaredDependency> {
    match kind {
        ManifestKind::NpmPackageJson => parse_package_json(text),
        ManifestKind::NpmPackageLock => parse_package_lock(text),
        ManifestKind::PyRequirementsTxt => parse_requirements_txt(text),
        ManifestKind::PyPyprojectToml => parse_pyproject_toml(text),
        ManifestKind::CargoToml => parse_cargo_toml(text),
        ManifestKind::GoMod => parse_go_mod(text),
        ManifestKind::RubyGemfile => parse_gemfile(text),
    }
}

/// npm `package.json`: `dependencies`, `devDependencies`, `optionalDependencies`,
/// `peerDependencies`. `devDependencies` are tagged `dev = true`.
fn parse_package_json(text: &str) -> Vec<DeclaredDependency> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
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
    out
}

/// npm `package-lock.json`: the fully-resolved tree. lockfile v2/v3 keys the
/// `packages` map by install path (`node_modules/<name>`); v1 keys the
/// `dependencies` map directly by name. Both are read so the lock's
/// *transitive* closure is covered.
fn parse_package_lock(text: &str) -> Vec<DeclaredDependency> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
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

    out
}

/// Extract the package name from a `package-lock.json` v2/v3 path key.
/// `"node_modules/lodash"` → `"lodash"`,
/// `"node_modules/foo/node_modules/@scope/bar"` → `"@scope/bar"`.
/// The empty string (the lockfile's root entry) yields `None`.
fn package_lock_name_from_path(path_key: &str) -> Option<String> {
    if path_key.is_empty() {
        return None;
    }
    // The installed name is whatever follows the LAST `node_modules/`.
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

/// Python `requirements.txt`: one PEP 508 requirement specifier per line.
/// Comments (`#`), blank lines, and pip option lines (`-r`, `--index-url`,
/// `-e`, …) are skipped. A leading environment marker / extras / version
/// specifier is trimmed to leave the bare distribution name.
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

/// Extract the bare distribution name from a PEP 508 requirement line.
/// `"requests>=2.0"` → `"requests"`, `"flask[async]==3.0"` → `"flask"`,
/// `'django ; python_version < "3.9"'` → `"django"`.
fn python_requirement_name(line: &str) -> Option<String> {
    // Cut at the first character that ends the name: a version operator, an
    // extras bracket, an environment-marker semicolon, or whitespace.
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
fn parse_pyproject_toml(text: &str) -> Vec<DeclaredDependency> {
    let Ok(doc) = toml::from_str::<toml::Value>(text) else {
        return Vec::new();
    };
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
    // Poetry dev groups: `[tool.poetry.group.<name>.dependencies]` and the
    // legacy `[tool.poetry.dev-dependencies]`.
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

    out
}

/// Rust `Cargo.toml`: `[dependencies]`, `[build-dependencies]`,
/// `[dev-dependencies]`, and the same three under any `[target.*]` table.
fn parse_cargo_toml(text: &str) -> Vec<DeclaredDependency> {
    let Ok(doc) = toml::from_str::<toml::Value>(text) else {
        return Vec::new();
    };
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
                // A `package = "real-name"` rename keys the real crate under a
                // different table key — score the real crate name.
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

    out
}

/// Go `go.mod`: `require` directives, both the single-line form
/// (`require example.com/mod v1.2.3`) and the block form. The module path
/// is taken as the package name.
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

/// Parse one `go.mod` require entry: `"example.com/mod v1.2.3"` (an optional
/// trailing `// indirect`-style comment is already stripped by the caller).
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

/// Ruby `Gemfile`: `gem "name"` / `gem 'name', '~> 1.0'` directives. A `gem`
/// line inside a `group :development` / `group :test` block is tagged
/// `dev = true`.
fn parse_gemfile(text: &str) -> Vec<DeclaredDependency> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    // Track group nesting so a dev/test group tags its gems.
    let mut group_dev_depth = 0i32;

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
        if let Some(rest) = line.strip_prefix("group ") {
            let lower = rest.to_lowercase();
            let is_dev = lower.contains("development") || lower.contains("test");
            if line.ends_with("do") {
                group_dev_depth += if is_dev { 1 } else { 0 };
            }
            continue;
        }
        if line == "end" && group_dev_depth > 0 {
            group_dev_depth -= 1;
            continue;
        }
        if let Some(name) = gemfile_gem_name(line) {
            if seen.insert(name.clone()) {
                out.push(DeclaredDependency {
                    name,
                    ecosystem: Ecosystem::RubyGems,
                    version: None,
                    dev: group_dev_depth > 0,
                });
            }
        }
    }
    out
}

/// Extract the gem name from a `gem "name", ...` Gemfile line.
fn gemfile_gem_name(line: &str) -> Option<String> {
    let rest = line.strip_prefix("gem ")?.trim_start();
    // The name is the first single- or double-quoted string.
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

/// `true` when `name` is shaped like a real package name and not, e.g., a
/// path fragment, a TOML inline-table fragment, or an empty token. Deliberately
/// permissive — it rejects only clearly-not-a-name strings.
fn is_plausible_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 214 {
        return false;
    }
    // A name is made of name characters: ASCII alphanumerics plus the small
    // set of separators package ecosystems allow. A scope (`@scope/pkg`) and a
    // Go module path (`example.com/mod`) both legitimately contain `/`.
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '/' | '+'))
}

// ===========================================================================
// slopsquat detection
// ===========================================================================

/// The deterministic verdict of the slopsquat heuristic for one dependency.
///
/// *Slopsquatting* is the registration of a plausible-but-fake package name
/// that an LLM is likely to hallucinate when asked to "suggest a package".
/// This is **not** a confirmed-malicious signal — it is an advisory shape
/// match — so it is deliberately conservative: it fires only when a name is
/// unknown to the threat DB **and** looks AI-hallucinated **and** sits near a
/// real popular name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SlopsquatAssessment {
    /// `true` when the dependency is slopsquat-suspicious.
    pub suspicious: bool,
    /// The named, inspectable reasons the heuristic fired (empty when not
    /// suspicious). Each is a plain-language clause a reader can verify.
    pub reasons: Vec<String>,
    /// The popular package the suspicious name sits near, when the heuristic
    /// identified one (an edit-distance near-miss or a shared token).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub near_popular: Option<String>,
}

impl SlopsquatAssessment {
    /// The not-suspicious verdict.
    fn clear() -> Self {
        SlopsquatAssessment {
            suspicious: false,
            reasons: Vec::new(),
            near_popular: None,
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

/// Assess whether a declared dependency is slopsquat-suspicious.
///
/// Pure and total — a function of the name, its [`NameVsPopular`]
/// classification (already computed by [`package_risk::classify_name`]), and
/// the threat DB. The DB is consulted read-only for popular-name token / known
/// status; no network, no filesystem.
///
/// The heuristic, all three layers required:
///
/// 1. **Unknown to the threat DB.** A known-popular package, or a name the DB
///    lists as a confirmed typosquat, is *not* a slopsquat candidate — those
///    are handled by their own (stronger) findings. Slopsquatting is about
///    names that are simply *not real*.
/// 2. **AI-hallucinated name shape.** The name is composed in the way an LLM
///    composes a plausible-but-fake suggestion: a language prefix plus a real
///    package token, or a stack of generic filler words, or an unusually long
///    multi-segment descriptive name.
/// 3. **Near a real popular name.** The name is one edit from a popular
///    package ([`NameVsPopular::NearPopular`]), or it *contains a popular
///    package name as one of its `-`/`_`-delimited tokens* (the
///    `<popular>-helper` shape — a hallucinated companion to a real library).
pub fn slopsquat(
    name: &str,
    name_vs_popular: &NameVsPopular,
    db: Option<&ThreatDb>,
    ecosystem: Ecosystem,
) -> SlopsquatAssessment {
    // Layer 1 — must be unknown. A known-popular name is real; a near-popular
    // name that the DB *also* lists as a confirmed typosquat is covered by the
    // typosquat finding. Slopsquatting only concerns names that are not real.
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

    // The heuristic fires only when BOTH a hallucinated shape AND a
    // near-popular anchor are present. A name that merely looks generic, or
    // merely resembles a popular name, is not enough on its own — that keeps
    // the false-positive rate low (an honest `data-utils` with no popular
    // anchor does not fire; a near-miss with a normal name does not fire).
    let suspicious = shape.is_some() && near_popular.is_some();
    if !suspicious {
        return SlopsquatAssessment::clear();
    }

    SlopsquatAssessment {
        suspicious,
        reasons,
        near_popular,
    }
}

/// If `name` is shaped like an AI-hallucinated package name, return a
/// plain-language reason; otherwise `None`.
///
/// Three recognised shapes:
/// * a language prefix (`python-`, `node-`, `go-`) on a longer descriptive
///   name;
/// * a name whose `-`/`_` tokens are *mostly* generic filler words;
/// * an unusually long multi-segment descriptive name (4+ tokens).
fn hallucinated_name_shape(name: &str) -> Option<String> {
    let lower = name.to_lowercase();
    // Tokenize on the separators package names use. A scope is dropped so
    // `@acme/data-helper-utils` tokenizes as `data`, `helper`, `utils`.
    let bare = lower.rsplit('/').next().unwrap_or(&lower);
    let tokens: Vec<&str> = bare
        .split(['-', '_', '.'])
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.len() < 2 {
        // A single-token name (`requests`, `lodash`) is not a composed,
        // descriptive shape — slopsquatting hallucinates *descriptive* names.
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

    // Shape C — an unusually long multi-segment descriptive name with at
    // least one filler word (4+ tokens). Real packages are occasionally long
    // (`@babel/plugin-transform-runtime`) so a filler word is also required.
    if tokens.len() >= 4 && filler_count >= 1 {
        return Some(format!(
            "the name stacks {} '-'/'_'-separated tokens including filler words — \
             real packages are rarely this descriptively long",
            tokens.len()
        ));
    }

    None
}

/// If one of `name`'s `-`/`_`-delimited tokens is *itself* a known-popular
/// package (and the whole name is not that package), return the popular token.
///
/// This catches the `<popular>-helper` / `easy-<popular>` slopsquat shape: an
/// LLM hallucinates a companion to a library the user actually wanted
/// (`react-router-helper`, `easy-express`). The token must be reasonably long
/// (>= 3 chars) so a coincidental short token (`go`, `js`) does not match.
fn popular_token_in_name(name: &str, db: Option<&ThreatDb>, eco: Ecosystem) -> Option<String> {
    let db = db?;
    let lower = name.to_lowercase();
    let bare = lower.rsplit('/').next().unwrap_or(&lower);
    let tokens: Vec<&str> = bare.split(['-', '_']).filter(|t| t.len() >= 3).collect();
    // A single-token name *is* its token — that is not "embedding" a popular
    // name, it is just being (or not being) that package. Require composition.
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

// ===========================================================================
// per-dependency assessment + finding construction
// ===========================================================================

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

/// Build the [`Finding`]s a single [`DependencyAssessment`] produces.
///
/// A dependency can yield more than one finding (a confirmed-malicious package
/// that is *also* slopsquat-shaped), but in practice the strongest signal
/// usually stands alone. Findings reuse the existing package-supply-chain
/// [`RuleId`]s. An allowlisted dependency produces no findings.
pub fn findings_for(assessment: &DependencyAssessment) -> Vec<Finding> {
    if assessment.allowlisted {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let dep = &assessment.dependency;
    let manifest = &assessment.manifest;

    // 1 — confirmed malicious typosquat from the threat DB. The strongest
    // offline signal; it stands alone.
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

    // 2 — slopsquat-suspicious (AI-hallucinated name). Advisory: a name shaped
    // like an LLM hallucination, near a real popular package.
    if assessment.slopsquat.suspicious {
        let near = assessment
            .slopsquat
            .near_popular
            .as_deref()
            .unwrap_or("a popular package");
        findings.push(Finding {
            rule_id: RuleId::ThreatSuspiciousPackage,
            severity: Severity::Medium,
            title: format!(
                "Possible slopsquat dependency: {} (near '{}')",
                dep.name, near
            ),
            description: format!(
                "The {} dependency '{}' declared in {} is not a known-real package and its \
                 name is shaped like an AI-hallucinated ('slopsquat') name sitting near the \
                 real package '{}'. {}. Verify the package is intentional and exists on its \
                 registry before trusting it. Risk score {}/100 ({}).",
                dep.ecosystem,
                dep.name,
                manifest,
                near,
                assessment.slopsquat.reasons.join("; "),
                assessment.risk.score,
                assessment.risk.risk_level,
            ),
            evidence: vec![Evidence::Text {
                detail: format!(
                    "manifest={manifest} package={} ecosystem={} near_popular={near} \
                     reasons=[{}]",
                    dep.name,
                    dep.ecosystem,
                    assessment.slopsquat.reasons.join(" | "),
                ),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
        return findings;
    }

    // 3 — name resembles a popular package (one edit) without a slopsquat
    // shape and without a DB typosquat record. The weakest signal.
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
    }

    findings
}

// ===========================================================================
// the scan itself
// ===========================================================================

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
    /// The manifest files discovered and parsed.
    pub manifests: Vec<String>,
    /// Total declared dependencies discovered across all manifests.
    pub dependency_count: usize,
    /// The per-dependency assessments, in a stable order.
    pub assessments: Vec<DependencyAssessment>,
    /// Whether the registry-API (`--online`) signals were used.
    pub online: bool,
    /// Notes about coverage — unreadable manifests, truncation, a missing
    /// threat DB.
    pub notes: Vec<ScanNote>,
    /// The verdict: every finding from every non-allowlisted dependency, with
    /// an action derived from the strongest finding's severity.
    pub verdict: Verdict,
}

/// How a scan resolves the registry-API state per dependency. The CLI layer
/// supplies this so the core stays free of any direct network or
/// environment-variable knowledge: an offline scan passes [`OnlineMode::Off`];
/// an `--online` scan passes [`OnlineMode::Resolver`] with a closure that does
/// the (cached, gated) fetch.
pub enum OnlineMode<'a> {
    /// Offline scan — every dependency's API signals are
    /// [`ApiSignals::NotComputed`].
    Off,
    /// `--online` scan — the closure resolves each `(ecosystem, name)` to its
    /// [`ApiSignals`]. The closure is expected to be offline-safe (degrading
    /// any failure to [`ApiSignals::Unavailable`]); it is called at most once
    /// per distinct package.
    Resolver(&'a dyn Fn(Ecosystem, &str) -> ApiSignals),
}

/// Inputs to [`scan`] — kept in a struct so the signature stays stable as
/// options are added.
pub struct ScanRequest<'a> {
    /// The directory or single manifest file to scan.
    pub root: &'a Path,
    /// The loaded threat DB, or `None` when one is not installed (the scan
    /// still runs; name signals fall back to "unknown" and a note is added).
    pub db: Option<&'a ThreatDb>,
    /// The registry-API resolution mode.
    pub online: OnlineMode<'a>,
    /// A predicate that returns `true` when a `(ecosystem, name)` pair is
    /// allowlisted by policy and its findings must be suppressed.
    pub is_allowlisted: &'a dyn Fn(Ecosystem, &str) -> bool,
}

/// Run an `ecosystem scan` over `request.root` and return the full report.
///
/// This is the single entry point. It discovers manifests, parses every
/// declared dependency, scores each through [`package_risk::score_package`],
/// folds in the [`slopsquat`] heuristic, and assembles a [`Verdict`]. It never
/// panics; a malformed manifest is skipped with a note, not an error.
pub fn scan(request: &ScanRequest) -> EcosystemScanReport {
    let manifests = discover_manifests(request.root);
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

    if manifests.is_empty() {
        notes.push(ScanNote {
            manifest: None,
            note: "no dependency manifests found (looked for package.json, \
                   package-lock.json, requirements*.txt, pyproject.toml, Cargo.toml, \
                   go.mod, Gemfile)."
                .to_string(),
        });
    }

    // Parse every manifest into its declared dependencies.
    let root_display = request.root.display().to_string();
    let mut declared: Vec<(DeclaredDependency, String)> = Vec::new();
    let mut manifest_labels: Vec<String> = Vec::new();
    for manifest in &manifests {
        let rel = relative_label(request.root, &manifest.path);
        manifest_labels.push(rel.clone());
        let text = match std::fs::read_to_string(&manifest.path) {
            Ok(t) => t,
            Err(e) => {
                notes.push(ScanNote {
                    manifest: Some(rel.clone()),
                    note: format!("could not read manifest: {e}"),
                });
                continue;
            }
        };
        let deps = parse_manifest(manifest.kind, &text);
        if deps.is_empty() {
            notes.push(ScanNote {
                manifest: Some(rel.clone()),
                note: "no dependencies parsed (the file may be empty, malformed, or \
                       declare no dependencies)."
                    .to_string(),
            });
        }
        for dep in deps {
            declared.push((dep, rel.clone()));
        }
    }

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

    // Score each declared dependency. The registry-API resolver is memoized so
    // a package declared in two manifests is fetched at most once.
    let online = matches!(request.online, OnlineMode::Resolver(_));
    let mut api_cache: std::collections::HashMap<(Ecosystem, String), ApiSignals> =
        std::collections::HashMap::new();
    let mut assessments: Vec<DependencyAssessment> = Vec::new();

    for (dep, manifest) in declared {
        let assessment = assess_dependency(&dep, &manifest, request, &mut api_cache);
        assessments.push(assessment);
    }

    // Assemble the verdict: every finding from every assessment.
    let mut findings: Vec<Finding> = Vec::new();
    for assessment in &assessments {
        findings.extend(findings_for(assessment));
    }
    // tier_reached is 3 — `ecosystem scan` does the full analysis (it is not a
    // tier-gated hot-path command).
    let verdict = Verdict::from_findings(findings, 3, Timings::default());

    EcosystemScanReport {
        scan_root: root_display,
        manifests: manifest_labels,
        dependency_count,
        assessments,
        online,
        notes,
        verdict,
    }
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
        threat_db_missing: request.db.is_none(),
        name_vs_popular: name_vs_popular.clone(),
        malicious_typosquat_of,
        // A manifest scan never has the package *content* on disk (the
        // manifest only *declares* the dependency), so content signals are
        // always NotInspected. `tirith package risk --path` is the command
        // for inspecting installed content.
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
/// path when it is not under the root. Keeps report output stable and short.
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

    // --- manifest classification ------------------------------------------

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

    // --- package.json -----------------------------------------------------

    #[test]
    fn parse_package_json_extracts_deps_and_dev_deps() {
        let text = r#"{
            "name": "app",
            "dependencies": { "react": "^18.0.0", "lodash": "4.17.21" },
            "devDependencies": { "jest": "^29.0.0" }
        }"#;
        let deps = parse_package_json(text);
        assert_eq!(deps.len(), 3);
        let react = deps.iter().find(|d| d.name == "react").unwrap();
        assert!(!react.dev);
        assert_eq!(react.version.as_deref(), Some("^18.0.0"));
        let jest = deps.iter().find(|d| d.name == "jest").unwrap();
        assert!(jest.dev, "devDependencies must be tagged dev");
    }

    #[test]
    fn parse_package_json_handles_malformed() {
        assert!(parse_package_json("{not json").is_empty());
        assert!(parse_package_json("").is_empty());
        // Valid JSON, no dependency fields.
        assert!(parse_package_json(r#"{"name":"x"}"#).is_empty());
    }

    // --- package-lock.json ------------------------------------------------

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
        let deps = parse_package_lock(text);
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
        let deps = parse_package_lock(text);
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

    // --- requirements.txt -------------------------------------------------

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

    // --- pyproject.toml ---------------------------------------------------

    #[test]
    fn parse_pyproject_pep621_dependencies() {
        let text = r#"
[project]
name = "app"
dependencies = ["requests>=2.0", "click"]

[project.optional-dependencies]
dev = ["pytest>=7.0", "black"]
"#;
        let deps = parse_pyproject_toml(text);
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
        let deps = parse_pyproject_toml(text);
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
        assert!(parse_pyproject_toml("[[[not toml").is_empty());
    }

    // --- Cargo.toml -------------------------------------------------------

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
        let deps = parse_cargo_toml(text);
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
        let deps = parse_cargo_toml(text);
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
        let deps = parse_cargo_toml(text);
        assert!(deps.iter().any(|d| d.name == "libc"));
    }

    // --- go.mod -----------------------------------------------------------

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

    // --- Gemfile ----------------------------------------------------------

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

    // --- is_plausible_package_name ----------------------------------------

    #[test]
    fn plausible_package_name_rejects_garbage() {
        assert!(is_plausible_package_name("react"));
        assert!(is_plausible_package_name("@scope/pkg"));
        assert!(is_plausible_package_name("github.com/x/y"));
        assert!(!is_plausible_package_name(""));
        assert!(!is_plausible_package_name("has spaces"));
        assert!(!is_plausible_package_name("{table}"));
    }

    // --- slopsquat: hallucinated name shape -------------------------------

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

    // --- slopsquat: full heuristic ----------------------------------------

    #[test]
    fn slopsquat_clear_for_known_popular() {
        let a = slopsquat("react", &NameVsPopular::KnownPopular, None, Ecosystem::Npm);
        assert!(!a.suspicious, "a known-popular package is never slopsquat");
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
            !a.suspicious,
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
        assert!(
            a.suspicious,
            "hallucinated shape + near-popular anchor must fire: {a:?}"
        );
        assert_eq!(a.near_popular.as_deref(), Some("requests"));
        assert!(!a.reasons.is_empty());
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
            !a.suspicious,
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
            !a.suspicious,
            "a near-miss with a normal name shape is similar_name, not slopsquat"
        );
    }

    // --- findings ----------------------------------------------------------

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
        assert!(
            findings_for(&a).is_empty(),
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
        let findings = findings_for(&a);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::ThreatPackageTyposquat);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn findings_for_slopsquat_is_medium_suspicious_package() {
        let slop = SlopsquatAssessment {
            suspicious: true,
            reasons: vec!["test reason".to_string()],
            near_popular: Some("requests".to_string()),
        };
        let a = assessment_with(
            "python-requests-helper",
            NameVsPopular::Unknown,
            None,
            slop,
            false,
        );
        let findings = findings_for(&a);
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
        let findings = findings_for(&a);
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
        assert!(findings_for(&a).is_empty());
    }

    // --- end-to-end scan over a temp project ------------------------------

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
}
