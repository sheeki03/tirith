//! `tirith package risk` and `tirith package explain` — provenance /
//! maintainer-risk scoring for a package.
//!
//! These commands score a package the way `tirith score` scores a URL: a
//! deterministic, fully explainable sum of named factors.
//!
//! **Offline by default.** Name signals come from the local threat DB, and
//! content signals only from a package directory the user already has on
//! disk — no network. `--online` additionally consults the package's
//! registry API (npm / PyPI / crates.io) for provenance signals; that is the
//! ONLY path on which these commands reach the network — never the `check`
//! hot path. `--offline` / `TIRITH_OFFLINE` forces offline even with
//! `--online`, and a registry failure degrades gracefully to the offline
//! score with an honest `api signals: unavailable (reason)`.

use std::path::{Path, PathBuf};

use tirith_core::package_risk::{
    self, ApiProvenance, ApiSignals, ContentSignals, NameVsPopular, PackageSignals, RiskBreakdown,
};
use tirith_core::registry_api::{self, HttpRegistryClient, RegistryClient};
use tirith_core::threatdb::{Ecosystem, ThreatDb};

/// Run `tirith package risk <ecosystem> <name>`.
///
/// Prints the deterministic risk score (human or JSON). `path` optionally
/// points at locally-available package content to inspect for install-script
/// and binary-blob signals; when omitted, tirith tries to auto-discover the
/// package under `node_modules` / `site-packages` relative to the cwd.
///
/// `online` opts into the registry-API provenance signals; `offline` (or the
/// `TIRITH_OFFLINE` env var) forces offline scoring even when `online` is set.
pub fn risk(
    ecosystem: &str,
    name: &str,
    path: Option<&str>,
    online: bool,
    offline: bool,
    json: bool,
) -> i32 {
    run(
        ecosystem, name, path, online, offline, json, /* explain = */ false,
    )
}

/// Run `tirith package explain <ecosystem> <name>` — the factor-by-factor
/// derivation of the same score (mirrors `tirith score --explain`).
pub fn explain(
    ecosystem: &str,
    name: &str,
    path: Option<&str>,
    online: bool,
    offline: bool,
    json: bool,
) -> i32 {
    run(
        ecosystem, name, path, online, offline, json, /* explain = */ true,
    )
}

/// `true` when `TIRITH_OFFLINE` is set to a truthy value. Mirrors
/// `threatdb_cmd::offline_env_active` so the offline switch is consistent
/// across the CLI.
fn offline_env_active() -> bool {
    std::env::var("TIRITH_OFFLINE")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

#[allow(clippy::too_many_arguments)]
fn run(
    ecosystem: &str,
    name: &str,
    path: Option<&str>,
    online: bool,
    offline: bool,
    json: bool,
    explain: bool,
) -> i32 {
    let Some(eco) = Ecosystem::from_name(ecosystem) else {
        eprintln!(
            "tirith package: unknown ecosystem '{ecosystem}'. \
             Known: npm, pypi, rubygems, crates.io, go, maven, nuget, packagist."
        );
        return 2;
    };

    let trimmed_name = name.trim();
    if trimmed_name.is_empty() {
        eprintln!("tirith package: package name must not be empty.");
        return 2;
    }

    let db = ThreatDb::cached();
    let threat_db_missing = db.is_none();

    // Name signals — from the local threat DB only.
    let name_vs_popular = package_risk::classify_name(db.as_deref(), eco, trimmed_name);
    let malicious_typosquat_of = db
        .as_deref()
        .and_then(|db| db.check_typosquat(eco, trimmed_name))
        .map(|ts| ts.target_name);

    // Content signals — only from locally-available package content. tirith
    // never downloads the package to obtain these.
    let content_signals = gather_content_signals(eco, trimmed_name, path);

    // Registry-API signals — ONLY when `--online` was passed and offline mode
    // is not in force. The production client is the networked
    // `HttpRegistryClient`; `gather_api` itself is offline-safe and degrades
    // any failure to `ApiSignals::Unavailable`.
    let api = if online {
        let client = HttpRegistryClient::new();
        gather_api(&client, eco, trimmed_name, offline)
    } else {
        // No `--online`: the default offline state.
        ApiSignals::offline()
    };

    let signals = PackageSignals {
        ecosystem: eco,
        name: trimmed_name.to_string(),
        threat_db_missing,
        name_vs_popular,
        malicious_typosquat_of,
        content_signals,
        api,
    };

    let breakdown = package_risk::score_package(&signals);
    // Defence in depth: the breakdown's public contract is that the factors
    // sum to the score. Assert it in debug so a future factor that breaks the
    // invariant is caught immediately (same guard as `tirith score`).
    debug_assert!(
        breakdown.verify(),
        "package-risk breakdown factors must sum to the final score"
    );

    if json {
        print_json(&breakdown, explain);
    } else {
        print_human(&breakdown, explain);
    }
    0
}

// --- registry-API signals (opt-in, networked) ------------------------------

/// Gather registry-API provenance signals using `client`.
///
/// `offline_flag` carries the `--offline` flag; when it — or the
/// `TIRITH_OFFLINE` env var — is set, this is a guaranteed no-op that returns
/// [`ApiSignals::Unavailable`] WITHOUT making any network call, so an
/// `--online --offline` invocation (or `--online` under `TIRITH_OFFLINE=1`)
/// stays purely local. Otherwise it delegates to
/// [`registry_api::gather_api_signals`], which itself degrades any registry
/// failure gracefully — this function never panics, never hangs beyond the
/// client's timeout, and never blocks the caller.
///
/// `client` is a trait object so tests inject a fixture-fed fake and never
/// touch the real registries.
fn gather_api(
    client: &dyn RegistryClient,
    eco: Ecosystem,
    name: &str,
    offline_flag: bool,
) -> ApiSignals {
    if offline_flag || offline_env_active() {
        return ApiSignals::unavailable(
            "offline mode is active (--offline / TIRITH_OFFLINE) — \
             registry-API signals were skipped, scored with offline signals only",
        );
    }
    registry_api::gather_api_signals(client, eco, name)
}

// --- content inspection (offline, filesystem-only) -------------------------

/// The directory names a package's content lives under, per ecosystem, for
/// auto-discovery relative to the cwd.
fn ecosystem_content_root(eco: Ecosystem) -> Option<&'static str> {
    match eco {
        Ecosystem::Npm => Some("node_modules"),
        // pip installs unpack into a `site-packages` directory.
        Ecosystem::PyPI => Some("site-packages"),
        // Other ecosystems have no single conventional local layout that is
        // safe to auto-discover; an explicit --path still works for them.
        _ => None,
    }
}

/// Gather install-script / binary-blob signals from locally-available content.
///
/// Resolution order:
///  1. an explicit `--path` (used as-is — error if it does not exist);
///  2. otherwise, auto-discovery of `<content-root>/<name>` under the cwd;
///  3. otherwise, [`ContentSignals::NotInspected`].
///
/// This only ever reads a directory the user already has — it never fetches.
fn gather_content_signals(
    eco: Ecosystem,
    name: &str,
    explicit_path: Option<&str>,
) -> ContentSignals {
    let dir: Option<PathBuf> = match explicit_path {
        Some(p) => {
            let pb = PathBuf::from(p);
            if !pb.exists() {
                eprintln!(
                    "tirith package: --path '{p}' does not exist; \
                     scoring with name signals only."
                );
                None
            } else {
                Some(pb)
            }
        }
        None => discover_local_package(eco, name),
    };

    let Some(dir) = dir else {
        return ContentSignals::NotInspected;
    };

    let (has_install_script, install_script_detail) = detect_install_script(eco, &dir);
    let (has_binary_blob, binary_blob_detail) = detect_binary_blob(&dir);

    ContentSignals::Inspected {
        path: dir.display().to_string(),
        has_install_script,
        install_script_detail,
        has_binary_blob,
        binary_blob_detail,
    }
}

/// Auto-discover a package directory under the cwd's conventional content root.
fn discover_local_package(eco: Ecosystem, name: &str) -> Option<PathBuf> {
    let root = ecosystem_content_root(eco)?;
    let cwd = std::env::current_dir().ok()?;
    let candidate = cwd.join(root).join(name);
    if candidate.is_dir() {
        Some(candidate)
    } else {
        None
    }
}

/// Detect an install / lifecycle hook in a locally-available package directory.
///
/// - npm: a `package.json` with a non-empty `install`, `preinstall`, or
///   `postinstall` script entry.
/// - PyPI: a `setup.py` (executes arbitrary Python at install time).
/// - Other ecosystems: not inspected for install scripts in this phase.
fn detect_install_script(eco: Ecosystem, dir: &Path) -> (bool, Option<String>) {
    match eco {
        Ecosystem::Npm => detect_npm_install_script(dir),
        Ecosystem::PyPI => {
            if dir.join("setup.py").is_file() {
                (
                    true,
                    Some("a setup.py (runs arbitrary Python at install time)".to_string()),
                )
            } else {
                (false, None)
            }
        }
        _ => (false, None),
    }
}

/// Read `package.json` and report whether any install lifecycle hook is set.
fn detect_npm_install_script(dir: &Path) -> (bool, Option<String>) {
    let manifest = dir.join("package.json");
    let Ok(text) = std::fs::read_to_string(&manifest) else {
        return (false, None);
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        return (false, None);
    };
    let Some(scripts) = json.get("scripts").and_then(|s| s.as_object()) else {
        return (false, None);
    };
    let mut hooks: Vec<&str> = Vec::new();
    for hook in ["preinstall", "install", "postinstall"] {
        if scripts
            .get(hook)
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
        {
            hooks.push(hook);
        }
    }
    if hooks.is_empty() {
        (false, None)
    } else {
        (
            true,
            Some(format!(
                "an npm {} lifecycle script in package.json",
                hooks.join(" / ")
            )),
        )
    }
}

/// Native / compiled artifact file extensions, lowercased, leading dot
/// included. A file with one of these extensions inside the package directory
/// is opaque compiled code that cannot be reviewed as source.
const BINARY_BLOB_EXTENSIONS: &[&str] = &[
    ".so", ".dll", ".dylib", ".node", ".wasm", ".a", ".lib", ".o", ".obj", ".exe", ".bin", ".dex",
    ".class", ".jar", ".pyd",
];

/// Detect bundled binary blobs by walking the package directory and matching
/// known native/compiled file extensions. Bounded: at most a few thousand
/// entries are examined, and the walk reads only file names (no file content).
fn detect_binary_blob(dir: &Path) -> (bool, Option<String>) {
    // Cap the walk so a pathological tree cannot stall the command.
    const MAX_ENTRIES: usize = 20_000;
    let mut examined = 0usize;
    let mut found: Vec<String> = Vec::new();

    for entry in walkdir::WalkDir::new(dir)
        .max_depth(8)
        .into_iter()
        .filter_map(Result::ok)
    {
        examined += 1;
        if examined > MAX_ENTRIES {
            break;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let fname = entry.file_name().to_string_lossy().to_lowercase();
        if let Some(ext) = BINARY_BLOB_EXTENSIONS
            .iter()
            .find(|ext| fname.ends_with(*ext))
        {
            if !found.iter().any(|f| f == ext) {
                found.push((*ext).to_string());
            }
            // Three distinct kinds is plenty for the human summary.
            if found.len() >= 3 {
                break;
            }
        }
    }

    if found.is_empty() {
        (false, None)
    } else {
        (
            true,
            Some(format!("bundled compiled artifacts ({})", found.join(", "))),
        )
    }
}

// --- output ----------------------------------------------------------------

fn print_json(breakdown: &RiskBreakdown, explain: bool) {
    #[derive(serde::Serialize)]
    struct PackageRiskOutput<'a> {
        ecosystem: &'a str,
        name: &'a str,
        score: u32,
        risk_level: &'a str,
        threat_db_missing: bool,
        name_vs_popular: &'a NameVsPopular,
        #[serde(skip_serializing_if = "Option::is_none")]
        malicious_typosquat_of: Option<&'a str>,
        content_signals: &'a ContentSignals,
        api_signals: &'a ApiSignals,
        /// Full factor breakdown — present only with `explain`.
        #[serde(skip_serializing_if = "Option::is_none")]
        risk_breakdown: Option<&'a RiskBreakdown>,
    }

    let out = PackageRiskOutput {
        ecosystem: &breakdown.ecosystem,
        name: &breakdown.name,
        score: breakdown.score,
        risk_level: breakdown.risk_level,
        threat_db_missing: breakdown.threat_db_missing,
        name_vs_popular: &breakdown.name_vs_popular,
        malicious_typosquat_of: breakdown.malicious_typosquat_of.as_deref(),
        content_signals: &breakdown.content_signals,
        api_signals: &breakdown.api_signals,
        risk_breakdown: if explain { Some(breakdown) } else { None },
    };
    if serde_json::to_writer_pretty(std::io::stdout().lock(), &out).is_err() {
        eprintln!("tirith: failed to write JSON output");
    }
    println!();
}

fn print_human(breakdown: &RiskBreakdown, explain: bool) {
    println!(
        "tirith package risk: {} package '{}'",
        breakdown.ecosystem, breakdown.name
    );
    println!(
        "  risk score:  {}/100 ({})",
        breakdown.score, breakdown.risk_level
    );

    // Name signal — always present.
    match &breakdown.name_vs_popular {
        NameVsPopular::KnownPopular => {
            println!("  name:        known-popular package (recognized)");
        }
        NameVsPopular::NearPopular {
            popular_name,
            distance,
        } => {
            println!(
                "  name:        edit-distance {distance} from popular package '{popular_name}' \
                 — possible typosquat/slopsquat"
            );
        }
        NameVsPopular::Unknown => {
            if breakdown.threat_db_missing {
                println!(
                    "  name:        unknown — threat DB not installed, \
                     popular-package comparison skipped"
                );
            } else {
                println!("  name:        not a known-popular package, and no near-miss");
            }
        }
    }

    if let Some(target) = &breakdown.malicious_typosquat_of {
        println!("  threat DB:   listed as a known malicious typosquat of '{target}'");
    }

    // Content signal — what (if anything) was inspected.
    match &breakdown.content_signals {
        ContentSignals::NotInspected => {
            println!(
                "  content:     not inspected (no local package directory — \
                 pass --path to inspect install scripts and binary blobs)"
            );
        }
        ContentSignals::Inspected {
            path,
            has_install_script,
            install_script_detail,
            has_binary_blob,
            binary_blob_detail,
        } => {
            println!("  content:     inspected {path}");
            match (has_install_script, install_script_detail) {
                (true, Some(d)) => println!("               - install script: {d}"),
                (true, None) => println!("               - install script: present"),
                (false, _) => println!("               - install script: none"),
            }
            match (has_binary_blob, binary_blob_detail) {
                (true, Some(d)) => println!("               - binary blob: {d}"),
                (true, None) => println!("               - binary blob: present"),
                (false, _) => println!("               - binary blob: none"),
            }
        }
    }

    // API-signal seam — always reported so the offline/online scope is
    // explicit and a degraded online run is honest about why.
    match &breakdown.api_signals {
        ApiSignals::NotComputed { reason } => {
            println!("  api signals: not computed — {reason}");
        }
        ApiSignals::Unavailable { reason } => {
            println!("  api signals: unavailable — {reason}");
        }
        ApiSignals::Available { provenance } => {
            print_api_provenance_human(provenance);
        }
    }

    if explain {
        print_breakdown_human(breakdown);
    } else {
        println!(
            "  Run 'tirith package explain {} {}' for the factor-by-factor derivation.",
            breakdown.ecosystem, breakdown.name
        );
    }
}

/// Render the gathered registry-API provenance for the human summary. Only the
/// signals the registry actually reported are printed; an unknown datum is
/// shown as `unknown` so the reader can see what the registry did not expose.
fn print_api_provenance_human(p: &ApiProvenance) {
    println!("  api signals: from the {} registry API", p.source);
    match p.package_age_days {
        Some(d) => println!("               - package age: {d} day(s) since first publish"),
        None => println!("               - package age: unknown (not reported)"),
    }
    match (&p.latest_version, p.latest_version_age_days) {
        (Some(v), Some(d)) => {
            println!("               - latest version: {v} ({d} day(s) old)")
        }
        (Some(v), None) => println!("               - latest version: {v}"),
        (None, _) => println!("               - latest version: unknown"),
    }
    match p.ownership_transferred {
        Some(true) => println!("               - ownership: transferred recently"),
        Some(false) => println!("               - ownership: stable"),
        None => println!("               - ownership: unknown (no history)"),
    }
    match p.version_spike {
        Some(true) => println!("               - version jump: abnormal (major-version spike)"),
        Some(false) => println!("               - version jump: normal"),
        None => println!("               - version jump: unknown (one version only)"),
    }
    match p.recent_downloads {
        Some(dl) => println!("               - downloads: {dl} (recent window)"),
        None => println!("               - downloads: unknown (not reported)"),
    }
    match p.has_source_repo {
        Some(true) => println!("               - source repo: listed"),
        Some(false) => println!("               - source repo: missing or unusable"),
        None => println!("               - source repo: unknown (field not in API)"),
    }
    if p.yanked_or_deprecated {
        println!("               - status: latest version yanked / deprecated");
    } else {
        println!("               - status: latest version current");
    }
}

/// Render the factor breakdown so the reader can reproduce the score by hand —
/// identical in spirit to `tirith score --explain`. The actual formatting
/// lives in [`write_breakdown_human`] so it can be unit-tested against a
/// buffer.
fn print_breakdown_human(breakdown: &RiskBreakdown) {
    let _ = write_breakdown_human(breakdown, &mut std::io::stdout().lock());
}

/// Write the factor breakdown to `w`. Separated from [`print_breakdown_human`]
/// purely so tests can capture the rendered text; the output is identical.
fn write_breakdown_human(
    breakdown: &RiskBreakdown,
    w: &mut impl std::io::Write,
) -> std::io::Result<()> {
    writeln!(w)?;
    writeln!(
        w,
        "  risk breakdown (each factor is fixed and inspectable — no model):"
    )?;
    let mut running: i32 = 0;
    for factor in &breakdown.factors {
        running += factor.points;
        // `+NN` for positive contributions, `-NN` for the clamp factor.
        let sign = if factor.points >= 0 { "+" } else { "" };
        writeln!(
            w,
            "    {sign}{:<4} {}  (running total: {running})",
            factor.points, factor.label
        )?;
        writeln!(w, "           {}", factor.detail)?;
    }
    writeln!(
        w,
        "    = {} / {}  ({}) — sum of every factor above",
        breakdown.score,
        package_risk::MAX_SCORE,
        breakdown.risk_level
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn render(breakdown: &RiskBreakdown) -> String {
        let mut buf: Vec<u8> = Vec::new();
        write_breakdown_human(breakdown, &mut buf).expect("write to Vec never fails");
        String::from_utf8(buf).expect("breakdown output is valid UTF-8")
    }

    #[test]
    fn unknown_ecosystem_is_rejected_with_exit_2() {
        assert_eq!(
            risk("not-a-real-ecosystem", "react", None, false, false, false),
            2
        );
    }

    #[test]
    fn empty_name_is_rejected_with_exit_2() {
        assert_eq!(risk("npm", "   ", None, false, false, false), 2);
    }

    #[test]
    fn detect_npm_install_script_finds_postinstall() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"p","scripts":{"postinstall":"node evil.js"}}"#,
        )
        .unwrap();
        let (found, detail) = detect_npm_install_script(dir.path());
        assert!(found);
        assert!(detail.unwrap().contains("postinstall"));
    }

    #[test]
    fn detect_npm_install_script_ignores_non_lifecycle_scripts() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"p","scripts":{"test":"jest","build":"tsc"}}"#,
        )
        .unwrap();
        let (found, _) = detect_npm_install_script(dir.path());
        assert!(!found, "test/build scripts are not install hooks");
    }

    #[test]
    fn detect_npm_install_script_ignores_empty_hook() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"p","scripts":{"postinstall":"   "}}"#,
        )
        .unwrap();
        let (found, _) = detect_npm_install_script(dir.path());
        assert!(!found, "an empty postinstall string is not a real hook");
    }

    #[test]
    fn detect_npm_install_script_handles_missing_or_bad_manifest() {
        let dir = tempdir().unwrap();
        // No package.json at all.
        assert!(!detect_npm_install_script(dir.path()).0);
        // Malformed package.json.
        fs::write(dir.path().join("package.json"), "{not json").unwrap();
        assert!(!detect_npm_install_script(dir.path()).0);
    }

    #[test]
    fn detect_install_script_pypi_setup_py() {
        let dir = tempdir().unwrap();
        let (no, _) = detect_install_script(Ecosystem::PyPI, dir.path());
        assert!(!no);
        fs::write(dir.path().join("setup.py"), "from setuptools import setup").unwrap();
        let (yes, detail) = detect_install_script(Ecosystem::PyPI, dir.path());
        assert!(yes);
        assert!(detail.unwrap().contains("setup.py"));
    }

    #[test]
    fn detect_binary_blob_finds_native_extensions() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("index.js"), "// pure source").unwrap();
        // No binary yet.
        assert!(!detect_binary_blob(dir.path()).0);
        // Add a native addon.
        fs::write(dir.path().join("addon.node"), [0u8, 1, 2, 3]).unwrap();
        let (found, detail) = detect_binary_blob(dir.path());
        assert!(found);
        assert!(detail.unwrap().contains(".node"));
    }

    #[test]
    fn detect_binary_blob_clean_directory() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("index.js"), "// pure source").unwrap();
        fs::write(dir.path().join("README.md"), "# docs").unwrap();
        let sub = dir.path().join("lib");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("util.js"), "// more source").unwrap();
        assert!(!detect_binary_blob(dir.path()).0);
    }

    #[test]
    fn gather_content_signals_missing_explicit_path_is_not_inspected() {
        let signals = gather_content_signals(
            Ecosystem::Npm,
            "whatever",
            Some("/definitely/not/a/real/path/xyzzy"),
        );
        assert!(matches!(signals, ContentSignals::NotInspected));
    }

    #[test]
    fn gather_content_signals_inspects_explicit_path() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"p","scripts":{"install":"node build.js"}}"#,
        )
        .unwrap();
        fs::write(dir.path().join("native.so"), [0u8; 4]).unwrap();
        let signals =
            gather_content_signals(Ecosystem::Npm, "p", Some(dir.path().to_str().unwrap()));
        match signals {
            ContentSignals::Inspected {
                has_install_script,
                has_binary_blob,
                ..
            } => {
                assert!(has_install_script);
                assert!(has_binary_blob);
            }
            ContentSignals::NotInspected => panic!("explicit path should be inspected"),
        }
    }

    #[test]
    fn breakdown_human_renders_known_popular_zero() {
        let signals = PackageSignals {
            ecosystem: Ecosystem::Npm,
            name: "react".to_string(),
            threat_db_missing: false,
            name_vs_popular: NameVsPopular::KnownPopular,
            malicious_typosquat_of: None,
            content_signals: ContentSignals::NotInspected,
            api: ApiSignals::offline(),
        };
        let breakdown = package_risk::score_package(&signals);
        let out = render(&breakdown);
        assert!(out.contains("risk breakdown"), "must print header: {out}");
        assert!(out.contains("+0"), "known-popular contributes +0: {out}");
        assert!(out.contains("= 0 / 100"), "total must read 0/100: {out}");
        assert!(out.contains("(low)"), "0 is the low bucket: {out}");
    }

    #[test]
    fn breakdown_human_renders_negative_clamp_factor() {
        let signals = PackageSignals {
            ecosystem: Ecosystem::Npm,
            name: "raect".to_string(),
            threat_db_missing: false,
            name_vs_popular: NameVsPopular::NearPopular {
                popular_name: "react".to_string(),
                distance: 1,
            },
            malicious_typosquat_of: Some("react".to_string()),
            content_signals: ContentSignals::Inspected {
                path: "/tmp/p".to_string(),
                has_install_script: true,
                install_script_detail: None,
                has_binary_blob: true,
                binary_blob_detail: None,
            },
            api: ApiSignals::offline(),
        };
        let breakdown = package_risk::score_package(&signals);
        assert_eq!(breakdown.score, 100);
        let out = render(&breakdown);
        // The clamp factor renders as a bare `-15` (no leading '+').
        assert!(out.contains("    -15 "), "clamp must render bare: {out}");
        assert!(!out.contains("+-15"), "clamp must not get a '+': {out}");
        assert!(
            out.contains("= 100 / 100"),
            "total must read 100/100: {out}"
        );
        assert!(
            out.contains("(critical)"),
            "100 is the critical bucket: {out}"
        );
    }

    // --- registry-API path (no real network: fixture-fed fake client) ------

    use tirith_core::registry_api::{FetchError, RegistryMetadata};

    /// A fixture-fed [`RegistryClient`]. The `panic!` on `fetch` for the
    /// offline-short-circuit tests proves no network call was attempted.
    struct FakeClient {
        result: Result<RegistryMetadata, FetchError>,
    }
    impl RegistryClient for FakeClient {
        fn fetch(&self, _eco: Ecosystem, _name: &str) -> Result<RegistryMetadata, FetchError> {
            self.result.clone()
        }
    }

    /// A client whose `fetch` panics — used to prove the offline switch
    /// short-circuits *before* any registry call is made.
    struct ExplodingClient;
    impl RegistryClient for ExplodingClient {
        fn fetch(&self, _eco: Ecosystem, _name: &str) -> Result<RegistryMetadata, FetchError> {
            panic!("fetch must not be called when offline mode is active");
        }
    }

    #[test]
    fn gather_api_offline_flag_skips_network() {
        // The exploding client would panic if reached — the `--offline` flag
        // must short-circuit to Unavailable without calling `fetch`.
        let sig = gather_api(&ExplodingClient, Ecosystem::Npm, "react", true);
        match sig {
            ApiSignals::Unavailable { reason } => {
                assert!(reason.contains("offline"), "reason: {reason}");
            }
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn gather_api_success_returns_available() {
        let meta = RegistryMetadata {
            source: "npm".to_string(),
            latest_version: Some("1.0.0".to_string()),
            ..Default::default()
        };
        let client = FakeClient { result: Ok(meta) };
        let sig = gather_api(&client, Ecosystem::Npm, "react", false);
        assert!(matches!(sig, ApiSignals::Available { .. }));
    }

    #[test]
    fn gather_api_failure_degrades_to_unavailable() {
        let client = FakeClient {
            result: Err(FetchError::Network("connection refused".to_string())),
        };
        let sig = gather_api(&client, Ecosystem::Npm, "react", false);
        assert!(matches!(sig, ApiSignals::Unavailable { .. }));
    }

    #[test]
    fn online_run_offline_flag_still_exits_zero_without_network() {
        // `--online` together with `--offline` must score with offline
        // signals and exit 0 — and make no network call (the offline flag
        // short-circuits before any `HttpRegistryClient` request). This
        // exercises the public `run` end-to-end with no real network.
        let code = run(
            "npm", "react", None, /* online = */ true, /* offline = */ true,
            /* json = */ true, /* explain = */ false,
        );
        assert_eq!(code, 0, "an --online --offline run must exit 0 offline");
    }

    #[test]
    fn available_provenance_drives_api_factors_and_human_output() {
        let provenance = ApiProvenance {
            source: "pypi".to_string(),
            package_age_days: Some(2),
            latest_version_age_days: Some(1),
            ownership_transferred: Some(true),
            version_spike: Some(true),
            recent_downloads: Some(5),
            has_source_repo: Some(false),
            yanked_or_deprecated: true,
            latest_version: Some("9.9.9".to_string()),
        };
        let s = PackageSignals {
            ecosystem: Ecosystem::PyPI,
            name: "p".to_string(),
            threat_db_missing: true,
            name_vs_popular: NameVsPopular::Unknown,
            malicious_typosquat_of: None,
            content_signals: ContentSignals::NotInspected,
            api: ApiSignals::Available { provenance },
        };
        let breakdown = package_risk::score_package(&s);
        // The breakdown carries the API factors; the score is non-zero.
        assert!(breakdown.score > 0);
        assert!(breakdown.factors.iter().any(|f| f.id.starts_with("api_")));
        assert!(matches!(
            breakdown.api_signals,
            ApiSignals::Available { .. }
        ));
        // The human renderer prints a line for every API signal.
        if let ApiSignals::Available { provenance } = &breakdown.api_signals {
            // `print_api_provenance_human` writes to stdout; just confirm it
            // does not panic on a fully-populated provenance.
            print_api_provenance_human(provenance);
        }
    }
}
