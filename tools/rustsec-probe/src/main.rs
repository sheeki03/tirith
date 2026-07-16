//! Research probe for spike 5a: parse the RustSec advisory-db TOML front matter
//! with the toml 0.8 line the tirith workspace already pins, on Rust 1.83.
//!
//! Standalone (see the empty `[workspace]` in Cargo.toml): this never enters the
//! product build. It walks an advisory-db checkout, extracts the leading
//! ```` ```toml ```` fenced block from every advisory `.md`, parses it into a
//! typed model, and prints a corpus summary: parsed / skipped / withdrawn /
//! informational counts, alias coverage, license split (CC0 vs CC-BY-4.0), and
//! the version-range comparator shapes used by `patched` / `unaffected`.
//!
//! Usage:  cargo +1.83 run --release -- <path-to-advisory-db>
//!
//! Exit code is 0 on a completed run (parse failures are reported as data, not a
//! probe error); it is non-zero only when the path cannot be walked at all.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Deserialize;

/// The subset of the advisory front matter this probe reads. No
/// `deny_unknown_fields`, so `[affected]`, `[affected.functions]`, `cvss`,
/// `keywords`, and any future keys are ignored rather than failing the parse.
#[derive(Debug, Deserialize)]
struct Advisory {
    advisory: AdvisoryMeta,
    #[serde(default)]
    versions: Versions,
}

#[derive(Debug, Deserialize)]
struct AdvisoryMeta {
    id: String,
    #[serde(default)]
    package: String,
    #[serde(default)]
    withdrawn: Option<String>,
    #[serde(default)]
    informational: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    license: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Versions {
    #[serde(default)]
    patched: Vec<String>,
    #[serde(default)]
    unaffected: Vec<String>,
}

#[derive(Default)]
struct Stats {
    md_files: usize,
    fenced: usize,
    parsed_ok: usize,
    parse_errors: Vec<(String, String)>,
    packages: BTreeSet<String>,
    withdrawn: usize,
    informational: usize,
    with_aliases: usize,
    alias_cve: usize,
    alias_ghsa: usize,
    alias_other: usize,
    id_rustsec: usize,
    id_cve: usize,
    id_other: usize,
    license_cc_by: usize,
    license_cc0_explicit: usize,
    license_unset: usize,
    with_patched: usize,
    with_unaffected: usize,
    version_no_ranges: usize,
    /// Distinct comparator operators seen across all patched/unaffected tokens.
    operators: BTreeMap<String, usize>,
    /// Range tokens whose leading operator is not one this probe recognizes as a
    /// standard semver comparator. Documents Q6 "unsupported version expressions".
    unrecognized_range_tokens: Vec<String>,
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(root) = args.next() else {
        eprintln!("usage: rustsec-probe <path-to-advisory-db>");
        return ExitCode::from(2);
    };
    let root = PathBuf::from(root);
    if !root.is_dir() {
        eprintln!("error: {} is not a directory", root.display());
        return ExitCode::from(2);
    }

    let mut files = Vec::new();
    if let Err(e) = collect_md_files(&root, &mut files) {
        eprintln!("error walking {}: {e}", root.display());
        return ExitCode::from(1);
    }
    files.sort();

    let mut stats = Stats::default();
    for path in &files {
        stats.md_files += 1;
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                stats
                    .parse_errors
                    .push((rel(&root, path), format!("read: {e}")));
                continue;
            }
        };
        let Some(front) = extract_front_matter(&text) else {
            // Not an advisory (README, EXAMPLE_ADVISORY, CONTRIBUTING, ...): no
            // leading toml fence. Skipped, not an error.
            continue;
        };
        stats.fenced += 1;
        match toml::from_str::<Advisory>(&front) {
            Ok(adv) => {
                stats.parsed_ok += 1;
                tally(&mut stats, &adv);
            }
            Err(e) => {
                let msg = e.to_string();
                let first = msg.lines().next().unwrap_or("").to_string();
                stats.parse_errors.push((rel(&root, path), first));
            }
        }
    }

    print_report(&root, &stats);
    ExitCode::SUCCESS
}

/// Recursively collect every `.md` file under `dir`, skipping any `.git` subtree.
fn collect_md_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            if path.file_name().map(|n| n == ".git").unwrap_or(false) {
                continue;
            }
            collect_md_files(&path, out)?;
        } else if file_type.is_file() && path.extension().map(|e| e == "md").unwrap_or(false) {
            out.push(path);
        }
    }
    Ok(())
}

/// Return the TOML inside the leading ```` ```toml ... ``` ```` fence, or `None`
/// if the first non-empty line is not that fence. RustSec advisories always open
/// with this block; other markdown files (README, template) do not.
fn extract_front_matter(text: &str) -> Option<String> {
    let mut lines = text.lines();
    // First non-empty line must be the toml fence.
    let opening = lines.by_ref().find(|l| !l.trim().is_empty())?;
    if opening.trim() != "```toml" {
        return None;
    }
    let mut body = String::new();
    for line in lines {
        if line.trim() == "```" {
            return Some(body);
        }
        body.push_str(line);
        body.push('\n');
    }
    // Unterminated fence: return what we have so toml reports the real error.
    Some(body)
}

fn tally(stats: &mut Stats, adv: &Advisory) {
    let meta = &adv.advisory;

    if !meta.package.is_empty() {
        stats.packages.insert(meta.package.clone());
    }

    if meta.withdrawn.is_some() {
        stats.withdrawn += 1;
    }
    if meta.informational.is_some() {
        stats.informational += 1;
    }

    if meta.id.starts_with("RUSTSEC-") {
        stats.id_rustsec += 1;
    } else if meta.id.starts_with("CVE-") {
        stats.id_cve += 1;
    } else {
        stats.id_other += 1;
    }

    if !meta.aliases.is_empty() {
        stats.with_aliases += 1;
    }
    for alias in &meta.aliases {
        if alias.starts_with("CVE-") {
            stats.alias_cve += 1;
        } else if alias.starts_with("GHSA-") {
            stats.alias_ghsa += 1;
        } else {
            stats.alias_other += 1;
        }
    }

    match meta.license.as_deref() {
        Some("CC-BY-4.0") => stats.license_cc_by += 1,
        Some("CC0-1.0") => stats.license_cc0_explicit += 1,
        Some(_) => stats.license_cc0_explicit += 1,
        None => stats.license_unset += 1,
    }

    let has_patched = !adv.versions.patched.is_empty();
    let has_unaffected = !adv.versions.unaffected.is_empty();
    if has_patched {
        stats.with_patched += 1;
    }
    if has_unaffected {
        stats.with_unaffected += 1;
    }
    if !has_patched && !has_unaffected {
        stats.version_no_ranges += 1;
    }

    for token_set in adv
        .versions
        .patched
        .iter()
        .chain(adv.versions.unaffected.iter())
    {
        for token in token_set.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            let op = leading_operator(token);
            *stats.operators.entry(op.to_string()).or_default() += 1;
            if op == "?" {
                stats.unrecognized_range_tokens.push(token.to_string());
            }
        }
    }
}

/// Classify the leading comparator of a single version-range token. Returns the
/// operator string, or "?" for anything a standard semver `VersionReq` comparator
/// set would not recognize.
fn leading_operator(token: &str) -> &'static str {
    if let Some(rest) = token.strip_prefix(">=") {
        return if starts_versionish(rest) { ">=" } else { "?" };
    }
    if let Some(rest) = token.strip_prefix("<=") {
        return if starts_versionish(rest) { "<=" } else { "?" };
    }
    if let Some(rest) = token.strip_prefix('>') {
        return if starts_versionish(rest) { ">" } else { "?" };
    }
    if let Some(rest) = token.strip_prefix('<') {
        return if starts_versionish(rest) { "<" } else { "?" };
    }
    if let Some(rest) = token.strip_prefix('^') {
        return if starts_versionish(rest) { "^" } else { "?" };
    }
    if let Some(rest) = token.strip_prefix('~') {
        return if starts_versionish(rest) { "~" } else { "?" };
    }
    if let Some(rest) = token.strip_prefix('=') {
        return if starts_versionish(rest) { "=" } else { "?" };
    }
    // A bare version with no operator ("1.2.3") is caret-equivalent (^1.2.3) in
    // Cargo / semver VersionReq grammar, NOT an exact match. Recorded as "bare"
    // to preserve the raw token shape; a matcher must treat it as a caret range.
    if starts_versionish(token) {
        return "bare";
    }
    "?"
}

fn starts_versionish(s: &str) -> bool {
    s.trim_start()
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
}

fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn print_report(root: &Path, s: &Stats) {
    println!("RustSec advisory-db parse probe (toml =0.8.23, edition 2021)");
    println!("corpus root: {}", root.display());
    println!();
    println!("markdown files walked      : {}", s.md_files);
    println!("advisories (toml fence)    : {}", s.fenced);
    println!("parsed OK                  : {}", s.parsed_ok);
    println!("parse errors               : {}", s.parse_errors.len());
    println!("distinct affected packages : {}", s.packages.len());
    println!();
    println!("id = RUSTSEC-*             : {}", s.id_rustsec);
    println!("id = CVE-*                 : {}", s.id_cve);
    println!("id = other                 : {}", s.id_other);
    println!();
    println!("withdrawn (has `withdrawn`): {}", s.withdrawn);
    println!("informational              : {}", s.informational);
    println!();
    println!("with any alias             : {}", s.with_aliases);
    println!("  alias CVE-*              : {}", s.alias_cve);
    println!("  alias GHSA-*             : {}", s.alias_ghsa);
    println!("  alias other              : {}", s.alias_other);
    println!();
    println!("license CC-BY-4.0 (GHSA)   : {}", s.license_cc_by);
    println!("license CC0/other explicit : {}", s.license_cc0_explicit);
    println!("license unset (CC0 default): {}", s.license_unset);
    println!();
    println!("with patched ranges        : {}", s.with_patched);
    println!("with unaffected ranges     : {}", s.with_unaffected);
    println!(
        "with neither (informational-style): {}",
        s.version_no_ranges
    );
    println!();
    println!("version-range operators seen:");
    for (op, n) in &s.operators {
        println!("  {:<5} : {}", op, n);
    }
    println!(
        "unrecognized range tokens  : {}",
        s.unrecognized_range_tokens.len()
    );
    for token in s.unrecognized_range_tokens.iter().take(10) {
        println!("  ! {token}");
    }
    if !s.parse_errors.is_empty() {
        println!();
        println!("first parse errors (up to 20):");
        for (path, err) in s.parse_errors.iter().take(20) {
            println!("  {path}: {err}");
        }
    }
}
