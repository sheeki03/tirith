//! Threat DB compiler — builds the binary threat intelligence database from
//! multiple open-source feeds.
//!
//! This binary is used by CI (`.github/workflows/threatdb.yml`) to compile
//! OSSF malicious-packages, Datadog dataset, Feodo Tracker, CISA KEV, and
//! ecosyste.ms typosquats into a signed `.dat` file.
//!
//! The binary format is defined in `tirith_core::threatdb` — this compiler
//! uses `ThreatDbWriter` from there to produce files that are compatible
//! with the reader.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};

use tirith_core::threatdb::{Confidence, Ecosystem, ThreatDbWriter, ThreatSource};
use tirith_core::threatdb_feeds::{
    parse_domain_blocklist, parse_phishtank_csv, parse_threatfox_zip, parse_tor_exit_list,
    parse_urlhaus_csv,
};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "tirith-threatdb-compile",
    about = "Compile threat intelligence feeds into a signed binary database"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// OSSF malicious-packages repo root
    #[arg(long)]
    ossf: Option<PathBuf>,

    /// Datadog malicious-software-packages-dataset repo root
    #[arg(long)]
    datadog: Option<PathBuf>,

    /// Feodo Tracker IP blocklist file
    #[arg(long)]
    feodo: Option<PathBuf>,

    /// CISA KEV JSON file
    #[arg(long)]
    cisa_kev: Option<PathBuf>,

    /// ecosyste.ms typosquats CSV file
    #[arg(long)]
    typosquats: Option<PathBuf>,

    /// popular_packages.csv (default: built-in asset)
    #[arg(long)]
    popular: Option<PathBuf>,

    /// URLhaus bulk CSV export (Phase B)
    #[arg(long)]
    urlhaus: Option<PathBuf>,

    /// ThreatFox full CSV zip export (Phase B)
    #[arg(long)]
    threatfox: Option<PathBuf>,

    /// Phishing Army blocklist text file (Phase B)
    #[arg(long)]
    phishing_army: Option<PathBuf>,

    /// PhishTank verified CSV (Phase B)
    #[arg(long)]
    phishtank: Option<PathBuf>,

    /// Tor bulk exit list (Phase B)
    #[arg(long)]
    tor_exit: Option<PathBuf>,

    /// Env var name containing Ed25519 private key (base64-encoded)
    #[arg(long)]
    sign_key_env: Option<String>,

    /// File containing Ed25519 private key (base64-encoded)
    #[arg(long)]
    sign_key_file: Option<PathBuf>,

    /// Build sequence number (monotonic). Used for rollback protection
    /// and must match the manifest `version` field. If not set, defaults
    /// to the current Unix timestamp.
    #[arg(long)]
    sequence: Option<u64>,

    /// Output .dat file path
    #[arg(long, default_value = "tirith-threatdb.dat")]
    output: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Sign a payload string and output base64 signature
    SignPayload {
        /// Payload string to sign
        #[arg(long)]
        payload: String,

        /// Env var name containing Ed25519 private key (base64-encoded)
        #[arg(long)]
        key_env: String,
    },
}

// ---------------------------------------------------------------------------
// Types — intermediate types used during parsing before feeding to ThreatDbWriter.
// Ecosystem, ThreatSource, and Confidence are imported from tirith_core::threatdb.
// ---------------------------------------------------------------------------

/// A malicious package entry.
#[derive(Debug, Clone)]
struct PackageEntry {
    ecosystem: Ecosystem,
    name: String,
    /// Exact versions known to be affected. Empty if `all_versions_malicious`.
    affected_versions: Vec<String>,
    /// True only when source explicitly confirms ALL versions are malicious.
    all_versions_malicious: bool,
    source: ThreatSource,
    confidence: Confidence,
    reference: Option<String>,
}

/// A confirmed typosquat entry.
#[derive(Debug, Clone)]
struct TyposquatEntry {
    ecosystem: Ecosystem,
    /// The malicious/typosquatting package name.
    name: String,
    /// The legitimate package it impersonates.
    target_name: String,
}

/// A popular package entry (for Levenshtein comparison).
#[derive(Debug, Clone)]
struct PopularEntry {
    ecosystem: Ecosystem,
    name: String,
}

/// CISA KEV entry (stored as-is in Phase A, no cross-ref).
/// Fields are read from JSON but only used for counting in Phase A.
/// Phase C will use these for runtime OSV.dev cross-reference.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct KevVulnerability {
    #[serde(default, alias = "cveID")]
    cve_id: String,
    #[serde(default)]
    vendor_project: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    vulnerability_name: String,
    #[serde(default)]
    date_added: String,
    #[serde(default)]
    short_description: String,
    #[serde(default)]
    required_action: String,
    #[serde(default)]
    due_date: String,
    #[serde(default)]
    known_ransomware_campaign_use: String,
}

#[derive(Debug, serde::Deserialize)]
struct KevCatalog {
    #[serde(default)]
    vulnerabilities: Vec<KevVulnerability>,
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/// Normalize package name per ecosystem conventions.
fn normalize_name(eco: Ecosystem, name: &str) -> String {
    match eco {
        Ecosystem::PyPI => {
            // PEP 503: lowercase, normalize - and _ to -
            name.to_lowercase().replace(['_', '.'], "-")
        }
        Ecosystem::Npm => {
            // npm is case-sensitive, keep as-is
            name.to_string()
        }
        _ => {
            // Default: lowercase
            name.to_lowercase()
        }
    }
}

// ---------------------------------------------------------------------------
// OSSF malicious-packages parser
// ---------------------------------------------------------------------------

/// OSV JSON schema (subset used for malicious-packages).
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)] // id used for diagnostics in future
struct OsvEntry {
    #[serde(default)]
    id: String,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    database_specific: Option<OsvDatabaseSpecific>,
    #[serde(default)]
    references: Vec<OsvReference>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvAffected {
    #[serde(default)]
    package: Option<OsvPackage>,
    #[serde(default)]
    versions: Vec<String>,
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvPackage {
    #[serde(default)]
    ecosystem: String,
    #[serde(default)]
    name: String,
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)] // range_type preserved for Phase A.1 range evaluators
struct OsvRange {
    #[serde(default, rename = "type")]
    range_type: String,
}

#[derive(Debug, serde::Deserialize)]
struct OsvDatabaseSpecific {
    #[serde(default, rename = "type")]
    entry_type: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvReference {
    #[serde(default)]
    url: String,
}

struct OssfStats {
    total_entries: usize,
    parsed_packages: usize,
    skipped_range_only_count: usize,
    skipped_unknown_ecosystem: usize,
    skipped_unreadable: usize,
    skipped_corrupt: usize,
}

fn parse_ossf(root: &Path) -> (Vec<PackageEntry>, OssfStats) {
    let mut entries = Vec::new();
    let mut stats = OssfStats {
        total_entries: 0,
        parsed_packages: 0,
        skipped_range_only_count: 0,
        skipped_unknown_ecosystem: 0,
        skipped_unreadable: 0,
        skipped_corrupt: 0,
    };

    // Walk the directory tree for JSON files
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension().is_some_and(|ext| ext == "json") && e.file_type().is_file()
        })
    {
        let path = entry.path();
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  warning: cannot read OSSF file {}: {e}", path.display());
                stats.skipped_unreadable += 1;
                continue;
            }
        };

        let osv: OsvEntry = match serde_json::from_str(&content) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("  warning: cannot parse OSSF file {}: {e}", path.display());
                stats.skipped_corrupt += 1;
                continue;
            }
        };

        stats.total_entries += 1;

        // Determine confidence from database_specific.type
        let confidence = match osv
            .database_specific
            .as_ref()
            .and_then(|d| d.entry_type.as_deref())
        {
            Some("MALWARE") => Confidence::Confirmed,
            Some("POTENTIALLY_UNWANTED") => Confidence::Medium,
            _ => Confidence::Medium, // Default: Medium (OSSF allows borderline)
        };

        let is_malware = matches!(
            osv.database_specific
                .as_ref()
                .and_then(|d| d.entry_type.as_deref()),
            Some("MALWARE")
        );

        // Extract first reference URL
        let reference = osv.references.first().map(|r| r.url.clone());

        for affected in &osv.affected {
            let pkg = match &affected.package {
                Some(p) => p,
                None => continue,
            };

            let ecosystem = match Ecosystem::from_name(&pkg.ecosystem) {
                Some(e) => e,
                None => {
                    stats.skipped_unknown_ecosystem += 1;
                    continue;
                }
            };

            let name = normalize_name(ecosystem, &pkg.name);

            let has_versions = !affected.versions.is_empty();
            let has_ranges = !affected.ranges.is_empty();

            if has_versions {
                // Exact version list available — use it
                entries.push(PackageEntry {
                    ecosystem,
                    name,
                    affected_versions: affected.versions.clone(),
                    all_versions_malicious: false,
                    source: ThreatSource::OssfMalicious,
                    confidence,
                    reference: reference.clone(),
                });
                stats.parsed_packages += 1;
            } else if has_ranges {
                // Has ranges but no explicit version list — skip in Phase A
                stats.skipped_range_only_count += 1;
            } else if is_malware {
                // MALWARE with no versions AND no ranges — entire package is malicious
                entries.push(PackageEntry {
                    ecosystem,
                    name,
                    affected_versions: Vec::new(),
                    all_versions_malicious: true,
                    source: ThreatSource::OssfMalicious,
                    confidence,
                    reference: reference.clone(),
                });
                stats.parsed_packages += 1;
            } else {
                // Not MALWARE, no versions, no ranges — skip
                stats.skipped_range_only_count += 1;
            }
        }
    }

    (entries, stats)
}

// ---------------------------------------------------------------------------
// Datadog malicious-packages-dataset parser
// ---------------------------------------------------------------------------

/// Datadog dataset entry format.
#[derive(Debug, serde::Deserialize)]
struct DatadogEntry {
    #[serde(default)]
    ecosystem: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    reference: Option<String>,
}

/// Datadog dataset can be a single JSON array or a directory of JSON files.
fn parse_datadog(root: &Path) -> (Vec<PackageEntry>, usize, usize) {
    let mut entries = Vec::new();
    let mut skipped = 0usize;
    let mut files_read = 0usize;

    // Try to find JSON files in the repo
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension().is_some_and(|ext| ext == "json") && e.file_type().is_file()
        })
    {
        let path = entry.path();
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "  warning: cannot read Datadog file {}: {e}",
                    path.display()
                );
                skipped += 1;
                continue;
            }
        };

        files_read += 1;

        // Try parsing as an array of entries
        if let Ok(arr) = serde_json::from_str::<Vec<DatadogEntry>>(&content) {
            for dd in arr {
                if let Some(eco) = Ecosystem::from_name(&dd.ecosystem) {
                    let name = normalize_name(eco, &dd.name);
                    let (affected_versions, all_versions) = match dd.version {
                        Some(ref v) if !v.is_empty() => (vec![v.clone()], false),
                        _ => (Vec::new(), true),
                    };
                    entries.push(PackageEntry {
                        ecosystem: eco,
                        name,
                        affected_versions,
                        all_versions_malicious: all_versions,
                        source: ThreatSource::DatadogMalicious,
                        confidence: Confidence::Confirmed,
                        reference: dd.reference,
                    });
                }
            }
            continue;
        }

        // Try parsing as a single entry
        if let Ok(dd) = serde_json::from_str::<DatadogEntry>(&content) {
            if let Some(eco) = Ecosystem::from_name(&dd.ecosystem) {
                let name = normalize_name(eco, &dd.name);
                let (affected_versions, all_versions) = match dd.version {
                    Some(ref v) if !v.is_empty() => (vec![v.clone()], false),
                    _ => (Vec::new(), true),
                };
                entries.push(PackageEntry {
                    ecosystem: eco,
                    name,
                    affected_versions,
                    all_versions_malicious: all_versions,
                    source: ThreatSource::DatadogMalicious,
                    confidence: Confidence::Confirmed,
                    reference: dd.reference,
                });
            }
            continue; // Don't fall through to OSV parse — avoids double-counting
        }

        // Also try parsing as OSV format (Datadog may use OSV-like structures)
        if let Ok(osv) = serde_json::from_str::<OsvEntry>(&content) {
            for affected in &osv.affected {
                if let Some(pkg) = &affected.package {
                    if let Some(eco) = Ecosystem::from_name(&pkg.ecosystem) {
                        // Only include entries with explicit version lists,
                        // matching the OSSF parser behavior (skip range-only).
                        if affected.versions.is_empty() {
                            continue;
                        }
                        let name = normalize_name(eco, &pkg.name);
                        entries.push(PackageEntry {
                            ecosystem: eco,
                            name,
                            affected_versions: affected.versions.clone(),
                            all_versions_malicious: false,
                            source: ThreatSource::DatadogMalicious,
                            confidence: Confidence::Confirmed,
                            reference: osv.references.first().map(|r| r.url.clone()),
                        });
                    }
                }
            }
        }
    }

    (entries, skipped, files_read)
}

// ---------------------------------------------------------------------------
// Feodo Tracker IP blocklist parser
// ---------------------------------------------------------------------------

fn parse_feodo(path: &Path) -> Vec<Ipv4Addr> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("warning: cannot open Feodo file {}: {e}", path.display());
            return Vec::new();
        }
    };

    let reader = BufReader::new(file);
    let mut ips = Vec::new();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Parse IPv4 address (may have trailing whitespace or other data)
        let ip_str = trimmed.split_whitespace().next().unwrap_or("");
        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
            ips.push(ip);
        }
    }

    ips.sort();
    ips.dedup();
    ips
}

// ---------------------------------------------------------------------------
// CISA KEV parser
// ---------------------------------------------------------------------------

fn parse_cisa_kev(path: &Path) -> Vec<KevVulnerability> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("warning: cannot read CISA KEV file {}: {e}", path.display());
            return Vec::new();
        }
    };

    let catalog: KevCatalog = match serde_json::from_str(&content) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("warning: cannot parse CISA KEV JSON: {e}");
            return Vec::new();
        }
    };

    catalog.vulnerabilities
}

// ---------------------------------------------------------------------------
// Phase B feed parsers
// ---------------------------------------------------------------------------

fn parse_urlhaus_file(path: &Path) -> Vec<String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("warning: cannot open URLhaus file {}: {e}", path.display());
            return Vec::new();
        }
    };

    match parse_urlhaus_csv(file) {
        Ok(entries) => entries.hostnames,
        Err(e) => {
            eprintln!("warning: cannot parse URLhaus CSV {}: {e}", path.display());
            Vec::new()
        }
    }
}

fn parse_threatfox_file(path: &Path) -> (Vec<String>, Vec<Ipv4Addr>) {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!(
                "warning: cannot open ThreatFox file {}: {e}",
                path.display()
            );
            return (Vec::new(), Vec::new());
        }
    };

    match parse_threatfox_zip(file) {
        Ok(entries) => (entries.hostnames, entries.ips),
        Err(e) => {
            eprintln!(
                "warning: cannot parse ThreatFox ZIP {}: {e}",
                path.display()
            );
            (Vec::new(), Vec::new())
        }
    }
}

fn parse_blocklist_file(path: &Path) -> Vec<String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => parse_domain_blocklist(&contents).hostnames,
        Err(e) => {
            eprintln!("warning: cannot read blocklist {}: {e}", path.display());
            Vec::new()
        }
    }
}

fn parse_phishtank_file(path: &Path) -> Vec<String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!(
                "warning: cannot open PhishTank file {}: {e}",
                path.display()
            );
            return Vec::new();
        }
    };

    match parse_phishtank_csv(file) {
        Ok(entries) => entries.hostnames,
        Err(e) => {
            eprintln!(
                "warning: cannot parse PhishTank CSV {}: {e}",
                path.display()
            );
            Vec::new()
        }
    }
}

fn parse_tor_exit_file(path: &Path) -> Vec<Ipv4Addr> {
    match std::fs::read_to_string(path) {
        Ok(contents) => parse_tor_exit_list(&contents).ips,
        Err(e) => {
            eprintln!("warning: cannot read Tor exit list {}: {e}", path.display());
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------
// ecosyste.ms typosquats CSV parser
// ---------------------------------------------------------------------------

fn parse_typosquats_csv(path: &Path) -> Vec<TyposquatEntry> {
    let mut entries = Vec::new();

    let mut reader = match csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_path(path)
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "warning: cannot open typosquats CSV {}: {e}",
                path.display()
            );
            return entries;
        }
    };

    for result in reader.records() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Expected columns: ecosystem, name, target_name
        if record.len() < 3 {
            continue;
        }

        let ecosystem_str = record.get(0).unwrap_or("").trim();
        let name = record.get(1).unwrap_or("").trim();
        let target = record.get(2).unwrap_or("").trim();

        if name.is_empty() || target.is_empty() {
            continue;
        }

        if let Some(eco) = Ecosystem::from_name(ecosystem_str) {
            entries.push(TyposquatEntry {
                ecosystem: eco,
                name: normalize_name(eco, name),
                target_name: normalize_name(eco, target),
            });
        }
    }

    entries
}

// ---------------------------------------------------------------------------
// Popular packages CSV parser
// ---------------------------------------------------------------------------

/// Default popular packages CSV embedded from assets.
const DEFAULT_POPULAR_CSV: &str =
    include_str!("../../../tirith-core/assets/data/popular_packages.csv");

fn parse_popular_csv(path: Option<&Path>) -> Vec<PopularEntry> {
    let content = match path {
        Some(p) => match std::fs::read_to_string(p) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "warning: cannot read popular packages file {}: {e}",
                    p.display()
                );
                return parse_popular_from_string(DEFAULT_POPULAR_CSV);
            }
        },
        None => DEFAULT_POPULAR_CSV.to_string(),
    };

    parse_popular_from_string(&content)
}

fn parse_popular_from_string(csv_content: &str) -> Vec<PopularEntry> {
    let mut entries = Vec::new();

    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(csv_content.as_bytes());

    for result in reader.records() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };

        if record.len() < 2 {
            continue;
        }

        let ecosystem_str = record.get(0).unwrap_or("").trim();
        let name = record.get(1).unwrap_or("").trim();

        if name.is_empty() {
            continue;
        }

        if let Some(eco) = Ecosystem::from_name(ecosystem_str) {
            entries.push(PopularEntry {
                ecosystem: eco,
                name: normalize_name(eco, name),
            });
        }
    }

    entries
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

/// Composite key for deduplication.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct PackageKey {
    ecosystem: Ecosystem,
    name: String,
}

/// Merge duplicate package entries: keep highest confidence + richest reference.
fn deduplicate_packages(entries: Vec<PackageEntry>) -> Vec<PackageEntry> {
    let mut by_key: BTreeMap<PackageKey, PackageEntry> = BTreeMap::new();

    for entry in entries {
        let key = PackageKey {
            ecosystem: entry.ecosystem,
            name: entry.name.clone(),
        };

        by_key
            .entry(key)
            .and_modify(|existing| {
                // Keep highest confidence
                if entry.confidence > existing.confidence {
                    existing.confidence = entry.confidence;
                    existing.source = entry.source;
                }

                // Merge affected_versions (union)
                let existing_versions: HashSet<String> =
                    existing.affected_versions.iter().cloned().collect();
                for v in &entry.affected_versions {
                    if !existing_versions.contains(v) {
                        existing.affected_versions.push(v.clone());
                    }
                }

                // If either source says all versions are malicious, honor it
                if entry.all_versions_malicious {
                    existing.all_versions_malicious = true;
                }

                // Keep richest reference (prefer non-None)
                if existing.reference.is_none() && entry.reference.is_some() {
                    existing.reference = entry.reference.clone();
                }
            })
            .or_insert(entry);
    }

    by_key.into_values().collect()
}

// Binary format writing is handled by `tirith_core::threatdb::ThreatDbWriter`.
// The compiler feeds parsed data into that writer, which produces files
// compatible with the reader.

// ---------------------------------------------------------------------------
// Signing key loading
// ---------------------------------------------------------------------------

fn load_signing_key(env_var: Option<&str>, key_file: Option<&Path>) -> Option<SigningKey> {
    // Try env var first
    if let Some(var_name) = env_var {
        if let Ok(b64) = std::env::var(var_name) {
            let b64_trimmed = b64.trim();
            if !b64_trimmed.is_empty() {
                match BASE64.decode(b64_trimmed) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut key_bytes = [0u8; 32];
                        key_bytes.copy_from_slice(&bytes);
                        return Some(SigningKey::from_bytes(&key_bytes));
                    }
                    Ok(bytes) => {
                        eprintln!(
                            "warning: signing key from {var_name} has wrong length (expected 32, got {})",
                            bytes.len()
                        );
                    }
                    Err(e) => {
                        eprintln!("warning: cannot decode base64 signing key from {var_name}: {e}");
                    }
                }
            }
        }
    }

    // Try key file
    if let Some(path) = key_file {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                let b64_trimmed = content.trim();
                match BASE64.decode(b64_trimmed) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut key_bytes = [0u8; 32];
                        key_bytes.copy_from_slice(&bytes);
                        return Some(SigningKey::from_bytes(&key_bytes));
                    }
                    Ok(bytes) => {
                        eprintln!(
                            "warning: signing key file {} has wrong length (expected 32, got {})",
                            path.display(),
                            bytes.len()
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "warning: cannot decode base64 signing key from {}: {e}",
                            path.display()
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "warning: cannot read signing key file {}: {e}",
                    path.display()
                );
            }
        }
    }

    None
}

/// Sign a payload and return the base64-encoded signature.
fn sign_payload(payload: &str, key: &SigningKey) -> String {
    let signature = key.sign(payload.as_bytes());
    BASE64.encode(signature.to_bytes())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    // Handle sign-payload subcommand
    if let Some(Commands::SignPayload { payload, key_env }) = &cli.command {
        let key = load_signing_key(Some(key_env), None).unwrap_or_else(|| {
            eprintln!("error: could not load signing key from env var {key_env}");
            std::process::exit(1);
        });
        println!("{}", sign_payload(payload, &key));
        return;
    }

    // Main compilation flow
    eprintln!("tirith-threatdb-compile: starting compilation");

    // Parse all sources
    let mut all_packages = Vec::new();
    let mut total_files_scanned = 0usize;
    let mut total_files_skipped = 0usize;

    // 1. OSSF malicious-packages
    let ossf_stats;
    if let Some(ref ossf_dir) = cli.ossf {
        eprintln!(
            "  parsing OSSF malicious-packages from {}",
            ossf_dir.display()
        );
        let (ossf_packages, stats) = parse_ossf(ossf_dir);
        eprintln!(
            "    {} entries scanned, {} packages extracted, {} skipped (range-only), {} unknown ecosystem, {} unreadable, {} corrupt",
            stats.total_entries,
            stats.parsed_packages,
            stats.skipped_range_only_count,
            stats.skipped_unknown_ecosystem,
            stats.skipped_unreadable,
            stats.skipped_corrupt,
        );
        total_files_scanned +=
            stats.total_entries + stats.skipped_unreadable + stats.skipped_corrupt;
        total_files_skipped += stats.skipped_unreadable + stats.skipped_corrupt;
        ossf_stats = stats;
        all_packages.extend(ossf_packages);
    } else {
        ossf_stats = OssfStats {
            total_entries: 0,
            parsed_packages: 0,
            skipped_range_only_count: 0,
            skipped_unknown_ecosystem: 0,
            skipped_unreadable: 0,
            skipped_corrupt: 0,
        };
    }

    // 2. Datadog
    if let Some(ref dd_dir) = cli.datadog {
        eprintln!(
            "  parsing Datadog malicious-packages from {}",
            dd_dir.display()
        );
        let (dd_packages, dd_skipped, dd_files_read) = parse_datadog(dd_dir);
        eprintln!(
            "    {} packages extracted, {} files skipped",
            dd_packages.len(),
            dd_skipped
        );
        total_files_scanned += dd_files_read + dd_skipped;
        total_files_skipped += dd_skipped;
        all_packages.extend(dd_packages);
    }

    // Fail if >50% of input files were skipped (corrupt/unreadable)
    if total_files_scanned > 0 && total_files_skipped * 2 > total_files_scanned {
        eprintln!(
            "error: {total_files_skipped}/{total_files_scanned} input files skipped (>{:.0}%) — aborting to avoid corrupt DB",
            (total_files_skipped as f64 / total_files_scanned as f64) * 100.0
        );
        std::process::exit(1);
    }

    // 3. Normalize + deduplicate packages
    let pre_dedup = all_packages.len();
    let packages = deduplicate_packages(all_packages);
    eprintln!(
        "  deduplication: {} -> {} packages",
        pre_dedup,
        packages.len()
    );

    // 4. Feodo Tracker IPs
    let ips = if let Some(ref feodo_path) = cli.feodo {
        eprintln!("  parsing Feodo Tracker IPs from {}", feodo_path.display());
        let ips = parse_feodo(feodo_path);
        eprintln!("    {} unique IPs", ips.len());
        ips
    } else {
        Vec::new()
    };

    // 5. CISA KEV (counted for summary, not stored in DB in Phase A)
    let kev_count = if let Some(ref kev_path) = cli.cisa_kev {
        eprintln!("  parsing CISA KEV from {}", kev_path.display());
        let entries = parse_cisa_kev(kev_path);
        eprintln!("    {} CVEs", entries.len());
        entries.len()
    } else {
        0
    };

    // 6. Typosquats
    let typosquats = if let Some(ref typo_path) = cli.typosquats {
        eprintln!("  parsing typosquats from {}", typo_path.display());
        let entries = parse_typosquats_csv(typo_path);
        eprintln!("    {} typosquat entries", entries.len());
        entries
    } else {
        Vec::new()
    };

    // 7. Popular packages
    eprintln!("  loading popular packages");
    let popular = parse_popular_csv(cli.popular.as_deref());
    eprintln!("    {} popular packages", popular.len());

    // 8. Phase B hostname/IP feeds
    let urlhaus_hosts = if let Some(ref path) = cli.urlhaus {
        eprintln!("  parsing URLhaus hostnames from {}", path.display());
        let hosts = parse_urlhaus_file(path);
        eprintln!("    {} hostnames", hosts.len());
        hosts
    } else {
        Vec::new()
    };

    let (threatfox_hosts, threatfox_ips) = if let Some(ref path) = cli.threatfox {
        eprintln!("  parsing ThreatFox IOCs from {}", path.display());
        let parsed = parse_threatfox_file(path);
        eprintln!("    {} hostnames, {} IPs", parsed.0.len(), parsed.1.len());
        parsed
    } else {
        (Vec::new(), Vec::new())
    };

    let phishing_army_hosts = if let Some(ref path) = cli.phishing_army {
        eprintln!("  parsing Phishing Army blocklist from {}", path.display());
        let hosts = parse_blocklist_file(path);
        eprintln!("    {} hostnames", hosts.len());
        hosts
    } else {
        Vec::new()
    };

    let phishtank_hosts = if let Some(ref path) = cli.phishtank {
        eprintln!("  parsing PhishTank CSV from {}", path.display());
        let hosts = parse_phishtank_file(path);
        eprintln!("    {} hostnames", hosts.len());
        hosts
    } else {
        Vec::new()
    };

    let tor_exit_ips = if let Some(ref path) = cli.tor_exit {
        eprintln!("  parsing Tor exit nodes from {}", path.display());
        let ips = parse_tor_exit_file(path);
        eprintln!("    {} IPs", ips.len());
        ips
    } else {
        Vec::new()
    };

    // Load signing key
    let signing_key = load_signing_key(cli.sign_key_env.as_deref(), cli.sign_key_file.as_deref());

    let signing_key = match signing_key {
        Some(k) => k,
        None => {
            eprintln!("error: signing key is required to build a valid DB");
            std::process::exit(1);
        }
    };

    // Build DB using tirith_core::threatdb::ThreatDbWriter
    let timestamp = chrono::Utc::now().timestamp() as u64;
    let sequence = cli.sequence.unwrap_or(timestamp);
    let mut writer = ThreatDbWriter::new(timestamp, sequence);

    // Feed deduplicated packages
    for pkg in &packages {
        let version_refs: Vec<&str> = pkg.affected_versions.iter().map(|s| s.as_str()).collect();
        writer.add_package(
            pkg.ecosystem,
            &pkg.name,
            &version_refs,
            pkg.source,
            pkg.confidence,
            pkg.all_versions_malicious,
            pkg.reference.as_deref(),
        );
    }

    // Feed IPs
    for ip in &ips {
        writer.add_ip(*ip, ThreatSource::FeodoTracker);
    }

    for host in &urlhaus_hosts {
        writer.add_hostname(host, ThreatSource::Urlhaus);
    }

    for host in &threatfox_hosts {
        writer.add_hostname(host, ThreatSource::ThreatFoxIoc);
    }

    for ip in &threatfox_ips {
        writer.add_ip(*ip, ThreatSource::ThreatFoxIoc);
    }

    for host in &phishing_army_hosts {
        writer.add_hostname(host, ThreatSource::PhishingArmy);
    }

    for host in &phishtank_hosts {
        writer.add_hostname(host, ThreatSource::PhishTank);
    }

    for ip in &tor_exit_ips {
        writer.add_ip(*ip, ThreatSource::TorExit);
    }

    // Feed typosquats
    for typo in &typosquats {
        writer.add_typosquat(typo.ecosystem, &typo.name, &typo.target_name);
    }

    // Feed popular packages
    for pop in &popular {
        writer.add_popular(pop.ecosystem, &pop.name);
    }

    // Build and sign — ThreatDbWriter handles sorting, dedup, index generation,
    // header layout, and signing in a format compatible with the reader.
    let data = writer.build(&signing_key).unwrap_or_else(|e| {
        eprintln!("error: failed to build threat DB: {e}");
        std::process::exit(1);
    });

    // Write to output file
    let mut file = std::fs::File::create(&cli.output).unwrap_or_else(|e| {
        eprintln!(
            "error: cannot create output file {}: {e}",
            cli.output.display()
        );
        std::process::exit(1);
    });
    file.write_all(&data).unwrap_or_else(|e| {
        eprintln!("error: cannot write output file: {e}");
        std::process::exit(1);
    });

    // Summary
    let ecosystems_seen: BTreeSet<String> = packages
        .iter()
        .map(|p| format!("{:?}", p.ecosystem))
        .collect();

    eprintln!();
    eprintln!("=== Threat DB compilation complete ===");
    eprintln!("  output:                {}", cli.output.display());
    eprintln!("  file size:             {} bytes", data.len());
    eprintln!("  packages:              {}", packages.len());
    eprintln!("  IPs (Feodo):           {}", ips.len());
    eprintln!("  typosquats:            {}", typosquats.len());
    eprintln!("  popular packages:      {}", popular.len());
    eprintln!("  CISA KEV CVEs:         {}", kev_count);
    eprintln!(
        "  skipped (range-only):  {}",
        ossf_stats.skipped_range_only_count
    );
    eprintln!("  skipped (corrupt):     {}", total_files_skipped);
    eprintln!(
        "  ecosystems:            {}",
        ecosystems_seen
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    );
    eprintln!("  signed:                yes");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_normalize_pypi() {
        assert_eq!(normalize_name(Ecosystem::PyPI, "My_Package"), "my-package");
        assert_eq!(normalize_name(Ecosystem::PyPI, "my.package"), "my-package");
        assert_eq!(normalize_name(Ecosystem::PyPI, "MY-PACKAGE"), "my-package");
    }

    #[test]
    fn test_normalize_npm_case_sensitive() {
        assert_eq!(normalize_name(Ecosystem::Npm, "Express"), "Express");
        assert_eq!(normalize_name(Ecosystem::Npm, "@scope/Pkg"), "@scope/Pkg");
    }

    #[test]
    fn test_normalize_crates_lowercase() {
        assert_eq!(normalize_name(Ecosystem::Crates, "Serde"), "serde");
    }

    #[test]
    fn test_ecosystem_from_str() {
        assert_eq!(Ecosystem::from_name("npm"), Some(Ecosystem::Npm));
        assert_eq!(Ecosystem::from_name("PyPI"), Some(Ecosystem::PyPI));
        assert_eq!(Ecosystem::from_name("crates.io"), Some(Ecosystem::Crates));
        assert_eq!(Ecosystem::from_name("cargo"), Some(Ecosystem::Crates));
        assert_eq!(Ecosystem::from_name("unknown"), None);
    }

    #[test]
    fn test_deduplication_keeps_highest_confidence() {
        let entries = vec![
            PackageEntry {
                ecosystem: Ecosystem::PyPI,
                name: "evil-pkg".to_string(),
                affected_versions: vec!["1.0".to_string()],
                all_versions_malicious: false,
                source: ThreatSource::OssfMalicious,
                confidence: Confidence::Medium,
                reference: None,
            },
            PackageEntry {
                ecosystem: Ecosystem::PyPI,
                name: "evil-pkg".to_string(),
                affected_versions: vec!["2.0".to_string()],
                all_versions_malicious: false,
                source: ThreatSource::DatadogMalicious,
                confidence: Confidence::Confirmed,
                reference: Some("https://example.com".to_string()),
            },
        ];

        let deduped = deduplicate_packages(entries);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].confidence, Confidence::Confirmed);
        assert_eq!(deduped[0].affected_versions.len(), 2);
        assert!(deduped[0].reference.is_some());
    }

    #[test]
    fn test_deduplication_merges_all_versions_flag() {
        let entries = vec![
            PackageEntry {
                ecosystem: Ecosystem::Npm,
                name: "bad-pkg".to_string(),
                affected_versions: vec!["1.0".to_string()],
                all_versions_malicious: false,
                source: ThreatSource::OssfMalicious,
                confidence: Confidence::Medium,
                reference: None,
            },
            PackageEntry {
                ecosystem: Ecosystem::Npm,
                name: "bad-pkg".to_string(),
                affected_versions: Vec::new(),
                all_versions_malicious: true,
                source: ThreatSource::DatadogMalicious,
                confidence: Confidence::Confirmed,
                reference: None,
            },
        ];

        let deduped = deduplicate_packages(entries);
        assert_eq!(deduped.len(), 1);
        assert!(deduped[0].all_versions_malicious);
    }

    #[test]
    fn test_parse_feodo_skips_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("feodo.txt");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "# Feodo Tracker IP Blocklist").unwrap();
        writeln!(f, "# Last updated: 2024-01-01").unwrap();
        writeln!(f).unwrap();
        writeln!(f, "1.2.3.4").unwrap();
        writeln!(f, "5.6.7.8").unwrap();
        writeln!(f, "# another comment").unwrap();
        writeln!(f, "10.0.0.1").unwrap();
        drop(f);

        let ips = parse_feodo(&path);
        assert_eq!(ips.len(), 3);
        assert_eq!(ips[0], "1.2.3.4".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn test_popular_csv_parsing() {
        let entries = parse_popular_from_string("ecosystem,name\nnpm,express\npypi,requests\n");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ecosystem, Ecosystem::Npm);
        assert_eq!(entries[0].name, "express");
        assert_eq!(entries[1].ecosystem, Ecosystem::PyPI);
        assert_eq!(entries[1].name, "requests");
    }

    #[test]
    fn test_default_popular_csv_loads() {
        let entries = parse_popular_csv(None);
        assert!(
            entries.len() >= 50,
            "expected at least 50 popular packages, got {}",
            entries.len()
        );
    }

    #[test]
    fn test_binary_roundtrip_via_core_writer() {
        use tirith_core::threatdb::ThreatDb;

        let key = SigningKey::from_bytes(&[42u8; 32]);
        let mut writer = ThreatDbWriter::new(1700000000, 42);

        writer.add_package(
            Ecosystem::PyPI,
            "evil-test",
            &["1.0.0"],
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            false,
            Some("https://example.com/advisory"),
        );
        writer.add_ip("1.2.3.4".parse().unwrap(), ThreatSource::FeodoTracker);
        writer.add_popular(Ecosystem::Npm, "express");

        let data = writer.build(&key).expect("build failed");

        // Verify magic
        assert_eq!(&data[..8], b"TIRITHDB");

        // Verify format version
        let version = u32::from_le_bytes(data[8..12].try_into().unwrap());
        assert_eq!(version, 1);

        // Verify the DB can be read back by the core reader
        let db = ThreatDb::from_bytes(data, 0).expect("reader should accept writer output");
        let stats = db.stats();
        assert_eq!(stats.package_count, 1);
        assert_eq!(stats.ip_count, 1);
        assert_eq!(stats.popular_count, 1);
        assert_eq!(stats.build_timestamp, 1700000000);
        assert_eq!(stats.build_sequence, 42);
    }

    #[test]
    fn test_sign_payload_deterministic() {
        // Use a fixed test key
        let key_bytes = [42u8; 32];
        let key = SigningKey::from_bytes(&key_bytes);

        let sig1 = sign_payload("test payload", &key);
        let sig2 = sign_payload("test payload", &key);
        assert_eq!(sig1, sig2, "signing must be deterministic");
        assert!(!sig1.is_empty(), "signature must not be empty");
    }

    #[test]
    fn test_ossv_confidence_mapping() {
        // Test the confidence mapping logic directly
        let malware_type: Option<&str> = Some("MALWARE");
        let confidence = match malware_type {
            Some("MALWARE") => Confidence::Confirmed,
            Some("POTENTIALLY_UNWANTED") => Confidence::Medium,
            _ => Confidence::Medium,
        };
        assert_eq!(confidence, Confidence::Confirmed);

        let unwanted_type: Option<&str> = Some("POTENTIALLY_UNWANTED");
        let confidence2 = match unwanted_type {
            Some("MALWARE") => Confidence::Confirmed,
            Some("POTENTIALLY_UNWANTED") => Confidence::Medium,
            _ => Confidence::Medium,
        };
        assert_eq!(confidence2, Confidence::Medium);

        let no_type: Option<&str> = None;
        let confidence3 = match no_type {
            Some("MALWARE") => Confidence::Confirmed,
            Some("POTENTIALLY_UNWANTED") => Confidence::Medium,
            _ => Confidence::Medium,
        };
        assert_eq!(confidence3, Confidence::Medium);
    }

    #[test]
    fn test_typosquats_csv_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("typosquats.csv");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "ecosystem,name,target_name").unwrap();
        writeln!(f, "pypi,reqeusts,requests").unwrap();
        writeln!(f, "npm,loadsh,lodash").unwrap();
        drop(f);

        let entries = parse_typosquats_csv(&path);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ecosystem, Ecosystem::PyPI);
        assert_eq!(entries[0].name, "reqeusts");
        assert_eq!(entries[0].target_name, "requests");
    }

    #[test]
    fn test_cisa_kev_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kev.json");
        std::fs::write(
            &path,
            r#"{"vulnerabilities":[{"cveID":"CVE-2024-1234","vendorProject":"TestVendor","product":"TestProduct","vulnerabilityName":"Test Vuln","dateAdded":"2024-01-01","shortDescription":"A test vulnerability","requiredAction":"Apply update","dueDate":"2024-02-01","knownRansomwareCampaignUse":"Unknown"}]}"#,
        )
        .unwrap();

        let entries = parse_cisa_kev(&path);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].cve_id, "CVE-2024-1234");
    }
}
