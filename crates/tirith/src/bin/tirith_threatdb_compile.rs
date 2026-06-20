//! Threat DB compiler — builds the binary threat intelligence database from
//! multiple open-source feeds (OSSF, Datadog, Feodo, CISA KEV, ecosyste.ms,
//! …) into a signed `.dat`. Used by CI (`.github/workflows/threatdb.yml`).
//! The binary format and `ThreatDbWriter` live in `tirith_core::threatdb`.

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
    parse_domain_blocklist, parse_exfil_endpoint_list, parse_phishtank_csv, parse_threatfox_zip,
    parse_tor_exit_list, parse_urlhaus_csv,
};

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

    /// Curated exfiltration-endpoint / webhook-catcher hostname list. Plain
    /// domain-per-line blocklist; compiled into the signed primary DB under
    /// ThreatSource::ExfilEndpoint. Optional — skipped if not supplied.
    #[arg(long)]
    exfil_endpoints: Option<PathBuf>,

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

// Intermediate parse types fed to ThreatDbWriter. Ecosystem, ThreatSource, and
// Confidence are imported from tirith_core::threatdb.

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

/// CISA KEV entry. Phase A only counts these; Phase C will cross-ref OSV.dev.
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

/// OSV JSON schema (subset used for malicious-packages).
///
/// OSV records are extensible, so every struct here uses `#[serde(default)]`
/// and tolerates unknown fields. The shapes below were derived from real
/// `MAL-*` records fetched from the OSV API (see the vendored fixtures in
/// `tests/fixtures` exercised by `test_parse_real_ossf_record_indicators`):
/// indicators live in the entry-level `database_specific.iocs` and
/// `database_specific.malicious-packages-origins`, NOT under
/// `affected[].database_specific`. The affected-level `database_specific`
/// carries provenance (`source` URL) and `cwes`.
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
    // Parsed so the field is tolerated and available to DB-B; provenance only,
    // never an indicator source.
    #[serde(default)]
    #[allow(dead_code)] // affected-level provenance retained for DB-B correlation
    database_specific: Option<OsvAffectedDatabaseSpecific>,
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

/// Entry-level `database_specific`. Legacy OSV exports carried a `type`
/// (MALWARE/POTENTIALLY_UNWANTED); current OpenSSF malicious-packages records
/// instead carry `iocs` and `malicious-packages-origins`.
#[derive(Debug, serde::Deserialize)]
struct OsvDatabaseSpecific {
    #[serde(default, rename = "type")]
    entry_type: Option<String>,
    #[serde(default)]
    iocs: Option<OsvIocs>,
    #[serde(default, rename = "malicious-packages-origins")]
    malicious_packages_origins: Vec<OsvOrigin>,
}

/// Indicators of compromise carried at the entry level by current records.
#[derive(Debug, Default, serde::Deserialize)]
struct OsvIocs {
    #[serde(default)]
    ips: Vec<String>,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    urls: Vec<String>,
}

/// One entry in `malicious-packages-origins`: a per-source attestation that
/// carries the OSSF analysis artifact `sha256` and the versions it covers.
#[derive(Debug, Default, serde::Deserialize)]
#[allow(dead_code)] // versions/id retained for DB-B correlation
struct OsvOrigin {
    #[serde(default)]
    source: String,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    versions: Vec<String>,
    #[serde(default)]
    id: Option<String>,
}

/// Affected-level `database_specific`: provenance only (a `source` URL and
/// `cwes`), never indicators. Captured so the parser tolerates the field.
#[derive(Debug, Default, serde::Deserialize)]
#[allow(dead_code)] // provenance retained for DB-B correlation
struct OsvAffectedDatabaseSpecific {
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    cwes: Vec<OsvCwe>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[allow(dead_code)] // cwe metadata retained for DB-B correlation
struct OsvCwe {
    #[serde(default, rename = "cweId")]
    cwe_id: String,
}

#[derive(Debug, serde::Deserialize)]
struct OsvReference {
    #[serde(default)]
    url: String,
}

/// In-memory intermediate model of the artifact/file/URL indicators parsed out
/// of an OpenSSF malicious-packages record.
///
/// DB-A has no on-disk format for these (v1 has no indicator sections), so this
/// is staged in memory and its counts logged to prove the parser against real
/// records; it is NOT persisted and does not change client behavior. DB-B's v2
/// writer will consume this same model to populate v2 indicator sections.
///
/// Only explicit indicator fields are collected. OSV `references` (ADVISORY /
/// ARTICLE / REPORT links) are legitimate documentation, never malicious
/// indicators, and are deliberately excluded.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct OssfIndicators {
    /// SHA-256 hashes of the analysis artifacts, from
    /// `database_specific.malicious-packages-origins[].sha256`.
    artifact_sha256: Vec<String>,
    /// Malicious IPs, from `database_specific.iocs.ips`.
    ips: Vec<String>,
    /// Malicious domains, from `database_specific.iocs.domains`.
    domains: Vec<String>,
    /// Malicious URLs, from `database_specific.iocs.urls`.
    urls: Vec<String>,
}

impl OssfIndicators {
    /// Extract indicators from an entry-level `database_specific`. Pure: it
    /// reads only explicit indicator fields and never touches `references`.
    fn from_database_specific(ds: Option<&OsvDatabaseSpecific>) -> Self {
        let mut out = OssfIndicators::default();
        let Some(ds) = ds else {
            return out;
        };
        for origin in &ds.malicious_packages_origins {
            if let Some(sha) = &origin.sha256 {
                if !sha.is_empty() {
                    out.artifact_sha256.push(sha.clone());
                }
            }
        }
        if let Some(iocs) = &ds.iocs {
            out.ips.extend(iocs.ips.iter().cloned());
            out.domains.extend(iocs.domains.iter().cloned());
            out.urls.extend(iocs.urls.iter().cloned());
        }
        out
    }

    /// Total number of indicators across all kinds (for diagnostics).
    fn len(&self) -> usize {
        self.artifact_sha256.len() + self.ips.len() + self.domains.len() + self.urls.len()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// OpenSSF malicious-packages confidence.
///
/// Current `MAL-*` records do not carry the legacy `database_specific.type`, so
/// keying confidence on `type` alone left every real record at `Medium`. A
/// record published by OpenSSF malicious-packages whose id starts with `MAL-`
/// is a confirmed-malicious entry, so it maps to `Confirmed` even without a
/// `type`. Legacy `type` values are still honored when present.
///
/// This is source-specific on purpose: it is only applied inside `parse_ossf`
/// (the OpenSSF feed). The Datadog OSV-fallback path does not call it, so an
/// arbitrary `MAL-` id arriving from another feed is not auto-promoted.
fn ossf_confidence(id: &str, entry_type: Option<&str>) -> Confidence {
    match entry_type {
        Some("MALWARE") => Confidence::Confirmed,
        Some("POTENTIALLY_UNWANTED") => Confidence::Medium,
        _ if id.starts_with("MAL-") => Confidence::Confirmed,
        Some(other) => {
            // An OpenSSF type we do not recognize: surface it (the feed may have
            // grown a new value worth handling) and fall back to the borderline
            // default rather than silently swallowing it.
            eprintln!(
                "  warning: unrecognized OpenSSF database_specific type {other:?} for {id}, defaulting to Medium"
            );
            Confidence::Medium
        }
        None => Confidence::Medium, // No type and not a MAL- id: borderline default.
    }
}

struct OssfStats {
    total_entries: usize,
    parsed_packages: usize,
    skipped_range_only_count: usize,
    skipped_unknown_ecosystem: usize,
    skipped_unreadable: usize,
    skipped_corrupt: usize,
    /// Records that carried at least one parsed indicator (artifact/IP/domain/URL).
    records_with_indicators: usize,
    /// Total parsed indicators across all records. Staged in memory only (DB-A
    /// has no on-disk section for them); DB-B's v2 writer will persist them.
    total_indicators: usize,
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
        records_with_indicators: 0,
        total_indicators: 0,
    };

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

        let entry_type = osv
            .database_specific
            .as_ref()
            .and_then(|d| d.entry_type.as_deref());

        // Source-specific: an OpenSSF malicious-packages MAL-* record is
        // Confirmed even without the legacy `type`. parse_ossf is the only
        // caller, so the OpenSSF-source constraint is satisfied by construction.
        let confidence = ossf_confidence(&osv.id, entry_type);

        // An all-versions ("whole package is bad") entry is produced for a
        // Confirmed record with no versions and no ranges. Previously only a
        // legacy `type == "MALWARE"` qualified; current MAL-* records confirm
        // via the id, so key this on the resolved confidence instead.
        let is_confirmed = confidence == Confidence::Confirmed;

        // Stage indicators in memory and log their counts. DB-A does not persist
        // them (v1 has no indicator section); DB-B's v2 writer consumes this
        // same model. Only explicit indicator fields are read; `references` are
        // legitimate documentation links and are excluded.
        let indicators = OssfIndicators::from_database_specific(osv.database_specific.as_ref());
        if !indicators.is_empty() {
            stats.records_with_indicators += 1;
            stats.total_indicators += indicators.len();
        }

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
                // Ranges but no explicit version list — skipped in Phase A.
                stats.skipped_range_only_count += 1;
            } else if is_confirmed {
                // Confirmed-malicious (legacy MALWARE type or a MAL-* id) with no
                // versions and no ranges — the whole package is bad.
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
                stats.skipped_range_only_count += 1;
            }
        }
    }

    (entries, stats)
}

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

        // Try an array of entries, then a single entry, then OSV-shaped JSON.
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

        if let Ok(osv) = serde_json::from_str::<OsvEntry>(&content) {
            for affected in &osv.affected {
                if let Some(pkg) = &affected.package {
                    if let Some(eco) = Ecosystem::from_name(&pkg.ecosystem) {
                        // Only explicit version lists, like the OSSF parser.
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

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Take the first whitespace-delimited token as the IP.
        let ip_str = trimmed.split_whitespace().next().unwrap_or("");
        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
            ips.push(ip);
        }
    }

    ips.sort();
    ips.dedup();
    ips
}

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

// Phase B feed parsers.

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

/// Parse the explicit exfil-endpoint feed. FALLIBLE on purpose: `--exfil-endpoints
/// <path>` means the operator INTENDED that primary feed, so an unreadable path
/// must NOT silently degrade to zero endpoints (which would let CI publish a
/// weakened, signed threat DB after a transient path/permission failure). The read
/// error is propagated so the call site can exit non-zero. Contrast: a feed that is
/// simply not supplied stays a no-op (the call site skips this entirely).
fn parse_exfil_endpoints_file(path: &Path) -> std::io::Result<Vec<String>> {
    let contents = std::fs::read_to_string(path)?;
    Ok(parse_exfil_endpoint_list(&contents).hostnames)
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

        // Columns: ecosystem, name, target_name
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

/// Default popular packages CSV, embedded from the crate's own assets so
/// `cargo publish` can verify the tarball in isolation.
const DEFAULT_POPULAR_CSV: &str = include_str!("../../assets/data/popular_packages.csv");

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
                // Keep highest confidence.
                if entry.confidence > existing.confidence {
                    existing.confidence = entry.confidence;
                    existing.source = entry.source;
                }

                // Union the affected_versions.
                let existing_versions: HashSet<String> =
                    existing.affected_versions.iter().cloned().collect();
                for v in &entry.affected_versions {
                    if !existing_versions.contains(v) {
                        existing.affected_versions.push(v.clone());
                    }
                }

                if entry.all_versions_malicious {
                    existing.all_versions_malicious = true;
                }

                // Keep the richest reference (prefer non-None).
                if existing.reference.is_none() && entry.reference.is_some() {
                    existing.reference = entry.reference.clone();
                }
            })
            .or_insert(entry);
    }

    by_key.into_values().collect()
}

fn load_signing_key(env_var: Option<&str>, key_file: Option<&Path>) -> Option<SigningKey> {
    // Try env var first, then key file.
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

fn main() {
    let cli = Cli::parse();

    // Handle sign-payload subcommand.
    if let Some(Commands::SignPayload { payload, key_env }) = &cli.command {
        let key = load_signing_key(Some(key_env), None).unwrap_or_else(|| {
            eprintln!("error: could not load signing key from env var {key_env}");
            std::process::exit(1);
        });
        println!("{}", sign_payload(payload, &key));
        return;
    }

    eprintln!("tirith-threatdb-compile: starting compilation");

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
        // DB-A stages indicators in memory only; DB-B's v2 writer persists them.
        eprintln!(
            "    {} indicators parsed across {} records (staged in memory, not persisted in v1)",
            stats.total_indicators, stats.records_with_indicators,
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
            records_with_indicators: 0,
            total_indicators: 0,
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

    // Fail if >50% of input files were skipped (corrupt/unreadable).
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

    let exfil_endpoint_hosts = if let Some(ref path) = cli.exfil_endpoints {
        eprintln!("  parsing exfil endpoints from {}", path.display());
        // Fail closed: an explicitly-supplied feed that cannot be read must abort
        // rather than sign a DB with zero exfil endpoints (a weakened DB).
        let hosts = parse_exfil_endpoints_file(path).unwrap_or_else(|e| {
            eprintln!(
                "error: cannot read explicitly-supplied exfil-endpoint list {}: {e}",
                path.display()
            );
            std::process::exit(1);
        });
        eprintln!("    {} hostnames", hosts.len());
        hosts
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

    let timestamp = chrono::Utc::now().timestamp() as u64;
    let sequence = cli.sequence.unwrap_or(timestamp);
    let mut writer = ThreatDbWriter::new(timestamp, sequence);

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

    for host in &exfil_endpoint_hosts {
        writer.add_hostname(host, ThreatSource::ExfilEndpoint);
    }

    for ip in &tor_exit_ips {
        writer.add_ip(*ip, ThreatSource::TorExit);
    }

    for typo in &typosquats {
        writer.add_typosquat(typo.ecosystem, &typo.name, &typo.target_name);
    }

    for pop in &popular {
        writer.add_popular(pop.ecosystem, &pop.name);
    }

    // ThreatDbWriter handles sorting, dedup, index generation, header layout,
    // and signing in a format compatible with the reader.
    let data = writer.build(&signing_key).unwrap_or_else(|e| {
        eprintln!("error: failed to build threat DB: {e}");
        std::process::exit(1);
    });

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

        assert_eq!(&data[..8], b"TIRITHDB");
        let version = u32::from_le_bytes(data[8..12].try_into().unwrap());
        assert_eq!(version, 1);

        // The DB must read back via the core reader.
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
        let key_bytes = [42u8; 32];
        let key = SigningKey::from_bytes(&key_bytes);

        let sig1 = sign_payload("test payload", &key);
        let sig2 = sign_payload("test payload", &key);
        assert_eq!(sig1, sig2, "signing must be deterministic");
        assert!(!sig1.is_empty(), "signature must not be empty");
    }

    #[test]
    fn test_ossv_confidence_mapping() {
        // Legacy `database_specific.type` still wins when present, regardless of id.
        assert_eq!(
            ossf_confidence("MAL-2025-6812", Some("MALWARE")),
            Confidence::Confirmed
        );
        assert_eq!(
            ossf_confidence("MAL-2025-6812", Some("POTENTIALLY_UNWANTED")),
            Confidence::Medium
        );

        // Source-specific fix: a real MAL-* record carries no `type`, but is a
        // confirmed OpenSSF malicious-packages entry, so it maps to Confirmed.
        assert_eq!(
            ossf_confidence("MAL-2026-2307", None),
            Confidence::Confirmed
        );

        // A non-MAL id with no `type` stays Medium (OSSF allows borderline).
        assert_eq!(ossf_confidence("OSV-2025-0001", None), Confidence::Medium);
        assert_eq!(ossf_confidence("", None), Confidence::Medium);

        // POTENTIALLY_UNWANTED is never promoted by a MAL- id.
        assert_eq!(
            ossf_confidence("MAL-2026-2307", Some("POTENTIALLY_UNWANTED")),
            Confidence::Medium
        );

        // An unrecognized type on a non-MAL id falls back to Medium (and emits a
        // warning that surfaces the new type); a MAL- id still wins over it.
        assert_eq!(
            ossf_confidence("OSV-2025-0002", Some("BRAND_NEW_TYPE")),
            Confidence::Medium
        );
        assert_eq!(
            ossf_confidence("MAL-2026-9999", Some("BRAND_NEW_TYPE")),
            Confidence::Confirmed
        );
    }

    // Real OpenSSF malicious-packages records fetched from the OSV API and
    // vendored as fixtures. The parser structs are derived from these actual
    // shapes (indicators under entry-level `database_specific.iocs` /
    // `malicious-packages-origins`, not `affected[].database_specific`).
    const MAL_2025_6812: &str = include_str!("fixtures/mal-2025-6812.json");
    const MAL_2026_2307: &str = include_str!("fixtures/mal-2026-2307.json");

    #[test]
    fn test_parse_real_ossf_record_indicators() {
        // MAL-2025-6812: malicious-packages-origins with one sha256, no iocs.
        let osv: OsvEntry = serde_json::from_str(MAL_2025_6812).expect("fixture must deserialize");
        assert_eq!(osv.id, "MAL-2025-6812");
        assert_eq!(osv.affected.len(), 1);
        assert_eq!(osv.affected[0].versions, vec!["71.71.72".to_string()]);

        // Confirmed via the MAL- id, with no legacy `type`.
        let entry_type = osv
            .database_specific
            .as_ref()
            .and_then(|d| d.entry_type.as_deref());
        assert_eq!(entry_type, None);
        assert_eq!(
            ossf_confidence(&osv.id, entry_type),
            Confidence::Confirmed,
            "a MAL-* record with no type must be Confirmed"
        );

        let ind = OssfIndicators::from_database_specific(osv.database_specific.as_ref());
        assert_eq!(
            ind.artifact_sha256,
            vec!["091ef657bc115b400dc3d8cd65691df53caef85fa307f52d627aac4d50120a77".to_string()]
        );
        assert!(ind.ips.is_empty());
        assert!(ind.domains.is_empty());
        assert!(ind.urls.is_empty());
        assert_eq!(ind.len(), 1);

        // The affected-level database_specific (source URL) is tolerated, not
        // mistaken for an indicator.
        assert!(osv.affected[0]
            .database_specific
            .as_ref()
            .and_then(|d| d.source.as_deref())
            .is_some_and(|s| s.contains("ossf/malicious-packages")));
    }

    #[test]
    fn test_parse_real_ossf_record_with_iocs() {
        // MAL-2026-2307: iocs (ips/domains/urls) plus three origin sha256s.
        let osv: OsvEntry = serde_json::from_str(MAL_2026_2307).expect("fixture must deserialize");
        assert_eq!(osv.id, "MAL-2026-2307");

        let ind = OssfIndicators::from_database_specific(osv.database_specific.as_ref());
        assert_eq!(ind.ips, vec!["142.11.206.73".to_string()]);
        assert_eq!(ind.domains, vec!["sfrclak.com".to_string()]);
        assert_eq!(
            ind.urls,
            vec!["http://sfrclak.com:8000/6202033".to_string()]
        );
        // Three origins each contribute their artifact sha256.
        assert_eq!(ind.artifact_sha256.len(), 3);
        assert!(ind.artifact_sha256.contains(
            &"503284900929e333b801f9f47419a2b4c21e4022d13a03fc14e4b5390767a51d".to_string()
        ));
        assert_eq!(ind.len(), 6);

        // The OSV `references` (ADVISORY/ARTICLE/REPORT) are legitimate links and
        // must NOT leak into any indicator field.
        assert!(!osv.references.is_empty(), "fixture has references");
        for r in &osv.references {
            assert!(
                !ind.urls.contains(&r.url),
                "references must not be indicators"
            );
        }
    }

    #[test]
    fn test_ossf_indicators_ignore_references_and_tolerate_unknowns() {
        // Unknown top-level and nested fields are tolerated (records are
        // extensible), and references never become indicators.
        let json = r#"{
            "id": "MAL-2099-0001",
            "some_future_field": {"nested": [1, 2, 3]},
            "references": [{"type": "ADVISORY", "url": "https://example.com/advisory"}],
            "database_specific": {
                "future_key": true,
                "iocs": {"domains": ["evil.example"], "future_ioc": ["x"]},
                "malicious-packages-origins": [
                    {"source": "ossf-package-analysis", "sha256": "abc", "extra": 1}
                ]
            },
            "affected": [{
                "package": {"name": "p", "ecosystem": "npm"},
                "versions": ["1.0.0"],
                "database_specific": {"source": "https://x", "unknown": 5}
            }]
        }"#;
        let osv: OsvEntry = serde_json::from_str(json).expect("unknown fields must be tolerated");
        let ind = OssfIndicators::from_database_specific(osv.database_specific.as_ref());
        assert_eq!(ind.domains, vec!["evil.example".to_string()]);
        assert_eq!(ind.artifact_sha256, vec!["abc".to_string()]);
        assert!(ind.urls.is_empty());
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
    fn test_exfil_endpoints_read_error_is_fatal_err() {
        // An explicitly-supplied feed that cannot be read must surface an Err so the
        // call site can exit non-zero (fail closed). Previously this logged a warning
        // and returned an empty Vec, letting CI sign a weakened DB.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.txt");
        let result = parse_exfil_endpoints_file(&missing);
        assert!(
            result.is_err(),
            "an unreadable explicit exfil feed must return Err, not an empty Vec"
        );

        // A readable feed still parses to its hostnames (the no-op vs. real-feed
        // distinction is preserved: a supplied, readable feed yields entries).
        let path = dir.path().join("exfil.txt");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "# exfil endpoints").unwrap();
        writeln!(f, "evil-webhook.example").unwrap();
        writeln!(f, "catcher.example").unwrap();
        drop(f);
        let hosts = parse_exfil_endpoints_file(&path).expect("a readable feed must parse");
        assert!(
            hosts.iter().any(|h| h == "evil-webhook.example"),
            "the readable feed's hostnames must be returned, got {hosts:?}"
        );
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
