//! Threat DB compiler — builds the binary threat intelligence database from
//! multiple open-source feeds (OSSF, Datadog, Feodo, CISA KEV, ecosyste.ms,
//! …) into a signed `.dat`. Used by CI (`.github/workflows/threatdb.yml`).
//! The binary format and `ThreatDbWriter` live in `tirith_core::threatdb`.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use sha2::{Digest, Sha256};

use tirith_core::threatdb::{
    canonical_package_name, canonical_threat_hostname, Confidence, Ecosystem, SourceRecordCounts,
    ThreatDb, ThreatDbFormat, ThreatDbWriter, ThreatSource,
};
use tirith_core::threatdb_feeds::{
    parse_curated_file_hashes, parse_digitalside_csv, parse_domain_blocklist,
    parse_exfil_endpoint_list, parse_phishtank_csv, parse_threatfox_zip, parse_tor_exit_list,
    parse_urlhaus_csv, CuratedFileHashes, FileHashProvenance,
};

#[derive(Parser)]
#[command(
    name = "tirith-threatdb-compile",
    about = "Compile threat intelligence feeds into a signed binary database",
    version
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

    /// Audited registry-version snapshot produced by `fetch-registry-snapshots`.
    /// Required only for active confirmed OpenSSF bounded ranges.
    #[arg(long, requires = "source_provenance")]
    registry_snapshots: Option<PathBuf>,

    /// Immutable pre-compile source transaction provenance. Required with a
    /// registry snapshot so its OpenSSF revision and exact file digest are
    /// authenticated before bounded versions are materialized.
    #[arg(long, requires = "ossf")]
    source_provenance: Option<PathBuf>,

    /// Destination for the compiler's post-parse, machine-readable counters.
    /// Required for signed generation publication and merged into the released
    /// provenance only after compilation succeeds.
    #[arg(long)]
    compiler_metadata: Option<PathBuf>,

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

    /// DigitalSide Threat-Intel MISP-style CSV export (davidonzo/Threat-Intel).
    /// GATED feed: the source is defined but the CI fetch is disabled while the
    /// upstream feed is stale (last automatic update 2024-10-18; gate re-checked
    /// 2026-07-16). Optional -- skipped if not supplied; fails closed if supplied
    /// but unreadable, malformed, or empty.
    #[arg(long)]
    digitalside: Option<PathBuf>,

    /// Curated exfiltration-endpoint / webhook-catcher hostname list. Plain
    /// domain-per-line blocklist; compiled into the signed primary DB under
    /// ThreatSource::ExfilEndpoint. Optional — skipped if not supplied.
    #[arg(long)]
    exfil_endpoints: Option<PathBuf>,

    /// Curated malicious file-hash companion feed. One record per line:
    /// `<sha256-hex>  tags=process_spawn,...  campaign=<id>  source=ossf|registry-yank`.
    /// Compiled into the v2 FileHash + BehaviorTags sections (so `check_file_sha256`
    /// goes live); ignored by a v1 build. Optional; skipped if not supplied.
    #[arg(long)]
    file_hashes: Option<PathBuf>,

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

    /// Output v1 .dat file path
    #[arg(long, default_value = "tirith-threatdb.dat")]
    output: PathBuf,

    /// Optional v2 .dat output path. When set, the compiler ALSO emits a v2 DB
    /// to this path: the same base package/network data PLUS artifact-SHA,
    /// file-SHA, and malicious-URL sections. The v1 `--output` is always written
    /// too, so CI can publish both formats.
    #[arg(long)]
    output_v2: Option<PathBuf>,

    /// Previously published, signed v1 database used for sequence and anti-drop
    /// comparison. This is independent of `--output`, whose immutable CI name is
    /// new on every run.
    #[arg(long)]
    baseline_v1: Option<PathBuf>,

    /// Previously published, signed v2 database used for section-aware anti-drop
    /// comparison.
    #[arg(long, requires = "output_v2")]
    baseline_v2: Option<PathBuf>,

    /// Optional signed multi-asset generation pointer. When dual output is
    /// requested it is published only after both immutable DB files are durable.
    /// Its schema is the client-compatible `threatdb-index-v2.json` format.
    #[arg(long, requires = "output_v2", requires = "generation_base_url")]
    generation_manifest: Option<PathBuf>,

    /// Base URL prepended to the immutable output filenames recorded in
    /// `--generation-manifest`.
    #[arg(long, requires = "generation_manifest")]
    generation_base_url: Option<String>,

    /// Run-scoped signed source-integrity sidecar. This preserves the existing
    /// schema-v2 generation payload byte-for-byte while separately binding the
    /// generation's DB hashes to audited source and compiler metadata.
    #[arg(
        long,
        requires = "output_v2",
        requires = "generation_manifest",
        requires = "compiler_metadata",
        requires = "source_provenance"
    )]
    source_integrity_manifest: Option<PathBuf>,

    /// Minimum Tirith version allowed to select the v2 asset in the signed
    /// generation manifest.
    #[arg(long, default_value = "0.3.4")]
    v2_min_tirith_version: String,
}

type FeedResult<T> = Result<T, String>;

// These are deliberately conservative floors, not estimates of the live feeds.
// They catch a missing/empty/truncated fetch while leaving ample room for normal
// upstream churn. Supplemental feeds remain optional, but an explicitly supplied
// supplemental feed must contribute at least one record.
const MIN_OSSF_PACKAGES: usize = 100;
const MIN_DATADOG_PACKAGES: usize = 100;
const MIN_FEODO_IPS: usize = 10;
const MIN_CISA_KEV_RECORDS: usize = 100;
const MIN_TYPOSQUAT_RECORDS: usize = 100;
const MAX_BASELINE_DROP_PERCENT: u64 = 50;
const MAX_OSV_VALUE_BYTES: usize = 256;
const MAX_BOUNDED_PACKAGE_REQUESTS: usize = 1_000;
const MAX_REGISTRY_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_REGISTRY_AGGREGATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_REGISTRY_VERSIONS_PER_PACKAGE: usize = 20_000;
const MAX_SOURCE_PROVENANCE_BYTES: usize = 1024 * 1024;

fn require_minimum(feed: &str, count: usize, minimum: usize) -> FeedResult<()> {
    if count < minimum {
        return Err(format!(
            "{feed} produced {count} records, below the fail-closed minimum of {minimum}"
        ));
    }
    Ok(())
}

fn feed_error<T>(feed: &str, path: &Path, result: FeedResult<T>) -> T {
    result.unwrap_or_else(|e| {
        eprintln!(
            "error: cannot compile explicitly-supplied {feed} feed {}: {e}",
            path.display()
        );
        std::process::exit(1);
    })
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

    /// Fetch the unique bounded OpenSSF package-version universes into one
    /// capped, content-hashed snapshot. Whole-package claims are excluded.
    FetchRegistrySnapshots {
        /// OpenSSF malicious-packages repo root.
        #[arg(long)]
        ossf: PathBuf,

        /// Exact checked-out OpenSSF commit recorded in provenance.
        #[arg(long)]
        ossf_commit: String,

        /// Destination JSON file.
        #[arg(long)]
        output: PathBuf,
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
    // This function feeds the legacy v1 publication as well as v2. Keep the
    // exact historical spellings here so v1-only readers continue to hash the
    // same keys; ThreatDbWriter canonicalizes a private working copy only when
    // it emits v2 (via `canonical_package_name`), which is the spelling the
    // current runtime hashes. pr173-0025's casing mismatch is closed by that
    // v2 canonicalization; the v1 spelling must not change.
    match eco {
        Ecosystem::PyPI => name.to_lowercase().replace(['_', '.'], "-"),
        Ecosystem::Npm => name.to_string(),
        _ => name.to_lowercase(),
    }
}

/// OSV JSON schema (subset used for malicious-packages).
///
/// OSV records are extensible, so every struct here uses `#[serde(default)]`
/// and tolerates unknown fields. The shapes below were derived from real
/// `MAL-*` records fetched from the OSV API (see the vendored fixtures in
/// `src/bin/fixtures` exercised by `test_parse_real_ossf_record_indicators`):
/// indicators live in the entry-level `database_specific.iocs` and
/// `database_specific.malicious-packages-origins`, NOT under
/// `affected[].database_specific`. The affected-level `database_specific`
/// carries provenance (`source` URL) and `cwes`.
#[derive(Debug, serde::Deserialize)]
struct OsvEntry {
    #[serde(default)]
    id: String,
    #[serde(default)]
    withdrawn: Option<String>,
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
struct OsvRange {
    #[serde(default, rename = "type")]
    range_type: String,
    #[serde(default)]
    events: Vec<OsvEvent>,
    #[serde(default, flatten)]
    extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct OsvEvent {
    #[serde(default)]
    introduced: Option<String>,
    #[serde(default)]
    fixed: Option<String>,
    #[serde(default)]
    last_affected: Option<String>,
    #[serde(default)]
    limit: Option<String>,
    #[serde(default, flatten)]
    extra: BTreeMap<String, serde_json::Value>,
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
/// Hostname/IPv4 IOCs are persisted through the base indexes shared by v1/v2;
/// artifact hashes and URLs are persisted through the v2-only sections. Keeping
/// one parsed model ensures diagnostics and round-trip expectations cover every
/// accepted indicator instead of silently counting data that is never emitted.
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
                // Only accept a real 64-char hex SHA-256: a malformed value would
                // poison the artifact-hash index DB-B builds from these indicators.
                if sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                    out.artifact_sha256.push(sha.to_ascii_lowercase());
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

    /// Fold another record's indicators into this aggregate for the shared
    /// network indexes and the v2-only indicator sections.
    fn extend(&mut self, other: OssfIndicators) {
        self.artifact_sha256.extend(other.artifact_sha256);
        self.ips.extend(other.ips);
        self.domains.extend(other.domains);
        self.urls.extend(other.urls);
    }
}

/// Decode a 64-char hex SHA-256 string into 32 bytes; `None` for anything that
/// is not exactly a 32-byte hex digest (so a malformed indicator is dropped, not
/// written as a bogus hash). Accepts upper or lower case.
fn decode_sha256_hex(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
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
        Some(other) => {
            // An OpenSSF type we do not recognize: surface it (the feed may have grown a
            // new value worth handling) rather than silently swallowing it. The type is
            // PRESENT, so the `MAL-` id promotion does NOT apply here - that is reserved
            // for TYPELESS records (the `None` arm below). Promoting a MAL- id with an
            // explicit-but-unrecognized type would break precedence and could turn a
            // future explicit LOWER-confidence type into Confirmed. An unrecognized
            // explicit type is the borderline default.
            eprintln!(
                "  warning: unrecognized OpenSSF database_specific type {other:?} for {id}, defaulting to Medium"
            );
            Confidence::Medium
        }
        None if id.starts_with("MAL-") => Confidence::Confirmed,
        None => Confidence::Medium, // No type and not a MAL- id: borderline default.
    }
}

#[derive(Debug, Default)]
struct OssfStats {
    total_entries: usize,
    parsed_packages: usize,
    direct_whole_package_claims: usize,
    bounded_intervals_materialized: usize,
    exact_versions_emitted: usize,
    unsupported_confirmed_shapes: usize,
    snapshot_failures: usize,
    skipped_withdrawn: usize,
    skipped_non_malicious: usize,
    skipped_unknown_ecosystem: usize,
    skipped_unreadable: usize,
    skipped_corrupt: usize,
    records_with_indicators: usize,
    total_indicators: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RegistryPackageKey {
    ecosystem: Ecosystem,
    name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeEndKind {
    Fixed,
    LastAffected,
    Limit,
}

#[derive(Debug, Clone)]
struct OsvInterval {
    introduced: String,
    end: Option<(RangeEndKind, String)>,
}

#[derive(Debug, Clone)]
enum RangeProjection {
    None,
    WholePackage,
    Bounded(Vec<OsvInterval>),
}

#[derive(Debug, Clone)]
struct PendingOssfClaim {
    key: RegistryPackageKey,
    explicit_versions: Vec<String>,
    intervals: Vec<OsvInterval>,
    confidence: Confidence,
    reference: Option<String>,
}

trait RegistryVersionProvider {
    fn versions_for(&mut self, key: &RegistryPackageKey) -> FeedResult<Vec<String>>;
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrySnapshotDocument {
    schema_version: u32,
    ossf_commit: String,
    retrieved_at: String,
    packages: Vec<RegistrySnapshotPackage>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrySnapshotPackage {
    ecosystem: String,
    name: String,
    source_url: String,
    response_sha256: String,
    response_bytes: usize,
    versions: Vec<String>,
}

#[derive(Debug)]
struct RegistrySnapshotStore {
    packages: BTreeMap<RegistryPackageKey, Vec<String>>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GitSourceProvenance {
    source_url: String,
    r#ref: String,
    commit: String,
    spdx: String,
    files: usize,
    bytes: usize,
    content_sha256: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RowSourceProvenance {
    source_url: String,
    r#ref: String,
    commit: String,
    spdx: String,
    files: usize,
    rows: usize,
    bytes: usize,
    content_sha256: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HashSourceProvenance {
    source_url: String,
    spdx: String,
    files: usize,
    bytes: usize,
    sha256: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalSourceProvenance {
    source_url: String,
    spdx: String,
    files: usize,
    bytes: usize,
    content_sha256: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrySourceProvenance {
    ossf_commit: String,
    retrieved_at: String,
    source_urls: Vec<String>,
    spdx: String,
    packages: usize,
    bytes: usize,
    sha256: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceProvenanceDocument {
    schema_version: u32,
    retrieved_at: String,
    compiler_version: String,
    ossf_malicious_packages: GitSourceProvenance,
    datadog_malicious_software_packages: GitSourceProvenance,
    ecosystems_typosquatting_dataset: RowSourceProvenance,
    registry_version_snapshot: RegistrySourceProvenance,
    feodo_tracker_ipblocklist: HashSourceProvenance,
    cisa_known_exploited_vulnerabilities: HashSourceProvenance,
    web3_package_anchors: LocalSourceProvenance,
}

#[derive(Debug, Clone)]
struct SourceTransactionBinding {
    provenance_sha256: String,
    registry_snapshot_sha256: String,
    ossf_commit: String,
    registry_retrieved_at: String,
    registry_packages: usize,
}

struct SourceInputPaths<'a> {
    ossf: &'a Path,
    datadog: &'a Path,
    typosquats: &'a Path,
    feodo: &'a Path,
    cisa_kev: &'a Path,
    web3_anchors: &'a Path,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CanonicalSourceSummary {
    files: usize,
    bytes: usize,
    content_sha256: String,
}

fn validate_lower_hex(value: &str, bytes: usize, label: &str) -> FeedResult<()> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || value.bytes().all(|byte| byte == b'0')
    {
        return Err(format!(
            "{label} must be a nonzero lowercase {}-hex digest",
            bytes * 2
        ));
    }
    Ok(())
}

fn validate_commit(value: &str, label: &str) -> FeedResult<()> {
    validate_lower_hex(value, 20, label)
}

fn validate_utc_timestamp(value: &str, label: &str) -> FeedResult<()> {
    let parsed = chrono::DateTime::parse_from_rfc3339(value)
        .map_err(|error| format!("{label} is not RFC3339: {error}"))?;
    if parsed.to_rfc3339_opts(chrono::SecondsFormat::Secs, true) != value {
        return Err(format!(
            "{label} must be canonical UTC whole-second RFC3339"
        ));
    }
    Ok(())
}

fn validate_git_source(
    source: &GitSourceProvenance,
    expected_url: &str,
    expected_spdx: &str,
    label: &str,
) -> FeedResult<()> {
    if source.source_url != expected_url || source.spdx != expected_spdx {
        return Err(format!("{label} source URL or SPDX metadata is unexpected"));
    }
    validate_commit(&source.r#ref, &format!("{label} ref"))?;
    validate_commit(&source.commit, &format!("{label} commit"))?;
    if source.r#ref != source.commit || source.files == 0 || source.bytes == 0 {
        return Err(format!("{label} revision/count metadata is inconsistent"));
    }
    validate_lower_hex(
        &source.content_sha256,
        32,
        &format!("{label} content SHA-256"),
    )?;
    Ok(())
}

fn canonical_source_summary(
    root: &Path,
    relative_paths: &[PathBuf],
) -> FeedResult<CanonicalSourceSummary> {
    if relative_paths.is_empty() {
        return Err("source summary has no files".to_string());
    }
    let mut paths = relative_paths.to_vec();
    paths.sort();
    paths.dedup();
    if paths.len() != relative_paths.len() {
        return Err("source summary contains duplicate paths".to_string());
    }
    let mut digest = Sha256::new();
    let mut total_bytes = 0usize;
    for relative in &paths {
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(format!(
                "source summary path {} is not a safe relative path",
                relative.display()
            ));
        }
        let normalized = relative
            .to_str()
            .ok_or_else(|| format!("source summary path {} is not UTF-8", relative.display()))?
            .replace('\\', "/");
        let path = root.join(relative);
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect source input {}: {error}", path.display()))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(format!(
                "source input {} is not a regular non-symlink file",
                path.display()
            ));
        }
        let bytes = std::fs::read(&path)
            .map_err(|error| format!("cannot read source input {}: {error}", path.display()))?;
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| "source byte count overflow".to_string())?;
        digest.update(normalized.as_bytes());
        digest.update([0]);
        digest.update(sha256_hex(&bytes).as_bytes());
        digest.update([0]);
    }
    Ok(CanonicalSourceSummary {
        files: paths.len(),
        bytes: total_bytes,
        content_sha256: format!("{:x}", digest.finalize()),
    })
}

fn collect_tree_source_paths(root: &Path, subtree: &str) -> FeedResult<Vec<PathBuf>> {
    let subtree_path = root.join(subtree);
    let mut paths = Vec::new();
    for entry in walkdir::WalkDir::new(&subtree_path).follow_links(false) {
        let entry = entry.map_err(|error| {
            format!(
                "cannot walk source subtree {}: {error}",
                subtree_path.display()
            )
        })?;
        if entry.file_type().is_symlink() {
            return Err(format!(
                "source subtree contains symlink {}",
                entry.path().display()
            ));
        }
        if entry.file_type().is_file() {
            paths.push(
                entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|_| "source tree path escaped its root".to_string())?
                    .to_path_buf(),
            );
        }
    }
    if paths.is_empty() {
        return Err(format!("source subtree {subtree} contains no files"));
    }
    Ok(paths)
}

fn verify_expected_summary(
    label: &str,
    actual: &CanonicalSourceSummary,
    files: usize,
    bytes: usize,
    content_sha256: &str,
) -> FeedResult<()> {
    if actual.files != files || actual.bytes != bytes || actual.content_sha256 != content_sha256 {
        return Err(format!(
            "{label} staged files changed after provenance: files={}/{files} bytes={}/{bytes} sha256={}/{}",
            actual.files, actual.bytes, actual.content_sha256, content_sha256
        ));
    }
    Ok(())
}

fn verify_git_checkout(root: &Path, expected_commit: &str, label: &str) -> FeedResult<()> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .map_err(|error| format!("cannot inspect {label} Git HEAD: {error}"))?;
    if !output.status.success() {
        return Err(format!("cannot resolve {label} Git HEAD"));
    }
    let head = std::str::from_utf8(&output.stdout)
        .map_err(|_| format!("{label} Git HEAD is not UTF-8"))?
        .trim();
    if head != expected_commit {
        return Err(format!(
            "{label} Git HEAD {head} does not match pinned {expected_commit}"
        ));
    }
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .map_err(|error| format!("cannot inspect {label} Git worktree: {error}"))?;
    if !status.status.success() || !status.stdout.is_empty() {
        return Err(format!(
            "{label} Git worktree has unrecorded tracked changes"
        ));
    }
    Ok(())
}

fn verify_source_contents(
    document: &SourceProvenanceDocument,
    inputs: &SourceInputPaths<'_>,
) -> FeedResult<()> {
    let ossf =
        canonical_source_summary(inputs.ossf, &collect_tree_source_paths(inputs.ossf, "osv")?)?;
    verify_expected_summary(
        "OpenSSF",
        &ossf,
        document.ossf_malicious_packages.files,
        document.ossf_malicious_packages.bytes,
        &document.ossf_malicious_packages.content_sha256,
    )?;
    let datadog_paths = [
        PathBuf::from("samples/npm/manifest.json"),
        PathBuf::from("samples/pypi/manifest.json"),
    ];
    let datadog = canonical_source_summary(inputs.datadog, &datadog_paths)?;
    verify_expected_summary(
        "Datadog",
        &datadog,
        document.datadog_malicious_software_packages.files,
        document.datadog_malicious_software_packages.bytes,
        &document.datadog_malicious_software_packages.content_sha256,
    )?;
    let typosquat_root = inputs
        .typosquats
        .parent()
        .ok_or_else(|| "typosquat CSV has no source root".to_string())?;
    let typosquat_name = inputs
        .typosquats
        .file_name()
        .ok_or_else(|| "typosquat CSV has no filename".to_string())?;
    let typosquats = canonical_source_summary(typosquat_root, &[PathBuf::from(typosquat_name)])?;
    verify_expected_summary(
        "typosquat",
        &typosquats,
        document.ecosystems_typosquatting_dataset.files,
        document.ecosystems_typosquatting_dataset.bytes,
        &document.ecosystems_typosquatting_dataset.content_sha256,
    )?;
    for (label, path, source) in [
        ("Feodo", inputs.feodo, &document.feodo_tracker_ipblocklist),
        (
            "CISA KEV",
            inputs.cisa_kev,
            &document.cisa_known_exploited_vulnerabilities,
        ),
    ] {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {label} source: {error}"))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(format!("{label} source is not a regular non-symlink file"));
        }
        let bytes =
            std::fs::read(path).map_err(|error| format!("cannot read {label} source: {error}"))?;
        if source.files != 1 || source.bytes != bytes.len() || source.sha256 != sha256_hex(&bytes) {
            return Err(format!("{label} staged file changed after provenance"));
        }
    }
    let anchor_root = inputs
        .web3_anchors
        .parent()
        .ok_or_else(|| "Web3 anchor file has no source root".to_string())?;
    let anchor_name = inputs
        .web3_anchors
        .file_name()
        .ok_or_else(|| "Web3 anchor file has no filename".to_string())?;
    let anchors = canonical_source_summary(anchor_root, &[PathBuf::from(anchor_name)])?;
    verify_expected_summary(
        "Web3 anchors",
        &anchors,
        document.web3_package_anchors.files,
        document.web3_package_anchors.bytes,
        &document.web3_package_anchors.content_sha256,
    )?;
    let embedded_anchor_sha = {
        let mut digest = Sha256::new();
        digest.update(b"web3_package_anchors.csv");
        digest.update([0]);
        digest.update(sha256_hex(WEB3_PACKAGE_ANCHORS_CSV.as_bytes()).as_bytes());
        digest.update([0]);
        format!("{:x}", digest.finalize())
    };
    if document.web3_package_anchors.bytes != WEB3_PACKAGE_ANCHORS_CSV.len()
        || document.web3_package_anchors.content_sha256 != embedded_anchor_sha
    {
        return Err(
            "Web3 anchor provenance does not match the compiler-embedded parsed input".to_string(),
        );
    }
    Ok(())
}

fn verify_source_inputs(
    document: &SourceProvenanceDocument,
    inputs: &SourceInputPaths<'_>,
) -> FeedResult<()> {
    verify_git_checkout(
        inputs.ossf,
        &document.ossf_malicious_packages.commit,
        "OpenSSF",
    )?;
    verify_git_checkout(
        inputs.datadog,
        &document.datadog_malicious_software_packages.commit,
        "Datadog",
    )?;
    verify_git_checkout(
        inputs
            .typosquats
            .parent()
            .ok_or_else(|| "typosquat CSV has no source root".to_string())?,
        &document.ecosystems_typosquatting_dataset.commit,
        "typosquat",
    )?;
    verify_source_contents(document, inputs)
}

impl SourceTransactionBinding {
    fn load(
        provenance_path: &Path,
        snapshot_path: &Path,
        inputs: &SourceInputPaths<'_>,
    ) -> FeedResult<Self> {
        Self::load_internal(provenance_path, snapshot_path, Some(inputs))
    }

    #[cfg(test)]
    fn load_provenance_only(provenance_path: &Path, snapshot_path: &Path) -> FeedResult<Self> {
        Self::load_internal(provenance_path, snapshot_path, None)
    }

    fn load_internal(
        provenance_path: &Path,
        snapshot_path: &Path,
        inputs: Option<&SourceInputPaths<'_>>,
    ) -> FeedResult<Self> {
        let provenance_bytes = std::fs::read(provenance_path).map_err(|error| {
            format!(
                "cannot read source provenance {}: {error}",
                provenance_path.display()
            )
        })?;
        if provenance_bytes.is_empty() || provenance_bytes.len() > MAX_SOURCE_PROVENANCE_BYTES {
            return Err("source provenance is empty or above its byte cap".to_string());
        }
        let document: SourceProvenanceDocument = serde_json::from_slice(&provenance_bytes)
            .map_err(|error| format!("invalid source provenance JSON: {error}"))?;
        if document.schema_version != 2 || document.compiler_version != env!("CARGO_PKG_VERSION") {
            return Err("source provenance schema or compiler version is unexpected".to_string());
        }
        if let Some(inputs) = inputs {
            verify_source_inputs(&document, inputs)?;
        }
        validate_utc_timestamp(&document.retrieved_at, "source retrieval time")?;
        let source_retrieved_at = chrono::DateTime::parse_from_rfc3339(&document.retrieved_at)
            .expect("timestamp validated above");
        validate_git_source(
            &document.ossf_malicious_packages,
            "https://github.com/ossf/malicious-packages.git",
            "CC-BY-4.0",
            "OpenSSF",
        )?;
        validate_git_source(
            &document.datadog_malicious_software_packages,
            "https://github.com/DataDog/malicious-software-packages-dataset.git",
            "Apache-2.0",
            "Datadog",
        )?;
        let typosquats = &document.ecosystems_typosquatting_dataset;
        if typosquats.source_url != "https://github.com/ecosyste-ms/typosquatting-dataset.git"
            || typosquats.spdx != "CC0-1.0"
            || typosquats.files != 1
            || typosquats.rows == 0
            || typosquats.bytes == 0
        {
            return Err("typosquat source/count metadata is inconsistent".to_string());
        }
        validate_commit(&typosquats.r#ref, "typosquat ref")?;
        validate_commit(&typosquats.commit, "typosquat commit")?;
        if typosquats.r#ref != typosquats.commit {
            return Err("typosquat ref/commit metadata disagrees".to_string());
        }
        validate_lower_hex(&typosquats.content_sha256, 32, "typosquat content SHA-256")?;
        for (source, expected_url, expected_spdx, label) in [
            (
                &document.feodo_tracker_ipblocklist,
                "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                "LicenseRef-abuse-ch-terms",
                "Feodo",
            ),
            (
                &document.cisa_known_exploited_vulnerabilities,
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "LicenseRef-US-Government-Work",
                "CISA KEV",
            ),
        ] {
            if source.source_url != expected_url
                || source.spdx != expected_spdx
                || source.files != 1
                || source.bytes == 0
            {
                return Err(format!("{label} source/count metadata is inconsistent"));
            }
            validate_lower_hex(&source.sha256, 32, &format!("{label} SHA-256"))?;
        }
        let anchors = &document.web3_package_anchors;
        if anchors.source_url != "repository:crates/tirith/assets/data/web3_package_anchors.csv"
            || anchors.spdx != "LicenseRef-Package-Name-Facts"
            || anchors.files != 1
            || anchors.bytes == 0
        {
            return Err("Web3 anchor source/count metadata is inconsistent".to_string());
        }
        validate_lower_hex(&anchors.content_sha256, 32, "Web3 anchor content SHA-256")?;
        let registry = &document.registry_version_snapshot;
        validate_commit(&registry.ossf_commit, "registry snapshot OpenSSF commit")?;
        validate_utc_timestamp(&registry.retrieved_at, "registry snapshot retrieval time")?;
        let registry_retrieved_at = chrono::DateTime::parse_from_rfc3339(&registry.retrieved_at)
            .expect("timestamp validated above");
        if registry.ossf_commit != document.ossf_malicious_packages.commit
            || registry_retrieved_at > source_retrieved_at
            || source_retrieved_at - registry_retrieved_at > chrono::Duration::hours(1)
            || registry.source_urls
                != [
                    "https://registry.npmjs.org/".to_string(),
                    "https://pypi.org/pypi/".to_string(),
                ]
            || registry.spdx != "LicenseRef-Registry-Metadata"
            || registry.packages > MAX_BOUNDED_PACKAGE_REQUESTS
            || registry.bytes == 0
            || registry.bytes > MAX_REGISTRY_AGGREGATE_BYTES
        {
            return Err("registry snapshot provenance metadata is inconsistent".to_string());
        }
        validate_lower_hex(&registry.sha256, 32, "registry snapshot SHA-256")?;

        let snapshot_bytes = std::fs::read(snapshot_path).map_err(|error| {
            format!(
                "cannot read registry snapshot {}: {error}",
                snapshot_path.display()
            )
        })?;
        let actual_snapshot_sha256 = sha256_hex(&snapshot_bytes);
        if registry.bytes != snapshot_bytes.len() || registry.sha256 != actual_snapshot_sha256 {
            return Err(
                "registry snapshot bytes/digest do not match source provenance".to_string(),
            );
        }
        Ok(Self {
            provenance_sha256: sha256_hex(&provenance_bytes),
            registry_snapshot_sha256: actual_snapshot_sha256,
            ossf_commit: registry.ossf_commit.clone(),
            registry_retrieved_at: registry.retrieved_at.clone(),
            registry_packages: registry.packages,
        })
    }

    fn verify_inputs_unchanged(
        &self,
        provenance_path: &Path,
        inputs: &SourceInputPaths<'_>,
    ) -> FeedResult<()> {
        let bytes = std::fs::read(provenance_path).map_err(|error| {
            format!(
                "cannot reread source provenance {}: {error}",
                provenance_path.display()
            )
        })?;
        if sha256_hex(&bytes) != self.provenance_sha256 {
            return Err("source provenance changed during compilation".to_string());
        }
        let document: SourceProvenanceDocument = serde_json::from_slice(&bytes)
            .map_err(|error| format!("cannot reparse source provenance: {error}"))?;
        verify_source_inputs(&document, inputs)
    }
}

impl RegistrySnapshotStore {
    fn load(path: &Path, binding: &SourceTransactionBinding) -> FeedResult<Self> {
        let bytes = std::fs::read(path).map_err(|error| {
            format!("cannot read registry snapshot {}: {error}", path.display())
        })?;
        if bytes.len() > MAX_REGISTRY_AGGREGATE_BYTES {
            return Err(format!(
                "registry snapshot is {} bytes, above the {} byte aggregate cap",
                bytes.len(),
                MAX_REGISTRY_AGGREGATE_BYTES
            ));
        }
        if sha256_hex(&bytes) != binding.registry_snapshot_sha256 {
            return Err("registry snapshot digest changed after provenance validation".to_string());
        }
        let document: RegistrySnapshotDocument = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid registry snapshot JSON: {error}"))?;
        if document.schema_version != 1 {
            return Err(format!(
                "unsupported registry snapshot schema {}",
                document.schema_version
            ));
        }
        if document.ossf_commit != binding.ossf_commit {
            return Err(format!(
                "registry snapshot OpenSSF commit {} does not match expected {}",
                document.ossf_commit, binding.ossf_commit
            ));
        }
        if document.retrieved_at != binding.registry_retrieved_at {
            return Err("registry snapshot retrieval time does not match provenance".to_string());
        }
        validate_utc_timestamp(&document.retrieved_at, "registry snapshot retrieval time")?;
        if document.packages.len() > MAX_BOUNDED_PACKAGE_REQUESTS {
            return Err("registry snapshot exceeds bounded-package cap".to_string());
        }
        if document.packages.len() != binding.registry_packages {
            return Err("registry snapshot package count does not match provenance".to_string());
        }
        let mut packages = BTreeMap::new();
        for package in document.packages {
            let ecosystem = Ecosystem::from_name(&package.ecosystem).ok_or_else(|| {
                format!(
                    "registry snapshot has unsupported ecosystem {:?}",
                    package.ecosystem
                )
            })?;
            let key = RegistryPackageKey {
                ecosystem,
                name: canonical_package_name(ecosystem, &package.name),
            };
            if key.name != package.name {
                return Err(format!(
                    "registry snapshot package name {:?} is not canonical",
                    package.name
                ));
            }
            let expected_url = registry_metadata_url(&key)?;
            if package.source_url != expected_url.as_str() {
                return Err(format!(
                    "registry snapshot entry for {} has unexpected source URL",
                    key.name
                ));
            }
            validate_lower_hex(
                &package.response_sha256,
                32,
                &format!("registry response SHA-256 for {}", key.name),
            )?;
            if package.response_bytes > MAX_REGISTRY_RESPONSE_BYTES
                || package.response_bytes == 0
                || package.versions.is_empty()
                || package.versions.len() > MAX_REGISTRY_VERSIONS_PER_PACKAGE
            {
                return Err(format!(
                    "registry snapshot entry for {} is outside caps",
                    key.name
                ));
            }
            let versions = package.versions;
            for version in &versions {
                validate_osv_value(version, "registry version")?;
            }
            if versions.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(format!(
                    "registry snapshot versions for {} are not strictly sorted and unique",
                    key.name
                ));
            }
            if packages.insert(key.clone(), versions).is_some() {
                return Err(format!(
                    "duplicate registry snapshot entry for {}",
                    key.name
                ));
            }
        }
        Ok(Self { packages })
    }

    fn ensure_fully_consumed(&self) -> FeedResult<()> {
        if self.packages.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "registry snapshot contains {} unrequested package entries",
                self.packages.len()
            ))
        }
    }
}

impl RegistryVersionProvider for RegistrySnapshotStore {
    fn versions_for(&mut self, key: &RegistryPackageKey) -> FeedResult<Vec<String>> {
        self.packages.remove(key).ok_or_else(|| {
            format!(
                "registry snapshot is missing {}:{}",
                key.ecosystem, key.name
            )
        })
    }
}

fn validate_osv_value(value: &str, label: &str) -> FeedResult<()> {
    if value.is_empty() || value.len() > MAX_OSV_VALUE_BYTES || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{label} is empty, overlong, or contains control bytes"
        ));
    }
    Ok(())
}

fn parse_range_projection(
    ranges: &[OsvRange],
    ecosystem: Ecosystem,
    path: &Path,
) -> FeedResult<RangeProjection> {
    if ranges.is_empty() {
        return Ok(RangeProjection::None);
    }
    let mut intervals = Vec::new();
    for range in ranges {
        if !range.extra.is_empty() {
            return Err(format!(
                "{} has unsupported OSV range fields {:?}",
                path.display(),
                range.extra.keys().collect::<Vec<_>>()
            ));
        }
        if range.range_type != "ECOSYSTEM" {
            return Err(format!(
                "{} uses unsupported confirmed OSV range type {:?}",
                path.display(),
                range.range_type
            ));
        }
        if range.events.is_empty() {
            return Err(format!(
                "{} has an OSV range without events",
                path.display()
            ));
        }
        let mut open: Option<String> = None;
        for event in &range.events {
            if !event.extra.is_empty() {
                return Err(format!(
                    "{} has unsupported OSV event fields {:?}",
                    path.display(),
                    event.extra.keys().collect::<Vec<_>>()
                ));
            }
            let key_count = [
                event.introduced.is_some(),
                event.fixed.is_some(),
                event.last_affected.is_some(),
                event.limit.is_some(),
            ]
            .into_iter()
            .filter(|present| *present)
            .count();
            if key_count != 1 {
                return Err(format!(
                    "{} has an OSV event with {key_count} recognized keys; expected exactly one",
                    path.display()
                ));
            }
            if let Some(introduced) = &event.introduced {
                validate_osv_value(introduced, "introduced boundary")?;
                if open.replace(introduced.clone()).is_some() {
                    return Err(format!(
                        "{} opens an OSV interval before closing the previous interval",
                        path.display()
                    ));
                }
                continue;
            }
            let (kind, close): (RangeEndKind, &str) = if let Some(value) = &event.fixed {
                (RangeEndKind::Fixed, value.as_str())
            } else if let Some(value) = &event.last_affected {
                (RangeEndKind::LastAffected, value.as_str())
            } else {
                (
                    RangeEndKind::Limit,
                    event.limit.as_deref().unwrap_or_default(),
                )
            };
            validate_osv_value(close, "range closing boundary")?;
            let introduced = open.take().ok_or_else(|| {
                format!(
                    "{} closes an OSV interval before introducing it",
                    path.display()
                )
            })?;
            intervals.push(OsvInterval {
                introduced,
                end: Some((kind, close.to_string())),
            });
        }
        if let Some(introduced) = open {
            if introduced != "0" {
                return Err(format!(
                    "{} has an unrepresentable non-zero open-ended confirmed interval",
                    path.display()
                ));
            }
            intervals.push(OsvInterval {
                introduced,
                end: None,
            });
        }
    }
    // A package-wide interval changes only the aggregate projection. It must
    // not let malformed sibling intervals escape validation, because that
    // would turn contradictory confirmed source data into a broader claim.
    for interval in &intervals {
        validate_interval_order(ecosystem, interval)?;
    }
    if intervals
        .iter()
        .any(|interval| interval.introduced == "0" && interval.end.is_none())
    {
        return Ok(RangeProjection::WholePackage);
    }
    if intervals.is_empty() {
        return Err(format!("{} produced no OSV intervals", path.display()));
    }
    Ok(RangeProjection::Bounded(intervals))
}

fn collect_ossf(
    root: &Path,
) -> FeedResult<(
    Vec<PackageEntry>,
    Vec<PendingOssfClaim>,
    OssfStats,
    OssfIndicators,
)> {
    let metadata = std::fs::metadata(root)
        .map_err(|e| format!("cannot inspect root {}: {e}", root.display()))?;
    if !metadata.is_dir() {
        return Err(format!("root {} is not a directory", root.display()));
    }

    let mut entries = Vec::new();
    let mut pending = Vec::new();
    let mut all_indicators = OssfIndicators::default();
    let mut stats = OssfStats::default();
    let mut paths = Vec::new();
    for entry in walkdir::WalkDir::new(root) {
        let entry = entry.map_err(|e| format!("root traversal failed: {e}"))?;
        if entry.path().extension().is_some_and(|ext| ext == "json")
            && entry.file_type().is_file()
            && entry
                .path()
                .file_stem()
                .is_some_and(|stem| stem.to_string_lossy().starts_with("MAL-"))
        {
            paths.push(entry.into_path());
        }
    }
    paths.sort();

    for path in paths {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let osv: OsvEntry = serde_json::from_str(&content)
            .map_err(|e| format!("cannot parse {} as OSV JSON: {e}", path.display()))?;
        if osv.id.trim().is_empty() || !osv.id.starts_with("MAL-") {
            return Err(format!("{} is not an OpenSSF MAL record", path.display()));
        }
        stats.total_entries += 1;
        if let Some(withdrawn) = osv.withdrawn.as_deref() {
            if withdrawn.trim().is_empty() {
                return Err(format!("{} has an empty withdrawn value", path.display()));
            }
            stats.skipped_withdrawn += 1;
            continue;
        }
        if osv.affected.is_empty() {
            return Err(format!(
                "{} has no affected package records",
                path.display()
            ));
        }

        let entry_type = osv
            .database_specific
            .as_ref()
            .and_then(|d| d.entry_type.as_deref());
        if entry_type.is_some_and(|value| !matches!(value, "MALWARE" | "POTENTIALLY_UNWANTED")) {
            return Err(format!(
                "{} has unsupported database_specific.type {:?}",
                path.display(),
                entry_type
            ));
        }
        let confidence = ossf_confidence(&osv.id, entry_type);
        if confidence != Confidence::Confirmed {
            stats.skipped_non_malicious += 1;
            continue;
        }

        let indicators = OssfIndicators::from_database_specific(osv.database_specific.as_ref());
        if !indicators.is_empty() {
            stats.records_with_indicators += 1;
            stats.total_indicators += indicators.len();
            all_indicators.extend(indicators);
        }
        let reference = osv.references.first().map(|record| record.url.clone());

        for affected in &osv.affected {
            let package = affected.package.as_ref().ok_or_else(|| {
                format!(
                    "{} has an affected record without a package",
                    path.display()
                )
            })?;
            if package.ecosystem.trim().is_empty() || package.name.trim().is_empty() {
                return Err(format!(
                    "{} has an affected package with an empty ecosystem or name",
                    path.display()
                ));
            }
            let Some(ecosystem) = Ecosystem::from_name(&package.ecosystem) else {
                return Err(format!(
                    "unsupported_confirmed_shapes=1: {} has unsupported confirmed ecosystem {:?}",
                    path.display(),
                    package.ecosystem
                ));
            };
            let key = RegistryPackageKey {
                ecosystem,
                name: canonical_package_name(ecosystem, &package.name),
            };
            let mut explicit_versions = affected.versions.clone();
            for version in &explicit_versions {
                validate_osv_value(version, "explicit affected version")?;
            }
            explicit_versions.sort();
            explicit_versions.dedup();

            let projection = parse_range_projection(&affected.ranges, ecosystem, &path)
                .map_err(|error| format!("unsupported_confirmed_shapes=1: {error}"))?;
            match projection {
                RangeProjection::WholePackage => {
                    stats.direct_whole_package_claims += 1;
                    stats.exact_versions_emitted += explicit_versions.len();
                    entries.push(PackageEntry {
                        ecosystem,
                        name: key.name,
                        affected_versions: explicit_versions,
                        all_versions_malicious: true,
                        source: ThreatSource::OssfMalicious,
                        confidence,
                        reference: reference.clone(),
                    });
                }
                RangeProjection::Bounded(intervals) => pending.push(PendingOssfClaim {
                    key,
                    explicit_versions,
                    intervals,
                    confidence,
                    reference: reference.clone(),
                }),
                RangeProjection::None if !explicit_versions.is_empty() => {
                    stats.exact_versions_emitted += explicit_versions.len();
                    entries.push(PackageEntry {
                        ecosystem,
                        name: key.name,
                        affected_versions: explicit_versions,
                        all_versions_malicious: false,
                        source: ThreatSource::OssfMalicious,
                        confidence,
                        reference: reference.clone(),
                    });
                }
                RangeProjection::None => {
                    // A confirmed MAL record with neither versions nor ranges is
                    // itself a direct package-wide claim, preserving r3's safe
                    // no-version behavior without conflating bounded ranges.
                    stats.direct_whole_package_claims += 1;
                    entries.push(PackageEntry {
                        ecosystem,
                        name: key.name,
                        affected_versions: Vec::new(),
                        all_versions_malicious: true,
                        source: ThreatSource::OssfMalicious,
                        confidence,
                        reference: reference.clone(),
                    });
                }
            }
        }
    }
    if stats.total_entries == 0 {
        return Err(format!(
            "root {} contains no MAL JSON records",
            root.display()
        ));
    }
    Ok((entries, pending, stats, all_indicators))
}

fn compare_versions(ecosystem: Ecosystem, left: &str, right: &str) -> FeedResult<Ordering> {
    match ecosystem {
        Ecosystem::Npm => tirith_core::version_intent::compare_semver_public_versions(left, right)
            .ok_or_else(|| format!("unsupported npm version boundary {left:?} or {right:?}")),
        Ecosystem::PyPI => tirith_core::version_intent::compare_pep440_public_versions(left, right)
            .ok_or_else(|| format!("unsupported PyPI version boundary {left:?} or {right:?}")),
        other => Err(format!(
            "bounded OpenSSF ranges for {other} are not safely representable by the current pinned comparator"
        )),
    }
}

fn interval_contains(
    ecosystem: Ecosystem,
    interval: &OsvInterval,
    version: &str,
) -> FeedResult<bool> {
    let after_start = interval.introduced == "0"
        || compare_versions(ecosystem, version, &interval.introduced)? != Ordering::Less;
    if !after_start {
        return Ok(false);
    }
    let Some((kind, end)) = &interval.end else {
        return Err("non-zero open interval reached materialization".to_string());
    };
    let ordering = compare_versions(ecosystem, version, end)?;
    Ok(match kind {
        RangeEndKind::Fixed | RangeEndKind::Limit => ordering == Ordering::Less,
        RangeEndKind::LastAffected => ordering != Ordering::Greater,
    })
}

fn validate_interval_order(ecosystem: Ecosystem, interval: &OsvInterval) -> FeedResult<()> {
    if interval.introduced == "0" {
        if let Some((_, end)) = &interval.end {
            // `0` is OSV's unbounded-start sentinel rather than an ecosystem
            // version, but a bounded close is still a concrete version and
            // must parse even when another interval makes the aggregate claim
            // package-wide.
            compare_versions(ecosystem, end, end)?;
        }
        return Ok(());
    }
    let Some((kind, end)) = &interval.end else {
        return Err("non-zero open interval is unrepresentable".to_string());
    };
    let ordering = compare_versions(ecosystem, &interval.introduced, end)?;
    let valid = match kind {
        RangeEndKind::Fixed | RangeEndKind::Limit => ordering == Ordering::Less,
        RangeEndKind::LastAffected => ordering != Ordering::Greater,
    };
    if !valid {
        return Err(format!(
            "contradictory affected interval {} .. {:?} {}",
            interval.introduced, kind, end
        ));
    }
    Ok(())
}

fn parse_ossf_with_provider(
    root: &Path,
    mut provider: Option<&mut dyn RegistryVersionProvider>,
) -> FeedResult<(Vec<PackageEntry>, OssfStats, OssfIndicators)> {
    let (mut entries, pending, mut stats, indicators) = collect_ossf(root)?;
    let request_set: BTreeSet<RegistryPackageKey> =
        pending.iter().map(|claim| claim.key.clone()).collect();
    if request_set.len() > MAX_BOUNDED_PACKAGE_REQUESTS {
        return Err(format!(
            "{} unique bounded packages exceed the request cap of {}",
            request_set.len(),
            MAX_BOUNDED_PACKAGE_REQUESTS
        ));
    }
    let mut universes = BTreeMap::new();
    for key in request_set {
        let result = provider
            .as_deref_mut()
            .ok_or_else(|| {
                format!(
                    "bounded OpenSSF claim for {}:{} requires --registry-snapshots",
                    key.ecosystem, key.name
                )
            })?
            .versions_for(&key);
        match result {
            Ok(versions) => {
                universes.insert(key, versions);
            }
            Err(error) => {
                return Err(format!("snapshot_failures=1: {error}"));
            }
        }
    }

    for claim in pending {
        let versions = universes.get(&claim.key).ok_or_else(|| {
            format!(
                "registry snapshot missing materialization key {}",
                claim.key.name
            )
        })?;
        let mut affected = claim.explicit_versions;
        for interval in &claim.intervals {
            validate_interval_order(claim.key.ecosystem, interval)?;
            let mut interval_matches = 0usize;
            for version in versions {
                if interval_contains(claim.key.ecosystem, interval, version)? {
                    affected.push(version.clone());
                    interval_matches += 1;
                }
            }
            if interval_matches == 0 {
                return Err(format!(
                    "bounded interval for {}:{} materialized to no registry versions",
                    claim.key.ecosystem, claim.key.name
                ));
            }
        }
        affected.sort();
        affected.dedup();
        if affected.is_empty() {
            return Err(format!(
                "bounded confirmed claim for {}:{} materialized to no versions",
                claim.key.ecosystem, claim.key.name
            ));
        }
        stats.bounded_intervals_materialized += claim.intervals.len();
        stats.exact_versions_emitted += affected.len();
        entries.push(PackageEntry {
            ecosystem: claim.key.ecosystem,
            name: claim.key.name,
            affected_versions: affected,
            all_versions_malicious: false,
            source: ThreatSource::OssfMalicious,
            confidence: claim.confidence,
            reference: claim.reference,
        });
    }
    stats.parsed_packages = entries.len();
    if entries.is_empty() {
        return Err(format!(
            "root {} produced no active package records",
            root.display()
        ));
    }
    Ok((entries, stats, indicators))
}

#[cfg(test)]
fn parse_ossf(root: &Path) -> FeedResult<(Vec<PackageEntry>, OssfStats, OssfIndicators)> {
    parse_ossf_with_provider(root, None)
}

/// Parse only Datadog's documented path-derived manifests. `null` is an
/// explicitly malicious-intent package (all versions); a non-empty array is the
/// exact compromised-version set. Every other value, including an empty array,
/// is a publication error.
struct StrictJsonObject(BTreeMap<String, serde_json::Value>);

impl<'de> serde::Deserialize<'de> for StrictJsonObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ObjectVisitor;

        impl<'de> serde::de::Visitor<'de> for ObjectVisitor {
            type Value = StrictJsonObject;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object with unique package keys")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                    if values.insert(key.clone(), value).is_some() {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate package key {key:?}"
                        )));
                    }
                }
                Ok(StrictJsonObject(values))
            }
        }

        deserializer.deserialize_map(ObjectVisitor)
    }
}

fn parse_datadog(root: &Path) -> FeedResult<(Vec<PackageEntry>, usize, usize)> {
    let metadata = std::fs::metadata(root)
        .map_err(|e| format!("cannot inspect root {}: {e}", root.display()))?;
    if !metadata.is_dir() {
        return Err(format!("root {} is not a directory", root.display()));
    }

    let manifests = [
        (Ecosystem::Npm, root.join("samples/npm/manifest.json")),
        (Ecosystem::PyPI, root.join("samples/pypi/manifest.json")),
    ];
    let mut by_key: BTreeMap<PackageKey, PackageEntry> = BTreeMap::new();
    for (ecosystem, path) in &manifests {
        let bytes = std::fs::read(path).map_err(|error| {
            format!(
                "cannot read exact Datadog manifest {}: {error}",
                path.display()
            )
        })?;
        let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
        let object = <StrictJsonObject as serde::Deserialize>::deserialize(&mut deserializer)
            .and_then(|object| {
                deserializer.end()?;
                Ok(object.0)
            })
            .map_err(|error| format!("invalid Datadog manifest {}: {error}", path.display()))?;
        if object.is_empty() {
            return Err(format!("Datadog manifest {} is empty", path.display()));
        }
        let mut raw_names = object.keys().collect::<Vec<_>>();
        raw_names.sort();
        for raw_name in raw_names {
            if raw_name.trim().is_empty() || raw_name.len() > MAX_OSV_VALUE_BYTES {
                return Err(format!(
                    "{} contains an invalid package key",
                    path.display()
                ));
            }
            let canonical = canonical_package_name(*ecosystem, raw_name);
            if canonical.is_empty() {
                return Err(format!(
                    "{} contains an empty canonical package key",
                    path.display()
                ));
            }
            let (mut versions, all_versions_malicious) = match &object[raw_name] {
                serde_json::Value::Null => (Vec::new(), true),
                serde_json::Value::Array(values) if !values.is_empty() => {
                    let mut versions = Vec::with_capacity(values.len());
                    for value in values {
                        let version = value.as_str().ok_or_else(|| {
                            format!("{} has a non-string version for {raw_name}", path.display())
                        })?;
                        validate_osv_value(version, "Datadog version")?;
                        versions.push(version.to_string());
                    }
                    versions.sort();
                    versions.dedup();
                    (versions, false)
                }
                serde_json::Value::Array(_) => {
                    return Err(format!(
                        "{} has an empty version array for {raw_name}",
                        path.display()
                    ))
                }
                _ => {
                    return Err(format!(
                        "{} has an undocumented value shape for {raw_name}",
                        path.display()
                    ))
                }
            };
            versions.sort();
            let key = PackageKey {
                ecosystem: *ecosystem,
                name: canonical.clone(),
            };
            let package = PackageEntry {
                ecosystem: *ecosystem,
                name: canonical,
                affected_versions: versions,
                all_versions_malicious,
                source: ThreatSource::DatadogMalicious,
                confidence: Confidence::Confirmed,
                reference: Some(
                    "https://github.com/DataDog/malicious-software-packages-dataset".to_string(),
                ),
            };
            if let Some(existing) = by_key.get(&key) {
                if existing.all_versions_malicious != package.all_versions_malicious
                    || existing.affected_versions != package.affected_versions
                {
                    return Err(format!(
                        "{} has conflicting entries for canonical package {}",
                        path.display(),
                        key.name
                    ));
                }
            } else {
                by_key.insert(key, package);
            }
        }
    }
    if by_key.is_empty() {
        return Err(format!(
            "root {} produced no Datadog records",
            root.display()
        ));
    }
    Ok((by_key.into_values().collect(), 0, manifests.len()))
}

fn parse_feodo(path: &Path) -> FeedResult<Vec<Ipv4Addr>> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;

    let reader = BufReader::new(file);
    let mut ips = Vec::new();

    for (line_index, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("cannot read line {}: {e}", line_index + 1))?;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Take the first whitespace-delimited token as the IP.
        let ip_str = trimmed.split_whitespace().next().unwrap_or("");
        let ip = ip_str.parse::<Ipv4Addr>().map_err(|e| {
            format!(
                "invalid IPv4 address on line {} ({ip_str:?}): {e}",
                line_index + 1
            )
        })?;
        ips.push(ip);
    }

    ips.sort();
    ips.dedup();
    if ips.is_empty() {
        return Err("feed contains no IPv4 records".to_string());
    }
    Ok(ips)
}

fn parse_cisa_kev(path: &Path) -> FeedResult<Vec<KevVulnerability>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let catalog: KevCatalog =
        serde_json::from_str(&content).map_err(|e| format!("cannot parse CISA KEV JSON: {e}"))?;
    if catalog.vulnerabilities.is_empty() {
        return Err("catalog contains no vulnerabilities".to_string());
    }
    let mut unique = BTreeMap::new();
    for (index, mut entry) in catalog.vulnerabilities.into_iter().enumerate() {
        let canonical = canonical_cve_id(&entry.cve_id).ok_or_else(|| {
            format!(
                "catalog vulnerability {} has an invalid cveID {:?}",
                index + 1,
                entry.cve_id
            )
        })?;
        entry.cve_id = canonical.clone();
        unique.entry(canonical).or_insert(entry);
    }
    if unique.is_empty() {
        return Err("catalog contains no unique CVE records".to_string());
    }
    Ok(unique.into_values().collect())
}

// Phase B feed parsers.

fn parse_urlhaus_file(path: &Path) -> FeedResult<Vec<String>> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut validator = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(bytes.as_slice());
    let headers = validator
        .headers()
        .map_err(|e| format!("invalid URLhaus CSV headers: {e}"))?
        .clone();
    if !headers
        .iter()
        .any(|header| matches!(header, "url" | "urlhaus_link"))
    {
        return Err("URLhaus CSV has no url or urlhaus_link column".to_string());
    }
    for (index, record) in validator.records().enumerate() {
        record.map_err(|e| format!("invalid URLhaus CSV record {}: {e}", index + 2))?;
    }
    let entries =
        parse_urlhaus_csv(bytes.as_slice()).map_err(|e| format!("invalid URLhaus CSV: {e}"))?;
    if entries.hostnames.is_empty() {
        return Err("URLhaus CSV contains no valid hostnames".to_string());
    }
    Ok(entries.hostnames)
}

fn parse_threatfox_file(path: &Path) -> FeedResult<(Vec<String>, Vec<Ipv4Addr>)> {
    const MAX_DECOMPRESSED: u64 = 512 * 1024 * 1024;
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes.as_slice()))
        .map_err(|e| format!("invalid ThreatFox ZIP: {e}"))?;
    let mut found_csv = false;
    for index in 0..archive.len() {
        let mut member = archive
            .by_index(index)
            .map_err(|e| format!("cannot read ThreatFox ZIP member {index}: {e}"))?;
        if !member.name().ends_with(".csv") {
            continue;
        }
        found_csv = true;
        let mut csv_bytes = Vec::new();
        member
            .by_ref()
            .take(MAX_DECOMPRESSED + 1)
            .read_to_end(&mut csv_bytes)
            .map_err(|e| format!("cannot extract ThreatFox CSV: {e}"))?;
        if csv_bytes.len() as u64 > MAX_DECOMPRESSED {
            return Err("ThreatFox CSV exceeds 512 MiB decompressed limit".to_string());
        }
        let mut validator = csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .from_reader(csv_bytes.as_slice());
        let headers = validator
            .headers()
            .map_err(|e| format!("invalid ThreatFox CSV headers: {e}"))?
            .clone();
        if !headers.iter().any(|header| header == "ioc") {
            return Err("ThreatFox CSV has no ioc column".to_string());
        }
        for (record_index, record) in validator.records().enumerate() {
            record
                .map_err(|e| format!("invalid ThreatFox CSV record {}: {e}", record_index + 2))?;
        }
        break;
    }
    if !found_csv {
        return Err("ThreatFox ZIP did not contain a CSV payload".to_string());
    }
    drop(archive);
    let entries = parse_threatfox_zip(std::io::Cursor::new(bytes))
        .map_err(|e| format!("invalid ThreatFox ZIP: {e}"))?;
    if entries.hostnames.is_empty() && entries.ips.is_empty() {
        return Err("ThreatFox feed contains no valid indicators".to_string());
    }
    Ok((entries.hostnames, entries.ips))
}

fn validate_domain_list_lines(contents: &str) -> FeedResult<()> {
    for (line_index, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parsed = parse_domain_blocklist(trimmed);
        // localhost and loopback lines are intentionally excluded by the core
        // parser and remain legitimate controls rather than structural errors.
        let is_explicitly_ignored = trimmed
            .split_whitespace()
            .take_while(|token| !token.starts_with('#'))
            .last()
            .is_some_and(|token| {
                token.eq_ignore_ascii_case("localhost") || token.starts_with("127.")
            });
        if parsed.hostnames.is_empty() && !is_explicitly_ignored {
            return Err(format!(
                "invalid domain-list record on line {}: {trimmed:?}",
                line_index + 1
            ));
        }
    }
    Ok(())
}

fn parse_blocklist_file(path: &Path) -> FeedResult<Vec<String>> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    validate_domain_list_lines(&contents)?;
    let entries = parse_domain_blocklist(&contents).hostnames;
    if entries.is_empty() {
        return Err("blocklist contains no valid hostnames".to_string());
    }
    Ok(entries)
}

/// Parse the explicit exfil-endpoint feed. FALLIBLE on purpose: `--exfil-endpoints
/// <path>` means the operator INTENDED that primary feed, so an unreadable path
/// must NOT silently degrade to zero endpoints (which would let CI publish a
/// weakened, signed threat DB after a transient path/permission failure). The read
/// error is propagated so the call site can exit non-zero. Contrast: a feed that is
/// simply not supplied stays a no-op (the call site skips this entirely).
fn parse_exfil_endpoints_file(path: &Path) -> FeedResult<Vec<String>> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    validate_domain_list_lines(&contents)?;
    let entries = parse_exfil_endpoint_list(&contents).hostnames;
    if entries.is_empty() {
        return Err("exfil-endpoint list contains no valid hostnames".to_string());
    }
    Ok(entries)
}

/// Read and parse the curated malicious file-hash companion feed. Fail-closed for
/// the same reason as [`parse_exfil_endpoints_file`]: `--file-hashes <path>` means
/// the operator INTENDED that feed, so an unreadable path must abort the build
/// rather than silently sign a DB with an empty FileHash section. A feed that is
/// simply not supplied stays a no-op (the call site skips this entirely). Per-line
/// malformed records (bad digest / unknown tag) are fatal for an explicitly
/// supplied feed, because silently dropping them would weaken a signed output.
fn parse_curated_file_hashes_file(path: &Path) -> FeedResult<CuratedFileHashes> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let parsed = parse_curated_file_hashes(&contents);
    if parsed.skipped_bad_sha > 0 || parsed.skipped_unknown_tags > 0 {
        return Err(format!(
            "file-hash feed has {} invalid SHA-256 records and {} unknown behavior tags",
            parsed.skipped_bad_sha, parsed.skipped_unknown_tags
        ));
    }
    if parsed.records.is_empty() {
        return Err("file-hash feed contains no valid records".to_string());
    }
    Ok(parsed)
}

fn parse_phishtank_file(path: &Path) -> FeedResult<Vec<String>> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut validator = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(bytes.as_slice());
    let headers = validator
        .headers()
        .map_err(|e| format!("invalid PhishTank CSV headers: {e}"))?
        .clone();
    if !headers.iter().any(|header| header == "url") {
        return Err("PhishTank CSV has no url column".to_string());
    }
    for (index, record) in validator.records().enumerate() {
        record.map_err(|e| format!("invalid PhishTank CSV record {}: {e}", index + 2))?;
    }
    let entries =
        parse_phishtank_csv(bytes.as_slice()).map_err(|e| format!("invalid PhishTank CSV: {e}"))?;
    if entries.hostnames.is_empty() {
        return Err("PhishTank CSV contains no valid hostnames".to_string());
    }
    Ok(entries.hostnames)
}

fn parse_tor_exit_file(path: &Path) -> FeedResult<Vec<Ipv4Addr>> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    for (line_index, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        trimmed.parse::<Ipv4Addr>().map_err(|e| {
            format!(
                "invalid IPv4 address on line {} ({trimmed:?}): {e}",
                line_index + 1
            )
        })?;
    }
    let entries = parse_tor_exit_list(&contents).ips;
    if entries.is_empty() {
        return Err("Tor exit list contains no valid IPv4 records".to_string());
    }
    Ok(entries)
}

/// Parse a DigitalSide MISP-style CSV file into hostnames and IPv4 IoCs.
///
/// DigitalSide remains opt-in while its freshness/licensing gate is closed. Once
/// the operator explicitly supplies it, however, unreadable, malformed, or empty
/// data is fatal just like every other supplied feed; omission is the only no-op.
fn parse_digitalside_file(path: &Path) -> FeedResult<(Vec<String>, Vec<Ipv4Addr>)> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut validator = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(bytes.as_slice());
    for (index, record) in validator.records().enumerate() {
        record.map_err(|e| format!("invalid DigitalSide CSV record {}: {e}", index + 1))?;
    }
    let entries = parse_digitalside_csv(bytes.as_slice())
        .map_err(|e| format!("invalid DigitalSide CSV: {e}"))?;
    if entries.hostnames.is_empty() && entries.ips.is_empty() {
        return Err("DigitalSide CSV contains no valid indicators".to_string());
    }
    Ok((entries.hostnames, entries.ips))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TyposquatStats {
    accepted: usize,
    rejected_unsupported_ecosystem: usize,
    rejected_pseudo_package: usize,
    deduplicated: usize,
}

fn parse_typosquats_csv(path: &Path) -> FeedResult<(Vec<TyposquatEntry>, TyposquatStats)> {
    let mut by_key: BTreeMap<(Ecosystem, String), TyposquatEntry> = BTreeMap::new();
    let mut stats = TyposquatStats::default();

    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_path(path)
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let headers = reader
        .headers()
        .map_err(|e| format!("cannot read CSV headers: {e}"))?;
    let expected = [
        "malicious_package",
        "target_package",
        "ecosystem",
        "registry",
        "classification",
        "source",
    ];
    if headers.len() != expected.len()
        || !headers
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual == expected)
    {
        return Err(format!(
            "expected typosquat CSV headers {}",
            expected.join(",")
        ));
    }

    for (record_index, result) in reader.records().enumerate() {
        let record = result.map_err(|e| format!("invalid CSV record {}: {e}", record_index + 2))?;

        if record.len() != expected.len() {
            return Err(format!(
                "CSV record {} has {} fields; expected {}",
                record_index + 2,
                record.len(),
                expected.len()
            ));
        }

        let name = record.get(0).unwrap_or("").trim();
        let target = record.get(1).unwrap_or("").trim();
        let ecosystem_str = record.get(2).unwrap_or("").trim();
        let registry = record.get(3).unwrap_or("").trim();
        let classification = record.get(4).unwrap_or("").trim();
        let source = record.get(5).unwrap_or("").trim();

        if name.is_empty()
            || target.is_empty()
            || registry.is_empty()
            || classification.is_empty()
            || source.is_empty()
        {
            return Err(format!(
                "CSV record {} has an empty required field",
                record_index + 2
            ));
        }

        let Some(eco) = Ecosystem::from_name(ecosystem_str) else {
            stats.rejected_unsupported_ecosystem += 1;
            continue;
        };
        let name = canonical_package_name(eco, name);
        let target_name = canonical_package_name(eco, target);
        if name == target_name {
            stats.rejected_pseudo_package += 1;
            continue;
        }
        let entry = TyposquatEntry {
            ecosystem: eco,
            name: name.clone(),
            target_name,
        };
        let key = (eco, name);
        if let Some(existing) = by_key.get(&key) {
            if existing.target_name != entry.target_name {
                return Err(format!(
                    "CSV record {} conflicts on target for {}:{}",
                    record_index + 2,
                    eco,
                    key.1
                ));
            }
            stats.deduplicated += 1;
        } else {
            by_key.insert(key, entry);
        }
    }

    if by_key.is_empty() {
        return Err("typosquat CSV contains no records".to_string());
    }
    let entries = by_key.into_values().collect::<Vec<_>>();
    stats.accepted = entries.len();
    Ok((entries, stats))
}

/// Default popular packages CSV, embedded from the crate's own assets so
/// `cargo publish` can verify the tarball in isolation.
const DEFAULT_POPULAR_CSV: &str = include_str!("../../assets/data/popular_packages.csv");
const WEB3_PACKAGE_ANCHORS_CSV: &str = include_str!("../../assets/data/web3_package_anchors.csv");

fn parse_popular_csv(path: Option<&Path>) -> FeedResult<Vec<PopularEntry>> {
    let content = match path {
        Some(p) => std::fs::read_to_string(p)
            .map_err(|e| format!("cannot read explicitly-supplied file {}: {e}", p.display()))?,
        None => DEFAULT_POPULAR_CSV.to_string(),
    };

    let mut entries = parse_popular_from_string(&content)?;
    entries.extend(parse_popular_from_string(WEB3_PACKAGE_ANCHORS_CSV)?);
    entries.sort_by(|left, right| {
        left.ecosystem
            .cmp(&right.ecosystem)
            .then_with(|| left.name.cmp(&right.name))
    });
    entries.dedup_by(|left, right| left.ecosystem == right.ecosystem && left.name == right.name);
    Ok(entries)
}

fn parse_popular_from_string(csv_content: &str) -> FeedResult<Vec<PopularEntry>> {
    let mut entries = Vec::new();

    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(csv_content.as_bytes());

    let headers = reader
        .headers()
        .map_err(|e| format!("cannot read popular-package CSV headers: {e}"))?;
    if headers.get(0) != Some("ecosystem") || headers.get(1) != Some("name") {
        return Err("expected CSV headers ecosystem,name".to_string());
    }

    for (record_index, result) in reader.records().enumerate() {
        let record = result.map_err(|e| {
            format!(
                "invalid popular-package CSV record {}: {e}",
                record_index + 2
            )
        })?;

        if record.len() < 2 {
            return Err(format!(
                "popular-package CSV record {} has fewer than 2 fields",
                record_index + 2
            ));
        }

        let ecosystem_str = record.get(0).unwrap_or("").trim();
        let name = record.get(1).unwrap_or("").trim();

        if name.is_empty() {
            return Err(format!(
                "popular-package CSV record {} has an empty name",
                record_index + 2
            ));
        }

        let eco = Ecosystem::from_name(ecosystem_str).ok_or_else(|| {
            format!(
                "popular-package CSV record {} has unsupported ecosystem {ecosystem_str:?}",
                record_index + 2
            )
        })?;
        entries.push(PopularEntry {
            ecosystem: eco,
            name: normalize_name(eco, name),
        });
    }

    if entries.is_empty() {
        return Err("popular-package CSV contains no records".to_string());
    }
    Ok(entries)
}

/// Composite key for deduplication.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct PackageKey {
    ecosystem: Ecosystem,
    name: String,
}

fn unique_package_count(entries: &[PackageEntry]) -> usize {
    entries
        .iter()
        .map(|entry| PackageKey {
            ecosystem: entry.ecosystem,
            // Floors protect registry identities, not raw feed rows or legacy
            // spellings. Use the same canonical key the v2 index uses so aliases
            // such as repeated PyPI separators and crates.io `_`/`-` variants
            // cannot inflate a source above its minimum.
            name: canonical_package_name(entry.ecosystem, &entry.name),
        })
        .collect::<BTreeSet<_>>()
        .len()
}

/// Project rich package claims into the one-record-per-registry-key legacy v1
/// model. V2 must not use this projection: its format can retain independent
/// source/scope/evidence claims for the same package.
fn project_v1_packages(entries: Vec<PackageEntry>) -> Vec<PackageEntry> {
    let mut by_key: BTreeMap<PackageKey, PackageEntry> = BTreeMap::new();

    for entry in entries {
        let key = PackageKey {
            ecosystem: entry.ecosystem,
            name: entry.name.clone(),
        };

        by_key
            .entry(key)
            .and_modify(|existing| {
                // Scope and evidence are one claim. In particular, a confirmed
                // version-specific record must never promote an unrelated
                // medium-confidence all-version record to confirmed merely
                // because both normalize to one package key.
                let replace_claim_metadata = match (
                    existing.all_versions_malicious,
                    entry.all_versions_malicious,
                ) {
                    (false, true) => true,
                    (true, false) => false,
                    _ => {
                        entry.confidence > existing.confidence
                            || (entry.confidence == existing.confidence
                                && existing.reference.is_none()
                                && entry.reference.is_some())
                    }
                };
                if replace_claim_metadata {
                    existing.confidence = entry.confidence;
                    existing.source = entry.source;
                    existing.reference = entry.reference.clone();
                }

                // Union the affected_versions.
                let existing_versions: HashSet<String> =
                    existing.affected_versions.iter().cloned().collect();
                for v in &entry.affected_versions {
                    if !existing_versions.contains(v) {
                        existing.affected_versions.push(v.clone());
                    }
                }

                existing.all_versions_malicious |= entry.all_versions_malicious;
            })
            .or_insert(entry);
    }

    by_key.into_values().collect()
}

/// Complete v2 claim identity, excluding versions because equal claims union
/// their explicitly affected version lists in the writer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PackageClaimKey {
    ecosystem: Ecosystem,
    name: String,
    source: u8,
    confidence: u8,
    all_versions_malicious: bool,
    reference: Option<String>,
}

fn preserve_v2_package_claims(entries: Vec<PackageEntry>) -> Vec<PackageEntry> {
    let mut claims: BTreeMap<PackageClaimKey, PackageEntry> = BTreeMap::new();
    for mut entry in entries {
        entry.name = canonical_package_name(entry.ecosystem, &entry.name);
        entry.affected_versions.sort();
        entry.affected_versions.dedup();
        let key = PackageClaimKey {
            ecosystem: entry.ecosystem,
            name: entry.name.clone(),
            source: entry.source as u8,
            confidence: entry.confidence as u8,
            all_versions_malicious: entry.all_versions_malicious,
            reference: entry.reference.clone(),
        };
        claims
            .entry(key)
            .and_modify(|existing| {
                existing
                    .affected_versions
                    .extend(entry.affected_versions.clone());
                existing.affected_versions.sort();
                existing.affected_versions.dedup();
            })
            .or_insert(entry);
    }
    claims.into_values().collect()
}

fn canonical_cve_id(value: &str) -> Option<String> {
    let mut parts = value.trim().split('-');
    let prefix = parts.next()?;
    let year = parts.next()?;
    let sequence = parts.next()?;
    if parts.next().is_some()
        || !prefix.eq_ignore_ascii_case("CVE")
        || year.len() != 4
        || !year.bytes().all(|byte| byte.is_ascii_digit())
        || sequence.len() < 4
        || !sequence.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some(format!("CVE-{year}-{sequence}"))
}

fn insert_hostname_indicator(
    indicators: &mut BTreeMap<String, ThreatSource>,
    hostname: &str,
    source: ThreatSource,
) -> FeedResult<()> {
    let canonical = canonical_threat_hostname(hostname)
        .ok_or_else(|| format!("invalid hostname indicator {hostname:?}"))?;
    indicators
        .entry(canonical)
        .and_modify(|current| {
            if (source as u8) < (*current as u8) {
                *current = source;
            }
        })
        .or_insert(source);
    Ok(())
}

fn insert_ip_indicator(
    indicators: &mut BTreeMap<Ipv4Addr, ThreatSource>,
    ip: Ipv4Addr,
    source: ThreatSource,
) {
    indicators
        .entry(ip)
        .and_modify(|current| {
            if (source as u8) < (*current as u8) {
                *current = source;
            }
        })
        .or_insert(source);
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

#[derive(Clone, Copy)]
struct SourceExpectation {
    source: ThreatSource,
    counts: SourceRecordCounts,
}

fn source_counts_mut(
    expectations: &mut Vec<SourceExpectation>,
    source: ThreatSource,
) -> &mut SourceRecordCounts {
    if !expectations.iter().any(|entry| entry.source == source) {
        expectations.push(SourceExpectation {
            source,
            counts: SourceRecordCounts::default(),
        });
    }
    &mut expectations
        .iter_mut()
        .find(|entry| entry.source == source)
        .expect("source expectation was inserted")
        .counts
}

fn expected_sources(
    packages: &[PackageEntry],
    hostnames: &BTreeMap<String, ThreatSource>,
    ips: &BTreeMap<Ipv4Addr, ThreatSource>,
    typosquat_count: usize,
    artifact_sha256_count: usize,
    file_sha256_count: usize,
    malicious_url_count: usize,
) -> Vec<SourceExpectation> {
    let mut expectations = Vec::new();
    for package in packages {
        source_counts_mut(&mut expectations, package.source).package_count += 1;
    }
    for source in hostnames.values() {
        source_counts_mut(&mut expectations, *source).hostname_count += 1;
    }
    for source in ips.values() {
        source_counts_mut(&mut expectations, *source).ip_count += 1;
    }
    source_counts_mut(&mut expectations, ThreatSource::EcosystemsTyposquat).typosquat_count +=
        typosquat_count as u64;
    let ossf = source_counts_mut(&mut expectations, ThreatSource::OssfMalicious);
    ossf.artifact_sha256_count += artifact_sha256_count as u64;
    ossf.file_sha256_count += file_sha256_count as u64;
    ossf.malicious_url_count += malicious_url_count as u64;
    expectations.retain(|expectation| expectation.counts.total() > 0);
    expectations
}

fn add_packages(writer: &mut ThreatDbWriter, packages: &[PackageEntry]) {
    for package in packages {
        let versions: Vec<&str> = package
            .affected_versions
            .iter()
            .map(String::as_str)
            .collect();
        writer.add_package(
            package.ecosystem,
            &package.name,
            &versions,
            package.source,
            package.confidence,
            package.all_versions_malicious,
            package.reference.as_deref(),
        );
    }
}

fn verify_compiler_signature(data: &[u8], signing_key: &SigningKey) -> FeedResult<()> {
    // The public threatdb module documents this stable v1/v2 header layout. Keep
    // this independent verification in the compiler so the staged artifact is
    // checked with the actual key supplied for this run, even in tests or key
    // rotation preparations where the client's embedded production key differs.
    const HEADER_SIZE: usize = 172;
    const FINGERPRINT_OFFSET: usize = 76;
    const SIGNATURE_OFFSET: usize = 108;
    const SIGNATURE_LENGTH: usize = 64;

    if data.len() < HEADER_SIZE {
        return Err(format!("staged database is only {} bytes", data.len()));
    }
    let verifying_key = signing_key.verifying_key();
    let expected_fingerprint = Sha256::digest(verifying_key.as_bytes());
    if data[FINGERPRINT_OFFSET..SIGNATURE_OFFSET] != expected_fingerprint[..] {
        return Err("staged database signer fingerprint does not match this run's key".to_string());
    }
    let signature =
        Signature::from_slice(&data[SIGNATURE_OFFSET..SIGNATURE_OFFSET + SIGNATURE_LENGTH])
            .map_err(|e| format!("staged database has an invalid signature encoding: {e}"))?;
    let mut signed_data = Vec::with_capacity(SIGNATURE_OFFSET + data.len() - HEADER_SIZE);
    signed_data.extend_from_slice(&data[..SIGNATURE_OFFSET]);
    signed_data.extend_from_slice(&data[HEADER_SIZE..]);
    verifying_key
        .verify(&signed_data, &signature)
        .map_err(|_| "staged database signature does not verify".to_string())
}

#[derive(Debug, Clone, serde::Serialize)]
struct GenerationAsset {
    filename: String,
    format: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_tirith_version: Option<String>,
    sha256: String,
    size: u64,
    url: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct GenerationPayload {
    assets: Vec<GenerationAsset>,
    manifest_version: u64,
    sequence: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
struct SourceIntegrityDigests {
    compiler_metadata_sha256: String,
    registry_snapshot_sha256: String,
    source_transaction_sha256: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct SourceIntegrityPayload {
    compiler_metadata_sha256: String,
    manifest_version: u64,
    registry_snapshot_sha256: String,
    sequence: u64,
    source_transaction_sha256: String,
    v1_filename: String,
    v1_sha256: String,
    v2_filename: String,
    v2_sha256: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct CompilerParserCounts {
    accepted: usize,
    rejected: usize,
    details: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct CompilerParseMetadata {
    schema_version: u32,
    compiler_version: String,
    parsed_at: String,
    source_transaction_sha256: Option<String>,
    registry_snapshot_sha256: Option<String>,
    sources: BTreeMap<String, CompilerParserCounts>,
}

/// First generation-index schema whose version is part of the signed payload.
/// Schema v1 placed `manifest_version` outside the signature; publishing v2
/// gives old clients an unambiguous reason to use the legacy v1 channel while
/// new clients authenticate the schema before acting on it.
const GENERATION_MANIFEST_VERSION: u64 = 2;
const SOURCE_INTEGRITY_MANIFEST_VERSION: u64 = 1;

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn immutable_asset_filename(path: &Path) -> FeedResult<String> {
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("output {} has no UTF-8 filename", path.display()))?;
    if filename.is_empty()
        || !filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(format!(
            "output filename {filename:?} is unsafe for a signed generation URL"
        ));
    }
    Ok(filename.to_string())
}

// Keep both assets' paths and bytes explicit at this signed two-asset commit
// boundary so a caller cannot accidentally pair one asset's identity with the
// other's content.
#[allow(clippy::too_many_arguments)]
fn build_generation_manifest(
    sequence: u64,
    v1_path: &Path,
    v1_data: &[u8],
    v2_path: &Path,
    v2_data: &[u8],
    base_url: &str,
    v2_min_tirith_version: &str,
    signing_key: &SigningKey,
) -> FeedResult<Vec<u8>> {
    let base_url = base_url.trim_end_matches('/');
    if base_url.is_empty() || v2_min_tirith_version.trim().is_empty() {
        return Err("generation base URL and v2 minimum version must be non-empty".to_string());
    }
    let parsed_base = url::Url::parse(base_url)
        .map_err(|error| format!("generation base URL is invalid: {error}"))?;
    if parsed_base.scheme() != "https"
        || parsed_base.host_str().is_none()
        || parsed_base.username() != ""
        || parsed_base.password().is_some()
        || parsed_base.query().is_some()
        || parsed_base.fragment().is_some()
    {
        return Err(
            "generation base URL must be an HTTPS origin/path without credentials, query, or fragment"
                .to_string(),
        );
    }
    let v1_filename = immutable_asset_filename(v1_path)?;
    let v2_filename = immutable_asset_filename(v2_path)?;
    if v1_filename == v2_filename {
        return Err(format!(
            "generation assets must have distinct immutable filenames, both resolved to {v1_filename:?}"
        ));
    }
    let v1_url = format!("{base_url}/{v1_filename}");
    let v2_url = format!("{base_url}/{v2_filename}");
    if v1_url == v2_url {
        return Err(format!(
            "generation assets must have distinct immutable URLs, both resolved to {v1_url:?}"
        ));
    }
    let payload = GenerationPayload {
        assets: vec![
            GenerationAsset {
                filename: v1_filename.clone(),
                format: 1,
                min_tirith_version: None,
                sha256: sha256_hex(v1_data),
                size: v1_data.len() as u64,
                url: v1_url,
            },
            GenerationAsset {
                filename: v2_filename.clone(),
                format: 2,
                min_tirith_version: Some(v2_min_tirith_version.to_string()),
                sha256: sha256_hex(v2_data),
                size: v2_data.len() as u64,
                url: v2_url,
            },
        ],
        manifest_version: GENERATION_MANIFEST_VERSION,
        sequence,
    };
    let canonical = serde_json::to_string(&payload)
        .map_err(|error| format!("cannot serialize generation payload: {error}"))?;
    let signature = sign_payload(&canonical, signing_key);
    let mut document = serde_json::to_value(payload)
        .map_err(|error| format!("cannot serialize generation manifest: {error}"))?;
    let object = document
        .as_object_mut()
        .ok_or_else(|| "generation payload did not serialize as an object".to_string())?;
    object.insert("signature".to_string(), serde_json::json!(signature));
    let mut bytes = serde_json::to_vec(&document)
        .map_err(|error| format!("cannot encode generation manifest: {error}"))?;
    bytes.push(b'\n');
    verify_generation_manifest(&bytes, &canonical, signing_key)?;
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
fn build_source_integrity_manifest(
    sequence: u64,
    v1_path: &Path,
    v1_data: &[u8],
    v2_path: &Path,
    v2_data: &[u8],
    digests: &SourceIntegrityDigests,
    signing_key: &SigningKey,
) -> FeedResult<Vec<u8>> {
    for (label, digest) in [
        (
            "source transaction",
            digests.source_transaction_sha256.as_str(),
        ),
        (
            "registry snapshot",
            digests.registry_snapshot_sha256.as_str(),
        ),
        (
            "compiler metadata",
            digests.compiler_metadata_sha256.as_str(),
        ),
    ] {
        validate_lower_hex(digest, 32, &format!("source-integrity {label} SHA-256"))?;
    }
    let payload = SourceIntegrityPayload {
        compiler_metadata_sha256: digests.compiler_metadata_sha256.clone(),
        manifest_version: SOURCE_INTEGRITY_MANIFEST_VERSION,
        registry_snapshot_sha256: digests.registry_snapshot_sha256.clone(),
        sequence,
        source_transaction_sha256: digests.source_transaction_sha256.clone(),
        v1_filename: immutable_asset_filename(v1_path)?,
        v1_sha256: sha256_hex(v1_data),
        v2_filename: immutable_asset_filename(v2_path)?,
        v2_sha256: sha256_hex(v2_data),
    };
    let canonical = serde_json::to_string(&payload)
        .map_err(|error| format!("cannot serialize source-integrity payload: {error}"))?;
    let signature = sign_payload(&canonical, signing_key);
    let mut document = serde_json::to_value(payload)
        .map_err(|error| format!("cannot serialize source-integrity manifest: {error}"))?;
    document
        .as_object_mut()
        .ok_or_else(|| "source-integrity payload did not serialize as an object".to_string())?
        .insert("signature".to_string(), serde_json::json!(signature));
    let mut bytes = serde_json::to_vec(&document)
        .map_err(|error| format!("cannot encode source-integrity manifest: {error}"))?;
    bytes.push(b'\n');
    verify_source_integrity_manifest(&bytes, &canonical, signing_key)?;
    Ok(bytes)
}

fn verify_source_integrity_manifest(
    bytes: &[u8],
    expected_payload: &str,
    signing_key: &SigningKey,
) -> FeedResult<()> {
    let mut document: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("cannot parse source-integrity manifest: {error}"))?;
    let object = document
        .as_object_mut()
        .ok_or_else(|| "source-integrity manifest is not an object".to_string())?;
    let manifest_version = object
        .get("manifest_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "source-integrity manifest has no integer manifest_version".to_string())?;
    let signature_b64 = object
        .remove("signature")
        .and_then(|value| value.as_str().map(str::to_string))
        .ok_or_else(|| "source-integrity manifest has no signature".to_string())?;
    let canonical = serde_json::to_string(&document)
        .map_err(|error| format!("cannot reconstruct source-integrity payload: {error}"))?;
    if canonical != expected_payload {
        return Err("source-integrity signed region changed during staging".to_string());
    }
    let signature_bytes = BASE64
        .decode(signature_b64)
        .map_err(|error| format!("invalid source-integrity signature base64: {error}"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|error| format!("invalid source-integrity signature encoding: {error}"))?;
    signing_key
        .verifying_key()
        .verify(canonical.as_bytes(), &signature)
        .map_err(|_| "source-integrity manifest signature does not verify".to_string())?;
    if manifest_version != SOURCE_INTEGRITY_MANIFEST_VERSION {
        return Err(format!(
            "source-integrity manifest version {manifest_version} is unsupported"
        ));
    }
    Ok(())
}

fn verify_generation_manifest(
    bytes: &[u8],
    expected_payload: &str,
    signing_key: &SigningKey,
) -> FeedResult<()> {
    let mut document: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("cannot parse staged generation manifest: {error}"))?;
    let object = document
        .as_object_mut()
        .ok_or_else(|| "generation manifest is not an object".to_string())?;
    let manifest_version = object
        .get("manifest_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "generation manifest has no integer manifest_version".to_string())?;
    let signature_b64 = object
        .remove("signature")
        .and_then(|value| value.as_str().map(str::to_string))
        .ok_or_else(|| "generation manifest has no signature".to_string())?;
    let canonical = serde_json::to_string(&document)
        .map_err(|error| format!("cannot reconstruct generation payload: {error}"))?;
    if canonical != expected_payload {
        return Err("generation manifest signed region changed during staging".to_string());
    }
    let signature_bytes = BASE64
        .decode(signature_b64)
        .map_err(|error| format!("invalid generation signature base64: {error}"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|error| format!("invalid generation signature encoding: {error}"))?;
    signing_key
        .verifying_key()
        .verify(canonical.as_bytes(), &signature)
        .map_err(|_| "generation manifest signature does not verify".to_string())?;
    if manifest_version != GENERATION_MANIFEST_VERSION {
        return Err(format!(
            "generation manifest version {manifest_version} is unsupported (expected {GENERATION_MANIFEST_VERSION})"
        ));
    }
    Ok(())
}

fn validate_drop(label: &str, previous: u64, candidate: u64) -> FeedResult<()> {
    if previous > 0
        && (candidate as u128) * 100
            < (previous as u128) * (100 - MAX_BASELINE_DROP_PERCENT) as u128
    {
        return Err(format!(
            "{label} dropped from {previous} to {candidate} records (more than {MAX_BASELINE_DROP_PERCENT}%)"
        ));
    }
    Ok(())
}

fn load_signed_baseline(path: &Path, signing_key: &SigningKey) -> FeedResult<ThreatDb> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("cannot read signed baseline {}: {e}", path.display()))?;
    verify_compiler_signature(&bytes, signing_key)
        .map_err(|e| format!("untrusted baseline {}: {e}", path.display()))?;
    ThreatDb::from_bytes(bytes, 0)
        .map_err(|e| format!("cannot parse signed baseline {}: {e}", path.display()))
}

fn resolve_baseline<'a>(
    explicit: Option<&'a Path>,
    output: &'a Path,
) -> FeedResult<Option<&'a Path>> {
    if explicit.is_some() {
        return Ok(explicit);
    }
    let exists = output
        .try_exists()
        .map_err(|error| format!("cannot inspect {}: {error}", output.display()))?;
    Ok(exists.then_some(output))
}

fn validate_source_sections(
    source: ThreatSource,
    previous: SourceRecordCounts,
    candidate: SourceRecordCounts,
) -> FeedResult<()> {
    for (section, old, new) in [
        ("packages", previous.package_count, candidate.package_count),
        (
            "hostnames",
            previous.hostname_count,
            candidate.hostname_count,
        ),
        ("IPv4 indicators", previous.ip_count, candidate.ip_count),
        (
            "typosquats",
            previous.typosquat_count,
            candidate.typosquat_count,
        ),
        (
            "artifact SHA-256",
            previous.artifact_sha256_count,
            candidate.artifact_sha256_count,
        ),
        (
            "file SHA-256",
            previous.file_sha256_count,
            candidate.file_sha256_count,
        ),
        (
            "malicious URLs",
            previous.malicious_url_count,
            candidate.malicious_url_count,
        ),
    ] {
        validate_drop(&format!("{} {section}", source.as_str()), old, new)?;
    }
    Ok(())
}

fn validate_against_baseline(
    path: &Path,
    candidate: &ThreatDb,
    signing_key: &SigningKey,
) -> FeedResult<()> {
    let previous = load_signed_baseline(path, signing_key)?;
    if previous.stats().format_version != candidate.stats().format_version {
        return Err(format!(
            "baseline {} format v{} does not match candidate format v{}",
            path.display(),
            previous.stats().format_version,
            candidate.stats().format_version
        ));
    }
    if candidate.build_sequence() <= previous.build_sequence() {
        return Err(format!(
            "candidate sequence {} is not newer than existing sequence {}",
            candidate.build_sequence(),
            previous.build_sequence()
        ));
    }

    let previous_sources = previous.source_breakdown();
    let candidate_sources = candidate.source_breakdown();
    for source in ThreatSource::ALL {
        validate_drop(
            source.as_str(),
            previous_sources.count_for(source),
            candidate_sources.count_for(source),
        )?;
        validate_source_sections(
            source,
            previous_sources.section_counts_for(source),
            candidate_sources.section_counts_for(source),
        )?;
    }
    validate_drop(
        "typosquats",
        previous_sources.typosquat_count,
        candidate_sources.typosquat_count,
    )?;
    validate_drop(
        "popular packages",
        previous_sources.popular_count,
        candidate_sources.popular_count,
    )?;
    let previous_stats = previous.stats();
    let candidate_stats = candidate.stats();
    validate_drop(
        "v2 artifact SHA-256 section",
        previous_stats.artifact_sha256_count,
        candidate_stats.artifact_sha256_count,
    )?;
    validate_drop(
        "v2 file SHA-256 section",
        previous_stats.file_sha256_count,
        candidate_stats.file_sha256_count,
    )?;
    validate_drop(
        "v2 malicious-URL section",
        previous_stats.malicious_url_count,
        candidate_stats.malicious_url_count,
    )?;
    Ok(())
}

struct RoundTripExpectations<'a> {
    format: ThreatDbFormat,
    sequence: u64,
    package_count: usize,
    popular_count: usize,
    typosquat_count: usize,
    sources: &'a [SourceExpectation],
    artifact_hashes: &'a [[u8; 32]],
    file_hashes: &'a CuratedFileHashes,
    malicious_urls: &'a [String],
    baseline: Option<&'a Path>,
}

fn validate_round_trip_count(
    format: ThreatDbFormat,
    label: &str,
    actual: usize,
    input: usize,
) -> FeedResult<()> {
    if actual != input {
        return Err(format!(
            "staged {} {label} count is {actual}, expected exactly {input}",
            match format {
                ThreatDbFormat::V1 => "v1",
                ThreatDbFormat::V2 => "v2",
            }
        ));
    }
    Ok(())
}

fn validate_round_trip(
    _path: &Path,
    data: &[u8],
    signing_key: &SigningKey,
    expected: &RoundTripExpectations<'_>,
) -> FeedResult<()> {
    verify_compiler_signature(data, signing_key)?;
    let db = ThreatDb::from_bytes(data.to_vec(), 0)
        .map_err(|e| format!("cannot reopen staged database: {e}"))?;
    let stats = db.stats();
    let expected_format = match expected.format {
        ThreatDbFormat::V1 => 1,
        ThreatDbFormat::V2 => 2,
    };
    if stats.format_version != expected_format {
        return Err(format!(
            "staged format is {}, expected {expected_format}",
            stats.format_version
        ));
    }
    if stats.build_sequence != expected.sequence {
        return Err(format!(
            "staged sequence is {}, expected {}",
            stats.build_sequence, expected.sequence
        ));
    }
    validate_round_trip_count(
        expected.format,
        "package",
        stats.package_count as usize,
        expected.package_count,
    )?;
    validate_round_trip_count(
        expected.format,
        "popular-package",
        stats.popular_count as usize,
        expected.popular_count,
    )?;
    validate_round_trip_count(
        expected.format,
        "typosquat",
        stats.typosquat_count as usize,
        expected.typosquat_count,
    )?;

    let breakdown = db.source_breakdown();
    let attributed_total: u64 = breakdown.per_source().iter().map(|(_, count)| *count).sum();
    let indexed_total = stats.package_count as u64
        + stats.hostname_count as u64
        + stats.ip_count as u64
        + stats.typosquat_count as u64
        + stats.artifact_sha256_count
        + stats.file_sha256_count
        + stats.malicious_url_count;
    if attributed_total != indexed_total {
        return Err(format!(
            "source breakdown attributes {attributed_total} records but indexes contain {indexed_total}"
        ));
    }
    for source in ThreatSource::ALL {
        let expected_counts = expected
            .sources
            .iter()
            .find_map(|expectation| (expectation.source == source).then_some(expectation.counts))
            .unwrap_or_default();
        let actual = breakdown.section_counts_for(source);
        if actual != expected_counts {
            return Err(format!(
                "{} round-trip section counts are {actual:?}, expected {:?}",
                source.as_str(),
                expected_counts
            ));
        }
    }

    if expected.format == ThreatDbFormat::V2 {
        for sha in expected.artifact_hashes {
            if db.check_artifact_sha256(sha).is_none() {
                return Err("v2 round-trip lost an OSSF artifact SHA-256".to_string());
            }
        }
        for record in &expected.file_hashes.records {
            if db.check_file_sha256(&record.sha256).is_none() {
                return Err("v2 round-trip lost a curated file SHA-256".to_string());
            }
        }
        for url in expected.malicious_urls {
            if db.check_malicious_url(url).is_none() {
                return Err("v2 round-trip lost an OSSF malicious URL".to_string());
            }
        }
    }

    if let Some(baseline) = expected.baseline {
        validate_against_baseline(baseline, &db, signing_key)?;
    }
    Ok(())
}

fn stage_database(
    output: &Path,
    data: &[u8],
    signing_key: &SigningKey,
    expected: &RoundTripExpectations<'_>,
) -> FeedResult<tempfile::NamedTempFile> {
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("cannot create staging file in {}: {e}", parent.display()))?;
    staged
        .write_all(data)
        .map_err(|e| format!("cannot write staging file: {e}"))?;
    staged
        .as_file_mut()
        .flush()
        .map_err(|e| format!("cannot flush staging file: {e}"))?;
    staged
        .as_file()
        .sync_all()
        .map_err(|e| format!("cannot sync staging file: {e}"))?;

    let mut reopened = Vec::new();
    std::fs::File::open(staged.path())
        .and_then(|mut file| file.read_to_end(&mut reopened))
        .map_err(|e| format!("cannot reopen staging file: {e}"))?;
    if reopened != data {
        return Err("staging file bytes differ after reopen".to_string());
    }
    validate_round_trip(output, &reopened, signing_key, expected)?;
    Ok(staged)
}

fn stage_generation_manifest(
    output: &Path,
    data: &[u8],
    signing_key: &SigningKey,
) -> FeedResult<tempfile::NamedTempFile> {
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("cannot create generation staging file: {error}"))?;
    staged
        .write_all(data)
        .and_then(|_| staged.as_file_mut().flush())
        .and_then(|_| staged.as_file().sync_all())
        .map_err(|error| format!("cannot durably stage generation manifest: {error}"))?;
    let reopened = std::fs::read(staged.path())
        .map_err(|error| format!("cannot reopen staged generation manifest: {error}"))?;
    if reopened != data {
        return Err("generation manifest bytes differ after reopen".to_string());
    }
    let mut document: serde_json::Value = serde_json::from_slice(&reopened)
        .map_err(|error| format!("cannot parse staged generation manifest: {error}"))?;
    let object = document
        .as_object_mut()
        .ok_or_else(|| "generation manifest is not an object".to_string())?;
    object.remove("signature");
    let canonical = serde_json::to_string(&document)
        .map_err(|error| format!("cannot reconstruct staged generation payload: {error}"))?;
    verify_generation_manifest(&reopened, &canonical, signing_key)?;
    Ok(staged)
}

fn stage_source_integrity_manifest(
    output: &Path,
    data: &[u8],
    signing_key: &SigningKey,
) -> FeedResult<tempfile::NamedTempFile> {
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("cannot create source-integrity staging file: {error}"))?;
    staged
        .write_all(data)
        .and_then(|_| staged.as_file_mut().flush())
        .and_then(|_| staged.as_file().sync_all())
        .map_err(|error| format!("cannot durably stage source-integrity manifest: {error}"))?;
    let reopened = std::fs::read(staged.path())
        .map_err(|error| format!("cannot reopen staged source-integrity manifest: {error}"))?;
    if reopened != data {
        return Err("source-integrity manifest bytes differ after reopen".to_string());
    }
    let mut document: serde_json::Value = serde_json::from_slice(&reopened)
        .map_err(|error| format!("cannot parse staged source-integrity manifest: {error}"))?;
    document
        .as_object_mut()
        .ok_or_else(|| "source-integrity manifest is not an object".to_string())?
        .remove("signature");
    let canonical = serde_json::to_string(&document)
        .map_err(|error| format!("cannot reconstruct staged source-integrity payload: {error}"))?;
    verify_source_integrity_manifest(&reopened, &canonical, signing_key)?;
    Ok(staged)
}

fn stage_compiler_metadata(output: &Path, data: &[u8]) -> FeedResult<tempfile::NamedTempFile> {
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("cannot create compiler metadata staging file: {error}"))?;
    staged
        .write_all(data)
        .and_then(|_| staged.as_file_mut().flush())
        .and_then(|_| staged.as_file().sync_all())
        .map_err(|error| format!("cannot durably stage compiler metadata: {error}"))?;
    let reopened = std::fs::read(staged.path())
        .map_err(|error| format!("cannot reopen staged compiler metadata: {error}"))?;
    if reopened != data {
        return Err("compiler metadata bytes differ after reopen".to_string());
    }
    let document: serde_json::Value = serde_json::from_slice(&reopened)
        .map_err(|error| format!("cannot parse staged compiler metadata: {error}"))?;
    if document
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
        || document
            .get("compiler_version")
            .and_then(serde_json::Value::as_str)
            != Some(env!("CARGO_PKG_VERSION"))
        || document
            .get("sources")
            .and_then(serde_json::Value::as_object)
            .is_none()
    {
        return Err("compiler metadata schema/version/counts are incomplete".to_string());
    }
    Ok(staged)
}

fn publish_staged(staged: tempfile::NamedTempFile, output: &Path) -> FeedResult<()> {
    let published = staged.persist(output).map_err(|e| {
        format!(
            "cannot atomically publish {}: {}",
            output.display(),
            e.error
        )
    })?;
    published
        .sync_all()
        .map_err(|e| format!("cannot sync published output {}: {e}", output.display()))?;
    #[cfg(unix)]
    {
        let parent = output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| format!("cannot sync output directory {}: {e}", parent.display()))?;
    }
    Ok(())
}

fn publish_staged_immutable(staged: tempfile::NamedTempFile, output: &Path) -> FeedResult<()> {
    let published = staged.persist_noclobber(output).map_err(|error| {
        format!(
            "cannot publish immutable generation asset {}: {}",
            output.display(),
            error.error
        )
    })?;
    published
        .sync_all()
        .map_err(|error| format!("cannot sync immutable output {}: {error}", output.display()))?;
    #[cfg(unix)]
    {
        let parent = output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                format!("cannot sync output directory {}: {error}", parent.display())
            })?;
    }
    Ok(())
}

struct StagedAuxiliaryArtifacts<'a> {
    compiler_metadata: Option<(tempfile::NamedTempFile, &'a Path)>,
    source_integrity: Option<(tempfile::NamedTempFile, &'a Path)>,
}

fn publish_compiled_generation<F, G>(
    staged_v1: tempfile::NamedTempFile,
    v1_path: &Path,
    staged_v2: Option<(tempfile::NamedTempFile, &Path)>,
    staged_manifest: Option<(tempfile::NamedTempFile, &Path)>,
    staged_auxiliary: StagedAuxiliaryArtifacts<'_>,
    mut publish_asset: F,
    mut publish_pointer: G,
) -> FeedResult<()>
where
    F: FnMut(tempfile::NamedTempFile, &Path) -> FeedResult<()>,
    G: FnMut(tempfile::NamedTempFile, &Path) -> FeedResult<()>,
{
    if let Some((manifest, manifest_path)) = staged_manifest {
        let (v2, v2_path) = staged_v2.ok_or_else(|| {
            "a signed generation manifest requires both staged DB formats".to_string()
        })?;
        // Generation-pointer mode uses immutable asset names. Refusing an
        // overwrite makes a partial crash leave only unreferenced files; the
        // authoritative pointer remains on the previous complete generation.
        for path in [v1_path, v2_path] {
            if path.try_exists().map_err(|error| {
                format!(
                    "cannot inspect immutable output {}: {error}",
                    path.display()
                )
            })? {
                return Err(format!(
                    "refusing to overwrite immutable generation asset {}",
                    path.display()
                ));
            }
        }
        publish_asset(staged_v1, v1_path)?;
        publish_asset(v2, v2_path)?;
        if let Some((metadata, metadata_path)) = staged_auxiliary.compiler_metadata {
            publish_asset(metadata, metadata_path)?;
        }
        if let Some((integrity, integrity_path)) = staged_auxiliary.source_integrity {
            publish_asset(integrity, integrity_path)?;
        }
        // The one shared pointer is the commit point and is always last.
        publish_pointer(manifest, manifest_path)?;
        return Ok(());
    }

    // Legacy direct-path compatibility: without a generation pointer there is no
    // claim of pair atomicity, so retain the previous v2-first/v1-last behavior.
    if let Some((v2, v2_path)) = staged_v2 {
        publish_staged(v2, v2_path)?;
    }
    publish_staged(staged_v1, v1_path)?;
    if let Some((metadata, metadata_path)) = staged_auxiliary.compiler_metadata {
        publish_asset(metadata, metadata_path)?;
    }
    if let Some((integrity, integrity_path)) = staged_auxiliary.source_integrity {
        publish_asset(integrity, integrity_path)?;
    }
    Ok(())
}

fn registry_metadata_url(key: &RegistryPackageKey) -> FeedResult<url::Url> {
    let base = match key.ecosystem {
        Ecosystem::Npm => "https://registry.npmjs.org/",
        Ecosystem::PyPI => "https://pypi.org/pypi/",
        ecosystem => {
            return Err(format!(
                "bounded registry snapshots are unsupported for {ecosystem}:{}",
                key.name
            ))
        }
    };
    let mut url = url::Url::parse(base).map_err(|error| error.to_string())?;
    url.path_segments_mut()
        .map_err(|_| "registry metadata base URL cannot accept path segments".to_string())?
        .push(&key.name);
    if key.ecosystem == Ecosystem::PyPI {
        url.path_segments_mut()
            .map_err(|_| "PyPI metadata URL cannot accept path segments".to_string())?
            .push("json");
    }
    Ok(url)
}

fn extract_registry_versions(key: &RegistryPackageKey, bytes: &[u8]) -> FeedResult<Vec<String>> {
    let document: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid registry response for {}: {error}", key.name))?;
    let field = match key.ecosystem {
        Ecosystem::Npm => "versions",
        Ecosystem::PyPI => "releases",
        _ => return Err(format!("unsupported registry ecosystem {}", key.ecosystem)),
    };
    let versions = document
        .get(field)
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| format!("registry response for {} has no {field} object", key.name))?;
    if versions.is_empty() || versions.len() > MAX_REGISTRY_VERSIONS_PER_PACKAGE {
        return Err(format!(
            "registry response for {} contains {} versions, outside 1..={} cap",
            key.name,
            versions.len(),
            MAX_REGISTRY_VERSIONS_PER_PACKAGE
        ));
    }
    let mut output = versions.keys().cloned().collect::<Vec<_>>();
    for version in &output {
        validate_osv_value(version, "registry version")?;
    }
    output.sort();
    output.dedup();
    Ok(output)
}

fn fetch_registry_snapshots(root: &Path, ossf_commit: &str, output: &Path) -> FeedResult<()> {
    if ossf_commit.len() != 40
        || !ossf_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("--ossf-commit must be an exact lowercase 40-hex revision".to_string());
    }
    let (_, pending, _, _) = collect_ossf(root)?;
    let requests: BTreeSet<RegistryPackageKey> =
        pending.into_iter().map(|claim| claim.key).collect();
    if requests.len() > MAX_BOUNDED_PACKAGE_REQUESTS {
        return Err(format!(
            "{} bounded package requests exceed cap {}",
            requests.len(),
            MAX_BOUNDED_PACKAGE_REQUESTS
        ));
    }

    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .user_agent(concat!(
            "tirith-threatdb-compile/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .map_err(|error| format!("cannot build bounded registry client: {error}"))?;
    let mut aggregate_bytes = 0usize;
    let mut packages = Vec::with_capacity(requests.len());
    for key in requests {
        let url = registry_metadata_url(&key)?;
        let response = client.get(url.clone()).send().map_err(|error| {
            format!("registry snapshot request for {} failed: {error}", key.name)
        })?;
        if !response.status().is_success() {
            return Err(format!(
                "registry snapshot request for {} returned {}",
                key.name,
                response.status()
            ));
        }
        if response.url() != &url {
            return Err(format!("registry request for {} redirected", key.name));
        }
        let mut bytes = Vec::new();
        response
            .take((MAX_REGISTRY_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("cannot read registry response for {}: {error}", key.name))?;
        if bytes.len() > MAX_REGISTRY_RESPONSE_BYTES {
            return Err(format!(
                "registry response for {} exceeds byte cap",
                key.name
            ));
        }
        aggregate_bytes = aggregate_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| "registry aggregate byte count overflow".to_string())?;
        if aggregate_bytes > MAX_REGISTRY_AGGREGATE_BYTES {
            return Err("registry responses exceed aggregate byte cap".to_string());
        }
        let versions = extract_registry_versions(&key, &bytes)?;
        packages.push(RegistrySnapshotPackage {
            ecosystem: key.ecosystem.to_string(),
            name: key.name,
            source_url: url.to_string(),
            response_sha256: format!("{:x}", Sha256::digest(&bytes)),
            response_bytes: bytes.len(),
            versions,
        });
    }
    let document = RegistrySnapshotDocument {
        schema_version: 1,
        ossf_commit: ossf_commit.to_string(),
        retrieved_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        packages,
    };
    let bytes = serde_json::to_vec_pretty(&document)
        .map_err(|error| format!("cannot serialize registry snapshot: {error}"))?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("cannot stage registry snapshot: {error}"))?;
    staged
        .write_all(&bytes)
        .and_then(|_| staged.as_file_mut().flush())
        .and_then(|_| staged.as_file().sync_all())
        .map_err(|error| format!("cannot durably stage registry snapshot: {error}"))?;
    staged.persist_noclobber(output).map_err(|error| {
        format!(
            "cannot publish registry snapshot {}: {}",
            output.display(),
            error.error
        )
    })?;
    Ok(())
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
    if let Some(Commands::FetchRegistrySnapshots {
        ossf,
        ossf_commit,
        output,
    }) = &cli.command
    {
        fetch_registry_snapshots(ossf, ossf_commit, output).unwrap_or_else(|error| {
            eprintln!("error: cannot fetch registry snapshots: {error}");
            std::process::exit(1);
        });
        eprintln!("registry snapshots written to {}", output.display());
        return;
    }

    eprintln!("tirith-threatdb-compile: starting compilation");

    let mut all_packages = Vec::new();
    let mut total_files_scanned = 0usize;
    let mut total_files_skipped = 0usize;

    if cli.registry_snapshots.is_some() != cli.source_provenance.is_some() {
        eprintln!("error: --registry-snapshots and --source-provenance must be supplied together");
        std::process::exit(1);
    }
    let web3_anchor_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/data/web3_package_anchors.csv");
    let source_inputs = if cli.source_provenance.is_some() {
        match (
            cli.ossf.as_deref(),
            cli.datadog.as_deref(),
            cli.typosquats.as_deref(),
            cli.feodo.as_deref(),
            cli.cisa_kev.as_deref(),
        ) {
            (Some(ossf), Some(datadog), Some(typosquats), Some(feodo), Some(cisa_kev)) => {
                Some(SourceInputPaths {
                    ossf,
                    datadog,
                    typosquats,
                    feodo,
                    cisa_kev,
                    web3_anchors: &web3_anchor_path,
                })
            }
            _ => {
                eprintln!(
                    "error: source provenance requires the exact OpenSSF, Datadog, typosquat, Feodo, CISA, and Web3-anchor inputs"
                );
                std::process::exit(1);
            }
        }
    } else {
        None
    };
    let source_binding = cli
        .source_provenance
        .as_deref()
        .zip(cli.registry_snapshots.as_deref())
        .map(|(provenance, snapshot)| {
            let inputs = source_inputs
                .as_ref()
                .expect("source input paths validated above");
            feed_error(
                "source provenance",
                provenance,
                SourceTransactionBinding::load(provenance, snapshot, inputs),
            )
        });
    let mut registry_snapshots = cli.registry_snapshots.as_deref().map(|path| {
        let binding = source_binding
            .as_ref()
            .expect("paired source provenance validated above");
        feed_error(
            "registry snapshots",
            path,
            RegistrySnapshotStore::load(path, binding),
        )
    });

    // 1. OSSF malicious-packages
    let ossf_stats;
    // Aggregated OpenSSF indicators (DB-A model). Hostname and IPv4 IOCs use
    // the common v1/v2 indexes; artifact hashes, file hashes, and URLs are v2.
    let mut ossf_indicators = OssfIndicators::default();
    if let Some(ref ossf_dir) = cli.ossf {
        eprintln!(
            "  parsing OSSF malicious-packages from {}",
            ossf_dir.display()
        );
        let provider = registry_snapshots
            .as_mut()
            .map(|store| store as &mut dyn RegistryVersionProvider);
        let (ossf_packages, stats, indicators) = feed_error(
            "OSSF",
            ossf_dir,
            parse_ossf_with_provider(ossf_dir, provider),
        );
        if let Some(store) = registry_snapshots.as_ref() {
            feed_error(
                "registry snapshots",
                ossf_dir,
                store.ensure_fully_consumed(),
            );
        }
        let unique_packages = unique_package_count(&ossf_packages);
        feed_error(
            "OSSF",
            ossf_dir,
            require_minimum("OSSF", unique_packages, MIN_OSSF_PACKAGES),
        );
        eprintln!(
            "    {} entries scanned, {} unique packages ({} parsed claims), {} whole-package claims, {} bounded intervals, {} exact versions, {} withdrawn, {} non-malicious, {} unknown ecosystem, {} unsupported shapes, {} snapshot failures",
            stats.total_entries,
            unique_packages,
            stats.parsed_packages,
            stats.direct_whole_package_claims,
            stats.bounded_intervals_materialized,
            stats.exact_versions_emitted,
            stats.skipped_withdrawn,
            stats.skipped_non_malicious,
            stats.skipped_unknown_ecosystem,
            stats.unsupported_confirmed_shapes,
            stats.snapshot_failures,
        );
        eprintln!(
            "    {} indicators parsed across {} records ({} domains, {} IPv4 candidates, {} artifact sha256, {} urls; network IOCs persist in v1/v2, hashes and URLs in v2)",
            stats.total_indicators,
            stats.records_with_indicators,
            indicators.domains.len(),
            indicators.ips.len(),
            indicators.artifact_sha256.len(),
            indicators.urls.len(),
        );
        total_files_scanned +=
            stats.total_entries + stats.skipped_unreadable + stats.skipped_corrupt;
        total_files_skipped += stats.skipped_unreadable + stats.skipped_corrupt;
        ossf_stats = stats;
        ossf_indicators = indicators;
        all_packages.extend(ossf_packages);
    } else {
        ossf_stats = OssfStats::default();
    }

    // 2. Datadog
    let mut datadog_unique_packages = 0usize;
    let mut datadog_files_read = 0usize;
    let mut datadog_rejected_files = 0usize;
    if let Some(ref dd_dir) = cli.datadog {
        eprintln!(
            "  parsing Datadog malicious-packages from {}",
            dd_dir.display()
        );
        let (dd_packages, dd_skipped, dd_files_read) =
            feed_error("Datadog", dd_dir, parse_datadog(dd_dir));
        let unique_packages = unique_package_count(&dd_packages);
        datadog_unique_packages = unique_packages;
        datadog_files_read = dd_files_read;
        datadog_rejected_files = dd_skipped;
        feed_error(
            "Datadog",
            dd_dir,
            require_minimum("Datadog", unique_packages, MIN_DATADOG_PACKAGES),
        );
        eprintln!(
            "    {} unique packages extracted, {} files skipped",
            unique_packages, dd_skipped
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

    // 3. Project the parsed claims separately for the legacy and v2 formats.
    // V1 has one physical record per registry key; v2 preserves independent
    // source/scope/evidence claims for that key.
    let parsed_package_claims = all_packages.len();
    let v1_packages = project_v1_packages(all_packages.clone());
    let v2_packages = preserve_v2_package_claims(all_packages);
    eprintln!(
        "  package projection: {} claims -> {} v1 keys / {} v2 claims",
        parsed_package_claims,
        v1_packages.len(),
        v2_packages.len()
    );

    // 4. Feodo Tracker IPs
    let ips = if let Some(ref feodo_path) = cli.feodo {
        eprintln!("  parsing Feodo Tracker IPs from {}", feodo_path.display());
        let ips = feed_error("Feodo", feodo_path, parse_feodo(feodo_path));
        feed_error(
            "Feodo",
            feodo_path,
            require_minimum("Feodo", ips.len(), MIN_FEODO_IPS),
        );
        eprintln!("    {} unique IPs", ips.len());
        ips
    } else {
        Vec::new()
    };

    // 5. CISA KEV (counted for summary, not stored in DB in Phase A)
    let kev_count = if let Some(ref kev_path) = cli.cisa_kev {
        eprintln!("  parsing CISA KEV from {}", kev_path.display());
        let entries = feed_error("CISA KEV", kev_path, parse_cisa_kev(kev_path));
        feed_error(
            "CISA KEV",
            kev_path,
            require_minimum("CISA KEV", entries.len(), MIN_CISA_KEV_RECORDS),
        );
        eprintln!("    {} CVEs", entries.len());
        entries.len()
    } else {
        0
    };

    // 6. Typosquats
    let mut typosquat_parse_stats = TyposquatStats::default();
    let typosquats = if let Some(ref typo_path) = cli.typosquats {
        eprintln!("  parsing typosquats from {}", typo_path.display());
        let (entries, stats) = feed_error("typosquats", typo_path, parse_typosquats_csv(typo_path));
        feed_error(
            "typosquats",
            typo_path,
            require_minimum("typosquats", entries.len(), MIN_TYPOSQUAT_RECORDS),
        );
        eprintln!(
            "    {} accepted, {} unsupported ecosystems, {} pseudo-packages, {} duplicates",
            stats.accepted,
            stats.rejected_unsupported_ecosystem,
            stats.rejected_pseudo_package,
            stats.deduplicated
        );
        typosquat_parse_stats = stats;
        entries
    } else {
        Vec::new()
    };

    // 7. Popular packages
    eprintln!("  loading popular packages");
    let popular = parse_popular_csv(cli.popular.as_deref()).unwrap_or_else(|e| {
        eprintln!("error: cannot load popular-package feed: {e}");
        std::process::exit(1);
    });
    if popular.len() < 50 {
        eprintln!(
            "error: popular-package feed produced {} records, below the fail-closed minimum of 50",
            popular.len()
        );
        std::process::exit(1);
    }
    eprintln!("    {} popular packages", popular.len());

    // 8. Phase B hostname/IP feeds
    let urlhaus_hosts = if let Some(ref path) = cli.urlhaus {
        eprintln!("  parsing URLhaus hostnames from {}", path.display());
        let hosts = feed_error("URLhaus", path, parse_urlhaus_file(path));
        eprintln!("    {} hostnames", hosts.len());
        hosts
    } else {
        Vec::new()
    };

    let (threatfox_hosts, threatfox_ips) = if let Some(ref path) = cli.threatfox {
        eprintln!("  parsing ThreatFox IOCs from {}", path.display());
        let parsed = feed_error("ThreatFox", path, parse_threatfox_file(path));
        eprintln!("    {} hostnames, {} IPs", parsed.0.len(), parsed.1.len());
        parsed
    } else {
        (Vec::new(), Vec::new())
    };

    let phishing_army_hosts = if let Some(ref path) = cli.phishing_army {
        eprintln!("  parsing Phishing Army blocklist from {}", path.display());
        let hosts = feed_error("Phishing Army", path, parse_blocklist_file(path));
        eprintln!("    {} hostnames", hosts.len());
        hosts
    } else {
        Vec::new()
    };

    let phishtank_hosts = if let Some(ref path) = cli.phishtank {
        eprintln!("  parsing PhishTank CSV from {}", path.display());
        let hosts = feed_error("PhishTank", path, parse_phishtank_file(path));
        eprintln!("    {} hostnames", hosts.len());
        hosts
    } else {
        Vec::new()
    };

    let tor_exit_ips = if let Some(ref path) = cli.tor_exit {
        eprintln!("  parsing Tor exit nodes from {}", path.display());
        let ips = feed_error("Tor exit", path, parse_tor_exit_file(path));
        eprintln!("    {} IPs", ips.len());
        ips
    } else {
        Vec::new()
    };

    let (digitalside_hosts, digitalside_ips) = if let Some(ref path) = cli.digitalside {
        eprintln!("  parsing DigitalSide IOCs from {}", path.display());
        let parsed = feed_error("DigitalSide", path, parse_digitalside_file(path));
        eprintln!("    {} hostnames, {} IPs", parsed.0.len(), parsed.1.len());
        parsed
    } else {
        (Vec::new(), Vec::new())
    };

    let exfil_endpoint_hosts = if let Some(ref path) = cli.exfil_endpoints {
        eprintln!("  parsing exfil endpoints from {}", path.display());
        let hosts = feed_error("exfil-endpoint", path, parse_exfil_endpoints_file(path));
        eprintln!("    {} hostnames", hosts.len());
        hosts
    } else {
        Vec::new()
    };

    let curated_file_hashes = if let Some(ref path) = cli.file_hashes {
        eprintln!("  parsing curated file hashes from {}", path.display());
        let parsed = feed_error(
            "curated file-hash",
            path,
            parse_curated_file_hashes_file(path),
        );
        eprintln!(
            "    {} file hashes ({} bad sha skipped, {} unknown tags skipped)",
            parsed.records.len(),
            parsed.skipped_bad_sha,
            parsed.skipped_unknown_tags,
        );
        parsed
    } else {
        CuratedFileHashes::default()
    };

    // All source-derived records are now in memory. Recompute the complete
    // source transaction once more so a mutation racing the initial validation
    // cannot influence parsed records and then escape the signed metadata.
    if let (Some(binding), Some(inputs), Some(provenance)) = (
        source_binding.as_ref(),
        source_inputs.as_ref(),
        cli.source_provenance.as_deref(),
    ) {
        feed_error(
            "source provenance",
            provenance,
            binding.verify_inputs_unchanged(provenance, inputs),
        );
    }

    // Canonicalize network indicators once, before either writer or expectation
    // accounting. When feeds overlap, the numerically lowest stable source id is
    // the deterministic owner. Primary input floors are checked before this
    // projection, and published source/section drift is checked against the
    // signed baseline afterward.
    let mut hostname_indicators = BTreeMap::new();
    let mut ip_indicators = BTreeMap::new();
    let hostname_feeds: [(&[String], ThreatSource); 7] = [
        (&ossf_indicators.domains, ThreatSource::OssfMalicious),
        (&urlhaus_hosts, ThreatSource::Urlhaus),
        (&threatfox_hosts, ThreatSource::ThreatFoxIoc),
        (&phishing_army_hosts, ThreatSource::PhishingArmy),
        (&phishtank_hosts, ThreatSource::PhishTank),
        (&exfil_endpoint_hosts, ThreatSource::ExfilEndpoint),
        (&digitalside_hosts, ThreatSource::DigitalSide),
    ];
    for (hosts, source) in hostname_feeds {
        for host in hosts {
            insert_hostname_indicator(&mut hostname_indicators, host, source).unwrap_or_else(
                |error| {
                    eprintln!("error: invalid hostname IOC: {error}");
                    std::process::exit(1);
                },
            );
        }
    }

    for raw in &ossf_indicators.ips {
        let ip = raw.parse::<Ipv4Addr>().unwrap_or_else(|error| {
            eprintln!("error: invalid or unsupported OSSF IPv4 IOC {raw:?}: {error}");
            std::process::exit(1);
        });
        insert_ip_indicator(&mut ip_indicators, ip, ThreatSource::OssfMalicious);
    }
    for ip in &ips {
        insert_ip_indicator(&mut ip_indicators, *ip, ThreatSource::FeodoTracker);
    }
    for ip in &threatfox_ips {
        insert_ip_indicator(&mut ip_indicators, *ip, ThreatSource::ThreatFoxIoc);
    }
    for ip in &tor_exit_ips {
        insert_ip_indicator(&mut ip_indicators, *ip, ThreatSource::TorExit);
    }
    for ip in &digitalside_ips {
        insert_ip_indicator(&mut ip_indicators, *ip, ThreatSource::DigitalSide);
    }

    let expected_v1_popular_count = popular
        .iter()
        .map(|entry| (entry.ecosystem, entry.name.clone()))
        .collect::<BTreeSet<_>>()
        .len();
    let expected_v2_popular_count = popular
        .iter()
        .map(|entry| {
            (
                entry.ecosystem,
                canonical_package_name(entry.ecosystem, &entry.name),
            )
        })
        .collect::<BTreeSet<_>>()
        .len();
    let expected_v1_typosquat_count = typosquats
        .iter()
        .map(|entry| (entry.ecosystem, entry.name.clone()))
        .collect::<BTreeSet<_>>()
        .len();
    let expected_v2_typosquat_count = typosquats
        .iter()
        .map(|entry| {
            (
                entry.ecosystem,
                canonical_package_name(entry.ecosystem, &entry.name),
            )
        })
        .collect::<BTreeSet<_>>()
        .len();

    if cli
        .output_v2
        .as_ref()
        .is_some_and(|output_v2| output_v2 == &cli.output)
    {
        eprintln!("error: --output and --output-v2 must be distinct paths");
        std::process::exit(1);
    }
    if let Some(generation_manifest) = cli.generation_manifest.as_ref() {
        if generation_manifest == &cli.output
            || cli
                .output_v2
                .as_ref()
                .is_some_and(|output| output == generation_manifest)
        {
            eprintln!("error: --generation-manifest must be distinct from both DB outputs");
            std::process::exit(1);
        }
    } else if cli.output_v2.is_some() {
        eprintln!(
            "warning: dual direct-path outputs requested without --generation-manifest; compatibility mode does not provide pair-atomic visibility"
        );
    }
    if let Some(compiler_metadata) = cli.compiler_metadata.as_ref() {
        if compiler_metadata == &cli.output
            || cli
                .output_v2
                .as_ref()
                .is_some_and(|output| output == compiler_metadata)
            || cli
                .generation_manifest
                .as_ref()
                .is_some_and(|output| output == compiler_metadata)
            || cli
                .source_provenance
                .as_ref()
                .is_some_and(|input| input == compiler_metadata)
        {
            eprintln!("error: --compiler-metadata must be distinct from inputs and DB outputs");
            std::process::exit(1);
        }
    }
    if let Some(source_integrity) = cli.source_integrity_manifest.as_ref() {
        if source_integrity == &cli.output
            || cli
                .output_v2
                .as_ref()
                .is_some_and(|output| output == source_integrity)
            || cli
                .generation_manifest
                .as_ref()
                .is_some_and(|output| output == source_integrity)
            || cli
                .compiler_metadata
                .as_ref()
                .is_some_and(|output| output == source_integrity)
        {
            eprintln!(
                "error: --source-integrity-manifest must be distinct from DB and metadata outputs"
            );
            std::process::exit(1);
        }
    }
    if cli.generation_manifest.is_some()
        && (source_binding.is_none()
            || cli.compiler_metadata.is_none()
            || cli.source_integrity_manifest.is_none())
    {
        eprintln!(
            "error: a signed generation requires source provenance, compiler metadata, and a signed source-integrity sidecar"
        );
        std::process::exit(1);
    }

    let timestamp = chrono::Utc::now().timestamp() as u64;
    let sequence = cli.sequence.unwrap_or(timestamp);

    // Load signing key
    let signing_key = load_signing_key(cli.sign_key_env.as_deref(), cli.sign_key_file.as_deref());

    let signing_key = match signing_key {
        Some(k) => k,
        None => {
            eprintln!("error: signing key is required to build a valid DB");
            std::process::exit(1);
        }
    };

    let mut parser_sources = BTreeMap::new();
    let ossf_rejected = ossf_stats.skipped_withdrawn
        + ossf_stats.skipped_non_malicious
        + ossf_stats.skipped_unknown_ecosystem
        + ossf_stats.skipped_unreadable
        + ossf_stats.skipped_corrupt
        + ossf_stats.unsupported_confirmed_shapes
        + ossf_stats.snapshot_failures;
    parser_sources.insert(
        "ossf_malicious_packages".to_string(),
        CompilerParserCounts {
            accepted: ossf_stats.parsed_packages,
            rejected: ossf_rejected,
            details: BTreeMap::from([
                ("input_records".to_string(), ossf_stats.total_entries),
                (
                    "direct_whole_package_claims".to_string(),
                    ossf_stats.direct_whole_package_claims,
                ),
                (
                    "bounded_intervals_materialized".to_string(),
                    ossf_stats.bounded_intervals_materialized,
                ),
                (
                    "exact_versions_emitted".to_string(),
                    ossf_stats.exact_versions_emitted,
                ),
                ("withdrawn".to_string(), ossf_stats.skipped_withdrawn),
                (
                    "non_malicious".to_string(),
                    ossf_stats.skipped_non_malicious,
                ),
                (
                    "unsupported_confirmed_shapes".to_string(),
                    ossf_stats.unsupported_confirmed_shapes,
                ),
                (
                    "snapshot_failures".to_string(),
                    ossf_stats.snapshot_failures,
                ),
            ]),
        },
    );
    parser_sources.insert(
        "datadog_malicious_software_packages".to_string(),
        CompilerParserCounts {
            accepted: datadog_unique_packages,
            rejected: datadog_rejected_files,
            details: BTreeMap::from([
                ("files_read".to_string(), datadog_files_read),
                ("files_rejected".to_string(), datadog_rejected_files),
            ]),
        },
    );
    parser_sources.insert(
        "ecosystems_typosquatting_dataset".to_string(),
        CompilerParserCounts {
            accepted: typosquat_parse_stats.accepted,
            rejected: typosquat_parse_stats.rejected_unsupported_ecosystem
                + typosquat_parse_stats.rejected_pseudo_package,
            details: BTreeMap::from([
                (
                    "unsupported_ecosystem".to_string(),
                    typosquat_parse_stats.rejected_unsupported_ecosystem,
                ),
                (
                    "pseudo_package".to_string(),
                    typosquat_parse_stats.rejected_pseudo_package,
                ),
                (
                    "deduplicated".to_string(),
                    typosquat_parse_stats.deduplicated,
                ),
            ]),
        },
    );
    parser_sources.insert(
        "feodo_tracker_ipblocklist".to_string(),
        CompilerParserCounts {
            accepted: ips.len(),
            rejected: 0,
            details: BTreeMap::new(),
        },
    );
    parser_sources.insert(
        "cisa_known_exploited_vulnerabilities".to_string(),
        CompilerParserCounts {
            accepted: kev_count,
            rejected: 0,
            details: BTreeMap::new(),
        },
    );
    parser_sources.insert(
        "popular_package_comparison_index".to_string(),
        CompilerParserCounts {
            accepted: popular.len(),
            rejected: 0,
            details: BTreeMap::new(),
        },
    );
    let compiler_metadata = CompilerParseMetadata {
        schema_version: 1,
        compiler_version: env!("CARGO_PKG_VERSION").to_string(),
        parsed_at: chrono::DateTime::from_timestamp(timestamp as i64, 0)
            .expect("current timestamp is representable")
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        source_transaction_sha256: source_binding
            .as_ref()
            .map(|binding| binding.provenance_sha256.clone()),
        registry_snapshot_sha256: source_binding
            .as_ref()
            .map(|binding| binding.registry_snapshot_sha256.clone()),
        sources: parser_sources,
    };
    let compiler_metadata_data = cli.compiler_metadata.as_ref().map(|_| {
        let value = serde_json::to_value(&compiler_metadata).unwrap_or_else(|error| {
            eprintln!("error: cannot serialize compiler parse metadata: {error}");
            std::process::exit(1);
        });
        serde_json::to_vec(&value).unwrap_or_else(|error| {
            eprintln!("error: cannot encode compiler parse metadata: {error}");
            std::process::exit(1);
        })
    });
    let source_integrity_digests = source_binding
        .as_ref()
        .zip(compiler_metadata_data.as_deref())
        .map(|(binding, metadata)| SourceIntegrityDigests {
            source_transaction_sha256: binding.provenance_sha256.clone(),
            registry_snapshot_sha256: binding.registry_snapshot_sha256.clone(),
            compiler_metadata_sha256: sha256_hex(metadata),
        });

    let mut common_writer = ThreatDbWriter::new(timestamp, sequence);

    for (hostname, source) in &hostname_indicators {
        common_writer.add_hostname(hostname, *source);
    }
    for (ip, source) in &ip_indicators {
        common_writer.add_ip(*ip, *source);
    }

    for typo in &typosquats {
        common_writer.add_typosquat(typo.ecosystem, &typo.name, &typo.target_name);
    }

    for pop in &popular {
        common_writer.add_popular(pop.ecosystem, &pop.name);
    }

    // v2-only: persist the OpenSSF artifact-SHA and malicious-URL indicators
    // (DB-A's parsed model). These are ignored by a v1 build and only emitted
    // into the v2 file. Malformed artifact hashes are dropped, not written.
    let mut v2_skipped_bad_sha = 0usize;
    let mut v2_artifact_hashes = BTreeSet::new();
    for sha in &ossf_indicators.artifact_sha256 {
        match decode_sha256_hex(sha) {
            Some(bytes) => {
                v2_artifact_hashes.insert(bytes);
            }
            None => v2_skipped_bad_sha += 1,
        }
    }
    for bytes in &v2_artifact_hashes {
        common_writer.add_artifact_sha256(
            *bytes,
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            // The OSSF origin sha256 attests a specific analysis artifact,
            // not "all versions"; mark it as a specific match.
            false,
            None,
        );
    }
    // Malicious URLs come ONLY from explicit indicator fields (never OSSF
    // `references`, which DB-A already excludes from the indicator model).
    let mut v2_malicious_urls = BTreeSet::new();
    for url in &ossf_indicators.urls {
        let normalized = url.trim();
        if !normalized.is_empty() {
            v2_malicious_urls.insert(normalized.to_string());
        }
    }
    for url in &v2_malicious_urls {
        common_writer.add_malicious_url(url, ThreatSource::OssfMalicious);
    }

    // pr173-0024: the OpenSSF `iocs.ips` / `iocs.domains` were collected but
    // never written — connections to a listed IP/domain evaded the gate.
    // Emit them through the same writer as every other feed.
    let mut v2_ioc_ips = BTreeSet::new();
    for ip in &ossf_indicators.ips {
        if let Ok(addr) = ip.trim().parse::<std::net::Ipv4Addr>() {
            v2_ioc_ips.insert(addr);
        }
    }
    for addr in &v2_ioc_ips {
        common_writer.add_ip(*addr, ThreatSource::OssfMalicious);
    }
    let mut v2_ioc_domains = BTreeSet::new();
    for domain in &ossf_indicators.domains {
        let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if !normalized.is_empty() {
            v2_ioc_domains.insert(normalized);
        }
    }
    for domain in &v2_ioc_domains {
        common_writer.add_hostname(domain, ThreatSource::OssfMalicious);
    }

    // v2-only: persist the curated malicious file-content hashes into the FileHash
    // + BehaviorTags sections, so `check_file_sha256` goes live. Behavior tags and
    // the campaign label come ONLY from the feed's explicit structured fields
    // (never advisory prose). Both OSSF-derived and registry-yank provenance are
    // recorded under the Primary OssfMalicious source at Confirmed confidence; the
    // hash IS the positive indicator and the tags are correlation-only enrichment.
    let mut v2_file_hash_yank_count = 0usize;
    let mut unique_file_hashes = BTreeSet::new();
    for rec in &curated_file_hashes.records {
        if rec.provenance == FileHashProvenance::RegistryYank {
            v2_file_hash_yank_count += 1;
        }
        common_writer.add_file_sha256(
            rec.sha256,
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            &rec.behavior_tags,
            rec.campaign.as_deref(),
        );
        unique_file_hashes.insert(rec.sha256);
    }

    let v2_artifact_count = v2_artifact_hashes.len();
    let v2_url_count = v2_malicious_urls.len();
    let v2_file_hash_count = unique_file_hashes.len();
    let v1_source_expectations = expected_sources(
        &v1_packages,
        &hostname_indicators,
        &ip_indicators,
        expected_v1_typosquat_count,
        0,
        0,
        0,
    );
    let v2_source_expectations = expected_sources(
        &v2_packages,
        &hostname_indicators,
        &ip_indicators,
        expected_v2_typosquat_count,
        v2_artifact_count,
        v2_file_hash_count,
        v2_url_count,
    );
    let v2_artifact_hashes: Vec<[u8; 32]> = v2_artifact_hashes.into_iter().collect();
    let v2_malicious_urls: Vec<String> = v2_malicious_urls.into_iter().collect();

    let mut v1_writer = common_writer.clone();
    add_packages(&mut v1_writer, &v1_packages);
    let mut v2_writer = common_writer;
    add_packages(&mut v2_writer, &v2_packages);

    // Build both requested formats in memory first. Each is then written to a
    // same-directory staging file, reopened, structurally/source validated, and
    // signature-verified before either final output path is replaced.
    let data = v1_writer
        .build_format(ThreatDbFormat::V1, &signing_key)
        .unwrap_or_else(|e| {
            eprintln!("error: failed to build threat DB: {e}");
            std::process::exit(1);
        });

    let v2_data = cli.output_v2.as_ref().map(|_| {
        v2_writer
            .build_format(ThreatDbFormat::V2, &signing_key)
            .unwrap_or_else(|e| {
                eprintln!("error: failed to build v2 threat DB: {e}");
                std::process::exit(1);
            })
    });

    let v1_baseline =
        resolve_baseline(cli.baseline_v1.as_deref(), &cli.output).unwrap_or_else(|error| {
            eprintln!("error: cannot resolve v1 baseline: {error}");
            std::process::exit(1);
        });
    let v2_baseline = match cli.output_v2.as_ref() {
        Some(output) => {
            resolve_baseline(cli.baseline_v2.as_deref(), output).unwrap_or_else(|error| {
                eprintln!("error: cannot resolve v2 baseline: {error}");
                std::process::exit(1);
            })
        }
        None => None,
    };

    let v1_expectations = RoundTripExpectations {
        format: ThreatDbFormat::V1,
        sequence,
        package_count: v1_packages.len(),
        popular_count: expected_v1_popular_count,
        typosquat_count: expected_v1_typosquat_count,
        sources: &v1_source_expectations,
        artifact_hashes: &[],
        file_hashes: &curated_file_hashes,
        malicious_urls: &[],
        baseline: v1_baseline,
    };
    let staged_v1 = stage_database(&cli.output, &data, &signing_key, &v1_expectations)
        .unwrap_or_else(|e| {
            eprintln!("error: v1 output validation failed: {e}");
            std::process::exit(1);
        });

    let staged_v2 = cli
        .output_v2
        .as_ref()
        .zip(v2_data.as_ref())
        .map(|(v2_path, v2_data)| {
            let expectations = RoundTripExpectations {
                format: ThreatDbFormat::V2,
                sequence,
                package_count: v2_packages.len(),
                popular_count: expected_v2_popular_count,
                typosquat_count: expected_v2_typosquat_count,
                sources: &v2_source_expectations,
                artifact_hashes: &v2_artifact_hashes,
                file_hashes: &curated_file_hashes,
                malicious_urls: &v2_malicious_urls,
                baseline: v2_baseline,
            };
            stage_database(v2_path, v2_data, &signing_key, &expectations).unwrap_or_else(|e| {
                eprintln!("error: v2 output validation failed: {e}");
                std::process::exit(1);
            })
        });

    let generation_data = match (
        cli.generation_manifest.as_ref(),
        cli.generation_base_url.as_deref(),
        cli.output_v2.as_ref(),
        v2_data.as_deref(),
    ) {
        (Some(_), Some(base_url), Some(v2_path), Some(v2_bytes)) => Some(
            build_generation_manifest(
                sequence,
                &cli.output,
                &data,
                v2_path,
                v2_bytes,
                base_url,
                &cli.v2_min_tirith_version,
                &signing_key,
            )
            .unwrap_or_else(|error| {
                eprintln!("error: cannot build signed generation manifest: {error}");
                std::process::exit(1);
            }),
        ),
        (None, None, _, _) => None,
        _ => {
            eprintln!("error: incomplete signed-generation arguments");
            std::process::exit(1);
        }
    };
    let staged_generation = cli
        .generation_manifest
        .as_ref()
        .zip(generation_data.as_deref())
        .map(|(path, bytes)| {
            stage_generation_manifest(path, bytes, &signing_key).unwrap_or_else(|error| {
                eprintln!("error: generation manifest validation failed: {error}");
                std::process::exit(1);
            })
        });
    let source_integrity_data = match (
        cli.source_integrity_manifest.as_ref(),
        cli.output_v2.as_ref(),
        v2_data.as_deref(),
        source_integrity_digests.as_ref(),
    ) {
        (Some(_), Some(v2_path), Some(v2_bytes), Some(digests)) => Some(
            build_source_integrity_manifest(
                sequence,
                &cli.output,
                &data,
                v2_path,
                v2_bytes,
                digests,
                &signing_key,
            )
            .unwrap_or_else(|error| {
                eprintln!("error: cannot build signed source-integrity manifest: {error}");
                std::process::exit(1);
            }),
        ),
        (None, _, _, _) => None,
        _ => {
            eprintln!("error: incomplete source-integrity sidecar arguments");
            std::process::exit(1);
        }
    };
    let staged_source_integrity = cli
        .source_integrity_manifest
        .as_ref()
        .zip(source_integrity_data.as_deref())
        .map(|(path, bytes)| {
            stage_source_integrity_manifest(path, bytes, &signing_key).unwrap_or_else(|error| {
                eprintln!("error: source-integrity manifest validation failed: {error}");
                std::process::exit(1);
            })
        });
    let staged_compiler_metadata = cli
        .compiler_metadata
        .as_ref()
        .zip(compiler_metadata_data.as_deref())
        .map(|(path, bytes)| {
            stage_compiler_metadata(path, bytes).unwrap_or_else(|error| {
                eprintln!("error: compiler metadata validation failed: {error}");
                std::process::exit(1);
            })
        });

    publish_compiled_generation(
        staged_v1,
        &cli.output,
        staged_v2.zip(cli.output_v2.as_deref()),
        staged_generation.zip(cli.generation_manifest.as_deref()),
        StagedAuxiliaryArtifacts {
            compiler_metadata: staged_compiler_metadata.zip(cli.compiler_metadata.as_deref()),
            source_integrity: staged_source_integrity.zip(cli.source_integrity_manifest.as_deref()),
        },
        publish_staged_immutable,
        publish_staged,
    )
    .unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });

    if let (Some(v2_path), Some(v2_data)) = (cli.output_v2.as_ref(), v2_data.as_ref()) {
        eprintln!(
            "  v2 output:             {} ({} bytes; {} artifact sha256, {} file sha256 ({} yank), {} urls; {} bad sha skipped)",
            v2_path.display(),
            v2_data.len(),
            v2_artifact_count,
            v2_file_hash_count,
            v2_file_hash_yank_count,
            v2_url_count,
            v2_skipped_bad_sha,
        );
    }

    let ecosystems_seen: BTreeSet<String> = v2_packages
        .iter()
        .map(|p| format!("{:?}", p.ecosystem))
        .collect();

    eprintln!();
    eprintln!("=== Threat DB compilation complete ===");
    eprintln!("  output:                {}", cli.output.display());
    eprintln!("  file size:             {} bytes", data.len());
    eprintln!("  packages (v1):         {}", v1_packages.len());
    eprintln!("  network IPv4 IOCs:     {}", ip_indicators.len());
    eprintln!("  typosquats:            {}", typosquats.len());
    eprintln!("  popular packages:      {}", popular.len());
    eprintln!("  CISA KEV CVEs:         {}", kev_count);
    eprintln!(
        "  OSSF whole/bounded:     {}/{}",
        ossf_stats.direct_whole_package_claims, ossf_stats.bounded_intervals_materialized
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
    use tirith_core::threatdb::BehaviorTag;

    fn write_mal(root: &Path, file: &str, json: &str) {
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(root.join(file), json).unwrap();
    }

    #[derive(Default)]
    struct SpyRegistryVersions {
        calls: Vec<RegistryPackageKey>,
        versions: BTreeMap<RegistryPackageKey, Vec<String>>,
    }

    impl RegistryVersionProvider for SpyRegistryVersions {
        fn versions_for(&mut self, key: &RegistryPackageKey) -> FeedResult<Vec<String>> {
            self.calls.push(key.clone());
            self.versions
                .get(key)
                .cloned()
                .ok_or_else(|| format!("missing spy universe for {}", key.name))
        }
    }

    #[test]
    fn test_v1_normalize_pypi_preserves_legacy_separator_bytes() {
        assert_eq!(normalize_name(Ecosystem::PyPI, "My_Package"), "my-package");
        assert_eq!(normalize_name(Ecosystem::PyPI, "my.package"), "my-package");
        assert_eq!(normalize_name(Ecosystem::PyPI, "MY-PACKAGE"), "my-package");
        assert_eq!(
            normalize_name(Ecosystem::PyPI, "FrIeNdLy-._.-BaRd"),
            "friendly-----bard"
        );
    }

    #[test]
    fn test_normalize_npm_case_sensitive() {
        assert_eq!(normalize_name(Ecosystem::Npm, "Express"), "Express");
        assert_eq!(normalize_name(Ecosystem::Npm, "@scope/Pkg"), "@scope/Pkg");
    }

    #[test]
    fn test_v1_normalize_crates_preserves_legacy_underscore_key() {
        assert_eq!(
            normalize_name(Ecosystem::Crates, "Serde_JSON"),
            "serde_json"
        );
        assert_eq!(
            normalize_name(Ecosystem::Crates, "serde-json"),
            "serde-json"
        );
    }

    #[test]
    fn test_normalize_nuget_case_insensitive() {
        assert_eq!(
            normalize_name(Ecosystem::NuGet, "Newtonsoft.JSON"),
            "newtonsoft.json"
        );
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

        let deduped = project_v1_packages(entries);
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

        let deduped = project_v1_packages(entries);
        assert_eq!(deduped.len(), 1);
        assert!(deduped[0].all_versions_malicious);
    }

    #[test]
    fn v2_projection_preserves_cross_source_scope_and_confidence_claims() {
        let all_versions = PackageEntry {
            ecosystem: Ecosystem::PyPI,
            name: "collision-pkg".to_string(),
            affected_versions: Vec::new(),
            all_versions_malicious: true,
            source: ThreatSource::DatadogMalicious,
            confidence: Confidence::Medium,
            reference: Some("https://example.invalid/all".to_string()),
        };
        let version_specific = PackageEntry {
            ecosystem: Ecosystem::PyPI,
            name: "collision-pkg".to_string(),
            affected_versions: vec!["1.0".to_string()],
            all_versions_malicious: false,
            source: ThreatSource::OssfMalicious,
            confidence: Confidence::Confirmed,
            reference: Some("https://example.invalid/specific".to_string()),
        };

        let claims = preserve_v2_package_claims(vec![all_versions, version_specific]);
        assert_eq!(claims.len(), 2);
        assert!(claims.iter().any(|claim| {
            claim.all_versions_malicious
                && claim.confidence == Confidence::Medium
                && claim.source == ThreatSource::DatadogMalicious
        }));
        assert!(claims.iter().any(|claim| {
            !claim.all_versions_malicious
                && claim.confidence == Confidence::Confirmed
                && claim.source == ThreatSource::OssfMalicious
                && claim.affected_versions == vec!["1.0".to_string()]
        }));

        let key = SigningKey::from_bytes(&[8u8; 32]);
        let mut writer = ThreatDbWriter::new(1_700_000_000, 1);
        add_packages(&mut writer, &claims);
        let bytes = writer
            .build_format(ThreatDbFormat::V2, &key)
            .expect("v2 build");
        let db = ThreatDb::from_bytes(bytes, 0).expect("v2 load");
        assert_eq!(db.stats().package_count, 2);
        assert_eq!(
            db.source_breakdown()
                .section_counts_for(ThreatSource::OssfMalicious)
                .package_count,
            1
        );
        assert_eq!(
            db.source_breakdown()
                .section_counts_for(ThreatSource::DatadogMalicious)
                .package_count,
            1
        );
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

        let ips = parse_feodo(&path).unwrap();
        assert_eq!(ips.len(), 3);
        assert_eq!(ips[0], "1.2.3.4".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn test_popular_csv_parsing() {
        let entries =
            parse_popular_from_string("ecosystem,name\nnpm,express\npypi,requests\n").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ecosystem, Ecosystem::Npm);
        assert_eq!(entries[0].name, "express");
        assert_eq!(entries[1].ecosystem, Ecosystem::PyPI);
        assert_eq!(entries[1].name, "requests");
    }

    #[test]
    fn test_default_popular_csv_loads() {
        let entries = parse_popular_csv(None).unwrap();
        assert!(
            entries.len() >= 50,
            "expected at least 50 popular packages, got {}",
            entries.len()
        );
        for anchor in [
            "ethers",
            "web3",
            "viem",
            "wagmi",
            "@solana/kit",
            "@solana/web3.js",
            "hardhat",
            "@openzeppelin/contracts",
            "@ledgerhq/hw-app-eth",
        ] {
            assert!(entries
                .iter()
                .any(|entry| { entry.ecosystem == Ecosystem::Npm && entry.name == anchor }));
        }
        assert!(!entries
            .iter()
            .any(|entry| entry.ecosystem == Ecosystem::Npm && entry.name == "foundry"));
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
    fn test_ossf_confidence_mapping() {
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

        // An unrecognized but PRESENT type falls back to Medium and emits a warning,
        // for BOTH a non-MAL and a MAL- id: an explicit (if unrecognized) type takes
        // precedence, so MAL- promotion applies only to TYPELESS records (tested above).
        assert_eq!(
            ossf_confidence("OSV-2025-0002", Some("BRAND_NEW_TYPE")),
            Confidence::Medium
        );
        assert_eq!(
            ossf_confidence("MAL-2026-9999", Some("BRAND_NEW_TYPE")),
            Confidence::Medium
        );

        // G1: the curated file-hash companion feed maps to the same Confirmed
        // confidence the artifact-SHA records use, regardless of provenance
        // (OSSF-derived or registry-yank). Behavior tags ride along as structured
        // enrichment only and never change the confidence: a record with rich
        // tags and a bare record both resolve to Confirmed.
        let sha = "e".repeat(64);
        let rich = parse_curated_file_hashes(&format!(
            "{sha}  tags=process_spawn,credential_access  campaign=miasma  source=ossf\n"
        ));
        let bare = parse_curated_file_hashes(&format!("{sha}  source=registry-yank\n"));
        assert_eq!(rich.records.len(), 1);
        assert_eq!(bare.records.len(), 1);
        // The compiler writes every curated file hash at Confirmed (see the
        // add_file_sha256 call), independent of how many tags it carries.
        assert_eq!(
            rich.records[0].provenance,
            FileHashProvenance::OssfMalicious
        );
        assert_eq!(bare.records[0].provenance, FileHashProvenance::RegistryYank);
        assert!(rich.records[0]
            .behavior_tags
            .contains(&BehaviorTag::CredentialAccess));
        assert!(bare.records[0].behavior_tags.is_empty());
    }

    // Real OpenSSF malicious-packages records fetched from the OSV API and
    // vendored as fixtures. The parser structs are derived from these actual
    // shapes (indicators under entry-level `database_specific.iocs` /
    // `malicious-packages-origins`, not `affected[].database_specific`).
    const MAL_2025_6812: &str = include_str!("fixtures/mal-2025-6812.json");
    const MAL_2026_2307: &str = include_str!("fixtures/mal-2026-2307.json");
    const C01_WHOLE_PACKAGE: &str = include_str!("fixtures/threatdb-c01/MAL-whole-package.json");
    const C01_SOLANA_BOUNDED: &str =
        include_str!("fixtures/threatdb-c01/MAL-solana-web3-bounded.json");
    const C01_REGISTRY_VERSIONS: &str =
        include_str!("fixtures/threatdb-c01/registry-versions.json");

    fn fixture_snapshot_binding(snapshot_path: &Path) -> SourceTransactionBinding {
        let bytes = std::fs::read(snapshot_path).unwrap();
        let document: RegistrySnapshotDocument = serde_json::from_slice(&bytes).unwrap();
        SourceTransactionBinding {
            provenance_sha256: "11".repeat(32),
            registry_snapshot_sha256: sha256_hex(&bytes),
            ossf_commit: document.ossf_commit,
            registry_retrieved_at: document.retrieved_at,
            registry_packages: document.packages.len(),
        }
    }

    fn fixture_source_integrity_digests() -> SourceIntegrityDigests {
        SourceIntegrityDigests {
            source_transaction_sha256: "11".repeat(32),
            registry_snapshot_sha256: "22".repeat(32),
            compiler_metadata_sha256: "33".repeat(32),
        }
    }

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
    fn whole_package_range_bypasses_registry_provider() {
        let directory = tempfile::tempdir().unwrap();
        write_mal(directory.path(), "MAL-2099-0001.json", C01_WHOLE_PACKAGE);
        let mut spy = SpyRegistryVersions::default();
        let (entries, stats, _) =
            parse_ossf_with_provider(directory.path(), Some(&mut spy)).unwrap();
        assert!(spy.calls.is_empty(), "whole-package claims must not fetch");
        assert_eq!(stats.direct_whole_package_claims, 1);
        assert_eq!(stats.bounded_intervals_materialized, 0);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].all_versions_malicious);
    }

    #[test]
    fn bounded_introduced_zero_closures_materialize_exactly() {
        for (close_key, close_value, expected) in [
            ("fixed", "1.2.0", vec!["0.9.0", "1.0.0", "1.1.9"]),
            ("last_affected", "1.1.9", vec!["0.9.0", "1.0.0", "1.1.9"]),
            ("limit", "1.2.0", vec!["0.9.0", "1.0.0", "1.1.9"]),
        ] {
            let directory = tempfile::tempdir().unwrap();
            write_mal(
                directory.path(),
                "MAL-2099-0002.json",
                &format!(
                    r#"{{
                        "id":"MAL-2099-0002",
                        "affected":[{{
                            "package":{{"ecosystem":"npm","name":"bounded-package"}},
                            "versions":["2.5.0"],
                            "ranges":[{{"type":"ECOSYSTEM","events":[
                                {{"introduced":"0"}},{{"{close_key}":"{close_value}"}}
                            ]}}]
                        }}]
                    }}"#
                ),
            );
            let key = RegistryPackageKey {
                ecosystem: Ecosystem::Npm,
                name: "bounded-package".to_string(),
            };
            let mut spy = SpyRegistryVersions::default();
            spy.versions.insert(
                key.clone(),
                ["0.9.0", "1.0.0", "1.1.9", "1.2.0", "2.0.0"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            );
            let (entries, stats, _) =
                parse_ossf_with_provider(directory.path(), Some(&mut spy)).unwrap();
            assert_eq!(spy.calls, vec![key]);
            assert!(!entries[0].all_versions_malicious);
            let mut expected = expected.into_iter().map(str::to_string).collect::<Vec<_>>();
            expected.push("2.5.0".to_string());
            expected.sort();
            assert_eq!(entries[0].affected_versions, expected);
            assert_eq!(stats.bounded_intervals_materialized, 1);
        }
    }

    #[test]
    fn pypi_bounded_ranges_use_core_pep440_precedence() {
        let cases = [
            (
                r#"[{"introduced":"0"},{"fixed":"1.0"}]"#,
                vec!["0.9", "1.0.dev1", "1.0a1", "1.0rc1"],
            ),
            (
                r#"[{"introduced":"1.0"},{"last_affected":"1.0"}]"#,
                vec!["1.0", "1.0+vendor.1"],
            ),
            (
                r#"[{"introduced":"1.0.post1.dev1"},{"limit":"1.0.post2"}]"#,
                vec!["1.0.post1.dev1", "1.0.post1"],
            ),
        ];
        for (events, expected) in cases {
            let directory = tempfile::tempdir().unwrap();
            write_mal(
                directory.path(),
                "MAL-2099-0010.json",
                &format!(
                    r#"{{
                        "id":"MAL-2099-0010",
                        "affected":[{{
                            "package":{{"ecosystem":"PyPI","name":"Pep.Package"}},
                            "ranges":[{{"type":"ECOSYSTEM","events":{events}}}]
                        }}]
                    }}"#
                ),
            );
            let key = RegistryPackageKey {
                ecosystem: Ecosystem::PyPI,
                name: "pep-package".to_string(),
            };
            let mut spy = SpyRegistryVersions::default();
            spy.versions.insert(
                key.clone(),
                [
                    "0.9",
                    "1.0.dev1",
                    "1.0a1",
                    "1.0rc1",
                    "1.0",
                    "1.0+vendor.1",
                    "1.0.post1.dev1",
                    "1.0.post1",
                    "1.0.post2",
                ]
                .into_iter()
                .map(str::to_string)
                .collect(),
            );
            let (entries, _, _) =
                parse_ossf_with_provider(directory.path(), Some(&mut spy)).unwrap();
            assert_eq!(spy.calls, vec![key]);
            let mut expected = expected.into_iter().map(str::to_string).collect::<Vec<_>>();
            expected.sort();
            assert_eq!(entries[0].affected_versions, expected);
        }
    }

    #[test]
    fn bounded_multiple_intervals_prereleases_and_unique_request_set() {
        let directory = tempfile::tempdir().unwrap();
        for (file, id) in [
            ("MAL-2099-0003.json", "MAL-2099-0003"),
            ("MAL-2099-0004.json", "MAL-2099-0004"),
        ] {
            write_mal(
                directory.path(),
                file,
                &format!(
                    r#"{{
                        "id":"{id}",
                        "affected":[{{
                            "package":{{"ecosystem":"npm","name":"multi-package"}},
                            "ranges":[{{"type":"ECOSYSTEM","events":[
                                {{"introduced":"1.0.0-beta.1"}},{{"fixed":"1.0.0"}},
                                {{"introduced":"2.0.0"}},{{"limit":"2.1.0"}}
                            ]}}]
                        }}]
                    }}"#
                ),
            );
        }
        let key = RegistryPackageKey {
            ecosystem: Ecosystem::Npm,
            name: "multi-package".to_string(),
        };
        let mut spy = SpyRegistryVersions::default();
        spy.versions.insert(
            key.clone(),
            [
                "1.0.0-alpha.1",
                "1.0.0-beta.1",
                "1.0.0-rc.1",
                "1.0.0",
                "2.0.0",
                "2.0.5",
                "2.1.0",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
        );
        let (entries, stats, _) =
            parse_ossf_with_provider(directory.path(), Some(&mut spy)).unwrap();
        assert_eq!(
            spy.calls,
            vec![key],
            "duplicate bounded packages fetch once"
        );
        assert_eq!(entries.len(), 2);
        for entry in entries {
            assert_eq!(
                entry.affected_versions,
                ["1.0.0-beta.1", "1.0.0-rc.1", "2.0.0", "2.0.5"]
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            );
            assert!(!entry.all_versions_malicious);
        }
        assert_eq!(stats.bounded_intervals_materialized, 4);
    }

    #[test]
    fn confirmed_unrepresentable_range_shapes_fail_publication() {
        for events_or_range in [
            r#"{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"}]}"#,
            r#"{"type":"GIT","events":[{"introduced":"0"},{"fixed":"abc"}]}"#,
            r#"{"type":"ECOSYSTEM","events":[{"fixed":"1.0.0"}]}"#,
            r#"{"type":"ECOSYSTEM","events":[{"introduced":"0","fixed":"1.0.0"}]}"#,
            r#"{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"introduced":"1.0.0"}]}"#,
        ] {
            let directory = tempfile::tempdir().unwrap();
            write_mal(
                directory.path(),
                "MAL-2099-0005.json",
                &format!(
                    r#"{{
                        "id":"MAL-2099-0005",
                        "affected":[{{
                            "package":{{"ecosystem":"npm","name":"unsupported-package"}},
                            "ranges":[{events_or_range}]
                        }}]
                    }}"#
                ),
            );
            assert!(parse_ossf(directory.path()).is_err(), "{events_or_range}");
        }
    }

    #[test]
    fn whole_package_interval_does_not_hide_contradictory_sibling_ranges() {
        for close_key in ["fixed", "last_affected", "limit"] {
            let directory = tempfile::tempdir().unwrap();
            write_mal(
                directory.path(),
                "MAL-2099-0011.json",
                &format!(
                    r#"{{
                        "id":"MAL-2099-0011",
                        "affected":[{{
                            "package":{{"ecosystem":"npm","name":"mixed-whole-package"}},
                            "ranges":[
                                {{"type":"ECOSYSTEM","events":[{{"introduced":"0"}}]}},
                                {{"type":"ECOSYSTEM","events":[
                                    {{"introduced":"2.0.0"}},{{"{close_key}":"1.0.0"}}
                                ]}}
                            ]
                        }}]
                    }}"#
                ),
            );
            let error = parse_ossf(directory.path())
                .expect_err("a whole-package sibling must not suppress interval validation");
            assert!(
                error.contains("contradictory affected interval"),
                "{close_key}: {error}"
            );
        }
    }

    #[test]
    fn whole_package_interval_does_not_hide_invalid_zero_based_closures() {
        for close_key in ["fixed", "last_affected", "limit"] {
            let directory = tempfile::tempdir().unwrap();
            write_mal(
                directory.path(),
                "MAL-2099-0012.json",
                &format!(
                    r#"{{
                        "id":"MAL-2099-0012",
                        "affected":[{{
                            "package":{{"ecosystem":"npm","name":"mixed-invalid-close"}},
                            "ranges":[
                                {{"type":"ECOSYSTEM","events":[{{"introduced":"0"}}]}},
                                {{"type":"ECOSYSTEM","events":[
                                    {{"introduced":"0"}},{{"{close_key}":"not-semver"}}
                                ]}}
                            ]
                        }}]
                    }}"#
                ),
            );
            let error = parse_ossf(directory.path())
                .expect_err("a whole-package sibling must not suppress close validation");
            assert!(
                error.contains("unsupported npm version boundary"),
                "{close_key}: {error}"
            );
        }
    }

    #[test]
    fn withdrawn_records_are_counted_and_do_not_publish() {
        let directory = tempfile::tempdir().unwrap();
        write_mal(
            directory.path(),
            "MAL-2099-0006.json",
            r#"{
                "id":"MAL-2099-0006",
                "withdrawn":"2099-01-01T00:00:00Z",
                "affected":[{"package":{"ecosystem":"npm","name":"withdrawn"},"versions":["1.0.0"]}]
            }"#,
        );
        write_mal(
            directory.path(),
            "MAL-2099-0007.json",
            r#"{
                "id":"MAL-2099-0007",
                "affected":[{"package":{"ecosystem":"npm","name":"active"},"versions":["1.0.0"]}]
            }"#,
        );
        let (entries, stats, _) = parse_ossf(directory.path()).unwrap();
        assert_eq!(stats.skipped_withdrawn, 1);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "active");
    }

    #[test]
    fn solana_web3_bounded_versions_round_trip_without_false_whole_package_bit() {
        let directory = tempfile::tempdir().unwrap();
        write_mal(directory.path(), "MAL-2099-0008.json", C01_SOLANA_BOUNDED);
        let snapshot_path = directory.path().join("registry-versions.json");
        std::fs::write(&snapshot_path, C01_REGISTRY_VERSIONS).unwrap();
        let binding = fixture_snapshot_binding(&snapshot_path);
        let mut snapshot = RegistrySnapshotStore::load(&snapshot_path, &binding).unwrap();
        let (entries, _, _) =
            parse_ossf_with_provider(directory.path(), Some(&mut snapshot)).unwrap();
        snapshot.ensure_fully_consumed().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].affected_versions, ["1.95.6", "1.95.7"]);
        assert!(!entries[0].all_versions_malicious);

        let signing_key = SigningKey::from_bytes(&[49u8; 32]);
        let mut writer = ThreatDbWriter::new(1_700_000_000, 1);
        add_packages(&mut writer, &entries);
        let database = ThreatDb::from_bytes(
            writer
                .build_format(ThreatDbFormat::V1, &signing_key)
                .unwrap(),
            0,
        )
        .unwrap();
        assert!(database
            .check_package(Ecosystem::Npm, "@solana/web3.js", Some("1.95.5"))
            .is_none());
        for bad in ["1.95.6", "1.95.7"] {
            assert!(database
                .check_package(Ecosystem::Npm, "@solana/web3.js", Some(bad))
                .is_some());
        }
        assert!(database
            .check_package(Ecosystem::Npm, "@solana/web3.js", Some("1.95.8"))
            .is_none());
        assert!(matches!(
            database.assess_package(
                Ecosystem::Npm,
                "@solana/web3.js",
                &tirith_core::version_intent::VersionIntent::Unspecified
            ),
            tirith_core::threatdb::PackageThreatAssessment::Unresolved { .. }
        ));
    }

    #[test]
    fn registry_snapshot_rejects_stale_commit_and_wrong_digest() {
        let directory = tempfile::tempdir().unwrap();
        let snapshot_path = directory.path().join("registry-versions.json");
        std::fs::write(&snapshot_path, C01_REGISTRY_VERSIONS).unwrap();
        let mut binding = fixture_snapshot_binding(&snapshot_path);
        binding.ossf_commit = "22".repeat(20);
        assert!(RegistrySnapshotStore::load(&snapshot_path, &binding)
            .unwrap_err()
            .contains("does not match expected"));

        let mut binding = fixture_snapshot_binding(&snapshot_path);
        binding.registry_snapshot_sha256 = "33".repeat(32);
        assert!(RegistrySnapshotStore::load(&snapshot_path, &binding)
            .unwrap_err()
            .contains("digest changed"));
    }

    #[test]
    fn registry_snapshot_rejects_wrong_url_and_response_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let snapshot_path = directory.path().join("registry-versions.json");
        let mut document: serde_json::Value = serde_json::from_str(C01_REGISTRY_VERSIONS).unwrap();
        document["packages"][0]["source_url"] =
            serde_json::json!("https://registry.npmjs.org/@solana%2Fweb3.js/redirected");
        std::fs::write(&snapshot_path, serde_json::to_vec(&document).unwrap()).unwrap();
        let binding = fixture_snapshot_binding(&snapshot_path);
        assert!(RegistrySnapshotStore::load(&snapshot_path, &binding)
            .unwrap_err()
            .contains("unexpected source URL"));

        document["packages"][0]["source_url"] =
            serde_json::json!("https://registry.npmjs.org/@solana%2Fweb3.js");
        document["packages"][0]["response_bytes"] = serde_json::json!(0);
        std::fs::write(&snapshot_path, serde_json::to_vec(&document).unwrap()).unwrap();
        let binding = fixture_snapshot_binding(&snapshot_path);
        assert!(RegistrySnapshotStore::load(&snapshot_path, &binding)
            .unwrap_err()
            .contains("outside caps"));
    }

    #[test]
    fn source_provenance_binds_exact_snapshot_revision_digest_and_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let snapshot_path = directory.path().join("registry-versions.json");
        std::fs::write(&snapshot_path, C01_REGISTRY_VERSIONS).unwrap();
        let snapshot_bytes = std::fs::read(&snapshot_path).unwrap();
        let provenance_path = directory.path().join("source-provenance.json");
        let provenance = serde_json::json!({
            "schema_version": 2,
            "retrieved_at": "2026-08-08T00:00:01Z",
            "compiler_version": env!("CARGO_PKG_VERSION"),
            "ossf_malicious_packages": {
                "source_url": "https://github.com/ossf/malicious-packages.git",
                "ref": "1ea2762d5fb415aef003a244d5aa83c5fc48cc6e",
                "commit": "1ea2762d5fb415aef003a244d5aa83c5fc48cc6e",
                "spdx": "CC-BY-4.0", "files": 1, "bytes": 1,
                "content_sha256": "11".repeat(32)
            },
            "datadog_malicious_software_packages": {
                "source_url": "https://github.com/DataDog/malicious-software-packages-dataset.git",
                "ref": "ef4a781d476cd6eb89c8517ff9adbb54a5cfa8cc",
                "commit": "ef4a781d476cd6eb89c8517ff9adbb54a5cfa8cc",
                "spdx": "Apache-2.0", "files": 2, "bytes": 2,
                "content_sha256": "22".repeat(32)
            },
            "ecosystems_typosquatting_dataset": {
                "source_url": "https://github.com/ecosyste-ms/typosquatting-dataset.git",
                "ref": "fd0bde98d200efe5c282a07edc4c68fba13252c6",
                "commit": "fd0bde98d200efe5c282a07edc4c68fba13252c6",
                "spdx": "CC0-1.0", "files": 1, "rows": 100, "bytes": 3,
                "content_sha256": "33".repeat(32)
            },
            "registry_version_snapshot": {
                "ossf_commit": "1ea2762d5fb415aef003a244d5aa83c5fc48cc6e",
                "retrieved_at": "2026-08-08T00:00:00Z",
                "source_urls": ["https://registry.npmjs.org/", "https://pypi.org/pypi/"],
                "spdx": "LicenseRef-Registry-Metadata", "packages": 1,
                "bytes": snapshot_bytes.len(), "sha256": sha256_hex(&snapshot_bytes)
            },
            "feodo_tracker_ipblocklist": {
                "source_url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                "spdx": "LicenseRef-abuse-ch-terms", "files": 1, "bytes": 4,
                "sha256": "44".repeat(32)
            },
            "cisa_known_exploited_vulnerabilities": {
                "source_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "spdx": "LicenseRef-US-Government-Work", "files": 1, "bytes": 5,
                "sha256": "55".repeat(32)
            },
            "web3_package_anchors": {
                "source_url": "repository:crates/tirith/assets/data/web3_package_anchors.csv",
                "spdx": "LicenseRef-Package-Name-Facts", "files": 1, "bytes": 1,
                "content_sha256": "66".repeat(32)
            }
        });
        std::fs::write(&provenance_path, serde_json::to_vec(&provenance).unwrap()).unwrap();
        let binding =
            SourceTransactionBinding::load_provenance_only(&provenance_path, &snapshot_path)
                .unwrap();
        assert_eq!(
            binding.registry_snapshot_sha256,
            sha256_hex(&snapshot_bytes)
        );
        assert_eq!(binding.registry_packages, 1);

        let mut altered = provenance;
        altered["registry_version_snapshot"]["sha256"] = serde_json::json!("66".repeat(32));
        std::fs::write(&provenance_path, serde_json::to_vec(&altered).unwrap()).unwrap();
        assert!(
            SourceTransactionBinding::load_provenance_only(&provenance_path, &snapshot_path)
                .unwrap_err()
                .contains("do not match source provenance")
        );
    }

    #[test]
    fn every_staged_source_mutation_breaks_canonical_provenance_binding() {
        let directory = tempfile::tempdir().unwrap();
        let ossf = directory.path().join("ossf");
        let datadog = directory.path().join("datadog");
        let typosquat_root = directory.path().join("typosquats");
        let feodo = directory.path().join("feodo.txt");
        let cisa = directory.path().join("cisa.json");
        let anchors = directory.path().join("web3_package_anchors.csv");
        std::fs::create_dir_all(ossf.join("osv/npm")).unwrap();
        std::fs::create_dir_all(datadog.join("samples/npm")).unwrap();
        std::fs::create_dir_all(datadog.join("samples/pypi")).unwrap();
        std::fs::create_dir_all(&typosquat_root).unwrap();
        let ossf_file = ossf.join("osv/npm/MAL-2099-0001.json");
        let datadog_npm = datadog.join("samples/npm/manifest.json");
        let datadog_pypi = datadog.join("samples/pypi/manifest.json");
        let typosquats = typosquat_root.join("typosquats.csv");
        let originals: Vec<(&Path, &[u8])> = vec![
            (&ossf_file, br#"{"id":"MAL-2099-0001"}"#),
            (&datadog_npm, br#"{"bad":null}"#),
            (&datadog_pypi, br#"{"bad":null}"#),
            (&typosquats, b"malicious_package,target_package\nbad,good\n"),
            (&feodo, b"203.0.113.1\n"),
            (&cisa, br#"{"vulnerabilities":[]}"#),
            (&anchors, WEB3_PACKAGE_ANCHORS_CSV.as_bytes()),
        ];
        for (path, bytes) in &originals {
            std::fs::write(path, bytes).unwrap();
        }
        let inputs = SourceInputPaths {
            ossf: &ossf,
            datadog: &datadog,
            typosquats: &typosquats,
            feodo: &feodo,
            cisa_kev: &cisa,
            web3_anchors: &anchors,
        };
        let ossf_summary =
            canonical_source_summary(&ossf, &collect_tree_source_paths(&ossf, "osv").unwrap())
                .unwrap();
        let datadog_summary = canonical_source_summary(
            &datadog,
            &[
                PathBuf::from("samples/npm/manifest.json"),
                PathBuf::from("samples/pypi/manifest.json"),
            ],
        )
        .unwrap();
        let typosquat_summary =
            canonical_source_summary(&typosquat_root, &[PathBuf::from("typosquats.csv")]).unwrap();
        let anchor_summary = canonical_source_summary(
            anchors.parent().unwrap(),
            &[PathBuf::from("web3_package_anchors.csv")],
        )
        .unwrap();
        let document: SourceProvenanceDocument = serde_json::from_value(serde_json::json!({
            "schema_version": 2,
            "retrieved_at": "2026-08-08T00:00:00Z",
            "compiler_version": env!("CARGO_PKG_VERSION"),
            "ossf_malicious_packages": {
                "source_url": "https://github.com/ossf/malicious-packages.git",
                "ref": "11".repeat(20), "commit": "11".repeat(20), "spdx": "CC-BY-4.0",
                "files": ossf_summary.files, "bytes": ossf_summary.bytes,
                "content_sha256": ossf_summary.content_sha256
            },
            "datadog_malicious_software_packages": {
                "source_url": "https://github.com/DataDog/malicious-software-packages-dataset.git",
                "ref": "22".repeat(20), "commit": "22".repeat(20), "spdx": "Apache-2.0",
                "files": datadog_summary.files, "bytes": datadog_summary.bytes,
                "content_sha256": datadog_summary.content_sha256
            },
            "ecosystems_typosquatting_dataset": {
                "source_url": "https://github.com/ecosyste-ms/typosquatting-dataset.git",
                "ref": "33".repeat(20), "commit": "33".repeat(20), "spdx": "CC0-1.0",
                "files": typosquat_summary.files, "rows": 1, "bytes": typosquat_summary.bytes,
                "content_sha256": typosquat_summary.content_sha256
            },
            "registry_version_snapshot": {
                "ossf_commit": "11".repeat(20), "retrieved_at": "2026-08-08T00:00:00Z",
                "source_urls": ["https://registry.npmjs.org/", "https://pypi.org/pypi/"],
                "spdx": "LicenseRef-Registry-Metadata", "packages": 0, "bytes": 1,
                "sha256": "44".repeat(32)
            },
            "feodo_tracker_ipblocklist": {
                "source_url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                "spdx": "LicenseRef-abuse-ch-terms", "files": 1,
                "bytes": std::fs::read(&feodo).unwrap().len(),
                "sha256": sha256_hex(&std::fs::read(&feodo).unwrap())
            },
            "cisa_known_exploited_vulnerabilities": {
                "source_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "spdx": "LicenseRef-US-Government-Work", "files": 1,
                "bytes": std::fs::read(&cisa).unwrap().len(),
                "sha256": sha256_hex(&std::fs::read(&cisa).unwrap())
            },
            "web3_package_anchors": {
                "source_url": "repository:crates/tirith/assets/data/web3_package_anchors.csv",
                "spdx": "LicenseRef-Package-Name-Facts", "files": anchor_summary.files,
                "bytes": anchor_summary.bytes, "content_sha256": anchor_summary.content_sha256
            }
        }))
        .unwrap();
        verify_source_contents(&document, &inputs).unwrap();

        for (label, path, original) in [
            ("OpenSSF", ossf_file.as_path(), originals[0].1),
            ("Datadog", datadog_npm.as_path(), originals[1].1),
            ("typosquat", typosquats.as_path(), originals[3].1),
            ("Feodo", feodo.as_path(), originals[4].1),
            ("CISA", cisa.as_path(), originals[5].1),
            ("anchor", anchors.as_path(), originals[6].1),
        ] {
            let mut mutated = original.to_vec();
            mutated.push(b'!');
            std::fs::write(path, mutated).unwrap();
            assert!(
                verify_source_contents(&document, &inputs).is_err(),
                "{label} mutation must fail before signing"
            );
            std::fs::write(path, original).unwrap();
            verify_source_contents(&document, &inputs).unwrap();
        }
    }

    #[test]
    fn git_source_revision_and_tracked_cleanliness_are_enforced() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("input.txt"), b"clean\n").unwrap();
        for args in [
            vec!["init", "--quiet"],
            vec!["add", "input.txt"],
            vec![
                "-c",
                "user.name=Tirith Test",
                "-c",
                "user.email=tirith@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
        ] {
            let status = std::process::Command::new("git")
                .arg("-C")
                .arg(directory.path())
                .args(args)
                .status()
                .unwrap();
            assert!(status.success());
        }
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(directory.path())
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        let commit = std::str::from_utf8(&output.stdout).unwrap().trim();
        verify_git_checkout(directory.path(), commit, "fixture").unwrap();
        assert!(verify_git_checkout(directory.path(), &"77".repeat(20), "fixture").is_err());
        std::fs::write(directory.path().join("input.txt"), b"dirty\n").unwrap();
        assert!(verify_git_checkout(directory.path(), commit, "fixture").is_err());
    }

    #[test]
    fn test_decode_sha256_hex() {
        // 64 lowercase hex -> 32 bytes.
        let s = "503284900929e333b801f9f47419a2b4c21e4022d13a03fc14e4b5390767a51d";
        let bytes = decode_sha256_hex(s).expect("valid sha256 hex");
        assert_eq!(bytes[0], 0x50);
        assert_eq!(bytes[31], 0x1d);
        // Uppercase tolerated.
        assert!(decode_sha256_hex(&s.to_uppercase()).is_some());
        // Wrong length / non-hex rejected.
        assert!(decode_sha256_hex("abc").is_none());
        assert!(decode_sha256_hex(&"z".repeat(64)).is_none());
    }

    #[test]
    fn test_compiler_emits_v2_sections_from_indicator_model() {
        use ed25519_dalek::SigningKey;
        use tirith_core::threatdb::{ThreatDb, ThreatDbFormat};

        // Drive the DB-A parser over the vendored MAL-2026-2307 record, which
        // carries artifact sha256 + an ioc URL, then feed that model into the v2
        // writer exactly as main() does and assert the v2 lookups resolve.
        let osv: OsvEntry = serde_json::from_str(MAL_2026_2307).expect("fixture deserialize");
        let indicators = OssfIndicators::from_database_specific(osv.database_specific.as_ref());
        assert!(!indicators.artifact_sha256.is_empty());
        assert!(!indicators.urls.is_empty());

        let key = SigningKey::from_bytes(&[11u8; 32]);
        let mut writer = ThreatDbWriter::new(1_700_000_000, 1);
        // A v1 package too, so the v2 file still carries v1 data.
        writer.add_package(
            Ecosystem::PyPI,
            "compiler-v2-pkg",
            &["1.0.0"],
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            false,
            None,
        );
        for sha in &indicators.artifact_sha256 {
            if let Some(bytes) = decode_sha256_hex(sha) {
                writer.add_artifact_sha256(
                    bytes,
                    ThreatSource::OssfMalicious,
                    Confidence::Confirmed,
                    false,
                    None,
                );
            }
        }
        for url in &indicators.urls {
            writer.add_malicious_url(url.trim(), ThreatSource::OssfMalicious);
        }
        for domain in &indicators.domains {
            writer.add_hostname(domain, ThreatSource::OssfMalicious);
        }
        for ip in &indicators.ips {
            writer.add_ip(
                ip.parse::<Ipv4Addr>().expect("fixture IPv4 IOC"),
                ThreatSource::OssfMalicious,
            );
        }

        let v2 = writer
            .build_format(ThreatDbFormat::V2, &key)
            .expect("v2 build");
        let db = ThreatDb::from_bytes(v2, 0).expect("v2 load");
        assert_eq!(db.stats().format_version, 2);

        // The artifact hash from the fixture resolves.
        let target =
            decode_sha256_hex("503284900929e333b801f9f47419a2b4c21e4022d13a03fc14e4b5390767a51d")
                .unwrap();
        let am = db.check_artifact_sha256(&target).expect("artifact hit");
        assert_eq!(am.source, ThreatSource::OssfMalicious);

        // The ioc URL resolves; a non-listed URL does not.
        assert_eq!(
            db.check_malicious_url("http://sfrclak.com:8000/6202033"),
            Some(ThreatSource::OssfMalicious)
        );
        assert!(db
            .check_malicious_url("http://not-listed.example/x")
            .is_none());

        assert_eq!(
            db.check_hostname("SFRCLAK.COM.")
                .map(|matched| matched.source),
            Some(ThreatSource::OssfMalicious)
        );
        assert_eq!(
            db.check_ip(Ipv4Addr::new(142, 11, 206, 73))
                .map(|matched| matched.source),
            Some(ThreatSource::OssfMalicious)
        );

        // v1 package still resolves on the v2 file.
        assert!(db
            .check_package(Ecosystem::PyPI, "compiler-v2-pkg", Some("1.0.0"))
            .is_some());
    }

    #[test]
    fn test_curated_file_hashes_go_live_in_v2() {
        use ed25519_dalek::SigningKey;
        use tirith_core::threatdb::{ThreatDb, ThreatDbFormat};

        // Parse the curated companion feed exactly as main() does, feed it into the
        // v2 writer via add_file_sha256, and assert check_file_sha256 resolves with
        // the structured behavior tags and campaign label carried through.
        let sha_hex = "503284900929e333b801f9f47419a2b4c21e4022d13a03fc14e4b5390767a51d";
        let feed = format!(
            "# curated malicious file hashes\n\
             {sha_hex}  tags=runtime_loader,cross_runtime  campaign=miasma  source=ossf\n"
        );
        let parsed = parse_curated_file_hashes(&feed);
        assert_eq!(parsed.records.len(), 1);

        let key = SigningKey::from_bytes(&[12u8; 32]);
        let mut writer = ThreatDbWriter::new(1_700_000_000, 1);
        for rec in &parsed.records {
            writer.add_file_sha256(
                rec.sha256,
                ThreatSource::OssfMalicious,
                Confidence::Confirmed,
                &rec.behavior_tags,
                rec.campaign.as_deref(),
            );
        }

        let v2 = writer
            .build_format(ThreatDbFormat::V2, &key)
            .expect("v2 build");
        let db = ThreatDb::from_bytes(v2, 0).expect("v2 load");
        assert_eq!(db.stats().format_version, 2);

        let target = decode_sha256_hex(sha_hex).unwrap();
        let fm = db
            .check_file_sha256(&target)
            .expect("curated file hash must resolve");
        assert_eq!(fm.source, ThreatSource::OssfMalicious);
        assert_eq!(fm.confidence, Confidence::Confirmed);
        assert!(fm.behavior_tags.contains(&BehaviorTag::RuntimeLoader));
        assert!(fm.behavior_tags.contains(&BehaviorTag::CrossRuntime));
        assert_eq!(fm.campaign.as_deref(), Some("miasma"));

        // A hash that was never listed does not resolve (no false positive).
        let absent = decode_sha256_hex(&"f".repeat(64)).unwrap();
        assert!(db.check_file_sha256(&absent).is_none());
    }

    #[test]
    fn test_file_hashes_read_error_is_fatal_err() {
        // The curated file-hash feed is fail-closed like the exfil feed: an
        // explicitly-supplied path that cannot be read returns Err so main() exits
        // non-zero rather than signing a DB with an empty FileHash section.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.txt");
        assert!(
            parse_curated_file_hashes_file(&missing).is_err(),
            "an unreadable explicit file-hash feed must return Err"
        );

        // A readable feed parses and a registry-yank line is preserved.
        let path = dir.path().join("file-hashes.txt");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "# curated file hashes").unwrap();
        writeln!(
            f,
            "{}  tags=process_spawn  source=registry-yank",
            "a".repeat(64)
        )
        .unwrap();
        drop(f);
        let parsed = parse_curated_file_hashes_file(&path).expect("readable feed must parse");
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(
            parsed.records[0].provenance,
            FileHashProvenance::RegistryYank
        );
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
                    {"source": "ossf-package-analysis", "sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "extra": 1}
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
        assert_eq!(
            ind.artifact_sha256,
            vec!["deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string()]
        );
        assert!(ind.urls.is_empty());
    }

    /// A malformed (non-64-hex) `sha256` indicator is rejected, not pushed: it would
    /// otherwise poison the artifact-hash index DB-B builds, and a mixed-case hex is
    /// normalized to lowercase.
    #[test]
    fn ossf_indicators_rejects_non_hex_sha() {
        let json = r#"{
            "id": "MAL-2099-0002",
            "database_specific": {
                "malicious-packages-origins": [
                    {"sha256": "not-hex"},
                    {"sha256": "abc"},
                    {"sha256": "DEADBEEFdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
                ]
            }
        }"#;
        let osv: OsvEntry = serde_json::from_str(json).unwrap();
        let ind = OssfIndicators::from_database_specific(osv.database_specific.as_ref());
        // The two malformed values are dropped; the valid hex survives, lowercased.
        assert_eq!(
            ind.artifact_sha256,
            vec!["deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string()]
        );
    }

    #[test]
    fn test_typosquats_csv_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("typosquats.csv");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            "malicious_package,target_package,ecosystem,registry,classification,source"
        )
        .unwrap();
        writeln!(
            f,
            "reqeusts,requests,pypi,https://pypi.org,transposition,fixture"
        )
        .unwrap();
        writeln!(f, "loadsh,lodash,npm,https://npmjs.org,omission,fixture").unwrap();
        writeln!(
            f,
            "unsupported,target,github_actions,https://github.com,other,fixture"
        )
        .unwrap();
        writeln!(f, "requests,requests,pypi,https://pypi.org,other,fixture").unwrap();
        drop(f);

        let (entries, stats) = parse_typosquats_csv(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(stats.accepted, 2);
        assert_eq!(stats.rejected_unsupported_ecosystem, 1);
        assert_eq!(stats.rejected_pseudo_package, 1);
        assert!(entries.iter().any(|entry| {
            entry.ecosystem == Ecosystem::PyPI
                && entry.name == "reqeusts"
                && entry.target_name == "requests"
        }));

        std::fs::write(&path, "ecosystem,name,target_name\npypi,x,y\n").unwrap();
        assert!(parse_typosquats_csv(&path).is_err());

        std::fs::write(
            &path,
            "malicious_package,target_package,ecosystem,registry,classification,source\nreqeusts,requests,pypi,https://pypi.org,transposition,a\nreqeusts,request,pypi,https://pypi.org,transposition,b\n",
        )
        .unwrap();
        assert!(parse_typosquats_csv(&path).is_err());
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

        let entries = parse_cisa_kev(&path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].cve_id, "CVE-2024-1234");
    }

    #[test]
    fn explicit_primary_feeds_fail_closed_on_missing_empty_or_malformed_input() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        assert!(parse_ossf(&missing).is_err());
        assert!(parse_datadog(&missing).is_err());
        assert!(parse_feodo(&missing).is_err());
        assert!(parse_cisa_kev(&missing).is_err());

        let ossf = dir.path().join("ossf");
        std::fs::create_dir(&ossf).unwrap();
        std::fs::write(ossf.join("MAL-2099-0001.json"), b"{not json").unwrap();
        assert!(parse_ossf(&ossf).is_err());

        let datadog = dir.path().join("datadog");
        std::fs::create_dir(&datadog).unwrap();
        std::fs::write(datadog.join("feed.json"), br#"[]"#).unwrap();
        assert!(parse_datadog(&datadog).is_err());

        let feodo = dir.path().join("feodo.txt");
        std::fs::write(&feodo, b"# comments only\n").unwrap();
        assert!(parse_feodo(&feodo).is_err());
        std::fs::write(&feodo, b"203.0.113.10\nnot-an-ip\n").unwrap();
        assert!(parse_feodo(&feodo).is_err());

        let kev = dir.path().join("kev.json");
        std::fs::write(&kev, br#"{"vulnerabilities":[]}"#).unwrap();
        assert!(parse_cisa_kev(&kev).is_err());
    }

    #[test]
    fn primary_feed_minimums_are_inclusive_fail_closed_gates() {
        assert!(require_minimum("OSSF", MIN_OSSF_PACKAGES - 1, MIN_OSSF_PACKAGES).is_err());
        assert!(require_minimum("OSSF", MIN_OSSF_PACKAGES, MIN_OSSF_PACKAGES).is_ok());
        assert!(require_minimum("Feodo", MIN_FEODO_IPS - 1, MIN_FEODO_IPS).is_err());
        assert!(require_minimum("Feodo", MIN_FEODO_IPS, MIN_FEODO_IPS).is_ok());
    }

    #[test]
    fn primary_package_floors_count_unique_normalized_keys() {
        let records: Vec<PackageEntry> = (0..MIN_OSSF_PACKAGES)
            .map(|index| PackageEntry {
                ecosystem: Ecosystem::PyPI,
                // These are distinct legacy spellings but one PEP 503 identity.
                name: if index % 2 == 0 {
                    "one-package".to_string()
                } else {
                    "one---package".to_string()
                },
                affected_versions: vec![format!("1.0.{index}")],
                all_versions_malicious: false,
                source: ThreatSource::OssfMalicious,
                confidence: Confidence::Confirmed,
                reference: None,
            })
            .collect();
        assert_eq!(unique_package_count(&records), 1);
        assert!(
            require_minimum("OSSF", unique_package_count(&records), MIN_OSSF_PACKAGES).is_err()
        );
    }

    #[test]
    fn cisa_parser_validates_and_deduplicates_cve_ids() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kev.json");
        std::fs::write(
            &path,
            br#"{"vulnerabilities":[{"cveID":"cve-2024-1234"},{"cveID":"CVE-2024-1234"}]}"#,
        )
        .unwrap();
        let entries = parse_cisa_kev(&path).expect("valid CVE records");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].cve_id, "CVE-2024-1234");

        std::fs::write(&path, br#"{"vulnerabilities":[{"cveID":"not-a-cve"}]}"#).unwrap();
        assert!(parse_cisa_kev(&path).is_err());
    }

    #[test]
    fn datadog_real_manifest_shape_is_path_derived_stable_and_strict() {
        let dir = tempfile::tempdir().unwrap();
        let npm = dir.path().join("samples/npm");
        let pypi = dir.path().join("samples/pypi");
        std::fs::create_dir_all(&npm).unwrap();
        std::fs::create_dir_all(&pypi).unwrap();
        std::fs::write(
            npm.join("manifest.json"),
            r#"{"z-package":["2.0.0","1.0.0","1.0.0"],"all-bad":null}"#,
        )
        .unwrap();
        std::fs::write(
            pypi.join("manifest.json"),
            r#"{"Friendly_Bard":["3.0"],"other":null}"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("unrelated.json"), r#"["ignored"]"#).unwrap();

        let (entries, skipped, files) = parse_datadog(dir.path()).unwrap();
        assert_eq!(files, 2);
        assert_eq!(skipped, 0);
        assert_eq!(entries.len(), 4);
        let exact = entries
            .iter()
            .find(|entry| entry.name == "z-package")
            .unwrap();
        assert_eq!(exact.affected_versions, ["1.0.0", "2.0.0"]);
        assert!(!exact.all_versions_malicious);
        assert!(entries.iter().any(|entry| entry.name == "friendly-bard"));
        assert!(
            entries
                .iter()
                .find(|entry| entry.name == "all-bad")
                .unwrap()
                .all_versions_malicious
        );

        std::fs::write(npm.join("manifest.json"), r#"{"bad":[]}"#).unwrap();
        assert!(parse_datadog(dir.path()).is_err());
        std::fs::write(npm.join("manifest.json"), r#"{"bad":"1.0.0"}"#).unwrap();
        assert!(parse_datadog(dir.path()).is_err());
        std::fs::write(npm.join("manifest.json"), r#"{"dup":null,"dup":null}"#).unwrap();
        assert!(parse_datadog(dir.path()).is_err());
        std::fs::write(
            pypi.join("manifest.json"),
            r#"{"Friendly_Bard":["1.0"],"friendly-bard":["2.0"]}"#,
        )
        .unwrap();
        std::fs::write(npm.join("manifest.json"), r#"{"ok":null}"#).unwrap();
        assert!(parse_datadog(dir.path()).is_err());
    }

    #[test]
    fn explicitly_supplied_supplemental_feeds_do_not_fallback_or_publish_empty() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.csv");
        assert!(parse_popular_csv(Some(&missing)).is_err());
        assert!(parse_urlhaus_file(&missing).is_err());
        assert!(parse_phishtank_file(&missing).is_err());

        let empty = dir.path().join("empty.txt");
        std::fs::write(&empty, b"# no records\n").unwrap();
        assert!(parse_blocklist_file(&empty).is_err());
        assert!(parse_exfil_endpoints_file(&empty).is_err());
        assert!(parse_tor_exit_file(&empty).is_err());

        let hashes = dir.path().join("hashes.txt");
        std::fs::write(&hashes, b"not-a-sha tags=not_a_real_behavior source=ossf\n").unwrap();
        assert!(parse_curated_file_hashes_file(&hashes).is_err());
    }

    #[test]
    fn loopback_controls_with_inline_comments_match_core_parser_semantics() {
        let controls = "127.0.0.1 localhost # local control\n127.0.0.2 # loopback alias\n";
        assert!(validate_domain_list_lines(controls).is_ok());
        assert!(parse_domain_blocklist(controls).hostnames.is_empty());
        assert!(validate_domain_list_lines("not-a-domain # malformed\n").is_err());
    }

    #[test]
    fn overlapping_network_iocs_have_deterministic_source_ownership() {
        let mut hosts = BTreeMap::new();
        insert_hostname_indicator(&mut hosts, "OVERLAP.example.", ThreatSource::PhishTank).unwrap();
        insert_hostname_indicator(&mut hosts, "overlap.example", ThreatSource::Urlhaus).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts["overlap.example"], ThreatSource::Urlhaus);

        let mut ips = BTreeMap::new();
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        insert_ip_indicator(&mut ips, ip, ThreatSource::TorExit);
        insert_ip_indicator(&mut ips, ip, ThreatSource::FeodoTracker);
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[&ip], ThreatSource::FeodoTracker);
    }

    #[test]
    fn staged_database_is_reopened_signature_checked_and_only_then_published() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("threatdb.dat");
        let key = SigningKey::from_bytes(&[31u8; 32]);
        let mut writer = ThreatDbWriter::new(1_700_000_000, 77);
        writer.add_package(
            Ecosystem::Npm,
            "malicious-example",
            &["1.0.0"],
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            false,
            None,
        );
        writer.add_ip(Ipv4Addr::new(203, 0, 113, 10), ThreatSource::FeodoTracker);
        writer.add_popular(Ecosystem::Npm, "express");
        let data = writer.build_format(ThreatDbFormat::V1, &key).unwrap();
        let sources = [
            SourceExpectation {
                source: ThreatSource::OssfMalicious,
                counts: SourceRecordCounts {
                    package_count: 1,
                    ..SourceRecordCounts::default()
                },
            },
            SourceExpectation {
                source: ThreatSource::FeodoTracker,
                counts: SourceRecordCounts {
                    ip_count: 1,
                    ..SourceRecordCounts::default()
                },
            },
        ];
        let hashes = CuratedFileHashes::default();
        let expected = RoundTripExpectations {
            format: ThreatDbFormat::V1,
            sequence: 77,
            package_count: 1,
            popular_count: 1,
            typosquat_count: 0,
            sources: &sources,
            artifact_hashes: &[],
            file_hashes: &hashes,
            malicious_urls: &[],
            baseline: None,
        };

        let staged = stage_database(&output, &data, &key, &expected).unwrap();
        assert!(
            !output.exists(),
            "validation must not publish the final path"
        );
        publish_staged(staged, &output).unwrap();
        let reopened = ThreatDb::load_from_path(&output, 0).unwrap();
        assert_eq!(reopened.stats().package_count, 1);
        assert_eq!(
            reopened
                .source_breakdown()
                .count_for(ThreatSource::FeodoTracker),
            1
        );

        let mut tampered = data;
        tampered[172] ^= 1;
        assert!(verify_compiler_signature(&tampered, &key).is_err());
    }

    #[test]
    fn existing_output_rejects_more_than_fifty_percent_source_drop() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("threatdb.dat");
        let key = SigningKey::from_bytes(&[32u8; 32]);

        let mut previous = ThreatDbWriter::new(1_700_000_000, 1);
        for index in 0..4 {
            previous.add_package(
                Ecosystem::Npm,
                &format!("malicious-{index}"),
                &["1.0.0"],
                ThreatSource::OssfMalicious,
                Confidence::Confirmed,
                false,
                None,
            );
        }
        std::fs::write(
            &output,
            previous.build_format(ThreatDbFormat::V1, &key).unwrap(),
        )
        .unwrap();

        let mut candidate = ThreatDbWriter::new(1_700_000_001, 2);
        candidate.add_package(
            Ecosystem::Npm,
            "malicious-0",
            &["1.0.0"],
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            false,
            None,
        );
        let data = candidate.build_format(ThreatDbFormat::V1, &key).unwrap();
        let sources = [SourceExpectation {
            source: ThreatSource::OssfMalicious,
            counts: SourceRecordCounts {
                package_count: 1,
                ..SourceRecordCounts::default()
            },
        }];
        let hashes = CuratedFileHashes::default();
        let expected = RoundTripExpectations {
            format: ThreatDbFormat::V1,
            sequence: 2,
            package_count: 1,
            popular_count: 0,
            typosquat_count: 0,
            sources: &sources,
            artifact_hashes: &[],
            file_hashes: &hashes,
            malicious_urls: &[],
            baseline: Some(&output),
        };
        let error = stage_database(&output, &data, &key, &expected)
            .expect_err("a 75% OSSF drop must not reach publication");
        assert!(error.contains("ossf_malicious dropped"), "{error}");
    }

    #[test]
    fn signed_v2_baseline_rejects_section_loss_hidden_by_stable_source_total() {
        let dir = tempfile::tempdir().unwrap();
        let baseline_path = dir.path().join("baseline-v2.dat");
        let key = SigningKey::from_bytes(&[33u8; 32]);

        let mut baseline_writer = ThreatDbWriter::new(1_700_000_000, 1);
        let mut candidate_writer = ThreatDbWriter::new(1_700_000_001, 2);
        for index in 0..4u8 {
            let name = format!("stable-package-{index}");
            for writer in [&mut baseline_writer, &mut candidate_writer] {
                writer.add_package(
                    Ecosystem::Npm,
                    &name,
                    &["1.0.0"],
                    ThreatSource::OssfMalicious,
                    Confidence::Confirmed,
                    false,
                    None,
                );
            }
            baseline_writer.add_artifact_sha256(
                [index; 32],
                ThreatSource::OssfMalicious,
                Confidence::Confirmed,
                false,
                None,
            );
        }
        std::fs::write(
            &baseline_path,
            baseline_writer
                .build_format(ThreatDbFormat::V2, &key)
                .unwrap(),
        )
        .unwrap();
        let candidate = ThreatDb::from_bytes(
            candidate_writer
                .build_format(ThreatDbFormat::V2, &key)
                .unwrap(),
            0,
        )
        .unwrap();
        let error = validate_against_baseline(&baseline_path, &candidate, &key)
            .expect_err("complete artifact-section loss must fail");
        assert!(error.contains("artifact SHA-256"), "{error}");
    }

    #[test]
    fn baseline_must_verify_with_the_configured_signer() {
        let dir = tempfile::tempdir().unwrap();
        let baseline_path = dir.path().join("baseline.dat");
        let trusted = SigningKey::from_bytes(&[34u8; 32]);
        let untrusted = SigningKey::from_bytes(&[35u8; 32]);
        let mut writer = ThreatDbWriter::new(1_700_000_000, 1);
        std::fs::write(
            &baseline_path,
            writer.build_format(ThreatDbFormat::V1, &untrusted).unwrap(),
        )
        .unwrap();
        assert!(load_signed_baseline(&baseline_path, &trusted).is_err());
    }

    #[test]
    fn explicit_baseline_is_used_for_a_new_run_scoped_output_name() {
        let dir = tempfile::tempdir().unwrap();
        let baseline = dir.path().join("previous-generation.dat");
        let output = dir.path().join("tirith-threatdb-new-run.dat");
        std::fs::write(&baseline, b"baseline marker").unwrap();

        assert_eq!(
            resolve_baseline(Some(&baseline), &output).unwrap(),
            Some(baseline.as_path())
        );
        assert!(!output.exists());
    }

    #[test]
    fn generation_pointer_is_not_advanced_when_second_asset_publish_fails() {
        use std::cell::Cell;

        let dir = tempfile::tempdir().unwrap();
        let v1_path = dir.path().join("generation-v1.dat");
        let v2_path = dir.path().join("generation-v2.dat");
        let pointer_path = dir.path().join("threatdb-index-v2.json");
        std::fs::write(&pointer_path, b"old-generation\n").unwrap();

        let mut staged_v1 = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        staged_v1.write_all(b"v1").unwrap();
        let mut staged_v2 = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        staged_v2.write_all(b"v2").unwrap();
        let mut staged_pointer = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        staged_pointer.write_all(b"new-generation\n").unwrap();

        let calls = Cell::new(0usize);
        let error = publish_compiled_generation(
            staged_v1,
            &v1_path,
            Some((staged_v2, &v2_path)),
            Some((staged_pointer, &pointer_path)),
            StagedAuxiliaryArtifacts {
                compiler_metadata: None,
                source_integrity: None,
            },
            |staged, output| {
                let call = calls.get() + 1;
                calls.set(call);
                if call == 2 {
                    return Err("injected second-asset failure".to_string());
                }
                publish_staged(staged, output)
            },
            publish_staged,
        )
        .expect_err("second asset publication must fail");
        assert!(error.contains("injected second-asset failure"));
        assert_eq!(std::fs::read(&pointer_path).unwrap(), b"old-generation\n");
        assert!(
            v1_path.exists(),
            "first immutable asset may remain orphaned"
        );
        assert!(!v2_path.exists());
    }

    #[test]
    fn generation_pointer_is_not_advanced_when_metadata_publish_fails() {
        use std::cell::Cell;

        let dir = tempfile::tempdir().unwrap();
        let v1_path = dir.path().join("metadata-v1.dat");
        let v2_path = dir.path().join("metadata-v2.dat");
        let metadata_path = dir.path().join("compiler-metadata.json");
        let pointer_path = dir.path().join("metadata-index.json");
        std::fs::write(&pointer_path, b"old-generation\n").unwrap();
        let mut staged_v1 = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        staged_v1.write_all(b"v1").unwrap();
        let mut staged_v2 = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        staged_v2.write_all(b"v2").unwrap();
        let mut staged_metadata = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        staged_metadata.write_all(b"metadata").unwrap();
        let mut staged_pointer = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        staged_pointer.write_all(b"new-generation\n").unwrap();

        let calls = Cell::new(0usize);
        let error = publish_compiled_generation(
            staged_v1,
            &v1_path,
            Some((staged_v2, &v2_path)),
            Some((staged_pointer, &pointer_path)),
            StagedAuxiliaryArtifacts {
                compiler_metadata: Some((staged_metadata, &metadata_path)),
                source_integrity: None,
            },
            |staged, output| {
                let call = calls.get() + 1;
                calls.set(call);
                if call == 3 {
                    return Err("injected metadata failure".to_string());
                }
                publish_staged(staged, output)
            },
            publish_staged,
        )
        .expect_err("metadata publication must fail before pointer commit");
        assert!(error.contains("injected metadata failure"));
        assert_eq!(std::fs::read(&pointer_path).unwrap(), b"old-generation\n");
        assert!(!metadata_path.exists());
    }

    #[test]
    fn generation_pointer_is_not_advanced_when_integrity_sidecar_publish_fails() {
        use std::cell::Cell;

        let directory = tempfile::tempdir().unwrap();
        let v1_path = directory.path().join("sidecar-v1.dat");
        let v2_path = directory.path().join("sidecar-v2.dat");
        let metadata_path = directory.path().join("sidecar-metadata.json");
        let integrity_path = directory.path().join("source-integrity.json");
        let pointer_path = directory.path().join("sidecar-index.json");
        std::fs::write(&pointer_path, b"old-generation\n").unwrap();
        let staged = |bytes: &'static [u8]| {
            let mut file = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
            file.write_all(bytes).unwrap();
            file
        };
        let calls = Cell::new(0usize);
        let error = publish_compiled_generation(
            staged(b"v1"),
            &v1_path,
            Some((staged(b"v2"), &v2_path)),
            Some((staged(b"new-generation\n"), &pointer_path)),
            StagedAuxiliaryArtifacts {
                compiler_metadata: Some((staged(b"metadata"), &metadata_path)),
                source_integrity: Some((staged(b"integrity"), &integrity_path)),
            },
            |staged, output| {
                let call = calls.get() + 1;
                calls.set(call);
                if call == 4 {
                    return Err("injected sidecar failure".to_string());
                }
                publish_staged(staged, output)
            },
            publish_staged,
        )
        .expect_err("sidecar publication must fail before pointer commit");
        assert!(error.contains("injected sidecar failure"));
        assert_eq!(std::fs::read(&pointer_path).unwrap(), b"old-generation\n");
        assert!(!integrity_path.exists());
    }

    #[test]
    fn compiler_generation_manifest_is_one_signed_two_asset_commit_point() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = dir.path().join("tirith-threatdb-7-1.dat");
        let v2 = dir.path().join("tirith-threatdb-v2-7-1.dat");
        let key = SigningKey::from_bytes(&[36u8; 32]);
        let bytes = build_generation_manifest(
            7,
            &v1,
            b"v1 bytes",
            &v2,
            b"v2 bytes",
            "https://example.invalid/threatdb-latest/",
            "0.3.4",
            &key,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["manifest_version"], GENERATION_MANIFEST_VERSION);
        assert_eq!(value["sequence"], 7);
        assert_eq!(value["assets"].as_array().unwrap().len(), 2);
        assert_eq!(value["assets"][0]["format"], 1);
        assert_eq!(value["assets"][1]["format"], 2);
        assert_eq!(
            value
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "assets".to_string(),
                "manifest_version".to_string(),
                "sequence".to_string(),
                "signature".to_string(),
            ])
        );
    }

    #[test]
    fn base_schema_v2_reader_reconstructs_compiler_generation_signature() {
        let directory = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[40u8; 32]);
        let bytes = build_generation_manifest(
            11,
            &directory.path().join("tirith-threatdb-11-1.dat"),
            b"v1",
            &directory.path().join("tirith-threatdb-v2-11-1.dat"),
            b"v2",
            "https://example.invalid/threatdb-latest",
            "0.3.4",
            &key,
        )
        .unwrap();
        let mut document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let signature_b64 = document
            .as_object_mut()
            .unwrap()
            .remove("signature")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(
            document
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "assets".to_string(),
                "manifest_version".to_string(),
                "sequence".to_string(),
            ])
        );
        let base_reader_payload = serde_json::to_string(&document).unwrap();
        let signature = Signature::from_slice(&BASE64.decode(signature_b64).unwrap()).unwrap();
        key.verifying_key()
            .verify(base_reader_payload.as_bytes(), &signature)
            .expect("base schema-v2 reader must reconstruct the exact signed bytes");
    }

    #[test]
    fn signed_source_integrity_sidecar_binds_generation_and_rejects_tampering() {
        let directory = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[39u8; 32]);
        let bytes = build_source_integrity_manifest(
            7,
            &directory.path().join("tirith-threatdb-7-1.dat"),
            b"v1 bytes",
            &directory.path().join("tirith-threatdb-v2-7-1.dat"),
            b"v2 bytes",
            &fixture_source_integrity_digests(),
            &key,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["manifest_version"], SOURCE_INTEGRITY_MANIFEST_VERSION);
        assert_eq!(value["sequence"], 7);
        assert_eq!(value["v1_sha256"], sha256_hex(b"v1 bytes"));
        assert_eq!(value["v2_sha256"], sha256_hex(b"v2 bytes"));
        assert_eq!(value["compiler_metadata_sha256"], "33".repeat(32));

        for field in ["source_transaction_sha256", "v1_sha256"] {
            let mut tampered = value.clone();
            tampered[field] = serde_json::json!("44".repeat(32));
            let mut signed_region = tampered.clone();
            signed_region.as_object_mut().unwrap().remove("signature");
            let canonical = serde_json::to_string(&signed_region).unwrap();
            let tampered_bytes = serde_json::to_vec(&tampered).unwrap();
            assert!(
                verify_source_integrity_manifest(&tampered_bytes, &canonical, &key)
                    .unwrap_err()
                    .contains("signature does not verify"),
                "tampering {field} must invalidate the sidecar"
            );
        }
    }

    #[test]
    fn compiler_parse_metadata_has_machine_readable_accepted_and_rejected_counts() {
        let mut sources = BTreeMap::new();
        sources.insert(
            "ossf_malicious_packages".to_string(),
            CompilerParserCounts {
                accepted: 101,
                rejected: 3,
                details: BTreeMap::from([
                    ("withdrawn".to_string(), 2),
                    ("non_malicious".to_string(), 1),
                ]),
            },
        );
        let document = CompilerParseMetadata {
            schema_version: 1,
            compiler_version: env!("CARGO_PKG_VERSION").to_string(),
            parsed_at: "2026-08-08T00:00:00Z".to_string(),
            source_transaction_sha256: Some("11".repeat(32)),
            registry_snapshot_sha256: Some("22".repeat(32)),
            sources,
        };
        let bytes = serde_json::to_vec(&serde_json::to_value(&document).unwrap()).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("compiler-metadata.json");
        let staged = stage_compiler_metadata(&output, &bytes).unwrap();
        publish_staged_immutable(staged, &output).unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["sources"]["ossf_malicious_packages"]["accepted"], 101);
        assert_eq!(value["sources"]["ossf_malicious_packages"]["rejected"], 3);
        assert_eq!(
            value["sources"]["ossf_malicious_packages"]["details"]["withdrawn"],
            2
        );
    }

    #[test]
    fn generation_manifest_signature_covers_manifest_version() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[37u8; 32]);
        let bytes = build_generation_manifest(
            7,
            &dir.path().join("generation-v1.dat"),
            b"v1 bytes",
            &dir.path().join("generation-v2.dat"),
            b"v2 bytes",
            "https://example.invalid/threatdb-latest",
            "0.3.4",
            &key,
        )
        .unwrap();

        let mut tampered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        tampered["manifest_version"] = serde_json::json!(GENERATION_MANIFEST_VERSION + 1);
        let mut signed_region = tampered.clone();
        signed_region.as_object_mut().unwrap().remove("signature");
        let canonical = serde_json::to_string(&signed_region).unwrap();
        let tampered_bytes = serde_json::to_vec(&tampered).unwrap();
        let error = verify_generation_manifest(&tampered_bytes, &canonical, &key)
            .expect_err("changing manifest_version must invalidate the signature");
        assert!(error.contains("signature does not verify"), "{error}");
    }

    #[test]
    fn generation_manifest_rejects_duplicate_immutable_basenames() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[38u8; 32]);
        let error = build_generation_manifest(
            7,
            &dir.path().join("v1").join("database.dat"),
            b"v1 bytes",
            &dir.path().join("v2").join("database.dat"),
            b"v2 bytes",
            "https://example.invalid/threatdb-latest",
            "0.3.4",
            &key,
        )
        .expect_err("two formats cannot share one immutable release identity");
        assert!(error.contains("distinct immutable filenames"), "{error}");
    }
}
