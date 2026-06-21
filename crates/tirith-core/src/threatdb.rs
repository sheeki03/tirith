//! Threat intelligence database — binary format with sorted sections for O(log n) lookup.
//!
//! The DB file (`tirith-threatdb.dat`) is compiled daily by CI from open threat feeds,
//! signed with Ed25519, and distributed via GitHub Releases.
//!
//! ## Binary layout
//!
//! | Offset | Field | Size |
//! |--------|-------|------|
//! | 0 | Magic `TIRITHDB` | 8 |
//! | 8 | Format version (u32 LE) | 4 |
//! | 12 | Build timestamp (u64 LE, Unix epoch secs) | 8 |
//! | 20 | Build sequence (u64 LE, monotonic) | 8 |
//! | 28 | Section 1 (packages) offset (u32 LE) | 4 |
//! | 32 | Section 1 count (u32 LE) | 4 |
//! | 36 | Section 2 (hostnames) offset (u32 LE) | 4 |
//! | 40 | Section 2 count (u32 LE) | 4 |
//! | 44 | Section 3 (IPs) offset (u32 LE) | 4 |
//! | 48 | Section 3 count (u32 LE) | 4 |
//! | 52 | Section 4 (typosquats) offset (u32 LE) | 4 |
//! | 56 | Section 4 count (u32 LE) | 4 |
//! | 60 | Section 5 (popular pkgs) offset (u32 LE) | 4 |
//! | 64 | Section 5 count (u32 LE) | 4 |
//! | 68 | Section 6 (string table) offset (u32 LE) | 4 |
//! | 72 | Section 6 size (u32 LE, bytes) | 4 |
//! | 76 | Signer pubkey fingerprint (SHA-256, 32 bytes) | 32 |
//! | 108 | Ed25519 signature (64 bytes) | 64 |
//! | 172 | (sections data follows) | ... |
//!
//! Signature covers bytes `[0..108)` (header before sig) ++ bytes `[172..)` (all section data).

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

use ed25519_dalek::{Signature, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::policy;
use crate::util::levenshtein;

const MAGIC: &[u8; 8] = b"TIRITHDB";
/// Highest on-disk format this binary can WRITE and is the newest it can READ.
const FORMAT_VERSION: u32 = 2;
/// Public view of the highest on-disk format this build understands. The
/// updater uses it to select the highest `format <= MAX_FORMAT_VERSION` asset
/// from the v2 index, so a future binary that bumps `FORMAT_VERSION` starts
/// preferring the newer asset with no manifest-schema change.
pub const MAX_FORMAT_VERSION: u32 = FORMAT_VERSION;
/// Oldest on-disk format this binary still accepts on read. A v1 file loads with
/// every v2 section absent (every v2 lookup returns None), so it behaves exactly
/// like a pre-v2 binary did. An OLD binary (whose `FORMAT_VERSION` is 1) reading
/// a v2 file rejects it via the `version != 1` check it shipped with and fails
/// closed; the dual-cache-filename split below keeps it from ever seeing one.
const MIN_SUPPORTED_FORMAT_VERSION: u32 = 1;
/// Total header size in bytes.
const HEADER_SIZE: usize = 172;
/// Offset of the Ed25519 signature within the header.
const SIG_OFFSET: usize = 108;
/// Offset of the signer fingerprint within the header.
const FINGERPRINT_OFFSET: usize = 76;
const FINGERPRINT_LEN: usize = 32;
/// Canonical v1 cache filename. An OLD binary only ever knows this name, so the
/// v2 updater must never clobber it (see [`DB_FILENAME_V2`]).
const DB_FILENAME: &str = "tirith-threatdb.dat";
/// Distinct v2 cache filename. A v2-capable client writes the v2 DB here and the
/// loader prefers it when present and parseable, falling back to [`DB_FILENAME`].
/// A co-located old binary never reads this file, so it is never fail-opened.
const DB_FILENAME_V2: &str = "tirith-threatdb-v2.dat";
const SUPPLEMENTAL_DB_FILENAME: &str = "tirith-threatdb-supplemental.dat";
/// Distinct v2 supplemental filename (same split rationale as [`DB_FILENAME_V2`]).
const SUPPLEMENTAL_DB_FILENAME_V2: &str = "tirith-threatdb-supplemental-v2.dat";
/// Re-check file mtime at most every 60 seconds.
const MTIME_CHECK_INTERVAL_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// v2 binary format: a fixed EOF footer anchoring a variable, checked descriptor
// trailer, with all new sections living AFTER `HEADER_SIZE` so the existing
// Ed25519 signature (over `data[0..SIG_OFFSET]` ++ `data[HEADER_SIZE..]`) covers
// them with NO change to `SIG_OFFSET` or the signed range.
// ---------------------------------------------------------------------------

/// Magic at the very end of a v2 file, anchoring the descriptor trailer.
const FOOTER_MAGIC: &[u8; 8] = b"TRTHDBV2";
/// Fixed EOF footer size: magic[8] + trailer_offset u64 + trailer_length u64 +
/// trailer_version u16 + flags u16.
const FOOTER_SIZE: usize = 8 + 8 + 8 + 2 + 2;
/// Trailer format version carried in the footer (independent of the section
/// `record_version`s). Bumped only on a trailer-layout change.
const TRAILER_VERSION: u16 = 1;
/// Per-descriptor size in the trailer: section_type u16 + record_version u16 +
/// offset u64 + length u64 + count u64.
const DESCRIPTOR_SIZE: usize = 2 + 2 + 8 + 8 + 8;
/// Upper bound on the descriptor count, so a corrupt trailer_length cannot make
/// the reader attempt an absurd allocation. Far above the handful of section
/// types we define.
const MAX_DESCRIPTORS: u64 = 1024;
/// Defensive ceiling on any single section's record count. Each v2 record is at
/// least 32 bytes (a SHA-256), so a file large enough to hold this many is well
/// past any real DB; the real bound is the file-length check, this only stops a
/// `count * record_size` multiply from being attempted on a wild value.
const MAX_SECTION_RECORDS: u64 = 1 << 40;

/// Fixed record size of the artifact-SHA index: full 32-byte SHA-256 +
/// confidence(u8) + source(u8) + flags(u8) + reserved(u8) + campaign_offset(u32
/// into the v2 campaign string table; 0xFFFF_FFFF = none).
const ARTIFACT_SHA_RECORD_SIZE: usize = 32 + 1 + 1 + 1 + 1 + 4;
/// Fixed record size of the file-hash index: full 32-byte SHA-256 +
/// confidence(u8) + source(u8) + behavior_tags(u16) + campaign_offset(u32).
const FILE_HASH_RECORD_SIZE: usize = 32 + 1 + 1 + 2 + 4;
/// Fixed-size head of a malicious-URL index entry: full 32-byte SHA-256 of the
/// normalized URL + url_offset(u32 into the v2 campaign string table) +
/// source(u8) + reserved(u8). The URL string itself lives in the string table,
/// so the index is fixed-size and binary-searchable on the hash.
const URL_INDEX_RECORD_SIZE: usize = 32 + 4 + 1 + 1;

/// v2 section type tags (stored in each descriptor's `section_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
enum SectionType {
    ArtifactSha = 1,
    FileHash = 2,
    MaliciousUrl = 3,
    CampaignStrings = 4,
    BehaviorTags = 5,
}

impl SectionType {
    fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::ArtifactSha),
            2 => Some(Self::FileHash),
            3 => Some(Self::MaliciousUrl),
            4 => Some(Self::CampaignStrings),
            5 => Some(Self::BehaviorTags),
            _ => None,
        }
    }

    /// Fixed record size for the index sections; `None` for the byte-blob
    /// sections (campaign string table, behavior-tag bitset) whose `length` is
    /// authoritative and whose `count` is informational.
    fn record_size(self) -> Option<usize> {
        match self {
            Self::ArtifactSha => Some(ARTIFACT_SHA_RECORD_SIZE),
            Self::FileHash => Some(FILE_HASH_RECORD_SIZE),
            Self::MaliciousUrl => Some(URL_INDEX_RECORD_SIZE),
            Self::CampaignStrings | Self::BehaviorTags => None,
        }
    }
}

/// Ed25519 verification key for threat DB signatures, compiled into the binary.
/// The corresponding private key is stored as a GitHub Actions secret (THREATDB_SIGNING_KEY).
static VERIFY_KEY_BYTES: &[u8; PUBLIC_KEY_LENGTH] =
    include_bytes!("../assets/keys/threatdb-verify.pub");

/// Package ecosystem identifiers, encoded as a single byte in the DB.
/// Discriminants are part of the on-disk binary format and must stay stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Ecosystem {
    Npm = 0,
    PyPI = 1,
    RubyGems = 2,
    Crates = 3,
    Go = 4,
    Maven = 5,
    NuGet = 6,
    Packagist = 7,
    // M6 ch1 — distro/docker backends for `tirith install`; threat-DB lookups
    // are empty until feed wiring extends.
    Apt = 8,
    Brew = 9,
    Dnf = 10,
    Yum = 11,
    Pacman = 12,
    Scoop = 13,
    Docker = 14,
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ecosystem::Npm => write!(f, "npm"),
            Ecosystem::PyPI => write!(f, "pypi"),
            Ecosystem::RubyGems => write!(f, "rubygems"),
            Ecosystem::Crates => write!(f, "crates.io"),
            Ecosystem::Go => write!(f, "go"),
            Ecosystem::Maven => write!(f, "maven"),
            Ecosystem::NuGet => write!(f, "nuget"),
            Ecosystem::Packagist => write!(f, "packagist"),
            Ecosystem::Apt => write!(f, "apt"),
            Ecosystem::Brew => write!(f, "brew"),
            Ecosystem::Dnf => write!(f, "dnf"),
            Ecosystem::Yum => write!(f, "yum"),
            Ecosystem::Pacman => write!(f, "pacman"),
            Ecosystem::Scoop => write!(f, "scoop"),
            Ecosystem::Docker => write!(f, "docker"),
        }
    }
}

impl Ecosystem {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Npm),
            1 => Some(Self::PyPI),
            2 => Some(Self::RubyGems),
            3 => Some(Self::Crates),
            4 => Some(Self::Go),
            5 => Some(Self::Maven),
            6 => Some(Self::NuGet),
            7 => Some(Self::Packagist),
            8 => Some(Self::Apt),
            9 => Some(Self::Brew),
            10 => Some(Self::Dnf),
            11 => Some(Self::Yum),
            12 => Some(Self::Pacman),
            13 => Some(Self::Scoop),
            14 => Some(Self::Docker),
            _ => None,
        }
    }

    /// Parse an ecosystem from its string name (case-insensitive, with aliases).
    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "npm" => Some(Self::Npm),
            "pypi" => Some(Self::PyPI),
            "rubygems" => Some(Self::RubyGems),
            "crates.io" | "crates" | "cargo" => Some(Self::Crates),
            "go" => Some(Self::Go),
            "maven" => Some(Self::Maven),
            "nuget" => Some(Self::NuGet),
            "packagist" => Some(Self::Packagist),
            "apt" | "apt-get" => Some(Self::Apt),
            "brew" | "homebrew" => Some(Self::Brew),
            "dnf" => Some(Self::Dnf),
            "yum" => Some(Self::Yum),
            "pacman" => Some(Self::Pacman),
            "scoop" => Some(Self::Scoop),
            "docker" | "oci" => Some(Self::Docker),
            _ => None,
        }
    }
}

/// Which physical DB file a threat source's records live in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceTier {
    /// Compiled and Ed25519-signed by CI; verified on download and load.
    Primary,
    /// Unsigned user-local overlay compiled from optional opt-in feeds.
    Supplemental,
}

impl SourceTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Supplemental => "supplemental",
        }
    }
}

/// Origin of the threat intelligence signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ThreatSource {
    OssfMalicious = 0,
    DatadogMalicious = 1,
    FeodoTracker = 2,
    EcosystemsTyposquat = 3,
    CisaKev = 4,
    Urlhaus = 5,
    PhishingArmy = 6,
    PhishTank = 7,
    ThreatFoxIoc = 8,
    FireholIp = 9,
    TorExit = 10,
    /// Known data-exfiltration / webhook-catcher endpoints (hostnames). Curated
    /// list supplied at CI time; compiled into the signed primary DB. Appended
    /// as discriminant 11 so older `.dat` files (sources 0-10) still load.
    ExfilEndpoint = 11,
}

impl ThreatSource {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::OssfMalicious),
            1 => Some(Self::DatadogMalicious),
            2 => Some(Self::FeodoTracker),
            3 => Some(Self::EcosystemsTyposquat),
            4 => Some(Self::CisaKev),
            5 => Some(Self::Urlhaus),
            6 => Some(Self::PhishingArmy),
            7 => Some(Self::PhishTank),
            8 => Some(Self::ThreatFoxIoc),
            9 => Some(Self::FireholIp),
            10 => Some(Self::TorExit),
            11 => Some(Self::ExfilEndpoint),
            _ => None,
        }
    }

    /// Every threat source variant, in stable declaration order.
    pub const ALL: [ThreatSource; 12] = [
        Self::OssfMalicious,
        Self::DatadogMalicious,
        Self::FeodoTracker,
        Self::EcosystemsTyposquat,
        Self::CisaKev,
        Self::Urlhaus,
        Self::PhishingArmy,
        Self::PhishTank,
        Self::ThreatFoxIoc,
        Self::FireholIp,
        Self::TorExit,
        Self::ExfilEndpoint,
    ];

    /// Stable machine-readable identifier (snake_case). Used as the key in
    /// `--format json` and the snapshot history, so it must stay stable.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OssfMalicious => "ossf_malicious",
            Self::DatadogMalicious => "datadog_malicious",
            Self::FeodoTracker => "feodo_tracker",
            Self::EcosystemsTyposquat => "ecosystems_typosquat",
            Self::CisaKev => "cisa_kev",
            Self::Urlhaus => "urlhaus",
            Self::PhishingArmy => "phishing_army",
            Self::PhishTank => "phishtank",
            Self::ThreatFoxIoc => "threatfox_ioc",
            Self::FireholIp => "firehol_ip",
            Self::TorExit => "tor_exit",
            Self::ExfilEndpoint => "exfil_endpoint",
        }
    }

    /// Whether this source is carried in the signed CI-built primary DB or in
    /// the optional user-local supplemental overlay.
    pub fn tier(&self) -> SourceTier {
        match self {
            Self::OssfMalicious
            | Self::DatadogMalicious
            | Self::FeodoTracker
            | Self::EcosystemsTyposquat
            | Self::CisaKev
            | Self::ExfilEndpoint => SourceTier::Primary,
            Self::Urlhaus
            | Self::PhishingArmy
            | Self::PhishTank
            | Self::ThreatFoxIoc
            | Self::FireholIp
            | Self::TorExit => SourceTier::Supplemental,
        }
    }

    /// Upstream project / homepage for the feed (attribution).
    pub fn upstream_url(&self) -> &'static str {
        match self {
            Self::OssfMalicious => "https://github.com/ossf/malicious-packages",
            Self::DatadogMalicious => {
                "https://github.com/DataDog/malicious-software-packages-dataset"
            }
            Self::FeodoTracker => "https://feodotracker.abuse.ch/",
            Self::EcosystemsTyposquat => "https://ecosyste.ms/",
            Self::CisaKev => "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            Self::Urlhaus => "https://urlhaus.abuse.ch/",
            Self::PhishingArmy => "https://phishing.army/",
            Self::PhishTank => "https://phishtank.org/",
            Self::ThreatFoxIoc => "https://threatfox.abuse.ch/",
            Self::FireholIp => "https://iplists.firehol.org/",
            Self::TorExit => "https://www.torproject.org/",
            // Curated in-tree feed, not a third-party project; point at the repo.
            Self::ExfilEndpoint => "https://github.com/sheeki03/tirith",
        }
    }

    /// Human-readable label for display.
    pub fn label(&self) -> &'static str {
        match self {
            Self::OssfMalicious => "OSSF Malicious Packages",
            Self::DatadogMalicious => "Datadog Malicious Packages",
            Self::FeodoTracker => "Feodo Tracker",
            Self::EcosystemsTyposquat => "ecosyste.ms Typosquats",
            Self::CisaKev => "CISA KEV",
            Self::Urlhaus => "URLhaus",
            Self::PhishingArmy => "Phishing Army",
            Self::PhishTank => "PhishTank",
            Self::ThreatFoxIoc => "ThreatFox IOC",
            Self::FireholIp => "FireHOL IP",
            Self::TorExit => "Tor Exit Node",
            Self::ExfilEndpoint => "Exfiltration Endpoint",
        }
    }

    /// Default confidence level for network-indicator sources (hostnames, IPs).
    pub fn default_confidence(self) -> Confidence {
        match self {
            Self::TorExit => Confidence::Medium,
            // Curated exfil destinations are confirmed-bad, like the other
            // network-indicator hostname feeds.
            Self::OssfMalicious
            | Self::DatadogMalicious
            | Self::FeodoTracker
            | Self::EcosystemsTyposquat
            | Self::CisaKev
            | Self::Urlhaus
            | Self::PhishingArmy
            | Self::PhishTank
            | Self::ThreatFoxIoc
            | Self::FireholIp
            | Self::ExfilEndpoint => Confidence::Confirmed,
        }
    }
}

/// Confidence level for a threat match.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum Confidence {
    Low = 0,
    Medium = 1,
    Confirmed = 2,
}

impl Confidence {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Low),
            1 => Some(Self::Medium),
            2 => Some(Self::Confirmed),
            _ => None,
        }
    }

    /// Stable machine-readable identifier (lowercase), matching the serde form.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::Confirmed => "confirmed",
        }
    }
}

/// Result of a package, hostname, or IP lookup in the threat DB.
///
/// `ecosystem` / `all_versions_malicious` are only meaningful for package
/// matches; hostname/IP matches leave `ecosystem` as `None`.
#[derive(Debug, Clone)]
pub struct ThreatMatch {
    pub ecosystem: Option<Ecosystem>,
    pub name: String,
    pub source: ThreatSource,
    pub confidence: Confidence,
    pub reference_url: Option<String>,
    pub all_versions_malicious: bool,
}

/// Result of a typosquat lookup.
#[derive(Debug, Clone)]
pub struct TyposquatMatch {
    pub ecosystem: Ecosystem,
    pub malicious_name: String,
    pub target_name: String,
}

/// Which on-disk format a [`ThreatDbWriter`] should emit. v2 carries the same v1
/// sections PLUS the artifact/file-hash/URL/campaign/behavior sections behind a
/// fixed EOF footer; v1 is byte-for-byte the legacy layout (no footer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatDbFormat {
    V1,
    V2,
}

/// Behavioral capability tags carried as a bitset on a v2 file-hash record.
/// Discriminants are the bit positions and are part of the on-disk format, so
/// they must stay stable; new tags append at higher bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum BehaviorTag {
    ProcessSpawn = 0,
    NetworkExfil = 1,
    RuntimeLoader = 2,
    DynamicCodeLoad = 3,
    StartupHook = 4,
    NativeInit = 5,
    CrossRuntime = 6,
    CredentialAccess = 7,
}

impl BehaviorTag {
    /// The single-bit mask for this tag within a `u16` bitset.
    pub fn mask(self) -> u16 {
        1u16 << (self as u16)
    }

    /// Every tag, in stable bit order.
    pub const ALL: [BehaviorTag; 8] = [
        Self::ProcessSpawn,
        Self::NetworkExfil,
        Self::RuntimeLoader,
        Self::DynamicCodeLoad,
        Self::StartupHook,
        Self::NativeInit,
        Self::CrossRuntime,
        Self::CredentialAccess,
    ];

    /// Decode a bitset into the set of tags it carries (stable bit order).
    pub fn from_bits(bits: u16) -> Vec<BehaviorTag> {
        Self::ALL
            .iter()
            .copied()
            .filter(|t| bits & t.mask() != 0)
            .collect()
    }
}

/// Result of an artifact-SHA-256 lookup against the v2 artifact index. Returned
/// only by a v2 DB; v1 (and the artifact index being absent) yields `None`.
#[derive(Debug, Clone)]
pub struct ArtifactMatch {
    pub source: ThreatSource,
    pub confidence: Confidence,
    /// True when the record marks the whole artifact malicious (vs. a specific
    /// version attestation); mirrors the package `all_versions_malicious` flag.
    pub all_versions_malicious: bool,
    /// Optional campaign label resolved from the v2 campaign string table.
    pub campaign: Option<String>,
}

/// Result of a file-content SHA-256 lookup against the v2 file-hash index.
#[derive(Debug, Clone)]
pub struct FileIndicatorMatch {
    pub source: ThreatSource,
    pub confidence: Confidence,
    /// Decoded behavioral capability tags carried by the record.
    pub behavior_tags: Vec<BehaviorTag>,
    pub campaign: Option<String>,
}

/// Aggregate statistics about a loaded DB.
#[derive(Debug, Clone, Default)]
pub struct ThreatDbStats {
    pub format_version: u32,
    pub build_timestamp: u64,
    pub build_sequence: u64,
    pub package_count: u32,
    pub hostname_count: u32,
    pub ip_count: u32,
    pub typosquat_count: u32,
    pub popular_count: u32,
    pub string_table_bytes: u32,
}

/// Per-source record counts derived by walking a loaded DB's sections.
///
/// `per_source` is private and holds at most one entry per source (an
/// invariant `count_for`/`merge` rely on); the accessor exposes it read-only.
#[derive(Debug, Clone, Default)]
pub struct SourceBreakdown {
    per_source: Vec<(ThreatSource, u64)>,
    pub typosquat_count: u64,
    pub popular_count: u64,
}

impl SourceBreakdown {
    /// Read-only view of the per-source counts, at most one entry per source.
    pub fn per_source(&self) -> &[(ThreatSource, u64)] {
        &self.per_source
    }

    /// Fold another breakdown's counts into this one (overlay into primary).
    fn merge(&mut self, other: SourceBreakdown) {
        for (src, count) in other.per_source {
            if let Some((_, existing)) = self.per_source.iter_mut().find(|(s, _)| *s == src) {
                *existing += count;
            } else {
                self.per_source.push((src, count));
            }
        }
        self.typosquat_count += other.typosquat_count;
        self.popular_count += other.popular_count;
    }

    /// Count for a specific source (0 if absent).
    pub fn count_for(&self, src: ThreatSource) -> u64 {
        self.per_source
            .iter()
            .find(|(s, _)| *s == src)
            .map(|(_, c)| *c)
            .unwrap_or(0)
    }
}

#[derive(Debug, Error)]
pub enum ThreatDbError {
    #[error("invalid magic: expected TIRITHDB")]
    InvalidMagic,
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u32),
    #[error("file too small: {0} bytes, need at least {HEADER_SIZE}")]
    FileTooSmall(usize),
    #[error("section offset/count out of bounds")]
    SectionOutOfBounds,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("signer fingerprint mismatch")]
    FingerprintMismatch,
    #[error("rollback detected: sequence {got} <= current {current}")]
    RollbackDetected { got: u64, current: u64 },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid record at offset {0}")]
    InvalidRecord(usize),
    #[error("string table offset out of bounds: {0}")]
    StringOutOfBounds(u32),
    /// The fixed EOF footer was present but structurally invalid (bad magic,
    /// unsupported trailer version, or trailer bounds that do not fit the file
    /// or escape the signed region). A v2 file that fails this is rejected, so
    /// the DB never loads from a corrupt v2 trailer (fail closed for v2 data).
    #[error("invalid v2 trailer: {0}")]
    InvalidTrailer(&'static str),
}

/// Package index entry (8 bytes): offset_into_data(u32 LE) + key_hash(u32 LE,
/// FNV-1a of (ecosystem, name)). Records are variable-size, length-prefixed:
/// ecosystem(u8), name_len(u16)+name, source(u8), confidence(u8), flags(u8;
/// bit0=all_versions_malicious), version_count(u16) + [len(u16)+bytes]*,
/// reference_offset(u32 into string table; 0xFFFFFFFF = none).
const PKG_INDEX_ENTRY_SIZE: usize = 8;

/// IP record: u32 LE (IPv4) + source(u8) = 5 bytes.
const IP_RECORD_SIZE: usize = 5;

/// Typosquat index entry: offset(u32 LE) + key_hash(u32 LE) = 8 bytes.
const TYPOSQUAT_INDEX_ENTRY_SIZE: usize = 8;

/// Popular package index entry: offset(u32 LE) + key_hash(u32 LE) = 8 bytes.
const POPULAR_INDEX_ENTRY_SIZE: usize = 8;

/// Hostname index entry: offset(u32 LE) + key_hash(u32 LE) = 8 bytes.
const HOSTNAME_INDEX_ENTRY_SIZE: usize = 8;

/// FNV-1a 32-bit hash used for both string-table dedup and index key hashes.
fn fnv1a_hash(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in data {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

fn pkg_key_hash(eco: Ecosystem, name: &[u8]) -> u32 {
    let mut buf = Vec::with_capacity(1 + name.len());
    buf.push(eco as u8);
    buf.extend_from_slice(name);
    fnv1a_hash(&buf)
}

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    buf.get(off..off + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// One parsed, structurally-validated v2 trailer descriptor.
struct Descriptor {
    section_type: SectionType,
    #[allow(dead_code)] // record_version retained for forward-compat dispatch
    record_version: u16,
    offset: u64,
    length: u64,
    count: u64,
}

/// Locate and fully validate the v2 footer + descriptor trailer, returning the
/// section extents the reader will index into. Every arithmetic step is checked
/// and every offset is bounds- and signed-region-validated, so a hostile file
/// can only ever be REJECTED, never made to read out of bounds.
///
/// Validations (any failure rejects the whole file):
/// - fixed EOF footer present, magic matches, `trailer_version` supported;
/// - the trailer region `[trailer_offset, trailer_offset+trailer_length)` lies
///   inside the file, after `HEADER_SIZE` (never inside the signature header),
///   and entirely before the fixed footer;
/// - `trailer_length` is an exact multiple of [`DESCRIPTOR_SIZE`] and the
///   descriptor count is `<= MAX_DESCRIPTORS`;
/// - every descriptor's `section_type` is known (unknown mandatory type rejects;
///   we treat all defined types as mandatory in v1 of the trailer);
/// - no duplicate `section_type`;
/// - each section `[offset, offset+length)` fits the file, starts after
///   `HEADER_SIZE`, and ends at or before `trailer_offset` (so no section runs
///   into the trailer or footer);
/// - for fixed-record sections, `count * record_size == length` with the
///   multiply done checked (`count <= MAX_SECTION_RECORDS` first);
/// - no two sections overlap.
fn parse_v2_footer(data: &[u8]) -> Result<V2Sections, ThreatDbError> {
    use ThreatDbError::InvalidTrailer;

    let file_len = data.len() as u64;
    // The header and the footer must both fit, and they must not overlap.
    let footer_start = file_len
        .checked_sub(FOOTER_SIZE as u64)
        .ok_or(InvalidTrailer("file shorter than footer"))?;
    if footer_start < HEADER_SIZE as u64 {
        return Err(InvalidTrailer("footer overlaps header"));
    }
    let footer = &data[footer_start as usize..];

    if &footer[0..8] != FOOTER_MAGIC {
        return Err(InvalidTrailer("bad footer magic"));
    }
    let trailer_offset =
        read_u64_le(footer, 8).ok_or(InvalidTrailer("truncated trailer_offset"))?;
    let trailer_length =
        read_u64_le(footer, 16).ok_or(InvalidTrailer("truncated trailer_length"))?;
    let trailer_version =
        read_u16_le(footer, 24).ok_or(InvalidTrailer("truncated trailer_version"))?;
    // flags at footer[26..28] reserved for future use; bit usage is validated
    // per-descriptor, not here.
    if trailer_version != TRAILER_VERSION {
        return Err(InvalidTrailer("unsupported trailer version"));
    }

    // Trailer region must sit after the header, before the footer, in bounds.
    let trailer_end = trailer_offset
        .checked_add(trailer_length)
        .ok_or(InvalidTrailer("trailer extent overflow"))?;
    if trailer_offset < HEADER_SIZE as u64 {
        return Err(InvalidTrailer("trailer offset inside header"));
    }
    if trailer_end > footer_start {
        return Err(InvalidTrailer("trailer runs into footer"));
    }

    if trailer_length % DESCRIPTOR_SIZE as u64 != 0 {
        return Err(InvalidTrailer("trailer length not a descriptor multiple"));
    }
    let descriptor_count = trailer_length / DESCRIPTOR_SIZE as u64;
    if descriptor_count > MAX_DESCRIPTORS {
        return Err(InvalidTrailer("too many descriptors"));
    }

    // Parse each descriptor with full bounds + arithmetic checks.
    let mut descriptors: Vec<Descriptor> = Vec::with_capacity(descriptor_count as usize);
    let mut seen_types: Vec<u16> = Vec::new();
    for i in 0..descriptor_count {
        let base = (trailer_offset + i * DESCRIPTOR_SIZE as u64) as usize;
        let raw_type = read_u16_le(data, base).ok_or(InvalidTrailer("truncated descriptor"))?;
        let record_version =
            read_u16_le(data, base + 2).ok_or(InvalidTrailer("truncated descriptor"))?;
        let offset = read_u64_le(data, base + 4).ok_or(InvalidTrailer("truncated descriptor"))?;
        let length = read_u64_le(data, base + 12).ok_or(InvalidTrailer("truncated descriptor"))?;
        let count = read_u64_le(data, base + 20).ok_or(InvalidTrailer("truncated descriptor"))?;

        // Unknown mandatory section type rejects (the trailer carries only
        // sections this version understands).
        let section_type =
            SectionType::from_u16(raw_type).ok_or(InvalidTrailer("unknown section type"))?;
        if seen_types.contains(&raw_type) {
            return Err(InvalidTrailer("duplicate section type"));
        }
        seen_types.push(raw_type);

        // Section extent must fit the file, sit after the header, and end at or
        // before the trailer (so it cannot run into the trailer or footer).
        let section_end = offset
            .checked_add(length)
            .ok_or(InvalidTrailer("section extent overflow"))?;
        if offset < HEADER_SIZE as u64 {
            return Err(InvalidTrailer("section offset inside header"));
        }
        if section_end > trailer_offset {
            return Err(InvalidTrailer("section runs into trailer"));
        }

        // Fixed-record sections: count * record_size must equal length exactly,
        // with the multiply checked.
        if let Some(rec_size) = section_type.record_size() {
            if count > MAX_SECTION_RECORDS {
                return Err(InvalidTrailer("absurd section count"));
            }
            let expected = count
                .checked_mul(rec_size as u64)
                .ok_or(InvalidTrailer("count * record_size overflow"))?;
            if expected != length {
                return Err(InvalidTrailer("section length != count * record_size"));
            }
        }

        descriptors.push(Descriptor {
            section_type,
            record_version,
            offset,
            length,
            count,
        });
    }

    // Reject any pairwise overlap among the sections (the trailer/footer/header
    // are already excluded by the per-descriptor checks above).
    for a in 0..descriptors.len() {
        for b in (a + 1)..descriptors.len() {
            let da = &descriptors[a];
            let db = &descriptors[b];
            let a_end = da.offset + da.length; // checked above
            let b_end = db.offset + db.length;
            if da.offset < b_end && db.offset < a_end {
                return Err(InvalidTrailer("overlapping sections"));
            }
        }
    }

    // Assemble the located extents. Absent optional sections stay zero/empty.
    let mut out = V2Sections::default();
    for d in &descriptors {
        match d.section_type {
            SectionType::ArtifactSha => {
                out.artifact_sha_offset = d.offset;
                out.artifact_sha_count = d.count;
            }
            SectionType::FileHash => {
                out.file_hash_offset = d.offset;
                out.file_hash_count = d.count;
            }
            SectionType::MaliciousUrl => {
                out.url_offset = d.offset;
                out.url_count = d.count;
            }
            SectionType::CampaignStrings => {
                out.campaign_offset = d.offset;
                out.campaign_length = d.length;
            }
            SectionType::BehaviorTags => {
                // Validated structurally above; tags ride inline on file-hash
                // records, so nothing more to retain for lookup.
            }
        }
    }
    Ok(out)
}

/// In-memory threat intelligence database loaded from the signed binary file.
#[derive(Debug)]
pub struct ThreatDb {
    data: Vec<u8>,
    supplemental: Option<Box<ThreatDb>>,
    // Parsed header fields cached for fast access.
    format_version: u32,
    build_timestamp: u64,
    build_sequence: u64,
    pkg_index_offset: u32,
    pkg_index_count: u32,
    hostname_index_offset: u32,
    hostname_index_count: u32,
    ip_offset: u32,
    ip_count: u32,
    typosquat_index_offset: u32,
    typosquat_index_count: u32,
    popular_index_offset: u32,
    popular_index_count: u32,
    string_table_offset: u32,
    string_table_size: u32,
    /// Parsed v2 sections, or `None` for a v1 file (every v2 lookup then
    /// returns None and defers to the supplemental overlay, behaving exactly
    /// like a pre-v2 binary).
    v2: Option<V2Sections>,
}

/// Located, validated v2 section extents (absolute byte offsets into `data`).
/// Present only when [`ThreatDb::from_bytes`] parsed a valid v2 footer + trailer.
#[derive(Debug, Clone, Default)]
struct V2Sections {
    /// Artifact-SHA index: sorted by the full 32-byte hash.
    artifact_sha_offset: u64,
    artifact_sha_count: u64,
    /// File-content-hash index: sorted by the full 32-byte hash.
    file_hash_offset: u64,
    file_hash_count: u64,
    /// Malicious-URL index: sorted by the full 32-byte hash of the normalized URL.
    url_offset: u64,
    url_count: u64,
    /// v2 campaign / URL string table (length-prefixed entries, like the v1 one).
    campaign_offset: u64,
    campaign_length: u64,
    // The behavior-tag bitset rides inline on each file-hash record, so no
    // separate section needs to be retained for lookup; the descriptor is still
    // validated structurally on load.
}

impl ThreatDb {
    /// Load and verify a threat DB from raw bytes.
    ///
    /// `min_sequence` enforces rollback protection — the DB is rejected if its
    /// build sequence is <= this value. Pass 0 to skip.
    pub fn from_bytes(data: Vec<u8>, min_sequence: u64) -> Result<Self, ThreatDbError> {
        if data.len() < HEADER_SIZE {
            return Err(ThreatDbError::FileTooSmall(data.len()));
        }

        if &data[0..8] != MAGIC {
            return Err(ThreatDbError::InvalidMagic);
        }

        let err = || ThreatDbError::InvalidRecord(0);
        let version = read_u32_le(&data, 8).ok_or_else(err)?;
        // Range-accepting: any format in [MIN..=FORMAT_VERSION] loads. A v1 file
        // loads with v2 sections absent; a v2 file loads its v2 sections. An OLD
        // binary (FORMAT_VERSION == 1) keeps its `version != 1` reject and fails
        // closed on a v2 file.
        if !(MIN_SUPPORTED_FORMAT_VERSION..=FORMAT_VERSION).contains(&version) {
            return Err(ThreatDbError::UnsupportedVersion(version));
        }

        let build_timestamp = read_u64_le(&data, 12).ok_or_else(err)?;
        let build_sequence = read_u64_le(&data, 20).ok_or_else(err)?;

        // Rollback protection.
        if min_sequence > 0 && build_sequence <= min_sequence {
            return Err(ThreatDbError::RollbackDetected {
                got: build_sequence,
                current: min_sequence,
            });
        }

        // Section offsets/counts (all within bounds-checked HEADER_SIZE).
        let pkg_index_offset = read_u32_le(&data, 28).ok_or_else(err)?;
        let pkg_index_count = read_u32_le(&data, 32).ok_or_else(err)?;
        let hostname_index_offset = read_u32_le(&data, 36).ok_or_else(err)?;
        let hostname_index_count = read_u32_le(&data, 40).ok_or_else(err)?;
        let ip_offset = read_u32_le(&data, 44).ok_or_else(err)?;
        let ip_count = read_u32_le(&data, 48).ok_or_else(err)?;
        let typosquat_index_offset = read_u32_le(&data, 52).ok_or_else(err)?;
        let typosquat_index_count = read_u32_le(&data, 56).ok_or_else(err)?;
        let popular_index_offset = read_u32_le(&data, 60).ok_or_else(err)?;
        let popular_index_count = read_u32_le(&data, 64).ok_or_else(err)?;
        let string_table_offset = read_u32_le(&data, 68).ok_or_else(err)?;
        let string_table_size = read_u32_le(&data, 72).ok_or_else(err)?;

        // Bounds checks on sections.
        let len = data.len() as u64;
        let check_section = |off: u32, count: u32, entry_size: usize| -> bool {
            let end = off as u64 + count as u64 * entry_size as u64;
            end <= len
        };

        if !check_section(ip_offset, ip_count, IP_RECORD_SIZE) {
            return Err(ThreatDbError::SectionOutOfBounds);
        }

        // Index extents are validated here; individual variable-size records
        // are validated lazily on access.
        if !check_section(pkg_index_offset, pkg_index_count, PKG_INDEX_ENTRY_SIZE) {
            return Err(ThreatDbError::SectionOutOfBounds);
        }
        if !check_section(
            hostname_index_offset,
            hostname_index_count,
            HOSTNAME_INDEX_ENTRY_SIZE,
        ) {
            return Err(ThreatDbError::SectionOutOfBounds);
        }
        if !check_section(
            typosquat_index_offset,
            typosquat_index_count,
            TYPOSQUAT_INDEX_ENTRY_SIZE,
        ) {
            return Err(ThreatDbError::SectionOutOfBounds);
        }
        if !check_section(
            popular_index_offset,
            popular_index_count,
            POPULAR_INDEX_ENTRY_SIZE,
        ) {
            return Err(ThreatDbError::SectionOutOfBounds);
        }

        if (string_table_offset as u64 + string_table_size as u64) > len {
            return Err(ThreatDbError::SectionOutOfBounds);
        }

        // v2 footer/trailer. Only parsed for a v2 file; a v1 file has no footer
        // and `v2` stays None. A v2 file with a malformed footer/trailer is
        // REJECTED (fail closed for v2 data) rather than silently degraded.
        let v2 = if version >= 2 {
            Some(parse_v2_footer(&data)?)
        } else {
            None
        };

        Ok(Self {
            data,
            supplemental: None,
            format_version: version,
            build_timestamp,
            build_sequence,
            pkg_index_offset,
            pkg_index_count,
            hostname_index_offset,
            hostname_index_count,
            ip_offset,
            ip_count,
            typosquat_index_offset,
            typosquat_index_count,
            popular_index_offset,
            popular_index_count,
            string_table_offset,
            string_table_size,
            v2,
        })
    }

    /// Load from the default data directory (`~/.local/share/tirith/tirith-threatdb.dat`).
    pub fn load_from_data_dir() -> Result<Self, ThreatDbError> {
        let path = Self::default_path().ok_or_else(|| {
            ThreatDbError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "cannot determine data directory",
            ))
        })?;
        Self::load_from_path(&path, 0)
    }

    /// Load from a specific path with rollback protection.
    pub fn load_from_path(path: &Path, min_sequence: u64) -> Result<Self, ThreatDbError> {
        let data = std::fs::read(path)?;
        Self::from_bytes(data, min_sequence)
    }

    /// Canonical v1 filesystem path for the primary threat DB. Checks
    /// `TIRITH_THREATDB_PATH` first, then `~/.local/share/tirith/...`.
    ///
    /// This is the path an OLD (v1-only) binary reads, and the only one the v2
    /// updater must never clobber. The loader resolves the *effective* path via
    /// [`resolve_primary_path`], which prefers the v2 file when present and
    /// parseable.
    pub fn default_path() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("TIRITH_THREATDB_PATH") {
            if !p.is_empty() {
                return Some(PathBuf::from(p));
            }
        }
        policy::data_dir().map(|d| d.join(DB_FILENAME))
    }

    /// Distinct v2 primary DB path. A v2-capable client writes the v2 DB here so
    /// a co-located old binary, which only knows [`default_path`], never reads a
    /// v2 file it cannot parse (and is therefore never fail-opened).
    ///
    /// Honors the same `TIRITH_THREATDB_PATH` override as [`default_path`] by
    /// deriving a sibling `*-v2.dat` name next to the overridden path, so tests
    /// and operators that redirect the primary path also redirect its v2 sibling.
    ///
    /// [`default_path`]: Self::default_path
    pub fn default_path_v2() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("TIRITH_THREATDB_PATH") {
            if !p.is_empty() {
                return Some(v2_sibling(&PathBuf::from(p)));
            }
        }
        policy::data_dir().map(|d| d.join(DB_FILENAME_V2))
    }

    /// Effective primary DB path the loader should read: the v2 file when it is
    /// present, structurally loadable, AND signature-valid, else the v1 file. An
    /// old binary never calls this and only ever reads [`default_path`].
    ///
    /// Requiring a valid signature here (not merely "parseable") closes a
    /// fail-open: a structurally-valid but unsigned/wrong-key v2 planted beside a
    /// good v1 must NOT shadow it, since the cache loads exactly the resolved
    /// primary and would otherwise reject the bad v2 without falling back.
    ///
    /// [`default_path`]: Self::default_path
    pub fn resolve_primary_path() -> Option<PathBuf> {
        resolve_preferring_v2(Self::default_path_v2(), Self::default_path(), true)
    }

    /// Canonical v1 supplemental DB path for user-local keyed feeds compiled on
    /// the user's machine during `tirith threat-db update`.
    pub fn supplemental_path() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("TIRITH_THREATDB_SUPPLEMENTAL_PATH") {
            if !p.is_empty() {
                return Some(PathBuf::from(p));
            }
        }
        policy::data_dir().map(|d| d.join(SUPPLEMENTAL_DB_FILENAME))
    }

    /// Distinct v2 supplemental DB path (same split rationale as
    /// [`default_path_v2`]).
    ///
    /// [`default_path_v2`]: Self::default_path_v2
    pub fn supplemental_path_v2() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("TIRITH_THREATDB_SUPPLEMENTAL_PATH") {
            if !p.is_empty() {
                return Some(v2_sibling(&PathBuf::from(p)));
            }
        }
        policy::data_dir().map(|d| d.join(SUPPLEMENTAL_DB_FILENAME_V2))
    }

    /// Effective supplemental DB path: the v2 file when present and structurally
    /// loadable, else the v1 file, else `None` when neither exists. The
    /// supplemental overlay is intentionally UNSIGNED (its authenticity is
    /// anchored to local machine policy, not CI), so the resolver requires only
    /// "parseable" here, never a signature.
    pub fn resolve_supplemental_path() -> Option<PathBuf> {
        resolve_preferring_v2(
            Self::supplemental_path_v2(),
            Self::supplemental_path(),
            false,
        )
    }

    fn with_supplemental(mut self, supplemental: Option<ThreatDb>) -> Self {
        self.supplemental = supplemental.map(Box::new);
        self
    }

    /// Verify the Ed25519 signature and signer fingerprint against the embedded
    /// public key. Returns `Err(reason)` on any failure.
    pub fn verify_signature(&self) -> Result<(), String> {
        let key_fingerprint = Sha256::digest(VERIFY_KEY_BYTES);
        let stored_fp = &self.data[FINGERPRINT_OFFSET..FINGERPRINT_OFFSET + FINGERPRINT_LEN];
        if key_fingerprint.as_slice() != stored_fp {
            return Err("signer fingerprint does not match embedded public key".to_string());
        }

        let verify_key = VerifyingKey::from_bytes(VERIFY_KEY_BYTES)
            .map_err(|e| format!("invalid embedded public key: {e}"))?;

        let sig_bytes = &self.data[SIG_OFFSET..SIG_OFFSET + SIGNATURE_LENGTH];
        let signature = Signature::from_slice(sig_bytes)
            .map_err(|e| format!("invalid signature in header: {e}"))?;

        // Signed message = header before sig ++ all data after header.
        let mut signed_data = Vec::with_capacity(SIG_OFFSET + (self.data.len() - HEADER_SIZE));
        signed_data.extend_from_slice(&self.data[..SIG_OFFSET]);
        signed_data.extend_from_slice(&self.data[HEADER_SIZE..]);

        use ed25519_dalek::Verifier;
        verify_key
            .verify(&signed_data, &signature)
            .map_err(|_| "Ed25519 signature verification failed".to_string())
    }

    pub fn build_time(&self) -> u64 {
        self.build_timestamp
    }

    pub fn build_sequence(&self) -> u64 {
        self.build_sequence
    }

    pub fn stats(&self) -> ThreatDbStats {
        let overlay = self
            .supplemental
            .as_deref()
            .map(|db| db.stats())
            .unwrap_or_default();
        ThreatDbStats {
            format_version: self.format_version,
            build_timestamp: self.build_timestamp,
            build_sequence: self.build_sequence,
            package_count: self.pkg_index_count + overlay.package_count,
            hostname_count: self.hostname_index_count + overlay.hostname_count,
            ip_count: self.ip_count + overlay.ip_count,
            typosquat_count: self.typosquat_index_count + overlay.typosquat_count,
            popular_count: self.popular_index_count + overlay.popular_count,
            string_table_bytes: self.string_table_size + overlay.string_table_bytes,
        }
    }

    /// Count how many records each [`ThreatSource`] contributes, across this DB
    /// and any supplemental overlay. Walks every section (no per-source
    /// manifest on disk); malformed records are skipped best-effort.
    pub fn source_breakdown(&self) -> SourceBreakdown {
        let mut breakdown = self.source_breakdown_self();
        if let Some(overlay) = self.supplemental.as_deref() {
            breakdown.merge(overlay.source_breakdown());
        }
        breakdown
    }

    /// Per-source counts for this DB file only (no overlay recursion).
    fn source_breakdown_self(&self) -> SourceBreakdown {
        let mut counts: std::collections::BTreeMap<u8, u64> = std::collections::BTreeMap::new();
        let mut bump = |src: ThreatSource| {
            *counts.entry(src as u8).or_insert(0) += 1;
        };

        // Packages: index entries point to variable-size records.
        for i in 0..self.pkg_index_count {
            if let Some((data_off, _)) = self.pkg_index_entry(i) {
                if let Some(rec) = self.parse_pkg_record(data_off as usize) {
                    bump(rec.source);
                }
            }
        }

        // Hostnames: record is source(u8) + name_len(u16 LE) + name.
        for i in 0..self.hostname_index_count {
            let base = self.hostname_index_offset as usize + i as usize * HOSTNAME_INDEX_ENTRY_SIZE;
            if let Some(data_off) = read_u32_le(&self.data, base) {
                if let Some(src) = self
                    .data
                    .get(data_off as usize)
                    .and_then(|&b| ThreatSource::from_u8(b))
                {
                    bump(src);
                }
            }
        }

        // IPs: fixed-size records, source byte at offset+4.
        for i in 0..self.ip_count {
            let base = self.ip_offset as usize + i as usize * IP_RECORD_SIZE;
            if let Some(src) = self
                .data
                .get(base + 4)
                .and_then(|&b| ThreatSource::from_u8(b))
            {
                bump(src);
            }
        }

        SourceBreakdown {
            per_source: ThreatSource::ALL
                .iter()
                .map(|src| {
                    // Typosquat records carry no source byte, so the walk never
                    // bumps `EcosystemsTyposquat`; attribute the whole typosquat
                    // index to it (adding, not replacing, stays correct).
                    let mut count = counts.get(&(*src as u8)).copied().unwrap_or(0);
                    if *src == ThreatSource::EcosystemsTyposquat {
                        count += self.typosquat_index_count as u64;
                    }
                    (*src, count)
                })
                .collect(),
            // Typosquat and popular counts are also reported as their own
            // categories (popular has no single source).
            typosquat_count: self.typosquat_index_count as u64,
            popular_count: self.popular_index_count as u64,
        }
    }

    fn read_string_table_entry(&self, offset: u32) -> Option<&str> {
        if offset == 0xFFFF_FFFF {
            return None;
        }
        let abs = self.string_table_offset as usize + offset as usize;
        let len = read_u16_le(&self.data, abs)? as usize;
        let start = abs + 2;
        let end = start + len;
        if end > self.data.len() {
            return None;
        }
        std::str::from_utf8(&self.data[start..end]).ok()
    }

    /// Returns (data_offset, key_hash) for a package index entry.
    fn pkg_index_entry(&self, idx: u32) -> Option<(u32, u32)> {
        let base = self.pkg_index_offset as usize + idx as usize * PKG_INDEX_ENTRY_SIZE;
        let data_off = read_u32_le(&self.data, base)?;
        let hash = read_u32_le(&self.data, base + 4)?;
        Some((data_off, hash))
    }

    /// Parse a package record at an absolute offset.
    fn parse_pkg_record(&self, off: usize) -> Option<PkgRecord<'_>> {
        let eco = Ecosystem::from_u8(*self.data.get(off)?)?;
        let name_len = read_u16_le(&self.data, off + 1)? as usize;
        let name_start = off + 3;
        let name_end = name_start + name_len;
        if name_end + 4 > self.data.len() {
            return None;
        }
        let name = std::str::from_utf8(&self.data[name_start..name_end]).ok()?;
        let mut cursor = name_end;

        let source = ThreatSource::from_u8(*self.data.get(cursor)?)?;
        cursor += 1;
        let confidence = Confidence::from_u8(*self.data.get(cursor)?)?;
        cursor += 1;
        let flags = *self.data.get(cursor)?;
        cursor += 1;
        let all_versions_malicious = (flags & 1) != 0;

        let version_count = read_u16_le(&self.data, cursor)? as usize;
        cursor += 2;

        let mut versions = Vec::with_capacity(version_count);
        for _ in 0..version_count {
            let vlen = read_u16_le(&self.data, cursor)? as usize;
            cursor += 2;
            let vend = cursor + vlen;
            if vend > self.data.len() {
                return None;
            }
            let v = std::str::from_utf8(&self.data[cursor..vend]).ok()?;
            versions.push(v);
            cursor = vend;
        }

        let ref_offset = read_u32_le(&self.data, cursor)?;

        Some(PkgRecord {
            ecosystem: eco,
            name,
            source,
            confidence,
            all_versions_malicious,
            versions,
            reference_offset: ref_offset,
        })
    }

    /// Check a package against the threat DB.
    ///
    /// - If `version` is `Some`, match if `all_versions_malicious` is set OR
    ///   the version appears in the record's affected versions list.
    /// - If `version` is `None`, match only if `all_versions_malicious` is set.
    pub fn check_package(
        &self,
        eco: Ecosystem,
        name: &str,
        version: Option<&str>,
    ) -> Option<ThreatMatch> {
        let target_hash = pkg_key_hash(eco, name.as_bytes());

        if let Some(idx) = self.binary_search_pkg_index(eco, name, target_hash) {
            let (data_off, _) = self.pkg_index_entry(idx)?;
            let rec = self.parse_pkg_record(data_off as usize)?;

            match version {
                Some(v) => {
                    if !rec.all_versions_malicious && !rec.versions.iter().any(|rv| rv == &v) {
                        return self
                            .supplemental
                            .as_deref()
                            .and_then(|db| db.check_package(eco, name, version));
                    }
                }
                None => {
                    if !rec.all_versions_malicious {
                        return self
                            .supplemental
                            .as_deref()
                            .and_then(|db| db.check_package(eco, name, version));
                    }
                }
            }

            let reference_url = self
                .read_string_table_entry(rec.reference_offset)
                .map(String::from);

            return Some(ThreatMatch {
                ecosystem: Some(rec.ecosystem),
                name: rec.name.to_string(),
                source: rec.source,
                confidence: rec.confidence,
                reference_url,
                all_versions_malicious: rec.all_versions_malicious,
            });
        }

        self.supplemental
            .as_deref()
            .and_then(|db| db.check_package(eco, name, version))
    }

    fn binary_search_pkg_index(&self, eco: Ecosystem, name: &str, target_hash: u32) -> Option<u32> {
        if self.pkg_index_count == 0 {
            return None;
        }
        let mut lo: u32 = 0;
        let mut hi: u32 = self.pkg_index_count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let (data_off, hash) = self.pkg_index_entry(mid)?;

            // Compare by hash first (fast path), then verify the actual key.
            match hash.cmp(&target_hash) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => {
                    let rec = self.parse_pkg_record(data_off as usize)?;
                    match (rec.ecosystem as u8, rec.name).cmp(&(eco as u8, name)) {
                        std::cmp::Ordering::Equal => return Some(mid),
                        std::cmp::Ordering::Less => lo = mid + 1,
                        std::cmp::Ordering::Greater => hi = mid,
                    }
                }
            }
        }
        None
    }

    /// Check a hostname against the threat DB.
    pub fn check_hostname(&self, host: &str) -> Option<ThreatMatch> {
        if self.hostname_index_count == 0 {
            return self
                .supplemental
                .as_deref()
                .and_then(|db| db.check_hostname(host));
        }
        let normalized = host.to_ascii_lowercase();
        let target_hash = fnv1a_hash(normalized.as_bytes());

        let Some(idx) = self.binary_search_hostname_index(&normalized, target_hash) else {
            return self
                .supplemental
                .as_deref()
                .and_then(|db| db.check_hostname(host));
        };
        let base = self.hostname_index_offset as usize + idx as usize * HOSTNAME_INDEX_ENTRY_SIZE;
        let data_off = read_u32_le(&self.data, base)? as usize;

        // Hostname record: source(u8) + name_len(u16 LE) + name(bytes).
        let source = ThreatSource::from_u8(*self.data.get(data_off)?)?;
        let name_len = read_u16_le(&self.data, data_off + 1)? as usize;
        let name_start = data_off + 3;
        let name_end = name_start + name_len;
        if name_end > self.data.len() {
            return None;
        }

        Some(ThreatMatch {
            ecosystem: None,
            name: normalized,
            confidence: source.default_confidence(),
            source,
            reference_url: None,
            all_versions_malicious: false,
        })
    }

    fn binary_search_hostname_index(&self, normalized: &str, target_hash: u32) -> Option<u32> {
        if self.hostname_index_count == 0 {
            return None;
        }
        let mut lo: u32 = 0;
        let mut hi: u32 = self.hostname_index_count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let base =
                self.hostname_index_offset as usize + mid as usize * HOSTNAME_INDEX_ENTRY_SIZE;
            let _data_off = read_u32_le(&self.data, base)?;
            let hash = read_u32_le(&self.data, base + 4)?;
            match hash.cmp(&target_hash) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => {
                    let data_off = _data_off as usize;
                    let name_len = read_u16_le(&self.data, data_off + 1)? as usize;
                    let name_start = data_off + 3;
                    let name_end = name_start + name_len;
                    if name_end > self.data.len() {
                        return None;
                    }
                    let stored = std::str::from_utf8(&self.data[name_start..name_end]).ok()?;
                    match stored.cmp(normalized) {
                        std::cmp::Ordering::Equal => return Some(mid),
                        std::cmp::Ordering::Less => lo = mid + 1,
                        std::cmp::Ordering::Greater => hi = mid,
                    }
                }
            }
        }
        None
    }

    /// Check an IPv4 address against the threat DB.
    pub fn check_ip(&self, ip: Ipv4Addr) -> Option<ThreatMatch> {
        if self.ip_count == 0 {
            return self.supplemental.as_deref().and_then(|db| db.check_ip(ip));
        }
        let target = u32::from(ip);
        let Some(idx) = self.binary_search_ip(target) else {
            return self.supplemental.as_deref().and_then(|db| db.check_ip(ip));
        };
        let base = self.ip_offset as usize + idx as usize * IP_RECORD_SIZE;
        let source = ThreatSource::from_u8(*self.data.get(base + 4)?)?;

        Some(ThreatMatch {
            ecosystem: None,
            name: ip.to_string(),
            confidence: source.default_confidence(),
            source,
            reference_url: None,
            all_versions_malicious: false,
        })
    }

    fn binary_search_ip(&self, target: u32) -> Option<u32> {
        let mut lo: u32 = 0;
        let mut hi: u32 = self.ip_count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let base = self.ip_offset as usize + mid as usize * IP_RECORD_SIZE;
            let val = read_u32_le(&self.data, base)?;
            match val.cmp(&target) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(mid),
            }
        }
        None
    }

    /// Check a package name against known typosquats.
    pub fn check_typosquat(&self, eco: Ecosystem, name: &str) -> Option<TyposquatMatch> {
        if self.typosquat_index_count == 0 {
            return self
                .supplemental
                .as_deref()
                .and_then(|db| db.check_typosquat(eco, name));
        }
        let target_hash = pkg_key_hash(eco, name.as_bytes());
        let Some(idx) = self.binary_search_typosquat_index(eco, name, target_hash) else {
            return self
                .supplemental
                .as_deref()
                .and_then(|db| db.check_typosquat(eco, name));
        };
        let base = self.typosquat_index_offset as usize + idx as usize * TYPOSQUAT_INDEX_ENTRY_SIZE;
        let data_off = read_u32_le(&self.data, base)? as usize;

        // Typosquat record: ecosystem(u8) + mal_len(u16)+mal + tgt_len(u16)+tgt.
        let _eco = Ecosystem::from_u8(*self.data.get(data_off)?)?;
        let mut cursor = data_off + 1;
        let mal_len = read_u16_le(&self.data, cursor)? as usize;
        cursor += 2;
        let mal_end = cursor + mal_len;
        if mal_end > self.data.len() {
            return None;
        }
        let malicious_name = std::str::from_utf8(&self.data[cursor..mal_end]).ok()?;
        cursor = mal_end;

        let tgt_len = read_u16_le(&self.data, cursor)? as usize;
        cursor += 2;
        let tgt_end = cursor + tgt_len;
        if tgt_end > self.data.len() {
            return None;
        }
        let target_name = std::str::from_utf8(&self.data[cursor..tgt_end]).ok()?;

        Some(TyposquatMatch {
            ecosystem: eco,
            malicious_name: malicious_name.to_string(),
            target_name: target_name.to_string(),
        })
    }

    fn binary_search_typosquat_index(
        &self,
        eco: Ecosystem,
        name: &str,
        target_hash: u32,
    ) -> Option<u32> {
        let mut lo: u32 = 0;
        let mut hi: u32 = self.typosquat_index_count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let base =
                self.typosquat_index_offset as usize + mid as usize * TYPOSQUAT_INDEX_ENTRY_SIZE;
            let _data_off = read_u32_le(&self.data, base)?;
            let hash = read_u32_le(&self.data, base + 4)?;
            match hash.cmp(&target_hash) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => {
                    let data_off = _data_off as usize;
                    let rec_eco = Ecosystem::from_u8(*self.data.get(data_off)?)?;
                    let mal_len = read_u16_le(&self.data, data_off + 1)? as usize;
                    let mal_start = data_off + 3;
                    let mal_end = mal_start + mal_len;
                    if mal_end > self.data.len() {
                        return None;
                    }
                    let stored = std::str::from_utf8(&self.data[mal_start..mal_end]).ok()?;
                    match (rec_eco as u8, stored).cmp(&(eco as u8, name)) {
                        std::cmp::Ordering::Equal => return Some(mid),
                        std::cmp::Ordering::Less => lo = mid + 1,
                        std::cmp::Ordering::Greater => hi = mid,
                    }
                }
            }
        }
        None
    }

    /// Read a length-prefixed entry from the v2 campaign string table at a
    /// relative `offset` (`0xFFFF_FFFF` = none). Mirrors the v1 string-table
    /// reader but keyed off the v2 campaign section's absolute base.
    fn read_campaign_string(&self, offset: u32) -> Option<&str> {
        if offset == 0xFFFF_FFFF {
            return None;
        }
        let v2 = self.v2.as_ref()?;
        let abs = v2.campaign_offset.checked_add(offset as u64)? as usize;
        let len = read_u16_le(&self.data, abs)? as usize;
        let start = abs.checked_add(2)?;
        let end = start.checked_add(len)?;
        // The string must stay inside the campaign section's own extent.
        if end as u64 > v2.campaign_offset + v2.campaign_length {
            return None;
        }
        std::str::from_utf8(&self.data[start..end]).ok()
    }

    /// Binary-search a fixed-record v2 index (artifact or file-hash) whose first
    /// 32 bytes per record are the full SHA-256, sorted ascending. Returns the
    /// absolute byte offset of the matching record, or `None`.
    fn binary_search_hash_index(
        &self,
        section_offset: u64,
        section_count: u64,
        record_size: usize,
        target: &[u8; 32],
    ) -> Option<usize> {
        if section_count == 0 {
            return None;
        }
        let mut lo: u64 = 0;
        let mut hi: u64 = section_count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let base = (section_offset + mid * record_size as u64) as usize;
            let stored = self.data.get(base..base + 32)?;
            match stored.cmp(&target[..]) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(base),
            }
        }
        None
    }

    /// Look up a wheel/sdist artifact by the FULL 32-byte SHA-256 of its bytes.
    ///
    /// Returns `None` for a v1 file (no artifact index) and defers to the
    /// supplemental overlay on a local miss, exactly mirroring [`check_hostname`].
    /// This is one of the two methods PR B8 reserved a feature-gated seam for;
    /// DB-B only ADDS it.
    ///
    /// [`check_hostname`]: Self::check_hostname
    pub fn check_artifact_sha256(&self, sha256: &[u8; 32]) -> Option<ArtifactMatch> {
        if let Some(v2) = self.v2.as_ref() {
            if let Some(base) = self.binary_search_hash_index(
                v2.artifact_sha_offset,
                v2.artifact_sha_count,
                ARTIFACT_SHA_RECORD_SIZE,
                sha256,
            ) {
                // Record layout: sha[32] confidence(u8) source(u8) flags(u8)
                // reserved(u8) campaign_offset(u32).
                let confidence = Confidence::from_u8(*self.data.get(base + 32)?)?;
                let source = ThreatSource::from_u8(*self.data.get(base + 33)?)?;
                let flags = *self.data.get(base + 34)?;
                let all_versions_malicious = flags & 1 != 0;
                let campaign_offset = read_u32_le(&self.data, base + 36)?;
                let campaign = self.read_campaign_string(campaign_offset).map(String::from);
                return Some(ArtifactMatch {
                    source,
                    confidence,
                    all_versions_malicious,
                    campaign,
                });
            }
        }
        self.supplemental
            .as_deref()
            .and_then(|db| db.check_artifact_sha256(sha256))
    }

    /// Look up a file by the FULL 32-byte SHA-256 of its content against the v2
    /// file-hash index. `None` for v1; defers to supplemental on a miss.
    pub fn check_file_sha256(&self, sha256: &[u8; 32]) -> Option<FileIndicatorMatch> {
        if let Some(v2) = self.v2.as_ref() {
            if let Some(base) = self.binary_search_hash_index(
                v2.file_hash_offset,
                v2.file_hash_count,
                FILE_HASH_RECORD_SIZE,
                sha256,
            ) {
                // Record layout: sha[32] confidence(u8) source(u8)
                // behavior_tags(u16) campaign_offset(u32).
                let confidence = Confidence::from_u8(*self.data.get(base + 32)?)?;
                let source = ThreatSource::from_u8(*self.data.get(base + 33)?)?;
                let tag_bits = read_u16_le(&self.data, base + 34)?;
                let campaign_offset = read_u32_le(&self.data, base + 36)?;
                let campaign = self.read_campaign_string(campaign_offset).map(String::from);
                return Some(FileIndicatorMatch {
                    source,
                    confidence,
                    behavior_tags: BehaviorTag::from_bits(tag_bits),
                    campaign,
                });
            }
        }
        self.supplemental
            .as_deref()
            .and_then(|db| db.check_file_sha256(sha256))
    }

    /// Look up a normalized URL string against the v2 malicious-URL index. The
    /// index is keyed on the SHA-256 of the normalized URL; after locating the
    /// hash, the stored URL is compared for an exact match (so a hash collision
    /// cannot produce a false positive). `None` for v1; defers to supplemental.
    pub fn check_malicious_url(&self, normalized_url: &str) -> Option<ThreatSource> {
        if let Some(v2) = self.v2.as_ref() {
            let digest = Sha256::digest(normalized_url.as_bytes());
            let mut target = [0u8; 32];
            target.copy_from_slice(&digest);
            if let Some(base) = self.binary_search_hash_index(
                v2.url_offset,
                v2.url_count,
                URL_INDEX_RECORD_SIZE,
                &target,
            ) {
                // Record layout: sha[32] url_offset(u32) source(u8) reserved(u8).
                let url_offset = read_u32_le(&self.data, base + 32)?;
                let source = ThreatSource::from_u8(*self.data.get(base + 36)?)?;
                // Compare the stored URL after locating the hash range.
                if self.read_campaign_string(url_offset) == Some(normalized_url) {
                    return Some(source);
                }
            }
        }
        self.supplemental
            .as_deref()
            .and_then(|db| db.check_malicious_url(normalized_url))
    }

    /// Whether `name` is itself a known-popular package in `eco`. Exact-match
    /// companion to [`check_popular_distance`], which instead flags near-misses.
    ///
    /// [`check_popular_distance`]: Self::check_popular_distance
    pub fn is_popular_package(&self, eco: Ecosystem, name: &str) -> bool {
        // Linear scan: the popular index is sorted by (ecosystem, name), not by
        // hash, so a hash-keyed binary search would be unsound.
        for i in 0..self.popular_index_count {
            let base = self.popular_index_offset as usize + i as usize * POPULAR_INDEX_ENTRY_SIZE;
            let data_off = match read_u32_le(&self.data, base) {
                Some(v) => v as usize,
                None => continue,
            };
            let rec_eco = match self.data.get(data_off).and_then(|&b| Ecosystem::from_u8(b)) {
                Some(e) => e,
                None => continue,
            };
            if rec_eco != eco {
                continue;
            }
            let name_len = match read_u16_le(&self.data, data_off + 1) {
                Some(l) => l as usize,
                None => continue,
            };
            let name_start = data_off + 3;
            let name_end = name_start + name_len;
            if name_end > self.data.len() {
                continue;
            }
            if let Ok(popular_name) = std::str::from_utf8(&self.data[name_start..name_end]) {
                if popular_name == name {
                    return true;
                }
            }
        }
        self.supplemental
            .as_deref()
            .map(|db| db.is_popular_package(eco, name))
            .unwrap_or(false)
    }

    /// Find the closest popular package name within Levenshtein distance.
    /// Returns `(popular_name, distance)` if distance <= 1.
    pub fn check_popular_distance(&self, eco: Ecosystem, name: &str) -> Option<(String, usize)> {
        // Linear scan is fine for ~5k short names.
        let mut best: Option<(String, usize)> = None;
        let max_distance = 1;

        for i in 0..self.popular_index_count {
            let base = self.popular_index_offset as usize + i as usize * POPULAR_INDEX_ENTRY_SIZE;
            let data_off = match read_u32_le(&self.data, base) {
                Some(v) => v as usize,
                None => continue,
            };

            // Popular record: ecosystem(u8) + name_len(u16 LE) + name(bytes).
            let rec_eco = match self.data.get(data_off).and_then(|&b| Ecosystem::from_u8(b)) {
                Some(e) => e,
                None => continue,
            };
            if rec_eco != eco {
                continue;
            }

            let name_len = match read_u16_le(&self.data, data_off + 1) {
                Some(l) => l as usize,
                None => continue,
            };
            let name_start = data_off + 3;
            let name_end = name_start + name_len;
            if name_end > self.data.len() {
                continue;
            }
            let popular_name = match std::str::from_utf8(&self.data[name_start..name_end]) {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Skip exact matches — the package itself is popular, not suspicious.
            if popular_name == name {
                continue;
            }

            let dist = levenshtein(name, popular_name);
            if dist <= max_distance {
                match &best {
                    Some((_, d)) if dist < *d => {
                        best = Some((popular_name.to_string(), dist));
                    }
                    None => {
                        best = Some((popular_name.to_string(), dist));
                    }
                    _ => {}
                }
            }
        }

        let overlay = self
            .supplemental
            .as_deref()
            .and_then(|db| db.check_popular_distance(eco, name));

        // Return whichever result has the smaller edit distance; prefer primary on tie.
        match (best, overlay) {
            (Some(a), Some(b)) if b.1 < a.1 => Some(b),
            (Some(a), _) => Some(a),
            (None, b) => b,
        }
    }

    /// Get the cached threat DB instance, loading/reloading as needed.
    /// Re-checks file mtime every 60s; returns `None` on miss/failure (fail-open).
    pub fn cached() -> Option<Arc<ThreatDb>> {
        let cache = CACHE.get_or_init(ThreatDbCache::new);
        cache.get()
    }

    /// Force-refresh the cached DB. Honors source/overlay changes even when the
    /// primary build sequence is unchanged (tests, supplemental rebuilds).
    pub fn refresh_cache() {
        if let Some(cache) = CACHE.get() {
            cache.force_reload();
        } else {
            let _ = CACHE.get_or_init(ThreatDbCache::new);
        }
    }
}

// Internal parsed record (borrows from DB data).
struct PkgRecord<'a> {
    ecosystem: Ecosystem,
    name: &'a str,
    source: ThreatSource,
    confidence: Confidence,
    all_versions_malicious: bool,
    versions: Vec<&'a str>,
    reference_offset: u32,
}

static CACHE: OnceLock<ThreatDbCache> = OnceLock::new();

struct ThreatDbCache {
    db: RwLock<Option<Arc<ThreatDb>>>,
    last_mtime_check: AtomicU64,
    loaded_mtime: AtomicU64,
}

struct CacheSource {
    primary_path: PathBuf,
    supplemental_path: Option<PathBuf>,
    combined_mtime: u64,
}

impl ThreatDbCache {
    fn new() -> Self {
        let cache = Self {
            db: RwLock::new(None),
            last_mtime_check: AtomicU64::new(0),
            loaded_mtime: AtomicU64::new(0),
        };
        // Attempt initial load
        cache.force_reload();
        cache
    }

    fn get(&self) -> Option<Arc<ThreatDb>> {
        let now = unix_now();
        let last_check = self.last_mtime_check.load(Ordering::Relaxed);
        if now.saturating_sub(last_check) >= MTIME_CHECK_INTERVAL_SECS {
            self.last_mtime_check.store(now, Ordering::Relaxed);
            match current_cache_source() {
                Some(source) => {
                    if source.combined_mtime != self.loaded_mtime.load(Ordering::Relaxed) {
                        self.reload(&source, false);
                    }
                }
                None => self.clear(),
            }
        }
        self.db.read().ok()?.clone()
    }

    fn force_reload(&self) {
        if let Some(source) = current_cache_source() {
            self.reload(&source, true);
        } else {
            self.clear();
        }
    }

    fn reload(&self, source: &CacheSource, allow_downgrade: bool) {
        let current_seq = self
            .db
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().map(|db| db.build_sequence))
            .unwrap_or(0);
        let loaded_mtime = self.loaded_mtime.load(Ordering::Relaxed);

        match ThreatDb::load_from_path(&source.primary_path, 0) {
            Ok(primary_db) => {
                if let Err(e) = primary_db.verify_signature() {
                    eprintln!(
                        "tirith: warning: threat DB failed signature verification, ignoring update: {e}"
                    );
                    return;
                }
                // Supplemental overlays are intentionally NOT signature-verified
                // (authenticity is anchored to local machine policy, not CI);
                // `load_from_path` still validates binary structure/header/version.
                let supplemental_db =
                    source.supplemental_path.as_ref().and_then(
                        |path| match ThreatDb::load_from_path(path, 0) {
                            Ok(db) => Some(db),
                            Err(e) => {
                                eprintln!(
                                "tirith: warning: failed to load supplemental threat DB {}: {e}",
                                path.display()
                            );
                                None
                            }
                        },
                    );
                let new_db = primary_db.with_supplemental(supplemental_db);
                if should_replace_cached_db(
                    current_seq,
                    new_db.build_sequence,
                    loaded_mtime,
                    source.combined_mtime,
                    allow_downgrade,
                ) {
                    if let Ok(mut guard) = self.db.write() {
                        *guard = Some(Arc::new(new_db));
                        self.loaded_mtime
                            .store(source.combined_mtime, Ordering::Relaxed);
                    }
                }
            }
            Err(e) => {
                eprintln!("tirith: warning: failed to reload threat DB: {e}");
            }
        }
    }

    fn clear(&self) {
        if let Ok(mut guard) = self.db.write() {
            *guard = None;
        }
        self.loaded_mtime.store(0, Ordering::Relaxed);
    }
}

fn should_replace_cached_db(
    current_sequence: u64,
    new_sequence: u64,
    loaded_mtime: u64,
    new_mtime: u64,
    allow_downgrade: bool,
) -> bool {
    allow_downgrade
        || current_sequence == 0
        || new_sequence > current_sequence
        || (new_sequence == current_sequence && new_mtime != loaded_mtime)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn path_mtime_epoch(path: &Path) -> Option<u64> {
    let meta = std::fs::metadata(path).ok()?;
    meta.modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Derive the `*-v2.dat` sibling of a `.dat` path: replace a trailing `.dat`
/// extension with `-v2.dat`, falling back to appending `-v2` for any other name.
fn v2_sibling(path: &Path) -> PathBuf {
    if path.extension().and_then(|e| e.to_str()) == Some("dat") {
        // Strip the ".dat" extension and append "-v2.dat", operating on the OsStr so
        // a non-UTF-8 filename is not corrupted by a lossy string conversion.
        if let Some(stem) = path.file_stem() {
            let mut name = stem.to_os_string();
            name.push("-v2.dat");
            return path.with_file_name(name);
        }
    }
    let mut s = path.as_os_str().to_os_string();
    s.push("-v2");
    PathBuf::from(s)
}

/// Prefer `v2_path` when it exists AND loads (any format), else `v1_path` when
/// it exists, else `None`. "Loads" means [`ThreatDb::load_from_path`] succeeds;
/// when `require_signature` is set, the v2 file must ALSO pass
/// [`ThreatDb::verify_signature`]. A present-but-corrupt (or, for the signed
/// primary, wrongly-signed) v2 file is skipped so it never shadows a good v1.
fn resolve_preferring_v2(
    v2_path: Option<PathBuf>,
    v1_path: Option<PathBuf>,
    require_signature: bool,
) -> Option<PathBuf> {
    if let Some(ref v2) = v2_path {
        if v2.exists() {
            if let Ok(db) = ThreatDb::load_from_path(v2, 0) {
                if !require_signature || db.verify_signature().is_ok() {
                    return v2_path;
                }
            }
        }
    }
    match v1_path {
        Some(p) if p.exists() => Some(p),
        // No v1 file but a (corrupt-or-not) v2 path: fall back to whatever v1
        // path was configured so the caller's "missing" handling is unchanged.
        _ => v1_path,
    }
}

fn current_cache_source() -> Option<CacheSource> {
    // Prefer the v2 primary/supplemental files when present and parseable; an
    // old binary never reaches this code and only ever reads the v1 names.
    let primary_path = ThreatDb::resolve_primary_path()?;
    let primary_mtime = path_mtime_epoch(&primary_path)?;
    let supplemental_path = ThreatDb::resolve_supplemental_path().filter(|path| path.exists());
    let supplemental_mtime = supplemental_path
        .as_ref()
        .and_then(|path| path_mtime_epoch(path))
        .unwrap_or(0);

    Some(CacheSource {
        primary_path,
        supplemental_path,
        combined_mtime: combined_mtime_from_parts(primary_mtime, supplemental_mtime),
    })
}

fn combined_mtime_from_parts(primary_mtime: u64, supplemental_mtime: u64) -> u64 {
    primary_mtime.rotate_left(13) ^ supplemental_mtime.rotate_left(29) ^ 0x5448_5245_4154_4442
}

#[cfg(test)]
fn combined_mtime_epoch() -> Option<u64> {
    current_cache_source().map(|source| source.combined_mtime)
}

/// Builder for creating threat DB files (used by the compiler binary to
/// produce `.dat` files).
///
/// Usage:
/// ```ignore
/// let mut writer = ThreatDbWriter::new(build_timestamp, build_sequence);
/// writer.add_package(Ecosystem::Npm, "evil-pkg", &["1.0.0"], ThreatSource::OssfMalicious,
///                    Confidence::Confirmed, true, Some("https://ref"));
/// writer.add_ip(Ipv4Addr::new(1,2,3,4), ThreatSource::FeodoTracker);
/// writer.write_to(Path::new("threatdb.dat"), &signing_key)?;
/// ```
pub struct ThreatDbWriter {
    build_timestamp: u64,
    build_sequence: u64,
    packages: Vec<WriterPkg>,
    hostnames: Vec<WriterHostname>,
    ips: Vec<WriterIp>,
    typosquats: Vec<WriterTyposquat>,
    popular: Vec<WriterPopular>,
    string_table: StringTable,
    // v2-only inputs. Empty for a v1 build; only emitted by `build_format(V2,..)`.
    artifact_shas: Vec<WriterArtifactSha>,
    file_hashes: Vec<WriterFileHash>,
    malicious_urls: Vec<WriterMaliciousUrl>,
}

struct WriterArtifactSha {
    sha256: [u8; 32],
    source: ThreatSource,
    confidence: Confidence,
    all_versions_malicious: bool,
    /// Campaign label offset into the v2 campaign string table (set at build).
    campaign: Option<String>,
}

struct WriterFileHash {
    sha256: [u8; 32],
    source: ThreatSource,
    confidence: Confidence,
    behavior_tags: u16,
    campaign: Option<String>,
}

struct WriterMaliciousUrl {
    /// The normalized URL string (stored in the campaign string table) and
    /// keyed in the index by its SHA-256.
    normalized_url: String,
    source: ThreatSource,
}

struct WriterPkg {
    ecosystem: Ecosystem,
    name: String,
    versions: Vec<String>,
    source: ThreatSource,
    confidence: Confidence,
    all_versions_malicious: bool,
    reference_offset: u32, // into string table
}

struct WriterHostname {
    name: String,
    source: ThreatSource,
}

struct WriterIp {
    addr: u32,
    source: ThreatSource,
}

struct WriterTyposquat {
    ecosystem: Ecosystem,
    malicious_name: String,
    target_name: String,
}

struct WriterPopular {
    ecosystem: Ecosystem,
    name: String,
}

/// Deduplicated string table builder.
struct StringTable {
    data: Vec<u8>,
    index: std::collections::HashMap<String, u32>,
}

impl StringTable {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            index: std::collections::HashMap::new(),
        }
    }

    /// Intern a string, returning its offset.
    fn intern(&mut self, s: &str) -> u32 {
        if let Some(&off) = self.index.get(s) {
            return off;
        }
        let off = self.data.len() as u32;
        let bytes = s.as_bytes();
        self.data
            .extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        self.data.extend_from_slice(bytes);
        self.index.insert(s.to_string(), off);
        off
    }

    fn bytes(&self) -> &[u8] {
        &self.data
    }

    fn len(&self) -> u32 {
        self.data.len() as u32
    }
}

impl ThreatDbWriter {
    pub fn new(build_timestamp: u64, build_sequence: u64) -> Self {
        Self {
            build_timestamp,
            build_sequence,
            packages: Vec::new(),
            hostnames: Vec::new(),
            ips: Vec::new(),
            typosquats: Vec::new(),
            popular: Vec::new(),
            string_table: StringTable::new(),
            artifact_shas: Vec::new(),
            file_hashes: Vec::new(),
            malicious_urls: Vec::new(),
        }
    }

    /// Add a malicious-artifact record keyed by the FULL 32-byte SHA-256 of the
    /// artifact bytes. v2-only: ignored by a `ThreatDbFormat::V1` build.
    pub fn add_artifact_sha256(
        &mut self,
        sha256: [u8; 32],
        source: ThreatSource,
        confidence: Confidence,
        all_versions_malicious: bool,
        campaign: Option<&str>,
    ) {
        self.artifact_shas.push(WriterArtifactSha {
            sha256,
            source,
            confidence,
            all_versions_malicious,
            campaign: campaign.map(str::to_string),
        });
    }

    /// Add a malicious-file record keyed by the FULL 32-byte SHA-256 of the file
    /// content, carrying a behavior-tag bitset. v2-only.
    pub fn add_file_sha256(
        &mut self,
        sha256: [u8; 32],
        source: ThreatSource,
        confidence: Confidence,
        behavior_tags: &[BehaviorTag],
        campaign: Option<&str>,
    ) {
        let bits = behavior_tags.iter().fold(0u16, |acc, t| acc | t.mask());
        self.file_hashes.push(WriterFileHash {
            sha256,
            source,
            confidence,
            behavior_tags: bits,
            campaign: campaign.map(str::to_string),
        });
    }

    /// Add a malicious-URL record. The normalized URL is stored and the index is
    /// keyed by its SHA-256. Populate ONLY from explicit indicator fields, never
    /// OpenSSF `references`. v2-only.
    pub fn add_malicious_url(&mut self, normalized_url: &str, source: ThreatSource) {
        self.malicious_urls.push(WriterMaliciousUrl {
            normalized_url: normalized_url.to_string(),
            source,
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_package(
        &mut self,
        eco: Ecosystem,
        name: &str,
        versions: &[&str],
        source: ThreatSource,
        confidence: Confidence,
        all_versions_malicious: bool,
        reference: Option<&str>,
    ) {
        let ref_offset = match reference {
            Some(r) => self.string_table.intern(r),
            None => 0xFFFF_FFFF,
        };
        self.packages.push(WriterPkg {
            ecosystem: eco,
            name: name.to_string(),
            versions: versions.iter().map(|v| v.to_string()).collect(),
            source,
            confidence,
            all_versions_malicious,
            reference_offset: ref_offset,
        });
    }

    pub fn add_hostname(&mut self, name: &str, source: ThreatSource) {
        self.hostnames.push(WriterHostname {
            name: name.to_ascii_lowercase(),
            source,
        });
    }

    pub fn add_ip(&mut self, addr: Ipv4Addr, source: ThreatSource) {
        self.ips.push(WriterIp {
            addr: u32::from(addr),
            source,
        });
    }

    pub fn add_typosquat(&mut self, eco: Ecosystem, malicious_name: &str, target_name: &str) {
        self.typosquats.push(WriterTyposquat {
            ecosystem: eco,
            malicious_name: malicious_name.to_string(),
            target_name: target_name.to_string(),
        });
    }

    pub fn add_popular(&mut self, eco: Ecosystem, name: &str) {
        self.popular.push(WriterPopular {
            ecosystem: eco,
            name: name.to_string(),
        });
    }

    /// Build and write a v1 database to a file. Signs with the provided keypair.
    pub fn write_to(
        mut self,
        path: &Path,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(), ThreatDbError> {
        let bytes = self.build(signing_key)?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    /// Build and write a database of the requested format to a file.
    pub fn write_to_format(
        mut self,
        format: ThreatDbFormat,
        path: &Path,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(), ThreatDbError> {
        let bytes = self.build_format(format, signing_key)?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    /// Build a v1 database into bytes (the legacy default). Byte-for-byte the
    /// pre-v2 layout: no footer, no v2 sections, version stamp 1.
    pub fn build(
        &mut self,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Vec<u8>, ThreatDbError> {
        self.build_format(ThreatDbFormat::V1, signing_key)
    }

    /// Build a database of the requested format into bytes. A v1 build emits the
    /// legacy layout unchanged; a v2 build appends the artifact / file-hash /
    /// URL / campaign / behavior sections, a checked descriptor trailer, and a
    /// fixed EOF footer, all AFTER `HEADER_SIZE` so the existing signed range
    /// (`[0..SIG_OFFSET)` ++ `[HEADER_SIZE..)`) covers them unchanged.
    pub fn build_format(
        &mut self,
        format: ThreatDbFormat,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Vec<u8>, ThreatDbError> {
        // Sort and deduplicate each section.
        self.packages
            .sort_by(|a, b| (a.ecosystem as u8, &a.name).cmp(&(b.ecosystem as u8, &b.name)));
        self.packages
            .dedup_by(|a, b| a.ecosystem == b.ecosystem && a.name == b.name);

        self.hostnames.sort_by(|a, b| a.name.cmp(&b.name));
        self.hostnames.dedup_by(|a, b| a.name == b.name);

        self.ips.sort_by_key(|ip| ip.addr);
        self.ips.dedup_by_key(|ip| ip.addr);

        self.typosquats.sort_by(|a, b| {
            (a.ecosystem as u8, &a.malicious_name).cmp(&(b.ecosystem as u8, &b.malicious_name))
        });
        self.typosquats
            .dedup_by(|a, b| a.ecosystem == b.ecosystem && a.malicious_name == b.malicious_name);

        self.popular
            .sort_by(|a, b| (a.ecosystem as u8, &a.name).cmp(&(b.ecosystem as u8, &b.name)));
        self.popular
            .dedup_by(|a, b| a.ecosystem == b.ecosystem && a.name == b.name);

        let mut pkg_data: Vec<u8> = Vec::new();
        let mut pkg_index: Vec<(u32, u32)> = Vec::new(); // (data_offset, key_hash)

        for pkg in &self.packages {
            let data_offset = (HEADER_SIZE + pkg_data.len()) as u32;
            let key_hash = pkg_key_hash(pkg.ecosystem, pkg.name.as_bytes());

            pkg_data.push(pkg.ecosystem as u8);
            let name_bytes = pkg.name.as_bytes();
            pkg_data.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            pkg_data.extend_from_slice(name_bytes);
            pkg_data.push(pkg.source as u8);
            pkg_data.push(pkg.confidence as u8);
            let flags: u8 = if pkg.all_versions_malicious { 1 } else { 0 };
            pkg_data.push(flags);
            pkg_data.extend_from_slice(&(pkg.versions.len() as u16).to_le_bytes());
            for v in &pkg.versions {
                let vbytes = v.as_bytes();
                pkg_data.extend_from_slice(&(vbytes.len() as u16).to_le_bytes());
                pkg_data.extend_from_slice(vbytes);
            }
            pkg_data.extend_from_slice(&pkg.reference_offset.to_le_bytes());

            pkg_index.push((data_offset, key_hash));
        }

        // Hostname data region
        let mut hostname_data: Vec<u8> = Vec::new();
        let mut hostname_index: Vec<(u32, u32)> = Vec::new();

        for hn in &self.hostnames {
            let key_hash = fnv1a_hash(hn.name.as_bytes());
            let local_off = hostname_data.len();

            hostname_data.push(hn.source as u8);
            let name_bytes = hn.name.as_bytes();
            hostname_data.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            hostname_data.extend_from_slice(name_bytes);

            hostname_index.push((local_off as u32, key_hash));
        }

        // Typosquat data region
        let mut typo_data: Vec<u8> = Vec::new();
        let mut typo_index: Vec<(u32, u32)> = Vec::new();

        for ts in &self.typosquats {
            let local_off = typo_data.len();
            let key_hash = pkg_key_hash(ts.ecosystem, ts.malicious_name.as_bytes());

            typo_data.push(ts.ecosystem as u8);
            let mal_bytes = ts.malicious_name.as_bytes();
            typo_data.extend_from_slice(&(mal_bytes.len() as u16).to_le_bytes());
            typo_data.extend_from_slice(mal_bytes);
            let tgt_bytes = ts.target_name.as_bytes();
            typo_data.extend_from_slice(&(tgt_bytes.len() as u16).to_le_bytes());
            typo_data.extend_from_slice(tgt_bytes);

            typo_index.push((local_off as u32, key_hash));
        }

        // Popular data region
        let mut popular_data: Vec<u8> = Vec::new();
        let mut popular_index: Vec<(u32, u32)> = Vec::new();

        for pop in &self.popular {
            let local_off = popular_data.len();
            let key_hash = pkg_key_hash(pop.ecosystem, pop.name.as_bytes());

            popular_data.push(pop.ecosystem as u8);
            let name_bytes = pop.name.as_bytes();
            popular_data.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            popular_data.extend_from_slice(name_bytes);

            popular_index.push((local_off as u32, key_hash));
        }

        // IP records
        let mut ip_data: Vec<u8> = Vec::with_capacity(self.ips.len() * IP_RECORD_SIZE);
        for ip in &self.ips {
            ip_data.extend_from_slice(&ip.addr.to_le_bytes());
            ip_data.push(ip.source as u8);
        }

        // File layout after header:
        //   pkg_index | pkg_data | hostname_index | hostname_data |
        //   ip_data | typo_index | typo_data | popular_index | popular_data | string_table

        let pkg_index_size = pkg_index.len() * PKG_INDEX_ENTRY_SIZE;
        let hostname_index_size = hostname_index.len() * HOSTNAME_INDEX_ENTRY_SIZE;
        let typo_index_size = typo_index.len() * TYPOSQUAT_INDEX_ENTRY_SIZE;
        let popular_index_size = popular_index.len() * POPULAR_INDEX_ENTRY_SIZE;

        let mut offset = HEADER_SIZE;

        let pkg_index_offset = offset as u32;
        offset += pkg_index_size;
        let pkg_data_offset = offset;
        offset += pkg_data.len();

        let hostname_index_offset = offset as u32;
        offset += hostname_index_size;
        let hostname_data_offset = offset;
        offset += hostname_data.len();

        let ip_data_offset = offset as u32;
        offset += ip_data.len();

        let typo_index_offset = offset as u32;
        offset += typo_index_size;
        let typo_data_offset = offset;
        offset += typo_data.len();

        let popular_index_offset = offset as u32;
        offset += popular_index_size;
        let popular_data_offset = offset;
        offset += popular_data.len();

        let string_table_offset = offset as u32;

        // Fix up data offsets to be absolute. pkg_index was built as
        // HEADER_SIZE + local; rebase onto the real pkg_data_offset.
        for (data_off, _) in &mut pkg_index {
            let local_off = *data_off as usize - HEADER_SIZE;
            *data_off = (pkg_data_offset + local_off) as u32;
        }

        for (data_off, _) in &mut hostname_index {
            *data_off = (hostname_data_offset + *data_off as usize) as u32;
        }

        for (data_off, _) in &mut typo_index {
            *data_off = (typo_data_offset + *data_off as usize) as u32;
        }

        for (data_off, _) in &mut popular_index {
            *data_off = (popular_data_offset + *data_off as usize) as u32;
        }

        // Sort index vectors by hash so binary search works (data was sorted by
        // (ecosystem, name), but lookups use FNV hash ordering).
        pkg_index.sort_by_key(|&(_, hash)| hash);
        hostname_index.sort_by_key(|&(_, hash)| hash);
        typo_index.sort_by_key(|&(_, hash)| hash);

        let total_size = HEADER_SIZE
            + pkg_index_size
            + pkg_data.len()
            + hostname_index_size
            + hostname_data.len()
            + ip_data.len()
            + typo_index_size
            + typo_data.len()
            + popular_index_size
            + popular_data.len()
            + self.string_table.len() as usize;

        let mut buf = vec![0u8; total_size];

        // Header (signature + fingerprint filled in after the data is written).
        // The version stamp is format-selected: a v1 build stamps 1 (so existing
        // signed DBs and an old binary are unaffected), a v2 build stamps 2.
        let stamped_version: u32 = match format {
            ThreatDbFormat::V1 => 1,
            ThreatDbFormat::V2 => 2,
        };
        buf[0..8].copy_from_slice(MAGIC);
        buf[8..12].copy_from_slice(&stamped_version.to_le_bytes());
        buf[12..20].copy_from_slice(&self.build_timestamp.to_le_bytes());
        buf[20..28].copy_from_slice(&self.build_sequence.to_le_bytes());
        buf[28..32].copy_from_slice(&pkg_index_offset.to_le_bytes());
        buf[32..36].copy_from_slice(&(self.packages.len() as u32).to_le_bytes());
        buf[36..40].copy_from_slice(&hostname_index_offset.to_le_bytes());
        buf[40..44].copy_from_slice(&(self.hostnames.len() as u32).to_le_bytes());
        buf[44..48].copy_from_slice(&ip_data_offset.to_le_bytes());
        buf[48..52].copy_from_slice(&(self.ips.len() as u32).to_le_bytes());
        buf[52..56].copy_from_slice(&typo_index_offset.to_le_bytes());
        buf[56..60].copy_from_slice(&(self.typosquats.len() as u32).to_le_bytes());
        buf[60..64].copy_from_slice(&popular_index_offset.to_le_bytes());
        buf[64..68].copy_from_slice(&(self.popular.len() as u32).to_le_bytes());
        buf[68..72].copy_from_slice(&string_table_offset.to_le_bytes());
        buf[72..76].copy_from_slice(&self.string_table.len().to_le_bytes());

        let fingerprint = Sha256::digest(signing_key.verifying_key().as_bytes());
        buf[FINGERPRINT_OFFSET..FINGERPRINT_OFFSET + FINGERPRINT_LEN].copy_from_slice(&fingerprint);

        // Write sections in layout order.
        let mut pos = HEADER_SIZE;

        for (data_off, hash) in &pkg_index {
            buf[pos..pos + 4].copy_from_slice(&data_off.to_le_bytes());
            buf[pos + 4..pos + 8].copy_from_slice(&hash.to_le_bytes());
            pos += PKG_INDEX_ENTRY_SIZE;
        }
        buf[pos..pos + pkg_data.len()].copy_from_slice(&pkg_data);
        pos += pkg_data.len();

        for (data_off, hash) in &hostname_index {
            buf[pos..pos + 4].copy_from_slice(&data_off.to_le_bytes());
            buf[pos + 4..pos + 8].copy_from_slice(&hash.to_le_bytes());
            pos += HOSTNAME_INDEX_ENTRY_SIZE;
        }
        buf[pos..pos + hostname_data.len()].copy_from_slice(&hostname_data);
        pos += hostname_data.len();

        buf[pos..pos + ip_data.len()].copy_from_slice(&ip_data);
        pos += ip_data.len();

        for (data_off, hash) in &typo_index {
            buf[pos..pos + 4].copy_from_slice(&data_off.to_le_bytes());
            buf[pos + 4..pos + 8].copy_from_slice(&hash.to_le_bytes());
            pos += TYPOSQUAT_INDEX_ENTRY_SIZE;
        }
        buf[pos..pos + typo_data.len()].copy_from_slice(&typo_data);
        pos += typo_data.len();

        for (data_off, hash) in &popular_index {
            buf[pos..pos + 4].copy_from_slice(&data_off.to_le_bytes());
            buf[pos + 4..pos + 8].copy_from_slice(&hash.to_le_bytes());
            pos += POPULAR_INDEX_ENTRY_SIZE;
        }
        buf[pos..pos + popular_data.len()].copy_from_slice(&popular_data);
        pos += popular_data.len();

        let st = self.string_table.bytes();
        buf[pos..pos + st.len()].copy_from_slice(st);

        // v2: append the new sections, a checked descriptor trailer, and a fixed
        // EOF footer. All of this lands at >= `HEADER_SIZE`, so the existing
        // signed range covers it with no change to `SIG_OFFSET`. A v1 build skips
        // this entirely and is byte-for-byte the legacy layout.
        if format == ThreatDbFormat::V2 {
            self.append_v2_sections(&mut buf);
        }

        // Sign: header before sig ++ all data after header. Unchanged from v1:
        // for a v2 file the appended trailing bytes are simply part of the
        // `[HEADER_SIZE..]` tail and are signed automatically.
        let mut signed_data = Vec::with_capacity(SIG_OFFSET + (buf.len() - HEADER_SIZE));
        signed_data.extend_from_slice(&buf[..SIG_OFFSET]);
        signed_data.extend_from_slice(&buf[HEADER_SIZE..]);

        use ed25519_dalek::Signer;
        let signature = signing_key.sign(&signed_data);
        buf[SIG_OFFSET..SIG_OFFSET + SIGNATURE_LENGTH].copy_from_slice(&signature.to_bytes());

        Ok(buf)
    }

    /// Append the v2 sections, descriptor trailer, and fixed EOF footer to a
    /// freshly-built v1 body. The layout (all after `HEADER_SIZE`):
    ///
    /// ```text
    /// [v1 body up to the v1 string table]
    /// artifact_sha index      (sorted by full SHA-256)
    /// file_hash index         (sorted by full SHA-256)
    /// url index               (sorted by full SHA-256 of the normalized URL)
    /// campaign string table   (length-prefixed; also holds URL strings)
    /// behavior-tag bitset      (a single u16 bitset for emitted file hashes)
    /// descriptor trailer      (one [`Descriptor`] per present section)
    /// fixed EOF footer        (magic + trailer_offset/length + version + flags)
    /// ```
    fn append_v2_sections(&mut self, buf: &mut Vec<u8>) {
        // Build a dedicated v2 campaign string table. Both campaign labels and
        // malicious-URL strings live here; the index records carry offsets into
        // it. Keep it separate from the v1 string table so v1 offsets are
        // untouched.
        let mut campaign_table = StringTable::new();

        // Sort + dedup the artifact/file/URL inputs by their hash so binary
        // search is sound; store and sort the FULL 32-byte SHA-256.
        self.artifact_shas.sort_by_key(|a| a.sha256);
        self.artifact_shas.dedup_by(|a, b| a.sha256 == b.sha256);
        self.file_hashes.sort_by_key(|f| f.sha256);
        self.file_hashes.dedup_by(|a, b| a.sha256 == b.sha256);

        // URL records: key on SHA-256 of the normalized URL, sort + dedup by it.
        let mut url_records: Vec<([u8; 32], &WriterMaliciousUrl)> = self
            .malicious_urls
            .iter()
            .map(|u| {
                let digest = Sha256::digest(u.normalized_url.as_bytes());
                let mut key = [0u8; 32];
                key.copy_from_slice(&digest);
                (key, u)
            })
            .collect();
        url_records.sort_by_key(|r| r.0);
        url_records.dedup_by(|a, b| a.0 == b.0);

        // Artifact-SHA section bytes.
        let mut artifact_bytes: Vec<u8> =
            Vec::with_capacity(self.artifact_shas.len() * ARTIFACT_SHA_RECORD_SIZE);
        for a in &self.artifact_shas {
            let campaign_offset = match &a.campaign {
                Some(c) => campaign_table.intern(c),
                None => 0xFFFF_FFFF,
            };
            artifact_bytes.extend_from_slice(&a.sha256);
            artifact_bytes.push(a.confidence as u8);
            artifact_bytes.push(a.source as u8);
            artifact_bytes.push(if a.all_versions_malicious { 1 } else { 0 });
            artifact_bytes.push(0); // reserved
            artifact_bytes.extend_from_slice(&campaign_offset.to_le_bytes());
        }

        // File-hash section bytes.
        let mut file_bytes: Vec<u8> =
            Vec::with_capacity(self.file_hashes.len() * FILE_HASH_RECORD_SIZE);
        for f in &self.file_hashes {
            let campaign_offset = match &f.campaign {
                Some(c) => campaign_table.intern(c),
                None => 0xFFFF_FFFF,
            };
            file_bytes.extend_from_slice(&f.sha256);
            file_bytes.push(f.confidence as u8);
            file_bytes.push(f.source as u8);
            file_bytes.extend_from_slice(&f.behavior_tags.to_le_bytes());
            file_bytes.extend_from_slice(&campaign_offset.to_le_bytes());
        }

        // URL section bytes (the URL string itself is interned in the campaign
        // table; the record stores only its offset + source).
        let mut url_bytes: Vec<u8> = Vec::with_capacity(url_records.len() * URL_INDEX_RECORD_SIZE);
        for (key, u) in &url_records {
            let url_offset = campaign_table.intern(&u.normalized_url);
            url_bytes.extend_from_slice(key);
            url_bytes.extend_from_slice(&url_offset.to_le_bytes());
            url_bytes.push(u.source as u8);
            url_bytes.push(0); // reserved
        }

        // The campaign table is now final (all interns done above).
        let campaign_bytes = campaign_table.bytes().to_vec();

        // Behavior-tag bitset section: an OR of every emitted file-hash record's
        // tags. The per-record tags are authoritative for lookup; this aggregate
        // section exists so the format carries an explicit, descriptor-anchored
        // bitset (and so future readers can summarize without scanning records).
        let aggregate_tags = self
            .file_hashes
            .iter()
            .fold(0u16, |acc, f| acc | f.behavior_tags);
        let behavior_bytes = aggregate_tags.to_le_bytes().to_vec();

        // Lay the sections out contiguously after the current `buf` end, all of
        // which is already past `HEADER_SIZE`.
        let mut descriptors: Vec<(SectionType, u64, u64, u64)> = Vec::new(); // (type, offset, length, count)
        let place = |buf: &mut Vec<u8>,
                     descriptors: &mut Vec<(SectionType, u64, u64, u64)>,
                     ty: SectionType,
                     bytes: &[u8],
                     count: u64| {
            let offset = buf.len() as u64;
            buf.extend_from_slice(bytes);
            descriptors.push((ty, offset, bytes.len() as u64, count));
        };

        place(
            buf,
            &mut descriptors,
            SectionType::ArtifactSha,
            &artifact_bytes,
            self.artifact_shas.len() as u64,
        );
        place(
            buf,
            &mut descriptors,
            SectionType::FileHash,
            &file_bytes,
            self.file_hashes.len() as u64,
        );
        place(
            buf,
            &mut descriptors,
            SectionType::MaliciousUrl,
            &url_bytes,
            url_records.len() as u64,
        );
        place(
            buf,
            &mut descriptors,
            SectionType::CampaignStrings,
            &campaign_bytes,
            // count is informational for a byte-blob section; report bytes.
            campaign_bytes.len() as u64,
        );
        place(
            buf,
            &mut descriptors,
            SectionType::BehaviorTags,
            &behavior_bytes,
            behavior_bytes.len() as u64,
        );

        // Descriptor trailer, in section-type order.
        let trailer_offset = buf.len() as u64;
        for (ty, offset, length, count) in &descriptors {
            buf.extend_from_slice(&(*ty as u16).to_le_bytes());
            buf.extend_from_slice(&1u16.to_le_bytes()); // record_version
            buf.extend_from_slice(&offset.to_le_bytes());
            buf.extend_from_slice(&length.to_le_bytes());
            buf.extend_from_slice(&count.to_le_bytes());
        }
        let trailer_length = buf.len() as u64 - trailer_offset;

        // Fixed EOF footer.
        buf.extend_from_slice(FOOTER_MAGIC);
        buf.extend_from_slice(&trailer_offset.to_le_bytes());
        buf.extend_from_slice(&trailer_length.to_le_bytes());
        buf.extend_from_slice(&TRAILER_VERSION.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // flags (reserved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Helper: create a writer, add test data, build, and return a ThreatDb.
    fn build_test_db(signing_key: &SigningKey) -> ThreatDb {
        let mut writer = ThreatDbWriter::new(1700000000, 42);

        // Packages
        writer.add_package(
            Ecosystem::Npm,
            "evil-package",
            &["1.0.0", "1.0.1"],
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            false,
            Some("https://example.com/advisory/1"),
        );
        writer.add_package(
            Ecosystem::PyPI,
            "malware-pkg",
            &[],
            ThreatSource::DatadogMalicious,
            Confidence::Confirmed,
            true,
            None,
        );
        writer.add_package(
            Ecosystem::Npm,
            "borderline-pkg",
            &["2.0.0"],
            ThreatSource::OssfMalicious,
            Confidence::Medium,
            false,
            Some("https://example.com/advisory/2"),
        );

        // IPs
        writer.add_ip(Ipv4Addr::new(192, 168, 1, 100), ThreatSource::FeodoTracker);
        writer.add_ip(Ipv4Addr::new(10, 0, 0, 1), ThreatSource::FeodoTracker);
        writer.add_ip(Ipv4Addr::new(203, 0, 113, 50), ThreatSource::FeodoTracker);

        // Typosquats
        writer.add_typosquat(Ecosystem::Npm, "reacct", "react");
        writer.add_typosquat(Ecosystem::PyPI, "reqeusts", "requests");

        // Popular packages
        writer.add_popular(Ecosystem::Npm, "react");
        writer.add_popular(Ecosystem::Npm, "express");
        writer.add_popular(Ecosystem::PyPI, "requests");
        writer.add_popular(Ecosystem::PyPI, "flask");

        let bytes = writer.build(signing_key).expect("build failed");
        ThreatDb::from_bytes(bytes, 0).expect("load failed")
    }

    fn signed_fixture_db_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests")
            .join("fixtures")
            .join("test-threatdb.dat")
    }

    /// A FROZEN v1 DB blob, captured once from `ThreatDbWriter::build` with a
    /// fixed key `[7u8; 32]`, timestamp 1_700_000_000, sequence 7, one npm
    /// package `frozen-evil@1.0.0` (Confirmed, OSSF, ref) and one Feodo IP. It is
    /// hard-coded (not regenerated) so the v1-load path is pinned: any future
    /// writer change that would alter the v1 byte layout fails
    /// `frozen_v1_blob_still_loads`, and the range-accepting v2 reader must keep
    /// loading this exact blob with every v2 lookup returning None.
    #[rustfmt::skip]
    const FROZEN_V1_DB: &[u8] = &[
        0x54, 0x49, 0x52, 0x49, 0x54, 0x48, 0x44, 0x42, 0x01, 0x00, 0x00, 0x00, 0x00, 0xf1, 0x53, 0x65,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xac, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0xd2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd2, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0xd7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd7, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xd7, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0xfe, 0x81, 0x2c, 0x12,
        0xf3, 0xab, 0x4c, 0xe6, 0xac, 0x5d, 0xb6, 0x9a, 0xc3, 0x52, 0xf9, 0x06, 0xcb, 0x1b, 0x11, 0xef,
        0x43, 0xfb, 0x33, 0xe2, 0x52, 0xef, 0x7f, 0xf5, 0x52, 0x26, 0x38, 0x89, 0x1d, 0xb2, 0x0a, 0x25,
        0xd4, 0x1b, 0x74, 0xcc, 0x95, 0xe5, 0x50, 0x6e, 0x37, 0x52, 0x8b, 0x3b, 0xa8, 0x43, 0xaa, 0xb8,
        0x97, 0xd6, 0xf5, 0x2f, 0x44, 0xa6, 0xaa, 0xf1, 0x3e, 0x1f, 0xae, 0x90, 0x01, 0x06, 0xdb, 0x73,
        0xd4, 0x2c, 0x21, 0x70, 0xf3, 0x17, 0x25, 0x94, 0x4e, 0x3e, 0x7e, 0xd4, 0xc6, 0xf5, 0xaa, 0x5d,
        0x9b, 0xb1, 0xa7, 0x52, 0xe0, 0x28, 0xa1, 0x95, 0xc9, 0x64, 0x0c, 0x07, 0xb4, 0x00, 0x00, 0x00,
        0xfa, 0x0d, 0x42, 0xcb, 0x00, 0x0b, 0x00, 0x66, 0x72, 0x6f, 0x7a, 0x65, 0x6e, 0x2d, 0x65, 0x76,
        0x69, 0x6c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x05, 0x00, 0x31, 0x2e, 0x30, 0x2e, 0x30, 0x00, 0x00,
        0x00, 0x00, 0x07, 0x71, 0x00, 0xcb, 0x02, 0x1a, 0x00, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f,
        0x2f, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x66, 0x72, 0x6f,
        0x7a, 0x65, 0x6e,
    ];

    /// A v1 blob frozen at the byte level loads on the range-accepting reader,
    /// keeps its v1 lookups, and returns None for every v2 lookup. This is the
    /// regression guard that the v1-load path never breaks, even after future
    /// writer changes.
    #[test]
    fn frozen_v1_blob_still_loads() {
        let db = ThreatDb::from_bytes(FROZEN_V1_DB.to_vec(), 0).expect("frozen v1 blob must load");
        assert_eq!(db.stats().format_version, 1);
        assert_eq!(db.stats().build_sequence, 7);
        // v1 lookups still resolve.
        let m = db
            .check_package(Ecosystem::Npm, "frozen-evil", Some("1.0.0"))
            .expect("frozen package must match");
        assert_eq!(m.source, ThreatSource::OssfMalicious);
        assert_eq!(
            m.reference_url.as_deref(),
            Some("https://example.com/frozen")
        );
        assert!(db.check_ip(Ipv4Addr::new(203, 0, 113, 7)).is_some());
        // Every v2 lookup returns None on a v1 file.
        assert!(db.check_artifact_sha256(&[0u8; 32]).is_none());
        assert!(db.check_file_sha256(&[0u8; 32]).is_none());
        assert!(db.check_malicious_url("http://evil.example/x").is_none());
    }

    /// The committed shared v1 fixture (`tests/fixtures/test-threatdb.dat`) also
    /// loads on the new reader and exposes no v2 sections, so the production v1
    /// asset is never rejected by a v2-capable binary.
    #[test]
    fn committed_v1_fixture_loads_with_no_v2_sections() {
        let path = signed_fixture_db_path();
        let db = ThreatDb::load_from_path(&path, 0).expect("committed v1 fixture must load");
        assert_eq!(db.stats().format_version, 1);
        assert!(db.check_artifact_sha256(&[0u8; 32]).is_none());
        assert!(db.check_file_sha256(&[0u8; 32]).is_none());
    }

    /// Helper: a 32-byte SHA-256-shaped array seeded from a single byte.
    fn sha(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn test_round_trip_all_sections() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        let stats = db.stats();
        assert_eq!(stats.format_version, 1);
        assert_eq!(stats.build_timestamp, 1700000000);
        assert_eq!(stats.build_sequence, 42);
        assert_eq!(stats.package_count, 3);
        assert_eq!(stats.ip_count, 3);
        assert_eq!(stats.typosquat_count, 2);
        assert_eq!(stats.popular_count, 4);
        assert_eq!(stats.hostname_count, 0);
    }

    #[test]
    fn test_package_version_in_list() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        let m = db
            .check_package(Ecosystem::Npm, "evil-package", Some("1.0.0"))
            .expect("should match");
        assert_eq!(m.source, ThreatSource::OssfMalicious);
        assert_eq!(m.confidence, Confidence::Confirmed);
        assert!(!m.all_versions_malicious);
        assert!(m.reference_url.is_some());
    }

    #[test]
    fn test_package_version_not_in_list() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        assert!(db
            .check_package(Ecosystem::Npm, "evil-package", Some("2.0.0"))
            .is_none());
    }

    #[test]
    fn test_package_no_version_all_malicious() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        let m = db
            .check_package(Ecosystem::PyPI, "malware-pkg", None)
            .expect("should match all-versions-malicious without version");
        assert!(m.all_versions_malicious);
        assert_eq!(m.source, ThreatSource::DatadogMalicious);
    }

    #[test]
    fn test_package_no_version_not_all_malicious() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        assert!(
            db.check_package(Ecosystem::Npm, "evil-package", None)
                .is_none(),
            "should NOT match when no version provided and all_versions_malicious=false"
        );
    }

    #[test]
    fn test_package_all_malicious_with_version() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        let m = db
            .check_package(Ecosystem::PyPI, "malware-pkg", Some("99.99.99"))
            .expect("all_versions_malicious should match any version");
        assert!(m.all_versions_malicious);
    }

    #[test]
    fn test_package_missing() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        assert!(db
            .check_package(Ecosystem::Npm, "safe-package", Some("1.0.0"))
            .is_none());
    }

    #[test]
    fn test_package_wrong_ecosystem() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        assert!(db
            .check_package(Ecosystem::PyPI, "evil-package", Some("1.0.0"))
            .is_none());
    }

    #[test]
    fn test_package_medium_confidence() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        let m = db
            .check_package(Ecosystem::Npm, "borderline-pkg", Some("2.0.0"))
            .expect("should match");
        assert_eq!(m.confidence, Confidence::Medium);
    }

    #[test]
    fn test_ip_found() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        let m = db
            .check_ip(Ipv4Addr::new(192, 168, 1, 100))
            .expect("should find IP");
        assert_eq!(m.source, ThreatSource::FeodoTracker);
    }

    #[test]
    fn test_ip_not_found() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        assert!(db.check_ip(Ipv4Addr::new(8, 8, 8, 8)).is_none());
    }

    #[test]
    fn test_ip_first_element() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        assert!(db.check_ip(Ipv4Addr::new(10, 0, 0, 1)).is_some());
    }

    #[test]
    fn test_ip_last_element() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        assert!(db.check_ip(Ipv4Addr::new(203, 0, 113, 50)).is_some());
    }

    #[test]
    fn test_typosquat_found() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        let m = db
            .check_typosquat(Ecosystem::Npm, "reacct")
            .expect("should find typosquat");
        assert_eq!(m.target_name, "react");
    }

    #[test]
    fn test_typosquat_not_found() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        assert!(db.check_typosquat(Ecosystem::Npm, "react").is_none());
    }

    #[test]
    fn test_typosquat_wrong_ecosystem() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        assert!(db.check_typosquat(Ecosystem::PyPI, "reacct").is_none());
    }

    #[test]
    fn test_popular_distance_1() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        let result = db.check_popular_distance(Ecosystem::PyPI, "reqests");
        assert!(result.is_some(), "should find close match");
        let (name, dist) = result.unwrap();
        assert_eq!(name, "requests");
        assert_eq!(dist, 1);
    }

    #[test]
    fn test_popular_exact_match_skipped() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        assert!(db.check_popular_distance(Ecosystem::Npm, "react").is_none());
    }

    #[test]
    fn test_popular_distance_too_far() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        assert!(db.check_popular_distance(Ecosystem::Npm, "xyz").is_none());
    }

    #[test]
    fn test_is_popular_package_exact_match() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        // Exact, in the right ecosystem → true.
        assert!(db.is_popular_package(Ecosystem::Npm, "react"));
        assert!(db.is_popular_package(Ecosystem::PyPI, "requests"));
        // Right name, wrong ecosystem → false.
        assert!(!db.is_popular_package(Ecosystem::PyPI, "react"));
        // A near-miss is not an exact match → false.
        assert!(!db.is_popular_package(Ecosystem::Npm, "reactt"));
        // Unknown name → false.
        assert!(!db.is_popular_package(Ecosystem::Npm, "totally-unknown-pkg"));
    }

    #[test]
    fn test_is_popular_package_finds_supplemental_overlay() {
        let key = SigningKey::generate(&mut OsRng);
        let primary =
            ThreatDb::from_bytes(ThreatDbWriter::new(1700000000, 1).build(&key).unwrap(), 0)
                .unwrap();
        let mut overlay_writer = ThreatDbWriter::new(1700000001, 1);
        overlay_writer.add_popular(Ecosystem::Crates, "serde");
        let overlay =
            ThreatDb::from_bytes(overlay_writer.build(&key).unwrap(), 0).expect("overlay load");
        let db = primary.with_supplemental(Some(overlay));

        assert!(db.is_popular_package(Ecosystem::Crates, "serde"));
        assert!(!db.is_popular_package(Ecosystem::Crates, "not-there"));
    }

    #[test]
    fn test_hostname_empty_section() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);

        assert!(db.check_hostname("evil.example.com").is_none());
    }

    #[test]
    fn test_signature_valid() {
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1700000000, 1);
        writer.add_ip(Ipv4Addr::new(1, 2, 3, 4), ThreatSource::FeodoTracker);

        let bytes = writer.build(&key).expect("build");
        let db = ThreatDb::from_bytes(bytes, 0).expect("load");

        // Negative path: the embedded placeholder key won't match the signer.
        assert!(
            db.verify_signature().is_err(),
            "placeholder key should not verify real signature"
        );
    }

    #[test]
    fn test_signature_corrupt_byte() {
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1700000000, 1);
        writer.add_ip(Ipv4Addr::new(1, 2, 3, 4), ThreatSource::FeodoTracker);

        let mut bytes = writer.build(&key).expect("build");

        if bytes.len() > HEADER_SIZE + 1 {
            bytes[HEADER_SIZE + 1] ^= 0xFF;
        }

        let db = ThreatDb::from_bytes(bytes, 0).expect("load");
        assert!(
            db.verify_signature().is_err(),
            "corrupt data should fail verification"
        );
    }

    #[test]
    fn test_signature_with_matching_key() {
        // Verification works when checked against the key that actually signed
        // (simulating the real key replacing the placeholder).
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1700000000, 1);
        writer.add_ip(Ipv4Addr::new(1, 2, 3, 4), ThreatSource::FeodoTracker);

        let bytes = writer.build(&key).expect("build");

        let sig_bytes = &bytes[SIG_OFFSET..SIG_OFFSET + SIGNATURE_LENGTH];
        let signature = Signature::from_slice(sig_bytes).expect("parse sig");

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&bytes[..SIG_OFFSET]);
        signed_data.extend_from_slice(&bytes[HEADER_SIZE..]);

        use ed25519_dalek::Verifier;
        assert!(
            key.verifying_key().verify(&signed_data, &signature).is_ok(),
            "signature should verify against signing key"
        );
    }

    #[test]
    fn test_rollback_rejected() {
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1700000000, 5);
        writer.add_ip(Ipv4Addr::new(1, 2, 3, 4), ThreatSource::FeodoTracker);
        let bytes = writer.build(&key).expect("build");

        let err = ThreatDb::from_bytes(bytes, 10).expect_err("should reject rollback");
        match err {
            ThreatDbError::RollbackDetected {
                got: 5,
                current: 10,
            } => {}
            other => panic!("expected RollbackDetected, got: {other}"),
        }
    }

    #[test]
    fn test_rollback_equal_rejected() {
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1700000000, 10);
        writer.add_ip(Ipv4Addr::new(1, 2, 3, 4), ThreatSource::FeodoTracker);
        let bytes = writer.build(&key).expect("build");

        let err = ThreatDb::from_bytes(bytes, 10).expect_err("equal sequence should be rejected");
        assert!(matches!(err, ThreatDbError::RollbackDetected { .. }));
    }

    #[test]
    fn test_rollback_newer_accepted() {
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1700000000, 20);
        writer.add_ip(Ipv4Addr::new(1, 2, 3, 4), ThreatSource::FeodoTracker);
        let bytes = writer.build(&key).expect("build");

        assert!(ThreatDb::from_bytes(bytes, 10).is_ok());
    }

    #[test]
    fn test_invalid_magic() {
        let mut data = vec![0u8; HEADER_SIZE + 10];
        data[0..8].copy_from_slice(b"BADMAGIC");
        assert!(matches!(
            ThreatDb::from_bytes(data, 0),
            Err(ThreatDbError::InvalidMagic)
        ));
    }

    #[test]
    fn test_file_too_small() {
        let data = vec![0u8; 10];
        assert!(matches!(
            ThreatDb::from_bytes(data, 0),
            Err(ThreatDbError::FileTooSmall(_))
        ));
    }

    #[test]
    fn test_unsupported_version() {
        let mut data = vec![0u8; HEADER_SIZE + 10];
        data[0..8].copy_from_slice(MAGIC);
        data[8..12].copy_from_slice(&99u32.to_le_bytes());
        assert!(matches!(
            ThreatDb::from_bytes(data, 0),
            Err(ThreatDbError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn test_single_entry_db() {
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1700000000, 1);
        writer.add_package(
            Ecosystem::Crates,
            "only-pkg",
            &["0.1.0"],
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            false,
            None,
        );
        let bytes = writer.build(&key).expect("build");
        let db = ThreatDb::from_bytes(bytes, 0).expect("load");

        assert!(db
            .check_package(Ecosystem::Crates, "only-pkg", Some("0.1.0"))
            .is_some());
        assert!(db
            .check_package(Ecosystem::Crates, "other", Some("0.1.0"))
            .is_none());
    }

    #[test]
    fn test_empty_db() {
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1700000000, 1);
        let bytes = writer.build(&key).expect("build");
        let db = ThreatDb::from_bytes(bytes, 0).expect("load");

        assert!(db.check_package(Ecosystem::Npm, "anything", None).is_none());
        assert!(db.check_ip(Ipv4Addr::new(1, 2, 3, 4)).is_none());
        assert!(db.check_typosquat(Ecosystem::Npm, "anything").is_none());
        assert!(db.check_hostname("anything.com").is_none());
        assert!(db
            .check_popular_distance(Ecosystem::Npm, "anything")
            .is_none());

        let stats = db.stats();
        assert_eq!(stats.package_count, 0);
        assert_eq!(stats.ip_count, 0);
    }

    #[test]
    fn test_cache_returns_none_when_no_file() {
        // Fail-open smoke test: cached() must not panic regardless of whether a
        // DB file happens to exist in the test environment.
        let result = ThreatDb::cached();
        let _ = result;
    }

    #[test]
    fn test_writer_deduplicates() {
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1700000000, 1);

        // Same package twice.
        writer.add_package(
            Ecosystem::Npm,
            "dupe-pkg",
            &["1.0.0"],
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            false,
            None,
        );
        writer.add_package(
            Ecosystem::Npm,
            "dupe-pkg",
            &["2.0.0"],
            ThreatSource::DatadogMalicious,
            Confidence::Confirmed,
            false,
            None,
        );

        // Same IP twice.
        writer.add_ip(Ipv4Addr::new(1, 2, 3, 4), ThreatSource::FeodoTracker);
        writer.add_ip(Ipv4Addr::new(1, 2, 3, 4), ThreatSource::FeodoTracker);

        let bytes = writer.build(&key).expect("build");
        let db = ThreatDb::from_bytes(bytes, 0).expect("load");

        assert_eq!(
            db.stats().package_count,
            1,
            "duplicate packages should be deduped"
        );
        assert_eq!(db.stats().ip_count, 1, "duplicate IPs should be deduped");
    }

    #[test]
    fn test_supplemental_overlay_lookup_and_stats() {
        let key = SigningKey::generate(&mut OsRng);

        let mut primary_writer = ThreatDbWriter::new(1700000000, 1);
        primary_writer.add_package(
            Ecosystem::Npm,
            "primary-pkg",
            &["1.0.0"],
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            false,
            None,
        );
        let primary = ThreatDb::from_bytes(primary_writer.build(&key).expect("primary build"), 0)
            .expect("primary load");

        let mut supplemental_writer = ThreatDbWriter::new(1700000001, 1);
        supplemental_writer.add_package(
            Ecosystem::PyPI,
            "overlay-pkg",
            &["2.0.0"],
            ThreatSource::DatadogMalicious,
            Confidence::Confirmed,
            false,
            None,
        );
        supplemental_writer.add_hostname("overlay.example", ThreatSource::Urlhaus);
        supplemental_writer.add_ip(Ipv4Addr::new(203, 0, 113, 77), ThreatSource::ThreatFoxIoc);
        supplemental_writer.add_typosquat(Ecosystem::Npm, "reacct", "react");
        supplemental_writer.add_popular(Ecosystem::Npm, "react");

        let supplemental = ThreatDb::from_bytes(
            supplemental_writer.build(&key).expect("supplemental build"),
            0,
        )
        .expect("supplemental load");

        let db = primary.with_supplemental(Some(supplemental));

        assert!(db
            .check_package(Ecosystem::Npm, "primary-pkg", Some("1.0.0"))
            .is_some());
        assert!(db
            .check_package(Ecosystem::PyPI, "overlay-pkg", Some("2.0.0"))
            .is_some());
        assert!(db.check_hostname("overlay.example").is_some());
        assert!(db.check_ip(Ipv4Addr::new(203, 0, 113, 77)).is_some());
        assert!(db.check_typosquat(Ecosystem::Npm, "reacct").is_some());
        assert_eq!(
            db.check_popular_distance(Ecosystem::Npm, "reac"),
            Some(("react".to_string(), 1))
        );

        let stats = db.stats();
        assert_eq!(stats.package_count, 2);
        assert_eq!(stats.hostname_count, 1);
        assert_eq!(stats.ip_count, 1);
        assert_eq!(stats.typosquat_count, 1);
        assert_eq!(stats.popular_count, 1);
    }

    #[test]
    fn test_supplemental_overlay_falls_through_on_primary_version_mismatch() {
        let key = SigningKey::generate(&mut OsRng);

        let mut primary_writer = ThreatDbWriter::new(1700000000, 1);
        primary_writer.add_package(
            Ecosystem::Npm,
            "shared-pkg",
            &["1.0.0"],
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            false,
            None,
        );
        let primary = ThreatDb::from_bytes(primary_writer.build(&key).expect("primary build"), 0)
            .expect("primary load");

        let mut supplemental_writer = ThreatDbWriter::new(1700000001, 1);
        supplemental_writer.add_package(
            Ecosystem::Npm,
            "shared-pkg",
            &["2.0.0"],
            ThreatSource::DatadogMalicious,
            Confidence::Confirmed,
            false,
            None,
        );
        let supplemental = ThreatDb::from_bytes(
            supplemental_writer.build(&key).expect("supplemental build"),
            0,
        )
        .expect("supplemental load");

        let db = primary.with_supplemental(Some(supplemental));
        let threat = db
            .check_package(Ecosystem::Npm, "shared-pkg", Some("2.0.0"))
            .expect("supplemental version should match");
        assert_eq!(threat.source, ThreatSource::DatadogMalicious);
    }

    #[test]
    fn test_combined_mtime_requires_primary_db() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("primary.dat");
        let supplemental = tmp.path().join("supplemental.dat");

        unsafe {
            std::env::set_var("TIRITH_THREATDB_PATH", &primary);
            std::env::set_var("TIRITH_THREATDB_SUPPLEMENTAL_PATH", &supplemental);
        }

        assert_eq!(combined_mtime_epoch(), None);

        std::fs::write(&supplemental, b"overlay").unwrap();
        assert_eq!(combined_mtime_epoch(), None);

        std::fs::remove_file(&supplemental).unwrap();
        std::fs::write(&primary, b"primary").unwrap();
        let primary_only = combined_mtime_epoch().expect("primary mtime");

        std::fs::write(&supplemental, b"overlay-updated").unwrap();
        let combined = combined_mtime_epoch().expect("combined mtime");
        assert_ne!(primary_only, combined);

        unsafe {
            std::env::remove_var("TIRITH_THREATDB_PATH");
            std::env::remove_var("TIRITH_THREATDB_SUPPLEMENTAL_PATH");
        }
    }

    #[test]
    fn test_refresh_cache_reloads_when_only_supplemental_changes() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = signed_fixture_db_path();
        let tmp = tempfile::tempdir().unwrap();
        let supplemental = tmp.path().join("supplemental.dat");
        let signing_key = SigningKey::generate(&mut OsRng);

        unsafe {
            std::env::set_var("TIRITH_THREATDB_PATH", &fixture);
            std::env::remove_var("TIRITH_THREATDB_SUPPLEMENTAL_PATH");
        }
        ThreatDb::refresh_cache();

        let before = ThreatDb::cached().expect("fixture DB should load");
        assert!(
            before
                .check_package(Ecosystem::PyPI, "overlay-pkg", Some("2.0.0"))
                .is_none(),
            "fixture DB should not include the test-only supplemental package"
        );

        let mut writer = ThreatDbWriter::new(1700000001, 1);
        writer.add_package(
            Ecosystem::PyPI,
            "overlay-pkg",
            &["2.0.0"],
            ThreatSource::DatadogMalicious,
            Confidence::Confirmed,
            false,
            None,
        );
        writer
            .write_to(&supplemental, &signing_key)
            .expect("write supplemental DB");

        unsafe {
            std::env::set_var("TIRITH_THREATDB_SUPPLEMENTAL_PATH", &supplemental);
        }
        ThreatDb::refresh_cache();

        let after = ThreatDb::cached().expect("fixture DB with supplemental should load");
        assert!(
            after
                .check_package(Ecosystem::PyPI, "overlay-pkg", Some("2.0.0"))
                .is_some(),
            "refresh_cache should pick up supplemental changes even when the primary sequence is unchanged"
        );

        unsafe {
            std::env::remove_var("TIRITH_THREATDB_PATH");
            std::env::remove_var("TIRITH_THREATDB_SUPPLEMENTAL_PATH");
        }
        ThreatDb::refresh_cache();
    }

    #[test]
    fn test_refresh_cache_clears_when_current_source_disappears() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fixture = signed_fixture_db_path();
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("missing-primary.dat");

        unsafe {
            std::env::set_var("TIRITH_THREATDB_PATH", &fixture);
            std::env::remove_var("TIRITH_THREATDB_SUPPLEMENTAL_PATH");
        }
        ThreatDb::refresh_cache();
        assert!(ThreatDb::cached().is_some(), "fixture DB should load");

        unsafe {
            std::env::set_var("TIRITH_THREATDB_PATH", &missing);
        }
        ThreatDb::refresh_cache();
        assert!(
            ThreatDb::cached().is_none(),
            "refresh_cache should clear the cached DB when the configured primary file disappears"
        );

        unsafe {
            std::env::remove_var("TIRITH_THREATDB_PATH");
            std::env::remove_var("TIRITH_THREATDB_SUPPLEMENTAL_PATH");
        }
        ThreatDb::refresh_cache();
    }

    #[test]
    fn test_string_table_deduplication() {
        let mut st = StringTable::new();
        let off1 = st.intern("https://example.com");
        let off2 = st.intern("https://example.com");
        let off3 = st.intern("https://other.com");

        assert_eq!(off1, off2, "same string should return same offset");
        assert_ne!(
            off1, off3,
            "different strings should have different offsets"
        );
    }

    #[test]
    fn test_reference_url_round_trip() {
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1700000000, 1);
        writer.add_package(
            Ecosystem::Npm,
            "ref-pkg",
            &["1.0.0"],
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            false,
            Some("https://example.com/advisory/123"),
        );
        let bytes = writer.build(&key).expect("build");
        let db = ThreatDb::from_bytes(bytes, 0).expect("load");

        let m = db
            .check_package(Ecosystem::Npm, "ref-pkg", Some("1.0.0"))
            .expect("should match");
        assert_eq!(
            m.reference_url.as_deref(),
            Some("https://example.com/advisory/123")
        );
    }

    #[test]
    fn threat_source_all_covers_every_variant() {
        // Guards `threat-db sources` against silently dropping a source: every
        // variant must round-trip through ALL, with no duplicates.
        for src in ThreatSource::ALL {
            assert_eq!(
                ThreatSource::from_u8(src as u8),
                Some(src),
                "ALL entry {src:?} must round-trip through from_u8"
            );
        }
        let mut seen = std::collections::HashSet::new();
        for src in ThreatSource::ALL {
            assert!(seen.insert(src as u8), "ALL has a duplicate: {src:?}");
        }
        assert_eq!(ThreatSource::ALL.len(), 12);
        assert!(
            ThreatSource::from_u8(12).is_none(),
            "from_u8 must reject an out-of-range discriminant"
        );
    }

    #[test]
    fn threat_source_as_str_is_unique_and_stable() {
        let mut seen = std::collections::HashSet::new();
        for src in ThreatSource::ALL {
            let s = src.as_str();
            assert!(!s.is_empty());
            assert!(seen.insert(s), "as_str collision on {s:?}");
        }
        // Spot-check a couple of stable identifiers.
        assert_eq!(ThreatSource::OssfMalicious.as_str(), "ossf_malicious");
        assert_eq!(ThreatSource::TorExit.as_str(), "tor_exit");
    }

    #[test]
    fn threat_source_tier_split_matches_feed_origin() {
        // The feeds compiled into the signed CI DB are Primary (incl. the
        // curated exfil-endpoint hostname feed).
        for src in [
            ThreatSource::OssfMalicious,
            ThreatSource::DatadogMalicious,
            ThreatSource::FeodoTracker,
            ThreatSource::EcosystemsTyposquat,
            ThreatSource::CisaKev,
            ThreatSource::ExfilEndpoint,
        ] {
            assert_eq!(src.tier(), SourceTier::Primary, "{src:?} should be primary");
        }
        // The rest are opt-in supplemental.
        for src in [
            ThreatSource::Urlhaus,
            ThreatSource::PhishingArmy,
            ThreatSource::PhishTank,
            ThreatSource::ThreatFoxIoc,
            ThreatSource::FireholIp,
            ThreatSource::TorExit,
        ] {
            assert_eq!(
                src.tier(),
                SourceTier::Supplemental,
                "{src:?} should be supplemental"
            );
        }
    }

    #[test]
    fn source_breakdown_counts_records_per_source() {
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1700000000, 1);
        writer.add_package(
            Ecosystem::Npm,
            "evil-a",
            &["1.0.0"],
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            true,
            None,
        );
        writer.add_package(
            Ecosystem::PyPI,
            "evil-b",
            &[],
            ThreatSource::DatadogMalicious,
            Confidence::Confirmed,
            true,
            None,
        );
        writer.add_package(
            Ecosystem::Npm,
            "evil-c",
            &["2.0.0"],
            ThreatSource::OssfMalicious,
            Confidence::Medium,
            false,
            None,
        );
        writer.add_hostname("bad.example", ThreatSource::Urlhaus);
        writer.add_hostname("phish.example", ThreatSource::PhishTank);
        writer.add_ip(Ipv4Addr::new(203, 0, 113, 1), ThreatSource::FeodoTracker);
        writer.add_ip(Ipv4Addr::new(203, 0, 113, 2), ThreatSource::TorExit);
        writer.add_typosquat(Ecosystem::Npm, "reacct", "react");
        writer.add_popular(Ecosystem::Npm, "react");

        let db = ThreatDb::from_bytes(writer.build(&key).expect("build"), 0).expect("load");
        let bd = db.source_breakdown();

        assert_eq!(bd.count_for(ThreatSource::OssfMalicious), 2);
        assert_eq!(bd.count_for(ThreatSource::DatadogMalicious), 1);
        assert_eq!(bd.count_for(ThreatSource::Urlhaus), 1);
        assert_eq!(bd.count_for(ThreatSource::PhishTank), 1);
        assert_eq!(bd.count_for(ThreatSource::FeodoTracker), 1);
        assert_eq!(bd.count_for(ThreatSource::TorExit), 1);
        assert_eq!(bd.count_for(ThreatSource::CisaKev), 0);
        // Typosquats are attributed to EcosystemsTyposquat (not 0).
        assert_eq!(bd.count_for(ThreatSource::EcosystemsTyposquat), 1);
        assert_eq!(bd.typosquat_count, 1);
        assert_eq!(bd.popular_count, 1);

        // 3 packages + 2 hostnames + 2 IPs + 1 typosquat = 8; popular is separate.
        let total: u64 = bd.per_source().iter().map(|(_, c)| c).sum();
        assert_eq!(total, 8);
    }

    #[test]
    fn source_breakdown_folds_in_supplemental_overlay() {
        let key = SigningKey::generate(&mut OsRng);

        let mut primary_writer = ThreatDbWriter::new(1700000000, 1);
        primary_writer.add_ip(Ipv4Addr::new(203, 0, 113, 1), ThreatSource::FeodoTracker);
        let primary =
            ThreatDb::from_bytes(primary_writer.build(&key).expect("build"), 0).expect("load");

        let mut overlay_writer = ThreatDbWriter::new(1700000001, 1);
        overlay_writer.add_hostname("bad.example", ThreatSource::Urlhaus);
        overlay_writer.add_ip(Ipv4Addr::new(203, 0, 113, 9), ThreatSource::TorExit);
        let overlay =
            ThreatDb::from_bytes(overlay_writer.build(&key).expect("build"), 0).expect("load");

        let db = primary.with_supplemental(Some(overlay));
        let bd = db.source_breakdown();

        assert_eq!(bd.count_for(ThreatSource::FeodoTracker), 1);
        assert_eq!(bd.count_for(ThreatSource::Urlhaus), 1);
        assert_eq!(bd.count_for(ThreatSource::TorExit), 1);
    }

    #[test]
    fn source_breakdown_empty_db_is_all_zero() {
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1700000000, 1);
        let db = ThreatDb::from_bytes(writer.build(&key).expect("build"), 0).expect("load");
        let bd = db.source_breakdown();
        for (_, count) in bd.per_source() {
            assert_eq!(*count, 0);
        }
        assert_eq!(bd.typosquat_count, 0);
        assert_eq!(bd.popular_count, 0);
    }

    /// `Ecosystem` discriminants are part of the on-disk binary format — a
    /// renumber would misread every signed DB shipped to date. Pin them.
    #[test]
    fn test_ecosystem_discriminants_are_contiguous() {
        // Existing (must NEVER change — they are written by signed DBs).
        assert_eq!(Ecosystem::Npm as u8, 0);
        assert_eq!(Ecosystem::PyPI as u8, 1);
        assert_eq!(Ecosystem::RubyGems as u8, 2);
        assert_eq!(Ecosystem::Crates as u8, 3);
        assert_eq!(Ecosystem::Go as u8, 4);
        assert_eq!(Ecosystem::Maven as u8, 5);
        assert_eq!(Ecosystem::NuGet as u8, 6);
        assert_eq!(Ecosystem::Packagist as u8, 7);
        // M6 ch1 additions — appended, not inserted.
        assert_eq!(Ecosystem::Apt as u8, 8);
        assert_eq!(Ecosystem::Brew as u8, 9);
        assert_eq!(Ecosystem::Dnf as u8, 10);
        assert_eq!(Ecosystem::Yum as u8, 11);
        assert_eq!(Ecosystem::Pacman as u8, 12);
        assert_eq!(Ecosystem::Scoop as u8, 13);
        assert_eq!(Ecosystem::Docker as u8, 14);
        // from_u8 round-trips every value; unknown bytes return None.
        for v in 0u8..=14 {
            let eco = Ecosystem::from_u8(v).expect("must decode");
            assert_eq!(eco as u8, v, "round-trip failed for byte {v}");
        }
        assert!(Ecosystem::from_u8(255).is_none());
    }

    /// M6 ch1 — lookups for the new ecosystems (no feed wiring yet) must return
    /// empty without panicking on a populated DB.
    #[test]
    fn test_new_ecosystem_lookups_are_empty_no_panic() {
        let key = SigningKey::generate(&mut OsRng);
        let db = build_test_db(&key);
        for eco in [
            Ecosystem::Apt,
            Ecosystem::Brew,
            Ecosystem::Dnf,
            Ecosystem::Yum,
            Ecosystem::Pacman,
            Ecosystem::Scoop,
            Ecosystem::Docker,
        ] {
            assert!(db.check_package(eco, "nginx", Some("1.0.0")).is_none());
            assert!(db.check_package(eco, "nginx", None).is_none());
            assert!(!db.is_popular_package(eco, "nginx"));
            assert!(db.check_typosquat(eco, "nginx").is_none());
            assert!(db.check_popular_distance(eco, "nginx").is_none());
        }
    }

    // ------------------------------------------------------------------
    // v2 format (DB-B): writer/reader roundtrip, backward compat, footer/
    // trailer rejection, signature, and per-format cache-filename selection.
    // ------------------------------------------------------------------

    /// Build a v2 DB carrying one v1 package plus one artifact hash, one file
    /// hash (with behavior tags + campaign), and one malicious URL.
    fn build_v2_db(key: &SigningKey) -> Vec<u8> {
        let mut writer = ThreatDbWriter::new(1_700_000_500, 100);
        // A v1 package so the v1 sections are non-empty too.
        writer.add_package(
            Ecosystem::PyPI,
            "v2-pkg",
            &["1.2.3"],
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            false,
            Some("https://example.com/v2"),
        );
        writer.add_artifact_sha256(
            sha(0xAA),
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            true,
            Some("miasma"),
        );
        writer.add_file_sha256(
            sha(0xBB),
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            &[BehaviorTag::ProcessSpawn, BehaviorTag::CrossRuntime],
            Some("miasma"),
        );
        writer.add_malicious_url(
            "http://sfrclak.com:8000/6202033",
            ThreatSource::ExfilEndpoint,
        );
        writer
            .build_format(ThreatDbFormat::V2, key)
            .expect("v2 build")
    }

    #[test]
    fn v2_roundtrip_artifact_file_url_hits() {
        let key = SigningKey::generate(&mut OsRng);
        let bytes = build_v2_db(&key);
        let db = ThreatDb::from_bytes(bytes, 0).expect("v2 load");

        assert_eq!(db.stats().format_version, 2);

        // v1 package still resolves on a v2 file.
        assert!(db
            .check_package(Ecosystem::PyPI, "v2-pkg", Some("1.2.3"))
            .is_some());

        // Artifact hash hit.
        let am = db.check_artifact_sha256(&sha(0xAA)).expect("artifact hit");
        assert_eq!(am.source, ThreatSource::OssfMalicious);
        assert!(am.all_versions_malicious);
        assert_eq!(am.campaign.as_deref(), Some("miasma"));
        // Artifact miss.
        assert!(db.check_artifact_sha256(&sha(0xAB)).is_none());

        // File hash hit with behavior tags + campaign.
        let fm = db.check_file_sha256(&sha(0xBB)).expect("file hit");
        assert_eq!(fm.source, ThreatSource::OssfMalicious);
        assert!(fm.behavior_tags.contains(&BehaviorTag::ProcessSpawn));
        assert!(fm.behavior_tags.contains(&BehaviorTag::CrossRuntime));
        assert!(!fm.behavior_tags.contains(&BehaviorTag::NetworkExfil));
        assert_eq!(fm.campaign.as_deref(), Some("miasma"));
        assert!(db.check_file_sha256(&sha(0xBC)).is_none());

        // URL hit (exact compare after locating the hash) + miss.
        assert_eq!(
            db.check_malicious_url("http://sfrclak.com:8000/6202033"),
            Some(ThreatSource::ExfilEndpoint)
        );
        assert!(db
            .check_malicious_url("http://sfrclak.com:8000/other")
            .is_none());
    }

    #[test]
    fn v2_signature_verifies_against_signing_key() {
        // Freshly-signed v2 verifies against the key that signed it (the
        // embedded production key is a placeholder in tests, so we verify
        // against the signer directly, like test_signature_with_matching_key).
        let key = SigningKey::generate(&mut OsRng);
        let bytes = build_v2_db(&key);
        let sig_bytes = &bytes[SIG_OFFSET..SIG_OFFSET + SIGNATURE_LENGTH];
        let signature = Signature::from_slice(sig_bytes).expect("parse sig");
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&bytes[..SIG_OFFSET]);
        signed_data.extend_from_slice(&bytes[HEADER_SIZE..]);
        use ed25519_dalek::Verifier;
        assert!(
            key.verifying_key().verify(&signed_data, &signature).is_ok(),
            "v2 signature must verify over [0..SIG_OFFSET) ++ [HEADER_SIZE..)"
        );
    }

    #[test]
    fn v2_corrupt_section_byte_fails_signature() {
        // A byte flipped inside the appended v2 region must break the signature,
        // proving the v2 sections + trailer + footer are inside the signed range.
        let key = SigningKey::generate(&mut OsRng);
        let mut bytes = build_v2_db(&key);
        // Flip a byte well after the v1 header (in the v2 area / trailer / footer).
        let idx = bytes.len() - 10;
        bytes[idx] ^= 0xFF;
        let sig_bytes = &bytes[SIG_OFFSET..SIG_OFFSET + SIGNATURE_LENGTH];
        let signature = Signature::from_slice(sig_bytes).expect("parse sig");
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&bytes[..SIG_OFFSET]);
        signed_data.extend_from_slice(&bytes[HEADER_SIZE..]);
        use ed25519_dalek::Verifier;
        assert!(
            key.verifying_key()
                .verify(&signed_data, &signature)
                .is_err(),
            "tampering with the v2 region must invalidate the signature"
        );
    }

    #[test]
    fn v2_rollback_still_enforced() {
        // The rollback build_sequence check is preserved verbatim for v2.
        let key = SigningKey::generate(&mut OsRng);
        let bytes = build_v2_db(&key); // sequence 100
        let err = ThreatDb::from_bytes(bytes, 200).expect_err("v2 rollback must reject");
        assert!(matches!(err, ThreatDbError::RollbackDetected { .. }));
    }

    #[test]
    fn v2_empty_sections_roundtrip() {
        // A v2 DB with no v2 records at all still loads and every v2 lookup
        // returns None (empty sections are valid).
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1_700_000_000, 1);
        writer.add_ip(Ipv4Addr::new(1, 2, 3, 4), ThreatSource::FeodoTracker);
        let bytes = writer
            .build_format(ThreatDbFormat::V2, &key)
            .expect("v2 build");
        let db = ThreatDb::from_bytes(bytes, 0).expect("empty v2 load");
        assert_eq!(db.stats().format_version, 2);
        assert!(db.check_artifact_sha256(&sha(1)).is_none());
        assert!(db.check_file_sha256(&sha(1)).is_none());
        assert!(db.check_malicious_url("http://x").is_none());
    }

    #[test]
    fn v2_supplemental_overlay_resolves_v2_lookups() {
        // A v2 lookup that misses the primary defers to a v2 supplemental.
        let key = SigningKey::generate(&mut OsRng);
        let primary = ThreatDb::from_bytes(
            ThreatDbWriter::new(1, 1)
                .build_format(ThreatDbFormat::V2, &key)
                .unwrap(),
            0,
        )
        .unwrap();
        let mut overlay_writer = ThreatDbWriter::new(2, 1);
        overlay_writer.add_artifact_sha256(
            sha(0xCC),
            ThreatSource::DatadogMalicious,
            Confidence::Confirmed,
            false,
            None,
        );
        let overlay = ThreatDb::from_bytes(
            overlay_writer
                .build_format(ThreatDbFormat::V2, &key)
                .unwrap(),
            0,
        )
        .unwrap();
        let db = primary.with_supplemental(Some(overlay));
        let am = db
            .check_artifact_sha256(&sha(0xCC))
            .expect("supplemental artifact hit");
        assert_eq!(am.source, ThreatSource::DatadogMalicious);
    }

    /// Take a valid v2 DB and overwrite the fixed footer fields via a closure,
    /// returning the mutated bytes (for rejection tests).
    fn v2_with_footer_mut(mutate: impl FnOnce(&mut [u8])) -> Vec<u8> {
        let key = SigningKey::generate(&mut OsRng);
        let mut bytes = build_v2_db(&key);
        let foot = bytes.len() - FOOTER_SIZE;
        mutate(&mut bytes[foot..]);
        bytes
    }

    #[test]
    fn v2_reject_bad_footer_magic() {
        let bytes = v2_with_footer_mut(|f| f[0] ^= 0xFF);
        assert!(matches!(
            ThreatDb::from_bytes(bytes, 0),
            Err(ThreatDbError::InvalidTrailer(_))
        ));
    }

    #[test]
    fn v2_reject_unsupported_trailer_version() {
        // trailer_version is at footer[24..26].
        let bytes = v2_with_footer_mut(|f| f[24..26].copy_from_slice(&999u16.to_le_bytes()));
        assert!(matches!(
            ThreatDb::from_bytes(bytes, 0),
            Err(ThreatDbError::InvalidTrailer(_))
        ));
    }

    #[test]
    fn v2_reject_trailer_offset_out_of_bounds() {
        // trailer_offset at footer[8..16]: push it past EOF.
        let bytes = v2_with_footer_mut(|f| {
            f[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        });
        assert!(matches!(
            ThreatDb::from_bytes(bytes, 0),
            Err(ThreatDbError::InvalidTrailer(_))
        ));
    }

    #[test]
    fn v2_reject_trailer_offset_inside_header() {
        // A trailer_offset inside the signature header (< HEADER_SIZE) is rejected.
        let bytes = v2_with_footer_mut(|f| {
            f[8..16].copy_from_slice(&10u64.to_le_bytes());
            // keep a small length so only the offset rule trips.
            f[16..24].copy_from_slice(&(DESCRIPTOR_SIZE as u64).to_le_bytes());
        });
        assert!(matches!(
            ThreatDb::from_bytes(bytes, 0),
            Err(ThreatDbError::InvalidTrailer(_))
        ));
    }

    #[test]
    fn v2_reject_trailer_length_not_descriptor_multiple() {
        // trailer_length at footer[16..24]: set to a non-multiple.
        let bytes = v2_with_footer_mut(|f| {
            f[16..24].copy_from_slice(&((DESCRIPTOR_SIZE as u64) + 1).to_le_bytes())
        });
        assert!(matches!(
            ThreatDb::from_bytes(bytes, 0),
            Err(ThreatDbError::InvalidTrailer(_))
        ));
    }

    /// Build a v2 DB and rewrite a chosen descriptor field in the trailer, given
    /// a mutator over the descriptor index and a mutable slice of its 32 bytes.
    fn v2_with_descriptor_mut(which: usize, mutate: impl FnOnce(&mut [u8])) -> Vec<u8> {
        let key = SigningKey::generate(&mut OsRng);
        let mut bytes = build_v2_db(&key);
        let foot = bytes.len() - FOOTER_SIZE;
        let trailer_offset =
            u64::from_le_bytes(bytes[foot + 8..foot + 16].try_into().unwrap()) as usize;
        let dbase = trailer_offset + which * DESCRIPTOR_SIZE;
        mutate(&mut bytes[dbase..dbase + DESCRIPTOR_SIZE]);
        bytes
    }

    #[test]
    fn v2_reject_duplicate_section_type() {
        // Rewrite descriptor 1's section_type to equal descriptor 0's.
        let bytes = v2_with_descriptor_mut(1, |d| {
            d[0..2].copy_from_slice(&(SectionType::ArtifactSha as u16).to_le_bytes());
        });
        assert!(matches!(
            ThreatDb::from_bytes(bytes, 0),
            Err(ThreatDbError::InvalidTrailer(_))
        ));
    }

    #[test]
    fn v2_reject_unknown_section_type() {
        let bytes = v2_with_descriptor_mut(0, |d| {
            d[0..2].copy_from_slice(&4242u16.to_le_bytes());
        });
        assert!(matches!(
            ThreatDb::from_bytes(bytes, 0),
            Err(ThreatDbError::InvalidTrailer(_))
        ));
    }

    #[test]
    fn v2_reject_section_offset_inside_header() {
        // descriptor offset field is at descriptor[4..12].
        let bytes = v2_with_descriptor_mut(0, |d| {
            d[4..12].copy_from_slice(&10u64.to_le_bytes());
        });
        assert!(matches!(
            ThreatDb::from_bytes(bytes, 0),
            Err(ThreatDbError::InvalidTrailer(_))
        ));
    }

    #[test]
    fn v2_reject_section_count_times_record_size_mismatch() {
        // Inflate the artifact-sha descriptor count so count*record_size != length.
        let bytes = v2_with_descriptor_mut(0, |d| {
            d[20..28].copy_from_slice(&9999u64.to_le_bytes());
        });
        assert!(matches!(
            ThreatDb::from_bytes(bytes, 0),
            Err(ThreatDbError::InvalidTrailer(_))
        ));
    }

    #[test]
    fn v2_reject_section_running_into_trailer() {
        // Extend the artifact-sha section length so it overlaps the trailer.
        let bytes = v2_with_descriptor_mut(0, |d| {
            d[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
        });
        assert!(matches!(
            ThreatDb::from_bytes(bytes, 0),
            Err(ThreatDbError::InvalidTrailer(_))
        ));
    }

    #[test]
    fn v2_full_32_byte_hash_no_short_prefix_collision() {
        // Two hashes sharing a long common prefix but differing in the LAST byte
        // must be distinguished (the index keys on the full 32 bytes).
        let key = SigningKey::generate(&mut OsRng);
        let mut a = [0x11u8; 32];
        let mut b = [0x11u8; 32];
        a[31] = 0x01;
        b[31] = 0x02;
        let mut writer = ThreatDbWriter::new(1, 1);
        writer.add_artifact_sha256(
            a,
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            false,
            None,
        );
        let bytes = writer.build_format(ThreatDbFormat::V2, &key).unwrap();
        let db = ThreatDb::from_bytes(bytes, 0).unwrap();
        assert!(
            db.check_artifact_sha256(&a).is_some(),
            "exact 32-byte match hits"
        );
        assert!(
            db.check_artifact_sha256(&b).is_none(),
            "a hash differing only in the last byte must NOT match"
        );
    }

    #[test]
    fn v2_sibling_path_derivation() {
        assert_eq!(
            v2_sibling(Path::new("/x/tirith-threatdb.dat")),
            PathBuf::from("/x/tirith-threatdb-v2.dat")
        );
        assert_eq!(
            v2_sibling(Path::new("/x/custom.bin")),
            PathBuf::from("/x/custom.bin-v2")
        );
        // A non-UTF-8 `.dat` filename keeps its raw bytes (no lossy corruption).
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let raw = std::ffi::OsStr::from_bytes(b"/x/\xff-threatdb.dat");
            assert_eq!(
                v2_sibling(Path::new(raw)),
                PathBuf::from(std::ffi::OsStr::from_bytes(b"/x/\xff-threatdb-v2.dat"))
            );
        }
    }

    #[test]
    fn resolve_preferring_v2_parseable_else_v1() {
        // Drive the resolver directly with require_signature=false (the
        // supplemental discipline), so a self-signed v2 can be exercised. The
        // signed-primary discipline is covered by
        // `resolve_primary_requires_valid_signature` below.
        let key = SigningKey::generate(&mut OsRng);
        let tmp = tempfile::tempdir().unwrap();
        let v1_path = tmp.path().join("v1.dat");
        let v2_path = tmp.path().join("v2.dat");
        ThreatDbWriter::new(1, 1)
            .write_to(&v1_path, &key)
            .expect("write v1");

        // Only v1 present -> v1.
        assert_eq!(
            resolve_preferring_v2(Some(v2_path.clone()), Some(v1_path.clone()), false),
            Some(v1_path.clone())
        );
        // Both present, v2 parseable -> v2.
        ThreatDbWriter::new(2, 2)
            .write_to_format(ThreatDbFormat::V2, &v2_path, &key)
            .expect("write v2");
        assert_eq!(
            resolve_preferring_v2(Some(v2_path.clone()), Some(v1_path.clone()), false),
            Some(v2_path.clone())
        );
        // v2 corrupt -> falls back to v1 (corrupt v2 never shadows).
        std::fs::write(&v2_path, b"not a db").unwrap();
        assert_eq!(
            resolve_preferring_v2(Some(v2_path.clone()), Some(v1_path.clone()), false),
            Some(v1_path.clone())
        );
    }

    #[test]
    fn resolve_primary_requires_valid_signature() {
        // The signed-primary resolver (require_signature=true) must NOT prefer a
        // structurally-valid v2 that fails signature verification against the
        // embedded key (a self-signed DB does), so a planted unsigned v2 cannot
        // shadow a good v1 and fail-open the DB.
        let key = SigningKey::generate(&mut OsRng);
        let tmp = tempfile::tempdir().unwrap();
        let v1_path = tmp.path().join("v1.dat");
        let v2_path = tmp.path().join("v2.dat");
        ThreatDbWriter::new(1, 1)
            .write_to(&v1_path, &key)
            .expect("write v1");
        ThreatDbWriter::new(2, 2)
            .write_to_format(ThreatDbFormat::V2, &v2_path, &key)
            .expect("write v2");
        // Self-signed v2 fails the embedded-key signature check -> falls back to v1.
        assert_eq!(
            resolve_preferring_v2(Some(v2_path.clone()), Some(v1_path.clone()), true),
            Some(v1_path.clone()),
            "an unverifiable v2 must not shadow a good v1 under the signed-primary discipline"
        );
    }

    #[test]
    fn resolve_primary_path_falls_back_to_v1_for_self_signed_v2() {
        // End-to-end through resolve_primary_path (which requires a valid
        // signature): a self-signed v2 beside a v1 resolves to v1.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let key = SigningKey::generate(&mut OsRng);
        let tmp = tempfile::tempdir().unwrap();
        let v1_path = tmp.path().join("tirith-threatdb.dat");
        let v2_path = tmp.path().join("tirith-threatdb-v2.dat");
        ThreatDbWriter::new(1, 1)
            .write_to(&v1_path, &key)
            .expect("write v1");
        ThreatDbWriter::new(2, 2)
            .write_to_format(ThreatDbFormat::V2, &v2_path, &key)
            .expect("write v2");
        unsafe {
            std::env::set_var("TIRITH_THREATDB_PATH", &v1_path);
        }
        // v2 exists and parses but is self-signed, so the signed-primary resolver
        // falls back to the v1 path.
        assert_eq!(ThreatDb::resolve_primary_path(), Some(v1_path.clone()));
        // With no v2 at all, still v1.
        std::fs::remove_file(&v2_path).unwrap();
        assert_eq!(ThreatDb::resolve_primary_path(), Some(v1_path.clone()));
        unsafe {
            std::env::remove_var("TIRITH_THREATDB_PATH");
        }
    }
}
