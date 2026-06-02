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
const FORMAT_VERSION: u32 = 1;
/// Total header size in bytes.
const HEADER_SIZE: usize = 172;
/// Offset of the Ed25519 signature within the header.
const SIG_OFFSET: usize = 108;
/// Offset of the signer fingerprint within the header.
const FINGERPRINT_OFFSET: usize = 76;
const FINGERPRINT_LEN: usize = 32;
const DB_FILENAME: &str = "tirith-threatdb.dat";
const SUPPLEMENTAL_DB_FILENAME: &str = "tirith-threatdb-supplemental.dat";
/// Re-check file mtime at most every 60 seconds.
const MTIME_CHECK_INTERVAL_SECS: u64 = 60;

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
            _ => None,
        }
    }

    /// Every threat source variant, in stable declaration order.
    pub const ALL: [ThreatSource; 11] = [
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
            | Self::CisaKev => SourceTier::Primary,
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
        }
    }

    /// Default confidence level for network-indicator sources (hostnames, IPs).
    pub fn default_confidence(self) -> Confidence {
        match self {
            Self::TorExit => Confidence::Medium,
            Self::OssfMalicious
            | Self::DatadogMalicious
            | Self::FeodoTracker
            | Self::EcosystemsTyposquat
            | Self::CisaKev
            | Self::Urlhaus
            | Self::PhishingArmy
            | Self::PhishTank
            | Self::ThreatFoxIoc
            | Self::FireholIp => Confidence::Confirmed,
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
        if version != FORMAT_VERSION {
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

    /// Default filesystem path for the threat DB file. Checks
    /// `TIRITH_THREATDB_PATH` first, then `~/.local/share/tirith/...`.
    pub fn default_path() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("TIRITH_THREATDB_PATH") {
            if !p.is_empty() {
                return Some(PathBuf::from(p));
            }
        }
        policy::data_dir().map(|d| d.join(DB_FILENAME))
    }

    /// Optional supplemental DB path for user-local keyed feeds compiled on the
    /// user's machine during `tirith threat-db update`.
    pub fn supplemental_path() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("TIRITH_THREATDB_SUPPLEMENTAL_PATH") {
            if !p.is_empty() {
                return Some(PathBuf::from(p));
            }
        }
        policy::data_dir().map(|d| d.join(SUPPLEMENTAL_DB_FILENAME))
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

fn current_cache_source() -> Option<CacheSource> {
    let primary_path = ThreatDb::default_path()?;
    let primary_mtime = path_mtime_epoch(&primary_path)?;
    let supplemental_path = ThreatDb::supplemental_path().filter(|path| path.exists());
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
        }
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

    /// Build and write the database to a file. Signs with the provided keypair.
    pub fn write_to(
        mut self,
        path: &Path,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(), ThreatDbError> {
        let bytes = self.build(signing_key)?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    /// Build the database into bytes (for testing or in-memory use).
    pub fn build(
        &mut self,
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
        buf[0..8].copy_from_slice(MAGIC);
        buf[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
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

        // Sign: header before sig ++ all data after header.
        let mut signed_data = Vec::with_capacity(SIG_OFFSET + (buf.len() - HEADER_SIZE));
        signed_data.extend_from_slice(&buf[..SIG_OFFSET]);
        signed_data.extend_from_slice(&buf[HEADER_SIZE..]);

        use ed25519_dalek::Signer;
        let signature = signing_key.sign(&signed_data);
        buf[SIG_OFFSET..SIG_OFFSET + SIGNATURE_LENGTH].copy_from_slice(&signature.to_bytes());

        Ok(buf)
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
        assert_eq!(ThreatSource::ALL.len(), 11);
        assert!(
            ThreatSource::from_u8(11).is_none(),
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
        // The five feeds compiled into the signed CI DB are Primary.
        for src in [
            ThreatSource::OssfMalicious,
            ThreatSource::DatadogMalicious,
            ThreatSource::FeodoTracker,
            ThreatSource::EcosystemsTyposquat,
            ThreatSource::CisaKev,
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
}
