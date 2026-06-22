//! Wheel-RECORD and installed-RECORD integrity verification (PR B5).
//!
//! The two RECORD semantics are genuinely different, so this module has two entry
//! points and never conflates them:
//!
//! * [`verify_wheel_record`] is STRICT. A wheel is a freshly-built artifact, so
//!   its RECORD must account for EVERY member except RECORD itself (and the
//!   deprecated `RECORD.jws`/`RECORD.p7s` signature files), each hashed with
//!   SHA-256 or stronger. An unlisted executable member, a missing hash, a weak
//!   hash, or a hash that does not match the member's actual bytes is a
//!   violation. It consumes the [`ArtifactInspection`] A4's wheel reader produced
//!   (which already streamed and hashed every member), so it re-reads nothing.
//!
//! * [`verify_installed_record`] is LAX, per the installed-packages
//!   specification. An installed environment legitimately drifts (`.pyc` files
//!   appear, editable installs are sparse, conda/distro packaging diverges), so:
//!   a missing RECORD is a COVERAGE GAP, not a violation; a path may be absolute
//!   or relative to the directory containing `.dist-info`, and may use `/` or `\`;
//!   an empty hash OR size column makes a file [`FileVerification::Unverifiable`]
//!   (NOT a mismatch); scripts may live outside `site-packages`; and the verifier
//!   never resolves a path OUT of the environment unless RECORD legitimately names
//!   a scheme path AND policy permits it.
//!
//! Both produce granular [`crate::artifact::ArtifactSignal`]s
//! ([`crate::artifact::ArtifactSignalKind::RecordHashMismatch`] and friends);
//! upstream correlation maps a set of signals to the single user-facing
//! [`crate::verdict::RuleId::PythonInstalledIntegrityViolation`] finding. This
//! module emits SIGNALS, never findings.
//!
//! # Ownership index
//!
//! [`OwnershipIndex`] is a DUPLICATE-AWARE multimap
//! (`BTreeMap<NormalizedInstalledPath, Vec<DistributionIdentity>>`), because
//! duplicate ownership is exactly what we detect: two distributions claiming the
//! same installed path, or one distribution's payload reference resolving to a
//! file owned by ANOTHER distribution (the cross-distribution loader/payload
//! split). A plain map keyed by path would hide the second owner.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::artifact::wheel::{parse_record, RecordEntry};
use crate::artifact::{
    ArtifactFileKind, ArtifactInspection, ArtifactSignal, ArtifactSignalKind, DistributionIdentity,
    EdgeConfidence, InspectionSubject,
};
use crate::location::SubjectLocation;

/// A normalized installed path used as the ownership-index key and for
/// cross-distribution reference resolution. Normalization makes two spellings of
/// the same install location compare equal: separators are unified to `/`, a
/// `./` prefix is dropped, and a trailing slash is trimmed. Case is preserved
/// (NOT folded), because a wheel RECORD and a cross-distribution `.pth` reference
/// both use forward slashes and case-exact module names; folding case here would
/// over-merge two genuinely distinct modules on a case-sensitive filesystem.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NormalizedInstalledPath(String);

impl NormalizedInstalledPath {
    /// Normalize a raw RECORD / on-disk relative path into the index key:
    /// backslashes to forward slashes, collapse repeated slashes, drop a leading
    /// `./`, and trim a trailing slash. Does NOT resolve `..` (a RECORD path
    /// containing `..` is suspicious and handled by the verifier, not silently
    /// normalized away).
    pub fn new(raw: &str) -> Self {
        let unified = raw.replace('\\', "/");
        let mut out = String::with_capacity(unified.len());
        let mut prev_slash = false;
        for ch in unified.chars() {
            if ch == '/' {
                if !prev_slash {
                    out.push('/');
                    prev_slash = true;
                }
            } else {
                out.push(ch);
                prev_slash = false;
            }
        }
        let trimmed = out
            .strip_prefix("./")
            .unwrap_or(&out)
            .trim_end_matches('/')
            .to_string();
        NormalizedInstalledPath(trimmed)
    }

    /// The normalized string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NormalizedInstalledPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A duplicate-aware ownership multimap from a normalized installed path to every
/// distribution that lists it in its RECORD. Built once per `site-packages` root.
#[derive(Debug, Clone, Default)]
pub struct OwnershipIndex {
    map: BTreeMap<NormalizedInstalledPath, Vec<DistributionIdentity>>,
}

impl OwnershipIndex {
    /// An empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `dist` owns `path`. The same `(path, dist)` pair is not
    /// recorded twice (a RECORD listing a path once means one ownership), but two
    /// DIFFERENT distributions owning the same path are both kept (that is the
    /// duplicate we detect).
    pub fn insert(&mut self, path: NormalizedInstalledPath, dist: DistributionIdentity) {
        let owners = self.map.entry(path).or_default();
        if !owners.iter().any(|d| same_distribution(d, &dist)) {
            owners.push(dist);
        }
    }

    /// The distributions owning `path`, or an empty slice if none.
    pub fn owners(&self, path: &NormalizedInstalledPath) -> &[DistributionIdentity] {
        self.map.get(path).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Every path owned by more than one distribution, with its owners. Used to
    /// emit [`ArtifactSignalKind::DuplicateOwnedFile`] signals.
    pub fn duplicates(
        &self,
    ) -> impl Iterator<Item = (&NormalizedInstalledPath, &[DistributionIdentity])> {
        self.map
            .iter()
            .filter(|(_, owners)| owners.len() > 1)
            .map(|(p, owners)| (p, owners.as_slice()))
    }

    /// Whether ANY distribution owns `path`.
    pub fn is_owned(&self, path: &NormalizedInstalledPath) -> bool {
        self.map.contains_key(path)
    }

    /// The number of distinct owned paths (for tests/diagnostics).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Whether two distribution identities refer to the same install (same name +
/// same `.dist-info` directory). Name alone is insufficient (two trees could each
/// hold a `foo`), and the `.dist-info` path is the install's stable identity.
fn same_distribution(a: &DistributionIdentity, b: &DistributionIdentity) -> bool {
    a.name == b.name && a.dist_info_path == b.dist_info_path
}

/// A hard wheel-RECORD violation. A wheel is a fresh build, so any of these means
/// the RECORD does not honestly account for the wheel's contents. These are DATA;
/// the caller maps them to signals/findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WheelRecordViolation {
    /// The wheel has no RECORD member at all. (An unparseable RECORD is surfaced
    /// by [`parse_record`]'s `Result` before this verifier runs, so the caller
    /// passes `None` here for both an absent and an unparseable RECORD.)
    MissingRecord,
    /// A member is present in the wheel but absent from RECORD. `executable`
    /// flags a member that can run (a native module or a script), which is the
    /// most serious unlisted case.
    UnlistedMember { member: String, executable: bool },
    /// A RECORD entry's recorded hash does not match the member's actual bytes.
    HashMismatch {
        member: String,
        recorded: String,
        actual: String,
    },
    /// A RECORD entry lists a member with no hash (or a weak/short one) where a
    /// strong SHA-256+ hash is required.
    WeakOrMissingHash { member: String },
    /// RECORD lists a path that is not a member of the wheel.
    RecordPathNotPresent { path: String },
}

/// The result of a STRICT wheel-RECORD verification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WheelRecordResult {
    /// Every violation found (the verifier reports all, not just the first).
    pub violations: Vec<WheelRecordViolation>,
    /// Granular signals for correlation (mirrors the violations as
    /// `ArtifactSignal`s with locations).
    pub signals: Vec<ArtifactSignal>,
}

impl WheelRecordResult {
    /// Whether the wheel's RECORD verified with no violation.
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }
}

/// The deprecated RECORD signature members that are EXEMPT from being listed in
/// RECORD (a RECORD cannot list its own signature, just as it cannot list
/// itself).
fn is_record_or_signature(member_basename: &str) -> bool {
    matches!(member_basename, "RECORD" | "RECORD.jws" | "RECORD.p7s")
}

/// The `.dist-info/RECORD` member path within a wheel, if THIS member is it.
/// A wheel has exactly one `<name>-<version>.dist-info/RECORD`.
fn is_dist_info_record(member: &str) -> bool {
    member
        .rsplit('/')
        .next()
        .map(is_record_or_signature)
        .unwrap_or(false)
        && member.contains(".dist-info/")
}

/// Verify a wheel's RECORD STRICTLY against the [`ArtifactInspection`] A4 produced
/// (whose `files` already carry each member's real SHA-256 and size). `record`
/// is the parsed RECORD (from [`parse_record`] on the RECORD member's bytes), or
/// `None` if the wheel had no RECORD member.
///
/// Strictness: every member except RECORD/signature files must be listed in
/// RECORD with a strong (SHA-256+) hash that matches its actual bytes; an
/// UNLISTED member is a violation (an unlisted EXECUTABLE member is the serious
/// case the plan calls out); a RECORD path naming no member is a violation.
pub fn verify_wheel_record(
    inspection: &ArtifactInspection,
    record: Option<&[RecordEntry]>,
) -> WheelRecordResult {
    let mut result = WheelRecordResult::default();

    let Some(record) = record else {
        result.violations.push(WheelRecordViolation::MissingRecord);
        return result;
    };

    let outer = wheel_outer_name(inspection);

    // Index the RECORD by normalized path -> entry, so a member lookup is O(log n)
    // and a wheel filename with a comma (CSV-quoted) is handled by the parser.
    let mut record_by_path: BTreeMap<NormalizedInstalledPath, &RecordEntry> = BTreeMap::new();
    for entry in record {
        record_by_path.insert(NormalizedInstalledPath::new(&entry.path), entry);
    }

    // 1. Every wheel member (except RECORD/signatures) must be listed + verified.
    let mut listed_member_keys: Vec<NormalizedInstalledPath> = Vec::new();
    for file in &inspection.files {
        let Some(member) = file.location.member_path.as_deref() else {
            continue;
        };
        if is_dist_info_record(member) {
            continue; // RECORD / signatures are exempt from listing themselves.
        }
        let key = NormalizedInstalledPath::new(member);
        listed_member_keys.push(key.clone());
        let executable = is_executable_kind(file.kind);

        match record_by_path.get(&key) {
            None => {
                result
                    .violations
                    .push(WheelRecordViolation::UnlistedMember {
                        member: member.to_string(),
                        executable,
                    });
                result.signals.push(signal(
                    ArtifactSignalKind::UnlistedInstalledFile,
                    member_location(outer.as_deref(), member),
                    format!("wheel member '{member}' is not listed in RECORD"),
                    if executable {
                        EdgeConfidence::High
                    } else {
                        EdgeConfidence::Medium
                    },
                ));
            }
            Some(entry) => {
                // The member is listed; the hash must be strong AND match.
                match &entry.hash {
                    None => {
                        result
                            .violations
                            .push(WheelRecordViolation::WeakOrMissingHash {
                                member: member.to_string(),
                            });
                    }
                    Some(hash) if !hash.is_strong() => {
                        result
                            .violations
                            .push(WheelRecordViolation::WeakOrMissingHash {
                                member: member.to_string(),
                            });
                    }
                    Some(hash) if hash.algorithm == "sha256" => {
                        // Compare the recorded digest to the member's actual
                        // SHA-256 (A4 computed it). Only sha256 is directly
                        // comparable to the inspection's hex.
                        let actual_hex = &file.sha256;
                        let recorded_hex = hex_of(&hash.digest);
                        if &recorded_hex != actual_hex {
                            result.violations.push(WheelRecordViolation::HashMismatch {
                                member: member.to_string(),
                                recorded: recorded_hex.clone(),
                                actual: actual_hex.clone(),
                            });
                            result.signals.push(signal(
                                ArtifactSignalKind::RecordHashMismatch,
                                member_location(outer.as_deref(), member),
                                format!(
                                    "wheel member '{member}' RECORD hash {recorded_hex} \
                                     != actual {actual_hex}"
                                ),
                                EdgeConfidence::High,
                            ));
                        }
                    }
                    Some(_) => {
                        // A strong hash in an algorithm OTHER than sha256
                        // (sha512/sha384/sha3_*). A4 only computed sha256 for the
                        // member, so this tool cannot recompute the recorded digest
                        // to confirm or refute it. Accepting it on the strength of
                        // the label alone would let a fabricated
                        // `member,sha512=<bogus>,size` row clear STRICT verification
                        // with no comparison. Under strict wheel verification an
                        // UNVERIFIABLE member is a violation, not silent acceptance.
                        result
                            .violations
                            .push(WheelRecordViolation::WeakOrMissingHash {
                                member: member.to_string(),
                            });
                    }
                }
            }
        }
    }

    // 2. Every RECORD path must correspond to a wheel member (a RECORD listing a
    // path that is not in the wheel is a structural lie).
    let member_key_set: std::collections::BTreeSet<&NormalizedInstalledPath> =
        listed_member_keys.iter().collect();
    for entry in record {
        let key = NormalizedInstalledPath::new(&entry.path);
        // RECORD itself (and signatures) need not be a "member" we collected if
        // the inspection skipped them; exempt by basename.
        let basename = key.as_str().rsplit('/').next().unwrap_or(key.as_str());
        if is_record_or_signature(basename) {
            continue;
        }
        if !member_key_set.contains(&key) {
            result
                .violations
                .push(WheelRecordViolation::RecordPathNotPresent {
                    path: entry.path.clone(),
                });
        }
    }

    result
}

/// Whether an [`ArtifactFileKind`] is something that can EXECUTE (a native module
/// or a bundled script). An unlisted member of one of these kinds is the serious
/// wheel-RECORD case.
fn is_executable_kind(kind: ArtifactFileKind) -> bool {
    matches!(
        kind,
        ArtifactFileKind::NativeModule | ArtifactFileKind::Script | ArtifactFileKind::WasmModule
    )
}

/// The wheel's on-disk filename from its inspection subject, for member
/// locations. `None` for a subject that is not an artifact/archive.
fn wheel_outer_name(inspection: &ArtifactInspection) -> Option<String> {
    match &inspection.subject {
        InspectionSubject::Artifact(a) => Some(a.filename.clone()),
        InspectionSubject::GenericArchive(g) => Some(g.filename.clone()),
        _ => None,
    }
}

/// A member [`SubjectLocation`] (`outer.whl!/member`) when the outer name is
/// known, else a bare member-path location.
fn member_location(outer: Option<&str>, member: &str) -> SubjectLocation {
    match outer {
        Some(o) => SubjectLocation::member(o, member),
        None => SubjectLocation {
            outer_path: None,
            member_path: Some(member.to_string()),
            installed_path: None,
        },
    }
}

/// Lowercase-hex of a digest byte slice (to compare with A4's hex hashes).
fn hex_of(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Build an [`ArtifactSignal`].
fn signal(
    kind: ArtifactSignalKind,
    location: SubjectLocation,
    evidence: String,
    confidence: EdgeConfidence,
) -> ArtifactSignal {
    ArtifactSignal {
        kind,
        location,
        evidence,
        confidence,
    }
}

// ---------------------------------------------------------------------------
// Installed RECORD (lax)
// ---------------------------------------------------------------------------

/// The on-disk layout an installed RECORD resolves against. An installed RECORD
/// path may be absolute, or relative to the directory CONTAINING the `.dist-info`
/// (which is the site-packages root for a normal install), and a few entries
/// (scripts, headers, data) belong to OTHER scheme directories. The layout names
/// the directories so the verifier can resolve a path WITHOUT ever escaping the
/// environment unless a scheme path is legitimately named and policy permits it.
#[derive(Debug, Clone)]
pub struct EnvironmentLayout {
    /// The directory containing the `.dist-info` (the purelib/platlib root for a
    /// normal install). A relative RECORD path resolves against this.
    pub site_packages: PathBuf,
    /// Additional scheme roots a RECORD path may legitimately reference
    /// (`scripts`, `data`, `headers`, the venv prefix). A path that resolves
    /// inside any of these (or `site_packages`) is in-environment.
    pub scheme_roots: Vec<PathBuf>,
}

impl EnvironmentLayout {
    /// A layout for a `site-packages` directory with no extra scheme roots known
    /// (the common case: the verifier resolves relative paths against it and
    /// treats an absolute path outside it as out-of-environment).
    pub fn for_site_packages(site_packages: impl Into<PathBuf>) -> Self {
        Self {
            site_packages: site_packages.into(),
            scheme_roots: Vec::new(),
        }
    }

    /// Whether `resolved` is inside the environment (the site-packages root or any
    /// scheme root), comparing already-normalized absolute paths by prefix.
    fn contains(&self, resolved: &Path) -> bool {
        if resolved.starts_with(&self.site_packages) {
            return true;
        }
        self.scheme_roots.iter().any(|r| resolved.starts_with(r))
    }
}

/// How a single RECORD-listed file verified against disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileVerification {
    /// The file exists and its hash (and size, when recorded) matched.
    Verified,
    /// The file exists but its recorded hash did not match the bytes on disk.
    Mismatch { recorded: String, actual: String },
    /// The file's hash OR size column was empty, so it cannot be verified. This
    /// is EXPECTED for some installed files and is NOT a mismatch.
    Unverifiable { reason: UnverifiableReason },
    /// RECORD lists the file but it is absent from disk.
    Missing,
    /// The recorded path resolves OUTSIDE the environment and is not a permitted
    /// scheme path, so the verifier refuses to read it (it will not follow a
    /// RECORD path out of the tree).
    OutOfEnvironment,
}

/// Why a file is [`FileVerification::Unverifiable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnverifiableReason {
    /// The hash column was empty.
    EmptyHash,
    /// The size column was empty (and so a hash, even if present, is not a
    /// complete record; per the spec an empty size is tolerated).
    EmptySize,
    /// The recorded hash used an algorithm this verifier does not compute, so it
    /// could not be checked (still not a mismatch).
    UnsupportedAlgorithm,
    /// The file could not be opened/hashed (a permission error), so no comparison
    /// was possible. Distinct from `Missing` (which is absence).
    Unreadable,
}

/// One verified RECORD entry: the recorded path, its resolved on-disk path (when
/// in-environment), and the verification outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEntry {
    /// The path as written in RECORD.
    pub recorded_path: String,
    /// The normalized ownership key for this path.
    pub normalized: NormalizedInstalledPath,
    /// The verification outcome.
    pub verification: FileVerification,
}

/// The result of a LAX installed-RECORD verification of one distribution.
#[derive(Debug, Clone, Default)]
pub struct InstalledRecordResult {
    /// `true` when the distribution had NO RECORD file. Per the installed-packages
    /// spec this is a COVERAGE GAP, not a violation; the caller records it as
    /// such. The other fields are empty in this case.
    pub record_missing: bool,
    /// `true` when the install is editable (from `direct_url.json`), so a sparse
    /// RECORD is expected and an absent project file is not flagged.
    pub editable: bool,
    /// `true` when an `INSTALLER` file or an externally-managed marker indicates a
    /// non-pip installer (conda, distro), where divergence is legitimate.
    pub externally_managed: bool,
    /// Per-entry verification outcomes.
    pub entries: Vec<VerifiedEntry>,
    /// Granular signals for correlation (hash mismatch, missing file).
    pub signals: Vec<ArtifactSignal>,
    /// A RECORD parse error, if the RECORD existed but was unparseable. The
    /// installed path is lenient, so an unparseable RECORD is surfaced (the caller
    /// may treat it as a coverage gap), not a hard violation.
    pub parse_error: Option<String>,
}

/// Verify an installed distribution's RECORD LENIENTLY. `dist_info_dir` is the
/// on-disk `.dist-info` directory; `layout` resolves relative paths and bounds
/// the environment; `dist` identifies the distribution for signal locations.
/// `allow_scheme_escape` permits resolving a RECORD path that legitimately names
/// a scheme directory outside `site-packages` (off by default; the verifier never
/// escapes the environment otherwise).
///
/// Leniency (per the installed-packages spec):
/// * No RECORD -> `record_missing` (a coverage gap, NOT a violation).
/// * An empty hash or size column -> [`FileVerification::Unverifiable`], not a
///   mismatch.
/// * A path may be absolute, relative-to-`site_packages`, or `\`-separated.
/// * A path outside the environment (and not a permitted scheme path) ->
///   [`FileVerification::OutOfEnvironment`] (refused, never read).
pub fn verify_installed_record(
    dist_info_dir: &Path,
    layout: &EnvironmentLayout,
    dist: &DistributionIdentity,
    allow_scheme_escape: bool,
) -> InstalledRecordResult {
    // Installer / externally-managed and editable signals up front: a non-pip
    // installer (conda, distro) or an editable install means drift is expected,
    // which downstream correlation uses to avoid over-flagging.
    let mut result = InstalledRecordResult {
        externally_managed: detect_externally_managed(dist_info_dir, layout),
        editable: detect_editable(dist_info_dir),
        ..Default::default()
    };

    let record_path = dist_info_dir.join("RECORD");
    let text = match read_record_text(&record_path) {
        RecordRead::Missing => {
            result.record_missing = true;
            return result;
        }
        RecordRead::Unreadable => {
            // Treat an unreadable RECORD like a missing one (a coverage gap); we
            // cannot verify what we cannot read.
            result.record_missing = true;
            return result;
        }
        RecordRead::Text(t) => t,
    };

    let entries = match parse_record(&text) {
        Ok(e) => e,
        Err(e) => {
            result.parse_error = Some(e.to_string());
            return result;
        }
    };

    let canonical_site = std::fs::canonicalize(&layout.site_packages)
        .unwrap_or_else(|_| layout.site_packages.clone());

    for entry in &entries {
        let normalized = NormalizedInstalledPath::new(&entry.path);
        let basename = normalized
            .as_str()
            .rsplit('/')
            .next()
            .unwrap_or(normalized.as_str());

        // RECORD itself is listed with empty hash/size; skip verifying it.
        if is_record_or_signature(basename) && entry.path.replace('\\', "/").contains(".dist-info/")
        {
            result.entries.push(VerifiedEntry {
                recorded_path: entry.path.clone(),
                normalized,
                verification: FileVerification::Unverifiable {
                    reason: UnverifiableReason::EmptyHash,
                },
            });
            continue;
        }

        let resolved = resolve_installed_path(&entry.path, layout);
        let verification = match resolved {
            ResolvedPath::OutOfEnvironment if !allow_scheme_escape => {
                FileVerification::OutOfEnvironment
            }
            ResolvedPath::OutOfEnvironment => {
                // Scheme escape permitted, but ONLY into a legitimate scheme root
                // (scripts/data/headers/prefix). An absolute RECORD path that does
                // not canonicalize under any scheme root stays OutOfEnvironment;
                // the flag does not license reading arbitrary absolute paths.
                let abs = PathBuf::from(entry.path.replace('\\', "/"));
                if path_within_scheme_roots(&abs, layout) {
                    verify_one_file(&abs, entry)
                } else {
                    FileVerification::OutOfEnvironment
                }
            }
            ResolvedPath::InEnvironment(path) => {
                // Confirm the resolved path canonicalizes to a real location inside
                // the (canonical) environment BEFORE touching disk. This resolves
                // through every intermediate directory, so an in-tree symlink whose
                // target escapes the environment (e.g. `site/legitdir -> /etc`) is
                // rejected here rather than followed out of the tree.
                if path_is_within(&path, &canonical_site, layout) {
                    verify_one_file(&path, entry)
                } else {
                    FileVerification::OutOfEnvironment
                }
            }
        };

        // Emit a signal for a real integrity problem (mismatch / missing), but NOT
        // for an unverifiable or out-of-environment entry (those are expected /
        // refused, not tampering).
        match &verification {
            FileVerification::Mismatch { recorded, actual } => {
                result.signals.push(signal(
                    ArtifactSignalKind::RecordHashMismatch,
                    SubjectLocation::installed(layout.site_packages.join(normalized.as_str())),
                    format!(
                        "installed file '{}' of {} RECORD hash {recorded} != actual {actual}",
                        entry.path, dist.name
                    ),
                    EdgeConfidence::High,
                ));
            }
            // A missing file is a weaker signal in an installed tree (it may be a
            // `.pyc` that was never compiled, or an editable's absent file); it is
            // suppressed entirely for an editable install.
            FileVerification::Missing if !result.editable => {
                result.signals.push(signal(
                    ArtifactSignalKind::RecordMissingFile,
                    SubjectLocation::installed(layout.site_packages.join(normalized.as_str())),
                    format!(
                        "installed file '{}' listed in {} RECORD is missing from disk",
                        entry.path, dist.name
                    ),
                    EdgeConfidence::Low,
                ));
            }
            _ => {}
        }

        result.entries.push(VerifiedEntry {
            recorded_path: entry.path.clone(),
            normalized,
            verification,
        });
    }

    result
}

/// Add every RECORD-listed path of an installed distribution to an ownership
/// index. Reads the distribution's RECORD leniently; a missing/unparseable RECORD
/// contributes nothing (it is a coverage gap, handled elsewhere). Returns the
/// number of paths added.
pub fn index_distribution_ownership(
    dist_info_dir: &Path,
    dist: &DistributionIdentity,
    index: &mut OwnershipIndex,
) -> usize {
    let record_path = dist_info_dir.join("RECORD");
    let RecordRead::Text(text) = read_record_text(&record_path) else {
        return 0;
    };
    let Ok(entries) = parse_record(&text) else {
        return 0;
    };
    let mut added = 0;
    for entry in &entries {
        let normalized = NormalizedInstalledPath::new(&entry.path);
        // A directory entry (trailing slash stripped to empty) or RECORD itself is
        // not an owned file worth indexing for cross-distribution detection.
        let basename = normalized
            .as_str()
            .rsplit('/')
            .next()
            .unwrap_or(normalized.as_str());
        if normalized.as_str().is_empty() || is_record_or_signature(basename) {
            continue;
        }
        index.insert(normalized, dist.clone());
        added += 1;
    }
    added
}

/// The outcome of reading a RECORD file.
enum RecordRead {
    /// The file does not exist.
    Missing,
    /// The file exists but could not be read.
    Unreadable,
    /// The file's text.
    Text(String),
}

/// Read a RECORD file no-follow within a sane cap (a RECORD is a manifest, not a
/// payload; 64 MiB is far above any real one). A symlinked RECORD is refused (a
/// planted symlink must not redirect the read).
fn read_record_text(path: &Path) -> RecordRead {
    const MAX_RECORD_BYTES: u64 = 64 * 1024 * 1024;
    match crate::util::read_text_no_follow_capped(path, MAX_RECORD_BYTES) {
        Ok(bytes) => RecordRead::Text(String::from_utf8_lossy(&bytes).into_owned()),
        Err(crate::util::OpenRegularError::NotFound) => RecordRead::Missing,
        Err(_) => RecordRead::Unreadable,
    }
}

/// How a RECORD path resolved against the environment.
enum ResolvedPath {
    /// The path is inside the environment; the resolved on-disk path.
    InEnvironment(PathBuf),
    /// The path is absolute and outside the environment (a scheme path or an
    /// escape); the caller decides whether to verify it.
    OutOfEnvironment,
}

/// Resolve an installed-RECORD path against the layout. A relative path resolves
/// against `site_packages`; an absolute path is checked for containment in the
/// environment. Backslashes are unified first (a Windows RECORD may use `\`).
fn resolve_installed_path(raw: &str, layout: &EnvironmentLayout) -> ResolvedPath {
    let unified = raw.replace('\\', "/");
    let p = Path::new(&unified);
    if p.is_absolute() {
        let pb = PathBuf::from(&unified);
        if layout.contains(&pb) {
            ResolvedPath::InEnvironment(pb)
        } else {
            ResolvedPath::OutOfEnvironment
        }
    } else {
        // Relative to the site-packages root. A `..` escaping the root is caught
        // by the post-resolution containment check in the caller.
        ResolvedPath::InEnvironment(layout.site_packages.join(&unified))
    }
}

/// Whether a resolved path is genuinely within the environment, by REAL
/// filesystem location and never by lexical spelling. The path's parent is
/// canonicalized through every intermediate directory and the final component
/// re-attached (so a not-yet-created file is still checked), then containment is
/// confirmed against the canonical site root or any canonical scheme root.
///
/// This deliberately has NO lexical fast path: a RECORD entry like `legitdir/x`
/// where `site/legitdir` is a symlink to `/etc` would lexically start inside the
/// site root, yet its real location is outside the environment. Routing through
/// [`crate::util::canonical_within`] (which is fail-closed on any
/// canonicalization error) resolves that symlink and rejects the escape, holding
/// the module's documented guarantee that it never reads a path OUT of the
/// environment.
fn path_is_within(path: &Path, canonical_site: &Path, layout: &EnvironmentLayout) -> bool {
    crate::util::canonical_within(path, canonical_site)
        || layout
            .scheme_roots
            .iter()
            .any(|r| crate::util::canonical_within(path, r))
}

/// Whether an absolute RECORD path's REAL location lies under one of the layout's
/// scheme roots (scripts/data/headers/prefix). Used only on the
/// `allow_scheme_escape` path: the flag permits resolving a path that legitimately
/// names a scheme directory, NOT reading an arbitrary absolute path. A path under
/// no scheme root stays out-of-environment. Canonicalizes through intermediate
/// directories (fail-closed) so an in-tree symlink cannot smuggle an escape past
/// the scheme-root check either.
fn path_within_scheme_roots(path: &Path, layout: &EnvironmentLayout) -> bool {
    layout
        .scheme_roots
        .iter()
        .any(|r| crate::util::canonical_within(path, r))
}

/// Verify one in-environment file against its RECORD entry. A present, usable
/// (sha256) hash is ALWAYS compared to the file's actual SHA-256, even when the
/// size column is empty: a hash is the real integrity check, and an empty size is
/// tolerated by the spec, so a valid hash must not be skipped just because size is
/// blank. Only when no usable hash is available does an empty hash or size column
/// make the entry [`FileVerification::Unverifiable`].
fn verify_one_file(path: &Path, entry: &RecordEntry) -> FileVerification {
    // Prefer the hash. A sha256 hash is comparable; an empty size column does NOT
    // suppress it (that was a bug: a valid hash with a blank size was never
    // checked). A non-sha256 algorithm or an absent hash falls through to the
    // unverifiable classification below.
    let Some(hash) = &entry.hash else {
        // No hash to compare. With no size either, the row carries no verifiable
        // data at all; report the empty-size reason when size is also blank, else
        // the empty-hash reason.
        return FileVerification::Unverifiable {
            reason: if entry.size.is_none() {
                UnverifiableReason::EmptySize
            } else {
                UnverifiableReason::EmptyHash
            },
        };
    };
    if hash.algorithm != "sha256" {
        // We only compute SHA-256; a different (even if strong) algorithm cannot
        // be checked here, so it is unverifiable, not a mismatch.
        return FileVerification::Unverifiable {
            reason: UnverifiableReason::UnsupportedAlgorithm,
        };
    }

    // Open no-follow and hash from the same handle (TOCTOU-safe). A missing file
    // is `Missing`; an unreadable one is `Unverifiable::Unreadable`.
    let file = match crate::util::open_read_no_follow_capped(path, u64::MAX) {
        Ok(f) => f,
        Err(crate::util::OpenRegularError::NotFound) => return FileVerification::Missing,
        Err(_) => {
            return FileVerification::Unverifiable {
                reason: UnverifiableReason::Unreadable,
            }
        }
    };
    match crate::util::sha256_from_handle(file, crate::scan::MAX_COVERAGE_HASH_BYTES) {
        Ok(crate::util::HashOutcome::Digest(actual)) => {
            let recorded = hex_of(&hash.digest);
            if recorded == actual {
                FileVerification::Verified
            } else {
                FileVerification::Mismatch { recorded, actual }
            }
        }
        // A file too large to hash within the budget is unverifiable, not a
        // mismatch (we refuse to hash unbounded).
        Ok(crate::util::HashOutcome::BudgetExceeded) | Err(_) => FileVerification::Unverifiable {
            reason: UnverifiableReason::Unreadable,
        },
    }
}

/// Detect a non-pip installer from an `INSTALLER` file or an externally-managed
/// marker, where divergence from a clean wheel install is legitimate.
fn detect_externally_managed(dist_info_dir: &Path, layout: &EnvironmentLayout) -> bool {
    // `<dist-info>/INSTALLER` naming a non-pip installer (conda, distro tools).
    let installer = dist_info_dir.join("INSTALLER");
    if let Ok(bytes) = crate::util::read_text_no_follow_capped(&installer, 4096) {
        let who = String::from_utf8_lossy(&bytes).trim().to_ascii_lowercase();
        if !who.is_empty() && who != "pip" {
            return true;
        }
    }
    // A PEP 668 `EXTERNALLY-MANAGED` marker at the environment prefix (one level
    // up from site-packages, best-effort) means a distro/system manager owns it.
    if let Some(prefix) = layout.site_packages.parent() {
        if prefix.join("EXTERNALLY-MANAGED").exists() {
            return true;
        }
    }
    false
}

/// Detect an editable install from `direct_url.json` (`dir_info.editable`), so a
/// sparse RECORD and absent project files are expected.
fn detect_editable(dist_info_dir: &Path) -> bool {
    let direct_url = dist_info_dir.join("direct_url.json");
    let Ok(bytes) = crate::util::read_text_no_follow_capped(&direct_url, 1024 * 1024) else {
        return false;
    };
    let text = String::from_utf8_lossy(&bytes);
    crate::artifact::wheel::parse_direct_url(&text)
        .map(|du| du.editable)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::wheel::RecordHash;
    use crate::artifact::{ArtifactFile, ArtifactIdentity};
    use crate::threatdb::Ecosystem;
    use base64::Engine as _;
    use std::fs;
    use tempfile::tempdir;

    /// One RECORD row for a test helper: `(path, optional digest bytes, optional
    /// size)`. An absent digest/size yields an empty RECORD column.
    type TestRecordRow<'a> = (&'a str, Option<Vec<u8>>, Option<u64>);

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(bytes))
    }

    /// SHA-256 digest bytes of a slice (for a RECORD hash).
    fn sha256_bytes(bytes: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes).to_vec()
    }

    fn wheel_subject(filename: &str) -> InspectionSubject {
        InspectionSubject::Artifact(ArtifactIdentity {
            ecosystem: Ecosystem::PyPI,
            name: "demo".to_string(),
            version: Some("1.0".to_string()),
            filename: filename.to_string(),
            sha256: "a".repeat(64),
        })
    }

    fn member_file(outer: &str, member: &str, body: &[u8], kind: ArtifactFileKind) -> ArtifactFile {
        ArtifactFile {
            location: SubjectLocation::member(outer, member),
            size: body.len() as u64,
            sha256: sha256_hex(body),
            kind,
        }
    }

    fn dist(name: &str, dist_info: &Path) -> DistributionIdentity {
        DistributionIdentity {
            ecosystem: Ecosystem::PyPI,
            name: name.to_string(),
            version: Some("1.0".to_string()),
            dist_info_path: SubjectLocation::installed(dist_info.to_path_buf()),
        }
    }

    // ---- wheel RECORD: STRICT -------------------------------------------------

    #[test]
    fn wheel_record_clean_passes() {
        let outer = "demo-1.0-py3-none-any.whl";
        let init_body = b"print('hi')\n";
        let mut inspection = ArtifactInspection::new(wheel_subject(outer));
        inspection.files.push(member_file(
            outer,
            "demo/__init__.py",
            init_body,
            ArtifactFileKind::PythonSource,
        ));
        // RECORD member itself (exempt from listing itself).
        inspection.files.push(member_file(
            outer,
            "demo-1.0.dist-info/RECORD",
            b"",
            ArtifactFileKind::DistInfoMetadata,
        ));

        let record = vec![
            RecordEntry {
                path: "demo/__init__.py".to_string(),
                hash: Some(RecordHash {
                    algorithm: "sha256".to_string(),
                    digest: sha256_bytes(init_body),
                }),
                size: Some(init_body.len() as u64),
            },
            RecordEntry {
                path: "demo-1.0.dist-info/RECORD".to_string(),
                hash: None,
                size: None,
            },
        ];

        let result = verify_wheel_record(&inspection, Some(&record));
        assert!(result.is_clean(), "violations: {:?}", result.violations);
    }

    #[test]
    fn wheel_record_unlisted_executable_member_fails() {
        // The plan's headline strictness case: an unlisted EXECUTABLE member
        // (a native .so) is a violation.
        let outer = "demo-1.0-cp311-cp311-linux_x86_64.whl";
        let so_body = b"\x7fELF native";
        let mut inspection = ArtifactInspection::new(wheel_subject(outer));
        inspection.files.push(member_file(
            outer,
            "demo/_speedups.abi3.so",
            so_body,
            ArtifactFileKind::NativeModule,
        ));
        // RECORD lists ONLY the dist-info RECORD, not the .so.
        let record = vec![RecordEntry {
            path: "demo-1.0.dist-info/RECORD".to_string(),
            hash: None,
            size: None,
        }];

        let result = verify_wheel_record(&inspection, Some(&record));
        assert!(!result.is_clean());
        assert!(result.violations.iter().any(|v| matches!(
            v,
            WheelRecordViolation::UnlistedMember {
                executable: true,
                ..
            }
        )));
        // And a granular UnlistedInstalledFile signal at High confidence.
        assert!(result
            .signals
            .iter()
            .any(|s| s.kind == ArtifactSignalKind::UnlistedInstalledFile
                && s.confidence == EdgeConfidence::High));
    }

    #[test]
    fn wheel_record_hash_mismatch_fails() {
        let outer = "demo-1.0-py3-none-any.whl";
        let actual_body = b"real bytes";
        let mut inspection = ArtifactInspection::new(wheel_subject(outer));
        inspection.files.push(member_file(
            outer,
            "demo/mod.py",
            actual_body,
            ArtifactFileKind::PythonSource,
        ));
        // RECORD records a DIFFERENT hash than the member's actual bytes.
        let record = vec![RecordEntry {
            path: "demo/mod.py".to_string(),
            hash: Some(RecordHash {
                algorithm: "sha256".to_string(),
                digest: sha256_bytes(b"tampered-different"),
            }),
            size: Some(actual_body.len() as u64),
        }];
        let result = verify_wheel_record(&inspection, Some(&record));
        assert!(result
            .violations
            .iter()
            .any(|v| matches!(v, WheelRecordViolation::HashMismatch { .. })));
        assert!(result
            .signals
            .iter()
            .any(|s| s.kind == ArtifactSignalKind::RecordHashMismatch));
    }

    #[test]
    fn wheel_record_missing_record_fails() {
        let outer = "demo-1.0-py3-none-any.whl";
        let inspection = ArtifactInspection::new(wheel_subject(outer));
        let result = verify_wheel_record(&inspection, None);
        assert_eq!(result.violations, vec![WheelRecordViolation::MissingRecord]);
    }

    #[test]
    fn wheel_record_weak_hash_fails() {
        let outer = "demo-1.0-py3-none-any.whl";
        let body = b"x";
        let mut inspection = ArtifactInspection::new(wheel_subject(outer));
        inspection.files.push(member_file(
            outer,
            "demo/mod.py",
            body,
            ArtifactFileKind::PythonSource,
        ));
        // md5 is weak: a strict wheel RECORD requires sha256+.
        let record = vec![RecordEntry {
            path: "demo/mod.py".to_string(),
            hash: Some(RecordHash {
                algorithm: "md5".to_string(),
                digest: vec![0u8; 16],
            }),
            size: Some(1),
        }];
        let result = verify_wheel_record(&inspection, Some(&record));
        assert!(result
            .violations
            .iter()
            .any(|v| matches!(v, WheelRecordViolation::WeakOrMissingHash { .. })));
    }

    #[test]
    fn wheel_record_sha512_fabricated_hash_is_rejected() {
        // A RECORD row whose hash is a STRONG-but-non-sha256 algorithm (sha512)
        // cannot be recompared by this tool (A4 only produced sha256), so an
        // attacker could fabricate the digest. Strict verification must treat it
        // as a violation, never accept it by silence.
        let outer = "demo-1.0-py3-none-any.whl";
        let body = b"honest bytes";
        let mut inspection = ArtifactInspection::new(wheel_subject(outer));
        inspection.files.push(member_file(
            outer,
            "demo/mod.py",
            body,
            ArtifactFileKind::PythonSource,
        ));
        // A 64-byte (sha512-length, so `is_strong()`) but entirely fabricated
        // digest, labeled sha512. The real bytes are never hashed with sha512.
        let record = vec![RecordEntry {
            path: "demo/mod.py".to_string(),
            hash: Some(RecordHash {
                algorithm: "sha512".to_string(),
                digest: vec![0xabu8; 64],
            }),
            size: Some(body.len() as u64),
        }];
        let result = verify_wheel_record(&inspection, Some(&record));
        assert!(
            !result.is_clean(),
            "a fabricated sha512 hash must not clear strict verification"
        );
        assert!(
            result
                .violations
                .iter()
                .any(|v| matches!(v, WheelRecordViolation::WeakOrMissingHash { .. })),
            "an unverifiable strong-non-sha256 hash is a violation: {:?}",
            result.violations
        );
    }

    // ---- installed RECORD: LAX ------------------------------------------------

    /// Build a minimal installed distribution under a fresh site-packages dir,
    /// returning (site_packages, dist_info_dir).
    fn make_installed_dist(
        site: &Path,
        dist_name: &str,
        version: &str,
        files: &[(&str, &[u8])],
        record_rows: &[TestRecordRow],
        extra_dist_info: &[(&str, &[u8])],
    ) -> PathBuf {
        let dist_info = site.join(format!("{dist_name}-{version}.dist-info"));
        fs::create_dir_all(&dist_info).unwrap();
        for (rel, body) in files {
            let p = site.join(rel);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(p, body).unwrap();
        }
        for (name, body) in extra_dist_info {
            fs::write(dist_info.join(name), body).unwrap();
        }
        // Build the RECORD CSV.
        let mut record = String::new();
        for (path, digest, size) in record_rows {
            let hash_col = match digest {
                Some(d) => format!("sha256={}", b64(d)),
                None => String::new(),
            };
            let size_col = match size {
                Some(s) => s.to_string(),
                None => String::new(),
            };
            record.push_str(&format!("{path},{hash_col},{size_col}\n"));
        }
        fs::write(dist_info.join("RECORD"), record).unwrap();
        dist_info
    }

    #[test]
    fn installed_record_missing_is_coverage_gap_not_violation() {
        let tmp = tempdir().unwrap();
        let site = tmp.path();
        let dist_info = site.join("demo-1.0.dist-info");
        fs::create_dir_all(&dist_info).unwrap();
        // No RECORD file written.
        let layout = EnvironmentLayout::for_site_packages(site);
        let d = dist("demo", &dist_info);
        let result = verify_installed_record(&dist_info, &layout, &d, false);
        assert!(result.record_missing);
        assert!(
            result.signals.is_empty(),
            "missing RECORD is not a violation"
        );
    }

    #[test]
    fn installed_record_empty_hash_is_unverifiable() {
        let tmp = tempdir().unwrap();
        let site = tmp.path();
        let body = b"data\n";
        let dist_info = make_installed_dist(
            site,
            "demo",
            "1.0",
            &[("demo/data.bin", body)],
            // empty hash AND empty size -> Unverifiable, NOT mismatch.
            &[("demo/data.bin", None, None)],
            &[],
        );
        let layout = EnvironmentLayout::for_site_packages(site);
        let d = dist("demo", &dist_info);
        let result = verify_installed_record(&dist_info, &layout, &d, false);
        let entry = result
            .entries
            .iter()
            .find(|e| e.recorded_path == "demo/data.bin")
            .unwrap();
        assert!(matches!(
            entry.verification,
            FileVerification::Unverifiable { .. }
        ));
        // No mismatch signal from an unverifiable entry.
        assert!(result
            .signals
            .iter()
            .all(|s| s.kind != ArtifactSignalKind::RecordHashMismatch));
    }

    #[test]
    fn installed_record_verified_when_hash_matches() {
        let tmp = tempdir().unwrap();
        let site = tmp.path();
        let body = b"verified bytes\n";
        let dist_info = make_installed_dist(
            site,
            "demo",
            "1.0",
            &[("demo/mod.py", body)],
            &[(
                "demo/mod.py",
                Some(sha256_bytes(body)),
                Some(body.len() as u64),
            )],
            &[],
        );
        let layout = EnvironmentLayout::for_site_packages(site);
        let d = dist("demo", &dist_info);
        let result = verify_installed_record(&dist_info, &layout, &d, false);
        let entry = result
            .entries
            .iter()
            .find(|e| e.recorded_path == "demo/mod.py")
            .unwrap();
        assert_eq!(entry.verification, FileVerification::Verified);
    }

    #[test]
    fn installed_record_tampered_file_mismatches() {
        let tmp = tempdir().unwrap();
        let site = tmp.path();
        // Write the file with DIFFERENT bytes than the recorded hash.
        let dist_info = make_installed_dist(
            site,
            "demo",
            "1.0",
            &[("demo/mod.py", b"TAMPERED on disk\n")],
            &[(
                "demo/mod.py",
                Some(sha256_bytes(b"original honest bytes\n")),
                Some(20),
            )],
            &[],
        );
        let layout = EnvironmentLayout::for_site_packages(site);
        let d = dist("demo", &dist_info);
        let result = verify_installed_record(&dist_info, &layout, &d, false);
        let entry = result
            .entries
            .iter()
            .find(|e| e.recorded_path == "demo/mod.py")
            .unwrap();
        assert!(matches!(
            entry.verification,
            FileVerification::Mismatch { .. }
        ));
        assert!(result
            .signals
            .iter()
            .any(|s| s.kind == ArtifactSignalKind::RecordHashMismatch));
    }

    #[test]
    fn installed_record_backslash_path_resolves() {
        let tmp = tempdir().unwrap();
        let site = tmp.path();
        let body = b"win path\n";
        // The file is on disk under demo/sub/mod.py, but RECORD lists it with
        // backslashes (a Windows-written RECORD).
        let dist_info = make_installed_dist(
            site,
            "demo",
            "1.0",
            &[("demo/sub/mod.py", body)],
            &[(
                "demo\\sub\\mod.py",
                Some(sha256_bytes(body)),
                Some(body.len() as u64),
            )],
            &[],
        );
        let layout = EnvironmentLayout::for_site_packages(site);
        let d = dist("demo", &dist_info);
        let result = verify_installed_record(&dist_info, &layout, &d, false);
        let entry = result
            .entries
            .iter()
            .find(|e| e.recorded_path == "demo\\sub\\mod.py")
            .unwrap();
        assert_eq!(
            entry.verification,
            FileVerification::Verified,
            "a backslash-separated RECORD path must resolve to the on-disk file"
        );
    }

    #[test]
    fn installed_record_absolute_in_environment_path_resolves() {
        let tmp = tempdir().unwrap();
        let site = tmp.path();
        let body = b"abs path\n";
        // RECORD lists the file by ABSOLUTE path inside the environment.
        let abs = site.join("demo/abs.py");
        fs::create_dir_all(abs.parent().unwrap()).unwrap();
        fs::write(&abs, body).unwrap();
        let dist_info = site.join("demo-1.0.dist-info");
        fs::create_dir_all(&dist_info).unwrap();
        let record = format!(
            "{},sha256={},{}\n",
            abs.display(),
            b64(&sha256_bytes(body)),
            body.len()
        );
        fs::write(dist_info.join("RECORD"), record).unwrap();
        let layout = EnvironmentLayout::for_site_packages(site);
        let d = dist("demo", &dist_info);
        let result = verify_installed_record(&dist_info, &layout, &d, false);
        let entry = &result.entries[0];
        assert_eq!(entry.verification, FileVerification::Verified);
    }

    #[test]
    fn installed_record_absolute_out_of_environment_is_refused() {
        let tmp = tempdir().unwrap();
        let site = tmp.path().join("site");
        fs::create_dir_all(&site).unwrap();
        // A second dir OUTSIDE the environment.
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let evil = outside.join("evil.py");
        fs::write(&evil, b"evil\n").unwrap();
        let dist_info = site.join("demo-1.0.dist-info");
        fs::create_dir_all(&dist_info).unwrap();
        let record = format!("{},sha256={},5\n", evil.display(), b64(&sha256_bytes(b"x")));
        fs::write(dist_info.join("RECORD"), record).unwrap();
        let layout = EnvironmentLayout::for_site_packages(&site);
        let d = dist("demo", &dist_info);
        let result = verify_installed_record(&dist_info, &layout, &d, false);
        assert_eq!(
            result.entries[0].verification,
            FileVerification::OutOfEnvironment
        );
    }

    #[test]
    fn verify_one_file_checks_valid_hash_when_size_empty() {
        // A row with a VALID sha256 hash but an EMPTY size column must still be
        // hash-verified (previously the empty size short-circuited to
        // Unverifiable before the hash was ever compared).
        let tmp = tempdir().unwrap();
        let site = tmp.path();
        let body = b"hashed but sizeless\n";
        let dist_info = make_installed_dist(
            site,
            "demo",
            "1.0",
            &[("demo/mod.py", body)],
            // Valid hash, empty size.
            &[("demo/mod.py", Some(sha256_bytes(body)), None)],
            &[],
        );
        let layout = EnvironmentLayout::for_site_packages(site);
        let d = dist("demo", &dist_info);
        let result = verify_installed_record(&dist_info, &layout, &d, false);
        let entry = result
            .entries
            .iter()
            .find(|e| e.recorded_path == "demo/mod.py")
            .unwrap();
        assert_eq!(
            entry.verification,
            FileVerification::Verified,
            "a valid hash must be checked even when the size column is empty"
        );

        // And the same row over TAMPERED bytes must be a mismatch, not silently
        // unverifiable.
        let tmp2 = tempdir().unwrap();
        let site2 = tmp2.path();
        let dist_info2 = make_installed_dist(
            site2,
            "demo",
            "1.0",
            &[("demo/mod.py", b"TAMPERED\n")],
            &[("demo/mod.py", Some(sha256_bytes(body)), None)],
            &[],
        );
        let d2 = dist("demo", &dist_info2);
        let layout2 = EnvironmentLayout::for_site_packages(site2);
        let result2 = verify_installed_record(&dist_info2, &layout2, &d2, false);
        let entry2 = result2
            .entries
            .iter()
            .find(|e| e.recorded_path == "demo/mod.py")
            .unwrap();
        assert!(
            matches!(entry2.verification, FileVerification::Mismatch { .. }),
            "empty size must not suppress a hash mismatch: {:?}",
            entry2.verification
        );
    }

    #[cfg(unix)]
    #[test]
    fn record_path_via_in_tree_symlink_is_out_of_environment() {
        use std::os::unix::fs::symlink;
        // Plant an in-tree symlink `site/legitdir -> /etc`. A RECORD row
        // `legitdir/passwd` lexically starts inside the site root, but its REAL
        // location is /etc/passwd, OUT of the environment. The verifier must treat
        // it as OutOfEnvironment and never read /etc/passwd.
        let tmp = tempdir().unwrap();
        let site = tmp.path();
        let dist_info = site.join("demo-1.0.dist-info");
        fs::create_dir_all(&dist_info).unwrap();
        symlink("/etc", site.join("legitdir")).unwrap();
        // A real (in-environment) control file to prove honest rows still verify.
        let body = b"in env\n";
        let good = site.join("demo/ok.py");
        fs::create_dir_all(good.parent().unwrap()).unwrap();
        fs::write(&good, body).unwrap();
        let record = format!(
            "legitdir/passwd,sha256={},10\ndemo/ok.py,sha256={},{}\n",
            b64(&sha256_bytes(b"whatever")),
            b64(&sha256_bytes(body)),
            body.len()
        );
        fs::write(dist_info.join("RECORD"), record).unwrap();
        let layout = EnvironmentLayout::for_site_packages(site);
        let d = dist("demo", &dist_info);
        let result = verify_installed_record(&dist_info, &layout, &d, false);

        let escaped = result
            .entries
            .iter()
            .find(|e| e.recorded_path == "legitdir/passwd")
            .unwrap();
        assert_eq!(
            escaped.verification,
            FileVerification::OutOfEnvironment,
            "an in-tree symlink whose target escapes the environment must not be followed"
        );
        // The escaped row must NOT have been read: no mismatch/missing signal, and
        // it is certainly not Verified (it would never match /etc/passwd anyway).
        assert!(!matches!(escaped.verification, FileVerification::Verified));
        // The honest in-environment row still verifies (the no-lexical-fast-path
        // change did not break legitimate resolution).
        let honest = result
            .entries
            .iter()
            .find(|e| e.recorded_path == "demo/ok.py")
            .unwrap();
        assert_eq!(honest.verification, FileVerification::Verified);
    }

    #[cfg(unix)]
    #[test]
    fn scheme_escape_only_reads_scheme_roots() {
        // With allow_scheme_escape, an absolute RECORD path is verified ONLY when
        // it canonicalizes under a declared scheme root. A path outside every
        // scheme root stays OutOfEnvironment despite the flag.
        let tmp = tempdir().unwrap();
        let site = tmp.path().join("site");
        let scripts = tmp.path().join("scripts");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&site).unwrap();
        fs::create_dir_all(&scripts).unwrap();
        fs::create_dir_all(&outside).unwrap();

        // A legitimate scheme file (inside `scripts`) and an out-of-scheme file.
        let in_scheme_body = b"#!/bin/sh\necho hi\n";
        let in_scheme = scripts.join("demo-cli");
        fs::write(&in_scheme, in_scheme_body).unwrap();
        let evil = outside.join("evil.py");
        fs::write(&evil, b"evil\n").unwrap();

        let dist_info = site.join("demo-1.0.dist-info");
        fs::create_dir_all(&dist_info).unwrap();
        let record = format!(
            "{},sha256={},{}\n{},sha256={},5\n",
            in_scheme.display(),
            b64(&sha256_bytes(in_scheme_body)),
            in_scheme_body.len(),
            evil.display(),
            b64(&sha256_bytes(b"x")),
        );
        fs::write(dist_info.join("RECORD"), record).unwrap();

        let layout = EnvironmentLayout {
            site_packages: site.clone(),
            scheme_roots: vec![scripts.clone()],
        };
        let d = dist("demo", &dist_info);
        let result = verify_installed_record(&dist_info, &layout, &d, true);

        // The out-of-scheme absolute path stays refused even with the flag set.
        let evil_entry = result
            .entries
            .iter()
            .find(|e| e.recorded_path == evil.display().to_string())
            .unwrap();
        assert_eq!(
            evil_entry.verification,
            FileVerification::OutOfEnvironment,
            "scheme escape must not license reading a path outside every scheme root"
        );
        // The legitimate scheme path IS verified (the flag still works for real
        // scheme directories).
        let scheme_entry = result
            .entries
            .iter()
            .find(|e| e.recorded_path == in_scheme.display().to_string())
            .unwrap();
        assert_eq!(scheme_entry.verification, FileVerification::Verified);
    }

    // ---- ownership index ------------------------------------------------------

    #[test]
    fn ownership_index_detects_duplicate_owned_path() {
        let tmp = tempdir().unwrap();
        let site = tmp.path();
        // Two distributions both list the SAME module path.
        let di_a = make_installed_dist(
            site,
            "alpha",
            "1.0",
            &[("shared/mod.py", b"a\n")],
            &[("shared/mod.py", None, None)],
            &[],
        );
        let di_b = make_installed_dist(
            site,
            "beta",
            "2.0",
            &[],
            &[("shared/mod.py", None, None)],
            &[],
        );
        let mut index = OwnershipIndex::new();
        index_distribution_ownership(&di_a, &dist("alpha", &di_a), &mut index);
        index_distribution_ownership(&di_b, &dist("beta", &di_b), &mut index);
        let dups: Vec<_> = index.duplicates().collect();
        assert_eq!(dups.len(), 1);
        assert_eq!(dups[0].0.as_str(), "shared/mod.py");
        assert_eq!(dups[0].1.len(), 2);
    }

    #[test]
    fn ownership_index_resolves_cross_distribution_reference() {
        // Dist A's payload reference (a path) is owned by Dist B.
        let tmp = tempdir().unwrap();
        let site = tmp.path();
        let di_b = make_installed_dist(
            site,
            "beta",
            "2.0",
            &[("beta/payload.js", b"//payload\n")],
            &[("beta/payload.js", None, None)],
            &[],
        );
        let mut index = OwnershipIndex::new();
        index_distribution_ownership(&di_b, &dist("beta", &di_b), &mut index);
        // A reference from dist A naming beta/payload.js resolves to beta.
        let key = NormalizedInstalledPath::new("beta/payload.js");
        let owners = index.owners(&key);
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].name, "beta");
    }

    #[test]
    fn normalized_path_unifies_separators() {
        assert_eq!(
            NormalizedInstalledPath::new("demo\\sub\\mod.py").as_str(),
            "demo/sub/mod.py"
        );
        assert_eq!(
            NormalizedInstalledPath::new("./demo//mod.py").as_str(),
            "demo/mod.py"
        );
    }
}
