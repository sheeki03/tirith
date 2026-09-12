//! Bounded, read-only npm tarball inspection. No extraction, installation,
//! network request or package code execution occurs here.
//!
//! The supported transport is one gzip member containing POSIX ustar, including
//! local PAX path/size extensions produced by node-tar. PAX metadata which cannot
//! change file interpretation is accepted; sparse files, links, special files,
//! GNU extensions, unknown PAX keys and ambiguous portable paths are refused.
//! Limits cover the complete compressed stream, decoded stream, headers (also
//! extension headers), member sizes, path storage and analyzer work. A refused
//! archive never enters a content analyzer. "Archive complete" means that every
//! supported archive member was read and hashed, not that its code is safe.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};

use flate2::bufread::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

#[path = "npm_signals.rs"]
mod signals;
pub use signals::{NpmCapability, NpmMetadata, NpmSignal, NpmSignalKind, NpmSignalLevel};

#[cfg(test)]
#[path = "npm_archive_tests.rs"]
mod tests;

pub const NPM_INSPECTION_SCHEMA_VERSION: u32 = 1;
/// Changes when the interpretation of an unchanged artifact can change.
pub const NPM_ANALYZER_VERSION: &str = "npm-static-1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NpmLimits {
    pub compressed_bytes: usize,
    pub decompressed_bytes: usize,
    pub member_bytes: usize,
    pub headers: usize,
    pub path_bytes: usize,
    pub path_depth: usize,
    pub total_path_bytes: usize,
    pub pax_bytes: usize,
    pub compression_ratio: usize,
    pub metadata_bytes: usize,
    pub code_member_bytes: usize,
    pub total_code_bytes: usize,
    pub code_files: usize,
    pub native_files: usize,
    pub signals: usize,
}

impl Default for NpmLimits {
    fn default() -> Self {
        Self {
            compressed_bytes: 32 * 1024 * 1024,
            decompressed_bytes: 128 * 1024 * 1024,
            member_bytes: 32 * 1024 * 1024,
            headers: 20_000,
            path_bytes: 4096,
            path_depth: 64,
            total_path_bytes: 4 * 1024 * 1024,
            pax_bytes: 64 * 1024,
            compression_ratio: 1000,
            metadata_bytes: 512 * 1024,
            code_member_bytes: 2 * 1024 * 1024,
            total_code_bytes: 32 * 1024 * 1024,
            code_files: 2000,
            native_files: 16,
            signals: 256,
        }
    }
}

impl NpmLimits {
    /// Caller configuration can tighten the reader's fixed ceilings, never turn
    /// attacker-controlled sizes into unbounded allocations or parser work.
    fn bounded(&self) -> Self {
        let ceiling = Self::default();
        macro_rules! cap {
            ($($field:ident),+ $(,)?) => { Self { $($field: self.$field.min(ceiling.$field)),+ } };
        }
        cap!(
            compressed_bytes,
            decompressed_bytes,
            member_bytes,
            headers,
            path_bytes,
            path_depth,
            total_path_bytes,
            pax_bytes,
            compression_ratio,
            metadata_bytes,
            code_member_bytes,
            total_code_bytes,
            code_files,
            native_files,
            signals
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmArtifactIdentity {
    pub filename: String,
    /// None only when the whole input could not be read within the input cap.
    /// A prefix hash is never substituted for an exact artifact identity.
    pub sha256: Option<String>,
    pub compressed_bytes: Option<u64>,
    pub name: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmArchiveState {
    Accepted,
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmIssueKind {
    InputReadFailed,
    CompressedLimit,
    DecompressedLimit,
    CompressionRatioLimit,
    GzipCorrupt,
    GzipTrailingData,
    TarCorrupt,
    UnsupportedTarFormat,
    UnsupportedExtension,
    InvalidPax,
    HeaderLimit,
    MemberLimit,
    PathLimit,
    UnsafePath,
    PathCollision,
    LinkMember,
    SpecialMember,
    MissingMetadata,
    InvalidMetadata,
    ContradictoryIdentity,
    MetadataLimit,
    CodeLimit,
    SignalLimit,
    UnsupportedCode,
    DynamicCode,
    NestedArchive,
    NativeIncomplete,
    UnresolvedLifecycle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmIssue {
    pub kind: NpmIssueKind,
    pub member: Option<String>,
    /// Controlled text; no OS error, source body or credential is interpolated.
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmCoverage {
    /// Fixed description carried with the result so "complete" cannot be
    /// mistaken for proof of arbitrary program behavior or installation safety.
    pub analysis_scope: String,
    pub archive_complete: bool,
    pub metadata_complete: bool,
    /// All code candidates were covered by the documented static analyzers.
    /// This is never a claim to resolve arbitrary JavaScript behavior.
    pub static_analysis_complete: bool,
    pub inspected_code_files: usize,
    pub inspected_code_bytes: u64,
    pub issues: Vec<NpmIssue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmFileKind {
    Metadata,
    JavaScript,
    ShellScript,
    Native,
    WebAssembly,
    NestedArchive,
    OtherCode,
    Resource,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmFile {
    /// Normalized portable member path, always rooted at package/.
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub executable: bool,
    pub kind: NpmFileKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmInspection {
    pub schema_version: u32,
    pub analyzer_version: String,
    pub artifact: NpmArtifactIdentity,
    pub archive_state: NpmArchiveState,
    pub limits: NpmLimits,
    pub coverage: NpmCoverage,
    pub files: Vec<NpmFile>,
    pub metadata: Option<NpmMetadata>,
    pub signals: Vec<NpmSignal>,
    /// Local artifact inspection has no registry provenance authority. Presence
    /// or absence of a provenance-looking file must not become a safety verdict.
    pub provenance_verification: String,
}

impl NpmInspection {
    pub fn check_schema(&self) -> bool {
        self.schema_version == NPM_INSPECTION_SCHEMA_VERSION
    }

    pub(crate) fn issue(&mut self, kind: NpmIssueKind, member: Option<&str>, detail: &str) {
        // At most one issue per kind/member. The output is bounded independently
        // of the number of archive members, including adversarial empty files.
        if self.coverage.issues.len() < 256
            && !self
                .coverage
                .issues
                .iter()
                .any(|issue| issue.kind == kind && issue.member.as_deref() == member)
        {
            self.coverage.issues.push(NpmIssue {
                kind,
                member: member.map(str::to_owned),
                detail: detail.to_owned(),
            });
        }
        self.coverage.static_analysis_complete = false;
    }

    fn refuse(&mut self, issue: NpmIssue) {
        self.archive_state = NpmArchiveState::Refused;
        self.coverage.archive_complete = false;
        self.coverage.static_analysis_complete = false;
        self.coverage.issues.push(issue);
    }
}

/// Inspect the exact compressed byte stream supplied by the caller. A local file
/// caller should open one regular, no-follow handle and pass that same handle;
/// it must not compute an identity with a second path read. Reads at most the
/// compressed cap plus one byte, even for a non-terminating reader.
pub fn read_npm_tarball<R: Read>(reader: R, filename: &str, limits: &NpmLimits) -> NpmInspection {
    read_npm_tarball_impl(reader, filename, limits, false).0
}

/// Private install-preparation seam. Complete root metadata is returned only
/// alongside the inspection derived from the same bounded, validated stream.
pub(crate) fn read_npm_tarball_with_manifest<R: Read>(
    reader: R,
    filename: &str,
    limits: &NpmLimits,
) -> (NpmInspection, Option<Vec<u8>>) {
    read_npm_tarball_impl(reader, filename, limits, true)
}

fn read_npm_tarball_impl<R: Read>(
    mut reader: R,
    filename: &str,
    limits: &NpmLimits,
    capture_manifest: bool,
) -> (NpmInspection, Option<Vec<u8>>) {
    let limits = limits.bounded();
    let mut inspection = NpmInspection {
        schema_version: NPM_INSPECTION_SCHEMA_VERSION,
        analyzer_version: NPM_ANALYZER_VERSION.to_owned(),
        artifact: NpmArtifactIdentity {
            filename: bounded_text(filename, 4096),
            sha256: None,
            compressed_bytes: None,
            name: None,
            version: None,
        },
        archive_state: NpmArchiveState::Refused,
        limits: limits.clone(),
        coverage: NpmCoverage {
            analysis_scope: "bounded_static_patterns_and_native_triage; behavior_not_proven"
                .to_owned(),
            archive_complete: false,
            metadata_complete: false,
            static_analysis_complete: false,
            inspected_code_files: 0,
            inspected_code_bytes: 0,
            issues: Vec::new(),
        },
        files: Vec::new(),
        metadata: None,
        signals: Vec::new(),
        provenance_verification: "not_performed_offline".to_owned(),
    };
    let compressed = match read_capped(&mut reader, limits.compressed_bytes) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            inspection.refuse(problem(
                NpmIssueKind::CompressedLimit,
                None,
                "Compressed input exceeds the configured limit; exact identity is unavailable.",
            ));
            return (inspection, None);
        }
        Err(_) => {
            inspection.refuse(problem(
                NpmIssueKind::InputReadFailed,
                None,
                "The complete input could not be read; exact identity is unavailable.",
            ));
            return (inspection, None);
        }
    };
    inspection.artifact.sha256 = Some(hex::encode(Sha256::digest(&compressed)));
    inspection.artifact.compressed_bytes = Some(compressed.len() as u64);
    let ratio_cap = compressed.len().saturating_mul(limits.compression_ratio);
    let decoded_cap = limits.decompressed_bytes.min(ratio_cap);
    let mut decoder = GzDecoder::new(compressed.as_slice());
    let decoded = match read_capped(&mut decoder, decoded_cap) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            let (kind, message) = if ratio_cap < limits.decompressed_bytes {
                (
                    NpmIssueKind::CompressionRatioLimit,
                    "Gzip expansion exceeds the configured ratio limit.",
                )
            } else {
                (
                    NpmIssueKind::DecompressedLimit,
                    "Decompressed bytes exceed the configured limit.",
                )
            };
            inspection.refuse(problem(kind, None, message));
            return (inspection, None);
        }
        Err(_) => {
            inspection.refuse(problem(
                NpmIssueKind::GzipCorrupt,
                None,
                "Invalid or truncated gzip stream, including its checksum trailer.",
            ));
            return (inspection, None);
        }
    };
    if !decoder.into_inner().is_empty() {
        inspection.refuse(problem(
            NpmIssueKind::GzipTrailingData,
            None,
            "Concatenated gzip members and trailing compressed data are unsupported.",
        ));
        return (inspection, None);
    }
    let members = match parse_tar(&decoded, &limits) {
        Ok(members) => members,
        Err(issue) => {
            inspection.refuse(issue);
            return (inspection, None);
        }
    };
    inspection.archive_state = NpmArchiveState::Accepted;
    inspection.coverage.archive_complete = true;
    inspection.coverage.static_analysis_complete = true;
    inspection.files = members
        .iter()
        .map(|member| NpmFile {
            path: member.path.clone(),
            size: member.bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(member.bytes)),
            executable: member.executable,
            kind: member.kind,
        })
        .collect();
    signals::inspect_members(&members, &mut inspection);
    // This private capture comes from the exact already-validated member walk.
    // It is withheld whenever root metadata is absent, invalid or over budget.
    // Public inspection reports never carry these raw manifest bytes.
    let manifest = (capture_manifest && inspection.coverage.metadata_complete).then(|| {
        members
            .iter()
            .find(|member| member.path == "package/package.json")
            .expect("complete metadata requires the unique root member")
            .bytes
            .to_vec()
    });
    (inspection, manifest)
}

fn read_capped(reader: &mut impl Read, cap: usize) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    // Hard ceilings above make cap+1 and its u64 conversion safe on all targets.
    reader.take((cap + 1) as u64).read_to_end(&mut bytes)?;
    Ok((bytes.len() <= cap).then_some(bytes))
}

fn problem(kind: NpmIssueKind, member: Option<&str>, detail: &str) -> NpmIssue {
    NpmIssue {
        kind,
        member: member.map(|s| bounded_text(s, 4096)),
        detail: detail.to_owned(),
    }
}

pub(crate) fn bounded_text(text: &str, cap: usize) -> String {
    // DLP runs at the later output boundary. Keeping an arbitrary prefix here
    // could cut a custom-pattern secret in half so that boundary cannot match
    // it. An oversized unredacted value is withheld in its entirety.
    if text.len() > cap {
        "[withheld: text exceeds display limit]".to_owned()
    } else {
        text.to_owned()
    }
}

pub(crate) struct Member<'a> {
    pub path: String,
    pub bytes: &'a [u8],
    pub executable: bool,
    pub kind: NpmFileKind,
}

#[derive(Default)]
struct Pax {
    path: Option<String>,
    size: Option<usize>,
}

fn parse_tar<'a>(bytes: &'a [u8], limits: &NpmLimits) -> Result<Vec<Member<'a>>, NpmIssue> {
    let corrupt = || {
        problem(
            NpmIssueKind::TarCorrupt,
            None,
            "Invalid, truncated or ambiguous tar structure.",
        )
    };
    if bytes.len() < 1024 || bytes.len() % 512 != 0 {
        return Err(corrupt());
    }
    let mut offset = 0usize;
    let mut headers = 0usize;
    let mut path_storage = 0usize;
    let mut members = Vec::new();
    let mut named: BTreeMap<String, bool> = BTreeMap::new();
    let mut pending: Option<Pax> = None;
    while offset < bytes.len() {
        let header = bytes.get(offset..offset + 512).ok_or_else(corrupt)?;
        offset += 512;
        if header.iter().all(|b| *b == 0) {
            if pending.is_some()
                || bytes.len() - offset < 512
                || bytes[offset..].iter().any(|b| *b != 0)
            {
                return Err(corrupt());
            }
            return Ok(members);
        }
        headers += 1;
        if headers > limits.headers {
            return Err(problem(
                NpmIssueKind::HeaderLimit,
                None,
                "Tar header count exceeds the configured limit.",
            ));
        }
        let checksum = octal(&header[148..156]).ok_or_else(corrupt)?;
        let actual: usize = header
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    usize::from(*b)
                }
            })
            .sum();
        if checksum != actual {
            return Err(corrupt());
        }
        if &header[257..263] != b"ustar\0" || &header[263..265] != b"00" {
            return Err(problem(
                NpmIssueKind::UnsupportedTarFormat,
                None,
                "Only POSIX ustar and supported PAX extensions are inspected.",
            ));
        }
        let name = text_field(&header[..100]).ok_or_else(corrupt)?;
        let prefix = text_field(&header[345..500]).ok_or_else(corrupt)?;
        let raw_path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        let mode = octal(&header[100..108]).ok_or_else(corrupt)?;
        let header_size = octal(&header[124..136]).ok_or_else(corrupt)?;
        let entry_type = header[156];
        let extension = matches!(entry_type, b'x' | b'g');
        let pax = if extension {
            if pending.is_some() {
                return Err(problem(
                    NpmIssueKind::InvalidPax,
                    None,
                    "Stacked PAX extensions are ambiguous and unsupported.",
                ));
            }
            Pax::default()
        } else {
            pending.take().unwrap_or_default()
        };
        let size = if extension {
            header_size
        } else {
            pax.size.unwrap_or(header_size)
        };
        let cap = if extension {
            limits.pax_bytes
        } else {
            limits.member_bytes
        };
        if size > cap {
            return Err(problem(
                NpmIssueKind::MemberLimit,
                None,
                "Tar member or extension size exceeds the configured limit.",
            ));
        }
        let end = offset.checked_add(size).ok_or_else(corrupt)?;
        let padded = size
            .checked_add(511)
            .map(|n| n / 512 * 512)
            .ok_or_else(corrupt)?;
        let next = offset.checked_add(padded).ok_or_else(corrupt)?;
        let body = bytes.get(offset..end).ok_or_else(corrupt)?;
        let padding = bytes.get(end..next).ok_or_else(corrupt)?;
        if padding.iter().any(|b| *b != 0) {
            return Err(corrupt());
        }
        offset = next;
        if extension {
            let parsed = parse_pax(body, entry_type == b'g', limits)?;
            if entry_type == b'x' {
                pending = Some(parsed);
            }
            continue;
        }
        let directory = entry_type == b'5';
        if mode & !0o777 != 0 {
            return Err(problem(
                NpmIssueKind::SpecialMember,
                Some(&raw_path),
                "Privileged or unsupported tar mode bits are not inspected.",
            ));
        }
        match entry_type {
            0 | b'0' | b'5' => {}
            b'1' | b'2' => {
                return Err(problem(
                    NpmIssueKind::LinkMember,
                    Some(&raw_path),
                    "Hard links and symbolic links are not inspected.",
                ))
            }
            b'3' | b'4' | b'6' => {
                return Err(problem(
                    NpmIssueKind::SpecialMember,
                    Some(&raw_path),
                    "Device nodes and FIFOs are not valid inspection members.",
                ))
            }
            _ => {
                return Err(problem(
                    NpmIssueKind::UnsupportedExtension,
                    Some(&raw_path),
                    "GNU, sparse and unknown tar entry types are unsupported.",
                ))
            }
        }
        if !text_field(&header[157..257])
            .ok_or_else(corrupt)?
            .is_empty()
            || (directory && size != 0)
        {
            return Err(corrupt());
        }
        let path = normalize_path(pax.path.as_deref().unwrap_or(&raw_path), directory, limits)?;
        path_storage = path_storage.checked_add(path.len()).ok_or_else(corrupt)?;
        if path_storage > limits.total_path_bytes {
            return Err(problem(
                NpmIssueKind::PathLimit,
                None,
                "Combined member path bytes exceed the configured limit.",
            ));
        }
        let key = collision_key(&path);
        let descendant_prefix = format!("{key}/");
        let has_descendant = named
            .range(descendant_prefix.clone()..)
            .next()
            .is_some_and(|(existing, _)| existing.starts_with(&descendant_prefix));
        if named.contains_key(&key) || (!directory && has_descendant) {
            return Err(problem(
                NpmIssueKind::PathCollision,
                Some(&path),
                "Duplicate, case/Unicode alias or file/directory collision.",
            ));
        }
        let mut parent = key.as_str();
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            if named.get(prefix) == Some(&false) {
                return Err(problem(
                    NpmIssueKind::PathCollision,
                    Some(&path),
                    "A file member is also used as a parent directory.",
                ));
            }
            parent = prefix;
        }
        named.insert(key, directory);
        let executable = mode & 0o111 != 0;
        let kind = classify(&path, body, directory, executable);
        members.push(Member {
            path,
            bytes: body,
            executable,
            kind,
        });
    }
    Err(corrupt()) // Two zero end blocks are required; EOF is not a terminator.
}

fn text_field(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    if bytes[end..].iter().any(|b| *b != 0) {
        return None;
    }
    std::str::from_utf8(&bytes[..end]).ok()
}

fn octal(bytes: &[u8]) -> Option<usize> {
    // Base-256 GNU numbers and signed/overflowing numeric encodings are refused.
    let field = std::str::from_utf8(bytes).ok()?.trim_matches(['\0', ' ']);
    if field.is_empty() {
        return Some(0);
    }
    if !field.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return None;
    }
    usize::from_str_radix(field, 8).ok()
}

fn parse_pax(bytes: &[u8], global: bool, limits: &NpmLimits) -> Result<Pax, NpmIssue> {
    let invalid = || {
        problem(
            NpmIssueKind::InvalidPax,
            None,
            "PAX records must have exact decimal byte lengths and unique supported keys.",
        )
    };
    let mut remaining = bytes;
    let mut seen = BTreeSet::new();
    let mut pax = Pax::default();
    while !remaining.is_empty() {
        if seen.len() >= 64 {
            return Err(invalid());
        }
        let space = remaining
            .iter()
            .position(|b| *b == b' ')
            .ok_or_else(invalid)?;
        if space == 0
            || space > 10
            || remaining[0] == b'0'
            || !remaining[..space].iter().all(u8::is_ascii_digit)
        {
            return Err(invalid());
        }
        let len: usize = std::str::from_utf8(&remaining[..space])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(invalid)?;
        let record = remaining.get(..len).ok_or_else(invalid)?;
        if len <= space + 3 || record.last() != Some(&b'\n') {
            return Err(invalid());
        }
        let payload = std::str::from_utf8(&record[space + 1..len - 1]).map_err(|_| invalid())?;
        let (key, value) = payload.split_once('=').ok_or_else(invalid)?;
        if !seen.insert(key.to_owned()) || value.contains(['\0', '\n', '\r']) {
            return Err(invalid());
        }
        match key {
            "path" if !global => {
                if value.len() > limits.path_bytes {
                    return Err(problem(
                        NpmIssueKind::PathLimit,
                        None,
                        "PAX path exceeds the configured limit.",
                    ));
                }
                pax.path = Some(value.to_owned());
            }
            "size" if !global => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid());
                }
                pax.size = Some(value.parse().map_err(|_| invalid())?);
            }
            "uid" | "gid" | "mtime" | "atime" | "ctime" | "uname" | "gname" | "comment"
            | "SCHILY.dev" | "SCHILY.ino" | "SCHILY.nlink" => {}
            "charset" | "hdrcharset" if matches!(value, "UTF-8" | "ISO-IR 10646 2000 UTF-8") => {}
            "linkpath" if value.is_empty() && !global => {}
            _ => {
                return Err(problem(
                    NpmIssueKind::UnsupportedExtension,
                    None,
                    "A PAX key changes unsupported archive semantics or its character encoding.",
                ))
            }
        }
        remaining = &remaining[len..];
    }
    Ok(pax)
}

fn normalize_path(raw: &str, directory: bool, limits: &NpmLimits) -> Result<String, NpmIssue> {
    let unsafe_path = || {
        problem(
            NpmIssueKind::UnsafePath,
            Some(raw),
            "Member path is not a portable relative path under package/.",
        )
    };
    if raw.len() > limits.path_bytes {
        return Err(problem(
            NpmIssueKind::PathLimit,
            None,
            "Member path exceeds the configured byte limit.",
        ));
    }
    let raw = raw.strip_prefix("./").unwrap_or(raw);
    let path = if directory {
        raw.strip_suffix('/').unwrap_or(raw)
    } else {
        raw
    };
    let components: Vec<_> = path.split('/').collect();
    if components.len() > limits.path_depth {
        return Err(problem(
            NpmIssueKind::PathLimit,
            None,
            "Member path exceeds the configured depth limit.",
        ));
    }
    if components.first() != Some(&"package")
        || (components.len() == 1 && !directory)
        || components
            .iter()
            .any(|component| unsafe_component(component))
    {
        return Err(unsafe_path());
    }
    Ok(path.to_owned())
}

fn unsafe_component(component: &str) -> bool {
    if component.is_empty()
        || matches!(component, "." | "..")
        || component.ends_with(['.', ' '])
        || component
            .chars()
            .any(|c| c.is_control() || matches!(c, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'))
    {
        return true;
    }
    let stem = component.split('.').next().unwrap_or(component);
    let upper = stem.to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) || upper
        .strip_prefix("COM")
        .or_else(|| upper.strip_prefix("LPT"))
        .is_some_and(|suffix| {
            matches!(
                suffix,
                "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    {
        return true;
    }
    // Reject potential DOS short-name aliases without predicting volume-specific
    // 8.3 generation. This matches the existing portable wheel reader contract.
    let mut parts = component.split('.');
    let stem = parts.next().unwrap_or_default();
    let ext = parts.next();
    parts.next().is_none()
        && stem.chars().count() <= 8
        && ext.is_none_or(|e| e.chars().count() <= 3)
        && stem.rsplit_once('~').is_some_and(|(prefix, digits)| {
            !prefix.is_empty() && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
        })
}

fn collision_key(path: &str) -> String {
    // Apply normalization on both sides of casing so combining characters
    // introduced by lowercasing cannot evade the collision map.
    path.nfc()
        .collect::<String>()
        .to_uppercase()
        .to_lowercase()
        .nfc()
        .collect()
}

fn classify(path: &str, bytes: &[u8], directory: bool, executable: bool) -> NpmFileKind {
    if directory {
        return NpmFileKind::Directory;
    }
    let lower = path.to_ascii_lowercase();
    if lower == "package/package.json" || lower.ends_with("/package.json") {
        return NpmFileKind::Metadata;
    }
    if bytes.starts_with(b"\0asm") || lower.ends_with(".wasm") {
        return NpmFileKind::WebAssembly;
    }
    if bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(b"MZ")
        || bytes.get(..4).is_some_and(|magic| {
            matches!(
                magic,
                [0xfe, 0xed, 0xfa, 0xce]
                    | [0xce, 0xfa, 0xed, 0xfe]
                    | [0xfe, 0xed, 0xfa, 0xcf]
                    | [0xcf, 0xfa, 0xed, 0xfe]
                    | [0xca, 0xfe, 0xba, 0xbe]
                    | [0xbe, 0xba, 0xfe, 0xca]
            )
        })
        || [".node", ".dll", ".so", ".dylib", ".exe"]
            .iter()
            .any(|ext| lower.ends_with(ext))
    {
        return NpmFileKind::Native;
    }
    if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"\x1f\x8b")
        || bytes.get(257..263) == Some(b"ustar\0")
    {
        return NpmFileKind::NestedArchive;
    }
    if [".js", ".mjs", ".cjs"]
        .iter()
        .any(|ext| lower.ends_with(ext))
    {
        return NpmFileKind::JavaScript;
    }
    if [".sh", ".bash", ".zsh"]
        .iter()
        .any(|ext| lower.ends_with(ext))
    {
        return NpmFileKind::ShellScript;
    }
    let first_line = bytes.split(|b| *b == b'\n').next().unwrap_or_default();
    if first_line.starts_with(b"#!") {
        let line = std::str::from_utf8(first_line).unwrap_or_default();
        if line
            .split_ascii_whitespace()
            .any(|word| matches!(word.rsplit('/').next(), Some("node" | "nodejs")))
        {
            return NpmFileKind::JavaScript;
        }
        if line
            .split_ascii_whitespace()
            .any(|word| matches!(word.rsplit('/').next(), Some("sh" | "bash" | "zsh")))
        {
            return NpmFileKind::ShellScript;
        }
        return NpmFileKind::OtherCode;
    }
    if executable
        || [
            ".ts", ".tsx", ".jsx", ".py", ".pl", ".rb", ".ps1", ".bat", ".cmd", ".gyp", ".gypi",
        ]
        .iter()
        .any(|ext| lower.ends_with(ext))
    {
        return NpmFileKind::OtherCode;
    }
    NpmFileKind::Resource
}
