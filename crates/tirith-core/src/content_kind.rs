//! Bounded, byte-first content classification for file scanning.
//!
//! The classifier deliberately consumes only a small prefix.  Callers must pass
//! bytes from the handle they will analyze; a path suffix is never evidence of
//! content identity.

/// Maximum prefix searched for a PDF header. ISO 32000 permits the header to
/// appear within the first 1024 bytes for compatibility with leading transport
/// bytes, while a later `%PDF-` substring is not a PDF identity signal.
pub const MAGIC_PREFIX_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentKind {
    Text,
    Pdf,
    Zip,
    Gzip,
    Elf,
    MachO,
    Pe,
    Wasm,
    UnknownBinary,
}

/// Bounded classification plus the PDF-ownership signal needed by FileScan.
/// `classify` remains the simple 0.3.3-compatible primary-kind API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentClassification {
    pub kind: ContentKind,
    pub pdf_header_offset: Option<usize>,
    /// A PDF header coexists with a stronger offset-zero magic or with a
    /// non-whitespace prefix. Such input is a possible polyglot and must never
    /// be handed exclusively to the PDF analyzer as though ownership were
    /// proved.
    pub ambiguous_pdf_ownership: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArchiveMagic {
    Zip,
    Gzip,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeMagic {
    Elf,
    MachO,
    MachOFat,
    Pe,
    Unknown,
}

impl ContentKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Pdf => "PDF",
            Self::Zip => "ZIP archive",
            Self::Gzip => "gzip archive",
            Self::Elf => "ELF binary",
            Self::MachO => "Mach-O binary",
            Self::Pe => "PE binary",
            Self::Wasm => "WebAssembly module",
            Self::UnknownBinary => "unknown binary",
        }
    }
}

/// Classify by bounded magic, with magic taking precedence over text shape.
pub fn classify(bytes: &[u8]) -> ContentKind {
    classify_with_ambiguity(bytes).kind
}

/// Classify with explicit PDF ownership/ambiguity metadata.
pub fn classify_with_ambiguity(bytes: &[u8]) -> ContentClassification {
    let prefix = &bytes[..bytes.len().min(MAGIC_PREFIX_BYTES)];
    let pdf_header_offset = prefix.windows(5).position(|window| window == b"%PDF-");
    let trailing_zip_probe = if pdf_header_offset.is_some() {
        trailing_zip_analysis(bytes).probe
    } else {
        ZipTailProbe::AbsentExhaustive
    };
    let strong_kind = match classify_archive_prefix(bytes) {
        ArchiveMagic::Zip => Some(ContentKind::Zip),
        ArchiveMagic::Gzip => Some(ContentKind::Gzip),
        ArchiveMagic::Unknown => match classify_native_prefix(bytes) {
            NativeMagic::Elf => Some(ContentKind::Elf),
            NativeMagic::MachO | NativeMagic::MachOFat => Some(ContentKind::MachO),
            NativeMagic::Pe => Some(ContentKind::Pe),
            NativeMagic::Unknown if bytes.starts_with(b"\0asm") => Some(ContentKind::Wasm),
            NativeMagic::Unknown => None,
        },
    };
    if let Some(kind) = strong_kind {
        return ContentClassification {
            kind,
            pdf_header_offset,
            ambiguous_pdf_ownership: pdf_header_offset.is_some(),
        };
    }

    if let Some(offset) = pdf_header_offset {
        let prefix_is_transport_whitespace = bytes[..offset]
            .iter()
            .all(|byte| byte.is_ascii_whitespace());
        if offset == 0 || prefix_is_transport_whitespace {
            return ContentClassification {
                kind: ContentKind::Pdf,
                pdf_header_offset: Some(offset),
                ambiguous_pdf_ownership: match trailing_zip_probe {
                    ZipTailProbe::Present { offset: zip_offset } => zip_offset > offset,
                    ZipTailProbe::Indeterminate => true,
                    ZipTailProbe::AbsentExhaustive => false,
                },
            };
        }
        return ContentClassification {
            kind: if !bytes.contains(&0) && std::str::from_utf8(bytes).is_ok() {
                ContentKind::Text
            } else {
                ContentKind::UnknownBinary
            },
            pdf_header_offset: Some(offset),
            ambiguous_pdf_ownership: true,
        };
    }

    // UTF-8 (including ordinary ASCII) with no NUL is the generic text path.
    // A NUL-bearing or malformed byte sequence must not be interpreted through
    // lossy UTF-8 and handed to config/code rules.
    if !bytes.contains(&0) && std::str::from_utf8(bytes).is_ok() {
        ContentClassification {
            kind: ContentKind::Text,
            pdf_header_offset: None,
            ambiguous_pdf_ownership: false,
        }
    } else {
        ContentClassification {
            kind: ContentKind::UnknownBinary,
            pdf_header_offset: None,
            ambiguous_pdf_ownership: false,
        }
    }
}

fn read_le_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let value = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([value[0], value[1]]))
}

fn read_le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let value = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_le_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let value = bytes.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

const ZIP64_EXTRA_ID: u16 = 0x0001;

/// Canonical arithmetic and non-spanned-layout proof shared by file ownership
/// classification and the bounded archive preflight. `record_offset` is the
/// physical classic EOCD offset or the physical ZIP64 EOCD-record offset. The
/// caller remains responsible for locating the record and validating central
/// and local-header bytes; this function is the single source of truth for the
/// EOCD counts and archive-relative central-directory layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ZipEocdLayout {
    pub(crate) archive_start: u64,
    pub(crate) physical_central: u64,
    pub(crate) central_size: u64,
    pub(crate) central_offset: u64,
    pub(crate) total_entries: u64,
}

pub(crate) fn validate_zip_eocd_layout(
    record_offset: u64,
    disk: u64,
    central_disk: u64,
    disk_entries: u64,
    total_entries: u64,
    central_size: u64,
    central_offset: u64,
) -> Result<ZipEocdLayout, &'static str> {
    if disk != 0 || central_disk != 0 || disk_entries != total_entries {
        return Err("multi-disk or inconsistent EOCD");
    }
    if total_entries == 0 {
        // zip 2.4.2 deliberately accepts an empty archive without consulting
        // central-directory bytes or size. Mirror its saturating prefix
        // calculation so an accepted empty tail cannot restore exclusive PDF
        // ownership merely through ignored EOCD fields.
        return Ok(ZipEocdLayout {
            archive_start: record_offset.saturating_sub(central_offset),
            physical_central: record_offset,
            central_size,
            central_offset,
            total_entries,
        });
    }
    let physical_central = record_offset
        .checked_sub(central_size)
        .ok_or("central directory extends before its EOCD record")?;
    let archive_start = physical_central
        .checked_sub(central_offset)
        .ok_or("central-directory offset is inconsistent")?;
    Ok(ZipEocdLayout {
        archive_start,
        physical_central,
        central_size,
        central_offset,
        total_entries,
    })
}

fn validate_trailing_zip_directory(bytes: &[u8], layout: ZipEocdLayout) -> Option<usize> {
    let physical_central = usize::try_from(layout.physical_central).ok()?;
    let archive_start = usize::try_from(layout.archive_start).ok()?;
    let central_size = usize::try_from(layout.central_size).ok()?;
    let total_entries = usize::try_from(layout.total_entries).ok()?;

    // The locked reader accepts a zero-entry ZIP without reading central bytes.
    // The shared layout already mirrors its saturating prefix calculation.
    if total_entries == 0 {
        return Some(archive_start);
    }

    if central_size < 46
        || bytes.get(physical_central..physical_central.checked_add(4)?) != Some(b"PK\x01\x02")
    {
        return None;
    }
    let first_central_end = physical_central
        .checked_add(46)?
        .checked_add(usize::from(read_le_u16(
            bytes,
            physical_central.checked_add(28)?,
        )?))?
        .checked_add(usize::from(read_le_u16(
            bytes,
            physical_central.checked_add(30)?,
        )?))?
        .checked_add(usize::from(read_le_u16(
            bytes,
            physical_central.checked_add(32)?,
        )?))?;
    let central_end = physical_central.checked_add(central_size)?;
    if first_central_end > central_end {
        return None;
    }

    let compressed_size = read_le_u32(bytes, physical_central.checked_add(20)?)?;
    let uncompressed_size = read_le_u32(bytes, physical_central.checked_add(24)?)?;
    let name_len = usize::from(read_le_u16(bytes, physical_central.checked_add(28)?)?);
    let extra_len = usize::from(read_le_u16(bytes, physical_central.checked_add(30)?)?);
    let disk_start = read_le_u16(bytes, physical_central.checked_add(34)?)?;
    let classic_local_offset = read_le_u32(bytes, physical_central.checked_add(42)?)?;
    let uses_per_entry_zip64 = compressed_size == u32::MAX
        || uncompressed_size == u32::MAX
        || disk_start == u16::MAX
        || classic_local_offset == u32::MAX;
    let local_offset = if uses_per_entry_zip64 {
        let extra_start = physical_central.checked_add(46)?.checked_add(name_len)?;
        let extra_end = extra_start.checked_add(extra_len)?;
        match zip64_central_local_offset(
            bytes,
            extra_start,
            extra_end,
            uncompressed_size,
            compressed_size,
            classic_local_offset,
            disk_start,
        ) {
            Some(offset) => offset,
            // A coherent ZIP64 EOCD and central entry with sentinels is already
            // enough to make exclusive PDF ownership unsafe. If its bounded
            // 0x0001 field is malformed or uses an unsupported multi-disk
            // shape, fail toward polyglot ambiguity instead of false-PDF.
            None => return Some(archive_start),
        }
    } else {
        usize::try_from(classic_local_offset).ok()?
    };
    let physical_local = archive_start.checked_add(local_offset)?;
    if bytes.get(physical_local..physical_local.checked_add(4)?) != Some(b"PK\x03\x04") {
        return None;
    }
    let local_header_end = physical_local
        .checked_add(30)?
        .checked_add(usize::from(read_le_u16(
            bytes,
            physical_local.checked_add(26)?,
        )?))?
        .checked_add(usize::from(read_le_u16(
            bytes,
            physical_local.checked_add(28)?,
        )?))?;
    (local_header_end <= physical_central).then_some(archive_start)
}

fn zip64_central_local_offset(
    bytes: &[u8],
    extra_start: usize,
    extra_end: usize,
    uncompressed_size: u32,
    compressed_size: u32,
    local_offset: u32,
    disk_start: u16,
) -> Option<usize> {
    const MAX_EXTRA_FIELDS: usize = 256;

    let extras = bytes.get(extra_start..extra_end)?;
    let mut offset = 0usize;
    let mut fields = 0usize;
    while offset < extras.len() {
        fields = fields.checked_add(1)?;
        if fields > MAX_EXTRA_FIELDS {
            return None;
        }
        let header_end = offset.checked_add(4)?;
        let header = extras.get(offset..header_end)?;
        let id = u16::from_le_bytes([header[0], header[1]]);
        let size = usize::from(u16::from_le_bytes([header[2], header[3]]));
        let data_end = header_end.checked_add(size)?;
        let data = extras.get(header_end..data_end)?;
        offset = data_end;
        if id != ZIP64_EXTRA_ID {
            continue;
        }

        let mut cursor = 0usize;
        let mut read_u64 = || {
            let end = cursor.checked_add(8)?;
            let value = data.get(cursor..end)?;
            cursor = end;
            Some(u64::from_le_bytes([
                value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
            ]))
        };
        if uncompressed_size == u32::MAX {
            usize::try_from(read_u64()?).ok()?;
        }
        if compressed_size == u32::MAX {
            usize::try_from(read_u64()?).ok()?;
        }
        let resolved_offset = if local_offset == u32::MAX {
            usize::try_from(read_u64()?).ok()?
        } else {
            usize::try_from(local_offset).ok()?
        };
        if disk_start == u16::MAX {
            let end = cursor.checked_add(4)?;
            let value = data.get(cursor..end)?;
            let disk = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
            if disk != 0 {
                return None;
            }
        } else if disk_start != 0 {
            return None;
        }
        return Some(resolved_offset);
    }
    None
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ClassicEocdFields {
    pub(crate) disk: u16,
    pub(crate) central_disk: u16,
    pub(crate) disk_entries: u16,
    pub(crate) total_entries: u16,
    pub(crate) central_size: u32,
    pub(crate) central_offset: u32,
}

impl ClassicEocdFields {
    pub(crate) fn requires_zip64(self) -> bool {
        self.disk == u16::MAX
            || self.central_disk == u16::MAX
            || self.disk_entries == u16::MAX
            || self.total_entries == u16::MAX
            || self.central_size == u32::MAX
            || self.central_offset == u32::MAX
    }

    pub(crate) fn matches_zip64_layout(self, layout: ZipEocdLayout) -> bool {
        let u16_matches =
            |legacy: u16, actual: u64| legacy == u16::MAX || u64::from(legacy) == actual;
        let u32_matches =
            |legacy: u32, actual: u64| legacy == u32::MAX || u64::from(legacy) == actual;
        u16_matches(self.disk, 0)
            && u16_matches(self.central_disk, 0)
            && u16_matches(self.disk_entries, layout.total_entries)
            && u16_matches(self.total_entries, layout.total_entries)
            && u32_matches(self.central_size, layout.central_size)
            && u32_matches(self.central_offset, layout.central_offset)
    }
}

const ZIP_EOCD_BYTES: usize = 22;
#[cfg(test)]
const ZIP_MAX_COMMENT_BYTES: usize = u16::MAX as usize;
const ZIP64_LOCATOR_BYTES: usize = 20;
const ZIP64_RECORD_BASE_BYTES: usize = 56;
/// Maximum suffix searched for an EOCD accepted by the locked `zip` reader.
/// FileScan caps inputs at 10 MiB and archive inspection buffers a member only
/// through its 64 MiB default ceiling, so both production callers are
/// exhaustive. Callers passing larger buffers receive `Indeterminate` rather
/// than a false absence.
const MAX_ZIP_TAIL_SCAN_BYTES: usize = 64 * 1024 * 1024;
/// Bound retained EOCD candidates under a signature flood.
const MAX_ZIP_EOCD_CANDIDATES: usize = 4096;
/// Maximum bytes inspected in each of the two ZIP64-record search windows.
///
/// One window is adjacent to the locator (the ordinary small-record case); the
/// other starts at the locator's declared archive-relative record offset. The
/// latter is what keeps a PDF+ZIP64 polyglot with an extensible-data sector
/// larger than this limit ambiguous: its fixed EOCD64 header is near the start
/// of the appended archive even though its locator is more than 1 MiB away.
/// Neither window is copied or allocated, so the work is fixed while the
/// record's attacker-declared extensible sector may be arbitrarily large.
const MAX_ZIP64_RECORD_SCAN_BYTES: usize = 1024 * 1024;
/// Bound retained exact-end record candidates even under a signature flood.
/// Hitting this cap fails toward PDF/ZIP ambiguity rather than exclusive PDF.
const MAX_ZIP64_INDEXED_RECORDS: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct Zip64Locator {
    offset: usize,
    declared_record_offset: usize,
}

#[derive(Debug, Clone, Copy)]
enum TrailingEocdKind {
    Classic,
    Zip64(Zip64Locator),
}

#[derive(Debug, Clone, Copy)]
struct TrailingEocdCandidate {
    eocd: usize,
    legacy: ClassicEocdFields,
    kind: TrailingEocdKind,
}

struct Zip64RecordIndex {
    by_locator: std::collections::BTreeMap<usize, Vec<usize>>,
    scanned_positions: usize,
    candidate_limit_hit: bool,
    search_incomplete: bool,
}

fn valid_zip64_locator(bytes: &[u8], eocd: usize) -> Option<Zip64Locator> {
    let offset = eocd.checked_sub(ZIP64_LOCATOR_BYTES)?;
    if bytes.get(offset..offset.checked_add(4)?) != Some(b"PK\x06\x07")
        || read_le_u32(bytes, offset.checked_add(4)?)? != 0
        || read_le_u32(bytes, offset.checked_add(16)?)? != 1
    {
        return None;
    }
    let declared_record_offset =
        usize::try_from(read_le_u64(bytes, offset.checked_add(8)?)?).ok()?;
    if declared_record_offset > offset.saturating_sub(ZIP64_RECORD_BASE_BYTES) {
        return None;
    }
    Some(Zip64Locator {
        offset,
        declared_record_offset,
    })
}

/// Index every structurally sized ZIP64 record signature once across the union
/// of all eligible locator windows. A signature is retained only when its exact
/// computed end is an eligible locator, so signature floods cannot create an
/// unbounded allocation or per-EOCD rescan.
fn build_zip64_record_index(
    bytes: &[u8],
    locators: &std::collections::BTreeMap<usize, usize>,
) -> Zip64RecordIndex {
    let mut index = Zip64RecordIndex {
        by_locator: std::collections::BTreeMap::new(),
        scanned_positions: 0,
        candidate_limit_hit: false,
        search_incomplete: false,
    };
    let (Some((&first_locator, _)), Some((&last_locator, _))) =
        (locators.first_key_value(), locators.last_key_value())
    else {
        return index;
    };
    let Some(search_end) = last_locator.checked_sub(ZIP64_RECORD_BASE_BYTES) else {
        return index;
    };

    let tail_start = first_locator.saturating_sub(MAX_ZIP64_RECORD_SCAN_BYTES.saturating_add(12));
    let declared_start = locators.values().copied().min().unwrap_or(0);
    let declared_end = declared_start
        .saturating_add(MAX_ZIP64_RECORD_SCAN_BYTES.saturating_sub(1))
        .min(search_end);

    // Merge the at-most-two windows so an overlapping prefix/tail is scanned
    // once. Their total work is at most 2 MiB regardless of the input length or
    // the attacker-declared EOCD64 record size.
    let mut ranges = Vec::with_capacity(2);
    if tail_start <= search_end {
        ranges.push((tail_start, search_end));
    }
    if declared_start <= declared_end {
        ranges.push((declared_start, declared_end));
    }
    ranges.sort_unstable_by_key(|range| range.0);
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(2);
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut() {
            if start <= last.1.saturating_add(1) {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }

    let mut retained = 0usize;
    for &(search_start, search_end) in &merged {
        // Reverse order preserves deterministic latest-to-earliest validation.
        // Retain every exact-end candidate until the global candidate cap: a
        // later nested record can be invalid while an enclosing record is real.
        for candidate in (search_start..=search_end).rev() {
            index.scanned_positions = index.scanned_positions.saturating_add(1);
            if bytes.get(candidate..candidate.saturating_add(4)) != Some(b"PK\x06\x06") {
                continue;
            }
            let Some(size) = read_le_u64(bytes, candidate.saturating_add(4))
                .and_then(|size| usize::try_from(size).ok())
            else {
                continue;
            };
            if size < 44 {
                continue;
            }
            let Some(locator) = candidate
                .checked_add(12)
                .and_then(|end| end.checked_add(size))
            else {
                continue;
            };
            if !locators.contains_key(&locator) {
                continue;
            }
            if retained >= MAX_ZIP64_INDEXED_RECORDS {
                index.candidate_limit_hit = true;
                continue;
            }
            retained += 1;
            index.by_locator.entry(locator).or_default().push(candidate);
        }
    }
    index.search_incomplete = locators.iter().any(|(&locator, &declared)| {
        let Some(possible_end) = locator.checked_sub(ZIP64_RECORD_BASE_BYTES) else {
            return false;
        };
        let mut next = declared;
        for &(start, end) in &merged {
            if end < next {
                continue;
            }
            if start > next {
                return true;
            }
            next = end.saturating_add(1);
            if next > possible_end {
                return false;
            }
        }
        next <= possible_end
    });
    index
}

fn structurally_valid_zip64_offset(
    bytes: &[u8],
    locator: Zip64Locator,
    record: usize,
    legacy: ClassicEocdFields,
) -> Option<usize> {
    let size = usize::try_from(read_le_u64(bytes, record.checked_add(4)?)?).ok()?;
    if size < 44
        || record.checked_add(12).and_then(|end| end.checked_add(size)) != Some(locator.offset)
    {
        return None;
    }

    let disk = u64::from(read_le_u32(bytes, record.checked_add(16)?)?);
    let central_disk = u64::from(read_le_u32(bytes, record.checked_add(20)?)?);
    let disk_entries = read_le_u64(bytes, record.checked_add(24)?)?;
    let total_entries = read_le_u64(bytes, record.checked_add(32)?)?;
    let central_size = read_le_u64(bytes, record.checked_add(40)?)?;
    let central_offset = read_le_u64(bytes, record.checked_add(48)?)?;
    let layout = validate_zip_eocd_layout(
        u64::try_from(record).ok()?,
        disk,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
    )
    .ok()?;
    if !legacy.matches_zip64_layout(layout) {
        return None;
    }
    if layout.total_entries == 0 {
        return record.checked_sub(locator.declared_record_offset);
    }

    let archive_start = validate_trailing_zip_directory(bytes, layout)?;
    (record.checked_sub(archive_start)? == locator.declared_record_offset).then_some(archive_start)
}

/// Result of the bounded trailing-ZIP proof. Work-budget exhaustion is never
/// represented as absence because callers use this to decide exclusive parser
/// ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZipTailProbe {
    Present { offset: usize },
    AbsentExhaustive,
    Indeterminate,
}

/// Return the physical start of a structurally coherent trailing ZIP archive
/// plus bounded-work receipts. The EOCD comment may end before EOF because the
/// locked `zip` 2.4.2 reader deliberately accepts garbage after the comment.
/// The EOCD must describe one
/// non-spanned standard or ZIP64 central directory. A non-empty archive's first
/// central entry must resolve to a real local header after accounting for a
/// self-extracting/polyglot prefix; a canonical empty archive is valid too.
/// Signature substrings inside a PDF stream therefore do not create ambiguity
/// by themselves.
#[derive(Debug, Clone, Copy)]
struct TrailingZipAnalysis {
    probe: ZipTailProbe,
    #[cfg_attr(not(test), allow(dead_code))]
    offset: Option<usize>,
    #[cfg_attr(not(test), allow(dead_code))]
    scanned_positions: usize,
    #[cfg_attr(not(test), allow(dead_code))]
    candidate_limit_hit: bool,
    #[cfg_attr(not(test), allow(dead_code))]
    search_incomplete: bool,
}

fn trailing_zip_analysis(bytes: &[u8]) -> TrailingZipAnalysis {
    if bytes.len() < ZIP_EOCD_BYTES {
        return TrailingZipAnalysis {
            probe: ZipTailProbe::AbsentExhaustive,
            offset: None,
            scanned_positions: 0,
            candidate_limit_hit: false,
            search_incomplete: false,
        };
    }
    let search_start = bytes.len().saturating_sub(MAX_ZIP_TAIL_SCAN_BYTES);
    let mut candidates = Vec::new();
    let mut zip64_locators = std::collections::BTreeMap::new();
    let mut eocd_candidate_limit_hit = false;
    for eocd in (search_start..=bytes.len() - ZIP_EOCD_BYTES).rev() {
        if bytes.get(eocd..eocd + 4) != Some(b"PK\x05\x06") {
            continue;
        }
        let Some(comment_len) = read_le_u16(bytes, eocd + 20).map(usize::from) else {
            continue;
        };
        let Some(candidate_end) = eocd
            .checked_add(ZIP_EOCD_BYTES)
            .and_then(|end| end.checked_add(comment_len))
        else {
            continue;
        };
        if candidate_end > bytes.len() {
            continue;
        }
        let (Some(disk), Some(central_disk), Some(disk_entries), Some(total_entries)) = (
            read_le_u16(bytes, eocd + 4),
            read_le_u16(bytes, eocd + 6),
            read_le_u16(bytes, eocd + 8),
            read_le_u16(bytes, eocd + 10),
        ) else {
            continue;
        };
        let (Some(central_size), Some(declared_central_offset)) =
            (read_le_u32(bytes, eocd + 12), read_le_u32(bytes, eocd + 16))
        else {
            continue;
        };

        let legacy = ClassicEocdFields {
            disk,
            central_disk,
            disk_entries,
            total_entries,
            central_size,
            central_offset: declared_central_offset,
        };
        if legacy.requires_zip64() {
            let Some(locator) = valid_zip64_locator(bytes, eocd) else {
                continue;
            };
            if candidates.len() >= MAX_ZIP_EOCD_CANDIDATES {
                eocd_candidate_limit_hit = true;
                continue;
            }
            zip64_locators.insert(locator.offset, locator.declared_record_offset);
            candidates.push(TrailingEocdCandidate {
                eocd,
                legacy,
                kind: TrailingEocdKind::Zip64(locator),
            });
            continue;
        }

        if candidates.len() >= MAX_ZIP_EOCD_CANDIDATES {
            eocd_candidate_limit_hit = true;
            continue;
        }
        candidates.push(TrailingEocdCandidate {
            eocd,
            legacy,
            kind: TrailingEocdKind::Classic,
        });
    }

    let zip64_records = build_zip64_record_index(bytes, &zip64_locators);
    for candidate in candidates {
        let eocd = candidate.eocd;
        let ClassicEocdFields {
            disk,
            central_disk,
            disk_entries,
            total_entries,
            central_size,
            central_offset: declared_central_offset,
        } = candidate.legacy;
        if let TrailingEocdKind::Zip64(locator) = candidate.kind {
            let Some(records) = zip64_records.by_locator.get(&locator.offset) else {
                continue;
            };
            for &record in records {
                if let Some(offset) =
                    structurally_valid_zip64_offset(bytes, locator, record, candidate.legacy)
                {
                    return TrailingZipAnalysis {
                        probe: ZipTailProbe::Present { offset },
                        offset: Some(offset),
                        scanned_positions: zip64_records.scanned_positions,
                        candidate_limit_hit: eocd_candidate_limit_hit
                            || zip64_records.candidate_limit_hit,
                        search_incomplete: search_start > 0 || zip64_records.search_incomplete,
                    };
                }
            }
            continue;
        }

        let Ok(record_offset) = u64::try_from(eocd) else {
            continue;
        };
        let Ok(layout) = validate_zip_eocd_layout(
            record_offset,
            u64::from(disk),
            u64::from(central_disk),
            u64::from(disk_entries),
            u64::from(total_entries),
            u64::from(central_size),
            u64::from(declared_central_offset),
        ) else {
            continue;
        };
        if let Some(offset) = validate_trailing_zip_directory(bytes, layout) {
            return TrailingZipAnalysis {
                probe: ZipTailProbe::Present { offset },
                offset: Some(offset),
                scanned_positions: zip64_records.scanned_positions,
                candidate_limit_hit: eocd_candidate_limit_hit || zip64_records.candidate_limit_hit,
                search_incomplete: search_start > 0 || zip64_records.search_incomplete,
            };
        }
    }
    let candidate_limit_hit = eocd_candidate_limit_hit || zip64_records.candidate_limit_hit;
    let search_incomplete = search_start > 0 || zip64_records.search_incomplete;
    TrailingZipAnalysis {
        probe: if candidate_limit_hit || search_incomplete {
            ZipTailProbe::Indeterminate
        } else {
            ZipTailProbe::AbsentExhaustive
        },
        offset: None,
        scanned_positions: zip64_records.scanned_positions,
        candidate_limit_hit,
        search_incomplete,
    }
}

/// Whether bytes open a trailing ZIP analysis boundary under the bounded
/// structural preflight. This includes a validated classic/ZIP64 archive and a
/// ZIP64 candidate whose record search exceeded the bounded windows; the latter
/// must fail toward incomplete coverage rather than false ownership.
pub(crate) fn has_trailing_zip_boundary(bytes: &[u8]) -> bool {
    !matches!(
        trailing_zip_analysis(bytes).probe,
        ZipTailProbe::AbsentExhaustive
    )
}

/// Shared source of truth for archive magic used by file dispatch and the
/// existing artifact inspector.
pub(crate) fn classify_archive_prefix(bytes: &[u8]) -> ArchiveMagic {
    if bytes.len() >= 4
        && bytes[0] == b'P'
        && bytes[1] == b'K'
        && matches!(
            (bytes[2], bytes[3]),
            (0x03, 0x04) | (0x05, 0x06) | (0x07, 0x08)
        )
    {
        ArchiveMagic::Zip
    } else if bytes.starts_with(&[0x1f, 0x8b]) {
        ArchiveMagic::Gzip
    } else {
        ArchiveMagic::Unknown
    }
}

/// Shared source of truth for native magic used by file dispatch and native
/// triage. It preserves the fat/thin Mach-O distinction needed by the latter.
pub(crate) fn classify_native_prefix(bytes: &[u8]) -> NativeMagic {
    if bytes.starts_with(b"\x7fELF") {
        return NativeMagic::Elf;
    }
    if bytes.len() >= 4 {
        let magic = &bytes[..4];
        if matches!(
            magic,
            [0xca, 0xfe, 0xba, 0xbe]
                | [0xca, 0xfe, 0xba, 0xbf]
                | [0xbe, 0xba, 0xfe, 0xca]
                | [0xbf, 0xba, 0xfe, 0xca]
        ) {
            return NativeMagic::MachOFat;
        }
        if matches!(
            magic,
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xcf, 0xfa, 0xed, 0xfe]
        ) {
            return NativeMagic::MachO;
        }
    }
    if valid_pe_header(bytes) {
        NativeMagic::Pe
    } else {
        NativeMagic::Unknown
    }
}

fn valid_pe_header(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"MZ") || bytes.len() < 0x40 {
        return false;
    }
    let Some(pe_offset) = read_le_u32(bytes, 0x3c).and_then(|value| usize::try_from(value).ok())
    else {
        return false;
    };
    pe_offset >= 0x40
        && pe_offset
            .checked_add(24)
            .is_some_and(|header_end| header_end <= bytes.len())
        && bytes.get(pe_offset..pe_offset + 4) == Some(b"PE\0\0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_precedes_text_and_suffix_is_not_consulted() {
        assert_eq!(classify(b"plain UTF-8"), ContentKind::Text);
        let embedded = classify_with_ambiguity(b"prefix\n%PDF-1.7\n");
        assert_eq!(embedded.kind, ContentKind::Text);
        assert!(embedded.ambiguous_pdf_ownership);
        assert_eq!(classify(b"PK\x03\x04text"), ContentKind::Zip);
        assert_eq!(classify(b"\x7fELF"), ContentKind::Elf);
        assert_eq!(classify(b"\0asm"), ContentKind::Wasm);
        assert_eq!(classify(b"bad\xffbytes"), ContentKind::UnknownBinary);
    }

    #[test]
    fn stronger_offset_zero_magic_keeps_ownership_over_embedded_pdf() {
        for (mut bytes, expected) in [
            (b"PK\x03\x04payload".to_vec(), ContentKind::Zip),
            (b"\x7fELFpayload".to_vec(), ContentKind::Elf),
            (b"\0asmpayload".to_vec(), ContentKind::Wasm),
        ] {
            bytes.extend_from_slice(b"%PDF-1.7");
            let classification = classify_with_ambiguity(&bytes);
            assert_eq!(classification.kind, expected);
            assert!(classification.ambiguous_pdf_ownership);
            assert!(classification.pdf_header_offset.is_some());
        }
    }

    fn pdf_with_trailing_zip() -> Vec<u8> {
        let mut bytes = b"%PDF-1.7\n1 0 obj <<>> endobj\n%%EOF\n".to_vec();
        let archive_start = bytes.len();
        let mut local = vec![0u8; 30];
        local[..4].copy_from_slice(b"PK\x03\x04");
        local[4..6].copy_from_slice(&20u16.to_le_bytes());
        local[26..28].copy_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&local);
        bytes.push(b'x');

        let central_offset = bytes.len() - archive_start;
        let mut central = vec![0u8; 46];
        central[..4].copy_from_slice(b"PK\x01\x02");
        central[4..6].copy_from_slice(&20u16.to_le_bytes());
        central[6..8].copy_from_slice(&20u16.to_le_bytes());
        central[28..30].copy_from_slice(&1u16.to_le_bytes());
        central[42..46].copy_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&central);
        bytes.push(b'x');
        let central_size = bytes.len() - archive_start - central_offset;

        let mut eocd = vec![0u8; 22];
        eocd[..4].copy_from_slice(b"PK\x05\x06");
        eocd[8..10].copy_from_slice(&1u16.to_le_bytes());
        eocd[10..12].copy_from_slice(&1u16.to_le_bytes());
        eocd[12..16].copy_from_slice(&(central_size as u32).to_le_bytes());
        eocd[16..20].copy_from_slice(&(central_offset as u32).to_le_bytes());
        bytes.extend_from_slice(&eocd);
        bytes
    }

    fn pdf_with_trailing_zip64_extensible(extensible_bytes: usize) -> Vec<u8> {
        let mut bytes = b"%PDF-1.7\n1 0 obj <<>> endobj\n%%EOF\n".to_vec();
        let archive_start = bytes.len();
        let mut local = vec![0u8; 30];
        local[..4].copy_from_slice(b"PK\x03\x04");
        local[4..6].copy_from_slice(&45u16.to_le_bytes());
        local[26..28].copy_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&local);
        bytes.push(b'x');

        let central_offset = bytes.len() - archive_start;
        let mut central = vec![0u8; 46];
        central[..4].copy_from_slice(b"PK\x01\x02");
        central[4..6].copy_from_slice(&45u16.to_le_bytes());
        central[6..8].copy_from_slice(&45u16.to_le_bytes());
        central[28..30].copy_from_slice(&1u16.to_le_bytes());
        central[42..46].copy_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&central);
        bytes.push(b'x');
        let central_size = bytes.len() - archive_start - central_offset;

        let record_start = bytes.len();
        let mut record = vec![0u8; ZIP64_RECORD_BASE_BYTES + extensible_bytes];
        record[..4].copy_from_slice(b"PK\x06\x06");
        record[4..12].copy_from_slice(&(44u64 + extensible_bytes as u64).to_le_bytes());
        record[12..14].copy_from_slice(&45u16.to_le_bytes());
        record[14..16].copy_from_slice(&45u16.to_le_bytes());
        record[24..32].copy_from_slice(&1u64.to_le_bytes());
        record[32..40].copy_from_slice(&1u64.to_le_bytes());
        record[40..48].copy_from_slice(&(central_size as u64).to_le_bytes());
        record[48..56].copy_from_slice(&(central_offset as u64).to_le_bytes());
        bytes.extend_from_slice(&record);

        let mut locator = vec![0u8; 20];
        locator[..4].copy_from_slice(b"PK\x06\x07");
        locator[8..16].copy_from_slice(&((record_start - archive_start) as u64).to_le_bytes());
        locator[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&locator);

        let mut eocd = vec![0u8; 22];
        eocd[..4].copy_from_slice(b"PK\x05\x06");
        eocd[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
        eocd[10..12].copy_from_slice(&u16::MAX.to_le_bytes());
        eocd[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        eocd[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&eocd);
        bytes
    }

    fn pdf_with_trailing_zip64() -> Vec<u8> {
        pdf_with_trailing_zip64_extensible(0)
    }

    fn append_false_zip64_eocd_comment_tail(bytes: &mut Vec<u8>, count: usize) -> Vec<usize> {
        let mut fake_eocds = Vec::with_capacity(count);
        for _ in 0..count {
            let mut locator = [0u8; ZIP64_LOCATOR_BYTES];
            locator[..4].copy_from_slice(b"PK\x06\x07");
            locator[16..20].copy_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&locator);

            let eocd_offset = bytes.len();
            let mut eocd = [0u8; ZIP_EOCD_BYTES];
            eocd[..4].copy_from_slice(b"PK\x05\x06");
            eocd[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
            eocd[10..12].copy_from_slice(&u16::MAX.to_le_bytes());
            eocd[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
            eocd[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
            bytes.extend_from_slice(&eocd);
            fake_eocds.push(eocd_offset);
        }
        let final_len = bytes.len();
        for eocd in &fake_eocds {
            let comment_len = final_len - eocd - ZIP_EOCD_BYTES;
            bytes[*eocd + 20..*eocd + 22].copy_from_slice(&(comment_len as u16).to_le_bytes());
        }
        fake_eocds
    }

    fn pdf_with_trailing_per_entry_zip64() -> Vec<u8> {
        let mut bytes = b"%PDF-1.7\n1 0 obj <<>> endobj\n%%EOF\n".to_vec();
        let archive_start = bytes.len();

        let mut local = vec![0u8; 30];
        local[..4].copy_from_slice(b"PK\x03\x04");
        local[4..6].copy_from_slice(&45u16.to_le_bytes());
        local[18..22].copy_from_slice(&u32::MAX.to_le_bytes());
        local[22..26].copy_from_slice(&u32::MAX.to_le_bytes());
        local[26..28].copy_from_slice(&1u16.to_le_bytes());
        local[28..30].copy_from_slice(&20u16.to_le_bytes());
        bytes.extend_from_slice(&local);
        bytes.push(b'x');
        bytes.extend_from_slice(&ZIP64_EXTRA_ID.to_le_bytes());
        bytes.extend_from_slice(&16u16.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());

        let central_offset = bytes.len() - archive_start;
        let mut central = vec![0u8; 46];
        central[..4].copy_from_slice(b"PK\x01\x02");
        central[4..6].copy_from_slice(&45u16.to_le_bytes());
        central[6..8].copy_from_slice(&45u16.to_le_bytes());
        central[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        central[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        central[28..30].copy_from_slice(&1u16.to_le_bytes());
        central[30..32].copy_from_slice(&28u16.to_le_bytes());
        central[42..46].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&central);
        bytes.push(b'x');
        bytes.extend_from_slice(&ZIP64_EXTRA_ID.to_le_bytes());
        bytes.extend_from_slice(&24u16.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        let central_size = bytes.len() - archive_start - central_offset;

        // Per-entry ZIP64 sizes/offsets do not require an archive-level ZIP64
        // EOCD when the directory count/size/offset still fit classic fields.
        let mut eocd = vec![0u8; 22];
        eocd[..4].copy_from_slice(b"PK\x05\x06");
        eocd[8..10].copy_from_slice(&1u16.to_le_bytes());
        eocd[10..12].copy_from_slice(&1u16.to_le_bytes());
        eocd[12..16].copy_from_slice(&(central_size as u32).to_le_bytes());
        eocd[16..20].copy_from_slice(&(central_offset as u32).to_le_bytes());
        bytes.extend_from_slice(&eocd);
        bytes
    }

    fn assert_locked_zip_reader_accepts(bytes: &[u8], label: &str) {
        let archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
            .unwrap_or_else(|error| panic!("locked zip 2.4.2 rejected {label}: {error}"));
        assert_eq!(archive.len(), 1, "unexpected entry count for {label}");
    }

    #[test]
    fn pdf_first_structural_zip_polyglot_never_gets_exclusive_pdf_ownership() {
        let classification = classify_with_ambiguity(&pdf_with_trailing_zip());
        assert_eq!(classification.kind, ContentKind::Pdf);
        assert!(classification.ambiguous_pdf_ownership);

        let benign = classify_with_ambiguity(b"%PDF-1.7\n(PK\x03\x04 is text)\n%%EOF\n");
        assert_eq!(benign.kind, ContentKind::Pdf);
        assert!(!benign.ambiguous_pdf_ownership);
    }

    #[test]
    fn zip_reader_accepted_trailing_junk_never_restores_exclusive_pdf_ownership() {
        for trailing_junk in [
            b"\n".as_slice(),
            &[b'x'; 4096],
            &[b'y'; ZIP_MAX_COMMENT_BYTES + 1],
        ] {
            let mut bytes = pdf_with_trailing_zip();
            bytes.extend_from_slice(trailing_junk);

            assert!(
                zip::ZipArchive::new(std::io::Cursor::new(&bytes)).is_ok(),
                "fixture must remain accepted by the locked ZIP reader"
            );
            let analysis = trailing_zip_analysis(&bytes);
            assert!(matches!(analysis.probe, ZipTailProbe::Present { .. }));
            let classification = classify_with_ambiguity(&bytes);
            assert_eq!(classification.kind, ContentKind::Pdf);
            assert!(classification.ambiguous_pdf_ownership);
        }
    }

    #[test]
    fn locked_zip_reader_layout_matrix_never_gets_exclusive_pdf_ownership() {
        for (label, bytes) in [
            ("classic", pdf_with_trailing_zip()),
            ("archive-level ZIP64", pdf_with_trailing_zip64()),
            ("per-entry ZIP64", pdf_with_trailing_per_entry_zip64()),
        ] {
            assert_locked_zip_reader_accepts(&bytes, label);
            let analysis = trailing_zip_analysis(&bytes);
            assert!(
                matches!(analysis.probe, ZipTailProbe::Present { .. }),
                "accepted {label} archive was not detected: {analysis:?}"
            );
            assert!(classify_with_ambiguity(&bytes).ambiguous_pdf_ownership);
        }
    }

    #[test]
    fn one_byte_trailing_junk_is_ambiguous_for_every_locked_reader_layout() {
        for (label, mut bytes) in [
            ("classic", pdf_with_trailing_zip()),
            ("archive-level ZIP64", pdf_with_trailing_zip64()),
            ("per-entry ZIP64", pdf_with_trailing_per_entry_zip64()),
        ] {
            bytes.push(b'j');
            assert_locked_zip_reader_accepts(&bytes, label);
            assert!(matches!(
                trailing_zip_analysis(&bytes).probe,
                ZipTailProbe::Present { .. }
            ));
            assert!(classify_with_ambiguity(&bytes).ambiguous_pdf_ownership);
        }
    }

    #[test]
    fn locked_zip_reader_comment_boundaries_never_get_exclusive_pdf_ownership() {
        for comment_len in [1usize, ZIP_MAX_COMMENT_BYTES] {
            let mut bytes = pdf_with_trailing_zip();
            let eocd = bytes.len() - ZIP_EOCD_BYTES;
            bytes[eocd + 20..eocd + 22].copy_from_slice(&(comment_len as u16).to_le_bytes());
            bytes.resize(bytes.len() + comment_len, b'c');

            assert_locked_zip_reader_accepts(&bytes, "classic archive comment boundary");
            assert!(matches!(
                trailing_zip_analysis(&bytes).probe,
                ZipTailProbe::Present { .. }
            ));
            assert!(classify_with_ambiguity(&bytes).ambiguous_pdf_ownership);
        }
    }

    #[test]
    fn locked_reader_accepted_empty_archive_ignores_unused_directory_fields() {
        let mut bytes = b"%PDF-1.7\n%%EOF\n".to_vec();
        let mut eocd = [0u8; ZIP_EOCD_BYTES];
        eocd[..4].copy_from_slice(b"PK\x05\x06");
        eocd[12..16].copy_from_slice(&7u32.to_le_bytes());
        eocd[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&eocd);

        let archive = zip::ZipArchive::new(std::io::Cursor::new(&bytes))
            .expect("locked reader accepts ignored empty-archive directory fields");
        assert_eq!(archive.len(), 0);
        assert!(matches!(
            trailing_zip_analysis(&bytes).probe,
            ZipTailProbe::Present { .. }
        ));
        assert!(classify_with_ambiguity(&bytes).ambiguous_pdf_ownership);
    }

    #[test]
    fn malformed_classic_offsets_rejected_by_locked_reader_are_exhaustive_absence() {
        for malformed_offset in [u32::MAX - 1, u32::MAX] {
            let mut bytes = pdf_with_trailing_zip();
            let eocd = bytes.len() - ZIP_EOCD_BYTES;
            bytes[eocd + 16..eocd + 20].copy_from_slice(&malformed_offset.to_le_bytes());

            assert!(
                zip::ZipArchive::new(std::io::Cursor::new(&bytes)).is_err(),
                "locked reader unexpectedly accepted malformed offset {malformed_offset}"
            );
            assert!(matches!(
                trailing_zip_analysis(&bytes).probe,
                ZipTailProbe::AbsentExhaustive
            ));
            assert!(!classify_with_ambiguity(&bytes).ambiguous_pdf_ownership);
        }
    }

    #[test]
    fn classic_eocd_candidate_flood_fails_toward_ambiguity_at_the_exact_cap() {
        let mut bytes = b"%PDF-1.7\n%%EOF\n".to_vec();
        for _ in 0..=MAX_ZIP_EOCD_CANDIDATES {
            let mut invalid = [0u8; ZIP_EOCD_BYTES];
            invalid[..4].copy_from_slice(b"PK\x05\x06");
            invalid[4..6].copy_from_slice(&1u16.to_le_bytes());
            bytes.extend_from_slice(&invalid);
        }

        let analysis = trailing_zip_analysis(&bytes);
        assert!(matches!(analysis.probe, ZipTailProbe::Indeterminate));
        assert!(analysis.candidate_limit_hit);
        assert_eq!(analysis.offset, None);
        assert!(classify_with_ambiguity(&bytes).ambiguous_pdf_ownership);
    }

    #[test]
    fn pdf_first_empty_and_zip64_archives_are_ambiguous() {
        let mut empty = b"%PDF-1.7\n%%EOF\n".to_vec();
        let mut empty_eocd = [0u8; 22];
        empty_eocd[..4].copy_from_slice(b"PK\x05\x06");
        empty.extend_from_slice(&empty_eocd);

        for bytes in [empty, pdf_with_trailing_zip64()] {
            let classification = classify_with_ambiguity(&bytes);
            assert_eq!(classification.kind, ContentKind::Pdf);
            assert!(classification.ambiguous_pdf_ownership);
        }
    }

    #[test]
    fn zip64_extensible_sector_beyond_scan_window_stays_ambiguous_without_linear_work() {
        let bytes =
            pdf_with_trailing_zip64_extensible(MAX_ZIP64_RECORD_SCAN_BYTES.saturating_add(1));
        let classification = classify_with_ambiguity(&bytes);
        let analysis = trailing_zip_analysis(&bytes);

        assert_eq!(classification.kind, ContentKind::Pdf);
        assert!(classification.ambiguous_pdf_ownership);
        assert!(analysis.offset.is_some());
        assert!(
            analysis.scanned_positions
                <= MAX_ZIP64_RECORD_SCAN_BYTES
                    .saturating_mul(2)
                    .saturating_add(128),
            "large EOCD64 sector caused unbounded search work: {}",
            analysis.scanned_positions
        );
    }

    #[test]
    fn zip64_record_outside_both_windows_fails_toward_polyglot_ambiguity() {
        let mut bytes =
            pdf_with_trailing_zip64_extensible(MAX_ZIP64_RECORD_SCAN_BYTES.saturating_mul(2));
        let archive_start = bytes
            .windows(4)
            .position(|window| window == b"PK\x03\x04")
            .unwrap();
        bytes.splice(
            archive_start..archive_start,
            std::iter::repeat_n(b' ', MAX_ZIP64_RECORD_SCAN_BYTES.saturating_mul(2)),
        );

        let classification = classify_with_ambiguity(&bytes);
        let analysis = trailing_zip_analysis(&bytes);
        assert_eq!(classification.kind, ContentKind::Pdf);
        assert!(classification.ambiguous_pdf_ownership);
        assert_eq!(analysis.offset, None);
        assert!(analysis.search_incomplete);
        assert!(
            analysis.scanned_positions
                <= MAX_ZIP64_RECORD_SCAN_BYTES
                    .saturating_mul(2)
                    .saturating_add(128)
        );
    }

    #[test]
    fn large_exact_end_zip64_signature_with_invalid_fixed_fields_is_not_enough() {
        let mut bytes =
            pdf_with_trailing_zip64_extensible(MAX_ZIP64_RECORD_SCAN_BYTES.saturating_add(1));
        let record = bytes
            .windows(4)
            .position(|window| window == b"PK\x06\x06")
            .unwrap();
        bytes[record + 16..record + 20].copy_from_slice(&1u32.to_le_bytes());

        let classification = classify_with_ambiguity(&bytes);
        let analysis = trailing_zip_analysis(&bytes);
        assert_eq!(classification.kind, ContentKind::Pdf);
        assert!(!classification.ambiguous_pdf_ownership);
        assert_eq!(analysis.offset, None);
        assert!(!analysis.candidate_limit_hit);
    }

    #[test]
    fn pdf_first_per_entry_zip64_archive_is_ambiguous() {
        let classification = classify_with_ambiguity(&pdf_with_trailing_per_entry_zip64());
        assert_eq!(classification.kind, ContentKind::Pdf);
        assert!(classification.ambiguous_pdf_ownership);
    }

    #[test]
    fn false_zip64_eocd_flood_has_one_global_signature_scan_budget() {
        const FALSE_EOCDS: usize = 1_500;
        let mut bytes = b"%PDF-1.7\n".to_vec();
        bytes.resize(bytes.len() + MAX_ZIP64_RECORD_SCAN_BYTES, 0);
        append_false_zip64_eocd_comment_tail(&mut bytes, FALSE_EOCDS);

        let classification = classify_with_ambiguity(&bytes);
        let analysis = trailing_zip_analysis(&bytes);

        assert_eq!(classification.kind, ContentKind::Pdf);
        assert!(!classification.ambiguous_pdf_ownership);
        assert_eq!(analysis.offset, None);
        assert!(!analysis.candidate_limit_hit);
        assert!(
            analysis.scanned_positions
                <= MAX_ZIP64_RECORD_SCAN_BYTES
                    .saturating_add(ZIP_MAX_COMMENT_BYTES)
                    .saturating_add(64),
            "ZIP64 index exceeded its global byte-position budget: {}",
            analysis.scanned_positions
        );
    }

    #[test]
    fn valid_zip64_before_many_false_eocds_remains_ambiguous_with_one_scan() {
        const FALSE_EOCDS: usize = 1_500;
        let mut bytes = pdf_with_trailing_zip64();
        let real_eocd = bytes.len() - ZIP_EOCD_BYTES;
        let tail_bytes = FALSE_EOCDS * (ZIP64_LOCATOR_BYTES + ZIP_EOCD_BYTES);
        assert!(tail_bytes <= ZIP_MAX_COMMENT_BYTES);
        bytes[real_eocd + 20..real_eocd + 22].copy_from_slice(&(tail_bytes as u16).to_le_bytes());
        append_false_zip64_eocd_comment_tail(&mut bytes, FALSE_EOCDS);

        let classification = classify_with_ambiguity(&bytes);
        let analysis = trailing_zip_analysis(&bytes);

        assert_eq!(classification.kind, ContentKind::Pdf);
        assert!(classification.ambiguous_pdf_ownership);
        assert!(analysis.offset.is_some());
        assert!(
            analysis.scanned_positions
                <= MAX_ZIP64_RECORD_SCAN_BYTES
                    .saturating_add(ZIP_MAX_COMMENT_BYTES)
                    .saturating_add(64),
            "ZIP64 index exceeded its global byte-position budget: {}",
            analysis.scanned_positions
        );
    }

    #[test]
    fn invalid_nested_zip64_record_cannot_shadow_valid_enclosing_record() {
        let mut bytes = pdf_with_trailing_zip64();
        let record = bytes
            .windows(4)
            .position(|window| window == b"PK\x06\x06")
            .unwrap();
        let locator = bytes
            .windows(4)
            .position(|window| window == b"PK\x06\x07")
            .unwrap();

        // Grow the valid outer record by 64 extensible-data bytes, then place
        // a second exact-end record inside that extension. The nested record
        // is visited first by the reverse index scan but deliberately has
        // incoherent directory fields.
        bytes.splice(locator..locator, [0u8; 64]);
        let shifted_locator = locator + 64;
        bytes[record + 4..record + 12].copy_from_slice(&108u64.to_le_bytes());
        let nested = shifted_locator - ZIP64_RECORD_BASE_BYTES;
        bytes[nested..nested + 4].copy_from_slice(b"PK\x06\x06");
        bytes[nested + 4..nested + 12].copy_from_slice(&44u64.to_le_bytes());

        let classification = classify_with_ambiguity(&bytes);
        let analysis = trailing_zip_analysis(&bytes);
        assert_eq!(classification.kind, ContentKind::Pdf);
        assert!(classification.ambiguous_pdf_ownership);
        assert!(analysis.offset.is_some());
    }

    #[test]
    fn fake_zip64_sentinels_overflow_and_offset_mismatch_stay_exclusive_pdf() {
        let mut sentinels_without_locator = b"%PDF-1.7\n%%EOF\n".to_vec();
        let mut eocd = [0u8; 22];
        eocd[..4].copy_from_slice(b"PK\x05\x06");
        eocd[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
        eocd[10..12].copy_from_slice(&u16::MAX.to_le_bytes());
        eocd[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        eocd[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        sentinels_without_locator.extend_from_slice(&eocd);

        let mut overflowing_record = pdf_with_trailing_zip64();
        let record = overflowing_record
            .windows(4)
            .position(|window| window == b"PK\x06\x06")
            .unwrap();
        overflowing_record[record + 4..record + 12].copy_from_slice(&u64::MAX.to_le_bytes());

        let mut mismatched_locator = pdf_with_trailing_zip64();
        let locator = mismatched_locator
            .windows(4)
            .position(|window| window == b"PK\x06\x07")
            .unwrap();
        mismatched_locator[locator + 8..locator + 16].copy_from_slice(&u64::MAX.to_le_bytes());

        for bytes in [
            sentinels_without_locator,
            overflowing_record,
            mismatched_locator,
        ] {
            let classification = classify_with_ambiguity(&bytes);
            assert_eq!(classification.kind, ContentKind::Pdf);
            assert!(!classification.ambiguous_pdf_ownership);
        }
    }

    #[test]
    fn malformed_eocd_signature_inside_zip_comment_does_not_hide_real_archive() {
        let mut bytes = pdf_with_trailing_zip();
        let real_eocd = bytes.len() - 22;
        bytes[real_eocd + 20..real_eocd + 22].copy_from_slice(&22u16.to_le_bytes());
        let mut fake = vec![0u8; 22];
        fake[..4].copy_from_slice(b"PK\x05\x06");
        fake[8..10].copy_from_slice(&1u16.to_le_bytes());
        fake[10..12].copy_from_slice(&1u16.to_le_bytes());
        fake[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&fake);

        assert_locked_zip_reader_accepts(&bytes, "comment with false EOCD signature");
        assert!(classify_with_ambiguity(&bytes).ambiguous_pdf_ownership);
    }

    #[test]
    fn pdf_marker_outside_prefix_is_not_magic() {
        let mut bytes = vec![b'x'; MAGIC_PREFIX_BYTES + 1];
        bytes.extend_from_slice(b"%PDF-1.7");
        assert_eq!(classify(&bytes), ContentKind::Text);
    }

    #[test]
    fn shared_archive_magic_matches_file_dispatch() {
        for (bytes, archive, content) in [
            (
                b"PK\x03\x04rest".as_slice(),
                ArchiveMagic::Zip,
                ContentKind::Zip,
            ),
            (
                b"PK\x05\x06".as_slice(),
                ArchiveMagic::Zip,
                ContentKind::Zip,
            ),
            (
                b"\x1f\x8brest".as_slice(),
                ArchiveMagic::Gzip,
                ContentKind::Gzip,
            ),
        ] {
            assert_eq!(classify_archive_prefix(bytes), archive);
            assert_eq!(classify(bytes), content);
        }
    }

    #[test]
    fn shared_native_magic_preserves_macho_shape() {
        let cases = [
            (b"\x7fELF".as_slice(), NativeMagic::Elf, ContentKind::Elf),
            (
                &[0xfe, 0xed, 0xfa, 0xcf][..],
                NativeMagic::MachO,
                ContentKind::MachO,
            ),
            (
                &[0xca, 0xfe, 0xba, 0xbe][..],
                NativeMagic::MachOFat,
                ContentKind::MachO,
            ),
        ];
        for (bytes, native, content) in cases {
            assert_eq!(classify_native_prefix(bytes), native);
            assert_eq!(classify(bytes), content);
        }

        let mut pe = vec![0u8; 0x80];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        assert_eq!(classify_native_prefix(&pe), NativeMagic::Pe);
        assert_eq!(classify(&pe), ContentKind::Pe);
    }

    #[test]
    fn mz_text_without_a_valid_pe_header_stays_text() {
        let text = b"MZ is the title of this ordinary UTF-8 document";
        assert_eq!(classify_native_prefix(text), NativeMagic::Unknown);
        assert_eq!(classify(text), ContentKind::Text);
    }
}
