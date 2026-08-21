use std::collections::BTreeSet;
use std::io::{BufRead, Read, Seek};
use std::net::Ipv4Addr;

use crate::threatdb::BehaviorTag;

/// Hard decoded-input ceiling for one remotely sourced threat-intelligence feed.
/// Parsers enforce this while reading, so a missing or false Content-Length does
/// not turn a feed into an unbounded allocation.
pub const MAX_FEED_INPUT_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum logical records consumed from one feed.
pub const MAX_FEED_RECORDS: usize = 1_000_000;
/// Maximum columns accepted in one CSV record.
pub const MAX_FEED_FIELDS: usize = 128;
/// Maximum UTF-8 bytes accepted in one field/line.
pub const MAX_FEED_FIELD_BYTES: usize = 16 * 1024;
/// Maximum unique host/IP indicators returned by one parser or accumulated into
/// the supplemental overlay.
pub const MAX_FEED_ENTRIES: usize = 250_000;
const MAX_FEED_ARCHIVE_MEMBERS: usize = 128;

#[derive(Clone, Copy)]
struct FeedLimits {
    input_bytes: u64,
    records: usize,
    fields: usize,
    field_bytes: usize,
    entries: usize,
}

const DEFAULT_FEED_LIMITS: FeedLimits = FeedLimits {
    input_bytes: MAX_FEED_INPUT_BYTES,
    records: MAX_FEED_RECORDS,
    fields: MAX_FEED_FIELDS,
    field_bytes: MAX_FEED_FIELD_BYTES,
    entries: MAX_FEED_ENTRIES,
};

/// Reader that permits at most `remaining` bytes and probes once at the
/// boundary. Unlike `Read::take`, excess input is an error rather than a
/// successful truncated EOF.
struct CappedReader<R> {
    inner: R,
    remaining: u64,
}

impl<R> CappedReader<R> {
    fn new(inner: R, remaining: u64) -> Self {
        Self { inner, remaining }
    }
}

impl<R: Read> Read for CappedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "threat-intelligence feed exceeds decoded input limit",
                )),
            };
        }
        let allowed = usize::try_from(self.remaining.min(buf.len() as u64)).unwrap_or(buf.len());
        let read = self.inner.read(&mut buf[..allowed])?;
        self.remaining = self.remaining.saturating_sub(read as u64);
        Ok(read)
    }
}

#[derive(Default)]
struct FeedAccumulator {
    hostnames: BTreeSet<String>,
    ips: BTreeSet<Ipv4Addr>,
}

impl FeedAccumulator {
    fn len(&self) -> usize {
        self.hostnames.len() + self.ips.len()
    }

    fn add_hostname(
        &mut self,
        hostname: String,
        feed: &str,
        limits: FeedLimits,
    ) -> Result<(), String> {
        if !self.hostnames.contains(&hostname) && self.len() >= limits.entries {
            return Err(format!(
                "{feed} exceeds the unique-indicator limit of {}",
                limits.entries
            ));
        }
        self.hostnames.insert(hostname);
        Ok(())
    }

    fn add_ip(&mut self, ip: Ipv4Addr, feed: &str, limits: FeedLimits) -> Result<(), String> {
        if !self.ips.contains(&ip) && self.len() >= limits.entries {
            return Err(format!(
                "{feed} exceeds the unique-indicator limit of {}",
                limits.entries
            ));
        }
        self.ips.insert(ip);
        Ok(())
    }

    fn finish(self) -> FeedEntries {
        FeedEntries {
            hostnames: self.hostnames.into_iter().collect(),
            ips: self.ips.into_iter().collect(),
        }
    }
}

fn validate_record(
    feed: &str,
    record_number: usize,
    record: &csv::StringRecord,
    limits: FeedLimits,
) -> Result<(), String> {
    if record_number > limits.records {
        return Err(format!(
            "{feed} exceeds the record limit of {}",
            limits.records
        ));
    }
    if record.len() > limits.fields {
        return Err(format!(
            "{feed} record {record_number} has {} fields (max {})",
            record.len(),
            limits.fields
        ));
    }
    if let Some(field) = record.iter().find(|field| field.len() > limits.field_bytes) {
        return Err(format!(
            "{feed} record {record_number} has a {}-byte field (max {})",
            field.len(),
            limits.field_bytes
        ));
    }
    Ok(())
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FeedEntries {
    pub hostnames: Vec<String>,
    pub ips: Vec<Ipv4Addr>,
}

impl FeedEntries {
    pub fn sort_and_dedup(&mut self) {
        self.hostnames.sort();
        self.hostnames.dedup();
        self.ips.sort();
        self.ips.dedup();
    }
}

pub fn extract_hostname_from_url(raw: &str) -> Option<String> {
    let parsed = url::Url::parse(raw).ok()?;
    parsed.host_str().map(|host| host.to_ascii_lowercase())
}

pub fn parse_urlhaus_csv<R: Read>(reader: R) -> Result<FeedEntries, String> {
    parse_urlhaus_csv_with_limits(reader, DEFAULT_FEED_LIMITS)
}

fn parse_urlhaus_csv_with_limits<R: Read>(
    reader: R,
    limits: FeedLimits,
) -> Result<FeedEntries, String> {
    let mut csv = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(false)
        .from_reader(CappedReader::new(reader, limits.input_bytes));
    let headers = csv
        .headers()
        .map_err(|e| format!("URLhaus headers: {e}"))?
        .clone();
    validate_record("URLhaus", 0, &headers, limits)?;

    let url_idx = headers
        .iter()
        .position(|header| matches!(header, "url" | "urlhaus_link"))
        .ok_or_else(|| format!("URLhaus schema error: no 'url' column in headers {headers:?}"))?;

    let mut entries = FeedAccumulator::default();
    for (index, record) in csv.records().enumerate() {
        let record = record.map_err(|e| format!("URLhaus record error: {e}"))?;
        validate_record("URLhaus", index + 1, &record, limits)?;
        let raw = record.get(url_idx).or_else(|| {
            record
                .iter()
                .find(|value| value.starts_with("http://") || value.starts_with("https://"))
        });
        if let Some(host) = raw.and_then(extract_hostname_from_url) {
            entries.add_hostname(host, "URLhaus", limits)?;
        }
    }
    Ok(entries.finish())
}

pub fn parse_threatfox_csv<R: Read>(reader: R) -> Result<FeedEntries, String> {
    parse_threatfox_csv_with_limits(reader, DEFAULT_FEED_LIMITS)
}

fn parse_threatfox_csv_with_limits<R: Read>(
    reader: R,
    limits: FeedLimits,
) -> Result<FeedEntries, String> {
    let mut csv = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(false)
        .from_reader(CappedReader::new(reader, limits.input_bytes));
    let headers = csv
        .headers()
        .map_err(|e| format!("ThreatFox headers: {e}"))?
        .clone();
    validate_record("ThreatFox", 0, &headers, limits)?;

    let ioc_idx = headers.iter().position(|header| header == "ioc");
    let ioc_type_idx = headers.iter().position(|header| header == "ioc_type");
    let ioc_idx = ioc_idx
        .ok_or_else(|| format!("ThreatFox schema error: no 'ioc' column in headers {headers:?}"))?;

    let mut entries = FeedAccumulator::default();
    for (index, record) in csv.records().enumerate() {
        let record = record.map_err(|e| format!("ThreatFox record error: {e}"))?;
        validate_record("ThreatFox", index + 1, &record, limits)?;

        let raw_ioc = record.get(ioc_idx).or_else(|| {
            record.iter().find(|value| {
                value.contains('.') || value.starts_with("http://") || value.starts_with("https://")
            })
        });
        let raw_ioc = match raw_ioc {
            Some(value) if !value.is_empty() => value.trim(),
            _ => continue,
        };

        let ioc_type = ioc_type_idx
            .and_then(|idx| record.get(idx))
            .map(|value| value.to_ascii_lowercase())
            .unwrap_or_default();

        if raw_ioc.starts_with("http://") || raw_ioc.starts_with("https://") {
            if let Some(host) = extract_hostname_from_url(raw_ioc) {
                entries.add_hostname(host, "ThreatFox", limits)?;
            }
            continue;
        }

        if matches!(ioc_type.as_str(), "ip:port" | "ip_port") {
            let ip_part = raw_ioc.split(':').next().unwrap_or(raw_ioc);
            if let Ok(ip) = ip_part.parse::<Ipv4Addr>() {
                entries.add_ip(ip, "ThreatFox", limits)?;
            }
            continue;
        }

        if let Ok(ip) = raw_ioc.parse::<Ipv4Addr>() {
            entries.add_ip(ip, "ThreatFox", limits)?;
            continue;
        }

        if !raw_ioc.contains('/') && raw_ioc.contains('.') {
            entries.add_hostname(raw_ioc.to_ascii_lowercase(), "ThreatFox", limits)?;
        }
    }

    Ok(entries.finish())
}

pub fn parse_threatfox_zip<R: Read + Seek>(reader: R) -> Result<FeedEntries, String> {
    let mut archive =
        zip::ZipArchive::new(reader).map_err(|e| format!("ThreatFox ZIP open failed: {e}"))?;
    if archive.len() > MAX_FEED_ARCHIVE_MEMBERS {
        return Err(format!(
            "ThreatFox ZIP contains {} members (max {MAX_FEED_ARCHIVE_MEMBERS})",
            archive.len()
        ));
    }
    for idx in 0..archive.len() {
        let file = archive
            .by_index(idx)
            .map_err(|e| format!("ThreatFox ZIP read failed: {e}"))?;
        if !file.name().ends_with(".csv") {
            continue;
        }

        // Stream the decompressed member directly into the bounded CSV parser;
        // never materialize a second 512 MiB buffer.
        if file.size() > MAX_FEED_INPUT_BYTES {
            return Err(format!(
                "ThreatFox CSV exceeds {} MiB decompressed size limit",
                MAX_FEED_INPUT_BYTES / (1024 * 1024)
            ));
        }
        return parse_threatfox_csv(file).map_err(|e| format!("ThreatFox CSV parse failed: {e}"));
    }

    Err("ThreatFox ZIP did not contain a CSV payload".to_string())
}

pub fn parse_phishtank_csv<R: Read>(reader: R) -> Result<FeedEntries, String> {
    parse_phishtank_csv_with_limits(reader, DEFAULT_FEED_LIMITS)
}

fn parse_phishtank_csv_with_limits<R: Read>(
    reader: R,
    limits: FeedLimits,
) -> Result<FeedEntries, String> {
    let mut csv = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(false)
        .from_reader(CappedReader::new(reader, limits.input_bytes));
    let headers = csv
        .headers()
        .map_err(|e| format!("PhishTank headers: {e}"))?
        .clone();
    validate_record("PhishTank", 0, &headers, limits)?;
    let url_idx = headers
        .iter()
        .position(|header| header == "url")
        .ok_or_else(|| format!("PhishTank schema error: no 'url' column in headers {headers:?}"))?;

    let mut entries = FeedAccumulator::default();
    for (index, record) in csv.records().enumerate() {
        let record = record.map_err(|e| format!("PhishTank record error: {e}"))?;
        validate_record("PhishTank", index + 1, &record, limits)?;
        if let Some(host) = record.get(url_idx).and_then(extract_hostname_from_url) {
            entries.add_hostname(host, "PhishTank", limits)?;
        }
    }
    Ok(entries.finish())
}

/// Parse a DigitalSide Threat-Intel MISP-style CSV export.
///
/// The upstream feed (davidonzo/Threat-Intel) exports one MISP attribute per
/// row in the standard MISP CSV shape:
///
/// ```text
/// uuid,event_id,category,type,value,comment,to_ids,date,object_relation,...
/// ```
///
/// MISP semantics enforced here:
/// * Only rows with `to_ids=1` are ingested (an analyst has flagged the
///   attribute as a detectable indicator); `to_ids=0` context rows are dropped.
/// * Only network-indicator `type`s are ingested: `url` (mapped through
///   [`extract_hostname_from_url`]), `domain` / `hostname` (taken directly), and
///   `ip-src` / `ip-dst` (parsed as IPv4). Every other type -- `filename`,
///   `md5` / `sha1` / `sha256`, `mime-type`, `comment`, and so on -- is skipped,
///   so a file name or a hash is never mistaken for a host or IP.
///
/// The header row is detected rather than assumed: if the first row carries the
/// `type` / `value` / `to_ids` column names it sets the column positions and is
/// skipped; otherwise the fixed MISP layout (`type` = 3, `value` = 4,
/// `to_ids` = 6) is used and that first row is ingested as a real indicator, so a
/// headerless export never silently drops its first record. Scope is v1 hostnames
/// plus IPv4; file-hash ingestion is deferred to a follow-up (the
/// `CuratedFileHashes` path).
pub fn parse_digitalside_csv<R: Read>(reader: R) -> Result<FeedEntries, String> {
    parse_digitalside_csv_with_limits(reader, DEFAULT_FEED_LIMITS)
}

fn parse_digitalside_csv_with_limits<R: Read>(
    reader: R,
    limits: FeedLimits,
) -> Result<FeedEntries, String> {
    // has_headers(false) so we detect the header ourselves. has_headers(true)
    // would consume the first row of a headerless export as the header and drop
    // that indicator.
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(false)
        .from_reader(CappedReader::new(reader, limits.input_bytes));
    let mut records = rdr.records();

    let first = match records.next() {
        Some(Ok(record)) => record,
        Some(Err(e)) => return Err(format!("DigitalSide first record: {e}")),
        None => return Ok(FeedEntries::default()),
    };
    validate_record("DigitalSide", 1, &first, limits)?;
    let has_header = first.iter().any(|field| field == "type")
        && first.iter().any(|field| field == "value")
        && first.iter().any(|field| field == "to_ids");
    let (type_idx, value_idx, to_ids_idx) = if has_header {
        (
            first.iter().position(|field| field == "type").unwrap_or(3),
            first.iter().position(|field| field == "value").unwrap_or(4),
            first
                .iter()
                .position(|field| field == "to_ids")
                .unwrap_or(6),
        )
    } else {
        // Fixed MISP column layout when the export has no header row.
        (3, 4, 6)
    };

    // Skip the first row only if it was the header; a headerless export's first
    // row is a real indicator and is ingested with the rest.
    let leading = if has_header { None } else { Some(Ok(first)) };

    let mut entries = FeedAccumulator::default();
    for (index, record) in leading.into_iter().chain(records).enumerate() {
        let record = record.map_err(|e| format!("DigitalSide record error: {e}"))?;
        // `index == 0` may be the already-validated leading record for a
        // headerless export; validating it twice is harmless and keeps the
        // logical-record budget uniform.
        validate_record("DigitalSide", index + 1, &record, limits)?;

        // MISP `to_ids` gate: ingest only analyst-flagged detectable indicators.
        if record.get(to_ids_idx).map(str::trim) != Some("1") {
            continue;
        }

        let ioc_type = match record.get(type_idx) {
            Some(value) => value.trim().to_ascii_lowercase(),
            None => continue,
        };
        let value = match record.get(value_idx) {
            Some(value) => value.trim(),
            None => continue,
        };
        if value.is_empty() {
            continue;
        }

        match ioc_type.as_str() {
            "url" => {
                if let Some(host) = extract_hostname_from_url(value) {
                    entries.add_hostname(host, "DigitalSide", limits)?;
                }
            }
            // A domain/hostname attribute is a bare host; the guard rejects a
            // stray URL sneaking into the field before it is stored.
            "domain" | "hostname" if !value.contains('/') => {
                entries.add_hostname(value.to_ascii_lowercase(), "DigitalSide", limits)?;
            }
            "ip-src" | "ip-dst" => {
                if let Ok(ip) = value.parse::<Ipv4Addr>() {
                    entries.add_ip(ip, "DigitalSide", limits)?;
                }
            }
            // filename, md5/sha*, mime-type, comment, and every other type are
            // deliberately not network indicators and are skipped.
            _ => {}
        }
    }

    Ok(entries.finish())
}

pub fn parse_domain_blocklist(contents: &str) -> FeedEntries {
    let mut entries = FeedEntries::default();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Strip inline `#` comments, then take the last token (handles the
        // "0.0.0.0 bad.example" hosts format).
        let token = line
            .split_whitespace()
            .take_while(|value| !value.starts_with('#'))
            .last()
            .unwrap_or(line);

        if token.eq_ignore_ascii_case("localhost") || token.starts_with("127.") {
            continue;
        }

        if token.contains('.') && !token.contains('/') {
            entries.hostnames.push(token.to_ascii_lowercase());
        }
    }
    entries.sort_and_dedup();
    entries
}

/// Streaming, fail-closed form of [`parse_domain_blocklist`] for remote feeds.
/// The compatibility wrapper above remains infallible for curated local files;
/// network consumers must use this entry point so excess records/fields/input
/// preserve the last-known-good overlay instead of publishing a prefix.
pub fn parse_domain_blocklist_reader<R: Read>(reader: R) -> Result<FeedEntries, String> {
    parse_domain_blocklist_reader_with_limits(reader, DEFAULT_FEED_LIMITS)
}

fn parse_domain_blocklist_reader_with_limits<R: Read>(
    reader: R,
    limits: FeedLimits,
) -> Result<FeedEntries, String> {
    let reader = std::io::BufReader::new(CappedReader::new(reader, limits.input_bytes));
    let mut entries = FeedAccumulator::default();
    for (index, line) in reader.split(b'\n').enumerate() {
        let line = line.map_err(|error| format!("domain blocklist read failed: {error}"))?;
        let record_number = index + 1;
        if record_number > limits.records {
            return Err(format!(
                "domain blocklist exceeds the record limit of {}",
                limits.records
            ));
        }
        if line.len() > limits.field_bytes {
            return Err(format!(
                "domain blocklist record {record_number} has a {}-byte field (max {})",
                line.len(),
                limits.field_bytes
            ));
        }
        let line = std::str::from_utf8(&line)
            .map_err(|error| format!("domain blocklist is not UTF-8: {error}"))?
            .trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let token = line
            .split_whitespace()
            .take_while(|value| !value.starts_with('#'))
            .last()
            .unwrap_or(line);
        if token.eq_ignore_ascii_case("localhost") || token.starts_with("127.") {
            continue;
        }
        if token.contains('.') && !token.contains('/') {
            entries.add_hostname(token.to_ascii_lowercase(), "domain blocklist", limits)?;
        }
    }
    Ok(entries.finish())
}

/// Parse a curated exfiltration-endpoint / webhook-catcher hostname list.
///
/// The on-disk format is a plain domain-per-line blocklist (one hostname per
/// line, `#` comments and blank lines ignored, hosts-file `0.0.0.0 host` lines
/// tolerated), so this is a thin wrapper over [`parse_domain_blocklist`]. It
/// exists as a distinct entry point so the compiler call site reads clearly and
/// the feed can grow its own parsing rules later without disturbing the shared
/// blocklist parser. Output goes into `FeedEntries.hostnames`.
pub fn parse_exfil_endpoint_list(contents: &str) -> FeedEntries {
    parse_domain_blocklist(contents)
}

/// Registry-provenance marker for one curated file-hash record.
///
/// The plan sources removal/yank state "from a registry-provenance feed (not
/// assumed OpenSSF)", so a record can attest either that the bytes are a
/// known-malicious analysis/file artifact (OSSF-derived) or that a registry
/// has yanked/removed the distribution the bytes came from. Both are carried
/// on the same v2 file-hash record (there is no separate on-disk yank section
/// and G1 must not bump the format); the marker only records WHERE the
/// provenance came from for the compile-time log and so the two feeds stay
/// distinguishable at ingestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileHashProvenance {
    /// Derived from the OpenSSF malicious-packages corpus / a curated analysis
    /// feed: the file content itself is known-malicious.
    OssfMalicious,
    /// Sourced from a registry-provenance (yank/removal) feed: the registry
    /// pulled the distribution these bytes belong to.
    RegistryYank,
}

/// One parsed entry from the curated file-hash companion feed.
///
/// `behavior_tags` and `campaign` are taken ONLY from the explicit structured
/// `tags=` / `campaign=` fields of the feed line. They are never inferred from
/// free text: the OSV `details`/`summary` prose is deliberately not a source
/// here (the plan forbids scraping behavior tags from advisory prose). The
/// `sha256` is the validated 32-byte content digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CuratedFileHash {
    pub sha256: [u8; 32],
    pub behavior_tags: Vec<BehaviorTag>,
    pub campaign: Option<String>,
    pub provenance: FileHashProvenance,
}

/// Outcome of parsing a curated file-hash feed: the accepted records plus the
/// counts of lines dropped for a bad digest or an unrecognized tag token. The
/// caller logs the drop counts (so a malformed feed is observable, not silent).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CuratedFileHashes {
    pub records: Vec<CuratedFileHash>,
    /// Lines dropped because the first field was not a 64-char hex SHA-256.
    pub skipped_bad_sha: usize,
    /// Tag tokens dropped because no `BehaviorTag` matched the name.
    pub skipped_unknown_tags: usize,
}

fn decode_feed_sha256(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Parse the curated malicious file-hash companion feed.
///
/// Format (one record per line; `#` comments and blank lines ignored):
///
/// ```text
/// <sha256-hex>  tags=process_spawn,network_exfil  campaign=miasma  source=ossf
/// <sha256-hex>  source=registry-yank
/// ```
///
/// The first whitespace-delimited token is the content SHA-256. The remaining
/// `key=value` tokens are order-independent and all optional:
/// * `tags=` a comma list of stable `BehaviorTag` names (see
///   [`BehaviorTag::from_name`]); unknown names are dropped and counted.
/// * `campaign=` a campaign label, interned into the v2 campaign string table.
/// * `source=` `ossf` (default) or `registry-yank` -> [`FileHashProvenance`].
///
/// This feeds [`crate::threatdb::ThreatDbWriter::add_file_sha256`] so the v2
/// `FileHash` + `BehaviorTags` sections go live. It is a SUPERSET-safe pure
/// parser: nothing here reads advisory prose, and a record with no `tags=` is
/// valid (the file hash alone is the indicator; tags are enrichment).
pub fn parse_curated_file_hashes(contents: &str) -> CuratedFileHashes {
    let mut out = CuratedFileHashes::default();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut fields = line.split_whitespace();
        let Some(sha_token) = fields.next() else {
            continue;
        };
        let Some(sha256) = decode_feed_sha256(sha_token) else {
            out.skipped_bad_sha += 1;
            continue;
        };

        let mut behavior_tags: Vec<BehaviorTag> = Vec::new();
        let mut campaign: Option<String> = None;
        let mut provenance = FileHashProvenance::OssfMalicious;

        for field in fields {
            let Some((key, value)) = field.split_once('=') else {
                continue;
            };
            match key {
                "tags" => {
                    for tag in value.split(',').filter(|t| !t.trim().is_empty()) {
                        match BehaviorTag::from_name(tag) {
                            Some(t) => {
                                if !behavior_tags.contains(&t) {
                                    behavior_tags.push(t);
                                }
                            }
                            None => out.skipped_unknown_tags += 1,
                        }
                    }
                }
                "campaign" => {
                    let label = value.trim();
                    if !label.is_empty() {
                        campaign = Some(label.to_string());
                    }
                }
                "source" => {
                    provenance = match value.trim().to_ascii_lowercase().as_str() {
                        "registry-yank" | "registry_yank" | "yank" => {
                            FileHashProvenance::RegistryYank
                        }
                        _ => FileHashProvenance::OssfMalicious,
                    };
                }
                _ => {}
            }
        }

        out.records.push(CuratedFileHash {
            sha256,
            behavior_tags,
            campaign,
            provenance,
        });
    }
    out
}

pub fn parse_tor_exit_list(contents: &str) -> FeedEntries {
    let mut entries = FeedEntries::default();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(ip) = line.parse::<Ipv4Addr>() {
            entries.ips.push(ip);
        }
    }
    entries.sort_and_dedup();
    entries
}

/// Streaming, bounded Tor-exit parser for remote supplemental updates.
pub fn parse_tor_exit_list_reader<R: Read>(reader: R) -> Result<FeedEntries, String> {
    parse_tor_exit_list_reader_with_limits(reader, DEFAULT_FEED_LIMITS)
}

fn parse_tor_exit_list_reader_with_limits<R: Read>(
    reader: R,
    limits: FeedLimits,
) -> Result<FeedEntries, String> {
    let reader = std::io::BufReader::new(CappedReader::new(reader, limits.input_bytes));
    let mut entries = FeedAccumulator::default();
    for (index, line) in reader.split(b'\n').enumerate() {
        let line = line.map_err(|error| format!("Tor exit feed read failed: {error}"))?;
        let record_number = index + 1;
        if record_number > limits.records {
            return Err(format!(
                "Tor exit feed exceeds the record limit of {}",
                limits.records
            ));
        }
        if line.len() > limits.field_bytes {
            return Err(format!(
                "Tor exit record {record_number} has a {}-byte field (max {})",
                line.len(),
                limits.field_bytes
            ));
        }
        let line = std::str::from_utf8(&line)
            .map_err(|error| format!("Tor exit feed is not UTF-8: {error}"))?
            .trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(ip) = line.parse::<Ipv4Addr>() {
            entries.add_ip(ip, "Tor exit feed", limits)?;
        }
    }
    Ok(entries.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    #[test]
    fn urlhaus_csv_extracts_hostnames() {
        let csv = "id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n1,2024-01-01,https://evil.example/path,online,2024-01-01,payload,,https://urlhaus.abuse.ch/url/1/,test\n";
        let entries = parse_urlhaus_csv(csv.as_bytes()).unwrap();
        assert_eq!(entries.hostnames, vec!["evil.example".to_string()]);
    }

    #[test]
    fn threatfox_csv_extracts_domains_and_ips() {
        let csv = "ioc,ioc_type\nbad.example,domain\n203.0.113.25,ip\n198.51.100.9:443,ip:port\nhttps://c2.example/payload,url\n";
        let entries = parse_threatfox_csv(csv.as_bytes()).unwrap();
        assert!(entries.hostnames.contains(&"bad.example".to_string()));
        assert!(entries.hostnames.contains(&"c2.example".to_string()));
        assert!(entries.ips.contains(&Ipv4Addr::new(203, 0, 113, 25)));
        assert!(entries.ips.contains(&Ipv4Addr::new(198, 51, 100, 9)));
    }

    #[test]
    fn threatfox_zip_extracts_domains_and_ips() {
        let cursor = Cursor::new(Vec::<u8>::new());
        let mut writer = zip::ZipWriter::new(cursor);
        writer
            .start_file("full.csv", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer
            .write_all(
                b"ioc,ioc_type\nbad.example,domain\n203.0.113.25,ip\nhttps://c2.example/payload,url\n",
            )
            .unwrap();
        let cursor = writer.finish().unwrap();

        let entries = parse_threatfox_zip(Cursor::new(cursor.into_inner())).unwrap();
        assert!(entries.hostnames.contains(&"bad.example".to_string()));
        assert!(entries.hostnames.contains(&"c2.example".to_string()));
        assert!(entries.ips.contains(&Ipv4Addr::new(203, 0, 113, 25)));
    }

    #[test]
    fn phishtank_csv_extracts_url_column() {
        let csv = "phish_id,url,detail_url\n1,https://phish.example/login,https://phishtank.org/phish/1\n";
        let entries = parse_phishtank_csv(csv.as_bytes()).unwrap();
        assert_eq!(entries.hostnames, vec!["phish.example".to_string()]);
    }

    // Standard MISP CSV export header used by the DigitalSide feed.
    const DIGITALSIDE_HEADER: &str = "uuid,event_id,category,type,value,comment,to_ids,date,object_relation,attribute_tag,object_uuid,object_name,object_meta_category";

    #[test]
    fn digitalside_csv_ingests_only_network_indicators_with_to_ids() {
        // MISP-style rows using synthetic RFC-2606 hosts and RFC-5737 IPs, in the
        // real quoted export shape (string fields quoted, numerics bare).
        let rows = [
            // Ingested: to_ids=1 network indicators (url/domain/hostname/ip-src/ip-dst).
            r#""u1",100,"Network activity","url","http://malware.example/x","",1,1728745084,"","","","","""#,
            r#""u2",100,"Network activity","domain","evil.example","",1,1728745084,"","","","","""#,
            r#""u3",100,"Network activity","hostname","c2.evil.example","",1,1728745084,"","","","","""#,
            r#""u4",100,"Network activity","ip-src","192.0.2.10","",1,1728745084,"","","","","""#,
            r#""u5",100,"Network activity","ip-dst","198.51.100.20","",1,1728745084,"","","","","""#,
            // Dropped: to_ids=0 context row, even though it is a domain.
            r#""u6",100,"Network activity","domain","benign-context.example","",0,1728745084,"","","","","""#,
            // Dropped: non-network types, even with to_ids=1. A filename that
            // happens to look like a host must NOT become a hostname.
            r#""u7",100,"Payload delivery","filename","dropper.example","",1,1728745084,"","","","","""#,
            r#""u8",100,"Payload delivery","md5","d41d8cd98f00b204e9800998ecf8427e","",1,1728745084,"","","","","""#,
            r#""u9",100,"Payload delivery","sha256","e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","",1,1728745084,"","","","","""#,
            r#""u10",100,"Other","comment","see evil.example for details","",1,1728745084,"","","","","""#,
        ];
        let csv = format!("{DIGITALSIDE_HEADER}\n{}\n", rows.join("\n"));
        let entries = parse_digitalside_csv(csv.as_bytes()).unwrap();

        // Hostnames come out sorted+deduped: url host, domain, and hostname only.
        assert_eq!(
            entries.hostnames,
            vec![
                "c2.evil.example".to_string(),
                "evil.example".to_string(),
                "malware.example".to_string(),
            ],
        );
        assert_eq!(
            entries.ips,
            vec![
                Ipv4Addr::new(192, 0, 2, 10),
                Ipv4Addr::new(198, 51, 100, 20)
            ],
        );
        // The to_ids=0 domain, the filename, the hashes, and the comment produced
        // no host: a non-network attribute is never ingested as an indicator.
        assert!(!entries
            .hostnames
            .contains(&"benign-context.example".to_string()));
        assert!(!entries.hostnames.contains(&"dropper.example".to_string()));
    }

    #[test]
    fn digitalside_csv_dedups_repeated_indicators() {
        let rows = [
            r#""u1",100,"Network activity","domain","dup.example","",1,1728745084,"","","","","""#,
            r#""u2",100,"Network activity","domain","dup.example","",1,1728745084,"","","","","""#,
            // Same host reached via a url attribute; must fold into one entry.
            r#""u3",100,"Network activity","url","http://dup.example/other","",1,1728745084,"","","","","""#,
            r#""u4",100,"Network activity","ip-dst","203.0.113.5","",1,1728745084,"","","","","""#,
            r#""u5",100,"Network activity","ip-dst","203.0.113.5","",1,1728745084,"","","","","""#,
        ];
        let csv = format!("{DIGITALSIDE_HEADER}\n{}\n", rows.join("\n"));
        let entries = parse_digitalside_csv(csv.as_bytes()).unwrap();
        assert_eq!(entries.hostnames, vec!["dup.example".to_string()]);
        assert_eq!(entries.ips, vec![Ipv4Addr::new(203, 0, 113, 5)]);
    }

    #[test]
    fn digitalside_csv_drops_to_ids_zero_rows() {
        // A single to_ids=0 row yields nothing: the MISP flag gate is required.
        let rows = [
            r#""u1",100,"Network activity","domain","context-only.example","",0,1728745084,"","","","","""#,
        ];
        let csv = format!("{DIGITALSIDE_HEADER}\n{}\n", rows.join("\n"));
        let entries = parse_digitalside_csv(csv.as_bytes()).unwrap();
        assert!(entries.hostnames.is_empty());
        assert!(entries.ips.is_empty());
    }

    #[test]
    fn digitalside_csv_headerless_export_keeps_first_indicator() {
        // A headerless export (no type/value/to_ids header row) must ingest its
        // first row instead of consuming it as a header. Column positions fall
        // back to the fixed MISP layout (type=3, value=4, to_ids=6).
        let rows = [
            r#""u1",100,"Network activity","domain","first.example","",1,1728745084,"","","","","""#,
            r#""u2",100,"Network activity","ip-dst","192.0.2.7","",1,1728745084,"","","","","""#,
        ];
        let csv = format!("{}\n", rows.join("\n"));
        let entries = parse_digitalside_csv(csv.as_bytes()).unwrap();
        // The first indicator is not swallowed as a header.
        assert_eq!(entries.hostnames, vec!["first.example".to_string()]);
        assert_eq!(entries.ips, vec![Ipv4Addr::new(192, 0, 2, 7)]);
    }

    #[test]
    fn domain_blocklist_parses_hosts_like_lines() {
        let contents = "# comment\n0.0.0.0 bad.example\nphish.example\n127.0.0.1 localhost\n";
        let entries = parse_domain_blocklist(contents);
        assert_eq!(
            entries.hostnames,
            vec!["bad.example".to_string(), "phish.example".to_string()]
        );
    }

    #[test]
    fn exfil_endpoint_list_parses_hostnames() {
        // Fictional template entries only (CLAUDE.md: no real domains).
        let contents = "# curated exfil / webhook-catcher endpoints\nexfil-sink.example\n0.0.0.0 webhook-catcher.invalid\n127.0.0.1 localhost\n";
        let entries = parse_exfil_endpoint_list(contents);
        assert_eq!(
            entries.hostnames,
            vec![
                "exfil-sink.example".to_string(),
                "webhook-catcher.invalid".to_string(),
            ]
        );
        assert!(entries.ips.is_empty());
    }

    #[test]
    fn tor_exit_list_parses_ipv4_lines() {
        let contents = "# generated\n203.0.113.10\n198.51.100.12\n";
        let entries = parse_tor_exit_list(contents);
        assert_eq!(
            entries.ips,
            vec![
                Ipv4Addr::new(198, 51, 100, 12),
                Ipv4Addr::new(203, 0, 113, 10),
            ]
        );
    }

    #[test]
    fn curated_file_hashes_parses_tags_campaign_and_source() {
        let sha = "a".repeat(64);
        let contents = format!(
            "# curated malicious file hashes\n\
             {sha}  tags=process_spawn,network_exfil  campaign=miasma  source=ossf\n"
        );
        let parsed = parse_curated_file_hashes(&contents);
        assert_eq!(parsed.records.len(), 1);
        let rec = &parsed.records[0];
        assert_eq!(rec.sha256, [0xaa; 32]);
        assert!(rec.behavior_tags.contains(&BehaviorTag::ProcessSpawn));
        assert!(rec.behavior_tags.contains(&BehaviorTag::NetworkExfil));
        assert_eq!(rec.campaign.as_deref(), Some("miasma"));
        assert_eq!(rec.provenance, FileHashProvenance::OssfMalicious);
        assert_eq!(parsed.skipped_bad_sha, 0);
        assert_eq!(parsed.skipped_unknown_tags, 0);
    }

    #[test]
    fn curated_file_hashes_record_with_no_tags_is_valid() {
        // A bare file hash is a valid indicator on its own; tags are enrichment.
        let sha = "b".repeat(64);
        let parsed = parse_curated_file_hashes(&format!("{sha}\n"));
        assert_eq!(parsed.records.len(), 1);
        assert!(parsed.records[0].behavior_tags.is_empty());
        assert!(parsed.records[0].campaign.is_none());
    }

    #[test]
    fn curated_file_hashes_registry_yank_source() {
        let sha = "c".repeat(64);
        let parsed = parse_curated_file_hashes(&format!(
            "{sha}  source=registry-yank  campaign=axios-rat\n"
        ));
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(
            parsed.records[0].provenance,
            FileHashProvenance::RegistryYank
        );
        assert_eq!(parsed.records[0].campaign.as_deref(), Some("axios-rat"));
    }

    #[test]
    fn curated_file_hashes_drops_bad_sha_and_unknown_tag() {
        let good = "d".repeat(64);
        let contents = format!(
            "not-a-hash  tags=process_spawn\n\
             {good}  tags=process_spawn,definitely_not_a_tag\n"
        );
        let parsed = parse_curated_file_hashes(&contents);
        // The malformed-digest line is dropped entirely; the good line survives.
        assert_eq!(parsed.records.len(), 1);
        assert_eq!(parsed.skipped_bad_sha, 1);
        // The unknown tag token is dropped, the known one is kept.
        assert_eq!(parsed.skipped_unknown_tags, 1);
        assert_eq!(
            parsed.records[0].behavior_tags,
            vec![BehaviorTag::ProcessSpawn]
        );
    }

    #[test]
    fn behavior_tag_name_round_trips() {
        for tag in BehaviorTag::ALL {
            assert_eq!(BehaviorTag::from_name(tag.as_str()), Some(tag));
        }
        assert_eq!(
            BehaviorTag::from_name("PROCESS_SPAWN"),
            Some(BehaviorTag::ProcessSpawn)
        );
        assert_eq!(
            BehaviorTag::from_name("  network_exfil "),
            Some(BehaviorTag::NetworkExfil)
        );
        assert_eq!(BehaviorTag::from_name("nope"), None);
    }

    #[test]
    fn urlhaus_csv_fails_without_url_header() {
        let csv = "id,dateadded,link\n1,2024-01-01,https://evil.example/path\n";
        let err = parse_urlhaus_csv(csv.as_bytes()).unwrap_err();
        assert!(err.contains("schema error"), "unexpected error: {err}");
    }

    #[test]
    fn threatfox_csv_fails_without_ioc_header() {
        let csv = "value,type\nbad.example,domain\n";
        let err = parse_threatfox_csv(csv.as_bytes()).unwrap_err();
        assert!(err.contains("schema error"), "unexpected error: {err}");
    }

    #[test]
    fn phishtank_csv_fails_without_url_header() {
        let csv = "phish_id,link\n1,https://phish.example/login\n";
        let err = parse_phishtank_csv(csv.as_bytes()).unwrap_err();
        assert!(err.contains("schema error"), "unexpected error: {err}");
    }

    #[test]
    fn csv_record_errors_are_fatal() {
        // A ragged record (fewer fields than the header) is a hard parse error
        // under the strict (non-flexible) reader; the feed must fail rather
        // than silently return the records read so far.
        let csv = "id,dateadded,url\n1,2024-01-01,https://ok.example/\n2,2024-01-02\n";
        assert!(parse_urlhaus_csv(csv.as_bytes()).is_err());

        let csv = "ioc,ioc_type\nbad.example,domain\n\"unclosed,domain\n";
        assert!(parse_threatfox_csv(csv.as_bytes()).is_err());
    }

    fn tiny_limits() -> FeedLimits {
        FeedLimits {
            input_bytes: 1024,
            records: 2,
            fields: 4,
            field_bytes: 64,
            entries: 2,
        }
    }

    #[test]
    fn csv_limits_fail_closed_for_records_fields_and_aggregate_entries() {
        let mut limits = tiny_limits();
        limits.records = 1;
        let two_rows = "url\nhttps://one.example/\nhttps://two.example/\n";
        let error = parse_urlhaus_csv_with_limits(two_rows.as_bytes(), limits).unwrap_err();
        assert!(error.contains("record limit"), "{error}");

        let mut limits = tiny_limits();
        limits.field_bytes = 8;
        let wide = "url\nhttps://wide.example/\n";
        let error = parse_urlhaus_csv_with_limits(wide.as_bytes(), limits).unwrap_err();
        assert!(error.contains("byte field"), "{error}");

        let mut limits = tiny_limits();
        limits.fields = 1;
        let wide_record = "url,other\nhttps://one.example/,x\n";
        let error = parse_urlhaus_csv_with_limits(wide_record.as_bytes(), limits).unwrap_err();
        assert!(error.contains("fields"), "{error}");

        let mut limits = tiny_limits();
        limits.entries = 1;
        let two_unique = "url\nhttps://one.example/\nhttps://two.example/\n";
        let error = parse_urlhaus_csv_with_limits(two_unique.as_bytes(), limits).unwrap_err();
        assert!(error.contains("unique-indicator limit"), "{error}");

        let duplicate = "url\nhttps://one.example/\nhttps://one.example/\n";
        let parsed = parse_urlhaus_csv_with_limits(duplicate.as_bytes(), limits).unwrap();
        assert_eq!(parsed.hostnames, vec!["one.example"]);
    }

    #[test]
    fn decoded_input_cap_is_enforced_during_streaming_read() {
        let mut limits = tiny_limits();
        limits.input_bytes = 24;
        let input = "url\nhttps://one.example/\n";
        let error = parse_urlhaus_csv_with_limits(input.as_bytes(), limits).unwrap_err();
        assert!(error.contains("decoded input limit"), "{error}");

        limits.input_bytes = input.len() as u64;
        let parsed = parse_urlhaus_csv_with_limits(input.as_bytes(), limits).unwrap();
        assert_eq!(parsed.hostnames, vec!["one.example"]);
    }

    #[test]
    fn streaming_line_feeds_refuse_partial_prefixes_at_every_budget() {
        let mut limits = tiny_limits();
        limits.records = 1;
        let error = parse_domain_blocklist_reader_with_limits(
            "one.example\ntwo.example\n".as_bytes(),
            limits,
        )
        .unwrap_err();
        assert!(error.contains("record limit"), "{error}");

        let mut limits = tiny_limits();
        limits.field_bytes = 4;
        let error = parse_domain_blocklist_reader_with_limits("wide.example\n".as_bytes(), limits)
            .unwrap_err();
        assert!(error.contains("byte field"), "{error}");

        let mut limits = tiny_limits();
        limits.entries = 1;
        let error =
            parse_tor_exit_list_reader_with_limits("203.0.113.1\n203.0.113.2\n".as_bytes(), limits)
                .unwrap_err();
        assert!(error.contains("unique-indicator limit"), "{error}");
    }

    #[test]
    fn threatfox_zip_rejects_excess_member_table() {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut cursor);
            for index in 0..=MAX_FEED_ARCHIVE_MEMBERS {
                zip.start_file(
                    format!("member-{index}.txt"),
                    zip::write::SimpleFileOptions::default(),
                )
                .unwrap();
                zip.write_all(b"x").unwrap();
            }
            zip.finish().unwrap();
        }
        cursor.set_position(0);
        let error = parse_threatfox_zip(cursor).unwrap_err();
        assert!(error.contains("members"), "{error}");
    }
}
