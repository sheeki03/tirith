//! Bounded, stateless reads of authoritative audit records.
//!
//! Cursors are opaque, process-local capabilities: each one carries its read
//! position and is sealed with a per-reader secret over the source identity,
//! the inspected prefix, the read direction and the filter. A restarted
//! collector (new secret), a replaced or truncated log, or a different filter
//! asks consumers to replace their view; it never silently replays old records
//! as new checks. The reader keeps no cursor table. Parsing is not chain
//! verification, and a check is not proof of execution. This reader never
//! rewrites a log or its signed representation.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit_aggregator::AuditRecord;

const PAGE_BYTES: u64 = 2 * 1024 * 1024;
const LINE_BYTES: usize = 1024 * 1024;
const PAGE_RECORDS: usize = 500;
const ANCHOR_BYTES: u64 = 4096;
/// offset (8) + flags (1) + source length (8) + generation (16).
const CURSOR_PAYLOAD: usize = 33;
const CURSOR_SEAL: usize = 32;
/// Hex spelling of a sealed cursor; anything else is not one this reader issued.
pub const CURSOR_HEX_LEN: usize = (CURSOR_PAYLOAD + CURSOR_SEAL) * 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Available,
    Empty,
    Absent,
    Disabled,
    Unreadable,
    Corrupt,
    Partial,
    RefreshRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryFilter {
    pub since: Option<String>,
    pub until: Option<String>,
    pub action: Option<crate::verdict::Action>,
    pub rule: Option<crate::verdict::RuleId>,
}

impl HistoryFilter {
    fn validate(&self) -> Result<(), &'static str> {
        if self.since.as_ref().is_some_and(|value| value.len() > 64)
            || self.until.as_ref().is_some_and(|value| value.len() > 64)
        {
            return Err("history timestamps exceed the 64-byte limit");
        }
        let parse = |value: &Option<String>| {
            value
                .as_deref()
                .map(chrono::DateTime::parse_from_rfc3339)
                .transpose()
        };
        let since = parse(&self.since).map_err(|_| "since must be an RFC3339 timestamp")?;
        let until = parse(&self.until).map_err(|_| "until must be an RFC3339 timestamp")?;
        if since.zip(until).is_some_and(|(since, until)| since > until) {
            return Err("history window starts after it ends");
        }
        Ok(())
    }

    fn matches(&self, record: &AuditRecord) -> bool {
        let Ok(timestamp) = chrono::DateTime::parse_from_rfc3339(&record.timestamp) else {
            return false;
        };
        if self
            .since
            .as_deref()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .is_some_and(|since| timestamp < since)
            || self
                .until
                .as_deref()
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                .is_some_and(|until| timestamp > until)
        {
            return false;
        }
        if let Some(action) = self.action {
            use crate::verdict::Action;
            let matches = match action {
                Action::Allow => record.action.eq_ignore_ascii_case("allow"),
                Action::Warn => record.action.eq_ignore_ascii_case("warn"),
                Action::WarnAck => {
                    record.action.eq_ignore_ascii_case("warn_ack")
                        || record.action.eq_ignore_ascii_case("WarnAck")
                }
                Action::Block => record.action.eq_ignore_ascii_case("block"),
            };
            if !matches {
                return false;
            }
        }
        self.rule.is_none_or(|rule| {
            let canonical = serde_json::to_value(rule)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned));
            canonical.is_some_and(|rule| record.rule_ids.contains(&rule))
        })
    }
}

/// A display copy, separate from the canonical signed line. The caller must
/// apply its current DLP policy before exposing record content.
#[derive(Clone, Serialize)]
pub struct HistoryEvent {
    pub record_id: String,
    pub semantics: &'static str,
    pub execution_evidence: &'static str,
    pub record: AuditRecord,
}

#[derive(Clone, Serialize)]
pub struct HistoryQueryResult {
    pub schema_version: u32,
    pub generation: String,
    pub availability: Availability,
    pub next_cursor: Option<String>,
    pub events: Vec<HistoryEvent>,
    pub filter: HistoryFilter,
    pub inspected_bytes: u64,
    pub malformed_lines: usize,
    pub oversized_lines: usize,
    pub incomplete_tail: bool,
    pub earlier_history_uninspected: bool,
    pub more_available: bool,
    pub integrity: &'static str,
    pub detail: Option<&'static str>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadOrder {
    Forward,
    Recent,
    NewestPage,
}

impl ReadOrder {
    fn tag(self) -> u8 {
        match self {
            Self::Forward => 0,
            Self::Recent => 1,
            Self::NewestPage => 2,
        }
    }
}

/// The position a sealed cursor carries back to the reader.
struct Cursor {
    offset: u64,
    earlier_uninspected: bool,
    discarding_line: bool,
    /// Source length when the cursor was issued; the sealed anchor covers it.
    length: u64,
    generation: [u8; 16],
}

impl Cursor {
    fn payload(&self) -> [u8; CURSOR_PAYLOAD] {
        let mut bytes = [0; CURSOR_PAYLOAD];
        bytes[..8].copy_from_slice(&self.offset.to_be_bytes());
        bytes[8] = u8::from(self.earlier_uninspected) | (u8::from(self.discarding_line) << 1);
        bytes[9..17].copy_from_slice(&self.length.to_be_bytes());
        bytes[17..].copy_from_slice(&self.generation);
        bytes
    }

    fn parse(bytes: &[u8; CURSOR_PAYLOAD]) -> Option<Self> {
        if bytes[8] > 0b11 {
            return None;
        }
        let cursor = Self {
            offset: u64::from_be_bytes(bytes[..8].try_into().ok()?),
            earlier_uninspected: bytes[8] & 1 != 0,
            discarding_line: bytes[8] & 2 != 0,
            length: u64::from_be_bytes(bytes[9..17].try_into().ok()?),
            generation: bytes[17..].try_into().ok()?,
        };
        (cursor.offset <= cursor.length).then_some(cursor)
    }
}

/// One allowlisted log path, chosen by the service/CLI, never by a browser.
/// Memory is bounded independently of the log size and refresh count, and no
/// per-cursor state is retained between reads.
pub struct HistoryReader {
    path: PathBuf,
    key: [u8; 32],
}

impl HistoryReader {
    pub fn new(path: PathBuf) -> Self {
        let mut key = [0; 32];
        key[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        key[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        Self { path, key }
    }

    /// Start with a bounded recent suffix, or continue a previously issued
    /// cursor. Identical retries keep the same record IDs and byte position.
    /// A supplied cursor cannot select a file or an arbitrary seek offset.
    pub fn query(
        &self,
        cursor: Option<&str>,
        filter: HistoryFilter,
        limit: usize,
        logging_enabled: bool,
    ) -> Result<HistoryQueryResult, &'static str> {
        check_limit(limit)?;
        self.query_window(cursor, filter, limit, logging_enabled, ReadOrder::Forward)
    }

    /// Select the newest matching records within one bounded suffix. This
    /// snapshot has no continuation cursor; use `query` for forward paging.
    pub fn recent(
        &self,
        filter: HistoryFilter,
        limit: usize,
        logging_enabled: bool,
    ) -> Result<HistoryQueryResult, &'static str> {
        check_limit(limit)?;
        self.query_window(None, filter, limit, logging_enabled, ReadOrder::Recent)
    }

    /// Every record of the bounded newest suffix (at most one 2 MiB window),
    /// oldest first. Used by aggregates that summarize the window as a whole.
    pub(crate) fn suffix(&self, logging_enabled: bool) -> Result<HistoryQueryResult, &'static str> {
        self.query_window(
            None,
            HistoryFilter::default(),
            usize::MAX,
            logging_enabled,
            ReadOrder::Forward,
        )
    }

    /// Start at the newest records and page toward older history. Each page
    /// is chronological, with an opaque cursor bound to its filter and read
    /// direction. Appending records does not shift an issued older-page bound;
    /// refresh without a cursor to observe new records.
    pub fn newest_page(
        &self,
        cursor: Option<&str>,
        filter: HistoryFilter,
        limit: usize,
        logging_enabled: bool,
    ) -> Result<HistoryQueryResult, &'static str> {
        check_limit(limit)?;
        self.query_window(
            cursor,
            filter,
            limit,
            logging_enabled,
            ReadOrder::NewestPage,
        )
    }

    fn keyed(&self, domain: &[u8]) -> Sha256 {
        let mut hash = Sha256::new();
        hash.update(self.key);
        hash.update(domain);
        hash
    }

    /// Bind a cursor to this reader, its read direction and filter, the
    /// opened source identity, and the source prefix it was issued against.
    fn seal(
        &self,
        order: ReadOrder,
        filter: &HistoryFilter,
        identity: (u64, u64),
        anchor: &[u8; 32],
        payload: &[u8; CURSOR_PAYLOAD],
    ) -> [u8; CURSOR_SEAL] {
        let filter = serde_json::to_vec(filter).unwrap_or_default();
        let mut hash = self.keyed(b"tirith-history-cursor-v1\0");
        hash.update([order.tag()]);
        hash.update((filter.len() as u64).to_be_bytes());
        hash.update(&filter);
        hash.update(identity.0.to_be_bytes());
        hash.update(identity.1.to_be_bytes());
        hash.update(anchor);
        hash.update(payload);
        hash.finalize().into()
    }

    /// A generation names one source as seen by this reader: its identity and
    /// its first record. Replacing the file or rewriting its beginning yields
    /// a different generation, and so different record IDs.
    fn generation(&self, identity: (u64, u64), file: &mut File) -> std::io::Result<[u8; 16]> {
        file.seek(SeekFrom::Start(0))?;
        let mut head = Vec::new();
        (&mut *file).take(ANCHOR_BYTES).read_to_end(&mut head)?;
        if let Some(end) = head.iter().position(|byte| *byte == b'\n') {
            head.truncate(end + 1);
        }
        let mut hash = self.keyed(b"tirith-history-generation-v1\0");
        hash.update(identity.0.to_be_bytes());
        hash.update(identity.1.to_be_bytes());
        hash.update(&head);
        let digest = hash.finalize();
        let mut generation = [0; 16];
        generation.copy_from_slice(&digest[..16]);
        Ok(generation)
    }

    /// The generation reported when no source could be opened.
    fn unavailable_generation(&self) -> String {
        let digest = self.keyed(b"tirith-history-unavailable-v1\0").finalize();
        let mut generation = [0; 16];
        generation.copy_from_slice(&digest[..16]);
        generation_text(&generation)
    }

    /// The position a cursor carries, if this reader sealed it for this
    /// direction, filter and the unchanged source prefix.
    fn open_cursor(
        &self,
        text: &str,
        order: ReadOrder,
        filter: &HistoryFilter,
        identity: (u64, u64),
        file: &mut File,
        length: u64,
    ) -> Result<Option<Cursor>, &'static str> {
        if text.len() != CURSOR_HEX_LEN {
            return Ok(None);
        }
        let Ok(bytes) = hex::decode(text) else {
            return Ok(None);
        };
        if crate::util::hex(&bytes) != text {
            return Ok(None);
        }
        let (payload, seal) = bytes.split_at(CURSOR_PAYLOAD);
        let Ok(payload) = <[u8; CURSOR_PAYLOAD]>::try_from(payload) else {
            return Ok(None);
        };
        let Some(cursor) = Cursor::parse(&payload) else {
            return Ok(None);
        };
        if cursor.length > length {
            return Ok(None);
        }
        let anchor = anchor(file, cursor.length).map_err(|_| "cannot check history generation")?;
        let expected = self.seal(order, filter, identity, &anchor, &payload);
        let matched = expected
            .iter()
            .zip(seal)
            .fold(0u8, |diff, (left, right)| diff | (left ^ right))
            == 0;
        Ok(matched.then_some(cursor))
    }

    fn query_window(
        &self,
        cursor: Option<&str>,
        filter: HistoryFilter,
        limit: usize,
        logging_enabled: bool,
        order: ReadOrder,
    ) -> Result<HistoryQueryResult, &'static str> {
        let recent = order != ReadOrder::Forward;
        filter.validate()?;
        let mut result = empty_result(self.unavailable_generation(), filter.clone());
        if !logging_enabled {
            result.availability = Availability::Disabled;
            result.detail = Some("logging is disabled; retained history may still exist");
            return Ok(result);
        }
        let mut file = match crate::util::open_read_no_follow_capped(&self.path, u64::MAX) {
            Ok(file) => file,
            Err(crate::util::OpenRegularError::NotFound) => {
                result.availability = Availability::Absent;
                return Ok(result);
            }
            Err(_) => {
                result.availability = Availability::Unreadable;
                return Ok(result);
            }
        };
        let metadata = file.metadata().map_err(|_| "cannot inspect history file")?;
        let identity = crate::util::file_identity(&file)
            .map_err(|_| "history file identity is unavailable")?;
        let length = metadata.len();
        let continuation = match cursor {
            Some(text) => {
                match self.open_cursor(text, order, &filter, identity, &mut file, length)? {
                    Some(continuation) => Some(continuation),
                    None => {
                        result.availability = Availability::RefreshRequired;
                        result.detail = Some("history changed, the reader restarted, or this cursor expired; replace the previous view");
                        return Ok(result);
                    }
                }
            }
            None => None,
        };
        let generation = match &continuation {
            Some(continuation) => continuation.generation,
            None => self
                .generation(identity, &mut file)
                .map_err(|_| "cannot inspect history generation")?,
        };
        result.generation = generation_text(&generation);
        let window_end = if order == ReadOrder::NewestPage {
            continuation.as_ref().map_or(length, |saved| saved.offset)
        } else {
            length
        };
        let (mut offset, earlier, mut discarding_line) = if order == ReadOrder::Forward {
            continuation
                .map(|saved| {
                    (
                        saved.offset,
                        saved.earlier_uninspected,
                        saved.discarding_line,
                    )
                })
                .unwrap_or_else(|| {
                    (
                        length.saturating_sub(PAGE_BYTES),
                        length > PAGE_BYTES,
                        length > PAGE_BYTES,
                    )
                })
        } else {
            (
                window_end.saturating_sub(PAGE_BYTES),
                window_end > PAGE_BYTES,
                window_end > PAGE_BYTES,
            )
        };
        let read_start = offset;
        result.earlier_history_uninspected = earlier;
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| "cannot seek history")?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(PAGE_BYTES.min(window_end.saturating_sub(offset)))
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read history page")?;
        result.inspected_bytes = bytes.len() as u64;
        let read_end = offset + result.inspected_bytes;
        let mut position = if recent {
            recent_start(&bytes, &filter, limit, discarding_line)
        } else {
            0
        };
        // A suffix can begin inside a record. Retain its terminating newline
        // in the older page so a valid record split across the byte boundary
        // can be read completely there. If one line fills the entire window,
        // it exceeds LINE_BYTES; advance by a bounded chunk without looping.
        let older_end = if position > 0 {
            read_start + position as u64
        } else if read_start > 0 {
            bytes
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|end| read_start + end as u64 + 1)
                .filter(|end| *end < window_end)
                .unwrap_or(read_start)
        } else {
            0
        };
        if position > 0 {
            offset += position as u64;
            result.earlier_history_uninspected = true;
            discarding_line = false;
        }
        while position < bytes.len() && (recent || result.events.len() < limit) {
            if discarding_line {
                // Keep discard state in the cursor across arbitrarily large
                // records. Advancing bounded chunks prevents a huge line from
                // permanently hiding all later records; a middle chunk is
                // never reinterpreted as a new JSON record.
                let end = bytes[position..].iter().position(|byte| *byte == b'\n');
                let consumed = end.map_or(bytes.len() - position, |end| end + 1);
                position += consumed;
                offset += consumed as u64;
                discarding_line = end.is_none();
                continue;
            }
            let Some(relative_end) = bytes[position..].iter().position(|byte| *byte == b'\n')
            else {
                if bytes.len() - position > LINE_BYTES {
                    result.oversized_lines += 1;
                    discarding_line = true;
                    offset += (bytes.len() - position) as u64;
                }
                // Do not advance past a partially appended line. A continuation
                // can read it once after the writer finishes it, unless the
                // known oversize requires bounded forward discard above.
                result.incomplete_tail = read_end >= length;
                break;
            };
            let end = position + relative_end;
            let line = &bytes[position..end];
            let record_offset = offset;
            offset += (relative_end + 1) as u64;
            position = end + 1;
            if line.len() > LINE_BYTES {
                result.oversized_lines += 1;
                continue;
            }
            if line.is_empty() {
                continue;
            }
            let record = match serde_json::from_slice::<AuditRecord>(line) {
                Ok(record) if chrono::DateTime::parse_from_rfc3339(&record.timestamp).is_ok() => {
                    record
                }
                _ => {
                    result.malformed_lines += 1;
                    continue;
                }
            };
            if !filter.matches(&record) {
                continue;
            }
            let semantics = match record.entry_type.as_str() {
                "verdict" | "" => "recorded_check",
                "hook_telemetry" => "hook_observation",
                "trust_change" => "trust_change",
                "task_boundary" => "boundary_assessment",
                _ => "unclassified_record",
            };
            result.events.push(HistoryEvent {
                record_id: format!("{}:{record_offset}", result.generation),
                semantics,
                execution_evidence: "not_established_by_this_record",
                record,
            });
        }
        if discarding_line && offset >= length {
            result.incomplete_tail = true;
        }
        let after = file.metadata().map_err(|_| "cannot recheck history file")?;
        if after.len() < length
            || (after.len() == length && after.modified().ok() != metadata.modified().ok())
        {
            let mut changed = empty_result(result.generation, filter);
            changed.availability = Availability::RefreshRequired;
            changed.detail = Some("history was modified while reading; replace the previous view");
            return Ok(changed);
        }
        result.more_available = if order == ReadOrder::NewestPage {
            older_end > 0
        } else {
            offset < length
        };
        result.availability =
            if result.malformed_lines + result.oversized_lines > 0 && result.events.is_empty() {
                Availability::Corrupt
            } else if result.earlier_history_uninspected
                || result.more_available
                || result.malformed_lines + result.oversized_lines > 0
                || result.incomplete_tail
            {
                Availability::Partial
            } else if result.events.is_empty() {
                Availability::Empty
            } else {
                Availability::Available
            };
        if order == ReadOrder::Recent || (order == ReadOrder::NewestPage && older_end == 0) {
            return Ok(result);
        }
        let next = Cursor {
            offset: if order == ReadOrder::NewestPage {
                older_end
            } else {
                offset
            },
            earlier_uninspected: earlier,
            discarding_line,
            length,
            generation,
        };
        let payload = next.payload();
        let anchor = anchor(&mut file, length).map_err(|_| "cannot retain history generation")?;
        let seal = self.seal(order, &filter, identity, &anchor, &payload);
        let mut sealed = payload.to_vec();
        sealed.extend_from_slice(&seal);
        result.next_cursor = Some(crate::util::hex(&sealed));
        Ok(result)
    }
}

fn check_limit(limit: usize) -> Result<(), &'static str> {
    if (1..=PAGE_RECORDS).contains(&limit) {
        Ok(())
    } else {
        Err("history limit must be between 1 and 500")
    }
}

fn generation_text(generation: &[u8; 16]) -> String {
    uuid::Uuid::from_bytes(*generation).to_string()
}

fn empty_result(generation: String, filter: HistoryFilter) -> HistoryQueryResult {
    HistoryQueryResult {
        schema_version: 1,
        generation,
        availability: Availability::Empty,
        next_cursor: None,
        events: Vec::new(),
        filter,
        inspected_bytes: 0,
        malformed_lines: 0,
        oversized_lines: 0,
        incomplete_tail: false,
        earlier_history_uninspected: false,
        more_available: false,
        integrity: "not_verified_by_history_reader",
        detail: None,
    }
}

// Walk each byte at most once, from complete tail records toward the front.
// The caller already capped bytes at PAGE_BYTES. Invalid/oversized lines never
// displace a later matching record, and a cut initial line is never parsed.
fn recent_start(bytes: &[u8], filter: &HistoryFilter, limit: usize, cut_initial: bool) -> usize {
    let Some(last_newline) = bytes.iter().rposition(|byte| *byte == b'\n') else {
        return 0;
    };
    let mut end = last_newline + 1;
    let mut matches = 0;
    while end > 0 {
        let start = bytes[..end - 1]
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |position| position + 1);
        if start == 0 && cut_initial {
            return 0;
        }
        let line = &bytes[start..end - 1];
        if !line.is_empty() && line.len() <= LINE_BYTES {
            if let Ok(record) = serde_json::from_slice::<AuditRecord>(line) {
                if chrono::DateTime::parse_from_rfc3339(&record.timestamp).is_ok()
                    && filter.matches(&record)
                {
                    matches += 1;
                    if matches == limit {
                        return start;
                    }
                }
            }
        }
        end = start;
    }
    0
}

fn anchor(file: &mut File, length: u64) -> std::io::Result<[u8; 32]> {
    let mut hash = Sha256::new();
    for start in [0, length.saturating_sub(ANCHOR_BYTES)] {
        file.seek(SeekFrom::Start(start))?;
        let mut bytes = Vec::new();
        (&mut *file)
            .take(ANCHOR_BYTES.min(length.saturating_sub(start)))
            .read_to_end(&mut bytes)?;
        hash.update(bytes);
    }
    Ok(hash.finalize().into())
}

/// Project all untrusted audit content separately from the signed source. No
/// signature or chain hash is copied into this display record.
pub fn display_projection(result: &HistoryQueryResult, patterns: &[String]) -> serde_json::Value {
    let mut value = serde_json::to_value(result).unwrap_or(serde_json::Value::Null);
    let compiled = crate::redact::CompiledCustomPatterns::new_silent(patterns);
    if let Some(events) = value
        .get_mut("events")
        .and_then(serde_json::Value::as_array_mut)
    {
        for event in events {
            if let Some(record) = event.get_mut("record") {
                // The audit record has legacy free-form action/origin fields;
                // only preserve values validated by the owning output schema.
                crate::output_contract::redact_projection(
                    record,
                    crate::output_contract::Projection::HistoryRecord,
                    &compiled,
                );
            }
        }
    }
    crate::verdict::bound_json_value_for_output(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn line(command: &str) -> String {
        format!(
            "{}\n",
            serde_json::json!({"timestamp":"2026-09-12T00:00:00Z", "action":"Block", "command_redacted":command, "rule_ids":["curl_pipe_shell"]})
        )
    }
    fn query(reader: &HistoryReader, cursor: Option<&str>, limit: usize) -> HistoryQueryResult {
        reader
            .query(cursor, HistoryFilter::default(), limit, true)
            .unwrap()
    }

    #[test]
    fn recent_snapshot_keeps_newest_records_without_changing_forward_cursors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let bytes = (0..600)
            .map(|index| line(&format!("check-{index}")))
            .collect::<String>();
        std::fs::write(&path, &bytes).unwrap();
        let reader = HistoryReader::new(path.clone());
        let first = query(&reader, None, 10);
        let recent = reader.recent(HistoryFilter::default(), 10, true).unwrap();
        assert_eq!(recent.events.len(), 10);
        assert_eq!(recent.events[0].record.command_redacted, "check-590");
        assert_eq!(recent.events[9].record.command_redacted, "check-599");
        assert!(recent.earlier_history_uninspected);
        assert_eq!(recent.availability, Availability::Partial);
        assert!(recent.next_cursor.is_none());
        assert!(recent.inspected_bytes <= PAGE_BYTES);
        let next = query(&reader, first.next_cursor.as_deref(), 10);
        assert_eq!(next.events[0].record.command_redacted, "check-10");
        assert_eq!(std::fs::read_to_string(path).unwrap(), bytes);
    }

    #[test]
    fn recent_snapshot_ignores_partial_tail_and_bounds_filtered_selection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let bytes = format!(
            "{}{}broken\n{}{{\"timestamp\":",
            line("old"),
            line("new"),
            line("allowed").replace("\"Block\"", "\"Allow\"")
        );
        std::fs::write(&path, &bytes).unwrap();
        let reader = HistoryReader::new(path);
        let filter = HistoryFilter {
            action: Some(crate::verdict::Action::Block),
            ..Default::default()
        };
        let recent = reader.recent(filter, 1, true).unwrap();
        assert_eq!(recent.events.len(), 1);
        assert_eq!(recent.events[0].record.command_redacted, "new");
        assert!(recent.earlier_history_uninspected);
        // A subsequent unrestricted snapshot exposes malformed/unfinished tail
        // coverage without ever interpreting unfinished JSON as a record.
        let all = reader.recent(HistoryFilter::default(), 500, true).unwrap();
        assert_eq!(all.events.len(), 3);
        assert_eq!(all.malformed_lines, 1);
        assert!(all.incomplete_tail);
    }

    #[test]
    fn newest_pages_keep_bounds_on_append_and_reject_other_cursor_directions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(
            &path,
            (0..600)
                .map(|i| line(&format!("check-{i}")))
                .collect::<String>(),
        )
        .unwrap();
        let reader = HistoryReader::new(path.clone());
        let first = reader
            .newest_page(None, HistoryFilter::default(), 100, true)
            .unwrap();
        assert_eq!(first.events[0].record.command_redacted, "check-500");
        assert_eq!(first.events[99].record.command_redacted, "check-599");
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(line("appended").as_bytes())
            .unwrap();
        let next = reader
            .newest_page(
                first.next_cursor.as_deref(),
                HistoryFilter::default(),
                100,
                true,
            )
            .unwrap();
        let retry = reader
            .newest_page(
                first.next_cursor.as_deref(),
                HistoryFilter::default(),
                100,
                true,
            )
            .unwrap();
        assert_eq!(next.events[0].record.command_redacted, "check-400");
        assert_eq!(next.events[99].record.command_redacted, "check-499");
        assert_eq!(
            next.events.iter().map(|e| &e.record_id).collect::<Vec<_>>(),
            retry
                .events
                .iter()
                .map(|e| &e.record_id)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            query(&reader, first.next_cursor.as_deref(), 100).availability,
            Availability::RefreshRequired
        );
        let forward = query(&reader, None, 100);
        assert_eq!(
            reader
                .newest_page(
                    forward.next_cursor.as_deref(),
                    HistoryFilter::default(),
                    100,
                    true
                )
                .unwrap()
                .availability,
            Availability::RefreshRequired
        );
        assert_eq!(
            reader
                .newest_page(
                    first.next_cursor.as_deref(),
                    HistoryFilter {
                        action: Some(crate::verdict::Action::Allow),
                        ..Default::default()
                    },
                    100,
                    true
                )
                .unwrap()
                .availability,
            Availability::RefreshRequired
        );
        let fresh = reader
            .newest_page(None, HistoryFilter::default(), 100, true)
            .unwrap();
        assert_eq!(
            fresh.events.last().unwrap().record.command_redacted,
            "appended"
        );
        std::fs::write(&path, line("replacement")).unwrap();
        assert_eq!(
            reader
                .newest_page(
                    next.next_cursor.as_deref(),
                    HistoryFilter::default(),
                    100,
                    true
                )
                .unwrap()
                .availability,
            Availability::RefreshRequired
        );
    }

    #[test]
    fn newest_pages_recover_records_cut_by_the_byte_window_without_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let commands: Vec<_> = (0..8)
            .map(|i| format!("{i}:{}", "x".repeat(700_000)))
            .collect();
        std::fs::write(
            &path,
            commands
                .iter()
                .map(|command| line(command))
                .collect::<String>(),
        )
        .unwrap();
        let reader = HistoryReader::new(path);
        let mut cursor = None;
        let mut observed = Vec::new();
        for _ in 0..10 {
            let page = reader
                .newest_page(cursor.as_deref(), HistoryFilter::default(), 100, true)
                .unwrap();
            assert!(page.inspected_bytes <= PAGE_BYTES);
            assert!(!page.incomplete_tail);
            for event in page.events.iter().rev() {
                observed.push(event.record.command_redacted.clone());
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert!(cursor.is_none());
        assert_eq!(observed, commands.into_iter().rev().collect::<Vec<_>>());
    }

    #[test]
    fn newest_pages_make_progress_across_a_line_larger_than_multiple_windows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(
            &path,
            format!(
                "{}{}\n{}",
                line("oldest"),
                "x".repeat(PAGE_BYTES as usize * 3),
                line("newest")
            ),
        )
        .unwrap();
        let reader = HistoryReader::new(path);
        let mut cursor = None;
        let mut observed = Vec::new();
        for _ in 0..10 {
            let page = reader
                .newest_page(cursor.as_deref(), HistoryFilter::default(), 100, true)
                .unwrap();
            assert!(page.inspected_bytes <= PAGE_BYTES);
            observed.extend(
                page.events
                    .into_iter()
                    .rev()
                    .map(|e| e.record.command_redacted),
            );
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert!(cursor.is_none());
        assert_eq!(observed, ["newest", "oldest"]);
    }

    #[test]
    fn append_and_retry_do_not_duplicate_or_relabel_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, line("first")).unwrap();
        let reader = HistoryReader::new(path.clone());
        let first = query(&reader, None, 50);
        assert_eq!(first.events.len(), 1);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(line("second").as_bytes()).unwrap();
        let next = query(&reader, first.next_cursor.as_deref(), 50);
        let retry = query(&reader, first.next_cursor.as_deref(), 50);
        assert_eq!(next.events.len(), 1);
        assert_eq!(next.events[0].record.command_redacted, "second");
        assert_eq!(next.events[0].record_id, retry.events[0].record_id);
        assert_ne!(next.events[0].record_id, first.events[0].record_id);
        assert_eq!(next.events[0].semantics, "recorded_check");
        assert_eq!(
            next.events[0].execution_evidence,
            "not_established_by_this_record"
        );
        assert!(query(&reader, next.next_cursor.as_deref(), 50)
            .events
            .is_empty());
    }

    #[test]
    fn partial_append_is_not_skipped_or_counted_twice() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let record = line("later");
        std::fs::write(&path, &record[..record.len() - 1]).unwrap();
        let reader = HistoryReader::new(path.clone());
        let first = query(&reader, None, 10);
        assert!(first.incomplete_tail);
        assert!(first.events.is_empty());
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        let next = query(&reader, first.next_cursor.as_deref(), 10);
        assert_eq!(next.events.len(), 1);
        assert_eq!(next.malformed_lines, 0);
    }

    #[test]
    fn oversized_partial_lines_make_bounded_forward_progress() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, line("initial")).unwrap();
        let reader = HistoryReader::new(path.clone());
        let first = query(&reader, None, 10);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(&vec![b'x'; (PAGE_BYTES * 3) as usize])
            .unwrap();
        let mut page = query(&reader, first.next_cursor.as_deref(), 10);
        assert_eq!(page.oversized_lines, 1);
        for _ in 0..2 {
            page = query(&reader, page.next_cursor.as_deref(), 10);
            assert_eq!(page.oversized_lines, 0);
            assert!(page.inspected_bytes <= PAGE_BYTES);
        }
        assert!(page.incomplete_tail);
        file.write_all(format!("\n{}", line("after-oversize")).as_bytes())
            .unwrap();
        let next = query(&reader, page.next_cursor.as_deref(), 10);
        assert_eq!(next.events.len(), 1);
        assert_eq!(next.events[0].record.command_redacted, "after-oversize");
        assert_eq!(next.malformed_lines, 0);
    }

    #[test]
    fn replacement_truncation_restart_and_changed_filters_require_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, line("initial")).unwrap();
        let reader = HistoryReader::new(path.clone());
        let first = query(&reader, None, 10);
        let restart = HistoryReader::new(path.clone());
        assert_eq!(
            query(&restart, first.next_cursor.as_deref(), 10).availability,
            Availability::RefreshRequired
        );
        let filter = HistoryFilter {
            action: Some(crate::verdict::Action::Allow),
            ..Default::default()
        };
        assert_eq!(
            reader
                .query(first.next_cursor.as_deref(), filter, 10, true)
                .unwrap()
                .availability,
            Availability::RefreshRequired
        );
        std::fs::write(&path, line("replace")).unwrap();
        assert_eq!(
            query(&reader, first.next_cursor.as_deref(), 10).availability,
            Availability::RefreshRequired
        );
        let fresh = query(&reader, None, 10);
        assert_ne!(fresh.generation, first.generation);
        std::fs::write(&path, "").unwrap();
        assert_eq!(
            query(&reader, fresh.next_cursor.as_deref(), 10).availability,
            Availability::RefreshRequired
        );
    }

    #[test]
    fn errors_large_logs_and_limits_have_explicit_coverage() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let reader = HistoryReader::new(path.clone());
        assert_eq!(query(&reader, None, 10).availability, Availability::Absent);
        assert_eq!(
            reader
                .query(None, HistoryFilter::default(), 10, false)
                .unwrap()
                .availability,
            Availability::Disabled
        );
        std::fs::write(&path, "broken\n").unwrap();
        assert_eq!(query(&reader, None, 10).availability, Availability::Corrupt);
        let mut file = std::fs::File::create(&path).unwrap();
        file.set_len(300 * 1024 * 1024).unwrap();
        file.seek(SeekFrom::End(0)).unwrap();
        file.write_all(format!("\n{}", line("recent")).as_bytes())
            .unwrap();
        let result = query(&reader, None, 10);
        assert!(result.earlier_history_uninspected);
        assert!(result.inspected_bytes <= PAGE_BYTES);
        assert_eq!(result.events.len(), 1);
        assert!(reader
            .query(None, HistoryFilter::default(), 501, true)
            .is_err());
        assert!(reader
            .query(
                None,
                HistoryFilter {
                    since: Some("yesterday".into()),
                    ..Default::default()
                },
                10,
                true
            )
            .is_err());
    }

    #[test]
    fn cursors_are_sealed_stateless_and_never_expire_while_the_source_is_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(
            &path,
            (0..300)
                .map(|i| line(&format!("check-{i}")))
                .collect::<String>(),
        )
        .unwrap();
        let reader = HistoryReader::new(path.clone());
        let first = reader
            .newest_page(None, HistoryFilter::default(), 10, true)
            .unwrap();
        let cursor = first.next_cursor.clone().unwrap();
        assert_eq!(cursor.len(), CURSOR_HEX_LEN);
        // No cursor table: issuing many more cursors does not evict this one.
        for _ in 0..200 {
            reader
                .newest_page(None, HistoryFilter::default(), 10, true)
                .unwrap();
        }
        let older = reader
            .newest_page(Some(&cursor), HistoryFilter::default(), 10, true)
            .unwrap();
        assert_eq!(older.events[0].record.command_redacted, "check-280");
        assert_eq!(older.generation, first.generation);
        // Any change to the sealed bytes, or a spelling this reader never
        // issues, asks for a fresh view instead of seeking anywhere.
        let mut tampered = cursor.clone().into_bytes();
        tampered[15] = if tampered[15] == b'0' { b'1' } else { b'0' };
        for bad in [
            String::from_utf8(tampered).unwrap(),
            cursor.to_uppercase(),
            cursor[..CURSOR_HEX_LEN - 2].to_string(),
            format!("{cursor}00"),
            uuid::Uuid::new_v4().to_string(),
        ] {
            assert_eq!(
                reader
                    .newest_page(Some(&bad), HistoryFilter::default(), 10, true)
                    .unwrap()
                    .availability,
                Availability::RefreshRequired,
                "{bad}"
            );
        }
    }

    #[test]
    fn the_bounded_suffix_holds_every_record_of_its_window() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(
            &path,
            (0..1200)
                .map(|i| line(&format!("check-{i}")))
                .collect::<String>(),
        )
        .unwrap();
        let suffix = HistoryReader::new(path).suffix(true).unwrap();
        assert_eq!(suffix.events.len(), 1200);
        assert_eq!(suffix.events[0].record.command_redacted, "check-0");
        assert_eq!(suffix.availability, Availability::Available);
        assert!(!suffix.more_available);
        assert!(suffix.next_cursor.is_some());
    }
}
