//! Bounded, incremental reads of authoritative audit records.
//!
//! Cursors are opaque, process-local capabilities. A restarted collector asks
//! consumers to replace their view; it never silently replays old records as
//! new checks. Parsing is not chain verification, and a check is not proof of
//! execution. This reader never rewrites a log or its signed representation.

use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit_aggregator::AuditRecord;

const PAGE_BYTES: u64 = 2 * 1024 * 1024;
const LINE_BYTES: usize = 1024 * 1024;
const PAGE_RECORDS: usize = 500;
const CURSORS: usize = 128;
const ANCHOR_BYTES: u64 = 4096;

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

#[derive(Clone)]
struct Cursor {
    order: ReadOrder,
    offset: u64,
    filter: HistoryFilter,
    earlier_uninspected: bool,
    discarding_line: bool,
}

/// One allowlisted log path, chosen by the service/CLI, never by a browser.
/// Memory is bounded independently of the log size and refresh count.
pub struct HistoryReader {
    path: PathBuf,
    generation: String,
    source: Option<Source>,
    cursors: BTreeMap<String, Cursor>,
    order: VecDeque<String>,
}

struct Source {
    // Keep the handle alive so inode/file-ID reuse cannot alias the old source.
    _held: File,
    identity: (u64, u64),
    length: u64,
    anchor: [u8; 32],
}

impl HistoryReader {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            generation: uuid::Uuid::new_v4().to_string(),
            source: None,
            cursors: BTreeMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Start with a bounded recent suffix, or continue a previously issued
    /// cursor. Identical retries keep the same record IDs and byte position.
    /// A supplied cursor cannot select a file or an arbitrary seek offset.
    pub fn query(
        &mut self,
        cursor: Option<&str>,
        filter: HistoryFilter,
        limit: usize,
        logging_enabled: bool,
    ) -> Result<HistoryQueryResult, &'static str> {
        self.query_window(cursor, filter, limit, logging_enabled, ReadOrder::Forward)
    }

    /// Select the newest matching records within one bounded suffix. This
    /// snapshot has no continuation cursor; use `query` for forward paging.
    pub fn recent(
        &mut self,
        filter: HistoryFilter,
        limit: usize,
        logging_enabled: bool,
    ) -> Result<HistoryQueryResult, &'static str> {
        self.query_window(None, filter, limit, logging_enabled, ReadOrder::Recent)
    }

    /// Start at the newest records and page toward older history. Each page
    /// is chronological, with an opaque cursor bound to its filter and read
    /// direction. Appending records does not shift an issued older-page bound;
    /// refresh without a cursor to observe new records.
    pub fn newest_page(
        &mut self,
        cursor: Option<&str>,
        filter: HistoryFilter,
        limit: usize,
        logging_enabled: bool,
    ) -> Result<HistoryQueryResult, &'static str> {
        self.query_window(
            cursor,
            filter,
            limit,
            logging_enabled,
            ReadOrder::NewestPage,
        )
    }

    fn query_window(
        &mut self,
        cursor: Option<&str>,
        filter: HistoryFilter,
        limit: usize,
        logging_enabled: bool,
        order: ReadOrder,
    ) -> Result<HistoryQueryResult, &'static str> {
        let recent = order != ReadOrder::Forward;
        filter.validate()?;
        if !(1..=PAGE_RECORDS).contains(&limit) {
            return Err("history limit must be between 1 and 500");
        }
        let mut result = self.empty_result(filter.clone());
        if !logging_enabled {
            result.availability = Availability::Disabled;
            result.detail = Some("logging is disabled; retained history may still exist");
            return Ok(result);
        }
        let mut file = match crate::util::open_read_no_follow_capped(&self.path, u64::MAX) {
            Ok(file) => file,
            Err(crate::util::OpenRegularError::NotFound) => {
                self.reset();
                result.generation = self.generation.clone();
                result.availability = Availability::Absent;
                return Ok(result);
            }
            Err(_) => {
                result.availability = Availability::Unreadable;
                return Ok(result);
            }
        };
        let metadata = file.metadata().map_err(|_| "cannot inspect history file")?;
        let identity = file_identity(&file).map_err(|_| "history file identity is unavailable")?;
        let length = metadata.len();
        let source_changed = if let Some(source) = &self.source {
            source.identity != identity
                || length < source.length
                || anchor(&mut file, source.length)
                    .map_err(|_| "cannot check history generation")?
                    != source.anchor
        } else {
            false
        };
        if source_changed {
            self.reset();
        }
        if self.source.is_none() {
            self.source = Some(Source {
                _held: file
                    .try_clone()
                    .map_err(|_| "cannot retain history identity")?,
                identity,
                length,
                anchor: anchor(&mut file, length)
                    .map_err(|_| "cannot inspect history generation")?,
            });
        }
        result.generation = self.generation.clone();
        let continuation = match cursor {
            Some(cursor) if cursor.len() <= 64 => self
                .cursors
                .get(cursor)
                .filter(|saved| saved.filter == filter && saved.order == order)
                .cloned(),
            _ => None,
        };
        if cursor.is_some() && continuation.is_none() {
            result.availability = Availability::RefreshRequired;
            result.detail = Some("history changed, the reader restarted, or this cursor expired; replace the previous view");
            return Ok(result);
        }
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
                record_id: format!("{}:{record_offset}", self.generation),
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
            self.reset();
            let mut changed = self.empty_result(filter);
            changed.availability = Availability::RefreshRequired;
            changed.detail = Some("history was modified while reading; replace the previous view");
            return Ok(changed);
        }
        if let Some(source) = &mut self.source {
            source.length = length;
            source.anchor =
                anchor(&mut file, length).map_err(|_| "cannot retain history generation")?;
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
        let token = uuid::Uuid::new_v4().to_string();
        self.cursors.insert(
            token.clone(),
            Cursor {
                order,
                offset: if order == ReadOrder::NewestPage {
                    older_end
                } else {
                    offset
                },
                filter,
                earlier_uninspected: earlier,
                discarding_line,
            },
        );
        self.order.push_back(token.clone());
        while self.order.len() > CURSORS {
            if let Some(old) = self.order.pop_front() {
                self.cursors.remove(&old);
            }
        }
        result.next_cursor = Some(token);
        Ok(result)
    }

    fn empty_result(&self, filter: HistoryFilter) -> HistoryQueryResult {
        HistoryQueryResult {
            schema_version: 1,
            generation: self.generation.clone(),
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

    fn reset(&mut self) {
        self.generation = uuid::Uuid::new_v4().to_string();
        self.source = None;
        self.cursors.clear();
        self.order.clear();
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

#[cfg(unix)]
fn file_identity(file: &File) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn file_identity(file: &File) -> std::io::Result<(u64, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((
        u64::from(info.dwVolumeSerialNumber),
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_: &File) -> std::io::Result<(u64, u64)> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "history identity is unavailable",
    ))
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
    fn query(reader: &mut HistoryReader, cursor: Option<&str>, limit: usize) -> HistoryQueryResult {
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
        let mut reader = HistoryReader::new(path.clone());
        let first = query(&mut reader, None, 10);
        let recent = reader.recent(HistoryFilter::default(), 10, true).unwrap();
        assert_eq!(recent.events.len(), 10);
        assert_eq!(recent.events[0].record.command_redacted, "check-590");
        assert_eq!(recent.events[9].record.command_redacted, "check-599");
        assert!(recent.earlier_history_uninspected);
        assert_eq!(recent.availability, Availability::Partial);
        assert!(recent.next_cursor.is_none());
        assert!(recent.inspected_bytes <= PAGE_BYTES);
        let next = query(&mut reader, first.next_cursor.as_deref(), 10);
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
        let mut reader = HistoryReader::new(path);
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
        let mut reader = HistoryReader::new(path.clone());
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
            query(&mut reader, first.next_cursor.as_deref(), 100).availability,
            Availability::RefreshRequired
        );
        let forward = query(&mut reader, None, 100);
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
        let mut reader = HistoryReader::new(path);
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
        let mut reader = HistoryReader::new(path);
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
        let mut reader = HistoryReader::new(path.clone());
        let first = query(&mut reader, None, 50);
        assert_eq!(first.events.len(), 1);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(line("second").as_bytes()).unwrap();
        let next = query(&mut reader, first.next_cursor.as_deref(), 50);
        let retry = query(&mut reader, first.next_cursor.as_deref(), 50);
        assert_eq!(next.events.len(), 1);
        assert_eq!(next.events[0].record.command_redacted, "second");
        assert_eq!(next.events[0].record_id, retry.events[0].record_id);
        assert_ne!(next.events[0].record_id, first.events[0].record_id);
        assert_eq!(next.events[0].semantics, "recorded_check");
        assert_eq!(
            next.events[0].execution_evidence,
            "not_established_by_this_record"
        );
        assert!(query(&mut reader, next.next_cursor.as_deref(), 50)
            .events
            .is_empty());
    }

    #[test]
    fn partial_append_is_not_skipped_or_counted_twice() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let record = line("later");
        std::fs::write(&path, &record[..record.len() - 1]).unwrap();
        let mut reader = HistoryReader::new(path.clone());
        let first = query(&mut reader, None, 10);
        assert!(first.incomplete_tail);
        assert!(first.events.is_empty());
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        let next = query(&mut reader, first.next_cursor.as_deref(), 10);
        assert_eq!(next.events.len(), 1);
        assert_eq!(next.malformed_lines, 0);
    }

    #[test]
    fn oversized_partial_lines_make_bounded_forward_progress() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, line("initial")).unwrap();
        let mut reader = HistoryReader::new(path.clone());
        let first = query(&mut reader, None, 10);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(&vec![b'x'; (PAGE_BYTES * 3) as usize])
            .unwrap();
        let mut page = query(&mut reader, first.next_cursor.as_deref(), 10);
        assert_eq!(page.oversized_lines, 1);
        for _ in 0..2 {
            page = query(&mut reader, page.next_cursor.as_deref(), 10);
            assert_eq!(page.oversized_lines, 0);
            assert!(page.inspected_bytes <= PAGE_BYTES);
        }
        assert!(page.incomplete_tail);
        file.write_all(format!("\n{}", line("after-oversize")).as_bytes())
            .unwrap();
        let next = query(&mut reader, page.next_cursor.as_deref(), 10);
        assert_eq!(next.events.len(), 1);
        assert_eq!(next.events[0].record.command_redacted, "after-oversize");
        assert_eq!(next.malformed_lines, 0);
    }

    #[test]
    fn replacement_truncation_restart_and_changed_filters_require_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, line("initial")).unwrap();
        let mut reader = HistoryReader::new(path.clone());
        let first = query(&mut reader, None, 10);
        let mut restart = HistoryReader::new(path.clone());
        assert_eq!(
            query(&mut restart, first.next_cursor.as_deref(), 10).availability,
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
            query(&mut reader, first.next_cursor.as_deref(), 10).availability,
            Availability::RefreshRequired
        );
        let fresh = query(&mut reader, None, 10);
        assert_ne!(fresh.generation, first.generation);
        std::fs::write(&path, "").unwrap();
        assert_eq!(
            query(&mut reader, fresh.next_cursor.as_deref(), 10).availability,
            Availability::RefreshRequired
        );
    }

    #[test]
    fn errors_large_logs_and_limits_have_explicit_coverage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut reader = HistoryReader::new(path.clone());
        assert_eq!(
            query(&mut reader, None, 10).availability,
            Availability::Absent
        );
        assert_eq!(
            reader
                .query(None, HistoryFilter::default(), 10, false)
                .unwrap()
                .availability,
            Availability::Disabled
        );
        std::fs::write(&path, "broken\n").unwrap();
        assert_eq!(
            query(&mut reader, None, 10).availability,
            Availability::Corrupt
        );
        let mut file = std::fs::File::create(&path).unwrap();
        file.set_len(300 * 1024 * 1024).unwrap();
        file.seek(SeekFrom::End(0)).unwrap();
        file.write_all(format!("\n{}", line("recent")).as_bytes())
            .unwrap();
        let result = query(&mut reader, None, 10);
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
}
