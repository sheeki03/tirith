//! Pure parsers for the metadata files a Python wheel / installed distribution
//! carries (PR B5). No I/O: every function takes already-read bytes or text and
//! returns a parsed value, so the same parser serves an in-memory wheel member
//! (from A4's archive reader) and an on-disk installed file.
//!
//! The files parsed here are the `.dist-info` family:
//!
//! * `METADATA` (PEP 566): `Name:`/`Version:` headers. The header loop is the
//!   single shared helper [`parse_metadata_headers`], also used by
//!   `ecosystem_scan::read_dist_info_metadata`, so the two paths cannot drift.
//! * `WHEEL` (PEP 427): the wheel format metadata. `Root-Is-Purelib: true`
//!   shipping a native `.so` is a [`WheelMetadata`] signal a later analyzer
//!   weighs (a pure-lib wheel claiming no platform code, yet carrying a compiled
//!   extension, is contradictory).
//! * `entry_points.txt`: console/gui entry points. These are `module:object`
//!   IMPORT targets, NOT file paths; the parser preserves that distinction so a
//!   caller never mistakes `foo.bar:baz` for a path.
//! * `direct_url.json` (PEP 610): records an editable or VCS install so the
//!   installed-RECORD verifier can treat a legitimately-sparse editable RECORD
//!   leniently instead of flagging every missing project file.
//! * `RECORD`: the manifest of every installed file with its hash and size.
//!   Parsed with the `csv` crate because a member path may contain a comma and
//!   be CSV-quoted; splitting rows by hand would corrupt such a path. A RECORD
//!   hash is `sha256=<base64url-no-pad>` (or a stronger algorithm), decoded with
//!   `base64`'s `URL_SAFE_NO_PAD` engine.

use base64::Engine as _;
use serde::Deserialize;

/// Parse the `Name:` and `Version:` headers of a PEP 566 `METADATA` (or PKG-INFO)
/// document. The single shared header loop: headers run until the first blank
/// line (the body is the long description and is irrelevant), a header value is
/// trimmed, and an empty value is treated as absent. Returns `(name, version)`
/// with `name` required (the file is useless without it) and `version` optional.
///
/// This is the promotion of `ecosystem_scan`'s former private header loop into a
/// shared place, so the installed-tree scan and the artifact parsers agree on
/// exactly what a METADATA name/version is.
pub fn parse_metadata_headers(text: &str) -> Option<(String, Option<String>)> {
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    for line in text.lines() {
        if line.is_empty() {
            break; // headers end at the first blank line
        }
        if let Some(rest) = line.strip_prefix("Name:") {
            let val = rest.trim();
            if !val.is_empty() {
                name = Some(val.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("Version:") {
            let val = rest.trim();
            if !val.is_empty() {
                version = Some(val.to_string());
            }
        }
    }
    name.map(|n| (n, version))
}

/// Parsed `WHEEL` metadata (PEP 427). Only the fields a later analyzer weighs are
/// retained; unknown headers are ignored (the format is extensible).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WheelMetadata {
    /// `Wheel-Version:` (e.g. `1.0`), if present.
    pub wheel_version: Option<String>,
    /// `Root-Is-Purelib:` parsed as a bool. `true` asserts the wheel is pure
    /// Python (its root unpacks into `purelib`); a `true` here alongside a native
    /// `.so` member is contradictory and is a signal the correlation weighs.
    pub root_is_purelib: Option<bool>,
    /// Every `Tag:` line (platform/abi/py tags), in file order.
    pub tags: Vec<String>,
}

/// Parse a `WHEEL` file's headers (same colon-separated header grammar as
/// METADATA, but a different key set). Unknown keys are ignored.
pub fn parse_wheel_metadata(text: &str) -> WheelMetadata {
    let mut meta = WheelMetadata::default();
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "Wheel-Version" if !value.is_empty() => {
                meta.wheel_version = Some(value.to_string());
            }
            "Root-Is-Purelib" => {
                // PEP 427 spells the boolean `true`/`false` (lowercase); accept any
                // case defensively. An unrecognized value leaves it `None`.
                meta.root_is_purelib = match value.to_ascii_lowercase().as_str() {
                    "true" => Some(true),
                    "false" => Some(false),
                    _ => None,
                };
            }
            "Tag" if !value.is_empty() => meta.tags.push(value.to_string()),
            _ => {}
        }
    }
    meta
}

/// One entry point from `entry_points.txt`: a `name = module:object` line under a
/// `[console_scripts]`/`[gui_scripts]`/other group. The target is an IMPORT
/// reference (`module[.submodule]:object[.attr]`), NOT a filesystem path; turning
/// it into a path (`foo/bar.py`) would be wrong, so the parser keeps the module
/// and object parts separate and never fabricates a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPoint {
    /// The INI group the entry point is declared under (`console_scripts`, ...).
    pub group: String,
    /// The entry-point name (the left side of `=`).
    pub name: String,
    /// The dotted import module (the part before `:`).
    pub module: String,
    /// The object/attribute within the module (the part after `:`), if present.
    /// `module` alone (no `:object`) is legal and leaves this `None`.
    pub object: Option<String>,
}

/// Parse `entry_points.txt` (an INI-shaped file). Returns every entry point with
/// its group. A malformed line is skipped, not fatal. Group headers are
/// `[group_name]`; entries are `name = module:object` (or `name = module`).
pub fn parse_entry_points(text: &str) -> Vec<EntryPoint> {
    let mut out: Vec<EntryPoint> = Vec::new();
    let mut group: Option<String> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(inner) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            group = Some(inner.trim().to_string());
            continue;
        }
        let Some(g) = &group else {
            // An entry before any group header is malformed; skip it.
            continue;
        };
        let Some((name, target)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        // The target may carry an `[extras]` suffix (`pkg.mod:fn [extra]`); keep
        // only the import reference before any whitespace/bracket.
        let target = target.trim();
        let target = target
            .split_whitespace()
            .next()
            .unwrap_or(target)
            .trim_end_matches('[');
        if name.is_empty() || target.is_empty() {
            continue;
        }
        let (module, object) = match target.split_once(':') {
            Some((m, o)) => (m.trim().to_string(), {
                let o = o.trim();
                if o.is_empty() {
                    None
                } else {
                    Some(o.to_string())
                }
            }),
            None => (target.to_string(), None),
        };
        if module.is_empty() {
            continue;
        }
        out.push(EntryPoint {
            group: g.clone(),
            name: name.to_string(),
            module,
            object,
        });
    }
    out
}

/// A parsed `direct_url.json` (PEP 610), enough to tell whether the install was
/// editable and/or from a VCS, so the installed-RECORD verifier can be lenient
/// about a legitimately-sparse editable RECORD. Unknown fields are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DirectUrl {
    /// The `url` field (a `file://`, VCS, or archive URL).
    pub url: Option<String>,
    /// `true` when `dir_info.editable` is true (an editable / `-e` install).
    pub editable: bool,
    /// `true` when a `vcs_info` block is present (installed from a VCS checkout).
    pub vcs: bool,
}

/// The serde shape of `direct_url.json` we read. Only the discriminating fields
/// are modeled; `#[serde(default)]` tolerates their absence and extra keys are
/// ignored, because the record is extensible.
#[derive(Debug, Deserialize)]
struct DirectUrlRaw {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    dir_info: Option<DirInfoRaw>,
    #[serde(default)]
    vcs_info: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct DirInfoRaw {
    #[serde(default)]
    editable: bool,
}

/// Parse `direct_url.json`. Returns `None` on invalid JSON (the file is optional;
/// a malformed one simply yields no direct-url signal).
pub fn parse_direct_url(text: &str) -> Option<DirectUrl> {
    let raw: DirectUrlRaw = serde_json::from_str(text).ok()?;
    Some(DirectUrl {
        url: raw.url,
        editable: raw.dir_info.map(|d| d.editable).unwrap_or(false),
        vcs: raw.vcs_info.is_some(),
    })
}

/// A hash recorded in a RECORD row: the algorithm name and the decoded digest
/// bytes. The on-the-wire form is `<algorithm>=<base64url-no-pad-digest>` (e.g.
/// `sha256=AbCd...`); the digest is decoded so a caller compares bytes, never the
/// (padding/case-sensitive) base64 text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordHash {
    /// The hash algorithm name as written, lowercased (`sha256`, `sha512`, ...).
    pub algorithm: String,
    /// The decoded digest bytes.
    pub digest: Vec<u8>,
}

impl RecordHash {
    /// Whether this hash uses SHA-256 or a stronger SHA-2/SHA-3 algorithm. The
    /// wheel spec deprecates `md5`/`sha1`; a strict verifier requires at least
    /// SHA-256. The digest length is also checked so a truncated/`sha256=`-labeled
    /// short digest does not pass as strong.
    pub fn is_strong(&self) -> bool {
        match self.algorithm.as_str() {
            "sha256" => self.digest.len() == 32,
            "sha384" => self.digest.len() == 48,
            "sha512" => self.digest.len() == 64,
            // sha3-256/384/512 are also acceptable strong hashes.
            "sha3_256" | "sha3-256" => self.digest.len() == 32,
            "sha3_384" | "sha3-384" => self.digest.len() == 48,
            "sha3_512" | "sha3-512" => self.digest.len() == 64,
            _ => false,
        }
    }
}

/// One parsed RECORD row: the recorded path, its optional hash, and its optional
/// size. The wheel/installed specs allow the hash and size columns to be EMPTY
/// for some files (notably RECORD itself, and `.pyc`/data files in an installed
/// tree), so both are `Option`; an empty column is "unverifiable", which is
/// different from "present but wrong".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordEntry {
    /// The path exactly as written in the RECORD (still ecosystem-encoded:
    /// forward slashes in a wheel, possibly absolute or backslash-separated in an
    /// installed RECORD). Normalization is the verifier's job, not the parser's.
    pub path: String,
    /// The recorded hash, or `None` when the hash column was empty.
    pub hash: Option<RecordHash>,
    /// The recorded size in bytes, or `None` when the size column was empty.
    pub size: Option<u64>,
}

/// An error parsing a RECORD file: either the CSV itself was malformed, or a row
/// did not have the three expected columns. A hash/size that is merely EMPTY is
/// NOT an error (it is a valid "unverifiable" row); only structural breakage is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordParseError {
    /// The CSV could not be parsed (unterminated quote, etc.).
    MalformedCsv(String),
    /// A row had the wrong number of columns (RECORD is always 3: path, hash,
    /// size).
    BadRow { row: usize, columns: usize },
    /// A row had the three expected columns but an EMPTY path field. This is its
    /// own error rather than a `BadRow { columns: 3 }`, which would falsely claim
    /// a column-count problem on a row that has the right number of columns.
    EmptyPath { row: usize },
    /// A hash field was present but not `<algorithm>=<base64url>` shaped, or the
    /// base64 digest did not decode.
    BadHash { row: usize, value: String },
    /// A size field was present but not a non-negative integer.
    BadSize { row: usize, value: String },
}

impl std::fmt::Display for RecordParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordParseError::MalformedCsv(e) => write!(f, "malformed RECORD CSV: {e}"),
            RecordParseError::BadRow { row, columns } => {
                write!(f, "RECORD row {row} has {columns} columns, expected 3")
            }
            RecordParseError::EmptyPath { row } => {
                write!(f, "RECORD row {row} has an empty path field")
            }
            RecordParseError::BadHash { row, value } => {
                write!(f, "RECORD row {row} has an unparseable hash '{value}'")
            }
            RecordParseError::BadSize { row, value } => {
                write!(f, "RECORD row {row} has an unparseable size '{value}'")
            }
        }
    }
}

impl std::error::Error for RecordParseError {}

/// Parse a `RECORD` file into its rows using the `csv` crate (RECORD has no
/// header row, and a path field may legitimately contain a comma, so it MUST be
/// parsed as CSV with quoting, never split by hand). Each row is
/// `path,hash,size`; the hash and size columns may be empty. Returns every parsed
/// entry, or a [`RecordParseError`] on structural breakage.
pub fn parse_record(text: &str) -> Result<Vec<RecordEntry>, RecordParseError> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(false)
        .from_reader(text.as_bytes());

    let mut entries: Vec<RecordEntry> = Vec::new();
    for (i, record) in reader.records().enumerate() {
        let row = i + 1;
        let record = record.map_err(|e| RecordParseError::MalformedCsv(e.to_string()))?;
        // A wholly blank trailing line yields an empty record; skip it.
        if record.iter().all(|f| f.is_empty()) {
            continue;
        }
        if record.len() != 3 {
            return Err(RecordParseError::BadRow {
                row,
                columns: record.len(),
            });
        }
        let path = record[0].to_string();
        if path.is_empty() {
            // A row with the right column count but no path is meaningless; report
            // it as an empty-path row, not a (false) column-count error.
            return Err(RecordParseError::EmptyPath { row });
        }
        let hash = parse_record_hash(&record[1]).map_err(|()| RecordParseError::BadHash {
            row,
            value: record[1].to_string(),
        })?;
        let size = parse_record_size(&record[2]).map_err(|()| RecordParseError::BadSize {
            row,
            value: record[2].to_string(),
        })?;
        entries.push(RecordEntry { path, hash, size });
    }
    Ok(entries)
}

/// Parse a RECORD hash cell. `""` -> `Ok(None)` (a legitimately unverifiable
/// row). `"<algorithm>=<base64url>"` -> `Ok(Some(..))`. Anything else -> `Err`.
fn parse_record_hash(cell: &str) -> Result<Option<RecordHash>, ()> {
    let cell = cell.trim();
    if cell.is_empty() {
        return Ok(None);
    }
    let (algorithm, b64) = cell.split_once('=').ok_or(())?;
    let algorithm = algorithm.trim().to_ascii_lowercase();
    let b64 = b64.trim();
    if algorithm.is_empty() || b64.is_empty() {
        return Err(());
    }
    let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| ())?;
    Ok(Some(RecordHash { algorithm, digest }))
}

/// Parse a RECORD size cell. `""` -> `Ok(None)`. A non-negative integer ->
/// `Ok(Some(n))`. Anything else -> `Err`.
fn parse_record_size(cell: &str) -> Result<Option<u64>, ()> {
    let cell = cell.trim();
    if cell.is_empty() {
        return Ok(None);
    }
    cell.parse::<u64>().map(Some).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_headers_stop_at_blank_line() {
        let text = "Metadata-Version: 2.1\nName: Demo-Pkg\nVersion: 1.4.2\n\nName: not-a-header\n";
        let (name, version) = parse_metadata_headers(text).unwrap();
        assert_eq!(name, "Demo-Pkg");
        assert_eq!(version.as_deref(), Some("1.4.2"));
    }

    #[test]
    fn metadata_without_name_is_none() {
        assert!(parse_metadata_headers("Version: 1.0\n\n").is_none());
    }

    #[test]
    fn wheel_root_is_purelib_parsed() {
        let meta = parse_wheel_metadata(
            "Wheel-Version: 1.0\nGenerator: bdist_wheel\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        );
        assert_eq!(meta.wheel_version.as_deref(), Some("1.0"));
        assert_eq!(meta.root_is_purelib, Some(true));
        assert_eq!(meta.tags, vec!["py3-none-any".to_string()]);
    }

    #[test]
    fn wheel_root_is_purelib_false() {
        let meta = parse_wheel_metadata("Wheel-Version: 1.0\nRoot-Is-Purelib: false\n");
        assert_eq!(meta.root_is_purelib, Some(false));
    }

    #[test]
    fn entry_points_keep_module_object_separate() {
        let text = "[console_scripts]\ndemo = demo.cli:main\nbare = demo.run\n\n[gui_scripts]\nui = demo.ui:start [gui]\n";
        let eps = parse_entry_points(text);
        assert_eq!(eps.len(), 3);
        assert_eq!(eps[0].group, "console_scripts");
        assert_eq!(eps[0].name, "demo");
        assert_eq!(eps[0].module, "demo.cli");
        assert_eq!(eps[0].object.as_deref(), Some("main"));
        // A bare `module` (no `:object`) is legal.
        assert_eq!(eps[1].module, "demo.run");
        assert_eq!(eps[1].object, None);
        // The `[gui]` extras suffix is stripped, the group is tracked.
        assert_eq!(eps[2].group, "gui_scripts");
        assert_eq!(eps[2].module, "demo.ui");
        assert_eq!(eps[2].object.as_deref(), Some("start"));
    }

    #[test]
    fn direct_url_editable_detected() {
        let text = r#"{"url":"file:///home/me/proj","dir_info":{"editable":true}}"#;
        let du = parse_direct_url(text).unwrap();
        assert!(du.editable);
        assert!(!du.vcs);
        assert_eq!(du.url.as_deref(), Some("file:///home/me/proj"));
    }

    #[test]
    fn direct_url_vcs_detected() {
        let text = r#"{"url":"https://github.com/x/y","vcs_info":{"vcs":"git","commit_id":"abc"}}"#;
        let du = parse_direct_url(text).unwrap();
        assert!(du.vcs);
        assert!(!du.editable);
    }

    #[test]
    fn record_hash_strength() {
        let strong = parse_record_hash(&format!(
            "sha256={}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32])
        ))
        .unwrap()
        .unwrap();
        assert!(strong.is_strong());
        assert_eq!(strong.algorithm, "sha256");

        // An md5 hash is NOT strong.
        let weak = parse_record_hash(&format!(
            "md5={}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 16])
        ))
        .unwrap()
        .unwrap();
        assert!(!weak.is_strong());

        // A sha256 label with a too-short digest is NOT strong (truncation guard).
        let truncated = parse_record_hash(&format!(
            "sha256={}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 8])
        ))
        .unwrap()
        .unwrap();
        assert!(!truncated.is_strong());
    }

    #[test]
    fn record_empty_hash_is_unverifiable_not_error() {
        // RECORD's own row is `path,,` (empty hash and size); that is valid.
        let entries =
            parse_record("demo/__init__.py,sha256=AAAA,15\ndemo-1.0.dist-info/RECORD,,\n").unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[1].hash.is_none());
        assert!(entries[1].size.is_none());
        assert_eq!(entries[1].path, "demo-1.0.dist-info/RECORD");
    }

    #[test]
    fn record_path_with_quoted_comma_parses() {
        // A filename containing a comma is CSV-quoted; the path must survive whole,
        // never be split into extra columns.
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]);
        let text = format!("\"demo/weird, name.py\",sha256={b64},42\n");
        let entries = parse_record(&text).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "demo/weird, name.py");
        assert_eq!(entries[0].size, Some(42));
        assert!(entries[0].hash.as_ref().unwrap().is_strong());
    }

    #[test]
    fn record_bad_row_column_count_errors() {
        // Two columns instead of three is structural breakage.
        let err = parse_record("demo/x.py,sha256=AAAA\n").unwrap_err();
        assert!(matches!(err, RecordParseError::BadRow { columns: 2, .. }));
    }

    #[test]
    fn parse_record_empty_path_is_empty_path_not_bad_row() {
        // A row with three columns but an empty path must be reported as
        // EmptyPath, NOT a (false) BadRow column-count error.
        let err = parse_record(",sha256=AAAA,10\n").unwrap_err();
        assert!(
            matches!(err, RecordParseError::EmptyPath { row: 1 }),
            "expected EmptyPath, got {err:?}"
        );
    }

    #[test]
    fn record_bad_size_errors() {
        let err = parse_record("demo/x.py,,not-a-number\n").unwrap_err();
        assert!(matches!(err, RecordParseError::BadSize { .. }));
    }

    #[test]
    fn record_bad_hash_errors() {
        // A non-empty hash cell that is not `alg=b64` is an error.
        let err = parse_record("demo/x.py,garbage,10\n").unwrap_err();
        assert!(matches!(err, RecordParseError::BadHash { .. }));
    }
}
