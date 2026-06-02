//! Cross-platform clipboard helpers (M7 ch3). Thin text-only wrapper around
//! [`arboard`](https://crates.io/crates/arboard): translates `arboard::Error`
//! into [`ClipboardError`], and maps "no clipboard backend" (Linux without
//! X/Wayland, headless CI, Windows session 0) onto [`ClipboardError::NoBackend`]
//! so the CLI degrades to a soft JSON envelope instead of panicking. The full
//! polling/audit lifecycle lives in `crates/tirith/src/cli/clipboard.rs`.
//!
//! ## Examples
//!
//! ```no_run
//! use tirith_core::clipboard;
//!
//! match clipboard::read_clipboard_text() {
//!     Ok(Some(text)) => println!("clipboard has {} bytes", text.len()),
//!     Ok(None) => println!("clipboard is empty"),
//!     Err(clipboard::ClipboardError::NoBackend) => {
//!         println!("no clipboard backend (likely headless)");
//!     }
//!     Err(e) => eprintln!("clipboard error: {e}"),
//! }
//! ```

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Read cap for the companion `clipboard_source.json`; larger → unreadable
/// (`None`) rather than buffered. Mirrors the incident-flag / command-card caps.
/// Public so `tirith browser host` rejects a record whose serialized form would
/// exceed what this reader accepts (else it writes a record it can't read back).
pub const SOURCE_READ_CAP: u64 = 64 * 1024;

/// One record the companion browser extension (M12 ch1) writes each time it sets
/// the clipboard; tirith reads (never writes) it to attribute a paste to its
/// source page. The extension lives in a SEPARATE repo, so this struct is the
/// on-disk contract — unknown fields are ignored so a newer extension doesn't
/// break an older tirith.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardSourceRecord {
    /// RFC-3339 timestamp the extension set the clipboard.
    pub updated_at: String,
    /// Lowercase-hex SHA-256 of the written content. `paste_provenance` compares
    /// it to `sha256(pasted_input)`; a mismatch means no attribution.
    pub content_sha256: String,
    /// The page URL the content was copied from.
    pub source_url: String,
    /// The page title (best-effort, may be empty).
    #[serde(default)]
    pub source_title: String,
    /// Whether the extension flagged hidden/invisible text in the selection.
    #[serde(default)]
    pub hidden_text_detected: bool,
}

impl ClipboardSourceRecord {
    /// True when `raw` hashes to this record's `content_sha256`. The single
    /// comparison both `paste_source_mismatch` and the CLI display use, so they
    /// can't disagree. Case-insensitive; trims the stored hash.
    pub fn matches_bytes(&self, raw: &[u8]) -> bool {
        content_sha256_hex(raw).eq_ignore_ascii_case(self.content_sha256.trim())
    }
}

/// Tri-state for what a caller knows about the companion clipboard-source record,
/// threaded through [`crate::engine::AnalysisContext::clipboard_source`]. Replaces
/// an `Option` whose `None` conflated "never looked" with "looked, found nothing"
/// — that ambiguity reopened the G1 TOCTOU (the engine re-read disk after a
/// `--with-source` miss, so a sidecar written between the two reads could fire
/// `PasteSourceMismatch` while the CLI showed "no source"). Variants below make
/// intent explicit so the finding and the CLI display can never disagree.
#[derive(Debug, Clone, Default)]
pub enum ClipboardSourceState {
    /// The caller never consulted the sidecar; the engine may read it once.
    #[default]
    Unread,
    /// The caller tried and found no usable record; the engine must not re-read.
    AbsentOrInvalid,
    /// The caller loaded this record and passes it through unchanged.
    Loaded(ClipboardSourceRecord),
}

/// Default on-disk path of the companion record: `state_dir()/clipboard_source.json`.
/// `None` when the tirith state directory cannot be resolved.
pub fn source_file_path() -> Option<PathBuf> {
    crate::policy::state_dir().map(|d| d.join("clipboard_source.json"))
}

/// Read + parse the companion record at `path` (test seam). FAIL-SAFE: a
/// missing/non-regular/oversized/unreadable/unparseable file yields `None`, never
/// a panic. Goes through race-free [`crate::util::read_regular_capped`]
/// (`O_NONBLOCK` + `fstat` on the open fd, capped at [`SOURCE_READ_CAP`]) so a
/// file swapped for a FIFO/device can't hang the paste path.
pub fn read_source_record_at(path: &Path) -> Option<ClipboardSourceRecord> {
    let bytes = crate::util::read_regular_capped(path, SOURCE_READ_CAP).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Read the companion record from the default `state_dir()/clipboard_source.json`.
/// `None` when the state dir is unresolved, or the file is absent/unreadable/malformed.
pub fn read_source_record() -> Option<ClipboardSourceRecord> {
    source_file_path().and_then(|p| read_source_record_at(&p))
}

/// `true` when the companion record at `path` is a non-empty REGULAR file (one
/// `metadata()` stat, no parse) — the engine's tier-1 force-past probe. Requires
/// `is_file()` (CodeRabbit R7) to match the reader contract: a stray directory
/// (non-zero `len()` on some FS) must not force the slow-path for a record
/// [`read_source_record_at`] would reject.
pub fn source_file_nonempty_at(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.len() > 0)
        .unwrap_or(false)
}

/// `true` when `state_dir()/clipboard_source.json` exists and is non-empty (one
/// stat) — the engine's tier-1 force-past decision; free without the extension.
pub fn source_file_nonempty() -> bool {
    source_file_path()
        .map(|p| source_file_nonempty_at(&p))
        .unwrap_or(false)
}

/// Lowercase-hex SHA-256 of `bytes` — the single source of truth for the
/// clipboard-content hash (Greptile R1 #6) so the record, the rule, and the CLI
/// displays can never drift apart.
pub fn content_sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Failure modes for clipboard access. `NoBackend` is the soft-fail path —
/// callers degrade (empty envelope, exit 0 in JSON mode), never panic.
#[derive(Debug, Error)]
pub enum ClipboardError {
    /// No clipboard backend (Linux without X/Wayland, non-interactive Windows
    /// session). Caller degrades gracefully.
    #[error("no clipboard backend available (headless display server?)")]
    NoBackend,

    /// `arboard` rejected the request (content-type mismatch, held selection,
    /// permissions denial, …).
    #[error("clipboard error: {0}")]
    Other(String),
}

/// Read the clipboard's text payload. `Ok(None)` when empty or non-text (image,
/// file list); `Err(NoBackend)` when no backend is available.
pub fn read_clipboard_text() -> Result<Option<String>, ClipboardError> {
    let mut cb = open_clipboard()?;
    match cb.get_text() {
        Ok(s) => Ok(Some(s)),
        // Non-text payload is normal → Ok(None).
        Err(arboard::Error::ContentNotAvailable) => Ok(None),
        Err(e) => Err(classify_arboard_error(e)),
    }
}

/// Replace the clipboard's text payload with `s`. `Err(NoBackend)` if no backend.
pub fn write_clipboard_text(s: &str) -> Result<(), ClipboardError> {
    let mut cb = open_clipboard()?;
    cb.set_text(s.to_string()).map_err(classify_arboard_error)
}

/// Open an arboard handle, mapping a new()-side failure to `NoBackend`.
fn open_clipboard() -> Result<arboard::Clipboard, ClipboardError> {
    arboard::Clipboard::new().map_err(classify_arboard_error)
}

/// Classify an `arboard::Error`. `arboard` has no stable typed "headless"
/// discriminator, so we keyword-match the rendered description (resilient to
/// minor arboard rev bumps).
fn classify_arboard_error(e: arboard::Error) -> ClipboardError {
    let rendered = e.to_string();
    let lc = rendered.to_ascii_lowercase();

    // Linux X11/Wayland init failures and Windows session-0
    // "OpenClipboard failed" all collapse to NoBackend.
    if lc.contains("no display server")
        || lc.contains("display not found")
        || lc.contains("could not open display")
        || lc.contains("wayland_display")
        || lc.contains("openclipboard failed")
        || lc.contains("no x11 display")
        || lc.contains("could not connect to display")
    {
        return ClipboardError::NoBackend;
    }

    ClipboardError::Other(rendered)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `NoBackend`'s message is part of the public contract (the CLI JSON
    /// envelope quotes it back).
    #[test]
    fn no_backend_renders_stable_message() {
        let msg = ClipboardError::NoBackend.to_string();
        assert!(msg.contains("no clipboard backend"));
    }

    /// `Other` carries the upstream message through unchanged.
    #[test]
    fn other_passes_through_upstream_message() {
        let e = ClipboardError::Other("permissions denied".into());
        assert!(e.to_string().contains("permissions denied"));
    }

    // ---- companion clipboard-source record (M12 ch1) ----------------------

    use tempfile::tempdir;

    #[test]
    fn source_record_roundtrips_from_disk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("clipboard_source.json");
        std::fs::write(
            &path,
            r#"{"updated_at":"2026-05-30T00:00:00Z","content_sha256":"abc123","source_url":"https://docs.example.com/install","source_title":"Install","hidden_text_detected":false}"#,
        )
        .unwrap();
        let rec = read_source_record_at(&path).expect("record parses");
        assert_eq!(rec.content_sha256, "abc123");
        assert_eq!(rec.source_url, "https://docs.example.com/install");
        assert_eq!(rec.source_title, "Install");
        assert!(!rec.hidden_text_detected);
    }

    #[test]
    fn source_record_optional_fields_default() {
        // `#[serde(default)]` fields let a minimal/older record still parse.
        let dir = tempdir().unwrap();
        let path = dir.path().join("clipboard_source.json");
        std::fs::write(
            &path,
            r#"{"updated_at":"t","content_sha256":"deadbeef","source_url":"https://x.example"}"#,
        )
        .unwrap();
        let rec = read_source_record_at(&path).expect("record parses with defaults");
        assert_eq!(rec.source_title, "");
        assert!(!rec.hidden_text_detected);
    }

    #[test]
    fn source_record_absent_is_none_not_panic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("clipboard_source.json");
        // File never created — fail-safe to None.
        assert!(read_source_record_at(&path).is_none());
        assert!(!source_file_nonempty_at(&path));
    }

    #[test]
    fn source_record_malformed_is_none() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("clipboard_source.json");
        std::fs::write(&path, b"this is not json").unwrap();
        // Present-but-unparseable → None (and nonempty stat is true, but the
        // parse failing is what makes the rule treat it as "no source").
        assert!(read_source_record_at(&path).is_none());
        assert!(source_file_nonempty_at(&path));
    }

    #[test]
    fn source_file_nonempty_reflects_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("clipboard_source.json");
        assert!(!source_file_nonempty_at(&path));
        std::fs::write(&path, b"{}").unwrap();
        assert!(source_file_nonempty_at(&path));
    }

    #[test]
    fn source_file_nonempty_rejects_a_directory() {
        // CodeRabbit R7: a directory at the path (non-zero len() on some
        // filesystems) must NOT count as a non-empty record — the reader only
        // accepts a regular file, so the fast-path probe must too.
        let dir = tempdir().unwrap();
        let as_dir = dir.path().join("clipboard_source.json");
        std::fs::create_dir(&as_dir).unwrap();
        assert!(
            !source_file_nonempty_at(&as_dir),
            "a directory must not be treated as a non-empty source record"
        );
    }

    /// The tri-state defaults to `Unread` (the safe "caller never looked" state);
    /// `AbsentOrInvalid`/`Loaded` are set only by a caller that consulted the sidecar.
    #[test]
    fn clipboard_source_state_defaults_to_unread() {
        assert!(matches!(
            ClipboardSourceState::default(),
            ClipboardSourceState::Unread
        ));
    }
}
