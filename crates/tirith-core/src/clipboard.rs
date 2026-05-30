//! Cross-platform clipboard helpers (M7 ch3).
//!
//! Thin wrapper around [`arboard`](https://crates.io/crates/arboard) that:
//!
//! 1. Translates `arboard::Error` into a tirith-friendly [`ClipboardError`]
//!    so callers don't have to depend on `arboard` directly.
//! 2. Maps "no clipboard backend" (Linux without X/Wayland, headless CI)
//!    onto [`ClipboardError::NoBackend`] so the CLI can degrade to a
//!    documented JSON envelope instead of panicking.
//!
//! The clipboard helpers are intentionally tiny — text-only, no images,
//! no clear-on-exit hooks. The full feature surface (debounced polling,
//! audit-log on secret detect) lives in `crates/tirith/src/cli/clipboard.rs`
//! where the polling lifecycle is owned by the daemon command.
//!
//! ## Headless behavior
//!
//! On Linux without `$DISPLAY` or `$WAYLAND_DISPLAY` and on Windows session
//! 0 ("non-interactive" services), `arboard::Clipboard::new()` returns an
//! error. We classify any such failure as `NoBackend` — the CLI surfaces
//! this as a soft "no clipboard backend" envelope so headless CI runners
//! and SSH sessions don't see a hard panic.
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

/// Upper bound on the bytes we read from the companion `clipboard_source.json`.
/// The record is a tiny JSON object (a timestamp, a sha256 hex, a URL, a title,
/// a bool); 64 KiB is far more than a genuine record needs, so anything larger
/// is treated as unreadable (→ `None`) rather than buffered. Mirrors the
/// incident-flag / command-card read caps.
///
/// Public so the browser native-messaging host (`tirith browser host`) can reject
/// a record whose serialized form would exceed what this READER will later accept
/// — otherwise a 64–256 KiB record passes the host's wire-frame cap, is written,
/// and is then unreadable by the paste-provenance path.
pub const SOURCE_READ_CAP: u64 = 64 * 1024;

/// One record written by the companion browser extension (M12 ch1) each time it
/// sets the system clipboard. tirith reads (never writes) this file to attribute
/// a paste to the page it was copied from. See [`read_source_record_at`] and the
/// `paste_provenance` rule.
///
/// The extension lives in a SEPARATE repo; this struct is the on-disk contract.
/// Unknown fields are ignored (serde default) so a newer extension that adds
/// fields does not break an older tirith.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipboardSourceRecord {
    /// RFC-3339 timestamp the extension set the clipboard.
    pub updated_at: String,
    /// Lowercase-hex SHA-256 of the clipboard content the extension wrote. The
    /// `paste_provenance` rule compares this against `sha256(pasted_input)`; a
    /// mismatch means the paste did NOT come from this recorded source, so no
    /// attribution is made.
    pub content_sha256: String,
    /// The page URL the content was copied from.
    pub source_url: String,
    /// The page title the content was copied from (best-effort, may be empty).
    #[serde(default)]
    pub source_title: String,
    /// Whether the extension detected hidden / invisible text in the copied
    /// selection (a risk signal the rule escalates on).
    #[serde(default)]
    pub hidden_text_detected: bool,
}

/// Tri-state describing what a caller knows about the companion clipboard-source
/// record, threaded through [`crate::engine::AnalysisContext::clipboard_source`].
///
/// The earlier `Option<ClipboardSourceRecord>` collapsed two DISTINCT states into
/// `None`: "the caller never tried to read the sidecar" and "the caller read it
/// and found nothing usable". That ambiguity reopened the G1 TOCTOU window — when
/// `tirith paste --with-source` read the file, found nothing, and set `None`, the
/// engine would STILL re-read the file from disk, so a sidecar written between the
/// two reads could fire `PasteSourceMismatch` while the CLI displayed "no source".
/// The tri-state makes the caller's intent explicit:
///
/// * [`Unread`](ClipboardSourceState::Unread) — the caller did NOT consult the
///   sidecar (e.g. plain `tirith paste`). The engine may read it once itself.
/// * [`AbsentOrInvalid`](ClipboardSourceState::AbsentOrInvalid) — the caller
///   DEFINITIVELY tried (`--with-source`) and found no usable record. The engine
///   must NOT re-read disk: the caller already decided there is no source, so the
///   finding and the CLI display cannot disagree.
/// * [`Loaded`](ClipboardSourceState::Loaded) — the caller read a usable record
///   and hands the SAME in-memory copy to the engine, so the
///   `paste_source_mismatch` finding and the displayed attribution agree
///   byte-for-byte.
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
/// `None` when the state dir cannot be resolved (no `$HOME`, no `$XDG_STATE_HOME`).
pub fn source_file_path() -> Option<PathBuf> {
    crate::policy::state_dir().map(|d| d.join("clipboard_source.json"))
}

/// Read + parse the companion record at `path` (test seam). FAIL-SAFE: a
/// missing, non-regular, oversized, unreadable, or unparseable file yields
/// `None` — never a panic. The paste-provenance rule treats `None` as "no
/// source recorded" and emits no finding.
///
/// Goes through the shared, race-free [`crate::util::read_regular_capped`]
/// helper (the same one the command-card / incident-flag reads use): it opens
/// with `O_NONBLOCK` and `fstat`s the OPEN fd, so a `clipboard_source.json`
/// swapped for a FIFO / device cannot hang the paste path, and the read is
/// capped at [`SOURCE_READ_CAP`].
pub fn read_source_record_at(path: &Path) -> Option<ClipboardSourceRecord> {
    let bytes = crate::util::read_regular_capped(path, SOURCE_READ_CAP).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Production entry point: read the companion record from the default path
/// (`state_dir()/clipboard_source.json`). `None` when the state dir cannot be
/// resolved, the file is absent, or it is unreadable / malformed.
pub fn read_source_record() -> Option<ClipboardSourceRecord> {
    source_file_path().and_then(|p| read_source_record_at(&p))
}

/// `true` when the companion record at `path` exists and has at least one byte.
/// A cheap `metadata()` stat — no parse. Used by the engine's tier-1 force-past
/// decision so a no-extension machine pays a single stat. Mirrors
/// [`crate::canary::store_nonempty_at`].
pub fn source_file_nonempty_at(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
}

/// Production entry point for the engine's tier-1 force-past decision: `true`
/// when `state_dir()/clipboard_source.json` exists and is non-empty. A single
/// stat, free when the companion extension was never installed.
pub fn source_file_nonempty() -> bool {
    source_file_path()
        .map(|p| source_file_nonempty_at(&p))
        .unwrap_or(false)
}

/// Failure modes for clipboard access.
///
/// `NoBackend` is the soft-fail path: callers should report it as a
/// degraded state (empty envelope, exit 0 in JSON mode) rather than a
/// hard error so headless CI runners and SSH sessions don't trip alerts.
#[derive(Debug, Error)]
pub enum ClipboardError {
    /// No clipboard backend is available (e.g. Linux without X or
    /// Wayland, or a non-interactive Windows session). Caller should
    /// degrade gracefully, not panic.
    #[error("no clipboard backend available (headless display server?)")]
    NoBackend,

    /// `arboard` rejected the request for an unrelated reason — e.g.
    /// content type mismatch, an actively-held selection elsewhere, or
    /// an OS-level permissions denial.
    #[error("clipboard error: {0}")]
    Other(String),
}

/// Read the clipboard's text payload. Returns `Ok(None)` when the
/// clipboard is empty or carries non-text content (an image, a file
/// list, etc.). Returns `Err(NoBackend)` when no clipboard backend is
/// available.
///
/// Underlying calls are routed through `arboard::Clipboard::new()` +
/// `get_text()`. `arboard` documents `ContentNotAvailable` for
/// non-text payloads, which we collapse into `Ok(None)`.
pub fn read_clipboard_text() -> Result<Option<String>, ClipboardError> {
    let mut cb = open_clipboard()?;
    match cb.get_text() {
        Ok(s) => Ok(Some(s)),
        // Non-text payload (e.g. image, file list) is normal — surface
        // as `Ok(None)` rather than an error.
        Err(arboard::Error::ContentNotAvailable) => Ok(None),
        Err(e) => Err(classify_arboard_error(e)),
    }
}

/// Replace the clipboard's text payload with `s`. Returns
/// `Err(NoBackend)` when no clipboard backend is available.
pub fn write_clipboard_text(s: &str) -> Result<(), ClipboardError> {
    let mut cb = open_clipboard()?;
    cb.set_text(s.to_string()).map_err(classify_arboard_error)
}

/// Opens an arboard handle, classifying the new()-side failure into a
/// `NoBackend` when the OS reports no display server.
fn open_clipboard() -> Result<arboard::Clipboard, ClipboardError> {
    arboard::Clipboard::new().map_err(classify_arboard_error)
}

/// Classify an `arboard::Error` into the right `ClipboardError` variant.
///
/// `arboard` doesn't expose a stable typed "headless" discriminator —
/// the symptom shows up either as `ClipboardOccupied` or, more often,
/// as `Unknown { description: "No X/Wayland display..." }`. We pattern-
/// match on the rendered description so the CLI sees the same
/// `NoBackend` regardless of which underlying init path failed.
fn classify_arboard_error(e: arboard::Error) -> ClipboardError {
    let rendered = e.to_string();
    let lc = rendered.to_ascii_lowercase();

    // Linux X11/Wayland init failure paths surface as "no display server",
    // "wayland display not found", "x11 display not found", "could not
    // open display", etc. Windows non-interactive session-0 returns
    // "OpenClipboard failed". Match a small set of keywords rather than
    // exact strings so we don't get brittle on minor arboard rev bumps.
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

    /// `ClipboardError::NoBackend` renders a stable human message — the
    /// CLI's JSON envelope quotes it back, so the wording is part of the
    /// public contract.
    #[test]
    fn no_backend_renders_stable_message() {
        let msg = ClipboardError::NoBackend.to_string();
        assert!(msg.contains("no clipboard backend"));
    }

    /// `ClipboardError::Other` carries the upstream message through
    /// unchanged so debugging an arboard failure doesn't require
    /// repro'ing the headless case.
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
        // `source_title` and `hidden_text_detected` are `#[serde(default)]` so an
        // older / minimal extension record without them still parses.
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

    /// The tri-state defaults to `Unread` — the safe "caller never looked"
    /// state, so every `AnalysisContext` built without explicitly addressing the
    /// clipboard sidecar lets the engine read it once itself (the historical
    /// plain-`tirith paste` behavior). `AbsentOrInvalid` / `Loaded` are set ONLY
    /// by a caller that definitively consulted the sidecar.
    #[test]
    fn clipboard_source_state_defaults_to_unread() {
        assert!(matches!(
            ClipboardSourceState::default(),
            ClipboardSourceState::Unread
        ));
    }
}
