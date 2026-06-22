#![no_main]
//! Persistent fuzz target for the wheel + native + `.pth` artifact parsers
//! (plan unit G2). Drives the same byte-level seams the synthetic lab fixtures
//! feed:
//!
//!   * `archive::read_wheel_default` — the wheel (zip) reader, which streams each
//!     member under the archive limits and hands native members to the triage
//!     visitor. This is the primary entry: arbitrary bytes here must never panic
//!     (a non-archive is a structural rejection, not a crash).
//!   * `pth::scan_capabilities` / `pth::analyze_body` — the `.pth` / startup-hook
//!     body analyzers, fed the same bytes as a lossy UTF-8 string.
//!
//! Contract under fuzz: NEVER panic. Every parse path is fallible and degrades to
//! partial facts or a structural rejection, never an abort.
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

use tirith_core::artifact::archive::read_wheel_default;
use tirith_core::artifact::pth::{self, StartupHookKind};
use tirith_core::location::SubjectLocation;

fuzz_target!(|data: &[u8]| {
    // Wheel reader: the outer name/sha are fixed; the reader does not re-read the
    // outer file, so any 64-hex placeholder is fine. A `Cursor` is Read + Seek.
    let placeholder_sha = "0".repeat(64);
    let _ = read_wheel_default(Cursor::new(data), "fuzz-1.0-py3-none-any.whl", &placeholder_sha);

    // `.pth` / startup-hook body analyzers over the same bytes as text.
    let body = String::from_utf8_lossy(data);
    let _ = pth::scan_capabilities(&body);
    let loc = SubjectLocation::installed("/venv/lib/site-packages/fuzz.pth");
    let _ = pth::analyze_body(&body, &loc, StartupHookKind::Pth);
});
