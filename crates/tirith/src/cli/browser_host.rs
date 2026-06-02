//! M12 ch3 — `tirith browser host`: the Chrome **Native Messaging** host.
//!
//! The companion browser extension (a SEPARATE repo) speaks Chrome's native
//! messaging protocol to this binary over stdin/stdout. Each message is framed
//! as:
//!
//! ```text
//!   [ 4-byte length prefix, NATIVE byte order ][ that many bytes of UTF-8 JSON ]
//! ```
//!
//! Each valid frame is deserialized into a
//! [`tirith_core::clipboard::ClipboardSourceRecord`] and written ATOMICALLY to
//! `state_dir()/clipboard_source.json` (the same file the engine's
//! `paste_source_mismatch` rule reads), then a `{"ok":true}` ack frame is sent.
//!
//! Security model — the browser side is an UNTRUSTED input boundary into a file
//! the engine later reads. Three defenses: (1) a hard [`MAX_FRAME_BYTES`] cap
//! enforced BEFORE allocating, aborting the stream on an oversized prefix; (2)
//! schema validation before write (a non-parsing frame is ack'd false and never
//! touches disk); (3) atomic write via [`crate::cli::write_file_atomic`].
//!
//! Runs until stdin EOF. Hidden from `--help` (invoked by Chrome, not a human).

use std::io::{Read, Write};

use tirith_core::clipboard::SOURCE_READ_CAP;

/// Hard cap on a single incoming frame: 256 KiB. The companion record is tiny;
/// the cap stops a hostile / desynced length prefix from forcing an arbitrary
/// allocation. Larger than the 64 KiB file-side read cap ([`SOURCE_READ_CAP`]).
pub const MAX_FRAME_BYTES: u32 = 256 * 1024;

/// `true` when a re-serialized record fits the FILE-side read cap
/// ([`SOURCE_READ_CAP`], 64 KiB). The wire cap ([`MAX_FRAME_BYTES`], 256 KiB) is
/// larger, so a record in the 64–256 KiB band would frame fine, be written, then
/// be silently UNREADABLE — refuse to persist it. The reader rejects strictly
/// larger than the cap, so the boundary here is `<=`.
fn serialized_fits_read_cap(bytes: &[u8]) -> bool {
    bytes.len() as u64 <= SOURCE_READ_CAP
}

/// Outcome of attempting to read one native-messaging frame from a reader.
#[derive(Debug)]
pub enum FrameRead {
    /// A complete frame's JSON payload bytes.
    Frame(Vec<u8>),
    /// Clean end of stream (the 4-byte prefix could not be fully read because
    /// the peer closed). The host loop exits 0 on this.
    Eof,
    /// The declared length exceeded [`MAX_FRAME_BYTES`] (carried for
    /// diagnostics). Fatal — a bogus length means framing is untrustworthy, so
    /// the host stops rather than resync. The oversized payload is never read.
    TooLarge(u32),
    /// The prefix promised N body bytes but the stream ended/errored first.
    /// Fatal — framing is broken.
    Truncated,
}

/// Read exactly one native-messaging frame from `reader`: a 4-byte native-order
/// length prefix (`u32::from_ne_bytes`, per Chrome), then that many payload
/// bytes. [`FrameRead::Eof`] for a clean inter-frame close; [`FrameRead::TooLarge`]
/// when the prefix exceeds [`MAX_FRAME_BYTES`] (body never read);
/// [`FrameRead::Truncated`] for a partial prefix or short body.
pub fn read_frame<R: Read>(reader: &mut R) -> FrameRead {
    let mut len_buf = [0u8; 4];
    match read_exact_or_eof(reader, &mut len_buf) {
        ReadExact::Ok => {}
        // Zero bytes before the prefix = clean EOF between frames.
        ReadExact::Eof => return FrameRead::Eof,
        // A partial prefix (1–3 bytes then EOF/error) = broken framing.
        ReadExact::Short | ReadExact::Err => return FrameRead::Truncated,
    }
    let len = u32::from_ne_bytes(len_buf);

    // Enforce the cap BEFORE allocating.
    if len > MAX_FRAME_BYTES {
        return FrameRead::TooLarge(len);
    }

    // A zero-length frame is well-formed but won't parse, so it's ack'd false.
    let mut payload = vec![0u8; len as usize];
    match read_exact_or_eof(reader, &mut payload) {
        ReadExact::Ok => FrameRead::Frame(payload),
        ReadExact::Eof | ReadExact::Short | ReadExact::Err => FrameRead::Truncated,
    }
}

/// Result of [`read_exact_or_eof`].
enum ReadExact {
    /// The buffer was filled completely.
    Ok,
    /// Zero bytes were read before EOF (clean stream end at a frame boundary).
    Eof,
    /// Some (but not all) bytes were read before EOF (truncated).
    Short,
    /// A non-EOF I/O error occurred.
    Err,
}

/// Fill `buf` completely, distinguishing "clean EOF before any byte" from "EOF
/// partway through" — `Read::read_exact` collapses both into `UnexpectedEof`,
/// but the native-messaging loop needs to tell a clean inter-frame close
/// (`Eof`) from a truncated frame (`Short`). Retries on `Interrupted`.
fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> ReadExact {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => {
                return if filled == 0 {
                    ReadExact::Eof
                } else {
                    ReadExact::Short
                };
            }
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return ReadExact::Err,
        }
    }
    ReadExact::Ok
}

/// Parse a frame payload into a [`tirith_core::clipboard::ClipboardSourceRecord`].
/// Returns `None` (caller acks false, writes nothing) on any deserialize error,
/// so malformed input never reaches the file the engine trusts.
pub fn parse_record(payload: &[u8]) -> Option<tirith_core::clipboard::ClipboardSourceRecord> {
    serde_json::from_slice(payload).ok()
}

/// Write a native-messaging ack frame (`{"ok":<ok>}`) — length prefix + JSON
/// body. The `Result` is observed by [`run`]: an `Err` means the peer closed our
/// stdout's read end, so the channel is one-way and `run` stops serving. (A
/// failed PERSIST is separate and non-fatal — there the caller acks false.)
fn write_ack<W: Write>(writer: &mut W, ok: bool) -> std::io::Result<()> {
    let body = if ok {
        b"{\"ok\":true}".to_vec()
    } else {
        b"{\"ok\":false}".to_vec()
    };
    // Tiny fixed body; the cast cannot overflow u32.
    let len = body.len() as u32;
    writer.write_all(&len.to_ne_bytes())?;
    writer.write_all(&body)?;
    writer.flush()
}

/// `tirith browser host` entry point. Reads native-messaging frames from stdin
/// until EOF, persisting + acking each valid frame. Exit `0` on clean EOF (how
/// Chrome ends the host); `1` on a fatal framing error or an unresolvable state
/// directory.
pub fn run() -> i32 {
    let Some(out_path) = tirith_core::clipboard::source_file_path() else {
        eprintln!("tirith browser host: cannot resolve the tirith state directory");
        return 1;
    };

    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();

    // Each iteration computes the ack value (or returns early on a fatal frame),
    // then writes the ack ONCE at the bottom; a failed ack-write means Chrome's
    // stdout read end is gone, so the channel is one-way and we stop serving.
    loop {
        // `false` = ack {"ok":false} (record dropped, keep serving); `true` = ok.
        let ack_ok: bool = match read_frame(&mut stdin) {
            FrameRead::Eof => {
                // Normal shutdown: Chrome closed the pipe.
                return 0;
            }
            FrameRead::TooLarge(len) => {
                eprintln!(
                    "tirith browser host: frame length {len} exceeds the {MAX_FRAME_BYTES}-byte cap; aborting (possible hostile or desynced peer)"
                );
                return 1;
            }
            FrameRead::Truncated => {
                eprintln!("tirith browser host: truncated frame on stdin; aborting");
                return 1;
            }
            FrameRead::Frame(payload) => {
                match parse_record(&payload) {
                    Some(record) => {
                        // Re-serialize the VALIDATED record (pretty, M12 ch1 form)
                        // so only schema-clean JSON reaches the file.
                        match serde_json::to_vec_pretty(&record) {
                            Ok(bytes) if !serialized_fits_read_cap(&bytes) => {
                                // A 64–256 KiB record frames fine but would be
                                // UNREADABLE by the paste-provenance path — reject
                                // it here. Ack false; nothing touches disk.
                                eprintln!(
                                    "tirith browser host: dropped a record whose serialized form ({} bytes) exceeds the {SOURCE_READ_CAP}-byte read cap",
                                    bytes.len()
                                );
                                false
                            }
                            Ok(bytes) => {
                                if let Err(e) = persist(&out_path, &bytes) {
                                    eprintln!(
                                        "tirith browser host: failed to write {}: {e}",
                                        out_path.display()
                                    );
                                    // Persist failure: ack false, keep serving —
                                    // a transient disk error shouldn't kill the host.
                                    false
                                } else {
                                    true
                                }
                            }
                            Err(_) => false,
                        }
                    }
                    None => {
                        // Schema-invalid frame: never written. Ack false so the
                        // extension knows the record was rejected.
                        eprintln!(
                            "tirith browser host: dropped a frame that did not match the clipboard-source schema"
                        );
                        false
                    }
                }
            }
        };

        // A failed ack-write (unlike a transient persist failure) means the peer
        // closed our stdout's read end — the channel is one-way, so stop serving
        // rather than persist records the peer can never confirm.
        if let Err(e) = write_ack(&mut stdout, ack_ok) {
            eprintln!(
                "tirith browser host: failed to write ack frame ({e}); the peer's read end is gone, stopping"
            );
            break;
        }
    }

    // Reached only via the `break` above (broken ack channel) — treat the
    // peer-initiated close as a normal shutdown.
    0
}

/// Persist `bytes` to `path` atomically (overwrite), creating the parent dir
/// first (`write_file_atomic` does not `mkdir -p`). Thin wrapper over the shared
/// `write_file_atomic`.
fn persist(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        // fsync the parent only when newly created, so a crash after the ack
        // can't lose the directory entry (CodeRabbit; `commands init` pattern).
        let parent_existed = parent.exists();
        std::fs::create_dir_all(parent)?;
        if !parent_existed {
            tirith_core::util::fsync_parent_dir_logged(parent, "browser host state directory");
        }
    }
    super::write_file_atomic(path, bytes, /*overwrite=*/ true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frame a JSON body the way Chrome does: native-order u32 length prefix +
    /// the bytes. Test helper.
    fn frame(body: &[u8]) -> Vec<u8> {
        let mut v = (body.len() as u32).to_ne_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    const VALID_JSON: &str = r#"{"updated_at":"2026-05-30T00:00:00Z","content_sha256":"abc123","source_url":"https://docs.example.com/install","source_title":"Install","hidden_text_detected":false}"#;

    /// A well-formed frame parses into a `ClipboardSourceRecord` with the right
    /// fields.
    #[test]
    fn well_formed_frame_parses_to_record() {
        let bytes = frame(VALID_JSON.as_bytes());
        let mut cursor = std::io::Cursor::new(bytes);
        let FrameRead::Frame(payload) = read_frame(&mut cursor) else {
            panic!("expected a complete frame");
        };
        let rec = parse_record(&payload).expect("payload parses as record");
        assert_eq!(rec.content_sha256, "abc123");
        assert_eq!(rec.source_url, "https://docs.example.com/install");
        assert_eq!(rec.source_title, "Install");
        assert!(!rec.hidden_text_detected);
        // The stream is now at EOF (clean inter-frame close).
        assert!(matches!(read_frame(&mut cursor), FrameRead::Eof));
    }

    /// An oversized length prefix is rejected as `TooLarge` without reading the
    /// body — proven by a reader that yields only the prefix, then panics.
    #[test]
    fn oversized_prefix_rejected_without_allocating() {
        struct PrefixOnlyThenPanic {
            prefix: [u8; 4],
            pos: usize,
        }
        impl std::io::Read for PrefixOnlyThenPanic {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.pos >= self.prefix.len() {
                    panic!("read_frame must NOT read the body of an oversized frame");
                }
                let n = std::cmp::min(buf.len(), self.prefix.len() - self.pos);
                buf[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
                self.pos += n;
                Ok(n)
            }
        }

        // Declare a frame far larger than the cap (cap + 1).
        let huge = MAX_FRAME_BYTES + 1;
        let mut reader = PrefixOnlyThenPanic {
            prefix: huge.to_ne_bytes(),
            pos: 0,
        };
        match read_frame(&mut reader) {
            FrameRead::TooLarge(len) => assert_eq!(len, huge),
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    /// A length prefix exactly at the cap is allowed (boundary), and a prefix at
    /// cap+1 is rejected. Uses tiny actual bodies so we don't allocate 256 KiB
    /// in the test for the boundary case — instead we check the decision via a
    /// short body whose declared length we vary.
    #[test]
    fn cap_boundary_is_inclusive() {
        // Exactly MAX is permitted as a length — we don't supply the full body,
        // so it then reports Truncated (not TooLarge), proving the cap check
        // passed at the boundary.
        let mut at_cap = MAX_FRAME_BYTES.to_ne_bytes().to_vec();
        at_cap.extend_from_slice(b"short"); // far fewer than MAX bytes
        let mut cursor = std::io::Cursor::new(at_cap);
        assert!(
            matches!(read_frame(&mut cursor), FrameRead::Truncated),
            "a length == cap must pass the cap check (then truncate on the short body)"
        );

        // cap + 1 is rejected as TooLarge.
        let over = (MAX_FRAME_BYTES + 1).to_ne_bytes().to_vec();
        let mut cursor = std::io::Cursor::new(over);
        assert!(matches!(read_frame(&mut cursor), FrameRead::TooLarge(_)));
    }

    /// A truncated frame (prefix promises more than the body delivers) yields a
    /// clean `Truncated` — never a panic, never a partial parse.
    #[test]
    fn truncated_frame_is_clean_error() {
        // Prefix says 100 bytes; body is 3.
        let mut bytes = 100u32.to_ne_bytes().to_vec();
        bytes.extend_from_slice(b"abc");
        let mut cursor = std::io::Cursor::new(bytes);
        assert!(matches!(read_frame(&mut cursor), FrameRead::Truncated));
    }

    /// A garbage payload of valid length is a complete frame but fails schema
    /// validation → `parse_record` returns None (so the host writes nothing).
    #[test]
    fn garbage_payload_fails_schema_validation() {
        let bytes = frame(b"this is not json at all");
        let mut cursor = std::io::Cursor::new(bytes);
        let FrameRead::Frame(payload) = read_frame(&mut cursor) else {
            panic!("expected a complete frame for valid-length garbage");
        };
        assert!(
            parse_record(&payload).is_none(),
            "non-JSON payload must not parse into a record"
        );
    }

    /// JSON that is well-formed but missing a REQUIRED field (`source_url`)
    /// fails validation — defends the engine's file against partial records.
    #[test]
    fn json_missing_required_field_fails_validation() {
        let partial = br#"{"updated_at":"t","content_sha256":"deadbeef"}"#;
        assert!(
            parse_record(partial).is_none(),
            "a record missing source_url must be rejected"
        );
    }

    /// An empty stream (zero bytes) is a clean EOF, not an error.
    #[test]
    fn empty_stream_is_eof() {
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        assert!(matches!(read_frame(&mut cursor), FrameRead::Eof));
    }

    /// A partial length prefix (1–3 bytes then EOF) is `Truncated`, not `Eof` —
    /// a frame boundary is exactly 0 or a full 4-byte prefix.
    #[test]
    fn partial_prefix_is_truncated() {
        let mut cursor = std::io::Cursor::new(vec![0x01, 0x02]); // 2 of 4 prefix bytes
        assert!(matches!(read_frame(&mut cursor), FrameRead::Truncated));
    }

    /// Two valid frames back-to-back both read cleanly, then EOF — the loop can
    /// process a stream of records.
    #[test]
    fn two_frames_then_eof() {
        let mut stream = frame(VALID_JSON.as_bytes());
        stream.extend_from_slice(&frame(VALID_JSON.as_bytes()));
        let mut cursor = std::io::Cursor::new(stream);
        assert!(matches!(read_frame(&mut cursor), FrameRead::Frame(_)));
        assert!(matches!(read_frame(&mut cursor), FrameRead::Frame(_)));
        assert!(matches!(read_frame(&mut cursor), FrameRead::Eof));
    }

    /// The validated record re-serializes and round-trips back through
    /// `parse_record` — the exact transform the host applies before writing.
    #[test]
    fn validated_record_reserializes_and_roundtrips() {
        let bytes = frame(VALID_JSON.as_bytes());
        let mut cursor = std::io::Cursor::new(bytes);
        let FrameRead::Frame(payload) = read_frame(&mut cursor) else {
            panic!("frame");
        };
        let rec = parse_record(&payload).unwrap();
        let reserialized = serde_json::to_vec_pretty(&rec).unwrap();
        let back = parse_record(&reserialized).expect("reserialized record parses");
        assert_eq!(back, rec);
    }

    /// A schema-VALID record whose serialized form exceeds the file-side read
    /// cap is rejected by `serialized_fits_read_cap` (rejection is about SIZE,
    /// not schema — it still parses). A normal record fits.
    #[test]
    fn oversized_serialized_record_is_rejected_before_persist() {
        // A `source_title` large enough that serialization clears the read cap.
        let big_title = "A".repeat(SOURCE_READ_CAP as usize + 1);
        let record = tirith_core::clipboard::ClipboardSourceRecord {
            updated_at: "2026-05-30T00:00:00Z".to_string(),
            content_sha256: "abc123".to_string(),
            source_url: "https://docs.example.com/install".to_string(),
            source_title: big_title,
            hidden_text_detected: false,
        };
        let wire = frame(serde_json::to_vec(&record).unwrap().as_slice());
        let mut cursor = std::io::Cursor::new(wire.clone());
        let FrameRead::Frame(payload) = read_frame(&mut cursor) else {
            panic!("oversized-but-valid record must still frame");
        };
        let parsed = parse_record(&payload).expect("the record is schema-valid");

        // The pretty form the host would write exceeds the read cap.
        let serialized = serde_json::to_vec_pretty(&parsed).unwrap();
        assert!(
            serialized.len() as u64 > SOURCE_READ_CAP,
            "test setup: serialized form must exceed the read cap"
        );
        assert!(
            !serialized_fits_read_cap(&serialized),
            "an oversized serialized record must be rejected before persist"
        );

        // A normal record fits and would be persisted.
        let small = serde_json::to_vec_pretty(
            &parse_record(VALID_JSON.as_bytes()).expect("VALID_JSON parses"),
        )
        .unwrap();
        assert!(
            serialized_fits_read_cap(&small),
            "a genuine small record must pass the read-cap check"
        );
    }

    /// The ack frame is itself a valid native-messaging frame whose body is the
    /// expected JSON.
    #[test]
    fn ack_frame_is_well_formed() {
        let mut buf: Vec<u8> = Vec::new();
        write_ack(&mut buf, true).unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let FrameRead::Frame(payload) = read_frame(&mut cursor) else {
            panic!("ack must be a complete frame");
        };
        assert_eq!(payload, b"{\"ok\":true}");

        let mut buf: Vec<u8> = Vec::new();
        write_ack(&mut buf, false).unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let FrameRead::Frame(payload) = read_frame(&mut cursor) else {
            panic!("ack must be a complete frame");
        };
        assert_eq!(payload, b"{\"ok\":false}");
    }

    /// `write_ack` surfaces a writer error as `Err` (rather than swallowing it).
    /// This is the signal `run()` now relies on: when the peer's read end of our
    /// stdout is gone, the ack write fails and `run()` stops serving. A writer
    /// that always errors on `write` proves the error reaches the caller.
    #[test]
    fn write_ack_propagates_writer_error() {
        /// A `Write` that fails every `write` with `BrokenPipe` — models Chrome
        /// closing the read end of the host's stdout.
        struct FailingWriter;
        impl std::io::Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "peer closed stdout",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut failing = FailingWriter;
        let err = write_ack(&mut failing, true)
            .expect_err("write_ack must return Err when the underlying writer fails");
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);

        // The `ok=false` path must propagate the error too (both branches write).
        let mut failing = FailingWriter;
        assert!(
            write_ack(&mut failing, false).is_err(),
            "write_ack(false) must also surface a writer error"
        );
    }
}
