//! Utility helpers shared across the core crate.

use std::fs::File;
use std::io::BufRead;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Why [`open_regular_capped`] refused to hand back a usable reader. Each caller
/// maps these onto its own surface (corrupt / unverified / silent-empty).
#[derive(Debug)]
pub enum OpenRegularError {
    /// The path does not exist (`ENOENT`). Callers that treat "absent" specially
    /// (an empty store, no incident flag) branch on this.
    NotFound,
    /// The path was opened, but an `fstat` of the OPEN fd says it is not a
    /// regular file (FIFO / device / socket / directory). Reading it could block
    /// or stream forever, so it is refused.
    NotRegularFile,
    /// A regular file whose `fstat` size exceeds the caller's cap. Refused before
    /// any bytes are read so an oversized file cannot exhaust memory.
    TooLarge,
    /// Any other open / stat / read failure (permission denied, I/O error, a
    /// post-open TOCTOU grow past the cap).
    Io(std::io::Error),
}

/// Open `path` and return its handle ONLY when it is a regular file no larger
/// than `cap` bytes — closing the metadata→open TOCTOU that a plain
/// `metadata(path)` + `open(path)` leaves open (CodeRabbit R11 #1/#2).
///
/// ## Why this is race-free
///
/// The naive guard stats the PATH, then opens the PATH. Between the two an
/// attacker can swap the path to a FIFO/device, so the open/read still blocks on
/// a special file. Here we open FIRST, then `fstat` the OPEN fd (`File::metadata`
/// stats the inode behind the descriptor we hold, not the path) — the inode we
/// check is exactly the inode we will read.
///
/// ## Why opening a FIFO does not block (unix)
///
/// We pass `O_NONBLOCK` via `custom_flags`. `open(2)` on a FIFO opened read-only
/// with `O_NONBLOCK` returns IMMEDIATELY (success, no writer required) instead of
/// blocking until a writer appears; we then `fstat` it, see it is not a regular
/// file, and drop it without ever reading. On a regular file `O_NONBLOCK` is a
/// no-op for reads (regular files are always "ready"), so the subsequent read is
/// unaffected. Symlinks are FOLLOWED (a symlink to a regular file is fine; a
/// symlink to a FIFO/device is rejected by the post-open `fstat`) — matching the
/// pre-existing `metadata`-follows-symlinks behaviour of every read site.
///
/// On non-unix there is no FIFO open-blocking semantics to defend against, so we
/// open plainly and `fstat` the open handle (still race-free: we check the inode
/// we hold, not the path).
pub fn open_regular_capped(path: &Path, cap: u64) -> Result<File, OpenRegularError> {
    let open_result = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            std::fs::OpenOptions::new()
                .read(true)
                // O_NONBLOCK: a FIFO with no writer would otherwise block the
                // open forever. With it, the open returns immediately and the
                // fstat below rejects the FIFO before any read.
                .custom_flags(libc::O_NONBLOCK)
                .open(path)
        }
        #[cfg(not(unix))]
        {
            std::fs::OpenOptions::new().read(true).open(path)
        }
    };
    let file = match open_result {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(OpenRegularError::NotFound)
        }
        Err(e) => return Err(OpenRegularError::Io(e)),
    };
    // fstat the OPEN fd — NOT the path. This is the inode we will read, so a
    // swap after our open cannot substitute a special file.
    let meta = file.metadata().map_err(OpenRegularError::Io)?;
    if !meta.is_file() {
        return Err(OpenRegularError::NotRegularFile);
    }
    if meta.len() > cap {
        return Err(OpenRegularError::TooLarge);
    }
    Ok(file)
}

/// Read at most `cap` bytes from a regular file at `path`, race-free.
///
/// Wraps [`open_regular_capped`] (so FIFOs/devices/oversized files are refused
/// without blocking or unbounded allocation) and then reads through a
/// `take(cap + 1)` so a TOCTOU grow BETWEEN the `fstat` and the read is caught:
/// if the handle delivers more than `cap` bytes the read is rejected as
/// [`OpenRegularError::TooLarge`] rather than buffered. Shared by the
/// command-card read, the incident-flag read, and the baseline-salt read.
pub fn read_regular_capped(path: &Path, cap: u64) -> Result<Vec<u8>, OpenRegularError> {
    use std::io::Read as _;
    let file = open_regular_capped(path, cap)?;
    let mut buf = Vec::new();
    file.take(cap.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(OpenRegularError::Io)?;
    if buf.len() as u64 > cap {
        return Err(OpenRegularError::TooLarge);
    }
    Ok(buf)
}

/// Read a line-oriented store, returning the TRIMMED, non-empty lines.
///
/// Shared by the JSONL stores (baseline / canary / taint). Two failure
/// behaviours are deliberately split so a corrupt file can never (a) silently
/// drop the rest of the file, nor (b) spin forever:
///
/// * A single [`std::io::ErrorKind::InvalidData`] line (the recoverable
///   invalid-UTF-8 case — `BufRead::lines()` decodes each line as UTF-8 and
///   yields `InvalidData` on a bad byte) is SKIPPED, so one corrupt byte does
///   not hide every later entry. A previous `map_while(Result::ok)` stopped at
///   the first such line, dropping the remainder of the store.
/// * Any OTHER error kind BREAKS the loop. A persistent I/O fault keeps
///   yielding the SAME `Err` from every `next()`, so an unconditional `continue`
///   would be an unbounded spin — we stop reading instead and return what we
///   have so far (fail-open, consistent with the corrupt-line-skip contract).
///
/// ## Absent vs unreadable (CodeRabbit R9 #G)
///
/// An ABSENT store (`ENOENT`) is legitimately empty and yields an empty vec
/// SILENTLY — first use, before anything was ever written. A store that is
/// PRESENT but cannot be opened/stat'd (permissions, I/O fault) is a different
/// situation for a SECURITY store: returning empty silently is a fail-open miss
/// (a canary/taint that should fire reads as "no entries"). We still return the
/// lines we can (callers degrade gracefully), but emit a ONE-LINE stderr
/// diagnostic so the operator is warned rather than the failure being silent.
///
/// ## Special files (CodeRabbit R9 #C, hardened R11 #1)
///
/// The canary/taint stores are read on the hot path; a store path an attacker
/// could point at a FIFO/device would BLOCK `BufRead::lines()` forever. We go
/// through the shared, race-free [`open_regular_capped`] helper — it opens with
/// `O_NONBLOCK` and `fstat`s the OPEN fd, so a FIFO/device is refused (a
/// diagnostic + empty) WITHOUT the metadata→open TOCTOU a separate `stat`+`open`
/// leaves. `metadata`/`fstat` follow symlinks, so a symlink to a FIFO/device is
/// correctly rejected too. No byte cap is applied (`u64::MAX`): the stores are
/// legitimately multi-MiB (baseline holds up to `MAX_ENTRIES`) and are bounded by
/// compaction, so capping would silently drop live entries.
pub fn read_store_lines(path: &Path) -> Vec<String> {
    // `open_regular_capped` opens-then-fstats (race-free) and distinguishes:
    //   NotFound       → truly absent: empty, no diagnostic (common first use).
    //   NotRegularFile → FIFO/device/socket/dir: warn + empty (never block).
    //   Io             → present-but-unreadable (permissions, etc.): warn + empty.
    // `cap == u64::MAX` so the size gate never trips for a legitimately large
    // store; `TooLarge` is therefore unreachable here but handled for totality.
    read_store_lines_complete(path).0
}

/// Like [`read_store_lines`] but also reports whether the store was read to
/// completion. Returns `(lines, complete)`.
///
/// `complete == false` means the lines are NOT a faithful image of the whole
/// store and MUST NOT be used to rewrite it (CodeRabbit R13 #1). Two cases set
/// it false:
///
/// * The line loop BROKE on a real mid-file I/O fault (the tail is unread) — see
///   [`collect_store_lines_complete`].
/// * The store is PRESENT but could not be opened/stat'd as a readable regular
///   file (FIFO/device/oversized/permission/I/O). Those already yield an empty
///   vec + a diagnostic for the fail-open reader; for a rewrite path, an empty
///   "image" here is NOT proof the store is empty, so `complete` is false to
///   forbid a truncating rewrite.
///
/// An ABSENT store (`NotFound`) is genuinely empty and returns `(vec![], true)`:
/// a rewrite from "no lines" is correct (the store does not exist yet).
pub fn read_store_lines_complete(path: &Path) -> (Vec<String>, bool) {
    read_store_lines_complete_inner(path, true)
}

/// Like [`read_store_lines_complete`] but yields each non-blank line RAW
/// (UNTRIMMED) for the REWRITE/preserve path (CodeRabbit R15 #3). The
/// open/stat/`complete` semantics are identical to [`read_store_lines_complete`];
/// only the per-line trimming differs (see [`collect_store_lines_raw_complete`]).
/// Rewrite callers (taint clear, canary prune/rotate, baseline compaction) use
/// THIS so an unparseable line survives byte-for-byte through the rewrite.
pub fn read_store_lines_raw_complete(path: &Path) -> (Vec<String>, bool) {
    read_store_lines_complete_inner(path, false)
}

/// Shared open/stat core of the trimmed / raw store readers. `trim` selects the
/// per-line policy ([`collect_store_lines_complete`] vs
/// [`collect_store_lines_raw_complete`]); the unreadable/absent classification
/// and `complete` flag are identical in both.
fn read_store_lines_complete_inner(path: &Path, trim: bool) -> (Vec<String>, bool) {
    let file = match open_regular_capped(path, u64::MAX) {
        Ok(f) => f,
        // Truly absent: an empty, COMPLETE image — rewriting from it is correct.
        Err(OpenRegularError::NotFound) => return (Vec::new(), true),
        // Present-but-unreadable: empty image is NOT a proven-empty store, so
        // mark it incomplete to forbid a truncating rewrite.
        Err(OpenRegularError::NotRegularFile) => {
            warn_store_unreadable(path, "not a regular file");
            return (Vec::new(), false);
        }
        Err(OpenRegularError::TooLarge) => {
            warn_store_unreadable(path, "exceeds read cap");
            return (Vec::new(), false);
        }
        Err(OpenRegularError::Io(e)) => {
            warn_store_unreadable(path, &e.to_string());
            return (Vec::new(), false);
        }
    };
    let reader = std::io::BufReader::new(file);
    if trim {
        collect_store_lines_complete(reader)
    } else {
        collect_store_lines_raw_complete(reader)
    }
}

/// One-line stderr diagnostic when a PRESENT security store cannot be read (vs a
/// legitimately-absent one, which is silent). Kept deliberately simple per
/// CodeRabbit R9 #G — a warning so the unreadable case is not silent; callers
/// still degrade gracefully on the empty result.
fn warn_store_unreadable(path: &Path, reason: &str) {
    eprintln!(
        "tirith: warning: security store {} is present but unreadable ({reason}); \
         treating as empty",
        path.display()
    );
}

/// Reader-generic core of [`read_store_lines`]. Split out so the
/// skip-`InvalidData` / break-on-other-error termination contract is unit-
/// testable against a custom `BufRead` (a real `File` cannot be made to yield a
/// deterministic non-`InvalidData` error across platforms).
pub fn collect_store_lines<R: BufRead>(reader: R) -> Vec<String> {
    collect_store_lines_complete(reader).0
}

/// Like [`collect_store_lines`] but also reports whether the read reached EOF
/// CLEANLY. Returns `(lines, complete)` where `complete == false` means the loop
/// BROKE early on a non-`InvalidData` I/O fault — so `lines` is a PARTIAL prefix
/// of the file, missing its unread tail.
///
/// ## Why a REWRITE path must check this (CodeRabbit R13 #1 — data loss)
///
/// A skipped [`std::io::ErrorKind::InvalidData`] line (one bad byte) is fully
/// recoverable: the file is read to completion, just minus that one line, and
/// `complete` stays `true`. But a REAL mid-file I/O fault (a `break`) leaves the
/// tail UNREAD. The fail-open hot-path reader ([`read_store_lines`]) is fine with
/// that — it returns what it has and the worst case is one missed lookup. A
/// COMPACTION/CLEAR rewrite is NOT: rewriting the store from a truncated prefix
/// would PERMANENTLY DROP every unread tail entry (data loss). Such callers use
/// [`read_store_lines_complete`] and ABORT the rewrite when `complete == false`,
/// leaving the store intact for a future attempt.
///
/// This is the TRIMMED variant: each retained line is whitespace-trimmed. Use it
/// for the JSON-parse READ path (`serde_json` ignores surrounding whitespace, so
/// trimming is harmless and the output is tidy). REWRITE paths that preserve an
/// unparseable line verbatim must instead use [`collect_store_lines_raw_complete`]
/// — trimming would corrupt a `  {unknown}  ` line's whitespace on write-back
/// (CodeRabbit R15 #3).
pub fn collect_store_lines_complete<R: BufRead>(reader: R) -> (Vec<String>, bool) {
    collect_lines_inner(reader, true)
}

/// Like [`collect_store_lines_complete`] but yields each non-blank line RAW
/// (UNTRIMMED). The REWRITE/preserve path (taint clear, canary prune/rotate,
/// baseline compaction) keeps unparseable lines verbatim, so it must read them
/// byte-for-byte: a leading/trailing-whitespace `  {"unknown":1}  ` line would
/// otherwise be silently re-written without its surrounding whitespace
/// (CodeRabbit R15 #3). Parseable lines are unaffected — `serde_json` tolerates
/// the surrounding whitespace, so they still deserialize identically.
///
/// Genuinely blank (whitespace-only) lines are STILL dropped: they carry no
/// data, are inert to every reader, and preserving them would let the store
/// accumulate blank noise across rewrites. "Verbatim" therefore means
/// "byte-for-byte for any line with content", not "re-emit empty lines".
/// `complete` has the identical meaning as the trimmed variant.
pub fn collect_store_lines_raw_complete<R: BufRead>(reader: R) -> (Vec<String>, bool) {
    collect_lines_inner(reader, false)
}

/// Shared core of the trimmed / raw line collectors. `trim == true` pushes the
/// whitespace-trimmed line (read path); `trim == false` pushes the line verbatim
/// (rewrite/preserve path). Either way a line that is blank AFTER trimming is
/// skipped, and the `complete` flag follows the same skip-`InvalidData` /
/// break-on-other-fault contract documented on [`collect_store_lines_complete`].
fn collect_lines_inner<R: BufRead>(reader: R, trim: bool) -> (Vec<String>, bool) {
    let mut out = Vec::new();
    // Optimistically complete; flipped to false only if we BREAK on a real fault.
    // A clean EOF or a sequence of skipped InvalidData lines both leave this true.
    let mut complete = true;
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => continue,
            Err(_) => {
                // Real I/O fault: the tail is unread. Stop (a persistent fault
                // would otherwise spin) and signal the partial read.
                complete = false;
                break;
            }
        };
        // Skip blank/whitespace-only lines in BOTH modes — they hold no data.
        if line.trim().is_empty() {
            continue;
        }
        if trim {
            out.push(line.trim().to_string());
        } else {
            out.push(line);
        }
    }
    (out, complete)
}

/// Outcome of [`run_shell_with_timeout`]. Callers map this onto their own
/// error type (e.g. `ContextDetectFailure`, plain `String`).
#[derive(Debug)]
pub enum ShellTimeoutOutcome {
    /// Child ran to completion within the deadline. `stdout` is the
    /// captured bytes; `status` is the exit status (callers decide how to
    /// treat non-zero exits).
    Completed { status: ExitStatus, stdout: Vec<u8> },
    /// `spawn()` failed with `ErrorKind::NotFound` — the binary isn't on
    /// PATH. Callers typically translate this to "not configured".
    NotFound,
    /// `spawn()` failed for some other reason. The string carries a short
    /// formatted reason for audit/log surfaces.
    SpawnError(String),
    /// `try_wait()` returned an error after spawn succeeded.
    WaitError(String),
    /// Deadline elapsed; the child was sent `kill()` and reaped.
    Timeout,
}

/// Spawn a child process with stdout piped, drain stdout on a helper
/// thread (so the pipe buffer never blocks the child), and poll
/// `try_wait()` against a deadline. On timeout the child is killed and
/// reaped before returning.
///
/// Stderr behaviour is delegated to the caller via `stderr_stdio` —
/// passing `Stdio::null()` discards it cheaply, passing `Stdio::piped()`
/// requires the caller to drain stderr themselves (or accept the
/// pipe-fill deadlock risk). Most callers should pass `Stdio::null()`.
///
/// This consolidates two near-identical 70-line copies (PR-127 review #8)
/// in `context_detect.rs::run_with_timeout` and
/// `iac_plan.rs::run_terraform_show_json`.
pub fn run_shell_with_timeout(
    program: &str,
    args: &[&str],
    timeout: Duration,
    poll_interval: Duration,
    stderr_stdio: Stdio,
) -> ShellTimeoutOutcome {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(stderr_stdio)
        .stdin(Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return ShellTimeoutOutcome::NotFound;
        }
        Err(e) => {
            return ShellTimeoutOutcome::SpawnError(format!("spawn {program}: {e}"));
        }
    };

    // Stream stdout on a helper thread so the pipe buffer never blocks
    // the child when output exceeds ~64KiB.
    let stdout_handle: Option<JoinHandle<Vec<u8>>> = child.stdout.take().map(|mut s| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            use std::io::Read as _;
            let _ = s.read_to_end(&mut buf);
            buf
        })
    });

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_handle
                    .and_then(|h| h.join().ok())
                    .unwrap_or_default();
                return ShellTimeoutOutcome::Completed { status, stdout };
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    if let Some(h) = stdout_handle {
                        let _ = h.join();
                    }
                    return ShellTimeoutOutcome::Timeout;
                }
                std::thread::sleep(poll_interval);
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                if let Some(h) = stdout_handle {
                    let _ = h.join();
                }
                return ShellTimeoutOutcome::WaitError(format!("try_wait {program}: {e}"));
            }
        }
    }
}

/// fsync the directory that CONTAINS `path`, so a freshly published or removed
/// directory entry (a `rename`/`persist`/`hard_link` claim, or an unlink) is
/// itself crash-durable — not just the file body.
///
/// On Unix, `rename`/`unlink` mutate the parent directory's entries, and that
/// mutation is not guaranteed durable until the directory inode is fsync'd.
/// Without this, a crash/power-loss right after the atomic publish can lose the
/// new name→inode mapping even though the file's DATA was synced — leaving a
/// zero/absent entry where a complete file was just written (or resurrecting a
/// just-removed one). Callers fsync the file body BEFORE the rename; this makes
/// the directory entry durable AFTER it.
///
/// **Unix-only** real work; **no-op `Ok(())` on non-Unix** (directory fsync is
/// not portable — Windows has no directory-fsync). Returns the fsync result
/// (CodeRabbit R13 #5) so a durability-critical caller can LOG or propagate a
/// dir-fsync failure instead of silently dropping it — see
/// [`fsync_parent_dir_logged`] for the common "the body is already durable, so
/// don't fail the publish but don't be silent" wrapper.
///
/// `#[must_use]`: the whole point of returning the error is that it not be
/// dropped on the floor. A caller that genuinely wants best-effort with no log
/// must say so explicitly (`let _ = …`).
///
/// (Consolidates the per-module copies in `incident.rs` / `selfupdate.rs` / the
/// card-sign path; CodeRabbit R9 #B.)
#[cfg(unix)]
#[must_use = "a dir-fsync failure should be logged or propagated, not silently dropped"]
pub fn fsync_parent_dir(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        // A single-component relative destination (e.g. `commands.yaml`) has
        // `Path::parent() == Some("")`: its containing directory IS the current
        // working directory, so fsync `.` rather than skipping — otherwise the
        // required directory fsync is silently dropped (CodeRabbit R19 #2).
        Some(parent) if parent.as_os_str().is_empty() => {
            std::fs::File::open(Path::new("."))?.sync_all()
        }
        Some(parent) => std::fs::File::open(parent)?.sync_all(),
        // No parent (root, e.g. `/`): nothing to fsync — vacuously durable.
        None => Ok(()),
    }
}

/// No-op stand-in on non-Unix (directory fsync is not portable). See the unix
/// form for the durability rationale.
#[cfg(not(unix))]
#[must_use = "a dir-fsync failure should be logged or propagated, not silently dropped"]
pub fn fsync_parent_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// [`fsync_parent_dir`] for the common durability-path shape: the file BODY is
/// already fsync'd and the atomic publish (rename/hard_link) has SUCCEEDED, so a
/// failure of the trailing PARENT-DIR fsync must NOT turn the successful publish
/// into an error — but it should also not be silent (CodeRabbit R13 #5). Logs a
/// one-line stderr diagnostic on failure and returns nothing. No-op success path
/// on non-Unix (the inner call returns `Ok`).
pub fn fsync_parent_dir_logged(path: &Path, context: &str) {
    if let Err(e) = fsync_parent_dir(path) {
        eprintln!(
            "tirith: warning: could not fsync parent directory of {} ({context}): {e}; \
             the write succeeded but its directory entry may not be crash-durable",
            path.display()
        );
    }
}

/// Truncate a string to a maximum number of bytes without breaking UTF-8.
/// Returns the original string if it is already within the limit.
pub fn truncate_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    if max_bytes == 0 {
        return String::new();
    }
    let mut end = max_bytes.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Simple Levenshtein distance for short strings.
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for (i, row) in dp.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, val) in dp[0].iter_mut().enumerate() {
        *val = j;
    }
    for i in 1..=m {
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            dp[i][j] = (dp[i - 1][j] + 1)
                .min(dp[i][j - 1] + 1)
                .min(dp[i - 1][j - 1] + cost);
        }
    }
    dp[m][n]
}

#[cfg(test)]
mod open_regular_tests {
    use super::{open_regular_capped, read_regular_capped, read_store_lines, OpenRegularError};
    use tempfile::tempdir;

    #[test]
    fn regular_file_within_cap_reads() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("ok.bin");
        std::fs::write(&p, b"hello").unwrap();
        let bytes = read_regular_capped(&p, 1024).expect("regular file reads");
        assert_eq!(bytes, b"hello");
        // The handle-returning form opens it too.
        assert!(open_regular_capped(&p, 1024).is_ok());
    }

    #[test]
    fn oversized_regular_file_is_rejected_before_read() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("big.bin");
        // One byte over the cap. The fstat size gate must reject it.
        std::fs::write(&p, vec![b'x'; 1025]).unwrap();
        assert!(matches!(
            read_regular_capped(&p, 1024),
            Err(OpenRegularError::TooLarge)
        ));
        assert!(matches!(
            open_regular_capped(&p, 1024),
            Err(OpenRegularError::TooLarge)
        ));
    }

    #[test]
    fn exactly_cap_bytes_is_accepted() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("exact.bin");
        std::fs::write(&p, vec![b'y'; 1024]).unwrap();
        let bytes = read_regular_capped(&p, 1024).expect("exactly cap is fine");
        assert_eq!(bytes.len(), 1024);
    }

    #[test]
    fn absent_path_is_not_found() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("nope.bin");
        assert!(matches!(
            read_regular_capped(&p, 1024),
            Err(OpenRegularError::NotFound)
        ));
        assert!(matches!(
            open_regular_capped(&p, 1024),
            Err(OpenRegularError::NotFound)
        ));
    }

    #[test]
    fn directory_is_not_regular_file() {
        let dir = tempdir().unwrap();
        // The temp dir itself is a directory — opening it as a "regular file"
        // must be rejected by the fstat (cross-platform: a dir is never a file).
        match open_regular_capped(dir.path(), 1024) {
            Err(OpenRegularError::NotRegularFile) => {}
            // Some platforms refuse to `open` a directory for reading at all,
            // surfacing an Io error instead — also acceptable (still not handed
            // back as a readable regular file, still no block).
            Err(OpenRegularError::Io(_)) => {}
            other => panic!("a directory must not open as a regular file, got {other:?}"),
        }
    }

    /// R11 #1: a FIFO at a store path must NOT hang `read_store_lines`. The
    /// shared helper opens with O_NONBLOCK and rejects the FIFO via the post-open
    /// fstat, so the store reads as EMPTY and returns promptly. A regression to a
    /// blocking read would HANG here (caught by the suite timeout). Unix-only.
    #[cfg(unix)]
    #[test]
    fn fifo_store_does_not_hang_and_reads_empty() {
        use std::ffi::CString;
        let dir = tempdir().unwrap();
        let fifo = dir.path().join("store.fifo");
        let c_path = CString::new(fifo.as_os_str().to_str().unwrap()).unwrap();
        if unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) } != 0 {
            eprintln!("skipping: mkfifo unsupported here");
            return;
        }
        // Must complete promptly; a blocking read on the FIFO would hang.
        assert!(
            read_store_lines(&fifo).is_empty(),
            "a FIFO store must read as empty, not block"
        );
        // And the helper itself rejects it as non-regular (no block).
        assert!(matches!(
            open_regular_capped(&fifo, u64::MAX),
            Err(OpenRegularError::NotRegularFile)
        ));
    }

    /// R11 #1: a symlink pointing at a FIFO must also be rejected — `fstat` on the
    /// open fd follows the symlink to the FIFO inode and refuses it — without
    /// blocking. Unix-only.
    #[cfg(unix)]
    #[test]
    fn symlink_to_fifo_does_not_hang() {
        use std::ffi::CString;
        let dir = tempdir().unwrap();
        let real_fifo = dir.path().join("real.fifo");
        let c_path = CString::new(real_fifo.as_os_str().to_str().unwrap()).unwrap();
        if unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) } != 0 {
            eprintln!("skipping: mkfifo unsupported here");
            return;
        }
        let link = dir.path().join("link.fifo");
        std::os::unix::fs::symlink(&real_fifo, &link).unwrap();
        assert!(
            read_store_lines(&link).is_empty(),
            "a symlink-to-FIFO store must read as empty, not block"
        );
        assert!(matches!(
            read_regular_capped(&link, 4096),
            Err(OpenRegularError::NotRegularFile)
        ));
    }
}

#[cfg(test)]
mod store_line_tests {
    use super::{collect_store_lines, collect_store_lines_complete};
    use std::io::{self, BufRead, Read};

    /// A `BufRead` whose `read_line` first yields some good lines, then returns
    /// a PERSISTENT non-`InvalidData` error on every subsequent call — modelling
    /// a hard I/O fault. If the loop `continue`d on this it would spin forever;
    /// the contract is to BREAK, so the call must return promptly with only the
    /// lines read before the fault.
    struct PersistentErrorReader {
        good: Vec<String>,
        idx: usize,
    }

    impl Read for PersistentErrorReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            // `lines()` uses `read_line`, not `read`; this is only here to
            // satisfy the `Read` supertrait bound on `BufRead`.
            Err(io::Error::other("unused"))
        }
    }

    impl BufRead for PersistentErrorReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Ok(&[])
        }
        fn consume(&mut self, _amt: usize) {}
        // `lines()` calls `read_line` under the hood; override it directly so we
        // control exactly what each iteration yields.
        fn read_line(&mut self, buf: &mut String) -> io::Result<usize> {
            if self.idx < self.good.len() {
                buf.push_str(&self.good[self.idx]);
                buf.push('\n');
                self.idx += 1;
                Ok(self.good[self.idx - 1].len() + 1)
            } else {
                // Persistent fault: returns the SAME error every call. A
                // `continue`-on-all-errors loop would never terminate.
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "persistent fault",
                ))
            }
        }
    }

    #[test]
    fn persistent_non_invaliddata_error_breaks_does_not_spin() {
        // CodeRabbit R6 #7: an unbounded `continue` on every read error spins
        // forever on a persistent fault. `collect_store_lines` must BREAK on a
        // non-`InvalidData` error and return the lines gathered so far. This
        // test would hang (not fail) on a regression — it is deliberately
        // cheap so the suite still time-boxes.
        let reader = PersistentErrorReader {
            good: vec!["one".to_string(), "two".to_string()],
            idx: 0,
        };
        let lines = collect_store_lines(reader);
        assert_eq!(lines, vec!["one".to_string(), "two".to_string()]);
    }

    #[test]
    fn invalid_utf8_line_is_skipped_not_fatal() {
        // The recoverable case: a single invalid-UTF-8 line is skipped and the
        // reader keeps going. A real `BufReader` over bytes yields `InvalidData`
        // for the bad line, then continues.
        let bytes: Vec<u8> = [b"good1\n".as_ref(), &[0xff, 0xfe, b'\n'], b"good2\n"].concat();
        let lines = collect_store_lines(std::io::BufReader::new(&bytes[..]));
        assert_eq!(lines, vec!["good1".to_string(), "good2".to_string()]);
    }

    #[test]
    fn complete_flag_false_on_mid_file_io_fault() {
        // CodeRabbit R13 #1: a REAL mid-file I/O fault leaves the tail unread, so
        // the lines are a PARTIAL prefix. `collect_store_lines_complete` must
        // report `complete == false` so a rewrite path knows NOT to truncate the
        // store from this partial image. The lines read before the fault are still
        // returned (for the fail-open reader), but the flag forbids a rewrite.
        let reader = PersistentErrorReader {
            good: vec!["one".to_string(), "two".to_string()],
            idx: 0,
        };
        let (lines, complete) = collect_store_lines_complete(reader);
        assert_eq!(lines, vec!["one".to_string(), "two".to_string()]);
        assert!(!complete, "a broken mid-file read must report incomplete");
    }

    #[test]
    fn complete_flag_true_on_clean_eof_and_skipped_invalid_utf8() {
        // A clean read — including one where a single invalid-UTF-8 line is
        // skipped — reaches EOF, so the image is COMPLETE and a rewrite from it is
        // safe (the skipped line is genuinely undecodable, not an unread tail).
        let bytes: Vec<u8> = [b"good1\n".as_ref(), &[0xff, 0xfe, b'\n'], b"good2\n"].concat();
        let (lines, complete) = collect_store_lines_complete(std::io::BufReader::new(&bytes[..]));
        assert_eq!(lines, vec!["good1".to_string(), "good2".to_string()]);
        assert!(
            complete,
            "a clean EOF (even skipping bad UTF-8) is complete"
        );
    }

    #[test]
    fn raw_variant_preserves_surrounding_whitespace_but_drops_blank_lines() {
        use super::collect_store_lines_raw_complete;
        // CodeRabbit R15 #3 — regression pinning BOTH properties of the raw
        // collector used by the REWRITE/preserve path.
        //
        // A store with an unknown line that carries surrounding whitespace must
        // come back EXACTLY (whitespace included) so a verbatim rewrite writes it
        // byte-for-byte; a blank/whitespace-only line carries no data and is still
        // dropped (so rewrites don't accumulate blank noise).
        let input = "  {\"unknown\":\"x\"}  \n\t{\"a\":1}\n   \n\n\tplain content\t\n";
        let (raw, complete) =
            collect_store_lines_raw_complete(std::io::BufReader::new(input.as_bytes()));
        assert!(complete, "a clean read is complete");
        assert_eq!(
            raw,
            vec![
                "  {\"unknown\":\"x\"}  ".to_string(), // (1) verbatim: surrounding spaces kept
                "\t{\"a\":1}".to_string(),             // verbatim: leading tab kept
                "\tplain content\t".to_string(),       // verbatim: leading + trailing tab kept
            ],
            "raw variant must keep each non-blank line byte-for-byte and drop blank lines"
        );

        // CONTRAST: the TRIMMED variant (read path) strips that same whitespace.
        // Proves the two variants differ exactly on the preserve property — and
        // that the prior trimmed behavior the read path relies on is unchanged.
        let (trimmed, _) = collect_store_lines_complete(std::io::BufReader::new(input.as_bytes()));
        assert_eq!(
            trimmed,
            vec![
                "{\"unknown\":\"x\"}".to_string(),
                "{\"a\":1}".to_string(),
                "plain content".to_string(),
            ],
            "trimmed variant must still strip whitespace for the parse path"
        );
    }
}

#[cfg(all(test, unix))]
mod fsync_parent_dir_tests {
    use super::fsync_parent_dir;
    use std::path::Path;

    #[test]
    fn single_component_relative_path_fsyncs_cwd() {
        // CodeRabbit R19 #2: a single-component relative destination (e.g.
        // `commands.yaml`) has `Path::parent() == Some("")`. The old
        // `.filter(|p| !p.as_os_str().is_empty())` DROPPED that and returned
        // `Ok(())`, SKIPPING the required directory fsync. The fix treats an
        // empty parent as the current directory (`.`) and fsyncs it, so a
        // relative single-component publish is still made durable. The test
        // process always has an openable cwd, so this must SUCCEED (and never
        // panic) — proving we now fsync `.` rather than skipping.
        fsync_parent_dir(Path::new("commands.yaml"))
            .expect("single-component relative path must fsync the cwd, not skip");
    }

    #[test]
    fn root_path_with_no_parent_is_noop_ok() {
        // The genuine no-parent case (`/` has `parent() == None`) stays a
        // vacuous `Ok(())` no-op — there is no containing directory to fsync.
        fsync_parent_dir(Path::new("/")).expect("a path with no parent is a vacuous Ok no-op");
    }
}
