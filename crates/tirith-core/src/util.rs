//! Utility helpers shared across the core crate.

use std::fs::File;
use std::io::BufRead;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Why [`open_regular_capped`] refused to hand back a usable reader.
#[derive(Debug)]
pub enum OpenRegularError {
    /// The path does not exist (`ENOENT`); callers treat "absent" specially.
    NotFound,
    /// An `fstat` of the OPEN fd says it is not a regular file (FIFO / device /
    /// socket / directory) — refused since reading could block or stream forever.
    NotRegularFile,
    /// A regular file whose `fstat` size exceeds the cap; refused before any read.
    TooLarge,
    /// Any other open / stat / read failure (permission, I/O, post-open grow).
    Io(std::io::Error),
}

/// Open `path` and return its handle ONLY when it is a regular file no larger
/// than `cap` bytes — closing the metadata→open TOCTOU a plain `metadata` +
/// `open` leaves (CodeRabbit R11 #1/#2).
///
/// Race-free because we open FIRST, then `fstat` the OPEN fd (the inode we check
/// is exactly the one we will read) — a path swap after the open cannot
/// substitute a special file. On unix we pass `O_NONBLOCK` so opening a FIFO
/// returns immediately instead of blocking on a writer; the post-open `fstat`
/// then rejects it. It is a no-op for reads of a regular file. Symlinks are
/// followed; a symlink to a FIFO/device is rejected by the `fstat`.
pub fn open_regular_capped(path: &Path, cap: u64) -> Result<File, OpenRegularError> {
    let open_result = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            std::fs::OpenOptions::new()
                .read(true)
                // O_NONBLOCK so a writer-less FIFO open returns immediately;
                // the fstat below rejects it before any read.
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
    // fstat the OPEN fd, not the path — the inode we will read.
    let meta = file.metadata().map_err(OpenRegularError::Io)?;
    if !meta.is_file() {
        return Err(OpenRegularError::NotRegularFile);
    }
    if meta.len() > cap {
        return Err(OpenRegularError::TooLarge);
    }
    Ok(file)
}

/// Read at most `cap` bytes from a regular file at `path`, race-free. Wraps
/// [`open_regular_capped`] and reads through `take(cap + 1)` so a TOCTOU grow
/// between the `fstat` and the read is caught (rejected as
/// [`OpenRegularError::TooLarge`] rather than buffered).
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

/// Read a line-oriented store (JSONL baseline / canary / taint), returning the
/// TRIMMED, non-empty lines. Two failure behaviours are split so a corrupt file
/// can never silently drop the rest, nor spin forever: a single
/// [`std::io::ErrorKind::InvalidData`] (bad-UTF-8) line is SKIPPED, while any
/// other error kind BREAKS the loop (a persistent fault would otherwise spin).
///
/// Absent vs unreadable (CodeRabbit R9 #G): an absent store yields an empty vec
/// silently; a PRESENT-but-unreadable security store also returns empty but with
/// a one-line stderr diagnostic, so a fail-open miss isn't silent.
///
/// Special files (CodeRabbit R9 #C / R11 #1): goes through the race-free
/// [`open_regular_capped`] so an attacker-planted FIFO/device (or symlink to one)
/// is refused without blocking. No byte cap (`u64::MAX`): stores are legitimately
/// multi-MiB and compaction-bounded, so capping would drop live entries.
pub fn read_store_lines(path: &Path) -> Vec<String> {
    read_store_lines_complete(path).0
}

/// Like [`read_store_lines`] but also reports whether the store was read to
/// completion. `complete == false` means the lines are NOT a faithful image and
/// MUST NOT be used to rewrite the store (CodeRabbit R13 #1) — set when the loop
/// broke on a mid-file I/O fault, or the store is present-but-unreadable (an
/// empty image is not proof of emptiness). An ABSENT store returns
/// `(vec![], true)`: rewriting from "no lines" is correct.
pub fn read_store_lines_complete(path: &Path) -> (Vec<String>, bool) {
    read_store_lines_complete_inner(path, true)
}

/// Like [`read_store_lines_complete`] but yields each non-blank line RAW
/// (untrimmed) for the rewrite/preserve path (CodeRabbit R15 #3), so an
/// unparseable line survives byte-for-byte. Same open/stat/`complete` semantics;
/// only the per-line trimming differs.
pub fn read_store_lines_raw_complete(path: &Path) -> (Vec<String>, bool) {
    read_store_lines_complete_inner(path, false)
}

/// Shared open/stat core of the trimmed / raw store readers. `trim` selects the
/// per-line policy; the absent/unreadable classification and `complete` flag are
/// identical in both.
fn read_store_lines_complete_inner(path: &Path, trim: bool) -> (Vec<String>, bool) {
    let file = match open_regular_capped(path, u64::MAX) {
        Ok(f) => f,
        // Truly absent: an empty, COMPLETE image — rewriting from it is correct.
        Err(OpenRegularError::NotFound) => return (Vec::new(), true),
        // Present-but-unreadable: empty image is NOT proven-empty, so mark
        // incomplete to forbid a truncating rewrite.
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

/// One-line stderr diagnostic when a PRESENT security store cannot be read, so
/// the unreadable case is not silent (CodeRabbit R9 #G).
fn warn_store_unreadable(path: &Path, reason: &str) {
    eprintln!(
        "tirith: warning: security store {} is present but unreadable ({reason}); \
         treating as empty",
        path.display()
    );
}

/// Reader-generic core of [`read_store_lines`]. Split out so the
/// skip-`InvalidData` / break-on-other-error contract is unit-testable against a
/// custom `BufRead`.
pub fn collect_store_lines<R: BufRead>(reader: R) -> Vec<String> {
    collect_store_lines_complete(reader).0
}

/// Like [`collect_store_lines`] but also reports whether the read reached EOF
/// cleanly. `complete == false` means the loop broke on a non-`InvalidData` I/O
/// fault, so `lines` is a partial prefix missing its unread tail.
///
/// A REWRITE path must check this (CodeRabbit R13 #1 — data loss): a skipped bad
/// line is recoverable and keeps `complete == true`, but rewriting from a
/// truncated prefix would permanently drop the unread tail. Such callers abort
/// the rewrite when `complete == false`.
///
/// This is the TRIMMED variant (JSON-parse read path); rewrite paths that
/// preserve an unparseable line verbatim use [`collect_store_lines_raw_complete`]
/// (CodeRabbit R15 #3).
pub fn collect_store_lines_complete<R: BufRead>(reader: R) -> (Vec<String>, bool) {
    collect_lines_inner(reader, true)
}

/// Like [`collect_store_lines_complete`] but yields each non-blank line RAW
/// (untrimmed) for the rewrite/preserve path, so an unparseable line survives
/// byte-for-byte (CodeRabbit R15 #3). Genuinely blank lines are STILL dropped, so
/// "verbatim" means "byte-for-byte for any line with content". `complete` has the
/// identical meaning as the trimmed variant.
pub fn collect_store_lines_raw_complete<R: BufRead>(reader: R) -> (Vec<String>, bool) {
    collect_lines_inner(reader, false)
}

/// Shared core of the trimmed / raw line collectors. `trim == true` pushes the
/// trimmed line (read path); `trim == false` the verbatim line (rewrite path).
/// Either way a blank-after-trimming line is skipped, and `complete` follows the
/// skip-`InvalidData` / break-on-other-fault contract of
/// [`collect_store_lines_complete`].
fn collect_lines_inner<R: BufRead>(reader: R, trim: bool) -> (Vec<String>, bool) {
    let mut out = Vec::new();
    // Optimistically complete; flipped only on a real-fault BREAK.
    let mut complete = true;
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => continue,
            Err(_) => {
                // Real I/O fault: the tail is unread. Stop (a persistent fault
                // would spin) and signal the partial read.
                complete = false;
                break;
            }
        };
        // Skip blank lines in both modes — they hold no data.
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

/// Outcome of [`run_shell_with_timeout`]. Callers map this onto their own error
/// type (e.g. `ContextDetectFailure`).
#[derive(Debug)]
pub enum ShellTimeoutOutcome {
    /// Child completed within the deadline. Callers decide how to treat non-zero.
    Completed { status: ExitStatus, stdout: Vec<u8> },
    /// `spawn()` failed `NotFound` — binary not on PATH (often "not configured").
    NotFound,
    /// `spawn()` failed otherwise; the string is a short reason.
    SpawnError(String),
    /// `try_wait()` errored after spawn succeeded.
    WaitError(String),
    /// Deadline elapsed; the child was killed and reaped.
    Timeout,
}

/// Spawn a child with stdout piped, drain stdout on a helper thread (so the pipe
/// buffer never blocks the child), and poll `try_wait()` against a deadline,
/// killing + reaping on timeout. Stderr is delegated via `stderr_stdio` — most
/// callers pass `Stdio::null()`; `Stdio::piped()` requires the caller to drain it.
/// Consolidates two near-identical copies (PR-127 review #8).
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

    // Drain stdout on a helper thread so the pipe buffer never blocks the child.
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

/// fsync the directory CONTAINING `path` so a freshly published/removed
/// directory entry (rename / unlink) is itself crash-durable, not just the file
/// body. On Unix the name→inode mutation isn't durable until the directory inode
/// is fsync'd; without this a crash right after an atomic publish can lose a
/// just-written entry (or resurrect a removed one). Callers fsync the body BEFORE
/// the rename; this makes the directory entry durable after it.
///
/// Unix-only real work; no-op `Ok(())` on non-Unix (no portable dir-fsync).
/// Returns the result (CodeRabbit R13 #5) and is `#[must_use]` so a dir-fsync
/// failure is logged or propagated, not silently dropped — see
/// [`fsync_parent_dir_logged`]. Consolidates per-module copies (CodeRabbit R9 #B).
#[cfg(unix)]
#[must_use = "a dir-fsync failure should be logged or propagated, not silently dropped"]
pub fn fsync_parent_dir(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        // A single-component relative dest (e.g. `commands.yaml`) has
        // `parent() == Some("")`; fsync `.` rather than skipping it (CodeRabbit
        // R19 #2).
        Some(parent) if parent.as_os_str().is_empty() => {
            std::fs::File::open(Path::new("."))?.sync_all()
        }
        Some(parent) => std::fs::File::open(parent)?.sync_all(),
        // No parent (root): nothing to fsync — vacuously durable.
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

/// [`fsync_parent_dir`] for the common shape where the body is already fsync'd
/// and the publish succeeded: a trailing dir-fsync failure must not fail the
/// publish, but isn't silent either (CodeRabbit R13 #5) — logs a one-line stderr
/// diagnostic and returns nothing.
pub fn fsync_parent_dir_logged(path: &Path, context: &str) {
    if let Err(e) = fsync_parent_dir(path) {
        eprintln!(
            "tirith: warning: could not fsync parent directory of {} ({context}): {e}; \
             the write succeeded but its directory entry may not be crash-durable",
            path.display()
        );
    }
}

/// Resolve the effective atomic-rewrite target for `path` (CodeRabbit R13b).
/// When `path` is a symlink to an existing target, returns the canonicalized
/// target so a `temp → rename` writes THROUGH the link (preserving it) instead of
/// replacing it. A regular/missing/dangling path returns `path` unchanged.
/// Callers must put their temp file in `dest.parent()` and fsync that parent.
pub fn resolve_symlink_target(path: &Path) -> std::path::PathBuf {
    match std::fs::symlink_metadata(path) {
        // Symlink whose target resolves: write through to the real file
        // (`canonicalize` errors on a dangling link, falling back to `path`).
        Ok(meta) if meta.file_type().is_symlink() => {
            std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
        }
        // Not a symlink: rename onto `path` directly.
        _ => path.to_path_buf(),
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

/// Normalize a path's separators to forward slashes for the `file.path_matches`
/// DSL predicate (its regexes are written with `/`, so a Windows `C:\repo\.env`
/// would never match otherwise). Both the FileScan path and `tirith rule test`
/// route through here for byte-identical normalization (CodeRabbit M13 PR #132).
/// `None` passes through (no path → no `file.path_matches` fact).
pub fn normalize_path_separators(path: Option<&Path>) -> Option<String> {
    path.map(|p| p.to_string_lossy().replace('\\', "/"))
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
        // One byte over the cap — the fstat size gate must reject it.
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
        // A directory must be rejected by the fstat (a dir is never a file).
        match open_regular_capped(dir.path(), 1024) {
            Err(OpenRegularError::NotRegularFile) => {}
            // Some platforms refuse to `open` a directory at all, surfacing an
            // Io error instead — also acceptable.
            Err(OpenRegularError::Io(_)) => {}
            other => panic!("a directory must not open as a regular file, got {other:?}"),
        }
    }

    /// R11 #1: a FIFO at a store path must NOT hang `read_store_lines` — the
    /// helper opens O_NONBLOCK and rejects it via the post-open fstat, reading
    /// empty. A regression to a blocking read would hang here. Unix-only.
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

    /// R11 #1: a symlink to a FIFO must also be rejected — `fstat` on the open fd
    /// follows it to the FIFO inode and refuses it without blocking. Unix-only.
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

    /// A `BufRead` that yields good lines, then a PERSISTENT non-`InvalidData`
    /// error on every subsequent call (a hard I/O fault). The contract is to
    /// BREAK, not spin, so the call returns only the lines read before the fault.
    struct PersistentErrorReader {
        good: Vec<String>,
        idx: usize,
    }

    impl Read for PersistentErrorReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            // Only here to satisfy the `Read` supertrait bound; `lines()` uses
            // `read_line`.
            Err(io::Error::other("unused"))
        }
    }

    impl BufRead for PersistentErrorReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            Ok(&[])
        }
        fn consume(&mut self, _amt: usize) {}
        // Override `read_line` directly (what `lines()` calls) to control each
        // iteration.
        fn read_line(&mut self, buf: &mut String) -> io::Result<usize> {
            if self.idx < self.good.len() {
                buf.push_str(&self.good[self.idx]);
                buf.push('\n');
                self.idx += 1;
                Ok(self.good[self.idx - 1].len() + 1)
            } else {
                // Persistent fault: the SAME error every call — a continue-on-all
                // -errors loop would never terminate.
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "persistent fault",
                ))
            }
        }
    }

    #[test]
    fn persistent_non_invaliddata_error_breaks_does_not_spin() {
        // CodeRabbit R6 #7: `collect_store_lines` must BREAK on a non-`InvalidData`
        // error (an unbounded continue would spin). A regression hangs here.
        let reader = PersistentErrorReader {
            good: vec!["one".to_string(), "two".to_string()],
            idx: 0,
        };
        let lines = collect_store_lines(reader);
        assert_eq!(lines, vec!["one".to_string(), "two".to_string()]);
    }

    #[test]
    fn invalid_utf8_line_is_skipped_not_fatal() {
        // Recoverable case: a single invalid-UTF-8 line is skipped, the reader
        // keeps going.
        let bytes: Vec<u8> = [b"good1\n".as_ref(), &[0xff, 0xfe, b'\n'], b"good2\n"].concat();
        let lines = collect_store_lines(std::io::BufReader::new(&bytes[..]));
        assert_eq!(lines, vec!["good1".to_string(), "good2".to_string()]);
    }

    #[test]
    fn complete_flag_false_on_mid_file_io_fault() {
        // CodeRabbit R13 #1: a mid-file I/O fault leaves the tail unread, so
        // `complete == false` forbids a rewrite (the partial lines are still
        // returned for the fail-open reader).
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
        // A clean read (even skipping a bad-UTF-8 line) reaches EOF, so the image
        // is COMPLETE and safe to rewrite from.
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
        // CodeRabbit R15 #3 — the raw collector preserves surrounding whitespace
        // on content lines (for a byte-for-byte rewrite) but still drops blank ones.
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

        // CONTRAST: the TRIMMED variant (read path) strips that same whitespace,
        // proving the two variants differ exactly on the preserve property.
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
        // CodeRabbit R19 #2: a single-component relative dest has `parent() ==
        // Some("")`; the fix fsyncs `.` rather than skipping. The test process
        // always has an openable cwd, so this must succeed.
        fsync_parent_dir(Path::new("commands.yaml"))
            .expect("single-component relative path must fsync the cwd, not skip");
    }

    #[test]
    fn root_path_with_no_parent_is_noop_ok() {
        // The no-parent case (`/`) stays a vacuous `Ok(())` no-op.
        fsync_parent_dir(Path::new("/")).expect("a path with no parent is a vacuous Ok no-op");
    }
}

#[cfg(test)]
mod normalize_path_separators_tests {
    use super::normalize_path_separators;
    use std::path::Path;

    #[test]
    fn backslashes_become_forward_slashes() {
        assert_eq!(
            normalize_path_separators(Some(Path::new(r"C:\repo\.env"))).as_deref(),
            Some("C:/repo/.env"),
            "Windows backslash separators must normalize to forward slashes so \
             `file.path_matches` regexes (written with `/`) match"
        );
    }

    #[test]
    fn none_passes_through() {
        assert_eq!(
            normalize_path_separators(None),
            None,
            "no path → None, so there is no `file.path_matches` fact"
        );
    }

    #[test]
    fn mixed_separators_normalize_to_forward_slashes() {
        assert_eq!(
            normalize_path_separators(Some(Path::new(r"a/b\c/d\.env"))).as_deref(),
            Some("a/b/c/d/.env"),
            "mixed `/` and `\\` separators all normalize to `/`"
        );
    }

    #[test]
    fn plain_forward_slash_path_is_unchanged() {
        // A POSIX path with no backslashes is returned byte-identical.
        assert_eq!(
            normalize_path_separators(Some(Path::new("src/secrets/.env"))).as_deref(),
            Some("src/secrets/.env"),
            "a path with no backslashes is returned unchanged"
        );
    }
}
