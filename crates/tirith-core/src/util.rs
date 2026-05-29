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
    let file = match open_regular_capped(path, u64::MAX) {
        Ok(f) => f,
        Err(OpenRegularError::NotFound) => return Vec::new(),
        Err(OpenRegularError::NotRegularFile) => {
            warn_store_unreadable(path, "not a regular file");
            return Vec::new();
        }
        Err(OpenRegularError::TooLarge) => {
            warn_store_unreadable(path, "exceeds read cap");
            return Vec::new();
        }
        Err(OpenRegularError::Io(e)) => {
            warn_store_unreadable(path, &e.to_string());
            return Vec::new();
        }
    };
    collect_store_lines(std::io::BufReader::new(file))
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
    let mut out = Vec::new();
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => continue,
            Err(_) => break,
        };
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            out.push(trimmed.to_string());
        }
    }
    out
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
/// Best-effort and **unix-only**: directory fsync is not portable (Windows has
/// no directory-fsync), and a failure here must never turn an otherwise-
/// successful publish into an error — the body is already on stable storage.
/// No-op on non-Unix. (Consolidates the per-module copies in `incident.rs` /
/// `selfupdate.rs` / the card-sign path; CodeRabbit R9 #B.)
#[cfg(unix)]
pub fn fsync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

/// No-op stand-in on non-Unix (directory fsync is not portable). See the unix
/// form for the durability rationale.
#[cfg(not(unix))]
pub fn fsync_parent_dir(_path: &Path) {}

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
    use super::collect_store_lines;
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
}
