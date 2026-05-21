//! Rust-native PTY conformance harness for tirith shell-hook tests.
//!
//! This module spawns a *disposable* interactive shell through a real
//! pseudo-terminal (via `portable-pty`), sources a tirith shell hook inside
//! it, sends bytes (commands + Enter), reads terminal output, and lets the
//! caller assert invariants. The test *driver* is Rust — there is no
//! dependency on the external `expect` Tcl tool, which is flaky on macOS and
//! silently bash-version-sensitive.
//!
//! The harness is the substrate for the "hook conformance contract" — see
//! `docs/shell-hook-conformance.md` and `tests/shell_conformance.rs`.
//!
//! ## Hermeticity
//!
//! Every session runs with `XDG_STATE_HOME` / `XDG_DATA_HOME` /
//! `XDG_CONFIG_HOME` pointed at fresh temp dirs, so a test never reads or
//! writes the developer's real tirith state. `HOME` is also redirected. The
//! enter-mode bash hook shells out to `tirith check`, which *may* attempt a
//! background threat-DB refresh; tests must therefore not assert on network
//! behaviour. A future `--offline` switch (roadmap M0.3) will let the harness
//! pin this deterministically.
//!
//! ## Test tiers / graceful skipping
//!
//! Helpers return `None` (or the test early-returns) when a required shell is
//! not installed. `cargo test --workspace` must stay green on a machine with
//! no modern bash, no fish, no tmux and no SSH — absence is a skip, never a
//! failure.

#![cfg(unix)]
// Each Rust integration test file is its own crate, so a shared support
// module inevitably has items that a given test file does not touch.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use tempfile::TempDir;

/// A writer shared between the reader thread (which answers terminal-capability
/// queries) and the test driver (which sends commands). Each side writes a
/// complete escape/byte sequence while holding the lock, so the two never
/// interleave on the PTY master.
type SharedWriter = Arc<Mutex<Box<dyn Write + Send>>>;

/// Absolute path to an embedded shell hook.
///
/// Tests source the *embedded* copy under `assets/shell/lib/`, exactly as the
/// existing `expect`-based tests do. `embedded_shell_hooks_match_repo_hooks`
/// (in `cli_integration.rs`) guarantees it is byte-identical to `shell/lib/`.
pub fn embedded_hook(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets/shell/lib")
        .join(file)
}

/// Path to the freshly-built `tirith` binary under test.
pub fn tirith_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tirith"))
}

/// Locate a modern bash (>= 5).
///
/// macOS ships an ancient `/bin/bash` 3.2 that lacks features the hook's
/// enter mode relies on; Homebrew installs a current bash at
/// `/opt/homebrew/bin/bash` (Apple Silicon) or `/usr/local/bin/bash` (Intel).
/// Returns `None` when no bash >= 5 can be found, so callers skip cleanly.
pub fn modern_bash() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = vec![
        PathBuf::from("/opt/homebrew/bin/bash"),
        PathBuf::from("/usr/local/bin/bash"),
    ];
    // Whatever `bash` resolves to on PATH — may already be modern.
    if let Ok(out) = Command::new("sh").args(["-c", "command -v bash"]).output() {
        if out.status.success() {
            let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !p.is_empty() {
                candidates.push(PathBuf::from(p));
            }
        }
    }
    candidates
        .into_iter()
        .find(|p| p.exists() && bash_major_version(p).map(|v| v >= 5).unwrap_or(false))
}

/// Parse the major version of the bash binary at `path`.
pub fn bash_major_version(path: &Path) -> Option<u32> {
    let out = Command::new(path).arg("--version").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    let marker = "version ";
    let idx = first.find(marker)?;
    let rest = &first[idx + marker.len()..];
    rest.split('.').next()?.trim().parse::<u32>().ok()
}

/// Locate a fish shell. Returns `None` when fish is not installed.
pub fn fish_bin() -> Option<PathBuf> {
    let out = Command::new("sh")
        .args(["-c", "command -v fish"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if p.is_empty() {
        None
    } else {
        Some(PathBuf::from(p))
    }
}

/// A fresh, fully-isolated environment for one PTY session.
///
/// Holds the temp dirs alive for the session's lifetime and exposes the env
/// var map to apply to the spawned shell. Dropping it cleans everything up.
pub struct IsolatedEnv {
    _root: TempDir,
    pub home: PathBuf,
    pub state_home: PathBuf,
    pub data_home: PathBuf,
    pub config_home: PathBuf,
    /// A scratch directory the test may use as the shell's cwd.
    pub workdir: PathBuf,
    env: HashMap<String, String>,
}

impl IsolatedEnv {
    /// Build a fresh isolated environment with all XDG dirs under one temp root.
    pub fn new() -> Self {
        let root = tempfile::tempdir().expect("pty harness: tempdir");
        let base = root.path();
        let home = base.join("home");
        let state_home = base.join("state");
        let data_home = base.join("data");
        let config_home = base.join("config");
        let workdir = base.join("work");
        for d in [&home, &state_home, &data_home, &config_home, &workdir] {
            std::fs::create_dir_all(d).expect("pty harness: create dir");
        }

        let mut env = HashMap::new();
        env.insert("HOME".to_string(), home.display().to_string());
        env.insert(
            "XDG_STATE_HOME".to_string(),
            state_home.display().to_string(),
        );
        env.insert("XDG_DATA_HOME".to_string(), data_home.display().to_string());
        env.insert(
            "XDG_CONFIG_HOME".to_string(),
            config_home.display().to_string(),
        );
        // Keep the spawned shell from inheriting a double-load guard or a
        // stale bash mode from the developer's own shell.
        env.insert("TERM".to_string(), "xterm-256color".to_string());
        // Unique session id per IsolatedEnv so tirith's per-session state never
        // collides between concurrently-running tests. `process::id()` alone is
        // identical for every test in one `cargo test` run (integration tests
        // share a process); a per-call counter makes it genuinely unique.
        use std::sync::atomic::{AtomicU64, Ordering};
        static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);
        env.insert(
            "TIRITH_SESSION_ID".to_string(),
            format!(
                "pty-conformance-{}-{}",
                std::process::id(),
                SESSION_COUNTER.fetch_add(1, Ordering::Relaxed)
            ),
        );
        // Audit log off: tests assert on terminal behaviour, not the log.
        env.insert("TIRITH_LOG".to_string(), "0".to_string());

        Self {
            _root: root,
            home,
            state_home,
            data_home,
            config_home,
            workdir,
            env,
        }
    }

    /// Set (or override) an env var for the spawned shell.
    pub fn set(&mut self, key: &str, val: &str) -> &mut Self {
        self.env.insert(key.to_string(), val.to_string());
        self
    }

    /// Remove an env var so the spawned shell does not inherit it.
    pub fn unset(&mut self, key: &str) -> &mut Self {
        self.env.remove(key);
        self
    }

    /// Path to the persisted bash safe-mode flag for this environment.
    ///
    /// The bash hook writes this file when enter mode degrades, so a test can
    /// assert that a *visible* degrade also *persisted*.
    pub fn bash_safe_mode_flag(&self) -> PathBuf {
        self.state_home.join("tirith").join("bash-safe-mode")
    }
}

impl Default for IsolatedEnv {
    fn default() -> Self {
        Self::new()
    }
}

/// Answer the terminal-capability queries a shell emits at startup.
///
/// Fish 4.x in particular probes the terminal — DA1 (`ESC [ c`), cursor
/// position (`ESC [ 6 n`), the OSC 11 background-colour query, the kitty
/// keyboard-protocol query (`ESC [ ? u`) and XTGETTCAP (`ESC P + q`). With a
/// real terminal those are answered by the emulator; inside a bare PTY they
/// go unanswered and fish *blocks in startup forever*. This responder writes
/// minimal, honest replies back through the master so the shell proceeds.
///
/// It is harmless for bash (bash does not issue these), so the harness always
/// installs it.
fn answer_terminal_queries(writer: &SharedWriter, data: &[u8]) {
    let contains = |needle: &[u8]| -> bool {
        !needle.is_empty() && data.windows(needle.len()).any(|w| w == needle)
    };
    let mut answer: Vec<u8> = Vec::new();
    // DA1: report as a plain VT100 with advanced video option.
    if contains(b"\x1b[0c") || contains(b"\x1b[c") || contains(b"\x1b[>0c") {
        answer.extend_from_slice(b"\x1b[?1;2c");
    }
    // OSC 11: background colour — answer "black".
    if contains(b"\x1b]11;?") {
        answer.extend_from_slice(b"\x1b]11;rgb:0000/0000/0000\x1b\\");
    }
    // Cursor position report: claim row 1, column 1.
    if contains(b"\x1b[6n") {
        answer.extend_from_slice(b"\x1b[1;1R");
    }
    // Kitty keyboard protocol query: report "not supported".
    if contains(b"\x1b[?u") {
        answer.extend_from_slice(b"\x1b[?0u");
    }
    // XTGETTCAP: reply with an empty/invalid capability response.
    if contains(b"\x1bP+q") {
        answer.extend_from_slice(b"\x1bP0+r\x1b\\");
    }
    if !answer.is_empty() {
        if let Ok(mut w) = writer.lock() {
            let _ = w.write_all(&answer);
            let _ = w.flush();
        }
    }
}

/// A live shell running inside a PTY.
///
/// `send`/`expect`/`drain` drive the conversation; `output()` returns
/// everything read so far. The child is killed on `Drop` as a backstop, but
/// callers should still call [`PtySession::close`] for a clean exit.
pub struct PtySession {
    writer: SharedWriter,
    child: Box<dyn portable_pty::Child + Send + Sync>,
    rx: mpsc::Receiver<Vec<u8>>,
    buf: String,
    closed: bool,
}

/// How long any single `expect` may wait before failing the test.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

impl PtySession {
    /// Spawn `program` with `args` inside a fresh PTY under `env`.
    ///
    /// The shell starts with `cwd` set to the isolated `workdir`.
    pub fn spawn(env: &IsolatedEnv, program: &Path, args: &[&str]) -> Self {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 40,
                cols: 100,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("pty harness: openpty");

        let mut cmd = CommandBuilder::new(program);
        for a in args {
            cmd.arg(a);
        }
        // Start from a clean slate, then apply only the isolated env. This
        // prevents the developer's exported `_TIRITH_*` vars, bash mode,
        // SSH_* markers, etc. from leaking into the disposable shell.
        cmd.env_clear();
        // PATH must survive so the shell can find `tirith`, coreutils, etc.
        if let Ok(path) = std::env::var("PATH") {
            cmd.env("PATH", path);
        }
        for (k, v) in &env.env {
            cmd.env(k, v);
        }
        cmd.cwd(&env.workdir);

        let child = pair
            .slave
            .spawn_command(cmd)
            .expect("pty harness: spawn shell");
        // The slave handle must be dropped once the child holds it, or the
        // master read loop never sees EOF when the child exits.
        drop(pair.slave);

        // `take_writer` is single-shot, so the one writer is shared behind a
        // mutex between the reader thread (terminal-query answers) and the
        // test driver (commands). The reader thread answers queries inline —
        // promptly enough for fish's blocking startup probes — and forwards
        // all output on `tx`.
        let writer: SharedWriter = Arc::new(Mutex::new(
            pair.master.take_writer().expect("pty harness: take_writer"),
        ));
        let mut reader = pair
            .master
            .try_clone_reader()
            .expect("pty harness: clone_reader");
        // The master is not needed past this point: the reader is cloned and
        // the writer is taken. Dropping it keeps the PTY pair minimal.
        drop(pair.master);

        // Drain the PTY on a background thread so a chatty shell can never
        // deadlock us by filling the kernel pipe buffer while we are writing.
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let answer_writer = Arc::clone(&writer);
        thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        answer_terminal_queries(&answer_writer, &chunk[..n]);
                        if tx.send(chunk[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            writer,
            child,
            rx,
            buf: String::new(),
            closed: false,
        }
    }

    /// Pull whatever output is currently available into the buffer, blocking
    /// at most `slice` for the first chunk.
    fn pump(&mut self, slice: Duration) {
        match self.rx.recv_timeout(slice) {
            Ok(bytes) => self.buf.push_str(&String::from_utf8_lossy(&bytes)),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => self.closed = true,
        }
        // Greedily absorb any further chunks already queued.
        while let Ok(bytes) = self.rx.try_recv() {
            self.buf.push_str(&String::from_utf8_lossy(&bytes));
        }
    }

    /// Write raw bytes to the shell's stdin (the PTY master).
    pub fn send_raw(&mut self, bytes: &[u8]) {
        let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        w.write_all(bytes).expect("pty harness: write to pty");
        w.flush().expect("pty harness: flush pty");
    }

    /// Type `line` followed by a carriage return (the Enter key).
    ///
    /// `\r` — not `\n` — is what a real terminal delivers when the user
    /// presses Return, and it is the byte the shell hooks bind.
    pub fn send_line(&mut self, line: &str) {
        let mut s = line.to_string();
        s.push('\r');
        self.send_raw(s.as_bytes());
    }

    /// Block until `needle` appears in cumulative output, or panic on timeout.
    ///
    /// Returns the full output captured up to and including the match.
    pub fn expect(&mut self, needle: &str) -> String {
        self.expect_within(needle, DEFAULT_TIMEOUT)
    }

    /// Like [`PtySession::expect`] but with a caller-chosen deadline.
    pub fn expect_within(&mut self, needle: &str, timeout: Duration) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            if self.buf.contains(needle) {
                return self.buf.clone();
            }
            if Instant::now() >= deadline {
                panic!(
                    "pty harness: timed out after {:?} waiting for {:?}\n\
                     ---- captured output ----\n{}\n-------------------------",
                    timeout,
                    needle,
                    self.buf.trim_end()
                );
            }
            if self.closed && self.rx.try_recv().is_err() {
                panic!(
                    "pty harness: shell exited before {:?} appeared\n\
                     ---- captured output ----\n{}\n-------------------------",
                    needle,
                    self.buf.trim_end()
                );
            }
            self.pump(Duration::from_millis(100));
        }
    }

    /// Return `true` if `needle` appears anywhere in output within `timeout`,
    /// `false` otherwise. Never panics — use to assert a marker is *absent*.
    pub fn appears_within(&mut self, needle: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.buf.contains(needle) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            self.pump(Duration::from_millis(100));
        }
    }

    /// Passively collect output for `dur`, then return everything captured.
    pub fn drain(&mut self, dur: Duration) -> String {
        let deadline = Instant::now() + dur;
        while Instant::now() < deadline {
            self.pump(Duration::from_millis(100));
        }
        self.buf.clone()
    }

    /// All output captured from the shell so far.
    pub fn output(&self) -> &str {
        &self.buf
    }

    /// Discard captured output so far. Useful between phases of a test so a
    /// later [`PtySession::expect`] cannot match an echo from an earlier
    /// command.
    pub fn clear_buffer(&mut self) {
        self.buf.clear();
    }

    /// Block until the shell produces no new output for `quiet` consecutively,
    /// bounded by `max`. Returns the full captured output.
    ///
    /// This is the harness's "the shell has settled" signal — more robust than
    /// a fixed sleep when a hook shells out to `tirith` (variable latency).
    pub fn wait_idle(&mut self, quiet: Duration, max: Duration) -> String {
        let hard_deadline = Instant::now() + max;
        loop {
            let before = self.buf.len();
            self.pump(quiet);
            let settled = self.buf.len() == before;
            if settled || Instant::now() >= hard_deadline {
                return self.buf.clone();
            }
        }
    }

    /// Send `exit` and wait briefly for the shell to terminate.
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        // Best-effort: the shell may already be mid-prompt.
        if let Ok(mut w) = self.writer.lock() {
            let _ = w.write_all(b"exit\r");
            let _ = w.flush();
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                self.closed = true;
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        self.closed = true;
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.child.kill();
        }
    }
}

/// Count non-overlapping occurrences of `needle` in `haystack`.
///
/// The central tool for the "executes EXACTLY ONCE" invariant: a hook bug
/// that swallows a command yields 0, one that double-delivers yields 2.
pub fn count_occurrences(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let mut count = 0;
    let mut rest = haystack;
    while let Some(idx) = rest.find(needle) {
        count += 1;
        rest = &rest[idx + needle.len()..];
    }
    count
}
