//! Rust-native PTY conformance harness: spawns a disposable interactive shell
//! through a real pseudo-terminal (`portable-pty`), sources a tirith hook,
//! sends commands + Enter, reads terminal output, and lets the caller assert
//! invariants — no dependency on the flaky external `expect` tool. Substrate
//! for the hook conformance contract (`docs/shell-hook-conformance.md`,
//! `tests/shell_conformance.rs`).
//!
//! Hermetic: every session points `HOME`/`XDG_*` at fresh temp dirs, so a test
//! never touches real tirith state. The hook shells out to `tirith check`,
//! which may do a background threat-DB refresh, so tests must not assert on
//! network behaviour. Helpers return `None` / early-return when a shell is
//! missing — `cargo test` stays green on a machine without bash/fish/etc.

#![cfg(unix)]
// Each integration test file is its own crate, so a shared support module
// inevitably has items a given file does not touch.
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

/// A writer shared between the reader thread (terminal-query answers) and the
/// test driver (commands); each side writes a complete sequence under the lock
/// so the two never interleave on the PTY master.
type SharedWriter = Arc<Mutex<Box<dyn Write + Send>>>;

/// Absolute path to an embedded shell hook under `assets/shell/lib/`
/// (`embedded_shell_hooks_match_repo_hooks` guarantees it matches `shell/lib/`).
pub fn embedded_hook(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets/shell/lib")
        .join(file)
}

/// Path to the freshly-built `tirith` binary under test.
pub fn tirith_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tirith"))
}

/// Directory of the freshly-built `tirith` binary. The hooks resolve `tirith`
/// by NAME, but cargo doesn't put `target/<profile>/` on `PATH` for integration
/// tests (only `CARGO_BIN_EXE_tirith`), so the harness prepends this itself (see
/// [`PtySession::spawn`]); otherwise `command tirith` exits 127 → false block.
pub fn tirith_bin_dir() -> PathBuf {
    tirith_bin()
        .parent()
        .expect("CARGO_BIN_EXE_tirith must have a parent directory")
        .to_path_buf()
}

/// Locate a modern bash (>= 5). macOS's `/bin/bash` is 3.2 (too old for enter
/// mode); checks the Homebrew paths and whatever's on `PATH`. `None` ⇒ skip.
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

/// Read the full `$BASH_VERSION` string at `path`. The capability cache is keyed
/// on this exact string (not the differently-formatted `bash --version` banner),
/// so a test seeding a cache must use this value.
pub fn bash_version_string(path: &Path) -> Option<String> {
    let out = Command::new(path)
        .args(["-c", "printf '%s' \"$BASH_VERSION\""])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
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

/// A fresh, fully-isolated environment for one PTY session: holds the temp dirs
/// alive and exposes the env var map for the spawned shell. Drop cleans up.
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
        env.insert("TERM".to_string(), "xterm-256color".to_string());
        // Unique session id per IsolatedEnv so per-session state never collides
        // between concurrent tests (`process::id()` is shared across a run, so
        // pair it with a per-call counter).
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

    /// Path to the persisted bash safe-mode flag (the hook writes it on enter-mode
    /// degrade, so a test can assert a visible degrade also persisted).
    pub fn bash_safe_mode_flag(&self) -> PathBuf {
        self.state_home.join("tirith").join("bash-safe-mode")
    }

    /// Path to the bash enter-mode capability cache for this environment.
    pub fn bash_enter_capability_file(&self) -> PathBuf {
        self.state_home.join("tirith").join("bash-enter-capability")
    }

    /// Seed the bash enter-mode capability cache (#111) with `verdict`
    /// (`works`/`broken`/`inconclusive`) to pin the hook's enter-vs-preexec
    /// decision. `bash_version`/`bash_path` must match the spawned shell's exact
    /// `$BASH_VERSION`/`$BASH` or the hook treats the cache as stale (also useful
    /// to test); pass the same path used for [`PtySession::spawn`].
    pub fn seed_bash_enter_capability(&self, verdict: &str, bash_version: &str, bash_path: &Path) {
        let path = self.bash_enter_capability_file();
        std::fs::create_dir_all(path.parent().expect("capability cache parent"))
            .expect("pty harness: create state dir");
        // Schema 1 mirrors `CACHE_SCHEMA`. tirith_version is blank: the hook only
        // enforces it when a sibling `.hooks-version` exists, which the harness
        // (sourcing the hook directly) does not create.
        let body = format!(
            "schema=1\ntirith_version=\nshell=bash\nbash_version={bash_version}\n\
             bash_path={}\nenter_capability={verdict}\n\
             reason=seeded by pty conformance harness\n",
            bash_path.display()
        );
        std::fs::write(&path, body).expect("pty harness: write capability cache");
    }
}

impl Default for IsolatedEnv {
    fn default() -> Self {
        Self::new()
    }
}

/// Answer the terminal-capability queries a shell emits at startup. Fish 4.x
/// probes DA1, cursor position, OSC 11, kitty-keyboard and XTGETTCAP; unanswered
/// in a bare PTY it blocks in startup forever, so this writes minimal honest
/// replies. Harmless for bash (which doesn't issue these), so always installed.
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

/// A live shell running inside a PTY. `send`/`expect`/`drain` drive it;
/// `output()` returns all read so far. Killed on `Drop` as a backstop, but
/// callers should still [`PtySession::close`] for a clean exit.
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
    /// Spawn `program` with `args` in a fresh PTY under `env` (cwd = `workdir`).
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
        // Clean slate + only the isolated env, so the developer's `_TIRITH_*` /
        // bash-mode / SSH_* vars don't leak in.
        cmd.env_clear();
        // PATH must survive (coreutils, shells) and PREPEND the tirith under
        // test: the hooks resolve `tirith` by name, cargo doesn't put
        // `target/<profile>/` on PATH, and a missing tirith → exit 127 → false
        // block. Prepending wins over any stale installed copy.
        let parent_path = std::env::var("PATH").unwrap_or_default();
        let path = if parent_path.is_empty() {
            tirith_bin_dir().display().to_string()
        } else {
            format!("{}:{}", tirith_bin_dir().display(), parent_path)
        };
        cmd.env("PATH", path);
        for (k, v) in &env.env {
            cmd.env(k, v);
        }
        cmd.cwd(&env.workdir);

        let child = pair
            .slave
            .spawn_command(cmd)
            .expect("pty harness: spawn shell");
        // Drop the slave once the child holds it, or the master never sees EOF.
        drop(pair.slave);

        // `take_writer` is single-shot, so the one writer is mutex-shared between
        // the reader thread (answers terminal queries inline, promptly enough for
        // fish's startup probes, and forwards output on `tx`) and the driver.
        let writer: SharedWriter = Arc::new(Mutex::new(
            pair.master.take_writer().expect("pty harness: take_writer"),
        ));
        let mut reader = pair
            .master
            .try_clone_reader()
            .expect("pty harness: clone_reader");
        // Master no longer needed (reader cloned, writer taken).
        drop(pair.master);

        // Drain on a background thread so a chatty shell can't deadlock us by
        // filling the kernel pipe buffer while we write.
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

    /// Pull available output into the buffer, blocking at most `slice` for the
    /// first chunk.
    fn pump(&mut self, slice: Duration) {
        match self.rx.recv_timeout(slice) {
            Ok(bytes) => self.buf.push_str(&String::from_utf8_lossy(&bytes)),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => self.closed = true,
        }
        // Greedily absorb any further queued chunks.
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

    /// Type `line` + a carriage return (`\r`, not `\n`, is what Enter sends and
    /// what the hooks bind).
    pub fn send_line(&mut self, line: &str) {
        let mut s = line.to_string();
        s.push('\r');
        self.send_raw(s.as_bytes());
    }

    /// Block until `needle` appears in cumulative output (panic on timeout),
    /// returning the full captured output.
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

    /// Block until ANY of `needles` appears, returning the captured output; on
    /// timeout (or the shell exiting) returns what was captured WITHOUT panicking
    /// so the caller can assert with a domain message. Use this (not
    /// [`PtySession::wait_idle`]) when waiting on output from a command whose hook
    /// shells out to `tirith` — `wait_idle` would return mid-subprocess (the
    /// no-output race on [`wait_for_marker`]); this polls patiently.
    pub fn expect_any(&mut self, needles: &[&str], timeout: Duration) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            if needles.iter().any(|n| self.buf.contains(n)) {
                return self.buf.clone();
            }
            if Instant::now() >= deadline {
                return self.buf.clone();
            }
            if self.closed && self.rx.try_recv().is_err() {
                return self.buf.clone();
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

    /// Discard captured output so a later [`PtySession::expect`] can't match an
    /// earlier command's echo.
    pub fn clear_buffer(&mut self) {
        self.buf.clear();
    }

    /// Block until no new output for `quiet` consecutively (bounded by `max`) —
    /// the "shell settled" signal, more robust than a fixed sleep.
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

/// Count non-overlapping occurrences of `needle` — the "executes EXACTLY ONCE"
/// primitive (a swallowed command yields 0, a double-delivery yields 2).
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

/// Poll `marker` until it contains `needle` (or `timeout`), returning the
/// file's final contents.
///
/// The no-output race: [`PtySession::wait_idle`] keys on terminal quiet, but a
/// side-effect-only command (and an allow-verdict `tirith check`) prints
/// nothing, so `wait_idle` returns BEFORE the hook delivers the command and the
/// marker is read while empty (macOS wins this race, slow CI doesn't — #116).
/// Polling the filesystem side effect is correct at any machine speed.
pub fn wait_for_marker(marker: &Path, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let body = std::fs::read_to_string(marker).unwrap_or_default();
        if count_occurrences(&body, needle) >= 1 {
            return body;
        }
        if Instant::now() >= deadline {
            return body;
        }
        thread::sleep(Duration::from_millis(50));
    }
}
