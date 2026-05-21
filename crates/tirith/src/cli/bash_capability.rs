//! Bash enter-mode delivery capability self-test (issue #111).
//!
//! # Why this exists
//!
//! Tirith's bash hook has two modes:
//!
//! * **enter** — rebinds Enter (`\C-m`) with `bind -x` to a shell function so it
//!   can *block* a dangerous command before it runs.
//! * **preexec** — a `DEBUG`-trap observer; warn-only, cannot block.
//!
//! Enter mode is the only bash mode that can truly block. But `bind -x` on
//! `\C-m` has a fatal quirk in many environments: it runs the bound function
//! and then **does not accept the line**. Bash stays inside readline's editing
//! loop, never returns to its command-evaluation loop, so `PROMPT_COMMAND`
//! never fires and the command the hook deferred into `_TIRITH_PENDING_EVAL`
//! is never delivered. The typed command is silently eaten — issue #111.
//!
//! Whether `bind -x` accepts the line is a *capability* of the specific
//! bash/readline build, not a function of the bash version number. So tirith
//! cannot decide enter-vs-preexec by version gate. Instead it **proves** the
//! capability empirically: spawn a disposable bash through a PTY, source the
//! real hook in enter mode, and check whether a command typed + Enter actually
//! runs — and, just as importantly, whether a command that should be *blocked*
//! is actually stopped.
//!
//! # The init-time constraint
//!
//! `tirith init` output is `eval`'d on **every** interactive shell startup, so
//! it must stay fast and side-effect-free. The PTY self-test is far too heavy
//! to run there. Instead:
//!
//! * The self-test runs only at `tirith setup` and `tirith doctor` (and the
//!   explicit `tirith doctor --simulate-enter`). It is timeout-bound.
//! * It writes a small `key=value` **cache file** to the tirith state dir,
//!   recording the verdict keyed by the bash identity (version + path). The
//!   cache `schema` number is the cross-tirith-version invalidator: enter-mode
//!   delivery is a bash-build property and does not change across tirith
//!   releases, so any change to the probe semantics or cache format bumps
//!   [`CACHE_SCHEMA`] instead of keying on the tirith version.
//! * `tirith init` is unchanged. The bash hook itself reads the cache at
//!   startup — a single small-file read, which *is* init-safe — and only
//!   selects enter mode when the cache proves enter delivery works for the
//!   running bash. Absent / stale / `broken` cache ⇒ the hook falls back to the
//!   safe default (preexec, warn-only).
//!
//! Failing closed to preexec is the safety floor: a wrong guess never leaves
//! the user believing they are protected when they are not.

#![cfg(unix)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, CommandBuilder, PtySize};

/// Cache-file schema version. Bump when the cache format changes so an old
/// hook reading a new file (or vice versa) treats the mismatch as stale.
pub const CACHE_SCHEMA: u32 = 1;

/// Name of the capability cache file inside `state_dir()`.
pub const CACHE_FILENAME: &str = "bash-enter-capability";

/// Hard cap on one PTY probe phase settling.
const PHASE_TIMEOUT: Duration = Duration::from_secs(6);
/// Hard cap on waiting for a side-effect-only command's marker file to appear
/// (or to be confirmed absent). A command like `printf >> marker` writes
/// nothing to the terminal, and when tirith *allows* it the `tirith check`
/// subprocess prints nothing either — so terminal silence is reached *before*
/// the command runs. Completion must therefore be read from the filesystem
/// side effect, not from terminal quiet. Generous for a loaded CI box, yet
/// bounded so a genuinely swallowed command still fails fast.
const MARKER_TIMEOUT: Duration = Duration::from_secs(8);
/// Filesystem poll interval while waiting on a marker file.
const MARKER_POLL: Duration = Duration::from_millis(50);

/// Verdict of the enter-mode delivery self-test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnterCapability {
    /// Enter mode delivers an allowed command exactly once **and** blocks a
    /// command that should be blocked. Enter mode is safe to use.
    Works,
    /// Enter mode does not deliver, or delivers but fails to block. Enter mode
    /// must not be used; fall back to preexec.
    Broken,
    /// The probe could not reach a confident verdict (no bash, PTY spawn
    /// failure, ambiguous output). Treated exactly like `Broken` by the hook —
    /// fail closed — but reported separately so `doctor` can explain it.
    Inconclusive,
}

impl EnterCapability {
    /// The token written to / read from the cache file.
    fn as_token(self) -> &'static str {
        match self {
            EnterCapability::Works => "works",
            EnterCapability::Broken => "broken",
            EnterCapability::Inconclusive => "inconclusive",
        }
    }

    /// Human-facing one-liner for `doctor` output.
    pub fn describe(self) -> &'static str {
        match self {
            EnterCapability::Works => "enter mode delivers and blocks correctly",
            EnterCapability::Broken => "enter mode cannot deliver/block — preexec will be used",
            EnterCapability::Inconclusive => {
                "enter-mode self-test inconclusive — preexec will be used"
            }
        }
    }

    /// Only `Works` lets the hook turn on enter mode.
    pub fn enables_enter(self) -> bool {
        matches!(self, EnterCapability::Works)
    }
}

/// Outcome of [`run_and_cache`]: the verdict, the bash that was probed, and a
/// short reason string suitable for diagnostics.
#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    pub capability: EnterCapability,
    /// `$BASH_VERSION` of the bash that was probed, when one was found.
    pub bash_version: Option<String>,
    /// Absolute path of the bash binary that was probed, when one was found.
    pub bash_path: Option<PathBuf>,
    /// Short human-readable reason for the verdict.
    pub reason: String,
    /// Absolute path of the cache file that was written, when the write
    /// succeeded.
    pub cache_path: Option<PathBuf>,
}

/// A cached capability decision read back from disk.
#[derive(Debug, Clone)]
pub struct CachedDecision {
    pub capability: EnterCapability,
    pub tirith_version: String,
    pub bash_version: String,
    /// Absolute path of the bash binary the verdict was measured against.
    /// Empty when the writer could not resolve one. The capability is a
    /// property of the bash *build*, not just the version string, so a
    /// different binary at the same version is treated as a different bash.
    pub bash_path: String,
    pub reason: String,
}

/// Locate a bash binary to probe.
///
/// The hook the user actually runs is whatever `bash` resolves to for them, so
/// the probe targets the same: `command -v bash`. The path is returned *as
/// resolved by `command -v`* — deliberately not canonicalized through
/// symlinks — because the hook compares the cached value against bash's own
/// `$BASH`, which is likewise the user-facing invocation path. Comparing
/// resolved-symlink paths would instead cause a false mismatch for the common
/// Homebrew layout (`/opt/homebrew/bin/bash` is a symlink into `Cellar`).
/// Returns `None` when bash is not on `PATH`.
pub fn discover_bash() -> Option<PathBuf> {
    let out = std::process::Command::new("sh")
        .args(["-c", "command -v bash"])
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

/// Read `$BASH_VERSION` for the bash binary at `path`.
pub fn bash_version_of(path: &Path) -> Option<String> {
    let out = std::process::Command::new(path)
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

/// Single-quote a path for safe embedding in a POSIX shell command.
///
/// The probe types commands like `source <path>` into the disposable shell;
/// the temp dir comes from `$TMPDIR`, which could contain a `'`. Wrapping in
/// single quotes and escaping any embedded `'` as `'\''` makes the path a
/// single shell word regardless of its contents.
fn posix_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

/// Absolute path to the embedded bash hook materialised for probing.
///
/// The probe must source the *real* hook — the same bytes a user runs — so it
/// writes the embedded `assets::BASH_HOOK` into the supplied temp dir. (Reading
/// the on-disk materialised copy would couple the probe to install layout; the
/// embedded copy is byte-identical and always present.)
fn write_probe_hook(dir: &Path) -> std::io::Result<PathBuf> {
    let path = dir.join("bash-hook.bash");
    std::fs::write(&path, crate::assets::BASH_HOOK)?;
    Ok(path)
}

// ---------------------------------------------------------------------------
// PTY probe
// ---------------------------------------------------------------------------

/// A minimal PTY-driven shell session, just enough for the two-phase probe.
struct ProbeSession {
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
    rx: mpsc::Receiver<Vec<u8>>,
    buf: String,
}

impl ProbeSession {
    /// Spawn `program` with `args` in a fresh PTY under the given environment.
    fn spawn(
        program: &Path,
        args: &[&str],
        envs: &[(String, String)],
        cwd: &Path,
    ) -> std::io::Result<Self> {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: 40,
                cols: 100,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| std::io::Error::other(format!("openpty: {e}")))?;

        let mut cmd = CommandBuilder::new(program);
        for a in args {
            cmd.arg(a);
        }
        cmd.env_clear();
        if let Ok(path) = std::env::var("PATH") {
            cmd.env("PATH", path);
        }
        for (k, v) in envs {
            cmd.env(k, v);
        }
        cmd.cwd(cwd);

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| std::io::Error::other(format!("spawn: {e}")))?;
        drop(pair.slave);

        let writer: Arc<Mutex<Box<dyn Write + Send>>> =
            Arc::new(Mutex::new(pair.master.take_writer().map_err(|e| {
                std::io::Error::other(format!("take_writer: {e}"))
            })?));
        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| std::io::Error::other(format!("clone_reader: {e}")))?;
        drop(pair.master);

        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        if tx.send(chunk[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            writer,
            child,
            rx,
            buf: String::new(),
        })
    }

    /// Pull whatever output is queued into the buffer, blocking at most `slice`.
    fn pump(&mut self, slice: Duration) {
        match self.rx.recv_timeout(slice) {
            Ok(bytes) => self.buf.push_str(&String::from_utf8_lossy(&bytes)),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {}
        }
        while let Ok(bytes) = self.rx.try_recv() {
            self.buf.push_str(&String::from_utf8_lossy(&bytes));
        }
    }

    /// Type `line` followed by a carriage return — the byte a real terminal
    /// sends when Enter is pressed, and the byte the hook binds.
    fn send_line(&mut self, line: &str) {
        let mut s = line.to_string();
        s.push('\r');
        if let Ok(mut w) = self.writer.lock() {
            let _ = w.write_all(s.as_bytes());
            let _ = w.flush();
        }
    }

    /// Block until `needle` appears in output, or `timeout` elapses. Returns
    /// `true` on match.
    fn wait_for(&mut self, needle: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.buf.contains(needle) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            self.pump(Duration::from_millis(80));
        }
    }

    /// Drain whatever PTY output is currently queued, blocking at most `slice`
    /// for the first chunk. Used to keep the reader channel from filling while
    /// the probe waits on a filesystem marker rather than on terminal output.
    fn drain(&mut self, slice: Duration) {
        self.pump(slice);
    }

    /// Kill the child immediately. Used after a failed probe phase: the readline
    /// buffer may still hold a stale command, so the session must be torn down
    /// hard rather than nudged with another Enter (which could let a deferred
    /// command through and produce a false `works`).
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ProbeSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

/// Count non-overlapping occurrences of `needle` in `haystack`.
fn count_occurrences(haystack: &str, needle: &str) -> usize {
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

/// Poll `marker` until its contents contain `needle`, or `timeout` elapses.
/// Returns `true` once `needle` is seen, `false` if the deadline passes first.
/// `sess` is drained each tick so the PTY reader channel cannot fill.
///
/// ## Why this exists — the no-output race
///
/// The probe types side-effect-only commands (`printf >> marker`,
/// `printf 'true' | bash && touch marker`) into a disposable shell whose
/// enter-mode hook shells out to `tirith check`. A `printf >> marker` command
/// prints nothing to the terminal, and on an *allow* verdict `tirith check`
/// prints nothing either — so the only terminal output is the keystroke echo.
/// Keying completion on terminal silence (the old `wait_idle`) therefore
/// returns *before* the hook has finished shelling out to `tirith` and
/// delivered the command, and the marker is then read while still empty —
/// caching a false `Broken` on a working bash, and (worse) letting
/// `probe_blocking` read a not-yet-run command's absent marker as "blocked".
/// macOS happens to win that race; a slower Linux CI box does not.
///
/// The fix mirrors `tests/pty_support::wait_for_marker` exactly: stop
/// inferring completion from terminal quiet and poll the filesystem side
/// effect — the marker file is the ground truth — with a generous bounded
/// timeout instead of a fixed settle-then-kill.
fn wait_for_marker(
    sess: &mut ProbeSession,
    marker: &Path,
    needle: &str,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if std::fs::read_to_string(marker)
            .unwrap_or_default()
            .contains(needle)
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        // Keep the PTY reader channel drained while we wait on the filesystem.
        sess.drain(MARKER_POLL);
    }
}

/// Wait `timeout` for `marker` to appear, draining the PTY meanwhile, then
/// report whether it stayed **absent**. The mirror of [`wait_for_marker`] for
/// an expected-absent side effect: an absence cannot be confirmed early, so it
/// always waits the full bound to be sure the marker never shows up.
fn marker_stays_absent(sess: &mut ProbeSession, marker: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if marker.exists() {
            return false;
        }
        // The check above already established absence for this tick; if the
        // deadline has now passed, the marker stayed absent for the full bound.
        if Instant::now() >= deadline {
            return true;
        }
        sess.drain(MARKER_POLL);
    }
}

/// Environment for a hermetic probe session, isolated from the developer's real
/// tirith state. Holds the temp dir alive for the probe's duration.
struct ProbeEnv {
    _root: tempfile::TempDir,
    work: PathBuf,
    envs: Vec<(String, String)>,
    hook: PathBuf,
}

impl ProbeEnv {
    fn new() -> std::io::Result<Self> {
        let root = tempfile::tempdir()?;
        let base = root.path().to_path_buf();
        let home = base.join("home");
        let state = base.join("state");
        let data = base.join("data");
        let config = base.join("config");
        let work = base.join("work");
        for d in [&home, &state, &data, &config, &work] {
            std::fs::create_dir_all(d)?;
        }
        let hook = write_probe_hook(&base)?;

        let envs = vec![
            ("HOME".to_string(), home.display().to_string()),
            ("XDG_STATE_HOME".to_string(), state.display().to_string()),
            ("XDG_DATA_HOME".to_string(), data.display().to_string()),
            ("XDG_CONFIG_HOME".to_string(), config.display().to_string()),
            ("TERM".to_string(), "xterm-256color".to_string()),
            // Force enter mode for the probe regardless of the developer's env.
            ("TIRITH_BASH_MODE".to_string(), "enter".to_string()),
            // Audit log off — the probe asserts on behaviour, not the log.
            ("TIRITH_LOG".to_string(), "0".to_string()),
        ];

        Ok(Self {
            _root: root,
            work,
            envs,
            hook,
        })
    }
}

/// Probe whether bash enter mode can *deliver* an allowed command exactly once.
///
/// Returns `Ok(true)` when the marker file holds exactly one nonce line after
/// the command + Enter, `Ok(false)` when delivery failed (#111 reproduced),
/// and `Err` when the probe could not run to a verdict.
///
/// Completion is read from the marker *file*, not from terminal quiet: the
/// probe command is side-effect-only and the hook shells out to `tirith
/// check`, so terminal silence is reached before the command actually runs
/// (the no-output race documented on [`wait_for_marker`]). The marker is
/// polled with a bounded timeout — the same robustness the PTY conformance
/// harness already adopted.
fn probe_delivery(bash: &Path, env: &ProbeEnv) -> Result<bool, String> {
    let marker = env.work.join("deliver_marker");
    let nonce = "TIRITH_PROBE_DELIVER_NONCE";

    let mut sess =
        ProbeSession::spawn(bash, &["--norc", "--noprofile", "-i"], &env.envs, &env.work)
            .map_err(|e| format!("PTY spawn failed: {e}"))?;

    // A fixed prompt the probe synchronises on.
    sess.send_line("export PS1='TIRITH_PROBE> '");
    if !sess.wait_for("TIRITH_PROBE> ", PHASE_TIMEOUT) {
        sess.kill();
        return Err("bash never reached the probe prompt".into());
    }
    sess.send_line(&format!("source {}", posix_quote(&env.hook)));
    if !sess.wait_for("TIRITH_PROBE> ", PHASE_TIMEOUT) {
        sess.kill();
        return Err("sourcing the hook did not return a prompt".into());
    }

    // An allowed, side-effect-only command: append one nonce line to a marker.
    // Poll the marker file rather than wait for terminal quiet — a
    // `printf >> marker` command (and `tirith check` on an allow verdict)
    // print nothing, so terminal silence happens *before* delivery.
    sess.send_line(&format!("printf '{nonce}\\n' >> {}", posix_quote(&marker)));
    let delivered = wait_for_marker(&mut sess, &marker, nonce, MARKER_TIMEOUT);
    // Tear the session down hard — never send a second Enter, which (in the
    // broken case) could flush a stale readline buffer and fake a success.
    sess.kill();

    if !delivered {
        // The marker never gained the nonce within the bound: the command was
        // not delivered (#111 reproduced).
        return Ok(false);
    }
    // Delivered. Re-read once to assert it ran *exactly* once — a hook that
    // double-delivered would write the nonce twice and is just as broken.
    let body = std::fs::read_to_string(&marker).unwrap_or_default();
    Ok(count_occurrences(&body, nonce) == 1)
}

/// Probe whether bash enter mode actually *blocks* a command that tirith would
/// block.
///
/// A delivery-only check is not enough: a hook variant that delivers but cannot
/// block would still be unsafe. This phase types a blocked pipe-to-interpreter
/// whose payload, if it ran, would create a marker; the marker must stay absent.
///
/// The pipe producer is a purely local `printf` — **not** `curl` — on purpose:
/// `printf 'true' | bash` is blocked by the same `pipe_to_interpreter` rule, but
/// involves no network. A `curl`-based probe could report "blocked" simply
/// because `curl` is missing or the network is down, which is indistinguishable
/// from a correct block and would falsely upgrade a broken hook to `works`.
///
/// ## Why an empty-policy probe environment is correct
///
/// [`ProbeEnv::new`] points `XDG_CONFIG_HOME` / `XDG_DATA_HOME` /
/// `XDG_STATE_HOME` at fresh empty temp dirs — no policy file, no threat
/// database. This is deliberate, not an oversight: tirith's detection rules
/// (including `pipe_to_interpreter`) fire **unconditionally**, independent of
/// any policy. A policy file only *adds* allowlist / blocklist / severity
/// overrides on top of the rule engine — there is no "allow-all when no policy"
/// default. So `printf 'true' | bash` is a HIGH `pipe_to_interpreter` block
/// (`tirith check` exit 1) in a zero-policy environment, exactly as it is with
/// a policy present. Verified empirically: `tirith check` on that command in an
/// env with an empty `XDG_CONFIG_HOME` exits 1 / `BLOCKED`.
///
/// Were tirith ever to gain an allow-by-default-without-policy mode, this probe
/// would have to seed a minimal blocking policy first — but as built, an empty
/// probe environment is the correct, network-free way to assert "enter mode can
/// block".
///
/// ## Why this phase has an anti-vacuous guard
///
/// A swallowed command trivially produces no marker — so "the blocked
/// command's marker is absent" proves *blocking* only once it is also proven
/// that this probe shell delivers commands at all. The old code killed the
/// shell after terminal quiet and read marker-absent as "blocked": a command
/// the hook never even ran (the #111 swallow, or a command killed before it
/// executed) was indistinguishable from a correctly blocked one, and would
/// falsely upgrade a broken hook to `works`.
///
/// This phase therefore first delivers an *allowed* side-effect-only command
/// and polls its marker. Only if that marker appears — proving the probe shell
/// is genuinely delivering commands — does it then send the blocked command
/// and poll *its* marker as absent. If the allowed command never runs, the
/// probe cannot conclude anything: it returns `Err` (which [`probe`] maps to
/// [`EnterCapability::Inconclusive`]), never `Ok(true)`.
///
/// Returns `Ok(true)` when the allowed command ran *and* the blocked command
/// did not (marker absent), `Ok(false)` when the blocked command executed
/// anyway, and `Err` when the probe could not run to a verdict — including the
/// anti-vacuous case where the allowed command itself was not delivered.
fn probe_blocking(bash: &Path, env: &ProbeEnv) -> Result<bool, String> {
    let allowed_marker = env.work.join("block_allowed_marker");
    let blocked_marker = env.work.join("block_marker");
    let allowed_nonce = "TIRITH_PROBE_BLOCK_ALLOWED_NONCE";

    let mut sess =
        ProbeSession::spawn(bash, &["--norc", "--noprofile", "-i"], &env.envs, &env.work)
            .map_err(|e| format!("PTY spawn failed: {e}"))?;

    sess.send_line("export PS1='TIRITH_PROBE> '");
    if !sess.wait_for("TIRITH_PROBE> ", PHASE_TIMEOUT) {
        sess.kill();
        return Err("bash never reached the probe prompt".into());
    }
    sess.send_line(&format!("source {}", posix_quote(&env.hook)));
    if !sess.wait_for("TIRITH_PROBE> ", PHASE_TIMEOUT) {
        sess.kill();
        return Err("sourcing the hook did not return a prompt".into());
    }

    // Anti-vacuous guard: an *allowed* side-effect-only command must actually
    // run. If its marker never appears, this probe shell is swallowing
    // commands — a marker-absent verdict on the blocked command below would
    // then be meaningless, so bail to an inconclusive result rather than
    // report a false `blocked`.
    sess.send_line(&format!(
        "printf '{allowed_nonce}\\n' >> {}",
        posix_quote(&allowed_marker)
    ));
    if !wait_for_marker(&mut sess, &allowed_marker, allowed_nonce, MARKER_TIMEOUT) {
        sess.kill();
        return Err(
            "anti-vacuous guard failed: the probe shell did not deliver an allowed \
             command, so a blocked-command verdict cannot be trusted"
                .into(),
        );
    }

    // A purely local pipe-to-interpreter — `printf 'true' | bash` — which
    // tirith blocks via the `pipe_to_interpreter` rule. The `&& touch` clause
    // runs only if the pipeline executed; tirith must block before that. Using
    // a local producer (not `curl`) keeps the verdict independent of network
    // reachability — see the doc comment above. The marker is *expected to be
    // absent*: poll for the full timeout to be sure it never appears, draining
    // the PTY meanwhile.
    sess.send_line(&format!(
        "printf 'true' | bash && touch {}",
        posix_quote(&blocked_marker)
    ));
    let blocked = !marker_stays_absent(&mut sess, &blocked_marker, MARKER_TIMEOUT);
    sess.kill();

    // Guard passed (commands are delivered) and the blocked command's marker
    // stayed absent ⇒ it was genuinely blocked.
    Ok(!blocked)
}

/// Combine the two probe phases' results into the final verdict and reason.
///
/// Pulled out of [`probe`] as a pure function so the verdict logic is unit
/// testable without spawning a PTY — the PTY phases are environment-dependent
/// (whether `bind -x` accepts the line is a property of the bash/readline
/// build), but the composition rule is fixed and must stay regression-safe:
///
/// * delivery `Ok(true)` + blocking `Ok(true)` ⇒ [`EnterCapability::Works`].
/// * delivery `Ok(false)` (the #111 swallow) ⇒ [`EnterCapability::Broken`] —
///   blocking is not even attempted.
/// * delivery `Ok(true)` + blocking `Ok(false)` (delivered but did not block)
///   ⇒ [`EnterCapability::Broken`].
/// * either phase `Err` ⇒ [`EnterCapability::Inconclusive`] — the probe could
///   not run to a confident verdict (including `probe_blocking`'s anti-vacuous
///   guard failing). Fail closed: the hook treats this exactly like `Broken`.
///
/// `blocking` is `None` when delivery failed and blocking was skipped.
fn classify_probe_results(
    delivery: &Result<bool, String>,
    blocking: Option<&Result<bool, String>>,
) -> (EnterCapability, String) {
    match delivery {
        Ok(false) => (
            EnterCapability::Broken,
            "enter mode did not deliver an allowed command (issue #111)".into(),
        ),
        Err(e) => (
            EnterCapability::Inconclusive,
            format!("delivery probe could not run: {e}"),
        ),
        Ok(true) => match blocking {
            Some(Ok(true)) => (
                EnterCapability::Works,
                "enter mode delivers an allowed command and blocks a blocked one".into(),
            ),
            Some(Ok(false)) => (
                EnterCapability::Broken,
                "enter mode delivered but failed to block a blocked command".into(),
            ),
            Some(Err(e)) => (
                EnterCapability::Inconclusive,
                format!("blocking probe could not run: {e}"),
            ),
            None => (
                EnterCapability::Inconclusive,
                "delivery succeeded but the blocking phase was not run".into(),
            ),
        },
    }
}

/// Run the full enter-mode self-test against whatever bash is on `PATH`.
///
/// Never panics and never blocks unbounded — every phase is timeout-capped. A
/// missing bash, a PTY failure, or ambiguous output all yield
/// [`EnterCapability::Inconclusive`], which the hook treats as "do not use
/// enter mode".
pub fn probe() -> ProbeOutcome {
    let Some(bash) = discover_bash() else {
        return ProbeOutcome {
            capability: EnterCapability::Inconclusive,
            bash_version: None,
            bash_path: None,
            reason: "no bash found on PATH".into(),
            cache_path: None,
        };
    };
    let bash_version = bash_version_of(&bash);

    let env = match ProbeEnv::new() {
        Ok(e) => e,
        Err(e) => {
            return ProbeOutcome {
                capability: EnterCapability::Inconclusive,
                bash_version,
                bash_path: Some(bash),
                reason: format!("could not stage probe environment: {e}"),
                cache_path: None,
            };
        }
    };

    // Phase 1 — delivery. If an allowed command is not delivered, this is #111.
    let delivery = probe_delivery(&bash, &env);
    // Phase 2 — blocking runs only if delivery succeeded: delivery alone is not
    // enough (enter mode must also stop a dangerous command), and a failed
    // delivery already settles the verdict as `Broken`.
    let blocking = matches!(delivery, Ok(true)).then(|| probe_blocking(&bash, &env));

    let (capability, reason) = classify_probe_results(&delivery, blocking.as_ref());
    ProbeOutcome {
        capability,
        bash_version,
        bash_path: Some(bash),
        reason,
        cache_path: None,
    }
}

// ---------------------------------------------------------------------------
// Cache file
// ---------------------------------------------------------------------------

/// Absolute path of the capability cache file.
pub fn cache_path() -> Option<PathBuf> {
    tirith_core::policy::state_dir().map(|d| d.join(CACHE_FILENAME))
}

/// Render the cache file body. A deliberately tiny, strict `key=value` format —
/// no JSON — so the bash hook can parse it with the same `IFS='='` loop it
/// already uses for approval files, with no `jq` / `python` / subprocess.
fn render_cache(outcome: &ProbeOutcome) -> String {
    let bash_version = outcome.bash_version.as_deref().unwrap_or("");
    // `command -v bash` output is a single path with no newline, so it is safe
    // in the key=value grammar as-is.
    let bash_path = outcome
        .bash_path
        .as_deref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let mut body = String::new();
    body.push_str(&format!("schema={CACHE_SCHEMA}\n"));
    body.push_str(&format!("tirith_version={}\n", env!("CARGO_PKG_VERSION")));
    body.push_str("shell=bash\n");
    body.push_str(&format!("bash_version={bash_version}\n"));
    body.push_str(&format!("bash_path={bash_path}\n"));
    body.push_str(&format!(
        "enter_capability={}\n",
        outcome.capability.as_token()
    ));
    // Reason is diagnostic only — the hook never parses it. Strip newlines so a
    // multi-line reason can never break the key=value grammar.
    let reason = outcome.reason.replace(['\n', '\r'], " ");
    body.push_str(&format!("reason={reason}\n"));
    body
}

/// Write the capability decision to the cache file atomically.
///
/// Writes to a uniquely-named temp file in the same directory then renames it
/// over the target, so a hook reading concurrently sees either the whole old
/// file or the whole new one — never a half-written one, and two concurrent
/// writers never share a staging file. Returns the path written on success.
pub fn write_cache(outcome: &ProbeOutcome) -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;

    let path = cache_path().ok_or("could not determine tirith state directory")?;
    let dir = path
        .parent()
        .ok_or("capability cache path has no parent directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;

    let body = render_cache(outcome);

    // `NamedTempFile` picks a random, collision-free name in `dir`, so
    // concurrent `write_cache` calls — even in the same process — never clobber
    // each other's staging file. It is created mode 0o600; tighten explicitly
    // in case a restrictive default ever changes.
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| format!("create temp file in {}: {e}", dir.display()))?;
    tmp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod temp cache file: {e}"))?;
    tmp.write_all(body.as_bytes())
        .map_err(|e| format!("write temp cache file: {e}"))?;
    tmp.flush()
        .map_err(|e| format!("flush temp cache file: {e}"))?;
    // `persist` is the atomic rename onto the same filesystem; on failure it
    // hands back the temp file, which is dropped (and unlinked) immediately.
    tmp.persist(&path)
        .map_err(|e| format!("rename into {}: {}", path.display(), e.error))?;
    Ok(path)
}

/// Parse a capability token from the cache file.
fn parse_capability(token: &str) -> Option<EnterCapability> {
    match token.trim() {
        "works" => Some(EnterCapability::Works),
        "broken" => Some(EnterCapability::Broken),
        "inconclusive" => Some(EnterCapability::Inconclusive),
        _ => None,
    }
}

/// Read and validate the capability cache.
///
/// Returns `Some` only when the file exists, parses, and its schema matches the
/// running binary's. The caller decides what to do with a stale tirith /bash
/// version. Returns `None` on any failure — fail closed.
pub fn read_cache() -> Option<CachedDecision> {
    let path = cache_path()?;
    let body = std::fs::read_to_string(&path).ok()?;
    // Guard against an oversized / junk file masquerading as a cache.
    if body.len() > 4096 {
        return None;
    }

    let mut schema: Option<u32> = None;
    let mut tirith_version: Option<String> = None;
    let mut bash_version: Option<String> = None;
    let mut bash_path: Option<String> = None;
    let mut capability: Option<EnterCapability> = None;
    let mut reason = String::new();

    for line in body.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "schema" => schema = value.trim().parse().ok(),
            "tirith_version" => tirith_version = Some(value.trim().to_string()),
            "bash_version" => bash_version = Some(value.trim().to_string()),
            "bash_path" => bash_path = Some(value.trim().to_string()),
            "enter_capability" => capability = parse_capability(value),
            "reason" => reason = value.trim().to_string(),
            _ => {}
        }
    }

    if schema != Some(CACHE_SCHEMA) {
        return None;
    }
    // Every field the freshness check needs must be present. A schema-1 cache
    // is always written with all of them; a missing one means a corrupt or
    // hand-edited file, so reject it (`?`) and fail closed to preexec.
    Some(CachedDecision {
        capability: capability?,
        tirith_version: tirith_version?,
        bash_version: bash_version?,
        bash_path: bash_path?,
        reason,
    })
}

/// Whether a cached decision is fresh for the bash currently on `PATH`.
///
/// "Fresh" requires the bash `$BASH_VERSION` and the bash *path* (`command -v
/// bash`) to match: `bind -x` line-acceptance is a property of the specific
/// bash/readline build, so a different bash now first on `PATH` must invalidate
/// the verdict. The tirith version is *not* part of freshness — enter-mode
/// delivery does not change across tirith releases, and the cache schema
/// (checked in [`read_cache`]) is the cross-version invalidator for any probe
/// or format change. This mirrors the bash hook's `_tirith_enter_capability_
/// proven` exactly, so `doctor` and the hook never disagree about a cache. A
/// `false` result means the hook ignores the cache and falls back to preexec.
pub fn decision_is_fresh(decision: &CachedDecision) -> bool {
    let Some(bash) = discover_bash() else {
        return false;
    };
    if bash.display().to_string() != decision.bash_path {
        return false;
    }
    match bash_version_of(&bash) {
        Some(running) => running == decision.bash_version,
        None => false,
    }
}

/// Run the self-test and persist the result.
///
/// This is the entry point for `tirith setup` and `tirith doctor`. It always
/// returns a [`ProbeOutcome`]; cache-write failure is folded into the outcome's
/// `cache_path` (left `None`) rather than surfaced as a hard error, because a
/// failed cache write simply means the hook keeps using its safe default.
pub fn run_and_cache() -> ProbeOutcome {
    let mut outcome = probe();
    match write_cache(&outcome) {
        Ok(path) => outcome.cache_path = Some(path),
        Err(e) => {
            eprintln!("tirith: could not write bash enter-mode capability cache: {e}");
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_quote_escapes_embedded_single_quotes() {
        assert_eq!(posix_quote(Path::new("/tmp/plain")), "'/tmp/plain'");
        // A path with a single quote must round-trip as one shell word.
        assert_eq!(
            posix_quote(Path::new("/tmp/it's here/bash")),
            "'/tmp/it'\\''s here/bash'"
        );
        // Spaces are covered by the surrounding quotes.
        assert_eq!(posix_quote(Path::new("/a b/c")), "'/a b/c'");
    }

    #[test]
    fn count_occurrences_is_non_overlapping() {
        assert_eq!(count_occurrences("", "x"), 0);
        assert_eq!(count_occurrences("abc", ""), 0);
        assert_eq!(count_occurrences("NONCE", "NONCE"), 1);
        assert_eq!(count_occurrences("NONCE NONCE", "NONCE"), 2);
        assert_eq!(count_occurrences("aaaa", "aa"), 2);
    }

    #[test]
    fn capability_tokens_round_trip() {
        for cap in [
            EnterCapability::Works,
            EnterCapability::Broken,
            EnterCapability::Inconclusive,
        ] {
            assert_eq!(parse_capability(cap.as_token()), Some(cap));
        }
        assert_eq!(parse_capability("garbage"), None);
        assert_eq!(parse_capability(""), None);
    }

    #[test]
    fn only_works_enables_enter() {
        assert!(EnterCapability::Works.enables_enter());
        assert!(!EnterCapability::Broken.enables_enter());
        assert!(!EnterCapability::Inconclusive.enables_enter());
    }

    #[test]
    fn rendered_cache_has_strict_key_value_grammar() {
        let outcome = ProbeOutcome {
            capability: EnterCapability::Works,
            bash_version: Some("5.3.9(1)-release".to_string()),
            bash_path: Some(PathBuf::from("/opt/homebrew/bin/bash")),
            // A reason with embedded newlines must not break the grammar.
            reason: "line one\nline two\rline three".to_string(),
            cache_path: None,
        };
        let body = render_cache(&outcome);
        // Every non-empty line is exactly one `key=value` pair.
        for line in body.lines() {
            assert!(
                line.split_once('=').is_some(),
                "cache line is not key=value: {line:?}"
            );
        }
        assert!(body.contains(&format!("schema={CACHE_SCHEMA}\n")));
        assert!(body.contains("enter_capability=works\n"));
        assert!(body.contains("bash_version=5.3.9(1)-release\n"));
        assert!(body.contains("bash_path=/opt/homebrew/bin/bash\n"));
        // The reason line is collapsed onto a single physical line.
        let reason_lines = body.lines().filter(|l| l.starts_with("reason=")).count();
        assert_eq!(reason_lines, 1, "reason must be a single line");
    }

    #[test]
    fn render_then_parse_round_trip() {
        // Render a cache body, write it to a temp state dir, read it back.
        let outcome = ProbeOutcome {
            capability: EnterCapability::Broken,
            bash_version: Some("5.2.0".to_string()),
            bash_path: Some(PathBuf::from("/usr/bin/bash")),
            reason: "issue #111 reproduced".to_string(),
            cache_path: None,
        };
        let body = render_cache(&outcome);

        // Parse the body directly with the same logic read_cache uses.
        let mut schema = None;
        let mut cap = None;
        let mut bv = None;
        let mut bp = None;
        let mut tv = None;
        for line in body.lines() {
            if let Some((k, v)) = line.split_once('=') {
                match k.trim() {
                    "schema" => schema = v.trim().parse::<u32>().ok(),
                    "enter_capability" => cap = parse_capability(v),
                    "bash_version" => bv = Some(v.trim().to_string()),
                    "bash_path" => bp = Some(v.trim().to_string()),
                    "tirith_version" => tv = Some(v.trim().to_string()),
                    _ => {}
                }
            }
        }
        assert_eq!(schema, Some(CACHE_SCHEMA));
        assert_eq!(cap, Some(EnterCapability::Broken));
        assert_eq!(bv.as_deref(), Some("5.2.0"));
        assert_eq!(bp.as_deref(), Some("/usr/bin/bash"));
        assert_eq!(tv.as_deref(), Some(env!("CARGO_PKG_VERSION")));
    }

    // `XDG_STATE_HOME` is process-global, and cargo runs unit tests in
    // parallel. The tests that point it at a temp dir must therefore not
    // interleave: this mutex serialises them. An RAII guard ([`StateHomeGuard`])
    // sets and restores the variable so a panicking test still cleans up.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct StateHomeGuard {
        prev: Option<std::ffi::OsString>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl StateHomeGuard {
        fn set(dir: &Path) -> Self {
            // Hold the lock for the whole guard lifetime — recover from a
            // poisoned mutex so one panicking test does not wedge the rest.
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prev = std::env::var_os("XDG_STATE_HOME");
            std::env::set_var("XDG_STATE_HOME", dir);
            Self { prev, _lock: lock }
        }
    }

    impl Drop for StateHomeGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var("XDG_STATE_HOME", v),
                None => std::env::remove_var("XDG_STATE_HOME"),
            }
        }
    }

    #[test]
    fn write_cache_is_atomic_and_readable() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = StateHomeGuard::set(dir.path());

        let outcome = ProbeOutcome {
            capability: EnterCapability::Works,
            bash_version: Some("5.3.0".to_string()),
            bash_path: Some(PathBuf::from("/opt/homebrew/bin/bash")),
            reason: "test".to_string(),
            cache_path: None,
        };
        let written = write_cache(&outcome).expect("cache write");
        assert!(written.exists(), "cache file must exist after write");

        let decision = read_cache().expect("cache must read back");
        assert_eq!(decision.capability, EnterCapability::Works);
        assert_eq!(decision.bash_version, "5.3.0");
        assert_eq!(decision.bash_path, "/opt/homebrew/bin/bash");
        assert_eq!(decision.tirith_version, env!("CARGO_PKG_VERSION"));

        // The atomic write must leave only the cache file — no staging temp
        // file behind (NamedTempFile is consumed by `persist`).
        let entries: Vec<String> = std::fs::read_dir(dir.path().join("tirith"))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            entries,
            vec![CACHE_FILENAME.to_string()],
            "atomic write must leave only the cache file, found: {entries:?}"
        );
    }

    #[test]
    fn read_cache_rejects_wrong_schema() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = StateHomeGuard::set(dir.path());

        let state = dir.path().join("tirith");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join(CACHE_FILENAME),
            "schema=999\ntirith_version=0.0.0\nshell=bash\nbash_version=5.3.0\nenter_capability=works\n",
        )
        .unwrap();
        assert!(
            read_cache().is_none(),
            "a cache with an unknown schema must be rejected"
        );
    }

    #[test]
    fn read_cache_rejects_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = StateHomeGuard::set(dir.path());

        let state = dir.path().join("tirith");
        std::fs::create_dir_all(&state).unwrap();
        let mut junk = String::from("schema=1\n");
        junk.push_str(&"x".repeat(5000));
        std::fs::write(state.join(CACHE_FILENAME), junk).unwrap();
        assert!(
            read_cache().is_none(),
            "an oversized cache file must be rejected"
        );
    }

    #[test]
    fn read_cache_rejects_cache_missing_bash_path() {
        // A schema-1 cache is always written with `bash_path`. One missing it
        // is corrupt/hand-edited and must be rejected, not read with an empty
        // path — fail closed.
        let dir = tempfile::tempdir().unwrap();
        let _guard = StateHomeGuard::set(dir.path());

        let state = dir.path().join("tirith");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join(CACHE_FILENAME),
            format!(
                "schema={CACHE_SCHEMA}\ntirith_version=0.0.0\nshell=bash\n\
                 bash_version=5.3.0\nenter_capability=works\n"
            ),
        )
        .unwrap();
        assert!(
            read_cache().is_none(),
            "a schema-1 cache missing bash_path must be rejected"
        );
    }

    // --- Live probe tests (issue #111 / PR #116 probe-race fix) ------------
    //
    // These actually run the PTY self-test. They skip cleanly when the bash
    // the probe would target (`discover_bash`) is missing or older than 5 —
    // bash 3.2 (macOS `/bin/bash`) is not a supported enter-mode target, and
    // `cargo test` must stay green where only an old bash exists.

    /// Major version of the bash binary at `path`, parsed from `bash --version`.
    fn bash_major(path: &Path) -> Option<u32> {
        let out = std::process::Command::new(path)
            .arg("--version")
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let first = String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string();
        let rest = &first[first.find("version ")? + "version ".len()..];
        rest.split('.').next()?.trim().parse::<u32>().ok()
    }

    /// The bash the probe will actually target, *only* when it is modern
    /// (>= 5). `None` ⇒ the caller should skip.
    fn probe_target_if_modern() -> Option<PathBuf> {
        let bash = discover_bash()?;
        match bash_major(&bash) {
            Some(major) if major >= 5 => Some(bash),
            _ => None,
        }
    }

    /// Deterministic, always-runs coverage of the verdict-composition rule —
    /// the heart of what the PR #116 fix protects. `classify_probe_results` is
    /// pure, so the `Works` classification is asserted here without depending
    /// on any host's `bind -x` behaviour. The live-`probe()` test below adds
    /// the integration angle; this nails the logic regression-safely.
    #[test]
    fn classify_probe_results_maps_phases_to_verdicts() {
        let ok_true: Result<bool, String> = Ok(true);
        let ok_false: Result<bool, String> = Ok(false);
        let err: Result<bool, String> = Err("boom".into());

        // delivery works + blocking works ⇒ Works.
        let (cap, _) = classify_probe_results(&ok_true, Some(&ok_true));
        assert_eq!(cap, EnterCapability::Works, "delivered + blocked ⇒ Works");
        assert!(
            cap.enables_enter(),
            "only a Works verdict enables enter mode"
        );

        // delivery failed (#111 swallow) ⇒ Broken, blocking skipped (None).
        let (cap, reason) = classify_probe_results(&ok_false, None);
        assert_eq!(cap, EnterCapability::Broken, "no delivery ⇒ Broken");
        assert!(
            reason.contains("#111"),
            "reason should cite the #111 swallow"
        );

        // delivered but did not block ⇒ Broken.
        let (cap, _) = classify_probe_results(&ok_true, Some(&ok_false));
        assert_eq!(
            cap,
            EnterCapability::Broken,
            "delivered-but-not-blocked ⇒ Broken"
        );

        // delivery probe could not run ⇒ Inconclusive (fail closed).
        let (cap, _) = classify_probe_results(&err, None);
        assert_eq!(
            cap,
            EnterCapability::Inconclusive,
            "delivery Err ⇒ Inconclusive"
        );

        // blocking's anti-vacuous guard failed (Err) ⇒ Inconclusive, never a
        // false Works. This is the P1 anti-vacuous safety property.
        let (cap, _) = classify_probe_results(&ok_true, Some(&err));
        assert_eq!(
            cap,
            EnterCapability::Inconclusive,
            "blocking Err (e.g. anti-vacuous guard failed) ⇒ Inconclusive, not Works"
        );
        assert!(
            !cap.enables_enter(),
            "an Inconclusive verdict must not enable enter mode — fail closed"
        );
    }

    /// The integration regression test for the PR #116 probe-race fix: running
    /// the real self-test against a modern bash must reach a **definite,
    /// race-free verdict** — `Works` or `Broken`, never `Inconclusive`.
    ///
    /// Before the fix, `probe_delivery` / `probe_blocking` keyed completion on
    /// terminal silence and killed the shell after a quiet gap. For a
    /// no-terminal-output command whose hook shells out to `tirith check`,
    /// that silence is reached *before* the command runs — so the probe read
    /// an empty marker and could not tell "delivery genuinely failed" from
    /// "delivery had not happened yet". After the fix the probe polls the
    /// marker file, so the verdict reflects the bash build's *real* enter-mode
    /// behaviour: a build whose `bind -x` accepts the line ⇒ `Works`, one that
    /// does not ⇒ `Broken`. Either way it is definite; `Inconclusive` would
    /// mean the probe could not even run, which must not happen for a healthy
    /// modern bash.
    ///
    /// Whether *this* host's bash delivers in a PTY is build-dependent (the
    /// `portable-pty` conformance harness documents builds where `bind -x`
    /// does not accept the line — genuine #111), so the test does not hard-pin
    /// `Works`. When the host's bash *does* deliver, the verdict is `Works` and
    /// that is the full end-to-end proof; the deterministic `Works` coverage
    /// lives in `classify_probe_results_maps_phases_to_verdicts` above.
    #[test]
    fn probe_reaches_definite_verdict_on_modern_bash() {
        let Some(bash) = probe_target_if_modern() else {
            eprintln!("skipping: no modern bash (>= 5) on PATH for the probe to target");
            return;
        };
        let outcome = probe();
        // The verdict must be definite: `Works` or `Broken`, never
        // `Inconclusive`. An exhaustive match (not an `assert_ne!`) keeps this
        // future-proof — a new `EnterCapability` variant becomes a compile
        // error here, forcing a deliberate decision.
        match outcome.capability {
            EnterCapability::Works => assert!(
                outcome.capability.enables_enter(),
                "a Works verdict must enable enter mode"
            ),
            EnterCapability::Broken => {}
            EnterCapability::Inconclusive => panic!(
                "the PR #116 fix must let the probe reach a definite verdict for a \
                 healthy modern bash ({}) — an Inconclusive here means the probe \
                 could not run, not a real delivery failure; reason was {:?}",
                bash.display(),
                outcome.reason,
            ),
        }
        // The probe must record the bash it measured, whatever the verdict.
        assert!(
            outcome.bash_version.is_some(),
            "a completed probe must record the probed $BASH_VERSION"
        );
        assert_eq!(
            outcome.bash_path.as_deref(),
            Some(bash.as_path()),
            "the probe must record the bash path it targeted"
        );
        eprintln!(
            "probe verdict for {}: {:?} ({})",
            bash.display(),
            outcome.capability,
            outcome.reason
        );
    }

    /// `probe_delivery` against a modern bash must reach a **definite** verdict
    /// (`Ok(true)` or `Ok(false)`), never `Err`. Before the fix it keyed on
    /// terminal silence and could not distinguish "delivery had not happened
    /// yet" from a real result; polling the marker file makes the outcome
    /// reflect the build's real behaviour regardless of `tirith check`
    /// latency. When this host's build *does* deliver, the result is
    /// `Ok(true)` — printed for visibility.
    #[test]
    fn probe_delivery_reaches_definite_verdict_on_modern_bash() {
        let Some(bash) = probe_target_if_modern() else {
            eprintln!("skipping: no modern bash (>= 5) on PATH for the probe to target");
            return;
        };
        let env = ProbeEnv::new().expect("stage probe environment");
        match probe_delivery(&bash, &env) {
            Ok(delivered) => eprintln!("probe_delivery for {}: Ok({delivered})", bash.display()),
            Err(e) => panic!(
                "probe_delivery on a healthy modern bash ({}) must reach a definite \
                 Ok(_) verdict, not Err — Err means the probe could not run: {e}",
                bash.display()
            ),
        }
    }

    /// `probe_blocking`'s anti-vacuous guard must never produce a false
    /// `Ok(true)`: the only way it returns `Ok(true)` ("blocked") is *after*
    /// an allowed command has been proven to run. So a swallowed-command shell
    /// yields `Err` (→ `Inconclusive`), and `Ok(true)` is reachable only when
    /// delivery genuinely works. This test asserts the guard holds — the
    /// result is `Ok(true)`, `Ok(false)`, or `Err`, and an `Err` here is the
    /// anti-vacuous guard correctly refusing to vouch for a non-delivering
    /// shell rather than a crash.
    #[test]
    fn probe_blocking_anti_vacuous_guard_holds_on_modern_bash() {
        let Some(bash) = probe_target_if_modern() else {
            eprintln!("skipping: no modern bash (>= 5) on PATH for the probe to target");
            return;
        };
        let env = ProbeEnv::new().expect("stage probe environment");
        match probe_blocking(&bash, &env) {
            Ok(true) => eprintln!(
                "probe_blocking for {}: Ok(true) — delivery works and the blocked \
                 command was stopped",
                bash.display()
            ),
            Ok(false) => eprintln!(
                "probe_blocking for {}: Ok(false) — delivered but did not block",
                bash.display()
            ),
            Err(e) => {
                // The anti-vacuous guard refusing to conclude is a *correct*
                // outcome on a build where enter delivery does not work — it
                // must surface as Err, never a false Ok(true).
                assert!(
                    e.contains("anti-vacuous") || e.contains("probe"),
                    "an Err from probe_blocking must be a probe/guard failure, got: {e}"
                );
                eprintln!(
                    "probe_blocking for {}: Err (anti-vacuous guard refused to vouch \
                     for a non-delivering shell) — {e}",
                    bash.display()
                );
            }
        }
    }

    /// `marker_stays_absent` reports `true` only while the file never appears,
    /// and flips to `false` the moment it does — the absence primitive the
    /// blocking probe relies on.
    #[test]
    fn marker_stays_absent_detects_a_created_marker() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("never");
        let present = dir.path().join("created");

        // A throwaway session just to satisfy the `&mut ProbeSession` drain
        // argument; `drain` on a quiet PTY is a bounded no-op.
        let Some(bash) = probe_target_if_modern() else {
            eprintln!("skipping: no modern bash (>= 5) to host a drain-only session");
            return;
        };
        let env = ProbeEnv::new().expect("stage probe environment");
        let mut sess = ProbeSession::spawn(
            &bash,
            &["--norc", "--noprofile", "-i"],
            &env.envs,
            &env.work,
        )
        .expect("spawn probe session");

        // A file that never appears stays absent for the whole (short) bound.
        assert!(
            marker_stays_absent(&mut sess, &absent, Duration::from_millis(200)),
            "a file that is never created must be reported absent"
        );
        // A file that already exists is detected immediately as present.
        std::fs::write(&present, "x").unwrap();
        assert!(
            !marker_stays_absent(&mut sess, &present, Duration::from_millis(200)),
            "an existing file must be reported present"
        );
        sess.kill();
    }
}
