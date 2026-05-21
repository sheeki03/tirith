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
/// "Output settled" gap — no new bytes for this long means the shell finished.
const QUIET_GAP: Duration = Duration::from_millis(600);

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

    /// Wait until output has been quiet for `quiet`, bounded by `max`.
    fn wait_idle(&mut self, quiet: Duration, max: Duration) {
        let hard = Instant::now() + max;
        loop {
            let before = self.buf.len();
            self.pump(quiet);
            if self.buf.len() == before || Instant::now() >= hard {
                return;
            }
        }
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
/// Returns `Ok(true)` when the marker file holds exactly one line after the
/// command + Enter, `Ok(false)` when delivery failed (#111 reproduced), and
/// `Err` when the probe could not run to a verdict.
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
    sess.wait_idle(QUIET_GAP, PHASE_TIMEOUT);

    // An allowed, side-effect-only command: append one nonce line to a marker.
    sess.send_line(&format!("printf '{nonce}\\n' >> {}", posix_quote(&marker)));
    sess.wait_idle(QUIET_GAP, PHASE_TIMEOUT);
    // Tear the session down hard — never send a second Enter, which (in the
    // broken case) could flush a stale readline buffer and fake a success.
    sess.kill();

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
/// Returns `Ok(true)` when the command was blocked (marker absent), `Ok(false)`
/// when it executed anyway, and `Err` when the probe could not run.
fn probe_blocking(bash: &Path, env: &ProbeEnv) -> Result<bool, String> {
    let marker = env.work.join("block_marker");

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
    sess.wait_idle(QUIET_GAP, PHASE_TIMEOUT);

    // A purely local pipe-to-interpreter — `printf 'true' | bash` — which
    // tirith blocks via the `pipe_to_interpreter` rule. The `&& touch` clause
    // runs only if the pipeline executed; tirith must block before that. Using
    // a local producer (not `curl`) keeps the verdict independent of network
    // reachability — see the doc comment above.
    sess.send_line(&format!(
        "printf 'true' | bash && touch {}",
        posix_quote(&marker)
    ));
    sess.wait_idle(QUIET_GAP, PHASE_TIMEOUT);
    sess.kill();

    Ok(!marker.exists())
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
    match probe_delivery(&bash, &env) {
        Ok(true) => {}
        Ok(false) => {
            return ProbeOutcome {
                capability: EnterCapability::Broken,
                bash_version,
                bash_path: Some(bash),
                reason: "enter mode did not deliver an allowed command (issue #111)".into(),
                cache_path: None,
            };
        }
        Err(e) => {
            return ProbeOutcome {
                capability: EnterCapability::Inconclusive,
                bash_version,
                bash_path: Some(bash),
                reason: format!("delivery probe could not run: {e}"),
                cache_path: None,
            };
        }
    }

    // Phase 2 — blocking. Delivery alone is not enough: enter mode must also be
    // able to stop a dangerous command.
    match probe_blocking(&bash, &env) {
        Ok(true) => ProbeOutcome {
            capability: EnterCapability::Works,
            bash_version,
            bash_path: Some(bash),
            reason: "enter mode delivers an allowed command and blocks a blocked one".into(),
            cache_path: None,
        },
        Ok(false) => ProbeOutcome {
            capability: EnterCapability::Broken,
            bash_version,
            bash_path: Some(bash),
            reason: "enter mode delivered but failed to block a blocked command".into(),
            cache_path: None,
        },
        Err(e) => ProbeOutcome {
            capability: EnterCapability::Inconclusive,
            bash_version,
            bash_path: Some(bash),
            reason: format!("blocking probe could not run: {e}"),
            cache_path: None,
        },
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
}
