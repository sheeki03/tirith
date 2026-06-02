//! Bash enter-mode delivery capability self-test (issue #111).
//!
//! The bash hook has two modes: **enter** (rebinds Enter via `bind -x`, can
//! block) and **preexec** (DEBUG-trap, warn-only). Enter is the only blocking
//! mode, but `bind -x` on `\C-m` in many builds runs the bound function without
//! accepting the line, so `PROMPT_COMMAND` never fires and the deferred command
//! is silently eaten (#111). Whether it accepts the line is a property of the
//! bash/readline BUILD, not the version, so tirith PROVES it empirically: spawn
//! a disposable bash through a PTY, source the real hook, and check that a typed
//! command runs and a blocked one is stopped.
//!
//! `tirith init` is `eval`'d on every shell startup and must stay fast, so the
//! heavy PTY probe runs only at `tirith setup`/`doctor` (timeout-bound) and
//! writes a `key=value` cache keyed by bash identity (version + path).
//! [`CACHE_SCHEMA`] (not the tirith version) invalidates across releases, since
//! enter delivery is a bash-build property. The hook reads the cache at startup
//! (init-safe) and selects enter only when proven; absent/stale/`broken` falls
//! back to preexec — the fail-closed safety floor.

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
/// Hard cap on waiting for a side-effect-only command's marker file (a
/// `printf >> marker` + allow-verdict `tirith check` print nothing, so
/// completion must be read from the filesystem, not terminal quiet). Generous
/// for CI yet bounded so a swallowed command fails fast.
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

/// Locate the bash to probe via `command -v bash` (the same bash the user
/// runs). Returned UNCANONICALIZED — the hook compares the cache against bash's
/// `$BASH` (also the user-facing path), and resolving symlinks would falsely
/// mismatch the Homebrew Cellar layout. `None` when bash is not on `PATH`.
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

/// Single-quote a path as one POSIX shell word (the temp dir from `$TMPDIR`
/// could contain a `'`, escaped as `'\''`).
fn posix_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

/// Materialise the embedded `assets::BASH_HOOK` into `dir` for probing (the
/// real hook bytes; reading the installed copy would couple to install layout).
fn write_probe_hook(dir: &Path) -> std::io::Result<PathBuf> {
    let path = dir.join("bash-hook.bash");
    std::fs::write(&path, crate::assets::BASH_HOOK)?;
    Ok(path)
}

/// `PATH` for the probe's shell: the running tirith's directory
/// ([`std::env::current_exe()`]) PREPENDED to the ambient `PATH`, so the hook's
/// `command tirith check` resolves to the binary under test (not a stale
/// installed copy, nor exit-127 → false `Broken`). Falls back to ambient `PATH`
/// if `current_exe()` has no parent. Mirrors `tests/pty_support`.
fn probe_path() -> String {
    let ambient = std::env::var("PATH").unwrap_or_default();
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf));
    match exe_dir {
        Some(dir) if ambient.is_empty() => dir.display().to_string(),
        Some(dir) => format!("{}:{}", dir.display(), ambient),
        None => ambient,
    }
}

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
        cmd.env("PATH", probe_path());
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

    /// Type `line` + carriage return — the byte Enter sends and the hook binds.
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

    /// Drain queued PTY output (blocking at most `slice`) so the reader channel
    /// can't fill while the probe waits on a filesystem marker.
    fn drain(&mut self, slice: Duration) {
        self.pump(slice);
    }

    /// Kill the child immediately. After a failed phase the readline buffer may
    /// hold a stale command, so tear down hard rather than nudge with another
    /// Enter (which could let a deferred command through → a false `works`).
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

/// Poll `marker` until it contains `needle` (`true`) or `timeout` elapses
/// (`false`), draining `sess` each tick so the PTY reader channel can't fill.
///
/// Polls the filesystem, not terminal quiet: a side-effect-only command and an
/// allow-verdict `tirith check` print nothing, so `wait_idle` would return
/// before delivery (caching a false `Broken`, or a false "blocked"). The marker
/// file is the ground truth. Mirrors `tests/pty_support::wait_for_marker`.
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
        sess.drain(MARKER_POLL);
    }
}

/// Wait the full `timeout` for `marker`, draining the PTY meanwhile, and report
/// whether it stayed ABSENT (an absence can't be confirmed early). Mirror of
/// [`wait_for_marker`] for an expected-absent side effect.
fn marker_stays_absent(sess: &mut ProbeSession, marker: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if marker.exists() {
            return false;
        }
        if Instant::now() >= deadline {
            return true;
        }
        sess.drain(MARKER_POLL);
    }
}

/// Hermetic probe-session environment, isolated from the developer's real
/// tirith state; holds the temp dir alive for the probe's duration.
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
            // Audit log off — the probe asserts on behaviour.
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

/// Probe whether enter mode DELIVERS an allowed command exactly once.
/// `Ok(true)` when the marker holds exactly one nonce, `Ok(false)` on delivery
/// failure (#111 reproduced), `Err` when the probe couldn't run. Completion is
/// read from the marker file (the no-output race on [`wait_for_marker`]).
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

    // Allowed, side-effect-only command (poll the marker, not terminal quiet).
    sess.send_line(&format!("printf '{nonce}\\n' >> {}", posix_quote(&marker)));
    let delivered = wait_for_marker(&mut sess, &marker, nonce, MARKER_TIMEOUT);
    // Tear down hard — a second Enter could flush a stale buffer and fake success.
    sess.kill();

    if !delivered {
        // Marker never gained the nonce: not delivered (#111 reproduced).
        return Ok(false);
    }
    // Re-read to assert it ran EXACTLY once (a double-delivery is just as broken).
    let body = std::fs::read_to_string(&marker).unwrap_or_default();
    Ok(count_occurrences(&body, nonce) == 1)
}

/// Probe whether enter mode actually BLOCKS a command tirith would block
/// (delivery alone is not enough). Types a blocked pipe-to-interpreter whose
/// payload, if it ran, would create a marker; the marker must stay absent.
///
/// The producer is a local `printf`, NOT `curl`: `printf 'true' | bash` hits the
/// same `pipe_to_interpreter` rule with no network, so an absent marker can't be
/// confused with "curl missing / network down" → a false `works`.
///
/// The empty-policy probe env ([`ProbeEnv::new`]) is correct: detection rules
/// fire UNCONDITIONALLY (a policy only adds allowlist/overlays — no allow-all
/// default), so the pipe is a HIGH block (exit 1) here too.
///
/// Anti-vacuous guard: a swallowed command also leaves no marker, so this phase
/// first delivers an ALLOWED command and polls its marker; only once that proves
/// delivery does it send the blocked command. If the allowed command never runs,
/// it returns `Err` (→ `Inconclusive`), never a false `Ok(true)`.
///
/// `Ok(true)` = allowed ran AND blocked did not; `Ok(false)` = blocked ran
/// anyway; `Err` = couldn't conclude (incl. the anti-vacuous case).
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

    // Anti-vacuous guard: an allowed command must actually run. If its marker
    // never appears the shell is swallowing commands, so bail to inconclusive
    // rather than report a false `blocked`.
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

    // Local pipe-to-interpreter (blocked by `pipe_to_interpreter`); the
    // `&& touch` runs only if the pipeline executed. Marker expected absent —
    // poll the full timeout to be sure.
    sess.send_line(&format!(
        "printf 'true' | bash && touch {}",
        posix_quote(&blocked_marker)
    ));
    let blocked = !marker_stays_absent(&mut sess, &blocked_marker, MARKER_TIMEOUT);
    sess.kill();

    // Guard passed + blocked marker absent ⇒ genuinely blocked.
    Ok(!blocked)
}

/// Combine the two probe phases into the final verdict + reason. Pure (no PTY)
/// so it is unit-testable: `Ok(true)`+`Ok(true)` ⇒ `Works`; delivery `Ok(false)`
/// (#111 swallow) or delivered-but-not-blocked ⇒ `Broken`; either phase `Err`
/// (incl. the anti-vacuous guard) ⇒ `Inconclusive` (fail closed). `blocking` is
/// `None` when delivery failed and blocking was skipped.
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

/// Run the full enter-mode self-test against whatever bash is on `PATH`. Never
/// panics or blocks unbounded; a missing bash / PTY failure / ambiguous output
/// all yield [`EnterCapability::Inconclusive`] ("do not use enter mode").
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

    // Phase 1 — delivery (non-delivery is #111).
    let delivery = probe_delivery(&bash, &env);
    // Phase 2 — blocking, only if delivery succeeded (a failed delivery already
    // settles the verdict as `Broken`).
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

/// Absolute path of the capability cache file.
pub fn cache_path() -> Option<PathBuf> {
    tirith_core::policy::state_dir().map(|d| d.join(CACHE_FILENAME))
}

/// Render the cache body as a strict `key=value` format (no JSON) the bash hook
/// can parse with its existing `IFS='='` loop — no `jq`/subprocess.
fn render_cache(outcome: &ProbeOutcome) -> String {
    let bash_version = outcome.bash_version.as_deref().unwrap_or("");
    // `command -v bash` output is a single newline-free path, safe as-is.
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
    // Reason is diagnostic only; strip newlines so it can't break the grammar.
    let reason = outcome.reason.replace(['\n', '\r'], " ");
    body.push_str(&format!("reason={reason}\n"));
    body
}

/// Atomically write the capability decision: a uniquely-named temp file renamed
/// over the target, so a concurrent reader sees the whole old or whole new file
/// and two writers never share a staging file. Returns the path on success.
pub fn write_cache(outcome: &ProbeOutcome) -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;

    let path = cache_path().ok_or("could not determine tirith state directory")?;
    let dir = path
        .parent()
        .ok_or("capability cache path has no parent directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;

    let body = render_cache(outcome);

    // `NamedTempFile` picks a collision-free name so concurrent writers never
    // clobber each other's staging file. Created 0o600; tighten explicitly.
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .map_err(|e| format!("create temp file in {}: {e}", dir.display()))?;
    tmp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod temp cache file: {e}"))?;
    tmp.write_all(body.as_bytes())
        .map_err(|e| format!("write temp cache file: {e}"))?;
    tmp.flush()
        .map_err(|e| format!("flush temp cache file: {e}"))?;
    // `persist` is the atomic same-fs rename; on failure the temp file is
    // dropped (and unlinked) immediately.
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

/// Read and validate the capability cache. `Some` only when the file exists,
/// parses, and its schema matches; `None` on any failure (fail closed). The
/// caller decides what to do with a stale tirith/bash version.
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
    // Every freshness-check field must be present; a missing one means a
    // corrupt/hand-edited file, so reject (`?`) and fail closed to preexec.
    Some(CachedDecision {
        capability: capability?,
        tirith_version: tirith_version?,
        bash_version: bash_version?,
        bash_path: bash_path?,
        reason,
    })
}

/// Whether a cached decision is fresh for the bash on `PATH`: both
/// `$BASH_VERSION` and the bash PATH must match (`bind -x` acceptance is a
/// build property). The tirith version is NOT part of freshness (schema is the
/// cross-version invalidator). MUST mirror the bash hook's
/// `_tirith_enter_capability_proven` so `doctor` and the hook agree.
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

/// Run the self-test and persist the result (entry point for `tirith
/// setup`/`doctor`). Always returns a [`ProbeOutcome`]; a cache-write failure
/// just leaves `cache_path` `None` (the hook keeps its safe default).
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
    fn probe_path_prepends_running_exe_directory() {
        // The PATH must lead with the running tirith's directory so the hook's
        // `command tirith` finds the binary under test, not a stale copy or
        // nothing (the F1 fix: a missing tirith → exit 127 → false `Broken`).
        let path = probe_path();
        let exe_dir = std::env::current_exe()
            .expect("current_exe must resolve in the test runner")
            .parent()
            .expect("the test binary has a parent directory")
            .display()
            .to_string();

        assert!(
            path.starts_with(&exe_dir),
            "probe PATH must START with the running exe's directory \
             (so it wins over any stale installed tirith); exe_dir={exe_dir:?}, path={path:?}"
        );
        // The running exe's directory must be a PATH *entry*, not just a
        // substring of some longer component.
        assert!(
            path.split(':').any(|seg| seg == exe_dir),
            "the running exe's directory must be a discrete PATH entry; path={path:?}"
        );
        // The ambient PATH must still be present (the shell needs coreutils,
        // bash, etc.) — prepended, never replaced.
        if let Ok(ambient) = std::env::var("PATH") {
            if !ambient.is_empty() {
                assert!(
                    path.ends_with(&ambient),
                    "the ambient PATH must be preserved after the prepended dir; \
                     ambient={ambient:?}, path={path:?}"
                );
            }
        }
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

    // `XDG_STATE_HOME` is process-global and cargo runs tests in parallel, so
    // this mutex serialises the tests that repoint it; `StateHomeGuard` restores
    // it (RAII) so a panicking test still cleans up.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct StateHomeGuard {
        prev: Option<std::ffi::OsString>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl StateHomeGuard {
        fn set(dir: &Path) -> Self {
            // Hold the lock for the guard's lifetime; recover from a poisoned
            // mutex so one panicking test does not wedge the rest.
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
    // These run the real PTY self-test; they skip cleanly when the target bash
    // is missing or < 5 (macOS's bash 3.2 is not a supported enter-mode target).

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

    /// The probe's target bash, only when modern (>= 5); `None` ⇒ skip.
    fn probe_target_if_modern() -> Option<PathBuf> {
        let bash = discover_bash()?;
        match bash_major(&bash) {
            Some(major) if major >= 5 => Some(bash),
            _ => None,
        }
    }

    /// Deterministic coverage of the pure verdict-composition rule (the PR #116
    /// heart), asserted without depending on any host's `bind -x` behaviour.
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

    /// PR #116 integration regression: the real self-test against a modern bash
    /// must reach a DEFINITE verdict (`Works` or `Broken`, never `Inconclusive`,
    /// which would mean the probe couldn't even run). After the fix the probe
    /// polls the marker file, so the verdict reflects the build's real `bind -x`
    /// behaviour. `Works` isn't hard-pinned (delivery is build-dependent).
    #[test]
    fn probe_reaches_definite_verdict_on_modern_bash() {
        let Some(bash) = probe_target_if_modern() else {
            eprintln!("skipping: no modern bash (>= 5) on PATH for the probe to target");
            return;
        };
        let outcome = probe();
        // Definite verdict only. An exhaustive match (not `assert_ne!`) makes a
        // future `EnterCapability` variant a compile error, forcing a decision.
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

    /// `probe_delivery` against a modern bash must reach a DEFINITE verdict
    /// (`Ok(true)`/`Ok(false)`), never `Err` — marker polling makes the outcome
    /// reflect the build's real behaviour regardless of `tirith check` latency.
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
    /// `Ok(true)`: it only returns `Ok(true)` AFTER an allowed command is proven
    /// to run, so a swallowing shell yields `Err` (→ `Inconclusive`). An `Err`
    /// here is the guard refusing to vouch, not a crash.
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
                // The guard refusing to conclude is correct where enter delivery
                // doesn't work — it must surface as Err, never a false Ok(true).
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

    /// `marker_stays_absent` is `true` only while the file never appears and
    /// flips `false` the moment it does — the blocking probe's absence primitive.
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
