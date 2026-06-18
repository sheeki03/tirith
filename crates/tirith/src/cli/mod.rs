use std::io::Write;

/// Output format for commands that support human and JSON output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum HumanJsonFormat {
    #[default]
    Human,
    Json,
}

impl HumanJsonFormat {
    /// Resolve the effective format from `--format` and the `--json` alias.
    /// Returns `(format, is_json)`.
    pub fn resolve(format: Option<Self>, json_flag: bool) -> (Self, bool) {
        let resolved = if json_flag {
            Self::Json
        } else {
            format.unwrap_or(Self::Human)
        };
        (resolved, resolved == Self::Json)
    }
}

/// Output format for scan, which additionally supports SARIF.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum HumanJsonSarifFormat {
    #[default]
    Human,
    Json,
    Sarif,
}

impl HumanJsonSarifFormat {
    /// Resolve the effective format from `--format`, `--json`, and `--sarif`.
    /// Returns `(format, is_json, is_sarif)`.
    pub fn resolve(format: Option<Self>, json_flag: bool, sarif_flag: bool) -> (Self, bool, bool) {
        let resolved = if json_flag {
            Self::Json
        } else if sarif_flag {
            Self::Sarif
        } else {
            format.unwrap_or(Self::Human)
        };
        (resolved, resolved == Self::Json, resolved == Self::Sarif)
    }
}

/// `true` when `TIRITH_OFFLINE` is set truthy (`1`/`true`/`yes`/`on`,
/// case-insensitive, trimmed). The env-var half of the CLI-wide offline switch
/// that every networked command routes through, so it behaves identically.
pub(crate) fn offline_env_active() -> bool {
    std::env::var("TIRITH_OFFLINE")
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Write `value` as pretty JSON + trailing newline to stdout through one locked
/// handle with fallible ops, so a broken pipe returns `false` rather than
/// panicking (a bare `println!` would). `ctx` is the stderr message on failure.
/// Returns `false` on a write failure so the caller can exit non-zero — a piped
/// consumer must not see truncated JSON paired with a success code.
pub(crate) fn write_json_stdout<T: serde::Serialize>(value: &T, ctx: &str) -> bool {
    let mut out = std::io::stdout().lock();
    if write_json_to(&mut out, value) {
        true
    } else {
        eprintln!("{ctx}");
        false
    }
}

/// Write `value` as pretty JSON + trailing newline to `out`; `false` if either
/// write fails. Factored out of [`write_json_stdout`] so the failure path is
/// unit-testable with a deliberately-failing writer.
fn write_json_to<W: Write, T: serde::Serialize>(out: &mut W, value: &T) -> bool {
    serde_json::to_writer_pretty(&mut *out, value).is_ok() && writeln!(out).is_ok()
}

#[cfg(test)]
mod write_json_tests {
    use super::write_json_to;

    /// A writer that always fails — models a broken pipe / closed stdout.
    struct FailingWriter;
    impl std::io::Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "broken pipe",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "broken pipe",
            ))
        }
    }

    #[test]
    fn write_json_to_reports_failure_on_write_error() {
        // A failed write returns `false` so callers exit non-zero rather than
        // pairing truncated JSON with a success code.
        let mut w = FailingWriter;
        assert!(
            !write_json_to(&mut w, &serde_json::json!({"signed": true})),
            "a writer that errors must make write_json_to return false"
        );
    }

    #[test]
    fn write_json_to_succeeds_to_a_buffer() {
        let mut buf: Vec<u8> = Vec::new();
        assert!(write_json_to(&mut buf, &serde_json::json!({"ok": 1})));
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("\"ok\""));
        assert!(s.ends_with('\n'), "a trailing newline must be written");
    }

    /// R12 #B: `write_file_atomic` lands content exactly, an overwrite FULLY
    /// replaces the prior content, and no temp file is left behind.
    #[test]
    fn write_file_atomic_writes_replaces_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commands.yaml");

        super::write_file_atomic(&path, b"first: true\n", true).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first: true\n");

        // Overwrite with SHORTER content: the rename fully replaces it (a
        // truncate-in-place could leave trailing old bytes).
        super::write_file_atomic(&path, b"x\n", true).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "x\n");

        // The only directory entry is the target — the temp file was consumed.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        assert_eq!(entries.len(), 1, "no temp file left behind: {entries:?}");
        assert_eq!(entries[0], path);
    }

    /// R17 #4: `write_file_atomic` through a SYMLINK must update the link's
    /// TARGET, not clobber the link with a regular file (the fix canonicalizes a
    /// symlinked destination and writes through). Unix-only.
    #[cfg(unix)]
    #[test]
    fn write_file_atomic_through_symlink_updates_target_not_link() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        // Real config in a SEPARATE subdir to prove the temp file lands next to
        // the resolved target (same filesystem), not the link.
        let target_dir = dir.path().join("real");
        std::fs::create_dir_all(&target_dir).unwrap();
        let target = target_dir.join("config.yaml");
        std::fs::write(&target, b"old: true\n").unwrap();

        let link = dir.path().join("config.yaml");
        symlink(&target, &link).unwrap();

        super::write_file_atomic(&link, b"new: true\n", true).unwrap();

        // The TARGET holds the new content; the symlink is INTACT, not clobbered.
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new: true\n");
        let link_meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(
            link_meta.file_type().is_symlink(),
            "the destination must remain a symlink, not be clobbered by a regular file"
        );
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            target,
            "the symlink must still point at the original target"
        );
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "new: true\n");

        // No temp file left dangling in EITHER directory.
        for d in [dir.path(), target_dir.as_path()] {
            let extra: Vec<_> = std::fs::read_dir(d)
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p != &link && p != &target && p != &target_dir)
                .collect();
            assert!(
                extra.is_empty(),
                "no temp file left behind in {d:?}: {extra:?}"
            );
        }
    }

    /// A DANGLING symlink (missing target) falls back to renaming onto the link
    /// path (a regular file) — `canonicalize` can't resolve it, so the
    /// write-through path is correctly NOT taken. Unix-only.
    #[cfg(unix)]
    #[test]
    fn write_file_atomic_dangling_symlink_falls_back() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let missing_target = dir.path().join("does-not-exist.yaml");
        let link = dir.path().join("config.yaml");
        symlink(&missing_target, &link).unwrap();

        super::write_file_atomic(&link, b"data: 1\n", true).unwrap();

        // The link path holds the content as a REGULAR file (fallback path).
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "data: 1\n");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_file(),
            "a dangling symlink falls back to a regular-file write at the link path"
        );
    }

    /// R13 #K: `overwrite=false` must NOT clobber an existing file — closing the
    /// TOCTOU between an `init` caller's `exists()` check and the publish (the
    /// file survives, write reports `AlreadyExists`); `overwrite=true` replaces it.
    #[test]
    fn write_file_atomic_no_clobber_preserves_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commands.yaml");

        // No-clobber create when absent: succeeds.
        super::write_file_atomic(&path, b"original\n", false).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "original\n");

        // No-clobber write when the file EXISTS: fails AlreadyExists, untouched.
        let err = super::write_file_atomic(&path, b"clobbered\n", false)
            .expect_err("no-clobber write over an existing file must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "original\n",
            "a failed no-clobber write must leave the existing file untouched"
        );

        // overwrite=true still replaces it, and leaves no temp file behind.
        super::write_file_atomic(&path, b"forced\n", true).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "forced\n");
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        assert_eq!(entries.len(), 1, "no temp file left behind: {entries:?}");
    }
}

/// Write `contents` to `path` atomically: a sibling temp file is written,
/// flushed, fsync'd, then renamed over `path`, so a reader (or a crash
/// mid-write) sees either the old or the complete new contents. Used by the
/// operator-facing config writers, NOT regenerable caches.
///
/// Durability (R12 #B): `sync_all()` BEFORE the rename, parent dir fsync AFTER.
///
/// Symlink destinations (R17 #4): `persist` would clobber a symlinked config, so
/// a symlink to an EXISTING target is canonicalized and written THROUGH (temp
/// file in the resolved target's dir to keep the rename atomic); a non-symlink /
/// dangling / unresolvable target falls back to renaming onto `path`.
///
/// `overwrite` (R13 #K): `true` → `persist` (replaces `dest`); `false` →
/// `persist_noclobber` (fails `AlreadyExists`), closing the TOCTOU between an
/// `init` caller's `exists()` check and this publish.
pub(crate) fn write_file_atomic(
    path: &std::path::Path,
    contents: &[u8],
    overwrite: bool,
) -> std::io::Result<()> {
    // Resolve a symlinked destination so we write THROUGH the link;
    // non-symlinks resolve to themselves.
    let dest = resolve_atomic_dest(path);
    let dir = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(std::path::PathBuf::from)
        // Bare filename: keep the temp file in cwd so the rename stays on the
        // same filesystem.
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let mut tmp = tempfile::NamedTempFile::new_in(&dir)?;
    tmp.write_all(contents)?;
    // sync_all() forces data + metadata to disk BEFORE the rename publishes it.
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    if overwrite {
        tmp.persist(&dest).map_err(|e| e.error)?;
    } else {
        tmp.persist_noclobber(&dest).map_err(|e| e.error)?;
    }
    // fsync the parent so the new name→inode entry survives a crash. persist
    // already succeeded, so a dir-fsync failure is LOGGED, not propagated
    // (R13 #5). No-op on non-Unix.
    tirith_core::util::fsync_parent_dir_logged(&dest, "atomic file write");
    Ok(())
}

/// Resolve the effective rename target for [`write_file_atomic`]: a symlink to
/// an existing target → its canonicalized target (write THROUGH the link);
/// otherwise `path` unchanged.
pub(crate) fn resolve_atomic_dest(path: &std::path::Path) -> std::path::PathBuf {
    tirith_core::util::resolve_symlink_target(path)
}

/// Reconstruct a shell command STRING from already-split argv, PRESERVING word
/// boundaries (R13b). Shell-significant args are single-quoted, safe args emitted
/// bare. Fed to the engine (`commands check`): a naive `argv.join(" ")` lets a
/// multi-word arg re-split into separate tokens and skew the verdict (e.g.
/// `git commit -m "fix; rm -rf /"` would look like a `;`-separated `rm`).
pub(crate) fn shell_join(argv: &[String]) -> String {
    // A SINGLE arg is already a complete command string (the user quoted the
    // whole command) — return it verbatim; quoting would hide its
    // pipes/URLs/substitutions from the engine. Quote-as-needed only kicks in for
    // MULTIPLE argv elements where word boundaries would otherwise be lost.
    if argv.len() == 1 {
        return argv[0].clone();
    }
    fn needs_quoting(s: &str) -> bool {
        // Bare only for a conservative shell-safe set; anything else is quoted.
        s.is_empty()
            || !s.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(
                        b,
                        b'-' | b'_' | b'.' | b'/' | b':' | b'=' | b'@' | b',' | b'+' | b'%'
                    )
            })
    }
    argv.iter()
        .map(|a| {
            if needs_quoting(a) {
                format!("'{}'", a.replace('\'', "'\\''"))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Closest candidate by Levenshtein distance, or `None` if none is within
/// `max_distance`.
pub fn suggest_closest<'a>(
    query: &str,
    candidates: &[&'a str],
    max_distance: usize,
) -> Option<&'a str> {
    candidates
        .iter()
        .map(|c| (*c, tirith_core::util::levenshtein(query, c)))
        .filter(|(_, d)| *d <= max_distance)
        .min_by_key(|(_, d)| *d)
        .map(|(c, _)| c)
}

/// Prompt for confirmation. `true` only if `--yes`, or stderr is a TTY and the
/// user types y/yes. `false` in non-interactive contexts without `--yes`, so
/// destructive operations are never silently approved.
pub fn confirm(prompt: &str, yes: bool) -> bool {
    if yes {
        return true;
    }
    if !is_terminal::is_terminal(std::io::stderr()) {
        eprintln!("tirith: skipping prompt (not a TTY — use --yes to auto-approve)");
        return false;
    }
    eprint!("{prompt} [y/N] ");
    // Best-effort flush; read_line still works if it fails.
    let _ = std::io::stderr().flush();
    let mut input = String::new();
    match std::io::stdin().read_line(&mut input) {
        Ok(_) => matches!(input.trim(), "y" | "Y" | "yes" | "Yes"),
        Err(e) => {
            eprintln!("tirith: could not read confirmation input: {e}");
            false
        }
    }
}

pub mod agent;
pub mod ai;
pub mod aliases;
pub mod audit;
pub mod baseline;
#[cfg(unix)]
pub mod bash_capability;
pub mod browser;
pub mod browser_host;
pub mod canary;
pub mod check;
pub mod checkpoint;
pub mod clipboard;
pub mod codespaces;
pub mod command_card;
pub mod commands;
pub mod completions;
pub mod context;
pub mod daemon;
pub mod dashboard;
pub mod devcontainer;
pub mod diff;
pub mod doctor;
pub mod ecosystem;
pub mod env_guard;
pub mod exec;
pub mod explain;
pub mod fix;
pub mod gateway;
pub mod hook_event;
pub mod hooks;
pub mod hygiene;
pub mod iac;
pub mod incident;
pub mod init;
pub mod install;
pub mod intent;
pub mod lab;
pub mod last_trigger;
pub mod license_cmd;
pub mod logs;
pub mod lsp;
pub mod manpage;
pub mod mcp;
pub mod mcp_server;
pub mod onboard;
pub mod output_guard;
pub mod package;
pub mod paste;
pub mod path;
pub mod pending;
pub mod persistence;
pub mod policy;
pub mod preview;
pub mod prompt_status;
pub mod receipt;
pub mod rule;
pub mod scan;
pub mod score;
pub mod secret;
pub mod selfupdate;
pub mod share;
pub mod ssh;
pub mod status;
pub mod sudo;
pub mod taint;
pub mod temp_run;
pub mod threatdb_cmd;
pub mod trust;
pub mod view;
pub mod visual_audit;
pub mod warnings;
pub mod why;
pub mod yaml;

#[cfg(unix)]
pub mod fetch;
#[cfg(unix)]
pub mod run;
pub mod setup;

#[cfg(test)]
pub(crate) mod test_harness;

#[cfg(any(test, windows))]
fn trim_wrapping_quotes(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

#[cfg(any(test, windows))]
fn parse_shim_target(contents: &str) -> Option<std::path::PathBuf> {
    contents.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        if !key.trim().eq_ignore_ascii_case("path") {
            return None;
        }
        let value = trim_wrapping_quotes(value.trim());
        if value.is_empty() {
            return None;
        }
        Some(std::path::PathBuf::from(value))
    })
}

#[cfg(any(test, windows))]
fn resolve_shim_target(path: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut sidecar = path.to_path_buf();
    sidecar.set_extension("shim");

    let contents = std::fs::read_to_string(&sidecar).ok()?;
    let target = parse_shim_target(&contents)?;
    let target = if target.is_relative() {
        sidecar.parent()?.join(target)
    } else {
        target
    };

    target.canonicalize().ok().or(Some(target))
}

/// Map (`OS`, `ARCH`) to the platform-specific npm package name under the
/// `@sheeki03/` scope. `None` on unsupported Unix targets. Mirrors
/// `npm/tirith/bin/tirith` exactly.
#[cfg(unix)]
fn npm_platform_package() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("tirith-linux-x64"),
        ("linux", "aarch64") => Some("tirith-linux-arm64"),
        ("macos", "x86_64") => Some("tirith-darwin-x64"),
        ("macos", "aarch64") => Some("tirith-darwin-arm64"),
        _ => None,
    }
}

/// If `path` is the official tirith npm wrapper
/// (`…/node_modules/tirith/bin/tirith`), resolve to the platform-package native
/// binary. The wrapper `execFileSync`s the native binary, so naive
/// `canonicalize()` makes them look like different installs and triggers a
/// false-positive shadow warning (issue #105).
#[cfg(unix)]
fn resolve_npm_wrapper_target(path: &std::path::Path) -> Option<std::path::PathBuf> {
    use std::path::Component;

    // Canonicalize FIRST — the PATH entry is typically a symlink, and the layout
    // check must run on the resolved target.
    let canonical = path.canonicalize().ok()?;

    // The last four components must be exactly `node_modules`, `tirith`, `bin`,
    // `tirith`; anything else falls through to the existing behavior.
    let components: Vec<Component> = canonical.components().collect();
    if components.len() < 4 {
        return None;
    }
    let tail = &components[components.len() - 4..];
    let expected = [
        Component::Normal("node_modules".as_ref()),
        Component::Normal("tirith".as_ref()),
        Component::Normal("bin".as_ref()),
        Component::Normal("tirith".as_ref()),
    ];
    if tail != expected {
        return None;
    }

    // `node_modules` is three parents up from `…/tirith/bin/tirith`.
    let node_modules = canonical.ancestors().nth(3)?;

    let platform = npm_platform_package()?;
    let native = node_modules
        .join("@sheeki03")
        .join(platform)
        .join("bin")
        .join("tirith");

    if !native.is_file() {
        return None;
    }
    native.canonicalize().ok()
}

fn resolve_effective_tirith_target(path: &std::path::Path) -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    if let Some(target) = resolve_shim_target(path) {
        return Some(target);
    }

    #[cfg(unix)]
    if let Some(target) = resolve_npm_wrapper_target(path) {
        return Some(target);
    }

    path.canonicalize().ok()
}

pub fn tirith_path_lookup_command() -> &'static str {
    #[cfg(unix)]
    {
        "which -a tirith"
    }
    #[cfg(not(unix))]
    {
        "where.exe tirith"
    }
}

/// Resolve all `tirith` executables on PATH via the shell's own resolution —
/// the paths the shell would actually execute, not just filesystem entries.
pub fn resolve_tirith_on_path() -> Vec<std::path::PathBuf> {
    let output = {
        #[cfg(unix)]
        {
            std::process::Command::new("sh")
                .args(["-c", "which -a tirith 2>/dev/null"])
                .output()
        }
        #[cfg(not(unix))]
        {
            std::process::Command::new("where.exe")
                .arg("tirith")
                .output()
        }
    };

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(std::path::PathBuf::from)
        .collect()
}

/// Find `tirith` executables on PATH that aren't the current binary, deduped by
/// logical target path so duplicate PATH entries and shim aliases don't repeat.
pub fn find_shadow_binaries() -> Vec<String> {
    let our_canonical = std::env::current_exe()
        .ok()
        .and_then(|p| resolve_effective_tirith_target(&p));

    let mut seen = std::collections::HashSet::new();
    let mut shadows = Vec::new();

    for path in resolve_tirith_on_path() {
        let canonical = resolve_effective_tirith_target(&path);
        // Skip if it resolves to our own binary.
        if let (Some(ours), Some(ref theirs)) = (&our_canonical, &canonical) {
            if ours == theirs {
                continue;
            }
        }
        // Dedup by canonical path (display path for unresolvable entries).
        let key = canonical
            .map(|c| c.display().to_string())
            .unwrap_or_else(|| path.display().to_string());
        if seen.insert(key) {
            shadows.push(path.display().to_string());
        }
    }
    shadows
}

/// Process-global quiet flag, set once from the root `--quiet` / `TIRITH_QUIET`.
/// Low-value advisory lines route through [`note`]; security notices, verdicts,
/// errors, and JSON do NOT, so quiet never hides anything that matters.
static QUIET: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Whether `TIRITH_QUIET`'s value is truthy. Pure helper over the raw env value so
/// the `1`/`true` (case-insensitive) parsing is unit-testable without process globals.
fn quiet_from_env(val: Option<&str>) -> bool {
    matches!(val, Some(v) if v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Set once in `main()` right after clap parse. `--quiet` OR `TIRITH_QUIET=1/true`.
pub fn init_quiet(flag: bool) {
    let env = quiet_from_env(std::env::var("TIRITH_QUIET").ok().as_deref());
    let _ = QUIET.set(flag || env);
}

/// True when LOW-VALUE advisory output should be suppressed. Defaults to `false`
/// (fail-safe: if `init_quiet` somehow never ran, we never accidentally hide output).
pub fn is_quiet() -> bool {
    *QUIET.get().unwrap_or(&false)
}

/// Print a LOW-VALUE advisory line to stderr unless `--quiet`. Use for clean
/// "no issues" lines, tips, shadow/session footers, the onboard hint — NEVER for
/// errors, verdicts, or security notices (degraded protection / repo-policy
/// neutralization), which must always be visible.
pub fn note(msg: impl std::fmt::Display) {
    if !is_quiet() {
        eprintln!("{msg}");
    }
}

/// Read at most `max` bytes from stdin — the shared cap used by `check`/`paste`
/// when consuming piped input. Returns the raw bytes; callers decode lossily.
///
/// FAILS CLOSED on over-limit input: it reads ONE byte past `max` so an oversized
/// stream is DETECTABLE, then returns an error rather than silently truncating.
/// Silent truncation is unsafe here — a command analyzed only up to `max` could
/// drop a dangerous tail (e.g. `... | sh` after a 1 MiB prefix) and read as
/// benign. Mirrors `paste`'s explicit over-limit rejection.
pub fn read_stdin_capped(max: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut buf = Vec::new();
    std::io::stdin().take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("input exceeds the {max}-byte limit"),
        ));
    }
    Ok(buf)
}

/// Gate decision for [`warn_repo_policy_neutralized`]: emit the once-per-session notice
/// only for a REPO-scoped policy (the only untrusted scope) that actually had weakening
/// fields dropped, and only when this session hasn't been warned yet (marker absent).
/// Pure so the matrix is unit-testable without `state_dir()` I/O or process globals.
fn should_warn_neutralized(
    scope: tirith_core::policy::PolicyScope,
    neutralized_fields: &[&str],
    marker_exists: bool,
) -> bool {
    scope == tirith_core::policy::PolicyScope::Repo
        && !neutralized_fields.is_empty()
        && !marker_exists
}

/// Surface invalid `injection_seeds_custom` regexes once to stderr on the
/// paste/check CLI path. The engine compiles these seeds internally on the paste
/// path but is a library and does not print, so it drops the bad list; a seed that
/// passes the lenient `tirith policy validate` shape check yet fails the real
/// compile would otherwise be silently skipped with no operator feedback. Mirrors
/// the view/lsp/gateway seams. stderr is safe: `tirith check`/`paste` write their
/// verdict to stdout.
pub fn warn_bad_injection_seeds(policy: &tirith_core::policy::Policy) {
    let (_seeds, bad) =
        tirith_core::rules::prompt_injection::compile_seeds(&policy.injection_seeds_custom);
    for (pattern, error) in &bad {
        eprintln!("tirith: warning: invalid injection_seeds_custom regex {pattern:?}: {error}");
    }
}

/// Once per shell SESSION (per policy), tell the operator that a repo-scoped policy
/// had WEAKENING fields neutralized (F9 — a repo may tighten, never weaken). A repo
/// author who sets `allowlist`/`severity_overrides` otherwise gets zero feedback that
/// it was ignored. This is a SECURITY notice: printed unconditionally, NOT routed
/// through `note()`/`--quiet`. `tirith policy effective` always lists the full drop
/// set regardless of this throttle.
pub fn warn_repo_policy_neutralized(policy: &tirith_core::policy::Policy) {
    if policy.scope != tirith_core::policy::PolicyScope::Repo
        || policy.neutralized_fields.is_empty()
    {
        return;
    }
    // Throttle by SESSION id (so it re-warns in every new shell) + policy path —
    // NOT by file mtime, which would suppress the warning across new shells.
    let Some(dir) = tirith_core::policy::state_dir().map(|d| d.join("policy-weakening-warned"))
    else {
        return;
    };
    let session = tirith_core::session::resolve_session_id();
    let path_key = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        policy.path.hash(&mut h);
        format!("{:016x}", h.finish())
    };
    let marker = dir.join(format!("{session}-{path_key}"));
    if !should_warn_neutralized(policy.scope, &policy.neutralized_fields, marker.exists()) {
        return;
    }
    eprintln!(
        "tirith: this repo's .tirith/policy.yaml is tightening-only — the following \
         weakening field(s) were ignored: {}.\n  See the resolved policy with \
         `tirith policy effective`.",
        policy.neutralized_fields.join(", ")
    );
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(&marker, b"");
}

#[cfg(test)]
mod tests {
    use super::{
        parse_shim_target, quiet_from_env, resolve_shim_target, shell_join, should_warn_neutralized,
    };
    use std::fs;
    use std::path::PathBuf;
    use tirith_core::policy::PolicyScope;

    #[test]
    fn shell_join_preserves_argv_boundaries() {
        let q = |v: &[&str]| shell_join(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        // A SINGLE arg is a pre-formed command string — returned VERBATIM.
        assert_eq!(q(&["curl https://x.sh | sh"]), "curl https://x.sh | sh");
        assert_eq!(q(&["$(rm -rf /)"]), "$(rm -rf /)");
        // Shell-safe args round-trip bare.
        assert_eq!(q(&["echo", "hello", "world"]), "echo hello world");
        assert_eq!(
            q(&["curl", "https://example.com/x.sh"]),
            "curl https://example.com/x.sh"
        );
        // An arg with shell-significant bytes is single-quoted so it stays one token.
        assert_eq!(
            q(&["git", "commit", "-m", "fix; rm -rf /"]),
            "git commit -m 'fix; rm -rf /'"
        );
        // Embedded single quotes escaped as '\''; empty arg shown as ''.
        assert_eq!(q(&["echo", "it's"]), "echo 'it'\\''s'");
        assert_eq!(q(&["x", ""]), "x ''");
    }

    #[test]
    fn parse_shim_target_accepts_unquoted_values() {
        let parsed =
            parse_shim_target("path = C:\\Users\\alice\\scoop\\apps\\tirith\\current\\tirith.exe");
        assert_eq!(
            parsed,
            Some(PathBuf::from(
                "C:\\Users\\alice\\scoop\\apps\\tirith\\current\\tirith.exe"
            ))
        );
    }

    #[test]
    fn parse_shim_target_accepts_case_insensitive_quoted_values() {
        let parsed = parse_shim_target("ARGS = --help\r\nPATH = \"/tmp/tirith.exe\"\r\n");
        assert_eq!(parsed, Some(PathBuf::from("/tmp/tirith.exe")));
    }

    #[test]
    fn resolve_shim_target_uses_absolute_target_from_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("apps/tirith/current/tirith.exe");
        let shim = dir.path().join("shims/tirith.exe");

        fs::create_dir_all(real.parent().unwrap()).unwrap();
        fs::create_dir_all(shim.parent().unwrap()).unwrap();
        fs::write(&real, b"real").unwrap();
        fs::write(&shim, b"shim").unwrap();
        fs::write(
            shim.with_extension("shim"),
            format!("path = \"{}\"\n", real.display()),
        )
        .unwrap();

        assert_eq!(
            resolve_shim_target(&shim).unwrap().canonicalize().unwrap(),
            real.canonicalize().unwrap()
        );
    }

    #[test]
    fn resolve_shim_target_uses_relative_target_from_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("apps/tirith/current/tirith.exe");
        let shim = dir.path().join("shims/tirith.exe");

        fs::create_dir_all(real.parent().unwrap()).unwrap();
        fs::create_dir_all(shim.parent().unwrap()).unwrap();
        fs::write(&real, b"real").unwrap();
        fs::write(&shim, b"shim").unwrap();
        fs::write(
            shim.with_extension("shim"),
            "path = ../apps/tirith/current/tirith.exe\n",
        )
        .unwrap();

        assert_eq!(
            resolve_shim_target(&shim).unwrap().canonicalize().unwrap(),
            real.canonicalize().unwrap()
        );
    }

    #[cfg(unix)]
    mod npm_wrapper_tests {
        use super::super::{npm_platform_package, resolve_npm_wrapper_target};
        use std::fs;
        use std::os::unix::fs::symlink;

        /// Build the canonical npm layout under `root` →
        /// `Some((symlink-on-PATH, native-binary))`, or `None` on Unix targets
        /// the npm distribution doesn't ship for (so tests early-skip).
        fn build_layout(
            root: &std::path::Path,
        ) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
            let platform = npm_platform_package()?;

            let wrapper_dir = root.join("lib/node_modules/tirith/bin");
            let native_dir = root
                .join("lib/node_modules/@sheeki03")
                .join(platform)
                .join("bin");
            let bin_dir = root.join("bin");

            fs::create_dir_all(&wrapper_dir).unwrap();
            fs::create_dir_all(&native_dir).unwrap();
            fs::create_dir_all(&bin_dir).unwrap();

            let wrapper = wrapper_dir.join("tirith");
            let native = native_dir.join("tirith");
            fs::write(&wrapper, b"#!/usr/bin/env node\n// wrapper").unwrap();
            fs::write(&native, b"\x7fELF native bytes").unwrap();

            let symlinked = bin_dir.join("tirith");
            symlink(&wrapper, &symlinked).unwrap();

            Some((symlinked, native))
        }

        /// The bug path: PATH entry → symlink → wrapper. Fails without the
        /// canonicalize-first step in `resolve_npm_wrapper_target`.
        #[test]
        fn resolve_npm_wrapper_target_via_symlink_resolves_native_binary() {
            let dir = tempfile::tempdir().unwrap();
            let Some((symlinked, native)) = build_layout(dir.path()) else {
                eprintln!("skipping: npm distribution doesn't ship for this Unix target");
                return;
            };

            assert_eq!(
                resolve_npm_wrapper_target(&symlinked),
                Some(native.canonicalize().unwrap())
            );
        }

        #[test]
        fn resolve_npm_wrapper_target_resolves_native_binary_when_called_with_wrapper_path() {
            let dir = tempfile::tempdir().unwrap();
            let Some((_symlinked, native)) = build_layout(dir.path()) else {
                eprintln!("skipping: npm distribution doesn't ship for this Unix target");
                return;
            };

            let wrapper = dir.path().join("lib/node_modules/tirith/bin/tirith");
            assert_eq!(
                resolve_npm_wrapper_target(&wrapper),
                Some(native.canonicalize().unwrap())
            );
        }

        #[test]
        fn resolve_npm_wrapper_target_returns_none_when_native_missing() {
            // Wrapper layout WITHOUT the platform sibling (broken install) →
            // None, so the existing canonicalize path still warns.
            let dir = tempfile::tempdir().unwrap();
            let wrapper_dir = dir.path().join("lib/node_modules/tirith/bin");
            fs::create_dir_all(&wrapper_dir).unwrap();
            let wrapper = wrapper_dir.join("tirith");
            fs::write(&wrapper, b"wrapper").unwrap();

            assert_eq!(resolve_npm_wrapper_target(&wrapper), None);
        }

        #[test]
        fn resolve_npm_wrapper_target_ignores_non_npm_paths() {
            // Pip-style layout (outside any node_modules) → None, preserving the
            // documented PyPI conflict warning.
            let dir = tempfile::tempdir().unwrap();
            let pip_dir = dir.path().join("local/bin");
            fs::create_dir_all(&pip_dir).unwrap();
            let pip = pip_dir.join("tirith");
            fs::write(&pip, b"pip-installed").unwrap();

            assert_eq!(resolve_npm_wrapper_target(&pip), None);
        }
    }

    #[test]
    fn should_warn_neutralized_only_fires_for_repo_with_drops_and_no_marker() {
        // Repo scope + something neutralized + no session marker → warn.
        assert!(should_warn_neutralized(
            PolicyScope::Repo,
            &["allowlist"],
            false
        ));
        // Already warned this session (marker present) → silent.
        assert!(!should_warn_neutralized(
            PolicyScope::Repo,
            &["allowlist"],
            true
        ));
        // A non-repo (trusted) scope is never sanitized, so never warned — even with
        // a (would-be) drop set and no marker.
        assert!(!should_warn_neutralized(
            PolicyScope::Org,
            &["allowlist"],
            false
        ));
        // Repo scope but nothing was neutralized → nothing to report.
        assert!(!should_warn_neutralized(PolicyScope::Repo, &[], false));
    }

    #[test]
    fn quiet_from_env_recognizes_only_truthy_values() {
        for v in ["1", "true", "TRUE", "True"] {
            assert!(quiet_from_env(Some(v)), "{v:?} should be truthy");
        }
        for v in ["0", "", "yes", "false", "01", " 1"] {
            assert!(!quiet_from_env(Some(v)), "{v:?} should NOT be truthy");
        }
        assert!(!quiet_from_env(None), "unset TIRITH_QUIET is not quiet");
    }
}
