use std::io::Write;

/// Output format for commands that support human and JSON output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum HumanJsonFormat {
    #[default]
    Human,
    Json,
}

impl HumanJsonFormat {
    /// Resolve the effective format from an optional `--format` value and a
    /// `--json` boolean alias.  Returns `(format, is_json)` so callers can
    /// destructure both in one step.
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
    /// Resolve the effective format from optional `--format`, `--json`, and
    /// `--sarif` boolean aliases.  Returns `(format, is_json, is_sarif)`.
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

/// `true` when the `TIRITH_OFFLINE` environment variable is set to a truthy
/// value (`1`, `true`, `yes`, `on`, case-insensitive, trimmed). An empty value,
/// an unset variable, or any other value is treated as "not offline".
///
/// This is the env-var half of the CLI-wide offline switch. The commands that
/// have a networked `--online` opt-in (`package risk`, `ecosystem scan`,
/// `install`) and the background threat-DB refresh all route through this one
/// helper so the offline switch behaves identically everywhere.
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

/// Write `value` as pretty JSON to stdout, followed by a trailing newline.
///
/// The JSON body and the newline are both written through one locked stdout
/// handle with fallible ops, so a broken pipe (SIGPIPE → `BrokenPipe`) is
/// reported as `false` rather than panicking — a bare `println!()` for the
/// newline would panic. `ctx` is the command-prefixed message printed to
/// stderr on failure (e.g. `"tirith scan: failed to write JSON output"`).
///
/// Returns `false` on a write failure so the caller can exit non-zero — a
/// piped consumer must not see truncated JSON paired with a success code.
pub(crate) fn write_json_stdout<T: serde::Serialize>(value: &T, ctx: &str) -> bool {
    let mut out = std::io::stdout().lock();
    if write_json_to(&mut out, value) {
        true
    } else {
        eprintln!("{ctx}");
        false
    }
}

/// Write `value` as pretty JSON followed by a trailing newline to `out`.
/// Returns `false` if either the JSON body or the newline failed to write.
/// Factored out of [`write_json_stdout`] so the failure path is unit-testable
/// with a deliberately-failing writer (the real stdout cannot be made to fail
/// deterministically across platforms).
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
        // The contract the `command-card sign/verify/fetch` (and canary)
        // callers rely on: a failed write returns `false` so they can exit
        // non-zero rather than pairing truncated JSON with a success code.
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

    /// CodeRabbit R12 #B: `write_file_atomic` lands content exactly, an overwrite
    /// FULLY replaces the prior content (no truncate-in-place), and no temp file
    /// is left behind. fsync is not directly observable in a unit test; the
    /// content-integrity + no-leftover-temp assertions cover the userspace-visible
    /// post-condition and the sync is exercised on every call (a sync error would
    /// surface as `Err` and fail the `.unwrap()`).
    #[test]
    fn write_file_atomic_writes_replaces_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commands.yaml");

        super::write_file_atomic(&path, b"first: true\n", true).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first: true\n");

        // Overwrite with SHORTER content: a non-atomic truncate-in-place could
        // leave trailing bytes of the old content; the rename fully replaces it.
        super::write_file_atomic(&path, b"x\n", true).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "x\n");

        // The only entry in the directory is the target file — the temp file was
        // renamed (consumed), not left dangling.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        assert_eq!(entries.len(), 1, "no temp file left behind: {entries:?}");
        assert_eq!(entries[0], path);
    }

    /// CodeRabbit R17 #4: `write_file_atomic` through a SYMLINK must update the
    /// link's TARGET, not replace the symlink with a regular file. `persist`
    /// renames onto the destination, so without resolving the symlink first the
    /// link would be clobbered; the fix canonicalizes a symlinked destination and
    /// writes through to the real file. Unix-only (`std::os::unix::fs::symlink`).
    #[cfg(unix)]
    #[test]
    fn write_file_atomic_through_symlink_updates_target_not_link() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        // The real config lives in a SEPARATE subdir to prove the temp file is
        // placed next to the resolved target (same filesystem), not next to the
        // link — a cross-directory symlink would otherwise break atomicity.
        let target_dir = dir.path().join("real");
        std::fs::create_dir_all(&target_dir).unwrap();
        let target = target_dir.join("config.yaml");
        std::fs::write(&target, b"old: true\n").unwrap();

        let link = dir.path().join("config.yaml");
        symlink(&target, &link).unwrap();

        // Write through the symlink.
        super::write_file_atomic(&link, b"new: true\n", true).unwrap();

        // The TARGET now holds the new content...
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new: true\n");
        // ...and the symlink is INTACT (still a symlink pointing at the target),
        // not replaced by a regular file.
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
        // Reading through the link yields the updated content.
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "new: true\n");

        // No temp file left dangling in EITHER directory (it was renamed into the
        // target dir, consuming it).
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

    /// A DANGLING symlink (target missing) falls back to the pre-existing
    /// behavior: `write_file_atomic` renames onto the link path. The resulting
    /// path holds the content and is a regular file (the dangling link is
    /// replaced) — `canonicalize` cannot resolve a missing target, so the
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

        // The link path now holds the content as a REGULAR file (fallback path).
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "data: 1\n");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_file(),
            "a dangling symlink falls back to a regular-file write at the link path"
        );
    }

    /// CodeRabbit R13 #K: `overwrite=false` must NOT clobber an existing file —
    /// it closes the TOCTOU between an `init` caller's `exists()` pre-check and the
    /// publish. A file created in that window survives untouched and the write
    /// reports `AlreadyExists`; `overwrite=true` still replaces it.
    #[test]
    fn write_file_atomic_no_clobber_preserves_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commands.yaml");

        // No-clobber create when absent: succeeds.
        super::write_file_atomic(&path, b"original\n", false).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "original\n");

        // No-clobber write when the file now EXISTS: fails AlreadyExists, content
        // untouched (simulates the racing-create the exists() check cannot prevent).
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

/// Write `contents` to `path` atomically: a sibling temp file in the same
/// directory is written, flushed, fsync'd, then renamed over `path`. The rename
/// is atomic on the same filesystem, so a concurrent reader (or a crash
/// mid-write) never observes a truncated or half-written file — it sees either
/// the previous contents or the complete new ones.
///
/// Durability mirrors `command_card::write_card_atomic` and the core
/// `canary`/`baseline` rewrite paths (CodeRabbit R12 #B): the body is
/// `sync_all()`'d BEFORE the rename so a crash after the rename cannot leave a
/// zero/partial file, and the parent directory is fsync'd AFTER the rename so
/// the new directory entry is itself crash-durable. Used by the operator-facing
/// config writers (`commands init`, `policy init`, `output wrap` shell-profile
/// edits) — files the operator relies on, NOT regenerable caches.
///
/// SYMLINK DESTINATIONS (CodeRabbit R17 #4): `persist` renames the temp file
/// ONTO the destination, which would replace a *symlinked* config file with the
/// regular temp file — clobbering the link instead of updating its target. So if
/// `path` is a symlink to an EXISTING target we resolve it (`canonicalize`) and
/// write THROUGH to the resolved target, leaving the symlink intact. The temp
/// file is created in the RESOLVED target's directory so the rename stays atomic
/// (same filesystem). A non-symlink, a dangling symlink, or an unresolvable
/// target falls back to renaming onto `path` as before.
///
/// `overwrite` (CodeRabbit R13 #K): `true` publishes with `persist` (replaces an
/// existing `dest` — for full-file rewrites like `output wrap` and `--force`
/// inits). `false` publishes with `persist_noclobber`, which fails atomically
/// with `AlreadyExists` if `dest` already exists. The no-clobber mode closes the
/// TOCTOU between an `init` caller's `exists()` pre-check and this publish: a file
/// created in that window is no longer silently clobbered when `--force` was not
/// passed (the operator's "don't overwrite" intent is enforced atomically, not
/// just advisorily).
pub(crate) fn write_file_atomic(
    path: &std::path::Path,
    contents: &[u8],
    overwrite: bool,
) -> std::io::Result<()> {
    // Resolve a symlinked destination to its real target so we write THROUGH the
    // link rather than replacing it; non-symlinks resolve to themselves.
    let dest = resolve_atomic_dest(path);
    let dir = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(std::path::PathBuf::from)
        // No parent component (a bare filename): keep the temp file in the
        // current directory so the rename stays on the same filesystem.
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let mut tmp = tempfile::NamedTempFile::new_in(&dir)?;
    tmp.write_all(contents)?;
    // `flush()` only drains the userspace buffer into the kernel; `sync_all()`
    // forces the file's data + metadata to stable storage BEFORE the rename
    // publishes it, so a reader after a crash sees the old or the complete new
    // contents, never a truncated file.
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    // Publish atomically. `overwrite` renames over an existing `dest`; no-clobber
    // uses `persist_noclobber`, which fails with `AlreadyExists` rather than
    // replacing a file that appeared after the caller's `exists()` check.
    if overwrite {
        tmp.persist(&dest).map_err(|e| e.error)?;
    } else {
        tmp.persist_noclobber(&dest).map_err(|e| e.error)?;
    }
    // The persist renames the temp over `dest` but does not fsync the containing
    // directory. fsync the parent so the new name→inode entry survives a crash.
    // The persist already succeeded, so a dir-fsync failure is LOGGED, not
    // propagated (R13 #5). Best-effort, no-op on non-Unix (no directory fsync).
    tirith_core::util::fsync_parent_dir_logged(&dest, "atomic file write");
    Ok(())
}

/// Resolve the EFFECTIVE rename target for [`write_file_atomic`]. When `path` is
/// a symlink to an existing target, returns the canonicalized target so the
/// write goes THROUGH the link (the symlink itself is preserved); otherwise (a
/// regular path, a missing path, or a dangling/unresolvable symlink) returns
/// `path` unchanged so the caller renames onto it as before.
pub(crate) fn resolve_atomic_dest(path: &std::path::Path) -> std::path::PathBuf {
    // Single source of truth shared with the core state-store rewrites.
    tirith_core::util::resolve_symlink_target(path)
}

/// Reconstruct a shell command STRING from already-split argv, PRESERVING word
/// boundaries (CodeRabbit R13b). Each arg containing a shell-significant byte is
/// single-quoted (embedded `'` escaped as `'\''`); shell-safe args are emitted
/// bare so the common case round-trips unchanged (`["echo","hi"]` → `echo hi`).
///
/// Used where the reconstructed string is fed to the analysis engine
/// (`commands check`): a naive `argv.join(" ")` lets a multi-word arg be re-split
/// into separate tokens/commands and skew the verdict — e.g.
/// `git commit -m "fix; rm -rf /"` would look like a `;`-separated `rm` command.
/// Quoting the dangerous arg keeps the engine's tokenization faithful to the argv
/// the user actually invoked. (Reconstructing a human's ORIGINAL quoting from
/// post-shell-split argv is impossible, so this is about token boundaries, not
/// byte-identical manifest matching.)
pub(crate) fn shell_join(argv: &[String]) -> String {
    // A SINGLE argument is already a complete command string — the user quoted the
    // whole command (`tirith check "curl https://x | sh"`), so `cmd` has one
    // element that IS the command. Return it verbatim: quoting it would wrap the
    // entire command in `'…'` and hide its pipes/URLs/substitutions from the
    // engine. Quote-as-needed only kicks in when the command arrives as MULTIPLE
    // argv elements (`-- git commit -m "a; b"`), where word boundaries would
    // otherwise be lost to a naive space-join.
    if argv.len() == 1 {
        return argv[0].clone();
    }
    fn needs_quoting(s: &str) -> bool {
        // Bare only for a conservative shell-safe set (alphanumerics + a few
        // punctuation bytes with no unquoted shell meaning); anything else —
        // space, `;`, `|`, `&`, `$`, quotes, `\`, glob chars, newline — is quoted.
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

/// Suggest the closest match from a list of candidates using Levenshtein distance.
/// Returns `None` if no candidate is within `max_distance`.
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

/// Prompt user for confirmation. Returns true only if:
/// - `yes` is true (`--yes` was passed), OR
/// - stderr is a TTY AND user types y/yes
///
/// Returns **false** in non-interactive contexts without `--yes`,
/// preventing silent approval of destructive operations.
pub fn confirm(prompt: &str, yes: bool) -> bool {
    if yes {
        return true;
    }
    if !is_terminal::is_terminal(std::io::stderr()) {
        eprintln!("tirith: skipping prompt (not a TTY — use --yes to auto-approve)");
        return false;
    }
    eprint!("{prompt} [y/N] ");
    // Flush is best-effort; if it fails the prompt may not be visible but read_line still works.
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
pub mod manpage;
pub mod mcp;
pub mod mcp_server;
pub mod onboard;
pub mod output_guard;
pub mod package;
pub mod paste;
pub mod path;
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

/// Map (`OS`, `ARCH`) to the platform-specific package name used under the
/// `@sheeki03/` npm scope (e.g. `tirith-linux-x64`, joined later as
/// `@sheeki03/tirith-linux-x64`). Returns `None` on unsupported Unix
/// targets (e.g. FreeBSD). Mirrors `npm/tirith/bin/tirith` exactly.
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

/// If `path` is the official tirith npm wrapper at
/// `…/node_modules/tirith/bin/tirith`, resolve to the platform-package native
/// binary at `…/node_modules/@sheeki03/tirith-{platform}-{arch}/bin/tirith`.
///
/// The wrapper is a Node script that `execFileSync`s the native binary, so
/// `current_exe()` returns the native ELF while `which -a tirith` returns the
/// wrapper — naive `canonicalize()` makes them appear to be different installs
/// and triggers a false-positive shadow warning. See issue #105.
#[cfg(unix)]
fn resolve_npm_wrapper_target(path: &std::path::Path) -> Option<std::path::PathBuf> {
    use std::path::Component;

    // Canonicalize FIRST. The path on PATH is typically a symlink (e.g.
    // `~/.nvm/.../bin/tirith` → `…/node_modules/tirith/bin/tirith`) and the
    // layout check has to happen on the resolved target.
    let canonical = path.canonicalize().ok()?;

    // Verify the canonicalized path's last four components are exactly
    // `node_modules`, `tirith`, `bin`, `tirith` (in that order). Anything
    // else falls through to the existing `canonicalize()` behavior.
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

    // Walk up to the `node_modules` ancestor (parent of the `tirith` package
    // directory). `canonical` ends in `…/node_modules/tirith/bin/tirith`, so
    // `node_modules` is three parents up.
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

/// Resolve all `tirith` executables on PATH using the shell's own command resolution.
/// Returns paths that the shell would actually execute, not just filesystem entries.
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

/// Find `tirith` executables on PATH that are not the current binary.
/// Deduplicates by logical target path so duplicate PATH entries and shim aliases
/// don't produce repeated warnings.
pub fn find_shadow_binaries() -> Vec<String> {
    let our_canonical = std::env::current_exe()
        .ok()
        .and_then(|p| resolve_effective_tirith_target(&p));

    let mut seen = std::collections::HashSet::new();
    let mut shadows = Vec::new();

    for path in resolve_tirith_on_path() {
        let canonical = resolve_effective_tirith_target(&path);
        // Skip if it resolves to our own binary
        if let (Some(ours), Some(ref theirs)) = (&our_canonical, &canonical) {
            if ours == theirs {
                continue;
            }
        }
        // Dedup by canonical path (fall back to display path for unresolvable entries)
        let key = canonical
            .map(|c| c.display().to_string())
            .unwrap_or_else(|| path.display().to_string());
        if seen.insert(key) {
            shadows.push(path.display().to_string());
        }
    }
    shadows
}

#[cfg(test)]
mod tests {
    use super::{parse_shim_target, resolve_shim_target, shell_join};
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn shell_join_preserves_argv_boundaries() {
        let q = |v: &[&str]| shell_join(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        // A SINGLE arg is a pre-formed command string — returned VERBATIM, never
        // quoted (else the whole command would be hidden from the engine).
        assert_eq!(q(&["curl https://x.sh | sh"]), "curl https://x.sh | sh");
        assert_eq!(q(&["$(rm -rf /)"]), "$(rm -rf /)");
        // Shell-safe args round-trip bare (common case, manifest-friendly).
        assert_eq!(q(&["echo", "hello", "world"]), "echo hello world");
        assert_eq!(
            q(&["curl", "https://example.com/x.sh"]),
            "curl https://example.com/x.sh"
        );
        // An arg with shell-significant bytes is single-quoted so the engine does
        // NOT re-split it: `;`, spaces, and `/` inside one arg stay one token.
        assert_eq!(
            q(&["git", "commit", "-m", "fix; rm -rf /"]),
            "git commit -m 'fix; rm -rf /'"
        );
        // Embedded single quotes are escaped as '\''.
        assert_eq!(q(&["echo", "it's"]), "echo 'it'\\''s'");
        // An empty arg must be represented (not vanish) as '' .
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

        /// Build the canonical npm layout under `root` and return
        /// `Some((path-to-symlink-on-PATH, path-to-native-binary))`. Returns
        /// `None` on Unix targets that aren't in `npm_platform_package`'s
        /// mapping (FreeBSD, OpenBSD, etc.) so tests can early-skip without
        /// panicking on platforms the npm distribution doesn't ship for.
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

        /// The actual bug path: PATH entry → symlink → wrapper. Without the
        /// canonicalize-first step in `resolve_npm_wrapper_target`, this fails.
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
            // Build wrapper layout WITHOUT the platform sibling — simulates a
            // broken install. Helper must return None so the existing
            // canonicalize path still warns naturally.
            let dir = tempfile::tempdir().unwrap();
            let wrapper_dir = dir.path().join("lib/node_modules/tirith/bin");
            fs::create_dir_all(&wrapper_dir).unwrap();
            let wrapper = wrapper_dir.join("tirith");
            fs::write(&wrapper, b"wrapper").unwrap();

            assert_eq!(resolve_npm_wrapper_target(&wrapper), None);
        }

        #[test]
        fn resolve_npm_wrapper_target_ignores_non_npm_paths() {
            // Pip-style layout: a tirith binary outside any node_modules tree.
            // Helper must return None so the documented PyPI conflict warning
            // (docs/troubleshooting.md:29-47) is preserved.
            let dir = tempfile::tempdir().unwrap();
            let pip_dir = dir.path().join("local/bin");
            fs::create_dir_all(&pip_dir).unwrap();
            let pip = pip_dir.join("tirith");
            fs::write(&pip, b"pip-installed").unwrap();

            assert_eq!(resolve_npm_wrapper_target(&pip), None);
        }
    }
}
