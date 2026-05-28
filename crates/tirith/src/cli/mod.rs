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
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    if serde_json::to_writer_pretty(&mut out, value).is_err() || writeln!(out).is_err() {
        eprintln!("{ctx}");
        return false;
    }
    true
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
pub mod aliases;
pub mod audit;
#[cfg(unix)]
pub mod bash_capability;
pub mod check;
pub mod checkpoint;
pub mod clipboard;
pub mod codespaces;
pub mod completions;
pub mod context;
pub mod daemon;
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
pub mod init;
pub mod install;
pub mod lab;
pub mod last_trigger;
pub mod license_cmd;
pub mod logs;
pub mod manpage;
pub mod mcp;
pub mod mcp_server;
pub mod output_guard;
pub mod package;
pub mod paste;
pub mod path;
pub mod persistence;
pub mod policy;
pub mod prompt_status;
pub mod receipt;
pub mod scan;
pub mod score;
pub mod selfupdate;
pub mod share;
pub mod ssh;
pub mod sudo;
pub mod threatdb_cmd;
pub mod trust;
pub mod view;
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
    use super::{parse_shim_target, resolve_shim_target};
    use std::fs;
    use std::path::PathBuf;

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
