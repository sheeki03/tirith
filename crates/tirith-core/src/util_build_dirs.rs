//! Shared set of built-in build-artifact directory names.
//!
//! These are directories that contain generated or vendored output rather than
//! authored source. The scanner skips them during directory walks, and a later
//! correlation pass reuses the same set so the two stay in agreement.

/// Directory basenames treated as build artifacts / generated output.
///
/// Skipping these avoids scanning machine-generated files and keeps walks fast.
pub const BUILT_IN_SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "__pycache__",
    ".tox",
    "dist",
    "build",
    ".next",
    "vendor",
    ".cache",
    "out",
    ".turbo",
    "coverage",
    ".expo",
];

/// Returns true if `name` (a directory basename) is a built-in build-artifact
/// directory that should be skipped during scanning.
pub fn should_skip_dir(name: &str) -> bool {
    BUILT_IN_SKIP_DIRS.contains(&name)
}

/// Classify the narrowly-defined runtime paths created by Hermes Agent.
///
/// Hermes writes shell snapshots as `hermes-snap-*.sh.tmp.*` and creates
/// `hermes_sandbox_*` roots below the operating system's temporary directory.
/// These names are generated output only when the path is a clean, ordinary
/// absolute path below a known temp root. Sandbox *descendants* are deliberately
/// not classified: a generated directory can contain symlinks to authored data,
/// while cleanup of the generated root itself is the narrow safe shape.
fn is_hermes_runtime_artifact_path(path: &str) -> bool {
    if path.ends_with(['/', '\\']) {
        return false;
    }
    let Some((path, temp_root_len)) = clean_hermes_temp_path(path) else {
        return false;
    };
    let relative = &path.components()[temp_root_len..];
    let [basename] = relative else {
        return false;
    };
    is_hermes_snapshot_temp_basename(basename) || is_hermes_sandbox_basename(basename)
}

/// Parse a Hermes candidate without allowing a parent component to be erased
/// during normalization, and return the component length of its known temp
/// root. Only ordinary POSIX roots and Windows drive-absolute roots qualify;
/// UNC, rooted-no-drive, drive-relative, verbatim, and device namespaces do not.
fn clean_hermes_temp_path(path: &str) -> Option<(crate::lexical_path::LexicalPath, usize)> {
    use crate::lexical_path::{detect_dialect, LexicalPath, PathDialect, RootClass};

    if !is_static_hermes_path_text(path)
        || path.split(['/', '\\']).any(|component| component == ".")
    {
        return None;
    }
    let dialect = detect_dialect(path);
    let path = LexicalPath::parse_preserving_parents(path, dialect).ok()?;
    if !path.parent_state().is_clean() {
        return None;
    }

    let components = path.components();
    let temp_root_len = match (dialect, path.root_class()) {
        (PathDialect::Posix, RootClass::PosixRoot) => posix_temp_root_len(components),
        (PathDialect::Windows, RootClass::DriveAbsolute) => windows_temp_root_len(components),
        _ => None,
    }?;
    (components.len() > temp_root_len).then_some((path, temp_root_len))
}

/// The broad artifact heuristic receives a dequoted shell operand, so it cannot
/// distinguish literal whitespace/metacharacters from expansion syntax. Hermes'
/// generated names need none of them; reject ambiguity instead of allowing a
/// glob, parameter expansion, command operator, or control byte to manufacture
/// a matching path at runtime. Backslashes remain allowed as Windows separators.
fn is_static_hermes_path_text(path: &str) -> bool {
    let bytes = path.as_bytes();
    let has_valid_drive_colon =
        bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    !path.is_empty()
        && !path.char_indices().any(|(index, ch)| {
            ch.is_whitespace()
                || ch.is_control()
                || (ch == ':' && !(index == 1 && has_valid_drive_colon))
                || matches!(
                    ch,
                    '$' | '`'
                        | '*'
                        | '?'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | ';'
                        | '|'
                        | '&'
                        | '<'
                        | '>'
                        | '\''
                        | '"'
                        | '%'
                        | '!'
                        | '^'
                        | '('
                        | ')'
                )
        })
}

fn posix_temp_root_len(components: &[String]) -> Option<usize> {
    match components {
        [root, ..] if root == "tmp" => Some(1),
        [first, second, ..]
            if (first == "private" && second == "tmp") || (first == "var" && second == "tmp") =>
        {
            Some(2)
        }
        [var, folders, shard, owner, temp, ..]
            if var == "var"
                && folders == "folders"
                && !shard.is_empty()
                && !owner.is_empty()
                && temp == "T" =>
        {
            Some(5)
        }
        [private, var, folders, shard, owner, temp, ..]
            if private == "private"
                && var == "var"
                && folders == "folders"
                && !shard.is_empty()
                && !owner.is_empty()
                && temp == "T" =>
        {
            Some(6)
        }
        _ => None,
    }
}

fn windows_temp_root_len(components: &[String]) -> Option<usize> {
    match components {
        [temp, ..] if temp == "temp" => Some(1),
        [windows, temp, ..] if windows == "windows" && temp == "temp" => Some(2),
        [users, user, appdata, local, temp, ..]
            if users == "users"
                && !user.is_empty()
                && appdata == "appdata"
                && local == "local"
                && temp == "temp" =>
        {
            Some(5)
        }
        _ => None,
    }
}

fn is_hermes_snapshot_temp_basename(basename: &str) -> bool {
    let Some(rest) = basename.strip_prefix("hermes-snap-") else {
        return false;
    };
    let Some((session, suffix)) = rest.split_once(".sh.tmp.") else {
        return false;
    };
    !session.is_empty() && !suffix.is_empty()
}

fn is_hermes_sandbox_basename(basename: &str) -> bool {
    basename
        .strip_prefix("hermes_sandbox_")
        .is_some_and(|suffix| !suffix.is_empty())
}

/// Returns true if any component of `path` is a built-in build-artifact
/// directory. Components are split on both `/` and `\` so the check works for
/// POSIX and Windows-style paths. Dot components are normalized lexically
/// before classification: a canceled `dist/..` must not exempt the real target,
/// and an unresolved upward traversal is never trusted as generated output.
pub fn is_build_artifact_path(path: &str) -> bool {
    if is_hermes_runtime_artifact_path(path) {
        return true;
    }
    let Ok(path) = crate::lexical_path::LexicalPath::parse_auto(path) else {
        return false;
    };
    if !path.parent_state().is_clean()
        || matches!(
            path.root_class(),
            crate::lexical_path::RootClass::Verbatim | crate::lexical_path::RootClass::Device
        )
    {
        return false;
    }
    path.components()
        .iter()
        .any(|component| should_skip_dir(component))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_dirs_are_members() {
        for name in ["out", ".turbo", "coverage", ".expo"] {
            assert!(should_skip_dir(name), "{name} should be a skip dir");
        }
    }

    #[test]
    fn original_dirs_still_members() {
        for name in [
            ".git",
            "node_modules",
            "target",
            "__pycache__",
            ".tox",
            "dist",
            "build",
            ".next",
            "vendor",
            ".cache",
        ] {
            assert!(should_skip_dir(name), "{name} should be a skip dir");
        }
    }

    #[test]
    fn non_build_dirs_are_not_members() {
        assert!(!should_skip_dir("src"));
        assert!(!should_skip_dir(".vscode"));
    }

    #[test]
    fn build_artifact_path_detection() {
        assert!(is_build_artifact_path("a/dist/b.js"));
        assert!(!is_build_artifact_path("src/main.rs"));
    }

    #[test]
    fn build_artifact_path_handles_backslashes() {
        assert!(is_build_artifact_path("a\\node_modules\\b.js"));
        assert!(is_build_artifact_path(r"C:\Work\NODE_MODULES\b.js"));
    }

    #[test]
    fn build_artifact_path_normalizes_canceled_components() {
        assert!(is_build_artifact_path("src/../dist/bundle.js"));
        assert!(!is_build_artifact_path("dist/../src/main.rs"));
        assert!(!is_build_artifact_path("build/./../src/lib.rs"));
    }

    #[test]
    fn build_artifact_path_rejects_unresolved_parent_traversal() {
        assert!(!is_build_artifact_path("../dist/bundle.js"));
        assert!(!is_build_artifact_path("dist/../../dist/bundle.js"));
        assert!(!is_build_artifact_path("/../../dist/bundle.js"));
        assert!(!is_build_artifact_path(r"\\server\share\..\dist\x"));
    }

    #[test]
    fn build_artifact_path_preserves_root_integrity_and_dialect_case() {
        assert!(!is_build_artifact_path(r"\\server\dist\x"));
        assert!(is_build_artifact_path(r"\\server\share\dist\x"));
        assert!(!is_build_artifact_path("/SRC/DIST/x"));
        assert!(!is_build_artifact_path(r"\\?\C:\dist\x"));
        assert!(!is_build_artifact_path(r"\\.\C:\dist\x"));
    }

    #[test]
    fn hermes_runtime_artifacts_are_recognized_only_under_known_temp_roots() {
        for path in [
            "/tmp/hermes-snap-session.sh.tmp.4K2p9a",
            "/private/tmp/hermes-snap-a.sh.tmp.x",
            "/var/tmp/hermes_sandbox_job-1",
            "/var/folders/0h/owner/T/hermes-snap-session.sh.tmp.123456",
            "/private/var/folders/zz/owner/T/hermes_sandbox_abc",
            r"C:\Temp\hermes-snap-session.sh.tmp.A1",
            r"D:\Windows\Temp\hermes_sandbox_job",
            r"C:\Users\Alice\AppData\Local\Temp\HERMES-SNAP-ID.SH.TMP.X",
        ] {
            assert!(is_build_artifact_path(path), "not recognized: {path}");
        }
    }

    #[test]
    fn hermes_authored_lookalikes_and_malformed_names_remain_non_artifacts() {
        for path in [
            "hermes-snap-session.sh.tmp.123",
            "project/hermes_sandbox_job/work",
            "/workspace/hermes-snap-session.sh.tmp.123",
            "/tmp/project/hermes-snap-session.sh.tmp.123",
            "/tmp/hermes-snap-.sh.tmp.123",
            "/tmp/hermes-snap-session.sh.tmp.",
            "/tmp/hermes-snap-session.sh",
            "/tmp/hermes_sandbox_",
            "/tmp/hermes_sandbox_job/work/output.txt",
            "/tmp/hermes_sandbox_job/symlink/important.txt",
            "/tmp/hermes_sandbox_job/",
            "/tmp/hermes_sandbox_job/.",
            "/tmp/./hermes_sandbox_job",
            "/private/tmp/hermes_sandbox_job/etc/passwd",
            "/tmp/not_hermes_sandbox_job/work",
            "/var/folders/0h/owner/X/hermes_sandbox_job",
            r"C:\Work\Temp\hermes_sandbox_job",
            r"C:\Users\Alice\Temp\hermes-snap-session.sh.tmp.x",
            r"C:\Temp\hermes_sandbox_job\linked\secret.txt",
        ] {
            assert!(!is_build_artifact_path(path), "false exemption: {path}");
        }
    }

    #[test]
    fn hermes_paths_reject_traversal_and_unsafe_windows_namespaces() {
        for path in [
            "/tmp/project/../hermes_sandbox_job",
            "/workspace/../tmp/hermes-snap-session.sh.tmp.123",
            "/tmp/../tmp/hermes-snap-session.sh.tmp.123",
            r"C:\Work\..\Temp\hermes_sandbox_job",
            r"\Temp\hermes_sandbox_job",
            r"C:Temp\hermes_sandbox_job",
            r"\\server\share\Temp\hermes_sandbox_job",
            r"\\?\C:\Temp\hermes_sandbox_job",
            r"\\.\C:\Temp\hermes_sandbox_job",
        ] {
            assert!(!is_build_artifact_path(path), "unsafe exemption: {path}");
        }
    }

    #[test]
    fn hermes_runtime_artifacts_require_static_unambiguous_path_text() {
        for path in [
            "/tmp/hermes-snap-*.sh.tmp.*",
            "/tmp/hermes-snap-$session.sh.tmp.123",
            "/tmp/hermes-snap-${session}.sh.tmp.123",
            "/tmp/hermes-snap-$(printf x).sh.tmp.123",
            "/tmp/hermes-snap-{one,two}.sh.tmp.123",
            "/tmp/hermes_sandbox_$suffix",
            "/tmp/hermes_sandbox_${suffix}",
            "/tmp/hermes_sandbox_${suffix}/",
            "/tmp/hermes_sandbox_$suffix/linked-secret",
            "/tmp/hermes_sandbox_[ab]",
            "/tmp/hermes_sandbox_job;rm-secret",
            "/tmp/hermes_sandbox_job child",
            "/tmp/hermes_sandbox_job\nrm-secret",
            "/tmp/hermes_sandbox_job\tchild",
            "/tmp/hermes_sandbox_job\u{00a0}child",
            r"C:\Temp\hermes_sandbox_%SUFFIX%",
            r"C:\Temp\hermes_sandbox_!SUFFIX!",
            r"C:\Temp\hermes_sandbox_job:stream",
            r"C:\Temp\hermes-snap-session.sh.tmp.123:stream",
            r"C:\Temp\hermes_sandbox_job::$DATA",
            "/tmp/hermes_sandbox_(job)",
            "/tmp/hermes-snap-(session).sh.tmp.123",
        ] {
            assert!(
                !is_build_artifact_path(path),
                "dynamic or ambiguous path received a Hermes exemption: {path:?}"
            );
        }
    }
}
