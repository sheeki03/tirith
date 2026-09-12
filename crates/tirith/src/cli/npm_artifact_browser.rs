//! Explicit, read-only artifact selection beneath the retained service project.
//! Browser input never selects an absolute host path or an execution command.
use std::path::{Component, Path};
use std::sync::Mutex;

use serde::Deserialize;
use serde_json::{json, Value};
use tirith_core::artifact::npm_archive::{read_npm_tarball, NpmInspection, NpmLimits};
use tirith_core::artifact::npm_diff::compare_npm_releases;
use tirith_core::util::ContainedAtomicFile;

static INSPECTION: Mutex<()> = Mutex::new(());

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Request {
    Inspect { path: String },
    Compare { old_path: String, new_path: String },
}

fn load(root: &Path, path: &str, anchor: &ContainedAtomicFile) -> Result<NpmInspection, String> {
    if path.is_empty()
        || path.len() > 512
        || path.contains(['\\', ':', '\0'])
        || Path::new(path).components().count() > 12
        || Path::new(path)
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || !super::is_npm_path(Path::new(path))
    {
        return Err(
            "Select a project-relative .tgz or .tar.gz file without parent traversal.".into(),
        );
    }
    let target = root.join(path);
    let file = ContainedAtomicFile::prepare(root, &target, false)
        .map_err(|_| "Artifact parent is absent, linked or unavailable.")?;
    if !file.shares_retained_root(anchor).unwrap_or(false) {
        return Err("The service project directory changed; reopen the dashboard.".into());
    }
    let limits = NpmLimits::default();
    let bytes = file
        .read_capped(limits.compressed_bytes as u64)
        .map_err(|_| {
            "Artifact must be a readable regular file without symbolic links, at most 32 MiB."
        })?;
    // Hashing and parsing consume these same bounded bytes. The report makes
    // no assertion that the pathname still contains them after this capture.
    let filename = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("Artifact filename is not valid UTF-8.")?;
    Ok(read_npm_tarball(bytes.as_slice(), filename, &limits))
}

pub(crate) fn review(
    cwd: &str,
    request: Request,
    anchor: &ContainedAtomicFile,
) -> Result<Value, String> {
    let _work = INSPECTION
        .try_lock()
        .map_err(|_| "Another local artifact inspection is active; retry when it finishes.")?;
    let root = Path::new(cwd);
    if !root.is_absolute() {
        return Err("The service project is unavailable; reopen the dashboard.".into());
    }
    let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
    // Capture before reading and again before projection so stricter local
    // privacy introduced during analysis is included in the captured union.
    let mut context = super::Context::capture_for(Some(cwd));
    let mut report = match request {
        Request::Inspect { path } => {
            let inspection = load(root, &path, anchor)?;
            context.refresh_for(Some(cwd));
            context.with_redaction_coverage(super::inspection_projection(
                &[inspection],
                &context.compiled,
                &context.diagnostics,
            ))
        }
        Request::Compare { old_path, new_path } => {
            let old = load(root, &old_path, anchor)?;
            let new = load(root, &new_path, anchor)?;
            let comparison = compare_npm_releases(&old, &new)?;
            context.refresh_for(Some(cwd));
            context.with_redaction_coverage(super::comparison_projection(
                &comparison,
                &context.compiled,
                &context.diagnostics,
            ))
        }
    };
    report["selection"] = json!({"scope":"service_project","executed":false,
        "installed":false,"network_used":false,"current_paths_revalidated":false,
        "identity":"sha256_of_captured_archive_bytes"});
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn browser_refuses_a_rebound_project_even_when_archive_bytes_are_identical() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().canonicalize().unwrap();
        let root = parent.join("project");
        std::fs::create_dir(&root).unwrap();
        let archive =
            include_bytes!("../../../tirith-core/tests/fixtures/npm/npm-11.19.0-portable-pax.tgz");
        std::fs::write(root.join("p.tgz"), archive).unwrap();
        let anchor = ContainedAtomicFile::prepare(&root, &root.join("anchor"), false).unwrap();
        assert!(load(&root, "p.tgz", &anchor).is_ok());
        std::fs::rename(&root, parent.join("moved")).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("p.tgz"), archive).unwrap();
        assert!(load(&root, "p.tgz", &anchor)
            .unwrap_err()
            .contains("project directory changed"));
    }

    #[test]
    fn browser_artifacts_refuse_escaping_paths_and_do_not_create_parents() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let anchor = ContainedAtomicFile::prepare(&root, &root.join("anchor"), false).unwrap();
        for path in [
            "../outside.tgz",
            "/tmp/outside.tgz",
            "C:\\outside.tgz",
            "package.json",
            "missing/p.tgz",
        ] {
            assert!(load(root.as_path(), path, &anchor).is_err());
        }
        assert_eq!(std::fs::read_dir(root.as_path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn browser_artifacts_refuse_linked_parent_and_leaf() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let anchor = ContainedAtomicFile::prepare(&root, &root.join("anchor"), false).unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("p.tgz"), b"not an archive").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.as_path().join("linked")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("p.tgz"), root.as_path().join("p.tgz"))
            .unwrap();
        assert!(load(root.as_path(), "linked/p.tgz", &anchor).is_err());
        assert!(load(root.as_path(), "p.tgz", &anchor).is_err());
    }
}
