//! Exact signed ThreatDB candidates, plus the guarded dashboard refresh that
//! runs the same update code as `tirith threatdb update`.
use std::path::{Path, PathBuf};

use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
use tirith_core::threatdb::ThreatDb;

use crate::cli::control::identity::DirectoryIdentity;
use crate::cli::setup::fs_helpers;

pub(super) enum Candidate {
    Index {
        index: super::IndexV2,
        selected_format: u32,
    },
    Legacy {
        manifest: super::Manifest,
    },
}

struct Asset<'a> {
    sequence: u64,
    format: u32,
    url: &'a str,
    sha256: &'a str,
    size: u64,
}

impl Candidate {
    fn asset(&self) -> Result<Asset<'_>, String> {
        match self {
            Self::Index {
                index,
                selected_format,
            } => {
                let key = ed25519_dalek::VerifyingKey::from_bytes(super::VERIFY_KEY_BYTES)
                    .map_err(|_| "invalid embedded verification key")?;
                index.verify_signature_with_key(&key)?;
                let asset = index
                    .select_asset(env!("CARGO_PKG_VERSION"))
                    .ok_or("prepared index no longer has a compatible asset")?;
                if asset.format != *selected_format {
                    return Err("prepared asset differs from signed index selection".into());
                }
                Ok(Asset {
                    sequence: index.sequence,
                    format: asset.format,
                    url: &asset.url,
                    sha256: &asset.sha256,
                    size: asset.size,
                })
            }
            Self::Legacy { manifest } => {
                manifest.verify_signature()?;
                if manifest.size == 0
                    || manifest.size > super::MAX_DB_SIZE
                    || manifest.sha256.len() != 64
                    || !manifest.sha256.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err("prepared manifest has invalid asset bounds".into());
                }
                Ok(Asset {
                    sequence: manifest.version,
                    format: 1,
                    url: &manifest.url,
                    sha256: &manifest.sha256,
                    size: manifest.size,
                })
            }
        }
    }
}

/// Network is explicit here; applying a Candidate never calls this selector.
pub(super) fn resolve_candidate() -> Result<Candidate, String> {
    match super::fetch_index_v2() {
        Ok(Some(index)) => if let Some(asset) = index.select_asset(env!("CARGO_PKG_VERSION")) {
            let selected_format = asset.format;
            return Ok(Candidate::Index { index, selected_format });
        },
        Ok(None) => {},
        Err(error) => eprintln!("tirith: signed index unavailable ({error}); checking independently signed legacy manifest"),
    }
    resolve_legacy()
}

pub(super) fn resolve_legacy() -> Result<Candidate, String> {
    let candidate = Candidate::Legacy {
        manifest: super::fetch_manifest()?,
    };
    candidate.asset()?;
    Ok(candidate)
}

/// Shared by the CLI and the dashboard refresh. All publication uses the exact
/// signed asset; the dashboard never requests force.
pub(super) fn apply_primary(
    candidate: &Candidate,
    force: bool,
    before_publish: impl Fn(bool) -> Result<(), String>,
) -> Result<super::UpdateOutcome, String> {
    let asset = candidate.asset()?;
    let current = ThreatDb::cached().map(|db| (db.build_sequence(), db.stats().format_version));
    let needed = super::index_install_needed(asset.sequence, asset.format, current, force)?;
    if !needed {
        before_publish(false)?;
        super::evidence::refresh(asset.url, asset.sequence, asset.format, asset.sha256);
        return Ok(super::UpdateOutcome::AlreadyCurrent);
    }
    let bytes = super::download_url(asset.url, asset.size)?;
    if bytes.len() as u64 != asset.size || tirith_core::util::sha256_hex(&bytes) != asset.sha256 {
        return Err("downloaded ThreatDB differs from its exact signed size/checksum".into());
    }
    let equal_sequence_switch =
        current.is_some_and(|(seq, format)| seq == asset.sequence && format != asset.format);
    super::install_primary_db_checked(
        bytes,
        asset.format,
        asset.sequence,
        force || equal_sequence_switch,
        &|| before_publish(true),
    )?;
    if asset.format == 1 {
        super::retire_primary_v2()?;
    }
    super::evidence::refresh(asset.url, asset.sequence, asset.format, asset.sha256);
    Ok(super::UpdateOutcome::Installed)
}

/// The canonical operator data directory and its four database paths. The
/// dashboard writes only there; redirected cache paths are explicit CLI
/// operations owned by the terminal that set them.
fn data_paths() -> Result<(PathBuf, Vec<PathBuf>), String> {
    if ["TIRITH_THREATDB_PATH", "TIRITH_THREATDB_SUPPLEMENTAL_PATH"]
        .iter()
        .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
    {
        return Err("ThreatDB paths are redirected; use `tirith threatdb update` in the terminal that owns those paths".into());
    }
    let root = tirith_core::policy::data_dir().ok_or("cannot locate operator data directory")?;
    if !root.is_absolute()
        || root
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err("ThreatDB data directory must be absolute without traversal".into());
    }
    let paths = [
        ThreatDb::default_path(),
        ThreatDb::default_path_v2(),
        ThreatDb::supplemental_path(),
        ThreatDb::supplemental_path_v2(),
    ]
    .into_iter()
    .collect::<Option<Vec<_>>>()
    .ok_or("cannot resolve database paths")?;
    if paths
        .iter()
        .any(|path| path.parent() != Some(root.as_path()))
    {
        return Err("database paths are outside the current operator data directory".into());
    }
    Ok((root, paths))
}

/// Refuse a root service and an administrator-owned data directory, then hold
/// the directory identity so a swap before publication is detected.
fn owned_data_directory(root: &Path) -> Result<DirectoryIdentity, String> {
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 {
        return Err("the dashboard does not refresh ThreatDB for the root account; run `tirith threatdb update` in the owning terminal".into());
    }
    if !root.exists() {
        fs_helpers::ensure_private_directory(root, root)?;
    }
    let directory = DirectoryIdentity::capture_trusted(root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata =
            std::fs::symlink_metadata(root).map_err(|_| "cannot inspect ThreatDB directory")?;
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(
                "ThreatDB directory is administrator-owned; use the owning terminal or installer"
                    .into(),
            );
        }
    }
    Ok(directory)
}

/// A configured remote policy authority must still admit local mutation.
fn require_mutable_policy(cwd: &Path) -> Result<(), String> {
    EffectivePolicySnapshot::resolve(cwd.to_str(), ResolutionMode::Runtime)
        .revalidate_for_mutation()
        .map_err(|error| error.to_string())
}

/// Dashboard "Refresh threat DB now". Every refusal (task gate with audit,
/// redirected paths, root, directory owner, remote policy, a concurrent update)
/// happens before any network access. It then runs the same update as
/// `tirith threatdb update` under the same foreground update lock, and
/// rechecks the task lease, data directory and policy before each publication.
pub(crate) fn guarded_refresh(cwd: &Path) -> Result<(), String> {
    guarded_refresh_with(cwd, |before_publish| {
        super::do_update_checked(false, before_publish)
    })
}

fn guarded_refresh_with(
    cwd: &Path,
    update: impl FnOnce(&dyn Fn(bool) -> Result<(), String>) -> Result<(), String>,
) -> Result<(), String> {
    let auth = crate::cli::selfupdate::authorize_threatdb_refresh()?;
    let (root, _) = data_paths()?;
    let directory = owned_data_directory(&root)?;
    require_mutable_policy(cwd)?;
    let _update_lock = super::lock_foreground_update()?;
    let check = |_will_publish: bool| -> Result<(), String> {
        auth.revalidate()?;
        directory.revalidate()?;
        if data_paths()?.0 != root {
            return Err("ThreatDB data scope changed during the refresh".into());
        }
        require_mutable_policy(cwd)
    };
    check(false)?;
    update(&check)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unverifiable_candidate_is_refused_before_any_download() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let candidate = Candidate::Legacy {
            manifest: super::super::Manifest {
                sha256: "0".repeat(64),
                size: 100,
                url: "https://example.invalid/untrusted.dat".into(),
                version: 1,
                signature: "invalid".into(),
            },
        };
        assert!(candidate.asset().is_err());
        let calls = std::cell::Cell::new(0);
        assert!(apply_primary(&candidate, false, |_| {
            calls.set(calls.get() + 1);
            Ok(())
        })
        .is_err());
        assert_eq!(calls.get(), 0);
    }

    fn canonical_data_state() -> tirith_test_support::GlobalStateGuard {
        let mut state = tirith_test_support::GlobalStateGuard::new().unwrap();
        state.remove_env("TIRITH_THREATDB_PATH");
        state.remove_env("TIRITH_THREATDB_SUPPLEMENTAL_PATH");
        state
    }

    #[test]
    fn dashboard_refresh_refuses_redirected_paths_before_any_update() {
        // The shared fixture redirects both ThreatDB paths.
        let state = tirith_test_support::GlobalStateGuard::new().unwrap();
        let called = std::cell::Cell::new(false);
        let error = guarded_refresh_with(&state.roots().cwd, |_| {
            called.set(true);
            Ok(())
        })
        .unwrap_err();
        assert!(error.contains("redirected"), "{error}");
        assert!(!called.get());
    }

    #[test]
    fn dashboard_refresh_refuses_while_another_update_holds_the_cli_lock() {
        let state = canonical_data_state();
        let _held = super::super::lock_foreground_update().unwrap();
        let called = std::cell::Cell::new(false);
        let error = guarded_refresh_with(&state.roots().cwd, |_| {
            called.set(true);
            Ok(())
        })
        .unwrap_err();
        assert!(
            error.contains("another ThreatDB update is active"),
            "{error}"
        );
        assert!(!called.get());
    }

    #[test]
    fn dashboard_refresh_runs_the_update_under_the_cli_lock_and_rechecks_before_publish() {
        let state = canonical_data_state();
        let calls = std::cell::Cell::new(0);
        guarded_refresh_with(&state.roots().cwd, |before_publish| {
            calls.set(calls.get() + 1);
            // The CLI and background updaters are excluded while it runs.
            assert!(super::super::lock_foreground_update().is_err());
            before_publish(true)
        })
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert!(super::super::lock_foreground_update().is_ok());
    }

    #[test]
    fn dashboard_refresh_refuses_publication_after_the_data_directory_is_swapped() {
        let state = canonical_data_state();
        let error = guarded_refresh_with(&state.roots().cwd, |before_publish| {
            let (root, _) = data_paths()?;
            std::fs::rename(&root, root.with_extension("moved")).unwrap();
            std::fs::create_dir(&root).unwrap();
            before_publish(true)
        })
        .unwrap_err();
        assert!(!error.is_empty());
    }
}
