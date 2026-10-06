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

/// The account the refresh runs as. Tests substitute it to reach the root and
/// directory-owner refusals.
#[derive(Clone, Copy)]
struct Account {
    #[cfg(unix)]
    euid: u32,
}

impl Account {
    fn current() -> Self {
        Self {
            #[cfg(unix)]
            euid: unsafe { libc::geteuid() },
        }
    }
}

/// Refuse a root service and an administrator-owned data directory, then hold
/// the directory identity so a swap before publication is detected.
fn owned_data_directory(root: &Path, account: Account) -> Result<DirectoryIdentity, String> {
    #[cfg(unix)]
    if account.euid == 0 {
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
        if metadata.uid() != account.euid {
            return Err(
                "ThreatDB directory is administrator-owned; use the owning terminal or installer"
                    .into(),
            );
        }
    }
    #[cfg(not(unix))]
    let _ = account;
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
    guarded_refresh_with(
        cwd,
        crate::cli::selfupdate::authorize_threatdb_refresh,
        Account::current(),
        |before_publish| super::do_update_checked(false, before_publish),
    )
}

/// The task-gate decision a refresh holds; it is rechecked before each
/// publication.
trait RefreshAuthorization {
    fn revalidate(&self) -> Result<(), String>;
}

impl RefreshAuthorization for crate::cli::selfupdate::ThreatDbRefreshAuthorization {
    fn revalidate(&self) -> Result<(), String> {
        crate::cli::selfupdate::ThreatDbRefreshAuthorization::revalidate(self)
    }
}

fn guarded_refresh_with<A: RefreshAuthorization>(
    cwd: &Path,
    authorize: impl FnOnce() -> Result<A, String>,
    account: Account,
    update: impl FnOnce(&dyn Fn(bool) -> Result<(), String>) -> Result<(), String>,
) -> Result<(), String> {
    let auth = authorize()?;
    let (root, _) = data_paths()?;
    let directory = owned_data_directory(&root, account)?;
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
        state.remove_env("TIRITH_SERVER_URL");
        state.remove_env("TIRITH_API_KEY");
        state
    }

    /// The dashboard route's own authorization and account.
    fn live_refresh(
        cwd: &Path,
        update: impl FnOnce(&dyn Fn(bool) -> Result<(), String>) -> Result<(), String>,
    ) -> Result<(), String> {
        guarded_refresh_with(
            cwd,
            crate::cli::selfupdate::authorize_threatdb_refresh,
            Account::current(),
            update,
        )
    }

    /// A refusal must come before the update (and so before any network).
    fn refused_before_update(
        refresh: impl FnOnce(
            &mut dyn FnMut(&dyn Fn(bool) -> Result<(), String>) -> Result<(), String>,
        ) -> Result<(), String>,
    ) -> String {
        let mut called = false;
        let error = refresh(&mut |_: &dyn Fn(bool) -> Result<(), String>| {
            called = true;
            Ok(())
        })
        .unwrap_err();
        assert!(!called, "the update ran despite the refusal: {error}");
        error
    }

    #[test]
    fn dashboard_refresh_refuses_redirected_paths_before_any_update() {
        // The shared fixture redirects both ThreatDB paths.
        let state = tirith_test_support::GlobalStateGuard::new().unwrap();
        let called = std::cell::Cell::new(false);
        let error = live_refresh(&state.roots().cwd, |_| {
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
        let error = live_refresh(&state.roots().cwd, |_| {
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
        live_refresh(&state.roots().cwd, |before_publish| {
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
        let error = live_refresh(&state.roots().cwd, |before_publish| {
            let (root, _) = data_paths()?;
            std::fs::rename(&root, root.with_extension("moved")).unwrap();
            std::fs::create_dir(&root).unwrap();
            before_publish(true)
        })
        .unwrap_err();
        assert!(!error.is_empty());
    }

    #[test]
    fn dashboard_refresh_task_gate_refusal_is_audited_before_any_update() {
        let mut state = canonical_data_state();
        state.set_env("TIRITH_LOG", "1");
        let config = tirith_core::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(
            config.join("policy.yaml"),
            "task_gate:\n  mode: enforce\n  effects_denied_for_untrusted_sources: [network_egress, filesystem_write]\n",
        )
        .unwrap();
        let cwd = state.roots().cwd.clone();
        let error = refused_before_update(|update| live_refresh(&cwd, update));
        assert!(error.contains("task gate refused"), "{error}");
        let log_path = tirith_core::audit::audit_log_path().unwrap();
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        let audited = log
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .any(|entry| {
                entry["entry_type"] == "task_boundary"
                    && entry["event"] == "owned_boundary_assessment"
                    && entry["action"] == "deny"
            });
        assert!(
            audited,
            "the refusal must be audited in {log_path:?}: {log}"
        );
    }

    struct Revocable(std::rc::Rc<std::cell::Cell<bool>>);

    impl RefreshAuthorization for Revocable {
        fn revalidate(&self) -> Result<(), String> {
            if self.0.get() {
                Err("task authorization is no longer valid: revoked".into())
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn dashboard_refresh_rechecks_the_task_authorization_before_the_update_and_each_publish() {
        let state = canonical_data_state();
        let cwd = state.roots().cwd.clone();
        // Lapsed before the update starts: refused before any download.
        let revoked = std::rc::Rc::new(std::cell::Cell::new(true));
        let auth = Revocable(std::rc::Rc::clone(&revoked));
        let error = refused_before_update(|update| {
            guarded_refresh_with(&cwd, || Ok(auth), Account::current(), update)
        });
        assert!(error.contains("revoked"), "{error}");
        // Lapsed during the update: the publication is refused.
        let revoked = std::rc::Rc::new(std::cell::Cell::new(false));
        let auth = Revocable(std::rc::Rc::clone(&revoked));
        let error = guarded_refresh_with(
            &cwd,
            || Ok(auth),
            Account::current(),
            |before_publish| {
                before_publish(false)?;
                revoked.set(true);
                before_publish(true)
            },
        )
        .unwrap_err();
        assert!(error.contains("revoked"), "{error}");
    }

    #[test]
    fn dashboard_refresh_refuses_a_remote_policy_before_the_lock_and_before_publish() {
        let mut state = canonical_data_state();
        let cwd = state.roots().cwd.clone();
        // A legacy policy server; plain HTTP is refused before any socket opens.
        state.set_env("TIRITH_SERVER_URL", "http://127.0.0.1:1");
        state.set_env("TIRITH_API_KEY", "fixture-key");
        let error = refused_before_update(|update| live_refresh(&cwd, update));
        assert!(error.contains("remote policy authority"), "{error}");
        // Checked before the update lock, so a concurrent update cannot mask it.
        let held = super::super::lock_foreground_update().unwrap();
        let error = refused_before_update(|update| live_refresh(&cwd, update));
        assert!(error.contains("remote policy authority"), "{error}");
        drop(held);

        // Configured while the update runs: the publication is refused.
        state.remove_env("TIRITH_SERVER_URL");
        state.remove_env("TIRITH_API_KEY");
        let error = live_refresh(&cwd, |before_publish| {
            before_publish(false)?;
            state.set_env("TIRITH_SERVER_URL", "http://127.0.0.1:1");
            state.set_env("TIRITH_API_KEY", "fixture-key");
            before_publish(true)
        })
        .unwrap_err();
        assert!(error.contains("remote policy authority"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn dashboard_refresh_refuses_the_root_account_before_touching_the_data_directory() {
        let mut state = canonical_data_state();
        state.set_env("TIRITH_LOG", "0");
        let cwd = state.roots().cwd.clone();
        let (root, _) = data_paths().unwrap();
        assert!(!root.exists());
        let error = refused_before_update(|update| {
            guarded_refresh_with(
                &cwd,
                crate::cli::selfupdate::authorize_threatdb_refresh,
                Account { euid: 0 },
                update,
            )
        });
        assert!(error.contains("root account"), "{error}");
        assert!(!root.exists(), "the root refusal must not create {root:?}");
    }

    #[cfg(unix)]
    #[test]
    fn dashboard_refresh_refuses_a_data_directory_owned_by_another_account() {
        let state = canonical_data_state();
        let cwd = state.roots().cwd.clone();
        // The refresh creates the directory as this test's account but runs
        // as another, non-root one.
        let owner = Account::current().euid;
        let other = Account {
            euid: if owner == 1 { 2 } else { 1 },
        };
        let error = refused_before_update(|update| {
            guarded_refresh_with(
                &cwd,
                crate::cli::selfupdate::authorize_threatdb_refresh,
                other,
                update,
            )
        });
        assert!(error.contains("administrator-owned"), "{error}");
    }
}
