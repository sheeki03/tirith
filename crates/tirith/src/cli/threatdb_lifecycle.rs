//! Exact signed ThreatDB candidates and typed local lifecycle operations.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tirith_core::policy_snapshot::{
    EffectivePolicySnapshot, PrivatePolicyReplayGuard, ResolutionMode,
};
use tirith_core::threatdb::ThreatDb;

use crate::cli::control::identity::{BinaryIdentity, DirectoryIdentity};
use crate::cli::selfupdate::lifecycle_operations::{
    Action, Operation, OperationView, Phase, Preview, Store,
};
use crate::cli::selfupdate::lifecycle_service::authorize_threatdb;
use crate::cli::setup::fs_helpers;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "channel", rename_all = "snake_case", deny_unknown_fields)]
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

/// Shared by CLI and browser. All publication uses the exact signed asset;
/// browser callers never request force or choose another candidate on failure.
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
    if bytes.len() as u64 != asset.size || format!("{:x}", Sha256::digest(&bytes)) != asset.sha256 {
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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilePreimage {
    path: PathBuf,
    sha256: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    cwd: PathBuf,
    data_directory: PathBuf,
    policy: PrivatePolicyReplayGuard,
    files: Vec<FilePreimage>,
    candidate: Candidate,
}

struct DataState {
    directory: DirectoryIdentity,
    files: Vec<Option<BinaryIdentity>>,
}

fn data_paths() -> Result<(PathBuf, Vec<PathBuf>), String> {
    // Browser writes stay in the operator's canonical data directory. Redirected
    // cache paths are explicit CLI operations, never browser capabilities.
    if ["TIRITH_THREATDB_PATH", "TIRITH_THREATDB_SUPPLEMENTAL_PATH"]
        .iter()
        .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
    {
        return Err("ThreatDB paths are redirected; use `tirith threat-db update` in the terminal that owns those paths".into());
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

impl DataState {
    fn capture(root: &Path, paths: &[PathBuf]) -> Result<(Self, Vec<FilePreimage>), String> {
        let directory = DirectoryIdentity::capture_trusted(root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata =
                std::fs::symlink_metadata(root).map_err(|_| "cannot inspect ThreatDB directory")?;
            if metadata.uid() != unsafe { libc::geteuid() } {
                return Err("ThreatDB directory is administrator-owned; use the owning terminal or installer".into());
            }
        }
        let mut files = Vec::new();
        let mut preimages = Vec::new();
        for path in paths {
            let held = match std::fs::symlink_metadata(path) {
                Ok(_) => Some(BinaryIdentity::capture(path)?),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(_) => return Err("cannot inspect existing ThreatDB state".into()),
            };
            preimages.push(FilePreimage {
                path: path.clone(),
                sha256: held.as_ref().map(|file| file.sha256().into()),
            });
            files.push(held);
        }
        let result = Self { directory, files };
        result.revalidate(&preimages)?;
        Ok((result, preimages))
    }
    fn revalidate(&self, preimages: &[FilePreimage]) -> Result<(), String> {
        self.directory.revalidate()?;
        if self.files.len() != preimages.len() {
            return Err("ThreatDB preimage list changed".into());
        }
        for (held, before) in self.files.iter().zip(preimages) {
            match held {
                Some(file) => {
                    file.revalidate()?;
                    if Some(file.sha256()) != before.sha256.as_deref() || file.path() != before.path
                    {
                        return Err("ThreatDB preimage changed after preparation".into());
                    }
                }
                None => match std::fs::symlink_metadata(&before.path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    _ => return Err("an absent database entry appeared after preparation".into()),
                },
            }
        }
        Ok(())
    }
}

struct Retained {
    store: Store,
    state: DataState,
}
fn retained() -> &'static Mutex<BTreeMap<String, Arc<Retained>>> {
    static RETAINED: OnceLock<Mutex<BTreeMap<String, Arc<Retained>>>> = OnceLock::new();
    RETAINED.get_or_init(|| Mutex::new(BTreeMap::new()))
}
fn cwd() -> Result<PathBuf, String> {
    std::env::current_dir()
        .and_then(|dir| dir.canonicalize())
        .map_err(|_| "cannot resolve operation working directory".into())
}
fn snapshot(plan: Option<&Plan>) -> Result<EffectivePolicySnapshot, String> {
    let cwd = cwd()?;
    if plan.is_some_and(|plan| plan.cwd != cwd) {
        return Err("working directory changed after ThreatDB preview".into());
    }
    let snapshot = EffectivePolicySnapshot::resolve(cwd.to_str(), ResolutionMode::Runtime);
    snapshot
        .revalidate_for_mutation()
        .map_err(|error| error.to_string())?;
    if plan.is_some_and(|plan| snapshot.private_replay_guard() != plan.policy) {
        return Err(
            "policy, feed settings, trust or environment changed; prepare another ThreatDB refresh"
                .into(),
        );
    }
    Ok(snapshot)
}

pub(crate) fn prepare(id: &str) -> Result<OperationView, String> {
    let store = Store::current()?;
    if store.reserve(id, Action::RefreshThreatDb)?.is_some() {
        return crate::cli::selfupdate::lifecycle_service::status(id);
    }
    let result = prepare_reserved(id, store);
    if result.is_err() {
        let _ = Store::current().and_then(|store| store.fail_preparation(id));
    }
    result
}

fn prepare_reserved(id: &str, store: Store) -> Result<OperationView, String> {
    let auth = authorize_threatdb(
        "browser-threatdb-prepare",
        serde_json::json!({"force":false}),
    )?;
    auth.revalidate()?;
    let policy = snapshot(None)?;
    let (data_directory, paths) = data_paths()?;
    if !data_directory.exists() {
        fs_helpers::ensure_private_directory(&data_directory, &data_directory)?;
    }
    let (state, files) = DataState::capture(&data_directory, &paths)?;
    let candidate = resolve_candidate()?;
    let asset = candidate.asset()?;
    let current = ThreatDb::cached().map(|db| (db.build_sequence(), db.stats().format_version));
    super::index_install_needed(asset.sequence, asset.format, current, false)?;
    let preview = Preview {
        current_version: env!("CARGO_PKG_VERSION").into(),
        candidate_version: None,
        candidate_sequence: Some(asset.sequence),
        candidate_format: Some(asset.format),
        evidence: "pinned_ed25519_signed_manifest_and_internal_database_signature_required".into(),
        compatible: true,
        issues: vec![],
        configuration_changed: false,
        integration_reload_required: false,
        service_restart_required: false,
    };
    state.revalidate(&files)?;
    policy
        .revalidate_for_mutation()
        .map_err(|error| error.to_string())?;
    auth.revalidate()?;
    let plan = Plan {
        cwd: cwd()?,
        data_directory,
        policy: policy.private_replay_guard(),
        files,
        candidate,
    };
    let held = Arc::new(Retained { store, state });
    let mut registry = retained()
        .lock()
        .map_err(|_| "ThreatDB preview registry unavailable")?;
    registry.retain(|id, held| {
        held.store
            .load::<Plan>(id)
            .is_ok_and(|operation| operation.phase() == Phase::Prepared && !operation.is_expired())
    });
    if registry.len() >= 16 {
        return Err("too many ThreatDB previews; cancel an unused preview first".into());
    }
    let operation = held
        .store
        .create(id, Action::RefreshThreatDb, preview, plan)?;
    registry.insert(operation.id().into(), held);
    Ok(operation.view())
}

pub(crate) fn release_preview(id: &str) -> Result<(), String> {
    retained()
        .lock()
        .map_err(|_| "ThreatDB preview registry unavailable")?
        .remove(id);
    Ok(())
}
pub(crate) fn has_preview(id: &str) -> bool {
    retained()
        .lock()
        .is_ok_and(|registry| registry.contains_key(id))
}

/// Called as a counted control-service job. It needs no service restart or
/// elevation. A binary update waits for this job through normal quiescence.
pub(crate) fn apply(id: &str) -> Result<OperationView, String> {
    let held = retained()
        .lock()
        .map_err(|_| "ThreatDB preview registry unavailable")?
        .remove(id)
        .ok_or("ThreatDB preview context was lost or already applied; prepare a fresh preview")?;
    let _operation_lock = held
        .store
        .lock(id)?
        .ok_or("this operation already has an active worker")?;
    let mut operation = held.store.load::<Plan>(id)?;
    held.store.require_original_client(&operation)?;
    if operation.phase() != Phase::Prepared || operation.is_expired() {
        return Err(
            "ThreatDB preview expired or was already accepted; inspect status and prepare again"
                .into(),
        );
    }
    let auth = authorize_threatdb(
        "browser-threatdb-apply",
        serde_json::json!({"operation_id":id,"plan_sha256":operation.plan_sha256(),"force":false}),
    )?;
    let _update_lock = super::lock_foreground_update()?;
    held.state.revalidate(&operation.payload().files)?;
    snapshot(Some(operation.payload()))?;
    held.store.transition(
        &mut operation,
        Phase::Accepted,
        false,
        None,
        "Refreshing the exact signed ThreatDB candidate.",
    )?;
    held.store.transition(
        &mut operation,
        Phase::Verifying,
        false,
        None,
        "Validating signed database bytes; the previous database remains active until publication.",
    )?;
    let result = apply_inner(&held, &mut operation, &auth);
    if let Err(error) = result {
        let _ = held.store.record_failure(operation.id(), &error);
        let started = matches!(
            operation.phase(),
            Phase::PublicationIntent | Phase::Published
        );
        let published = operation.view().published;
        held.store.transition(&mut operation, if started { Phase::RecoveryRequired } else { Phase::Failed }, published, Some(if started { "refresh_publication_requires_inspection" } else { "refresh_failed" }), "Refresh stopped. Retain the last-known-good databases, inspect health, and prepare a new explicit refresh; this operation will not choose another generation.")?;
        super::evidence::record("primary", Some(&error));
        return Err(error);
    }
    Ok(operation.view())
}

fn apply_inner(
    held: &Retained,
    operation: &mut Operation<Plan>,
    auth: &crate::cli::selfupdate::lifecycle_service::ThreatDbAuthorization,
) -> Result<(), String> {
    let candidate = operation.payload().candidate.clone();
    // Download and verify BEFORE publication intent, then keep the same signed
    // candidate for publication. The callback transitions immediately before the
    // durable write; RefCell serializes this synchronous one-worker callback.
    let operation_cell = std::cell::RefCell::new(operation);
    let outcome = apply_primary(&candidate, false, |will_publish| {
        auth.revalidate()?;
        let mut operation = operation_cell.borrow_mut();
        held.store.revalidate()?;
        held.state.revalidate(&operation.payload().files)?;
        snapshot(Some(operation.payload()))?;
        if will_publish && operation.phase() == Phase::Verifying {
            held.store.transition(
                &mut operation,
                Phase::PublicationIntent,
                false,
                None,
                "Signed database bytes verified; exact database publication is starting.",
            )?;
        }
        Ok(())
    })?;
    let operation = operation_cell.into_inner();
    ThreatDb::refresh_cache();
    let published = outcome == super::UpdateOutcome::Installed;
    if published {
        held.store.transition(
            operation,
            Phase::Published,
            true,
            None,
            "The exact signed primary database was installed and verified.",
        )?;
    }
    let (root, paths) = data_paths()?;
    if root != operation.payload().data_directory {
        return Err("ThreatDB data scope changed during publication".into());
    }
    let (after_primary, preimages) = DataState::capture(&root, &paths)?;
    let policy = snapshot(Some(operation.payload()))?;
    auth.revalidate()?;
    let supplemental = super::update_supplemental_db_checked(&policy.policy, &|| {
        auth.revalidate()?;
        held.store.revalidate()?;
        after_primary.revalidate(&preimages)?;
        snapshot(Some(operation.payload()))?;
        Ok(())
    });
    match supplemental {
        Ok(()) => {
            super::evidence::record("complete", None);
            held.store.transition(operation, Phase::Completed, published, None, "Signed ThreatDB generation is current. Enabled supplemental feeds were reconciled; shell protection continues without restart.")?;
        }
        Err(error) => {
            super::evidence::record("supplemental", Some(&error));
            held.store.transition(operation, Phase::Partial, published, Some("supplemental_refresh_incomplete"), "The signed primary generation is current. A supplemental feed failed; its prior valid overlay was retained. Inspect ThreatDB health and explicitly retry later.")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_candidate_reauthenticates_signature_before_any_download() {
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

    #[test]
    fn candidate_plan_cannot_enable_forced_or_arbitrary_actions() {
        assert!(serde_json::from_value::<Candidate>(
            serde_json::json!({"channel":"unsigned","url":"https://example.invalid","force":true})
        )
        .is_err());
    }
}
