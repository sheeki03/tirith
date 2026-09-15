//! Narrow writer authority for the organization policy already selected by the
//! resolver. A request never supplies a path or creates a new authority root.
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tirith_core::policy_rollout::RolloutScope;
use tirith_core::policy_snapshot::EffectivePolicySnapshot;

use super::setup::change_plan::OperationKind;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProfileScope {
    #[default]
    User,
    Org,
}

impl ProfileScope {
    pub fn is_user(&self) -> bool {
        *self == Self::User
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Org => "org",
        }
    }
    pub fn operation_kind(self) -> OperationKind {
        match self {
            Self::User => OperationKind::SetProfile,
            Self::Org => OperationKind::SetManagedProfile,
        }
    }
    pub fn report_scope(self) -> RolloutScope {
        match self {
            Self::User => RolloutScope::PersonalUser,
            Self::Org => RolloutScope::LocalManaged,
        }
    }
}

/// Read-only authorization, repeated by the journal before every managed write.
/// Remote/fallback snapshots cannot authorize this local publication.
pub(crate) fn selected_target(
    snapshot: &EffectivePolicySnapshot,
) -> Result<(PathBuf, PathBuf), String> {
    snapshot
        .revalidate_for_mutation()
        .map_err(|error| error.to_string())?;
    let root = std::env::var("TIRITH_POLICY_ROOT")
        .map_err(|_| "organization rollout requires the selected TIRITH_POLICY_ROOT authority")?;
    let root = PathBuf::from(root.trim());
    if !root.is_absolute()
        || root
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err("organization policy root must be absolute without parent traversal".into());
    }
    let directory = root.join(".tirith");
    let (path, scope) =
        tirith_core::policy::discover_local_policy_path_scoped(snapshot.resolution_cwd())
            .ok_or("no selected organization policy exists")?;
    if scope != tirith_core::policy::PolicyScope::Org
        || path.parent() != Some(directory.as_path())
        || !snapshot.operator_targets.iter().any(|target| {
            target.scope == "org" && Path::new(&target.path) == path && target.effective
        })
    {
        return Err(
            "organization rollout must target the existing selected organization authority".into(),
        );
    }
    validate_native_owner(&root, &directory, &path)?;
    snapshot
        .revalidate_inputs()
        .map_err(|_| "organization policy selection changed during authorization")?;
    Ok((directory, path))
}

pub(crate) fn authorize_target(
    root: &Path,
    target: &Path,
    snapshot: &EffectivePolicySnapshot,
) -> Result<(), String> {
    let (selected_root, selected_path) = selected_target(snapshot)?;
    if selected_root != root || selected_path != target {
        return Err("managed operation no longer owns the selected organization authority".into());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_native_owner(root: &Path, directory: &Path, target: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let uid = unsafe { libc::geteuid() };
    if uid == 0 || uid != unsafe { libc::getuid() } {
        return Err("organization rollout requires an ordinary file-owning operator without privilege escalation".into());
    }
    let operator = super::shell_target::resolve_for_shell("unknown")?;
    super::shell_target::require_personal_writer(&operator)?;
    for path in [root, directory] {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| "cannot inspect the selected organization policy root")?;
        if !metadata.is_dir() || !owner_mode_allowed(uid, metadata.uid(), metadata.mode()) {
            return Err("organization policy roots must be real operator-owned directories without group or world write permission".into());
        }
    }
    let metadata = std::fs::symlink_metadata(target)
        .map_err(|_| "cannot inspect the selected organization policy file")?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || !owner_mode_allowed(uid, metadata.uid(), metadata.mode())
    {
        return Err("organization policy must be a regular, singly linked operator-owned file without group or world write permission".into());
    }
    Ok(())
}

#[cfg(unix)]
fn owner_mode_allowed(operator: u32, owner: u32, mode: u32) -> bool {
    operator != 0 && operator == owner && mode & 0o022 == 0
}

#[cfg(not(unix))]
fn validate_native_owner(_root: &Path, _directory: &Path, _target: &Path) -> Result<(), String> {
    Err("local managed rollout writer is unavailable on this platform; native ownership authorization is not implemented".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_accepts_only_the_two_implemented_authorities() {
        assert_eq!(
            serde_json::from_str::<ProfileScope>("\"org\"").unwrap(),
            ProfileScope::Org
        );
        for value in ["remote", "repo", "incident", "managed", "ORG"] {
            assert!(serde_json::from_value::<ProfileScope>(serde_json::json!(value)).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn owner_gate_rejects_other_owners_privilege_and_shared_write_modes() {
        assert!(owner_mode_allowed(501, 501, 0o100600));
        assert!(owner_mode_allowed(501, 501, 0o40755));
        for (operator, owner, mode) in [
            (501, 502, 0o100600),
            (501, 0, 0o100600),
            (0, 0, 0o100600),
            (501, 501, 0o100620),
            (501, 501, 0o40777),
        ] {
            assert!(!owner_mode_allowed(operator, owner, mode));
        }
    }
}
