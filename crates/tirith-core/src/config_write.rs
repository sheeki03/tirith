//! A single-use permit for a Tirith-owned configuration write (C12).
//!
//! The final rename of a config file is irreversible: once the directory entry
//! points at the new inode, the previous contents are gone. This type holds that
//! transition open. It binds, at preparation time, the parent capability, the
//! final component, the observed preimage identity/digest, the exact output
//! bytes, the policy identity in force, and the overwrite decision; and it
//! re-checks those bindings again at commit, immediately before publication.
//!
//! Three deliberate shapes, copied from [`crate::execution_state::GatewayExecutionPermit`]
//! rather than invented:
//!
//! - **Not `Clone`, not `Copy`.** A permit that can be duplicated is a permit
//!   that can authorise two writes.
//! - **Single use.** [`ConfigWritePermit::commit`] takes `self`, so the type
//!   system, not a runtime flag, makes a second commit unexpressible.
//! - **Digest-only `Debug`.** The permit knows a path and a payload; a log line
//!   or a panic message must not learn either. Only hashes are printed.
//!
//! The publication itself is delegated to [`ContainedAtomicFile`], the existing
//! bound atomic-file primitive: this type adds binding and single use, and never
//! re-implements the write. In particular the retained parent capability stays
//! authoritative for the rename, so re-validating the visible path at commit is
//! an additional check and never the thing the write trusts.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::command_card::sha256_hex;
use crate::effects::CommandEffectKind;
use crate::task_boundary::{
    config_write_envelope, BoundaryOperation, ConfigWriteBoundary, ConfigWriteOperationBinding,
    OwnedBoundary, TaskBoundaryPermit,
};
use crate::util::{ContainedAtomicFile, ContainedFilePreimage};

#[cfg(test)]
thread_local! {
    static PRE_PUBLISH_TEST_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static POST_PUBLISH_TEST_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn run_pre_publish_test_hook() {
    PRE_PUBLISH_TEST_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
fn run_post_publish_test_hook() {
    POST_PUBLISH_TEST_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

/// Why a bound config write refused to publish.
#[derive(Debug)]
pub enum ConfigWriteError {
    /// The bytes handed to `commit` are not the bytes the permit was issued
    /// for. Either the caller regenerated them, or something changed them in
    /// between; neither is authorised by this permit.
    ContentMismatch,
    /// The destination is no longer bound beneath the root the permit was
    /// prepared against.
    BindingLost(std::io::Error),
    /// The publication itself failed.
    Io(std::io::Error),
    /// The typed task authorization did not bind the exact configuration-write
    /// operation or the operation named a different destination.
    AuthorizationMismatch,
}

impl fmt::Display for ConfigWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No path and no content in any message, so this type is safe to print
        // anywhere, including the shared logs some CLI surfaces write to. The
        // inner errors are deliberately reduced to their `ErrorKind`: the ones
        // `ContainedAtomicFile` produces embed the absolute destination path,
        // and a private config path reaching a shared log is the exact defect
        // C05 had to fix once already. A caller that legitimately wants to show
        // the operator their own path converts through the `From` impl below,
        // which hands back the untouched inner error.
        match self {
            Self::ContentMismatch => write!(
                formatter,
                "refusing to publish: the content digest changed after the permit was issued"
            ),
            Self::BindingLost(error) => write!(
                formatter,
                "refusing to publish: the destination is no longer bound beneath its root ({})",
                error.kind()
            ),
            Self::Io(error) => write!(
                formatter,
                "could not publish the configuration ({})",
                error.kind()
            ),
            Self::AuthorizationMismatch => write!(
                formatter,
                "refusing to publish: task authorization does not bind this configuration write"
            ),
        }
    }
}

impl std::error::Error for ConfigWriteError {}

impl From<ConfigWriteError> for std::io::Error {
    fn from(error: ConfigWriteError) -> Self {
        match error {
            ConfigWriteError::Io(error) | ConfigWriteError::BindingLost(error) => error,
            ConfigWriteError::ContentMismatch => {
                std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
            }
            ConfigWriteError::AuthorizationMismatch => {
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, error.to_string())
            }
        }
    }
}

/// A held, single-use authorisation to publish one exact configuration payload
/// to one bound destination.
pub struct ConfigWritePermit {
    /// The retained parent capability. Authoritative for the publication.
    destination: ContainedAtomicFile,
    root: PathBuf,
    path: PathBuf,
    destination_display: String,
    root_identity_sha256: String,
    destination_identity_sha256: String,
    content_sha256: String,
    preimage_sha256: Option<String>,
    expected_preimage: Option<ContainedFilePreimage>,
    /// [`crate::policy::Policy::security_projection_hash`] at issue time, so an
    /// audit can tell which posture authorised the write.
    policy_identity: String,
    overwrite: bool,
    policy_change: bool,
}

impl fmt::Debug for ConfigWritePermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigWritePermit")
            .field("content_sha256", &self.content_sha256)
            .field(
                "preimage_sha256",
                &self
                    .expected_preimage
                    .as_ref()
                    .map(ContainedFilePreimage::projection_sha256),
            )
            .field("destination_sha256", &self.destination_identity_sha256)
            .field("policy_identity", &self.policy_identity)
            .field("overwrite", &self.overwrite)
            .field("policy_change", &self.policy_change)
            .finish_non_exhaustive()
    }
}

impl ConfigWritePermit {
    /// Bind `path` beneath `root` and take out a permit for exactly `contents`.
    ///
    /// Preparation retains the parent capability. Nothing is published here; a
    /// permit that is dropped without [`ConfigWritePermit::commit`] leaves the
    /// destination untouched.
    pub fn prepare(
        root: &Path,
        path: &Path,
        contents: &[u8],
        overwrite: bool,
        policy_identity: &str,
    ) -> std::io::Result<Self> {
        Self::prepare_owned(
            root,
            path,
            contents,
            overwrite,
            policy_identity,
            false,
            false,
        )
    }

    /// Prepare a Tirith-owned write and retain its exact destination capability.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_owned(
        root: &Path,
        path: &Path,
        contents: &[u8],
        overwrite: bool,
        policy_identity: &str,
        policy_change: bool,
        create_parent: bool,
    ) -> std::io::Result<Self> {
        // Validate and derive the complete operation identity before a
        // create-parent preparation can have any filesystem side effect.
        let _ = Self::operation_envelope_for(
            root,
            path,
            contents,
            overwrite,
            policy_identity,
            policy_change,
        )?;
        let destination = ContainedAtomicFile::prepare(root, path, create_parent)?;
        Self::from_prepared(
            destination,
            root,
            path,
            contents,
            overwrite,
            policy_identity,
            policy_change,
        )
    }

    /// Bind a capability already retained across a read-modify-write sequence.
    #[allow(clippy::too_many_arguments)]
    pub fn from_prepared(
        destination: ContainedAtomicFile,
        root: &Path,
        path: &Path,
        contents: &[u8],
        overwrite: bool,
        policy_identity: &str,
        policy_change: bool,
    ) -> std::io::Result<Self> {
        let absolute_root = std::path::absolute(root)?;
        let absolute_path = std::path::absolute(path)?;
        let destination_display = absolute_path.to_str().ok_or_else(non_utf8_destination)?;
        absolute_root.to_str().ok_or_else(non_utf8_destination)?;
        let retained_identity = destination.binding_identity()?;
        let visible = ContainedAtomicFile::prepare(root, path, false)?;
        if visible.binding_identity()? != retained_identity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "prepared configuration capability does not match its declared destination",
            ));
        }
        let content_sha256 = sha256_hex(contents);
        let expected_preimage = destination.observed_preimage()?;
        let preimage_sha256 = expected_preimage
            .as_ref()
            .map(ContainedFilePreimage::projection_sha256);
        Ok(Self {
            destination,
            root: root.to_path_buf(),
            path: path.to_path_buf(),
            destination_display: destination_display.to_string(),
            root_identity_sha256: identity_digest("root-capability", retained_identity.root()),
            destination_identity_sha256: identity_digest(
                "destination-capability",
                retained_identity.destination(),
            ),
            content_sha256,
            preimage_sha256,
            expected_preimage,
            policy_identity: policy_identity.to_string(),
            overwrite,
            policy_change,
        })
    }

    /// The digest this permit authorises.
    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }

    /// The policy identity in force when the permit was issued.
    pub fn policy_identity(&self) -> &str {
        &self.policy_identity
    }

    /// Exact task envelope reconstructed from this retained capability.
    pub fn operation_envelope(&self) -> crate::task::TaskEnvelopeInput {
        config_write_envelope(&self.operation_binding())
    }

    /// Construct a path-level projection for side-effect-free authorization
    /// preflight. Publication must use a prepared permit whose final operation
    /// is rebuilt from the retained filesystem capability.
    #[allow(clippy::too_many_arguments)]
    pub fn operation_envelope_for(
        root: &Path,
        path: &Path,
        contents: &[u8],
        overwrite: bool,
        policy_identity: &str,
        policy_change: bool,
    ) -> std::io::Result<crate::task::TaskEnvelopeInput> {
        let absolute_root = std::path::absolute(root)?;
        let absolute_path = std::path::absolute(path)?;
        let root_display = absolute_root.to_str().ok_or_else(non_utf8_destination)?;
        let destination_display = absolute_path.to_str().ok_or_else(non_utf8_destination)?;
        let root_identity = identity_digest("root", root_display);
        let destination_identity = identity_digest("destination", destination_display);
        let content_sha256 = sha256_hex(contents);
        Ok(config_write_envelope(&ConfigWriteOperationBinding::new(
            destination_display,
            &root_identity,
            &destination_identity,
            &content_sha256,
            None,
            overwrite,
            policy_identity,
            policy_change,
        )))
    }

    /// Boundary-known effects for this exact publication.
    pub fn boundary_effects(&self) -> std::collections::BTreeSet<CommandEffectKind> {
        Self::boundary_effects_for(self.policy_change)
    }

    pub fn boundary_effects_for(
        policy_change: bool,
    ) -> std::collections::BTreeSet<CommandEffectKind> {
        policy_change
            .then_some(CommandEffectKind::PolicyChange)
            .into_iter()
            .collect()
    }

    /// Pure pre-replay check for the exact bytes and task operation. The
    /// authorized commit repeats this check after replay consumption and
    /// filesystem revalidation at the publication seam.
    pub fn binds_publication(&self, contents: &[u8], operation: &BoundaryOperation<'_>) -> bool {
        sha256_hex(contents) == self.content_sha256 && self.binds_operation(operation)
    }

    /// Publish through the compatibility library API, consuming the permit.
    ///
    /// This API predates typed task-boundary permits. It remains public for
    /// external library compatibility, but it is outside Tirith-owned CLI
    /// boundaries and must not be used by Tirith's own configuration writers.
    /// Owned callers use [`Self::commit_authorized`] so publication consumes
    /// both the filesystem capability and its exact task authorization.
    pub fn commit(self, contents: &[u8]) -> Result<(), ConfigWriteError> {
        self.validate_for_publication(contents)?;
        self.publish(contents)
    }

    /// Publish one Tirith-owned configuration write, consuming both permits.
    ///
    /// The task permit is type-bound to ConfigWriteBoundary and is checked
    /// against the exact operation after payload and filesystem revalidation,
    /// immediately before the retained destination capability publishes. The
    /// operation must also name this permit's exact destination.
    pub fn commit_authorized(
        self,
        contents: &[u8],
        authorization: TaskBoundaryPermit<ConfigWriteBoundary>,
        operation: &BoundaryOperation<'_>,
    ) -> Result<(), ConfigWriteError> {
        self.validate_for_publication(contents)?;
        if !authorization.binds_operation(operation) || !self.binds_operation(operation) {
            return Err(ConfigWriteError::AuthorizationMismatch);
        }
        self.publish(contents)
    }

    fn validate_for_publication(&self, contents: &[u8]) -> Result<(), ConfigWriteError> {
        if sha256_hex(contents) != self.content_sha256 {
            return Err(ConfigWriteError::ContentMismatch);
        }
        self.visible_destination()?;
        Ok(())
    }

    fn visible_destination(&self) -> Result<ContainedAtomicFile, ConfigWriteError> {
        // Re-resolving proves the visible path has not become an escape since
        // the permit was issued. The write below still goes through the ORIGINAL
        // retained capability, so this check can only refuse, never redirect.
        let visible = ContainedAtomicFile::prepare(&self.root, &self.path, false)
            .map_err(ConfigWriteError::BindingLost)?;
        let visible_identity = visible
            .binding_identity()
            .map_err(ConfigWriteError::BindingLost)?;
        let retained_identity = self
            .destination
            .binding_identity()
            .map_err(ConfigWriteError::BindingLost)?;
        if visible_identity != retained_identity {
            return Err(ConfigWriteError::BindingLost(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "visible configuration destination no longer matches the retained capability",
            )));
        }
        Ok(visible)
    }

    fn binds_operation(&self, operation: &BoundaryOperation<'_>) -> bool {
        operation.boundary == OwnedBoundary::ConfigWrite
            && operation.envelope == &self.operation_envelope()
            && operation.boundary_effects == self.boundary_effects()
    }

    fn operation_binding(&self) -> ConfigWriteOperationBinding<'_> {
        ConfigWriteOperationBinding::new(
            &self.destination_display,
            &self.root_identity_sha256,
            &self.destination_identity_sha256,
            &self.content_sha256,
            self.preimage_sha256.as_deref(),
            self.overwrite,
            &self.policy_identity,
            self.policy_change,
        )
    }

    fn publish(self, contents: &[u8]) -> Result<(), ConfigWriteError> {
        self.destination
            .write_atomic_checked(contents, self.overwrite, || {
                #[cfg(test)]
                run_pre_publish_test_hook();
                self.destination
                    .verify_observed_preimage(&self.expected_preimage)?;
                self.visible_destination()
                    .map(|_| ())
                    .map_err(std::io::Error::from)
            })
            .map_err(ConfigWriteError::Io)?;

        #[cfg(test)]
        run_post_publish_test_hook();

        // A retained-parent rename cannot redirect publication, but without a
        // postcondition it could make a successful write disappear from the
        // operator-visible path. Rebind and read back exact bytes before success.
        let visible = self.visible_destination()?;
        let cap = u64::try_from(contents.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let read_back = visible.read_capped(cap).map_err(|_| {
            ConfigWriteError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "configuration publication could not be read back",
            ))
        })?;
        if read_back != contents {
            return Err(ConfigWriteError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "configuration publication failed exact read-back validation",
            )));
        }
        Ok(())
    }
}

fn identity_digest(kind: &str, value: &str) -> String {
    sha256_hex(format!("tirith-config-write-{kind}:v1:{value}").as_bytes())
}

fn non_utf8_destination() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "configuration destinations must be valid UTF-8",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use crate::task::IngressAdapter;
    use crate::task_analysis::TaskAnalysisContext;
    use crate::task_boundary::prepare_locally_derived_boundary_authorization;
    use crate::web3_policy::TaskGatePolicy;

    fn temp_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    fn config_operation<'a>(
        envelope: &'a crate::task::TaskEnvelopeInput,
        boundary_effects: BTreeSet<CommandEffectKind>,
    ) -> BoundaryOperation<'a> {
        BoundaryOperation {
            boundary: OwnedBoundary::ConfigWrite,
            envelope,
            adapter: IngressAdapter::Unattributed,
            boundary_effects,
        }
    }

    fn authorization(operation: &BoundaryOperation<'_>) -> TaskBoundaryPermit<ConfigWriteBoundary> {
        prepare_locally_derived_boundary_authorization::<ConfigWriteBoundary>(
            operation,
            &TaskGatePolicy::default(),
            &TaskAnalysisContext::default(),
        )
        .expect("prepare task authorization")
        .consume_default(chrono::Utc::now())
        .expect("consume task authorization")
    }

    #[test]
    fn a_committed_permit_publishes_the_exact_bytes() {
        let root = temp_root();
        let path = root.path().join("policy.yaml");
        let permit =
            ConfigWritePermit::prepare(root.path(), &path, b"safe: true\n", true, "policy-id")
                .expect("prepare");
        permit.commit(b"safe: true\n").expect("commit");
        assert_eq!(
            std::fs::read(&path).expect("read back"),
            b"safe: true\n".to_vec()
        );
    }

    #[test]
    fn authorized_commit_consumes_both_exact_permits() {
        let root = temp_root();
        let path = root.path().join("policy.yaml");
        let write_permit =
            ConfigWritePermit::prepare(root.path(), &path, b"safe: true\n", true, "policy-id")
                .expect("prepare write");
        let envelope = write_permit.operation_envelope();
        let operation = config_operation(&envelope, write_permit.boundary_effects());
        let boundary_permit = authorization(&operation);

        write_permit
            .commit_authorized(b"safe: true\n", boundary_permit, &operation)
            .expect("authorized commit");
        assert_eq!(std::fs::read(&path).expect("read back"), b"safe: true\n");
    }

    #[test]
    fn authorized_commit_rejects_a_task_permit_for_another_operation() {
        let root = temp_root();
        let path = root.path().join("policy.yaml");
        let other = root.path().join("other.yaml");
        let write_permit =
            ConfigWritePermit::prepare(root.path(), &path, b"safe\n", true, "policy-id")
                .expect("prepare write");
        let envelope = write_permit.operation_envelope();
        let operation = config_operation(&envelope, write_permit.boundary_effects());
        let other_permit =
            ConfigWritePermit::prepare(root.path(), &other, b"safe\n", true, "policy-id")
                .expect("prepare other write");
        let other_envelope = other_permit.operation_envelope();
        let other_operation = config_operation(&other_envelope, other_permit.boundary_effects());
        let boundary_permit = authorization(&other_operation);

        let error = write_permit
            .commit_authorized(b"safe\n", boundary_permit, &operation)
            .expect_err("mismatched task permit must refuse");
        assert!(matches!(error, ConfigWriteError::AuthorizationMismatch));
        assert!(!path.exists());
    }

    #[test]
    fn authorized_commit_rejects_a_filesystem_permit_for_another_destination() {
        let root = temp_root();
        let authorized_path = root.path().join("authorized.yaml");
        let actual_path = root.path().join("actual.yaml");
        let authorized_write =
            ConfigWritePermit::prepare(root.path(), &authorized_path, b"safe\n", true, "policy-id")
                .expect("prepare authorized write");
        let envelope = authorized_write.operation_envelope();
        let operation = config_operation(&envelope, authorized_write.boundary_effects());
        let boundary_permit = authorization(&operation);
        let write_permit =
            ConfigWritePermit::prepare(root.path(), &actual_path, b"safe\n", true, "policy-id")
                .expect("prepare write");

        let error = write_permit
            .commit_authorized(b"safe\n", boundary_permit, &operation)
            .expect_err("mismatched destination must refuse");
        assert!(matches!(error, ConfigWriteError::AuthorizationMismatch));
        assert!(!authorized_path.exists());
        assert!(!actual_path.exists());
    }

    #[test]
    fn from_prepared_rejects_a_capability_for_another_destination() {
        let root = temp_root();
        let declared = root.path().join("declared.yaml");
        let actual = root.path().join("actual.yaml");
        let destination = ContainedAtomicFile::prepare(root.path(), &actual, false)
            .expect("prepare actual destination");

        let error = ConfigWritePermit::from_prepared(
            destination,
            root.path(),
            &declared,
            b"safe\n",
            true,
            "policy-id",
            true,
        )
        .expect_err("a retained capability must match its declared destination");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!declared.exists());
        assert!(!actual.exists());
    }

    #[cfg(unix)]
    #[test]
    fn authorized_commit_rejects_an_ordinary_parent_directory_replacement() {
        let root = temp_root();
        let config = root.path().join(".tirith");
        let displaced = root.path().join(".tirith-displaced");
        std::fs::create_dir(&config).expect("create config");
        let path = config.join("policy.yaml");
        let write_permit = ConfigWritePermit::prepare_owned(
            root.path(),
            &path,
            b"safe\n",
            true,
            "policy-id",
            true,
            false,
        )
        .expect("prepare write");
        let envelope = write_permit.operation_envelope();
        let operation = config_operation(&envelope, write_permit.boundary_effects());
        let boundary_permit = authorization(&operation);

        std::fs::rename(&config, &displaced).expect("displace held directory");
        std::fs::create_dir(&config).expect("create ordinary replacement");
        let error = write_permit
            .commit_authorized(b"safe\n", boundary_permit, &operation)
            .expect_err("visible identity replacement must refuse");

        assert!(matches!(error, ConfigWriteError::BindingLost(_)));
        assert!(!path.exists());
        assert!(!displaced.join("policy.yaml").exists());
    }

    #[cfg(unix)]
    #[test]
    fn authorized_commit_rechecks_visible_parent_at_final_publication_seam() {
        let root = temp_root();
        let config = root.path().join(".tirith");
        let displaced = root.path().join(".tirith-displaced");
        std::fs::create_dir(&config).expect("create config");
        let path = config.join("policy.yaml");
        let write_permit = ConfigWritePermit::prepare_owned(
            root.path(),
            &path,
            b"safe\n",
            true,
            "policy-id",
            true,
            false,
        )
        .expect("prepare write");
        let envelope = write_permit.operation_envelope();
        let operation = config_operation(&envelope, write_permit.boundary_effects());
        let boundary_permit = authorization(&operation);
        let hook_config = config.clone();
        let hook_displaced = displaced.clone();
        PRE_PUBLISH_TEST_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                std::fs::rename(&hook_config, &hook_displaced).unwrap();
                std::fs::create_dir(&hook_config).unwrap();
            }));
        });

        write_permit
            .commit_authorized(b"safe\n", boundary_permit, &operation)
            .expect_err("the final-seam visible identity check must refuse");

        assert!(!path.exists());
        assert!(!displaced.join("policy.yaml").exists());
        assert_eq!(std::fs::read_dir(&displaced).unwrap().count(), 0);
    }

    #[test]
    fn authorized_rmw_refuses_a_changed_present_preimage_at_publication_seam() {
        let root = temp_root();
        let path = root.path().join("policy.yaml");
        std::fs::write(&path, b"old\n").unwrap();
        let destination = ContainedAtomicFile::prepare(root.path(), &path, false).unwrap();
        destination.lock_parent_for_mutation().unwrap();
        assert_eq!(destination.read_capped(1024).unwrap(), b"old\n");
        let write_permit = ConfigWritePermit::from_prepared(
            destination,
            root.path(),
            &path,
            b"rendered from old\n",
            true,
            "policy-id",
            true,
        )
        .unwrap();
        let envelope = write_permit.operation_envelope();
        let operation = config_operation(&envelope, write_permit.boundary_effects());
        let boundary_permit = authorization(&operation);
        let competing_path = path.clone();
        PRE_PUBLISH_TEST_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                std::fs::write(&competing_path, b"competing\n").unwrap();
            }));
        });

        write_permit
            .commit_authorized(b"rendered from old\n", boundary_permit, &operation)
            .expect_err("a stale read-modify-write must refuse publication");
        assert_eq!(std::fs::read(&path).unwrap(), b"competing\n");
    }

    #[test]
    fn authorized_rmw_refuses_when_an_absent_preimage_appears_at_publication_seam() {
        let root = temp_root();
        let path = root.path().join("policy.yaml");
        let destination = ContainedAtomicFile::prepare(root.path(), &path, false).unwrap();
        destination.lock_parent_for_mutation().unwrap();
        assert!(matches!(
            destination.read_capped(1024),
            Err(crate::util::OpenRegularError::NotFound)
        ));
        let write_permit = ConfigWritePermit::from_prepared(
            destination,
            root.path(),
            &path,
            b"new\n",
            true,
            "policy-id",
            true,
        )
        .unwrap();
        let envelope = write_permit.operation_envelope();
        let operation = config_operation(&envelope, write_permit.boundary_effects());
        let boundary_permit = authorization(&operation);
        let competing_path = path.clone();
        PRE_PUBLISH_TEST_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                std::fs::write(&competing_path, b"appeared\n").unwrap();
            }));
        });

        write_permit
            .commit_authorized(b"new\n", boundary_permit, &operation)
            .expect_err("an absent preimage that appeared must refuse publication");
        assert_eq!(std::fs::read(&path).unwrap(), b"appeared\n");
    }

    #[test]
    fn exact_operation_projection_binds_the_observed_preimage() {
        let first_root = temp_root();
        let second_root = temp_root();
        let first_path = first_root.path().join("policy.yaml");
        let second_path = second_root.path().join("policy.yaml");
        std::fs::write(&first_path, b"first\n").unwrap();
        std::fs::write(&second_path, b"second\n").unwrap();

        let first_destination =
            ContainedAtomicFile::prepare(first_root.path(), &first_path, false).unwrap();
        let second_destination =
            ContainedAtomicFile::prepare(second_root.path(), &second_path, false).unwrap();
        first_destination.read_capped(1024).unwrap();
        second_destination.read_capped(1024).unwrap();
        let first = ConfigWritePermit::from_prepared(
            first_destination,
            first_root.path(),
            &first_path,
            b"same output\n",
            true,
            "policy-id",
            true,
        )
        .unwrap();
        let second = ConfigWritePermit::from_prepared(
            second_destination,
            second_root.path(),
            &second_path,
            b"same output\n",
            true,
            "policy-id",
            true,
        )
        .unwrap();

        assert_ne!(
            first.preimage_sha256, second.preimage_sha256,
            "the same postimage derived from different preimages needs distinct authorization"
        );
    }

    #[cfg(unix)]
    #[test]
    fn authorized_commit_never_reports_success_when_publication_disappears_from_view() {
        let root = temp_root();
        let config = root.path().join(".tirith");
        let displaced = root.path().join(".tirith-displaced");
        std::fs::create_dir(&config).expect("create config");
        let path = config.join("policy.yaml");
        let write_permit = ConfigWritePermit::prepare_owned(
            root.path(),
            &path,
            b"safe\n",
            true,
            "policy-id",
            true,
            false,
        )
        .expect("prepare write");
        let envelope = write_permit.operation_envelope();
        let operation = config_operation(&envelope, write_permit.boundary_effects());
        let boundary_permit = authorization(&operation);
        let hook_config = config.clone();
        let hook_displaced = displaced.clone();
        POST_PUBLISH_TEST_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                std::fs::rename(&hook_config, &hook_displaced).unwrap();
                std::fs::create_dir(&hook_config).unwrap();
            }));
        });

        let error = write_permit
            .commit_authorized(b"safe\n", boundary_permit, &operation)
            .expect_err("a post-publication visible identity change must refuse success");

        assert!(matches!(error, ConfigWriteError::BindingLost(_)));
        assert!(!path.exists());
        assert_eq!(
            std::fs::read(displaced.join("policy.yaml")).unwrap(),
            b"safe\n"
        );
    }

    #[test]
    fn authorized_commit_rejects_every_exact_operation_mutation() {
        struct Mutation {
            label: &'static str,
            other_root: bool,
            contents: &'static [u8],
            overwrite: bool,
            policy_identity: &'static str,
            policy_change: bool,
        }

        let mutations = [
            Mutation {
                label: "content",
                other_root: false,
                contents: b"changed\n",
                overwrite: true,
                policy_identity: "policy-a",
                policy_change: true,
            },
            Mutation {
                label: "overwrite mode",
                other_root: false,
                contents: b"safe\n",
                overwrite: false,
                policy_identity: "policy-a",
                policy_change: true,
            },
            Mutation {
                label: "root identity",
                other_root: true,
                contents: b"safe\n",
                overwrite: true,
                policy_identity: "policy-a",
                policy_change: true,
            },
            Mutation {
                label: "policy identity",
                other_root: false,
                contents: b"safe\n",
                overwrite: true,
                policy_identity: "policy-b",
                policy_change: true,
            },
            Mutation {
                label: "policy-change classification",
                other_root: false,
                contents: b"safe\n",
                overwrite: true,
                policy_identity: "policy-a",
                policy_change: false,
            },
        ];

        for mutation in mutations {
            let authorized_root = temp_root();
            let other_root = temp_root();
            let authorized_path = authorized_root.path().join("policy.yaml");
            let authorized_write = ConfigWritePermit::prepare_owned(
                authorized_root.path(),
                &authorized_path,
                b"safe\n",
                true,
                "policy-a",
                true,
                false,
            )
            .expect("prepare authorized write");
            let envelope = authorized_write.operation_envelope();
            let operation = config_operation(&envelope, authorized_write.boundary_effects());
            let boundary_permit = authorization(&operation);

            let root = if mutation.other_root {
                other_root.path()
            } else {
                authorized_root.path()
            };
            let path = root.join("policy.yaml");
            let mutated_write = ConfigWritePermit::prepare_owned(
                root,
                &path,
                mutation.contents,
                mutation.overwrite,
                mutation.policy_identity,
                mutation.policy_change,
                false,
            )
            .unwrap_or_else(|error| panic!("{}: prepare: {error}", mutation.label));
            let error = mutated_write
                .commit_authorized(mutation.contents, boundary_permit, &operation)
                .unwrap_err();
            assert!(
                matches!(error, ConfigWriteError::AuthorizationMismatch),
                "{}: {error}",
                mutation.label
            );
            assert!(!path.exists(), "{} published bytes", mutation.label);
        }
    }

    #[cfg(unix)]
    #[test]
    fn distinct_non_utf8_destinations_are_rejected_instead_of_aliasing() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let root = temp_root();
        let first = root
            .path()
            .join(OsString::from_vec(b"policy-\x80.yaml".to_vec()));
        let second = root
            .path()
            .join(OsString::from_vec(b"policy-\x81.yaml".to_vec()));

        assert_ne!(first, second);
        assert_eq!(first.to_string_lossy(), second.to_string_lossy());
        for path in [&first, &second] {
            let error =
                ConfigWritePermit::prepare(root.path(), path, b"safe: true\n", true, "policy-id")
                    .expect_err("non-UTF-8 destinations must fail before a permit is issued");
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(!path.exists());
        }
    }

    /// The Display impl claims to be safe to print into a shared log, so it has
    /// to actually be. A no-clobber collision is the cheapest way to get the
    /// contained-file layer to hand back an error carrying the absolute
    /// destination path, which is what this must not forward.
    #[test]
    fn a_rendered_error_never_carries_the_destination_path() {
        let root = temp_root();
        let path = root.path().join("policy.yaml");
        std::fs::write(&path, b"existing\n").expect("seed");

        let permit = ConfigWritePermit::prepare(root.path(), &path, b"new\n", false, "policy-id")
            .expect("prepare");
        let error = permit
            .commit(b"new\n")
            .expect_err("a no-clobber commit over an existing file must refuse");

        let rendered = error.to_string();
        assert!(
            !rendered.contains("policy.yaml")
                && !rendered.contains(&*root.path().to_string_lossy()),
            "the rendered error leaked the destination path: {rendered}"
        );
    }

    #[test]
    fn a_permit_refuses_content_it_was_not_issued_for() {
        let root = temp_root();
        let path = root.path().join("policy.yaml");
        let permit =
            ConfigWritePermit::prepare(root.path(), &path, b"approved\n", true, "policy-id")
                .expect("prepare");
        let error = permit.commit(b"substituted\n").expect_err("must refuse");
        assert!(matches!(error, ConfigWriteError::ContentMismatch));
        // The refusal happened BEFORE publication, so nothing exists.
        assert!(!path.exists());
    }

    #[test]
    fn dropping_a_permit_publishes_nothing() {
        let root = temp_root();
        let path = root.path().join("policy.yaml");
        {
            let _permit =
                ConfigWritePermit::prepare(root.path(), &path, b"body\n", true, "policy-id")
                    .expect("prepare");
        }
        assert!(!path.exists());
    }

    #[test]
    fn debug_prints_digests_and_never_the_path_or_the_payload() {
        let root = temp_root();
        let path = root.path().join("secret-name.yaml");
        let permit =
            ConfigWritePermit::prepare(root.path(), &path, b"token: hunter2\n", true, "policy-id")
                .expect("prepare");
        let rendered = format!("{permit:?}");
        assert!(!rendered.contains("secret-name"));
        assert!(!rendered.contains("hunter2"));
        assert!(rendered.contains(permit.content_sha256()));
    }

    #[test]
    fn a_no_clobber_permit_refuses_an_existing_destination() {
        let root = temp_root();
        let path = root.path().join("policy.yaml");
        std::fs::write(&path, b"original\n").expect("seed");
        let permit =
            ConfigWritePermit::prepare(root.path(), &path, b"replacement\n", false, "policy-id")
                .expect("prepare");
        let error = permit.commit(b"replacement\n").expect_err("must refuse");
        assert!(matches!(error, ConfigWriteError::Io(_)));
        assert_eq!(
            std::fs::read(&path).expect("read back"),
            b"original\n".to_vec()
        );
    }
}
