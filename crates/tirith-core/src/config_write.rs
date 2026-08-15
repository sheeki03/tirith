//! A single-use permit for a Tirith-owned configuration write (C12).
//!
//! The final rename of a config file is irreversible: once the directory entry
//! points at the new inode, the previous contents are gone. This type holds that
//! transition open. It binds, at preparation time, the parent capability, the
//! final component, the exact bytes, the policy identity in force, and the
//! overwrite decision; and it re-checks the bytes and the binding again at
//! commit, immediately before publication.
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
use crate::util::ContainedAtomicFile;

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
    content_sha256: String,
    /// [`crate::policy::Policy::security_projection_hash`] at issue time, so an
    /// audit can tell which posture authorised the write.
    policy_identity: String,
    overwrite: bool,
}

impl fmt::Debug for ConfigWritePermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigWritePermit")
            .field("content_sha256", &self.content_sha256)
            .field(
                "destination_sha256",
                &sha256_hex(self.path.to_string_lossy().as_bytes()),
            )
            .field("policy_identity", &self.policy_identity)
            .field("overwrite", &self.overwrite)
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
        // Parent creation stays the caller's responsibility, matching the
        // existing contained writer's NotFound behaviour.
        let destination = ContainedAtomicFile::prepare(root, path, false)?;
        Ok(Self {
            destination,
            root: root.to_path_buf(),
            path: path.to_path_buf(),
            content_sha256: sha256_hex(contents),
            policy_identity: policy_identity.to_string(),
            overwrite,
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

    /// Publish, consuming the permit.
    ///
    /// Re-validates both bindings first: the payload must still hash to what the
    /// permit was issued for, and the named destination must still resolve
    /// beneath the permit's root. Only then does the retained capability publish.
    pub fn commit(self, contents: &[u8]) -> Result<(), ConfigWriteError> {
        if sha256_hex(contents) != self.content_sha256 {
            return Err(ConfigWriteError::ContentMismatch);
        }
        // Re-resolving proves the visible path has not become an escape since
        // the permit was issued. The write below still goes through the ORIGINAL
        // retained capability, so this check can only refuse, never redirect.
        ContainedAtomicFile::prepare(&self.root, &self.path, false)
            .map_err(ConfigWriteError::BindingLost)?;
        self.destination
            .write_atomic(contents, self.overwrite)
            .map_err(ConfigWriteError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
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
