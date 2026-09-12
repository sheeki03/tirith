//! Compatibility declarations are checksum-bound data, never candidate code.
use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tirith_core::selfupdate::{self, SemVer};

pub(super) const ASSET: &str = "release-compatibility.json";
const LIMIT: u64 = 256 * 1024;
const REQUIRED_FEATURES: &[&str] = &[
    "effective_policy_snapshot_v1",
    "scoped_trust_grants_v1",
    "protection_profiles_v1",
    "owned_change_journals_v1",
];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Target {
    archive: String,
    archive_sha256: String,
    binary_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u32,
    version: String,
    policy_read_versions: Vec<u32>,
    mcp_lock_read_versions: Vec<u32>,
    mcp_lock_authorize_versions: Vec<u32>,
    legacy_trust_read_versions: Vec<u32>,
    scoped_grant_read_versions: Vec<u32>,
    operation_journal_version: u32,
    operation_journal_client_rule: String,
    control_service_protocol: u32,
    control_service_reuse_rule: String,
    configuration_update_rule: String,
    features: Vec<String>,
    targets: BTreeMap<String, Target>,
}

impl Document {
    fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || SemVer::parse(&self.version)
                .map(|version| version.to_string())
                .as_deref()
                != Some(self.version.as_str())
            || self.operation_journal_version == 0
            || self.control_service_protocol == 0
            || self.targets.len() > 32
            || self.features.len() > 64
            || self.features.iter().any(|feature| {
                feature.len() > 128
                    || !feature
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            })
        {
            return Err(
                "candidate compatibility metadata is invalid or uses an unsupported schema".into(),
            );
        }
        for versions in [
            &self.policy_read_versions,
            &self.mcp_lock_read_versions,
            &self.mcp_lock_authorize_versions,
            &self.legacy_trust_read_versions,
            &self.scoped_grant_read_versions,
        ] {
            if versions.len() > 32
                || versions.contains(&0)
                || versions
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != versions.len()
            {
                return Err(
                    "candidate compatibility metadata has invalid format declarations".into(),
                );
            }
        }
        if self.targets.iter().any(|(target, identity)| {
            identity.archive != selfupdate::release_archive_name(target)
                || !digest(&identity.archive_sha256)
                || !digest(&identity.binary_sha256)
        }) {
            return Err("candidate compatibility metadata has invalid executable bindings".into());
        }
        Ok(())
    }

    fn current() -> Self {
        Self {
            schema_version: 1,
            version: env!("CARGO_PKG_VERSION").into(),
            policy_read_versions: (1..=tirith_core::policy_migrations::CURRENT_SCHEMA_VERSION)
                .collect(),
            mcp_lock_read_versions: (4..=tirith_core::mcp_lock::MCP_LOCK_FORMAT_VERSION).collect(),
            mcp_lock_authorize_versions: vec![tirith_core::mcp_lock::MCP_LOCK_FORMAT_VERSION],
            legacy_trust_read_versions: vec![1],
            scoped_grant_read_versions: vec![tirith_core::trust_grants::STORE_VERSION],
            operation_journal_version: 1,
            operation_journal_client_rule: "exact_client_version_required".into(),
            control_service_protocol: 1,
            control_service_reuse_rule: "exact_protocol_version_and_binary_sha256_required".into(),
            configuration_update_rule: "preserve_existing_bytes".into(),
            features: REQUIRED_FEATURES
                .iter()
                .map(|feature| (*feature).into())
                .collect(),
            targets: BTreeMap::new(),
        }
    }
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Serialize)]
pub(super) struct Preview {
    pub candidate_version: String,
    pub evidence: &'static str,
    pub compatible: bool,
    pub issues: Vec<String>,
    pub observed_formats: Vec<super::lifecycle::FormatFact>,
    pub lock_reapproval_required: bool,
    pub configuration_changed: bool,
    pub service_action: &'static str,
    pub integration_action: &'static str,
    pub journal_action: &'static str,
}

fn preview(
    document: &Document,
    evidence: &'static str,
    formats: Vec<super::lifecycle::FormatFact>,
) -> Preview {
    let mut issues = Vec::new();
    let mut lock_reapproval_required = false;
    for observed in &formats {
        if observed.state == "absent" {
            continue;
        }
        let Some(version) = observed.declared_version else {
            issues.push(format!(
                "{} format is {}; repair or verify it before changing the binary",
                observed.surface, observed.state
            ));
            continue;
        };
        let versions = match observed.surface {
            "policy" => &document.policy_read_versions,
            "mcp_lock" => &document.mcp_lock_read_versions,
            "legacy_trust" => &document.legacy_trust_read_versions,
            "scoped_grants" => &document.scoped_grant_read_versions,
            _ => {
                issues.push(
                    "an observed stored surface has no candidate compatibility contract".into(),
                );
                continue;
            }
        };
        if !versions.contains(&version) {
            issues.push(format!("candidate {} cannot read {} format {}; retain this binary or migrate that surface explicitly", document.version, observed.surface, version));
        }
        if observed.surface == "mcp_lock"
            && !document.mcp_lock_authorize_versions.contains(&version)
        {
            lock_reapproval_required = true;
        }
    }
    if REQUIRED_FEATURES
        .iter()
        .any(|required| !document.features.iter().any(|feature| feature == required))
    {
        issues.push("candidate lacks a required policy, scoped-grant, profile, or owned-journal capability; automatic downgrade is unsupported".into());
    }
    if document.operation_journal_version != 1
        || document.operation_journal_client_rule != "exact_client_version_required"
    {
        issues.push("candidate operation-journal compatibility is unsupported; retain the originating binary for pending recovery or undo".into());
    }
    if document.control_service_protocol != 1
        || document.control_service_reuse_rule
            != "exact_protocol_version_and_binary_sha256_required"
    {
        issues.push(
            "candidate control-service protocol or binary-identity negotiation is unsupported"
                .into(),
        );
    }
    if document.configuration_update_rule != "preserve_existing_bytes" {
        issues.push("candidate requires an unsupported automatic configuration migration".into());
    }
    Preview {
        candidate_version: document.version.clone(),
        evidence,
        compatible: issues.is_empty(),
        issues,
        observed_formats: formats,
        lock_reapproval_required,
        configuration_changed: false,
        service_action: "quiesce_current_operator_service_and_hold_launch_lock_through_replacement",
        integration_action: "open_fresh_shell_or_reload_host_then_verify_behavior",
        journal_action: "retain_original_client_for_prior_version_recovery_and_owned_undo",
    }
}

impl Preview {
    pub(super) fn require_compatible(&self) -> Result<(), String> {
        if self.compatible {
            Ok(())
        } else {
            Err(format!(
                "unsupported update or downgrade: {}",
                self.issues.join("; ")
            ))
        }
    }
}

pub(super) struct VerifiedCandidate {
    document: Document,
    target: String,
    evidence: &'static str,
}

impl VerifiedCandidate {
    pub(super) fn verify(
        release: &super::ReleaseSet,
        bytes: &[u8],
        target: &str,
        allow_unsigned: bool,
    ) -> Result<Self, String> {
        let cosign = super::cosign_program();
        Self::verify_with_program(release, bytes, target, allow_unsigned, cosign.as_deref())
    }

    pub(super) fn verify_with_program(
        release: &super::ReleaseSet,
        bytes: &[u8],
        target: &str,
        allow_unsigned: bool,
        cosign: Option<&Path>,
    ) -> Result<Self, String> {
        if bytes.len() as u64 > LIMIT {
            return Err("candidate compatibility document exceeds its limit".into());
        }
        let expected = selfupdate::checksum_for(&release.checksums_txt, ASSET)
            .map_err(|_| "release checksums are malformed")?
            .ok_or("release has no checksum-bound compatibility document; automatic update is unsupported, use the owning installation channel after reviewing format compatibility")?;
        if !selfupdate::digest_eq(&super::hex_sha256(bytes), &expected) {
            return Err(
                "candidate compatibility document does not match the release checksum".into(),
            );
        }
        let evidence = match super::verify_cosign_signature_with_program(release, cosign) {
            super::CosignOutcomeInternal::Verified => "signed_release_checksums",
            super::CosignOutcomeInternal::Unavailable(_) if allow_unsigned => {
                "checksum_only_explicitly_allowed"
            }
            super::CosignOutcomeInternal::Unavailable(reason) => {
                return Err(format!(
                    "cannot authenticate candidate compatibility: {}",
                    reason.detail()
                ))
            }
            super::CosignOutcomeInternal::Failed(_) => {
                return Err("candidate compatibility release signature failed".into())
            }
        };
        Self::from_bound_bytes(release, bytes, target, evidence)
    }

    fn from_bound_bytes(
        release: &super::ReleaseSet,
        bytes: &[u8],
        target: &str,
        evidence: &'static str,
    ) -> Result<Self, String> {
        let document: Document = serde_json::from_slice(bytes)
            .map_err(|_| "candidate compatibility document is malformed")?;
        document.validate()?;
        if SemVer::parse(&release.tag)
            .map(|version| version.to_string())
            .as_deref()
            != Some(document.version.as_str())
        {
            return Err(
                "candidate compatibility version differs from the authenticated release tag".into(),
            );
        }
        let identity = document
            .targets
            .get(target)
            .ok_or("candidate compatibility lacks this release target")?;
        let checksum = selfupdate::checksum_for(
            &release.checksums_txt,
            &selfupdate::release_archive_name(target),
        )
        .map_err(|_| "release checksums are malformed")?
        .ok_or("release checksum lacks the selected archive")?;
        if !selfupdate::digest_eq(&identity.archive_sha256, &checksum) {
            return Err("candidate compatibility archive identity differs from the signed checksum manifest".into());
        }
        Ok(Self {
            document,
            target: target.into(),
            evidence,
        })
    }

    pub(super) fn archive_sha256(&self) -> &str {
        &self.document.targets[&self.target].archive_sha256
    }
    pub(super) fn binary_sha256(&self) -> &str {
        &self.document.targets[&self.target].binary_sha256
    }
    pub(super) fn preview(&self, provenance: &super::CliProvenance) -> Preview {
        let facts = super::lifecycle::gather(provenance, Some(&self.document.version));
        preview(
            &self.document,
            self.evidence,
            facts.compatibility.observed_formats,
        )
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RollbackReceipt {
    schema_version: u32,
    kind: String,
    binary_sha256: String,
    document: Document,
}

fn receipt_path(binary: &Path, sha256: &str) -> Result<PathBuf, String> {
    if !digest(sha256) {
        return Err("rollback executable identity is invalid".into());
    }
    let name = binary
        .file_name()
        .ok_or("cannot locate binary basename")?
        .to_string_lossy();
    Ok(binary.with_file_name(format!("{name}.tirith-rollback-{sha256}.json")))
}

fn read_receipt(path: &Path) -> Result<Vec<u8>, String> {
    let file = tirith_core::util::open_read_no_follow_capped(path, LIMIT)
        .map_err(|_| "rollback compatibility evidence is absent or unsafe; this older rollback point cannot be checked automatically, use its owning installation channel after reviewing stored formats")?;
    let mut bytes = Vec::new();
    file.take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read rollback compatibility evidence")?;
    if bytes.len() as u64 > LIMIT {
        return Err("rollback compatibility evidence exceeds its limit".into());
    }
    Ok(bytes)
}

pub(super) fn preserve_current_for_rollback(
    provenance: &super::CliProvenance,
    authorization: &impl super::SelfEffectAuthorization,
) -> Result<(), String> {
    let binary = provenance
        .binary_path
        .as_deref()
        .ok_or("cannot locate current binary")?;
    let sha = provenance
        .binary_sha256
        .as_deref()
        .ok_or("cannot bind current binary")?;
    super::verify_exact_regular_preimage(binary, Some(sha))?;
    let path = receipt_path(binary, sha)?;
    let receipt = RollbackReceipt {
        schema_version: 1,
        kind: "captured_running_binary_compatibility".into(),
        binary_sha256: sha.into(),
        document: Document::current(),
    };
    let bytes = serde_json::to_vec(&receipt).map_err(|_| "cannot encode rollback compatibility")?;
    if path
        .try_exists()
        .map_err(|_| "cannot inspect prior rollback compatibility evidence")?
    {
        if read_receipt(&path)? == bytes {
            return Ok(());
        }
        return Err("existing rollback compatibility evidence differs; preserve and resolve this conflict before updating".into());
    }
    let parent = binary.parent().ok_or("cannot locate binary directory")?;
    let prefix = format!(
        "{}.tirith-rollback-",
        binary
            .file_name()
            .ok_or("cannot locate binary basename")?
            .to_string_lossy()
    );
    let mut retained = 0;
    for (index, entry) in std::fs::read_dir(parent)
        .map_err(|_| "cannot inspect rollback evidence retention")?
        .enumerate()
    {
        if index >= 4096 {
            return Err("binary directory exceeds the bounded rollback-evidence scan; review this installation before updating".into());
        }
        let entry = entry.map_err(|_| "rollback evidence directory changed")?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&prefix) && name.ends_with(".json") {
            retained += 1;
        }
        if retained >= 64 {
            return Err("rollback compatibility retention reached 64 generations; preserve evidence for the live and saved previous binary, then remove obsolete unchanged receipts before updating".into());
        }
    }
    authorization.authorize_effect()?;
    let mut staged =
        tempfile::NamedTempFile::new_in(binary.parent().ok_or("cannot locate binary directory")?)
            .map_err(|_| "cannot stage rollback compatibility evidence")?;
    staged
        .write_all(&bytes)
        .map_err(|_| "cannot stage rollback compatibility evidence")?;
    staged
        .as_file()
        .sync_all()
        .map_err(|_| "cannot persist rollback compatibility evidence")?;
    authorization.authorize_effect()?;
    staged
        .persist_noclobber(&path)
        .map_err(|_| "rollback compatibility evidence changed before publication")?;
    Ok(())
}

pub(super) struct VerifiedRollback {
    document: Document,
    receipt_sha256: String,
}

impl VerifiedRollback {
    pub(super) fn load(binary: &Path, backup_sha256: &str) -> Result<Self, String> {
        let bytes = read_receipt(&receipt_path(binary, backup_sha256)?)?;
        let receipt: RollbackReceipt = serde_json::from_slice(&bytes)
            .map_err(|_| "rollback compatibility evidence is malformed")?;
        if receipt.schema_version != 1
            || receipt.kind != "captured_running_binary_compatibility"
            || receipt.binary_sha256 != backup_sha256
        {
            return Err(
                "rollback compatibility evidence does not bind the saved executable".into(),
            );
        }
        receipt.document.validate()?;
        Ok(Self {
            document: receipt.document,
            receipt_sha256: super::hex_sha256(&bytes),
        })
    }
    pub(super) fn receipt_sha256(&self) -> &str {
        &self.receipt_sha256
    }
    pub(super) fn preview(&self, provenance: &super::CliProvenance) -> Preview {
        let facts = super::lifecycle::gather(provenance, None);
        preview(
            &self.document,
            "captured_previous_running_binary_contract",
            facts.compatibility.observed_formats,
        )
    }
    pub(super) fn revalidate(&self, binary: &Path, backup_sha256: &str) -> Result<(), String> {
        if Self::load(binary, backup_sha256)?.receipt_sha256 == self.receipt_sha256 {
            Ok(())
        } else {
            Err("rollback compatibility evidence changed after preview".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_preview_refuses_unknown_future_and_unsupported_downgrades() {
        let mut document = Document::current();
        let fact = |surface, version, state| super::super::lifecycle::FormatFact {
            surface,
            declared_version: version,
            state,
        };
        let ok = preview(
            &document,
            "fixture",
            vec![
                fact("policy", Some(2), "declared_local_unverified"),
                fact("scoped_grants", None, "absent"),
            ],
        );
        assert!(ok.require_compatible().is_ok());
        for observed in [
            fact("policy", Some(99), "declared_local_unverified"),
            fact("scoped_grants", None, "unreadable"),
            fact("mcp_lock", None, "invalid"),
        ] {
            assert!(preview(&document, "fixture", vec![observed])
                .require_compatible()
                .is_err());
        }
        assert!(
            preview(
                &document,
                "fixture",
                vec![fact("mcp_lock", Some(7), "declared_local_unverified")]
            )
            .lock_reapproval_required
        );
        document.features.clear();
        assert!(preview(&document, "fixture", vec![])
            .require_compatible()
            .is_err());
    }

    #[test]
    fn rollback_evidence_requires_exact_binary_binding_and_retains_future_fields_as_errors() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("tirith");
        let sha = "a".repeat(64);
        let path = receipt_path(&binary, &sha).unwrap();
        assert!(VerifiedRollback::load(&binary, &sha).is_err());
        let receipt = RollbackReceipt {
            schema_version: 1,
            kind: "captured_running_binary_compatibility".into(),
            binary_sha256: sha.clone(),
            document: Document::current(),
        };
        std::fs::write(&path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        let proof = VerifiedRollback::load(&binary, &sha).unwrap();
        assert!(proof.revalidate(&binary, &sha).is_ok());
        let mut edited = serde_json::to_value(&receipt).unwrap();
        edited["document"]["future_permission"] = serde_json::json!(true);
        std::fs::write(&path, serde_json::to_vec(&edited).unwrap()).unwrap();
        assert!(proof.revalidate(&binary, &sha).is_err());
        assert!(VerifiedRollback::load(&binary, &"b".repeat(64)).is_err());
    }

    #[test]
    fn candidate_metadata_requires_checksum_target_version_and_explicit_signature_policy() {
        let directory = tempfile::tempdir().unwrap();
        let target = "x86_64-unknown-linux-gnu";
        let archive = selfupdate::release_archive_name(target);
        let mut document = Document::current();
        document.targets.insert(
            target.into(),
            Target {
                archive: archive.clone(),
                archive_sha256: "a".repeat(64),
                binary_sha256: "b".repeat(64),
            },
        );
        let bytes = serde_json::to_vec(&document).unwrap();
        let checksums = format!(
            "{}  {}\n{}  {}\n",
            super::super::hex_sha256(&bytes),
            ASSET,
            "a".repeat(64),
            archive
        );
        let checksums_path = directory.path().join("checksums.txt");
        std::fs::write(&checksums_path, &checksums).unwrap();
        let mut release = super::super::ReleaseSet {
            tag: format!("v{}", env!("CARGO_PKG_VERSION")),
            archive_path: directory.path().join(&archive),
            checksums_txt: checksums,
            sig_path: None,
            cert_path: None,
            checksums_path,
        };
        assert!(
            VerifiedCandidate::verify_with_program(&release, &bytes, target, false, None).is_err()
        );
        let candidate =
            VerifiedCandidate::verify_with_program(&release, &bytes, target, true, None).unwrap();
        assert_eq!(candidate.binary_sha256(), "b".repeat(64));
        let mut tampered = bytes.clone();
        tampered.push(b' ');
        assert!(
            VerifiedCandidate::verify_with_program(&release, &tampered, target, true, None)
                .is_err()
        );
        assert!(VerifiedCandidate::verify_with_program(
            &release,
            &bytes,
            "aarch64-apple-darwin",
            true,
            None
        )
        .is_err());
        release.tag = "v999.0.0".into();
        assert!(
            VerifiedCandidate::verify_with_program(&release, &bytes, target, true, None).is_err()
        );
        release.tag = format!("v{}", env!("CARGO_PKG_VERSION"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let verifier = directory.path().join("reject-signature");
            std::fs::write(&verifier, b"#!/bin/sh\nexit 1\n").unwrap();
            std::fs::set_permissions(&verifier, std::fs::Permissions::from_mode(0o755)).unwrap();
            let signature = directory.path().join("checksums.sig");
            let certificate = directory.path().join("checksums.pem");
            std::fs::write(&signature, b"invalid signature").unwrap();
            std::fs::write(&certificate, b"invalid certificate").unwrap();
            release.sig_path = Some(signature);
            release.cert_path = Some(certificate);
            assert!(VerifiedCandidate::verify_with_program(
                &release,
                &bytes,
                target,
                true,
                Some(&verifier)
            )
            .is_err());
            release.sig_path = None;
            release.cert_path = None;
        }
        release.checksums_txt = release
            .checksums_txt
            .replace(&"a".repeat(64), &"c".repeat(64));
        assert!(
            VerifiedCandidate::verify_with_program(&release, &bytes, target, true, None).is_err()
        );
    }

    #[test]
    fn rollback_receipt_preserves_manual_edits_and_binds_current_preimage() {
        struct Authorized;
        impl super::super::SelfEffectAuthorization for Authorized {
            fn authorize_effect(&self) -> Result<(), String> {
                Ok(())
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("tirith");
        std::fs::write(&binary, b"CURRENT").unwrap();
        let sha = super::super::hex_sha256(b"CURRENT");
        let provenance = super::super::CliProvenance {
            core: selfupdate::Provenance {
                version: env!("CARGO_PKG_VERSION").into(),
                binary_path: Some(binary.clone()),
                binary_sha256: Some(sha.clone()),
                install_method: selfupdate::InstallMethod::SelfManaged,
                target: Some("x86_64-unknown-linux-gnu".into()),
                dev_build: false,
                path_resolution_failed: false,
            },
            origin: super::super::CliInstallOrigin::Standard,
        };
        preserve_current_for_rollback(&provenance, &Authorized).unwrap();
        preserve_current_for_rollback(&provenance, &Authorized).unwrap();
        let receipt = receipt_path(&binary, &sha).unwrap();
        std::fs::write(&receipt, b"manual edit").unwrap();
        assert!(preserve_current_for_rollback(&provenance, &Authorized).is_err());
        assert_eq!(std::fs::read(&receipt).unwrap(), b"manual edit");
        std::fs::write(&binary, b"CHANGED").unwrap();
        assert!(preserve_current_for_rollback(&provenance, &Authorized).is_err());
        assert_eq!(std::fs::read(&receipt).unwrap(), b"manual edit");
    }
}
