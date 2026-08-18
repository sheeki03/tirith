//! Native-authority package-install approval records.
//!
//! Schema v2 is deliberately the first authorizing schema. Legacy records that
//! only contained a self-consistent [`InstallPlanDigest`] are data, not proof of
//! operator approval, and therefore never deserialize as this type.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::artifact::install::InstallPlanDigest;

pub const PACKAGE_APPROVAL_SCHEMA_V2: u16 = 2;
pub const MAX_PACKAGE_APPROVAL_LIFETIME_SECS: i64 = 30 * 60;
pub const MAX_PACKAGE_APPROVAL_CLOCK_SKEW_SECS: i64 = 5 * 60;
const SIGNING_DOMAIN: &[u8] = b"tirith-package-approval:v2\n";
const KEY_ID_HEX_LEN: usize = 16;
const SIGNATURE_HEX_LEN: usize = 128;

/// Canonical, expiry-independent plan projection shown by both the
/// unprivileged CLI and the privileged authority before a grant is signed.
/// Dynamic issuance fields are excluded so both processes display identical
/// bytes while the authority remains the sole owner of timestamps.
pub fn package_approval_plan_projection(
    digest: &InstallPlanDigest,
) -> Result<String, PackageApprovalError> {
    let requested = expiry_independent_plan(digest)?;
    serde_json::to_string_pretty(&requested).map_err(|_| PackageApprovalError::MalformedRecord)
}

/// Return the stable requested-plan identity used as the approval-record key.
/// A signed record adds an authority-stamped expiry and therefore has a
/// different `plan_digest`; renewable grants must not be keyed by that field.
pub fn expiry_independent_plan(
    digest: &InstallPlanDigest,
) -> Result<InstallPlanDigest, PackageApprovalError> {
    if !digest.digest_matches() {
        return Err(PackageApprovalError::InvalidDigest);
    }
    let mut requested = digest.clone();
    requested.expiry.clear();
    requested.plan_digest = requested.compute_plan_digest();
    if !requested.digest_matches() {
        return Err(PackageApprovalError::InvalidDigest);
    }
    Ok(requested)
}

/// A native-authority-signed approval for one exact install plan.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageApprovalRecordV2 {
    schema_version: u16,
    authority_key_id: String,
    issued_at: String,
    expires_at: String,
    digest: InstallPlanDigest,
    signature: String,
}

impl PackageApprovalRecordV2 {
    /// Issue a v2 record. The expiry is intentionally duplicated in the signed
    /// envelope and the plan digest; disagreement is rejected.
    pub fn issue(
        digest: InstallPlanDigest,
        issued_at: &str,
        expires_at: &str,
        signing_key: &SigningKey,
    ) -> Result<Self, PackageApprovalError> {
        validate_digest_and_lifetime(&digest, issued_at, expires_at)?;
        let authority_key_id =
            crate::command_card::key_id_for_pubkey(&signing_key.verifying_key().to_bytes());
        let mut record = Self {
            schema_version: PACKAGE_APPROVAL_SCHEMA_V2,
            authority_key_id,
            issued_at: issued_at.to_string(),
            expires_at: expires_at.to_string(),
            digest,
            signature: String::new(),
        };
        let signature = signing_key.sign(&record.signing_payload()?);
        record.signature = crate::command_card::hex_encode(&signature.to_bytes());
        Ok(record)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, PackageApprovalError> {
        let text = std::str::from_utf8(bytes).map_err(|_| PackageApprovalError::MalformedRecord)?;
        let value = crate::mcp_lock::parse_json_no_duplicates(text)
            .map_err(|_| PackageApprovalError::MalformedRecord)?;
        let record: Self = serde_json::from_value(value.clone())
            .map_err(|_| PackageApprovalError::MalformedRecord)?;
        if serde_json::to_value(&record).map_err(|_| PackageApprovalError::MalformedRecord)?
            != value
        {
            return Err(PackageApprovalError::MalformedRecord);
        }
        Ok(record)
    }

    pub fn to_json_pretty(&self) -> Result<String, PackageApprovalError> {
        serde_json::to_string_pretty(self).map_err(|_| PackageApprovalError::MalformedRecord)
    }

    pub fn digest(&self) -> &InstallPlanDigest {
        &self.digest
    }

    pub fn authority_key_id(&self) -> &str {
        &self.authority_key_id
    }

    pub fn issued_at(&self) -> &str {
        &self.issued_at
    }

    pub fn expires_at(&self) -> &str {
        &self.expires_at
    }

    fn signing_payload(&self) -> Result<Vec<u8>, PackageApprovalError> {
        #[derive(Serialize)]
        struct SignedProjection<'a> {
            schema_version: u16,
            authority_key_id: &'a str,
            issued_at: &'a str,
            expires_at: &'a str,
            digest: &'a InstallPlanDigest,
        }

        let projection = serde_json::to_value(SignedProjection {
            schema_version: self.schema_version,
            authority_key_id: &self.authority_key_id,
            issued_at: &self.issued_at,
            expires_at: &self.expires_at,
            digest: &self.digest,
        })
        .map_err(|_| PackageApprovalError::MalformedRecord)?;
        let canonical = crate::audit::canonical_json_for_hash(&projection);
        let mut payload = Vec::with_capacity(SIGNING_DOMAIN.len() + canonical.len());
        payload.extend_from_slice(SIGNING_DOMAIN);
        payload.extend_from_slice(canonical.as_bytes());
        Ok(payload)
    }
}

/// Opaque, non-cloneable evidence that a trusted native authority signed the
/// exact install plan being requested and that the record is currently fresh.
pub struct VerifiedPackageApproval {
    authority_key_id: String,
    approved_plan_digest: String,
    requested_plan_digest: String,
    requested_plan: InstallPlanDigest,
    expires_at: String,
}

impl VerifiedPackageApproval {
    pub(crate) fn authority_key_id(&self) -> &str {
        &self.authority_key_id
    }

    pub(crate) fn approved_plan_digest(&self) -> &str {
        &self.approved_plan_digest
    }

    pub(crate) fn requested_plan_digest(&self) -> &str {
        &self.requested_plan_digest
    }

    pub(crate) fn requested_plan(&self) -> &InstallPlanDigest {
        &self.requested_plan
    }

    pub(crate) fn expires_at(&self) -> &str {
        &self.expires_at
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PackageApprovalError {
    #[error("package approval record is malformed")]
    MalformedRecord,
    #[error("unsupported package approval schema version")]
    UnsupportedSchema,
    #[error("package approval record has an invalid authority key id")]
    InvalidKeyId,
    #[error("package approval record has an invalid signature encoding")]
    InvalidSignatureEncoding,
    #[error("package approval record's plan digest is invalid")]
    InvalidDigest,
    #[error("package approval expiry must be present and match the approved plan")]
    InvalidExpiry,
    #[error("package approval timestamp is invalid: {0}")]
    InvalidTimestamp(&'static str),
    #[error("package approval lifetime must be positive and at most 30 minutes")]
    InvalidLifetime,
    #[error("package approval issue time exceeds the permitted clock skew")]
    ClockSkew,
    #[error("package approval has expired")]
    Expired,
    #[error("package approval authority key is not trusted")]
    UnknownAuthority,
    #[error("package approval signature is invalid")]
    InvalidSignature,
    #[error("package approval does not bind the exact requested install plan")]
    PlanMismatch,
}

/// Verify a signed record against the admin-trusted authority keyring and the
/// exact no-expiry install digest being prepared.
pub fn verify_package_approval(
    record: &PackageApprovalRecordV2,
    requested: &InstallPlanDigest,
    trusted_keys: &BTreeMap<String, [u8; 32]>,
    now: DateTime<Utc>,
) -> Result<VerifiedPackageApproval, PackageApprovalError> {
    if record.schema_version != PACKAGE_APPROVAL_SCHEMA_V2 {
        return Err(PackageApprovalError::UnsupportedSchema);
    }
    validate_key_id(&record.authority_key_id)?;
    validate_digest_and_lifetime(&record.digest, &record.issued_at, &record.expires_at)?;

    let public = trusted_keys
        .get(&record.authority_key_id)
        .ok_or(PackageApprovalError::UnknownAuthority)?;
    if crate::command_card::key_id_for_pubkey(public) != record.authority_key_id {
        return Err(PackageApprovalError::UnknownAuthority);
    }
    if record.signature.len() != SIGNATURE_HEX_LEN
        || !record
            .signature
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(PackageApprovalError::InvalidSignatureEncoding);
    }
    let signature_bytes = hex::decode(&record.signature)
        .map_err(|_| PackageApprovalError::InvalidSignatureEncoding)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| PackageApprovalError::InvalidSignatureEncoding)?;
    let verifying_key =
        VerifyingKey::from_bytes(public).map_err(|_| PackageApprovalError::UnknownAuthority)?;
    verifying_key
        .verify_strict(&record.signing_payload()?, &signature)
        .map_err(|_| PackageApprovalError::InvalidSignature)?;

    if !requested.digest_matches()
        || !requested.expiry.is_empty()
        || !same_plan_except_expiry(&record.digest, requested)
    {
        return Err(PackageApprovalError::PlanMismatch);
    }

    let issued_at = parse_timestamp(&record.issued_at, "issued_at")?;
    let expires_at = parse_timestamp(&record.expires_at, "expires_at")?;
    if issued_at > now + Duration::seconds(MAX_PACKAGE_APPROVAL_CLOCK_SKEW_SECS) {
        return Err(PackageApprovalError::ClockSkew);
    }
    if now >= expires_at {
        return Err(PackageApprovalError::Expired);
    }

    Ok(VerifiedPackageApproval {
        authority_key_id: record.authority_key_id.clone(),
        approved_plan_digest: record.digest.plan_digest.clone(),
        requested_plan_digest: requested.plan_digest.clone(),
        requested_plan: requested.clone(),
        expires_at: record.expires_at.clone(),
    })
}

fn validate_digest_and_lifetime(
    digest: &InstallPlanDigest,
    issued_at: &str,
    expires_at: &str,
) -> Result<(), PackageApprovalError> {
    if !digest.digest_matches() {
        return Err(PackageApprovalError::InvalidDigest);
    }
    if expires_at.is_empty() || digest.expiry.is_empty() || digest.expiry != expires_at {
        return Err(PackageApprovalError::InvalidExpiry);
    }
    let issued_at = parse_timestamp(issued_at, "issued_at")?;
    let expires_at = parse_timestamp(expires_at, "expires_at")?;
    let lifetime = expires_at.signed_duration_since(issued_at);
    if lifetime <= Duration::zero()
        || lifetime > Duration::seconds(MAX_PACKAGE_APPROVAL_LIFETIME_SECS)
    {
        return Err(PackageApprovalError::InvalidLifetime);
    }
    Ok(())
}

fn parse_timestamp(
    value: &str,
    field: &'static str,
) -> Result<DateTime<Utc>, PackageApprovalError> {
    if value.is_empty() {
        return Err(PackageApprovalError::InvalidTimestamp(field));
    }
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| PackageApprovalError::InvalidTimestamp(field))
}

fn validate_key_id(key_id: &str) -> Result<(), PackageApprovalError> {
    if key_id.len() != KEY_ID_HEX_LEN
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(PackageApprovalError::InvalidKeyId);
    }
    Ok(())
}

fn same_plan_except_expiry(approved: &InstallPlanDigest, requested: &InstallPlanDigest) -> bool {
    let situation = |digest: &InstallPlanDigest| {
        let mut copy = digest.clone();
        copy.plan_digest.clear();
        copy.expiry.clear();
        copy
    };
    situation(approved) == situation(requested)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::install::{InstallCommand, InstallPlanInputs};
    use crate::artifact::resolver::{
        PIP_TREE_BINDING_VERSION, PIP_TREE_MAX_BYTES, PIP_TREE_MAX_FILES, PIP_TREE_MAX_FILE_BYTES,
        PIP_TREE_MAX_PATH_BYTES,
    };
    use crate::capsule::CapsuleSpec;
    use std::path::PathBuf;

    fn digest(expiry: &str) -> InstallPlanDigest {
        InstallPlanDigest::new(InstallPlanInputs {
            artifact_sha256: vec!["a".repeat(64)],
            normalized_packages: vec!["demo".into()],
            interpreter: PathBuf::from("/usr/bin/python3"),
            interpreter_sha256: "b".repeat(64),
            resolver: PathBuf::from("/usr/bin/uv"),
            resolver_sha256: "c".repeat(64),
            resolver_version: "uv 1.0".into(),
            package_manager_version: "pip 24".into(),
            pip_tree_root: PathBuf::from("/usr/lib/pip"),
            pip_tree_sha256: "d".repeat(64),
            pip_tree_binding_version: PIP_TREE_BINDING_VERSION,
            pip_tree_max_files: PIP_TREE_MAX_FILES,
            pip_tree_max_bytes: PIP_TREE_MAX_BYTES,
            pip_tree_max_file_bytes: PIP_TREE_MAX_FILE_BYTES,
            pip_tree_max_path_bytes: PIP_TREE_MAX_PATH_BYTES,
            pip_tree_files: 1,
            pip_tree_bytes: 1,
            target_environment: PathBuf::from("/tmp/target"),
            target_parent_identity: "devino:1:2".into(),
            target_component: "target".into(),
            platform_tags: vec!["py3-none-any".into()],
            install_command_semantics: InstallCommand {
                approved_requirements_path: PathBuf::from("approved.txt"),
                target_environment: PathBuf::from("/tmp/target"),
            }
            .pip_install_args_without_requirements_path(),
            policy_projection_hash: "e".repeat(64),
            threat_db_sequence: 1,
            capsule_backend: "landlock-seccomp".into(),
            required_coverage: CapsuleSpec::locked_down().required_coverage(),
            task_gate_binding: "task_gate:v1:mode=off;denied=".into(),
            expiry: expiry.into(),
        })
    }

    fn fixture() -> (
        PackageApprovalRecordV2,
        InstallPlanDigest,
        BTreeMap<String, [u8; 32]>,
        DateTime<Utc>,
    ) {
        let now = DateTime::parse_from_rfc3339("2026-08-17T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let expires = "2026-08-17T12:30:00Z";
        let key = SigningKey::from_bytes(&[37; 32]);
        let record =
            PackageApprovalRecordV2::issue(digest(expires), &now.to_rfc3339(), expires, &key)
                .unwrap();
        let key_id = record.authority_key_id().to_string();
        let keys = BTreeMap::from([(key_id, key.verifying_key().to_bytes())]);
        (record, digest(""), keys, now)
    }

    #[test]
    fn valid_v2_record_verifies() {
        let (record, requested, keys, now) = fixture();
        assert!(verify_package_approval(&record, &requested, &keys, now).is_ok());
    }

    #[test]
    fn canonical_projection_and_storage_identity_ignore_authority_expiry() {
        let first = digest("2026-08-17T12:20:00Z");
        let second = digest("2026-08-17T12:30:00Z");
        let first_requested = expiry_independent_plan(&first).unwrap();
        let second_requested = expiry_independent_plan(&second).unwrap();
        assert_eq!(first_requested, second_requested);
        assert!(first_requested.expiry.is_empty());
        assert_eq!(
            package_approval_plan_projection(&first).unwrap(),
            package_approval_plan_projection(&second).unwrap()
        );
    }

    #[test]
    fn unsigned_v1_never_deserializes_as_authority_proof() {
        let legacy = serde_json::json!({ "digest": digest("2026-08-17T12:30:00Z") });
        assert!(matches!(
            PackageApprovalRecordV2::from_json(legacy.to_string().as_bytes()),
            Err(PackageApprovalError::MalformedRecord)
        ));

        let (record, _, _, _) = fixture();
        let mut non_canonical = serde_json::to_value(&record).unwrap();
        non_canonical["digest"]["unsigned_extra"] = true.into();
        assert!(matches!(
            PackageApprovalRecordV2::from_json(non_canonical.to_string().as_bytes()),
            Err(PackageApprovalError::MalformedRecord)
        ));
    }

    #[test]
    fn unknown_key_and_signed_field_mutations_are_rejected() {
        let (record, requested, keys, now) = fixture();
        assert!(matches!(
            verify_package_approval(&record, &requested, &BTreeMap::new(), now),
            Err(PackageApprovalError::UnknownAuthority)
        ));

        let mut value = serde_json::to_value(&record).unwrap();
        value["issued_at"] = serde_json::Value::String("2026-08-17T12:00:01Z".into());
        let mutated: PackageApprovalRecordV2 = serde_json::from_value(value).unwrap();
        assert!(matches!(
            verify_package_approval(&mutated, &requested, &keys, now),
            Err(PackageApprovalError::InvalidSignature)
        ));
    }

    #[test]
    fn expiry_lifetime_clock_skew_and_plan_mutation_fail_closed() {
        let (record, requested, keys, now) = fixture();
        assert!(matches!(
            verify_package_approval(&record, &requested, &keys, now + Duration::minutes(30)),
            Err(PackageApprovalError::Expired)
        ));

        let key = SigningKey::from_bytes(&[37; 32]);
        assert!(matches!(
            PackageApprovalRecordV2::issue(digest(""), "2026-08-17T12:00:00Z", "", &key,),
            Err(PackageApprovalError::InvalidExpiry)
        ));
        assert!(matches!(
            PackageApprovalRecordV2::issue(
                digest("2026-08-17T12:30:01Z"),
                "2026-08-17T12:00:00Z",
                "2026-08-17T12:30:01Z",
                &key,
            ),
            Err(PackageApprovalError::InvalidLifetime)
        ));
        assert!(matches!(
            verify_package_approval(
                &record,
                &requested,
                &keys,
                now - Duration::seconds(MAX_PACKAGE_APPROVAL_CLOCK_SKEW_SECS + 1),
            ),
            Err(PackageApprovalError::ClockSkew)
        ));

        let mut changed = digest("");
        changed.interpreter = "/attacker/python".into();
        changed.plan_digest = changed.compute_plan_digest();
        assert!(matches!(
            verify_package_approval(&record, &changed, &keys, now),
            Err(PackageApprovalError::PlanMismatch)
        ));
    }
}
