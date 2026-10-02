//! Signed complete-only interruption milestones. Saved bytes cannot construct a
//! native completion proof, resume npm, or authorize removal of any target.
pub(crate) const RECOVERY_MILESTONE_SCHEMA_VERSION: u32 = 1;

#[cfg(target_os = "linux")]
mod linux {
    use super::RECOVERY_MILESTONE_SCHEMA_VERSION as SCHEMA;
    use crate::cli::{
        capsule::CompletedNpmRun,
        package_checkpoint::materialization_store::{OperationStore, RecordKind, RECORD_CAP},
    };
    use base64::Engine as _;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use tirith_core::{
        artifact::npm_install::{
            recovery::{NpmRecoveryPlanBinding, NpmRecoveryTreeObservation},
            PreparedNpmExecution, VerifiedNpmTree, CONTRACT,
        },
        receipt::{
            ArtifactScanReceipt, ReceiptPublicationState, RecordedCommittedReceipt,
            RecordedPrivateReceipt,
        },
    };

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct Binding {
        operation: String,
        reviewed_sha256: String,
        private_plan_digest: String,
        public_plan_digest: String,
        target_sha256: String,
        parent_device: u64,
        parent_inode: u64,
        operator: u32,
    }
    impl Binding {
        fn from_prepared(
            prepared: &PreparedNpmExecution<'_>,
            reviewed: &str,
        ) -> Result<Self, String> {
            let NpmRecoveryPlanBinding {
                operation_id,
                private_plan_digest,
                public_plan_digest,
                target,
                parent_identity,
            } = prepared.recovery_plan_binding().map_err(error)?;
            Self::expected(
                &operation_id,
                reviewed,
                &private_plan_digest,
                &public_plan_digest,
                target.as_os_str().as_encoded_bytes(),
                parent_identity,
            )
        }
        fn expected(
            operation: &str,
            reviewed: &str,
            private: &str,
            public: &str,
            target: &[u8],
            parent: (u64, u64),
        ) -> Result<Self, String> {
            crate::cli::package_checkpoint::materialization_store::canonical_operation(operation)
                .map_err(error)?;
            if ![reviewed, private, public]
                .iter()
                .all(|value| digest_valid(value))
            {
                return Err("invalid npm recovery commitment".into());
            }
            Ok(Self {
                operation: operation.into(),
                reviewed_sha256: reviewed.into(),
                private_plan_digest: private.into(),
                public_plan_digest: public.into(),
                target_sha256: digest(target),
                parent_device: parent.0,
                parent_inode: parent.1,
                operator: unsafe { libc::geteuid() },
            })
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Phase {
        Private,
        Committed,
    }
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Payload {
        binding: Binding,
        tree: NpmRecoveryTreeObservation,
        npm_summary_sha256: String,
        private_receipt_id: String,
        private_receipt_sha256: String,
        committed_receipt_id: Option<String>,
        committed_receipt_sha256: Option<String>,
        private_milestone_sha256: Option<String>,
    }
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SignedMilestone {
        schema: u32,
        contract: String,
        phase: Phase,
        payload: Payload,
        signature: String,
    }
    /// Only record_private constructs this witness, after consuming current
    /// opaque native-completion, output-verification, and signed-receipt facts.
    pub(crate) struct PrivateNpmMilestone {
        envelope: SignedMilestone,
        sha256: String,
    }
    /// Verified historical signature and linkage, still not a completion proof
    /// for a running child or authority over the current tree.
    pub(crate) struct CommittedNpmObservation {
        pub(crate) tree: NpmRecoveryTreeObservation,
        pub(crate) private_receipt_id: String,
        pub(crate) committed_receipt_id: String,
        pub(crate) private_milestone_sha256: String,
        pub(crate) committed_milestone_sha256: String,
    }
    pub(crate) struct NpmRecoveryStore {
        operation: String,
        store: OperationStore,
    }
    impl NpmRecoveryStore {
        pub(crate) fn open(operation: &str, create: bool) -> Result<Self, String> {
            Ok(Self {
                operation: operation.into(),
                store: OperationStore::open_npm_recovery(operation, create).map_err(error)?,
            })
        }
        pub(crate) fn revalidate(&self) -> Result<(), String> {
            self.store.revalidate().map_err(error)
        }
        pub(crate) fn record_private(
            &mut self,
            reviewed_sha256: &str,
            completed: &CompletedNpmRun,
            prepared: &PreparedNpmExecution<'_>,
            tree: &VerifiedNpmTree,
            recorded: &RecordedPrivateReceipt,
        ) -> Result<PrivateNpmMilestone, String> {
            prepared.revalidate_for_publication(tree).map_err(error)?;
            completed.matches_binding(
                prepared.operation_id(),
                &tree.clone_retained_root().map_err(error)?,
            )?;
            let binding = Binding::from_prepared(prepared, reviewed_sha256)?;
            if binding.operation != self.operation {
                return Err("npm recovery operation changed".into());
            }
            let receipt = load_receipt(recorded.receipt_id())?;
            if receipt.publication_state() != ReceiptPublicationState::NpmPrivateVerified
                || receipt.npm_verification.as_ref()
                    != Some(&tree.receipt_summary().map_err(error)?)
            {
                return Err("private receipt differs from the current verified npm output".into());
            }
            let snapshot = tree.private_recovery_snapshot().map_err(error)?;
            let envelope = signed(
                Phase::Private,
                Payload {
                    binding,
                    tree: snapshot.observation().clone(),
                    npm_summary_sha256: summary_hash(&receipt)?,
                    private_receipt_id: recorded.receipt_id().into(),
                    private_receipt_sha256: receipt_hash(&receipt)?,
                    committed_receipt_id: None,
                    committed_receipt_sha256: None,
                    private_milestone_sha256: None,
                },
            )?;
            prepared.revalidate_for_publication(tree).map_err(error)?;
            completed.matches_binding(
                prepared.operation_id(),
                &tree.clone_retained_root().map_err(error)?,
            )?;
            if tree
                .private_recovery_snapshot()
                .map_err(error)?
                .observation()
                != &envelope.payload.tree
            {
                return Err("private npm output changed before milestone storage".into());
            }
            if receipt_hash(&load_receipt(recorded.receipt_id())?)?
                != envelope.payload.private_receipt_sha256
            {
                return Err("private npm receipt changed before milestone storage".into());
            }
            let bytes = encode(&envelope)?;
            self.store
                .append(RecordKind::PrivateMilestone, bytes.clone())
                .map_err(error)?;
            self.revalidate()?;
            Ok(PrivateNpmMilestone {
                envelope,
                sha256: digest(&bytes),
            })
        }
        pub(crate) fn record_committed(
            &mut self,
            private: &PrivateNpmMilestone,
            prepared: &PreparedNpmExecution<'_>,
            tree: &VerifiedNpmTree,
            recorded: &RecordedCommittedReceipt,
        ) -> Result<(), String> {
            prepared.revalidate_published(tree).map_err(error)?;
            let binding = Binding::from_prepared(
                prepared,
                &private.envelope.payload.binding.reviewed_sha256,
            )?;
            if binding != private.envelope.payload.binding
                || binding.operation != self.operation
                || recorded.private_receipt_id() != private.envelope.payload.private_receipt_id
            {
                return Err(
                    "committed npm milestone binding differs from private verification".into(),
                );
            }
            let stored_private = self
                .store
                .read(RecordKind::PrivateMilestone)
                .map_err(error)?
                .ok_or("private npm milestone unavailable")?;
            if digest(&stored_private) != private.sha256 {
                return Err("private npm milestone changed".into());
            }
            verify(&decode(&stored_private)?)?;
            let old_receipt = load_receipt(recorded.private_receipt_id())?;
            let receipt = load_receipt(recorded.receipt_id())?;
            if receipt_hash(&old_receipt)? != private.envelope.payload.private_receipt_sha256
                || !receipt.is_committed_publication_for(&old_receipt)
            {
                return Err("npm committed receipt is not the signed private derivation".into());
            }
            let snapshot = tree
                .recovery_snapshot_at(&prepared.target_policy_path())
                .map_err(error)?;
            if (
                snapshot.observation().root_device,
                snapshot.observation().root_inode,
            ) != (
                private.envelope.payload.tree.root_device,
                private.envelope.payload.tree.root_inode,
            ) {
                return Err("npm publication changed the verified root identity".into());
            }
            let mut payload = private.envelope.payload.clone();
            payload.tree = snapshot.observation().clone();
            payload.committed_receipt_id = Some(recorded.receipt_id().into());
            payload.committed_receipt_sha256 = Some(receipt_hash(&receipt)?);
            payload.private_milestone_sha256 = Some(private.sha256.clone());
            let envelope = signed(Phase::Committed, payload)?;
            prepared.revalidate_published(tree).map_err(error)?;
            if tree
                .recovery_snapshot_at(&prepared.target_policy_path())
                .map_err(error)?
                .observation()
                != &envelope.payload.tree
            {
                return Err("published npm output changed before milestone storage".into());
            }
            self.store
                .append(RecordKind::CommittedMilestone, encode(&envelope)?)
                .map_err(error)?;
            self.revalidate()
        }
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn load_committed(
            &mut self,
            reviewed: &str,
            private: &str,
            public: &str,
            target: &std::path::Path,
            parent: (u64, u64),
        ) -> Result<CommittedNpmObservation, String> {
            let expected = Binding::expected(
                &self.operation,
                reviewed,
                private,
                public,
                target.as_os_str().as_encoded_bytes(),
                parent,
            )?;
            let private_bytes = self
                .store
                .read(RecordKind::PrivateMilestone)
                .map_err(error)?
                .ok_or("complete signed private npm milestone unavailable; objects preserved")?;
            let committed_bytes = self.store.read(RecordKind::CommittedMilestone).map_err(error)?
                .ok_or("signed committed npm milestone unavailable; private or ambiguous objects preserved")?;
            let private: SignedMilestone = decode(&private_bytes)?;
            let committed: SignedMilestone = decode(&committed_bytes)?;
            verify(&private)?;
            verify(&committed)?;
            validate_pair(&private, &committed, &digest(&private_bytes), &expected)?;
            let before = load_receipt(&private.payload.private_receipt_id)?;
            let after = load_receipt(
                committed
                    .payload
                    .committed_receipt_id
                    .as_deref()
                    .ok_or("committed receipt id unavailable")?,
            )?;
            if receipt_hash(&before)? != private.payload.private_receipt_sha256
                || receipt_hash(&after)?
                    != *committed
                        .payload
                        .committed_receipt_sha256
                        .as_ref()
                        .ok_or("committed receipt binding unavailable")?
                || summary_hash(&before)? != private.payload.npm_summary_sha256
                || !after.is_committed_publication_for(&before)
            {
                return Err(
                    "saved npm receipts differ from their signed milestone content or linkage"
                        .into(),
                );
            }
            self.revalidate()?;
            Ok(CommittedNpmObservation {
                tree: committed.payload.tree,
                private_receipt_id: private.payload.private_receipt_id,
                committed_receipt_id: committed
                    .payload
                    .committed_receipt_id
                    .ok_or("committed receipt id unavailable")?,
                private_milestone_sha256: digest(&private_bytes),
                committed_milestone_sha256: digest(&committed_bytes),
            })
        }
    }
    fn validate_pair(
        private: &SignedMilestone,
        committed: &SignedMilestone,
        private_sha: &str,
        expected: &Binding,
    ) -> Result<(), String> {
        if private.phase != Phase::Private
            || committed.phase != Phase::Committed
            || private.payload.binding != *expected
            || committed.payload.binding != *expected
            || committed.payload.private_milestone_sha256.as_deref() != Some(private_sha)
            || committed.payload.private_receipt_id != private.payload.private_receipt_id
            || committed.payload.private_receipt_sha256 != private.payload.private_receipt_sha256
            || committed.payload.npm_summary_sha256 != private.payload.npm_summary_sha256
            || (
                committed.payload.tree.root_device,
                committed.payload.tree.root_inode,
            ) != (
                private.payload.tree.root_device,
                private.payload.tree.root_inode,
            )
        {
            return Err(
                "npm recovery milestones do not form the exact signed completion chain".into(),
            );
        }
        Ok(())
    }
    fn validate(envelope: &SignedMilestone) -> Result<(), String> {
        let p = &envelope.payload;
        if envelope.schema != SCHEMA
            || envelope.contract != CONTRACT
            || ![
                p.binding.reviewed_sha256.as_str(),
                &p.binding.private_plan_digest,
                &p.binding.public_plan_digest,
                &p.binding.target_sha256,
                &p.tree.sha256,
                &p.npm_summary_sha256,
                &p.private_receipt_id,
                &p.private_receipt_sha256,
            ]
            .iter()
            .all(|value| digest_valid(value))
            || p.tree.files == 0
            || p.tree.directories == 0
            || p.tree
                .files
                .checked_add(p.tree.directories)
                .is_none_or(|n| n > tirith_core::artifact::npm_install::MAX_INSTALLED_ENTRIES)
            || p.tree.bytes == 0
            || p.tree.bytes > tirith_core::artifact::npm_install::MAX_TOTAL_INSTALLED_BYTES
            || match envelope.phase {
                Phase::Private => {
                    p.committed_receipt_id.is_some()
                        || p.committed_receipt_sha256.is_some()
                        || p.private_milestone_sha256.is_some()
                }
                Phase::Committed => {
                    ![
                        p.committed_receipt_id.as_deref(),
                        p.committed_receipt_sha256.as_deref(),
                        p.private_milestone_sha256.as_deref(),
                    ]
                    .iter()
                    .all(|value| value.is_some_and(digest_valid))
                        || p.committed_receipt_id.as_deref() == Some(p.private_receipt_id.as_str())
                }
            }
        {
            return Err("unsupported or inconsistent npm completion milestone".into());
        }
        crate::cli::package_checkpoint::materialization_store::canonical_operation(
            &p.binding.operation,
        )
        .map_err(error)
    }
    fn signed(phase: Phase, payload: Payload) -> Result<SignedMilestone, String> {
        let mut envelope = SignedMilestone {
            schema: SCHEMA,
            contract: CONTRACT.into(),
            phase,
            payload,
            signature: String::new(),
        };
        validate(&envelope)?;
        envelope.signature =
            tirith_core::audit::sign_canonical_bytes(&signing_bytes(&envelope)?)
                .ok_or("trusted audit signing is unavailable for npm completion milestone")?;
        verify(&envelope)?;
        Ok(envelope)
    }
    fn verify(envelope: &SignedMilestone) -> Result<(), String> {
        let key = tirith_core::audit::audit_verifying_key_bytes()
            .ok_or("trusted audit verification key unavailable; npm objects preserved")?;
        verify_with_key(envelope, key)
    }
    /// Check the exact configured signing/verifying key pair before any npm
    /// process is started. No store is created, and this challenge is deliberately
    /// in a different signature domain from persisted completion milestones.
    pub(crate) fn preflight_milestone_signing() -> Result<(), String> {
        let mut challenge = b"tirith-npm-completion-preflight-v1\0".to_vec();
        challenge.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
        let signature = tirith_core::audit::sign_canonical_bytes(&challenge);
        let key = tirith_core::audit::audit_verifying_key_bytes();
        verify_preflight_signature(
            &challenge,
            signature.as_deref(),
            key.as_ref().map(|key| key.as_slice()),
        )
    }
    fn verify_preflight_signature(
        challenge: &[u8],
        signature: Option<&str>,
        public_key: Option<&[u8]>,
    ) -> Result<(), String> {
        let signature =
            signature.ok_or("npm completion signing key unavailable before execution")?;
        let public_key = public_key
            .ok_or("trusted npm completion verifying key unavailable before execution")?;
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| "npm completion verifying key has an invalid length")?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
            .map_err(|_| "npm completion verifying key is invalid")?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(signature)
            .map_err(|_| "npm completion preflight signature encoding is invalid")?;
        let signature = ed25519_dalek::Signature::from_slice(&decoded)
            .map_err(|_| "npm completion preflight signature length is invalid")?;
        key.verify_strict(challenge, &signature)
            .map_err(|_| "npm completion signing and trusted verifying keys do not match".into())
    }

    fn verify_with_key(envelope: &SignedMilestone, key: [u8; 32]) -> Result<(), String> {
        validate(envelope)?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(error)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&envelope.signature)
            .map_err(error)?;
        let signature = ed25519_dalek::Signature::from_slice(&bytes).map_err(error)?;
        key.verify_strict(&signing_bytes(envelope)?, &signature)
            .map_err(|_| "npm completion milestone signature refused".into())
    }
    fn signing_bytes(envelope: &SignedMilestone) -> Result<Vec<u8>, String> {
        let mut value = serde_json::to_value(envelope).map_err(error)?;
        value["signature"] = serde_json::json!("");
        let mut bytes = b"tirith-npm-completion-milestone-v1\0".to_vec();
        bytes.extend_from_slice(tirith_core::audit::canonical_json_for_hash(&value).as_bytes());
        Ok(bytes)
    }
    fn load_receipt(id: &str) -> Result<ArtifactScanReceipt, String> {
        let receipt = ArtifactScanReceipt::load(id)?;
        if receipt.receipt_id != id || !receipt.content_hash_matches() {
            return Err("npm recovery receipt content differs from signed identity".into());
        }
        let summary = receipt
            .npm_verification
            .as_ref()
            .ok_or("npm recovery receipt lacks exact npm evidence")?;
        summary.validate_stored().map_err(str::to_owned)?;
        Ok(receipt)
    }
    fn summary_hash(receipt: &ArtifactScanReceipt) -> Result<String, String> {
        let summary = receipt
            .npm_verification
            .as_ref()
            .ok_or("npm verification unavailable")?;
        Ok(digest(
            tirith_core::audit::canonical_json_for_hash(
                &serde_json::to_value(summary).map_err(error)?,
            )
            .as_bytes(),
        ))
    }
    fn receipt_hash(receipt: &ArtifactScanReceipt) -> Result<String, String> {
        Ok(digest(
            tirith_core::audit::canonical_json_for_hash(
                &serde_json::to_value(receipt).map_err(error)?,
            )
            .as_bytes(),
        ))
    }
    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
    fn digest_valid(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    fn error(error: impl std::fmt::Debug) -> String {
        format!("npm recovery evidence refused: {error:?}")
    }
    fn encode(value: &impl Serialize) -> Result<Vec<u8>, String> {
        let bytes = serde_json::to_vec(value).map_err(error)?;
        if bytes.is_empty() || bytes.len() > RECORD_CAP {
            return Err("npm recovery milestone exceeds bound".into());
        }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<SignedMilestone, String> {
        if bytes.is_empty() || bytes.len() > RECORD_CAP {
            return Err("npm recovery milestone exceeds bound".into());
        }
        serde_json::from_slice(bytes).map_err(error)
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use ed25519_dalek::Signer;
        const ID: &str = "11111111-1111-4111-8111-111111111111";
        fn fixture() -> SignedMilestone {
            SignedMilestone {
                schema: SCHEMA,
                contract: CONTRACT.into(),
                phase: Phase::Private,
                payload: Payload {
                    binding: Binding::expected(
                        ID,
                        &"a".repeat(64),
                        &"b".repeat(64),
                        &"c".repeat(64),
                        b"/fixture/target",
                        (1, 2),
                    )
                    .unwrap(),
                    tree: NpmRecoveryTreeObservation {
                        sha256: "d".repeat(64),
                        root_device: 1,
                        root_inode: 3,
                        files: 1,
                        directories: 1,
                        bytes: 10,
                    },
                    npm_summary_sha256: "e".repeat(64),
                    private_receipt_id: "f".repeat(64),
                    private_receipt_sha256: "0".repeat(64),
                    committed_receipt_id: None,
                    committed_receipt_sha256: None,
                    private_milestone_sha256: None,
                },
                signature: String::new(),
            }
        }
        fn fixture_sign(value: &mut SignedMilestone, key: &ed25519_dalek::SigningKey) {
            value.signature = base64::engine::general_purpose::STANDARD
                .encode(key.sign(&signing_bytes(value).unwrap()).to_bytes());
        }
        #[test]
        fn trusted_signature_is_required_even_when_all_public_hashes_are_recomputed() {
            let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
            let other = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
            let mut original = fixture();
            fixture_sign(&mut original, &key);
            assert!(verify_with_key(&original, key.verifying_key().to_bytes()).is_ok());
            assert!(verify_with_key(&original, other.verifying_key().to_bytes()).is_err());
            for field in ["tree", "target", "private", "receipt", "operator"] {
                let mut changed = original.clone();
                match field {
                    "tree" => changed.payload.tree.sha256 = "1".repeat(64),
                    "target" => changed.payload.binding.target_sha256 = "1".repeat(64),
                    "private" => changed.payload.binding.private_plan_digest = "1".repeat(64),
                    "receipt" => changed.payload.private_receipt_sha256 = "1".repeat(64),
                    _ => changed.payload.binding.operator ^= 1,
                }
                assert!(
                    verify_with_key(&changed, key.verifying_key().to_bytes()).is_err(),
                    "{field}"
                );
                fixture_sign(&mut changed, &other);
                assert!(
                    verify_with_key(&changed, key.verifying_key().to_bytes()).is_err(),
                    "{field}"
                );
            }
            let mut unsigned = original;
            unsigned.signature.clear();
            assert!(verify_with_key(&unsigned, key.verifying_key().to_bytes()).is_err());
        }
        #[test]
        fn committed_milestone_requires_exact_private_envelope_receipt_and_root_binding() {
            let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
            let mut private = fixture();
            fixture_sign(&mut private, &key);
            let hash = digest(&encode(&private).unwrap());
            let mut committed = private.clone();
            committed.phase = Phase::Committed;
            committed.payload.committed_receipt_id = Some("1".repeat(64));
            committed.payload.committed_receipt_sha256 = Some("2".repeat(64));
            committed.payload.private_milestone_sha256 = Some(hash.clone());
            // Publication legitimately changes the root generation in its whole-tree digest.
            committed.payload.tree.sha256 = "3".repeat(64);
            fixture_sign(&mut committed, &key);
            assert!(verify_with_key(&committed, key.verifying_key().to_bytes()).is_ok());
            assert!(validate_pair(&private, &committed, &hash, &private.payload.binding).is_ok());
            for field in ["predecessor", "receipt", "root", "plan"] {
                let mut changed = committed.clone();
                match field {
                    "predecessor" => {
                        changed.payload.private_milestone_sha256 = Some("4".repeat(64))
                    }
                    "receipt" => changed.payload.private_receipt_id = "4".repeat(64),
                    "root" => changed.payload.tree.root_inode += 1,
                    _ => changed.payload.binding.public_plan_digest = "4".repeat(64),
                }
                fixture_sign(&mut changed, &key);
                assert!(
                    validate_pair(&private, &changed, &hash, &private.payload.binding).is_err(),
                    "{field}"
                );
            }
        }
        #[test]
        fn malformed_unknown_and_oversized_milestones_do_not_parse_as_authority() {
            let value = fixture();
            let mut raw = serde_json::to_value(&value).unwrap();
            raw["stored_verification_key"] = serde_json::json!("untrusted");
            assert!(decode(&serde_json::to_vec(&raw).unwrap()).is_err());
            assert!(decode(&vec![b' '; RECORD_CAP + 1]).is_err());
            let mut changed = value.clone();
            changed.schema += 1;
            assert!(validate(&changed).is_err());
            let mut changed = value.clone();
            changed.payload.tree.files = usize::MAX;
            assert!(validate(&changed).is_err());
            let mut changed = value;
            changed.phase = Phase::Committed;
            assert!(validate(&changed).is_err());
        }
        #[test]
        fn private_only_or_unsigned_store_is_preserved_without_reconfirmation() {
            let _scope = tirith_test_support::GlobalStateGuard::new().unwrap();
            let mut store = NpmRecoveryStore::open(ID, true).unwrap();
            let private = encode(&fixture()).unwrap();
            store
                .store
                .append(RecordKind::PrivateMilestone, private.clone())
                .unwrap();
            assert!(store
                .load_committed(
                    &"a".repeat(64),
                    &"b".repeat(64),
                    &"c".repeat(64),
                    std::path::Path::new("/fixture/target"),
                    (1, 2)
                )
                .is_err());
            assert_eq!(
                store.store.read(RecordKind::PrivateMilestone).unwrap(),
                Some(private)
            );
            assert!(store
                .store
                .read(RecordKind::CommittedMilestone)
                .unwrap()
                .is_none());
            assert!(store
                .store
                .append(RecordKind::Started, b"{}".to_vec())
                .is_err());
            assert!(store.revalidate().is_ok());
        }
        #[test]
        fn valid_signed_private_observation_still_cannot_recover_without_committed_milestone() {
            let _scope = tirith_test_support::GlobalStateGuard::new().unwrap();
            let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
            // Synthetic signed history tests admission only. It cannot construct
            // CompletedNpmRun or be passed to either opaque milestone issuer.
            let mut private = fixture();
            fixture_sign(&mut private, &key);
            verify_with_key(&private, key.verifying_key().to_bytes()).unwrap();
            let bytes = encode(&private).unwrap();
            let mut store = NpmRecoveryStore::open(ID, true).unwrap();
            store
                .store
                .append(RecordKind::PrivateMilestone, bytes.clone())
                .unwrap();
            let failure = store
                .load_committed(
                    &"a".repeat(64),
                    &"b".repeat(64),
                    &"c".repeat(64),
                    std::path::Path::new("/fixture/target"),
                    (1, 2),
                )
                .err()
                .unwrap();
            assert!(failure.contains("committed npm milestone unavailable"));
            assert_eq!(
                store.store.read(RecordKind::PrivateMilestone).unwrap(),
                Some(bytes)
            );
            assert!(store
                .store
                .read(RecordKind::CommittedMilestone)
                .unwrap()
                .is_none());
        }

        #[test]
        fn interrupted_committed_milestone_append_preserves_both_records_and_refuses_reconfirmation(
        ) {
            let _scope = tirith_test_support::GlobalStateGuard::new().unwrap();
            let mut store = NpmRecoveryStore::open(ID, true).unwrap();
            let private = encode(&fixture()).unwrap();
            let truncated =
                br#"{"schema":1,"contract":"LocalLeafNoScriptsV1","phase":"committed"#.to_vec();
            store
                .store
                .append(RecordKind::PrivateMilestone, private.clone())
                .unwrap();
            store
                .store
                .append(RecordKind::CommittedMilestone, truncated.clone())
                .unwrap();
            assert!(store
                .load_committed(
                    &"a".repeat(64),
                    &"b".repeat(64),
                    &"c".repeat(64),
                    std::path::Path::new("/fixture/target"),
                    (1, 2)
                )
                .is_err());
            assert_eq!(
                store.store.read(RecordKind::PrivateMilestone).unwrap(),
                Some(private)
            );
            assert_eq!(
                store.store.read(RecordKind::CommittedMilestone).unwrap(),
                Some(truncated)
            );
            assert!(store
                .store
                .append(RecordKind::CommittedMilestone, b"{}".to_vec())
                .is_err());
        }

        #[test]
        fn milestone_preflight_requires_matching_complete_signature_and_trusted_public_key() {
            let challenge = b"tirith-npm-completion-preflight-v1\0isolated-test-challenge";
            let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
            let other = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
            let public = key.verifying_key().to_bytes();
            let signature =
                base64::engine::general_purpose::STANDARD.encode(key.sign(challenge).to_bytes());
            assert!(verify_preflight_signature(challenge, Some(&signature), Some(&public)).is_ok());
            assert!(verify_preflight_signature(challenge, None, Some(&public)).is_err());
            assert!(verify_preflight_signature(challenge, Some(&signature), None).is_err());
            assert!(
                verify_preflight_signature(challenge, Some(&signature), Some(&public[..31]))
                    .is_err()
            );
            assert!(verify_preflight_signature(
                challenge,
                Some(&signature),
                Some(&other.verifying_key().to_bytes())
            )
            .is_err());
            assert!(verify_preflight_signature(
                b"different-domain-or-challenge",
                Some(&signature),
                Some(&public)
            )
            .is_err());
            let short_signature = base64::engine::general_purpose::STANDARD.encode([0u8; 63]);
            for invalid in ["", "not-base64!", &short_signature] {
                assert!(
                    verify_preflight_signature(challenge, Some(invalid), Some(&public)).is_err()
                );
            }
        }
    }
}
#[cfg(target_os = "linux")]
pub(crate) use linux::{preflight_milestone_signing, CommittedNpmObservation, NpmRecoveryStore};
