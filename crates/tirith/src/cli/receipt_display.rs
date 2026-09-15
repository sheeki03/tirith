//! Bounded saved-receipt reads and separate, freshly redacted display values.
//! Canonical records remain untouched and never receive display substitutions.

use serde_json::Value;
use tirith_core::output_contract::{redact_projection, Projection};
use tirith_core::receipt::{ArtifactScanReceipt, Receipt};
use tirith_core::redact::CompiledCustomPatterns;

const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

pub(super) fn output_dlp() -> CompiledCustomPatterns {
    let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
    let cwd = std::env::current_dir()
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    let policy = tirith_core::policy_snapshot::EffectivePolicySnapshot::resolve(
        cwd.as_deref(),
        tirith_core::policy_snapshot::ResolutionMode::Runtime,
    );
    let patterns =
        tirith_core::policy::captured_policy_dlp_patterns_or(&policy.policy.dlp_custom_patterns);
    let compiled = CompiledCustomPatterns::new_silent(&patterns);
    for diagnostic in tirith_core::policy::drain_captured_policy_diagnostics_for_output(&compiled) {
        eprintln!("{diagnostic}");
    }
    compiled
}

pub(super) use tirith_core::receipt::stored::{
    list_artifact, list_download, load_artifact, load_download, verify_download,
};

pub(super) fn download(receipt: &Receipt, compiled: &CompiledCustomPatterns) -> Value {
    let mut value = serde_json::to_value(
        receipt
            .presentation_clone_with_compiled(compiled)
            .public_view(),
    )
    .expect("receipt contains only serializable fields");
    // Stored records can be edited: only canonical enum/digest/time values get
    // the protocol exemption, even though original producers generate them.
    redact_projection(&mut value, Projection::RunReceipt, compiled);
    value
}

pub(super) fn artifact(receipt: &ArtifactScanReceipt, compiled: &CompiledCustomPatterns) -> Value {
    let mut value =
        serde_json::to_value(receipt).expect("receipt contains only serializable fields");
    redact_projection(&mut value, Projection::ArtifactReceipt, compiled);
    value
}

pub(super) fn artifact_display(
    receipt: &ArtifactScanReceipt,
    compiled: &CompiledCustomPatterns,
) -> Value {
    let mut display = artifact(receipt, compiled);
    let id = display
        .as_object_mut()
        .expect("receipt is an object")
        .remove("receipt_id");
    serde_json::json!({
        "kind":"artifact_receipt_display", "schema_version":1, "display_only":true,
        "canonical_receipt_id":id, "stored_content_hash_matches":receipt.content_hash_matches(),
        "signature_verification":"not_performed", "receipt":display
    })
}

pub(super) fn artifact_canonical(
    receipt: &ArtifactScanReceipt,
    compiled: &CompiledCustomPatterns,
) -> Result<Value, &'static str> {
    let canonical = serde_json::to_value(receipt).map_err(|_| "Receipt serialization failed.")?;
    if artifact(receipt, compiled) != canonical {
        return Err("Current privacy rules require a redacted display. Use --format display-json; canonical stored receipt bytes remain unchanged.");
    }
    Ok(canonical)
}

pub(super) fn bounded(value: &Value) -> Result<(), &'static str> {
    if serde_json::to_vec_pretty(value).map_or(true, |bytes| bytes.len() > MAX_OUTPUT_BYTES) {
        Err("Receipt output exceeds the presentation limit; select a receipt by ID.")
    } else {
        Ok(())
    }
}

pub(super) fn write(value: &Value) -> bool {
    match bounded(value) {
        Ok(()) => super::write_json_stdout(value, "tirith receipt: failed to write JSON output"),
        Err(error) => {
            eprintln!("tirith receipt: {error}");
            false
        }
    }
}

pub(super) fn text(value: &Value, key: &str) -> String {
    super::sanitize_for_human_output(
        value
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("unavailable"),
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_core::receipt::{CapsuleReceipt, VerdictSummary};

    fn artifact_receipt() -> ArtifactScanReceipt {
        ArtifactScanReceipt::new(
            "0.4.2".into(),
            "c".repeat(64),
            9,
            "uv pinned-private-index".into(),
            "0.8.22".into(),
            "25.1".into(),
            CapsuleReceipt {
                backend_id: "landlock-seccomp".into(),
                coverage: tirith_core::capsule::CapsuleCoverage::NONE,
            },
            vec!["b".repeat(64)],
            None,
            VerdictSummary {
                action: "Allow".into(),
                rule_ids: vec![],
                finding_count: 0,
            },
        )
    }

    fn download_receipt() -> Receipt {
        serde_json::from_value(serde_json::json!({
            "url":"https://name:password@example.test/install?token=receipt-canary#secret",
            "final_url":null,"redirects":[],"sha256":"a".repeat(64),"size":3,
            "domains_referenced":["receipt-canary.example.test"],"paths_referenced":["/receipt-canary/key"],
            "analysis_method":"receipt-canary","privilege":"user","timestamp":"2026-09-12T00:00:00Z",
            "cwd":"/receipt-canary/private","git_repo":null,"git_branch":"receipt-canary"
        })).unwrap()
    }

    #[test]
    fn expanded_json_output_obeys_the_presentation_budget() {
        let within = serde_json::json!({"content":"x".repeat(MAX_OUTPUT_BYTES / 2)});
        assert!(bounded(&within).is_ok());
        let escaped = serde_json::json!({"content":"\u{0001}".repeat(MAX_OUTPUT_BYTES / 2)});
        assert!(bounded(&escaped).is_err());
    }

    #[test]
    fn tightened_privacy_refuses_canonical_export_without_rewriting_signed_content() {
        let receipt = artifact_receipt();
        let original = serde_json::to_vec(&receipt).unwrap();
        let empty = CompiledCustomPatterns::new_silent(&[]);
        assert_eq!(
            artifact_canonical(&receipt, &empty).unwrap(),
            serde_json::to_value(&receipt).unwrap()
        );
        let compiled = CompiledCustomPatterns::new_silent(&["pinned-private-index".into()]);
        assert!(artifact_canonical(&receipt, &compiled)
            .unwrap_err()
            .contains("display-json"));
        let shown = artifact_display(&receipt, &compiled);
        assert!(!shown.to_string().contains("pinned-private-index"));
        assert_eq!(shown["canonical_receipt_id"], receipt.receipt_id);
        assert_eq!(shown["stored_content_hash_matches"], true);
        assert_eq!(shown["signature_verification"], "not_performed");
        assert!(shown["receipt"].get("receipt_id").is_none());
        assert!(serde_json::from_value::<ArtifactScanReceipt>(shown).is_err());
        assert_eq!(serde_json::to_vec(&receipt).unwrap(), original);
        assert!(receipt.content_hash_matches());
    }

    #[test]
    fn catch_all_patterns_preserve_only_typed_receipt_protocol_values() {
        let receipt = artifact_receipt();
        let compiled = CompiledCustomPatterns::new_silent(&[".+".into()]);
        let shown = artifact_display(&receipt, &compiled);
        assert_eq!(shown["canonical_receipt_id"], receipt.receipt_id);
        assert_eq!(shown["receipt"]["policy_hash"], receipt.policy_hash);
        assert_eq!(
            shown["receipt"]["capsule"]["backend_id"],
            "landlock-seccomp"
        );
        assert_eq!(shown["receipt"]["verdict"]["action"], "Allow");
        assert_eq!(shown["receipt"]["timestamp"], receipt.timestamp);
        assert_eq!(shown["receipt"]["resolver_command"], "[REDACTED:custom]");
        let mut tampered = receipt.clone();
        tampered.verdict.action = "secret-action".into();
        tampered.capsule.backend_id = "secret-backend".into();
        let tampered = artifact_display(&tampered, &compiled);
        assert_eq!(tampered["stored_content_hash_matches"], false);
        assert!(!tampered.to_string().contains("secret-"));
    }

    #[test]
    fn saved_download_views_reapply_policy_and_validate_edited_protocol_fields() {
        let mut receipt = download_receipt();
        let original = serde_json::to_vec(&receipt).unwrap();
        let compiled = CompiledCustomPatterns::new_silent(&["receipt-canary".into()]);
        let shown = download(&receipt, &compiled);
        for secret in ["receipt-canary", "name:password", "token=", "#secret"] {
            assert!(!shown.to_string().contains(secret), "{secret}");
        }
        assert!(shown.get("cwd").is_none());
        assert_eq!(shown["sha256"], receipt.sha256);
        assert_eq!(shown["privilege"], "user");
        assert_eq!(serde_json::to_vec(&receipt).unwrap(), original);
        receipt.privilege = "receipt-canary".into();
        receipt.timestamp = "receipt-canary".into();
        let shown = download(&receipt, &compiled);
        assert!(!shown.to_string().contains("receipt-canary"));
    }
}
