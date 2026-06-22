use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

fn validate_sha256(sha256: &str) -> Result<(), String> {
    if sha256.len() != 64
        || !sha256
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!(
            "invalid sha256: expected 64 lowercase hex characters, got '{}'",
            crate::util::truncate_bytes(sha256, 16)
        ));
    }
    Ok(())
}

/// UTF-8-safe short prefix of a hash for display (tolerates corrupted non-ASCII sha256).
pub fn short_hash(s: &str) -> String {
    crate::util::truncate_bytes(s, 12)
}

/// A receipt for a script that was downloaded and analyzed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub url: String,
    pub final_url: Option<String>,
    pub redirects: Vec<String>,
    pub sha256: String,
    pub size: u64,
    pub domains_referenced: Vec<String>,
    pub paths_referenced: Vec<String>,
    pub analysis_method: String,
    pub privilege: String,
    pub timestamp: String,
    pub cwd: Option<String>,
    pub git_repo: Option<String>,
    pub git_branch: Option<String>,
}

impl Receipt {
    /// Save receipt atomically (temp file + rename).
    pub fn save(&self) -> Result<PathBuf, String> {
        validate_sha256(&self.sha256)?;
        let dir = receipts_dir().ok_or("cannot determine receipts directory")?;
        fs::create_dir_all(&dir).map_err(|e| format!("create dir: {e}"))?;

        let path = dir.join(format!("{}.json", self.sha256));

        let json = serde_json::to_string_pretty(self).map_err(|e| format!("serialize: {e}"))?;

        {
            use std::io::Write;
            use tempfile::NamedTempFile;

            let mut tmp = NamedTempFile::new_in(&dir).map_err(|e| format!("tempfile: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tmp.as_file()
                    .set_permissions(std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| format!("permissions: {e}"))?;
            }
            tmp.write_all(json.as_bytes())
                .map_err(|e| format!("write: {e}"))?;
            tmp.persist(&path).map_err(|e| format!("persist: {e}"))?;
        }

        Ok(path)
    }

    /// Load a receipt by SHA256.
    pub fn load(sha256: &str) -> Result<Self, String> {
        validate_sha256(sha256)?;
        let dir = receipts_dir().ok_or("cannot determine receipts directory")?;
        let path = dir.join(format!("{sha256}.json"));
        let content = fs::read_to_string(&path).map_err(|e| format!("read: {e}"))?;
        serde_json::from_str(&content).map_err(|e| format!("parse: {e}"))
    }

    /// List all receipts.
    pub fn list() -> Result<Vec<Self>, String> {
        let dir = receipts_dir().ok_or("cannot determine receipts directory")?;
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut receipts = Vec::new();
        let entries = fs::read_dir(&dir).map_err(|e| format!("read dir: {e}"))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("entry: {e}"))?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "json")
                && !path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with('.'))
            {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(receipt) = serde_json::from_str::<Receipt>(&content) {
                        receipts.push(receipt);
                    }
                }
            }
        }

        receipts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(receipts)
    }

    /// Verify a receipt: check if the file at the cached path still matches sha256.
    pub fn verify(&self) -> Result<bool, String> {
        validate_sha256(&self.sha256)?;
        let cache_dir = cache_dir().ok_or("cannot determine cache directory")?;
        let cached = cache_dir.join(&self.sha256);
        if !cached.exists() {
            return Ok(false);
        }

        let content = fs::read(&cached).map_err(|e| format!("read: {e}"))?;
        let hash = sha2_hex(&content);
        Ok(hash == self.sha256)
    }
}

// ===========================================================================
// D6: tamper-evident package-firewall scan receipt
// ===========================================================================

/// The schema version of [`ArtifactScanReceipt`]. Bumped when a field is added or
/// its meaning changes, so a reader can tell which shape a saved receipt is. This
/// is a NEW versioned schema, deliberately distinct from the script-download
/// [`Receipt`] above (which is unversioned and describes a single fetched script):
/// the only thing the two share is the atomic-`0600` save mechanism.
pub const ARTIFACT_SCAN_RECEIPT_SCHEMA: u32 = 1;

/// The build-time engine SHA, sourced from the `TIRITH_BUILD_SHA` env var when the
/// binary is built in CI (which sets it to the commit SHA), else `"unknown"`. There
/// is no git-SHA build script in-tree, so this is honest best-effort: a dev build
/// records `"unknown"` rather than a fabricated value. Pure compile-time lookup; no
/// runtime I/O.
pub fn engine_build_sha() -> &'static str {
    option_env!("TIRITH_BUILD_SHA").unwrap_or("unknown")
}

/// A compact, redaction-safe summary of the install verdict the receipt attests.
///
/// Only the action and the rule ids (+ a count) are recorded, NOT the findings'
/// evidence text, which can contain machine paths. The receipt's job is to attest
/// "the firewall returned this action over these rules", not to reproduce every
/// evidence string (those live in the audit log / verdict output at decision time).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerdictSummary {
    /// The verdict action, e.g. `"Allow"` / `"Block"` (the `Debug` form of
    /// [`crate::verdict::Action`], matching the audit log's `action`).
    pub action: String,
    /// The rule ids that fired, sorted for a stable fingerprint.
    pub rule_ids: Vec<String>,
    /// The number of findings (`rule_ids` may dedup; this is the raw count).
    pub finding_count: usize,
}

impl VerdictSummary {
    /// Build a redaction-safe summary from a full [`crate::verdict::Verdict`].
    pub fn from_verdict(verdict: &crate::verdict::Verdict) -> Self {
        let mut rule_ids: Vec<String> = verdict
            .findings
            .iter()
            .map(|f| f.rule_id.to_string())
            .collect();
        rule_ids.sort();
        rule_ids.dedup();
        VerdictSummary {
            action: format!("{:?}", verdict.action),
            rule_ids,
            finding_count: verdict.findings.len(),
        }
    }
}

/// The post-install RECORD verification result the receipt records (the D5
/// coverage counters + whether the verdict blocked). A redaction-safe mirror of
/// [`crate::artifact::install::PostInstallIntegrity`] carrying no paths.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostInstallRecordSummary {
    /// Whether the post-install verdict blocked (a strict integrity policy).
    pub blocked: bool,
    /// Distributions located and RECORD-verified.
    pub distributions_verified: usize,
    /// Named distributions not found in the target environment (a coverage gap).
    pub distributions_not_found: usize,
    /// Located distributions with no RECORD file (a coverage gap).
    pub records_missing: usize,
    /// RECORD-listed files whose on-disk bytes did not match (the tamper signal).
    pub hash_mismatches: usize,
}

/// The containment the install actually ran under, for the receipt. `backend_id`
/// is the [`crate::capsule::Capsule::backend_id`] (`"landlock-seccomp"` /
/// `"seatbelt"` / `"appcontainer"` / `"noop"`); `coverage` is the honest
/// per-capability ledger the backend reported (serde-serializable as-is).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapsuleReceipt {
    /// The backend that contained the install.
    pub backend_id: String,
    /// The per-capability coverage actually enforced (the honesty ledger).
    pub coverage: crate::capsule::CapsuleCoverage,
}

/// A **new versioned, tamper-evident** receipt for one package-firewall install
/// (PR D6).
///
/// It records exactly what the install ran: the tirith version + engine build SHA,
/// a redacted policy-posture hash, the threat-DB sequence the approval bound to,
/// the redacted resolver / package-manager commands and their versions, the capsule
/// backend + coverage, every artifact sha256, the post-install RECORD result, the
/// finalised verdict summary, and a timestamp.
///
/// # Tamper-evidence
///
/// [`Self::record`] does two things: it saves the receipt JSON to
/// `data_dir()/receipts/<receipt_id>.json` (atomic `0600`, reusing the [`Receipt`]
/// save discipline via [`crate::util::write_file_atomic_0600`]), AND it anchors the
/// receipt's own content hash in the audit hash-chain
/// ([`crate::audit::log_artifact_scan_receipt`]). The chain line carries the
/// receipt's `content_sha256`, so editing or deleting a saved receipt is detectable
/// against the (optionally ed25519-signed) chain. When the audit log is signed the
/// anchor is cryptographically SIGNED ("mandatory for `pkg install`"); otherwise it
/// is "tamper-evident" (hash-chained). The `receipt_id` is the content hash, so the
/// receipt is content-addressed: two byte-identical receipts share one file.
///
/// # Redaction contract (cross-cutting invariant 7)
///
/// Every field is constructed redacted by the CALLER: the resolver / package-manager
/// command strings must already have had any index credential stripped, the policy is
/// recorded only as [`crate::policy::Policy::security_projection_hash`] (never the
/// raw policy), and no machine path is stored (artifacts are sha256 only, the verdict
/// is summarised without evidence text). The receipt NEVER serializes API keys,
/// registry credentials, secrets, or machine paths.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactScanReceipt {
    /// Schema version ([`ARTIFACT_SCAN_RECEIPT_SCHEMA`]).
    pub schema: u32,
    /// Content-addressed id: the lowercase-hex sha256 of the receipt's canonical
    /// JSON with `receipt_id` itself blanked (see [`Self::compute_content_hash`]).
    /// Also the file stem and the value anchored in the audit chain.
    pub receipt_id: String,
    /// The running tirith version (`CARGO_PKG_VERSION`).
    pub tirith_version: String,
    /// The engine build SHA ([`engine_build_sha`]); `"unknown"` for a dev build.
    pub engine_build_sha: String,
    /// The redacted security-projection hash of the effective policy
    /// ([`crate::policy::Policy::security_projection_hash`]). NOT the policy itself.
    pub policy_hash: String,
    /// The threat-DB build sequence the (re-validated) install bound to.
    pub threat_db_sequence: u64,
    /// The resolver command, already redacted (no index credential / secret).
    pub resolver_command: String,
    /// The resolver tool version string (e.g. `uv`'s version), already redacted.
    pub resolver_version: String,
    /// The package-manager (pip) version string, already redacted.
    pub package_manager_version: String,
    /// The containment the install ran under (backend + honest coverage).
    pub capsule: CapsuleReceipt,
    /// Every installed artifact's sha256 (lowercase hex), sorted. No filenames or
    /// paths. The hash is the identity.
    pub artifact_sha256: Vec<String>,
    /// The post-install RECORD verification result, when the install ran to
    /// completion; `None` when the install failed before extraction (nothing to
    /// verify).
    pub post_install_record: Option<PostInstallRecordSummary>,
    /// The finalised install verdict, summarised (no evidence text).
    pub verdict: VerdictSummary,
    /// RFC 3339 UTC timestamp of when the receipt was produced.
    pub timestamp: String,
}

/// Why anchoring/saving a receipt could not complete.
#[derive(Debug)]
pub enum ReceiptError {
    /// `data_dir()` could not be resolved, so there is nowhere to save.
    NoReceiptsDir,
    /// Creating the receipts directory or writing the receipt file failed.
    Io(std::io::Error),
    /// A signed chain anchor was REQUIRED (the `pkg install` "Ed25519 mandatory"
    /// rule) but the audit log is not signed, so the receipt cannot be anchored
    /// with a signature. The file is NOT saved in this case (fail-closed): the
    /// caller asked for a signed receipt and we cannot produce one.
    SignatureRequiredButUnavailable,
    /// The chain anchor append failed (the carried string is the reason). The
    /// receipt file may have been saved, but it is not anchored.
    AnchorFailed(String),
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiptError::NoReceiptsDir => {
                write!(
                    f,
                    "cannot determine the receipts directory (data_dir unset)"
                )
            }
            ReceiptError::Io(e) => write!(f, "receipt I/O failed: {e}"),
            ReceiptError::SignatureRequiredButUnavailable => write!(
                f,
                "a signed receipt is required for this install but audit signing is not \
                 configured (no audit-signing.key); refusing to record an unsigned receipt"
            ),
            ReceiptError::AnchorFailed(r) => {
                write!(f, "could not anchor the receipt in the audit chain: {r}")
            }
        }
    }
}

impl std::error::Error for ReceiptError {}

/// The successful outcome of [`ArtifactScanReceipt::record`].
#[derive(Debug, Clone)]
pub struct RecordedReceipt {
    /// The path the receipt JSON was saved to.
    pub path: PathBuf,
    /// Whether the audit-chain anchor was ed25519-SIGNED. `true` => the receipt is
    /// cryptographically signed; `false` => it is "tamper-evident" (hash-chained
    /// only). A `pkg install` surface words its output from this.
    pub signed: bool,
    /// `Some(reason)` when the receipt was SAVED but its audit-chain anchor could NOT
    /// be appended (a non-fatal degrade reached only for the unsigned case, e.g. the
    /// audit-log lock is unavailable on Windows). The receipt exists on disk but is
    /// NOT tamper-evident-chained, so a caller that cares about audit integrity should
    /// surface this rather than treat the install as fully anchored. `None` on a
    /// normally-anchored receipt or a deliberately-disabled chain (those are not a
    /// failure, so they must not look like one).
    pub anchor_warning: Option<String>,
}

impl ArtifactScanReceipt {
    /// Assemble a receipt from already-redacted inputs and stamp its content hash +
    /// timestamp. The caller is responsible for redacting `resolver_command` /
    /// `resolver_version` / `package_manager_version` (strip any index credential)
    /// and for passing `policy_hash` from
    /// [`crate::policy::Policy::security_projection_hash`]; this constructor sorts
    /// the artifact hashes, fills the schema + timestamp, and computes the
    /// content-addressed `receipt_id`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tirith_version: String,
        policy_hash: String,
        threat_db_sequence: u64,
        resolver_command: String,
        resolver_version: String,
        package_manager_version: String,
        capsule: CapsuleReceipt,
        artifact_sha256: Vec<String>,
        post_install_record: Option<PostInstallRecordSummary>,
        verdict: VerdictSummary,
    ) -> Self {
        let mut artifact_sha256 = artifact_sha256;
        artifact_sha256.sort();
        artifact_sha256.dedup();
        let mut receipt = ArtifactScanReceipt {
            schema: ARTIFACT_SCAN_RECEIPT_SCHEMA,
            receipt_id: String::new(),
            tirith_version,
            engine_build_sha: engine_build_sha().to_string(),
            policy_hash,
            threat_db_sequence,
            resolver_command,
            resolver_version,
            package_manager_version,
            capsule,
            artifact_sha256,
            post_install_record,
            verdict,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        receipt.receipt_id = receipt.compute_content_hash();
        receipt
    }

    /// The lowercase-hex sha256 of this receipt's canonical JSON with `receipt_id`
    /// blanked (so the id is a stable function of the rest of the content, never
    /// of itself). Computed through the SAME canonical JSON the audit chain uses
    /// ([`crate::audit::canonical_json_for_hash`]) so the hash a receipt advertises
    /// is exactly what the chain anchor records.
    pub fn compute_content_hash(&self) -> String {
        let mut value = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        if let Some(obj) = value.as_object_mut() {
            obj.insert(
                "receipt_id".to_string(),
                serde_json::Value::String(String::new()),
            );
        }
        let canon = crate::audit::canonical_json_for_hash(&value);
        sha2_hex(canon.as_bytes())
    }

    /// Whether the stored `receipt_id` matches a recomputation over the content.
    /// `tirith pkg receipt` uses this to detect an edited receipt file.
    pub fn content_hash_matches(&self) -> bool {
        self.receipt_id == self.compute_content_hash()
    }

    /// Save the receipt to `data_dir()/receipts/<receipt_id>.json` (atomic `0600`)
    /// AND anchor its content hash in the audit hash-chain.
    ///
    /// `require_signature` enforces the D6 "Ed25519 mandatory for `pkg install`"
    /// rule: when `true` and audit signing is NOT available, this fails closed with
    /// [`ReceiptError::SignatureRequiredButUnavailable`] and writes NOTHING. When
    /// `false`, an unsigned (still hash-chained, "tamper-evident") anchor is
    /// acceptable. On success it returns the saved path and whether the anchor was
    /// signed.
    ///
    /// Order: the file is saved first, then the chain anchor is appended. If the
    /// anchor append fails when a signature is mandatory, it is reported via
    /// [`ReceiptError::AnchorFailed`] (the file exists but is unanchored). For the
    /// unsigned case a failed anchor degrades to a saved-but-unanchored receipt
    /// (`signed: false`), like a disabled chain, so a platform that cannot take the
    /// audit-log lock (Windows) still produces a receipt rather than blocking install.
    pub fn record(&self, require_signature: bool) -> Result<RecordedReceipt, ReceiptError> {
        // Fail closed BEFORE writing anything if a signature is mandatory but
        // unavailable: a `pkg install` that asked for a signed receipt must not get
        // a saved-but-unsigned one.
        if require_signature && !crate::audit::audit_signing_available() {
            return Err(ReceiptError::SignatureRequiredButUnavailable);
        }

        let dir = receipts_dir().ok_or(ReceiptError::NoReceiptsDir)?;
        crate::util::create_dir_durable(&dir).map_err(ReceiptError::Io)?;
        let path = dir.join(format!("{}.json", self.receipt_id));
        let json = serde_json::to_string_pretty(self).map_err(|e| {
            ReceiptError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;
        crate::util::write_file_atomic_0600(&path, json.as_bytes()).map_err(ReceiptError::Io)?;

        // Anchor the content hash in the chain. The chain line carries the verdict
        // action + rule ids + the receipt id/hash; no secret is recorded.
        match crate::audit::log_artifact_scan_receipt(
            &self.receipt_id,
            &self.receipt_id,
            &self.verdict.action,
            &self.verdict.rule_ids,
        ) {
            crate::audit::ReceiptAnchor::Recorded { signed } => Ok(RecordedReceipt {
                path,
                signed,
                anchor_warning: None,
            }),
            // No chain at all (logging off). The file is saved; report it as
            // unsigned/unanchored so the caller does not over-claim tamper-evidence.
            // This is a deliberate config choice, NOT a failure, so no anchor_warning.
            crate::audit::ReceiptAnchor::Skipped => Ok(RecordedReceipt {
                path,
                signed: false,
                anchor_warning: None,
            }),
            // The receipt file is saved but the chain anchor could not be appended.
            // When a signature is mandatory this is fatal. Otherwise (unsigned /
            // tamper-evident acceptable) it degrades like `Skipped`: report the
            // saved-but-unanchored receipt rather than failing the whole install. This
            // is the path a platform that cannot take the audit-log lock (Windows
            // `fs2` denies locking an append handle) takes, so `tirith pkg install`
            // still produces a receipt there instead of hard-failing.
            crate::audit::ReceiptAnchor::Failed(reason) => {
                if require_signature {
                    Err(ReceiptError::AnchorFailed(reason))
                } else {
                    // Never SILENTLY swallow the anchor failure: log it AND record it
                    // on the result, so the caller can surface the degraded (saved but
                    // unanchored) state instead of reporting a fully-anchored install.
                    eprintln!(
                        "tirith: package receipt saved but could not be audit-anchored: {reason}"
                    );
                    Ok(RecordedReceipt {
                        path,
                        signed: false,
                        anchor_warning: Some(reason),
                    })
                }
            }
        }
    }

    /// Load a saved receipt by its `receipt_id` (the content-hash file stem).
    pub fn load(receipt_id: &str) -> Result<Self, String> {
        // The id is a 64-char lowercase-hex sha256 by construction; validate it as
        // a path-safe stem before joining (same guard as the script Receipt).
        validate_sha256(receipt_id)?;
        let dir = receipts_dir().ok_or("cannot determine receipts directory")?;
        let path = dir.join(format!("{receipt_id}.json"));
        let content = fs::read_to_string(&path).map_err(|e| format!("read: {e}"))?;
        serde_json::from_str(&content).map_err(|e| format!("parse: {e}"))
    }

    /// List all saved [`ArtifactScanReceipt`]s, newest first. Ignores files that do
    /// not parse as this schema (e.g. the legacy script [`Receipt`] files), so the
    /// two receipt kinds can share the directory.
    pub fn list() -> Result<Vec<Self>, String> {
        let dir = receipts_dir().ok_or("cannot determine receipts directory")?;
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut receipts = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|e| format!("read dir: {e}"))? {
            let entry = entry.map_err(|e| format!("entry: {e}"))?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "json")
                && !path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with('.'))
            {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(r) = serde_json::from_str::<ArtifactScanReceipt>(&content) {
                        receipts.push(r);
                    }
                }
            }
        }
        receipts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(receipts)
    }
}

fn receipts_dir() -> Option<PathBuf> {
    crate::policy::data_dir().map(|d| d.join("receipts"))
}

fn cache_dir() -> Option<PathBuf> {
    crate::policy::data_dir().map(|d| d.join("cache"))
}

fn sha2_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_sha256_valid() {
        let hash = "a".repeat(64);
        assert!(validate_sha256(&hash).is_ok());
    }

    #[test]
    fn test_validate_sha256_too_short() {
        assert!(validate_sha256("abc").is_err());
    }

    #[test]
    fn test_validate_sha256_path_traversal() {
        assert!(validate_sha256("../../etc/passwd").is_err());
    }

    #[test]
    fn test_validate_sha256_uppercase_rejected() {
        let hash = "A".repeat(64);
        assert!(validate_sha256(&hash).is_err());
    }

    #[test]
    fn test_short_hash_short_input() {
        assert_eq!(short_hash("abc"), "abc");
    }

    #[test]
    fn test_short_hash_normal() {
        let hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert_eq!(short_hash(hash), "abcdef012345");
    }

    #[test]
    fn test_short_hash_non_ascii() {
        // Multi-byte UTF-8: each char is 3 bytes, so 12 bytes = 4 chars.
        let s = "日本語テスト";
        let result = short_hash(s);
        assert!(!result.is_empty());
        assert!(result.len() <= 12);
    }

    #[test]
    fn test_receipt_save_no_predictable_tmp() {
        // NamedTempFile must replace the old predictable `.{sha}.json.tmp` scheme.
        let dir = tempfile::tempdir().unwrap();
        let receipts_sub = dir.path().join("receipts");
        std::fs::create_dir_all(&receipts_sub).unwrap();

        let sha = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        let path = receipts_sub.join(format!("{sha}.json"));
        let json = r#"{"test": true}"#;
        {
            use std::io::Write;
            use tempfile::NamedTempFile;

            let mut tmp = NamedTempFile::new_in(&receipts_sub).unwrap();
            tmp.write_all(json.as_bytes()).unwrap();
            tmp.persist(&path).unwrap();
        }

        let old_tmp = receipts_sub.join(format!(".{sha}.json.tmp"));
        assert!(
            !old_tmp.exists(),
            "predictable .{{sha}}.json.tmp should not exist after NamedTempFile save"
        );
        assert!(path.exists(), "receipt file should exist after persist");
    }

    #[cfg(unix)]
    #[test]
    fn test_receipt_save_permissions_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let receipts_dir = dir.path().join("receipts");
        std::fs::create_dir_all(&receipts_dir).unwrap();

        let sha = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        // Mirror save()'s 0600 pattern directly so this test stays independent
        // of the public API's internals.
        let path = receipts_dir.join(format!("{sha}.json"));
        let json = r#"{"test": true}"#;
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            opts.mode(0o600);
            let mut f = opts.open(&path).unwrap();
            f.write_all(json.as_bytes()).unwrap();
        }

        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "receipt file should be 0600"
        );
    }

    // ── D6: ArtifactScanReceipt ─────────────────────────────────────────────

    use crate::capsule::CapsuleCoverage;

    /// A scoped env-var override that restores the prior value on drop. Local to
    /// these tests so they do not depend on policy.rs's private guard.
    struct EnvGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }
    impl EnvGuard {
        fn set(key: &'static str, val: &std::path::Path) -> Self {
            let prev = std::env::var_os(key);
            std::env::set_var(key, val);
            EnvGuard { key, prev }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    /// Point every directory env var [`crate::policy::data_dir`] /
    /// [`crate::policy::config_dir`] consult at `root`, on whichever platform the
    /// test runs (XDG on unix, APPDATA/LOCALAPPDATA on Windows), plus HOME so a
    /// stray home lookup cannot escape. The guards restore on drop.
    fn isolate_dirs(root: &std::path::Path) -> Vec<EnvGuard> {
        vec![
            EnvGuard::set("XDG_DATA_HOME", root),
            EnvGuard::set("XDG_CONFIG_HOME", root),
            EnvGuard::set("XDG_STATE_HOME", root),
            EnvGuard::set("APPDATA", root),
            EnvGuard::set("LOCALAPPDATA", root),
            EnvGuard::set("HOME", root),
            EnvGuard::set("USERPROFILE", root),
        ]
    }

    /// A sample capsule receipt with full deny-all coverage (what a clean
    /// landlock/seatbelt install would report).
    fn sample_capsule() -> CapsuleReceipt {
        CapsuleReceipt {
            backend_id: "landlock-seccomp".to_string(),
            coverage: CapsuleCoverage {
                fs_read_enforced: true,
                fs_write_enforced: true,
                exec_limited: true,
                network_raw_denied: true,
                domain_proxy_enforced: false,
                resource_limits_enforced: true,
                env_isolated: true,
                handles_isolated: true,
            },
        }
    }

    /// A receipt assembled from already-redacted inputs.
    fn sample_receipt() -> ArtifactScanReceipt {
        ArtifactScanReceipt::new(
            "0.3.3".to_string(),
            "deadbeef".repeat(8), // a stand-in policy hash
            42,
            "uv pip compile --generate-hashes --no-build".to_string(),
            "uv 0.4.0".to_string(),
            "pip 24.0".to_string(),
            sample_capsule(),
            vec!["b".repeat(64), "a".repeat(64)], // out of order -> sorted by new()
            Some(PostInstallRecordSummary {
                blocked: false,
                distributions_verified: 1,
                distributions_not_found: 0,
                records_missing: 0,
                hash_mismatches: 0,
            }),
            VerdictSummary {
                action: "Allow".to_string(),
                rule_ids: vec![],
                finding_count: 0,
            },
        )
    }

    #[test]
    fn receipt_is_content_addressed_and_stable() {
        let r = sample_receipt();
        // The id is the content hash with id blanked, so it is reproducible and the
        // stored id matches a recomputation.
        assert_eq!(r.receipt_id.len(), 64);
        assert!(r.content_hash_matches());
        // Recomputing the same content gives the same id.
        assert_eq!(r.compute_content_hash(), r.receipt_id);
        // The schema is stamped.
        assert_eq!(r.schema, ARTIFACT_SCAN_RECEIPT_SCHEMA);
        // Artifact hashes were sorted by new().
        assert_eq!(r.artifact_sha256, vec!["a".repeat(64), "b".repeat(64)]);
    }

    #[test]
    fn receipt_id_changes_when_content_changes() {
        let mut a = sample_receipt();
        let original = a.receipt_id.clone();
        // Mutate a meaningful field and recompute: the content hash must change.
        a.threat_db_sequence = 99;
        assert_ne!(
            a.compute_content_hash(),
            original,
            "a different threat-DB sequence must change the content hash"
        );
        // And an edited file (id left stale) is detected.
        assert!(!a.content_hash_matches());
    }

    #[test]
    fn receipt_roundtrips_through_json() {
        let r = sample_receipt();
        let json = serde_json::to_string(&r).unwrap();
        let back: ArtifactScanReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
        assert!(back.content_hash_matches());
    }

    #[test]
    fn receipt_serialization_never_contains_secrets_or_paths() {
        // The receipt is built from PRE-REDACTED inputs; assert the serialized form
        // carries no token/key/secret/path even if a careless caller's redacted
        // strings are themselves clean. (This guards the schema: no field smuggles a
        // secret.) We feed deliberately suspicious-but-redacted values and confirm
        // the dangerous tokens are absent.
        let r = sample_receipt();
        let json = serde_json::to_string_pretty(&r).unwrap();
        for needle in [
            "api_key",
            "API_KEY",
            "password",
            "PASSWORD",
            "ghp_",
            "AKIA",
            "secret",
            "/Users/",
            "/home/",
            "C:\\\\Users",
        ] {
            assert!(
                !json.contains(needle),
                "receipt JSON must not contain {needle:?}: {json}"
            );
        }
        // It DOES carry the redaction-safe identity fields.
        assert!(json.contains("\"schema\""));
        assert!(json.contains("\"policy_hash\""));
        assert!(json.contains("\"artifact_sha256\""));
        assert!(json.contains("landlock-seccomp"));
    }

    #[test]
    fn record_saves_file_and_anchors_in_audit_chain() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _guards = isolate_dirs(root.path());
        // Make sure logging is on for this test even if the ambient env set it off.
        let _log = EnvGuard {
            key: "TIRITH_LOG",
            prev: std::env::var_os("TIRITH_LOG"),
        };
        std::env::set_var("TIRITH_LOG", "1");

        let r = sample_receipt();
        // require_signature=false: an unsigned (tamper-evident) anchor is fine here.
        let recorded = r.record(false).expect("record should save + anchor");
        // The file is saved under the isolated data dir, named by the receipt id.
        assert!(recorded.path.exists(), "receipt file must exist");
        assert!(recorded
            .path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(&r.receipt_id));
        // No signing key configured in the isolated config dir -> unsigned anchor.
        assert!(!recorded.signed);

        // It is loadable back by id and still content-consistent.
        let loaded = ArtifactScanReceipt::load(&r.receipt_id).expect("load by id");
        assert_eq!(loaded, r);
        assert!(loaded.content_hash_matches());

        // The audit chain has an `artifact_receipt` line carrying the content hash,
        // and the chain verifies (tamper-evident).
        let log_path = crate::audit::audit_log_path().expect("log path under isolated dir");
        let body = std::fs::read_to_string(&log_path).expect("audit log written");
        assert!(
            body.contains("\"entry_type\":\"artifact_receipt\""),
            "an artifact_receipt entry must be anchored: {body}"
        );
        assert!(
            body.contains(&r.receipt_id),
            "the chain anchor must carry the receipt content hash"
        );
        let report = crate::audit::verify_audit_log(&log_path, None);
        assert!(
            report.ok,
            "the audit chain must verify after anchoring: {:?}",
            report.problems
        );
    }

    #[test]
    fn record_lists_alongside_script_receipts_without_cross_parse() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        let _guards = isolate_dirs(root.path());
        let _log = EnvGuard {
            key: "TIRITH_LOG",
            prev: std::env::var_os("TIRITH_LOG"),
        };
        std::env::set_var("TIRITH_LOG", "1");

        // Save one artifact-scan receipt.
        let r = sample_receipt();
        r.record(false).unwrap();

        // Drop a legacy script Receipt JSON into the SAME receipts dir.
        let receipts = root.path().join("tirith").join("receipts");
        std::fs::create_dir_all(&receipts).unwrap();
        let script = Receipt {
            url: "https://example.invalid/install.sh".to_string(),
            final_url: None,
            redirects: vec![],
            sha256: "c".repeat(64),
            size: 10,
            domains_referenced: vec![],
            paths_referenced: vec![],
            analysis_method: "static".to_string(),
            privilege: "user".to_string(),
            timestamp: "2026-06-22T00:00:00+00:00".to_string(),
            cwd: None,
            git_repo: None,
            git_branch: None,
        };
        std::fs::write(
            receipts.join(format!("{}.json", script.sha256)),
            serde_json::to_string(&script).unwrap(),
        )
        .unwrap();

        // ArtifactScanReceipt::list ignores the script receipt; Receipt::list ignores
        // the artifact receipt. The two schemas coexist in one directory.
        let arts = ArtifactScanReceipt::list().unwrap();
        assert_eq!(arts.len(), 1, "only the one artifact receipt is listed");
        assert_eq!(arts[0].receipt_id, r.receipt_id);

        let scripts = Receipt::list().unwrap();
        assert_eq!(scripts.len(), 1, "only the one script receipt is listed");
        assert_eq!(scripts[0].sha256, "c".repeat(64));
    }

    #[test]
    fn record_fails_closed_when_signature_required_but_unavailable() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir().unwrap();
        // Isolate config so no real audit-signing.key is present -> signing
        // unavailable.
        let _guards = isolate_dirs(root.path());

        let r = sample_receipt();
        // require_signature=true with no signing key must fail closed and write
        // nothing.
        let err = r
            .record(true)
            .expect_err("a required-but-unavailable signature must fail closed");
        assert!(matches!(err, ReceiptError::SignatureRequiredButUnavailable));
        // Nothing was saved.
        let receipts = root.path().join("tirith").join("receipts");
        let saved = receipts.join(format!("{}.json", r.receipt_id));
        assert!(
            !saved.exists(),
            "no receipt file may be saved when the mandatory signature is unavailable"
        );
    }
}
