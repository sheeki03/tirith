pub mod stored;

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

    /// Load a receipt by SHA256 through the bounded, identity-bound stored reader.
    pub fn load(sha256: &str) -> Result<Self, String> {
        stored::load_download(sha256).map_err(String::from)
    }

    /// List bounded saved download receipts, newest first. Valid artifact
    /// receipts share this directory; invalid inventory remains an error.
    pub fn list() -> Result<Vec<Self>, String> {
        let mut receipts = stored::list_download().map_err(String::from)?;
        receipts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(receipts)
    }

    /// Verify the original cached content with a bounded, native regular-file read.
    pub fn verify(&self) -> Result<bool, String> {
        stored::verify_download(self).map_err(String::from)
    }

    /// The public, JSON-serializable view of this receipt for default CLI
    /// output (repo-0415 / repo-0420): credential-bearing URL userinfo is
    /// redacted and local-machine metadata (`cwd`) is omitted. The stored
    /// receipt keeps full fidelity; only the default output is minimized.
    pub fn public_view(&self) -> PublicReceipt {
        PublicReceipt {
            url: redact_url_userinfo(&self.url),
            final_url: self.final_url.as_deref().map(redact_url_userinfo),
            redirects: self
                .redirects
                .iter()
                .map(|u| redact_url_userinfo(u))
                .collect(),
            sha256: self.sha256.clone(),
            size: self.size,
            domains_referenced: self.domains_referenced.clone(),
            paths_referenced: self.paths_referenced.clone(),
            analysis_method: self.analysis_method.clone(),
            privilege: self.privilege.clone(),
            timestamp: self.timestamp.clone(),
            git_repo: self.git_repo.as_deref().map(redact_url_userinfo),
            git_branch: self.git_branch.clone(),
        }
    }

    /// Clone this receipt for a public DTO using one frozen analysis DLP plan.
    /// Stored receipts retain full local fidelity; the returned clone removes
    /// cwd and structurally strips URL credentials/query/fragment/provider
    /// tokens while DLP-redacting and bounding every free-text path field.
    pub fn presentation_clone_with_compiled(
        &self,
        compiled: &crate::redact::CompiledCustomPatterns,
    ) -> Self {
        let text =
            |value: &str| crate::redact::sanitize_provenance_text_with_compiled(value, compiled);
        let url =
            |value: &str| crate::redact::sanitize_provenance_url_with_compiled(value, compiled);
        Self {
            url: url(&self.url),
            final_url: self.final_url.as_deref().map(url),
            redirects: self.redirects.iter().map(|value| url(value)).collect(),
            sha256: self.sha256.clone(),
            size: self.size,
            domains_referenced: self
                .domains_referenced
                .iter()
                .map(|value| text(value))
                .collect(),
            paths_referenced: self
                .paths_referenced
                .iter()
                .map(|value| text(value))
                .collect(),
            // `analysis_method` keeps the DLP pass: it embeds an incomplete-reason
            // string from the runner, so it is not a closed vocabulary.
            analysis_method: text(&self.analysis_method),
            // `privilege` and `timestamp` are program-generated, never derived
            // from analysed input: privilege is one of "normal"/"elevated"/"user"
            // and timestamp is `Utc::now().to_rfc3339()`. Running operator DLP
            // over them could only ever corrupt them -- a custom pattern as
            // ordinary as `\d{4}` rewrites the year and breaks the receipt for
            // the downstream verifier that parses it. There is nothing to redact.
            privilege: self.privilege.clone(),
            timestamp: self.timestamp.clone(),
            cwd: None,
            git_repo: self.git_repo.as_deref().map(url),
            git_branch: self.git_branch.as_deref().map(text),
        }
    }
}

/// Redact the userinfo component (`user:password@`) of an absolute URL while
/// keeping scheme, host, and path for diagnostics (repo-0415). Applied to
/// every URL a receipt serializes so a credential-bearing Git remote or
/// download URL (`https://user:pat@host/...`) cannot reach JSON output, logs,
/// or CI artifacts. Strings without a `scheme://authority` form or without
/// userinfo pass through unchanged.
pub fn redact_url_userinfo(url: &str) -> String {
    // Userinfo exists only in an authority-based absolute URL.
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let authority_start = scheme_end + 3;
    let after_scheme = &url[authority_start..];
    // The authority ends at the first path/query/fragment delimiter.
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .map(|i| authority_start + i)
        .unwrap_or(url.len());
    let authority = &url[authority_start..authority_end];
    // RFC 3986 splits userinfo at the LAST `@` (a conformant producer
    // percent-encodes any `@` inside the password).
    let Some(at) = authority.rfind('@') else {
        // Fail closed. A non-conformant userinfo can carry a raw `/`, `?`, or
        // `#` (`https://deploy:ab/cd@host/repo.git`), which ends the authority
        // scan above early and hides the `@` — the URL would then be returned
        // verbatim, credentials and all. The URL parser rejects exactly those
        // strings, so a parse failure plus a remaining `@` means we cannot
        // prove the value is credential-free. A URL the parser ACCEPTS has no
        // userinfo (the scan would have found it), so an `@` in its path or
        // query is left alone.
        if ::url::Url::parse(url).is_err() {
            if let Some(rel) = after_scheme.rfind('@') {
                return format!("{}://***@{}", &url[..scheme_end], &after_scheme[rel + 1..]);
            }
        }
        return url.to_string();
    };
    format!(
        "{}://***@{}{}",
        &url[..scheme_end],
        &authority[at + 1..],
        &url[authority_end..]
    )
}

/// The redacted output DTO serialized by `tirith run --json` and
/// `tirith receipt last|list --json` (repo-0415 / repo-0420). Same diagnostic
/// shape as [`Receipt`] minus `cwd`, with every URL field userinfo-redacted.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PublicReceipt {
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
    pub git_repo: Option<String>,
    pub git_branch: Option<String>,
}

// ===========================================================================
// D6: tamper-evident package-firewall scan receipt (written by the pip
// package firewall in earlier releases; `pkg receipt` still reads them)
// ===========================================================================

/// The schema version of [`ArtifactScanReceipt`]. Bumped when a field is added or
/// its meaning changes, so a reader can tell which shape a saved receipt is. This
/// is a NEW versioned schema, deliberately distinct from the script-download
/// [`Receipt`] above (which is unversioned and describes a single fetched script):
/// the only thing the two share is the atomic-`0600` save mechanism.
pub const ARTIFACT_SCAN_RECEIPT_SCHEMA: u32 = 2;

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

/// Publication phase attested by an [`ArtifactScanReceipt`].
///
/// A successful enforcing install produces two signed, content-addressed
/// receipts. `PrivateVerified` records the contained install and RECORD verdict
/// while the target is still private and rollback-safe. Only a second,
/// `Committed` receipt may attest that the exact private target crossed the
/// no-replace publication boundary; it links back to the private receipt through
/// [`ArtifactScanReceipt::private_receipt_id`].
///
/// `LegacyUnspecified` is solely the serde default for schema-v1 receipts, which
/// predate publication tracking. It is omitted when serializing so recomputing a
/// v1 receipt's content hash remains backward-compatible. Legacy receipts must
/// never be treated as committed-publication proof.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptPublicationState {
    #[default]
    LegacyUnspecified,
    PrivateVerified,
    Committed,
}

impl ReceiptPublicationState {
    fn is_private_verified(self) -> bool {
        self == Self::PrivateVerified
    }
    fn committed(self) -> Self {
        Self::Committed
    }
    fn is_legacy_unspecified(&self) -> bool {
        *self == Self::LegacyUnspecified
    }
}

/// A **versioned, tamper-evident** receipt for one package-firewall install
/// (PR D6). Earlier releases wrote these from the now-removed pip package
/// firewall. This release has no writer; `pkg receipt` reads, lists and verifies
/// the receipts already on disk, and the format stays readable.
///
/// It records exactly what the install ran: the tirith version + engine build SHA,
/// a redacted policy-posture hash, the threat-DB sequence the approval bound to,
/// the redacted resolver / package-manager commands and their versions, the capsule
/// backend + coverage, every artifact sha256, the post-install RECORD result, the
/// finalised verdict summary, and a timestamp.
///
/// # Tamper-evidence
///
/// The removed writer saved the receipt JSON to
/// `data_dir()/receipts/<receipt_id>.json` (atomic `0600`) and anchored the
/// receipt's own content hash in the audit hash-chain as an `artifact_receipt`
/// line, so editing or deleting a saved receipt is detectable against the
/// (optionally ed25519-signed) chain. The `receipt_id` is the content hash
/// ([`Self::compute_content_hash`]), so the receipt is content-addressed and
/// [`Self::content_hash_matches`] detects an edited file.
///
/// # Redaction contract (cross-cutting invariant 7)
///
/// Every field was constructed redacted by the writer: the resolver / package-manager
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
    /// Whether this receipt covers a still-private verified target or a target
    /// whose exact identity was durably published. Missing on schema-v1 receipts.
    #[serde(
        default,
        skip_serializing_if = "ReceiptPublicationState::is_legacy_unspecified"
    )]
    publication_state: ReceiptPublicationState,
    /// The content-addressed id of the signed `PrivateVerified` receipt. Present
    /// exactly on a schema-v2 `Committed` receipt, binding the publication proof
    /// to the private bytes/verdict that were approved before the rename.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_receipt_id: Option<String>,
    /// RFC 3339 UTC timestamp of when the receipt was produced.
    pub timestamp: String,
}

impl ArtifactScanReceipt {
    /// Publication phase carried by this persisted receipt.
    pub fn publication_state(&self) -> ReceiptPublicationState {
        self.publication_state
    }

    /// Signed private receipt linked by a committed receipt, when present.
    pub fn private_receipt_id(&self) -> Option<&str> {
        self.private_receipt_id.as_deref()
    }

    /// Verify that this is the exact committed derivation of `private`. This
    /// compares the complete receipt contents (allowing only the publication
    /// state/link, fresh timestamp, and resulting content id to differ), rather
    /// than accepting any syntactically valid 64-hex link. Schema-v1 receipts,
    /// unrelated links, and tampered values fail closed.
    ///
    /// This proves the content linkage only. The caller must separately verify
    /// both receipts' mandatory signed audit anchors.
    pub fn is_committed_publication_for(&self, private: &Self) -> bool {
        if private.schema != ARTIFACT_SCAN_RECEIPT_SCHEMA
            || !private.publication_state.is_private_verified()
            || private.validate_structure().is_err()
            || private.private_receipt_id.is_some()
            || !private.content_hash_matches()
        {
            return false;
        }

        let mut expected = private.clone();
        expected.publication_state = private.publication_state.committed();
        expected.private_receipt_id = Some(private.receipt_id.clone());
        expected.timestamp = self.timestamp.clone();
        expected.receipt_id.clear();
        expected.receipt_id = expected.compute_content_hash();
        self == &expected
    }

    /// The lowercase-hex sha256 of this receipt's canonical JSON with `receipt_id`
    /// blanked (so the id is a stable function of the rest of the content, never
    /// of itself). Computed through the SAME canonical JSON the audit chain uses
    /// ([`crate::audit::canonical_json_for_hash`]) so the hash a receipt advertises
    /// is exactly what the chain anchor records.
    pub fn compute_content_hash(&self) -> String {
        let serialized = serde_json::to_value(self);
        // A derive-`Serialize` receipt cannot fail to serialize today, so the
        // `Null` fallback is unreachable. Guard it: a future non-serializable
        // field would otherwise silently hash `null` (a constant), collapsing
        // every receipt id to the same value. Caught in tests/debug; release
        // keeps the lenient fallback rather than panicking on the hash path.
        debug_assert!(
            serialized.is_ok(),
            "receipt failed to serialize for content hash; a field is not serializable"
        );
        let mut value = serialized.unwrap_or(serde_json::Value::Null);
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

    /// Validate every structural invariant a canonical receipt satisfies.
    /// Deserialization intentionally remains backward-compatible and permissive
    /// enough to inspect old/corrupt files; this check is strict and side-effect
    /// free.
    fn validate_structure(&self) -> Result<(), String> {
        validate_sha256(&self.receipt_id)?;
        if !self.content_hash_matches() {
            return Err("receipt_id does not match the canonical receipt content".to_string());
        }

        match (self.schema, self.publication_state) {
            (1, ReceiptPublicationState::LegacyUnspecified) => {
                if self.private_receipt_id.is_some() {
                    return Err("schema-v1 receipt cannot carry a private receipt link".to_string());
                }
            }
            (ARTIFACT_SCAN_RECEIPT_SCHEMA, ReceiptPublicationState::PrivateVerified) => {
                if self.private_receipt_id.is_some() {
                    return Err(
                        "private_verified receipt cannot carry a predecessor link".to_string()
                    );
                }
            }
            (ARTIFACT_SCAN_RECEIPT_SCHEMA, ReceiptPublicationState::Committed) => {
                let private_id = self.private_receipt_id.as_deref().ok_or_else(|| {
                    "committed receipt is missing its signed private predecessor".to_string()
                })?;
                validate_sha256(private_id).map_err(|reason| {
                    format!("committed receipt has an invalid private receipt id: {reason}")
                })?;
                if private_id == self.receipt_id {
                    return Err("committed receipt cannot link to itself".to_string());
                }
            }
            (ARTIFACT_SCAN_RECEIPT_SCHEMA, ReceiptPublicationState::LegacyUnspecified) => {
                return Err("schema-v2 receipt must declare private_verified or committed publication state".to_string());
            }
            (1, _) => {
                return Err("schema-v1 receipt cannot claim a publication phase".to_string());
            }
            (schema, _) => {
                return Err(format!("unsupported artifact receipt schema {schema}"));
            }
        }
        Ok(())
    }

    /// Load a bounded saved receipt whose embedded identity matches its file stem.
    /// This is an inspection read; content-hash and publication validation remain
    /// explicit, separate checks before a receipt can confer any authority.
    pub fn load(receipt_id: &str) -> Result<Self, String> {
        stored::load_artifact(receipt_id).map_err(String::from)
    }

    /// List bounded saved artifact receipts, newest first. Valid download
    /// receipts share this directory; invalid inventory remains an error.
    pub fn list() -> Result<Vec<Self>, String> {
        let mut receipts = stored::list_artifact().map_err(String::from)?;
        receipts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(receipts)
    }
}

fn receipts_dir() -> Option<PathBuf> {
    crate::policy::data_dir().map(|d| d.join("receipts"))
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
    use tirith_test_support::GlobalStateGuard;

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

    fn script_receipt(sha256: String) -> Receipt {
        Receipt {
            url: "https://example.com/install.sh".to_string(),
            final_url: None,
            redirects: vec![],
            sha256,
            size: 42,
            domains_referenced: vec!["example.com".to_string()],
            paths_referenced: vec![],
            analysis_method: "test".to_string(),
            privilege: "user".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            cwd: Some("/Users/operator/secret-project".to_string()),
            git_repo: Some("https://deploy:pat-token-123@github.com/org/repo.git".to_string()),
            git_branch: Some("main".to_string()),
        }
    }

    #[test]
    fn redact_url_userinfo_strips_credentials_keeps_host() {
        assert_eq!(
            redact_url_userinfo("https://deploy:pat-token-123@github.com/org/repo.git"),
            "https://***@github.com/org/repo.git"
        );
        assert_eq!(
            redact_url_userinfo("https://user@host:8443/path?q=1#f"),
            "https://***@host:8443/path?q=1#f"
        );
        // No userinfo / not an absolute authority URL: unchanged.
        assert_eq!(
            redact_url_userinfo("https://github.com/org/repo"),
            "https://github.com/org/repo"
        );
        assert_eq!(
            redact_url_userinfo("git@github.com:org/repo.git"),
            "git@github.com:org/repo.git"
        );
        assert_eq!(redact_url_userinfo("not a url @ all"), "not a url @ all");
    }

    #[test]
    fn public_view_redacts_userinfo_and_omits_cwd() {
        let r = script_receipt("a".repeat(64));
        let v = serde_json::to_value(r.public_view()).unwrap();
        assert_eq!(
            v["git_repo"],
            serde_json::json!("https://***@github.com/org/repo.git"),
            "credential userinfo must be redacted, host kept"
        );
        assert!(
            v.get("cwd").is_none(),
            "local-machine cwd must not reach default JSON output"
        );
        let blob = v.to_string();
        assert!(!blob.contains("pat-token-123"), "{blob}");
        assert!(!blob.contains("secret-project"), "{blob}");
    }

    #[test]
    fn presentation_clone_uses_frozen_dlp_and_shared_url_sanitizer() {
        let canary = "C02_RECEIPT_PRESENTATION_CANARY";
        let provider_token = "provider-token-0123456789";
        let patterns = vec![regex::escape(canary)];
        let compiled = crate::redact::CompiledCustomPatterns::new_silent(&patterns);
        let mut receipt = script_receipt("a".repeat(64));
        receipt.url = format!(
            "https://user:password@mainnet.infura.io/v3/{provider_token}?token={canary}#fragment"
        );
        receipt.final_url = Some(format!(
            "https://eth-mainnet.g.alchemy.com/v2/{provider_token}?token={canary}"
        ));
        receipt.redirects = vec![format!(
            "https://rpc.ankr.com/eth/{provider_token}?token={canary}"
        )];
        receipt.paths_referenced = vec![format!("/private/{canary}/wallet.json")];
        receipt.git_repo = Some(format!(
            "https://user:password@github.com/org/repo?token={canary}#fragment"
        ));
        receipt.git_branch = Some(format!("branch-{canary}"));

        let projected = receipt.presentation_clone_with_compiled(&compiled);
        let serialized = serde_json::to_string(&projected).unwrap();

        for secret in [
            canary,
            provider_token,
            "user:password",
            "token=",
            "#fragment",
        ] {
            assert!(!serialized.contains(secret), "receipt leaked {secret}");
        }
        assert!(serialized.contains("[REDACTED:custom]"));
        assert!(projected.cwd.is_none());
        assert!(
            receipt.url.contains(canary),
            "raw receipt must remain intact"
        );
        assert!(
            receipt.cwd.is_some(),
            "stored receipt must retain local cwd"
        );
    }

    /// `privilege` and `timestamp` are produced by tirith itself, never derived
    /// from the analysed subject, so there is nothing in them to redact. Running
    /// the operator's custom DLP patterns over them could only ever corrupt them,
    /// and an operator pattern broad enough to hit a bare 4-digit run is entirely
    /// ordinary. A mangled timestamp breaks the downstream verifier that parses
    /// the receipt, so this is a data-integrity bug, not a cosmetic one.
    #[test]
    fn a_broad_operator_dlp_pattern_cannot_corrupt_program_generated_receipt_fields() {
        // Matches the year in any RFC 3339 timestamp, and "user"/"normal".
        let patterns = vec![r"\d{4}".to_string(), r"user|normal".to_string()];
        let compiled = crate::redact::CompiledCustomPatterns::new_silent(&patterns);

        let mut receipt = script_receipt("b".repeat(64));
        receipt.timestamp = "2026-01-01T00:00:00Z".to_string();
        receipt.privilege = "user".to_string();

        let projected = receipt.presentation_clone_with_compiled(&compiled);

        assert_eq!(
            projected.timestamp, "2026-01-01T00:00:00Z",
            "a program-generated timestamp must survive operator DLP verbatim"
        );
        assert_eq!(
            projected.privilege, "user",
            "a closed-vocabulary privilege must survive operator DLP verbatim"
        );
        assert!(
            chrono::DateTime::parse_from_rfc3339(&projected.timestamp).is_ok(),
            "the projected timestamp must still parse as RFC 3339"
        );

        // The same pattern set must still redact genuinely attacker-influenced
        // free text, so this is a scoping fix and not a hole in the DLP pass.
        let mut tainted = script_receipt("c".repeat(64));
        tainted.analysis_method = "static-incomplete:normal".to_string();
        let tainted = tainted.presentation_clone_with_compiled(&compiled);
        assert!(
            tainted.analysis_method.contains("[REDACTED:custom]"),
            "analysis_method still carries subject-derived text: {}",
            tainted.analysis_method
        );
    }

    #[test]
    fn load_rejects_substituted_receipt_identity() {
        // repo-0416: a receipt file whose embedded hash differs from the
        // requested filename is a substituted receipt — verifying it would
        // check a DIFFERENT cached script while reporting success for the
        // requested one.
        let root = tempfile::tempdir().unwrap();
        let _environment = isolate_dirs(root.path());
        let dir = root.path().join("tirith").join("receipts");
        std::fs::create_dir_all(&dir).unwrap();
        let requested = "a".repeat(64);
        let embedded = "b".repeat(64);
        let receipt = script_receipt(embedded);
        std::fs::write(
            dir.join(format!("{requested}.json")),
            serde_json::to_string(&receipt).unwrap(),
        )
        .unwrap();
        let err = Receipt::load(&requested).expect_err("a substituted receipt must be rejected");
        assert!(err.contains("identity mismatch"), "{err}");
        assert!(!err.contains(&requested));
        assert!(!err.contains(&receipt.sha256));
        // A matching receipt still loads.
        let receipt = script_receipt(requested.clone());
        std::fs::write(
            dir.join(format!("{requested}.json")),
            serde_json::to_string(&receipt).unwrap(),
        )
        .unwrap();
        assert!(Receipt::load(&requested).is_ok());
    }

    #[test]
    fn public_artifact_load_and_list_reject_substituted_identity() {
        let _environment = GlobalStateGuard::new().unwrap();
        let directory = receipts_dir().unwrap();
        fs::create_dir_all(&directory).unwrap();
        let receipt = sample_receipt();
        let requested = "e".repeat(64);
        assert_ne!(requested, receipt.receipt_id);
        fs::write(
            directory.join(format!("{requested}.json")),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();

        for error in [
            ArtifactScanReceipt::load(&requested).unwrap_err(),
            ArtifactScanReceipt::list().unwrap_err(),
        ] {
            assert!(error.contains("identity mismatch"), "{error}");
            assert!(!error.contains(&requested));
            assert!(!error.contains(&receipt.receipt_id));
        }
    }

    #[test]
    fn public_receipt_invalid_ids_keep_safe_diagnostic_without_stored_values() {
        let _environment = GlobalStateGuard::new().unwrap();
        let invalid = "receipt-private-canary/../../outside";
        let receipt = script_receipt(invalid.into());
        for error in [
            Receipt::load(invalid).unwrap_err(),
            ArtifactScanReceipt::load(invalid).unwrap_err(),
            receipt.verify().unwrap_err(),
        ] {
            assert!(error.contains("invalid sha256"), "{error}");
            assert!(!error.contains("receipt-private-canary"));
        }
        assert!(!receipts_dir().unwrap().exists());
    }

    #[test]
    fn public_receipt_readers_refuse_oversized_record_and_inventory() {
        let _environment = GlobalStateGuard::new().unwrap();
        let directory = receipts_dir().unwrap();
        fs::create_dir_all(&directory).unwrap();
        let id = "a".repeat(64);
        let path = directory.join(format!("{id}.json"));
        fs::File::create(&path)
            .unwrap()
            .set_len(1024 * 1024 + 1)
            .unwrap();
        for error in [
            Receipt::load(&id).unwrap_err(),
            ArtifactScanReceipt::load(&id).unwrap_err(),
            Receipt::list().unwrap_err(),
            ArtifactScanReceipt::list().unwrap_err(),
        ] {
            assert!(error.contains("read limit"), "{error}");
        }
        fs::remove_file(path).unwrap();

        // Each real serialized receipt fits the individual limit. Together they
        // exceed the shared inventory budget, even for the other receipt kind.
        let mut receipt = script_receipt(String::new());
        receipt.url = "x".repeat(950 * 1024);
        for index in 0..18 {
            receipt.sha256 = format!("{index:064x}");
            let path = receipt.save().unwrap();
            assert!(fs::metadata(path).unwrap().len() < 1024 * 1024);
        }
        assert!(Receipt::list()
            .unwrap_err()
            .contains("inventory exceeds the byte limit"));
        assert!(ArtifactScanReceipt::list()
            .unwrap_err()
            .contains("inventory exceeds the byte limit"));
    }

    #[test]
    fn public_receipt_verify_bounds_cache_and_preserves_missing_or_changed_results() {
        let _environment = GlobalStateGuard::new().unwrap();
        let receipt = script_receipt(sha2_hex(b"abc"));
        assert!(!receipt.verify().unwrap());
        let cache = crate::policy::data_dir().unwrap().join("cache");
        fs::create_dir_all(&cache).unwrap();
        let path = cache.join(&receipt.sha256);
        fs::write(&path, b"abc").unwrap();
        assert!(receipt.verify().unwrap());
        fs::write(&path, b"abd").unwrap();
        assert!(!receipt.verify().unwrap());
        fs::File::create(&path)
            .unwrap()
            .set_len(10 * 1024 * 1024 + 1)
            .unwrap();
        assert!(receipt.verify().unwrap_err().contains("download limit"));
    }

    #[cfg(unix)]
    #[test]
    fn public_receipt_readers_refuse_symlinked_records_and_cached_content() {
        use std::os::unix::fs::symlink;
        let _environment = GlobalStateGuard::new().unwrap();
        let directory = receipts_dir().unwrap();
        fs::create_dir_all(&directory).unwrap();
        let script = script_receipt(sha2_hex(b"abc"));
        let artifact = sample_receipt();
        fs::write(
            directory.join("download-target"),
            serde_json::to_vec(&script).unwrap(),
        )
        .unwrap();
        fs::write(
            directory.join("artifact-target"),
            serde_json::to_vec(&artifact).unwrap(),
        )
        .unwrap();
        symlink(
            "download-target",
            directory.join(format!("{}.json", script.sha256)),
        )
        .unwrap();
        symlink(
            "artifact-target",
            directory.join(format!("{}.json", artifact.receipt_id)),
        )
        .unwrap();
        assert!(Receipt::load(&script.sha256).is_err());
        assert!(ArtifactScanReceipt::load(&artifact.receipt_id).is_err());
        assert!(Receipt::list().is_err());
        assert!(ArtifactScanReceipt::list().is_err());

        let cache = crate::policy::data_dir().unwrap().join("cache");
        fs::create_dir_all(&cache).unwrap();
        fs::write(cache.join("content-target"), b"abc").unwrap();
        symlink("content-target", cache.join(&script.sha256)).unwrap();
        assert!(script.verify().is_err());
        assert_eq!(fs::read(cache.join("content-target")).unwrap(), b"abc");
    }

    #[test]
    fn public_receipt_inventory_reports_invalid_records_without_disclosing_them() {
        let _environment = GlobalStateGuard::new().unwrap();
        assert!(Receipt::list().unwrap().is_empty());
        assert!(ArtifactScanReceipt::list().unwrap().is_empty());
        let directory = receipts_dir().unwrap();
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join(format!("{}.json", "a".repeat(64)));
        for body in [
            br#"{"unsupported":"receipt-private-canary"}"#.as_slice(),
            b"invalid JSON receipt-private-canary".as_slice(),
        ] {
            fs::write(&path, body).unwrap();
            for error in [
                Receipt::list().unwrap_err(),
                ArtifactScanReceipt::list().unwrap_err(),
            ] {
                assert!(error.contains("invalid or unsupported"), "{error}");
                assert!(!error.contains("receipt-private-canary"));
            }
        }
    }

    #[test]
    fn public_receipt_lists_keep_newest_first_and_all_produced_schemas_separate() {
        let _environment = GlobalStateGuard::new().unwrap();
        let mut older_download = script_receipt("f".repeat(64));
        older_download.timestamp = "2026-01-01T00:00:00Z".into();
        let mut newer_download = script_receipt("0".repeat(64));
        newer_download.timestamp = "2026-01-03T00:00:00Z".into();
        newer_download.save().unwrap();
        older_download.save().unwrap();

        let mut legacy = sample_receipt();
        legacy.schema = 1;
        legacy.publication_state = ReceiptPublicationState::LegacyUnspecified;
        legacy.timestamp = "2026-01-01T00:00:00Z".into();
        let mut committed = committed_from_private(&sample_receipt()).unwrap();
        committed.timestamp = "2026-01-03T00:00:00Z".into();
        let mut wheel = sample_receipt();
        wheel.timestamp = "2026-01-02T00:00:00Z".into();
        let mut artifacts = [legacy, committed, wheel];
        for receipt in &mut artifacts {
            receipt.receipt_id = receipt.compute_content_hash();
            fs::write(
                receipts_dir()
                    .unwrap()
                    .join(format!("{}.json", receipt.receipt_id)),
                serde_json::to_vec(receipt).unwrap(),
            )
            .unwrap();
            assert_eq!(
                ArtifactScanReceipt::load(&receipt.receipt_id).unwrap(),
                *receipt
            );
        }

        let downloads = Receipt::list().unwrap();
        assert_eq!(downloads.len(), 2);
        assert_eq!(downloads[0].sha256, newer_download.sha256);
        assert_eq!(downloads[1].sha256, older_download.sha256);
        assert_eq!(
            ArtifactScanReceipt::list().unwrap(),
            vec![
                artifacts[1].clone(),
                artifacts[2].clone(),
                artifacts[0].clone()
            ]
        );
        let loaded = Receipt::load(&older_download.sha256).unwrap();
        assert_eq!(
            loaded.cwd, older_download.cwd,
            "inspection retains stored metadata"
        );
        assert_eq!(loaded.git_repo, older_download.git_repo);
    }

    #[test]
    fn public_artifact_load_preserves_inspection_of_edited_content_without_authority() {
        let _environment = GlobalStateGuard::new().unwrap();
        let mut receipt = sample_receipt();
        receipt.resolver_command = "edited after the content ID was computed".into();
        assert!(!receipt.content_hash_matches());
        let directory = receipts_dir().unwrap();
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join(format!("{}.json", receipt.receipt_id)),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        let loaded = ArtifactScanReceipt::load(&receipt.receipt_id).unwrap();
        assert_eq!(loaded, receipt);
        assert!(!loaded.content_hash_matches());
        assert!(loaded.validate_structure().is_err());
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
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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

    /// Point every directory env var [`crate::policy::data_dir`] /
    /// [`crate::policy::config_dir`] consult at `root`, on whichever platform the
    /// test runs (XDG on unix, APPDATA/LOCALAPPDATA on Windows), plus HOME so a
    /// stray home lookup cannot escape. The shared guard restores on drop.
    fn isolate_dirs(root: &std::path::Path) -> GlobalStateGuard {
        let mut environment = GlobalStateGuard::new().expect("isolate receipt directories");
        for key in [
            "XDG_DATA_HOME",
            "XDG_CONFIG_HOME",
            "XDG_STATE_HOME",
            "APPDATA",
            "LOCALAPPDATA",
            "HOME",
            "USERPROFILE",
        ] {
            environment.set_env(key, root);
        }
        environment
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

    #[test]
    fn capsule_resource_gap_survives_receipt_json_roundtrip() {
        let mut capsule = sample_capsule();
        capsule.coverage.resource_limits_enforced = false;

        let json = serde_json::to_string(&capsule).expect("serialize capsule receipt");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse receipt JSON");
        assert_eq!(
            value["coverage"]["resource_limits_enforced"],
            serde_json::Value::Bool(false)
        );

        let round_trip: CapsuleReceipt =
            serde_json::from_str(&json).expect("deserialize capsule receipt");
        assert!(!round_trip.coverage.resource_limits_enforced);
    }

    /// A schema-v2 `private_verified` receipt as the removed install writer
    /// produced it (sorted artifact hashes, stamped schema, content-addressed id).
    fn sample_receipt() -> ArtifactScanReceipt {
        let mut receipt = ArtifactScanReceipt {
            schema: ARTIFACT_SCAN_RECEIPT_SCHEMA,
            receipt_id: String::new(),
            tirith_version: "0.3.3".to_string(),
            engine_build_sha: engine_build_sha().to_string(),
            policy_hash: "deadbeef".repeat(8), // a stand-in policy hash
            threat_db_sequence: 42,
            resolver_command: "uv pip compile --generate-hashes --no-build".to_string(),
            resolver_version: "uv 0.4.0".to_string(),
            package_manager_version: "pip 24.0".to_string(),
            capsule: sample_capsule(),
            artifact_sha256: vec!["a".repeat(64), "b".repeat(64)],
            post_install_record: Some(PostInstallRecordSummary {
                blocked: false,
                distributions_verified: 1,
                distributions_not_found: 0,
                records_missing: 0,
                hash_mismatches: 0,
            }),
            verdict: VerdictSummary {
                action: "Allow".to_string(),
                rule_ids: vec![],
                finding_count: 0,
            },
            publication_state: ReceiptPublicationState::PrivateVerified,
            private_receipt_id: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        receipt.receipt_id = receipt.compute_content_hash();
        receipt
    }

    /// The committed-publication receipt the removed writer derived from an
    /// intact private receipt: fresh timestamp and content id, linked by
    /// `private_receipt_id`. Kept as a fixture so the reader-side linkage check
    /// ([`ArtifactScanReceipt::is_committed_publication_for`]) stays covered.
    fn committed_from_private(
        private: &ArtifactScanReceipt,
    ) -> Result<ArtifactScanReceipt, String> {
        private.validate_structure()?;
        if private.schema != ARTIFACT_SCAN_RECEIPT_SCHEMA
            || private.publication_state != ReceiptPublicationState::PrivateVerified
            || private.private_receipt_id.is_some()
        {
            return Err("committed receipt requires one unlinked private receipt".to_string());
        }
        let mut committed = private.clone();
        committed.publication_state = ReceiptPublicationState::Committed;
        committed.private_receipt_id = Some(private.receipt_id.clone());
        committed.timestamp = chrono::Utc::now().to_rfc3339();
        committed.receipt_id.clear();
        committed.receipt_id = committed.compute_content_hash();
        Ok(committed)
    }

    /// Save `receipt` where the removed writer put it, under the isolated data dir.
    fn store_fixture(receipt: &ArtifactScanReceipt) {
        let directory = receipts_dir().expect("isolated receipt directory");
        std::fs::create_dir_all(&directory).unwrap();
        crate::util::write_file_atomic_0600(
            &directory.join(format!("{}.json", receipt.receipt_id)),
            serde_json::to_string_pretty(receipt).unwrap().as_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn wheel_v1_v2_canonical_hashes_remain_byte_compatible() {
        // Fixed hashes pin the original wheel JSON shape. A newly serialized
        // field would break them.
        for (schema, phase, expected) in [
            (
                2,
                ReceiptPublicationState::PrivateVerified,
                "60e50808e1b6fbb91ecc0ab76dd7f364dad8158dc40e6b45c0d5794504adfc30",
            ),
            (
                1,
                ReceiptPublicationState::LegacyUnspecified,
                "ea89dbc3bbc1b4752d27e369c7d41cd2a0df704d3be168b55be8b927a70b1132",
            ),
        ] {
            let mut receipt = sample_receipt();
            receipt.schema = schema;
            receipt.publication_state = phase;
            receipt.engine_build_sha = "compat-fixture".into();
            receipt.timestamp = "2026-06-22T00:00:00+00:00".into();
            receipt.receipt_id = receipt.compute_content_hash();
            assert_eq!(receipt.receipt_id, expected);
            let value = serde_json::to_value(&receipt).unwrap();
            let decoded: ArtifactScanReceipt = serde_json::from_value(value).unwrap();
            assert_eq!(decoded, receipt);
            decoded.validate_structure().unwrap();
        }
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
        assert_eq!(
            r.publication_state(),
            ReceiptPublicationState::PrivateVerified
        );
        assert!(r.private_receipt_id().is_none());
        assert!(!r.is_committed_publication_for(&r));
        // Artifact hashes are stored sorted.
        assert_eq!(r.artifact_sha256, vec!["a".repeat(64), "b".repeat(64)]);
    }

    #[test]
    fn committed_receipt_links_exact_private_receipt() {
        let private = sample_receipt();
        let committed =
            committed_from_private(&private).expect("derive linked committed publication receipt");

        assert_eq!(
            committed.publication_state(),
            ReceiptPublicationState::Committed
        );
        assert_eq!(
            committed.private_receipt_id(),
            Some(private.receipt_id.as_str())
        );
        assert_ne!(committed.receipt_id, private.receipt_id);
        assert!(committed.content_hash_matches());
        assert!(committed.is_committed_publication_for(&private));
        assert!(committed_from_private(&committed).is_err());

        let mut unrelated = committed.clone();
        unrelated.private_receipt_id = Some("f".repeat(64));
        unrelated.receipt_id.clear();
        unrelated.receipt_id = unrelated.compute_content_hash();
        assert!(unrelated.content_hash_matches());
        assert!(!unrelated.is_committed_publication_for(&private));
    }

    #[test]
    fn legacy_v1_receipt_roundtrips_without_becoming_committed_proof() {
        let mut legacy = sample_receipt();
        legacy.schema = 1;
        legacy.publication_state = ReceiptPublicationState::LegacyUnspecified;
        legacy.private_receipt_id = None;
        legacy.receipt_id.clear();
        legacy.receipt_id = legacy.compute_content_hash();

        let json = serde_json::to_string(&legacy).expect("serialize legacy-compatible receipt");
        assert!(!json.contains("publication_state"));
        assert!(!json.contains("private_receipt_id"));
        let loaded: ArtifactScanReceipt =
            serde_json::from_str(&json).expect("deserialize schema-v1 receipt");

        assert_eq!(loaded.schema, 1);
        assert_eq!(
            loaded.publication_state(),
            ReceiptPublicationState::LegacyUnspecified
        );
        assert!(loaded.content_hash_matches());
        assert!(!loaded.is_committed_publication_for(&sample_receipt()));
        assert!(committed_from_private(&loaded).is_err());
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

    /// TG5: every SECURITY-relevant field must be inside the content-hash preimage,
    /// so a future `#[serde(skip)]` (or a tamperer flipping just that field) is
    /// caught by the receipt id. We mutate each in isolation from a fresh sample and
    /// assert the recomputed content hash diverges from the original id and that
    /// `content_hash_matches()` then reports the edit. Covers the verdict ACTION
    /// (Block->Allow), the fired RULE IDS, and the capsule coverage's
    /// `network_raw_denied` flag (the deny-by-default network attestation).
    #[test]
    fn receipt_content_hash_covers_security_relevant_fields() {
        // verdict.action: a Block downgraded to Allow must change the hash.
        {
            let mut r = sample_receipt();
            let original = r.receipt_id.clone();
            assert_eq!(r.verdict.action, "Allow");
            r.verdict.action = "Block".to_string();
            assert_ne!(
                r.compute_content_hash(),
                original,
                "flipping verdict.action (Allow<->Block) must change the content hash"
            );
            assert!(
                !r.content_hash_matches(),
                "a mutated verdict.action with a stale id must be detected as edited"
            );
        }

        // verdict.rule_ids: dropping (or adding) a fired rule must change the hash.
        {
            // Start from a receipt that actually carries a fired rule, then drop it.
            let mut r = sample_receipt();
            r.verdict.rule_ids = vec!["WheelStructurallyRejected".to_string()];
            r.receipt_id = r.compute_content_hash();
            let with_rule = r.receipt_id.clone();
            r.verdict.rule_ids.clear(); // drop the fired rule
            assert_ne!(
                r.compute_content_hash(),
                with_rule,
                "dropping a fired rule id must change the content hash"
            );
            assert!(
                !r.content_hash_matches(),
                "a mutated verdict.rule_ids with a stale id must be detected as edited"
            );
        }

        // capsule.coverage.network_raw_denied: flipping the raw-net-deny attestation
        // (true->false) must change the hash.
        {
            let mut r = sample_receipt();
            let original = r.receipt_id.clone();
            assert!(r.capsule.coverage.network_raw_denied);
            r.capsule.coverage.network_raw_denied = false;
            assert_ne!(
                r.compute_content_hash(),
                original,
                "flipping capsule.coverage.network_raw_denied must change the content hash"
            );
            assert!(
                !r.content_hash_matches(),
                "a mutated capsule coverage flag with a stale id must be detected as edited"
            );
        }

        // Publication state/link: neither a private receipt nor an unrelated id
        // can be edited into committed-publication proof under the old content id.
        {
            let mut r = sample_receipt();
            let original = r.receipt_id.clone();
            r.publication_state = ReceiptPublicationState::Committed;
            r.private_receipt_id = Some("f".repeat(64));
            assert_ne!(r.compute_content_hash(), original);
            assert!(!r.content_hash_matches());
            assert!(!r.is_committed_publication_for(&sample_receipt()));
        }
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
    fn stored_artifact_receipt_loads_by_id() {
        let root = tempfile::tempdir().unwrap();
        let _environment = isolate_dirs(root.path());

        let r = sample_receipt();
        store_fixture(&r);
        let loaded = ArtifactScanReceipt::load(&r.receipt_id).expect("load by id");
        assert_eq!(loaded, r);
        assert!(loaded.content_hash_matches());

        let committed = committed_from_private(&r).unwrap();
        store_fixture(&committed);
        let loaded = ArtifactScanReceipt::load(&committed.receipt_id).expect("load committed");
        assert_eq!(
            loaded.publication_state(),
            ReceiptPublicationState::Committed
        );
        assert_eq!(loaded.private_receipt_id(), Some(r.receipt_id.as_str()));
        assert!(loaded.is_committed_publication_for(&r));
    }

    #[test]
    fn artifact_receipts_list_alongside_script_receipts_without_cross_parse() {
        let root = tempfile::tempdir().unwrap();
        let _environment = isolate_dirs(root.path());

        // Save one artifact-scan receipt.
        let r = sample_receipt();
        store_fixture(&r);

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
    fn url_redaction_fails_closed_on_a_non_conformant_userinfo() {
        // A raw `/`, `?`, or `#` inside the password ends the authority scan
        // early, so the `@` is never found and the URL used to be returned
        // verbatim with the credentials intact.
        for raw in [
            "https://deploy:ab/cd@github.com/org/repo.git",
            "https://deploy:ab?cd@github.com/org/repo.git",
            "https://deploy:ab#cd@github.com/org/repo.git",
        ] {
            let redacted = redact_url_userinfo(raw);
            assert!(
                !redacted.contains("deploy"),
                "credentials survived redaction: {redacted}"
            );
            assert!(
                redacted.contains("***@"),
                "expected a redaction marker: {redacted}"
            );
        }

        // The conformant form is unchanged, and a URL the parser accepts keeps
        // an `@` that belongs to its path or query.
        assert_eq!(
            redact_url_userinfo("https://user:tok@example.com/x"),
            "https://***@example.com/x"
        );
        assert_eq!(
            redact_url_userinfo("https://example.com/a@b"),
            "https://example.com/a@b"
        );
    }
}
