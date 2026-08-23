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
        let receipt: Self = serde_json::from_str(&content).map_err(|e| format!("parse: {e}"))?;
        // Bind the loaded receipt to the requested identity (repo-0416): the
        // store is content-addressed, so a document whose embedded hash differs
        // from the requested filename is a substituted receipt — verifying it
        // would check a DIFFERENT cached script while reporting the requested
        // one as verified.
        if receipt.sha256 != sha256 {
            return Err(format!(
                "receipt identity mismatch: {sha256}.json contains a receipt for {}",
                receipt.sha256
            ));
        }
        Ok(receipt)
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
            final_url: self.final_url.as_deref().map(&url),
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
// D6: tamper-evident package-firewall scan receipt
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
    fn is_legacy_unspecified(&self) -> bool {
        *self == Self::LegacyUnspecified
    }
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

/// Why anchoring/saving a receipt could not complete.
#[derive(Debug)]
pub enum ReceiptError {
    /// The in-memory receipt is not a canonical, internally consistent record.
    /// Validation happens before any directory creation, file write, or audit
    /// append, so this error is always side-effect free.
    InvalidReceipt(String),
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
            ReceiptError::InvalidReceipt(reason) => {
                write!(f, "refusing invalid artifact receipt: {reason}")
            }
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

/// Opaque proof that one canonical schema-v2 `PrivateVerified` receipt was
/// durably saved and appended to the audit chain with an Ed25519 signature.
///
/// The fields are intentionally private and the type is neither serializable nor
/// cloneable: callers can obtain it only from
/// [`ArtifactScanReceipt::record_private_signed`]. A generic
/// [`RecordedReceipt`] cannot be promoted back into this capability.
#[derive(Debug)]
pub struct RecordedPrivateReceipt {
    receipt: ArtifactScanReceipt,
    recorded: RecordedReceipt,
}

impl RecordedPrivateReceipt {
    /// Content-addressed id of the signed private-verification receipt.
    pub fn receipt_id(&self) -> &str {
        &self.receipt.receipt_id
    }

    /// Ordinary reporting information for the saved/signed receipt.
    pub fn recorded(&self) -> &RecordedReceipt {
        &self.recorded
    }

    /// Discard the phase capability while retaining ordinary reporting data.
    pub fn into_recorded(self) -> RecordedReceipt {
        self.recorded
    }

    /// Consume the signed private capability and derive the only value that can
    /// be recorded as the linked committed-publication phase.
    pub fn prepare_committed(self) -> Result<PreparedCommittedReceipt, ReceiptError> {
        let committed = self.receipt.committed_from_private()?;
        Ok(PreparedCommittedReceipt {
            private: self.receipt,
            committed,
        })
    }
}

/// Opaque, one-shot committed receipt derived from a signed private receipt.
/// It is not itself proof of durable commitment until [`Self::record_signed`]
/// succeeds.
#[derive(Debug)]
pub struct PreparedCommittedReceipt {
    private: ArtifactScanReceipt,
    committed: ArtifactScanReceipt,
}

impl PreparedCommittedReceipt {
    /// Content-addressed id the committed receipt will have when recorded.
    pub fn receipt_id(&self) -> &str {
        &self.committed.receipt_id
    }

    /// Id of the signed private receipt this committed phase links to.
    pub fn private_receipt_id(&self) -> &str {
        &self.private.receipt_id
    }

    /// Record and sign the linked committed receipt. The opaque private
    /// capability is consumed, so no public `ArtifactScanReceipt` mutation or
    /// deserialization path can invoke this sink.
    pub fn record_signed(self) -> Result<RecordedCommittedReceipt, ReceiptError> {
        self.committed.validate_for_record()?;
        if !self.committed.is_committed_publication_for(&self.private) {
            return Err(ReceiptError::InvalidReceipt(
                "committed receipt is not the exact derivation of its signed private receipt"
                    .to_string(),
            ));
        }
        let recorded = self.committed.record_validated(true)?;
        if !recorded.signed || recorded.anchor_warning.is_some() {
            return Err(ReceiptError::AnchorFailed(
                "committed receipt did not produce one signed audit anchor".to_string(),
            ));
        }
        Ok(RecordedCommittedReceipt {
            private_receipt_id: self.private.receipt_id,
            receipt_id: self.committed.receipt_id,
            recorded,
        })
    }
}

/// Opaque proof that the exact committed derivation of a signed private receipt
/// was itself durably saved and signed in the audit chain.
#[derive(Debug)]
pub struct RecordedCommittedReceipt {
    private_receipt_id: String,
    receipt_id: String,
    recorded: RecordedReceipt,
}

impl RecordedCommittedReceipt {
    /// Content-addressed id of the committed receipt.
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    /// Content-addressed id of its signed private predecessor.
    pub fn private_receipt_id(&self) -> &str {
        &self.private_receipt_id
    }

    /// Ordinary reporting information for the committed receipt.
    pub fn recorded(&self) -> &RecordedReceipt {
        &self.recorded
    }

    /// Consume the phase proof after a checkpoint accepts it, retaining the
    /// ordinary reporting result for user-facing output.
    pub fn into_recorded(self) -> RecordedReceipt {
        self.recorded
    }
}

/// Mandatory package-install receipts are commit records, not best-effort UI
/// state. Re-sync their containing directory with the strict helper after the
/// atomic writer returns, because the general-purpose writer deliberately logs
/// and swallows a trailing directory-fsync failure for compatibility callers.
fn sync_mandatory_receipt_entry(path: &std::path::Path) -> std::io::Result<()> {
    crate::util::fsync_parent_dir(path)
}

impl ArtifactScanReceipt {
    /// Assemble a receipt from already-redacted inputs and stamp its content hash +
    /// timestamp. The caller is responsible for redacting `resolver_command` /
    /// `resolver_version` / `package_manager_version` (strip any index credential)
    /// and for passing `policy_hash` from
    /// [`crate::policy::Policy::security_projection_hash`]; this constructor sorts
    /// the artifact hashes, fills the schema + timestamp, and computes the
    /// content-addressed `receipt_id`. New receipts begin in
    /// [`ReceiptPublicationState::PrivateVerified`]. Enforcing callers obtain a
    /// signed [`RecordedPrivateReceipt`] and consume that capability through
    /// [`RecordedPrivateReceipt::prepare_committed`] only after durable,
    /// identity-verified target publication.
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
            publication_state: ReceiptPublicationState::PrivateVerified,
            private_receipt_id: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        receipt.receipt_id = receipt.compute_content_hash();
        receipt
    }

    /// Publication phase carried by this persisted receipt.
    pub fn publication_state(&self) -> ReceiptPublicationState {
        self.publication_state
    }

    /// Signed private receipt linked by a committed receipt, when present.
    pub fn private_receipt_id(&self) -> Option<&str> {
        self.private_receipt_id.as_deref()
    }

    /// Derive the committed-publication receipt from an intact schema-v2 private
    /// receipt. The returned receipt has a fresh timestamp/content id and embeds
    /// the private receipt id, so the two signed audit anchors form an explicit
    /// prepare -> commit chain without mutating either content-addressed record.
    /// This is deliberately private: only an opaque [`RecordedPrivateReceipt`]
    /// may reach it.
    fn committed_from_private(&self) -> Result<Self, ReceiptError> {
        self.validate_for_record()?;
        if self.schema != ARTIFACT_SCAN_RECEIPT_SCHEMA
            || self.publication_state != ReceiptPublicationState::PrivateVerified
            || self.private_receipt_id.is_some()
        {
            return Err(ReceiptError::InvalidReceipt(
                "committed receipt requires one unlinked schema-v2 private_verified receipt"
                    .to_string(),
            ));
        }
        if !self.content_hash_matches() {
            return Err(ReceiptError::InvalidReceipt(
                "private_verified receipt content does not match its content-addressed id"
                    .to_string(),
            ));
        }

        let mut committed = self.clone();
        committed.publication_state = ReceiptPublicationState::Committed;
        committed.private_receipt_id = Some(self.receipt_id.clone());
        committed.timestamp = chrono::Utc::now().to_rfc3339();
        committed.receipt_id.clear();
        committed.receipt_id = committed.compute_content_hash();
        Ok(committed)
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
            || private.publication_state != ReceiptPublicationState::PrivateVerified
            || private.private_receipt_id.is_some()
            || !private.content_hash_matches()
        {
            return false;
        }

        let mut expected = private.clone();
        expected.publication_state = ReceiptPublicationState::Committed;
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

    /// Validate every invariant needed before a receipt can influence the
    /// filesystem or signed audit chain. Deserialization intentionally remains
    /// backward-compatible and permissive enough to inspect old/corrupt files;
    /// this mutation boundary is strict and side-effect free.
    fn validate_for_record(&self) -> Result<(), ReceiptError> {
        validate_sha256(&self.receipt_id).map_err(ReceiptError::InvalidReceipt)?;
        if !self.content_hash_matches() {
            return Err(ReceiptError::InvalidReceipt(
                "receipt_id does not match the canonical receipt content".to_string(),
            ));
        }

        match (self.schema, self.publication_state) {
            (1, ReceiptPublicationState::LegacyUnspecified) => {
                if self.private_receipt_id.is_some() {
                    return Err(ReceiptError::InvalidReceipt(
                        "schema-v1 receipt cannot carry a private receipt link".to_string(),
                    ));
                }
            }
            (ARTIFACT_SCAN_RECEIPT_SCHEMA, ReceiptPublicationState::PrivateVerified) => {
                if self.private_receipt_id.is_some() {
                    return Err(ReceiptError::InvalidReceipt(
                        "private_verified receipt cannot carry a predecessor link".to_string(),
                    ));
                }
            }
            (ARTIFACT_SCAN_RECEIPT_SCHEMA, ReceiptPublicationState::Committed) => {
                let private_id = self.private_receipt_id.as_deref().ok_or_else(|| {
                    ReceiptError::InvalidReceipt(
                        "committed receipt is missing its signed private predecessor".to_string(),
                    )
                })?;
                validate_sha256(private_id).map_err(|reason| {
                    ReceiptError::InvalidReceipt(format!(
                        "committed receipt has an invalid private receipt id: {reason}"
                    ))
                })?;
                if private_id == self.receipt_id {
                    return Err(ReceiptError::InvalidReceipt(
                        "committed receipt cannot link to itself".to_string(),
                    ));
                }
            }
            (ARTIFACT_SCAN_RECEIPT_SCHEMA, ReceiptPublicationState::LegacyUnspecified) => {
                return Err(ReceiptError::InvalidReceipt(
                    "schema-v2 receipt must declare private_verified or committed publication state"
                        .to_string(),
                ));
            }
            (1, _) => {
                return Err(ReceiptError::InvalidReceipt(
                    "schema-v1 receipt cannot claim a publication phase".to_string(),
                ));
            }
            (schema, _) => {
                return Err(ReceiptError::InvalidReceipt(format!(
                    "unsupported artifact receipt schema {schema}"
                )));
            }
        }
        Ok(())
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
    /// Order: the file is saved first, its directory entry is strictly synced when
    /// a signature is mandatory, then the chain anchor is appended. A mandatory
    /// sync failure is [`ReceiptError::Io`]; an anchor failure is
    /// [`ReceiptError::AnchorFailed`] (the file exists but is unanchored). For the
    /// unsigned case a failed anchor degrades to a saved-but-unanchored receipt
    /// (`signed: false`), like a disabled chain, so a platform that cannot take the
    /// audit-log lock (Windows) still produces a receipt rather than blocking install.
    ///
    /// When a signature is mandatory, "logging is off" (`TIRITH_LOG=0`, the anchor is
    /// [`crate::audit::ReceiptAnchor::Skipped`]) is ALSO fail-closed: even with a
    /// signing key present, a `pkg install` that asked for a signed, anchored receipt
    /// must not accept a config that anchors and signs nothing. Only the
    /// `require_signature = false` path treats `Skipped` as an acceptable
    /// (unsigned/unanchored) outcome.
    pub fn record(&self, require_signature: bool) -> Result<RecordedReceipt, ReceiptError> {
        self.validate_for_record()?;
        if self.publication_state == ReceiptPublicationState::Committed {
            return Err(ReceiptError::InvalidReceipt(
                "committed receipts require a signed RecordedPrivateReceipt capability".to_string(),
            ));
        }
        self.record_validated(require_signature)
    }

    /// Record this schema-v2 private-verification receipt with a mandatory signed
    /// audit anchor and return the opaque capability required for committed
    /// publication. A generic [`Self::record`] result cannot be upgraded into this
    /// proof.
    pub fn record_private_signed(&self) -> Result<RecordedPrivateReceipt, ReceiptError> {
        self.validate_for_record()?;
        if self.schema != ARTIFACT_SCAN_RECEIPT_SCHEMA
            || self.publication_state != ReceiptPublicationState::PrivateVerified
            || self.private_receipt_id.is_some()
        {
            return Err(ReceiptError::InvalidReceipt(
                "private recording proof requires one unlinked schema-v2 private_verified receipt"
                    .to_string(),
            ));
        }
        let recorded = self.record_validated(true)?;
        if !recorded.signed || recorded.anchor_warning.is_some() {
            return Err(ReceiptError::AnchorFailed(
                "private receipt did not produce one signed audit anchor".to_string(),
            ));
        }
        Ok(RecordedPrivateReceipt {
            receipt: self.clone(),
            recorded,
        })
    }

    /// Side-effecting sink shared only by already-validated public/private and
    /// opaque committed paths.
    fn record_validated(&self, require_signature: bool) -> Result<RecordedReceipt, ReceiptError> {
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
        if require_signature {
            sync_mandatory_receipt_entry(&path).map_err(ReceiptError::Io)?;
        }

        // Anchor the content hash in the chain. The chain line carries the verdict
        // action + rule ids + the receipt id/hash; no secret is recorded.
        match crate::audit::log_artifact_scan_receipt(
            &self.receipt_id,
            &self.receipt_id,
            &self.verdict.action,
            &self.verdict.rule_ids,
        ) {
            crate::audit::ReceiptAnchor::Recorded { signed: false } if require_signature => {
                // The signing key can disappear or become unusable between the
                // preflight above and the locked append. Never let that race turn
                // a mandatory signed phase receipt into an accepted unsigned
                // anchor. The saved file/unsigned chain entry remain forensic
                // evidence, but the caller must fail closed.
                Err(ReceiptError::AnchorFailed(
                    "audit anchor was written without the required ed25519 signature".to_string(),
                ))
            }
            crate::audit::ReceiptAnchor::Recorded { signed } => Ok(RecordedReceipt {
                path,
                signed,
                anchor_warning: None,
            }),
            // No chain at all (logging off). When a SIGNED anchor is mandatory this is
            // fatal: "logging is off" is not an acceptable reason to skip the chain a
            // `pkg install` demanded. The signing key may be present (so the key-absence
            // gate above passed), yet with `TIRITH_LOG=0` nothing is anchored or signed,
            // and the caller would otherwise print "tamper-evident" + exit 0 over an
            // unsigned, unanchored receipt. Fail closed instead, mirroring the
            // key-absent refusal. (The file was already saved above; it is left on disk
            // but the install does NOT succeed.)
            crate::audit::ReceiptAnchor::Skipped if require_signature => {
                Err(ReceiptError::SignatureRequiredButUnavailable)
            }
            // No chain at all (logging off) and a signature is NOT mandatory. The file is
            // saved; report it as unsigned/unanchored so the caller does not over-claim
            // tamper-evidence. This is a deliberate config choice, NOT a failure, so no
            // anchor_warning.
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
        assert!(err.contains("mismatch"), "{err}");
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
        assert_eq!(
            r.publication_state(),
            ReceiptPublicationState::PrivateVerified
        );
        assert!(r.private_receipt_id().is_none());
        assert!(!r.is_committed_publication_for(&r));
        // Artifact hashes were sorted by new().
        assert_eq!(r.artifact_sha256, vec!["a".repeat(64), "b".repeat(64)]);
    }

    #[test]
    fn committed_receipt_links_exact_private_receipt() {
        let private = sample_receipt();
        let committed = private
            .committed_from_private()
            .expect("derive linked committed publication receipt");

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
        assert!(committed.committed_from_private().is_err());

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
        assert!(loaded.committed_from_private().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn mandatory_receipt_directory_sync_is_strict() {
        let root = tempfile::tempdir().unwrap();
        let receipt = root.path().join("receipt.json");
        std::fs::write(&receipt, b"fixture").unwrap();
        sync_mandatory_receipt_entry(&receipt)
            .expect("an existing receipt directory can be made durable");

        let missing_parent = root.path().join("missing/receipt.json");
        assert!(
            sync_mandatory_receipt_entry(&missing_parent).is_err(),
            "mandatory receipt durability must propagate a parent-sync failure"
        );
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
    // Unix-only: the audit-chain anchor needs the audit-log lock, which fs2 cannot
    // take on a Windows append handle, so the "anchor succeeds" assertions below
    // cannot hold there. The Windows degrade (receipt saved, unanchored) is covered
    // by the pkg_install receipt tests.
    #[cfg(unix)]
    fn record_saves_file_and_anchors_in_audit_chain() {
        let root = tempfile::tempdir().unwrap();
        let mut environment = isolate_dirs(root.path());
        // Make sure logging is on for this test even if the ambient env set it off.
        environment.set_env("TIRITH_LOG", "1");

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
        let root = tempfile::tempdir().unwrap();
        let mut environment = isolate_dirs(root.path());
        environment.set_env("TIRITH_LOG", "1");

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
        let root = tempfile::tempdir().unwrap();
        // Isolate config so no real audit-signing.key is present -> signing
        // unavailable.
        let _environment = isolate_dirs(root.path());

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

    /// Write a 32-byte ed25519 signing key the way an operator must (0600,
    /// owner-only) so `audit_signing_available()` accepts it under the isolated
    /// config dir. A plain `fs::write` lands at the process umask (often 0644 =
    /// group/other-readable), which the audit signing-key gate correctly refuses.
    #[cfg(unix)]
    fn plant_signing_key(config_dir: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(config_dir).unwrap();
        let key = config_dir.join("audit-signing.key");
        std::fs::write(&key, [7u8; 32]).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn forged_committed_receipt_is_rejected_before_write_or_anchor() {
        let root = tempfile::tempdir().unwrap();
        let mut environment = isolate_dirs(root.path());
        environment.set_env("TIRITH_LOG", "1");

        let private = sample_receipt();
        let mut forged = private.clone();
        forged.publication_state = ReceiptPublicationState::Committed;
        forged.private_receipt_id = Some(private.receipt_id.clone());
        forged.timestamp = chrono::Utc::now().to_rfc3339();
        forged.receipt_id.clear();
        forged.receipt_id = forged.compute_content_hash();
        assert!(forged.content_hash_matches());

        let receipt_path = receipts_dir()
            .expect("isolated receipt directory")
            .join(format!("{}.json", forged.receipt_id));
        let audit_path = crate::audit::audit_log_path().expect("isolated audit path");
        let error = forged
            .record(false)
            .expect_err("a public value cannot record the committed phase");
        assert!(matches!(error, ReceiptError::InvalidReceipt(_)));
        assert!(!receipt_path.exists(), "forged receipt must not be written");
        assert!(!audit_path.exists(), "forged receipt must not be anchored");
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_or_stale_receipt_id_is_rejected_before_write_or_anchor() {
        let root = tempfile::tempdir().unwrap();
        let mut environment = isolate_dirs(root.path());
        environment.set_env("TIRITH_LOG", "1");

        let mut forged = sample_receipt();
        forged.receipt_id = "../../escape".to_string();
        let audit_path = crate::audit::audit_log_path().expect("isolated audit path");
        let error = forged
            .record(false)
            .expect_err("a non-canonical receipt id must fail before path construction");
        assert!(matches!(error, ReceiptError::InvalidReceipt(_)));
        assert!(
            !root.path().join("escape.json").exists(),
            "receipt id must never escape the receipt directory"
        );
        assert!(
            !receipts_dir().expect("receipt path").exists(),
            "invalid receipt must not create its storage directory"
        );
        assert!(!audit_path.exists(), "invalid receipt must not be anchored");
    }

    #[cfg(unix)]
    #[test]
    fn signed_private_capability_is_required_for_committed_recording() {
        let root = tempfile::tempdir().unwrap();
        let mut environment = isolate_dirs(root.path());
        let tirith_dir = root.path().join("tirith");
        plant_signing_key(&tirith_dir);
        environment.set_env("TIRITH_LOG", "1");

        let private = sample_receipt();
        let private_id = private.receipt_id.clone();
        let private_proof = private
            .record_private_signed()
            .expect("private phase must be saved and signed");
        assert_eq!(private_proof.receipt_id(), private_id);
        assert!(private_proof.recorded().signed);

        let committed = private_proof
            .prepare_committed()
            .expect("signed private proof can derive committed phase");
        let committed_id = committed.receipt_id().to_string();
        assert_eq!(committed.private_receipt_id(), private_id);
        let committed_proof = committed
            .record_signed()
            .expect("linked committed phase must be saved and signed");
        assert_eq!(committed_proof.private_receipt_id(), private_id);
        assert_eq!(committed_proof.receipt_id(), committed_id);
        assert!(committed_proof.recorded().signed);

        let loaded = ArtifactScanReceipt::load(&committed_id).expect("load committed receipt");
        assert_eq!(
            loaded.publication_state(),
            ReceiptPublicationState::Committed
        );
        assert_eq!(loaded.private_receipt_id(), Some(private_id.as_str()));
        assert!(loaded.content_hash_matches());

        let audit_path = crate::audit::audit_log_path().expect("isolated audit path");
        let audit = std::fs::read_to_string(audit_path).expect("two signed receipt anchors");
        assert!(audit.contains(&private_id));
        assert!(audit.contains(&committed_id));
        assert_eq!(
            audit.matches("\"entry_type\":\"artifact_receipt\"").count(),
            2,
            "the typed two-phase flow must append exactly two receipt anchors"
        );
    }

    /// IM1 (fail-open fix): a mandatory-signature install must NOT silently downgrade
    /// to "unsigned, success" when `TIRITH_LOG=0`. With the signing KEY present (so
    /// the key-absence gate passes) but logging OFF, the anchor is `Skipped` (nothing
    /// is anchored OR signed); `record(true)` must therefore fail closed with
    /// `SignatureRequiredButUnavailable`, exactly like the key-absent case, rather
    /// than returning `Ok(signed: false)`.
    #[cfg(unix)]
    #[test]
    fn record_fails_closed_when_signature_required_but_logging_off() {
        let root = tempfile::tempdir().unwrap();
        let mut environment = isolate_dirs(root.path());
        // config_dir() == data_dir() == <root>/tirith under the isolated XDG vars.
        let tirith_dir = root.path().join("tirith");
        plant_signing_key(&tirith_dir);
        // Logging OFF -> the receipt anchor is Skipped.
        environment.set_env("TIRITH_LOG", "0");

        // Sanity: the signing key IS available (so this is NOT the key-absent path).
        assert!(
            crate::audit::audit_signing_available(),
            "the planted signing key must be accepted so we exercise the Skipped-under-mandatory \
             path, not the key-absent path"
        );

        let r = sample_receipt();
        let err = r.record(true).expect_err(
            "a mandatory-signature install must fail closed when logging is off (anchor Skipped), \
             never downgrade to an unsigned success",
        );
        assert!(
            matches!(err, ReceiptError::SignatureRequiredButUnavailable),
            "logging-off under a mandatory signature must map to SignatureRequiredButUnavailable, \
             got {err:?}"
        );
    }

    /// IM1 negative control: with the SAME logging-off config but
    /// `require_signature = false`, `Skipped` stays an acceptable
    /// unsigned/unanchored success (no behavior change for the non-mandatory path).
    #[cfg(unix)]
    #[test]
    fn record_skipped_is_ok_unsigned_when_signature_not_required() {
        let root = tempfile::tempdir().unwrap();
        let mut environment = isolate_dirs(root.path());
        environment.set_env("TIRITH_LOG", "0");

        let r = sample_receipt();
        let recorded = r
            .record(false)
            .expect("logging-off with no mandatory signature is an acceptable unsigned record");
        assert!(recorded.path.exists(), "the receipt file is still saved");
        assert!(!recorded.signed, "a skipped anchor is not signed");
        assert!(
            recorded.anchor_warning.is_none(),
            "a deliberately-disabled chain is NOT a failure, so it carries no anchor_warning"
        );
    }

    /// TG3: drive the `ReceiptAnchor::Failed -> anchor_warning: Some(_)` degrade that
    /// the unsigned (Windows audit-log-lock) case relies on. We force a REAL append
    /// failure by putting a DIRECTORY where the audit log file must be opened: the
    /// append `open()` then fails (EISDIR), so the anchor is `Failed`. With
    /// `require_signature = false` this degrades to a saved-but-unanchored receipt
    /// (the file exists, `!signed`, and `anchor_warning` is set) instead of a hard
    /// failure. Unix-only: the deterministic directory-at-path failure and the
    /// audit-log lock semantics are a unix construction.
    #[cfg(unix)]
    #[test]
    fn record_degrades_to_anchor_warning_when_chain_append_fails() {
        let root = tempfile::tempdir().unwrap();
        let mut environment = isolate_dirs(root.path());
        // Keep logging ON so the anchor is attempted (not Skipped).
        environment.set_env("TIRITH_LOG", "1");

        // Put a DIRECTORY at the audit log path so the append open() fails (EISDIR)
        // -> AuditWrite::Failed -> ReceiptAnchor::Failed.
        let log_path = crate::audit::audit_log_path().expect("log path under isolated dir");
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::create_dir_all(&log_path).unwrap();
        assert!(
            log_path.is_dir(),
            "the log path must be a directory to force the append failure"
        );

        let r = sample_receipt();
        // require_signature=false: a failed anchor degrades (saved but unanchored)
        // rather than failing the install.
        let recorded = r
            .record(false)
            .expect("an unsigned receipt with a failed anchor must still save (degraded)");
        assert!(
            recorded.path.exists(),
            "the receipt file must exist even when the chain anchor failed"
        );
        assert!(!recorded.signed, "a failed anchor is not signed");
        assert!(
            recorded.anchor_warning.is_some(),
            "a failed (non-skipped) anchor must surface an anchor_warning so the caller does not \
             over-claim tamper-evidence"
        );
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
