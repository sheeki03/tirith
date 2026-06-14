use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use base64::Engine as _;
use fs2::FileExt;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::verdict::Verdict;

fn audit_diagnostics_enabled() -> bool {
    matches!(
        std::env::var("TIRITH_AUDIT_DEBUG")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1" | "true" | "yes")
    )
}

/// Emit a non-fatal diagnostic only when `TIRITH_AUDIT_DEBUG` is set. For
/// background paths that must never interfere with hooks or change the verdict.
pub fn audit_diagnostic(msg: impl AsRef<str>) {
    if audit_diagnostics_enabled() {
        eprintln!("{}", msg.as_ref());
    }
}

/// An audit log entry.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub session_id: String,
    pub action: String,
    pub rule_ids: Vec<String>,
    pub command_redacted: String,
    pub bypass_requested: bool,
    pub bypass_honored: bool,
    pub interactive: bool,
    pub policy_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    pub tier_reached: u8,

    /// Tagged-union discriminator — "verdict", "hook_telemetry", or "trust_change".
    pub entry_type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_rule_ids: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_ttl_expires: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_scope: Option<String>,

    /// Best-effort caller origin for verdict entries; `None` for
    /// hook_telemetry / trust_change. Old logs parse (serde-default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_origin: Option<crate::agent_origin::AgentOrigin>,

    /// M11 ch2 — the matched manifest `allowed[*].name`, if any. AUDIT-CONTEXT
    /// ONLY: never read by any action-derivation path (manifest is
    /// suppression-bounded and cannot weaken a verdict). Old logs parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_allowed_match: Option<String>,

    /// W4 tamper-evidence: sha256 over the canonical JSON (with `sig` excluded)
    /// of the PREVIOUS log line. `None` for the genesis entry and for legacy
    /// entries written before chaining existed. Set under the audit lock inside
    /// [`append_to_audit_log`], never by the constructors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,

    /// W4 optional ed25519 signature (base64) over the canonical JSON of this
    /// entry INCLUDING `prev_hash` and EXCLUDING `sig`. Present only when audit
    /// signing is enabled (a key file exists in `config_dir()`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

/// Outcome of an audit-log append. [`AuditWrite::Skipped`] is NOT an error
/// (logging off / no path); [`AuditWrite::Failed`] broke the recorded-transaction promise.
enum AuditWrite {
    /// Written; the serialized line is carried for the optional remote-upload spool.
    Written(String),
    /// Intentionally not performed — `TIRITH_LOG=0` or no log path. Not an error.
    Skipped,
    /// A real write failure; the string is a human-readable reason.
    Failed(String),
}

/// Serialize an AuditEntry and append it to the audit log (TIRITH_LOG check,
/// path resolution, symlink guard, open/lock/write/sync/unlock). Never panics;
/// a real write failure is reported as [`AuditWrite::Failed`].
fn append_to_audit_log(entry: &AuditEntry, log_path: Option<PathBuf>) -> AuditWrite {
    if std::env::var("TIRITH_LOG").ok().as_deref() == Some("0") {
        return AuditWrite::Skipped;
    }

    let Some(path) = log_path.or_else(default_log_path) else {
        return AuditWrite::Skipped;
    };

    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            let reason = format!("cannot create log dir {}: {e}", parent.display());
            audit_diagnostic(format!("tirith: audit: {reason}"));
            return AuditWrite::Failed(reason);
        }
    }

    // The entry is serialized AFTER the exclusive lock is acquired (below), so
    // the chain `prev_hash` is read from the on-disk tail atomically.

    // Refuse to follow symlinks — prevents an attacker with write access in the
    // log directory from redirecting audit output to an arbitrary file.
    #[cfg(unix)]
    {
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let reason = format!("refusing to follow symlink at {}", path.display());
                audit_diagnostic(format!("tirith: audit: {reason}"));
                return AuditWrite::Failed(reason);
            }
            _ => {}
        }
    }

    let mut open_opts = OpenOptions::new();
    open_opts.create(true).append(true);
    #[cfg(unix)]
    {
        open_opts.mode(0o600);
        open_opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = open_opts.open(&path);

    let file = match file {
        Ok(f) => f,
        Err(e) => {
            let reason = format!("cannot open {}: {e}", path.display());
            audit_diagnostic(format!("tirith: audit: {reason}"));
            return AuditWrite::Failed(reason);
        }
    };

    // Enforce 0600 even on pre-existing files created before this tightening.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }

    if let Err(e) = file.lock_exclusive() {
        let reason = format!("cannot lock {}: {e}", path.display());
        audit_diagnostic(format!("tirith: audit: {reason}"));
        return AuditWrite::Failed(reason);
    }

    // C1: capture the LOCKED fd's identity (device + inode) via fstat so the
    // path-based reads below (`read_last_line` / `count_lines`, which reopen the
    // log BY PATHNAME) can confirm they read the SAME inode we hold the lock on and
    // will append to. If the log is rotated/replaced between `open()` and those
    // reads, the path would resolve to a DIFFERENT inode and `prev_hash`/`count`
    // would come from a file we are not appending to, poisoning the chain. On unix
    // we stat the path before each such read and fail closed on a mismatch; on
    // non-unix there is no portable dev/ino, so we keep the prior best-effort
    // behavior (None disables the check).
    #[cfg(unix)]
    let locked_ident: Option<(u64, u64)> = {
        use std::os::unix::fs::MetadataExt;
        match file.metadata() {
            Ok(m) => Some((m.dev(), m.ino())),
            // If we cannot fstat the locked handle we cannot prove identity; fail
            // closed rather than read a possibly-rotated path.
            Err(e) => {
                let reason = format!("cannot stat locked audit log {}: {e}", path.display());
                audit_diagnostic(format!("tirith: audit: {reason}"));
                let _ = fs2::FileExt::unlock(&file);
                return AuditWrite::Failed(reason);
            }
        }
    };
    #[cfg(not(unix))]
    let locked_ident: Option<()> = None;

    // Verify the LOG path still resolves to the locked inode. Returns an error
    // string when it does not (or cannot be stat'd) so the caller fails closed.
    // Always Ok on non-unix (no dev/ino) and a vacuous Ok if identity capture was
    // unavailable. The `.head` sidecar is intentionally NOT covered: it is rewritten
    // atomically under this same lock and verified by its own signature/count, so a
    // sidecar swap is caught downstream, not here.
    let verify_log_identity = |_p: &std::path::Path| -> Result<(), String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Some((dev, ino)) = locked_ident {
                match std::fs::metadata(_p) {
                    Ok(m) if m.dev() == dev && m.ino() == ino => Ok(()),
                    Ok(_) => Err("audit log changed identity under lock".to_string()),
                    Err(e) => Err(format!("cannot stat audit log under lock: {e}")),
                }
            } else {
                Ok(())
            }
        }
        #[cfg(not(unix))]
        {
            let _ = &locked_ident;
            Ok(())
        }
    };

    // Under the exclusive lock: derive `prev_hash` from the actual on-disk tail
    // (never trusting the head sidecar blindly, so it is crash-safe), set it on a
    // clone, optionally sign, serialize, append, then refresh the head receipt.
    if let Err(reason) = verify_log_identity(&path) {
        audit_diagnostic(format!("tirith: audit: {reason}"));
        let _ = fs2::FileExt::unlock(&file);
        return AuditWrite::Failed(reason);
    }
    let prev_hash = read_last_line(&path).as_deref().and_then(line_hash);
    let head_before = read_head(&path);
    let prev_count = match (&head_before, &prev_hash) {
        (Some(h), Some(ph)) if &h.head_hash == ph => h.count,
        _ => {
            // The fallback path reopens the log by pathname to count lines; re-verify
            // identity immediately before it so a rotation between the tail read and
            // here cannot feed a count from a different inode.
            if let Err(reason) = verify_log_identity(&path) {
                audit_diagnostic(format!("tirith: audit: {reason}"));
                let _ = fs2::FileExt::unlock(&file);
                return AuditWrite::Failed(reason);
            }
            count_lines(&path)
        }
    };

    let mut entry = entry.clone();
    entry.prev_hash = prev_hash;
    // Whether the log was ALREADY signed before this append (head receipt says so).
    // Once true, an unsigned append would be an undetectable-from-tampering
    // downgrade, so a failure to sign here must FAIL the write, not silently
    // write an unsigned line.
    let was_signed = head_before
        .as_ref()
        .map(|h| h.signing_enabled)
        .unwrap_or(false);
    // Opt-in signing: sign the canonical form (`sig` excluded, `prev_hash`
    // included) only when a signing key file exists. Attempt the signature first,
    // THEN enforce the signed-log invariant unconditionally below, so a failure to
    // produce a signature fails closed whether it came from `to_value` erroring OR
    // from `sign_canonical` returning None, never falling through to an unsigned
    // `to_string` write on a previously signed log.
    let mut signed_now = false;
    let signature = match serde_json::to_value(&entry) {
        Ok(mut unsigned) => {
            if let Some(o) = unsigned.as_object_mut() {
                o.remove("sig");
            }
            let canon = canonical_json_string(&unsigned);
            sign_canonical(canon.as_bytes())
        }
        // `to_value` failed: no signature could be produced. Treat exactly like a
        // signing failure so the `was_signed` invariant below still fires.
        Err(_) => None,
    };
    match signature {
        Some(sig) => {
            entry.sig = Some(sig);
            signed_now = true;
        }
        // The log carried signatures, but we cannot sign this entry (key gone /
        // unreadable, or the entry would not serialize). Writing it unsigned would
        // poison the log: on verify it is indistinguishable from a stripped
        // signature. Refuse BEFORE any unsigned write is attempted.
        None if was_signed => {
            let reason = "signing key unavailable for a previously signed audit log".to_string();
            audit_diagnostic(format!("tirith: audit: {reason}"));
            let _ = fs2::FileExt::unlock(&file);
            return AuditWrite::Failed(reason);
        }
        None => {}
    }
    // Fail-safe: do NOT switch signing ON mid-stream over a non-empty log whose
    // prior chained entries are unsigned. Verification would then expect every
    // chained line to be signed (signing_expected = any_line_signed OR
    // head.signing_enabled) and flag the intact, legitimately-unsigned prior
    // entries as signature downgrades, corrupting an otherwise valid log. The
    // operator must rotate the log first so signing starts from a fresh genesis.
    // (`prev_count` is the prior on-disk line count read under the lock above.)
    if !was_signed && signed_now && prev_count > 0 {
        let reason =
            "cannot enable signing on a non-empty unsigned log; rotate the log first".to_string();
        audit_diagnostic(format!("tirith: audit: {reason}"));
        let _ = fs2::FileExt::unlock(&file);
        return AuditWrite::Failed(reason);
    }
    // Signing state is monotonic per log: once any entry was signed, the receipt
    // records it so a later signature strip is detectable even if the current
    // entry happens to be unsigned.
    let signing_enabled = signed_now || was_signed;
    let line = match serde_json::to_string(&entry) {
        Ok(l) => l,
        Err(e) => {
            let reason = format!("failed to serialize entry: {e}");
            audit_diagnostic(format!("tirith: audit: {reason}"));
            let _ = fs2::FileExt::unlock(&file);
            return AuditWrite::Failed(reason);
        }
    };

    let mut writer = std::io::BufWriter::new(&file);
    if let Err(e) = writeln!(writer, "{line}") {
        let reason = format!("write failed: {e}");
        audit_diagnostic(format!("tirith: audit: {reason}"));
        let _ = fs2::FileExt::unlock(&file);
        return AuditWrite::Failed(reason);
    }
    if let Err(e) = writer.flush() {
        let reason = format!("flush failed: {e}");
        audit_diagnostic(format!("tirith: audit: {reason}"));
        let _ = fs2::FileExt::unlock(&file);
        return AuditWrite::Failed(reason);
    }
    // A failed `sync_all()` means the line is not durably on disk. The
    // recorded-transaction promise is unmet, so report it as a write failure.
    if let Err(e) = file.sync_all() {
        let reason = format!("sync failed: {e}");
        audit_diagnostic(format!("tirith: audit: {reason}"));
        let _ = fs2::FileExt::unlock(&file);
        return AuditWrite::Failed(reason);
    }
    // Refresh the head receipt (the truncation anchor) while still under the lock.
    // The log line is already durable; if the receipt cannot be made durable too,
    // a later crash could leave verify reporting a false truncation, so treat a
    // receipt-durability failure as a write failure rather than reporting success.
    if let Some(self_hash) = line_hash(&line) {
        if let Err(e) = write_head(
            &path,
            &HeadReceipt {
                head_hash: self_hash,
                count: prev_count + 1,
                signing_enabled,
                // `write_head` fills this in by signing the receipt when
                // `signing_enabled`; the constructor leaves it None.
                sig: None,
            },
        ) {
            let reason = format!("head receipt write failed: {e}");
            audit_diagnostic(format!("tirith: audit: {reason}"));
            let _ = fs2::FileExt::unlock(&file);
            return AuditWrite::Failed(reason);
        }
    }
    let _ = fs2::FileExt::unlock(&file);

    AuditWrite::Written(line)
}

// ── Tamper-evident audit chain (W4) ──────────────────────────────────────────
//
// Every entry carries `prev_hash` = sha256 over the canonical JSON (sorted keys,
// `sig` excluded) of the PREVIOUS log line, so any edit or reorder of a retained
// line breaks the chain. A per-log `<path>.head` receipt records the latest hash
// + count so tail TRUNCATION is detectable (the chain alone cannot catch it).
// Legacy lines without `prev_hash` are tolerated as an unchained prefix.
//
// Signing-state integrity (F5). For a SIGNED log, the head receipt is itself
// ed25519-signed (see `write_head` / [`HeadReceipt::sig`]), binding
// `signing_enabled` under a signature an attacker without the private key cannot
// forge. That, together with `signing_expected = any_line_signed ||
// head.signing_enabled`, closes the "strip every `sig` and rewrite the receipt to
// look unsigned" downgrade for signed logs: any head tamper invalidates the head
// signature and verify fails. HONEST LIMITATION: for an UNSIGNED log there is no
// key, so this anchor cannot exist. A fully local attacker can strip a log back
// to plain unsigned lines and there is no cryptographic way for purely local
// verification to prove signing was NEVER enabled. Proving that requires an
// external anchor (an off-box signed copy, or an out-of-band `--expected-head`).

/// Canonical JSON: object keys sorted recursively, compact, no whitespace, so a
/// re-canonicalization on read reproduces the bytes hashed on write regardless
/// of the stored line's key order.
fn canonical_json_string(v: &serde_json::Value) -> String {
    let mut out = String::new();
    canon_write(v, &mut out);
    out
}

fn canon_write(v: &serde_json::Value, out: &mut String) {
    match v {
        serde_json::Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut first = true;
            for k in keys {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push(':');
                canon_write(&map[k], out);
            }
            out.push('}');
        }
        serde_json::Value::Array(arr) => {
            out.push('[');
            for (i, e) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canon_write(e, out);
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other).unwrap_or_default()),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Hash of one audit line: parse JSON, drop `sig`, canonicalize, sha256-hex.
/// `None` if the line is not valid JSON (a legacy/corrupt line yields no hash
/// rather than crashing verification).
fn line_hash(line: &str) -> Option<String> {
    let mut v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    if let Some(obj) = v.as_object_mut() {
        obj.remove("sig");
    }
    Some(sha256_hex(canonical_json_string(&v).as_bytes()))
}

/// Read the last non-empty line of `path` without loading the whole file.
fn read_last_line(path: &std::path::Path) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    if len == 0 {
        return None;
    }
    let mut buf: Vec<u8> = Vec::new();
    let mut pos = len;
    let chunk = 4096u64;
    loop {
        let read_size = chunk.min(pos);
        pos -= read_size;
        f.seek(SeekFrom::Start(pos)).ok()?;
        let mut tmp = vec![0u8; read_size as usize];
        f.read_exact(&mut tmp).ok()?;
        tmp.extend_from_slice(&buf);
        buf = tmp;
        let trimmed_end = if buf.last() == Some(&b'\n') {
            buf.len() - 1
        } else {
            buf.len()
        };
        if let Some(nl) = buf[..trimmed_end].iter().rposition(|&b| b == b'\n') {
            return Some(String::from_utf8_lossy(&buf[nl + 1..trimmed_end]).into_owned());
        }
        if pos == 0 {
            return Some(String::from_utf8_lossy(&buf[..trimmed_end]).into_owned());
        }
    }
}

/// Count `b'\n'` occurrences in `path` by streaming fixed-size chunks rather than
/// slurping the whole file. Semantics are identical to the previous `fs::read`
/// implementation: a missing/unreadable file or any read error yields 0, an empty
/// file yields 0, and the result is the number of newline bytes (so a file with no
/// trailing newline counts one fewer than its visible line count, exactly as
/// before). This runs under the exclusive audit lock on the fallback path, so it
/// must not allocate the entire (possibly multi-GB) log.
fn count_lines(path: &std::path::Path) -> u64 {
    use std::io::Read;
    let Ok(mut f) = fs::File::open(path) else {
        return 0;
    };
    let mut buf = [0u8; 64 * 1024];
    let mut count: u64 = 0;
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => count += buf[..n].iter().filter(|&&c| c == b'\n').count() as u64,
            // A mid-stream read error matches the old behavior's all-or-nothing 0:
            // the prior `fs::read` returned 0 on any failure, so do the same here.
            Err(_) => return 0,
        }
    }
    count
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct HeadReceipt {
    head_hash: String,
    count: u64,
    /// W4 downgrade-resistance: set once signing has produced at least one `sig`
    /// for this log. Recorded OUT-OF-BAND (the chain hash deliberately excludes
    /// `sig`, so a stripped signature is otherwise byte-identical to an unsigned
    /// line). Verification uses it to flag a chained entry that lost its `sig`.
    /// Defaults to false so pre-signing receipts parse unchanged.
    #[serde(default)]
    signing_enabled: bool,
    /// F5: ed25519 signature (base64) over this receipt's canonical JSON with its
    /// OWN `sig` excluded. Present only for SIGNED logs (`signing_enabled`), set in
    /// [`write_head`] using the audit signing key. Closes the strip-all + head
    /// rewrite bypass: an attacker without the private key cannot flip
    /// `signing_enabled` to false (or otherwise rewrite the receipt) without
    /// invalidating this signature. Defaults to None so pre-F5 receipts parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sig: Option<String>,
}

fn head_path(log_path: &std::path::Path) -> PathBuf {
    let mut p = log_path.as_os_str().to_owned();
    p.push(".head");
    PathBuf::from(p)
}

fn read_head(log_path: &std::path::Path) -> Option<HeadReceipt> {
    let s = fs::read_to_string(head_path(log_path)).ok()?;
    serde_json::from_str(&s).ok()
}

/// Compute the canonical JSON of a head receipt with its OWN `sig` excluded, the
/// exact bytes signed in [`write_head`] and verified in [`verify_audit_log`]. Key
/// order is normalized (sorted) so re-serialization on read reproduces the bytes.
fn head_canonical_unsigned(receipt: &HeadReceipt) -> Option<String> {
    let mut v = serde_json::to_value(receipt).ok()?;
    if let Some(o) = v.as_object_mut() {
        o.remove("sig");
    }
    Some(canonical_json_string(&v))
}

/// Refresh the per-log head receipt durably. We already hold the log's exclusive
/// lock, so there is no concurrent writer. The receipt is the truncation anchor;
/// if the log line is durable but the receipt is lost or rolled back by more than
/// one entry, `verify_audit_log` reports a false truncation. So the temp file is
/// fsynced before the atomic rename, and the parent directory is fsynced after,
/// before this returns. `Err` means the receipt is NOT durably on disk.
///
/// F5: for a SIGNED log (`receipt.signing_enabled`), the receipt is itself signed
/// with the audit signing key (over its canonical JSON, own `sig` excluded) before
/// it is written. That binds `signing_enabled`, `head_hash`, and `count` under a
/// signature an attacker without the private key cannot forge, so flipping
/// `signing_enabled` to false (the strip-all downgrade) invalidates the head.
fn write_head(log_path: &std::path::Path, receipt: &HeadReceipt) -> std::io::Result<()> {
    let hp = head_path(log_path);

    // Sign the receipt itself when the log is signed. Signing here MUST succeed:
    // writing an unsigned head over a signed log leaves verify with no head
    // signature to check, which an attacker could exploit to mask a signing-state
    // downgrade. So if the receipt is signed-expected but signing yields nothing
    // (key gone / unreadable), fail the head write. The caller releases the lock
    // and reports the append as Failed, so no head is written at all rather than an
    // unsigned one. (The line-write path already refuses to mark a log signed
    // without a key, so in practice the key is present here.)
    let to_write = if receipt.signing_enabled {
        let mut signed = receipt.clone();
        signed.sig =
            head_canonical_unsigned(&signed).and_then(|canon| sign_canonical(canon.as_bytes()));
        if signed.sig.is_none() {
            return Err(std::io::Error::other(
                "cannot sign head receipt for a signed audit log (signing key unavailable)",
            ));
        }
        std::borrow::Cow::Owned(signed)
    } else {
        std::borrow::Cow::Borrowed(receipt)
    };
    let s = serde_json::to_string(to_write.as_ref())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    // The temp file is created fresh each call and renamed into place immediately.
    // Open it with O_NOFOLLOW|O_EXCL on unix (matching the audit log's symlink
    // hardening) so a planted symlink or pre-existing file at the temp path is
    // NOT followed or clobbered: O_EXCL fails if the path already exists, and
    // O_NOFOLLOW fails if the final component is a symlink. On an O_EXCL
    // collision (a name already squatted), randomize the suffix and retry a few
    // times before giving up. On non-unix we fall back to plain create+truncate.
    let (tmp, mut f) = open_head_tmp(&hp)?;

    // Write + fsync the temp file so its bytes are durable before the rename.
    f.write_all(s.as_bytes())?;
    f.sync_all()?;
    drop(f);

    // Atomic rename into place, then fsync the directory so the rename itself is
    // durable (a rename is a directory metadata change).
    fs::rename(&tmp, &hp)?;
    if let Some(dir) = hp.parent() {
        // Opening a directory as a File is best-effort: on Windows it fails, so an
        // open error must NOT fail the write (that would break every Windows head
        // write). But when the open SUCCEEDS (unix), a failing `sync_all()` means
        // the rename is not durably recorded, so surface that as the write error.
        if let Ok(d) = fs::File::open(dir) {
            d.sync_all()?;
        }
    }
    Ok(())
}

/// Open the head-receipt temp file for [`write_head`], hardened against a planted
/// symlink/file at the temp path. Returns the chosen temp path and its open
/// handle. On unix uses `O_NOFOLLOW|O_EXCL` and, on an `AlreadyExists` collision,
/// retries with a randomized suffix so a squatted temp name cannot wedge the
/// writer permanently.
fn open_head_tmp(hp: &std::path::Path) -> std::io::Result<(PathBuf, fs::File)> {
    #[cfg(unix)]
    {
        // First the stable `<head>.tmp` name (the common, uncontended case), then
        // randomized fallbacks if that exact path is squatted.
        for attempt in 0..8u32 {
            let mut tmp_os = hp.as_os_str().to_owned();
            if attempt == 0 {
                tmp_os.push(".tmp");
            } else {
                // Cheap, non-cryptographic uniqueness: pid + nanos + attempt. The
                // O_EXCL open is what actually guarantees we created the file; this
                // only needs to avoid colliding with the squatted name.
                let nonce = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                tmp_os.push(format!(".tmp.{}.{}.{}", std::process::id(), nonce, attempt));
            }
            let tmp = PathBuf::from(tmp_os);
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true).mode(0o600);
            opts.custom_flags(libc::O_NOFOLLOW);
            match opts.open(&tmp) {
                Ok(f) => return Ok((tmp, f)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "head temp path is squatted; refusing to write head receipt",
        ))
    }
    #[cfg(not(unix))]
    {
        let mut tmp_os = hp.as_os_str().to_owned();
        tmp_os.push(".tmp");
        let tmp = PathBuf::from(tmp_os);
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        Ok((tmp, f))
    }
}

/// Optional ed25519 signing secret key (32 raw bytes). Signing is OPT-IN: it
/// happens only when this file exists.
///
/// On unix the key file is stat'd BEFORE it is read and REFUSED if it is not a
/// regular file owned by the current effective user, or if it carries any group/
/// other bits (`mode & 0o077 != 0`). A world/group-readable private key lets any
/// local user read the 32-byte secret and forge audit signatures, so an insecure
/// key makes signing unavailable (returns None) rather than reading it. This
/// matches the `O_NOFOLLOW | 0o600` discipline used for the head temp file and the
/// pending store. On non-unix the permission model differs, so the check is
/// skipped and the key is read as before.
fn audit_signing_secret() -> Option<[u8; 32]> {
    let p = crate::policy::config_dir()?.join("audit-signing.key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(&p).ok()?;
        if !meta.file_type().is_file() {
            audit_diagnostic(format!(
                "tirith: audit: refusing signing key {} (not a regular file)",
                p.display()
            ));
            return None;
        }
        if meta.mode() & 0o077 != 0 {
            audit_diagnostic(format!(
                "tirith: audit: refusing group/other-readable signing key {} (chmod 600 it)",
                p.display()
            ));
            return None;
        }
        // SAFETY: geteuid is always-succeeds and thread-safe.
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            audit_diagnostic(format!(
                "tirith: audit: refusing signing key {} (not owned by current user)",
                p.display()
            ));
            return None;
        }
    }
    let bytes = fs::read(&p).ok()?;
    bytes.get(..32)?.try_into().ok()
}

/// Optional ed25519 verifying (public) key for `tirith audit verify`.
fn audit_verify_key() -> Option<ed25519_dalek::VerifyingKey> {
    let p = crate::policy::config_dir()?.join("audit-signing.pub");
    let bytes = fs::read(&p).ok()?;
    let arr: [u8; 32] = bytes.get(..32)?.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&arr).ok()
}

fn sign_canonical(canonical: &[u8]) -> Option<String> {
    use ed25519_dalek::Signer;
    let sk = ed25519_dalek::SigningKey::from_bytes(&audit_signing_secret()?);
    let sig = sk.sign(canonical);
    Some(base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()))
}

/// Result of verifying the audit chain over a log file.
#[derive(Debug, Clone)]
pub struct AuditVerifyReport {
    pub total_lines: usize,
    pub chained_lines: usize,
    pub legacy_prefix: usize,
    pub ok: bool,
    pub head_status: String,
    pub problems: Vec<String>,
    /// Number of chained lines that carried a `sig`.
    pub signed_lines: usize,
    /// Whether this log is expected to carry signatures — true if the head
    /// receipt records signing was enabled OR any retained line still carries a
    /// `sig` (so the signal is also anchored in the chained data, not only in the
    /// mutable sidecar). When true, a chained entry without `sig` is a downgrade,
    /// and verification fails closed if no verifying key is available.
    pub signing_expected: bool,
}

/// Verify the tamper-evident chain over `log_path` by parsing RAW JSON lines
/// (not the tolerant `AuditRecord`), recomputing each line's hash, checking each
/// entry's `prev_hash` against the previous line, validating any ed25519 `sig`
/// when a public key is configured, and comparing the tail to the `<path>.head`
/// receipt (and `expected_head`, if given). Tolerates a leading legacy-unchained
/// prefix and a head receipt that is one entry behind (a crash window).
pub fn verify_audit_log(
    log_path: &std::path::Path,
    expected_head: Option<&str>,
) -> AuditVerifyReport {
    let mut report = AuditVerifyReport {
        total_lines: 0,
        chained_lines: 0,
        legacy_prefix: 0,
        ok: true,
        head_status: String::new(),
        problems: Vec::new(),
        signed_lines: 0,
        signing_expected: false,
    };
    // C2: read the log AND its `.head` sidecar under a SHARED fs2 lock, the same
    // lock `append_to_audit_log` takes exclusively. Without it, a concurrent append
    // can interleave so that `content` (N lines) and the head receipt (N+1) are read
    // inconsistently, or the last line is observed half-written, producing a false
    // truncation / invalid-JSON failure. Open once, lock_shared, read the log
    // through THAT handle, then read the sidecar, then unlock. A missing log is the
    // genuine "cannot read" case and is reported as before.
    let (content, head) = {
        let log_file = match fs::File::open(log_path) {
            Ok(f) => f,
            Err(e) => {
                report.ok = false;
                report
                    .problems
                    .push(format!("cannot read {}: {e}", log_path.display()));
                return report;
            }
        };
        // A shared lock can fail (e.g. unsupported fs); treat that as unreadable and
        // fail closed rather than reading without the lock.
        if let Err(e) = fs2::FileExt::lock_shared(&log_file) {
            report.ok = false;
            report
                .problems
                .push(format!("cannot lock {}: {e}", log_path.display()));
            return report;
        }
        let read_result = {
            use std::io::Read;
            let mut buf = String::new();
            (&log_file).read_to_string(&mut buf).map(|_| buf)
        };
        let content = match read_result {
            Ok(c) => c,
            Err(e) => {
                let _ = fs2::FileExt::unlock(&log_file);
                report.ok = false;
                report
                    .problems
                    .push(format!("cannot read {}: {e}", log_path.display()));
                return report;
            }
        };
        // Read the head receipt once while STILL holding the shared lock so it is
        // consistent with the log content just read: its `signing_enabled` flag
        // tells us whether a chained entry missing `sig` is a downgrade (signature
        // stripped) rather than a legitimately unsigned line.
        let head = read_head(log_path);
        let _ = fs2::FileExt::unlock(&log_file);
        (content, head)
    };
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    report.total_lines = lines.len();
    let verify_key = audit_verify_key();
    // "Signatures required" must NOT rest solely on the mutable `<log>.head`
    // sidecar: an attacker could strip every `sig` AND rewrite the receipt to
    // `signing_enabled: false`. So anchor the signal in the (hash-chained) log
    // data too — if ANY retained line still carries a `sig`, signing was enabled
    // and every chained line is expected to be signed. Stripping a single sig
    // then becomes detectable from the lines that remain signed, independent of
    // the sidecar. (The pre-scan is over the same lines we re-read below.)
    let any_line_signed = lines.iter().any(|l| {
        serde_json::from_str::<serde_json::Value>(l.trim())
            .ok()
            .and_then(|v| v.get("sig").and_then(|s| s.as_str()).map(|s| !s.is_empty()))
            .unwrap_or(false)
    });
    report.signing_expected =
        head.as_ref().map(|h| h.signing_enabled).unwrap_or(false) || any_line_signed;
    let mut hashes: Vec<String> = Vec::with_capacity(lines.len());
    let mut chaining_started = false;

    for (i, line) in lines.iter().enumerate() {
        let val: serde_json::Value = match serde_json::from_str(line.trim()) {
            Ok(v) => v,
            Err(e) => {
                report.ok = false;
                report
                    .problems
                    .push(format!("line {}: invalid JSON: {e}", i + 1));
                hashes.push(String::new());
                continue;
            }
        };
        let prev = val.get("prev_hash").and_then(|v| v.as_str());
        let this_hash = line_hash(line).unwrap_or_default();

        // The signature handling below runs for EVERY entry independent of whether
        // it carries `prev_hash` (is chained), so the genesis/first signed entry
        // (which has no `prev_hash`) is authenticated, counted, and downgrade-
        // checked just like a chained line.
        if let Some(prev) = prev {
            if !chaining_started && i > 0 && report.legacy_prefix > 0 && hashes[i - 1] == prev {
                // The immediately preceding unchained line is this chain's
                // genesis (its root), not a legacy entry, so it does not count
                // toward the legacy prefix.
                report.legacy_prefix -= 1;
            }
            chaining_started = true;
            report.chained_lines += 1;
            if i == 0 {
                report.ok = false;
                report
                    .problems
                    .push("line 1: prev_hash present but no prior entry".to_string());
            } else if hashes[i - 1] != prev {
                report.ok = false;
                report
                    .problems
                    .push(format!("line {}: chain break (prev_hash mismatch)", i + 1));
            }
        } else if !chaining_started {
            report.legacy_prefix += 1;
        } else {
            report.ok = false;
            report.problems.push(format!(
                "line {}: missing prev_hash after the chain started",
                i + 1
            ));
        }

        // Signature handling, run for EVERY entry independent of `prev_hash`. The
        // genesis entry (no `prev_hash`) and every chained entry are each counted
        // in `signed_lines` and ed25519-verified when a public key is configured.
        // Verifying only inside the chained branch (the prior bug) left the first
        // signed entry unauthenticated and undercounted.
        let sig_present = val.get("sig").and_then(|v| v.as_str());
        if sig_present.is_some() {
            report.signed_lines += 1;
        } else if report.signing_expected {
            // This log is signed (per the head receipt OR a still-signed line
            // observed in the pre-scan), but this entry has no `sig`. Because `sig`
            // is excluded from the chain hash, stripping it leaves the chain intact
            // and is otherwise invisible, so flag it as a signature downgrade. This
            // runs for EVERY entry, NOT just chained ones: a signed log signs from
            // its genesis (signing cannot be enabled mid-stream over a non-empty
            // log), so stripping `sig` from the FIRST (genesis/root) entry, which
            // has no `prev_hash` and so is unchained, is just as much a downgrade as
            // stripping it from a later line. Gating on `is_chained` here would let
            // that first-entry strip pass undetected.
            report.ok = false;
            report.problems.push(format!(
                "line {}: missing signature on a signed log (possible signature downgrade)",
                i + 1
            ));
        }
        if let (Some(sig_b64), Some(vk)) = (sig_present, verify_key.as_ref()) {
            let mut unsigned = val.clone();
            if let Some(o) = unsigned.as_object_mut() {
                o.remove("sig");
            }
            let canon = canonical_json_string(&unsigned);
            let verified = base64::engine::general_purpose::STANDARD
                .decode(sig_b64)
                .ok()
                .and_then(|b| ed25519_dalek::Signature::from_slice(&b).ok())
                .map(|sig| {
                    use ed25519_dalek::Verifier;
                    vk.verify(canon.as_bytes(), &sig).is_ok()
                })
                .unwrap_or(false);
            if !verified {
                report.ok = false;
                report
                    .problems
                    .push(format!("line {}: signature verification failed", i + 1));
            }
        }
        hashes.push(this_hash);
    }

    // Fail CLOSED when a signed log cannot actually be authenticated. If
    // signatures are expected (head receipt OR an observed `sig`) but no public
    // key (`audit-signing.pub`) is configured, the signatures present in the log
    // were never verified above, so we cannot vouch for the log. Reporting `ok`
    // here would let a signed log "pass" purely because the verifier lacks the
    // key — a fail-open hole. Require the key to be present to call it verified.
    if report.signing_expected && verify_key.is_none() {
        report.ok = false;
        report.problems.push(
            "log is signed but no verifying key (audit-signing.pub) is available; \
             cannot authenticate signatures"
                .to_string(),
        );
    }

    // F5: verify the HEAD RECEIPT's own signature when the log is signed. The chain
    // hash excludes `sig`, so an attacker could strip every line's `sig` AND set
    // the receipt's `signing_enabled=false` to masquerade the log as unsigned.
    // Anchoring `signing_expected` in the chained data (any_line_signed) already
    // means stripping must ALSO rewrite the receipt; signing the receipt closes the
    // loop: without the private key the attacker cannot re-sign a tampered receipt,
    // so any head edit (including flipping `signing_enabled`) invalidates this
    // signature. For an UNSIGNED log there is no key and this anchor cannot exist;
    // see the module note: local verification cannot prove signing was NEVER
    // enabled on an unsigned log without an external anchor.
    if report.signing_expected {
        if let (Some(h), Some(vk)) = (head.as_ref(), verify_key.as_ref()) {
            let head_sig_ok = match (h.sig.as_deref(), head_canonical_unsigned(h)) {
                (Some(sig_b64), Some(canon)) => base64::engine::general_purpose::STANDARD
                    .decode(sig_b64)
                    .ok()
                    .and_then(|b| ed25519_dalek::Signature::from_slice(&b).ok())
                    .map(|sig| {
                        use ed25519_dalek::Verifier;
                        vk.verify(canon.as_bytes(), &sig).is_ok()
                    })
                    .unwrap_or(false),
                _ => false,
            };
            if !head_sig_ok {
                report.ok = false;
                report
                    .problems
                    .push("head signature invalid (possible signing-state downgrade)".to_string());
            }
        }
    }

    match head {
        Some(head) => {
            let n = hashes.len();
            // The head `count` is the TOTAL number of log lines the receipt covers
            // (set as `prev_count + 1` in `write_head`, where `prev_count` starts
            // from `count_lines` over the whole file including any legacy-unchained
            // prefix). So a clean tail must match BOTH the tail hash AND the line
            // count: a stale/rewritten receipt that reuses an old hash but reports
            // the wrong count is otherwise accepted, hiding a rollback/replace.
            if n > 0 && head.head_hash == hashes[n - 1] {
                if head.count == n as u64 {
                    report.head_status = format!("head receipt OK (count {})", head.count);
                } else {
                    report.ok = false;
                    report.head_status = format!(
                        "head receipt count mismatch: expected {n}, got {}",
                        head.count
                    );
                    report.problems.push(report.head_status.clone());
                }
            } else if n > 1 && head.head_hash == hashes[n - 2] {
                // The documented crash window: the last line synced but the receipt
                // still points one entry back, so its count must be exactly n - 1.
                if head.count == (n - 1) as u64 {
                    report.head_status =
                        "head receipt is one entry behind (crash window); acceptable".to_string();
                } else {
                    report.ok = false;
                    report.head_status = format!(
                        "head receipt count mismatch: expected {}, got {}",
                        n - 1,
                        head.count
                    );
                    report.problems.push(report.head_status.clone());
                }
            } else {
                report.ok = false;
                report.head_status =
                    "head receipt does not match log tail (possible truncation)".to_string();
                report.problems.push(report.head_status.clone());
            }
        }
        None => {
            // A missing `.head` sidecar must fail closed when there is a truncation
            // anchor to defeat: an attacker who deletes the sidecar of an existing
            // chained log would otherwise pass verification, defeating truncation
            // detection (the chain alone proves internal consistency but not that
            // the tail is intact). The operator can still verify by supplying
            // `--expected-head` (an explicit out-of-band anchor, validated just
            // below); when present it is the trusted tail, so we stay tolerant here
            // and let that check decide. A purely legacy/unchained log (no chained
            // entries) has no truncation anchor by design and remains tolerant.
            //
            // C3: a SIGNED log whose ONLY retained entry is the genesis line has
            // `signing_expected = true` but `chained_lines = 0` (the genesis has no
            // `prev_hash`). Deleting its `.head` must ALSO fail closed: the receipt
            // is what binds `signing_enabled`, so dropping it makes a
            // truncation-to-empty of a signed log unverifiable. Gate on `signing
            // expected OR chained` so the signed single-entry case is covered too.
            if (report.chained_lines > 0 || report.signing_expected) && expected_head.is_none() {
                report.ok = false;
                report.head_status =
                    "no head receipt for a signed/chained log (missing sidecar; truncation cannot \
                     be ruled out; pass --expected-head to verify out-of-band)"
                        .to_string();
                report.problems.push(report.head_status.clone());
            } else {
                report.head_status = "no head receipt (truncation cannot be detected)".to_string();
            }
        }
    }

    if let Some(exp) = expected_head {
        let n = hashes.len();
        if n == 0 || hashes[n - 1] != exp {
            report.ok = false;
            report
                .problems
                .push("expected-head does not match the computed tail hash".to_string());
        }
    }

    report
}

/// Append a verdict entry to the audit log. Never panics or changes the verdict.
///
/// `custom_dlp_patterns` are Team-tier regexes applied alongside built-in DLP
/// redaction before the command is logged. Returns `Ok(())` when written OR
/// intentionally skipped (`TIRITH_LOG=0`, no path); `Err(reason)` only on a real
/// write failure.
#[must_use = "a failed audit write is silently lost unless the Result is handled"]
pub fn log_verdict(
    verdict: &Verdict,
    command: &str,
    log_path: Option<PathBuf>,
    event_id: Option<String>,
    custom_dlp_patterns: &[String],
) -> Result<(), String> {
    log_verdict_with_raw(
        verdict,
        command,
        log_path,
        event_id,
        custom_dlp_patterns,
        None,
        None,
    )
}

/// Like [`log_verdict`] but also records the raw (pre-post-processing) action
/// (before overrides/escalation) and rule_ids (before paranoia).
#[must_use = "a failed audit write is silently lost unless the Result is handled"]
pub fn log_verdict_with_raw(
    verdict: &Verdict,
    command: &str,
    log_path: Option<PathBuf>,
    event_id: Option<String>,
    custom_dlp_patterns: &[String],
    raw_action: Option<String>,
    raw_rule_ids: Option<Vec<String>>,
) -> Result<(), String> {
    let entry = AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: crate::session::resolve_session_id(),
        action: format!("{:?}", verdict.action),
        rule_ids: verdict
            .findings
            .iter()
            .map(|f| f.rule_id.to_string())
            .collect(),
        command_redacted: redact_command(command, custom_dlp_patterns),
        bypass_requested: verdict.bypass_requested,
        bypass_honored: verdict.bypass_honored,
        interactive: verdict.interactive_detected,
        policy_path: verdict.policy_path_used.clone(),
        event_id,
        tier_reached: verdict.tier_reached,
        entry_type: "verdict".to_string(),
        event: None,
        integration: None,
        hook_type: None,
        detail: None,
        elapsed_ms: None,
        raw_action,
        raw_rule_ids,
        trust_pattern: None,
        trust_rule_id: None,
        trust_action: None,
        trust_ttl_expires: None,
        trust_scope: None,
        // Carry the caller origin (already consulted for enforcement upstream)
        // so downstream tooling can attribute verdicts after the fact.
        agent_origin: verdict.agent_origin.clone(),
        // Audit-context only; never consulted for action.
        manifest_allowed_match: verdict.manifest_allowed_match.clone(),
        // Chain fields are filled in under the lock in `append_to_audit_log`.
        prev_hash: None,
        sig: None,
    };

    let line = match append_to_audit_log(&entry, log_path) {
        AuditWrite::Written(l) => l,
        AuditWrite::Skipped => return Ok(()),
        AuditWrite::Failed(reason) => return Err(reason),
    };

    // If a policy server is configured via env, spool the entry for background upload.
    let server_url = std::env::var("TIRITH_SERVER_URL")
        .ok()
        .filter(|s| !s.is_empty());
    let api_key = std::env::var("TIRITH_API_KEY")
        .ok()
        .filter(|s| !s.is_empty());
    if let (Some(url), Some(key)) = (server_url, api_key) {
        crate::audit_upload::spool_and_upload(&line, &url, &key, None, None);
    }
    Ok(())
}

/// Log a hook telemetry event (`entry_type = "hook_telemetry"`). Best-effort,
/// never panics; reuses the same log file / I/O pattern as `log_verdict`.
pub fn log_hook_event(
    integration: &str,
    hook_type: &str,
    event: &str,
    elapsed_ms: Option<f64>,
    detail: Option<&str>,
) {
    let entry = AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: crate::session::resolve_session_id(),
        action: "hook".to_string(),
        rule_ids: vec![],
        command_redacted: String::new(),
        bypass_requested: false,
        bypass_honored: false,
        interactive: false,
        policy_path: None,
        event_id: None,
        tier_reached: 0,
        entry_type: "hook_telemetry".to_string(),
        event: Some(event.to_string()),
        integration: Some(integration.to_string()),
        hook_type: Some(hook_type.to_string()),
        detail: detail.map(String::from),
        elapsed_ms,
        raw_action: None,
        raw_rule_ids: None,
        trust_pattern: None,
        trust_rule_id: None,
        trust_action: None,
        trust_ttl_expires: None,
        trust_scope: None,
        // A hook event is a probe/heartbeat, not a verdict — no synthetic origin.
        agent_origin: None,
        manifest_allowed_match: None,
        prev_hash: None,
        sig: None,
    };

    // Best-effort: a write failure here is not surfaced to the user.
    let _ = append_to_audit_log(&entry, None);
}

/// Log a trust change (`entry_type = "trust_change"`). Best-effort, never panics;
/// reuses the same log file / I/O pattern as `log_verdict`.
pub fn log_trust_change(
    pattern: &str,
    rule_id: Option<&str>,
    trust_action: &str,
    ttl_expires: Option<&str>,
    scope: &str,
) {
    let entry = AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: crate::session::resolve_session_id(),
        action: "trust".to_string(),
        rule_ids: vec![],
        command_redacted: String::new(),
        bypass_requested: false,
        bypass_honored: false,
        interactive: false,
        policy_path: None,
        event_id: None,
        tier_reached: 0,
        entry_type: "trust_change".to_string(),
        event: None,
        integration: None,
        hook_type: None,
        detail: None,
        elapsed_ms: None,
        raw_action: None,
        raw_rule_ids: None,
        trust_pattern: Some(pattern.to_string()),
        trust_rule_id: rule_id.map(String::from),
        trust_action: Some(trust_action.to_string()),
        trust_ttl_expires: ttl_expires.map(String::from),
        trust_scope: Some(scope.to_string()),
        // Trust changes are operator actions, not agent-attributed commands.
        agent_origin: None,
        manifest_allowed_match: None,
        prev_hash: None,
        sig: None,
    };

    // Best-effort: a write failure here is not surfaced to the user.
    let _ = append_to_audit_log(&entry, None);
}

fn default_log_path() -> Option<PathBuf> {
    crate::policy::data_dir().map(|d| d.join("log.jsonl"))
}

/// Public accessor for the audit log path (so out-of-crate readers need not
/// hard-code `data_dir()/log.jsonl`).
pub fn audit_log_path() -> Option<PathBuf> {
    default_log_path()
}

/// Build a parseable finding ID `<event_id>:<index>` (used by `tirith explain
/// --finding`). Colon delimiter is safe: production `event_id`s (UUID-derived)
/// contain no colon, and [`parse_finding_id`] splits on the LAST colon anyway.
pub fn finding_id_for(event_id: &str, index: usize) -> String {
    format!("{event_id}:{index}")
}

/// Parse a [`finding_id_for`] ID into `(event_id, index)`, splitting on the LAST
/// colon. Returns `None` when malformed (no colon, empty prefix, or non-`usize`
/// index — the `usize` parse is the load-bearing validator against bad indices).
pub fn parse_finding_id(id: &str) -> Option<(&str, usize)> {
    let (event_id, index_str) = id.rsplit_once(':')?;
    if event_id.is_empty() {
        return None;
    }
    let index: usize = index_str.parse().ok()?;
    Some((event_id, index))
}

fn redact_command(cmd: &str, custom_patterns: &[String]) -> String {
    let dlp_redacted = crate::redact::redact_with_custom(cmd, custom_patterns);
    let prefix = crate::util::truncate_bytes(&dlp_redacted, 80);
    if prefix.len() == dlp_redacted.len() {
        dlp_redacted
    } else {
        format!(
            "{}[...redacted {} bytes]",
            prefix,
            dlp_redacted.len() - prefix.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Action, Verdict};

    /// Write a signing key to `path` with secure (0600, owner-only) permissions so
    /// `audit_signing_secret`'s unix permission gate accepts it. A plain
    /// `fs::write` would create the file with the process umask (commonly 0644 =
    /// group/other readable), which the gate now correctly refuses. Tests that want
    /// signing to be available must therefore store the key the secure way, which
    /// is also how a real operator must store it.
    fn write_signing_key(path: &std::path::Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn test_tirith_log_disabled() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.jsonl");

        unsafe { std::env::set_var("TIRITH_LOG", "0") };

        let verdict = Verdict {
            action: Action::Allow,
            findings: vec![],
            tier_reached: 1,
            timings_ms: crate::verdict::Timings {
                tier0_ms: 0.0,
                tier1_ms: 0.0,
                tier2_ms: None,
                tier3_ms: None,
                total_ms: 0.0,
            },
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
            agent_origin: None,
            manifest_allowed_match: None,
        };

        // TIRITH_LOG=0 is an intentional skip, not a failure → Ok(()).
        assert!(
            log_verdict(&verdict, "test cmd", Some(log_path.clone()), None, &[]).is_ok(),
            "TIRITH_LOG=0 is an intentional skip, not a write failure"
        );

        assert!(
            !log_path.exists(),
            "log file should not be created when TIRITH_LOG=0"
        );

        unsafe { std::env::remove_var("TIRITH_LOG") };
    }

    #[test]
    fn test_audit_diagnostics_disabled_by_default() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("TIRITH_AUDIT_DEBUG") };
        assert!(!audit_diagnostics_enabled());
    }

    #[test]
    fn test_audit_diagnostics_enabled_by_env() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("TIRITH_AUDIT_DEBUG", "true") };
        assert!(audit_diagnostics_enabled());
        unsafe { std::env::remove_var("TIRITH_AUDIT_DEBUG") };
    }

    #[cfg(unix)]
    #[test]
    fn test_audit_log_permissions_0600() {
        use std::os::unix::fs::PermissionsExt;

        // Test the OpenOptions pattern directly — avoids env var races with
        // test_tirith_log_disabled (which sets TIRITH_LOG=0 in the same process).
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test_perms.jsonl");

        {
            use std::io::Write;
            let mut open_opts = OpenOptions::new();
            open_opts.create(true).append(true);
            use std::os::unix::fs::OpenOptionsExt;
            open_opts.mode(0o600);
            let mut f = open_opts.open(&log_path).unwrap();
            writeln!(f, "test").unwrap();
        }

        let meta = std::fs::metadata(&log_path).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "audit log should be 0600"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_remote_audit_upload_spools_when_configured() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let state_home = dir.path().join("state");

        // Invalid local URL so drain returns early after spooling.
        unsafe { std::env::set_var("TIRITH_SERVER_URL", "http://127.0.0.1") };
        unsafe { std::env::set_var("TIRITH_API_KEY", "dummy") };
        unsafe { std::env::set_var("XDG_STATE_HOME", &state_home) };
        unsafe { std::env::remove_var("TIRITH_LOG") };

        let verdict = Verdict {
            action: Action::Allow,
            findings: vec![],
            tier_reached: 1,
            timings_ms: crate::verdict::Timings {
                tier0_ms: 0.0,
                tier1_ms: 0.0,
                tier2_ms: None,
                tier3_ms: None,
                total_ms: 0.0,
            },
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
            agent_origin: None,
            manifest_allowed_match: None,
        };

        let _ = log_verdict(&verdict, "echo hello", Some(log_path), None, &[]);

        let spool = state_home.join("tirith").join("audit-queue.jsonl");
        assert!(spool.exists(), "remote audit events should be spooled");

        unsafe { std::env::remove_var("XDG_STATE_HOME") };
        unsafe { std::env::remove_var("TIRITH_API_KEY") };
        unsafe { std::env::remove_var("TIRITH_SERVER_URL") };
    }

    #[cfg(unix)]
    #[test]
    fn test_audit_refuses_symlink() {
        // Hermetic: pin every env input that could otherwise route this through
        // `AuditWrite::Skipped` (which would yield Ok and break the assertion).
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let state_home = dir.path().join("state");
        unsafe { std::env::set_var("TIRITH_LOG", "1") };
        unsafe { std::env::set_var("XDG_STATE_HOME", &state_home) };
        unsafe { std::env::set_var("APPDATA", &state_home) };
        unsafe { std::env::remove_var("TIRITH_SERVER_URL") };
        unsafe { std::env::remove_var("TIRITH_API_KEY") };

        let target = dir.path().join("target");
        std::fs::write(&target, "original").unwrap();

        let symlink_path = dir.path().join("log.jsonl");
        std::os::unix::fs::symlink(&target, &symlink_path).unwrap();

        let verdict = Verdict {
            action: Action::Allow,
            findings: vec![],
            tier_reached: 1,
            timings_ms: crate::verdict::Timings {
                tier0_ms: 0.0,
                tier1_ms: 0.0,
                tier2_ms: None,
                tier3_ms: None,
                total_ms: 0.0,
            },
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
            agent_origin: None,
            manifest_allowed_match: None,
        };

        // Refusing the symlink is a real write failure → Err, so the caller
        // can surface it.
        let result = log_verdict(&verdict, "test cmd", Some(symlink_path), None, &[]);
        assert!(
            result.is_err(),
            "refusing a symlinked log path must report a write failure"
        );

        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "original",
            "audit should refuse to write through symlink"
        );

        unsafe { std::env::remove_var("TIRITH_LOG") };
        unsafe { std::env::remove_var("XDG_STATE_HOME") };
        unsafe { std::env::remove_var("APPDATA") };
    }

    /// CR2: a write that cannot be durably recorded must surface as a failure,
    /// not a silent success (a dir-as-log-path is the deterministic proxy here).
    #[cfg(unix)]
    #[test]
    fn test_audit_durability_failure_is_reported() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let state_home = dir.path().join("state");
        unsafe { std::env::set_var("TIRITH_LOG", "1") };
        unsafe { std::env::set_var("XDG_STATE_HOME", &state_home) };
        unsafe { std::env::set_var("APPDATA", &state_home) };
        unsafe { std::env::remove_var("TIRITH_SERVER_URL") };
        unsafe { std::env::remove_var("TIRITH_API_KEY") };

        // A directory can't be opened for append → must report Failed.
        let log_path = dir.path().join("not-a-file");
        std::fs::create_dir(&log_path).unwrap();

        let verdict = Verdict {
            action: Action::Allow,
            findings: vec![],
            tier_reached: 1,
            timings_ms: crate::verdict::Timings {
                tier0_ms: 0.0,
                tier1_ms: 0.0,
                tier2_ms: None,
                tier3_ms: None,
                total_ms: 0.0,
            },
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
            agent_origin: None,
            manifest_allowed_match: None,
        };

        let result = log_verdict(&verdict, "test cmd", Some(log_path), None, &[]);
        assert!(
            result.is_err(),
            "an audit write that cannot be durably recorded must report a failure"
        );

        unsafe { std::env::remove_var("TIRITH_LOG") };
        unsafe { std::env::remove_var("XDG_STATE_HOME") };
        unsafe { std::env::remove_var("APPDATA") };
    }

    /// `agent_origin` must flow through into the audit entry and survive the JSON round-trip.
    #[cfg(unix)]
    #[test]
    fn test_audit_entry_carries_agent_origin() {
        use crate::agent_origin::AgentOrigin;
        use crate::audit_aggregator;

        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let state_home = dir.path().join("state");
        unsafe {
            std::env::set_var("TIRITH_LOG", "1");
            std::env::set_var("XDG_STATE_HOME", &state_home);
            std::env::set_var("APPDATA", &state_home);
            std::env::remove_var("TIRITH_SERVER_URL");
            std::env::remove_var("TIRITH_API_KEY");
        }

        let mut verdict = Verdict {
            action: Action::Allow,
            findings: vec![],
            tier_reached: 1,
            timings_ms: crate::verdict::Timings::default(),
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
            agent_origin: None,
            manifest_allowed_match: None,
        };
        verdict.agent_origin = AgentOrigin::agent("claude-code", Some("1.2.3"));

        log_verdict(&verdict, "echo hi", Some(log_path.clone()), None, &[])
            .expect("audit write should succeed");

        let read = audit_aggregator::read_log(&log_path).expect("read_log");
        assert_eq!(read.records.len(), 1, "expected exactly one audit record");
        let rec = &read.records[0];
        match rec.agent_origin.as_ref().expect("agent_origin present") {
            AgentOrigin::Agent { tool, version } => {
                assert_eq!(tool, "claude-code");
                assert_eq!(version.as_deref(), Some("1.2.3"));
            }
            other => panic!("expected Agent variant, got {other:?}"),
        }

        unsafe {
            std::env::remove_var("TIRITH_LOG");
            std::env::remove_var("XDG_STATE_HOME");
            std::env::remove_var("APPDATA");
        }
    }

    /// An old log line without an `agent_origin` field must still parse (serde-default).
    #[cfg(unix)]
    #[test]
    fn test_audit_record_parses_legacy_line_without_agent_origin() {
        use crate::audit_aggregator;

        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("legacy.jsonl");

        // A pre-chunk-1 audit line — no agent_origin field at all.
        let legacy = r#"{"timestamp":"2026-04-10T12:00:00+00:00","session_id":"abc","action":"Allow","rule_ids":[],"command_redacted":"echo hi","bypass_requested":false,"bypass_honored":false,"interactive":false,"tier_reached":1,"entry_type":"verdict"}"#;
        std::fs::write(&log_path, format!("{legacy}\n")).unwrap();

        let read = audit_aggregator::read_log(&log_path).expect("read_log");
        assert_eq!(read.records.len(), 1);
        assert_eq!(read.skipped_lines, 0);
        assert!(
            read.records[0].agent_origin.is_none(),
            "legacy line must parse with agent_origin = None"
        );
    }

    /// A verdict with `agent_origin: None` must NOT emit the field on the wire.
    #[cfg(unix)]
    #[test]
    fn test_audit_entry_omits_field_when_no_origin() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("noorigin.jsonl");
        let state_home = dir.path().join("state");
        unsafe {
            std::env::set_var("TIRITH_LOG", "1");
            std::env::set_var("XDG_STATE_HOME", &state_home);
            std::env::set_var("APPDATA", &state_home);
            std::env::remove_var("TIRITH_SERVER_URL");
            std::env::remove_var("TIRITH_API_KEY");
        }

        let verdict = Verdict {
            action: Action::Allow,
            findings: vec![],
            tier_reached: 1,
            timings_ms: crate::verdict::Timings::default(),
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
            agent_origin: None,
            manifest_allowed_match: None,
        };
        log_verdict(&verdict, "echo hi", Some(log_path.clone()), None, &[])
            .expect("audit write should succeed");

        let line = std::fs::read_to_string(&log_path).unwrap();
        assert!(
            !line.contains("agent_origin"),
            "the field must be omitted when None: line was {line}"
        );

        unsafe {
            std::env::remove_var("TIRITH_LOG");
            std::env::remove_var("XDG_STATE_HOME");
            std::env::remove_var("APPDATA");
        }
    }

    // finding_id_for / parse_finding_id round-trip — shape contract is
    // `<event_id>:<index>`, parsed back by splitting on the LAST colon.

    #[test]
    fn finding_id_round_trip_simple() {
        let id = finding_id_for("evt-abc-123", 2);
        assert_eq!(id, "evt-abc-123:2");
        let parsed = parse_finding_id(&id).expect("simple ID must parse");
        assert_eq!(parsed.0, "evt-abc-123");
        assert_eq!(parsed.1, 2);
    }

    #[test]
    fn parse_finding_id_handles_colon_in_event_id() {
        // Splitting on the LAST colon lets a colon-bearing event_id round-trip.
        let id = "ns:evt-with:colon:7";
        let parsed = parse_finding_id(id).expect("trailing-int form must parse");
        assert_eq!(parsed.0, "ns:evt-with:colon");
        assert_eq!(parsed.1, 7);
    }

    #[test]
    fn parse_finding_id_rejects_malformed_input() {
        assert_eq!(parse_finding_id("no-colon-here"), None);
        assert_eq!(parse_finding_id(":5"), None);
        assert_eq!(parse_finding_id("evt:not-a-number"), None);
        assert_eq!(parse_finding_id("evt:"), None);
        assert_eq!(parse_finding_id(""), None);
    }

    #[test]
    fn parse_finding_id_rejects_negative_index() {
        // `usize` cannot parse negatives.
        assert_eq!(parse_finding_id("evt:-1"), None);
    }

    // ── W4: tamper-evident audit chain ──────────────────────────────────────

    #[cfg(unix)]
    fn chain_test_entry(action: &str) -> AuditEntry {
        AuditEntry {
            timestamp: "2026-06-12T00:00:00+00:00".to_string(),
            session_id: "sess".to_string(),
            action: action.to_string(),
            rule_ids: vec![],
            command_redacted: format!("cmd-{action}"),
            bypass_requested: false,
            bypass_honored: false,
            interactive: false,
            policy_path: None,
            event_id: None,
            tier_reached: 1,
            entry_type: "verdict".to_string(),
            event: None,
            integration: None,
            hook_type: None,
            detail: None,
            elapsed_ms: None,
            raw_action: None,
            raw_rule_ids: None,
            trust_pattern: None,
            trust_rule_id: None,
            trust_action: None,
            trust_ttl_expires: None,
            trust_scope: None,
            agent_origin: None,
            manifest_allowed_match: None,
            prev_hash: None,
            sig: None,
        }
    }

    #[cfg(unix)]
    fn append_chain(log_path: &std::path::Path, actions: &[&str]) {
        for a in actions {
            let _ = append_to_audit_log(&chain_test_entry(a), Some(log_path.to_path_buf()));
        }
    }

    #[test]
    fn canonical_json_sorts_keys_and_ignores_sig() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"b":1,"a":{"z":2,"y":[3,2,1]}}"#).unwrap();
        assert_eq!(
            canonical_json_string(&v),
            r#"{"a":{"y":[3,2,1],"z":2},"b":1}"#
        );
        // line_hash is independent of key order and of the `sig` field.
        let h1 = line_hash(r#"{"a":1,"b":2}"#).unwrap();
        let h2 = line_hash(r#"{"b":2,"a":1,"sig":"whatever"}"#).unwrap();
        assert_eq!(h1, h2);
    }

    #[cfg(unix)]
    #[test]
    fn audit_chain_append_then_verify_ok() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("TIRITH_LOG", "1") };
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        append_chain(&log, &["Allow", "Block", "Warn"]);

        let content = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(!lines[0].contains("prev_hash"));
        assert!(lines[1].contains("prev_hash"));

        let report = verify_audit_log(&log, None);
        assert!(report.ok, "expected clean chain, got {:?}", report.problems);
        assert_eq!(report.chained_lines, 2);
        assert_eq!(report.legacy_prefix, 0);
        assert!(report.head_status.starts_with("head receipt OK"));
    }

    #[cfg(unix)]
    #[test]
    fn audit_chain_detects_edit() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("TIRITH_LOG", "1") };
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        append_chain(&log, &["Allow", "Block", "Warn"]);

        let content = std::fs::read_to_string(&log).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        lines[0] = lines[0].replace("cmd-Allow", "cmd-EVIL");
        std::fs::write(&log, lines.join("\n") + "\n").unwrap();

        let report = verify_audit_log(&log, None);
        assert!(!report.ok, "edited line must break the chain");
        assert!(report.problems.iter().any(|p| p.contains("chain break")));
    }

    #[cfg(unix)]
    #[test]
    fn audit_chain_detects_truncation() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("TIRITH_LOG", "1") };
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        append_chain(&log, &["Allow", "Block", "Warn"]);

        // Drop the last line but leave the head receipt pointing at 3 entries.
        let content = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        std::fs::write(&log, lines[..2].join("\n") + "\n").unwrap();

        let report = verify_audit_log(&log, None);
        assert!(
            !report.ok,
            "tail truncation must be caught by the head receipt"
        );
        assert!(report.head_status.contains("truncation"));
    }

    #[cfg(unix)]
    #[test]
    fn audit_chain_tolerates_legacy_prefix() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("TIRITH_LOG", "1") };
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        std::fs::write(
            &log,
            "{\"action\":\"Allow\",\"timestamp\":\"t1\"}\n{\"action\":\"Allow\",\"timestamp\":\"t2\"}\n",
        )
        .unwrap();
        append_chain(&log, &["Block", "Warn"]);

        let report = verify_audit_log(&log, None);
        assert!(
            report.ok,
            "legacy prefix must not fail verification: {:?}",
            report.problems
        );
        // Two pre-chain lines, but the second is the genesis that the first
        // chained entry points back to, so only the first counts as legacy.
        assert_eq!(report.legacy_prefix, 1);
        assert_eq!(report.chained_lines, 2);
    }

    #[cfg(unix)]
    #[test]
    fn audit_verify_expected_head() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("TIRITH_LOG", "1") };
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        append_chain(&log, &["Allow", "Block"]);

        let content = std::fs::read_to_string(&log).unwrap();
        let last = content.lines().last().unwrap();
        let head = line_hash(last).unwrap();
        assert!(verify_audit_log(&log, Some(&head)).ok);
        assert!(!verify_audit_log(&log, Some("deadbeef")).ok);
    }

    #[cfg(unix)]
    #[test]
    fn audit_verify_tolerates_head_one_entry_behind() {
        // Simulate the documented crash window: the last log line synced to disk
        // but the process died before write_head ran, so the head receipt still
        // points at the SECOND-to-last line. Verification must accept this.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("TIRITH_LOG", "1") };
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        append_chain(&log, &["Allow", "Block", "Warn"]);

        // Compute the hash of the second-to-last line and rewrite ONLY the head
        // sidecar to point at it (count = total - 1). The log file is untouched.
        let content = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let second_to_last = line_hash(lines[lines.len() - 2]).unwrap();
        write_head(
            &log,
            &HeadReceipt {
                head_hash: second_to_last,
                count: (lines.len() - 1) as u64,
                signing_enabled: false,
                sig: None,
            },
        )
        .expect("rewrite head receipt");

        let report = verify_audit_log(&log, None);
        assert!(
            report.ok,
            "a head one entry behind is the crash window and must verify ok: {:?}",
            report.problems
        );
        assert!(
            report.head_status.contains("one entry behind"),
            "head_status should flag the crash window: {}",
            report.head_status
        );
    }

    #[cfg(unix)]
    #[test]
    fn audit_verify_head_two_behind_is_truncation() {
        // A head pointing at NEITHER the last nor the second-to-last line is not
        // the crash window; it is treated as a possible truncation (the n-2 arm
        // must not over-tolerate). Pins the boundary between the n-2 arm and else.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("TIRITH_LOG", "1") };
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        append_chain(&log, &["Allow", "Block", "Warn"]);

        // Point the head at a hash matching no current line.
        write_head(
            &log,
            &HeadReceipt {
                head_hash: "f00dfeed".repeat(8),
                count: 1,
                signing_enabled: false,
                sig: None,
            },
        )
        .expect("rewrite head receipt");

        let report = verify_audit_log(&log, None);
        assert!(!report.ok, "a head matching no line must fail verification");
        assert!(
            report.head_status.contains("truncation"),
            "head_status should flag possible truncation: {}",
            report.head_status
        );
    }

    #[cfg(unix)]
    #[test]
    fn audit_verify_head_count_mismatch_fails() {
        // F3: a receipt whose head_hash MATCHES the current tail but whose `count`
        // is wrong (a stale/rewritten receipt reusing an old hash) must be rejected
        // with a clear count-mismatch status, not silently accepted.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("TIRITH_LOG", "1") };
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        append_chain(&log, &["Allow", "Block", "Warn"]);

        // Recompute the REAL tail hash, then write a head with that exact hash but
        // a deliberately wrong count (the tail is intact, only the count lies).
        let content = std::fs::read_to_string(&log).unwrap();
        let last = content.lines().last().unwrap();
        let real_tail = line_hash(last).unwrap();
        write_head(
            &log,
            &HeadReceipt {
                head_hash: real_tail,
                count: 99, // wrong: the log has 3 lines
                signing_enabled: false,
                sig: None,
            },
        )
        .expect("rewrite head receipt");

        let report = verify_audit_log(&log, None);
        assert!(
            !report.ok,
            "a head with the right tail hash but a wrong count must fail"
        );
        assert!(
            report.head_status.contains("count mismatch"),
            "head_status should flag a count mismatch: {}",
            report.head_status
        );
        assert!(
            report.problems.iter().any(|p| p.contains("count mismatch")),
            "a count-mismatch problem must be reported: {:?}",
            report.problems
        );
    }

    #[cfg(unix)]
    #[test]
    fn audit_signature_strip_is_detected_as_downgrade() {
        // With signing enabled, an attacker who strips `sig` from a signed entry
        // leaves the chain intact (the chain hash excludes `sig`) and the line
        // becomes byte-identical to an unsigned one. The head receipt's
        // signing_enabled flag makes the downgrade detectable.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config");
        std::fs::create_dir_all(cfg.join("tirith")).unwrap();
        // Deterministic ed25519 keypair from fixed secret bytes.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        write_signing_key(
            &cfg.join("tirith").join("audit-signing.key"),
            &sk.to_bytes(),
        );
        std::fs::write(cfg.join("tirith").join("audit-signing.pub"), vk.to_bytes()).unwrap();

        // SAFETY: serialized by TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("TIRITH_LOG", "1");
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
        }

        let result = std::panic::catch_unwind(|| {
            let log = dir.path().join("audit.jsonl");
            append_chain(&log, &["Allow", "Block", "Warn"]);

            // Sanity: signed + intact chain verifies clean and reports signing.
            let clean = verify_audit_log(&log, None);
            assert!(
                clean.ok,
                "a signed, intact chain must verify ok: {:?}",
                clean.problems
            );
            assert!(clean.signing_expected, "head must record signing enabled");
            assert!(clean.signed_lines >= 2, "chained lines were signed");

            // Strip `sig` from the LAST line, leaving the chain otherwise intact.
            let content = std::fs::read_to_string(&log).unwrap();
            let mut lines: Vec<String> = content.lines().map(String::from).collect();
            let last = lines.last_mut().unwrap();
            let mut v: serde_json::Value = serde_json::from_str(last).unwrap();
            assert!(
                v.get("sig").is_some(),
                "precondition: the last line was signed"
            );
            v.as_object_mut().unwrap().remove("sig");
            *last = serde_json::to_string(&v).unwrap();
            std::fs::write(&log, lines.join("\n") + "\n").unwrap();

            // The downgrade must now be detected.
            let report = verify_audit_log(&log, None);
            assert!(
                !report.ok,
                "stripping a signature on a signed log must fail verification"
            );
            assert!(
                report
                    .problems
                    .iter()
                    .any(|p| p.contains("signature downgrade")),
                "a signature-downgrade problem must be reported: {:?}",
                report.problems
            );
        });

        // SAFETY: serialized by TEST_ENV_LOCK; restore regardless of outcome.
        unsafe {
            std::env::remove_var("TIRITH_LOG");
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    #[cfg(unix)]
    #[test]
    fn audit_signed_head_signature_detects_signing_enabled_flip() {
        // F5: for a SIGNED log the head receipt is itself signed. Flipping
        // `head.signing_enabled` to false (the strip-all + head-rewrite downgrade)
        // invalidates the head signature, so verify must fail on "head signature
        // invalid". An intact signed log (with a signed head) verifies ok.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config");
        std::fs::create_dir_all(cfg.join("tirith")).unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(&[17u8; 32]);
        let vk = sk.verifying_key();
        write_signing_key(
            &cfg.join("tirith").join("audit-signing.key"),
            &sk.to_bytes(),
        );
        std::fs::write(cfg.join("tirith").join("audit-signing.pub"), vk.to_bytes()).unwrap();

        // SAFETY: serialized by TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("TIRITH_LOG", "1");
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
        }

        let result = std::panic::catch_unwind(|| {
            let log = dir.path().join("audit.jsonl");
            append_chain(&log, &["Allow", "Block", "Warn"]);

            // Intact signed log with a SIGNED head verifies clean.
            let clean = verify_audit_log(&log, None);
            assert!(
                clean.ok,
                "a signed, intact log with a signed head must verify ok: {:?}",
                clean.problems
            );
            assert!(clean.signing_expected, "signing must be expected");

            // The head sidecar must itself carry a `sig`.
            let hp = head_path(&log);
            let head_json = std::fs::read_to_string(&hp).unwrap();
            let mut head_val: serde_json::Value = serde_json::from_str(&head_json).unwrap();
            assert!(
                head_val.get("sig").and_then(|s| s.as_str()).is_some(),
                "a signed log's head receipt must carry its own signature: {head_json}"
            );

            // Flip `signing_enabled` to false WITHOUT re-signing (the attacker has
            // no private key). The lines stay signed, so `any_line_signed` keeps
            // signing_expected = true, and the head signature no longer matches the
            // tampered receipt body.
            head_val.as_object_mut().unwrap().insert(
                "signing_enabled".to_string(),
                serde_json::Value::Bool(false),
            );
            std::fs::write(&hp, serde_json::to_string(&head_val).unwrap()).unwrap();

            let report = verify_audit_log(&log, None);
            assert!(
                !report.ok,
                "flipping head.signing_enabled on a signed log must fail verification"
            );
            assert!(
                report
                    .problems
                    .iter()
                    .any(|p| p.contains("head signature invalid")),
                "a head-signature-invalid problem must be reported: {:?}",
                report.problems
            );
        });

        // SAFETY: serialized by TEST_ENV_LOCK; restore regardless of outcome.
        unsafe {
            std::env::remove_var("TIRITH_LOG");
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    #[cfg(unix)]
    #[test]
    fn audit_signed_log_without_pubkey_fails_closed() {
        // A signed log must NOT verify `ok` when no verifying key is available:
        // the signatures present were never checked, so the verifier cannot
        // authenticate the log. Reporting ok here would be a fail-open hole.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config");
        std::fs::create_dir_all(cfg.join("tirith")).unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        // Write ONLY the secret key (so appends sign) — deliberately NO pub key.
        write_signing_key(
            &cfg.join("tirith").join("audit-signing.key"),
            &sk.to_bytes(),
        );

        // SAFETY: serialized by TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("TIRITH_LOG", "1");
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
        }

        let result = std::panic::catch_unwind(|| {
            let log = dir.path().join("audit.jsonl");
            append_chain(&log, &["Allow", "Block", "Warn"]);

            let report = verify_audit_log(&log, None);
            assert!(
                report.signing_expected,
                "a log with signed lines must be treated as signing-expected"
            );
            assert!(
                !report.ok,
                "a signed log cannot verify ok without a verifying key"
            );
            assert!(
                report
                    .problems
                    .iter()
                    .any(|p| p.contains("no verifying key")),
                "a missing-verifying-key problem must be reported: {:?}",
                report.problems
            );
        });

        // SAFETY: serialized by TEST_ENV_LOCK; restore regardless of outcome.
        unsafe {
            std::env::remove_var("TIRITH_LOG");
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    #[cfg(unix)]
    #[test]
    fn audit_append_fails_when_signed_log_loses_its_key() {
        // Once a log is signed, an append that cannot sign (key removed) must
        // FAIL rather than silently write an unsigned line that verify cannot
        // distinguish from a stripped-signature attack.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config");
        std::fs::create_dir_all(cfg.join("tirith")).unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let key_path = cfg.join("tirith").join("audit-signing.key");
        write_signing_key(&key_path, &sk.to_bytes());

        // SAFETY: serialized by TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("TIRITH_LOG", "1");
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
        }

        let result = std::panic::catch_unwind(|| {
            let log = dir.path().join("audit.jsonl");
            // First append signs (key present) and records signing_enabled.
            let first = append_to_audit_log(&chain_test_entry("Allow"), Some(log.clone()));
            assert!(
                matches!(first, AuditWrite::Written(_)),
                "the first signed append must succeed"
            );

            // Remove the key, then append again: signing now fails, and because
            // the head receipt records signing_enabled, the write must FAIL.
            std::fs::remove_file(&key_path).unwrap();
            let second = append_to_audit_log(&chain_test_entry("Block"), Some(log.clone()));
            assert!(
                matches!(second, AuditWrite::Failed(_)),
                "an append that cannot sign a previously signed log must fail"
            );

            // The poisoned unsigned line must NOT have been written.
            let n = std::fs::read_to_string(&log).unwrap().lines().count();
            assert_eq!(n, 1, "the unsigned entry must not have been appended");
        });

        // SAFETY: serialized by TEST_ENV_LOCK; restore regardless of outcome.
        unsafe {
            std::env::remove_var("TIRITH_LOG");
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    #[cfg(unix)]
    #[test]
    fn audit_append_refuses_to_enable_signing_on_nonempty_unsigned_log() {
        // F4: switching signing ON mid-stream over a non-empty UNSIGNED log must
        // FAIL (and not append). Verification would otherwise expect every chained
        // line to be signed and flag the intact, legitimately-unsigned prior
        // entries as downgrades. The operator must rotate the log first.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config");
        std::fs::create_dir_all(cfg.join("tirith")).unwrap();
        let key_path = cfg.join("tirith").join("audit-signing.key");

        // SAFETY: serialized by TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("TIRITH_LOG", "1");
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
        }

        let result = std::panic::catch_unwind(|| {
            let log = dir.path().join("audit.jsonl");
            // Two UNSIGNED appends first (no key on disk yet).
            append_chain(&log, &["Allow", "Block"]);
            let before = std::fs::read_to_string(&log).unwrap();
            assert_eq!(before.lines().count(), 2, "two unsigned lines written");
            assert!(
                !before.lines().any(|l| l.contains("\"sig\"")),
                "the prior entries must be unsigned"
            );

            // Now plant a signing key and attempt a THIRD append: signing would
            // turn on over a non-empty unsigned log, which must be refused.
            let sk = ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]);
            write_signing_key(&key_path, &sk.to_bytes());
            let third = append_to_audit_log(&chain_test_entry("Warn"), Some(log.clone()));
            assert!(
                matches!(third, AuditWrite::Failed(_)),
                "enabling signing on a non-empty unsigned log must fail"
            );
            if let AuditWrite::Failed(reason) = &third {
                assert!(
                    reason.contains("rotate the log first"),
                    "the failure reason must explain rotation: {reason}"
                );
            }

            // No new line was appended.
            let after = std::fs::read_to_string(&log).unwrap();
            assert_eq!(
                after.lines().count(),
                2,
                "the refused append must not add a line"
            );
        });

        // SAFETY: serialized by TEST_ENV_LOCK; restore regardless of outcome.
        unsafe {
            std::env::remove_var("TIRITH_LOG");
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    #[cfg(unix)]
    #[test]
    fn audit_chain_concurrent_appends_stay_consistent() {
        // The exclusive fs2 lock must serialize concurrent in-process writers so
        // no interleave breaks a prev_hash. Spawn several threads each appending
        // a few entries to ONE log, then verify the chain and line count.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("TIRITH_LOG", "1") };
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");

        const THREADS: usize = 8;
        const PER_THREAD: usize = 4;
        std::thread::scope(|scope| {
            for t in 0..THREADS {
                let log = log.clone();
                scope.spawn(move || {
                    for i in 0..PER_THREAD {
                        let _ = append_to_audit_log(
                            &chain_test_entry(&format!("t{t}-{i}")),
                            Some(log.clone()),
                        );
                    }
                });
            }
        });

        let total = std::fs::read_to_string(&log).unwrap().lines().count();
        assert_eq!(total, THREADS * PER_THREAD, "every append must land");
        let report = verify_audit_log(&log, None);
        assert!(
            report.ok,
            "concurrent appends must produce an unbroken chain: {:?}",
            report.problems
        );
        // Genesis line is unchained; every subsequent line is chained.
        assert_eq!(report.chained_lines, THREADS * PER_THREAD - 1);
    }

    #[cfg(unix)]
    #[test]
    fn audit_genesis_signature_is_authenticated_and_counted() {
        // F1: the genesis/first signed entry carries a `sig` but NO `prev_hash`.
        // Signature verification (and signed_lines counting) must run for it too;
        // the prior bug only verified inside the `prev_hash` branch, so a tampered
        // signature on a single-line log went unauthenticated and uncounted.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config");
        std::fs::create_dir_all(cfg.join("tirith")).unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(&[13u8; 32]);
        let vk = sk.verifying_key();
        write_signing_key(
            &cfg.join("tirith").join("audit-signing.key"),
            &sk.to_bytes(),
        );
        std::fs::write(cfg.join("tirith").join("audit-signing.pub"), vk.to_bytes()).unwrap();

        // SAFETY: serialized by TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("TIRITH_LOG", "1");
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
        }

        let result = std::panic::catch_unwind(|| {
            let log = dir.path().join("audit.jsonl");
            // A SINGLE signed entry: it is the genesis (no prev_hash) but signed.
            append_chain(&log, &["Allow"]);
            let content = std::fs::read_to_string(&log).unwrap();
            let lines: Vec<&str> = content.lines().collect();
            assert_eq!(lines.len(), 1, "single-line log");
            assert!(
                !lines[0].contains("prev_hash"),
                "the only line is the genesis (no prev_hash)"
            );

            // Intact single signed line: verifies ok AND counts the genesis sig.
            let clean = verify_audit_log(&log, None);
            assert!(
                clean.ok,
                "an intact single signed entry must verify ok: {:?}",
                clean.problems
            );
            assert_eq!(
                clean.signed_lines, 1,
                "the genesis signed line must be counted in signed_lines"
            );

            // Replace the genesis `sig` with a structurally valid but WRONG
            // signature (64 zero bytes, base64). `sig` is excluded from the chain
            // hash, so the head receipt still matches; only signature verification
            // can catch this. The prior bug never verified the genesis, so it
            // passed — now it must fail.
            let mut v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
            assert!(
                v.get("sig").is_some(),
                "precondition: the genesis was signed"
            );
            let bogus = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
            v.as_object_mut()
                .unwrap()
                .insert("sig".to_string(), serde_json::Value::String(bogus));
            std::fs::write(&log, serde_json::to_string(&v).unwrap() + "\n").unwrap();

            let report = verify_audit_log(&log, None);
            assert!(
                !report.ok,
                "a tampered genesis signature must fail verification"
            );
            assert!(
                report
                    .problems
                    .iter()
                    .any(|p| p.contains("signature verification failed")),
                "a signature-verification-failed problem must be reported: {:?}",
                report.problems
            );
            assert_eq!(
                report.signed_lines, 1,
                "the genesis line still carries a sig and must be counted"
            );
        });

        // SAFETY: serialized by TEST_ENV_LOCK; restore regardless of outcome.
        unsafe {
            std::env::remove_var("TIRITH_LOG");
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    #[cfg(unix)]
    #[test]
    fn audit_genesis_signature_strip_is_detected_as_downgrade() {
        // A4: stripping `sig` from the FIRST (genesis/root) entry of a signed log,
        // while LATER lines stay signed, must be flagged as a signature downgrade.
        // The genesis has no `prev_hash` (it is unchained), so a downgrade check
        // gated on `is_chained` would miss it and reopen the bypass on the first
        // entry. The check now fires whenever signing is expected and a sig is
        // absent, regardless of chaining.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config");
        std::fs::create_dir_all(cfg.join("tirith")).unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]);
        let vk = sk.verifying_key();
        write_signing_key(
            &cfg.join("tirith").join("audit-signing.key"),
            &sk.to_bytes(),
        );
        std::fs::write(cfg.join("tirith").join("audit-signing.pub"), vk.to_bytes()).unwrap();

        // SAFETY: serialized by TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("TIRITH_LOG", "1");
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
        }

        let result = std::panic::catch_unwind(|| {
            let log = dir.path().join("audit.jsonl");
            // Three signed entries: line 1 is the genesis (no prev_hash), lines 2-3
            // are chained. All are signed.
            append_chain(&log, &["Allow", "Block", "Warn"]);

            let clean = verify_audit_log(&log, None);
            assert!(
                clean.ok,
                "a signed, intact chain must verify ok: {:?}",
                clean.problems
            );
            assert!(clean.signing_expected, "signing must be expected");

            // Strip `sig` from the FIRST line only, leaving lines 2-3 signed and the
            // chain otherwise intact. `any_line_signed` keeps signing_expected true.
            let content = std::fs::read_to_string(&log).unwrap();
            let mut lines: Vec<String> = content.lines().map(String::from).collect();
            assert!(lines.len() >= 3, "expected at least three lines");
            assert!(
                !lines[0].contains("prev_hash"),
                "line 1 is the genesis (no prev_hash)"
            );
            let mut v: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
            assert!(
                v.get("sig").is_some(),
                "precondition: the genesis line was signed"
            );
            v.as_object_mut().unwrap().remove("sig");
            lines[0] = serde_json::to_string(&v).unwrap();
            std::fs::write(&log, lines.join("\n") + "\n").unwrap();

            let report = verify_audit_log(&log, None);
            assert!(
                !report.ok,
                "stripping the genesis signature on a signed log must fail verification"
            );
            assert!(
                report
                    .problems
                    .iter()
                    .any(|p| { p.contains("line 1") && p.contains("signature downgrade") }),
                "a genesis signature-downgrade problem must be reported for line 1: {:?}",
                report.problems
            );
        });

        // SAFETY: serialized by TEST_ENV_LOCK; restore regardless of outcome.
        unsafe {
            std::env::remove_var("TIRITH_LOG");
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    #[cfg(unix)]
    #[test]
    fn audit_missing_head_on_chained_log_fails_closed() {
        // F11: deleting the `.head` sidecar of an existing CHAINED log must NOT
        // pass verification (truncation could no longer be ruled out). It stays
        // verifiable only via an explicit out-of-band --expected-head anchor.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("TIRITH_LOG", "1") };
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        append_chain(&log, &["Allow", "Block", "Warn"]);

        // Sanity: with the sidecar present the chain verifies ok.
        assert!(
            verify_audit_log(&log, None).ok,
            "intact chained log with head receipt must verify ok"
        );

        // Delete the head sidecar (an attacker removing the truncation anchor).
        std::fs::remove_file(head_path(&log)).expect("remove head sidecar");

        let report = verify_audit_log(&log, None);
        assert!(
            !report.ok,
            "a chained log with a missing head sidecar must fail closed"
        );
        assert!(
            report
                .problems
                .iter()
                .any(|p| p.contains("no head receipt") || p.contains("missing sidecar")),
            "the missing-sidecar problem must be reported: {:?}",
            report.problems
        );

        // The operator can still verify out-of-band with --expected-head.
        let content = std::fs::read_to_string(&log).unwrap();
        let last = content.lines().last().unwrap();
        let head = line_hash(last).unwrap();
        assert!(
            verify_audit_log(&log, Some(&head)).ok,
            "an explicit --expected-head anchor must restore tolerance for a missing sidecar"
        );
        // A WRONG expected-head still fails.
        assert!(
            !verify_audit_log(&log, Some("deadbeef")).ok,
            "a wrong --expected-head must still fail"
        );
    }

    #[cfg(unix)]
    #[test]
    fn audit_missing_head_on_signed_single_entry_log_fails_closed() {
        // C3: a SIGNED log whose ONLY retained entry is the genesis line has
        // `signing_expected = true` but `chained_lines = 0`. Deleting its `.head`
        // sidecar must STILL fail closed (no --expected-head): the receipt is what
        // binds `signing_enabled`, so dropping it makes a truncation-to-empty of a
        // signed log unverifiable. The prior gate (`chained_lines > 0`) missed this.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("cfg");
        std::fs::create_dir_all(cfg.join("tirith")).unwrap();
        // Deterministic ed25519 keypair so signing AND verifying are configured.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
        let vk = sk.verifying_key();
        write_signing_key(
            &cfg.join("tirith").join("audit-signing.key"),
            &sk.to_bytes(),
        );
        std::fs::write(cfg.join("tirith").join("audit-signing.pub"), vk.to_bytes()).unwrap();

        // SAFETY: serialized by TEST_ENV_LOCK across all modules.
        unsafe {
            std::env::set_var("TIRITH_LOG", "1");
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
        }

        let result = std::panic::catch_unwind(|| {
            let log = dir.path().join("audit.jsonl");
            // ONE signed entry: the genesis (no prev_hash), signed.
            append_chain(&log, &["Allow"]);

            // Precondition: exactly one line, signed, and it verifies ok with its
            // sidecar present.
            let content = std::fs::read_to_string(&log).unwrap();
            assert_eq!(content.lines().count(), 1, "exactly one entry");
            let clean = verify_audit_log(&log, None);
            assert!(
                clean.ok,
                "a signed single-entry log with its head must verify ok: {:?}",
                clean.problems
            );
            assert!(clean.signing_expected, "signing must be expected");
            assert_eq!(clean.chained_lines, 0, "the lone genesis is not chained");

            // Remove the head sidecar (an attacker dropping the signed receipt).
            std::fs::remove_file(head_path(&log)).expect("remove head sidecar");

            let report = verify_audit_log(&log, None);
            assert!(
                !report.ok,
                "a signed single-entry log with a missing head sidecar must fail closed"
            );
            assert!(
                report
                    .problems
                    .iter()
                    .any(|p| p.contains("no head receipt") || p.contains("missing sidecar")),
                "the missing-sidecar problem must be reported: {:?}",
                report.problems
            );

            // An explicit --expected-head anchor still restores tolerance.
            let last = content.lines().last().unwrap();
            let head = line_hash(last).unwrap();
            assert!(
                verify_audit_log(&log, Some(&head)).ok,
                "an explicit --expected-head anchor must restore tolerance"
            );
        });

        // SAFETY: serialized by TEST_ENV_LOCK; restore regardless of outcome.
        unsafe {
            std::env::remove_var("TIRITH_LOG");
            std::env::remove_var("XDG_CONFIG_HOME");
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    #[cfg(unix)]
    #[test]
    fn audit_missing_head_on_legacy_log_stays_tolerant() {
        // F11 boundary: a purely LEGACY/unchained log (no prev_hash entries) has
        // no truncation anchor by design, so a missing head sidecar must remain
        // tolerant (ok stays true). Only chained logs fail closed.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("audit.jsonl");
        // Write two legacy lines (no prev_hash, no head sidecar) directly.
        std::fs::write(
            &log,
            "{\"timestamp\":\"t1\",\"action\":\"Allow\"}\n\
             {\"timestamp\":\"t2\",\"action\":\"Block\"}\n",
        )
        .unwrap();

        let report = verify_audit_log(&log, None);
        assert!(
            report.ok,
            "a purely legacy log with no head sidecar must stay tolerant: {:?}",
            report.problems
        );
        assert_eq!(report.chained_lines, 0, "no chained lines");
        assert_eq!(report.legacy_prefix, 2, "both lines are legacy");
    }

    /// G1: the streaming `count_lines` returns the same newline count as the old
    /// slurping implementation for the boundary cases (missing, empty, trailing
    /// newline, no trailing newline, a span larger than one read chunk).
    #[test]
    fn count_lines_streams_with_identical_semantics() {
        let dir = tempfile::tempdir().unwrap();

        // Missing file -> 0.
        let missing = dir.path().join("nope.jsonl");
        assert_eq!(count_lines(&missing), 0, "missing file counts 0");

        // Empty file -> 0.
        let empty = dir.path().join("empty.jsonl");
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(count_lines(&empty), 0, "empty file counts 0");

        // Three lines, trailing newline -> 3 newline bytes.
        let trailing = dir.path().join("trailing.jsonl");
        std::fs::write(&trailing, b"a\nb\nc\n").unwrap();
        assert_eq!(count_lines(&trailing), 3, "trailing newline counts 3");

        // Three visible lines, NO trailing newline -> 2 newline bytes (matches the
        // old fs::read behavior exactly: it counts bytes, not visible lines).
        let no_trailing = dir.path().join("no_trailing.jsonl");
        std::fs::write(&no_trailing, b"a\nb\nc").unwrap();
        assert_eq!(
            count_lines(&no_trailing),
            2,
            "no trailing newline counts newline bytes only"
        );

        // A file larger than one 64 KiB read chunk: 5000 lines must all be counted
        // across multiple reads.
        let big = dir.path().join("big.jsonl");
        let mut content = Vec::new();
        for i in 0..5000u32 {
            content.extend_from_slice(format!("line-{i}-padding-padding-padding\n").as_bytes());
        }
        std::fs::write(&big, &content).unwrap();
        assert_eq!(
            count_lines(&big),
            5000,
            "lines spanning multiple read chunks must all be counted"
        );
    }

    /// G3: a group/other-readable signing key is refused (signing unavailable), a
    /// 0600 key owned by the current user is accepted. Unix-only because the
    /// permission model is unix-specific.
    #[cfg(unix)]
    #[test]
    fn signing_key_permissions_are_enforced() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let cfg_home = dir.path().join("config");
        // config_dir() resolves to <XDG_CONFIG_HOME>/tirith on unix (etcetera base
        // strategy), so point it at our temp dir.
        unsafe { std::env::set_var("XDG_CONFIG_HOME", &cfg_home) };

        let key_dir = cfg_home.join("tirith");
        std::fs::create_dir_all(&key_dir).unwrap();
        let key_path = key_dir.join("audit-signing.key");
        std::fs::write(&key_path, [7u8; 32]).unwrap();

        // 0644 (group/other readable) must be refused -> None.
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            audit_signing_secret().is_none(),
            "a world/group-readable signing key must be refused"
        );

        // 0600 (owner-only) must be accepted -> Some(32 bytes).
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let secret = audit_signing_secret();
        assert!(
            secret.is_some(),
            "a 0600 owner-only signing key must be accepted"
        );
        assert_eq!(
            secret.unwrap(),
            [7u8; 32],
            "the 32-byte secret must round-trip"
        );

        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
    }
}
