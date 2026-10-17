//! The audit verifier over a caller-retained, already-locked log handle.
//! Both normal verification and retention use this exact implementation.
use super::*;

pub(super) fn verify_open_audit_log(
    log_file: &fs::File,
    head: Option<HeadReceipt>,
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
    match log_file.metadata() {
        Ok(metadata) if metadata.len() <= MAX_AUDIT_LOG_BYTES => {}
        Ok(_) => {
            fail_audit_problem(&mut report, "audit log exceeds verification byte limit");
            return report;
        }
        Err(error) => {
            fail_audit_problem(
                &mut report,
                format!("cannot stat retained audit log: {error}"),
            );
            return report;
        }
    }
    let verify_key = audit_verify_key();

    // Stream the log instead of slurping it into a String + Vec<&str> + Vec<String>
    // of per-line hashes: a large log.jsonl would otherwise burn memory proportional
    // to the file size (and worse, to the 64-hex hash strings). Verification only
    // needs ROLLING state: the previous line's hash (for the chain link), the line
    // BEFORE it (for the head one-behind crash-window check), the running counts,
    // and whether any line is signed. So we keep just `prev_hash` / `prev_prev_hash`
    // and scalar counters here, not the whole file.
    use std::io::Read as _;
    // `Take` limits actual reads to one byte past the accepted ceiling, while
    // `remaining_log_bytes` prevents even that sentinel byte entering a line.
    // This stays bounded if a writer that ignores the advisory lock grows the
    // inode after the metadata check above.
    let limited_log = log_file.take(MAX_AUDIT_LOG_BYTES + 1);
    let mut reader = std::io::BufReader::new(limited_log);
    let mut remaining_log_bytes = MAX_AUDIT_LOG_BYTES;
    let mut chaining_started = false;
    // Rolling tail hashes: `prev_hash` is line (i-1)'s hash, `prev_prev_hash` is
    // line (i-2)'s. These replace the old `hashes[i-1]` / `hashes[n-1]` / `hashes[n-2]`
    // indexing. `last_hash`/`second_last_hash` snapshot the final tail for the head
    // and `--expected-head` checks after the loop.
    let mut prev_hash = String::new();
    let mut prev_prev_hash = String::new();
    // "Signatures required" must NOT rest solely on the mutable `<log>.head` sidecar:
    // an attacker could strip every `sig` AND rewrite the receipt to `signing_enabled:
    // false`. So anchor the signal in the (hash-chained) log data too: if ANY retained
    // line still carries a `sig`, signing was enabled and every entry is expected to be
    // signed. Signing configuration is also a local monotonic-mode anchor: if the
    // key/public-key path remains, removing the only line signature and `.head`
    // cannot make verification silently reinterpret the log as unsigned.
    // Because a signed log signs from its genesis (signing cannot be enabled mid-stream
    // over a non-empty log), the realistic case flips on line 0. The ONLY way a signed
    // line appears after unsigned ones is a tampered log whose earlier `sig`s were
    // stripped. Track only a count/range for leading unsigned entries; retaining
    // every line number made this otherwise-streaming verifier linear-space.
    let mut signing_expected =
        head.as_ref().map(|h| h.signing_enabled).unwrap_or(false) || audit_signing_configured();
    let mut early_unsigned_count = 0usize;
    let mut early_unsigned_first = 0usize;
    let mut early_unsigned_last = 0usize;
    let mut i = 0usize;
    let mut physical_lines = 0usize;

    loop {
        let line = match read_bounded_audit_line(
            &mut reader,
            MAX_AUDIT_LINE_BYTES,
            &mut remaining_log_bytes,
        ) {
            Ok(BoundedAuditLine::Eof) => break,
            Ok(BoundedAuditLine::Line(line)) => {
                if physical_lines >= MAX_AUDIT_LOG_LINES {
                    report.total_lines = i;
                    report.signing_expected = signing_expected;
                    fail_audit_problem(
                        &mut report,
                        format!(
                            "audit log exceeds the {} physical-line verification limit",
                            MAX_AUDIT_LOG_LINES
                        ),
                    );
                    return report;
                }
                physical_lines += 1;
                line
            }
            Ok(BoundedAuditLine::TooLong) => {
                if physical_lines >= MAX_AUDIT_LOG_LINES {
                    report.total_lines = i;
                    report.signing_expected = signing_expected;
                    fail_audit_problem(
                        &mut report,
                        format!(
                            "audit log exceeds the {} physical-line verification limit",
                            MAX_AUDIT_LOG_LINES
                        ),
                    );
                    return report;
                }
                physical_lines += 1;
                fail_audit_problem(
                    &mut report,
                    format!(
                        "line {}: exceeds the {} byte limit",
                        i + 1,
                        MAX_AUDIT_LINE_BYTES
                    ),
                );
                prev_prev_hash = std::mem::take(&mut prev_hash);
                i += 1;
                continue;
            }
            Ok(BoundedAuditLine::TotalLimit) => {
                report.total_lines = i;
                report.signing_expected = signing_expected;
                fail_audit_problem(
                    &mut report,
                    format!(
                        "audit log exceeds the {} byte verification limit during read",
                        MAX_AUDIT_LOG_BYTES
                    ),
                );
                return report;
            }
            Err(error) => {
                report.total_lines = i;
                report.signing_expected = signing_expected;
                fail_audit_problem(
                    &mut report,
                    format!("cannot read retained audit log: {error}"),
                );
                return report;
            }
        };
        if line.trim().is_empty() {
            continue;
        }

        let trimmed = line.trim();
        let val: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                fail_audit_problem(&mut report, format!("line {}: invalid JSON: {e}", i + 1));
                // An invalid line still occupies a chain slot, so its hash is the
                // empty string (as the old `hashes.push(String::new())` recorded),
                // breaking any chain link that points at it.
                prev_prev_hash = std::mem::take(&mut prev_hash);
                i += 1;
                continue;
            }
        };
        let prev = val.get("prev_hash").and_then(|v| v.as_str());
        let this_hash = line_hash(trimmed).unwrap_or_default();

        // The signature handling below runs for EVERY entry independent of whether
        // it carries `prev_hash` (is chained), so the genesis/first signed entry
        // (which has no `prev_hash`) is authenticated, counted, and downgrade-
        // checked just like a chained line.
        if let Some(prev) = prev {
            if !chaining_started && i > 0 && report.legacy_prefix > 0 && prev_hash == prev {
                // The immediately preceding unchained line is this chain's
                // genesis (its root), not a legacy entry, so it does not count
                // toward the legacy prefix.
                report.legacy_prefix -= 1;
            }
            chaining_started = true;
            report.chained_lines += 1;
            if i == 0 {
                fail_audit_problem(&mut report, "line 1: prev_hash present but no prior entry");
            } else if prev_hash != prev {
                fail_audit_problem(
                    &mut report,
                    format!("line {}: chain break (prev_hash mismatch)", i + 1),
                );
            }
        } else if !chaining_started {
            report.legacy_prefix += 1;
        } else {
            fail_audit_problem(
                &mut report,
                format!("line {}: missing prev_hash after the chain started", i + 1),
            );
        }

        // Signature handling, run for EVERY entry independent of `prev_hash`. The
        // genesis entry (no `prev_hash`) and every chained entry are each counted
        // in `signed_lines` and ed25519-verified when a public key is configured.
        // Verifying only inside the chained branch (the prior bug) left the first
        // signed entry unauthenticated and undercounted.
        let sig_present = val.get("sig").and_then(|v| v.as_str());
        if sig_present.is_some() {
            // A `sig` field is present (counted exactly as the old `is_some()` did,
            // including an empty `sig: ""`, which is counted but is NOT a real
            // signature). Only a NON-EMPTY sig anchors `signing_expected` (matching
            // the old `any_line_signed` pre-scan, which required `!s.is_empty()`).
            report.signed_lines += 1;
            if sig_present.map(|s| !s.is_empty()).unwrap_or(false) && !signing_expected {
                // First REAL signed line: signing IS expected. Aggregate earlier
                // unsigned entries as one bounded diagnostic; a signed line after
                // them means their `sig`s were stripped (e.g. a stripped genesis).
                signing_expected = true;
                if early_unsigned_count == 1 {
                    fail_audit_problem(
                        &mut report,
                        format!(
                            "line {early_unsigned_first}: missing signature on a signed log \
                             (possible signature downgrade)"
                        ),
                    );
                } else if early_unsigned_count > 1 {
                    fail_audit_problem(
                        &mut report,
                        format!(
                            "lines {early_unsigned_first}-{early_unsigned_last}: \
                             {early_unsigned_count} missing signatures on a signed log \
                             (possible signature downgrade)"
                        ),
                    );
                }
            }
        } else if signing_expected {
            // No `sig` field, but this log is signed (per the head receipt OR an
            // already-observed `sig`). Because `sig` is excluded from the chain hash,
            // stripping it leaves the chain intact and is otherwise invisible, so flag
            // it as a signature downgrade. This runs for EVERY entry, NOT just chained
            // ones: a signed log signs from its genesis, so stripping `sig` from the
            // FIRST (genesis/root) entry is just as much a downgrade as from a later
            // line.
            fail_audit_problem(
                &mut report,
                format!(
                    "line {}: missing signature on a signed log (possible signature downgrade)",
                    i + 1
                ),
            );
        } else {
            // No `sig` field while signing is NOT YET known to be expected (head says
            // unsigned and no real signed line seen yet). Buffer its number: if a
            // signed line appears later it is retroactively flagged above; otherwise
            // the log is genuinely unsigned and the counters are discarded.
            if early_unsigned_count == 0 {
                early_unsigned_first = i + 1;
            }
            early_unsigned_last = i + 1;
            early_unsigned_count = early_unsigned_count.saturating_add(1);
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
                fail_audit_problem(
                    &mut report,
                    format!("line {}: signature verification failed", i + 1),
                );
            }
        }
        // Advance the rolling tail: line i becomes the new "previous", and the old
        // "previous" becomes "previous-previous" (kept for the head one-behind check).
        prev_prev_hash = std::mem::replace(&mut prev_hash, this_hash);
        i += 1;
    }

    // Finalize the streamed state into the shape the post-loop checks expect.
    report.total_lines = i;
    report.signing_expected = signing_expected;
    // The final tail hashes (replacing the old `hashes[n-1]` / `hashes[n-2]`). After
    // the loop, `prev_hash` is the LAST line's hash and `prev_prev_hash` the one
    // before it; for n < 2 the unused one stays empty, matching the old `n > 1` guards.
    let last_hash = prev_hash;
    let second_last_hash = prev_prev_hash;
    let n = i;

    // Fail CLOSED when a signed log cannot actually be authenticated. If
    // signatures are expected (head receipt OR an observed `sig`) but no public
    // key (`audit-signing.pub`) is configured, the signatures present in the log
    // were never verified above, so we cannot vouch for the log. Reporting `ok`
    // here would let a signed log "pass" purely because the verifier lacks the
    // key — a fail-open hole. Require the key to be present to call it verified.
    if report.signing_expected && verify_key.is_none() {
        fail_audit_problem(
            &mut report,
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
    // signature. Continued key-path presence independently requires signed mode,
    // covering a stripped single-entry genesis plus deleted receipt.
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
                fail_audit_problem(
                    &mut report,
                    "head signature invalid (possible signing-state downgrade)",
                );
            }
        }
    }

    match head {
        Some(head) => {
            // The head `count` is the TOTAL number of log lines the receipt covers
            // (set as `prev_count + 1` in `write_head`, where `prev_count` starts
            // from `count_lines` over the whole file including any legacy-unchained
            // prefix). So a clean tail must match BOTH the tail hash AND the line
            // count: a stale/rewritten receipt that reuses an old hash but reports
            // the wrong count is otherwise accepted, hiding a rollback/replace.
            // `last_hash` is the streamed equivalent of the old `hashes[n - 1]`.
            if n > 0 && head.head_hash == last_hash {
                if head.count == n as u64 {
                    report.head_status = format!("head receipt OK (count {})", head.count);
                } else {
                    report.head_status = format!(
                        "head receipt count mismatch: expected {n}, got {}",
                        head.count
                    );
                    let problem = report.head_status.clone();
                    fail_audit_problem(&mut report, problem);
                }
            } else if n > 1 && head.head_hash == second_last_hash {
                // The documented crash window: the last line synced but the receipt
                // still points one entry back, so its count must be exactly n - 1.
                if head.count == (n - 1) as u64 {
                    report.head_status =
                        "head receipt is one entry behind (crash window); acceptable".to_string();
                } else {
                    report.head_status = format!(
                        "head receipt count mismatch: expected {}, got {}",
                        n - 1,
                        head.count
                    );
                    let problem = report.head_status.clone();
                    fail_audit_problem(&mut report, problem);
                }
            } else {
                report.head_status =
                    "head receipt does not match log tail (possible truncation)".to_string();
                let problem = report.head_status.clone();
                fail_audit_problem(&mut report, problem);
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
                report.head_status =
                    "no head receipt for a signed/chained log (missing sidecar; truncation cannot \
                     be ruled out; pass --expected-head to verify out-of-band)"
                        .to_string();
                let problem = report.head_status.clone();
                fail_audit_problem(&mut report, problem);
            } else {
                report.head_status = "no head receipt (truncation cannot be detected)".to_string();
            }
        }
    }

    if let Some(exp) = expected_head {
        // `last_hash` is the streamed tail hash (old `hashes[n - 1]`).
        if n == 0 || last_hash != exp {
            fail_audit_problem(
                &mut report,
                "expected-head does not match the computed tail hash",
            );
        }
    }

    report
}
