//! Safe-command suggestions — concrete "what to run instead" rewrites.
//!
//! This module is the engine behind `tirith check --suggest-safe-command`. It
//! is **purely advisory** and never influences detection, verdicts, or exit
//! codes — it inspects an already-computed [`Verdict`] plus the original
//! command and, *only where a transformation is genuinely safer and correct*,
//! emits a concrete rewritten command.
//!
//! ## Design rule: a wrong suggestion is worse than none
//!
//! Every rewrite here must be mechanically correct and actually safer than the
//! input. Where there is no safe mechanical rewrite of the literal command
//! (homograph hostnames, archive extraction targets, dotfile writes, threat-DB
//! hits, …), this module returns *no rewrite* — the caller falls back to the
//! per-rule remediation text from [`crate::rule_explanations::remediation`],
//! which is honest guidance rather than a fabricated command.
//!
//! Three transformations are supported, each provably safe:
//!
//! 1. **Pipe-to-shell** (`curl URL | bash`) → download to a file, review it,
//!    then run it. Covers `curl`/`wget`/`http`/`https`/`xh`/`fetch` piped into
//!    a shell interpreter.
//! 2. **Insecure TLS flag** (`-k`, `--insecure`, `--no-check-certificate`) →
//!    drop the flag so certificate verification is restored. The command still
//!    works whenever the server presents a valid certificate.
//! 3. **Plain HTTP to a sink** (`http://…`) → switch the scheme to `https://`.
//!    Suggested with an explicit "verify the host serves HTTPS" caveat.

use crate::tokenize::{self, ShellType};
use crate::verdict::{Finding, RuleId, Verdict};

/// A single safe-command suggestion tied to one finding.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SafeSuggestion {
    /// The rule this suggestion addresses (snake_case, e.g. `curl_pipe_shell`).
    pub rule_id: String,
    /// A concrete safer command, when a correct mechanical rewrite exists.
    /// `None` means there is no safe rewrite of the literal command — the
    /// `remediation` field below carries honest guidance instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_command: Option<String>,
    /// One-line explanation of why the suggestion is safer, or — when
    /// `safe_command` is `None` — why no mechanical rewrite is possible.
    pub rationale: String,
    /// The per-rule remediation advice (always populated; never fabricated).
    pub remediation: String,
}

/// Build safe-command suggestions for every actionable finding in `verdict`.
///
/// `cmd` is the original command text and `shell` the shell it was checked
/// under. Returns one [`SafeSuggestion`] per finding, de-duplicated by rule id
/// (the same rule firing twice yields a single suggestion). Returns an empty
/// vec when the verdict has no findings.
pub fn suggest(cmd: &str, shell: ShellType, verdict: &Verdict) -> Vec<SafeSuggestion> {
    let segments = tokenize::tokenize(cmd, shell);
    let mut out: Vec<SafeSuggestion> = Vec::new();
    let mut seen: Vec<RuleId> = Vec::new();

    for finding in &verdict.findings {
        // One suggestion per rule id — compare the Copy enum, no allocation.
        if seen.contains(&finding.rule_id) {
            continue;
        }
        seen.push(finding.rule_id);
        out.push(build_suggestion(cmd, shell, &segments, finding));
    }
    out
}

fn build_suggestion(
    cmd: &str,
    shell: ShellType,
    segments: &[tokenize::Segment],
    finding: &Finding,
) -> SafeSuggestion {
    let remediation = crate::rule_explanations::remediation(finding.rule_id).to_string();
    let rule_id = finding.rule_id.to_string();

    let (safe_command, rationale) = match finding.rule_id {
        RuleId::CurlPipeShell
        | RuleId::WgetPipeShell
        | RuleId::HttpiePipeShell
        | RuleId::XhPipeShell
        | RuleId::PipeToInterpreter => match rewrite_pipe_to_shell(segments, shell) {
            Some(rewrite) => (
                Some(rewrite),
                "Downloads the script to a file you can review before running it, \
                 instead of executing it sight-unseen."
                    .to_string(),
            ),
            None => (
                None,
                "No safe one-line rewrite for this pipeline: capture the piped content \
                 to a file, review it, then run that file."
                    .to_string(),
            ),
        },
        RuleId::InsecureTlsFlags => match rewrite_drop_insecure_tls(cmd, segments) {
            Some(rewrite) => (
                Some(rewrite),
                "Drops the flag that disables TLS certificate verification, restoring \
                 protection against man-in-the-middle tampering."
                    .to_string(),
            ),
            None => (
                None,
                "Remove the insecure TLS flag (-k / --insecure / --no-check-certificate) \
                 so the certificate is verified."
                    .to_string(),
            ),
        },
        RuleId::PlainHttpToSink => match rewrite_http_to_https(cmd) {
            Some(rewrite) => (
                Some(rewrite),
                "Switches the URL to HTTPS so the download is encrypted and \
                 tamper-evident — verify the host actually serves HTTPS."
                    .to_string(),
            ),
            None => (
                None,
                "Fetch the URL over HTTPS instead of plain HTTP.".to_string(),
            ),
        },
        // Every other rule: no safe mechanical rewrite of the literal command.
        // Be honest — the remediation field carries the real guidance.
        _ => (
            None,
            "No automatic safe rewrite for this finding — see the remediation below.".to_string(),
        ),
    };

    SafeSuggestion {
        rule_id,
        safe_command,
        rationale,
        remediation,
    }
}

/// Shell interpreters a download can be piped into.
fn is_shell_interpreter(name: &str) -> bool {
    matches!(
        name,
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "fish" | "ash"
    )
}

/// Rewrite `<fetch> URL | <shell>` into a download-review-run sequence.
///
/// Returns `None` (no rewrite) unless the command is exactly a single pipe
/// from a recognized URL-fetch command into a shell interpreter, and exactly
/// one `http(s)` URL can be extracted from the fetch side. Anything more
/// complex (extra pipeline stages, redirections we don't model, no clear URL)
/// falls through to honest guidance rather than a possibly-wrong rewrite.
fn rewrite_pipe_to_shell(segments: &[tokenize::Segment], shell: ShellType) -> Option<String> {
    // Exactly two segments joined by a single pipe.
    if segments.len() != 2 {
        return None;
    }
    let source = &segments[0];
    let sink = &segments[1];
    match sink.preceding_separator.as_deref() {
        Some("|") | Some("|&") => {}
        _ => return None,
    }

    let source_cmd = base_command(source.command.as_deref()?, shell);
    let sink_cmd = base_command(sink.command.as_deref()?, shell);

    // Source must be a URL-fetch command; sink must be a shell.
    if !is_url_fetch_command(&source_cmd) {
        return None;
    }
    if !is_shell_interpreter(&sink_cmd) {
        return None;
    }

    // Need exactly one http(s) URL on the fetch side — ambiguity → no rewrite.
    let urls = extract_http_urls(&source.args);
    if urls.len() != 1 {
        return None;
    }
    let url = sanitize_for_display(&urls[0]);
    if url.is_empty() {
        return None;
    }

    // Concrete download-review-run sequence. `/tmp/tirith-review.sh` is a
    // stable, obvious scratch path; the user reviews, then runs explicitly.
    let fetch = match source_cmd.as_str() {
        "wget" => format!("wget -O /tmp/tirith-review.sh {url}"),
        // curl + httpie + xh: `-o`/`--output` style differs, but `curl` is the
        // safe, universally-available downloader to suggest here.
        _ => format!("curl -fsSL -o /tmp/tirith-review.sh {url}"),
    };
    Some(format!(
        "{fetch} && less /tmp/tirith-review.sh && {sink_cmd} /tmp/tirith-review.sh"
    ))
}

/// Remove insecure TLS flags from the command, preserving everything else
/// verbatim.
///
/// Works by byte-span splicing: it locates each maximal whitespace-delimited
/// run in the *original* string whose content (quotes stripped) is exactly an
/// insecure flag and removes that run plus one adjacent whitespace gap. An
/// insecure flag is itself a simple token — `-k` / `--insecure` /
/// `--no-check-certificate` never contains internal whitespace — so this is
/// exact: every other byte of the command, including quoted arguments with
/// spaces, is left untouched.
///
/// Returns `None` if no insecure flag is present, or if the segment-level view
/// (the same view the detector used) does not also see one — so an `-k` buried
/// inside an unrelated quoted string is never rewritten.
fn rewrite_drop_insecure_tls(cmd: &str, segments: &[tokenize::Segment]) -> Option<String> {
    const INSECURE: &[&str] = &["-k", "--insecure", "--no-check-certificate"];

    // Cross-check against the tokenizer: only rewrite when a real arg token is
    // an insecure flag, not when `-k` merely appears inside another argument.
    let detector_sees_it = segments.iter().any(|seg| {
        seg.args
            .iter()
            .any(|a| INSECURE.contains(&strip_quotes(a).as_str()))
    });
    if !detector_sees_it {
        return None;
    }

    // Collect byte spans of whitespace-delimited runs that are insecure flags.
    let bytes = cmd.as_bytes();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let run = &cmd[start..i];
        if INSECURE.contains(&strip_quotes(run).as_str()) {
            spans.push((start, i));
        }
    }
    if spans.is_empty() {
        return None;
    }

    // Rebuild the command, dropping each flagged span and the single space
    // that separated it from the preceding token (so `curl -k URL` collapses
    // cleanly to `curl URL`, not `curl  URL`).
    let mut out = String::with_capacity(cmd.len());
    let mut cursor = 0;
    for (start, end) in spans {
        // Copy everything up to the flag, trimming one trailing space.
        let mut keep_until = start;
        if keep_until > cursor && bytes[keep_until - 1].is_ascii_whitespace() {
            keep_until -= 1;
        }
        out.push_str(&cmd[cursor..keep_until]);
        cursor = end;
    }
    out.push_str(&cmd[cursor..]);
    let result = out.trim().to_string();
    if result.is_empty() || result == cmd.trim() {
        return None;
    }
    Some(result)
}

/// Rewrite the first `http://` URL in the command to `https://`.
///
/// Only rewrites a literal `http://` scheme; returns `None` if the command has
/// no plain-HTTP URL. The caller pairs this with an explicit caveat that the
/// host must actually serve HTTPS.
fn rewrite_http_to_https(cmd: &str) -> Option<String> {
    // Find a case-insensitive `http://` not immediately preceded by 's'
    // (so `https://` is never matched).
    let lower = cmd.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut idx = 0;
    while let Some(rel) = lower[idx..].find("http://") {
        let pos = idx + rel;
        let preceded_by_s = pos > 0 && (bytes[pos - 1] == b's' || bytes[pos - 1] == b'S');
        if !preceded_by_s {
            // Rewrite this occurrence: insert 's' after `http`.
            let mut rewritten = String::with_capacity(cmd.len() + 1);
            rewritten.push_str(&cmd[..pos + 4]); // up to and including "http"
            rewritten.push('s');
            rewritten.push_str(&cmd[pos + 4..]);
            return Some(rewritten);
        }
        idx = pos + 7;
    }
    None
}

// ── Shared helpers ──────────────────────────────────────────────────────────

/// URL-fetch command base names that piping into a shell is dangerous for.
fn is_url_fetch_command(cmd: &str) -> bool {
    matches!(cmd, "curl" | "wget" | "http" | "https" | "xh" | "fetch")
}

/// Strip one matched pair of surrounding quotes (`"` or `'`).
fn strip_quotes(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

/// Reduce a command token to its base name: strip a directory path and, for
/// PowerShell, a trailing `.exe`. Mirrors how the detector identifies commands.
fn base_command(cmd: &str, shell: ShellType) -> String {
    let stripped = strip_quotes(cmd);
    let base = stripped
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&stripped)
        .to_string();
    if shell == ShellType::PowerShell {
        base.strip_suffix(".exe")
            .or_else(|| base.strip_suffix(".EXE"))
            .unwrap_or(&base)
            .to_ascii_lowercase()
    } else {
        base
    }
}

/// Extract `http(s)://` URLs from command arguments, including `--flag=URL`.
fn extract_http_urls(args: &[String]) -> Vec<String> {
    let mut urls = Vec::new();
    for arg in args {
        let token = strip_quotes(arg.trim());
        if starts_with_http(&token) {
            urls.push(token);
            continue;
        }
        if let Some((_, val)) = token.split_once('=') {
            if starts_with_http(val) {
                urls.push(val.to_string());
            }
        }
    }
    urls
}

fn starts_with_http(s: &str) -> bool {
    let b = s.as_bytes();
    (b.len() >= 8 && b[..8].eq_ignore_ascii_case(b"https://"))
        || (b.len() >= 7 && b[..7].eq_ignore_ascii_case(b"http://"))
}

/// Strip ASCII control characters so a rewritten command echoed to the terminal
/// cannot smuggle ANSI escapes or newlines from a hostile URL.
fn sanitize_for_display(s: &str) -> String {
    s.chars().filter(|c| !c.is_ascii_control()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Action, Evidence, Severity, Timings};

    fn finding(rule_id: RuleId) -> Finding {
        Finding {
            rule_id,
            severity: Severity::High,
            title: "t".into(),
            description: "d".into(),
            evidence: vec![Evidence::Text { detail: "e".into() }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }
    }

    fn verdict_with(findings: Vec<Finding>) -> Verdict {
        Verdict::from_findings(findings, 3, Timings::default())
    }

    #[test]
    fn curl_pipe_bash_rewrites_to_download_review_run() {
        let cmd = "curl https://example.com/install.sh | bash";
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        assert_eq!(s.len(), 1);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert!(sc.contains("curl -fsSL -o /tmp/tirith-review.sh"), "{sc}");
        assert!(sc.contains("https://example.com/install.sh"), "{sc}");
        assert!(sc.contains("less /tmp/tirith-review.sh"), "{sc}");
        assert!(sc.ends_with("bash /tmp/tirith-review.sh"), "{sc}");
    }

    #[test]
    fn wget_pipe_sh_uses_wget_o_flag() {
        let cmd = "wget https://example.com/x.sh | sh";
        let v = verdict_with(vec![finding(RuleId::WgetPipeShell)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert!(sc.starts_with("wget -O /tmp/tirith-review.sh"), "{sc}");
        assert!(sc.ends_with("sh /tmp/tirith-review.sh"), "{sc}");
    }

    #[test]
    fn pipe_with_extra_stage_yields_no_rewrite() {
        // Three segments — too complex for a correct one-line rewrite.
        let cmd = "curl https://example.com/x.sh | tac | bash";
        let v = verdict_with(vec![finding(RuleId::PipeToInterpreter)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        assert_eq!(s.len(), 1);
        assert!(s[0].safe_command.is_none(), "{:?}", s[0].safe_command);
        // Remediation must still be present and non-empty.
        assert!(!s[0].remediation.is_empty());
    }

    #[test]
    fn pipe_with_two_urls_yields_no_rewrite() {
        let cmd = "curl https://a.example/x https://b.example/y | bash";
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        assert!(s[0].safe_command.is_none());
    }

    #[test]
    fn insecure_tls_flag_dropped() {
        let cmd = "curl -k https://example.com/install.sh";
        let v = verdict_with(vec![finding(RuleId::InsecureTlsFlags)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert_eq!(sc, "curl https://example.com/install.sh");
    }

    #[test]
    fn insecure_tls_long_flag_dropped() {
        let cmd = "wget --no-check-certificate https://example.com/x";
        let v = verdict_with(vec![finding(RuleId::InsecureTlsFlags)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert_eq!(sc, "wget https://example.com/x");
    }

    #[test]
    fn insecure_tls_drop_preserves_quoted_arg_with_spaces() {
        // Span-based deletion must not mangle a quoted argument containing
        // whitespace elsewhere in the command.
        let cmd = r#"curl -k --data "a b c" https://example.com/x"#;
        let v = verdict_with(vec![finding(RuleId::InsecureTlsFlags)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert_eq!(sc, r#"curl --data "a b c" https://example.com/x"#);
    }

    #[test]
    fn insecure_tls_drop_handles_flag_in_middle() {
        let cmd = "curl https://example.com/x -k -o out";
        let v = verdict_with(vec![finding(RuleId::InsecureTlsFlags)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert_eq!(sc, "curl https://example.com/x -o out");
    }

    #[test]
    fn insecure_tls_k_inside_quoted_string_not_rewritten() {
        // `-k` only appears inside a quoted data payload, not as a real flag.
        // The tokenizer cross-check must prevent a rewrite. (No InsecureTlsFlags
        // finding would fire here in practice; the suggestion for whatever rule
        // did fire must not fabricate a TLS rewrite.)
        let cmd = r#"curl --data "pass -k here" https://example.com/x"#;
        // Drive the TLS branch directly to prove the guard holds.
        let segs = tokenize::tokenize(cmd, ShellType::Posix);
        assert!(rewrite_drop_insecure_tls(cmd, &segs).is_none());
    }

    #[test]
    fn plain_http_rewritten_to_https() {
        let cmd = "curl http://example.com/install.sh | bash";
        // PlainHttpToSink finding present.
        let v = verdict_with(vec![finding(RuleId::PlainHttpToSink)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert!(sc.contains("https://example.com/install.sh"), "{sc}");
        assert!(!sc.contains("http://"), "{sc}");
    }

    #[test]
    fn https_url_not_double_rewritten() {
        // rewrite_http_to_https must never touch an already-https URL.
        assert!(rewrite_http_to_https("curl https://example.com/x").is_none());
    }

    #[test]
    fn homograph_finding_gets_no_rewrite_but_keeps_remediation() {
        let cmd = "curl https://xn--gthub-2o5f.com/x";
        let v = verdict_with(vec![finding(RuleId::ConfusableDomain)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        assert_eq!(s.len(), 1);
        assert!(s[0].safe_command.is_none());
        assert!(!s[0].remediation.is_empty());
        assert!(s[0].rationale.contains("remediation"));
    }

    #[test]
    fn duplicate_rule_ids_deduplicated() {
        let cmd = "curl https://example.com/x.sh | bash";
        let v = verdict_with(vec![
            finding(RuleId::CurlPipeShell),
            finding(RuleId::CurlPipeShell),
        ]);
        let s = suggest(cmd, ShellType::Posix, &v);
        assert_eq!(s.len(), 1, "same rule id must collapse to one suggestion");
    }

    #[test]
    fn no_findings_yields_no_suggestions() {
        let v = Verdict::allow_fast(1, Timings::default());
        assert!(suggest("ls", ShellType::Posix, &v).is_empty());
        assert_eq!(v.action, Action::Allow);
    }

    #[test]
    fn powershell_exe_suffix_stripped_for_interpreter_match() {
        // bash.exe piped under PowerShell must still be recognized.
        let cmd = "curl https://example.com/x.sh | bash.exe";
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let s = suggest(cmd, ShellType::PowerShell, &v);
        // base_command lowercases + strips .exe → "bash" recognized.
        assert!(s[0].safe_command.is_some(), "{:?}", s[0]);
    }

    #[test]
    fn every_suggestion_has_nonempty_remediation_and_rationale() {
        let cmd = "curl http://example.com/x.sh | bash";
        let v = verdict_with(vec![
            finding(RuleId::CurlPipeShell),
            finding(RuleId::PlainHttpToSink),
        ]);
        for s in suggest(cmd, ShellType::Posix, &v) {
            assert!(!s.remediation.is_empty(), "rule {}", s.rule_id);
            assert!(!s.rationale.is_empty(), "rule {}", s.rule_id);
        }
    }
}
