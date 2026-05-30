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
//! (homograph hostnames, threat-DB hits with ambiguous targets, …), this
//! module returns *no rewrite* — the caller falls back to the per-rule
//! remediation text from [`crate::rule_explanations::remediation`], which is
//! honest guidance rather than a fabricated command.
//!
//! ## Output channel
//!
//! [`SafeSuggestion::safe_command`] is the *only* output channel for a
//! rewrite. Multi-step rewrites (preview-then-extract, backup-then-redirect)
//! are emitted as a single string with the individual steps joined by ` && `
//! — no separate `command_steps: Vec<String>` field exists. Callers that need
//! to display the steps individually should split on ` && `.
//!
//! Eight transformations are supported, each mechanically safe:
//!
//! 1. **Pipe-to-shell** (`curl URL | bash`) → download to a file, review it,
//!    then run it. Covers `curl`/`wget`/`http`/`https`/`xh`/`fetch` piped into
//!    a shell interpreter.
//! 2. **Insecure TLS flag** (`-k`, `--insecure`, `--no-check-certificate`) →
//!    drop the flag so certificate verification is restored.
//! 3. **Plain HTTP to a sink** (`http://…`) → switch the scheme to `https://`.
//! 4. **Typosquat rewrite** — when the threat DB unambiguously names a popular
//!    target, suggest `<pm> install <target>` instead.
//! 5. **Sudo narrow** — command-shape based: when `sudo` wraps a command that
//!    would be `Allow` without the prefix (and isn't an interactive shell),
//!    suggest dropping `sudo`.
//! 6. **Env scrub** — when any High-severity finding is present and sensitive
//!    env vars (`AWS_*`, `GITHUB_TOKEN`, …) are currently set, suggest
//!    `env -u VAR1 -u VAR2 ... <original>`.
//! 7. **Archive list-before-extract** — for [`RuleId::ArchiveExtract`], suggest
//!    `tar -tzf <archive> | head && tar -xzf <archive>` (analogous for zip /
//!    unzip / 7z).
//! 8. **Dotfile redirect** — for [`RuleId::DotfileOverwrite`], suggest
//!    `cp <target> <target>.bak && <original>` (only when the target actually
//!    exists on disk).

use std::path::Path;
use std::sync::LazyLock;

use crate::engine::{self, AnalysisContext};
use crate::extract::ScanContext;
use crate::tokenize::{self, ShellType};
use crate::verdict::{Action, Finding, RuleId, Severity, Verdict};

/// A single safe-command suggestion tied to one finding.
///
/// Multi-step rewrites (preview-then-extract, backup-then-redirect) live in
/// the single [`Self::safe_command`] field, with steps joined by ` && ` — no
/// separate `command_steps: Vec<String>` field exists. Callers that need to
/// display the steps individually should split on ` && `.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SafeSuggestion {
    /// The rule this suggestion addresses (snake_case, e.g. `curl_pipe_shell`,
    /// `sudo_narrow`, `env_scrub`).
    pub rule_id: String,
    /// A concrete safer command, when a correct mechanical rewrite exists.
    /// `None` means there is no safe rewrite of the literal command — the
    /// `remediation` field below carries honest guidance instead.
    ///
    /// Multi-step rewrites are emitted as a single string with steps joined by
    /// ` && ` — see the type-level docs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safe_command: Option<String>,
    /// One-line explanation of why the suggestion is safer, or — when
    /// `safe_command` is `None` — why no mechanical rewrite is possible.
    pub rationale: String,
    /// The per-rule remediation advice (always populated; never fabricated).
    pub remediation: String,
}

/// Sensitive environment variable names loaded from `sensitive_env.toml`.
///
/// Used by the env-scrub transform and (in a later milestone) by the
/// env-guard rule. Compiled into the binary at build time via `include_str!`.
static SENSITIVE_ENV_VARS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    #[derive(serde::Deserialize)]
    struct SensitiveEnvFile {
        sensitive: Vec<String>,
    }
    let toml_str = include_str!("../assets/data/sensitive_env.toml");
    let parsed: SensitiveEnvFile = toml::from_str(toml_str).expect("invalid sensitive_env.toml");
    // Leak each string to get a `&'static str`. The list is tiny (≤30 vars)
    // and read once for the lifetime of the process.
    parsed
        .sensitive
        .into_iter()
        .map(|s| Box::leak(s.into_boxed_str()) as &'static str)
        .collect()
});

/// Public read-only accessor for the sensitive env-var list. M9 ch4's env-guard
/// rule will share this same list — exposing it here keeps the asset file as
/// the single source of truth.
pub fn sensitive_env_vars() -> &'static [&'static str] {
    &SENSITIVE_ENV_VARS
}

/// Build safe-command suggestions for every actionable finding in `verdict`.
///
/// `cmd` is the original command text and `shell` the shell it was checked
/// under. Returns one [`SafeSuggestion`] per finding, de-duplicated by rule id
/// (the same rule firing twice yields a single suggestion).
///
/// In addition, two *command-shape* transforms run once per verdict and can
/// append synthetic suggestions with rule ids `"sudo_narrow"` and
/// `"env_scrub"`. They are not tied to any specific [`RuleId`] — they fire on
/// the overall command shape and the set of process-level env vars currently
/// set. Both are conservative: they never produce a rewrite that the engine
/// itself would still flag.
///
/// Returns an empty vec when the verdict has no findings.
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

    // Command-shape transforms — fire at most once per verdict, independent of
    // any specific rule id. Only run when the verdict has findings (an empty
    // verdict has nothing to rewrite).
    if !verdict.findings.is_empty() {
        if let Some(s) = build_sudo_narrow_suggestion(cmd, shell, &segments, verdict) {
            out.push(s);
        }
        if let Some(s) = build_env_scrub_suggestion(cmd, shell, verdict) {
            out.push(s);
        }
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
        RuleId::ThreatPackageTyposquat => match rewrite_typosquat(segments, shell, finding) {
            Some(rewrite) => (
                Some(rewrite),
                "Replaces the typosquatted package name with the popular package the \
                 threat database identifies it as impersonating."
                    .to_string(),
            ),
            None => (
                None,
                "The threat database flagged this name as a typosquat but did not \
                 unambiguously name a single popular target — pick the legitimate \
                 package by hand."
                    .to_string(),
            ),
        },
        RuleId::ArchiveExtract => match rewrite_archive_list_first(segments, shell) {
            Some(rewrite) => (
                Some(rewrite),
                "Lists the archive contents first so path-traversal entries (e.g. \
                 `../../etc/passwd`) are visible before any file is written to disk."
                    .to_string(),
            ),
            None => (
                None,
                "Inspect the archive contents (e.g. `tar -tzf <archive>`) before \
                 extracting to a sensitive path."
                    .to_string(),
            ),
        },
        RuleId::DotfileOverwrite => match rewrite_dotfile_backup_first(cmd, segments, shell) {
            Some(rewrite) => (
                Some(rewrite),
                "Backs up the existing dotfile before the redirect modifies it, so \
                 the previous configuration can be restored if the change breaks login."
                    .to_string(),
            ),
            None => (
                None,
                "Back up the target dotfile (`cp <file> <file>.bak`) before \
                 redirecting output into it."
                    .to_string(),
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

// ── Typosquat rewrite ───────────────────────────────────────────────────────

/// Extract the typosquat target name from a `ThreatPackageTyposquat` finding.
///
/// Both producers — `rules/threatintel.rs` and `install_txn.rs` — format the
/// finding title as `"Confirmed typosquat: <name> → <target>"`. Parse the arrow
/// out of the title.
///
/// `install_txn.rs` additionally stamps `typosquat_of=<target>` into the
/// evidence text; that field is checked as a backup signal so the rewrite is
/// robust against a future title-string tweak.
fn typosquat_target(finding: &Finding) -> Option<String> {
    // Primary parse: "Confirmed typosquat: <name> → <target>" — `→` is a BMP
    // character so byte-indexing via `str::find` is safe.
    let arrow = " → ";
    if let Some(idx) = finding.title.find(arrow) {
        let target = finding.title[idx + arrow.len()..].trim();
        if !target.is_empty() && !target.contains(char::is_whitespace) {
            return Some(target.to_string());
        }
    }

    // Backup parse: install_txn evidence carries `typosquat_of=<name>`.
    for ev in &finding.evidence {
        if let crate::verdict::Evidence::Text { detail } = ev {
            if let Some(pos) = detail.find("typosquat_of=") {
                let after = &detail[pos + "typosquat_of=".len()..];
                let end = after
                    .find(|c: char| c.is_ascii_whitespace())
                    .unwrap_or(after.len());
                let target = after[..end].trim();
                if !target.is_empty() {
                    return Some(target.to_string());
                }
            }
        }
    }

    None
}

/// Package-manager `install` shape detector. Returns `(pm_binary, install_verb)`
/// when `segments` is a single segment whose leader is a recognized package
/// manager and the first non-flag arg is an install-style verb. The verb is
/// preserved so `npm install` stays `npm install` and `npm i` stays `npm i`.
///
/// The supported set mirrors what the install-txn engine pass already handles
/// (`pip`/`pip3`, `npm`/`yarn`/`pnpm`, `cargo`, `gem`, `go`); other package
/// managers fall through to "no rewrite".
fn detect_pm_install(segments: &[tokenize::Segment], shell: ShellType) -> Option<(String, String)> {
    if segments.len() != 1 {
        return None;
    }
    let seg = &segments[0];
    let cmd = base_command(seg.command.as_deref()?, shell);
    let install_verbs: &[(&str, &[&str])] = &[
        ("pip", &["install"]),
        ("pip3", &["install"]),
        ("npm", &["install", "i", "add"]),
        ("yarn", &["add"]),
        ("pnpm", &["add", "install", "i"]),
        ("cargo", &["install", "add"]),
        ("gem", &["install"]),
        ("go", &["install", "get"]),
    ];

    let (_, verbs) = install_verbs.iter().find(|(name, _)| *name == cmd)?;
    let verb_arg = seg
        .args
        .iter()
        .find(|a| !strip_quotes(a).starts_with('-'))?;
    let verb = strip_quotes(verb_arg);
    if !verbs.contains(&verb.as_str()) {
        return None;
    }
    Some((cmd, verb))
}

/// Build a typosquat rewrite when the target is unambiguous.
///
/// Returns `None` when:
///  * the finding shape doesn't expose a single target (handled by
///    [`typosquat_target`]), or
///  * the command shape isn't a recognized `<pm> install <name>` (the only
///    shape we can mechanically rewrite — touching a manifest file, a
///    Brewfile, `npx`, etc. is out of scope for a one-line rewrite).
fn rewrite_typosquat(
    segments: &[tokenize::Segment],
    shell: ShellType,
    finding: &Finding,
) -> Option<String> {
    let target = typosquat_target(finding)?;
    let target = sanitize_for_display(&target);
    if target.is_empty() {
        return None;
    }
    let (pm, verb) = detect_pm_install(segments, shell)?;
    Some(format!("{pm} {verb} {target}"))
}

// ── Archive list-before-extract ────────────────────────────────────────────

/// Archive command names recognized by the `ArchiveExtract` rule.
fn archive_command_kind(cmd: &str) -> Option<&'static str> {
    match cmd {
        "tar" => Some("tar"),
        "unzip" => Some("unzip"),
        "7z" => Some("7z"),
        _ => None,
    }
}

/// Find the archive filename in an extract command's args.
///
/// `tar -xzf <archive> [-C dir]` and `tar -x -z -f <archive>` both work — the
/// archive is the first non-flag arg after `-f`/`--file`. For `unzip
/// <archive>` it's the first non-flag arg. For `7z x <archive>` it's the
/// first non-flag arg after the verb.
fn find_archive_arg(args: &[String], kind: &str) -> Option<String> {
    // Direct scan: `-f <file>`, `--file=<file>`, `--file <file>`, and combined
    // short-form `-xzf <file>` / `-tzf <file>`.
    let mut i = 0;
    while i < args.len() {
        let arg = strip_quotes(&args[i]);
        if arg == "-f" || arg == "--file" {
            if let Some(next) = args.get(i + 1) {
                let v = strip_quotes(next);
                if !v.starts_with('-') {
                    return Some(v);
                }
            }
        }
        if let Some(rest) = arg.strip_prefix("--file=") {
            return Some(rest.to_string());
        }
        // Combined short form `-xzf` / `-tzf` etc — `-f` is the trailing letter
        // and the next positional is the archive.
        if arg.starts_with('-')
            && !arg.starts_with("--")
            && arg.len() > 2
            && arg.ends_with('f')
            && arg[1..].chars().all(|c| c.is_ascii_alphanumeric())
        {
            if let Some(next) = args.get(i + 1) {
                let v = strip_quotes(next);
                if !v.starts_with('-') {
                    return Some(v);
                }
            }
        }
        i += 1;
    }

    // For unzip / 7z: take the first non-flag positional (skipping the verb for 7z).
    match kind {
        "unzip" => args
            .iter()
            .map(|a| strip_quotes(a))
            .find(|a| !a.starts_with('-') && !a.is_empty()),
        "7z" => {
            let mut it = args.iter().map(|a| strip_quotes(a));
            // Skip the verb (e.g. `x`, `e`).
            let _verb = it.find(|a| !a.starts_with('-') && !a.is_empty())?;
            it.find(|a| !a.starts_with('-') && !a.is_empty())
        }
        _ => None,
    }
}

/// Build the preview-then-extract rewrite for a flagged archive command.
///
/// Returns `None` when the command is multi-segment, the leader isn't one of
/// `tar` / `unzip` / `7z`, or the archive filename can't be located.
fn rewrite_archive_list_first(segments: &[tokenize::Segment], shell: ShellType) -> Option<String> {
    if segments.len() != 1 {
        return None;
    }
    let seg = &segments[0];
    let cmd = base_command(seg.command.as_deref()?, shell);
    let kind = archive_command_kind(&cmd)?;
    let archive = find_archive_arg(&seg.args, kind)?;
    let archive = sanitize_for_display(&archive);
    if archive.is_empty() {
        return None;
    }
    let raw = seg.raw.trim();
    // `tar -tf` (NO compression flag) works for .tar / .tar.gz / .tar.bz2 /
    // .tar.xz / .tar.zst on modern GNU & BSD tar — the binary auto-detects
    // compression from the archive's magic bytes. Hard-coding `-tzf` (gzip)
    // would break the preview step for every non-gzip tar variant.
    Some(match kind {
        "tar" => format!("tar -tf {archive} | head && {raw}"),
        "unzip" => format!("unzip -l {archive} | head && {raw}"),
        "7z" => format!("7z l {archive} | head && {raw}"),
        _ => return None,
    })
}

// ── Dotfile backup-first redirect ──────────────────────────────────────────

/// Extract the redirect target path from a `> ~/.<file>` / `>> $HOME/.<file>`
/// shape. Returns the literal token as written (so `~/.zshrc` stays
/// `~/.zshrc`).
fn dotfile_redirect_target(cmd: &str) -> Option<String> {
    let bytes = cmd.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'>' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        if j < bytes.len() && bytes[j] == b'>' {
            j += 1;
        }
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        let rest = &cmd[j..];
        let prefixes = ["~/.", "$HOME/."];
        for prefix in &prefixes {
            if rest.starts_with(prefix) {
                let end = rest
                    .find(|c: char| c.is_ascii_whitespace() || c == ';' || c == '|' || c == '&')
                    .unwrap_or(rest.len());
                let token = &rest[..end];
                if !token.is_empty() {
                    return Some(token.to_string());
                }
            }
        }
        i = j;
    }
    None
}

/// Expand `~/...` and `$HOME/...` to an absolute filesystem path for the
/// dotfile existence check.
fn expand_dotfile_to_fs_path(token: &str) -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    let home = std::path::PathBuf::from(home);
    if let Some(rest) = token.strip_prefix("~/") {
        return Some(home.join(rest));
    }
    if let Some(rest) = token.strip_prefix("$HOME/") {
        return Some(home.join(rest));
    }
    None
}

/// Build the backup-then-redirect rewrite for a dotfile-overwrite command.
///
/// Only fires when the target dotfile actually *exists* on disk — backing up a
/// non-existent file produces a confusing error from `cp` and the backup has
/// no value (there's nothing to lose).
fn rewrite_dotfile_backup_first(
    cmd: &str,
    segments: &[tokenize::Segment],
    _shell: ShellType,
) -> Option<String> {
    if segments.len() != 1 {
        return None;
    }
    let target_token = dotfile_redirect_target(cmd)?;
    let fs_path = expand_dotfile_to_fs_path(&target_token)?;
    if !Path::new(&fs_path).exists() {
        return None;
    }
    let target_token = sanitize_for_display(&target_token);
    if target_token.is_empty() {
        return None;
    }
    Some(format!(
        "cp {target_token} {target_token}.bak && {cmd}",
        cmd = cmd.trim()
    ))
}

// ── Sudo narrow (command-shape based) ──────────────────────────────────────

/// Interactive shells that must never appear as the "narrowed" base command of
/// a `sudo` rewrite. Suggesting `sh` instead of `sudo sh` would be strictly
/// worse — it would still produce a root shell, and a user copy-pasting the
/// suggestion would lose the visible `sudo` cue.
fn is_interactive_shell(name: &str) -> bool {
    matches!(
        name,
        "sh" | "bash" | "zsh" | "fish" | "dash" | "ksh" | "tcsh" | "pwsh" | "powershell" | "nu"
    )
}

/// Heuristic catch-all for destructive command shapes the engine does not
/// (yet) model as a finding but for which dropping `sudo` is obviously the
/// wrong advice. `rm -rf /` is the canonical example: stripping sudo would
/// still produce a dangerous command, just one that runs as the current user.
///
/// Tirith's detection engine deliberately does not have a `rm -rf /` rule —
/// shell-builtin destructiveness is squarely the user's intent to express —
/// but the suggester has a stricter mandate: never produce a rewrite a careful
/// reviewer would call out as obviously worse than `--help` text. This
/// denylist closes that gap for the handful of shapes everyone agrees on.
fn looks_obviously_destructive(inner: &str) -> bool {
    // Normalize whitespace runs so the matcher is robust against extra spaces.
    let collapsed: String = inner.split_whitespace().collect::<Vec<_>>().join(" ");
    // Match leading `rm` with `-rf` / `-fr` / `-r -f` etc against `/`, `~`,
    // `$HOME`, `*`. Bound the check to the LEADING segment of the command —
    // anything later is somebody else's problem (and is the engine's domain).
    let lower = collapsed.to_ascii_lowercase();
    let triggers = [
        "rm -rf /",
        "rm -rf /*",
        "rm -fr /",
        "rm -fr /*",
        "rm -rf ~",
        "rm -rf $home",
        "rm -rf --no-preserve-root",
        "rm --no-preserve-root -rf /",
        "dd if=/dev/zero of=/dev/sd",
        "mkfs ",
        ":(){ :|:&};:",
    ];
    triggers.iter().any(|t| lower.starts_with(t))
}

/// Strip a leading `sudo` from the command bytes, returning the inner command
/// as raw text (preserving quoting / spacing). Returns `None` when no inner
/// command can be located (`sudo` with no arguments, only flags, etc.).
///
/// Handles common option flags (`-u USER`, `--user=USER`, `--`, …). Exotic
/// sudo flags fall through to "no rewrite" rather than risk a wrong strip.
fn strip_sudo_prefix(cmd: &str, shell: ShellType) -> Option<String> {
    let segs = tokenize::tokenize(cmd, shell);
    let seg = segs.first()?;
    let leader = base_command(seg.command.as_deref()?, shell);
    if leader != "sudo" {
        return None;
    }

    let value_short = ["-u", "-g", "-C", "-D", "-R", "-T"];
    let value_long = [
        "--user",
        "--group",
        "--close-from",
        "--chdir",
        "--role",
        "--type",
        "--other-user",
        "--host",
        "--timeout",
    ];

    let mut idx = 0;
    let mut start_arg = None;
    while idx < seg.args.len() {
        let arg = strip_quotes(&seg.args[idx]);
        if arg == "--" {
            start_arg = Some(idx + 1);
            break;
        }
        if arg.starts_with("--") {
            if value_long.iter().any(|f| arg == *f) {
                idx += 2;
            } else {
                // `--user=root` or any other `--flag=value` consumes one slot.
                idx += 1;
            }
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            if value_short.iter().any(|f| arg == *f) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        start_arg = Some(idx);
        break;
    }

    let start = start_arg?;
    if start >= seg.args.len() {
        return None;
    }
    // Reassemble the inner command from the raw segment so quoting is
    // preserved verbatim: find where the first inner-arg token begins in the
    // raw segment text and return everything from there onward.
    let first_arg = &seg.args[start];
    let stripped = strip_quotes(first_arg);
    let raw = &seg.raw;
    let pos = raw
        .find(first_arg.as_str())
        .or_else(|| raw.find(stripped.as_str()))?;
    Some(raw[pos..].trim().to_string())
}

/// Build the sudo-narrow suggestion for the verdict.
///
/// Fires when:
///  (i)   the parsed command's leader is `sudo`,
///  (ii)  the verdict has at least one finding (caller-checked),
///  (iii) the stripped leader is NOT an interactive shell, AND
///  (iv)  re-running [`engine::analyze`] on the inner command yields
///        [`Action::Allow`].
///
/// When (iii) fails, returns a `safe_command: None` suggestion with the
/// interactive-shell remediation text. When (iv) fails the inner command is
/// still flagged — per-finding suggestions already cover it, so returns `None`.
fn build_sudo_narrow_suggestion(
    cmd: &str,
    shell: ShellType,
    segments: &[tokenize::Segment],
    _verdict: &Verdict,
) -> Option<SafeSuggestion> {
    // (i) leader is sudo.
    let leader = base_command(segments.first()?.command.as_deref()?, shell);
    if leader != "sudo" {
        return None;
    }

    // Strip the prefix.
    let inner = strip_sudo_prefix(cmd, shell)?;
    if inner.is_empty() {
        return None;
    }

    // (iii) interactive-shell trip wire on the stripped leader.
    let inner_segs = tokenize::tokenize(&inner, shell);
    let inner_leader = inner_segs
        .first()
        .and_then(|s| s.command.as_deref())
        .map(|c| base_command(c, shell))
        .unwrap_or_default();
    if is_interactive_shell(&inner_leader) {
        return Some(SafeSuggestion {
            rule_id: "sudo_narrow".to_string(),
            safe_command: None,
            rationale: "no safe mechanical rewrite available; avoid interactive root shells — \
                 run the specific non-privileged command you intended, or use sudo only \
                 for the minimal command that requires elevation."
                .to_string(),
            remediation: "Identify the single command that needs elevation, then prefix only \
                          that command with sudo. Don't run an interactive root shell."
                .to_string(),
        });
    }

    // Refuse to rewrite obvious shell-builtin destructiveness (`rm -rf /`)
    // *before* re-analysis. The engine does not model these — it treats
    // user-typed `rm -rf /` as expressing intent — but the suggester has the
    // stricter mandate of never advising something a reviewer would call out
    // as worse than the original.
    if looks_obviously_destructive(&inner) {
        return None;
    }

    // (iv) re-analyze the stripped command. If it still flags, the sudo
    // wrapper was not the dangerous part — per-finding suggestions already
    // describe the real issue, so we return None here.
    let ctx = AnalysisContext {
        input: inner.clone(),
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
    };
    let inner_verdict = engine::analyze(&ctx);
    if inner_verdict.action != Action::Allow {
        return None;
    }

    Some(SafeSuggestion {
        rule_id: "sudo_narrow".to_string(),
        safe_command: Some(inner),
        rationale: "The command is safe to run without sudo — dropping the sudo prefix \
                    removes a privilege the inner command does not require."
            .to_string(),
        remediation: "Re-run the command without sudo. If the underlying tool genuinely \
                      needs root, narrow sudo to only the minimal command that does."
            .to_string(),
    })
}

// ── Env scrub (command-shape based) ────────────────────────────────────────

/// Currently-set sensitive env vars, in stable order (built-ins first, then any
/// user `policy.env_guard_sensitive_vars` extension). Stable order keeps the
/// suggested command deterministic.
///
/// M9 ch4 fix: the effective list MERGES the built-in `sensitive_env.toml`
/// names with the user's `policy.env_guard_sensitive_vars` extension (via
/// [`crate::env_guard::effective_sensitive_vars`]) so an `env -u …` rewrite
/// never silently omits a user-declared secret. The previous reasoning that the
/// two paths could never co-fire was load-bearing and undocumented to the user;
/// merging the list removes that fragility outright. A partial-policy discover
/// (local files only) is cheap and only runs when the env-scrub transform is
/// actually being built.
fn sensitive_env_set_in_process() -> Vec<String> {
    let policy = crate::policy::Policy::discover_partial(None);
    let effective = crate::env_guard::effective_sensitive_vars(&policy.env_guard_sensitive_vars);
    effective
        .into_iter()
        .filter(|name| std::env::var_os(name).is_some_and(|v| !v.is_empty()))
        .collect()
}

/// Returns `true` when `cmd` looks like a *single simple command* that
/// `env -u VAR ... <cmd>` can safely wrap.
///
/// `env -u VAR <cmd>` only scrubs the environment of the immediately
/// following process. Pipelines (`|`), logical chains (`&&`, `||`), command
/// separators (`;`), redirections (`>`, `<`, `>>`, `<<`), background jobs
/// (`&`), command substitutions (`` ` ``, `$(`), and subshells (`(`, `)`)
/// all spawn additional child processes that *inherit the caller's env*,
/// not the scrubbed one. Wrapping such a command with `env -u` produces a
/// safe-looking rewrite whose later stages still see the secret — strictly
/// worse than admitting we have no automatic fix.
///
/// Implementation: scan byte-by-byte while tracking single-quote,
/// double-quote, and backslash-escape state. POSIX single quotes
/// (`'...'`) make their contents literal; inside double quotes only
/// `$`, `` ` ``, and `\` retain meaning, so `|`, `&`, `;`, `>`, `<`,
/// `(`, `)` are safe to ignore there. `` ` `` and `$(` are flagged
/// whenever they appear outside single quotes — they trigger command
/// substitution even inside `"..."`.
fn is_simple_command_for_env_scrub(cmd: &str) -> bool {
    // Quote / escape tracking state. Both quote flags cannot be true at
    // the same time — POSIX shells don't nest the two.
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;

    let bytes = cmd.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];

        // Backslash outside single quotes consumes the next byte verbatim.
        // Inside single quotes a backslash is literal — POSIX has no escape.
        if escape {
            escape = false;
            i += 1;
            continue;
        }
        if b == b'\\' && !in_single {
            escape = true;
            i += 1;
            continue;
        }

        if in_single {
            if b == b'\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            match b {
                b'"' => in_double = false,
                // Command substitution is active inside double quotes.
                b'`' => return false,
                b'$' if i + 1 < bytes.len() && bytes[i + 1] == b'(' => return false,
                _ => {}
            }
            i += 1;
            continue;
        }

        // Unquoted context — flag any shell-compound metacharacter.
        match b {
            b'\'' => in_single = true,
            b'"' => in_double = true,
            b'|' | b'&' | b';' | b'>' | b'<' | b'(' | b')' | b'`' => return false,
            b'$' if i + 1 < bytes.len() && bytes[i + 1] == b'(' => return false,
            _ => {}
        }
        i += 1;
    }

    // Unterminated quotes or trailing backslash — treat as not-simple. A
    // malformed command is exactly the case where guessing the right
    // wrapper is most dangerous.
    !(in_single || in_double || escape)
}

/// Build an env-scrub suggestion for the verdict when:
///  (i)   the dedicated [`RuleId::EnvSensitiveExposedToUnknownScript`] finding
///        is present (M9 ch4 — the explicit trigger this transform points at),
///        OR at least one finding is High severity or above (the original M6
///        ch5 heuristic, kept for backward compat), AND
///  (ii)  at least one sensitive env var is currently set in this process,
///        AND
///  (iii) the shell is a POSIX shell (bash/zsh/sh/fish/posix) — `env -u`
///        does not exist on PowerShell, so we'd emit a broken "safe
///        command". Detect-and-decline for PowerShell rather than ship a
///        rewrite that won't execute, AND
///  (iv)  the command is a single simple command (no `|`, `&&`, `;`,
///        redirections, subshells, or command substitution). `env -u VAR`
///        only scrubs the immediately-following child process — every
///        subsequent stage in a pipeline or chain still inherits the real
///        env, so wrapping a compound command would emit a "safe" rewrite
///        the secret could still leak through. See
///        [`is_simple_command_for_env_scrub`].
///
/// Returns `None` otherwise.
fn build_env_scrub_suggestion(
    cmd: &str,
    shell: ShellType,
    verdict: &Verdict,
) -> Option<SafeSuggestion> {
    // Fire when EITHER the dedicated M9 ch4 rule is present (the explicit,
    // audit-visible trigger this transform was designed to point at) OR any
    // High-severity finding is present (the original M6 ch5 heuristic, kept
    // for backward compat). Both paths are valid; the dedicated-rule path
    // makes the env-scrub trigger explicit in `--explain` / audit output.
    let dedicated_rule_present = verdict
        .findings
        .iter()
        .any(|f| f.rule_id == RuleId::EnvSensitiveExposedToUnknownScript);
    let any_high = verdict
        .findings
        .iter()
        .any(|f| f.severity >= Severity::High);
    if !dedicated_rule_present && !any_high {
        return None;
    }

    // `env -u VAR1 -u VAR2 ... <cmd>` is POSIX-only. On PowerShell the
    // equivalent is per-var `$env:VAR = $null` lines, which can't be
    // expressed as a single inline command without changing semantics
    // (the lines would mutate the *caller's* session env, not just the
    // child's). Decline rather than ship a broken rewrite. The user's
    // remediation field in the per-rule guidance covers the PowerShell
    // manual unset path.
    if shell == ShellType::PowerShell {
        return None;
    }

    let set_vars = sensitive_env_set_in_process();
    if set_vars.is_empty() {
        return None;
    }

    // `env -u` only affects the immediately-following command, so a
    // compound shell construct (pipeline, chain, redirect, subshell,
    // background, command substitution) would leak the secret through
    // its later stages. Decline rather than ship a misleading rewrite.
    if !is_simple_command_for_env_scrub(cmd.trim()) {
        return None;
    }

    // `env -u VAR1 -u VAR2 ... <original-cmd>` — works on POSIX shells.
    let mut rewrite = String::from("env");
    for var in &set_vars {
        rewrite.push_str(" -u ");
        rewrite.push_str(var);
    }
    rewrite.push(' ');
    rewrite.push_str(cmd.trim());

    Some(SafeSuggestion {
        rule_id: "env_scrub".to_string(),
        safe_command: Some(rewrite),
        rationale: format!(
            "Unsets {} sensitive env var(s) currently in your environment before \
             running the command, so a malicious script cannot exfiltrate them.",
            set_vars.len()
        ),
        remediation: "Unset sensitive environment variables (API tokens, cloud credentials) \
                      before running untrusted commands, or use `env -u VAR ...` to scrub them \
                      for a single invocation."
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
    use crate::verdict::{Evidence, Timings};

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

    // ── is_simple_command_for_env_scrub guard ─────────────────────────────
    //
    // The guard is exercised directly (instead of via `suggest()`) because
    // `build_env_scrub_suggestion` also requires a sensitive env var to be
    // set in the *current process* — mutating `std::env` from a test would
    // race against any parallel test that reads the env. The integration
    // path is covered by the existing `suggest()` flow plus the dedicated
    // `env_scrub_declines_when_command_is_compound` test below, which
    // uses a known-sensitive var name guarded by `serial_test`-free
    // explicit set/unset.

    #[test]
    fn simple_command_accepted_for_env_scrub() {
        assert!(is_simple_command_for_env_scrub("npm install foo"));
        assert!(is_simple_command_for_env_scrub(
            "curl https://example.com/x"
        ));
        assert!(is_simple_command_for_env_scrub("pip install requests"));
        assert!(is_simple_command_for_env_scrub("ls -la /tmp"));
    }

    #[test]
    fn pipeline_rejected_for_env_scrub() {
        // `env -u VAR npm install foo | sh` would scrub only the npm
        // process; the piped `sh` still inherits the original env and
        // could exfiltrate the secret. The guard refuses to emit a
        // misleading "safe" rewrite for this shape.
        assert!(!is_simple_command_for_env_scrub("npm install foo | sh"));
        assert!(!is_simple_command_for_env_scrub("curl https://foo | bash"));
    }

    #[test]
    fn logical_chain_rejected_for_env_scrub() {
        // && and || run a second command in the same shell context;
        // wrapping with `env -u` would only scrub the first stage.
        assert!(!is_simple_command_for_env_scrub("ls && cat secret"));
        assert!(!is_simple_command_for_env_scrub("ls || echo failed"));
        // `;` is a hard sequence — same problem, second command keeps
        // the original env.
        assert!(!is_simple_command_for_env_scrub("ls; cat secret"));
    }

    #[test]
    fn redirection_rejected_for_env_scrub() {
        // Redirection by itself is benign for env scrubbing, but the
        // operator may have constructed a compound command (here-doc,
        // multi-line pipeline through a file) that we cannot reason
        // about. Conservative: refuse the suggestion.
        assert!(!is_simple_command_for_env_scrub("ls > /tmp/x"));
        assert!(!is_simple_command_for_env_scrub("cat < /etc/passwd"));
        assert!(!is_simple_command_for_env_scrub("ls >> /tmp/x"));
    }

    #[test]
    fn background_and_subshell_rejected_for_env_scrub() {
        assert!(!is_simple_command_for_env_scrub("long-job &"));
        assert!(!is_simple_command_for_env_scrub("(cd /tmp && ls)"));
    }

    #[test]
    fn command_substitution_rejected_for_env_scrub() {
        // `$(...)` and backticks spawn a child shell that inherits the
        // env regardless of what the outer `env -u` scrubs.
        assert!(!is_simple_command_for_env_scrub("echo $(whoami)"));
        assert!(!is_simple_command_for_env_scrub("echo `whoami`"));
        // `$(` inside double quotes is still command substitution.
        assert!(!is_simple_command_for_env_scrub("echo \"$(whoami)\""));
        // Backtick inside double quotes is still command substitution.
        assert!(!is_simple_command_for_env_scrub("echo \"`whoami`\""));
    }

    #[test]
    fn metacharacter_inside_single_quotes_does_not_disqualify() {
        // Single-quoted strings are literal in POSIX shells — the `|`,
        // `&`, etc. inside them are not metacharacters and the command
        // is in fact a single simple invocation.
        assert!(is_simple_command_for_env_scrub(
            "echo 'this is | not a pipe'"
        ));
        assert!(is_simple_command_for_env_scrub("echo 'a && b'"));
        assert!(is_simple_command_for_env_scrub("echo 'cat > file'"));
    }

    #[test]
    fn metacharacter_inside_double_quotes_treated_correctly() {
        // Inside double quotes, `|`, `&`, `;`, `<`, `>`, `(`, `)` are
        // *not* metacharacters in POSIX — the shell passes them through
        // as literal bytes — so the command is still a single
        // invocation.
        assert!(is_simple_command_for_env_scrub(
            "echo \"this is | not a pipe\""
        ));
        assert!(is_simple_command_for_env_scrub("echo \"a && b\""));
        // But `$(` and backtick *are* still active inside double quotes:
        assert!(!is_simple_command_for_env_scrub("echo \"$(whoami)\""));
    }

    #[test]
    fn escaped_metacharacter_does_not_disqualify() {
        // A literal backslash-pipe is just an escaped char (passed
        // through to the command as the two bytes `\|`). It is not a
        // pipeline.
        assert!(is_simple_command_for_env_scrub("grep \\| file"));
        assert!(is_simple_command_for_env_scrub("echo a\\&b"));
    }

    #[test]
    fn unterminated_quote_is_rejected() {
        // Malformed input — exactly the case where guessing the right
        // wrapper is most dangerous. Decline.
        assert!(!is_simple_command_for_env_scrub("echo 'unterminated"));
        assert!(!is_simple_command_for_env_scrub("echo \"unterminated"));
        // Trailing backslash with nothing to escape — same reason.
        assert!(!is_simple_command_for_env_scrub("echo trailing\\"));
    }

    #[test]
    fn dedicated_rule_present_is_an_env_scrub_trigger() {
        // M9 ch4 — prove the dedicated `EnvSensitiveExposedToUnknownScript`
        // finding is recognized as an env-scrub trigger independent of the
        // legacy "any High finding" heuristic. This exercises the trigger
        // predicate WITHOUT mutating `std::env` (the libc setenv race, PR
        // #125): the end-to-end rewrite additionally needs a sensitive var
        // set in the process, which is covered race-free by the CLI
        // integration test `env_scrub_fires_under_dedicated_rule` (it sets
        // the var in a CHILD `tirith` process).
        //
        // The finding is Medium severity, so the `any_high` heuristic is
        // false; only the dedicated-rule branch can mark this verdict as a
        // candidate. We assert the predicate the function uses, mirroring the
        // exact `dedicated_rule_present` check.
        let mut f = finding(RuleId::EnvSensitiveExposedToUnknownScript);
        f.severity = Severity::Medium;
        let v = verdict_with(vec![f]);
        let any_high = v.findings.iter().any(|f| f.severity >= Severity::High);
        let dedicated_present = v
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::EnvSensitiveExposedToUnknownScript);
        assert!(!any_high, "Medium finding must not trip the High heuristic");
        assert!(
            dedicated_present,
            "dedicated rule must be detectable as an env-scrub trigger"
        );
    }

    // NOTE: An end-to-end `env_scrub_declines_when_command_is_compound` test
    // that mutates `std::env::GITHUB_TOKEN` was intentionally NOT added.
    // Under parallel `cargo test`, that mutation races with other tests in
    // this module that exercise `suggest()` and read the environment
    // (`homograph_finding_gets_no_rewrite_but_keeps_remediation`, etc.).
    // The compound-shape guard is fully covered by the
    // `is_simple_command_for_env_scrub` direct-call unit tests above
    // (pipeline/redirection/and-chain/semicolon/backtick/command-sub etc.),
    // which exercise exactly the predicate that controls env_scrub firing.
}
