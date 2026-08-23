use std::io::{self, Write};
use std::path::Path;

use tirith_core::rules::cloaking;

/// `tirith fetch --save <path> <url>` — download `url` to `path` (no execution)
/// and mark `path` tainted, so a later `bash <path>` / `source <path>` fires the
/// engine's tainted-file rule. Unlike `tirith run`, nothing is executed.
pub fn save(url: &str, save_path: &str, sha256: Option<String>, json: bool) -> i32 {
    let dest = Path::new(save_path);

    let binding =
        match tirith_core::runner::remote_fetch_save_boundary_binding(url, dest, sha256.as_deref())
        {
            Ok(binding) => binding,
            Err(error) => return report_save_error(&error, json),
        };
    let operation = binding.operation();
    let cwd = std::env::current_dir()
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    let policy = tirith_core::policy::Policy::discover(cwd.as_deref());
    let pending = tirith_core::task_boundary::prepare_locally_derived_boundary_authorization::<
        tirith_core::task_boundary::RemoteScriptRunBoundary,
    >(
        &operation,
        &policy.task_gate,
        &tirith_core::task_analysis::TaskAnalysisContext::default(),
    );
    let assessment = match &pending {
        Ok(pending) => Some(pending.assessment()),
        Err(error) => error.assessment(),
    };
    if let Some(assessment) = assessment {
        if let Err(error) = tirith_core::audit::log_task_boundary_assessment(assessment) {
            tirith_core::audit::audit_diagnostic(format!(
                "fetch-save task-boundary audit append failed: {error}"
            ));
        }
    }
    let pending = match pending {
        Ok(pending) => pending,
        Err(error) => return report_save_error(&error.to_string(), json),
    };

    let (result, entry) = match tirith_core::runner::download_to_path_and_mark_tainted_authorized(
        url,
        dest,
        sha256.as_deref(),
        pending,
        &operation,
    ) {
        Ok(result) => result,
        Err(error) => return report_save_error(&error, json),
    };

    if json {
        #[derive(serde::Serialize)]
        struct SaveOut<'a> {
            saved_path: String,
            sha256: &'a str,
            final_url: &'a str,
            size: u64,
            interpreter: &'a str,
            tainted: bool,
            taint_entry: &'a tirith_core::taint::TaintEntry,
        }
        let out = SaveOut {
            saved_path: entry.path.clone(),
            sha256: &result.sha256,
            final_url: &result.final_url,
            size: result.size,
            interpreter: &result.interpreter,
            tainted: true,
            taint_entry: &entry,
        };
        if !super::write_json_stdout(&out, "tirith fetch --save: failed to write JSON output") {
            return 2;
        }
    } else {
        println!(
            "Saved {} bytes to {} (SHA256: {})",
            result.size,
            save_path,
            tirith_core::receipt::short_hash(&result.sha256)
        );
        println!(
            "Marked TAINTED (origin: fetch --save, source: {}).",
            result.final_url
        );
        println!();
        println!("This file was NOT executed. A later `bash {save_path}` or `source {save_path}`");
        println!("will be flagged by tirith. Review it first; once you trust it:");
        println!("  tirith taint clear {save_path}");
    }
    0
}

fn report_save_error(error: &str, json: bool) -> i32 {
    if json {
        let err = serde_json::json!({ "error": error });
        // On a broken `--json` write, exit 2 (protocol failure), not 1
        // (transaction failure), because the JSON never reached the caller.
        if !super::write_json_stdout(&err, "tirith fetch --save: failed to write JSON output") {
            return 2;
        }
    } else {
        eprintln!("tirith fetch --save: {error}");
    }
    1
}

pub fn run(url: &str, json: bool) -> i32 {
    let cwd = std::env::current_dir()
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    // This is an enforcement boundary, so freeze the fully resolved effective
    // policy (including remote/cached fail-mode semantics) exactly once for the
    // whole cloaking transaction.
    let policy = tirith_core::policy::Policy::discover(cwd.as_deref());
    run_with_policy(url, json, &policy)
}

fn run_with_policy(url: &str, json: bool, policy: &tirith_core::policy::Policy) -> i32 {
    let compiled =
        tirith_core::redact::CompiledCustomPatterns::new_silent(&policy.dlp_custom_patterns);
    let mut task_boundary = None;
    let checked = cloaking::check_with_audit(url, &policy.task_gate, |assessment| {
        let projection = redacted_task_boundary_projection(assessment, &compiled);
        let detail = serde_json::to_string(&projection).ok();
        tirith_core::audit::log_hook_event(
            "cli",
            "fetch_cloaking",
            "task_boundary",
            None,
            detail.as_deref(),
        );
        task_boundary = Some(projection);
    });

    match checked {
        Ok(authorized) => {
            let result = authorized.result;
            if json {
                print_json(&result, task_boundary.as_ref());
            } else if !print_human(&result) {
                return 2;
            }
            if result.cloaking_detected {
                1
            } else {
                0
            }
        }
        Err(error) => {
            if task_boundary.is_none() {
                task_boundary = error
                    .assessment()
                    .filter(|assessment| assessment.is_recordable())
                    .map(|assessment| redacted_task_boundary_projection(assessment, &compiled));
            }
            let safe_error = tirith_core::redact::redact_sanitize_redact_with_compiled(
                &error.to_string(),
                &compiled,
            );
            if json {
                let body = cloaking_error_json(&safe_error, task_boundary.as_ref());
                if !super::write_json_stdout(
                    &body,
                    "tirith fetch: failed to write JSON error output",
                ) {
                    return 2;
                }
            } else {
                eprintln!("tirith fetch: {safe_error}");
            }
            2
        }
    }
}

fn redacted_task_boundary_projection(
    assessment: &tirith_core::task_boundary::BoundaryAssessment,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> serde_json::Value {
    let mut projection = assessment.projection();
    tirith_core::redact::redact_json_strings(&mut projection, compiled);
    tirith_core::verdict::bound_json_value_for_output(projection)
}

fn cloaking_error_json(
    error: &str,
    task_boundary: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut body = serde_json::json!({"error": error});
    if let Some(task_boundary) = task_boundary {
        body.as_object_mut()
            .unwrap()
            .insert("task_boundary".to_string(), task_boundary.clone());
    }
    body
}

fn print_json(result: &cloaking::CloakingResult, task_boundary: Option<&serde_json::Value>) {
    let mut json = result.to_json(true);
    if let Some(task_boundary) = task_boundary {
        json.as_object_mut()
            .unwrap()
            .insert("task_boundary".to_string(), task_boundary.clone());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json).unwrap_or_else(|e| {
            eprintln!("tirith: fetch: JSON serialization failed: {e}");
            "{}".to_string()
        })
    );
}

fn print_human(result: &cloaking::CloakingResult) -> bool {
    let mut stdout = io::stdout().lock();
    if print_human_to(&mut stdout, result).is_err() {
        eprintln!("tirith fetch: failed to write human output");
        return false;
    }
    true
}

/// Render a cloaking result to a human terminal. Machine JSON deliberately
/// bypasses this projection and remains raw structured data.
fn print_human_to<W: Write>(out: &mut W, result: &cloaking::CloakingResult) -> io::Result<()> {
    let url = super::sanitize_for_human_output(&result.url, false);
    writeln!(out, "Cloaking check: {url}")?;
    writeln!(out)?;

    for agent in &result.agent_responses {
        let status = if agent.status_code == 0 {
            "FAILED".to_string()
        } else {
            agent.status_code.to_string()
        };
        let agent_name = super::sanitize_for_human_output(&agent.agent_name, false);
        writeln!(
            out,
            "  {:<14} status={:<6} length={}",
            agent_name, status, agent.content_length
        )?;
    }

    writeln!(out)?;

    if result.cloaking_detected {
        writeln!(
            out,
            "{}",
            tirith_core::style::bold_red("Cloaking detected!", tirith_core::style::Stream::Stdout)
        )?;
        for diff in &result.diff_pairs {
            let agent_a = super::sanitize_for_human_output(&diff.agent_a, false);
            let agent_b = super::sanitize_for_human_output(&diff.agent_b, false);
            writeln!(
                out,
                "  {} vs {}: {} chars different",
                agent_a, agent_b, diff.diff_chars
            )?;
            if let Some(ref text) = diff.diff_text {
                let text = super::sanitize_for_human_output(text, true).replace('\n', "\n    ");
                writeln!(out, "    {text}")?;
            }
        }
    } else {
        writeln!(
            out,
            "{}",
            tirith_core::style::green("No cloaking detected.", tirith_core::style::Stream::Stdout)
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cloaking_result(url: &str, agent: &str, diff_text: &str) -> cloaking::CloakingResult {
        cloaking::CloakingResult {
            url: url.to_string(),
            cloaking_detected: true,
            findings: Vec::new(),
            agent_responses: vec![cloaking::AgentResponse {
                agent_name: agent.to_string(),
                status_code: 200,
                content_length: 42,
            }],
            diff_pairs: vec![cloaking::DiffPair {
                agent_a: "chrome".to_string(),
                agent_b: agent.to_string(),
                diff_chars: 42,
                diff_text: Some(diff_text.to_string()),
            }],
        }
    }

    #[test]
    fn human_renderer_neutralizes_untrusted_terminal_controls() {
        let result = cloaking_result(
            "https://safe.example/before\x1b]52;c;aGVsbG8=\x07after\u{202e}",
            "bot\x1b[2J\u{009b}\nFORGED",
            "remote\x1b[31mred\x1b[0m\nFORGED DETAIL",
        );
        let mut out = Vec::new();

        print_human_to(&mut out, &result).expect("render human output");

        let rendered = String::from_utf8(out).expect("renderer emits UTF-8");
        assert!(
            !rendered.contains('\x1b'),
            "ESC must not reach the terminal"
        );
        assert!(
            !rendered.contains('\u{202e}'),
            "bidi controls must not reach the terminal"
        );
        assert!(
            !rendered.contains('\u{009b}'),
            "C1 CSI must not reach the terminal"
        );
        assert!(
            !rendered.contains("\nFORGED"),
            "untrusted fields must not forge a top-level line: {rendered:?}"
        );
        assert!(rendered.contains("https://safe.example/beforeafter"));
        // A C1 CSI consumes through its final byte, so text immediately after an
        // unterminated control introducer is not guaranteed to survive. Safety
        // requires removing the sequence and preventing row forgery, not
        // preserving attacker-controlled bytes inside that sequence.
        assert!(rendered.contains("bot"));
        assert!(rendered.contains("remotered\n      FORGED DETAIL"));
    }

    #[test]
    fn human_renderer_preserves_legitimate_unicode() {
        let result = cloaking_result(
            "https://例え.テスト/路径",
            "検査-bot",
            "café résumé 東京 🚀",
        );
        let mut out = Vec::new();

        print_human_to(&mut out, &result).expect("render human output");

        let rendered = String::from_utf8(out).expect("renderer emits UTF-8");
        assert!(rendered.contains("https://例え.テスト/路径"));
        assert!(rendered.contains("検査-bot"));
        assert!(rendered.contains("café résumé 東京 🚀"));
    }

    #[test]
    fn json_projection_preserves_raw_structured_values() {
        let raw_url = "https://safe.example/\x1b[2J路径";
        let raw_diff = "before\x1b]52;c;aGVsbG8=\x07after";
        let result = cloaking_result(raw_url, "検査-bot", raw_diff);

        let json = result.to_json(true);

        assert_eq!(json["url"], raw_url);
        assert_eq!(json["agents"][0]["agent"], "検査-bot");
        assert_eq!(json["diffs"][0]["diff_text"], raw_diff);
    }

    #[test]
    fn enforcing_operator_policy_refuses_before_fetch() {
        let policy = tirith_core::policy::Policy {
            task_gate: tirith_core::web3_policy::TaskGatePolicy {
                mode: tirith_core::web3_policy::TaskGateMode::Enforce,
                effects_denied_for_untrusted_sources: [
                    tirith_core::effects::CommandEffectKind::NetworkEgress,
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(cloaking::check("https://example.com", &policy.task_gate).is_err());
    }

    #[test]
    fn json_error_retains_the_structured_task_boundary_projection() {
        let projection = serde_json::json!({
            "boundary": "fetch_cloaking",
            "mode": "enforce",
            "outcome": "deny"
        });
        let body = cloaking_error_json("authorization refused", Some(&projection));
        assert_eq!(body["error"], "authorization refused");
        assert_eq!(body["task_boundary"], projection);
    }
}
