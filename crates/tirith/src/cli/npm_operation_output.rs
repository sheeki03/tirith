//! Display-only npm operation output. Stored intents and signed records never
//! receive privacy substitutions or become authority through this projection.
use serde_json::{json, Value};
use std::io::Write;
use tirith_core::{
    output_contract::{redact_projection, withhold_projection_content, Projection},
    policy::{captured_policy_dlp_patterns_or, PolicyDiagnosticCapture},
    policy_snapshot::{EffectivePolicySnapshot, InputState, ResolutionMode},
    redact::CompiledCustomPatterns,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum OperationKind {
    Install,
    Materialize,
}
impl OperationKind {
    fn projection(self) -> Projection {
        match self {
            Self::Install => Projection::NpmInstall,
            Self::Materialize => Projection::NpmMaterialization,
        }
    }
}

pub(super) struct OutputContext {
    capture: PolicyDiagnosticCapture,
    patterns: Vec<String>,
    local_capture_complete: bool,
    withheld_diagnostics: usize,
}
impl OutputContext {
    pub(super) fn start() -> Self {
        let cwd = current_cwd();
        Self::start_for(cwd.as_deref())
    }

    fn start_for(cwd: Option<&str>) -> Self {
        let patterns = captured_policy_dlp_patterns_or(&[]);
        let capture = PolicyDiagnosticCapture::start();
        tirith_core::policy::freeze_captured_policy_dlp_patterns(&patterns);
        let mut context = Self {
            capture,
            patterns,
            local_capture_complete: true,
            withheld_diagnostics: 0,
        };
        context.refresh_for(cwd);
        context
    }

    fn refresh_for(&mut self, cwd: Option<&str>) {
        if let Some(cwd) = cwd {
            // Presentation collects current trusted local privacy rules without
            // making a remote request or granting runtime authority.
            let snapshot = EffectivePolicySnapshot::resolve(Some(cwd), ResolutionMode::LocalOnly);
            self.local_capture_complete &= snapshot.revalidate_captured().is_ok()
                && !snapshot
                    .input_revisions
                    .iter()
                    .any(|input| input.state == InputState::Unreadable);
            for pattern in captured_policy_dlp_patterns_or(&snapshot.policy.dlp_custom_patterns) {
                if !self.patterns.contains(&pattern) {
                    self.patterns.push(pattern);
                }
            }
        } else {
            self.local_capture_complete = false;
        }
        let diagnostics = self.capture.drain();
        self.local_capture_complete &= diagnostics.is_empty();
        self.withheld_diagnostics = self.withheld_diagnostics.saturating_add(diagnostics.len());
        self.local_capture_complete &= CompiledCustomPatterns::new_silent(&self.patterns)
            .incomplete_reason()
            .is_none();
    }

    fn display(&self, original: &Value, kind: OperationKind) -> Value {
        let mut value = original.clone();
        if self.local_capture_complete {
            redact_projection(
                &mut value,
                kind.projection(),
                &CompiledCustomPatterns::new_silent(&self.patterns),
            );
        } else {
            withhold_projection_content(&mut value, kind.projection());
        }
        value["redaction"] = json!({
            "source":"current_local_and_invocation_captured_patterns",
            "local_capture_complete":self.local_capture_complete,
            "content_withheld":!self.local_capture_complete,
            "withheld_diagnostics":self.withheld_diagnostics,
            "remote_policy":"not_fetched_for_presentation",
            "effective_runtime_policy":false,
            "display_only":true,
        });
        value
    }

    pub(super) fn finish(
        mut self,
        original: &Value,
        kind: OperationKind,
        json: bool,
        exit: i32,
    ) -> i32 {
        let cwd = current_cwd();
        self.refresh_for(cwd.as_deref());
        let mut value = self.display(original, kind);
        if kind == OperationKind::Materialize && !json && exit != 0 {
            let message = super::sanitize_for_human_output(
                value["error"].as_str().unwrap_or("Output is unavailable."),
                false,
            );
            value["error"] = Value::String(if self.local_capture_complete {
                tirith_core::redact::redact_sanitize_redact_with_compiled(
                    &message,
                    &CompiledCustomPatterns::new_silent(&self.patterns),
                )
            } else {
                "[withheld: privacy capture incomplete]".into()
            });
        }
        write_result(
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
            &value,
            kind,
            json,
            exit,
        )
    }
}

fn current_cwd() -> Option<String> {
    std::env::current_dir()
        .ok()
        .and_then(|path| path.to_str().map(str::to_owned))
}

fn write_result(
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    value: &Value,
    kind: OperationKind,
    json: bool,
    exit: i32,
) -> i32 {
    if kind == OperationKind::Materialize && !json && exit != 0 {
        let message = value["error"].as_str().unwrap_or("Output is unavailable.");
        if stderr.write_all(b"tirith pkg materialize: ").is_err()
            || stderr.write_all(message.as_bytes()).is_err()
            || stderr.write_all(b"\n").is_err()
            || stderr.flush().is_err()
        {
            1
        } else {
            exit
        }
    } else {
        write_to(stdout, value, json, exit)
    }
}

fn write_to(out: &mut impl Write, value: &Value, json: bool, exit: i32) -> i32 {
    let written = if json {
        serde_json::to_writer(&mut *out, value)
    } else {
        serde_json::to_writer_pretty(&mut *out, value)
    };
    if written.is_err() || out.write_all(b"\n").is_err() || out.flush().is_err() {
        1
    } else {
        exit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_test_support::GlobalStateGuard;

    const OPERATION: &str = "11111111-1111-4111-8111-111111111111";

    fn value(kind: OperationKind) -> Value {
        let contract = match kind {
            OperationKind::Install => "LocalLeafNoScriptsV1",
            OperationKind::Materialize => "LocalLeafMaterializeV1",
        };
        json!({"schema":1,"contract":contract,"operation":OPERATION,"phase":"reviewed_intent",
            "reviewed_sha256":"a".repeat(64),"target":"/operator-secret/target",
            "archives":[{"path":"/operator-secret/package.tgz","sha256":"b".repeat(64)}],
            "summary":{"schema":1,"contract":contract,"operation_id":OPERATION,
                "public_plan_digest":"c".repeat(64),"inventory_digest":"d".repeat(64),
                "packages":[{"name":"operator-secret","version":"operator-secret","compressed_sha256":"b".repeat(64)}],
                "code_safety":"not_established"},
            "transaction_observation":{"phase":"private_receipt","reason":"operator-secret", "private_receipt_id":"e".repeat(64)},
            "error":"operator-secret", "future_field":{"operation":OPERATION,"phase":"reviewed_intent","detail":"operator-secret"}})
    }

    fn isolated_context(patterns: &[&str], complete: bool) -> OutputContext {
        OutputContext {
            capture: PolicyDiagnosticCapture::start(),
            patterns: patterns.iter().map(|pattern| (*pattern).into()).collect(),
            local_capture_complete: complete,
            withheld_diagnostics: 0,
        }
    }

    #[test]
    fn display_redacts_content_without_changing_canonical_commitments() {
        let context = isolated_context(&["(?s).+"], true);
        for kind in [OperationKind::Install, OperationKind::Materialize] {
            let original = value(kind);
            let canonical = serde_json::to_vec(&original).unwrap();
            let shown = context.display(&original, kind);
            assert_eq!(shown["operation"], OPERATION);
            assert_eq!(shown["reviewed_sha256"], "a".repeat(64));
            assert_eq!(shown["phase"], "reviewed_intent");
            assert_eq!(shown["archives"][0]["sha256"], "b".repeat(64));
            assert_eq!(shown["summary"]["public_plan_digest"], "c".repeat(64));
            assert_eq!(
                shown["summary"]["packages"][0]["compressed_sha256"],
                "b".repeat(64)
            );
            assert_eq!(shown["future_field"]["operation"], "[REDACTED:custom]");
            assert!(!shown.to_string().contains("operator-secret"));
            assert_eq!(serde_json::to_vec(&original).unwrap(), canonical);
        }
    }

    #[test]
    fn schema_is_selected_by_the_producer_not_an_edited_contract_field() {
        let context = isolated_context(&["(?s).+"], true);
        let mut edited = value(OperationKind::Install);
        edited["contract"] = json!("LocalLeafMaterializeV1");
        edited["operation"] = json!("00000000-0000-0000-0000-000000000000");
        edited["reviewed_sha256"] = json!("A".repeat(64));
        edited["phase"] = json!("operator-secret");
        let shown = context.display(&edited, OperationKind::Install);
        for key in ["contract", "operation", "reviewed_sha256", "phase"] {
            assert_eq!(shown[key], "[REDACTED:custom]", "{key}");
        }
        assert_eq!(
            shown["transaction_observation"]["private_receipt_id"],
            "e".repeat(64)
        );
    }

    #[test]
    fn missing_capture_withholds_content_and_keeps_review_handles_usable() {
        let context = isolated_context(&[], false);
        let original = value(OperationKind::Install);
        let shown = context.display(&original, OperationKind::Install);
        assert_eq!(shown["operation"], OPERATION);
        assert_eq!(shown["reviewed_sha256"], "a".repeat(64));
        assert_eq!(shown["target"], "[withheld: privacy capture incomplete]");
        assert_eq!(shown["redaction"]["content_withheld"], true);
        assert_eq!(shown["redaction"]["local_capture_complete"], false);
        assert!(!shown.to_string().contains("operator-secret"));
    }

    #[test]
    fn refresh_unions_before_transaction_and_after_patterns() {
        let state = GlobalStateGuard::new().unwrap();
        let config = tirith_core::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let path = config.join("policy.yaml");
        std::fs::write(&path, "dlp_custom_patterns: ['earlier-secret']\n").unwrap();
        let mut context = OutputContext::start_for(state.roots().cwd.to_str());
        {
            let _bounded = tirith_core::policy::BoundedRuntimePolicyInputs::enter();
            tirith_core::policy::freeze_captured_policy_dlp_patterns(
                &["transaction-secret".into()],
            );
        }
        std::fs::write(&path, "dlp_custom_patterns: ['later-secret']\n").unwrap();
        context.refresh_for(state.roots().cwd.to_str());
        assert!(context.local_capture_complete);
        let shown = context.display(
            &json!({"error":"earlier-secret transaction-secret later-secret"}),
            OperationKind::Install,
        );
        for secret in ["earlier-secret", "transaction-secret", "later-secret"] {
            assert!(!shown.to_string().contains(secret));
        }
    }

    #[test]
    fn failed_policy_capture_stays_withheld_after_a_later_success() {
        let state = GlobalStateGuard::new().unwrap();
        let config = tirith_core::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let path = config.join("policy.yaml");
        std::fs::write(&path, "dlp_custom_patterns: [invalid yaml\n").unwrap();
        let mut context = OutputContext::start_for(state.roots().cwd.to_str());
        assert!(!context.local_capture_complete);
        std::fs::write(&path, "dlp_custom_patterns: []\n").unwrap();
        context.refresh_for(state.roots().cwd.to_str());
        assert!(!context.local_capture_complete);
        let shown = context.display(
            &value(OperationKind::Materialize),
            OperationKind::Materialize,
        );
        assert!(!shown.to_string().contains("operator-secret"));
        assert_eq!(shown["redaction"]["content_withheld"], true);
    }

    #[test]
    fn invalid_custom_regex_and_unavailable_cwd_cannot_enable_content() {
        let state = GlobalStateGuard::new().unwrap();
        let config = tirith_core::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("policy.yaml"), "dlp_custom_patterns: ['(']\n").unwrap();
        let context = OutputContext::start_for(state.roots().cwd.to_str());
        assert!(!context.local_capture_complete);
        drop(context);
        let context = OutputContext::start_for(None);
        assert!(!context.local_capture_complete);
    }

    #[test]
    fn materialize_human_errors_keep_stderr_and_json_errors_keep_stdout() {
        let context = isolated_context(&["operator-secret"], true);
        let shown = context.display(
            &value(OperationKind::Materialize),
            OperationKind::Materialize,
        );
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            write_result(
                &mut stdout,
                &mut stderr,
                &shown,
                OperationKind::Materialize,
                false,
                2
            ),
            2
        );
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "tirith pkg materialize: [REDACTED:custom]\n"
        );
        let mut stderr = Vec::new();
        assert_eq!(
            write_result(
                &mut stdout,
                &mut stderr,
                &shown,
                OperationKind::Materialize,
                true,
                2
            ),
            2
        );
        assert!(stderr.is_empty());
        assert_eq!(serde_json::from_slice::<Value>(&stdout).unwrap(), shown);

        let bytes = b"tirith pkg materialize: [REDACTED:custom]".len();
        for (remaining, fail_flush) in [(0, false), (bytes, false), (usize::MAX, true)] {
            let mut stdout = Vec::new();
            assert_eq!(
                write_result(
                    &mut stdout,
                    &mut FailingWriter {
                        remaining,
                        fail_flush
                    },
                    &shown,
                    OperationKind::Materialize,
                    false,
                    2
                ),
                1
            );
            assert!(stdout.is_empty());
        }
    }

    struct FailingWriter {
        remaining: usize,
        fail_flush: bool,
    }
    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            let n = self.remaining.min(bytes.len());
            self.remaining -= n;
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            if self.fail_flush {
                Err(std::io::ErrorKind::BrokenPipe.into())
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn body_newline_and_flush_failures_return_failure_without_panicking() {
        let value = json!({"schema":1,"phase":"withdrawn"});
        for json in [false, true] {
            let bytes = if json {
                serde_json::to_vec(&value)
            } else {
                serde_json::to_vec_pretty(&value)
            }
            .unwrap();
            for (remaining, fail_flush) in [(0, false), (bytes.len(), false), (usize::MAX, true)] {
                assert_eq!(
                    write_to(
                        &mut FailingWriter {
                            remaining,
                            fail_flush
                        },
                        &value,
                        json,
                        0
                    ),
                    1
                );
            }
            let mut out = Vec::new();
            assert_eq!(write_to(&mut out, &value, json, 2), 2);
            assert!(out.ends_with(b"\n"));
            assert_eq!(serde_json::from_slice::<Value>(&out).unwrap(), value);
        }
    }
}
