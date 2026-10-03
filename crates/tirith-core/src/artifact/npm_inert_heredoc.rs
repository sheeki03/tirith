//! Heredoc text a shell file provably only prints (a `usage()` message, a
//! `: <<'COMMENT'` block, help text read into a variable that is only echoed).
//!
//! The core tokenizer does not know heredocs, so every heredoc line reads as a
//! command and help text such as `curl URL | sh` looked like a download-to-
//! shell pipeline. [`mask`] blanks such bodies so the download pass treats
//! them like comments. It is deliberately narrow and all-or-nothing: if
//! ANYTHING in the file could route printed text or a variable back into a
//! shell (a pipe into anything but a plain text filter, a file redirection, a
//! command substitution around the printer, eval/source/exec/coproc/trap, a
//! shell or privilege wrapper, an alias or a redefined printer, `PATH`
//! changes, allexport), nothing is masked and every heredoc line is read as
//! before.
//!
//! Model boundary: what the CALLER does with this file's stdout, and a
//! non-shell interpreter evaluating text this file reads back from its own
//! source, are outside it, as they already are for comments and quoted
//! strings.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use crate::extract::PosixHeredocSpan;

/// Commands that only print (or discard) a heredoc fed to them.
const PRINTERS: &[&str] = &["cat", "echo", "printf", ":"];

/// Pipe stages that only write filtered text to stdout: no output-file
/// operand, no command execution.
const TEXT_FILTERS: &[&str] = &[
    "cat", "grep", "egrep", "fgrep", "head", "tail", "wc", "cut", "tr", "column", "fold", "fmt",
    "nl", "rev", "tac", "paste", "expand", "unexpand",
];

/// Redirection words allowed on a printer's header line and anywhere in the
/// file: they only reorder stdout/stderr or discard output.
const FD_REDIRECTS: &[&str] = &[
    ">&2",
    "1>&2",
    ">&1",
    "2>&1",
    ">/dev/null",
    "2>/dev/null",
    "1>/dev/null",
];

/// Words that evaluate text, change what a command name means, or start a
/// shell (which could read text back as code). Any of them anywhere disables
/// masking.
const EVALUATING_WORDS: &[&str] = &[
    "eval",
    "source",
    "exec",
    "coproc",
    "trap",
    "alias",
    "unalias",
    "enable",
    "hash",
    "declare",
    "typeset",
    "command_not_found_handle",
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "mksh",
    "ash",
    "yash",
    "posh",
    "fish",
    "csh",
    "tcsh",
    "busybox",
    "sudo",
    "su",
    "doas",
    "runuser",
    "pkexec",
];

/// Lines longer than this never hold an accepted variable print.
const MAX_LINE: usize = 4096;

/// More mentions of a captured variable than this are not checked one by
/// one; the heredoc stays live.
const MAX_VARIABLE_MENTIONS: usize = 64;

/// Prefixes allowed before a printer on its header line.
const HEADER_PREFIXES: &[&str] = &["{", "then", "do", "else"];

enum Shape {
    /// `cat <<EOF`: output goes to stdout/stderr.
    Printer,
    /// `NAME=$(cat <<EOF` ... `)`: `open` is the `$(` offset, `closer` the
    /// line holding the closing `)`.
    Capture {
        name: String,
        open: usize,
        closer: Range<usize>,
    },
    /// `read -r -d '' NAME <<EOF`.
    Read { name: String },
}

/// A shell file's heredocs, split into provably shown-only text and the rest.
#[derive(Default)]
pub(super) struct HeredocView {
    /// The text with every shown-only body and terminator blanked, when at
    /// least one was.
    pub(super) masked: Option<String>,
    /// Bodies that may be executed. The tokenizer can miss them as a whole
    /// (inside `eval "$(cat <<EOF ...)"` they sit in a quoted word), so the
    /// caller also scans each one on its own.
    pub(super) live_bodies: Vec<Range<usize>>,
    /// A heredoc whose boundaries are ambiguous (opened inside a quoted
    /// word, unterminated, oversized, a here-string): nothing is masked and
    /// the caller adds a line-by-line pass.
    pub(super) ambiguous: bool,
}

pub(super) fn analyze(text: &str) -> HeredocView {
    if !text.contains("<<") {
        return HeredocView::default();
    }
    let Some(spans) = crate::extract::posix_heredoc_spans(text) else {
        return HeredocView {
            ambiguous: true,
            ..HeredocView::default()
        };
    };
    // `<<` the heredoc parser did not take as an operator (inside a quoted
    // word, as in `eval "$(cat <<EOF`, or arithmetic) leaves its lines to
    // the tokenizer, which may see them only as one quoted word.
    let mut outside = text.as_bytes().to_vec();
    for span in &spans {
        blank(&mut outside, span.through_terminator.clone());
    }
    let outside = blank_comment_lines(&String::from_utf8_lossy(&outside));
    let operators = outside
        .matches("<<")
        .count()
        .saturating_sub(outside.matches("<<<").count());
    if operators != spans.len() {
        return HeredocView {
            ambiguous: true,
            ..HeredocView::default()
        };
    }
    match mask(text, &spans) {
        Some((masked, inert)) => HeredocView {
            masked: Some(masked),
            live_bodies: spans
                .iter()
                .filter(|span| !inert.contains(&span.body.start))
                .map(|span| span.body.clone())
                .collect(),
            ambiguous: false,
        },
        None => HeredocView {
            masked: None,
            live_bodies: spans.iter().map(|span| span.body.clone()).collect(),
            ambiguous: false,
        },
    }
}

/// The text with every provably-inert heredoc body (and terminator) blanked
/// and the start offsets of those bodies, or `None` when nothing may be
/// masked.
fn mask(text: &str, spans: &[PosixHeredocSpan]) -> Option<(String, BTreeSet<usize>)> {
    if spans.is_empty() {
        return None;
    }
    // Group heredocs by their header line.
    let mut headers: Vec<(Range<usize>, Vec<&PosixHeredocSpan>)> = Vec::new();
    for span in spans {
        match headers.last_mut() {
            Some((header, group)) if *header == span.header => group.push(span),
            _ => headers.push((span.header.clone(), vec![span])),
        }
    }

    let mut candidates: Vec<(Range<usize>, Shape, Vec<&PosixHeredocSpan>)> = Vec::new();
    for (header, group) in headers {
        if group.iter().any(|span| expands(text, span)) {
            continue;
        }
        let mut line = text.as_bytes()[header.clone()].to_vec();
        for span in &group {
            for byte in
                &mut line[span.operator.start - header.start..span.operator.end - header.start]
            {
                *byte = b' ';
            }
        }
        let Ok(line) = String::from_utf8(line) else {
            continue;
        };
        let last_end = group
            .last()
            .map_or(header.end, |span| span.through_terminator.end);
        if let Some(shape) = header_shape(text, &header, &line, last_end) {
            candidates.push((header, shape, group));
        }
    }
    if candidates.is_empty() {
        return None;
    }

    // The rest of the file: candidate bodies blanked, quote-free full-line
    // comments (shebang included) blanked. Capture and read headers stay
    // for the substitution check.
    let mut rest = text.as_bytes().to_vec();
    let mut masked = rest.clone();
    let mut names = Vec::new();
    // Capture `$(` offset -> the line holding its `)`.
    let mut captures = BTreeMap::new();
    let mut variable_lines = Vec::new();
    for (header, shape, group) in &candidates {
        for span in group {
            blank(&mut rest, span.through_terminator.clone());
            blank(&mut masked, span.through_terminator.clone());
        }
        match shape {
            Shape::Printer => {}
            Shape::Capture { name, open, closer } => {
                names.push(name.clone());
                captures.insert(*open, closer.clone());
                blank(&mut masked, header.clone());
                blank(&mut masked, closer.clone());
                variable_lines.push(header.clone());
                variable_lines.push(closer.clone());
            }
            Shape::Read { name } => {
                names.push(name.clone());
                blank(&mut masked, header.clone());
                variable_lines.push(header.clone());
            }
        }
    }
    let rest = blank_comment_lines(&String::from_utf8(rest).ok()?);
    let header_starts: Vec<usize> = candidates.iter().map(|(header, ..)| header.start).collect();
    if !rest_is_inert(&rest, &header_starts, &captures, &names) {
        return None;
    }
    // Variable uses: the assignments themselves are not uses, and a mention
    // inside another heredoc's body is data for an unknown consumer.
    let mut uses = rest.into_bytes();
    for line in variable_lines {
        blank(&mut uses, line);
    }
    let uses = String::from_utf8(uses).ok()?;
    let substitutions = substitution_ranges(&uses)?;
    let other_bodies: Vec<Range<usize>> = spans
        .iter()
        .filter(|span| {
            !candidates
                .iter()
                .any(|(_, _, group)| group.iter().any(|own| own.body == span.body))
        })
        .map(|span| span.body.clone())
        .collect();
    if !names
        .iter()
        .all(|name| variable_only_printed(&uses, name, &substitutions, &other_bodies))
    {
        return None;
    }
    let inert = candidates
        .iter()
        .flat_map(|(_, _, group)| group.iter().map(|span| span.body.start))
        .collect();
    Some((String::from_utf8(masked).ok()?, inert))
}

fn blank(bytes: &mut [u8], range: Range<usize>) {
    for byte in bytes.get_mut(range).into_iter().flatten() {
        if !matches!(*byte, b'\n' | b'\r') {
            *byte = b' ';
        }
    }
}

/// An unquoted body runs `$(...)`, backticks and `$[...]` when the heredoc is
/// read, so it is code whatever consumes it.
fn expands(text: &str, span: &PosixHeredocSpan) -> bool {
    let body = &text[span.body.clone()];
    !span.quoted && (body.contains('`') || body.contains("$(") || body.contains("$["))
}

fn is_name(word: &str) -> bool {
    let mut chars = word.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn header_shape(text: &str, header: &Range<usize>, line: &str, last_end: usize) -> Option<Shape> {
    let mut words: Vec<&str> = line.split_whitespace().collect();
    while words
        .first()
        .is_some_and(|word| HEADER_PREFIXES.contains(word))
    {
        words.remove(0);
    }
    let (&first, rest) = words.split_first()?;
    if PRINTERS.contains(&first) {
        return rest
            .iter()
            .all(|word| FD_REDIRECTS.contains(word))
            .then_some(Shape::Printer);
    }

    // `[local|readonly] NAME=$(cat` / `NAME="$(cat`, closed by a `)` line.
    let (assignment, rest) = match first {
        "local" | "readonly" => rest.split_first()?,
        _ => (&first, rest),
    };
    if let Some((name, value)) = assignment
        .split_once('=')
        .filter(|(_, value)| value.contains("$("))
    {
        let quoted = match value {
            "$(cat" => false,
            "\"$(cat" => true,
            _ => return None,
        };
        if !is_name(name) || !rest.iter().all(|word| FD_REDIRECTS.contains(word)) {
            return None;
        }
        let open = header.start + line.find("$(cat")?;
        let closer_start = last_end;
        let closer_end = text[closer_start..]
            .find('\n')
            .map_or(text.len(), |offset| closer_start + offset);
        let expected = if quoted { ")\"" } else { ")" };
        if text[closer_start..closer_end].trim() != expected {
            return None;
        }
        return Some(Shape::Capture {
            name: name.to_string(),
            open,
            closer: closer_start..closer_end,
        });
    }

    // `[IFS=] read [-r] [-d ''] NAME [|| true]`.
    let mut words = words.as_slice();
    if words.first() == Some(&"IFS=") {
        words = &words[1..];
    }
    let (&"read", mut words) = words.split_first()? else {
        return None;
    };
    if let [head @ .., "||", "true" | ":"] = words {
        words = head;
    }
    let (&name, flags) = words.split_last()?;
    let flags_ok = flags
        .iter()
        .all(|flag| matches!(*flag, "-r" | "-d" | "-rd" | "''" | "\"\""));
    (flags_ok && is_name(name)).then(|| Shape::Read {
        name: name.to_string(),
    })
}

/// Blank full-line comments that contain no quote or escape character. Such
/// a line cannot end a string, so whether it is a comment or string data,
/// this shell never runs it.
fn blank_comment_lines(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') && !line.contains(['"', '\'', '`', '\\']) {
            out.extend(line.chars().map(|c| if c == '\n' { '\n' } else { ' ' }));
        } else {
            out.push_str(line);
        }
    }
    out
}

/// Every `$(`, `<(`, `>(`, `=(` and backtick substitution, as byte ranges of
/// the opener through the closer. `None` when one does not close.
fn substitution_ranges(text: &str) -> Option<Vec<Range<usize>>> {
    let bytes = text.as_bytes();
    let mut ranges = Vec::new();
    let mut backtick_closers = BTreeSet::new();
    for index in 0..bytes.len() {
        if bytes[index] == b'`' {
            if (index > 0 && bytes[index - 1] == b'\\') || backtick_closers.contains(&index) {
                continue;
            }
            let close = crate::extract::posix_backtick_close(text, index)?;
            backtick_closers.insert(close);
            ranges.push(index..close + 1);
        } else if bytes[index] == b'('
            && index > 0
            && matches!(bytes[index - 1], b'$' | b'<' | b'>' | b'=')
        {
            let close = crate::extract::posix_delimiter_close(text, index)?;
            ranges.push(index - 1..close + 1);
        }
    }
    Some(ranges)
}

fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '+')))
        .filter(|word| !word.is_empty())
}

fn function_names(text: &str) -> BTreeSet<String> {
    static DEFINITION: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(
            r"(?m)(?:^|[;&|{(\s])(?:function\s+)?([A-Za-z_:.][A-Za-z0-9_:.+-]*)\s*\(\s*\)|(?:^|[;&|{(\s])function\s+([A-Za-z_:.][A-Za-z0-9_:.+-]*)",
        )
        .expect("static regex")
    });
    DEFINITION
        .captures_iter(text)
        .filter_map(|captures| captures.get(1).or_else(|| captures.get(2)))
        .map(|name| name.as_str().to_string())
        .collect()
}

/// The global conditions, checked on the rest of the file.
fn rest_is_inert(
    rest: &str,
    header_starts: &[usize],
    captures: &BTreeMap<usize, Range<usize>>,
    names: &[String],
) -> bool {
    // Nothing evaluates text, starts a shell or rebinds a command name.
    if words(rest).any(|word| EVALUATING_WORDS.contains(&word) || word == "allexport")
        || assigns_path(rest)
        || dot_command(rest)
        || line_has_flag(rest, "set", 'a')
        || line_has_flag(rest, "export", 'f')
    {
        return false;
    }
    let functions = function_names(rest);
    if functions
        .iter()
        .any(|name| PRINTERS.contains(&name.as_str()) || TEXT_FILTERS.contains(&name.as_str()))
    {
        return false;
    }
    if !pipes_only_filter(rest) || !redirects_only_reorder(rest) {
        return false;
    }
    // No printed text is captured: no printer, function or inert variable
    // inside a substitution, and no candidate header inside one other than
    // its own capture.
    let Some(substitutions) = substitution_ranges(rest) else {
        return false;
    };
    for range in &substitutions {
        if let Some(closer) = captures.get(&range.start) {
            // A capture holds exactly its own heredoc: it closes on its
            // closer line and nothing else opens inside it.
            if !closer.contains(&(range.end - 1))
                || substitutions
                    .iter()
                    .any(|other| other.start > range.start && other.start < range.end)
            {
                return false;
            }
            continue;
        }
        if header_starts.iter().any(|start| range.contains(start)) {
            return false;
        }
        let body = &rest[range.clone()];
        if words(body).any(|word| {
            PRINTERS.contains(&word)
                || functions.contains(word)
                || names.iter().any(|name| name == word)
        }) {
            return false;
        }
    }
    // Every capture was found as a substitution.
    captures
        .keys()
        .all(|open| substitutions.iter().any(|range| range.start == *open))
}

/// `PATH=` / `PATH+=` anywhere (`export PATH=...`, `PATH=x cmd`).
fn assigns_path(text: &str) -> bool {
    text.match_indices("PATH").any(|(at, _)| {
        let before = text[..at].chars().next_back();
        !before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
            && (text[at + 4..].starts_with('=') || text[at + 4..].starts_with("+="))
    })
}

/// `.` (source) in command position.
fn dot_command(text: &str) -> bool {
    let bytes = text.as_bytes();
    (0..bytes.len()).any(|index| {
        bytes[index] == b'.'
            && bytes
                .get(index + 1)
                .is_none_or(|next| next.is_ascii_whitespace())
            && text[..index]
                .trim_end_matches([' ', '\t'])
                .chars()
                .next_back()
                .is_none_or(|previous| matches!(previous, '\n' | ';' | '&' | '|' | '(' | '{' | '!'))
            || bytes[index] == b'.'
                && bytes
                    .get(index + 1)
                    .is_none_or(|next| next.is_ascii_whitespace())
                && ["then", "do", "else", "elif", "if", "while", "until", "time"]
                    .iter()
                    .any(|keyword| {
                        text[..index]
                            .trim_end_matches([' ', '\t'])
                            .rsplit(|c: char| c.is_whitespace() || c == ';')
                            .next()
                            == Some(keyword)
                    })
    })
}

/// `command` followed on its line by a short-option word holding `flag`:
/// `set -a`, `set -ea` (allexport; `set -o allexport` is caught by the
/// word), `export -f` / `export -nf` (exported functions).
fn line_has_flag(text: &str, command: &str, flag: char) -> bool {
    text.lines().any(|line| {
        let mut words = line.split_whitespace().skip_while(|word| *word != command);
        words.next().is_some()
            && words.any(|word| {
                (word.starts_with('-') || word.starts_with('+'))
                    && !word.starts_with("--")
                    && word[1..].contains(flag)
            })
    })
}

/// Every `|` / `|&` feeds a plain text filter, or separates `case` patterns.
fn pipes_only_filter(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'|' {
            index += 1;
            continue;
        }
        if bytes.get(index + 1) == Some(&b'|') {
            index += 2;
            continue;
        }
        let mut next = index + 1;
        if bytes.get(next) == Some(&b'&') {
            next += 1;
        }
        let after = text[next..].trim_start_matches(|c: char| c.is_whitespace() || c == '\\');
        let word_end = after
            .find(|c: char| c.is_whitespace() || matches!(c, ';' | '|' | '&' | ')' | '<' | '>'))
            .unwrap_or(after.len());
        if TEXT_FILTERS.contains(&&after[..word_end]) {
            index = next;
            continue;
        }
        match case_pattern_alternative(bytes, index) {
            Some(close) => index = close + 1,
            None => return false,
        }
    }
    true
}

/// Characters a simple `case` pattern alternative may hold.
fn pattern_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-_.*?\"'=+,:/~@%[]!|".contains(&byte)
}

/// `-h|--help)` in a `case` arm list: a pattern of plain pattern characters
/// up to its `)`, starting right after `case WORD in` or a `;;` / `;&` arm
/// end, on its own line or the previous line. Outside a case statement that
/// shape is a syntax error, so nothing in it runs. Returns the offset of
/// the pattern's `)`. Every scan is local to the pattern and the line(s)
/// right before it.
fn case_pattern_alternative(bytes: &[u8], bar: usize) -> Option<usize> {
    let mut start = bar;
    while start > 0 && pattern_byte(bytes[start - 1]) {
        start -= 1;
    }
    let mut close = bar + 1;
    while close < bytes.len() && pattern_byte(bytes[close]) {
        close += 1;
    }
    if start == bar || bytes[start] == b'|' || bytes.get(close) != Some(&b')') {
        return None;
    }
    let blank = |byte: u8| matches!(byte, b' ' | b'\t');
    let mut before = start;
    while before > 0 && blank(bytes[before - 1]) {
        before -= 1;
    }
    let arm_end = |end: usize| end >= 2 && matches!(&bytes[end - 2..end], b";;" | b";&");
    if arm_end(before) || after_case_in(bytes, before) {
        return Some(close);
    }
    if before > 0 && bytes[before - 1] != b'\n' {
        return None;
    }
    // The pattern starts its line: the previous non-blank line must end an
    // arm or be `case WORD in`.
    let mut end = before;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    (end > 0 && (arm_end(end) || after_case_in(bytes, end))).then_some(close)
}

/// Whether `bytes[..end]` ends with `case WORD in` that starts its line.
fn after_case_in(bytes: &[u8], end: usize) -> bool {
    let Some(rest) = end.checked_sub(2) else {
        return false;
    };
    if &bytes[rest..end] != b"in" || rest == 0 || !matches!(bytes[rest - 1], b' ' | b'\t') {
        return false;
    }
    let mut cursor = rest - 1;
    while cursor > 0 && matches!(bytes[cursor - 1], b' ' | b'\t') {
        cursor -= 1;
    }
    let word_end = cursor;
    while cursor > 0 && !bytes[cursor - 1].is_ascii_whitespace() && word_end - cursor <= 256 {
        cursor -= 1;
    }
    if cursor == word_end || word_end - cursor > 256 {
        return false;
    }
    let Some(keyword) = cursor.checked_sub(5) else {
        return false;
    };
    if &bytes[keyword..cursor] != b"case " {
        return false;
    }
    let mut line = keyword;
    while line > 0 && matches!(bytes[line - 1], b' ' | b'\t') {
        line -= 1;
    }
    line == 0 || bytes[line - 1] == b'\n'
}

/// Every `>` only reorders stdout/stderr or discards output.
fn redirects_only_reorder(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'>' {
            index += 1;
            continue;
        }
        let mut next = index + 1;
        if bytes.get(next) == Some(&b'>') {
            next += 1;
        }
        let ok = if bytes.get(next) == Some(&b'&') {
            matches!(bytes.get(next + 1), Some(b'1' | b'2'))
                && !bytes.get(next + 2).is_some_and(u8::is_ascii_alphanumeric)
        } else {
            let target = text[next..].trim_start_matches([' ', '\t']);
            ["/dev/null", "/dev/stderr", "/dev/stdout"]
                .iter()
                .any(|path| {
                    target.strip_prefix(path).is_some_and(|after| {
                        after
                            .chars()
                            .next()
                            .is_none_or(|c| c.is_whitespace() || matches!(c, ';' | '&' | '|' | ')'))
                    })
                })
        };
        if !ok {
            return false;
        }
        index = next;
    }
    true
}

/// Every mention of `name` is a plain `$name` / `${name}` expansion in an
/// `echo` or `printf` (without `-v`) command, outside any substitution and
/// any other heredoc's body.
fn variable_only_printed(
    text: &str,
    name: &str,
    substitutions: &[Range<usize>],
    other_bodies: &[Range<usize>],
) -> bool {
    let bytes = text.as_bytes();
    let ident = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let mut search = 0usize;
    let mut mentions = 0usize;
    while let Some(offset) = text[search..].find(name) {
        let at = search + offset;
        mentions += 1;
        if mentions > MAX_VARIABLE_MENTIONS {
            return false;
        }
        let end = at + name.len();
        search = end;
        if (at > 0 && ident(bytes[at - 1])) || bytes.get(end).copied().is_some_and(ident) {
            continue;
        }
        let plain = (at >= 1 && bytes[at - 1] == b'$')
            || (at >= 2 && &bytes[at - 2..at] == b"${" && bytes.get(end) == Some(&b'}'));
        if !plain {
            return false;
        }
        if substitutions
            .iter()
            .chain(other_bodies)
            .any(|range| range.contains(&at))
        {
            return false;
        }
        // The command around it, split at `;`, `&&`, `||` and newlines.
        let line_start = text[..at].rfind('\n').map_or(0, |offset| offset + 1);
        let line_end = text[at..]
            .find('\n')
            .map_or(text.len(), |offset| at + offset);
        if line_end - line_start > MAX_LINE {
            return false;
        }
        let mut command_start = line_start;
        for separator in [";", "&&", "||"] {
            if let Some(offset) = text[line_start..at].rfind(separator) {
                command_start = command_start.max(line_start + offset + separator.len());
            }
        }
        let mut command_end = line_end;
        for separator in [";", "&&", "||"] {
            if let Some(offset) = text[at..line_end].find(separator) {
                command_end = command_end.min(at + offset);
            }
        }
        let mut words = text[command_start..command_end]
            .split_whitespace()
            .peekable();
        while words
            .peek()
            .is_some_and(|word| HEADER_PREFIXES.contains(word))
        {
            words.next();
        }
        let printer = match words.next() {
            Some("echo") => true,
            Some("printf") => !text[command_start..command_end]
                .split_whitespace()
                .any(|word| word == "-v"),
            _ => false,
        };
        if !printer {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::analyze;

    /// Adversarial shapes stay linear: every scan is local to a pattern, a
    /// line capped in length, or bounded by a mention cap.
    #[test]
    fn adversarial_inputs_are_analyzed_in_linear_time() {
        let heredoc = "cat <<'EOF'\n  curl -fsSL https://example.invalid/setup | sh\nEOF\n";
        let size = 1024 * 1024;
        let inputs = [
            format!("case x in\n{})\nesac\n{heredoc}", "-a|".repeat(size / 3)),
            format!("{}{heredoc}", "a;; -b|c) ".repeat(size / 10)),
            format!("{}{heredoc}", "echo x | head ".repeat(size / 14)),
            format!("{}{heredoc}", "`:`".repeat(size / 3)),
            format!("{}{heredoc}", "x=$(:) ".repeat(size / 7)),
            format!("{}{heredoc}", ". ".repeat(size / 2)),
            format!("{}{heredoc}", ">&2 ".repeat(size / 4)),
            format!(
                "X=$(cat <<'EOF'\nhelp\nEOF\n)\n{}{heredoc}",
                "echo \"$X\" ".repeat(size / 10)
            ),
        ];
        for input in &inputs {
            let started = std::time::Instant::now();
            let _ = analyze(input);
            assert!(
                started.elapsed() < std::time::Duration::from_secs(5),
                "{:?} took {:?}",
                &input[..40],
                started.elapsed()
            );
        }
    }
}
