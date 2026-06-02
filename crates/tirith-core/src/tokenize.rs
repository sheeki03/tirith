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
    match shell {
        ShellType::Posix => tokenize_posix(input),
        ShellType::Fish => tokenize_fish(input),
        ShellType::PowerShell => tokenize_powershell(input),
        ShellType::Cmd => tokenize_cmd(input),
    }
}

fn tokenize_posix(input: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut preceding_sep = None;
    let mut search_cursor: usize = 0;
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let ch = chars[i];

        match ch {
            '\\' if i + 1 < len => {
                current.push(chars[i]);
                current.push(chars[i + 1]);
                i += 2;
                continue;
            }
            // Single quotes: everything literal until the closing quote.
            '\'' => {
                current.push(ch);
                i += 1;
                while i < len && chars[i] != '\'' {
                    current.push(chars[i]);
                    i += 1;
                }
                if i < len {
                    current.push(chars[i]);
                    i += 1;
                }
                continue;
            }
            // Double quotes: backslash escaping allowed inside.
            '"' => {
                current.push(ch);
                i += 1;
                while i < len && chars[i] != '"' {
                    if chars[i] == '\\' && i + 1 < len {
                        current.push(chars[i]);
                        current.push(chars[i + 1]);
                        i += 2;
                    } else {
                        current.push(chars[i]);
                        i += 1;
                    }
                }
                if i < len {
                    current.push(chars[i]);
                    i += 1;
                }
                continue;
            }
            '|' => {
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
                    continue;
                } else if i + 1 < len && chars[i + 1] == '&' {
                    // |& (bash: pipe stderr too)
                    push_segment(
                        &mut segments,
                        &current,
                        preceding_sep.take(),
                        input,
                        &mut search_cursor,
                    );
                    current.clear();
                    preceding_sep = Some("|&".to_string());
                    i += 2;
                    continue;
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
                    continue;
                }
            }
            '&' if i + 1 < len && chars[i + 1] == '&' => {
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
                continue;
            }
            ';' => {
                push_segment(
                    &mut segments,
                    &current,
                    preceding_sep.take(),
                    input,
                    &mut search_cursor,
                );
                current.clear();
                preceding_sep = Some(";".to_string());
                i += 1;
                continue;
            }
            '\n' => {
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
    segments
}

fn tokenize_fish(input: &str) -> Vec<Segment> {
    // Fish differs slightly from POSIX, but POSIX tokenization is close enough
    // for URL extraction.
    tokenize_posix(input)
}

fn tokenize_powershell(input: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut preceding_sep = None;
    let mut search_cursor: usize = 0;
    // Collect (byte_offset, char) pairs so byte slicing stays valid for multi-byte UTF-8.
    let indexed: Vec<(usize, char)> = input.char_indices().collect();
    let len = indexed.len();
    let mut i = 0;

    while i < len {
        let (byte_off, ch) = indexed[i];

        match ch {
            // Backtick escaping in PowerShell.
            '`' if i + 1 < len => {
                current.push(indexed[i].1);
                current.push(indexed[i + 1].1);
                i += 2;
                continue;
            }
            // Single quotes: literal.
            '\'' => {
                current.push(ch);
                i += 1;
                while i < len && indexed[i].1 != '\'' {
                    current.push(indexed[i].1);
                    i += 1;
                }
                if i < len {
                    current.push(indexed[i].1);
                    i += 1;
                }
                continue;
            }
            '"' => {
                current.push(ch);
                i += 1;
                while i < len && indexed[i].1 != '"' {
                    if indexed[i].1 == '`' && i + 1 < len {
                        current.push(indexed[i].1);
                        current.push(indexed[i + 1].1);
                        i += 2;
                    } else {
                        current.push(indexed[i].1);
                        i += 1;
                    }
                }
                if i < len {
                    current.push(indexed[i].1);
                    i += 1;
                }
                continue;
            }
            '|' => {
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
                preceding_sep = Some("|".to_string());
                i += 1;
                continue;
            }
            ';' => {
                push_segment(
                    &mut segments,
                    &current,
                    preceding_sep.take(),
                    input,
                    &mut search_cursor,
                );
                current.clear();
                preceding_sep = Some(";".to_string());
                i += 1;
                continue;
            }
            // PS 7+ `&&` chain op. The arm guard lets a bare `&` (PS
            // call/background operator) fall through to the catch-all.
            '&' if i + 1 < len && indexed[i + 1].1 == '&' => {
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
                continue;
            }
            // PowerShell logical `-and` / `-or` operators.
            '-' if current.ends_with(char::is_whitespace) || current.is_empty() => {
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
                    preceding_sep = Some("-or".to_string());
                    i += 3;
                    continue;
                }
                current.push(ch);
                i += 1;
            }
            '\n' => {
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
    segments
}

fn tokenize_cmd(input: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut preceding_sep = None;
    let mut search_cursor: usize = 0;
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
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
            '|' => {
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
            '&' => {
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
            '\n' => {
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
    segments
}

/// Push a tokenized segment into `segments`, trimming leading/trailing
/// whitespace and locating the trimmed content in `input` to populate
/// `byte_range`.
///
/// `search_cursor` is advanced past the pushed segment so subsequent
/// searches skip already-consumed bytes (handles duplicate segments like
/// `foo | foo` correctly).
fn push_segment(
    segments: &mut Vec<Segment>,
    raw: &str,
    preceding_sep: Option<String>,
    input: &str,
    search_cursor: &mut usize,
) {
    let trimmed = raw.trim();
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

    let words = split_words(trimmed);
    // Skip leading `VAR=VALUE` assignments.
    let first_non_assign = words.iter().position(|w| !is_env_assignment(w));
    let (command, args) = match first_non_assign {
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
    let s = word.trim();
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
    let mut assignments = Vec::new();
    for word in split_words(segment_raw.trim()) {
        if !is_env_assignment(&word) {
            break;
        }
        if let Some((name, value)) = word.split_once('=') {
            assignments.push((name.to_string(), value.to_string()));
        }
    }
    assignments
}

/// Return the values from leading `NAME=VALUE` tokens in a raw segment.
/// Stops at the first non-assignment word, matching the shell prefix-assignment model.
pub fn leading_env_assignment_values(segment_raw: &str) -> Vec<String> {
    leading_env_assignments(segment_raw)
        .into_iter()
        .map(|(_, value)| value)
        .collect()
}

/// Split a segment into words, respecting quotes.
fn split_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let ch = chars[i];
        match ch {
            ' ' | '\t' if !current.is_empty() => {
                words.push(current.clone());
                current.clear();
                i += 1;
                while i < len && (chars[i] == ' ' || chars[i] == '\t') {
                    i += 1;
                }
            }
            ' ' | '\t' => {
                i += 1;
            }
            '\'' => {
                current.push(ch);
                i += 1;
                while i < len && chars[i] != '\'' {
                    current.push(chars[i]);
                    i += 1;
                }
                if i < len {
                    current.push(chars[i]);
                    i += 1;
                }
            }
            '"' => {
                current.push(ch);
                i += 1;
                while i < len && chars[i] != '"' {
                    if chars[i] == '\\' && i + 1 < len {
                        current.push(chars[i]);
                        current.push(chars[i + 1]);
                        i += 2;
                    } else {
                        current.push(chars[i]);
                        i += 1;
                    }
                }
                if i < len {
                    current.push(chars[i]);
                    i += 1;
                }
            }
            '\\' if i + 1 < len => {
                current.push(chars[i]);
                current.push(chars[i + 1]);
                i += 2;
            }
            _ => {
                current.push(ch);
                i += 1;
            }
        }
    }

    if !current.is_empty() {
        words.push(current);
    }

    words
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
    fn ps_tokenizer_bare_single_ampersand_not_separator() {
        // Bare `&` (PS call / background operator) is NOT a chain operator on
        // its own. Single `&` must fall through to the catch-all and be part
        // of the current segment, so this tokenizes as ONE segment.
        let segs = tokenize("Get-Job & Get-Process", ShellType::PowerShell);
        assert_eq!(
            segs.len(),
            1,
            "expected 1 segment (single & is not a separator), got {:?}",
            segs
        );
    }

    #[test]
    fn test_single_quotes() {
        let segs = tokenize("echo 'hello | world' | bash", ShellType::Posix);
        assert_eq!(segs.len(), 2);
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
