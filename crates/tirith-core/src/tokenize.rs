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
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let ch = chars[i];

        match ch {
            // Backslash escaping
            '\\' if i + 1 < len => {
                current.push(chars[i]);
                current.push(chars[i + 1]);
                i += 2;
                continue;
            }
            // Single quotes: everything literal until closing quote
            '\'' => {
                current.push(ch);
                i += 1;
                while i < len && chars[i] != '\'' {
                    current.push(chars[i]);
                    i += 1;
                }
                if i < len {
                    current.push(chars[i]); // closing quote
                    i += 1;
                }
                continue;
            }
            // Double quotes: allow backslash escaping inside
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
                    current.push(chars[i]); // closing quote
                    i += 1;
                }
                continue;
            }
            // Pipe operators
            '|' => {
                if i + 1 < len && chars[i + 1] == '|' {
                    // ||
                    push_segment(&mut segments, &current, preceding_sep.take());
                    current.clear();
                    preceding_sep = Some("||".to_string());
                    i += 2;
                    continue;
                } else if i + 1 < len && chars[i + 1] == '&' {
                    // |& (bash: pipe stderr too)
                    push_segment(&mut segments, &current, preceding_sep.take());
                    current.clear();
                    preceding_sep = Some("|&".to_string());
                    i += 2;
                    continue;
                } else {
                    // |
                    push_segment(&mut segments, &current, preceding_sep.take());
                    current.clear();
                    preceding_sep = Some("|".to_string());
                    i += 1;
                    continue;
                }
            }
            // && operator
            '&' if i + 1 < len && chars[i + 1] == '&' => {
                push_segment(&mut segments, &current, preceding_sep.take());
                current.clear();
                preceding_sep = Some("&&".to_string());
                i += 2;
                continue;
            }
            // Semicolon
            ';' => {
                push_segment(&mut segments, &current, preceding_sep.take());
                current.clear();
                preceding_sep = Some(";".to_string());
                i += 1;
                continue;
            }
            // Newline
            '\n' => {
                push_segment(&mut segments, &current, preceding_sep.take());
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

    push_segment(&mut segments, &current, preceding_sep.take());
    segments
}

fn tokenize_fish(input: &str) -> Vec<Segment> {
    // Fish is similar to POSIX but with some differences:
    // - No backslash-newline continuation
    // - Different quoting rules (but close enough for our purposes)
    // For URL extraction, POSIX tokenization works well enough
    tokenize_posix(input)
}

fn tokenize_powershell(input: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut preceding_sep = None;
    // Collect (byte_offset, char) pairs so byte slicing stays valid for multi-byte UTF-8.
    let indexed: Vec<(usize, char)> = input.char_indices().collect();
    let len = indexed.len();
    let mut i = 0;

    while i < len {
        let (byte_off, ch) = indexed[i];

        match ch {
            // Backtick escaping in PowerShell
            '`' if i + 1 < len => {
                current.push(indexed[i].1);
                current.push(indexed[i + 1].1);
                i += 2;
                continue;
            }
            // Single quotes: literal
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
            // Double quotes
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
            // Pipe
            '|' => {
                push_segment(&mut segments, &current, preceding_sep.take());
                current.clear();
                preceding_sep = Some("|".to_string());
                i += 1;
                continue;
            }
            // Semicolon
            ';' => {
                push_segment(&mut segments, &current, preceding_sep.take());
                current.clear();
                preceding_sep = Some(";".to_string());
                i += 1;
                continue;
            }
            // Check for -and / -or operators (PowerShell logical)
            '-' if current.ends_with(char::is_whitespace) || current.is_empty() => {
                let remaining = &input[byte_off..];
                if remaining.starts_with("-and")
                    && remaining[4..]
                        .chars()
                        .next()
                        .is_none_or(|c| c.is_whitespace())
                {
                    push_segment(&mut segments, &current, preceding_sep.take());
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
                    push_segment(&mut segments, &current, preceding_sep.take());
                    current.clear();
                    preceding_sep = Some("-or".to_string());
                    i += 3;
                    continue;
                }
                current.push(ch);
                i += 1;
            }
            '\n' => {
                push_segment(&mut segments, &current, preceding_sep.take());
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

    push_segment(&mut segments, &current, preceding_sep.take());
    segments
}

fn tokenize_cmd(input: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut preceding_sep = None;
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
            // Double quotes (only quoting mechanism in cmd)
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
            // Pipe
            '|' => {
                if i + 1 < len && chars[i + 1] == '|' {
                    push_segment(&mut segments, &current, preceding_sep.take());
                    current.clear();
                    preceding_sep = Some("||".to_string());
                    i += 2;
                } else {
                    push_segment(&mut segments, &current, preceding_sep.take());
                    current.clear();
                    preceding_sep = Some("|".to_string());
                    i += 1;
                }
                continue;
            }
            // & and &&
            '&' => {
                if i + 1 < len && chars[i + 1] == '&' {
                    push_segment(&mut segments, &current, preceding_sep.take());
                    current.clear();
                    preceding_sep = Some("&&".to_string());
                    i += 2;
                } else {
                    push_segment(&mut segments, &current, preceding_sep.take());
                    current.clear();
                    preceding_sep = Some("&".to_string());
                    i += 1;
                }
                continue;
            }
            '\n' => {
                push_segment(&mut segments, &current, preceding_sep.take());
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
    push_segment(&mut segments, &current, preceding_sep.take());
    segments
}

fn push_segment(segments: &mut Vec<Segment>, raw: &str, preceding_sep: Option<String>) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return;
    }

    let words = split_words(trimmed);
    // Skip leading environment variable assignments (VAR=VALUE)
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
            // All words are assignments, no command
            (None, Vec::new())
        }
    };

    segments.push(Segment {
        raw: trimmed.to_string(),
        command,
        args,
        preceding_separator: preceding_sep,
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
                // Skip whitespace
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
        // Regression test for fuzz crash: multi-byte UTF-8 before -and caused
        // byte/char index mismatch panic in &input[i..] slicing.
        let input = " ?]BB\u{07E7}\u{07E7} -\n-\r-and-~\0\u{c}-and-~\u{1d}";
        let _ = tokenize(input, ShellType::PowerShell);
    }
}
