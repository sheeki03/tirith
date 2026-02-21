use serde::{Deserialize, Serialize};

/// Shell type for tokenization rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShellType {
    Posix,
    Fish,
    PowerShell,
}

impl std::str::FromStr for ShellType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "posix" | "bash" | "zsh" | "sh" => Ok(ShellType::Posix),
            "fish" => Ok(ShellType::Fish),
            "powershell" | "pwsh" => Ok(ShellType::PowerShell),
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
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let ch = chars[i];

        match ch {
            // Backtick escaping in PowerShell
            '`' if i + 1 < len => {
                current.push(chars[i]);
                current.push(chars[i + 1]);
                i += 2;
                continue;
            }
            // Single quotes: literal
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
            // Double quotes
            '"' => {
                current.push(ch);
                i += 1;
                while i < len && chars[i] != '"' {
                    if chars[i] == '`' && i + 1 < len {
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
                let remaining = &input[i..];
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
        None => (None, Vec::new()),
    };

    segments.push(Segment {
        raw: trimmed.to_string(),
        command,
        args,
        preceding_separator: preceding_sep,
    });
}


/// Check if a word looks like an environment variable assignment (VAR=VALUE).
pub fn is_env_assignment(word: &str) -> bool {
    let s = word.trim();
    // Strip outer quotes if present
    let s = if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"'))
            || (s.starts_with(''') && s.ends_with(''')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    };

    // Must not start with - or =
    if s.starts_with('-') || s.starts_with('=') {
        return false;
    }

    // Must contain = with valid identifier chars before it
    if let Some(eq_pos) = s.find('=') {
        if eq_pos == 0 {
            return false;
        }
        let name = &s[..eq_pos];
        name.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    } else {
        false
    }
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
}
