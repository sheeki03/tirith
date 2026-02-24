use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;

/// Result of static script analysis.
#[derive(Debug, Clone, Serialize)]
pub struct ScriptAnalysis {
    pub domains_referenced: Vec<String>,
    pub paths_referenced: Vec<String>,
    pub has_sudo: bool,
    pub has_eval: bool,
    pub has_base64: bool,
    pub has_curl_wget: bool,
    pub interpreter: String,
}

static DOMAIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)").unwrap()
});

static PATH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:/(?:usr|etc|var|tmp|opt|home|root|bin|sbin|lib|dev)(?:/[\w.-]+)+)").unwrap()
});

/// Perform static analysis on script content.
pub fn analyze(content: &str, interpreter: &str) -> ScriptAnalysis {
    let mut domains = Vec::new();
    for cap in DOMAIN_RE.captures_iter(content) {
        if let Some(m) = cap.get(1) {
            let domain = m.as_str().to_string();
            if !domains.contains(&domain) {
                domains.push(domain);
            }
        }
    }

    let mut paths = Vec::new();
    for mat in PATH_RE.find_iter(content) {
        let path = mat.as_str().to_string();
        if !paths.contains(&path) {
            paths.push(path);
        }
    }

    ScriptAnalysis {
        domains_referenced: domains,
        paths_referenced: paths,
        has_sudo: content.contains("sudo "),
        has_eval: content.contains("eval ") || content.contains("eval("),
        has_base64: content.contains("base64"),
        has_curl_wget: content.contains("curl ")
            || content.contains("wget ")
            || content.contains("http ")
            || content.contains("https ")
            || content.contains("xh "),
        interpreter: interpreter.to_string(),
    }
}

/// Detect interpreter from shebang line.
pub fn detect_interpreter(content: &str) -> &str {
    if let Some(first_line) = content.lines().next() {
        let first_line = first_line.trim();
        if first_line.starts_with("#!") {
            let shebang = first_line.trim_start_matches("#!");
            let parts: Vec<&str> = shebang.split_whitespace().collect();
            if let Some(prog) = parts.first() {
                let base = prog.rsplit('/').next().unwrap_or(prog);
                if base == "env" {
                    // Skip flags (-S, -i, etc.) and VAR=val assignments
                    for part in parts.iter().skip(1) {
                        if part.starts_with('-') || part.contains('=') {
                            continue;
                        }
                        return part;
                    }
                } else {
                    return base;
                }
            }
        }
    }
    "sh" // default
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_interpreter_env_s() {
        let content = "#!/usr/bin/env -S python3 -u\nprint('hello')";
        assert_eq!(detect_interpreter(content), "python3");
    }

    #[test]
    fn test_detect_interpreter_env_s_with_var() {
        let content = "#!/usr/bin/env -S VAR=1 python3\nprint('hello')";
        assert_eq!(detect_interpreter(content), "python3");
    }

    #[test]
    fn test_detect_interpreter_crlf() {
        let content = "#!/bin/bash\r\necho hello";
        assert_eq!(detect_interpreter(content), "bash");
    }

    #[test]
    fn test_detect_interpreter_basic() {
        let content = "#!/usr/bin/env python3\nprint('hello')";
        assert_eq!(detect_interpreter(content), "python3");
    }

    #[test]
    fn test_detect_interpreter_no_shebang() {
        let content = "echo hello";
        assert_eq!(detect_interpreter(content), "sh");
    }
}
