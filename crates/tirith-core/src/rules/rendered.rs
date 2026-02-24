use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Check rendered content (HTML/Markdown) for hidden content attacks.
///
/// Detection is free for all tiers (ADR-13). Pro enrichment (human_view/
/// agent_view, decoded hidden text) is populated by the engine enrichment pass.
pub fn check(input: &str, file_path: Option<&std::path::Path>) -> Vec<Finding> {
    let mut findings = Vec::new();

    check_css_hiding(input, &mut findings);
    check_color_hiding(input, &mut findings);
    check_html_hidden_attributes(input, &mut findings);
    check_html_comments(input, file_path, &mut findings);
    check_markdown_comments(input, file_path, &mut findings);

    findings
}

/// Returns true if a file path has a renderable extension that should trigger
/// rendered content scanning.
pub fn is_renderable_file(path: Option<&std::path::Path>) -> bool {
    let path = match path {
        Some(p) => p,
        None => return false,
    };
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    matches!(ext.as_str(), "md" | "html" | "htm" | "xhtml" | "pdf")
}

// ---------------------------------------------------------------------------
// CSS hiding detection
// ---------------------------------------------------------------------------

/// 6 CSS hiding patterns that conceal content from visual rendering.
fn check_css_hiding(input: &str, findings: &mut Vec<Finding>) {
    use once_cell::sync::Lazy;
    use regex::Regex;

    static CSS_PATTERNS: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
        vec![
            (
                Regex::new(r#"(?i)display\s*:\s*none"#).unwrap(),
                "display:none",
            ),
            (
                Regex::new(r#"(?i)visibility\s*:\s*hidden"#).unwrap(),
                "visibility:hidden",
            ),
            (
                Regex::new(r#"(?i)opacity\s*:\s*0(?:[;\s\}"]|$)"#).unwrap(),
                "opacity:0",
            ),
            (
                Regex::new(r#"(?i)font-size\s*:\s*0(?:px|em|rem|pt|%)?(?:[;\s\}"]|$)"#).unwrap(),
                "font-size:0",
            ),
            (
                Regex::new(r#"(?i)clip\s*:\s*rect\s*\(\s*0"#).unwrap(),
                "clip:rect(0...)",
            ),
            (
                Regex::new(r#"(?i)position\s*:\s*(?:absolute|fixed)[^;]*(?:left|top)\s*:\s*-9999"#)
                    .unwrap(),
                "off-screen positioning",
            ),
        ]
    });

    for (pattern, technique) in CSS_PATTERNS.iter() {
        let matches: Vec<_> = pattern.find_iter(input).collect();
        if !matches.is_empty() {
            let line_num = line_number_of(input, matches[0].start());
            findings.push(Finding {
                rule_id: RuleId::HiddenCssContent,
                severity: Severity::High,
                title: "Hidden content via CSS".to_string(),
                description: format!(
                    "Content hidden using CSS technique: {technique} ({} occurrence{})",
                    matches.len(),
                    if matches.len() == 1 { "" } else { "s" }
                ),
                evidence: matches
                    .iter()
                    .map(|m| Evidence::Text {
                        detail: format!(
                            "line {}: {}",
                            line_number_of(input, m.start()),
                            m.as_str()
                        ),
                    })
                    .collect(),
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });

            // Only report first CSS technique per finding (avoid flood)
            _ = line_num;
            break;
        }
    }

    // Check for multiple CSS hiding techniques (compound hiding is more suspicious)
    let technique_count = CSS_PATTERNS
        .iter()
        .filter(|(p, _)| p.is_match(input))
        .count();
    if technique_count >= 2 {
        findings.push(Finding {
            rule_id: RuleId::HiddenCssContent,
            severity: Severity::Critical,
            title: "Multiple CSS hiding techniques detected".to_string(),
            description: format!(
                "{technique_count} different CSS hiding techniques used — likely deliberate content concealment"
            ),
            evidence: CSS_PATTERNS
                .iter()
                .filter(|(p, _)| p.is_match(input))
                .map(|(_, technique)| Evidence::Text {
                    detail: format!("technique: {technique}"),
                })
                .collect(),
            human_view: None,
            agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
        });
    }
}

// ---------------------------------------------------------------------------
// Color hiding detection (WCAG luminance)
// ---------------------------------------------------------------------------

/// Detect text hidden via color similarity (e.g., white text on white background).
fn check_color_hiding(input: &str, findings: &mut Vec<Finding>) {
    use once_cell::sync::Lazy;
    use regex::Regex;

    // Match inline style with both color and background-color
    static COLOR_PAIR: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r#"(?i)style\s*=\s*["'][^"']*(?:(?:color\s*:\s*([^;"']+))[^"']*background(?:-color)?\s*:\s*([^;"']+)|(?:background(?:-color)?\s*:\s*([^;"']+))[^"']*color\s*:\s*([^;"']+))"#,
        )
        .unwrap()
    });

    for cap in COLOR_PAIR.captures_iter(input) {
        let (fg_str, bg_str) = if cap.get(1).is_some() {
            (
                cap.get(1).unwrap().as_str().trim(),
                cap.get(2).unwrap().as_str().trim(),
            )
        } else {
            (
                cap.get(4).unwrap().as_str().trim(),
                cap.get(3).unwrap().as_str().trim(),
            )
        };

        if let (Some(fg), Some(bg)) = (parse_color(fg_str), parse_color(bg_str)) {
            let contrast = contrast_ratio(fg, bg);
            if contrast < 1.5 {
                findings.push(Finding {
                    rule_id: RuleId::HiddenColorContent,
                    severity: Severity::High,
                    title: "Hidden content via color similarity".to_string(),
                    description: format!(
                        "Text color ({fg_str}) nearly identical to background ({bg_str}), \
                         contrast ratio {contrast:.2}:1 (below 1.5:1 threshold)"
                    ),
                    evidence: vec![Evidence::Text {
                        detail: format!(
                            "line {}: fg={fg_str}, bg={bg_str}, contrast={contrast:.2}:1",
                            line_number_of(input, cap.get(0).unwrap().start())
                        ),
                    }],
                    human_view: None,
                    agent_view: None,
                    mitre_id: None,
                    custom_rule_id: None,
                });
            }
        }
    }
}

/// Parse a CSS color value to (r, g, b) floats in [0, 1].
fn parse_color(s: &str) -> Option<(f64, f64, f64)> {
    let s = s.trim();

    // Named colors (common hiding pairs)
    match s.to_lowercase().as_str() {
        "white" => return Some((1.0, 1.0, 1.0)),
        "black" => return Some((0.0, 0.0, 0.0)),
        "transparent" => return Some((1.0, 1.0, 1.0)), // treat as white for contrast
        _ => {}
    }

    // Hex: #rgb or #rrggbb
    if let Some(hex) = s.strip_prefix('#') {
        return match hex.len() {
            3 => {
                let r = u8::from_str_radix(&hex[0..1].repeat(2), 16).ok()?;
                let g = u8::from_str_radix(&hex[1..2].repeat(2), 16).ok()?;
                let b = u8::from_str_radix(&hex[2..3].repeat(2), 16).ok()?;
                Some((r as f64 / 255.0, g as f64 / 255.0, b as f64 / 255.0))
            }
            6 => {
                let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                Some((r as f64 / 255.0, g as f64 / 255.0, b as f64 / 255.0))
            }
            _ => None,
        };
    }

    // rgb(r, g, b)
    if s.starts_with("rgb(") && s.ends_with(')') {
        let inner = &s[4..s.len() - 1];
        let parts: Vec<&str> = inner.split(',').collect();
        if parts.len() == 3 {
            let r: f64 = parts[0].trim().parse().ok()?;
            let g: f64 = parts[1].trim().parse().ok()?;
            let b: f64 = parts[2].trim().parse().ok()?;
            return Some((r / 255.0, g / 255.0, b / 255.0));
        }
    }

    None
}

/// WCAG 2.0 relative luminance.
fn relative_luminance(r: f64, g: f64, b: f64) -> f64 {
    fn linearize(c: f64) -> f64 {
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    }
    0.2126 * linearize(r) + 0.7152 * linearize(g) + 0.0722 * linearize(b)
}

/// WCAG contrast ratio between two colors.
fn contrast_ratio(c1: (f64, f64, f64), c2: (f64, f64, f64)) -> f64 {
    let l1 = relative_luminance(c1.0, c1.1, c1.2);
    let l2 = relative_luminance(c2.0, c2.1, c2.2);
    let (lighter, darker) = if l1 > l2 { (l1, l2) } else { (l2, l1) };
    (lighter + 0.05) / (darker + 0.05)
}

// ---------------------------------------------------------------------------
// HTML hidden/aria-hidden attribute detection
// ---------------------------------------------------------------------------

fn check_html_hidden_attributes(input: &str, findings: &mut Vec<Finding>) {
    use once_cell::sync::Lazy;
    use regex::Regex;

    static HIDDEN_ATTR: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?i)<[a-z][a-z0-9]*\s[^>]*(?:(?:\bhidden\b)|(?:aria-hidden\s*=\s*["']true["']))[^>]*>"#).unwrap()
    });

    let matches: Vec<_> = HIDDEN_ATTR.find_iter(input).collect();
    if matches.is_empty() {
        return;
    }

    // Filter out common benign patterns (SVG symbol defs, icon sprites)
    let suspicious: Vec<_> = matches
        .iter()
        .filter(|m| {
            let text = m.as_str().to_lowercase();
            // aria-hidden on <svg>, <span class="sr-only">, <i class="icon"> are benign
            !(text.starts_with("<svg") || text.contains("sr-only") || text.contains("icon"))
        })
        .collect();

    if suspicious.is_empty() {
        return;
    }

    findings.push(Finding {
        rule_id: RuleId::HiddenHtmlAttribute,
        severity: Severity::Medium,
        title: "Hidden HTML content via attribute".to_string(),
        description: format!(
            "{} element(s) with hidden/aria-hidden attribute",
            suspicious.len()
        ),
        evidence: suspicious
            .iter()
            .take(5)
            .map(|m| Evidence::Text {
                detail: format!(
                    "line {}: {}",
                    line_number_of(input, m.start()),
                    truncate_str(m.as_str(), 120)
                ),
            })
            .collect(),
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    });
}

// ---------------------------------------------------------------------------
// HTML comment detection
// ---------------------------------------------------------------------------

fn check_html_comments(
    input: &str,
    file_path: Option<&std::path::Path>,
    findings: &mut Vec<Finding>,
) {
    use once_cell::sync::Lazy;
    use regex::Regex;

    // Only check HTML-like files
    let is_html = match file_path {
        Some(p) => {
            let ext = p
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            matches!(ext.as_str(), "html" | "htm" | "xhtml" | "md")
        }
        None => {
            // No file path — check if content looks like HTML
            input.contains("<!DOCTYPE") || input.contains("<html") || input.contains("<!--")
        }
    };

    if !is_html {
        return;
    }

    static HTML_COMMENT: Lazy<Regex> = Lazy::new(|| Regex::new(r"<!--([\s\S]*?)-->").unwrap());

    let mut comment_count = 0;
    let mut long_comments = Vec::new();

    for cap in HTML_COMMENT.captures_iter(input) {
        let body = cap.get(1).unwrap().as_str().trim();
        comment_count += 1;

        // Flag comments with substantial content (>50 chars) that might hide instructions
        if body.len() > 50 {
            long_comments.push((
                line_number_of(input, cap.get(0).unwrap().start()),
                body.len(),
            ));
        }
    }

    if !long_comments.is_empty() {
        findings.push(Finding {
            rule_id: RuleId::HtmlComment,
            severity: Severity::Low,
            title: "HTML comments with substantial content".to_string(),
            description: format!(
                "{} HTML comment(s) found, {} with >50 chars of content",
                comment_count,
                long_comments.len()
            ),
            evidence: long_comments
                .iter()
                .take(5)
                .map(|(line, len)| Evidence::Text {
                    detail: format!("line {line}: comment with {len} chars"),
                })
                .collect(),
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }
}

// ---------------------------------------------------------------------------
// Markdown comment detection
// ---------------------------------------------------------------------------

fn check_markdown_comments(
    input: &str,
    file_path: Option<&std::path::Path>,
    findings: &mut Vec<Finding>,
) {
    use once_cell::sync::Lazy;
    use regex::Regex;

    // Only check Markdown files
    let is_md = match file_path {
        Some(p) => {
            let ext = p
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            ext == "md"
        }
        None => false,
    };

    if !is_md {
        return;
    }

    // Markdown link-reference comments: [//]: # (hidden text)
    static MD_COMMENT: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"\[//\]\s*:\s*#\s*\(([^)]*)\)"#).unwrap());

    let mut comment_entries = Vec::new();

    for cap in MD_COMMENT.captures_iter(input) {
        let body = cap.get(1).unwrap().as_str().trim();
        if body.len() > 10 {
            comment_entries.push((
                line_number_of(input, cap.get(0).unwrap().start()),
                body.len(),
            ));
        }
    }

    if !comment_entries.is_empty() {
        findings.push(Finding {
            rule_id: RuleId::MarkdownComment,
            severity: Severity::Low,
            title: "Markdown comments with hidden content".to_string(),
            description: format!(
                "{} markdown comment(s) with >10 chars of content",
                comment_entries.len()
            ),
            evidence: comment_entries
                .iter()
                .take(5)
                .map(|(line, len)| Evidence::Text {
                    detail: format!("line {line}: markdown comment with {len} chars"),
                })
                .collect(),
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }
}

// ---------------------------------------------------------------------------
// PDF hidden text detection
// ---------------------------------------------------------------------------

/// Check a PDF file (raw bytes) for hidden text using sub-pixel scale transforms.
///
/// Attackers embed invisible text in PDFs using font-size 0 or scale transforms
/// that shrink text below 1 pixel. This text is invisible to humans but readable
/// by AI tools that extract PDF text content. Detection is free (ADR-13).
pub fn check_pdf(raw_bytes: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let doc = match lopdf::Document::load_mem(raw_bytes) {
        Ok(d) => d,
        Err(_) => return findings, // Not a valid PDF or parse error — skip silently
    };

    let mut hidden_texts: Vec<(u32, String)> = Vec::new(); // (page_num, text_snippet)

    for (page_num, page_id) in doc.get_pages() {
        let content = match doc.get_page_content(page_id) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let ops = match lopdf::content::Content::decode(&content) {
            Ok(c) => c.operations,
            Err(_) => continue,
        };

        let mut current_font_size: f64 = 12.0; // Default
        let mut current_scale: f64 = 1.0;
        let mut in_text_block = false;

        for op in &ops {
            match op.operator.as_str() {
                "BT" => {
                    in_text_block = true;
                    current_font_size = 12.0;
                    current_scale = 1.0;
                }
                "ET" => {
                    in_text_block = false;
                }
                // Text font and size: Tf <font> <size>
                "Tf" if in_text_block => {
                    if let Some(size) = op.operands.get(1) {
                        if let Ok(s) = pdf_operand_to_f64(size) {
                            current_font_size = s;
                        }
                    }
                }
                // Text matrix: Tm <a> <b> <c> <d> <e> <f>
                // a and d are x/y scale factors
                "Tm" if in_text_block => {
                    if op.operands.len() >= 4 {
                        let a = pdf_operand_to_f64(&op.operands[0]).unwrap_or(1.0);
                        let d = pdf_operand_to_f64(&op.operands[3]).unwrap_or(1.0);
                        current_scale = a.abs().min(d.abs());
                    }
                }
                // Concatenate matrix: cm <a> <b> <c> <d> <e> <f>
                "cm" => {
                    if op.operands.len() >= 4 {
                        let a = pdf_operand_to_f64(&op.operands[0]).unwrap_or(1.0);
                        let d = pdf_operand_to_f64(&op.operands[3]).unwrap_or(1.0);
                        let scale = a.abs().min(d.abs());
                        if (0.0..1.0).contains(&scale) {
                            current_scale = scale;
                        }
                    }
                }
                // Show text: Tj, TJ, ', "
                "Tj" | "TJ" | "'" | "\"" if in_text_block => {
                    let effective_size = current_font_size * current_scale;
                    if effective_size < 1.0 {
                        // Sub-pixel text — hidden from human view
                        let text = extract_text_from_operands(&op.operands);
                        if !text.trim().is_empty() {
                            hidden_texts.push((page_num, text));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if !hidden_texts.is_empty() {
        let page_list: Vec<String> = hidden_texts
            .iter()
            .map(|(p, _)| p.to_string())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        findings.push(Finding {
            rule_id: RuleId::PdfHiddenText,
            severity: Severity::High,
            title: "Hidden text in PDF via sub-pixel rendering".to_string(),
            description: format!(
                "PDF contains {} text fragment(s) rendered at sub-pixel size (invisible to humans) \
                 on page(s): {}",
                hidden_texts.len(),
                page_list.join(", ")
            ),
            evidence: hidden_texts
                .iter()
                .take(5)
                .map(|(page, text)| Evidence::Text {
                    detail: format!("page {page}: hidden text: \"{}\"", truncate_str(text, 100)),
                })
                .collect(),
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }

    findings
}

/// Extract a float from a PDF operand.
fn pdf_operand_to_f64(obj: &lopdf::Object) -> Result<f64, ()> {
    match obj {
        lopdf::Object::Integer(i) => Ok(*i as f64),
        lopdf::Object::Real(f) => Ok(*f as f64),
        _ => Err(()),
    }
}

/// Extract text from PDF text-showing operands.
fn extract_text_from_operands(operands: &[lopdf::Object]) -> String {
    let mut result = String::new();
    for op in operands {
        match op {
            lopdf::Object::String(bytes, _) => {
                // Try UTF-8, fall back to latin-1
                match std::str::from_utf8(bytes) {
                    Ok(s) => result.push_str(s),
                    Err(_) => {
                        for &b in bytes.iter() {
                            result.push(b as char);
                        }
                    }
                }
            }
            lopdf::Object::Array(arr) => {
                // TJ array: mix of strings and spacing adjustments
                for item in arr {
                    if let lopdf::Object::String(bytes, _) = item {
                        match std::str::from_utf8(bytes) {
                            Ok(s) => result.push_str(s),
                            Err(_) => {
                                for &b in bytes.iter() {
                                    result.push(b as char);
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Get 1-based line number for a byte offset.
fn line_number_of(input: &str, byte_offset: usize) -> usize {
    input[..byte_offset.min(input.len())]
        .chars()
        .filter(|&c| c == '\n')
        .count()
        + 1
}

/// Truncate a string to max_len chars, appending "..." if truncated.
fn truncate_str(s: &str, max_len: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max_len {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_len).collect();
        format!("{truncated}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_css_display_none() {
        let input = r#"<div style="display: none">secret instructions</div>"#;
        let findings = check(input, Some(Path::new("test.html")));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::HiddenCssContent),
            "should detect display:none"
        );
    }

    #[test]
    fn test_css_visibility_hidden() {
        let input = r#"<span style="visibility: hidden">hidden text</span>"#;
        let findings = check(input, Some(Path::new("test.html")));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::HiddenCssContent),
            "should detect visibility:hidden"
        );
    }

    #[test]
    fn test_css_opacity_zero() {
        let input = r#"<p style="opacity: 0">invisible</p>"#;
        let findings = check(input, Some(Path::new("test.html")));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::HiddenCssContent),
            "should detect opacity:0"
        );
    }

    #[test]
    fn test_css_font_size_zero() {
        let input = r#"<span style="font-size:0px">hidden</span>"#;
        let findings = check(input, Some(Path::new("test.html")));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::HiddenCssContent),
            "should detect font-size:0"
        );
    }

    #[test]
    fn test_multiple_css_techniques_critical() {
        let input = r#"
            <div style="display:none">hidden1</div>
            <span style="visibility:hidden">hidden2</span>
        "#;
        let findings = check(input, Some(Path::new("test.html")));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::HiddenCssContent && f.severity == Severity::Critical),
            "multiple CSS hiding techniques should be Critical"
        );
    }

    #[test]
    fn test_color_hiding_white_on_white() {
        let input = r#"<span style="color: #ffffff; background-color: #ffffff">secret</span>"#;
        let findings = check(input, Some(Path::new("test.html")));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::HiddenColorContent),
            "should detect white-on-white"
        );
    }

    #[test]
    fn test_color_hiding_named_colors() {
        let input = r#"<span style="color: white; background-color: white">secret</span>"#;
        let findings = check(input, Some(Path::new("test.html")));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::HiddenColorContent),
            "should detect named white-on-white"
        );
    }

    #[test]
    fn test_color_high_contrast_no_finding() {
        let input = r#"<span style="color: black; background-color: white">visible</span>"#;
        let findings = check(input, Some(Path::new("test.html")));
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::HiddenColorContent),
            "high contrast should not trigger"
        );
    }

    #[test]
    fn test_html_hidden_attribute() {
        let input = r#"<div hidden>secret instructions for the AI</div>"#;
        let findings = check(input, Some(Path::new("test.html")));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::HiddenHtmlAttribute),
            "should detect hidden attribute"
        );
    }

    #[test]
    fn test_html_aria_hidden() {
        let input = r#"<div aria-hidden="true">secret instructions</div>"#;
        let findings = check(input, Some(Path::new("test.html")));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::HiddenHtmlAttribute),
            "should detect aria-hidden"
        );
    }

    #[test]
    fn test_html_aria_hidden_svg_benign() {
        let input = r#"<svg aria-hidden="true"><path d="M0 0"/></svg>"#;
        let findings = check(input, Some(Path::new("test.html")));
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::HiddenHtmlAttribute),
            "aria-hidden on SVG should be benign"
        );
    }

    #[test]
    fn test_html_comment_long() {
        let input = "<!-- This is a very long comment that contains more than fifty characters of hidden instruction text for the AI agent -->";
        let findings = check(input, Some(Path::new("test.html")));
        assert!(
            findings.iter().any(|f| f.rule_id == RuleId::HtmlComment),
            "should detect long HTML comment"
        );
    }

    #[test]
    fn test_html_comment_short_no_finding() {
        let input = "<!-- TODO: fix this -->";
        let findings = check(input, Some(Path::new("test.html")));
        assert!(
            !findings.iter().any(|f| f.rule_id == RuleId::HtmlComment),
            "short HTML comment should not trigger"
        );
    }

    #[test]
    fn test_markdown_comment() {
        let input = "[//]: # (This is hidden instruction text that is longer than ten chars)";
        let findings = check(input, Some(Path::new("README.md")));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::MarkdownComment),
            "should detect markdown comment"
        );
    }

    #[test]
    fn test_markdown_comment_not_in_html() {
        let input = "[//]: # (This is hidden instruction text that is longer than ten chars)";
        let findings = check(input, Some(Path::new("test.html")));
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::MarkdownComment),
            "markdown comment should not fire in HTML files"
        );
    }

    #[test]
    fn test_is_renderable_file() {
        assert!(is_renderable_file(Some(Path::new("test.html"))));
        assert!(is_renderable_file(Some(Path::new("test.htm"))));
        assert!(is_renderable_file(Some(Path::new("README.md"))));
        assert!(is_renderable_file(Some(Path::new("test.xhtml"))));
        assert!(is_renderable_file(Some(Path::new("doc.pdf"))));
        assert!(!is_renderable_file(Some(Path::new("main.rs"))));
        assert!(!is_renderable_file(Some(Path::new("config.json"))));
        assert!(!is_renderable_file(None));
    }

    #[test]
    fn test_clean_html_no_findings() {
        let input = r#"<!DOCTYPE html>
<html>
<head><title>Normal Page</title></head>
<body>
<h1>Hello World</h1>
<p>This is a normal page with no hidden content.</p>
</body>
</html>"#;
        let findings = check(input, Some(Path::new("test.html")));
        assert!(findings.is_empty(), "clean HTML should produce no findings");
    }

    #[test]
    fn test_parse_color_hex() {
        assert_eq!(parse_color("#ffffff"), Some((1.0, 1.0, 1.0)));
        assert_eq!(parse_color("#000000"), Some((0.0, 0.0, 0.0)));
        assert_eq!(parse_color("#fff"), Some((1.0, 1.0, 1.0)));
    }

    #[test]
    fn test_parse_color_rgb() {
        assert_eq!(parse_color("rgb(255, 255, 255)"), Some((1.0, 1.0, 1.0)));
        assert_eq!(parse_color("rgb(0, 0, 0)"), Some((0.0, 0.0, 0.0)));
    }

    #[test]
    fn test_parse_color_named() {
        assert_eq!(parse_color("white"), Some((1.0, 1.0, 1.0)));
        assert_eq!(parse_color("black"), Some((0.0, 0.0, 0.0)));
    }

    #[test]
    fn test_contrast_ratio_same_color() {
        let white = (1.0, 1.0, 1.0);
        let ratio = contrast_ratio(white, white);
        assert!(
            ratio < 1.1,
            "same color contrast should be ~1.0, got {ratio}"
        );
    }

    #[test]
    fn test_contrast_ratio_black_white() {
        let white = (1.0, 1.0, 1.0);
        let black = (0.0, 0.0, 0.0);
        let ratio = contrast_ratio(white, black);
        assert!(ratio > 20.0, "B&W contrast should be 21:1, got {ratio}");
    }

    #[test]
    fn test_line_number_of() {
        let input = "line1\nline2\nline3";
        assert_eq!(line_number_of(input, 0), 1);
        assert_eq!(line_number_of(input, 6), 2);
        assert_eq!(line_number_of(input, 12), 3);
    }

    #[test]
    fn test_pdf_invalid_bytes_no_panic() {
        // Invalid PDF bytes should not panic, just return empty
        let findings = check_pdf(b"not a pdf");
        assert!(
            findings.is_empty(),
            "invalid PDF should produce no findings"
        );
    }

    #[test]
    fn test_pdf_operand_to_f64() {
        assert_eq!(pdf_operand_to_f64(&lopdf::Object::Integer(42)), Ok(42.0));
        // Real stores f32 internally, so compare with tolerance
        let real_val = pdf_operand_to_f64(&lopdf::Object::Real(3.25)).unwrap();
        assert!((real_val - 3.25).abs() < 0.001, "got {real_val}");
        assert!(pdf_operand_to_f64(&lopdf::Object::Boolean(true)).is_err());
    }

    #[test]
    fn test_extract_text_from_operands() {
        let ops = vec![lopdf::Object::String(
            b"Hello World".to_vec(),
            lopdf::StringFormat::Literal,
        )];
        assert_eq!(extract_text_from_operands(&ops), "Hello World");
    }

    #[test]
    fn test_extract_text_from_tj_array() {
        let ops = vec![lopdf::Object::Array(vec![
            lopdf::Object::String(b"Hel".to_vec(), lopdf::StringFormat::Literal),
            lopdf::Object::Integer(-50),
            lopdf::Object::String(b"lo".to_vec(), lopdf::StringFormat::Literal),
        ])];
        assert_eq!(extract_text_from_operands(&ops), "Hello");
    }

    #[test]
    fn test_truncate_str_multibyte_safe() {
        // Multibyte characters: each emoji is 4 bytes
        let s = "\u{1F600}\u{1F601}\u{1F602}\u{1F603}";
        assert_eq!(s.len(), 16); // 4 chars * 4 bytes each
                                 // Truncating to 2 chars should NOT panic
        let result = truncate_str(s, 2);
        assert_eq!(result, "\u{1F600}\u{1F601}...");
    }

    #[test]
    fn test_truncate_str_short() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_str_exact() {
        assert_eq!(truncate_str("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_str_truncated() {
        assert_eq!(truncate_str("hello world", 5), "hello...");
    }
}
