//! Homoglyph analysis utilities for detailed character reporting.

use crate::verdict::{Evidence, SuspiciousChar};
use unicode_script::UnicodeScript;

/// Analyze a string for suspicious non-ASCII characters and generate detailed evidence.
pub fn analyze_hostname(raw: &str) -> Evidence {
    let mut suspicious_chars = Vec::new();
    let mut byte_offset = 0;

    for ch in raw.chars() {
        if !ch.is_ascii() {
            let script = ch.script();
            let script_name = format!("{script:?}");

            let mut hex_bytes = String::new();
            for byte in ch.to_string().as_bytes() {
                if !hex_bytes.is_empty() {
                    hex_bytes.push(' ');
                }
                hex_bytes.push_str(&format!("{byte:02x}"));
            }

            suspicious_chars.push(SuspiciousChar {
                offset: byte_offset,
                character: ch,
                codepoint: format!("U+{:04X}", ch as u32),
                description: get_char_description(ch, &script_name),
                hex_bytes,
            });
        }
        byte_offset += ch.len_utf8();
    }

    let escaped = escape_to_ascii(raw);

    Evidence::HomoglyphAnalysis {
        raw: raw.to_string(),
        escaped,
        suspicious_chars,
    }
}

/// Get a human-readable description of a character based on its script
fn get_char_description(ch: char, script_name: &str) -> String {
    let description = match ch {
        'а' => "Cyrillic 'а' (looks like Latin 'a')",
        'е' => "Cyrillic 'е' (looks like Latin 'e')",
        'о' => "Cyrillic 'о' (looks like Latin 'o')",
        'р' => "Cyrillic 'р' (looks like Latin 'p')",
        'с' => "Cyrillic 'с' (looks like Latin 'c')",
        'у' => "Cyrillic 'у' (looks like Latin 'y')",
        'х' => "Cyrillic 'х' (looks like Latin 'x')",
        'і' => "Cyrillic 'і' (looks like Latin 'i')",
        'ј' => "Cyrillic 'ј' (looks like Latin 'j')",
        'ѕ' => "Cyrillic 'ѕ' (looks like Latin 's')",
        'ԁ' => "Cyrillic 'ԁ' (looks like Latin 'd')",
        'ɡ' => "Latin Small Letter Script G (looks like 'g')",
        'ո' => "Armenian 'ո' (looks like Latin 'n')",
        'ա' => "Armenian 'ա' (looks like Latin 'u')",
        'Α' => "Greek 'Α' (looks like Latin 'A')",
        'Β' => "Greek 'Β' (looks like Latin 'B')",
        'Ε' => "Greek 'Ε' (looks like Latin 'E')",
        'Η' => "Greek 'Η' (looks like Latin 'H')",
        'Ι' => "Greek 'Ι' (looks like Latin 'I')",
        'Κ' => "Greek 'Κ' (looks like Latin 'K')",
        'Μ' => "Greek 'Μ' (looks like Latin 'M')",
        'Ν' => "Greek 'Ν' (looks like Latin 'N')",
        'Ο' => "Greek 'Ο' (looks like Latin 'O')",
        'Ρ' => "Greek 'Ρ' (looks like Latin 'P')",
        'Τ' => "Greek 'Τ' (looks like Latin 'T')",
        'Χ' => "Greek 'Χ' (looks like Latin 'X')",
        'Ζ' => "Greek 'Ζ' (looks like Latin 'Z')",
        'ο' => "Greek 'ο' (looks like Latin 'o')",
        _ => "",
    };

    if !description.is_empty() {
        description.to_string()
    } else {
        format!("{script_name} character")
    }
}

/// Convert a hostname to its ASCII/punycode equivalent via the url crate's
/// UTS-46 host parsing (wrap in a dummy URL, read back `host_str()`).
fn escape_to_ascii(raw: &str) -> String {
    let dummy_url = format!("https://{raw}/");
    match url::Url::parse(&dummy_url) {
        Ok(parsed) => parsed.host_str().unwrap_or(raw).to_string(),
        Err(_) => raw.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_cyrillic_i() {
        let evidence = analyze_hostname("іnstall");
        if let Evidence::HomoglyphAnalysis {
            raw,
            escaped: _,
            suspicious_chars,
        } = evidence
        {
            assert_eq!(raw, "іnstall");
            assert!(!suspicious_chars.is_empty());
            assert_eq!(suspicious_chars[0].codepoint, "U+0456");
            assert!(suspicious_chars[0]
                .description
                .contains("looks like Latin 'i'"));
        } else {
            panic!("Expected HomoglyphAnalysis evidence");
        }
    }

    #[test]
    fn test_escape_to_ascii_punycode() {
        let escaped = escape_to_ascii("paradіgm.xyz");
        assert!(
            escaped.contains("xn--"),
            "Expected punycode, got: {escaped}"
        );
    }

    #[test]
    fn test_escape_pure_ascii() {
        let escaped = escape_to_ascii("example.com");
        assert_eq!(escaped, "example.com");
    }

    #[test]
    fn test_escape_google_cyrillic() {
        let escaped = escape_to_ascii("gооgle.com");
        assert!(
            escaped.contains("xn--"),
            "Expected punycode for Cyrillic o, got: {escaped}"
        );
    }

    #[test]
    fn test_escape_mixed_labels() {
        // Only the homoglyph label should be punycoded; ASCII labels preserved.
        let escaped = escape_to_ascii("аpple.example.com");
        assert!(escaped.contains("xn--"), "First label should be punycode");
        assert!(escaped.contains("example.com"), "ASCII labels preserved");
    }

    #[test]
    fn test_byte_offsets_correct() {
        let evidence = analyze_hostname("aіb");
        if let Evidence::HomoglyphAnalysis {
            suspicious_chars, ..
        } = evidence
        {
            assert_eq!(suspicious_chars.len(), 1);
            // 'a' is 1 byte, so Cyrillic і starts at offset 1.
            assert_eq!(suspicious_chars[0].offset, 1);
        } else {
            panic!("Expected HomoglyphAnalysis evidence");
        }
    }

    #[test]
    fn test_hex_bytes_format() {
        let evidence = analyze_hostname("і");
        if let Evidence::HomoglyphAnalysis {
            suspicious_chars, ..
        } = evidence
        {
            assert_eq!(suspicious_chars.len(), 1);
            // Cyrillic і is U+0456 = UTF-8 d1 96.
            assert_eq!(suspicious_chars[0].hex_bytes, "d1 96");
        } else {
            panic!("Expected HomoglyphAnalysis evidence");
        }
    }

    #[test]
    fn test_evidence_serialization() {
        let evidence = analyze_hostname("tеst");
        let json = serde_json::to_string(&evidence).expect("serialization should work");
        assert!(json.contains("homoglyph_analysis"));
        assert!(json.contains("suspicious_chars"));
        assert!(json.contains("character"));
    }

    #[test]
    fn test_multiple_suspicious_chars() {
        let evidence = analyze_hostname("аррle");
        if let Evidence::HomoglyphAnalysis {
            suspicious_chars, ..
        } = evidence
        {
            // Cyrillic а plus two Cyrillic р.
            assert_eq!(suspicious_chars.len(), 3);
        } else {
            panic!("Expected HomoglyphAnalysis evidence");
        }
    }
}
