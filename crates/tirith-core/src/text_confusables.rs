//! Text-level confusable character lookup using embedded data from build.rs.
//! Separate from `confusables.rs` which is used for hostname skeleton matching.
//! This table covers Mathematical Alphanumeric Symbols (U+1D400–U+1D7FF)
//! used in steganographic text attacks.

use once_cell::sync::Lazy;
use std::collections::HashMap;

// Include generated text confusable table
include!(concat!(env!("OUT_DIR"), "/text_confusables_gen.rs"));

/// Map from text-confusable char to the ASCII char it resembles.
static TEXT_CONFUSABLES_MAP: Lazy<HashMap<char, char>> = Lazy::new(|| {
    let mut m = HashMap::with_capacity(TEXT_CONFUSABLE_COUNT);
    for &(src, tgt) in TEXT_CONFUSABLE_TABLE {
        if let (Some(s), Some(t)) = (char::from_u32(src), char::from_u32(tgt)) {
            m.insert(s, t);
        }
    }
    m
});

/// Check if a character has a text-level confusable mapping (math alphanumerics).
pub fn is_text_confusable(ch: char) -> Option<char> {
    TEXT_CONFUSABLES_MAP.get(&ch).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_math_bold_a() {
        // U+1D400 = Mathematical Bold Capital A
        assert_eq!(is_text_confusable('\u{1D400}'), Some('A'));
    }

    #[test]
    fn test_math_bold_lowercase() {
        // U+1D41A = Mathematical Bold Small A
        assert_eq!(is_text_confusable('\u{1D41A}'), Some('a'));
    }

    #[test]
    fn test_math_bold_digit() {
        // U+1D7CE = Mathematical Bold Digit Zero
        assert_eq!(is_text_confusable('\u{1D7CE}'), Some('0'));
    }

    #[test]
    fn test_ascii_not_confusable() {
        assert_eq!(is_text_confusable('a'), None);
        assert_eq!(is_text_confusable('A'), None);
        assert_eq!(is_text_confusable('0'), None);
    }

    #[test]
    fn test_math_monospace() {
        // U+1D670 = Mathematical Monospace Capital A
        assert_eq!(is_text_confusable('\u{1D670}'), Some('A'));
    }
}
