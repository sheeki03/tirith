#![no_main]

use libfuzzer_sys::fuzz_target;
use tirith_core::lexical_path::{LexicalPath, PathDialect};

fn check_dialect(input: &str, dialect: PathDialect) {
    let parsed = LexicalPath::parse(input, dialect);
    let repeated = LexicalPath::parse(input, dialect);
    assert_eq!(parsed, repeated, "lexical parsing must be deterministic");

    let preserved = LexicalPath::parse_preserving_parents(input, dialect);
    let preserved_repeated = LexicalPath::parse_preserving_parents(input, dialect);
    assert_eq!(
        preserved, preserved_repeated,
        "parent-preserving parsing must be deterministic"
    );

    if let (Ok(parsed), Ok(preserved)) = (&parsed, &preserved) {
        assert_eq!(parsed.root_class(), preserved.root_class());
        assert_eq!(
            parsed.parent_state().leading,
            preserved.parent_state().leading,
            "retaining parent tokens must not alter leading traversal state"
        );
        assert_eq!(
            parsed.parent_state().above_root,
            preserved.parent_state().above_root,
            "retaining parent tokens must not alter above-root traversal state"
        );
    } else {
        assert_eq!(
            parsed.is_ok(),
            preserved.is_ok(),
            "parent retention must not change whether a root is parseable"
        );
    }

    if let Ok(parsed) = parsed {
        check_round_trip(input, dialect, &parsed);
    }
    if let Ok(preserved) = preserved {
        let rendered = preserved.to_slash_string();
        assert!(
            rendered.len() <= input.len(),
            "normalization expanded {} input bytes to {} output bytes",
            input.len(),
            rendered.len()
        );
        let reparsed = LexicalPath::parse_preserving_parents(&rendered, dialect)
            .expect("a rendered parent-preserving path must remain parseable");
        assert_eq!(
            preserved, reparsed,
            "rendering must preserve roots, components, and traversal state"
        );
    }
}

fn check_round_trip(input: &str, dialect: PathDialect, parsed: &LexicalPath) {
    let rendered = parsed.to_slash_string();
    assert!(
        rendered.len() <= input.len(),
        "normalization expanded {} input bytes to {} output bytes",
        input.len(),
        rendered.len()
    );

    let reparsed = LexicalPath::parse(&rendered, dialect)
        .expect("a rendered lexical path must remain parseable");
    assert_eq!(
        reparsed.root_class(),
        parsed.root_class(),
        "normalization changed the root class"
    );
    assert_eq!(
        reparsed.to_slash_string(),
        rendered,
        "normalized rendering must be idempotent"
    );

    // Ordinary rendering deliberately clamps attempts above an absolute root.
    // Every other normalized representation must round-trip without losing
    // components or traversal state. The preserving parser checks the clamped
    // case separately without discarding the `..` tokens.
    if !parsed.parent_state().above_root {
        assert_eq!(parsed, &reparsed);
    }
}

fuzz_target!(|input: &str| {
    check_dialect(input, PathDialect::Posix);
    check_dialect(input, PathDialect::Windows);

    let auto = LexicalPath::parse_auto(input);
    assert_eq!(auto, LexicalPath::parse_auto(input));
    if let Ok(parsed) = auto {
        check_round_trip(input, parsed.dialect(), &parsed);
    }
});
