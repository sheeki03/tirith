//! Package version intent: a lossless replacement for the old
//! `version: Option<String>` carried on package references.
//!
//! A bare `Option<String>` could not distinguish "no version asked for" from
//! "an exact pin" from "a range constraint", so a constrained request like
//! `pip install foo>=1.4.4` was flattened to "no version" and silently treated
//! as unpinned. [`VersionIntent`] keeps that distinction, and an unparsed or
//! only-partially-understood constraint is preserved verbatim and treated as
//! UNRESOLVED, never silently as an exact match.
//!
//! The constraint evaluator here is a deliberately small, conservative subset
//! of PEP 440: numeric release segments and the comparison operators `==`,
//! `!=`, `<`, `<=`, `>`, `>=`. Anything outside that subset (an environment
//! marker, an epoch, a pre/post/dev release, a wildcard, the compatible-release
//! `~=`, or arbitrary equality `===`) deliberately fails to parse so the caller
//! falls back to UNRESOLVED instead of guessing. A PEP 440 LOCAL version
//! (`1.0+ubuntu1`) is the exception: an EXACT local pin is kept as `Exact` and
//! matched against the threat DB literally and by its base release (a local build
//! carries the base's code); only a local inside a RANGE stays unresolved. A full
//! PEP 440 solver is intentionally out of scope; the contract is "prove exclusion
//! only when every part is understood, otherwise stay unresolved".

/// How a package's version was expressed at the point of reference.
///
/// `Exact` and `Resolved` both name a single concrete version; they are kept
/// distinct because `Exact` is what the user typed (an `==` pin or `name@ver`)
/// while `Resolved` is what a resolver/lockfile pinned. Both are treated the
/// same by the threat-DB assessment (a single version to test), but keeping the
/// provenance lets later milestones reason about pin vs resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionIntent {
    /// No version was given (e.g. `pip install foo`). The resolver is free to
    /// pick any version, so a version-specific malicious record cannot be
    /// excluded.
    Unspecified,
    /// An exact pin the user wrote (`==1.2.3`, `name@1.2.3`).
    Exact(String),
    /// A range/constraint expression (`>=1.4.4`, `>=1.2,<2.0`, `^1.0`). `raw`
    /// preserves the original text exactly; `parsed` is `Some` only when the
    /// WHOLE expression is within the supported PEP 440 subset.
    Constraint {
        raw: String,
        parsed: Option<VersionConstraint>,
    },
    /// A concrete version a resolver/lockfile already pinned.
    Resolved(String),
}

impl VersionIntent {
    /// The single concrete version this intent names, if any (`Exact` or
    /// `Resolved`). `Unspecified` and `Constraint` return `None`.
    pub fn exact_version(&self) -> Option<&str> {
        match self {
            VersionIntent::Exact(v) | VersionIntent::Resolved(v) => Some(v.as_str()),
            VersionIntent::Unspecified | VersionIntent::Constraint { .. } => None,
        }
    }

    /// The raw constraint text, if this is a `Constraint`.
    pub fn constraint_raw(&self) -> Option<&str> {
        match self {
            VersionIntent::Constraint { raw, .. } => Some(raw.as_str()),
            _ => None,
        }
    }

    /// The version text as originally written, regardless of kind: the concrete
    /// version for `Exact`/`Resolved`, the raw constraint for `Constraint`, and
    /// `None` for `Unspecified`. This reconstructs the lossy `Option<String>`
    /// the field replaced, for consumers (e.g. OSV correlation) that just want
    /// "the version string the user typed, if any".
    pub fn as_version_str(&self) -> Option<&str> {
        match self {
            VersionIntent::Exact(v) | VersionIntent::Resolved(v) => Some(v.as_str()),
            VersionIntent::Constraint { raw, .. } => Some(raw.as_str()),
            VersionIntent::Unspecified => None,
        }
    }

    /// Build an intent from a pip-style version-specifier tail (the part after
    /// the package name, e.g. `==1.2.3`, `>=1.4.4`, `>=1.2,<2.0`, or `""`).
    ///
    /// A lone `==<ver>` (no wildcard) is an [`Exact`](VersionIntent::Exact)
    /// pin; an empty/whitespace tail is [`Unspecified`](VersionIntent::Unspecified);
    /// anything else is a [`Constraint`](VersionIntent::Constraint) whose `parsed`
    /// is populated only when the whole expression is understood.
    pub fn from_pep440_specifier(spec: &str) -> VersionIntent {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return VersionIntent::Unspecified;
        }

        // A single `==<ver>` (no wildcard, no extra clauses) is an exact pin,
        // regardless of whether the version parses as a plain numeric release.
        // The exact INTENT does not need a parseable version: the threat-DB
        // match is a literal/numeric string compare, so a prerelease pin like
        // `==1.0.0rc1` is still Exact (and would otherwise degrade to a
        // Constraint and a mere Warn). This mirrors `from_explicit_version`,
        // which already returns Exact for prerelease tails.
        if let Some(rest) = trimmed.strip_prefix("==") {
            let ver = rest.trim();
            // Only a clean exact-looking version is an Exact pin. `looks_like_plain_version`
            // rejects environment markers (`;`), arbitrary equality (`===`, which leaves a
            // leading `=`), epochs (`!`), wildcards (`*`), empty segments, and whitespace,
            // so those fall through to a Constraint (and thus UNRESOLVED) instead of a bogus
            // Exact. Prereleases (`1.0.0rc1`) AND PEP 440 local versions (`1.0+ubuntu1`) are
            // kept Exact: `assess_package_self` matches an exact-local DB record literally
            // and a malicious base record via its base, and `ReleaseVersion::parse` rejects
            // locals so the numeric fallback never produces a false base match.
            if looks_like_plain_version(ver) {
                return VersionIntent::Exact(ver.to_string());
            }
        }

        VersionIntent::Constraint {
            parsed: VersionConstraint::parse(trimmed),
            raw: trimmed.to_string(),
        }
    }

    /// Build an intent from a single explicit version token of a non-PyPI
    /// ecosystem (`name@1.2.3`, `name:^3.0`, `--version 1.2.3`).
    ///
    /// A plain version-looking token (digits and dots, optionally with a build/
    /// prerelease tail like `-beta.1`) is an [`Exact`](VersionIntent::Exact)
    /// pin: the threat DB stores literal version strings, so this preserves the
    /// pre-existing exact-string match behavior. Anything carrying a range
    /// sigil, wildcard, dist-tag, or whitespace becomes an unparsed
    /// [`Constraint`](VersionIntent::Constraint) (the constraint syntax of these
    /// ecosystems is not modeled, so it stays unresolved rather than being
    /// mistaken for an exact pin).
    pub fn from_explicit_version(token: &str) -> VersionIntent {
        let t = token.trim();
        if t.is_empty() {
            return VersionIntent::Unspecified;
        }
        if looks_like_plain_version(t) {
            VersionIntent::Exact(t.to_string())
        } else {
            // The constraint syntax of non-PyPI ecosystems is not parsed; keep
            // the raw text and leave it unresolved.
            VersionIntent::Constraint {
                parsed: None,
                raw: t.to_string(),
            }
        }
    }

    /// Build an intent from a Cargo version requirement (`cargo add serde@1.0`,
    /// `cargo install --version 1.0`). Unlike pip's `==` or an npm FULL pin, Cargo treats a
    /// PLAIN version as a caret REQUIREMENT (`1.0` == `^1.0`); resolution then selects the
    /// highest SemVer-compatible release, so the literal token is NOT what gets installed.
    /// A plain token is therefore a [`Constraint`] (matching resolves the real installed
    /// version), NOT an [`Exact`] pin. Only Cargo's `=` operator (`=1.0.0`) is an exact pin.
    pub fn from_cargo_version(token: &str) -> VersionIntent {
        let t = token.trim();
        if t.is_empty() {
            return VersionIntent::Unspecified;
        }
        // Cargo's `=` operator is the only exact pin: `=1.0.0` -> Exact("1.0.0").
        if let Some(pinned) = t.strip_prefix('=') {
            let pinned = pinned.trim();
            if looks_like_plain_version(pinned) {
                return VersionIntent::Exact(pinned.to_string());
            }
        }
        // A plain version (Cargo's caret default) or any other sigil/range is a Constraint.
        VersionIntent::Constraint {
            parsed: None,
            raw: t.to_string(),
        }
    }

    /// Build an intent from a Ruby Gemfile version requirement (`gem "x", "= 1.0"`,
    /// `gem "x", "~> 1.0"`). Unlike Cargo, a bare `1.0` and an explicit `= 1.0` are BOTH
    /// exact pins; `~>`, `>=`, `<`, etc. are ranges. Strip a single leading `=` operator,
    /// then reuse the plain-or-constraint logic (plain -> Exact, sigil -> Constraint).
    pub fn from_gem_version(token: &str) -> VersionIntent {
        let t = token.trim();
        let stripped = t.strip_prefix('=').map(str::trim).unwrap_or(t);
        Self::from_explicit_version(stripped)
    }
}

/// Whether a token looks like a plain, fully-specified version (an exact pin)
/// rather than a range/tag. Accepts an optional single leading `v`/`V` (the Go
/// module convention `v1.9.1`), then a digit, then digits, dots, and a `-`/`+`
/// prerelease/build tail (`1.2.3`, `1.2.3-beta.1`, `1.2.3+build.5`). Rejects
/// range sigils (`^ ~ > < = | *`), wildcards (`1.x`), whitespace, and dist-tags
/// (`latest`).
pub(crate) fn looks_like_plain_version(t: &str) -> bool {
    // Allow a single leading `v`/`V` so Go's `v1.9.1` stays an exact pin.
    let body = t.strip_prefix(['v', 'V']).unwrap_or(t);
    match body.chars().next() {
        Some(c) if c.is_ascii_digit() => {}
        _ => return false,
    }
    body.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+')
        // Every segment must be non-empty and not a wildcard: this rejects an empty
        // segment (`1.`, `1..2`, `1.+`, a malformed or Gradle-style dynamic selector)
        // and a `x`/`X` wildcard (`1.x`), which are ranges, not exact pins.
        && body
            .split(['.', '-', '+'])
            .all(|seg| !seg.is_empty() && seg != "x" && seg != "X")
}

/// A parsed PEP 440 version constraint: a conjunction (AND) of comparison
/// clauses, all within the supported subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionConstraint {
    clauses: Vec<Clause>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Clause {
    op: Operator,
    version: ReleaseVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operator {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl VersionConstraint {
    /// Parse a comma-separated constraint expression. Returns `Some` only when
    /// EVERY clause uses a supported operator and a parseable plain version.
    /// Any unsupported form (`~=`, `===`, wildcard, marker, epoch, local, pre/
    /// post/dev release) makes the whole parse fail, by design.
    pub fn parse(raw: &str) -> Option<VersionConstraint> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        // Environment markers (`; python_version < "3.9"`) are not understood.
        if raw.contains(';') {
            return None;
        }
        let mut clauses = Vec::new();
        for part in raw.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return None;
            }
            clauses.push(parse_clause(part)?);
        }
        if clauses.is_empty() {
            return None;
        }
        Some(VersionConstraint { clauses })
    }

    /// Evaluate the constraint against a concrete version. Every clause must
    /// hold (logical AND), matching PEP 440 specifier-set semantics.
    pub fn matches(&self, version: &ReleaseVersion) -> bool {
        self.clauses.iter().all(|c| c.matches(version))
    }
}

impl Clause {
    fn matches(&self, version: &ReleaseVersion) -> bool {
        let ord = version.cmp(&self.version);
        match self.op {
            Operator::Eq => ord == std::cmp::Ordering::Equal,
            Operator::Ne => ord != std::cmp::Ordering::Equal,
            Operator::Lt => ord == std::cmp::Ordering::Less,
            Operator::Le => ord != std::cmp::Ordering::Greater,
            Operator::Gt => ord == std::cmp::Ordering::Greater,
            Operator::Ge => ord != std::cmp::Ordering::Less,
        }
    }
}

/// Parse a single clause like `>=1.4.4`. Rejects `~=`, `===`, and wildcards.
fn parse_clause(part: &str) -> Option<Clause> {
    // Reject the compatible-release and arbitrary-equality operators outright:
    // their semantics are not modeled, so a constraint using them is unresolved.
    if part.starts_with("~=") || part.starts_with("===") {
        return None;
    }

    // Order matters: try two-character operators before one-character ones.
    let (op, rest) = if let Some(r) = part.strip_prefix("==") {
        (Operator::Eq, r)
    } else if let Some(r) = part.strip_prefix("!=") {
        (Operator::Ne, r)
    } else if let Some(r) = part.strip_prefix("<=") {
        (Operator::Le, r)
    } else if let Some(r) = part.strip_prefix(">=") {
        (Operator::Ge, r)
    } else if let Some(r) = part.strip_prefix('<') {
        (Operator::Lt, r)
    } else if let Some(r) = part.strip_prefix('>') {
        (Operator::Gt, r)
    } else {
        // A bare version, a caret/tilde range, or anything else: not understood.
        return None;
    };

    let ver = rest.trim();
    if ver.contains('*') {
        // `==1.4.*` prefix matching is not modeled.
        return None;
    }
    let version = ReleaseVersion::parse(ver)?;
    Some(Clause { op, version })
}

/// A plain PEP 440 release version: numeric segments only (`1`, `1.4`,
/// `1.4.4`). Trailing-zero differences compare equal (`1.4` == `1.4.0`), per
/// PEP 440 release-segment semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseVersion {
    segments: Vec<u64>,
}

impl ReleaseVersion {
    /// Parse a plain numeric release version. Returns `None` for anything with
    /// an epoch (`1!2.0`), a local version (`1.0+abc`), a pre/post/dev suffix
    /// (`1.0rc1`, `1.0.post1`, `1.0.dev0`), a wildcard, a leading `v`, or any
    /// non-numeric/empty segment.
    pub fn parse(s: &str) -> Option<ReleaseVersion> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        // Epoch, local version, and wildcards are out of the supported subset.
        if s.contains('!') || s.contains('+') || s.contains('*') {
            return None;
        }
        // Bound the allocation on attacker-influenceable version strings. A real
        // release version has a handful of segments; a string with more than 16
        // dot-separated parts is not a version we model, so refuse it rather than
        // grow `segments` in proportion to the input length.
        const MAX_SEGMENTS: usize = 16;
        if s.split('.').count() > MAX_SEGMENTS {
            return None;
        }
        let mut segments = Vec::new();
        for seg in s.split('.') {
            if seg.is_empty() {
                return None;
            }
            // Reject any non-digit (covers `rc`, `a`, `b`, `post`, `dev`, `v`,
            // whitespace, and sign characters).
            if !seg.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            segments.push(seg.parse::<u64>().ok()?);
        }
        if segments.is_empty() {
            return None;
        }
        Some(ReleaseVersion { segments })
    }
}

impl PartialOrd for ReleaseVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ReleaseVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Compare segment by segment, treating a missing trailing segment as 0
        // so `1.4` and `1.4.0` are equal.
        let len = self.segments.len().max(other.segments.len());
        for i in 0..len {
            let a = self.segments.get(i).copied().unwrap_or(0);
            let b = other.segments.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                std::cmp::Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        std::cmp::Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_specifier_is_unspecified() {
        assert_eq!(
            VersionIntent::from_pep440_specifier(""),
            VersionIntent::Unspecified
        );
        assert_eq!(
            VersionIntent::from_pep440_specifier("   "),
            VersionIntent::Unspecified
        );
    }

    #[test]
    fn exact_pin_is_exact() {
        assert_eq!(
            VersionIntent::from_pep440_specifier("==1.2.3"),
            VersionIntent::Exact("1.2.3".to_string())
        );
    }

    #[test]
    fn exact_pin_with_prerelease_is_exact() {
        // A lone `==<prerelease>` is an exact INTENT even though the version is
        // not a plain numeric release: the DB match is a literal string compare,
        // so it must not degrade to an Unresolved Constraint (a mere Warn).
        match VersionIntent::from_pep440_specifier("==1.0.0rc1") {
            VersionIntent::Exact(v) => assert_eq!(v, "1.0.0rc1"),
            other => panic!("expected Exact for `==1.0.0rc1`, got {other:?}"),
        }
    }

    #[test]
    fn exact_pin_with_wildcard_is_unresolved_constraint() {
        // `==1.2.*` is prefix matching, not an exact pin; it must not parse.
        let intent = VersionIntent::from_pep440_specifier("==1.2.*");
        match intent {
            VersionIntent::Constraint { raw, parsed } => {
                assert_eq!(raw, "==1.2.*");
                assert!(parsed.is_none(), "wildcard must not parse");
            }
            other => panic!("expected unresolved Constraint, got {other:?}"),
        }
    }

    #[test]
    fn pep440_arbitrary_equality_and_markers_are_not_exact() {
        // `===1.0` (arbitrary equality, leaves a leading `=`) and a marker-qualified
        // pin must NOT become a bogus Exact; they fall through to an unresolved
        // Constraint per the conservative subset.
        assert!(matches!(
            VersionIntent::from_pep440_specifier("===1.0"),
            VersionIntent::Constraint { parsed: None, .. }
        ));
        assert!(matches!(
            VersionIntent::from_pep440_specifier("==1.0.0;python_version<\"3.9\""),
            VersionIntent::Constraint { parsed: None, .. }
        ));
        // Malformed/dynamic versions with an empty segment are NOT Exact (they cannot
        // be a real pin). A `+` local version is handled separately below.
        for spec in ["==1.", "==1..2", "==1.+"] {
            assert!(
                matches!(
                    VersionIntent::from_pep440_specifier(spec),
                    VersionIntent::Constraint { .. }
                ),
                "{spec} must be an unresolved Constraint, not Exact"
            );
        }
        // A PEP 440 local version IS Exact: `assess_package_self` matches it against an
        // exact-local DB record literally and a malicious base record via its base, so
        // it must not be downgraded to an unresolved Constraint.
        assert_eq!(
            VersionIntent::from_pep440_specifier("==1.0+ubuntu1"),
            VersionIntent::Exact("1.0+ubuntu1".to_string())
        );
        // A clean exact pin and a prerelease pin are still Exact.
        assert_eq!(
            VersionIntent::from_pep440_specifier("==1.2.3"),
            VersionIntent::Exact("1.2.3".to_string())
        );
        assert_eq!(
            VersionIntent::from_pep440_specifier("==1.0.0rc1"),
            VersionIntent::Exact("1.0.0rc1".to_string())
        );
    }

    #[test]
    fn range_constraint_parses() {
        let intent = VersionIntent::from_pep440_specifier(">=1.2,<2.0");
        match intent {
            VersionIntent::Constraint {
                raw,
                parsed: Some(c),
            } => {
                assert_eq!(raw, ">=1.2,<2.0");
                assert!(c.matches(&ReleaseVersion::parse("1.5").unwrap()));
                assert!(!c.matches(&ReleaseVersion::parse("2.0").unwrap()));
                assert!(!c.matches(&ReleaseVersion::parse("1.1").unwrap()));
            }
            other => panic!("expected parsed Constraint, got {other:?}"),
        }
    }

    #[test]
    fn compatible_release_operator_does_not_parse() {
        assert!(VersionConstraint::parse("~=1.4.4").is_none());
    }

    #[test]
    fn arbitrary_equality_does_not_parse() {
        assert!(VersionConstraint::parse("===1.4.4").is_none());
    }

    #[test]
    fn marker_does_not_parse() {
        assert!(VersionConstraint::parse(">=1.0 ; python_version < \"3.9\"").is_none());
    }

    #[test]
    fn caret_range_does_not_parse() {
        // npm/cargo `^1.0` is not PEP 440 and is not in the supported subset.
        assert!(VersionConstraint::parse("^1.0").is_none());
    }

    #[test]
    fn epoch_and_local_and_prerelease_versions_do_not_parse() {
        assert!(ReleaseVersion::parse("1!2.0").is_none());
        assert!(ReleaseVersion::parse("1.0+ubuntu1").is_none());
        assert!(ReleaseVersion::parse("1.0rc1").is_none());
        assert!(ReleaseVersion::parse("1.0.post1").is_none());
        assert!(ReleaseVersion::parse("1.0.dev0").is_none());
        assert!(ReleaseVersion::parse("v1.0").is_none());
    }

    #[test]
    fn excessive_segments_do_not_parse() {
        // 17 dot-separated segments is past the cap; the parser refuses it
        // rather than allocating a segment vector sized to the input.
        assert!(ReleaseVersion::parse("1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17").is_none());
    }

    #[test]
    fn trailing_zero_segments_compare_equal() {
        let a = ReleaseVersion::parse("1.4").unwrap();
        let b = ReleaseVersion::parse("1.4.0").unwrap();
        assert_eq!(a.cmp(&b), std::cmp::Ordering::Equal);
    }

    #[test]
    fn ordering_is_numeric_not_lexical() {
        let v9 = ReleaseVersion::parse("1.9").unwrap();
        let v10 = ReleaseVersion::parse("1.10").unwrap();
        assert!(v9 < v10, "1.9 must be less than 1.10");
    }

    #[test]
    fn excluding_constraint_excludes_affected() {
        let c = VersionConstraint::parse(">=1.4.4").unwrap();
        assert!(!c.matches(&ReleaseVersion::parse("1.4.2").unwrap()));
        assert!(!c.matches(&ReleaseVersion::parse("1.4.3").unwrap()));
        assert!(c.matches(&ReleaseVersion::parse("1.4.4").unwrap()));
    }

    #[test]
    fn not_equal_clause_evaluates() {
        let c = VersionConstraint::parse("!=1.4.2").unwrap();
        assert!(!c.matches(&ReleaseVersion::parse("1.4.2").unwrap()));
        assert!(c.matches(&ReleaseVersion::parse("1.4.3").unwrap()));
    }

    #[test]
    fn explicit_plain_version_is_exact() {
        assert_eq!(
            VersionIntent::from_explicit_version("4.17.21"),
            VersionIntent::Exact("4.17.21".to_string())
        );
        // Prerelease/build tails are still exact pins.
        assert_eq!(
            VersionIntent::from_explicit_version("1.2.3-beta.1"),
            VersionIntent::Exact("1.2.3-beta.1".to_string())
        );
    }

    #[test]
    fn explicit_range_is_unparsed_constraint() {
        for raw in ["^4.0", "~4.0", ">=4.0", "1.x", "latest", "4.0 || 5.0"] {
            match VersionIntent::from_explicit_version(raw) {
                VersionIntent::Constraint { raw: r, parsed } => {
                    assert_eq!(r, raw.trim());
                    assert!(parsed.is_none(), "non-PyPI range `{raw}` stays unparsed");
                }
                other => panic!("expected unparsed Constraint for `{raw}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn explicit_empty_is_unspecified() {
        assert_eq!(
            VersionIntent::from_explicit_version(""),
            VersionIntent::Unspecified
        );
    }
}
