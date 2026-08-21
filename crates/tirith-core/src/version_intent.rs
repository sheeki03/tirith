//! Package version intent: a semantics-preserving replacement for the old
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

use once_cell::sync::Lazy;
use regex::Regex;

/// Bound parser work and canonical keys derived from attacker-controlled
/// package specifications. Registry versions are tiny in practice; refusing an
/// oversized spelling is safer than treating it as a concrete release.
const MAX_EXACT_VERSION_BYTES: usize = 256;
const MAX_VERSION_PARTS: usize = 16;

/// The public and local components of a canonical PEP 440 version.
///
/// Keeping the public component separate is required for the deliberate
/// local-to-base rule: a requested local build such as `1.0+ubuntu1` carries
/// the code from public release `1.0`, so a malicious-base record must match it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalPep440Version {
    pub(crate) public: String,
    pub(crate) local: Option<String>,
}

impl CanonicalPep440Version {
    pub(crate) fn full(&self) -> String {
        match &self.local {
            Some(local) => format!("{}+{local}", self.public),
            None => self.public.clone(),
        }
    }
}

/// How a package's version was expressed at the point of reference.
///
/// `Exact` and `Resolved` both name a single concrete version; they are kept
/// distinct because `Exact` is what the user typed (an `==` pin or `name@ver`)
/// while `Resolved` is what a resolver/lockfile pinned. That provenance is
/// security-relevant for PEP 440: public `==1.0` may select `1.0+vendor1`, while
/// a lockfile reporting resolved identity `1.0` names that concrete artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionIntent {
    /// No version was given (e.g. `pip install foo`). The resolver is free to
    /// pick any version, so a version-specific malicious record cannot be
    /// excluded.
    Unspecified,
    /// An exact pin (`==1.2.3`, `name@1.2.3`) in the registry-comparable
    /// spelling when its ecosystem parser supports one.
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

    /// The version text carried by the intent: the canonical concrete version
    /// for `Exact`, resolver text for `Resolved`, raw constraint for
    /// `Constraint`, and `None` for `Unspecified`. This reconstructs the old
    /// lossy `Option<String>` shape for consumers that need one version field.
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

        // A single `==<ver>` is exact only when the WHOLE version parses under
        // PEP 440. This distinguishes concrete releases from wildcards,
        // arbitrary equality, markers, and malformed values, and stores the
        // registry-comparable spelling used by downstream advisory lookups.
        if let Some(rest) = trimmed.strip_prefix("==") {
            let ver = rest.trim();
            if let Some(canonical) = canonical_pep440_version(ver) {
                return VersionIntent::Exact(canonical.full());
            }
        }

        VersionIntent::Constraint {
            parsed: VersionConstraint::parse(trimmed),
            raw: trimmed.to_string(),
        }
    }

    /// Build an intent from a single SemVer-like explicit version token
    /// (`name@1.2.3`, `name:^3.0`, `--version 1.2.3`).
    ///
    /// Only a complete valid SemVer is an [`Exact`](VersionIntent::Exact) pin.
    /// Anything carrying a range sigil, wildcard, dist-tag (including a tag
    /// that begins with a digit), partial version, or whitespace becomes an
    /// unparsed
    /// [`Constraint`](VersionIntent::Constraint) (the constraint syntax of these
    /// ecosystems is not modeled, so it stays unresolved rather than being
    /// mistaken for an exact pin).
    pub fn from_explicit_version(token: &str) -> VersionIntent {
        let t = token.trim();
        if t.is_empty() {
            return VersionIntent::Unspecified;
        }
        if let Some(canonical) = canonical_semver_concrete(t, SemverPrefix::OptionalV, false) {
            VersionIntent::Exact(canonical)
        } else {
            // The constraint syntax of non-PyPI ecosystems is not parsed; keep
            // the raw text and leave it unresolved.
            VersionIntent::Constraint {
                parsed: None,
                raw: t.to_string(),
            }
        }
    }

    /// Build an npm version intent. A complete SemVer (with npm's accepted
    /// leading `v` spelling) is exact; dist-tags, git revisions, aliases,
    /// partial versions, and ranges stay unresolved until a resolver supplies
    /// the concrete version.
    pub fn from_npm_version(token: &str) -> VersionIntent {
        Self::from_explicit_version(token)
    }

    /// Build a Go module version-query intent. Only a complete canonical
    /// `vMAJOR.MINOR.PATCH` semantic version is concrete. Branch names,
    /// non-version tags, commit prefixes (including digit-leading ones),
    /// `latest`, and partial version queries are resolver selectors and remain
    /// unresolved.
    pub fn from_go_version(token: &str) -> VersionIntent {
        let t = token.trim();
        if t.is_empty() {
            return VersionIntent::Unspecified;
        }
        // The Go command rewrites arbitrary SemVer build metadata to a
        // pseudo-version. Only `+incompatible` is part of a canonical module
        // version and therefore proven to name the version written here.
        let has_canonical_build = t
            .split_once('+')
            .is_none_or(|(_, build)| build == "incompatible");
        match canonical_semver_concrete(t, SemverPrefix::RequiredV, true)
            .filter(|_| has_canonical_build)
        {
            Some(canonical) => VersionIntent::Exact(canonical),
            None => VersionIntent::Constraint {
                parsed: None,
                raw: t.to_string(),
            },
        }
    }

    /// Build a NuGet version intent. NuGet floating versions and ranges remain
    /// unresolved; a concrete full 3-4 component version is normalized to
    /// NuGet's case-insensitive, trailing-zero-equivalent identity. Shorter
    /// PackageReference values remain ranges.
    pub fn from_nuget_version(token: &str) -> VersionIntent {
        let t = token.trim();
        if t.is_empty() {
            return VersionIntent::Unspecified;
        }
        // A bare one/two-component PackageReference value is a minimum range
        // in NuGet dependency syntax. Require a full package version here even
        // though the registry comparator below accepts shorter equivalent
        // spellings from advisory data.
        let public = t.split('+').next().unwrap_or(t);
        let release = public.split('-').next().unwrap_or(public);
        let release_parts = release.split('.').count();
        match canonical_nuget_version(t).filter(|_| release_parts >= 3) {
            Some(canonical) => VersionIntent::Exact(canonical),
            None => VersionIntent::Constraint {
                parsed: None,
                raw: t.to_string(),
            },
        }
    }

    /// Build a Composer/Packagist version intent. Composer accepts branch and
    /// stability selectors that can begin with digits; only a complete
    /// concrete Composer version is proven concrete here.
    pub fn from_composer_version(token: &str) -> VersionIntent {
        let t = token.trim();
        if t.is_empty() {
            return VersionIntent::Unspecified;
        }
        match canonical_composer_version(t) {
            Some(canonical) => VersionIntent::Exact(canonical),
            None => VersionIntent::Constraint {
                parsed: None,
                raw: t.to_string(),
            },
        }
    }

    /// Build an intent for Maven's literal version coordinate. Maven ranges,
    /// mutable `-SNAPSHOT` versions, and the dynamic `LATEST`/`RELEASE`
    /// selectors stay unresolved; other coordinate values name that literal
    /// version.
    pub fn from_maven_version(token: &str) -> VersionIntent {
        let t = token.trim();
        if t.is_empty() {
            return VersionIntent::Unspecified;
        }
        let uppercase = t.to_ascii_uppercase();
        let dynamic = matches!(uppercase.as_str(), "LATEST" | "RELEASE")
            || uppercase.ends_with("-SNAPSHOT")
            || t.starts_with(['[', '('])
            || t.contains(',')
            || t.chars().any(char::is_whitespace);
        if dynamic {
            VersionIntent::Constraint {
                parsed: None,
                raw: t.to_string(),
            }
        } else {
            VersionIntent::Exact(t.to_string())
        }
    }

    /// Build a Docker reference intent. Immutable SHA-256 digests and literal
    /// complete SemVer-shaped tags are concrete references. Free-form mutable
    /// selectors remain unresolved so a version-specific malicious record
    /// cannot be dismissed as a clean miss.
    pub fn from_docker_version(token: &str) -> VersionIntent {
        let t = token.trim();
        if t.is_empty() {
            return VersionIntent::Unspecified;
        }
        if let Some(hex) = t.strip_prefix("sha256:") {
            if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return VersionIntent::Exact(format!("sha256:{}", hex.to_ascii_lowercase()));
            }
        }
        if t.len() <= 128
            && !t.contains('+')
            && canonical_semver(t, SemverPrefix::OptionalV).is_some()
        {
            // Docker tag names are literal and case-sensitive. Validate the
            // shape as SemVer, but do not erase a leading `v` or change case.
            VersionIntent::Exact(t.to_string())
        } else {
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
            if let Some(canonical) =
                canonical_semver_concrete(pinned, SemverPrefix::Forbidden, false)
            {
                return VersionIntent::Exact(canonical);
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
        if stripped.is_empty() {
            return VersionIntent::Unspecified;
        }
        if let Some(canonical) = canonical_rubygems_version(stripped) {
            VersionIntent::Exact(canonical)
        } else {
            VersionIntent::Constraint {
                parsed: None,
                raw: t.to_string(),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SemverPrefix {
    Forbidden,
    OptionalV,
    RequiredV,
}

/// Return a canonical SemVer identity without build metadata.
///
/// SemVer build metadata does not participate in precedence/equality, while
/// prerelease identifiers do (and are case-sensitive). Numeric identifiers are
/// validated as strings so an attacker cannot force integer overflow with an
/// otherwise syntactically valid, very large version component.
pub(crate) fn canonical_semver(raw: &str, prefix: SemverPrefix) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_EXACT_VERSION_BYTES || !raw.is_ascii() {
        return None;
    }
    let body = match prefix {
        SemverPrefix::Forbidden => {
            if raw.starts_with(['v', 'V']) {
                return None;
            }
            raw
        }
        SemverPrefix::OptionalV => raw.strip_prefix(['v', 'V']).unwrap_or(raw),
        SemverPrefix::RequiredV => raw.strip_prefix('v')?,
    };

    let mut plus = body.split('+');
    let public = plus.next()?;
    let build = plus.next();
    if plus.next().is_some() {
        return None;
    }
    if let Some(build) = build {
        if !valid_semver_identifiers(build, false) {
            return None;
        }
    }

    let (release, prerelease) = match public.split_once('-') {
        Some((release, prerelease)) => (release, Some(prerelease)),
        None => (public, None),
    };
    let release_parts: Vec<&str> = release.split('.').collect();
    if release_parts.len() != 3 || release_parts.iter().any(|part| !valid_semver_numeric(part)) {
        return None;
    }
    if prerelease.is_some_and(|pre| !valid_semver_identifiers(pre, true)) {
        return None;
    }

    let mut canonical = release_parts.join(".");
    if let Some(pre) = prerelease {
        canonical.push('-');
        canonical.push_str(pre);
    }
    Some(canonical)
}

/// Return a concrete SemVer spelling suitable for resolver/API use while
/// retaining valid build metadata. `canonical_semver` deliberately omits build
/// metadata for equality; this wrapper keeps it on the source-side intent so a
/// later exact artifact lookup does not silently request a different spelling.
fn canonical_semver_concrete(
    raw: &str,
    prefix: SemverPrefix,
    emit_lowercase_v: bool,
) -> Option<String> {
    let raw = raw.trim();
    let public = canonical_semver(raw, prefix)?;
    let build = raw.split_once('+').map(|(_, build)| build);
    let mut concrete = String::with_capacity(raw.len());
    if emit_lowercase_v {
        concrete.push('v');
    }
    concrete.push_str(&public);
    if let Some(build) = build {
        concrete.push('+');
        concrete.push_str(build);
    }
    Some(concrete)
}

fn valid_semver_numeric(part: &str) -> bool {
    !part.is_empty()
        && part.bytes().all(|b| b.is_ascii_digit())
        && (part == "0" || !part.starts_with('0'))
}

fn valid_semver_identifiers(raw: &str, reject_numeric_leading_zero: bool) -> bool {
    let mut count = 0usize;
    for part in raw.split('.') {
        count += 1;
        if count > MAX_VERSION_PARTS
            || part.is_empty()
            || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || (reject_numeric_leading_zero
                && part.bytes().all(|b| b.is_ascii_digit())
                && part.len() > 1
                && part.starts_with('0'))
        {
            return false;
        }
    }
    count > 0
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SemverPrecedenceIdentifier {
    Numeric(String),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SemverPrecedence {
    release: [String; 3],
    prerelease: Option<Vec<SemverPrecedenceIdentifier>>,
}

fn parse_semver_precedence(raw: &str) -> Option<SemverPrecedence> {
    let canonical = canonical_semver(raw, SemverPrefix::OptionalV)?;
    let (release, prerelease) = canonical
        .split_once('-')
        .map_or((canonical.as_str(), None), |(release, pre)| {
            (release, Some(pre))
        });
    let mut release = release.split('.').map(str::to_string);
    let release = [release.next()?, release.next()?, release.next()?];
    if release
        .iter()
        .any(|part| part.len() > 1 && part.starts_with('0'))
    {
        return None;
    }
    let prerelease = prerelease.map(|value| {
        value
            .split('.')
            .map(|part| {
                if part.bytes().all(|byte| byte.is_ascii_digit()) {
                    SemverPrecedenceIdentifier::Numeric(part.to_string())
                } else {
                    // SemVer 2.0.0 compares ASCII identifiers lexically and
                    // case-sensitively. Preserve the source spelling exactly.
                    SemverPrecedenceIdentifier::Text(part.to_string())
                }
            })
            .collect()
    });
    Some(SemverPrecedence {
        release,
        prerelease,
    })
}

fn compare_canonical_decimal(left: &str, right: &str) -> std::cmp::Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

/// Compare two concrete npm/SemVer public versions by SemVer 2.0.0
/// precedence. Build metadata is ignored and prerelease text is deliberately
/// ASCII case-sensitive. Returns `None` for aliases, ranges, malformed values,
/// or versions outside Tirith's bounded concrete-version grammar.
pub fn compare_semver_public_versions(left: &str, right: &str) -> Option<std::cmp::Ordering> {
    let left = parse_semver_precedence(left)?;
    let right = parse_semver_precedence(right)?;
    for (left, right) in left.release.iter().zip(right.release.iter()) {
        match compare_canonical_decimal(left, right) {
            std::cmp::Ordering::Equal => {}
            ordering => return Some(ordering),
        }
    }
    match (&left.prerelease, &right.prerelease) {
        (None, None) => Some(std::cmp::Ordering::Equal),
        (None, Some(_)) => Some(std::cmp::Ordering::Greater),
        (Some(_), None) => Some(std::cmp::Ordering::Less),
        (Some(left), Some(right)) => {
            for index in 0..left.len().max(right.len()) {
                match (left.get(index), right.get(index)) {
                    (None, None) => return Some(std::cmp::Ordering::Equal),
                    (None, Some(_)) => return Some(std::cmp::Ordering::Less),
                    (Some(_), None) => return Some(std::cmp::Ordering::Greater),
                    (
                        Some(SemverPrecedenceIdentifier::Numeric(left)),
                        Some(SemverPrecedenceIdentifier::Numeric(right)),
                    ) => match compare_canonical_decimal(left, right) {
                        std::cmp::Ordering::Equal => {}
                        ordering => return Some(ordering),
                    },
                    (
                        Some(SemverPrecedenceIdentifier::Numeric(_)),
                        Some(SemverPrecedenceIdentifier::Text(_)),
                    ) => return Some(std::cmp::Ordering::Less),
                    (
                        Some(SemverPrecedenceIdentifier::Text(_)),
                        Some(SemverPrecedenceIdentifier::Numeric(_)),
                    ) => return Some(std::cmp::Ordering::Greater),
                    (
                        Some(SemverPrecedenceIdentifier::Text(left)),
                        Some(SemverPrecedenceIdentifier::Text(right)),
                    ) => match left.as_bytes().cmp(right.as_bytes()) {
                        std::cmp::Ordering::Equal => {}
                        ordering => return Some(ordering),
                    },
                }
            }
            Some(std::cmp::Ordering::Equal)
        }
    }
}

/// Canonicalize a concrete NuGet version. NuGet compares prerelease labels
/// case-insensitively, ignores build metadata, and treats missing/trailing zero
/// release components as equivalent. Floating (`*`) and range syntax never
/// reaches this function as a concrete identity.
pub(crate) fn canonical_nuget_version(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_EXACT_VERSION_BYTES || !raw.is_ascii() {
        return None;
    }
    let mut plus = raw.split('+');
    let public = plus.next()?;
    let build = plus.next();
    if plus.next().is_some() || build.is_some_and(|value| !valid_semver_identifiers(value, false)) {
        return None;
    }
    let (release, prerelease) = match public.split_once('-') {
        Some((release, prerelease)) => (release, Some(prerelease)),
        None => (public, None),
    };
    let parts: Vec<&str> = release.split('.').collect();
    if parts.is_empty()
        || parts.len() > 4
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    if prerelease.is_some_and(|pre| !valid_semver_identifiers(pre, false)) {
        return None;
    }

    let mut normalized: Vec<String> = parts.iter().map(|part| normalize_decimal(part)).collect();
    while normalized.len() < 3 {
        normalized.push("0".to_string());
    }
    while normalized.len() > 3 && normalized.last().is_some_and(|part| part == "0") {
        normalized.pop();
    }
    let mut canonical = normalized.join(".");
    if let Some(pre) = prerelease {
        canonical.push('-');
        canonical.push_str(
            &pre.split('.')
                .map(|part| {
                    if part.bytes().all(|b| b.is_ascii_digit()) {
                        normalize_decimal(part)
                    } else {
                        part.to_ascii_lowercase()
                    }
                })
                .collect::<Vec<_>>()
                .join("."),
        );
    }
    Some(canonical)
}

static COMPOSER_VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?xi)^
        v?
        (?P<release>[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)
        (?:[-_.]?
            (?P<stability>stable|dev|patch|p|alpha|a|beta|b|rc)
            (?:[-_.]?(?P<stability_n>[0-9]+))?
        )?
        (?:\+(?P<build>[0-9a-z-]+(?:\.[0-9a-z-]+)*))?
        $",
    )
    .expect("static Composer version regex")
});

static RUBYGEMS_VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[0-9]+(?:\.[0-9A-Za-z]+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")
        .expect("static RubyGems version regex")
});

/// Validate and canonicalize one concrete `Gem::Version` spelling. RubyGems
/// treats letters as case-sensitive, rewrites hyphens to `.pre.`, splits
/// alphanumeric segments, and ignores trailing numeric zero segments on both
/// sides of the first alphabetic segment. Tokens outside its grammar
/// (including digit-leading aliases such as `1stable`) are resolver/requirement
/// expressions, not proven releases.
pub(crate) fn canonical_rubygems_version(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty()
        || raw.len() > MAX_EXACT_VERSION_BYTES
        || !raw.is_ascii()
        || !RUBYGEMS_VERSION_RE.is_match(raw)
    {
        return None;
    }
    #[derive(Clone)]
    enum Segment {
        Numeric(String),
        Alpha(String),
    }

    let normalized = raw.replace('-', ".pre.");
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut current_is_numeric = None;
    for byte in normalized.bytes() {
        if byte == b'.' {
            if !current.is_empty() {
                segments.push(if current_is_numeric == Some(true) {
                    Segment::Numeric(normalize_decimal(&current))
                } else {
                    Segment::Alpha(std::mem::take(&mut current))
                });
                current.clear();
                current_is_numeric = None;
            }
            continue;
        }
        let is_numeric = byte.is_ascii_digit();
        if current_is_numeric.is_some_and(|kind| kind != is_numeric) {
            segments.push(if current_is_numeric == Some(true) {
                Segment::Numeric(normalize_decimal(&current))
            } else {
                Segment::Alpha(std::mem::take(&mut current))
            });
            current.clear();
        }
        current_is_numeric = Some(is_numeric);
        current.push(byte as char);
    }
    if !current.is_empty() {
        segments.push(if current_is_numeric == Some(true) {
            Segment::Numeric(normalize_decimal(&current))
        } else {
            Segment::Alpha(current)
        });
    }

    let first_alpha = segments
        .iter()
        .position(|segment| matches!(segment, Segment::Alpha(_)))
        .unwrap_or(segments.len());
    let mut numeric = segments[..first_alpha].to_vec();
    let mut prerelease = segments[first_alpha..].to_vec();
    while matches!(numeric.last(), Some(Segment::Numeric(value)) if value == "0") {
        numeric.pop();
    }
    while matches!(prerelease.last(), Some(Segment::Numeric(value)) if value == "0") {
        prerelease.pop();
    }
    numeric.append(&mut prerelease);
    if numeric.is_empty() || matches!(numeric.first(), Some(Segment::Alpha(_))) {
        numeric.insert(0, Segment::Numeric("0".to_string()));
    }
    Some(
        numeric
            .into_iter()
            .map(|segment| match segment {
                Segment::Numeric(value) | Segment::Alpha(value) => value,
            })
            .collect::<Vec<_>>()
            .join("."),
    )
}

/// Canonicalize a concrete Composer/Packagist version.
///
/// Composer normalizes a leading `v`, an optional fourth zero component, and
/// case-insensitive stability aliases such as `RC`, `a`, and `p`. Branch names,
/// wildcard versions, stability flags, and other solver expressions do not
/// match this grammar and therefore stay unresolved.
pub(crate) fn canonical_composer_version(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_EXACT_VERSION_BYTES || !raw.is_ascii() {
        return None;
    }
    let captures = COMPOSER_VERSION_RE.captures(raw)?;
    let mut release: Vec<String> = captures
        .name("release")?
        .as_str()
        .split('.')
        .map(normalize_decimal)
        .collect();
    if release.len() == 4 && release.last().is_some_and(|part| part == "0") {
        release.pop();
    }
    let mut canonical = release.join(".");

    if let Some(stability) = captures.name("stability") {
        let stability = stability.as_str().to_ascii_lowercase();
        let number = captures
            .name("stability_n")
            .map(|value| normalize_decimal(value.as_str()));
        match stability.as_str() {
            "stable" if number.is_none() => {}
            "dev" if number.is_none() => canonical.push_str("-dev"),
            "patch" | "p" => {
                canonical.push_str("-patch");
                canonical.push_str(number.as_deref().unwrap_or("0"));
            }
            "alpha" | "a" => {
                canonical.push_str("-alpha");
                canonical.push_str(number.as_deref().unwrap_or("0"));
            }
            "beta" | "b" => {
                canonical.push_str("-beta");
                canonical.push_str(number.as_deref().unwrap_or("0"));
            }
            "rc" => {
                canonical.push_str("-rc");
                canonical.push_str(number.as_deref().unwrap_or("0"));
            }
            _ => return None,
        }
    }
    Some(canonical)
}

static PEP440_VERSION_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?xi)^
        v?
        (?:(?P<epoch>[0-9]+)!)?
        (?P<release>[0-9]+(?:\.[0-9]+)*)
        (?:
            [-_.]?
            (?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)
            [-_.]?
            (?P<pre_n>[0-9]+)?
        )?
        (?:
            (?P<post_n1>-[0-9]+)
            |
            (?:
                [-_.]?
                (?P<post_l>post|rev|r)
                [-_.]?
                (?P<post_n2>[0-9]+)?
            )
        )?
        (?:
            [-_.]?
            (?P<dev_l>dev)
            [-_.]?
            (?P<dev_n>[0-9]+)?
        )?
        (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
        $",
    )
    .expect("static PEP 440 version regex")
});

/// Parse and canonicalize the PEP 440 public/local identity used by PyPI.
pub(crate) fn canonical_pep440_version(raw: &str) -> Option<CanonicalPep440Version> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_EXACT_VERSION_BYTES || !raw.is_ascii() {
        return None;
    }
    let captures = PEP440_VERSION_RE.captures(raw)?;
    let release = captures.name("release")?.as_str();
    let mut release_parts: Vec<String> = release.split('.').map(normalize_decimal).collect();
    if release_parts.len() > MAX_VERSION_PARTS {
        return None;
    }
    while release_parts.len() > 1 && release_parts.last().is_some_and(|part| part == "0") {
        release_parts.pop();
    }

    let epoch = captures
        .name("epoch")
        .map(|value| normalize_decimal(value.as_str()))
        .unwrap_or_else(|| "0".to_string());
    let mut public = String::new();
    if epoch != "0" {
        public.push_str(&epoch);
        public.push('!');
    }
    public.push_str(&release_parts.join("."));

    if let Some(label) = captures.name("pre_l") {
        let label = match label.as_str().to_ascii_lowercase().as_str() {
            "alpha" | "a" => "a",
            "beta" | "b" => "b",
            "preview" | "pre" | "c" | "rc" => "rc",
            _ => return None,
        };
        let number = captures
            .name("pre_n")
            .map(|value| normalize_decimal(value.as_str()))
            .unwrap_or_else(|| "0".to_string());
        public.push_str(label);
        public.push_str(&number);
    }

    let post_number = captures
        .name("post_n1")
        .map(|value| value.as_str().trim_start_matches('-'))
        .or_else(|| captures.name("post_n2").map(|value| value.as_str()));
    if captures.name("post_n1").is_some() || captures.name("post_l").is_some() {
        public.push_str(".post");
        public.push_str(&normalize_decimal(post_number.unwrap_or("0")));
    }

    if captures.name("dev_l").is_some() {
        let number = captures
            .name("dev_n")
            .map(|value| normalize_decimal(value.as_str()))
            .unwrap_or_else(|| "0".to_string());
        public.push_str(".dev");
        public.push_str(&number);
    }

    let local = captures.name("local").map(|value| {
        value
            .as_str()
            .split(['-', '_', '.'])
            .map(|part| {
                if part.bytes().all(|b| b.is_ascii_digit()) {
                    normalize_decimal(part)
                } else {
                    part.to_ascii_lowercase()
                }
            })
            .collect::<Vec<_>>()
            .join(".")
    });
    if local
        .as_deref()
        .is_some_and(|value| value.split('.').count() > MAX_VERSION_PARTS)
    {
        return None;
    }
    Some(CanonicalPep440Version { public, local })
}

/// Compare two concrete PyPI versions by their PEP 440 public precedence.
///
/// Local labels are deliberately ignored, matching ordered PEP 440 specifier
/// semantics: `1.0+vendor.1` compares equal to the public boundary `1.0` for
/// `<`, `<=`, `>`, and `>=` range projection. The parser is the same bounded
/// grammar used by [`canonical_pep440_version`], including epochs, pre-releases,
/// post-releases, and development releases.
pub fn compare_pep440_public_versions(left: &str, right: &str) -> Option<std::cmp::Ordering> {
    Some(Pep440PrecedenceKey::parse(left)?.cmp(&Pep440PrecedenceKey::parse(right)?))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pep440PrecedenceKey {
    epoch: String,
    release: Vec<String>,
    pre: Pep440Pre,
    post: Pep440OptionalNumber,
    dev: Pep440Dev,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Pep440Pre {
    NegativeInfinity,
    Value(u8, NumericString),
    Infinity,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Pep440OptionalNumber {
    NegativeInfinity,
    Value(NumericString),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Pep440Dev {
    Value(NumericString),
    Infinity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NumericString(String);

impl NumericString {
    fn new(raw: &str) -> Self {
        Self(normalize_decimal(raw))
    }
}

impl PartialOrd for NumericString {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NumericString {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.cmp(&other.0))
    }
}

impl Pep440PrecedenceKey {
    fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty() || raw.len() > MAX_EXACT_VERSION_BYTES || !raw.is_ascii() {
            return None;
        }
        let captures = PEP440_VERSION_RE.captures(raw)?;
        let release = captures
            .name("release")?
            .as_str()
            .split('.')
            .map(normalize_decimal)
            .collect::<Vec<_>>();
        if release.len() > MAX_VERSION_PARTS {
            return None;
        }
        let epoch = captures
            .name("epoch")
            .map(|value| normalize_decimal(value.as_str()))
            .unwrap_or_else(|| "0".to_string());
        let post_number = captures
            .name("post_n1")
            .map(|value| value.as_str().trim_start_matches('-'))
            .or_else(|| captures.name("post_n2").map(|value| value.as_str()));
        let post = if captures.name("post_n1").is_some() || captures.name("post_l").is_some() {
            Pep440OptionalNumber::Value(NumericString::new(post_number.unwrap_or("0")))
        } else {
            Pep440OptionalNumber::NegativeInfinity
        };
        let dev = if captures.name("dev_l").is_some() {
            Pep440Dev::Value(NumericString::new(
                captures
                    .name("dev_n")
                    .map(|value| value.as_str())
                    .unwrap_or("0"),
            ))
        } else {
            Pep440Dev::Infinity
        };
        let pre = if let Some(label) = captures.name("pre_l") {
            let rank = match label.as_str().to_ascii_lowercase().as_str() {
                "alpha" | "a" => 0,
                "beta" | "b" => 1,
                "preview" | "pre" | "c" | "rc" => 2,
                _ => return None,
            };
            Pep440Pre::Value(
                rank,
                NumericString::new(
                    captures
                        .name("pre_n")
                        .map(|value| value.as_str())
                        .unwrap_or("0"),
                ),
            )
        } else if matches!(post, Pep440OptionalNumber::NegativeInfinity)
            && !matches!(dev, Pep440Dev::Infinity)
        {
            Pep440Pre::NegativeInfinity
        } else {
            Pep440Pre::Infinity
        };
        Some(Self {
            epoch,
            release,
            pre,
            post,
            dev,
        })
    }
}

impl PartialOrd for Pep440PrecedenceKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Pep440PrecedenceKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match NumericString(self.epoch.clone()).cmp(&NumericString(other.epoch.clone())) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
        let release_len = self.release.len().max(other.release.len());
        for index in 0..release_len {
            let left = self.release.get(index).map(String::as_str).unwrap_or("0");
            let right = other.release.get(index).map(String::as_str).unwrap_or("0");
            match NumericString::new(left).cmp(&NumericString::new(right)) {
                std::cmp::Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        self.pre
            .cmp(&other.pre)
            .then_with(|| self.post.cmp(&other.post))
            .then_with(|| self.dev.cmp(&other.dev))
    }
}

fn normalize_decimal(raw: &str) -> String {
    let normalized = raw.trim_start_matches('0');
    if normalized.is_empty() {
        "0".to_string()
    } else {
        normalized.to_string()
    }
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
    } else {
        // Only `>` remains here; a bare version, a caret/tilde range, or anything
        // else is not a recognized operator, so `?` yields None (not understood).
        let r = part.strip_prefix('>')?;
        (Operator::Gt, r)
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
        // PEP 440 treats missing release segments as zero. Store a single
        // canonical representation so derived Eq agrees with Ord and ordered
        // collections observe one identity for `1.4`, `1.4.0`, and so on.
        while segments.len() > 1 && segments.last() == Some(&0) {
            segments.pop();
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
        // A lone valid prerelease is exact and stored in canonical PEP 440 form.
        match VersionIntent::from_pep440_specifier("==1.0.0rc1") {
            VersionIntent::Exact(v) => assert_eq!(v, "1rc1"),
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
            VersionIntent::Exact("1+ubuntu1".to_string())
        );
        // A clean exact pin and a prerelease pin are still Exact.
        assert_eq!(
            VersionIntent::from_pep440_specifier("==1.2.3"),
            VersionIntent::Exact("1.2.3".to_string())
        );
        assert_eq!(
            VersionIntent::from_pep440_specifier("==1.0.0rc1"),
            VersionIntent::Exact("1rc1".to_string())
        );
    }

    #[test]
    fn pep440_exact_versions_use_registry_canonical_identity() {
        for (raw, canonical) in [
            ("==v1.0.0", "1"),
            ("==1.0RC01", "1rc1"),
            ("==01.002-post03", "1.2.post3"),
            ("==1.0+Ubuntu_01", "1+ubuntu.1"),
        ] {
            assert_eq!(
                VersionIntent::from_pep440_specifier(raw),
                VersionIntent::Exact(canonical.to_string()),
                "{raw}"
            );
        }
    }

    #[test]
    fn pep440_public_precedence_covers_dev_pre_final_and_post() {
        let ordered = [
            "1.0.dev1",
            "1.0a1.dev1",
            "1.0a1",
            "1.0b1",
            "1.0rc1",
            "1.0",
            "1.0.post1.dev1",
            "1.0.post1",
        ];
        for pair in ordered.windows(2) {
            assert_eq!(
                compare_pep440_public_versions(pair[0], pair[1]),
                Some(std::cmp::Ordering::Less),
                "{} must sort before {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn pep440_public_precedence_handles_epoch_release_padding_and_local_labels() {
        assert_eq!(
            compare_pep440_public_versions("1.0+vendor.1", "1.0"),
            Some(std::cmp::Ordering::Equal)
        );
        assert_eq!(
            compare_pep440_public_versions("1.0.0", "1.0"),
            Some(std::cmp::Ordering::Equal)
        );
        assert_eq!(
            compare_pep440_public_versions("1!0.1", "2.0"),
            Some(std::cmp::Ordering::Greater)
        );
        assert_eq!(compare_pep440_public_versions("not-a-version", "1.0"), None);
    }

    #[test]
    fn semver_public_precedence_preserves_ascii_prerelease_case() {
        assert_eq!(
            compare_semver_public_versions("1.0.0-RC.1", "1.0.0-rc.1"),
            Some(std::cmp::Ordering::Less)
        );
        assert_eq!(
            compare_semver_public_versions("1.0.0-rc.1", "1.0.0-RC.1"),
            Some(std::cmp::Ordering::Greater)
        );
        assert_eq!(
            compare_semver_public_versions("1.0.0+BUILD", "1.0.0+build"),
            Some(std::cmp::Ordering::Equal)
        );
    }

    #[test]
    fn semver_public_precedence_is_numeric_and_rejects_nonconcrete_values() {
        assert_eq!(
            compare_semver_public_versions("1.9.0", "1.10.0"),
            Some(std::cmp::Ordering::Less)
        );
        assert_eq!(
            compare_semver_public_versions("1.0.0-9", "1.0.0-10"),
            Some(std::cmp::Ordering::Less)
        );
        assert_eq!(compare_semver_public_versions("^1.0.0", "1.0.0"), None);
    }

    #[test]
    fn ecosystem_selectors_are_not_misclassified_as_exact() {
        for intent in [
            VersionIntent::from_npm_version("1stable"),
            VersionIntent::from_npm_version("1.2"),
            VersionIntent::from_go_version("123abc"),
            VersionIntent::from_go_version("v1.2"),
            VersionIntent::from_go_version("v1.2.3+metadata"),
            VersionIntent::from_composer_version("1stable"),
            VersionIntent::from_gem_version("1stable"),
            VersionIntent::from_maven_version("1.2.3-SNAPSHOT"),
            VersionIntent::from_nuget_version("v1.2.3"),
            VersionIntent::from_nuget_version("1.2"),
            VersionIntent::from_nuget_version("1.*"),
        ] {
            assert!(matches!(
                intent,
                VersionIntent::Constraint { parsed: None, .. }
            ));
        }
    }

    #[test]
    fn ecosystem_concrete_version_controls_remain_exact() {
        assert_eq!(
            VersionIntent::from_npm_version("v1.2.3-beta.1+build.7"),
            VersionIntent::Exact("1.2.3-beta.1+build.7".to_string())
        );
        assert_eq!(
            VersionIntent::from_go_version("v0.0.0-20260101000000-abcdef123456"),
            VersionIntent::Exact("v0.0.0-20260101000000-abcdef123456".to_string())
        );
        assert_eq!(
            VersionIntent::from_go_version("v2.0.0+incompatible"),
            VersionIntent::Exact("v2.0.0+incompatible".to_string())
        );
        assert_eq!(
            VersionIntent::from_cargo_version("=1.2.3+vendor.7"),
            VersionIntent::Exact("1.2.3+vendor.7".to_string())
        );
        assert_eq!(
            VersionIntent::from_nuget_version("01.2.0.0-RC.01+BUILD"),
            VersionIntent::Exact("1.2.0-rc.1".to_string())
        );
        assert_eq!(
            VersionIntent::from_composer_version("v01.2.3.0-RC01+build.7"),
            VersionIntent::Exact("1.2.3-rc1".to_string())
        );
        assert_eq!(
            VersionIntent::from_gem_version("1.0-RC1"),
            VersionIntent::Exact("1.pre.RC.1".to_string())
        );
        assert_eq!(
            VersionIntent::from_docker_version("v1.2.3"),
            VersionIntent::Exact("v1.2.3".to_string()),
            "Docker tag identity is literal"
        );
        assert_eq!(
            VersionIntent::from_maven_version("1stable"),
            VersionIntent::Exact("1stable".to_string()),
            "Maven coordinates are literal, not resolver dist-tags"
        );
    }

    #[test]
    fn rubygems_versions_follow_gem_version_canonical_segments() {
        for (raw, canonical) in [
            ("1.0.0", "1"),
            ("1.0-RC1", "1.pre.RC.1"),
            ("1.0.pre.RC1", "1.pre.RC.1"),
            ("1.0.a.0", "1.a"),
            ("0.0.a.0", "0.a"),
            ("01.002", "1.2"),
        ] {
            assert_eq!(canonical_rubygems_version(raw).as_deref(), Some(canonical));
        }
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
        assert_eq!(a, b, "Eq must agree with Ord for trailing-zero forms");
    }

    #[test]
    fn trailing_zero_versions_are_one_ordered_collection_key() {
        // pr173-0028: ordered collections must observe the same identity as `==`.
        let short = ReleaseVersion::parse("1.4").unwrap();
        let padded = ReleaseVersion::parse("1.4.0.0").unwrap();
        let mut versions = std::collections::BTreeSet::new();
        assert!(versions.insert(short.clone()));
        assert!(!versions.insert(padded.clone()));
        assert_eq!(short, padded);
        assert!(versions.contains(&padded));
    }

    #[test]
    fn canonicalization_preserves_nonzero_ordering_and_zero_versions() {
        // Legitimate controls: removing redundant trailing zeroes must not alter
        // numeric ordering, and all-zero versions remain valid values.
        assert!(ReleaseVersion::parse("1.4.1").unwrap() > ReleaseVersion::parse("1.4").unwrap());
        assert_eq!(
            ReleaseVersion::parse("0").unwrap(),
            ReleaseVersion::parse("0.0.0").unwrap()
        );
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
