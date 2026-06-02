//! M6 ch6/ch7 — dependency-confusion heuristic. Offline, read-only.
//!
//!  1. Operator-supplied internal-name patterns
//!     (`package_policy.internal_package_names`, M6 ch7): a public-registry
//!     resolution matching one is the textbook dep-confusion shape. Each
//!     [`InternalPackageSpec`] may scope to an ecosystem; a trailing `@<org>/*`
//!     wildcard is supported.
//!  2. Registry-namespace shape: without the operator list, fall back to
//!     `@<reserved-org>/<name>` npm scopes (`@internal`, `@private`, …).
//!     Conservative — false positives on legit scoped packages hurt more than
//!     a missed signal.

use crate::package_risk::DepConfusionVerdict;
use crate::policy::{InternalPackageSpec, Policy};
use crate::threatdb::Ecosystem;

/// Evaluate the dependency-confusion heuristic for `(eco, name)`.
///
/// `risk == false` is the default; only a positive match flips it.
pub fn evaluate(eco: Ecosystem, name: &str, policy: &Policy) -> DepConfusionVerdict {
    // Whitespace-padded names don't resolve at the registry → no-match.
    let name = name.trim();
    if name.is_empty() {
        return DepConfusionVerdict {
            risk: false,
            reason: String::new(),
        };
    }

    // (1) Operator-supplied internal-name patterns. `ecosystem == None`
    // matches every ecosystem; patterns support a single trailing `*`.
    for spec in &policy.package_policy.internal_package_names {
        if !ecosystem_matches(spec, eco) {
            continue;
        }
        if matches_pattern(&spec.name, name) {
            return DepConfusionVerdict {
                risk: true,
                reason: format!(
                    "name '{name}' matches the operator-declared internal pattern \
                     '{pattern}'; resolving it on the public registry shadows the \
                     internal package.",
                    pattern = spec.name,
                ),
            };
        }
    }

    // (2) Registry-namespace shape — npm scopes that look internal-only.
    if matches!(eco, Ecosystem::Npm) {
        if let Some(scope) = npm_scope(name) {
            if is_reserved_internal_scope(scope) {
                return DepConfusionVerdict {
                    risk: true,
                    reason: format!(
                        "the scope '{scope}' has a reserved/internal shape; resolving \
                         '{name}' on the public registry can shadow an internal package."
                    ),
                };
            }
        }
    }

    DepConfusionVerdict {
        risk: false,
        reason: String::new(),
    }
}

/// `true` when `pattern` matches `name`. The only supported wildcard is a
/// single trailing `*`: `@org/*` matches every `@org/<anything>` name.
fn matches_pattern(pattern: &str, name: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else {
        pattern == name
    }
}

/// Return the `@<scope>` portion of an npm scoped name (`@org`), or `None`.
fn npm_scope(name: &str) -> Option<&str> {
    if !name.starts_with('@') {
        return None;
    }
    let slash = name.find('/')?;
    Some(&name[..slash])
}

/// `true` when this spec is unscoped (matches every ecosystem) or its declared
/// ecosystem matches `eco` (case-insensitive, matching `Ecosystem` serialization).
fn ecosystem_matches(spec: &InternalPackageSpec, eco: Ecosystem) -> bool {
    let Some(declared) = &spec.ecosystem else {
        return true;
    };
    let declared = declared.trim();
    if declared.is_empty() {
        return true;
    }
    declared.eq_ignore_ascii_case(&eco.to_string())
}

/// Scopes whose shape strongly signals "private". Conservative fallback;
/// `package_policy.internal_package_names` is the real surface.
const RESERVED_INTERNAL_SCOPES: &[&str] = &[
    "@internal",
    "@private",
    "@corp",
    "@company",
    "@inhouse",
    "@enterprise",
    "@local",
];

fn is_reserved_internal_scope(scope: &str) -> bool {
    let lower = scope.to_lowercase();
    RESERVED_INTERNAL_SCOPES.contains(&lower.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with(internal: &[&str]) -> Policy {
        let mut policy = Policy::default();
        policy.package_policy.internal_package_names = internal
            .iter()
            .map(|s| InternalPackageSpec::from_pattern(*s))
            .collect();
        policy
    }

    fn policy_with_scoped(specs: &[(Option<&str>, &str)]) -> Policy {
        let mut policy = Policy::default();
        policy.package_policy.internal_package_names = specs
            .iter()
            .map(|(eco, name)| InternalPackageSpec {
                ecosystem: eco.map(|s| s.to_string()),
                name: (*name).to_string(),
            })
            .collect();
        policy
    }

    #[test]
    fn no_internal_names_does_not_flag_normal_packages() {
        let p = Policy::default();
        let v = evaluate(Ecosystem::Npm, "react", &p);
        assert!(!v.risk);
        assert!(v.reason.is_empty());
    }

    #[test]
    fn exact_internal_name_flags() {
        let p = policy_with(&["@my-co/util"]);
        let v = evaluate(Ecosystem::Npm, "@my-co/util", &p);
        assert!(v.risk);
        assert!(v.reason.contains("@my-co/util"));
    }

    #[test]
    fn wildcard_internal_pattern_flags_subnames() {
        let p = policy_with(&["@my-co/*"]);
        let v = evaluate(Ecosystem::Npm, "@my-co/util", &p);
        assert!(v.risk);
        let v2 = evaluate(Ecosystem::Npm, "@my-co/another", &p);
        assert!(v2.risk);
        let v3 = evaluate(Ecosystem::Npm, "@other/util", &p);
        assert!(!v3.risk);
    }

    #[test]
    fn reserved_internal_scope_flags_without_policy() {
        let p = Policy::default();
        let v = evaluate(Ecosystem::Npm, "@internal/helper", &p);
        assert!(v.risk);
        let v2 = evaluate(Ecosystem::Npm, "@private/util", &p);
        assert!(v2.risk);
    }

    #[test]
    fn non_reserved_scope_does_not_flag_without_policy() {
        let p = Policy::default();
        let v = evaluate(Ecosystem::Npm, "@org/lib", &p);
        assert!(!v.risk);
    }

    #[test]
    fn non_npm_ecosystem_does_not_use_scope_heuristic() {
        let p = Policy::default();
        let v = evaluate(Ecosystem::PyPI, "@internal/helper", &p);
        assert!(!v.risk, "PyPI does not use npm scopes");
    }

    #[test]
    fn empty_name_returns_no_risk() {
        let p = Policy::default();
        let v = evaluate(Ecosystem::Npm, "   ", &p);
        assert!(!v.risk);
    }

    #[test]
    fn scoped_spec_matches_only_declared_ecosystem() {
        let p = policy_with_scoped(&[(Some("npm"), "internal-tool")]);
        let v_npm = evaluate(Ecosystem::Npm, "internal-tool", &p);
        assert!(v_npm.risk);
        let v_pypi = evaluate(Ecosystem::PyPI, "internal-tool", &p);
        assert!(
            !v_pypi.risk,
            "spec scoped to npm must not match a pypi resolution"
        );
    }

    #[test]
    fn unscoped_spec_matches_all_ecosystems() {
        let p = policy_with_scoped(&[(None, "internal-tool")]);
        assert!(evaluate(Ecosystem::Npm, "internal-tool", &p).risk);
        assert!(evaluate(Ecosystem::PyPI, "internal-tool", &p).risk);
    }

    #[test]
    fn pattern_matcher_handles_trailing_star() {
        assert!(matches_pattern("@foo/*", "@foo/bar"));
        assert!(!matches_pattern("@foo/*", "@bar/baz"));
        assert!(matches_pattern("exact", "exact"));
        assert!(!matches_pattern("exact", "exact-different"));
    }
}
