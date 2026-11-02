//! M6 ch6 — registry-claimed repository URL verification (`--online` only).
//!
//! For a package whose registry response carries a `repository_url`, fetch it
//! and verify: (1) parses as a known git host (GitHub/GitLab/Bitbucket),
//! (2) host reachable, (3) hosted manifest names this package. Returns a
//! [`RepoMismatchVerdict`]:
//!  * `Match` — all three checks passed.
//!  * `Mismatch` — the claimed URL is not a recognized git project URL, or the
//!    hosted manifest names a different package.
//!  * `Unverifiable` — no URL, dead host, transport failure, or a manifest
//!    whose shape cannot be parsed conclusively. Emits no finding by design.

use std::time::Duration;

use crate::package_risk::{RepoMismatchState, RepoMismatchVerdict};
use crate::threatdb::Ecosystem;

/// Default cap on the number of repo-mismatch checks per scan. M6 ch6 const;
/// ch7's `package_policy.repo_mismatch_check_max_packages` replaces this.
pub const DEFAULT_REPO_MISMATCH_CHECK_MAX: u32 = 50;

/// HTTP timeout per request. Short — `--online` is interactive; a verdict of
/// `Unverifiable` on a slow host is better than a hang.
const REQUEST_TIMEOUT_SECS: u64 = 10;
/// Hard cap on the size of the fetched manifest body. A package.json should
/// never approach this.
const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;

/// Verify a registry-claimed repository URL against `(eco, name)`.
///
/// A *present* claimed repository that is unsupported or not a recognized git
/// project is a `Mismatch` (fail closed on provenance); `Unverifiable` is
/// reserved for absence and genuine transport/shape failures, so the rule
/// never fires unless the verdict is positively `Mismatch`.
pub fn verify(repository_url: &str, eco: Ecosystem, name: &str) -> RepoMismatchVerdict {
    let trimmed = sanitize_repo_url(repository_url);
    let host = match parse_known_git_host(&trimmed) {
        Some(h) => h,
        None => {
            return RepoMismatchVerdict {
                state: RepoMismatchState::Mismatch,
                reason: "the claimed repository URL is not a recognized git project URL (GitHub/GitLab/Bitbucket); provenance cannot be trusted"
                    .to_string(),
            };
        }
    };

    let raw_url = match host.raw_manifest_url(eco, name) {
        Some(u) => u,
        None => {
            return RepoMismatchVerdict {
                state: RepoMismatchState::Unverifiable,
                reason: format!(
                    "no raw-manifest URL is wired for {} on {} yet",
                    eco,
                    host.host_label()
                ),
            };
        }
    };

    if let Err(reason) = crate::url_validate::validate_server_url(&raw_url) {
        return RepoMismatchVerdict {
            state: RepoMismatchState::Unverifiable,
            reason: format!("refusing unsafe repo manifest URL: {reason}"),
        };
    }

    let client = match reqwest::blocking::Client::builder()
        .no_proxy()
        .dns_resolver(crate::ssrf_guard::ssrf_guard_resolver())
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .redirect(crate::ssrf_guard::server_redirect_policy())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return RepoMismatchVerdict {
                state: RepoMismatchState::Unverifiable,
                reason: format!("could not build HTTP client: {e}"),
            };
        }
    };

    let resp = match client.get(&raw_url).send() {
        Ok(r) => r,
        Err(e) => {
            return RepoMismatchVerdict {
                state: RepoMismatchState::Unverifiable,
                reason: format!("could not reach the repo URL ({e})"),
            };
        }
    };
    if !resp.status().is_success() {
        return RepoMismatchVerdict {
            state: RepoMismatchState::Unverifiable,
            reason: format!(
                "the repo manifest URL returned HTTP {}",
                resp.status().as_u16()
            ),
        };
    }
    // An HTML response with a success status is a login wall, error page, or
    // redirect shell — never a manifest. Do not let its text influence the
    // provenance decision either way.
    if let Some(content_type) = resp.headers().get(reqwest::header::CONTENT_TYPE) {
        if content_type
            .to_str()
            .map(|v| v.to_ascii_lowercase().contains("html"))
            .unwrap_or(false)
        {
            return RepoMismatchVerdict {
                state: RepoMismatchState::Unverifiable,
                reason: "the repo manifest URL returned HTML, not a manifest".to_string(),
            };
        }
    }

    use std::io::Read as _;
    let mut buf = Vec::new();
    if resp
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut buf)
        .is_err()
        || buf.len() as u64 > MAX_MANIFEST_BYTES
    {
        return RepoMismatchVerdict {
            state: RepoMismatchState::Unverifiable,
            reason: "the repo manifest exceeded tirith's size cap".to_string(),
        };
    }

    let body = String::from_utf8_lossy(&buf);
    match manifest_names_package(&body, name, eco) {
        ManifestMatch::Names => RepoMismatchVerdict {
            state: RepoMismatchState::Match,
            reason: format!(
                "the hosted manifest at {raw_url} names this package; provenance verified"
            ),
        },
        ManifestMatch::DoesNotName => RepoMismatchVerdict {
            state: RepoMismatchState::Mismatch,
            reason: format!("the hosted manifest at {raw_url} does not name package '{name}'"),
        },
        ManifestMatch::Inconclusive => RepoMismatchVerdict {
            state: RepoMismatchState::Unverifiable,
            reason: format!("the hosted manifest at {raw_url} could not be parsed conclusively"),
        },
    }
}

/// Strip `git+` prefixes / `.git` suffixes / `#fragment` tails the registry
/// often embeds in repository fields.
fn sanitize_repo_url(url: &str) -> String {
    let mut s = url.trim().to_string();
    for prefix in ["git+", "ssh+"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.to_string();
        }
    }
    // Normalize the `git://` transport form to HTTPS; host/path identity is
    // unchanged and HTTPS is the only scheme the verifier will fetch.
    if let Some(rest) = s.strip_prefix("git://") {
        s = format!("https://{rest}");
    }
    // Normalize the `ssh://` transport the same way. npm's registry commonly
    // normalizes `repository.url` to `git+ssh://git@github.com/owner/repo.git`,
    // which the `git+` strip above reduces to this form; without the rewrite a
    // genuine GitHub repository reads as unverifiable-or-worse. Only the
    // canonical `git@` userinfo is stripped: any other userinfo survives so the
    // deliberate non-empty-username rejection in `parse_known_git_host` still
    // catches lookalike tricks.
    if let Some(rest) = s.strip_prefix("ssh://") {
        let rest = rest.strip_prefix("git@").unwrap_or(rest);
        s = format!("https://{rest}");
    }
    // Convert `git@host:owner/repo.git` to `https://host/owner/repo` so we can
    // attempt a known-host parse.
    if s.starts_with("git@") {
        if let Some(at) = s.find('@') {
            if let Some(colon) = s[at..].find(':') {
                let host = &s[at + 1..at + colon];
                let path = &s[at + colon + 1..];
                s = format!("https://{host}/{path}");
            }
        }
    }
    if let Some(idx) = s.find('#') {
        s.truncate(idx);
    }
    // Trim trailing `.git` (GitHub HTTPS URLs often have this).
    if let Some(rest) = s.strip_suffix(".git") {
        s = rest.to_string();
    }
    s
}

/// A known git host the verifier can fetch a raw manifest from.
struct KnownGitHost {
    namespace: Vec<String>,
    repo: String,
    kind: HostKind,
}

#[derive(Debug, Clone, Copy)]
enum HostKind {
    GitHub,
    GitLab,
    Bitbucket,
}

impl KnownGitHost {
    fn host_label(&self) -> &'static str {
        match self.kind {
            HostKind::GitHub => "github.com",
            HostKind::GitLab => "gitlab.com",
            HostKind::Bitbucket => "bitbucket.org",
        }
    }

    fn raw_manifest_url(&self, eco: Ecosystem, name: &str) -> Option<String> {
        let manifest = manifest_filename(eco, name)?;
        let base = match self.kind {
            HostKind::GitHub => "https://raw.githubusercontent.com/",
            HostKind::GitLab => "https://gitlab.com/",
            HostKind::Bitbucket => "https://bitbucket.org/",
        };
        let mut url = url::Url::parse(base).ok()?;
        {
            // `push` percent-encodes each already-validated component, so query
            // delimiters and path separators can never change request identity.
            let mut path = url.path_segments_mut().ok()?;
            path.clear();
            for segment in &self.namespace {
                path.push(segment);
            }
            path.push(&self.repo);
            match self.kind {
                HostKind::GitHub => {
                    path.push("HEAD");
                }
                HostKind::GitLab => {
                    path.push("-");
                    path.push("raw");
                    path.push("HEAD");
                }
                HostKind::Bitbucket => {
                    path.push("raw");
                    path.push("HEAD");
                }
            }
            path.push(&manifest);
        }
        Some(url.into())
    }
}

fn manifest_filename(eco: Ecosystem, name: &str) -> Option<String> {
    match eco {
        Ecosystem::Npm => Some("package.json".to_string()),
        Ecosystem::Crates => Some("Cargo.toml".to_string()),
        Ecosystem::PyPI => Some("pyproject.toml".to_string()),
        // A Gemfile names dependencies, not the gem itself; the gemspec is the
        // only conventional repo-root file carrying the gem's own identity.
        Ecosystem::RubyGems => Some(format!("{name}.gemspec")),
        // Other ecosystems have no single conventional repo-root manifest; skip rather than guess.
        _ => None,
    }
}

/// Outcome of checking the hosted manifest for the package's own identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManifestMatch {
    /// The manifest's canonical package identity equals the package name.
    Names,
    /// The manifest parsed conclusively and names a different package.
    DoesNotName,
    /// The manifest shape could not be parsed conclusively.
    Inconclusive,
}

/// Check the manifest's canonical top-level package identity for `name`,
/// parsing each ecosystem's real format instead of substring matching (which
/// could be spoofed via comments, unrelated tables, or nested members).
fn manifest_names_package(manifest: &str, name: &str, eco: Ecosystem) -> ManifestMatch {
    match eco {
        Ecosystem::Npm => {
            let parsed: serde_json::Value = match serde_json::from_str(manifest) {
                Ok(v) => v,
                Err(_) => return ManifestMatch::Inconclusive,
            };
            match parsed.get("name").and_then(|v| v.as_str()) {
                Some(found) if found == name => ManifestMatch::Names,
                // A manifest that names a DIFFERENT package is conclusive; one
                // with no name at all is a shape we cannot conclude from (a
                // repo-root manifest for a workspace layout), mirroring the
                // gemspec arm below.
                Some(_) => ManifestMatch::DoesNotName,
                None => ManifestMatch::Inconclusive,
            }
        }
        Ecosystem::Crates => {
            let parsed: toml::Value = match toml::from_str(manifest) {
                Ok(v) => v,
                Err(_) => return ManifestMatch::Inconclusive,
            };
            match parsed
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
            {
                Some(found) if found == name => ManifestMatch::Names,
                // A root Cargo.toml without a [package] table is the standard
                // virtual-workspace layout (the crate publishes from a member
                // directory), not evidence against the claim. Only a manifest
                // that names a DIFFERENT package is conclusive.
                Some(_) => ManifestMatch::DoesNotName,
                None => ManifestMatch::Inconclusive,
            }
        }
        Ecosystem::PyPI => {
            let parsed: toml::Value = match toml::from_str(manifest) {
                Ok(v) => v,
                Err(_) => return ManifestMatch::Inconclusive,
            };
            let found = parsed
                .get("project")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .or_else(|| {
                    parsed
                        .get("tool")
                        .and_then(|t| t.get("poetry"))
                        .and_then(|p| p.get("name"))
                        .and_then(|n| n.as_str())
                });
            match found {
                Some(found) if pep503_normalize(found) == pep503_normalize(name) => {
                    ManifestMatch::Names
                }
                // No project/poetry name: a pyproject.toml that only configures
                // tooling cannot be concluded from, mirroring the gemspec arm.
                Some(_) => ManifestMatch::DoesNotName,
                None => ManifestMatch::Inconclusive,
            }
        }
        Ecosystem::RubyGems => {
            // Gemspec: require an explicit `spec.name = "..."` identity
            // assignment; a gemspec without one cannot be concluded either way.
            let assign = regex::Regex::new(r#"(?m)^\s*[A-Za-z_]\w*\.name\s*=\s*['"]([^'"]+)['"]"#)
                .expect("gemspec name regex compiles");
            let mut found_any = false;
            for caps in assign.captures_iter(manifest) {
                found_any = true;
                if &caps[1] == name {
                    return ManifestMatch::Names;
                }
            }
            if found_any {
                ManifestMatch::DoesNotName
            } else {
                ManifestMatch::Inconclusive
            }
        }
        _ => ManifestMatch::Inconclusive,
    }
}

/// PEP 503 normalization: lowercase and collapse runs of `-`, `_`, `.` to `-`.
fn pep503_normalize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_dash = false;
    for ch in name.chars().flat_map(char::to_lowercase) {
        let sep = matches!(ch, '-' | '_' | '.');
        if sep {
            if !last_dash {
                out.push('-');
            }
            last_dash = true;
        } else {
            out.push(ch);
            last_dash = false;
        }
    }
    out
}

/// Parse `(owner, repo, kind)` from a sanitized URL. Returns `None` when the
/// URL is not a github/gitlab/bitbucket project URL.
fn parse_known_git_host(url: &str) -> Option<KnownGitHost> {
    let parsed = url::Url::parse(url).ok()?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    let kind = match parsed
        .host_str()?
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .as_str()
    {
        "github.com" => HostKind::GitHub,
        "gitlab.com" => HostKind::GitLab,
        "bitbucket.org" => HostKind::Bitbucket,
        _ => return None,
    };

    let mut encoded: Vec<&str> = parsed.path_segments()?.collect();
    if encoded.last().copied() == Some("") {
        encoded.pop();
    }
    // GitHub/Bitbucket project URLs commonly carry trailing navigation
    // segments (`/tree/main/...`, `/src/...`). The first two segments already
    // pin the project identity unambiguously, so drop the rest instead of
    // rejecting a usable claimed repository. GitLab stays strict: extra
    // segments are ambiguous with subgroup routes (`/-/...`).
    if !matches!(kind, HostKind::GitLab) && encoded.len() > 2 {
        encoded.truncate(2);
    }
    let mut components = Vec::with_capacity(encoded.len());
    for segment in encoded {
        if segment.is_empty() {
            // A trailing empty component was removed above; any other empty
            // segment changes path identity and is rejected.
            return None;
        }
        let decoded = percent_encoding::percent_decode_str(segment)
            .decode_utf8()
            .ok()?;
        if !valid_repository_component(&decoded) {
            return None;
        }
        components.push(decoded.into_owned());
    }
    let repo = components.pop()?;
    let repo = repo.strip_suffix(".git").unwrap_or(&repo).to_string();
    if !valid_repository_component(&repo) || components.is_empty() {
        return None;
    }
    // GitLab reserves `-` as the delimiter before project routes such as
    // `/-/raw/`. Check after normalizing the repository's optional `.git`
    // suffix so `-.git` cannot become the reserved route segment later.
    if matches!(kind, HostKind::GitLab)
        && (repo == "-" || components.iter().any(|part| part == "-"))
    {
        return None;
    }
    if !matches!(kind, HostKind::GitLab) && components.len() != 1 {
        return None;
    }
    Some(KnownGitHost {
        namespace: components,
        repo,
        kind,
    })
}

fn valid_repository_component(component: &str) -> bool {
    !component.is_empty()
        && component.len() <= 255
        && !matches!(component, "." | "..")
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_repo_url_handles_git_plus_prefix() {
        assert_eq!(
            sanitize_repo_url("git+https://github.com/o/r.git"),
            "https://github.com/o/r"
        );
    }

    #[test]
    fn sanitize_repo_url_normalizes_ssh_scheme_with_git_userinfo() {
        // npm's registry normalization for a GitHub repository field.
        assert_eq!(
            sanitize_repo_url("git+ssh://git@github.com/org/repo.git"),
            "https://github.com/org/repo"
        );
        assert_eq!(
            sanitize_repo_url("ssh://git@gitlab.com/org/repo.git"),
            "https://gitlab.com/org/repo"
        );
        // Non-canonical userinfo survives, so the known-host parse still
        // rejects lookalike tricks by its non-empty-username rule.
        assert_eq!(
            sanitize_repo_url("ssh://evil@github.com/org/repo"),
            "https://evil@github.com/org/repo"
        );
    }

    #[test]
    fn sanitize_repo_url_normalizes_git_scheme() {
        assert_eq!(
            sanitize_repo_url("git://gitlab.com/o/r"),
            "https://gitlab.com/o/r"
        );
        assert_eq!(
            sanitize_repo_url("git+git://github.com/o/r.git"),
            "https://github.com/o/r"
        );
    }

    #[test]
    fn sanitize_repo_url_handles_scp_form() {
        assert_eq!(
            sanitize_repo_url("git@github.com:owner/repo.git"),
            "https://github.com/owner/repo"
        );
    }

    #[test]
    fn sanitize_repo_url_strips_fragment() {
        assert_eq!(
            sanitize_repo_url("https://github.com/o/r#readme"),
            "https://github.com/o/r"
        );
    }

    #[test]
    fn parse_known_git_host_github() {
        let h =
            parse_known_git_host("https://github.com/owner/repo").expect("github URL must parse");
        assert_eq!(h.namespace, ["owner"]);
        assert_eq!(h.repo, "repo");
        assert!(matches!(h.kind, HostKind::GitHub));
        assert_eq!(
            h.raw_manifest_url(Ecosystem::Npm, "repo").as_deref(),
            Some("https://raw.githubusercontent.com/owner/repo/HEAD/package.json")
        );
    }

    #[test]
    fn parse_known_git_host_github_truncates_navigation_segments() {
        let h = parse_known_git_host("https://github.com/owner/repo/tree/main/pkg")
            .expect("github subpath URL must resolve to the project");
        assert_eq!(h.namespace, ["owner"]);
        assert_eq!(h.repo, "repo");
    }

    #[test]
    fn parse_known_git_host_models_gitlab_subgroups() {
        let h = parse_known_git_host("https://gitlab.com/group/subgroup/repo.git")
            .expect("GitLab subgroup URL must parse");
        assert_eq!(h.namespace, ["group", "subgroup"]);
        assert_eq!(h.repo, "repo");
        assert_eq!(
            h.raw_manifest_url(Ecosystem::PyPI, "repo").as_deref(),
            Some("https://gitlab.com/group/subgroup/repo/-/raw/HEAD/pyproject.toml")
        );
    }

    #[test]
    fn rubygems_manifest_is_the_gemspec() {
        let h = parse_known_git_host("https://github.com/owner/repo").unwrap();
        assert_eq!(
            h.raw_manifest_url(Ecosystem::RubyGems, "rack").as_deref(),
            Some("https://raw.githubusercontent.com/owner/repo/HEAD/rack.gemspec")
        );
    }

    #[test]
    fn parse_known_git_host_rejects_unknown() {
        assert!(parse_known_git_host("https://example.com/owner/repo").is_none());
    }

    #[test]
    fn parse_known_git_host_rejects_empty_segments() {
        assert!(parse_known_git_host("https://github.com//repo").is_none());
        assert!(parse_known_git_host("https://github.com/owner/").is_none());
    }

    #[test]
    fn parse_known_git_host_rejects_ambiguous_or_unsafe_identity() {
        for url in [
            "http://github.com/owner/repo",
            "https://user@github.com/owner/repo",
            "https://github.com:444/owner/repo",
            "https://github.com/owner/repo?raw=/other",
            "https://github.com/owner%2Frewrite/repo",
            "https://github.com/owner/%2E%2E/repo",
            "https://github.com.evil.invalid/owner/repo",
            "https://gitlab.com/group/project/-/raw/HEAD/subdir",
            "https://gitlab.com/group/-.git",
            "https://gitlab.com/group/-%2Egit",
        ] {
            assert!(
                parse_known_git_host(url).is_none(),
                "unsafe repository identity must be rejected: {url}"
            );
        }
    }

    #[test]
    fn manifest_names_package_npm_matches_quoted_name() {
        let text = r#"{ "name": "react", "version": "1.0.0" }"#;
        assert_eq!(
            manifest_names_package(text, "react", Ecosystem::Npm),
            ManifestMatch::Names
        );
        assert_eq!(
            manifest_names_package(text, "vue", Ecosystem::Npm),
            ManifestMatch::DoesNotName
        );
    }

    #[test]
    fn manifest_names_package_npm_ignores_nested_and_broken_json() {
        // A nested "name" member must not satisfy the identity check. With no
        // TOP-LEVEL name at all the manifest cannot be concluded from either
        // way (workspace-root package.json files commonly omit it).
        let nested = r#"{ "dependencies": { "evil": { "name": "react" } } }"#;
        assert_eq!(
            manifest_names_package(nested, "react", Ecosystem::Npm),
            ManifestMatch::Inconclusive
        );
        assert_eq!(
            manifest_names_package("not json", "react", Ecosystem::Npm),
            ManifestMatch::Inconclusive
        );
    }

    #[test]
    fn manifest_names_package_cargo_matches_unquoted_name() {
        let text = "[package]\nname = \"serde\"\nversion = \"1.0.0\"\n";
        assert_eq!(
            manifest_names_package(text, "serde", Ecosystem::Crates),
            ManifestMatch::Names
        );
        assert_eq!(
            manifest_names_package(text, "tokio", Ecosystem::Crates),
            ManifestMatch::DoesNotName
        );
    }

    #[test]
    fn manifest_names_package_cargo_ignores_comments_and_other_tables() {
        // Neither a commented-out name nor a name in an unrelated table may
        // count as NAMING the package (anti-spoofing). With no [package] table
        // at all, the shape is the virtual-workspace layout and cannot be
        // concluded from either way — Inconclusive, never Names.
        let commented = "# name = \"serde\"\n[dependencies]\nfoo = \"1\"\n";
        assert_eq!(
            manifest_names_package(commented, "serde", Ecosystem::Crates),
            ManifestMatch::Inconclusive
        );
        let other_table = "[workspace]\nmembers = []\n[profile.dev]\nname = \"serde\"\n";
        assert_eq!(
            manifest_names_package(other_table, "serde", Ecosystem::Crates),
            ManifestMatch::Inconclusive
        );
        let wrong_name = "[package]\nname = \"serde-clone\"\n";
        assert_eq!(
            manifest_names_package(wrong_name, "serde", Ecosystem::Crates),
            ManifestMatch::DoesNotName
        );
    }

    #[test]
    fn manifest_names_package_pypi_normalizes_pep503() {
        let text = "[project]\nname = \"My_Package\"\n";
        assert_eq!(
            manifest_names_package(text, "my-package", Ecosystem::PyPI),
            ManifestMatch::Names
        );
        let poetry = "[tool.poetry]\nname = \"my.package\"\n";
        assert_eq!(
            manifest_names_package(poetry, "my-package", Ecosystem::PyPI),
            ManifestMatch::Names
        );
    }

    #[test]
    fn manifest_names_package_rubygems_requires_name_assignment() {
        let spec = "Gem::Specification.new do |s|\n  s.name = \"rack\"\nend\n";
        assert_eq!(
            manifest_names_package(spec, "rack", Ecosystem::RubyGems),
            ManifestMatch::Names
        );
        assert_eq!(
            manifest_names_package(spec, "rails", Ecosystem::RubyGems),
            ManifestMatch::DoesNotName
        );
        // Substring mention without an identity assignment is inconclusive.
        assert_eq!(
            manifest_names_package("# rack is great\n", "rack", Ecosystem::RubyGems),
            ManifestMatch::Inconclusive
        );
    }

    #[test]
    fn verify_returns_mismatch_for_non_known_host() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // No network request — the host parse fails first, and a present but
        // unrecognized claimed repository is a Mismatch, not Unverifiable.
        let v = verify("https://example.com/owner/repo", Ecosystem::Npm, "p");
        assert!(matches!(v.state, RepoMismatchState::Mismatch));
        assert!(v.reason.contains("not a recognized git project"));
    }

    #[test]
    fn verify_returns_unverifiable_for_unsupported_ecosystem() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // No manifest filename for Docker — Unverifiable, not a panic.
        let v = verify(
            "https://github.com/owner/repo",
            Ecosystem::Docker,
            "owner/repo",
        );
        assert!(matches!(v.state, RepoMismatchState::Unverifiable));
    }
}
