//! M6 ch6 — registry-claimed repository URL verification (`--online` only).
//!
//! For a package whose registry response carries a `repository_url`, fetch it
//! and verify: (1) parses as a known git host (GitHub/GitLab/Bitbucket),
//! (2) host reachable, (3) hosted manifest names this package. Returns a
//! [`RepoMismatchVerdict`]:
//!  * `Match` — all three checks passed.
//!  * `Mismatch` — host reachable but manifest names a different package, or
//!    the URL parses as non-git.
//!  * `Unverifiable` — no URL, dead host, or transport failure. Emits no
//!    finding by design.

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
/// On any error the verdict defaults to `Unverifiable` with the reason
/// recorded — the rule never fires unless the verdict is positively `Mismatch`.
pub fn verify(repository_url: &str, eco: Ecosystem, name: &str) -> RepoMismatchVerdict {
    let trimmed = sanitize_repo_url(repository_url);
    let host = match parse_known_git_host(&trimmed) {
        Some(h) => h,
        None => {
            return RepoMismatchVerdict {
                state: RepoMismatchState::Unverifiable,
                reason: "the URL does not parse as a known git host (GitHub/GitLab/Bitbucket)"
                    .to_string(),
            };
        }
    };

    let raw_url = match host.raw_manifest_url(eco) {
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

    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
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
    if manifest_names_package(&body, name, eco) {
        RepoMismatchVerdict {
            state: RepoMismatchState::Match,
            reason: format!(
                "the hosted manifest at {raw_url} names this package; provenance verified"
            ),
        }
    } else {
        RepoMismatchVerdict {
            state: RepoMismatchState::Mismatch,
            reason: format!("the hosted manifest at {raw_url} does not mention package '{name}'"),
        }
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
    owner: String,
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

    fn raw_manifest_url(&self, eco: Ecosystem) -> Option<String> {
        let manifest = manifest_filename(eco)?;
        // Single candidate to keep network usage minimal; a 404 is treated as
        // `Unverifiable`, not `Mismatch`.
        match self.kind {
            HostKind::GitHub => Some(format!(
                "https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{manifest}",
                owner = self.owner,
                repo = self.repo,
            )),
            HostKind::GitLab => Some(format!(
                "https://gitlab.com/{owner}/{repo}/-/raw/HEAD/{manifest}",
                owner = self.owner,
                repo = self.repo,
            )),
            HostKind::Bitbucket => Some(format!(
                "https://bitbucket.org/{owner}/{repo}/raw/HEAD/{manifest}",
                owner = self.owner,
                repo = self.repo,
            )),
        }
    }
}

fn manifest_filename(eco: Ecosystem) -> Option<&'static str> {
    match eco {
        Ecosystem::Npm => Some("package.json"),
        Ecosystem::Crates => Some("Cargo.toml"),
        Ecosystem::PyPI => Some("pyproject.toml"),
        Ecosystem::RubyGems => Some("Gemfile"),
        // Other ecosystems have no single conventional repo-root manifest; skip rather than guess.
        _ => None,
    }
}

/// `true` when the manifest text references `name` in a way that's specific
/// to the ecosystem (e.g. `"name": "foo"` for npm).
fn manifest_names_package(manifest: &str, name: &str, eco: Ecosystem) -> bool {
    match eco {
        Ecosystem::Npm => {
            let needle = format!("\"name\": \"{name}\"");
            let needle_no_space = format!("\"name\":\"{name}\"");
            manifest.contains(&needle) || manifest.contains(&needle_no_space)
        }
        Ecosystem::Crates => {
            let needle = format!("name = \"{name}\"");
            manifest.contains(&needle)
        }
        Ecosystem::PyPI => {
            let needle = format!("name = \"{name}\"");
            manifest.contains(&needle)
        }
        Ecosystem::RubyGems => {
            // Gemfile: heuristic substring check.
            manifest.contains(name)
        }
        _ => false,
    }
}

/// Parse `(owner, repo, kind)` from a sanitized URL. Returns `None` when the
/// URL is not a github/gitlab/bitbucket project URL.
fn parse_known_git_host(url: &str) -> Option<KnownGitHost> {
    let (kind, after_host) = if let Some(rest) = url.strip_prefix("https://github.com/") {
        (HostKind::GitHub, rest)
    } else if let Some(rest) = url.strip_prefix("http://github.com/") {
        (HostKind::GitHub, rest)
    } else if let Some(rest) = url.strip_prefix("https://gitlab.com/") {
        (HostKind::GitLab, rest)
    } else if let Some(rest) = url.strip_prefix("http://gitlab.com/") {
        (HostKind::GitLab, rest)
    } else if let Some(rest) = url.strip_prefix("https://bitbucket.org/") {
        (HostKind::Bitbucket, rest)
    } else if let Some(rest) = url.strip_prefix("http://bitbucket.org/") {
        (HostKind::Bitbucket, rest)
    } else {
        return None;
    };
    let mut parts = after_host.split('/');
    let owner = parts.next().filter(|p| !p.is_empty())?.to_string();
    let repo = parts.next().filter(|p| !p.is_empty())?.to_string();
    Some(KnownGitHost { owner, repo, kind })
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
        assert_eq!(h.owner, "owner");
        assert_eq!(h.repo, "repo");
        assert!(matches!(h.kind, HostKind::GitHub));
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
    fn manifest_names_package_npm_matches_quoted_name() {
        let text = r#"{ "name": "react", "version": "1.0.0" }"#;
        assert!(manifest_names_package(text, "react", Ecosystem::Npm));
        assert!(!manifest_names_package(text, "vue", Ecosystem::Npm));
    }

    #[test]
    fn manifest_names_package_cargo_matches_unquoted_name() {
        let text = "[package]\nname = \"serde\"\nversion = \"1.0.0\"\n";
        assert!(manifest_names_package(text, "serde", Ecosystem::Crates));
        assert!(!manifest_names_package(text, "tokio", Ecosystem::Crates));
    }

    #[test]
    fn verify_returns_unverifiable_for_non_known_host() {
        // No network request — the host parse fails first.
        let v = verify("https://example.com/owner/repo", Ecosystem::Npm, "p");
        assert!(matches!(v.state, RepoMismatchState::Unverifiable));
        assert!(v.reason.contains("does not parse"));
    }

    #[test]
    fn verify_returns_unverifiable_for_unsupported_ecosystem() {
        // No manifest filename for Docker — Unverifiable, not a panic.
        let v = verify(
            "https://github.com/owner/repo",
            Ecosystem::Docker,
            "owner/repo",
        );
        assert!(matches!(v.state, RepoMismatchState::Unverifiable));
    }
}
