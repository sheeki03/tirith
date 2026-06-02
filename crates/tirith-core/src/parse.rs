use serde::{Deserialize, Serialize};
use url::Url;

/// Represents different forms of URL-like patterns found in commands.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UrlLike {
    /// Standard URL parsed by the `url` crate, with raw host preserved.
    Standard {
        #[serde(serialize_with = "serialize_url", deserialize_with = "deserialize_url")]
        parsed: Url,
        raw_host: String,
    },
    /// SCP-style git reference (e.g., `git@github.com:user/repo.git`).
    Scp {
        user: Option<String>,
        host: String,
        path: String,
    },
    /// Docker image reference following distribution spec.
    DockerRef {
        registry: Option<String>,
        image: String,
        tag: Option<String>,
        digest: Option<String>,
    },
    /// URL that failed standard parsing but has extractable components.
    Unparsed {
        raw: String,
        raw_host: Option<String>,
        raw_path: Option<String>,
    },
    /// Schemeless host+path found in sink contexts (curl, wget, etc.).
    SchemelessHostPath { host: String, path: String },
}

fn serialize_url<S>(url: &Url, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(url.as_str())
}

fn deserialize_url<'de, D>(deserializer: D) -> Result<Url, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Url::parse(&s).map_err(serde::de::Error::custom)
}

impl UrlLike {
    /// Returns the canonical host, if available.
    pub fn host(&self) -> Option<&str> {
        match self {
            UrlLike::Standard { parsed, .. } => parsed.host_str(),
            UrlLike::Scp { host, .. } => Some(host.as_str()),
            UrlLike::DockerRef { registry, .. } => {
                if let Some(reg) = registry {
                    Some(reg.as_str())
                } else {
                    Some("docker.io") // distribution-spec default
                }
            }
            UrlLike::Unparsed { raw_host, .. } => raw_host.as_deref(),
            UrlLike::SchemelessHostPath { host, .. } => Some(host.as_str()),
        }
    }

    /// Returns the raw (pre-IDNA) host, if available.
    pub fn raw_host(&self) -> Option<&str> {
        match self {
            UrlLike::Standard { raw_host, .. } => Some(raw_host.as_str()),
            UrlLike::Scp { host, .. } => Some(host.as_str()),
            UrlLike::DockerRef { registry, .. } => registry.as_deref().or(Some("docker.io")),
            UrlLike::Unparsed { raw_host, .. } => raw_host.as_deref(),
            UrlLike::SchemelessHostPath { host, .. } => Some(host.as_str()),
        }
    }

    /// Returns the raw string representation.
    pub fn raw_str(&self) -> String {
        match self {
            UrlLike::Standard { parsed, .. } => parsed.to_string(),
            UrlLike::Scp { user, host, path } => {
                if let Some(u) = user {
                    format!("{u}@{host}:{path}")
                } else {
                    format!("{host}:{path}")
                }
            }
            UrlLike::DockerRef {
                registry,
                image,
                tag,
                digest,
            } => {
                let mut s = String::new();
                if let Some(reg) = registry {
                    s.push_str(reg);
                    s.push('/');
                }
                s.push_str(image);
                if let Some(t) = tag {
                    s.push(':');
                    s.push_str(t);
                }
                if let Some(d) = digest {
                    s.push('@');
                    s.push_str(d);
                }
                s
            }
            UrlLike::Unparsed { raw, .. } => raw.clone(),
            UrlLike::SchemelessHostPath { host, path } => {
                format!("{host}{path}")
            }
        }
    }

    /// Returns the scheme if available.
    pub fn scheme(&self) -> Option<&str> {
        match self {
            UrlLike::Standard { parsed, .. } => Some(parsed.scheme()),
            _ => None,
        }
    }

    /// Returns the path component if available.
    pub fn path(&self) -> Option<&str> {
        match self {
            UrlLike::Standard { parsed, .. } => Some(parsed.path()),
            UrlLike::Scp { path, .. } => Some(path.as_str()),
            UrlLike::Unparsed { raw_path, .. } => raw_path.as_deref(),
            UrlLike::SchemelessHostPath { path, .. } => Some(path.as_str()),
            UrlLike::DockerRef { .. } => None,
        }
    }

    /// Returns port if available.
    pub fn port(&self) -> Option<u16> {
        match self {
            UrlLike::Standard { parsed, .. } => parsed.port(),
            _ => None,
        }
    }

    /// Returns userinfo if available.
    pub fn userinfo(&self) -> Option<&str> {
        match self {
            UrlLike::Standard { parsed, .. } => {
                let user = parsed.username();
                if user.is_empty() {
                    None
                } else {
                    Some(user)
                }
            }
            UrlLike::Scp { user, .. } => user.as_deref(),
            _ => None,
        }
    }
}

/// Extract the raw host from a URL string BEFORE IDNA normalization (handles
/// IPv6, userinfo, port, percent-encoded separators). Needed because
/// `Url::parse` IDNA-normalizes the host, hiding the homograph/punycode signals
/// the hostname rules depend on.
pub fn extract_raw_host(url_str: &str) -> Option<String> {
    let after_scheme = if let Some(idx) = url_str.find("://") {
        &url_str[idx + 3..]
    } else {
        return None;
    };

    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];

    if authority.is_empty() {
        return Some(String::new());
    }

    let host_part = split_userinfo(authority);
    let host = extract_host_from_hostport(host_part);

    Some(host.to_string())
}

/// Split userinfo from authority on the LAST unencoded `@` (so `user%40name@host`
/// resolves to `host` — `%40` is userinfo, not a separator).
fn split_userinfo(authority: &str) -> &str {
    let bytes = authority.as_bytes();
    let mut last_at = None;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            i += 3;
            continue;
        }
        if bytes[i] == b'@' {
            last_at = Some(i);
        }
        i += 1;
    }
    match last_at {
        Some(idx) => &authority[idx + 1..],
        None => authority,
    }
}

/// Extract host from a host:port string, handling IPv6 brackets.
fn extract_host_from_hostport(hostport: &str) -> &str {
    if hostport.starts_with('[') {
        if let Some(bracket_end) = hostport.find(']') {
            return &hostport[..bracket_end + 1];
        }
        return hostport;
    }

    let bytes = hostport.as_bytes();
    let mut last_colon = None;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            i += 3;
            continue;
        }
        if bytes[i] == b':' {
            last_colon = Some(i);
        }
        i += 1;
    }

    match last_colon {
        Some(idx) => {
            // Colon is a port separator only when the suffix is all digits.
            let after = &hostport[idx + 1..];
            if after.chars().all(|c| c.is_ascii_digit()) && !after.is_empty() {
                &hostport[..idx]
            } else {
                hostport
            }
        }
        None => hostport,
    }
}

/// Parse a URL string into a UrlLike.
pub fn parse_url(raw: &str) -> UrlLike {
    // SCP refs (`git@host:path`) must be matched before generic `Url::parse`.
    if let Some(scp) = try_parse_scp(raw) {
        return scp;
    }

    if let Ok(parsed) = Url::parse(raw) {
        let raw_host = extract_raw_host(raw).unwrap_or_default();
        return UrlLike::Standard { parsed, raw_host };
    }

    let raw_host = extract_raw_host(raw);
    let raw_path = extract_raw_path(raw);
    UrlLike::Unparsed {
        raw: raw.to_string(),
        raw_host,
        raw_path,
    }
}

/// Try to parse as SCP-style reference: `[user@]host:path`.
fn try_parse_scp(raw: &str) -> Option<UrlLike> {
    if raw.contains("://") {
        return None;
    }

    let (user_host, path) = raw.split_once(':')?;
    if path.starts_with("//") {
        return None; // scheme-relative URL, not SCP
    }

    let (user, host) = if let Some((u, h)) = user_host.split_once('@') {
        (Some(u.to_string()), h)
    } else {
        (None, user_host)
    };

    // Require a dot or `localhost` so `foo:bar` shell syntax isn't an SCP ref.
    if !host.contains('.') && host != "localhost" {
        return None;
    }

    Some(UrlLike::Scp {
        user,
        host: host.to_string(),
        path: path.to_string(),
    })
}

/// Parse a Docker image reference following distribution spec.
pub fn parse_docker_ref(raw: &str) -> UrlLike {
    let mut remaining = raw;
    let mut digest = None;
    let mut tag = None;

    if let Some(at_idx) = remaining.rfind('@') {
        digest = Some(remaining[at_idx + 1..].to_string());
        remaining = &remaining[..at_idx];
    }

    if let Some(colon_idx) = remaining.rfind(':') {
        let potential_tag = &remaining[colon_idx + 1..];
        let before_colon = &remaining[..colon_idx];
        // A `/` in the suffix means this colon is a registry:port, not a tag.
        if !potential_tag.contains('/') {
            tag = Some(potential_tag.to_string());
            remaining = before_colon;
        }
    }

    let parts: Vec<&str> = remaining.split('/').collect();

    let (registry, image) = if parts.len() == 1 {
        // `nginx` → implicit `library/nginx`.
        (None, format!("library/{}", parts[0]))
    } else {
        let first = parts[0];
        // A host-like first segment (`.`/`:` or `localhost`) is a registry.
        let is_registry = first.contains('.') || first.contains(':') || first == "localhost";

        if is_registry {
            let image_parts = &parts[1..];
            (Some(first.to_string()), image_parts.join("/"))
        } else {
            (None, parts.join("/"))
        }
    };

    UrlLike::DockerRef {
        registry,
        image,
        tag,
        digest,
    }
}

/// Extract raw path from a URL string (fallback for unparseable URLs).
fn extract_raw_path(raw: &str) -> Option<String> {
    if let Some(idx) = raw.find("://") {
        let after = &raw[idx + 3..];
        if let Some(slash) = after.find('/') {
            return Some(after[slash..].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_standard_url() {
        let u = parse_url("https://example.com/path?q=1");
        assert!(matches!(u, UrlLike::Standard { .. }));
        assert_eq!(u.host(), Some("example.com"));
        assert_eq!(u.scheme(), Some("https"));
        assert_eq!(u.path(), Some("/path"));
    }

    #[test]
    fn test_raw_host_preserved() {
        let u = parse_url("https://example.com/path");
        if let UrlLike::Standard { raw_host, .. } = &u {
            assert_eq!(raw_host, "example.com");
        } else {
            panic!("expected Standard");
        }
    }

    #[test]
    fn test_raw_host_ipv6() {
        let raw = "http://[::1]:8080/path";
        let host = extract_raw_host(raw);
        assert_eq!(host, Some("[::1]".to_string()));
    }

    #[test]
    fn test_raw_host_userinfo() {
        let raw = "http://user@example.com/path";
        let host = extract_raw_host(raw);
        assert_eq!(host, Some("example.com".to_string()));
    }

    #[test]
    fn test_raw_host_encoded_at() {
        let raw = "http://user%40name@host.com/path";
        let host = extract_raw_host(raw);
        assert_eq!(host, Some("host.com".to_string()));
    }

    #[test]
    fn test_raw_host_encoded_colon() {
        let raw = "http://exam%3Aple.com/path";
        let host = extract_raw_host(raw);
        assert_eq!(host, Some("exam%3Aple.com".to_string()));
    }

    #[test]
    fn test_raw_host_empty() {
        let raw = "http:///path";
        let host = extract_raw_host(raw);
        assert_eq!(host, Some("".to_string()));
    }

    #[test]
    fn test_raw_host_trailing_dot() {
        let raw = "http://example.com./path";
        let host = extract_raw_host(raw);
        assert_eq!(host, Some("example.com.".to_string()));
    }

    #[test]
    fn test_raw_host_with_port() {
        let raw = "http://example.com:8080/path";
        let host = extract_raw_host(raw);
        assert_eq!(host, Some("example.com".to_string()));
    }

    #[test]
    fn test_parse_scp() {
        let u = parse_url("git@github.com:user/repo.git");
        assert!(matches!(u, UrlLike::Scp { .. }));
        assert_eq!(u.host(), Some("github.com"));
        assert_eq!(u.path(), Some("user/repo.git"));
    }

    #[test]
    fn test_docker_ref_single_component() {
        let u = parse_docker_ref("nginx");
        if let UrlLike::DockerRef {
            registry, image, ..
        } = &u
        {
            assert!(registry.is_none());
            assert_eq!(image, "library/nginx");
        } else {
            panic!("expected DockerRef");
        }
        assert_eq!(u.host(), Some("docker.io"));
    }

    #[test]
    fn test_docker_ref_user_image() {
        let u = parse_docker_ref("user/image");
        if let UrlLike::DockerRef {
            registry, image, ..
        } = &u
        {
            assert!(registry.is_none());
            assert_eq!(image, "user/image");
        }
    }

    #[test]
    fn test_docker_ref_with_registry() {
        let u = parse_docker_ref("myregistry.com/image");
        if let UrlLike::DockerRef {
            registry, image, ..
        } = &u
        {
            assert_eq!(registry.as_deref(), Some("myregistry.com"));
            assert_eq!(image, "image");
        }
    }

    #[test]
    fn test_docker_ref_localhost_port() {
        let u = parse_docker_ref("localhost:5000/image");
        if let UrlLike::DockerRef {
            registry, image, ..
        } = &u
        {
            assert_eq!(registry.as_deref(), Some("localhost:5000"));
            assert_eq!(image, "image");
        }
    }

    #[test]
    fn test_docker_ref_with_digest() {
        let u = parse_docker_ref("registry:5000/org/image:v1@sha256:abc123");
        if let UrlLike::DockerRef {
            registry,
            image,
            tag,
            digest,
        } = &u
        {
            assert_eq!(registry.as_deref(), Some("registry:5000"));
            assert_eq!(image, "org/image");
            assert_eq!(tag.as_deref(), Some("v1"));
            assert_eq!(digest.as_deref(), Some("sha256:abc123"));
        }
    }

    #[test]
    fn test_docker_ref_gcr() {
        let u = parse_docker_ref("gcr.io/project/image");
        if let UrlLike::DockerRef {
            registry, image, ..
        } = &u
        {
            assert_eq!(registry.as_deref(), Some("gcr.io"));
            assert_eq!(image, "project/image");
        }
    }

    #[test]
    fn test_docker_dotted_tag() {
        let u = parse_docker_ref("nginx:1.25");
        if let UrlLike::DockerRef { image, tag, .. } = &u {
            assert_eq!(image, "library/nginx");
            assert_eq!(tag.as_deref(), Some("1.25"));
        } else {
            panic!("expected DockerRef");
        }
    }

    #[test]
    fn test_docker_registry_port_no_tag() {
        let u = parse_docker_ref("registry.io:5000/nginx");
        if let UrlLike::DockerRef {
            registry,
            image,
            tag,
            ..
        } = &u
        {
            assert_eq!(registry.as_deref(), Some("registry.io:5000"));
            assert_eq!(image, "nginx");
            assert!(tag.is_none());
        } else {
            panic!("expected DockerRef");
        }
    }

    #[test]
    fn test_docker_registry_port_with_dotted_tag() {
        let u = parse_docker_ref("registry.io:5000/nginx:1.25");
        if let UrlLike::DockerRef {
            registry,
            image,
            tag,
            ..
        } = &u
        {
            assert_eq!(registry.as_deref(), Some("registry.io:5000"));
            assert_eq!(image, "nginx");
            assert_eq!(tag.as_deref(), Some("1.25"));
        } else {
            panic!("expected DockerRef");
        }
    }

    #[test]
    fn test_unparsed_fallback() {
        let u = parse_url("not://[invalid");
        assert!(matches!(u, UrlLike::Unparsed { .. }));
    }
}
