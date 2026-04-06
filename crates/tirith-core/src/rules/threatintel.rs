use std::net::Ipv4Addr;

use crate::extract::ExtractedUrl;
use crate::threatdb::{self, Ecosystem, ThreatDb};
use crate::tokenize::{Segment, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// A reference to a package extracted from a shell command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRef {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: Option<String>,
}

/// Split a `name<sep>version` string (e.g. `serde@1.0` or `rails:7.0`).
///
/// Returns `(name, Some(version))` when `sep` is found and the version part
/// is non-empty, otherwise `(input, None)`.
fn split_name_version(s: &str, sep: char) -> (&str, Option<String>) {
    if let Some(pos) = s.find(sep) {
        let name = &s[..pos];
        let ver = &s[pos + 1..];
        (
            name,
            if ver.is_empty() {
                None
            } else {
                Some(ver.to_string())
            },
        )
    } else {
        (s, None)
    }
}

/// Extract package references from tokenized shell segments.
///
/// Recognizes install/add commands for: pip, npm, yarn, pnpm, bun, npx,
/// cargo, gem, go, composer, dotnet.
///
/// Skips flags (tokens starting with `-`) and known non-package arguments
/// like `--index-url <url>`, `--save-dev`, etc.
pub fn extract_packages(segments: &[Segment]) -> Vec<PackageRef> {
    let mut packages = Vec::new();

    for seg in segments {
        let cmd = match &seg.command {
            Some(c) => c.to_lowercase(),
            None => continue,
        };

        // Strip leading path (e.g., /usr/bin/pip3 -> pip3)
        let cmd_name = cmd.rsplit('/').next().unwrap_or(&cmd);

        match cmd_name {
            "pip" | "pip3" | "uv" => {
                extract_pip_packages(&seg.args, &mut packages);
            }
            "npm" | "npx" | "yarn" | "pnpm" | "bun" => {
                extract_npm_packages(cmd_name, &seg.args, &mut packages);
            }
            "cargo" => {
                extract_cargo_packages(&seg.args, &mut packages);
            }
            "gem" => {
                extract_gem_packages(&seg.args, &mut packages);
            }
            "go" => {
                extract_go_packages(&seg.args, &mut packages);
            }
            "composer" => {
                extract_composer_packages(&seg.args, &mut packages);
            }
            "dotnet" => {
                extract_dotnet_packages(&seg.args, &mut packages);
            }
            "mvn" | "gradle" | "gradlew" => {
                extract_maven_packages(&seg.args, &mut packages);
            }
            _ => {}
        }
    }

    packages
}

/// Flags for pip that consume the next argument (so it should be skipped).
const PIP_ARG_FLAGS: &[&str] = &[
    "--index-url",
    "-i",
    "--extra-index-url",
    "--find-links",
    "-f",
    "--constraint",
    "-c",
    "--requirement",
    "-r",
    "--target",
    "-t",
    "--root",
    "--prefix",
    "--src",
    "--build",
    "-b",
    "--config-settings",
    "--global-option",
    "--install-option",
    "--proxy",
    "--retries",
    "--timeout",
    "--exists-action",
    "--trusted-host",
    "--cert",
    "--client-cert",
    "--cache-dir",
];

fn extract_pip_packages(args: &[String], packages: &mut Vec<PackageRef>) {
    // Look for "install" subcommand
    let mut iter = args.iter();
    let mut found_install = false;
    while let Some(arg) = iter.next() {
        let lower = arg.to_lowercase();
        if !found_install {
            if lower == "install" {
                found_install = true;
            }
            continue;
        }

        // Skip flags
        if arg.starts_with('-') {
            // Check if this flag consumes the next arg
            if PIP_ARG_FLAGS.contains(&lower.as_str()) {
                let _ = iter.next(); // consume the value
            }
            continue;
        }

        // Skip URL-based installs (git+, http://, file://, etc.)
        if arg.contains("://") || lower.starts_with("git+") {
            continue;
        }

        // Skip local paths (contain / or \, or start with .)
        if arg.contains('/') || arg.contains('\\') || arg.starts_with('.') {
            continue;
        }

        // Parse package name and version
        // pip: foo==1.2.3, foo>=1.0, foo~=2.0, foo!=1.0, foo[extra]==1.0
        let pkg_str = arg.as_str();

        // Strip extras: foo[bar,baz]==1.0 -> foo==1.0
        let (name_part, rest) = if let Some(bracket_pos) = pkg_str.find('[') {
            if let Some(close_pos) = pkg_str[bracket_pos..].find(']') {
                let name = &pkg_str[..bracket_pos];
                let after = &pkg_str[bracket_pos + close_pos + 1..];
                (name, after)
            } else {
                (pkg_str, "")
            }
        } else {
            // Split at first version specifier
            let split_pos = pkg_str
                .find("==")
                .or_else(|| pkg_str.find(">="))
                .or_else(|| pkg_str.find("<="))
                .or_else(|| pkg_str.find("~="))
                .or_else(|| pkg_str.find("!="))
                .or_else(|| pkg_str.find('>'))
                .or_else(|| pkg_str.find('<'));
            if let Some(pos) = split_pos {
                (&pkg_str[..pos], &pkg_str[pos..])
            } else {
                (pkg_str, "")
            }
        };

        if name_part.is_empty() {
            continue;
        }

        // Extract version from rest (after ==, >=, etc.)
        let version = extract_pip_version(rest);

        // Normalize PyPI name: lowercase, replace - and _ with -
        let normalized = normalize_pypi_name(name_part);

        packages.push(PackageRef {
            ecosystem: Ecosystem::PyPI,
            name: normalized,
            version,
        });
    }
}

/// Normalize a PyPI package name: lowercase, replace `_` and `.` with `-`.
fn normalize_pypi_name(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c == '_' || c == '.' { '-' } else { c })
        .collect()
}

/// Extract exact version from pip version specifier.
/// Only returns a version for `==` (exact match).
fn extract_pip_version(spec: &str) -> Option<String> {
    if let Some(ver) = spec.strip_prefix("==") {
        let v = ver.trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    None
}

/// Flags for npm/yarn/pnpm that consume the next argument.
const NPM_ARG_FLAGS: &[&str] = &[
    "--registry",
    "--tag",
    "--scope",
    "--otp",
    "--workspace",
    "-w",
    "--prefix",
];

fn extract_npm_packages(cmd_name: &str, args: &[String], packages: &mut Vec<PackageRef>) {
    let mut iter = args.iter().peekable();
    let mut found_subcmd = false;

    // For npx, the first non-flag arg is the package to run,
    // unless --package/-p already specified an explicit package.
    if cmd_name == "npx" {
        let mut has_explicit_package = false;
        while let Some(arg) = iter.next() {
            if arg.starts_with('-') {
                // Some npx flags consume next arg
                if arg == "--package" || arg == "-p" {
                    if let Some(pkg_arg) = iter.next() {
                        if let Some(pr) = parse_npm_package_spec(pkg_arg) {
                            packages.push(pr);
                            has_explicit_package = true;
                        }
                    }
                }
                continue;
            }
            // First non-flag arg: only treat as package if no --package given
            if !has_explicit_package {
                if let Some(pr) = parse_npm_package_spec(arg) {
                    packages.push(pr);
                }
            }
            break;
        }
        return;
    }

    // Look for install/i/add subcommand
    while let Some(arg) = iter.next() {
        let lower = arg.to_lowercase();
        if !found_subcmd {
            if matches!(lower.as_str(), "install" | "i" | "add") {
                found_subcmd = true;
            }
            continue;
        }

        // Skip flags
        if arg.starts_with('-') {
            let lower_ref = lower.as_str();
            if NPM_ARG_FLAGS.contains(&lower_ref) {
                let _ = iter.next();
            }
            continue;
        }

        // Skip local paths and URLs
        if arg.contains("://") || arg.starts_with('.') || arg.starts_with('/') {
            continue;
        }

        if let Some(pr) = parse_npm_package_spec(arg) {
            packages.push(pr);
        }
    }
}

/// Parse an npm-style package spec: `@scope/name@version` or `name@version`.
fn parse_npm_package_spec(spec: &str) -> Option<PackageRef> {
    if spec.is_empty() {
        return None;
    }

    let (name, version) = if spec.starts_with('@') {
        // Scoped package: @scope/name@version
        // Find the version @ after the scope
        if let Some(slash_pos) = spec.find('/') {
            let after_scope = &spec[slash_pos + 1..];
            if let Some(at_pos) = after_scope.find('@') {
                let full_name = &spec[..slash_pos + 1 + at_pos];
                let ver = &after_scope[at_pos + 1..];
                (full_name, if ver.is_empty() { None } else { Some(ver) })
            } else {
                (spec, None)
            }
        } else {
            // Invalid scoped package (no slash)
            return None;
        }
    } else if let Some(at_pos) = spec.find('@') {
        let name = &spec[..at_pos];
        let ver = &spec[at_pos + 1..];
        (name, if ver.is_empty() { None } else { Some(ver) })
    } else {
        (spec, None)
    };

    if name.is_empty() {
        return None;
    }

    Some(PackageRef {
        ecosystem: Ecosystem::Npm,
        name: name.to_string(),
        version: version.map(|v| v.to_string()),
    })
}

fn extract_cargo_packages(args: &[String], packages: &mut Vec<PackageRef>) {
    let mut iter = args.iter();
    let mut found_subcmd = false;

    while let Some(arg) = iter.next() {
        let lower = arg.to_lowercase();
        if !found_subcmd {
            if matches!(lower.as_str(), "install" | "add") {
                found_subcmd = true;
            }
            continue;
        }

        // Skip flags
        if arg.starts_with('-') {
            // Flags that consume next arg
            if matches!(
                lower.as_str(),
                "--version"
                    | "--vers"
                    | "--git"
                    | "--branch"
                    | "--tag"
                    | "--rev"
                    | "--path"
                    | "--registry"
                    | "--index"
                    | "--features"
                    | "-F"
                    | "--target-dir"
                    | "--root"
                    | "--jobs"
                    | "-j"
                    | "--rename"
            ) {
                // If --version, capture it for the last package
                if lower == "--version" || lower == "--vers" {
                    if let Some(ver) = iter.next() {
                        if let Some(last) = packages.last_mut() {
                            if last.ecosystem == Ecosystem::Crates && last.version.is_none() {
                                last.version = Some(ver.to_string());
                            }
                        }
                    }
                } else {
                    let _ = iter.next();
                }
                continue;
            }
            continue;
        }

        // Skip git URLs and local paths
        if arg.contains("://") || arg.starts_with('.') || arg.contains('/') {
            continue;
        }

        // cargo add supports name@version
        let (name, version) = split_name_version(arg, '@');

        if !name.is_empty() {
            packages.push(PackageRef {
                ecosystem: Ecosystem::Crates,
                name: name.to_string(),
                version,
            });
        }
    }
}

fn extract_gem_packages(args: &[String], packages: &mut Vec<PackageRef>) {
    let mut iter = args.iter();
    let mut found_install = false;

    while let Some(arg) = iter.next() {
        let lower = arg.to_lowercase();
        if !found_install {
            if lower == "install" {
                found_install = true;
            }
            continue;
        }

        if arg.starts_with('-') {
            // gem install flags that take a value
            if matches!(
                lower.as_str(),
                "--version" | "-v" | "--source" | "--platform" | "--install-dir" | "-i"
            ) {
                // Capture version for last package
                if lower == "--version" || lower == "-v" {
                    if let Some(ver) = iter.next() {
                        if let Some(last) = packages.last_mut() {
                            if last.ecosystem == Ecosystem::RubyGems && last.version.is_none() {
                                last.version = Some(ver.to_string());
                            }
                        }
                    }
                } else {
                    let _ = iter.next();
                }
                continue;
            }
            continue;
        }

        // gem name:version or just name
        let (name, version) = split_name_version(arg, ':');

        if !name.is_empty() {
            packages.push(PackageRef {
                ecosystem: Ecosystem::RubyGems,
                name: name.to_string(),
                version,
            });
        }
    }
}

fn extract_go_packages(args: &[String], packages: &mut Vec<PackageRef>) {
    let mut found_subcmd = false;

    for arg in args {
        let lower = arg.to_lowercase();
        if !found_subcmd {
            if matches!(lower.as_str(), "get" | "install") {
                found_subcmd = true;
            }
            continue;
        }

        if arg.starts_with('-') {
            continue;
        }

        // go get github.com/user/pkg@v1.2.3
        let (name, version) = split_name_version(arg, '@');

        if !name.is_empty() {
            packages.push(PackageRef {
                ecosystem: Ecosystem::Go,
                name: name.to_string(),
                version,
            });
        }
    }
}

fn extract_composer_packages(args: &[String], packages: &mut Vec<PackageRef>) {
    let mut found_require = false;

    for arg in args {
        if !found_require {
            if arg.to_lowercase() == "require" {
                found_require = true;
            }
            continue;
        }

        if arg.starts_with('-') {
            continue;
        }

        // composer require vendor/package:^1.0
        let (name, version) = split_name_version(arg, ':');

        if !name.is_empty() {
            packages.push(PackageRef {
                ecosystem: Ecosystem::Packagist,
                name: name.to_string(),
                version,
            });
        }
    }
}

fn extract_dotnet_packages(args: &[String], packages: &mut Vec<PackageRef>) {
    let mut iter = args.iter();
    let mut found_add = false;
    let mut found_package = false;

    while let Some(arg) = iter.next() {
        let lower = arg.to_lowercase();
        if !found_add {
            if lower == "add" {
                found_add = true;
            }
            continue;
        }

        // `dotnet add package <name>` — skip the project file arg
        if !found_package {
            if lower == "package" {
                found_package = true;
            }
            continue;
        }

        if arg.starts_with('-') {
            // --version takes a value
            if lower == "--version" || lower == "-v" {
                if let Some(ver) = iter.next() {
                    if let Some(last) = packages.last_mut() {
                        if last.ecosystem == Ecosystem::NuGet && last.version.is_none() {
                            last.version = Some(ver.to_string());
                        }
                    }
                }
                continue;
            }
            // Other flags that take values
            if matches!(lower.as_str(), "--source" | "-s" | "--framework" | "-f") {
                let _ = iter.next();
            }
            continue;
        }

        packages.push(PackageRef {
            ecosystem: Ecosystem::NuGet,
            name: arg.to_string(),
            version: None,
        });
    }
}

/// Extract Maven/Gradle dependency coordinates from command arguments.
///
/// Handles `mvn dependency:get -Dartifact=group:artifact:version` and
/// `gradle` dependency notation `group:artifact:version`.
fn extract_maven_packages(args: &[String], packages: &mut Vec<PackageRef>) {
    for arg in args {
        // mvn dependency:get -Dartifact=group:artifact:version[:packaging[:classifier]]
        if let Some(coord) = arg.strip_prefix("-Dartifact=") {
            let parts: Vec<&str> = coord.splitn(4, ':').collect();
            if parts.len() >= 2 {
                let name = format!("{}:{}", parts[0], parts[1]);
                let version = parts.get(2).and_then(|v| {
                    if v.is_empty() {
                        None
                    } else {
                        Some(v.to_string())
                    }
                });
                packages.push(PackageRef {
                    ecosystem: Ecosystem::Maven,
                    name,
                    version,
                });
            }
            continue;
        }

        // Skip flags
        if arg.starts_with('-') {
            continue;
        }

        // Gradle-style group:artifact:version (at least 2 colons)
        let parts: Vec<&str> = arg.splitn(4, ':').collect();
        if parts.len() >= 2 && !parts[0].is_empty() && !parts[1].is_empty() {
            let name = format!("{}:{}", parts[0], parts[1]);
            let version = parts.get(2).and_then(|v| {
                if v.is_empty() {
                    None
                } else {
                    Some(v.to_string())
                }
            });
            packages.push(PackageRef {
                ecosystem: Ecosystem::Maven,
                name,
                version,
            });
        }
    }
}

/// Extract IPv4 addresses from a shell token.
///
/// Handles:
/// - Bare IP: `1.2.3.4`
/// - user@IP: `user@1.2.3.4`
/// - IP:port: `1.2.3.4:22`
/// - user@IP:port: `user@1.2.3.4:22`
///
/// Does NOT match:
/// - IPv6 addresses
/// - Non-IP text
/// - IPs embedded inside URLs (those are handled by URL extraction)
pub fn extract_ipv4_from_token(token: &str) -> Option<Ipv4Addr> {
    // Strip user@ prefix if present
    let after_at = if let Some(at_pos) = token.rfind('@') {
        &token[at_pos + 1..]
    } else {
        token
    };

    // Strip :port suffix if present (but only if what follows the colon is
    // purely digits — avoids stripping parts of IPv6 or other patterns)
    let ip_str = if let Some(colon_pos) = after_at.rfind(':') {
        let after_colon = &after_at[colon_pos + 1..];
        if !after_colon.is_empty() && after_colon.chars().all(|c| c.is_ascii_digit()) {
            &after_at[..colon_pos]
        } else {
            after_at
        }
    } else {
        after_at
    };

    // Strip surrounding brackets that some formats use
    let ip_str = ip_str.trim_matches(|c| c == '[' || c == ']');

    ip_str.parse::<Ipv4Addr>().ok()
}

/// Confidence level label for evidence output.
fn confidence_label(c: threatdb::Confidence) -> &'static str {
    match c {
        threatdb::Confidence::Confirmed => "confirmed",
        threatdb::Confidence::Medium => "medium",
        threatdb::Confidence::Low => "low",
    }
}

/// Map threat-DB confidence to finding severity.
fn confidence_to_severity(c: threatdb::Confidence) -> Severity {
    match c {
        threatdb::Confidence::Confirmed => Severity::Critical,
        threatdb::Confidence::Medium => Severity::Medium,
        threatdb::Confidence::Low => Severity::Medium,
    }
}

/// Check input against the local threat intelligence database.
///
/// Fail-open: if `db` is `None` (no DB file loaded), returns an empty Vec
/// and does not block the command. All lookups are in-memory binary search
/// with no network I/O.
pub fn check(
    input: &str,
    shell: ShellType,
    extracted: &[ExtractedUrl],
    db: Option<&ThreatDb>,
) -> Vec<Finding> {
    let db = match db {
        Some(d) => d,
        None => return Vec::new(), // fail-open
    };

    let mut findings = Vec::new();

    // --- Package checks ---
    let segments = crate::tokenize::tokenize(input, shell);
    let packages = extract_packages(&segments);

    for pkg in &packages {
        let db_eco = pkg.ecosystem;

        // 1. Known-malicious package lookup
        if let Some(m) = db.check_package(db_eco, &pkg.name, pkg.version.as_deref()) {
            findings.push(Finding {
                rule_id: RuleId::ThreatMaliciousPackage,
                severity: confidence_to_severity(m.confidence),
                title: format!("Known malicious {} package: {}", pkg.ecosystem, pkg.name),
                description: format!(
                    "Package '{}' in {} is flagged as malicious by {}. {}",
                    pkg.name,
                    pkg.ecosystem,
                    m.source.label(),
                    if m.all_versions_malicious {
                        "All versions are affected."
                    } else {
                        "Specific version(s) affected."
                    }
                ),
                evidence: vec![Evidence::ThreatIntel {
                    source: m.source.label().to_string(),
                    threat_type: "malicious_package".to_string(),
                    confidence: confidence_label(m.confidence).to_string(),
                    reference: m.reference_url,
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
            // Skip typosquat/distance checks for packages already flagged malicious
            continue;
        }

        // 2. Confirmed typosquat lookup
        if let Some(t) = db.check_typosquat(db_eco, &pkg.name) {
            findings.push(Finding {
                rule_id: RuleId::ThreatPackageTyposquat,
                severity: Severity::High,
                title: format!("Confirmed typosquat: {} → {}", pkg.name, t.target_name),
                description: format!(
                    "Package '{}' in {} is a confirmed typosquat of '{}' \
                     (source: ecosyste.ms typosquatting dataset).",
                    pkg.name, pkg.ecosystem, t.target_name
                ),
                evidence: vec![Evidence::ThreatIntel {
                    source: "ecosyste.ms Typosquats".to_string(),
                    threat_type: "typosquat".to_string(),
                    confidence: "confirmed".to_string(),
                    reference: None,
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }

        // 3. Levenshtein distance to popular package names
        if let Some((popular_name, distance)) = db.check_popular_distance(db_eco, &pkg.name) {
            findings.push(Finding {
                rule_id: RuleId::ThreatPackageSimilarName,
                severity: Severity::Medium,
                title: format!(
                    "Package name similar to popular package: {} ≈ {}",
                    pkg.name, popular_name
                ),
                description: format!(
                    "Package '{}' in {} is within edit distance {} of popular package '{}'. \
                     This could indicate a typosquatting attempt.",
                    pkg.name, pkg.ecosystem, distance, popular_name
                ),
                evidence: vec![Evidence::ThreatIntel {
                    source: "popular package names".to_string(),
                    threat_type: "similar_name".to_string(),
                    confidence: "low".to_string(),
                    reference: None,
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }

    // --- Hostname + IP-from-URL checks ---
    let mut checked_ips = std::collections::HashSet::new();
    for url_info in extracted {
        if let Some(host) = url_info.parsed.host() {
            // Check hostname against threat DB (Phase B data, empty in Phase A but wired)
            if let Some(m) = db.check_hostname(host) {
                findings.push(Finding {
                    rule_id: RuleId::ThreatMaliciousUrl,
                    severity: Severity::High,
                    title: format!("Malicious hostname detected: {}", host),
                    description: format!(
                        "Hostname '{}' appears in threat intelligence feed ({}).",
                        host,
                        m.source.label()
                    ),
                    evidence: vec![Evidence::ThreatIntel {
                        source: m.source.label().to_string(),
                        threat_type: "malicious_hostname".to_string(),
                        confidence: confidence_label(m.confidence).to_string(),
                        reference: m.reference_url,
                    }],
                    human_view: None,
                    agent_view: None,
                    mitre_id: None,
                    custom_rule_id: None,
                });
            }

            // Also check if URL host is an IP address (e.g., curl https://203.0.113.50/payload)
            if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                if checked_ips.insert(ip) {
                    if let Some(m) = db.check_ip(ip) {
                        findings.push(Finding {
                            rule_id: RuleId::ThreatMaliciousIp,
                            severity: Severity::High,
                            title: format!("Known malicious IP in URL: {}", ip),
                            description: format!(
                                "IP address {} (from URL) is flagged by {} as part of botnet C2 infrastructure.",
                                ip,
                                m.source.label()
                            ),
                            evidence: vec![Evidence::ThreatIntel {
                                source: m.source.label().to_string(),
                                threat_type: "malicious_ip".to_string(),
                                confidence: confidence_label(m.confidence).to_string(),
                                reference: m.reference_url,
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
    }

    // --- IP checks from command tokens (ssh/scp/nc args) ---
    for seg in &segments {
        for arg in &seg.args {
            if let Some(ip) = extract_ipv4_from_token(arg) {
                if checked_ips.insert(ip) {
                    if let Some(m) = db.check_ip(ip) {
                        findings.push(Finding {
                            rule_id: RuleId::ThreatMaliciousIp,
                            severity: Severity::High,
                            title: format!("Known malicious IP: {}", ip),
                            description: format!(
                                "IP address {} is flagged by {} as part of botnet C2 infrastructure.",
                                ip,
                                m.source.label()
                            ),
                            evidence: vec![Evidence::ThreatIntel {
                                source: m.source.label().to_string(),
                                threat_type: "malicious_ip".to_string(),
                                confidence: confidence_label(m.confidence).to_string(),
                                reference: m.reference_url,
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
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokenize;

    // ── Helper ──────────────────────────────────────────────────────────

    fn tokenize_and_extract(input: &str) -> Vec<PackageRef> {
        let segments = tokenize::tokenize(input, ShellType::Posix);
        extract_packages(&segments)
    }

    // ── pip tests ───────────────────────────────────────────────────────

    #[test]
    fn pip_install_single() {
        let pkgs = tokenize_and_extract("pip install requests");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::PyPI);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[0].version, None);
    }

    #[test]
    fn pip_install_with_version() {
        let pkgs = tokenize_and_extract("pip install requests==2.31.0");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[0].version, Some("2.31.0".to_string()));
    }

    #[test]
    fn pip_install_version_range_not_exact() {
        let pkgs = tokenize_and_extract("pip install requests>=2.0");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "requests");
        // Only == gives exact version
        assert_eq!(pkgs[0].version, None);
    }

    #[test]
    fn pip3_install() {
        let pkgs = tokenize_and_extract("pip3 install flask");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::PyPI);
        assert_eq!(pkgs[0].name, "flask");
    }

    #[test]
    fn uv_install() {
        let pkgs = tokenize_and_extract("uv install numpy");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::PyPI);
        assert_eq!(pkgs[0].name, "numpy");
    }

    #[test]
    fn pip_install_multiple() {
        let pkgs = tokenize_and_extract("pip install requests flask django");
        assert_eq!(pkgs.len(), 3);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[1].name, "flask");
        assert_eq!(pkgs[2].name, "django");
    }

    #[test]
    fn pip_install_with_extras() {
        let pkgs = tokenize_and_extract("pip install requests[security]==2.31.0");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[0].version, Some("2.31.0".to_string()));
    }

    #[test]
    fn pip_install_skips_flags() {
        let pkgs =
            tokenize_and_extract("pip install --index-url https://pypi.org/simple/ requests");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "requests");
    }

    #[test]
    fn pip_install_skips_url() {
        let pkgs =
            tokenize_and_extract("pip install git+https://github.com/user/repo.git requests");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "requests");
    }

    #[test]
    fn pip_install_skips_local_path() {
        let pkgs = tokenize_and_extract("pip install ./local_pkg requests");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "requests");
    }

    #[test]
    fn pip_normalizes_name() {
        let pkgs = tokenize_and_extract("pip install My_Package.Name");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "my-package-name");
    }

    #[test]
    fn pip_no_install_subcommand() {
        let pkgs = tokenize_and_extract("pip freeze");
        assert!(pkgs.is_empty());
    }

    // ── npm tests ───────────────────────────────────────────────────────

    #[test]
    fn npm_install_single() {
        let pkgs = tokenize_and_extract("npm install lodash");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::Npm);
        assert_eq!(pkgs[0].name, "lodash");
        assert_eq!(pkgs[0].version, None);
    }

    #[test]
    fn npm_install_with_version() {
        let pkgs = tokenize_and_extract("npm install lodash@4.17.21");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "lodash");
        assert_eq!(pkgs[0].version, Some("4.17.21".to_string()));
    }

    #[test]
    fn npm_install_scoped() {
        let pkgs = tokenize_and_extract("npm install @angular/core@16.0.0");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "@angular/core");
        assert_eq!(pkgs[0].version, Some("16.0.0".to_string()));
    }

    #[test]
    fn npm_install_scoped_no_version() {
        let pkgs = tokenize_and_extract("npm install @types/node");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "@types/node");
        assert_eq!(pkgs[0].version, None);
    }

    #[test]
    fn npm_i_shorthand() {
        let pkgs = tokenize_and_extract("npm i express");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "express");
    }

    #[test]
    fn yarn_add() {
        let pkgs = tokenize_and_extract("yarn add react@18.2.0");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::Npm);
        assert_eq!(pkgs[0].name, "react");
        assert_eq!(pkgs[0].version, Some("18.2.0".to_string()));
    }

    #[test]
    fn pnpm_add() {
        let pkgs = tokenize_and_extract("pnpm add vue");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::Npm);
        assert_eq!(pkgs[0].name, "vue");
    }

    #[test]
    fn bun_add() {
        let pkgs = tokenize_and_extract("bun add elysia");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::Npm);
        assert_eq!(pkgs[0].name, "elysia");
    }

    #[test]
    fn npx_package() {
        let pkgs = tokenize_and_extract("npx create-react-app my-app");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::Npm);
        assert_eq!(pkgs[0].name, "create-react-app");
    }

    #[test]
    fn npx_scoped_package() {
        let pkgs = tokenize_and_extract("npx @angular/cli new my-app");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "@angular/cli");
    }

    #[test]
    fn npx_with_package_flag() {
        let pkgs = tokenize_and_extract("npx --package typescript tsc");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "typescript");
    }

    #[test]
    fn npm_install_skips_save_dev() {
        let pkgs = tokenize_and_extract("npm install --save-dev jest");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "jest");
    }

    #[test]
    fn npm_install_multiple() {
        let pkgs = tokenize_and_extract("npm install react react-dom");
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "react");
        assert_eq!(pkgs[1].name, "react-dom");
    }

    // ── cargo tests ─────────────────────────────────────────────────────

    #[test]
    fn cargo_install() {
        let pkgs = tokenize_and_extract("cargo install ripgrep");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::Crates);
        assert_eq!(pkgs[0].name, "ripgrep");
        assert_eq!(pkgs[0].version, None);
    }

    #[test]
    fn cargo_add() {
        let pkgs = tokenize_and_extract("cargo add serde");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "serde");
    }

    #[test]
    fn cargo_add_with_version() {
        let pkgs = tokenize_and_extract("cargo add serde@1.0.193");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "serde");
        assert_eq!(pkgs[0].version, Some("1.0.193".to_string()));
    }

    #[test]
    fn cargo_install_with_version_flag() {
        let pkgs = tokenize_and_extract("cargo install ripgrep --version 14.0.0");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "ripgrep");
        assert_eq!(pkgs[0].version, Some("14.0.0".to_string()));
    }

    #[test]
    fn cargo_skips_git_url() {
        let pkgs = tokenize_and_extract("cargo install --git https://github.com/user/repo");
        assert!(pkgs.is_empty());
    }

    #[test]
    fn cargo_build_not_install() {
        let pkgs = tokenize_and_extract("cargo build --release");
        assert!(pkgs.is_empty());
    }

    // ── gem tests ───────────────────────────────────────────────────────

    #[test]
    fn gem_install() {
        let pkgs = tokenize_and_extract("gem install rails");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::RubyGems);
        assert_eq!(pkgs[0].name, "rails");
    }

    #[test]
    fn gem_install_with_version_flag() {
        let pkgs = tokenize_and_extract("gem install rails --version 7.0.0");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "rails");
        assert_eq!(pkgs[0].version, Some("7.0.0".to_string()));
    }

    #[test]
    fn gem_install_with_colon_version() {
        let pkgs = tokenize_and_extract("gem install rails:7.0.0");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "rails");
        assert_eq!(pkgs[0].version, Some("7.0.0".to_string()));
    }

    // ── go tests ────────────────────────────────────────────────────────

    #[test]
    fn go_get() {
        let pkgs = tokenize_and_extract("go get github.com/gin-gonic/gin");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::Go);
        assert_eq!(pkgs[0].name, "github.com/gin-gonic/gin");
        assert_eq!(pkgs[0].version, None);
    }

    #[test]
    fn go_get_with_version() {
        let pkgs = tokenize_and_extract("go get github.com/gin-gonic/gin@v1.9.1");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "github.com/gin-gonic/gin");
        assert_eq!(pkgs[0].version, Some("v1.9.1".to_string()));
    }

    #[test]
    fn go_install() {
        let pkgs = tokenize_and_extract("go install golang.org/x/tools/gopls@latest");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "golang.org/x/tools/gopls");
        assert_eq!(pkgs[0].version, Some("latest".to_string()));
    }

    // ── composer tests ──────────────────────────────────────────────────

    #[test]
    fn composer_require() {
        let pkgs = tokenize_and_extract("composer require monolog/monolog");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::Packagist);
        assert_eq!(pkgs[0].name, "monolog/monolog");
        assert_eq!(pkgs[0].version, None);
    }

    #[test]
    fn composer_require_with_version() {
        let pkgs = tokenize_and_extract("composer require monolog/monolog:^3.0");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "monolog/monolog");
        assert_eq!(pkgs[0].version, Some("^3.0".to_string()));
    }

    // ── dotnet tests ────────────────────────────────────────────────────

    #[test]
    fn dotnet_add_package() {
        let pkgs = tokenize_and_extract("dotnet add package Newtonsoft.Json");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::NuGet);
        assert_eq!(pkgs[0].name, "Newtonsoft.Json");
        assert_eq!(pkgs[0].version, None);
    }

    #[test]
    fn dotnet_add_package_with_version() {
        let pkgs = tokenize_and_extract("dotnet add package Newtonsoft.Json --version 13.0.3");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "Newtonsoft.Json");
        assert_eq!(pkgs[0].version, Some("13.0.3".to_string()));
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn no_packages_in_ls() {
        let pkgs = tokenize_and_extract("ls -la");
        assert!(pkgs.is_empty());
    }

    #[test]
    fn no_packages_in_echo() {
        let pkgs = tokenize_and_extract("echo hello world");
        assert!(pkgs.is_empty());
    }

    #[test]
    fn piped_commands_both_extracted() {
        let pkgs = tokenize_and_extract("pip install requests && npm install lodash");
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::PyPI);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[1].ecosystem, Ecosystem::Npm);
        assert_eq!(pkgs[1].name, "lodash");
    }

    // ── extract_ipv4_from_token tests ───────────────────────────────────

    #[test]
    fn ipv4_bare() {
        let ip = extract_ipv4_from_token("1.2.3.4");
        assert_eq!(ip, Some(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn ipv4_with_user() {
        let ip = extract_ipv4_from_token("user@192.168.1.1");
        assert_eq!(ip, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn ipv4_with_port() {
        let ip = extract_ipv4_from_token("10.0.0.1:22");
        assert_eq!(ip, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn ipv4_with_user_and_port() {
        let ip = extract_ipv4_from_token("root@10.0.0.1:22");
        assert_eq!(ip, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn ipv4_localhost() {
        let ip = extract_ipv4_from_token("127.0.0.1");
        assert_eq!(ip, Some(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn ipv4_not_an_ip() {
        let ip = extract_ipv4_from_token("hello");
        assert!(ip.is_none());
    }

    #[test]
    fn ipv4_partial_not_valid() {
        let ip = extract_ipv4_from_token("1.2.3");
        assert!(ip.is_none());
    }

    #[test]
    fn ipv4_out_of_range() {
        let ip = extract_ipv4_from_token("999.999.999.999");
        assert!(ip.is_none());
    }

    #[test]
    fn ipv6_not_matched() {
        // IPv6 should not produce IPv4 results
        assert!(extract_ipv4_from_token("::1").is_none());
        assert!(extract_ipv4_from_token("2001:db8::1").is_none());
        assert!(extract_ipv4_from_token("fe80::1%eth0").is_none());
    }

    #[test]
    fn ipv4_empty_string() {
        let ip = extract_ipv4_from_token("");
        assert!(ip.is_none());
    }

    #[test]
    fn ipv4_in_brackets() {
        let ip = extract_ipv4_from_token("[10.0.0.1]");
        assert_eq!(ip, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    // ── check() stub tests ──────────────────────────────────────────────

    #[test]
    fn check_returns_empty_without_db() {
        let findings = check("pip install malicious-pkg", ShellType::Posix, &[], None);
        assert!(findings.is_empty(), "check() must be fail-open without DB");
    }
}
