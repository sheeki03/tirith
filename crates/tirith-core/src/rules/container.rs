//! Container-runtime rules (M8 ch5). Fire when the leader is `docker`/`podman`
//! and: `run --privileged` (drops kernel-security boundaries), `run -v` mounting
//! a sensitive host path, or `exec` against a container labeled prod/critical via
//! `policy.context_labels` keyed by `container:<name>`.
//!
//! PATTERN_TABLE adds `docker_run`/`docker_exec` so these reach tier-3 from the
//! exec context. Detection short-circuits on a non-container leader.

use std::collections::HashSet;

use once_cell::sync::Lazy;

use crate::policy::Policy;
use crate::rules::shared::is_critical_label;
use crate::tokenize::{self, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Sensitive bind-mount source paths, matched against the SOURCE side of a
/// `-v src:dst[:opts]` / `--volume src:dst` pair (container side not checked).
static SENSITIVE_BIND_SOURCES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/var/run/podman/podman.sock",
        "/run/podman/podman.sock",
        "~/.ssh",
        "~/.aws",
        "~/.kube",
        "~/.gnupg",
        "~/.docker",
        "/etc",
        "/root/.ssh",
        "/root/.aws",
    ]
    .into_iter()
    .collect()
});

/// Run the container-runtime rules.
pub fn check(input: &str, shell: ShellType, policy: &Policy) -> Vec<Finding> {
    let segments = tokenize::tokenize(input, shell);
    let mut findings = Vec::new();

    for seg in &segments {
        let effective = match crate::rules::command::resolve_effective_segment(seg, shell) {
            Ok(effective) => effective,
            Err(crate::rules::command::EffectiveCommandError::WorkBudgetExceeded) => {
                findings.push(make_finding(
                    RuleId::AnalysisIncomplete,
                    Severity::High,
                    "Container command analysis exceeded its work budget".to_string(),
                    "The container command exceeded Tirith's bounded token-normalization budget. The omitted token suffix is blocked instead of being treated as a non-container command."
                        .to_string(),
                    input,
                    seg,
                ));
                continue;
            }
            Err(_) => {
                if seg.raw.split_whitespace().any(|word| {
                    matches!(command_basename(word, shell).as_str(), "docker" | "podman")
                }) {
                    findings.push(make_finding(
                        RuleId::AnalysisIncomplete,
                        Severity::High,
                        "Container wrapper chain could not be classified safely".to_string(),
                        "The command contains Docker/Podman behind ambiguous or over-deep execution-wrapper options. Tirith blocks it instead of assuming an unresolved container operation is safe.".to_string(),
                        input,
                        seg,
                    ));
                }
                continue;
            }
        };
        let Some(cmd) = effective.command.as_deref() else {
            continue;
        };
        let leader = command_basename(cmd, shell);
        if leader != "docker" && leader != "podman" {
            continue;
        }
        let (subcommand, after_sub) = match locate_subcommand(&effective.args, &leader) {
            Ok(Some(location)) => location,
            Ok(None) => continue,
            Err(()) => {
                findings.push(make_finding(
                    RuleId::AnalysisIncomplete,
                    Severity::High,
                    "Container runtime global options could not be classified safely".to_string(),
                    "The Docker/Podman command uses malformed or unsupported runtime-global option grammar before its subcommand. Tirith blocks it instead of guessing where a privileged run, sensitive mount, or production exec begins."
                        .to_string(),
                    input,
                    seg,
                ));
                continue;
            }
        };
        match subcommand.as_str() {
            "run" | "create" => {
                check_run_or_create(after_sub, input, seg, &mut findings);
            }
            "exec" => {
                check_exec(after_sub, input, seg, policy, &mut findings);
            }
            _ => {}
        }
    }

    findings
}

fn check_run_or_create(
    after_sub: &[String],
    input: &str,
    seg: &tokenize::Segment,
    findings: &mut Vec<Finding>,
) {
    if has_privileged_flag(after_sub) {
        findings.push(make_finding(
            RuleId::DockerRunPrivileged,
            Severity::High,
            "docker run --privileged drops kernel-security boundaries".to_string(),
            "`docker run --privileged` disables every Linux kernel security boundary the \
             runtime normally enforces (caps, seccomp, AppArmor, device cgroup). A breakout \
             from the container becomes a breakout to the host. Drop --privileged and use \
             `--cap-add=<specific>` for the kernel capabilities you actually need."
                .to_string(),
            input,
            seg,
        ));
    }
    if let Some(src) = sensitive_bind_mount(after_sub) {
        // The title and description are public and are persisted to
        // `last_trigger.json`, so the host path is redacted here rather than
        // relying on evidence-only scrubbing.
        let src = crate::redact::redact_command_text(&src, &[]);
        findings.push(make_finding(
            RuleId::DockerRunSensitiveBindMount,
            Severity::High,
            format!("docker run mounts sensitive host path '{src}' into container"),
            format!(
                "`-v {src}:…` exposes a sensitive host path inside the container. \
                 The standard escalation shape is `-v /var/run/docker.sock:…` — once \
                 the container speaks to the host's Docker socket it becomes equivalent \
                 to root on the host. Bind only the specific subdirectory the workload \
                 needs, and prefer a named volume for cached state."
            ),
            input,
            seg,
        ));
    }
}

fn check_exec(
    after_sub: &[String],
    input: &str,
    seg: &tokenize::Segment,
    policy: &Policy,
    findings: &mut Vec<Finding>,
) {
    let Some(container) = first_positional_arg(after_sub) else {
        return;
    };
    if !policy.context_guard_enabled || policy.context_labels.is_empty() {
        return;
    }
    let key = format!("container:{container}");
    let Some(label) = policy.context_labels.get(&key) else {
        return;
    };
    if !is_critical_label(label) {
        return;
    }
    findings.push(make_finding(
        RuleId::DockerExecProdContainer,
        Severity::Medium,
        format!("docker exec against production-labeled container '{container}'"),
        format!(
            "`docker exec {container}` opens an interactive session against a container \
             tagged `{label}` in tirith's context labels. Confirm the container before \
             running mutating commands inside it. The Medium severity is intentional — \
             surface the signal, do not hard-block, because reading logs is often \
             legitimate even on a prod container."
        ),
        input,
        seg,
    ));
}

/// Locate the Docker/Podman subcommand after consuming runtime-global options.
///
/// This deliberately models the global grammar instead of treating every
/// dash-prefixed token as a valueless flag: `docker --context prod run ...`
/// must not mistake `prod` for the subcommand. Both runtimes accept `--x=y`,
/// and their short value options accept attached values (`-Hunix://...`,
/// `-cprod`).
fn locate_subcommand<'a>(
    args: &'a [String],
    runtime: &str,
) -> Result<Option<(String, &'a [String])>, ()> {
    let mut idx = 0;
    while idx < args.len() {
        let a = strip_outer_quotes(&args[idx]);
        if a.is_empty() {
            idx += 1;
            continue;
        }
        if a == "--" {
            let subcommand = strip_outer_quotes(args.get(idx + 1).ok_or(())?);
            if subcommand.is_empty() {
                return Err(());
            }
            return Ok(Some((subcommand.to_lowercase(), &args[idx + 2..])));
        }
        if !a.starts_with('-') || a == "-" {
            return Ok(Some((a.to_lowercase(), &args[idx + 1..])));
        }

        if a.starts_with("--") {
            if let Some((option, _value)) = a.split_once('=') {
                if !global_value_option(runtime, option) && !global_boolean_option(runtime, option)
                {
                    return Err(());
                }
                idx += 1;
                continue;
            }
            if global_boolean_option(runtime, a) {
                idx += 1;
                continue;
            }
            if global_value_option(runtime, a) {
                // A missing value is an invalid/incomplete invocation, not a
                // license to reinterpret a later token as a subcommand.
                args.get(idx + 1).ok_or(())?;
                idx += 2;
                continue;
            }
            // Unknown global option grammar is ambiguous. Refuse to guess;
            // supported Docker/Podman options are enumerated below.
            return Err(());
        }

        if short_global_option_is_attached(runtime, a) || global_boolean_option(runtime, a) {
            idx += 1;
            continue;
        }
        if global_value_option(runtime, a) {
            args.get(idx + 1).ok_or(())?;
            idx += 2;
            continue;
        }
        return Err(());
    }
    Ok(None)
}

fn global_value_option(runtime: &str, option: &str) -> bool {
    let common = matches!(
        option,
        "--config" | "--connection" | "--context" | "--host" | "--log-level" | "--url"
    );
    if common {
        return true;
    }
    match runtime {
        "docker" => matches!(
            option,
            "-c" | "-H" | "-l" | "--tlscacert" | "--tlscert" | "--tlskey"
        ),
        "podman" => matches!(
            option,
            "-c" | "--cgroup-manager"
                | "--conmon"
                | "--db-backend"
                | "--events-backend"
                | "--hooks-dir"
                | "--identity"
                | "--module"
                | "--network-cmd-path"
                | "--network-config-dir"
                | "--out"
                | "--root"
                | "--runroot"
                | "--runtime"
                | "--runtime-flag"
                | "--storage-driver"
                | "--storage-opt"
                | "--tmpdir"
                | "--volumepath"
        ),
        _ => false,
    }
}

fn global_boolean_option(runtime: &str, option: &str) -> bool {
    let common = matches!(option, "--debug" | "--help" | "--version");
    if common {
        return true;
    }
    match runtime {
        "docker" => matches!(option, "-D" | "--tls" | "--tlsverify"),
        "podman" => matches!(
            option,
            "--remote" | "--syslog" | "--transient-store" | "--ssh"
        ),
        _ => false,
    }
}

fn short_global_option_is_attached(runtime: &str, option: &str) -> bool {
    match runtime {
        "docker" => {
            (option.starts_with("-c") || option.starts_with("-H") || option.starts_with("-l"))
                && option.len() > 2
        }
        "podman" => option.starts_with("-c") && option.len() > 2,
        _ => false,
    }
}

fn has_privileged_flag(args: &[String]) -> bool {
    for raw in args {
        let a = strip_outer_quotes(raw);
        if a == "--privileged" || a == "--privileged=true" {
            return true;
        }
    }
    false
}

/// First `-v` / `--volume` / `--mount source=…` argument naming a sensitive
/// source path; returns the matched source.
fn sensitive_bind_mount(args: &[String]) -> Option<String> {
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        let a = strip_outer_quotes(arg);
        if a == "-v" || a == "--volume" {
            if let Some(next) = iter.next() {
                let v = strip_outer_quotes(next);
                if let Some(src) = first_field(v, ':') {
                    if matches_sensitive(&src) {
                        return Some(src);
                    }
                }
            }
            continue;
        }
        if let Some(rest) = a.strip_prefix("--volume=") {
            if let Some(src) = first_field(rest, ':') {
                if matches_sensitive(&src) {
                    return Some(src);
                }
            }
            continue;
        }
        if let Some(rest) = a.strip_prefix("-v=") {
            if let Some(src) = first_field(rest, ':') {
                if matches_sensitive(&src) {
                    return Some(src);
                }
            }
            continue;
        }
        if a == "--mount" {
            if let Some(next) = iter.next() {
                let v = strip_outer_quotes(next);
                if let Some(src) = extract_mount_source(v) {
                    if matches_sensitive(&src) {
                        return Some(src);
                    }
                }
            }
            continue;
        }
        if let Some(rest) = a.strip_prefix("--mount=") {
            if let Some(src) = extract_mount_source(rest) {
                if matches_sensitive(&src) {
                    return Some(src);
                }
            }
        }
    }
    None
}

fn first_field(s: &str, sep: char) -> Option<String> {
    if s.is_empty() {
        return None;
    }
    Some(s.split(sep).next().unwrap_or(s).to_string())
}

fn extract_mount_source(spec: &str) -> Option<String> {
    for part in spec.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("source=") {
            return Some(v.to_string());
        }
        if let Some(v) = part.strip_prefix("src=") {
            return Some(v.to_string());
        }
    }
    None
}

fn matches_sensitive(src: &str) -> bool {
    let normalized = match normalize_bind_source(src) {
        Ok(path) => path,
        // Absolute/home-relative paths that attempt to walk above their root
        // are not safe to classify as benign.
        Err(()) => return true,
    };
    if SENSITIVE_BIND_SOURCES.contains(normalized.as_str()) {
        return true;
    }
    let trimmed = normalized.trim_end_matches('/');
    if SENSITIVE_BIND_SOURCES.contains(trimmed) {
        return true;
    }
    let dir_prefixes = [
        "/etc/",
        "~/.ssh/",
        "~/.aws/",
        "~/.kube/",
        "~/.gnupg/",
        "~/.docker/",
        // The exact-match set already carries /root/.ssh and /root/.aws; without
        // the prefixes a file inside them (`-v /root/.ssh/id_rsa:/k`) is missed
        // while the `~` spelling of the same mount is flagged.
        "/root/.ssh/",
        "/root/.aws/",
    ];
    for prefix in dir_prefixes {
        if normalized.starts_with(prefix) {
            return true;
        }
    }
    false
}

/// Lexically normalize a bind source without touching the filesystem. Known
/// home expansions are represented as `~`, repeated separators and `.` are
/// collapsed, and a `..` that would escape the absolute/home root is rejected.
fn normalize_bind_source(src: &str) -> Result<String, ()> {
    let src = strip_outer_quotes(src).trim();
    let (root, tail) = if let Some(tail) = src.strip_prefix("${HOME}/") {
        ("~", tail)
    } else if let Some(tail) = src.strip_prefix("$HOME/") {
        ("~", tail)
    } else if let Some(tail) = src.strip_prefix("~/") {
        ("~", tail)
    } else if src == "${HOME}" || src == "$HOME" || src == "~" {
        return Ok("~".to_string());
    } else if let Some(tail) = src.strip_prefix('/') {
        ("/", tail)
    } else {
        // Named volumes and unresolved relative host paths are not aliases for
        // the absolute/home protected paths this rule owns.
        return Ok(src.to_string());
    };

    let mut components: Vec<&str> = Vec::new();
    for component in tail.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if components.pop().is_none() {
                    return Err(());
                }
            }
            other => components.push(other),
        }
    }
    if components.is_empty() {
        return Ok(root.to_string());
    }
    if root == "/" {
        Ok(format!("/{}", components.join("/")))
    } else {
        Ok(format!("~/{}", components.join("/")))
    }
}

fn first_positional_arg(args: &[String]) -> Option<String> {
    let mut iter = args.iter().peekable();
    while let Some(raw) = iter.next() {
        let a = strip_outer_quotes(raw);
        if a.is_empty() {
            continue;
        }
        if a == "--" {
            if let Some(next) = iter.next() {
                return Some(strip_outer_quotes(next).to_string());
            }
            return None;
        }
        if a.starts_with('-') {
            if !a.contains('=') && exec_value_bearing_flag(a) {
                iter.next();
            }
            continue;
        }
        return Some(a.to_string());
    }
    None
}

fn exec_value_bearing_flag(flag: &str) -> bool {
    matches!(
        flag,
        "-u" | "-e" | "-w" | "--user" | "--workdir" | "--env" | "--env-file" | "--detach-keys"
    )
}

fn make_finding(
    rule_id: RuleId,
    severity: Severity,
    title: String,
    description: String,
    input: &str,
    seg: &tokenize::Segment,
) -> Finding {
    Finding {
        rule_id,
        severity,
        title,
        description,
        evidence: vec![
            Evidence::CommandPattern {
                pattern: "docker <container-gate>".to_string(),
                // Redact BEFORE truncating. Cutting first can split a private
                // path so the surviving prefix no longer matches a reviewed
                // root, which would leak part of a wallet or credential path
                // that the later redaction pass can no longer recognize.
                matched: crate::redact::redact_command_text(&seg.raw, &[])
                    .chars()
                    .take(200)
                    .collect(),
            },
            Evidence::Text {
                detail: format!(
                    "input: {}",
                    crate::redact::redact_command_text(input, &[])
                        .chars()
                        .take(200)
                        .collect::<String>()
                ),
            },
        ],
        human_view: Some(
            "Container guard — confirm with `tirith devcontainer --help` before re-running."
                .to_string(),
        ),
        agent_view: Some(format!("tirith refused: container gate. rule={rule_id:?}",)),
        mitre_id: None,
        custom_rule_id: None,
    }
}

fn strip_outer_quotes(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn command_basename(cmd: &str, shell: ShellType) -> String {
    let unq = strip_outer_quotes(cmd);
    let basename = match shell {
        ShellType::PowerShell | ShellType::Cmd => unq.rsplit(['/', '\\']).next().unwrap_or(unq),
        _ => unq.rsplit('/').next().unwrap_or(unq),
    };
    let lower = basename.to_lowercase();
    lower
        .strip_suffix(".exe")
        .map(str::to_string)
        .unwrap_or(lower)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn privileged_run_fires() {
        let policy = Policy::default();
        let findings = check("docker run --privileged alpine", ShellType::Posix, &policy);
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::DockerRunPrivileged)),
            "{findings:?}"
        );
    }

    #[test]
    fn execution_wrappers_do_not_hide_container_boundaries() {
        let policy = Policy::default();
        for command in [
            "sudo docker run --privileged alpine",
            "env podman run -v /etc:/host-etc alpine",
            "command docker run --mount type=bind,source=/var/run/docker.sock,target=/sock alpine",
        ] {
            let findings = check(command, ShellType::Posix, &policy);
            assert!(
                findings.iter().any(|finding| matches!(
                    finding.rule_id,
                    RuleId::DockerRunPrivileged | RuleId::DockerRunSensitiveBindMount
                )),
                "wrapper hid container boundary for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn ambiguous_wrapper_around_container_fails_closed() {
        let policy = Policy::default();
        let findings = check(
            "sudo --future-option value docker run --privileged alpine",
            ShellType::Posix,
            &policy,
        );
        assert!(findings.iter().any(|finding| {
            finding.rule_id == RuleId::AnalysisIncomplete && finding.severity == Severity::High
        }));
    }

    #[test]
    fn execution_wrapper_does_not_hide_labeled_container_exec() {
        let mut policy = Policy::default();
        policy
            .context_labels
            .insert("container:payments".to_string(), "production".to_string());
        let findings = check("env docker exec payments sh", ShellType::Posix, &policy);
        assert!(findings
            .iter()
            .any(|finding| matches!(finding.rule_id, RuleId::DockerExecProdContainer)));
    }

    #[test]
    fn privileged_true_form_fires() {
        let policy = Policy::default();
        let findings = check(
            "docker run --privileged=true alpine",
            ShellType::Posix,
            &policy,
        );
        assert!(findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::DockerRunPrivileged)));
    }

    #[test]
    fn global_options_with_split_and_attached_values_reach_subcommand() {
        let policy = Policy::default();
        for command in [
            "docker --context prod run --privileged alpine",
            "docker --context=prod --debug run --privileged alpine",
            "docker -cprod run --privileged alpine",
            "docker -Hunix:///var/run/docker.sock run --privileged alpine",
            "podman --connection prod run --privileged alpine",
            "podman -cprod run --privileged alpine",
            "podman --db-backend sqlite run --privileged alpine",
            "podman --db-backend=sqlite run --privileged alpine",
            "podman --runtime-flag log-format=json run --privileged alpine",
            "podman --runtime-flag=log-format=json run --privileged alpine",
        ] {
            let findings = check(command, ShellType::Posix, &policy);
            assert!(
                findings
                    .iter()
                    .any(|f| matches!(f.rule_id, RuleId::DockerRunPrivileged)),
                "global option bypassed privileged detection for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn global_option_value_is_not_mistaken_for_subcommand() {
        let args = ["--context", "prod", "run", "--privileged"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let (subcommand, rest) = locate_subcommand(&args, "docker")
            .expect("global grammar")
            .expect("subcommand");
        assert_eq!(subcommand, "run");
        assert_eq!(rest, &["--privileged"]);
    }

    #[test]
    fn unresolved_global_option_grammar_fails_closed() {
        let policy = Policy::default();
        for command in [
            "podman --future-global value run --privileged alpine",
            "podman --future-global=value run --privileged alpine",
            "docker --context",
            "podman --",
        ] {
            let findings = check(command, ShellType::Posix, &policy);
            assert!(
                findings.iter().any(|finding| {
                    finding.rule_id == RuleId::AnalysisIncomplete
                        && finding.severity == Severity::High
                }),
                "unresolved global grammar must fail closed for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn known_benign_global_option_forms_remain_clean() {
        let policy = Policy::default();
        for command in [
            "podman --db-backend sqlite run --rm alpine",
            "podman --db-backend=sqlite run --rm alpine",
            "podman --runtime-flag log-format=json run --rm alpine",
            "podman --runtime-flag=log-format=json run --rm alpine",
            "podman --help",
            "docker --version",
        ] {
            let findings = check(command, ShellType::Posix, &policy);
            assert!(
                findings.is_empty(),
                "known benign global grammar must remain clean for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn non_privileged_run_does_not_fire() {
        let policy = Policy::default();
        let findings = check("docker run --rm alpine echo ok", ShellType::Posix, &policy);
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::DockerRunPrivileged)),
            "{findings:?}"
        );
    }

    #[test]
    fn docker_sock_bind_mount_fires() {
        let policy = Policy::default();
        let findings = check(
            "docker run -v /var/run/docker.sock:/var/run/docker.sock alpine",
            ShellType::Posix,
            &policy,
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::DockerRunSensitiveBindMount)),
            "{findings:?}"
        );
    }

    #[test]
    fn equivalent_sensitive_bind_paths_fire() {
        let policy = Policy::default();
        for source in [
            "/var/run//docker.sock",
            "/var/run/./docker.sock",
            "/var/run/../run/docker.sock",
            "$HOME/.ssh/../.ssh",
            "${HOME}/.aws/./credentials",
        ] {
            let command = format!("docker run -v {source}:/host alpine");
            let findings = check(&command, ShellType::Posix, &policy);
            assert!(
                findings
                    .iter()
                    .any(|f| matches!(f.rule_id, RuleId::DockerRunSensitiveBindMount)),
                "equivalent sensitive source escaped detection for {command:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn lexical_bind_normalization_preserves_benign_paths() {
        assert_eq!(
            normalize_bind_source("/home/me/data/../cache"),
            Ok("/home/me/cache".to_string())
        );
        assert!(!matches_sensitive("/home/me/data/../cache"));
        assert!(normalize_bind_source("/../../etc").is_err());
        assert!(matches_sensitive("/../../etc"));
    }

    #[test]
    fn ssh_dir_bind_mount_fires() {
        let policy = Policy::default();
        let findings = check(
            "docker run -v ~/.ssh:/root/.ssh:ro alpine",
            ShellType::Posix,
            &policy,
        );
        assert!(findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::DockerRunSensitiveBindMount)));
    }

    #[test]
    fn aws_dir_bind_mount_fires() {
        let policy = Policy::default();
        let findings = check(
            "docker run --volume=~/.aws:/root/.aws alpine",
            ShellType::Posix,
            &policy,
        );
        assert!(findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::DockerRunSensitiveBindMount)));
    }

    #[test]
    fn mount_type_bind_source_etc_fires() {
        let policy = Policy::default();
        let findings = check(
            "docker run --mount type=bind,source=/etc,target=/host/etc alpine",
            ShellType::Posix,
            &policy,
        );
        assert!(findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::DockerRunSensitiveBindMount)));
    }

    #[test]
    fn benign_bind_mount_does_not_fire() {
        let policy = Policy::default();
        let findings = check(
            "docker run -v /home/me/data:/data alpine",
            ShellType::Posix,
            &policy,
        );
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::DockerRunSensitiveBindMount)),
            "{findings:?}"
        );
    }

    #[test]
    fn exec_prod_container_fires_when_labeled() {
        let mut labels = BTreeMap::new();
        labels.insert("container:payments-prod".to_string(), "prod".to_string());
        let policy = Policy {
            context_guard_enabled: true,
            context_labels: labels,
            ..Policy::default()
        };
        let findings = check(
            "docker exec payments-prod /bin/sh",
            ShellType::Posix,
            &policy,
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::DockerExecProdContainer)),
            "{findings:?}"
        );
    }

    #[test]
    fn exec_unlabeled_container_does_not_fire() {
        let policy = Policy {
            context_guard_enabled: true,
            ..Policy::default()
        };
        let findings = check("docker exec my-dev /bin/sh", ShellType::Posix, &policy);
        assert!(
            !findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::DockerExecProdContainer)),
            "{findings:?}"
        );
    }

    #[test]
    fn exec_guard_off_does_not_fire() {
        let mut labels = BTreeMap::new();
        labels.insert("container:payments-prod".to_string(), "prod".to_string());
        let policy = Policy {
            context_guard_enabled: false,
            context_labels: labels,
            ..Policy::default()
        };
        let findings = check(
            "docker exec payments-prod /bin/sh",
            ShellType::Posix,
            &policy,
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn podman_alias_recognized() {
        let policy = Policy::default();
        let findings = check("podman run --privileged alpine", ShellType::Posix, &policy);
        assert!(findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::DockerRunPrivileged)));
    }

    #[test]
    fn non_docker_leader_short_circuits() {
        let policy = Policy::default();
        let findings = check(
            "kubectl exec payments -- /bin/sh",
            ShellType::Posix,
            &policy,
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn etc_subpath_bind_mount_fires() {
        let policy = Policy::default();
        let findings = check(
            "docker run -v /etc/secrets:/etc/secrets alpine",
            ShellType::Posix,
            &policy,
        );
        assert!(findings
            .iter()
            .any(|f| matches!(f.rule_id, RuleId::DockerRunSensitiveBindMount)));
    }

    #[test]
    fn first_positional_skips_value_flag() {
        let args = ["-u", "root", "mycont", "ls"]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let got = first_positional_arg(&args);
        assert_eq!(got.as_deref(), Some("mycont"));
    }
}
