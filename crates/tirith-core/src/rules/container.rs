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
        let Some(cmd) = seg.command.as_deref() else {
            continue;
        };
        let leader = command_basename(cmd, shell);
        if leader != "docker" && leader != "podman" {
            continue;
        }
        let Some((subcommand, after_sub)) = locate_subcommand(&seg.args) else {
            continue;
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

/// First non-flag positional — the docker subcommand. Returns it plus the args
/// AFTER it.
fn locate_subcommand(args: &[String]) -> Option<(String, &[String])> {
    for (i, raw) in args.iter().enumerate() {
        let a = strip_outer_quotes(raw);
        if a.starts_with('-') {
            continue;
        }
        if a.is_empty() {
            continue;
        }
        return Some((a.to_lowercase(), &args[i + 1..]));
    }
    None
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
    if SENSITIVE_BIND_SOURCES.contains(src) {
        return true;
    }
    let trimmed = src.trim_end_matches('/');
    if SENSITIVE_BIND_SOURCES.contains(trimmed) {
        return true;
    }
    let dir_prefixes = ["/etc/", "~/.ssh/", "~/.aws/", "~/.kube/", "~/.docker/"];
    for prefix in dir_prefixes {
        if src.starts_with(prefix) {
            return true;
        }
    }
    false
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
                matched: seg.raw.chars().take(200).collect(),
            },
            Evidence::Text {
                detail: format!("input: {}", input.chars().take(200).collect::<String>()),
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
