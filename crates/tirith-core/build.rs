use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    // Data files live under the crate directory so they are included in the
    // crate tarball and `cargo publish` / `cargo install` work correctly.
    let data_dir = Path::new(&manifest_dir).join("assets").join("data");

    compile_confusables(&data_dir, &out_dir);
    compile_known_domains(&data_dir, &out_dir);
    compile_popular_repos(&data_dir, &out_dir);
    compile_public_suffix_list(&data_dir, &out_dir);
    compile_ocr_confusions(&data_dir, &out_dir);
    generate_tier1_regex(&out_dir);

    println!("cargo:rerun-if-changed=assets/data/confusables.txt");
    println!("cargo:rerun-if-changed=assets/data/known_domains.csv");
    println!("cargo:rerun-if-changed=assets/data/popular_repos.csv");
    println!("cargo:rerun-if-changed=assets/data/public_suffix_list.dat");
    println!("cargo:rerun-if-changed=assets/data/ocr_confusions.tsv");
    println!("cargo:rerun-if-changed=build.rs");
}

fn compile_confusables(data_dir: &Path, out_dir: &str) {
    let confusables_path = data_dir.join("confusables.txt");
    let content = fs::read_to_string(&confusables_path)
        .unwrap_or_else(|e| panic!("Failed to read confusables.txt: {e}"));

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
    code.push_str("/// Auto-generated confusable character table.\n");
    code.push_str("pub const CONFUSABLE_TABLE: &[(u32, u32)] = &[\n");
    for (src, tgt) in &entries {
        code.push_str(&format!("    (0x{src:04X}, 0x{tgt:04X}),\n"));
    }
    code.push_str("];\n");
    let count = entries.len();
    code.push_str(&format!("\npub const CONFUSABLE_COUNT: usize = {count};\n"));

    let out_path = Path::new(out_dir).join("confusables_gen.rs");
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
        // Validate: canonical values with alphabetic chars must be lowercase
        // (comparison pipeline lowercases input, so uppercase canonicals are dead code)
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

    // Sort by confusable length descending (multi-char first for longest-match)
    entries.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

    let mut code = String::new();
    code.push_str("/// Auto-generated OCR confusion table.\n");
    code.push_str(
        "/// Sorted by confusable length descending for longest-match-first normalization.\n",
    );
    code.push_str("pub const OCR_CONFUSIONS: &[(&str, &str)] = &[\n");
    for (confusable, canonical) in &entries {
        // Escape for Rust string literal
        let esc_c = confusable.replace('\\', "\\\\").replace('"', "\\\"");
        let esc_k = canonical.replace('\\', "\\\\").replace('"', "\\\"");
        code.push_str(&format!("    (\"{esc_c}\", \"{esc_k}\"),\n"));
    }
    code.push_str("];\n");
    let count = entries.len();
    code.push_str(&format!(
        "\npub const OCR_CONFUSION_COUNT: usize = {count};\n"
    ));

    let out_path = Path::new(out_dir).join("ocr_confusions_gen.rs");
    fs::write(&out_path, code).unwrap();
}

/// Declarative pattern table for Tier 1 / Tier 3 extraction.
///
/// Each entry has:
/// - id: human-readable extractor name
/// - tier1_exec_fragments: regex fragments that trigger Tier 1 for exec context
/// - tier1_paste_fragments: regex fragments that trigger Tier 1 for paste context (exec + extras)
/// - notes: documentation
///
/// INVARIANT: Any Tier 3 extraction path MUST have a corresponding Tier 1 fragment here.
/// A missing fragment means the extractor can silently miss input — a security bug.
/// build.rs assembles exec-time and paste-time regexes from these fragments at compile time.
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
            r"\|[&\s]*(sudo\s+|env\s+|/\S*/?)*(sh|bash|zsh|dash|ksh|python|node|perl|ruby|php|iex|invoke-expression)\b",
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
        id: "non_ascii_paste",
        tier1_exec_fragments: &[],
        tier1_paste_only_fragments: &[r"[^\x00-\x7F]"],
        notes:
            "Non-ASCII bytes in pasted content (analysis trigger only, never sole reason to WARN)",
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

        // Enforce: every entry must have at least one fragment
        if entry.tier1_exec_fragments.is_empty() && entry.tier1_paste_only_fragments.is_empty() {
            let id = entry.id;
            panic!(
                "COMPILE ERROR: Pattern table entry '{id}' has no Tier 1 fragments! \
                 Every extractor must have a Tier 1 trigger to maintain the superset invariant.",
            );
        }
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

    // Generate extractor IDs array
    code.push_str("\npub const EXTRACTOR_IDS: &[&str] = &[\n");
    for id in &ids {
        code.push_str(&format!("    \"{id}\",\n"));
    }
    code.push_str("];\n");

    let out_path = Path::new(out_dir).join("tier1_gen.rs");
    fs::write(&out_path, code).unwrap();
}
