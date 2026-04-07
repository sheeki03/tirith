mod assets;
mod cli;

use crate::cli::{HumanJsonFormat, HumanJsonSarifFormat};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "tirith",
    version,
    about = "URL security analysis for shell environments"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage the tirith background daemon
    #[command(after_help = "\
Examples:
  tirith daemon start
  tirith daemon stop
  tirith daemon status")]
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },

    /// Check a command for URL security issues before execution
    #[command(after_help = "\
Examples:
  tirith check -- 'curl https://example.com | bash'
  tirith check --format json -- 'npm install suspicious-pkg'")]
    Check {
        /// Shell type for tokenization
        #[arg(long, default_value = "posix")]
        shell: String,

        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,

        /// Force non-interactive mode
        #[arg(long)]
        non_interactive: bool,

        /// Force interactive mode
        #[arg(long)]
        interactive: bool,

        /// Write approval metadata to a temp file and print its path to stdout.
        /// Used by shell hooks for the approval workflow.
        #[arg(long)]
        approval_check: bool,

        /// Require acknowledgement for warnings (overrides policy)
        #[arg(long)]
        strict_warn: bool,

        /// Skip daemon and run analysis locally
        #[arg(long)]
        no_daemon: bool,

        /// The command to check
        #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
        cmd: Vec<String>,
    },

    /// Check pasted content for security issues
    #[command(after_help = "\
Examples:
  echo \"suspicious\" | tirith paste
  tirith paste --format json < clipboard.txt")]
    Paste {
        /// Shell type for tokenization
        #[arg(long, default_value = "posix")]
        shell: String,

        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,

        /// Force non-interactive mode
        #[arg(long)]
        non_interactive: bool,

        /// Force interactive mode
        #[arg(long)]
        interactive: bool,

        /// Path to clipboard HTML for rich-text paste analysis
        #[arg(long)]
        html: Option<String>,
    },

    /// Safely download and execute a script
    #[cfg(unix)]
    #[command(after_help = "\
Examples:
  tirith run https://get.example-tool.sh
  tirith run --no-exec https://example.com/install.sh
  tirith run --sha256 abc123 https://example.com/install.sh")]
    Run {
        /// URL to download and execute
        url: String,

        /// Download and analyze only, don't execute
        #[arg(long)]
        no_exec: bool,

        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,

        /// Expected SHA-256 hash of the downloaded script (abort if mismatch)
        #[arg(long)]
        sha256: Option<String>,
    },

    /// Score a URL for security risk
    #[command(after_help = "\
Examples:
  tirith score https://get.example-tool.sh
  tirith score --format json https://example.com")]
    Score {
        /// URL to score
        url: String,

        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Compare a URL against known-good patterns
    #[command(after_help = "\
Examples:
  tirith diff https://install.example-cli.dev
  tirith diff --format json https://install.example-cli.dev")]
    Diff {
        /// URL to analyze
        url: String,

        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Show documentation for a detection rule
    #[command(after_help = "\
Examples:
  tirith explain --rule pipe_to_interpreter
  tirith explain --list --category terminal")]
    Explain {
        /// Rule ID to explain (e.g., pipe_to_interpreter)
        #[arg(long, conflicts_with = "list")]
        rule: Option<String>,

        /// List all rules, optionally filtered by category
        #[arg(long, conflicts_with = "rule")]
        list: bool,

        /// Filter --list by category (hostname, path, transport, terminal, command, etc.)
        #[arg(long, requires = "list")]
        category: Option<String>,

        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Explain the last triggered rule
    #[command(after_help = "\
Examples:
  tirith why
  tirith why --format json")]
    Why {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Manage execution receipts
    #[command(after_help = "\
Examples:
  tirith receipt last
  tirith receipt list
  tirith receipt verify a1b2c3d4e5f6")]
    Receipt {
        #[command(subcommand)]
        action: ReceiptAction,
    },

    /// Manage file checkpoints for rollback (experimental)
    #[command(after_help = "\
Examples:
  tirith checkpoint create src/ Cargo.toml
  tirith checkpoint list
  tirith checkpoint restore <id>
  tirith checkpoint diff <id>
  tirith checkpoint purge")]
    Checkpoint {
        #[command(subcommand)]
        action: CheckpointAction,
    },

    /// Initialize tirith shell hooks
    #[command(after_help = "\
Examples:
  eval \"$(tirith init --shell zsh)\"
  eval \"$(tirith init --shell bash)\"")]
    Init {
        /// Target shell (default: auto-detect)
        #[arg(long)]
        shell: Option<String>,
    },

    /// Scan files for hidden content and config poisoning
    #[command(after_help = "\
Examples:
  tirith scan ./
  tirith scan --ci --fail-on high ./
  tirith scan --format sarif ./ > results.sarif")]
    Scan {
        /// Path to scan (directory or file)
        path: Option<String>,

        /// Scan a single file explicitly
        #[arg(long, conflicts_with = "path", conflicts_with = "stdin")]
        file: Option<String>,

        /// Read content from stdin
        #[arg(long, conflicts_with = "path", conflicts_with = "file")]
        stdin: bool,

        /// Exit non-zero in CI when findings meet threshold
        #[arg(long)]
        ci: bool,

        /// Severity threshold for CI failure
        #[arg(long, default_value = "critical")]
        fail_on: String,

        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonSarifFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format", conflicts_with = "sarif")]
        json: bool,
        /// Alias for --format sarif
        #[arg(long, hide = true, conflicts_with = "format", conflicts_with = "json")]
        sarif: bool,

        /// Patterns to ignore
        #[arg(long)]
        ignore: Vec<String>,

        /// Include only files matching these patterns
        #[arg(long)]
        include: Vec<String>,

        /// Exclude files matching these patterns (same as --ignore)
        #[arg(long)]
        exclude: Vec<String>,

        /// Load a named scan profile from policy
        #[arg(long)]
        profile: Option<String>,
    },

    /// Check a URL for server-side cloaking (different content for bots vs browsers)
    #[cfg(unix)]
    #[command(after_help = "\
Examples:
  tirith fetch https://example.com/install.sh
  tirith fetch --format json https://example.com/install.sh")]
    Fetch {
        /// URL to check for cloaking
        url: String,

        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Run as MCP server (JSON-RPC over stdio)
    #[command(
        name = "mcp-server",
        after_help = "\
Examples:
  tirith mcp-server

Used by MCP client configurations to run tirith as a local tool server."
    )]
    McpServer,

    /// MCP gateway proxy — intercepts shell tool calls for security analysis
    #[command(after_help = "\
Examples:
  tirith gateway run --upstream-bin npx --upstream-arg @modelcontextprotocol/server-filesystem --config gateway.yaml
  tirith gateway validate-config --config gateway.yaml")]
    Gateway {
        #[command(subcommand)]
        action: GatewayAction,
    },

    /// Configure tirith protection for an AI coding tool
    #[command(after_help = "\
Examples:
  tirith setup claude-code --with-mcp
  tirith setup cursor
  tirith setup claude-code --dry-run")]
    Setup {
        /// Tool to configure: claude-code, codex, cursor, gemini-cli, openclaw, pi-cli, vscode, windsurf
        tool: String,

        /// Scope: project (default for most tools) or user
        #[arg(long)]
        scope: Option<String>,

        /// Also register tirith MCP server (Claude Code and Gemini CLI)
        #[arg(long)]
        with_mcp: bool,

        /// Append zshenv guard to ~/.zshenv (default: print snippet only)
        #[arg(long)]
        install_zshenv: bool,

        /// Show what would be written without writing
        #[arg(long)]
        dry_run: bool,

        /// Overwrite existing files and update stale entries
        #[arg(long)]
        force: bool,

        /// Refresh embedded hook scripts and gateway config to latest defaults.
        /// WARNING: overwrites local edits to generated hook scripts and gateway.yaml.
        /// Does not re-register MCP servers or modify shell profiles — use full setup for that.
        #[arg(long)]
        update_configs: bool,
    },

    /// Manage security policies
    #[command(after_help = "\
Examples:
  tirith policy init
  tirith policy validate
  tirith policy test 'curl https://example.com | bash'")]
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },

    /// Audit log management: export, stats, compliance reports (Team)
    #[command(after_help = "\
Examples:
  tirith audit export
  tirith audit export --format csv --since 2025-01-01
  tirith audit stats --format json
  tirith audit report --format html > report.html")]
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },

    /// Activate a license key
    #[command(after_help = "\
Examples:
  tirith activate <license-key>")]
    Activate {
        /// The signed license token
        key: String,
    },

    /// Show or manage license status
    #[command(after_help = "\
Examples:
  tirith license
  tirith license --format json")]
    License {
        #[command(subcommand)]
        action: Option<LicenseAction>,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Log a hook telemetry event (called by hook scripts, always exits 0)
    #[command(hide = true)]
    HookEvent {
        /// Integration name (e.g., claude-code, cursor, vscode)
        #[arg(long)]
        integration: String,
        /// Hook type (e.g., pre_tool_use, before_shell_execution)
        #[arg(long)]
        hook_type: String,
        /// Event name (e.g., check_ok, check_block, warn_allowed, timeout)
        #[arg(long)]
        event: String,
        /// Hook-level timing in milliseconds
        #[arg(long)]
        elapsed_ms: Option<f64>,
        /// Freeform detail text
        #[arg(long)]
        detail: Option<String>,
    },

    /// Manage trusted patterns (allowlist entries with TTL, scoping, and audit)
    #[command(after_help = "\
Examples:
  tirith trust add example.com
  tirith trust add example.com --ttl 7d
  tirith trust list --format json --expired
  tirith trust remove example.com
  tirith trust last
  tirith trust gc")]
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },

    /// Show accumulated session warnings
    #[command(after_help = "\
Examples:
  tirith warnings
  tirith warnings --format json
  tirith warnings --hidden")]
    Warnings {
        /// Clear session warnings after display
        #[arg(long)]
        clear: bool,

        /// Override session ID
        #[arg(long)]
        session: Option<String>,

        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,

        /// One-line summary (for shell exit hooks)
        #[arg(long, conflicts_with = "format", conflicts_with = "json")]
        summary: bool,

        /// Show findings hidden by paranoia filtering
        #[arg(long)]
        hidden: bool,
    },

    /// Manage the threat intelligence database
    #[command(
        name = "threat-db",
        after_help = "\
Examples:
  tirith threat-db update
  tirith threat-db update --force
  tirith threat-db status --format json"
    )]
    ThreatDb {
        #[command(subcommand)]
        action: ThreatDbAction,
    },

    /// Diagnose tirith installation and configuration
    #[command(after_help = "\
Examples:
  tirith doctor
  tirith doctor --fix
  tirith doctor --fix --yes")]
    Doctor {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(
            long,
            hide = true,
            conflicts_with = "format",
            conflicts_with = "fix",
            conflicts_with = "reset_bash_safe_mode"
        )]
        json: bool,
        /// Remove persistent bash safe-mode flag (re-enables enter mode)
        #[arg(long, conflicts_with = "format")]
        reset_bash_safe_mode: bool,
        /// Auto-fix detected issues
        #[arg(long, conflicts_with = "format")]
        fix: bool,
        /// Auto-approve all fixes (no prompting)
        #[arg(long, requires = "fix")]
        yes: bool,
    },

    /// Generate shell completions
    #[command(hide = true)]
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Generate man page
    #[command(hide = true)]
    Manpage,
}

#[derive(Subcommand)]
enum LicenseAction {
    /// Deactivate current license
    Deactivate,
    /// Refresh license from server
    Refresh,
}

#[derive(Subcommand)]
enum AuditAction {
    /// Export audit log records as JSON or CSV
    #[command(after_help = "\
Examples:
  tirith audit export
  tirith audit export --format csv --since 2025-01-01")]
    Export {
        /// Output format
        #[arg(long, value_enum, default_value_t = AuditExportFormat::Json)]
        format: AuditExportFormat,
        /// Filter: only records since this ISO 8601 date
        #[arg(long)]
        since: Option<String>,
        /// Filter: only records until this ISO 8601 date
        #[arg(long)]
        until: Option<String>,
        /// Filter: only this session ID
        #[arg(long)]
        session: Option<String>,
        /// Filter: only this action (Allow, Warn, Block)
        #[arg(long)]
        action: Option<String>,
        /// Filter: only records matching these rule IDs
        #[arg(long)]
        rule_id: Vec<String>,
        /// Entry type filter: verdict (default), hook_telemetry, or all
        #[arg(long, default_value = "verdict")]
        entry_type: String,
    },
    /// Show summary statistics from the audit log
    #[command(after_help = "\
Examples:
  tirith audit stats
  tirith audit stats --format json")]
    Stats {
        /// Filter to a specific session ID
        #[arg(long)]
        session: Option<String>,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
        /// Entry type filter: verdict (default) or hook_telemetry
        #[arg(long, default_value = "verdict")]
        entry_type: String,
    },
    /// Generate a compliance report from the audit log
    #[command(after_help = "\
Examples:
  tirith audit report
  tirith audit report --format html > report.html")]
    Report {
        /// Output format
        #[arg(long, value_enum, default_value_t = AuditReportFormat::Markdown)]
        format: AuditReportFormat,
        /// Filter: only records since this ISO 8601 date
        #[arg(long)]
        since: Option<String>,
        /// Entry type filter: only verdict is supported
        #[arg(long, default_value = "verdict")]
        entry_type: String,
    },
}

#[derive(Subcommand)]
enum ReceiptAction {
    /// Show the last receipt
    #[command(after_help = "\
Examples:
  tirith receipt last")]
    Last {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// List all receipts
    #[command(after_help = "\
Examples:
  tirith receipt list")]
    List {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Verify a receipt by SHA256
    #[command(after_help = "\
Examples:
  tirith receipt verify a1b2c3d4e5f6")]
    Verify {
        sha256: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum CheckpointAction {
    /// Create a checkpoint of specified paths
    #[command(after_help = "\
Examples:
  tirith checkpoint create src/ Cargo.toml")]
    Create {
        /// Paths to checkpoint
        paths: Vec<String>,
        /// Command that triggered the checkpoint
        #[arg(long)]
        trigger: Option<String>,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// List all checkpoints
    #[command(after_help = "\
Examples:
  tirith checkpoint list")]
    List {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Restore files from a checkpoint
    #[command(after_help = "\
Examples:
  tirith checkpoint restore <id>")]
    Restore {
        /// Checkpoint ID
        id: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Show differences between checkpoint and current state
    #[command(after_help = "\
Examples:
  tirith checkpoint diff <id>")]
    Diff {
        /// Checkpoint ID
        id: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Remove old checkpoints based on age/count/size limits
    #[command(after_help = "\
Examples:
  tirith checkpoint purge")]
    Purge {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum GatewayAction {
    /// Run the gateway proxy
    #[command(after_help = "\
Examples:
  tirith gateway run --upstream-bin npx --upstream-arg @modelcontextprotocol/server-filesystem --config gateway.yaml")]
    Run {
        /// Path to upstream MCP server binary
        #[arg(long)]
        upstream_bin: String,

        /// Arguments to pass to upstream binary
        #[arg(long)]
        upstream_arg: Vec<String>,

        /// Path to gateway config YAML
        #[arg(long)]
        config: String,
    },
    /// Validate gateway config file
    #[command(after_help = "\
Examples:
  tirith gateway validate-config --config gateway.yaml")]
    ValidateConfig {
        /// Path to gateway config YAML
        #[arg(long)]
        config: String,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Generate a starter policy file
    #[command(after_help = "\
Examples:
  tirith policy init
  tirith policy init --force")]
    Init {
        /// Overwrite existing policy file
        #[arg(long)]
        force: bool,
        /// Generate minimal template (default: full)
        #[arg(long)]
        minimal: bool,
    },
    /// Validate a policy file for errors
    #[command(after_help = "\
Examples:
  tirith policy validate
  tirith policy validate --format json")]
    Validate {
        /// Path to policy file (default: auto-discover)
        #[arg(long)]
        path: Option<String>,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Test a command or file against the current policy
    #[command(after_help = "\
Examples:
  tirith policy test 'curl https://example.com | bash'
  tirith policy test --file script.sh")]
    Test {
        /// Command to test
        #[arg(conflicts_with = "file")]
        command: Option<String>,
        /// File to test
        #[arg(long, conflicts_with = "command")]
        file: Option<String>,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum TrustAction {
    /// Add a trusted pattern
    #[command(after_help = "\
Examples:
  tirith trust add example.com
  tirith trust add example.com --ttl 7d
  tirith trust add example.com --rule pipe_to_interpreter")]
    Add {
        /// Pattern to trust (domain, URL fragment, etc.)
        pattern: String,
        /// Scope trust to a specific rule ID
        #[arg(long)]
        rule: Option<String>,
        /// TTL duration (e.g., 1h, 7d, 30d)
        #[arg(long)]
        ttl: Option<String>,
        /// Scope: user (default) or repo
        #[arg(long, default_value = "user")]
        scope: String,
    },
    /// List trusted patterns from all sources
    #[command(after_help = "\
Examples:
  tirith trust list
  tirith trust list --format json --expired")]
    List {
        /// Filter by rule ID
        #[arg(long)]
        rule: Option<String>,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
        /// Include expired entries
        #[arg(long)]
        expired: bool,
        /// Scope: user, repo, or all (default)
        #[arg(long, default_value = "all")]
        scope: String,
    },
    /// Remove a trusted pattern
    #[command(after_help = "\
Examples:
  tirith trust remove example.com")]
    Remove {
        /// Pattern to remove
        pattern: String,
        /// Only remove entries scoped to this rule ID
        #[arg(long)]
        rule: Option<String>,
        /// Scope: user (default) or repo
        #[arg(long, default_value = "user")]
        scope: String,
    },
    /// Show last trigger and interactively trust domains
    #[command(after_help = "\
Examples:
  tirith trust last")]
    Last,
    /// Remove expired entries from trust stores
    #[command(after_help = "\
Examples:
  tirith trust gc")]
    Gc {
        /// Scope: user, repo, or all (default)
        #[arg(long, default_value = "all")]
        scope: String,
    },
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Start the daemon in the foreground
    #[command(after_help = "\
Examples:
  tirith daemon start")]
    Start,
    /// Stop a running daemon
    #[command(after_help = "\
Examples:
  tirith daemon stop")]
    Stop,
    /// Check if daemon is running and measure latency
    #[command(after_help = "\
Examples:
  tirith daemon status")]
    Status,
}

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
enum AuditExportFormat {
    #[default]
    Json,
    Csv,
}

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
enum AuditReportFormat {
    #[default]
    Markdown,
    Json,
    Html,
}

#[derive(Subcommand)]
enum ThreatDbAction {
    /// Download or update the threat intelligence database
    #[command(after_help = "\
Examples:
  tirith threat-db update
  tirith threat-db update --force")]
    Update {
        /// Force re-download even if up to date (bypasses rollback protection)
        #[arg(long)]
        force: bool,

        /// Run as a background update process (used internally by auto-update)
        #[arg(long, hide = true)]
        background: bool,
    },
    /// Show threat DB status, age, and entry counts
    #[command(after_help = "\
Examples:
  tirith threat-db status
  tirith threat-db status --format json")]
    Status {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

fn main() {
    // Reset SIGPIPE to default so piping to head/grep exits cleanly instead of panicking.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();

    let exit_code = match cli.command {
        Commands::Daemon { action } => match action {
            DaemonAction::Start => cli::daemon::start(),
            DaemonAction::Stop => cli::daemon::stop(),
            DaemonAction::Status => cli::daemon::status(),
        },

        Commands::Check {
            shell,
            format,
            json,
            non_interactive,
            interactive,
            approval_check,
            strict_warn,
            no_daemon,
            cmd,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::check::run(
                &cmd.join(" "),
                &shell,
                json,
                non_interactive,
                interactive,
                approval_check,
                strict_warn,
                no_daemon,
            )
        }

        Commands::Paste {
            shell,
            format,
            json,
            non_interactive,
            interactive,
            html,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::paste::run(&shell, json, non_interactive, interactive, html.as_deref())
        }

        #[cfg(unix)]
        Commands::Run {
            url,
            no_exec,
            format,
            json,
            sha256,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::run::run(&url, no_exec, json, sha256)
        }

        Commands::Score { url, format, json } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::score::run(&url, json)
        }

        Commands::Diff { url, format, json } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::diff::run(&url, json)
        }

        Commands::Explain {
            rule,
            list,
            category,
            format,
            json,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::explain::run(rule.as_deref(), list, category.as_deref(), json)
        }

        Commands::Why { format, json } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::why::run(json)
        }

        Commands::Scan {
            path,
            file,
            stdin,
            ci,
            fail_on,
            format,
            json,
            sarif,
            ignore,
            include,
            exclude,
            profile,
        } => {
            let (_, json, sarif) = HumanJsonSarifFormat::resolve(format, json, sarif);
            cli::scan::run(
                path.as_deref(),
                file.as_deref(),
                stdin,
                ci,
                &fail_on,
                json,
                sarif,
                &ignore,
                &include,
                &exclude,
                profile.as_deref(),
            )
        }

        #[cfg(unix)]
        Commands::Fetch { url, format, json } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::fetch::run(&url, json)
        }

        Commands::McpServer => cli::mcp_server::run(),

        Commands::Gateway { action } => match action {
            GatewayAction::Run {
                upstream_bin,
                upstream_arg,
                config,
            } => cli::gateway::run_gateway(&upstream_bin, &upstream_arg, &config),
            GatewayAction::ValidateConfig { config } => cli::gateway::validate_config(&config),
        },

        Commands::Setup {
            tool,
            scope,
            with_mcp,
            install_zshenv,
            dry_run,
            force,
            update_configs,
        } => cli::setup::run(
            &tool,
            scope.as_deref(),
            with_mcp,
            install_zshenv,
            dry_run,
            force,
            update_configs,
        ),

        Commands::Policy { action } => match action {
            PolicyAction::Init { force, minimal } => cli::policy::init(force, minimal),
            PolicyAction::Validate { path, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::policy::validate(path.as_deref(), json)
            }
            PolicyAction::Test {
                command,
                file,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::policy::test(command.as_deref(), file.as_deref(), json)
            }
        },

        Commands::HookEvent {
            integration,
            hook_type,
            event,
            elapsed_ms,
            detail,
        } => cli::hook_event::run(
            &integration,
            &hook_type,
            &event,
            elapsed_ms,
            detail.as_deref(),
        ),

        Commands::Audit { action } => match action {
            AuditAction::Export {
                format,
                since,
                until,
                session,
                action,
                rule_id,
                entry_type,
            } => {
                let format_str = match format {
                    AuditExportFormat::Json => "json",
                    AuditExportFormat::Csv => "csv",
                };
                cli::audit::export(
                    format_str,
                    since.as_deref(),
                    until.as_deref(),
                    session.as_deref(),
                    action.as_deref(),
                    &rule_id,
                    &entry_type,
                )
            }
            AuditAction::Stats {
                session,
                format,
                json,
                entry_type,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::audit::stats(session.as_deref(), json, &entry_type)
            }
            AuditAction::Report {
                format,
                since,
                entry_type,
            } => {
                let format_str = match format {
                    AuditReportFormat::Markdown => "markdown",
                    AuditReportFormat::Json => "json",
                    AuditReportFormat::Html => "html",
                };
                cli::audit::report(format_str, since.as_deref(), &entry_type)
            }
        },

        Commands::Receipt { action } => match action {
            ReceiptAction::Last { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::receipt::last(json)
            }
            ReceiptAction::List { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::receipt::list(json)
            }
            ReceiptAction::Verify {
                sha256,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::receipt::verify(&sha256, json)
            }
        },

        Commands::Checkpoint { action } => match action {
            CheckpointAction::Create {
                paths,
                trigger,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::checkpoint::create_checkpoint(&paths, trigger.as_deref(), json)
            }
            CheckpointAction::List { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::checkpoint::list_checkpoints(json)
            }
            CheckpointAction::Restore { id, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::checkpoint::restore_checkpoint(&id, json)
            }
            CheckpointAction::Diff { id, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::checkpoint::diff_checkpoint(&id, json)
            }
            CheckpointAction::Purge { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::checkpoint::purge_checkpoints(json)
            }
        },

        Commands::Activate { key } => cli::license_cmd::activate(&key),

        Commands::License {
            action,
            format,
            json,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            match action {
                None => cli::license_cmd::show(json),
                Some(LicenseAction::Deactivate) => cli::license_cmd::deactivate(),
                Some(LicenseAction::Refresh) => cli::license_cmd::refresh(),
            }
        }

        Commands::Trust { action } => match action {
            TrustAction::Add {
                pattern,
                rule,
                ttl,
                scope,
            } => cli::trust::add(&pattern, rule.as_deref(), ttl.as_deref(), &scope),
            TrustAction::List {
                rule,
                format,
                json,
                expired,
                scope,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::trust::list(rule.as_deref(), json, expired, &scope)
            }
            TrustAction::Remove {
                pattern,
                rule,
                scope,
            } => cli::trust::remove(&pattern, rule.as_deref(), &scope),
            TrustAction::Last => cli::trust::last(),
            TrustAction::Gc { scope } => cli::trust::gc(&scope),
        },

        Commands::Init { shell } => cli::init::run(shell.as_deref()),

        Commands::Warnings {
            clear,
            session,
            format,
            json,
            summary,
            hidden,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::warnings::run(clear, session.as_deref(), json, summary, hidden)
        }

        Commands::ThreatDb { action } => match action {
            ThreatDbAction::Update { force, background } => {
                cli::threatdb_cmd::update(force, background)
            }
            ThreatDbAction::Status { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::threatdb_cmd::status(json)
            }
        },

        Commands::Doctor {
            format,
            json,
            reset_bash_safe_mode,
            fix,
            yes,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::doctor::run(json, reset_bash_safe_mode, fix, yes)
        }

        Commands::Completions { shell } => cli::completions::run(shell),

        Commands::Manpage => cli::manpage::run(),
    };

    std::process::exit(exit_code);
}
