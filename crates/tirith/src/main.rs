mod assets;
mod cli;

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
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },

    /// Check a command for URL security issues before execution
    Check {
        /// Shell type for tokenization
        #[arg(long, default_value = "posix")]
        shell: String,

        /// Output as JSON
        #[arg(long)]
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
    Paste {
        /// Shell type for tokenization
        #[arg(long, default_value = "posix")]
        shell: String,

        /// Output as JSON
        #[arg(long)]
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
    Run {
        /// URL to download and execute
        url: String,

        /// Download and analyze only, don't execute
        #[arg(long)]
        no_exec: bool,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Expected SHA-256 hash of the downloaded script (abort if mismatch)
        #[arg(long)]
        sha256: Option<String>,
    },

    /// Score a URL for security risk
    Score {
        /// URL to score
        url: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Compare a URL against known-good patterns
    Diff {
        /// URL to analyze
        url: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show documentation for a detection rule
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

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Explain the last triggered rule
    Why {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Manage execution receipts
    Receipt {
        #[command(subcommand)]
        action: ReceiptAction,
    },

    /// Manage file checkpoints for rollback (experimental)
    Checkpoint {
        #[command(subcommand)]
        action: CheckpointAction,
    },

    /// Initialize tirith shell hooks
    Init {
        /// Target shell (default: auto-detect)
        #[arg(long)]
        shell: Option<String>,
    },

    /// Scan files for hidden content and config poisoning
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

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// Output as SARIF 2.1.0 JSON
        #[arg(long)]
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
    Fetch {
        /// URL to check for cloaking
        url: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Run as MCP server (JSON-RPC over stdio)
    #[command(name = "mcp-server")]
    McpServer,

    /// MCP gateway proxy — intercepts shell tool calls for security analysis
    Gateway {
        #[command(subcommand)]
        action: GatewayAction,
    },

    /// Configure tirith protection for an AI coding tool
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
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },

    /// Audit log management: export, stats, compliance reports (Team)
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },

    /// Activate a license key
    Activate {
        /// The signed license token
        key: String,
    },

    /// Show or manage license status
    License {
        #[command(subcommand)]
        action: Option<LicenseAction>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Log a hook telemetry event (called by hook scripts, always exits 0)
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
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },

    /// Show accumulated session warnings
    Warnings {
        /// Clear session warnings after display
        #[arg(long)]
        clear: bool,

        /// Override session ID
        #[arg(long)]
        session: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        /// One-line summary (for shell exit hooks)
        #[arg(long)]
        summary: bool,

        /// Show findings hidden by paranoia filtering
        #[arg(long)]
        hidden: bool,
    },

    /// Diagnose tirith installation and configuration
    Doctor {
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Remove persistent bash safe-mode flag (re-enables enter mode)
        #[arg(long, conflicts_with = "json")]
        reset_bash_safe_mode: bool,
        /// Auto-fix detected issues
        #[arg(long, conflicts_with = "json")]
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
    Export {
        /// Output format: json or csv
        #[arg(long, default_value = "json")]
        format: String,
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
    Stats {
        /// Filter to a specific session ID
        #[arg(long)]
        session: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Entry type filter: verdict (default) or hook_telemetry
        #[arg(long, default_value = "verdict")]
        entry_type: String,
    },
    /// Generate a compliance report from the audit log
    Report {
        /// Output format: markdown, json, or html
        #[arg(long, default_value = "markdown")]
        format: String,
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
    Last {
        #[arg(long)]
        json: bool,
    },
    /// List all receipts
    List {
        #[arg(long)]
        json: bool,
    },
    /// Verify a receipt by SHA256
    Verify {
        sha256: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum CheckpointAction {
    /// Create a checkpoint of specified paths
    Create {
        /// Paths to checkpoint
        paths: Vec<String>,
        /// Command that triggered the checkpoint
        #[arg(long)]
        trigger: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// List all checkpoints
    List {
        #[arg(long)]
        json: bool,
    },
    /// Restore files from a checkpoint
    Restore {
        /// Checkpoint ID
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Show differences between checkpoint and current state
    Diff {
        /// Checkpoint ID
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Remove old checkpoints based on age/count/size limits
    Purge {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum GatewayAction {
    /// Run the gateway proxy
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
    ValidateConfig {
        /// Path to gateway config YAML
        #[arg(long)]
        config: String,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Generate a starter policy file
    Init {
        /// Overwrite existing policy file
        #[arg(long)]
        force: bool,
        /// Generate minimal template (default: full)
        #[arg(long)]
        minimal: bool,
    },
    /// Validate a policy file for errors
    Validate {
        /// Path to policy file (default: auto-discover)
        #[arg(long)]
        path: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Test a command or file against the current policy
    Test {
        /// Command to test
        #[arg(conflicts_with = "file")]
        command: Option<String>,
        /// File to test
        #[arg(long, conflicts_with = "command")]
        file: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum TrustAction {
    /// Add a trusted pattern
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
    List {
        /// Filter by rule ID
        #[arg(long)]
        rule: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Include expired entries
        #[arg(long)]
        expired: bool,
        /// Scope: user, repo, or all (default)
        #[arg(long, default_value = "all")]
        scope: String,
    },
    /// Remove a trusted pattern
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
    Last,
    /// Remove expired entries from trust stores
    Gc {
        /// Scope: user, repo, or all (default)
        #[arg(long, default_value = "all")]
        scope: String,
    },
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Start the daemon in the foreground
    Start,
    /// Stop a running daemon
    Stop,
    /// Check if daemon is running and measure latency
    Status,
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
            json,
            non_interactive,
            interactive,
            approval_check,
            strict_warn,
            no_daemon,
            cmd,
        } => cli::check::run(
            &cmd.join(" "),
            &shell,
            json,
            non_interactive,
            interactive,
            approval_check,
            strict_warn,
            no_daemon,
        ),

        Commands::Paste {
            shell,
            json,
            non_interactive,
            interactive,
            html,
        } => cli::paste::run(&shell, json, non_interactive, interactive, html.as_deref()),

        #[cfg(unix)]
        Commands::Run {
            url,
            no_exec,
            json,
            sha256,
        } => cli::run::run(&url, no_exec, json, sha256),

        Commands::Score { url, json } => cli::score::run(&url, json),

        Commands::Diff { url, json } => cli::diff::run(&url, json),

        Commands::Explain {
            rule,
            list,
            category,
            json,
        } => cli::explain::run(rule.as_deref(), list, category.as_deref(), json),

        Commands::Why { json } => cli::why::run(json),

        Commands::Scan {
            path,
            file,
            stdin,
            ci,
            fail_on,
            json,
            sarif,
            ignore,
            include,
            exclude,
            profile,
        } => cli::scan::run(
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
        ),

        #[cfg(unix)]
        Commands::Fetch { url, json } => cli::fetch::run(&url, json),

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
            PolicyAction::Validate { path, json } => cli::policy::validate(path.as_deref(), json),
            PolicyAction::Test {
                command,
                file,
                json,
            } => cli::policy::test(command.as_deref(), file.as_deref(), json),
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
            } => cli::audit::export(
                &format,
                since.as_deref(),
                until.as_deref(),
                session.as_deref(),
                action.as_deref(),
                &rule_id,
                &entry_type,
            ),
            AuditAction::Stats {
                session,
                json,
                entry_type,
            } => cli::audit::stats(session.as_deref(), json, &entry_type),
            AuditAction::Report {
                format,
                since,
                entry_type,
            } => cli::audit::report(&format, since.as_deref(), &entry_type),
        },

        Commands::Receipt { action } => match action {
            ReceiptAction::Last { json } => cli::receipt::last(json),
            ReceiptAction::List { json } => cli::receipt::list(json),
            ReceiptAction::Verify { sha256, json } => cli::receipt::verify(&sha256, json),
        },

        Commands::Checkpoint { action } => match action {
            CheckpointAction::Create {
                paths,
                trigger,
                json,
            } => cli::checkpoint::create_checkpoint(&paths, trigger.as_deref(), json),
            CheckpointAction::List { json } => cli::checkpoint::list_checkpoints(json),
            CheckpointAction::Restore { id, json } => {
                cli::checkpoint::restore_checkpoint(&id, json)
            }
            CheckpointAction::Diff { id, json } => cli::checkpoint::diff_checkpoint(&id, json),
            CheckpointAction::Purge { json } => cli::checkpoint::purge_checkpoints(json),
        },

        Commands::Activate { key } => cli::license_cmd::activate(&key),

        Commands::License { action, json } => match action {
            None => cli::license_cmd::show(json),
            Some(LicenseAction::Deactivate) => cli::license_cmd::deactivate(),
            Some(LicenseAction::Refresh) => cli::license_cmd::refresh(),
        },

        Commands::Trust { action } => match action {
            TrustAction::Add {
                pattern,
                rule,
                ttl,
                scope,
            } => cli::trust::add(&pattern, rule.as_deref(), ttl.as_deref(), &scope),
            TrustAction::List {
                rule,
                json,
                expired,
                scope,
            } => cli::trust::list(rule.as_deref(), json, expired, &scope),
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
            json,
            summary,
            hidden,
        } => cli::warnings::run(clear, session.as_deref(), json, summary, hidden),

        Commands::Doctor {
            json,
            reset_bash_safe_mode,
            fix,
            yes,
        } => cli::doctor::run(json, reset_bash_safe_mode, fix, yes),

        Commands::Completions { shell } => cli::completions::run(shell),

        Commands::Manpage => cli::manpage::run(),
    };

    std::process::exit(exit_code);
}
