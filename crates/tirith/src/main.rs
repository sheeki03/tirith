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

        /// Patterns to ignore
        #[arg(long)]
        ignore: Vec<String>,
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
        /// Tool to configure: claude-code, codex, cursor, vscode, windsurf
        tool: String,

        /// Scope: project (default for most tools) or user
        #[arg(long)]
        scope: Option<String>,

        /// Also register tirith MCP server (Claude Code only)
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
    },

    /// Diagnose tirith installation and configuration
    Doctor {
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Remove persistent bash safe-mode flag (re-enables enter mode)
        #[arg(long, conflicts_with = "json")]
        reset_bash_safe_mode: bool,
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

fn main() {
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Commands::Check {
            shell,
            json,
            non_interactive,
            interactive,
            cmd,
        } => cli::check::run(&cmd.join(" "), &shell, json, non_interactive, interactive),

        Commands::Paste { shell, json } => cli::paste::run(&shell, json),

        #[cfg(unix)]
        Commands::Run { url, no_exec, json } => cli::run::run(&url, no_exec, json),

        Commands::Score { url, json } => cli::score::run(&url, json),

        Commands::Diff { url, json } => cli::diff::run(&url, json),

        Commands::Why { json } => cli::why::run(json),

        Commands::Scan {
            path,
            file,
            stdin,
            ci,
            fail_on,
            json,
            ignore,
        } => cli::scan::run(
            path.as_deref(),
            file.as_deref(),
            stdin,
            ci,
            &fail_on,
            json,
            &ignore,
        ),

        Commands::McpServer => cli::mcp_server::run(),

        Commands::Gateway { action } => match action {
            GatewayAction::Run {
                upstream_bin,
                upstream_arg,
                config,
            } => cli::gateway::run_gateway(&upstream_bin, &upstream_arg, &config),
            GatewayAction::ValidateConfig { config } => cli::gateway::validate_config(&config),
        },

        Commands::Receipt { action } => match action {
            ReceiptAction::Last { json } => cli::receipt::last(json),
            ReceiptAction::List { json } => cli::receipt::list(json),
            ReceiptAction::Verify { sha256, json } => cli::receipt::verify(&sha256, json),
        },

        Commands::Init { shell } => cli::init::run(shell.as_deref()),

        Commands::Setup {
            tool,
            scope,
            with_mcp,
            install_zshenv,
            dry_run,
            force,
        } => cli::setup::run(
            &tool,
            scope.as_deref(),
            with_mcp,
            install_zshenv,
            dry_run,
            force,
        ),

        Commands::Doctor {
            json,
            reset_bash_safe_mode,
        } => cli::doctor::run(json, reset_bash_safe_mode),

        Commands::Completions { shell } => cli::completions::run(shell),

        Commands::Manpage => cli::manpage::run(),
    };

    std::process::exit(exit_code);
}
