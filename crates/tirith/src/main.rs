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

        Commands::Receipt { action } => match action {
            ReceiptAction::Last { json } => cli::receipt::last(json),
            ReceiptAction::List { json } => cli::receipt::list(json),
            ReceiptAction::Verify { sha256, json } => cli::receipt::verify(&sha256, json),
        },

        Commands::Init { shell } => cli::init::run(shell.as_deref()),

        Commands::Doctor {
            json,
            reset_bash_safe_mode,
        } => cli::doctor::run(json, reset_bash_safe_mode),

        Commands::Completions { shell } => cli::completions::run(shell),

        Commands::Manpage => cli::manpage::run(),
    };

    std::process::exit(exit_code);
}
