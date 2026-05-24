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

        /// Caller cannot enforce a block (human output is rendered as
        /// `DETECTED (shell hook cannot block in preexec mode…)` instead of
        /// `BLOCKED`). Exit codes, JSON, and audit logs are unchanged — this
        /// flag only changes the human rendering. Used by bash preexec mode
        /// where the DEBUG trap can warn but can't abort the command.
        #[arg(long)]
        warn_only: bool,

        /// Suppress all network activity on the hot path: skip the periodic
        /// background threat-DB refresh so analysis runs purely locally.
        /// Also honored via the TIRITH_OFFLINE environment variable.
        #[arg(long)]
        offline: bool,

        /// When the command is blocked or warned, also print a concrete safer
        /// alternative (e.g. download-then-review instead of pipe-to-shell).
        /// Advisory only — does not change the verdict or exit code.
        ///
        /// The canonical spelling is `--suggest`; `--suggest-safe-command` is
        /// kept as a visible (non-hidden) deprecated alias for backward
        /// compatibility. Both spellings resolve to the same internal flag.
        #[arg(long = "suggest", visible_alias = "suggest-safe-command")]
        suggest_safe_command: bool,

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

    /// Analyze and run a package install as a recorded transaction
    #[command(after_help = "\
A safe-install transaction: tirith analyzes an install's supply-chain risk
BEFORE running it, presents the verdict, records the transaction (a working-
directory checkpoint plus an audit entry), then runs the real install only
after the analysis and your go-ahead.

This is pre-execution install-RISK ANALYSIS plus a recorded transaction. It
does NOT sandbox or isolate the install — the real `npm install` / `pip
install` / `cargo install` (or the downloaded script) runs with your full
privileges. Runtime sandboxing is an explicit tirith non-goal.

The package(s) are scored with the deterministic `tirith package risk`
engine, the install command with the install-command rules, and any URL with
the URL analysis. A block refuses (bypass per policy); a warn requires
acknowledgement; an allow proceeds. Offline by default — `--online` adds
registry-API provenance signals; `--offline` / TIRITH_OFFLINE forces offline.

tirith's own flags (--online, --offline, --no-exec, --yes, --format, --sha256)
go BEFORE the <source>; everything AFTER the source is passed verbatim to the
package manager (so `--save-dev` reaches npm, not tirith).

Examples:
  tirith install npm left-pad
  tirith install --online pip requests
  tirith install --yes cargo ripgrep
  tirith install --no-exec npm some-pkg       # analyze only, do not install
  tirith install npm some-pkg --save-dev      # --save-dev is passed to npm
  tirith install url https://get.example-tool.sh")]
    Install {
        /// What to install: a package manager (npm, pip, cargo) or a URL
        #[arg(value_enum)]
        source: cli::install::InstallSource,

        /// Packages and flags passed verbatim to the package manager (or the
        /// URL for the `url` form). tirith's own flags go before <source>.
        #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
        args: Vec<String>,

        /// Also consult each package's registry API (npm / PyPI / crates.io)
        /// for provenance signals. Off by default; ignored under --offline.
        #[arg(long)]
        online: bool,

        /// Force offline analysis even if --online is passed. Also honored via
        /// the TIRITH_OFFLINE environment variable.
        #[arg(long)]
        offline: bool,

        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,

        /// Proceed past warnings without an interactive prompt
        #[arg(long)]
        yes: bool,

        /// Analyze and record only — do NOT run the real install
        #[arg(long)]
        no_exec: bool,

        /// Expected SHA-256 of the downloaded script (url form only)
        #[arg(long)]
        sha256: Option<String>,
    },

    /// Run adversarial training scenarios (experimental)
    #[command(after_help = "\
Examples:
  tirith lab
  tirith lab --filter powershell
  tirith lab --score
  tirith lab --non-interactive
  tirith lab --format json")]
    Lab {
        /// Filter scenarios by tag (e.g. 'powershell', 'pipe-to-shell')
        #[arg(long)]
        filter: Option<String>,

        /// Non-interactive: run all scenarios without prompting
        #[arg(long)]
        non_interactive: bool,

        /// Include a deterministic 0-100 risk score per scenario
        /// (Critical=100, High=75, Medium=50, Low=25, Info=5; max wins).
        #[arg(long)]
        score: bool,

        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Score a URL for security risk
    #[command(after_help = "\
Examples:
  tirith score https://get.example-tool.sh
  tirith score --explain https://example.com
  tirith score --format json https://example.com")]
    Score {
        /// URL to score
        url: String,

        /// Show the full factor-by-factor breakdown of how the score was
        /// derived. Every factor is fixed and inspectable — the breakdown
        /// sums exactly to the final score, reproducible by hand.
        #[arg(long)]
        explain: bool,

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
  tirith explain --rule curl_pipe_shell --fix
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

        /// Show only the rule's remediation ("what to do instead").
        /// Requires --rule; not valid with --list.
        #[arg(long, requires = "rule", conflicts_with = "list")]
        fix: bool,

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

    /// Scan files for hidden content, config poisoning, and CI/repo supply-chain risk
    #[command(after_help = "\
Scans repository files for hidden/invisible content, AI-config poisoning, and
CI/repo supply-chain risks: unpinned GitHub Actions, the pull_request_target
trigger, curl|bash in workflow run steps, untrusted-input interpolation,
un-pinned Dockerfile base images, remote Terraform modules, untrusted Helm
chart repos, and dangerous package.json install scripts.

It also scans AI-relevant file types for content smuggled past a human
reviewer: hidden content in Jupyter notebooks (.ipynb) — invisible characters,
base64 blobs, hidden cells, suspicious outputs; hidden directives in AI
agent-instruction files (CLAUDE.md, AGENTS.md, .cursorrules) — HTML comments
and visually-hidden elements; and active or external content in SVG images —
embedded scripts, event handlers, remote references.

Examples:
  tirith scan ./
  tirith scan --ci --fail-on high ./
  tirith scan --format sarif ./ > results.sarif
  tirith scan --profile ci-hardening ./
  tirith scan --profile oss-maintainer ./

Built-in --profile values:
  ci-hardening    harden a CI/CD pipeline — every supply-chain check at full
                  strength, fail-on high
  ai-agent-repo   a repo an AI agent works in — keep injection/poisoning
                  findings, suppress low-value pinning-hygiene noise
  oss-maintainer  reviewing a contributed change — emphasize contributor-
                  controllable risk (script injection, dangerous triggers)")]
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

        /// Scan profile: a built-in (ci-hardening, ai-agent-repo, oss-maintainer)
        /// or a named profile from policy (a policy profile of the same name wins)
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

    /// Govern the MCP servers a repository declares
    #[command(after_help = "\
Captures and governs the Model Context Protocol (MCP) servers a repository
declares across its MCP configuration files — .mcp.json / mcp.json /
mcp_settings.json and the IDE variants under .vscode/, .cursor/, .windsurf/,
.cline/, .amazonq/, .continue/, .kiro/.

`tirith mcp lock` writes a deterministic lockfile at .tirith/mcp.lock recording
every declared MCP server — its name, transport (a remote URL, or a local
command + args), and declared tools — plus a content hash per server and over
the whole inventory. The lockfile is diff-friendly: servers are sorted by name,
so a `git diff` shows exactly what changed in the repo's MCP surface.

`tirith mcp verify` gates on drift: it loads the committed lockfile, rebuilds
the current inventory, and exits non-zero when the two differ. `tirith mcp
diff` shows the same drift informationally (always exits 0).

This is a local file operation — no network, off the detection hot path.
Discovery is repo-local only: user-level configs (e.g. ~/.claude/) are never
inventoried.

Examples:
  tirith mcp lock
  tirith mcp lock --format json
  tirith mcp verify
  tirith mcp diff --format json")]
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },

    /// Inspect and govern per-agent identity (observability surface)
    #[command(after_help = "\
Surfaces the agent governance signal recorded with every tirith verdict:
`AgentOrigin` — Human / Agent / Mcp / Gateway / Ci / Ide — captured from
`TIRITH_INTEGRATION`, MCP `clientInfo`, CI heuristics, and the gateway code
path. Every signal is **operator-trust** (caller-claimed); see
docs/agent-governance-design.md for the honest threat model.

`tirith agent sessions` lists recent audit log entries grouped by origin
with per-group counts, last-seen timestamps, and a (Allow / Warn / Block)
histogram. `tirith agent explain` drills into one session ID or partial
command. `tirith agent policy init` scaffolds an opt-in
`.tirith/agent-policy.yaml.example` from observed origins. `tirith agent
allow` validates and emits a matcher snippet for the policy.

**Enforcement is live.** Chunk 2 shipped the surface and the policy
schema; chunk 3 wired `agent_rules` into verdict gating via
`escalation::apply_agent_rules`. A non-bypass verdict whose
`agent_origin` matches a `deny` entry is now forced to Block (with a
`RuleId::AgentDeniedByPolicy` finding attached); a matching `allow` is
recorded but does NOT bypass an existing Block (`allow` is reserved for
richer matcher payloads in a future chunk). Test changes in a non-CI
shell before rolling out.

Examples:
  tirith agent sessions
  tirith agent sessions --format json
  tirith agent explain claude-code
  tirith agent policy init
  tirith agent allow --kind agent --tool claude-code")]
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },

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
  tirith setup copilot-cli
  tirith setup kiro --scope user
  tirith setup claude-code --dry-run")]
    Setup {
        /// Tool to configure: claude-code, codex, copilot-cli, cursor, gemini-cli, kiro, openclaw, pi-cli, vscode, windsurf
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
  tirith policy test 'curl https://example.com | bash'
  tirith policy tune --from-audit")]
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

    /// Manage trusted patterns (allowlist entries with scope, TTL, and audit)
    #[command(after_help = "\
Trust is narrow and expiring by default: trust the most specific thing that
works, and entries expire after 30d unless you pass --permanent. A broad
pattern (whole domain, wildcard, bare TLD) requires --broad.

Examples:
  tirith trust add raw.githubusercontent.com/org/repo/main/get.sh
  tirith trust add example.com --broad --ttl 7d
  tirith trust add get.docker.com --broad --rule curl_pipe_shell --permanent
  tirith trust list --format json --expired
  tirith trust explain example.com
  tirith trust diff
  tirith trust gc --expired
  tirith trust remove example.com")]
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

    /// Score a package's provenance / maintainer risk
    #[command(after_help = "\
Scores a package the way `tirith score` scores a URL: a deterministic,
fully explainable sum of named factors — no model, no learned weights.

Offline by default: name signals come from the local threat database, and
content signals (install scripts, bundled binary blobs) only from a package
directory you already have on disk. `--online` additionally consults the
package's registry API (npm / PyPI / crates.io) for provenance signals;
`--offline` / TIRITH_OFFLINE forces offline even with `--online`.

Examples:
  tirith package risk npm react
  tirith package risk pypi reqeusts
  tirith package risk npm left-pad --path ./node_modules/left-pad
  tirith package risk --online npm express
  tirith package explain npm express
  tirith package explain --format json pypi requests")]
    Package {
        #[command(subcommand)]
        action: PackageAction,
    },

    /// Scan a project's dependency manifests for supply-chain risk
    #[command(after_help = "\
Walks a project directory, parses every dependency manifest it understands
(npm, Python, Rust, Go, Ruby), and scores every declared dependency with the
same deterministic engine as `tirith package risk` — plus a slopsquat
(AI-hallucinated package name) heuristic. Offline by default; --online adds
registry-API provenance signals. Findings are policy-aware and audit-logged.

Examples:
  tirith ecosystem scan
  tirith ecosystem scan ./my-project
  tirith ecosystem scan --online ./my-project
  tirith ecosystem scan --format json ./my-project")]
    Ecosystem {
        #[command(subcommand)]
        action: EcosystemAction,
    },

    /// Manage the threat intelligence database
    #[command(
        name = "threat-db",
        visible_alias = "threatdb",
        after_help = "\
Examples:
  tirith threat-db update
  tirith threat-db status --format json
  tirith threat-db explain react
  tirith threat-db sources
  tirith threat-db health
  tirith threat-db diff --since 2026-01-01"
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
  tirith doctor --fix --yes
  tirith doctor --compat
  tirith doctor --simulate-enter")]
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
        /// Run the bash enter-mode delivery self-test and cache the result
        #[arg(
            long,
            conflicts_with = "format",
            conflicts_with = "json",
            conflicts_with = "fix",
            conflicts_with = "reset_bash_safe_mode"
        )]
        simulate_enter: bool,
        /// Print a focused shell/terminal compatibility report (supports
        /// --format json). Mutually exclusive with --fix, --simulate-enter,
        /// and --reset-bash-safe-mode.
        #[arg(
            long,
            conflicts_with = "fix",
            conflicts_with = "simulate_enter",
            conflicts_with = "reset_bash_safe_mode"
        )]
        compat: bool,

        /// Write a redacted diagnostic bundle to a file and print its path.
        /// The bundle (doctor info, tirith + hook versions, shell/mode/effective
        /// protection, hook-chain state, policy discovery, threat-DB status, and
        /// relevant environment) is safe to attach to a bug report: secrets,
        /// tokens, and the literal home-directory path are redacted. Accepts the
        /// aliases --redacted-report and --shell-trace. Mutually exclusive with
        /// --fix, --simulate-enter, --reset-bash-safe-mode, and --compat.
        #[arg(
            long,
            visible_alias = "redacted-report",
            visible_alias = "shell-trace",
            conflicts_with = "fix",
            conflicts_with = "simulate_enter",
            conflicts_with = "reset_bash_safe_mode",
            conflicts_with = "compat"
        )]
        bundle: bool,
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

    /// Verify the running tirith binary's integrity and provenance
    #[command(after_help = "\
Verifies that the tirith binary you are running is the genuine, unmodified
binary from an official release. It re-downloads the release archive for this
exact version, checks it against the signed release checksums.txt (and the
cosign signature when cosign is installed), and confirms the running binary is
byte-identical to the official one.

If full verification is not possible — a local dev build, no network, an
unknown install — it says so HONESTLY rather than reporting a false 'verified'.

This command reaches the network; it does so only when you run it.

Examples:
  tirith verify-self
  tirith verify-self --format json")]
    VerifySelf {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Update tirith to the latest release (package-manager aware)
    #[command(after_help = "\
Updates tirith to the latest release. tirith detects how it was installed:

  * Package-manager installs (Homebrew, cargo, npm, Scoop, AUR, apt/dnf) are
    NEVER self-modified — tirith prints the exact command to run instead.
  * A self-managed install (the install.sh tarball or a standalone binary) is
    updated in place: tirith downloads the release, verifies it, then performs
    an atomic swap, keeping the previous binary so --rollback can revert.

This command reaches the network; it does so only when you run it.

Examples:
  tirith update
  tirith update --verify
  tirith update --rollback
  tirith update --dry-run")]
    Update {
        /// Verify the new release's provenance (checksum + cosign signature)
        /// before installing; verification failure aborts the update.
        #[arg(long)]
        verify: bool,

        /// Revert to the previously-installed binary (self-managed installs
        /// only). Conflicts with --verify.
        #[arg(long, conflicts_with = "verify")]
        rollback: bool,

        /// Show what would happen without changing anything.
        #[arg(long)]
        dry_run: bool,

        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,

        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Show the running binary's version and provenance
    #[command(after_help = "\
Examples:
  tirith version
  tirith version --provenance
  tirith version --provenance --format json")]
    Version {
        /// Show full provenance: build info, detected install method, and the
        /// (offline) verification status. Run `tirith verify-self` for full
        /// networked verification.
        #[arg(long)]
        provenance: bool,

        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
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
  tirith policy init --force
  tirith policy init --template individual
  tirith policy init --template ci-strict
  tirith policy init --template ai-agent-heavy

Templates:
  individual      sensible defaults for a single developer
  ci-strict       strict CI settings (fail-closed, no bypass, scan fail-on)
  ai-agent-heavy  tuned for environments where AI agents run many commands")]
    Init {
        /// Overwrite existing policy file
        #[arg(long)]
        force: bool,
        /// Generate minimal template (default: full)
        #[arg(long, conflicts_with = "template")]
        minimal: bool,
        /// Use a curated starter policy: individual, ci-strict, or ai-agent-heavy
        #[arg(long, value_name = "NAME")]
        template: Option<String>,
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
    /// Suggest policy adjustments from the local audit log (suggest-only)
    #[command(after_help = "\
Analyzes your audit log and suggests concrete, conservative policy changes —
e.g. a rule you allow or bypass every time may warrant an allowlist entry.
It only SUGGESTS: it never edits your policy. Review each suggestion, then
apply it yourself. When the log is too small it says so rather than guess.

Examples:
  tirith policy tune --from-audit
  tirith policy tune --from-audit --format json")]
    Tune {
        /// Analyze the local audit log (currently the only source).
        #[arg(long)]
        from_audit: bool,
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
    /// Add a trusted pattern (narrow scope and a 30d TTL by default)
    #[command(after_help = "\
Trust the narrowest thing that works. A specific URL or path is accepted as-is;
a whole domain, wildcard, or bare TLD is broad and requires --broad. Entries
expire after 30d unless you pass --permanent or your own --ttl.

Examples:
  tirith trust add raw.githubusercontent.com/org/repo/main/get.sh
  tirith trust add example.com --broad --ttl 7d
  tirith trust add example.com --broad --rule pipe_to_interpreter --permanent
  tirith trust add example.com --broad --reason \"internal mirror, ticket OPS-42\"")]
    Add {
        /// Pattern to trust (a specific URL/path, or a domain with --broad)
        pattern: String,
        /// Scope trust to a specific rule ID (narrower than a global trust)
        #[arg(long)]
        rule: Option<String>,
        /// TTL duration (e.g., 1h, 7d, 30d). Default: 30d. Conflicts with --permanent
        #[arg(long, conflicts_with = "permanent")]
        ttl: Option<String>,
        /// Never expire this entry (opt out of the default TTL)
        #[arg(long)]
        permanent: bool,
        /// Accept a broad pattern (whole domain, wildcard, or bare TLD)
        #[arg(long)]
        broad: bool,
        /// Free-text reason recorded with the entry (shown by `trust explain`)
        #[arg(long)]
        reason: Option<String>,
        /// Scope: user (default) or repo
        #[arg(long, default_value = "user")]
        scope: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// List trusted patterns from all sources, with scope visualization
    #[command(after_help = "\
Each row shows the entry's scope class (exact / substring / domain / wildcard /
bare-TLD); a '!' marks a dangerously broad entry.

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
    /// Explain a trust entry: scope, coverage, expiry, and why it was added
    #[command(after_help = "\
Examples:
  tirith trust explain example.com
  tirith trust explain example.com --format json")]
    Explain {
        /// Pattern of the entry to explain
        pattern: String,
        /// Scope: user, repo, or all (default)
        #[arg(long, default_value = "all")]
        scope: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Show what changed in the trust set since the last snapshot
    #[command(after_help = "\
Examples:
  tirith trust diff
  tirith trust diff --format json")]
    Diff {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
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
    /// Garbage-collect expired entries from trust stores
    #[command(after_help = "\
Examples:
  tirith trust gc --expired
  tirith trust gc --expired --scope user")]
    Gc {
        /// Collect expired entries — currently the only collection mode, so
        /// this flag is optional
        #[arg(long)]
        expired: bool,
        /// Scope: user, repo, or all (default)
        #[arg(long, default_value = "all")]
        scope: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Prune expired trust entries (alias for `gc`).
    ///
    /// `prune` is the spec-named CLI surface for the M6 garbage-collection
    /// flow; `gc` is the shipping name kept as the canonical short form.
    /// Both invoke the same backing function in `cli::trust::gc`.
    #[command(after_help = "\
Examples:
  tirith trust prune --expired
  tirith trust prune --expired --scope user")]
    Prune {
        /// Collect expired entries — currently the only collection mode.
        #[arg(long)]
        expired: bool,
        /// Scope: user, repo, or all (default)
        #[arg(long, default_value = "all")]
        scope: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Show the audit log of trust-store mutations (add / remove / gc / prune).
    ///
    /// Reads audit-log JSONL entries with `entry_type == "trust_change"`,
    /// optionally filtered by a relative time window (`--since 7d`).
    #[command(after_help = "\
Examples:
  tirith trust audit
  tirith trust audit --since 7d
  tirith trust audit --format json --since 30d")]
    Audit {
        /// Show mutations within the last N days/hours/minutes (e.g. `7d`,
        /// `24h`, `15m`). Without this flag, the full audit history is shown.
        #[arg(long)]
        since: Option<String>,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
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
enum PackageAction {
    /// Score a package's provenance / maintainer risk
    #[command(after_help = "\
Examples:
  tirith package risk npm react
  tirith package risk pypi reqeusts
  tirith package risk npm left-pad --path ./node_modules/left-pad
  tirith package risk --online npm express
  tirith package risk --format json npm express

Offline by default: name and local-content signals only, no network. Add
--online to also consult the registry API (npm / PyPI / crates.io) for
provenance signals — package age, ownership transfer, version spike, download
counts, source-repo URL, yanked/deprecated status. --online is ignored when
--offline or TIRITH_OFFLINE is set, and a registry failure degrades gracefully
to the offline score.")]
    Risk {
        /// Package ecosystem: npm, pypi, rubygems, crates.io, go, maven, nuget, packagist
        ecosystem: String,
        /// Package name
        name: String,
        /// Inspect locally-available package content at this directory for
        /// install-script and binary-blob signals. tirith never downloads the
        /// package; without this flag it tries to auto-discover the package
        /// under node_modules / site-packages relative to the current dir.
        #[arg(long)]
        path: Option<String>,
        /// Also consult the package's registry API (npm / PyPI / crates.io)
        /// for provenance signals. Off by default — this is the only path on
        /// which `package risk` reaches the network. Ignored when --offline
        /// or TIRITH_OFFLINE is set; a registry failure degrades gracefully.
        #[arg(long)]
        online: bool,
        /// Force offline scoring even if --online is passed. Also honored via
        /// the TIRITH_OFFLINE environment variable.
        #[arg(long)]
        offline: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Show the factor-by-factor derivation of a package's risk score
    #[command(after_help = "\
Examples:
  tirith package explain npm express
  tirith package explain pypi reqeusts
  tirith package explain --online npm express
  tirith package explain --format json npm react

Offline by default. --online adds the registry-API provenance factors (see
`tirith package risk --help`); --offline / TIRITH_OFFLINE forces offline.")]
    Explain {
        /// Package ecosystem: npm, pypi, rubygems, crates.io, go, maven, nuget, packagist
        ecosystem: String,
        /// Package name
        name: String,
        /// Inspect locally-available package content at this directory (see
        /// `package risk --path`). tirith never downloads the package.
        #[arg(long)]
        path: Option<String>,
        /// Also consult the package's registry API for provenance signals
        /// (see `tirith package risk --help`). Off by default.
        #[arg(long)]
        online: bool,
        /// Force offline scoring even if --online is passed. Also honored via
        /// the TIRITH_OFFLINE environment variable.
        #[arg(long)]
        offline: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum EcosystemAction {
    /// Scan a project directory's dependency manifests for supply-chain risk
    #[command(after_help = "\
Examples:
  tirith ecosystem scan
  tirith ecosystem scan ./my-project
  tirith ecosystem scan --online ./my-project
  tirith ecosystem scan --format json ./my-project

Discovers package.json / package-lock.json, requirements*.txt / pyproject.toml,
Cargo.toml, go.mod, and Gemfile. Every declared dependency is scored with the
deterministic package-risk engine and checked for the slopsquat (AI-hallucinated
name) pattern. Offline by default — name and typosquat signals come from the
local threat database. --online additionally consults the registry API for
provenance signals; it is ignored under --offline / TIRITH_OFFLINE and a
registry failure degrades gracefully. Findings respect the policy allowlist.")]
    Scan {
        /// Project directory to scan (or a single manifest file).
        /// Defaults to the current directory.
        path: Option<String>,
        /// Also consult each package's registry API (npm / PyPI / crates.io)
        /// for provenance signals. Off by default — this is the only path on
        /// which `ecosystem scan` reaches the network. Ignored when --offline
        /// or TIRITH_OFFLINE is set; a registry failure degrades gracefully.
        #[arg(long)]
        online: bool,
        /// Force offline scoring even if --online is passed. Also honored via
        /// the TIRITH_OFFLINE environment variable.
        #[arg(long)]
        offline: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum McpAction {
    /// Generate or update .tirith/mcp.lock from the repo's MCP configs
    #[command(after_help = "\
Discovers the repository's MCP configuration files, builds a structured
inventory of every declared MCP server, and writes a deterministic lockfile to
.tirith/mcp.lock at the repository root.

If no MCP configuration is found, that is reported plainly — it is not an
error; an empty lockfile is still written so a later check has a baseline.

Examples:
  tirith mcp lock
  tirith mcp lock --format json")]
    Lock {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Verify that the current MCP inventory matches .tirith/mcp.lock (gates on drift)
    #[command(after_help = "\
Loads the committed .tirith/mcp.lock baseline, rebuilds the current MCP-server
inventory from the repo's configuration files, and reports any drift — an MCP
server added, removed, or altered (transport, env, declared tools, or URL
credentials) since the lockfile was taken.

This is the gating companion to `tirith mcp lock`: use it in CI to fail a
build when an MCP surface change lands without a lockfile refresh. The human
output never prints env values or URL userinfos — only the redacted / hashed
form the lockfile already carries.

Exit codes:
  0  inventory matches the lockfile (no drift).
  1  drift detected — the inventory and the lockfile differ.
  2  usage error — no lockfile to verify against, cannot read it, the
     repository root could not be determined, or another operational failure.

Examples:
  tirith mcp verify
  tirith mcp verify --format json")]
    Verify {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Show the drift between the current MCP inventory and .tirith/mcp.lock (informational)
    #[command(after_help = "\
Shows the same drift `tirith mcp verify` computes, but as an informational
diff — never gates a CI build. Use it to inspect what an edit to an MCP
config will do before running `tirith mcp lock` to refresh the committed
lockfile.

The human output groups drifts as added / removed / changed, naming each
server by its declared name. Env values and URL userinfos are never printed
— only that the variable / credential changed, and only on a per-name basis.

Exit codes:
  0  normal — `diff` is informational, so this exit code is returned whether
     drift is present or not. Use `tirith mcp verify` to gate.
  2  usage error — no lockfile to diff against, cannot read it, the
     repository root could not be determined, or another operational failure.
     Distinct from 0 so a piped consumer can tell \"no drift\" apart from
     \"there was nothing to compare\".

Examples:
  tirith mcp diff
  tirith mcp diff --format json")]
    Diff {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Scaffold a starter MCP policy from .tirith/mcp.lock
    #[command(
        name = "policy",
        after_help = "\
Reads the committed .tirith/mcp.lock and writes .tirith/mcp-policy.yaml.example
— a scaffold of `scan.trusted_mcp_servers` and `scan.mcp_allowed_tools` entries
listing every server currently locked and the tools it currently exposes.

Every entry in the example is commented out by design: copying the file
straight into your policy must NEVER silently widen trust. The operator
reviews the scaffold, uncomments the entries they intend to declare, and
merges them into .tirith/policy.yaml.

A separate .example file is cleaner than mutating an existing policy.yaml —
you can diff the scaffold against your working policy and integrate the bits
you want.

Determinism: running `tirith mcp policy init` twice against the same lockfile
produces a byte-identical example file. The lockfile is already sorted by
(name, source_config), so server order is stable.

Examples:
  tirith mcp policy init
  tirith mcp policy init --force            # overwrite an existing example
  tirith mcp policy init --format json     # planned-policy preview"
    )]
    Policy {
        #[command(subcommand)]
        action: McpPolicyAction,
    },
}

#[derive(Subcommand)]
enum McpPolicyAction {
    /// Scaffold a starter MCP policy from the current lockfile
    #[command(after_help = "\
Examples:
  tirith mcp policy init
  tirith mcp policy init --force
  tirith mcp policy init --format json")]
    Init {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
        /// Overwrite an existing .tirith/mcp-policy.yaml.example
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum AgentAction {
    /// List recent audit-log sessions grouped by agent origin
    #[command(after_help = "\
Reads the local JSONL audit log (default: $XDG_DATA_HOME/tirith/log.jsonl)
and aggregates every `verdict` entry by its recorded `AgentOrigin`. For
each origin group it reports the entry count, last-seen timestamp, and an
Allow / Warn / Block histogram so an operator can see at a glance which
classes of caller are producing which classes of verdict.

Entries with no `agent_origin` field (pre-chunk-1 audit lines, hook
telemetry, and any audit caller that did not stamp an origin before
calling `audit::log_verdict`) land in an explicit `unknown` group rather
than being silently dropped — honesty over apparent tidiness. Origin
attribution is best-effort and improves incrementally: chunk 3 removed
the engine's bypass-path audit (previously the engine logged once
without origin, then the CLI logged again with origin — a double entry
where one was attributed and the other was not) and stamped origin on
the `check`, `paste`, `install`, `ecosystem`, MCP, and gateway audit
sites. Other audit-writing paths added in future work may still ship
without origin until they adopt the same stamping pattern; those entries
remain in the `unknown` group rather than being attributed by guess.

Exit codes:
  0  the aggregation ran (zero or more groups reported).
  1  the audit log could not be read, or the JSON output could not be
     written.
  2  usage error (none defined today; reserved).

Examples:
  tirith agent sessions
  tirith agent sessions --format json")]
    Sessions {
        /// Path to the audit log JSONL file (default: $XDG_DATA_HOME/tirith/log.jsonl)
        #[arg(long)]
        log: Option<String>,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Explain the agent-origin attribution chain for a session or command
    #[command(after_help = "\
Given a session ID (an exact session id from `tirith agent sessions`) or a
command substring, locates the matching `verdict` entries in the audit log
and prints the attribution chain: `AgentOrigin`, redacted command, action,
timestamps, and the rule IDs that fired.

Search is **exact on session id, substring (case-insensitive) on command**.
Up to 20 matching entries are shown. With `--format json` the structured
payload carries every match, sorted newest-first.

Exit codes:
  0  one or more entries matched.
  1  no matches, or the audit log could not be read, or the JSON output
     could not be written.

Examples:
  tirith agent explain sess-abc123
  tirith agent explain curl
  tirith agent explain claude-code --format json")]
    Explain {
        /// Session ID or command substring to search for
        session_id_or_command: String,
        /// Path to the audit log JSONL file (default: $XDG_DATA_HOME/tirith/log.jsonl)
        #[arg(long)]
        log: Option<String>,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Scaffold an opt-in starter agent-governance policy from observed origins
    #[command(
        name = "policy",
        after_help = "\
Examples:
  tirith agent policy init
  tirith agent policy init --force
  tirith agent policy init --format json"
    )]
    Policy {
        #[command(subcommand)]
        action: AgentPolicyAction,
    },

    /// Validate an agent-matcher and print the policy snippet to add
    #[command(after_help = "\
Validates a `(kind, tool?)` matcher pair and emits the YAML snippet to paste
into `agent_rules.allow` under `.tirith/policy.yaml` (or
`.tirith/agent-policy.yaml.example`). **Does NOT mutate the policy** — the
operator copies the printed snippet into the file they wish to edit. Since
chunk 3 made `agent_rules` a live enforcement gate (a matching `deny`
forces a Block), keeping `allow` (the print-only command) separate from
any file mutation lets the operator review and place the snippet
deliberately rather than have a CLI silently extend a policy that now
affects live verdicts.

`kind` must be one of `human` / `agent` / `mcp` / `gateway` / `ci` / `ide`.
`tool` is optional and applies only when the kind carries a caller-claimed
payload (`agent`, `mcp`, `ci`, `ide`) — a tool filter on `human` or
`gateway` matches nothing and is rejected up-front.

Exit codes:
  0  the matcher is valid; the snippet was printed.
  1  the matcher is invalid, or the JSON output could not be written.
  2  usage error (none defined today; reserved).

Examples:
  tirith agent allow --kind agent --tool claude-code
  tirith agent allow --kind mcp --tool Cursor
  tirith agent allow --kind human
  tirith agent allow --kind agent --tool claude-code --format json")]
    Allow {
        /// Origin kind: human, agent, mcp, gateway, ci, ide
        #[arg(long)]
        kind: String,
        /// Caller-claimed payload to match (tool name / client name / provider / IDE name).
        /// Optional; omit to match every origin of the given kind.
        #[arg(long)]
        tool: Option<String>,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum AgentPolicyAction {
    /// Scaffold .tirith/agent-policy.yaml.example from observed audit-log origins
    #[command(after_help = "\
Reads the local audit log, collects every distinct `AgentOrigin` it has
recorded, and writes `.tirith/agent-policy.yaml.example` listing every
observed origin as a **commented-out** entry under `agent_rules.allow`.
The operator reviews the scaffold, uncomments the entries they intend to
declare, and merges them into `.tirith/policy.yaml` themselves.

Commented-out by design — importing the example must NEVER silently widen
trust. Mirrors the `tirith mcp policy init` convention.

Determinism: server / kind groups are sorted (kind, then payload), so two
runs against the same audit log produce a byte-identical scaffold.

Exit codes:
  0  the example was written (a missing or empty audit log still writes a
     header-only template so the operator has a starting point).
  1  the repo root could not be determined, the example file already
     exists without `--force`, the audit log is unreadable, or the file
     could not be written.

Examples:
  tirith agent policy init
  tirith agent policy init --force
  tirith agent policy init --format json")]
    Init {
        /// Path to the audit log JSONL file (default: $XDG_DATA_HOME/tirith/log.jsonl)
        #[arg(long)]
        log: Option<String>,
        /// Overwrite an existing .tirith/agent-policy.yaml.example
        #[arg(long)]
        force: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
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
    /// Explain what the threat DB knows about a domain, package, or IP
    #[command(after_help = "\
Examples:
  tirith threat-db explain react
  tirith threat-db explain npm:left-pad
  tirith threat-db explain example.com
  tirith threat-db explain 203.0.113.50 --format json")]
    Explain {
        /// Indicator to look up: a domain, a package name (optionally
        /// `ecosystem:name` or `name@version`), or an IPv4 address.
        indicator: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// List the threat-intelligence sources the DB is built from
    #[command(after_help = "\
Examples:
  tirith threat-db sources
  tirith threat-db sources --format json")]
    Sources {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Report threat DB health: install, signature, staleness, counts
    #[command(after_help = "\
Examples:
  tirith threat-db health
  tirith threat-db health --format json")]
    Health {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Summarize what changed in the DB since a given version or date
    #[command(after_help = "\
Examples:
  tirith threat-db diff --since 42
  tirith threat-db diff --since 2026-01-15
  tirith threat-db diff --since 2026-01-15 --format json")]
    Diff {
        /// Compare against this point: a DB version number (build sequence)
        /// or an ISO date (YYYY-MM-DD).
        #[arg(long)]
        since: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

/// Process entry point. tirith's real logic runs in [`run`], on a thread with
/// an explicit 16 MiB stack: `clap` builds and parses tirith's large command
/// tree at startup, which is stack-heavy, and Windows' ~1 MiB default
/// main-thread stack overflows it once the CLI grows. A generous stack keeps
/// startup safe on every platform regardless of how the command set expands.
fn main() {
    let handle = std::thread::Builder::new()
        .name("tirith-main".to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(run)
        .expect("failed to spawn tirith main thread");
    if handle.join().is_err() {
        // `run` panicked; the panic hook already reported it. Exit with the
        // conventional panic code rather than re-panicking (which would print
        // a second, confusing panic message).
        std::process::exit(101);
    }
}

fn run() {
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
            warn_only,
            offline,
            suggest_safe_command,
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
                warn_only,
                offline,
                suggest_safe_command,
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

        Commands::Install {
            source,
            args,
            online,
            offline,
            format,
            json,
            yes,
            no_exec,
            sha256,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::install::run(source, &args, online, offline, json, yes, no_exec, sha256)
        }

        Commands::Lab {
            filter,
            non_interactive,
            score,
            format,
            json,
        } => {
            let (_, want_json) = HumanJsonFormat::resolve(format, json);
            // Gate interactivity on BOTH stdout (so we don't write prompts
            // into a pipe / log file) AND stdin (so we don't block reading
            // from a closed/redirected stdin and "select interactive then
            // terminate immediately"). The lab loop reads stdin per scenario.
            let interactive = !non_interactive
                && !want_json
                && is_terminal::is_terminal(std::io::stdout())
                && is_terminal::is_terminal(std::io::stdin());
            cli::lab::run(interactive, filter.as_deref(), want_json, score)
        }

        Commands::Score {
            url,
            explain,
            format,
            json,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::score::run(&url, json, explain)
        }

        Commands::Diff { url, format, json } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::diff::run(&url, json)
        }

        Commands::Explain {
            rule,
            list,
            category,
            fix,
            format,
            json,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::explain::run(rule.as_deref(), list, category.as_deref(), fix, json)
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

        Commands::Mcp { action } => match action {
            McpAction::Lock { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::mcp::lock(json)
            }
            McpAction::Verify { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::mcp::verify(json)
            }
            McpAction::Diff { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::mcp::diff(json)
            }
            McpAction::Policy { action } => match action {
                McpPolicyAction::Init {
                    format,
                    json,
                    force,
                } => {
                    let (_, json) = HumanJsonFormat::resolve(format, json);
                    cli::mcp::policy_init(json, force)
                }
            },
        },

        Commands::Agent { action } => match action {
            AgentAction::Sessions { log, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::agent::sessions(log.as_deref(), json)
            }
            AgentAction::Explain {
                session_id_or_command,
                log,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::agent::explain(&session_id_or_command, log.as_deref(), json)
            }
            AgentAction::Policy { action } => match action {
                AgentPolicyAction::Init {
                    log,
                    force,
                    format,
                    json,
                } => {
                    let (_, json) = HumanJsonFormat::resolve(format, json);
                    cli::agent::policy_init(log.as_deref(), force, json)
                }
            },
            AgentAction::Allow {
                kind,
                tool,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::agent::allow(&kind, tool.as_deref(), json)
            }
        },

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
            PolicyAction::Init {
                force,
                minimal,
                template,
            } => cli::policy::init(force, minimal, template.as_deref()),
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
            PolicyAction::Tune {
                from_audit,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::policy::tune(from_audit, json)
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
                permanent,
                broad,
                reason,
                scope,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::trust::add(
                    &pattern,
                    rule.as_deref(),
                    ttl.as_deref(),
                    permanent,
                    broad,
                    reason.as_deref(),
                    &scope,
                    json,
                )
            }
            TrustAction::List {
                rule,
                format,
                json,
                expired,
                scope,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::trust::snapshot_current_trust();
                cli::trust::list(rule.as_deref(), json, expired, &scope)
            }
            TrustAction::Explain {
                pattern,
                scope,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::trust::explain(&pattern, &scope, json)
            }
            TrustAction::Diff { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::trust::diff(json)
            }
            TrustAction::Remove {
                pattern,
                rule,
                scope,
            } => cli::trust::remove(&pattern, rule.as_deref(), &scope),
            TrustAction::Last => cli::trust::last(),
            TrustAction::Gc {
                expired,
                scope,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::trust::gc(expired, &scope, json)
            }
            TrustAction::Prune {
                expired,
                scope,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::trust::prune(expired, &scope, json)
            }
            TrustAction::Audit {
                since,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::trust::audit(since.as_deref(), json)
            }
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

        Commands::Package { action } => match action {
            PackageAction::Risk {
                ecosystem,
                name,
                path,
                online,
                offline,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::package::risk(&ecosystem, &name, path.as_deref(), online, offline, json)
            }
            PackageAction::Explain {
                ecosystem,
                name,
                path,
                online,
                offline,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::package::explain(&ecosystem, &name, path.as_deref(), online, offline, json)
            }
        },

        Commands::Ecosystem { action } => match action {
            EcosystemAction::Scan {
                path,
                online,
                offline,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::ecosystem::scan(path.as_deref(), online, offline, json)
            }
        },

        Commands::ThreatDb { action } => match action {
            ThreatDbAction::Update { force, background } => {
                cli::threatdb_cmd::update(force, background)
            }
            ThreatDbAction::Status { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::threatdb_cmd::status(json)
            }
            ThreatDbAction::Explain {
                indicator,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::threatdb_cmd::explain(&indicator, json)
            }
            ThreatDbAction::Sources { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::threatdb_cmd::sources(json)
            }
            ThreatDbAction::Health { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::threatdb_cmd::health(json)
            }
            ThreatDbAction::Diff {
                since,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::threatdb_cmd::diff(&since, json)
            }
        },

        Commands::Doctor {
            format,
            json,
            reset_bash_safe_mode,
            fix,
            yes,
            simulate_enter,
            compat,
            bundle,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::doctor::run(
                json,
                reset_bash_safe_mode,
                fix,
                yes,
                simulate_enter,
                compat,
                bundle,
            )
        }

        Commands::Completions { shell } => cli::completions::run(shell),

        Commands::Manpage => cli::manpage::run(),

        Commands::VerifySelf { format, json } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::selfupdate::verify_self(json)
        }

        Commands::Update {
            verify,
            rollback,
            dry_run,
            yes,
            format,
            json,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::selfupdate::update(verify, rollback, dry_run, yes, json)
        }

        Commands::Version {
            provenance,
            format,
            json,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::selfupdate::version(provenance, json)
        }
    };

    std::process::exit(exit_code);
}
