mod assets;
mod cli;

use std::path::PathBuf;

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
        // `--rule`, `--list`, and `--finding` are three mutually exclusive
        // selectors. `--fix` needs at least one of `--rule`/`--finding`
        // (set as `requires` on the flag) and conflicts with `--list`. The
        // ArgGroup carries the exact-one-of semantics for `--rule` /
        // `--finding` so a stale `--rule X --finding Y` invocation surfaces
        // a clear usage error rather than silently picking one.
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
  PS1='$(tirith prompt-status --short) '\"$PS1\"          # bash
  PROMPT='$(tirith prompt-status --short) '\"$PROMPT\"     # zsh (after setopt PROMPT_SUBST)

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
  tirith clipboard guard status")]
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
  1  HIGH impact (system path / outside repo / empty-variable glob)
  2  review recommended (find -delete / rsync --delete / symlinks)

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
            } => cli::gateway::run_gateway_with_options(
                &upstream_bin,
                &upstream_arg,
                &config,
                cli::gateway::GatewayOptions { filter_output },
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

        Commands::Init {
            shell,
            prompt_status,
        } => cli::init::run(shell.as_deref(), prompt_status),

        Commands::PromptStatus {
            short,
            format,
            json,
        } => {
            let (_, json) = HumanJsonFormat::resolve(format, json);
            cli::prompt_status::run(short, json)
        }

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
            // The value_parser already constrained `target` to the
            // accepted set; parse_audience is infallible here but we
            // surface a clear error if something slips through.
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
    };

    std::process::exit(exit_code);
}
