---
name: tirith
description: >
  Terminal security analysis for shell environments. This skill should be used
  when checking commands for supply-chain attacks before execution, scanning
  repositories for hidden content or config poisoning, scoring URLs for
  homograph attacks, setting up AI tool protection for Claude Code / Cursor /
  Codex / Windsurf, downloading and executing scripts safely, investigating
  why tirith blocked a command, managing trusted patterns, running security
  audits, configuring MCP gateway proxies, or working with threat intelligence
  databases. Also use when the user mentions "tirith", "pipe-to-shell",
  "homograph", "ANSI injection", "zero-width", "punycode", "terminal security",
  "shell hook", "cloaking detection", "supply chain attack", "bidi override",
  "invisible unicode", or "config poisoning". Even if the user does not
  explicitly name tirith, use this skill when they ask about protecting shell
  environments, intercepting dangerous commands, or hardening AI agent tool
  execution.
---

# tirith — Terminal Security for Developer Environments

tirith intercepts shell commands and pasted text, detecting supply-chain
attacks before they execute. It catches pipe-to-shell patterns, homograph
domains (Cyrillic/Greek lookalikes), ANSI terminal injection, bidi text
overrides, zero-width characters, shortened URLs, punycode tricks, and
config poisoning. It runs as a shell hook for real-time protection and as
a standalone CLI for scanning, scoring, auditing, and AI agent security.

## Quick Start

```bash
# Install shell hooks (zsh/bash/fish/powershell/nushell)
eval "$(tirith init --shell zsh)"              # zsh
eval "$(tirith init --shell bash)"             # bash
tirith init --shell fish | source              # fish
tirith init --shell nushell | source           # nushell

# Check a command before running it
tirith check -- 'curl https://example.com/install.sh | bash'

# Verify installation health
tirith doctor
```

## Detection Rules

tirith uses a three-tier analysis pipeline:
1. **Tier 1** — compiled regex fast gate (sub-millisecond)
2. **Tier 2** — URL/Docker ref extraction, byte scanning for control chars
3. **Tier 3** — full rule evaluation with policy overrides

### Rule categories

| Category | Examples |
|----------|---------|
| **hostname** | Homograph domains, punycode tricks, mixed-script attacks, confusable characters |
| **transport** | Plain HTTP, insecure TLS flags (`--no-check-certificate`), shortened URLs |
| **command** | Pipe-to-shell (`curl \| bash`), dotfile overwrite, archive extract to sensitive paths |
| **terminal** | ANSI escape injection, bidi overrides, zero-width chars, hidden multiline, hangul filler |
| **ecosystem** | Git typosquat, Docker untrusted registry, npm/PyPI lookalike packages |
| **path** | Non-ASCII paths, homoglyph filenames, double-encoding attacks |
| **credential** | Exposed tokens, API keys in command arguments |

Additional categories (codefile, configfile, environment, rendered, threatintel,
custom) are also available.

List all rules: `tirith explain --list`
Filter by category: `tirith explain --list --category terminal`
Explain a specific rule: `tirith explain --rule pipe_to_interpreter`

## Common Workflows

### Intercept dangerous commands

tirith hooks into the shell and checks every command before execution.
Manual check:

```bash
tirith check -- 'curl https://example.com | bash'
tirith check --format json -- 'npm install suspicious-pkg'
tirith check --shell powershell -- 'iwr https://example.com | iex'
```

### Scan a repository for hidden threats

Scan files for invisible Unicode, ANSI escapes, config poisoning, and
hidden content:

```bash
tirith scan ./
tirith scan --ci --fail-on high ./
tirith scan --format sarif ./ > results.sarif
tirith scan --file suspicious.sh
echo "$CLIPBOARD" | tirith scan --stdin
```

Use `--profile` to load a named scan profile from your policy file.

### Score a URL

Get a risk score for a URL before visiting or using it:

```bash
tirith score https://get.example-tool.sh
tirith score --format json https://suspicious-domain.com
```

### Detect server-side cloaking (Unix)

Check if a server returns different content to bots versus browsers:

```bash
tirith fetch https://example.com/install.sh
tirith fetch --format json https://example.com/install.sh
```

### Download and execute safely (Unix)

Download a script, analyze it, and optionally execute with SHA-256
verification and receipt logging:

```bash
tirith run https://get.example-tool.sh
tirith run --no-exec https://example.com/install.sh     # analyze only
tirith run --sha256 abc123... https://example.com/install.sh
```

Verify past executions:

```bash
tirith receipt last
tirith receipt verify a1b2c3d4e5f6
```

### Set up AI tool protection

Configure tirith to guard AI coding agents against prompt injection
and malicious tool calls:

```bash
tirith setup claude-code --with-mcp    # Claude Code + MCP server
tirith setup cursor                     # Cursor
tirith setup codex                      # OpenAI Codex
tirith setup gemini-cli --with-mcp     # Gemini CLI + MCP
tirith setup vscode                     # VS Code
tirith setup windsurf                   # Windsurf
tirith setup pi-cli                     # Pi CLI
tirith setup openclaw                   # OpenClaw
```

Preview changes: `tirith setup claude-code --dry-run`
Update hook scripts: `tirith setup claude-code --update-configs`

### MCP gateway proxy

Intercept tool calls from AI agents through an MCP gateway:

```bash
tirith gateway run \
  --upstream-bin npx \
  --upstream-arg @modelcontextprotocol/server-filesystem \
  --config gateway.yaml
tirith gateway validate-config --config gateway.yaml
```

### Investigate a detection

After tirith blocks or warns:

```bash
tirith why                                    # explain last trigger
tirith why --format json                      # machine-readable
tirith explain --rule pipe_to_interpreter     # rule documentation
tirith explain --list --category terminal     # list rules in category
tirith diff https://install.example-cli.dev   # compare against patterns
```

### Manage trusted patterns

Allow specific domains or URLs after review with TTL and rule scoping:

```bash
tirith trust add example.com                              # permanent global
tirith trust add example.com --ttl 7d                     # expires in 7 days
tirith trust add example.com --rule pipe_to_interpreter   # rule-scoped
tirith trust add example.com --scope repo                 # repo-scoped
tirith trust list                                          # show all entries
tirith trust list --format json --expired                  # include expired
tirith trust last                                          # trust from last trigger
tirith trust gc                                            # remove expired entries
```

### Audit and compliance

Export verdicts, generate statistics, and produce compliance reports:

```bash
tirith audit export                                    # JSON export
tirith audit export --format csv --since 2025-01-01    # CSV with date filter
tirith audit stats --format json                       # summary statistics
tirith audit report --format html > report.html        # compliance report
tirith audit report --format markdown                  # markdown report
```

### Session warnings

Track accumulated warnings across a shell session:

```bash
tirith warnings                         # full warning table
tirith warnings --format json           # machine-readable
tirith warnings --summary               # one-line (for shell exit hooks)
tirith warnings --hidden                # show paranoia-filtered findings
tirith warnings --clear                 # clear after display
```

### Threat intelligence

Manage the threat intelligence database for enhanced detection:

```bash
tirith threat-db update          # download/update threat DB
tirith threat-db update --force  # force re-download
tirith threat-db status          # show DB age and entry counts
```

### Policy management

Configure detection behavior with YAML policies:

```bash
tirith policy init              # generate starter policy
tirith policy init --minimal    # minimal template
tirith policy validate          # check for errors
tirith policy test 'curl https://example.com | bash'  # test a command
```

Policy discovery: walks up from cwd to `.git` boundary looking for
`.tirith/policy.yaml`. Fallback: `~/.config/tirith/policy.yaml`.

Features: allowlists, blocklists, severity overrides, fail-open/closed
modes, scan profiles, org trust lists. See `docs/cookbook.md`.

### Diagnostics

```bash
tirith doctor                   # full diagnostic
tirith doctor --fix             # auto-fix detected issues
tirith doctor --fix --yes       # non-interactive fix
tirith doctor --format json     # machine-readable diagnostic
```

### Background daemon

Speed up repeated checks with a persistent daemon:

```bash
tirith daemon start     # start in foreground
tirith daemon stop      # stop running daemon
tirith daemon status    # check status and measure latency
```

## Output Behavior

### Exit codes

| Code | Action | Meaning |
|------|--------|---------|
| 0 | Allow | Safe — no findings or all findings are informational |
| 1 | Block | Dangerous — execution prevented |
| 2 | Warn | Suspicious — execution allowed, user notified |
| 3 | WarnAck | Warn with strict acknowledgement required |

### Output streams per command

| Command | JSON | Human |
|---------|------|-------|
| check, paste | stdout | stderr |
| run, score, diff | stdout | stderr |
| receipt | stdout | stderr |
| scan | stdout | stderr |
| warnings | stdout | stdout |
| warnings --summary | n/a | stderr |
| checkpoint | stdout | stdout |
| fetch | stdout | stdout |
| explain | stdout | stdout |
| doctor | stdout | stdout |
| audit | stdout | stdout |

### Format flags

Most commands accept `--format human|json` (default: human).

| Scope | Valid formats |
|-------|-------------|
| Most commands | `--format human\|json` |
| scan | `--format human\|json\|sarif` |
| audit export | `--format json\|csv` |
| audit report | `--format markdown\|json\|html` |

Legacy `--json` is accepted on most JSON-capable commands.
`audit export` and `audit report` use `--format` only.

## MCP Tools

When running as an MCP server (`tirith mcp-server`), these tools are
available to AI agents:

| Tool | Description |
|------|-------------|
| `tirith_check_command` | Analyze shell commands for pipe-to-shell, homograph URLs, env injection |
| `tirith_check_url` | Score URLs for homograph attacks, punycode tricks, shortened URLs |
| `tirith_check_paste` | Check pasted content for ANSI escapes, bidi controls, zero-width chars |
| `tirith_scan_file` | Scan a file for hidden content, invisible Unicode, config poisoning |
| `tirith_scan_directory` | Recursive scan with AI config file prioritization |
| `tirith_verify_mcp_config` | Validate MCP configs for insecure servers, shell injection in args |
| `tirith_fetch_cloaking` | Detect server-side cloaking (different content for bots vs browsers) |

Register: `tirith setup claude-code --with-mcp`
Run manually: `tirith mcp-server` (JSON-RPC over stdio)

## Subcommand Reference

| Command | Purpose |
|---------|---------|
| `check` | Analyze a command before execution |
| `paste` | Check pasted content for threats |
| `run` | Safely download and execute a script (Unix) |
| `score` | Risk-score a URL |
| `diff` | Compare a URL against known-good patterns |
| `scan` | Scan files for hidden content and config poisoning |
| `fetch` | Detect server-side cloaking (Unix) |
| `why` | Explain the last triggered rule |
| `explain` | Show documentation for a detection rule |
| `setup` | Configure tirith for an AI coding tool |
| `init` | Generate shell hook source line |
| `doctor` | Diagnose installation and configuration |
| `policy` | Manage security policies (init, validate, test) |
| `audit` | Export verdicts, stats, and compliance reports |
| `trust` | Manage trusted patterns with TTL and rule scoping |
| `receipt` | Manage execution receipts from `tirith run` |
| `checkpoint` | File checkpoints for rollback before risky operations |
| `warnings` | Show accumulated session warnings |
| `threat-db` | Manage threat intelligence database |
| `gateway` | MCP gateway proxy for AI agent security |
| `mcp-server` | Run as MCP server (JSON-RPC over stdio) |
| `daemon` | Background daemon for faster checks |
| `license` | Show or manage license status |
| `activate` | Activate a license key |
