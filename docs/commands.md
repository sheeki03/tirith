# Command reference

tirith ships 74 commands. `tirith --help` prints this same list grouped by
category, and `tirith <command> --help` documents any one in detail. The groups
below mirror that built-in grouping. The [README](../README.md) covers the
everyday subset; this is the complete reference.

## Scan & analyze

| Command | What it does |
|---------|-------------|
| `tirith check -- <cmd>` | Analyze a command without executing it (`--suggest` adds remediation and, only when fully verified on x86_64 Linux with the current Tirith binary at a fixed root-managed path, a typed pipe-runner command; `--defer` records a non-critical block as pending and exits 4 instead of blocking) |
| `tirith paste` | Check pasted content (called by shell hooks; `--with-source` attributes the paste to its recorded clipboard origin) |
| `tirith scan [path]` | Scan files, directories, and configs (`--include`, `--exclude`, `--profile`, `--format sarif`, `--ci`) |
| `tirith run [--capsule] <url>` | Inspect a remote script (`--no-exec` on Unix); Linux live execution is contained and fail-closed by default and executes exact reviewed bytes from a sealed anonymous descriptor (`--capsule` is legacy-compatible) |
| `tirith fix -- <cmd>` | On x86_64 Linux with the current Tirith binary at a fixed root-managed path, interactively apply a fully verified typed pipe-runner command when available; all other findings remain guidance-only, and an accepted command prints to stdout for `$(tirith fix ...)` |
| `tirith view [file]` | Safe pager that neutralizes terminal-deception escape sequences before they reach your terminal |
| `tirith score <url>` | Break down a URL's trust signals (`--explain` for the factor-by-factor derivation) |
| `tirith diff <url>` | Byte-level view of where suspicious characters hide |
| `tirith fetch <url>` | Detect server-side cloaking; `--save <path>` downloads without executing and marks the file tainted (Unix) |
| `tirith preview -- <cmd>` | Simulate the filesystem blast radius of `rm` / `mv` / `chmod -R` / `rsync --delete` without running it |
| `tirith watch -- <cmd>` | Run a command, then diff its filesystem, `$PATH`, and shell-rc impact |
| `tirith temp-run -- <cmd>` | Run a command in a throwaway temp directory and diff its file impact (file isolation, not a sandbox) |
| `tirith capsule run --preset untrusted-project --project <dir> -- <cmd>` | Copy an untrusted project into a held ephemeral directory and run an exact argv inside a fail-closed OS capsule, emitting a signed receipt. Enforceable on x86_64 Linux only; every other host refuses before anything is copied or spawned, and there is no degraded fallback |
| `tirith taint {list,explain,clear}` | Track files downloaded from risky sources; executing or sourcing a tainted file fires a finding |
| `tirith intend "<intent>" -- <cmd>` | Flag high-impact behavior the stated intent does not justify (advisory) |
| `tirith lab` | Run the detection engine against a curated adversarial corpus to see what it catches (`--filter`, `--score`) |
| `tirith explain --rule <id>` | Rule docs, examples, remediation, and MITRE mapping (`--fix`, `--list --category`) |
| `tirith why` | Explain the last rule that triggered |
| `tirith visual-audit` | Test whether your terminal and font can distinguish confusable glyph pairs |

## Status & health

| Command | What it does |
|---------|-------------|
| `tirith status` | "Am I protected?": protection mode, hook health, active policy, threat-DB freshness; exits non-zero when protection is provably reduced (`--json`) |
| `tirith doctor` | Diagnose install / hooks / policy. `--fix` auto-fixes, `--compat` is a shell/terminal report, `--quick` is a fast pollable snapshot (`--format json`) |
| `tirith prompt-status` | One-line protection and active-context indicator for your prompt (`--short`, `--json`; 30s cache) |
| `tirith dashboard {export,serve}` | Local-only HTML security dashboard from your audit log, policy, and trust store (`serve` binds loopback with an ephemeral token) |
| `tirith warnings` | Session warnings (`--summary` for shell exit hooks, `--clear`, `--format json`) |
| `tirith receipt {last,list,verify}` | Track and verify scripts run through `tirith run` |
| `tirith logs {scan,summarize,redact}` | Review agent / CLI logs for injection seeds, secrets, and escape bytes (`summarize --safe-for-agent`) |
| `tirith baseline {learn,status,reset}` | Opt-in per-user anomaly baseline (off by default) |

## Setup & onboarding

| Command | What it does |
|---------|-------------|
| `tirith init` | Print the shell hook for your profile (`--prompt-status` adds the prompt snippet) |
| `tirith onboard` | Guided first-run wizard: detect the environment and recommend a policy template (`--apply`) |
| `tirith setup <tool>` | One-command AI-tool setup (claude-code, codex, cursor, and more; `--with-mcp`) |
| `tirith install <backend> <args>` | Recorded, risk-analyzed install across npm / pip / cargo / apt / brew / dnf / yum / pacman / scoop / docker / go / url (`--online`, `--no-exec`, `--yes`, `--sha256`) |
| `tirith verify-self` / `update` / `version --provenance` | Verify the running binary, signature-verified self-update, and build / install provenance |
| `tirith browser {host,install-extension}` | Install the Chrome native-messaging host that records clipboard provenance |
| `tirith browser audit` | Read-only integrity audit of installed Chromium-family extensions: tree digests, permissions, execution surfaces, install class, provenance, and drift against a baseline receipt (`--browser`, `--profile`, `--baseline`, `--write-baseline`) |
| `tirith devcontainer {guard,inject}` / `codespaces {setup,inject}` | Guard container operations and inject tirith into `devcontainer.json` |
| `tirith activate <key>` / `tirith license` | Activate a commercial license key, or show and manage license status |

## Policy, trust & rule authoring

| Command | What it does |
|---------|-------------|
| `tirith policy {init,validate,test,tune,effective}` | Scaffold (`--template`), validate, dry-run, suggest from audit, and show the resolved effective policy with any neutralized repo fields |
| `tirith trust {add,list,explain,diff,remove,gc,last,from-last-trigger}` | Manage trusted patterns (narrow scope, 30-day TTL by default); `from-last-trigger` turns a block into a targeted trust |
| `tirith rule {test,validate,explain}` | Author and test custom detection rules (regex or the `when:` semantic DSL) |
| `tirith output wrap {on,off,status}` | Install or remove the `tirith-out` wrapper that runs a command's output through `tirith view` |

## Shell & system guards

| Command | What it does |
|---------|-------------|
| `tirith daemon {start,stop}` | Background daemon for faster checks and network enrichment (`start --detach`, Unix) |
| `tirith hooks {scan,guard,explain}` | Inventory and classify git / husky / lefthook / pre-commit hooks |
| `tirith exec {check,provenance,guard}` | Report a binary's package owner, signature, permissions, and whether it shadows a system command |
| `tirith env {guard,diff,explain}` | Monitor sensitive env-var lifecycle (values are never stored) |
| `tirith path {audit,watch,which}` | Flag PATH-hijack risk (repo-local, `/tmp`, or writable-before-system directories) |
| `tirith sudo {guard,session,require-reason}` | Sudo-escalation gates with a reasoned session window |
| `tirith ssh {guard,label}` | Label SSH hosts; destructive commands on a labeled-prod host escalate |
| `tirith context {status,guard,label}` | Label and guard active cloud / k8s contexts (prod-destructive escalation) |
| `tirith persistence {scan,diff,watch}` | Inventory and diff persistence footholds (rc files, authorized_keys, crontab, LaunchAgents) |
| `tirith hygiene {scan,fix}` | Scan `~/.ssh`, `~/.aws`, `~/.kube`, `.npmrc`, and more for loose permissions or plaintext tokens (`fix` is chmod-only) |
| `tirith aliases {scan,explain}` | Detect aliases that shadow critical commands, call the network, or read credentials |

## Supply-chain

| Command | What it does |
|---------|-------------|
| `tirith package {risk,explain,scan}` | Score a package's supply-chain risk (offline by default; `--online` adds registry provenance; `--installed` walks installed trees) |
| `tirith ecosystem scan [path]` | Score every declared dependency in a project, slopsquat-aware (`--installed`, `--online`, `--format json`) |
| `tirith threat-db {update,status,health,sources,explain,diff}` | Manage the signed local threat database (`threatdb` is an alias) |
| `tirith iac {guard,check-plan,require-plan-before-apply}` | Terraform / Pulumi / OpenTofu apply gates (saved-plan hash, no-plan-apply) |
| `tirith canary {create,status,list,prune,rotate}` | Plant synthetic honeytokens; a touch fires `canary_token_touched` |
| `tirith secret {triage,rotate,revoke}` | Guidance-only secret-rotation assistant for 11 providers (no network) |
| `tirith command-card {create,sign,verify,fetch}` | Ed25519-signed attestations that a known-good command is what it claims |
| `tirith commands {init,list,run,check}` | Repo command manifest (`.tirith/commands.yaml`): a bounded allowlist plus an elevation-only `dangerous[]` list |

## AI-agent integrations

| Command | What it does |
|---------|-------------|
| `tirith mcp-server` | Run tirith as an MCP server (7 tools) over JSON-RPC stdio (`--sanitize-tool-output`) |
| `tirith mcp {lock,verify,diff,explain,permissions,policy}` | Inventory and gate a repo's MCP servers into `.tirith/mcp.lock`, with per-server tool and per-capability views |
| `tirith gateway run` | MCP gateway proxy that intercepts AI-agent shell tool calls (`--filter-output`) |
| `tirith agent {sessions,explain,current,allow,block,policy}` | Caller-origin (human / agent / MCP / CI / IDE) governance; an `agent_rules.deny` match forces a block |
| `tirith ai {scan,diff,quarantine,explain-config,snapshot}` | AI-config workflow: scan, snapshot, detect drift or poisoning, and quarantine a suspect file |
| `tirith lsp` | Language server that surfaces tirith diagnostics inline in your editor |

## Forensics & response

| Command | What it does |
|---------|-------------|
| `tirith audit {export,stats,report,verify}` | Audit-log management; `verify` checks the tamper-evident hash chain (`--expected-head`) |
| `tirith incident {start,stop,status,report}` | Declare an "under attack" posture: fail-closed, bypass disabled, key rules elevated |
| `tirith checkpoint {create,list,restore,diff,purge,watch}` | Snapshot files before risky operations in the private per-user state directory; `restore` sha256-verifies each blob and reports per-file outcomes. Releases before 0.3.4 may have left data under `/tmp/tirith/checkpoints`; inspect and remove that legacy directory manually. |
| `tirith pending {list,resolve,export}` | Pending-decision registry for deferred blocks, suppressed-finding rollups, and restore prompts |
| `tirith share --target <a>` / `tirith redact --audience <a>` | Audience-aware redaction before sharing (github-issue, slack, llm, public-paste) |
| `tirith clipboard {copy,scan,guard,watch}` | Clipboard with secret-shape gating and browser source attribution |
