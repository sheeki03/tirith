# Policy Cookbook

## 0. Start From a Template

`tirith policy init --template <name>` writes a curated, well-commented,
schema-valid starter policy. It is the fastest way to a sensible baseline you
can then edit:

```bash
tirith policy init --template individual      # solo developer defaults
tirith policy init --template ci-strict       # fail-closed CI, no bypass
tirith policy init --template ai-agent-heavy  # heavy AI-agent environments
```

- **`individual`** — `fail_mode: open`, `paranoia: 1`, the noisy
  `shortened_url` rule escalated, an empty `allowlist` ready to fill in.
- **`ci-strict`** — `fail_mode: closed`, the `TIRITH=0` bypass disabled
  (interactive and non-interactive), `strict_warn: true`, remote-execution
  rules escalated to CRITICAL, and `scan.fail_on: high` so `tirith scan` fails
  the build.
- **`ai-agent-heavy`** — `fail_mode: open` (so an internal error cannot wedge
  an agent), `paranoia: 3`, the non-interactive bypass disabled, `approval_rules`
  for the highest-risk pipe-to-shell rules, and `escalation` rules that block
  on repeated warnings.

`tirith policy init` with no `--template` writes the full default policy.
The recipes below show hand-tuned variations on these baselines.

## 0b. Tune From Your Audit Log

Once tirith has some history, `tirith policy tune --from-audit` reads your
audit log and *suggests* conservative policy adjustments:

```bash
tirith policy tune --from-audit
tirith policy tune --from-audit --format json   # machine-readable
```

It is **suggest-only** — it never edits your policy. The headline suggestion
is a rule you allowed or bypassed *every* time and *never* blocked: that rule
is probably firing on something you trust, so an `allowlist` entry or a
`severity_overrides` downgrade may be warranted. A rule you *sometimes* block
on is never suggested for a downgrade — it is doing its job. Every suggestion
is a plain count from the log, not an inference; when the log is too small to
be meaningful, `policy tune` says so rather than guessing. Review each
suggestion, then apply it by hand to `.tirith/policy.yaml`.

## 1. Strict Organization (Fail Closed, No Bypass)

```yaml
# .tirith/policy.yaml (repo root)
fail_mode: closed
allow_bypass_env: false
severity_overrides:
  shortened_url: HIGH
  plain_http_to_sink: CRITICAL
```

All findings block execution. No bypass mechanism. Shortened URLs and plain HTTP are escalated.

## 2. Personal Developer (Defaults + Allowlist)

```yaml
# ~/.config/tirith/policy.yaml
fail_mode: open
allow_bypass_env: true
```

With allowlist at `~/.config/tirith/allowlist`:
```
raw.githubusercontent.com
homebrew.bintray.com
get.docker.com
```

Default severity mappings. Allowlisted URLs skip analysis.

## 3. CI Safe Mode (Non-Interactive, JSON Output)

```bash
# In CI pipeline
tirith check --non-interactive --format json -- curl https://example.com/setup.sh | bash
EXIT=$?
if [ $EXIT -eq 1 ]; then
  echo "BLOCKED by tirith" >&2
  exit 1
fi
```

Non-interactive mode never prompts. JSON output for machine parsing.

## 4. Docker-Focused (Escalate Docker Rules)

```yaml
# .tirith/policy.yaml
severity_overrides:
  docker_untrusted_registry: CRITICAL
  docker_tag_latest: HIGH
```

All Docker-related findings are escalated. Other rules use default severity.

## 5. Learning Mode (All Low Severity)

```yaml
# ~/.config/tirith/policy.yaml
fail_mode: open
allow_bypass_env: true
severity_overrides:
  curl_pipe_shell: LOW
  wget_pipe_shell: LOW
  pipe_to_interpreter: LOW
  punycode_domain: LOW
  confusable_domain: LOW
```

Everything becomes a LOW-severity warning. Nothing blocks. Useful for onboarding.

## 6. cargo-vet (Rust Supply-Chain Audit)

tirith detects when `cargo install` or `cargo add` is run in a project that
hasn't configured [cargo-vet](https://mozilla.github.io/cargo-vet/). The
`vet_not_configured` rule fires at LOW severity by default. To escalate:

```yaml
# .tirith/policy.yaml
severity_overrides:
  vet_not_configured: HIGH
```

To suppress it (e.g. for non-Rust repos):

```
# ~/.config/tirith/allowlist
# or .tirith/allowlist
vet_not_configured
```

## 7. vet (getvet.sh) — Safe Pipe-to-Shell

When tirith blocks a `curl | bash` pattern, the safest alternatives are:

### Ask tirith for a verified rewrite or guidance

`tirith check --suggest` prints remediation for the exact command
you ran and, when a narrow mechanical transform can be verified, a concrete
safer version:

```bash
tirith check --suggest -- 'curl -fsSL https://example.com/install.sh | bash'
# tirith: safer alternative
#   curl_pipe_shell
#     try: '/usr/local/bin/tirith' run --capsule --script-stdin --interpreter bash \
#          'https://example.com/install.sh'
```

On x86_64 Linux, a fixed root-managed current Tirith binary may emit this
rewrite. The generated command uses Tirith's absolute path so a later `PATH`
shadow cannot replace it. At execution, the runner requires the selected
interpreter's first `PATH` hit to be root-managed, binds its bytes before the
download, bounds and analyzes the downloaded bytes, asks for confirmation, then
feeds the reviewed bytes to a hash-verified, sealed interpreter descriptor
inside a fail-closed capsule. It also ignores a conflicting remote shebang.
Other architectures, platforms, and user-owned Tirith installations show
guidance instead of an executable rewrite. Curl rewrites require both
`-f`/`--fail` and
`-L`/`--location` semantics;
plain curl, `-f` alone, or `-L` alone stays guidance-only.
Literal no-argument `sh`, `bash`, `zsh`, `dash`, `ksh`, `fish`, and
`ash` are supported, as is the narrow POSIX-shell `-s -- <literal operands...>`
form. Dynamic or malformed URL tokens, controls, PowerShell, Cmd, `|&`, and
unsupported downloader/interpreter arguments produce guidance rather than an
executable rewrite. Executable suggestions are limited to the verified,
fail-closed pipe runner. Archive, dotfile, insecure-TLS removal, HTTP-to-HTTPS
changes, sudo narrowing, environment scrubbing, and package-name
corrections remain guidance-only because Tirith cannot mechanically prove the
required semantics. The flag is advisory — it never changes the verdict or exit
code.

### Using tirith run (inspection on Unix; live execution on Linux)

`tirith run` downloads and analyzes the script. On Linux, live mode prompts and
executes the exact reviewed bytes from a fully sealed anonymous descriptor; on
other hosts it refuses live mode before download. A manual invocation uses the
fully analyzed remote shebang and file semantics;
use the command emitted by `check --suggest` when preserving an original stdin
pipeline matters:

```bash
tirith run https://example.com/install.sh
```

Download and inspect only (no execution):

```bash
tirith run --no-exec https://example.com/install.sh
```

Pin to a known hash:

```bash
tirith run --sha256 abc123... https://example.com/install.sh
```

There is no pager step in `tirith run`; live execution is contained and fail-closed by default.
Use `--no-exec` to stop after analysis, or `tirith fetch <url> --save <path>` for explicit file review.
`--capsule` remains accepted as a legacy spelling but does not change that default. Download and DNS resolution
happen before the interpreter capsule, so containment is not a separate claim
about the pre-execution resolver path.

### Using tirith install (recorded install transaction)

`tirith install` wraps a real package install with pre-execution
supply-chain risk analysis and records the transaction. It analyzes first,
presents a verdict, takes a working-directory checkpoint and an audit entry,
then runs the real `npm install` / `pip install` / `cargo install` (or the
downloaded script for the `url` form) only after the analysis and your
go-ahead:

```bash
# Instead of: npm install left-pad
tirith install npm left-pad
```

A block refuses the install (bypassable per policy with `TIRITH=0`); a warn
asks for acknowledgement; an allow proceeds. tirith's own flags go *before*
the source — everything after the source is passed verbatim to the package
manager:

```bash
# --online adds registry-API provenance signals; --save-dev goes to npm
tirith install --online npm some-pkg --save-dev

# Analyze and record only — do not run the real install
tirith install --no-exec pip requests

# Proceed past warnings without the interactive prompt
tirith install --yes cargo ripgrep

# The url form delegates to `tirith run`'s safe download-and-run machinery
tirith install url https://get.example-tool.sh
```

`tirith install` package-manager forms are pre-execution install-**risk
analysis** plus a recorded transaction. They do **not** sandbox or isolate the
package-manager process, which runs with your full privileges. The checkpoint
is a before/after record (`tirith checkpoint diff <id>`), not an automatic
rollback. The `url` form is different: reviewed script bytes use Tirith's
contained runner and fail closed when the required containment is unavailable.

### Using vet (external, cross-platform)

[vet](https://getvet.sh) is an external tool for safer remote-script workflows (see getvet.sh for details):

```bash
# Instead of: curl -fsSL https://example.com/install.sh | bash
vet https://example.com/install.sh
```

Both approaches ensure you can inspect the script before it runs.

### Policy: suppress pipe-to-shell for trusted sources

If you routinely install from trusted URLs, allowlist them instead of bypassing:

```yaml
# .tirith/policy.yaml
allowlist:
  - "get.docker.com"
  - "raw.githubusercontent.com/org/repo"
```

### CLI: manage trust without editing YAML

`tirith trust` does the same thing from the command line, and steers you
toward the narrowest scope that works. Trusting a specific path is accepted
as-is; trusting a whole domain is broad and must be opted into with `--broad`.
Entries expire after 30 days by default, so a temporary allow does not linger.

```bash
# Narrow: trust one exact HTTPS resource. Expires in 30 days.
# Schemeless host/path patterns are normalized as HTTPS.
tirith trust add raw.githubusercontent.com/org/repo/main/get.sh

# Broad: trust a whole domain for one rule only. --broad is required.
tirith trust add get.docker.com --broad --rule curl_pipe_shell

tirith trust list                 # see every entry, its scope, and its TTL
tirith trust explain get.docker.com
tirith trust diff                 # what changed since last time
tirith trust gc --expired         # remove entries whose TTL has passed
```

Use `--permanent` if an entry genuinely should never expire, and `--reason`
to record why it was added — `tirith trust explain` shows it back to you.

## 8. Web3 Guard (Foundry / Hardhat / Solana / Anchor)

Both keys below are **grant-bearing**, so they only take effect from a user or
org policy. A checked-in `.tirith/policy.yaml` that declares them has them
dropped, and `tirith policy effective` names what it dropped.

```yaml
# ~/.config/tirith/policy.yaml
web3_guard:
  networks:
    - name: ethereum-mainnet
      family: evm
      identity:
        evm_chain_id: 1          # chain identity, so a fork cannot reuse a name
      endpoints:
        - scheme: https
          host: eth-mainnet.example-rpc.invalid
          subdomains: exact_host # widening to subdomains is a written decision
  allowed_signers: [hardware_wallet, keystore_file]
  deny_rpc:
    - scheme: https
      host: rpc.untrusted.invalid
      subdomains: host_and_subdomains
  action_unclassified_rpc: warn
```

Defaults are observational: with no `networks` declared, the
unclassified-endpoint path does not fire at all, so adding the section is what
turns endpoint checking on. `allowed_signers` has no spelling for a raw private
key, keypair, or mnemonic, by design.

Verify what a repository policy is allowed to contribute:

```bash
tirith policy effective   # prints the merged policy plus a "Neutralized (...)" line
```

A repo policy carrying `web3_guard.networks` and `web3_guard.allowed_signers`
prints them as neutralized while keeping its `deny_rpc` and `deny_destinations`
entries, because denial is the only direction a repository may move.

Note that surviving the merge is not the same as being enforced. Of the
`web3_guard` fields, only `networks`, `allowed_signers`, `deny_rpc`, and
`action_unclassified_rpc` are read by a rule. `deny_destinations`,
`require_command_card`, `command_card_key_ids`, `selector_aliases`,
`action_incomplete_analysis`, and `action_ambiguous_hardhat_production_run` are
parsed, validated, and merged, but no rule consults them, so a destination
listed in `deny_destinations` is not flagged. See
[web3-command-guard.md](security/web3-command-guard.md#declared-but-not-yet-wired).

## 9. Untrusted-Task Gate (observation first)

Start in `observe`. It decides without withholding, and an `off` gate does not
even write an audit line. Be aware that only the `gateway_forward` boundary
actually writes a record: the other eight decide and write nothing in any mode,
so an observation burn-in cannot measure them.

```yaml
# ~/.config/tirith/policy.yaml
task_gate:
  mode: observe
```

Once the incomplete rate is understood, express enforcement through the denied
effect set:

```yaml
task_gate:
  mode: enforce
  effects_denied_for_untrusted_sources: [policy_change, package_install]
  action_incomplete_analysis: warn   # see both notes below
```

**That denied-effect set applies to YOUR commands too.** Every tirith-owned
boundary reports its source as unattributed and untrusted, so the effect is
denied on every call. With the snippet above, `tirith pkg approve` and
`tirith policy init` both refuse. Under `mode: observe` they do not. Enable it
knowing that.

**`action_incomplete_analysis: block` is narrower than it sounds.** Task effect
inference models the Web3 shell grammar and nothing else, so nearly every
ordinary SHELL command is reported incomplete. But package-install and
config-write envelopes always assess as complete, so `block` refuses unmodelled
shell at five of the nine boundaries (`capsule_preset_run`, `gateway_forward`,
`remote_script_run`, `package_manager_network`, and
`package_manager_execution`) and changes nothing at `pkg approve`, the two
`pkg install` stages, or config writes. `warn`
is the conservative default; `block` is a real option once you have measured
your own incomplete rate on those five.

Unlike `web3_guard`, every `task_gate` field is restriction-shaped, so a
repository may tighten all of them. A repo policy that tries to LOOSEN the mode
is refused and reported as neutralized.

Try an envelope against the policy without running anything:

```bash
tirith task check --file envelope.json --adapter github-issue --format json
```

See [task-envelope.md](task-envelope.md) for the envelope format and the nine
transitions the gate actually enforces at.
