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

### Ask tirith for the rewrite

`tirith check --suggest-safe-command` prints a concrete safer version of the
exact command you ran:

```bash
tirith check --suggest-safe-command -- 'curl https://example.com/install.sh | bash'
# tirith: safer alternative
#   curl_pipe_shell
#     try: curl -fsSL -o /tmp/tirith-review.sh https://example.com/install.sh \
#          && less /tmp/tirith-review.sh && bash /tmp/tirith-review.sh
```

It also drops insecure-TLS flags and upgrades `http://` to `https://`. For
findings with no safe mechanical rewrite it says so plainly instead of guessing.
The flag is advisory — it never changes the verdict or exit code. Use
`tirith explain --rule curl_pipe_shell --fix` to see a rule's remediation on its
own.

### Using tirith run (built-in, Unix only)

`tirith run` downloads, inspects, and prompts before executing:

```bash
# Instead of: curl -fsSL https://example.com/install.sh | bash
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
# Narrow: trust one exact resource. Expires in 30 days.
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
