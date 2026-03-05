# Policy Cookbook

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
tirith check --non-interactive --json -- curl https://example.com/setup.sh | bash
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
