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

## 6. Cargo Vet Supply-Chain Audit

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

## 7. Safer Pipe-to-Shell with `vet`

[vet](https://getvet.sh) is a command-line tool that acts as a safety net for the risky `curl | bash` pattern. It downloads the script, lints it with ShellCheck, and prompts before execution.

You have two ways to use `vet` with tirith:

### Option A: Automatic wrapping in `tirith run`

When you use `tirith run https://example.com/install.sh`, tirith normally downloads the script, analyzes it, and prompts you to execute it. You can configure tirith to automatically hand over execution to `vet` instead.

```yaml
# ~/.config/tirith/policy.yaml
use_vet_runner: true
```

If `vet` is installed and this is enabled, `tirith run` will download the script, perform tirith's static analysis, and then run `vet <cached_script_path>` to provide its interactive diff and execution guard.

### Option B: Using `vet` directly in the pipeline

tirith allows executing `curl | vet` out-of-the-box without blocking, because `vet` isn't blindly executing the script.
```bash
$ curl -sSL https://example.com/install.sh | vet
```
