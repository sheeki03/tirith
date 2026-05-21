# Roadmap

This roadmap tracks what has shipped, what is in progress, and what is planned.
Priority and scope of unstarted work may change based on dogfooding feedback.

## Done

Shipped and available in the current release line (see [CHANGELOG.md](../CHANGELOG.md)).

- **Daemon mode (Unix)** — persistent background process for sub-millisecond
  hook latency, with network-aware URL checks. `tirith daemon start/stop/status`.
- **CI scanning with SARIF** — `tirith scan` exits non-zero in CI on a severity
  threshold and emits SARIF for GitHub Code Scanning.
- **GitHub Action** — `sheeki03/tirith@v1` wraps `tirith scan` for CI pipelines.
- **Pre-commit hook** — `.pre-commit-hooks.yaml` entry for local scanning.
- **`tirith policy init / validate / test`** — generate a starter policy,
  validate YAML syntax and conflicts, and dry-run a command or file against the
  active policy.
- **`tirith explain --rule <id>`** — detailed per-rule documentation, including
  examples and remediation, plus `--list` / `--category` filtering.
- **`tirith scan` include/exclude/profile filters** — `--include`, `--exclude`,
  and `--profile` (named profiles loaded from policy) for targeted scanning.
- **Per-session warning accumulator** — `tirith warnings` CLI command and
  shell exit summaries across all hooks.
- **Strict-warn mode** — `strict_warn` policy key / `--strict-warn` flag, with a
  dedicated `WarnAck` exit code (3) for the warn-ack hook protocol.

## Now

In progress — the current focus is shell-integration reliability and policy
discovery consistency.

- **Shell integration reliability** — fixing hook fragility across shells and
  versions. Bash "previous command not delivered"
  ([#111](https://github.com/sheeki03/tirith/issues/111)) is fixed: a
  capability self-test (run by `tirith setup` / `tirith doctor`) proves whether
  `bind -x` enter-mode delivery works for the running bash and caches the
  verdict; the hook reads the cache and uses enter mode only where proven, else
  falls back to preexec. Still tracking
  [#103](https://github.com/sheeki03/tirith/issues/103)
  (fish preexec/postexec functions not running).
- **Policy discovery consistency** — `tirith policy init` writes a file that
  `doctor` and `validate` then report as missing
  ([#112](https://github.com/sheeki03/tirith/issues/112)); fix is in
  [PR #113](https://github.com/sheeki03/tirith/pull/113).
- **Doctor compatibility diagnostics** — surfacing shell/terminal compatibility
  state more clearly in `tirith doctor`. `tirith doctor --simulate-enter`
  ships: it runs the bash enter-mode delivery self-test on demand and reports
  the verdict.

## Next

Planned, not yet started.

- **`tirith doctor --compat`** — a dedicated compatibility report covering the
  current shell, terminal, and prompt/history tooling.
- **Capability-based compatibility matrix** — classify each shell/terminal
  combination by the capabilities tirith actually needs, rather than by name.
  The bash enter-mode capability cache (issue #111) is the first instance.
- **Terminal / prompt / history-tool regression tests** — automated coverage
  for the integrations that historically break hook delivery.
- **Visible degraded-protection status indicator** — a clear, always-visible
  signal when a session has downgraded from blocking to warn-only.

## Later

Longer-horizon ideas, not yet scheduled.

- **IDE extension** — analyze terminal commands and inline URLs from inside an
  editor.
- **Custom rule SDK / DSL** — user-defined detection rules with custom severity
  and evidence, plus a rule testing framework.
- **Broader terminal-specific certification** — expanded, formalized
  compatibility guarantees across the terminal ecosystem.
