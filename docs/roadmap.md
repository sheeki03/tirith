# Roadmap

This roadmap tracks what has shipped, what is in progress, and what is planned.
Priority and scope of unstarted work may change based on dogfooding feedback.

The [capability matrix](capability-matrix.md) is the per-command companion to
this roadmap: it records, for every command, whether tirith inspects the bytes
it acts on and whether the active policy can fully govern that surface. It is
generated from the versioned [`capability-manifest.toml`](capability-manifest.toml)
and kept honest by a CI test.

## Done

Shipped and available in the current release line (see [CHANGELOG.md](../CHANGELOG.md)).

- **Daemon mode (Unix)**: persistent background process for sub-millisecond
  hook latency, with network-aware URL checks. `tirith daemon start/stop/status`.
- **CI scanning with SARIF**: `tirith scan` exits non-zero in CI on a severity
  threshold and emits SARIF for GitHub Code Scanning.
- **GitHub Action**: `sheeki03/tirith@v1` wraps `tirith scan` for CI pipelines.
- **Pre-commit hook**: `.pre-commit-hooks.yaml` entry for local scanning.
- **`tirith policy init / validate / test`**: generate a starter policy,
  validate YAML syntax and conflicts, and dry-run a command or file against the
  active policy. `tirith policy init --template <name>` offers curated starter
  policies (`individual`, `ci-strict`, and `ai-agent-heavy`), each a
  well-commented, schema-valid policy.
- **`tirith explain --rule <id>`**: detailed per-rule documentation, including
  examples and remediation, plus `--list` / `--category` filtering.
- **`tirith scan` include/exclude/profile filters**: `--include`, `--exclude`,
  and `--profile` (named profiles loaded from policy) for targeted scanning.
- **Per-session warning accumulator**: `tirith warnings` CLI command and
  shell exit summaries across all hooks.
- **Strict-warn mode**: `strict_warn` policy key / `--strict-warn` flag, with a
  dedicated `WarnAck` exit code (3) for the warn-ack hook protocol.
- **IDE / editor integration (LSP)**: `tirith lsp` runs a language server over
  stdio that surfaces tirith diagnostics inline in an editor, analyzing buffer
  contents and inline URLs through the detection engine.
- **Custom rule DSL**: user-defined detection rules under `custom_rules:` in
  `.tirith/policy.yaml`, each carrying either a `pattern:` regex or a `when:`
  semantic-predicate clause, with `tirith rule test / validate / explain` as the
  authoring and testing surface.
- **Offline mode for the hot path**: `tirith check --offline` and the
  `TIRITH_OFFLINE` environment variable, an opt-in switch that suppresses the
  periodic background threat-DB refresh so `check` runs purely locally. This is
  a mechanism only; the online default is unchanged.
- **Android / Termux support**: Termux runs on Bionic libc, so the
  `aarch64-unknown-linux-musl` static build is the supported artifact; the
  release workflow builds it and smoke-tests it (static-linkage check plus
  `--version` and a block check under QEMU user emulation). Install docs are in
  the README. Continuous verification on a real Android device is still future
  work, gated on device-backed CI.
- **Visible degraded-protection indicator**: when a shell hook downgrades
  protection (for example bash enter mode to preexec warn-only), the hook emits
  one consolidated one-shot message and sets a non-exported `TIRITH_STATUS`
  shell variable (`blocks` / `warn-only` / `degraded` / `off`) that a user can
  wire into their prompt; `tirith doctor` calls out a degraded session
  explicitly. tirith adds no per-prompt output of its own.
- **Doctor compatibility diagnostics**: `tirith doctor --simulate-enter` runs
  the bash enter-mode delivery self-test on demand; `tirith doctor --compat` is
  a dedicated, static shell/terminal compatibility report (human + `--format
  json`) covering the detected shell, requested-vs-effective bash mode, install
  checks, and best-effort detection of co-installed hook-interacting tools.
- **`tirith doctor` troubleshooting bundle**: `tirith doctor --bundle`
  (aliases `--redacted-report`, `--shell-trace`), a redacted diagnostic bundle
  (doctor info, versions, shell/mode/protection, hook chain, policy discovery,
  threat-DB status, curated environment) safe to attach to a bug report.

## Now

In progress. The current focus is shell-integration reliability and policy
discovery consistency.

- **Shell integration reliability**: fixing hook fragility across shells and
  versions. Bash "previous command not delivered"
  ([#111](https://github.com/sheeki03/tirith/issues/111)) is fixed: a
  capability self-test (run by `tirith setup` / `tirith doctor`) proves whether
  `bind -x` enter-mode delivery works for the running bash and caches the
  verdict; the hook reads the cache and uses enter mode only where proven, else
  falls back to preexec. Still tracking
  [#103](https://github.com/sheeki03/tirith/issues/103)
  (fish preexec/postexec functions not running).
- **Policy discovery consistency**: `tirith policy init` writes a file that
  `doctor` and `validate` then report as missing
  ([#112](https://github.com/sheeki03/tirith/issues/112)); fix is in
  [PR #113](https://github.com/sheeki03/tirith/pull/113).

## Next

Planned, not yet started.

- **Capability-based compatibility matrix**: classify each shell/terminal
  combination by the capabilities tirith actually needs, rather than by name.
  The bash enter-mode capability cache (issue #111) is the first instance. This
  extends the per-command [capability matrix](capability-matrix.md) down to the
  shell/terminal axis.
- **Terminal / prompt / history-tool regression tests**: automated coverage
  for the integrations that historically break hook delivery.

## Later

Longer-horizon ideas, not yet scheduled.

- **Broader terminal-specific certification**: expanded, formalized
  compatibility guarantees across the terminal ecosystem.
