# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Trust / allowlist UX — narrow by default, expiring by default, and transparent** — `tirith trust` no longer makes it easy to grant a broad, permanent allow by accident. (1) **Narrow-trust-by-default**: `trust add` classifies the pattern's scope — `exact` (a specific URL or path), `substring`, `domain` (a whole host and every subdomain), `wildcard` (`*.host`), or `bare-TLD` (`com`, `dev`) — and a *broad* pattern (domain / wildcard / bare-TLD) is now **refused** unless the caller passes an explicit `--broad`; an exact URL or path is still accepted as-is. The error tells the user to trust the narrowest thing that works, and a bare TLD gets an extra "this allows EVERY host under `.com`" warning. (2) **Default TTLs**: a `trust add` with neither `--ttl` nor the new `--permanent` flag now gets a 30-day TTL, so stale trust expires on its own; `--permanent` is the explicit opt-out and is mutually exclusive with `--ttl`. (3) **Scope visualization**: `trust list` shows each entry's scope class in a new `SCOPE` column, marks a dangerously broad entry (wildcard / bare-TLD) with a `!`, and renders TTLs as a friendly `(in 6d)` / `permanent`; `--format json` carries `scope_kind`, `scope_coverage`, and `broad_warning` per row. (4) **`tirith trust explain <pattern>`** — explains a single entry: its scope and what it covers, the rule it is scoped to (or "global"), when it was added, the free-text reason it was added (a new optional `--reason` flag on `trust add`, recorded in `trust.json`), and when it expires; for a pattern that is *not* trusted it explains what scope it *would* get. (5) **`tirith trust diff`** — shows what changed in the trust set (entries added / removed) since the previous observation; the trust commands opportunistically record a small, bounded snapshot of the trust set into `~/.local/state/tirith/trust-history.jsonl` so a diff trail accrues over time. (6) **`tirith trust gc --expired`** — the expired-entry garbage collector now takes an explicit `--expired` flag and supports `--format json`. All of this is backward-compatible: the `trust.json` schema only *gains* an optional `reason` field, an existing trust store written by an older tirith loads unchanged, and an entry with no TTL — every pre-existing entry and every `--permanent` entry — is treated as permanent and is never expired or garbage-collected. The engine's hot-path trust loader is untouched and still reads old and new stores alike.
- **Remediation — "what to run instead"** — a tirith finding no longer only says a command is dangerous, it tells you how to make it safe. (1) Every `RuleId` now has a per-rule remediation string — a short, accurate "what to do instead" line — exposed programmatically via a new build-time-generated `rule_explanations::remediation(RuleId)` lookup (single source of truth: `assets/data/rule_explanations.toml`, the same file `tirith explain` already reads). The remediation is surfaced under each finding in the normal `tirith check` output as a `Fix:` line, and as a `remediation` field on each finding in `--format json`. The on-disk `Finding` struct is unchanged — the JSON `remediation` is added through a serialization view, so SARIF, audit logs, and last-trigger output are untouched. (2) `tirith explain --rule <id> --fix` prints just that rule's remediation (human and `--format json`); `--fix` requires `--rule` and is not valid with `--list`. (3) `tirith check --suggest-safe-command` — when a command is blocked or warned, prints a concrete safer rewrite of the *actual* command, but only where a transformation is genuinely safer and mechanically correct: pipe-to-shell (`curl URL | bash`) becomes a download-review-run sequence (`curl -fsSL -o /tmp/tirith-review.sh URL && less … && bash …`); an insecure-TLS flag (`-k` / `--insecure` / `--no-check-certificate`) is dropped; a plain `http://` URL is switched to `https://` with an explicit "verify the host serves HTTPS" caveat. For findings with no safe mechanical rewrite (homograph hostnames, archive-extract targets, threat-DB hits, …) it says so plainly and shows the remediation instead — it never emits a bogus suggestion, and an ambiguous pipeline (extra stages, no clear single URL) yields no rewrite rather than a possibly-wrong one. `--suggest-safe-command` is advisory: it changes neither the verdict nor the exit code, and in `--format json` the rewrites appear under a top-level `safe_suggestions` array. This is incremental — remediation is populated for every rule that has a clear safer path; accuracy is prioritized over coverage.
- **Threat-DB transparency — `tirith threat-db explain | sources | health | diff`** — four additive read-only subcommands so a user can understand and trust the local threat database. They never download, never write the DB, and never change existing `update`/`status` behavior; all support `--format json`. `threat-db explain <indicator>` looks up a domain, package (`name`, `ecosystem:name`, or `name@version`), or IPv4 address and reports whether the DB knows it, the matching classification (malicious package / typosquat / popular-lookalike / malicious hostname / malicious IP), the flagging source, and confidence — and says so plainly when the indicator is absent, with the caveat that absence is not a safety guarantee. `threat-db sources` lists every threat-intelligence feed the DB is built from, grouped into primary (the signed CI database) and supplemental (the optional user-local overlay), with the upstream project URL and live per-source record counts walked from the loaded DB. `threat-db health` reports install state, Ed25519 signature validity, age and staleness against the configured `auto_update_hours` refresh interval, per-category entry counts, supplemental-overlay presence, and any load error, with a one-word `status` (`ok` / `stale` / `not_installed` / `error`). `threat-db diff --since <version-or-date>` summarizes what changed since a DB build sequence or ISO date. The DB binary format retains no per-entry history, so `diff` honestly reports category and per-source **count** deltas between snapshots — not the exact entries added or removed — and states that limitation prominently; the transparency commands opportunistically record a small, bounded snapshot of the current DB (version, build time, counts) into `~/.local/state/tirith/threatdb-history.jsonl` so a usable diff trail accrues over time. The canonical CLI spelling is `threat-db`; `threatdb` continues to work as an alias.
- **Scoring calibration — `tirith score --explain` and `tirith policy tune --from-audit`** — the risk score is now fully explainable, and tirith can read your audit log back to you as conservative policy advice. tirith's scoring stays deterministic and inspectable: there is no model, no learned weights, no statistical classifier — every score is a fixed sum of named factors, reproducible by hand. (1) **`tirith score <url> --explain`** prints the exact factor-by-factor derivation of the score: a *base-severity* factor (the single highest-severity finding sets the floor — `Critical` 90 / `High` 70 / `Medium` 40 / `Low` 15), an *additional-findings* factor (+5 for each finding past the first), and — when it applies — a *threat-intel corroboration* factor (+5 when a local threat-DB rule fired alongside other findings, an unambiguous external confirmation). Each factor shows its point contribution, a running total, and a plain-language reason; the factors sum *exactly* to the displayed score, and a test asserts that invariant for a wide input range. The breakdown is opt-in: without `--explain` the `score` JSON is byte-compatible with before, and with it a `score_breakdown` object is added. The base and additional-findings factors reproduce the historical `score` formula exactly, so no pre-existing score changed; the threat-intel factor is the only new term and is purely additive — it never fires on its own and never changes a verdict, exit code, or audit log (`score` is an inspection command, not an enforcement path). (2) **`tirith policy tune --from-audit`** analyzes the local JSONL audit log and *suggests* — never applies — concrete, conservative policy adjustments. The headline suggestion: a rule that fired often and was allowed or bypassed *every* time, and was *never* blocked, is flagged as a candidate for an allowlist entry or a severity override, with a copy-pasteable (and deliberately incomplete — the user picks the target severity) `severity_overrides` snippet. A rule the user *sometimes* blocks on is never suggested for a downgrade — it is doing its job. It also reports, purely informationally, rules that never fired, but only when that list is short enough to be useful. Every suggestion is a fixed rule over plain counts — an arithmetic fact about the log, not an inference — and when the log is too small to be meaningful (`policy tune` needs a minimum number of records) it says so plainly rather than guessing. `policy tune` never edits the policy: the user reviews each suggestion and applies it by hand. Both commands support `--format json`.

- **`tirith policy init --template <name>`** — three curated starter policies for `tirith policy init`. `individual` is sensible defaults for a single developer (fail-open, paranoia 1, the noisy `shortened_url` rule escalated). `ci-strict` is locked down for automated CI — `fail_mode: closed`, the `TIRITH=0` bypass disabled for both interactive and non-interactive shells, `strict_warn: true`, the common remote-execution rules escalated to CRITICAL, and a `scan.fail_on: high` threshold so `tirith scan` fails the build. `ai-agent-heavy` is tuned for environments where AI agents run many commands — fail-open so an internal error cannot wedge an agent mid-task, but `paranoia: 3`, the non-interactive bypass disabled (an agent must not be able to skip analysis), `approval_rules` requiring human approval for the highest-risk pipe-to-shell rules, and `escalation` rules that block on repeated warnings. Each template writes a well-commented YAML file; every key is verified against the real policy schema, so `tirith policy validate` passes on each. `tirith policy init` with no `--template` is unchanged (still the full default template); `--template` and `--minimal` are mutually exclusive, and an unknown template name fails fast and lists the valid names. The `fintech` and `windows-enterprise` templates are intentionally deferred.
- **Android / Termux install support** — Termux runs on Bionic libc and cannot execute the glibc Linux build, so the `aarch64-unknown-linux-musl` artifact (a statically linked binary) is now documented as the supported Termux build, with step-by-step install instructions in the README. The release workflow gained a CI smoke check for that artifact: after the cross-build it verifies the binary is fully static (no dynamic-linker `INTERP` segment) and, under QEMU aarch64 user-mode emulation, confirms `tirith --version` runs and a known-bad pipe-to-shell command is still blocked. Continuous verification on a real Android device is not yet in CI and is tracked as a follow-up.
- **Visible degraded-protection indicator** — when a shell hook downgrades protection (most commonly bash enter mode falling back to preexec warn-only), the downgrade is now surfaced three ways, deliberately without being naggy. (1) The bash hook emits a single consolidated one-shot message per session — `tirith: protection downgraded to warn-only (does not block) — run 'tirith doctor' for details` — replacing the several differently-worded degrade messages it printed before. (2) The tirith shell hooks expose a new `TIRITH_STATUS` shell variable — one of `blocks` / `warn-only` / `degraded` / `off` — reflecting the live protection level; `degraded` specifically means a *mid-session* downgrade from a stronger level, distinct from a shell that simply started in warn-only. A user who wants a prompt indicator can reference `$TIRITH_STATUS` in their PS1 / `fish_prompt` / PowerShell `prompt`; tirith itself adds **no** per-prompt output. It is a plain **non-exported** shell variable (bash/zsh global, fish `set -g`, PowerShell `$global:`): the prompt runs in the interactive shell and reads it fine, while a non-interactive child — which has no tirith protection — never inherits a misleading status. It is never set in a non-interactive shell at all (conformance invariant g). nushell has no session variable that is both prompt-readable and not child-inherited, so the nushell hook does not set `TIRITH_STATUS`. (3) `tirith doctor` now prints an explicit `protection:` line and, when the status is `degraded`, an unmistakable callout — no longer something the reader must infer from `effective protection: warn-only`. `tirith doctor --compat` gained a matching `protection status:` line. New docs page `docs/prompt-status.md` shows ready-to-paste prompt snippets for bash, zsh, fish, PowerShell, and Starship.
- **`tirith doctor --bundle`** (aliases `--redacted-report`, `--shell-trace`) — writes a single **redacted** diagnostic bundle to a file (path printed; under `~/.local/state/tirith/`) that is safe to attach to a bug report. The bundle contains doctor info, tirith + hook versions, shell / mode / effective protection, hook-chain state, policy discovery, threat-DB status, and a curated slice of the environment. Redaction is layered: the environment section emits only a curated allowlist of tirith-relevant variable names (so unrelated cloud credentials / API keys are never candidates), every emitted value is still scrubbed if it looks like a token/secret, and the literal home-directory path is masked to `~` so absolute paths do not reveal the account username. `--bundle` supports `--format json` (emits `{"bundle_path": "..."}`) and is mutually exclusive with `--fix`, `--simulate-enter`, `--reset-bash-safe-mode`, and `--compat`.
- **`tirith check --offline` / `TIRITH_OFFLINE`** — an opt-in switch that suppresses all network activity on the hot path. `tirith check` normally triggers a periodic background threat-DB refresh before analysis; with `--offline` (or `TIRITH_OFFLINE=1` in the environment) that refresh is a guaranteed no-op, so `check` analyzes purely locally with zero network attempts. `paste`, `score`, `diff`, and `why` are already local-only. This is a mechanism only — the default (online) behavior is unchanged. The env-var form lets shell hooks and the PTY conformance harness pin offline behavior deterministically.
- **`tirith doctor --compat`** — a focused shell/terminal compatibility report (human, plus `--format json`). It surfaces the detected shell, requested-vs-effective bash mode and protection (from the hook-exported `TIRITH_BASH_EFFECTIVE_*` vars), the enter-mode capability verdict, install checks (binary PATH shadowing, shell-profile wiring, materialized-hook staleness, policy discovery, threat-DB status), and best-effort detection of co-installed shell tools that historically interact with hooks (Atuin, Starship, fzf, zoxide, direnv, mise, asdf) via presence on PATH and/or in the shell profile. `--compat` is mutually exclusive with `--fix`, `--simulate-enter`, and `--reset-bash-safe-mode`. It is a static report and does not run the enter-mode self-test — `--simulate-enter` remains the way to (re)measure that.
- **`tirith doctor --simulate-enter`** — runs the bash enter-mode delivery self-test on demand: spawns a disposable bash through a PTY, sources the real hook in enter mode, verifies an allowed command is delivered exactly once and a blocked command is stopped, prints the verdict, and caches it. `tirith doctor` shows the cached verdict on a new `enter capability:` line.

### Fixed

- **Bash enter mode silently ate the typed command (#111)** — `bind -x` on Enter runs the bound function but, in many bash/readline builds, does not then accept the line, so `PROMPT_COMMAND` never fires and the command tirith deferred into `_TIRITH_PENDING_EVAL` is never delivered. Because whether `bind -x` accepts the line is a capability of the bash build rather than a version number, tirith now **proves** it: `tirith setup` and `tirith doctor` run a disposable-PTY self-test (`cli::bash_capability`) that checks enter-mode delivery *and* blocking, and write a `key=value` capability cache (`<state-dir>/bash-enter-capability`). Cache freshness is keyed on the bash identity — `$BASH_VERSION` and the bash binary path — because `bind -x` line-acceptance is a property of that specific bash/readline build; the cache `schema` number is the cross-tirith-version invalidator (a probe or format change bumps it), and the recorded `tirith_version` is diagnostic only. The bash hook reads that cache at startup — a single small-file read, so `tirith init` stays untouched and fast — and selects enter mode only when delivery is proven for the running bash, otherwise falling back to the safe default, preexec. An explicit `TIRITH_BASH_MODE=enter` still forces enter mode (the startup health gate and runtime self-healing degrade visibly if delivery then fails). New PTY conformance tests cover the capability-gated allowed/blocked contract, and `bash_preexec_enforce.rs` covers the cache reader against `HISTCONTROL` / `HISTIGNORE` / `set +o history` / pre-set `IFS` / pre-enabled `extdebug`.
- **`tirith doctor` reported `policies: (none found)` for a policy created by `tirith policy init` (#112)** — `doctor` now resolves the active policy through the same local discovery the engine uses — `TIRITH_POLICY_ROOT`, walk-up from the cwd to the `.git` boundary, then the user config dir — via a new shared `discover_local_policy_path` resolver. `tirith policy validate` resolves through it too, so it now locates and reports on a present-but-corrupt policy instead of reporting "no policy file found"; and `doctor --fix` gained an existence guard so it never overwrites an existing policy file. Previously `doctor` only checked the user config dir and `TIRITH_POLICY_ROOT`, never walking up from the cwd.
- **Bash enter-mode auto-degrade left `tirith doctor` reporting stale shell state (#111)** — when an interactive bash shell degrades from enter mode to preexec, `_tirith_degrade_to_preexec` now re-exports `TIRITH_BASH_EFFECTIVE_MODE=preexec` and `TIRITH_BASH_EFFECTIVE_PROTECTION=warn-only`, so a child `tirith doctor` reports the real post-degrade state instead of the stale `enter`/`blocks` values exported at shell startup. `tirith doctor` also now warns when a persisted bash safe-mode flag is being overridden by `TIRITH_BASH_MODE=enter`.
- **Bash enter-mode capability probe could mis-classify a working bash (#111 follow-up)** — the `cli::bash_capability` self-test sent a no-terminal-output command (`printf >> marker`; `printf 'true' | bash && touch marker`) and then keyed completion on the PTY going *quiet* before killing the shell. For a command whose hook shells out to `tirith check`, terminal silence is reached **before** the command runs, so the delivery probe could read an empty marker and cache `broken` for a perfectly working bash, and the blocking probe could read a not-yet-run command's absent marker as a successful "block". Both probes now poll the marker *file* with a bounded timeout — the same technique the PTY conformance harness already uses — instead of inferring completion from terminal quiet. The blocking probe additionally gained an **anti-vacuous guard**: it first delivers an allowed command and confirms (by polling its marker) that the probe shell genuinely delivers commands, and only then tests the blocked command; if the allowed command does not run the verdict is `inconclusive`, never a false "blocked".
- **`TIRITH_STATUS` leaked into non-interactive child processes** — every shell hook (bash, zsh, fish, PowerShell, nushell) set `TIRITH_STATUS` as an *exported* environment variable, so a non-interactive child — which has no tirith protection at all — inherited the parent interactive shell's status (e.g. `bash -i` then `bash -c 'echo $TIRITH_STATUS'` printed `warn-only`). `TIRITH_STATUS` exists only for the user's prompt, which runs *in* the interactive shell, so it is now a plain **non-exported** shell variable (bash/zsh global, fish `set -g`, PowerShell `$global:`) — in-shell prompt integration (PS1 / `PROMPT_COMMAND` / `fish_prompt` / a PowerShell `prompt` function) is unaffected, and children no longer inherit a misleading status. The nushell and PowerShell hooks also gained the interactivity guard they were missing. nushell has no session variable that is both prompt-readable and not child-inherited, so the nushell hook no longer sets `TIRITH_STATUS` at all. `docs/prompt-status.md` is updated accordingly, including a caveat that Starship — an external prompt renderer running as a separate process — needs the variable explicitly re-exported.

## [0.3.1] - 2026-05-08

### Fixed

- **AWS access-key false positive in S3 pre-signed URLs and SigV4 Authorization headers (#101)** — the credential rule no longer flags `AKIA…` matches that sit inside the `X-Amz-Credential` value of a parseable URL whose query also has `X-Amz-Algorithm=AWS4-HMAC-SHA256` and a non-empty `X-Amz-Signature`, or inside the `Credential=` field of an `Authorization: AWS4-HMAC-SHA256 …, Signature=…` header. The carve-out is anchored to absolute byte spans of the actual SigV4 fields — a stray `AKIA…` elsewhere in the same URL/headers/body still fires. Bare access keys, `Authorization: Bearer AKIA…` without SigV4 markers, and URLs missing any SigV4 marker continue to flag. New tests cover each shape and each adversarial bypass we considered.
- **`tirith setup codex` against current Codex CLI versions** — recognises the new `Error: No MCP server named 'X' found.` stderr message instead of treating it as an unexpected failure, and accepts both the legacy top-level `command`/`args` JSON shape and the current nested `transport.command`/`args` shape returned by `codex mcp get --json`. Drift detection still works against either shape.
- **Non-interactive `zsh -lc ...` no longer blocked by stale `.zshenv` guard** — the guard now bakes a stable absolute path to the tirith binary at install time (resolved via PATH lookup with symlink canonicalisation, falling back to `current_exe()` when the PATH entry is a `#!` wrapper script for npm/pnpm). Previously the guard relied on the bare name `tirith` being on PATH, which fails before `.zshrc`/`.zprofile` populate PATH. The path is shell-quoted so spaces and apostrophes round-trip safely.
- **npm shadow false positive on `tirith doctor` / `tirith init` (#105)** — Unix install via npm no longer warns that the `node_modules/tirith/bin/tirith` JS wrapper shadows the native binary. `resolve_effective_tirith_target` now detects the npm wrapper layout (after canonicalising the PATH entry through any symlinks), looks up the matching `@sheeki03/tirith-{platform}-{arch}/bin/tirith` sibling using the same OS+arch mapping the wrapper itself uses, and treats both paths as the same install. Unrelated tirith binaries on PATH (the documented PyPI collision case) still warn.
- **Windows path-shadow false positive on Scoop installs** — `tirith doctor`/`tirith init` no longer warn that the Scoop shim at `~\scoop\shims\tirith.exe` shadows the real binary; the shim is resolved through its `.shim` sidecar to the real path before the equality check.
- **Installer `verify_sha256` portability** — `scripts/install.sh` now probes whether `sha256sum -c` reads from stdin and falls back to `shasum -a 256 -c` when not (some BSDs, busybox). Regression harness added.

### Security

- `rand` bumped to 0.9.3 (RUSTSEC-2026-0097).
- `rustls-webpki` bumped to a version unaffected by upstream advisories.

### Docs

- README: expanded threat intel attribution table; added incident summary; added Nixpkgs install line.

### Internal

- Daily threat-DB manifest direct-pushes to `main` instead of opening auto-merge PRs that silently no-op'd when no required checks were present, accumulating an unmerged backlog.
- Scoop helper code moved under `#[cfg(windows)]` to silence a clippy warning surfaced by recent toolchain versions.
- `_tirith_output` in the bash, fish, and zsh hooks now forwards all arguments instead of only `$1` / `$argv[1]`. No call site passes more than one argument today, but the previous form was a footgun for any future refactor that splits a multi-line message across positional arguments.

## [0.3.0] - 2026-04-21

### Added

- **Bash preexec enforcement (opt-in)** — set `TIRITH_BASH_PREEXEC_ENFORCE=1` to get real blocking in bash preexec mode via `shopt -s extdebug` plus `return 1` from the `DEBUG` trap. Whole-line fail-closed semantics; one block verdict skips the entire typed line. Install-time hostile-history check refuses to engage in shells where `HISTCONTROL` contains `ignorespace`/`ignoredups`/`ignoreboth`, any `HISTIGNORE` is set, or history is disabled. Runtime drift detection with cache-then-degrade downgrades the session to warn-only rather than claim protection it cannot deliver. Idempotent `DEBUG` trap trampoline chains through any pre-existing user `DEBUG` trap. Closes the "tirith says BLOCKED but the command executes" gap in #77.
- **`tirith doctor` live state** — bash hook now exports `TIRITH_BASH_EFFECTIVE_MODE` and `TIRITH_BASH_EFFECTIVE_PROTECTION` (interactive shells only) so `doctor`, a child process, can read the parent shell's live state. Doctor splits requested-vs-effective onto separate lines so mid-session degrades are legible.
- **First-use preexec banner** — on the first command it intercepts, bash preexec prints a one-line reminder that warn-only mode does not block, with a pointer at enter mode.
- **Threat intelligence database** (Phases A/B/C) — `tirith threatdb` subcommand, threat DB compiler binary with CI workflow, signed cache format, detection rules keyed on known-bad hostnames/IPs/packages/typosquats, supplemental feed overlay with Phase B feed parsers and rule mapping, Phase C runtime API enrichment wired into `check` and daemon paths, auto-update and staleness reporting in `doctor`.
- **Per-session warning accumulator** with a new `tirith warnings` CLI command and shell exit summaries across all hooks.
- **Escalation engine** with cooldown and post-process verdicts, integrated into the engine, audit log, MCP gateway, check, and daemon paths.
- **Strict warn mode** with a new `WarnAck` exit code 3.
- **Daemon mode** with network-aware URL checks; Windows parity for network and setup features.
- **`tirith policy init`, `validate`, `test`** subcommands; **`tirith explain --rule`** for rule documentation.
- **`tirith doctor --fix`** for progressive remediation, plus `--reset-bash-safe-mode` flag.
- **`tirith setup`** gains `copilot-cli` (#74) and `kiro` (#75); scanner recognises `.kiro/`, `.amazonq/cli-agents/`, and `.github/hooks/` as config paths.
- **`--include`, `--exclude`, `--profile`** scan filters.
- **GitHub Action, pre-commit hook, and SARIF enrichment** for CI integration.
- **Text confusable detection** (math alphanumerics, same-word mixed-script) plus expanded terminal/config rules.
- **Detection gap analysis** surfaced in `tirith doctor`.
- **Warn-only rendering** for preexec mode (#77) — preexec verdicts now render "DETECTED (shell hook cannot block in preexec mode...)" instead of the misleading "BLOCKED" banner.
- `SKILL.md` for AI agent discovery.
- CLI UX: error suggestions, color module, `confirm` helper, normalised output flags, help examples on every subcommand.
- Tokenizer span tracking (trimmed byte range per segment) to support tighter carveouts without string scanning.
- `aarch64-unknown-linux-musl` target in the release pipeline.

### Fixed

- Restore `TIRITH=0` pipe bypass without weakening paste safety (#78).
- Scp/rsync remote-spec parser replaced so `host:/path` no longer trips URL-host false positives (#26).
- Carve out tirith inspection args so the scanner doesn't match its own prompt text (#29).
- Wrapped commands (`sudo`, `env`, `doas`, `command`, `time`, `nohup` prefixes) now resolve through `resolve_wrapped_command` in the `network_deny` path so prefix chains cannot bypass policy.
- `codefile` byte slicing clamps to UTF-8 char boundaries to avoid a panic on non-ASCII code (#76).
- Approval and warn-ack temp files are cleaned up on all paths to stop `/tmp` leaks (#80).
- Close mid-session `HISTCONTROL` bypass; preexec cache key corrected so drift-triggering pipelines do not leak composite rules.
- Warn-only dedupe scoped to a single typed line so long pipelines no longer suppress later DETECTED banners.
- Windows CI: Finding import, daemon/setup module compilation, XDG audit spool test gated to Unix, Gemini path assertion gated to Unix.
- Platform-specific snapshot tests replaced with cross-platform assertions.
- Early signing-key check in the threat DB workflow.
- Linux bash preexec tests made deterministic; CI caps hung test job runtime.

### Changed

- Stacked CI runs on the same ref are now cancelled; `fuzz/target` and `Cargo.lock` ignored in CI path filters.
- Documentation across README and `docs/troubleshooting.md` updated for the new enforcement matrix, threat-intel features, escalation, hidden findings, `--format` flag canonicalisation, and new MCP client setup guides (Gemini CLI, OpenClaw, Pi CLI).

## [0.2.12] - 2026-04-01

### Fixed

- Always-on pro runtime and shell-hook regression fixes.
- Windows CI test failures.
- Release publish workflow hardened.
- Crates.io re-publish idempotency check + HTTP status-code wait step.
- User-Agent header added to the crates.io API poll.

### Changed

- Docker image uses pre-built release binaries instead of compiling inside the container.

## [0.2.11] - 2026-03-31

### Added

- `Base64DecodeExecute`, `DataExfiltration`, and code-file scan rules for JS/Python files (obfuscated payloads, dynamic code execution, secret exfiltration via `fetch`/`requests.post`).
- HTML and Markdown comment content analysis with severity tiers (High for prompt injection, Medium for destructive commands).

### Fixed

- Send-position-only contract enforced for `SuspiciousCodeExfiltration`.
- Fish block-hides-prompt regression (#31).
- Zsh hook crash when `noclobber` is enabled (#70).
- Postfix `++`/`--` vs division disambiguation in the codefile exfil parser.
- Hardcoded user path removed from the Cursor MCP config template.

## [0.2.10] - 2026-03-25

### Added

- TeamPCP post-compromise behavior detection rules (`/proc/*/mem` scraping, Docker remote privilege escalation, credential-file sweeps) and domain corpus fix.
- Credential leak detection: known-pattern tokens (AWS, GitHub, Stripe, Slack, SendGrid, Anthropic, GCP, npm, private-key blocks) plus entropy-based generic secret detection.

## [0.2.9] - 2026-03-24

### Fixed

- SSRF bypass closed.
- `allowlist_rules` policy field now enforced.
- Webhook env-var hardening.

## [0.2.8] - 2026-03-21

### Added

- SSRF protection on cloaking fetch with DNS resolution checks.

### Fixed

- Cmd caret escapes inside double quotes; env values now redacted in findings.
- Inline `TIRITH=0` paste bypass removed; blocked content previews escape control characters.
- Guarded JSON-RPC notifications are analysed rather than forwarded blindly.
- Inline bypass parsing hardened; self-invocation guard removed.
- URL extraction from env-prefix assignments (`FOO=bar cmd url`); MCP scan file count capped.
- Secrets redacted in JSON output; shell metacharacters quoted in `init` output.
- Windows CI stability; `rustls-webpki` bumped for RUSTSEC-2026-0049 (0.101.x line ignored until upstream patches land).
- Windows `data_dir` uses `APPDATA`.
- `clippy::type_complexity` cleanup via `HostResolver` type alias.

## [0.2.7] - 2026-03-12

### Fixed

- VS Code / Cursor shell-env resolution: skip the `.zshenv` guard when the shell is resolving its env for IDE integration.

### Changed

- README lists `openclaw` under the setup commands.

## [0.2.6] - 2026-03-09

### Added

- Cmd (Windows cmd.exe) shell tokenizer.
- `tirith setup openclaw` command.

## [0.2.5]

### Added

- Pipe-to-shell findings now suggest `vet` (and `tirith run` on Unix for POSIX fetch commands) as safer alternatives when the source is a URL-fetching command.
- Cookbook section for getvet.sh integration (section 7).
- Interpreter detection hardening: canonical INTERPRETERS list (26 entries), `normalize_shell_token()` state machine, `resolve_interpreter_name()` with sudo/env/command/exec/nohup prefix chains.
- Extended interpreter coverage: fish, csh, tcsh, ash, mksh, python2/3, deno, bun, lua, tclsh, elixir, rscript, pwsh.

### Fixed

- `sudo -iu root bash` combined short flags now correctly resolve to `bash`.
- `--` end-of-options marker now stops flag-skipping in interpreter resolution.
- ANSI-C quoting (`$'...'`) no longer applied to Fish shell (Fish doesn't support it).
- Extracted URLs in remediation hints are sanitized to prevent ANSI injection.

## [0.1.5] - 2026-02-04

### Fixed

- Shell hooks now reliably display block/warn messages in all terminal contexts (zsh, bash, fish, PowerShell).
- Blocked commands show with `command>` prefix, blocked pastes show with `paste>` prefix.
- Fish hook now works with vi keybindings (`fish_vi_key_bindings`). Binds Enter in insert, default, and replace modes.
- Fish vi mode: Enter from normal mode now correctly returns to insert mode after execution.

## [0.1.4] - 2026-02-04

### Fixed

- Shell hooks (zsh, bash) now properly display block/warn messages. Previously, messages were silently swallowed in zle/bind-x contexts.

## [0.1.3] - 2026-02-03

### Changed

- Re-licensed under AGPL-3.0-only with a commercial licensing option.

## [0.1.0] - 2026-02-02

### Added

- Tiered analysis engine (Tier 0-3) with <2ms fast path for clean commands
- 30 detection rules across 7 categories: hostname, path, transport, terminal, command, ecosystem, environment
- Shell hooks: zsh, bash (enter + preexec modes), fish, PowerShell
- Self-contained install: hooks embedded in binary, materialized on first `tirith init`
- Policy engine: YAML config, allowlist/blocklist, severity overrides, fail_mode (open/closed)
- JSONL audit log with file locking and event correlation IDs
- Receipt system for script execution tracking with SHA-256 verification
- `doctor` diagnostic command for installation troubleshooting
- Shell completions (zsh, bash, fish, PowerShell) via hidden `completions` subcommand
- Man page via hidden `manpage` subcommand
- `diff` command for comparing URLs against known-good patterns
- `score` command for URL risk scoring
- `why` command to explain the last triggered rule
- `run` command for safe script download and execution (Unix only)
- 235 golden fixture tests across 10 categories
- Criterion performance benchmarks
