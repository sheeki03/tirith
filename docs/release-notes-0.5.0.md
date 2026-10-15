# Tirith 0.5.0 release notes

Tirith 0.5.0 is a minor release. It makes Tirith safer to run under coding
agents, removes the ordinary-command false positives reported against 0.4.2,
and adds reviewed, undoable ways to choose and roll out protection. It removes
`tirith-core` library API, so it is `0.5.0` rather than a 0.4.x patch.

The [0.4.0 release notes](release-notes-0.4.0.md) describe the 0.4 line's
feature set and platform boundaries. The [CHANGELOG](../CHANGELOG.md) lists
every change in detail.

## Read this before upgrading

- **Refresh agent integrations.** Installed agent adapters are files that
  `tirith setup` wrote; upgrading the binary does not rewrite them. Adapters
  installed by 0.4.x do not enforce the new approval requirement described
  below. After upgrading, re-run setup with `--force` for every agent host you
  use, at the scope you installed it with, for example
  `tirith setup claude-code --scope user --force`. Without `--force`, setup
  stops with "exists but content differs". `tirith doctor` lists every
  installed adapter and marks outdated ones STALE with the exact command, and
  `tirith doctor --fix` refreshes them.
- **`tirith check --json` answers an honored bypass.** A `TIRITH=0` bypass
  that policy honors now prints the normal verdict (`action: "allow"`,
  `bypass_honored: true`, `requires_approval: false`, exit 0) instead of
  nothing.
- **`tirith check` rejects unknown options before the command.**
  `tirith check --json --bogus -- cmd` exits 2 with clap's error and prints
  nothing on stdout. 0.4.2 analyzed `--bogus` as the first word of the
  command, so a caller passing a newer flag to an older Tirith got a verdict
  for a different command. A command that starts with `-` goes after `--`.
- **`package_lookup_incomplete` replaces `analysis_incomplete` for package
  lookups.** A live OSV.dev or deps.dev lookup that could not finish is now its
  own Medium warning. A policy that adjusts or allowlists `analysis_incomplete`
  to handle `pip install` or `npm install` warnings must name
  `package_lookup_incomplete` instead.
- **`tirith trust add` needs `--rule RULE` or `--all-rules`** and writes to the
  new `trust-grants.json`. Existing `trust.json` entries keep working until
  `tirith trust migrate`.
- **Package installation stays disabled.** `tirith pkg install` and
  `tirith pkg approve` refuse on every host and record nothing; use
  `tirith install --no-exec`.
- **`tirith-core` library users:** the pip resolve, quarantine, firewall and
  approval pipeline and several receipt writers are removed, and
  `AnalysisContext`, `Policy` and `output::JsonOutput` gained fields. See
  Removed and Changed in the CHANGELOG.

## Agents

- **Approval cannot turn into a warning.** `tirith check` JSON (schema 3 and 4)
  always carries a boolean `requires_approval`. Active approval rules, `WarnAck`
  and `strict_warn` acknowledgement set it, and every installed Python, shell
  and TypeScript adapter (Claude Code, Cline, Copilot CLI, Cursor, Gemini CLI,
  Grok Build, Kiro, OpenClaw, OpenHands, pi and Prime Agent, VS Code,
  Windsurf) denies such a command
  instead of running it as an ordinary warning. Hosts without an approval
  interface deny with guidance to run the command in an interactive shell.
- **Known verdicts are never fail-open.** Adapters deny a block even when its
  output is lost, a required acknowledgement (exit 3), and a deferred block
  (exit 4), also with `TIRITH_FAIL_OPEN=1`, which now covers only checker
  errors. A warning that `TIRITH_HOOK_WARN_ACTION=deny` blocks stays denied when
  its output is damaged. The Cursor, VS Code and Windsurf adapters no longer
  import Python modules from the project directory.
- **Fewer agent false positives.** Ordinary agent command shapes that 0.4.2
  blocked now pass: bracket conditions and arithmetic over substitutions
  ([#260](https://github.com/sheeki03/tirith/issues/260)), variable indirection
  and `echo … | python3 -c` data pipelines
  ([#264](https://github.com/sheeki03/tirith/issues/264)), redirection tokens
  read as package names ([#270](https://github.com/sheeki03/tirith/issues/270)),
  bare numbers and ports read as IP addresses
  ([#255](https://github.com/sheeki03/tirith/issues/255)), literal
  `npm view` selectors, `"$VAR/scripts/x.sh"` command words, bearer-token
  header expansions, plain LAN health checks (now a warning), and the `.app` and
  `.dev` TLDs.
- **New detections.** Uploading a project secret file (`.env`, `.envrc`,
  `credentials.json`, SSH private keys) through curl, wget, scp or rsync is
  `data_exfiltration`. Downloaded command-substitution output used as
  `python -c` or `node -e` source is `interpreter_suspicious_inline_exec` in
  POSIX shells, also when curl or wget writes it to `/dev/stdout`. Inline
  programs after clustered options (`python3 -Pc`, `perl -lne`, `ruby -we`) or
  after a leading redirection (`2>/dev/null python3 -c`) are analyzed, and fish
  blocks `curl … | sh>/dev/null` like `| sh >/dev/null`.
  Curl destinations written with one to three scheme slashes, curl URL globs,
  and metadata or private-network URLs run through `sudo`, `env`, `nohup` or
  `command` keep their metadata, raw-IP, transport and network-deny checks.

## Shells

- **fish** runs multi-line commands and loops exactly once
  ([#273](https://github.com/sheeki03/tirith/issues/273)) and no longer leaks
  umask 077 into the interactive shell
  ([#265](https://github.com/sheeki03/tirith/issues/265)).
- **Concurrent shells** (multiplexer restore) get independent sessions and no
  longer stay locked on an unresolved execution receipt
  ([#257](https://github.com/sheeki03/tirith/issues/257)). On a fresh install,
  every shell that starts at the same moment now loads its hook; before, some
  `tirith init` runs lost a race and left their shell unprotected.
- **Virtual filesystems** such as KDE kio-fuse no longer force fail-closed with
  a phantom repository policy
  ([#266](https://github.com/sheeki03/tirith/issues/266)).
- Bash, zsh and fish start one Tirith process per execution-receipt step
  instead of up to three. `tirith status` and `tirith doctor` report whether the
  current terminal's loaded hook is current or stale, and
  `tirith doctor --verify-shell` proves blocking in the calling shell.
- The exec gate and heredoc reader follow the shells' own parsing in many more
  places (comments in `${...}` and backticks, quotes in substitutions, heredocs
  inside `$(...)`, redirections joined to the command word), so the command
  after such text is analyzed instead of hidden.
- **Packages:** native packages no longer depend on or suggest sudo
  ([#249](https://github.com/sheeki03/tirith/issues/249)). Android/Termux
  builds compile in CI and the installer refuses incompatible Android installs;
  there is no Android release asset yet
  ([#261](https://github.com/sheeki03/tirith/issues/261), based on
  [#262](https://github.com/sheeki03/tirith/pull/262)).

## Choosing and rolling out protection

- Versioned personal protection profiles (`tirith policy profile
  comfortable|balanced|strict`) and typed settings (`tirith policy setting`),
  each change previewed, saved as an operation and undoable byte for byte.
- `tirith policy rollout` measures a profile against your own commands before
  you activate it; `tirith policy simulate` compares one command.
- `tirith setup recommended` and `tirith setup shell`: one reviewed, undoable
  plan for shell startup files, a profile and optionally the Claude Code hook.
- Scoped, expiring trust grants (`trust-grants.json`), with `trust expiry`,
  `trust revoke` and `trust migrate`. A private Docker registry is trusted with
  `tirith trust add <registry-host> --broad --rule docker_untrusted_registry`;
  a `<registry-host>/*` pattern is refused with that hint instead of being
  stored as a literal that never matched
  ([#271](https://github.com/sheeki03/tirith/issues/271)).
- `tirith dashboard`: an authenticated loopback dashboard for profiles,
  history, exceptions, integrations, team policy and saved changes.
- Optional self-hosted team policy (`tirith-policy-server`,
  `tirith policy team`) with enrollment, reviewed publication and an offline
  grace period.
- `tirith review` (read-only project review), `tirith pkg inspect` and
  `tirith pkg diff` (npm tarball inspection without extracting or running
  anything), audit history tools, and ThreatDB freshness reporting.

## Security fixes

- x86_64 Linux containment restricts `clone` flags with the same table as
  aarch64 and returns `ENOSYS` for `clone3`.
- The `python -c` data-pipeline exemption no longer applies when the input may
  enable Python inspect mode.
- rustls is updated to 0.23.46 (RUSTSEC-2026-0346 to RUSTSEC-2026-0349; 0.4.2
  shipped rustls 0.23.36, also affected by RUSTSEC-2026-0285).

## Known gaps

- Downloaded inline source (`python -c "$(curl …)"`) is detected in POSIX
  shells only, not in fish's `python3 -c (curl …)`. Pipe-to-interpreter and
  the other command rules apply in fish as before. php's `-B`, `-R` and `-E`
  code options are not treated as inline source (`-r` is).
- A heredoc fed to a remote or nested reader (`ssh host sh <<EOF`,
  `x=$(sh) <<EOF`) is not analyzed as code, and curl's
  `--variable`/`--expand-url` templates are read as unknown values.
- KDE kio-fuse ([#266](https://github.com/sheeki03/tirith/issues/266)) is
  handled from the report, not yet reproduced on that desktop. Android builds
  compile in CI but have no release asset or device qualification
  ([#261](https://github.com/sheeki03/tirith/issues/261)).
- `serde_yaml` 0.9 is deprecated and its `unsafe-libyaml` dependency is
  flagged unmaintained (RUSTSEC-2024-0449, no vulnerability reported); it will
  be replaced in a later release.

## Upgrade

Use the package manager that owns your installation:

```bash
npm install -g tirith@0.5.0
cargo install tirith --version 0.5.0 --locked
brew update && brew upgrade tirith
```

```powershell
scoop update
scoop update tirith
choco upgrade tirith --version=0.5.0
```

Standalone installations can use `tirith update`, which verifies the release
before replacing the executable. Signed platform archives, the installer,
Debian/RPM packages, and verification material are available from
[GitHub Releases](https://github.com/sheeki03/tirith/releases/tag/v0.5.0).
The release workflow also updates the project Homebrew tap, Scoop bucket, AUR
package, and versioned GHCR images. Homebrew core, Chocolatey community
moderation and distribution packages such as nixpkgs may update later; if your
package manager does not offer 0.5.0 yet, use the project tap or a signed
GitHub release artifact.

After updating, restart your shell and agent host, refresh each agent
integration, then run:

```bash
tirith --version
tirith setup <host> --scope <scope> --force   # once per agent host, at its installed scope
tirith doctor
tirith threat-db update
```

The Hermes Agent plugin ([sheeki03/hermes-plugin-tirith](https://github.com/sheeki03/hermes-plugin-tirith))
requires this release and refuses older Tirith versions.

Thanks to everyone who reported problems and supplied reproductions, and to
the contributors whose proposals shaped the Android and npm fixes.
