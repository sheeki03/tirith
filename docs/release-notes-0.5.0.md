# Tirith 0.5.0 release notes

Tirith 0.5.0 is a minor release. It makes Tirith safer to run under coding
agents, removes most of the ordinary-command false positives reported against
0.4.2 (Known gaps lists those that remain), and adds reviewed, undoable ways
to choose and roll out protection. It removes `tirith-core` library API, so it
is `0.5.0` rather than a 0.4.x patch.

The [0.4.0 release notes](https://github.com/sheeki03/tirith/blob/v0.5.0/docs/release-notes-0.4.0.md)
describe the 0.4 line's feature set and platform boundaries. The
[CHANGELOG](https://github.com/sheeki03/tirith/blob/v0.5.0/CHANGELOG.md) lists
every change in detail.

## Read this before upgrading

- **Refresh agent integrations.** Installed agent adapters are files that
  `tirith setup` wrote; upgrading the binary does not rewrite them. Adapters
  installed by 0.4.x do not enforce the new approval requirement described
  below. After upgrading, re-run setup with `--force` for every agent host you
  use, at the scope you installed it with, for example
  `tirith setup claude-code --scope user --force`. Project scope is the default
  for most hosts, so repeat this from each project directory where you ran
  setup. Without `--force`, setup stops with "exists but content differs".
  `--force` leaves `.tirith-backup-v2-*` recovery copies and empty
  `.tirith-setup-v2-*.tmp` files next to the files it rewrites (inside the
  project's `.claude/` for Claude Code); add `.tirith-*` to that project's
  `.gitignore`.
- **`tirith doctor` sees user-scope adapters and the project you run it in.**
  Run `tirith doctor` (or `tirith doctor --fix`) from inside each project where
  you ran project-scope setup; it finds the project's adapters from any
  directory in the repository and marks outdated ones STALE with the exact
  refresh command. From outside the project, such as your home directory, it
  does not list that project's adapters.
- **Warnings no longer approve agent commands.** After the refresh, a command
  Tirith warns about goes through Claude Code's and VS Code's normal permission
  prompt; 0.4.x answered such a warning with `allow`, which skips the prompt.
  An unrecognized `TIRITH_HOOK_WARN_ACTION` value now denies warnings; the
  valid values are `allow`, `ask` and `deny`.
- **Commands holding raw terminal control bytes block.** A checked command
  with an ESC sequence, or a carriage return that is not part of a CRLF line
  ending, is now `ansi_escapes` / `control_chars`, as a paste is. Integrations
  that put ANSI colour codes inside commands must strip them first.
- **zsh guard.** If you installed the `~/.zshenv` guard, re-run
  `tirith setup <host> --scope <scope> --force --install-zshenv`; `--force`
  alone and `tirith doctor --fix` leave the 0.4.x guard in place.
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
- **IaC auto-approve rules check every command on a line.**
  `cd infra; terraform apply -auto-approve` and
  `tofu init && tofu apply -auto-approve` now warn (`iac_apply_auto_approve`,
  exit 2) where 0.4.2 checked only the first command. With
  `iac_require_plan_before_apply: true`, `cd infra; terraform apply` now
  blocks.
- **`tirith trust add` needs `--rule RULE` or `--all-rules`** and writes to the
  new `trust-grants.json`. Existing `trust.json` entries keep working.
  `tirith trust migrate` moves them into `trust-grants.json`, which 0.4.x
  ignores, so migrated entries stop applying if you downgrade.
- **Contained package installation is disabled.** `tirith pkg install` (which
  0.4.x ran for pip on x86_64 Linux) and `tirith pkg approve` now refuse on
  every host and record nothing. Use `tirith install --no-exec` to analyze an
  install.
- **`tirith dashboard serve` parses HTTP more strictly.** Some unusual or
  malformed requests that 0.4.2 answered now get 400, 405 or 431; the
  CHANGELOG lists them.
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
  Windsurf) denies such a command instead of running it as an ordinary
  warning. Hosts without an approval interface deny with guidance to run the
  command in an interactive shell.
- **Known verdicts are never fail-open.** Adapters deny a block (even when its
  output is lost), a required acknowledgement (exit 3) and a deferred block
  (exit 4), also with `TIRITH_FAIL_OPEN=1`, which now covers only checker
  errors. A warning that `TIRITH_HOOK_WARN_ACTION` gates (`ask`, `deny` or an
  unrecognized value) stays denied when its output is damaged. The Cursor,
  VS Code and Windsurf adapters no longer import Python modules from the
  project directory.
- **A warning is shown, not approved.** Claude Code and VS Code receive the
  warning as a message for the user and context for the model, with no
  permission decision, so their own permission rules apply.
  `TIRITH_HOOK_WARN_ACTION=ask` asks the user on hosts that can (Claude Code,
  VS Code, Copilot CLI, Cursor) and denies with guidance elsewhere.
- **Malformed or oversized hook traffic is denied.** The VS Code, Cursor,
  Windsurf and OpenClaw adapters deny a shell call whose command is missing or
  not a string; before, they skipped the check or checked the wrong text. The
  Pi, Prime Agent, OMP and OpenClaw guards read checker responses up to 16 MiB
  and deny anything larger, even with `TIRITH_FAIL_OPEN=1`. On Linux and
  macOS, an adapter whose pinned Python has moved or been removed denies
  instead of silently switching off, and `tirith setup` skips an untrusted
  first `python3` on `PATH` for the next trusted one.
- With `allow_bypass_env_noninteractive: true`, the zsh non-interactive
  guard allows an honored `TIRITH=0` bypass again, as 0.4.2 did.
- **Fewer agent false positives.** These shapes, which 0.4.2 blocked or
  warned on, now pass:
  - `if` and `while` bracket conditions over a substitution, and arithmetic
    over `$(date +%s)`, `$(printf N)`, `$(nproc)`, `getconf`,
    `sysctl -n hw.ncpu` or `wc -l < file` (`make -j$(( $(nproc) + 1 ))`)
    ([#260](https://github.com/sheeki03/tirith/issues/260)).
  - In POSIX shells, a command named through a variable
    (`BIN=/bin/echo; "$BIN" --help`)
    ([#264](https://github.com/sheeki03/tirith/issues/264)).
  - Data pipelines into Python, in POSIX shells and fish: `python3 -c`
    programs that pass their input to `print`, transform it as data
    (`json.dumps`, `.upper()`, `.readlines()`, `for l in sys.stdin`) or print
    a constant ([#264](https://github.com/sheeki03/tirith/issues/264)), and
    `| python3 -m json.tool` with its own options, also for downloaded input
    (`curl -s URL | python3 -m json.tool`).
  - Here-strings into text filters (`jq -r .name <<< "$OUT"`), `xargs -I{}`
    (`git branch --merged | xargs -I{} git branch -d {}`), and a `{ …; }`
    group with a redirect or pipe
    (`{ cargo build; cargo test; } 2>&1 | tee build.log`).
  - Shell setup lines such as `eval "$(brew shellenv)"`,
    `eval "$(ssh-agent -s)"`, `eval "$(pyenv init -)"` and
    `source <(kubectl completion zsh)`.
  - Agent batch scripts of a few thousand lines and large heredoc file
    writes; past the analysis limits the command still blocks and the
    message names the limit.
  - Requests to this machine: `curl -F 'env=@.env' http://localhost:3000/debug`,
    `curl localhost:3000`, and `curl -k https://localhost:8443/health` (now a
    Low finding), when no proxy, config file or redirect can send the request
    elsewhere. Copying an SSH public key (`scp ~/.ssh/id_ed25519.pub host:`).
  - In fish, an escaped quote inside single quotes
    (`git commit -m 'it\'s done'`), and in every shell wrapper spellings such
    as `nice -n5`, `timeout -k1 5`, `ionice -c3 cmd`, `flock FILE cmd` and
    macOS `/usr/bin/time -l cmd`.
  - Redirections after a package command (`npm install express 2>&1`) are no
    longer looked up as package names
    ([#270](https://github.com/sheeki03/tirith/issues/270)).
  - Literal `npm view` version selectors.
  - Command words such as `"$HOME/scripts/x.sh"`.
  - Header expansions such as `-H "Authorization: Bearer $TOKEN"`.
  - The `.app` and `.dev` TLDs.

  Plain LAN health checks (`curl http://192.168.1.20:8080/health`) now warn
  instead of blocking.
- **Numeric hosts ([#255](https://github.com/sheeki03/tirith/issues/255),
  still open).** A curl finding for a bare number now names the number you
  typed (`8080`) as well as the address it converts to (`0.0.31.144`). The
  warning itself remains; see Known gaps.

## New detections

- Uploading a project secret file (`.env`, `.envrc`, `credentials.json`, SSH
  private keys) to another machine with curl, wget, scp or rsync is
  `data_exfiltration`. An upload to this machine (a literal `localhost`,
  `127.x.y.z` or `[::1]` address with no proxy, config-file override or
  redirect following) is not, and the public files of `~/.ssh` (`*.pub`,
  `known_hosts`, `authorized_keys`, `config`) are not secret material.
- Downloaded output used as program source (`python3 -c "$(curl …)"`,
  `node -e`, php `-r`, `-B`, `-R` and `-E`) is
  `interpreter_suspicious_inline_exec` in POSIX shells and in fish
  (`python3 -c (curl …)`), also when curl or wget writes to `/dev/stdout`.
- A download piped into `source` or `.` (`curl … | source /dev/stdin`, fish's
  `curl … | source`) or into `busybox sh` is `curl_pipe_shell`, like `| sh`.
  Local generators piped into `source` (`starship init fish | source`) are
  unchanged.
- Inline programs after clustered options (`python3 -Pc`, `perl -lne`,
  `ruby -we`), after a leading redirection (`2>/dev/null python3 -c`), joined
  to their flag inside quotes (`perl '-e…'`) or split across several `-e`
  words are analyzed.
- In fish, the command run by `nice`, `timeout`, `setsid`, `stdbuf`,
  `taskset`, `ionice` or `flock` is analyzed (`nice perl -e …`,
  `timeout 30 sh -c '…'`).
- A shell's `-c` script is found after any option (`sh -c -e CMD`,
  `bash -c -- CMD`), and fish's `-C` value is code. A heredoc fed to a remote
  shell over ssh (best-effort) or to `x=$(sh)` is analyzed as code.
- Raw terminal control bytes in a checked command (an OSC 52 clipboard write,
  hidden text, a carriage return that overwrites the line) are
  `ansi_escapes` / `control_chars`, as in a paste. This covers agent commands,
  which all go through `tirith check`.
- `xargs -I REPL` whose item becomes the command, a shell or interpreter
  program, or the target of `rm`, `mv` or `chmod` blocks as incomplete
  analysis.
- When node, bun, perl or ruby gets several inline programs, every one is
  checked, so a harmless first program no longer hides a later payload:
  0.4.2 checked only the first `-e` word and missed `node -e 1 -e …`,
  `bun -e 1 -e …`, `perl -e 1 -e …` and `ruby -e 1 -e …`. Downloaded source
  in a later program (`node -p 1 -e "$(curl …)"`) is caught too.
- fish blocks `curl … | sh>/dev/null` like `| sh >/dev/null`.
- curl URLs with one to three slashes after the scheme, curl URL globs
  (`http://169.254.169.[254-254]/`), and URLs run through `sudo`, `env`,
  `nohup` or `command` keep their metadata, private-network, raw-IP and
  network-deny checks.
- A bare number given as a curl proxy (`curl -x 8080 …`) is read as a numeric
  host and warns `raw_ip_url`.

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
- Commands hidden after a comment, quote or heredoc are now analyzed: Tirith
  reads a `#` inside `${...}` or backticks, quotes inside a substitution, a
  heredoc inside `$(...)` and a redirection joined to the command word the
  way the shells do.

## Packaging

- Native packages no longer depend on or suggest sudo
  ([#249](https://github.com/sheeki03/tirith/issues/249)).
- Android/Termux builds compile in CI and the installer refuses incompatible
  Android installs; there is no Android release asset yet
  ([#261](https://github.com/sheeki03/tirith/issues/261), based on
  [#262](https://github.com/sheeki03/tirith/pull/262)).
- Both crates ship the AGPL license text and the NOTICE file with the
  third-party data attributions.

## Choosing and rolling out protection

- Versioned personal protection profiles (`tirith policy profile
  comfortable|balanced|strict`) and typed settings (`tirith policy setting`),
  each change previewed, saved as an operation and undoable byte for byte.
- `tirith policy rollout` measures a profile against your own commands before
  you activate it; `tirith policy simulate` compares one command.
- `tirith setup recommended` and `tirith setup shell`: one reviewed, undoable
  plan for shell startup files, a profile and optionally the Claude Code hook.
- Scoped, expiring trust grants (`trust-grants.json`), with `trust expiry`,
  `trust revoke` and `trust migrate`.
- A private Docker registry is trusted with
  `tirith trust add <registry-host> --broad --rule docker_untrusted_registry`
  ([#271](https://github.com/sheeki03/tirith/issues/271)). A
  `<registry-host>/*` pattern is refused with that hint instead of being
  stored as a literal that never matched. A `/*` grant that 0.4.x stored shows
  as `invalid` (`wildcard_never_matches`) in `tirith trust list` and
  `tirith trust explain`, which print the exact commands that replace it.
  `tirith trust migrate` lists such entries and leaves them in place, and
  `tirith policy validate` warns about the same shape in allowlist entries.
- `tirith dashboard`: an authenticated loopback dashboard for profiles,
  history, exceptions, integrations, team policy and saved changes.
- Optional self-hosted team policy (`tirith-policy-server`,
  `tirith policy team`) with enrollment, reviewed publication and an offline
  grace period.
- `tirith review` (read-only project review), `tirith pkg inspect` and
  `tirith pkg diff` (npm tarball inspection without extracting or running
  anything), audit history tools, and ThreatDB freshness reporting (source
  ages are not available yet; see Known gaps).

## Security fixes

- x86_64 Linux containment restricts `clone` flags with the same table as
  aarch64 and returns `ENOSYS` for `clone3`.
- The `python -c` data-pipeline exemption no longer applies when the input may
  enable Python inspect mode.
- rustls is updated to 0.23.46 (RUSTSEC-2026-0346 to RUSTSEC-2026-0349). The
  rustls 0.23.36 that 0.4.2 shipped is affected by RUSTSEC-2026-0285, -0346,
  -0348 and -0349.

## Known gaps

- Some agent command shapes still block as incomplete analysis, as in 0.4.2:
  - a here-string fed to a program that may run it (`python3`, `awk`, `sed`,
    `kubectl apply -f -`);
  - `xargs -I{}` whose item becomes code or the target of `rm`, `mv` or
    `chmod`, and `xargs -I{}` in fish;
  - arithmetic over other command output, and the assignment form
    `N=$(( $(nproc) * 2 ))`;
  - a Python pipe stage with a redirection (`| python3 -m json.tool 2>&1`) or
    interpreter options (`python3 -I -c`);
  - a shell setup line next to an assignment
    (`export PYENV_ROOT=…; eval "$(pyenv init -)"`);
  - in fish, `alias ll 'ls -lah'` and `command -sq rg; and rg foo`.
- Bare numbers still read as hosts
  ([#255](https://github.com/sheeki03/tirith/issues/255)): a curl port operand
  (`curl -sv example.com 8080`), git's `--depth 1` and wget's `-t 3` warn
  `raw_ip_url`.
- A heredoc fed to ssh is analyzed best-effort: when Tirith cannot read the
  remote command (`ssh host "$CMD" <<EOF`) the heredoc stays data. A download
  staged by one command and run by a later one
  (`curl -o f URL; python3 -c "$(cat f)"`) is not followed. curl variables
  imported from the environment (`--variable %NAME`) or a file
  (`name@file`) are read as unknown values.
- `scp`, `rsync` and `ssh` to `localhost` are treated as remote, and a secret
  piped into an ssh remote command (`cat ~/.ssh/id_ed25519 | ssh host 'cat > k'`)
  is not detected, as in 0.4.2. A shell's attached `--command=CMD` option is
  not analyzed.
- On Windows, the Gemini CLI and Kiro hook commands run the pinned Python
  directly, so a moved or removed interpreter makes them fail open until
  `tirith setup` is run again.
- Source ages in `tirith threat-db status` and `health` stay unavailable, and
  `tirith threat-db update` prints a "source evidence HTTP 404" notice, until
  the v2 threat feed is enabled. The signed database still updates and
  protects normally.
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

After updating, restart your shell, then run:

```bash
tirith --version
tirith doctor                                 # marks outdated adapters STALE
tirith setup <host> --scope <scope> --force   # each STALE one (or tirith doctor --fix)
tirith threat-db update
```

Run `tirith doctor` and the setup command it prints from your home directory
for user-scope adapters, and again from inside each project where you ran
project-scope setup. Restart each agent host after refreshing its adapter.

The Hermes Agent plugin ([sheeki03/hermes-plugin-tirith](https://github.com/sheeki03/hermes-plugin-tirith))
requires this release and refuses older Tirith versions.

Thanks to everyone who reported problems and supplied reproductions, and to
the contributors whose proposals shaped the Android and npm fixes.
