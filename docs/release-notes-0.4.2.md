# Tirith 0.4.2 release notes

Tirith 0.4.2 is a reliability and performance patch for the 0.4 line. It fixes
shell integration failures and ordinary-command false positives, restores
reliable ThreatDB publication and reloads, and reduces repeated work in command
analysis and diagnostics. It adds no top-level command.

The [0.4.0 release notes](release-notes-0.4.0.md) describe the feature set and
platform boundaries; the [0.4.1 release notes](release-notes-0.4.1.md) explain
the Bash enter-mode behavior introduced by that release.

## Shells and everyday commands

- **NixOS and non-FHS installations:** hooks resolve and pin trusted helper
  executables instead of assuming `/usr/bin` and `/bin` contain them. Ordinary
  commands are no longer discarded because those helper paths are absent
  ([#239](https://github.com/sheeki03/tirith/issues/239)).
- **npm installations:** on Unix, initialization binds Bash, zsh, and fish
  hooks to the running native Tirith executable. The Node launcher no longer
  sits between the shell and receipt registration. Other platforms retain
  shell PATH resolution. The npm launcher also preserves signal termination
  and nonzero child exits.
- **Sourced loaders:** `shell/tirith.sh` finds its own directory in Bash and
  zsh, including installation paths containing spaces or apostrophes.
- **mise installations:** `doctor` recognizes a shim that resolves to the
  current executable instead of reporting a shadow-binary conflict
  ([#240](https://github.com/sheeki03/tirith/issues/240)).
- **False positives:** Go `./...` package patterns, ordinary home-directory
  paths, and Codex zsh environment snapshots using `[[` and `alias -L` no
  longer produce the reported incomplete-analysis errors
  ([#235](https://github.com/sheeki03/tirith/issues/235),
  [#236](https://github.com/sheeki03/tirith/issues/236),
  [#237](https://github.com/sheeki03/tirith/issues/237)).

These changes retain signature, ownership, receipt, and enforcement checks.
Unsupported containment platforms remain unsupported; this patch does not
extend the Linux-only package-installation or capsule guarantees.

## ThreatDB publication and updates

The daily source fetch previously failed when npm returned valid package
metadata as `application/octet-stream`. The fetcher now accepts that response
only after strict JSON-object parsing and an exact package-name check. Invalid
metadata still aborts the publication transaction.

Git timestamps are compared as instants, so equivalent timezone offsets no
longer fail provenance checks. Written provenance remains canonical UTC and
retains chronological validation.

The source-pin watcher separates read-only validation from PR publication,
supports the repository workflow token, and finds existing proposals reliably.
Generated manifest transitions reject stale publication pointers. Source-pin
proposals still require review before adoption.

The reviewed OpenSSF and DataDog snapshots advance to September 11 revisions,
with matching attribution entries in `NOTICE`. The candidate snapshots passed
source fetching and compilation before adoption; upstream scripts are not run.
The ecosyste.ms pin remains unchanged.

Dual-mode clients quietly use the supported v1 channel when the server has not
published a v2 index. Authentication, signature, integrity, and other server
failures remain visible
([#238](https://github.com/sheeki03/tirith/issues/238)). The minimum client
version for the v2 database remains 0.4.0.

Long-running processes now detect same-second database replacements and changes
to the selected database path. The cache publishes the accepted database and
its source metadata together, retaining signature and sequence rollback checks.

## Performance and diagnostics

- Legacy database lookups for npm, RubyGems, Go, and Maven use their sorted
  package index directly. Ecosystems with spelling aliases retain canonical
  lookup behavior.
- Custom rules compile once per analysis request. The per-thread DSL regex
  cache is bounded, and rule-ID redaction is deferred until a warning is emitted.
- Recent-log commands read a bounded suffix instead of parsing the entire audit
  history. `explain`, `doctor`, and incident reports disclose partial coverage.
  Doctor JSON gains the additive `audit_history_truncated` field.
- Bash prompt callbacks avoid unnecessary history-capture subprocesses.
- Legacy session correlation projects its event window once when expiring a
  batch of warning markers, preserving the existing matching and privacy rules.
- Daemon enrichment reuses the policy resolved for the initial analysis,
  preventing inconsistent decisions if configuration changes during a request.

Fuzz and packaging workflows cancel superseded pull-request checks. Release-tag,
scheduled, and other non-PR runs remain independent.

The license-service source also fixes token refresh for entitled trial
subscriptions. Operators running that service must deploy the updated service;
upgrading a CLI installation alone does not deploy a license backend.

## Upgrade

Use the package manager that owns your installation:

```bash
npm install -g tirith@0.4.2
cargo install tirith --version 0.4.2 --locked
brew update && brew upgrade tirith
```

```powershell
scoop update
scoop update tirith
choco upgrade tirith --version=0.4.2
```

Standalone installations can use `tirith update`, which verifies the release
before replacing the executable. Signed platform archives, the installer,
Debian/RPM packages, and verification material are available from
[GitHub Releases](https://github.com/sheeki03/tirith/releases/tag/v0.4.2).
The release workflow also updates the project Homebrew tap, Scoop bucket, AUR
package, and versioned GHCR images.

Homebrew core and Chocolatey community moderation are independent of the
project's publication jobs. Check the version your package manager offers; if
it has not reached 0.4.2, use the project tap or a signed GitHub release artifact.
Distribution-maintained packages, including nixpkgs, may also update later.
Do not mix installation methods without first resolving which binary your
shell invokes.

After updating, restart your shell and agent host, then run:

```bash
tirith --version
tirith doctor
tirith threat-db update
```

For Bash, `tirith doctor --simulate-enter` refreshes the delivery/blocking
self-test for the installed Bash binary. Restart Bash afterward to load the
verified mode. Agent integrations can be refreshed using their existing
`tirith setup <host>` command.

Thanks to everyone who reported problems and supplied reproductions. The
reports above directly shaped this release.
