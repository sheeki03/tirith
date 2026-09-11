# Tirith 0.4.1 release notes

Tirith 0.4.1 is a patch release on the 0.4 line. It changes no schema, adds no
command, and removes nothing. The [0.4.0 release
notes](release-notes-0.4.0.md) remain the description of what the 0.4 line
does; this document covers what 0.4.1 changes on top of it.

One item here is a real behaviour change rather than a fix in the usual sense:
bash now blocks. Read that section before upgrading a bash workstation.

## The headline: bash actually blocks now

In 0.4.0 and every release before it, bash enter mode could not deliver a
command. A bare `bind -x` on Enter runs the bound function but does not then
accept the line on stock bash, so the hook captured the typed command and then
dropped it. The capability self-test detected exactly that and correctly
refused to enable enter mode, which is why 0.4.0 was safe. The cost was that
every bash user fell back to warn-only preexec, and the only way to get real
blocking on bash was `TIRITH_BASH_PREEXEC_ENFORCE=1`. Issues #111 and #224.

0.4.1 binds Enter to a readline macro instead: the macro runs the checker and
then a guarded accept-line whose accept half is a no-op until the checker arms
it. The prompt hook re-disarms it at every prompt, so possession of the accept
sequence on its own can never accept a line, and `operate-and-get-next`
(Ctrl-O), which would otherwise accept a line without consulting the checker,
is unbound while enter mode owns delivery. Bindings and the startup health gate
cover `emacs-standard`, `vi-insert`, and `vi-command`, so a later `set -o vi`
cannot expose an unguarded Enter, and a user's own Ctrl-O binding is captured
per keymap and restored if the hook degrades.

The self-test now returns `works` on stock GNU bash, which means enter mode is
the ordinary outcome rather than a rare one.

**What you should expect after upgrading.** On a bash workstation that
previously printed a DETECTED banner and ran the command anyway, tirith will
now refuse the command. That is the intended behaviour, and it is what the
zsh and fish hooks have always done. If you need the old behaviour for a
session, `export TIRITH_BASH_MODE=preexec` before the `tirith init` line.

Run `tirith doctor --simulate-enter` after upgrading to refresh the cached
capability verdict for your bash. The cache is keyed on the bash binary and
version, so it does not carry over from a different bash.

The gate itself is unchanged from 0.4.0: enter mode is selected only when the
self-test has proven delivery for that exact bash, and an SSH session, a
persisted safe-mode flag, or a forced `TIRITH_BASH_MODE=preexec` still selects
preexec.

## Silent downgrades to legacy mode

Two separate paths dropped a shell to legacy mode with no execution receipts,
and neither said why. Both were reported in issue #221.

- **A symlinked install on macOS.** `std::env::current_exe` returns the launch
  path unresolved on macOS, so registering the receipt capability through
  Homebrew's `/opt/homebrew/bin/tirith` or an npm wrapper hit the `O_NOFOLLOW`
  identity open on the symlink itself and failed with `ELOOP`. The launch path
  is canonicalized first now. The no-follow open and every ownership and
  permission check still run against the resolved path, so a symlink swapped in
  after canonicalization still fails closed.
- **A zsh prompt framework that installs a `WINCH` trap.** The zsh hook
  registered its receipt instance through a command substitution, and the Rust
  side binds the capability to its immediate parent pid. Whenever zsh's exec
  optimization is suppressed while the rc file is sourced, which a `WINCH` trap
  earlier in the rc reliably triggers, the substitution ran behind an
  intermediate fork and registration was rejected. zsh now registers with a
  plain foreground command, the way the bash hook already did.

All three hooks also stop discarding the registration error. The first line of
the rejection is kept and printed under the legacy-mode warning, so a downgrade
now says why instead of leaving you to guess.

`noclobber` is handled too. A redirect into a file `mktemp` already created
fails under `noclobber`, and the bash hook used a plain `>` throughout; those
redirects are now forced.

## Guidance that was wrong

- The warn-only block advisory recommended "an enter-capable shell (bash
  5+/zsh/fish)", so a bash 5 user was told to switch to bash 5. It now names
  zsh or fish, plus the path that blocks on bash without enter mode.
- `tirith doctor` prints the concrete remedy when bash is not blocking, and
  says that a forced `TIRITH_BASH_MODE=enter` has to go, because preexec
  enforcement only arms in a shell that starts in preexec mode.
- `tirith receipt` said it managed execution receipts. It fronts the download
  receipts `tirith run` writes; shell execution receipts are a separate store
  with no CLI viewer. Help, empty-store message, and the compatibility matrix
  now say so.
- The repository-policy neutralization notice was keyed on the merged policy's
  scope, which since the baseline plus overlay merge is the trusted baseline's
  scope. Anyone with a user or org policy therefore never saw it. It is keyed
  on the recorded drop set now.
- `TIRITH_BASH_REQUIRE_ENTER` is displayed by doctor but consumed nowhere. It
  is labelled reserved rather than implying an enforcement that does not exist.

## Self-update on Hermes-managed installs

A Tirith release cached under a Hermes root matched no branch of
`detect_install_method`, so on a Debian or RPM host it was misclassified as an
apt or dnf install. `tirith update` then exited successfully having changed
nothing, advising a `dpkg -i` or `rpm -U` of a package the user never
installed, and `--rollback` refused outright.

Such an install is now recognized as self-replaceable and runs the existing
verified path unchanged: signed download, mandatory cosign verification, atomic
swap keeping the `tirith.tirith-previous` sidecar, and rollback. Recognition is
proof-based and Unix-only. The root, every traversed directory, and the binary
must be owned by the current effective uid, must not be symlinks, must carry no
group or world write bit, and must carry no ACL entry granting write to another
principal; system, Homebrew, and Nix roots are denied outright, and a tree
carrying Cargo's install metadata is never granted self-replacement. The proof
is re-run immediately before the swap and again before a rollback.

`tirith version --provenance` and `verify-self` report `hermes`. The public
`tirith_core::selfupdate::InstallMethod` enum is deliberately untouched, so
this patch release adds no variant to a public API.

Updates remain manual and explicit. Tirith still never checks for or installs a
new binary in the background.

## ThreatDB source pinning

The reviewed OpenSSF and DataDog source pins advance to 2026-08-31 revisions,
and the per-source fetch budget rises from 180s to 300s to materialize them.
The 600s end-to-end transaction deadline is unchanged and remains the stricter
ceiling. Content hashing no longer forks a subprocess per file, which on the
current OpenSSF tree was close to half a million of them; the replacement
computes a byte-identical digest, and a fixture test recomputes it with the old
shell implementation and fails on any difference.

`.github/threatdb-source-pins.json` is now the manifest builds resolve those
revisions from, and a daily workflow proposes updates to it instead of applying
them. The watcher only ever selects a completed OpenSSF `Assign IDs` boundary,
proves each candidate with a real fetch and compile before opening anything,
runs on the read-only workflow token, holds no signing key, publishes no
database, and pushes only to its own automation branch. Published provenance
now records when each pinned commit was authored and when its pin was selected,
and the compiler verifies both against the checked-out tree rather than
trusting the document.

**Pipeline configuration:** validation runs with a read-only token. A separate
publication job uses the repository's `GITHUB_TOKEN` to open the review PR;
enable “Allow GitHub Actions to create and approve pull requests” in repository
Actions settings. Approve the resulting pending workflow runs before merging.
An optional `THREATDB_PIN_PR_TOKEN` secret (contents plus pull requests, scoped
to this repository) lets those PR workflows start automatically. Neither job
receives the production signing key, and pins still require human review.

## Upgrade and installation

Use the same package manager that owns the current installation:

```bash
brew upgrade tirith
npm install -g tirith@0.4.1
cargo install tirith --version 0.4.1 --locked
```

```powershell
scoop update tirith
choco upgrade tirith
```

Chocolatey's community-repository moderation can lag the GitHub release. Run
`choco info tirith` to see the approved version; use Scoop or a signed GitHub
release artifact when the newest version is required before moderation
finishes.

After upgrading, restart your interactive shells. The hooks pin one absolute
Tirith executable when they are sourced, so a live shell keeps running the
previous binary until it restarts. On bash, run `tirith doctor
--simulate-enter` in the fresh shell to refresh the enter-mode capability
verdict.

## Compatibility

0.4.1 is a patch release inside the supported 0.4.x line.

- No policy, document, receipt, or command-card schema changes.
- No new or removed subcommands, and no change to the frozen MCP `tools/list`.
- No change to the public `tirith_core` API surface, including
  `InstallMethod`.
- ThreatDB provenance gains two optional fields. Provenance written before this
  release carries neither and still validates, so older signed generations keep
  verifying.
- `V2_MIN_VERSION` stays at 0.4.0: 0.4.0 is still the first release that ships
  the v2 database reader, and a 0.4.0 client remains eligible for the v2 asset.

## Known limitations that remain

Every limitation listed under "Known issues" in the
[0.4.0 changelog entry](../CHANGELOG.md) is unchanged and still applies, with
one narrowing: the full-disk lockout entry says bash is unaffected because it
degrades to preexec. That is still true, and 0.4.1 does not change it for zsh
or fish.

## Publication and verification

0.4.1 is published only from the protected `v0.4.1` tag on the default-branch
commit, through the same signing, attestation, and single-use registry checks
0.4.0 used. See the [release checklist](release-checklist.md) for the sequence
and the post-publication verification steps.
