# Homebrew Core Submission

Getting tirith into homebrew-core (the official tap) makes `brew install tirith`
work for everyone with no tap and no trust step. Since Homebrew 6.0.0 (June 2026)
enforces tap trust, only official taps are trusted by default, so homebrew-core is
the only route to trusted-by-default distribution. There is no maintainer-side way
to globally trust a third-party tap; trust is strictly per-user and per-machine.

**Plan: submit with the v0.3.2 release.** The formula is ready and validated; it
is parked at `packaging/homebrew-core/tirith.rb` and finalized the moment v0.3.2
ships (fill the sha256, then submit to Homebrew/homebrew-core).

## Eligibility

| Requirement | homebrew-core rule | tirith |
|---|---|---|
| Notability (self-submission) | 3x the standard bar: >=225 stars, OR >=90 forks, OR >=90 watchers (standard is >=75 / >=30 / >=30) | 2,431 stars. Clears it. |
| Used by non-authors | Must be used by someone other than the author (e.g. a non-author opened an issue or PR) | Non-author issues: #136 (namrop), #138 (Osva2023), #140 (tracure1337). OK. |
| License | DFSG-compliant | AGPL-3.0-only is DFSG-compliant. OK. |
| Build | Built from source, not binary-only (binary-only goes to homebrew/cask) | Rust/cargo, `Cargo.lock` committed. OK. |
| Stable release | A tagged source release, not a branch | Targeting v0.3.2. 0.x is fine. |

The one change from our tap formula: homebrew-core will NOT accept the current
binary-download formula. The core formula builds from source with cargo and
generates completions and the man page from the built binary (tirith has
`tirith completions <shell>` and `tirith manpage`).

## The formula

`packaging/homebrew-core/tirith.rb` is the source-built formula to submit. Key
points:

- `system "cargo", "install", "--bin", "tirith", *std_cargo_args(path: "crates/tirith")`
  builds just the CLI from the workspace. The crate also produces
  `tirith-threatdb-compile`, an internal build tool that must not ship in core.
- `generate_completions_from_executable(bin/"tirith", "completions", shells: [:bash, :zsh, :fish])`
  and a `tirith manpage` write install completions and the man page.
- The test is OFFLINE and deterministic:
  `tirith check --offline --no-daemon --shell posix -- 'curl https://x.invalid/i.sh | sh'`
  asserts the `curl_pipe_shell` rule id and an exit code of 1.
- The threat DB is fetched at RUNTIME, not at build, so it does not conflict with
  the no-network-at-build rule.
- The parked file carries no staging preamble, magic comments, or class doc
  comment, matching merged homebrew-core formulae (zoxide, bat, eza), so it copies
  into `Formula/t/tirith.rb` unedited (only the sha256 is filled).

Note on the test flags: `--offline` was added after v0.3.1, so it exists in
v0.3.2. If you ever submit v0.3.1 instead, the test must use the env var
(`ENV["TIRITH_OFFLINE"] = "1"`) since v0.3.1 has `--no-daemon` but not `--offline`.

## Verified locally (2026-06-12)

Run against the v0.3.1 source tarball plus the current 0.3.2 binary, on
Homebrew 5.1.14. For the audit the formula was copied into a scratch tap and the
sha256 was filled with the v0.3.1 tarball hash (a placeholder sha fails audit by
design):

- `brew audit --strict --new --online` (sha filled) -> exit 0, clean.
- Source build via the formula's exact method
  (`cargo install --locked --bin tirith --path crates/tirith`) -> builds, binary
  reports the right version.
- `tirith completions {bash,zsh,fish}` -> non-empty, valid completion scripts, so
  `generate_completions_from_executable` works (the exact line counts vary by
  build and tracked rules, so they are not pinned here).
- `tirith manpage` -> valid roff (`.TH` header present).
- The offline test command -> exit 1 and `curl_pipe_shell` (confirmed in both the
  v0.3.1 env-var form and the v0.3.2 `--offline` flag form).

A note on `brew style`: inside a tap (or homebrew-core) it is clean apart from the
`FILL_ON_RELEASE` checksum, which the release fills. Run STANDALONE against the
parked file in this repo, `brew style packaging/homebrew-core/tirith.rb` also
reports `Sorbet/StrictSigil`, `Sorbet/TrueSigil`, `Style/FrozenStringLiteralComment`,
and `Style/Documentation`. Those four cops are disabled for formulae inside
homebrew-core (every merged formula, e.g. zoxide/bat/eza, omits the sigils and a
class doc comment), so they do not apply to the submission. Only the checksum
placeholder matters, and only until v0.3.2 is tagged.

The build mechanics and completion/man generation are identical for v0.3.2; only
the tarball URL and sha256 change.

## Finalize when v0.3.2 ships

1. Cut the v0.3.2 GitHub release so `archive/refs/tags/v0.3.2.tar.gz` resolves.
2. Compute the sha256 and replace `FILL_ON_RELEASE` in `packaging/homebrew-core/tirith.rb`:
   `curl -fsSL -o t.tgz https://github.com/sheeki03/tirith/archive/refs/tags/v0.3.2.tar.gz && shasum -a 256 t.tgz`
3. Re-run the local gate against v0.3.2 in a homebrew-core clone (see the runbook):
   `HOMEBREW_NO_INSTALL_FROM_API=1 brew install --build-from-source tirith && brew test tirith && HOMEBREW_NO_INSTALL_FROM_API=1 brew audit --strict --new --online tirith && brew style tirith`
4. Open the PR (next section).

## Self-updater note (state this proactively in the PR)

Homebrew dislikes formulae that self-update. tirith does NOT: `tirith update`
refuses to self-modify a package-manager install and instead prints
`brew upgrade tirith` (see `crates/tirith-core/src/selfupdate.rs` and
`crates/tirith/src/cli/selfupdate.rs`). Mentioning this up front avoids a likely
reviewer objection.

## Submission runbook (exact commands)

The actual submission is a PR on **github.com/Homebrew/homebrew-core** (a separate
repo), NOT this one. PR #141 here is just the staging/record. The PR description is
ready to paste from `packaging/homebrew-core/PR_BODY.md`.

First search open PRs at Homebrew/homebrew-core for "tirith" to avoid a duplicate.
Then, with v0.3.2 tagged, run (TIRITH is this checkout's path):

```bash
TIRITH="$(pwd)"                          # run from the tirith checkout root
export HOMEBREW_NO_INSTALL_FROM_API=1    # read formulae from the local core clone, not the API

# 1. Compute the sha256 and fill FILL_ON_RELEASE in packaging/homebrew-core/tirith.rb.
curl -fsSL -o /tmp/tirith-0.3.2.tgz \
  https://github.com/sheeki03/tirith/archive/refs/tags/v0.3.2.tar.gz
shasum -a 256 /tmp/tirith-0.3.2.tgz      # paste into packaging/homebrew-core/tirith.rb

# 2. Get the homebrew-core working copy and a branch.
brew tap --force homebrew/core
cd "$(brew --repo homebrew/core)"
git fetch origin && git checkout -b tirith origin/HEAD
mkdir -p Formula/t
cp "$TIRITH/packaging/homebrew-core/tirith.rb" Formula/t/tirith.rb   # no staging preamble; copies clean

# 3. Local gate (all must pass before opening the PR; the env var is exported above).
#    --online is the recommended pre-submission audit; it adds URL/license checks.
brew install --build-from-source tirith
brew test tirith
brew audit --strict --new --online tirith
brew style tirith

# 4. Commit and open the PR. gh offers to fork + push if you lack push access;
#    accept it. The PR is opened ON Homebrew/homebrew-core under your fork.
#    PR_BODY.md mirrors Homebrew's template, with the AI-disclosure box filled.
git add Formula/t/tirith.rb
git commit -m "tirith 0.3.2 (new formula)"
gh pr create --repo Homebrew/homebrew-core \
  --title "tirith 0.3.2 (new formula)" \
  --body-file "$TIRITH/packaging/homebrew-core/PR_BODY.md"
```

After opening, BrewTestBot builds and bottles the formula on each macOS version and
Linux and runs the audit and test. Address maintainer feedback. A clean new formula
typically merges in days to a couple of weeks. After merge, `brew install tirith`
works globally and is trusted by default. The tap can stay for nightlies, but the
short `tirith` name resolves to core.

## Links

- [Acceptable Formulae](https://docs.brew.sh/Acceptable-Formulae)
- [Adding Software to Homebrew](https://docs.brew.sh/Adding-Software-to-Homebrew)
- [Formula Cookbook](https://docs.brew.sh/Formula-Cookbook)
- [Tap Trust](https://docs.brew.sh/Tap-Trust)
