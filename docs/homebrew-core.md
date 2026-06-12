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

Note on the test flags: `--offline` was added after v0.3.1, so it exists in
v0.3.2. If you ever submit v0.3.1 instead, the test must use the env var
(`ENV["TIRITH_OFFLINE"] = "1"`) since v0.3.1 has `--no-daemon` but not `--offline`.

## Verified locally (2026-06-12)

Run against the v0.3.1 source tarball plus the current 0.3.2 binary, on
Homebrew 5.1.14:

- `brew style` -> no offenses.
- `brew audit --strict --new --online` -> exit 0, clean.
- Source build via the formula's exact method
  (`cargo install --locked --bin tirith --path crates/tirith`) -> builds, binary
  reports the right version.
- `tirith completions {bash,zsh,fish}` -> real completion scripts (3020 / 2243 /
  396 lines), so `generate_completions_from_executable` works.
- `tirith manpage` -> valid roff (`.TH` header present).
- The offline test command -> exit 1 and `curl_pipe_shell` (confirmed in both the
  v0.3.1 env-var form and the v0.3.2 `--offline` flag form).

The build mechanics and completion/man generation are identical for v0.3.2; only
the tarball URL and sha256 change.

## Finalize when v0.3.2 ships

1. Cut the v0.3.2 GitHub release so `archive/refs/tags/v0.3.2.tar.gz` resolves.
2. Compute the sha256 and replace `FILL_ON_RELEASE` in `packaging/homebrew-core/tirith.rb`:
   `curl -sSL -o t.tgz https://github.com/sheeki03/tirith/archive/refs/tags/v0.3.2.tar.gz && sha256sum t.tgz`
3. Re-run the local gate against v0.3.2 (a scratch tap or a homebrew-core clone):
   `brew install --build-from-source tirith && brew test tirith && brew audit --strict --new --online tirith && brew style tirith`
4. Open the PR (next section).

## Self-updater note (state this proactively in the PR)

Homebrew dislikes formulae that self-update. tirith does NOT: `tirith update`
refuses to self-modify a package-manager install and instead prints
`brew upgrade tirith` (see `crates/tirith-core/src/selfupdate.rs` and
`crates/tirith/src/cli/selfupdate.rs`). Mentioning this up front avoids a likely
reviewer objection.

## Submission

1. Search open PRs at Homebrew/homebrew-core for "tirith" to avoid a duplicate.
2. Fork Homebrew/homebrew-core.
3. Add the formula at `Formula/t/tirith.rb` (the contents of
   `packaging/homebrew-core/tirith.rb`, sha256 filled).
4. Open a PR titled `tirith 0.3.2 (new formula)` with a one-paragraph description
   and the self-updater note above.
5. BrewTestBot builds and bottles the formula on each macOS version and Linux and
   runs the audit and test. Address maintainer feedback. A clean new formula
   typically merges in days to a couple of weeks.

After merge, `brew install tirith` works globally and is trusted by default. The
tap can stay for nightlies, but the short `tirith` name resolves to core.

## Links

- [Acceptable Formulae](https://docs.brew.sh/Acceptable-Formulae)
- [Adding Software to Homebrew](https://docs.brew.sh/Adding-Software-to-Homebrew)
- [Formula Cookbook](https://docs.brew.sh/Formula-Cookbook)
- [Tap Trust](https://docs.brew.sh/Tap-Trust)
