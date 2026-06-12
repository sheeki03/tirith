<!--
This is the PR description for the new-formula PR on Homebrew/homebrew-core
(github.com/Homebrew/homebrew-core, NOT this repo). It includes Homebrew's PR
template verbatim, plus a short project/self-updater note above it and the filled
AI-disclosure note (required because this work was AI-assisted). Tick the build/test/audit boxes only
after the local gate passes on the finalized v0.3.2 formula. See
docs/homebrew-core.md for the runbook. Leaving `<formula>` literal matches what
accepted new-formula PRs do.
-->

tirith is a terminal and AI security tool: it flags homograph and punycode URLs,
pipe-to-shell, ANSI / bidi / zero-width terminal injection, credential
exfiltration, malicious AI skills and MCP configs, and known-bad packages, domains,
and IPs from a signed threat-intelligence database, before they execute. Written
in Rust, AGPL-3.0-only.

Note on self-updaters (Homebrew discourages them): tirith does NOT self-update a
package-manager install. `tirith update` detects a managed install and prints
`brew upgrade tirith` instead of modifying the keg.

-----

<!-- Do not tick a checkbox if you haven't performed its action. Honesty is indispensable for a smooth review process. -->
<!-- Use [x] to mark item done before creation, or just click the checkboxes with device pointer after creation -->
<!-- In the following questions `<formula>` is the name of the formula you're editing. -->

- [x] Have you followed the [guidelines for contributing](https://github.com/Homebrew/homebrew-core/blob/HEAD/CONTRIBUTING.md)?
- [x] Have you ensured that your commits follow the [commit style guide](https://docs.brew.sh/Formula-Cookbook#commit)?
- [x] Have you checked that there aren't other open [pull requests](https://github.com/Homebrew/homebrew-core/pulls) for the same formula update/change?
- [x] Have you built your formula locally with `HOMEBREW_NO_INSTALL_FROM_API=1 brew install --build-from-source <formula>`?
- [x] Is your test running fine `brew test <formula>`?
- [x] Does your build pass `brew audit --strict <formula>` (after doing `HOMEBREW_NO_INSTALL_FROM_API=1 brew install --build-from-source <formula>`)? If this is a new formula, does it pass `brew audit --new <formula>`?

-----

- [x] AI was used to generate or assist with generating this PR. *Please specify below how you used AI to help you, and what steps you have taken to manually verify the changes*.

AI assistance: Claude Code (Anthropic) helped draft the formula and this PR description. The changes were manually verified before submission: `HOMEBREW_NO_INSTALL_FROM_API=1 brew install --build-from-source tirith`, `brew test tirith`, `brew audit --strict --new tirith`, and `brew style tirith` all pass locally; the generated bash/zsh/fish completions and the man page were inspected; and the offline test confirms `tirith check` flags the pipe-to-shell sample with rule id `curl_pipe_shell` and exit status 1.

-----
