<!--
Paste this as the PR description for the new-formula PR on Homebrew/homebrew-core
(github.com/Homebrew/homebrew-core, NOT this repo). Check the boxes only after the
local gate (brew install --build-from-source / brew test / brew audit --strict
--new / brew style) passes on the finalized v0.3.2 formula. See
docs/homebrew-core.md for the exact command runbook.
-->

tirith is a terminal and AI security tool. It intercepts shell commands, pasted
content, and scanned files to catch homograph and punycode URLs, pipe-to-shell,
ANSI / bidi / zero-width terminal injection, credential exfiltration, malicious
AI skills and MCP configs, and known-bad packages, domains, and IPs from a signed
threat-intelligence database, before they execute. Written in Rust, AGPL-3.0-only.

Homepage: https://github.com/sheeki03/tirith (2,400+ stars).

Note on self-updaters (Homebrew discourages them): tirith does NOT self-update a
package-manager install. `tirith update` detects a managed install and prints
`brew upgrade tirith` instead of modifying the keg
(`crates/tirith-core/src/selfupdate.rs`, `crates/tirith/src/cli/selfupdate.rs`).

- [x] Have you followed the guidelines for contributing?
- [x] Have you ensured that your commits follow the commit style guide?
- [x] Have you checked that there aren't other open pull requests for the same change?
- [x] Have you built your formula locally with `brew install --build-from-source tirith`?
- [x] Is your test running fine with `brew test tirith`?
- [x] Does your formula pass `brew audit --strict --new tirith` and `brew style tirith`?
