# Policy resolution: first foundation slice

Implements part of WP01, covering baseline F02 / acceptance A01. It does not
complete the field-provenance, revision or preview contracts.

`policy_snapshot::resolve_runtime_policy` is now the shared resolver for the
engine and `EffectivePolicySnapshot`. It preserves the existing ordering:
trusted local baseline plus repository tightening; authenticated remote
replacement/fallback; incident restrictions; user lists; repository blocklist;
user trust; context labels; SSH host labels. The engine calls this directly,
without adding serialization or hash computation to command checks.

The CLI supports:

```sh
tirith policy effective                         # existing offline default
tirith policy effective --local-only --json     # explicit compatibility view
tirith policy effective --runtime --format json # same resolver as enforcement
```

The offline default still excludes remote resolution and separate list/trust/
label files. It now says so. Making the default contact a policy server would
break the established network-free contract, so runtime resolution is opt-in.
The runtime route may refresh the existing remote cache, but never analyzes or
executes a command and does not append session/warning events.

Primary source and scope come from the resolved policy object. A separate
filesystem discovery previously could report a repository path while the actual
policy retained the user baseline's source. Neither primary source nor scope is
complete field provenance: additional restrictions can come from other layers.
Neutralized repository fields are reported even when the primary scope is user
or organization.

The JSON envelope retains `source_path`, `scope`, `neutralized_fields` and
`policy`, adding `schema_version: 1` and `resolution`. The latter identifies the
resolution mode, whether remote configuration was evaluated and separate overlay
loading enabled, the existing non-secret policy-posture hash, effective failure
and bypass settings, and explicitly unavailable evidence. Enabling overlay
loading does not establish that every optional file was present or readable.

`policy` is a redacted display projection and must not be saved back as
configuration. Arbitrary API-key values and webhook-header values are hidden by
field, and display content also receives built-in and custom redaction. Dynamic map keys (including aliases and header names)
also receive redaction; collisions retain separate display entries. Custom
patterns can replace strings in this display; protocol scope/mode, effective
failure/bypass settings, schema and posture hash are separate and preserved.
Threat-intelligence credentials retain their existing serialization exclusion.
Both human and JSON presenters use the same display projection. JSON stays on
stdout and diagnostics stay on stderr; policy discovery failure retains the
existing inspection exit contract and appears in the resolved fail-closed policy.

This snapshot cannot authorize Apply or execute a preview. Its posture hash is
not an input revision, proof of remote freshness, or guard against file changes.
Field-level provenance, requested profile/version, remote fetch timestamps,
per-overlay availability, trust-expiry deadline and input-generation identities
remain explicit gaps. They must be added before revision-bound mutation APIs.

Meaningful checks for this slice:

```sh
cargo test --locked -p tirith-core --lib policy_snapshot::tests -- --test-threads=1
cargo test --locked -p tirith-core --lib force_full_runner_evaluates_regex_rule_and_returns_effective_policy
cargo test --locked -p tirith --test policy_effective_snapshot
```

The regressions cover trusted/repository composition, user/repo lists and labels,
rule-scoped/expired trust, offline versus deterministic remote refusal, snapshot
stability after edits, accurate primary source, retained CLI flags/streams,
credential redaction and broad custom patterns matching envelope tokens. Native
host behavior and atomic multi-input revision capture remain separate gates.
