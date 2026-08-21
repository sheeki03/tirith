# Cross-workflow artifact flow

`tirith scan` correlates a repository's GitHub Actions workflows and reports one
specific trust break: an untrusted contributor's workflow uploads a build
artifact, and a privileged `workflow_run` workflow downloads that artifact from
the triggering run and then executes, sources, PATH-mutates, publishes, or
deploys it.

This is the Safe and Bybit class of build-output compromise. The artifact is the
trust boundary, and CI is where it is usually forgotten.

## Why it is a repository post-pass

No single workflow file can prove a producer-to-consumer chain. The producer and
the consumer are different files, and the binding between them is an artifact
name plus a run id.

So `crates/tirith-core/src/rules/workflow_artifacts.rs` reduces each workflow to
a bounded `WorkflowModel` and `analyze_repository` correlates the models.
`crates/tirith-core/src/scan.rs` owns the plumbing; the analyzer itself reads
neither the filesystem nor the network, and every function in it is total, so a
malformed or hostile workflow yields no findings rather than a panic.

**Consequence an operator must know:** the post-pass runs only for a directory
scan, and "directory scan" is not the CLI alone. It lives inside `scan::scan`
(`scan.rs:254`, invoking it at `:436`), so it runs for `tirith scan`
(`crates/tirith/src/cli/scan.rs:248`), the `tirith_scan_directory` MCP tool
(`crates/tirith-core/src/mcp/tools.rs:742`), and both MCP scan resources
(`crates/tirith-core/src/mcp/resources.rs:153` and `:244`). An agent gating on
`tirith_scan_directory` gets the chain findings and the downgraded severity just
as the CLI does.

Per-file analysis never runs it: `tirith check` on a single workflow file, the
`tirith_scan_file` MCP tool via `scan_single_file_guarded`, and the LSP.

## What a High requires

`workflow_artifact_poisoning` (High) fires only for the complete proven chain:

```
fork/PR-reachable untrusted producer
  -> uploads an artifact under a statically known name
  -> privileged `workflow_run` consumer bound to the TRIGGERING run
  -> matching artifact identity
  -> execute / source / PATH-mutation / publish / deploy sink
```

Anything less is represented as INCOMPLETENESS, never guessed. Each of these
records an unresolved note instead of a finding: an expression, a wildcard, a
reusable workflow, a composite action, a matrix job, an `if:` condition, a
download mechanism or post-download command outside the modelled tables, an
artifact re-upload hop, a digest comparison whose expected value cannot be
placed, and a shell the analyzer cannot resolve.

Containment is what proves an execute, source, or PATH-mutation sink touched the
artifact's bytes, so the extraction directory has to be the REAL one.
`actions/download-artifact`, `dawidd6/action-download-artifact`, and
`gh run download` each fan every artifact of the run into its own
`<path>/<artifact-name>/` subdirectory unless they are given exactly one
artifact name, and the model follows that rule rather than assuming a flat
extraction.

An artifact re-upload hop is not followed. A `workflow_run` workflow that
downloads a cross-run artifact and then uploads one of its own is republishing
bytes of untrusted provenance under a NEW identity, and following that would
need taint propagation this pass does not do. A consumer bound to such a relay
is therefore bound to an artifact of unknown provenance, not of known-clean
provenance.

A digest comparison whose expected value came from INSIDE the downloaded tree
suppresses nothing. Naming it in the evidence is what tells the operator their
check is self-referential rather than absent.

## The presence-level rule, and its conditional downgrade

`workflow_run_trigger` is the pre-existing presence-level finding: this
repository has a privileged `workflow_run` workflow at all. It is High.

The post-pass may lower it to Medium, but only for a consumer it had COMPLETE
visibility into and proved no chain for. Completeness is destroyed by any
exhausted bound, any workflow that panicked, and any workflow that did not
parse, so a bounded scan degrades to "not proven either way" rather than to
"clean". A workflow that could not be parsed could be an untrusted producer, so
its mere presence removes the right to say no chain exists.

The lowering happens only in the post-pass, never in `rules::cifile`, because
the four surfaces listed above cannot run the post-pass and must keep the
original severity. A downgrade there would have weakened `tirith check`, the MCP
scan tool, and the LSP.

## Bounds

| Bound | Value |
|---|---|
| workflows modelled per repository | 256 |
| aggregate YAML source retained | 32 MiB |
| aggregate steps modelled | 4096 |
| segments per `run:` body | 512 |
| words per segment | 256 |
| bytes per word | 4096 |

A dropped workflow gets its own typed coverage gap, which becomes an
`analysis_incomplete` finding through the normal driver path, plus one stderr
note per scan rather than one per workflow. A monorepo therefore cannot turn the
bound into thousands of diagnostic lines while losing nothing machine-readable.

## What this is not

- **Not enforcement.** This is a scanner finding. Tirith does not stop a
  workflow from running, does not talk to the GitHub API, and does not gate a
  merge. A CI job can fail on the finding through `tirith scan --ci` if an
  operator wires it that way.
- **Not a general Actions linter.** It answers one question about artifact
  provenance. Pinning, permissions, and secret exposure are covered by the
  existing `cifile` rules, separately.
- **Not taint propagation.** One hop is modelled. A relay is treated as unknown
  provenance rather than followed.

## See also

- [Enforcement coverage](enforcement-coverage.md), the per-capability ledger
- [Threat model](threat-model.md)
