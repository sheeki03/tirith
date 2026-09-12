# Decision messages and audit tuning

This document describes the decision wording and history-tuning boundaries in
WP02 and WP09. The implementation also provides frozen evaluation and reviewed
local feedback; these remain separate from permission and execution receipts.

## Human decision output

The color and plain renderers share the same action labels:

| Existing action | Human label | Existing exit code |
| --- | --- | --- |
| `allow`, with findings | ALLOWED WITH ADVISORY | 0 |
| `warn` | WARNING | 2 |
| `warn_ack` | CONFIRMATION REQUIRED | 3 |
| `block` | BLOCKED | 1 |

These are action exit codes, not every caller's final exit: legacy `check`
callers can require acknowledgement for `warn` under CLI/policy `strict_warn`
without changing the stored action. The shared renderer therefore makes no
claim that a `warn` action is exempt from acknowledgement.

A supplied warn-only integration capability changes the block label to DETECTED
and states that this hook does not withhold execution. It does not claim the
command subsequently ran. The acknowledgement label also discloses that such a
hook cannot enforce acknowledgement. These labels describe the decision and
supplied integration capability, not independently observed interception or
execution.

Existing `analysis_incomplete`, `output_analysis_overflow`, and
`wrapper_chain_too_deep` findings add an explicit ANALYSIS INCOMPLETE note. The
note does not replace the final action or reinterpret incomplete coverage as
proof of malicious content. Findings continue to provide the specific gap and
reason.

A URL or domain trust hint is labelled as an exception to review. It covers the
shown target and rule only if policy permits it, tells the operator to re-check
the command, and names up to five other reported rules requiring review. A
domain hint still explicitly discloses whole-domain scope and `--broad`. The
renderer does not evaluate a hypothetical grant and cannot promise that the
command will become allowed. Existing redaction, shell quoting, retained-finding
selection, and presentation bounds remain in use.

## Tuning from history

`tirith policy tune --from-audit` reports rules present in at least five blocked
check records separately from policy relaxation suggestions. This report is
available even below the twenty-record recommendation threshold. Up to ten
rules are displayed, ordered by blocked check count; existing JSON `rule_stats`
retains all counts.

Counts are per check, not per occurrence of a rule in its findings. Duplicate
rule IDs within a check no longer inflate the numerator. Legacy `WarnAck` and
serialized `warn_ack` both count as warnings. Multiple rules may appear in the
same blocked check, so the counts do not assign causality, prove interception,
or establish a false positive.

No-suggestion output states that the history does not establish a safe
relaxation. Guidance points to `tirith policy effective --runtime` and an
authorized policy target. It explicitly explains that repository policy cannot
lower severity or suppress findings, and that user settings remain subject to
applicable restrictions. No policy or audit file is changed.

Existing JSON keys, action tokens, suggestion kinds, stdout/stderr routing, and
exit contracts are preserved. Human wording is intentionally corrected.

## Verification and remaining work

Focused regression targets:

```sh
cargo test -p tirith-core output::tests
cargo test -p tirith-core audit_tune::tests
cargo test -p tirith --test policy_tune_decisions
```

The tests cover action/exit/JSON compatibility, both renderers, incomplete
coverage, warn-only limitations, multiple independent findings, blocked-only
and thin history, duplicate rules, warning spelling, target guidance, and
read-only tuning.

Frozen evaluation now captures detector evidence and available cached threat
enrichment, then compares policies without execution, receipt consumption or
state updates. Its explanations retain contributing restrictions and explicit
gaps for unavailable sessions, baselines, enrichment or changed detector inputs.
CLI/browser simulation and impact reviews use that frozen context. Missing
evidence never becomes proof of complete analysis.

Bounded tuning reads freshly redacted examples and explicitly selected local
feedback labels through the same history reader. Labels are reversible review
metadata, not trust grants. The full browser candidate exercised tuning,
feedback, impact apply/undo and history paging; revision-specific results and
remaining native/release qualifications are recorded in [verification](verification.md).
Shell-appropriate recovery remains a separate [contract](recovery.md).
