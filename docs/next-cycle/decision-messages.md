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

For example, `BIN=/bin/echo; $BIN --help` (unquoted) or
`false && BIN=/bin/echo; "$BIN" --help` (assignment may not run) has an
unresolved command name. Use the literal command path, `/bin/echo --help`, when
that is the intended command, then check that exact command again.

`BIN=/bin/echo; "$BIN" --help` itself is analyzed as
`BIN=/bin/echo; /bin/echo --help`, with every finding of that literal form
(POSIX shells only). This applies to the command line itself, never to a
nested body such as `bash -c '...'`, `eval` or `$(...)`, because a nested body
can inherit functions and aliases from the enclosing command. It needs a
literal value assigned unconditionally at the top level, the variable quoted as
the command word, and nothing else in the command that can rebind it: no
function or alias definition, no other builtin except `echo`, `printf`,
`test`/`[`, `true`, `false`, `:` and `pwd` (zsh module builtins such as `stat`
count as other builtins), no arithmetic (`((`, `$[`, zsh `$NAME[...]`
subscripts, a `printf` numeric conversion of a name-like argument, `test`
integer comparisons or zsh `test -t`, an assignment to an integer-typed shell
parameter such as `MAILCHECK`), zsh `$~`/`$=`/`$^` expansions, unquoted
expansions in a command, `${...}` assignment forms, subshells, heredocs, line
continuations or history expansion. Custom regex rules match both the command
as typed and its literal form, and `tirith rule test` evaluates both forms the
same way `tirith check` does. A failed assignment (a read-only or integer variable inherited
from the shell) aborts the rest of the line in bash, zsh, sh, dash and ksh, so
the expansion cannot run with the inherited value. State the command cannot
show, such as live aliases, functions or variable attributes like
`typeset -u`, is outside the analysis, exactly as it is for a literal command
name.

JSON clients can distinguish this limitation through
`findings[].rule_id == "analysis_incomplete"` while continuing to honor the
returned `action` and show any other findings. A coverage limitation is not a
malicious-content finding. Normal command JSON does not expose a universal
coverage-status boolean; file and project scan reports have their own coverage
fields.

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
