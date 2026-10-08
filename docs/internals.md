# Internals

Contracts and mechanisms behind the user-facing features, for maintainers and
reviewers. User guides start at [everyday workflows](user-journeys.md); the
[command reference](commands.md) lists every command.

- [Install channels, update compatibility and owned configuration](#install-channels-update-compatibility-and-owned-configuration)
- [Output privacy and compatibility contracts](#output-privacy-and-compatibility-contracts)
- [Decision messages and audit tuning](#decision-messages-and-audit-tuning)
- [Recovery at the execution boundary](#recovery-at-the-execution-boundary)
- [History reading](#history-reading)
- [Audit segment retention](#audit-segment-retention)
- [Effective policy snapshot](#effective-policy-snapshot)
- [Personal profile ownership](#personal-profile-ownership)
- [Trust grant storage and mutation](#trust-grant-storage-and-mutation)
- [Shell targets and protection evidence](#shell-targets-and-protection-evidence)
- [Task command families (Python and Cargo)](#task-command-families-python-and-cargo)
- [ThreatDB publication operations](#threatdb-publication-operations)
- [Allocation and timing gates](#allocation-and-timing-gates)
- [Native mixed-version audit harness](#native-mixed-version-audit-harness)
- [Native service update coordination harness](#native-service-update-coordination-harness)
- [Windows workspace test job](#windows-workspace-test-job)

## Install channels, update compatibility and owned configuration

`tirith version --provenance --json` and the local lifecycle API report separate
facts for the running binary, release discovery, the owning package channel,
and an inherited shell integration. Reading these facts does not execute other
Tirith binaries, query package managers, request elevation, or establish that a
hook actually blocks commands.

### Version and channel facts

The installed version comes from the running binary's build metadata. Release
and channel-available versions remain null until their own source is queried;
GitHub release discovery does not establish availability in a package-manager
repository. A loaded integration's `TIRITH_INTEGRATION_VERSION` and
`TIRITH_INTEGRATION_SHELL` are inherited, unverified evidence. Equal versions do
not establish active protection. A mismatched version requires a fresh shell or
host reload and another behavioral verification. An absent marker means unknown.

Generated shell activation stamps a version only when the sourced hook bytes
match the binary's embedded hook. An older external hook bundle reports
`unknown`. PATH scanning counts distinct resolved binaries with a bounded scan;
unresolved wrappers and an incomplete scan remain explicit.

| Owning channel | Detection and upgrade behavior |
| --- | --- |
| Shell installer / standalone | Only a resolved installation in a recognized user-local location can self-update. Existing protected helper state remains a paired transaction. |
| Hermes | Requires the existing exact ownership/provenance proof; an expired proof refuses replacement. |
| Debian / RPM | Distro refinement is limited to recognized system binary directories. Use the owning package manager. |
| Homebrew / npm / Cargo / Scoop / AUR | Existing channel-specific paths and package-manager guidance apply; the CLI does not replace managed binaries. |
| Chocolatey | Recognize the package's `chocolatey/lib/tirith` path. Use `choco upgrade tirith` with the permissions required by that Chocolatey installation. |
| Nix | Recognize the immutable `/nix/store` path. Update the owning profile, flake, or Home Manager configuration. A source-built binary is honestly unverified against generic release bytes. |
| mise | Recognize Tirith's GitHub/Cargo backend install paths. Use `mise upgrade tirith --no-prune` to retain the previous installed version. The Cargo carveout requires Tirith's own valid local Cargo install record. |
| asdf | Recognize `.asdf/installs/tirith` and custom `asdf/installs/tirith` paths. Install with `asdf install tirith latest`, then select the intended project/user scope explicitly with `asdf set`. |
| Unknown / custom / unresolved shim | Remain non-self-modifying. Host OS alone cannot turn an arbitrary path into a package-manager installation. |

The [mise upgrade reference](https://mise.jdx.dev/cli/upgrade.html),
[asdf version-management reference](https://asdf-vm.com/manage/versions.html),
and [Chocolatey upgrade reference](https://docs.chocolatey.org/en-us/choco/commands/upgrade/)
describe those manager commands and their scope. Retaining an older binary does
not automatically make newer policy, grant, lock, or journal formats compatible
with it.

### Signed compatibility artifact

Release publication creates `release-compatibility.json` before generating
`checksums.txt`; the existing exact-tag Sigstore signature covers its checksum
alongside every other payload. The document binds the release version, each
canonical target archive SHA-256, the exact root CLI executable SHA-256, readable
policy, MCP lock and trust versions, lock formats that can authorize execution,
and the readable persisted-state contract versions (`state_contract_versions`).
Generation reads archive members without executing candidates. It rejects
missing targets, duplicate or escaping members, links, special files, and
oversized archives. Changed format constants require review of the contract
before another publication.

| Stored surface | Current reader | Compatibility consequence |
| --- | --- | --- |
| Policy | Schemas 1 and 2; forward migration occurs in memory | Future or malformed versions fail closed. Updates preserve existing file bytes. |
| MCP lock | Formats 4–8 readable; only 8 authorizes a live gateway | Older formats are migration inputs and require explicit reapproval. |
| Legacy trust | Version 1 | Existing expiry and authority rules continue to apply. |
| Scoped trust grants | Store schema 1 | 0.4.2 ignores the separate grant store; downgrade loses these exceptions rather than making them global. Unknown newer schemas are inactive. |
| Operation journal | Schema 1 with the exact originating client version | Another client version cannot silently replay or undo an old mutation. |
| Local control service | Protocol 1, exact binary version and SHA-256 | Reuse requires the full identity; an update must quiesce writes and reconcile pending jobs. |
| Team connection, enrollment, report and rollout records | Each schema 1; team policy semantics 1 | Candidates must retain team Runtime enforcement and explicit report/rollout recovery. A missing reader or capability refuses update and rollback, even if the old binary has the same package version. |
| Shell execution receipts | Schema 3 active/unacknowledged records; schema 4 acknowledged terminal records | A receipt is acknowledged only after an observed terminal result: the same `consume`, `discard` or `reconcile` call that succeeds retires it (best effort), and a separate `acknowledge` call from an older hook is accepted as a no-op. Schema 4 is non-authorizing and eligible for the next locked cleanup; schema 3 recovery windows are preserved. Schema 1/2 are authenticated retirement inputs only. Older readers reject schema 4; missing reader declarations refuse update/rollback. Hook capability schema 3 is unchanged. Explicit ACK may end only its own exact clean shell-boundary record's retention at the actual acknowledgment time, advancing the ledger generation without upgrading its unresolved evidence. The observation remains available to normal reads until existing pressure or stale-session cleanup reclaims it; warnings, escalation, typed events and later transitions keep their existing retention. |

One persisted-state contract version (currently 1) covers every row above except
policy, MCP lock and trust, which keep their own reader lists: the operation
journal, the local control service, the team records with Runtime enforcement
and recovery, shell execution receipts, and byte-preserving configuration
updates. A candidate or rollback point must declare that it reads the current
contract version; a missing or different declaration means unsupported and is
not filled from the running client's capabilities. Local team and receipt stores
are checked against this binary's own contract readers, so a store written by a
newer contract is refused. Publication checks the actual writer/reader constants
against the contract and refuses an unreviewed format change; changing any of
them requires a new contract version.

Inventory reads only fixed private team files, the bounded team rollout directory,
and shell receipt declarations in the private session receipt directory. Known receipt locks, hook capability
and hook load-record filenames are skipped; this inventory does not authenticate or declare compatibility
for their payloads. The same captured bytes
also expose document schemas and policy semantics inside enrollment caches and
both rollout policy documents; future or malformed nested declarations refuse.
It uses the existing
guarded native readers, caps directory entries and total bytes, and reports
unknown names, partial scans, changed inventories and unreadable records as
incompatible. These observations expose no credentials, stored contents or paths.
Target-local package checkpoints are **not discovered** by this inventory.
This is not a claim that
all pending operations have been discovered, reconciled, or successfully recovered.

Local format observations report only the surface, declared version, and
readability. They omit policy contents, grant patterns, service credentials,
and paths. A declared version is unverified local metadata, not a successful
candidate compatibility check. Unknown, malformed, and future versions remain
visible rather than being treated as empty legacy state.

`tirith update --dry-run --json` fetches the compatibility document and checksum
verification material without downloading or executing the candidate binary.
Its preview binds the selected release, target archive and executable hashes to
the readable local formats. Replacement repeats the format and preimage checks
before publication. Missing compatibility metadata, unreadable local formats,
unsupported feature contracts, or an invalid signature refuse the update.
An explicit `--allow-unsigned` can accept missing signature tooling or material;
the evidence then says checksum-only and does not claim signature verification.
It never permits an invalid available signature.

Before replacing a running binary, the updater preserves its current format
contract in an adjacent receipt bound to that binary's exact SHA-256. Rollback
checks this receipt against the saved executable and current local formats,
preserves configuration bytes, and refuses modified evidence. These receipts
record the previously running binary's contract; they are not release signatures.
Older backups without a receipt require a compatible release through the owning
installation channel. Retention is bounded to 64 receipt generations; reaching
that bound requires reviewing obsolete receipts while keeping those for the live
and saved previous executable. Updates do not erase manually edited evidence.

Update and rollback quiesce the current operator's local control service and
retain its launch and lifetime locks through replacement and verification. Active
jobs must drain within the bounded wait; the updater does not force-kill them or
claim to quiesce another user's service. A fresh shell or host reload and another
behavioral verification are required after replacement.

### Owned configuration and removal

Configuration changes use the shared operation journals and ownership-aware
change plans. Undo restores only unchanged owned fields, blocks, or files; newer
manual edits are conflicts. An update must not copy old configuration wholesale
over current user edits. Disablement, removing an integration, uninstalling the
owning package, and deleting retained data are separate operations. Package
installation or removal follows the administrator policy for that destination;
personal setup does not implicitly select another user's home or invoke sudo.

The optional native package-approval capability is separate from ordinary
command checks and shell protection. Package metadata does not install or
suggest sudo. `tirith pkg approve` issues no approvals in this release, and the
packaged helper refuses every operation, so neither sudo nor the helper enables
approval.

## Output privacy and compatibility contracts

MCP, CLI, history, support-export and dashboard output share one set of
schema-selected projections. This section lists which fields are protocol
(preserved exactly) and which are content (redacted and bounded).

### Implemented boundary inventory

| Boundary | Protocol fields | Content fields | Enforcement |
| --- | --- | --- | --- |
| JSON-RPC envelope | `jsonrpc`, request correlation `id`, numeric error code | Error message and error data | The request ID is echoed exactly, including string IDs. Errors retain redaction and transport bounds. |
| MCP initialize | Supported `protocolVersion`, server name/version, capability keys | None | Generated metadata is emitted without content redaction. Unsupported requested versions receive the preferred supported version through existing negotiation. |
| MCP tool/resource list | Names, descriptions, URI/MIME, input-schema types, enums, required-field names and receipt schema | None; all definitions are generated by Tirith | The complete generated definitions survive broad custom DLP patterns. |
| MCP tool result | `content[].type = text`, booleans/counts, schema-positioned canonical action/rule/severity enums | Text, paths, finding titles/descriptions/evidence, policy diagnostics, caller identity labels, unknown fields | The tool name selects a private projection contract. Sensitive fields receive the tool policy and the dispatcher's frozen session DLP policy before bounding. |
| MCP task/boundary assessment | Mode, effects, enforceability, boundary/outcome, provenance enums, receipt status, schema/envelope versions | Outcome reason, rejection detail, unknown future fields | Diagnostic metadata stays distinct from enforcement evidence. The task text JSON is regenerated from the redacted structured projection. |
| MCP scan | Rule/severity/evidence type, gap kind, validated SHA-256, counts and completeness flags | Paths, finding content, gap locations, panic paths, truncation prose | File/directory/gap schemas are selected explicitly. A digest does not imply that omitted analysis succeeded. |
| MCP cloaking | Fixed probe profile names and task-boundary enums | URL, remote diff content, finding content, error text, unexpected profile names | The remote output filter still runs. Custom DLP then applies to the content projection. |
| `tirith://project-safety` resource | Exact generated URI, MIME and scan protocol fields | Scan content inside the resource's JSON text | Parse and redact the scan projection before encoding it as resource text; do not redact the JSON string as prose. |

The shared implementation is in `crates/tirith-core/src/output_contract.rs`.
Tirith-owned producers select an explicit schema. External/upstream MCP payloads continue
through `output_filter`; an upstream server cannot select these exemptions.

An exemption depends on both schema position and a canonical value. A field
called `action` inside arbitrary content receives redaction. Unknown fields and
invalid enum strings receive redaction. Free-form rule IDs and caller labels are
content. String-backed verdict approval fields preserve only recognized action
and built-in rule tokens. Broad custom patterns still redact the same tokens
when those tokens occur in user content.

`redact_json_strings` remains appropriate for content subtrees and error data.
It must not be used on an entire protocol envelope or encoded structured JSON.
Numeric/boolean presentation and analysis markers retain their existing meaning.

### Signed data

The current MCP tools return receipt **status**, not signed authorization
receipts. Receipt-bearing input schemas are generated protocol metadata and are
preserved; receipt input is not echoed as a display object. The correction does
not change receipt parsing, signing, verification or replay consumption.

Canonical signed material must be preserved in its canonical store. A display
projection is not a substitute for that material and must never be passed to a
verifier, signer, execution boundary or replay consumer. If newer policy requires
additional redaction, derive a separate display view and label it as such; do not
weaken redaction or claim the modified view still verifies. Existing artifact
receipts already require redacted inputs before hashing/signing.

### Compatibility decision

Command-check JSON defaults to the frozen schema-3 contract. Callers explicitly
select `tirith check --format json --json-schema 4` to include typed recovery
advice. Both versions retain the same action and exit code. Schema selection is
rejected without JSON output and cannot be combined with approval checks or
execution receipts. `tirith commands check` keeps its existing schema-3 output.

This correction preserves current field names, serialized enum spellings,
optional fields, stdout/stderr routing and process exits. It repairs corruption
of existing contracts and does not introduce a new envelope version. Existing
MCP versions remain supported. The default tool list stays unchanged; preview
tools remain behind `TIRITH_MCP_PREVIEW`.

Future fields may be additive only when absence retains the older meaning and
old clients can ignore the field safely. A new required field, changed enum
meaning, narrower permission, altered execution behavior, or changed signed
representation requires a versioned contract with explicit negotiation or a
refusal. Transport-version negotiation alone must not be treated as permission
to enable a new mutation capability. Dashboard changes go through typed plans
and the shared operation service, never through these output projections.

Result states must retain these distinctions:

| State | Required interpretation |
| --- | --- |
| Absent | No value was supplied or observed; not success or zero. |
| Unknown | Available evidence cannot classify the state. |
| Partial | Some evidence was analyzed; completeness/presentation flags identify the limit. |
| Unsupported | This implementation cannot provide the requested capability or validate this format. |
| Unverified | Evidence exists or may be absent, but no verification claim is made. |
| Failed | An attempted operation/check failed; preserve its error/refusal indicator. |

These are interpretation rules, not a newly introduced universal status enum.
In particular, MCP task `receipt_status=unverified` grants nothing, `complete=false`
is not a clean pass, and a truncated presentation retains its explicit markers.

### Coverage

Regression tests cover a complete initialize/list/check/task session under a
catch-all custom pattern with the output filter enabled and disabled, exact
correlation IDs, legacy protocol negotiation, preview receipt schemas, task
receipt status, task text/structured agreement, encoded resource JSON, scan
digests and completeness markers. Additional cases pin built-in secret redaction,
unknown fields and malformed protocol values. Existing output-filter, bound and
policy-diagnostic tests remain applicable.

CLI `commands` decisions, `fetch` task assessments, `install`, `paste`, `run`,
`scan`, `score`, and shared `output.rs` now select schemas at their producing
boundaries. Run receipt displays preserve validated digest/time/privilege fields
while URLs, paths and analysis prose receive DLP. Safe suggestions retain their
rule identity; an executable suggestion is omitted when its display would alter
the analyzed bytes. History displays contain no signature or chain hash, retain
canonical actions/rules/timestamps, and freshly redact recorded content.
Schemas are not a global key allowlist. The effective policy snapshot has its
own explicitly redacted display projection; it is not canonical or round-trip
editable, and its enforcement-posture hash is not a full policy revision
identity. Support exports and dashboard output retain bounded content, fresh
redaction and explicit signed/display separation.


### Bounded saved receipt access

CLI views and the public Rust download/artifact receipt readers share one bounded
store reader. A record is limited to 1 MiB; inventory to 10,000 entries and 16 MiB
of record bytes; cached script verification streams at most the downloader's
10 MiB ceiling. Oversized historical metadata returns an explicit read-limit
error. The writer's historical format and signed bytes are not rewritten.

Files must be native regular files opened without following a leaf symlink.
Embedded download hashes and artifact receipt IDs must match their requested
filenames. Invalid inventory is an error rather than an empty history; valid
download and artifact schema 1/2/3 records can share the directory. Public list
methods retain newest-first ordering. Loading a record for inspection does not
validate its signature, content address or publication authority. Those checks
remain mandatory at the corresponding authority boundary. Read diagnostics use
static descriptions without echoing stored content.

## Decision messages and audit tuning

Decision wording, history tuning, frozen evaluation and local feedback labels.
None of these is a permission or an execution receipt.

### Human decision output

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

Existing `analysis_incomplete`, `package_lookup_incomplete`,
`output_analysis_overflow`, and `wrapper_chain_too_deep` findings add an
explicit ANALYSIS INCOMPLETE note. `package_lookup_incomplete` (Medium) means a
live package lookup (OSV.dev, deps.dev) for a package being installed did not
complete, for example offline with no cached answer; `analysis_incomplete` is
kept for command structure tirith could not analyze, so a policy can treat the
two differently. The
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

A command word whose directory is a double-quoted parameter expansion and
whose file name is literal (`"$VIRTUAL_ENV/bin/python" -m pytest`,
`"$REPO_ROOT/scripts/test.sh"`, `"${PROJECT_DIR}"/bin/run`) is analyzed as
that file name in a placeholder directory (`/tirith-inherited-dir/bin/python
-m pytest`). The quotes keep it one word and the `/` makes the shell run that
file directly, so only the directory is unknown, and every rule that keys on
the program name (`bash -c`, `sh` at the end of a pipe, `sudo`) still applies.
This applies only to a variable the command line does not mention anywhere
else (`D=/tmp; "$D/x.sh"`, `read D` or `echo "$D"` keep the word unresolved),
and when a tainted download's path ends with the same file path, the
execution is still reported as `exec_of_tainted_file`. Unquoted
(`$D/x.sh`), operator (`${D:-/tmp}/x`) and positional (`"$1/x"`) expansions,
a substitution, an expansion after the last `/`, or an empty, `.` or `..`
component in the file path (`"$D//x.sh"`, `"$D/./x.sh"`, `"$D/a/../x.sh"`,
which a taint mark's normalized path would not end with) stay unresolved, as
does such a word inside a nested body.

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

### Tuning from history

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

### Frozen evaluation and feedback

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
metadata, not trust grants. Shell-appropriate recovery is described in
[Recovery at the execution boundary](#recovery-at-the-execution-boundary).

## Recovery at the execution boundary

`tirith check` prints guidance for the exact input's shell and command shape.
Machine callers opt into the versioned `recovery` projection with
`--format json --json-schema 4`. Ordinary JSON remains schema 3 with its existing
fields; `--json-schema 3` selects that contract explicitly. Selecting a JSON
schema without JSON output is refused before analysis. Neither version changes
the decision or exit code. The projection uses the same
inline-bypass parser as runtime. A policy-enabled POSIX/Fish pipeline can receive
a `TIRITH=0 ` prefix hint; compound and background forms that runtime rejects do
not. PowerShell and Cmd environment assignments persist beyond one operation, so
the one-use recovery projection reports that capability as unsupported.

The projection contains no command text or command digest. It lists the current
restriction rule IDs, and never grants execution permission. An exception preview
must be evaluated independently to establish which other restrictions remain.
When policy disables bypass, including incident mode, no bypass is offered.

Acknowledgement and hard Block remain separate. Browser confirmation and
`tirith pending resolve ID approve` cannot authorize a blocked command. The latter
records a review decision only. Existing shell protocol-v3 receipts own permitted
approval and acknowledgement at Tirith's execution prompt, bind the exact
secret-sealed command/CWD/session/hook process/executable/policy/expiry, re-evaluate
at consumption, and refuse changed commands or replay. Receipt consumption after
a crash reconciles its durable ledger before any retry can proceed. Ordinary
operation journals never store those secret-bearing command bytes.

Missing private scratch storage or helper executables can fail before Tirith
runs. Bash/Zsh/Fish capture-failure diagnostics therefore describe opening a
separate terminal without startup hooks, inspecting the pinned helpers and
writable `TMPDIR`, running doctor, and restarting to verify. `TIRITH=0` cannot
repair that failure. A clean diagnostic terminal is not represented as protected.

Init-generated activation snippets report `TIRITH_INTEGRATION_VERSION` and
`TIRITH_INTEGRATION_SHELL` after sourcing. A version is emitted only when the hook
bytes match the running binary's embedded copy; another bundle reports `unknown`.
Status labels these inherited values as unverified. They help identify a loaded
old integration after an update, but do not constitute a fresh blocking probe.

## History reading

`history::HistoryReader` is a read-only, stateless reader for one path chosen
by the CLI or local service. A browser supplies filters and an issued cursor,
never a filesystem path or byte offset. Each request reads at most 2 MiB plus
bounded generation anchors, retains at most 500 records, and rejects individual
lines over 1 MiB. The reader keeps no cursor table: a cursor carries its own
read position and is sealed with a per-reader random secret over the read
direction, the filter, the opened file's identity and the inspected prefix, so
it cannot be forged, retargeted or replayed against another source.

CLI recent-history, tuning and incident feedback select the newest matching
records within a bounded suffix. Activity opens on the newest page and offers
older pages. These cursors retain their upper byte boundary when new records
arrive; explicit refresh reads the latest records. Each returned page is
chronological, and Activity renders the newest records first. A record cut by
the byte-window boundary is recovered on the older page when it is within the
per-record size limit.

`earlier_history_uninspected` reports the omitted prefix even when all retained
records match the query. The separate forward-reader interface retains its
append-aware cursors, including incomplete last lines until the writer finishes
them. Cursors are bound to their read direction and filter. Malformed records,
oversized lines, unknown source, disabled logging and unavailable data are
separate from an empty result.

Record IDs combine a reader generation (keyed by the reader secret, the file
identity and its first record) with the original byte position. Retries within
that generation return the same IDs. Replacing/truncating the file, changing the
filter, restarting the reader, or altering a cursor requires the consumer to
replace its view. File identity is obtained from the open native handle;
bounded head/tail anchors also detect truncation and tail replacement.

The Activity summary is rebuilt from one bounded read of the newest 2 MiB suffix
on every request, so nothing is cached between requests and every report
replaces the previous one (`replace_previous` is always true).

This is an append-oriented display index, **not an integrity verifier**. It does
not establish that an arbitrary earlier byte range was unchanged between reads.
The existing audit verifier remains authoritative for chain/signature checks;
verification failure requires rebuilding the display view. Canonical signed
lines remain untouched. Display projections omit signature material and apply
the current DLP rules to historical content.

An ordinary verdict record means a recorded check. Hook telemetry is an
observation; a task-boundary entry is an assessment. None is silently promoted to
proof that execution happened or was prevented. Recorded actions and policy
paths retain their historical attribution.

The live dashboard, the Activity summary and retention transactions use shared
core and CLI services. Retention preserves signed segment/head evidence and
explicitly addresses older writers; this reader does not rotate or delete
anything.

### Append-failure observations

Instrumented audit writers record an actual append failure without changing an
ordinary check's verdict. Required audit writes still refuse their operation on
failure. Audit-lock acquisition has a 250 ms deadline; the first observed failure
in a process emits a generic warning that recorded history may be incomplete.

For the default audit destination, the CLI attempts to store a private notice of
at most 1 KiB with a 25 ms coordination-lock wait. It retains the first valid
notice, preserving existing invalid or changed data rather than replacing it.
Repeated failures do not accumulate recovery copies. The notice contains only a
canonical observation ID, time and a private destination binding, with no command
or error text. The binding is excluded from public reports.

Status, doctor, bounded history, Overview and Activity distinguish an observed
failure, disabled logging and unknown recording state. A prior failure does not
prove that the writer is still failing; absence of a notice does not prove
complete history. Missing, unreadable, oversized, corrupt, future-dated or
destination-mismatched notices cannot become a healthy result. Failure to persist
a notice can leave later processes with unknown state. These observations cover
instrumented default-log writers only, not every possible source of lost data.

## Audit segment retention

Retention creates an explicit checkpointed segment. It does not silently remove a signed prefix to stay under a size cap. The active log keeps its inode and native exclusive lock so an already-open older writer remains serialized with rotation. Existing writers derive their next link and count from that same locked handle after acquiring the lock.

A rotation plan binds the operator, captured policy, operation UUID, active log identity and exact digest, original head receipt, archived line count, immutable segment checkpoint, and replacement genesis/head bytes. The journal contains those bounded metadata values; the original log is streamed to private archive storage rather than copied into the journal. Planning verifies integrity through the same retained-handle verifier used by ordinary audit verification.

The write order is:

1. Publish and sync exact original log bytes, its original head receipt and the checkpoint in private archive storage; verify the archived digests.
2. Publish a bounded rotation barrier in the active head file while holding the active log lock. This intentionally fails the older `HeadReceipt` grammar. A writer entering after a crash refuses to append until recovery finishes.
3. Truncate the same active inode, sync, write and sync the new checkpoint-linked genesis.
4. Publish the corresponding valid head receipt and sync it before releasing the lock.

Signed segments retain their original signatures and signed head. The new checkpoint/genesis/head must be signed when the prior segment or local signing configuration requires signing. An unavailable key refuses the operation before truncation. Rotation does not delete signing keys or reinterpret previously signed records as unsigned.

Recovery recognizes the exact original, original behind barrier, empty behind barrier, planned genesis behind barrier, and complete new segment. A completed rotation followed by new records can reconcile as applied only when the exact planned genesis remains and the active chain verifies. An exact partial genesis or exact archived-prefix compensation can resume only behind this operation’s barrier. Unknown or unrelated bytes remain explicit recovery failures; they are never overwritten by an optimistic retry. A failure while holding the barrier may temporarily make older appenders report storage failure, which is safer than accepting a record into an ambiguous chain.

Undo verifies the private archive and restores active bytes only before later active records exist. Even one later append prevents compensation. Archives remain retained as recovery evidence after undo. When the original log had no head, compensation may add a computed head for the restored log instead of reintroducing missing verification metadata; this is reported as retained metadata, not exact metadata absence.

The mutation service supplies private native file capabilities, policy preflight/publication authorization, idempotent operation status, cancellation and bounded jobs. Archive export is an explicit separate action. Deletion must identify a retained segment and leave a checkpoint/tombstone that distinguishes unavailable history from an intact retained chain. Neither export nor deletion targets the live log through an arbitrary browser path.

Qualification must include real appenders waiting across the same-inode rotation, interruption at each durable boundary, signed and unsigned logs, missing keys, modified archives, subsequent append followed by undo refusal, oversized/corrupt histories and storage errors. Native Windows lock and ACL behavior requires native qualification; parser fixtures or a macOS run do not supply that evidence.

Exports select a recorded segment UUID and copy its exact chunk bytes, original head and checkpoint into a separate private bundle. The manifest is published last. Export undo removes only unchanged owned copies; it leaves the source segment and active chain alone.

Deletion requires an explicit irreversible choice. It publishes a deletion record before removing the selected segment’s exact chunks, original head and manifest. The checkpoint and deletion record remain available. Interrupted deletion resumes from the remaining owned files; changed bytes require review. A completed deletion has no undo route, and an active-chain verification result does not establish availability of deleted historical records.

## Effective policy snapshot

`EffectivePolicySnapshot::resolve(cwd, Runtime)` executes the same resolver as
enforcement: trusted local baseline, repository tightening, configured remote
replacement/fallback, incident restrictions, operator and repository lists,
operator trust, and context/SSH labels. `LocalOnly` remains an explicitly limited
diagnostic. It omits remote resolution and separate list/trust/label files.

The observer records input bytes when the runtime reads them and records field
contributions at the actual composition boundaries. It does not discover or read
policy a second time to manufacture provenance. Missing discovery candidates
are revision inputs: creating a policy after preview invalidates a defaults-only
snapshot. A source can constrain a field even when the existing value is already
equally restrictive. Repository neutralization includes its reason and source.

`policy effective --runtime --json` exposes the snapshot identity, primary/all
input revisions, field sources, constraints, operator target scopes, trust
generation and nearest accepted grant expiry, requested profile and effective
customizations, and remote availability/fallback/freshness. The legacy policy
object remains a redacted display projection. It must never be reapplied as YAML.
Paths and dynamic field keys are projected; opaque identities and protocol
status values are preserved even with broad custom DLP expressions.

Revision IDs are random identifiers of this particular observation. No public
revision is a hash of secret-bearing policy bytes or environment credentials.
The snapshot and its private witnesses are not serializable and their Debug
projection omits policy values. The protected operation journal may persist a
`PrivatePolicyReplayGuard`, which binds canonical effective policy and actual
captured inputs; that guard is private comparison material and must never be
included in public output. It is neither a bearer token nor permission to write.

`revalidate_inputs()` compares the captured inputs using the original scoped
readers and rejects changed bytes, new/missing files, changed roots/environment,
incident changes, or expired grants. Trusted managed policy symlinks continue
using the bounded symlink-following reader; repository reads retain their
no-follow containment. Revalidation reads fresh incident semantics. It does not
re-fetch remote policy or create a second policy snapshot.

`revalidate_for_mutation()` additionally requires full Runtime resolution and
rejects configured remote authority. The current remote fetch protocol has no
atomic server revision precondition; re-reading a local cache cannot prove that
the server still authorizes a write. Mutation services must still authorize the
operator and scope, lock and compare target preimages, apply once, and verify
effective readback. A local snapshot revalidation is not a filesystem transaction.

Successful validated fetches retain client receipt/validation times and bounded
Date/ETag/Last-Modified evidence. Cache metadata is stored in a separate receipt
bound to the exact origin/credential-bound v1 cache envelope bytes, preserving
compatibility with old binaries that reject unknown cache fields. An older cache,
missing/malformed receipt, mismatched generation, or future timestamp reports
unknown freshness without changing established cached-fallback enforcement.
Server headers are evidence, not authority. A cache write/receipt interruption
can lose freshness evidence but cannot certify a mismatched policy generation.

## Personal profile ownership

`protection_profiles::prepare_change` is a pure document transformation. It
returns proposed YAML and a public changes/custom-overrides projection to the
shared operation service. It performs no write. Apply records the selected name,
version, and precisely which fields it inserted. Existing explicit settings are
preserved, including manual approval rules. Switching presets replaces only
unchanged owned defaults; reset removes only unchanged owned defaults. A manual
edit made after selection survives both switching and reset. Unknown versions,
duplicate ownership entries, and ownership of fields outside the named definition
are rejected.

Enforcement settings are materialized as existing policy fields. The profile
marker records intent and ownership and never causes hidden runtime defaults.
An older client that ignores the marker still enforces the concrete policy.
Repository markers are neutralized and cannot claim ownership of operator
preferences. Shipped v1 definitions are immutable; a behavior change requires a
new version, a behavior comparison, and an explicit update operation/release note.
There is no automatic profile promotion or observe-only preset.

The corpus covers ordinary Git/Go/npm commands, quoted output, ordinary downloads,
nearby download-and-execute/exfiltration controls, selected versus unselected
advisories, unsupported prompt hosts, and strict incomplete-analysis handling.
Reset, repeated apply, unrelated settings, forged ownership, unknown versions,
and old-reader materialization have independent regressions.

`tirith onboard` recommends personal Balanced v1 by default and with `--repo`.
Detected CI workflows, AI instructions and MCP configuration remain inventory
signals; they no longer choose `ci-strict`, `ai-agent-heavy` or `individual` as
an inferred personal preference. Explicit `--team` and `--ai-agent-heavy` retain
their legacy template selections. The schema-1 onboarding report keeps
`recommended_template` as an accepted legacy fallback (`individual` for personal
setup), so older consumers can still pass it to `policy init --template`.
`recommended_profile` and `recommended_profile_version` carry the primary
versioned personal recommendation; current next steps and apply use that route.
Profile-aware consumers should prefer those fields when present and otherwise
use the legacy template field. `balanced` is not a legacy template name.

## Trust grant storage and mutation

New grants live in the operator configuration directory's `trust-grants.json`.
Its version-one envelope has `schema_version` and `grants`; it deliberately has
no `entries` member. A 0.4.2 client ignores this store. Even if someone copies
this envelope over a legacy `trust.json`, that client's entry reader finds no
grants. A new project grant never enters a legacy globally interpreted entry.

Each new record has a random UUID, target pattern, optional rule, scope,
creation timestamp, optional expiry, optional reason and optional revocation
timestamp. UUIDs are public identities, not hashes of sensitive target content.
The operator store and the mutation journal are private files. CLI projections
redact targets, rules, reasons and project paths while preserving validated
identities and lifecycle states.

Mutations use the shared typed, revision-bound operation service and
configuration-write authorization. The journal binds exact preimages, owned
postimages, operator and policy authority. Refresh and retry are explicit when
authority changes. Multi-file migration removes legacy applicability before
activating the new envelope, so interruption can temporarily narrow trust but
cannot widen it. Runtime resolves both stores for every request, including
daemon requests, and snapshots retain the earliest accepted expiry plus input
revisions. The checkout identity is captured only when the grant store holds a
project-scoped record. Removing a grant or reaching its deadline needs no cache-file
rewrite to affect the next request.

Regression coverage resides in `trust_grants` core tests and the
`trust_lifecycle` CLI tests: old envelope compatibility, invalid expiry,
stable-ID edits, remaining broader grants, checkout identity boundaries,
project-store removal, migration, explicit broadness and redacted projections.

## Shell targets and protection evidence

Setup, doctor and `tirith output wrap` share `cli::shell_target`. An observed ancestor process
selects the shell family; an environment default is explicitly weaker evidence.
Unknown shells have no inferred Bash target. Status can measure the observed
executable's version with bounded, sanitized child execution; polling and prompt
paths do not launch version probes.

| Family | Personal startup targets |
| --- | --- |
| Bash | `.bashrc` for interactive non-login shells, plus the first existing `.bash_profile`, `.bash_login`, or `.profile` for login shells; a new `.bash_profile` when none exists |
| Zsh | `$ZDOTDIR/.zshrc`, otherwise `$HOME/.zshrc` |
| Fish | `$XDG_CONFIG_HOME/fish/config.fish`, otherwise `$HOME/.config/fish/config.fish` |
| Nushell | `$XDG_CONFIG_HOME/nushell/config.nu`; without that override, native Linux `.config`, macOS `Library/Application Support`, or Windows `%APPDATA%` |
| PowerShell 7 on Windows | Native redirected Documents directory, `PowerShell/Microsoft.PowerShell_profile.ps1` |
| Windows PowerShell 5.1 | Native redirected Documents directory, `WindowsPowerShell/Microsoft.PowerShell_profile.ps1` |
| PowerShell on Unix | `$XDG_CONFIG_HOME/powershell/Microsoft.PowerShell_profile.ps1`, otherwise `$HOME/.config/powershell/Microsoft.PowerShell_profile.ps1` |

The implementation follows the [Bash startup contract](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files),
[Nushell configuration contract](https://www.nushell.sh/book/configuration), and
[PowerShell profile contract](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles).
A configured console-host profile does not establish that a custom host loads it.
No-profile and custom startup arguments are observed from the actual ancestor
where available; setup refuses those modes because default profiles
would not activate them. Custom host profiles and unobserved startup modes remain
unknown. Manual workflows remain available.

Under sudo, the resolver uses the account database for the intended operator's
home. Personal mutations refuse a different effective UID. Run personal setup as
the intended user without sudo. Default paths remain contained beneath the home;
explicit external configuration roots retain protected filesystem transactions.

The generic `tirith status` exit contract is preserved: a configured hook whose
live blocking mode is unobservable still exits successfully. Its JSON now exposes
`protection_evidence`, with state, source, observation time, expiry, freshness,
invalidation reason, and a separate `verified_blocking` flag. `protected` is true
only for verified blocking. The legacy `protection_mode` string remains the
reported mode and does not independently establish verification.

`tirith status --require-verified-blocking` exits unsuccessfully when the current
shell has no fresh allow-and-block observation. Exporting `TIRITH_STATUS=blocks`
or inheriting Bash's effective-mode variable cannot satisfy that requirement.
Prompt text shows `blocking-unverified` for this case. A configured hook without
an observable active mode is shown as configured, never as freshly verified
protection. An absent environment variable alone does not prove that activation
is missing.

`tirith doctor --simulate-enter --format json` emits the measured Bash executable,
version, and an actual disposable-shell allow/block observation. That observation
belongs only to `disposable-bash-enter-probe`; it never certifies the calling shell,
a nested shell, another host, or the whole machine. Observations are rejected on
surface/identity mismatch, expiry, clock rollback, incomplete/failed probes, or a
current report of reduced protection. No current-shell verifier is implied by the
existence of the disposable probe.

Unit fixtures cover Bash startup priority, custom config roots, native platform
Nushell paths, separate Windows PowerShell variants and redirected Documents,
unsupported shells, inherited environment, stale/changed identities, expired and
future observations, and cross-surface evidence. Native Windows execution must
still run on Windows CI; Unix fixtures are not Windows certification.

The PowerShell hook checks actual terminal availability and startup options
before installing PSReadLine handlers or starting background snapshots.
Noninteractive invocations remain off, including a command or file payload that
contains the text `-NoExit`. Missing checker or temporary storage leaves Enter
unexecuted and paste uninserted, with degraded status until a successful check.
Unexpected Enter exit codes preserve the existing unprotected fallback and
report it explicitly; unexpected paste exits refuse insertion. Clipboard input
uses one raw string so multiline content is checked and inserted intact.

`scripts/certify-powershell-hook.py` records executable, hook and harness hashes
in disposable environments. Its full mode uses native POSIX terminals; the
Windows CI lane explicitly selects noninteractive-only. Neither lane certifies
an untested platform, version or current user session. The full mode also
checks that only the interactive hook writes its hook load record and that
`tirith status --json` run at its prompt reports the hook as `current`.

PowerShell and Nushell hook load records (`tirith __hook-presence --family
powershell|nushell --shell-pid <pid>`, Unix only) live beside the hook
capabilities as `.hook-presence-<key>.record`, where the key hashes the
effective UID, shell PID and process start identity. A record holds those, the
family, and the identity of the Tirith executable that wrote it; it holds no
secret. The command records only the shell that caller detection (the same
detection `status` uses) names as its caller, of the named family. Hook
freshness accepts a record only for a live process with the same start
identity and, for the calling shell, the same family; a capability lookup never
accepts one. Registration removes records of exited shells and is bounded like
the capability registry. The name matches no receipt (`*.json`) or capability
pattern, so 0.4.2 and current receipt and capability scans skip it.

## Task command families (Python and Cargo)

The task gate now recognizes operation intent in two existing incomplete workflows: the `pip install` example in `docs/task-envelope.md` and the mixed pip command in `tests/task_provenance.rs`, plus the pip/Cargo installation workflows documented in `docs/cookbook.md`. Recognition adds effect evidence; these command families remain incomplete even with an authoritative shell, absolute working directory and captured policy identity.

The grammar consumes the shared shell tokenizer and wrapper resolver for the boundary-selected POSIX, Fish, PowerShell or Cmd dialect. Caller-claimed dialects produce diagnostic hints only. Parser fixtures for Windows are lexical coverage, not native Windows execution qualification.

| Family | Supported operation grammar | Potential effects | Remaining unknown behavior |
|---|---|---|---|
| Python packaging | `pip`, `pip3`, versioned `pip3.N`; `python[3[.N]]` or Windows `py` with a literal `-m pip`; followed by `install` | Package installation, network egress, filesystem writes, persistence changes | Build backends, package code, credentials/configuration, requirements files and dynamic values |
| Python artifact preparation | Same launchers, `download` or `wheel` | Network egress and filesystem writes | Build/metadata hooks and dependency resolution |
| Python removal | Same launchers, `uninstall` | Filesystem writes and persistence changes | Installed metadata, interpreter startup/configuration and dynamic values |
| Cargo installation | `cargo [+toolchain] install` | Package installation, network egress, filesystem writes, persistence changes | Build scripts, procedural macros, toolchain dispatch, registry/configuration and dynamic values |
| Cargo build or execution | `cargo [+toolchain] build`, `b`, `check`, `c`, `test`, `t`, `run`, `r`, `bench`, `rustc`, `rustdoc` or `doc` | Network egress and filesystem writes | Build scripts, procedural macros, tests, executable entrypoints and external tooling |
| Cargo dependency fetch | `cargo [+toolchain] fetch` | Network egress and filesystem writes | Registry/configuration, credential providers and dependency resolution |

Known prefix options consume their declared values. An unknown prefix option, a dynamic subcommand, an arbitrary Python script, `python -c`, or a Cargo custom subcommand cannot be reinterpreted by finding an operation word later in its arguments. Recognized but unsupported invocations remain unknown. A pip `--log` prefix adds a write hint even when its operation is unsupported; option values never become command verbs.

The effect sets describe possible operation capabilities, not proof that the command will perform every effect. `--offline`, `--no-index`, `--dry-run` and `--ignore-installed` do not grant completeness or establish that package/build code cannot use the network or write files. This parser executes nothing and reads no package metadata or configuration.

Limits are explicit: 1 MiB of command text, 256 retained executable segments, 512 retained words per segment and 16 KiB per word. Reaching any limit keeps the result incomplete. Effects from retained invocations survive a mixed command; no recognized occurrence can vouch for another segment or an additional runtime effect. Existing Web3 occurrence accounting and npm-family inference remain authoritative for their own grammars.

The integration has no new authorization path: the existing task gate receives the inferred effects and incomplete state, and existing owned boundaries apply policy. A claimed trusted origin, requested effect or shell name cannot supply provenance or a runtime permit.

Grammar references: [pip general options](https://pip.pypa.io/en/stable/cli/pip/), [pip install](https://pip.pypa.io/en/stable/cli/pip_install/), [Cargo build](https://doc.rust-lang.org/cargo/commands/cargo-build.html), and [Cargo install](https://doc.rust-lang.org/cargo/commands/cargo-install.html). Parser coverage is deliberately narrower than these tools' full interfaces.

## ThreatDB publication operations

The read-only upstream observer compares each reviewed pin with a completed
upstream revision. Its observations enter compiler metadata and therefore the
signed source-integrity contract. Neither observing nor publishing adopts a pin.
The existing watcher still proposes updates for review. A failed observation
prevents the publication run from claiming a complete fresh observation.

The source transaction still exposes inputs only after all required sources
validate. The compiler retains its signed baseline, unique-record minimums,
per-source and per-section drop gates, and atomic signed generation commit point.
No validation failure republishes a partial source set. A partial supplemental
feed outage preserves the entire prior supplemental database.

Before pruning, the publisher independently verifies primary and fallback
discovery, every referenced immutable database's size/hash/signature/sequence,
and source provenance. It then runs the actual CLI with empty data/state caches
and verifies its installed generation and authenticated freshness. A failure
prevents pruning and is retained as an operational artifact.

The independent verifier rejects duplicate JSON fields, non-integer schema or
sequence declarations, mixed immutable asset generations and same-sequence
primary/fallback or legacy/index disagreement. All signed pointer declarations
are checked before an older pointer is treated as propagation lag. Only that
validated lag receives up to three observations with 10/20-second delays;
invalid successful responses are not retried. Transport retries retain their
separate curl limits. Verification failures also retain a refused report.
The cold-client step creates a fresh private temporary cache directory each time.

Each run has one structured `threatdb-run-report.json` and one summary. Stable
incident keys group repeats by failed phase. The prior completed workflow outcome
distinguishes recovery from ordinary success. Failure before publication reports
the retained generation; a failed or cancelled publication attempt reports partial/unverified
publication and instructs the operator to check both discovery surfaces. These
reports do not post new issues or adopt pins automatically.
Every named publication/retirement/commit/prune phase is recorded. A failure
after successful cold-client verification still requires recovery review, while
preserving the fact that discovery and the client were verified. Reruns bind
recovery to the previous attempt of the same run when that record is available;
missing API evidence does not establish an earlier failure or recovery.

### Count calibration and tests

The existing fail-closed gate rejects a source or section loss greater than 50%
against a signature-verified baseline. Required-source floors remain source
specific: OpenSSF, DataDog, CISA and typosquats require at least 100 records;
Feodo requires a nonempty feed because its reviewed live baseline contains five
addresses. Parse acceptance fractions are now reported but do not introduce a
new universal gate. Review historical per-feed fractions and count changes before
tightening thresholds; otherwise legitimate feed cleanup could block publication.

Deterministic tests cover old unchanged upstream, reviewed-pin lag, timezone
equivalence, future clocks, missing observations, wrong signatures/generations,
provenance tampering, transient retry/backoff limits, invalid successful responses,
partial upload, replayed pointers, stable incident keys and recovery. Existing
tests cover missing/empty required sources, transactional cleanup, signed baseline
loss, generation commit failures, rollback and same-second cache replacement.
Publication tests use an in-memory download map and a local fixture signing key;
they prove verifier, retry and incident-report behavior, not remote publication.
The workflow serializes scheduled/manual runs and retains the monotonic signed
sequence allocator and stale-source guard. Actual overlapping/rerun workflow,
partial remote upload and cold-client recovery evidence must come from retained
workflow executions; parser fixtures do not satisfy those remote checks.

## Allocation and timing gates

The Performance CI job (`.github/workflows/bench.yml`, ubuntu-latest) has two
absolute gates:

- Criterion timing ceilings for the `perf` benchmark, checked by
  `scripts/check-bench-budgets.sh` against `crates/tirith-core/benches/budgets.txt`.
- Allocation ceilings for the `resource_counts` benchmark, checked by the
  benchmark itself against `crates/tirith-core/benches/resource_ceilings.json`.

### What `resource_counts` measures

A thread-local counter wraps Rust's `System` global allocator for each measured
workload. It counts successful allocation, zeroed allocation, reallocation and
deallocation requests. Requested bytes include the full new size of each
reallocation, not only its increase. A direct allocation/reallocation/deallocation
self-check runs before measurement. Fixture setup and report writing happen
outside the counter.

The workloads are clean tier-1 scanning, full analysis of a clean command, a URL
pipeline, obfuscated tool output, analysis with a custom policy, and reading the
100 most recent records of a 10,000-row history file. They use disposable
policy, cache and history roots and never read the operator's own state.

Limits:

- It does not see native allocations that bypass the Rust global allocator,
  other threads, child processes, live heap size, CLI startup, or a whole
  interactive shell or agent operation.
- Its elapsed times are instrumented. They are reported, never gated, and are not
  comparable with ordinary CLI timings.
- Process and OS caches are not reset; no sample is a cold-cache claim.

### The ceilings

`resource_ceilings.json` holds, for every workload, two pairs of ceilings: an
`allocation_requests` ceiling (allocation + zeroed allocation + reallocation
calls) and a `requested_bytes` ceiling for `first_sample` (the first sample,
which includes one-time initialization), and the same pair for `steady` (the
largest of the later samples). Each is compared separately. It fails when a value is above its ceiling, when a
measured workload has no ceiling, or when a ceiling names a workload that was not
measured.

The ceilings are about 25% above measured values, rounded up. Allocation counts
are close to deterministic, so the headroom absorbs small differences between
operating systems, architectures, toolchains and dependency versions without
pinning any of them. Nothing in CI compares hashes of `Cargo.toml`, `Cargo.lock`,
the compiler or the runner image. The source revision, `rustc -Vv`, `cargo -V`
and the runner image are uploaded as an artifact (`resource-provenance.txt`) for
reference only.

When a change makes a workload allocate more on purpose, measure it, set the
ceiling about 25% above the new value, and say why in the commit.

### Run it locally

```sh
cargo bench --locked -p tirith-core --bench resource_counts -- \
  --output /absolute/path/resource-allocations.json \
  --ceilings "$PWD/crates/tirith-core/benches/resource_ceilings.json"
```

Cargo runs the benchmark from the `crates/tirith-core` directory, so pass
absolute paths. `--samples` (3 to 100, default 10) sets the samples per workload.

## Native mixed-version audit harness

This standard-library Python runner executes two existing, distinct SHA-256-pinned Tirith binaries in fresh operator roots. It never builds, installs, edits the source tree, executes inspected commands, or uses the caller's policy, audit records, keys, proxy settings or shell initialization. Native Windows is explicitly outside its scope. macOS needs its built-in `/usr/sbin/lsof`; Linux uses `/proc` for descriptor observation.

The six native cases are signed and unsigned variants of:

1. Both versions append and verify; the candidate rotates without replacing the active inode; both verify the retained exact original bytes/head and the new active chain; both append afterward; compensation refuses after append without changing active bytes. Signed cases additionally remove the fixture private key and require rotation and both appenders to refuse audit writes while retaining the Allow check exit code. The candidate must display its audit failure notice.
2. Six overlapping native writers (three of each version) append before rotation, then another mixed burst appends after rotation. Exact command accounting and both native verifiers check all expected records. This case does not claim forced overlap with truncation.
3. The real candidate prepares a rotation. The harness watches its private journal enter `applying`, observes the native lock is held, then stops the **lock owner** with SIGSTOP. It observes the stopped process and re-probes the lock, checks the original log/head are still intact, starts the real legacy writer, and records the writer's open audit descriptor using native OS observation. After SIGCONT, it requires completed rotation, unchanged inode, exact original archive, the legacy record in the new active segment, and successful active/archive verification by both versions. No binary is instrumented or replaced; all product log bytes are written by the supplied binaries. Missing the bounded observation window fails the case rather than claiming coverage.

The private signing fixture is the publicly known RFC 8032 section 7.1 test-vector-1 seed. It exists only as an owner-only file in fresh signed case roots and is removed at case completion, including handled failures. It is not an operator credential or a production signing identity. Native verifiers establish the fixture signatures; Python's signature check only enforces framing and count.

### Run

Use a Python runtime exposing `os.waitid` with `WNOWAIT`, and a new evidence output directory whose parent already exists. This is feature-checked before spawning a candidate; there is no fallback that reaps a leader before signaling its group. On macOS, Python 3.14 supplies this interface; Apple's `/usr/bin/python3` 3.9 does not. Linux also needs readable native `/proc` process metadata. The mandatory input hashes are checked before creating the output directory and rechecked after all cases. A binary symlink, identical binaries, changed hash, or existing output directory is rejected. Exit 0 means every requested native case passed; exit 1 means a case failed; exit 2 means the runner itself could not start or complete normally. Omitting `--held-writer` runs four cases and explicitly records the missing held-descriptor coverage.

```sh
python3 tools/qualification/mixed_audit_native.py \
  --baseline /absolute/path/baseline/tirith \
  --baseline-sha256 BASELINE_SHA256 \
  --candidate /absolute/path/candidate/tirith \
  --candidate-sha256 CANDIDATE_SHA256 \
  --output /absolute/path/new-evidence-directory \
  --held-writer

python3 tools/qualification/test_mixed_audit_native.py
```

Each invocation records input and runner hashes, host OS/architecture, a precise coverage scope, each argument vector/result/PID, bounded stdout/stderr, native observations, and case/environment records. `artifacts.json` hashes all retained evidence files, including the report; it intentionally excludes itself. No ambient environment dump is collected. Children have a 45-second deadline, at most 16 can be drained together, and each stream is capped at 64 KiB. Each candidate starts in a new session and process group. Cleanup sends signals only while the owned leader remains waitable and unreaped, observes that the group has no executing members, and then reaps the leader exactly once. Group observation and signaling have a three-second deadline, followed by at most one second for leader termination/reaping and two seconds for pipe drainage. Descriptor observation has a separate 3-second child limit. Fixture log reads are capped at 16 MiB. The harness leaves evidence roots for review and refuses to reuse them.

These results apply only to the exact input bytes on the recorded native host. Hash pinning does not authenticate vendor release signatures. Native Windows ACL/locking qualification, crash injection at every durable boundary, corrupt/modified archives, full/read-only storage, other historic clients, and non-fixture policy contexts remain separate evidence requirements.

### Process cleanup

The fixture tests (`tools/qualification/test_mixed_audit_native.py`) verify isolation, hash/reuse rejection, read/output caps, child/descendant cleanup, stopped-child timeouts, native result requirements, exact command accounting, archive substitution refusal and fixture-key cleanup. They validate the runner; they are not release qualification.

The runner also bounds drainage when an out-of-group process retains an output pipe. Such a case fails with incomplete output cleanup. An arbitrary descendant that creates a new session and closes inherited pipes is outside this process-group observation; this helper does not claim process-tree containment. Group signal permission failures are retried only within a finite deadline, and successful leader reaping or output EOF alone does not establish group cleanup. Fixture private signing-key removal runs even when child cleanup raises an error.

Cleanup reports retain `leader_reaped`, `group_signaled_or_absent`, and `output_eof`, and add the required `group_members_exited` boolean. The last value requires bounded native membership/status observation through Darwin `libproc` or Linux procfs while the leader still pins the numeric group identity. Exited zombies may still await reaping by their actual parent; they cannot execute or retain descriptors. `group_observation` records the method, observed members, and this scope. A group signal merely being delivered is insufficient. Failure to inspect membership, an observation bound being exceeded, or losing the waitable leader produces a cleanup failure. New evidence consumers must require all four facts; historical reports lack the new group proof and must not be relabeled as meeting it.

The shared `Job.process` wrapper deliberately makes `poll()` and `wait(timeout=...)` non-reaping observations. Callers should use `send_signal()` and `observe_stop()` for stop/resume observation, and `Job.kill()`/`finish()` for cleanup. They must not call raw `waitpid()` or `waitid()` without `WNOWAIT` for its child. Premature or external reaping is detected and prohibits further numeric PID/group signals. Repeated cleanup calls are inert after the single bounded attempt.

## Native service update coordination harness

This isolated, ignored Unix test exercises the actual local HTTP service,
asynchronous mutation worker and updater drain handshake. It is a mechanism
test: it does not replace a binary, verify an official release, simulate another
released service protocol or establish final package compatibility.

The test prepares a real mutation using the service's actual project context.
An authenticated HTTP request admits the worker and publishes its durable
Running state. A test-only gate then holds that worker for at most 30 seconds;
ordinary unit-test gates retain their existing ten-second limit. No production
deadline, authorization rule or service counter is changed.

The required observations are:

- Stale discovery protocol and binary identity refuse before quiescing or
  changing the mutation target.
- The production updater's ten-second wait refuses while the admitted job is
  still active. Further mutation and required-service reuse are refused.
- Releasing the gate lets the real mutation finish. The service acknowledges
  completion before its retained thread is joined.
- The updater guard retains both launch and service-lifetime locks. A later
  service has a distinct identity; the old required identity cannot launch or
  select a replacement.

Compile the CLI test target with Cargo's JSON output, select the sole `tirith`
test executable for `crates/tirith/Cargo.toml`, and retain its exact digest and
build record. Run as an ordinary user with native Python supporting
`os.waitid`/`WNOWAIT`:

```text
python3 -B tools/qualification/service_coordination_native.py \
  --test-executable /absolute/retained/tirith-test \
  --sha256 <sha256-of-that-test-executable> \
  --output /absolute/new-evidence-directory
```

The runner creates private HOME/XDG/project/organization roots, selects only
this ignored test and bounds the owned process to 90 seconds after spawn.
The pinned native owner retains its waitable leader through original-group
cleanup and reaps last. Each service thread must acknowledge completion before
joining; Rust never deletes the external fixture root. Failure, missing cleanup
evidence or changed input bytes retains the fixture. Success requires the
structured in-process result, all four outer cleanup facts and unchanged inputs.
Arbitrary escaped sessions and an asynchronous pre-spawn watchdog are outside
this runner's scope.

CI runs it through `.github/scripts/run-service-coordination.py`, which builds
the test target, selects that executable and passes its digest. Linux and macOS
CI retain the Cargo selection, exact test digest, structured
result and failures. The separate pure controls inject cleanup/reporting errors
without spawning a process; they do not establish native behavior.

## Windows workspace test job

`test-workspace-windows.ps1` runs only in the disposable GitHub-hosted Windows
test job. It creates a fresh standard local account for the existing
`control_dashboard` integration executable. It does not change Tirith's
administrator refusal or its directory/owner trust rules.

The controller reads Cargo's JSON compiler-artifact inventory, pins every test
executable and the companion CLI, and retains read handles that deny writing or
deleting those files through execution. The dashboard harness and CLI stay at
their original build paths: the harness's compiled `CARGO_BIN_EXE_tirith` still
names the same pinned CLI. Package working directories and native library search
paths are preserved. Ordinary harnesses run under the CI account; dashboard
tests run under the new account; workspace doctests run separately. Each
inventory entry receives a result even when an earlier harness fails.

`windows-test-process.cs` creates the worker suspended with
`CreateProcessWithLogonW`, `LOGON_WITH_PROFILE`, and a profile-derived environment.
The password exists only in process memory and Windows' account database. It is
never an argument, environment variable, manifest field or log entry. Before
resuming the worker, the controller reads its real token and verifies the exact
new SID, non-elevation, absence of the Administrators SID (including deny-only
groups), and an integrity level no higher than Medium. The worker then enters a
job with kill-on-close and no breakaway permission. Failure to attest or assign
the job prevents execution.

The worker creates its own disposable state under its actual loaded profile and
records the native owner SID and ancestor SDDL for diagnosis. It receives
read/execute access to the original build and fixture paths, not a product
override. Runner-owned files do not become standard-user-owned files. An
unsupported native owner or ancestor descriptor remains a failing test; the CI
runner does not relax or replace that product check.

The dashboard harness is listed and run without a filter. The nine required test
names in windows-test-common.ps1 must be present, and every other listed test
must also run. A
successful result requires every listed test to pass with zero failures,
ignored tests and filtered tests. Output overflow, malformed results, missing
tests, changed binary hashes, a worker deadline, or leaked descendants all fail.

The native job also exercises the same CLI's elevated refusal, a wrong-SID
suspended worker, a wrong-hash worker, and a deliberately stalled worker with a
real long-lived child. The last probe must hit its deadline with an empty job
after termination. These controls cannot replace the complete dashboard suite.
Account/profile removal follows confirmed native process cleanup and verifies
the exact account SID before deletion. Only the fresh account's ACL entries are
removed from existing trees.

`test-windows-test-runner.ps1` exercises parser, inventory, immutable-input and
bounded-process contracts without provisioning an account. Passing it on another
OS does not qualify Windows logon, token inspection, nested jobs, profile
ownership, ACL inheritance or native dashboard behavior. Those gates require the
actual Windows job and its `summary.json`, inventory, native facts and complete
bounded logs. The workflow retains that evidence for seven days.

Native contracts: [Cargo JSON messages](https://doc.rust-lang.org/cargo/reference/external-tools.html#json-messages),
[Cargo dynamic library paths](https://doc.rust-lang.org/cargo/reference/environment-variables.html#dynamic-library-paths),
[CreateProcessWithLogonW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw),
[Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

### Owned Job failure diagnostics

Process results retain `leader_exit_code` separately from the final runner exit:
successful Cargo completion followed by a descendant leak still fails. The
`before_cleanup` snapshot records native Job accounting and its process-ID list
before termination. Each retained process image and creation time is read through
a held process handle only after membership in that exact Job is confirmed.
An exited or reused PID is reported as unavailable, never attributed by name or
used as cleanup authority. `after_cleanup` is captured if the Job does not empty.

The snapshot uses one fixed 256-PID buffer, at most 32 process observations and
1024 image-path characters per process. It stops between queries after one second;
the individual Win32 metadata calls have no cancellable timeout contract. Errors,
truncation and unavailable fields remain explicit. It starts no diagnostic child,
enumerates no unrelated host processes, and collects no command line/environment.
Snapshots are observations at different instants, so accounting and list counts
can differ while processes exit. They do not relax the leak or cleanup gates.

A compiler/PDB server is a hypothesis until its owned image is observed. Do not
allowlist a process name, detach it, or lengthen the grace period merely to make a
build pass. The real exited-leader Windows control must retain the known child's
PID, creation time and image before cleanup and still confirm its termination.


### Compiler tools during CI builds

Every descendant still alive after Cargo exits (for example an MSVC
`vctip.exe`) fails the build. This hosted qualification job explicitly uses the installed LLVM `clang-cl`,
`llvm-lib`, and `lld-link` at `C:\Program Files\LLVM\bin` while retaining the
`x86_64-pc-windows-msvc` Rust target and Windows SDK/runtime. It therefore
qualifies Windows/MSVC ABI behavior with LLVM C compilation and linking, and
does not claim to qualify Microsoft's `cl.exe` or `link.exe` implementations.
Missing tools, reparse-point inputs, inconsistent versions, unexpected driver
output, or a non-MSVC compiler target refuse before compilation. No PATH or
project compiler preference supplies a replacement executable.

`compiler-tools.json` records fixed absolute paths, sizes, SHA256 hashes, PE
versions, bounded driver probes, selected child environment and source URLs.
Read-only handles pin these tools through build and doctests. `llvm-lib` has no
version command, so its PE VERSIONINFO version is combined with the documented
LLVM Lib help marker; all three versions must agree. Native probes themselves
must pass the same owned Job, exit, EOF, and cleanup checks as all other runs.

The child-only environment sets every documented `cc` 1.2.55 CC/CXX/AR
host/target spelling, a fixed Cargo target linker, and encoded Rust/rustdoc
linker flags. This explicit CI profile replaces ambient/project rustflags and
compiler wrappers. Native host mode (no `--target` and no inherited `CARGO_BUILD_TARGET`) ensures
linker flags also cover build-script and proc-macro compilation. Project,
ancestor and Cargo-home configuration files refuse instead of overriding this
fixed profile; the controller explicitly selects the installed stable MSVC Rust
toolchain and verifies its verbose host identity before Cargo runs. It does not change
process-wide environment, installed tools, registry, product account defaults,
Cargo.lock, or product harness cleanup. Compiler debug output is bounded by the
existing build log limits. The next full native build must still prove absence
of surviving helpers; portable fixture success is not that proof.
