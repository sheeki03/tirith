# Incremental history contract

`history::HistoryReader` is a read-only, process-local reader for one path chosen
by the CLI or local service. A browser supplies filters and an issued cursor,
never a filesystem path or byte offset. Each request reads at most 2 MiB plus
bounded generation anchors, retains at most 500 records, and rejects individual
lines over 1 MiB. At most 128 opaque cursor capabilities remain live.

The first request inspects a recent suffix. `earlier_history_uninspected` reports
the omitted prefix even when all retained records match the query. A continuation
reads forward, including later appends. A partial last line retains its starting
offset until it is complete. Malformed records, oversized lines, unknown source,
disabled logging and unavailable data are separate from an empty result.

Record IDs combine a random reader generation with the original byte position.
Retries within that generation return the same IDs. Replacing/truncating the
file, changing the filter, restarting the reader, or using an evicted cursor
requires the consumer to replace its view. Consumers must not append replayed
pages to old aggregates. File identity is obtained from the retained native
handle; bounded head/tail anchors also detect truncation and tail replacement.

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

The initial implementation and deterministic regressions are pending current
build verification. Integration into the live dashboard, incremental aggregates,
append-failure health, and rotation/retention transactions remain WP12 work.
Rotation must preserve signed segment/head evidence and explicitly address
older writers; this reader does not rotate or delete anything.
