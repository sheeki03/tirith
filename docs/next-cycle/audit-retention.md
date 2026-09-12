# Audit segment retention

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
