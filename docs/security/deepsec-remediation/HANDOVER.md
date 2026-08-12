# Security merge handover

This handover is the continuation contract for the current security merge
program. Read [MERGE-CHECKPOINT.md](MERGE-CHECKPOINT.md) first for immutable
merge receipts and the current state of every requested pull request.

## Source-of-truth order

When records disagree, use this order:

1. live GitHub pull-request head, base, review threads, and required checks;
2. exact local Git object and merge-tree against current `main`;
3. this checkpoint and handover;
4. the original planning prose;
5. older comments or previously green runs.

Never infer readiness from branch age, a prior green child run, a clean
merge-tree, or a local process still running.

## Preserve the operator workspace

The primary workspace may contain unrelated operator work and untracked Codex
work directories. Do not reset, clean, stash, stage, or overwrite them. Perform
each integration in a dedicated worktree created from the intended parent, and
verify the primary workspace before and after any Git operation.

Safe preflight:

```text
git status --short --branch
git diff --name-only --diff-filter=U
git rev-parse -q --verify CHERRY_PICK_HEAD
git worktree list --porcelain
```

Run worktree creation and the subsequent merge/cherry-pick as separate commands
with the second command's working directory explicitly set to the new worktree.

## Exact continuation order

Do not parallel-merge stacked children. The supported order is:

```text
#173 -> #174 -> #177
  -> #183 -> #184 -> #185 -> #186 -> #179
  -> #187 -> #180
  -> #181
```

After each parent merge:

1. read back the new `main` SHA;
2. retarget or rebuild the immediate child on that exact parent;
3. resolve conflicts by preserving both the parent's safety invariant and the
   child's intended behavior;
4. run focused local gates;
5. push with a lease against the authenticated old head;
6. mark a draft ready only after the branch is coherent;
7. wait for all required checks and review threads on the new head;
8. merge through GitHub and read back the resulting merge commit.

## Pull-request gate checklist

Every PR requires all applicable items below:

- [ ] Head SHA and base branch authenticated.
- [ ] Parent is the latest required merge commit.
- [ ] Merge-tree reviewed; no unresolved semantic conflict.
- [ ] No staged accident or unrelated worktree change.
- [ ] Focused regressions pass.
- [ ] Formatting passes.
- [ ] Strict Clippy passes on Rust 1.88.
- [ ] Workspace/package tests appropriate to the risk pass.
- [ ] `cargo audit` has zero vulnerabilities and no ignored advisory.
- [ ] `cargo deny` passes without advisory exceptions.
- [ ] Linux, macOS, Windows, install, performance, and MSRV checks pass when
  required by the repository.
- [ ] Every actionable review thread is fixed and resolved.
- [ ] Draft status is removed only after the exact head is ready.
- [ ] Merge result and merge commit are read back from GitHub.
- [ ] [MERGE-CHECKPOINT.md](MERGE-CHECKPOINT.md) is updated.

## Conflict-resolution invariants

Retain all of the following when integrating older DeepSec branches:

- Rust 1.88 as the active MSRV and the current dependency graph.
- No RustSec or cargo-deny advisory ignores.
- Typed completeness and explicit fail-closed outcomes.
- Work-budget and recursion/depth limits from newer parent changes.
- Privacy projection before persistence, display, Debug, and serialization.
- No-follow, contained, transactional filesystem behavior.
- Exact parser/runtime identity and conservative handling of ambiguity.
- Hermetic HOME/XDG/AppData, proxy, credential, and state isolation in tests.

If an older child deletes, weakens, or silently bypasses one of these controls,
the child must be repaired before it is pushed or marked ready.

## Known implementation traps

### #185

The transactional retry path must not replay emitted diagnostics, durable state
changes, or external side effects. Test the first-attempt failure, retry, and
post-retry public output/state counts through the real boundary.

### #187

A pip constraints file is not a dependency manifest. Only packages declared by
the active install/requirements input may be constrained. Add positive tests for
declared packages and negatives proving constraint-only names do not become
installation or threat-assessment subjects.

### Descendant drift

Older branch checks and reviews become stale whenever a parent is rewritten or
merged. Re-authenticate every descendant after its parent changes; never reuse a
green status from the old SHA.

## Documentation completion

Before final convergence:

- replace every in-progress row in `MERGE-CHECKPOINT.md` with a merge receipt;
- update the execution mapping in
  `implementation/stacked-pr-plan.md` if PR boundaries change;
- keep historical Rust 1.83 research labelled historical;
- update README status from in progress to complete only after #181 and the
  final exact-main gate; and
- keep private DeepSec evidence and payloads outside the repository.

## Stop conditions

Stop the merge sequence and leave the PR open when any of these occurs:

- a required check fails, is missing, or is attached to a stale SHA;
- `cargo audit` or `cargo deny` reports an unremediated advisory;
- a review thread identifies a plausible unresolved security regression;
- an integration drops a parent invariant or changes public compatibility
  without an explicit migration;
- the target worktree cannot be authenticated or contains unrelated changes;
- GitHub reports a non-clean merge state that has not been locally reproduced
  and resolved.

The user's authorization is to fix and merge, not to waive these conditions.
