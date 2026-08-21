# Working on a project you do not trust

Somebody sent you a repository and asked you to run it. A recruiter, a bug
bounty, a "can you reproduce this", a take-home exercise. This is the workflow
tirith supports for that, and, just as importantly, the workflow's real limits.

The short version: **`tirith capsule run --preset untrusted-project` is the only
control here that can stop anything, and it is enforceable on x86_64 Linux
only.** Everything else on this page is inspection and evidence.

## Before you clone

```bash
tirith scan /path/to/project --format json
```

Directory scanning covers config poisoning, hidden and invisible content,
prompt-injection seeds in AI config files, credential material, and the
[cross-workflow artifact flow](ci-artifact-flow.md) post-pass over
`.github/workflows/`. Only a directory scan runs the artifact-flow post-pass; a
single-file `tirith check` does not.

```bash
tirith ecosystem scan /path/to/project
tirith hooks scan /path/to/project
```

`ecosystem scan` scores every declared dependency, `hooks scan` inventories git,
husky, lefthook, and pre-commit hooks, which is where a repository most cheaply
arranges to run code the moment you touch it.

## Running it: the capsule preset

```bash
tirith capsule run \
  --preset untrusted-project \
  --project . \
  --receipt ./run-receipt.json \
  -- npm test
```

The project is copied into a held ephemeral directory and the exact argv runs
there, with write access to the copy, a private temporary HOME, and nothing
else.

### The copy refuses; it does not skip

A symlink, a hardlink, an entry on another filesystem mounted inside the tree, a
path that escapes the project root, a case or Unicode name collision, a fifo, a
socket, a device, or a non-UTF-8 name all REFUSE the run. Silently skipping any
of them would leave you believing the whole project was copied, and a hardlink
in particular is a second name for content the project root does not contain,
which is how a file is smuggled out of a denied directory one inode at a time.

`.git` is excluded at every depth, including a submodule `.git` file. The copy
caps at 100,000 files, 200,000 entries of every kind, 256 levels of nesting, and
2 GiB.

### It refuses on the wrong host, before copying anything

The preset is enforceable on x86_64 Linux with a usable Landlock ABI and nowhere
else. Raw-network denial needs seccomp, which is x86_64 Linux only in this
build; macOS cannot enforce a per-process memory ceiling or a process-count
ceiling at all; and the parent-owned wall-clock and combined-output supervisor
is Linux-only.

On any other host the command refuses before anything is copied or spawned,
names the exact control it could not deliver, and writes a refusal receipt. On a
macOS host at this release the refusal reads:

```
capsule backend 'seatbelt' cannot enforce required containment on this host
(missing: resource_limits); refusing to run uncontained; additionally the
parent-owned wall-clock and combined-output supervisor this preset requires is
implemented only on Linux, so max_output_bytes and wall_clock_seconds cannot be
enforced on this platform
```

with `"project_copy_materialized": false` and exit 1. **There is no degraded
fallback.** A preset that quietly ran uncontained would be worse than one that
refuses, because you would believe the project was contained.

### There is no network allow-list

Domain allow-listing is deliberately not offered. `domain_proxy_enforced` is
false in every OS backend, and a coverage ledger may not claim domain egress
without raw-socket denial, so an allow-list preset would fail closed on every
host while implying a capability the product does not have.

The preset is deny-all. **Dependencies must be vendored or installed by a
separate trusted transaction before the contained run.** This preset performs no
network dependency installation.

### The receipt

Every invocation writes one content-addressed receipt, including a refusal. It
signs it when this installation has an audit key, and anchors it in the audit
hash chain when an audit chain is configured. Both conditions are printed on the
run: the command reports either `receipt is ed25519-signed and anchored in the
audit chain` or, with no key and no chain (for example under the documented
`TIRITH_LOG=0`), `receipt is unsigned (no audit signing key configured) and NOT
anchored in the audit chain`. A skipped anchor is deliberately not a failure and
does NOT change the exit code
(`crates/tirith/src/cli/capsule_run.rs:913-925`), so read the printed line
rather than the exit status before handing a receipt to someone else as
tamper-evident evidence. It records the argv DIGEST
(never the argv), the project input and output tree digests, the backend,
requested versus achieved coverage, the effective limits, the child's exit
status separately from tirith's own decision, the termination reason, a bounded
file diff, whether an ephemeral copy was materialized at all, and cleanup
confirmation covering the project copy, the process tree, and the temporary
HOME.

Absolute host paths are redacted out of the recorded reason, because the receipt
is the copy you hand to someone else.

| Exit | Meaning |
|---|---|
| 0 | contained, and the child exited 0 |
| 1 | a tirith decision: refused before launch, terminated after it, or a run whose receipt could not be recorded or anchored |
| 2 | usage or input error |
| 3 | contained, but the child itself exited non-zero |

See [docs/capsule.md](capsule.md) for the full containment model and the
per-backend coverage ledger.

## Afterwards

```bash
tirith browser audit --baseline ~/ext-baseline.json
tirith persistence diff
tirith checkpoint diff
```

If you keep a browser extension baseline, comparing after the fact is how a
silently updated wallet extension becomes visible. That is
[a read-only integrity audit](browser-extension-audit.md), not monitoring: it
reads extension source trees and three install-class fields, and never touches
browsing data.

## What none of this does

- **It does not contain your shell.** The capsule contains a process tirith
  launched. A command you type yourself runs with your full privileges.
- **It does not contain anything on macOS or Windows.** The preset refuses
  there; it does not degrade.
- **It does not analyze the project's behaviour.** A tree digest says what the
  bytes were, not what they do. Tirith does not detonate, sandbox-and-observe,
  or signature-match.
- **It does not audit npm's tarballs.** See
  [npm provenance receipt](npm-provenance-receipt.md) for exactly what the npm
  surface does and does not bind.

## See also

- [Capsule](capsule.md), the containment model
- [Enforcement coverage](enforcement-coverage.md), the per-capability ledger
- [Threat model](threat-model.md), the non-goals this workflow operates inside
