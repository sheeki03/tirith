# Owned numeric lifecycle qualification

This is a test-only composition of the primitives behind `tirith update` and
`tirith update --rollback`: the real signature verifier, compatibility preview,
task policy authorization, rollback receipt, service quiesce and atomic
publication. It does not exercise the production release download. A public
RFC8032 test-vector key
is its only signature authority. It adds no production key or URL override.

The tracked workspace remains version **0.4.2**. A separately retained source
copy may contain the exact **0.4.3** version-only fixture delta. Neither build
is a published release. No user binary, configuration or host session is used.

## Inputs and admission

Three actual native images are required: a 0.4.2 test controller, an ordinary
release-profile 0.4.2 product and an ordinary release-profile 0.4.3 product.
The controller executes from `inputs/controller`; the installed slot always
contains an ordinary product. Before/after source captures bracket each build.
Retained Cargo JSON must identify the exact native package, version, role and
selected executable. A successful build terminator and retained image equality
are mandatory. These records are local evidence, not a build attestation.

`signed_numeric_inputs.py` reuses the unchanged v1 source capture tool while
using a distinct build record contract. It refuses v1 record relabelling,
neighbor versions, suffixes, swapped roles, unsuccessful/ambiguous Cargo output,
source drift and non-release product profiles. Controller and old-product
source files must match exactly. Candidate source files must match except for
the exact approved Cargo.toml and Cargo.lock version bytes. Unrelated lock
dependencies, formatting, source paths and all format generators stay fixed.

The unchanged dependencies retain these SHA-256 pins:

| Dependency | SHA-256 |
| --- | --- |
| `signed_replacement_inputs.py` | `f7a512121b7a400e34fe86bb8fc0fdc86b8bca6e892b4fcc107ff8a60b57f101` (re-pinned after the retired npm generator inputs were removed) |
| `mixed_audit_native.py` | `913a3499bd78b39c6870b9dc280fcaad8a49739db7f2781bbfe914ff4db12e75` |
| `signed_replacement_native.py` | `de7b2ac0af3c10d10e27fd44ec0d60fa5486803b03f69b693a5ed6b67d1b4e7b` |

## Cases and permitted claims

Run one case per new evidence directory. Every input, failed fixture, run
UUID and resulting installed generation is retained.

| Case | Crash boundary | Installed binary afterwards |
| --- | --- | --- |
| `complete` | None: 0.4.2 → 0.4.3, then receipt-bound 0.4.3 → 0.4.2 | Exactly 0.4.3, then exactly 0.4.2 |
| `verifying` | Killed after verification, before extraction | Exactly the old 0.4.2 image |
| `publication_intent` | Killed after extraction, quiesce and the rollback receipt, before the swap | Exactly the old 0.4.2 image |
| `published` | Killed after the verified swap | Exactly the new 0.4.3 image |

Each death case requires the controller's real `waitid(WSTOPPED)` event, an
exact boundary marker and installed-byte readback before SIGKILL. The runner
signals only its retained child/group and requires leader reap, observed group
exit and output EOF. A marker or deliberate error return cannot replace
process-death evidence. Publication-intent and published cases require normal
completion of the production extractor first.

After death the installed slot must hold exactly the complete old or the
complete new image (never a partial one), and the installed product's own
`tirith version --provenance` and allow/block checks must match that image.
No interrupted run is resumed.

The complete case observes actual installed provenance and allow/block checker
behavior before upgrade, after upgrade and after rollback. It retains an actual
interactive Zsh initialized by 0.4.2, observes installed 0.4.3 with loaded 0.4.2
and `reload_required`, then initializes a fresh shell and requires loaded 0.4.3.
These are loaded-version observations. They do not claim a PTY preexec blocking
certificate or a retained/fresh Claude host lifecycle. That host acceptance
remains a separate exact-binary real-host run.

Customized policy, startup bytes, legacy trust, scoped trust and MCP lock bytes
are held across publication and rollback. The inert custom deny rule also
provides an ordinary-product functional control. Existing pending-job service
coordination, package-channel refusal and migration tests retain their separate
scope; this lane does not turn those into numeric cross-version coverage.

## Bounds and execution gate

Preparation/execution uses a 600-second case deadline. Every native spawn,
stop wait is refused after expiry and clamped to the
remaining case time; successful stage completion rechecks it. Cleanup is exempt.
Ordinary CLI/controller jobs are bounded at 45 seconds and the retained shell
at 180 seconds.
The shared owner helper supplies bounded kill/reap/group-observation/output
drain attempts. These are finite userspace attempts, not a kernel-time guarantee.
Input/source/metadata/archive caps are inherited from strict v1 admission. Each
case reserves at most 3 GiB and requires an additional 64 MiB free. Run cases
serially and admit aggregate retained disk use before launching another case.
The runner never prunes evidence or builds an input.

Only pure Python admission controls and syntax/format checks may run before a
separate reviewed build/resource packet. Native execution additionally requires
review of the resulting exact source/build/input identities. Do not run Cargo
against another task's active target directory. Do not delete Docker data,
executables or retained evidence to obtain space.

The production extractor owns a separate process group. Normal completion is
observed; outer cleanup does not attest that nested group after an outer failure.
Any such failure is refused and retained. No power-loss, Windows, official
publication, all-channel compatibility or human-pilot claim is made.

## Commands after admission

Capture source before and after each authorized build with the unchanged
`signed_replacement_inputs.py capture-source`. Seal it with the numeric tool:

```sh
python3 tools/qualification/signed_numeric_inputs.py \
  --before BEFORE.json --after AFTER.json \
  --binary RETAINED_IMAGE --cargo-executable ACTUAL_CARGO_IMAGE \
  --cargo-json CARGO.jsonl --role product \
  --rustc-verbose RUSTC.txt --cargo-verbose CARGO.txt --output BUILD.json
```

The controller uses `--role test_harness`. The runner requires all three build
records and outputs, and executes only the one named case:

```sh
python3 tools/qualification/signed_numeric_native.py \
  --controller CONTROLLER --controller-build CONTROLLER.json --controller-cargo-json CONTROLLER.jsonl \
  --installed PRODUCT_042 --installed-build PRODUCT_042.json --installed-cargo-json PRODUCT_042.jsonl \
  --candidate PRODUCT_043 --candidate-build PRODUCT_043.json --candidate-cargo-json PRODUCT_043.jsonl \
  --case complete --output-dir NEW_ABSOLUTE_EVIDENCE_DIRECTORY
```

An exit zero qualifies only the recorded case. Four passing case directories,
their exact build/source identities and a separate real-host reload receipt are
needed before claiming those WP15 acceptance rows.
