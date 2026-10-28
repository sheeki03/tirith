# Signed native replacement fixture

This optional qualification lane exercises actual self-replacement and rollback in a disposable ordinary-user installation slot. The old image is explicitly a Tirith **test executable**, the candidate is a separately retained **release product**, and both have version 0.4.2. A public [RFC 8032 section 7.1 test vector](https://www.rfc-editor.org/rfc/rfc8032#section-7.1) signs the exact fixture checksum document. The released CLI gains no key, trust switch, environment override or execution route.

This lane cannot qualify an official signed release, a numeric version upgrade, a user's installation, shell reload, service or pending-job migration, interruption recovery, power-loss durability, Windows, or a package-manager channel. The fixture’s test-only authority label remains visible in every result.

## Preconditions and build records

Use an ordinary account on native macOS or glibc Linux, Python 3.11 or newer with `cryptography`, and the normal supported Rust toolchain. Python must expose native no-follow file/directory opening; the owned helper separately requires WNOWAIT process observation. The scripts use a portable Python shebang and record the actual interpreter identity. macOS ARM64 qualification in this workspace uses `/opt/homebrew/opt/python@3.14/bin/python3.14` explicitly.

The driver invokes neither Cargo nor Git and never downloads a candidate. Build and retain both images beforehand:

1. Capture a before source manifest with `signed_replacement_inputs.py capture-source --root <canonical-checkout> --stage before --output <new-before.json>`.
2. Retain verbose `rustc -vV` and `cargo -vV` output separately. For the test executable run `cargo test --locked -p tirith --bin tirith --no-run --message-format=json`; for the product run `cargo build --locked --release -p tirith --bin tirith --message-format=json`. Retain Cargo JSON stdout separately from stderr and require a successful exit. These are independent authorized builds, not driver actions.
3. Capture the after source manifest with the same command and `--stage after`. Copy the exact `tirith` executable selected by the completed Cargo JSON to a fresh retained file. Both roles are Cargo **binary** targets; only the test harness has `profile.test = true`.
4. Seal each build with `signed_replacement_inputs.py seal-build --before <before.json> --after <after.json> --binary <retained-image> --cargo-json <cargo.jsonl> --cargo-executable <original-Cargo-executable> --role <test_harness-or-product> --rustc-verbose <rustc.txt> --cargo-verbose <cargo.txt> --output <new-build.json>`.

Source capture includes all local workspace crate sources/assets, manifests and lockfile, optional toolchain/configuration files, the compatibility generator and its inputs, and the reviewed owned-process helper. Empty source files are valid; symlinks, special files, changed directory generations and oversized captures are refused. The captured source closure must remain present and identical when the driver runs. Records establish local reproducibility evidence; they are not independent build attestations.

Keep the original Cargo executables until sealing completes. Test/product source closures can differ only as a disclosed observation; compatibility-generator inputs must match. The ordinary product must have release optimization and runtime provenance matching the supplied native target, version and file hash. Provenance is observed before packing and does not prove that the swapped-in product started.

## Run

Pass six retained inputs and a new output directory beneath an existing owner-controlled canonical parent:

```text
python3 -B tools/qualification/signed_replacement_native.py \
  --test-executable <retained-test-image> \
  --test-source-manifest <sealed-test-build.json> \
  --test-cargo-json <test-cargo.jsonl> \
  --candidate <retained-product> \
  --candidate-source-manifest <sealed-product-build.json> \
  --candidate-cargo-json <product-cargo.jsonl> \
  --output-dir <new-canonical-output-directory>
```

The driver creates a private fixture root and isolated HOME/XDG/PATH/cwd, copies the two images, preserves policy/startup/trust/grant/lock fixtures, and constructs one bounded regular USTAR member. Python and Rust independently check archive content and the public-key signature before the production trusted extractor runs. The Rust case uses current policy and real task-effect authorization, production replacement, actual rollback receipts, and exact destination/backup readback.

Refusal assertions cover bad signatures, wrong keys, changed checksums/documents/archives, missing or extra targets, wrong version/archive binding, unsupported local formats, task-policy denial, changed extracted bytes, stale destination or backup, edited rollback receipt, and a later destination generation. The parser-only unit controls do not execute a product or qualify replacement.

Limits include 32 KiB manifest, 1 MiB source/build metadata, 256 KiB compatibility/checksums, 64-byte signature, 64 KiB preserved files, 64 MiB compressed archive, 256 MiB product and 512 MiB test executable. The driver reserves a conservative full layout within 3 GiB and refuses insufficient free space before invoking either image. Each owned outer job has a 45-second limit; total preparation/execution has a 600-second cooperative limit. These fixture bounds are not updater performance guarantees.

## Results and process scope

A successful result requires one exact selected ignored test, exit zero, both completion markers once in order, unchanged inputs/configuration and retained build sources, exact restored install/backup bytes, and the owned helper’s four cleanup facts. The driver retains raw job output, manifests, its own runner/input source bytes, all build records, the isolated fixture and a final result. Failed attempts remain failures and are retained; do not warm or relabel them as successes.

The trusted extractor creates a separate process group. Outer-helper cleanup does **not** attest that nested group. A successful extractor marker records only the production extractor’s normal `Completed` result. Any outer failure leaves nested cleanup `unknown_after_outer_failure`, even if the outer group's four cleanup facts pass. No interruption, crash, timeout or power-loss fault is injected. The driver does not remove a failed fixture automatically.

Run non-product unit controls with `python3 -B -m unittest -v test_signed_replacement_native.py` from `tools/qualification`. Compile and run the ordinary Rust parser/crypto tests before scheduling the explicit ignored native case.
