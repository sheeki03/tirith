# Captured 0.4.2 release contracts

These fixtures are a compact projection of commands run against the separately
verified published macOS arm64 0.4.2 executable. They are observations, not
expected success exits for unconfigured protection or a blocked command.
Dynamic timings, test-directory paths and full policy content are omitted;
protocol field names, selected typed values and actual exits are preserved.

The trust comparison uses the recorded candidate hash, not the current working
tree. It records a one-hour project-scoped grant, sibling refusal, old-client
refusal in both projects and refusal after copying the new envelope into the
old store location. Neither command check executes the proposed pipeline.
See [verification](../../../docs/next-cycle/verification.md) for signature and
scope details. Wider native, expiry, copy/move and final-candidate evidence is
still required.

`cli-reader-compatibility.json` adds 32 actual baseline/candidate reader cases:
clean/blocked check contracts, personal and neutralized repository policies,
permanent/expired/malformed-expiry legacy trust, four inherited shell modes,
and saved download receipt list/last/cache verification. Inputs are synthetic
fixtures written by the harness; the outputs are observations from native
executables. This does not claim receipt producer, signature, publication or
live shell-interception qualification. Both native versions and all supplied
input hashes are retained. The baseline executable matches the separately
authenticated release recorded by `macos-release-contracts.json`.

The compact projection omits test-root paths, full policy values and timing
noise. It records the default schema-3 check contract and policy-envelope
additions separately. Inherited status never becomes verified blocking in the
candidate. Use `tools/qualification/compatibility_capture.py` for a new capture;
the report pins both binaries and the runner and process-helper sources before
and after execution. It refuses a baseline other than 0.4.2.
