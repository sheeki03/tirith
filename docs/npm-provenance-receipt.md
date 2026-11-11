# npm signature and provenance receipt

`tirith pkg attest-npm` asks the project's OWN npm to verify its installed
packages' registry signatures and provenance attestations, and binds the answer
to the exact `package-lock.json`, the installed `node_modules` inventory, and
both the lockfile's registry hosts and the ones npm itself reported.

```bash
tirith pkg attest-npm
tirith pkg attest-npm --project ./service --format json --out ./npm-receipt.json
tirith pkg attest-npm --require-provenance
```

## What it is, and what it is not

**It is an adapter around npm's own answer.** Tirith does not implement npm's
signature verification. It resolves npm, runs one exact command from a closed
table, parses the result strictly, and binds that result to the exact files it
would apply to.

**It is not an npm firewall.** Tirith has not downloaded, inspected, or bound
the tarball bytes npm will install. There is no npm quarantine, no npm install
transaction, and no npm rollback. npm performs its own registry network I/O,
outside tirith's fetch validator and capsule broker.

**A clean receipt does not mean the package code is benign.** It means npm's own
registry signature check passed. That sentence is a constant in the source so
the human, JSON, and receipt paths cannot drift into implying different things.

## The closed contract table

npm's `audit signatures` output shape has changed across majors, and handing a
speculative flag to an npm whose output tirith has not characterized would be a
guess. So the contract is a fixed table: a version RANGE, the exact argv, the
expected JSON schema, whether attestation bundles are available, and the
committed stdout fixture that proves it.

**The table has exactly one entry today** (`>=11.0.0, <12.0.0`, running
`npm audit signatures --json --include-attestations`), because exactly one
fixture was captured from a real npm rather than extrapolated. An npm outside
every range returns `partial` with `unsupported_npm_version` and runs NO audit
command.

Resolution goes through tirith's trusted-executable mechanism with no shell, so
an alias cannot hijack the name, and the exact version is discovered before the
table is consulted. The audit runs with a 120 second timeout and 8 MiB stdout
and stderr caps, and its stderr is redacted before it reaches the receipt.

## Per-package states

| State | Meaning |
|---|---|
| `provenance-verified` | npm verified a publish attestation. When a lockfile SRI was available, the attestation's in-toto subject digest bound to it |
| `signature-only` | a legacy state, kept so older receipts still parse. No current run produces it: npm's JSON has no positive per-package signature bucket, and a package npm did not name is `not-audited` |
| `missing` | the registry provides signing keys but published no signature for this package |
| `invalid` | a signature, an attestation, or the attested subject digest FAILED. The security-relevant negative state |
| `not-audited` | installed and eligible, but no audit result covers it |
| `unsupported-source` | the dependency is not from a registry (git, file, link, workspace), so npm's signature audit does not apply. Kept explicit rather than dropped, because a silently omitted dependency reads as coverage that was never attempted |

`signature-only` is not derived by subtraction. npm's `--include-attestations`
JSON enumerates only the invalid, the missing, and the ATTESTED packages, and it
carries no counters. Absence from all three buckets is therefore never read as a
verified signature, even for an installed package from the public registry: that
package is `not-audited`. The receipt's `signature_only_derived_by_subtraction`
coverage field is a legacy field and is always `false`.

## The one binding tirith performs itself

`bind_attested_subject` compares the sha512 subject digest inside an
attestation's in-toto statement against the `integrity` SRI the project's own
`package-lock.json` pins. Those cover the same tarball bytes, so a disagreement
means the attestation is over DIFFERENT bytes than the lockfile will install.
That is the `invalid` case with tirith's own `ESUBJECTINTEGRITY` code, and it
forces an overall mismatch.

Tirith still does not verify the Sigstore bundle itself. The
`sigstore-attestations` feature is off because the Sigstore closure needs a
newer Rust than the workspace MSRV, so npm's verification is what the receipt
reports and the receipt says so.

## Outcomes and exit codes

| Outcome | Exit | Meaning |
|---|---|---|
| `clean` | 0 | every eligible package is `provenance-verified`. A registry dependency that npm names in no bucket is `not-audited`, which makes the run `partial`, so a project with any unattested dependency is not `clean`. `--require-provenance` is recorded in the receipt and additionally rejects `signature-only`, which no current run produces |
| `mismatch` | 1 | at least one `invalid`. A failed signature, attestation, or subject binding dominates everything |
| `partial` | 3 | the receipt exists but the coverage is incomplete. Never a claim that the incomplete part was fine |

Exit 3 here is NOT the `tirith check` warn-acknowledgement meaning. Per-command
exit codes in this repository are deliberately distinct, and each command's
help says so.

## When you get `partial`, and why

The common causes, each of which runs no audit command at all rather than
guessing:

- **an unsupported npm version**, outside the contract table;
- **a project `.npmrc` with any setting in it.** If the project's own `.npmrc`
  holds any assignment at all, whatever the key, the run returns partial and
  names the first key. Only comments and blank lines pass. It is not a list of
  dangerous keys, because npm can add audit-affecting keys over time. The audit
  child runs in the project directory, where npm reads the project's `.npmrc`
  above the user and global config, so honoring it would let the audited project
  configure its own audit;
- **Windows**, where npm is a batch launcher (`npm.cmd`) that the
  trusted-executable validator refuses;
- **offline mode**, which resolves and spawns nothing;
- **a missing `node_modules` or `package-lock.json`**;
- **an invalid registry mode.** Setting `TIRITH_NPM_REGISTRY`,
  `TIRITH_NPM_AUTH_SOURCE`, `TIRITH_NPM_CA_FILE`, or `TIRITH_NPM_PROXY` without
  `TIRITH_NPM_AUDIT_MODE=trusted-private`, or selecting that mode without its
  required inputs, is refused rather than falling back to the public registry.

**A non-public registry** is a separate case, and here the audit command does
run. The default (public) mode pins `https://registry.npmjs.org/` with isolated,
empty user and global npm config, so a dependency the lockfile resolves from
another host is never reported as covered and the run cannot be clean. A private
registry is audited only in the explicit trusted-private mode:
`TIRITH_NPM_AUDIT_MODE=trusted-private`, an HTTPS `TIRITH_NPM_REGISTRY` origin,
and an absolute, owner-only credential file in `TIRITH_NPM_AUTH_SOURCE`, with
optional `TIRITH_NPM_CA_FILE` and `TIRITH_NPM_PROXY`. The receipt records which
mode ran and the registry origin, never the credential.

Other partial reasons cover the honest failure modes of the run itself: a
timeout, an output-cap breach, non-strict JSON, a duplicate JSON key, trailing
JSON data, a lockfile over the entry cap, a capped inventory, an unaccounted
installed package, and a project that declares no registry dependency at all.

## The receipt

Content-addressed and ed25519-signed when the installation has an audit key,
written atomically at mode `0600` when `--out` is given. It carries the schema,
receipt type, content address, timestamp, tirith version, engine build, policy
projection hash, status, subject, evidence, coverage, and the caveats. It shares
its envelope shape with the capsule, browser-baseline, build, and deployment
receipts. Like the browser-baseline, build, and deployment receipts it is **not
anchored in the audit hash chain**. Only the capsule run receipt is eligible for
anchoring, and only when an audit chain is configured.

## See also

- [Enforcement coverage](enforcement-coverage.md), the per-capability ledger
- [Attestation receipts](attestation-receipts.md), the build and deployment pair
- [Capability matrix](capability-matrix.md), what `install` and `package` report for npm
