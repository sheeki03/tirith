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
| `signature-only` | npm named neither an invalid nor a missing signature for it, so its registry signature verified and it publishes no attestation. Derived by subtraction, and the receipt says so |
| `missing` | the registry provides signing keys but published no signature for this package |
| `invalid` | a signature, an attestation, or the attested subject digest FAILED. The security-relevant negative state |
| `not-audited` | installed and eligible, but no audit result covers it |
| `unsupported-source` | the dependency is not from a registry (git, file, link, workspace), so npm's signature audit does not apply. Kept explicit rather than dropped, because a silently omitted dependency reads as coverage that was never attempted |

`signature-only` is derived by subtraction because npm's
`--include-attestations` JSON enumerates only the invalid, the missing, and the
ATTESTED packages. Subtraction needs a premise about what npm audited, and npm's
JSON carries no counters, so the premise is re-established from the lockfile and
the install tree. Anything that cannot be established becomes `not-audited`
instead.

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
| `clean` | 0 | every eligible package is signature-covered, and provenance-verified too when `--require-provenance` is set |
| `mismatch` | 1 | at least one `invalid`. A failed signature, attestation, or subject binding dominates everything |
| `partial` | 3 | the receipt exists but the coverage is incomplete. Never a claim that the incomplete part was fine |

Exit 3 here is NOT the `tirith check` warn-acknowledgement meaning. Per-command
exit codes in this repository are deliberately distinct, and each command's
help says so.

## When you get `partial`, and why

The common causes, each of which runs no audit command at all rather than
guessing:

- **an unsupported npm version**, outside the contract table;
- **a project `.npmrc` that reconfigures the audit.** If the project's own
  `.npmrc` sets `registry`, `ca`, `cafile`, `strict-ssl`, `_keys`, `omit`,
  `userconfig`, or `globalconfig`, the run returns partial. The audit child runs
  in the project directory, where npm reads the project's `.npmrc` above the
  user and global config, so honoring it would let the audited project configure
  its own audit;
- **Windows**, where npm is a batch launcher (`npm.cmd`) that the
  trusted-executable validator refuses;
- **offline mode**, which resolves and spawns nothing;
- **a missing `node_modules` or `package-lock.json`**;
- **a non-public registry.** npm ships the Sigstore TUF root that pins
  `registry.npmjs.org`, and that is the only host whose signing-key availability
  tirith can assert without asking the host itself. A private registry is
  therefore partial rather than clean.

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
receipts, and like them it is **not anchored in the audit hash chain**.

## See also

- [Enforcement coverage](enforcement-coverage.md), the per-capability ledger
- [Attestation receipts](attestation-receipts.md), the build and deployment pair
- [Capability matrix](capability-matrix.md), what `install` and `package` report for npm
