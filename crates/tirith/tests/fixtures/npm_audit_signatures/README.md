# `npm audit signatures` fixtures (C17)

Every fixture here backs one entry of the closed contract table in
`crates/tirith-core/src/provenance/npm.rs`
(`NPM_AUDIT_SIGNATURES_CONTRACTS`) or one honest failure mode of it. The table
only ships a version range when a fixture establishes that range's exact argv
AND its output schema, so this directory is the reason the table has exactly one
entry today.

## Captured from a real npm

| File | Provenance |
| --- | --- |
| `npm11_clean.json` | Real stdout of `npm audit signatures --json --include-attestations`, npm **11.17.0**, run against the two-package project whose lockfile is `npm11_clean_package-lock.json`. Byte-for-byte as npm printed it, Sigstore bundles included. |
| `npm11_clean_package-lock.json` | The real `package-lock.json` npm wrote for that project (`chalk@5.4.1`, `semver@7.8.5`). Paired with the file above so the attested subject digest can be bound to the lockfile `integrity` SRI. |

`semver@7.8.5` publishes provenance and appears in `verified`. `chalk@5.4.1` has
a good registry signature and no attestation, so it appears in **none** of the
three arrays: npm's `--include-attestations` JSON enumerates only the invalid,
the missing, and the ATTESTED packages (`verify-signatures.js` pushes to
`verified` inside `if (attestations)`). That is why a signature-only status is
derived by subtraction, and why the receipt says so.

## Synthesized from npm's own source

A real `invalid` or `missing` entry cannot be produced without forging a
signature or finding an unsigned release, so these three are built from the
exact object literals npm 11.17.0 pushes in
`lib/utils/verify-signatures.js`: `this.missing.push({integrity, location,
name, registry, resolved, version})` and `this.invalid.push({code, message,
integrity, keyid, location, name, registry, resolved, signature, predicateType,
type, version})`. The field NAMES and shapes are npm's; the digests, key ids,
and signature strings are synthetic.

| File | What it exercises |
| --- | --- |
| `npm11_missing.json` | A package the registry provides keys for but published no signature for. |
| `npm11_invalid_signature.json` | `code: EINTEGRITYSIGNATURE`. `predicateType` is absent, matching npm (`JSON.stringify` drops the undefined property). |
| `npm11_invalid_attestation.json` | `code: EATTESTATIONVERIFY`, with the SLSA predicate type npm carries on that error. |

## Strict-JSON corpus

These prove the four parse failures map to distinct partial reasons rather than
collapsing into one, and that none of them can read as a clean result.

| File | Refusal |
| --- | --- |
| `malformed_duplicate_key.json` | Duplicate object key: two readers would disagree about the document. |
| `malformed_trailing_data.json` | A second document appended after the first top-level value. |
| `malformed_truncated.json` | Truncated mid-document. |
| `empty.json` | Zero bytes. |
| `unknown_flag_hard_error.txt` | The usage text a future npm prints when it hard-errors on an unrecognized flag. npm 11.17.0 only WARNS today (`npm warn Unknown cli config "--x". This will stop working in the next major version of npm.`), which is precisely why the contract table is version-ranged rather than open. |

## Regenerating `npm11_clean.json`

```sh
mkdir project && cd project
printf '{"name":"tirith-c17-fixture","version":"1.0.0","private":true,\
"dependencies":{"semver":"7.8.5","chalk":"5.4.1"}}' > package.json
npm install --no-audit --no-fund --ignore-scripts
npm audit signatures --json --include-attestations
```

Needs network access to the registry and to the Sigstore TUF repository. If the
capture is refreshed, refresh `npm11_clean_package-lock.json` from the same run:
the subject-digest binding test compares the attestation's in-toto `sha512`
against the lockfile SRI, so the two files must come from one install.
