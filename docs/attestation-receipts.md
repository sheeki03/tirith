# Build and deployment receipts

`tirith attest` binds one source tree, one output tree, and one set of deployed
routes into content-addressed, point-in-time receipts, signed when the
installation has an audit key.

```bash
tirith attest build --source . --output ./dist --out ./build-receipt.json
tirith attest verify-build ./build-receipt.json --source . --output ./dist

tirith attest deployment --build-receipt ./build-receipt.json \
    --base-url https://app.example.com --out ./deploy-receipt.json
tirith attest verify-deployment ./deploy-receipt.json
```

## Read this part first

**These are not reproducible-build claims.** Tirith does not run your build, does
not observe the compiler, and cannot say the output was produced from the
source. Two receipts over the same source with different outputs are both
perfectly valid receipts. The `caveats` field is part of the document and
`validate` refuses a receipt that dropped it, so the limit travels with the
evidence rather than living only in this file.

**A deployment receipt is not monitoring.** It proves one thing: at the
timestamp it records, the routes it lists returned the byte sequences the build
receipt bound. A CDN can serve different bytes to the next client, in another
region, a second later. It says nothing about routes it did not fetch.

`tirith attest` is a different namespace from `tirith pkg attest`, which binds
PyPI publish attestations. The two share a verb and nothing else.

## `attest build`

What it binds: a deterministic sha256 over each tree (sorted relative paths,
mode, size, and file bytes), the HEAD commit and dirty state when the source is
a repository, the lockfile digests, the policy projection hash, a digest of the
REDACTED argv, the per-file output manifest, and the identity of the one
external tool tirith itself ran.

What it refuses, and every refusal is a refusal rather than a silently skipped
entry: a symlink anywhere in either tree, a non-regular entry, a non-UTF-8 path,
two paths that collide under case folding or Unicode normalization, a file that
was rebound, grew, or was truncated while it was being hashed, and anything past
100,000 entries, 2 GiB, or 256 directories deep.

A digest over a tree that was silently partial would be a receipt that says
something false about bytes, which is the one thing a receipt must not do.

Removed from the SOURCE digest, explicitly and on the record: `.git` at every
depth (every pruned path is listed in the receipt and folded into the digest),
the `--output` root when it is nested under `--source`, and the `--out`
destination, so a receipt can never hash itself into existence.

`--execution-receipt` links the build to a `tirith capsule run` receipt, which
is how a contained build gets connected to its own evidence.

## `attest deployment`

It verifies the build receipt FIRST. A receipt that fails its own integrity
rules, or whose signature this installation rejects, produces a mismatch and
ZERO requests.

Then it fetches only the routes the build's output manifest names, from ONE
origin, through tirith's connect-time DNS guard.

- **One origin.** The base URL is validated (HTTPS unless `TIRITH_ALLOW_HTTP=1`,
  no embedded credentials, no private, loopback, link-local, or cloud-metadata
  destination after DNS), and every redirect hop must stay on that exact scheme,
  host, and port. A cross-origin redirect is a MISMATCH, not a follow: an open
  redirect that moves the answer to another host has changed which server the
  receipt is about.
- **Route mapping is gated, including the default.** By default `index.html`
  serves its containing directory and every other file serves its exact relative
  path; `--route-map` replaces that with your own map. Both go through the same
  check, because the default is derived from filenames in a build tree nothing
  character-checked, and a file named so that its route resolves to another
  authority would otherwise send the request there. Every resolved URL is
  re-checked against the base origin before the request leaves, and a route that
  resolves elsewhere is a mismatch that reaches no network.
- **`Accept-Encoding: identity`.** The workspace builds its HTTP client without
  gzip, brotli, or deflate, so a non-identity `Content-Encoding` that arrives
  anyway means the origin or a CDN transformed the body. The bytes on the wire
  are then genuinely not the bytes that were built, and the route is PARTIAL:
  calling that a mismatch would be a false accusation.
- **Bounds.** 8 concurrent fetches, 5 redirect hops, 32 MiB per response, 2 GiB
  in total, a 30 second request budget, and a 10 second connect budget. The
  per-response cap is checked against `Content-Length` first and again on the
  read, so a lying `Content-Length` cannot get past it, and the aggregate budget
  lives in one atomic so concurrent workers cannot each spend the whole thing.

CSP, SRI, and Trusted Types are recorded as OBSERVATIONS on the route, bounded
and sanitized. They are deployment hygiene, not byte-deployment proof, and they
never move a route's state. A site with a perfect CSP that serves the wrong
bytes is a mismatch.

## `verify-deployment` does not re-fetch

It re-checks the DOCUMENT: its content address, its signature against this
installation's anchor, and its internal consistency. It makes no network
request.

That is deliberate. A second measurement presented as verification of the first
would be exactly the continuous-monitoring claim these receipts refuse to make.
To measure the site again, run `attest deployment` again.

## Status and exit codes

All four subcommands share one status vocabulary:

| Status | Exit | Meaning |
|---|---|---|
| `clean` | 0 | everything the command set out to bind was bound |
| `mismatch` | 1 | something that was bound no longer matches, or a document failed its own integrity rules |
| `partial` | 3 | evidence was produced but it is incomplete. Never a claim that the incomplete part was fine |
| usage or input error | 2 | distinct from every evidence outcome |

Exit 3 here is NOT the `tirith check` warn-acknowledgement meaning. Per-command
exit codes in this repository are deliberately distinct, and each `attest`
subcommand's help says so.

## Signature states

| Trust | Effect on status |
|---|---|
| `verified` | `clean` |
| `unsigned` | `clean` (the installation had no audit key when the receipt was made) |
| `uncheckable` | `partial` (a signature is present but this installation has no key to check it) |
| `rejected` | `mismatch` |

A STRIPPED signature is `rejected`, not `unsigned`, because stripping is
otherwise the cheapest forgery available: `signature_present` is inside the
content address on purpose, so removing the signature changes the receipt id.

## Not anchored in the audit chain

Neither receipt is entered into the tamper-evident audit hash chain. The chain's
receipt anchors are typed per receipt kind and mint their trust capability by
re-reading a receipt from a tirith-owned directory under a `0600` owner
contract, and a receipt written to an operator-chosen `--out` path cannot
satisfy that constructor. `audit_chain_anchored` is therefore always `false`,
and `validate` refuses a receipt that claims otherwise.

The same call was made for the browser baseline and the npm provenance receipt.
The `tirith capsule run` receipt is the one kind ELIGIBLE to be anchored,
because it is written to a tirith-owned store. It is anchored only when an audit
chain is configured; with the chain disabled (`TIRITH_LOG=0`) the run prints
`... and NOT anchored in the audit chain` and still exits with its normal code,
so eligibility is not the same as a guarantee. Check the printed line before
relying on a capsule receipt being tamper-evident.

## See also

- [Enforcement coverage](enforcement-coverage.md), the per-capability ledger
- [npm provenance receipt](npm-provenance-receipt.md)
- [Untrusted projects](untrusted-projects.md), where `--execution-receipt` comes from
