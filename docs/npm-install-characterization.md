# Local npm install behavior characterization

These controlled runs characterize npm behavior. They do not grant package
installation authority or qualify a Tirith launcher. The local inspection API
continues to return evidence only.

The native Linux ARM64 trial used the official image
`node@sha256:2b028cd57303b2761d24173789c85a013558d6cf20e78f51723385f368b6e34d`,
Node 26.7.0 and npm 11.19.0, running as UID 65534. The image was 83,256,863 bytes.
Docker had no network, a read-only root, no capabilities, no-new-privileges,
bounded memory/process/CPU resources, and two private temporary filesystems.
Only controlled fixture tarballs and the driver were mounted read-only.

Node SHA-256 was
`9507fea66ea788dfb2bbef1380ef6ef8940697ef1de15bee62b279e6cfef035c`.
The npm tree contained 1,926 regular files totaling 12,182,611 bytes. Its
characterization inventory SHA-256 was
`3a34157a11136a4e01f691b297bed524edee9b8cc3bc30e34ad195b17dd8c60e`.
That inventory covers relative paths, kinds, sizes, file digests, executable
flags and link targets. A production tool closure must separately bind the
loader/shared libraries and retained native identities; these two hashes alone
are not a complete execution capability.

The exact argv, following `/usr/local/bin/node`, was:

```text
/usr/local/lib/node_modules/npm/bin/npm-cli.js install
--offline --ignore-scripts --no-audit --no-fund --no-update-notifier
--bin-links=false --package-lock=false --no-save --omit=dev
--prefix <fresh-empty-target> <controlled-local-artifact.tgz>
```

The child environment contained an explicit PATH, LANG, private HOME/cache, and
two distinct empty npm configuration files. An earlier trial pointed both
configuration options at `/dev/null`: npm refused to load one file twice. That
refusal is retained as evidence, rather than treated as an install result.

| Fixture | Observed result |
| --- | --- |
| Seven lifecycle scripts plus a bin entry | Exit 0; no lifecycle sentinel executed; exact package bytes and executable flags; no `.bin` entry |
| Implicit `binding.gyp` build | Exit 0; no generated build artifacts; exact package bytes |
| Scoped package with unavailable dev dependency | Exit 0; no dev dependency selected; exact package bytes |
| Nonempty unavailable peer dependency | Exit 1 with offline cache refusal; empty target |
| Platform/funding/license/bin metadata | Exit 0; exact package bytes; generated metadata normalizes license object and bin string |
| Packaged shrinkwrap with no manifest dependencies | Exit 0 in this fixture; shrinkwrap remained an ordinary package file |

The final case does not establish general shrinkwrap safety. The first closed
contract refuses packaged resolution/configuration files, embedded
`node_modules`, and all nonempty production/optional/peer/bundled/workspace
graphs. It captures `acceptDependencies` too; missing dependency-field capture
is never interpreted as an empty graph.

Every successful trial created `node_modules/.package-lock.json` despite
`--package-lock=false --no-save`. Its top-level shape was exactly
`lockfileVersion: 3`, `requires: true`, and a `packages` map. Each installed leaf
row contained its version, relative `file:` origin, and SHA-512 integrity of the
compressed tarball. Explicit install lifecycle scripts added
`hasInstallScript: true`; the implicit `binding.gyp` fixture did not. Other
supported metadata was copied or normalized by npm: a license object's `type`
became its license string, and a scoped package's string bin entry used the
unscoped package name and a normalized relative path.

A verifier must derive the entire allowed metadata value from the exact
retained manifest/artifact and fixed staging layout. It must reject duplicate
JSON keys, unexpected fields, changed origins/integrity, added packages and
unbounded metadata. It must not accept a hidden lock merely because npm
generated it or because its format/version looks familiar.

The source behavior was checked against npm 11.19.0's bundled Arborist
`lib/arborist/reify.js`, `lib/shrinkwrap.js` and
`npm-normalize-package-bin/lib/index.js`. The official runtime release is
documented at <https://nodejs.org/en/blog/release/v26.7.0>; the image definition
was reviewed at nodejs/docker-node revision
`6f0689e044949377103a6c7fe56ede924838f9b0`, `26/bookworm-slim/Dockerfile`.

Private local evidence is stored in
the local evidence bundle's `wp26/characterization.json`, with the
driver, fixture metadata and prior configuration-refusal trial alongside it.
This local path is an implementation evidence location, not a public report
identifier or portable installation input.
