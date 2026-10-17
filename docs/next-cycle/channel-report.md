# Next-cycle channel acceptance record

Status: prepared; this cycle has no selected release version or published
candidate. The workspace remains **0.4.2 development**. Existing 0.4.2 release
assets are unchanged and cannot stand in for this implementation.

The reviewed implementation checkpoint is
`e2c94439786d2d2abf87bd50a17b227f8e632c12` in
[PR #250](https://github.com/sheeki03/tirith/pull/250). Its
[release-validation run](https://github.com/sheeki03/tirith/actions/runs/36450737299)
passes all six target builds, package assembly and required runtime gates.
Signing, attestation and publication jobs were skipped on that PR run as
designed. These results establish PR package checks; every final channel
installation, upgrade and removal observation below remains **unrecorded**.
Later source or version changes require evidence bound to their own artifacts.

## Candidate identity

| Field | Value |
| --- | --- |
| Selected version, immutable tag and release commit | Not selected |
| Release workflow run and attempt | Not recorded |
| Public artifact names, URLs, sizes and SHA-256 digests | Not recorded |
| Signed checksum verification and exact workflow/tag identity | Not recorded |
| Per-channel package, recipe, registry or image identities | Not recorded |
| Test account privilege, OS/architecture and shell/agent versions | Not recorded |
| Prior installed version and verified upgrade source | Not recorded |
| Acceptance reviewer, date and retained evidence links | Not recorded |

Use the [release checklist](../release-checklist.md) for publication order and
verification. Bind signed downloads to this repository's
`release.yml@refs/tags/v<VERSION>` identity and the selected commit. An absent
attestation or a source build must retain its actual evidence grade; do not
infer official binary identity from a matching version string.

## Channel evidence

All states below describe the **new cycle candidate**, not whether older
versions exist. “Not published” also means publication has not been attempted
for this undecided candidate. Independent downstream channels require their own
availability observations.

| Channel | Exact identity and provenance to retain | Installation, upgrade and removal route | Current cycle state |
| --- | --- | --- | --- |
| GitHub archives and installer | Six public platform archives and installer; hashes against the signed checksum manifest; extracted executable hashes and exact target/libc | Ordinary-user installer or standalone archive; self-update and supported rollback; owned setup removal | Not published; final journeys unrecorded |
| Debian package | Public `.deb` hash and GitHub build attestation bound to tag/commit; both executables byte-identical to canonical x86_64 GNU archive | `dpkg`/APT ownership; package upgrade and removal; preserve unrelated configuration | Not published; final journeys unrecorded |
| RPM package | Public `.rpm` hash and GitHub build attestation bound to tag/commit; both executables byte-identical to canonical x86_64 GNU archive | RPM/DNF ownership; package upgrade and removal on advertised distributions | Not published; final journeys unrecorded |
| crates.io / Cargo | Exact `tirith-core` then `tirith` registry versions and crate checksums; source revision and local build/toolchain identity | Cargo install, upgrade and uninstall; record source-built executable hash without claiming canonical archive identity | Not published; final journeys unrecorded |
| npm | Unscoped `tirith` plus five `@sheeki03/tirith-*` platform versions; registry integrity and npm provenance; wrapper and extracted native hashes | npm-managed install, upgrade and uninstall; clean and blocked commands through the actual wrapper | Not published; final journeys unrecorded |
| Homebrew tap | `sheeki03/homebrew-tap` commit/formula; four platform URLs/checksums matching signed release archives | Tap formula install, upgrade and uninstall; resolve the actual symlink target | Not published; final journeys unrecorded |
| Homebrew core | Independent core formula revision, source/bottle checksums and installed bottle/build identity | Core formula install, upgrade and uninstall; verify availability separately from the tap | Downstream update unrecorded; final journeys unrecorded |
| Scoop | `sheeki03/scoop-tirith` bucket commit, exact manifest version and archive checksum | Scoop install, update and uninstall; verify shim target and ordinary-user location | Not published; final journeys unrecorded |
| Chocolatey | Exact `.nupkg` version/hash, embedded download checksum and submission result; approved version from `choco info tirith` | Community install, upgrade and uninstall; record actual account privileges and resolved executable | Not submitted; moderation unrecorded; final journeys unrecorded |
| AUR | AUR commit, `PKGBUILD`/`.SRCINFO`, exact tagged source checksum and local package/build identity | Pacman-owned install, upgrade and removal; retain source-built executable hash | Not published; final journeys unrecorded |
| GHCR | Immutable version manifest digest and amd64/arm64 child digests; contained executables matched to canonical GNU archives | Pull/run by digest; replace with the selected version and remove owned containers/images; host shell activation is not a container capability | Not published; final journeys unrecorded |
| Nix upstream flake / nixpkgs | Record each route separately: exact flake or nixpkgs revision, lock inputs, derivation/store identity and executable hash | Nix-managed install, generation upgrade/rollback and removal; preserve Home Manager ownership | No dedicated release publisher; selected-version availability and journeys unrecorded |
| mise | Registry/backend revision, selected exact version, downloaded artifact identity and resolved shim target | mise-managed install, version switch/upgrade and removal | No dedicated release publisher; selected-version resolution and journeys unrecorded |
| asdf | `sheeki03/asdf-tirith` plugin revision, selected exact version, downloaded artifact identity and resolved shim target | asdf-managed install, version switch/upgrade and removal | No dedicated release publisher; selected-version resolution and journeys unrecorded |

After a successful Chocolatey submission, record **pending external approval**
until the community package is actually available. A failed submission remains
**failed**. Apply the same distinction to downstream propagation and record
timestamps; submission or a green publisher job alone does not prove availability.

## Installed acceptance

For each advertised tuple, append evidence links for the exact public download,
install/upgrade/remove commands, exit status, executable digest and package-owner
readback. Capture `tirith version --provenance`, `tirith verify-self` and
`tirith doctor`, preserving partial, unsupported and unverified outcomes.
Record installed and loaded integration versions separately, required fresh
shell/host reloads, harmless allow-once and inert blocked-marker results, browser
assets where applicable, retained settings and ownership-preserving removal.
Use the [acceptance matrix](acceptance-matrix.md) for the qualified surface;
unavailable adapters cannot become certified through package installation.

Ordinary protection must work without elevation. Record any package manager's
installation privileges separately and confirm optional privileged approval is
off by default with accurate unavailable-feature guidance. For source-built
channels, retain their actual provenance result instead of requiring byte
identity with a different official build.

Final G1 acceptance also needs the [consented beginner record](beginner-pilot.md)
and [ThreatDB operational evidence](threatdb-operations.md). A successful PR
build, completed channel row or unattempted human journey cannot substitute for
those separate observations.
