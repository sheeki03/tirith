# Local npm archive fixtures

`npm-11.19.0-portable-pax.tgz` was generated locally with npm 11.19.0 using
`npm pack --ignore-scripts --offline --json`. Both npm configuration files and
the npm cache were isolated in a temporary directory. No dependency was fetched,
installed or executed. The test reader never extracts this archive.

The package is `tirith-local-inspection-fixture@1.0.0`. It contains an addition
function in `index.js`, a `postinstall` declaration naming `install.js` (which
only prints `local fixture`), and a long Unicode path ending in `résumé.js`.
The script declaration is an ordinary capability observation, not a malicious
finding. The transport SHA-256 is
`769755af559bda513cfe86d6c433bf8e6c0b2431dbb24955393e0dc69eeb2c0f`.

Hostile tar/PAX/gzip fixtures are generated deterministically inside
`src/artifact/npm_archive_tests.rs`. Keeping the builders visible makes their
exact malformed lengths, checksums, paths and overridden fields reviewable.
The corpus also contains a deterministic bounded malformed-input smoke test;
this does not substitute for sustained fuzzing or platform qualification.
