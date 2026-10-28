# Third-party test source

The small `fixtures/npm11.19.0/` subtree contains unmodified source captured
from npm CLI v11.19.0. These files are used only by pure descriptor parser
controls, not bundled into the product bootstrap. No dependencies are fetched
or installed by these controls.

- **npm-package-arg 13.0.2**, copyright npm, Inc., ISC license.
  Files: `node_modules/npm-package-arg/lib/npa.js`, package metadata and its
  complete `LICENSE`. Upstream: https://github.com/npm/cli/tree/v11.19.0/node_modules/npm-package-arg
- **validate-npm-package-name 7.0.2**, copyright 2015 npm, Inc., ISC license.
  Files: `node_modules/validate-npm-package-name/lib/index.js`,
  `lib/builtin-modules.json`, package metadata and its complete `LICENSE`.
  Upstream: https://github.com/npm/cli/tree/v11.19.0/node_modules/validate-npm-package-name

`fixtures/npm-source-manifest.json` records exact source URLs, sizes and SHA256
digests. Preserve the adjacent license text with every copied source. The
control harness verifies the manifest digests before executing the parser
sources in its bounded VM context. Its dependency stubs deliberately refuse
network/Git/version parsing outside the exact local-descriptor cases.
