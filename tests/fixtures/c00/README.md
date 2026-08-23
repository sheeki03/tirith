# C00 post-r3 compatibility baseline

This fixture set freezes security and compatibility contracts at the exact
post-r3 base before the Web3/task-boundary stack changes production behavior.

- branch base: `1ff079dee632989c244a95c06606ce026f60cac9`
- base parent: `e638e156a1652d9e18bd50a18406112cd0f8ba4c`
- base tree: `ca7a0471b689f80ae4b1e8e137755696387ad37d`
- PR #187 tip: `3bbd568db9e7be899e4b20b2206cefae2633a879`
- PR #180 tip: `e638e156a1652d9e18bd50a18406112cd0f8ba4c`
- PR #181 tip: `1ff079dee632989c244a95c06606ce026f60cac9`
- Tirith version: `0.3.3`
- Rust MSRV: `1.83`
- workspace manifest SHA-256: `6bdb2ccdc84225072cd2f69c601687220ebe2bd32b88a4a354a488e6cd658857`
- lockfile SHA-256: `89a2a0e852196f7427f515bedf962d2cd8495c2792b949ce1c221b71ee8b0885`
- shared signed v1 DB fixture SHA-256: `32be54fcfa8abb1321787a1029bb781f6d60cd32fbe9609b60f4c376ef134371`

Post-r3 source snapshots (computed from `git show 1ff079de:<path>`):

| Source | SHA-256 |
|---|---|
| `crates/tirith-core/src/threatdb.rs` | `f34c898657c0d3ec5ee440206bae038c7bb4efe44b14268b7587f307a5c52009` |
| `crates/tirith/src/cli/threatdb_cmd.rs` | `5daf60cf7e6a40a68f5067b2edba1007e98a8e0907424b1d61da8b0ab231cfbe` |
| `crates/tirith-core/src/policy.rs` | `b9354c18ae6801b50939950c5513a533ee1e1f2c2aea40ee813c9f9014b62ee2` |
| `crates/tirith-core/src/command_card.rs` | `f21f45eecf60d14700ced6cf1c3fa265cdae5c3eaa63acd870416e626e36d630` |
| `crates/tirith-core/src/mcp/tools.rs` | `84588c575daa1126cb5ceef6f5b70f866c2e4698368c0c5f765dd38cd0bde5a1` |
| `crates/tirith/tests/cli_integration.rs` | `4251e924e393b80a8a233d321d9309e85d4931d163030fd82f0307d3108df0c5` |
| `docs/capability-manifest.toml` | `adc381012366d995f6c55ca2b1850e3071791d3cea0e6f2d7fd854545b010c65` |

`contracts.toml` records deterministic byte/hash expectations and the exact
default MCP tool names. `legacy-policy-v1.yaml` and
`command-card-v1-signing.json` are inputs, not generated outputs.

All CLI cases run with test-owned HOME, USERPROFILE, XDG config/data/state/cache
and runtime directories, AppData roots, working directory, policy roots,
ThreatDB paths, credentials, audit state, and receipt/state roots.
