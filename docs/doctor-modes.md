# `tirith doctor` modes (full vs `--quick`)

`tirith doctor` has two report depths:

- **Full** (`tirith doctor`, the default) — a complete installation and
  configuration diagnostic: shell/hook state, policy discovery, threat-DB
  status, anomaly-baseline status, detection-gap analysis from the audit log,
  shadow-binary detection, and (on Unix) the bash enter-mode capability cache.
  Some of these probes are deliberately expensive: they parse the audit log
  (which can grow to tens of MB), deserialize the threat database, read the
  baseline store, and walk `PATH`.
- **Quick** (`tirith doctor --quick`) — a fast, read-only status snapshot that
  reports only what a polling integration needs. It skips every expensive probe
  the full report runs, so it is cheap enough to poll on a short interval.

Full, quick, and compatibility JSON reports include `protection_evidence`.
Their inherited environment markers and startup-file configuration are diagnostic
inputs: neither verifies that the current shell blocks dangerous commands. Raw
legacy fields and generic command exit codes remain available. Human reports
label inherited markers as reported and blocking as unverified.

For a strict blocking requirement, use `tirith status --require-verified-blocking`.
A fresh authenticated caller-shell observation can establish blocking only for
that shell and its bound configuration; full doctor and `doctor --compat` do not
perform that verification.

## When to use `--quick`

`--quick` exists for integrations that need a frequently-refreshed protection
status without paying for the full diagnostic — most notably the VS Code
extension, which polls `tirith doctor --quick --format json` roughly every 30
seconds.

`--quick` is **read-only**: it never materializes hooks, downloads anything, or
mutates state. It is **safe to poll** at a short interval.

`--quick` is compatible with `--format json` (and the hidden `--json` alias).
It is mutually exclusive with the mutating and full-report flags: `--fix`,
`--reset-bash-safe-mode`, `--simulate-enter`, `--compat`, and `--bundle`.

## What `--quick` skips

`--quick` does **not** run any of these full-report probes:

| Skipped probe          | What the full report does with it                      |
| ---------------------- | ------------------------------------------------------ |
| Audit-log analysis     | Reads and parses `data_dir()/log.jsonl` (can be large) |
| Threat-DB status       | Loads and deserializes the threat database             |
| Anomaly-baseline status| Reads the baseline observation store                   |
| Shadow-binary check    | Walks `PATH` looking for other `tirith` binaries       |
| Bash enter-capability  | Reads the cached bash enter-mode self-test verdict     |

Because none of these run, `--quick` returns quickly and performs no large file
reads, no deserialization, and no `PATH` walk.

## `--quick --format json` output

The JSON object is intentionally minimal and stable — exactly these fields:

| field             | type             | meaning                                                                                                                                                                                                       |
| ----------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `schema_version`  | integer          | Version of this payload's shape. Currently `1`. Bumped only on a breaking change to the field set or meaning.                                                                                                  |
| `protection_mode` | string | Legacy reported mode: reads `TIRITH_BASH_EFFECTIVE_PROTECTION` first, then `TIRITH_STATUS`. Values are `guarded`, `warn-only`, `degraded`, `off`, or an unrecognized value passed through verbatim. An absent/nonexported marker also maps to `off`; it does not establish missing activation or verified blocking. |
| `policy_path_used`| string or `null` | The single policy file the engine would load for the current directory, or `null` when none is discovered. Existence-based discovery only — never a network fetch.                                            |
| `hook_configured` | boolean          | Whether the tirith shell hook is configured in the detected shell's profile.                                                                                                                                   |
| `protection_evidence` | object | Canonical evidence with source, state, freshness, observation/expiry times, and `verified_blocking`. Ordinary doctor capture always leaves `verified_blocking` and `fresh` false. |

Example:

```json
{
  "schema_version": 1,
  "protection_mode": "guarded",
  "policy_path_used": "/path/to/repo/.tirith/policy.yaml",
  "hook_configured": true,
  "protection_evidence": {
    "schema_version": 1,
    "surface": "current-shell",
    "state": "configured",
    "source": "inherited-environment-unverified",
    "observed_at": null,
    "expires_at": null,
    "fresh": false,
    "verified_blocking": false,
    "invalidation_reason": "no allow-and-block observation for this shell process and current configuration",
    "reported_integration_version": null,
    "reported_integration_shell": null,
    "integration_version_source": "inherited-environment-unverified"
  }
}
```

### `protection_mode` values

`protection_mode` uses the same vocabulary as `tirith prompt-status` (see
`docs/prompt-integration.md`), derived from the hook's effective-protection
signal — `TIRITH_BASH_EFFECTIVE_PROTECTION` first, falling back to
`TIRITH_STATUS`. Both carry the same value set:

| hook signal value   | `protection_mode` | meaning                                            |
| ------------------- | ----------------- | -------------------------------------------------- |
| `blocks`            | `guarded`         | Marker reports blocking; current-shell blocking remains unverified. |
| `warn-only`         | `warn-only`       | Marker reports checking without blocking. |
| `degraded`          | `degraded`        | Marker reports a downgrade to warn-only. |
| `off`, empty, unset | `off`             | No live mode visible to this external process / protection off.|
| (any other value)   | (verbatim)        | Forwarded unchanged for forward compatibility.     |

`protection_mode` preserves the reported marker, which may be inherited or
absent. It does not authenticate the hook state of the calling shell. A saved
report, a startup-file entry, or exporting `TIRITH_STATUS=blocks` cannot promote
`protection_evidence.verified_blocking`.

## `--quick` human output

Without `--format json`, `--quick` prints a short 2-3 line summary instead of
the full diagnostic:

```text
  protection:   guarded (reported; blocking unverified)
  hook:         configured
  policy:       /path/to/repo/.tirith/policy.yaml
```
