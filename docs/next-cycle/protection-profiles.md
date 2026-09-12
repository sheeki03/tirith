# Personal protection profiles, version 1

These versioned presets describe concrete rule/action behavior. They are distinct
from named `scan.profiles`, integration selection, and presentation preferences.
The definition's compact/detailed presentation suggestion is display guidance;
it does not change authorization. The legacy `paranoia` setting still filters
findings and can recalculate actions, so it is held at 1 for all three presets
and is not described as a verbosity control.

| Behavior | Comfortable v1 | Balanced v1 | Strict v1 |
| --- | --- | --- | --- |
| Existing High/Critical findings | Block retained | Block retained | Block retained |
| `non_standard_port`, `non_ascii_path` | Low | Low | Built-in Medium |
| `raw_ip_url` alone | Low | Medium advisory | Medium acknowledgement |
| `shortened_url`, `package_repo_mismatch` when not already blocked | Advisory | Selected confirmation, 120 seconds, timeout blocks | Warning acknowledgement |
| Other Medium findings | Advisory | Advisory | Warning acknowledgement |
| `analysis_incomplete`, `wrapper_chain_too_deep` | Existing behavior | Existing behavior | Action override blocks |
| Internal failure | Open | Open | Closed |
| Interactive environment bypass | Permitted | Permitted | Disabled |
| Noninteractive environment bypass | Disabled | Disabled | Disabled |
| Scan complete coverage | Existing default | Existing default | Required |

Balanced uses existing per-rule approval rules; it does not turn on global
`strict_warn`. A finding already blocked remains blocked and does not become
approvable. Package repository mismatch requires the package analysis that emits
that finding; the profile does not fabricate online evidence. A caller without
an authenticated interactive approval boundary refuses a pending confirmation.
Strict's acknowledgement behavior likewise remains subject to the actual
surface's interaction capability.

All presets retain unrelated detection, repository tightening, organization and
remote restrictions, and incident restrictions. Explicit manual customizations
remain explicit overrides. Saving a personal preference cannot claim it is
effective under an organization or remote replacement.

`protection_profiles::prepare_change` is a pure document transformation. It
returns proposed YAML and a public changes/custom-overrides projection to the
shared operation service. It performs no write. Apply records the selected name,
version, and precisely which fields it inserted. Existing explicit settings are
preserved, including manual approval rules. Switching presets replaces only
unchanged owned defaults; reset removes only unchanged owned defaults. A manual
edit made after selection survives both switching and reset. Unknown versions,
duplicate ownership entries, and ownership of fields outside the named definition
are rejected.

Enforcement settings are materialized as existing policy fields. The profile
marker records intent and ownership and never causes hidden runtime defaults.
An older client that ignores the marker still enforces the concrete policy.
Repository markers are neutralized and cannot claim ownership of operator
preferences. Shipped v1 definitions are immutable; a behavior change requires a
new version, a behavior comparison, and an explicit update operation/release note.
There is no automatic profile promotion or observe-only preset.

The corpus covers ordinary Git/Go/npm commands, quoted output, ordinary downloads,
nearby download-and-execute/exfiltration controls, selected versus unselected
advisories, unsupported prompt hosts, and strict incomplete-analysis handling.
Reset, repeated apply, unrelated settings, forged ownership, unknown versions,
and old-reader materialization have independent regressions.
