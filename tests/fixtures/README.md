# Golden Test Fixtures

TOML files defining expected behavior for tirith rules.

## Format

```toml
name = "descriptive_name"
min_milestone = 1  # historical product milestone; current fixtures span 0-13
input = "command string"
context = "exec"   # exec, paste, or file
shell = "posix"    # posix, fish, powershell, or cmd (optional; default posix)
expected_action = "block"  # allow, warn, block
expected_rules = ["rule_id"]  # expected rule IDs to fire
exact_rules = false             # optional exact unique RuleId equality
forbidden_rules = []            # optional RuleIds that must not fire
```

`min_milestone` records the repository's historical product milestone, not the
Web3/task-boundary commit label. C05 fixtures therefore use the current M13
baseline while their names and comments identify the C05 stack slice.

`web3.toml` is the dedicated C05-and-later Web3 corpus. Its C05 entries use the
`c05_exfil_` prefix and pair proven source-to-sink flows with source-only,
sink-only, incomplete-analysis, cross-platform path, and inbound/local controls.
The file is registered in the dedicated runner, Tier-1 coverage, aggregate count,
and global RuleId/fast-path fixture registry in `golden_fixtures.rs`.
