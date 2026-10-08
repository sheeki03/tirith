# Project review

`tirith review` statically reviews a project's known risky surfaces (dependency
manifests, Git hook bodies, AI instruction files and MCP configuration) without
running anything from the project.

## Review a project

1. Change to the project directory.
2. Review the known surfaces:

   ```sh
   tirith review --json
   ```

3. To review specific files instead, name them (repeat `--path`; paths are
   relative to the project):

   ```sh
   tirith review --path package.json --path .mcp.json --json
   ```

4. Read each input's coverage state: inspected, absent, changed, unsupported or
   unavailable. Exit status 2 can accompany a complete report when findings or
   coverage gaps remain.

In the [dashboard](dashboard.md), use Overview → Inspect selected project files.
A saved dashboard report can be rechecked against the current files.

The review reads bounded regular files without following links and reuses the
dependency, hook-body, AI-file and MCP-configuration analyzers. It starts no
package manager, Git subprocess, hook, MCP server or project command, and makes
no registry requests. A local threat database is used when present.

## Limits

- At most 64 selected files, 256 KiB per file, 4 MiB of total read work, 500
  assessed dependencies and 128 displayed findings. Display fields are redacted
  with your current local privacy rules before entries are withheld at the
  output limits.
- The ten-second work deadline is checked between files, not inside a single
  filesystem or parser operation.
- The known-surface selection does not recurse into private files or nested
  workspaces. External Git hook paths, included requirements files, automation
  DSL behavior, dependency code, runtime tool descriptors and unselected files
  are not inspected.
- A parsed declaration does not prove a package safe or that a later command
  will be allowed. Report identities and content hashes are not an execution
  permit. Use [artifact inspection](npm-inspection.md) and
  `tirith policy simulate` for that separate evidence.
- The dashboard keeps at most four saved reports, each recheckable for ten
  minutes. Replacing the project root, or replacing a file even with identical
  bytes, invalidates a saved report. Restarting the service requires a fresh
  review.
- The report says nothing about containment, runtime behavior or default
  activation.
