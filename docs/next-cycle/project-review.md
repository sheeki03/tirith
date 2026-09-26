# Explicit project review

Implementation under validation. `tirith review --json` reviews known project
surfaces in the current directory. Repeated `--path` options replace that default
with an explicit set of project-relative files. The optional dashboard workflow
uses its fixed working directory and starts only after a review request.

The collector holds native parent capabilities, reads bounded regular files
without following links, then reuses the dependency, hook-body, AI-file and MCP
configuration analyzers. It starts no package manager, Git subprocess, hook, MCP
server or project command. Local threat intelligence is optional; registry
requests are never made by this workflow. Private report identities and content
hashes do not become an execution permit.

Each report states inspected, absent, changed, unsupported and unavailable
inputs. Root replacement and byte-identical file replacement invalidate their
retained identities. A saved browser report can be revalidated for ten minutes;
there are at most four retained reports. Restarting the service loses these
process-local identities and requires a fresh review.

Limits are 64 selected files, 256 KiB per file, 4 MiB charged read work, 500
assessed dependencies and 128 displayed findings. The collector checks its
ten-second work deadline between files; this does not promise a hard deadline
for an individual filesystem or parser operation. Display fields receive current
local privacy rules before complete entries are withheld at output limits.

The known-surface selection does not recursively discover private files or
nested workspaces. External Git hook paths, included requirements files,
automation DSL behavior, dependency code, runtime tool descriptors and unselected
files remain uninspected. A parsed declaration is not proof that the package is
safe or that a later command will be allowed. Use artifact inspection and the
frozen policy simulation workflow for their separate evidence.

Native containment, default activation, release qualification and complete
runtime simulation are outside the meaning of this static report.
