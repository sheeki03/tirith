# Local npm artifact inspection

The npm reader accepts one gzip stream containing a POSIX ustar archive rooted
at `package/`. It hashes the exact compressed bytes and every accepted member.
It does not extract files, contact a registry, install dependencies or execute
package scripts. Local provenance verification is recorded as
`not_performed_offline`; a provenance-looking member and its absence are not
malware evidence.

Run `tirith pkg inspect package.tgz --format json` for inspection or
`tirith pkg diff old.tgz new.tgz --format json` for release comparison. Both
commands also support human output and `--format sarif`. The existing
`tirith package inspect --artifact package.tgz --json` entry point uses the same
inspector. Automatic npm selection applies to `.tgz` only. Ambiguous `.tar.gz`
files retain the established Python inspection report and fail closed as
unsupported source distributions. Select npm explicitly with
`tirith pkg inspect package.tar.gz --ecosystem npm --json`,
`tirith pkg diff old.tar.gz new.tar.gz --ecosystem npm --json`, or
`tirith package inspect --artifact package.tar.gz --ecosystem npm --json`.
`--ecosystem python` explicitly selects the Python reader. This option applies
to local artifact files, not installed environments or wheel-set directories.
Select one ecosystem per invocation; wheel behavior is preserved.
The npm JSON schema is versioned independently, and SARIF 2.1.0 embeds its same
redacted report. Exit 1 means the archive was refused; exit 2 means review,
incomplete/qualified analysis, differences, or a usage/read error; exit 0 means
the bounded supported analysis completed without review signals or differences.
An exit 0 is not proof that arbitrary package behavior is safe.

Offline CLI display captures trusted local DLP patterns and explicitly reports
remote redaction coverage as unavailable. It does not claim effective runtime
policy coverage or fetch a remote policy. Content is redacted before display
limits; oversized reader excerpts are withheld whole. Canonical hashes and
typed status fields remain machine-readable. JSON reports are bounded to
384 KiB, with omitted-row counts; inspections accept at most eight artifacts.
The hashes identify the captured read streams, not a later mutable filesystem
path or a verified registry publisher.

The dashboard Overview also accepts an explicit project-relative tarball for
inspection, or a previous/current pair for comparison. Parent traversal,
absolute paths and symbolic links in parents or leaves are refused. Only one artifact
request runs at a time per service, and each input uses the same 32 MiB
compressed ceiling as the CLI reader. Opening the dashboard does not scan
archives. The service retains its original project directory identity, and a
replaced directory requires reopening it. The browser shows captured hashes, coverage gaps, script/code/native
observations and bounded deltas. Its download action performs a new inspection
with fresh local redaction; changed path contents can therefore produce a new
hash in the downloaded report. Neither view authorizes an installation.

The parser supports the local PAX path and decimal size records used by npm's
node-tar writer, plus the metadata keys documented in its
[PAX implementation](https://github.com/isaacs/node-tar/blob/main/src/pax.ts).
Global PAX records may contain supported metadata but cannot alter paths or
sizes. Duplicate keys, unsupported character encodings, sparse files, GNU long
name/link extensions and unknown extension semantics are refused explicitly.
Hard links, symbolic links, device nodes, FIFOs, privileged modes, traversal,
portable Windows aliases, duplicate paths, Unicode/case collisions and
file/directory collisions are also refused. The inspector never relies on the
host filesystem to interpret member paths.

The complete compressed input is read once under a cap. A gzip checksum failure,
truncation, concatenated stream or trailing compressed bytes refuses the
archive. The [single-member flate2 decoder](https://docs.rs/flate2/latest/flate2/bufread/struct.GzDecoder.html)
retains unread input so trailing data can be detected. Two zero tar terminator
blocks are required, followed only by zero padding. Content analysis begins
only after the entire supported archive structure has been validated.

Default ceilings are 32 MiB compressed, 128 MiB decoded, 32 MiB per archive
member, 20,000 headers including extensions, 4,096 bytes and 64 components per
path, 4 MiB of combined path storage, 64 KiB per PAX header, and a 1,000:1
expansion ratio. Static analysis adds independent ceilings: 512 KiB root
metadata, 2 MiB per analyzed code member, 32 MiB total analyzed code, 2,000 code
files, 16 native files, 256 signals and 256 coverage issues. Callers may tighten
these limits. A compressed input that exceeds its cap has no invented prefix
hash; an analysis limit retains the already computed exact artifact/member
identities and records incomplete coverage.

The versioned result separates archive completeness, metadata completeness and
completion of the supported static passes. Its analysis scope explicitly says
that program behavior is not proven. JavaScript receives a bounded lexical
module/call-pattern pass; comments and quoted API examples are distinguished
from code tokens. Dynamic evaluation/import selection, unsupported lexical
forms, dependency resolution, conditional exports, shell effects, nested
archives, WebAssembly and unsupported source formats remain explicit gaps.
Native objects reuse the existing bounded object-format triage.

[npm lifecycle events](https://docs.npmjs.com/cli/v11/using-npm/scripts/) are
reported with their declared event names: a `prepare` declaration does not
mean every registry installation executes it. A plain lifecycle declaration,
minified JavaScript or native module is an observation. A literal download
pipeline feeding a shell, encoded dynamic evaluation, or credential-like
filesystem reads co-occurring with network calls produces a review signal with
the actual evidence and its limits. Co-occurrence is not proof of exfiltration,
and these static signals do not authorize installation or claim containment.

The deterministic corpus includes a real tarball produced by npm 11.19.0 with
`pack --ignore-scripts --offline`, PAX long Unicode paths, malformed lengths and
checksums, traversal/alias collisions, gzip expansion limits, ordinary and
suspicious lifecycle/code pairs, native modules and incomplete formats. The
`npm_artifact` fuzz target uses smaller explicit ceilings for sustained parser
fuzzing. Corpus success is evidence for these contracts, not a claim that all
JavaScript behavior or every platform has been qualified.

Release comparison consumes two captured inspections without reading either
path again. Both exact transport hashes remain in the report. Identical bytes
never produce a package-change delta, even when analyzer output changes.
Member hashes, declared scripts, binaries, command entries and metadata changes
are kept separate from capability observations. A changed analyzer version,
limits or incomplete/different coverage disables capability-delta claims; the
new artifact's current review evidence remains visible without calling it newly
introduced. Different package names are explicitly labelled. At most 200 deltas
are retained, with an exact omitted-delta count and a qualified comparison state.
