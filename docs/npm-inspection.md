# npm tarball inspection

`tirith pkg inspect` reads a local npm tarball (`.tgz`), hashes its exact bytes
and every member, and reports bounded static evidence about its scripts, code
and native files. It never extracts files, contacts a registry, installs
dependencies or runs package scripts.

## Inspect a tarball

```sh
tirith pkg inspect package.tgz --format json
```

Use `--format sarif` for SARIF 2.1.0 (it embeds the same redacted report), or
omit `--format` for human output. `tirith package inspect --artifact package.tgz --json`
runs the same inspector. One invocation accepts at most eight artifacts.

## Compare two releases

```sh
tirith pkg diff old.tgz new.tgz --format json
```

The comparison keeps both exact hashes. Member hashes, declared scripts,
binaries, command entries and metadata changes are reported separately from
capability observations. Identical bytes never produce a package-change delta.
Different package names are labelled as such.

## Choose the ecosystem

`.tgz` files are read as npm. A `.tar.gz` file is read as a Python source
distribution unless you select npm explicitly:

```sh
tirith pkg inspect package.tar.gz --ecosystem npm --json
tirith pkg diff old.tar.gz new.tar.gz --ecosystem npm --json
tirith package inspect --artifact package.tar.gz --ecosystem npm --json
```

`--ecosystem python` selects the Python reader. `--ecosystem` applies to local
artifact files only, not installed environments or wheel-set directories.

## Read the result

- Exit 0: the bounded supported analysis completed without review signals or
  differences.
- Exit 1: the archive was refused.
- Exit 2: review signals, incomplete analysis, differences, or a usage or read
  error.

The report separates archive completeness, metadata completeness and completion
of the static passes. [npm lifecycle events](https://docs.npmjs.com/cli/v11/using-npm/scripts/)
are reported with their declared names (a `prepare` declaration does not mean
every registry install runs it). A lifecycle declaration, minified JavaScript or
a native module is an observation. A literal download piped into a shell,
encoded dynamic evaluation, or credential-like file reads together with network
calls is a review signal, shown with its evidence and limits.

## Use the dashboard

On the [dashboard](dashboard.md)'s Overview page, enter a project-relative
tarball to inspect, or a previous/current pair to compare. The page shows the
captured hashes, coverage gaps, script/code/native observations and bounded
deltas. Its download action inspects again with fresh redaction, so changed
file contents can produce a new hash in the downloaded report.

## Limits

- Exit 0 is not proof that the package behaves safely. Neither the CLI nor the
  dashboard authorizes an installation, and co-occurring signals are not proof
  of exfiltration.
- Provenance is not verified offline (`not_performed_offline`). A
  provenance-looking member, or its absence, is not malware evidence. Hashes
  identify the bytes that were read, not a later file at the same path or a
  verified registry publisher.
- Only one gzip stream holding a POSIX ustar archive rooted at `package/` is
  accepted. A checksum failure, truncation, a concatenated stream or trailing
  bytes refuse the archive; two zero terminator blocks followed only by zero
  padding are required.
- Supported PAX records are npm's local path and decimal size records and the
  metadata keys of node-tar's
  [PAX implementation](https://github.com/isaacs/node-tar/blob/main/src/pax.ts);
  global records cannot change paths or sizes. Duplicate keys, unsupported
  character encodings, sparse files, GNU long name/link extensions, unknown
  extensions, hard and symbolic links, device nodes, FIFOs, privileged modes,
  traversal, Windows aliases, duplicate paths, Unicode/case collisions and
  file/directory collisions are refused.
- Archive ceilings: 32 MiB compressed, 128 MiB decoded, 32 MiB per member,
  20,000 headers including extensions, 4,096 bytes and 64 components per path,
  4 MiB of path storage, 64 KiB per PAX header, and a 1,000:1 expansion ratio.
  An input over the compressed cap gets no partial hash.
- Analysis ceilings: 512 KiB of root metadata, 2 MiB per code member, 32 MiB of
  code in total, 2,000 code files, 16 native files, 256 signals and 256 coverage
  issues. Reaching one keeps the computed hashes and marks coverage incomplete.
- JavaScript gets a bounded lexical pass. Dynamic evaluation or import
  selection, unsupported syntax, dependency resolution, conditional exports,
  shell effects, nested archives, WebAssembly and unsupported source formats are
  reported as gaps.
- Shell files and lifecycle scripts get a bounded command-pattern pass for a
  literal curl/wget pipeline into a shell, including inside brace groups,
  functions and subshells (also with a trailing redirection). Heredoc text is
  skipped only when the file provably just prints it: a heredoc given to
  `cat`, `echo`, `printf` or `:` (or read into a variable that is only
  echoed), in a file with no pipe except into plain text filters, no output
  redirection to a file, no capture of the printed text, no `eval`,
  `source`, `exec`, shell, `$SHELL` / `$BASH`, `sudo`, alias, `hash`,
  `autoload`, `BASH_CMDS` / `BASH_ALIASES` / `expand_aliases`, zsh
  `functions` / `commands` / `aliases` / `path` / `fpath` assignment or
  `PATH` word (other than reading `$PATH`), also when spelled with
  backslashes or quotes inside the word (`ha\sh`, `al''ias`), no function
  named after a printer, filter, `read`, `local` or `readonly`, or whose
  name holds a backslash, quote or expansion (`c\at() {`), and no command
  whose name is or holds an expansion (`"$RUN" ...`, `env "$X" ...`,
  `al${E}ias`). A variable holding the text must only appear as a plain
  `$NAME` or `${NAME}`, not inside another `${...}` or `$[...]` (a
  subscript or substring offset is arithmetic), in `echo` / `printf`
  commands that start on their own line (a `printf` whose first word after
  any redirection is or could expand to an option, such as `-v`,
  `{-v,X}`, `[-]v` or `~-`, or whose format is not a literal with only
  `%s` / `%b` / `%q` / `%c` conversions, does not count; no quoted word
  or backslash-newline carried in from another line, no lone `&`), and the
  file must not reach it indirectly (`${!...}`, a nameref, `$_`, a bare
  `set` or other variable listing). The variable must not be one the shell
  expands or evaluates by itself (`PS4` under xtrace, integer specials such
  as `OPTIND`, `RANDOM` or `SECONDS`, `BASH_*`, prompts). Anything else keeps the signal. What a caller does with a script's output is not followed.
- JSON reports are capped at 384 KiB with omitted-row counts. A comparison keeps
  at most 200 deltas with an exact omitted count. A changed analyzer version,
  changed limits, or incomplete or different coverage disables capability-delta
  claims.
- Display output is redacted with your trusted local patterns only; remote
  redaction coverage is reported as unavailable. Oversized excerpts are withheld
  whole.
- The dashboard refuses parent traversal, absolute paths and symbolic links in
  the path, runs one artifact request at a time, and uses the same 32 MiB cap.
