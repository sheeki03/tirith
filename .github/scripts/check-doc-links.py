#!/usr/bin/env python3
"""Check the repository's Markdown links and documentation path references.

Reports, for every tracked Markdown file:
  * a relative link (inline, image or reference definition) whose target file
    or directory does not exist;
  * a `#fragment` that names no heading or explicit anchor in the target
    Markdown file (GitHub heading slugs);
  * a mention of a command that was removed before release;
  * a `tirith trust add` example (in code) that the current CLI refuses:
    one without `--rule` or `--all-rules`, or a domain / wildcard pattern
    without `--broad`;
  * a fenced `tirith pkg approve` / `tirith pkg install` example: both are
    disabled on every host in this release.
For tracked source, script and workflow files it also reports a `docs/*.md`
path named in a comment (or a GitHub `blob/<ref>/` URL) that does not exist.

Standard library only. Exit 0 when clean, 1 when problems are found.
Usage: check-doc-links.py [REPO_ROOT]
"""
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

# Commands removed before they were ever released. Documentation must not
# describe them as available.
REMOVED_COMMANDS = (
    (re.compile(r"\btirith\s+menu\b"), "`tirith menu` was removed"),
    (re.compile(r"\binstall-npm\b"), "`tirith pkg install-npm` was removed"),
    (re.compile(r"\bpkg\s+materialize\b"), "`tirith pkg materialize` was removed"),
)

TRUST_ADD = re.compile(r"\btirith\s+trust\s+add\s+([^\s`#]+)([^`#]*)")


def trust_add_problems(code):
    """Problems with each `tirith trust add` invocation in a code fragment."""
    problems = []
    for match in TRUST_ADD.finditer(code):
        target, rest = match.group(1), match.group(2)
        words = [target] + rest.split()
        if any(w in ("--help", "-h") for w in words):
            continue
        if target.startswith("-") or target.isupper():
            continue  # a flag-first or placeholder form such as PATTERN
        if not any(w == "--all-rules" or w == "--rule" or w.startswith("--rule=")
                   for w in words):
            problems.append(
                f"`tirith trust add {target}` needs --rule RULE or --all-rules"
            )
        host = re.sub(r"^[a-z]+://", "", target)
        if ("*" in host or "/" not in host) and "--broad" not in words:
            problems.append(
                f"`tirith trust add {target}` trusts a domain and needs --broad"
            )
    return problems


DISABLED_PKG = re.compile(r"\btirith\s+pkg\s+(approve|install)\s+(?!-h\b|--help\b)\S")


SOURCE_SUFFIXES = {
    ".rs", ".py", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".nu", ".yml",
    ".yaml", ".toml", ".js", ".mjs", ".ts",
}
SKIP_PREFIXES = ("target/", "fuzz/target/", "node_modules/")
# Verbatim third-party audit reports, kept exactly as received. Their links
# point into the auditor's own checkout, not this repository.
VERBATIM_PREFIXES = ("docs/security/remediation/sources/",)
FENCE = re.compile(r"^\s*(```|~~~)")
INLINE_CODE = re.compile(r"(`+)(?:(?!\1).)+?\1")
INLINE_LINK = re.compile(r"!?\[(?:[^\[\]]|\[[^\[\]]*\])*\]\(\s*(<[^>]*>|[^)\s]+)(?:\s+\"[^\"]*\")?\s*\)")
REF_DEF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*(<[^>]*>|\S+)")
HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
HTML_ANCHOR = re.compile(r"<a\s+(?:[^>]*?\s)?(?:id|name)=\"([^\"]+)\"", re.I)
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
DOC_PATH = re.compile(r"(?<![\w.-])((?:\.\./)*docs/[\w./-]+?\.md)\b")
BLOB_DOC = re.compile(r"/blob/[\w.-]+/(docs/[\w./-]+?\.md)\b")
COMMENT_LINE = re.compile(r"^\s*(//|#|\*|/\*|--|<!--|;)")


def tracked_files(root):
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True, capture_output=True,
        ).stdout.decode("utf-8")
        names = [n for n in out.split("\0") if n]
    except (OSError, subprocess.CalledProcessError):
        names = [str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()]
    return sorted(n for n in names if not n.startswith(SKIP_PREFIXES))


def slugify(heading):
    text = re.sub(r"<[^>]+>", "", heading)
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = text.replace("`", "").strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def markdown_lines(text):
    """Yield (line_number, line, in_code_block) for a Markdown document."""
    fence = None
    for number, line in enumerate(text.splitlines(), 1):
        match = FENCE.match(line)
        if match:
            marker = match.group(1)
            if fence is None:
                fence = marker
                yield number, line, True
                continue
            if marker == fence:
                fence = None
                yield number, line, True
                continue
        yield number, line, fence is not None


def anchors_of(path, cache):
    if path in cache:
        return cache[path]
    found = set()
    counts = {}
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        cache[path] = found
        return found
    for _, line, in_code in markdown_lines(text):
        if in_code:
            continue
        for anchor in HTML_ANCHOR.findall(line):
            found.add(anchor)
        match = HEADING.match(line)
        if match:
            slug = slugify(match.group(2))
            n = counts.get(slug, 0)
            counts[slug] = n + 1
            found.add(slug if n == 0 else f"{slug}-{n}")
    cache[path] = found
    return found


def check_target(root, source, target, anchor_cache):
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    if not target or SCHEME.match(target) or target.startswith("//"):
        return None
    path_part, _, fragment = target.partition("#")
    path_part = urllib.parse.unquote(path_part.split("?", 1)[0])
    if path_part:
        if path_part.startswith("/"):
            resolved = root / path_part.lstrip("/")
        else:
            resolved = (source.parent / path_part)
        try:
            resolved.resolve().relative_to(root)
        except ValueError:
            # Leaves the repository: a GitHub web route such as
            # ../../security/advisories/new, which no checkout can verify.
            return None
        if not resolved.exists():
            return f"broken link {target!r}: {path_part} does not exist"
    else:
        resolved = source
    if fragment and resolved.is_file() and resolved.suffix.lower() == ".md":
        if urllib.parse.unquote(fragment) not in anchors_of(resolved, anchor_cache):
            return f"broken anchor {target!r}: no heading #{fragment} in {resolved.relative_to(root)}"
    return None


def check_markdown(root, name, anchor_cache):
    path = root / name
    problems = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return problems
    continued = ""
    for number, line, in_code in markdown_lines(text):
        for pattern, why in REMOVED_COMMANDS:
            if pattern.search(line):
                problems.append(f"{name}:{number}: {why}")
        if in_code:
            # Join shell line continuations so flags on later lines count.
            if line.rstrip().endswith("\\"):
                continued += line.rstrip()[:-1] + " "
                continue
            for why in trust_add_problems(continued + line):
                problems.append(f"{name}:{number}: {why}")
            disabled = DISABLED_PKG.search(continued + line)
            if disabled:
                problems.append(
                    f"{name}:{number}: `tirith pkg {disabled.group(1)}` is "
                    "disabled on every host; do not show it as a working example"
                )
            continued = ""
            continue
        continued = ""
        for span in INLINE_CODE.finditer(line):
            for why in trust_add_problems(span.group(0).strip("`")):
                problems.append(f"{name}:{number}: {why}")
        prose = INLINE_CODE.sub("", line)
        targets = [m.group(1) for m in INLINE_LINK.finditer(prose)]
        ref = REF_DEF.match(prose)
        if ref:
            targets.append(ref.group(1))
        for target in targets:
            problem = check_target(root, path, target, anchor_cache)
            if problem:
                problems.append(f"{name}:{number}: {problem}")
    return problems


def check_source(root, name):
    path = root / name
    problems = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return problems
    for number, line in enumerate(text.splitlines(), 1):
        refs = [m.group(1) for m in BLOB_DOC.finditer(line)]
        if COMMENT_LINE.match(line):
            refs += [m.group(1) for m in DOC_PATH.finditer(line)]
        for ref in refs:
            if "/examples/" in ref:
                continue  # an illustrative path, not a document reference
            candidates = [root / ref.lstrip("./")]
            if ref.startswith("../"):
                candidates.append((path.parent / ref).resolve())
            stripped = re.sub(r"^(\.\./)+", "", ref)
            candidates.append(root / stripped)
            if not any(c.exists() for c in candidates):
                problems.append(f"{name}:{number}: names missing document {ref}")
    return problems


def check(root):
    root = Path(root).resolve()
    anchor_cache = {}
    problems = []
    for name in tracked_files(root):
        suffix = Path(name).suffix.lower()
        if name.startswith(VERBATIM_PREFIXES):
            continue
        if suffix == ".md":
            problems += check_markdown(root, name, anchor_cache)
        elif suffix in SOURCE_SUFFIXES:
            problems += check_source(root, name)
    return problems


def main(argv):
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[2]
    problems = check(root)
    for problem in problems:
        print(problem)
    if problems:
        print(f"{len(problems)} documentation link problem(s)", file=sys.stderr)
        return 1
    print("documentation links: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
