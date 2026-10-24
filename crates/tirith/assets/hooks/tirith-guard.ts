// Pi-family agent extension: intercepts shell tool calls and runs a tirith
// security check before the host executes them.
//
// One file serves Pi CLI, Prime Agent, and OMP. All three expose the same
// `pi.on("tool_call", ...)` pre-execution event and the same
// `{ block: true, reason }` veto, so setup substitutes the two placeholders
// below and writes the same bytes into each host's extension directory.
//
// Like `openclaw-tirith-guard.ts`, this asset deliberately stays valid
// JavaScript even though its extension is `.ts`: the hosts load it through a
// TypeScript-aware runtime, while the conformance test loads the exact shipped
// bytes and needs no transform to do it. Types are documented in JSDoc.
//
// Protocol limitation: the extension API supports only two return values:
//   - undefined (allow, invisible to the agent)
//   - { block: true, reason } (deny with a reason)
// There is no "allow with message". On the warn-allow path findings go to
// process.stderr as a best-effort side channel; the host may or may not surface
// stderr to the user.
//
// Environment:
//   TIRITH_HOOK_WARN_ACTION       — "allow" (default) or "deny" for engine warnings
//   TIRITH_HOOK_UNRESOLVED_ACTION — "deny" (default) or "warn" for an execution
//                                   path whose real command this cannot read
//   TIRITH_FAIL_OPEN              — "1" to allow on error (default: deny)

import { execFileSync } from "node:child_process";

const TIRITH_BIN = "__TIRITH_BIN__";
const TIRITH_INTEGRATION = "__TIRITH_INTEGRATION__";

/** Tool names that carry a shell command string in `input.command`. */
const SHELL_TOOLS = new Set(["bash", "shell", "run_terminal_command", "terminal"]);
/** Tool names whose `input.code` is an IPython cell. */
const NOTEBOOK_TOOLS = new Set(["ipython", "python", "jupyter"]);
/** OMP tools that can execute without going through its `bash` tool. */
const OMP_EVAL_TOOL = "eval";
const OMP_PROCESS_TOOL = "hub";
const OMP_DEBUG_TOOL = "debug";

/** OMP debug actions whose effects are inspection-only. */
const OMP_DEBUG_READONLY_ACTIONS = new Set([
  "output", "threads", "stack_trace", "scopes", "variables", "disassemble",
  "read_memory", "loaded_sources", "modules", "sessions",
]);

/**
 * `tirith check` reads the command from stdin when it is given no argument and
 * stdin is not a terminal, capped at one mebibyte. The script is handed over
 * that way rather than as an argument, so its size is bounded by a stated
 * limit instead of by the platform's argument-length ceiling.
 */
const MAX_CHECK_SCRIPT_BYTES = 1024 * 1024;
/** Prevent adversarial tool payloads from making argv rendering itself unbounded. */
const MAX_EXEC_ARGUMENTS = 4096;

// ---------------------------------------------------------------------------
// IPython cell execution-vector extraction.
//
// A notebook cell can reach a shell through several syntaxes at once, so this
// collects every vector it can recognise rather than returning at the first
// hit: a cell whose first line is a harmless `!ls` and whose fifth line calls
// `os.system(...)` must not be waved through on the strength of the first line.
//
// Extraction only. Nothing here decides whether a command is dangerous; the
// recovered commands go to `tirith check`, so every security decision stays in
// the engine. What this CANNOT do is prove arbitrary Python safe. A wrapper
// function defined in an earlier cell, a `getattr` or `__import__` indirection,
// or a third-party package that spawns a process will not be recognised. The
// guard raises the cost of the obvious routes and refuses the unreadable ones;
// it is not a sandbox, and the documentation says so.
// ---------------------------------------------------------------------------

/**
 * @typedef {object} IpythonVectors
 * @property {string[]} commands
 *   Literal shell commands recovered from the cell, in source order.
 * @property {string[]} unresolved
 *   Execution vectors whose command could not be recovered as a literal, such
 *   as `os.system(user_input)` or `!echo {payload}`. Reported, never guessed:
 *   the cell reaches a shell in a way this cannot show the engine.
 */

/**
 * Import bindings remembered across cells.
 *
 * Prime's kernel is persistent, so `import subprocess as sp` in one cell makes
 * `sp.run(...)` an execution vector in every later cell. A fresh set per cell
 * would forget that.
 *
 * @typedef {object} KernelBindings
 * @property {Map<string, string>} moduleAlias local name -> os | subprocess | pty
 * @property {Map<string, {module: string, member: string}>} bareExec
 *   local name -> canonical execution API bound by `from os import ...`
 * @property {Set<string>} ipythonAlias names bound by `ip = get_ipython()`
 */

/** @returns {KernelBindings} */
export function createBindings() {
  return { moduleAlias: new Map(), bareExec: new Map(), ipythonAlias: new Set() };
}

const SHELL_CELL_MAGIC = /^\s*%%(bash|sh|script)\b(.*)$/;
const SHELL_INTERPRETERS = new Set([
  "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish",
]);
/** `%%script` options that consume the following word. */
const SCRIPT_VALUE_OPTIONS = new Set(["--out", "--err", "--proc"]);
/** `%%script` options that stand alone. */
const SCRIPT_FLAG_OPTIONS = new Set(["--bg", "--no-raise-error", "--raise-error"]);

/**
 * `!cmd`, `!!cmd`, and assignment from a system command. IPython's own
 * transformer accepts `name`, `name.attr`, and `name[index]` on the left, so
 * the same shapes are accepted here. `!(?!=)` keeps `a != b` a comparison.
 */
const PY_IDENTIFIER_SOURCE = String.raw`[_\p{ID_Start}][_\p{ID_Continue}]*`;
const BANG_LINE = new RegExp(
  String.raw`^\s*(?:${PY_IDENTIFIER_SOURCE}(?:\.${PY_IDENTIFIER_SOURCE}|\[[^\]]*\])*\s*=\s*)?!{1,2}(?!=)(.*)$`,
  "u",
);
/** `%system cmd`, `%sx cmd`, and their assignment forms. */
const SYSTEM_MAGIC = new RegExp(
  String.raw`^\s*(?:${PY_IDENTIFIER_SOURCE}(?:\.${PY_IDENTIFIER_SOURCE}|\[[^\]]*\])*\s*=\s*)?%(?:system|sx)\s+(.*)$`,
  "u",
);
/** Any other magic can run a built-in or user-defined executor. */
const OTHER_MAGIC = /^\s*%{1,2}[_\p{ID_Start}]/u;
/**
 * IPython expands `{expr}` and `$name` / `${name}` inside a shell escape before
 * running it. Either makes the command a runtime value.
 */
const IPYTHON_EXPANSION = /\{[^{}]*\}|\$\{?[_\p{ID_Start}]/u;

/** `os` members that take ONE command string. */
const OS_COMMAND = new Set(["system", "popen"]);
/** `os` members that take a program and an argv spread across the arguments. */
const OS_ARGV = new Set([
  "execl", "execle", "execlp", "execv", "execve", "execvp", "execvpe",
  "spawnl", "spawnle", "spawnlp", "spawnv", "spawnve", "spawnvp", "spawnvpe",
  "posix_spawn", "posix_spawnp",
]);
const SUBPROCESS_EXEC = new Set([
  "run", "call", "check_call", "check_output", "Popen",
  "getoutput", "getstatusoutput",
]);
const PTY_EXEC = new Set(["spawn"]);
const EXEC_MODULES = new Set(["os", "subprocess", "pty"]);
/**
 * Member names specific enough to be an exec site on ANY receiver. `run` and
 * `system` are too common to treat that way, so those still need a receiver
 * that is known to be the module; these never appear on anything else, which
 * lets a module imported before the guard loaded still be caught.
 */
const UNAMBIGUOUS_EXEC_MEMBERS = new Set([
  ...OS_ARGV, "Popen", "check_call", "check_output", "getoutput", "getstatusoutput",
]);

const STRING_PREFIXES = new Set([
  "r", "b", "u", "f", "rb", "br", "fr", "rf", "bf", "fb",
]);

function execNamesFor(module) {
  if (module === "os") return new Set([...OS_COMMAND, ...OS_ARGV]);
  if (module === "subprocess") return SUBPROCESS_EXEC;
  return PTY_EXEC;
}

/**
 * Read one Python string literal starting at `start` (a quote character).
 *
 * @param {string} src
 * @param {number} start
 * @param {boolean} raw
 * @param {boolean} formatted true for an f-string
 * @param {boolean} bytes true for a bytes literal
 * @returns {{ value: string, end: number, dynamic: boolean }}
 */
function readString(src, start, raw, formatted, bytes = false) {
  const quote = src[start];
  const triple = src.slice(start, start + 3) === quote.repeat(3);
  const delim = triple ? quote.repeat(3) : quote;
  let i = start + delim.length;
  let out = "";
  let dynamic = false;
  const n = src.length;

  while (i < n) {
    if (!raw && src[i] === "\\" && i + 1 < n) {
      const esc = src[i + 1];
      if (esc === "n") { out += "\n"; i += 2; continue; }
      if (esc === "t") { out += "\t"; i += 2; continue; }
      if (esc === "r") { out += "\r"; i += 2; continue; }
      if (esc === "a") { out += "\x07"; i += 2; continue; }
      if (esc === "b") { out += "\x08"; i += 2; continue; }
      if (esc === "f") { out += "\x0c"; i += 2; continue; }
      if (esc === "v") { out += "\x0b"; i += 2; continue; }
      if (esc === "\\") { out += "\\"; i += 2; continue; }
      if (esc === "'") { out += "'"; i += 2; continue; }
      if (esc === '"') { out += '"'; i += 2; continue; }
      if (esc === "\n") { i += 2; continue; }
      if (esc >= "0" && esc <= "7") {
        // Octal: one to three digits. `"\143\165\162\154"` is `curl`.
        let j = i + 1;
        let digits = "";
        while (j < n && digits.length < 3 && src[j] >= "0" && src[j] <= "7") {
          digits += src[j];
          j++;
        }
        out += String.fromCharCode(parseInt(digits, 8));
        i = j;
        continue;
      }
      if (esc === "x") {
        const hex = src.slice(i + 2, i + 4);
        if (/^[0-9a-fA-F]{2}$/.test(hex)) {
          out += String.fromCharCode(parseInt(hex, 16));
          i += 4;
          continue;
        }
        dynamic = true;
        out += src.slice(i, Math.min(i + 4, n));
        i = Math.min(i + 4, n);
        continue;
      }
      if (esc === "u" && !bytes) {
        const hex = src.slice(i + 2, i + 6);
        if (/^[0-9a-fA-F]{4}$/.test(hex)) {
          out += String.fromCharCode(parseInt(hex, 16));
          i += 6;
          continue;
        }
        dynamic = true;
        out += src.slice(i, Math.min(i + 6, n));
        i = Math.min(i + 6, n);
        continue;
      }
      if (esc === "U" && !bytes) {
        const hex = src.slice(i + 2, i + 10);
        const point = /^[0-9a-fA-F]{8}$/.test(hex) ? parseInt(hex, 16) : -1;
        if (point >= 0 && point <= 0x10ffff) {
          out += String.fromCodePoint(point);
          i += 10;
          continue;
        }
        dynamic = true;
        out += src.slice(i, Math.min(i + 10, n));
        i = Math.min(i + 10, n);
        continue;
      }
      if (esc === "N" && !bytes) {
        // JavaScript has no Unicode-name database. Preserve the source and
        // mark the literal unresolved rather than changing Python's value.
        const close = src.indexOf("}", i + 3);
        dynamic = true;
        const end = close >= 0 ? close + 1 : Math.min(i + 2, n);
        out += src.slice(i, end);
        i = end;
        continue;
      }
      // Python currently preserves an unknown escape's backslash (with a
      // warning). Dropping it can turn an executable string into harmless
      // text, so retain both characters exactly.
      out += "\\" + esc;
      i += 2;
      continue;
    }
    if (raw && src[i] === "\\" && i + 1 < n) {
      // A raw string keeps its backslash, but the backslash still escapes the
      // quote for the purpose of finding the terminator.
      out += src[i] + src[i + 1];
      i += 2;
      continue;
    }
    if (formatted && src[i] === "{") {
      if (src[i + 1] === "{") {
        // `{{` is a literal brace in an f-string.
        out += "{";
        i += 2;
        continue;
      }
      dynamic = true;
    }
    if (formatted && src[i] === "}" && src[i + 1] === "}") {
      // As is `}}`.
      out += "}";
      i += 2;
      continue;
    }
    if (src.slice(i, i + delim.length) === delim) {
      return { value: out, end: i + delim.length, dynamic };
    }
    if (!triple && src[i] === "\n") {
      // Unterminated single-quoted string: stop at the newline, as Python does.
      return { value: out, end: i, dynamic };
    }
    out += src[i];
    i++;
  }
  return { value: out, end: n, dynamic };
}

/**
 * Lex enough Python to find call sites and their literal arguments.
 *
 * Comments and string bodies are consumed here rather than matched by regex
 * over raw source, so a commented-out `# os.system("rm -rf /")` is correctly
 * ignored and a `#` inside a string does not truncate the line.
 *
 * @param {string} src
 * @returns {Array<{t: string, v: string, dynamic?: boolean}>} tokens tagged
 *   "name", "str" or "op"; a "str" token from an f-string with a placeholder
 *   carries `dynamic: true`
 */
function lexPython(src) {
  const tokens = [];
  let i = 0;
  const n = src.length;

  while (i < n) {
    const c = src[i];

    if (c === "#") {
      while (i < n && src[i] !== "\n") i++;
      continue;
    }
    if (c === "\\" && src[i + 1] === "\n") {
      i += 2;
      continue;
    }
    if (c === " " || c === "\t" || c === "\r" || c === "\n") {
      i++;
      continue;
    }
    const firstPoint = String.fromCodePoint(src.codePointAt(i));
    if (/^[_\p{ID_Start}]$/u.test(firstPoint)) {
      let j = i + firstPoint.length;
      while (j < n) {
        const point = String.fromCodePoint(src.codePointAt(j));
        if (!/^[_\p{ID_Continue}]$/u.test(point)) break;
        j += point.length;
      }
      const sourceWord = src.slice(i, j);
      // Python compares identifiers after NFKC normalization. Recording the
      // normalized spelling makes `import os as 𝐨` and `o.system(...)`
      // resolve to the same binding where Python does.
      const word = sourceWord.normalize("NFKC");
      // A string prefix binds to the quote immediately following it.
      if ((src[j] === '"' || src[j] === "'") && STRING_PREFIXES.has(sourceWord.toLowerCase())) {
        const lower = sourceWord.toLowerCase();
        const lit = readString(
          src,
          j,
          lower.indexOf("r") >= 0,
          lower.indexOf("f") >= 0,
          lower.indexOf("b") >= 0,
        );
        tokens.push({ t: "str", v: lit.value, dynamic: lit.dynamic });
        i = lit.end;
        continue;
      }
      tokens.push({ t: "name", v: word });
      i = j;
      continue;
    }
    if (c === '"' || c === "'") {
      const lit = readString(src, i, false, false, false);
      tokens.push({ t: "str", v: lit.value, dynamic: lit.dynamic });
      i = lit.end;
      continue;
    }
    tokens.push({ t: "op", v: c });
    i++;
  }
  return tokens;
}

function tokenName(tok) {
  return tok !== undefined && tok.t === "name" ? tok.v : null;
}

function isOp(tok, value) {
  return tok !== undefined && tok.t === "op" && tok.v === value;
}

/**
 * Record the import and assignment forms that let an exec call appear under
 * another name, into the persistent kernel bindings.
 *
 * @param {Array<{t: string, v: string}>} tokens
 * @param {KernelBindings} bindings
 */
function collectBindings(tokens, bindings) {
  const { moduleAlias, bareExec, ipythonAlias } = bindings;

  for (let i = 0; i < tokens.length; i++) {
    const word = tokenName(tokens[i]);
    if (word === null) continue;

    if (word === "import" && tokenName(tokens[i - 1]) !== "from") {
      // `import os`, `import os as o`, `import os, subprocess`
      let j = i + 1;
      while (j < tokens.length) {
        const mod = tokenName(tokens[j]);
        if (mod === null) break;
        let alias = mod;
        let k = j + 1;
        if (tokenName(tokens[k]) === "as" && tokenName(tokens[k + 1]) !== null) {
          alias = tokenName(tokens[k + 1]);
          k += 2;
        }
        if (EXEC_MODULES.has(mod)) moduleAlias.set(alias, mod);
        if (isOp(tokens[k], ",")) {
          j = k + 1;
          continue;
        }
        break;
      }
      continue;
    }

    if (word === "from") {
      const module = tokenName(tokens[i + 1]);
      if (module === null || !EXEC_MODULES.has(module)) continue;
      if (tokenName(tokens[i + 2]) !== "import") continue;
      const allowed = execNamesFor(module);
      let j = i + 3;
      while (j < tokens.length) {
        if (isOp(tokens[j], "(") || isOp(tokens[j], ")")) {
          j++;
          continue;
        }
        const imported = tokenName(tokens[j]);
        if (imported === null) break;
        let local = imported;
        let k = j + 1;
        if (tokenName(tokens[k]) === "as" && tokenName(tokens[k + 1]) !== null) {
          local = tokenName(tokens[k + 1]);
          k += 2;
        }
        if (allowed.has(imported)) bareExec.set(local, { module, member: imported });
        if (isOp(tokens[k], ",")) {
          j = k + 1;
          continue;
        }
        break;
      }
      continue;
    }

    // `x = os`, `sp = subprocess`, `ip = get_ipython()`, `ip = IPython.get_ipython()`
    if (isOp(tokens[i + 1], "=") && !isOp(tokens[i + 2], "=")) {
      const rhs = tokenName(tokens[i + 2]);
      if (rhs !== null && EXEC_MODULES.has(rhs) && !isOp(tokens[i + 3], ".") && !isOp(tokens[i + 3], "(")) {
        moduleAlias.set(word, rhs);
        continue;
      }
      const aliased = rhs !== null ? moduleAlias.get(rhs) : undefined;
      if (aliased !== undefined && !isOp(tokens[i + 3], ".") && !isOp(tokens[i + 3], "(")) {
        moduleAlias.set(word, aliased);
        continue;
      }
      let j = i + 2;
      if (rhs === "IPython" && isOp(tokens[j + 1], ".")) j += 2;
      if (tokenName(tokens[j]) === "get_ipython" && isOp(tokens[j + 1], "(") && isOp(tokens[j + 2], ")")) {
        ipythonAlias.add(word);
      }
    }
  }
}

/**
 * POSIX-quote one argv element so the engine sees the argument the program
 * would receive, not a re-parse of it. `["printf", "%s", "a | b"]` is one
 * argument containing a pipe character; rendered bare it would read as a
 * pipeline, and the engine would block a command that starts no shell at all.
 *
 * @param {string} word
 */
function posixQuote(word) {
  if (word.length > 0 && /^[A-Za-z0-9_\/:=.,+@%^-]+$/.test(word)) return word;
  return "'" + word.replace(/'/g, "'\\''") + "'";
}

/**
 * Read one positional argument starting at token `i`.
 *
 * @returns {{ kind: "str", value: string, end: number }
 *         | { kind: "list", values: string[], end: number }
 *         | { kind: "bool", value: boolean, end: number }
 *         | { kind: "dynamic", end: number }
 *         | null} null at the end of the argument list
 */
function readArgument(tokens, i) {
  if (tokens[i] === undefined || isOp(tokens[i], ")")) return null;

  const boolName = tokenName(tokens[i]);
  if ((boolName === "True" || boolName === "False")
    && (isOp(tokens[i + 1], ",") || isOp(tokens[i + 1], ")"))) {
    return { kind: "bool", value: boolName === "True", end: i + 1 };
  }

  // A list or tuple of literals.
  if (isOp(tokens[i], "[") || isOp(tokens[i], "(")) {
    const close = isOp(tokens[i], "[") ? "]" : ")";
    const values = [];
    let dynamic = false;
    let j = i + 1;
    let depth = 0;
    while (j < tokens.length) {
      const tok = tokens[j];
      if (tok.t === "op" && (tok.v === "[" || tok.v === "(")) depth++;
      if (tok.t === "op" && (tok.v === "]" || tok.v === ")")) {
        if (depth === 0 && tok.v === close) break;
        depth--;
      }
      if (depth === 0) {
        if (tok.t === "str") {
          if (tok.dynamic) dynamic = true;
          else values.push(tok.v);
        } else if (!(tok.t === "op" && tok.v === ",")) {
          dynamic = true;
        }
      } else {
        dynamic = true;
      }
      j++;
    }
    const end = skipToArgumentEnd(tokens, j + 1);
    return dynamic ? { kind: "dynamic", end } : { kind: "list", values, end };
  }

  // Adjacent string literals concatenate in Python: `"cu" "rl example.test"`.
  const parts = [];
  let dynamic = false;
  let j = i;
  while (tokens[j] !== undefined && tokens[j].t === "str") {
    if (tokens[j].dynamic) dynamic = true;
    parts.push(tokens[j].v);
    j++;
  }
  if (parts.length === 0) {
    return { kind: "dynamic", end: skipToArgumentEnd(tokens, i) };
  }
  // Anything other than the end of this argument means the value is computed
  // (`"cmd " + user_input`), so the literal half must not stand in for it.
  if (!(isOp(tokens[j], ",") || isOp(tokens[j], ")"))) {
    return { kind: "dynamic", end: skipToArgumentEnd(tokens, j) };
  }
  return dynamic ? { kind: "dynamic", end: j } : { kind: "str", value: parts.join(""), end: j };
}

/** Advance to the `,` or `)` that ends the current argument, honouring nesting. */
function skipToArgumentEnd(tokens, i) {
  let depth = 0;
  let j = i;
  while (j < tokens.length) {
    const tok = tokens[j];
    if (tok.t === "op") {
      if (tok.v === "(" || tok.v === "[" || tok.v === "{") depth++;
      else if (tok.v === ")" || tok.v === "]" || tok.v === "}") {
        if (depth === 0) return j;
        depth--;
      } else if (tok.v === "," && depth === 0) return j;
    }
    j++;
  }
  return j;
}

/** Read every positional and keyword argument of a call. */
function readArguments(tokens, openParen) {
  const positional = [];
  const keywords = new Map();
  let unknownPositional = false;
  let unknownKeywords = false;
  let i = openParen + 1;
  while (true) {
    if (tokens[i] === undefined || isOp(tokens[i], ")")) break;
    if (isOp(tokens[i], "*")) {
      const isDouble = isOp(tokens[i + 1], "*");
      const arg = readArgument(tokens, i + (isDouble ? 2 : 1));
      if (arg === null) break;
      if (isDouble) unknownKeywords = true;
      else unknownPositional = true;
      i = arg.end;
      if (isOp(tokens[i], ",")) {
        i++;
        continue;
      }
      break;
    }
    const keyword = tokenName(tokens[i]);
    const isKeyword = keyword !== null && isOp(tokens[i + 1], "=");
    const arg = readArgument(tokens, isKeyword ? i + 2 : i);
    if (arg === null) break;
    if (isKeyword) keywords.set(keyword, arg);
    else positional.push(arg);
    i = arg.end;
    if (isOp(tokens[i], ",")) {
      i++;
      continue;
    }
    break;
  }
  return { positional, keywords, unknownPositional, unknownKeywords };
}

/**
 * Render a call's arguments as the command the engine should see, according
 * to that API's real argument shape.
 *
 * @param {"command" | "argv" | "command_or_argv"} shape
 * @returns {string | null} null when any part is computed at runtime
 */
function renderCall(shape, call) {
  if (call.unknownPositional || call.unknownKeywords) return null;
  const args = call.positional;
  if (args.length === 0) return null;
  if (shape === "command" || shape === "command_or_argv") {
    const first = args[0];
    if (first.kind === "str") return first.value.trim().length > 0 ? first.value : null;
    if (first.kind === "list" && shape === "command_or_argv") {
      return first.values.length > 0 ? first.values.map(posixQuote).join(" ") : null;
    }
    return null;
  }
  // argv: `execl(path, arg0, arg1, ...)` or `execv(path, [argv])`.
  const words = [];
  for (const arg of args) {
    if (arg.kind === "str") words.push(arg.value);
    else if (arg.kind === "list") words.push(...arg.values);
    else return null;
  }
  return words.length > 0 ? words.map(posixQuote).join(" ") : null;
}

function renderProgramAndArgs(program, values) {
  if (program === null || program.length === 0) return null;
  return [program, ...values].map(posixQuote).join(" ");
}

/** Render the real argv rules for Python's os.exec*, spawn*, and posix_spawn*. */
function renderOsArgvCall(member, call) {
  if (call.unknownPositional || call.unknownKeywords) return null;
  const args = call.positional;
  const isSpawn = member.startsWith("spawn") && !member.startsWith("posix_spawn");
  const isVector = member.includes("v") || member.startsWith("posix_spawn");
  const programIndex = isSpawn ? 1 : 0;
  const argvIndex = programIndex + 1;
  const programArg = args[programIndex];
  if (programArg === undefined || programArg.kind !== "str") return null;

  if (isVector) {
    const argv = args[argvIndex];
    if (argv === undefined || argv.kind !== "list" || argv.values.length === 0) return null;
    // Python's argv[0] is the target process name, not a CLI argument. Keeping
    // it would turn `/bin/sh`, `sh`, `-c`, `payload` into `/bin/sh sh -c ...`
    // and hide what the shell actually executes.
    return renderProgramAndArgs(programArg.value, argv.values.slice(1));
  }

  // l-forms spread argv after the program. `*e` variants end with an env map,
  // which readArgument deliberately marks dynamic and which is not an argv
  // element. spawn* also begins with the wait mode, omitted above.
  let end = args.length;
  if (member.endsWith("e")) end--;
  const argv0 = args[argvIndex];
  if (argv0 === undefined || argv0.kind !== "str") return null;
  const values = [];
  for (const arg of args.slice(argvIndex + 1, end)) {
    if (arg.kind !== "str") return null;
    values.push(arg.value);
  }
  return renderProgramAndArgs(programArg.value, values);
}

/** Render subprocess APIs, including the semantic switch made by shell=True. */
function renderSubprocessCall(member, call) {
  if (call.unknownPositional || call.unknownKeywords) return null;
  if (call.positional.length > 1) return null;
  for (const keyword of ["executable", "env", "preexec_fn"]) {
    if (call.keywords.has(keyword)) return null;
  }
  const first = call.positional[0];
  if (first === undefined) return null;
  const alwaysShell = member === "getoutput" || member === "getstatusoutput";
  const shellArg = call.keywords.get("shell");
  let usesShell = alwaysShell;
  if (shellArg !== undefined) {
    if (shellArg.kind !== "bool") return null;
    usesShell = shellArg.value;
  }

  if (usesShell) {
    if (first.kind === "str") return first.value.trim().length > 0 ? first.value : null;
    // On POSIX, subprocess passes a list with shell=True as
    // `/bin/sh -c args[0] args[1]...`; only args[0] is the command string.
    if (first.kind === "list" && first.values.length > 0) return first.values[0];
    return null;
  }
  if (first.kind === "list") {
    return first.values.length > 0 ? first.values.map(posixQuote).join(" ") : null;
  }
  if (first.kind === "str") {
    // With shell=False a string is one executable pathname; Python does not
    // split its spaces into arguments.
    return first.value.length > 0 ? posixQuote(first.value) : null;
  }
  return null;
}

function renderExecutionCall(module, member, call) {
  if (module === "os") {
    if (OS_ARGV.has(member)) return renderOsArgvCall(member, call);
    return renderCall("command", call);
  }
  if (module === "subprocess") return renderSubprocessCall(member, call);
  return renderCall("command_or_argv", call);
}

/**
 * Interpret a `%%script` line: options parsed the way IPython's argparse does,
 * then the first remaining word is the interpreter. `%%script bash --out x`
 * must not mistake `x` for the program.
 *
 * @returns {boolean} whether the interpreter is a shell
 */
function scriptMagicIsShell(rest) {
  const words = rest.split(/\s+/).filter((w) => w.length > 0);
  let i = 0;
  while (i < words.length) {
    const word = words[i];
    if (SCRIPT_FLAG_OPTIONS.has(word)) { i++; continue; }
    if (SCRIPT_VALUE_OPTIONS.has(word)) { i += 2; continue; }
    if (word.startsWith("--") && word.indexOf("=") > 0) { i++; continue; }
    break;
  }
  let interpreter = i < words.length ? words[i] : "";
  let base = interpreter.split("/").pop() || "";
  if (base === "env") {
    i++;
    while (i < words.length) {
      const word = words[i];
      if (word === "-i" || word === "--ignore-environment" || word === "-0"
        || word === "--null" || word === "--debug") {
        i++;
        continue;
      }
      if (word === "-u" || word === "--unset" || word === "-C" || word === "--chdir") {
        i += 2;
        continue;
      }
      if (word.startsWith("--unset=") || word.startsWith("--chdir=")
        || /^[A-Za-z_][A-Za-z0-9_]*=/.test(word)) {
        i++;
        continue;
      }
      // -S/--split-string needs another shell-like parse. Returning false is
      // safe: the caller marks an unclassified script interpreter unresolved.
      if (word === "-S" || word === "--split-string" || word.startsWith("--split-string=")) {
        return false;
      }
      interpreter = word;
      base = interpreter.split("/").pop() || "";
      break;
    }
  }
  return SHELL_INTERPRETERS.has(base);
}

/** Join continuations only for IPython shell escapes, never inside comments. */
function joinShellEscapeContinuations(source) {
  const input = source.split(/\r?\n/);
  const output = [];
  for (let i = 0; i < input.length; i++) {
    let line = input[i];
    if (BANG_LINE.test(line) || SYSTEM_MAGIC.test(line)) {
      while (/[ \t]*\\$/.test(line) && i + 1 < input.length) {
        line = line.replace(/[ \t]*\\$/, " ") + input[++i].trimStart();
      }
    }
    output.push(line);
  }
  return output;
}

/**
 * Extract every shell execution vector an IPython cell carries.
 *
 * @param {string} source
 * @param {KernelBindings} [bindings] persistent bindings; a fresh set if omitted
 * @returns {IpythonVectors}
 */
export function extractIpythonVectors(source, bindings) {
  const commands = [];
  const unresolved = [];
  if (typeof source !== "string" || source.length === 0) {
    return { commands, unresolved };
  }
  const state = bindings !== undefined ? bindings : createBindings();

  // Shell escapes use IPython's continuation transform. Python continuations
  // are instead handled by the lexer, which knows that a backslash inside a
  // comment does not join the following executable line.
  const lines = joinShellEscapeContinuations(source);

  // A shell cell magic makes the whole remaining cell one shell script, so it
  // is decided first and the Python lexer never runs.
  const magic = lines.length > 0 ? SHELL_CELL_MAGIC.exec(lines[0]) : null;
  if (magic !== null) {
    const kind = magic[1];
    const rest = (magic[2] || "").trim();
    const isShell = kind === "script" ? scriptMagicIsShell(rest) : true;
    if (isShell) {
      const body = lines.slice(1).join("\n").trim();
      if (body.length > 0) commands.push(body);
      return { commands, unresolved };
    }
    // Every other %%script interpreter still launches arbitrary code. The
    // event does not carry a runtime command that the shell engine can prove.
    unresolved.push(`%%script ${rest || "unknown interpreter"}`);
    return { commands, unresolved };
  }

  const pythonLines = [];
  for (const line of lines) {
    const bang = BANG_LINE.exec(line);
    const sys = bang === null ? SYSTEM_MAGIC.exec(line) : null;
    if (bang !== null || sys !== null) {
      const cmd = (bang !== null ? bang[1] : sys[1]).trim();
      if (cmd.length > 0) {
        // `{expr}` and `$name` are expanded by IPython before the shell runs,
        // so the text here is not the command that will run.
        if (IPYTHON_EXPANSION.test(cmd)) unresolved.push(bang !== null ? "!" + cmd : "%system " + cmd);
        else commands.push(cmd);
      }
      pythonLines.push("");
      continue;
    }
    if (OTHER_MAGIC.test(line)) {
      // Built-in and user-defined magics can execute their argument or cell.
      // Erasing an unknown magic would turn execution into an apparent no-op.
      unresolved.push(line.trim().split(/\s+/, 1)[0]);
      pythonLines.push("");
      continue;
    }
    pythonLines.push(line);
  }

  const tokens = lexPython(pythonLines.join("\n"));
  collectBindings(tokens, state);

  for (let i = 0; i < tokens.length; i++) {
    const word = tokenName(tokens[i]);
    if (word === null) continue;

    let label = null;
    let callModule = null;
    let callMember = null;
    let openParen = -1;

    // get_ipython().system(...) and friends, directly or through an alias.
    let ipythonMemberAt = -1;
    // A bare `get_ipython()`; the `IPython.get_ipython()` spelling is handled
    // from its receiver below, so a dotted one must not be counted twice.
    if (word === "get_ipython" && !isOp(tokens[i - 1], ".") && isOp(tokens[i + 1], "(") && isOp(tokens[i + 2], ")") && isOp(tokens[i + 3], ".")) {
      ipythonMemberAt = i + 4;
    } else if (word === "IPython" && isOp(tokens[i + 1], ".") && tokenName(tokens[i + 2]) === "get_ipython"
      && isOp(tokens[i + 3], "(") && isOp(tokens[i + 4], ")") && isOp(tokens[i + 5], ".")) {
      ipythonMemberAt = i + 6;
    } else if (state.ipythonAlias.has(word) && isOp(tokens[i + 1], ".")) {
      ipythonMemberAt = i + 2;
    }
    if (ipythonMemberAt >= 0 && isOp(tokens[ipythonMemberAt + 1], "(")) {
      const member = tokenName(tokens[ipythonMemberAt]);
      const args = readArguments(tokens, ipythonMemberAt + 1);
      if (member === "system" || member === "getoutput") {
        label = "get_ipython()." + member;
        const rendered = renderCall("command", args);
        if (rendered !== null && !IPYTHON_EXPANSION.test(rendered)) commands.push(rendered);
        else unresolved.push(label);
        continue;
      }
      if (member === "run_line_magic") {
        label = "get_ipython().run_line_magic";
        const name = args.positional[0] !== undefined && args.positional[0].kind === "str"
          ? args.positional[0].value : null;
        if (name === "system" || name === "sx") {
          const rendered = args.positional[1] !== undefined && args.positional[1].kind === "str"
            ? args.positional[1].value : null;
          if (rendered !== null && rendered.trim().length > 0 && !IPYTHON_EXPANSION.test(rendered)) commands.push(rendered);
          else unresolved.push(label);
        } else {
          unresolved.push(name === null ? label : `${label}(${name})`);
        }
        continue;
      }
      if (member === "run_cell_magic") {
        label = "get_ipython().run_cell_magic";
        const name = args.positional[0] !== undefined && args.positional[0].kind === "str"
          ? args.positional[0].value : null;
        const line = args.positional[1] !== undefined && args.positional[1].kind === "str"
          ? args.positional[1].value : null;
        const cell = args.positional[2] !== undefined && args.positional[2].kind === "str"
          ? args.positional[2].value : null;
        const isShell = name === "bash" || name === "sh" || (name === "script" && line !== null && scriptMagicIsShell(line));
        if (isShell) {
          if (cell !== null && cell.trim().length > 0) commands.push(cell.trim());
          else unresolved.push(label);
        } else {
          unresolved.push(name === null ? label : `${label}(${name})`);
        }
        continue;
      }
      continue;
    }

    // `<receiver>.<member>(`: the receiver is os/subprocess/pty or an alias,
    // or the member is one that only an exec API has.
    if (isOp(tokens[i + 1], ".") && tokenName(tokens[i + 2]) !== null && isOp(tokens[i + 3], "(")) {
      const member = tokenName(tokens[i + 2]);
      const aliased = state.moduleAlias.get(word);
      const canonical = aliased !== undefined ? aliased : EXEC_MODULES.has(word) ? word : null;
      const known = canonical !== null && execNamesFor(canonical).has(member);
      if (known || UNAMBIGUOUS_EXEC_MEMBERS.has(member)) {
        label = word + "." + member;
        openParen = i + 3;
        callModule = canonical !== null ? canonical : OS_ARGV.has(member) ? "os" : "subprocess";
        callMember = member;
      }
    }

    // A bare name bound by `from subprocess import run`. The canonical member
    // is retained so an alias of os.execl still gets execl's argv semantics.
    const bare = state.bareExec.get(word);
    if (label === null && bare !== undefined && isOp(tokens[i + 1], "(")) {
      label = word;
      openParen = i + 1;
      callModule = bare.module;
      callMember = bare.member;
    }

    if (label === null) continue;

    const rendered = renderExecutionCall(
      callModule,
      callMember,
      readArguments(tokens, openParen),
    );
    if (rendered !== null && rendered.trim().length > 0) commands.push(rendered);
    else unresolved.push(label);
  }

  return { commands, unresolved };
}

/** Quote one argv element for the POSIX parser used by `tirith check`. */
function quotePosixArgument(value) {
  return "'" + value.replaceAll("'", "'\\''") + "'";
}

/**
 * Render an application plus an argv array without turning argv data into
 * shell syntax. OMP passes both `hub start` and debug launch arguments directly
 * to their subprocess APIs, so quoting every element preserves that boundary.
 */
function renderArgv(application, args, label) {
  if (typeof application !== "string" || application.length === 0) {
    return { script: "", unresolved: [`${label} has no literal application`] };
  }
  if (args !== undefined && !Array.isArray(args)) {
    return { script: "", unresolved: [`${label} args are not an array`] };
  }
  const argv = args === undefined ? [] : args;
  if (argv.length > MAX_EXEC_ARGUMENTS) {
    return { script: "", unresolved: [`${label} has more than ${MAX_EXEC_ARGUMENTS} arguments`] };
  }
  if (argv.some((arg) => typeof arg !== "string")) {
    return { script: "", unresolved: [`${label} has a non-string argument`] };
  }
  const script = [application, ...argv].map(quotePosixArgument).join(" ");
  if (Buffer.byteLength(script, "utf8") > MAX_CHECK_SCRIPT_BYTES) {
    return { script: "", unresolved: [`${label} argv is larger than the ${MAX_CHECK_SCRIPT_BYTES}-byte inspection limit`] };
  }
  return { script, unresolved: [] };
}

/** Build the check for OMP's persistent multi-language evaluator. */
function buildOmpEvalCheck(bag, bindings) {
  const language = bag.language;
  const code = bag.code;
  if (typeof language !== "string" || typeof code !== "string" || code.trim().length === 0) {
    return { script: "", unresolved: ["eval payload is malformed"] };
  }

  // Python literals are still useful evidence for the engine, but no supported
  // eval language can be proved process-free from source text. For example,
  // JavaScript can import child_process, Ruby can call Kernel.system, and a
  // Python helper imported earlier can spawn without a visible call here.
  const vectors = language === "py" ? extractIpythonVectors(code, bindings) : { commands: [], unresolved: [] };
  const script = vectors.commands.join("\n");
  const unresolved = [
    ...vectors.unresolved,
    `eval ${language} code can execute processes outside the shell guard`,
  ];
  if (Buffer.byteLength(script, "utf8") > MAX_CHECK_SCRIPT_BYTES) {
    return {
      script: "",
      unresolved: [...unresolved, `eval vectors are larger than the ${MAX_CHECK_SCRIPT_BYTES}-byte inspection limit`],
    };
  }
  return { script, unresolved };
}

/** Build the check for OMP's long-running process supervisor. */
function buildOmpHubCheck(bag) {
  const op = bag.op;
  if (typeof op !== "string") return { script: "", unresolved: ["hub operation is malformed"] };
  if (op === "start") {
    const built = renderArgv(bag.application, bag.args, "hub start");
    if (bag.env !== undefined) {
      if (typeof bag.env !== "object" || bag.env === null || Array.isArray(bag.env)) {
        built.unresolved.push("hub start env is malformed");
      } else if (Object.keys(bag.env).length > 0) {
        // Environment variables such as NODE_OPTIONS, RUBYOPT, BASH_ENV, and
        // dynamic-loader variables can execute code before the visible argv.
        built.unresolved.push("hub start environment can change what the application executes");
      }
    }
    return built;
  }
  if (op === "restart") {
    return { script: "", unresolved: ["hub restart omits the persisted application and argv"] };
  }
  const processName = typeof bag.name === "string" ? bag.name.trim() : "";
  const peerName = typeof bag.to === "string" ? bag.to.trim() : "";
  if (op === "send" && processName.length > 0 && peerName.length === 0) {
    const script = typeof bag.text === "string" ? bag.text : "";
    if (Buffer.byteLength(script, "utf8") > MAX_CHECK_SCRIPT_BYTES) {
      return { script: "", unresolved: [`hub process input is larger than the ${MAX_CHECK_SCRIPT_BYTES}-byte inspection limit`] };
    }
    return {
      script,
      unresolved: ["hub process input targets an unknown persistent interpreter or terminal"],
    };
  }
  // `stop` terminates a process; the remaining hub operations are messaging,
  // job control, waits, or inspection.
  if (["send", "wait", "inbox", "list", "jobs", "cancel", "ps", "logs", "stop", "describe"].includes(op)) {
    return null;
  }
  return { script: "", unresolved: [`unknown hub operation ${op}`] };
}

/** Build the check for OMP's Debug Adapter Protocol controller. */
function buildOmpDebugCheck(bag) {
  const action = bag.action;
  if (typeof action !== "string") return { script: "", unresolved: ["debug action is malformed"] };
  if (OMP_DEBUG_READONLY_ACTIONS.has(action) || action === "terminate") return null;
  if (action === "launch") {
    const built = renderArgv(bag.program, bag.args, "debug launch");
    // OMP starts a configured debugger adapter as well as the visible target.
    // The adapter command is absent from the event and workspace dap.json can
    // redefine it, so the event is not a complete process description.
    built.unresolved.push("debug launch omits the configured debugger-adapter command");
    return built;
  }
  if (action === "evaluate") {
    const script = typeof bag.expression === "string" ? bag.expression : "";
    return {
      script: Buffer.byteLength(script, "utf8") <= MAX_CHECK_SCRIPT_BYTES ? script : "",
      unresolved: ["debug evaluate runs in an unknown target language or REPL"],
    };
  }
  // Attach, resume/step/pause, conditional breakpoints, writes, and custom DAP
  // requests can execute or mutate a live process without exposing a command
  // that Tirith can inspect.
  return { script: "", unresolved: [`debug ${action} can control execution without a visible command`] };
}

/**
 * Build the script handed to `tirith check` for one tool call.
 *
 * Recovered vectors are joined with newlines so the engine sees each as its
 * own segment and a single check covers the whole cell. A script past the
 * engine's stdin limit is reported as unresolved rather than trimmed: nothing
 * is ever partially inspected.
 *
 * @param {string} toolName
 * @param {Record<string, unknown> | undefined} input
 * @param {KernelBindings} [bindings]
 * @returns {{ script: string, unresolved: string[] } | null} null when the call
 *   carries nothing executable
 */
export function buildCheckScript(toolName, input, bindings) {
  const bag = input === undefined || input === null ? {} : input;
  if (typeof bag !== "object" || Array.isArray(bag)) {
    if (SHELL_TOOLS.has(toolName) || NOTEBOOK_TOOLS.has(toolName)
      || toolName === OMP_EVAL_TOOL || toolName === OMP_PROCESS_TOOL || toolName === OMP_DEBUG_TOOL) {
      return { script: "", unresolved: [`${toolName || "execution"} payload is not an object`] };
    }
    return null;
  }
  if (SHELL_TOOLS.has(toolName)) {
    const command = bag.command;
    if (typeof command !== "string" || command.trim().length === 0) {
      return { script: "", unresolved: [`${toolName} command is missing or empty`] };
    }
    if (Buffer.byteLength(command, "utf8") > MAX_CHECK_SCRIPT_BYTES) {
      return { script: "", unresolved: [`command larger than the ${MAX_CHECK_SCRIPT_BYTES}-byte inspection limit`] };
    }
    return { script: command, unresolved: [] };
  }
  if (NOTEBOOK_TOOLS.has(toolName)) {
    let code = bag.code;
    if (code === undefined) code = bag.cell;
    if (code === undefined) code = bag.source;
    if (typeof code !== "string" || code.trim().length === 0) {
      return { script: "", unresolved: [`${toolName} code is missing or empty`] };
    }
    const vectors = extractIpythonVectors(code, bindings);
    if (vectors.commands.length === 0 && vectors.unresolved.length === 0) return null;
    const script = vectors.commands.join("\n");
    if (Buffer.byteLength(script, "utf8") > MAX_CHECK_SCRIPT_BYTES) {
      return {
        script: "",
        unresolved: [...vectors.unresolved, `cell vectors larger than the ${MAX_CHECK_SCRIPT_BYTES}-byte inspection limit`],
      };
    }
    return { script, unresolved: vectors.unresolved };
  }
  if (toolName === OMP_EVAL_TOOL) return buildOmpEvalCheck(bag, bindings);
  if (toolName === OMP_PROCESS_TOOL) return buildOmpHubCheck(bag);
  if (toolName === OMP_DEBUG_TOOL) return buildOmpDebugCheck(bag);
  return null;
}

// ---------------------------------------------------------------------------
// Host integration.
// ---------------------------------------------------------------------------

/** Bindings for the lifetime of this extension process: one kernel, one set. */
const kernelBindings = createBindings();

function hookEvent(event, detail, deadline = Infinity) {
  if (performance.now() + 250 >= deadline) return; // Never extend an exhausted check budget.
  try {
    const args = [
      "hook-event", "--integration", TIRITH_INTEGRATION,
      "--hook-type", "tool_call", "--event", event,
    ];
    if (detail) args.push("--detail", detail);
    // A finite timeout/kill request, not a hard kernel reaping guarantee.
    execFileSync(TIRITH_BIN, args, { timeout: 250, killSignal: "SIGKILL", stdio: "ignore" });
  } catch {
    /* telemetry is best effort */
  }
}

function describeFindings(stdout, fallback) {
  if (!stdout || stdout.trim().length === 0) return fallback;
  try {
    const verdict = JSON.parse(stdout);
    const findings = verdict.findings || [];
    if (findings.length === 0) return fallback;
    const parts = findings.map((f) => {
      const title = f.title || f.rule_id || "unknown";
      const severity = f.severity || "";
      return severity ? `[${severity}] ${title}` : title;
    });
    return "Tirith: " + parts.join("; ");
  } catch {
    return stdout.trim().slice(0, 500);
  }
}

function failOpen() {
  return process.env.TIRITH_FAIL_OPEN === "1";
}

/** Validated `TIRITH_HOOK_WARN_ACTION`: "allow" or "deny". */
function warnAction() {
  const value = (process.env.TIRITH_HOOK_WARN_ACTION || "allow").toLowerCase();
  if (value === "allow" || value === "deny") return value;
  process.stderr.write(
    `tirith: warning: unrecognized TIRITH_HOOK_WARN_ACTION='${value}', defaulting to 'allow'\n`,
  );
  return "allow";
}

/**
 * Validated `TIRITH_HOOK_UNRESOLVED_ACTION`: "deny" (default) or "warn".
 *
 * A vector this could not read is not a warning the engine issued; it is a
 * command the engine never saw. Refusing it is the only fail-closed answer,
 * so that is the default, and `TIRITH_HOOK_WARN_ACTION=deny` implies it too.
 */
function unresolvedAction() {
  if (warnAction() === "deny") return "deny";
  const value = (process.env.TIRITH_HOOK_UNRESOLVED_ACTION || "deny").toLowerCase();
  if (value === "deny" || value === "warn") return value;
  process.stderr.write(
    `tirith: warning: unrecognized TIRITH_HOOK_UNRESOLVED_ACTION='${value}', defaulting to 'deny'\n`,
  );
  return "deny";
}

export default function (pi) {
  pi.on("tool_call", async (event, _ctx) => {
    const telemetryDeadline = performance.now() + 10_000;
    const recordHookEvent = (event, detail) => hookEvent(event, detail, telemetryDeadline);
    const toolName = event && typeof event.toolName === "string" ? event.toolName : "";
    const built = buildCheckScript(toolName, event ? event.input : undefined, kernelBindings);
    if (built === null) return undefined;

    const script = built.script;
    const unresolved = built.unresolved;
    const unresolvedNote = unresolved.length > 0
      ? `tirith: ${unresolved.length} execution vector(s) in this call (${unresolved.join(", ")}) `
        + "are hidden, built at runtime, malformed, or exceed the inspection limit and could not be inspected"
      : "";

    let deferredUnresolved = null;
    if (unresolvedNote) {
      if (unresolvedAction() === "deny") {
        recordHookEvent("unresolved_vector", unresolved.join(","));
        return { block: true, reason: unresolvedNote + " — blocked; set TIRITH_HOOK_UNRESOLVED_ACTION=warn to allow uninspectable execution calls" };
      }
      // Optional telemetry must not consume the security checker's budget.
      deferredUnresolved = unresolved.join(",");
      process.stderr.write(unresolvedNote + "\n");
    }

    if (script.trim().length === 0) {
      if (deferredUnresolved !== null) recordHookEvent("unresolved_vector", deferredUnresolved);
      return undefined;
    }

    try {
      execFileSync(
        TIRITH_BIN,
        ["check", "--json", "--non-interactive", "--shell", "posix"],
        {
          input: script,
          timeout: 10000,
          encoding: "utf-8",
          env: { ...process.env, TIRITH_INTEGRATION },
        },
      );
      recordHookEvent("check_ok");
      return undefined;
    } catch (err) {
      // execFileSync throws on a non-zero exit as well as on spawn failure.
      if (err.code === "ENOENT") {
        if (failOpen()) return undefined;
        return {
          block: true,
          reason: `tirith: ${TIRITH_BIN} not found — reinstall the integration or set TIRITH_FAIL_OPEN=1`,
        };
      }
      if (err.killed) {
        recordHookEvent("timeout");
        if (failOpen()) return undefined;
        return { block: true, reason: "tirith: check timed out — blocked for safety" };
      }

      const exitCode = err.status;
      if (exitCode === null || exitCode === undefined) {
        recordHookEvent("unexpected_exit", err.message || "unknown");
        if (failOpen()) return undefined;
        return { block: true, reason: `tirith: unexpected error — ${err.message || "unknown"}` };
      }

      const stdout = err.stdout || "";

      if (exitCode !== 1 && exitCode !== 2) {
        recordHookEvent("unexpected_exit", `exit code ${exitCode}`);
        if (failOpen()) return undefined;
        return {
          block: true,
          reason: `tirith: unexpected exit code ${exitCode} — blocked for safety`,
        };
      }

      if (exitCode === 2 && warnAction() !== "deny") {
        recordHookEvent("warn_allowed");
        process.stderr.write(
          describeFindings(stdout, "Tirith: security warnings detected (non-blocking)") + "\n",
        );
        return undefined;
      }

      recordHookEvent(exitCode === 1 ? "check_block" : "warn_denied");
      return { block: true, reason: describeFindings(stdout, "Tirith security check failed") };
    } finally {
      if (deferredUnresolved !== null) recordHookEvent("unresolved_vector", deferredUnresolved);
    }
  });
}
