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
//   TIRITH_HOOK_UNRESOLVED_ACTION — "deny" (default) or "warn" for a cell that
//                                   reaches a shell in a way this cannot read
//   TIRITH_FAIL_OPEN              — "1" to allow on error (default: deny)

import { execFile, execFileSync } from "node:child_process";

const TIRITH_BIN = "__TIRITH_BIN__";
const TIRITH_INTEGRATION = "__TIRITH_INTEGRATION__";

/** Tool names that carry a shell command string in `input.command`. */
const SHELL_TOOLS = new Set(["bash", "shell", "run_terminal_command", "terminal"]);
/** Tool names whose `input.code` is an IPython cell. */
const NOTEBOOK_TOOLS = new Set(["ipython", "python", "jupyter"]);

/**
 * `tirith check` reads the command from stdin when it is given no argument and
 * stdin is not a terminal, capped at one mebibyte. The script is handed over
 * that way rather than as an argument, so its size is bounded by a stated
 * limit instead of by the platform's argument-length ceiling.
 */
const MAX_CHECK_SCRIPT_BYTES = 1024 * 1024;

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
 * @property {Set<string>} bareExec names bound by `from os import system` and friends
 * @property {Set<string>} ipythonAlias names bound by `ip = get_ipython()`
 */

/** @returns {KernelBindings} */
export function createBindings() {
  return { moduleAlias: new Map(), bareExec: new Set(), ipythonAlias: new Set() };
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
const BANG_LINE = /^\s*(?:[A-Za-z_]\w*(?:\.\w+|\[[^\]]*\])*\s*=\s*)?!{1,2}(?!=)(.*)$/;
/** `%system cmd`, `%sx cmd`, and their assignment forms. */
const SYSTEM_MAGIC = /^\s*(?:[A-Za-z_]\w*(?:\.\w+|\[[^\]]*\])*\s*=\s*)?%(?:system|sx)\s+(.*)$/;
/** Any other line magic: not Python, and not a shell vector either. */
const OTHER_MAGIC = /^\s*%{1,2}\w/;
/**
 * IPython expands `{expr}` and `$name` / `${name}` inside a shell escape before
 * running it. Either makes the command a runtime value.
 */
const IPYTHON_EXPANSION = /\{[^{}]*\}|\$\{?[A-Za-z_]/;

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
 * @returns {{ value: string, end: number, dynamic: boolean }}
 */
function readString(src, start, raw, formatted) {
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
      }
      if (esc === "u") {
        const hex = src.slice(i + 2, i + 6);
        if (/^[0-9a-fA-F]{4}$/.test(hex)) {
          out += String.fromCharCode(parseInt(hex, 16));
          i += 6;
          continue;
        }
      }
      out += esc;
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
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < n && /[A-Za-z0-9_]/.test(src[j])) j++;
      const word = src.slice(i, j);
      // A string prefix binds to the quote immediately following it.
      if ((src[j] === '"' || src[j] === "'") && STRING_PREFIXES.has(word.toLowerCase())) {
        const lower = word.toLowerCase();
        const lit = readString(src, j, lower.indexOf("r") >= 0, lower.indexOf("f") >= 0);
        tokens.push({ t: "str", v: lit.value, dynamic: lit.dynamic });
        i = lit.end;
        continue;
      }
      tokens.push({ t: "name", v: word });
      i = j;
      continue;
    }
    if (c === '"' || c === "'") {
      const lit = readString(src, i, false, false);
      tokens.push({ t: "str", v: lit.value, dynamic: false });
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
        if (allowed.has(imported)) bareExec.add(local);
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
 *         | { kind: "dynamic", end: number }
 *         | null} null at the end of the argument list
 */
function readArgument(tokens, i) {
  if (tokens[i] === undefined || isOp(tokens[i], ")")) return null;

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

/** Read every positional argument of a call whose `(` is at `openParen`. */
function readArguments(tokens, openParen) {
  const args = [];
  let i = openParen + 1;
  while (true) {
    const arg = readArgument(tokens, i);
    if (arg === null) break;
    args.push(arg);
    i = arg.end;
    if (isOp(tokens[i], ",")) {
      i++;
      // A keyword argument (`shell=True`) ends the positional list.
      if (tokenName(tokens[i]) !== null && isOp(tokens[i + 1], "=")) break;
      continue;
    }
    break;
  }
  return args;
}

/**
 * Render a call's arguments as the command the engine should see, according
 * to that API's real argument shape.
 *
 * @param {"command" | "argv" | "command_or_argv"} shape
 * @returns {string | null} null when any part is computed at runtime
 */
function renderCall(shape, args) {
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
  const interpreter = i < words.length ? words[i] : "";
  const base = interpreter.split("/").pop() || "";
  return SHELL_INTERPRETERS.has(base);
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

  // IPython joins a line ending in a backslash with the next one before any
  // transformation, so a shell escape continued onto a second line is one
  // system call. Do the same first, or the line pass sees only the first half.
  const joined = source.replace(/[ \t]*\\\r?\n[ \t]*/g, " ");
  const lines = joined.split("\n");

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
    // A non-shell `%%script python` cell still runs Python, so fall through.
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
    let shape = null;
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
        const name = args[0] !== undefined && args[0].kind === "str" ? args[0].value : null;
        if (name === "system" || name === "sx") {
          const rendered = args[1] !== undefined && args[1].kind === "str" ? args[1].value : null;
          if (rendered !== null && rendered.trim().length > 0 && !IPYTHON_EXPANSION.test(rendered)) commands.push(rendered);
          else unresolved.push(label);
        } else if (name === null) {
          unresolved.push(label);
        }
        continue;
      }
      if (member === "run_cell_magic") {
        label = "get_ipython().run_cell_magic";
        const name = args[0] !== undefined && args[0].kind === "str" ? args[0].value : null;
        const line = args[1] !== undefined && args[1].kind === "str" ? args[1].value : null;
        const cell = args[2] !== undefined && args[2].kind === "str" ? args[2].value : null;
        const isShell = name === "bash" || name === "sh" || (name === "script" && line !== null && scriptMagicIsShell(line));
        if (isShell) {
          if (cell !== null && cell.trim().length > 0) commands.push(cell.trim());
          else unresolved.push(label);
        } else if (name === null) {
          unresolved.push(label);
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
        const module = canonical !== null ? canonical : OS_ARGV.has(member) ? "os" : "subprocess";
        shape = module === "os" ? (OS_ARGV.has(member) ? "argv" : "command")
          : module === "pty" ? "command_or_argv" : "command_or_argv";
      }
    }

    // A bare name bound by `from subprocess import run`.
    if (label === null && state.bareExec.has(word) && isOp(tokens[i + 1], "(")) {
      label = word;
      openParen = i + 1;
      shape = OS_ARGV.has(word) ? "argv" : "command_or_argv";
    }

    if (label === null) continue;

    const rendered = renderCall(shape, readArguments(tokens, openParen));
    if (rendered !== null && rendered.trim().length > 0) commands.push(rendered);
    else unresolved.push(label);
  }

  return { commands, unresolved };
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
  if (SHELL_TOOLS.has(toolName)) {
    const command = bag.command;
    if (typeof command !== "string" || command.trim().length === 0) return null;
    if (Buffer.byteLength(command, "utf8") > MAX_CHECK_SCRIPT_BYTES) {
      return { script: "", unresolved: [`command larger than the ${MAX_CHECK_SCRIPT_BYTES}-byte inspection limit`] };
    }
    return { script: command, unresolved: [] };
  }
  if (NOTEBOOK_TOOLS.has(toolName)) {
    let code = bag.code;
    if (code === undefined) code = bag.cell;
    if (code === undefined) code = bag.source;
    if (typeof code !== "string" || code.trim().length === 0) return null;
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
  return null;
}

// ---------------------------------------------------------------------------
// Host integration.
// ---------------------------------------------------------------------------

/** Bindings for the lifetime of this extension process: one kernel, one set. */
const kernelBindings = createBindings();

function hookEvent(event, detail) {
  try {
    const args = [
      "hook-event", "--integration", TIRITH_INTEGRATION,
      "--hook-type", "tool_call", "--event", event,
    ];
    if (detail) args.push("--detail", detail);
    execFile(TIRITH_BIN, args, () => {});
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
    const toolName = event && typeof event.toolName === "string" ? event.toolName : "";
    const built = buildCheckScript(toolName, event ? event.input : undefined, kernelBindings);
    if (built === null) return undefined;

    const script = built.script;
    const unresolved = built.unresolved;
    const unresolvedNote = unresolved.length > 0
      ? `tirith: ${unresolved.length} execution vector(s) in this call (${unresolved.join(", ")}) `
        + "are built at runtime or exceed the inspection limit and could not be inspected"
      : "";

    if (unresolvedNote) {
      hookEvent("unresolved_vector", unresolved.join(","));
      if (unresolvedAction() === "deny") {
        return { block: true, reason: unresolvedNote + " — blocked; set TIRITH_HOOK_UNRESOLVED_ACTION=warn to allow uninspectable cells" };
      }
      process.stderr.write(unresolvedNote + "\n");
    }

    if (script.trim().length === 0) return undefined;

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
      hookEvent("check_ok");
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
        hookEvent("timeout");
        if (failOpen()) return undefined;
        return { block: true, reason: "tirith: check timed out — blocked for safety" };
      }

      const exitCode = err.status;
      if (exitCode === null || exitCode === undefined) {
        hookEvent("unexpected_exit", err.message || "unknown");
        if (failOpen()) return undefined;
        return { block: true, reason: `tirith: unexpected error — ${err.message || "unknown"}` };
      }

      const stdout = err.stdout || "";

      if (exitCode !== 1 && exitCode !== 2) {
        hookEvent("unexpected_exit", `exit code ${exitCode}`);
        if (failOpen()) return undefined;
        return {
          block: true,
          reason: `tirith: unexpected exit code ${exitCode} — blocked for safety`,
        };
      }

      if (exitCode === 2 && warnAction() !== "deny") {
        hookEvent("warn_allowed");
        process.stderr.write(
          describeFindings(stdout, "Tirith: security warnings detected (non-blocking)") + "\n",
        );
        return undefined;
      }

      hookEvent(exitCode === 1 ? "check_block" : "warn_denied");
      return { block: true, reason: describeFindings(stdout, "Tirith security check failed") };
    }
  });
}
