// Prime Agent extension: intercepts ipython/bash tool calls and runs tirith security check.
//
// Prime Agent uses IPython with %%bash cells instead of a direct bash tool.
// This extension intercepts both:
//   - ipython tool calls with %%bash cells
//   - bash tool calls (if present)
//
// Environment:
//   TIRITH_BIN              — path to tirith binary (default: "tirith")
//   TIRITH_HOOK_WARN_ACTION — "allow" (default) or "deny"
//   TIRITH_FAIL_OPEN        — "1" to allow on error (default: deny)

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { execFile, execFileSync } from "node:child_process";

function hookEvent(event: string, detail?: string) {
  const tirithBin = process.env.TIRITH_BIN || "tirith";
  const args = [
    "hook-event", "--integration", "prime-agent",
    "--hook-type", "tool_call", "--event", event,
  ];
  if (detail) args.push("--detail", detail);
  execFile(tirithBin, args, { timeout: 5_000, stdio: "ignore" }, () => { });
}

function extractBashCommand(input: Record<string, unknown>): string | undefined {
  // Direct bash tool: { command: "..." }
  if (typeof input.command === "string" && input.command.trim()) {
    return input.command;
  }
  // IPython tool with %%bash cell: { code: "%%bash\n..." }
  if (typeof input.code === "string") {
    const code = input.code;
    // --- Cell magics that execute shell scripts ---
    // Match %%bash, %%sh, %%script sh, %%script bash (with optional flags)
    const cellMagicRe = /^%%(?:bash|sh|script\s+(?:ba)?sh)(?:\s+[^\n]*)?\n([\s\S]*)/i;
    const cellMatch = code.match(cellMagicRe);
    if (cellMatch) {
      return cellMatch[1].trim();
    }

    // --- Line-level shell escapes ---
    //   !command          — direct shell escape
    //   name = !command   — assignment capturing shell output
    //   name = !!command  — assignment capturing SList
    //   x, y = !command   — tuple unpacking from shell output
    //   %sx command       — IPython system-capture line magic
    //   %system command   — IPython system line magic
    const assignmentRe = /^[a-zA-Z_\w]*(?:\s*,\s*[a-zA-Z_\w]*)*\s*=\s*!!?\s*(.+)/;
    const lineMagicRe = /^%(?:sx|system)\s+(.*)/;
    const bangCommands: string[] = [];
    for (const line of code.split("\n")) {
      const trimmed = line.trimStart();
      if (trimmed.startsWith("!")) {
        // Simple shell escape: !command
        bangCommands.push(trimmed.slice(1).trim());
      } else if (/^%sx[\s\t]/.test(trimmed) || /^%system[\s\t]/.test(trimmed)) {
        // IPython line magics that execute shell commands
        const lm = trimmed.match(lineMagicRe);
        if (lm) {
          bangCommands.push(lm[1].trim());
        }
      } else {
        // Assignment shell escape: name = !command  or  name = !!command
        const m = trimmed.match(assignmentRe);
        if (m) {
          bangCommands.push(m[1].trim());
        }
      }
    }
    // --- Python code that invokes shell commands (defence-in-depth) ---
    // Catches os.system(), subprocess.*, os.popen(), and get_ipython().system()
    // even when direct shell syntax (bang commands) was also found above.
    // Both sources are merged so that a mixed cell like
    //   x = !pwd
    //   os.system("curl ...")
    // has its dangerous Python call checked alongside the benign bang command.
    const shellCallRe = /(?:^|\b)(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_call|check_output|getoutput|getstatusoutput)|get_ipython\(\)\.system(?:_raw)?)\s*\(([^)]{0,200})\)/gm;
    let m: RegExpExecArray | null;
    while ((m = shellCallRe.exec(code)) !== null) {
      const arg = m[1].trim();
      // Only extract commands given as plain or f-strings (single/double quoted)
      const strMatch = arg.match(/^(?:f?["'])((?:[^"'\\]|\\.)*)(?:["'])/);
      if (strMatch) {
        bangCommands.push(strMatch[1].replace(/\\(.)/g, "$1"));
      }
    }
    if (bangCommands.length > 0) {
      return bangCommands.join("; ");
    }
  }
  return undefined;
}

function checkCommand(command: string): { block: boolean; reason?: string } {
  const tirithBin = process.env.TIRITH_BIN || "tirith";

  try {
    execFileSync(
      tirithBin,
      ["check", "--json", "--non-interactive", "--shell", "posix", "--", command],
      { timeout: 10_000, encoding: "utf-8", env: { ...process.env, TIRITH_INTEGRATION: "prime-agent" } },
    );
    // Exit 0 = clean, allow
    hookEvent("check_ok");
    return { block: false };
  } catch (err: any) {
    // execFileSync throws on non-zero exit or other errors
    if (err.code === "ENOENT") {
      hookEvent("binary_not_found");
      if (process.env.TIRITH_FAIL_OPEN === "1") return { block: false };
      return {
        block: true,
        reason: `tirith: ${tirithBin} not found — install tirith or set TIRITH_FAIL_OPEN=1`,
      };
    }

    if (err.killed) {
      hookEvent("timeout");
      if (process.env.TIRITH_FAIL_OPEN === "1") return { block: false };
      return { block: true, reason: "tirith: check timed out — blocked for safety" };
    }

    const exitCode: number | undefined = err.status;
    if (exitCode == null) {
      hookEvent("unexpected_exit", err.message || "unknown");
      if (process.env.TIRITH_FAIL_OPEN === "1") return { block: false };
      return {
        block: true,
        reason: `tirith: unexpected error — ${err.message || "unknown"}`,
      };
    }

    const stdout: string = err.stdout || "";

    // Unexpected exit code
    if (exitCode !== 1 && exitCode !== 2) {
      hookEvent("unexpected_exit", `exit code ${exitCode}`);
      if (process.env.TIRITH_FAIL_OPEN === "1") return { block: false };
      return {
        block: true,
        reason: `tirith: unexpected exit code ${exitCode} — blocked for safety`,
      };
    }

    // Exit 2 = warn — check TIRITH_HOOK_WARN_ACTION
    if (exitCode === 2) {
      let warnAction = (process.env.TIRITH_HOOK_WARN_ACTION || "allow").toLowerCase();
      if (warnAction !== "allow" && warnAction !== "deny") {
        warnAction = "allow";
      }
      if (warnAction !== "deny") {
        let warningText = "Tirith: security warnings detected (non-blocking)";
        if (stdout.trim()) {
          try {
            const verdict = JSON.parse(stdout);
            const findings: any[] = verdict.findings || [];
            if (findings.length > 0) {
              warningText = "Tirith warnings (non-blocking): " + findings.map((f: any) => {
                const title = f.title || f.rule_id || "unknown";
                const sev = f.severity || "";
                return sev ? `[${sev}] ${title}` : title;
              }).join("; ");
            }
          } catch { /* ignore parse errors */ }
        }
        hookEvent("warn_allowed");
        process.stderr.write(warningText + "\n");
        return { block: false };
      }
    }

    // Exit 1 = block, Exit 2 + deny = block
    hookEvent(exitCode === 1 ? "check_block" : "warn_denied");

    // Build reason from tirith JSON output
    let reason = "Tirith security check failed";
    if (stdout.trim()) {
      try {
        const verdict = JSON.parse(stdout);
        const findings: any[] = verdict.findings || [];
        if (findings.length > 0) {
          const parts = findings.map((f: any) => {
            const title = f.title || f.rule_id || "unknown";
            const severity = f.severity || "";
            return severity ? `[${severity}] ${title}` : title;
          });
          reason = "Tirith: " + parts.join("; ");
        }
      } catch {
        reason = stdout.trim().slice(0, 500);
      }
    }

    return { block: true, reason };
  }
}

export default function (pi: ExtensionAPI) {
  pi.on("tool_call", async (event, _ctx) => {
    // Only check bash and ipython tools
    if (event.toolName !== "bash" && event.toolName !== "ipython") return undefined;

    // Extract bash command from either bash or ipython tool
    const command = extractBashCommand(event.input as Record<string, unknown>);
    if (!command) return undefined;

    const result = checkCommand(command);
    if (result.block) {
      return { block: true, reason: result.reason };
    }
    return undefined;
  });
}
