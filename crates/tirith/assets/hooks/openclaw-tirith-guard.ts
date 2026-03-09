// OpenClaw plugin: intercepts exec tool calls and runs tirith security check.
//
// Environment:
//   TIRITH_BIN              -- path to tirith binary (default: "tirith")
//   TIRITH_SHELL            -- shell tokenizer: posix, powershell, cmd (default: "posix")
//   TIRITH_HOOK_WARN_ACTION -- "deny" (default) or "allow"
//   TIRITH_FAIL_OPEN        -- "1" to allow on error (default: deny)

import { execFileSync } from "node:child_process";
import type { OpenClawPluginDefinition } from "openclaw/plugin-sdk";

export default {
  id: "tirith-security",
  name: "tirith Security Scanner",
  description: "Pre-exec command security scanning via tirith",
  register(api) {
    api.on("before_tool_call", (event, ctx) => {
      if (event.toolName !== "exec" && event.toolName !== "bash") return;
      const command = event.params?.command as string | undefined;
      if (typeof command !== "string" || !command.trim()) return;

      const tirithBin = process.env.TIRITH_BIN || "tirith";
      const shell = process.env.TIRITH_SHELL || "posix";
      try {
        execFileSync(
          tirithBin,
          ["check", "--json", "--non-interactive", "--shell", shell, "--", command],
          { timeout: 10_000, encoding: "utf-8" },
        );
        return; // Exit 0 = allow
      } catch (err: any) {
        if (err.code === "ENOENT") {
          if (process.env.TIRITH_FAIL_OPEN === "1") return;
          return { block: true, blockReason: `tirith not found -- install or set TIRITH_FAIL_OPEN=1` };
        }
        // Timeout detection: execFileSync sets killed=true and/or signal="SIGTERM".
        if (err.killed || err.signal === "SIGTERM" || err.code === "ETIMEDOUT") {
          if (process.env.TIRITH_FAIL_OPEN === "1") return;
          return { block: true, blockReason: "tirith: check timed out" };
        }
        const exitCode: number | undefined = err.status; // execFileSync uses .status
        if (exitCode == null || (exitCode !== 1 && exitCode !== 2)) {
          if (process.env.TIRITH_FAIL_OPEN === "1") return;
          return { block: true, blockReason: `tirith: unexpected exit ${exitCode}` };
        }
        if (exitCode === 2) {
          const warnAction = (process.env.TIRITH_HOOK_WARN_ACTION || "deny").toLowerCase();
          if (warnAction === "allow") return;
        }
        // Parse findings from stdout
        let reason = "tirith security check failed";
        const stdout: string = err.stdout || "";
        if (stdout.trim()) {
          try {
            const verdict = JSON.parse(stdout);
            const findings: any[] = verdict.findings || [];
            if (findings.length > 0) {
              reason = "tirith: " + findings.map((f: any) => {
                const title = f.title || f.rule_id || "unknown";
                const sev = f.severity || "";
                return sev ? `[${sev}] ${title}` : title;
              }).join("; ");
            }
          } catch { reason = stdout.trim().slice(0, 500); }
        }
        return { block: true, blockReason: reason };
      }
    });
  },
} satisfies OpenClawPluginDefinition;
