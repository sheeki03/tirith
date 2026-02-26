// Pi CLI extension: intercepts bash tool calls and runs tirith security check.
//
// Environment:
//   TIRITH_BIN              — path to tirith binary (default: "tirith")
//   TIRITH_HOOK_WARN_ACTION — "deny" (default) or "allow"
//   TIRITH_FAIL_OPEN        — "1" to allow on error (default: deny)

import { execFileSync } from "node:child_process";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

export default function (pi: ExtensionAPI) {
  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName !== "bash") return undefined;

    const command = event.input?.command as string | undefined;
    if (typeof command !== "string" || !command.trim()) return undefined;

    const tirithBin = process.env.TIRITH_BIN || "tirith";

    try {
      execFileSync(
        tirithBin,
        ["check", "--json", "--non-interactive", "--shell", "posix", "--", command],
        { timeout: 10_000, encoding: "utf-8" },
      );
      // Exit 0 = clean, allow
      return undefined;
    } catch (err: any) {
      // execFileSync throws on non-zero exit or other errors
      if (err.code === "ENOENT") {
        if (process.env.TIRITH_FAIL_OPEN === "1") return undefined;
        return {
          block: true,
          reason: `tirith: ${tirithBin} not found — install tirith or set TIRITH_FAIL_OPEN=1`,
        };
      }

      if (err.killed) {
        if (process.env.TIRITH_FAIL_OPEN === "1") return undefined;
        return { block: true, reason: "tirith: check timed out — blocked for safety" };
      }

      const exitCode: number | undefined = err.status;
      if (exitCode == null) {
        if (process.env.TIRITH_FAIL_OPEN === "1") return undefined;
        return {
          block: true,
          reason: `tirith: unexpected error — ${err.message || "unknown"}`,
        };
      }

      const stdout: string = err.stdout || "";

      // Unexpected exit code
      if (exitCode !== 1 && exitCode !== 2) {
        if (process.env.TIRITH_FAIL_OPEN === "1") return undefined;
        return {
          block: true,
          reason: `tirith: unexpected exit code ${exitCode} — blocked for safety`,
        };
      }

      // Exit 2 = warn — check TIRITH_HOOK_WARN_ACTION
      if (exitCode === 2) {
        const warnAction = (process.env.TIRITH_HOOK_WARN_ACTION || "deny").toLowerCase();
        if (warnAction === "allow") return undefined;
      }

      // Exit 1 = block, Exit 2 + deny = block
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
  });
}
