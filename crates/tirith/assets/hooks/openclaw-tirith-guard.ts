// OpenClaw plugin: intercepts exec tool calls and runs tirith security check.
//
// Protocol limitation: the OpenClaw plugin API only supports two return shapes:
//   - void/undefined (allow, invisible to the agent)
//   - { block: true, blockReason: string } (deny with reason)
// There is no "allow with message" option. On the warn-allow path, findings are
// written to process.stderr as a best-effort side channel — the host may or may
// not surface stderr to the user.
//
// Environment:
//   TIRITH_BIN              -- path to tirith binary (default: "tirith")
//   TIRITH_SHELL            -- shell tokenizer: posix, powershell, cmd (default: "posix")
//   TIRITH_HOOK_WARN_ACTION -- "allow" (default) or "deny"
//   TIRITH_FAIL_OPEN        -- "1" to allow on error (default: deny)

import { execFile, execFileSync } from "node:child_process";
import type { OpenClawPluginDefinition } from "openclaw/plugin-sdk";

function hookEvent(event: string, detail?: string) {
  try {
    const tirithBin = process.env.TIRITH_BIN || "tirith";
    execFile(tirithBin, [
      "hook-event", "--integration", "openclaw",
      "--hook-type", "before_tool_call", "--event", event,
      ...(detail ? ["--detail", detail] : []),
    ], () => {});
  } catch {}
}

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
          { timeout: 10_000, encoding: "utf-8", env: { ...process.env, TIRITH_INTEGRATION: "openclaw" } },
        );
        hookEvent("check_ok");
        return; // Exit 0 = allow
      } catch (err: any) {
        if (err.code === "ENOENT") {
          if (process.env.TIRITH_FAIL_OPEN === "1") return;
          return { block: true, blockReason: `tirith not found -- install or set TIRITH_FAIL_OPEN=1` };
        }
        // Timeout detection: execFileSync sets killed=true and/or signal="SIGTERM".
        if (err.killed || err.signal === "SIGTERM" || err.code === "ETIMEDOUT") {
          hookEvent("timeout");
          if (process.env.TIRITH_FAIL_OPEN === "1") return;
          return { block: true, blockReason: "tirith: check timed out" };
        }
        const exitCode: number | undefined = err.status; // execFileSync uses .status
        if (exitCode == null || (exitCode !== 1 && exitCode !== 2)) {
          hookEvent("unexpected_exit", `exit code ${exitCode}`);
          if (process.env.TIRITH_FAIL_OPEN === "1") return;
          return { block: true, blockReason: `tirith: unexpected exit ${exitCode}` };
        }
        if (exitCode === 2) {
          let warnAction = (process.env.TIRITH_HOOK_WARN_ACTION || "allow").toLowerCase();
          if (warnAction !== "allow" && warnAction !== "deny") {
            process.stderr.write(`tirith: warning: unrecognized TIRITH_HOOK_WARN_ACTION='${warnAction}', defaulting to 'allow'\n`);
            warnAction = "allow";
          }
          if (warnAction !== "deny") {
            // Parse findings from stdout for stderr warning
            let warningText = "Tirith: security warnings detected (non-blocking)";
            const stdout: string = err.stdout || "";
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
            return;
          }
        }
        hookEvent(exitCode === 1 ? "check_block" : "warn_denied");
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
