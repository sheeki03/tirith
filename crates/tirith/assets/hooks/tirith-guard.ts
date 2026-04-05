// Pi CLI extension: intercepts bash tool calls and runs tirith security check.
//
// Protocol limitation: the Pi CLI extension API only supports two return values:
//   - undefined (allow, invisible to the agent)
//   - { block: true, reason: string } (deny with reason)
// There is no "allow with message" option. On the warn-allow path, findings are
// written to process.stderr as a best-effort side channel — the host may or may
// not surface stderr to the user.
//
// Environment:
//   TIRITH_BIN              — path to tirith binary (default: "tirith")
//   TIRITH_HOOK_WARN_ACTION — "allow" (default) or "deny"
//   TIRITH_FAIL_OPEN        — "1" to allow on error (default: deny)

import { execFile, execFileSync } from "node:child_process";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

function hookEvent(event: string, detail?: string) {
  try {
    const tirithBin = process.env.TIRITH_BIN || "tirith";
    execFile(tirithBin, [
      "hook-event", "--integration", "pi-cli",
      "--hook-type", "tool_call", "--event", event,
      ...(detail ? ["--detail", detail] : []),
    ], () => {});
  } catch {}
}

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
        { timeout: 10_000, encoding: "utf-8", env: { ...process.env, TIRITH_INTEGRATION: "pi-cli" } },
      );
      // Exit 0 = clean, allow
      hookEvent("check_ok");
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
        hookEvent("timeout");
        if (process.env.TIRITH_FAIL_OPEN === "1") return undefined;
        return { block: true, reason: "tirith: check timed out — blocked for safety" };
      }

      const exitCode: number | undefined = err.status;
      if (exitCode == null) {
        hookEvent("unexpected_exit", err.message || "unknown");
        if (process.env.TIRITH_FAIL_OPEN === "1") return undefined;
        return {
          block: true,
          reason: `tirith: unexpected error — ${err.message || "unknown"}`,
        };
      }

      const stdout: string = err.stdout || "";

      // Unexpected exit code
      if (exitCode !== 1 && exitCode !== 2) {
        hookEvent("unexpected_exit", `exit code ${exitCode}`);
        if (process.env.TIRITH_FAIL_OPEN === "1") return undefined;
        return {
          block: true,
          reason: `tirith: unexpected exit code ${exitCode} — blocked for safety`,
        };
      }

      // Exit 2 = warn — check TIRITH_HOOK_WARN_ACTION
      if (exitCode === 2) {
        let warnAction = (process.env.TIRITH_HOOK_WARN_ACTION || "allow").toLowerCase();
        if (warnAction !== "allow" && warnAction !== "deny") {
          process.stderr.write(`tirith: warning: unrecognized TIRITH_HOOK_WARN_ACTION='${warnAction}', defaulting to 'allow'\n`);
          warnAction = "allow";
        }
        if (warnAction !== "deny") {
          // Parse findings from stdout for stderr warning
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
          return undefined;
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
  });
}
