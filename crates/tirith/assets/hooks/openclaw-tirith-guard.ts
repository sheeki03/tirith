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
//   TIRITH_SHELL            -- explicit exec-tool shell assertion: posix, fish, powershell, cmd
//   TIRITH_BASH_SHELL       -- explicit legacy Bash-tool shell assertion (same values)
//   TIRITH_HOOK_WARN_ACTION -- "allow" (default) or "deny"; "ask" denies with
//                              guidance (see warnDenial), any other value denies
//   TIRITH_FAIL_OPEN        -- "1" to allow on error (default: deny)

import { execFileSync } from "node:child_process";

// Upper bound on the checker's JSON response. Node's 1 MiB default is smaller
// than a block verdict for a large command can be. A response past this limit
// makes Node stop the checker and discard its exit status, so it is denied.
const MAX_CHECK_RESPONSE_BYTES = 16 * 1024 * 1024;
const VALID_SHELLS = new Set(["posix", "fish", "powershell", "cmd"]);
const VALID_EXEC_HOSTS = new Set(["auto", "sandbox", "gateway", "node"]);
const POSIX_GATEWAY_SHELLS = new Set([
  "sh",
  "bash",
  "zsh",
  "dash",
  "ash",
  "ksh",
  "ksh93",
  "mksh",
]);

function resolvedShell(shell) {
  return { ok: true, shell };
}

function unresolvedShell(reason) {
  return { ok: false, reason };
}

function invalidShellAssertion(name) {
  return unresolvedShell(
    `tirith: invalid ${name} (expected posix, fish, powershell, or cmd)`,
  );
}

function requireShellAssertion(configuredShell, assertionName = "TIRITH_SHELL") {
  if (configuredShell === undefined) {
    return unresolvedShell(
      `tirith: cannot determine OpenClaw's effective shell; set ${assertionName}=posix, fish, powershell, or cmd to match the executor`,
    );
  }
  return resolvedShell(configuredShell);
}

function gatewayShellForPlatform(platform, shellPath) {
  if (platform === "win32") return "powershell";
  const raw = typeof shellPath === "string" ? shellPath.trim() : "";
  // OpenClaw resolves sh/bash when SHELL is absent or is a non-interactive
  // placeholder. Both use POSIX grammar.
  if (!raw) return "posix";
  const name = raw.replaceAll("\\", "/").split("/").pop().toLowerCase();
  if (name === "false" || name === "nologin") return "posix";
  if (name === "pwsh" || name === "pwsh.exe" || name === "powershell" || name === "powershell.exe") {
    return "powershell";
  }
  if (name === "cmd" || name === "cmd.exe") return "cmd";
  if (POSIX_GATEWAY_SHELLS.has(name)) return "posix";
  // Fish is deliberately ambiguous: OpenClaw prefers bash/sh when either is on
  // PATH, but otherwise executes fish. Unknown custom shells are ambiguous too.
  return undefined;
}

function normalizeExecHost(value) {
  if (typeof value !== "string" || !VALID_EXEC_HOSTS.has(value)) return undefined;
  return value;
}

function findAgentEntry(config, agentId) {
  if (!agentId || !config || typeof config !== "object") return undefined;
  const agents = config.agents;
  if (!agents || typeof agents !== "object" || Array.isArray(agents)) return undefined;
  const normalizedId = String(agentId).trim().toLowerCase();
  if (agents.entries && typeof agents.entries === "object" && !Array.isArray(agents.entries)) {
    const key = Object.keys(agents.entries).find(
      (candidate) => candidate.trim().toLowerCase() === normalizedId,
    );
    return key === undefined ? undefined : agents.entries[key];
  }
  if (Array.isArray(agents.list)) {
    return agents.list.find(
      (entry) =>
        entry &&
        typeof entry === "object" &&
        typeof entry.id === "string" &&
        entry.id.trim().toLowerCase() === normalizedId,
    );
  }
  return undefined;
}

function hasAgentExecHostOverride(config) {
  const agents = config?.agents;
  if (!agents || typeof agents !== "object" || Array.isArray(agents)) return false;
  const entries =
    agents.entries && typeof agents.entries === "object" && !Array.isArray(agents.entries)
      ? Object.values(agents.entries)
      : Array.isArray(agents.list)
        ? agents.list
        : [];
  return entries.some((entry) => entry?.tools?.exec?.host !== undefined);
}

function readConfiguredExecHost(config, agentId, sessionState) {
  if (!sessionState.known) return { known: false };
  const sessionHost = sessionState.entry?.execHost;
  if (sessionHost !== undefined) {
    const host = normalizeExecHost(sessionHost);
    return host === undefined
      ? { known: false, invalid: "tirith: invalid OpenClaw session exec host" }
      : { known: true, host };
  }

  if (!agentId && hasAgentExecHostOverride(config)) {
    return { known: false };
  }

  const agentEntry = findAgentEntry(config, agentId);
  const agentHost = agentEntry?.tools?.exec?.host;
  if (agentHost !== undefined) {
    const host = normalizeExecHost(agentHost);
    return host === undefined
      ? { known: false, invalid: "tirith: invalid OpenClaw agent exec host" }
      : { known: true, host };
  }

  const globalHost = config?.tools?.exec?.host;
  if (globalHost !== undefined) {
    const host = normalizeExecHost(globalHost);
    return host === undefined
      ? { known: false, invalid: "tirith: invalid OpenClaw configured exec host" }
      : { known: true, host };
  }
  return { known: true, host: "auto" };
}

function readSessionState(api, context) {
  if (!context?.sessionKey) return { known: false };
  const getSessionEntry = api?.runtime?.agent?.session?.getSessionEntry;
  if (typeof getSessionEntry !== "function") return { known: false };
  try {
    return {
      known: true,
      entry: getSessionEntry({
        sessionKey: context.sessionKey,
        ...(context.agentId ? { agentId: context.agentId } : {}),
        readConsistency: "latest",
      }),
    };
  } catch {
    return { known: false };
  }
}

function readSandboxAvailability(api, config, context) {
  if (!context?.sessionKey) return undefined;
  const resolveWorkspaceAuthority = api?.runtime?.sandbox?.resolveWorkspaceAuthority;
  if (typeof resolveWorkspaceAuthority !== "function") return undefined;
  try {
    const authority = resolveWorkspaceAuthority({
      config,
      ...(context.agentId ? { agentId: context.agentId } : {}),
      sessionKey: context.sessionKey,
      requiredToolNames: ["exec"],
    });
    return typeof authority?.sandboxed === "boolean" ? authority.sandboxed : undefined;
  } catch {
    return undefined;
  }
}

export function deriveExecContext(api, context) {
  const config = api?.config && typeof api.config === "object" ? api.config : {};
  const sessionState = readSessionState(api, context);
  const sessionAgentId =
    typeof sessionState.entry?.agentId === "string" ? sessionState.entry.agentId : undefined;
  const agentId = context?.agentId ?? sessionAgentId;
  const configured = readConfiguredExecHost(config, agentId, sessionState);
  return {
    configuredHost: configured.host,
    configuredHostKnown: configured.known,
    // Omitted per-call elevation resolves from an inline message directive,
    // then the session override, then agents.defaults.elevatedDefault, and is
    // finally gated by provider/agent allow policy. before_tool_call exposes
    // none of that effective turn-level state. Even an absent or "off" session
    // value can be overridden inline, so both elevated outcomes must remain
    // candidates until their grammars agree or TIRITH_SHELL binds the executor.
    elevatedDefaultKnown: false,
    sandboxAvailable: readSandboxAvailability(api, config, context),
    invalid: configured.invalid,
  };
}

function candidateEffectiveHosts(params, execContext) {
  const requestedHost = params?.host;
  const selectedHosts = requestedHost !== undefined
    ? [requestedHost]
    : execContext?.configuredHostKnown
      ? [execContext.configuredHost]
      : ["auto", "sandbox", "gateway", "node"];
  const elevatedStates = params?.elevated !== undefined
    ? [params.elevated]
    : execContext?.elevatedDefaultKnown
      ? [execContext.elevatedDefault]
      : [false, true];
  const effectiveHosts = new Set();

  for (const selectedHost of selectedHosts) {
    for (const elevated of elevatedStates) {
      const target = elevated
        ? selectedHost === "node" ? "node" : "gateway"
        : selectedHost;
      if (target === "auto") {
        if (execContext?.sandboxAvailable === true) effectiveHosts.add("sandbox");
        else if (execContext?.sandboxAvailable === false) effectiveHosts.add("gateway");
        else {
          effectiveHosts.add("sandbox");
          effectiveHosts.add("gateway");
        }
      } else {
        effectiveHosts.add(target);
      }
    }
  }
  return effectiveHosts;
}

function resolveExecShell(configuredShell, platform, gatewayShellPath, params, execContext) {
  if (execContext?.invalid) return unresolvedShell(execContext.invalid);
  const candidates = new Set();
  let hasUnknown = false;
  for (const host of candidateEffectiveHosts(params, execContext)) {
    if (host === "sandbox") {
      candidates.add("posix");
    } else if (host === "gateway") {
      const gatewayShell = gatewayShellForPlatform(platform, gatewayShellPath);
      if (gatewayShell === undefined) hasUnknown = true;
      else candidates.add(gatewayShell);
    } else if (host === "node") {
      hasUnknown = true;
    } else {
      return unresolvedShell("tirith: invalid OpenClaw effective exec host");
    }
  }

  if (configuredShell !== undefined) {
    if (!hasUnknown && !candidates.has(configuredShell)) {
      const expected = Array.from(candidates).join(" or ");
      return unresolvedShell(
        `tirith: TIRITH_SHELL does not match OpenClaw's effective ${expected} shell`,
      );
    }
    return resolvedShell(configuredShell);
  }
  if (!hasUnknown && candidates.size === 1) {
    return resolvedShell(candidates.values().next().value);
  }
  return requireShellAssertion(configuredShell);
}

// OpenClaw's before_tool_call context does not expose the fully resolved exec
// host or remote node OS. Infer only where its public execution contract is
// unambiguous and otherwise require an explicit operator assertion. A bad or
// mismatched assertion is a configuration error and always fails closed; it is
// intentionally not covered by TIRITH_FAIL_OPEN.
export function resolveShellTokenizer(
  toolName,
  params = {},
  configuredShell = process.env.TIRITH_SHELL,
  platform = process.platform,
  gatewayShellPath = process.env.SHELL,
  configuredBashShell = process.env.TIRITH_BASH_SHELL,
  execContext = {
    configuredHost: "auto",
    configuredHostKnown: true,
    elevatedDefaultKnown: false,
  },
) {
  if (toolName === "bash") {
    if (configuredBashShell !== undefined && !VALID_SHELLS.has(configuredBashShell)) {
      return invalidShellAssertion("TIRITH_BASH_SHELL");
    }
    // before_tool_call does not expose the Bash surface's settings.shellPath
    // or custom operations. Even its default shell differs from
    // exec on Windows. A separate trusted assertion is therefore mandatory and
    // deliberately independent from TIRITH_SHELL.
    return requireShellAssertion(configuredBashShell, "TIRITH_BASH_SHELL");
  }

  if (configuredShell !== undefined && !VALID_SHELLS.has(configuredShell)) {
    return invalidShellAssertion("TIRITH_SHELL");
  }

  const host = params?.host;
  if (host !== undefined && (typeof host !== "string" || !VALID_EXEC_HOSTS.has(host))) {
    return unresolvedShell("tirith: invalid OpenClaw exec host; refusing an ambiguous scan");
  }
  if (params?.elevated !== undefined && typeof params.elevated !== "boolean") {
    return unresolvedShell("tirith: invalid OpenClaw elevated flag; refusing an ambiguous scan");
  }

  return resolveExecShell(configuredShell, platform, gatewayShellPath, params, execContext);
}

function hookEvent(event, detail, deadline = Infinity) {
  if (performance.now() + 250 >= deadline) return; // Never extend an exhausted check budget.
  try {
    const tirithBin = process.env.TIRITH_BIN || "tirith";
    // A finite timeout/kill request, not a hard kernel reaping guarantee.
    execFileSync(tirithBin, [
      "hook-event", "--integration", "openclaw",
      "--hook-type", "before_tool_call", "--event", event,
      ...(detail ? ["--detail", detail] : []),
    ], { timeout: 250, killSignal: "SIGKILL", stdio: "ignore" });
  } catch {}
}

/**
 * `TIRITH_HOOK_WARN_ACTION`: "allow" (default), "ask", "deny", or "invalid"
 * for any other value. An unparseable security setting fails closed, so
 * callers deny "invalid" as they deny "deny".
 */
function warnAction() {
  const value = (process.env.TIRITH_HOOK_WARN_ACTION || "allow").toLowerCase();
  return value === "allow" || value === "ask" || value === "deny" ? value : "invalid";
}

/**
 * Explain a warning denied by a non-allow warn action. "ask" is denied with
 * guidance: OpenClaw's newer `requireApproval` result is not used, because a
 * host that predates it would ignore it and run the command, and its outcome
 * with no one to answer is undocumented.
 */
function warnDenial(action, findings) {
  if (action === "invalid") {
    return `tirith: unrecognized TIRITH_HOOK_WARN_ACTION=${JSON.stringify(process.env.TIRITH_HOOK_WARN_ACTION ?? "")} `
      + `(valid values: allow, ask, deny) — warning blocked for safety. ${findings}`;
  }
  if (action === "ask") {
    return `${findings} — blocked; TIRITH_HOOK_WARN_ACTION=ask needs a confirmation prompt this host `
      + "integration does not have. Review the command and retry from a Tirith-protected interactive shell to confirm it.";
  }
  return findings;
}

function describeFindings(verdict, stdout, fallback, prefix = "tirith: ") {
  if (!stdout || !stdout.trim()) return fallback;
  if (verdict === undefined) return stdout.trim().slice(0, 500);
  const findings = Array.isArray(verdict?.findings) ? verdict.findings : [];
  if (findings.length === 0) return fallback;
  return prefix + findings.map((f) => {
    const title = f?.title || f?.rule_id || "unknown";
    const severity = f?.severity || "";
    return severity ? `[${severity}] ${title}` : title;
  }).join("; ");
}

export default {
  id: "tirith-security",
  name: "tirith Security Scanner",
  description: "Pre-exec command security scanning via tirith",
  register(api) {
    api.on("before_tool_call", (event, context) => {
      const telemetryDeadline = performance.now() + 10_000;
      const recordHookEvent = (event, detail) => hookEvent(event, detail, telemetryDeadline);
      if (event.toolName !== "exec" && event.toolName !== "bash") return;
      const command = event.params?.command;
      if (typeof command !== "string" || !command.trim()) {
        // A shell tool call without a string command cannot be checked; it is
        // not a no-op this guard may silently allow.
        recordHookEvent("parse_error", "no command in shell tool params");
        if (process.env.TIRITH_FAIL_OPEN === "1") return;
        return { block: true, blockReason: "tirith: no command found in hook input — blocked for safety" };
      }

      const tirithBin = process.env.TIRITH_BIN || "tirith";
      const shellResolution = resolveShellTokenizer(
        event.toolName,
        event.params,
        process.env.TIRITH_SHELL,
        process.platform,
        process.env.SHELL,
        process.env.TIRITH_BASH_SHELL,
        deriveExecContext(api, context),
      );
      if (!shellResolution.ok) {
        recordHookEvent("shell_resolution_error", shellResolution.reason);
        return { block: true, blockReason: shellResolution.reason };
      }
      const shell = shellResolution.shell;
      let stdout;
      let exitCode = 0;
      try {
        stdout = execFileSync(
          tirithBin,
          ["check", "--json", "--non-interactive", "--shell", shell, "--", command],
          {
            timeout: 10_000,
            maxBuffer: MAX_CHECK_RESPONSE_BYTES,
            encoding: "utf-8",
            env: { ...process.env, TIRITH_INTEGRATION: "openclaw" },
          },
        );
      } catch (err) {
        const execError = /** @type {any} */ (err);
        if (execError.code === "ENOBUFS") {
          // Node stops the checker once the response passes maxBuffer (with
          // SIGTERM, so this must precede the timeout test), and the exit
          // status is usually lost. A response that large comes from a verdict
          // with many findings, not a checker failure. Deny it whatever the
          // status (a block, deferred block, or acknowledgement gate must
          // never become an allow); TIRITH_FAIL_OPEN does not apply.
          recordHookEvent("check_block", "oversized checker response");
          return {
            block: true,
            blockReason: `tirith: check response exceeded the ${MAX_CHECK_RESPONSE_BYTES}-byte limit — blocked for safety`,
          };
        }
        if (execError.status === 3) {
          // Required acknowledgement is authoritative even without valid JSON,
          // and is not a checker failure covered by TIRITH_FAIL_OPEN.
          recordHookEvent("check_block");
          return {
            block: true,
            blockReason: "tirith: warning acknowledgement required — blocked; this integration cannot collect acknowledgement. Use a Tirith-protected interactive shell to acknowledge the warning.",
          };
        }
        if (execError.status === 4) {
          // A deferred block (TIRITH_DEFER=1 / --defer, pending review) is a
          // verdict, not a checker error covered by TIRITH_FAIL_OPEN.
          recordHookEvent("check_block");
          const deferredStdout = typeof execError.stdout === "string" ? execError.stdout : "";
          let deferred;
          try {
            deferred = JSON.parse(deferredStdout);
          } catch {
            deferred = undefined;
          }
          return {
            block: true,
            blockReason: describeFindings(deferred, deferredStdout, "tirith security check failed")
              + " — blocked, pending review (deferred). Resolve with `tirith pending`.",
          };
        }
        if (execError.code === "ENOENT") {
          if (process.env.TIRITH_FAIL_OPEN === "1") return;
          return { block: true, blockReason: `tirith not found -- install or set TIRITH_FAIL_OPEN=1` };
        }
        // Timeout detection: execFileSync sets killed=true and/or signal="SIGTERM".
        if (execError.killed || execError.signal === "SIGTERM" || execError.code === "ETIMEDOUT") {
          recordHookEvent("timeout");
          if (process.env.TIRITH_FAIL_OPEN === "1") return;
          return { block: true, blockReason: "tirith: check timed out" };
        }
        exitCode = execError.status; // execFileSync uses .status
        if (exitCode == null || (exitCode !== 1 && exitCode !== 2)) {
          recordHookEvent("unexpected_exit", `exit code ${exitCode}`);
          if (process.env.TIRITH_FAIL_OPEN === "1") return;
          return { block: true, blockReason: `tirith: unexpected exit ${exitCode}` };
        }
        stdout = execError.stdout || "";
      }

      let verdict;
      try {
        verdict = JSON.parse(stdout);
        // Execution-permitting responses must explicitly carry the policy gate.
        if (exitCode !== 1 && (
          verdict === null || typeof verdict !== "object"
          || !Object.prototype.hasOwnProperty.call(verdict, "requires_approval")
          || typeof verdict.requires_approval !== "boolean"
        )) {
          throw new Error("requires_approval must be a boolean");
        }
      } catch {
        if (exitCode !== 1) {
          recordHookEvent("unexpected_exit", "invalid checker JSON or requires_approval");
          if (process.env.TIRITH_FAIL_OPEN === "1" && (exitCode !== 2 || warnAction() === "allow")) return;
          return {
            block: true,
            blockReason: "tirith: invalid check response — expected JSON with a boolean requires_approval; update Tirith and reinstall the integration",
          };
        }
      }

      if (exitCode === 1) {
        recordHookEvent("check_block");
        return { block: true, blockReason: describeFindings(verdict, stdout, "tirith security check failed") };
      }
      if (verdict.requires_approval) {
        // before_tool_call has no approval result; this is not a checker error
        // that the operator's TIRITH_FAIL_OPEN setting can bypass.
        recordHookEvent("check_block");
        return {
          block: true,
          blockReason: "tirith: human approval required by policy — blocked; this integration cannot collect approval. Use a Tirith-protected interactive shell to request approval.",
        };
      }
      if (exitCode === 0) {
        recordHookEvent("check_ok");
        return;
      }

      const action = warnAction();
      if (action === "allow") {
        recordHookEvent("warn_allowed");
        process.stderr.write(
          describeFindings(
            verdict, stdout, "Tirith: security warnings detected (non-blocking)",
            "Tirith warnings (non-blocking): ",
          ) + "\n",
        );
        return;
      }
      recordHookEvent("warn_denied");
      return {
        block: true,
        blockReason: warnDenial(action, describeFindings(verdict, stdout, "tirith security check failed")),
      };
    });
  },
};
