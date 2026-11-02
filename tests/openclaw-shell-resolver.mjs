import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

// The installed OpenClaw asset deliberately stays JavaScript-compatible even
// though its extension is .ts. Loading the exact shipped bytes through a data
// URL tests the resolver that setup writes, rather than a duplicated fixture.
const assetUrl = new URL(
  "../crates/tirith/assets/hooks/openclaw-tirith-guard.ts",
  import.meta.url,
);
const source = await readFile(assetUrl, "utf8");
const moduleUrl = `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
const { default: plugin, deriveExecContext, resolveShellTokenizer } = await import(moduleUrl);

const defaultExecContext = {
  configuredHost: "auto",
  configuredHostKnown: true,
  elevatedDefaultKnown: false,
};
const unknownExecContext = {
  configuredHostKnown: false,
  elevatedDefaultKnown: false,
};

function expectShell(
  expected,
  toolName,
  params,
  configured,
  platform,
  gatewayShell = platform === "win32" ? null : "/bin/sh",
  configuredBash,
  execContext = defaultExecContext,
) {
  const result = resolveShellTokenizer(
    toolName,
    params,
    configured,
    platform,
    gatewayShell,
    configuredBash,
    execContext,
  );
  assert.equal(result.ok, true, result.reason);
  assert.equal(result.shell, expected);
}

function expectBlocked(
  toolName,
  params,
  configured,
  platform,
  reasonFragment,
  gatewayShell = platform === "win32" ? null : "/bin/sh",
  configuredBash,
  execContext = defaultExecContext,
) {
  const result = resolveShellTokenizer(
    toolName,
    params,
    configured,
    platform,
    gatewayShell,
    configuredBash,
    execContext,
  );
  assert.equal(result.ok, false, `unexpectedly resolved ${result.shell}`);
  assert.match(result.reason, reasonFragment);
}

// The legacy Bash surface can be redirected by settings.shellPath or custom
// operations, neither of which is present in before_tool_call. Its assertion is
// mandatory and independent from the exec gateway assertion.
expectBlocked("bash", {}, undefined, "linux", /TIRITH_BASH_SHELL/);
expectShell("fish", "bash", {}, "powershell", "linux", "/bin/sh", "fish");
expectShell("powershell", "bash", {}, "posix", "linux", "/opt/custom", "powershell");
expectShell("posix", "exec", { host: "gateway" }, "posix", "linux", "/bin/sh", "fish");
expectBlocked("bash", {}, undefined, "linux", /invalid TIRITH_BASH_SHELL/, "/bin/sh", "nu");

// Explicit exec surfaces have one known grammar.
expectShell("posix", "exec", { host: "sandbox", elevated: false }, undefined, "win32");
expectShell("powershell", "exec", { host: "gateway" }, undefined, "win32");
expectShell("posix", "exec", { host: "gateway" }, undefined, "linux");
expectShell("powershell", "exec", { host: "sandbox", elevated: true }, undefined, "win32");
expectBlocked("exec", { host: "sandbox" }, undefined, "win32", /cannot determine/);
expectShell("posix", "exec", { host: "sandbox" }, undefined, "linux");

// Non-Windows gateways honor OpenClaw's process SHELL. PowerShell on Linux or
// macOS must be scanned as PowerShell, and auto/sandbox-with-default-elevation
// stays ambiguous because it may instead resolve to the POSIX sandbox.
expectShell("powershell", "exec", { host: "gateway" }, undefined, "linux", "/usr/bin/pwsh");
expectBlocked(
  "exec",
  { host: "gateway" },
  "posix",
  "linux",
  /does not match/,
  "/usr/bin/pwsh",
);
expectShell(
  "powershell",
  "exec",
  { host: "sandbox", elevated: true },
  undefined,
  "linux",
  "/usr/bin/pwsh",
);
expectBlocked(
  "exec",
  { host: "auto" },
  undefined,
  "linux",
  /cannot determine/,
  "/usr/bin/pwsh",
);
expectShell(
  "powershell",
  "exec",
  { host: "auto" },
  "powershell",
  "linux",
  "/usr/bin/pwsh",
);
expectBlocked(
  "exec",
  { host: "sandbox" },
  undefined,
  "linux",
  /cannot determine/,
  "/usr/bin/pwsh",
  undefined,
  { ...defaultExecContext, elevatedDefaultKnown: false },
);
expectShell(
  "posix",
  "exec",
  { host: "sandbox", elevated: false },
  undefined,
  "linux",
  "/usr/bin/pwsh",
);

// auto is equivalent across POSIX hosts, but ambiguous on Windows because the
// sandbox uses sh and the gateway uses PowerShell.
expectShell("posix", "exec", { host: "auto" }, undefined, "linux");
expectBlocked("exec", { host: "auto" }, undefined, "win32", /cannot determine/);
expectShell("powershell", "exec", { host: "auto" }, "powershell", "win32");
expectShell(
  "powershell",
  "exec",
  { host: "auto" },
  undefined,
  "win32",
  null,
  undefined,
  { ...defaultExecContext, sandboxAvailable: false },
);

// Recommended setup: an ordinary omitted-host exec uses OpenClaw's configured
// default (`auto`). On a POSIX gateway, both auto outcomes use POSIX grammar,
// so `ls -la` resolves without an environment override. The shipped resolver
// also consumes the trusted api.config/session context for explicit defaults.
const normalSetupApi = {
  config: {},
  runtime: {
    agent: { session: { getSessionEntry: () => undefined } },
    sandbox: { resolveWorkspaceAuthority: () => ({ sandboxed: false, workspaceAccess: "rw" }) },
  },
};
const normalSetupContext = deriveExecContext(normalSetupApi, {
  agentId: "main",
  sessionKey: "agent:main:main",
});
assert.deepEqual(normalSetupContext, {
  configuredHost: "auto",
  configuredHostKnown: true,
  elevatedDefaultKnown: false,
  sandboxAvailable: false,
  invalid: undefined,
});
expectShell(
  "posix",
  "exec",
  {},
  undefined,
  "linux",
  "/bin/zsh",
  undefined,
  normalSetupContext,
);

// OpenClaw resolves omitted elevation from an inline directive, then the
// session override, then agents.defaults.elevatedDefault. The hook cannot see
// the effective inline/allowlist result, so even an absent session entry and a
// global default of `on` must retain both outcomes. On a Windows gateway an
// elevated sandbox call executes as PowerShell rather than POSIX.
const globalElevatedDefaultContext = deriveExecContext(
  {
    config: { agents: { defaults: { elevatedDefault: "on" } } },
    runtime: {
      agent: { session: { getSessionEntry: () => undefined } },
      sandbox: { resolveWorkspaceAuthority: () => ({ sandboxed: true }) },
    },
  },
  { agentId: "main", sessionKey: "agent:main:main" },
);
assert.equal(globalElevatedDefaultContext.elevatedDefaultKnown, false);
expectBlocked(
  "exec",
  { host: "sandbox" },
  undefined,
  "win32",
  /cannot determine/,
  null,
  undefined,
  globalElevatedDefaultContext,
);
expectShell(
  "powershell",
  "exec",
  { host: "sandbox" },
  "powershell",
  "win32",
  null,
  undefined,
  globalElevatedDefaultContext,
);

// A turn-local inline `/elevated` directive outranks a stored `off` session
// value, but before_tool_call does not expose that directive or its allow
// eligibility. Treat the stored value as unobservable rather than known-false.
const inlineElevatedContext = deriveExecContext(
  {
    config: { agents: { defaults: { elevatedDefault: "off" } } },
    runtime: {
      agent: { session: { getSessionEntry: () => ({ elevatedLevel: "off" }) } },
      sandbox: { resolveWorkspaceAuthority: () => ({ sandboxed: true }) },
    },
  },
  { agentId: "main", sessionKey: "agent:main:main" },
);
assert.equal(inlineElevatedContext.elevatedDefaultKnown, false);
expectBlocked(
  "exec",
  { host: "sandbox" },
  undefined,
  "win32",
  /cannot determine/,
  null,
  undefined,
  inlineElevatedContext,
);

const nodeSessionContext = deriveExecContext(
  {
    config: { tools: { exec: { host: "gateway" } } },
    runtime: {
      agent: { session: { getSessionEntry: () => ({ execHost: "node" }) } },
      sandbox: { resolveWorkspaceAuthority: () => ({ sandboxed: false }) },
    },
  },
  { agentId: "main", sessionKey: "agent:main:main" },
);
expectBlocked(
  "exec",
  {},
  undefined,
  "linux",
  /cannot determine/,
  "/bin/sh",
  undefined,
  nodeSessionContext,
);

const invalidSessionContext = deriveExecContext(
  {
    config: {},
    runtime: {
      agent: { session: { getSessionEntry: () => ({ execHost: "mystery" }) } },
      sandbox: { resolveWorkspaceAuthority: () => ({ sandboxed: false }) },
    },
  },
  { agentId: "main", sessionKey: "agent:main:main" },
);
expectBlocked(
  "exec",
  {},
  "posix",
  "linux",
  /invalid OpenClaw session exec host/,
  "/bin/sh",
  undefined,
  invalidSessionContext,
);

const missingAgentIdentityContext = deriveExecContext(
  {
    config: {
      agents: { entries: { main: { tools: { exec: { host: "node" } } } } },
    },
    runtime: {
      agent: { session: { getSessionEntry: () => undefined } },
      sandbox: { resolveWorkspaceAuthority: () => ({ sandboxed: false }) },
    },
  },
  { sessionKey: "opaque-session" },
);
expectBlocked(
  "exec",
  {},
  undefined,
  "linux",
  /cannot determine/,
  "/bin/sh",
  undefined,
  missingAgentIdentityContext,
);

// Without trusted session context an omitted host might be a remote node, so
// it still fails closed. A shell assertion supplies the missing identity.
expectBlocked(
  "exec",
  {},
  undefined,
  "linux",
  /cannot determine/,
  "/bin/sh",
  undefined,
  unknownExecContext,
);
expectShell(
  "powershell",
  "exec",
  {},
  "powershell",
  "win32",
  null,
  undefined,
  unknownExecContext,
);
expectShell(
  "posix",
  "exec",
  {},
  "posix",
  "linux",
  "/bin/sh",
  undefined,
  unknownExecContext,
);

// Remote node OS is not present in before_tool_call context. Exercise every
// supported asserted grammar, including cmd, and refuse a missing assertion.
expectBlocked("exec", { host: "node" }, undefined, "linux", /cannot determine/);
for (const shell of ["posix", "fish", "powershell", "cmd"]) {
  expectShell(shell, "exec", { host: "node" }, shell, "linux");
}

// Fish and unknown custom gateway shells cannot be inferred from SHELL alone:
// OpenClaw may replace fish with bash/sh depending on PATH.
expectBlocked("exec", { host: "gateway" }, undefined, "linux", /cannot determine/, "/bin/fish");
expectShell("fish", "exec", { host: "gateway" }, "fish", "linux", "/bin/fish");
expectBlocked("exec", { host: "gateway" }, undefined, "linux", /cannot determine/, "/opt/nu");

// Invalid values and contradictions must not fall through to Tirith's POSIX
// fallback, even when TIRITH_FAIL_OPEN is enabled elsewhere in the plugin.
expectBlocked("exec", { host: "gateway" }, "posix", "win32", /does not match/);
expectBlocked("exec", { host: "gateway" }, "", "win32", /invalid TIRITH_SHELL/);
expectBlocked("exec", { host: "mystery" }, undefined, "linux", /invalid OpenClaw exec host/);
expectBlocked("exec", { host: "gateway", elevated: "yes" }, undefined, "linux", /invalid OpenClaw elevated flag/);

// CI runs this on every platform. Verify the real runner maps its gateway to
// the same tokenizer the resolver advertises.
expectShell(
  process.platform === "win32" ? "powershell" : "posix",
  "exec",
  { host: "gateway" },
  undefined,
  process.platform,
);

// Exercise the installed hook boundary as well as the pure resolver: shell
// identity errors must block before Tirith is spawned and cannot be weakened by
// the operational TIRITH_FAIL_OPEN escape hatch.
let beforeToolCall;
plugin.register({
  ...normalSetupApi,
  on(name, handler) {
    if (name === "before_tool_call") beforeToolCall = handler;
  },
});
assert.equal(typeof beforeToolCall, "function");
const originalFailOpen = process.env.TIRITH_FAIL_OPEN;
const originalShell = process.env.TIRITH_SHELL;
const originalBashShell = process.env.TIRITH_BASH_SHELL;
const originalTirithBin = process.env.TIRITH_BIN;
const originalExpectedTokenizer = process.env.TIRITH_TEST_EXPECTED_TOKENIZER;
const originalCwd = process.cwd();
const fakeTirithDir = await mkdtemp(join(tmpdir(), "tirith-openclaw-test-"));
try {
  // Exercise the actual registered handler for the documented setup check. A
  // tiny Node entry named `check` stands in for a successful tirith binary on
  // every CI platform; the plugin still owns config/session derivation and the
  // exact execFileSync argv boundary.
  await writeFile(
    join(fakeTirithDir, "check"),
    [
      'const shellIndex = process.argv.indexOf("--shell");',
      "if (process.argv[shellIndex + 1] !== process.env.TIRITH_TEST_EXPECTED_TOKENIZER) process.exit(3);",
      'process.stdout.write(JSON.stringify({ requires_approval: false, findings: [] }));',
      "",
    ].join("\n"),
    "utf8",
  );
  process.chdir(fakeTirithDir);
  process.env.TIRITH_BIN = process.execPath;
  // Same platform contract the resolver assertion above checks: the runner's
  // own gateway is PowerShell on Windows and POSIX elsewhere.
  process.env.TIRITH_TEST_EXPECTED_TOKENIZER =
    process.platform === "win32" ? "powershell" : "posix";
  delete process.env.TIRITH_SHELL;
  const allowed = beforeToolCall(
    { toolName: "exec", params: { command: "ls -la" } },
    { agentId: "main", sessionKey: "agent:main:main" },
  );
  assert.equal(allowed, undefined);

  // TIRITH_SHELL belongs to exec only. A custom Fish/PowerShell Bash backend
  // is scanned with its independent assertion and reaches tirith unchanged.
  process.env.TIRITH_SHELL = "powershell";
  process.env.TIRITH_BASH_SHELL = "fish";
  process.env.TIRITH_TEST_EXPECTED_TOKENIZER = "fish";
  const fishBashAllowed = beforeToolCall(
    { toolName: "bash", params: { command: "ls -la" } },
    { agentId: "main", sessionKey: "agent:main:main" },
  );
  assert.equal(fishBashAllowed, undefined);

  process.env.TIRITH_BASH_SHELL = "powershell";
  process.env.TIRITH_TEST_EXPECTED_TOKENIZER = "powershell";
  const powershellBashAllowed = beforeToolCall(
    { toolName: "bash", params: { command: "Get-ChildItem" } },
    { agentId: "main", sessionKey: "agent:main:main" },
  );
  assert.equal(powershellBashAllowed, undefined);

  process.env.TIRITH_FAIL_OPEN = "1";
  delete process.env.TIRITH_SHELL;
  delete process.env.TIRITH_BASH_SHELL;
  const blocked = beforeToolCall({
    toolName: "exec",
    params: { command: "echo safe", host: "node" },
  });
  assert.equal(blocked?.block, true);
  assert.match(blocked?.blockReason, /cannot determine/);

  const bashBlocked = beforeToolCall({ toolName: "bash", params: { command: "echo safe" } });
  assert.equal(bashBlocked?.block, true);
  assert.match(bashBlocked?.blockReason, /TIRITH_BASH_SHELL/);

  process.env.TIRITH_BASH_SHELL = "nu";
  const invalidBashAssertion = beforeToolCall({
    toolName: "bash",
    params: { command: "echo safe" },
  });
  assert.equal(invalidBashAssertion?.block, true);
  assert.match(invalidBashAssertion?.blockReason, /invalid TIRITH_BASH_SHELL/);
} finally {
  if (originalFailOpen === undefined) delete process.env.TIRITH_FAIL_OPEN;
  else process.env.TIRITH_FAIL_OPEN = originalFailOpen;
  if (originalShell === undefined) delete process.env.TIRITH_SHELL;
  else process.env.TIRITH_SHELL = originalShell;
  if (originalBashShell === undefined) delete process.env.TIRITH_BASH_SHELL;
  else process.env.TIRITH_BASH_SHELL = originalBashShell;
  if (originalTirithBin === undefined) delete process.env.TIRITH_BIN;
  else process.env.TIRITH_BIN = originalTirithBin;
  if (originalExpectedTokenizer === undefined) delete process.env.TIRITH_TEST_EXPECTED_TOKENIZER;
  else process.env.TIRITH_TEST_EXPECTED_TOKENIZER = originalExpectedTokenizer;
  process.chdir(originalCwd);
  // Windows runners hold fresh temp entries briefly (antivirus and the old
  // process cwd release), which surfaces as EBUSY from rmdir. Retry with
  // backoff, and treat a still-held leftover as non-fatal: every assertion
  // above has already passed and the runner temp dir is disposable.
  try {
    await rm(fakeTirithDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  } catch (error) {
    console.warn(`leaving temp dir behind after retries: ${error?.message ?? error}`);
  }
}

console.log("OpenClaw shell resolver: all parser/executor mappings passed");
