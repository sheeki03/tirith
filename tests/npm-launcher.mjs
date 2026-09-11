import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fs.mkdtempSync(path.join(os.tmpdir(), "tirith-npm-launcher-"));
const source = fileURLToPath(new URL("../npm/tirith/bin/tirith", import.meta.url));
const launcher = path.join(root, "tirith.cjs");
const platform = `${process.platform}-${process.arch}`;
const packageName = `@sheeki03/tirith-${platform}`;
const packageDir = path.join(root, "node_modules", packageName);
const binary = path.join(packageDir, "bin", process.platform === "win32" ? "tirith.exe" : "tirith");
const env = { ...process.env };
delete env.NODE_OPTIONS;
delete env.NODE_PATH;

function launch(...args) {
  const result = spawnSync(process.execPath, [launcher, ...args], {
    cwd: root,
    env,
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.ifError(result.error);
  return result;
}

try {
  fs.copyFileSync(source, launcher);
  const missingPackage = launch();
  assert.equal(missingPackage.status, 1);
  assert.match(missingPackage.stderr, /Could not find package/);
  assert.ok(missingPackage.stderr.includes(packageName));
  assert.match(missingPackage.stderr, /npm install tirith --force/);

  fs.mkdirSync(path.dirname(binary), { recursive: true });
  fs.writeFileSync(path.join(packageDir, "package.json"), JSON.stringify({ name: packageName }));
  // Node supplies a real platform executable, so these assertions exercise
  // execFileSync and OS exit/signal behavior without a Cargo build or release.
  if (process.platform === "win32") {
    fs.copyFileSync(process.execPath, binary);
  } else {
    fs.symlinkSync(process.execPath, binary);
  }

  const success = launch("-e", "process.stdout.write(process.argv[1])", "--", "literal ; $(argument)");
  assert.equal(success.status, 0);
  assert.equal(success.stdout, "literal ; $(argument)");
  assert.equal(launch("-e", "process.exit(7)").status, 7);

  const killed = launch("-e", "process.kill(process.pid, 'SIGTERM')");
  assert.notEqual(killed.status, 0, "a terminated native child must never look successful");
  if (process.platform !== "win32") {
    assert.equal(killed.signal, "SIGTERM");
  }

  fs.unlinkSync(binary);
  const missingBinary = launch();
  assert.notEqual(missingBinary.status, 0);
  assert.match(missingBinary.stderr, /ENOENT/);
  console.log("npm launcher exit, signal, argument, and missing-installation checks passed");
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
