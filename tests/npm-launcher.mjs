import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

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

function checkRuntimeSelection(platform, arch, report, expectedStatus, excludeNetwork = false) {
  let selected = 0;
  let executed = 0;
  let reportReads = 0;
  const errors = [];
  const stopped = {};
  let status = 0;
  const requireMock = (name) => {
    if (name === "path") return path;
    assert.equal(name, "child_process");
    return { execFileSync: () => { executed += 1; } };
  };
  requireMock.resolve = () => { selected += 1; return "/fixture/package.json"; };
  const reportMock = report === undefined ? undefined : {
    excludeNetwork,
    getReport() {
      assert.equal(this.excludeNetwork, true, "runtime report must exclude networking");
      reportReads += 1;
      if (report instanceof Error) throw report;
      return report;
    },
  };
  try {
    vm.runInNewContext(fs.readFileSync(source, "utf8"), {
      require: requireMock,
      console: { error: (message) => errors.push(message) },
      process: {
        platform, arch, report: reportMock, argv: ["node", "tirith"],
        exit(code) { status = code; throw stopped; },
      },
    });
  } catch (error) {
    if (error !== stopped) throw error;
  }
  assert.equal(status, expectedStatus);
  assert.equal(selected, expectedStatus === 0 ? 1 : 0);
  assert.equal(executed, expectedStatus === 0 ? 1 : 0);
  if (expectedStatus !== 0) {
    assert.match(errors.join("\n"), /require glibc/);
    assert.match(errors.join("\n"), /cargo install tirith/);
    assert.match(errors.join("\n"), /does not require administrator/);
    const reportAvailable = typeof excludeNetwork === "boolean" &&
      report && !(report instanceof Error) && report.header && typeof report.header === "object";
    if (reportAvailable) {
      assert.match(errors.join("\n"), /does not identify glibc/);
      assert.doesNotMatch(errors.join("\n"), /Use Node/);
    } else {
      assert.match(errors.join("\n"), /Use Node 20\.13/);
    }
  }
  if (reportMock) assert.equal(reportMock.excludeNetwork, excludeNetwork, "report options must be restored");
  if (platform !== "linux" || typeof excludeNetwork !== "boolean") assert.equal(reportReads, 0);
}

for (const arch of ["x64", "arm64"]) {
  checkRuntimeSelection("linux", arch, { header: { glibcVersionRuntime: "2.36" } }, 0);
  checkRuntimeSelection("linux", arch, { header: { glibcVersionRuntime: "2.36" } }, 0, true);
  checkRuntimeSelection("linux", arch, { header: { glibcVersionRuntime: "2.36" } }, 1, null);
  checkRuntimeSelection("linux", arch, new Error("report failed with exclusion set"), 1, true);
  for (const report of [undefined, null, {}, { header: {} },
    { header: { glibcVersionRuntime: "" } },
    { header: { glibcVersionRuntime: "musl" } },
    new Error("runtime report unavailable")]) {
    checkRuntimeSelection("linux", arch, report, 1);
  }
}
checkRuntimeSelection("darwin", "arm64", new Error("must not inspect libc"), 0);
checkRuntimeSelection("win32", "x64", new Error("must not inspect libc"), 0);

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
