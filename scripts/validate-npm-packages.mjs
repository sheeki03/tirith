#!/usr/bin/env node
// Validate npm pack membership, versions, and the exact embedded release bytes.

import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

if (process.argv.length !== 4) {
  console.error("usage: validate-npm-packages.mjs <version> <artifact-root>");
  process.exit(2);
}

const version = process.argv[2].replace(/^v/, "");
const artifactRoot = process.argv[3];
const npmCache = mkdtempSync(join(tmpdir(), "tirith-npm-cache-"));
const MAX_ARCHIVE_MEMBER_BYTES = 128 * 1024 * 1024;
const platforms = {
  "darwin-arm64": ["tirith-aarch64-apple-darwin/tirith-aarch64-apple-darwin.tar.gz", "tirith"],
  "darwin-x64": ["tirith-x86_64-apple-darwin/tirith-x86_64-apple-darwin.tar.gz", "tirith"],
  "linux-x64": ["tirith-x86_64-unknown-linux-gnu/tirith-x86_64-unknown-linux-gnu.tar.gz", "tirith"],
  "linux-arm64": ["tirith-aarch64-unknown-linux-gnu/tirith-aarch64-unknown-linux-gnu.tar.gz", "tirith"],
  "win32-x64": ["tirith-x86_64-pc-windows-msvc/tirith-x86_64-pc-windows-msvc.zip", "tirith.exe"],
};

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: null, ...options });
  if (result.error || result.status !== 0) {
    const cause = result.error?.message || result.stderr?.toString() || `exit status ${result.status}`;
    throw new Error(`${command} ${args.join(" ")} failed: ${cause}`);
  }
  return result.stdout;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function packFiles(directory) {
  const output = run("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd: directory,
    env: { ...process.env, npm_config_cache: npmCache },
  });
  const parsed = JSON.parse(output.toString());
  if (!Array.isArray(parsed) || parsed.length !== 1 || !Array.isArray(parsed[0].files)) {
    throw new Error(`unexpected npm pack report for ${directory}`);
  }
  return parsed[0].files.map((file) => file.path).sort();
}

for (const [platform, [archive, binary]] of Object.entries(platforms)) {
  const directory = `npm/${platform}`;
  const pkg = JSON.parse(readFileSync(`${directory}/package.json`, "utf8"));
  if (pkg.version !== version) {
    throw new Error(`${pkg.name} has version ${pkg.version}; expected ${version}`);
  }
  const expectedFiles = ["LICENSE-AGPL", "LICENSE-COMMERCIAL", `bin/${binary}`, "package.json"].sort();
  const actualFiles = packFiles(directory);
  if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
    throw new Error(`${pkg.name} pack members changed: ${JSON.stringify(actualFiles)}`);
  }

  const archivePath = `${artifactRoot}/${archive}`;
  const sourceBinary = archive.endsWith(".zip")
    ? run("unzip", ["-p", archivePath, binary], { maxBuffer: MAX_ARCHIVE_MEMBER_BYTES })
    : run("tar", ["xOzf", archivePath, binary], { maxBuffer: MAX_ARCHIVE_MEMBER_BYTES });
  const stagedBinary = readFileSync(`${directory}/bin/${binary}`);
  if (sha256(sourceBinary) !== sha256(stagedBinary)) {
    throw new Error(`${pkg.name} embeds bytes that differ from ${archivePath}`);
  }
}

const rootDirectory = "npm/tirith";
const rootPackage = JSON.parse(readFileSync(`${rootDirectory}/package.json`, "utf8"));
if (rootPackage.version !== version) {
  throw new Error(`tirith has version ${rootPackage.version}; expected ${version}`);
}
for (const [name, dependencyVersion] of Object.entries(rootPackage.optionalDependencies || {})) {
  if (dependencyVersion !== version) {
    throw new Error(`${name} is pinned to ${dependencyVersion}; expected ${version}`);
  }
}
const rootFiles = packFiles(rootDirectory);
const expectedRootFiles = ["LICENSE-AGPL", "LICENSE-COMMERCIAL", "README.md", "bin/tirith", "package.json"].sort();
if (JSON.stringify(rootFiles) !== JSON.stringify(expectedRootFiles)) {
  throw new Error(`tirith pack members changed: ${JSON.stringify(rootFiles)}`);
}

console.log(`validated six npm packages for ${version}`);
