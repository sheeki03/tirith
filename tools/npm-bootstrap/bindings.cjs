'use strict';

// Native code creates and seals this record after task/policy/input admission.
// Parsing this record alone never grants execution or containment authority.
const { createHash } = require('node:crypto');
const FD_MAX = 255;
const BINDING_MAX = 16 * 1024;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const refuse = () => { throw Object.assign(new Error('invalid sealed npm binding'), { code: 'EBOUNDINPUT' }); };
const objectKeys = (value, keys) => value !== null && typeof value === 'object' &&
  !Array.isArray(value) && Object.keys(value).join(',') === keys;
const uint = (n, max) => Number.isSafeInteger(n) && n >= 0 && n <= max;
const digest = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const decimal64 = value => typeof value === 'string' && /^(?:0|[1-9][0-9]{0,19})$/.test(value) &&
  BigInt(value) <= 18446744073709551615n;
const operand = fd => `/proc/self/fd/${fd}`;

function decodeBinding (text, bindingFd) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > BINDING_MAX ||
      !uint(bindingFd, FD_MAX) || bindingFd < 3) refuse();
  const value = JSON.parse(text);
  if (JSON.stringify(value) !== text ||
      !objectKeys(value, 'schema_version,contract,runtime,artifacts,target,cache,user_config,global_config') ||
      value.schema_version !== 1 || value.contract !== 'LocalLeafNoScriptsV1') refuse();
  const used = new Set([bindingFd]);
  const admitFd = fd => {
    if (!uint(fd, FD_MAX) || fd < 3 || used.has(fd)) refuse();
    used.add(fd);
  };
  if (!objectKeys(value.runtime, 'fd,sha256,size') || !digest(value.runtime.sha256) ||
      !uint(value.runtime.size, 64 * 1024 * 1024) || value.runtime.size < 12) refuse();
  admitFd(value.runtime.fd);
  if (!Array.isArray(value.artifacts) || value.artifacts.length < 1 || value.artifacts.length > 8) refuse();
  let total = 0;
  const names = new Set();
  for (const row of value.artifacts) {
    if (!objectKeys(row, 'fd,package_name,sha256,size') || typeof row.package_name !== 'string' ||
        !/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(row.package_name) ||
        row.package_name.length > 214 || names.has(row.package_name) || !digest(row.sha256) ||
        !uint(row.size, 32 * 1024 * 1024) || row.size === 0) refuse();
    total += row.size;
    if (total > 64 * 1024 * 1024) refuse();
    names.add(row.package_name);
    admitFd(row.fd);
  }
  for (const row of [value.target, value.cache]) {
    if (!objectKeys(row, 'fd,device,inode') || !decimal64(row.device) ||
        !decimal64(row.inode) || row.inode === '0') refuse();
    admitFd(row.fd);
  }
  if (value.target.device === value.cache.device && value.target.inode === value.cache.inode) refuse();
  for (const row of [value.user_config, value.global_config]) {
    if (!objectKeys(row, 'fd')) refuse();
    admitFd(row.fd);
  }
  for (const row of [value.runtime, ...value.artifacts, value.target, value.cache,
    value.user_config, value.global_config]) Object.freeze(row);
  Object.freeze(value.artifacts);
  return Object.freeze(value);
}

function readExact (fs, fd, size, limit) {
  if (!uint(size, limit)) refuse();
  const before = fs.fstatSync(fd, { bigint: true });
  if (!before.isFile() || before.size !== BigInt(size)) refuse();
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < size) {
    const got = fs.readSync(fd, bytes, offset, size - offset, offset);
    if (!Number.isSafeInteger(got) || got <= 0 || got > size - offset) refuse();
    offset += got;
  }
  const after = fs.fstatSync(fd, { bigint: true });
  if (!after.isFile() || after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size) refuse();
  return bytes;
}

function readBinding (fs, argv) {
  if (!Array.isArray(argv) || argv.length !== 2 || !/^(?:[3-9]|[1-9][0-9]{1,2})$/.test(argv[1])) refuse();
  const fd = Number(argv[1]);
  if (fd > FD_MAX) refuse();
  const stat = fs.fstatSync(fd, { bigint: true });
  if (!stat.isFile() || stat.size < 1n || stat.size > BigInt(BINDING_MAX)) refuse();
  const bytes = readExact(fs, fd, Number(stat.size), BINDING_MAX);
  // Round-trip UTF-8 rejects replacement decoding before canonical JSON checks.
  const text = bytes.toString('utf8');
  if (!Buffer.from(text).equals(bytes)) refuse();
  return decodeBinding(text, fd);
}

function verifyInputs (fs, binding) {
  for (const row of [binding.target, binding.cache]) {
    const stat = fs.fstatSync(row.fd, { bigint: true });
    if (!stat.isDirectory() || stat.dev.toString() !== row.device || stat.ino.toString() !== row.inode) refuse();
  }
  readExact(fs, binding.user_config.fd, 0, 0);
  readExact(fs, binding.global_config.fd, 0, 0);
  const pack = readExact(fs, binding.runtime.fd, binding.runtime.size, 64 * 1024 * 1024);
  if (sha256(pack) !== binding.runtime.sha256) refuse();
  const artifacts = binding.artifacts.map(row => {
    const bytes = readExact(fs, row.fd, row.size, 32 * 1024 * 1024);
    if (sha256(bytes) !== row.sha256) refuse();
    return Object.freeze({ fd: row.fd, name: row.package_name, sha256: row.sha256,
      sha512: createHash('sha512').update(bytes).digest('hex') });
  });
  return Object.freeze({ pack, artifacts: Object.freeze(artifacts) });
}

module.exports = { BINDING_MAX, decodeBinding, readBinding, readExact, verifyInputs, operand };
