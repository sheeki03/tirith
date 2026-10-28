'use strict';

const path = require('node:path').posix;
const { createHash } = require('node:crypto');
const NODE_SHA256 = '9507fea66ea788dfb2bbef1380ef6ef8940697ef1de15bee62b279e6cfef035c';
const NPM_TREE_SHA256 = '3a34157a11136a4e01f691b297bed524edee9b8cc3bc30e34ad195b17dd8c60e';
const PREFIX = 'usr/local/lib/node_modules/npm/';
const EXTRA_PATHS = new Set([
  'usr/lib/aarch64-linux-gnu/libatomic.so.1', 'usr/lib/aarch64-linux-gnu/libatomic.so.1.2.0',
  'usr/lib/aarch64-linux-gnu/libdl.so.2', 'usr/lib/aarch64-linux-gnu/libm.so.6',
  'usr/lib/aarch64-linux-gnu/libstdc++.so.6', 'usr/lib/aarch64-linux-gnu/libstdc++.so.6.0.30',
  'usr/lib/aarch64-linux-gnu/libgcc_s.so.1', 'usr/lib/aarch64-linux-gnu/libpthread.so.0',
  'usr/lib/aarch64-linux-gnu/libc.so.6', 'usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1',
  'usr/lib/ld-linux-aarch64.so.1', 'etc/ld.so.cache', 'etc/passwd', 'etc/group',
  'etc/nsswitch.conf', 'etc/hosts', 'etc/resolv.conf', 'etc/tirith-empty-openssl.cnf',
]);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const refuse = () => { throw Object.assign(new Error('invalid sealed npm runtime pack'), { code: 'EBOUNDRUNTIME' }); };
const keys = (value, expected) => value !== null && typeof value === 'object' &&
  !Array.isArray(value) && Object.keys(value).join(',') === expected;
const uint = n => Number.isSafeInteger(n) && n >= 0;

function decodeRuntimePack (bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 12 || bytes.length > 64 * 1024 * 1024 ||
      !bytes.subarray(0, 8).equals(Buffer.from('TIRNPM01'))) refuse();
  const length = bytes.readUInt32BE(8);
  if (length > 1024 * 1024 || length > bytes.length - 12) refuse();
  const raw = bytes.subarray(12, 12 + length);
  const text = raw.toString('utf8');
  if (!Buffer.from(text).equals(raw)) refuse();
  const manifest = JSON.parse(text);
  if (JSON.stringify(manifest) !== text ||
      !keys(manifest, 'schema_version,node_sha256,npm_tree_sha256,entries') ||
      manifest.schema_version !== 1 || manifest.node_sha256 !== NODE_SHA256 ||
      manifest.npm_tree_sha256 !== NPM_TREE_SHA256 || !Array.isArray(manifest.entries) ||
      manifest.entries.length < 1 || manifest.entries.length > 4096) refuse();
  const names = new Set();
  const directories = new Map();
  const npm = [];
  let previous = '';
  let offset = 0;
  for (const entry of manifest.entries) {
    if (!keys(entry, 'path,executable,size,sha256,offset') || typeof entry.path !== 'string' ||
        entry.path.length > 4096 || /[^\x20-\x7e]|[\\:]/.test(entry.path) ||
        entry.path.split('/').some(part => !part || part === '.' || part === '..') ||
        entry.path.split('/').length > 72 ||
        !(entry.path.startsWith(PREFIX) && entry.path.length > PREFIX.length || EXTRA_PATHS.has(entry.path)) ||
        typeof entry.executable !== 'boolean' || !uint(entry.size) || entry.size > 8 * 1024 * 1024 ||
        !uint(entry.offset) || entry.offset !== offset || typeof entry.sha256 !== 'string' ||
        !/^[0-9a-f]{64}$/.test(entry.sha256) || entry.path <= previous ||
        entry.size > bytes.length - 12 - length - offset) refuse();
    const name = entry.path.toLowerCase();
    if (names.has(name) || directories.has(name)) refuse();
    for (let parent = path.dirname(entry.path); parent !== '.'; parent = path.dirname(parent)) {
      const folded = parent.toLowerCase();
      if (names.has(folded) || directories.has(folded) && directories.get(folded) !== parent) refuse();
      directories.set(folded, parent);
      if (directories.size > 16384) refuse();
    }
    const content = bytes.subarray(12 + length + offset, 12 + length + offset + entry.size);
    if (sha256(content) !== entry.sha256) refuse();
    if (entry.path.startsWith(PREFIX)) {
      npm.push(Object.freeze({ path: entry.path.slice(PREFIX.length), bytes: content, sha256: entry.sha256 }));
    }
    names.add(name);
    previous = entry.path;
    offset += entry.size;
  }
  if (12 + length + offset !== bytes.length || npm.length === 0) refuse();
  // Non-npm entries were validated but are never mounted or made JS modules.
  // Native code admits exact retained host libraries for this separate mode.
  return Object.freeze(npm);
}

module.exports = { decodeRuntimePack, NODE_SHA256, NPM_TREE_SHA256 };
