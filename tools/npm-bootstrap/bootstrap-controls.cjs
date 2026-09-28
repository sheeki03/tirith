'use strict';

// Pure bounded control model. No npm command, package code, native process,
// mount, kernel seal, host mutation or containment qualification occurs here.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { pathToFileURL } = require('node:url');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const { join } = require('node:path');
const { decodeBinding, readBinding, verifyInputs } = require('./bindings.cjs');
const { decodeRuntimePack, NODE_SHA256, NPM_TREE_SHA256 } = require('./runtime-pack.cjs');
const { bindEmptyProjectConfig } = require('./project-config.cjs');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const cases = [];
const check = (name, body) => { body(); cases.push({ name, passed: true }); };
const clone = value => JSON.parse(JSON.stringify(value));

function pack (rows, change = x => x) {
  let offset = 0;
  const entries = rows.map(([path, bytes, executable = false]) => {
    const row = { path, executable, size: bytes.length, sha256: sha(bytes), offset };
    offset += bytes.length;
    return row;
  });
  const manifest = change({ schema_version: 1, node_sha256: NODE_SHA256, npm_tree_sha256: NPM_TREE_SHA256, entries });
  const text = Buffer.from(JSON.stringify(manifest));
  const header = Buffer.alloc(12);
  header.write('TIRNPM01'); header.writeUInt32BE(text.length, 8);
  return Buffer.concat([header, text, ...rows.map(row => row[1])]);
}
const npmPrefix = 'usr/local/lib/node_modules/npm/';
const runtime = pack([
  ['etc/resolv.conf', Buffer.alloc(0)],
  [npmPrefix + 'bin/npm-cli.js', Buffer.from('module.exports = 1;'), true],
  [npmPrefix + 'package.json', Buffer.from('{"name":"npm","version":"11.19.0"}')],
]);
const artifact = Buffer.from('opaque statically reviewed compressed bytes');
const example = () => ({
  schema_version: 1, contract: 'LocalLeafNoScriptsV1',
  runtime: { fd: 19, sha256: sha(runtime), size: runtime.length },
  artifacts: [{ fd: 7, package_name: 'leaf-a', sha256: sha(artifact), size: artifact.length }],
  target: { fd: 255, device: '123', inode: '18446744073709551615' },
  cache: { fd: 6, device: '123', inode: '4294967296' },
  user_config: { fd: 8 }, global_config: { fd: 11 },
});
const parse = value => decodeBinding(JSON.stringify(value), 23);
check('canonical dynamic binding retains exact u64 identities', () => {
  const value = parse(example());
  assert.equal(value.target.inode, '18446744073709551615');
  assert.equal(value.artifacts[0].fd, 7);
  assert(Object.isFrozen(value) && Object.isFrozen(value.artifacts) && Object.isFrozen(value.target));
});
for (const [name, mutate] of [
  ['caller argv extension', x => { x.argv = []; }],
  ['wrong contract', x => { x.contract = 'GenericInstall'; }],
  ['runtime checksum shape', x => { x.runtime.sha256 = 'A'.repeat(64); }],
  ['negative runtime size', x => { x.runtime.size = -1; }],
  ['runtime over limit', x => { x.runtime.size = 64 * 1024 * 1024 + 1; }],
  ['descriptor overlaps record', x => { x.runtime.fd = 23; }],
  ['descriptor overlaps input', x => { x.artifacts[0].fd = 19; }],
  ['stdio descriptor', x => { x.target.fd = 2; }],
  ['descriptor past native cap', x => { x.cache.fd = 256; }],
  ['same config operand', x => { x.global_config.fd = 8; }],
  ['same target and cache identity', x => { x.cache.inode = x.target.inode; }],
  ['noncanonical identity', x => { x.target.device = '0123'; }],
  ['u64 identity overflow', x => { x.target.inode = '18446744073709551616'; }],
  ['unapproved artifact property', x => { x.artifacts[0].sha512 = 'a'.repeat(128); }],
  ['archive over per-input cap', x => { x.artifacts[0].size = 32 * 1024 * 1024 + 1; }],
  ['empty input set', x => { x.artifacts = []; }],
  ['duplicate package name', x => { x.artifacts.push({ ...x.artifacts[0], fd: 9 }); }],
  ['noncanonical package name', x => { x.artifacts[0].package_name = '../leaf'; }],
  ['too many artifacts', x => { x.artifacts = Array.from({ length: 9 }, (_, i) => ({ ...x.artifacts[0], fd: 30 + i, package_name: 'leaf-' + i })); }],
  ['aggregate archive cap', x => { x.artifacts = Array.from({ length: 3 }, (_, i) => ({ ...x.artifacts[0], fd: 30 + i, package_name: 'leaf-' + i, size: 32 * 1024 * 1024 })); }],
]) check(`binding refusal: ${name}`, () => { const value = example(); mutate(value); assert.throws(() => parse(value)); });
check('whitespace duplicate keys and key-order ambiguity refuse', () => {
  const text = JSON.stringify(example());
  for (const value of [' ' + text, text.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
    text.replace('"schema_version":1,"contract":"LocalLeafNoScriptsV1"', '"contract":"LocalLeafNoScriptsV1","schema_version":1')]) {
    assert.throws(() => decodeBinding(value, 23));
  }
});

function memoryFs (value = example()) {
  const files = new Map([[19, runtime], [7, artifact], [8, Buffer.alloc(0)], [11, Buffer.alloc(0)]]);
  files.set(23, Buffer.from(JSON.stringify(value)));
  const reads = [];
  const dirs = new Map([[255, { dev: 123n, ino: 18446744073709551615n }], [6, { dev: 123n, ino: 4294967296n }]]);
  return {
    files, reads, dirs,
    fstatSync (fd) {
      if (dirs.has(fd)) return { ...dirs.get(fd), isFile: () => false, isDirectory: () => true };
      const bytes = files.get(fd); assert(bytes, 'unexpected descriptor');
      return { dev: 77n, ino: BigInt(fd), size: BigInt(bytes.length), isFile: () => true, isDirectory: () => false };
    },
    readSync (fd, buffer, offset, size, position) {
      reads.push({ fd, position });
      assert(Number.isInteger(position));
      // Deliberate short reads exercise cursor-independent exact-byte loops.
      const n = Math.min(size, 7, files.get(fd).length - position);
      files.get(fd).copy(buffer, offset, position, position + n);
      return n;
    },
  };
}
check('positional reads verify inputs and derive SHA512 from actual bytes', () => {
  const fs = memoryFs();
  const binding = readBinding(fs, ['node', '23']);
  const verified = verifyInputs(fs, binding);
  assert(verified.pack.equals(runtime));
  assert.equal(verified.artifacts[0].sha512, crypto.createHash('sha512').update(artifact).digest('hex'));
  assert(fs.reads.every(row => Number.isInteger(row.position)));
  assert(!fs.reads.some(row => row.fd === 8 || row.fd === 11));
});
for (const argv of [['node'], ['node', '23', 'extra'], ['node', '023'], ['node', '2'], ['node', '256'], ['node', '-1']]) {
  check('unbound bootstrap argv refuses', () => assert.throws(() => readBinding(memoryFs(), argv)));
}
for (const [name, change] of [
  ['runtime bytes changed', fs => { fs.files.set(19, Buffer.from(runtime).fill(0, runtime.length - 1)); }],
  ['artifact bytes changed', fs => { fs.files.set(7, Buffer.alloc(artifact.length)); }],
  ['nonempty config', fs => { fs.files.set(8, Buffer.from('ignore-scripts=false')); }],
  ['directory identity changed', fs => { fs.dirs.set(255, { dev: 123n, ino: 99n }); }],
  ['short input EOF', fs => { fs.readSync = () => 0; }],
]) check(`input refusal: ${name}`, () => { const fs = memoryFs(); change(fs); assert.throws(() => verifyInputs(fs, parse(example()))); });

check('full pack validates extras but exposes only npm files', () => {
  const entries = decodeRuntimePack(runtime);
  assert.deepEqual(entries.map(row => row.path), ['bin/npm-cli.js', 'package.json']);
});
const baseRows = [[npmPrefix + 'a.js', Buffer.from('a')]];
for (const [name, transform] of [
  ['wrong runtime pin', x => { x.node_sha256 = 'a'.repeat(64); return x; }],
  ['unknown manifest key', x => { x.extra = 1; return x; }],
  ['unknown entry key', x => { x.entries[0].extra = 1; return x; }],
  ['offset gap', x => { x.entries[0].offset = 1; return x; }],
  ['entry digest drift', x => { x.entries[0].sha256 = 'a'.repeat(64); return x; }],
  ['noninteger entry size', x => { x.entries[0].size = 0.5; return x; }],
  ['path traversal', x => { x.entries[0].path = npmPrefix + '../escape.js'; return x; }],
  ['unadmitted runtime path', x => { x.entries[0].path = 'etc/unapproved'; return x; }],
]) check(`runtime refusal: ${name}`, () => assert.throws(() => decodeRuntimePack(pack(baseRows, transform))));
for (const rows of [
  [[npmPrefix + 'A/x.js', Buffer.from('a')], [npmPrefix + 'a/y.js', Buffer.from('b')]],
  [[npmPrefix + 'A/x.js', Buffer.from('a')], [npmPrefix + 'a', Buffer.from('b')]],
  [[npmPrefix + 'a', Buffer.from('a')], [npmPrefix + 'a/x.js', Buffer.from('b')]],
  [[npmPrefix + 'a.js', Buffer.from('a')], [npmPrefix + 'a.js', Buffer.from('b')]],
]) check('case alias duplicate and directory/file collision refuses', () => assert.throws(() => decodeRuntimePack(pack(rows))));
check('trailing bytes and truncated pack refuse', () => {
  assert.throws(() => decodeRuntimePack(Buffer.concat([runtime, Buffer.from('x')])));
  assert.throws(() => decodeRuntimePack(runtime.subarray(0, runtime.length - 1)));
});

// Execute the actual generated refusal tail with inert private modules. The
// throwing entry replaces npm; no package, VFS mount or child is launched.
const generated = readFileSync(join(__dirname, '../../crates/tirith/src/cli/npm_sealed_bootstrap.cjs'), 'utf8');
const tailStart = generated.indexOf("let bootstrapStage = 'entry';\n");
assert(tailStart > 0);
const refusalTail = generated.slice(tailStart);
function observeRefusal (error, { stage = 'vfs-mount', write, loadFails = false } = {}) {
  const writes = [];
  const state = {};
  let calls = 0;
  const context = {
    bindings: {}, runtimePack: {}, resolver: {}, descriptorBridge: {}, projectConfig: {},
    process: state,
    console: new Proxy({}, { get () { throw new Error('lazy console must not be used'); } }),
    require (name) {
      assert.equal(name, 'node:fs');
      if (loadFails) throw new Error('unavailable diagnostic writer');
      return { writeSync (fd, text) {
        calls++;
        assert.equal(fd, 2);
        assert.equal(typeof text, 'string');
        assert(Buffer.byteLength(text) < 256);
        const count = write ? write(text, calls) : text.length;
        if (Number.isInteger(count) && count > 0) writes.push(text.slice(0, count));
        return count;
      } };
    },
    entry: { runSealedNpm (...args) { args[5](stage); throw error; } },
  };
  runInNewContext(refusalTail, context, { timeout: 500 });
  assert.equal(state.exitCode, 78);
  assert(calls <= 8);
  return { output: writes.join(''), calls };
}
check('generated catch reports static stage and known code without console initialization', () => {
  const error = Object.assign(new TypeError('private path /secret/input'), { code: 'EPERM' });
  const result = observeRefusal(error);
  assert.equal(result.output, 'tirith: sealed npm bootstrap refused its bound inputs (stage=vfs-mount, code=EPERM, name=TypeError, reason=unclassified)\n');
  assert.equal(result.calls, 1);
});
check('generated catch omits arbitrary messages names codes and stage values', () => {
  const result = observeRefusal({ code: '/secret/token', name: '/secret/name', message: '/secret/message', stack: '/secret/stack' }, { stage: '/secret/stage' });
  assert.equal(result.output, 'tirith: sealed npm bootstrap refused its bound inputs (stage=unknown, code=UNKNOWN, name=Error, reason=unclassified)\n');
});
check('generated catch avoids exception getters and tolerates proxy traps or invalid throws', () => {
  let getterCalls = 0;
  const getters = Object.defineProperties({}, {
    code: { get () { getterCalls++; throw new Error('private code'); } },
    name: { get () { getterCalls++; throw new Error('private name'); } },
    message: { get () { getterCalls++; throw new Error('private message'); } },
  });
  for (const error of [getters, null, undefined, 'private thrown string', new Proxy({}, { getOwnPropertyDescriptor () { throw new Error('private proxy'); } })]) {
    const result = observeRefusal(error);
    assert.match(result.output, /code=UNKNOWN, name=Error, reason=unclassified\)\n$/);
    assert.doesNotMatch(result.output, /private/);
  }
  assert.equal(getterCalls, 0);
});
check('generated catch maps only known refusal reasons without path suffixes', () => {
  for (const [message, reason] of [
    ['module parent is outside captured inventory', 'module-parent-outside-inventory'],
    ['module not in captured closure: /secret/package.js', 'module-not-in-inventory'],
    ['package is outside captured closure: @secret/package', 'package-outside-closure'],
    ['runtime is not read-only', 'readonly-check'],
    ['unsupported sealed npm runtime', 'unsupported-runtime'],
  ]) {
    const result = observeRefusal(new Error(message));
    assert(result.output.endsWith(`reason=${reason})\n`));
    assert.doesNotMatch(result.output, /secret/);
  }
});
check('generated catch bounds partial writes and preserves refusal after broken output', () => {
  const error = Object.assign(new Error('private'), { code: 'EBOUNDINPUT' });
  const full = observeRefusal(error).output;
  const short = observeRefusal(error, { write: text => Math.min(32, text.length) });
  assert.equal(short.output, full);
  assert(short.calls > 1);
  const capped = observeRefusal(error, { write: () => 1 });
  assert.equal(capped.calls, 8);
  assert.equal(capped.output, full.slice(0, 8));
  for (const write of [() => 0, () => -1, () => NaN, text => text.length + 1, () => { throw new Error('EPIPE'); }]) {
    assert.equal(observeRefusal(error, { write }).calls, 1);
  }
  assert.equal(observeRefusal(error, { loadFails: true }).calls, 0);
});

(async () => {
  const calls = [];
  const fsPromises = { readFile: async function (file, options) { calls.push({ file, options }); return 'unreviewed physical bytes'; } };
  bindEmptyProjectConfig(fsPromises, '/proc/self/fd/255');
  assert.equal(await fsPromises.readFile('/proc/self/fd/255/.npmrc', 'utf8'), '');
  assert.deepEqual(calls, []);
  cases.push({ name: 'project configuration reads sealed-empty content without physical read', passed: true });
  for (const file of ['/proc/self/fd/255//.npmrc', '/proc/self/fd/255/x/../.npmrc',
    Buffer.from('/proc/self/fd/255/.npmrc'), pathToFileURL('/proc/self/fd/255/.npmrc')]) {
    await assert.rejects(() => fsPromises.readFile(file, 'utf8'));
  }
  for (const options of [undefined, 'ascii', { encoding: 'utf8' }]) {
    await assert.rejects(() => fsPromises.readFile('/proc/self/fd/255/.npmrc', options));
  }
  assert.deepEqual(calls, []);
  cases.push({ name: 'unreviewed project-config alias and read shapes refuse', passed: true });
  for (const file of ['/proc/self/fd/8', '/proc/self/fd/11', '/proc/self/fd/255/package.json', '/tirith-runtime/npm/npmrc']) {
    assert.equal(await fsPromises.readFile(file, 'utf8'), 'unreviewed physical bytes');
  }
  assert.equal(calls.length, 4);
  cases.push({ name: 'user/global descriptor and unrelated reads preserve stock dispatch', passed: true });
  console.log(JSON.stringify({ classification: 'pure_product_bootstrap_controls_no_native_qualification',
    npm_install_executed: false, kernel_seals_checked: false, native_containment_qualified: false, cases }, null, 2));
})().catch(error => { console.error(error); process.exitCode = 1; });
