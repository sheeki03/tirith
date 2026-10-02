'use strict';
// Pure in-memory resolution controls. The small package trees are synthetic;
// no npm command, package code, disk module fallback or native launch runs.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { pathToFileURL, fileURLToPath } = require('node:url');
const { closedResolver } = require('./closed-resolver.cjs');
const root = '/tirith-runtime/npm';
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const entry = (path, text) => {
  const bytes = Buffer.from(typeof text === 'string' ? text : JSON.stringify(text));
  return { path, bytes, sha256: sha(bytes) };
};
const entries = [
  entry('package.json', { name: 'fixture-root' }),
  entry('lib/main.js', '// inert root source'),
  entry('lib/commands/install.js', '// inert command'),
  entry('lib/data.json', { inert: true }),
  entry('lib/native.node', 'not an executable addon'),
  entry('node_modules/conditional/package.json', { name: 'conditional', exports: { '.': { require: './cjs.cjs', import: './esm.mjs' }, './feature/*': './features/*.js' } }),
  entry('node_modules/conditional/cjs.cjs', '// inert CJS'),
  entry('node_modules/conditional/esm.mjs', '// inert ESM'),
  entry('node_modules/conditional/features/x.js', '// inert feature'),
  entry('node_modules/module-scope/package.json', { name: 'module-scope', type: 'module', main: './index.js', imports: { '#inner': { node: './inner.js' } } }),
  entry('node_modules/module-scope/index.js', '// inert ESM scope'),
  entry('node_modules/module-scope/inner.js', '// inert internal import'),
  entry('node_modules/module-scope/forced.cjs', '// inert CJS override'),
  entry('node_modules/array-export/package.json', { name: 'array-export', exports: ['./index.js'] }),
  entry('node_modules/array-export/index.js', '// inert array target'),
  entry('node_modules/outer/package.json', { name: 'outer', main: './index.js' }),
  entry('node_modules/outer/index.js', '// inert outer'),
  entry('node_modules/outer/node_modules/nested/package.json', { name: 'nested', main: './index.js' }),
  entry('node_modules/outer/node_modules/nested/index.js', '// inert nested'),
  entry('node_modules/index-fallback/index.js', '// inert legacy index'),
];
const adapter = closedResolver(entries, root);
const cases = [];
const check = (name, fn) => { fn(); cases.push({ name, passed: true }); };
const url = relative => pathToFileURL(root + '/' + relative).href;
const parent = url('lib/main.js');
function resolves(name, specifier, relative, conditions, expected, format) {
  check(name, () => {
    const value = adapter.resolve(specifier, url(relative), conditions);
    assert.equal(fileURLToPath(value.url), root + '/' + expected);
    assert.equal(value.format, format);
    assert.equal(value.shortCircuit, true);
  });
}
resolves('CJS relative extension', './commands/install', 'lib/main.js', ['node', 'require'], 'lib/commands/install.js', 'commonjs');
resolves('CJS conditional package export', 'conditional', 'lib/main.js', ['node', 'require'], 'node_modules/conditional/cjs.cjs', 'commonjs');
resolves('ESM conditional package export', 'conditional', 'lib/main.js', ['node', 'import'], 'node_modules/conditional/esm.mjs', 'module');
resolves('star package export', 'conditional/feature/x', 'lib/main.js', ['node', 'require'], 'node_modules/conditional/features/x.js', 'commonjs');
resolves('exact internal import', '#inner', 'node_modules/module-scope/index.js', ['node', 'import'], 'node_modules/module-scope/inner.js', 'module');
resolves('CJS extension overrides module scope', './forced.cjs', 'node_modules/module-scope/index.js', ['node', 'require'], 'node_modules/module-scope/forced.cjs', 'commonjs');
resolves('module scope sets JS format', 'module-scope', 'lib/main.js', ['node', 'require'], 'node_modules/module-scope/index.js', 'module');
resolves('array package export', 'array-export', 'lib/main.js', ['node', 'require'], 'node_modules/array-export/index.js', 'commonjs');
resolves('nested dependency stays in inventory', 'nested', 'node_modules/outer/index.js', ['node', 'require'], 'node_modules/outer/node_modules/nested/index.js', 'commonjs');
resolves('bounded legacy index fallback', 'index-fallback', 'lib/main.js', ['node', 'require'], 'node_modules/index-fallback/index.js', 'commonjs');
resolves('JSON format', './data.json', 'lib/main.js', ['node', 'require'], 'lib/data.json', 'json');
for (const [name, specifier] of Object.entries({
  network: 'https://invalid.example/x.js', unknown: 'unbound-package',
  traversal: '../../../../../../outside.js', native: './native.node',
  query: parent + '?changed', fragment: parent + '#changed', absolute: '/outside.js',
  nul: './x\0.js', encoded: 'file://' + root + '/lib%2fmain.js',
})) check('refuse ' + name, () => assert.throws(() => adapter.resolve(specifier, parent)));
check('unbound parent refuses', () => assert.throws(() => adapter.resolve('conditional', 'file:///outside.js')));
check('missing inventory parent refuses', () => assert.throws(() => adapter.resolve('conditional', url('lib/missing.js'))));
check('ESM relative extension fallback refuses', () => assert.throws(() => adapter.resolve('./commands/install', parent, ['node', 'import'])));
check('unexported package path refuses', () => assert.throws(() => adapter.resolve('conditional/package.json', parent), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' }));
check('undefined internal import refuses', () => assert.throws(() => adapter.resolve('#missing', url('node_modules/module-scope/index.js')), { code: 'ERR_PACKAGE_IMPORT_NOT_DEFINED' }));
check('builtin exact delegation', () => assert.equal(adapter.resolve('fs', parent).url, 'node:fs'));
check('load never falls back to disk', () => assert.throws(() => adapter.load(url('lib/missing.js'))));
check('captured and returned buffers cannot mutate admitted source', () => {
  const source = entries.find(row => row.path === 'lib/main.js');
  const original = source.bytes[0];
  source.bytes[0] ^= 1;
  assert.equal(adapter.load(parent).source[0], original);
  source.bytes[0] = original;
  const returned = adapter.load(parent);
  returned.source[0] ^= 1;
  assert.equal(adapter.load(parent).source[0], original);
});
for (const [name, rows] of [
  ['wrong digest', [{ ...entries[0], sha256: '0'.repeat(64) }]],
  ['duplicate file', [entries[0], entries[0]]],
  ['path traversal', [{ ...entries[0], path: '../outside.js' }]],
  ['file-directory collision', [entry('x', 'x'), entry('x/y.js', 'y')]],
  ['entry count bound', Array(4097).fill(entries[0])],
]) check('inventory refusal: ' + name, () => assert.throws(() => closedResolver(rows)));
check('package main cannot escape closure', () => {
  const bad = closedResolver([entry('main.js', ''), entry('node_modules/bad/package.json', { main: '../../../../outside.js' })]);
  assert.throws(() => bad.resolve('bad', url('main.js')));
});
check('conditional export recursion is bounded', () => {
  let target = './index.js';
  for (let i = 0; i < 18; i++) target = { default: target };
  const bad = closedResolver([entry('main.js', ''), entry('node_modules/deep/package.json', { exports: target }), entry('node_modules/deep/index.js', '')]);
  assert.throws(() => bad.resolve('deep', url('main.js')), /conditional export depth/);
});
console.log(JSON.stringify({ classification: 'pure_synthetic_closed_resolver_controls', npm_install_executed: false, native_containment_qualified: false, cases }, null, 2));
