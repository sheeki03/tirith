'use strict'

// Execute only pinned parser source in a fixed Linux path model. Unused network,
// Git and semver parsing dependencies throw if called. No npm install/fetch,
// artifact open, kernel seal check or containment claim occurs in this fixture.
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const crypto = require('node:crypto')
const { descriptorBridge } = require('./descriptor-bridge.cjs')
const sourceRoot = path.join(__dirname, 'fixtures/npm11.19.0')
const pins = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/npm-source-manifest.json'), 'utf8'))
const usedSources = []
assert.equal(pins.length, 7)
for (const row of pins) {
  assert(/^node_modules\/(npm-package-arg|validate-npm-package-name)\/[A-Za-z0-9._/-]+$/.test(row.path))
  assert(!row.path.split('/').includes('..'))
  const bytes = fs.readFileSync(path.join(sourceRoot, row.path))
  assert.equal(bytes.length, row.bytes)
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), row.sha256)
}
function readPinned (relative) {
  const bytes = fs.readFileSync(path.join(sourceRoot, relative))
  const sha256 = crypto.createHash('sha256').update(bytes).digest('hex')
  assert.equal(sha256, pins.find(row => row.path === relative)?.sha256)
  usedSources.push({ path: relative, sha256 })
  return bytes.toString('utf8')
}
function sourceModule (relative, resolve) {
  const module = { exports: {} }
  vm.runInNewContext(readPinned(relative), {
    module,
    exports: module.exports,
    require: resolve,
    process: Object.freeze({ platform: 'linux', cwd: () => '/tirith/target' }),
    URL,
  }, { filename: relative, timeout: 1000 })
  return module.exports
}
const builtins = JSON.parse(readPinned('node_modules/validate-npm-package-name/lib/builtin-modules.json'))
const validator = sourceModule('node_modules/validate-npm-package-name/lib/index.js', name => {
  assert.equal(name, './builtin-modules.json')
  return builtins
})
let unrelatedDependencyCalls = 0
const unused = new Proxy({}, { get: () => () => {
  unrelatedDependencyCalls++
  throw new Error('fixture attempted an uncharacterized parser dependency')
} })
const stock = sourceModule('node_modules/npm-package-arg/lib/npa.js', name => {
  switch (name) {
    case 'node:url': return require('node:url')
    case 'node:path': return path.posix
    case 'node:os': return { homedir: () => { throw new Error('ambient HOME is outside fixture') } }
    case 'validate-npm-package-name': return validator
    case 'semver':
    case 'hosted-git-info': return unused
    case 'proc-log': return { log: unused }
    default: throw new Error(`unapproved fixture import ${name}`)
  }
})
const rows = [
  { fd: 64, name: 'leaf-a', sha256: '12'.repeat(32), sha512: '34'.repeat(64) },
  { fd: 65, name: '@scope/leaf-b', sha256: 'ab'.repeat(32), sha512: 'cd'.repeat(64) },
]
const bridge = descriptorBridge(stock, rows)
const cases = []
function check (name, body) { body(); cases.push({ name, passed: true }) }
check('stock bare descriptor remains directory', () => {
  assert.equal(stock('/proc/self/fd/64').type, 'directory')
})
check('native-reserved noncontiguous descriptor slots remain exact', () => {
  const dynamic = descriptorBridge(stock, [
    { fd: 7, name: 'leaf-a', sha256: '12'.repeat(32), sha512: '34'.repeat(64) },
    { fd: 255, name: '@scope/leaf-b', sha256: 'ab'.repeat(32), sha512: 'cd'.repeat(64) },
  ])
  const get = dynamic.guardFetcher((spec, opts) => ({ spec, opts }))
  assert.equal(get('/proc/self/fd/7').opts.resolved, '/proc/self/fd/7')
  assert.equal(get('/proc/self/fd/255').opts.resolved, '/proc/self/fd/255')
  assert.throws(() => get('/proc/self/fd/64'), { code: 'EBOUNDINPUT' })
  assert.throws(() => descriptorBridge(stock, [
    { fd: 7, name: 'leaf-a', sha256: '12'.repeat(32), sha512: '34'.repeat(64) },
    { fd: 7, name: 'leaf-b', sha256: 'ab'.repeat(32), sha512: 'cd'.repeat(64) },
  ]), { code: 'EBOUNDINPUT' })
  for (const fd of [0, 1, 2, 256, -1, 3.5, '7']) {
    assert.throws(() => descriptorBridge(stock, [
      { fd, name: 'leaf-a', sha256: '12'.repeat(32), sha512: '34'.repeat(64) },
    ]), { code: 'EBOUNDINPUT' })
  }
})
check('only bound canonical descriptor becomes file', () => {
  assert.equal(bridge.npa('/proc/self/fd/64').type, 'file')
  assert.equal(bridge.npa('/proc/self/fd/66').type, 'directory')
  assert.equal(bridge.npa('/proc/self/fd/64.tgz').fetchSpec, '/proc/self/fd/64.tgz')
})
check('relative Arborist add reparsing retains bound identity', () => {
  const result = bridge.npa('file:../../proc/self/fd/64', '/tirith/target')
  assert.equal(result.type, 'file')
  assert.equal(result.fetchSpec, '/proc/self/fd/64')
  result.name = 'leaf-a'
  const again = bridge.npa(result.toString(), '/tirith/target')
  assert.equal(again.type, 'file')
  assert.equal(again.name, 'leaf-a')
  assert.equal(again.fetchSpec, '/proc/self/fd/64')
})
check('resolve entry point and named scoped references stay bound', () => {
  const result = bridge.npa.resolve('@scope/leaf-b', 'file:/proc/self/fd/65', '/tirith/target')
  assert.equal(result.type, 'file')
  assert.equal(result.name, '@scope/leaf-b')
  assert.equal(bridge.npa(result.toString()).fetchSpec, '/proc/self/fd/65')
})
check('Result reuse and changed-where reparse both retain file type', () => {
  const result = bridge.npa('/proc/self/fd/64', '/tirith/target')
  assert.equal(bridge.npa(result), result)
  assert.equal(bridge.npa(result, '/tirith/other').type, 'file')
})
let fetchCalls = 0
const guarded = bridge.guardFetcher((spec, opts) => { fetchCalls++; return { spec, opts } })
check('fetch gate passes exact bound name and forced digest', () => {
  const value = guarded('leaf-a@file:/proc/self/fd/64', { offline: true, allowRemote: 'all' })
  assert.equal(value.spec.type, 'file')
  assert.equal(value.opts.resolved, '/proc/self/fd/64')
  assert.equal(value.opts.integrity, 'sha512-' + Buffer.from('34'.repeat(64), 'hex').toString('base64'))
  assert.equal(value.opts.offline, true)
  assert.equal(value.opts.allowRemote, 'none')
  assert.equal(value.opts.allowRegistry, 'none')
})
for (const [name, spec, opts] of [
  ['unbound descriptor', '/proc/self/fd/66', {}],
  ['suffix spoof', '/proc/self/fd/64.tgz', {}],
  ['ordinary local archive', '/tirith/changed.tgz', {}],
  ['ordinary directory', '/tirith/unapproved', {}],
  ['different package name', 'other@file:/proc/self/fd/64', {}],
  ['resolved drift', '/proc/self/fd/64', { resolved: '/proc/self/fd/65' }],
  ['integrity drift', '/proc/self/fd/64', { integrity: 'sha256-wrong' }],
  ['query suffix', 'file:/proc/self/fd/64?x.tgz', {}],
  ['fragment suffix', 'file:/proc/self/fd/64#x.tgz', {}],
]) {
  check(`fetch refusal: ${name}`, () => {
    const before = fetchCalls
    assert.throws(() => guarded(spec, opts), { code: 'EBOUNDINPUT' })
    assert.equal(fetchCalls, before)
  })
}
const expected256 = 'sha256-' + Buffer.from('12'.repeat(32), 'hex').toString('base64')
const expected512 = 'sha512-' + Buffer.from('34'.repeat(64), 'hex').toString('base64')
for (const integrity of [expected256, expected512, `${expected256} ${expected512}`, `${expected512} ${expected256}`]) {
  check('exact captured digest set accepts and returns SHA512', () => {
    assert.equal(guarded('/proc/self/fd/64', { resolved: 'file:/proc/self/fd/64', integrity }).opts.integrity, expected512)
  })
}
for (const integrity of [`${expected256} sha512-other`, `${expected512} sha256-other`, `${expected256} ${expected256}`, `${expected512} sha1-other`, `${expected256}  ${expected512}`, `${expected256}\n${expected512}`, `${expected512}?annotation`, '']) {
  check('extra foreign duplicate or malformed digest refuses', () => assert.throws(() => guarded('/proc/self/fd/64', { integrity }), { code: 'EBOUNDINPUT' }))
}
for (const resolved of ['file:/proc/self/fd/65', 'file:///proc/self/fd/64', 'file:/proc/self/fd/64?extra', '/proc/self/fd/064']) {
  check('resolved URI alias or drift refuses', () => assert.throws(() => guarded('/proc/self/fd/64', { resolved }), { code: 'EBOUNDINPUT' }))
}
check('caller rows cannot mutate captured binding', () => {
  rows[0].sha256 = 'ff'.repeat(32)
  rows[0].sha512 = 'ff'.repeat(64)
  assert.equal(guarded('/proc/self/fd/64').opts.integrity,
    'sha512-' + Buffer.from('34'.repeat(64), 'hex').toString('base64'))
})
for (const bad of [[], [{ fd: 63, name: 'leaf-a', sha256: '12'.repeat(32) }],
  [{ fd: 64, name: 'leaf-a', sha256: 'bad' }],
  [{ fd: 64, name: 'leaf-a', sha256: '12'.repeat(32), argv: [] }]]) {
  check('invalid binding model refuses', () => assert.throws(() => descriptorBridge(stock, bad), { code: 'EBOUNDINPUT' }))
}
assert.equal(unrelatedDependencyCalls, 0)
const digest = filename => crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex')
console.log(JSON.stringify({
  classification: 'hermetic_source_model_no_native_qualification',
  actual_node_version: process.version,
  actual_platform: process.platform,
  modeled_npm: '11.19.0',
  modeled_platform: 'linux',
  npm_install_executed: false,
  artifact_bytes_read: false,
  kernel_seals_checked: false,
  native_containment_qualified: false,
  unrelated_dependency_calls: unrelatedDependencyCalls,
  bridge_sha256: digest(path.join(__dirname, 'descriptor-bridge.cjs')),
  controls_sha256: digest(__filename),
  used_sources: usedSources,
  cases,
}, null, 2))
