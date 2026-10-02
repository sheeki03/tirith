'use strict';
// Resolves only the byte inventory admitted by the sealed runtime decoder.
// This module does not grant native execution or filesystem authority.
const path = require('node:path').posix;
const { createHash } = require('node:crypto');
const { isBuiltin } = require('node:module');
const { pathToFileURL, fileURLToPath } = require('node:url');

function closedResolver(entries, root = '/tirith-runtime/npm') {
  if (!Array.isArray(entries) || entries.length < 1 || entries.length > 4096 ||
      !/^\/[A-Za-z0-9_/-]+$/.test(root) || path.normalize(root) !== root || root === '/') {
    throw new Error('invalid bounded closure');
  }
  const files = new Map();
  const directories = new Set([root]);
  const packages = new Map();
  let total = 0;
  const fail = (message, code = 'MODULE_NOT_FOUND') => {
    throw Object.assign(new Error(message), { code });
  };
  const inside = p => p === root || p.startsWith(root + '/');
  for (const row of entries) {
    if (!row || typeof row.path !== 'string' ||
        !/^[A-Za-z0-9._@+/-]+$/.test(row.path) || row.path.startsWith('/') ||
        row.path.split('/').some(x => !x || x === '.' || x === '..') ||
        !Buffer.isBuffer(row.bytes) || row.bytes.length > 8 * 1024 * 1024 ||
        !/^[a-f0-9]{64}$/.test(row.sha256)) fail('invalid closure entry');
    const p = root + '/' + row.path;
    if (files.has(p) || directories.has(p)) fail('duplicate or colliding closure entry');
    const bytes = Buffer.from(row.bytes);
    if (createHash('sha256').update(bytes).digest('hex') !== row.sha256) fail('closure hash mismatch');
    total += bytes.length;
    if (total > 64 * 1024 * 1024) fail('closure byte limit');
    files.set(p, bytes);
    for (let d = path.dirname(p); inside(d); d = path.dirname(d)) {
      if (files.has(d)) fail('file/directory collision');
      directories.add(d);
      if (directories.size > 16384) fail('closure directory limit');
      if (d === root) break;
    }
  }
  const json = dir => {
    if (packages.has(dir)) return packages.get(dir);
    const b = files.get(dir + '/package.json');
    let value = null;
    if (b) {
      value = JSON.parse(b.toString('utf8'));
      if (!value || typeof value !== 'object' || Array.isArray(value)) fail('invalid package metadata');
    }
    packages.set(dir, value);
    return value;
  };
  const scope = p => {
    for (let d = path.dirname(p); inside(d); d = path.dirname(d)) {
      const pkg = json(d);
      if (pkg) return { dir: d, pkg };
      if (d === root || path.basename(d) === 'node_modules') break;
    }
    return null;
  };
  const requireFile = p => {
    if (!inside(p)) fail('module outside captured closure');
    for (const candidate of [p, p + '.js', p + '.json']) {
      if (files.has(candidate)) return candidate;
    }
    return null;
  };
  const requirePath = p => {
    const direct = requireFile(p);
    if (direct) return direct;
    if (!directories.has(p)) return null;
    const pkg = json(p);
    if (typeof pkg?.main === 'string' && pkg.main) {
      const target = path.resolve(p, pkg.main);
      if (!inside(target)) fail('package main escapes captured closure');
      const main = requireFile(target) || requireFile(path.join(target, 'index'));
      if (main) return main;
    }
    return requireFile(path.join(p, 'index'));
  };
  const exact = p => {
    if (!inside(p) || !files.has(p)) fail('module not in captured closure: ' + p);
    return p;
  };
  const target = (value, dir, conditions, star, depth = 0) => {
    if (depth > 16) fail('conditional export depth');
    if (value === null) return null;
    if (typeof value === 'string') {
      if (!value.startsWith('./') || /[\\%?#\0]/.test(value)) fail('unsupported package target');
      const text = star === undefined ? value : value.replaceAll('*', star);
      if (text.includes('*') || text.split('/').slice(1).some(x => x === '..' || x === 'node_modules')) {
        fail('unsupported package target traversal');
      }
      const p = path.resolve(dir, text);
      if (!p.startsWith(dir + '/')) fail('package target escapes its package');
      return exact(p);
    }
    if (Array.isArray(value)) {
      // Pinned closure arrays use a valid first arm. Do not emulate permissive
      // invalid-target fallback: unsupported arms deliberately refuse.
      for (const v of value) {
        const result = target(v, dir, conditions, star, depth + 1);
        if (result !== undefined) return result;
      }
      return undefined;
    }
    if (value && typeof value === 'object') {
      for (const [condition, v] of Object.entries(value)) {
        if (condition.startsWith('.') || /^\d+$/.test(condition)) fail('unsupported conditional export');
        if (condition === 'default' || conditions.has(condition)) {
          const result = target(v, dir, conditions, star, depth + 1);
          if (result !== undefined) return result;
        }
      }
      return undefined;
    }
    fail('unsupported package target shape');
  };
  const mapped = (map, key, dir, conditions, kind) => {
    if (kind === 'exports' && (typeof map === 'string' || Array.isArray(map) ||
        map === null || Object.keys(map).every(x => !x.startsWith('.')))) {
      if (key !== '.') fail('package subpath is not exported', 'ERR_PACKAGE_PATH_NOT_EXPORTED');
      return target(map, dir, conditions);
    }
    if (!map || typeof map !== 'object' || Array.isArray(map)) fail('unsupported package map');
    if (Object.hasOwn(map, key)) return target(map[key], dir, conditions);
    const patterns = Object.keys(map).filter(x => x.split('*').length === 2)
      .sort((a, b) => b.indexOf('*') - a.indexOf('*') || b.length - a.length);
    for (const pattern of patterns) {
      const [prefix, suffix] = pattern.split('*');
      if (key.startsWith(prefix) && key.endsWith(suffix) && key.length >= prefix.length + suffix.length) {
        return target(map[pattern], dir, conditions, key.slice(prefix.length, key.length - suffix.length));
      }
    }
    fail('package map has no captured target', kind === 'imports' ? 'ERR_PACKAGE_IMPORT_NOT_DEFINED' : 'ERR_PACKAGE_PATH_NOT_EXPORTED');
  };
  const parseURL = value => {
    const u = new URL(value);
    if (u.protocol !== 'file:' || u.host || u.search || u.hash) fail('unsupported module URL');
    const p = fileURLToPath(u);
    if (!inside(p)) fail('module URL outside captured closure');
    return p;
  };
  const resolvePath = (specifier, parent, conditionNames) => {
    if (typeof specifier !== 'string' || specifier.length > 4096 || /[\\\0]/.test(specifier)) fail('invalid module specifier');
    if (isBuiltin(specifier)) return specifier.startsWith('node:') ? specifier : 'node:' + specifier;
    const conditions = new Set(conditionNames);
    const isRequire = conditions.has('require');
    const p = parseURL(parent);
    if (!files.has(p)) fail('module parent is outside captured inventory');
    if (specifier.startsWith('file:')) {
      const requested = parseURL(specifier);
      return isRequire ? requirePath(requested) || fail('missing captured file') : exact(requested);
    }
    if (specifier.startsWith('/') || specifier === '.' || specifier === '..' ||
        specifier.startsWith('./') || specifier.startsWith('../')) {
      const requested = path.resolve(path.dirname(p), specifier);
      return isRequire ? requirePath(requested) || fail('missing captured relative module') : exact(requested);
    }
    if (specifier.startsWith('#')) {
      const s = scope(p);
      if (!s?.pkg.imports) fail('unbound internal import', 'ERR_PACKAGE_IMPORT_NOT_DEFINED');
      return mapped(s.pkg.imports, specifier, s.dir, conditions, 'imports') || fail('disabled internal import');
    }
    if (specifier.includes(':') || specifier.includes('%') || specifier.includes('?')) fail('unsupported bare specifier');
    const parts = specifier.split('/');
    const count = specifier.startsWith('@') ? 2 : 1;
    if (parts.length < count || parts.some(x => !x || x === '.' || x === '..')) fail('invalid package name');
    const name = parts.slice(0, count).join('/');
    const sub = parts.length === count ? '.' : './' + parts.slice(count).join('/');
    const self = scope(p);
    const candidates = [];
    if (self?.pkg.name === name && self.pkg.exports !== undefined) candidates.push(self.dir);
    for (let d = path.dirname(p); inside(d); d = path.dirname(d)) {
      if (path.basename(d) !== 'node_modules') candidates.push(path.join(d, 'node_modules', name));
      if (d === root) break;
    }
    for (const dir of candidates) {
      if (!directories.has(dir)) continue;
      const pkg = json(dir);
      if (pkg?.exports !== undefined) {
        return mapped(pkg.exports, sub, dir, conditions, 'exports') || fail('disabled package export');
      }
      const requested = sub === '.' ? dir : path.join(dir, sub);
      const result = isRequire || sub === '.' ? requirePath(requested) : files.has(requested) ? requested : null;
      if (result) return result;
    }
    fail('package is outside captured closure: ' + name);
  };
  const format = p => {
    if (p.endsWith('.json')) return 'json';
    if (p.endsWith('.cjs')) return 'commonjs';
    if (p.endsWith('.mjs')) return 'module';
    if (p.endsWith('.js')) return scope(p)?.pkg.type === 'module' ? 'module' : 'commonjs';
    fail('unsupported captured module format');
  };
  return Object.freeze({
    resolve(specifier, parentURL, conditions = ['node', 'require']) {
      const p = resolvePath(specifier, parentURL, conditions);
      if (p.startsWith('node:')) return Object.freeze({ url: p, format: 'builtin', shortCircuit: true });
      return Object.freeze({ url: pathToFileURL(p).href, format: format(p), shortCircuit: true });
    },
    load(url) {
      const p = parseURL(url);
      return { format: format(p), source: Buffer.from(files.get(exact(p))), shortCircuit: true };
    },
    root,
  });
}
module.exports = { closedResolver };
