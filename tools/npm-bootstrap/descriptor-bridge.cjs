'use strict'

// Rows are derived from bytes read from retained native-admitted sealed inputs.
// Native descriptor admission, containment and output verification are separate.
const { Buffer } = require('node:buffer')

const refusal = reason => Object.assign(new Error(reason), { code: 'EBOUNDINPUT' })

function descriptorBridge (stockNpa, rows) {
  if (typeof stockNpa !== 'function' || typeof stockNpa.resolve !== 'function' ||
      typeof stockNpa.Result !== 'function' || !Array.isArray(rows) ||
      rows.length < 1 || rows.length > 8) {
    throw refusal('invalid closed descriptor model')
  }
  const bindings = new Map()
  const names = new Set()
  for (const row of rows) {
    if (!row || Object.keys(row).sort().join(',') !== 'fd,name,sha256,sha512' ||
        !Number.isInteger(row.fd) || row.fd < 3 || row.fd > 255 ||
        bindings.has(`/proc/self/fd/${row.fd}`) || typeof row.name !== 'string' ||
        !/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(row.name) ||
        row.name.length > 214 || names.has(row.name) ||
        typeof row.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(row.sha256) ||
        typeof row.sha512 !== 'string' || !/^[0-9a-f]{128}$/.test(row.sha512)) {
      throw refusal('invalid bound descriptor row')
    }
    names.add(row.name)
    const path = `/proc/self/fd/${row.fd}`
    bindings.set(path, Object.freeze({
      path,
      name: row.name,
      sha256Integrity: `sha256-${Buffer.from(row.sha256, 'hex').toString('base64')}`,
      integrity: `sha512-${Buffer.from(row.sha512, 'hex').toString('base64')}`,
    }))
  }

  function adapt (result) {
    // Stock parsing remains authoritative for canonical path and raw spelling.
    // This is the only parser behavior changed by the model.
    if (result instanceof stockNpa.Result && result.type === 'directory' &&
        bindings.has(result.fetchSpec)) {
      result.type = 'file'
    }
    return result
  }
  const npa = (arg, where) => adapt(stockNpa(arg, where))
  npa.resolve = (name, spec, where, arg) => adapt(stockNpa.resolve(name, spec, where, arg))
  npa.Result = stockNpa.Result
  npa.toPurl = stockNpa.toPurl

  function expectedIntegrity (value, bound) {
    const parts = String(value).split(' ')
    return parts.length >= 1 && parts.length <= 2 && new Set(parts).size === parts.length &&
      parts.every(part => part === bound.integrity || part === bound.sha256Integrity)
  }

  function guardFetcher (stockGet) {
    if (typeof stockGet !== 'function') {
      throw refusal('missing stock fetcher')
    }
    return (rawSpec, opts = {}) => {
      const spec = npa(rawSpec, opts.where)
      const bound = bindings.get(spec.fetchSpec)
      if (!(spec instanceof stockNpa.Result) || spec.type !== 'file' || !bound ||
          spec.registry || (spec.name !== undefined && spec.name !== bound.name) ||
          (opts.resolved !== undefined && opts.resolved !== null && opts.resolved !== bound.path && opts.resolved !== `file:${bound.path}`) ||
          (opts.integrity !== undefined && opts.integrity !== null &&
            !expectedIntegrity(opts.integrity, bound))) {
        throw refusal('fetch is outside the exact approved descriptor binding')
      }
      // Native seal/FD identity checks precede the bootstrap.
      return stockGet(spec, {
        ...opts,
        resolved: bound.path,
        integrity: bound.integrity,
        allowRegistry: 'none',
        allowRemote: 'none',
        allowGit: 'none',
        allowDirectory: 'none',
        allowFile: 'all',
      })
    }
  }
  return Object.freeze({ npa, guardFetcher })
}

module.exports = { descriptorBridge }
