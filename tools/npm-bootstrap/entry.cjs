'use strict';

// The bundler supplies these private modules as lexical values. No external
// path, caller-supplied source, npm configuration or module fallback is loaded.
function runSealedNpm (bindings, runtimePack, resolver, descriptorBridge, projectConfig, setStage) {
  setStage('runtime');
  const fs = require('node:fs');
  const fsPromises = require('node:fs/promises');
  const moduleApi = require('node:module');
  const path = require('node:path').posix;
  const vfs = require('node:vfs');
  if (process.version !== 'v26.7.0' || process.platform !== 'linux' || process.arch !== 'arm64') {
    throw new Error('unsupported sealed npm runtime');
  }
  setStage('binding');
  const binding = bindings.readBinding(fs, process.argv);
  setStage('inputs');
  const verified = bindings.verifyInputs(fs, binding);
  setStage('pack');
  const entries = runtimePack.decodeRuntimePack(verified.pack);
  const root = '/tirith-runtime/npm';
  setStage('resolver');
  const adapter = resolver.closedResolver(entries, root);
  setStage('vfs-create');
  const memory = vfs.create({ emitExperimentalWarning: false });
  setStage('vfs-populate');
  for (const row of entries) {
    const file = '/' + row.path;
    memory.mkdirSync(path.dirname(file), { recursive: true });
    memory.writeFileSync(file, row.bytes);
  }
  setStage('vfs-readonly');
  memory.provider.setReadOnly();
  setStage('vfs-mount');
  memory.mount(root);
  if (memory.readonly !== true) throw new Error('runtime is not read-only');
  setStage('module-hooks');
  moduleApi.registerHooks({
    resolve (specifier, context, nextResolve) {
      if (moduleApi.isBuiltin(specifier)) return nextResolve(specifier, context);
      return adapter.resolve(specifier, context.parentURL, context.conditions);
    },
    load (url, context, nextLoad) {
      if (url.startsWith('node:')) return nextLoad(url, context);
      return adapter.load(url);
    },
  });

  const target = bindings.operand(binding.target.fd);
  const cache = bindings.operand(binding.cache.fd);
  // Native code already verified both config descriptors are sealed empty
  // bytes. Distinct operands preserve npm's per-source uniqueness invariant.
  setStage('project-config');
  projectConfig.bindEmptyProjectConfig(fsPromises, target);
  const entry = root + '/bin/npm-cli.js';
  setStage('npm-argument');
  const req = moduleApi.createRequire(entry);
  const npaPath = req.resolve('npm-package-arg');
  const stockNpa = req('npm-package-arg');
  setStage('descriptor-bridge');
  const bridge = descriptorBridge.descriptorBridge(stockNpa, verified.artifacts);
  if (req.cache[npaPath]?.exports !== stockNpa) throw new Error('npm argument module changed');
  req.cache[npaPath].exports = bridge.npa;
  setStage('npm-fetcher');
  const fetcher = req('pacote/lib/fetcher.js');
  if (req.cache[req.resolve('pacote')] !== undefined) throw new Error('npm fetcher loaded before binding');
  fetcher.get = bridge.guardFetcher(fetcher.get);
  process.argv = [process.execPath, entry, 'install',
    '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--no-update-notifier',
    '--bin-links=false', '--package-lock=false', '--no-save', '--omit=dev', '--workspaces=false',
    '--allow-directory=none', '--allow-git=none', '--allow-remote=none', '--allow-file=all',
    `--prefix=${target}`, `--userconfig=${bindings.operand(binding.user_config.fd)}`,
    `--globalconfig=${bindings.operand(binding.global_config.fd)}`, `--cache=${cache}`,
    '--logs-max=0', '--loglevel=error', ...verified.artifacts.map(row => bindings.operand(row.fd))];
  // Stock npm owns normal config loading, command dispatch and exit behavior.
  // Native code independently verifies bytes, metadata and effect boundaries.
  setStage('npm-entry');
  req(entry);
}

module.exports = { runSealedNpm };
