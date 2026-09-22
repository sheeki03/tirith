'use strict';

const path = require('node:path').posix;
const { fileURLToPath } = require('node:url');

// npm 11.19.0 Config.loadProjectConfig resolves exactly prefix/.npmrc, then
// #loadFile calls the destructured fs/promises.readFile(file, 'utf8'). Install
// this routing before any npm module is loaded. Keep stock parsing/source flow.
function bindEmptyProjectConfig (fsPromises, targetOperand) {
  if (!/^\/proc\/self\/fd\/(?:[3-9]|[1-9][0-9]{1,2})$/.test(targetOperand) ||
      Number(targetOperand.slice(targetOperand.lastIndexOf('/') + 1)) > 255 ||
      typeof fsPromises.readFile !== 'function') throw new Error('invalid project config binding');
  const expected = path.resolve(targetOperand, '.npmrc');
  const original = fsPromises.readFile;
  fsPromises.readFile = async function (file, options) {
    let candidate = file;
    if (Buffer.isBuffer(file)) candidate = file.toString('utf8');
    else if (file instanceof URL && file.protocol === 'file:') candidate = fileURLToPath(file);
    if (typeof candidate === 'string' && path.isAbsolute(candidate) && path.resolve(candidate) === expected) {
      if (file !== expected || options !== 'utf8') throw new Error('unsupported project config read shape');
      return '';
    }
    return original.call(this, file, options);
  };
}

module.exports = { bindEmptyProjectConfig };
