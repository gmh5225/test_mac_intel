'use strict';
const fs = require('node:fs');
const path = require('node:path');

function snapshot(evidence) {
  try {
    const children = fs.readFileSync(path.join(evidence, 'children.json'));
    let registry;
    try {registry = JSON.parse(children.toString('utf8'));}
    catch (error) {if (error instanceof SyntaxError) return {pending: true}; throw error;}
    if (!Array.isArray(registry.process_groups) || registry.process_groups.length !== 1 ||
        !Number.isSafeInteger(registry.process_groups[0]) || registry.process_groups[0] <= 1) {
      throw new Error('upstream native identity is not unique');
    }
    const fd = fs.openSync(path.join(evidence, 'output.log'), fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try {
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || stat.size > 1024 * 1024) throw new Error('unexpected upstream output size');
      const buffer = Buffer.alloc(stat.size);
      const copied = fs.readSync(fd, buffer, 0, buffer.length, 0);
      return {pending: false, children, buffer: buffer.subarray(0, copied),
        native_pid: registry.process_groups[0], output: {size_at_open: stat.size,
          copied_bytes: copied, first_byte: 0, truncated: copied !== stat.size}};
    } finally {fs.closeSync(fd);}
  } catch (error) {
    // execute verifies source/binary before spawning. Registration is a small
    // file written immediately after spawn, so early snapshots may be pending.
    if (error.code === 'ENOENT') return {pending: true};
    throw error;
  }
}
module.exports = {snapshot};
