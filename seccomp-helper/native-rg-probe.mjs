// Owned experiment: compare plain-path and inherited-FD count reads through
// Bun's synchronous and asynchronous node:child_process implementations.
import { openSync, closeSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
const target = process.argv[2];
if (!target?.startsWith('/runtime/')) throw new Error('owned runtime path required');
const rows = [];
for (const mode of ['sync-path', 'sync-fd3', 'async-path', 'async-fd3']) {
  for (let attempt = 0; attempt < 16; attempt++) {
    const inherited = mode.endsWith('fd3');
    const fd = inherited ? openSync('/work/input.txt', 'r') : null;
    const path = inherited ? '/proc/self/fd/3' : '/work/input.txt';
    const args = ['--no-config', '--hidden', '--max-columns', '500', '-c', '-H', '--null', 'target', path];
    const expected = Buffer.from(path + '\0' + '2\n').toString('hex');
    const options = { argv0: 'rg', stdio: ['pipe', 'pipe', 'pipe', ...(inherited ? [fd] : [])] };
    let result;
    try {
      if (mode.startsWith('sync')) {
        const child = spawnSync(target, args, { ...options, timeout: 5000 });
        result = { code: child.status, signal: child.signal, error: child.error?.message,
          stdout: child.stdout?.toString('hex'), stderr: child.stderr?.toString('hex') };
      } else {
        result = await new Promise(resolve => {
          const child = spawn(target, args, { ...options, timeout: 5000 });
          const stdout = [], stderr = []; let error, exit;
          child.stdout.on('data', b => stdout.push(b));
          child.stderr.on('data', b => stderr.push(b));
          child.on('error', e => { error = e.message; });
          child.on('exit', (code, signal) => { exit = { code, signal, stdoutChunks: stdout.length }; });
          child.on('close', (code, signal) => resolve({ code, signal, error, exit,
            stdout: Buffer.concat(stdout).toString('hex'), stderr: Buffer.concat(stderr).toString('hex') }));
        });
      }
    } finally { if (fd !== null) closeSync(fd); }
    rows.push({ mode, attempt, ...result, pass: result.code === 0 && !result.signal && !result.error && result.stdout === expected && result.stderr === '' });
  }
}
console.log(JSON.stringify({ target, diagnosticOnly: true, rows, failures: rows.filter(r => !r.pass).length }));
