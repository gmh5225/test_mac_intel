// Uses pinned NeverD diagnostic helpers (AGPL-3.0-only); no upstream VM code copied.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {setTimeout: delay} = require('node:timers/promises');
const {snapshot} = require('./snapshot.cjs');
const root = process.env.GITHUB_WORKSPACE;
const helpers = path.join(root, 'diagnostics/.github/actions');
const {commandGroup, finishUpload} = require(path.join(helpers, 'hvf-intel-recovery/run.cjs'));
const {testEnvironment, captureHostState, UPLOAD_REVISION} = require(path.join(helpers, 'hvf-intel-diagnostic/run.cjs'));
const save = (file, value) => fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', {flag: 'wx'});

async function main() {
  const group = commandGroup();
  process.on('SIGINT', () => group.cancel());
  process.on('SIGTERM', () => group.cancel());
  const environment = testEnvironment(process.env);
  const uploader = path.join(root, 'artifact-uploader');
  const revision = spawnSync('git', ['-C', uploader, 'rev-parse', 'HEAD'], {env: environment, encoding: 'utf8', timeout: 10000});
  if (revision.status !== 0 || revision.stdout.trim() !== UPLOAD_REVISION) throw new Error('uploader revision mismatch');
  const evidence = path.join(root, 'evidence/upstream-control');
  const helper = path.join(root, 'harness/scripts/upstream_hvf_control.py');
  const args = ['--source', path.join(root, 'upstream'), '--diagnostics', path.join(root, 'diagnostics'), '--evidence', evidence];
  if (await group.start('python3', [helper, 'prepare', ...args], environment, {timeoutMs: 90000}).completion !== 0) throw new Error('preparation failed');
  const attempt = process.env.GITHUB_RUN_ATTEMPT;
  if (!/^\d+$/.test(attempt || '')) throw new Error('invalid attempt');
  fs.mkdirSync(path.join(evidence, 'uploads'));
  const upload = async (directory, suffix) => {
    const operation = group.start(process.execPath, [path.join(uploader, 'dist/upload/index.js')], {...process.env,
      INPUT_NAME: `intel-upstream-attempt-${attempt}-${suffix}`, INPUT_PATH: directory,
      'INPUT_IF-NO-FILES-FOUND': 'error', 'INPUT_RETENTION-DAYS': '7', 'INPUT_COMPRESSION-LEVEL': '6',
      INPUT_OVERWRITE: 'false', 'INPUT_INCLUDE-HIDDEN-FILES': 'false', INPUT_ARCHIVE: 'true'}, {timeoutMs: 120000});
    await finishUpload(operation, path.join(evidence, 'uploads', `${suffix}.json`), suffix);
  };
  const prepared = path.join(evidence, 'prepared');
  fs.mkdirSync(prepared);
  fs.copyFileSync(path.join(evidence, 'plan.json'), path.join(prepared, 'plan.json'));
  fs.copyFileSync(path.join(root, 'upstream/LICENSE.txt'), path.join(prepared, 'upstream-LICENSE.txt'));
  save(path.join(prepared, 'host.json'), await captureHostState(evidence, environment, group.signal));
  await upload(prepared, 'plan');
  // Revalidation precedes the native 300-second budget (five bounded git
  // queries plus hashing). Leave room for both that work and child retirement.
  const operation = group.start('python3', [helper, 'execute', ...args], environment, {timeoutMs: 375000});
  let running = true;
  const stopped = new AbortController();
  const completion = operation.completion.finally(() => {running = false; stopped.abort();});
  // Attach a rejection handler before collecting snapshots, which can outlast
  // the child. Native and uploader outcomes stay independently recorded.
  const native = completion.then(value => ({value}), error => ({error}));
  try {
    for (let sequence = 0; running && sequence < 64; ++sequence) {
      try { await delay(5000, undefined, {signal: stopped.signal}); }
      catch (error) { if (!running && error.name === 'AbortError') break; throw error; }
      if (!running || group.signal.aborted) break;
      const directory = path.join(evidence, `progress-${String(sequence).padStart(3, '0')}`);
      fs.mkdirSync(directory);
      const state = snapshot(evidence);
      if (!state.pending) {
        fs.writeFileSync(path.join(directory, 'output-prefix.log'), state.buffer, {flag: 'wx'});
        fs.writeFileSync(path.join(directory, 'children.json'), state.children, {flag: 'wx'});
      }
      save(path.join(directory, 'metadata.json'), {captured_at: new Date().toISOString(),
        registration_pending: state.pending, native_pid: state.native_pid ?? null,
        output: state.output ?? null, controller_pid: operation.child.pid,
        kind: 'independent-upstream-progress', complete_native_acceptance: false,
        host: await captureHostState(evidence, environment, group.signal)});
      if (running && !group.signal.aborted) await upload(directory, `progress-${String(sequence).padStart(3, '0')}`);
    }
    const outcome = await native;
    if (outcome.error) throw outcome.error;
    if (outcome.value !== 0) throw new Error(`upstream native control failed: ${outcome.value}`);
  } catch (error) {
    operation.cancel('upstream-evidence-or-controller-failure');
    await native;
    throw error;
  } finally {
    save(path.join(evidence, 'controller-status.json'), operation.result);
    save(path.join(evidence, 'host-finish.json'), await captureHostState(evidence, environment));
  }
  if (group.signal.aborted) throw new Error('upstream control interrupted during final collection');
}
main().catch(error => {console.error(error.message); process.exitCode = 1;});
