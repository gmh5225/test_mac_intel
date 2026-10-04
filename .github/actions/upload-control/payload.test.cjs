'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {test} = require('node:test');
const {loadReplay, PAYLOAD_REVISION} = require('./payload.cjs');
const root = path.resolve(__dirname, '../../..');

for (const [selection, run, snapshot] of [
  ['owner-macos-15', '37198629082', 'progress-000'],
  ['owner-macos-26', '37198630903', 'progress-005'],
]) {
  test(`${selection}: replay exact immutable bytes and reject tampering`, () => {
    const replay = loadReplay(root, selection);
    assert.equal(replay.manifest.native_execution, false);
    assert.equal(replay.manifest.source_commit, PAYLOAD_REVISION);
    assert.equal(replay.manifest.source_run, run);
    assert.equal(replay.manifest.source_snapshot, snapshot);
    assert.deepEqual(Object.keys(replay.data).sort(), ['children.json', 'metadata.json', 'output-tail.log']);
    for (const [name, raw] of Object.entries(replay.data))
      assert.deepEqual(raw, fs.readFileSync(path.join(root, 'results/2026-10-04-boundaries', run, snapshot, name)));
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'hvf-upload-replay-'));
    try {
      const original = path.join(root, 'results/2026-10-04-boundaries', run);
      const copy = path.join(temporary, 'results/2026-10-04-boundaries', run);
      fs.mkdirSync(copy, {recursive: true});
      fs.copyFileSync(path.join(original, 'files.json'), path.join(copy, 'files.json'));
      fs.cpSync(path.join(original, snapshot), path.join(copy, snapshot), {recursive: true});
      fs.appendFileSync(path.join(copy, snapshot, 'output-tail.log'), '\nmodified\n');
      assert.throws(() => loadReplay(temporary, selection), /hash mismatch/);
      fs.unlinkSync(path.join(copy, snapshot, 'metadata.json'));
      assert.throws(() => loadReplay(temporary, selection), /ENOENT/);
    } finally {
      fs.rmSync(temporary, {recursive: true, force: true});
    }
  });
}

test('arbitrary paths and inherited object keys are rejected', () => {
  for (const selection of ['../', 'constructor', '__proto__', 'synthetic', ''])
    assert.throws(() => loadReplay(root, selection), /unknown historical snapshot/);
});
