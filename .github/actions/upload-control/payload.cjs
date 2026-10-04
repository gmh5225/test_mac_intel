'use strict';
const fs = require('node:fs');
const path = require('node:path');
const {createHash} = require('node:crypto');

// These are immutable historical snapshots. Their contents must not be treated
// as evidence that a guest ran during this upload-only control.
const PAYLOAD_REVISION = 'e02e8c6c6861e7cc6919fda1209333a885c1ce25';
const SNAPSHOTS = {
  'owner-macos-15': {run: '37198629082', snapshot: 'progress-000'},
  'owner-macos-26': {run: '37198630903', snapshot: 'progress-005'},
};
const FILES = ['metadata.json', 'children.json', 'output-tail.log'];

function loadReplay(root, selection) {
  const source = SNAPSHOTS[selection];
  if (!Object.hasOwn(SNAPSHOTS, selection)) throw new Error('unknown historical snapshot');
  const directory = path.join(root, 'results/2026-10-04-boundaries', source.run);
  const inventory = JSON.parse(fs.readFileSync(path.join(directory, 'files.json'), 'utf8'));
  const data = {};
  const files = {};
  for (const name of FILES) {
    const relative = `${source.snapshot}/${name}`;
    const expected = inventory[relative];
    const raw = fs.readFileSync(path.join(directory, relative));
    const digest = createHash('sha256').update(raw).digest('hex');
    if (!expected || !/^[0-9a-f]{64}$/.test(expected.sha256) || digest !== expected.sha256)
      throw new Error(`historical snapshot hash mismatch: ${name}`);
    data[name] = raw;
    files[name] = {sha256: digest, bytes: raw.length, source_path: relative};
  }
  return {data, manifest: {kind: 'historical-snapshot-replay', native_execution: false,
    source_commit: PAYLOAD_REVISION, source_run: source.run,
    source_snapshot: source.snapshot, selection, files}};
}

module.exports = {loadReplay, PAYLOAD_REVISION};
