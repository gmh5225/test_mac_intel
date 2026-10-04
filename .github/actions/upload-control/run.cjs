'use strict';
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {createHash} = require('node:crypto');
const {loadReplay, PAYLOAD_REVISION} = require('./payload.cjs');
const base = process.env.GITHUB_WORKSPACE;
const {commandGroup, finishUpload} = require(path.join(base, 'diagnostics/.github/actions/hvf-intel-recovery/run.cjs'));
const {UPLOAD_REVISION} = require(path.join(base, 'diagnostics/.github/actions/hvf-intel-diagnostic/run.cjs'));

async function main() {
  const selection = process.env.UPLOAD_PAYLOAD || 'synthetic';
  const revision = directory => spawnSync('git', ['-C', directory, 'rev-parse', 'HEAD'],
    {encoding: 'utf8', timeout: 10000});
  const checkouts = [['artifact-uploader', UPLOAD_REVISION],
    ['diagnostics', process.env.DIAGNOSTIC_COMMIT]];
  if (selection !== 'synthetic') checkouts.push(['payloads', PAYLOAD_REVISION]);
  for (const [directory, expected] of checkouts) {
    const result = revision(path.join(base, directory));
    if (result.status !== 0 || result.stdout.trim() !== expected) throw new Error(`unexpected ${directory} revision`);
  }
  const replay = selection === 'synthetic' ? null : loadReplay(path.join(base, 'payloads'), selection);
  const group = commandGroup();
  process.on('SIGTERM', () => group.cancel());
  process.on('SIGINT', () => group.cancel());
  const evidence = path.join(base, 'evidence/upload-control');
  fs.mkdirSync(path.join(evidence, 'uploads'), {recursive: true});
  const save = (file, value) => fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', {flag: 'wx'});
  const macho = spawnSync('/usr/bin/dwarfdump', ['--uuid', process.execPath],
    {encoding: 'utf8', timeout: 10000});
  const uuids = [...(macho.stdout || '').matchAll(/^UUID: ([0-9a-f-]+) \(x86_64\)/gim)];
  if (macho.status !== 0 || uuids.length !== 1) throw new Error('native Intel Node UUID unavailable');
  const manifest = {kind: 'artifact-upload-only-control', native_execution: false,
    workflow_commit: process.env.GITHUB_SHA, diagnostic_commit: process.env.DIAGNOSTIC_COMMIT,
    upload_commit: UPLOAD_REVISION, node_version: process.version, node_executable: process.execPath,
    v8_version: process.versions.v8, node_x86_64_uuid: uuids[0][1].toLowerCase(),
    node_sha256: createHash('sha256').update(fs.readFileSync(process.execPath)).digest('hex'),
    host_architecture: process.arch, image_version: process.env.ImageVersion,
    requested_uploads: 16, completed_uploads: 0,
    payload: replay ? replay.manifest : {kind: 'synthetic', native_execution: false}};
  save(path.join(evidence, 'plan.json'), manifest);
  try {
    for (let index = 0; index < manifest.requested_uploads; ++index) {
      const suffix = `control-${String(index).padStart(3, '0')}`;
      const directory = path.join(evidence, suffix);
      fs.mkdirSync(directory);
      if (replay) {
        // Copy bytes exactly; current control identity stays in plan/result,
        // outside the three-file payload that crashed the earlier uploader.
        for (const [name, raw] of Object.entries(replay.data))
          fs.writeFileSync(path.join(directory, name), raw, {flag: 'wx'});
      } else {
        save(path.join(directory, 'metadata.json'), {...manifest, sequence: index});
        save(path.join(directory, 'children.json'), {native_execution: false, process_groups: []});
        fs.writeFileSync(path.join(directory, 'output-tail.log'),
          Array.from({length: 250}, (_, i) => `Synthetic upload control line ${i}: no native guest execution.\n`).join(''), {flag: 'wx'});
      }
      const operation = group.start(process.execPath,
        [path.join(base, 'artifact-uploader/dist/upload/index.js')], {...process.env,
          INPUT_NAME: `intel-upload-only-attempt-${process.env.GITHUB_RUN_ATTEMPT}-${suffix}`,
          INPUT_PATH: directory, 'INPUT_IF-NO-FILES-FOUND': 'error',
          'INPUT_RETENTION-DAYS': '7', 'INPUT_COMPRESSION-LEVEL': '6', INPUT_OVERWRITE: 'false',
          'INPUT_INCLUDE-HIDDEN-FILES': 'false', INPUT_ARCHIVE: 'true'}, {timeoutMs: 120000});
      await finishUpload(operation, path.join(evidence, 'uploads', suffix + '.json'), suffix);
      ++manifest.completed_uploads;
    }
  } finally {
    save(path.join(evidence, 'result.json'), {...manifest, cancelled: group.signal.aborted});
  }
  if (group.signal.aborted) throw new Error('upload control cancelled');
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
