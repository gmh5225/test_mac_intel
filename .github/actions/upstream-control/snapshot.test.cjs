'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {snapshot} = require('./snapshot.cjs');

test('startup and partially written registration remain pending without cancelling', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hvf-upstream-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  assert.deepEqual(snapshot(dir), {pending: true});
  fs.writeFileSync(path.join(dir, 'children.json'), '{"process_groups":');
  assert.deepEqual(snapshot(dir), {pending: true});
  fs.writeFileSync(path.join(dir, 'children.json'), '{"process_groups":[123]}');
  assert.deepEqual(snapshot(dir), {pending: true});
  fs.writeFileSync(path.join(dir, 'output.log'), 'guest\r\n');
  const result = snapshot(dir);
  assert.equal(result.pending, false);
  assert.equal(result.native_pid, 123);
  assert.equal(result.buffer.toString(), 'guest\r\n');
  assert.equal(result.output.truncated, false);
});

test('ambiguous native identity and oversized logs cannot become valid snapshots', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hvf-upstream-'));
  t.after(() => fs.rmSync(dir, {recursive: true, force: true}));
  fs.writeFileSync(path.join(dir, 'children.json'), '{"process_groups":[123,124]}');
  assert.throws(() => snapshot(dir), /not unique/);
  fs.writeFileSync(path.join(dir, 'children.json'), '{"process_groups":[123]}');
  fs.writeFileSync(path.join(dir, 'output.log'), Buffer.alloc(1024 * 1024 + 1));
  assert.throws(() => snapshot(dir), /output size/);
});
