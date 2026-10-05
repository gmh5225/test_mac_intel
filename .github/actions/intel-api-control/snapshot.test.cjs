'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {snapshot,observe,LIMIT,MAX_PROGRESS}=require('./snapshot.cjs');
function fixture(t,output='') {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'hvf-api-observer-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  fs.writeFileSync(path.join(dir,'children.json'),JSON.stringify({process_groups:[700]}));
  fs.writeFileSync(path.join(dir,'output.log'),output);
  return dir;
}
function operation() {
  let resolve;const completion=new Promise(done=>resolve=done);
  const result={completion,child:{pid:600},cancellations:[],resolve,
    cancel(reason){this.cancellations.push(reason);resolve(143);}};
  return result;
}
const identity=async()=>({verified:true});
const plan={command:['/native'],workflow_commit:'source',helper_commit:'helper'};
test('pending registry, terminated records and independent kind',t=>{
  const dir=fixture(t,'{"event":"iteration_begin","iteration":26}\n{"event":"iteration_complete","iteration":25}\n{"event":"iteration_complete","iteration":26}');
  const state=snapshot(dir);
  assert.equal(state.progress.last_completed_in_window,25);
  assert.equal(state.progress.last_started_in_window,26);
  assert.equal(state.output.first_byte,0);
  fs.writeFileSync(path.join(dir,'children.json'),'{');assert.equal(snapshot(dir).pending,true);
});
test('bounded byte windows survive output above the old one-megabyte limit',t=>{
  const line=JSON.stringify({event:'padding',bytes:'x'.repeat(4000)})+'\n';
  const output=line.repeat(Math.ceil((LIMIT+10000)/line.length))+'{"event":"iteration_complete","iteration":25}\n';
  const dir=fixture(t,output),state=snapshot(dir);
  assert.equal(state.output.copied_bytes,LIMIT);
  assert.equal(state.output.first_byte,Buffer.byteLength(output)-LIMIT);
  assert.equal(state.buffer.equals(Buffer.from(output).subarray(-LIMIT)),true);
  assert.equal(state.progress.last_completed_in_window,25);
});
test('non-unique identity and symlink log are errors',t=>{
  const dir=fixture(t,'');fs.writeFileSync(path.join(dir,'children.json'),'{"process_groups":[7,8]}');
  assert.throws(()=>snapshot(dir),/unique/);
  fs.writeFileSync(path.join(dir,'children.json'),'{"process_groups":[7]}');
  fs.renameSync(path.join(dir,'output.log'),path.join(dir,'real.log'));
  fs.symlinkSync('real.log',path.join(dir,'output.log'));
  assert.throws(()=>snapshot(dir));
});
test('registration and each 25 rounds seal immutable observations',async t=>{
  const dir=fixture(t,'{"event":"iteration_begin","iteration":1}\n');
  const op=operation(),abort=new AbortController(),uploads=[];
  const status=await observe(op,{evidence:dir,plan,identity,signal:abort.signal,pollMs:1,
    upload:async(folder,seq)=>{
      const data=fs.readFileSync(path.join(folder,'output-tail.log'));
      uploads.push(JSON.parse(fs.readFileSync(path.join(folder,'metadata.json'))));
      assert.equal(uploads.at(-1).complete_native_acceptance,false);
      if(seq===0) fs.appendFileSync(path.join(dir,'output.log'),'{"event":"iteration_complete","iteration":25}\n');
      else op.resolve(0);
      assert.equal(data.equals(fs.readFileSync(path.join(folder,'output-tail.log'))),true);
    }});
  assert.equal(status,0);assert.deepEqual(uploads.map(x=>x.reason),['registered','progress']);
  assert.equal(MAX_PROGRESS,64);
});
test('upload failure cancels native and waits for retirement',async t=>{
  const dir=fixture(t,'{"event":"iteration_begin","iteration":1}\n'),op=operation();
  await assert.rejects(observe(op,{evidence:dir,plan,identity,signal:new AbortController().signal,pollMs:1,
    upload:async()=>{throw new Error('upload failed');}}),/upload failed/);
  assert.deepEqual(op.cancellations,['evidence-failure']);
});
test('cancellation retires child and cannot become success',async t=>{
  const dir=fixture(t,''),op=operation(),abort=new AbortController();
  await assert.rejects(observe(op,{evidence:dir,plan,identity,signal:abort.signal,pollMs:1,
    upload:async()=>abort.abort()}),/interrupted/);
  assert.equal(op.cancellations.includes('observer-cancelled'),true);
});
test('an upload already in flight is awaited after native completion',async t=>{
  const dir=fixture(t,''),op=operation();let uploadComplete=false;
  const status=await observe(op,{evidence:dir,plan,identity,signal:new AbortController().signal,pollMs:1,
    upload:async()=>{op.resolve(0);await new Promise(r=>setTimeout(r,20));uploadComplete=true;}});
  assert.equal(status,0);assert.equal(uploadComplete,true);
});
