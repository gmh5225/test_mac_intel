'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {executeObserved}=require('./observation.cjs');
const forbidden=()=>{throw new Error('unexpected live observation');};
function options(signal=new AbortController().signal) {
  return {plan:{observation:'final-only'},signal,upload:forbidden,identity:forbidden};
}
test('live mode delegates the same operation and options',async()=>{
  const operation={},opts={...options(),plan:{observation:'live'}};
  assert.equal(await executeObserved(operation,opts,async(a,b)=>{
    assert.equal(a,operation);assert.equal(b,opts);return 17;
  }),17);
});
test('final-only waits for completion without touching live callbacks',async()=>{
  let resolve;const completion=new Promise(done=>resolve=done);
  let finished=false;
  const result=executeObserved({completion,cancel:forbidden},options(),forbidden).then(value=>{
    finished=true;return value;
  });
  await Promise.resolve();assert.equal(finished,false);resolve(0);
  assert.equal(await result,0);
});
test('nonzero native controller completion is preserved',async()=>{
  assert.equal(await executeObserved({completion:Promise.resolve(1)},options(),forbidden),1);
});
test('rejected completion cannot become success',async()=>{
  await assert.rejects(executeObserved({completion:Promise.reject(new Error('deadline'))},options(),forbidden),/deadline/);
});
test('external cancellation waits for completion and fails even on zero',async()=>{
  let resolve;const completion=new Promise(done=>resolve=done);
  const abort=new AbortController();let cancelled=false,settled=false;
  const result=executeObserved({completion,cancel:reason=>{
    assert.equal(reason,'observer-cancelled');cancelled=true;
  }},options(abort.signal),forbidden).finally(()=>{settled=true;});
  abort.abort();await Promise.resolve();assert.equal(cancelled,true);assert.equal(settled,false);
  resolve(0);await assert.rejects(result,/interrupted/);
});
test('already aborted observation cancels and awaits the operation',async()=>{
  const abort=new AbortController();abort.abort();let calls=0;
  await assert.rejects(executeObserved({completion:Promise.resolve(143),cancel:()=>++calls},
    options(abort.signal),forbidden),/interrupted/);assert.equal(calls,1);
});
test('unknown observation is rejected',async()=>{
  await assert.rejects(executeObserved({}, {...options(),plan:{observation:'invalid'}},forbidden),/unknown/);
});
