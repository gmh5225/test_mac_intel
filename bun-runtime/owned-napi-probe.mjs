import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url),probe=require(process.argv[2]);
const values=[];
assert.equal(probe.start(value=>values.push(value)),undefined);
for(let i=0;i<400 && probe.finalizers()!==1;i++)await new Promise(resolve=>setTimeout(resolve,5));
assert.deepStrictEqual(values,[0,1,2]);assert.equal(probe.finalizers(),1);
console.log(JSON.stringify({status:'owned_native_NAPI_loading_pthread_TSFn_and_finalizer_pass',callbacks:3,finalizers:1}));
