'use strict';
const {observe}=require('./snapshot.cjs');

async function executeObserved(operation,options,liveObserver=observe) {
  const {plan,signal}=options;
  if(plan.observation==='live') return liveObserver(operation,options);
  if(plan.observation!=='final-only') throw new Error('unknown observation mode');
  // No snapshot, identity probe or progress uploader runs in this mode.
  // The same bounded Python controller owns native collection and retirement.
  const abort=()=>operation.cancel('observer-cancelled');
  signal.addEventListener('abort',abort,{once:true});
  if(signal.aborted) abort();
  try {
    const status=await operation.completion;
    if(signal.aborted) throw new Error('control interrupted');
    return status;
  } finally { signal.removeEventListener('abort',abort); }
}
module.exports={executeObserved};
