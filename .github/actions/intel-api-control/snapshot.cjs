'use strict';
const fs=require('node:fs');
const path=require('node:path');
const {performance}=require('node:perf_hooks');
const {setTimeout:delay}=require('node:timers/promises');
// The ordinary 1000-round log fits this bounded window; offsets still expose
// any gap under exceptional IRQ volume or long in-flight uploads.
const LIMIT=8*1024*1024, MAX_PROGRESS=64;
const save=(file,value)=>fs.writeFileSync(file,JSON.stringify(value,null,2)+'\n',{flag:'wx'});
function snapshot(evidence) {
  try {
    const children=fs.readFileSync(path.join(evidence,'children.json'));
    let registry;
    try { registry=JSON.parse(children); }
    catch(error) { if(error instanceof SyntaxError) return {pending:true}; throw error; }
    if(!Array.isArray(registry.process_groups)||registry.process_groups.length!==1||
      !Number.isSafeInteger(registry.process_groups[0])||registry.process_groups[0]<=1)
      throw new Error('native process identity is not unique');
    const fd=fs.openSync(path.join(evidence,'output.log'),fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
    try {
      const stat=fs.fstatSync(fd);
      if(!stat.isFile()||stat.size>32*1024*1024) throw new Error('native log exceeded limit');
      const first=Math.max(0,stat.size-LIMIT), buffer=Buffer.alloc(Math.min(stat.size,LIMIT));
      const copied=fs.readSync(fd,buffer,0,buffer.length,first), bytes=buffer.subarray(0,copied);
      const lines=bytes.toString('utf8').split('\n');
      if(first) lines.shift();
      lines.pop(); // only newline-terminated records are observations
      let completed=0,started=0;
      for(const line of lines) {
        const record=JSON.parse(line);
        if(record.event==='iteration_complete'||record.event==='iteration_begin') {
          if(!Number.isSafeInteger(record.iteration)||record.iteration<1||record.iteration>1000)
            throw new Error('invalid observed iteration');
          if(record.event==='iteration_complete') completed=Math.max(completed,record.iteration);
          else started=Math.max(started,record.iteration);
        }
      }
      return {pending:false,children,buffer:bytes,native_pid:registry.process_groups[0],
        output:{size_at_open:stat.size,first_byte:first,copied_bytes:copied,truncated:first!==0},
        progress:{last_completed_in_window:completed,last_started_in_window:started}};
    } finally { fs.closeSync(fd); }
  } catch(error) { if(error.code==='ENOENT') return {pending:true}; throw error; }
}
async function observe(operation,{evidence,plan,upload,identity,signal,pollMs=1000,stallMs=5000}) {
  let running=true;
  const stopped=new AbortController();
  const completion=operation.completion.finally(()=>{running=false;stopped.abort();});
  const abort=()=>{stopped.abort();operation.cancel('observer-cancelled');};
  signal.addEventListener('abort',abort,{once:true});
  if(signal.aborted) abort();
  const observing=(async()=>{
    let sequence=0,uploaded=0,lastCompleted=0,savedBytes=-1,lastAdvance=performance.now(),stalled=false;
    while(running&&!signal.aborted&&sequence<MAX_PROGRESS) {
      const state=snapshot(evidence);
      if(!state.pending) {
        const completed=state.progress.last_completed_in_window;
        if(completed>lastCompleted){lastCompleted=completed;lastAdvance=performance.now();}
        const reason=sequence===0?'registered':completed>=uploaded+25?'progress':
          !stalled&&state.output.size_at_open>savedBytes&&performance.now()-lastAdvance>=stallMs?'stalled':null;
        if(reason) {
          const folder=path.join(evidence,`progress-${String(sequence).padStart(3,'0')}`);
          fs.mkdirSync(folder);
          fs.writeFileSync(path.join(folder,'output-tail.log'),state.buffer,{flag:'wx'});
          fs.writeFileSync(path.join(folder,'children.json'),state.children,{flag:'wx'});
          const nativeIdentity=await identity(state.native_pid,operation.child.pid,plan.command[0],signal);
          save(path.join(folder,'metadata.json'),{kind:'independent-real-mode-partial-progress',
            complete_native_acceptance:false,workflow_commit:plan.workflow_commit,helper_commit:plan.helper_commit,
            captured_at:new Date().toISOString(),reason,sequence,output:state.output,progress:state.progress,
            identity:nativeIdentity,execution_running_at_seal:running,cancelled:signal.aborted});
          if(!running||signal.aborted) break;
          await upload(folder,sequence);
          ++sequence; uploaded=completed; savedBytes=state.output.size_at_open;
          if(reason==='stalled') stalled=true;
          continue;
        }
      }
      await delay(pollMs,undefined,{signal:stopped.signal});
    }
  })().catch(error=>{
    if(error.name==='AbortError'&&!running&&!signal.aborted) return;
    operation.cancel('evidence-failure'); throw error;
  });
  try {
    const [native,observed]=await Promise.allSettled([completion,observing]);
    if(observed.status==='rejected') throw observed.reason;
    if(native.status==='rejected') throw native.reason;
    if(signal.aborted) throw new Error('control interrupted');
    return native.value;
  } finally {signal.removeEventListener('abort',abort);}
}
module.exports={snapshot,observe,LIMIT,MAX_PROGRESS};
