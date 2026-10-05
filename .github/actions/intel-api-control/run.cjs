// Pinned NeverD observer helpers are AGPL-3.0-only; the native derivative is BSD-2-Clause.
'use strict';
const fs=require('node:fs');
const path=require('node:path');
const {spawnSync,execFile}=require('node:child_process');
const {observe}=require('./snapshot.cjs');
const root=process.env.GITHUB_WORKSPACE;
const helpers=path.join(root,'diagnostics/.github/actions');
const {commandGroup,finishUpload,uploadInvocation}=require(path.join(helpers,'hvf-intel-recovery/run.cjs'));
const {testEnvironment,captureHostState,UPLOAD_REVISION}=require(path.join(helpers,'hvf-intel-diagnostic/run.cjs'));
const {captureRuntime}=require(path.join(helpers,'hvf-intel-diagnostic/runtime.cjs'));
const {verifyIdentity}=require(path.join(helpers,'hvf-intel-diagnostic/active-sample.cjs'));
const save=(file,value)=>fs.writeFileSync(file,JSON.stringify(value,null,2)+'\n',{flag:'wx'});
async function main() {
  const group=commandGroup();
  process.on('SIGINT',()=>group.cancel()); process.on('SIGTERM',()=>group.cancel());
  const environment=testEnvironment(process.env),uploader=path.join(root,'artifact-uploader');
  const revision=spawnSync('git',['-C',uploader,'rev-parse','HEAD'],{env:environment,encoding:'utf8',timeout:10000});
  if(revision.status!==0||revision.stdout.trim()!==UPLOAD_REVISION) throw new Error('uploader pin mismatch');
  const mode=process.env.INPUT_MODE;
  if(!['vcpu','vm'].includes(mode)) throw new Error('unknown lifecycle mode');
  const evidence=path.join(root,'evidence/api-control'),harness=path.join(root,'harness');
  const helper=path.join(harness,'scripts/intel_api_lifecycle.py');
  const args=['--source',harness,'--diagnostics',path.join(root,'diagnostics'),'--binary',
    path.join(root,'evidence-bin/hvf-intel-real-mode'),'--evidence',evidence,'--mode',mode];
  if(await group.start('python3',[helper,'prepare',...args],environment,{timeoutMs:120000}).completion!==0)
    throw new Error('control preparation failed');
  const plan=JSON.parse(fs.readFileSync(path.join(evidence,'plan.json')));
  const runtime=captureRuntime();
  if(runtime.host_architecture!=='x64') throw new Error('observer must be native x64');
  const invocation=uploadInvocation(path.join(uploader,'dist/upload/index.js'),{...process.env,'INPUT_UPLOAD-RUNTIME':'default'});
  save(path.join(evidence,'observer-runtime.json'),runtime);
  save(path.join(evidence,'uploader-runtime.json'),{...invocation,scope:'independent-api-plan-and-progress-children',runtime});
  save(path.join(evidence,'host-start.json'),await captureHostState(evidence,environment,group.signal));
  fs.mkdirSync(path.join(evidence,'uploads'));
  const attempt=process.env.GITHUB_RUN_ATTEMPT;
  if(!/^[1-9][0-9]*$/.test(attempt||'')) throw new Error('invalid attempt');
  const upload=async(folder,suffix)=>{
    const operation=group.start(invocation.executable,invocation.arguments,{...process.env,
      INPUT_NAME:`intel-api-attempt-${attempt}-${suffix}`,INPUT_PATH:folder,
      'INPUT_IF-NO-FILES-FOUND':'error','INPUT_RETENTION-DAYS':'7','INPUT_COMPRESSION-LEVEL':'6',
      INPUT_OVERWRITE:'false','INPUT_INCLUDE-HIDDEN-FILES':'false',INPUT_ARCHIVE:'true'},{timeoutMs:120000});
    await finishUpload(operation,path.join(evidence,'uploads',`${suffix}.json`),suffix);
  };
  const prepared=path.join(evidence,'prepared');fs.mkdirSync(prepared);
  for(const file of ['plan.json','observer-runtime.json','uploader-runtime.json','host-start.json'])
    fs.copyFileSync(path.join(evidence,file),path.join(prepared,file),fs.constants.COPYFILE_EXCL);
  fs.copyFileSync(path.join(harness,'native/HVFDOS-LICENSE.txt'),path.join(prepared,'HVFDOS-LICENSE.txt'));
  await upload(prepared,'plan');
  // Revalidation/signature checks precede the native 600s budget; reserve 90s
  // for these bounded commands and process-group retirement.
  const operation=group.start('python3',[helper,'execute',...args],environment,{timeoutMs:690000});
  const identity=(pid,parent,binary,signal)=>new Promise(resolve=>{
    execFile('/bin/ps',['-ww','-p',String(pid),'-o','pid=,ppid=,pgid=,comm='],
      {env:environment,signal,encoding:'utf8',timeout:2000,killSignal:'SIGKILL',maxBuffer:4096},
      (error,stdout,stderr)=>resolve({native_pid:pid,python_pid:parent,expected_binary:binary,
        observed_at:new Date().toISOString(),stdout,stderr,status:error?(error.code??null):0,
        verified:!error&&verifyIdentity(stdout,pid,parent,binary)}));
  });
  try {
    const status=await observe(operation,{evidence,plan,identity,signal:group.signal,
      upload:(folder,seq)=>upload(folder,`progress-${String(seq).padStart(3,'0')}`)});
    if(status!==0) throw new Error(`independent native control failed: ${status}`);
  } finally {
    save(path.join(evidence,'controller-status.json'),operation.result);
    save(path.join(evidence,'host-finish.json'),await captureHostState(evidence,environment));
  }
  if(group.signal.aborted) throw new Error('interrupted during final collection');
}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
