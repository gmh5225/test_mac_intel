"""Build private musl clients using shared typed, source-only graph adapters."""
from pathlib import Path
import argparse,gzip,hashlib,json,os,platform,shutil,struct,subprocess,sys
from sdk import ROOT,profile,sha
from runtime_sdk import prepare as prepare_runtime
from role_process import RoleProcess
from elf_client_layout import core_sections
from runtime_image import select as select_image
sys.path.insert(0,str(ROOT.parent/'seccomp-helper'))
from format_recipe import formatted

RECIPE_SHA256='16a521cc8223f1b6e688bd4ef72b1761dc009931d8a4d9eeb91aae1f05254690'


def rows(path):
 result=[]
 for index,line in enumerate(path.read_text().splitlines()):
  name,loader,encoding,form,side,file,size,digest=line.split('\t')
  result.append(dict(module_index=index,virtual_name=name,loader_id=int(loader),encoding_id=int(encoding),format_id=int(form),side_id=int(side),file=file,bytes=int(size),storage_sha256=digest))
 return result


def build(arch,original,engine,sdk_package,output,logs,workspace=None,*,baseline_control=False,runtime_image=None):
 assert platform.system() in ['Linux','Darwin'] and os.getuid()!=0
 assert {'aarch64':'arm64','arm64':'arm64','x86_64':'x64'}[platform.machine()]==arch,'Only the matching native public compiler is supported'
 docker_arch=json.loads(subprocess.check_output(['docker','info','--format','{{json .Architecture}}']))
 assert docker_arch in {'arm64':['arm64','aarch64'],'x64':['amd64','x86_64']}[arch]
 assert engine.is_file() and not engine.is_symlink()
 if baseline_control:
  pin=json.loads((ROOT.parent/'platform-runtime/musl-baseline-candidates.json').read_bytes())['profiles'][arch]
  assert sha(engine)==pin['binary_sha256'];engine_proof=dict(status='admitted_public_baseline_compiler_control_only',pin=pin,complete_native_source_engine_admitted=False)
 else:
  from source_engine import pin as pin_engine
  engine_proof=pin_engine(arch,engine)
 assert original is not None or workspace is not None
 original_pin=json.loads((ROOT/'original-pins.json').read_bytes())[arch]
 if original is not None:assert original.is_file() and not original.is_symlink() and original.stat().st_size==original_pin['bytes'] and sha(original)==original_pin['sha256']
 if workspace is not None:assert workspace.is_dir() and not any(p.is_symlink() for p in workspace.rglob('*'))
 recipe=ROOT/'musl-readable-recipes-v1.json.gz';assert sha(recipe)==RECIPE_SHA256
 recipes=json.loads(gzip.decompress(recipe.read_bytes()));assert recipes['kind']=='hash_pinned_whitespace_insertion_only' and not recipes['contains_captured_source']
 expected=recipes['profiles'][arch];assert expected['module_count']==2589 and expected['source_count']==2345 and expected['entry_index']==6 and expected['startup_count']==7 and expected['flags']==8191
 output.mkdir();logs.mkdir(exist_ok=True);tools=output/'tools';tools.mkdir()
 compiler=tools/'source-compiler';shutil.copyfile(engine,compiler);compiler.chmod(0o555);assert sha(compiler)==sha(engine)
 image=select_image(arch,runtime_image)
 def compile_tool(label,source,target):
  command=['docker','run','--rm','--log-driver','none','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--user',f'{os.getuid()}:{os.getgid()}','--cpus','2','--memory','1g','--pids-limit','64','--ulimit','core=0:0','--tmpfs','/tmp:rw,nosuid,nodev,size=64m','--mount',f'type=bind,src={ROOT.parent},dst=/recipes,readonly','--mount',f'type=bind,src={tools},dst=/tools','--entrypoint','/usr/bin/'+('cc' if source.suffix=='.c' else 'g++'),image]
  flags=['-static','-O2','-Wall','-Wextra','-Werror']
  if source.suffix=='.cpp':flags=['-std=c++20',*flags]
  else:flags=['-std=c11',*flags]
  command += [*flags,'/recipes/'+source.relative_to(ROOT.parent).as_posix(),*(['-lcrypto','-pthread','-ldl'] if source.suffix=='.cpp' else []),'-o','/tools/'+target.name]
  r=subprocess.run(command,capture_output=True,timeout=180)
  (logs/(label+'.stdout')).write_bytes(r.stdout);(logs/(label+'.stderr')).write_bytes(r.stderr);assert len(r.stdout)<=262144 and len(r.stderr)<=262144 and r.returncode==0,label
  target.chmod(0o555)
 guard=tools/'guard';compile_tool('compile-owned-guard',ROOT/'native-role-guard.c',guard)
 for name in ['extract-linux-graph','raw-graph-linux-adapter','graph-fidelity-linux-adapter']:compile_tool('compile-'+name,ROOT.parent/'seccomp-helper'/(name+'.cpp'),tools/name)
 sdk=output/'runtime-sdk';sdk_proof=prepare_runtime(arch,sdk_package,sdk)
 loader=output/'musl-loader.path';loader.write_text('/recovery-sdk/usr/lib:/recovery-sdk/lib\n')
 inbox=output/'inbox';inbox.mkdir();(inbox/'owned.txt').write_bytes(b'owned role profile\n')
 sentinel=output/'outside-sentinel';sentinel.write_bytes(b'owned compiler host sentinel\n')
 process=RoleProcess(arch,image,guard,sdk,loader,inbox,logs,profile(arch))
 receipt=dict(status='started',arch=arch,native_Docker_CPU=True,runtime_image=image,runtime_image_override_is_diagnostic_only=runtime_image is not None,
  source_engine=engine_proof,baseline_compiler_control_only=baseline_control,SDK=sdk_proof,formatting_recipe_sha256=RECIPE_SHA256,
  original_input_supplied=original is not None,original_executed_during_build=False,original_binary_uploaded=False,captured_source_uploaded=False,clients_uploaded=False,
  compiled_client_flags=4479,original_graph_flags=8191,original_caches_reused=False,original_descriptor_provider_preserved=True,clients={},controls={},actual_client_execution_acceptance=False,goal_complete=False)
 def execute(label,target,args,*,argv0='owned-tool',work=None,project=None,file_bytes=0,wall=120,stream_bytes=262144):
  r=process.execute(label,target,args,argv0=argv0,writable_work=work,project=project,user=f'{os.getuid()}:{os.getgid()}',file_bytes=file_bytes,cpu=120,wall=wall,stream_bytes=stream_bytes,tmp_size='512m')
  assert r['exit_code']==0 and not r['stderr'],label+' failed; inspect private bounded diagnostics'
  return r
 try:
  if original is not None:
   shutil.copyfile(original,inbox/'original')
   execute('extract-original-metadata',tools/'extract-linux-graph',['/input/original',original_pin['sha256'],'/work/extracted'],work=output,file_bytes=512*1024*1024)
   actual=rows(output/'extracted/mapping.tsv')
  else:actual=[dict({k:v for k,v in row.items() if k!='readable_sha256'},file='m'+str(row['module_index'])) for row in expected['rows']]
  assert [{k:v for k,v in row.items() if k!='file'} for row in actual]==[{k:v for k,v in row.items() if k!='readable_sha256'} for row in expected['rows']]
  for layout in ['preserved','readable']:
   work=output/layout;work.mkdir();source=work/'sources';source.mkdir();chosen=[];edits=[]
   if workspace is not None:
    supplied=workspace/layout/'sources';assert {p.name for p in supplied.iterdir()}=={'m'+str(row['module_index']) for row in actual}
    assert all(p.is_file() and not p.is_symlink() for p in supplied.iterdir())
   for row in actual:
    index=row['module_index'];name='m'+str(index);expected_sha=expected['rows'][index].get('readable_sha256') if layout=='readable' and row['loader_id']==1 else row['storage_sha256']
    if workspace is not None:
     file=supplied/name;assert file.stat().st_size<=512*1024*1024;raw=file.read_bytes()
     if hashlib.sha256(raw).hexdigest()!=expected_sha:edits.append(index)
    else:
     raw=(output/'extracted/input'/row['file']).read_bytes();assert hashlib.sha256(raw).hexdigest()==row['storage_sha256']
     if layout=='readable' and row['loader_id']==1:raw=formatted(raw,recipes['recipes'][row['storage_sha256']])
     assert hashlib.sha256(raw).hexdigest()==expected_sha
    (source/name).write_bytes(raw);chosen.append([row['virtual_name'],row['loader_id'],row['encoding_id'],row['format_id'],row['side_id'],name,len(raw),hashlib.sha256(raw).hexdigest()])
   mapping=work/'mapping.tsv';mapping.write_text(''.join('\t'.join(map(str,row))+'\n' for row in chosen))
   # Authored graph tools parse data; captured JavaScript is never evaluated.
   execute(layout+'-stage-raw-assets',tools/'raw-graph-linux-adapter',['stage','/work/mapping.tsv','/work/sources','/work/graph'],work=work,file_bytes=512*1024*1024,stream_bytes=2*1024*1024)
   graph=work/'graph';names=sorted(p.name for p in graph.iterdir());startup=[row['virtual_name'] for row in actual[:7]]
   (graph/'bootstrap.mjs').write_text(''.join('await import(JSON.parse('+json.dumps(json.dumps(name))+'));\n' for name in startup))
   scaffold="import{fileURLToPath}from'node:url';const path=s=>fileURLToPath(new URL(s,import.meta.url));await Bun.build({entrypoints:[path('./bootstrap.mjs')],target:'bun',env:'disable',macros:false,minify:false,compile:{outfile:'/work/client',executablePath:process.execPath,assets:"+json.dumps(names,separators=(',',':'))+".map(s=>path('./'+s))}});\n"
   (graph/'build.isolated.mjs').write_text(scaffold);(graph/'bunfig.toml').write_text('env = false\n');(graph/'tsconfig.json').write_text('{"compilerOptions":{}}\n')
   boundary=execute(layout+'-owned-boundary',None,['--probe',str(sentinel)],work=work,project=graph,file_bytes=512*1024*1024)
   assert json.loads(boundary['stdout'])==dict(readable=1,outside_errno=2,write_errno=30,network_errno=[1,1,1,1],unix_errno=1,shell_exec_refused=True)
   control=execute(layout+'-owned-compiler',compiler,['-e','const fs=require("node:fs");fs.writeFileSync("/work/owned-compiler.txt","owned compiler write");const writable=fs.readFileSync("/work/owned-compiler.txt","utf8")==="owned compiler write";fs.unlinkSync("/work/owned-compiler.txt");console.log(JSON.stringify({arch:process.arch,message:"owned musl source compiler",revision:Bun.revision.slice(0,9),writable}))'],argv0='bun',work=work,project=graph,file_bytes=512*1024*1024)
   assert json.loads(control['stdout'])==dict(arch=arch,message='owned musl source compiler',revision='c6da4a4d3',writable=True)
   receipt['controls'][layout]=dict(boundary=boundary['row'],compiler=control['row'])
   execute(layout+'-compile-private-source',compiler,['--config=/project/bunfig.toml','--tsconfig-override=/project/tsconfig.json','/project/build.isolated.mjs'],argv0='bun',work=work,project=graph,file_bytes=512*1024*1024,wall=180)
   execute(layout+'-restore-typed-graph',tools/'graph-fidelity-linux-adapter',['/work/mapping.tsv','/work/client','/work/client-final',actual[6]['virtual_name'],'7',str(expected['flags']&15),'8'],work=work,file_bytes=512*1024*1024,stream_bytes=2*1024*1024)
   client=work/'client-final';client.chmod(0o555)
   execute(layout+'-readback',tools/'extract-linux-graph',['/work/client-final',sha(client),'/work/readback'],work=work,file_bytes=512*1024*1024)
   rebuilt=rows(work/'readback/mapping.tsv');assert [[r['virtual_name'],r['loader_id'],r['encoding_id'],r['format_id'],r['side_id'],r['bytes'],r['storage_sha256']] for r in rebuilt]==[r[:5]+r[6:] for r in chosen]
   core=core_sections(engine,require_cxx=not baseline_control);assert core_sections(client,require_cxx=not baseline_control)==core
   receipt['clients'][layout]=dict(path=str(client),bytes=client.stat().st_size,sha256=sha(client),all_2589_rows_match_selected_source=True,source_engine_code_and_exception_sections_preserved=core,intentionally_edited_modules=edits)
   if 236 in edits:receipt['original_descriptor_provider_preserved']=False
  receipt['status']='both_musl_private_clients_rebuilt_and_2589_typed_rows_readback_exactly'
  return receipt
 finally:(logs/'native-client-build.json').write_text(json.dumps(receipt,indent=2)+'\n')


if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--arch',required=True,choices=['arm64','x64'])
 for name in ['engine','sdk','output','logs']:p.add_argument('--'+name,required=True,type=Path)
 p.add_argument('--original',type=Path);p.add_argument('--workspace',type=Path);p.add_argument('--runtime-image');p.add_argument('--baseline-compiler-control',action='store_true');a=p.parse_args()
 result=build(a.arch,a.original.resolve() if a.original else None,a.engine.resolve(),a.sdk.resolve(),a.output.resolve(),a.logs.resolve(),a.workspace.resolve() if a.workspace else None,baseline_control=a.baseline_compiler_control,runtime_image=a.runtime_image)
 print(json.dumps(dict(status=result['status'],clients={k:{x:y for x,y in v.items() if x!='source_engine_code_and_exception_sections_preserved'} for k,v in result['clients'].items()},baseline_compiler_control_only=result['baseline_compiler_control_only'])))
