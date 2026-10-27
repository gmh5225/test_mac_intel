"""Run the retained exact client oracles against fresh audio-integrated clients."""
from pathlib import Path
import argparse,hashlib,json,sys,traceback,os
sys.dont_write_bytecode=True
sys.path.insert(0,'/recipes/musl-native-components')
from client_root import Harness,elf_abi
from client_tools import accept as accept_tools
def sha(p):return hashlib.file_digest(p.open('rb'),'sha256').hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--arch',choices=['arm64','x64'],required=True);p.add_argument('--run-label',default='acceptance-v2');p.add_argument('--scope',choices=['full','builtin-search'],default='full');a=p.parse_args()
 assert a.run_label.replace('-','').isalnum()
 private=Path('/work')/a.run_label;private.mkdir();harness=None
 receipt=dict(status='started',arch=a.arch,source_audio_integration=True,original_execution_attempted=False,
  original_executed=False,full_client_runtime_accepted=False,goal_complete=False,
  environment='Linux Docker VM with exact Ubuntu 0.6.1-1ubuntu0.3 bwrap and Python/Debian public root; CPU mode recorded by host',
  prior_native_CI_acceptance_inherited=False,normalizers_modified=False,physical_audio_access=False)
 def cgroup_snapshot():
  result={}
  for name in ['pids.current','pids.max','pids.peak','pids.events','memory.events']:
   try:result[name]=(Path('/sys/fs/cgroup')/name).read_text().strip()
   except OSError as error:result[name]=dict(error=type(error).__name__)
  return result
 receipt['process_budget_observations']=[]
 original_run=Harness.run
 def observed_run(self,label,command,**kwargs):
  row=dict(label=label,before=cgroup_snapshot());receipt['process_budget_observations'].append(row)
  try:return original_run(self,label,command,**kwargs)
  finally:row['after']=cgroup_snapshot()
 Harness.run=observed_run
 try:
  pins=json.loads(Path('/inputs/inputs.json').read_text())
  for pin in pins:
   f=Path('/inputs')/pin['name'];assert f.is_file() and f.stat().st_size==pin['bytes'] and sha(f)==pin['sha256']
  harness=Harness(a.arch,Path('/sdk'),private)
  receipt['initial_owned_boundary']=harness.qualify('initial-owned')
  original=Path('/inputs/original');clients={name:Path('/inputs/client-'+name) for name in ['preserved','readable']}
  receipt['executable_input_modes']={label:oct(binary.stat().st_mode & 0o777) for label,binary in [('original',original),*clients.items()]}
  assert all(binary.stat().st_mode & 0o111 for binary in [original,*clients.values()]),'Staged client inputs must retain executable mode'
  expected=json.loads(Path('/recipes/musl-native-components/original-pins.json').read_text())[a.arch]
  assert sha(original)==expected['sha256'] and original.stat().st_size==expected['bytes']
  receipt['original_ABI']=elf_abi(a.arch,original);assert receipt['original_ABI']==harness.receipt['musl_owned_ABI']['client-boundary']
  spec=dict(kind='tool_then_text',tool=dict(name='Read',input=dict(file_path='/work/input.txt')),text='fixture-complete')
  versions=[]
  for label,binary in [('original',original),*[('client-'+name,b) for name,b in clients.items()]]:
   harness.qualify('before-version-'+label)
   if label=='original':receipt['original_execution_attempted']=True
   result,_=harness.execute('version-'+label,['/runtime/'+label],spec,client={label:binary},arguments=['--version'])
   assert result==dict(exit_code=0,stdout='2.1.296 (Claude Code)\n',stderr='')
   if label=='original':receipt['original_executed']=True
   versions.append(dict(label=label,**result))
  receipt['versions']=versions
  def execute(label,command,spec,**kwargs):
   if (kwargs.get('client')or{}).get('original')is not None:
    harness.qualify('before-'+label);receipt['original_execution_attempted']=True
   return harness.execute(label,command,spec,**kwargs)
  (harness.logs/'source').mkdir()
  if a.scope=='builtin-search':
   from native_search_acceptance import accept_native_search
   receipt['tools']=accept_native_search(execute,original,clients,harness.logs)
   assert len(receipt['tools']['differential_pairs'])==26 and all(r['equal'] for r in receipt['tools']['differential_pairs'])
   for pin in pins:assert sha(Path('/inputs')/pin['name'])==pin['sha256']
   receipt.update(status='both_audio_integrated_musl_clients_26_builtin_search_pairs_passed',differential_pairs=26,Grep_Glob_pairs=26,version_observations=3,actual_Bash_sandbox_accepted=False,full_client_runtime_accepted=False,scope='builtin-search-only',reason='Translated x64 environment rejected the original client seccomp call; full Bash acceptance is pending a qualified system boundary.')
   return
  receipt['tools']=accept_tools(execute,original,clients,harness.logs,{})
  assert len(receipt['tools']['differential_pairs'])==14 and all(r['equal'] for r in receipt['tools']['differential_pairs'])
  assert len(receipt['tools']['native_search']['differential_pairs'])==26 and all(r['equal'] for r in receipt['tools']['native_search']['differential_pairs'])
  for pin in pins:assert sha(Path('/inputs')/pin['name'])==pin['sha256']
  receipt.update(status='both_audio_integrated_musl_clients_40_actual_tool_pairs_passed',full_client_runtime_accepted=True,
   differential_pairs=40,Bash_pairs=14,Grep_Glob_pairs=26,version_observations=3,actual_Bash_sandbox_enabled=True,
   source_engine_and_descriptor_provider_unchanged=True,independent_helper_controls_reused_only_for_identical_engine_bytes=True)
 except BaseException as error:
  receipt.update(status='failed_not_admitted',error_type=type(error).__name__,private_error=str(error),private_traceback=traceback.format_exc());raise
 finally:
  if harness is not None:receipt['owned_harness']=harness.receipt
  (private/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
  print(json.dumps({k:v for k,v in receipt.items() if k in ['status','arch','differential_pairs','error_type','full_client_runtime_accepted']}),flush=True)
if __name__=='__main__':main()
