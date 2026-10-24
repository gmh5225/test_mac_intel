"""Run the retained exact client oracles against fresh audio-integrated clients."""
from pathlib import Path
import argparse,hashlib,json,sys,traceback,os
sys.dont_write_bytecode=True
sys.path.insert(0,'/recipes/musl-native-components')
from client_root import Harness,elf_abi
from client_tools import accept as accept_tools
def sha(p):return hashlib.file_digest(p.open('rb'),'sha256').hexdigest()
"""Add exact public GLIBC loader files and an owned dynamic GLIBC control."""
import re,subprocess,struct
class GnuHarness(Harness):
 def __init__(self,arch,sdk_package,private):
  super().__init__(arch,sdk_package,private)
  triplet={'arm64':'aarch64-linux-gnu','x64':'x86_64-linux-gnu'}[arch]
  interp={'arm64':'/lib/ld-linux-aarch64.so.1','x64':'/lib64/ld-linux-x86-64.so.2'}[arch]
  closure=[]
  for name in ['libc.so.6','libm.so.6','libpthread.so.0','libdl.so.2','librt.so.1','libstdc++.so.6','libgcc_s.so.1','libresolv.so.2']:
   p=Path('/lib')/triplet/name;assert p.is_file();destination='/lib/'+triplet+'/'+name
   present=self.root/destination.lstrip('/')
   if present.exists():assert present.is_file() and sha(present)==sha(p)
   else:self.copy_public(p,destination)
   closure.append(dict(destination=destination,sha256=sha(p)))
  present=self.root/interp.lstrip('/')
  if present.exists():assert present.is_file() and sha(present)==sha(Path(interp))
  else:self.copy_public(Path(interp),interp)
  target=self.inputs/'GNU-client-boundary'
  self.run('compile-owned-GNU-client-boundary',['gcc','-O2','-fPIE','-pie','-Wall','-Wextra','-Werror','/recipes/musl-native-components/client-boundary.c','-o',target]);target.chmod(0o500);self.copy_public(target,'/runtime/GNU-client-boundary')
  self.receipt['GNU_public_runtime']=dict(interpreter=interp,closure=closure,owned_control_ABI=gnu_abi(arch,target))
 def qualify(self,label):
  proof=super().qualify(label)
  spec=dict(kind='tool_then_text',tool=dict(name='Read',input=dict(file_path='/work/input.txt')),text='fixture-complete')
  result,_=self.execute(label+'-GNU-ABI',['/runtime/GNU-client-boundary'],spec)
  assert result['exit_code']==0 and not result['stderr'];value=json.loads(result['stdout'])
  assert value==dict(outside_errno=2,readonly_errno=30,network_result=-1,network_errno=101,uid=os.getuid(),no_new_privs=1)
  self.receipt.setdefault('GNU_boundary_controls',[]).append(dict(label=label,observation=value))
  return dict(base=proof,GNU_control=value)
def gnu_abi(arch,path):
 with path.open('rb') as stream:header=stream.read(64)
 assert header[:7]==b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H',header,18)[0]=={'arm64':183,'x64':62}[arch]
 needed=re.findall(r'\(NEEDED\).*\[([^\]]+)\]',subprocess.check_output(['readelf','-dW',path],text=True))
 interpreter=re.findall(r'Requesting program interpreter: ([^\]]+)',subprocess.check_output(['readelf','-lW',path],text=True))
 allowed={'libc.so.6','libm.so.6','libpthread.so.0','libdl.so.2','librt.so.1','libstdc++.so.6','libgcc_s.so.1','libresolv.so.2','ld-linux-aarch64.so.1','ld-linux-x86-64.so.2'}
 assert set(needed)<=allowed and 'libc.so.6' in needed
 assert interpreter==[{'arm64':'/lib/ld-linux-aarch64.so.1','x64':'/lib64/ld-linux-x86-64.so.2'}[arch]]
 return dict(needed=needed,interpreter=interpreter[0])
Harness=GnuHarness

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
  expected=json.loads(Path('/recipes/seccomp-helper/original-pins.json').read_text())[a.arch]
  assert sha(original)==expected['sha256'] and original.stat().st_size==expected['bytes']
  receipt['GNU_client_ABIs']={label:gnu_abi(a.arch,binary) for label,binary in [('original',original),*clients.items()]}
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
   receipt.update(status='both_audio_integrated_GNU_clients_26_builtin_search_pairs_passed',differential_pairs=26,Grep_Glob_pairs=26,version_observations=3,actual_Bash_sandbox_accepted=False,full_client_runtime_accepted=False,scope='builtin-search-only',reason='Translated x64 environment rejected the original client seccomp call; full Bash acceptance is pending a qualified system boundary.')
   return
  receipt['tools']=accept_tools(execute,original,clients,harness.logs,{})
  assert len(receipt['tools']['differential_pairs'])==14 and all(r['equal'] for r in receipt['tools']['differential_pairs'])
  assert len(receipt['tools']['native_search']['differential_pairs'])==26 and all(r['equal'] for r in receipt['tools']['native_search']['differential_pairs'])
  for pin in pins:assert sha(Path('/inputs')/pin['name'])==pin['sha256']
  import time
  retirement=[];deadline=time.monotonic()+2
  while True:
   snapshot=cgroup_snapshot()
   process_states=[]
   for entry in sorted(Path('/proc').iterdir()):
    if entry.name.isdecimal():
     try:
      fields=(entry/'stat').read_text().split(') ',1)[1].split()
      process_states.append(dict(pid=int(entry.name),state=fields[0],parent=int(fields[1])))
     except (OSError,IndexError):pass
   retirement.append(dict(cgroup=snapshot,process_states=process_states))
   if snapshot['pids.current']=='2':break
   assert time.monotonic()<deadline,'Owned init did not finish retirement within 2s'
   time.sleep(.01)
  assert snapshot['pids.events']=='max 0'and'oom_kill 0'in snapshot['memory.events']
  receipt['final_retirement_barrier']=dict(deadline_seconds=2,snapshots=retirement,final=snapshot,all_children_absent=True)
  receipt.update(status='both_audio_integrated_GNU_clients_40_actual_tool_pairs_passed',full_client_runtime_accepted=True,
   differential_pairs=40,Bash_pairs=14,Grep_Glob_pairs=26,version_observations=3,actual_Bash_sandbox_enabled=True,
   source_engine_NAPI_fix_admitted=True,original_descriptor_provider_preserved=True,independent_helper_controls_reused_only_for_identical_engine_bytes=True)
 except BaseException as error:
  receipt.update(status='failed_not_admitted',error_type=type(error).__name__,private_error=str(error),private_traceback=traceback.format_exc());raise
 finally:
  if harness is not None:receipt['owned_harness']=harness.receipt
  (private/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
  print(json.dumps({k:v for k,v in receipt.items() if k in ['status','arch','differential_pairs','error_type','full_client_runtime_accepted']}),flush=True)
if __name__=='__main__':main()
