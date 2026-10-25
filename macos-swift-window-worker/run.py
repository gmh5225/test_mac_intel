"""Public transport harness. Private source/SUTs/streams stay in runner.temp.
Only encrypted evidence and a bounded aggregate are exported.
"""
from pathlib import Path,PurePosixPath
import base64,hashlib,io,json,lzma,os,shutil,subprocess,sys,tarfile,traceback
ROOT=Path(__file__).resolve().parent
CONFIG=json.loads((ROOT/'transport.json').read_bytes())

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def receive(first,count):
 assert 0<=first and 0<count<=8 and first+count<=CONFIG['chunks']
 root=Path(os.environ['RUNNER_TEMP'])/'private-swift-window-worker/chunks';root.mkdir(parents=True,exist_ok=True,mode=0o700)
 for i in range(first,first+count):
  value=os.environ[CONFIG['secret_prefix']+format(i,'03')]
  assert 0<len(value)<=46000
  data=base64.b64decode(value,validate=True);assert data
  f=root/format(i,'03');f.write_text(value);f.chmod(0o600)
 print('Private input batch staged.')

def extract(folder):
 chunks=Path(os.environ['RUNNER_TEMP'])/'private-swift-window-worker/chunks'
 assert {f.name for f in chunks.iterdir()}=={format(i,'03') for i in range(CONFIG['chunks'])}
 data=base64.b64decode(b''.join((chunks/format(i,'03')).read_bytes() for i in range(CONFIG['chunks'])),validate=True)
 assert hashlib.sha256(data).hexdigest()==CONFIG['archive_sha256'] and len(data)==CONFIG['archive_bytes']
 d=lzma.LZMADecompressor(memlimit=256*1024*1024);plain=d.decompress(data,max_length=16*1024*1024)
 assert d.eof and not d.unused_data
 with tarfile.open(fileobj=io.BytesIO(plain),mode='r:') as archive:
  members=archive.getmembers();assert len(members)<=512
  for member in members:
   p=PurePosixPath(member.name);assert member.isreg() and not p.is_absolute() and '..' not in p.parts and 0<member.size<3*1024*1024
   target=folder.joinpath(*p.parts);target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
   with archive.extractfile(member) as src,target.open('xb') as dst:shutil.copyfileobj(src,dst)
   target.chmod(0o600)
 manifest=json.loads((folder/'input-manifest.json').read_bytes())
 for row in manifest['files']:
  f=folder/row['file'];assert f.stat().st_size==row['bytes'] and sha(f)==row['sha256']
 shutil.rmtree(chunks)

def seal(folder,output):
 selected=[]
 for f in folder.rglob('*'):
  if not f.is_file() or f.is_symlink():continue
  rel=f.relative_to(folder);root=rel.parts[0]
  if root in ('results','worker-source-package-v64w7','worker-package-build','geometry-build','build-1','build-2','complete-build-1','complete-build-2','complete-package-build'):
   selected.append(f)
 assert selected and len(selected)<8192 and sum(f.stat().st_size for f in selected)<256*1024*1024
 assert all(f.stat().st_size<32*1024*1024 for f in selected)
 index=folder/'record-index.json';index.write_text(json.dumps({'files':[{'file':f.relative_to(folder).as_posix(),'bytes':f.stat().st_size,'sha256':sha(f)} for f in sorted(selected)]},indent=2)+'\n');selected.append(index)
 archive=folder/'records.tar.gz'
 with tarfile.open(archive,'x:gz') as t:
  for f in sorted(selected):t.add(f,arcname=f.relative_to(folder).as_posix(),recursive=False)
 cert=ROOT.parent/'musl-native-components/private-diagnostics-recipient.pem';assert sha(cert)=='dc19589992ec91dbb66f34435d302a4b14e47d9ccd789c60c75f1894a9a943de'
 openssl=shutil.which('openssl',path='/opt/homebrew/opt/openssl@3/bin:/usr/local/opt/openssl@3/bin:'+os.environ['PATH']);assert openssl
 dest=output/'private-records.cms'
 r=subprocess.run([openssl,'cms','-encrypt','-aes-256-gcm','-binary','-in',str(archive),'-outform','DER','-out',str(dest),'-recip',str(cert),'-keyopt','rsa_padding_mode:oaep'],capture_output=True,timeout=60)
 assert r.returncode==0,'Private result encryption failed; plaintext not exported'
 return {'sha256':sha(dest),'bytes':dest.stat().st_size,'files':len(selected),'algorithm':'CMS AES-256-GCM / RSA-4096 OAEP'}

def diagnose_failed_worker(folder,arch,env):
 executable=folder/'build-1'/('worker-'+arch)
 if not executable.is_file():return
 results=folder/'results'
 command=['xcrun','lldb','--no-lldbinit','--no-use-colors','--batch',
  '-o','settings set target.disable-aslr false','-o','run',
  '-k','thread backtrace all','-k','register read',
  '-k','disassemble --frame --count 64','-k','image list -o -f',
  '--',str(executable),str(folder/'cases.json'),'sequential',str(results/'debugger-lifetime.json')]
 (results/'native-debugger.command.json').write_text(json.dumps(command,indent=2)+'\n')
 diagnostic_env=dict(env,SWIFT_DETERMINISTIC_HASHING='1')
 try:
  with (results/'native-debugger.stdout').open('wb') as o,(results/'native-debugger.stderr').open('wb') as e:
   result=subprocess.run(command,cwd=folder,env=diagnostic_env,stdout=o,stderr=e,timeout=90)
  record={'returncode':result.returncode,'same_source_and_executable':True,'original_host_loads':0}
 except subprocess.TimeoutExpired:
  record={'timeout':True,'same_source_and_executable':True,'original_host_loads':0}
 (results/'native-debugger.exit.json').write_text(json.dumps(record,indent=2)+'\n')

def main(arch):
 folder=Path(os.environ['RUNNER_TEMP'])/'private-swift-window-worker/work';folder.mkdir(parents=True,exist_ok=False,mode=0o700)
 output=Path.cwd()/'swift-window-worker-encrypted-records';output.mkdir(exist_ok=False)
 status='failed';report={}
 try:
  extract(folder);(folder/'results').mkdir()
  env={k:v for k,v in os.environ.items() if not k.startswith('NDC_')}
  with (folder/'results/driver.stdout').open('wb') as o,(folder/'results/driver.stderr').open('wb') as e:
   p=subprocess.run([sys.executable,'-B',str(folder/'actions.py'),arch],cwd=folder,env=env,stdout=o,stderr=e,timeout=5400)
  if p.returncode!=0:diagnose_failed_worker(folder,arch,env)
  if p.returncode==0:
   result=json.loads((folder/'results/acceptance.json').read_bytes())
   assert result['status']=='all_native_composed_worker_records_collected_independent_comparison_pending' and result['arch']==arch
   fields=('recording','arch','machine','source_rebuild_pairs','native_package_rebuild_pairs','accepted_callback_bodies','callbacks_recovered','original_host_loads','full_client_integrated','active_task_termination_covered','full_capture_window_callback_qualified','independent_acceptance_pending','full_worker_qualified','modified_composition_qualified','asynchronous_callbacks_exercised')
   report={k:result[k] for k in fields}
   status='passed'
 except Exception:
  (folder/'results').mkdir(exist_ok=True)
  (folder/'results/harness-error.txt').write_text(traceback.format_exc())
 envelope=seal(folder,output)
 (output/'receipt.json').write_text(json.dumps({'status':status,'aggregate':report,'encrypted_evidence':envelope,'plaintext_uploaded':False,'source_uploaded_publicly':False},indent=2)+'\n')
 print('Native Swift window worker controlled acceptance: '+status)
 return 0 if status=='passed' else 1
if __name__=='__main__':
 if sys.argv[1]=='receive':receive(int(sys.argv[2]),int(sys.argv[3]))
 else:sys.exit(main(sys.argv[1]))
