"""Opaque authenticated transport. No private input or plaintext diagnostics are uploaded."""
from pathlib import Path,PurePosixPath
import hashlib,json,lzma,os,re,shutil,subprocess,sys,tarfile,traceback
ROOT=Path(__file__).resolve().parent
CONFIG=json.loads((ROOT/'transport.json').read_bytes())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def openssl():
 p=shutil.which('openssl',path='/opt/homebrew/opt/openssl@3/bin:/usr/local/opt/openssl@3/bin:'+os.environ['PATH']);assert p;return p

def extract(arch,folder):
 config=CONFIG['inputs'][arch];envelope=folder.parent/'input.cms'
 assert 0<config['envelope_bytes']<256*1024*1024
 with envelope.open('xb') as dst:
  for part in config['parts']:
   assert re.fullmatch(r'input-(arm64|x64)-[0-9a-f]{12}\.cms\.[0-9]{3}',part['file'])
   p=ROOT/part['file'];assert p.is_file() and not p.is_symlink() and p.stat().st_size==part['bytes'] and sha(p)==part['sha256'];dst.write(p.read_bytes())
 assert sha(envelope)==config['envelope_sha256'] and envelope.stat().st_size==config['envelope_bytes']
 key_bytes=os.environ.pop(CONFIG['secret_name']).encode()
 key=folder.parent/'ephemeral-input.key';key.write_bytes(key_bytes);key.chmod(0o600)
 cert=ROOT/'input-recipient.pem';assert sha(cert)==CONFIG['input_certificate_sha256']
 archive=folder.parent/'input.tar.xz'
 try:
  r=subprocess.run([openssl(),'cms','-decrypt','-binary','-inform','DER','-in',str(envelope),'-inkey',str(key),'-recip',str(cert),'-out',str(archive)],capture_output=True,timeout=120)
  assert r.returncode==0,'Private input authentication failed'
 finally:key.unlink(missing_ok=True)
 assert archive.stat().st_size==config['archive_bytes'] and sha(archive)==config['archive_sha256']
 files=0;total=0
 with lzma.open(archive,'rb') as raw:
  with tarfile.open(fileobj=raw,mode='r|') as tar:
   for member in tar:
    files+=1;total+=member.size
    assert files<=20000 and total<=1024*1024*1024 and member.isreg() and 0<=member.size<=192*1024*1024
    rel=PurePosixPath(member.name);assert not rel.is_absolute() and '..' not in rel.parts and rel.parts
    target=folder.joinpath(*rel.parts);target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with tar.extractfile(member) as src,target.open('xb') as dst:shutil.copyfileobj(src,dst)
    target.chmod(0o500 if target.parent.name=='engines' else 0o400)
 assert files==config['input_files'] and sha(folder/'input-manifest.json')==config['input_manifest_sha256']
 manifest=json.loads((folder/'input-manifest.json').read_bytes());names=set()
 for row in manifest['files']:
  rel=PurePosixPath(row['file']);assert not rel.is_absolute() and '..' not in rel.parts
  p=folder.joinpath(*rel.parts);assert p.is_file() and not p.is_symlink() and p.stat().st_size==row['bytes'] and sha(p)==row['sha256'];names.add(row['file'])
 assert names|{'input-manifest.json'}=={p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()}
 if config.get('overlay'):apply_overlay(config['overlay'],folder,key_bytes)
 del key_bytes
 envelope.unlink();archive.unlink()

def apply_overlay(config,folder,key_bytes):
 assert re.fullmatch(r'overlay-(arm64|x64)-[0-9a-f]{12}\.cms',config['file'])
 envelope=ROOT/config['file'];assert envelope.is_file() and not envelope.is_symlink() and envelope.stat().st_size==config['bytes'] and sha(envelope)==config['sha256']
 key=folder.parent/'ephemeral-overlay.key';key.write_bytes(key_bytes);key.chmod(0o600)
 archive=folder.parent/'overlay.tar.xz'
 try:
  r=subprocess.run([openssl(),'cms','-decrypt','-binary','-inform','DER','-in',str(envelope),'-inkey',str(key),'-recip',str(ROOT/'input-recipient.pem'),'-out',str(archive)],capture_output=True,timeout=30)
  assert r.returncode==0,'Authenticated private overlay rejected'
 finally:key.unlink(missing_ok=True)
 assert archive.stat().st_size==config['archive_bytes'] and sha(archive)==config['archive_sha256']
 with lzma.open(archive,'rb') as raw:
  with tarfile.open(fileobj=raw,mode='r:') as tar:
   members=tar.getmembers();assert 1<len(members)<=32 and all(m.isreg() and m.size<=8*1024*1024 for m in members)
   assert sum(m.size for m in members)<=16*1024*1024
   rows=json.loads(tar.extractfile('replacement-index.json').read())['files']
   assert {m.name for m in members}=={'replacement-index.json'}|{r['payload'] for r in rows}
   for row in rows:
    rel=PurePosixPath(row['file']);assert not rel.is_absolute() and '..' not in rel.parts
    p=folder.joinpath(*rel.parts);assert p.is_file() and not p.is_symlink() and sha(p)==row['previous_sha256']
    data=tar.extractfile(row['payload']).read();assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
    p.chmod(0o600);p.write_bytes(data);p.chmod(0o400)
 assert sha(folder/'input-manifest.json')==config['input_manifest_sha256']
 manifest=json.loads((folder/'input-manifest.json').read_bytes())
 for row in manifest['files']:
  p=folder/row['file'];assert p.is_file() and not p.is_symlink() and sha(p)==row['sha256'] and p.stat().st_size==row['bytes']
 archive.unlink()

def collect(folder):
 # Preserve actual deliverables without duplicating identical successful builds.
 products=folder/'products';products.mkdir(exist_ok=True)
 for label in ('build-1','package-build'):
  for name in ('audio-capture.node','computer-use-swift.node','computer-use-input.node','prepare-observed.node'):
   p=folder/label/'native'/name
   if not p.is_file():continue
   existing=products/name
   if existing.exists() and sha(existing)==sha(p):continue
   target=existing if not existing.exists() else products/(label+'-'+name);shutil.copyfile(p,target)
  for layout in ('preserved','readable'):
   p=folder/label/'clients'/layout/'client-final'
   if not p.is_file():continue
   existing=products/('claude-'+layout)
   if existing.exists() and sha(existing)==sha(p):continue
   target=existing if not existing.exists() else products/(label+'-claude-'+layout);shutil.copyfile(p,target)
 selected=[]
 for p in folder.rglob('*'):
  if not p.is_file() or p.is_symlink():continue
  rel=p.relative_to(folder);parts=rel.parts
  include=parts[0] in ('results','products','fresh-source-package')
  if parts[0]=='offline-client-runs' and len(parts)>1 and parts[1]=='private-records':include=True
  if parts[0] in ('build-1','package-build'):
   include=(parts[1]=='rebuild.json' or parts[1]=='client-logs' or parts[1]=='native' and (parts[-1]=='build.json' or len(parts)>2 and parts[2]=='logs') or parts[1]=='clients' and parts[-1]=='mapping.tsv')
  if include:selected.append(p)
 assert selected and len(selected)<=30000 and sum(p.stat().st_size for p in selected)<1536*1024*1024
 assert all(p.stat().st_size<192*1024*1024 for p in selected)
 index=folder/'record-index.json';write(index,dict(files=[dict(file=p.relative_to(folder).as_posix(),bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(selected)]));selected.append(index)
 return selected

def seal(folder,output):
 selected=collect(folder);archive=folder.parent/'private-records.tar.gz'
 with tarfile.open(archive,'x:gz',compresslevel=6) as tar:
  for p in sorted(selected):tar.add(p,arcname=p.relative_to(folder).as_posix(),recursive=False)
 cert=ROOT.parent/'musl-native-components/private-diagnostics-recipient.pem';assert sha(cert)=='dc19589992ec91dbb66f34435d302a4b14e47d9ccd789c60c75f1894a9a943de'
 target=output/'private-records.cms'
 r=subprocess.run([openssl(),'cms','-encrypt','-aes-256-gcm','-binary','-in',str(archive),'-outform','DER','-out',str(target),'-recip',str(cert),'-keyopt','rsa_padding_mode:oaep'],capture_output=True,timeout=120)
 assert r.returncode==0,'Diagnostic encryption failed; plaintext not exported'
 return dict(algorithm='CMS AES-256-GCM / RSA-4096 OAEP',bytes=target.stat().st_size,sha256=sha(target),files=len(selected))

def main(arch):
 assert arch in ('arm64','x64')
 folder=Path(os.environ['RUNNER_TEMP'])/'private-darwin-native-clients/work';folder.mkdir(parents=True,exist_ok=False,mode=0o700)
 results=folder/'results';output=Path.cwd()/'darwin-native-client-encrypted-records';output.mkdir()
 status='failed';aggregate={}
 try:
  extract(arch,folder);results.mkdir()
  env={k:v for k,v in os.environ.items() if not k.startswith('NDC_')}
  with (results/'driver.stdout').open('wb') as o,(results/'driver.stderr').open('wb') as e:
   result=subprocess.run([sys.executable,'-B',str(folder/'actions.py'),arch],cwd=folder,env=env,stdout=o,stderr=e,timeout=5400)
  if result.returncode==0:
   value=json.loads((results/'acceptance.json').read_bytes())
   assert value['status']=='Darwin_full_clients_rebuilt_and_native_evidence_collected_independent_verification_pending' and value['arch']==arch
   aggregate={k:value[k] for k in ('arch','native_host','full_client_layouts','native_addons_built','source_rebuilds','fresh_package_rebuild','original_native_host_loads','independent_acceptance_pending','goal_complete')};status='passed'
 except Exception:
  results.mkdir(exist_ok=True);(results/'harness-error.txt').write_text(traceback.format_exc())
 envelope=seal(folder,output)
 write(output/'receipt.json',dict(status=status,aggregate=aggregate,encrypted_evidence=envelope,plaintext_uploaded=False,source_uploaded_publicly=False))
 print('Darwin source client collection: '+status)
 return 0 if status=='passed' else 1
if __name__=='__main__':sys.exit(main(sys.argv[1]))
