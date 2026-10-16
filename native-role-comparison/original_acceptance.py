"""Compare standalone public Ugrep/Bfs only after authored Docker controls."""
from pathlib import Path
import argparse,base64,bz2,gzip,hashlib,json,os,platform,selectors,shutil,signal,subprocess,tarfile,time,urllib.request
ROOT=Path(__file__).resolve().parent

def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def differences(original,candidate,expected):
    result=[]
    if original['exit_code']!=expected or candidate['exit_code']!=expected:result.append('exit status')
    for field in ['stdout','stderr']:
        if original[field]!=candidate[field]:result.append(field)
    return result

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--arch',required=True,choices=['x64','arm64']);ap.add_argument('--package',required=True,type=Path);ap.add_argument('--output',required=True,type=Path);a=ap.parse_args()
    assert platform.system()=='Linux' and {'x86_64':'x64','aarch64':'arm64'}[platform.machine()]==a.arch and os.getuid()!=0
    pins=json.loads((ROOT/'accepted-candidates.json').read_bytes());pin=pins['profiles'][a.arch];package=a.package.resolve()
    assert sha(package/'MANIFEST.json')==pin['manifest_sha256'] and not any(p.is_symlink() for p in package.rglob('*'))
    seen=set()
    for row in json.loads((package/'MANIFEST.json').read_bytes())['files']:
        rel=Path(row['file']);assert not rel.is_absolute() and '..' not in rel.parts and row['file'] not in seen;seen.add(row['file']);p=package/rel
        assert p.is_file() and p.stat().st_size==row['bytes'] and sha(p)==row['sha256']
    assert seen|{'MANIFEST.json'}=={p.relative_to(package).as_posix() for p in package.rglob('*') if p.is_file()}
    out=a.output.resolve();out.mkdir();logs=out/'diagnostics';logs.mkdir();inputs=out/'inputs';inputs.mkdir();empty=out/'empty';empty.mkdir()
    fixtures=out/'fixtures';fixtures.mkdir();(fixtures/'nested').mkdir()
    text=b'first\nNEEDLE\npreneedle\n';(fixtures/'input.txt').write_bytes(text);(fixtures/'猫.txt').write_text('first\n🐈\n');(fixtures/'nested/child.txt').write_text('nested NEEDLE\n');(fixtures/'link.txt').symlink_to('input.txt')
    for suffix,raw in [('gz',gzip.compress(text,mtime=0)),('bz2',bz2.compress(text)),('zst',bytes.fromhex('28b52ffd0458b9000066697273740a4e4545444c450a7072656e6565646c650a2c682895')),('br',bytes.fromhex('0f0b8066697273740a4e4545444c450a7072656e6565646c650a03'))]:
        (fixtures/('input.'+suffix)).write_bytes(raw)
    receipt=dict(status='started',arch=a.arch,boundary_qualified=False,captured_client_executed=False,captured_source_uploaded=False,client_uploaded=False,controls=[],cases=[],runtime_image=pin['runtime_image'],candidate_manifest_sha256=sha(package/'MANIFEST.json'),normalization='none; exact exit status and stdout/stderr bytes')
    canary=out/'outside-canary';canary.write_bytes(b'owned outside fixture\n')
    def host(label,command):
        r=subprocess.run(list(map(str,command)),capture_output=True,timeout=180)
        (logs/(label+'.stdout')).write_bytes(r.stdout);(logs/(label+'.stderr')).write_bytes(r.stderr);assert r.returncode==0,label
    def execute(label,target,actual,args,expected_failure=None):
        state=out/(label+'-state');state.mkdir();(state/'home').mkdir();(state/'work').mkdir();name='neverd-extra-'+a.arch+'-'+label
        command=['docker','run','--rm','--name',name,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--user',f'{os.getuid()}:{os.getgid()}','--cpus','2','--memory','512m','--pids-limit','64','--ulimit','core=0:0','--ulimit','fsize=262144:262144','--ulimit','nofile=256:256','--ulimit','cpu=20:20','--tmpfs','/tmp:rw,nosuid,nodev,size=32m','--workdir','/work','--env','BOUNDARY_OUTSIDE='+str(canary)]
        for source,dest in [(empty,'/bin'),(empty,'/sbin'),(empty,'/usr/bin'),(empty,'/usr/sbin'),(empty,'/usr/local/bin'),(empty,'/usr/local/sbin'),(target,'/runtime/target'),(inputs/'transport','/runtime/transport'),(inputs/'transport','/runtime/receiver'),(fixtures,'/fixtures')]:
            command+=['--mount',f'type=bind,src={source},dst={dest},readonly']
        for source,dest in [(state/'home','/home/test'),(state/'work','/work')]:command+=['--mount',f'type=bind,src={source},dst={dest}']
        command+=['--entrypoint','/runtime/transport',pin['runtime_image'],'/runtime/target',actual,*args]
        (logs/(label+'.command.json')).write_text(json.dumps(command,indent=2)+'\n')
        process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        selector=selectors.DefaultSelector();streams={'stdout':bytearray(),'stderr':bytearray()};failure=None
        for key,stream in [('stdout',process.stdout),('stderr',process.stderr)]:os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,key)
        deadline=time.monotonic()+30
        try:
            while selector.get_map():
                if time.monotonic()>deadline:failure='wall timeout';break
                for event,mask in selector.select(.1):
                    raw=os.read(event.fileobj.fileno(),65536)
                    if not raw:selector.unregister(event.fileobj);continue
                    result=streams[event.data]
                    if len(result)+len(raw)>262144:result.extend(raw[:262144-len(result)]);failure='output limit';break
                    result.extend(raw)
                if failure:break
            if failure:
                subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=15)
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
            code=process.wait(timeout=10)
        finally:
            selector.close()
            if process.poll() is None:
                subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=15)
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                process.wait(timeout=10)
            for key,raw in streams.items():(logs/(label+'.'+key)).write_bytes(raw)
        assert failure==expected_failure,label+': '+str(failure)
        return dict(exit_code=code,stdout=bytes(streams['stdout']),stderr=bytes(streams['stderr']))
    try:
        for name in ['original_acceptance.py','role-transport.c','accepted-candidates.json']:shutil.copyfile(ROOT/name,logs/name)
        shutil.copyfile(ROOT.parent/'seccomp-helper/boundary-control.c',logs/'boundary-control.c')
        host('runtime-pull',['docker','pull',pin['runtime_image']]);host('runtime-inspect',['docker','image','inspect',pin['runtime_image']])
        for name,source,static in [('transport',ROOT/'role-transport.c',True),('boundary-static',ROOT.parent/'seccomp-helper/boundary-control.c',True),('boundary-dynamic',ROOT.parent/'seccomp-helper/boundary-control.c',False)]:
            host('compile-'+name,['cc',*(['-static'] if static else []),'-O2','-Wall','-Wextra','-Werror',source,'-o',inputs/name]);(inputs/name).chmod(0o500)
        receipt['authored_binaries']={name:sha(inputs/name) for name in ['transport','boundary-static','boundary-dynamic']}
        for name in ['boundary-static','boundary-dynamic']:
            r=execute(name,inputs/name,'authored-boundary',[])
            assert r['exit_code']==0 and not r['stderr'] and json.loads(r['stdout'])==dict(outside_errno=2,readonly_errno=30,shell_result=-1,shell_errno=2,network_result=-1,network_errno=101,uid=os.getuid())
            assert (out/(name+'-state/work/allowed')).read_bytes()==b'owned fixture\n';receipt['controls'].append(dict(case=name,passed=True))
        for index,actual in enumerate(['ugrep','bfs','/fixture/猫']):
            args=['--transport-control','a b','quote"slash\\','🐈',''];r=execute('transport-'+str(index),inputs/'transport',actual,args)
            expected=''.join(v.encode().hex()+'\n' for v in [actual,*args])+'ARGV0=<unset>\n'
            assert r['exit_code']==0 and r['stdout']==expected.encode() and not r['stderr'];receipt['controls'].append(dict(case='transport-'+str(index),passed=True))
        r=execute('output-limit',inputs/'transport','authored-flood',['--flood-control'],expected_failure='output limit')
        assert len(r['stdout'])==262144
        receipt['controls'].append(dict(case='output-limit',passed=True,retained_stdout_bytes=262144))
        receipt['boundary_qualified']=True
        (logs/'qualified-before-original.json').write_text(json.dumps(receipt,indent=2)+'\n')
        original_pin=json.loads((ROOT.parent/'seccomp-helper/original-pins.json').read_bytes())[a.arch];archive=inputs/'published-input.tgz';digest=hashlib.sha512();size=0
        with urllib.request.urlopen(original_pin['url'],timeout=90) as response,archive.open('xb') as dest:
            while raw:=response.read(1048576):size+=len(raw);assert size<134217728;digest.update(raw);dest.write(raw)
        assert base64.b64encode(digest.digest()).decode()==original_pin['integrity']
        original=inputs/'original-copy'
        with tarfile.open(archive,'r:gz') as tar:
            members=[m for m in tar.getmembers() if m.name=='package/claude' and m.isfile()];assert len(members)==1 and members[0].size==original_pin['bytes']
            with tar.extractfile(members[0]) as source,original.open('xb') as dest:shutil.copyfileobj(source,dest)
        assert sha(original)==original_pin['sha256'];original.chmod(0o500)
        candidates={}
        for role in ['ugrep','bfs']:
            assert sha(package/role)==pin['binaries'][role]['sha256']
            candidate=inputs/role;shutil.copyfile(package/role,candidate);candidate.chmod(0o500);candidates[role]=candidate
        cases=[('UG-version','ugrep',['--version'],0),('UG-literal','ugrep',['--no-config','-n','NEEDLE','/fixtures/input.txt'],0),('UG-absent','ugrep',['--no-config','absent-value','/fixtures/input.txt'],1),('UG-invalid','ugrep',['--no-config','[','/fixtures/input.txt'],2),('UG-pcre','ugrep',['--no-config','-P','-o','(?<=pre)needle','/fixtures/input.txt'],0),('UG-unicode','ugrep',['--no-config','-n','🐈','/fixtures/猫.txt'],0)]
        cases += [('UG-'+s,'ugrep',['--no-config','-z','-n','NEEDLE','/fixtures/input.'+s],0) for s in ['gz','bz2','zst','br']]
        cases += [('BF-version','bfs',['--version'],0),('BF-name','bfs',['-s','/fixtures','-maxdepth','1','-type','f','-name','*.txt','-printf','%f\n'],0),('BF-depth','bfs',['-s','/fixtures','-mindepth','2','-maxdepth','2','-type','f','-printf','%P\n'],0),('BF-regex','bfs',['-s','/fixtures','-maxdepth','1','-regex','.*input[.]txt','-printf','%f\n'],0),('BF-link','bfs',['-L','-s','/fixtures/link.txt','-type','f','-printf','%f\n'],0),('BF-exec','bfs',['/fixtures/input.txt','-exec','/runtime/receiver','--env-control',';'],0),('BF-absent','bfs',['-s','/fixtures','-name','absent-value','-print'],0),('BF-missing-user','bfs',['/fixtures','-maxdepth','0','-user','neverd_missing_public_fixture_user_21296'],1)]
        for label,role,args,expected in cases:
            candidate=candidates[role];assert sha(candidate)==pin['binaries'][role]['sha256']
            left=execute('original-'+label,original,role,args);right=execute('candidate-'+label,candidate,role,args)
            if left['exit_code']!=126:receipt['captured_client_executed']=True
            mismatch=differences(left,right,expected)
            receipt['cases'].append(dict(case=label,role=role,expected_exit_code=expected,original_exit_code=left['exit_code'],candidate_exit_code=right['exit_code'],matches=not mismatch,differences=mismatch,original_stdout_sha256=hashlib.sha256(left['stdout']).hexdigest(),candidate_stdout_sha256=hashlib.sha256(right['stdout']).hexdigest(),original_stderr_sha256=hashlib.sha256(left['stderr']).hexdigest(),candidate_stderr_sha256=hashlib.sha256(right['stderr']).hexdigest()))
        assert sha(original)==original_pin['sha256']
        receipt['mismatches']=[row['case'] for row in receipt['cases'] if not row['matches']]
        assert not receipt['mismatches'],'Exact mismatches: '+', '.join(receipt['mismatches'])
        receipt.update(status='original_and_source_component_cases_match_exactly',differential_pairs=len(cases),original=original_pin,scope='Bounded standalone Ugrep/Bfs correspondence, with actual argv[0] role selection in the original. No static engine integration, portability-floor or exact transitive-version claim.')
    except BaseException as error:receipt.update(status='failed',error_type=type(error).__name__,error=str(error));raise
    finally:(logs/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
if __name__=='__main__':main()
