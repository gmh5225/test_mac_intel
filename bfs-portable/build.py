"""Rebuild Bfs with measured original portability flags and a pinned sysroot."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,platform,re,shutil,struct,subprocess,sys,urllib.request
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent/'runtime-helpers'))
from build import unpack
sys.path.insert(0,str(ROOT.parent/'bun-runtime'))
from prepare_sysroot import prepare
IMAGES={'x64':'ghcr.io/oven-sh/bun-development-docker-image@sha256:ee053ca8ff0a00ab51c8572378fb56dee902063d5020b4d90fb78a098fb70af2','arm64':'ghcr.io/oven-sh/bun-development-docker-image@sha256:19e1898469e3ab456b90a4120c1b96644af53c019434c2f9852eb14870e13d11'}
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--arch',required=True,choices=IMAGES);ap.add_argument('--output',required=True,type=Path);a=ap.parse_args()
    assert platform.system()=='Linux' and {'x86_64':'x64','aarch64':'arm64'}[platform.machine()]==a.arch and os.getuid()!=0
    out=a.output.resolve();out.mkdir();logs=out/'diagnostics';logs.mkdir();work=out/'bun';work.mkdir();(work/'embedded').mkdir();(work/'home').mkdir();(work/'no-host-pkgconfig').mkdir()
    inputs=out/'source-inputs';inputs.mkdir();sources=json.loads((ROOT.parent/'extra-components/sources.json').read_bytes())['files'];selected=[p for p in sources if p['name'] in ['bfs','oniguruma']];assert len(selected)==2
    receipt=dict(status='started',arch=a.arch,public_sources_only=True,captured_client_executed=False,exact_original_sysroot_proven=False,original_revision_recovered=False,compiler_image=IMAGES[a.arch],source_inputs=selected,commands=[])
    def run(label,command,timeout=1800):
        receipt['commands'].append(dict(label=label,argv=list(map(str,command))))
        with (logs/(label+'.log')).open('xb') as f:r=subprocess.run(list(map(str,command)),stdout=f,stderr=subprocess.STDOUT,timeout=timeout)
        assert r.returncode==0,label+' failed; inspect retained diagnostics'
    try:
        for pin in selected:
            p=inputs/(pin['name']+'.tar.gz')
            with urllib.request.urlopen(pin['url'],timeout=90) as response:raw=response.read(16777217)
            assert len(raw)<=16777216 and hashlib.sha256(raw).hexdigest()==pin['sha256'] and len(raw)==pin['bytes'];p.write_bytes(raw);unpack(p,work/'embedded'/pin['name'],pin['prefix'])
        prepare(a.arch,out,logs)
        docker_platform={'x64':'linux/amd64','arm64':'linux/arm64'}[a.arch];image=IMAGES[a.arch]
        run('compiler-pull',['docker','pull','--platform',docker_platform,image],900)
        run('compiler-inspect',['docker','image','inspect',image])
        measured_sysroot='/opt/linux-sysroot-glibc'+('-arm64' if a.arch=='arm64' else '')
        run('source-build',['docker','run','--rm','--platform',docker_platform,'--network','none','--cap-drop','ALL','--security-opt','no-new-privileges','--user',f'{os.getuid()}:{os.getgid()}','--cpus','2','--memory','4g','--pids-limit','256','--mount',f'type=bind,src={work},dst=/tmpfs/bun','--mount',f'type=bind,src={out/"sysroot"},dst={measured_sysroot},readonly','--mount',f'type=bind,src={ROOT},dst=/recipes,readonly','--env','RECOVERY_ARCH='+a.arch,'--entrypoint','/bin/bash',image,'/recipes/build-bfs.sh'])
        binary=work/'embedded/bfs/bin/bfs';assert binary.is_file();raw=binary.read_bytes();assert raw[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',raw,18)[0]=={'x64':62,'arm64':183}[a.arch]
        # Retain the public candidate even when its measured ABI floor refuses it.
        shutil.copyfile(binary,logs/'public-bfs-candidate')
        run('version-needs',['readelf','--version-info',binary]);run('dynamic-symbols',['readelf','--dyn-syms','--wide',binary])
        versions={tuple(map(int,v.split('.'))) for v in re.findall(r'GLIBC_([0-9]+(?:\.[0-9]+)+)',(logs/'version-needs.log').read_text())};assert versions
        receipt['maximum_glibc_requirement']='.'.join(map(str,max(versions)))
        assert max(versions)<=(2,17),'Bfs exceeds the original engine glibc floor'
        version=subprocess.check_output([binary,'--version'],timeout=10);(logs/'bfs-version.stdout').write_bytes(version);assert version.startswith(b'bfs 4.1.1\n')
        fixture=out/'fixture';fixture.mkdir();(fixture/'input.txt').write_text('owned fixture\n')
        controls=[]
        for label,args,code,text in [('name',[str(fixture),'-name','*.txt','-printf','%f\n'],0,b'input.txt\n'),('missing-user',[str(fixture),'-maxdepth','0','-user','neverd_missing_public_fixture_user_21296'],1,b'')]:
            r=subprocess.run([binary,*args],env=dict(PATH='/unavailable',LANG='C',LC_ALL='C'),capture_output=True,timeout=10);assert r.returncode==code and r.stdout==text
            for name,data in [('stdout',r.stdout),('stderr',r.stderr)]:(logs/(label+'.'+name)).write_bytes(data)
            controls.append(dict(case=label,exit_code=r.returncode))
        package=out/'public-bfs-portable';package.mkdir();shutil.copyfile(binary,package/'bfs');(package/'bfs').chmod(0o555)
        shutil.copytree(inputs,package/'source-inputs')
        for name in ['build.py','build-bfs.sh','README.md']:shutil.copyfile(ROOT/name,package/name)
        for name in ['prepare_sysroot.py','glibc-sysroot-pins.json']:shutil.copyfile(ROOT.parent/'bun-runtime'/name,package/name)
        shutil.copyfile(work/'embedded/bfs/LICENSE',package/'BFS-LICENSE');shutil.copyfile(work/'embedded/oniguruma/COPYING',package/'ONIGURUMA-LICENSE')
        receipt.update(status='public_bfs_original_compatibility_flags_pass_portability_and_native_controls',binary_sha256=sha(binary),binary_bytes=binary.stat().st_size,controls=controls,original_build_flags_output=version.decode(),scope='Measured compatibility flags with a public replacement sysroot. Original sysroot bytes, exact transitive version identity and Bun integration are not established.')
        (package/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');rows=[dict(file=p.relative_to(package).as_posix(),bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(package.rglob('*')) if p.is_file()];(package/'MANIFEST.json').write_text(json.dumps(dict(files=rows),indent=2)+'\n')
    except BaseException as error:receipt.update(status='failed',error_type=type(error).__name__,error=str(error));raise
    finally:
        generated=work/'embedded/bfs/gen'
        if generated.is_dir():
            retained=logs/'bfs-config';retained.mkdir()
            for p in sorted(generated.iterdir()):
                if p.is_file() and p.suffix in ['.mk','.h']:shutil.copyfile(p,retained/p.name)
        (logs/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
if __name__=='__main__':main()
