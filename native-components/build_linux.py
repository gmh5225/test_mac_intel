"""Prepare direct-link Rust/C component candidates in Bun's pinned toolchain."""
from pathlib import Path
import argparse,hashlib,json,os,platform,resource,shutil,subprocess,sys,tomllib
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent/'runtime-helpers'))
from build import unpack

IMAGES={
    'x64':'ghcr.io/oven-sh/bun-development-docker-image@sha256:ee053ca8ff0a00ab51c8572378fb56dee902063d5020b4d90fb78a098fb70af2',
    'arm64':'ghcr.io/oven-sh/bun-development-docker-image@sha256:19e1898469e3ab456b90a4120c1b96644af53c019434c2f9852eb14870e13d11',
}
RG_MANIFESTS={'x64':'8645bd24a2f25315636d73156e719380f1c77769ff8343d781a7d6b005743dfb',
              'arm64':'e25a46641db047f89bc5d84d93d9f7bd93a09e39cba94c6f24c1c211b925f3b8'}
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--arch',required=True,choices=IMAGES);ap.add_argument('--rg-package',type=Path,required=True);ap.add_argument('--seccomp-package',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    assert platform.system()=='Linux' and {'x86_64':'x64','aarch64':'arm64'}[platform.machine()]==a.arch
    rg=a.rg_package.resolve();seccomp=a.seccomp_package.resolve()
    assert sha(rg/'MANIFEST.json')==RG_MANIFESTS[a.arch]
    for package in [rg,seccomp]:
        for row in json.loads((package/'MANIFEST.json').read_bytes())['files']:
            rel=Path(row['file']);assert not rel.is_absolute() and '..' not in rel.parts
            path=package/rel;assert path.is_file() and not path.is_symlink() and sha(path)==row['sha256'] and path.stat().st_size==row['bytes']
    out=a.output.resolve();out.mkdir();logs=out/'diagnostics';logs.mkdir();work=out/'build';work.mkdir()
    package=out/'public-native-libraries';package.mkdir()
    receipt=dict(status='started',arch=a.arch,public_sources_only=True,captured_client_executed=False,compiler_image=IMAGES[a.arch],compiler_rust_channel='nightly-2026-09-15',commands=[],controls=[])
    def run(label,command,timeout=1800):
        receipt['commands'].append(dict(label=label,argv=list(map(str,command))))
        with (logs/(label+'.log')).open('xb') as stream:
            result=subprocess.run(list(map(str,command)),stdout=stream,stderr=subprocess.STDOUT,timeout=timeout)
        assert result.returncode==0,label+' failed; inspect retained diagnostics'
    try:
        unpack(rg/'ripgrep.tar.gz',work/'ripgrep','ripgrep-14.1.1/')
        unpack(rg/'pcre2.tar.gz',work/'pcre2','pcre2-10.45/')
        shutil.copytree(rg/'pcre2-overlay',work/'pcre2-overlay')
        shutil.copyfile(rg/'effective-ripgrep-Cargo.toml',work/'ripgrep/Cargo.toml')
        shutil.copyfile(rg/'Cargo.lock',work/'ripgrep/Cargo.lock')
        manifest=work/'ripgrep/Cargo.toml';before=manifest.read_text();assert '[lib]' not in before
        manifest.write_text(before+'\n[lib]\nname = "recovered_ripgrep"\npath = "crates/core/recovery_lib.rs"\ncrate-type = ["rlib"]\n')
        original=work/'ripgrep/crates/core/main.rs';original_bytes=original.read_bytes()
        assert original_bytes.count(b'fn main() -> ExitCode {')==1
        lib=work/'ripgrep/crates/core/recovery_lib.rs'
        lib.write_bytes(b'#![feature(exitcode_exit_method)]\n'+original_bytes+b'\n#[unsafe(no_mangle)]\npub extern "C" fn neverd_recovered_rg_main() -> ! { main().exit_process() }\n')
        vendor=work/'vendor';vendor.mkdir();upstream=tomllib.loads((rg/'upstream-Cargo.lock').read_text())
        checksums={(p['name'],p['version']):p['checksum'] for p in upstream['package'] if 'checksum' in p}
        for archive in (rg/'cargo-crates').glob('*.crate'):
            matched=[(name,version,digest) for (name,version),digest in checksums.items() if archive.name==name+'-'+version+'.crate'];assert len(matched)==1
            name,version,digest=matched[0];assert sha(archive)==digest
            dest=vendor/(name+'-'+version);unpack(archive,dest,name+'-'+version+'/')
            assert not any(p.is_symlink() for p in dest.rglob('*'))
            files={p.relative_to(dest).as_posix():sha(p) for p in sorted(dest.rglob('*')) if p.is_file()}
            (dest/'.cargo-checksum.json').write_text(json.dumps(dict(package=digest,files=files),sort_keys=True)+'\n')
        home=work/'cargo-home';home.mkdir()
        (home/'config.toml').write_text('[source.crates-io]\nreplace-with = "retained-vendor"\n[source.retained-vendor]\ndirectory = "/build/vendor"\n')
        native=work/'seccomp-source';native.mkdir()
        source=seccomp/'sources/sandbox-runtime/vendor/seccomp-src/apply-seccomp.c'
        assert sha(source)=='74e2ddfdef60edaf849ce13ab03def2d3ef42bf784ed79b86bab2823098f15dc'
        header=seccomp/'unix-block-bpf.h';assert sha(header)=='3d435576ff6eae7ba661432c2d202464f93bdd216e294659d9e4ae50588f7f61'
        shutil.copyfile(source,native/'apply-seccomp.c');shutil.copyfile(header,native/'unix-block-bpf.h')
        image=IMAGES[a.arch];docker_platform={'x64':'linux/amd64','arm64':'linux/arm64'}[a.arch];target={'x64':'x86_64-unknown-linux-gnu','arm64':'aarch64-unknown-linux-gnu'}[a.arch]
        run('pull',['docker','pull','--platform',docker_platform,image],timeout=900)
        run('build',['docker','run','--rm','--platform',docker_platform,'--network','none','--cap-drop','ALL','--cap-add','DAC_OVERRIDE','--security-opt','no-new-privileges','--cpus','2','--memory','4g','--pids-limit','256','--mount',f'type=bind,src={work},dst=/build','--mount',f'type=bind,src={ROOT},dst=/recipes,readonly','--env','RECOVERY_NATIVE_TARGET='+target,'--entrypoint','/bin/bash',image,'/recipes/build-libraries.sh'])
        probe=out/'native-role-probe';shutil.copyfile(work/'native-role-probe',probe);probe.chmod(0o500)
        fixture=out/'fixture.txt';fixture.write_text('first\nNEEDLE\npreneedle\n🐈\n')
        def no_file_writes():resource.setrlimit(resource.RLIMIT_FSIZE,(0,0));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        for label,role,args,code,text in [
            ('rg-version','rg',['--version'],0,'PCRE2 10.45 is available (JIT is available)'),
            ('rg-literal','rg',['--no-config','-n','NEEDLE',str(fixture)],0,'2:NEEDLE\n'),
            ('rg-absent','rg',['--no-config','absent-fixture',str(fixture)],1,''),
            ('rg-invalid','rg',['--no-config','[',str(fixture)],2,''),
            ('rg-pcre','rg',['--no-config','-P','-o','(?<=pre)needle',str(fixture)],0,'needle\n'),
            ('rg-unicode','rg',['--no-config','-o','🐈',str(fixture)],0,'🐈\n'),
            ('seccomp-usage','apply-seccomp',[],1,'Usage:')]:
            observed=subprocess.run([probe,*args],env=dict(PATH='/unavailable',LANG='C',LC_ALL='C',ARGV0=role),capture_output=True,text=True,preexec_fn=no_file_writes,timeout=30)
            (logs/(label+'.stdout')).write_text(observed.stdout);(logs/(label+'.stderr')).write_text(observed.stderr)
            assert observed.returncode==code
            assert text in observed.stdout+observed.stderr if label in ['rg-version','seccomp-usage'] else observed.stdout==text
            if label=='rg-version':assert '(rev ' not in observed.stdout
            receipt['controls'].append(dict(case=label,exit_code=observed.returncode,rlimit_fsize=0,stdout=observed.stdout,stderr=observed.stderr))
        shutil.copytree(work/'rust-libs',package/'rust-libs')
        shutil.copyfile(work/'librecovered_rg.a',package/'librecovered_rg.a')
        for name in ['apply-seccomp.c','unix-block-bpf.h']:shutil.copyfile(native/name,package/name)
        shutil.copyfile(seccomp/'sources/sandbox-runtime/LICENSE',package/'SECCOMP-LICENSE')
        inputs=package/'inputs';inputs.mkdir()
        for name in ['ripgrep.tar.gz','pcre2.tar.gz','Cargo.lock','upstream-Cargo.lock','effective-ripgrep-Cargo.toml','pcre2-overlay.json','pcre2-runtime-version.patch']:
            shutil.copyfile(rg/name,inputs/name)
        shutil.copytree(rg/'cargo-crates',inputs/'cargo-crates');shutil.copytree(rg/'pcre2-overlay',inputs/'pcre2-overlay')
        shutil.copyfile(lib,package/'recovery_lib.rs');shutil.copyfile(manifest,package/'effective-library-Cargo.toml');shutil.copyfile(probe,package/'native-role-probe')
        for name in ['build_linux.py','build-libraries.sh','select_artifacts.py','role-probe.rs','README.md']:shutil.copyfile(ROOT/name,package/name)
        shutil.copyfile(work/'selected-library-artifacts.json',package/'library-artifacts.json')
        receipt.update(status='direct_link_rust_and_c_candidates_pass_zero_file_budget_controls',original_rg_main_sha256=sha(original),library_source_sha256=sha(lib),combined_library_sha256=sha(package/'librecovered_rg.a'),rust_libraries=[dict(file=p.name,bytes=p.stat().st_size,sha256=sha(p)) for p in sorted((package/'rust-libs').glob('*.rlib'))],whole_bun_integration_accepted=False)
        (package/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        rows=[dict(file=p.relative_to(package).as_posix(),bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(package.rglob('*')) if p.is_file()]
        (package/'MANIFEST.json').write_text(json.dumps(dict(files=rows),indent=2)+'\n')
        print(json.dumps(dict(status=receipt['status'],arch=a.arch,rlibs=len(receipt['rust_libraries']))))
    except BaseException as error:receipt.update(status='failed',error=str(error));raise
    finally:
        for name in ['cargo-artifacts.jsonl','selected-library-artifacts.json']:
            if (work/name).is_file():shutil.copyfile(work/name,logs/name)
        (logs/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
if __name__=='__main__':main()
