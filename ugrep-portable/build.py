"""Build Ugrep's direct-call source library in the same portable Bun toolchain."""
from pathlib import Path
import argparse, hashlib, json, os, platform, re, shutil, subprocess, sys, urllib.request

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from prepare_sysroot import prepare
from build_linux import PROFILES
sys.path.insert(0, str(ROOT.parent / 'runtime-helpers'))
from build import unpack


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--arch', choices=PROFILES, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-inputs', type=Path)
    args = parser.parse_args()
    assert platform.system() == 'Linux' and {'x86_64': 'x64', 'aarch64': 'arm64'}[platform.machine()] == args.arch
    out = args.output.resolve(); out.mkdir(); logs = out / 'diagnostics'; logs.mkdir()
    sources = out / 'sources'; sources.mkdir(); inputs = out / 'source-inputs'; inputs.mkdir()
    names = {'ugrep', 'pcre2', 'zlib', 'bzip2', 'zstd', 'brotli'}
    selected = [row for row in json.loads((ROOT.parent / 'extra-components/sources.json').read_bytes())['files'] if row['name'] in names]
    assert {row['name'] for row in selected} == names
    receipt = dict(status='started',arch=args.arch,source_inputs=selected,compiler_image=PROFILES[args.arch]['image'],
                   captured_client_executed=False,original_binary_reused=False,exact_original_transitive_versions_proven=False,commands=[])
    receipt['source_archive_provider']='verified input archives' if args.source_inputs else 'pinned public upstream URLs'

    def run(label, command, timeout=1800):
        receipt['commands'].append(dict(label=label,argv=list(map(str,command))))
        print('Starting ' + label, flush=True)
        with (logs / (label + '.log')).open('xb') as stream:
            result = subprocess.run(list(map(str,command)),stdout=stream,stderr=subprocess.STDOUT,timeout=timeout)
        assert result.returncode == 0, label + ' failed; inspect retained diagnostics'

    try:
        for row in selected:
            archive = inputs / (row['name'] + '.tar.gz')
            if args.source_inputs:
                original=args.source_inputs/(row['name']+'.tar.gz')
                assert original.is_file() and not original.is_symlink()
                raw=original.read_bytes()
            else:
                with urllib.request.urlopen(row['url'],timeout=90) as response:
                    raw = response.read(16777217)
            assert len(raw) <= 16777216 and hashlib.sha256(raw).hexdigest() == row['sha256'], 'Pinned source archive mismatch: '+row['name']
            if 'bytes' in row: assert len(raw) == row['bytes']
            archive.write_bytes(raw); unpack(archive,sources / row['name'],row['prefix'])
            # Preserve autotools release timestamp relationships.
            import tarfile
            with tarfile.open(archive) as source:
                for member in source.getmembers():
                    if member.isfile():
                        assert 0 <= member.mtime < 4102444800
                        os.utime(sources / row['name'] / member.name[len(row['prefix']):],(member.mtime,member.mtime),follow_symlinks=False)
        prepare(args.arch,out,logs)
        image = PROFILES[args.arch]['image']; docker_platform = PROFILES[args.arch]['docker_platform']
        run('compiler-pull',['docker','pull','--platform',docker_platform,image],900)
        run('compiler-inspect',['docker','image','inspect',image])
        sysroot = '/opt/linux-sysroot-glibc' + ('-arm64' if args.arch == 'arm64' else '')
        run('source-library-build',['docker','run','--rm','--platform',docker_platform,'--network','none',
            '--cap-drop','ALL','--security-opt','no-new-privileges','--user',f'{os.getuid()}:{os.getgid()}',
            '--cpus','2','--memory','5g','--pids-limit','256','--mount',f'type=bind,src={out},dst=/output',
            '--mount',f'type=bind,src={out / "sysroot"},dst={sysroot},readonly',
            '--mount',f'type=bind,src={ROOT},dst=/recipes,readonly','--entrypoint','/usr/bin/python3',image,
            '/recipes/build-library.py','--arch',args.arch],2400)
        library = out / 'native-library'; native = json.loads((library / 'receipt.json').read_bytes())
        assert native['status'] == 'ugrep_source_library_host_and_upstream_checks_passed'
        assert native['source_objects'] == 9 and native['main_text_unchanged'] is True
        host = library / 'ugrep-library-host'
        run('version-needs',['readelf','--version-info',host])
        needs = {tuple(map(int,value.split('.'))) for value in re.findall(r'GLIBC_([0-9]+(?:\.[0-9]+)+)',(logs / 'version-needs.log').read_text())}
        assert needs; receipt['maximum_glibc_requirement'] = '.'.join(map(str,max(needs)))
        assert max(needs) <= (2,17), 'Ugrep source library host exceeds the original glibc floor'
        observed = subprocess.check_output([host,'--version'],timeout=10)
        assert observed == (ROOT / ('expected-version-' + args.arch + '.txt')).read_bytes(), 'Ugrep version bytes differ from the qualified original-role comparison'
        package = out / 'public-ugrep-library'; package.mkdir()
        shutil.copytree(library,package / 'native-library'); shutil.copytree(inputs,package / 'source-inputs')
        shutil.copyfile(ROOT / ('expected-version-' + args.arch + '.txt'),package / 'expected-original-version.txt')
        for name in ['build.py','build-library.py','README.md']:
            shutil.copyfile(ROOT / name,package / name)
        for name in ['prepare_sysroot.py','glibc-sysroot-pins.json']:
            shutil.copyfile(ROOT.parent / 'bun-runtime' / name,package / name)
        shutil.copyfile(sources / 'ugrep/LICENSE.txt',package / 'UGREP-LICENSE.txt')
        receipt.update(status='portable_ugrep_source_library_host_and_original_version_controls_passed',
                       native_library=native,host_sha256=sha(host),scope='Source-built direct-call Ugrep library. Bun integration, exact original dependency versions and complete-client acceptance remain open.')
        (package / 'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        rows = [dict(file=p.relative_to(package).as_posix(),bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(package.rglob('*')) if p.is_file()]
        (package / 'MANIFEST.json').write_text(json.dumps(dict(files=rows),indent=2)+'\n')
    except BaseException as error:
        receipt.update(status='failed',error_type=type(error).__name__,error=str(error));raise
    finally:
        library = out / 'native-library'
        if library.is_dir():
            shutil.copytree(library,logs / 'native-library')
        (logs / 'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')


if __name__ == '__main__':main()
