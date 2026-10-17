"""Capture an auditable Alpine SDK; it does not qualify a recovered engine."""
from pathlib import Path
import argparse
import gzip
import hashlib
import io
import json
import os
import platform
import shutil
import stat
import struct
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parent


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def records(raw):
    return [dict(line.split(':', 1) for line in block.splitlines() if ':' in line)
            for block in raw.strip().split('\n\n')]


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--arch', choices=['x64', 'arm64'], required=True)
    parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    assert platform.system() == 'Linux' and platform.machine() == {'x64': 'x86_64', 'arm64': 'aarch64'}[args.arch]
    pins = json.loads((ROOT / 'musl-sdk-pins.json').read_bytes()); pin = pins['profiles'][args.arch]
    out = args.output.resolve(); out.mkdir(); logs = out / 'diagnostics'; logs.mkdir(); inputs = out / 'inputs'; inputs.mkdir()
    root = out / 'sysroot'; root.mkdir()
    cache = root / 'var/cache/apk'; cache.mkdir(parents=True)
    receipt = dict(status='started', arch=args.arch, alpine_release='3.23', pin=pin, commands=[],
                   captured_client_executed=False, recovered_engine_qualified=False, goal_complete=False)

    def run(label, argv):
        receipt['commands'].append(dict(label=label, argv=list(map(str, argv)))); print('Starting ' + label, flush=True)
        with (logs / (label + '.log')).open('xb') as stream:
            result = subprocess.run(list(map(str, argv)), stdout=stream, stderr=subprocess.STDOUT, timeout=600)
        assert result.returncode == 0, label + ' failed; inspect retained diagnostics'

    def download(label, url, path):
        run(label, ['curl', '--http1.1', '--fail', '--silent', '--show-error', '--retry', '3', '--max-time', '120', '--output', path, url])

    try:
        index = inputs / 'APKINDEX.tar.gz'; download('publisher-index', pin['index_url'], index)
        assert sha(index) == pin['index_sha256'], 'Publisher index changed; new versions need qualification'
        with tarfile.open(index, 'r:gz') as stream:
            package_index = records(stream.extractfile('APKINDEX').read().decode())
        archive = inputs / 'apk-tools-static.apk'; download('apk-tools-source', pin['apk_url'], archive)
        assert archive.stat().st_size == pin['apk_bytes'] and sha(archive) == pin['apk_sha256']
        with tarfile.open(archive, 'r:gz', ignore_zeros=True) as stream:
            members = [m for m in stream.getmembers() if m.name.lstrip('./') == 'sbin/apk.static']
            assert len(members) == 1 and members[0].isfile(); body = stream.extractfile(members[0]).read()
        apk = out / 'apk.static'; apk.write_bytes(body); apk.chmod(0o755)
        assert sha(apk) == pin['apk_static_sha256']
        assert body[:4] == b'\x7fELF' and struct.unpack_from('<H', body, 18)[0] == {'x64': 62, 'arm64': 183}[args.arch]
        run('apk-version', [apk, '--version'])
        run('project-sdk-packages', ['sudo', apk, '--root', root, '--arch', pin['alpine_arch'],
            '--cache-dir', '/var/cache/apk', '--repository', 'https://dl-cdn.alpinelinux.org/alpine/v3.23/main',
            '--allow-untrusted', '--initdb', '--no-scripts', 'add',
            'musl-dev', 'libc-dev', 'linux-headers', 'g++', 'libstdc++-dev'])
        # Only the newly created SDK changes ownership; links are never followed.
        run('own-sdk-output', ['sudo', 'chown', '-R', '-h', f'{os.getuid()}:{os.getgid()}', root])
        db = root / 'lib/apk/db/installed'; installed = records(db.read_text())
        indexed = {(p['P'], p['V'], p.get('A', pin['alpine_arch'])) for p in package_index}
        assert installed and all((p['P'], p['V'], p.get('A', pin['alpine_arch'])) in indexed for p in installed)
        package = out / 'public-sdk'; package.mkdir(); source_apks = package / 'source-apks'; source_apks.mkdir()
        cached = sorted(root.rglob('*.apk')); assert len(cached) >= len(installed), 'Retain every installed APK before accepting the snapshot'
        for path in cached:
            assert not path.is_symlink() and not (source_apks / path.name).exists()
            shutil.copyfile(path, source_apks / path.name)
        receipt['installed_packages'] = [dict(name=p['P'], version=p['V'], arch=p.get('A', pin['alpine_arch'])) for p in installed]
        receipt['retained_package_archives'] = [dict(file=p.name, bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(source_apks.iterdir())]
        # Preserve volatile package-manager data as diagnostics, outside the SDK.
        if cache.exists(): shutil.copytree(cache, logs / 'apk-cache'); shutil.rmtree(cache)
        apk_log = root / 'var/log/apk.log'
        if apk_log.exists(): shutil.copyfile(apk_log, logs / 'apk-install.log'); apk_log.unlink()
        rewrites = []
        for path in sorted(root.rglob('*')):
            if path.is_symlink() and os.readlink(path).startswith('/'):
                before = os.readlink(path); target = root / before.lstrip('/')
                after = os.path.relpath(target, path.parent); path.unlink(); path.symlink_to(after)
                rewrites.append(dict(file=path.relative_to(root).as_posix(), before=before, after=after))
        files = []
        for path in sorted(root.rglob('*')):
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                assert path.resolve().is_relative_to(root), 'SDK link escapes its owned root'
                files.append(dict(file=rel, kind='symlink', target=os.readlink(path)))
            elif path.is_file():
                files.append(dict(file=rel, kind='file', bytes=path.stat().st_size, sha256=sha(path), mode=stat.S_IMODE(path.stat().st_mode)))
            else: assert path.is_dir(), 'Unsupported SDK filesystem object'
        (package / 'sysroot-files.json').write_text(json.dumps(files, indent=2) + '\n')
        tar_path = package / 'musl-sysroot.tar.gz'
        with tar_path.open('wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0, filename='') as compressed, tarfile.open(fileobj=compressed, mode='w') as stream:
            for path in sorted(root.rglob('*')):
                info = stream.gettarinfo(str(path), arcname=path.relative_to(root).as_posix())
                info.uid = info.gid = info.mtime = 0; info.uname = info.gname = ''
                if info.isfile():
                    with path.open('rb') as source: stream.addfile(info, source)
                else: stream.addfile(info)
        for source, name in [(index, 'APKINDEX.tar.gz'), (archive, 'apk-tools-static.apk'), (ROOT / 'musl-sdk-pins.json', 'musl-sdk-pins.json'), (Path(__file__), Path(__file__).name)]:
            shutil.copyfile(source, package / name)
        receipt.update(status='public_musl_sdk_files_and_installed_index_versions_captured', symlink_rewrites=rewrites,
                       sdk_files=len(files), sysroot_archive_sha256=sha(tar_path), sysroot_file_manifest_sha256=sha(package / 'sysroot-files.json'))
        (package / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        inventory = [dict(file=p.relative_to(package).as_posix(), bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(package.rglob('*')) if p.is_file()]
        (package / 'MANIFEST.json').write_text(json.dumps(dict(schema_version=1, files=inventory), indent=2) + '\n')
    except BaseException as error:
        receipt.update(status='musl_sdk_failed_not_admitted', error_type=type(error).__name__, error=str(error)); raise
    finally:
        (logs / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    main()
