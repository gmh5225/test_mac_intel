"""Build an unmodified public macOS Bun baseline with matching LLVM/Rust.

This establishes the platform build boundary before recovered native roles are
added. It never consumes captured clients and cannot admit a recovered engine.
Both targets build on ARM64; x64 execution is a separate native Intel job.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parent
COMMIT = 'c6da4a4d3010e5553438c60f6bd76d981976867c'
LLVM_VERSION = '23.1.1'
LLVM_ASSET = 'LLVM-23.1.1-macOS-ARM64.tar.xz'
LLVM_SHA256 = '64220f1c99132ef7e580447781b84f96fbba6862a43a8f6522b423052cd67502'
LLVM_BYTES = 1569887696
CHANNEL = 'nightly-2026-09-15'
BOOTSTRAP_ASSET = 'bun-darwin-aarch64.zip'
BOOTSTRAP_SHA256 = '90987a3a16d7db556d886ac3d551e7b6d3edf0a1cf43acaed622e8676be1d12f'
BOOTSTRAP_BYTES = 25377591
CMAKE_ASSET = 'cmake-3.30.5-macos-universal.tar.gz'
CMAKE_SHA256 = '3d603e507c7579b13518ef752b4ffcf3ed479fba80ee171d7d85da8153e869d0'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--arch', choices=['arm64', 'x64'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert platform.system() == 'Darwin' and platform.machine() == 'arm64'
    out = args.output.resolve(); out.mkdir()
    logs = out / 'diagnostics'; logs.mkdir()
    inputs = out / 'inputs'; inputs.mkdir()
    env = dict(os.environ)
    # The outer workflow's revision belongs to these recipes. Bun must embed
    # the revision of the public source checkout it actually compiles.
    for name in ['GITHUB_SHA', 'BUILDKITE_COMMIT', 'GIT_SHA']:
        env.pop(name, None)
    api_token = env.pop('GH_TOKEN', None)
    env.pop('GITHUB_TOKEN', None)
    record = dict(status='started', target_arch=args.arch, build_host_arch='arm64',
                  public_bun_commit=COMMIT, commands=[], captured_client_executed=False,
                  recovered_native_roles_integrated=False, original_prefix_reused=False,
                  original_private_revision_recovered=False, goal_complete=False)

    def run(label, argv, cwd=None, private_input=None):
        argv = list(map(str, argv)); record['commands'].append(dict(label=label, argv=argv))
        print('Starting ' + label, flush=True)
        with (logs / (label + '.log')).open('xb') as stream:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       stdin=subprocess.PIPE if private_input is not None else subprocess.DEVNULL)
            if private_input is not None:
                process.stdin.write(private_input)
                process.stdin.close()
            for block in iter(lambda: process.stdout.read(65536), b''):
                stream.write(block); stream.flush(); sys.stdout.buffer.write(block); sys.stdout.buffer.flush()
            code = process.wait()
        assert code == 0, label + ' failed; inspect retained diagnostics'

    def download(url, dest):
        config = 'url = ' + json.dumps(url) + '\n'
        if url.startswith('https://api.github.com/repos/'):
            assert api_token is not None and re.fullmatch('[A-Za-z0-9_]+', api_token)
            config += 'header = ' + json.dumps('Authorization: Bearer ' + api_token) + '\n'
        argv = ['curl', '--http1.1', '--fail', '--location', '--silent', '--show-error',
                '--retry', '3', '--max-time', '900', '--output', str(dest), '--config', '-']
        run('download-' + dest.name, argv, private_input=config.encode())

    def release(repo, tag, asset_name, pinned_digest=None, pinned_bytes=None):
        meta_path = inputs / (asset_name + '.release.json')
        download(f'https://api.github.com/repos/{repo}/releases/tags/{tag}', meta_path)
        release = json.loads(meta_path.read_bytes()); assert release['tag_name'] == tag
        assets = [a for a in release['assets'] if a['name'] == asset_name]; assert len(assets) == 1
        asset = assets[0]
        digest = asset.get('digest')
        if digest is None:
            # Older releases predate GitHub's asset digest field. The exact
            # publisher SHA-256 is still mandatory before extraction.
            assert pinned_digest is not None
            digest = 'sha256:' + pinned_digest
        assert isinstance(digest, str) and digest.startswith('sha256:') and len(digest) == 71
        if pinned_digest is not None: assert digest == 'sha256:' + pinned_digest
        if pinned_bytes is not None: assert asset['size'] == pinned_bytes
        assert asset['browser_download_url'] == f'https://github.com/{repo}/releases/download/{tag}/{asset_name}'
        archive = inputs / asset_name
        download(asset['browser_download_url'], archive)
        assert archive.stat().st_size == asset['size'] and sha(archive) == digest[7:]
        record.setdefault('public_tool_inputs', []).append(dict(repo=repo, tag=tag, name=asset_name,
                                                               bytes=asset['size'], sha256=digest[7:],
                                                               release_metadata_sha256=sha(meta_path)))
        return archive

    try:
        archive = release('llvm/llvm-project', 'llvmorg-' + LLVM_VERSION, LLVM_ASSET, LLVM_SHA256, LLVM_BYTES)
        tools = out / 'llvm'; tools.mkdir()
        with tarfile.open(archive, 'r:xz') as stream:
            stream.extractall(tools, filter='data')
        compilers = list(tools.glob('*/bin/clang++'))
        assert len(compilers) == 1
        toolbin = compilers[0].parent
        assert (toolbin / 'llvm-ar').is_file() and (toolbin / 'ld64.lld').is_file()
        env['PATH'] = str(toolbin) + os.pathsep + env['PATH']
        run('clang-version', [toolbin / 'clang++', '--version'])
        assert 'clang version 23.1.1' in (logs / 'clang-version.log').read_text()
        record['compiler'] = dict(version=LLVM_VERSION, clang_sha256=sha(toolbin / 'clang'),
                                  clangxx_sha256=sha(toolbin / 'clang++'),
                                  llvm_ar_sha256=sha(toolbin / 'llvm-ar'), ld64_lld_sha256=sha(toolbin / 'ld64.lld'))
        cmake_archive = release('Kitware/CMake', 'v3.30.5', CMAKE_ASSET, CMAKE_SHA256)
        cmake_root = out / 'cmake'; cmake_root.mkdir()
        with tarfile.open(cmake_archive, 'r:gz') as stream:
            stream.extractall(cmake_root, filter='data')
        cmake_bins = list(cmake_root.glob('*/CMake.app/Contents/bin/cmake')); assert len(cmake_bins) == 1
        env['PATH'] = str(cmake_bins[0].parent) + os.pathsep + env['PATH']
        run('cmake-version', [cmake_bins[0], '--version'])
        assert (logs / 'cmake-version.log').read_text().startswith('cmake version 3.30.5\n')
        record['cmake_sha256'] = sha(cmake_bins[0])
        bootstrap = release('oven-sh/bun', 'bun-v1.4.2', BOOTSTRAP_ASSET, BOOTSTRAP_SHA256, BOOTSTRAP_BYTES)
        bootdir = out / 'bootstrap'; bootdir.mkdir()
        with zipfile.ZipFile(bootstrap) as stream:
            names = stream.namelist()
            assert len(names) == len(set(names))
            assert set(names) <= {'bun-darwin-aarch64/', 'bun-darwin-aarch64/bun'}
            raw = stream.read('bun-darwin-aarch64/bun')
        bun = bootdir / 'bun'; bun.write_bytes(raw); bun.chmod(0o500)
        env['PATH'] = str(bootdir) + os.pathsep + env['PATH']
        run('bootstrap-version', [bun, '--version'])
        assert (logs / 'bootstrap-version.log').read_text().strip() == '1.4.2'
        record['bootstrap_bun_sha256'] = sha(bun)
        source = out / 'bun-source'
        run('git-init', ['git', 'init', source])
        run('git-remote', ['git', 'remote', 'add', 'origin', 'https://github.com/oven-sh/bun.git'], source)
        run('git-fetch', ['git', '-c', 'http.version=HTTP/1.1', 'fetch', '--depth', '1', 'origin', COMMIT], source)
        run('git-checkout', ['git', 'checkout', '--detach', COMMIT], source)
        assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip() == COMMIT
        record['source_tree'] = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=source, text=True).strip()
        record['upstream_rust_toolchain_sha256'] = sha(source / 'rust-toolchain.toml')
        record['upstream_build_config_sha256'] = sha(source / 'scripts/build/config.ts')
        env['RUSTUP_HOME'] = str(out / 'rustup')
        env['CARGO_HOME'] = str(out / 'cargo')
        env['RUSTUP_TOOLCHAIN'] = CHANNEL
        env['BUN_BUILD_CACHE_DIR'] = str(out / 'source-cache')
        env['CARGO_BUILD_JOBS'] = '2'
        rustup = shutil.which('rustup'); assert rustup is not None
        target = {'arm64': 'aarch64-apple-darwin', 'x64': 'x86_64-apple-darwin'}[args.arch]
        run('rust-install', [rustup, 'toolchain', 'install', CHANNEL, '--profile', 'minimal',
                             '--component', 'rust-src', '--target', target], out)
        run('rust-version', [rustup, 'run', CHANNEL, 'rustc', '-vV'], out)
        assert 'LLVM version: 23.' in (logs / 'rust-version.log').read_text()
        run('sdk-path', ['xcrun', '--sdk', 'macosx', '--show-sdk-path'])
        run('sdk-version', ['xcrun', '--sdk', 'macosx', '--show-sdk-version'])
        run('host-capacity', ['df', '-h', out])
        build_arch = 'aarch64' if args.arch == 'arm64' else 'x64'
        run('public-bun-build', [bun, 'scripts/build.ts', '--profile=release', '--arch=' + build_arch,
                                  '--os=darwin', '--osx-deployment-target=13.0',
                                  '--build-dir=' + str(source / 'build/recovery'), '-j4'], source)
        binary = source / 'build/recovery/bun'; assert binary.is_file()
        raw = binary.read_bytes()
        assert struct.unpack_from('<II', raw) == (0xfeedfacf, {'arm64': 0x100000c, 'x64': 0x1000007}[args.arch])
        assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=source)
        if args.arch == 'arm64':
            run('native-runtime-version', [binary, '--version'])
            assert (logs / 'native-runtime-version.log').read_text().strip() == '1.4.3'
            run('native-runtime-revision', [binary, '--revision'])
            assert COMMIT[:9] in (logs / 'native-runtime-revision.log').read_text()
        package = out / 'public-runtime'; package.mkdir()
        shutil.copyfile(binary, package / 'bun'); (package / 'bun').chmod(0o500)
        shutil.copyfile(Path(__file__), package / Path(__file__).name)
        record.update(status='unmodified_public_macos_source_baseline_built',
                      binary_sha256=sha(binary), binary_bytes=binary.stat().st_size,
                      native_arm64_version_controlled=args.arch == 'arm64', captured_source_uploaded=False)
        (package / 'receipt.json').write_text(json.dumps(record, indent=2) + '\n')
        files = [dict(file=p.name, bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(package.iterdir())]
        (package / 'MANIFEST.json').write_text(json.dumps(dict(schema_version=1, files=files), indent=2) + '\n')
    except BaseException as error:
        record.update(status='platform_baseline_failed_not_admitted', error_type=type(error).__name__, error=str(error))
        raise
    finally:
        (logs / 'receipt.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    main()
