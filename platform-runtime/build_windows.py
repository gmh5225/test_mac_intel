"""Rebuild the unmodified public Bun baseline on native Windows runners."""
from pathlib import Path
import argparse
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import zipfile
from build_macos import COMMIT, CHANNEL, curl_config, sha

PROFILES = {
    'x64': dict(llvm='LLVM-23.1.1-win64.msi', llvm_bytes=639493873,
                llvm_sha256='11af43ba261a1158090dd6f0da40d7a34f32dbfb4a76b43240bffa1ebb140984',
                bootstrap='bun-windows-x64-baseline.zip', bootstrap_bytes=39807490,
                bootstrap_sha256='78c221c2376f79731ccf4e4af0b3bb46d81fefa3296c5abee09ad8a1b21e68c6',
                cmake='cmake-3.30.5-windows-x86_64.zip',
                cmake_sha256='5ab6e1faf20256ee4f04886597e8b6c3b1bd1297b58a68a58511af013710004b',
                target='x86_64-pc-windows-msvc', machine=0x8664, build_arch='x64'),
    'arm64': dict(llvm='LLVM-23.1.1-woa64.msi', llvm_bytes=575774875,
                  llvm_sha256='aeb4415a5fcfd488dc0ef69ccb2c85a81163c11960b63b6b295c6c3df5a6317e',
                  bootstrap='bun-windows-aarch64.zip', bootstrap_bytes=36330062,
                  bootstrap_sha256='a7a16b876a305fd1029c66dbd27007b4f6112ae896532f675878731a21e50cfd',
                  cmake='cmake-3.30.5-windows-arm64.zip',
                  cmake_sha256='b5fa431bd569b591717a9a0f77c0ab56b072ef8603f924401227c178ac7072d9',
                  target='aarch64-pc-windows-msvc', machine=0xaa64, build_arch='aarch64'),
}
NASM_URL = 'https://www.nasm.us/pub/nasm/releasebuilds/2.16.03/win64/nasm-2.16.03-win64.zip'
NASM_SHA256 = '3ee4782247bcb874378d02f7eab4e294a84d3d15f3f6ee2de2f47a46aa7226e6'
NASM_BYTES = 513543


def unpack(archive, destination):
    destination.mkdir()
    with zipfile.ZipFile(archive) as stream:
        seen = set()
        for item in stream.infolist():
            path = Path(item.filename)
            assert not path.is_absolute() and '..' not in path.parts and '\\' not in item.filename
            assert item.filename.casefold() not in seen; seen.add(item.filename.casefold())
        stream.extractall(destination)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--arch', required=True, choices=PROFILES)
    parser.add_argument('--output', required=True, type=Path); args = parser.parse_args()
    assert platform.system() == 'Windows'
    assert os.environ['RUNNER_ARCH'].lower() == args.arch
    profile = PROFILES[args.arch]
    out = args.output.resolve(); out.mkdir(); logs = out / 'diagnostics'; logs.mkdir(); inputs = out / 'inputs'; inputs.mkdir()
    env = dict(os.environ); token = env.get('GH_TOKEN')
    for name in list(env):
        if name in ['GITHUB_SHA', 'BUILDKITE_COMMIT', 'GIT_SHA'] or name.startswith('ACTIONS_') or any(x in name.upper() for x in ['TOKEN', 'SECRET', 'PASSWORD']):
            env.pop(name)
    receipt = dict(status='started', target_arch=args.arch, runner_arch=os.environ['RUNNER_ARCH'],
                   python_machine=platform.machine(), public_bun_commit=COMMIT, commands=[],
                   recovered_native_roles_integrated=False, captured_client_executed=False,
                   original_private_revision_recovered=False, original_prefix_reused=False, goal_complete=False)

    def run(label, argv, cwd=None, data=None):
        argv = list(map(str, argv)); receipt['commands'].append(dict(label=label, argv=argv))
        print('Starting ' + label, flush=True)
        with (logs / (label + '.log')).open('xb') as stream:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL)
            if data is not None: process.stdin.write(data); process.stdin.close()
            for block in iter(lambda: process.stdout.read(65536), b''):
                stream.write(block); stream.flush(); sys.stdout.buffer.write(block); sys.stdout.buffer.flush()
            code = process.wait()
        assert code == 0, label + ' failed; inspect retained diagnostics'

    def download(url, destination):
        run('download-' + destination.name, ['curl.exe', '--http1.1', '--fail', '--location', '--silent', '--show-error',
              '--retry', '3', '--max-time', '900', '--output', destination, '--config', '-'], data=curl_config(url, token))

    def release(repo, tag, name, digest, size=None):
        meta = inputs / (name + '.release.json'); download(f'https://api.github.com/repos/{repo}/releases/tags/{tag}', meta)
        info = json.loads(meta.read_bytes()); assert info['tag_name'] == tag
        choices = [a for a in info['assets'] if a['name'] == name]; assert len(choices) == 1
        item = choices[0]
        assert item.get('digest') in [None, 'sha256:' + digest]
        if size is not None: assert item['size'] == size
        url = f'https://github.com/{repo}/releases/download/{tag}/{name}'; assert item['browser_download_url'] == url
        archive = inputs / name; download(url, archive)
        assert archive.stat().st_size == item['size'] and sha(archive) == digest
        receipt.setdefault('public_tool_inputs', []).append(dict(repo=repo, tag=tag, name=name, bytes=item['size'],
                                                                sha256=digest, release_metadata_sha256=sha(meta)))
        return archive

    try:
        for tool in ['git.exe', 'rustup.exe', 'go.exe', 'ruby.exe', 'rc.exe']:
            run('find-' + tool, ['where.exe', tool])
        if args.arch == 'x64':
            archive = inputs / 'nasm-2.16.03-win64.zip'; download(NASM_URL, archive)
            assert archive.stat().st_size == NASM_BYTES and sha(archive) == NASM_SHA256
            nasm_root = out / 'nasm'; unpack(archive, nasm_root)
            choices = list(nasm_root.glob('*/nasm.exe')); assert len(choices) == 1
            env['PATH'] = str(choices[0].parent) + os.pathsep + env['PATH']
            run('nasm-version', [choices[0], '--version'])
            assert (logs / 'nasm-version.log').read_text().startswith('NASM version 2.16.03')
            receipt['nasm_archive_sha256'] = NASM_SHA256
        llvm = release('llvm/llvm-project', 'llvmorg-23.1.1', profile['llvm'], profile['llvm_sha256'], profile['llvm_bytes'])
        tools = out / 'llvm'; tools.mkdir()
        run('extract-llvm-msi', ['msiexec.exe', '/a', llvm, '/qn', 'TARGETDIR=' + str(tools), '/l*v', logs / 'llvm-msi-extraction.log'])
        choices = list(tools.rglob('clang-cl.exe')); assert len(choices) == 1
        toolbin = choices[0].parent
        env['PATH'] = str(toolbin) + os.pathsep + env['PATH']; env['CC'] = str(toolbin / 'clang-cl.exe'); env['CXX'] = env['CC']
        # Bun's discovery prefers known system install locations over PATH for
        # tools without a version query. Pin the entire family, not only CC.
        env['BUN_TOOLCHAIN_LLVM'] = str(toolbin.parent)
        run('clang-version', [toolbin / 'clang-cl.exe', '--version'])
        assert 'clang version 23.1.1' in (logs / 'clang-version.log').read_text()
        receipt['clang_sha256'] = sha(toolbin / 'clang-cl.exe')
        receipt['llvm_tools'] = {}
        for name in ['llvm-nm.exe', 'lld-link.exe', 'llvm-ar.exe', 'llvm-lib.exe', 'llvm-objcopy.exe']:
            tool = toolbin / name; assert tool.is_file(), 'Incomplete pinned LLVM distribution'
            if name != 'llvm-lib.exe':  # MSVC lib-compatible driver has no --version query.
                run(name + '-version', [tool, '--version'])
                assert '23.1.1' in (logs / (name + '-version.log')).read_text()
            receipt['llvm_tools'][name] = dict(path=str(tool), sha256=sha(tool))
        cmake_archive = release('Kitware/CMake', 'v3.30.5', profile['cmake'], profile['cmake_sha256'])
        cmake_root = out / 'cmake'; unpack(cmake_archive, cmake_root)
        choices = list(cmake_root.glob('*/bin/cmake.exe')); assert len(choices) == 1
        env['PATH'] = str(choices[0].parent) + os.pathsep + env['PATH']; run('cmake-version', [choices[0], '--version'])
        assert (logs / 'cmake-version.log').read_text().startswith('cmake version 3.30.5\n')
        archive = release('oven-sh/bun', 'bun-v1.4.2', profile['bootstrap'], profile['bootstrap_sha256'], profile['bootstrap_bytes'])
        boot = out / 'bootstrap'; unpack(archive, boot)
        choices = list(boot.glob('*/bun.exe')); assert len(choices) == 1
        bun = choices[0]; env['PATH'] = str(bun.parent) + os.pathsep + env['PATH']; run('bootstrap-version', [bun, '--version'])
        assert (logs / 'bootstrap-version.log').read_text().strip() == '1.4.2'
        source = out / 'bun-source'; run('git-init', ['git', 'init', source])
        run('git-longpaths', ['git', 'config', 'core.longpaths', 'true'], source)
        run('git-source-bytes', ['git', 'config', 'core.autocrlf', 'false'], source)
        run('git-remote', ['git', 'remote', 'add', 'origin', 'https://github.com/oven-sh/bun.git'], source)
        run('git-fetch', ['git', '-c', 'http.version=HTTP/1.1', 'fetch', '--depth', '1', 'origin', COMMIT], source)
        run('git-checkout', ['git', 'checkout', '--detach', COMMIT], source)
        assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip() == COMMIT
        env.update(RUSTUP_HOME=str(out / 'rustup'), CARGO_HOME=str(out / 'cargo'), RUSTUP_TOOLCHAIN=CHANNEL,
                   BUN_BUILD_CACHE_DIR=str(out / 'source-cache'), CARGO_BUILD_JOBS='1')
        rustup = shutil.which('rustup'); assert rustup is not None
        run('rust-install', [rustup, 'toolchain', 'install', CHANNEL, '--profile', 'minimal', '--component', 'rust-src', '--target', profile['target']], out)
        run('rust-version', [rustup, 'run', CHANNEL, 'rustc', '-vV'], out)
        assert 'LLVM version: 23.' in (logs / 'rust-version.log').read_text()
        control = out / 'sdk-header-control.c'; control.write_text('#include <stdio.h>\nint main(void) { return 0; }\n')
        run('native-sdk-header-control', [toolbin / 'clang-cl.exe', '/nologo', '/Zs', '/TC', control])
        obj = out / 'llvm-family-control.obj'; exe = out / 'llvm-family-control.exe'
        run('llvm-family-compile-control', [toolbin / 'clang-cl.exe', '/nologo', '/c', '/O2',
            '/clang:-flto=thin', '/Fo' + str(obj), control])
        run('llvm-family-nm-control', [toolbin / 'llvm-nm.exe', obj])
        assert 'main' in (logs / 'llvm-family-nm-control.log').read_text()
        run('llvm-family-link-control', [toolbin / 'lld-link.exe', '/subsystem:console', '/entry:main',
            '/nodefaultlib', '/out:' + str(exe), obj])
        run('llvm-family-native-execution-control', [exe])
        receipt['native_lto_family_control_sha256'] = sha(exe)
        run('public-bun-build', [bun, 'scripts/build.ts', '--profile=release', '--os=windows', '--arch=' + profile['build_arch'],
                                  '--build-dir=' + str(source / 'build/recovery'), '-j2'], source)
        binary = source / 'build/recovery/bun.exe'; raw = binary.read_bytes(); assert raw[:2] == b'MZ'
        pe = struct.unpack_from('<I', raw, 60)[0]
        assert raw[pe:pe+4] == b'PE\0\0' and struct.unpack_from('<H', raw, pe+4)[0] == profile['machine']
        run('native-runtime-version', [binary, '--version']); assert (logs / 'native-runtime-version.log').read_text().strip() == '1.4.3'
        run('native-runtime-revision', [binary, '--revision']); assert COMMIT[:9] in (logs / 'native-runtime-revision.log').read_text()
        receipt.update(status='unmodified_public_windows_source_baseline_built_and_version_controlled',
                       binary_sha256=sha(binary), binary_bytes=binary.stat().st_size, native_version_executed=True,
                       source_tree=subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=source, text=True).strip())
        package = out / 'public-runtime'; package.mkdir(); shutil.copyfile(binary, package / 'bun.exe')
        for path in [Path(__file__), Path(__file__).with_name('build_macos.py')]: shutil.copyfile(path, package / path.name)
        (package / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        files = [dict(file=p.name, bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(package.iterdir())]
        (package / 'MANIFEST.json').write_text(json.dumps(dict(schema_version=1, files=files), indent=2) + '\n')
    except BaseException as error:
        receipt.update(status='platform_baseline_failed_not_admitted', error_type=type(error).__name__, error=str(error)); raise
    finally:
        (logs / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    main()
