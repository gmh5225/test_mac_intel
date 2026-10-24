"""Reuse the admitted Windows baseline's public native LLVM/CMake pins."""
from pathlib import Path
import json
import os
import platform
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'platform-runtime'))
from build_windows import PROFILES, unpack, curl_config, sha


def prepare(arch, output, environment, run, token):
    assert platform.system() == 'Windows' and os.environ['RUNNER_ARCH'].lower() == arch
    assert platform.machine().lower() in {'x64': ['amd64', 'x86_64'], 'arm64': ['arm64', 'aarch64']}[arch]
    inputs = output / 'tool-inputs'; inputs.mkdir()
    receipt = dict(arch=arch, native_CPU=True, LLVM_version='23.1.1', CMake_version='3.30.5',
        MSVC_toolset=os.environ.get('VCToolsVersion'), Windows_SDK=os.environ.get('WindowsSDKVersion'), sources=[])
    p = PROFILES[arch]
    def release(repo, tag, name, digest, size=None):
        meta = inputs / (name + '.release.json')
        run('metadata-' + name, ['curl.exe', '--http1.1', '--fail', '--silent', '--show-error', '--location', '--retry', '3', '--max-time', '300',
            '--output', meta, '--config', '-'], data=curl_config('https://api.github.com/repos/' + repo + '/releases/tags/' + tag, token))
        d = json.loads(meta.read_bytes()); assert d['tag_name'] == tag
        choices = [r for r in d['assets'] if r['name'] == name]; assert len(choices) == 1
        asset = choices[0]; assert asset.get('digest') in [None, 'sha256:' + digest]
        if size is not None: assert asset['size'] == size
        url = 'https://github.com/' + repo + '/releases/download/' + tag + '/' + name
        assert asset['browser_download_url'] == url
        archive = inputs / name
        run('download-' + name, ['curl.exe', '--http1.1', '--fail', '--silent', '--show-error', '--location', '--retry', '3', '--max-time', '900',
            '--output', archive, '--config', '-'], data=curl_config(url, token))
        assert archive.stat().st_size == asset['size'] and sha(archive) == digest
        receipt['sources'].append(dict(repo=repo, tag=tag, name=name, bytes=archive.stat().st_size, sha256=digest, metadata_sha256=sha(meta)))
        return archive
    llvm = release('llvm/llvm-project', 'llvmorg-23.1.1', p['llvm'], p['llvm_sha256'], p['llvm_bytes'])
    tools = output / 'llvm'; tools.mkdir()
    run('extract-LLVM', ['msiexec.exe', '/a', llvm, '/qn', 'TARGETDIR=' + str(tools), '/l*v', output / 'diagnostics/LLVM-extraction.log'])
    choices = list(tools.rglob('clang-cl.exe')); assert len(choices) == 1; toolbin = choices[0].parent
    environment.update(CC=str(toolbin / 'clang-cl.exe'), CXX=str(toolbin / 'clang-cl.exe'), BUN_TOOLCHAIN_LLVM=str(toolbin.parent))
    for name in ['clang-cl.exe', 'lld-link.exe', 'llvm-ar.exe', 'llvm-objcopy.exe', 'llvm-nm.exe', 'llvm-readobj.exe', 'llvm-lib.exe']:
        tool = toolbin / name; assert tool.is_file()
        if name != 'llvm-lib.exe':
            result = run(name + '-version', [tool, '--version']); assert b'23.1.1' in result
        receipt.setdefault('LLVM_tools', {})[name] = dict(path=str(tool), sha256=sha(tool))
    cmake_archive = release('Kitware/CMake', 'v3.30.5', p['cmake'], p['cmake_sha256'])
    cmake_root = output / 'cmake'; unpack(cmake_archive, cmake_root)
    choices = list(cmake_root.glob('*/bin/cmake.exe')); assert len(choices) == 1; cmake = choices[0]
    assert run('cmake-version', [cmake, '--version']).startswith(b'cmake version 3.30.5')
    environment['PATH'] = str(toolbin) + os.pathsep + str(cmake.parent) + os.pathsep + environment['PATH']
    return toolbin, cmake, receipt
