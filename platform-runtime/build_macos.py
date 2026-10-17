"""Build a public macOS Bun baseline with matching LLVM/Rust.

This establishes the platform build boundary before recovered native roles are
added. It never consumes captured clients and cannot admit a recovered engine.
Both targets build on ARM64; x64 execution is a separate native Intel job.
"""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import os
import platform
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
CONFIG_SHA256 = '8df541c3f3f3596b5d90f74161d0e946af2097fbe500a00355be3441bb5c046e'
TOOLS_SHA256 = '19603bce31fd5fd47eab2d70852a48665f9cfa01761df19df0c5cc5b82599e50'
FLAGS_SHA256 = '131cb0fbe11ae8249bace7d39486c30cd800f1e4e3903093c74c12f2b6e3395c'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def curl_config(url, token):
    config = 'url = ' + json.dumps(url) + '\n'
    if url.startswith('https://api.github.com/repos/'):
        # GitHub credentials are opaque; job tokens need not have the same
        # spelling as a local PAT. Only reject header/control injection.
        assert isinstance(token, str) and token and not any(c in token for c in '\r\n\0')
        config += 'header = ' + json.dumps('Authorization: Bearer ' + token) + '\n'
    return config.encode()


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
    # Upstream command failures may dump their child environment. Runner
    # service credentials do not belong in compiler diagnostics either.
    for name in list(env):
        if name.startswith('ACTIONS_') or any(word in name.upper() for word in ['TOKEN', 'SECRET', 'PASSWORD']):
            env.pop(name)
    record = dict(status='started', target_arch=args.arch, build_host_arch='arm64',
                  public_bun_commit=COMMIT, commands=[], captured_client_executed=False,
                  recovered_native_roles_integrated=False, original_prefix_reused=False,
                  original_private_revision_recovered=False, goal_complete=False)

    def run(label, argv, cwd=None, private_input=None, direct_log=False):
        argv = list(map(str, argv)); record['commands'].append(dict(label=label, argv=argv))
        print('Starting ' + label, flush=True)
        with (logs / (label + '.log')).open('xb') as stream:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stream if direct_log else subprocess.PIPE, stderr=subprocess.STDOUT,
                                       stdin=subprocess.PIPE if private_input is not None else subprocess.DEVNULL)
            if private_input is not None:
                process.stdin.write(private_input)
                process.stdin.close()
            if not direct_log:
                for block in iter(lambda: process.stdout.read(65536), b''):
                    stream.write(block); stream.flush(); sys.stdout.buffer.write(block); sys.stdout.buffer.flush()
            code = process.wait()
        if direct_log:
            # Bun's CI annotation wrapper exits with queued pipe writes on a
            # large failed link. A regular log FD retains the complete output.
            with (logs / (label + '.log')).open('rb') as stream:
                stream.seek(max(0, (logs / (label + '.log')).stat().st_size - 12000))
                sys.stdout.buffer.write(stream.read()); sys.stdout.buffer.flush()
        assert code == 0, label + ' failed with exit ' + str(code) + '; inspect retained diagnostics'

    def download(url, dest):
        argv = ['curl', '--http1.1', '--fail', '--location', '--silent', '--show-error',
                '--retry', '3', '--max-time', '900', '--output', str(dest), '--config', '-']
        run('download-' + dest.name, argv, private_input=curl_config(url, api_token))

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
        env['BUN_TOOLCHAIN_LLVM'] = str(toolbin.parent)
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
        assert record['upstream_build_config_sha256'] == CONFIG_SHA256
        flags_file = source / 'scripts/build/flags.ts'; assert sha(flags_file) == FLAGS_SHA256
        flags_before = flags_file.read_text()
        old = '      c.darwin && c.crossTarget !== undefined && c.osxSysroot !== undefined && c.clangResourceDir !== undefined,\n'
        new = '      c.darwin && c.osxSysroot !== undefined && c.clangResourceDir !== undefined,\n'
        assert flags_before.count(old) == 1
        flags_after = flags_before.replace(old, new).replace(
            "    // libc → SDK frameworks. Native darwin builds keep the default search.\n",
            "    // libc → SDK frameworks. Standalone LLVM on Darwin needs this too:\n"
            "    // its bundled libc++ headers can require symbols Apple's library lacks.\n")
        flags_file.write_text(flags_after)
        flags_patch = ''.join(difflib.unified_diff(flags_before.splitlines(True), flags_after.splitlines(True),
            fromfile='public-bun/scripts/build/flags.ts', tofile='qualified-bun/scripts/build/flags.ts'))
        (logs / 'sdk-libcxx-header.patch').write_text(flags_patch)
        record['sdk_libcxx_header_fix'] = dict(before_sha256=FLAGS_SHA256, after_sha256=sha(flags_file),
            patch_sha256=sha(logs / 'sdk-libcxx-header.patch'))
        if args.arch == 'x64':
            config = source / 'scripts/build/config.ts'; before = config.read_text()
            old = '  const darwinCross = darwin && host.os !== "darwin";\n'
            new = '  const darwinCross = darwin && (host.os !== "darwin" || host.arch !== arch);\n'
            assert before.count(old) == 1
            after = before.replace(old, new); config.write_text(after)
            patch = ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                                fromfile='public-bun/scripts/build/config.ts',
                                                tofile='qualified-bun/scripts/build/config.ts'))
            (logs / 'target-architecture.patch').write_text(patch)
            record['target_architecture_fix'] = dict(before_sha256=CONFIG_SHA256, after_sha256=sha(config),
                                                    patch_sha256=sha(logs / 'target-architecture.patch'))
            tools_file = source / 'scripts/build/tools.ts'; assert sha(tools_file) == TOOLS_SHA256
            before = tools_file.read_text(); old = '  if (os !== "darwin" && os !== "windows") {\n'
            new = '  if (os !== "windows") {\n'; assert before.count(old) == 1
            after = before.replace(old, new); tools_file.write_text(after)
            patch = ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                                fromfile='public-bun/scripts/build/tools.ts',
                                                tofile='qualified-bun/scripts/build/tools.ts'))
            (logs / 'darwin-linker-discovery.patch').write_text(patch)
            record['darwin_linker_discovery_fix'] = dict(before_sha256=TOOLS_SHA256, after_sha256=sha(tools_file),
                                                        patch_sha256=sha(logs / 'darwin-linker-discovery.patch'))
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
        sdk = (logs / 'sdk-path.log').read_text().strip()
        assert (Path(sdk) / 'usr/include/stdio.h').is_file()
        # Host tools such as TinyCC's code generator use the discovered clang
        # without target flags. The standalone LLVM driver needs the same SDK
        # that Bun passes explicitly to its target compilation edges.
        env['SDKROOT'] = sdk
        env['MACOSX_DEPLOYMENT_TARGET'] = '13.0'
        run('native-sdk-header-control', [toolbin / 'clang', '-x', 'c', '-fsyntax-only', '-'],
            private_input=b'#include <stdio.h>\nint main(void) { return 0; }\n')
        run('clang-resource-directory', [toolbin / 'clang', '-print-resource-dir'])
        resource_dir = Path((logs / 'clang-resource-directory.log').read_text().strip())
        assert (resource_dir / 'include/stddef.h').is_file()
        control = logs / 'sdk-libcxx-control.cpp'
        control.write_text('#include <unordered_map>\n#include <string>\nint main() { std::unordered_map<std::string, int> values; values["owned"] = 7; return values.at("owned") == 7 ? 0 : 1; }\n')
        target_flags = ['--target=x86_64-apple-macosx', '-march=nehalem'] if args.arch == 'x64' else []
        common = [toolbin / 'clang++', *target_flags, '-std=c++20', '-O2', '-mmacosx-version-min=13.0', '-isysroot', sdk]
        negative = list(map(str, [*common, control, '-o', out / 'default-libcxx-control']))
        record['commands'].append(dict(label='default-libcxx-abi-control', argv=negative))
        result = subprocess.run(negative, env=env, capture_output=True, timeout=120)
        (logs / 'default-libcxx-abi-control.stdout').write_bytes(result.stdout)
        (logs / 'default-libcxx-abi-control.stderr').write_bytes(result.stderr)
        record['default_libcxx_control_exit_code'] = result.returncode
        if result.returncode != 0:
            assert b'__hash_memory' in result.stderr, 'Unexpected C++ header ABI control failure'
        cpp_headers = ['-nostdinc', '-isystem', str(Path(sdk) / 'usr/include/c++/v1'),
            '-isystem', str(resource_dir / 'include'), '-isystem', str(Path(sdk) / 'usr/include'),
            '-iframework', str(Path(sdk) / 'System/Library/Frameworks')]
        executable = out / 'sdk-libcxx-control'
        run('sdk-libcxx-abi-control-build', [*common, *cpp_headers, control, '-o', executable])
        record['sdk_libcxx_control_sha256'] = sha(executable)
        if args.arch == 'arm64': run('sdk-libcxx-abi-control-native', [executable])
        extra_flags = []
        if args.arch == 'x64':
            control = out / 'x64-target-control.c'; control.write_text('#include <stdio.h>\nint main(void) { return 0; }\n')
            obj = out / 'x64-target-control.o'
            run('x64-target-object-control', [toolbin / 'clang', '--target=x86_64-apple-macosx', '-march=nehalem',
                                              '-isysroot', sdk, '-mmacosx-version-min=13.0', '-c', control, '-o', obj])
            assert struct.unpack_from('<II', obj.read_bytes()) == (0xfeedfacf, 0x1000007)
            record['x64_target_object_control_sha256'] = sha(obj)
            extra_flags = ['--macos-sdk=' + sdk]
        run('host-capacity', ['df', '-h', out])
        build_arch = 'aarch64' if args.arch == 'arm64' else 'x64'
        run('public-bun-build', [bun, 'scripts/build.ts', '--profile=release', '--arch=' + build_arch,
                                  '--os=darwin', '--osx-deployment-target=13.0',
                                  '--build-dir=' + str(source / 'build/recovery'), '-j4', *extra_flags], source, direct_log=True)
        binary = source / 'build/recovery/bun'; assert binary.is_file()
        raw = binary.read_bytes()
        assert struct.unpack_from('<II', raw) == (0xfeedfacf, {'arm64': 0x100000c, 'x64': 0x1000007}[args.arch])
        changed = subprocess.check_output(['git', 'status', '--porcelain'], cwd=source, text=True).splitlines()
        expected_changes = [' M scripts/build/config.ts', ' M scripts/build/flags.ts', ' M scripts/build/tools.ts'] if args.arch == 'x64' else [' M scripts/build/flags.ts']
        assert changed == expected_changes
        if args.arch == 'arm64':
            run('native-runtime-version', [binary, '--version'])
            assert (logs / 'native-runtime-version.log').read_text().strip() == '1.4.3'
            run('native-runtime-revision', [binary, '--revision'])
            assert COMMIT[:9] in (logs / 'native-runtime-revision.log').read_text()
        package = out / 'public-runtime'; package.mkdir()
        shutil.copyfile(binary, package / 'bun'); (package / 'bun').chmod(0o500)
        shutil.copyfile(Path(__file__), package / Path(__file__).name)
        record.update(status='public_macos_source_baseline_built',
                      binary_sha256=sha(binary), binary_bytes=binary.stat().st_size,
                      native_arm64_version_controlled=args.arch == 'arm64', captured_source_uploaded=False)
        (package / 'receipt.json').write_text(json.dumps(record, indent=2) + '\n')
        files = [dict(file=p.name, bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(package.iterdir())]
        (package / 'MANIFEST.json').write_text(json.dumps(dict(schema_version=1, files=files), indent=2) + '\n')
    except BaseException as error:
        record.update(status='platform_baseline_failed_not_admitted', error_type=type(error).__name__, error=str(error))
        raise
    finally:
        build = out / 'bun-source/build/recovery'
        for name in ['build.ninja', 'bun-profile.rsp', 'bun.rsp', 'configure.json']:
            path = build / name
            if path.is_file() and path.stat().st_size <= 8 * 1024 * 1024:
                shutil.copyfile(path, logs / name)
        (logs / 'receipt.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    main()
