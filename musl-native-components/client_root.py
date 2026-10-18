"""Owned native ABI controls and a disposable offline tool-fixture root."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import urllib.request

from sdk import ROOT, profile, sha, prepare as prepare_sdk
from runtime_sdk import prepare as prepare_runtime

SHARED = ROOT.parent / 'seccomp-helper'
sys.path.insert(0, str(SHARED))

spec = importlib.util.spec_from_file_location('musl_client_bounded_process', ROOT.parent / 'macos-native-components/bounded_process.py')
bounded = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bounded)


def elf_abi(arch, executable):
    # Standard readelf records; no ldd execution or host-installed musl assumed.
    with executable.open('rb') as stream: header = stream.read(64)
    assert header[:7] == b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H', header, 18)[0] == {'arm64': 183, 'x64': 62}[arch]
    dynamic = subprocess.check_output(['readelf', '-dW', executable], text=True)
    headers = subprocess.check_output(['readelf', '-lW', executable], text=True)
    needed = re.findall(r'\(NEEDED\).*\[([^\]]+)\]', dynamic)
    interpreter = re.findall(r'Requesting program interpreter: ([^\]]+)', headers)
    expected = profile(arch)
    assert needed == [expected['libc']] and interpreter == ['/lib/' + expected['loader']]
    sections = subprocess.check_output(['readelf', '-SW', executable], text=True)
    # The captured producer exports GLIBC-named allocator aliases even on
    # musl. Definitions do not impose a versioned runtime dependency. Every
    # admitted musl input here has no version-requirement section at all.
    assert re.search(r'\]\s+\.gnu\.version_r\s+', sections) is None
    return dict(needed=needed, interpreter=interpreter[0], versioned_import_requirements=[])


def check_static_elf(path, machine):
    raw = path.read_bytes()
    assert raw[:7] == b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H', raw, 18)[0] == machine
    offset = struct.unpack_from('<Q', raw, 32)[0]
    width, count = struct.unpack_from('<HH', raw, 54)
    assert width == 56 and 0 < count < 100 and offset + width * count <= len(raw)
    assert all(struct.unpack_from('<I', raw, offset + width * i)[0] not in [2, 3] for i in range(count))


class Harness:
    def __init__(self, arch, sdk_package, private):
        assert platform.system() == 'Linux' and {'x86_64': 'x64', 'aarch64': 'arm64'}[platform.machine()] == arch
        assert os.getuid() != 0
        self.arch = arch
        self.private = private
        self.logs = private / 'execution-records'; self.logs.mkdir()
        self.inputs = private / 'owned-inputs'; self.inputs.mkdir()
        self.root = private / 'tool-root'; self.root.mkdir()
        self.states = private / 'states'; self.states.mkdir()
        self.sentinel = private / 'outside-sentinel'; self.sentinel.write_text('owned host sentinel\n')
        self.receipt = dict(arch=arch, public_root_inputs=[], boundary_controls=[], process_records=[], host_directories_mounted=False)
        self.bwrap = Path(shutil.which('bwrap'))
        version = self.run('bwrap-package', ['dpkg-query', '-W', '-f=${Version}', 'bubblewrap'])
        assert version['stdout'] == '0.6.1-1ubuntu0.3'
        assert self.run('bwrap-version', [self.bwrap, '--version'])['stdout'].strip() == 'bubblewrap 0.6.1'
        self.receipt['bwrap'] = dict(sha256=sha(self.bwrap), package=version['stdout'])
        sdk = private / 'full-musl-sdk'
        self.receipt['SDK'] = prepare_sdk(arch, sdk_package, sdk)
        self.receipt['runtime_SDK'] = prepare_runtime(arch, sdk_package, self.root / 'recovery-sdk')
        for directory in ['runtime', 'bin', 'usr/bin', 'proc', 'dev', 'tmp', 'report', 'work', 'protected', 'secret', 'home/test', 'etc', 'lib']:
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        (self.root / 'secret/input').write_text('owned secret fixture\n')
        (self.root / 'etc/passwd').write_text(f'test:x:{os.getuid()}:{os.getgid()}:fixture:/home/test:/bin/bash\n')
        (self.root / 'etc/group').write_text(f'test:x:{os.getgid()}:\n')
        (self.root / 'etc/hosts').write_text('127.0.0.1 localhost\n::1 localhost\n')
        (self.root / 'etc/nsswitch.conf').write_text('hosts: files\npasswd: files\ngroup: files\n')
        loader = profile(arch)['loader']
        self.copy_public(sdk / 'lib' / loader, '/lib/' + loader)
        (self.root / 'etc' / loader.replace('.so.1', '.path')).write_text('/recovery-sdk/usr/lib:/recovery-sdk/lib\n')
        self.compile_controls(sdk)
        for name in ['bash', 'sh', 'bwrap', 'socat', 'env', 'which', 'readlink', 'pwd', 'mkdir', 'rm', 'sleep', 'cat', 'dirname', 'basename',
                     'realpath', 'mktemp', 'stat', 'touch', 'chmod', 'sed', 'head', 'tail', 'sort', 'tr', 'uname', 'wc', 'stty', 'date', 'grep', 'ls', 'timeout', 'true']:
            source = Path(shutil.which(name)); assert source.is_absolute() and source.is_file()
            self.copy_public(source, '/bin/' + name)
            if source.read_bytes()[:4] != b'\x7fELF':
                assert name == 'which' and re.fullmatch(rb'#![ \t]*/bin/sh[ \t]*', source.read_bytes().splitlines()[0])
                continue
            result = self.run('ldd-' + name, ['ldd', source])
            for match in re.finditer(r'(?:=>\s*)?(/(?:usr/)?lib[^\s]*)\s+\(', result['stdout']):
                library = Path(match.group(1)); assert library.is_file()
                if not (self.root / library.relative_to('/')).exists(): self.copy_public(library, str(library))
        for name in ['original', 'client-preserved', 'client-readable', 'source-bun']:
            (self.root / 'runtime' / name).touch()

    def run(self, label, command, *, expected=0, timeout=60, limited=False):
        row, stdout, stderr = bounded.run(label, command, self.private, {'PATH': os.defpath, 'LANG': 'C', 'LC_ALL': 'C'}, self.logs,
            wall=timeout, file_bytes=262144 if limited else 512 * 1024 * 1024, cpu=20 if limited else 120)
        self.receipt['process_records'].append(row)
        assert row['failure'] is None and not row['kill_errors'], label + ': bounded supervision failed'
        if expected is not None: assert row['exit_code'] == expected, label + ': process failed; private diagnostics retained'
        return dict(exit_code=row['exit_code'], stdout=stdout.decode(), stderr=stderr.decode())

    def copy_public(self, source, destination):
        target = self.root / destination.lstrip('/'); target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target); target.chmod(0o500 if source.stat().st_mode & 0o111 else 0o400)
        self.receipt['public_root_inputs'].append(dict(source=str(source), destination=destination, sha256=sha(target), mode=oct(target.stat().st_mode & 0o777)))

    def compile_controls(self, sdk):
        wrapper = ROOT / 'control-toolchain'
        pins = json.loads((wrapper / 'pins.json').read_bytes())
        for pin in pins['sources']:
            source = wrapper / pin['file']; assert source.stat().st_size == pin['bytes'] and sha(source) == pin['sha256']
        self.receipt['native_control_compiler'] = dict(official_wrapper=pins, host_gcc=self.run('owned-gcc-version', ['gcc', '--version'])['stdout'], source_engine_toolchain_claim=False)
        specs = self.run('generate-musl-specs', ['/bin/sh', wrapper / 'musl-gcc.specs.sh', sdk / 'usr/include', sdk / 'usr/lib', '/lib/' + profile(self.arch)['loader']])['stdout']
        specs_path = self.inputs / 'musl-control.specs'; specs_path.write_text(specs)
        for name, source in [('client-boundary', ROOT / 'client-boundary.c'), ('bash-payload-dynamic', SHARED / 'bash-payload.c')]:
            target = self.inputs / name
            self.run('compile-' + name, ['gcc', '-specs=' + str(specs_path), '-O2', '-fPIE', '-pie', '-Wall', '-Wextra', '-Werror', source, '-o', target])
            target.chmod(0o500); self.copy_public(target, '/runtime/' + name)
            self.receipt.setdefault('musl_owned_ABI', {})[name] = elf_abi(self.arch, target)
        header = self.inputs / 'include/nlohmann/json.hpp'; header.parent.mkdir(parents=True)
        with urllib.request.urlopen('https://raw.githubusercontent.com/nlohmann/json/v3.11.3/single_include/nlohmann/json.hpp', timeout=60) as stream:
            raw = stream.read(1048576)
        assert hashlib.sha256(raw).hexdigest() == '9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6'
        header.write_bytes(raw)
        for name, source in [('bash-driver', SHARED / 'bash-driver.cpp'), ('bash-payload', SHARED / 'bash-payload.c')]:
            target = self.inputs / name
            cpp = source.suffix == '.cpp'
            self.run('compile-' + name, ['g++' if cpp else 'gcc', *(['-std=c++20', '-I' + str(self.inputs / 'include')] if cpp else []),
                '-static', '-O2', '-Wall', '-Wextra', '-Werror', source, *(['-pthread'] if cpp else []), '-o', target], timeout=180)
            check_static_elf(target, {'arm64': 183, 'x64': 62}[self.arch]); target.chmod(0o500)
            self.copy_public(target, '/runtime/' + name)

    def execute(self, label, command, spec, *, client=None, arguments=(), work_input='fixture input\n', fixture_files=None, extra_env=None):
        state = self.states / label; state.mkdir()
        for name in ['work', 'home', 'protected', 'report']: (state / name).mkdir()
        (state / 'work/input.txt').write_bytes(work_input.encode())
        for name, contents in (fixture_files or {}).items():
            assert Path(name).name == name; (state / 'home' / name).write_text(contents)
        (state / 'report/spec.json').write_text(json.dumps(spec, ensure_ascii=False) + '\n')
        argv = [self.bwrap, '--unshare-all', '--die-with-parent', '--new-session', '--cap-drop', 'ALL', '--uid', str(os.getuid()), '--gid', str(os.getgid()),
            '--ro-bind', self.root, '/', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--bind', state / 'work', '/work',
            '--bind', state / 'home', '/home/test', '--bind', state / 'protected', '/protected', '--bind', state / 'report', '/report']
        assert set(client or {}) <= {'original', 'client-preserved', 'client-readable', 'source-bun'}
        for name, source in (client or {}).items(): argv += ['--ro-bind', source, '/runtime/' + name]
        argv += ['--chdir', '/work', '--clearenv']
        env = dict(HOME='/home/test', TMPDIR='/tmp', XDG_CONFIG_HOME='/home/test/config', XDG_CACHE_HOME='/home/test/cache',
            BUN_INSTALL_CACHE_DIR='/home/test/bun-cache', BUN_RUNTIME_TRANSPILER_CACHE_PATH='0', PATH='/bin:/usr/bin', LANG='C', LC_ALL='C', NO_COLOR='1',
            SHELL='/bin/bash', CLAUDE_CODE_SHELL='/bin/bash', ANTHROPIC_API_KEY='sk-ant-api03-offline-fixture-not-a-real-credential',
            CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1', DISABLE_AUTOUPDATER='1', ENABLE_CLAUDEAI_MCP_SERVERS='false', USE_BUILTIN_RIPGREP='true', BOUNDARY_OUTSIDE=str(self.sentinel))
        assert set(extra_env or {}) <= {'RIPGREP_CONFIG_PATH'}; env.update(extra_env or {})
        for key, value in env.items(): argv += ['--setenv', key, value]
        result = None
        try:
            result = self.run(label, [*argv, '--', '/runtime/bash-driver', *command, *arguments], expected=None, timeout=60, limited=True)
            return result, state
        finally:
            retained = self.logs / label; retained.mkdir()
            for path in (state / 'report').iterdir():
                assert path.is_file() and not path.is_symlink() and path.stat().st_size <= 262144
                shutil.copyfile(path, retained / path.name)
            if result: (retained / 'process.json').write_text(json.dumps(result, indent=2) + '\n')

    def qualify(self, label):
        spec = dict(kind='tool_then_text', tool=dict(name='Read', input=dict(file_path='/work/input.txt')), text='fixture-complete')
        network, _ = self.execute(label + '-network', ['--qualification'], spec)
        assert network['exit_code'] == 0 and not network['stderr']
        rows = json.loads(network['stdout']); assert rows[0]['connect_return'] == 0 and '200 OK' in rows[0]['reply']
        assert [row['errno'] for row in rows[1:]] == [111, 101, 111]
        boundary, _ = self.execute(label + '-musl-ABI', ['/runtime/client-boundary'], spec)
        expected = dict(outside_errno=2, readonly_errno=30, network_result=-1, network_errno=101, uid=os.getuid(), no_new_privs=1)
        assert boundary['exit_code'] == 0 and not boundary['stderr'] and json.loads(boundary['stdout']) == expected
        baseline, state = self.execute(label + '-payload-musl-ABI', ['/runtime/bash-payload-dynamic', 'baseline'], spec)
        assert baseline['exit_code'] == 0 and not baseline['stderr']
        observed = json.loads(baseline['stdout'])
        assert observed['sandboxed'] is False and observed['unix_errno'] == 0 and observed['write_denied_errno'] == 0 and observed['read_bytes'] == 21
        assert (state / 'protected/forbidden').is_file()
        proof = dict(label=label, network=rows, outer_boundary=expected, dynamic_musl_payload=observed)
        self.receipt['boundary_controls'].append(proof)
        return proof
