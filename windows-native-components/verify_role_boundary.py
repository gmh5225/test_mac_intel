"""Native UTF-16 argv and CRT/OS environment consumption controls."""
from pathlib import Path
import argparse
import json
import os
import platform
import shutil
import subprocess
from coff_admission import sha

ROOT = Path(__file__).resolve().parent
CHANNEL = 'nightly-2026-09-15'


def main():
    p = argparse.ArgumentParser(); p.add_argument('--arch', required=True, choices=['x64', 'arm64'])
    p.add_argument('--output', type=Path, required=True); a = p.parse_args()
    assert platform.system() == 'Windows' and os.environ['RUNNER_ARCH'].lower() == a.arch
    out = a.output.resolve(); out.mkdir(); logs = out / 'diagnostics'; logs.mkdir(); source = out / 'source'; source.mkdir()
    env = dict(os.environ)
    for key in list(env):
        if key.startswith('ACTIONS_') or any(v in key.upper() for v in ['TOKEN', 'SECRET', 'PASSWORD']): env.pop(key)
    env.update(RUSTUP_HOME=str(out / 'rustup'), CARGO_HOME=str(out / 'cargo'), RUSTUP_TOOLCHAIN=CHANNEL)
    receipt = dict(status='started', arch=a.arch, commands=[], cases=[], public_authored_inputs_only=True,
        full_engine_integrated=False, captured_input_used=False, goal_complete=False)
    def run(label, command, *, environment=None):
        r = subprocess.run(list(map(str, command)), cwd=out, env=environment or env, capture_output=True, timeout=1200)
        (logs / (label + '.stdout')).write_bytes(r.stdout); (logs / (label + '.stderr')).write_bytes(r.stderr)
        receipt['commands'].append(dict(label=label, exit_code=r.returncode)); assert r.returncode == 0, label
        return r.stdout
    try:
        for name in ['role_boundary.rs', 'role-boundary-control.rs']: shutil.copyfile(ROOT / name, source / name)
        shutil.copyfile(ROOT.parent / 'native-role-contracts/windows.rs', source / 'windows_role_contract.rs')
        rustup = shutil.which('rustup'); assert rustup
        run('install-native-Rust', [rustup, 'toolchain', 'install', CHANNEL, '--profile', 'minimal'])
        run('Rust-version', [rustup, 'run', CHANNEL, 'rustc', '-vV'])
        control = out / 'role-boundary-control.exe'
        run('build-native-control', [rustup, 'run', CHANNEL, 'rustc', '--edition=2024', '-O', '-Dwarnings', '-Dunreachable-pub', '-Ctarget-feature=+crt-static',
            source / 'role-boundary-control.rs', '-o', control])
        # Popen's executable selects the image while argv[0] remains independently
        # controlled, matching the qualified native CreateProcess transport.
        payload = ['', 'two words', 'quote"here', 'trailing\\', 'λ猫 🐈', '\ud800', '\udfff']
        cases = [('absent', 'owned-client', None, 255), ('empty', 'owned-client', '', 255),
            ('unknown', 'owned-client', '猫', 255), ('env-rg', 'owned-client', 'rg', 0),
            ('env-ugrep', 'owned-client', 'ugrep', 1), ('actual-rg', 'C:\\owned 猫\\rg.exe', 'ugrep', 0),
            ('actual-ugrep', '/owned/ugrep', 'rg', 1), ('actual-uppercase-fallback', 'RG.EXE', 'ug', 1),
            ('env-path-is-raw', 'owned-client', 'C:\\rg.exe', 255), ('bfs-normal-runtime', 'bfs', 'bfs', 255),
            ('seccomp-normal-runtime', 'apply-seccomp', 'apply-seccomp', 255)]
        for label, argv0, value, role in cases:
            current = dict(env); current.pop('ARGV0', None)
            if value is not None: current['ARGV0'] = value
            r = subprocess.run([argv0, *payload], executable=control, cwd=out, env=current, capture_output=True, timeout=30)
            (logs / (label + '.stdout')).write_bytes(r.stdout); (logs / (label + '.stderr')).write_bytes(r.stderr)
            assert r.returncode == 0 and not r.stderr, label
            rows = r.stdout.decode('ascii').splitlines(); fields = [line for line in rows if line.startswith('arg:')]
            expected = [''.join(f'{int.from_bytes(v[i:i+2], "little"):04x}' for i in range(0, len(v), 2))
                for v in [s.encode('utf-16-le', errors='surrogatepass') for s in [argv0, *payload]]]
            assert [s[4:] for s in fields] == expected, 'UTF-16 argument units changed: ' + label
            assert 'role:' + str(role) in rows and 'after:(false, false, false)' in rows and 'fresh_child:(false, false, false)' in rows
            assert 'vectors:196499' in rows
            receipt['cases'].append(dict(case=label, role=role, stdout_sha256=sha(logs / (label + '.stdout')),
                UTF16_units_preserved=True, CRT_narrow_wide_OS_and_child_consumed=True, classifier_vectors=196499))
        receipt.update(status='native_Windows_UTF16_role_selection_and_all_environment_views_consumed',
            control_sha256=sha(control), source_hashes={f.name: sha(f) for f in source.iterdir()},
            native_process_cases=len(cases), UTF16_payload_arguments=len(payload))
    except BaseException as error:
        receipt.update(status='owned_Windows_role_boundary_failed_not_admitted', error_type=type(error).__name__, error=str(error)); raise
    finally: (logs / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__': main()
