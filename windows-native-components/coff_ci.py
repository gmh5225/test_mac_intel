"""Run authored COFF controls with the pinned native Windows compiler family."""
from pathlib import Path
import argparse
import json
import os
import shutil
import subprocess

from toolchain import ROOT, prepare, sha
from verify_coff_objects import verify


def main():
    p = argparse.ArgumentParser(); p.add_argument('--arch', required=True, choices=['arm64', 'x64']); p.add_argument('--output', type=Path, required=True); a = p.parse_args()
    out = a.output.resolve(); out.mkdir(); logs = out / 'diagnostics'; logs.mkdir()
    env = dict(os.environ); token = env.get('GH_TOKEN')
    for key in list(env):
        if key.startswith('ACTIONS_') or any(v in key.upper() for v in ['TOKEN', 'SECRET', 'PASSWORD']): env.pop(key)
    receipt = dict(status='started', arch=a.arch, captured_input_used=False, object_execution=False, commands=[], goal_complete=False)
    def run(label, command, *, data=None):
        command = list(map(str, command)); print('Starting ' + label, flush=True)
        row = dict(label=label, argv=command); receipt['commands'].append(row)
        with (logs / (label + '.stdout')).open('xb') as stdout, (logs / (label + '.stderr')).open('xb') as stderr:
            process = subprocess.run(command, env=env, input=data, stdout=stdout, stderr=stderr, timeout=1200)
        row['exit_code'] = process.returncode; assert process.returncode == 0, label
        assert (logs / (label + '.stdout')).stat().st_size <= 16 * 1024 * 1024 and (logs / (label + '.stderr')).stat().st_size <= 16 * 1024 * 1024
        return (logs / (label + '.stdout')).read_bytes()
    try:
        toolbin, cmake, receipt['toolchain'] = prepare(a.arch, out, env, run, token)
        package = out / 'public-controls'; package.mkdir()
        controls = verify(toolbin / 'clang.exe', package / 'authored-object-controls', [a.arch])
        assert controls['native_Windows_host'] and '23.1.1' in controls['compiler_version']
        assert len(controls['objects']) == 5 and len(controls['refusals']) == 55
        source = package / 'source'; source.mkdir()
        for name in ['coff_ci.py', 'coff_objects.py', 'verify_coff_objects.py', 'toolchain.py']: shutil.copyfile(ROOT / name, source / name)
        receipt.update(status='native_Windows_pinned_LLVM23_COFF_typed_rename_and_mutation_controls_passed', controls=controls)
        (package / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        files = [dict(file=f.relative_to(package).as_posix(), bytes=f.stat().st_size, sha256=sha(f)) for f in sorted(package.rglob('*')) if f.is_file()]
        (package / 'MANIFEST.json').write_text(json.dumps(dict(schema_version=1, files=files), indent=2) + '\n')
    except BaseException as error:
        receipt.update(status='owned_COFF_control_failed_not_admitted', error_type=type(error).__name__); raise
    finally: (logs / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__': main()
