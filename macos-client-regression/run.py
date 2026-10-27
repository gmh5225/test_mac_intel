"""Stage the existing Mac suite privately; publish only a complete success."""
from pathlib import Path
import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
import traceback

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('Mac_helper_policy', REPO / 'macos-client-behavior/acceptance.py')
policy = importlib.util.module_from_spec(spec); spec.loader.exec_module(policy)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--arch', choices=['arm64', 'x64'], required=True)
    for name in ['package', 'output', 'logs']:
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    private = args.output.resolve(); public = args.logs.resolve()
    private.mkdir(mode=0o700); public.mkdir()
    try:
        control = private / 'own-envelope-control'; control.mkdir()
        (control / 'private-harness-receipt.json').write_text('{"authored_only":true}\n')
        (public / 'own-envelope-control').mkdir()
        encrypted = policy.encryption(control, public / 'own-envelope-control')
        policy.write(public / 'own-envelope-control/receipt.json', encrypted)
        with (private / 'driver.stdout').open('xb') as stdout, (private / 'driver.stderr').open('xb') as stderr:
            completed = subprocess.run([sys.executable, '-B', REPO / 'macos-native-components/client_ci.py',
                '--arch', args.arch, '--package', args.package.resolve(), '--output', private / 'work', '--logs', private / 'staged-success'],
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, timeout=2100)
        assert completed.returncode == 0, 'Existing native Mac client regression failed'
        result = json.loads((private / 'staged-success/receipt.json').read_bytes())
        assert result['status'] == 'both_native_Mac_client_layouts_twice_built_read_back_and_actual_cases_passed' and result['differential_pairs'] == 84
        shutil.copytree(private / 'staged-success', public, dirs_exist_ok=True)
        recipes = public / 'whole-suite-publication-policy'; recipes.mkdir()
        shutil.copyfile(Path(__file__), recipes / 'run.py')
        policy.write(recipes / 'receipt.json', dict(status='complete_native_Mac_regression_published_after_whole_suite_success',
            full_client_pairs=84, source_script_sha256=policy.sha(Path(__file__)), failure_plaintext_publication=False))
        print(json.dumps(dict(status='complete_native_Mac_client_regression_passed', arch=args.arch, pairs=84)))
        return 0
    except Exception as error:
        policy.write(private / 'private-harness-receipt.json', dict(error_type=type(error).__name__, traceback=traceback.format_exc()))
        diagnostics = private / 'execution-records'; diagnostics.mkdir()
        for name in ['driver.stdout', 'driver.stderr']:
            if (private / name).is_file():
                shutil.copyfile(private / name, diagnostics / name)
        for source, name in [
            (private / 'work/private-client-runs/private-records', 'bounded-client-records'),
            (private / 'staged-success', 'staged-observations'),
            (private / 'work/published-input/transport-diagnostic.json', 'published-input-transport.json')]:
            if source.is_dir():
                shutil.copytree(source, diagnostics / name)
            elif source.is_file():
                shutil.copyfile(source, diagnostics / name)
        for source in (private / 'work').glob('*logs*'):
            if source.is_dir():
                shutil.copytree(source, diagnostics / source.name)
        summary = dict(status='failed_private_regression_diagnostics_only', arch=args.arch,
            error_type=type(error).__name__, plaintext_uploaded=False, captured_inputs_uploaded=False)
        try:
            summary['private_diagnostics'] = policy.encryption(private, public)
        except Exception as sealing_error:
            summary['encryption_error_type'] = type(sealing_error).__name__
        policy.write(public / 'receipt.json', summary)
        print(json.dumps(dict(status=summary['status'], error_type=type(error).__name__)))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
