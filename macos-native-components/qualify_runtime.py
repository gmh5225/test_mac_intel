"""Run the final source engine on matching native Darwin CPUs and OS versions."""
from pathlib import Path
import argparse
import json
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from native_libraries import check_manifest, sha
from native_rg_controls import verify as verify_rg
from macho_runtime import qualify as qualify_macho
from build_runtime import owned_controls


def main():
    p = argparse.ArgumentParser(); p.add_argument('--arch', choices=['arm64', 'x64'], required=True)
    p.add_argument('--package', type=Path, required=True); p.add_argument('--output', type=Path, required=True); a = p.parse_args()
    assert platform.system() == 'Darwin' and platform.machine() == {'arm64': 'arm64', 'x64': 'x86_64'}[a.arch]
    translated = subprocess.run(['/usr/sbin/sysctl', '-n', 'sysctl.proc_translated'], capture_output=True, timeout=5)
    assert translated.stdout != b'1\n', 'Native target qualification cannot use Rosetta'
    assert int(platform.mac_ver()[0].split('.')[0]) in [15,26]
    package = a.package.resolve(); check_manifest(package, sha(package / 'MANIFEST.json'))
    r = json.loads((package / 'receipt.json').read_bytes()); assert r['status'] == 'public_macos_source_native_engine_built' and r['target_arch'] == a.arch
    assert r['recovered_native_roles_integrated'] and not r['captured_client_executed'] and not r['compiled_rust_archive_used']
    binary = package / 'bun'; assert sha(binary) == r['binary_sha256']; binary.chmod(0o500)
    out = a.output.resolve(); out.mkdir(); receipt = dict(status='started', arch=a.arch, native_target_CPU=True,
        runtime_os_version=platform.mac_ver()[0], package_manifest_sha256=sha(package / 'MANIFEST.json'), binary_sha256=sha(binary),
        captured_client_executed=False, actual_recovered_client_acceptance=False, goal_complete=False)
    try:
        receipt['final_macho'] = qualify_macho(binary, a.arch)
        receipt['rg_filename_controls'] = verify_rg(binary, out / 'rg-filename-controls')
        receipt['owned_role_controls'] = owned_controls(binary, a.arch, out / 'owned-role-controls', package / 'bfs-source-library-inputs', package / 'ugrep-source-library-inputs')
        receipt.update(status='native_source_engine_runtime_three_roles_and_768_filename_controls_passed')
    except BaseException as error:
        receipt.update(status='failed_not_admitted', error_type=type(error).__name__, error=str(error)); raise
    finally:
        (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__': main()
