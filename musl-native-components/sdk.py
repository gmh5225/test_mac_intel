"""Use the admitted musl SDK with one target profile and exact file readback."""
from pathlib import Path
import json
import os
import stat
import sys
import tarfile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'platform-runtime'))
from build_musl_baseline import verify_package
from build_macos import sha


def profile(arch):
    assert arch in ['x64', 'arm64']
    cpu = 'aarch64' if arch == 'arm64' else 'x86_64'
    return dict(triple=cpu + '-alpine-linux-musl', loader='ld-musl-' + cpu + '.so.1',
        libc='libc.musl-' + cpu + '.so.1', sysroot='/opt/linux-sysroot-musl' + ('-arm64' if arch == 'arm64' else ''),
        pcre2_jit=arch == 'x64')


def prepare(arch, package, output):
    pins = json.loads((ROOT.parent / 'platform-runtime/musl-sdk-runtime-pins.json').read_bytes())
    pin = pins['profiles'][arch]; receipt = verify_package(package, pin)
    assert receipt['arch'] == arch and not output.exists()
    output.mkdir()
    # This complete SDK contains case-distinct Linux headers. The producer
    # deliberately requires a native Linux, case-sensitive build filesystem.
    assert sys.platform == 'linux'
    with tarfile.open(package / 'musl-sysroot.tar.gz', 'r:gz') as archive:
        archive.extractall(output, filter='data')
    rows = json.loads((package / 'sysroot-files.json').read_bytes())
    for row in rows:
        path = output / row['file']
        assert not Path(row['file']).is_absolute() and '..' not in Path(row['file']).parts
        if row['kind'] == 'symlink':
            assert path.is_symlink() and os.readlink(path) == row['target'] and path.resolve().is_relative_to(output)
        else:
            assert not path.is_symlink() and path.is_file() and path.stat().st_size == row['bytes']
            assert sha(path) == row['sha256'] and stat.S_IMODE(path.stat().st_mode) == row['mode']
    assert {p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file() or p.is_symlink()} == {r['file'] for r in rows}
    return dict(sdk_pin=pin, producer_run=pins['producer_run'], files_reverified=len(rows),
        independent_qualification_sha256=pins['independent_qualification_sha256'])
