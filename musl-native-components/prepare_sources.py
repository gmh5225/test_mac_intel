"""Stage public rg and the previously qualified public Linux seccomp source."""
from pathlib import Path
import hashlib
import json
import shutil
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'bun-runtime'))
from prepare_native_sources import prepare as prepare_rg
from native_libraries import sha

HEADER_SHA256 = '3d435576ff6eae7ba661432c2d202464f93bdd216e294659d9e4ae50588f7f61'


def prepare(output, run):
    receipt = prepare_rg(output, run)
    pins = json.loads((ROOT.parent / 'seccomp-helper/pins.json').read_bytes())
    selected = []
    for rel, destination in [('sandbox-runtime/vendor/seccomp-src/apply-seccomp.c', 'apply-seccomp.c'), ('sandbox-runtime/LICENSE', 'SECCOMP-LICENSE')]:
        pin = next(row for row in pins['sources'] if row['file'] == rel)
        path = output / destination
        run('download-seccomp-' + destination, ['curl', '--http1.1', '--fail', '--silent', '--show-error', '--location', '--retry', '3', '--max-time', '300', '--output', path, pin['url']])
        assert path.stat().st_size == pin['bytes'] and sha(path) == pin['sha256']; selected.append(pin)
    assert sha(ROOT / 'unix-block-bpf.h') == HEADER_SHA256
    shutil.copyfile(ROOT / 'unix-block-bpf.h', output / 'unix-block-bpf.h')
    receipt.update(seccomp_sources=selected, generated_filter_header_sha256=HEADER_SHA256,
        generated_filter_origin='Independently qualified public sandbox-runtime/libseccomp Linux filter graph')
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    rows = [dict(file=p.relative_to(output).as_posix(), bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(output.rglob('*')) if p.is_file() and p.name != 'MANIFEST.json']
    (output / 'MANIFEST.json').write_text(json.dumps(dict(files=rows), indent=2) + '\n')
    return receipt
