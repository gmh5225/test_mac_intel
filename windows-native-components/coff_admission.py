"""Require the independently replayed native checker before component mutation."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parent


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def qualify(arch):
    pins = json.loads((ROOT / 'coff-checker-pins.json').read_bytes())
    evidence = ROOT / 'coff-native-controls-qualification.json'
    assert pins['schema_version'] == 1 and set(pins['profiles']) == {'arm64', 'x64'}
    assert sha(evidence) == pins['independent_qualification_sha256']
    controls = json.loads(evidence.read_bytes())
    assert controls['run'] == pins['producer_run'] and controls['head'] == pins['producer_head']
    assert controls['profiles'] == pins['profiles']
    assert controls['total_authentic_objects'] == controls['local_LLVM_readobj_header_cross_checks'] == 10
    assert controls['total_refused_mutations'] == 110 and not controls['object_execution']
    for profile in pins['profiles'].values():
        assert profile['authentic_objects'] == profile['LLVM_readobj_header_cross_checks'] == 5
        assert profile['refused_mutations'] == 55 and not profile['object_execution']
        for name, field in [('coff_objects.py', 'checker'), ('verify_coff_objects.py', 'driver')]:
            raw = (ROOT / name).read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            if digest != profile['canonical_' + field + '_sha256']:
                assert digest == profile['native_checkout_' + field + '_sha256']
                assert hashlib.sha256(raw.replace(b'\r\n', b'\n')).hexdigest() == profile['canonical_' + field + '_sha256']
    assert arch in pins['profiles']
    return dict(status='independently_qualified_native_COFF_checker_admitted', arch=arch,
        checker_sha256=sha(ROOT / 'coff_objects.py'), driver_sha256=sha(ROOT / 'verify_coff_objects.py'),
        pin_sha256=sha(ROOT / 'coff-checker-pins.json'), independent_qualification_sha256=sha(evidence),
        producer_run=pins['producer_run'], native_objects=10, refused_mutations=110)
