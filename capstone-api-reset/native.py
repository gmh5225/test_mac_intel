from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess as sp
import tempfile

r = Path(__file__).resolve().parent
original = r.parent / 'source'
out = r.parent / 'evidence'
out.mkdir()
meta = json.loads((r / 'candidate.json').read_text())
feature = json.loads((r / 'feature.json').read_text())
cc = os.environ['CC']


def save(name, value):
    (out / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args, name, expected=0):
    print(name, flush=True)
    with (out / (name + '.log')).open('wb') as log:
        result = sp.run(list(map(str, args)), stdout=log, stderr=sp.STDOUT)
    assert result.returncode == expected, (name, result.returncode, expected)


assert sha(r / 'reset.patch') == meta['sha256']
assert sha(r / 'feature.patch') == feature['sha256']
assert feature['parent'] == meta['parent']
w = Path(tempfile.mkdtemp(prefix='capstone-api-state-reset-'))
s, b = w / 'source', w / 'build'


def git(*args):
    return sp.check_output(['git', '-C', s, *map(str, args)])


def objects():
    root = b / 'CMakeFiles/capstone.dir'
    return {str(f.relative_to(root)): sha(f) for f in root.rglob('*.o')}


try:
    run(['git', 'clone', '-q', '--shared', '--no-checkout', original, s], 'clone')
    git('checkout', '-q', '--detach', meta['parent'])
    save('environment', dict(compiler=sp.check_output([cc, '--version'], text=True),
                             cpu=Path('/proc/cpuinfo').read_text(), candidate=meta, feature=feature))
    run(['cmake', '-S', s, '-B', b, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
         '-DCMAKE_C_COMPILER=' + cc, '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
         '-DCAPSTONE_AARCH64_SUPPORT=ON', '-DCAPSTONE_MIPS_SUPPORT=ON',
         '-DCAPSTONE_BUILD_SHARED_LIBS=ON', '-DCAPSTONE_BUILD_CSTEST=ON',
         '-DCAPSTONE_BUILD_CSTOOL=OFF', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'], 'configure')
    units = ['api', 'mapping', 'mcinst', 'mips_scan', 'aarch64_scan', 'aarch64_postprocess']
    build = ['cmake', '--build', b, '--target', 'capstone_static', 'capstone_shared', *units, '--parallel', '4']
    run(build, 'baseline-build')
    before = objects()
    run(['ctest', '--test-dir', b, '--no-tests=error', '--output-on-failure', '-R', '^unit_api$'], 'baseline-api', 8)
    git('apply', '--index', r / 'reset.patch')
    assert git('write-tree').decode().strip() == meta['tree']
    run(build, 'fixed-build')
    assert objects() == before
    pattern = '^unit_(' + '|'.join(units + ['aarch64_register_names_generator', 'fixed_len_decoder']) + ')$'
    test = ['ctest', '--test-dir', b, '--no-tests=error', '--output-on-failure', '-R', pattern]
    run(test, 'fixed-tests')
    api_hash = sha(b / 'tests/unit/api')
    git('apply', '--index', r / 'feature.patch')
    combined = git('write-tree').decode().strip()
    git('restore', '--source=HEAD', '--staged', '--', 'tests/unit/api.c')
    assert git('write-tree').decode().strip() == feature['tree']
    git('add', 'tests/unit/api.c')
    assert git('write-tree').decode().strip() == combined
    run(build, 'feature-build')
    assert objects() == before
    assert sha(b / 'tests/unit/api') == api_hash
    run(test, 'feature-tests')
    save('runtime-proof', dict(original_objects=len(before), all_identical=True, objects=before,
                               fixed_and_feature_api_binary_identical=True, api_sha256=api_hash))
    save('complete', dict(compiler=cc, source_before=meta['parent'], source_after=meta['tree'],
                         feature_source=feature['tree'], combined_source=combined,
                         baseline_api_failed=True, fixed_tests_passed=True, feature_tests_passed=True,
                         runtime_unchanged=True))
finally:
    amount = sum(f.lstat().st_size for f in w.rglob('*') if f.is_file())
    shutil.rmtree(w)
    save('cleanup', dict(bytes=amount, removed=not w.exists()))
