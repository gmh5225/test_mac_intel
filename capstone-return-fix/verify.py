from pathlib import Path
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess as sp
import tempfile

r = Path(__file__).resolve().parent
p = r.parent
evidence = p / 'evidence'
evidence.mkdir()
base = p / 'source'
meta = json.loads((r / 'candidate.json').read_text())
compiler = os.environ['CC']
profile = os.environ['PROFILE']


def save(name, value):
    (evidence / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')


def run(args, label, checked=True, cwd=None, timeout=1200):
    print(label, flush=True)
    with (evidence / (label + '.log')).open('wb') as log:
        result = sp.run(list(map(str, args)), stdout=log, stderr=sp.STDOUT,
                        cwd=cwd, timeout=timeout)
    if checked and result.returncode:
        raise RuntimeError((label, result.returncode, (evidence / (label + '.log')).read_text(errors='replace')[-3500:]))
    return result.returncode


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def objects(build):
    directory = build / ('capstone.dir' if os.name == 'nt' else 'CMakeFiles/capstone.dir')
    return {str(x.relative_to(directory)): sha(x) for x in directory.rglob('*.obj' if os.name == 'nt' else '*.o')}


def clean_error(fn, path, exc):
    os.chmod(path, 0o700)
    fn(path)


w = Path(tempfile.mkdtemp(prefix='capstone-return-fix-'))
try:
    version = 'MSVC via Visual Studio 17 2022' if os.name == 'nt' else sp.check_output([compiler, '--version'], text=True)
    match = re.search(r'clang version (\d+)', version)
    affected = platform.machine() in ('x86_64', 'AMD64') and match is not None and int(match[1]) < 17
    save('environment', dict(compiler=compiler, version=version, profile=profile, machine=platform.machine(),
         platform=platform.platform(), affected=affected, cmake=sp.check_output(['cmake', '--version'], text=True)))
    s, b = w / 'source', w / 'build'
    run(['git', 'clone', '-q', '--shared', '--no-checkout', '--config', 'core.autocrlf=false', base, s], 'clone')
    run(['git', '-C', s, 'checkout', '-q', '--detach', meta['parent']], 'checkout')
    patch = w / 'candidate.patch'
    raw = sp.check_output(['git', '-C', p, 'show', 'HEAD:capstone-return-fix/candidate.patch'])
    assert hashlib.sha256(raw).hexdigest() == meta['sha256']
    patch.write_bytes(raw)
    run(['git', '-C', s, 'apply', '--index', '--include=tests/unit/api.c', patch], 'regression-only')
    opts = ['-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
            '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
            *['-DCAPSTONE_' + a + '_SUPPORT=ON' for a in ['X86', 'ARM', 'AARCH64', 'MIPS']],
            '-DCAPSTONE_BUILD_STATIC_LIBS=ON', '-DCAPSTONE_BUILD_SHARED_LIBS=ON',
            '-DCAPSTONE_BUILD_CSTEST=ON', '-DCAPSTONE_BUILD_CSTOOL=OFF',
            '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF', '-DCAPSTONE_BUILD_MACOS_THIN=ON']
    if os.name == 'nt':
        opts += ['-G', 'Visual Studio 17 2022', '-A', 'x64', '-DCMAKE_C_FLAGS=/MP4']
    else:
        opts += ['-G', 'Ninja', '-DCMAKE_C_COMPILER=' + compiler]
        if compiler.startswith('clang'):
            opts += ['-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer -Wno-error=incompatible-pointer-types-discards-qualifiers']
        else:
            opts += ['-DCMAKE_C_FLAGS=-Wno-error=discarded-qualifiers']
    opts += {
        'four': [], 'all': ['-DCAPSTONE_ARCHITECTURE_DEFAULT=ON'],
        'dedicated': ['-DCAPSTONE_' + a + '_SUPPORT=OFF' for a in ['ARM', 'AARCH64', 'MIPS']],
        'diet': ['-DCAPSTONE_BUILD_DIET=ON'], 'reduced': ['-DCAPSTONE_X86_REDUCE=ON'],
        'adapter': ['-DCAPSTONE_X86_SCAN_ADAPTER=ON'],
    }[profile]
    run(['cmake', '-S', s, '-B', b, *opts], 'configure')
    build = ['cmake', '--build', b, '--config', 'Release', '--parallel', '4']
    run([*build, '--target', 'capstone_static', 'capstone_shared', 'api'], 'baseline-build')
    inventory = json.loads(sp.check_output(['ctest', '--test-dir', b, '-C', 'Release', '--show-only=json-v1', '-R', '^unit_api$'], text=True))
    api = Path(inventory['tests'][0]['command'][0])
    status = run([api], 'baseline-regression', checked=False)
    save('baseline-regression', dict(returncode=status, expected_failure=affected))
    assert (status != 0) == affected, (version, status)
    before = objects(b)
    assert before
    run(['git', '-C', s, 'apply', '--index', '--include=cs_priv.h', patch], 'fix')
    tested_tree = sp.check_output(['git', '-C', s, 'write-tree'], text=True).strip()
    assert tested_tree == meta['tree']
    run([*build, '--target', 'capstone_static', 'capstone_shared', 'api'], 'fixed-build')
    run([api], 'fixed-regression')
    after = objects(b)
    assert before.keys() == after.keys()
    changed = [name for name in before if before[name] != after[name]]
    assert bool(changed) == affected, (affected, changed)
    save('runtime-objects', dict(total=len(after), changed=changed, identical=not changed))
    if profile in ('diet', 'reduced'):
        units = ['api', 'mapping', 'mcinst', 'x86_scan_batch', 'x86_relative_jump', 'x86_reg_access', 'detail_option', 'x86_diet_feature_details']
        run([*build, '--target', *units], 'build-units')
        regex = '^unit_(' + '|'.join(units) + ')$'
    else:
        run(build, 'build-units')
        regex = '^unit_'
    inventory = json.loads(sp.check_output(['ctest', '--test-dir', b, '-C', 'Release', '--show-only=json-v1', '-R', regex], text=True))
    save('unit-inventory', dict(tests=[x['name'] for x in inventory['tests']]))
    run(['ctest', '--test-dir', b, '-C', 'Release', '--no-tests=error', '--output-on-failure', '--parallel', '2', '-R', regex], 'tests')
    log = (evidence / 'tests.log').read_text()
    count = re.search(r'100% tests passed, 0 tests failed out of (\d+)', log)
    assert count and int(count[1]) == len(inventory['tests'])
    save('test-summary', dict(count=int(count[1]), skipped=[line.strip() for line in log.splitlines() if '***Skipped' in line]))
    if os.name != 'nt':
        probe = w / 'probe-static'
        run([compiler, '-O2', '-I', s / 'include', r / 'abi-probe.c', b / 'libcapstone.a', '-o', probe], 'link-probe-static')
        run([probe], 'probe-static')
        shared = w / 'probe-shared'
        run([compiler, '-O2', '-I', s / 'include', r / 'abi-probe.c', '-L' + str(b), '-lcapstone', '-Wl,-rpath,' + str(b), '-o', shared], 'link-probe-shared')
        run([shared], 'probe-shared')
    if affected and profile == 'four':
        import deb
        label, bits, data, spans, provenance = next(x for x in deb.prepare(w) if x[0] == 'libjpeg62-turbo-amd64')
        intervals = w / 'intervals.tsv'
        intervals.write_text(''.join('%d %d %d\n' % item for item in spans))
        expected = json.loads((r / 'input.json').read_text())
        assert sha(data) == expected['text_sha256'] and sha(intervals) == expected['intervals_sha256']
        vectors = w / 'vectors'
        cxx = compiler.replace('clang', 'clang++', 1)
        run([cxx, '-O2', '-I', s / 'include', r / 'vectors.cpp', b / 'libcapstone.a', '-o', vectors], 'link-original-vectors')
        run([vectors, str(bits), data, intervals], 'original-vectors')
        assert sha(evidence / 'original-vectors.log') == 'c9601fbf18278545a1f9786107efc00fec32c08a213e1fc1013a3e79cfd4ebe2'
        save('original-vectors', dict(functions=len(spans), lines=len((evidence / 'original-vectors.log').read_text().splitlines()),
             input_sha256=sha(data), output_sha256=sha(evidence / 'original-vectors.log'), provenance=provenance))
        if compiler == 'clang-14':
            make = w / 'make-build'
            run(['make', '-j4', 'CAPSTONE_ARCHS=x86', 'CAPSTONE_BUILD_CORE_ONLY=yes', 'CC=' + compiler, 'BUILDDIR=' + str(make), make / 'libcapstone.a'], 'make-build', cwd=s)
            run([compiler, '-O2', '-I', s / 'include', '-I', s / 'tests/unit/include', s / 'tests/unit/api.c', make / 'libcapstone.a', '-lm', '-o', w / 'make-api'], 'make-api-link')
            run([w / 'make-api'], 'make-api')
    save('complete', dict(success=True, tested_tree=tested_tree, compiler=compiler, profile=profile,
                         baseline_failure_reproduced=affected, tests=int(count[1]), runtime_objects_identical=not changed))
finally:
    amount = sum(f.stat().st_size for f in w.rglob('*') if f.is_file())
    shutil.rmtree(w, onerror=clean_error)
    save('cleanup', dict(bytes=amount, removed=not w.exists()))
