"""Check the scoped tree against both original runtime variants."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess as sp
import tempfile

r = Path(__file__).resolve().parent
source, evidence = r.parent / 'source', r.parent / 'evidence'
evidence.mkdir()


def save(name, value):
    (evidence / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')


def run(args, label):
    with (evidence / (label + '.log')).open('wb') as out:
        sp.run(list(map(str, args)), cwd=source, stdout=out,
               stderr=sp.STDOUT, check=True)


def git(*args):
    return sp.check_output(['git', '-C', source, *args], text=True).strip()


w = Path(tempfile.mkdtemp(prefix='capstone-tricore-qualified-identity-'))
try:
    inputs = json.loads((r / 'inputs.json').read_text())
    assert git('rev-parse', 'HEAD') == inputs['capstone']
    assert not git('status', '--porcelain')
    cc = os.environ['MEASURE_CC']
    compiler = sp.check_output([cc, '--version'], text=True)
    profile = os.environ['RUNNER_PROFILE']
    old = next(row for row in json.loads((r / 'reference-binaries.json').read_text())
               if row['profile'] == profile)
    assert compiler == old['compiler'], (compiler, old['compiler'])
    inactive = cc == 'gcc' and sp.check_output(
        [cc, '-dumpversion'], text=True).strip().split('.')[0] == '11'
    save('inputs', inputs)
    save('cpu', dict(cpu=Path('/proc/cpuinfo').read_text(), compiler=compiler,
                     profile=profile, inactive=inactive))
    build = w / 'build'
    run(['cmake', '-S', source, '-B', build, '-G', 'Ninja',
         '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_COMPILER=' + cc,
         '-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer ' +
         ('-Wno-error=discarded-qualifiers' if cc == 'gcc' else
          '-Wno-error=incompatible-pointer-types-discards-qualifiers'),
         '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
         *['-DCAPSTONE_' + arch + '_SUPPORT=ON' for arch in
           ['X86', 'ARM', 'AARCH64', 'MIPS', 'PPC', 'RISCV', 'LOONGARCH', 'ARC', 'TRICORE']],
         '-DCAPSTONE_BUILD_SHARED_LIBS=OFF', '-DCAPSTONE_BUILD_CSTEST=OFF',
         '-DCAPSTONE_BUILD_CSTOOL=OFF', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'], 'configure')
    objects, binaries = {}, {}
    for label in ['baseline', 'reference', 'candidate']:
        if label != 'baseline':
            meta = inputs[label]
            patch = r / (label + '.patch')
            assert hashlib.sha256(patch.read_bytes()).hexdigest() == meta['sha256']
            run(['git', 'apply', '--index', patch], label + '-apply')
            assert git('write-tree') == meta['tree']
        run(['cmake', '--build', build, '--target', 'capstone_static',
             '--parallel', '4'], label + '-build')
        objroot = build / 'CMakeFiles/capstone.dir'
        objects[label] = {str(f.relative_to(objroot)): hashlib.sha256(f.read_bytes()).hexdigest()
                          for f in objroot.rglob('*.o')}
        exe = w / label
        run(['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-I', source,
             '-I', source / 'include', r / 'single.cpp', build / 'libcapstone.a',
             '-lm', '-o', exe], label + '-link')
        binaries[label] = hashlib.sha256(exe.read_bytes()).hexdigest()
        if label != 'baseline':
            run(['git', 'reset', '--hard', inputs['capstone']], label + '-restore')
            assert not git('status', '--porcelain')
    save('objects', objects)
    save('binaries', binaries)
    selected = 'baseline' if inactive else 'reference'
    assert objects['candidate'] == objects[selected]
    assert binaries['candidate'] == binaries[selected]
    # The preceding timing run used these exact executable bytes, not merely
    # a matching source revision or similar symbol sizes.
    assert binaries['baseline'] == old['sha256']['integer']
    assert binaries['reference'] == old['sha256']['scan']
    changed = sorted(k for k in objects['baseline']
                     if objects['baseline'][k] != objects['reference'][k])
    assert changed == ['arch/TriCore/TriCoreDisassembler.c.o'], changed
    save('complete', dict(success=True, tree=inputs['candidate']['tree'],
                          selected=selected, profile=profile,
                          objects=len(objects['candidate']),
                          exact_runtime_identity=True,
                          exact_prior_timed_binaries=True,
                          baseline_reference_delta=changed))
finally:
    files = [f for f in w.rglob('*') if f.is_file()]
    size = sum(f.stat().st_size for f in files)
    shutil.rmtree(w)
    save('cleanup', dict(removed=not w.exists(), bytes=size, files=len(files)))
