"""Validate the changed backends in ordinary, DIET and dedicated configurations."""
from pathlib import Path
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess as sp
import tempfile

r = Path(__file__).resolve().parent
source, evidence = r.parent / 'source', r.parent / 'evidence'
evidence.mkdir()
meta = json.loads((r / 'inputs.json').read_text())['candidate']
profile, compiler = os.environ['PROFILE'], os.environ['TOOLCHAIN']
selection = os.environ['ARCH_SET']
arches = ['PPC', 'RISCV', 'LOONGARCH', 'ARC', 'ALPHA', 'SPARC', 'SYSTEMZ', 'TRICORE', 'XTENSA'] if selection == 'combined' else [selection]


def save(name, value):
    (evidence / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')


def run(args, name, check=True):
    with (evidence / (name + '.log')).open('wb') as out:
        result = sp.run(list(map(str, args)), cwd=source, stdout=out, stderr=sp.STDOUT)
    if check and result.returncode:
        raise RuntimeError(name + ': ' + (evidence / (name + '.log')).read_text(errors='replace')[-4000:])
    return result.returncode


w = Path(tempfile.mkdtemp(prefix='capstone-riscv-admission-profile-'))
try:
    assert sp.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip() == meta['parent']
    assert not sp.check_output(['git', 'status', '--porcelain'], cwd=source)
    run(['git', 'config', 'core.autocrlf', 'false'], 'canonical-checkout-config')
    run(['git', 'checkout-index', '-a', '-f'], 'canonical-checkout')
    assert not sp.check_output(['git', 'status', '--porcelain'], cwd=source)
    patch = w / 'candidate.patch'
    canonical = sp.check_output(['git','show','HEAD:capstone-records/candidate.patch'],cwd=r.parent)
    checkout = (r / 'candidate.patch').read_bytes()
    assert hashlib.sha256(canonical).hexdigest() == meta['sha256']
    assert checkout == canonical or checkout.replace(b'\r\n',b'\n') == canonical
    patch.write_bytes(canonical)
    save('patch-source',dict(canonical_sha256=meta['sha256'],
                            checkout_sha256=hashlib.sha256(checkout).hexdigest(),
                            checkout_was_crlf=checkout != canonical))
    save('inputs', dict(candidate=meta, profile=profile, compiler=compiler, arches=arches))
    b = w / 'build'
    options = ['-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
               '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF', '-DCAPSTONE_BUILD_SHARED_LIBS=ON',
               '-DCAPSTONE_BUILD_MACOS_THIN=ON',
               '-DCAPSTONE_BUILD_CSTEST=ON', '-DCAPSTONE_BUILD_CSTOOL=OFF',
               '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
               *['-DCAPSTONE_' + arch + '_SUPPORT=ON' for arch in arches]]
    if os.name == 'nt':
        options += ['-G', 'Visual Studio 17 2022', '-A', 'x64', '-DCMAKE_C_FLAGS=/MP4',
                    '-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=' + ('ON' if compiler == 'MT' else 'OFF')]
    else:
        options += ['-G', 'Ninja', '-DCMAKE_C_COMPILER=' + compiler]
        if compiler == 'gcc':
            options += ['-DCMAKE_C_FLAGS=-Wno-error=discarded-qualifiers']
    if profile == 'diet':
        options += ['-DCAPSTONE_BUILD_DIET=ON']
    if profile == 'sanitize':
        options += ['-DENABLE_ASAN=ON', '-DCMAKE_C_FLAGS=-fsanitize=undefined',
                    '-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=undefined',
                    '-DCMAKE_SHARED_LINKER_FLAGS=-fsanitize=undefined']
    run(['cmake', '-S', source, '-B', b, *options], 'configure')
    run(['cmake', '--build', b, '--config', 'Release', '--parallel', '4'], 'base-build')
    test_args = ['ctest', '--test-dir', b, '-C', 'Release', '--no-tests=error',
                 '--output-on-failure', '-R', '^unit_']
    baseline_status = run(test_args, 'base-tests', check=False)
    library = None
    if os.name != 'nt':
        extension = '.dylib' if os.uname().sysname == 'Darwin' else '.so'
        library = b / ('libcapstone' + extension)
        shutil.copyfile(library, w / ('base' + extension))
    run(['git', '-c', 'core.autocrlf=false', 'apply', '--index', patch], 'apply')
    tree = sp.check_output(['git', 'write-tree'], cwd=source, text=True).strip()
    assert tree == meta['tree']
    run(['cmake', '--build', b, '--config', 'Release', '--parallel', '4'], 'candidate-build')
    candidate_status = run(test_args, 'candidate-tests', check=False)
    boundary = 'Not run on Windows; public unit suite runs on both source variants.'
    if library is not None and selection == 'combined':
        flags = ['-fsanitize=address,undefined'] if profile == 'sanitize' else []
        cxx = 'g++' if compiler == 'gcc' else 'clang++'
        run([cxx, '-O2', '-std=c++17', *flags, '-I', source / 'include',
             r / 'verify-extra.cpp', '-ldl', '-o', w / 'records'], 'records-link')
        run([w / 'records', w / ('base' + extension), library, '4096'], 'records')
        boundary = (evidence / 'records.log').read_text().splitlines()[-1]
    elif library is not None:
        boundary = 'Dedicated RISC-V public unit suite and generator regression tests.'
    save('test-status', dict(baseline=baseline_status, candidate=candidate_status, boundary=boundary))
    assert baseline_status == candidate_status == 0
    assert all('runtime error:' not in (evidence / (name + '.log')).read_text(errors='replace')
               for name in ('base-tests', 'candidate-tests', *(['records'] if library is not None and selection == 'combined' else [])))
    run(['python', 'suite/synctools/fixed_len_decoder.py', '--check'], 'generator-check')
    save('complete', dict(success=True, tree=tree, profile=profile, compiler=compiler,
                          arches=arches, boundary=boundary))
finally:
    amount = sum(f.stat().st_size for f in w.rglob('*') if f.is_file())
    def remove_readonly(fn, path, exc):
        os.chmod(path, 0o700)
        fn(path)
    shutil.rmtree(w, onerror=remove_readonly)
    save('cleanup', dict(removed=not w.exists(), bytes=amount))
