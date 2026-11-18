from pathlib import Path
import hashlib
import json
import os
import platform
import runpy
import shutil
import subprocess as sp
import tempfile

r = Path(__file__).resolve().parent
if os.name == 'nt':
    runpy.run_path(str(r / 'windows-build-driver.py'), run_name='__main__')
    raise SystemExit(0)
out = r.parent / 'evidence'
out.mkdir()
meta = json.loads((r / 'candidate.json').read_text())
profile = os.environ['PROFILE']
w = Path(tempfile.mkdtemp(prefix='capstone-evex-build-'))
s = w / 'source'

def save(name, value):
    (out / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')

def run(name, args, cwd=None):
    with (out / (name + '.log')).open('wb') as log:
        result = sp.run(list(map(str, args)), cwd=cwd, stdout=log, stderr=sp.STDOUT)
    if result.returncode:
        raise RuntimeError((name, (out / (name + '.log')).read_text(errors='replace')[-2500:]))

try:
    run('clone', ['git', 'clone', '-q', '--shared', '--no-checkout', r.parent / 'source', s])
    run('checkout', ['git', 'checkout', '-q', '--detach', meta['parent']], s)
    patch = (r / 'candidate.patch').read_bytes()
    assert hashlib.sha256(patch).hexdigest() == meta['sha256']
    run('apply', ['git', 'apply', '--index', r / 'candidate.patch'], s)
    assert sp.check_output(['git', 'write-tree'], cwd=s, text=True).strip() == meta['tree']
    if profile == 'xcode':
        run('project', ['plutil', '-lint', s / 'xcode/Capstone.xcodeproj/project.pbxproj'])
        run('build', ['xcodebuild', '-project', s / 'xcode/Capstone.xcodeproj',
                     '-configuration', 'Release', '-target', 'CapstoneStatic', '-target', 'CapstoneDynamic',
                     'ARCHS=' + platform.machine(), 'ONLY_ACTIVE_ARCH=YES', 'MACOSX_DEPLOYMENT_TARGET=11.0',
                     'CODE_SIGNING_ALLOWED=NO', 'SYMROOT=' + str(w / 'products'), 'OBJROOT=' + str(w / 'objects')], s)
        archives = list((w / 'products').rglob('libcapstone.a'))
        assert len(archives) == 1
        library = archives[0]
        defines = ['-DCAPSTONE_HAS_X86', '-DCAPSTONE_USE_SYS_DYN_MEM']
    elif profile == 'make':
        run('build', ['make', '-j4', 'CAPSTONE_ARCHS=arm aarch64 mips x86', 'CAPSTONE_STATIC=yes',
                     'CAPSTONE_SHARED=no', 'CAPSTONE_BUILD_CORE_ONLY=yes', 'CC=gcc', 'BUILDDIR=' + str(w / 'make')], s)
        library = w / 'make/libcapstone.a'
        assert library.exists()
        defines = ['-DCAPSTONE_HAS_' + a for a in ('ARM', 'AARCH64', 'MIPS', 'X86')]
        defines += ['-DCAPSTONE_ARM_AARCH64_MIPS_X86', '-DCAPSTONE_USE_SYS_DYN_MEM']
    else:
        raise RuntimeError(profile)
    units = ['x86_simple_output', 'mapping', 'aarch64_postprocess', 'mips_scan']
    for unit in units:
        run('unit-build-' + unit, ['clang', '-O2', '-I', s, '-I', s / 'include', *defines,
                                  s / ('tests/unit/' + unit + '.c'), library, '-lm', '-o', w / unit])
        run('unit-' + unit, [w / unit])
    save('complete', dict(success=True, profile=profile, source=meta, units=units,
                         full_private_output_unit_passed=True, tested_source_tree=meta['tree']))

finally:
    amount = sum(f.stat().st_size for f in w.rglob('*') if f.is_file())
    shutil.rmtree(w)
    save('cleanup', dict(bytes=amount, removed=not w.exists()))
