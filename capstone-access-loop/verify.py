from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess as sp
import tempfile

r = Path(__file__).resolve().parent
out = r.parent / 'evidence'
out.mkdir()
metadata = json.loads((r / 'candidate.json').read_text())
compiler, profile = os.environ['TOOLCHAIN'], os.environ['PROFILE']
w = Path(tempfile.mkdtemp(prefix='capstone-access-loop-'))
s, b = w / 'source', w / 'build'

def save(name, value):
    (out / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')

def run(name, args, cwd=None):
    with (out / (name + '.log')).open('wb') as log:
        result = sp.run(list(map(str, args)), cwd=cwd, stdout=log, stderr=sp.STDOUT)
    if result.returncode:
        raise RuntimeError((name, (out / (name + '.log')).read_text(errors='replace')[-3500:]))

def git(*args):
    return sp.check_output(['git', '-C', s, *args], text=True).strip()

def clean_error(function, path, exception):
    os.chmod(path, 0o700)
    function(path)

try:
    run('clone', ['git', 'clone', '-q', '--shared', '--no-checkout', '--config', 'core.autocrlf=false', r.parent / 'source', s])
    git('checkout', '-q', '--detach', metadata['parent'])
    assert not git('status', '--porcelain')
    patch = sp.check_output(['git', '-C', r.parent, 'show', 'HEAD:capstone-access-loop/candidate.patch'])
    assert hashlib.sha256(patch).hexdigest() == metadata['sha256']
    (w / 'candidate.patch').write_bytes(patch)
    git('apply', '--index', str(w / 'candidate.patch'))
    assert git('write-tree') == metadata['tree']
    options = ['-DCMAKE_BUILD_TYPE=Release', '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
               *['-DCAPSTONE_' + arch + '_SUPPORT=ON' for arch in ('X86', 'ARM', 'AARCH64', 'MIPS')],
               '-DCAPSTONE_BUILD_MACOS_THIN=ON', '-DCAPSTONE_BUILD_CSTEST=ON',
               '-DCAPSTONE_BUILD_CSTOOL=OFF', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
    if os.name == 'nt':
        options += ['-G', 'Visual Studio 17 2022', '-A', 'x64', '-DCMAKE_C_FLAGS=/MP4',
                    '-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=' + ('ON' if compiler == 'MT' else 'OFF')]
    else:
        options += ['-G', 'Ninja', '-DCMAKE_C_COMPILER=' + compiler]
        if compiler == 'gcc':
            options += ['-DCMAKE_C_FLAGS=-Wno-error=discarded-qualifiers']
    if profile == 'diet':
        options += ['-DCAPSTONE_BUILD_DIET=ON']
    elif profile == 'reduced':
        options += ['-DCAPSTONE_X86_REDUCE=ON']
    elif profile == 'adapter':
        options += ['-DCAPSTONE_X86_SCAN_ADAPTER=ON']
    elif profile == 'sanitize':
        options += ['-DENABLE_ASAN=ON', '-DCMAKE_C_FLAGS=-fsanitize=undefined', '-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=undefined']
    if profile == 'no-x86':
        options += ['-DCAPSTONE_X86_SUPPORT=OFF']
    units = ['api', 'utils', 'mapping', 'register_descriptors', 'sstream',
             'x86_reg_access', 'detail_option', 'text_option',
             'x86_encoding_accuracy', 'x86_scan_batch', 'x86_buffer_bounds', 'x86_memory_scale']
    if profile not in ('diet', 'reduced'):
        units += ['x86_simple_output', 'x86_printer_prechecked',
                  'arm_post_index', 'aarch64_postprocess', 'mips_scan']
    if profile not in ('diet', 'reduced', 'no-x86'):
        units = sorted(set(units) | {f.stem for f in (s / 'tests/unit').glob('x86_*.c') if f.stem.startswith(('x86_apx', 'x86_amx', 'x86_evex'))})
    if profile == 'adapter':
        units += ['x86_scan_adapter']
    if profile == 'no-x86':
        units = ['api', 'utils', 'mapping', 'register_descriptors', 'sstream', 'instruction_bytes', 'mcinst', 'feature_mode', 'arm_post_index', 'arm_private_stream', 'arm_reg_access', 'aarch64_scan', 'aarch64_postprocess', 'mips_scan']
    run('configure', ['cmake', '-S', s, '-B', b, *options])
    run('build', ['cmake', '--build', b, '--config', 'Release', '--target', 'capstone_static', *units, '--parallel', '4'])
    run('tests', ['ctest', '--test-dir', b, '-C', 'Release', '--no-tests=error', '--output-on-failure', '--output-junit', out / 'tests.xml', '-R', '^unit_(' + '|'.join(units) + ')$'])
    assert 'runtime error:' not in (out / 'tests.log').read_text()
    import xml.etree.ElementTree as ET
    cases = ET.parse(out / 'tests.xml').getroot().findall('testcase')
    assert len(cases) == len(units) and all(case.find('skipped') is None for case in cases)
    save('complete', dict(compiler=compiler, profile=profile, units=units, source=metadata, success=True))
finally:
    size = sum(path.stat().st_size for path in w.rglob('*') if path.is_file())
    shutil.rmtree(w, onerror=clean_error)
    save('cleanup', dict(bytes=size, removed=not w.exists()))
