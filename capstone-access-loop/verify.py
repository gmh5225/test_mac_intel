from pathlib import Path
import hashlib
import json
import os
import platform
import shlex
import shutil
import subprocess as sp
import tempfile

r = Path(__file__).resolve().parent
s = r.parent / 'source'
e = r.parent / 'evidence'
e.mkdir()
cc = os.environ['MEASURE_CC']
sha = lambda f: hashlib.sha256(f.read_bytes()).hexdigest()
meta = {key: json.loads((r / (key + '.json')).read_text()) for key in ('prior', 'candidate')}

def write(name, data):
    (e / (name + '.json')).write_text(json.dumps(data, indent=2) + '\n')

def run(label, args, cwd=None):
    print(label, flush=True)
    with (e / (label + '.log')).open('w') as stream:
        result = sp.run(list(map(str, args)), cwd=cwd, stdout=stream, stderr=sp.STDOUT)
    if result.returncode:
        raise RuntimeError((label, (e / (label + '.log')).read_text()[-2500:]))

def git(*args):
    return sp.check_output(['git', '-C', s, *args], text=True).strip()

assert git('rev-parse', 'HEAD') == meta['prior']['parent'] == meta['candidate']['parent']
for key in meta:
    assert sha(r / (key + '.patch')) == meta[key]['sha256']
write('inputs', dict(source=meta, consumer_sha256=sha(r / 'single.cpp')))
write('compiler', dict(compiler=sp.check_output([cc, '--version'], text=True), host=platform.platform()))

with tempfile.TemporaryDirectory(prefix='capstone-evex-host-identity-') as temporary:
    t = Path(temporary)
    b = t / 'build'
    try:
        run('consumer', ['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-I', s,
                         '-I', s / 'include', '-c', r / 'single.cpp', '-o', t / 'single.o'])
        run('configure', ['cmake', '-S', s, '-B', b, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
            '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', '-DCMAKE_C_COMPILER=' + cc,
            '-DCMAKE_C_FLAGS=' + ('-Wno-error=discarded-qualifiers' if cc == 'gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),
            '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
            *['-DCAPSTONE_' + a + '_SUPPORT=ON' for a in ('X86', 'ARM', 'AARCH64', 'MIPS')],
            '-DCAPSTONE_BUILD_SHARED_LIBS=ON', '-DCAPSTONE_BUILD_CSTEST=ON',
            '-DCAPSTONE_BUILD_MACOS_THIN=ON', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
            '-DCAPSTONE_BUILD_CSTOOL=OFF'])
        units = sorted(set(['api', 'x86_simple_output', 'x86_encoding_accuracy', 'x86_reg_access',
                            'detail_option', 'text_option', 'x86_printer_prechecked',
                            'x86_buffer_bounds', 'x86_scan_batch', 'aarch64_scan', 'mips_scan',
                            'arm_post_index']) |
                       {f.stem for f in (s / 'tests/unit').glob('x86_*.c')
                        if f.stem.startswith(('x86_apx', 'x86_amx', 'x86_evex'))})
        objects, libraries, binaries, projections = {}, {}, {}, {}
        for key in ('prior', 'candidate'):
            run('apply-' + key, ['git', 'apply', r / (key + '.patch')], s)
            git('add', '-A')
            assert git('write-tree') == meta[key]['tree']
            git('reset', '-q')
            run('build-' + key, ['cmake', '--build', b, '--target', 'capstone_static', 'capstone_shared',
                                 *units, '--parallel', '4'])
            run('link-' + key, ['clang++', t / 'single.o', b / 'libcapstone.a', '-lm', '-o', t / 'consumer'])
            objroot = b / 'CMakeFiles/capstone.dir'
            objects[key] = {str(f.relative_to(objroot)): sha(f) for f in objroot.rglob('*.o')}
            libraries[key] = {name: sha(b / name) for name in ('libcapstone.a', 'libcapstone.so')}
            binaries[key] = sha(t / 'consumer')
            write('objects', objects)
            write('libraries', libraries)
            write('binaries', binaries)

            command = next(x for x in json.loads((b / 'compile_commands.json').read_text())
                           if x['file'].endswith('/arch/X86/X86Mapping.c'))
            args = shlex.split(command['command'])
            index = args.index('-o')
            del args[index:index + 2]
            args.remove('-c')
            variants = {
                'release': [], 'native-frame-policy': ['-fomit-frame-pointer'],
                'diet': ['-DCAPSTONE_DIET'], 'reduced': ['-DCAPSTONE_X86_REDUCE'],
                'adapter': ['-DCAPSTONE_X86_SCAN_ADAPTER'],
                'sanitize': ['-fsanitize=address,undefined'],
                'no-x86': ['-UCAPSTONE_HAS_X86'],
            }
            projections[key] = {}
            for name, flags in variants.items():
                output = sp.check_output([*args, *flags, '-E', '-P'], cwd=command['directory'])
                # Strip only empty lines/indentation introduced by conditional
                # regions; preserve every token, string and preprocessor pragma.
                output = b'\n'.join(line.lstrip() for line in output.splitlines() if line.strip())
                projections[key][name] = hashlib.sha256(output).hexdigest()
            write('preprocessing', projections)
            if key == 'candidate':
                assert objects['prior'] == objects['candidate']
                assert libraries['prior'] == libraries['candidate']
                assert binaries['prior'] == binaries['candidate']
                assert projections['prior'] == projections['candidate']
                run('units', ['ctest', '--test-dir', b, '--no-tests=error', '--output-on-failure',
                               '-j4', '-R', '^unit_(' + '|'.join(units) + ')$'])
            run('restore-' + key, ['git', 'apply', '-R', r / (key + '.patch')], s)
        assert not git('status', '--porcelain')
        write('complete', dict(runtime_objects=len(objects['candidate']), all_objects_identical=True,
            static_library_identical=True, shared_library_identical=True,
            original_consumer_identical=True, preprocessing_profiles=len(variants),
            unit_checks=len(units), source=meta, timing_repeated=False))
    finally:
        size = sum(f.lstat().st_size for f in t.rglob('*') if f.is_file())
        shutil.rmtree(t)
        write('cleanup', dict(bytes=size, removed=not t.exists()))
