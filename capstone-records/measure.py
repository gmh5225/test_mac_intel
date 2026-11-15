"""Exercise the CRT fix across configuration switches and the pending mapping guard."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess as sp
import tempfile
import xml.etree.ElementTree as ET

r = Path(__file__).resolve().parent
source, evidence = r.parent / 'source', r.parent / 'evidence'
evidence.mkdir()
meta = json.loads((r / 'inputs.json').read_text())
runtime = os.environ['RUNTIME']
compiler = os.environ['TOOLCHAIN']


def save(name, value):
    (evidence / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')


def run(args, name):
    with (evidence / (name + '.log')).open('wb') as out:
        result = sp.run(list(map(str, args)), cwd=source, stdout=out, stderr=sp.STDOUT)
    if result.returncode:
        raise RuntimeError(name + ': ' + (evidence / (name + '.log')).read_text(errors='replace')[-5000:])


def git(*args):
    return sp.check_output(['git', *map(str, args)], cwd=source, text=True).strip()


w = Path(tempfile.mkdtemp(prefix='capstone-cstest-runtime-'))
try:
    assert git('rev-parse', 'HEAD') == meta['runtime']['parent']
    assert not git('status', '--porcelain')
    patches = {}
    for name, entry in [('runtime', meta['runtime']), ('mapping', meta['combined']['mapping'])]:
        data = sp.check_output(['git', 'show', 'HEAD:capstone-records/' + name + '.patch'], cwd=r.parent)
        assert hashlib.sha256(data).hexdigest() == entry['sha256']
        patches[name] = w / (name + '.patch')
        patches[name].write_bytes(data)
    save('inputs', dict(**meta, compiler=compiler, runtime_choice=runtime))
    b = w / 'build'
    options = ['-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
               '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF', '-DCAPSTONE_BUILD_SHARED_LIBS=ON',
               '-DCAPSTONE_BUILD_MACOS_THIN=ON', '-DCAPSTONE_BUILD_CSTEST=ON',
               '-DCAPSTONE_BUILD_CSTOOL=OFF', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
               *['-DCAPSTONE_' + a + '_SUPPORT=ON' for a in ('PPC', 'ARC', 'LOONGARCH', 'SYSTEMZ')]]
    if os.name == 'nt':
        options += ['-G', 'Visual Studio 17 2022', '-A', 'x64', '-DCMAKE_C_FLAGS=/MP4',
                    '-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=' + ('ON' if runtime == 'MT' else 'OFF')]
        if runtime == 'MD-explicit':
            options += ['-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded$<$<CONFIG:Debug>:Debug>DLL']
    else:
        options += ['-G', 'Ninja', '-DCMAKE_C_COMPILER=' + compiler]
        if compiler == 'gcc':
            options += ['-DCMAKE_C_FLAGS=-Wno-error=discarded-qualifiers']

    def objects():
        return {str(p.relative_to(b)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (b / 'CMakeFiles/capstone.dir').rglob('*.o')}

    def inspect_runtime(label):
        if os.name != 'nt':
            assert not (b / 'suite/cstest/msvc-runtime.cmake').exists()
            return
        expected = {'Release': 'MultiThreaded', 'Debug': 'MultiThreadedDebug'}
        if runtime != 'MT':
            expected = {k: v + 'DLL' for k, v in expected.items()}
        projects = []
        for name in ('capstone', 'cstest', 'cmocka', 'yaml', 'cyaml_static'):
            matches = list(b.rglob(name + '.vcxproj'))
            assert len(matches) == 1, (name, matches)
            project = matches[0]
            root = ET.parse(project).getroot()
            values = {}
            ns = {'m': 'http://schemas.microsoft.com/developer/msbuild/2003'}
            for group in root.findall('m:ItemDefinitionGroup', ns):
                condition = group.get('Condition', '')
                for config in expected:
                    if config + '|x64' in condition:
                        value = group.find('m:ClCompile/m:RuntimeLibrary', ns)
                        assert value is not None, (project, config)
                        values[config] = value.text
            assert values == expected, (project, values, expected)
            projects.append(dict(path=str(project.relative_to(b)), values=values))
        cache_values = {}
        if runtime != 'MD':
            literal = 'MultiThreaded$<$<CONFIG:Debug>:Debug>' + ('DLL' if runtime == 'MD-explicit' else '')
            for name in ('cmocka', 'libyaml', 'libcyaml'):
                cache = b / 'suite/cstest/extern/src' / (name + '_ext-build') / 'CMakeCache.txt'
                value = next(line.split('=', 1)[1] for line in cache.read_text().splitlines()
                             if line.startswith('CMAKE_MSVC_RUNTIME_LIBRARY:'))
                assert value == literal, (name, value, literal)
                cache_values[name] = value
        save(label + '-runtime', dict(projects=projects, child_cache=cache_values))

    phases = []
    def exercise(label, configurations):
        for index, config in enumerate(configurations):
            tag = label + '-' + str(index) + '-' + config.lower()
            run(['cmake', '--build', b, '--config', config, '--parallel', '4'], tag + '-build')
            run(['ctest', '--test-dir', b, '-C', config, '--no-tests=error',
                 '--output-on-failure', '-R', '^unit_'], tag + '-tests')
            exe = b / 'suite/cstest'
            exe = exe / config / 'cstest.exe' if os.name == 'nt' else exe / 'cstest'
            run([exe, source / 'tests/details/ppc.yaml'], tag + '-yaml')
            inspect_runtime(tag)
            phases.append(dict(label=label, config=config, tag=tag, tree=git('write-tree')))

    if os.name != 'nt':
        run(['cmake', '-S', source, '-B', b, *options], 'base-configure')
        exercise('base', ['Release'])
        original_objects = objects()
        assert original_objects
    run(['git', '-c', 'core.autocrlf=false', 'apply', '--index', patches['runtime']], 'apply-runtime')
    assert git('write-tree') == meta['runtime']['tree']
    run(['cmake', '-S', source, '-B', b, *options], 'fixed-configure')
    exercise('fixed', ['Release', 'Debug', 'Release'] if os.name == 'nt' else ['Release'])
    if os.name == 'nt':
        run(['git', '-c', 'core.autocrlf=false', 'apply', '--index', patches['mapping']], 'apply-mapping')
        assert git('write-tree') == meta['combined']['tree']
        exercise('combined', ['Release', 'Debug', 'Release'])
    else:
        assert objects() == original_objects
        save('object-identity', dict(equal=True, count=len(original_objects), sha256=original_objects))
    save('complete', dict(success=True, runtime=runtime, compiler=compiler, phases=phases))
finally:
    amount = sum(p.stat().st_size for p in w.rglob('*') if p.is_file())
    def remove_readonly(fn, path, exc):
        os.chmod(path, 0o700)
        fn(path)
    shutil.rmtree(w, onerror=remove_readonly)
    save('cleanup', dict(removed=not w.exists(), bytes=amount))
