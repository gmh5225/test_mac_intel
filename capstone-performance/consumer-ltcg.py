"""Qualify mixed-library Release IPO at four explicit image bases."""
from pathlib import Path
import hashlib
import json
import math
import os
import shutil
import statistics
import struct
import subprocess

from mixed_fixtures import fixture
import run
from inspect_release import inspect


def sections(path):
    data = path.read_bytes()
    pe = struct.unpack_from('<I', data, 60)[0]
    optional = pe + 24
    start = optional + struct.unpack_from('<H', data, pe + 20)[0]
    entries = []
    for i in range(struct.unpack_from('<H', data, pe + 6)[0]):
        offset = start + i * 40
        name = data[offset:offset + 8].rstrip(b'\0').decode()
        virtual, rva, size, raw = struct.unpack_from('<IIII', data, offset + 8)
        entries.append(dict(name=name, virtual=virtual, rva=rva, size=size, raw=raw,
                            sha256=hashlib.sha256(data[raw:raw + size]).hexdigest()))
    return dict(image_base=struct.unpack_from('<Q', data, optional + 24)[0],
                characteristics=struct.unpack_from('<H', data, optional + 70)[0],
                sections=entries, sha256=run.sha(path))


def main():
    source, work = run.SOURCE, run.WORK
    work.mkdir()
    run.EVIDENCE.mkdir()
    manifest = json.loads((source / 'manifest.json').read_text())
    capstone = run.fetch('base', 'https://github.com/NeverSight/capstone.git', manifest['capstone_revision'])
    patch = source / 'msvc-alias.patch'
    assert run.sha(patch) == manifest['source_lineage']['msvc-alias.patch']['sha256']
    run.write('inputs.json', dict(revision=manifest['capstone_revision'], patch=run.sha(patch),
                                bases=['0x140000000', '0x7ff6d8640000'],
                                purpose='Ordinary and LTCG consumer code with the same mixed libraries'))
    run.write('processor.json', json.loads(subprocess.check_output([
        'powershell', '-NoProfile', '-Command',
        'Get-CimInstance Win32_Processor | Select-Object Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors | ConvertTo-Json -Compress'], text=True)))
    options = ['-A', 'x64', '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL']
    build = work / 'capstone-build'
    libraries, compiler_flags = {}, {}
    for variant in ('base', 'new'):
        if variant == 'new':
            run.command(['git', 'apply', patch], 'apply', capstone)
        run.command(['cmake', '-S', capstone, '-B', build, *options,
                     '-DCMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE=ON', '-DCMAKE_C_FLAGS=/MP4',
                     '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
                     *['-DCAPSTONE_' + arch + '_SUPPORT=ON' for arch in ('X86', 'ARM', 'AARCH64', 'MIPS')],
                     '-DCAPSTONE_BUILD_CSTOOL=OFF', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
                     '-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=OFF'], 'configure-' + variant)
        run.command(['cmake', '--build', build, '--config', 'Release', '--parallel', '4',
                     '--target', 'capstone_static'], 'build-' + variant)
        flags = {}
        for log in (build / 'capstone.dir/Release').rglob('CL.command.1.tlog'):
            lines = log.read_text(encoding='utf-16', errors='replace').splitlines()
            for units, command in zip(lines[::2], lines[1::2]):
                for unit in units.lstrip('^').split('|'):
                    flags[Path(unit).name.lower()] = command
        compiler_flags[variant] = {name: flags[name] for name in
                                   ('cs.c', 'x86disassemblerdecoder.c', 'x86disassembler.c')}
        command = compiler_flags[variant]['x86disassemblerdecoder.c'].upper().split()
        switches = [word for word in command if word in ('/GL', '/GL-')]
        assert switches[-1] == ('/GL-' if variant == 'new' else '/GL')
        libraries[variant] = work / (variant + '.lib')
        shutil.copyfile(build / 'Release/capstone.lib', libraries[variant])
    run.write('compiler-flags.json', compiler_flags)
    driver = work / 'driver'
    driver.mkdir()
    lines = ['cmake_minimum_required(VERSION 3.20)', 'project(control CXX)']
    kinds = ('ordinary', 'ltcg')
    for kind in kinds:
        obj = 'consumer_' + kind
        lines.extend([f'add_library({obj} OBJECT "{(source / "fixed-single.cpp").as_posix()}")',
                      f'target_compile_features({obj} PRIVATE cxx_std_17)',
                      f'target_include_directories({obj} PRIVATE "{(capstone / "include").as_posix()}")',
                      f'set_property(TARGET {obj} PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE {"ON" if kind == "ltcg" else "OFF"})'])
    bases = [0x140000000, 0x7ff6d8640000]
    programs = {}
    for variant, library in libraries.items():
        for kind in kinds:
            for index, address in enumerate(bases):
                name = variant + '_' + kind + str(index)
                lines.extend([f'add_executable({name} $<TARGET_OBJECTS:consumer_{kind}>)',
                              f'target_link_libraries({name} PRIVATE "{library.as_posix()}")',
                              f'target_link_options({name} PRIVATE /LTCG /MAP:{name}.map /DYNAMICBASE:NO /HIGHENTROPYVA:NO /BASE:{address:#x})'])
                programs[name] = work / 'driver-build/Release' / (name + '.exe')
        snapshot = 'snapshot_' + variant
        lines.extend([f'add_executable({snapshot} "{(source / "fixed-snapshot.cpp").as_posix()}")',
                      f'target_include_directories({snapshot} PRIVATE "{(capstone / "include").as_posix()}")',
                      f'target_compile_features({snapshot} PRIVATE cxx_std_17)',
                      f'target_link_libraries({snapshot} PRIVATE "{library.as_posix()}" bcrypt)',
                      f'target_link_options({snapshot} PRIVATE /LTCG)'])
    (driver / 'CMakeLists.txt').write_text('\n'.join(lines) + '\n')
    run.command(['cmake', '-S', driver, '-B', work / 'driver-build', *options], 'driver-configure')
    run.command(['cmake', '--build', work / 'driver-build', '--config', 'Release',
                 '--parallel', '2'], 'driver-build')
    products = {name: sections(path) for name, path in programs.items()}
    run.write('products.json', products)
    assembly = {}
    for variant in libraries:
        for kind in kinds:
            for index, address in enumerate(bases):
                name = variant + '_' + kind + str(index)
                assert products[name]['image_base'] == address
                assert not products[name]['characteristics'] & 0x40
            name = variant + '_' + kind + '0'
            linker_map, = (work / 'driver-build').rglob(name + '.map')
            assembly[name] = inspect(programs[name], linker_map, run.EVIDENCE)
            run.write('linked-functions.json', assembly)
    flags = {}
    for kind in kinds:
        files = list((work / 'driver-build' / ('consumer_' + kind + '.dir/Release')).rglob('CL.command.1.tlog'))
        assert files
        flags[kind] = '\n'.join(path.read_text(encoding='utf-16', errors='replace') for path in files)
        assert (' /GL ' in flags[kind].upper()) == (kind == 'ltcg')
    run.write('consumer-flags.json', flags)
    selected = {'arm-ls', 'thumb-cp', 'mips64el-ls', 'arm64-ls', 'putty-32-0.85', 'putty-64-0.85'}
    packages = {}
    cases = [fixture(row, packages) for row in manifest['inputs'] if row['name'] in selected]
    assert len(cases) == 6
    for name, bits, flags in [('scalar32', 32, ['-fno-vectorize', '-fno-slp-vectorize']),
                             ('scalar64', 64, ['-fno-vectorize', '-fno-slp-vectorize']),
                             ('simd64', 64, ['-mavx2', '-mfma'])]:
        obj = work / (name + '.o')
        triple = ('i686' if bits == 32 else 'x86_64') + '-unknown-linux-gnu'
        run.command(['clang', '-target', triple, '-O3', '-ffreestanding', *flags, '-c',
                     source / ('simd.c' if name == 'simd64' else 'scalar.c'), '-o', obj], name)
        from corpus import elf_text
        path = work / (name + '.text')
        path.write_bytes(elf_text(obj.read_bytes()))
        cases.append(dict(name=name, selector=bits, path=str(path), sha256=run.sha(path)))
    run.write('cases.json', cases)
    snapshots = []
    measurements = []
    for case in cases:
        for mode in (0, 1, 2):
            if mode == 0 and case['selector'] < 16:
                continue
            signatures = []
            for variant in libraries:
                path = work / 'driver-build/Release' / ('snapshot_' + variant + '.exe')
                signatures.append(json.loads(subprocess.check_output([
                    path, str(case['selector']), str(mode), case['path']])))
            snapshots.append(dict(case=case['name'], mode=mode, outputs=signatures))
            run.write('snapshots.json', snapshots)
            assert signatures[0] == signatures[1]
            def sample(variant, kind, index, repeats):
                value = json.loads(subprocess.check_output([
                    programs[variant + '_' + kind + str(index)], str(case['selector']), str(mode), case['path'], str(repeats)]))
                assert value['image_base'] == bases[index]
                return value
            repeats = 1
            while (probe := sample('new', 'ordinary', 0, repeats))['wall_ns'] < 10000000:
                repeats *= 3
            repeats = max(1, math.ceil(repeats * 65000000 / probe['wall_ns']))
            rows = []
            for cycle in range(6):
                for kind in (kinds if cycle % 2 == 0 else kinds[::-1]):
                    for position in range(len(bases)):
                        index = (position + cycle) % len(bases)
                        order = ('base', 'new', 'new', 'base') if cycle % 2 == 0 else ('new', 'base', 'base', 'new')
                        raw = [(variant, sample(variant, kind, index, repeats)) for variant in order]
                        assert all(value['result'] == raw[0][1]['result'] for _, value in raw)
                        times = [[value['thread_cycles'] for label, value in raw if label == variant]
                                 for variant in ('base', 'new')]
                        rows.append(dict(cycle=cycle, consumer=kind, base=bases[index], raw=raw,
                                         gain=statistics.mean(times[0]) / statistics.mean(times[1]),
                                         aa=[values[0] / values[1] for values in times]))
            measurements.append(dict(case=case['name'], mode=mode, rows=rows))
            run.write('measurements.json', measurements)
    run.write('complete.json', dict(complete=True))


try:
    main()
finally:
    if run.EVIDENCE.exists():
        run.cleanup()
