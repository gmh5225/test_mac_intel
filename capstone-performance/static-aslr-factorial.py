"""Measure a narrow fallback boundary with persistent ordinary and LTCG consumers."""
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

processes = {}
logs = []


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
    variants = {'base': (False, False), 'outline': (True, False),
                'mask': (False, True), 'both': (True, True)}
    slots = range(3)
    run.write('inputs.json', dict(revision=manifest['capstone_revision'], patch=run.sha(patch),
                                variants=variants, copies=len(slots),
                                purpose='Static ordinary and LTCG consumers with default ASLR'))
    run.write('processor.json', json.loads(subprocess.check_output([
        'powershell', '-NoProfile', '-Command',
        'Get-CimInstance Win32_Processor | Select-Object Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors | ConvertTo-Json -Compress'], text=True)))
    options = ['-A', 'x64', '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL']
    build = work / 'capstone-build'
    libraries, compiler_flags = {}, {}
    # The decoder hunk adds only an inactive preprocessor branch to the baseline.
    run.command(['git', 'apply', '--include=arch/X86/X86DisassemblerDecoder.c', patch],
                'apply-decoder-boundary', capstone)
    with (capstone / 'CMakeLists.txt').open('a') as out:
        out.write('\nif(TEST_OUTLINE)\n'
                  '  set_property(SOURCE arch/X86/X86DisassemblerDecoder.c APPEND PROPERTY COMPILE_DEFINITIONS CAPSTONE_X86_LTCG_OUTLINE_SCAN)\n'
                  'endif()\nif(TEST_MASK)\n'
                  '  set_property(SOURCE arch/X86/X86Disassembler.c APPEND PROPERTY COMPILE_DEFINITIONS CAPSTONE_X86_LTCG_WRITEMASK)\n'
                  'endif()\n')
    for variant, (outline, mask) in variants.items():
        run.command(['cmake', '-S', capstone, '-B', build, *options,
                     '-DCMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE=ON', '-DCMAKE_C_FLAGS=/MP4',
                     '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
                     *['-DCAPSTONE_' + arch + '_SUPPORT=ON' for arch in ('X86', 'ARM', 'AARCH64', 'MIPS')],
                     '-DCAPSTONE_BUILD_CSTOOL=OFF', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
                     '-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=OFF', '-DCAPSTONE_BUILD_SHARED_LIBS=OFF',
                     '-DCAPSTONE_BUILD_STATIC_LIBS=ON',
                     '-DTEST_OUTLINE=' + ('ON' if outline else 'OFF'),
                     '-DTEST_MASK=' + ('ON' if mask else 'OFF')], 'configure-' + variant)
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
        decoder_flags = compiler_flags[variant]['x86disassemblerdecoder.c']
        switches = [word for word in decoder_flags.upper().split() if word in ('/GL', '/GL-')]
        assert switches[-1] == '/GL'
        assert ('CAPSTONE_X86_LTCG_OUTLINE_SCAN' in decoder_flags) == outline
        assert ('CAPSTONE_X86_LTCG_WRITEMASK' in compiler_flags[variant]['x86disassembler.c']) == mask
        libraries[variant] = work / (variant + '.lib')
        shutil.copyfile(build / 'Release/capstone.lib', libraries[variant])
    run.write('compiler-flags.json', compiler_flags)
    driver = work / 'driver'
    driver.mkdir()
    lines = ['cmake_minimum_required(VERSION 3.20)', 'project(control CXX)']
    kinds = ('ordinary', 'ltcg')
    for kind in kinds:
        obj = 'consumer_' + kind
        lines.extend([f'add_library({obj} OBJECT "{(source / "persistent-single.cpp").as_posix()}")',
                      f'target_compile_features({obj} PRIVATE cxx_std_17)',
                      f'target_include_directories({obj} PRIVATE "{(capstone / "include").as_posix()}")',
                      f'set_property(TARGET {obj} PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE {"ON" if kind == "ltcg" else "OFF"})'])
    programs = {}
    for variant, library in libraries.items():
        for kind in kinds:
            name = variant + '_' + kind + '0'
            lines.extend([f'add_executable({name} $<TARGET_OBJECTS:consumer_{kind}>)',
                          f'target_link_libraries({name} PRIVATE "{library.as_posix()}")',
                          f'target_link_options({name} PRIVATE /LTCG /MAP:{name}.map)'])
            for index in slots:
                programs[variant + '_' + kind + str(index)] = work / 'driver-build/Release' / (variant + '_' + kind + str(index) + '.exe')
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
    for variant in variants:
        for kind in kinds:
            original = programs[variant + '_' + kind + '0']
            for index in slots:
                if index:
                    shutil.copyfile(original, programs[variant + '_' + kind + str(index)])
    products = {name: sections(path) for name, path in programs.items()}
    run.write('products.json', products)
    assembly = {}
    for variant in libraries:
        for kind in kinds:
            for index in slots:
                name = variant + '_' + kind + str(index)
                assert products[name]['characteristics'] & 0x40
                assert products[name]['sha256'] == products[variant + '_' + kind + '0']['sha256']
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
    for name, path in programs.items():
        log = (run.EVIDENCE / (name + '-stderr.log')).open('w')
        logs.append(log)
        processes[name] = subprocess.Popen([path], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=log, text=True, bufsize=1)
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
            assert all(value == signatures[0] for value in signatures)
            def sample(variant, kind, index, repeats):
                process = processes[variant + '_' + kind + str(index)]
                process.stdin.write(f"{case['selector']} {mode} {json.dumps(case['path'])} {repeats}\n")
                process.stdin.flush()
                output = process.stdout.readline()
                if not output:
                    raise RuntimeError('consumer exited: ' + str(process.poll()))
                value = json.loads(output)
                return value
            repeats = 1
            while (probe := sample('both', 'ordinary', 0, repeats))['wall_ns'] < 10000000:
                repeats *= 3
            repeats = max(1, math.ceil(repeats * 40000000 / probe['wall_ns']))
            rows = []
            candidates = ['outline', 'mask', 'both', 'control']
            for cycle in range(6):
                for kind in (kinds if cycle % 2 == 0 else kinds[::-1]):
                    for position in slots:
                        index = (position + cycle) % len(slots)
                        for candidate_position in range(len(candidates)):
                            candidate = candidates[(candidate_position + cycle) % len(candidates)]
                            order = ('base', 'new', 'new', 'base') if cycle % 2 == 0 else ('new', 'base', 'base', 'new')
                            target = 'base' if candidate == 'control' else candidate
                            target_index = (index + 1) % len(slots) if candidate == 'control' else index
                            raw = [(label, sample('base' if label == 'base' else target, kind,
                                                  index if label == 'base' else target_index, repeats))
                                   for label in order]
                            assert all(value['result'] == raw[0][1]['result'] for _, value in raw)
                            times = [[value['thread_cycles'] for label, value in raw if label == variant]
                                     for variant in ('base', 'new')]
                            rows.append(dict(cycle=cycle, consumer=kind + '-' + candidate, base=index, raw=raw,
                                             gain=statistics.mean(times[0]) / statistics.mean(times[1]),
                                             aa=[values[0] / values[1] for values in times]))
            measurements.append(dict(case=case['name'], mode=mode, rows=rows))
            run.write('measurements.json', measurements)
    run.write('complete.json', dict(complete=True))


try:
    main()
finally:
    for process in processes.values():
        process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    for log in logs:
        log.close()
    if run.EVIDENCE.exists():
        run.cleanup()
