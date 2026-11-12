"""Compare DLLs loaded successively at the same address in one persistent consumer."""
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
    run.write('inputs.json', dict(revision=manifest['capstone_revision'], patch=run.sha(patch),
                                bases=['0x180000000', '0x7ff6d8640000'],
                                purpose='Same process, output and input storage, and preferred DLL address for baseline and candidate'))
    run.write('processor.json', json.loads(subprocess.check_output([
        'powershell', '-NoProfile', '-Command',
        'Get-CimInstance Win32_Processor | Select-Object Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors | ConvertTo-Json -Compress'], text=True)))
    options = ['-A', 'x64', '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL']
    build = work / 'capstone-build'
    libraries, compiler_flags = {}, {}
    bases = [0x180000000, 0x7ff6d8640000]
    with (capstone / 'CMakeLists.txt').open('a') as out:
        out.write('\ntarget_link_options(capstone_shared PRIVATE /LTCG /DYNAMICBASE:NO /HIGHENTROPYVA:NO /BASE:${TEST_IMAGE_BASE} /MAP:capstone.map)\n')
    for variant in ('base', 'new'):
        if variant == 'new':
            run.command(['git', 'apply', patch], 'apply', capstone)
        run.command(['cmake', '-S', capstone, '-B', build, *options,
                     '-DCMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE=ON', '-DCMAKE_C_FLAGS=/MP4',
                     '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
                     *['-DCAPSTONE_' + arch + '_SUPPORT=ON' for arch in ('X86', 'ARM', 'AARCH64', 'MIPS')],
                     '-DCAPSTONE_BUILD_CSTOOL=OFF', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
                     '-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=OFF', '-DCAPSTONE_BUILD_SHARED_LIBS=ON',
                     '-DCAPSTONE_BUILD_STATIC_LIBS=OFF', '-DTEST_IMAGE_BASE=0x180000000'], 'configure-' + variant)
        run.command(['cmake', '--build', build, '--config', 'Release', '--parallel', '4',
                     '--target', 'capstone_shared'], 'build-' + variant)
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
        assert switches[-1] == '/GL'
        assert ('CAPSTONE_X86_LTCG_OUTLINE_SCAN' in compiler_flags[variant]['x86disassemblerdecoder.c']) == (variant == 'new')
        for index, address in enumerate(bases):
            if index:
                run.command(['cmake', '-S', capstone, '-B', build, '-DTEST_IMAGE_BASE=' + hex(address)],
                            'rebase-configure-' + variant)
                run.command(['cmake', '--build', build, '--config', 'Release', '--target', 'capstone_shared'],
                            'rebase-build-' + variant)
            name = variant + str(index)
            libraries[name] = work / (name + '.dll')
            shutil.copyfile(build / 'Release/capstone.dll', libraries[name])
            linker_map, = build.rglob('capstone.map')
            shutil.copyfile(linker_map, run.EVIDENCE / (name + '.map'))
            inspect(libraries[name], linker_map, run.EVIDENCE)
    run.write('compiler-flags.json', compiler_flags)
    driver = work / 'driver'
    driver.mkdir()
    (driver / 'CMakeLists.txt').write_text(
        'cmake_minimum_required(VERSION 3.20)\nproject(consumer CXX)\n'
        + f'add_executable(consumer "{(source / "same-address-single.cpp").as_posix()}")\n'
        + f'target_include_directories(consumer PRIVATE "{(capstone / "include").as_posix()}")\n'
        + 'target_compile_features(consumer PRIVATE cxx_std_17)\n')
    run.command(['cmake', '-S', driver, '-B', work / 'driver-build', *options], 'driver-configure')
    run.command(['cmake', '--build', work / 'driver-build', '--config', 'Release', '--parallel', '2'], 'driver-build')
    products = {name: sections(path) for name, path in libraries.items()}
    run.write('products.json', products)
    for variant in ('base', 'new'):
        for index, address in enumerate(bases):
            assert products[variant + str(index)]['image_base'] == address
            assert not products[variant + str(index)]['characteristics'] & 0x40
    log = (run.EVIDENCE / 'consumer-stderr.log').open('w')
    logs.append(log)
    process = subprocess.Popen([work / 'driver-build/Release/consumer.exe'],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
                               text=True, bufsize=1)
    processes['consumer'] = process
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
    output_addresses = None
    measurements = []
    for case in cases:
        for mode in (0, 1, 2):
            if mode == 0 and case['selector'] < 16:
                continue
            def sample(variant, index, repeats):
                nonlocal output_addresses
                path = str(libraries[variant + str(index)])
                process.stdin.write(f"{json.dumps(path)} {case['selector']} {mode} {json.dumps(case['path'])} {repeats}\n")
                process.stdin.flush()
                output = process.stdout.readline()
                if not output:
                    raise RuntimeError('consumer exited: ' + str(process.poll()))
                value = json.loads(output)
                assert value['image_base'] == bases[index]
                addresses = [value['output'], value['detail_storage'], value['stack']]
                if output_addresses is None:
                    output_addresses = addresses
                assert addresses == output_addresses
                return value
            repeats = 1
            while (probe := sample('new', 0, repeats))['wall_ns'] < 10000000:
                repeats *= 3
            repeats = max(1, math.ceil(repeats * 65000000 / probe['wall_ns']))
            rows = []
            for cycle in range(10):
                for position in range(len(bases)):
                    index = (position + cycle) % len(bases)
                    order = ('base', 'new', 'new', 'base') if cycle % 2 == 0 else ('new', 'base', 'base', 'new')
                    raw = [(variant, sample(variant, index, repeats)) for variant in order]
                    assert all(value['result'] == raw[0][1]['result'] for _, value in raw)
                    assert all(value['input_storage'] == raw[0][1]['input_storage'] for _, value in raw)
                    times = [[value['thread_cycles'] for label, value in raw if label == variant]
                             for variant in ('base', 'new')]
                    rows.append(dict(cycle=cycle, consumer='same-address-dll', base=bases[index], raw=raw,
                                     gain=statistics.mean(times[0]) / statistics.mean(times[1]),
                                     aa=[values[0] / values[1] for values in times]))
            measurements.append(dict(case=case['name'], mode=mode, rows=rows))
            run.write('measurements.json', measurements)
    run.write('complete.json', dict(complete=True, output_addresses=output_addresses))


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
