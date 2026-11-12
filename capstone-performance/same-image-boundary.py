"""Isolate scan outlining and table lookup inside a shared executable image."""
from pathlib import Path
import json
import math
import re
import shutil
import statistics
import subprocess

from mixed_fixtures import fixture
import run
from inspect_release import inspect

process = None
log = None


def main():
    global process, log
    source, work = run.SOURCE, run.WORK
    work.mkdir()
    run.EVIDENCE.mkdir()
    manifest = json.loads((source / 'manifest.json').read_text())
    capstone = run.fetch('base', 'https://github.com/NeverSight/capstone.git', manifest['capstone_revision'])
    patch = source / 'same-image.patch'
    run.write('inputs.json', dict(revision=manifest['capstone_revision'], patch_sha256=run.sha(patch),
                                purpose='One image, common tables and handle, controlled instruction and detail addresses'))
    run.write('processor.json', json.loads(subprocess.check_output([
        'powershell', '-NoProfile', '-Command',
        'Get-CimInstance Win32_Processor | Select-Object Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors | ConvertTo-Json -Compress'], text=True)))
    run.command(['git', 'apply', '--check', patch], 'patch-check', capstone)
    run.command(['git', 'apply', patch], 'apply-diagnostic-entries', capstone)
    with (capstone / 'CMakeLists.txt').open('a') as out:
        out.write('\nset_property(SOURCE arch/X86/X86Disassembler.c APPEND PROPERTY COMPILE_DEFINITIONS CAPSTONE_X86_LTCG_WRITEMASK)\n'
                  'target_link_options(capstone_shared PRIVATE /LTCG /MAP:capstone.map)\n')
    options = ['-A', 'x64', '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL']
    build = work / 'capstone-build'
    run.command(['cmake', '-S', capstone, '-B', build, *options,
                 '-DCMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE=ON', '-DCMAKE_C_FLAGS=/MP4',
                 '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
                 *['-DCAPSTONE_' + arch + '_SUPPORT=ON' for arch in ('X86', 'ARM', 'AARCH64', 'MIPS')],
                 '-DCAPSTONE_BUILD_CSTOOL=OFF', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
                 '-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=OFF', '-DCAPSTONE_BUILD_SHARED_LIBS=ON',
                 '-DCAPSTONE_BUILD_STATIC_LIBS=OFF'], 'configure')
    run.command(['cmake', '--build', build, '--config', 'Release', '--parallel', '4',
                 '--target', 'capstone_shared'], 'build-library')
    flags = {}
    for path in (build / 'capstone.dir/Release').rglob('CL.command.1.tlog'):
        lines = path.read_text(encoding='utf-16', errors='replace').splitlines()
        for units, command in zip(lines[::2], lines[1::2]):
            for unit in units.lstrip('^').split('|'):
                flags[Path(unit).name.lower()] = command
    run.write('compiler-flags.json', flags)
    switches = [word for word in flags['x86disassemblerdecoder.c'].upper().split() if word in ('/GL', '/GL-')]
    assert switches[-1] == '/GL'
    library = build / 'Release/capstone.dll'
    linker_map, = build.rglob('capstone.map')
    shutil.copyfile(linker_map, run.EVIDENCE / 'capstone.map')
    assembly = inspect(library, linker_map, run.EVIDENCE)
    run.write('linked-functions.json', assembly)
    old_entry = '\n'.join(assembly['cs_disasm_iter']['entry'])
    new_entry = '\n'.join(assembly['cs_disasm_iter_outlined']['entry'])
    old_stack = int(re.search(r'movl \$(0x[0-9a-f]+), %eax', old_entry)[1], 16)
    new_stack = int(re.search(r'subq \$(0x[0-9a-f]+), %rsp', new_entry)[1], 16)
    assert old_stack > 65536 and new_stack < 8192, (old_stack, new_stack)
    run.write('frames.json', dict(original=old_stack, outlined=new_stack))
    driver = work / 'driver'
    driver.mkdir()
    lines = ['cmake_minimum_required(VERSION 3.20)', 'project(consumer CXX)']
    for target, filename in [('consumer', 'same-image-single.cpp'), ('snapshot', 'same-image-snapshot.cpp')]:
        lines += [f'add_executable({target} "{(source / filename).as_posix()}")',
                  f'target_include_directories({target} PRIVATE "{(capstone / "include").as_posix()}")',
                  f'target_compile_features({target} PRIVATE cxx_std_17)']
    lines += ['target_link_libraries(snapshot PRIVATE bcrypt)']
    (driver / 'CMakeLists.txt').write_text('\n'.join(lines) + '\n')
    run.command(['cmake', '-S', driver, '-B', work / 'driver-build', *options], 'driver-configure')
    run.command(['cmake', '--build', work / 'driver-build', '--config', 'Release', '--parallel', '2'], 'driver-build')
    run.write('products.json', {name: run.sha(path) for name, path in [
        ('library', library), ('consumer', work / 'driver-build/Release/consumer.exe'),
        ('snapshot', work / 'driver-build/Release/snapshot.exe')]})
    log = (run.EVIDENCE / 'consumer-stderr.log').open('w')
    process = subprocess.Popen([work / 'driver-build/Release/consumer.exe', library],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
                               text=True, bufsize=1)
    selected = {'arm-ls', 'thumb-cp', 'mips64el-ls', 'arm64-ls', 'putty-32-0.85', 'putty-64-0.85'}
    packages = {}
    cases = [fixture(row, packages) for row in manifest['inputs'] if row['name'] in selected]
    assert len(cases) == 6
    from corpus import elf_text
    for name, bits, flags in [('scalar32', 32, ['-fno-vectorize', '-fno-slp-vectorize']),
                             ('scalar64', 64, ['-fno-vectorize', '-fno-slp-vectorize']),
                             ('simd64', 64, ['-mavx2', '-mfma'])]:
        obj = work / (name + '.o')
        triple = ('i686' if bits == 32 else 'x86_64') + '-unknown-linux-gnu'
        run.command(['clang', '-target', triple, '-O3', '-ffreestanding', *flags, '-c',
                     source / ('simd.c' if name == 'simd64' else 'scalar.c'), '-o', obj], name)
        path = work / (name + '.text')
        path.write_bytes(elf_text(obj.read_bytes()))
        cases.append(dict(name=name, selector=bits, path=str(path), sha256=run.sha(path)))
    run.write('cases.json', cases)
    snapshots = []
    measurements = []
    variants = {'base': 0, 'outline': 1, 'mask': 2, 'both': 3, 'control': 0}
    for case in cases:
        for mode in (0, 1, 2):
            if mode == 0 and case['selector'] < 16:
                continue
            outputs = [json.loads(subprocess.check_output([
                work / 'driver-build/Release/snapshot.exe', library, str(variant),
                str(case['selector']), str(mode), case['path']])) for variant in range(4)]
            snapshots.append(dict(case=case['name'], mode=mode, outputs=outputs))
            run.write('snapshots.json', snapshots)
            assert all(value == outputs[0] for value in outputs)

    def measure(case, mode, panel, pads, cycles, target_ns):
        stable = {}
        fixed = None

        def sample(variant, padding, repeats):
            nonlocal stable, fixed
            output_offset = padding if panel == "output" else 0
            detail_offset = padding if panel == "detail" else 0
            process.stdin.write(f"{variants[variant]} 0 {case['selector']} {mode} {json.dumps(case['path'])} {repeats} {output_offset} {detail_offset}\n")
            process.stdin.flush()
            line = process.stdout.readline()
            if not line:
                raise RuntimeError('consumer exited: ' + str(process.poll()))
            value = json.loads(line)
            addresses = {key: value[key] for key in
                         ('image_base', 'output', 'detail_storage', 'input_storage', 'handle', 'stack')}
            if padding not in stable:
                stable[padding] = addresses
            assert stable[padding] == addresses, (stable[padding], addresses)
            invariant = {key: value[key] for key in ('image_base', 'input_storage', 'handle', 'stack', 'run_stack')}
            if fixed is None:
                fixed = invariant
            assert fixed == invariant, (fixed, invariant)
            return value

        repeats = 1
        while (probe := sample('both', 0, repeats))['wall_ns'] < 10000000:
            repeats *= 3
        repeats = max(1, math.ceil(repeats * target_ns / probe['wall_ns']))
        candidates = ['outline', 'mask', 'both', 'control']
        rows = []
        for cycle in range(cycles):
            for position in range(len(pads)):
                padding = pads[(position + cycle) % len(pads)]
                for candidate_position in range(len(candidates)):
                    candidate = candidates[(candidate_position + cycle) % len(candidates)]
                    order = ('base', 'new', 'new', 'base') if cycle % 2 == 0 else ('new', 'base', 'base', 'new')
                    raw = [(label, sample('base' if label == 'base' else candidate, padding, repeats))
                           for label in order]
                    assert all(value['result'] == raw[0][1]['result'] for _, value in raw)
                    assert all(value['run_stack'] == raw[0][1]['run_stack'] for _, value in raw)
                    times = [[value['thread_cycles'] for label, value in raw if label == variant]
                             for variant in ('base', 'new')]
                    rows.append(dict(cycle=cycle, consumer=candidate, base=padding, raw=raw,
                                     gain=statistics.mean(times[0]) / statistics.mean(times[1]),
                                     aa=[values[0] / values[1] for values in times]))
            print(panel, case['name'], mode, 'cycle', cycle + 1, flush=True)
        measurements.append(dict(panel=panel, case=case['name'], mode=mode, rows=rows))
        run.write('measurements.json', measurements)

    for case in cases:
        for mode in (0, 1, 2):
            if mode == 0 and case['selector'] < 16:
                continue
            measure(case, mode, 'normal', [0], 6, 40000000)
    offsets = [index * 64 + (index % 4) * 16 for index in range(64)]
    for case in cases:
        if case['name'] in ('putty-32-0.85', 'scalar64'):
            for panel in ['output', 'detail']:
                measure(case, 2, panel, offsets, 4, 20000000)
    run.write('complete.json', dict(complete=True))


try:
    main()
finally:
    if process:
        process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    if log:
        log.close()
    if run.EVIDENCE.exists():
        run.cleanup()
