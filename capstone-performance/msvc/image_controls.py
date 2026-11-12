"""Isolate image identity and ASLR with one immutable Capstone library."""
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import struct
import subprocess

import run as tool

source, work = tool.source, tool.work


def pe_layout(path):
    data = path.read_bytes()
    pe = struct.unpack_from('<I', data, 60)[0]
    optional = pe + 24
    sections = optional + struct.unpack_from('<H', data, pe + 20)[0]
    rows = {}
    for i in range(struct.unpack_from('<H', data, pe + 6)[0]):
        offset = sections + i * 40
        name = data[offset:offset + 8].rstrip(b'\0').decode()
        virtual_size, rva, size, raw = struct.unpack_from('<IIII', data, offset + 8)
        rows[name] = dict(rva=rva, virtual_size=virtual_size, size=size, raw=raw,
                          sha256=tool.digest(data[raw:raw + size]))
    return dict(sha256=tool.digest(data), size=len(data),
                image_base=struct.unpack_from('<Q', data, optional + 24)[0],
                dll_characteristics=struct.unpack_from('<H', data, optional + 70)[0],
                sections=rows)


def main():
    capstone = tool.fetch('base', 'capstone', tool.manifest['capstone_revision'])
    tool.fetch('iced', 'iced', tool.manifest['iced_revision'])
    adapter = work / 'adapter'
    adapter.mkdir()
    for name in ('Cargo.lock', 'iced.rs'):
        shutil.copyfile(source / name, adapter / name)
    (adapter / 'Cargo.toml').write_text('''[package]
name="iced_compare"
version="0.1.0"
edition="2021"
[lib]
crate-type=["staticlib"]
path="iced.rs"
[dependencies]
iced-x86={path="../iced/src/rust/iced-x86",default-features=false,features=["std","decoder","intel","instr_info"]}
[profile.release]
panic="abort"
opt-level=3
''')
    tool.run(['cargo', 'build', '--release', '--locked', '--manifest-path', adapter / 'Cargo.toml'], 'rust')
    options = ['-A', 'x64', '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL']
    build = work / 'capstone-build'
    tool.run(['cmake', '-S', capstone, '-B', build, *options,
              '-DCMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE=OFF', '-DCMAKE_C_FLAGS=/MP4',
              '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
              *['-DCAPSTONE_' + arch + '_SUPPORT=ON' for arch in ('X86', 'ARM', 'AARCH64', 'MIPS')],
              '-DCAPSTONE_BUILD_CSTOOL=OFF', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
              '-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=OFF'], 'configure')
    tool.run(['cmake', '--build', build, '--config', 'Release', '--parallel', '4',
              '--target', 'capstone_static'], 'build')
    library = build / 'Release/capstone.lib'
    rust = work / 'cargo-target/release/iced_compare.lib'
    driver = work / 'driver'
    driver.mkdir()
    lines = ['cmake_minimum_required(VERSION 3.20)', 'project(control C CXX)']
    programs = {}
    for kind, filename in [('original', 'compare.cpp'), ('diagnostic', 'layout_compare.cpp')]:
        obj = kind + '_consumer'
        lines.extend([f'add_library({obj} OBJECT "{(source / "msvc" / filename).as_posix()}")',
                      f'target_compile_features({obj} PRIVATE cxx_std_17)',
                      f'target_include_directories({obj} PRIVATE "{(capstone / "include").as_posix()}")'])
        if kind == 'diagnostic':
            lines.extend([f'target_sources({obj} PRIVATE "{(source / "msvc/layout.c").as_posix()}")',
                          f'target_include_directories({obj} PRIVATE "{capstone.as_posix()}")'])
        for label in ('regular', 'regular_new', 'fixed'):
            name = kind + '_' + label
            lines.extend([f'add_executable({name} $<TARGET_OBJECTS:{obj}>)',
                          f'target_link_libraries({name} PRIVATE "{library.as_posix()}" "{rust.as_posix()}" advapi32 bcrypt ntdll userenv ws2_32)'])
            if label == 'fixed':
                lines.append(f'target_link_options({name} PRIVATE /DYNAMICBASE:NO /HIGHENTROPYVA:NO /BASE:0x140000000)')
            programs[name] = work / 'driver-build/Release' / (name + '.exe')
    (driver / 'CMakeLists.txt').write_text('\n'.join(lines) + '\n')
    tool.run(['cmake', '-S', driver, '-B', work / 'driver-build', *options], 'driver-configure')
    tool.run(['cmake', '--build', work / 'driver-build', '--config', 'Release',
              '--parallel', '2'], 'driver-build')
    for kind in ('original', 'diagnostic'):
        for label, parent in [('replica', 'regular'), ('replica_new', 'regular'), ('fixed_copy', 'fixed')]:
            name = kind + '_' + label
            programs[name] = programs[kind + '_' + parent].with_name(name + '.exe')
            shutil.copyfile(programs[kind + '_' + parent], programs[name])
    layouts = {name: pe_layout(path) for name, path in programs.items()}
    for kind in ('original', 'diagnostic'):
        assert len({v['sections']['.text']['sha256'] for k, v in layouts.items() if k.startswith(kind + '_')}) == 1
        for label in ('replica', 'replica_new'):
            assert layouts[kind + '_' + label]['sha256'] == layouts[kind + '_regular']['sha256']
    tool.write('products.json', dict(library=tool.digest(library.read_bytes()), programs=layouts))
    tool.write('processor.json', json.loads(subprocess.check_output([
        'powershell', '-NoProfile', '-Command',
        'Get-CimInstance Win32_Processor | Select-Object Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors | ConvertTo-Json -Compress'], text=True)))
    cases = [case for case in tool.get_cases() if case['name'] in
             ('putty-32-0.85', 'putty-64-0.85', 'scalar32', 'scalar64', 'simd64')]
    results = []
    labels = ['regular', 'same_path', 'regular_new', 'replica', 'replica_new', 'fixed', 'fixed_copy']
    for kind in ('original', 'diagnostic'):
        for case in cases:
            for mode in ('scan', 'format', 'detail'):
                def sample(label, repeats):
                    label = 'regular' if label == 'same_path' else label
                    return json.loads(subprocess.check_output([
                        programs[kind + '_' + label], 'capstone', mode,
                        str(case['bits']), str(repeats), case['path']]))
                repeats = 1
                while (probe := sample('regular', repeats))['wall_ns'] < 10_000_000:
                    repeats *= 3
                repeats = max(1, math.ceil(repeats * 70_000_000 / probe['wall_ns']))
                cycles = []
                for cycle in range(8):
                    position = cycle % len(labels)
                    order = labels[position:] + labels[:position]
                    if cycle % 2:
                        order.reverse()
                    raw = [(label, sample(label, repeats)) for label in order + order[::-1]]
                    assert len({tuple(value[key] for key in ('instructions', 'rejected', 'boundary_hash', 'value_hash'))
                                for _, value in raw}) == 1
                    times = {label: statistics.mean(value['thread_cycles'] for key, value in raw if key == label)
                             for label in labels}
                    cycles.append(dict(raw=raw, relative={label: times['regular'] / times[label] for label in labels}))
                results.append(dict(kind=kind, case=case['name'], mode=mode, repeats=repeats, cycles=cycles))
                tool.write('measurements.json', results)
    tool.write('complete.json', dict(complete=True, capstone_revision=tool.manifest['capstone_revision']))


try:
    main()
finally:
    size = sum(path.stat().st_size for path in work.rglob('*') if path.is_file())
    def writable(function, path, error):
        os.chmod(path, 0o700)
        function(path)
    shutil.rmtree(work, onerror=writable)
    tool.write('cleanup.json', dict(logical_bytes=size, removed=not work.exists()))
