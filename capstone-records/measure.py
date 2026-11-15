from pathlib import Path
import gzip
import hashlib
import json
import os
import shutil
import subprocess as sp
import tempfile
import corpus
import layout

r = Path(__file__).resolve().parent
source = r.parent / 'source'
evidence = r.parent / 'evidence'
evidence.mkdir()


def save(name, value):
    (evidence / name).write_text(json.dumps(value, indent=2) + '\n')


def run(args, label):
    print(label, flush=True)
    with (evidence / (label + '.log')).open('wb') as out:
        sp.run(list(map(str, args)), cwd=source, stdout=out, stderr=sp.STDOUT, check=True)


work = Path(tempfile.mkdtemp(prefix='capstone-tie-layout-'))
try:
    inputs = json.loads((r / 'inputs.json').read_text())
    meta = inputs['candidate']
    assert sp.check_output(['git', '-C', source, 'rev-parse', 'HEAD'], text=True).strip() == meta['parent']
    assert not sp.check_output(['git', '-C', source, 'status', '--porcelain'])
    assert layout.sha(r / 'candidate.patch') == meta['sha256']
    cc = os.environ['MEASURE_CC']
    save('inputs.json', inputs)
    save('cpu.json', dict(cpu=Path('/proc/cpuinfo').read_text(),
                         compiler=sp.check_output([cc, '--version'], text=True)))
    cases = [case for case in corpus.prepare(r, work, evidence, run)
             if case['name'] in ('mips64el-ls', 'ppc64el-cp', 'loong64-ls')]
    assert len(cases) == 3
    consumer = work / 'consumer.o'
    run(['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-I', source, '-I', source / 'include',
         '-c', r / 'single.cpp', '-o', consumer], 'consumer')
    build = work / 'build'
    run(['cmake', '-S', source, '-B', build, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
         '-DCMAKE_C_COMPILER=' + cc,
         '-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer ' +
         ('-Wno-error=discarded-qualifiers' if cc == 'gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),
         '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
         *['-DCAPSTONE_' + name + '_SUPPORT=ON' for name in ('X86', 'ARM', 'AARCH64', 'MIPS', 'PPC', 'RISCV', 'LOONGARCH', 'ARC')],
         '-DCAPSTONE_BUILD_SHARED_LIBS=OFF', '-DCAPSTONE_BUILD_CSTEST=OFF',
         '-DCAPSTONE_BUILD_CSTOOL=OFF', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'], 'configure')
    captured, bins, objects = {}, dict(original={}, isolated={}), {}
    for variant in ('integer', 'scan'):
        run(['git', 'reset', '--hard', meta['parent']], 'reset-' + variant)
        if variant == 'scan':
            run(['git', 'apply', '--index', r / 'candidate.patch'], 'apply')
            assert sp.check_output(['git', '-C', source, 'write-tree'], text=True).strip() == meta['tree']
        for placement in ('original', 'isolated'):
            if placement == 'isolated':
                file = source / 'Mapping.c'
                text = file.read_text()
                anchor = 'const cs_ac_type mapping_get_op_access('
                assert text.count(anchor) == 1
                text = text.replace(anchor,
                    '__attribute__((section("' + layout.SECTION + '")))\n' + anchor)
                file.write_text(text)
                save('diagnostic-source-' + variant + '.json', dict(
                    only_added_attribute=True, mapping_sha256=layout.sha(file),
                    source_diff=sp.check_output(['git', '-C', source, 'diff', '--', 'Mapping.c'], text=True)))
            label = placement + '-' + variant
            run(['cmake', '--build', build, '--target', 'capstone_static', '--parallel', '4'], 'build-' + label)
            root = build / 'CMakeFiles/capstone.dir'
            objects[label] = {str(p.relative_to(root)): layout.sha(p) for p in root.rglob('*.o')}
            executable, linkmap = work / label, work / (label + '.map')
            run(['clang++', consumer, build / 'libcapstone.a', '-lm', '-Wl,-Map=' + str(linkmap),
                 '-o', executable], 'link-' + label)
            captured[label] = layout.freeze_objects(root, build / 'libcapstone.a', linkmap,
                                                    work / ('objects-' + label))
            bins[placement][variant] = executable
    base = objects['original-integer']
    for label, hashes in objects.items():
        assert hashes.keys() == base.keys()
        differences = [name for name in base if base[name] != hashes[name]]
        assert set(differences) <= {'Mapping.c.o'}, (label, differences)
    save('object-controls.json', objects)
    names = {tuple(p.name for p in paths) for paths in captured.values()}
    assert len(names) == 1
    isolated = {variant: next(p for p in captured['isolated-' + variant] if p.name == 'Mapping.c.o')
                for variant in ('integer', 'scan')}
    # Moving the sole changed function must leave the remaining instruction body identical.
    assert layout.section_bytes(isolated['integer'], '.text') == layout.section_bytes(isolated['scan'], '.text')
    capacity = (max(len(layout.section_bytes(p, layout.SECTION)) for p in isolated.values()) + 63) // 64 * 64
    script = layout.linker_script(work, capacity)
    save('linker-layout.json', dict(capacity=capacity, script=script.read_text(),
                                   object_bytes_unchanged=True))
    calls = {}
    for variant in isolated:
        paths = captured['isolated-' + variant]
        target = work / ('controlled-' + variant)
        run(['clang++', consumer, *paths, '-lm', '-Wl,-T,' + str(script), '-o', target],
            'link-controlled-' + variant)
        assert len(layout.section_bytes(target, layout.SECTION)) == capacity
        calls[variant] = layout.check_calls(target)
        bins['isolated'][variant] = target
    save('relocation-controls.json', calls)
    controls = {name: layout.compare_addresses(pair['integer'], pair['scan']) for name, pair in bins.items()}
    save('address-controls.json', controls)
    for placement, pair in bins.items():
        for variant, target in pair.items():
            (evidence / (placement + '-' + variant + '-symbols.txt')).write_bytes(
                sp.check_output(['nm', '-S', '-n', '--defined-only', target]))
            with gzip.open(evidence / (placement + '-' + variant + '-assembly.gz'), 'wb') as out:
                out.write(sp.check_output(['objdump', '-dr', target]))
    # Record imperfect isolation rather than silently claiming it is complete.
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    rows = layout.measure(work, bins, cases, save)
    assert len(rows) == 18
    save('complete.json', dict(success=True, observations=len(rows), diagnostic_only=True,
                               address_isolation=controls['isolated']['all_common_addresses_equal']))
finally:
    sp.run(['git', '-C', source, 'reset', '--hard', json.loads((r / 'tree.json').read_text())['parent']],
           stdout=sp.DEVNULL, check=True)
    files = [p for p in work.rglob('*') if p.is_file()]
    size = sum(p.stat().st_size for p in files)
    shutil.rmtree(work)
    save('cleanup.json', dict(removed=not work.exists(), files=len(files), bytes=size))
