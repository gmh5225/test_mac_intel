from pathlib import Path
import gzip
import hashlib
import json
import os
import platform
import shutil
import subprocess as sp
import tempfile
import corpus
from layout import linked_layout

r = Path(__file__).resolve().parent
s = r.parent / 'source'
e = r.parent / 'evidence'
e.mkdir()
cc = os.environ['MEASURE_CC']
active = cc == 'clang'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
meta = json.loads((r / 'candidate.json').read_text())


def save(name, value):
    (e / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')


def run(args, label, cwd=None):
    print(label, flush=True)
    with (e / (label + '.log')).open('w') as f:
        sp.run(list(map(str, args)), cwd=cwd, stdout=f, stderr=sp.STDOUT, check=True)


assert sp.check_output(['git', '-C', s, 'rev-parse', 'HEAD'], text=True).strip() == meta['parent']
assert not sp.check_output(['git', '-C', s, 'status', '--porcelain'])
assert sha(r / 'candidate.patch') == meta['sha256']
w = Path(tempfile.mkdtemp(prefix='capstone-clang-rolled-alias-cost-'))
try:
    if hasattr(os, 'sched_getaffinity'):
        os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    b = w / 'build'
    save('compiler', dict(compiler=sp.check_output([cc, '--version'], text=True),
                         cpu=Path('/proc/cpuinfo').read_text(), host=platform.platform()))
    all_cases = corpus.prepare(r, w, e, run)
    selected = {'arm-ls', 'arm64-ls', 'mips64el-ls', 'putty-32-0.85', 'putty-64-0.85'}
    cases = [x for x in all_cases if x['name'] in selected]
    assert len(cases) == len(selected)
    save('selected-panels', dict(cases=sorted(selected), modes=[0, 1, 2], traversals=3))
    run(['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-I', s, '-I', s / 'include',
         '-c', r / 'single.cpp', '-o', w / 'single.o'], 'consumer')
    save('consumer-object', dict(sha256=sha(w / 'single.o'), all_variants_identical=True))
    run(['cmake', '-S', s, '-B', b, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
         '-DCMAKE_C_COMPILER=' + cc, '-DCMAKE_C_FLAGS=' +
         ('-Wno-error=discarded-qualifiers' if cc == 'gcc' else
          '-Wno-error=incompatible-pointer-types-discards-qualifiers'),
         '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
         *['-DCAPSTONE_' + a + '_SUPPORT=ON' for a in ('X86', 'ARM', 'AARCH64', 'MIPS')],
         '-DCAPSTONE_BUILD_SHARED_LIBS=ON', '-DCAPSTONE_BUILD_CSTEST=ON',
         '-DCAPSTONE_BUILD_MACOS_THIN=ON', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
         '-DCAPSTONE_BUILD_CSTOOL=OFF'], 'configure')
    units = ['mapping', 'api', 'arm_post_index', 'detail_option', 'aarch64_scan',
             'aarch64_postprocess', 'mips_scan', 'x86_scan_batch', 'sstream', 'register_descriptors']
    objects, binaries, libraries = {}, {}, {}
    for key in ('base', 'trie'):
        if key == 'trie':
            run(['git', 'apply', '--index', r / 'candidate.patch'], 'apply', s)
            assert sp.check_output(['git', '-C', s, 'write-tree'], text=True).strip() == meta['tree']
            save('tested-source', dict(tree=meta['tree'], patch_sha256=meta['sha256']))
        run(['cmake', '--build', b, '--target', 'capstone_static', 'capstone_shared',
             *units, '--parallel', '4'], 'build-' + key)
        run(['ctest', '--test-dir', b, '--no-tests=error', '--output-on-failure',
             '-R', '^unit_(' + '|'.join(units) + ')$'], 'units-' + key)
        objdir = b / 'CMakeFiles/capstone.dir'
        objects[key] = {str(f.relative_to(objdir)): sha(f) for f in objdir.rglob('*.o')}
        if key == 'trie':
            changed = [n for n in objects['base'] if objects[key].get(n) != objects['base'][n]]
            assert set(changed) == ({'arch/AArch64/AArch64Mapping.c.o', 'arch/Mips/MipsMapping.c.o'} if active else set()), changed
            assert set(objects['trie']) - set(objects['base']) == {'AliasMapping.c.o'}
            assert set(objects['base']) <= set(objects['trie'])
            save('object-isolation', dict(active=active, changed=changed, added=['AliasMapping.c.o'],
                 unchanged=len(objects['base']) - len(changed), mapping_object_identical=True))
        identities = {}
        for arch in ('AArch64','Mips'):
            assembly = sp.check_output(['objdump','-dr',objdir/('arch/'+arch+'/'+arch+'Mapping.c.o')])
            with gzip.open(e/(key+'-'+arch+'-object.asm.gz'),'wb') as stream:stream.write(assembly)
            if key == 'trie':
                before_asm=gzip.decompress((e/('base-'+arch+'-object.asm.gz')).read_bytes())
                normalized=assembly.replace(('map_set_'+arch.lower()+'_alias_id').encode(),b'map_set_alias_id')
                identities[arch]=dict(unchanged_except_lookup_target=before_asm==normalized,before_sha256=hashlib.sha256(before_asm).hexdigest(),normalized_after_sha256=hashlib.sha256(normalized).hexdigest())
                assert before_asm==normalized,(arch,'caller machine code changed beyond the lookup target')
        if key == 'trie':save('caller-identity',identities)
        save('object-digests', objects)
        with gzip.open(e / (key + '-mapping-object.asm.gz'), 'wb') as f:
            f.write(sp.check_output(['objdump', '-dr', objdir / 'Mapping.c.o']))
        if key == 'trie':
            with gzip.open(e / 'trie-alias-object.asm.gz', 'wb') as f:
                f.write(sp.check_output(['objdump', '-dr', objdir / 'AliasMapping.c.o']))
            (e / 'trie-alias-sections.txt').write_bytes(sp.check_output(['readelf', '-WS', objdir / 'AliasMapping.c.o']))
            sections=sp.check_output(['objdump','-h',objdir/'AliasMapping.c.o'],text=True)
            text_rows=[line.split() for line in sections.splitlines() if len(line.split())>2 and line.split()[1]=='.text']
            assert len(text_rows)==1 and int(text_rows[0][2],16)==0, sections
            save('lookup-section-isolation',dict(ordinary_text_bytes=0,sections=sections))
            run(['python3', s / 'suite/synctools/alias_mnemonic_trie.py', '--check'], 'generator')
            if active:
                run(['python3', r / 'oracle.py', s, b], 'alias-oracle')
                shutil.copyfile(r / 'direct-alias-check.log', e / 'direct-alias-check.log')
            else:
                save('direct-alias-scope', dict(active=False, reason='GCC retains the original implementation; exact object and executable identity are required.'))
        binary = w / key
        run(['clang++', w / 'single.o', b / 'libcapstone.a', '-lm',
             '-Wl,-Map,' + str(e / (key + '-link.map')), '-o', binary], 'link-' + key)
        binaries[key] = binary
        libraries[key] = w / (key + '.so')
        shutil.copyfile(b / 'libcapstone.so', libraries[key])
        (e / (key + '-symbols.txt')).write_bytes(sp.check_output(['nm', '-n', '-S', '--defined-only', binary]))
        (e / (key + '-sections.txt')).write_bytes(sp.check_output(['readelf', '-WS', binary]))
        with gzip.open(e / (key + '-linked-disassembly.gz'), 'wb') as f:
            f.write(sp.check_output(['objdump', '-d', binary]))
    identity = dict(active=active, before=sha(binaries['base']), after=sha(binaries['trie']))
    identity['identical'] = identity['before'] == identity['after']
    save('binary-identity', identity)
    if not active:
        assert identity['identical'], 'Inactive GCC executable changed'
    layout=linked_layout(e / 'base-symbols.txt', e / 'trie-symbols.txt', 'output')
    save('linked-layout',layout)
    assert not layout['text']['changed'], 'Existing linked function positions or sizes changed'
    run(['clang++', '-O2', '-std=c++17', '-I', s / 'include', r / 'verify.cpp',
         '-ldl', '-o', w / 'verify'], 'verify-build')
    run([w / 'verify', libraries['base'], libraries['trie']], 'verify')
    costs = []
    for case in cases:
        for mode in (0, 1, 2):
            signatures = {}
            for key in ('base', 'trie'):
                ident = case['name'] + '-' + str(mode) + '-' + key
                raw = w / (ident + '.callgrind')
                args = [binaries[key], str(case['selector']), str(mode), case['path'], '1']
                run(['valgrind', '--tool=callgrind', '--demangle=no', '--collect-atstart=no',
                     '--toggle-collect=_ZL3runR7SessionRKSt6vectorIhSaIhEEj', '--dump-instr=yes',
                     '--collect-jumps=yes', '--cache-sim=yes', '--branch-sim=yes',
                     '--callgrind-out-file=' + str(raw), *args], 'cost-' + ident)
                log = (e / ('cost-' + ident + '.log')).read_text()
                output = json.loads(next(line for line in log.splitlines() if line.startswith('{')))
                signatures[key] = (output['first'], output['result'])
                assert signatures[key] == signatures['base']
                content = raw.read_text()
                events = next(line[8:].split() for line in content.splitlines() if line.startswith('events: '))
                counts = list(map(int, next(line[8:].split() for line in content.splitlines() if line.startswith('totals: '))))
                assert len(events) == len(counts) and counts[0] > 0
                costs.append(dict(case=case['name'], mode=mode, variant=key,
                                  events=dict(zip(events, counts)), result=signatures[key], collected_traversals=3))
                with gzip.open(e / (ident + '.callgrind.gz'), 'wb') as f:
                    f.write(raw.read_bytes())
                raw.unlink()
                save('instruction-costs', costs)
    assert len(costs) == 30
    save('complete', dict(success=True, traces=len(costs), cases=len(cases),
                         units_per_variant=len(units), native_qualification=False))
finally:
    files = [f for f in w.rglob('*') if f.is_file()]
    amount = sum(f.stat().st_size for f in files)
    shutil.rmtree(w)
    save('cleanup', dict(bytes=amount, files=len(files), removed=not w.exists()))
