"""Compare the exact held candidate with a matched downstream layout control."""
from pathlib import Path
from collections import defaultdict, Counter
import hashlib
import json
import os
import platform
import re
import shutil
import statistics
import subprocess as sp
import tempfile

from elftools.elf.elffile import ELFFile
import corpus

r = Path(__file__).resolve().parent
e = r.parent / 'evidence'
e.mkdir()
original = r.parent / 'source'
meta = json.loads((r / 'candidate.json').read_text())


def save(name, value):
    (e / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args, label, cwd=None):
    print(label, flush=True)
    with (e / (label + '.log')).open('w') as log:
        sp.run(list(map(str, args)), cwd=cwd, stdout=log, stderr=sp.STDOUT, check=True)


def symbols(binary, label):
    raw = sp.check_output(['nm', '-n', '-S', '--defined-only', binary], text=True)
    (e / (label + '-symbols.txt')).write_text(raw)
    (e / (label + '-sections.txt')).write_bytes(sp.check_output(['readelf', '-WS', binary]))
    (e / (label + '-segments.txt')).write_bytes(sp.check_output(['readelf', '-Wl', binary]))
    result = defaultdict(list)
    for line in raw.splitlines():
        match = re.fullmatch(r'([0-9a-f]+)\s+([0-9a-f]+)\s+(\S)\s+(.+)', line)
        if match:
            result[match[4]].append([int(match[1], 16), int(match[2], 16), match[3]])
    return dict(result)


def sections(binary):
    with binary.open('rb') as stream:
        elf = ELFFile(stream)
        return {s.name: dict(address=s['sh_addr'], size=s['sh_size'],
                            sha256=hashlib.sha256(s.data()).hexdigest())
                for s in elf.iter_sections() if s['sh_flags'] & 2}


assert platform.system() == 'Linux' and platform.machine() == 'x86_64'
version = sp.check_output(['clang', '--version'], text=True)
assert int(re.search(r'clang version (\d+)', version)[1]) >= 17
assert sha(r / 'scan.patch') == meta['sha256']
save('environment', dict(compiler=version, cpu=Path('/proc/cpuinfo').read_text(),
                         diagnostic_only=True, source=meta))
w = Path(tempfile.mkdtemp(prefix='capstone-vex32-shared-prefix-'))
try:
    s, b = w / 'source', w / 'build'
    prior = json.loads((r / 'prior.json').read_text())
    assert prior['parent'] == meta['parent'] and sha(r/'prior.patch') == prior['sha256']
    run(['git', 'clone', '-q', '--shared', '--no-checkout', original, s], 'clone')
    run(['git', '-C', s, 'checkout', '-q', '--detach', meta['parent']], 'checkout')
    cases = [x for x in corpus.prepare(r, w, e, run) if x['name'] in ('arm-cp', 'mips64el-ls')]
    assert len(cases) == 2
    run(['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-I', s, '-I', s/'include',
         '-c', r/'single.cpp', '-o', w/'single.o'], 'consumer')
    run(['cmake', '-S', s, '-B', b, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
         '-DCMAKE_C_COMPILER=clang', '-DCMAKE_C_FLAGS=-Wno-error=incompatible-pointer-types-discards-qualifiers',
         '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
         *['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ['X86','ARM','AARCH64','MIPS']],
         '-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON',
         '-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF'], 'configure')
    binaries, layouts, symbol_tables, object_hashes = {}, {}, {}, {}
    vector_symbols = set()
    for label in ('base','prior','scan'):
        if label != 'base':
            run(['git','-C',s,'apply','--index',r/(label+'.patch')],'apply-'+label)
            expected = prior if label == 'prior' else meta
            assert sp.check_output(['git','-C',s,'write-tree'],text=True).strip()==expected['tree']
        run(['cmake','--build',b,'--target','capstone_static','--parallel','4'],'build-'+label)
        if label == 'scan':
            run(['cmake','--build',b,'--target','x86_simple_output','--parallel','4'],'build-active-unit')
            run(['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_x86_simple_output$'],'active-unit')
        objroot=b/'CMakeFiles/capstone.dir'
        object_hashes[label]={str(p.relative_to(objroot)):sha(p) for p in objroot.rglob('*.o')}
        vector=objroot/'arch/X86/X86VectorOutput.c.o'
        vector_symbols.update(symbols(vector,label+'-vector'))
        import gzip
        with gzip.open(e/(label+'-vector.asm.gz'),'wb') as f:
            f.write(sp.check_output(['objdump','-dr',vector]))
        if label != 'base':
            with gzip.open(e/(label+'-vex32.asm.gz'),'wb') as f:
                f.write(sp.check_output(['objdump','-dr',objroot/'arch/X86/X86Vex32Output.c.o']))
        binaries[label]=w/label
        run(['clang++',w/'single.o',b/'libcapstone.a','-lm','-o',binaries[label]],'link-'+label)
        symbol_tables[label]=symbols(binaries[label],label)
        layouts[label]=sections(binaries[label])
        run(['git','-C',s,'read-tree','--reset','-u',meta['parent']],'reset-'+label)
        run(['git','-C',s,'clean','-fdx'],'clean-'+label)
    save('object-digests',object_hashes)
    for label in ('prior','scan'):
        delta={n for n,v in object_hashes['base'].items() if object_hashes[label].get(n)!=v}
        assert delta=={'arch/X86/X86OutputIterator.c.o','arch/X86/X86VectorOutput.c.o'},delta
    delta={n for n,v in object_hashes['prior'].items() if object_hashes['scan'].get(n)!=v}
    assert delta=={'arch/X86/X86VectorOutput.c.o','arch/X86/X86Vex32Output.c.o'},delta
    comparisons={}
    for label in ('prior','scan'):
        old, new=symbol_tables['base'],symbol_tables[label]
        differences={name:[v,new.get(name)] for name,v in old.items()
                     if name != 'X86_writeVectorOutput' and
                     Counter(tuple(x) for x in v if x[2] in 'tT') -
                     Counter(tuple(x) for x in new.get(name,[]) if x[2] in 'tT')}
        comparisons[label]=dict(other_original_text_positions_identical=not differences,
                                differences=differences,
                                vector_entry=symbol_tables[label]['X86_writeVectorOutput'])
    save('layout-control',dict(comparisons=comparisons,sections=layouts,
                              baseline_vector_entry=symbol_tables['base']['X86_writeVectorOutput'],
                              changed_from_prior=sorted(delta)))
    checks=[]
    for case in cases:
        for mode in range(3):
            outputs={k:json.loads(sp.check_output([p,str(case['selector']),str(mode),str(case['path']),'1'],text=True))
                     for k,p in binaries.items()}
            assert all([x['first'],x['result']]==[outputs['base']['first'],outputs['base']['result']] for x in outputs.values())
            checks.append(dict(case=case['name'],mode=mode,equal=True))
    save('semantic-cases',checks)
    if not comparisons['scan']['other_original_text_positions_identical']:
        save('complete',dict(success=True,layout_restored=False,native_timing_started=False,candidate_qualified=False))
    else:
        binaries['aa'] = w / 'aa'
        shutil.copy2(binaries['base'], binaries['aa'])
        payloads = {name: path.read_bytes() for name, path in binaries.items()}
        assert payloads['base'] == payloads['aa']
        maximum = max(map(len, payloads.values()))
        padded = {name: data + bytes(maximum - len(data)) for name, data in payloads.items()}
        image = w / 'same-image'
        image.write_bytes(padded['base'])
        image.chmod(0o755)
        inode = image.stat().st_ino
        probe = sp.run(['setarch', platform.machine(), '-R', '/bin/true'], capture_output=True, text=True)
        assert probe.returncode == 0, probe.stderr
        save('launch-controls', dict(launches=['images', 'same-file-fixed'], aslr_disable_returncode=0,
             inode=inode, fixed_size=maximum, original_sha256={k: hashlib.sha256(v).hexdigest() for k, v in payloads.items()}))
        os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})

        def sample(key, case, repeats, launch):
            args = list(map(str, [case['selector'], 0, case['path'], repeats]))
            if launch == 'images':
                args = [str(binaries[key]), *args]
            else:
                with image.open('r+b') as out:
                    assert out.write(padded[key]) == maximum
                assert image.stat().st_ino == inode and image.stat().st_size == maximum
                args = ['setarch', platform.machine(), '-R', str(image), *args]
            return json.loads(sp.check_output(args, text=True))

        measurements = []
        keys = ['base', 'aa', 'prior', 'scan']
        for case in cases:
            for launch in ('images', 'same-file-fixed'):
                warm = sample('base', case, 2, launch)
                repeats = max(2, min(4000, round(2 * 100e6 / warm['cpu_ns'])))
                pairs, reference = [], None
                for cycle in range(21):
                    order = keys[cycle % len(keys):] + keys[:cycle % len(keys)]
                    times = {key: [] for key in keys}
                    for key in order + order[::-1]:
                        out = sample(key, case, repeats, launch)
                        value = [out['first'], out['result']]
                        if reference is None:
                            reference = value
                        assert value == reference
                        times[key].append(out['cpu_ns'])
                    pair = {key: sum(times['base']) / sum(times[key]) for key in keys}
                    pairs.append(pair)
                measurements.append(dict(case=case['name'], mode=0, launch=launch, pairs=pairs,
                     median={key: statistics.median(v[key] for v in pairs) for key in pairs[0]}, result=reference))
                save('timings', measurements)
        save('complete', dict(success=True, cases=len(measurements), diagnostic_only=True,
                             candidate_qualified=False, layout_restored=True, native_timing_started=True))
finally:
    amount = sum(p.stat().st_size for p in w.rglob('*') if p.is_file())
    shutil.rmtree(w)
    save('cleanup', dict(bytes=amount, removed=not w.exists()))
