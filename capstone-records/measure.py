"""Compare the exact held candidate with a matched downstream layout control."""
from pathlib import Path
from collections import defaultdict
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
w = Path(tempfile.mkdtemp(prefix='capstone-vex-mixed-layout-'))
try:
    s, b = w / 'source', w / 'build'
    run(['git', 'clone', '-q', '--shared', '--no-checkout', original, s], 'clone')
    run(['git', '-C', s, 'checkout', '-q', '--detach', meta['parent']], 'checkout')
    cases = [x for x in corpus.prepare(r, w, e, run)
             if x['name'] in ('arm-ls', 'arm-sort', 'arm-cp', 'mips64el-ls')]
    assert len(cases) == 4
    run(['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-I', s, '-I', s / 'include',
         '-c', r / 'single.cpp', '-o', w / 'single.o'], 'consumer')
    run(['cmake', '-S', s, '-B', b, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
         '-DCMAKE_C_COMPILER=clang', '-DCMAKE_C_FLAGS=-Wno-error=incompatible-pointer-types-discards-qualifiers',
         '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
         *['-DCAPSTONE_' + a + '_SUPPORT=ON' for a in ['X86', 'ARM', 'AARCH64', 'MIPS']],
         '-DCAPSTONE_BUILD_SHARED_LIBS=OFF', '-DCAPSTONE_BUILD_STATIC_LIBS=ON',
         '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF', '-DCAPSTONE_BUILD_CSTOOL=OFF'], 'configure')
    linker = w / 'placed.ld'
    linker.write_text('''SECTIONS {
  .cs_vector_diag_text : { *(.cs_vector_diag_text) }
  .cs_vector_diag_rodata : { *(.cs_vector_diag_rodata*) }
  .cs_x86_vex32_text : { *(.cs_x86_vex32_text) }
  .cs_x86_vex32_rodata : { *(.cs_x86_vex32_rodata) }
} INSERT AFTER .bss;
''')
    shutil.copyfile(linker, e / 'diagnostic-layout.ld')
    binaries, layouts, symbol_tables, object_hashes = {}, {}, {}, {}
    relocated_names = set()
    for label in ('base', 'scan'):
        if label == 'scan':
            run(['git', '-C', s, 'apply', '--index', r / 'scan.patch'], 'apply-candidate')
            assert sp.check_output(['git', '-C', s, 'write-tree'], text=True).strip() == meta['tree']
        run(['cmake', '--build', b, '--target', 'capstone_static', '--parallel', '4'], 'build-' + label)
        root = b / 'CMakeFiles/capstone.dir'
        object_hashes[label] = {str(p.relative_to(root)): sha(p) for p in root.rglob('*.o')}
        binaries[label] = w / label
        run(['clang++', w / 'single.o', b / 'libcapstone.a', '-lm', '-o', binaries[label]], 'link-' + label)
        symbol_tables[label] = symbols(binaries[label], label)
        layouts[label] = sections(binaries[label])
        controlled = w / ('lib-' + label + '.a')
        shutil.copyfile(b / 'libcapstone.a', controlled)
        original_object = root / 'arch/X86/X86VectorOutput.c.o'
        new_object = w / ('object-' + label) / 'X86VectorOutput.c.o'
        new_object.parent.mkdir()
        renames = []
        with original_object.open('rb') as stream:
            elf = ELFFile(stream)
            for section in elf.iter_sections():
                if section.name == '.text':
                    renames.append((section.name, '.cs_vector_diag_text'))
                elif section.name.startswith('.rodata'):
                    renames.append((section.name, '.cs_vector_diag_rodata' + section.name[len('.rodata'):]))
            symtab = elf.get_section_by_name('.symtab')
            relocated_sections = {old for old, new in renames}
            for symbol in symtab.iter_symbols():
                index = symbol['st_shndx']
                if isinstance(index, int) and elf.get_section(index).name in relocated_sections and symbol.name:
                    relocated_names.add(symbol.name)
        assert any(old == '.text' for old, _ in renames) and any(old == '.rodata' for old, _ in renames)
        run(['objcopy', *[arg for old, new in renames for arg in ('--rename-section', old + '=' + new)],
             original_object, new_object], 'relocate-object-' + label)
        with original_object.open('rb') as left, new_object.open('rb') as right:
            old, new = ELFFile(left), ELFFile(right)
            for before, after in renames:
                assert old.get_section_by_name(before).data() == new.get_section_by_name(after).data()
        run(['ar', 'r', controlled, new_object], 'replace-object-' + label)
        run(['ranlib', controlled], 'index-archive-' + label)
        key = 'placed-' + label
        binaries[key] = w / key
        run(['clang++', w / 'single.o', controlled, '-Wl,-T,' + str(linker), '-lm', '-o', binaries[key]], 'link-' + key)
        symbol_tables[key] = symbols(binaries[key], key)
        layouts[key] = sections(binaries[key])
        save('object-relocation-' + label, dict(sections=renames, payload_bytes_identical=True,
             original_sha256=sha(original_object), relocated_sha256=sha(new_object)))
    save('object-digests', object_hashes)
    changed = [key for key, value in object_hashes['base'].items() if object_hashes['scan'].get(key) != value]
    assert set(changed) == {'arch/X86/X86OutputIterator.c.o', 'arch/X86/X86VectorOutput.c.o'}
    assert set(object_hashes['scan']) - set(object_hashes['base']) == {'arch/X86/X86Vex32Output.c.o'}
    left, right = symbol_tables['placed-base'], symbol_tables['placed-scan']
    ignored = relocated_names | {'X86_writeVex32RegisterOutput', 'writeVex32MemoryOutput'}
    mismatches = {name: [left[name], right.get(name)] for name in sorted(left)
                  if name not in ignored and left[name] != right.get(name)}
    text_equal = layouts['placed-base']['.text'] == layouts['placed-scan']['.text']
    save('layout-control', dict(main_text_identical=text_equal, unchanged_symbols_match=not mismatches,
         differences=mismatches, ignored_relocated_symbols=sorted(ignored), sections=layouts,
         diagnostic_only=True, no_microarchitecture_mechanism_claim=True))
    # A mismatched control is evidence, but must not be timed as a causal test.
    assert text_equal and not mismatches, (text_equal, mismatches)
    binaries['aa'] = w / 'aa'
    shutil.copyfile(binaries['base'], binaries['aa'])
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
    keys = ['base', 'aa', 'scan', 'placed-base', 'placed-scan']
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
                pair['isolated_gain'] = sum(times['placed-base']) / sum(times['placed-scan'])
                pairs.append(pair)
            measurements.append(dict(case=case['name'], mode=0, launch=launch, pairs=pairs,
                 median={key: statistics.median(v[key] for v in pairs) for key in pairs[0]}, result=reference))
            save('timings', measurements)
    save('complete', dict(success=True, cases=len(measurements), diagnostic_only=True,
                         candidate_qualified=False, main_text_identical=True, unchanged_symbols_match=True))
finally:
    amount = sum(p.stat().st_size for p in w.rglob('*') if p.is_file())
    shutil.rmtree(w)
    save('cleanup', dict(bytes=amount, removed=not w.exists()))
