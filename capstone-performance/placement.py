"""Isolate MIPS behavior and the linked addresses of unmodified backends on ELF."""
import argparse
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import struct
import subprocess

from run import EVIDENCE, MODES, SOURCE, WORK, command, sha, signature, write


OBJECTS = ('Mapping.c.o','MipsMapping.c.o')
VARIANTS = ('base','new','text-base','text-new','both-base','both-new','same-on','same-off','base-aa')
ORDER = (0,1,8,2,7,3,6,4,5)
ANCHORS = {('mips64el-ls','detail'),('mips64el-ls','format'),('mips64el-sort','detail'),
           ('mips64el-cp','format'),('s390x-ls','detail'),('ppc64el-ls','format'),
           ('putty-32-0.85','scan'),('putty-32-0.85','format')}
SYMBOLS = ('cs_disasm_iter', 'cs_decode_full_insn', 'cs_regs_access',
           'X86_getInstruction', 'X86_reg_access', 'X86_get_insn_id', 'X86_postprinter',
           'decodeInstructionFull', 'readModRM', 'X86_Intel_printInst',
           'X86_Intel_printInstructionPrechecked', 'map_set_alias_id',
           'map_set_alias_id_indexed','Mips_printer','Mips_LLVM_printInst',
           'x86_mapping_counts', 'reg_map')


def sections(image):
    if image[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', image, 18)[0] != 62:
        raise ValueError('expected a little endian x86-64 ELF')
    offset = struct.unpack_from('<Q', image, 40)[0]
    size, count, names = struct.unpack_from('<HHH', image, 58)
    headers = [struct.unpack_from('<IIQQQQIIQQ', image, offset + i * size) for i in range(count)]
    table = headers[names]
    strings = image[table[4]:table[4] + table[5]]
    result = {}
    for name, kind, flags, address, at, length, _, _, align, _ in headers:
        key = strings[name:strings.index(b'\0', name)].decode()
        result[key] = dict(type=kind, flags=flags, address=address, offset=at,
                           length=length, align=align)
    return result


def named_symbols(path):
    lines = subprocess.check_output(['nm', '-nS', '--defined-only', str(path)], text=True)
    matches = {}
    for line in lines.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) == 4 and fields[3] in SYMBOLS:
            matches.setdefault(fields[3], []).append(dict(address=int(fields[0], 16),
                    size=int(fields[1], 16), kind=fields[2]))
    return matches


def read_symbols(path):
    image = path.read_bytes()
    table = sections(image)
    named = named_symbols(path)
    for rows in named.values():
        for row in rows:
            address, size = row['address'], row['size']
            section = next(v for v in table.values() if v['flags'] & 2 and
                           v['address'] <= address and address + size <= v['address'] + v['length'])
            at = address - section['address'] + section['offset']
            data = image[at:at + size]
            row['first'] = data[:3].hex()
            row['sha256'] = __import__('hashlib').sha256(data).hexdigest()
    return dict(symbols=named, sections={k:v for k,v in table.items() if v['flags'] & 2},
                sha256=sha(path))


def objects(label):
    directory = WORK / (label + '-build/CMakeFiles/capstone.dir')
    return {name: next(directory.rglob(name)) for name in OBJECTS}


def pad_sections(image, lengths):
    # Keep section indices and relocations intact. Only move payloads that grow.
    header = struct.Struct('<IIQQQQIIQQ')
    if struct.unpack_from('<H', image, 16)[0] != 1:
        raise ValueError('expected a relocatable object')
    offset = struct.unpack_from('<Q', image, 40)[0]
    size, count, names = struct.unpack_from('<HHH', image, 58)
    if size != header.size or not 0 < names < count:
        raise ValueError('unsupported section table')
    entries = [list(header.unpack_from(image, offset + i * size)) for i in range(count)]
    strings = entries[names]
    original_names = image[strings[4]:strings[4] + strings[5]]
    names_blob = bytearray(original_names)
    by_name = {original_names[e[0]:original_names.index(b'\0', e[0])].decode(): e for e in entries}
    result = bytearray(image)

    def append(data, align):
        result.extend(bytes(-len(result) % max(align, 1)))
        start = len(result)
        result.extend(data)
        return start

    for name, (length, align) in lengths.items():
        entry = by_name.get(name)
        if entry is None:
            if name != '.rodata':
                raise ValueError('unexpected missing section ' + name)
            entry = [len(names_blob), 1, 2, 0, 0, 0, 0, 0, 1, 0]
            entries.append(entry)
            names_blob.extend(name.encode() + b'\0')
        if entry[1] != 1 or entry[5] > length:
            raise ValueError('invalid section growth ' + name)
        if entry[5] != length or entry[8] != align:
            old = image[entry[4]:entry[4] + entry[5]]
            entry[4] = append(old + bytes(length - len(old)), align)
            entry[5], entry[8] = length, align
    if names_blob != original_names:
        strings[4] = append(names_blob, strings[8])
        strings[5] = len(names_blob)
    new_table = append(b''.join(header.pack(*e) for e in entries), 8)
    struct.pack_into('<Q', result, 40, new_table)
    struct.pack_into('<H', result, 60, len(entries))
    return result


def relocation_inventory(image):
    return {name: image[v['offset']:v['offset'] + v['length']]
            for name, v in sections(image).items() if v['type'] in (4, 9)}


def archive(label, pair, matched):
    # Enlarge each section only to the maximum of the two observed object sizes.
    # No instructions are replaced. The original archives are kept for the natural pair.
    directory = WORK / (pair + '-' + label)
    directory.mkdir()
    original = WORK / (label + '-build/libcapstone.a')
    archive_path = directory / 'libcapstone.a'
    shutil.copyfile(original, archive_path)
    members = subprocess.check_output(['ar', 't', original], text=True).splitlines()
    changes = []
    for name in OBJECTS:
        if members.count(name) != 1:
            raise ValueError('expected a unique archive member: ' + name)
        inputs = {side: objects(side)[name].read_bytes() for side in ['base', 'new']}
        tables = {side: sections(data) for side, data in inputs.items()}
        lengths = {}
        for section in matched:
            existing = [t[section] for t in tables.values() if section in t]
            if not existing:
                continue
            length = max(v['length'] for v in existing)
            align = max(v['align'] for v in existing)
            before = tables[label].get(section, {}).get('length', 0)
            lengths[section] = (length, align)
            changes.append(dict(object=name, section=section, before=before, after=length, align=align))
        after = pad_sections(inputs[label], lengths)
        if relocation_inventory(after) != relocation_inventory(inputs[label]):
            raise ValueError('relocations changed: ' + name)
        target = directory / name
        target.write_bytes(after)
        check = sections(after)
        for sec in matched:
            before = tables[label].get(sec)
            expected = max((t[sec]['length'] for t in tables.values() if sec in t), default=0)
            if expected and check[sec]['length'] != expected:
                raise ValueError('size mismatch: ' + name + sec)
            if before:
                part = inputs[label][before['offset']:before['offset'] + before['length']]
                pos = check[sec]['offset']
                if after[pos:pos + len(part)] != part:
                    raise ValueError('original bytes modified: ' + name + sec)
    command(['ar', 'rDs', archive_path, *(directory / n for n in OBJECTS)], pair + '-' + label + '-archive')
    if subprocess.check_output(['ar', 't', archive_path], text=True).splitlines() != members:
        raise ValueError('archive member order changed')
    return archive_path, changes


def prepare():
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise RuntimeError('the experiment requires Linux x86-64')
    metadata = {}
    for pair, matched in [('text', ['.text']), ('both', ['.text', '.rodata'])]:
        for side in ['base', 'new']:
            lib, changes = archive(side, pair, matched)
            metadata[pair + '-' + side] = changes
            for consumer in ['single', 'decoder']:
                output = WORK / (consumer + '-' + pair + '-' + side)
                extra = [WORK / 'adapter/target/release/libiced_compare.a'] if consumer == 'decoder' else []
                command(['clang++', WORK / (consumer + '.o'), lib, *extra, '-lpthread', '-ldl',
                         '-lm', '-o', output], output.name + '-link')
    write('placement-sections.json', metadata)
    import shlex
    tree=WORK/'new'
    q=tree/'arch/Mips/MipsMapping.c';old=q.read_text()
    key='map_set_alias_id_indexed(MI, O, insn_alias_mnem_map, mips_alias_index,'
    assert old.count(key)==1
    mod=old.replace('void Mips_printer(', '#include <stdlib.h>\nstatic int force_linear;\n__attribute__((constructor)) static void mode(void) {force_linear = getenv("CAPSTONE_LINEAR_ALIAS") != NULL;}\nvoid Mips_printer(')
    mod=mod.replace(key,'if (force_linear) map_set_alias_id(MI,O,insn_alias_mnem_map,ARR_SIZE(insn_alias_mnem_map)); else '+key)
    c=next(row for row in json.loads((WORK/'new-build/compile_commands.json').read_text()) if row['file'].endswith('/MipsMapping.c'))
    out=WORK/'same';out.mkdir();a=shlex.split(c['command']);obj=out/'MipsMapping.c.o';a[a.index('-o')+1]=str(obj)
    try:
        q.write_text(mod);command(a,'compile-same-image',Path(c['directory']))
    finally:
        q.write_text(old)
    lib=out/'libcapstone.a';shutil.copyfile(WORK/'new-build/libcapstone.a',lib);command(['ar','rDs',lib,obj],'same-archive')
    for consumer in ('decoder','single'):
        extra=[WORK/'adapter/target/release/libiced_compare.a'] if consumer=='decoder' else []
        command(['clang++',WORK/(consumer+'.o'),lib,*extra,'-lpthread','-ldl','-lm','-o',WORK/(consumer+'-same')],consumer+'-same-link')
    lookup = {}
    for consumer in ['single', 'decoder']:
        for variant in (*VARIANTS[:6],'same'):
            name = consumer + '-' + variant
            lookup[name] = read_symbols(WORK / name)
    write('placement-symbols.json', lookup)
    for case in cases():
        expected = None
        for variant in VARIANTS:
            row = observe(case, variant, 1, lookup)
            actual = signature(row, case['consumer'])
            if expected is not None and expected != actual:
                raise ValueError(f'preflight output mismatch {case["name"]} {case["mode"]} {variant}')
            expected = actual
    print('Prepared and checked all placement controls.', flush=True)


def cases():
    all_cases = json.loads((EVIDENCE / 'cases.json').read_text())
    return [c for c in all_cases if (c['name'], c['mode']) in ANCHORS or
            (c['consumer'] == 'decoder' and c['mode'] == 'detail')]


def observe(case, variant, repeats, lookup):
    label={'same-on':'same','same-off':'same','base-aa':'base'}.get(variant,variant)
    name=case['consumer']+'-'+label
    env=dict(os.environ)
    if variant=='same-off':env['CAPSTONE_LINEAR_ALIAS']='1'
    args = (['capstone', case['mode'], str(case['selector']), str(repeats), case['path']]
            if case['consumer'] == 'decoder' else
            [str(case['selector']), str(MODES[case['mode']]), case['path'], str(repeats)])
    output = subprocess.check_output([WORK / name, *args], text=True, env=env)
    return json.loads(output)


def measure():
    allowed = sorted(os.sched_getaffinity(0))
    os.sched_setaffinity(0, {allowed[0]})
    selected = sorted(os.sched_getaffinity(0))
    if selected != [allowed[0]]:
        raise RuntimeError('CPU affinity did not take effect')
    lookup = json.loads((EVIDENCE / 'placement-symbols.json').read_text())
    for name, info in lookup.items():
        if info['sha256'] != sha(WORK / name):
            raise ValueError('linked executable changed')
    rows = cases()
    calibration = []
    for c in rows:
        a = observe(c, 'base', 1, lookup)
        n = max(1, round(25_000_000 / a['cpu_ns']))
        b = observe(c, 'base', n, lookup)
        calibration.append(dict(first=a, warm=b, repeats=max(1, round(n * 160_000_000 / b['cpu_ns']))))
    write('placement-plan.json', dict(allowed=allowed, selected=selected, cases=rows, calibration=calibration,
          variants=VARIANTS, order=ORDER, cycles=9, rotation=3, target_cpu_ms=160))
    with (EVIDENCE / 'placement-raw.jsonl').open('x') as out:
        for cycle in range(9):
            for pos in range(len(rows)):
                i = (pos + 3 * cycle) % len(rows)
                case = rows[i]
                expected = None
                for slot, idx in enumerate(ORDER):
                    variant = VARIANTS[(idx + cycle) % len(VARIANTS)]
                    row = observe(case, variant, calibration[i]['repeats'], lookup)
                    row.update(case=case['name'], mode=case['mode'], variant=variant, cycle=cycle, slot=slot)
                    out.write(json.dumps(row) + '\n')
                    out.flush()
                    actual = signature(row, case['consumer'])
                    if expected is not None and expected != actual:
                        raise ValueError(f'measured output mismatch {case["name"]} {variant}')
                    expected = actual
            print('Placement cycle', cycle + 1, 'of 9 complete.', flush=True)
    write('placement-complete.json', dict(complete=True, cases=len(rows), samples=len(rows)*81))


def finish():
    EVIDENCE.mkdir(exist_ok=True)
    complete_path = EVIDENCE / 'placement-complete.json'
    complete = json.loads(complete_path.read_text()) if complete_path.exists() else {'complete': False}
    write('summary.json', dict(experiment='ELF placement', **complete))
    lines = ['# ELF placement experiment', '', f"Timing complete: {complete['complete']}."]
    if complete['complete']:
        lines.append(f"{complete['samples']} observations across {complete['cases']} cases.")
    report = '\n'.join(lines) + '\n'
    (EVIDENCE / 'report.md').write_text(report)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as out:
            out.write(report)
    from run import cleanup
    cleanup()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['prepare', 'measure', 'finish'])
    args = parser.parse_args()
    {'prepare': prepare, 'measure': measure, 'finish': finish}[args.phase]()
