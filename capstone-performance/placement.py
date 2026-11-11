"""Isolate PPC behavior and the linked addresses of unmodified backends on ELF."""
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


OBJECTS = ('Mapping.c.o', 'PPCMapping.c.o', 'PPCInstPrinter.c.o')
VARIANTS = ('base', 'new', 'text-base', 'text-new', 'both-base', 'both-new', 'fallback', 'base-aa')
ORDER = (0, 1, 7, 2, 6, 3, 5, 4)
ANCHORS = {
    ('ppc64el-ls', 'detail'), ('ppc64el-ls', 'format'),
    ('arm-ls', 'detail'), ('riscv64-cp', 'format'),
    ('putty-32-0.85', 'scan'), ('putty-32-0.85', 'format'),
}
SYMBOLS = ('cs_disasm_iter', 'cs_decode_full_insn', 'cs_regs_access',
           'X86_getInstruction', 'X86_reg_access', 'X86_get_insn_id', 'X86_postprinter',
           'decodeInstructionFull', 'readModRM', 'X86_Intel_printInst',
           'X86_Intel_printInstructionPrechecked', 'map_set_alias_id',
           'map_try_alias_id_hint', 'PPC_printer', 'PPC_LLVM_printInst',
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
        args = []
        for section in matched:
            entries = {side: table.get(section) for side, table in tables.items()}
            existing = [v for v in entries.values() if v]
            if not existing:
                continue
            length = max(v['length'] for v in existing)
            align = max(v['align'] for v in existing)
            entry = entries[label]
            size = entry['length'] if entry else 0
            if size < length:
                data = b'' if not entry else inputs[label][entry['offset']:entry['offset'] + size]
                blob = directory / (name + section + '.bin')
                blob.write_bytes(data + bytes(length - size))
                args.extend(['--update-section' if entry else '--add-section', section + '=' + str(blob)])
                if not entry:
                    args.extend(['--set-section-flags', section + '=alloc,load,readonly,data,contents'])
            if not entry or entry['align'] != align:
                args.extend(['--set-section-alignment', section + '=' + str(align)])
            changes.append(dict(object=name, section=section, before=size, after=length, align=align))
        target = directory / name
        command(['objcopy', *args, objects(label)[name], target], pair + '-' + label + '-' + name)
        after = target.read_bytes()
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
    command(['cc', '-O2', '-Wall', '-Werror', '-shared', '-fPIC', SOURCE / 'placement_hook.c',
             '-ldl', '-o', WORK / 'placement-hook.so'], 'placement-hook')
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
    lookup = {}
    for consumer in ['single', 'decoder']:
        for variant in VARIANTS[:-2]:
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
    label = {'fallback':'new', 'base-aa':'base'}.get(variant, variant)
    name = case['consumer'] + '-' + label
    hook = 'map_set_alias_id' if label.endswith('base') else 'map_try_alias_id_hint'
    entry, = lookup[name]['symbols'][hook]
    first = bytes.fromhex(entry['first'])
    setting = ':'.join([format(entry['address'], 'x'), *(format(b, 'x') for b in first),
                        str(int(variant == 'fallback'))])
    env = dict(os.environ, LD_PRELOAD=str(WORK / 'placement-hook.so'), CAPSTONE_PROBE_ENTRY=setting)
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
        calibration.append(dict(first=a, warm=b, repeats=max(1, round(n * 250_000_000 / b['cpu_ns']))))
    write('placement-plan.json', dict(allowed=allowed, selected=selected, cases=rows, calibration=calibration,
          variants=VARIANTS, order=ORDER, cycles=8, rotation=3, target_cpu_ms=250))
    with (EVIDENCE / 'placement-raw.jsonl').open('x') as out:
        for cycle in range(8):
            for pos in range(len(rows)):
                i = (pos + 3 * cycle) % len(rows)
                case = rows[i]
                expected = None
                for slot, idx in enumerate(ORDER):
                    variant = VARIANTS[(idx + cycle) % 8]
                    row = observe(case, variant, calibration[i]['repeats'], lookup)
                    row.update(case=case['name'], mode=case['mode'], variant=variant, cycle=cycle, slot=slot)
                    out.write(json.dumps(row) + '\n')
                    out.flush()
                    actual = signature(row, case['consumer'])
                    if expected is not None and expected != actual:
                        raise ValueError(f'measured output mismatch {case["name"]} {variant}')
                    expected = actual
            print('Placement cycle', cycle + 1, 'of 8 complete.', flush=True)
    write('placement-complete.json', dict(complete=True, cases=len(rows), samples=len(rows)*64))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=['prepare', 'measure'])
    args = parser.parse_args()
    {'prepare': prepare, 'measure': measure}[args.phase]()
