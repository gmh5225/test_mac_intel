"""Test whether matching the changed x86 object's text extent restores other ISAs."""
from pathlib import Path
import hashlib
import json
import math
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys

import run

WORK = run.WORK
OUT = run.EVIDENCE
MEMBER = 'X86Mapping.c.o'


def output(args):
    return subprocess.check_output(list(map(str, args)), text=True)


def build_controls():
    objcopy = shutil.which('llvm-objcopy') or shutil.which('objcopy')
    assert objcopy
    arch = platform.machine()
    assert arch in ('x86_64', 'aarch64')
    nop = bytes.fromhex('90' if arch == 'x86_64' else '1f2003d5')
    texts, objects, archives = {}, {}, {}
    for label in ['base', 'new']:
        directory = WORK / ('layout-' + label)
        directory.mkdir()
        objects[label] = WORK / (label + '-build/CMakeFiles/capstone.dir/arch/X86') / MEMBER
        archives[label] = WORK / (label + '-build/libcapstone.a')
        raw = directory / 'text.bin'
        # Supplying a separate output keeps the verified object immutable.
        run.command([objcopy, '--dump-section', '.text=' + str(raw), objects[label],
                     directory / 'unmodified.o'], label + '-dump-text')
        texts[label] = raw.read_bytes()
    extent = max(map(len, texts.values()))
    assert len(texts['base']) != len(texts['new'])
    builds = {}
    for label in ['base', 'new']:
        directory = WORK / ('layout-' + label)
        padding = extent - len(texts[label])
        assert padding % len(nop) == 0
        padded = directory / MEMBER
        raw = directory / 'padded-text.bin'
        raw.write_bytes(texts[label] + nop * (padding // len(nop)))
        if padding:
            run.command([objcopy, '--update-section', '.text=' + str(raw), objects[label], padded],
                        label + '-extend-text')
        else:
            shutil.copyfile(objects[label], padded)
        roundtrip = directory / 'roundtrip.bin'
        run.command([objcopy, '--dump-section', '.text=' + str(roundtrip), padded,
                     directory / 'checked.o'], label + '-readback-text')
        assert roundtrip.read_bytes() == raw.read_bytes()
        archive = directory / 'libcapstone.a'
        shutil.copyfile(archives[label], archive)
        original = output(['ar', 't', archive]).splitlines()
        assert original.count(MEMBER) == 1
        run.command(['ar', 'r', archive, padded], label + '-replace-member')
        run.command(['ranlib', archive], label + '-archive-index')
        assert output(['ar', 't', archive]).splitlines() == original
        assert subprocess.check_output(['ar', 'p', archive, MEMBER]) == padded.read_bytes()
        for policy, library in [('fixed', archives[label]), ('padded', archive)]:
            for consumer in ('single', 'decoder'):
                name = '-'.join([policy, label, consumer])
                binary = WORK / name
                linkmap = OUT / (name + '.map')
                run.command(['clang++', '-no-pie', '-Wl,-Map,' + str(linkmap), WORK / (consumer + '.o'),
                             library, *([WORK / 'adapter/target/release/libiced_compare.a']
                                        if consumer == 'decoder' else []),
                             '-lpthread', '-ldl', '-lm', '-o', binary], name + '-link')
                assert re.search(r'Type:\s+EXEC', output(['readelf', '-h', binary]))
                builds[name] = dict(sha256=run.sha(binary), text=linked_text(binary, linkmap))
    run.write('text-extent.json', dict(extent=extent, lengths={k:len(v) for k,v in texts.items()},
                                      object_sha256={k:run.sha(v) for k,v in objects.items()}))
    run.write('linked-text.json', builds)
    comparison = []
    for consumer in ('single', 'decoder'):
        for policy in ('fixed', 'padded'):
            base = builds[policy + '-base-' + consumer]['text']
            new = builds[policy + '-new-' + consumer]['text']
            assert base.keys() == new.keys() and MEMBER in base and 'cs.c.o' in base
            others = sorted(member for member in base if member != MEMBER)
            comparison.append(dict(consumer=consumer, policy=policy, members=len(others),
                address_differences=[m for m in others if base[m]['address'] != new[m]['address']],
                byte_differences=[m for m in others if base[m]['sha256'] != new[m]['sha256']]))
    run.write('linked-comparison.json', comparison)


def linked_text(binary, linkmap):
    # GNU ld's map identifies the input archive member for each .text extent.
    segments = []
    for line in output(['readelf', '-lW', binary]).splitlines():
        words = line.split()
        if words and words[0] == 'LOAD':
            segments.append((int(words[1], 16), int(words[2], 16), int(words[4], 16)))
    pattern = re.compile(r'^ \.text\s+(0x[\da-f]+)\s+(0x[\da-f]+)\s+.*libcapstone\.a\(([^()]+)\)\s*$')
    content = binary.read_bytes()
    records = {}
    for line in linkmap.read_text().splitlines():
        match = pattern.match(line)
        if not match:
            continue
        address, size = int(match[1], 16), int(match[2], 16)
        if not size:
            continue
        offset, start, _ = next(s for s in segments if s[1] <= address and address + size <= s[1] + s[2])
        pos = offset + address - start
        assert match[3] not in records
        records[match[3]] = dict(address=address, size=size,
                                 sha256=hashlib.sha256(content[pos:pos + size]).hexdigest())
    assert len(records) > 40
    return records


def invoke(case, policy, side, repeats):
    consumer = case['consumer']
    binary = WORK / (consumer + '-' + side if policy == 'pie' else '-'.join([policy, side, consumer]))
    if consumer == 'single':
        args = [binary, case['selector'], run.MODES[case['mode']], case['path'], repeats]
    else:
        args = [binary, 'capstone', case['mode'], case['selector'], repeats, case['path']]
    row = json.loads(output(args))
    return dict(row, library_kind='capstone', consumer=consumer, case=case['name'],
                mode=case['mode'], policy=policy, side=side)


def measure():
    machine = platform.machine()
    allowed = sorted(os.sched_getaffinity(0))
    os.sched_setaffinity(0, {allowed[0]})
    assert os.sched_getaffinity(0) == {allowed[0]}
    run.write('placement-affinity.json', dict(machine=machine, original=allowed, cpu=allowed[0]))
    names = {'mips64el-ls', 'mips64el-cp', 'mips64el-sort', 'riscv64-ls', 'riscv64-cp',
             'arc-libm', 'putty-32-0.85', 'simd64'}
    cases = [c for c in json.loads((OUT / 'cases.json').read_text())
             if c['name'] in names and c['mode'] in ('format', 'detail')]
    assert len(cases) == 16
    variants = [(policy, side, copy) for copy in range(2) for policy in ('pie', 'fixed', 'padded')
                for side in ('base', 'new')]
    order = [0, 1, 11, 2, 10, 3, 9, 4, 8, 5, 7, 6]
    repeats = {}
    for index, case in enumerate(cases):
        rows = [invoke(case, policy, side, 1) for policy, side, copy in variants if copy == 0]
        assert run.check_outputs(rows, case)
        count = max(1, round(20_000_000 / max(rows[0]['cpu_ns'], 1)))
        warm = invoke(case, 'pie', 'base', count)
        repeats[index] = max(1, round(80_000_000 * count / max(warm['cpu_ns'], 1)))
    run.write('placement-plan.json', dict(cases=cases, repeats=repeats, variants=variants, order=order,
                                        cycles=12, target_ns=80_000_000))
    pairs = []
    with (OUT / 'placement-raw.jsonl').open('x') as raw:
        for cycle in range(12):
            for pos in range(len(cases)):
                index = (pos + cycle * 7) % len(cases)
                case = cases[index]
                rows = []
                for slot in order:
                    policy, side, copy = variants[(slot + cycle) % len(variants)]
                    row = invoke(case, policy, side, repeats[index])
                    row.update(copy=copy, cycle=cycle, position=pos, order_slot=len(rows))
                    raw.write(json.dumps(row) + '\n')
                    rows.append(row)
                assert run.check_outputs(rows, case)
                raw.flush()
                for policy in ('pie', 'fixed', 'padded'):
                    values = {(r['side'],r['copy']): r for r in rows if r['policy'] == policy}
                    pair = dict(cycle=cycle, case=case['name'], mode=case['mode'], policy=policy)
                    for timer in ('cpu_ns', 'wall_ns'):
                        base = [values['base',i][timer] for i in range(2)]
                        new = [values['new',i][timer] for i in range(2)]
                        pair[timer + '_gain'] = math.sqrt(base[0] * base[1] / (new[0] * new[1]))
                        pair[timer + '_base_aa'] = base[0] / base[1]
                        pair[timer + '_new_aa'] = new[0] / new[1]
                    pairs.append(pair)
            print('layout cycle', cycle + 1, flush=True)
    run.write('placement-pairs.json', pairs)
    groups = []
    for key in sorted({(r['case'],r['mode'],r['policy']) for r in pairs}):
        rows = [r for r in pairs if (r['case'],r['mode'],r['policy']) == key]
        assert len(rows) == 12
        groups.append(dict(case=key[0], mode=key[1], policy=key[2],
            median_cpu_gain=statistics.median(r['cpu_ns_gain'] for r in rows),
            positive_cycles=sum(r['cpu_ns_gain'] > 1 for r in rows),
            aa_outside_2pct=sum(abs(math.log(r[k])) > math.log(1.02) for r in rows
                                for k in ('cpu_ns_base_aa', 'cpu_ns_new_aa'))))
    run.write('placement-summary.json', dict(complete=True, groups=groups))


if __name__ == '__main__':
    if sys.argv[1:] == ['cleanup']:
        run.cleanup()
    else:
        build_controls()
        measure()
