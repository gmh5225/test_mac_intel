"""Recombine frozen diagnostic objects and trace the unchanged consumer."""
from pathlib import Path
import gzip
import hashlib
import json
import shutil
import subprocess as sp

def save(root, name, value):
    (root / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')

def archive_hashes(path):
    names = sp.check_output(['ar', 't', path], text=True).splitlines()
    assert len(names) == len(set(names))
    return {name: hashlib.sha256(sp.check_output(['ar', 'p', path, name])).hexdigest()
            for name in names}

def controls(build, temporary, evidence, source, consumer, original_iterator, run):
    original = build / 'libcapstone.a'
    before = archive_hashes(original)
    leaf_name = 'X86Vex32Output.c.o'
    iterator_name = 'X86OutputIterator.c.o'
    assert leaf_name in before and iterator_name in before
    folder = temporary / 'factorial-objects'
    folder.mkdir()
    stub = folder / 'stub.c'
    stub.write_text('''#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <capstone/capstone.h>
__attribute__((noinline,visibility("hidden"),section(".cs_x86_vex32_output")))
bool X86_writeVex32Output(const uint8_t *code, size_t size,
                         cs_insn *insn, uint16_t *insn_size) {
    return false;
}
''')
    shutil.copyfile(stub, evidence / 'rejecting-leaf.c')
    run(['clang', '-O3', '-DNDEBUG', '-fPIC', '-I', source / 'include',
         '-c', stub, '-o', folder / leaf_name], 'compile-rejecting-leaf')
    shutil.copyfile(original_iterator, folder / iterator_name)
    result, proofs = {}, {}
    for label, member in [('iterator', leaf_name), ('leaf', iterator_name)]:
        library = temporary / (label + '.a')
        shutil.copyfile(original, library)
        run(['ar', 'r', library, folder / member], 'replace-' + label)
        after = archive_hashes(library)
        assert list(before) == list(after)
        changed = [name for name in before if before[name] != after[name]]
        assert changed == [member], changed
        target = temporary / label
        force = ['-Wl,-u,X86_writeVex32Output'] if label == 'leaf' else []
        run(['clang++', consumer, library, *force, '-lm', '-o', target], 'link-' + label)
        for kind, command in [('symbols', ['nm', '-n', '-S', '--defined-only']),
                              ('sections', ['readelf', '-WS'])]:
            (evidence / (label + '-' + kind + '.txt')).write_bytes(sp.check_output([*command, target]))
        with gzip.open(evidence / (label + '-disassembly.gz'), 'wb') as out:
            out.write(sp.check_output(['objdump', '-d', target]))
        result[label] = target
        proofs[label] = dict(changed_members=changed, archive_member_order_identical=True,
                             untouched_members=len(before)-1, before=before, after=after,
                             forced_leaf_reference=bool(force))
    save(evidence, 'factorial-object-proof', proofs)
    return result

def cost_probe(binaries, cases, temporary, evidence, run):
    selected = [('arm-ls', 2), ('arm64-ls', 0), ('mips64el-ls', 2)]
    variants = ('base', 'iterator', 'leaf', 'candidate')
    symbol = '_ZL3runR7SessionRKSt6vectorIhSaIhEEj'
    for label in variants:
        names = sp.check_output(['nm', '--defined-only', binaries[label]], text=True)
        assert sum(line.endswith(' ' + symbol) for line in names.splitlines()) == 1
    records = []
    for name, mode in selected:
        case, = [item for item in cases if item['name'] == name]
        reference = None
        for label in variants:
            key = 'cost-' + name + '-' + label
            raw = temporary / (key + '.callgrind')
            args = [str(case['selector']), str(mode), str(case['path']), '1']
            run(['valgrind', '--tool=callgrind', '--demangle=no', '--collect-atstart=no',
                 '--toggle-collect=' + symbol, '--cache-sim=yes', '--branch-sim=yes',
                 '--dump-instr=yes', '--collect-jumps=yes', '--callgrind-out-file=' + str(raw),
                 binaries[label], *args], key)
            lines = (evidence / (key + '.log')).read_text().splitlines()
            output = next(json.loads(line) for line in lines if line.startswith('{"selector":'))
            record = (output['first'], output['result'])
            assert output['repeats'] == 1 and output['first'] == output['result']
            if reference is None:
                reference = record
            else:
                assert reference == record
            text = raw.read_text()
            events = next(line[8:].split() for line in text.splitlines() if line.startswith('events: '))
            totals = list(map(int, next(line[8:].split() for line in text.splitlines() if line.startswith('totals: '))))
            assert len(events) == len(totals) and totals[0] > 0
            records.append(dict(case=name, mode=mode, variant=label,
                events=dict(zip(events, totals)), result=record, traversals=3))
            with gzip.open(evidence / (key + '.callgrind.gz'), 'wb') as out:
                out.write(raw.read_bytes())
            raw.unlink()
            save(evidence, 'instruction-costs', records)
    expected = {(name, mode, label) for name, mode in selected for label in variants}
    assert len(records) == len(expected)
    assert {(x['case'], x['mode'], x['variant']) for x in records} == expected
    save(evidence, 'cost-protocol', dict(symbol=symbol, consumer_unchanged=True, traversals=3,
        limitation='Simulated cache and branch counts do not establish native hardware causes.'))

    installed = sorted(Path('/usr/lib/linux-tools').glob('*/perf'))
    perf = str(installed[-1]) if installed else shutil.which('perf')
    if not perf:
        save(evidence, 'pmu', dict(supported=False, reason='No perf executable installed'))
        return
    events = 'cycles:u,instructions:u,branches:u,branch-misses:u'
    probe = sp.run([perf, 'stat', '-x,', '-e', events, '--', '/bin/true'], capture_output=True, text=True)
    save(evidence, 'pmu', dict(supported=probe.returncode == 0, executable=perf,
        returncode=probe.returncode, stdout=probe.stdout, stderr=probe.stderr,
        scope='Separate whole-process counters, including setup and warm passes; unavailable counters are retained as unavailable.'))
    if probe.returncode:
        return
    for name, mode in selected:
        case, = [item for item in cases if item['name'] == name]
        for label in variants:
            key = 'pmu-' + name + '-' + label
            output = sp.run([perf, 'stat', '-x,', '-e', events, '-o', str(evidence / (key + '.txt')),
                '--', str(binaries[label]), str(case['selector']), str(mode), str(case['path']), '20'],
                capture_output=True, text=True)
            save(evidence, key, dict(returncode=output.returncode, stdout=output.stdout, stderr=output.stderr))
