"""Keep all original ARM code and data addresses fixed while measuring the outlined printer candidate."""
from pathlib import Path
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import statistics
import subprocess as sp
import tempfile

import corpus

r = Path(__file__).resolve().parent
e = r.parent / 'evidence'
e.mkdir()
s = r.parent / 'source'
meta = json.loads((r / 'candidate.json').read_text())
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def write(name, value):
    (e / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')


def run(args, label, cwd=None):
    print(label, flush=True)
    with (e / (label + '.log')).open('w') as log:
        result = sp.run(list(map(str, args)), cwd=cwd, stdout=log, stderr=sp.STDOUT)
    if result.returncode:
        raise RuntimeError((label, (e / (label + '.log')).read_text()[-1800:]))


def git(*args):
    return sp.check_output(['git', '-C', s, *args], text=True).strip()


assert platform.machine() == 'aarch64'
assert git('rev-parse', 'HEAD') == meta['parent']
assert sha(r / 'scan.patch') == meta['sha256']
assert not git('status', '--porcelain')
write('cpu', dict(info=Path('/proc/cpuinfo').read_text(),
                  compiler=sp.check_output(['gcc', '--version'], text=True)))
write('candidate', meta)

with tempfile.TemporaryDirectory(prefix='arm-print-placement-control-') as tmp:
    t = Path(tmp)
    b = t / 'build'
    try:
        cases = [x for x in corpus.prepare(r, t, e, run)
                 if x['name'] in ('arm-ls', 'arm-sort', 'arm-cp')]
        assert len(cases) == 3
        run(['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-DCAPSTONE_PERF_ARM_ONLY',
             '-I', s, '-I', s / 'include', '-c', r / 'single.cpp', '-o', t / 'single.o'], 'consumer')
        assert 'X86_disasmIter' not in sp.check_output(['nm', '-u', t / 'single.o'], text=True)
        run(['cmake', '-S', s, '-B', b, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
             '-DCMAKE_C_COMPILER=gcc', '-DCMAKE_C_FLAGS=-Wno-error=discarded-qualifiers',
             '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF', '-DCAPSTONE_ARM_SUPPORT=ON',
             '-DCAPSTONE_BUILD_SHARED_LIBS=ON', '-DCAPSTONE_BUILD_CSTEST=ON',
             '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF', '-DCAPSTONE_BUILD_CSTOOL=OFF'], 'configure')
        linker = t / 'placed.ld'
        linker.write_text('SECTIONS { .cs_arm_full_decoder : { *(.cs_arm_full_decoder) } .cs_arm_printer : { *(.cs_arm_printer) } } INSERT AFTER .bss;\n')
        (e / 'diagnostic-layout.ld').write_text(linker.read_text())
        bins, libraries, objects, symbols, data_symbols = {}, {}, {}, {}, {}
        for label in ('base', 'scan', 'placed-base', 'placed-scan'):
            active = label.endswith('scan')
            if active:
                run(['git', 'apply', r / 'scan.patch'], 'apply-' + label, s)
                git('add', '-A')
                assert git('write-tree') == meta['tree']
                git('reset', '-q')
            if label.startswith('placed-'):
                f = s / 'cs.c'
                text = f.read_text()
                old = 'CS_PRESERVE_MOST bool\ncs_decode_full_insn('
                assert text.count(old) == 2
                text = text.replace(old, '__attribute__((section(".cs_arm_full_decoder")))\n' + old)
                if active:
                    old_printer = 'static void print_arm_insn('
                    assert text.count(old_printer) == 1
                    text = text.replace(old_printer, '__attribute__((section(".cs_arm_printer")))\n' + old_printer)
                f.write_text(text)
            git('add', '-A')
            write('source-' + label, dict(tree=git('write-tree'), active=active,
                  separate_section=label.startswith('placed-'), patch_sha256=sha(r / 'scan.patch')))
            git('reset', '-q')
            run(['cmake', '--build', b, '--target', 'capstone_static', 'capstone_shared',
                 '--parallel', '4'], 'build-' + label)
            target = t / 'single'
            run(['clang++', t / 'single.o', b / 'libcapstone.a', '-lm', *(['-Wl,-T,'+str(linker)] if label.startswith('placed-') else []), '-o', target], 'link-' + label)
            bins[label] = t / label
            target.rename(bins[label])
            libraries[label] = t / (label + '.so')
            shutil.copy2(b / 'libcapstone.so', libraries[label])
            root = b / 'CMakeFiles/capstone.dir'
            objects[label] = {str(f.relative_to(root)): sha(f) for f in root.rglob('*.o')}
            raw = sp.check_output(['nm', '-n', '-S', '--defined-only', bins[label]], text=True)
            (e / (label + '-symbols.txt')).write_text(raw)
            symbols[label] = {}
            data_symbols[label] = {}
            for line in raw.splitlines():
                match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) ([Tt]) (.+)', line)
                if match:
                    symbols[label][match[4]] = [int(match[1], 16), int(match[2], 16)]
                data = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) ([rRdDbBgGsSvV]) (.+)', line)
                if data:
                    data_symbols[label][data[4]] = [int(data[1], 16), int(data[2], 16)]
            (e / (label + '-sections.txt')).write_bytes(sp.check_output(['readelf', '-WS', bins[label]]))
            with gzip.open(e / (label + '-assembly.gz'), 'wb') as stream:
                stream.write(sp.check_output(['objdump', '-dr', bins[label]]))
            with gzip.open(e / (label + '-cs-object-assembly.gz'), 'wb') as stream:
                stream.write(sp.check_output(['objdump', '-dr', root / 'cs.c.o']))
            if label == 'placed-scan':
                run(['cmake', '--build', b, '--target', 'arm_private_stream', 'arm_post_index',
                     '--parallel', '4'], 'callback-build')
                run(['ctest', '--test-dir', b, '--output-on-failure', '--no-tests=error',
                     '-R', '^unit_arm_(private_stream|post_index)$'], 'callback-contract')
            git('reset', '--hard', meta['parent'])
            git('clean', '-fdx')
        write('object-digests', objects)
        for label in ('scan', 'placed-base', 'placed-scan'):
            assert objects[label].keys() == objects['base'].keys()
            changed = [k for k in objects['base'] if objects[label][k] != objects['base'][k]]
            assert changed == ['cs.c.o'], (label, changed)
        names = set(symbols['placed-base']) | set(symbols['placed-scan'])
        shifted = {name: [symbols['placed-base'].get(name), symbols['placed-scan'].get(name)]
                   for name in sorted(names) if name not in ('cs_decode_full_insn', 'print_arm_insn')
                   and symbols['placed-base'].get(name) != symbols['placed-scan'].get(name)}
        write('text-layout-control', dict(other_text_matches=not shifted, differences=shifted,
              full_decoder={k: v['cs_decode_full_insn'] for k, v in symbols.items()}))
        data_names = set(data_symbols['placed-base']) | set(data_symbols['placed-scan'])
        data_delta = {name: [data_symbols['placed-base'].get(name), data_symbols['placed-scan'].get(name)]
                      for name in sorted(data_names)
                      if data_symbols['placed-base'].get(name) != data_symbols['placed-scan'].get(name)}
        full_entry_equal = symbols['placed-base']['cs_decode_full_insn'][0] == symbols['placed-scan']['cs_decode_full_insn'][0]
        write('data-layout-control', dict(original_data_matches=not data_delta, differences=data_delta,
              original_data_symbols=len(data_symbols['placed-base']), full_decoder_entry_equal=full_entry_equal))
        # Retain mismatches as diagnostic evidence, but do not call an unmatched
        # placement a causal control or proceed with timing it.
        assert not shifted and not data_delta and full_entry_equal, (shifted, data_delta, full_entry_equal)
        run(['clang++', '-O2', '-std=c++17', '-I', s / 'include', r / 'verify-arm.cpp',
             '-ldl', '-o', t / 'verify-arm'], 'records-link')
        for label in ('scan', 'placed-base', 'placed-scan'):
            run([t / 'verify-arm', libraries['base'], libraries[label]], 'records-' + label)
        bins['aa'] = t / 'aa'
        shutil.copy2(bins['base'], bins['aa'])
        payloads = {k: f.read_bytes() for k, f in bins.items()}
        assert payloads['base'] == payloads['aa']
        maximum = max(map(len, payloads.values()))
        padded = {k: value + bytes(maximum - len(value)) for k, value in payloads.items()}
        image = t / 'same-image'
        image.write_bytes(padded['base'])
        image.chmod(0o755)
        inode = image.stat().st_ino
        probe = sp.run(['setarch', platform.machine(), '-R', '/bin/true'], capture_output=True, text=True)
        assert probe.returncode == 0, probe.stderr
        launches = ['images', 'same-file-fixed']
        write('launch-controls', dict(launches=launches, inode=inode, fixed_size=maximum,
              original_sha256={k: hashlib.sha256(v).hexdigest() for k, v in payloads.items()},
              aslr_disable_returncode=probe.returncode))
        os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})

        def sample(key, case, repeats, launch):
            tail = list(map(str, [case['selector'], 0, case['path'], repeats]))
            if launch == 'images':
                args = [str(bins[key]), *tail]
            else:
                with image.open('r+b') as stream:
                    assert stream.write(padded[key]) == maximum
                assert image.stat().st_ino == inode and image.stat().st_size == maximum
                args = ['setarch', platform.machine(), '-R', str(image), *tail]
            return json.loads(sp.check_output(args, text=True))

        data = []
        keys = ['base', 'aa', 'scan', 'placed-base', 'placed-scan']
        for case in cases:
            for launch in launches:
                warm = sample('base', case, 2, launch)
                repeats = max(2, min(4000, round(2 * 100e6 / warm['cpu_ns'])))
                pairs, reference = [], None
                for cycle in range(21):
                    seq = keys[cycle % len(keys):] + keys[:cycle % len(keys)]
                    ticks = {k: [] for k in keys}
                    for key in seq + seq[::-1]:
                        out = sample(key, case, repeats, launch)
                        result = [out['first'], out['result']]
                        if reference is None:
                            reference = result
                        assert result == reference
                        ticks[key].append(out['cpu_ns'])
                    pair = {k: sum(ticks['base']) / sum(ticks[k]) for k in keys}
                    pair['isolated_gain'] = sum(ticks['placed-base']) / sum(ticks['placed-scan'])
                    pairs.append(pair)
                data.append(dict(case=case['name'], mode=0, launch=launch, pairs=pairs,
                     median={k: statistics.median(p[k] for p in pairs) for k in pairs[0]}, result=reference))
                write('timings', data)
        write('complete', dict(cases=len(data), other_text_matches=not shifted,
              diagnostic_only=True, native_qualified=False))
    finally:
        amount = sum(f.stat().st_size for f in t.rglob('*') if f.is_file())
        shutil.rmtree(t)
        write('cleanup', dict(bytes=amount, removed=not t.exists()))
