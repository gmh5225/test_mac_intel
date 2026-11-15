"""Vary startup heap allocation; leave timed decoder/consumer bytes unchanged."""
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess as sp


def measure(work, cases, save):
    assert platform.machine() == 'x86_64'
    assert shutil.which('gdb')
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    binaries = {name: work / name for name in ('integer', 'aa', 'scan')}
    shutil.copy2(binaries['integer'], binaries['aa'])
    payloads = {name: path.read_bytes() for name, path in binaries.items()}
    assert payloads['integer'] == payloads['aa'] != payloads['scan']
    size = max(map(len, payloads.values()))
    padded = {name: data + bytes(size - len(data)) for name, data in payloads.items()}
    image = work / 'same-image'
    image.write_bytes(padded['integer'])
    image.chmod(0o755)
    inode = image.stat().st_ino
    check = sp.run(['setarch', platform.machine(), '-R', '/bin/true'], capture_output=True, text=True)
    assert check.returncode == 0, check.stderr
    conditions = [dict(name='plain', shift=0, preload=False, aslr=False)]
    conditions += [dict(name='heap+' + str(n), shift=n, preload=True, aslr=False)
                   for n in (0, 16, 64, 256, 1024, 4096)]
    conditions.append(dict(name='random+0', shift=0, preload=True, aslr=True))
    save('launch-controls.json', dict(conditions=conditions, size=size, inode=inode,
         original_sha256={k: hashlib.sha256(v).hexdigest() for k, v in payloads.items()},
         reservation_library_sha256=hashlib.sha256((work / 'reserve.so').read_bytes()).hexdigest(),
         aslr_disable_returncode=check.returncode,
         scope='Allocation offset experiment only; no decoder or timed-consumer changes. '
               'Heap-offset comparisons use the same preload library and fixed-width environment values. '
               'The plain condition separately checks whether loading the reservation library hides the original loss.'))

    def prepare(payload, condition):
        with image.open('r+b') as stream:
            assert stream.write(padded[payload]) == size
        assert image.stat().st_ino == inode and image.stat().st_size == size
        env = dict(os.environ)
        env['CAPSTONE_HEAP_SHIFT'] = '%08x' % condition['shift']
        if condition['preload']:
            env['LD_PRELOAD'] = str(work / 'reserve.so')
        else:
            env.pop('LD_PRELOAD', None)
        return env

    def invoke(payload, condition, case, mode, repeats):
        env = prepare(payload, condition)
        args = [str(work / 'exec-launcher'), str(image), str(image),
                str(case['selector']), str(mode), str(case['path']), str(repeats)]
        if not condition['aslr']:
            args = ['setarch', platform.machine(), '-R', *args]
        result = json.loads(sp.check_output(args, env=env, text=True))
        assert result['cpu_ns'] > 0
        return result

    selected = [(case, mode) for case in cases
                for mode in ((1, 2) if case['selector'] == 11 else (2,))]
    assert len(selected) == 3
    preflight = []
    for case, mode in selected:
        expected = None
        for condition in conditions:
            for payload in payloads:
                result = invoke(payload, condition, case, mode, 1)
                signature = (result['first'], result['result'])
                if expected is None:
                    expected = signature
                assert signature == expected
        preflight.append(dict(case=case['name'], mode=mode, signature=expected))
    save('preflight.json', preflight)

    # The retained R1196 disassembly establishes these private MCInst and
    # cs_insn pointer offsets for this exact 64-bit source/compiler profile.
    case = next(case for case in cases if case['selector'] == 11)
    snapshots = []
    script = ('python import gdb,json; i=gdb.selected_inferior(); '
              'p=lambda a:int.from_bytes(i.read_memory(a,8).tobytes(),"little"); '
              'm=int(gdb.parse_and_eval("$rdi")); f=p(m+0x310); '
              'print("OBJECTS="+json.dumps(dict(mi=m,flat=f,detail=p(f+0xf8),handle=p(m+0x320))))')
    for condition in conditions:
        if condition['name'] not in ('plain', 'heap+0', 'heap+16', 'heap+256', 'heap+4096'):
            continue
        for payload in ('integer', 'scan'):
            env = prepare(payload, condition)
            args = ['gdb', '-nx', '-batch', '-ex', 'set pagination off', '-ex', 'set confirm off',
                    '-ex', 'set startup-with-shell off', '-ex', 'set disable-randomization on',
                    '-ex', 'break LoongArch_init_cs_detail', '-ex', 'run', '-ex', script,
                    '-ex', 'kill', '--args', str(image), str(case['selector']), '2', str(case['path']), '1']
            proc = sp.run(args, env=env, capture_output=True, text=True)
            matches = [line[len('OBJECTS='):] for line in proc.stdout.splitlines() if line.startswith('OBJECTS=')]
            assert proc.returncode == 0 and len(matches) == 1, (proc.returncode, proc.stdout[-2000:], proc.stderr[-1000:])
            addresses = json.loads(matches[0])
            assert all(addresses.values())
            snapshots.append(dict(condition=condition['name'], payload=payload, addresses=addresses,
                                  residues={str(n): {k: v % n for k, v in addresses.items()}
                                            for n in (64, 4096, 65536, 1048576)},
                                  scope='Separate debugger run; address evidence, not timing.'))
            save('address-snapshots.json', snapshots)

    observations = []
    for case, mode in selected:
        warm = invoke('integer', conditions[0], case, mode, 2)
        repeats = max(2, round(2 * 50e6 / warm['cpu_ns']))
        expected = None
        cycles = []
        rng = random.Random(case['name'] + '/' + str(mode))
        for cycle in range(13):
            order = [(condition, payload) for condition in conditions for payload in payloads]
            rng.shuffle(order)
            values = []
            for condition, payload in order + order[::-1]:
                row = invoke(payload, condition, case, mode, repeats)
                signature = (row['first'], row['result'])
                if expected is None:
                    expected = signature
                assert signature == expected
                values.append(dict(condition=condition['name'], payload=payload,
                                   cpu_ns=row['cpu_ns'], wall_ns=row['wall_ns']))
            ns = {condition['name']: {
                payload: statistics.mean(v['cpu_ns'] for v in values
                                         if v['condition'] == condition['name'] and v['payload'] == payload)
                for payload in payloads} for condition in conditions}
            cycles.append(dict(raw=values, ns=ns))
        observations.append(dict(case=case['name'], mode=mode, repetitions=repeats,
                                 signature=expected, cycles=cycles))
        save('factorial.json', observations)
        print(case['name'], mode, 'completed', flush=True)
    assert len(observations) == 3
