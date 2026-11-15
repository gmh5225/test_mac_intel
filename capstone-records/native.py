"""Cross ELF type and ASLR without recompiling the timed consumer."""
import hashlib
import json
import os
import platform
import random
import shutil
import statistics
import subprocess as sp


def measure(work, cases, save):
    assert platform.machine() == 'x86_64'
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    names = ('integer', 'aa', 'scan')
    payloads = {}
    for flavor in ('pie', 'exec'):
        shutil.copy2(work / (flavor + '-integer'), work / (flavor + '-aa'))
        for name in names:
            payloads[flavor, name] = (work / (flavor + '-' + name)).read_bytes()
        assert payloads[flavor, 'integer'] == payloads[flavor, 'aa'] != payloads[flavor, 'scan']
    size = max(map(len, payloads.values()))
    padded = {key: data + bytes(size - len(data)) for key, data in payloads.items()}
    image = work / 'same-image'
    image.write_bytes(padded['pie', 'integer'])
    image.chmod(0o755)
    inode = image.stat().st_ino
    check = sp.run(['setarch', platform.machine(), '-R', '/bin/true'], capture_output=True, text=True)
    assert check.returncode == 0, check.stderr
    conditions = [dict(name=flavor + '-' + ('random' if aslr else 'fixed'),
                       flavor=flavor, aslr=aslr)
                  for flavor in ('pie', 'exec') for aslr in (False, True)]
    save('launch-controls.json', dict(conditions=conditions, size=size, inode=inode,
         original_sha256={'/'.join(k): hashlib.sha256(v).hexdigest() for k, v in payloads.items()},
         aslr_disable_returncode=check.returncode,
         scope='ELF type and ASLR diagnostic. One compiled consumer object and archive per '
               'source variant; same inode/argv/size. No production build changes.'))

    def prepare(payload, condition):
        with image.open('r+b') as stream:
            assert stream.write(padded[condition['flavor'], payload]) == size
        assert image.stat().st_ino == inode and image.stat().st_size == size

    def invoke(payload, condition, case, mode, repeats):
        prepare(payload, condition)
        args = [str(work / 'exec-launcher'), str(image), str(image),
                str(case['selector']), str(mode), str(case['path']), str(repeats)]
        if not condition['aslr']:
            args = ['setarch', platform.machine(), '-R', *args]
        result = json.loads(sp.check_output(args, text=True))
        assert result['cpu_ns'] > 0
        return result

    selected = [(case, mode) for case in cases
                for mode in ((1, 2) if case['selector'] == 11 else (2,))]
    assert len(selected) == 3
    preflight = []
    for case, mode in selected:
        expected = None
        for condition in conditions:
            for payload in names:
                result = invoke(payload, condition, case, mode, 1)
                signature = (result['first'], result['result'])
                if expected is None:
                    expected = signature
                assert signature == expected
        preflight.append(dict(case=case['name'], mode=mode, signature=expected))
    save('preflight.json', preflight)

    case = next(case for case in cases if case['selector'] == 11)
    snapshots = []
    script = ('python import gdb,json; i=gdb.selected_inferior(); '
              'p=lambda a:int.from_bytes(i.read_memory(a,8).tobytes(),"little"); '
              'm=int(gdb.parse_and_eval("$rdi")); f=p(m+0x310); '
              'pc=int(gdb.parse_and_eval("$pc")); '
              'print("OBJECTS="+json.dumps(dict(pc=pc,mi=m,flat=f,detail=p(f+0xf8),handle=p(m+0x320))))')
    for condition in conditions:
        for payload in ('integer', 'scan'):
            for repeat in range(2):
                prepare(payload, condition)
                args = ['gdb', '-nx', '-batch', '-ex', 'set pagination off', '-ex', 'set confirm off',
                        '-ex', 'set startup-with-shell off', '-ex',
                        'set disable-randomization ' + ('off' if condition['aslr'] else 'on'),
                        '-ex', 'break LoongArch_init_cs_detail', '-ex', 'run', '-ex', script,
                        '-ex', 'kill', '--args', str(image), str(case['selector']), '2', str(case['path']), '1']
                proc = sp.run(args, capture_output=True, text=True)
                matches = [line[len('OBJECTS='):] for line in proc.stdout.splitlines() if line.startswith('OBJECTS=')]
                assert proc.returncode == 0 and len(matches) == 1, (proc.returncode, proc.stdout[-2000:], proc.stderr[-1000:])
                addresses = json.loads(matches[0])
                assert all(addresses.values())
                snapshots.append(dict(condition=condition['name'], payload=payload, repeat=repeat,
                                      addresses=addresses, scope='Separate debugger run, not timing.'))
                save('address-snapshots.json', snapshots)
            pair = [row['addresses'] for row in snapshots
                    if row['condition'] == condition['name'] and row['payload'] == payload]
            assert (pair[0]['pc'] != pair[1]['pc']) == (condition['aslr'] and condition['flavor'] == 'pie')
            if condition['aslr']:
                assert pair[0]['mi'] != pair[1]['mi']
            else:
                assert pair[0] == pair[1]

    observations = []
    for case, mode in selected:
        warm = invoke('integer', conditions[0], case, mode, 2)
        repeats = max(2, round(2 * 70e6 / warm['cpu_ns']))
        expected = None
        cycles = []
        rng = random.Random(case['name'] + '/' + str(mode))
        for cycle in range(21):
            order = [(condition, payload) for condition in conditions for payload in names]
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
                for payload in names} for condition in conditions}
            cycles.append(dict(raw=values, ns=ns))
        observations.append(dict(case=case['name'], mode=mode, repetitions=repeats,
                                 signature=expected, cycles=cycles))
        save('factorial.json', observations)
        print(case['name'], mode, 'completed', flush=True)
    assert len(observations) == 3
