"""Diagnose layout sensitivity; keep every predeclared layout and A/A control."""
import hashlib
import json
import os
import platform
import random
import statistics
import subprocess as sp


def measure(w, cases, plan, save):
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    probe = sp.run(['setarch', platform.machine(), '-R', '/bin/true'],
                   capture_output=True, text=True)
    assert probe.returncode == 0, probe.stderr
    offsets = plan['padding_bytes']
    payloads = {(offset, key): (w / f'{offset}-{key}').read_bytes()
                for offset in offsets for key in ('integer', 'scan')}
    for offset in offsets:
        payloads[offset, 'aa'] = payloads[offset, 'integer']
    maximum = max(map(len, payloads.values()))
    payloads = {key: value + bytes(maximum - len(value))
                for key, value in payloads.items()}
    image = w / 'same-image'
    image.write_bytes(payloads[0, 'integer'])
    image.chmod(0o755)
    inode = image.stat().st_ino
    save('launch-controls.json', dict(
        aslr_disable_returncode=probe.returncode, inode=inode, size=maximum,
        hashes={f'{offset}-{key}': hashlib.sha256(data).hexdigest()
                for (offset, key), data in payloads.items()},
        scope='Fixed executable pathname, inode, length and ASLR policy; paired source variants at each predeclared text padding. Diagnostic only.'))

    def sample(offset, key, case, mode, repeats):
        with image.open('r+b') as out:
            assert out.write(payloads[offset, key]) == maximum
        assert image.stat().st_ino == inode and image.stat().st_size == maximum
        return json.loads(sp.check_output(
            ['setarch', platform.machine(), '-R', str(image),
             str(case['selector']), str(mode), case['path'], str(repeats)], text=True))

    rows = []
    for selector, mode in plan['cases']:
        case = next(case for case in cases if case['selector'] == selector)
        warm = sample(0, 'integer', case, mode, 2)
        repeats = max(2, min(4000, round(2 * plan['target_cpu_ns'] / warm['cpu_ns'])))
        reference = None
        measurements = {offset: [] for offset in offsets}
        for cycle in range(plan['cycles']):
            order = offsets.copy()
            random.Random(f"{plan['seed']}/{selector}/{mode}/{cycle}").shuffle(order)
            for offset in order:
                keys = ['integer', 'aa', 'scan']
                keys = keys[cycle % 3:] + keys[:cycle % 3]
                ticks = {key: [] for key in keys}
                for key in keys + keys[::-1]:
                    result = sample(offset, key, case, mode, repeats)
                    signature = (result['first'], result['result'])
                    if reference is None:
                        reference = signature
                    assert signature == reference, (offset, key, selector, mode)
                    ticks[key].append(result['cpu_ns'])
                measurements[offset].append(dict(
                    cycle=cycle, cpu_ns=ticks,
                    gain={key: sum(ticks['integer']) / sum(ticks[key])
                          for key in keys}))
            save('progress.json', dict(selector=selector, mode=mode, cycle=cycle))
        for offset in offsets:
            pairs = measurements[offset]
            rows.append(dict(case=case['name'], selector=selector, mode=mode,
                             padding=offset, repeats=repeats, pairs=pairs,
                             median={key: statistics.median(v['gain'][key] for v in pairs)
                                     for key in ('aa', 'scan')}, result=reference))
        save('timings.json', rows)
    assert len(rows) == len(plan['cases']) * len(offsets)
