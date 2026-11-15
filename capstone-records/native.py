"""Native measurement with independent images, fixed launches and A/A."""
import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess as sp


def measure(w, cases, save):
    if hasattr(os, 'sched_getaffinity'):
        os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    bins = {key: w / key for key in ('integer', 'scan', 'aa')}
    shutil.copy2(bins['integer'], bins['aa'])
    payloads = {key: path.read_bytes() for key, path in bins.items()}
    assert payloads['integer'] == payloads['aa']
    assert payloads['integer'] != payloads['scan']
    maximum = max(map(len, payloads.values()))
    padded = {key: value + bytes(maximum - len(value)) for key, value in payloads.items()}
    image = w / 'same-image'
    image.write_bytes(padded['integer'])
    image.chmod(0o755)
    inode = image.stat().st_ino
    probe = sp.run(['setarch', platform.machine(), '-R', '/bin/true'], capture_output=True, text=True)
    assert probe.returncode == 0, probe.stderr
    launches = ['images', 'same-file-fixed']
    save('launch-controls.json', dict(
        launches=launches, aslr_disable_returncode=probe.returncode,
        inode=inode, fixed_size=maximum,
        original_sha256={k: hashlib.sha256(v).hexdigest() for k, v in payloads.items()},
        scope='Native shared operand-access qualification on PPC, RISCV, LoongArch and ARC; x86 and NeverD qualification are separate.'))

    def sample(key, case, mode, reps, launch):
        tail = list(map(str, [case['selector'], mode, case['path'], reps]))
        if launch == 'images':
            args = [str(bins[key]), *tail]
        else:
            with image.open('r+b') as out:
                assert out.write(padded[key]) == maximum
            assert image.stat().st_ino == inode and image.stat().st_size == maximum
            args = ['setarch', platform.machine(), '-R', str(image), *tail]
        return json.loads(sp.check_output(args, text=True))

    rows = []
    for case in cases:
        for mode in range(3):
            for launch in launches:
                warm = sample('integer', case, mode, 2, launch)
                reps = max(2, min(4000, round(2 * 160e6 / warm['cpu_ns'])))
                cycles = []
                reference = None
                keys = ['integer', 'aa', 'scan']
                for cycle in range(21):
                    order = keys[cycle % 3:] + keys[:cycle % 3]
                    ticks = {key: [] for key in keys}
                    for key in order + order[::-1]:
                        result = sample(key, case, mode, reps, launch)
                        signature = (result['first'], result['result'])
                        if reference is None:
                            reference = signature
                        assert signature == reference, (case['name'], mode, key)
                        ticks[key].append(result['cpu_ns'])
                    cycles.append({key: sum(ticks['integer']) / sum(ticks[key]) for key in keys})
                rows.append(dict(case=case['name'], mode=mode, launch=launch, pairs=cycles,
                                 median={key: statistics.median(c[key] for c in cycles) for key in keys},
                                 result=reference))
                save('timings.json', rows)
    assert len(rows) == 24
