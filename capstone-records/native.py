"""Locate time in unchanged native code; software samples are not cache events."""
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import shutil
import statistics
import subprocess as sp


def measure(work, cases, save):
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    evidence = Path(__file__).resolve().parent.parent / 'evidence'
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
    conditions = [dict(name='fixed', aslr=False), dict(name='random', aslr=True)]
    selected = [(case, mode) for case in cases
                for mode in ((1, 2) if case['selector'] == 11 else (2,))]
    assert len(selected) == 3
    save('launch-controls.json', dict(
        conditions=conditions, inode=inode, size=size, image=str(image),
        original_sha256={k: hashlib.sha256(v).hexdigest() for k, v in payloads.items()},
        aslr_disable_returncode=check.returncode,
        environment_sha256=hashlib.sha256(b'\0'.join(
            os.fsencode(k + '=' + v) for k, v in os.environ.items())).hexdigest(),
        scope='Unchanged consumer and decoder payloads; CPU-clock IP samples only. '
              'Unprofiled timing panels accompany samples; no cache or predictor attribution.'))

    signatures = {}

    def command(payload, condition, case, mode, repeats):
        with image.open('r+b') as stream:
            assert stream.write(padded[payload]) == size
        assert image.stat().st_ino == inode and image.stat().st_size == size
        args = [str(work / 'exec-launcher'), str(image), str(image),
                str(case['selector']), str(mode), str(case['path']), str(repeats)]
        if not condition['aslr']:
            args = ['setarch', platform.machine(), '-R', *args]
        return args

    def checked(raw, case, mode):
        row = json.loads(raw)
        assert row['cpu_ns'] > 0 and row['wall_ns'] > 0
        key = (case['name'], mode, row['repeats'])
        signature = (row['first'], row['result'])
        if key not in signatures:
            signatures[key] = signature
        assert signature == signatures[key], (key, signature, signatures[key])
        return row

    def unprofiled(phase):
        observations = []
        for case, mode in selected:
            warm = checked(sp.check_output(command('integer', conditions[0], case, mode, 2), text=True), case, mode)
            repeats = max(2, round(2 * 70e6 / warm['cpu_ns']))
            cycles = []
            rng = random.Random(phase + case['name'] + str(mode))
            for cycle in range(9):
                order = [(c, p) for c in conditions for p in payloads]
                rng.shuffle(order)
                values = []
                for condition, payload in order + order[::-1]:
                    row = checked(sp.check_output(command(payload, condition, case, mode, repeats), text=True), case, mode)
                    values.append(dict(condition=condition['name'], payload=payload,
                                       cpu_ns=row['cpu_ns'], wall_ns=row['wall_ns']))
                ns = {condition['name']: {
                    payload: statistics.mean(v['cpu_ns'] for v in values
                                             if v['condition'] == condition['name'] and v['payload'] == payload)
                    for payload in payloads} for condition in conditions}
                cycles.append(dict(raw=values, ns=ns))
            observations.append(dict(case=case['name'], mode=mode, repetitions=repeats, cycles=cycles))
            save('timings-' + phase + '.json', observations)
        return observations

    candidates = sorted(Path('/usr/lib/linux-tools').glob('*/perf'))
    if shutil.which('perf'):
        candidates.insert(0, Path(shutil.which('perf')))
    versions = []
    perf = None
    for executable in candidates:
        result = sp.run([str(executable), '--version'], capture_output=True, text=True)
        versions.append(dict(path=str(executable), returncode=result.returncode,
                             stdout=result.stdout, stderr=result.stderr))
        if result.returncode == 0:
            perf = executable
            break
    save('perf-versions.json', versions)
    assert perf is not None
    paranoid = Path('/proc/sys/kernel/perf_event_paranoid').read_text().strip()
    setup = sp.run(['sudo', 'sysctl', '-w', 'kernel.perf_event_paranoid=-1'], capture_output=True, text=True)
    save('permission-setup.json', dict(original=paranoid, returncode=setup.returncode,
                                      stdout=setup.stdout, stderr=setup.stderr))
    assert setup.returncode == 0, setup.stderr
    samples = []
    try:
        smoke = work / 'perf-smoke.data'
        check = sp.run([str(perf), 'record', '-q', '-B', '-e', 'cpu-clock:u', '-c', '1000000',
                        '-o', str(smoke), '--', 'python3', '-c', 'sum(i*i for i in range(3000000))'],
                       capture_output=True, text=True)
        assert check.returncode == 0, check.stderr
        export = sp.run([str(perf), 'script', '-i', str(smoke), '-F', 'ip,sym,symoff,dso', '--no-demangle'],
                        capture_output=True, text=True)
        save('perf-export-preflight.json', dict(record_returncode=check.returncode,
             script_returncode=export.returncode, stderr=export.stderr,
             lines=len(export.stdout.splitlines()), example=export.stdout.splitlines()[:5]))
        assert export.returncode == 0 and export.stdout.strip(), export.stderr
        smoke.unlink()
        unprofiled('before')
        for case, mode in selected:
            warm = checked(sp.check_output(command('integer', conditions[0], case, mode, 2), text=True), case, mode)
            repeats = max(2, round(2 * 4e9 / warm['cpu_ns']))
            for cycle in range(3):
                order = [(c, p) for c in conditions for p in ('integer', 'scan')]
                random.Random(case['name'] + str(mode) + str(cycle)).shuffle(order)
                for condition, payload in order:
                    name = '-'.join(map(str, (case['selector'], mode, condition['name'], payload, cycle)))
                    data = work / (name + '.perf.data')
                    args = [str(perf), 'record', '-q', '-B', '-e', 'cpu-clock:u', '-c', '1000000',
                            '-o', str(data), '--', *command(payload, condition, case, mode, repeats)]
                    proc = sp.run(args, capture_output=True, text=True)
                    (evidence / (name + '-record.stderr')).write_text(proc.stderr)
                    assert proc.returncode == 0, (name, proc.returncode, proc.stderr[-2000:])
                    row = checked(proc.stdout, case, mode)
                    script = sp.run([str(perf), 'script', '-i', str(data), '-F', 'ip,sym,symoff,dso', '--no-demangle'],
                                    capture_output=True, text=True)
                    (evidence / (name + '-script.stderr')).write_text(script.stderr)
                    assert script.returncode == 0, (name, script.stderr[-2000:])
                    with gzip.open(evidence / (name + '-samples.txt.gz'), 'wt') as stream:
                        stream.write(script.stdout)
                    symbols, offsets, dsos = Counter(), Counter(), Counter()
                    for line in script.stdout.splitlines():
                        fields = line.strip().split(maxsplit=2)
                        if not fields:
                            continue
                        assert len(fields) == 3 and re.fullmatch('[0-9a-fA-F]+', fields[0]), line
                        ip, symbol, dso = fields
                        match = re.fullmatch(r'(.+)\+0x([0-9a-fA-F]+)', symbol)
                        function = match.group(1) if match else symbol
                        symbols[function] += 1
                        offsets[symbol] += 1
                        dsos[dso] += 1
                    assert sum(symbols.values()) > 100, (name, symbols)
                    item = dict(name=name, case=case['name'], mode=mode, condition=condition['name'],
                                payload=payload, cycle=cycle, repetitions=repeats, measurement=row,
                                samples=sum(symbols.values()), symbols=symbols.most_common(),
                                offsets=offsets.most_common(), dsos=dsos.most_common())
                    samples.append(item)
                    save('samples.json', samples)
                    data.unlink()
                    print(name, item['samples'], flush=True)
        unprofiled('after')
        save('sampling-complete.json', dict(samples=len(samples), expected=36,
                                           event='cpu-clock:u', period_ns=1000000,
                                           hardware_counters_used=False, native_qualification=False))
        assert len(samples) == 36
    finally:
        restored = sp.run(['sudo', 'sysctl', '-w', 'kernel.perf_event_paranoid=' + paranoid], capture_output=True, text=True)
        save('permission-cleanup.json', dict(returncode=restored.returncode,
             setting_restored=Path('/proc/sys/kernel/perf_event_paranoid').read_text().strip() == paranoid))
