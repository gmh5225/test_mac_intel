from pathlib import Path
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess as sp
import tempfile

e = Path('evidence')
e.mkdir()
save = lambda name, value: (e / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')
assert platform.machine() == 'aarch64'
cpu = Path('/proc/cpuinfo').read_text()
is_n2 = bool(re.search(r'CPU implementer\s*:\s*0x41', cpu) and re.search(r'CPU part\s*:\s*0xd49', cpu))
if hasattr(os, 'sched_getaffinity'):
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
save('environment', dict(platform=platform.platform(), cpu=cpu, neoverse_n2=is_n2,
                         affinity=sorted(os.sched_getaffinity(0))))
inventory = {}
for device in Path('/sys/bus/event_source/devices').iterdir():
    if 'arm' not in device.name and 'cpu' not in device.name:
        continue
    values = {}
    for name in ('type', 'cpus', 'cpumask'):
        path = device / name
        if path.is_file():
            values[name] = path.read_text().strip()
    for folder in ('caps', 'events', 'format'):
        for path in sorted((device / folder).glob('*')):
            if path.is_file():
                values[str(path.relative_to(device))] = path.read_text().strip()
    inventory[device.name] = values
save('pmu-devices', inventory)
perf, = sorted(Path('/usr/lib/linux-tools').glob('*/perf'))[-1:]
save('tool', dict(path=str(perf), version=sp.check_output([perf, '--version'], text=True)))
permissions = dict(original=Path('/proc/sys/kernel/perf_event_paranoid').read_text().strip(), changed=False, restored=True)
groups = [('fetch', ['r1:u', 'r14:u']), ('itlb', ['r2:u', 'r26:u']),
          ('retired-branches', ['r21:u', 'r22:u']), ('micro-ops', ['r3a:u', 'r3b:u'])]
loads = [('integer', 'print(sum(i*i for i in range(1000000)))'),
         ('branch', 'print(sum(i*i if i & 7 else i+1 for i in range(1000000)))')]
records, sampling = [], []
w = Path(tempfile.mkdtemp(prefix='arm-raw-pmu-probe-'))
try:
    result = sp.run(['sudo', '-n', 'sysctl', '-w', 'kernel.perf_event_paranoid=-1'], capture_output=True, text=True)
    permissions.update(change_returncode=result.returncode, change_stdout=result.stdout, change_stderr=result.stderr,
                       changed=result.returncode == 0, restored=result.returncode != 0)
    if is_n2:
        for name, events in groups:
            for workload, program in loads:
                output = w / 'active.csv'
                result = sp.run([perf, 'stat', '-x,', '-o', output, '-e', '{' + ','.join(events) + '}',
                                 '--', 'python3', '-c', program], capture_output=True, text=True)
                raw = output.read_text() if output.exists() else ''
                counts, running = {}, {}
                for line in raw.splitlines():
                    fields = line.split(',')
                    if len(fields) >= 5 and fields[2] in events and fields[0].strip().isdigit():
                        counts[fields[2]] = int(fields[0])
                        running[fields[2]] = float(fields[4])
                accepted = result.returncode == 0 and counts.keys() == set(events)
                records.append(dict(group=name, workload=workload, events=events, returncode=result.returncode,
                                    accepted=accepted, all_events_positive=accepted and all(counts.values()),
                                    counts=counts, running_percent=running, stdout=result.stdout, stderr=result.stderr, raw=raw))
    for event, period in [('cycles:u', 1000000), ('branch-misses:u', 1024)]:
        key = event.split(':')[0]
        data = w / (key + '.data')
        result = sp.run([perf, 'record', '-B', '-e', event, '-c', str(period), '-o', data,
                         '--', 'python3', '-c', loads[1][1]], capture_output=True, text=True)
        item = dict(event=event, period=period, returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        if result.returncode == 0:
            script = sp.run([perf, 'script', '-i', data, '-F', 'ip,sym,dso,event,period'], capture_output=True, text=True)
            lines = [line for line in script.stdout.splitlines() if line.strip() and not line.startswith('#')]
            item.update(script_returncode=script.returncode, script_stderr=script.stderr, sample_lines=len(lines),
                        data_sha256=hashlib.sha256(data.read_bytes()).hexdigest(),
                        available=script.returncode == 0 and bool(lines))
            with gzip.open(e / (key + '-samples.txt.gz'), 'wt') as stream:
                stream.write(script.stdout)
        else:
            item['available'] = False
        sampling.append(item)
finally:
    if permissions['changed']:
        result = sp.run(['sudo', '-n', 'sysctl', '-w', 'kernel.perf_event_paranoid=' + permissions['original']],
                        capture_output=True, text=True)
        permissions.update(restore_returncode=result.returncode, restore_stdout=result.stdout, restore_stderr=result.stderr,
                           restored=result.returncode == 0 and Path('/proc/sys/kernel/perf_event_paranoid').read_text().strip() == permissions['original'])
    save('permissions', permissions)
    save('capability', dict(raw=records, sampling=sampling, raw_cpu_gate=is_n2))
    size = sum(path.stat().st_size for path in w.rglob('*') if path.is_file())
    shutil.rmtree(w)
    save('cleanup', dict(bytes=size, removed=not w.exists()))
    assert permissions['restored']
save('complete', dict(complete=True, production_modified=False, source_candidates_tested=False,
                      scope='Raw ARM event observability and sampled-profile capability only. Zero counters remain unavailable for causal inference.'))
