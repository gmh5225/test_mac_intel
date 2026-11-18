from pathlib import Path
import json
import os
import platform
import re
import shutil
import subprocess as sp

e = Path('evidence')
e.mkdir()
save = lambda name, value: (e / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')
assert platform.machine() == 'aarch64'
save('environment', dict(platform=platform.platform(), cpu=Path('/proc/cpuinfo').read_text(),
                         uid=os.getuid()))
paths = sorted(Path('/usr/lib/linux-tools').glob('*/perf'), reverse=True)
if shutil.which('perf'):
    paths.append(Path(shutil.which('perf')))
attempts = []
perf = None
for path in paths:
    result = sp.run([path, '--version'], capture_output=True, text=True)
    attempts.append(dict(path=str(path), returncode=result.returncode,
                         stdout=result.stdout, stderr=result.stderr))
    if result.returncode == 0:
        perf = path
        break
save('tools', attempts)
permissions = dict(original=Path('/proc/sys/kernel/perf_event_paranoid').read_text().strip(),
                   changed=False, restored=True)
records = []
try:
    if perf:
        if int(permissions['original']) > -1:
            result = sp.run(['sudo', '-n', 'sysctl', '-w', 'kernel.perf_event_paranoid=-1'],
                            capture_output=True, text=True)
            permissions.update(change_returncode=result.returncode, change_stdout=result.stdout,
                               change_stderr=result.stderr, changed=result.returncode == 0,
                               restored=result.returncode != 0)
        for name, events in [
            ('work', ['cycles:u', 'instructions:u']),
            ('branches', ['branches:u', 'branch-misses:u']),
            ('stalls', ['stalled-cycles-frontend:u', 'stalled-cycles-backend:u']),
            ('fetch', ['L1-icache-load-misses:u', 'iTLB-load-misses:u'])]:
            output = e / (name + '.csv')
            result = sp.run([perf, 'stat', '-x,', '-o', output, '-e', ','.join(events),
                             '--', 'python3', '-c', 'print(sum(i*i for i in range(1000000)))'],
                            capture_output=True, text=True)
            raw = output.read_text() if output.exists() else ''
            counts = {}
            for line in raw.splitlines():
                fields = line.split(',')
                if len(fields) >= 3 and fields[2] in events and re.fullmatch(r'\d+', fields[0].strip()):
                    counts[fields[2]] = int(fields[0])
            records.append(dict(group=name, events=events, returncode=result.returncode,
                                available=result.returncode == 0 and counts.keys() == set(events),
                                counts=counts, stdout=result.stdout, stderr=result.stderr, raw=raw))
finally:
    if permissions['changed']:
        result = sp.run(['sudo', '-n', 'sysctl', '-w',
                         'kernel.perf_event_paranoid=' + permissions['original']],
                        capture_output=True, text=True)
        permissions.update(restore_returncode=result.returncode, restore_stdout=result.stdout,
                           restore_stderr=result.stderr,
                           restored=result.returncode == 0 and
                           Path('/proc/sys/kernel/perf_event_paranoid').read_text().strip() == permissions['original'])
    save('permissions', permissions)
    save('capability', dict(perf=str(perf) if perf else None, records=records,
                           available=any(x['available'] for x in records),
                           reason=None if perf else 'No working installed perf executable'))
    assert permissions['restored']
save('complete', dict(complete=True, production_modified=False, compiled=False,
                      source_candidates_tested=False, scope='ARM runner hardware-event availability only'))
