from pathlib import Path
import json
import platform
import shutil
import statistics
import subprocess as sp


def cost_probe(binaries, cases, temporary, evidence, run):
    def save(name, value):
        (evidence / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')

    variants = ['base', 'aa', 'dispatch', 'scan']
    selected = [('scalar32', 1), ('scalar64', 1), ('simd64', 1), ('simd64', 2),
                ('arm64-ls', 0), ('arm64-ls', 1), ('putty-32-0.85', 1)]
    control = json.loads((evidence / 'launch-controls.json').read_text())
    assert control['aslr_disable_returncode'] == 0
    image = temporary / 'same-image'
    payloads = {v: binaries[v].read_bytes() for v in variants}
    assert payloads['base'] == payloads['aa']
    padded = {v: data + bytes(control['fixed_size'] - len(data)) for v, data in payloads.items()}
    by_name = {x['name']: x for x in cases}

    def target(variant):
        with image.open('r+b') as stream:
            assert stream.write(padded[variant]) == control['fixed_size']
        assert image.stat().st_ino == control['inode'] and image.stat().st_size == control['fixed_size']
        return image

    def arguments(variant, case, mode, repeats, fixed):
        tail = [str(case['selector']), str(mode), str(case['path']), str(repeats)]
        if fixed:
            return ['setarch', platform.machine(), '-R', str(target(variant)), *tail]
        return [str(binaries[variant]), *tail]

    repeats = {}
    references = {}
    timings = []
    for name, mode in selected:
        case = by_name[name]
        warm = json.loads(sp.check_output(arguments('base', case, mode, 2, True), text=True))
        n = max(20, min(4000, round(2 * 40e6 / warm['cpu_ns'])))
        repeats[name, mode] = n
        for launch in ('images', 'same-file-fixed'):
            pairs = []
            for cycle in range(21):
                seq = variants[cycle % 4:] + variants[:cycle % 4]
                ticks = {v: [] for v in variants}
                for variant in seq + seq[::-1]:
                    output = json.loads(sp.check_output(arguments(variant, case, mode, n,
                                                                   launch == 'same-file-fixed'), text=True))
                    value = (output['first'], output['result'])
                    references.setdefault((name, mode), value)
                    assert references[name, mode] == value
                    ticks[variant].append(output['cpu_ns'])
                pairs.append({v: sum(ticks['base']) / sum(ticks[v]) for v in variants})
            timings.append(dict(case=name, mode=mode, launch=launch, repeats=n, pairs=pairs,
                                median={v: statistics.median(x[v] for x in pairs) for v in variants}))
            save('timings', timings)
    assert len(timings) == 14

    installed = sorted(Path('/usr/lib/linux-tools').glob('*/perf'))
    perf = str(installed[-1]) if installed else shutil.which('perf')
    assert perf, 'perf tooling missing'
    setting = Path('/proc/sys/kernel/perf_event_paranoid')
    original = setting.read_text().strip()
    permission = sp.run(['sudo', '-n', 'sysctl', '-w', 'kernel.perf_event_paranoid=-1'],
                        capture_output=True, text=True)
    audit = dict(original_setting=original, permission_returncode=permission.returncode,
                 permission_stdout=permission.stdout, permission_stderr=permission.stderr, groups={})

    def parse(raw, events):
        counts, running = {}, {}
        for line in raw.splitlines():
            fields = line.split(',')
            if len(fields) >= 5 and fields[2] in events:
                if not fields[0].isdigit():
                    return None
                counts[fields[2]] = int(fields[0])
                running[fields[2]] = float(fields[4])
        if counts.keys() != set(events):
            return None
        return dict(counts=counts, running_percent=running)

    groups = {'work': ['cycles:u', 'instructions:u'],
              'branches': ['branches:u', 'branch-misses:u'],
              'stalls': ['stalled-cycles-frontend:u', 'stalled-cycles-backend:u']}
    records = []
    try:
        for group, events in groups.items():
            request = '{' + ','.join(events) + '}'
            probe = sp.run([perf, 'stat', '-x,', '-e', request, '--', '/bin/true'],
                           capture_output=True, text=True)
            valid = parse(probe.stderr, events)
            supported = probe.returncode == 0 and valid is not None
            audit['groups'][group] = dict(supported=supported, returncode=probe.returncode,
                                           stderr=probe.stderr, parsed=valid)
            save('pmu', audit)
            if not supported:
                continue
            for name, mode in selected:
                case = by_name[name]
                n = repeats[name, mode]
                for cycle in range(20):
                    seq = variants[cycle % 4:] + variants[:cycle % 4]
                    for position, variant in enumerate(seq + seq[::-1]):
                        binary = target(variant)
                        raw = temporary / 'active.perf'
                        result = sp.run(['setarch', platform.machine(), '-R', perf, 'stat', '-x,',
                                         '-e', request, '-o', str(raw), '--', str(binary),
                                         str(case['selector']), str(mode), str(case['path']), str(n)],
                                        capture_output=True, text=True)
                        assert result.returncode == 0, (result.returncode, result.stderr)
                        output = json.loads(result.stdout)
                        assert (output['first'], output['result']) == references[name, mode]
                        parsed = parse(raw.read_text(), events)
                        assert parsed is not None, raw.read_text()
                        records.append(dict(group=group, case=name, mode=mode, cycle=cycle,
                                            position=position, variant=variant, counters=parsed,
                                            consumer=output, stderr=result.stderr, raw=raw.read_text()))
                save('pmu-samples', records)
        audit['samples'] = len(records)
        audit['supported'] = any(x['supported'] for x in audit['groups'].values())
        save('protocol', dict(cases=selected, variants=variants, native_cycles=21, counter_cycles=20,
                              target_cpu_ms=40, minimum_repeats=20, whole_process_counters=True,
                              instruction_consumer_unchanged=True, fixed_guest_argv=True,
                              native_panels=14, expected_counter_samples_per_group=1120))
    finally:
        if permission.returncode == 0:
            restored = sp.run(['sudo', '-n', 'sysctl', '-w', 'kernel.perf_event_paranoid=' + original],
                              capture_output=True, text=True)
            audit.update(restore_returncode=restored.returncode, restore_stdout=restored.stdout,
                         restore_stderr=restored.stderr)
        audit['final_setting'] = setting.read_text().strip()
        audit['setting_restored'] = audit['final_setting'] == original
        save('pmu', audit)
        assert audit['setting_restored']
