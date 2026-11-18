from pathlib import Path
import gzip
import hashlib
import json
import platform
import subprocess as sp


def cost_probe(binaries, cases, temporary, evidence, run):
    def save(name, value):
        (evidence / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')

    variants = ['base', 'aa', 'dispatch', 'scan']
    selected = [('simd64', 1), ('arm64-ls', 0), ('arm64-ls', 1)]
    groups = {'retired-branches': ['r21:u', 'r22:u'], 'micro-ops': ['r3a:u', 'r3b:u']}
    events = [('cycles:u', 500000), ('branch-misses:u', 512)]
    control = json.loads((evidence / 'launch-controls.json').read_text())
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

    def arguments(variant, name, mode, repeats):
        return [str(target(variant)), str(by_name[name]['selector']), str(mode),
                str(by_name[name]['path']), str(repeats)]

    perf = str(sorted(Path('/usr/lib/linux-tools').glob('*/perf'))[-1])
    setting = Path('/proc/sys/kernel/perf_event_paranoid')
    original = setting.read_text().strip()
    permission = sp.run(['sudo', '-n', 'sysctl', '-w', 'kernel.perf_event_paranoid=-1'], capture_output=True, text=True)
    assert permission.returncode == 0, permission.stderr
    audit = dict(original_setting=original, permission_stdout=permission.stdout, groups={})
    references, repeats, counters, samples = {}, {}, [], []

    def checked_output(output, name, mode):
        value = (output['first'], output['result'])
        references.setdefault((name, mode), value)
        assert references[name, mode] == value

    def parse_counts(raw, requested):
        counts, running = {}, {}
        for line in raw.splitlines():
            fields = line.split(',')
            if len(fields) >= 5 and fields[2] in requested and fields[0].isdigit():
                counts[fields[2]] = int(fields[0])
                running[fields[2]] = float(fields[4])
        assert counts.keys() == set(requested), raw
        return dict(counts=counts, running_percent=running)

    try:
        for name, mode in selected:
            warm = json.loads(sp.check_output(['setarch', platform.machine(), '-R', *arguments('base', name, mode, 2)], text=True))
            checked_output(warm, name, mode)
            repeats[name, mode] = max(20, min(4000, round(2 * 100e6 / warm['cpu_ns'])))
        for group, requested in groups.items():
            for name, mode in selected:
                for cycle in range(20):
                    seq = variants[cycle % 4:] + variants[:cycle % 4]
                    for position, variant in enumerate(seq + seq[::-1]):
                        raw = temporary / 'active.perf'
                        result = sp.run(['setarch', platform.machine(), '-R', perf, 'stat', '-x,', '-e',
                                         '{' + ','.join(requested) + '}', '-o', str(raw), '--',
                                         *arguments(variant, name, mode, repeats[name, mode])], capture_output=True, text=True)
                        assert result.returncode == 0, result.stderr
                        output = json.loads(result.stdout)
                        checked_output(output, name, mode)
                        counts = parse_counts(raw.read_text(), requested)
                        assert all(counts['counts'].values()), counts
                        counters.append(dict(group=group, case=name, mode=mode, cycle=cycle, position=position,
                                             variant=variant, counters=counts, consumer=output, raw=raw.read_text(), stderr=result.stderr))
                save('counter-samples', counters)
                print('counted', group, name, mode, flush=True)
            audit['groups'][group] = requested
        assert len(counters) == 960
        for name, mode in selected:
            for event, period in events:
                for cycle in range(4):
                    seq = variants[cycle:] + variants[:cycle]
                    for position, variant in enumerate(seq + seq[::-1]):
                        key = '-'.join(map(str, [name, mode, event.split(':')[0], cycle, position, variant]))
                        data = temporary / 'active.data'
                        result = sp.run(['setarch', platform.machine(), '-R', perf, 'record', '-B', '-e', event,
                                         '-c', str(period), '-o', str(data), '--',
                                         *arguments(variant, name, mode, repeats[name, mode])], capture_output=True, text=True)
                        assert result.returncode == 0, result.stderr
                        output = json.loads(result.stdout)
                        checked_output(output, name, mode)
                        script = sp.run([perf, 'script', '--no-demangle', '--show-lost-events', '-i', data,
                                         '-F', 'ip,sym,symoff,dso,event,period'], capture_output=True, text=True)
                        assert script.returncode == 0 and script.stdout.strip(), script.stderr
                        with gzip.open(evidence / (key + '.samples.gz'), 'wt') as stream:
                            stream.write(script.stdout)
                        lost = [line for line in script.stdout.splitlines() if 'PERF_RECORD_LOST' in line]
                        samples.append(dict(key=key, case=name, mode=mode, event=event, period=period,
                                            cycle=cycle, position=position, variant=variant, consumer=output,
                                            data_sha256=hashlib.sha256(data.read_bytes()).hexdigest(),
                                            text_sha256=hashlib.sha256(script.stdout.encode()).hexdigest(),
                                            lost_records=lost, record_stderr=result.stderr, script_stderr=script.stderr))
                        data.unlink()
                    save('sample-index', samples)
                print('sampled', event, name, mode, flush=True)
        assert len(samples) == 192
        save('protocol', dict(cases=selected, variants=variants, counter_groups=groups, events=events,
                              counter_cycles=20, sampling_cycles=4, expected_counter_samples=960,
                              expected_sample_runs=192, target_cpu_ms=100, minimum_repeats=20,
                              repeats={name + '/' + str(mode): n for (name, mode), n in repeats.items()},
                              fixed_guest_argv=True, whole_process=True, call_graph=False,
                              exact_branch_attribution=False, native_timings=False))
    finally:
        restored = sp.run(['sudo', '-n', 'sysctl', '-w', 'kernel.perf_event_paranoid=' + original], capture_output=True, text=True)
        audit.update(restore_returncode=restored.returncode, restore_stderr=restored.stderr,
                     setting_restored=restored.returncode == 0 and setting.read_text().strip() == original)
        save('pmu', audit)
        assert audit['setting_restored']
