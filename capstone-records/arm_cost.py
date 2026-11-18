from pathlib import Path
import json
import platform
import shutil
import statistics
import subprocess as sp


def cost_probe(binaries, cases, temporary, evidence, run):
    def save(name, value):
        (evidence / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')

    variants = ['base', 'aa', 'scan']
    observers = [1, 0]
    states = [(v, o) for o in observers for v in variants]
    selected = [('simd64', 1), ('arm64-ls', 0), ('arm64-ls', 1), ('putty-32-0.85', 1)]
    control = json.loads((evidence / 'launch-controls.json').read_text())
    image = temporary / 'same-image'
    payloads = {v: binaries[v].read_bytes() for v in variants}
    assert payloads['base'] == payloads['aa'] and control['aslr_disable_returncode'] == 0
    padded = {v: data + bytes(control['fixed_size'] - len(data)) for v, data in payloads.items()}
    by_name = {x['name']: x for x in cases}

    def target(variant):
        with image.open('r+b') as stream:
            assert stream.write(padded[variant]) == control['fixed_size']
        assert image.stat().st_ino == control['inode'] and image.stat().st_size == control['fixed_size']
        return image

    def arguments(variant, case, mode, repeats, observer, fixed):
        tail = list(map(str, [case['selector'], mode, case['path'], repeats, observer]))
        return (['setarch', platform.machine(), '-R', str(target(variant))] if fixed
                else [str(binaries[variant])]) + tail

    references = {}
    first = {}
    def check(name, mode, observer, repeats, output):
        key = name, mode, observer, repeats
        value = output['first'], output['result']
        references.setdefault(key, value)
        assert references[key] == value
        first.setdefault((name, mode, observer), output['first'])
        assert first[name, mode, observer] == output['first']
        if mode == 0 and (name, mode, 1-observer) in first:
            assert first[name, mode, 1-observer] == output['first']

    repeats = {}
    timings = []
    for name, mode in selected:
        case = by_name[name]
        for observer in observers:
            warm = json.loads(sp.check_output(arguments('base', case, mode, 2, observer, True), text=True))
            check(name, mode, observer, 2, warm)
            repeats[name, mode, observer] = max(20, min(4000, round(2 * 40e6 / warm['cpu_ns'])))
        for launch in ('images', 'same-file-fixed'):
            pairs = {o: [] for o in observers}
            for cycle in range(21):
                seq = states[cycle % len(states):] + states[:cycle % len(states)]
                ticks = {(v, o): [] for v, o in states}
                for variant, observer in seq + seq[::-1]:
                    n = repeats[name, mode, observer]
                    output = json.loads(sp.check_output(arguments(variant, case, mode, n, observer,
                                                                   launch == 'same-file-fixed'), text=True))
                    check(name, mode, observer, n, output)
                    ticks[variant, observer].append(output['cpu_ns'])
                for observer in observers:
                    ratios = {v: sum(ticks['base', observer]) / sum(ticks[v, observer]) for v in variants}
                    pairs[observer].append(dict(cycle=cycle, ratios=ratios,
                        cpu_ns={v: ticks[v, observer] for v in variants}))
            for observer in observers:
                timings.append(dict(case=name, mode=mode, launch=launch, observer=observer,
                    repeats=repeats[name, mode, observer], pairs=pairs[observer],
                    median={v: statistics.median(x['ratios'][v] for x in pairs[observer]) for v in variants}))
            save('timings', timings)
    assert len(timings) == 16

    installed = sorted(Path('/usr/lib/linux-tools').glob('*/perf'))
    perf = str(installed[-1]) if installed else shutil.which('perf')
    assert perf
    setting = Path('/proc/sys/kernel/perf_event_paranoid')
    original = setting.read_text().strip()
    permission = sp.run(['sudo', '-n', 'sysctl', '-w', 'kernel.perf_event_paranoid=-1'],
                        capture_output=True, text=True)
    audit = dict(original_setting=original, permission_returncode=permission.returncode,
                 permission_stdout=permission.stdout, permission_stderr=permission.stderr)
    events = ['cycles:u', 'instructions:u', 'r21:u', 'r22:u']
    request = '{' + ','.join(events) + '}'
    def parse(raw):
        counts, running = {}, {}
        for line in raw.splitlines():
            fields = line.split(',')
            if len(fields) >= 5 and fields[2] in events:
                if not fields[0].isdigit():
                    return None
                counts[fields[2]] = int(fields[0])
                running[fields[2]] = float(fields[4])
        return dict(counts=counts, running_percent=running) if counts.keys() == set(events) else None

    records = []
    try:
        probe = sp.run([perf, 'stat', '-x,', '-e', request, '--', '/bin/true'], capture_output=True, text=True)
        valid = parse(probe.stderr)
        audit.update(supported=probe.returncode == 0 and valid is not None,
                     probe_returncode=probe.returncode, probe_stderr=probe.stderr, parsed=valid)
        save('pmu', audit)
        if audit['supported']:
            for name, mode in selected:
                case = by_name[name]
                for cycle in range(20):
                    seq = states[cycle % len(states):] + states[:cycle % len(states)]
                    for position, (variant, observer) in enumerate(seq + seq[::-1]):
                        n = repeats[name, mode, observer]
                        binary = target(variant)
                        raw = temporary / 'active.perf'
                        result = sp.run(['setarch', platform.machine(), '-R', perf, 'stat', '-x,',
                            '-e', request, '-o', str(raw), '--', str(binary), str(case['selector']),
                            str(mode), str(case['path']), str(n), str(observer)], capture_output=True, text=True)
                        assert result.returncode == 0, result.stderr
                        output = json.loads(result.stdout)
                        check(name, mode, observer, n, output)
                        parsed = parse(raw.read_text())
                        assert parsed and all(x == 100 for x in parsed['running_percent'].values()), raw.read_text()
                        records.append(dict(case=name, mode=mode, cycle=cycle, position=position,
                            variant=variant, observer=observer, counters=parsed, consumer=output,
                            raw=raw.read_text(), stderr=result.stderr))
                save('hardware', records)
            assert len(records) == 960
    finally:
        restored = sp.run(['sudo', '-n', 'sysctl', '-w', 'kernel.perf_event_paranoid=' + original],
                          capture_output=True, text=True)
        audit['restore_returncode'] = restored.returncode
        audit['restored_setting'] = setting.read_text().strip()
        save('pmu', audit)
        assert restored.returncode == 0 and audit['restored_setting'] == original
    save('observation-contract', dict(library_options_unchanged=True,
        observers={'1': 'Original NUL-string length/last-byte observation',
                   '0': 'Skip only the two text_value calls; IDs, boundaries and detail consumers remain'},
        raw_mode_first_results_equal=True, runtime_flag_same_binary=True,
        statistical_scope='Factorial balanced cycles; descriptive unadjusted intervals. No frozen benchmark or product qualification. Whole-process PMU includes startup and all warm/expected/measured traversals.'))
