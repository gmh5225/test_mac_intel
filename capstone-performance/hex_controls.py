"""Compare both numerical writers inside the same complete decoder image."""
from pathlib import Path
import hashlib
import json
import math
import os
import platform
import shutil
import statistics
import subprocess

import corpus
import run


def main():
    source, work, evidence = run.SOURCE, run.WORK, run.EVIDENCE
    work.mkdir()
    evidence.mkdir()
    manifest = json.loads((source / 'manifest.json').read_text())
    capstone = run.fetch('new', 'https://github.com/NeverSight/capstone.git', manifest['capstone_revision'])
    run.command(['git', 'apply', source / 'candidate.patch'], 'install-both-writers', capstone)
    run.fetch('iced', 'https://github.com/NeverSight/iced.git', manifest['iced_revision'])
    fixtures = corpus.prepare(source, work, evidence, run.command)
    build = run.build('new')
    adapter = work / 'adapter'
    adapter.mkdir()
    for name in ('iced.rs', 'Cargo.lock'):
        shutil.copyfile(source / name, adapter / name)
    (adapter / 'Cargo.toml').write_text('''[package]
name="iced_compare"
version="0.1.0"
edition="2021"
[lib]
crate-type=["staticlib"]
path="iced.rs"
[dependencies]
iced-x86={path="../iced/src/rust/iced-x86",default-features=false,features=["std","decoder","intel","instr_info"]}
[profile.release]
opt-level=3
panic="abort"
''')
    run.command(['cargo', 'build', '--locked', '--release', '--manifest-path', adapter / 'Cargo.toml'], 'iced-build')
    for name, filename in [('decoder', 'compare.cpp'), ('single', 'single.cpp')]:
        code = (source / filename).read_text()
        code = 'extern "C" void benchmark_set_hex_variant(int);\n' + code
        start = code.index('{', code.index('int main(')) + 1
        code = code[:start] + '\n  benchmark_set_hex_variant(std::getenv("HEX_VARIANT")[0] - \'0\');\n' + code[start:]
        (work / filename).write_text(code)
        args = ['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-I', capstone / 'include',
                work / filename, build / 'libcapstone.a']
        if name == 'decoder':
            args.append(adapter / 'target/release/libiced_compare.a')
        run.command([*args, '-lpthread', '-ldl', '-lm', '-o', work / name], name + '-link')
    available = sorted(os.sched_getaffinity(0))
    os.sched_setaffinity(0, {available[0]})
    run.write('build.json', dict(capstone=manifest['capstone_revision'], iced=manifest['iced_revision'],
                                host=list(platform.uname()), affinity=list(os.sched_getaffinity(0)),
                                library=run.sha(build / 'libcapstone.a'),
                                binaries={name: run.sha(work / name) for name in ('decoder', 'single')}))
    selected = {'putty-32-0.85', 'putty-64-0.85', 'scalar32', 'scalar64', 'simd64',
                'amd64-ls', 'amd64-cp', 'amd64-sort', 'sparc64-ls', 's390x-ls',
                'ppc64el-ls', 'arm64-ls', 'mips64el-ls', 'riscv64-ls'}
    cases = [(case, mode) for case in fixtures if case['name'] in selected
             for mode in ('format', 'detail')]
    assert len(cases) == 28, [(case['name'], mode) for case, mode in cases]

    def invoke(case, mode, variant, repeats):
        x86 = case['selector'] >= 16
        if x86:
            args = [work / 'decoder', 'capstone', mode, str(case['selector']), str(repeats), case['path']]
        else:
            args = [work / 'single', str(case['selector']), str(run.MODES[mode]), case['path'], str(repeats)]
        value = json.loads(subprocess.check_output(args, env=dict(os.environ, HEX_VARIANT=str(variant))))
        if x86:
            signature = [value[key] for key in ('instructions', 'rejected', 'boundary_hash', 'value_hash')]
        else:
            signature = value['result']
        return value, signature

    repetitions = []
    for case, mode in cases:
        sample, _ = invoke(case, mode, 0, 1)
        count = max(1, math.ceil(40e6 / sample['cpu_ns']))
        sample, _ = invoke(case, mode, 0, count)
        repetitions.append(max(1, math.ceil(120e6 * count / sample['cpu_ns'])))
    rows = []
    with (evidence / 'raw.jsonl').open('w') as output:
        for cycle in range(12):
            for position in range(len(cases)):
                index = (position + cycle * 9) % len(cases)
                case, mode = cases[index]
                signature = None
                for ordinal, variant in enumerate(([0, 1, 1, 0] if cycle % 2 == 0 else [1, 0, 0, 1])):
                    value, current = invoke(case, mode, variant, repetitions[index])
                    if signature is None:
                        signature = current
                    assert current == signature
                    row = dict(value)
                    row.update(case=case['name'], mode=mode, cycle=cycle,
                               ordinal=ordinal, variant=variant)
                    rows.append(row)
                    output.write(json.dumps(row) + '\n')
            output.flush()
    summary = []
    for case, mode in cases:
        ratios = []
        controls = []
        for cycle in range(12):
            timings = [[row['cpu_ns'] for row in rows if row['case'] == case['name']
                        and row['mode'] == mode and row['cycle'] == cycle and row['variant'] == variant]
                       for variant in (0, 1)]
            ratios.append(statistics.mean(timings[0]) / statistics.mean(timings[1]))
            controls.append([values[0] / values[1] for values in timings])
        summary.append(dict(case=case['name'], mode=mode, gain=statistics.median(ratios),
                            wins=sum(value > 1 for value in ratios), ratios=ratios, aa=controls))
    run.write('summary.json', summary)
    run.write('complete.json', dict(complete=True))


try:
    main()
finally:
    if run.EVIDENCE.exists():
        run.cleanup()
