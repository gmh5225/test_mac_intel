"""Alternate full decoder workloads with one image, handle and output buffer."""
from pathlib import Path
import json
import os
import platform
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
    patch = source / 'candidate.patch'
    assert run.sha(patch) == manifest['source_lineage']['candidate.patch']['sha256']
    run.command(['git', 'apply', patch], 'both-writers', capstone)
    fixtures = corpus.prepare(source, work, evidence, run.command)
    compiler = os.environ['HEX_COMPILER']
    assert compiler in ('clang', 'gcc')
    build = work / 'build'
    run.command(['cmake', '-S', capstone, '-B', build, '-G', 'Ninja',
                 '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_COMPILER=' + compiler,
                 '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF', '-DCAPSTONE_BUILD_CSTOOL=OFF'], 'configure')
    run.command(['cmake', '--build', build, '--target', 'capstone_static', '--parallel', '3'], 'build')
    run.command(['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-I', capstone / 'include',
                 source / 'inprocess.cpp', build / 'libcapstone.a', '-lpthread', '-ldl', '-lm',
                 '-o', work / 'consumer'], 'consumer')
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    run.command(['lscpu', '--json'], 'cpu')
    run.command([compiler, '--version'], 'compiler')
    run.write('build.json', dict(capstone=manifest['capstone_revision'], compiler=compiler,
                                host=list(platform.uname()), affinity=list(os.sched_getaffinity(0)),
                                executable=run.sha(work / 'consumer'), patch=run.sha(patch)))
    selected = {'putty-32-0.85', 'putty-64-0.85', 'scalar32', 'scalar64', 'simd64',
                'amd64-ls', 'amd64-cp', 'amd64-sort', 'sparc64-ls', 's390x-ls',
                'ppc64el-ls', 'arm64-ls', 'mips64el-ls', 'riscv64-ls'}
    cases = [case for case in fixtures if case['name'] in selected]
    assert len(cases) == 14
    summary = []
    for case in cases:
        for mode in ('format', 'detail'):
            path = evidence / (case['name'] + '-' + mode + '.jsonl')
            with path.open('w') as output:
                subprocess.run([work / 'consumer', str(case['selector']), str(run.MODES[mode]),
                                case['path']], stdout=output, check=True)
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            assert len(rows) == 64
            ratios, controls = [], []
            for cycle in range(16):
                times = [[row['cpu_ns'] for row in rows if row['cycle'] == cycle and row['variant'] == variant]
                         for variant in (0, 1)]
                assert [len(values) for values in times] == [2, 2]
                ratios.append(statistics.mean(times[0]) / statistics.mean(times[1]))
                controls.append([values[0] / values[1] for values in times])
            summary.append(dict(case=case['name'], mode=mode, gain=statistics.median(ratios),
                                wins=sum(value > 1 for value in ratios), ratios=ratios, aa=controls))
            run.write('summary.json', summary)
    run.write('complete.json', dict(complete=True))


try:
    main()
finally:
    if run.EVIDENCE.exists():
        run.cleanup()
