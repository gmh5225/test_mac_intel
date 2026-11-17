"""Separate process lifetime, compiler, and undefined-value effects on baseline timing."""
from pathlib import Path
import hashlib
import json
import os
import platform
import shutil
import subprocess as sp
import tempfile
import corpus

r = Path(__file__).resolve().parent
e = r.parent / 'evidence'
e.mkdir()
s = r.parent / 'source'


def write(name, value):
    (e / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')


def run(args, label):
    print(label, flush=True)
    with (e / (label + '.log')).open('w') as stream:
        value = sp.run(list(map(str, args)), stdout=stream, stderr=sp.STDOUT)
    if value.returncode:
        raise RuntimeError((label, (e / (label + '.log')).read_text()[-2000:]))


baseline = json.loads((r / 'manifest.json').read_text())['capstone_revision']
assert sp.check_output(['git', '-C', s, 'rev-parse', 'HEAD'], text=True).strip() == baseline
cpu = min(os.sched_getaffinity(0))
paths = ['/sys/kernel/mm/transparent_hugepage/enabled', '/sys/kernel/mm/transparent_hugepage/defrag',
         '/sys/devices/system/clocksource/clocksource0/current_clocksource', '/sys/fs/cgroup/cpu.max',
         f'/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list']
write('host', dict(cpu=Path('/proc/cpuinfo').read_text(), affinity=cpu,
                   settings={name: Path(name).read_text() for name in paths if Path(name).exists()},
                   baseline=baseline, compilers={cc: sp.check_output([cc, '--version'], text=True) for cc in ('clang', 'gcc')}))
with tempfile.TemporaryDirectory(prefix='capstone-baseline-runtime-state-') as tmp:
    t = Path(tmp)
    try:
        inputs = corpus.prepare(r, t, e, run)
        cases = [(x, 0 if x['name'] == 'amd64-ls' else 1) for x in inputs if x['name'] in ('amd64-ls', 'mips64el-ls')]
        assert len(cases) == 2
        code = (r / 'single.cpp').read_text()
        assert 'if (argc != 5)' in code
        code = code.replace('if (argc != 5)', 'if (argc != 6)')
        before = '    auto wall = std::chrono::steady_clock::now();'
        after = '    if (!equal(expected, measured)) throw std::runtime_error("sample mismatch");'
        assert code.count(before) == code.count(after) == 1
        code = code.replace(before,
            '    const unsigned samples = std::stoul(argv[5]);\n'
            '    for (unsigned trial = 0; trial < samples; ++trial) {\n'
            '    uint64_t calibration = repeats;\n'
            '    double calibration_ns = process_cpu_ns();\n'
            '    for (unsigned i = 0; i < 1048576; ++i) { calibration ^= calibration << 13; calibration ^= calibration >> 7; calibration ^= calibration << 17; }\n'
            '    calibration_ns = process_cpu_ns() - calibration_ns;\n'
            '    struct rusage before_usage{}, after_usage{};\n'
            '    if (getrusage(RUSAGE_SELF, &before_usage)) throw std::runtime_error("rusage");\n' + before)
        code = code.replace(after, after + '\n'
            '    if (getrusage(RUSAGE_SELF, &after_usage)) throw std::runtime_error("rusage");\n'
            '    Dl_info info{};\n'
            '    if (!dladdr(reinterpret_cast<void *>(api.cs_disasm_iter), &info)) throw std::runtime_error("dladdr");\n'
            '    std::fprintf(stderr, "{\\"trial\\":%u,\\"calibration_ns\\":%.0f,\\"calibration_value\\":%llu,'
            '\\"image\\":%llu,\\"stack\\":%llu,\\"handle\\":%llu,\\"insn\\":%llu,\\"input\\":%llu,'
            '\\"minor_faults\\":%ld,\\"major_faults\\":%ld,\\"voluntary_switches\\":%ld,\\"involuntary_switches\\":%ld}\\n",\n'
            '      trial, calibration_ns, (unsigned long long)calibration,\n'
            '      (unsigned long long)(uintptr_t)info.dli_fbase, (unsigned long long)(uintptr_t)&session,\n'
            '      (unsigned long long)session.handle, (unsigned long long)(uintptr_t)session.insn, (unsigned long long)(uintptr_t)bytes.data(),\n'
            '      after_usage.ru_minflt-before_usage.ru_minflt, after_usage.ru_majflt-before_usage.ru_majflt,\n'
            '      after_usage.ru_nvcsw-before_usage.ru_nvcsw, after_usage.ru_nivcsw-before_usage.ru_nivcsw);')
        assert code.count('    return 0;') == 1
        code = code.replace('    return 0;', '    }\n    return 0;')
        source = t / 'state.cpp'
        source.write_text(code)
        write('consumer', dict(original_sha256=hashlib.sha256((r/'single.cpp').read_bytes()).hexdigest(),
                               instrumented_sha256=hashlib.sha256(source.read_bytes()).hexdigest()))
        run(['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-I', s, '-I', s/'include', '-c', source, '-o', t/'consumer.o'], 'consumer')
        images = {}
        for cc in ('clang', 'gcc'):
            b = t / ('build-' + cc)
            run(['cmake', '-S', s, '-B', b, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_COMPILER='+cc,
                 '-DCMAKE_C_FLAGS=' + ('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),
                 '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF', '-DCAPSTONE_X86_SUPPORT=ON', '-DCAPSTONE_ARM_SUPPORT=ON',
                 '-DCAPSTONE_AARCH64_SUPPORT=ON', '-DCAPSTONE_MIPS_SUPPORT=ON', '-DCAPSTONE_BUILD_CSTEST=OFF',
                 '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF', '-DCAPSTONE_BUILD_CSTOOL=OFF'], 'configure-'+cc)
            run(['cmake', '--build', b, '--target', 'capstone_static', '--parallel', '4'], 'build-'+cc)
            images[cc] = t/cc
            run(['clang++', t/'consumer.o', b/'libcapstone.a', '-lm', '-ldl', '-o', images[cc]], 'link-'+cc)
        assert sp.run(['setarch', platform.machine(), '-R', '/bin/true']).returncode == 0
        os.sched_setaffinity(0, {cpu})

        def sample(cc, case, mode, repeats, count):
            args = list(map(str, [images[cc], case['selector'], mode, case['path'], repeats, count]))
            value = sp.run(['setarch', platform.machine(), '-R', *args], capture_output=True, text=True, check=True)
            records = [json.loads(line) for line in value.stdout.splitlines()]
            metadata = [json.loads(line) for line in value.stderr.splitlines()]
            assert len(records) == len(metadata) == count
            return [dict(record, runtime=meta) for record, meta in zip(records, metadata)]

        rows = []
        for case, mode in cases:
            repeats = {cc: max(2, min(4000, round(2*80e6/sample(cc, case, mode, 2, 1)[0]['cpu_ns']))) for cc in images}
            references = {}
            for block in range(8):
                compilers = ('clang','gcc') if block%2 == 0 else ('gcc','clang')
                for cc in compilers:
                    policies = ('retained','restarted') if block%2 == 0 else ('restarted','retained')
                    for policy in policies:
                        groups = [sample(cc, case, mode, repeats[cc], 8)] if policy=='retained' else [sample(cc, case, mode, repeats[cc], 1) for _ in range(8)]
                        for group_index, group in enumerate(groups):
                            for value in group:
                                signature = value['first'], value['result']
                                if cc not in references:
                                    references[cc] = signature
                                assert signature == references[cc]
                            rows.append(dict(case=case['name'],mode=mode,cc=cc,block=block,policy=policy,
                                             process=group_index,repeats=repeats[cc],samples=group))
                    write('measurements', rows)
        checks = []
        for cc in images:
            for case, mode in cases:
                label = cc + '-' + case['name']
                args = ['valgrind', '--tool=memcheck', '--track-origins=yes', '--leak-check=no', '--error-exitcode=86',
                        '--num-callers=24', '--log-file='+str(e/('memcheck-'+label+'.log')),
                        *map(str,[images[cc],case['selector'],mode,case['path'],1,1])]
                value = sp.run(args,capture_output=True,text=True)
                assert value.returncode in (0,86), (label,value.stderr[-2000:])
                checks.append(dict(compiler=cc,case=case['name'],mode=mode,returncode=value.returncode,
                                   log='memcheck-'+label+'.log'))
        write('memcheck',checks)
        assert len(rows)==288
        write('complete',dict(success=True,processes=len(rows),timed_samples=sum(len(x['samples'])for x in rows),
                              candidate_measured=False,source_unchanged=not sp.check_output(['git','-C',s,'status','--porcelain'])))
    finally:
        size=sum(path.stat().st_size for path in t.rglob('*')if path.is_file())
        shutil.rmtree(t)
        write('cleanup',dict(bytes=size,removed=not t.exists()))
