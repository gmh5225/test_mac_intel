"""Diagnose identical-binary variation; this does not measure a candidate gain."""
from pathlib import Path
import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess as sp
import tempfile
import corpus

r = Path(__file__).resolve().parent
e = r.parent / 'evidence'
e.mkdir()
s = r.parent / 'source'
cc = os.environ['MEASURE_CC']
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()


def write(name, data):
    (e / (name + '.json')).write_text(json.dumps(data, indent=2) + '\n')


def run(args, name):
    print(name, flush=True)
    with (e / (name + '.log')).open('w') as stream:
        result = sp.run(list(map(str, args)), stdout=stream, stderr=sp.STDOUT)
    if result.returncode:
        raise RuntimeError((name, (e / (name + '.log')).read_text()[-2000:]))


baseline = json.loads((r / 'manifest.json').read_text())['capstone_revision']
assert sp.check_output(['git', '-C', s, 'rev-parse', 'HEAD'], text=True).strip() == baseline
write('host', dict(cpu=next(line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                            if line.startswith('model name')),
                   compiler=sp.check_output([cc, '--version'], text=True),
                   original_consumer_sha256=sha(r / 'single.cpp'), baseline=baseline))
with tempfile.TemporaryDirectory(prefix='capstone-identical-image-address-') as tmp:
    t = Path(tmp)
    try:
        inputs = corpus.prepare(r, t, e, run)
        cases = [(x, 0 if x['name'] == 'amd64-ls' else 1) for x in inputs
                 if x['name'] in ('amd64-ls', 'mips64el-ls')]
        assert len(cases) == 2
        code = (r / 'single.cpp').read_text()
        before = '    auto wall = std::chrono::steady_clock::now();'
        after = '    if (!equal(expected, measured)) throw std::runtime_error("sample mismatch");'
        assert code.count(before) == code.count(after) == 1
        code = code.replace(before, '    struct rusage before_usage{}, after_usage{};\n'
                            '    if (getrusage(RUSAGE_SELF, &before_usage)) throw std::runtime_error("rusage");\n' + before)
        code = code.replace(after, after + '\n'
            '    if (getrusage(RUSAGE_SELF, &after_usage)) throw std::runtime_error("rusage");\n'
            '    Dl_info image_info{};\n'
            '    if (!dladdr(reinterpret_cast<void *>(api.cs_disasm_iter), &image_info)) throw std::runtime_error("dladdr");\n'
            '    std::fprintf(stderr, "{\\"image\\":%llu,\\"stack\\":%llu,\\"handle\\":%llu,\\"insn\\":%llu,\\"input\\":%llu,'
            '\\"minor_faults\\":%ld,\\"major_faults\\":%ld,\\"voluntary_switches\\":%ld,\\"involuntary_switches\\":%ld}\\n",\n'
            '      (unsigned long long)(uintptr_t)image_info.dli_fbase, (unsigned long long)(uintptr_t)&session,\n'
            '      (unsigned long long)session.handle, (unsigned long long)(uintptr_t)session.insn,\n'
            '      (unsigned long long)(uintptr_t)bytes.data(),\n'
            '      after_usage.ru_minflt-before_usage.ru_minflt, after_usage.ru_majflt-before_usage.ru_majflt,\n'
            '      after_usage.ru_nvcsw-before_usage.ru_nvcsw, after_usage.ru_nivcsw-before_usage.ru_nivcsw);')
        source = t / 'diagnostic.cpp'
        source.write_text(code)
        write('instrumentation', dict(diagnostic_consumer_sha256=sha(source),
              scope='Record image, stack and allocation addresses, timed-region faults and context switches outside the measured decoder loop. Both controls use the same resulting executable.'))
        b = t / 'build'
        run(['cmake', '-S', s, '-B', b, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_COMPILER=' + cc,
             '-DCMAKE_C_FLAGS=' + ('-Wno-error=discarded-qualifiers' if cc == 'gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),
             '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF', '-DCAPSTONE_X86_SUPPORT=ON', '-DCAPSTONE_ARM_SUPPORT=ON',
             '-DCAPSTONE_AARCH64_SUPPORT=ON', '-DCAPSTONE_MIPS_SUPPORT=ON', '-DCAPSTONE_BUILD_CSTEST=OFF',
             '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF', '-DCAPSTONE_BUILD_CSTOOL=OFF'], 'configure')
        run(['cmake', '--build', b, '--target', 'capstone_static', '--parallel', '4'], 'build')
        run(['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-I', s, '-I', s / 'include', source,
             b / 'libcapstone.a', '-lm', '-ldl', '-o', t / 'base'], 'consumer')
        shutil.copyfile(t / 'base', t / 'aa')
        shutil.copyfile(t / 'base', t / 'same')
        for name in ('aa', 'same'):
            (t / name).chmod(0o755)
        assert sha(t / 'base') == sha(t / 'aa') == sha(t / 'same')
        write('images', {name: dict(sha256=sha(t / name), inode=(t / name).stat().st_ino)
                         for name in ('base', 'aa', 'same')})
        probe = sp.run(['setarch', platform.machine(), '-R', '/bin/true'], capture_output=True, text=True)
        assert probe.returncode == 0, probe.stderr
        os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
        cells = [('separate', True), ('separate', False), ('same', True), ('same', False)]

        def sample(label, case, mode, repeats, cell):
            files, aslr = cell
            image = t / (label if files == 'separate' else 'same')
            args = list(map(str, [image, case['selector'], mode, case['path'], repeats]))
            if not aslr:
                args = ['setarch', platform.machine(), '-R', *args]
            value = sp.run(args, capture_output=True, text=True, check=True)
            record = json.loads(value.stdout)
            record.update(addresses=json.loads(value.stderr), label=label)
            return record

        records = []
        for case, mode in cases:
            warm = sample('base', case, mode, 2, ('same', False))
            repeats = max(2, min(4000, round(2 * 80e6 / warm['cpu_ns'])))
            reference = None
            for cycle in range(40):
                order = cells[cycle % 4:] + cells[:cycle % 4]
                for cell in order:
                    sequence = ('base', 'aa', 'aa', 'base') if cycle % 2 == 0 else ('aa', 'base', 'base', 'aa')
                    samples = [sample(label, case, mode, repeats, cell) for label in sequence]
                    for value in samples:
                        signature = value['first'], value['result']
                        if reference is None:
                            reference = signature
                        assert signature == reference
                    ratio = sum(x['cpu_ns'] for x in samples if x['label'] == 'base') / sum(x['cpu_ns'] for x in samples if x['label'] == 'aa')
                    records.append(dict(case=case['name'], mode=mode, cycle=cycle, files=cell[0], aslr=cell[1],
                                        repeats=repeats, ratio=ratio, samples=samples))
                write('measurements', records)
        assert len(records) == 320
        write('complete', dict(success=True, comparisons=len(records), candidate_measured=False,
                              fixed_source=not sp.check_output(['git', '-C', s, 'status', '--porcelain'])))
    finally:
        size = sum(path.stat().st_size for path in t.rglob('*') if path.is_file())
        shutil.rmtree(t)
        write('cleanup', dict(bytes=size, removed=not t.exists()))
