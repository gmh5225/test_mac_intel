from pathlib import Path
import hashlib
import json
import os
import platform
import shutil
import subprocess as sp
import tempfile

r = Path(__file__).resolve().parent
p = r.parent
evidence = p / 'evidence'
evidence.mkdir()
base = p / 'source'
meta = json.loads((r / 'candidate.json').read_text())


def save(name, data):
    (evidence / (name + '.json')).write_text(json.dumps(data, indent=2) + '\n')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args, label, cwd=None):
    with (evidence / (label + '.log')).open('wb') as out:
        sp.run(list(map(str, args)), cwd=cwd, stdout=out, stderr=sp.STDOUT, check=True)


w = Path(tempfile.mkdtemp(prefix='capstone-clang14-vectors-crash-'))
try:
    assert os.environ['CC'] == 'clang'
    assert sp.check_output(['git', '-C', base, 'rev-parse', 'HEAD'], text=True).strip() == meta['parent']
    save('environment', dict(platform=platform.platform(), machine=platform.machine(),
         cpu=Path('/proc/cpuinfo').read_text(), compiler=sp.check_output(['clang', '--version'], text=True),
         cxx=sp.check_output(['clang++', '--version'], text=True),
         cmake=sp.check_output(['cmake', '--version'], text=True),
         linker=sp.check_output(['ld', '--version'], text=True),
         debugger=sp.check_output(['gdb', '--version'], text=True),
         original_failure_run=43936130678, original_revision='89768ab7e3d57e4bb59f910eafaebbd24ae7b732',
         original_signal=11, rebuilt_reproducer=True))
    import deb
    case = next(x for x in deb.prepare(w) if x[0] == 'libjpeg62-turbo-amd64')
    name, bits, data, spans, provenance = case
    intervals = w / 'intervals.tsv'
    intervals.write_text(''.join('%d %d %d\n' % item for item in spans))
    save('input', dict(name=name, bits=bits, provenance=provenance,
         text_sha256=sha(data), intervals_sha256=sha(intervals), intervals=len(spans)))
    tree, build = w / 'source', w / 'build'
    run(['git', 'clone', '-q', '--shared', '--no-checkout', base, tree], 'clone')
    run(['git', 'checkout', '-q', '--detach', meta['parent']], 'checkout', tree)
    options = ['-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_COMPILER=clang',
               '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
               *['-DCAPSTONE_' + arch + '_SUPPORT=ON' for arch in ['X86', 'ARM', 'AARCH64', 'MIPS']],
               '-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer -Wno-error=incompatible-pointer-types-discards-qualifiers',
               '-DCAPSTONE_BUILD_MACOS_THIN=ON', '-DCAPSTONE_BUILD_SHARED_LIBS=OFF',
               '-DCAPSTONE_BUILD_STATIC_LIBS=ON', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
               '-DCAPSTONE_BUILD_CSTOOL=OFF']
    run(['cmake', '-S', tree, '-B', build, *options], 'configure')
    observations = []
    for label in ['baseline', 'candidate', 'census']:
        if label == 'candidate':
            assert sha(r / 'scan.patch') == meta['sha256']
            run(['git', 'apply', r / 'scan.patch'], 'apply', tree)
            run(['git', 'add', '-A'], 'stage', tree)
            assert sp.check_output(['git', 'write-tree'], cwd=tree, text=True).strip() == meta['tree']
        if label == 'census':
            with (tree / 'arch/X86/X86OutputIterator.c').open('a') as out:
                out.write('\nbool census_output(csh h,const uint8_t*p,size_t n,cs_insn*i){uint16_t len;return X86_trySimpleOutput((cs_struct*)(uintptr_t)h,p,n,i,&len);}\n')
        run(['cmake', '--build', build, '--target', 'capstone_static', '--parallel', '4'], 'build-' + label)
        executable = w / ('vectors-' + label)
        command = ['clang++', '-O2', '-I', base / 'include', r / 'vectors.cpp', build / 'libcapstone.a', '-o', executable]
        run(command, 'link-' + label)
        arguments = [executable, str(bits), data, intervals]
        with (evidence / (label + '-stdout.txt')).open('wb') as stdout, (evidence / (label + '-stderr.txt')).open('wb') as stderr:
            result = sp.run(list(map(str, arguments)), stdout=stdout, stderr=stderr, timeout=120)
        observation = dict(label=label, returncode=result.returncode, binary_sha256=sha(executable),
                           archive_sha256=sha(build / 'libcapstone.a'),
                           stdout_sha256=sha(evidence / (label + '-stdout.txt')),
                           completed_lines=len((evidence / (label + '-stdout.txt')).read_text().splitlines()))
        observations.append(observation)
        save('observations', observations)
        (evidence / (label + '-symbols.txt')).write_bytes(sp.check_output(['nm', '-n', '-S', '--defined-only', executable]))
        if result.returncode:
            run(['gdb', '-q', '--batch', '-ex', 'set pagination off', '-ex', 'run',
                 '-ex', 'thread apply all bt full', '-ex', 'info registers',
                 '-ex', 'x/20i $pc-32', '-ex', 'info frame', '--args', *arguments], 'gdb-' + label)
    save('complete', dict(success=True, diagnostic_only=True, cases=len(observations),
                          no_native_performance_claim=True))
finally:
    files = [path for path in w.rglob('*') if path.is_file()]
    amount = sum(path.stat().st_size for path in files)
    shutil.rmtree(w)
    save('cleanup', dict(bytes=amount, files=len(files), removed=not w.exists()))
