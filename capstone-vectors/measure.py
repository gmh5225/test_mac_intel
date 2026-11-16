from pathlib import Path
import hashlib
import json
import os
import platform
import re
import resource
import shutil
import subprocess as sp
import tempfile

r = Path(__file__).resolve().parent
p = r.parent
evidence = p / 'evidence'
evidence.mkdir()
base = p / 'source'
meta = json.loads((r / 'candidate.json').read_text())
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def save(name, data):
    (evidence / (name + '.json')).write_text(json.dumps(data, indent=2) + '\n')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args, label, cwd=None, checked=True, timeout=240):
    with (evidence / (label + '.log')).open('wb') as out:
        result = sp.run(list(map(str, args)), cwd=cwd, stdout=out, stderr=sp.STDOUT,
                        check=checked, timeout=timeout)
    return result.returncode


w = Path(tempfile.mkdtemp(prefix='capstone-clang14-vectors-abi-'))
try:
    assert os.environ['CC'] == 'clang'
    assert sp.check_output(['git', '-C', base, 'rev-parse', 'HEAD'], text=True).strip() == meta['parent']
    save('environment', dict(platform=platform.platform(), machine=platform.machine(),
         cpu=Path('/proc/cpuinfo').read_text(), compiler=sp.check_output(['clang', '--version'], text=True),
         linker=sp.check_output(['ld', '--version'], text=True),
         debugger=sp.check_output(['gdb', '--version'], text=True),
         original_failure_run=43936130678, rebuilt_reproducer=True))
    import deb
    case = next(x for x in deb.prepare(w) if x[0] == 'libjpeg62-turbo-amd64')
    name, bits, data, spans, provenance = case
    intervals = w / 'intervals.tsv'
    intervals.write_text(''.join('%d %d %d\n' % item for item in spans))
    save('input', dict(name=name, bits=bits, provenance=provenance,
         text_sha256=sha(data), intervals_sha256=sha(intervals), intervals=len(spans)))
    raw = data.read_bytes()
    bad_ip = 0x38e01
    context = []
    for start, length, ip in spans:
        if ip <= bad_ip < ip + length:
            pos = start + bad_ip - ip
            context.append(dict(start=start, length=length, ip=ip, bad_offset=pos,
                                context_start=max(start, pos - 40),
                                bytes=raw[max(start, pos - 40):start + length].hex()))
    save('first-violation-context', context)
    tree, build = w / 'source', w / 'build'
    run(['git', 'clone', '-q', '--shared', '--no-checkout', base, tree], 'clone')
    run(['git', 'checkout', '-q', '--detach', meta['parent']], 'checkout', tree)
    options = ['-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_COMPILER=clang',
               '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
               *['-DCAPSTONE_' + arch + '_SUPPORT=ON' for arch in ['X86', 'ARM', 'AARCH64', 'MIPS']],
               '-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer -Wno-error=incompatible-pointer-types-discards-qualifiers',
               '-DCAPSTONE_BUILD_MACOS_THIN=ON', '-DCAPSTONE_BUILD_SHARED_LIBS=OFF',
               '-DCAPSTONE_BUILD_STATIC_LIBS=ON', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
               '-DCAPSTONE_BUILD_CSTOOL=OFF']
    run(['cmake', '-S', tree, '-B', build, *options], 'configure')
    pristine = {name: (tree / name).read_text() for name in ['cs.c', 'cs_disasm_internal.h']}
    observations = []
    for label in ['baseline', 'full-cdecl', 'skip-cdecl']:
        for path, code in pristine.items():
            if label != 'baseline':
                names = 'cs_decode_full_insn|decode_full_insn_body' if label == 'full-cdecl' else 'cs_disasm_iter_skipdata'
                code, count = re.subn(r'CS_PRESERVE_MOST bool\n(' + names + r')\(', r'bool\n\1(', code)
                assert count == (4 if path == 'cs.c' and label == 'full-cdecl' else 1), (path, label, count)
            (tree / path).write_text(code)
        (evidence / (label + '.patch')).write_bytes(sp.check_output(['git', 'diff'], cwd=tree))
        run(['cmake', '--build', build, '--target', 'capstone_static', '--parallel', '4'], 'build-' + label)
        for surface, source, compiler in [('guarded', r / 'guarded.cpp', 'clang++'),
                                           ('minimal', r / 'abi-probe.c', 'clang')]:
            exe = w / (label + '-' + surface)
            run([compiler, '-O2', '-I', base / 'include', source, build / 'libcapstone.a', '-o', exe], 'link-' + label + '-' + surface)
            arguments = [exe, str(bits), data, intervals] if surface == 'guarded' else [exe]
            status = run(arguments, label + '-' + surface, checked=False)
            observations.append(dict(label=label, surface=surface, returncode=status,
                                     binary_sha256=sha(exe), archive_sha256=sha(build / 'libcapstone.a')))
            save('observations', observations)
            if label == 'baseline' and surface == 'guarded':
                commands = w / 'boundary.gdb'
                commands.write_text('''set pagination off
set print pretty on
break cs_disasm_iter if *(unsigned long*)$rdx == 4 && *(unsigned int*)*(unsigned long*)$rsi == 0xffffff4b
run
printf "\\nPUBLIC ENTRY\\n"
info registers
x/12i $pc
tbreak cs_decode_full_insn
continue
printf "\\nFULL ENTRY\\n"
info registers
x/12i $pc
bt
tbreak X86_getInstruction
continue
printf "\\nBACKEND ENTRY\\n"
info registers
x/8bx $rsi
finish
printf "\\nBACKEND RETURN\\n"
info registers
x/12i $pc
finish
printf "\\nFULL RETURN\\n"
info registers
x/18i $pc
continue
''')
                shutil.copyfile(commands, evidence / 'boundary.gdb')
                run(['gdb', '-q', '--batch', '-x', commands, '--args', *arguments], 'gdb-boundary', checked=False)
            if label == 'baseline' or surface == 'minimal':
                for function in ['cs_decode_full_insn', 'cs_disasm_iter_skipdata', 'cs_disasm_iter']:
                    run(['objdump', '-d', '--disassemble=' + function, exe], label + '-' + surface + '-' + function)
        shutil.copyfile(build / 'compile_commands.json', evidence / (label + '-compile_commands.json'))
    save('complete', dict(success=True, diagnostic_only=True, cases=len(observations), no_native_performance_claim=True))
finally:
    files = [path for path in w.rglob('*') if path.is_file()]
    amount = sum(path.stat().st_size for path in files)
    shutil.rmtree(w)
    save('cleanup', dict(bytes=amount, files=len(files), removed=not w.exists()))
