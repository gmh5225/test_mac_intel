import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

base = Path(__file__).resolve().parent
p = json.loads((base / 'Cursor.def').read_text())
source = Path(os.environ.get('NEVERD_CURSOR_SOURCE', 'neverd')).resolve()
fixture = (source / p['fixture']).read_text()

def body(key):
    return re.search(key + r', R"(asm|c)\((.*?)\)\1"', fixture, re.S)[2]

def run(args, cwd):
    return subprocess.run([str(a) for a in args], cwd=cwd, capture_output=True,
                          text=True, timeout=p['native_timeout'])

def check(args, cwd):
    r = run(args, cwd)
    if r.returncode:
        raise ValueError((r.returncode, r.stderr))

compile_only = os.environ.get('NEVERD_CURSOR_COMPILE_ONLY') == '1'
rev = subprocess.check_output(['git', '-C', source, 'rev-parse', 'HEAD'], text=True).strip()
assert rev == p['source']
report = {'source': rev, 'fixture_sha256': hashlib.sha256(fixture.encode()).hexdigest(),
          'results': [], 'system_cursor_qualified': False}
try:
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        # Darwin libunwind may inspect the caller during a walk across the
        # interrupted frame. Its saved LR must follow the native IB convention.
        wrapper = body('kCaller').replace('  stp x29, x30', '  pacibsp\n  stp x29, x30')
        wrapper = wrapper.replace('  ldp x29,x30,[sp],#16\n  ret', '  ldp x29,x30,[sp],#16\n  retab')
        wrapper += (base / p['outer']).read_text()
        driver = body('kObserver')
        driver = driver.replace('extern uintptr_t return_address(void);', 'extern uintptr_t return_address(void);\nextern uintptr_t outer_return_address(void);\nextern void call_outer(entry, struct handshake *);')
        driver = driver.replace('  invoke_stages(run, &state);', '  call_outer(run, &state);')
        driver = driver.replace('static uintptr_t expected_return;', 'static uintptr_t expected_return;\nstatic uintptr_t expected_outer;')
        driver = driver.replace('expected_return = return_address();', 'expected_return = return_address();\n  expected_outer = outer_return_address();')
        driver = driver.replace('  atomic_store(&state.done, stage);', (base / p['chain']).read_text() + '\n  atomic_store(&state.done, stage);')
        driver = driver.replace('static void observe(', (base / p['unwind']).read_text() + '\nstatic void observe(')
        driver = driver.replace('  atomic_store(&state.done, stage);',
                                '  if (stage == target_stage) walk_signal(s->pc);\n  atomic_store(&state.done, stage);')
        driver = driver.replace('if (argc != 5)', 'if (argc != 6)').replace('  alarm(20);','  target_stage = atoi(argv[5]);\n  alarm(20);')
        for name, text in [('stages.S', body('kAssembly')), ('companion.S', body('kOriginalCompanion')),
                           ('caller.S', wrapper), ('driver.c', driver)]:
            (td/name).write_text(text)
        cc = [p['compiler'], *p['flags']]
        check([*cc, 'driver.c', 'caller.S', '-o', 'driver'], td)
        for profile, flags, framed in [('explicit', ['-DNEVERD_TEST_EXPLICIT_RA'], False),
                                       ('implicit', [], False), ('framed-explicit', ['-DNEVERD_TEST_EXPLICIT_RA'], True),
                                       ('framed-implicit', [], True)]:
            stages = body('kAssembly')
            if framed:
                stages = stages.replace('  sub sp, sp, #16\n.cfi_def_cfa_offset 16\n  str x30, [sp,#8]',
                                        '  stp x29, x30, [sp,#-16]!\n.cfi_def_cfa_offset 16\n.cfi_offset x29,-16\n  mov x29,sp')
                stages = stages.replace('  ldr x30, [sp,#8]\n.cfi_restore 30\n  add sp, sp, #16',
                                        '  ldp x29,x30,[sp],#16\n.cfi_restore x29\n.cfi_restore 30')
            (td/'stages.S').write_text(stages)
            image = td / (profile + '.dylib')
            check([*cc, '-dynamiclib', *flags, 'stages.S', 'companion.S', '-o', image], td)
            if compile_only:
                continue
            # Zero exercises the compiler-original hardware control without a cursor.
            for stage in [0, -1, *p['stages']]:
                r = run([td/'driver', image, 0, 3, td/'samples', stage], td)
                report['results'].append({'profile': profile, 'stage': stage,
                                          'exit': r.returncode, 'trace': r.stderr[-2048:]})
                if stage == 0:
                    r.check_returncode()
        report['system_cursor_qualified'] = not compile_only and all(r['exit'] == 0 for r in report['results'] if r['stage'] > 0)
        report['sampled_chain_qualified'] = not compile_only and all(r['exit'] == 0 for r in report['results'] if r['stage'] == -1)
finally:
    Path(p['report']).write_text(json.dumps(report, indent=2) + '\n')
if not compile_only and not report['sampled_chain_qualified']:
    raise SystemExit(1)
