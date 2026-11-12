import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

base = Path(__file__).resolve().parent
p = json.loads((base / 'Policy.def').read_text())
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
report = {'source': p['source'], 'fixture_sha256': hashlib.sha256(fixture.encode()).hexdigest(), 'results': []}
try:
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        driver = body('kObserver')
        driver = driver.replace('static void observe(', (base / 'Probe.def').read_text() + '\nstatic void observe(')
        driver = driver.replace('  atomic_store(&state.done, stage);', '  if (stage == target_stage) walk_signal(regs, s->pc, caller, entry_sp);\n  atomic_store(&state.done, stage);')
        driver = driver.replace('argc != 6', 'argc != 8').replace('  alarm(20);', '  target_stage = atoi(argv[6]); walk_mode = atoi(argv[7]);\n  alarm(20);')
        for name, text in [('stages.S', body('kAssembly')), ('companion.S', body('kOriginalCompanion')), ('caller.S', body('kCaller')), ('driver.c', driver), ('rules', p['rules'])]:
            (td / name).write_text(text)
        cc = [p['compiler'], *p['flags'], '-I', source / 'include']
        check([*cc, 'driver.c', 'caller.S', '-o', 'driver'], td)
        for profile, flags in [('implicit', []), ('explicit', ['-DNEVERD_TEST_EXPLICIT_RA'])]:
            image = td / (profile + '.dylib')
            check([*cc, '-dynamiclib', *flags, 'stages.S', 'companion.S', '-o', image], td)
            for stage, mode in [(0, 0), *((s, m) for s in p['stages'] for m in p['modes'].values())]:
                r = run([td / 'driver', image, 0, 3, td / 'samples', td / 'rules', stage, mode], td)
                report['results'].append({'profile': profile, 'stage': stage, 'mode': mode, 'exit': r.returncode, 'trace': r.stderr})
                if stage == 0:
                    r.check_returncode()
finally:
    Path(p['report']).write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
