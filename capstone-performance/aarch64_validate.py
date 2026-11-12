"""Check outer AArch64 operand initialization through public decoder entry points."""
from pathlib import Path
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time

import corpus

SOURCE = Path(__file__).resolve().parent
EVIDENCE = SOURCE.parent / 'capstone-evidence'
EVIDENCE.mkdir()
WORK = Path(tempfile.mkdtemp(prefix='aarch64-outer-', dir=os.environ['RUNNER_TEMP']))
PROFILE = sys.argv[1]
MANIFEST = json.loads((SOURCE / 'manifest.json').read_text())


def write(name, value):
    (EVIDENCE / name).write_text(json.dumps(value, indent=2) + '\n')


def command(args, label, cwd=None):
    start = time.monotonic()
    print(label, flush=True)
    with (EVIDENCE / (label + '.log')).open('w') as log:
        result = subprocess.run(list(map(str, args)), cwd=cwd, stdout=log,
                                stderr=subprocess.STDOUT)
    with (EVIDENCE / 'commands.jsonl').open('a') as log:
        log.write(json.dumps(dict(label=label, args=list(map(str, args)),
                                  seconds=time.monotonic() - start,
                                  returncode=result.returncode)) + '\n')
    if result.returncode:
        print((EVIDENCE / (label + '.log')).read_text()[-5000:], flush=True)
        raise RuntimeError(label)


def instrument(tree, poison):
    header = tree / 'MCInst.h'
    code = header.read_text()
    marker = 'static inline MCOperand *MCInst_getOperand(MCInst *inst, unsigned i)\n{'
    assert code.count(marker) == 1
    replacement = '''extern __thread const MCInst *a64_probe_current_instruction;
extern __thread unsigned long long a64_probe_read_checks;
extern __thread unsigned long long a64_probe_slot_mask;
static inline MCOperand *MCInst_getOperand(MCInst *inst, unsigned i)
{
    if (inst == a64_probe_current_instruction) {
        if (i >= inst->size && !(i == 0 && inst->size == 0)) {
            fprintf(stderr, "outer operand read: index=%u count=%u opcode=%u\\n", i, inst->size, inst->Opcode);
            abort();
        }
        ++a64_probe_read_checks;
        a64_probe_slot_mask |= 1ULL << i;
    }'''
    header.write_text('#include <stdio.h>\n#include <stdlib.h>\n' + code.replace(marker, replacement))
    path = tree / 'cs.c'
    code = path.read_text()
    start = code.index('CS_PRESERVE_MOST bool\ncs_decode_full_insn(')
    end = code.index('\n#if defined(_MSC_VER)', start)
    body = code[start:end]
    assert body.count('return false;') == 1 and body.count('return true;') == 1
    body = body.replace('\tMCInst mci;', '''\tMCInst mci;
\tconst MCInst *previous_instruction = a64_probe_current_instruction;
\tif (handle->arch == CS_ARCH_AARCH64)
\t\tmemset(&mci, POISON_VALUE, sizeof(mci));'''.replace('POISON_VALUE', str(poison)))
    body = body.replace('\tmci.csh = handle;', '''\tif (handle->arch == CS_ARCH_AARCH64)
\t\ta64_probe_current_instruction = &mci;
\tmci.csh = handle;''')
    body = body.replace('\t\treturn false;', '''\t{
\t\ta64_probe_current_instruction = previous_instruction;
\t\treturn false;
\t}''')
    body = body.replace('\treturn true;', '''\ta64_probe_current_instruction = previous_instruction;
\treturn true;''')
    globals = '''__thread const MCInst *a64_probe_current_instruction;
__thread unsigned long long a64_probe_read_checks;
__thread unsigned long long a64_probe_slot_mask;
unsigned long long a64_probe_probe_checks(void) { return a64_probe_read_checks; }
unsigned long long a64_probe_probe_slots(void) { return a64_probe_slot_mask; }

'''
    # Keep the noinline attribute attached to the decoder declaration.
    declarations = code.rfind('#if defined(_MSC_VER)', 0, start)
    assert declarations >= 0
    path.write_text(code[:declarations] + globals + code[declarations:start] + body + code[end:])


def build(tree, label, units=False):
    build_dir = WORK / (label + '-build')
    options = ['-DCAPSTONE_BUILD_DIET=ON'] if PROFILE == 'diet' else []
    if PROFILE == 'pattern':
        options += ['-DCMAKE_C_FLAGS=-ftrivial-auto-var-init=pattern']
    command(['cmake', '-S', tree, '-B', build_dir, '-G', 'Ninja',
             '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_COMPILER=clang',
             '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF', '-DCAPSTONE_AARCH64_SUPPORT=ON',
             '-DCAPSTONE_BUILD_SHARED_LIBS=ON', '-DCAPSTONE_BUILD_STATIC_LIBS=ON',
             '-DCAPSTONE_BUILD_CSTOOL=OFF', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
             '-DCAPSTONE_BUILD_CSTEST=' + ('ON' if units else 'OFF'), *options],
            label + '-configure')
    tests = ['mcinst', 'aarch64_postprocess']
    command(['cmake', '--build', build_dir, '--target', 'capstone_shared',
             *(tests if units else []), '--parallel', '3'], label + '-build')
    if units:
        command(['ctest', '--test-dir', build_dir, '--no-tests=error', '--output-on-failure',
                 '-R', '^unit_(' + '|'.join(tests) + ')$'], label + '-tests')
    return build_dir / 'libcapstone.so.6.0.0'


def main():
    assert PROFILE in ('full', 'diet', 'pattern')
    write('environment.json', dict(profile=PROFILE, uname=list(platform.uname()),
                                  github_sha=os.environ['GITHUB_SHA'],
                                  baseline=MANIFEST['capstone_revision']))
    base = WORK / 'base'
    command(['git', 'init', base], 'base-init')
    command(['git', 'fetch', '--depth=1', 'https://github.com/NeverSight/capstone.git',
             MANIFEST['capstone_revision']], 'base-fetch', base)
    command(['git', 'checkout', '--detach', 'FETCH_HEAD'], 'base-checkout', base)
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=base,
                                   text=True).strip() == MANIFEST['capstone_revision']
    new = WORK / 'new'
    command(['git', 'worktree', 'add', '--detach', new, 'HEAD'], 'candidate-checkout', base)
    patch = SOURCE / 'aarch64-outer.patch'
    assert hashlib.sha256(patch.read_bytes()).hexdigest() == MANIFEST['source_lineage'][patch.name]['sha256']
    command(['git', 'apply', '--check', patch], 'patch-check', new)
    command(['git', 'apply', patch], 'patch-apply', new)
    assert (new / 'cs.c').read_bytes() != (base / 'cs.c').read_bytes()
    fixtures = WORK / 'corpus'
    fixtures.mkdir()
    cases = []
    packages = {}
    for row in MANIFEST['inputs']:
        if not row['name'].startswith('arm64-'):
            continue
        digest = row['package_sha256']
        if digest not in packages:
            package = fixtures / digest
            command(['curl', '--fail', '--location', '--silent', '--show-error',
                     '--max-time', '120', row['url'], '-o', package], 'download-' + digest[:8])
            assert corpus.digest(package.read_bytes()) == digest
            packages[digest] = package
        text = corpus.elf_text(corpus.deb_binary(packages[digest], row['command']))
        assert corpus.digest(text) == row['text_sha256']
        (fixtures / (row['name'] + '.text')).write_bytes(text)
        cases.append(row)
    assert len(cases) == 3
    # Exercise each four-byte instruction in the checked-out AArch64 MC corpus.
    import re
    words = set()
    for yaml in (base/'tests/MC/AArch64').rglob('*.yaml'):
        for lane in re.findall(r'bytes:\s*\[([^\]]+)\]',yaml.read_text()):
            try: data = bytes(int(v,0) for v in lane.split(','))
            except ValueError: continue
            if len(data)==4: words.add(data)
    assert len(words)>1000,len(words)
    (fixtures/'arm64-mc.text').write_bytes(b''.join(sorted(words)))
    write('mc-corpus.json',dict(distinct_words=len(words)))
    write('corpus.json', cases)
    libraries = {'base': build(base, 'base'), 'new': build(new, 'new', units=True)}
    for label, poison in [('poison-a5', 0xa5), ('poison-5a', 0x5a)]:
        tree = WORK / label
        shutil.copytree(new, tree, ignore=shutil.ignore_patterns('.git'))
        instrument(tree, poison)
        libraries[label] = build(tree, label)
    checker = WORK / 'aarch64-state'
    command(['clang++', '-O3', '-DNDEBUG', '-std=c++17', '-I', base / 'include',
             SOURCE / 'aarch64-state.cpp', '-ldl', '-o', checker], 'compile-checker')
    checks = []
    for label in ['new', 'poison-a5', 'poison-5a']:
        for custom in [False, True]:
            name = label + ('-custom' if custom else '-default')
            command([checker, libraries['base'], libraries[label], fixtures,
                     *(['custom'] if custom else [])], name)
            result = json.loads((EVIDENCE / (name + '.log')).read_text().splitlines()[-1])
            if label.startswith('poison'):
                assert result['outer_reads_checked'] > 0 and result['slot_mask'] > 0
            checks.append(dict(variant=label, **result))
            write('semantic-checks.json', checks)
    write('verified.json', dict(complete=True, checks=checks,
                               library_sha256={k: corpus.digest(v.read_bytes())
                                               for k, v in libraries.items()}))


try:
    main()
finally:
    size = sum(path.stat().st_size for path in WORK.rglob('*') if path.is_file())
    shutil.rmtree(WORK)
    write('cleanup.json', dict(bytes=size, removed=not WORK.exists()))
