from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess as sp
import tempfile
import xml.etree.ElementTree as ET

r = Path(__file__).resolve().parent
out = r.parent / 'evidence'
out.mkdir()
old = json.loads((r / 'original.json').read_text())
new = json.loads((r / 'candidate.json').read_text())
compiler = os.environ['TOOLCHAIN']
extended = os.environ['EXTENDED'] == '1'
w = Path(tempfile.mkdtemp(prefix='capstone-alias-scope-'))
s = w / 'source'


def save(name, value):
    (out / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')


def run(name, args, expected=True):
    with (out / (name + '.log')).open('wb') as log:
        rc = sp.run(list(map(str, args)), cwd=s, stdout=log, stderr=sp.STDOUT).returncode
    if expected:
        assert rc == 0, (name, (out / (name + '.log')).read_text()[-2500:])
    return rc


def git(*args):
    return sp.check_output(['git', '-C', s, *args], text=True).strip()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def apply(meta, patch):
    git('reset', '--hard', meta['parent'])
    git('clean', '-fd')
    assert sha(r / patch) == meta['sha256']
    git('apply', '--index', str(r / patch))
    assert git('write-tree') == meta['tree']


def options(profile):
    archs = ['X86', 'ARM', 'AARCH64', 'MIPS']
    if profile.endswith('-only'):
        archs = [profile[:-5].upper()]
    elif profile == 'mips-diet':
        archs = ['MIPS']
    elif profile == 'no-x86':
        archs.remove('X86')
    args = ['-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_COMPILER=' + compiler,
            '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
            *['-DCAPSTONE_' + arch + '_SUPPORT=ON' for arch in archs],
            '-DCAPSTONE_BUILD_CSTEST=ON', '-DCAPSTONE_BUILD_CSTOOL=OFF',
            '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF', '-DCAPSTONE_BUILD_MACOS_THIN=ON']
    if compiler == 'gcc':
        args += ['-DCMAKE_C_FLAGS=-Wno-error=discarded-qualifiers']
    if profile in ('diet', 'mips-diet'):
        args += ['-DCAPSTONE_BUILD_DIET=ON']
    elif profile == 'reduced':
        args += ['-DCAPSTONE_X86_REDUCE=ON']
    elif profile == 'adapter':
        args += ['-DCAPSTONE_X86_SCAN_ADAPTER=ON']
    return args


def units(profile):
    names = ['api', 'utils', 'mapping', 'sstream']
    if profile == 'full':
        names += ['register_descriptors', 'detail_option', 'text_option',
                  'x86_encoding_accuracy', 'x86_reg_access', 'x86_scan_batch',
                  'x86_buffer_bounds', 'x86_memory_scale', 'x86_simple_output',
                  'x86_printer_prechecked', 'arm_post_index', 'aarch64_postprocess', 'mips_scan']
        names += [p.stem for p in (s / 'tests/unit').glob('x86_*.c')
                  if p.stem.startswith(('x86_apx', 'x86_amx', 'x86_evex'))]
    elif profile == 'x86-only':
        names += ['x86_simple_output', 'x86_encoding_accuracy', 'x86_reg_access']
    elif profile == 'arm-only':
        names += ['arm_post_index', 'arm_private_stream', 'arm_reg_access']
    return sorted(set(names))


def snapshot(build):
    objroot = build / 'CMakeFiles/capstone.dir'
    return dict(archive=sha(build / 'libcapstone.a'),
                objects={str(p.relative_to(objroot)): sha(p) for p in objroot.rglob('*.o')})


try:
    sp.run(['git', 'clone', '-q', '--shared', '--no-checkout', r.parent / 'source', s], check=True)
    git('checkout', '-q', '--detach', new['parent'])
    assert old['parent'] == new['parent']
    apply(old, 'original.patch')
    old_files = git('ls-files', '-s').splitlines()
    old_guard = (s / 'AliasMapping.c').read_text()
    apply(new, 'candidate.patch')
    new_files = git('ls-files', '-s').splitlines()
    changed = [a.split('\t')[1] for a, b in zip(old_files, new_files) if a != b]
    assert len(old_files) == len(new_files) and changed == ['AliasMapping.c'], changed
    save('source-difference', dict(original=old, candidate=new, changed=changed,
                                  before=old_guard, after=(s / 'AliasMapping.c').read_text()))
    profiles = ['full']
    if extended:
        profiles += ['diet', 'reduced', 'adapter', 'no-x86', 'aarch64-only', 'mips-only']
    rows = []
    for profile in profiles:
        build = w / profile
        apply(old, 'original.patch')
        run('configure-' + profile, ['cmake', '-S', s, '-B', build, *options(profile)])
        run('old-' + profile, ['cmake', '--build', build, '--target', 'capstone_static', '--parallel', '4'])
        before = snapshot(build)
        apply(new, 'candidate.patch')
        selected = units(profile)
        run('new-' + profile, ['cmake', '--build', build, '--target', 'capstone_static', *selected, '--parallel', '4'])
        after = snapshot(build)
        assert before == after, (profile, before, after)
        run('tests-' + profile, ['ctest', '--test-dir', build, '--no-tests=error', '--output-on-failure',
            '--output-junit', out / (profile + '.xml'), '-R', '^unit_(' + '|'.join(selected) + ')$'])
        cases = ET.parse(out / (profile + '.xml')).getroot().findall('testcase')
        assert len(cases) == len(selected) and all(x.find('skipped') is None for x in cases)
        rows.append(dict(profile=profile, object_and_archive_identity=True, snapshot=after, tests=selected))
        save('identity', rows)
    repaired = []
    if compiler == 'clang':
        for profile in ('x86-only', 'arm-only', 'mips-diet'):
            build = w / profile
            apply(old, 'original.patch')
            run('configure-' + profile, ['cmake', '-S', s, '-B', build, *options(profile)])
            rc = run('old-' + profile, ['cmake', '--build', build, '--target',
                     'CMakeFiles/capstone.dir/AliasMapping.c.o', '--parallel', '4'], False)
            if profile != 'mips-diet':
                assert rc != 0 and 'unused function' in (out / ('old-' + profile + '.log')).read_text()
            else:
                assert rc == 0
            apply(new, 'candidate.patch')
            selected = units(profile)
            run('new-' + profile, ['cmake', '--build', build, '--target', 'capstone_static', *selected, '--parallel', '4'])
            run('tests-' + profile, ['ctest', '--test-dir', build, '--no-tests=error', '--output-on-failure',
                '--output-junit', out / (profile + '.xml'), '-R', '^unit_(' + '|'.join(selected) + ')$'])
            cases = ET.parse(out / (profile + '.xml')).getroot().findall('testcase')
            assert len(cases) == len(selected) and all(x.find('skipped') is None for x in cases)
            repaired.append(dict(profile=profile, original_returncode=rc, tests=selected))
    save('complete', dict(original=old, candidate=new, compiler=sp.check_output([compiler, '--version'], text=True),
                         identity_profiles=rows, repaired_profiles=repaired, success=True,
                         scope='Exact complete archive and member identity transfers the prior performance and semantic evidence only for the listed build configurations. The two newly failing profiles are reproduced and repaired independently.'))
finally:
    size = sum(p.stat().st_size for p in w.rglob('*') if p.is_file())
    shutil.rmtree(w)
    save('cleanup', dict(bytes=size, removed=not w.exists()))
