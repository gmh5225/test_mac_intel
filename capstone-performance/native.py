from pathlib import Path
import json
import os
import shutil
import subprocess as sp

import run


def verify(source, root, corpus, cc, configuration):
    flags = {'full': [], 'diet': ['-DCAPSTONE_BUILD_DIET=ON'],
             'reduced': ['-DCAPSTONE_X86_REDUCE=ON'],
             'no-att': ['-DCAPSTONE_X86_ATT_DISABLE=ON']}[configuration]
    arch = ['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF', '-DCAPSTONE_X86_SUPPORT=ON']
    build = root / 'states'
    libs = []
    for variant in ('base', 'candidate'):
        if variant == 'candidate':
            run.command(['git', 'apply', run.SOURCE / 'alias-trie.patch'], 'apply-states', source)
        run.command(['cmake', '-S', source, '-B', build, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
                     '-DCMAKE_C_COMPILER=' + cc, '-DCAPSTONE_BUILD_SHARED_LIBS=ON',
                     '-DCAPSTONE_BUILD_CSTOOL=OFF', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
                     *arch, *flags], 'states-configure-' + variant)
        run.command(['cmake', '--build', build, '--target', 'capstone_shared', '--parallel', '4'],
                    'states-build-' + variant)
        libs.append(root / (variant + '.so'))
        shutil.copyfile(build / 'libcapstone.so', libs[-1])
    run.command(['git', 'apply', '-R', run.SOURCE / 'alias-trie.patch'], 'restore-source', source)
    assert not sp.check_output(['git', 'status', '--porcelain'], cwd=source)
    program = root / 'verify'
    run.command(['clang++', '-std=c++17', '-O2', '-I', source / 'include', run.SOURCE / 'complete-public.cpp',
                 '-ldl', '-o', program], 'build-states-verifier')
    directory = Path(next(c['path'] for c in corpus if c['name'] == 'amd64-sort')).parent
    results = []
    for custom in (False, True):
        if custom:
            os.environ['CUSTOM_NAMES'] = '1'
        name = 'states-custom' if custom else 'states-default'
        run.command([program, *libs, '65536', directory], name)
        records = [json.loads(l) for l in (run.EVIDENCE / (name + '.log')).read_text().splitlines() if l.startswith('{')]
        assert records and records[-1]['compared_total'] > 500000
        results.append({'custom': custom, 'cells': len(records), 'records': records[-1]['compared_total']})
    os.environ.pop('CUSTOM_NAMES', None)
    run.write('public.json', {'cc': cc, 'config': configuration, 'results': results,
                             'libraries': [run.sha(lib) for lib in libs]})
