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
w = Path(tempfile.mkdtemp(prefix='capstone-vex32-archive-order-'))
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
    args += ['-DCAPSTONE_BUILD_SHARED_LIBS=ON', '-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer '+('-Wno-error=discarded-qualifiers' if compiler=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers')]
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
    sp.run(['git','clone','-q','--shared','--no-checkout',r.parent/'source',s],check=True)
    git('checkout','-q','--detach',new['parent'])
    assert old['parent']==new['parent']
    apply(old,'original.patch')
    old_files={line.split('\t')[1]:line.split('\t')[0] for line in git('ls-files','-s').splitlines()}
    apply(new,'candidate.patch')
    new_files={line.split('\t')[1]:line.split('\t')[0] for line in git('ls-files','-s').splitlines()}
    changed=sorted(k for k in old_files.keys()|new_files.keys() if old_files.get(k)!=new_files.get(k))
    assert changed==['CMakeLists.txt','Makefile','xcode/Capstone.xcodeproj/project.pbxproj'],changed
    save('source-difference',dict(changed=changed,original=old,candidate=new))
    git('reset','--hard',new['parent']);git('clean','-fd')
    run('consumer',['clang++','-O3','-DNDEBUG','-std=c++17','-I',s,'-I',s/'include','-c',r/'single.cpp','-o',w/'single.o'])
    selected=units('full');build=w/'build';snapshots={};orders={};binaries={}
    from layout import linked_layout
    for label in ('baseline','original','candidate'):
        if label=='baseline':git('reset','--hard',new['parent']);git('clean','-fd')
        else:apply(old if label=='original' else new,label+'.patch')
        run('configure-'+label,['cmake','-S',s,'-B',build,*options('full')])
        targets=['capstone_static']+(selected if label=='candidate' else [])
        run('build-'+label,['cmake','--build',build,'--target',*targets,'--parallel','4'])
        snapshots[label]=snapshot(build)
        orders[label]=sp.check_output(['ar','t',build/'libcapstone.a'],text=True).splitlines()
        binary=w/'single'
        run('link-'+label,['clang++',w/'single.o',build/'libcapstone.a','-lm','-o',binary])
        binaries[label]=sha(binary)
        (out/(label+'-symbols.txt')).write_text(sp.check_output(['nm','-S','--defined-only',binary],text=True))
        save('snapshots',snapshots);save('archive-orders',orders);save('binaries',binaries)
        if label!='baseline':save(label+'-linked-layout',linked_layout(out/'baseline-symbols.txt',out/(label+'-symbols.txt'),'output'))
    assert snapshots['original']['objects']==snapshots['candidate']['objects']
    before,after=orders['original'],orders['candidate']
    assert sorted(before)==sorted(after) and before!=after
    moved='X86Vex32Output.c.o'
    assert [x for x in before if x!=moved]==[x for x in after if x!=moved]
    assert before.index(moved)>before.index('X86VectorOutput.c.o')
    assert after.index('X86OutputIterator.c.o')<after.index(moved)<after.index('X86VectorOutput.c.o')
    layout=json.loads((out/'candidate-linked-layout.json').read_text())
    vectors={'X86_writeDisp8','X86_writeEvexBroadcastPrechecked','X86_writeVectorOutput','writeEvexOutput','writeVectorRegisters','writeVexIndexedOutput','writeVexRegisterOutput','writeVexRipLoad'}
    residual=[x for x in layout['text']['changed'] if x['symbol'] in vectors]
    save('order-proof',dict(compiled_members_identical=True,only_member_moved=moved,vector_positions_restored=not residual,residual_vector_positions=residual,source_changes=changed))
    run('tests',['ctest','--test-dir',build,'--no-tests=error','--output-on-failure','--output-junit',out/'full.xml','-R','^unit_('+'|'.join(selected)+')$'])
    cases=ET.parse(out/'full.xml').getroot().findall('testcase')
    assert len(cases)==len(selected) and all(x.find('skipped') is None for x in cases)
    if compiler=='clang':assert not residual,residual
    else:assert len(set(binaries.values()))==1,binaries
    save('complete',dict(success=True,original=old,candidate=new,compiler=compiler,objects=len(snapshots['candidate']['objects']),tests=len(cases),vector_positions_restored=True,inactive_binary_identical=compiler=='gcc',performance_qualified=False))
finally:
    size=sum(f.stat().st_size for f in w.rglob('*') if f.is_file())
    shutil.rmtree(w)
    save('cleanup',dict(bytes=size,removed=not w.exists()))
