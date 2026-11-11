from pathlib import Path
import hashlib, json, os, shutil, subprocess as sp, sys, tempfile
import corpus
from run import EVIDENCE, SOURCE, command, fetch, write, WORK, cleanup
name=sys.argv[1]
def main():
    EVIDENCE.mkdir();WORK.mkdir()
    manifest=json.loads((SOURCE/'manifest.json').read_text())
    patch=SOURCE/'combined-product.patch'
    assert hashlib.sha256(patch.read_bytes()).hexdigest()==manifest['source_lineage'][patch.name]['sha256']
    root=fetch('base','https://github.com/NeverSight/capstone.git',manifest['capstone_revision'])
    cand=WORK/'candidate';shutil.copytree(root,cand,ignore=shutil.ignore_patterns('.git'))
    command(['git','apply','--no-index',patch],'apply',cand)
    inputs=WORK/'corpus';inputs.mkdir()
    for row in manifest['inputs']:
        if row['name'] not in ('putty-32-0.85','putty-64-0.85'):continue
        f=inputs/row['name']
        command(['curl','-fLsS','--retry','2','--max-time','120',row['url'],'-o',f],'fetch-'+f.name)
        binary=f.read_bytes();assert hashlib.sha256(binary).hexdigest()==row['package_sha256']
        data=corpus.pe_text(binary);sha=hashlib.sha256(data).hexdigest()
        assert 'text_sha256' not in row or sha==row['text_sha256']
        (inputs/(f.name+'.text')).write_bytes(data)
        write(f.name+'-input.json',dict(package=row['package_sha256'],text=sha,bytes=len(data)))
    assert len(list(inputs.glob('*.text')))==2
    opts=['-G','Visual Studio 17 2022','-A','x64']
    dlls=[]
    for label,source in [('base',root),('candidate',cand)]:
        d=WORK/(label+'-build')
        flags=['-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=OFF','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=OFF','-DCMAKE_C_FLAGS=/MP4',*['-DCAPSTONE_'+s+'_SUPPORT=ON' for s in ('ARM','AARCH64','MIPS','X86')]]
        if source==cand:flags.append('-DCAPSTONE_MSVC_NATIVE_DECODER=ON')
        if name=='diet':flags.append('-DCAPSTONE_BUILD_DIET=ON')
        if name=='reduced':flags.append('-DCAPSTONE_X86_REDUCE=ON')
        command(['cmake','-S',source,'-B',d,*opts,*flags],label+'-config')
        command(['cmake','--build',d,'--config','Release','--target','capstone_shared','--parallel','4'],label+'-build')
        dll,=d.rglob('capstone.dll')
        # Distinct module names prevent the Windows loader from reusing a loaded DLL.
        target=WORK/('capstone-'+label+'.dll');shutil.copyfile(dll,target);dlls.append(target)
    driver=WORK/'driver';driver.mkdir();db=WORK/'driver-build'
    (driver/'CMakeLists.txt').write_text(f'cmake_minimum_required(VERSION 3.15)\nproject(check CXX)\nadd_executable(compare "{(SOURCE/"windows-public.cpp").as_posix()}")\ntarget_include_directories(compare PRIVATE "{(root/"include").as_posix()}")\ntarget_compile_features(compare PRIVATE cxx_std_17)\n')
    command(['cmake','-S',driver,'-B',db,*opts],'driver-config')
    command(['cmake','--build',db,'--config','Release'],'driver-build')
    exe,=db.rglob('compare.exe')
    write('binaries.json',{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in [exe,*dlls]})
    for label in ('default','custom-mnemonics'):
        if label.startswith('custom'):os.environ['CUSTOM_NAMES']='1'
        command([exe,*dlls,'65536',inputs],label)
        entries=[json.loads(line) for line in (EVIDENCE/(label+'.log')).read_text().splitlines() if line.startswith('{')]
        assert entries and entries[-1]['compared_total']>2000000
        write(label+'.json',dict(compared=entries[-1]['compared_total'],cases=len(entries)))
if __name__=='__main__':
    try:main()
    finally:cleanup()
