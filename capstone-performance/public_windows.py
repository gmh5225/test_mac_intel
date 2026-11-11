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
    import io, tarfile
    for arch in ('armel','armhf'):
        rows=[row for row in manifest['arm_fixtures'] if row['arch']==arch]
        f=inputs/arch
        command(['curl','-fLsS','--retry','3',rows[0]['url'],'-o',f],'fetch-'+arch)
        data=f.read_bytes();assert hashlib.sha256(data).hexdigest()==rows[0]['package_sha256']
        assert data[:8]==b'!<arch>\n';i=8
        while i<len(data):
            h=data[i:i+60];n=int(h[48:58]);i+=60
            if h[:16].strip().startswith(b'data.tar'):break
            i+=n+n%2
        with tarfile.open(fileobj=io.BytesIO(data[i:i+n])) as archive:
            for row in rows:
                binary=archive.extractfile(row['member']).read()
                text=corpus.elf_text(binary)
                assert hashlib.sha256(text).hexdigest()==row['text_sha256']
                assert int.from_bytes(binary[24:28],'little')==row['entry']
                (inputs/(arch+'-'+row['cmd']+'.text')).write_bytes(text)
    assert len(list(inputs.glob('*.text')))==6
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
    for label in ('default','custom-mnemonics','real-alias-detail'):
        if label.startswith('custom'):os.environ['CUSTOM_NAMES']='1'
        if label=='real-alias-detail':os.environ['DETAIL_FLAGS']='3'
        command([exe,*dlls,'65536',inputs],label)
        entries=[json.loads(line) for line in (EVIDENCE/(label+'.log')).read_text().splitlines() if line.startswith('{')]
        assert entries and len(entries)==(6 if label=='real-alias-detail' else 24) and entries[-1]['compared_total']>390000
        write(label+'.json',dict(compared=entries[-1]['compared_total'],cases=len(entries)))
if __name__=='__main__':
    try:main()
    finally:cleanup()
