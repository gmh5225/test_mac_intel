from pathlib import Path
import hashlib,json,os,shutil,struct,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;s=r.parent/'source';out=r.parent/'evidence';out.mkdir(exist_ok=True)
m=json.loads((r/'tree.json').read_text());arch=os.environ['TEST_MACHINE']
def sha(b):return hashlib.sha256(b).hexdigest()
def save(n,z):(out/(n+'.json')).write_text(json.dumps(z,indent=2)+'\n')
def run(cmd,n,cwd=None):
    z=sp.run(list(map(str,cmd)),cwd=cwd,stdout=sp.PIPE,stderr=sp.STDOUT)
    (out/(n+'.log')).write_bytes(z.stdout)
    if z.returncode:print(z.stdout[-2000:].decode(errors='replace'),flush=True);z.check_returncode()
    return z.stdout.decode(errors='replace')
def pe(f):
    b=f.read_bytes();p=struct.unpack_from('<I',b,60)[0];assert b[p:p+4]==b'PE\0\0'
    machine,count=struct.unpack_from('<HH',b,p+4);size=struct.unpack_from('<H',b,p+20)[0];sections={}
    for i in range(count):
        off=p+24+size+40*i;name=b[off:off+8].split(b'\0')[0].decode()
        length,rva,file_size,pos=struct.unpack_from('<4I',b,off+8)
        sections[name]=dict(rva=rva,size=length,sha256=sha(b[pos:pos+min(length,file_size)]))
    assert machine=={'x64':0x8664,'x86':0x14c}[arch] and '.text' in sections
    return dict(sha256=sha(b),machine=machine,sections=sections)
git=lambda *a:sp.check_output(['git','-C',s,*a],text=True).strip()
raw=sp.check_output(['git','-C',r.parent,'cat-file','blob','HEAD:private-win/candidate.patch'])
save('input',dict(canonical_sha256=sha(raw),checkout_sha256=sha((r/'candidate.patch').read_bytes()),source=git('rev-parse','HEAD')))
assert sha(raw)==m['sha256'] and git('rev-parse','HEAD')==m['parent']
t=Path(tempfile.mkdtemp());b=t/'build';checks={}
try:
    patch=t/'canonical.patch';patch.write_bytes(raw)
    run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=cl','-DCMAKE_CXX_COMPILER=cl','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTEST=ON'],'configure')
    for k in ('base','candidate'):
        if k=='candidate':
            git('apply','--index',str(patch));assert git('write-tree')==m['tree']
        tests=['x86_simple_output','x86_scan_batch','x86_evex_move_access','x86_buffer_bounds','text_option','detail_option']
        run(['cmake','--build',b,'--parallel','4','--target','capstone_shared','capstone_static',*tests],'build-'+k)
        lib,=b.rglob('capstone_static.lib');dll,=b.rglob('capstone.dll')
        names=sp.check_output(['lib','/nologo','/list',lib],text=True).splitlines()
        present=any(Path(n.strip()).name.lower()=='x86vex32output.c.obj' for n in names) or any('x86vex32output' in n.lower()for n in names)
        assert present==(k=='candidate'),(k,names)
        exports=sp.check_output(['dumpbin','/nologo','/exports',dll],text=True)
        assert 'X86_disasmIter32' not in exports and 'cs_disasm_iter' in exports
        ctest=run(['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','--parallel','2','-R','^unit_('+'|'.join(tests)+')$'],'tests-'+k)
        assert '100% tests passed' in ctest
        checks[k]=dict(library=pe(dll),archive_members=names,tests=tests)
    # The consumer calls the hidden integration through the static library on both host ABIs.
    exe=t/'iterator.exe'
    run(['cl','/nologo','/O2','/MT','/std:c11','/D_CRT_SECURE_NO_WARNINGS','/I'+str(s),'/I'+str(s/'include'),r/'fallback.c',lib,'/Fe:'+str(exe)],'consumer',t)
    assert run([exe],'fallback').strip()=='9216 raw iterator comparisons'
    x=checks['base']['library']['sections']['.text'];y=checks['candidate']['library']['sections']['.text']
    save('verified',dict(tree=m['tree'],arch=arch,tests=checks,shared_code_identical=x==y,raw_matrix=9216))
finally:
    n=sum(q.stat().st_size for q in t.rglob('*')if q.is_file());shutil.rmtree(t);save('cleanup',dict(bytes=n,removed=not t.exists()))
