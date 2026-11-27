from pathlib import Path
import hashlib,json,shutil,subprocess as sp,tempfile
from training import fetch
r=Path(__file__).resolve().parent;p=r.parent;s=p/'source';nd=p/'neverd-config';out=p/'evidence';out.mkdir(exist_ok=True)
q=json.loads((r/'source.json').read_bytes());w=Path(tempfile.mkdtemp());pr=w/'project';b=w/'build'
def run(*a):sp.run(a,check=True)
def get(*a):return sp.check_output(a,text=True).strip()
def save(f,v):(out/(f+'.json')).write_text(json.dumps(v,indent=2)+'\n')
try:
    assert get('git','-C',s,'rev-parse','HEAD')==q['shipping']['commit']
    (pr/'third_party').mkdir(parents=True);(pr/'third_party/capstone').symlink_to(s);(pr/'cmake').mkdir()
    cm='cmake/NeverDCapstoneCompilerOptions.inc';shutil.copyfile(nd/cm,pr/cm);cfg=(nd/'CMakeLists.txt').read_text()
    (pr/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(ForeignCounts LANGUAGES C CXX)\n'+cfg[cfg.index('# --- Capstone (our fork'):cfg.index('# --- NeverD CMake helpers')])
    run('cmake','-S',pr,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release')
    inputs=[z for z in fetch(r,w) if z['arch'] not in ('i386','amd64')];assert len(inputs)==5
    text=(r/'foreign.cpp').read_text()
    text=text.replace('int main(int argc', 'extern "C" { uint64_t profile_core,profile_reader,profile_fixed; }\nint main(int argc')
    text=text.replace('  cs_free(insn,1);','  std::printf("%llu %llu %llu\\n",(unsigned long long)profile_core,(unsigned long long)profile_reader,(unsigned long long)profile_fixed);\n  cs_free(insn,1);')
    (w/'probe.cpp').write_text(text)
    run('clang++','-O2','-std=c++17','-I',s/'include','-c',w/'probe.cpp','-o',w/'probe.o')
    f=w/'reference.c';f.write_text('#include "arch/X86/X86ScanAdapter.h"\n__attribute__((used)) static __typeof__(&X86_disasmIterText) const reader=X86_disasmIterText;\n')
    run('clang','-O2','-I',s,'-I',s/'include','-c',f,'-o',w/'native.o')
    results={};baseline={};symbols={}
    def instrument(file,marker,counter,body):
        f=s/file;text=f.read_text();assert text.count(marker)==1,(file,marker)
        pos=text.index(marker);pos=text.index('{',pos)+1 if body else pos
        f.write_text(text[:pos]+'\n\textern uint64_t '+counter+'; ++'+counter+';\n'+text[pos:])
    for tag,meta in q.items():
        run('git','-C',s,'restore','--source=HEAD','--staged','--worktree','--','.')
        if tag!='shipping':
            patch=r/(tag+'.patch');assert hashlib.sha256(patch.read_bytes()).hexdigest()==meta['sha256']
            run('git','-C',s,'apply','--index',patch)
        assert get('git','-C',s,'write-tree')==meta['tree']
        instrument('cs.c','\tMCInst mci;\n#ifdef CAPSTONE_HAS_X86\n\tif (handle->arch == CS_ARCH_X86)', 'profile_core',False)
        if tag in ('original','entry','outer'):
            f='arch/X86/X86PublicOutputImpl.h'
            instrument(f,'X86_decodePublicRecord(cs_struct *handle,','profile_reader',True)
            instrument(f,'CS_PRESERVE_MOST bool decodePublicTextRecord(','profile_fixed',True)
        run('cmake','--build',b,'--target','capstone_static','--parallel','4');lib,=b.rglob('libcapstone.a');results[tag]={};symbols[tag]={}
        for route in ('public','native'):
            exe=w/(tag+route);extra=[w/'native.o'] if route=='native' else []
            run('clang++',w/'probe.o',*extra,lib,'-o',exe);syms=get('nm',exe)
            assert (' X86_disasmIterText' in syms)==bool(extra)
            symbols[tag][route]=[ln.strip()for ln in syms.splitlines() if ln.endswith((' X86_decodePublicRecord',' X86_disasmIterText',' cs_decode_full_insn'))]
            rows={};results[tag][route]=rows
            for rec in inputs:
                for mode in range(3):
                    name=rec['name']+'/'+str(mode);raw=list(map(int,get(exe,rec['arch'],w/(rec['name']+'.text'),str(mode),'1').split()))
                    assert len(raw)==9
                    witness=raw[2:6];total=sum(witness[:2]);assert total>0
                    if name not in baseline:baseline[name]=witness
                    assert witness==baseline[name],(tag,route,name,witness,baseline[name])
                    want=[total,total if route=='native' and tag in ('original','entry') else 0,total if route=='native' and tag=='original' else 0]
                    assert raw[6:]==want,(tag,route,name,want,raw)
                    rows[name]=dict(attempts=total,accepted=witness[0],rejected=witness[1],boundaries=witness[2],score=witness[3],core=raw[6],x86_entry=raw[7],x86_text=raw[8])
            save('counts',results)
    save('complete',dict(complete=True,source=q,inputs=inputs,results=results,symbols=symbols))
finally:
    used=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=used))
