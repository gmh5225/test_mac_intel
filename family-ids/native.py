from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,tempfile
d=Path(__file__).resolve().parent;old=d.parent/'source';out=d.parent/'evidence';out.mkdir(exist_ok=True)
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def cmd(n,a):
 with (out/(n+'.log')).open('w')as log:z=sp.run(a,stdout=log,stderr=sp.STDOUT)
 if z.returncode:print((out/(n+'.log')).read_text(errors='replace')[-1700:]);z.check_returncode()
m=json.loads((d/'release-trees.json').read_text());t=Path(tempfile.mkdtemp(dir=os.environ['RUNNER_TEMP']));pr=t/'nd';s=pr/'third_party/capstone';b=t/'build'
def git(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
try:
 s.parent.mkdir(parents=True);cmd('clone',['git','clone','-q','--shared',old,s]);base=git('rev-parse','HEAD');assert base==m['ordered']['current']['parent']
 (pr/'cmake').mkdir();shutil.copyfile(d/'compiler.inc',pr/'cmake/NeverDCapstoneCompilerOptions.inc')
 (pr/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(VerifyNativeProduct LANGUAGES C CXX)\n'+(d/'product.cmake').read_text()+'\nadd_executable(probe probe.c)\ntarget_link_libraries(probe PRIVATE capstone_static)\n')
 (pr/'probe.c').write_text(r'''#include <capstone/capstone.h>
#include "third_party/capstone/arch/X86/X86ScanAdapter.h"
int main(int argc,char **argv) {
 static const uint8_t bytes[]={0xc5,0xf8,0x77,0x31,0xc0};
 const uint8_t *p=bytes; size_t size=sizeof(bytes);uint64_t ip=0;uint32_t words[2]={0};csh h;
 if(cs_open(CS_ARCH_X86,argc==1?CS_MODE_32:CS_MODE_64,&h))return 1;
 cs_insn *v=cs_malloc(h);
 if(!v||!X86_disasmIterText(h,&p,&size,&ip,v)||v->size!=3)return 2;
 if(cs_option(h,CS_OPT_TEXT,CS_OPT_OFF))return 3;
 if(X86_scanNativeBatch(h,bytes,sizeof(bytes),0,words,2).count!=2||(words[0]&255)!=3||(words[1]&255)!=2)return 4;
 cs_free(v,1);return cs_close(&h);
}
''')
 for name,versions in m.items():
    rows={}
    for key,meta in versions.items():
        git('reset','--hard','-q',base);patch=d/(name+'-'+key+'.patch');assert sha(patch)==meta['checkout_sha256'];git('apply','--index',str(patch));assert git('write-tree')==meta['tree']
        if not b.exists():
            cmd('configure',['cmake','-S',pr,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if os.environ['CC']=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers')])
        cmd(name+'-'+key,['cmake','--build',b,'--target','probe','--parallel','4']);exe=b/'probe';lib,=b.rglob('libcapstone.a')
        members=sp.check_output(['ar','t',lib],text=True).splitlines();assert members.index('X86Vex32Output.c.o')<members.index('X86Sse64Output.c.o')<members.index('X86BatchScan.c.o')
        for mode in ([],['64']):sp.run([exe,*mode],check=True)
        rows[key]=dict(archive=sha(lib),executable=sha(exe),members=len(members))
    assert rows['original']==rows['current']==rows['narrow'],rows
    save(name,rows)
 save('complete',dict(complete=True,source=m,compiler=sp.check_output([os.environ['CC'],'--version'],text=True),cpu=sp.check_output(['lscpu'],text=True)))
finally:
 count=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=count))
