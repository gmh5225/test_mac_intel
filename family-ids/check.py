from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,sys,tempfile
d=Path(__file__).resolve().parent;local=len(sys.argv)>1
out=d if local else d.parent/'evidence';out.mkdir(exist_ok=True)
def read(f):return json.loads(f.read_text())
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(n,args,cwd=None):
    with (out/(n+'.log')).open('w')as f:z=sp.run(args,cwd=cwd,stdout=f,stderr=sp.STDOUT)
    if z.returncode:print((out/(n+'.log')).read_text(errors='replace')[-2900:]);z.check_returncode()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
m=read(d/'layers.json');stages=m['layers'];t=Path(tempfile.mkdtemp(dir=d if local else os.environ['RUNNER_TEMP']));project=t/'neverd';s=project/'third_party/capstone';b=t/'build'
def git(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
try:
    s.parent.mkdir(parents=True)
    repo=next(d.parent.glob('round579-*'))/'source' if local else d.parent/'source'
    run('clone',['git','clone','--shared','--no-checkout','-q',repo,s]);git('checkout','--detach','-q',m['base_commit'])
    (project/'cmake').mkdir();shutil.copyfile(d/'compiler.inc',project/'cmake/NeverDCapstoneCompilerOptions.inc')
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(CompareLinkedDecoder LANGUAGES C CXX)\n'+(d/'product.cmake').read_text()+'\nadd_executable(compare-abi probe.c)\ntarget_link_libraries(compare-abi PRIVATE capstone_static)\n')
    (project/'probe.c').write_text('#include <capstone/capstone.h>\n#include "third_party/capstone/arch/X86/X86ScanAdapter.h"\nint main(int argc,char **v){ csh h; cs_insn *insn; uint64_t ip=0; size_t n=3; const uint8_t *p=(const uint8_t*)"\\xc5\\xf8\\x77"; if(cs_open(CS_ARCH_X86,argc==1 ? CS_MODE_32 : CS_MODE_64,&h))return 1; insn=cs_malloc(h); if(!insn||!X86_disasmIterText(h,&p,&n,&ip,insn)||ip!=3)return 2; cs_free(insn,1);return cs_close(&h);}\n')
    opts=['-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON']
    run('configure',['cmake','-S',project,'-B',b,'-G','Ninja',*opts]);rows={}
    for key,pair in stages.items():
        if key in ('writer',):git('apply','--index',str(d/(key+'.patch')))
        assert git('write-tree')==pair['original']
        # Save the original tree so the next x86 delta applies only once.
        for variant in ('original','rebased'):
            if variant=='rebased':
                git('apply','--index',str(d/'headers.patch'))
            assert git('write-tree')==pair[variant]
            run(key+'-'+variant,['cmake','--build',b,'--target','compare-abi','--parallel','4'])
            lib,=b.rglob('libcapstone.a');exe=b/'compare-abi'
            objs=[l for l in sp.check_output(['ar','t',lib],text=True).splitlines()if l and not l.startswith('__.SYMDEF')]
            members={n:hashlib.sha256(sp.check_output(['ar','p',lib,n])).hexdigest()for n in objs}
            assert len(members)==len(objs)>30
            run(key+'-'+variant+'-32',[exe]);run(key+'-'+variant+'-64',[exe,'64'])
            flags=json.loads((b/'compile_commands.json').read_text());assert all('CAPSTONE_MIPS_ONLY' not in c['command']for c in flags)
            rows.setdefault(key,{})[variant]=dict(tree=pair[variant],members=members,archive=sha(lib),linked=sha(exe))
        a,z=rows[key].values();assert a['members']==z['members'] and a['linked']==z['linked'],key
        if sys.platform.startswith('linux'):assert a['archive']==z['archive']
        git('read-tree','--reset','-u',pair['original'])
        save('pairs',rows)
    save('checked',dict(complete=True,source=m,pairs=rows,compiler=sp.check_output([os.getenv('CC','cc'),'--version'],text=True).splitlines()[0],system=sys.platform))
finally:
    size=sum(p.stat().st_size for p in t.rglob('*') if p.is_file()and not p.is_symlink());shutil.rmtree(t);save('identity-cleanup',dict(bytes=size,removed=not t.exists()))
