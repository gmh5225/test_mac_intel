from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;local=len(sys.argv)>1
out=r if local else r.parent/'evidence';out.mkdir(exist_ok=True)
def rd(f):return json.loads(f.read_text())
def sv(k,v):(out/(k+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(args,label,ok=True):
    with (out/(label+'.log')).open('w')as f:z=sp.run(args,stdout=f,stderr=sp.STDOUT)
    if ok and z.returncode:print((out/(label+'.log')).read_text()[-1400:]);z.check_returncode()
    return z.returncode
q=rd(r/'tree.json');tmp=Path(tempfile.mkdtemp(dir=r if local else None));cc=os.environ.get('CC','cc')
try:
    s=tmp/'src'if local else r.parent/'source';b=tmp/'b'
    if local:
        run(['git','clone','--quiet','--shared','--no-checkout',next(r.parent.glob('round579-*'))/'source',s],'clone');run(['git','-C',s,'checkout','--quiet','--detach',q['parent']],'checkout')
    g=lambda *a:sp.check_output(['git','-C',s,*a],text=True).strip()
    assert g('rev-parse','HEAD')==q['parent'] and hashlib.sha256((r/'candidate.patch').read_bytes()).hexdigest()==q['sha256']
    records={}
    for stage in ('base','candidate'):
        if stage=='candidate':g('apply','--index',str(r/'candidate.patch'));assert g('write-tree')==q['tree']
        status={}
        archs=['arch/RISCV/RISCVLinkage.h','arch/Mips/MipsLinkage.h']
        for name,headers,src in [('riscv-first',archs,''),('mips-first',archs[::-1],''),('raw',['arch/RISCV/RISCVDisassembler.h','MCDisassembler.h','SStream.h'],'''typedef DecodeStatus (*RiscVD)(MCInst *, uint16_t *, const uint8_t *, size_t, uint64_t, SStream *);
_Static_assert(_Generic(&RISCV_getInstruction, RiscVD: 1, default: 0), "RISC-V raw decoder signature");''')]:
            probe=tmp/(name+'.c');code='\n'.join('#include "'+n+'"' for n in headers)+'\n'
            if name!='raw':src='void test(void) { (void)&Mips_LLVM_getInstruction; (void)&RISCV_LLVM_getInstruction; }'
            probe.write_text(code+src+'\n');status[name]=run([cc,'-std=c11','-I',s,'-I',s/'include','-fsyntax-only',probe],stage+'-'+name,False)
            assert (status[name]!=0)==(stage=='base'),(name,status)
        flags=[] if local else ['-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers')]
        run(['cmake',*flags,'-G','Ninja','-S',s,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_RISCV_SUPPORT=ON','-DCAPSTONE_MIPS_SUPPORT=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON'],'configure-'+stage)
        units=['riscv_op_count_iter','riscv_instruction_groups','riscv_reg_access','mips_single','mips_scan']
        run(['cmake','--build',b,'--parallel','4','--target','capstone_static',*units],'build-'+stage);run(['ctest','--test-dir',b,'--no-tests=error','-R','^unit_('+'|'.join(units)+')$','--output-on-failure'],'tests-'+stage)
        lib=b/'libcapstone.a';members={n:hashlib.sha256(sp.check_output(['ar','p',lib,n])).hexdigest()for n in sp.check_output(['ar','t',lib],text=True).splitlines() if n and not n.startswith('__.SYM')}
        records[stage]=dict(members=members,tests=units,probes=status)
    sv('member-comparison',records)
    names=set(records['base']['members'])
    assert {'RISCVDisassembler.c.o','RISCVModule.c.o','MipsDisassembler.c.o','cs.c.o'}<=names
    assert records['base']['members']==members,[(n,records['base']['members'].get(n),members.get(n))for n in sorted(names|members.keys())if records['base']['members'].get(n)!=members.get(n)]
    sv('local-review'if local else 'checked',dict(complete=True,source=q,records=records))
finally:
    volume=sum(f.stat().st_size for f in tmp.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(tmp);sv('source-cleanup',dict(removed=not tmp.exists(),bytes=volume))
