from pathlib import Path
import collections,contextlib,hashlib,json,os,platform,shutil,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;p=r.parent;e=p/'evidence';e.mkdir(exist_ok=True)
src=p/'source';iced=p/'iced-source';dev=p/'neverd-config';q=json.loads((r/'sources.json').read_text())
def get(*args):return sp.check_output(args,text=True).strip()
def run(*a,**kw):sp.run(a,check=True,**kw)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(k,z):(e/(k+'.json')).write_text(json.dumps(z,indent=2)+'\n')
def git(*a):return get('git','-C',src,*a)
assert git('rev-parse','HEAD')==q['checkout'] and get('git','-C',iced,'rev-parse','HEAD')==q['iced'] and get('git','-C',dev,'rev-parse','HEAD')==q['neverd']
t=Path(tempfile.mkdtemp());inputs=t/'inputs';records={}
try:
    for bits in (16,32,64):
        for f in sorted((iced/'src/UnitTests/Intel/Decoder').glob('DecoderTest*'+str(bits)+'.txt')):
            for line in f.read_text().splitlines():
                if not line.strip() or line.startswith('#'):continue
                raw=bytes.fromhex(line.split(',',1)[0]);assert len(raw)<=63
                records[(bits,raw.hex())]=f.name
    for bits in (16,32):
        for bank in ('0f','0f38','0f3a'):
            for op in range(256):
                for p in ('66','6667','66f2','f266','66f3','f366',''):
                    for mr in (0x03,0x44,0x83,0xc0,0xc9,0xd3,0xe0,0xff):
                        raw=(p+bank+f'{op:02x}{mr:02x}'+'39'*12)[:30]
                        records.setdefault((bits,raw),'prefix-grid')
    for bits in (16,32,64):
        for op in ('6e','6f','7e','7f','d6'):
            for prefix in ('','66','6666','6766','6667','6466','6664','66f2','f266','66f3','f366','f2','f3'):
                for modrm in range(256):
                    raw=prefix+'0f'+op+format(modrm,'02x')+'a5393939393939'
                    for length in range(len(prefix)//2+2,min(15,len(raw)//2)+1):
                        records.setdefault((bits,raw[:2*length]),'integer-move-domain')
    for bits in (16,32,64):
        for op in ('78','79'):
            for prefix in (('66','6667','6766','f2','f3','') + (('6640','6641','6644','6648','664c','664f','4066') if bits==64 else ())):
                for mr in range(256):
                    raw=prefix+'0f'+op+f'{mr:02x}'+'041408202040'
                    for end in range(len(prefix)//2+2,len(raw)//2+1):
                        records.setdefault((bits,raw[:2*end]),'extrq-encoding')
    with inputs.open('w')as f:
        for bits,raw in records:print(bits,raw or "-",file=f)
    assert len(records)==651593;official=len(records)
    for bits in (16,32,64):
        for pred in range(256):
            for mr in ('d0','10'):
                for pp in range(4):
                    for prefix in ('c5'+format(0xe8|pp,'02x'),'c4e1'+format(0x68|pp,'02x')):
                        records.setdefault((bits,prefix+'c2'+mr+format(pred,'02x')),'vex-fp')
                for ll in (0x08,0x28,0x48):
                    for mask in (0,3):
                        p2=format(ll|mask,'02x')
                        for pp in range(4):
                            p1=(0x6c|pp)|(0x80 if pp in (1,3) else 0)
                            records.setdefault((bits,'62f1'+format(p1,'02x')+p2+'c2'+mr+format(pred,'02x')),'evex-fp')
                        for op in ('1e','1f','3e','3f'):
                            for wbit in (0x6d,0xed):
                                records.setdefault((bits,'62f3'+format(wbit,'02x')+p2+op+mr+format(pred,'02x')),'evex-int')
    with inputs.open('w')as f:
        for bits,raw in records:print(bits,raw or '-',file=f)
    save('inputs',dict(cases=len(records),official=official,sha256=sha(inputs),iced=q['iced']))
    a=t/'ice';a.mkdir();shutil.copyfile(r/'oracle.rs',a/'iced.rs')
    (a/'Cargo.toml').write_text('[package]\nname="check"\nversion="0.1.0"\nedition="2021"\n[[bin]]\nname="check"\npath="iced.rs"\n[dependencies]\niced-x86={path="'+str(iced/'src/rust/iced-x86')+'",default-features=false,features=["std","decoder","instr_info"]}\n')
    run('cargo','build','--release','--manifest-path',a/'Cargo.toml')
    def capture(exe,path,*args):
        with inputs.open('rb')as inp,path.open('wb')as out:run(exe,*args,stdin=inp,stdout=out)
    capture(a/'target/release/check',t/'oracle')
    project=t/'product';build=t/'build';(project/'third_party').mkdir(parents=True);(project/'third_party/capstone').symlink_to(src);(project/'cmake').mkdir()
    cm='cmake/NeverDCapstoneCompilerOptions.inc';(project/cm).write_bytes(sp.check_output(['git','-C',dev,'show',q['neverd']+':'+cm]))
    cmake=get('git','-C',dev,'show',q['neverd']+':CMakeLists.txt')
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Grid LANGUAGES C CXX)\n'+cmake[cmake.index('# --- Capstone (our fork'):cmake.index('# --- NeverD CMake helpers')])
    run('cmake','-S',project,'-B',build,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
    verdict={}
    for label in ('base','candidate','record'):
        git('restore','--source','HEAD','--staged','--worktree','--','.')
        if label!='base':git('apply','--index',r/(label+'.patch'))
        assert git('write-tree')==q[label]['tree']
        run('cmake','--build',build,'--target','capstone_static','--parallel','4');lib,=build.rglob('libcapstone.a')
        objects={Path(c['file']).name for c in json.loads((build/'compile_commands.json').read_text())};assert {'MipsMapping.c','AArch64Mapping.c','ARMMapping.c','X86Sse64Output.c'}<=objects
        for exe,code in [('cap','cap.cpp'),('scan','corpus-scan.cpp')]:
            run('clang++','-O2','-std=c++17','-I',src,'-I',src/'include',r/code,lib,'-o',t/exe);capture(t/exe,t/(label+'-'+exe))
        capture(t/'cap',t/(label+'-bulk'),'bulk')
        if label=='base':continue
        groups=collections.Counter();errors=[];by_mode=collections.Counter();kept=collections.Counter()
        paths=('base-cap','base-bulk',label+'-cap',label+'-bulk','base-scan',label+'-scan','oracle')
        with contextlib.ExitStack()as opened:
            lines=[opened.enter_context((t/f).open())for f in paths]
            for ((bits,raw),origin),*v in zip(records.items(),*lines,strict=True):
                before,bulk,now,current,bs,cs,oracle=[l.strip()for l in v]
                bx,bm,oldscan=map(int,bs.split());cx,cm,newscan=map(int,cs.split())
                def record_problem(reason):
                    groups['errors']+=1
                    if len(errors)<25:errors.append([reason,bits,raw,origin,before,bulk,now,current,bs,cs,oracle])
                families=('vpcmpb','vpcmpub','vpcmpw','vpcmpuw','vpcmpd','vpcmpud','vpcmpq','vpcmpuq')
                if bx!=cx or before!=now or bulk!=current:record_problem('changed-printed-record')
                if before!=bulk:groups['old-iterator-bulk']+=1
                if bm:groups['old-scan']+=1
                if oldscan!=newscan or bm!=cm:
                    by_mode[str(bits)+'/'+origin]+=1
                    if before=='-' or before.split()[1] not in families or not bm or cm or newscan!=(cx>>8) or before!=bulk:record_problem('invalid-scan-correction')
                    else:groups['corrected-integer-scan']+=1
                if cm:
                    if before==bulk or current=='-' or current.split()[1] not in ('vcmp','vcmpsd','vcmpss','vcmpps','vcmppd') or oldscan!=newscan or bm!=cm:record_problem('unexpected-surviving-mismatch')
                    groups['inherited-floating']+=1
                if origin.startswith(('vex-','evex-')) and current!='-' and oracle!='-':
                    oplen,op=oracle.split()[:2];render=current.split()
                    if render[0]!=oplen:record_problem('oracle-length')
                    if origin=='evex-int' and render[1]!=op:record_problem('integer-family')
                    if origin.endswith('-fp') and render[1] not in ('vcmp',op):record_problem('floating-family')
                    kept[op]+=1
                if origin.startswith('DecoderTest') and bm:groups['original-corpus-differences']+=1
        proof=dict(cases=len(records),groups=groups,examples=errors,changed=by_mode,iced_overlap=kept)
        save('case-proof-'+label,proof);assert not errors and groups['corrected-integer-scan']==1738 and groups['old-iterator-bulk']==groups['inherited-floating']==22414 and len(kept)==12,proof
        verdict[label]=proof
    assert verdict['candidate']==verdict['record']
    save('complete',dict(source=q,host=platform.platform(),proof=verdict['candidate']))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(bytes=n,removed=not t.exists()))
