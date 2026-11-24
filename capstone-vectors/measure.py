from pathlib import Path
import collections,contextlib,hashlib,json,os,platform,shutil,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;p=r.parent;e=p/'evidence';e.mkdir(exist_ok=True)
src=p/'source';iced=p/'iced-source';dev=p/'neverd-config';q=json.loads((r/'sources.json').read_text())
def get(*args):return sp.check_output(args,text=True).strip()
def run(*a,**kw):sp.run(a,check=True,**kw)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(k,z):(e/(k+'.json')).write_text(json.dumps(z,indent=2)+'\n')
def git(*a):return get('git','-C',src,*a)
assert git('rev-parse','HEAD')==q['baseline'] and get('git','-C',iced,'rev-parse','HEAD')==q['iced'] and get('git','-C',dev,'rev-parse','HEAD')==q['neverd']
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
    assert len(records)==651593;save('inputs',dict(cases=len(records),sha256=sha(inputs),iced=q['iced']))
    a=t/'ice';a.mkdir();shutil.copyfile(r/'oracle.rs',a/'iced.rs')
    (a/'Cargo.toml').write_text('[package]\nname="check"\nversion="0.1.0"\nedition="2021"\n[[bin]]\nname="check"\npath="iced.rs"\n[dependencies]\niced-x86={path="'+str(iced/'src/rust/iced-x86')+'",default-features=false,features=["std","decoder","instr_info"]}\n')
    run('cargo','build','--release','--manifest-path',a/'Cargo.toml')
    def capture(exe,path):
        with inputs.open('rb')as inp,path.open('wb')as out:run(exe,stdin=inp,stdout=out)
    capture(a/'target/release/check',t/'oracle')
    project=t/'product';build=t/'build';(project/'third_party').mkdir(parents=True);(project/'third_party/capstone').symlink_to(src);(project/'cmake').mkdir()
    cm='cmake/NeverDCapstoneCompilerOptions.inc';(project/cm).write_bytes(sp.check_output(['git','-C',dev,'show',q['neverd']+':'+cm]))
    cmake=get('git','-C',dev,'show',q['neverd']+':CMakeLists.txt')
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Grid LANGUAGES C CXX)\n'+cmake[cmake.index('# --- Capstone (our fork'):cmake.index('# --- NeverD CMake helpers')])
    run('cmake','-S',project,'-B',build,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
    verdict={}
    for label in ('base','prefix','selector','mask'):
        git('restore','--source','HEAD','--staged','--worktree','--','.')
        if label!='base':
            trial=q[label];patch=r/(label+'.patch');assert sha(patch)==trial['sha256'];git('apply','--index',patch);assert git('write-tree')==trial['tree']
        run('cmake','--build',build,'--target','capstone_static','--parallel','4');lib,=build.rglob('libcapstone.a')
        objects={Path(c['file']).name for c in json.loads((build/'compile_commands.json').read_text())};assert {'MipsMapping.c','AArch64Mapping.c','ARMMapping.c','X86Sse64Output.c'}<=objects
        for exe,code in [('cap','cap.cpp'),('scan','corpus-scan.cpp')]:
            run('clang++','-O2','-std=c++17','-I',src,'-I',src/'include',r/code,lib,'-o',t/exe);capture(t/exe,t/(label+'-'+exe))
        if label in ('base','mask'):
            run('clang','-O2','-DNDEBUG','-DCAPSTONE_HAS_X86','-I',src,'-I',src/'include',r/'mask.c',lib,'-o',t/'private')
            d=hashlib.sha256();size=0
            with sp.Popen([t/'private'],stdout=sp.PIPE,stderr=sp.PIPE)as proc:
                while chunk:=proc.stdout.read(1024*1024):size+=len(chunk);d.update(chunk)
                line=proc.stderr.read().decode().strip();assert proc.wait()==0
            mask=dict(sha256=d.hexdigest(),bytes=size,stats=line)
            if label=='base':original=mask
            assert mask==original and mask['bytes']>1572864*12;save('mask-'+label,mask)
        if label=='base':continue
        with contextlib.ExitStack()as files:
            streams=[files.enter_context((t/f).open()) for f in ('base-cap',label+'-cap','oracle','base-scan',label+'-scan')]
            delta=[];new=collections.Counter();all_errors=[0,0];new_examples=[]
            for ((bits,raw),origin),*values in zip(records.items(),*streams,strict=True):
                before,after,ref,bs,cs=[v.strip()for v in values]
                x,y=map(int,bs.split());j,k=map(int,cs.split())
                all_errors[0]+=bool(y);all_errors[1]+=bool(k)
                if (k & ~y) or (before==after and (x,y)!=(j,k)):
                    if len(new_examples)<12:new_examples.append([bits,raw,bs,cs,before,after])
                    new['added-or-unexplained']+=1
                if before!=after:
                    assert after==ref,(bits,raw,before,after,ref)
                    if k:new['changed-input-scan-disagreement']+=1
                    delta.append([raw,before,after,ref,origin,'fixed',bits])
        actual=hashlib.sha256((json.dumps(delta,indent=2)+'\n').encode()).hexdigest()
        v=dict(records=len(records),changes=len(delta),sha256=actual,scan_disagreements=all_errors,new=new,examples=new_examples)
        save('case-'+label,v);assert not new,v
        assert dict(prefix=62743,selector=3648,mask=0)[label]==len(delta) and actual==q['expected'][label],v
        verdict[label]=v
    save('complete',dict(source=q,host=platform.platform(),cases=len(records),verdict=verdict))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(bytes=n,removed=not t.exists()))
