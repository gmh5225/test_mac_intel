from pathlib import Path
import hashlib,json,math,re,os,platform,random,shutil,subprocess as sp,tempfile
from elf_slots import plan,symbols
from elftools.elf.elffile import ELFFile
import training,pe_panels
r=Path(__file__).resolve().parent
root=r.parent; e=root/'evidence';e.mkdir(exist_ok=True);src=root/'source';nd=root/'neverd-config'
def save(k,z):
    f=e/(k+'.json');t=f.with_suffix('.tmp');t.write_text(json.dumps(z,indent=2)+'\n');t.replace(f)
def read(p):return json.loads(p.read_text())
def run(*args):sp.run(args,check=True)
def get(*args):return sp.check_output(args,text=True).strip()
def sig(p):return hashlib.sha256(p.read_bytes()).hexdigest()
m=read(r/'layout-source.json');q=m['sources']['base']
assert get('git','-C',src,'rev-parse','HEAD')==q['parent'] and get('git','-C',nd,'rev-parse','HEAD')==m['neverd']
assert all(sig(r/(tag+'.patch'))==record['sha256']for tag,record in m['sources'].items())
w=Path(tempfile.mkdtemp());build=w/'build'
try:
    project=w/'project';(project/'third_party').mkdir(parents=True);(project/'third_party/capstone').symlink_to(src);(project/'cmake').mkdir()
    f='cmake/NeverDCapstoneCompilerOptions.inc';(project/f).write_bytes((nd/f).read_bytes())
    cm=(nd/'CMakeLists.txt').read_text()
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Layers LANGUAGES C CXX)\n'+cm[cm.index('# --- Capstone (our fork'):cm.index('# --- NeverD CMake helpers')])
    run('cmake','-G','Ninja','-S',project,'-B',build,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
    driver=(r/'foreign.cpp').read_text()
    driver=driver.replace('argc != 5','argc != 6').replace('  cs_arch arch;','  const uint64_t initial_ip=std::stoull(argv[5]);\n  cs_arch arch;')
    driver=driver.replace('  else if (target == "riscv64")','  else if (target == "i386") { arch = CS_ARCH_X86; mode = CS_MODE_32; }\n  else if (target == "riscv64")')
    driver=driver.replace('uint64_t ip = 0x100000;', 'uint64_t ip = initial_ip;')
    driver=driver.replace('size_t(arch == CS_ARCH_RISCV ? 2 : 4)', 'size_t(arch == CS_ARCH_X86 ? 1 : arch == CS_ARCH_RISCV ? 2 : 4)')
    assert driver.count('initial_ip')==2 and driver.count('target == "i386"')==1
    driver=driver.replace('  else if (target == "i386")','  else if (target == "amd64") { arch = CS_ARCH_X86; mode = CS_MODE_64; }\\n  else if (target == "i386")'.replace('\\n','\n'))
    driver=driver.replace('const unsigned output =','const unsigned setting =').replace('  cs_arch arch;', '  const unsigned output=setting<=2?setting:setting-2;\n  cs_arch arch;')
    driver=driver.replace('  cs_insn *insn =', '  if (setting>2 && (arch!=CS_ARCH_X86 || cs_option(handle,CS_OPT_SYNTAX,CS_OPT_SYNTAX_ATT)!=CS_ERR_OK)) return 7;\n  cs_insn *insn =')
    assert driver.count('setting')==5 and 'CS_OPT_SYNTAX_ATT' in driver
    (w/'driver.cpp').write_text(driver);run('clang++','-std=c++17','-O3','-DNDEBUG','-I',src/'include','-c',w/'driver.cpp','-o',w/'driver.o')
    bins={};layout={};ar=shutil.which('llvm-ar') or shutil.which('ar')
    for tag,record in m['sources'].items():
        run('git','-C',src,'reset','--hard',q['parent'])
        run('git','-C',src,'apply','--index',r/(tag+'.patch'));assert get('git','-C',src,'write-tree')==record['tree']
        run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        lib,=build.rglob('libcapstone.a');binary=w/tag;mapfile=w/(tag+'.map')
        run('clang++',w/'driver.o',lib,'-no-pie','-fuse-ld=bfd','-Wl,-Map,'+str(mapfile),'-o',binary)
        members=sorted(set(re.findall(re.escape(str(lib))+r'\(([^()\n]+\.o)\)',mapfile.read_text())))
        assert len(members)>=40
        symbols_,sections=symbols(binary)
        compile=read(build/'compile_commands.json')
        settings={'fixed_readers':any('CAPSTONE_STATIC_X86_READERS' in cmd['command']for cmd in compile),
                  'fixed_functions':[name for name in ('X86_decodeFixedRecord32','X86_decodeFixedRecord64')if name in symbols_]}
        assert settings['fixed_readers']==(tag=='fixed') and len(settings['fixed_functions'])==(2 if tag=='fixed'else 0),(tag,settings)
        hot=['cs_disasm_iter','cs_decode_full_insn','X86_getInstruction','X86_ATT_printInst','X86_Intel_printInst','RISCV_getInstruction','ARM_getInstruction','AArch64_getInstruction','Mips_getInstruction','PPC_getInstruction']
        layout[tag]=dict(members=members,settings=settings,hot={n:symbols_[n]for n in hot},sections=sections,sha256=sig(binary))
        bins[tag]=binary.read_bytes()
        save('layout',dict(source=m,variants=layout))
    cases=training.fetch(r,w)
    for name,bits,f,spans,meta in pe_panels.prepare(w):
        assert bits in (32,64) and spans
        bases={base-off for off,_,base in spans};assert len(bases)==1
        cases.append(dict(name=name,arch='i386' if bits==32 else 'amd64',address=bases.pop(),text_sha256=sig(f),bytes=f.stat().st_size))
    assert len(cases)==7;save('corpus',cases)
    length=max(map(len,bins.values()));bins={k:v.ljust(length,b'\0')for k,v in bins.items()}
    bins['duplicate']=bins['base']
    path=w/'selected';path.write_bytes(bins['base']);path.chmod(0o755);inode=path.stat().st_ino
    checked={};changes={}
    for prev in bins:
        for cur in bins:
            changes[prev,cur]=[p for p in range(0,length,4096) if bins[prev][p:p+4096]!=bins[cur][p:p+4096]]
    previous=['base']
    def once(row,tag,mode,reps):
        with path.open('r+b',buffering=0)as f:
            for off in changes[previous[0],tag]:
                f.seek(off);b=bins[tag][off:off+4096];assert f.write(b)==len(b)
        previous[0]=tag
        assert path.stat().st_ino==inode
        if tag not in checked:
            checked[tag]=sig(path);assert checked[tag]==hashlib.sha256(bins[tag]).hexdigest()
        args=['setarch',os.uname().machine,'-R',path,row['arch'],w/(row['name']+'.text'),str(mode),str(reps),str(row['address'])]
        return list(map(int,sp.check_output(args,text=True).split()))
    results={}
    for row in cases:
        for mode in (range(5) if row['arch'] in ('amd64','i386') else range(3)):
            reps=max(1,math.ceil(20e6/once(row,'base',mode,1)[0]))
            expected=once(row,'base',mode,reps)[2:];assert expected[0]>0
            for k in bins:
                actual=once(row,k,mode,reps)[2:]
                if actual!=expected:
                    save('semantic-mismatch',dict(sample=row,mode=mode,variant=k,wanted=expected,got=actual));raise ValueError((row['name'],mode,k,expected,actual))
            rng=random.Random(row['name']+str(mode));labels=list(bins);cycles=[]
            for _ in range(17):
                rng.shuffle(labels);times={k:[] for k in labels}
                for k in labels+labels[::-1]:
                    v=once(row,k,mode,reps);assert v[2:]==expected,(row['name'],k,mode)
                    times[k].append(v[:2])
                cycles.append({k:[a+b for a,b in zip(*xs)] for k,xs in times.items()})
            results[row['name']+'/'+str(mode)]=dict(reps=reps,output=expected,pairs=cycles)
            save('pairs',results)
    assert len(checked)==5 and len(results)==25
    save('complete',dict(complete=True,source=m,checks=checked,inode=inode,compiler=get('clang','--version'),host=platform.machine()))
finally:
    size=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink())
    shutil.rmtree(w);save('cleanup',dict(bytes=size,removed=not w.exists()))
