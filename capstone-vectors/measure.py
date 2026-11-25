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
m=read(r/'layout-source.json');q=m['candidate']
assert get('git','-C',src,'rev-parse','HEAD')==q['parent'] and get('git','-C',nd,'rev-parse','HEAD')==m['neverd']
assert sig(r/'layout.patch')==q['sha256']
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
    local_names=set(m['possible_objects'])
    versions={};archives={};objects={}
    ar=shutil.which('llvm-ar') or shutil.which('ar')
    objcopy=shutil.which('llvm-objcopy') or shutil.which('objcopy')
    for v in ('base','candidate'):
        tag=q if v=='candidate' else m['reference']
        patch=r/('layout.patch' if v=='candidate' else 'baseline.patch')
        assert sig(patch)==tag['sha256']
        run('git','-C',src,'reset','--hard',q['parent'])
        run('git','-C',src,'apply','--index',patch);assert get('git','-C',src,'write-tree')==tag['tree']
        run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        orig,=build.rglob('libcapstone.a');dest=versions[v]=w/('obj-'+v);dest.mkdir()
        lib=archives[v]=dest/'libcapstone.a';shutil.copyfile(orig,lib)
        objects[v]={str(x.relative_to(build)):sig(x) for x in build.rglob('*.c.o')}
        for member in sorted(local_names):
            matches=list(build.rglob(member))
            if not matches:continue
            obj,=matches;shutil.copy2(obj,dest/member)
            assert sp.check_output([ar,'p',lib,member])==obj.read_bytes()
    ch=[Path(k).name for k in objects['base'] if objects['base'][k]!=objects['candidate'][k]]
    required={'cs.c.o','X86ATTInstPrinter.c.o','X86OutputIterator.c.o','X86VectorOutput.c.o','X86ImmediateOutput.c.o'}
    assert required <= set(ch) <= local_names,ch
    other,script=plan(versions,archives,w,ar,objcopy,sorted(ch))
    def link(bin,lib,controlled):
        mapfile=bin.with_suffix('.map')
        args=['clang++',w/'driver.o','-no-pie','-fuse-ld=bfd','-Wl,-Map,'+str(mapfile)]
        if controlled:
            args+=['-Wl,--whole-archive',lib,'-Wl,--no-whole-archive','-Wl,-T,'+str(script)]
        else:args.append(lib)
        run(*args,'-o',bin)
        members=sorted(set(re.findall(re.escape(str(lib))+r'\(([^()\n]+\.o)\)',mapfile.read_text())))
        assert members,(lib,mapfile)
        return members
    original=script.read_text()
    anchors={}
    for group in ('exec','const','write','zero'):
        section='.csprobe_'+group
        if section+' : ALIGN' not in original:continue
        positions=[]
        for tag,lib in other.items():
            exe=w/('bounds-'+tag);link(exe,lib,True)
            with exe.open('rb')as stream:positions.append(ELFFile(stream).get_section_by_name(section)['sh_addr'])
        anchor=(max(positions)+4095)&~4095
        spec=script.read_text();mark=section+' : ALIGN(64)';assert spec.count(mark)==1
        script.write_text(spec.replace(mark,section+' '+hex(anchor)+' : ALIGN(64)'))
        anchors[section]=anchor
    (e/'diagnostic.ld').write_bytes(script.read_bytes())
    closure={}

    cases=training.fetch(r,w)
    for name,bits,f,spans,meta in pe_panels.prepare(w):
        assert bits in (32,64) and spans
        bases={base-off for off,_,base in spans};assert len(bases)==1
        cases.append(dict(name=name,arch='i386' if bits==32 else 'amd64',address=bases.pop(),text_sha256=sig(f),bytes=f.stat().st_size))
    assert len(cases)==7;save('corpus',cases)
    hot=['cs_disasm_iter','cs_decode_full_insn','X86_getInstruction','X86_ATT_printInst','X86_Intel_printInst','RISCV_getInstruction','ARM_getInstruction','AArch64_getInstruction','Mips_getInstruction','PPC_getInstruction']
    stamps={};addresses={};bins={}
    for kind,libs in [('regular',archives),('controlled',other)]:
        for v,lib in libs.items():
            tag=kind+'-'+v;exe=w/tag
            closure[tag]=link(exe,lib,kind=='controlled')
            sy,sec=symbols(exe);assert set(hot)<=sy.keys(),sy.keys()
            stamps[tag]=dict(hot={n:sy[n]for n in hot},sections=sec,sha256=sig(exe))
            if kind=='controlled':
                with exe.open('rb')as stream:
                    symtab=ELFFile(stream).get_section_by_name('.symtab')
                    stamps[tag]['slots']={a.name:a['st_value'] for a in symtab.iter_symbols() if a.name.startswith('csprobe_') and a.name.endswith(('_start','_end'))}
                assert len(stamps[tag]['slots'])>=8
            addresses[tag]=sy;bins[tag]=exe.read_bytes()
        ref=kind+'-base';cand=kind+'-candidate'
        common=addresses[ref].keys() & addresses[cand].keys()
        stamps[cand].update(equal_address=sum(addresses[ref][f][0]==addresses[cand][f][0]for f in common),
                             equal_address_and_bytes=sum(addresses[ref][f]==addresses[cand][f] for f in common),unique_functions=len(common))
    controlled=stamps['controlled-base']['sections']
    slots=[s for s in controlled if s.startswith('.csprobe_')]
    assert {'.csprobe_exec','.csprobe_const'}<=set(slots) and all(controlled[s][1]==stamps['controlled-candidate']['sections'][s][1]for s in slots)
    assert closure['controlled-base']==closure['controlled-candidate']==sorted(get(ar,'t',archives['base']).splitlines()),closure
    ends=stamps['controlled-base']['slots'];diff={k:v-stamps['controlled-candidate']['slots'][k]for k,v in ends.items()if v!=stamps['controlled-candidate']['slots'][k]}
    assert not diff,diff
    for k,p in anchors.items():assert controlled[k][0]==stamps['controlled-candidate']['sections'][k][0]==p
    save('archive-closure',dict(members=closure,anchors=anchors,script=sig(script),new=sorted(set(closure['regular-candidate'])-set(closure['regular-base'])),removed=sorted(set(closure['regular-base'])-set(closure['regular-candidate']))))
    save('layout',dict(objects=ch,syms=stamps,driver_sha=sig(w/'driver.cpp'),script=sig(script),source=m))
    length=max(map(len,bins.values()));bins={k:v.ljust(length,b'\0')for k,v in bins.items()}
    for kind in ['regular','controlled']:bins[kind+'-duplicate']=bins[kind+'-base']
    path=w/'selected';path.write_bytes(bins['regular-base']);path.chmod(0o755);inode=path.stat().st_ino
    checked={};changes={}
    for prev in bins:
        for cur in bins:
            changes[prev,cur]=[p for p in range(0,length,4096) if bins[prev][p:p+4096]!=bins[cur][p:p+4096]]
    previous=['regular-base']
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
            reps=max(1,math.ceil(20e6/once(row,'regular-base',mode,1)[0]))
            expected=once(row,'regular-base',mode,reps)[2:];assert expected[0]>0
            assert all(once(row,k,mode,reps)[2:]==expected for k in bins)
            rng=random.Random(row['name']+str(mode));labels=list(bins);cycles=[]
            for _ in range(17):
                rng.shuffle(labels);times={k:[] for k in labels}
                for k in labels+labels[::-1]:
                    v=once(row,k,mode,reps);assert v[2:]==expected,(row['name'],k,mode)
                    times[k].append(v[:2])
                cycles.append({k:[a+b for a,b in zip(*xs)] for k,xs in times.items()})
            results[row['name']+'/'+str(mode)]=dict(reps=reps,output=expected,pairs=cycles)
            save('pairs',results)
    assert len(checked)==6 and len(results)==25
    save('complete',dict(complete=True,source=m,checks=checked,inode=inode,compiler=get('clang','--version'),host=platform.machine()))
finally:
    size=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink())
    shutil.rmtree(w);save('cleanup',dict(bytes=size,removed=not w.exists()))
