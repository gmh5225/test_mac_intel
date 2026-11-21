"""Compare real ELF library functions at common boundaries with current forked iced."""
from pathlib import Path
import gzip, os, shlex, platform, hashlib, importlib.util, json, math, shutil, statistics, subprocess as sp, tempfile
from layout import linked_layout
r=Path(__file__).resolve().parent
p=r.parent
base=p/'source'
lab=r; evidence=p/'evidence'; evidence.mkdir()
pe=p/'round118-real-pe'

def save(name,data):
    (evidence/name).write_text(json.dumps(data,indent=2)+'\n')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def run(args,label,cwd=None):
    with (evidence/(label+'.log')).open('w') as f:sp.run(args,cwd=cwd,stdout=f,stderr=sp.STDOUT,check=True)
def module(path):
    spec=importlib.util.spec_from_file_location(path.stem,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def main(w):
    reference=json.loads((r/'experiment.json').read_text())['baseline_commit']
    assert sp.check_output(['git','-C',base,'rev-parse',reference],text=True).strip()==reference
    iced=json.loads((r/'experiment.json').read_text())['iced_revision']
    checkout=w/'iced';checkout.mkdir();tar=w/'iced.tar'
    run(['git','init','--bare',w/'iced-git'],'iced-repo');run(['git','-C',w/'iced-git','fetch','--depth','1','https://github.com/NeverSight/iced.git',iced],'iced-fetch');run(['git','-C',w/'iced-git','archive','--format=tar','-o',tar,iced,'src/rust/iced-x86'],'iced-archive');run(['tar','-xf',tar,'-C',checkout],'iced-extract');tar.unlink()
    ad=w/'adapter';ad.mkdir();src=(lab/'iced.rs').read_text().replace('repeats: u32,\n    output:', 'repeats: u32,\n    ip: u64,\n    output:').replace('bytes, 0x100000,','bytes, ip,').replace('set_ip(0x100000 +','set_ip(ip +')
    src=src.replace('InstructionInfoFactory, IntelFormatter,','InstructionInfoFactory, IntelFormatter, FastFormatter,').replace('    formatter: IntelFormatter,','    formatter: IntelFormatter,\n    fast: FastFormatter,\n    fast_enabled: bool,').replace('        mode,','        mode: mode & 3,\n        fast_enabled: mode & 8 != 0,\n        fast: FastFormatter::new(),')
    old='state.formatter.format(&instruction, &mut state.text);';assert src.count(old)==1;src=src.replace(old,'if state.fast_enabled {state.fast.format(&instruction, &mut state.text);} else {state.formatter.format(&instruction, &mut state.text);}')
    src=src.replace('mode: mode & 3,','mode: mode & 7,')
    src='extern "C" { fn observed_text(a:*const u8,b:*const u8)->u64; fn observed_detail(a:*const std::ffi::c_void,b:*const std::ffi::c_void); }\n'+src
    a=src.index('                result.values = result.values.wrapping_add(\n                    state.text.len()')
    b=src.index('            }\n            if state.mode == 2',a)
    src=src[:a]+'                if state.mode >= 5 {\n                    let text = if state.text.is_empty() { b"\\0".as_ptr() } else { state.text.as_ptr() };\n                    result.values = result.values.wrapping_add(observed_text(text,text));\n                } else {\n'+src[a:b]+'                }\n'+src[b:]
    src=src.replace('            if state.mode == 2 {','            if state.mode == 6 {\n                let info = state.factory.info(&instruction);\n                observed_detail((info as *const iced_x86::InstructionInfo).cast(), (&instruction as *const iced_x86::Instruction).cast());\n            } else if state.mode == 2 {')
    trace=(r/'iced-trace.rs').read_text().replace('iced_trace(input:', 'iced_trace(bits:u32,input:').replace('with_ip(64,','with_ip(bits,');(ad/'iced.rs').write_text(src+trace);shutil.copyfile(lab/'Cargo.lock',ad/'Cargo.lock')
    (ad/'Cargo.toml').write_text('[package]\nname="iced_compare"\nversion="0.1.0"\nedition="2021"\n[lib]\ncrate-type=["staticlib"]\npath="iced.rs"\n[dependencies]\niced-x86={path="../iced/src/rust/iced-x86",default-features=false,features=["std","decoder","intel","instr_info","fast_fmt"]}\n[profile.release]\npanic="abort"\nopt-level=3\n');run(['cargo','build','--locked','--release'],'iced-build',ad)
    save('cpu.json',dict(cpu=Path('/proc/cpuinfo').read_text(),compiler=sp.check_output([os.environ['CC'],'--version'],text=True)))
    save('iced-source.json',dict(revision=iced,source='https://github.com/NeverSight/iced.git',built_from_source=True,adapter_source_sha256=sha(ad/'iced.rs'),cargo_lock_sha256=sha(ad/'Cargo.lock')))
    save('entrypoints.json',dict(scan='cs_disasm_iter',format='cs_disasm_iter',detail='cs_disasm_iter',consumer='Public iterator benchmark plus the private static-link text entry called by NeverD; both consume the same output fields'))
    inc=(r/'driver.cpp').read_text().replace('size_t iced_trace(const','size_t iced_trace(unsigned, const').replace('if(argc!=6)','if(argc!=7)').replace('  csh handle=0;','  unsigned bits=std::stoul(argv[6]);\n  csh handle=0;').replace('cs_open(CS_ARCH_X86,CS_MODE_64,','cs_open(CS_ARCH_X86,bits==32?CS_MODE_32:CS_MODE_64,').replace('iced_create(64,mode)','iced_create(bits,mode)').replace('iced_trace(ptr,','iced_trace(bits,ptr,')
    inc=inc.replace('iced_create(bits,mode)','iced_create(bits,mode | (engine=="fast" ? 8 : 0))').replace('engine!="capstone" && engine!="iced"','engine!="capstone" && engine!="iced" && engine!="fast"')
    inc=inc.replace('if (mode>2 ||','if (mode>4 ||').replace('mode==2 ? CS_OPT_ON','mode>=2 ? CS_OPT_ON')
    inc=inc.replace('if (mode == 2) {','if (mode == 2 || mode == 4) {\n        if (mode == 2) {').replace('        const auto &x = insn->detail->x86;', '        }\n        const auto &x = insn->detail->x86;')
    old_engine='std::string engine=argv[1];';assert inc.count(old_engine)==1
    inc=inc.replace(old_engine,old_engine+'\n  if(engine=="iced____") engine="iced"; else if(engine=="fast____") engine="fast";')
    inc='#include "arch/X86/X86ScanAdapter.h"\n'+inc
    inc=inc.replace('static Result cs_span(', 'template <auto Next>\nstatic Result cs_span(')
    inc=inc.replace('bool ok = cs_disasm_iter(handle, &cursor, &left, &ip, insn);','bool ok = Next(handle, &cursor, &left, &ip, insn);')
    branch='if(engine=="capstone") row=cs_span(bytes.data()+f.offset,f.size,handle,insn,f.ip,mode);'
    assert inc.count(branch)==1
    inc=inc.replace(branch,'if(engine=="capstone") row=cs_span<cs_disasm_iter>(bytes.data()+f.offset,f.size,handle,insn,f.ip,mode);\n        else if(engine=="x86_iter") row=cs_span<X86_disasmIter>(bytes.data()+f.offset,f.size,handle,insn,f.ip,mode);')
    inc=inc.replace('engine!="capstone" &&','engine!="capstone" && engine!="x86_iter" &&')
    assert inc.count('iced_trace(bits,ptr,')==1
    sinks='''extern "C" __attribute__((noinline)) uint64_t observed_text(const unsigned char *a,const unsigned char *b) {
        __asm__ volatile("" : : "r"(a),"r"(b) : "memory");
        return a[0];
    }
    extern "C" __attribute__((noinline)) void observed_detail(const void *a,const void *b) {
        __asm__ volatile("" : : "r"(a),"r"(b) : "memory");
    }
'''
    inc=inc.replace('struct Result {',sinks+'\nstruct Result {').replace('mode>4','mode>6').replace('mode>=2 ? CS_OPT_ON','(mode==2 || mode==6) ? CS_OPT_ON')
    site='      if (mode) {\n        text_value(result, insn->mnemonic);'
    assert inc.count(site)==1
    inc=inc.replace(site,'''      if (mode >= 5) {
        result.values += observed_text(reinterpret_cast<const unsigned char *>(insn->mnemonic),reinterpret_cast<const unsigned char *>(insn->op_str));
        if (mode==6) observed_detail(insn,insn->detail);
      } else if (mode) {
        text_value(result, insn->mnemonic);''')
    (w/'functions.cpp').write_text(inc);run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',w/'functions.cpp','-o',w/'driver.o'],'driver')
    profile=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+os.environ['CC'],'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+arch+'_SUPPORT=ON' for arch in ['X86','ARM','AARCH64','MIPS']],'-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer '+('-Wno-error=discarded-qualifiers' if os.environ['CC']=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON']
    data=json.loads((r/'experiment.json').read_text())
    b=w/'build';exe={}
    run(['cmake','-S',base,'-B',b,*profile],'configure')
    obj=w/'driver.o'
    assert 'cs_disasm_iter' in sp.check_output(['nm','-u',obj],text=True)
    save('consumer-object.json',dict(sha256=sha(obj)))
    assert sp.check_output(['git','-C',base,'write-tree'],text=True).strip()==data['baseline_tree']
    run(['cmake','--build',b,'--parallel','4','--target','capstone_static'],'build')
    target=w/'engines';run(['clang++',obj,b/'libcapstone.a',ad/'target/release/libiced_compare.a','-lpthread','-ldl','-lm','-o',target],'link')
    bind=['setarch',platform.machine(),'-R'];sp.run([*bind,'/bin/true'],check=True)
    image_sha=sha(target);save('image.json',dict(sha256=image_sha,tree=data['baseline_tree'],affinity=sorted(os.sched_getaffinity(0)),fixed_aslr=True))
    import frozen_deb as deb
    run(['clang++','-O2','-I',base/'include',r/'vectors.cpp',b/'libcapstone.a','-o',w/'vectors'],'vectors');reported=[];manifest={}
    import pe_panels,itertools
    shutil.copyfile(r/'libmvec.py',w/'libmvec.py');shutil.copyfile(r/'libmvec.json',w/'libmvec.json')
    run(['python3','-B',w/'libmvec.py'],'glibc')
    glibc=json.loads((w/'libmvec.json').read_text())
    extra=[('libmvec-amd64',64,w/'libmvec.text',[(0,glibc['bytes'],glibc['address'])],glibc)]
    for name,bits,f,spans,source in itertools.chain(deb.prepare(w),pe_panels.prepare(w),extra):
        if name not in data['samples']:continue
        panel=data['samples'][name]
        intervals=w/(name+'.tsv')
        intervals.write_text(''.join('%d %d %d\n'%v for v in spans))
        audit=sp.check_output([target,'audit','0','1',f,intervals,str(bits)],text=True)
        trace=[list(map(int,z.split())) for z in audit.splitlines()]
        views=[list(map(int,x.split())) for x in sp.check_output([w/'vectors',str(bits),f,intervals],text=True).splitlines()]
        assert len(views)==len(spans)==len(trace)
        common=[(a[:3],v) for a,v in zip(trace,views) if a[1]==a[5]]
        selected=[a for a,v in common if panel!='simd-functions' or (v[1]>=8 and v[1]>=.15*v[0])]
        if panel=='whole-text':assert len(selected)==1 and selected[0][1]==f.stat().st_size,(name,trace[:1])
        assert selected
        intervals.write_text(''.join('%d %d %d\n'%tuple(a) for a in selected))
        sel=selected
        manifest[name]=dict(source=source,input_functions=len(spans),common_functions=len(common),timed_functions=len(sel),bytes=sum(v[1] for v in sel),selection=panel,extent_sha256=sha(intervals),text_sha256=sha(f),excluded_incompatible_extents=[a for a in trace if a[1]!=a[5]])
        save('provenance.json',manifest)
        for label,full,opaque in [('format',1,5),('detail',2,6)]:
            work={e+'/'+m:(e,k) for e in ['capstone','x86_iter','iced____','fast____']for m,k in [('fields',full),('opaque',opaque)]}
            work['private-copy']=('x86_iter',full);work['fast-copy']=('fast____',full)
            def measure(e,k,reps):return list(map(int,sp.check_output([*bind,target,e,str(k),str(reps),f,intervals,str(bits)]).split()))
            cal=measure('x86_iter',full,1);reps=max(1,math.ceil(35e6/max(1,cal[0])))
            circles=[];sigs={}
            for i in range(data['cycles']):
                keys=list(work);keys=keys[i%len(keys):]+keys[:i%len(keys)];v={k:[]for k in work}
                for k in keys+keys[::-1]:
                    q=measure(*work[k],reps);assert len(q)==6 and q[0]>0
                    v[k].append(q);sigs.setdefault(k,q[2:]);assert q[2:]==sigs[k]
                assert len({tuple(q[:3])for q in sigs.values()})==1
                for typ in ('fields','opaque'):assert sigs['capstone/'+typ]==sigs['x86_iter/'+typ]
                assert sigs['private-copy']==sigs['x86_iter/fields'] and sigs['fast-copy']==sigs['fast____/fields']
                circles.append(v)
            reported.append(dict(case=name,mode=label,functions=len(sel),bytes=sum(z[1]for z in sel),reps=reps,rows=sigs,cycles=circles))
            save('measurements.json',reported)
    assert len(reported)==2*len(data['samples']) and sha(target)==image_sha
    save('complete.json',dict(cases=len(reported),success=True,image=image_sha,source_tree=data['baseline_tree']))
w=Path(tempfile.mkdtemp(prefix='capstone-vex32-iced-'))
try:
    if hasattr(os,'sched_setaffinity'): os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    main(w)
finally:
    files=[v for v in w.rglob('*') if v.is_file()];amount=sum(v.stat().st_size for v in files);shutil.rmtree(w);save('cleanup.json',dict(removed=not w.exists(),bytes=amount,files=len(files)))
