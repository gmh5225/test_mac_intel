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
    reference=json.loads((r/'experiment.json').read_text())['checkout_commit']
    assert sp.check_output(['git','-C',base,'rev-parse',reference],text=True).strip()==reference
    meta=json.loads((r/'experiment.json').read_text())
    assert sp.check_output(['git','-C',base,'write-tree'],text=True).strip()==meta['checkout_tree']
    iced=json.loads((r/'experiment.json').read_text())['iced_revision']
    checkout=w/'iced';checkout.mkdir();tar=w/'iced.tar'
    run(['git','init','--bare',w/'iced-git'],'iced-repo');run(['git','-C',w/'iced-git','fetch','--depth','1','https://github.com/NeverSight/iced.git',iced],'iced-fetch');run(['git','-C',w/'iced-git','archive','--format=tar','-o',tar,iced,'src/rust/iced-x86'],'iced-archive');run(['tar','-xf',tar,'-C',checkout],'iced-extract');tar.unlink()
    ad=w/'adapter';ad.mkdir();src=(lab/'iced.rs').read_text().replace('repeats: u32,\n    output:', 'repeats: u32,\n    ip: u64,\n    output:').replace('bytes, 0x100000,','bytes, ip,').replace('set_ip(0x100000 +','set_ip(ip +')
    src=src.replace('InstructionInfoFactory, IntelFormatter,','InstructionInfoFactory, IntelFormatter, FastFormatter,').replace('    formatter: IntelFormatter,','    formatter: IntelFormatter,\n    fast: FastFormatter,\n    fast_enabled: bool,').replace('        mode,','        mode: mode & 3,\n        fast_enabled: mode & 8 != 0,\n        fast: FastFormatter::new(),')
    old='state.formatter.format(&instruction, &mut state.text);';assert src.count(old)==1;src=src.replace(old,'if state.fast_enabled {state.fast.format(&instruction, &mut state.text);} else {state.formatter.format(&instruction, &mut state.text);}')
    trace=(r/'iced-trace.rs').read_text().replace('iced_trace(input:', 'iced_trace(bits:u32,input:').replace('with_ip(64,','with_ip(bits,');(ad/'iced.rs').write_text(src+trace);shutil.copyfile(lab/'Cargo.lock',ad/'Cargo.lock')
    (ad/'Cargo.toml').write_text('[package]\nname="iced_compare"\nversion="0.1.0"\nedition="2021"\n[lib]\ncrate-type=["staticlib"]\npath="iced.rs"\n[dependencies]\niced-x86={path="../iced/src/rust/iced-x86",default-features=false,features=["std","decoder","intel","instr_info","fast_fmt"]}\n[profile.release]\npanic="abort"\nopt-level=3\n');run(['cargo','build','--locked','--release'],'iced-build',ad)
    save('cpu.json',dict(cpu=(sp.check_output(['sysctl','-n','machdep.cpu.brand_string'],text=True).strip() if platform.system()=='Darwin' else Path('/proc/cpuinfo').read_text()),compiler=sp.check_output([os.environ['CC'],'--version'],text=True)))
    save('iced-source.json',dict(revision=iced,source='https://github.com/NeverSight/iced.git',built_from_source=True,adapter_source_sha256=sha(ad/'iced.rs'),cargo_lock_sha256=sha(ad/'Cargo.lock')))
    save('entrypoints.json',dict(scan='X86_scanNativeBatch with canonical iterator fallback',format='X86_disasmIter32 / X86_disasmIterText',detail='X86_disasmIter32 / X86_disasmIterText',consumer='Public iterator benchmark plus the private static-link text entry called by NeverD; both consume the same output fields'))
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
    weak='extern "C" bool X86_disasmIterText(csh, const uint8_t **, size_t *, uint64_t *, cs_insn *) __attribute__((weak));'
    weak+='\n'+weak.replace('X86_disasmIterText','X86_disasmIter32')
    key='else if(engine=="x86_iter") row=cs_span<X86_disasmIter>'
    assert inc.count(key)==1
    inc=inc.replace('#include "arch/X86/X86ScanAdapter.h"', '#include "arch/X86/X86ScanAdapter.h"\n'+weak)
    inc=inc.replace(key,'else if(engine=="x86_iter" && bits==32 && X86_disasmIter32) row=cs_span<X86_disasmIter32>(bytes.data()+f.offset,f.size,handle,insn,f.ip,mode);\n        else if(engine=="x86_iter" && X86_disasmIterText) row=cs_span<X86_disasmIterText>(bytes.data()+f.offset,f.size,handle,insn,f.ip,mode);\n        '+key)
    head='static Result cs_span('
    anchor='extern "C" size_t iced_trace'
    assert inc.count(anchor)==1;inc=inc.replace(anchor,(r/'batch.inc').read_text()+'\n'+anchor)
    inc=inc.replace('if(engine!="capstone" &&','if(engine!="batch___" && engine!="capstone" &&')
    inc=inc.replace('else iced_run(iced,','else if(engine=="batch___") row=batch_span<false>(bytes.data()+f.offset,f.size,handle,insn,f.ip);\n        else iced_run(iced,')
    line='auto ptr=bytes.data()+f.offset;'
    assert inc.count(line)==1;inc=inc.replace(line,line+'\n      (void)batch_span<true>(ptr,f.size,handle,insn,f.ip);')
    inc=inc.replace('engine!="batch___" &&','engine!="vecbatch" && engine!="batch___" &&')
    anchor='else if(engine=="batch___") row=batch_span<false>'
    assert inc.count(anchor)==1;inc=inc.replace(anchor,'else if(engine=="vecbatch" && X86_scanBatch32) row=batch_span<false,X86_scanBatch32>(bytes.data()+f.offset,f.size,handle,insn,f.ip);\n        '+anchor)
    anchor='(void)batch_span<true>(ptr,f.size,handle,insn,f.ip);'
    assert inc.count(anchor)==1;inc=inc.replace(anchor,anchor+'\n      if(X86_scanBatch32)(void)batch_span<true,X86_scanBatch32>(ptr,f.size,handle,insn,f.ip);')
    inc=inc.replace('engine=="vecbatch" && X86_scanBatch32','engine=="vecbatch" && bits==32 && X86_scanBatch32').replace('else if(engine=="batch___") row=batch_span<false>', 'else if(engine=="batch___" || engine=="vecbatch") row=batch_span<false>')
    anchor='else if(engine=="vecbatch" && bits==32 && X86_scanBatch32)'
    assert inc.count(anchor)==1
    inc=inc.replace(anchor,'else if(engine=="vecbatch" && bits==64 && X86_scanBatch64) row=batch_span<false,X86_scanBatch64>(bytes.data()+f.offset,f.size,handle,insn,f.ip);\n        '+anchor)
    anchor='if(X86_scanBatch32)(void)batch_span<true,X86_scanBatch32>(ptr,f.size,handle,insn,f.ip);'
    assert inc.count(anchor)==1
    inc=inc.replace(anchor,'if(bits==64 && X86_scanBatch64)(void)batch_span<true,X86_scanBatch64>(ptr,f.size,handle,insn,f.ip); else '+anchor)
    inc=inc.replace('X86_scanBatch32','X86_scanNativeBatch').replace('X86_scanBatch64','X86_scanNativeBatch')
    def once(v,a,b):
        assert v.count(a)==1,(a,v.count(a))
        return v.replace(a,b)
    inc=once(inc,'static void text_value(', 'template<bool NativeLength>\nstatic void text_value(')
    inc=once(inc,'  while (s[n])\n    ++n;', '  if constexpr (NativeLength) n=std::strlen(s); else while (s[n]) ++n;')
    inc=once(inc,'template <auto Next>\nstatic Result cs_span', 'template <auto Next, bool NativeLength=false>\nstatic Result cs_span')
    inc=inc.replace('text_value(result,','text_value<NativeLength>(result,')
    assert inc.count('text_value<NativeLength>')==2
    pair='else if(engine=="x86_iter" && bits==32 && X86_disasmIter32)'
    alt='else if(engine=="x86_len_" && bits==32) row=cs_span<X86_disasmIter32,true>(bytes.data()+f.offset,f.size,handle,insn,f.ip,mode);\n        else if(engine=="x86_len_") row=cs_span<X86_disasmIterText,true>(bytes.data()+f.offset,f.size,handle,insn,f.ip,mode);\n        '
    inc=once(inc,pair,alt+pair)
    inc=once(inc,'engine!="x86_iter" &&','engine!="x86_iter" && engine!="x86_len_" &&')
    inc='#include <cstring>\n'+inc
    inc=once(inc,'row=cs_span<cs_disasm_iter>(', 'row=cs_span<cs_disasm_iter,true>(')
    (w/'functions.cpp').write_text(inc);run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',w/'functions.cpp','-o',w/'driver.o'],'driver')
    m=json.loads((r/'experiment.json').read_text());trees=m['stages']
    darwin=platform.system()=='Darwin';bins={}
    cfg=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON']
    for key,z in trees.items():
        run(['git','restore','--source','HEAD','--staged','--worktree','.'],'restore-'+key,base)
        assert sp.check_output(['git','-C',base,'rev-parse','HEAD'],text=True).strip()==m['checkout_commit']
        if key in ('word','project','single'):
            patch=r/(('project' if key=='single' else key)+'.patch');assert sha(patch)==z['sha256']
            run(['git','apply','--index',patch],'apply-'+key,base)
        assert sp.check_output(['git','-C',base,'write-tree'],text=True).strip()==z['tree']
        build=w/('build-'+key);project=base
        if key not in ('official','single'):
            nd=r.parent/'neverd-config';record=m['neverd']
            assert sp.check_output(['git','-C',nd,'rev-parse','HEAD'],text=True).strip()==record['commit']
            for name,blob in record['blobs'].items():assert sp.check_output(['git','-C',nd,'hash-object',name],text=True).strip()==blob
            text=(nd/'CMakeLists.txt').read_text();a=text.index('# --- Capstone (our fork');end=text.index('# --- NeverD CMake helpers',a)
            project=w/('project-'+key);(project/'cmake').mkdir(parents=True);(project/'third_party').mkdir();(project/'third_party/capstone').symlink_to(base,target_is_directory=True)
            shutil.copy2(nd/'cmake/NeverDCapstoneCompilerOptions.inc',project/'cmake')
            (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Profile LANGUAGES C CXX)\n'+text[a:end])
        run(['cmake','-S',project,'-B',build,'-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',*cfg],'configure-'+key)
        db=json.loads((build/'compile_commands.json').read_text());files={Path(u['file']).name for u in db}
        near={Path(u['file']).name for u in db if '-DCAPSTONE_X86_NEAR_INDIRECT_OUTPUT' in u['command'].split()}
        assert near==({'X86Sse64Output.c'}if key not in ('official','single')and not darwin else set()),near
        assert ('MipsMapping.c' in files and 'AArch64InstPrinter.c' in files and 'ARMMapping.c' in files)==(key not in ('official','single'))
        save('compile-'+key+'.json',dict(archive_profile=key,near_indirect=sorted(near),neverd=m['neverd'],compile_commands_sha256=sha(build/'compile_commands.json')))
        units=['x86_simple_output','x86_scan_batch','x86_buffer_bounds','x86_reg_access','x86_exchange_access']
        run(['cmake','--build',build,'--parallel','4','--target','capstone_static',*(units if key in ('official','single') else [])],'build-'+key)
        lib,=build.rglob('libcapstone.a')
        if key in ('official','single'):
            run(['ctest','--test-dir',build,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units)+')$'],'unit-'+key)
        else:
            for name in units:
                run(['clang','-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-I',base,'-I',base/'include',base/('tests/unit/'+name+'.c'),lib,'-lm','-o',w/name],'link-'+name+'-'+key)
                run([w/name],'unit-'+name+'-'+key)
        exe=w/('runner-'+key)
        flags=[('-Wl,-u,_' if darwin else '-Wl,--undefined=')+n for n in ('X86_scanNativeBatch','X86_disasmIterText','X86_disasmIter32')]
        syslibs=['-lpthread','-lm']+(['-framework','Security','-framework','CoreFoundation','-liconv'] if darwin else ['-ldl'])
        run(['clang++',w/'driver.o',*flags,lib,ad/'target/release/libiced_compare.a',*syslibs,'-o',exe],'link-'+key);bins[key]=exe
        if key=='project':
            run(['clang','-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-I',base,'-I',base/'include','-DX86_disasmRecordIter=observed_disasm_record_iter','-DX86_readScanWord=observed_read_scan_word','-DX86_disasmProjected32=observed_scan32','-DX86_disasmProjected64=observed_scan64','-c',r/'second.c','-o',w/'plan.o'],'link-plans')
            for name in ('rounded','shift','mandatory','vex3'):
                run(['clang++','-std=c++17','-O2','-I',base,'-I',base/'include',r/(name+'.cpp'),w/'plan.o',lib,'-o',w/name],'compile-'+name)
                run([w/name],'oracle-'+name)
            run(['clang++','-std=c++17','-O2','-I',base/'include',base/'suite/synctools/x86_vector_output.cpp',lib,'-o',w/'generator'],'compile-generator')
            for flag,file in [('--evex-scan','X86GenEvexScan.inc'),('--rounded-registers64','X86GenRoundedRegister64.inc'),('--evex-shifts','X86GenEvexShiftOutput.inc')]:
                assert sp.check_output([w/'generator',flag])==(base/'arch/X86'/file).read_bytes(),flag
            run(['clang++','-O2','-I',base/'include',r/'vectors.cpp',lib,'-o',w/'vectors'],'compile-vectors')
    import pe_panels,frozen_deb,itertools
    for f in ('libmvec.py','libmvec.json'):shutil.copy2(r/f,w/f)
    run(['python3','-B',w/'libmvec.py'],'libmvec')
    glibc=json.loads((w/'libmvec.json').read_text());extra=[('libmvec-amd64',64,w/'libmvec.text',[(0,glibc['bytes'],glibc['address'])],glibc)]
    results=[]
    for name,bits,f,spans,source in itertools.chain(extra,pe_panels.prepare(w),frozen_deb.prepare(w)):
        if name not in m['samples']:continue
        expected=m['provenance'][name];assert sha(f)==expected['text_sha256']
        intervals=w/(name+'.tsv');emit=lambda rows:intervals.write_text(''.join('%d %d %d\n'%tuple(a)for a in rows))
        emit(spans)
        audit=[sp.check_output([v,'audit','0','1',f,intervals,str(bits)],text=True)for k,v in bins.items()if k in trees]
        assert len(set(audit))==1
        trace=[list(map(int,l.split()))for l in audit[0].splitlines()]
        views=[list(map(int,l.split()))for l in sp.check_output([w/'vectors',str(bits),f,intervals],text=True).splitlines()]
        assert len(views)==len(trace)==len(spans)
        selected=[a[:3]for a,v in zip(trace,views)if a[1]==a[5] and (m['samples'][name]!='simd-functions' or (v[1]>=8 and v[1]>=.15*v[0]))]
        emit(selected);assert sha(intervals)==expected['extent_sha256']
        for mode in (0,1,2):
            def timed(label,count):
                key={'official':'official','public_release':'release','public_word':'word','public_single':'single','single_release':'official'}.get(label,'project')
                engine={'iced':'iced____','fast':'fast____','public':'capstone','public_release':'capstone','public_word':'capstone','public_single':'capstone','single_release':'capstone'}.get(label,'x86_len_' if mode else 'vecbatch')
                return list(map(int,sp.check_output([bins[key],engine,str(mode),str(count),f,intervals,str(bits)]).split()))
            rep=max(1,math.ceil(50e6/max(1,timed('project',1)[0])));cycles=[]
            labels=['official','project','copy','public','public_word','public_release','public_single','single_release','iced']+(['fast']if mode else [])
            for idx in range(13):
                labels=labels[1:]+labels[:1];obs=[(k,timed(k,rep))for k in labels+labels[::-1]]
                assert len({tuple(v[2:5])for k,v in obs})==1 and len({tuple(v[2:])for k,v in obs if k not in ('iced','fast','public','public_word','public_release','public_single','single_release')})==1
                assert len({tuple(v[2:])for k,v in obs if k in ('public','public_word','public_release','public_single','single_release')})==1
                if mode:assert len({tuple(v[2:])for k,v in obs if k in ('public','project')})==1
                cycles.append(dict(raw=obs))
            results.append(dict(case=name,mode=mode,bits=bits,extent_sha256=sha(intervals),counts=len(selected),rep=rep,cycles=cycles));save('timings.json',results)
    assert len(results)==3*len(m['samples'])
    save('complete.json',dict(trees=trees,iced=iced,records=len(results),neverd=m['neverd'],native=platform.platform(),machine=platform.machine()))
w=Path(tempfile.mkdtemp(prefix='capstone-portable-vector-'))
try:
    if hasattr(os,'sched_setaffinity'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    main(w)
finally:
    amount=sum(x.stat().st_size for x in w.rglob('*')if x.is_file()and not x.is_symlink());shutil.rmtree(w);save('cleanup.json',dict(removed=not w.exists(),bytes=amount))
