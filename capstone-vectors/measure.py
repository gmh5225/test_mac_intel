"""Measure exact, common-boundary PE function bodies and three additional ELF text sections."""
from pathlib import Path
import gzip, os, platform, hashlib, importlib.util, json, math, shutil, statistics, subprocess as sp, tempfile
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
    reference='729680277dd762704ea3270291b7a75318f51583'
    assert sp.check_output(['git','-C',base,'rev-parse',reference],text=True).strip()==reference
    iced='8b8d90b13374fbf38e7279749e48c673f4ec243a'
    checkout=w/'iced';checkout.mkdir();tar=w/'iced.tar'
    run(['git','init','--bare',w/'iced-git'],'iced-repo');run(['git','-C',w/'iced-git','fetch','--depth','1','https://github.com/NeverSight/iced.git',iced],'iced-fetch');run(['git','-C',w/'iced-git','archive','--format=tar','-o',tar,iced,'src/rust/iced-x86'],'iced-archive');run(['tar','-xf',tar,'-C',checkout],'iced-extract');tar.unlink()
    ad=w/'adapter';ad.mkdir();src=(lab/'iced.rs').read_text().replace('repeats: u32,\n    output:', 'repeats: u32,\n    ip: u64,\n    output:').replace('bytes, 0x100000,','bytes, ip,').replace('set_ip(0x100000 +','set_ip(ip +')
    src=src.replace('InstructionInfoFactory, IntelFormatter,','InstructionInfoFactory, IntelFormatter, FastFormatter,').replace('    formatter: IntelFormatter,','    formatter: IntelFormatter,\n    fast: FastFormatter,\n    fast_enabled: bool,').replace('        mode,','        mode: mode & 3,\n        fast_enabled: mode & 8 != 0,\n        fast: FastFormatter::new(),')
    old='state.formatter.format(&instruction, &mut state.text);';assert src.count(old)==1;src=src.replace(old,'if state.fast_enabled {state.fast.format(&instruction, &mut state.text);} else {state.formatter.format(&instruction, &mut state.text);}')
    trace=(r/'iced-trace.rs').read_text().replace('iced_trace(input:', 'iced_trace(bits:u32,input:').replace('with_ip(64,','with_ip(bits,');(ad/'iced.rs').write_text(src+trace);shutil.copyfile(lab/'Cargo.lock',ad/'Cargo.lock')
    (ad/'Cargo.toml').write_text('[package]\nname="iced_compare"\nversion="0.1.0"\nedition="2021"\n[lib]\ncrate-type=["staticlib"]\npath="iced.rs"\n[dependencies]\niced-x86={path="../iced/src/rust/iced-x86",default-features=false,features=["std","decoder","intel","instr_info","fast_fmt"]}\n[profile.release]\npanic="abort"\nopt-level=3\n');run(['cargo','build','--locked','--release'],'iced-build',ad)
    save('cpu.json',dict(cpu=Path('/proc/cpuinfo').read_text(),compiler=sp.check_output([os.environ['CC'],'--version'],text=True)))
    save('census-variant.json',dict(variant='integer',round=1124,capstone_revision=reference,iced_revision=iced,purpose='Compiler selection object identity; no timing claim'))
    save('variants.json',dict(integer='Released Capstone next',output='R1123 unconditional batch state split',scan='R1124 Clang-only batch state split'))
    save('entrypoints.json',dict(scan='cs_disasm_iter',format='X86_disasmIter',detail='X86_disasmIter',consumer='Physical output entry cost diagnostic; actual NeverD tested separately'))
    inc=(r/'driver.cpp').read_text().replace('size_t iced_trace(const','size_t iced_trace(unsigned, const').replace('if(argc!=6)','if(argc!=7)').replace('  csh handle=0;','  unsigned bits=std::stoul(argv[6]);\n  csh handle=0;').replace('cs_open(CS_ARCH_X86,CS_MODE_64,','cs_open(CS_ARCH_X86,bits==32?CS_MODE_32:CS_MODE_64,').replace('iced_create(64,mode)','iced_create(bits,mode)').replace('iced_trace(ptr,','iced_trace(bits,ptr,')
    inc=inc.replace('iced_create(bits,mode)','iced_create(bits,mode | (engine=="fast" ? 8 : 0))').replace('engine!="capstone" && engine!="iced"','engine!="capstone" && engine!="iced" && engine!="fast"')
    inc=inc.replace('if (mode>2 ||','if (mode>4 ||').replace('mode==2 ? CS_OPT_ON','mode>=2 ? CS_OPT_ON')
    inc=inc.replace('if (mode == 2) {','if (mode == 2 || mode == 4) {\n        if (mode == 2) {').replace('        const auto &x = insn->detail->x86;', '        }\n        const auto &x = insn->detail->x86;')
    assert inc.count('iced_trace(bits,ptr,')==1
    inc=inc.replace('static Result cs_span(', 'extern "C" __attribute__((noinline)) Result cs_span(')
    inc=inc.replace('#include <capstone/capstone.h>', '#include <capstone/capstone.h>\n#include <valgrind/callgrind.h>')
    assert inc.count('Result warm=run(1);')==1 and inc.count('Result timed=run(reps);')==1
    inc=inc.replace('Result warm=run(1);', 'Result warm=run(1);\n    CALLGRIND_ZERO_STATS;')
    inc=inc.replace('Result timed=run(reps);', 'CALLGRIND_TOGGLE_COLLECT;\n    Result timed=run(reps);\n    CALLGRIND_TOGGLE_COLLECT;')
    (w/'functions.cpp').write_text(inc);run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',base/'include','-c',w/'functions.cpp','-o',w/'driver.o'],'driver')
    profile=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+os.environ['CC'],'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+arch+'_SUPPORT=ON' for arch in ['X86','ARM','AARCH64','MIPS']],'-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer '+('-Wno-error=discarded-qualifiers' if os.environ['CC']=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF']
    tree=w/'tree';run(['git','clone','-q','--shared','--no-checkout',base,tree],'capstone-clone');run(['git','checkout','-q','--detach',reference],'capstone-checkout',tree);b=w/'build';run(['cmake','-S',tree,'-B',b,*profile],'configure');evidence={};exe={}
    objects={}
    iterator_shapes={}
    for label in ('integer','output','scan'):
        if label=='aa':
            exe[label]=w/'baseline-copy';shutil.copy2(exe['integer'],exe[label]);continue
        patches=[] if label=='integer' else [r/({'aligned':'alignment.patch','output':'dispatch.patch','isolated':'isolated.patch','scan':'scan.patch'}[label])]
        for patch in patches: run(['git','apply',patch],'apply-'+label+'-'+patch.stem,tree)
        run(['cmake','--build',b,'--target','capstone_static','--parallel','4'],'build-'+label)
        objroot=b/'CMakeFiles/capstone.dir'
        objects[label]={str(path.relative_to(objroot)):sha(path) for path in objroot.rglob('*.o')}
        assert len(objects[label])>30
        if label!='integer':
            changed={n for n in objects['integer']if objects[label].get(n)!=objects['integer'][n]}
            added=set(objects[label])-set(objects['integer'])
            expected=set() if label=='scan' and os.environ['CC']!='clang' else {'arch/X86/X86DisassemblerDecoder.c.o'}
            expected_added=set()
            assert changed==expected and added==expected_added,(label,changed,added)
            save('objects-'+label+'.json',dict(changed=sorted(changed),added=sorted(added),total=len(objects[label])))
        if label=='scan':
            delta={key for key in objects['output'] if objects['output'][key]!=objects['scan'][key]}
            expected_delta=set() if os.environ['CC']=='clang' else {'arch/X86/X86DisassemblerDecoder.c.o'}
            assert delta==expected_delta,(label,delta)
            owner='output' if os.environ['CC']=='clang' else 'integer'
            assert objects['scan']==objects[owner],owner
            save('controlled-object-delta.json',dict(only_changed=sorted(delta),reference='R1123 for Clang, release for GCC'))
        for component in ('X86Mapping','X86OutputIterator','X86DisassemblerDecoder','X86VectorOutput'):
            object_file=objroot/'arch/X86'/(component+'.c.o')
            assembly=sp.check_output(['objdump','-dr',object_file])
            with gzip.open(p/'evidence'/(label+'-'+component+'.asm.gz'),'wb') as stream:
                stream.write(assembly)
        code=inc.replace('#include <capstone/capstone.h>','#include <capstone/capstone.h>\n#include "X86ScanAdapter.h"');old='bool ok = cs_disasm_iter(handle, &cursor, &left, &ip, insn);';assert code.count(old)==1;code=code.replace(old,'bool ok = mode ? X86_disasmIter(handle,&cursor,&left,&ip,insn) : cs_disasm_iter(handle,&cursor,&left,&ip,insn);');(w/'owned.cpp').write_text(code);obj=w/'owned.o';run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',base/'include','-I',tree/'arch/X86','-c',w/'owned.cpp','-o',obj],'owned-driver-'+label)
        target=w/('run-'+label);run(['clang++',obj,b/'libcapstone.a',ad/'target/release/libiced_compare.a','-lpthread','-ldl','-lm','-o',target],'link-'+label);exe[label]=target
        import re
        asm=sp.check_output(['objdump','-d','--no-show-raw-insn',target],text=True)
        block=re.search(r'^[0-9a-f]+ <X86_disasmIter>:\n(.*?)(?=^[0-9a-f]+ <|\Z)',asm,re.M|re.S).group(1)
        shape=[]
        for line in block.splitlines():
            match=re.match(r'\s*[0-9a-f]+:\s+(.*)',line)
            if not match:continue
            instruction=match[1].split('#',1)[0].strip()
            instruction=re.sub(r'\b[0-9a-f]+ <([^>]+)>',r'<\1>',instruction)
            instruction=re.sub(r'-?0x[0-9a-f]+(?=\(%rip\))','<relative>',instruction)
            instruction=re.sub(r'\s+',' ',instruction)
            shape.append(instruction)
        iterator_shapes[label]=shape
        save('iterator-shape.json',dict(scope='Linked instruction sequence with external PC-relative addresses normalized; structural comparison, not semantic proof.',counts={k:len(v)for k,v in iterator_shapes.items()},equal_to_baseline={k:v==iterator_shapes['integer']for k,v in iterator_shapes.items()}))
        (p/'evidence'/(label+'-iterator-shape.txt')).write_text('\n'.join(shape)+'\n')
        save('object-digests.json',objects)
        symbols=sp.check_output(['nm','-n','-S','--defined-only',target],text=True)
        (p/'evidence'/(label+'-symbols.txt')).write_text(symbols)
        (p/'evidence'/(label+'-sections.txt')).write_bytes(sp.check_output(['readelf','-WS',target]))
        with gzip.open(p/'evidence'/(label+'-linked-assembly.gz'),'wb')as out:out.write(sp.check_output(['objdump','-dr',target]))
        run(['git','reset','--hard',reference],'restore-'+label,tree)
        run(['git','clean','-fdx'],'remove-generated-'+label,tree)
        assert not sp.check_output(['git','-C',tree,'status','--porcelain'])
    save('complete.json',dict(success=True,native_qualification=False,compiler=os.environ['CC'],object_identity_reference='R1123' if os.environ['CC']=='clang' else reference,all_objects_equal=True))

w=Path(tempfile.mkdtemp(prefix='capstone-iced-formatters-'))
try:
    if hasattr(os,'sched_setaffinity'): os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    main(w)
finally:
    files=[v for v in w.rglob('*') if v.is_file()];amount=sum(v.stat().st_size for v in files);shutil.rmtree(w);save('cleanup.json',dict(removed=not w.exists(),bytes=amount,files=len(files)))
