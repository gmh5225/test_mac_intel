from pathlib import Path
import hashlib,itertools,json,math,os,platform,random,shutil,statistics,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;p=r.parent
e=p/'evidence';e.mkdir(exist_ok=True);rd=lambda f:json.loads(f.read_text())
q=rd(r/'tree.json');m=rd(r/'experiment.json');dev=m['neverd'];base=p/'source';root=p/'neverd-config';ice=p/'iced-source'
def save(name,value):
    f=e/(name+'.json');temp=f.with_suffix('.tmp');temp.write_text(json.dumps(value,indent=2)+'\n');temp.replace(f)
def get(*args,**kwargs):return sp.check_output(args,text=True,**kwargs)
def run(*args,**kwargs):sp.run(args,check=True,**kwargs)
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def interval(values):
    x=sorted(values);n=len(x)
    def rank(q):
        return next(k for k in range(1,n+1) if 40*sum(math.comb(n,i)*k**i*(n-k)**(n-i) for i in range(n//2+1,n+1))>=q*n**n)-1
    return [statistics.median(x),x[rank(1)],x[rank(39)]]
w=Path(tempfile.mkdtemp());project=w/'project';build=w/'build';ad=w/'adapter'
try:
    assert get('git','-C',base,'rev-parse','HEAD').strip()==m['checkout_commit'] and get('git','-C',base,'write-tree').strip()==m['checkout_tree']
    assert get('git','-C',root,'rev-parse','HEAD').strip()==dev
    assert get('git','-C',ice,'rev-parse','HEAD').strip()==m['iced_revision']
    assert all(sha(r/f)==v for f,v in m['drivers'].items())
    (project/'third_party').mkdir(parents=True);(project/'third_party/capstone').symlink_to(base)
    (project/'cmake').mkdir();cm='cmake/NeverDCapstoneCompilerOptions.inc'
    (project/cm).write_bytes(sp.check_output(['git','-C',root,'show',dev+':'+cm]))
    v=get('git','-C',root,'show',dev+':CMakeLists.txt')
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Layers LANGUAGES C CXX)\n'+v[v.index('# --- Capstone (our fork'):v.index('# --- NeverD CMake helpers')])
    run('cmake','-G','Ninja','-S',project,'-B',build,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
    run('cmake','--build',build,'--target','capstone_static','--parallel','4');lib,=build.rglob('libcapstone.a')
    files={Path(c['file']).name for c in rd(build/'compile_commands.json')};assert {'MipsMapping.c','AArch64Mapping.c','ARMMapping.c','X86Sse64Output.c'}<=files and 'X86PublicOutput.c' not in files
    import sys
    sys.path.insert(0,str(base/'suite/synctools'))
    import x86_operand_specializations as spec
    sets=spec.read_sets(base/'arch/X86/X86GenDisassemblerTables.inc',include_duplicates=True)
    sets_special=dict(spec.read_specializations(''))
    save('descriptors',{i:dict(shape=z,special=i in sets_special) for i,z in enumerate(sets)})
    nsets=len(sets)
    source=base/'arch/X86/X86DisassemblerDecoder.c'
    original=source.read_text()
    def once(s,a,b):
        assert s.count(a)==1,(a,s.count(a))
        return s.replace(a,b)
    code=once(original,'static int readOperands(struct InternalInstruction *insn)\n{',
        'static int readOperandsBody(struct InternalInstruction *insn)\n{')
    key='\tneedVVVV = hasVVVV && (insn->vvvv != 0);'
    a=code.index('static int readOperandsBody(');b=code.index('/*\n * checkEVEX',a)
    body=once(code[a:b],key,key+'''
    unsigned set = insn->spec->operands;
    ++operand_visits[set][0];
    operand_visits[set][2] += !!insn->consumedModRM;
    operand_visits[set][3] += !!needVVVV;
    operand_visits[set][5] += insn->instructionID == X86_UD1;''')
    key='\tfor (i = 0; i < X86_MAX_OPERANDS &&'
    body=once(body,key,'\t++operand_visits[set][1];\n'+key)+'''
static int readOperands(struct InternalInstruction *insn)
{
    int status=readOperandsBody(insn);
    operand_visits[insn->spec->operands][4] += status != 0;
    return status;
}

'''
    code=code[:a]+body+code[b:]
    key='\t// dbgprintf(insn, "readModRM()");'
    code=once(code,key,'''    unsigned bucket;
    if (insn->consumedModRM)
        bucket = 32;
    else if (insn->readerCursor >= insn->codeSize)
        bucket = 33;
    else {
        const uint8_t raw=insn->code[insn->readerCursor];
        bucket = ((raw >> 6) << 3) | (raw & 7);
    }
    ++address_visits[materialize][bucket];''')
    at=code.index('static int readModRM(struct InternalInstruction *insn);')
    code=code[:at]+f'extern uint64_t operand_visits[{nsets}][6], address_visits[2][34];\n'+code[at:]
    export=r/'trial-export.c';shim=w/'observe.c'
    shim.write_text(export.read_text()+f'\nuint64_t operand_visits[{nsets}][6], address_visits[2][34];\n')
    main=(r/'trial-real.cpp').read_text();end='    return 0;\n}'
    main=once(main,end,r'''    const auto sets=tested.sym<const uint64_t (*)[6]>("operand_visits");
    const auto address=tested.sym<const uint64_t (*)[34]>("address_visits");
    for(unsigned i=0; i<ROW_COUNT; ++i) {
        if (!sets[i][0])continue;
        std::printf("set %u",i);
        for(unsigned j=0;j<6;++j)std::printf(" %" PRIu64,sets[i][j]);
        std::puts("");
    }
    for(unsigned m=0;m<2;++m) {
        std::printf("mod %u",m);
        for(unsigned j=0;j<34;++j)std::printf(" %" PRIu64,address[m][j]);
        std::puts("");
    }
'''.replace('ROW_COUNT',str(nsets))+end)
    (w/'driver-count.cpp').write_text(main)
    run('clang++','-O2','-std=c++17','-I',base/'include','-I',r,w/'driver-count.cpp','-ldl','-o',w/'counts')
    def objects():return {str(f.relative_to(build)):sha(f) for f in build.rglob('*.c.o')}
    before=objects();lib0=sha(lib)
    def link(f,output):run('clang','-O2','-fPIC','-shared','-I',base/'include',f,'-Wl,--whole-archive',lib,'-Wl,--no-whole-archive','-o',output)
    link(export,w/'old.so')
    run('clang++','-O2','-I',base/'include',r/'vectors.cpp',lib,'-o',w/'vectors')
    source.write_text(code);run('cmake','--build',build,'--target','capstone_static','--parallel','4')
    after=objects();assert after.keys()==before.keys() and [Path(k).name for k in after if after[k]!=before[k]]==['X86DisassemblerDecoder.c.o']
    link(shim,w/'observed.so')
    save('images',dict(before=lib0,instrumented=sha(lib),counts=sha(w/'counts'),observed=sha(w/'observed.so'),original=sha(w/'old.so'),objects=len(after)))
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','vectors.cpp','libmvec.py','libmvec.json'):
        shutil.copyfile(r/f,w/f)
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    observations={}
    fixtures=list(itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,raw['bytes'],raw['address'])],raw)],pe_panels.prepare(w),frozen_deb.prepare(w)))
    assert {row[0]for row in fixtures}==set(m["samples"])
    for name,bits,f,spans,_ in fixtures:
        spec=m['provenance'][name]
        assert sha(f)==spec['text_sha256']
        selected=[s for s in spans if tuple(s) not in {tuple(a[:3]) for a in spec['excluded_incompatible_extents']}]
        path=w/(name+'.tsv')
        def emit(v):path.write_text(''.join('%d %d %d\n'%tuple(a) for a in v))
        emit(selected)
        if m['samples'][name]=='simd-functions':
            view=[list(map(int,z.split())) for z in get(w/'vectors',str(bits),f,path).splitlines()]
            assert len(view)==len(selected)
            selected=[s for s,x in zip(selected,view)if x[1]>=8 and x[1]>=.15*x[0]];emit(selected)
        assert sha(path)==spec['extent_sha256']

        for route in range(8):
            lines=get(w/'counts',w/'old.so',w/'observed.so',f,path,str(bits),str(route)).splitlines()
            rec=list(map(int,lines.pop(0).split()))
            assert rec[0]>0 and rec[2]==spec['bytes']
            hits={};mod={}
            for line in lines:
                name2,num,*counts=line.split();v=list(map(int,counts))
                (hits if name2=='set' else mod)[int(num)]=v
            assert all(len(row)==6 and max(row[1:])<=row[0] for row in hits.values())
            assert set(mod)=={0,1} and all(len(row)==34 for row in mod.values())
            for i,row in hits.items():
                assert row[1]==(row[5] if i in sets_special else row[0])
            observations[name+'/'+str(route)]=dict(record=rec,visits=hits,address=mod)
            save('observations',observations)
    assert len(observations)==48
    save('complete',dict(complete=True,source=q,neverd=dev,host=os.uname().machine,cases=len(observations),count=nsets))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
