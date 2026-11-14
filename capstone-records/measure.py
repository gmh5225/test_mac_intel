from pathlib import Path
import gzip, hashlib, json, os, platform, re, shutil, statistics, subprocess as sp, tempfile
import corpus
r=Path(__file__).resolve().parent
e=r.parent/'evidence'
e.mkdir()
s=r.parent/'source'
cc=os.environ['MEASURE_CC']
reference=json.loads((r/'manifest.json').read_text())['capstone_revision']
def write(name,value):
    (e/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
def run(args,label,cwd=None):
    print(label,flush=True)
    with (e/(label+'.log')).open('wb') as out:
        sp.run(list(map(str,args)),cwd=cwd,stdout=out,stderr=sp.STDOUT,check=True)
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
assert sp.check_output(['git','-C',s,'rev-parse','HEAD'],text=True).strip()==reference
write('environment',dict(platform=platform.platform(),cpu=sp.check_output(['lscpu'],text=True),
      compiler=sp.check_output([cc,'--version'],text=True),reference=reference,
      profiler=sp.check_output(['valgrind','--version'],text=True)))
with tempfile.TemporaryDirectory(prefix='capstone-scan-costs-') as tmp:
    t=Path(tmp)
    b=t/'build'
    try:
        all_inputs=corpus.prepare(r,t,e,run)
        names={'putty-32-0.85','putty-64-0.85','amd64-ls','arm64-ls','mips64el-ls'}
        cases=[x for x in all_inputs if x['name'] in names]
        assert len(cases)==len(names)
        run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',s,'-I',s/'include','-c',r/'single.cpp','-o',t/'single.o'],'consumer')
        run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,
             '-DCMAKE_C_FLAGS=-Wno-error=discarded-qualifiers','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
             '-DCAPSTONE_ARM_SUPPORT=ON','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_MIPS_SUPPORT=ON',
             '-DCAPSTONE_AARCH64_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF',
             '-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF',
             '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'],'configure')
        bins={}
        symbols={}
        for key in ['base','outlined','combined','early-vex','split']:
            patch=r/(key+'.patch')
            if key!='base':
                run(['git','apply',patch],'apply-'+key,s)
            run(['cmake','--build',b,'--target','capstone_static','--parallel','4'],'build-'+key)
            exe=t/key
            run(['clang++',t/'single.o',b/'libcapstone.a','-lm','-o',exe],'link-'+key)
            bins[key]=exe
            symbol_text=sp.check_output(['nm','-n','-S','--defined-only',exe],text=True)
            (e/(key+'-symbols.txt')).write_text(symbol_text)
            symbols[key]={m[4]:{'address':int(m[1],16),'size':int(m[2],16),'type':m[3]}
                for line in symbol_text.splitlines()
                if (m:=re.match(r'^(\w+) (\w+) ([Tt]) (.+)$',line))}
            targets=[name for name in symbols[key] if name in ('cs_disasm_iter','cs_disasm_iter_full','cs_decode_full_insn')
                     or name.startswith('getInstructionScanResultAfterInitial')]
            for name in targets:
                output=sp.check_output(['objdump','-d','--disassemble='+name,exe])
                (e/(key+'-'+name+'.asm')).write_bytes(output)
            run(['git','reset','--hard',reference],'restore-'+key,s)
        bins['aa']=t/'aa'
        shutil.copy2(bins['base'],bins['aa'])
        write('binaries',{key:sha(path) for key,path in bins.items()})
        write('code-sizes',{key:{name:value for name,value in values.items()
               if name in ('cs_disasm_iter','cs_disasm_iter_full','cs_decode_full_insn') or name.startswith('getInstructionScanResultAfterInitial')}
               for key,values in symbols.items()})
        if hasattr(os,'sched_getaffinity'):
            os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
        def command(key,case,mode,reps):
            return list(map(str,[bins[key],case['selector'],mode,case['path'],reps]))
        def sample(key,case,mode,reps):
            return json.loads(sp.check_output(command(key,case,mode,reps)))
        timings=[]
        dynamic=[]
        for case in cases:
            mode=1 if case['name'] in ('arm64-ls','mips64el-ls') else 0
            warm=sample('base',case,mode,2)
            repeats=max(2,min(4000,round(2*160e6/warm['cpu_ns'])))
            checks=None
            pairs=[]
            keys=list(bins)
            for cycle in range(21):
                order=keys[cycle%len(keys):]+keys[:cycle%len(keys)]
                ticks={key:[] for key in keys}
                for key in order+order[::-1]:
                    result=sample(key,case,mode,repeats)
                    current=(result['first'],result['result'])
                    if checks is None:
                        checks=current
                    assert current==checks,(key,case,mode)
                    ticks[key].append(result['cpu_ns'])
                pairs.append({key:sum(ticks['base'])/sum(ticks[key]) for key in keys})
            timings.append(dict(case=case['name'],mode=mode,pairs=pairs,
                median={key:statistics.median(row[key] for row in pairs) for key in keys},result=checks))
            write('timings',timings)
            if case['name'] not in ('putty-32-0.85','arm64-ls','mips64el-ls'):
                continue
            for key in keys:
                if key=='aa':
                    continue
                label=case['name']+'-'+key
                profile=t/(label+'.callgrind')
                run(['valgrind','--tool=callgrind','--cache-sim=yes','--branch-sim=yes',
                     '--collect-atstart=no','--toggle-collect=cs_disasm_iter',
                     '--callgrind-out-file='+str(profile),*command(key,case,mode,1)],'profile-'+label)
                raw=profile.read_text()
                events=next(line.split()[1:] for line in raw.splitlines() if line.startswith('events:'))
                totals=next(line.split()[1:] for line in raw.splitlines() if line.startswith('summary:'))
                dynamic.append(dict(case=case['name'],mode=mode,variant=key,
                    events=dict(zip(events,map(int,totals)))))
                write('dynamic-costs',dynamic)
                annotation=sp.check_output(['callgrind_annotate','--inclusive=yes','--tree=both','--threshold=99.5',profile])
                (e/(label+'-calls.txt')).write_bytes(annotation)
                with gzip.open(e/(label+'.callgrind.gz'),'wb') as out:
                    out.write(raw.encode())
                profile.unlink()
        write('complete',dict(timing_cases=len(timings),profile_cases=len(dynamic)))
    finally:
        size=sum(f.stat().st_size for f in t.rglob('*') if f.is_file())
        shutil.rmtree(t)
        write('cleanup',dict(bytes=size,removed=not t.exists()))
