from pathlib import Path
import hashlib,io,json,math,os,random,shlex,shutil,statistics,subprocess as sp,sys
from elftools.elf.elffile import ELFFile
from profile_corpus import deb_binary,elf_text

def fetch(r,w):
    rows=json.loads((r/'training.json').read_text())
    packages={}
    for row in rows:
        h=row['package_sha256']
        if h not in packages:
            file=w/(h+'.deb')
            sp.run(['curl','-fsSL','--retry','3','--max-time','120',row['url'],'-o',file],check=True)
            assert hashlib.sha256(file.read_bytes()).hexdigest()==h
            packages[h]=file
        data=deb_binary(packages[h],row.get('command',''),row.get('member'))
        elf=ELFFile(io.BytesIO(data));text=elf_text(data);section=elf.get_section_by_name('.text')
        expected={'i386':('EM_386',32),'amd64':('EM_X86_64',64),'arm':('EM_ARM',32),
                  'arm64':('EM_AARCH64',64),'riscv64':('EM_RISCV',64),
                  'mips64el':('EM_MIPS',64),'ppc64el':('EM_PPC64',64)}
        arch=row['arch'];assert (elf['e_machine'],elf.elfclass)==expected[arch] and elf.little_endian
        if arch=='riscv64':assert elf['e_flags']&1
        assert section.data()==text
        digest=hashlib.sha256(text).hexdigest()
        assert row.get('text_sha256',digest)==digest
        row.update(text_sha256=digest,bytes=len(text),address=section['sh_addr'],binary_sha256=hashlib.sha256(data).hexdigest())
        (w/(row['name']+'.text')).write_bytes(text)
        (w/(row['name']+'.ranges')).write_text('0 %d %d\n'%(len(text),section['sh_addr']))
    assert len({r['text_sha256']for r in rows})==len(rows)
    for file in packages.values():file.unlink()
    return rows

def build_profile(r,w,project,build,lib,ice_lib,flags,base,save):
    rows=fetch(r,w);save('training-corpus',rows)
    profile=w/'native.profdata'
    foreign=w/'foreign.o'
    sp.run(['clang++','-std=c++17','-O3','-DNDEBUG','-I',base/'include','-c',r/'foreign.cpp','-o',foreign],check=True)
    def link_foreign(name,extra=()):
        sp.run(['clang++',foreign,lib,*extra,'-o',w/('foreign-'+name)],check=True)
    def config(flag):
        sp.run(['cmake','-S',project,'-B',build,'-DCMAKE_C_FLAGS='+flag],check=True)
        commands=json.loads((build/'compile_commands.json').read_text())
        assert all(flag.split()[0] in shlex.split(c['command']) for c in commands if c['file'].endswith('.c'))
        log=sp.run(['cmake','--build',build,'--target','capstone_static','--parallel','4'],text=True,stdout=sp.PIPE,stderr=sp.STDOUT)
        warnings=[l for l in log.stdout.splitlines() if 'warning:' in l]
        if log.returncode: print(log.stdout[-4500:],flush=True)
        log.check_returncode()
        return warnings
    link_foreign('base')
    gen_warnings=config('-fprofile-generate')
    sp.run(['clang++',w/'driver.o',lib,ice_lib,*flags,'-fprofile-generate','-o',w/'training-x86'],check=True)
    link_foreign('training',['-fprofile-generate'])
    train=[x for x in rows if x['use']=='train'];seen=[]
    for row in train:
        for mode in range(3):
            target=row['arch'];name=row['name'];f=w/(name+'.text')
            if target in ('amd64','i386'):
                cmd=[w/'training-x86','private',str(mode),'1',f,w/(name+'.ranges'),'32' if target=='i386' else '64']
            else:cmd=[w/'foreign-training',target,f,str(mode),'1']
            counter=w/(name+'-'+str(mode)+'.profraw')
            result=list(map(int,sp.check_output(cmd,env=dict(os.environ,LLVM_PROFILE_FILE=str(counter))).split()))
            assert len(result)==6 and result[2]>0 and counter.stat().st_size>0,(cmd,result)
            seen.append(counter)
    assert {x['arch'] for x in train}=={'amd64','i386','arm64','arm','ppc64el','mips64el','riscv64'}
    if sys.platform=='darwin':prof=sp.check_output(['xcrun','--find','llvm-profdata'],text=True).strip()
    else:
        clang=Path(shutil.which('clang')).resolve()
        prof=str(clang.parent/'llvm-profdata')
        if not Path(prof).exists():prof=shutil.which('llvm-profdata-'+clang.name.split('-')[-1]) or shutil.which('llvm-profdata')
    sp.run([prof,'merge','-o',profile,*seen],check=True)
    info=sp.check_output([prof,'show',profile],text=True)
    assert profile.stat().st_size>0 and 'IR' in info and 'Total functions' in info,info
    digest=hashlib.sha256(profile.read_bytes()).hexdigest()
    use_warnings=config('-fprofile-use='+str(profile)+' -Werror=profile-instr-out-of-date')
    link_foreign('candidate')
    shutil.copy2(w/'foreign-base',w/'foreign-duplicate')
    save('profile',dict(training_runs=len(seen),profile_bytes=profile.stat().st_size,
         sha256=digest,summary=info,gen_warnings=gen_warnings,use_warnings=use_warnings,profdata=str(prof),
         training_names=[r['name']for r in train],foreign_holdouts=[r['name']for r in rows if r['use']=='holdout']))
    for f in seen+[profile,w/'training-x86',w/'foreign-training']:f.unlink()
    return [row for row in rows if row['use']=='holdout']

def holdouts(rows,w,save):
    output={}
    for row in rows:
        for mode in range(3):
            def take(label,n):
                return list(map(int,sp.check_output([w/('foreign-'+label),row['arch'],w/(row['name']+'.text'),str(mode),str(n)]).split()))
            labels=['base','candidate','duplicate']
            n=max(1,math.ceil(18e6/max(take('base',1)[0],1)))
            expected=take('base',n)[2:];assert expected[0]>0
            rng=random.Random(row['name']+'/'+str(mode));cycles=[]
            for i in range(13):
                rng.shuffle(labels);pair={k:[] for k in labels}
                for k in labels+labels[::-1]:
                    got=take(k,n);assert got[2:]==expected
                    pair[k].append(got[:2])
                cycles.append({k:[sum(t[j]for t in ts)for j in (0,1)]for k,ts in pair.items()})
            output[row['name']+'/'+str(mode)]=dict(checks=expected,repeats=n,cycles=cycles)
            save('foreign-observations',output)
    assert len(output)==15
