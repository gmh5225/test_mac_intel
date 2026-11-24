from pathlib import Path
import array,bisect,collections,hashlib,json,math,os,random,shutil,statistics,struct,subprocess as sp
from elftools.elf.elffile import ELFFile
def collect(ctx):
    w,base,r,lib,ice_lib,ad,build,flags,save=ctx
    def get(*a,**kw):return sp.check_output(a,text=True,**kw)
    def run(*a,**kw):sp.run(a,check=True,**kw)
    def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
    ref=w/'reference';run('clang++',w/'driver.o',lib,ice_lib,*flags,'-o',ref)
    run('clang','-O2','-std=gnu11','-c',r/'timer.c','-o',w/'timer.o')
    (ad/'iced.rs').write_bytes((r/'sample.rs').read_bytes());run('cargo','build','--release','--locked',cwd=ad)
    sample=w/'sample'
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include',r/'sample.cpp',w/'timer.o',lib,ice_lib,*flags,'-o',sample)
    with sample.open('rb') as ff:
        elf=ELFFile(ff);assert elf['e_type']=='ET_EXEC'
        symbols=sorted((s['st_value'],s['st_size'],s.name)for s in elf.get_section_by_name('.symtab').iter_symbols()if s['st_info']['type']=='STT_FUNC' and s['st_size']>0)
    starts=[a for a,n,s in symbols]
    assert 'X86_disasmIterText' in {s for a,n,s in symbols}
    base_archive=sha(lib)
    f=base/'cs.c';old=f.read_text();key='MCInst mci;\n#ifdef CAPSTONE_HAS_X86\n\tif (handle->arch == CS_ARCH_X86)';assert old.count(key)==1
    f.write_text(old.replace('/* Keep the full decoder','uint64_t profile_full_decodes;\n/* Keep the full decoder',1).replace(key,key.replace('MCInst mci;','MCInst mci;\n\t++profile_full_decodes;')))
    run('cmake','--build',build,'--target','capstone_static','--parallel','4');assert sha(lib)!=base_archive
    census=w/'census';run('clang++','-std=c++17','-O2','-I',base,'-I',base/'include',r/'census.cpp',lib,'-o',census)
    f.write_text(old);run('cmake','--build',build,'--target','capstone_static','--parallel','4');assert sha(lib)==base_archive
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});prefix=['setarch',os.uname().machine,'-R']
    save('binaries',dict(archive=base_archive,reference=sha(ref),sample=sha(sample),symbols=len(symbols),driver=sha(r/'driver.cpp'),adapter=sha(r/'iced.rs'),sample_driver=sha(r/'sample.cpp'),sample_adapter=sha(r/'sample.rs')))
    raw=w/'pcs.bin';pcs=w/'pc-map'
    def panel(name,bits,path,tsv):
        route=w/'routes.bin';count=get(census,path,tsv,str(bits),route).splitlines()[0].split('\t')
        accepted,reject,covered,digest=map(int,count[1:5]);route_bytes=route.read_bytes();assert len(route_bytes)==covered
        def call(which,engine,mode,reps,env=None):return list(map(int,get(*prefix,which,engine,str(mode),str(reps),path,tsv,str(bits),env=env).split()))
        result={}
        for mode in (1,2):
            route_counts=collections.Counter('invalid' if v&4 else 'generic' if v&mode else 'direct'for v in route_bytes if v!=255)
            assert route_counts['direct']+route_counts['generic']==accepted and route_counts['invalid']==reject
            order=[(engine,i)for engine in ('private','fast')for i in range(3)];random.Random(name+'/'+str(mode)).shuffle(order)
            for engine,i in order:
                reps=max(1,math.ceil(2.7e9/call(ref,engine,mode,1)[0]))
                normal=call(ref,engine,mode,reps);period=(977,2077,3011)[i]
                sampled=call(sample,engine,mode,reps,dict(os.environ,FAMILY_TIMER_US=str(period),FAMILY_SAMPLES=str(raw),FAMILY_PC_PATH=str(pcs)))
                assert sampled[2:]==normal[2:] and normal[2]==accepted*reps and normal[3]==reject*reps
                offsets=array.array('i');offsets.frombytes(raw.read_bytes());names=pcs.read_text().splitlines()
                assert len(offsets)==len(names) and len(offsets)>=350
                counts=collections.defaultdict(collections.Counter)
                for tag,pc in zip(offsets,names):
                    if tag<0:assert tag==-1;stage='other'
                    else:
                        off=tag&0xffffff;phase=tag>>24;assert 0<=phase<=6 and off<len(route_bytes) and route_bytes[off]!=255
                        v=route_bytes[off];family='invalid' if v&4 else 'generic' if v&mode else 'direct'
                        stage=family+'/'+str(phase)
                    image,loc=pc.split('\t')
                    if image=='main':
                        at=int(loc,16);index=bisect.bisect_right(starts,at)-1
                        sym=symbols[index][2]if index>=0 and at<starts[index]+symbols[index][1]else '[unattributed main code]'
                    else:sym=image+'/'+loc
                    counts[stage][sym]+=1
                result[engine+'/'+str(mode)+'/'+str(i)]=dict(period=period,route_counts=route_counts,repeats=reps,samples=len(offsets),ns=normal[0]/normal[2],instrumented_ns=sampled[0]/sampled[2],checksum=normal[2:],counts=counts,raw_sha=sha(raw),pcs_sha=sha(pcs))
        return result
    return panel
