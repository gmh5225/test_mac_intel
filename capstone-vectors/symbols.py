from bisect import bisect_right
from collections import Counter,defaultdict
from functools import lru_cache
from pathlib import Path
from debug_names import resolve as shared_symbol
import math,os,random,re,subprocess as sp
@lru_cache(maxsize=None)
def direct_calls(image):
    # Confirm the saved PC is the exact return address of a direct branch
    # in this executable to a PLT entry for the sampled libc implementation.
    calls={}
    pat=re.compile(r'^\s*([0-9a-f]+):\s+(.*)')
    branch=re.compile(r'(?:callq?|bl)\s+[0-9a-fx]+\s+<(strlen|strnlen|memcpy|memmove|memset|memcmp|strcmp)@plt>')
    pending=None
    with sp.Popen(['objdump','-dw','--no-show-raw-insn',image],stdout=sp.PIPE,text=True,errors='replace') as dis:
        for line in dis.stdout:
            m=pat.match(line)
            if not m:continue
            addr=int(m[1],16)
            if pending is not None:
                site,name=pending
                if 0<addr-site<=15:calls[addr]=(site,name)
            match=branch.fullmatch(m[2].strip())
            pending=(addr,match[1]) if match else None
        assert dis.wait()==0
    assert len(calls)>20 and {'memcpy','strlen'}<={v[1] for v in calls.values()}
    return calls

ROUTES={'capstone-text':('private',1),'iced-text':('fast',1),
        'capstone-details':('private',2),'iced-details':('fast',2),
        'capstone-operands':('private',4),'iced-operands':('fast',4),
        'capstone-scan':('private',0),'iced-scan':('iced',0)}
def symbolizer(binary):
    lines=sp.check_output(['nm','-n','-S','-C','--defined-only',binary],text=True).splitlines()
    starts={};sizes={}
    for line in lines:
        cols=line.split(maxsplit=3)
        if len(cols)!=4 or cols[2] not in ('t','T','w','W','i','I'):continue
        addr=int(cols[0],16);size=int(cols[1],16)
        if size>sizes.get(addr,0):starts[addr]=cols[3];sizes[addr]=size
    ordered=sorted(starts);assert len(ordered)>1000
    @lru_cache(maxsize=None)
    def resolve(addr):
        i=bisect_right(ordered,addr)-1
        if i>=0:
            start=ordered[i]
            if addr<start+sizes[start]:return starts[start],addr-start
        return '[executable padding or unnamed code]',0
    return resolve

def case(name,bits,work,image,fixture,extents,save):
    resolve=symbolizer(image)
    calls=direct_calls(image);callers={tag:Counter() for tag in ROUTES}
    def take(tag,reps,env=None):
        engine,mode=ROUTES[tag]
        args=['setarch',os.uname().machine,'-R']
        if env:args+=['env',*env]
        return list(map(int,sp.check_output([*args,image,engine,str(mode),str(reps),fixture,extents,str(bits)],text=True).split()))
    libc_ids=set()
    path=work/'saved-pcs.tsv'
    meta={};seen={}
    for tag in ROUTES:
        first=take(tag,1);n=max(1,math.ceil(2.8e9/first[0]))
        meta[tag]={'repeats':n,'first':first,'expected':take(tag,n)}
        assert first[2]>0 and meta[tag]['expected'][2]==first[2]*n
    assert len({tuple(x['first'][2:5])for x in meta.values()})==1
    hist={k:Counter()for k in ROUTES};insns={k:Counter()for k in ROUTES}
    rng=random.Random(name);order=list(ROUTES)
    for epoch,(initial,period) in enumerate([(311,997),(947,1627),(193,2161)]):
        rng.shuffle(order)
        for tag in order:
            v=meta[tag];r=take(tag,v['repeats'],['LD_PRELOAD='+str(work/'sample.so'),f'SAMPLE_INITIAL_US={initial}',f'SAMPLE_PERIOD_US={period}','SAMPLE_OUTPUT='+str(path)])
            assert r[2:]==v['expected'][2:]
            freq=Counter();pcs=Counter()
            for line in path.read_text().splitlines():
                pc,lib,sym,relative,ret=line.split('\t');pc=int(pc,16)
                if Path(lib).name==image.name:
                    name_at,offset=resolve(pc);freq[name_at]+=1;pcs[pc]+=1
                elif Path(lib).name=='libc.so.6':
                    exact,build_id=shared_symbol(lib,int(relative,16));libc_ids.add(build_id)
                    leaf='libc.so.6!'+exact;freq[leaf]+=1
                    site=calls.get(int(ret,16));owner='[unresolved]'
                    if site and site[1] in exact.lower():
                        method,off=resolve(site[0]);owner=method+' + '+hex(off)+' -> '+site[1]
                    callers[tag][leaf,owner]+=1
                else:freq[Path(lib).name+': '+sym]+=1
            samples=sum(freq.values());assert samples>=160,(name,tag,epoch,r,samples)
            hist[tag].update(freq);insns[tag].update(pcs)
            seen.setdefault(tag,[]).append(dict(samples=samples,cpu_ns=r[0],wall_ns=r[1],top=freq.most_common(25)))
    for tag in ROUTES:
        top=[]
        for addr,n in insns[tag].most_common(16):
            name_at,offset=resolve(addr)
            assembly=sp.check_output(['objdump','-d','--no-show-raw-insn','--start-address='+hex(addr),'--stop-address='+hex(addr+16),image],text=True,errors='replace')
            steps=[line.strip()for line in assembly.splitlines()if ':' in line and line.lstrip()[:1] in '0123456789abcdef' and '<' not in line.split(':')[0]]
            top.append(dict(pc=hex(addr),samples=n,function=name_at,offset=offset,instructions=steps[:3]))
        meta[tag].update(samples=sum(hist[tag].values()),epochs=seen[tag],symbols=hist[tag].most_common(),top_instructions=top)
    for tag,v in meta.items():
        v['libc_callsites']=[[leaf,owner,n]for (leaf,owner),n in callers[tag].most_common()]
        assert sum(callers[tag].values())==sum(n for leaf,n in v['symbols']if leaf.startswith('libc.so.6!'))
    assert len(libc_ids)==1
    save('libc-build-id',dict(build_id=next(iter(libc_ids))))
    save('symbols-'+name,meta)
    return {tag:v['samples']for tag,v in meta.items()}
