from bisect import bisect_right
from collections import Counter,defaultdict
from functools import lru_cache
from pathlib import Path
import math,os,random,subprocess as sp

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
    def take(tag,reps,env=None):
        engine,mode=ROUTES[tag]
        args=['setarch',os.uname().machine,'-R']
        if env:args+=['env',*env]
        return list(map(int,sp.check_output([*args,image,engine,str(mode),str(reps),fixture,extents,str(bits)],text=True).split()))
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
                pc,lib,sym=line.split('\t');pc=int(pc,16)
                if Path(lib).name==image.name:
                    name_at,offset=resolve(pc);freq[name_at]+=1;pcs[pc]+=1
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
    save('symbols-'+name,meta)
    return {tag:v['samples']for tag,v in meta.items()}
