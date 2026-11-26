from pathlib import Path
import hashlib,json,math,os,random,shutil,subprocess as sp
def compare_files(w,binaries):
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    files={k:p.read_bytes() for k,p in binaries.items()};length=max(map(len,files.values()))
    images={k:v+bytes(length-len(v))for k,v in files.items()};images['duplicate']=images['base']
    selected=w/'selected-native';shutil.copy2(binaries['base'],selected);selected.write_bytes(images['base'])
    block=4096;offsets=[i for i in range(0,length,block) if len({v[i:i+block]for v in images.values()})>1]
    assert offsets;ino=selected.stat().st_ino;checked={}
    def select(tag):
        with selected.open('r+b',buffering=0) as f:
            for i in offsets:
                f.seek(i);part=images[tag][i:i+block];assert f.write(part)==len(part)
        assert selected.stat().st_ino==ino and selected.stat().st_size==length
        if tag not in checked:
            digest=hashlib.sha256(selected.read_bytes()).hexdigest();assert digest==hashlib.sha256(images[tag]).hexdigest()
            checked[tag]=digest
    def timing(sample,target,text,spans,bits):
        def one(tag,mode,n):
            select(tag)
            return list(map(int,sp.check_output(['setarch',os.uname().machine,'-R',selected,'private',str(mode),str(n),text,spans,str(bits)]).split()))
        results={}
        for mode in (0,1,2):
            n=max(1,math.ceil(28e6/one('base',mode,1)[0]))
            truth=one('base',mode,n)[2:];assert truth[0]==target*n
            rng=random.Random('reg-suffix-source/'+sample+'/'+str(mode));trials=[]
            keys=list(images)
            for _ in range(35):
                rng.shuffle(keys);counts={k:[0,0] for k in keys}
                for k in keys+keys[::-1]:
                    row=one(k,mode,n);assert row[2:]==truth,(sample,mode,k,row,truth)
                    for i in (0,1):counts[k][i]+=row[i]
                trials.append(counts)
            results[str(mode)]=dict(repeats=n,records=truth,cycles=trials)
        return results
    return timing,checked

def symbols(binary):
    names=('X86_disasmIter32','X86_disasmIterText','X86_disasmIterScan','X86_scanNativeBatch','cs_disasm_iter','X86_reg_access')
    result={}
    for line in sp.check_output(['nm','-S','--defined-only',binary],text=True).splitlines():
        cols=line.split()
        if len(cols)!=4 or cols[-1] not in names:continue
        addr,size,_,name=cols
        asm=sp.check_output(['objdump','-d','--no-show-raw-insn','--disassemble='+name,binary],text=True)
        rows=[s.split(':',1)[1].strip() for s in asm.splitlines() if ':' in s and s.split(':',1)[0].strip() and all(c in '0123456789abcdef' for c in s.split(':',1)[0].strip())]
        assert rows
        result[name]=dict(address=int(addr,16),length=int(size,16),assembly=hashlib.sha256('\n'.join(rows).encode()).hexdigest(),instructions=len(rows))
    assert {'cs_disasm_iter','X86_scanNativeBatch','X86_disasmIterText'}<=set(result)
    return result
