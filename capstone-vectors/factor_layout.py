import hashlib,os,platform,random,struct,subprocess
def locate(file):
    data=file.read_bytes()
    assert data[:6]==b'\x7fELF\x02\x01'
    off=struct.unpack_from('<Q',data,40)[0];sz,n,index=struct.unpack_from('<HHH',data,58)
    table=[struct.unpack_from('<IIQQQQIIQQ',data,off+j*sz)for j in range(n)]
    ss=table[index];names=data[ss[4]:ss[4]+ss[5]];sections={}
    for v in table:
        name=names[v[0]:names.index(b'\0',v[0])].decode()
        if name in ('.text','.rodata') or name.startswith('.cs_x86_') and v[5]:
            sections[name]=dict(address=v[3],size=v[5],sha256=hashlib.sha256(data[v[4]:v[4]+v[5]]).hexdigest())
    fo=struct.unpack_from('<Q',data,32)[0];w,count=struct.unpack_from('<HH',data,54)
    segments=[struct.unpack_from('<IIQQQQQQ',data,fo+j*w) for j in range(count)]
    assert not any(t==1 and (flags&3)==3 for t,flags,*_ in segments)
    routines={}
    hot={'tryOutput32','tryOutput64','X86_disasmIterText','writeVectorRegisters','X86_writeVectorOutput','writeEvexOutput','cs_decode_full_insn','X86_disasmIter32','X86_writeMemoryOutput','X86_writeImmediateOutput','writeRegisterImmediate','writeAluMemory32','writeAluMemory64'}
    for line in subprocess.check_output(['nm','-S','-n','--defined-only',file],text=True).splitlines():
        vals=line.split()
        if len(vals)!=4 or vals[3] not in hot:continue
        va,size=int(vals[0],16),int(vals[1],16);s,=(t for t in table if t[1]==1 and t[2]&4 and t[3]<=va and va+size<=t[3]+t[5])
        addr=s[4]+va-s[3];routines[vals[3]]=dict(address=va,size=size,sha256=hashlib.sha256(data[addr:addr+size]).hexdigest())
    assert {'X86_disasmIter32','X86_disasmIterText','writeVectorRegisters'}<=routines.keys()
    return dict(sha256=hashlib.sha256(data).hexdigest(),routines=routines,sections=sections)

def paired(w,image,payloads,case,bits,path,intervals,mode):
    bind=['setarch',platform.machine(),'-R']
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    ino=image.stat().st_ino
    def call(k,n):
        with image.open('r+b') as f:f.write(payloads[k])
        assert image.stat().st_ino==ino
        return list(map(int,subprocess.check_output([*bind,image,'x86_iter',str(mode),str(n),path,intervals,str(bits)],text=True).split()))
    first=call('baseline',1);assert first[0]>0
    reps=max(1,min(4096,round(55_000_000/first[0])));ref=call('baseline',reps)
    labels=['baseline','aa',*[str(v)for v in range(1,7)],'integrated'];rng=random.Random(str((case,mode)));cycles=[]
    for i in range(17):
        order=labels[:];rng.shuffle(order);obs={k:[]for k in labels}
        for k in order+order[::-1]:
            z=call(k,reps);assert z[2:]==ref[2:] and z[0]>0
            obs[k].append(z[:2])
        cycles.append(obs)
    return dict(case=case,bits=bits,mode=mode,cycles=cycles,reps=reps,signature=ref[2:])

