import hashlib,struct,subprocess as sp
def capture(path,pie):
    data=path.read_bytes()
    magic,cpu,sub,typ,ncmds,sz,flags,res=struct.unpack_from('<8I',data)
    assert magic==0xfeedfacf and bool(flags & 0x200000)==pie,(hex(magic),hex(flags),pie)
    p=32;section=None
    for _ in range(ncmds):
        cmd,size=struct.unpack_from('<II',data,p)
        if cmd==0x19:
            n=struct.unpack_from('<I',data,p+64)[0]
            for i in range(n):
                name,seg,addr,length,off=struct.unpack_from('<16s16sQQI',data,p+72+80*i)
                if name.rstrip(b'\x00')==b'__text' and seg.rstrip(b'\x00')==b'__TEXT':section=addr,length,off
        p+=size
    assert section;addr,length,offset=section
    syms={}
    for line in sp.check_output(['nm','-n',path],text=True).splitlines():
        parts=line.split()
        if len(parts)==3 and parts[1] in ('t','T'):
            start=int(parts[0],16)
            if addr<=start<addr+length:syms[parts[2].lstrip('_')]=start
    wanted=('X86_scanNativeBatch','X86_disasmIter32','cs_disasm_iter','X86_getInstruction','X86_decodePublicRecord','X86_disasmIterText','X86_scanInstruction')
    locs=sorted(set(syms.values())|{addr+length});result={}
    for name in wanted:
        if name not in syms:continue
        pc=syms[name];end=locs[locs.index(pc)+1];idx=pc-addr+offset
        result[name]=dict(address=pc,bytes=end-pc,sha256=hashlib.sha256(data[idx:idx+end-pc]).hexdigest())
    assert 'X86_scanNativeBatch'in result and 'cs_disasm_iter'in result
    return dict(pie=pie,functions=result)
