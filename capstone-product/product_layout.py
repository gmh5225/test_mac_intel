"""Allocated ELF sections and executable bytes of the decoder functions used by the product harness."""
import hashlib,struct,subprocess
def record_layout(exe):
    image=exe.read_bytes();assert image[:6]==b'\x7fELF\x02\x01'
    fields=struct.unpack_from('<16sHHIQQQIHHHHHH',image);offset=fields[6];stride,count,names=fields[-3:]
    assert stride==64 and count>0 and 0<names<count
    sections=[struct.unpack_from('<IIQQQQIIQQ',image,offset+i*stride)for i in range(count)]
    strtab=sections[names];strings=image[strtab[4]:strtab[4]+strtab[5]]
    mapped={};text={}
    for sec in sections:
        index,typ,flags,address,start,length,*_=sec
        if not flags&2:continue
        name=strings[index:strings.index(0,index)].decode()
        mapped[name]=[address,length,None if typ==8 else hashlib.sha256(image[start:start+length]).hexdigest()]
        if flags&4:text[name]=(address,start,length)
    symbols={}
    for line in subprocess.check_output(['nm','-nS','--defined-only',exe],text=True).splitlines():
        values=line.split(maxsplit=3)
        if len(values)!=4 or values[2] not in ('t','T','w','W'):continue
        name=values[3]
        if not any(k in name for k in ('Mips','MIPS','mips','X86_','cs_decode_full_insn','cs_disasm_iter','decodePublic','DisasmIter','decodeInstruction','fill_insn','cs_disasm','neverd6decode')):continue
        at,size=[int(x,16)for x in values[:2]]
        span=next(((start+at-base,n)for base,start,n in text.values()if base<=at<base+n and at+size<=base+n),None)
        if span:symbols[name]=[at,size,hashlib.sha256(image[span[0]:span[0]+size]).hexdigest()]
    assert len(symbols)>80
    return dict(sections=mapped,symbols=symbols)
