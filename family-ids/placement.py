import hashlib,struct,subprocess
def inspect(file):
    data=file.read_bytes();assert data[:6]==b'\x7fELF\x02\x01'
    off=struct.unpack_from('<Q',data,40)[0];sz,n=struct.unpack_from('<HH',data,58)
    sections=[struct.unpack_from('<IIQQQQIIQQ',data,off+j*sz)for j in range(n)]
    names=('PPC_getInstruction','PPC_LLVM_getInstruction','PPC_printer','PPC_printInst','cs_disasm_iter','cs_decode_full_insn','AArch64_add_vas','SStream_trimls')
    result={}
    for line in subprocess.check_output(['nm','-S','-n','--defined-only',file],text=True).splitlines():
        row=line.split()
        if len(row)!=4 or row[3] not in names:continue
        va,size=int(row[0],16),int(row[1],16)
        sec,=(s for s in sections if s[1]==1 and s[2]&4 and s[3]<=va and va+size<=s[3]+s[5])
        addr=sec[4]+va-sec[3];body=data[addr:addr+size]
        result[row[3]]=dict(address=va,size=size,sha256=hashlib.sha256(body).hexdigest())
    assert {'PPC_getInstruction','cs_disasm_iter','AArch64_add_vas'}<=result.keys()
    return result
