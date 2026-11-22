from pathlib import Path
import hashlib,subprocess as sp,shutil,shlex

printers=('SystemZInstPrinter.c.o','XtensaInstPrinter.c.o')
rv=('RISCVDisassembler.c.o','RISCVInstPrinter.c.o','RISCVModule.c.o')
targets=('RISCV_getInstruction','RISCV_LLVM_printInstruction','RISCV_disasm','cs_disasm_iter','SystemZ_printInst','Xtensa_printInst','SStream_concat0','matchRISCVAliasPatterns')
def record(build,library,where):
    where.mkdir(exist_ok=True)
    stats={}
    for member in printers+rv:
        obj,=build.rglob(member)
        if member in printers:shutil.copy2(obj,where/member)
        raw=where/(member+'.text');sp.run(['objcopy','--dump-section','.text='+str(raw),obj,where/(member+'.copy')],check=True)
        stats[member]=dict(size=raw.stat().st_size,sha256=hashlib.sha256(raw.read_bytes()).hexdigest())
    return dict(objects=stats,symbols=symbols(library))
def symbols(lib):
    sym={}
    for line in sp.check_output(['nm','-S','-n','--defined-only',lib],text=True).splitlines():
        z=line.split()
        if len(z)==4 and z[3]in targets:sym[z[3]]=[int(z[0],16),int(z[1],16)]
    assert 'cs_disasm_iter' in sym and 'RISCV_getInstruction' in sym and 'RISCV_LLVM_printInstruction' in sym
    return sym
def text_relocations(obj):
    records=[]
    reloc_text=False
    for line in sp.check_output(['readelf','-rW',obj],text=True).splitlines():
        if line.startswith("Relocation section "):
            reloc_text=line.split("'")[1] in (".rela.text",".rel.text")
        elif reloc_text:
            fields=line.split()
            if len(fields)>=3 and fields[2].startswith('R_'):
                records.append((int(fields[0],16),fields[2]))
    return sorted(records)
def pad_object(original,obj,tmp,amount):
    if not amount:
        shutil.copy2(original,obj)
        return
    asm=tmp/'padding.s'
    asm.write_text(chr(10).join(['.text','.space '+str(amount),'.section .note.GNU-stack,"",%progbits','']))
    sp.run(['cc','-c',asm,'-o',tmp/'padding.o'],check=True)
    sp.run(['ld','-r','-o',obj,original,tmp/'padding.o'],check=True)
def padded(build,library,tmp,mode,stats):
    extent={}
    for member in printers:
        included=[stats[k]['objects'][member]['size']for k in ('base','both')]
        length=max(included);raw=(tmp/mode/(member+'.text')).read_bytes()
        obj,=build.rglob(member)
        original=tmp/mode/member
        pad_object(original,obj,tmp,length-len(raw))
        relocs=text_relocations(original)
        assert relocs and text_relocations(obj)==relocs,(member,len(relocs),len(text_relocations(obj)))
        extent[member]=dict(original=len(raw),padded=length,text_relocations=len(relocs))
    # Relink the library without asking Ninja to recompile the controlled objects.
    commands=sp.check_output(['ninja','-C',build,'-t','commands','capstone_shared'],text=True)
    links=[]
    for line in commands.splitlines():
        if ' -shared ' not in line:continue
        words=shlex.split(line);output=words[words.index('-o')+1] if '-o' in words else ''
        if Path(output).name!=library.name:continue
        i=words.index('-shared')
        first=max((j+1 for j,v in enumerate(words[:i])if v=='&&'),default=0)
        last=next((j for j in range(i,len(words))if words[j]=='&&'),len(words))
        links.append(words[first:last])
    assert len(links)==1,(library,links)
    sp.run(links[0],cwd=build,check=True)
    check=tmp/('verify-'+mode);check.mkdir()
    for member in printers:
        obj,=build.rglob(member);sec=check/(member+'.text')
        sp.run(['objcopy','--dump-section','.text='+str(sec),obj,check/member],check=True)
        data=sec.read_bytes();expected=(tmp/mode/(member+'.text')).read_bytes()
        assert data==expected+bytes(extent[member]['padded']-len(expected))
    return dict(extents=extent,symbols=symbols(library))
