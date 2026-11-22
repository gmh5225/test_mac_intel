from pathlib import Path
import hashlib,subprocess as sp,shutil

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
def padded(build,library,tmp,mode,stats):
    extent={}
    for member in printers:
        included=[stats[k]['objects'][member]['size']for k in ('base','both')]
        length=max(included);raw=(tmp/mode/(member+'.text')).read_bytes()
        padded=tmp/(member+'.pad');padded.write_bytes(raw+bytes(length-len(raw)))
        obj,=build.rglob(member)
        sp.run(['objcopy','--update-section','.text='+str(padded),tmp/mode/member,obj],check=True)
        extent[member]=dict(original=len(raw),padded=length)
    sp.run(['cmake','--build',build,'--parallel','4','--target','capstone_shared'],check=True)
    check=tmp/('verify-'+mode);check.mkdir()
    for member in printers:
        obj,=build.rglob(member);sec=check/(member+'.text')
        sp.run(['objcopy','--dump-section','.text='+str(sec),obj,check/member],check=True)
        data=sec.read_bytes();expected=(tmp/mode/(member+'.text')).read_bytes()
        assert data==expected+bytes(extent[member]['padded']-len(expected))
    return dict(extents=extent,symbols=symbols(library))
