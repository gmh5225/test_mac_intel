"""Record the relocatable iterator instructions and every call-site relocation."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys
import tempfile

archive, image, dest = map(Path, sys.argv[1:])
with tempfile.TemporaryDirectory() as work:
    work = Path(work)
    obj = work / 'iterator.o'
    obj.write_bytes(subprocess.check_output(['ar','p',archive,'X86DisassemblerDecoder.c.o']))
    symbols = subprocess.check_output(['objdump','-t',obj],text=True).splitlines()
    symbol, = [s.split() for s in symbols if s.split() and s.split()[-1] == 'cs_disasm_iter']
    start = int(symbol[0],16)
    section = symbol[-3]
    size = int(symbol[-2],16)
    contents = work / 'section'
    subprocess.run(['objcopy','--dump-section',section+'='+str(contents),obj], check=True)
    code = contents.read_bytes()[start:start+size]
    assert len(code) == size and size > 0
    refs = []
    relocations = subprocess.check_output(['objdump','-r','-j',section,obj],text=True)
    for line in relocations.splitlines():
        parts = line.split()
        if len(parts) != 3 or not re.fullmatch('[a-fA-F0-9]+',parts[0]):
            continue
        offset = int(parts[0],16)
        if start <= offset < start+size:
            refs.append((offset-start,parts[1],parts[2]))
    # Collect the large full-decoder and private entry functions independently.
    functions = {}
    for member,wanted_names in [('cs.c.o',['cs_decode_full_insn','cs_decode_public_full_insn']),('X86Vex32Output.c.o',['X86_disasmIter32','tryOutput32']),('X86Sse64Output.c.o',['X86_disasmIterText','tryOutput64'])]:
        member_path = work/member
        member_path.write_bytes(subprocess.check_output(['ar','p',archive,member]))
        syms=subprocess.check_output(['objdump','-t',member_path],text=True).splitlines()
        for name in wanted_names:
            matches=[s.split() for s in syms if s.split() and s.split()[-1]==name]
            if not matches:continue
            line,=matches
            addr=int(line[0],16)
            # objdump prints visibility between the size and the symbol for hidden entries.
            fields=line[3:]
            sec=fields[0]; length=int(fields[1],16)
            f=work/(member+name)
            subprocess.run(['objcopy','--dump-section',sec+'='+str(f),member_path],check=True)
            func=f.read_bytes()[addr:addr+length]
            assert len(func)==length and length>0
            reloc=[]
            for raw in subprocess.check_output(['objdump','-r','-j',sec,member_path],text=True).splitlines():
                tok=raw.split()
                if len(tok)==3 and re.fullmatch('[a-f0-9]+',tok[0]) and addr<=int(tok[0],16)<addr+length:
                    reloc.append([int(tok[0],16)-addr,*tok[1:]])
            functions[name]=dict(size=length,code=hashlib.sha256(func).hexdigest(),relocations=reloc)
    addresses = {}
    wanted = {'cs_disasm_iter','X86_tryIteratorOutput32','X86_tryIteratorOutput64','cs_decode_public_full_insn','X86_decodeIteratorOutput','X86_disasmIter32','X86_disasmIterText',
              'cs_decode_full_insn','AArch64_getInstruction','Mips_getInstruction','RISCV_getInstruction','X86_getInstruction'}
    for line in subprocess.check_output(['nm','-S','--defined-only',image],text=True).splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[-1] in wanted:
            addresses[parts[-1]] = [int(parts[0],16),int(parts[1],16)]
    assert 'cs_disasm_iter' in addresses and (len(refs)>0 or size<64)
    adapter_code = []
    if 'X86_decodeIteratorOutput' in addresses:
        raw = subprocess.check_output(['objdump','-d','--disassemble=X86_decodeIteratorOutput',image],text=True)
        adapter_code=[line.strip() for line in raw.splitlines() if re.match(r'^\s*[0-9a-f]+:',line)][:100]
    full_code = {}
    for name in ('cs_decode_full_insn','cs_decode_public_full_insn'):
        if name not in addresses: continue
        asm=subprocess.check_output(['objdump','-d','--disassemble='+name,image],text=True)
        lines=[v.strip() for v in asm.splitlines() if re.match(r'^\s*[0-9a-f]+:',v)]
        full_code[name]=dict(bytes=addresses[name][1],entry=lines[:36],calls=[v for v in lines if 'call' in v])
    dest.write_text(json.dumps({'bytes':size,'section':section,'sha256':hashlib.sha256(code).hexdigest(),
                               'relocations':refs,'object_functions':functions,'linked_symbols':addresses,'adapter_assembly':adapter_code,'full_entry_assembly':full_code},indent=2)+'\n')
