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
    addresses = {}
    wanted = {'cs_disasm_iter','X86_disasmIterCanonical','disasm_iter_foreign','X86_decodeIteratorOutput','X86_disasmIter32','X86_disasmIterText',
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
    dest.write_text(json.dumps({'bytes':size,'section':section,'sha256':hashlib.sha256(code).hexdigest(),
                               'relocations':refs,'linked_symbols':addresses,'adapter_assembly':adapter_code},indent=2)+'\n')
