"""Read the actual linked iterator, including its direct callees and stack probes."""
import re
import shutil
import subprocess
from pathlib import Path
import os

def inspect(executable, map_file, evidence):
    symbols = {}
    for line in map_file.read_text(errors='replace').splitlines():
        label = re.match(r'^\s*[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{12,16})\s+',line)
        if label:
            symbols.setdefault(int(label[2], 16), []).append(label[1])
    starts = sorted(symbols)
    selected = {'cs_disasm_iter','cs_decode_full_insn','X86_getInstruction','X86_getInstructionScanResult','X86_getInstructionAfterExtensions','X86_decodeScanBatch','X86_scanBatch','decodeInstructionScan','decodeInstructionFull'}
    seen = set()
    result = {}
    objdump = shutil.which('llvm-objdump') or str(Path(os.environ['ProgramFiles'])/'LLVM/bin/llvm-objdump.exe')
    for i,address in enumerate(starts[:-1]):
        names = selected.intersection(symbols[address])
        if not names:
            continue
        name=sorted(names)[0];seen.update(names)
        end=starts[i+1]
        listing=subprocess.check_output([objdump,'-d','--no-show-raw-insn','--start-address='+hex(address),'--stop-address='+hex(end),executable],text=True,errors='replace')
        lines=[];calls={}
        for line in listing.splitlines():
            match=re.match(r'^\s*([\da-f]+):\s+([a-z][a-z0-9]*)\s*(.*)$',line)
            if not match:continue
            asm=match[2]+' '+match[3]
            if match[2].startswith(('call','jmp')) and (target:=re.match(r'0x([0-9a-f]+)',match[3])):
                target_names=symbols.get(int(target[1],16),[])
                if target_names:
                    target_name='/'.join(target_names[:3]);asm+='  ; '+target_name
                    if match[2].startswith('call'):calls[target_name]=calls.get(target_name,0)+1
            lines.append(hex(int(match[1],16)-address)+' '+asm)
        assert lines, (name,hex(address),hex(end))
        (evidence/(executable.stem+'-'+name+'.asm')).write_text('\n'.join(lines)+'\n')
        result[name]=dict(start=hex(address),span=end-address,decoded=len(lines),calls=calls,entry=lines[:18])
    assert 'cs_disasm_iter' in seen, seen
    return result
