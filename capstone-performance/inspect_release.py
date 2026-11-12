"""Read the actual linked iterator, including its direct callees and stack probes."""
import re
import shutil
import subprocess
from pathlib import Path
import os
import struct
import hashlib

def inspect(executable, map_file, evidence):
    symbols = {}
    for line in map_file.read_text(errors='replace').splitlines():
        label = re.match(r'^\s*[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{12,16})\s+',line)
        if label:
            symbols.setdefault(int(label[2], 16), []).append(label[1])
    pe=executable.read_bytes();nt=struct.unpack_from('<I',pe,60)[0];opt=nt+24
    assert struct.unpack_from('<H',pe,opt)[0]==0x20b
    imagebase=struct.unpack_from('<Q',pe,opt+24)[0]
    ex_rva,ex_len=struct.unpack_from('<II',pe,opt+112+3*8)
    section=opt+struct.unpack_from('<H',pe,nt+20)[0];sections=struct.unpack_from('<H',pe,nt+6)[0]
    end_for={}
    for off in range(section,section+sections*40,40):
        virt,rva,length,raw=struct.unpack_from('<IIII',pe,off+8)
        if rva<=ex_rva and ex_rva+ex_len<=rva+length:
            assert ex_len%12==0
            at=raw+(ex_rva-rva)
            for first,last,unwind in struct.iter_unpack('<III',pe[at:at+ex_len]):
                if first and last>first:end_for[imagebase+first]=imagebase+last
    assert end_for
    starts = sorted(symbols)
    selected = {'X86_Intel_printInst','X86_ATT_printInst','X86_reg_access','X86_get_insn_id','get_op_access','X86_insn_reg_intel2','X86_insn_reg_att2','X86_insn_reg_intel_h','X86_insn_reg_att_h','cs_disasm_iter','cs_disasm_iter_outlined','diagnosticScanFallback','cs_decode_full_insn','X86_getInstruction','X86_getInstructionScanResult','X86_getInstructionAfterExtensions','X86_decodeScanBatch','X86_scanBatch','decodeInstructionScan','decodeInstructionFull'}
    selected.update(name for names in symbols.values() for name in names if name.startswith('?run@@') or name == 'main')
    seen = set()
    result = {}
    objdump = shutil.which('llvm-objdump') or str(Path(os.environ['ProgramFiles'])/'LLVM/bin/llvm-objdump.exe')
    for i,address in enumerate(starts[:-1]):
        names = selected.intersection(symbols[address])
        if not names:
            continue
        name=sorted(names)[0];seen.update(names)
        end=end_for.get(address,min(starts[i+1],address+32768))
        listing=subprocess.check_output([objdump,'-d','--no-show-raw-insn','--start-address='+hex(address),'--stop-address='+hex(min(end,address+(65536 if name in {'X86_Intel_printInst','X86_ATT_printInst','X86_reg_access','X86_get_insn_id','get_op_access','X86_insn_reg_intel2','X86_insn_reg_att2','X86_insn_reg_intel_h','X86_insn_reg_att_h'} else 320))),executable],text=True,errors='replace')
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
        safe_name = 'consumer_run' if name.startswith('?run@@') else name
        (evidence/(executable.stem+'-'+safe_name+'.asm')).write_text('\n'.join(lines)+'\n')
        listing_hash=hashlib.sha256('\n'.join(lines).encode()).hexdigest()
        result[name]=dict(start=hex(address),span=end-address,decoded_prefix_instructions=len(lines),unwind_extent=address in end_for,sha256=listing_hash,calls=calls,entry=lines[:35])
    assert result, seen
    return result
