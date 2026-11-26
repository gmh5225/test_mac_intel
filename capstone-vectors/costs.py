from collections import defaultdict
from io import BytesIO
import hashlib
from pathlib import Path
import subprocess as sp
from elftools.elf.elffile import ELFFile

def symbol_layout(images):
    symbols = {}
    for stage, data in images.items():
        elf = ELFFile(BytesIO(data))
        by_name = defaultdict(list)
        for sym in elf.get_section_by_name('.symtab').iter_symbols():
            idx = sym['st_shndx']
            if sym['st_info']['type'] != 'STT_FUNC' or not isinstance(idx, int) or not sym['st_size']:
                continue
            sec = elf.get_section(idx)
            offset = sec['sh_offset'] + sym['st_value'] - sec['sh_addr']
            code = memoryview(data)[offset:offset+sym['st_size']]
            by_name[sym.name].append((sym['st_value'], len(code), hashlib.sha256(code).hexdigest()))
        symbols[stage] = {name:rows[0] for name,rows in by_name.items() if len(rows)==1}
    common = sorted(set.intersection(*(set(s) for s in symbols.values())))
    focus = [name for name in common if name in ('cs_disasm_iter','cs_decode_full_insn','cs_disasm_iter_core','cs_regs_access') or name.startswith(('X86_Intel_printInst','X86_ATT_printInst','RISCV_printInst','Mips_printInst','PPC_printInst','X86_getInstruction','cs_disasm_iter_skipdata'))]
    assert 'cs_disasm_iter' in focus and 'cs_decode_full_insn' in focus
    report = {}
    for start,end in (('base','linked'),('linked','candidate'),('base','candidate')):
        a,b = symbols[start],symbols[end]
        report[end+'/'+start] = dict(unique_functions=len(common), moved=sum(a[n][0]!=b[n][0] for n in common),
            resized=sum(a[n][1]!=b[n][1] for n in common),different_bytes=sum(a[n][2]!=b[n][2] for n in common),
            focus={n:dict(addresses=[a[n][0],b[n][0]],sizes=[a[n][1],b[n][1]],same_code=a[n][2]==b[n][2]) for n in focus})
    return report

def profile(work, invoke, command):
    native = list(map(int,sp.check_output([*invoke,*command],text=True).split()))[2:]
    dest = work/'current.profile'
    args = [*invoke,'valgrind','--tool=callgrind','--collect-atstart=no','--cache-sim=yes','--branch-sim=yes',
            '--compress-strings=no','--callgrind-out-file='+str(dest),*command]
    job = sp.run(args, text=True, capture_output=True)
    if job.returncode:
        raise RuntimeError(str(command)+'\n'+job.stderr[-4000:])
    simulated = list(map(int,job.stdout.split()))[2:]
    assert simulated == native, (command,native,simulated)
    keys,values = [],[]
    with dest.open() as stream:
        for line in stream:
            if line.startswith('events:'): keys = line.split()[1:]
            if line.startswith('totals:'): values = list(map(int,line.split()[1:]))
    from self_cost import read
    attribution=read(dest,None,None);dest.unlink()
    assert 0<len(values)<=len(keys)
    counts = dict(zip(keys,values+[0]*(len(keys)-len(values))))
    assert {'Ir','Dr','Dw','Bc','Bcm','Bi','Bim','I1mr','ILmr'}<=set(counts) and counts['Ir']>native[0]>0
    return dict(records=native,events=counts,attribution=attribution)
