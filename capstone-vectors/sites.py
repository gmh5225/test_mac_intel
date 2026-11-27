from collections import Counter
from pathlib import Path
import hashlib,re,subprocess as sp
from elftools.elf.elffile import ELFFile
tracked={'cs_disasm_iter','cs_decode_full_insn','X86_disasmIterText','X86_getInstruction','X86_reg_access',
         'SStream_trimls','SStream_Init','SStream_opt_unum','SStream_concat','SStream_concat0','SStream_concat1',
         'X86_Intel_printInst','X86_postprinter','printOperand','printMemReference','decodeInstructionFull',
         'readOperands','translateRMMemoryFull','X86_Intel_printInstructionPrechecked','readModRM'}
required={'cs_disasm_iter','cs_decode_full_insn','SStream_trimls','SStream_Init','SStream_opt_unum',
          'X86_getInstruction','X86_Intel_printInst','X86_postprinter','printOperand','printMemReference'}
def functions(path):
    with path.open('rb') as inp:
        elf=ELFFile(inp)
        bias=min(seg['p_vaddr']-seg['p_offset']for seg in elf.iter_segments()if seg['p_type']=='PT_LOAD')
        groups={}
        for sym in elf.get_section_by_name('.symtab').iter_symbols():
            name=sym.name
            if name not in tracked or not sym['st_size'] or sym['st_info']['type']!='STT_FUNC':continue
            sec=elf.get_section(sym['st_shndx']);addr=sym['st_value'];off=addr-sec['sh_addr']
            data=sec.data()[off:off+sym['st_size']]
            groups.setdefault(name,[]).append(dict(name=name,address=addr,size=len(data),sha256=hashlib.sha256(data).hexdigest()))
    assert required<=set(groups),required-set(groups)
    return groups,bias

def map_debug(program,debug,src):
    actual,bias=functions(program);other,_=functions(debug)
    out={};covered=set()
    for sym,entries in actual.items():
        for fn in sorted(entries,key=lambda v:v['address']):
            name=sym if len(entries)==1 else sym+'@'+hex(fn['address'])
            equivalents=[v for v in other.get(sym,[]) if fn['sha256']==v['sha256']]
            match=next((v for v in equivalents if v['address']==fn['address']),None)
            if match is None and len(equivalents)==1:match=equivalents[0]
            lo=fn['address'];hi=lo+fn['size']
            dump=sp.check_output(['objdump','-d','--no-show-raw-insn','--start-address='+hex(lo),'--stop-address='+hex(hi),program],text=True)
            ins={}
            for line in dump.splitlines():
                m=re.match(r'^\s*([0-9a-f]+):\s+(.+?)\s*$',line)
                if m:
                    pc=int(m[1],16)
                    if lo<=pc<hi:ins[pc]=dict(assembly=m[2],site=None)
            assert lo in ins and not covered.intersection(ins)
            covered.update(ins)
            if match:
                pcs=list(ins)
                for i in range(0,len(pcs),1500):
                    batch=pcs[i:i+1500]
                    lines=sp.check_output(['addr2line','-e',debug,*[hex(match['address']+pc-lo) for pc in batch]],text=True).splitlines()
                    assert len(lines)==len(batch)
                    for pc,line in zip(batch,lines):
                        loc=line.split(' (discriminator')[0]
                        if loc.startswith(str(src)+'/'):loc=loc[len(str(src))+1:]
                        ins[pc]['site']=loc
            out[name]=dict(**fn,source_mapped=bool(match),debug=match,instructions=ins)
    return dict(load_bias=bias,symbols=out)

owners={}
def set_owners(symbols):
    for name,fn in symbols['symbols'].items():
        for pc in fn['instructions']:
            assert pc not in owners
            owners[pc]=name

def counts(path):
    by={};sums=Counter();whole=Counter();symbol=None;edge=False;pos=None;events=[]
    with path.open()as inp:
        for raw in inp:
            line=raw.rstrip()
            if line.startswith('events:'):events=line.split()[1:]
            elif line.startswith('positions:'):
                pos=line.split()[1:];assert 'instr'in pos
            elif line.startswith('fn='):symbol=line[3:].split("'")[0]
            elif line.startswith(('calls=','jump=','jcnd=')):edge=True
            elif line and line[0].isdigit():
                parts=line.split()
                if edge:edge=False;continue
                n=len(pos);ir=int(parts[n+events.index('Ir')]) if len(parts)>n+events.index('Ir')else 0
                whole['Ir']+=ir
                if ir:
                    pc=int(parts[pos.index('instr')],0);owner=owners.get(pc)
                    if owner is not None:
                        by.setdefault(owner,Counter())[pc]+=ir;sums[owner]+=ir
    assert whole['Ir']>0 and sums
    return dict(ir=whole['Ir'],totals=sums,by_pc=by)
