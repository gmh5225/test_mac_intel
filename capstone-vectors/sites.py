from collections import Counter
from pathlib import Path
import hashlib,re,subprocess as sp
from elftools.elf.elffile import ELFFile
tracked={'tryOutput32','tryOutput64','X86_decodeOutputMiss32','X86_decodeOutputMiss64','cs_decode_full_insn','X86_reg_access'}
def functions(path):
    with path.open('rb') as inp:
        elf=ELFFile(inp)
        bias=min(seg['p_vaddr']-seg['p_offset']for seg in elf.iter_segments()if seg['p_type']=='PT_LOAD')
        out={}
        for sym in elf.get_section_by_name('.symtab').iter_symbols():
            name=sym.name
            if name not in tracked or not sym['st_size']:continue
            assert name not in out
            sec=elf.get_section(sym['st_shndx']);addr=sym['st_value'];off=addr-sec['sh_addr']
            data=sec.data()[off:off+sym['st_size']]
            out[name]=dict(address=addr,size=len(data),sha256=hashlib.sha256(data).hexdigest())
    return out,bias
def map_debug(program,debug,src):
    actual,bias=functions(program);other,_=functions(debug)
    assert set(actual)==set(other)==tracked
    out={}
    for name,fn in actual.items():
        same=fn['sha256']==other[name]['sha256']
        dump=sp.check_output(['objdump','-d','--no-show-raw-insn','--disassemble='+name,program],text=True)
        ins={}
        for line in dump.splitlines():
            match=re.match(r'^\s*([0-9a-f]+):\s+(.+?)\s*$',line)
            if match:
                addr=int(match[1],16)
                if fn['address']<=addr<fn['address']+fn['size']:ins[addr]=dict(assembly=match[2],site=None)
        assert fn['address']in ins
        if same:
            addresses=[other[name]['address']+v-fn['address']for v in ins]
            lines=sp.check_output(['addr2line','-e',debug,*[hex(a)for a in addresses]],text=True).splitlines()
            assert len(lines)==len(ins)
            for pc,line in zip(ins,lines):
                text=line.split(' (discriminator')[0]
                if text.startswith(str(src)+'/'):text=text[len(str(src))+1:]
                ins[pc]['site']=text
        out[name]=dict(**fn,source_mapped=same,debug=other[name],instructions=ins)
    return dict(load_bias=bias,symbols=out)

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
                if ir and symbol in tracked:
                    pc=int(parts[pos.index('instr')],0);by.setdefault(symbol,Counter())[pc]+=ir;sums[symbol]+=ir
    assert whole['Ir']>0 and sums
    return dict(ir=whole['Ir'],totals=sums,by_pc=by)
