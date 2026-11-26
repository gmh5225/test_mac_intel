"""Read exclusive event rows from the Callgrind file format, separate from call edges."""
from collections import Counter
import gzip,hashlib,re,shutil
def checksum(stream):
    digest=hashlib.sha256()
    for block in iter(lambda: stream.read(1<<20),b''):digest.update(block)
    return digest.digest()
def read(path,out,prefix):
    seen={};by_symbol={};symbols={};function=None;object_name=None;edge=False
    events=positions=None;totals=None;callee=None;calls=Counter()
    with path.open() as inp:
        for raw in inp:
            line=raw.rstrip()
            if line.startswith('events:'):events=line.split()[1:]
            elif line.startswith('positions:'):positions=line.split()[1:]
            elif line.startswith('totals:'):totals=list(map(int,line.split()[1:]))
            elif line.startswith(('cfn=','fn=','cob=','ob=')):
                tag,value=line.split('=',1);kind=tag.lstrip('c');m=re.match(r'\((\d+)\)(?: (.*))?$',value)
                if m:
                    key=kind,m[1]
                    if m[2] is not None:symbols[key]=m[2]
                    value=symbols[key]
                if tag=='cfn':callee=value
                if tag=='fn':function=value
                if tag=='ob':object_name=value
            elif line.startswith('calls='):
                edge=True;calls[callee]+=int(line[6:].split()[0])
            elif line.startswith(('calls=','jump=','jcnd=')):edge=True
            elif line and (line[0].isdigit()or line[0]in '+-*'):
                fields=line.split();n=len(positions)
                if edge:edge=False;continue
                if len(fields)<=n:continue
                nums=list(map(int,fields[n:]));sym=(object_name or '',function or '???')
                dest=by_symbol.setdefault(sym,Counter())
                for event,num in zip(events,nums):dest[event]+=num
    assert events and totals
    whole=dict(zip(events,totals));accounted={e:sum(v[e]for v in by_symbol.values())for e in events}
    order=sorted(by_symbol.items(),key=lambda v:-v[1]['Ir'])
    names=[v[0][1]for v in order if v[1]['Ir']]
    focus=lambda n:n and (n.startswith(('X86_decode','X86_disasm','X86_reg_access','X86_Intel_printInst','X86_ATT_printInst','cs_decode_full','tryOutput','writeVex2','cs_disasm_iter','cs_regs_access')) or n in ('decodeInstructionFull','readModRM'))
    ir=Counter()
    for (_,name),counts in by_symbol.items():ir[name]+=counts['Ir']
    return dict(events=whole,accounted=accounted,functions={name:dict(self_ir=ir[name],calls=calls[name])for name in set(ir)|set(calls)if focus(name)},top=[dict(function=k[1],ir=v['Ir'])for k,v in order[:20]])
