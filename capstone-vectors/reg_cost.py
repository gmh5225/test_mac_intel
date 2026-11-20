"""Count dynamic instructions in the actual register-access routine, retaining original ISA offsets."""
from collections import Counter
from pathlib import Path
import gzip, hashlib, json, re, subprocess as sp

def digest(path):
    hash_=hashlib.sha256()
    with path.open('rb') as src:
        for chunk in iter(lambda: src.read(1024*1024),b''):
            hash_.update(chunk)
    return hash_.hexdigest()
def count(trace,asm):
    by_address={}
    for line in asm.splitlines():
        m=re.fullmatch(r'\s*([0-9a-fA-F]+):\s+(.+?)\s*',line)
        if m:by_address[int(m[1],16)]=m[2]
    assert by_address and '<X86_reg_access>:' in asm
    fn=None;edge=False;events=None;counts=Counter();n=None;at=None
    with trace.open() as src:
        for raw in src:
            s=raw.strip()
            if s.startswith('positions:'):
                fields=s.split()[1:];at=fields.index('instr');n=len(fields)
            elif s.startswith('events:'):
                events=s.split()[1:];assert events[0]=='Ir'
            elif s.startswith('fn='):fn=s[3:];edge=False
            elif s.startswith('calls='):edge=True
            elif s and s[0].isdigit():
                if fn=='X86_reg_access' and not edge:
                    fields=s.split()
                    address=int(fields[at],0);cost=int(fields[n])
                    if cost:counts[address]+=cost
                edge=False
    assert counts and events and n
    delta=min(counts)-min(by_address)
    mapped=[dict(offset=a-min(counts),assembly=by_address[a-delta],ir=amount) for a,amount in sorted(counts.items())]
    classes=Counter()
    for row in mapped:
        op=row['assembly'].split()[0]
        classes[op]+=row['ir']
    assert sum(classes.values())==sum(counts.values())
    return dict(exclusive_ir=sum(counts.values()),samples=mapped,mnemonic_ir=dict(classes),load_bias=delta)
def run(r,w,exe,f,intervals,name,bits,out):
    for label in ('integer','route','vector'):
        asm=sp.check_output(['objdump','-d','-w','--no-show-raw-insn','--disassemble=X86_reg_access',exe[label]],text=True)
        (out/(label+'-reg-access.asm')).write_text(asm)
        trace=w/'reg.trace';args=['valgrind','--tool=callgrind','--collect-atstart=no','--toggle-collect=X86_reg_access','--compress-pos=no','--compress-strings=no','--dump-instr=yes','--callgrind-out-file='+str(trace),str(exe[label]),'capstone','2','1',str(f),str(intervals),str(bits)]
        with (out/(name+'-'+label+'-reg-profile.log')).open('w') as log:
            values=list(map(int,sp.check_output(args,stderr=log,text=True).split()))
        assert len(values)==6
        cost=count(trace,asm)
        cost.update(records=values[2:],trace_sha256=digest(trace))
        key=name+'-'+label
        (out/(key+'-reg-cost.json')).write_text(json.dumps(cost,indent=2)+'\n')
        import shutil
        with trace.open('rb') as src,gzip.open(out/(key+'-reg-trace.gz'),'wb',compresslevel=3) as dst:shutil.copyfileobj(src,dst)
        trace.unlink()
