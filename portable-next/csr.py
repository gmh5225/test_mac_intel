from pathlib import Path
import hashlib,re,subprocess as sp
def check(source,exe,stage):
    gen=(source/'arch/RISCV/RISCVGenSystemOperands.inc').read_text()
    table=gen.split('static const RISCV_SysReg SysRegsList[] = {',1)[1].split('};',1)[0]
    names=re.findall(r'^  \{ "([^"]+)"',table,re.M)
    idx=gen.split('const RISCV_SysReg *RISCV_lookupSysRegByEncoding(uint16_t Encoding) {',1)[1].split('};',1)[0]
    lookup={int(enc):names[int(row)] for enc,row in re.findall(r'\{(\d+),(\d+)\}',idx)}
    assert len(lookup)>380 and lookup[0x300]=='mstatus' and 0x7cb not in lookup
    cases=sorted(lookup) if stage=='base' else list(range(4096));texts={}
    for a in range(0,len(cases),128):
        part=cases[a:a+128]
        code=b''.join(((c<<20)|(11<<15)|(1<<12)|(10<<7)|0x73).to_bytes(4,'little')for c in part)
        out=sp.check_output([exe,'-d','riscv64',code.hex()],text=True)
        actual=re.findall(r'operands\[1\]\.type: CSR = ([^\n]+)',out)
        expected=[lookup.get(c,hex(c)) for c in part]
        assert actual==expected,(a,list(zip(part,actual,expected))[:10])
        texts.update(zip(part,actual))
    digest=lambda rows:hashlib.sha256('\n'.join(rows).encode()).hexdigest()
    return dict(total=len(cases),named=len(lookup),names_digest=digest([texts[c]for c in sorted(lookup)]),all_digest=digest(list(texts.values())))
