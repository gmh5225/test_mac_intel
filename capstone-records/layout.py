from pathlib import Path
from collections import Counter
import hashlib,json,re,shutil,subprocess as sp
def output(*args):return sp.check_output(list(map(str,args)),text=True)
def sections(file):
    result={}
    for line in output('objdump','-h',file).splitlines():
        fields=line.split()
        if len(fields)>=7 and fields[0].isdigit() and fields[1].startswith('.'):
            result[fields[1]]=dict(size=int(fields[2],16),vma=int(fields[3],16),offset=int(fields[5],16),alignment=fields[6])
    return result
def data(file,sec):
    with file.open('rb') as stream:
        stream.seek(sec['offset']);v=stream.read(sec['size'])
    assert len(v)==sec['size'];return v
def reloc(file):
    lines=output('objdump','-r',file).splitlines()
    return [x.strip() for x in lines if x.startswith('RELOCATION RECORDS FOR') or re.match(r'^[0-9a-f]+\s+R_',x)]
def match_text(t,base,candidate,objects,archives,consumer,link):
    member='RISCVDisassembler.c.o'
    sizes={k:sections(v)['.text']['size'] for k,v in objects.items()}
    small,big=sorted(sizes,key=sizes.get);delta=sizes[big]-sizes[small]
    key='layout';(t/key).mkdir()
    original=objects[small];new=t/key/member
    src=data(original,sections(original)['.text']);blob=t/'padded-text';blob.write_bytes(src+bytes(delta))
    if delta:
        sp.run(['objcopy','--update-section','.text='+str(blob),str(original),str(new)],check=True)
    else:
        shutil.copy2(original,new)
    assert data(new,sections(new)['.text'])==src+bytes(delta)
    assert reloc(new)==reloc(original)
    archive=t/key/'libcapstone.a';shutil.copy2(archives[small],archive)
    names=output('ar','t',archive).splitlines();assert names.count(member)==1
    sp.run(['ar','r',str(archive),str(new)],check=True);assert output('ar','t',archive).splitlines()==names
    exe=t/'matched-layout'
    link(['clang++',consumer,archive,'-lm','-o',exe],'link-matched-layout')
    return exe,dict(padded=small,matched_to=big,bytes=delta,sizes=sizes,relocations=len(reloc(new)),member=member,base_sha256=hashlib.sha256(base.read_bytes()).hexdigest(),candidate_sha256=hashlib.sha256(candidate.read_bytes()).hexdigest())
def hot(trace):
    names={};owner=None;callee=False;freq=Counter()
    def name(atom):
        match=re.fullmatch(r'\((\d+)\)(?: (.*))?',atom)
        if not match:return atom
        n,v=match.groups()
        if v is not None:names[n]=v
        return names.get(n,'('+n+')')
    for line in trace.read_text().splitlines():
        if line.startswith('fn='):owner=name(line[3:]);callee=False
        elif line.startswith('cfn='):name(line[4:])
        elif line.startswith('calls='):callee=True
        elif line and line[0] in '0123456789+-*' and owner:
            fields=line.split()
            if len(fields)==2 and fields[-1].isdigit():
                if not callee:freq[owner]+=int(fields[-1])
                callee=False
    return freq
def layout(exe,active):
    secs=sections(exe);symbols=output('nm','-n','-S','--defined-only',exe).splitlines();rows=[]
    text_sec=secs['.text'];code=data(exe,text_sec)
    for line in symbols:
        f=line.split(maxsplit=3)
        if len(f)!=4:continue
        addr,size,kind,n=f;addr=int(addr,16);size=int(size,16)
        if kind in ('t','T') and n in active:
            at=addr-text_sec['vma'];assert at>=0 and at+size<=len(code)
            rows.append(dict(name=n,address=addr,size=size,sha256=hashlib.sha256(code[at:at+size]).hexdigest(),simulated_self_ir=active[n]))
        elif kind in 'rRdD' and size>=256 and ('Mips' in n or 'MIPS' in n or 'DecoderTable' in n):
            rows.append(dict(name=n,address=addr,size=size,kind=kind))
    return dict(sections={k:v for k,v in secs.items() if k in ('.text','.rodata','.eh_frame','.data.rel.ro','.data','.bss')},symbols=rows)
