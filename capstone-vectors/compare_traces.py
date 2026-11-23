def inspect(root):
    from collections import Counter
    def read(f):
        z={}
        for ln in f.read_text().splitlines():
            i,off,n,mr,sib,name,encoding=ln.split()
            assert int(i) not in z and len(encoding)==2*int(n)
            z[int(i)]=(int(off),int(n),int(mr),int(sib),name,bytes.fromhex(encoding))
        return z
    results={}
    for f in (root/'base').glob('*-shapes.tsv'):
        sample=f.name.removesuffix('-shapes.tsv');a=read(f);b=read(root/'candidate'/f.name)
        assert all(a.get(i)==v for i,v in b.items())
        hits=[a[i] for i in a.keys()-b.keys()];forms=Counter()
        for off,n,mr,sib,name,encoding in hits:
            assert sample in ('putty-64-0.85','libmvec-amd64','libssl3t64-amd64')
            lead=int((encoding[0]&0xf0)==0x40);opcode=encoding[lead]
            assert name=='cmp' and opcode in (0x80,0x81,0x83) and encoding[lead+1]==mr
            assert mr<0xc0 and (mr&0x38)==0x38
            mod,rm=mr>>6,mr&7
            disp=4 if mod==2 or mod==0 and (rm==5 or rm==4 and sib&7==5) else int(mod==1)
            assert n==lead+2+(rm==4)+disp+(4 if opcode==0x81 else 1)
            forms[format(opcode,'02x')]+=1
        results[sample]=dict(base=len(a),candidate=len(b),new=len(hits),opcodes=dict(forms))
    assert len(results)==6
    return results
