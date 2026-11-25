from pathlib import Path
import hashlib,math,os,random,subprocess as sp
def paired_masm(w,save):
    original={tag:(w/('masm-'+tag)).read_bytes() for tag in ('base','candidate','outlined')}
    length=max(map(len,original.values()))
    images={k:v.ljust(length,b'\0') for k,v in original.items()}
    images['duplicate']=images['base']
    strides=[i for i in range(0,length,4096) if len({v[i:i+4096] for v in images.values()})>1]
    path=w/'masm-selected';path.write_bytes(images['base']);path.chmod(0o755);inode=path.stat().st_ino
    verified={}
    def sample(tag,mode,f,ranges,bits,reps):
        with path.open('r+b',buffering=0) as fd:
            for i in strides:
                fd.seek(i);part=images[tag][i:i+4096];assert fd.write(part)==len(part)
        assert inode==path.stat().st_ino
        if tag not in verified:
            verified[tag]=hashlib.sha256(path.read_bytes()).hexdigest()
            assert verified[tag]==hashlib.sha256(images[tag]).hexdigest()
            save('masm-images',dict(inode=inode,changed_pages=len(strides),verified=verified))
        cmd=['setarch',os.uname().machine,'-R',path,'capstone',str(mode),str(reps),f,ranges,str(bits)]
        return list(map(int,sp.check_output(cmd,text=True).split()))
    def take(name,mode,f,ranges,bits):
        one=sample('base',mode,f,ranges,bits,1)
        reps=max(1,math.ceil(16e6/one[0]));expected={tag:sample(tag,mode,f,ranges,bits,reps)[2:]for tag in images}
        assert len({tuple(v) for v in expected.values()})==1
        names=list(images);rng=random.Random(name+str(mode));pairs=[]
        for _ in range(25):
            rng.shuffle(names);times={k:[]for k in images}
            for tag in names+names[::-1]:
                z=sample(tag,mode,f,ranges,bits,reps);assert z[2:]==expected[tag];times[tag].append(z[:2])
            pairs.append({k:[sum(v)for v in zip(*xs)] for k,xs in times.items()})
        return dict(pairs=pairs,checks=expected,reps=reps)
    return take
