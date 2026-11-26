from pathlib import Path
import hashlib,math,os,random,subprocess as sp

def measure(rows, w, save):
    def digest(data):
        return hashlib.sha256(data).hexdigest()
    names = ('base','candidate')
    original = {k:(w/('riscv-option-'+k)).read_bytes() for k in names}
    image_shas = {k:digest(v) for k,v in original.items()}
    length = max(map(len,original.values()))
    images = {k:v+bytes(length-len(v)) for k,v in original.items()}
    images['duplicate'] = images['base']
    path=w/'riscv-option-selected'
    path.write_bytes(images['base'])
    path.chmod(0o755)
    inode = path.stat().st_ino
    offsets=[i for i in range(0,length,4096) if len({v[i:i+4096]for v in images.values()})>1] or [0]
    verified={}
    def run(k,row,mode,n):
        with path.open('r+b',buffering=0) as f:
            for i in offsets:
                f.seek(i)
                data=images[k][i:i+4096]
                assert f.write(data)==len(data)
        assert path.stat().st_ino==inode and path.stat().st_size==length
        if k not in verified:
            verified[k]=digest(path.read_bytes())
            assert verified[k]==digest(images[k])
        cmd=['setarch',os.uname().machine,'-R',path,row['arch'],w/(row['name']+'.text'),str(mode),str(n)]
        return list(map(int,sp.check_output(cmd,text=True).split()))
    data={}
    for row in rows:
        assert row['arch']=='riscv64'
        for mode in range(6):
            n=max(1,math.ceil(25e6/run('base',row,mode,1)[0]))
            expected=run('base',row,mode,n)[2:]
            assert expected[:2]==[{'ls': 24982, 'cat': 5992, 'sort': 18335, 'cp': 23108}[row['name']]*n,0],(row['name'],expected,n)
            cycles=[];labels=list(images);rng=random.Random(row['name']+'/'+str(mode))
            for _ in range(17):
                rng.shuffle(labels);pairs={k:[]for k in labels}
                for k in labels+labels[::-1]:
                    x=run(k,row,mode,n);assert x[2:]==expected
                    pairs[k].append(x[:2])
                cycles.append({k:[sum(x[i]for x in xs)for i in (0,1)]for k,xs in pairs.items()})
            data[row['name']+'/'+str(mode)]=dict(reps=n,checks=expected,cycles=cycles)
            save('riscv-option-observations',data)
    assert len(data)==24 and len(verified)==3
    save('riscv-option-fixed',dict(inode=inode,original=image_shas,verified=verified,bytes=length,blocks=len(offsets)))
