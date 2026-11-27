from pathlib import Path
import hashlib,math,os,random,subprocess as sp

def measure(rows, w, save, prefix='foreign', make_args=None, expected_cases=15):
    def digest(data):
        return hashlib.sha256(data).hexdigest()
    names = ('base','candidate','outlined')
    original = {k:(w/(prefix+'-'+k)).read_bytes() for k in names}
    image_shas = {k:digest(v) for k,v in original.items()}
    length = max(map(len,original.values()))
    images = {k:v+bytes(length-len(v)) for k,v in original.items()}
    images['duplicate'] = images['base']
    path=w/(prefix+'-selected')
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
        args=make_args(row,mode,n) if make_args else [row['arch'],w/(row['name']+'.text'),str(mode),str(n)]
        cmd=['setarch',os.uname().machine,'-R',path,*args]
        return list(map(int,sp.check_output(cmd,text=True).split()))
    data={}
    for row in rows:
        if not make_args and row['arch'] in ('i386','amd64'):continue
        for mode in range(3):
            n=max(1,math.ceil(25e6/run('base',row,mode,1)[0]))
            expected=run('base',row,mode,n)[2:]
            assert expected[0]>0
            cycles=[];labels=list(images);rng=random.Random(row['name']+'/'+str(mode))
            for _ in range(17):
                rng.shuffle(labels);pairs={k:[]for k in labels}
                for k in labels+labels[::-1]:
                    x=run(k,row,mode,n);assert x[2:]==expected
                    pairs[k].append(x[:2])
                cycles.append({k:[sum(x[i]for x in xs)for i in (0,1)]for k,xs in pairs.items()})
            data[row['name']+'/'+str(mode)]=dict(reps=n,checks=expected,cycles=cycles)
            save(prefix+'-observations',data)
    assert len(data)==expected_cases and len(verified)==4
    save(prefix+'-fixed',dict(inode=inode,original=image_shas,verified=verified,bytes=length,blocks=len(offsets)))
