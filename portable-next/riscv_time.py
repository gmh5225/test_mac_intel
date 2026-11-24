from pathlib import Path
import hashlib,math,os,random,shutil,subprocess as sp

def measure(rows, w, save):
    def digest(data):
        return hashlib.sha256(data).hexdigest()
    names = ('base','candidate')
    paths={k:w/('riscv-option-'+k) for k in names}
    paths['duplicate']=w/'riscv-option-duplicate'
    shutil.copyfile(paths['base'],paths['duplicate'])
    for p in paths.values():p.chmod(0o755)
    verified={k:digest(p.read_bytes()) for k,p in paths.items()}
    assert verified['duplicate']==verified['base']!=verified['candidate']
    path=w/'riscv-active';next_path=w/'riscv-next'
    inodes={k:p.stat().st_ino for k,p in paths.items()}
    def run(k,row,mode,n):
        os.link(paths[k],next_path)
        if path.exists() and next_path.samefile(path):next_path.unlink()
        else:next_path.replace(path)
        assert path.stat().st_ino==inodes[k]
        cmd=[path,row['arch'],w/(row['name']+'.text'),str(mode),str(n)]
        return list(map(int,sp.check_output(cmd,text=True).split()))
    data={}
    for row in rows:
        assert row['arch']=='riscv64'
        for mode in range(6):
            n=max(1,math.ceil((50e6 if mode==0 else 25e6)/run('base',row,mode,1)[0]))
            expected=run('base',row,mode,n)[2:]
            assert expected[0]>0
            cycles=[];labels=list(paths);rng=random.Random(row['name']+'/'+str(mode))
            for _ in range(35 if mode==0 else 17):
                rng.shuffle(labels);pairs={k:[]for k in labels}
                for k in labels+labels[::-1]:
                    x=run(k,row,mode,n);assert x[2:]==expected
                    pairs[k].append(x[:2])
                cycles.append({k:[sum(x[i]for x in xs)for i in (0,1)]for k,xs in pairs.items()})
            data[row['name']+'/'+str(mode)]=dict(reps=n,checks=expected,cycles=cycles)
            save('riscv-option-observations',data)
    assert len(data)==24 and len(verified)==3
    save('riscv-option-fixed',dict(inodes=inodes,verified=verified,method='same path, immutable Mach-O images with valid signatures, independent identical control'))
