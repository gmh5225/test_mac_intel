from pathlib import Path
import hashlib,math,os,random,shutil,statistics,subprocess
def digest(data):return hashlib.sha256(data).hexdigest()
def start(work):
    images={tag:(work/('att-'+tag)).read_bytes()for tag in ('base','candidate','outlined')}
    original={tag:digest(v) for tag,v in images.items()};length=max(map(len,images.values()))
    images={tag:image.ljust(length,b'\x00')for tag,image in images.items()};images['duplicate']=images['base']
    path=work/'att-selected';shutil.copy2(work/'att-base',path);path.write_bytes(images['base'])
    inode=path.stat().st_ino
    indices=[off for off in range(0,length,4096)if len({z[off:off+4096]for z in images.values()})>1]
    checked={};assert indices
    def select(tag):
        with path.open('r+b',buffering=0)as f:
            for off in indices:
                f.seek(off);data=images[tag][off:off+4096];assert f.write(data)==len(data)
        assert path.stat().st_ino==inode and path.stat().st_size==length
        if tag not in checked:
            checked[tag]=digest(path.read_bytes());assert checked[tag]==digest(images[tag])
    def measure(name,bits,blob,ranges,detail):
        def take(tag,n):
            if tag=='oracle':exe=work/'att-reference'
            else:select('base' if tag=='gas' else tag);exe=path
            return list(map(int,subprocess.check_output(['setarch',os.uname().machine,'-R',exe,'iced' if tag=='gas' else 'capstone',str(detail+1),str(n),blob,ranges,str(bits)],text=True).split()))
        n=max(1,math.ceil(25e6/take('base',1)[0]))
        labels=[*images,'gas'];expected={k:take(k,n)[2:]for k in labels}
        oracle=take('oracle',n)[2:]
        assert expected['base']==expected['duplicate'] and expected['candidate']==expected['outlined']==oracle
        assert expected['gas'][:3]==expected['base'][:3]==oracle[:3]
        pairs=[];rng=random.Random(name+'/AT&T/public/'+str(detail))
        for _ in range(17):
            rng.shuffle(labels);paired={k:[] for k in labels}
            for tag in labels+labels[::-1]:
                data=take(tag,n);assert data[2:]==expected[tag];paired[tag].append(data[:2])
            pairs.append({k:[sum(row[i]for row in vals)for i in (0,1)]for k,vals in paired.items()})
        return dict(repeats=n,checks=expected,oracle=oracle,pairs=pairs)
    return measure,dict(inode=inode,original=original,changed_pages=len(indices),verified=checked)
