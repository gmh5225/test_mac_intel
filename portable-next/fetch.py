from pathlib import Path
import hashlib,json,os,subprocess as sp,struct,tempfile,zipfile
r=Path(__file__).resolve().parent;q=json.loads((r/'release.json').read_text());asset=q['asset']
def save(n,v):(r/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def sha(x):return hashlib.sha256(x).hexdigest()
def elf(image):
    start=0;out=[]
    while True:
        i=image.find(b'\x7fELF',start)
        if i<0:break
        start=i+1;x=image[i:]
        if len(x)<52 or x[:7]!=b'\x7fELF\x01\x01\x01':continue
        h=struct.unpack_from('<16sHHIIIIIHHHHHH',x)
        if h[2]!=203 or h[-3]!=40 or h[-2]<1 or h[-1]>=h[-2] or h[6]+h[-2]*40>len(x):continue
        entries=[struct.unpack_from('<10I',x,h[6]+40*n)for n in range(h[-2])];strings=entries[h[-1]];names=x[strings[4]:strings[4]+strings[5]]
        for j,rec in enumerate(entries):
            name=names[rec[0]:].split(b'\0',1)[0].decode(errors='replace')
            if rec[1]!=1 or rec[2]&6!=6 or not rec[5] or rec[4]+rec[5]>len(x) or not name.startswith('.text'):continue
            out.append((dict(embedded_elf=i,section=j,name=name,address=rec[3],offset=i+rec[4],length=rec[5],machine=h[2],flags=h[7],entry=h[4]),x[rec[4]:rec[4]+rec[5]]))
    return out
with tempfile.TemporaryDirectory(dir=r)as tmp:
    f=Path(tmp)/asset['name'];sp.run(['curl','-fsSL','--retry','3','--connect-timeout','15','--max-time','180',asset['browser_download_url'],'-o',f],check=True)
    with f.open('rb')as stream:assert 'sha256:'+hashlib.sha256(stream.read()).hexdigest()==asset['digest'] and f.stat().st_size==asset['size']
    with zipfile.ZipFile(f)as package:
        images=[i for i in package.infolist()if i.filename.lower().endswith('.xe') and not i.filename.startswith('__MACOSX')]
        save('inventory',dict(xe=[dict(name=i.filename,bytes=i.file_size)for i in images],nested=[i.filename for i in package.infolist()if i.filename.lower().endswith('.zip')][:30]))
        dst=r/'inputs';dst.mkdir(exist_ok=True);samples=[];digests=set()
        for i in sorted(images,key=lambda z:(('xk_audio_216'not in z.filename.lower()),z.file_size)):
            raw=package.read(i);sections=elf(raw)
            if not sections:continue
            family='xs2'if ('216'in i.filename or 'xuf'in i.filename.lower()) else ('xs3'if any(k in i.filename.lower() for k in ('316','xu3','xs3')) else 'other')
            if any(s['family']==family for s in samples):continue
            records=[]
            for j,(info,data) in enumerate(sections):
                h=sha(data)
                if h in digests or len(data)<512:continue
                digests.add(h);key=f'{family}-{j}';(dst/(key+'.text')).write_bytes(data)
                records.append(dict(**info,sha256=h,file=key+'.text'))
            if records:samples.append(dict(member=i.filename,family=family,sha256=sha(raw),sections=records))
            if len(samples)==3:break
        save('samples',dict(complete=bool(samples),release=q,images=samples))
    assert samples, "No executable XCore ELF sections in the selected asset"
save('input-cleanup',dict(removed=not Path(tmp).exists(),archive_bytes=asset['size']))
