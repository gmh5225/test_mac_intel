from pathlib import Path
import hashlib,json,lzma,re,struct,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;server='https://deb.debian.org/debian/'
def sha(b):return hashlib.sha256(b).hexdigest()
def get(url,path):sp.run(['curl','--retry','3','--max-time','90','-fsSL','-o',path,url],check=True)
with tempfile.TemporaryDirectory(dir=r) as temp:
    w=Path(temp);receipt=r/'libmvec.json'
    if receipt.is_file():
        meta=json.loads(receipt.read_text())
    else:
        ref='main/binary-amd64/Packages.xz';get(server+'dists/trixie/Release',w/'release');release=(w/'release').read_text().split('\nSHA256:\n')[1].split('\nSHA512:')[0]
        h=re.search(r'^ ([a-f0-9]{64})\s+\d+ '+re.escape(ref)+r'$',release,re.M)[1]
        get(server+'dists/trixie/'+ref,w/'packages.xz');data=(w/'packages.xz').read_bytes();assert sha(data)==h
        entry=next(e for e in lzma.decompress(data).decode().split('\n\n') if e.startswith('Package: libc6\n'))
        header=dict(row.split(': ',1) for row in entry.splitlines() if ': ' in row and not row.startswith(' '))
        meta=dict(package='libc6',version=header['Version'],url=server+header['Filename'],package_sha256=header['SHA256'],index_sha256=h)
    url=meta['url']
    if meta['package_sha256']=='967aa62605721081c3eb2a17650611a792aa802d76a6511d1840242623d204c9':
        url='https://snapshot.debian.org/file/27904cc1b58dd79f0768ba6aa6dd993edc411b97'
    get(url,w/'lib.deb');assert sha((w/'lib.deb').read_bytes())==meta['package_sha256']
    name=next(v for v in sp.check_output(['ar','t',w/'lib.deb'],text=True).splitlines() if v.startswith('data.tar.'))
    tar=w/name
    with tar.open('wb') as out:sp.run(['ar','p',w/'lib.deb',name],stdout=out,check=True)
    member=next(v for v in sp.check_output(['tar','-tf',tar],text=True).splitlines() if v.endswith('/libmvec.so.1'))
    binary=sp.check_output(['tar','-xOf',tar,member]);assert binary[:6]==b'\x7fELF\x02\x01'
    hdr=struct.unpack_from('<16sHHIQQQIHHHHHH',binary)
    sections=[struct.unpack_from('<IIQQQQIIQQ',binary,hdr[6]+n*hdr[11]) for n in range(hdr[12])]
    st=sections[hdr[13]];names=binary[st[4]:st[4]+st[5]]
    sh=next(s for s in sections if names[s[0]:].split(b'\0',1)[0]==b'.text')
    data=binary[sh[4]:sh[4]+sh[5]]
    got=dict(member=member,binary_sha256=sha(binary),text_sha256=sha(data),bytes=len(data),address=sh[3])
    for k,v in got.items():
        if k in meta:assert meta[k]==v
        meta[k]=v
    receipt.write_text(json.dumps(meta,indent=2)+'\n');(r/'libmvec.text').write_bytes(data)
    print(meta['version'],len(data),meta['text_sha256'])
