"""Extract only the pinned Debian libcrypto text for pairwise public-record comparisons."""
from pathlib import Path
import hashlib,struct,tempfile,subprocess as sp,json
r=Path(__file__).resolve().parent
url='https://deb.debian.org/debian/pool/main/o/openssl/libssl3t64_3.5.7-1~deb13u2_amd64.deb'
def sha(x):return hashlib.sha256(x).hexdigest()
with tempfile.TemporaryDirectory(dir=r) as t:
    w=Path(t);d=w/'lib.deb';sp.run(['curl','-fsSL','--retry','3','-o',d,url],check=True)
    assert sha(d.read_bytes())=='916f7f40b34a06e6ebfaefcdab331bff458328411da672598f126a760472467d'
    name=next(s for s in sp.check_output(['ar','t',d],text=True).splitlines() if s.startswith('data.tar.'))
    f=w/name
    with f.open('wb') as out:sp.run(['ar','p',d,name],check=True,stdout=out)
    member=next(s for s in sp.check_output(['tar','-tf',f],text=True).splitlines() if s.endswith('/libcrypto.so.3'))
    b=sp.check_output(['tar','-xOf',f,member]);assert b[:6]==b'\x7fELF\x02\x01'
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',b);sec=[struct.unpack_from('<IIQQQQIIQQ',b,h[6]+i*h[11]) for i in range(h[12])]
    st=sec[h[13]];names=b[st[4]:st[4]+st[5]]
    sh=next(s for s in sec if names[s[0]:].split(b'\0',1)[0]==b'.text')
    data=b[sh[4]:sh[4]+sh[5]];assert sha(data)=='6d384a7079c5be0051952ad2d085a6a84de3a60cddd58f81094e8436cc962c0c'
    (r/'libcrypto.text').write_bytes(data)
(r/'openssl.json').write_text(json.dumps(dict(url=url,member=member,bytes=len(data),address=sh[3],sha256=sha(data)),indent=2)+'\n')
