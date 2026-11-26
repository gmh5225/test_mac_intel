"""Read independent operator boundaries from WABT; keep the original module offsets."""
from pathlib import Path
import base64,hashlib,io,json,re,struct,subprocess as sp,sys,tarfile,urllib.request
r=Path(sys.argv[1]);r.mkdir(parents=True,exist_ok=True)
specs=[
('wabt','1.0.37','package/bin/wasm-objdump','2B/TH4ppwtlkUosLtuIimKsTVnqM8aoXxYHnu/WOxiSqa+CGoZXmG+pQyfDQjEKIAc7GqFlJsuCKuK8rIPL1sg=='),
('sql.js','1.13.0','package/dist/sql-wasm.wasm','RJbVP1HRDlUUXahJ7VMTcu9Rm1Nzw+EBpoPr94vnbD4LwR715F3CcxE2G2k45PewcaZ57pjetYa+LoSJLAASgA=='),
('brotli-wasm','3.0.1','package/pkg.node/brotli_wasm_bg.wasm','U3K72/JAi3jITpdhZBqzSUq+DUY697tLxOuFXB+FpAE/Ug+5C3VZrv4uA674EUZHxNAuQ9wETXNqQkxZD6oL4A=='),
('esbuild-wasm','0.25.0','package/esbuild.wasm','60iuWr6jdTVylmGXjpnqk3pCktUi5Rmjiv6EMza3h4X20BLtfL2BjUGs1+UCt2G9UK7jVGrJdUr5i1k0sL3wBg==')]
manifest={}
for name,version,member,integrity in specs:
    url=f'https://registry.npmjs.org/{name}/-/{name}-{version}.tgz'
    data=urllib.request.urlopen(url,timeout=50).read();assert base64.b64encode(hashlib.sha512(data).digest()).decode()==integrity
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz')as archive: raw=archive.extractfile(member).read()
    del data
    dest=r/('wasm-objdump.cjs' if name=='wabt' else name+'.wasm');dest.write_bytes(raw)
    manifest[name]=dict(url=url,member=member,package_sha512=integrity,sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw))
    if name=='wabt':continue
    def uleb(p):
        n=0
        for i in range(5):
            b=raw[p+i];n|=(b&127)<<(i*7)
            if b<128:return n,p+i+1
        raise ValueError(p)
    # Code section delimits each function, including the last operator's extent.
    ends=[];p=8
    while p<len(raw):
        tag=raw[p];n,body=uleb(p+1);p=body+n
        if tag!=10:continue
        cnt,h=uleb(body)
        for _ in range(cnt):
            z,h=uleb(h);h+=z;ends.append(h)
        assert h==p
    args=['node',r/'wasm-objdump.cjs','-d',dest]
    record=bytearray();func=-1;last=None
    def write(start,end):
        assert start<end<=len(raw) and end-start<=65535,(start,end)
        record.extend(struct.pack('<II',start,end-start))
    pat=re.compile(r'^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}(?:\s+|$))+)\|\s*(\S.*)$')
    fun=re.compile(r'^[0-9a-fA-F]+ func\[\d+\]')
    with sp.Popen(args,stdout=sp.PIPE,text=True)as proc:
        for line in proc.stdout:
            if fun.match(line):
                if last is not None:
                    assert raw[last]==0x0b and last+1==ends[func]
                    write(last,ends[func])
                last=None;func+=1;continue
            match=pat.match(line)
            if not match:continue
            pos=int(match[1],16);op=match[3]
            if op.startswith('local['):continue
            assert func>=0 and pos<ends[func] and bytes.fromhex(match[2])==raw[pos:pos+len(bytes.fromhex(match[2]))],line
            if last is not None:write(last,pos)
            last=pos
        assert proc.wait()==0
    assert func+1==len(ends) and last is not None and raw[last]==0x0b and last+1==ends[-1],(func,len(ends),last)
    write(last,ends[-1]);(r/(name+'.ranges')).write_bytes(record)
    manifest[name].update(functions=len(ends),operators=len(record)//8,ranges_sha256=hashlib.sha256(record).hexdigest())
    print(name,manifest[name]['functions'],len(record)//8,flush=True)
(r/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
