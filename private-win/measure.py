from pathlib import Path
import bisect,collections,hashlib,json,os,re,shutil,statistics,struct,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;s=r.parent/'source';out=r.parent/'evidence';out.mkdir(exist_ok=True)
read=lambda f:json.loads(f.read_text())
def sha(z):return hashlib.sha256(z).hexdigest()
def write(k,v):(out/(k+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(args,name,cwd=None):
    with (out/(name+'.log')).open('wb')as f:sp.run(list(map(str,args)),cwd=cwd,stdout=f,stderr=sp.STDOUT,check=True)
g=lambda *a:sp.check_output(['git','-C',s,*a],text=True).strip()
def inspect(f,mapfile):
    z=f.read_bytes();hdr=struct.unpack_from('<I',z,60)[0];machine,count=struct.unpack_from('<HH',z,hdr+4);assert machine==0x14c
    optlen=struct.unpack_from('<H',z,hdr+20)[0];opt=hdr+24
    preferred=struct.unpack_from('<I',z,opt+28)[0];sec={}
    for i in range(count):
        start=opt+optlen+40*i;name=z[start:start+8].split(b'\0')[0].decode();n,rva,nf,offset=struct.unpack_from('<4I',z,start+8)
        sec[name]=(rva,z[offset:offset+min(n,nf)])
    rva,code=sec['.text'];rr,reloc=sec['.reloc'];fix=set();p=0
    while p+8<=len(reloc):
        page,length=struct.unpack_from('<II',reloc,p)
        if not length:break
        assert 8<=length<=len(reloc)-p
        for k in range(p+8,p+length,2):
            entry=struct.unpack_from('<H',reloc,k)[0]
            if entry>>12==3:
                off=page+(entry&4095)-rva
                if 0<=off<len(code):fix.update(range(off,off+4))
        p+=length
    symbols=[]
    for line in mapfile.read_text(errors='replace').splitlines():
        m=re.match(r'\s*0001:([0-9A-Fa-f]+)\s+(\S+)\s+[0-9A-Fa-f]+',line)
        if m:symbols.append((int(m[1],16),m[2]))
    assert len(symbols)>30
    return code,fix,sorted(symbols),preferred,rva
m=read(r/'tree.json');manifest=read(r/'pe-images.json');t=Path(tempfile.mkdtemp());build=t/'build'
try:
    patch=t/'change.patch';patch.write_bytes(sp.check_output(['git','-C',r.parent,'cat-file','blob','HEAD:private-win/candidate.patch']))
    assert sha(patch.read_bytes())==m['sha256'] and g('rev-parse','HEAD')==m['parent']
    run(['cmake','-S',s,'-B',build,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=cl','-DCMAKE_CXX_COMPILER=cl','-DCMAKE_SHARED_LINKER_FLAGS=/MAP','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'],'configure')
    exe=t/'reader.exe';run(['cl','/nologo','/O2','/MT','/std:c11','/D_CRT_SECURE_NO_WARNINGS','/I'+str(s/'include'),r/'driver.c','/Fe:'+str(exe)],'driver',t)
    images={};views={};objects={};units=build/'CMakeFiles/capstone.dir'
    for tag in ('base','candidate'):
        if tag=='candidate':
            g('apply','--cached',str(patch));assert g('write-tree')==m['tree']
            for name in g('diff','--cached','--no-renames','--name-only','HEAD').splitlines():
                dest=s/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(sp.check_output(['git','-C',s,'cat-file','blob',':'+name]))
                assert g('hash-object','--no-filters',str(dest))==g('rev-parse',':'+name)
        run(['cmake','--build',build,'--parallel','4','--target','capstone_shared'],'build-'+tag)
        dll,=build.rglob('capstone.dll');maps=list(build.rglob('*.map'));assert len(maps)==1,maps
        views[tag]=inspect(dll,maps[0]);images[tag]=dll.read_bytes()
        objects[tag]={str(q.relative_to(units)):sha(q.read_bytes())for q in units.rglob('*.obj')};assert len(objects[tag])>10
    a,ra,sa,pa,va=views['base'];b,rb,sb,pb,vb=views['candidate'];assert va==vb
    changes={i for i,(x,y) in enumerate(zip(a,b))if x!=y};positions=[i for i,k in sa]
    own=collections.Counter(sa[max(0,bisect.bisect_right(positions,i)-1)][1]for i in changes)
    write('difference',dict(sha256={k:sha(v)for k,v in images.items()},text=[sha(a),sha(b)],sizes=[len(a),len(b)],preferred=[pa,pb],changed_bytes=len(changes)+abs(len(a)-len(b)),changed_relocation_bytes=len(changes&(ra|rb)),changed_offsets_sample=sorted(changes)[:64],changed_symbols=own,normal_addresses_equal=sa==sb,changed_objects=sorted(k for k,v in objects['base'].items()if objects['candidate'].get(k)!=v)))
    images['copy']=images['base'];live=t/'active.dll';samples={}
    for item in manifest:
        f=t/('putty'+str(item['bits'])+'.exe');run(['curl.exe','--retry','4','--fail','--location','--silent','--show-error','-o',f,item['source']],'sample-'+str(item['bits']))
        z=f.read_bytes();assert sha(z)==item['executable_sha256'];off=item['section_file_offset'];code=z[off:off+item['bytes']];assert sha(code)==item['sha256'];f.unlink()
        path=t/('putty'+str(item['bits'])+'.text');path.write_bytes(code);samples[item['bits']]=path
    def sample(tag,bits,mode,reps):
        live.write_bytes(images[tag]);return list(map(int,sp.check_output([exe,live,samples[bits],str(bits),str(mode),str(reps)],text=True).split()))
    rows=[]
    for bits in samples:
        for mode in (0,1,2):
            probe=sample('base',bits,mode,1);assert len(probe)==8 and probe[4]>200000
            n=max(1,min(300,round(.16*probe[1]/probe[0])));frames=[]
            signature=probe[4:]
            for i in range(9):
                labels=['base','copy','candidate'];labels=labels[i%3:]+labels[:i%3];data={k:[]for k in labels}
                for label in labels+labels[::-1]:
                    o=sample(label,bits,mode,n);assert o[4:]==signature and o[0]>0 and o[1]==probe[1]
                    data[label].append(o[:4])
                frames.append(data)
            gains={k:statistics.median(sum(z[0]for z in f['base'])/sum(z[0]for z in f[k])for f in frames)for k in ('copy','candidate')}
            rows.append(dict(bits=bits,mode=mode,repetitions=n,signature=signature,cycles=frames,gains=gains));write('timings',rows)
    write('complete',dict(tree=m['tree'],cases=len(rows),corpus=manifest,driver=sha(exe.read_bytes())))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file());shutil.rmtree(t);write('cleanup',dict(removed=not t.exists(),bytes=n))
