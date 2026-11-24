import hashlib,json,os,re,subprocess as sp
from pathlib import Path

def snapshots(src, bench, build, temp, profile, label, run):
    exe=temp/('snapshot.exe' if os.name=='nt' else 'snapshot')
    library=build/('capstone.lib' if os.name=='nt' else 'libcapstone.a')
    if os.name=='nt':
        runtime='/MT' if 'CAPSTONE_BUILD_STATIC_MSVC_RUNTIME:BOOL=ON' in (build/'CMakeCache.txt').read_text() else '/MD'
        run(label+'-snapshot-link','cl','/nologo','/O2',runtime,'/EHsc','/std:c++17','/I'+str(src/'include'),bench/'snapshot.cpp',library,'/Fo:'+str(temp/'snapshot.obj'),'/Fe:'+str(exe))
    else:
        cxx='g++' if profile=='gcc' else 'clang++'
        run(label+'-snapshot-link',cxx,'-O2','-std=c++17','-I',src/'include',bench/'snapshot.cpp',library,'-o',exe)
    raw=library.read_bytes()
    records={str(bits):('X86_decodeFixedRecord'+str(bits)).encode() in raw for bits in (32,64)}
    source=bytearray()
    for fixture in sorted((src/'suite/MC/X86').glob('*.s.cs')):
        cases=[]
        for line in fixture.read_text().splitlines():
            left=line.partition('=')[0].strip()
            if re.fullmatch(r'0x[0-9a-fA-F]{2}(?:,\s*0x[0-9a-fA-F]{2})*',left):
                cases.append(bytes(int(x,16) for x in left.split(',')))
        step=max(1,(len(cases)+31)//32)
        source.extend(b''.join(cases[::step]))
    assert len(source)>1000
    sample=temp/'curated-x86.bin';sample.write_bytes(source)
    modes=[(0,0,0),(0,1,0)]
    if profile!='diet':modes.append((0,1,1))
    if profile not in ('diet','noatt'):modes.append((1,1,1))
    results={}
    for bits in (16,32,64):
        for att,text,detail in modes:
            args=(str(bits),str(att),str(text),str(detail),'1')
            with sp.Popen([exe,*args,sample],stdout=sp.PIPE,stderr=sp.PIPE) as proc:
                digest=hashlib.sha256()
                for chunk in iter(lambda: proc.stdout.read(1<<16),b''):digest.update(chunk)
                diag=proc.stderr.read().decode()
                assert proc.wait()==0,(args,diag)
            counts=json.loads(diag)
            assert counts['accepted']>0 and len(source)==sum(counts.values())
            results['/'.join(args[:4])]=dict(sha256=digest.hexdigest(),counts=counts)
    return dict(records=records,bytes=len(source),sha256=hashlib.sha256(source).hexdigest(),snapshots=results)
