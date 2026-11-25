import hashlib,json,os,re,subprocess as sp
from pathlib import Path

def snapshots(src, bench, build, temp, profile, label, run, linkage):
    shared=linkage=='shared'
    if os.name=='nt':
        library=build/('capstone.lib' if shared else 'capstone_static.lib')
        exe=(build if shared else temp)/'snapshot.exe'
    else:
        import sys
        library=build/(('libcapstone.dylib' if sys.platform=='darwin' else 'libcapstone.so') if shared else 'libcapstone.a')
        exe=temp/'snapshot'
    assert library.is_file(),library
    if os.name=='nt':
        runtime='/MT' if 'CAPSTONE_BUILD_STATIC_MSVC_RUNTIME:BOOL=ON' in (build/'CMakeCache.txt').read_text() else '/MD'
        run(label+'-snapshot-link','cl','/nologo','/O2',runtime,'/EHsc','/std:c++17','/I'+str(src/'include'),bench/'snapshot.cpp',library,'/Fo:'+str(temp/'snapshot.obj'),'/Fe:'+str(exe))
    else:
        cxx='g++' if profile=='gcc' else 'clang++'
        run(label+'-snapshot-link',cxx,'-O2','-std=c++17','-I',src/'include',bench/'snapshot.cpp',library,*(['-Wl,-rpath,'+str(build)] if shared else []),'-o',exe)
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
                status=proc.wait()
                assert status==0,(linkage,args,status,diag)
            counts=json.loads(diag)
            assert counts['accepted']>0 and len(source)==sum(counts.values())
            results['/'.join(args[:4])]=dict(sha256=digest.hexdigest(),counts=counts)

    corpus = bytearray()
    for f in sorted((src/'suite/MC/PowerPC').glob('*.s.cs')):
        for line in f.read_text().splitlines():
            left=line.partition('=')[0].strip()
            if re.fullmatch(r'0x[0-9a-fA-F]{2}(?:,\s*0x[0-9a-fA-F]{2}){3}',left):
                corpus.extend(bytes(int(v,16) for v in left.split(',')))
    assert len(corpus)>=128 and len(corpus)%4==0
    ppc_input=temp/'curated-ppc.bin';ppc_input.write_bytes(corpus)
    for big in (0,1):
        for detail in (range(2) if profile=='diet' else range(4)):
            args=[exe,ppc_input,str(big),str(detail)]
            with sp.Popen(args,stdout=sp.PIPE,stderr=sp.PIPE) as proc:
                digest=hashlib.sha256()
                for chunk in iter(lambda:proc.stdout.read(65536),b''):digest.update(chunk)
                diag=proc.stderr.read().decode()
                result=proc.wait()
                assert result==0,(args,result,diag)
            counts=json.loads(diag);assert counts['accepted']>0 and counts['accepted']<=len(corpus)//4
            if profile!='diet' and detail:assert counts['named']>0,counts
            results['powerpc/'+str(big)+'/'+str(detail)]=dict(counts=counts,sha256=digest.hexdigest(),corpus_sha256=hashlib.sha256(corpus).hexdigest())

    return dict(library_sha256=hashlib.sha256(raw).hexdigest(),ppc_index_symbol=b"PPC_setAliasId" in raw,records=records,bytes=len(source),sha256=hashlib.sha256(source).hexdigest(),snapshots=results)

def standalone(src, bench, build, temp, profile, label, run, linkage):
    shared=linkage=='shared'
    if os.name=='nt':
        library=build/('capstone.lib' if shared else 'capstone_static.lib')
        exe=(build if shared else temp)/'arm-record.exe'
    else:
        import sys
        library=build/(('libcapstone.dylib' if sys.platform=='darwin' else 'libcapstone.so') if shared else 'libcapstone.a')
        exe=temp/'arm-record'
    assert library.is_file(),library
    if os.name=='nt':
        runtime='/MT' if 'CAPSTONE_BUILD_STATIC_MSVC_RUNTIME:BOOL=ON' in (build/'CMakeCache.txt').read_text() else '/MD'
        run(label+'-snapshot-link','cl','/nologo','/O2',runtime,'/EHsc','/std:c++17','/I'+str(src/'include'),bench/'arm-record.cpp',library,'/Fo:'+str(temp/'snapshot.obj'),'/Fe:'+str(exe))
    else:
        cxx='g++' if profile=='gcc' else 'clang++'
        run(label+'-snapshot-link',cxx,'-O2','-std=c++17','-I',src/'include',bench/'arm-record.cpp',library,*(['-Wl,-rpath,'+str(build)] if shared else []),'-o',exe)
    raw=library.read_bytes()
    stream=bytearray()
    for file in sorted((src/'suite/MC/ARM').glob('*.s.cs')):
        for line in file.read_text().splitlines():
            text=line.partition('=')[0].strip()
            if re.fullmatch(r'0x[0-9a-fA-F]{2}(?:,\s*0x[0-9a-fA-F]{2}){3}',text):
                stream.extend(int(byte,16)for byte in text.split(','))
    assert len(stream)>256
    data=temp/'arm-full-record.bin';data.write_bytes(stream)
    views=sp.check_output([exe,data],text=True).splitlines()
    assert len(views)==(8 if profile=='diet' else 16) and all(int(v.split()[3])>0 for v in views)
    return dict(library_sha256=hashlib.sha256(raw).hexdigest(),views=views,bytes=len(stream),input=hashlib.sha256(stream).hexdigest())
