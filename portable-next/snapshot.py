import hashlib,json,os,re,subprocess as sp
from pathlib import Path

def snapshots(src, bench, build, temp, profile, label, run, linkage):
    shared=linkage=='shared'
    if os.name=='nt':
        cache=(build/'CMakeCache.txt').read_text()
        dual='CAPSTONE_BUILD_SHARED_LIBS:BOOL=ON' in cache
        library=build/('capstone_static.lib' if not shared and dual else 'capstone.lib')
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
    for prefix in (0x66,0xf2,0xf3):
        for rex in (b'',b'\x41',b'\x48',b'\x4f'):
            for opcode in (0x10,0x11,0x28,0x29,0x58,0x5a,0x6f,0x7f):
                for addr in (b'\x03',b'\x44\x24\x80',b'\x05\x34\x12\x00\x80'):
                    source.extend(bytes([prefix])+rex+bytes([0x0f,opcode])+addr)
    source.extend(bytes.fromhex('ff 70 80 ff 34 24 ff b5 34 12 00 80 48 ff 34 24 41 ff 75 80'))

    # Also visit source/destination reversals, the three AT&T-only mnemonic suffixes,
    # upper vector registers, RIP-relative and stack addresses, and VEX forms without ModR/M.
    source.extend(bytes.fromhex('c5 f8 77 c5 fc 77 c5 f9 5a 00 c5 f9 e6 04 24 c5 fb e6 4d 80'))
    for flags in (0x78,0x79,0x7a,0x7b,0x7c,0x7d,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd):
        for opcode in (0x10,0x11,0x28,0x29,0x51,0x5a,0x5b,0x6f,0x7f,0xe6):
            source.extend(bytes([0xc5,flags,opcode,0x44,0x24,0x80,0xc5,flags,opcode,0x05,0x12,0x34,0x56,0x80]))

    for m in (0x15,0x25):
        for disp in (0,9,10,0x80,0x2345,0x7fffffff,0x80000000,0xffffffff):
            source.extend(bytes([0xff,m])+disp.to_bytes(4,'little'))
    source.extend(bytes.fromhex('c5 fb c2 da 06 62 f1 4c 0b c2 d0 a5 c5 f8 c2 c0 1f'))
    for op in (0x3c,0x3d,0xa8,0xa9):
        for prefix in (b'',bytes([0x66]),bytes([0x67]),bytes([0xf3]),bytes([0x48])):
            for value in (0,1,9,10,127,128,255,0x7fffffff,0x80000000,0xffffffff):
                width=4 if op&1 else 1
                source.extend(prefix+bytes([op])+value.to_bytes(4,'little')[:width])
    sample=temp/'curated-x86.bin';sample.write_bytes(source)
    modes=[(0,0,0),(0,1,0)]
    if profile!='diet':modes.append((0,1,1))
    if profile not in ('diet','noatt'):modes.append((1,1,1))
    results={};comparisons={}
    for bits in (16,32,64):
        for att,text,detail in modes:
            args=(str(bits),str(att),str(text),str(detail),'1')
            with sp.Popen([exe,*args,sample,"0"],stdout=sp.PIPE,stderr=sp.PIPE) as proc:
                digest=hashlib.sha256()
                for chunk in iter(lambda: proc.stdout.read(1<<16),b''):digest.update(chunk)
                diag=proc.stderr.read().decode()
                status=proc.wait()
                assert status==0,(linkage,args,status,diag)
            counts=json.loads(diag)
            key='/'.join(args[:4]);comparisons[key]={i:counts.pop(i)for i in ('floating','projected')}
            assert label.startswith('base-') or not comparisons[key]['projected']
            assert counts['accepted']>0 and len(source)==sum(counts.values())
            results['/'.join(args[:4])]=dict(sha256=digest.hexdigest(),counts=counts)

    return dict(comparisons=comparisons,library_sha256=hashlib.sha256(raw).hexdigest(),ppc_index_symbol=b"PPC_setAliasId" in raw,records=records,bytes=len(source),sha256=hashlib.sha256(source).hexdigest(),snapshots=results)
