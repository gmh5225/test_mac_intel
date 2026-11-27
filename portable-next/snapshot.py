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
    # Masked EVEX register moves, memory loads/stores and displacements at
    # formatting boundaries. The driver also starts at each interior byte.
    masked = bytearray()
    for ext in (0x01,0x91,0xf1):
        for p2 in (0x09,0x2f,0x49,0xc9):
            for op in (0x6f,0x7f):
                word = bytes((0x62,ext,0x7f,p2,op))
                for rm in (0xc0,0xd1,0xff,0x07):
                    masked.extend(word + bytes((rm,)))
                for sib in (0x77,0xed,0xff):
                    masked.extend(word + bytes((0x44,sib,0x80)))
                    for disp in (0,9,10,0x7fffffff,0x80000000,0xffffffff):
                        masked.extend(word + bytes((0xbc,sib)) + disp.to_bytes(4,'little'))
    source.extend(masked)
    for opcode in range(0,0x40,8):
        source.extend(bytes([opcode+4,0x7f,opcode+5,0x78,0x56,0x34,0x12]))
    for head in (0xf8,0xfc,0xe8,0x78):
        source.extend(bytes([0xc5,head,0x77,0x90]))
    for prefix in (b'',bytes((0x66,)),bytes((0x67,0x66)),bytes((0x66,0x66)),bytes((0xf3,0x66))):
        for op in range(0x4f,0x61):
            source.extend(prefix+bytes((op,0x90)))
        for op in range(0xb7,0xc1):
            for imm in (0,9,10,127,128,0x80000000,0xffffffff):
                source.extend(prefix+bytes((op,))+imm.to_bytes(4,'little'))
    sample=temp/'curated-x86.bin';sample.write_bytes(source)
    modes=[(0,0,0),(0,1,0)]
    if profile!='diet':modes.append((0,1,1))
    if profile not in ('diet','noatt'):modes.append((1,1,1))
    results={};comparisons={}
    for bits in (16,32,64):
        for att,text,detail in modes:
            args=(str(bits),str(att),str(text),str(detail),'1')
            with sp.Popen([exe,*args,sample,str(int(label.startswith("base-")))],stdout=sp.PIPE,stderr=sp.PIPE) as proc:
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

    return dict(comparisons=comparisons,library_sha256=hashlib.sha256(raw).hexdigest(),ppc_index_symbol=b"PPC_setAliasId" in raw,records=records,bytes=len(source),sha256=hashlib.sha256(source).hexdigest(),snapshots=results)
