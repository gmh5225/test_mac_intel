from pathlib import Path
import hashlib,io,platform,shutil,subprocess as sp,tarfile
from elftools.elf.elffile import ELFFile

def sha(data):return hashlib.sha256(data).hexdigest()

def fixtures(r,w,m):
    ar=shutil.which('llvm-ar') or shutil.which('ar')
    if not ar and platform.system()=='Windows':
        ar=str(Path('C:/Program Files/LLVM/bin/llvm-ar.exe'))
    for name,v in m['provenance'].items():
        s=v['source'];pe=name.startswith('putty-')
        package=w/'package';url=s['source'] if pe else s['url']
        sp.run(['curl','-fsSL','--retry','3','--max-time','120','-o',package,url],check=True)
        data=package.read_bytes()
        if pe:
            assert sha(data)==s['executable_sha256']
            start=s['section_file_offset'];code=data[start:start+s['bytes']]
        else:
            assert sha(data)==s['package_sha256']
            names=sp.check_output([ar,'t',package],text=True).splitlines()
            payload,=[n for n in names if n.startswith('data.tar')]
            stream=io.BytesIO(sp.check_output([ar,'p',package,payload]))
            if payload.endswith('.zst'):
                import zstandard
                stream=zstandard.ZstdDecompressor().stream_reader(stream)
            member='libjpeg.a' if name=='jpeg-avx2-i386' else ('libmvec.so.1' if name=='libmvec-amd64' else 'libcrypto.so.3')
            with tarfile.open(fileobj=stream,mode='r|*') as tar:
                found=[tar.extractfile(entry).read() for entry in tar if entry.isfile() and entry.name.split('/')[-1]==member]
            image,=found
            if name=='jpeg-avx2-i386':
                lib=w/'libjpeg.a';lib.write_bytes(image)
                parts=[]
                for obj,info in s['members'].items():
                    args=['bsdtar','-xOf',lib,obj] if platform.system()=='Darwin' else [ar,'p',lib,obj]
                    raw=sp.check_output(args);assert sha(raw)==info['sha256']
                    part=ELFFile(io.BytesIO(raw)).get_section_by_name('.text').data()
                    assert len(part)==info['section_bytes'];parts.append(part)
                code=b''.join(parts);lib.unlink()
            else:
                assert sha(image)==s['binary_sha256']
                code=ELFFile(io.BytesIO(image)).get_section_by_name('.text').data()
        package.unlink()
        assert sha(code)==v['text_sha256'],name
        out=w/(name+'.text');out.write_bytes(code);extent=w/(name+'.tsv')
        # The working tree on Windows may use CRLF. Verify the canonical frozen extents.
        spans=(r/'extents'/extent.name).read_bytes().replace(b'\r\n',b'\n')
        assert sha(spans)==v['extent_sha256'],name
        extent.write_bytes(spans)
        yield name,32 if 'i386' in name or 'putty-32' in name else 64,out,extent
