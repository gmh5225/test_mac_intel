"""Read the ELF .text of the digest-pinned Malta I7200 kernel used by QEMU's functional test."""
from pathlib import Path
import hashlib, lzma, struct, subprocess as sp
URL='http://mipsdistros.mips.com/LinuxDistro/nanomips/kernels/v4.15.18-432-gb2eb9a8b07a1-20180627102142/generic_nano32r6el_page4k.xz'
DIGEST='019e034094ac6cf3aa77df5e130fb023ce4dbc804b04bfcc560c6403e1ae6bdb'
def prepare(folder):
    f=folder/'malta-kernel.xz'
    sp.run(['curl','-fsSL','--retry','3','--max-time','90','-o',f,URL],check=True)
    data=f.read_bytes()
    assert hashlib.sha256(data).hexdigest()==DIGEST, (len(data),hashlib.sha256(data).hexdigest())
    elf=lzma.decompress(data)
    assert elf[:6]==b'\x7fELF\x01\x01' and struct.unpack_from('<H',elf,18)[0]==249
    shoff=struct.unpack_from('<I',elf,32)[0]
    entsize,count,strings=struct.unpack_from('<HHH',elf,46)
    assert entsize==40 and strings<count
    sections=[struct.unpack_from('<10I',elf,shoff+i*entsize) for i in range(count)]
    names=sections[strings];names=elf[names[4]:names[4]+names[5]]
    sec,=[s for s in sections if names[s[0]:].split(b'\0',1)[0]==b'.text']
    image=elf[sec[4]:sec[4]+sec[5]];assert len(image)==sec[5]>65536
    f.unlink()
    return image,dict(url=URL,kernel_xz_sha256=DIGEST,elf_sha256=hashlib.sha256(elf).hexdigest(),text_sha256=hashlib.sha256(image).hexdigest(),text_size=len(image),virtual_address=sec[3],machine=249)
if __name__=='__main__':
    import tempfile,json
    dst=Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(dir=dst) as t:
        image,j=prepare(Path(t))
        print(j,flush=True);(dst/'kernel.json').write_text(json.dumps(j,indent=2)+'\n')
