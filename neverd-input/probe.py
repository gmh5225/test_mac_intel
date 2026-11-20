from pathlib import Path
import json, re, struct, subprocess, sys
src, out = Path(sys.argv[1]), Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
text=src.read_text()
body=re.search(r'A64_LEAF_TEXT\(kDispatchLeaves, R"asm\((.*?)\)asm"\)',text,re.S).group(1)
asm=out/"leaves.S"; asm.write_text("#define NEVERD_TEST_EMBEDDED_DISPATCH 1\n"+body)
for linker in sys.argv[3:]:
    image=out/(linker+".dylib")
    cmd=["/usr/bin/clang","-target","arm64e-apple-macosx15.0","-O2","-fomit-frame-pointer","-dynamiclib","-Wl,-headerpad,0","-Wl,-data_in_code_info"]
    if linker=="classic": cmd.append("-Wl,-ld_classic")
    subprocess.run([*cmd,asm,"-o",image],check=True)
    data=bytearray(image.read_bytes());pos=32; found=0
    for _ in range(struct.unpack_from("<I",data,16)[0]):
        typ,size=struct.unpack_from("<II",data,pos)
        if typ==0x19:
            for i in range(struct.unpack_from("<I",data,pos+64)[0]):
                sec=pos+72+i*80
                if data[sec:sec+16].rstrip(b"\0")==b"__text":
                    flag=struct.unpack_from("<I",data,sec+64)[0]
                    struct.pack_into("<I",data,sec+64,flag & ~0x80000000)
                    found+=1
        pos+=size
    assert found==1; image.write_bytes(data)
    subprocess.run(["/usr/bin/codesign","-f","-s","-","-i","com.neverd.arm64e.republication",image],check=True)
    subprocess.run(["/usr/bin/codesign","--verify","--strict",image],check=True)
    for flag in ("--data-in-code","--unwind-info"):
        subprocess.run(["xcrun","llvm-objdump","--macho",flag,image],check=True)
