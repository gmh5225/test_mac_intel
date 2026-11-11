import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess as sp
import tempfile

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parent / "capstone-evidence"
BASE = "c3fd1f110810201fa4d82a2d057ed82f5b08d5b1"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def snapshot(exe):
    data = exe.read_bytes()
    pe, = struct.unpack_from("<I", data, 0x3c)
    assert data[pe:pe+4] == b"PE\0\0"
    count, = struct.unpack_from("<H", data, pe+6)
    size, = struct.unpack_from("<H", data, pe+20)
    sections = {}
    for i in range(count):
        off = pe+24+size+i*40
        name = data[off:off+8].rstrip(b"\0").decode("ascii")
        virtual, address, length, start = struct.unpack_from("<4I", data, off+8)
        props, = struct.unpack_from("<I", data, off+36)
        sections[name] = [address, virtual, props, digest(data[start:start+length])]
    assert ".text" in sections and ".pdata" in sections
    return dict(file=digest(data), sections=sections)


def section_diffs(old, new, mapfile):
    import bisect
    import re
    symbols = []
    for line in mapfile.splitlines():
        m = re.match(r"\s+[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{8,16})\s+", line)
        if m:
            symbols.append((int(m[2], 16), m[1]))
    symbols.sort()
    def sections(buf):
        pe, = struct.unpack_from("<I",buf,0x3c)
        count, = struct.unpack_from("<H",buf,pe+6)
        opt, = struct.unpack_from("<H",buf,pe+20)
        image_base, = struct.unpack_from("<Q",buf,pe+24+24)
        result={}
        for i in range(count):
            at=pe+24+opt+i*40
            name=buf[at:at+8].rstrip(b"\0").decode("ascii")
            _, addr, size, start=struct.unpack_from("<4I",buf,at+8)
            result[name]=(image_base+addr,buf[start:start+size])
        return result
    left, right = sections(old), sections(new)
    changes={}
    for name,(base,before) in left.items():
        new_base,after=right[name]
        assert new_base==base and len(before)==len(after)
        if after==before:
            continue
        runs=[]
        for i,(a,b) in enumerate(zip(before,after)):
            if a==b:
                continue
            if runs and i==runs[-1][1]:
                runs[-1][1]=i+1
            else:
                runs.append([i,i+1])
        items=[]
        for a,b in runs[:100]:
            address=base+a
            k=bisect.bisect_right(symbols,(address,chr(0x10ffff)))-1
            start,symbol=symbols[k] if k>=0 else (0,"")
            items.append(dict(address=hex(address),length=b-a,symbol=symbol,symbol_offset=hex(address-start),
                              old=before[max(0,a-8):min(b+8,a+64)].hex(),new=after[max(0,a-8):min(b+8,a+64)].hex()))
        changes[name]=dict(ranges=len(runs),bytes=sum(b-a for a,b in runs),examples=items)
    return changes


def main(tmp):
    src = tmp / "capstone"
    env = dict(os.environ)
    vs = Path(os.environ["ProgramFiles"]) / "Microsoft Visual Studio/2022"
    vcvars = next(vs.glob("*/VC/Auxiliary/Build/vcvars64.bat"))
    (tmp / "load-vc.cmd").write_text('@echo off\ncall "'+str(vcvars)+'" >nul\nif errorlevel 1 exit /b 1\nset\n')
    lines = sp.check_output(["cmd.exe", "/d", "/c", "load-vc.cmd"], cwd=tmp).decode("mbcs").splitlines()
    for line in lines:
        if "=" in line and not line.startswith("="):
            name, value = line.split("=", 1)
            env[name.upper()] = value
    env["CL"] = "/Brepro"
    def run(args, cwd=tmp):
        print(" ".join(map(str, args)), flush=True)
        sp.run(list(map(str,args)), cwd=cwd, env=env, check=True)
    run(["git","init","-q",src])
    run(["git","config","core.autocrlf","false"], src)
    run(["git","remote","add","origin","https://github.com/NeverSight/capstone.git"], src)
    run(["git","fetch","-q","--depth=1","origin",BASE], src)
    run(["git","checkout","-q","--detach","FETCH_HEAD"], src)
    (tmp / "smoke.c").write_text('''#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    static const uint8_t input[] = {0x48, 0x89, 0xd8, 0x90};
    const uint8_t *cursor = input;
    size_t n = sizeof(input);
    uint64_t ip = 0;
    csh h;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) || cs_option(h, CS_OPT_DETAIL, CS_OPT_ON)) return 1;
    cs_insn *insn = cs_malloc(h);
    if (!insn || !cs_disasm_iter(h, &cursor, &n, &ip, insn) || insn->size != 3 || strcmp(insn->mnemonic, "mov")) return 2;
    cs_regs rr, ww; uint8_t nr, nw;
    if (cs_regs_access(h, insn, rr, &nr, ww, &nw) || !nr || !nw) return 3;
    puts(insn->op_str);
    cs_free(insn, 1);
    return cs_close(&h);
}
''')
    (tmp / "CMakeLists.txt").write_text('''cmake_minimum_required(VERSION 3.20)
project(image_probe C CXX)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
add_subdirectory(capstone)
add_executable(runtime_image smoke.c)
target_link_libraries(runtime_image PRIVATE capstone_static)
target_link_options(runtime_image PRIVATE /INCREMENTAL:NO /Brepro /DEBUG:NONE /MAP:runtime_probe.map)
''')
    build = tmp / "build"
    run(["cmake","-S",tmp,"-B",build,"-G","Ninja","-DCMAKE_BUILD_TYPE=Release",
         "-DCMAKE_C_COMPILER=cl","-DCMAKE_CXX_COMPILER=cl","-DCAPSTONE_BUILD_SHARED_LIBS=OFF",
         "-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=OFF","-DCAPSTONE_BUILD_CSTOOL=OFF",
         "-DCAPSTONE_BUILD_LEGACY_TESTS=OFF"])
    build_cmd = ["cmake","--build",build,"--target","runtime_image","--parallel","4"]
    run(build_cmd)
    exe = build / "runtime_image.exe"
    run([exe])
    before_bytes = exe.read_bytes()
    before = snapshot(exe)
    objects = list(build.rglob("*.obj"))
    target, = [f for f in objects if f.name.lower() == "x86disassemblerdecoder.c.obj"]
    base_objects = {f:digest(f.read_bytes()) for f in objects}
    timestamps = {f:(f.stat().st_atime_ns,f.stat().st_mtime_ns)
                  for f in src.rglob("*") if f.is_file() and ".git" not in f.parts}
    patch = HERE / "scoped.patch"
    assert digest(patch.read_bytes()) == (HERE / "scoped.patch.sha256").read_text().strip()
    run(["git","apply","--check",patch], src)
    run(["git","apply","--whitespace=nowarn",patch], src)
    # The full two-tree VS build already compared every runtime object. Replay
    # its sole changed MD translation unit in the same native executable.
    for path, times in timestamps.items():
        os.utime(path, ns=times)
    target.unlink()
    run(build_cmd)
    run([exe])
    after = snapshot(exe)
    changed = [str(f.relative_to(build)) for f in objects if digest(f.read_bytes()) != base_objects[f]]
    data = dict(reference=BASE, flags="/MD /O2 /Brepro", before=before, after=after, changed_objects=changed,
                same_image=before["file"]==after["file"], same_sections=before["sections"]==after["sections"])
    data["section_differences"] = section_diffs(before_bytes,exe.read_bytes(),(build/"runtime_probe.map").read_text(errors="replace"))
    (EVIDENCE / "linked-image.json").write_text(json.dumps(data, indent=2)+"\n")
    print(json.dumps(data), flush=True)
    assert [Path(n).name.lower() for n in changed] == ["x86disassemblerdecoder.c.obj"]
    assert before["sections"].keys() == after["sections"].keys()


if __name__ == "__main__":
    EVIDENCE.mkdir(exist_ok=True)
    workspace = tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"])
    with workspace as temp:
        root = Path(temp)
        try:
            main(root)
        finally:
            size = sum(f.stat().st_size for f in root.rglob("*") if f.is_file())
            workspace.cleanup()
            (EVIDENCE / "cleanup.json").write_text(json.dumps(dict(removed=not root.exists(),bytes=size)))
