"""Run original and decompiled private DLL calls on the native Windows ARM64 ABI."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

engine = Path(sys.argv[1]).resolve()
root = Path(sys.argv[2]).resolve()
report = Path(sys.argv[3]).resolve()
root.mkdir(parents=True, exist_ok=True)
os.chdir(root)
# Public WDK names intentionally identify different functions in this test DLL.
# The provider and the executable that checks its inputs compile independently.
cases = [
    ("RtlInitUnicodeString", "U a, U b, U c", "x, 42, 71",
     "return a + 3*b + 7*c;", "x + 623"),
    ("ZwClose", "U a, U b, U c, U d, U e, U f", "x, 2, 3, 4, 5, 6",
     "return a + 3*b + 5*c + 7*d + 11*e + 13*f;", "x + 182"),
    ("KeSetEvent", "void", "", "return 0x8ddc;", "0x8ddc"),
    ("KeClearEvent", "double a, U b, double c", "1.5, x, 2.25",
     "return b + (U)(4*a + 4*c);", "x + 15"),
    ("KeGetCurrentThread", "U a, ...", "x, (U)11, (U)13",
     "va_list v; va_start(v,a); U b=va_arg(v,U); U c=va_arg(v,U); "
     "va_end(v); return a+b+c;", "x + 24"),
]
target = "--target=aarch64-pc-windows-msvc"
reader = os.environ["NEVERD_READOBJ"]
word = "typedef unsigned long long U;\n"
declarations = "".join(f"U {n}({p});\n" for n,p,*_ in cases)

def run(*args):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError(f"{args[0]} returned {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result.stdout

def compile_source(path):
    obj = path.with_suffix(".obj")
    run("clang-cl", target, "/nologo", "/MT", "/O2", "/clang:-std=gnu17",
        "/clang:-fno-strict-aliasing", "/clang:-fno-builtin",
        "/clang:-fno-optimize-sibling-calls", "/c", path, "/Fo" + str(obj))
    return obj

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def machine(path):
    data = Path(path).read_bytes()
    header = int.from_bytes(data[0x3c:0x40],"little")
    assert data[header:header+4] == b"PE\0\0"
    return int.from_bytes(data[header+4:header+6],"little")

assert machine(engine) == 0xaa64
provider = Path("provider.c")
provider.write_text("#include <stdarg.h>\n"+word+"".join(
    f"__declspec(dllexport) U {n}({p}) {{ {body} }}\n" for n,p,_,body,_ in cases))
run("clang-cl", target, "/nologo", "/LD", compile_source(provider), "/Feprobehost.dll",
    "/link", "/implib:probehost.lib")
original = Path("caller.c")
source = word + "".join(f"__declspec(dllimport) U {n}({p});\n" for n,p,*_ in cases)
for n,_,args,_,_ in cases:
    source += f"__declspec(dllexport) U Probe{n}({'U x' if args else 'void'}) {{ return {n}({args}); }}\n"
original.write_text(source)
obj = compile_source(original)
image = Path("input.dll")
run("clang-cl", target, "/nologo", "/LD", obj, "probehost.lib", "/Fe"+str(image))
exports = run(reader, "--file-headers", "--coff-exports", image)
image_base = int(re.search(r"ImageBase: (0x[0-9A-Fa-f]+)", exports)[1],16)
entries = {n:image_base+int(a,16) for n,a in re.findall(r"Name: Probe(\w+)\s+RVA: (0x\w+)",exports)}
assert set(entries)=={r[0] for r in cases}
assert machine(image)==machine("probehost.dll")==0xaa64

# The official SDK harness already verified IcmpCloseHandle. This provider
# checks private prototypes even when their export names collide with the WDK.
directory = os.add_dll_directory(str(engine.parent))
lib = ctypes.CDLL(str(engine))
ptr = ctypes.c_void_p
def function(name, ret, args):
    f = getattr(lib,"neverd_"+name)
    f.restype=ret
    f.argtypes=args
    return f

create=function("session_create",ptr,[])
load=function("session_load",ctypes.c_int,[ptr,ctypes.c_char_p])
declare=function("local_types_declare",ptr,[ptr,ctypes.c_char_p,ctypes.c_char_p])
view=function("ir_view_ex_json",ptr,[ptr,ctypes.c_uint64,ctypes.c_char_p,ctypes.c_size_t,
                                      ctypes.c_size_t,ctypes.c_char_p])
free=function("free_string",None,[ptr])
last=function("last_error",ptr,[ptr])
destroy=function("session_destroy",None,[ptr])
def take(value):
    if not value:
        return ""
    try:
        return ctypes.string_at(value).decode()
    finally:
        free(value)

harness = Path("harness.c")
text = word+"".join(f"extern U Probe{n}({'U' if a else 'void'});\n" for n,_,a,_,_ in cases)
text += "int main(void) { for (U x=0; x<50; ++x) {\n"
for i,(n,_,a,_,expect) in enumerate(cases):
    text += f" if (Probe{n}({'x' if a else ''}) != ({expect})) return {i+1};\n"
harness.write_text(text+"} return 0; }\n")
harness_obj = compile_source(harness)
rows = []
session = create()
try:
    assert load(session, str(image.resolve()).encode()), take(last(session))
    response = json.loads(take(declare(session, (word+declarations).encode(), None)))
    assert not response.get("problems"), response
    for route,stage,symbolic in [("original",None,False),("highc","c",False),
                                 ("symbolic","c",True),("llvmc","llvmc",False)]:
        objects = []
        sources = {}
        if stage is None:
            objects.append(obj)
            sources["original"]=digest(original)
        else:
            for n,_,_,_,_ in cases:
                options = json.dumps({"symbolic":symbolic}).encode()
                raw = take(view(session, entries[n], stage.encode(), 0, 2048, options))
                assert raw,take(last(session))
                page = json.loads(raw)
                assert page["complete"] and "Probe"+n+"(" in page["text"]
                path=Path(route+"-"+n+".c")
                path.write_text(page["text"],encoding="utf-8")
                objects.append(compile_source(path))
                sources[n]=digest(path)
        exe=Path(route+".exe")
        run("clang-cl",target,"/nologo",harness_obj,*objects,"probehost.lib","/Fe"+str(exe))
        imports=run(reader,"--coff-imports",exe)
        block,=[b for b in imports.split("Import {") if "Name: probehost.dll" in b]
        assert all("Symbol: "+n+" (" in block for n in entries)
        assert machine(exe)==0xaa64
        run(exe.resolve())
        rows.append(dict(route=route,calls=len(cases)*50,source_sha256=sources,
                         executable_sha256=digest(exe)))
        print(route,"passed",flush=True)
finally:
    destroy(session)
    directory.close()
report.write_text(json.dumps(dict(revision=os.environ["NEVERD_REV"],machine=machine(engine),
                                  engine_sha256=digest(engine),provider_sha256=digest("probehost.dll"),
                                  observations=rows),indent=2)+"\n")
