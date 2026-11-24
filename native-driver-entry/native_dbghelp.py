"""Use a process-local DbgHelp virtual module to check the original DWORD entry on ARM64."""
from pathlib import Path
import ctypes
import hashlib
import re
import shutil
import subprocess

def check_legacy_module_base(engine, manifest, out):
    out = Path(out)
    out.mkdir()
    provider = next(p for lib in manifest["libraries"] for p in lib["providers"]
                    if p["name"] == "DbgHelpLegacy")
    bridge = provider["metadata"]["sdk_runtime_bridge"]
    library = Path(bridge["runtime_import_library"]["file"])
    actual = Path(bridge["source"]).resolve().as_posix()
    flags = bridge["arguments"]
    assert "-D_IMAGEHLP_SOURCE_" in flags
    original = out / "original.c"
    original.write_text('#include "' + actual + '"\n'
        '__declspec(dllexport) DWORD WINAPI InspectLegacyModuleBase(HANDLE p, DWORD a) {\n'
        '    return SymGetModuleBase(p, a);\n}\n', encoding="utf-8")
    link = shutil.which("lld-link")
    assert link
    obj_reader = bridge["runtime_import_library"]["command"][0]
    def build(src, opt, path):
        obj = path.with_suffix(".obj")
        subprocess.run([*flags, opt, "-fno-stack-protector", "-fno-optimize-sibling-calls",
                        "-c", src, "-o", obj], check=True)
        subprocess.run([link, "/machine:arm64", "/dll", "/noentry", "/nodefaultlib",
                        "/export:InspectLegacyModuleBase", "/out:" + str(path), obj, library], check=True)
        data = subprocess.check_output([obj_reader,"--coff-imports",path], text=True)
        assert re.findall(r"^  Name: (.*)$",data,re.M) and [v.strip().lower() for v in re.findall(r"^  Name: (.*)$",data,re.M)]==["dbghelp.dll"]
        assert re.findall(r"^  Symbol: ([^ \r\n]+) \(",data,re.M)==["SymGetModuleBase"]
    image = out / "caller.dll"
    build(original, "-O1", image)
    dbg = ctypes.WinDLL("dbghelp.dll", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    word, wide, ptr = ctypes.c_uint32, ctypes.c_uint64, ctypes.c_void_p
    def function(dll, name, result, args):
        f = getattr(dll, name)
        f.restype = result
        f.argtypes = args
        return f
    token = function(kernel, "GetCurrentProcess", ptr, [])()
    initialize = function(dbg, "SymInitializeW", ctypes.c_int, [ptr, ctypes.c_wchar_p, ctypes.c_int])
    cleanup = function(dbg, "SymCleanup", ctypes.c_int, [ptr])
    load = function(dbg, "SymLoadModuleExW", wide, [ptr, ptr, ctypes.c_wchar_p, ctypes.c_wchar_p, wide, word, ptr, word])
    raw = function(dbg, "SymGetModuleBase", word, [ptr, word])
    assert initialize(token, ".", 0),ctypes.get_last_error()
    base = 0x16000000
    observations=[]
    try:
        assert load(token, None, "NeverDLegacyProbe.dll", "NeverDLegacyProbe", base, 0x2000, None, 1)==base,ctypes.get_last_error()
        queries=[base+0x128, base+0x1fff, base+0x2000]
        reference=[raw(token,a) for a in queries]
        assert reference==[base, base, 0],reference
        for route in ("original", "highc", "llvmc"):
            c=original
            if route!="original":
                c=out/(route+".c")
                subprocess.run([engine,"decompile",image,"--func","InspectLegacyModuleBase",
                               *(["--llvm"] if route=="llvmc" else []),"-o",c],check=True)
            for opt in ("-O0","-O2"):
                dll=out/(route+opt+".dll")
                build(c,opt,dll)
                loaded=ctypes.WinDLL(str(dll.resolve()))
                get=function(loaded,"InspectLegacyModuleBase",word,[ptr,word])
                result=[get(token,a) for a in queries]
                assert result==reference,(route,opt,result,reference)
                observations.append(dict(route=route, opt=opt, module_bases=result,
                                         binary_sha256=hashlib.sha256(dll.read_bytes()).hexdigest()))
    finally:
        assert cleanup(token),ctypes.get_last_error()
    return dict(api="SymGetModuleBase",module="dbghelp.dll",queries=queries,
                expected=reference,observations=observations)
