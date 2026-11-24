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

def check_boolean_tag(engine, manifest, out, cache):
    out = Path(out)
    out.mkdir()
    provider = next(p for lib in manifest["libraries"] for p in lib["providers"] if p["name"]=="Bcp47mrmRuntime")
    bridge = provider["metadata"]["sdk_runtime_bridge"]
    module = bridge["runtime_exports"]["module"]
    name = "IsWellFormedTag"
    assert module.lower()=="bcp47mrm.dll" and name in bridge["runtime_exports"]["names"]
    sdk = Path(bridge["source"]).resolve().as_posix()
    original = out/"original.c"
    original.write_text(f'#include <stdbool.h>\n#include "{sdk}"\n__declspec(dllexport) bool InspectTag(PCWSTR tag) {{ return IsWellFormedTag(tag); }}\n',encoding="utf-8")
    reader = next(p for lib in manifest["libraries"] for p in lib["providers"] if p["name"]=="DbgHelpLegacy")["metadata"]["sdk_runtime_bridge"]["runtime_import_library"]["command"][0]
    linker = shutil.which("lld-link")
    assert linker
    from zipfile import ZipFile
    imp = out/"bcp47mrm.lib"
    package = Path(cache)/"microsoft.windows.sdk.cpp.arm64.10.0.26100.6584.nupkg"
    with ZipFile(package) as sdk_libs:
        member, = [n for n in sdk_libs.namelist() if n.lower()=="c/um/arm64/bcp47mrm.lib"]
        imp.write_bytes(sdk_libs.read(member))
    def build(source,opt,dll):
        obj=dll.with_suffix(".obj")
        subprocess.run([*bridge["arguments"],"-std=c17","-ffreestanding","-fno-optimize-sibling-calls","-fno-stack-protector",opt,"-c",source,"-o",obj],check=True)
        subprocess.run([linker,"/machine:arm64","/dll","/noentry","/nodefaultlib","/export:InspectTag","/out:"+str(dll),obj,imp],check=True)
        output=subprocess.check_output([reader,"--coff-imports",dll],text=True)
        assert [s.strip().lower() for s in re.findall(r"^  Name: (.*)$",output,re.M)]==[module.lower()]
        assert re.findall(r"^  Symbol: ([^ \r\n]+) \(",output,re.M)==[name]
    probe=out/"probe.dll"
    build(original,"-O1",probe)
    def execute(dll,func):
        query=getattr(ctypes.WinDLL(str(dll)),func)
        query.argtypes=[ctypes.c_wchar_p]
        query.restype=ctypes.c_bool
        return [bool(query(t)) for t in ("en-US","en__US","fr","bad tag!")]
    expected=execute(module,name)
    assert expected==[True,False,True,False],expected
    observations=[]
    for route in ("original","highc","llvmc"):
        source=original
        if route!="original":
            source=out/(route+".c")
            subprocess.run([engine,"decompile",probe,"--func","InspectTag",*(["--llvm"] if route=="llvmc" else []),"-o",source],check=True)
        for opt in ("-O0","-O2"):
            dll=out/(route+opt+".dll")
            build(source,opt,dll)
            results=execute(dll.resolve(),"InspectTag")
            assert results==expected,(route,opt,results)
            observations.append(dict(route=route,opt=opt,observed=results,sha256=hashlib.sha256(dll.read_bytes()).hexdigest()))
    return dict(name=name,module=module,source="original Microsoft SDK declaration and import library", import_library_sha256=hashlib.sha256(imp.read_bytes()).hexdigest(),
                expected=expected,observations=observations)
