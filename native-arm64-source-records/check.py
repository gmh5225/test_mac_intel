"""Replay Microsoft ARM64 register and stack call contracts in a native process."""
from pathlib import Path
import ctypes
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys

root = Path(__file__).resolve().parent
out = Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=True)
local = sys.platform != "win32"
if local:
    manifest = json.loads(Path(sys.argv[2]).read_text())
    provider = next(p for l in manifest["libraries"] for p in l["providers"] if p["name"] == "EappcfgRuntime")
    compiler = provider["metadata"]["sdk_runtime_bridge"]["arguments"]
    linker, reader = "lld-link-23", "llvm-readobj-23"
else:
    machine, native = ctypes.c_ushort(), ctypes.c_ushort()
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.GetCurrentProcess.restype = ctypes.c_void_p
    k.IsWow64Process2.argtypes = [ctypes.c_void_p,ctypes.POINTER(ctypes.c_ushort),ctypes.POINTER(ctypes.c_ushort)]
    assert k.IsWow64Process2(k.GetCurrentProcess(),ctypes.byref(machine),ctypes.byref(native))
    assert (machine.value,native.value)==(0,0xaa64)
    compiler = [shutil.which("clang"),"--target=aarch64-pc-windows-msvc","-fms-extensions","-fms-compatibility","-D_ARM64_=1","-DUNICODE=1"]
    linker, reader = shutil.which("lld-link"), shutil.which("llvm-readobj")
source = json.loads((root/"source.json").read_text())
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
for filename,digest in source["files"].items():
    if filename.endswith(".c"): assert sha(root/filename)==digest
def run(args):
    subprocess.run(list(map(str,args)),check=True,cwd=out)
def cc(filename,opt="O1"):
    obj=out/(filename+"-"+opt+".obj")
    run([*compiler,"-std=gnu17","-ffreestanding","-fno-stack-protector","-fno-optimize-sibling-calls","-"+opt,"-c",root/(filename+".c"),"-o",obj])
    return obj
def link(file,*args):
    run([linker,"/machine:arm64","/nologo","/nodefaultlib","/timestamp:0","/out:"+str(file),*args])
    data=file.read_bytes()
    pe=struct.unpack_from("<I",data,60)[0]
    assert struct.unpack_from("<H",data,pe+4)[0]==0xaa64
obs=[]
main,observer=cc("eap-main"),cc("eap-observe")
sdk_libs=Path(sys.argv[3]) if local else Path(os.environ["NEVERD_TEST_SDK_LIBDIR"])
library=next(s for s in sdk_libs.iterdir() if s.name.lower()=="bcp47mrm.lib")
eap_library=next(s for s in sdk_libs.iterdir() if s.name.lower()=="eappcfg.lib")
def query(dll,name):
    f=getattr(ctypes.WinDLL(str(dll)),name);f.argtypes=[ctypes.c_wchar_p];f.restype=ctypes.c_bool
    return [bool(f(t)) for t in ("en-US","en__US","fr","bad tag!")]
if not local:
    expected=query("bcp47mrm.dll","IsWellFormedTag")
    assert expected==[True,False,True,False],expected
for route in ("source","highc","llvmc"):
    for opt in ("O0","O2"):
        exe=out/("record-"+route+opt+".exe")
        eap_pe=out/("eap-"+route+opt+".dll")
        link(eap_pe,"/dll","/noentry","/export:InspectEapHostPeerInvokeConfigUI",cc("eap-"+route,opt),eap_library)
        eap_table=subprocess.check_output([reader,"--coff-imports",eap_pe],text=True)
        assert [s.strip().lower() for s in re.findall(r"^  Name: (.*)$",eap_table,re.M)]==["eappcfg.dll"]
        assert re.findall(r"^  Symbol: ([^ \r\n]+) \(",eap_table,re.M)==["EapHostPeerInvokeConfigUI"]
        link(exe,"/entry:main","/subsystem:console","/alternatename:EapHostPeerInvokeConfigUI=ObserveInputs",cc("eap-"+route,opt),observer,main)
        dll=out/("tag-"+route+opt+".dll")
        link(dll,"/dll","/noentry","/export:InspectIsWellFormedTag",cc("tag-"+route,opt),library)
        table=subprocess.check_output([reader,"--coff-imports",dll],text=True)
        assert [s.strip().lower() for s in re.findall(r"^  Name: (.*)$",table,re.M)]==["bcp47mrm.dll"]
        assert re.findall(r"^  Symbol: ([^ \r\n]+) \(",table,re.M)==["IsWellFormedTag"]
        row=dict(route=route,opt=opt,eap_sha256=sha(exe),tag_sha256=sha(dll))
        if not local:
            run([exe])
            row["eap_exit"]=0
            row["tag"]=query(dll.resolve(),"InspectIsWellFormedTag")
            assert row["tag"]==expected
        obs.append(row)
report=dict(revision=source["revision"],native=not local,observations=obs,original_import_libraries={x.name:sha(x) for x in (library,eap_library)})
if not local: report.update(machine=native.value,process_machine=machine.value,expected=expected)
(out/"run.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps(report,indent=2))
