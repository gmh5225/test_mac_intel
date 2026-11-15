import json, re, subprocess, hashlib
from pathlib import Path
p=json.loads(Path(__file__).with_name("Debug.def").read_text())
out=Path(p["output"]).resolve();out.mkdir(exist_ok=True)
text=Path(p["fixture"]).read_text()
def body(name,kind):
 return re.search(r"ASYNC_FRAME_TEXT\("+name+r", R\""+kind+r"\((.*?)\)"+kind+r"\"\)",text,re.S).group(1)
header=Path(p["include"])/"neverd/runtime/DarwinArm64eSystemUnwind.h"
h=header.read_text()
for old,new in p["header_replacements"]:
 assert h.count(old)==1,(old,h.count(old))
 h=h.replace(old,new)
header.write_text(h)
asm=body("kSignalNonCallBody","asm")
driver=body("kSignalScopeDriver","cpp")
for old,new in p["replacements"]:
 assert driver.count(old)==1,(old,driver.count(old))
 driver=driver.replace(old,new)
def run(name,args):
 r=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=p["timeout"])
 (out/(name+".json")).write_text(json.dumps({"args":list(map(str,args)),"returncode":r.returncode,"stdout":r.stdout,"stderr":r.stderr},indent=2))
 print(name,r.returncode,r.stdout,r.stderr,flush=True);return r.returncode
inc=Path(p["include"]).resolve();cc=["/usr/bin/clang++","-target",p["target"],"-std=c++20","-O2","-I",str(inc)]
failures=[]
for case in p["cases"]:
 name=case["name"]
 scope=out/(name+".S");scope.write_text(asm)
 writer=out/(name+"-writer.cpp");writer.write_text(p["writer"].replace("{20,24,true,0}","{24,28,true,0}") if case["catch"] else p["writer"])
 flags=(["-DNEVERD_LOCAL_CATCH"] if case["catch"] else [])
 framework=["-fobjc-exceptions","-framework","Foundation"] if case["objc"] else []
 assert run(name+"-compile-writer",cc+[writer,"-o",out/(name+"-writer")])==0
 assert run(name+"-write-rules",[out/(name+"-writer"),out/(name+"-rules")])==0
 assert run(name+"-compile-scope",["/usr/bin/clang++","-target",p["target"],"-O0","-DNEVERD_LIVE_LR","-dynamiclib",scope,"-o",out/(name+".dylib")]+flags+(["-DNEVERD_OBJC_PERSONALITY"] if case["objc"] else [])+framework)==0
 for control in [False,True]:
  variant=name+("-control" if control else "-walk")
  source=driver
  if control:
   for old,new in p["control_replacements"]:
    assert source.count(old)==1,(old,source.count(old))
    source=source.replace(old,new)
  file=out/(variant+(".mm" if case["objc"] else ".cpp"));file.write_text(source)
  binary=out/variant
  assert run(variant+"-compile",cc+["-DNEVERD_NONCALL_SCOPE",file,"-o",binary]+flags+framework)==0
  for alternate in ["0","1"]:
   if run(variant+"-alt"+alternate,[binary,out/(name+".dylib"),out/(name+"-rules"),"0",alternate,"1"]):failures.append(variant+"-alt"+alternate)
  (out/(variant+".sha256")).write_text(hashlib.sha256(binary.read_bytes()).hexdigest());binary.unlink()
 run(name+"-disassembly",["/usr/bin/otool","-tvV",out/(name+".dylib")])
 for suffix in ["-writer",".dylib"]:
  f=out/(name+suffix);(out/(name+suffix+".sha256")).write_text(hashlib.sha256(f.read_bytes()).hexdigest());f.unlink()

if failures:raise SystemExit(str(failures))
