from pathlib import Path
import hashlib,json,subprocess,tempfile
root=Path(__file__).resolve().parent
literal=""".text
.p2align 2
.globl _read_counter
_read_counter:
.cfi_startproc
 ldr x8, Lpointer
 ldr w0, [x8]
 ret
.cfi_endproc
{pool}
.p2align 3
{begin}
Lpointer: .quad _counter
{end}
.data
.p2align 3
_counter: .quad 37
.subsections_via_symbols
"""
absolute=""".text
.p2align 2
.globl _counter
_counter: mov w0, #37
 ret
.data_region {kind}
 .long _counter
.end_data_region
"""
result={}
with tempfile.TemporaryDirectory() as td:
 t=Path(td)
 for label,source,opts in [
  ("text-pointer-modern",literal.format(pool="",begin=".data_region",end=".end_data_region"),[]),
  ("text-pointer-classic",literal.format(pool="",begin=".data_region",end=".end_data_region"),["-Wl,-ld_classic,-data_in_code_info"]),
  ("separate-const-pool",literal.format(pool=".section __DATA_CONST,__const",begin="",end=""),[]),
  ("absolute-region-spelling",absolute.format(kind="jta32"),["-Wl,-ld_classic,-data_in_code_info"]),
  ("absolute-symbol-fixup32",absolute.format(kind="jt32"),["-Wl,-ld_classic,-data_in_code_info"])]:
  s=t/(label+".S"); o=t/(label+".dylib");s.write_text(source)
  proc=subprocess.run(["/usr/bin/clang","-target","arm64e-apple-macos13.0","-dynamiclib",*opts,s,"-o",o],capture_output=True,text=True)
  diag=proc.stderr.replace(str(t),"<fixture>")
  result[label]={"exit":proc.returncode,"stderr":diag,"input_sha256":hashlib.sha256(s.read_bytes()).hexdigest()}
  if o.is_file():
   result[label]["dylib_sha256"]=hashlib.sha256(o.read_bytes()).hexdigest()
   fix=subprocess.run(["xcrun","dyld_info","-fixups",o],capture_output=True,text=True)
   result[label]["fixups"]=(fix.stdout+fix.stderr).replace(str(t),"<fixture>")
(root/"object-formats.json").write_text(json.dumps(result,indent=2)+"\n")
for k,v in result.items(): print(k,v["exit"],v["stderr"][-290:])
