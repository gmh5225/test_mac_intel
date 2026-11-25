"""Compile the public fixture and both C texts produced by the specified NeverD build."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

arch = sys.argv[1]
manifest = json.loads(Path("prng-replay/sources.json").read_text())
root = Path("prng-replay")
out = Path("prng-out")
out.mkdir()
target = {"x86": "i686", "x64": "x86_64", "arm64": "aarch64"}[arch] + "-pc-windows-msvc"
cc = ["clang", "--target=" + target, "-fms-extensions", "-std=c17", "-O1", "-fno-strict-aliasing",
      "-fno-optimize-sibling-calls", "-fno-stack-protector"]
library = out / "provider.lib"
definition = out / "provider.def"
definition.write_text("LIBRARY bcryptprimitives.dll\nEXPORTS\nProcessPrng\n")
def command(args):
    r = subprocess.run(args, capture_output=True, text=True, timeout=90)
    if r.returncode:
        raise RuntimeError(f"{args[0]} returned {r.returncode}\n{r.stderr}\n{r.stdout}")
    return r.stdout

command(["lld-link", "/lib", "/machine:"+arch, "/def:"+str(definition), "/out:"+str(library)])
# The DLL names ProcessPrng without decoration, while i386 stdcall object references use @8.
aliases = ["/alternatename:_ProcessPrng@8=_ProcessPrng", "/alternatename:__imp__ProcessPrng@8=__imp__ProcessPrng"] if arch == "x86" else []
rows = []
for route in ("original", "highc", "llvmc"):
    src = root / arch / (route+".c")
    source_hash = hashlib.sha256(src.read_bytes()).hexdigest()
    assert source_hash == manifest["views"][arch][route], (route, source_hash)
    obj = out / (route+".obj")
    exe = out / (route+".exe")
    command([*cc, "-c", src, "-o", obj])
    command(["clang-cl", "--target="+target, "/nologo", "/O2", "/std:c17", "/DTEST_RECOVERED_PRNG_CALLER",
             "/DTEST_CDECL_PRNG_CALLER", "native-driver-entry/process_prng.c", obj, library,
             "/Fe:"+str(exe), "/Fo:"+str(out/"harness.obj"), "/link", *aliases])
    imports = command(["llvm-readobj", "--coff-imports", exe])
    assert any(re.search(r"Name: bcryptprimitives\.dll\b", block, re.I) and
               re.search(r"Symbol: ProcessPrng \(", block) for block in imports.split("Import {"))
    observed = json.loads(command([exe.resolve()]))
    assert observed["result_bits"] == 32 and observed["pointer_bits"] == (32 if arch == "x86" else 64)
    assert observed["calls"] == 5
    rows.append(dict(route=route, source_sha256=source_hash, observed=observed))
    print(arch, route, observed, flush=True)
system = Path(os.environ["SystemRoot"]) / ("SysWOW64" if arch=="x86" else "System32") / "bcryptprimitives.dll"
result = dict(target=arch, revision=manifest["revision"], core_sha256=manifest["core_sha256"],
              provider_sha256=hashlib.sha256(system.read_bytes()).hexdigest(), routes=rows)
(out/"report.json").write_text(json.dumps(result, indent=2)+"\n")
