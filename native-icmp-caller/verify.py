import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

fixture = Path(sys.argv[1]).resolve()
root = Path(__file__).resolve().parent
inputs = json.loads((root / "inputs.json").read_text())
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
repo = Path(subprocess.check_output(["git", "-C", fixture.parent, "rev-parse", "--show-toplevel"],
                                   text=True).strip())
tracked = fixture.relative_to(repo).as_posix()
blob = subprocess.check_output(["git", "-C", repo, "show", "HEAD:" + tracked])
assert hashlib.sha256(blob).hexdigest() == inputs["fixture_source_sha256"]
function = re.findall(r"^__declspec\(dllexport\) BOOL UseIcmpHandle\([^)]*\) \{.*?^\}",
                      blob.decode(), flags=re.M | re.S)
assert len(function) == 1
original = root / "original.c"
original.write_text("#include <winsock2.h>\n#include <windows.h>\n"
                    "#include <iphlpapi.h>\n#include <icmpapi.h>\n" + function[0] + "\n")
compiler = ["clang-cl", "--target=aarch64-pc-windows-msvc", "/nologo", "/O2",
            "/D_WIN32_WINNT=0x0A00"]
objects = []
for route in ("original", "highc", "llvmc"):
    source = root / (route + ".c")
    flags = []
    if route != "original":
        assert digest(source) == inputs["emitted_sources"][route]
        flags = [f"/DUseIcmpHandle={route}_UseIcmpHandle",
                 f"/Dneverd_ucrt_abi_0={route}_declaration"]
    obj = root / (route + ".obj")
    subprocess.run([*compiler, *flags, "/c", source, "/Fo" + str(obj)], check=True)
    objects.append(obj)
exe = root / "icmp.exe"
subprocess.run([*compiler, root / "run.c", *objects, "Iphlpapi.lib", "/Fe" + str(exe)], check=True)
result = json.loads(subprocess.check_output([exe], text=True, timeout=30))
assert result["native_machine"] == 0xaa64 and result["process_machine"] == 0
assert result["original"] == result["highc"] == result["llvmc"] != 0
evidence = dict(inputs=inputs, executable_sha256=digest(exe), observed=result)
(root / "result.json").write_text(json.dumps(evidence, indent=2) + "\n")
print(result)
