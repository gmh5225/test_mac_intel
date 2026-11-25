"""Compile all three callers and exercise the same signed Windows ARM64 export."""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import sys


engine, product, out = (Path(v).resolve() for v in sys.argv[1:])
sys.path.insert(0, str(product / "scripts"))
from check_microsoft_provider_abis import compiler_contracts

out.mkdir(parents=True, exist_ok=True)
harness = Path(__file__).resolve().with_name("process_prng.c")
cc = ["clang", "--target=aarch64-pc-windows-msvc", "-fms-extensions", "-std=c17"]
api = "ProcessPrng"
function = "InspectProcessPrng"
library = out / "bcryptprimitives.lib"
definition = out / "provider.def"
definition.write_text("LIBRARY bcryptprimitives.dll\nEXPORTS\nProcessPrng\n")
original = out / "original.c"
original.write_text('''#include <windows.h>
__declspec(dllimport) BOOL WINAPI ProcessPrng(PBYTE buffer, SIZE_T length);
__declspec(dllexport) BOOL WINAPI InspectProcessPrng(PBYTE buffer, SIZE_T length) {
  return ProcessPrng(buffer, length);
}
''')


def run(args):
    command = subprocess.run(args, text=True, capture_output=True, timeout=100)
    if command.returncode:
        raise RuntimeError(f"{args[0]} exited {command.returncode}\n{command.stderr}\n{command.stdout}")
    return command.stdout


def contracts(source):
    probe = source.with_name(source.stem + "-type.c")
    probe.write_text(source.read_text() + "\n__typeof__(&ProcessPrng) neverd_ucrt_abi_0 = &ProcessPrng;\n")
    return compiler_contracts(run([*cc, "-S", "-emit-llvm", "-O0", probe, "-o", "-"]), (api,))


def object_file(source):
    obj = source.with_suffix(".obj")
    run([*cc, "-O1", "-fno-stack-protector", "-fno-optimize-sibling-calls", "-c", source, "-o", obj])
    return obj


run(["lld-link", "/lib", "/machine:arm64", "/def:" + str(definition), "/out:" + str(library)])
ref = contracts(original)
obj = object_file(original)
image = out / "fixture.dll"
run(["lld-link", "/dll", "/noentry", "/nodefaultlib", "/machine:arm64", "/out:" + str(image), obj, library])
rows = []
for route in ("original", "highc", "llvmc"):
    source = original
    if route != "original":
        source = out / (route + ".c")
        run([engine, "decompile", image, "--func", function, *(["--llvm"] if route == "llvmc" else []), "-o", source])
    actual = contracts(source)
    assert actual == ref, (route, actual, ref)
    exe = out / (route + ".exe")
    guard = out / "guard.obj"
    run(["clang-cl", "/nologo", "/std:c17", "/O2", "/c", "/DTEST_RECOVERED_PRNG_CALLER",
         harness, "/Fo" + str(guard)])
    run(["clang-cl", "/nologo", guard, object_file(source), library, "/Fe" + str(exe)])
    pe = run(["llvm-readobj", "--coff-imports", exe])
    assert any(re.search(r"Name: bcryptprimitives\.dll\b", block, re.I) and
               re.search(r"Symbol: ProcessPrng \(", block) for block in pe.split("Import {"))
    observed = json.loads(run([exe]))
    assert observed["calls"] == 5 and observed["result_bits"] == 32 and observed["pointer_bits"] == 64
    rows.append(dict(route=route, machine="arm64", declaration=actual[api], observed=observed,
                     source_sha256=hashlib.sha256(source.read_bytes()).hexdigest()))
    print(route, observed, flush=True)
system = Path(os.environ["SystemRoot"]) / "System32/bcryptprimitives.dll"
(out / "native-prng-callers.json").write_text(json.dumps(dict(observations=rows,
    revision=os.environ["NEVERD_REV"],system_dll_sha256=hashlib.sha256(system.read_bytes()).hexdigest()),indent=2) + "\n")
