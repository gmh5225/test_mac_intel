"""Check each documented named runtime export in the reviewed ARM64 system DLL."""
from pathlib import Path
from ctypes import WinDLL, byref, c_char_p, c_void_p, c_ushort
import hashlib
import json
import os
import sys

source, generated, validation, output = map(Path, sys.argv[1:])
profiles = json.loads((source / "scripts/MicrosoftNamedRuntimeSDKInputs.json").read_text(encoding="utf-8"))
cpdk = json.loads((source / "scripts/MicrosoftCPDKInputs.json").read_text(encoding="utf-8"))
profiles["providers"].update(cpdk["providers"])
manifest = json.loads((generated / "arm64/manifest.json").read_text(encoding="utf-8-sig"))
report = json.loads((validation / "report.json").read_text(encoding="utf-8-sig"))
checks = {case["provider"]: case for case in report["cases"]}
kernel = WinDLL("kernel32.dll", use_last_error=True)
kernel.GetProcAddress.argtypes = [c_void_p, c_char_p]
kernel.GetProcAddress.restype = c_void_p
machine, process = c_ushort(), c_ushort()
assert kernel.IsWow64Process2(c_void_p(-1), byref(process), byref(machine))
assert machine.value == 0xaa64 and process.value == 0
records = {}
for name, profile in profiles["providers"].items():
    target = profile["targets"]["arm64"]
    functions = sorted({**profile["exports"], **target["additional_exports"]})
    case = checks[name]
    assert case["passed"] and sorted(case["functions"]) == functions
    library = Path(os.environ["SystemRoot"]) / "System32" / profile["module"]
    digest = hashlib.sha256(library.read_bytes()).hexdigest()
    assert digest == target["image_sha256"], (library.name, digest)
    module = WinDLL(str(library), use_last_error=True)
    resolved = [symbol for symbol in functions if kernel.GetProcAddress(module._handle, symbol.encode("ascii"))]
    assert resolved == functions
    records[name] = {"module": library.name, "sha256": digest, "resolved": resolved}
result = {"machine": machine.value, "process_machine": process.value, "modules": records,
          "libraries": {lib["name"]: lib["prototypes"] for lib in manifest["libraries"]},
          "normalized_headers": {lib["name"]: hashlib.sha256((generated / "arm64" / (lib["name"] + ".h")).read_bytes().replace(b"\r\n", b"\n")).hexdigest() for lib in manifest["libraries"]}}
output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print({name: len(data["resolved"]) for name, data in records.items()})
