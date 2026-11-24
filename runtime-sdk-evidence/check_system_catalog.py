"""Match native ARM64 SDK declarations to the installed Microsoft system images."""
from ctypes import WinDLL, byref, c_char_p, c_void_p, c_ushort
from pathlib import Path
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

source, generated, reader, output = map(Path, sys.argv[1:])
def read(file):
    return json.loads(file.read_text(encoding="utf-8-sig"))

witness = source / "scripts/MicrosoftSystemRuntimeSDKInputs.json"
profiles = read(witness)["providers"]
manifest = read(generated / "arm64/manifest.json")
assert manifest["profiles"]["system_runtime"] == hashlib.sha256(witness.read_bytes()).hexdigest()
providers = {p["name"]: p for library in manifest["libraries"] for p in library["providers"]}
expected_names = {name for name, p in profiles.items() if "arm64" in p["targets"]}
assert providers.keys() & profiles.keys() == expected_names
kernel = WinDLL("kernel32.dll", use_last_error=True)
kernel.GetProcAddress.argtypes = [c_void_p, c_char_p]
kernel.GetProcAddress.restype = c_void_p
machine, process = c_ushort(), c_ushort()
assert kernel.IsWow64Process2(c_void_p(-1), byref(process), byref(machine))
assert machine.value == 0xaa64 and process.value == 0
samples = {"D3d9Runtime": "D3DPERF_GetStatus", "Cfgmgr32Runtime": "SwDeviceClose",
           "MswsockRuntime": "EnumProtocolsW"}
rows = {}
for name in sorted(expected_names):
    profile = profiles[name]
    target = profile["targets"]["arm64"]
    counts = profile["exports"] | target["additional_exports"]
    bridge = providers[name]["metadata"]["sdk_runtime_bridge"]
    assert bridge["runtime_exports"]["parameter_counts"] == counts
    assert set(bridge["verified_functions"]) == set(bridge["published_abi"]["verified_functions"]) == counts.keys()
    path = Path(os.environ["SystemRoot"]) / "System32" / profile["module"]
    image = path.read_bytes()
    pe = struct.unpack_from("<I", image, 0x3c)[0]
    assert image[pe:pe+4] == b"PE\0\0" and struct.unpack_from("<H",image,pe+4)[0] == machine.value
    digest = hashlib.sha256(image).hexdigest()
    assert digest == target["image_sha256"], (path, digest, target)
    symbols = subprocess.run(["llvm-readobj", "--coff-exports", path], text=True,
                             capture_output=True, check=True).stdout
    exported = set(re.findall(r"^  Name: (\S+)\s*$", symbols, re.M))
    assert counts.keys() <= exported, (name, counts.keys() - exported)
    rows[name] = {"module": path.name, "image_sha256": digest, "names": sorted(counts)}
    if name in samples:
        api = samples[name]
        dll = WinDLL(str(path), use_last_error=True)
        assert api in counts and kernel.GetProcAddress(dll._handle, api.encode("ascii"))
        rows[name]["resolved_by_loader"] = api
assert samples.keys() <= rows.keys()
result = {"architecture": "arm64", "process_machine": process.value, "machine": machine.value,
          "providers": rows, "counts": sum(len(r["names"]) for r in rows.values()),
          "headers": {lib["name"]: hashlib.sha256((generated/"arm64"/(lib["name"]+".h")).read_bytes().replace(b"\r\n",b"\n")).hexdigest() for lib in manifest["libraries"]}}
sys.path.insert(0, str(source.resolve() / "scripts"))
from check_microsoft_provider_abis import generated_compiler

provider = providers["NtdllRuntime"]
proof = provider["metadata"]["sdk_runtime_bridge"]
published_args = generated_compiler(provider["commands"][0][:-2])
address_check = "_Static_assert(sizeof(DL_EUI48) == 6 && sizeof(((DL_EUI48 *)0)->Byte) == 6, \"Ethernet address layout\");"
frame_check = "_Static_assert(sizeof(ETHERNET_HEADER) == 14, \"Ethernet frame layout\");"
with tempfile.TemporaryDirectory() as directory:
    unit = Path(directory) / "address.c"
    for domain, cc, header, checks in (
        ("reference", proof["arguments"], Path(proof["source"]), [address_check, frame_check]),
        ("user", published_args, generated / "arm64/WindowsUserARM64.h", [address_check]),
        ("kernel", published_args, generated / "arm64/WindowsKernelARM64.h", [address_check, frame_check]),
    ):
        if domain != "reference":
            selected = Path(directory) / (domain + ".h")
            names = ["DL_EUI48"] if domain == "user" else ["DL_EUI48", "ETHERNET_HEADER"]
            subprocess.run([str(reader), "types", "--data-model", "LLP64", "--record-abi",
                            "microsoft", "--declare", str(header), "--spelling", "windows",
                            "--asserts", *[v for name in names for v in ("--type", name)],
                            "-o", str(selected)], check=True)
            header = selected
        unit.write_text('#include "' + header.resolve().as_posix() + '"\n' +
                        "\n".join(checks) + "\n", encoding="utf-8")
        subprocess.run([*cc, "-fsyntax-only", str(unit)], check=True)
result["ethernet_layout"] = {"reference": "netiodef.h", "address_bytes": 6,
                            "frame_bytes": 14, "user_and_kernel_compiled": True}
output.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
print(len(rows), "native providers verified,", result["counts"], "named exports")
