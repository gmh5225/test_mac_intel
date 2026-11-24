"""Link SDK and lifted public callers, then exercise their real operating-system imports."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import tempfile
import wave

ROOT = Path(__file__).resolve().parent
APIS = {
    "McastApiStartup": ("dhcpcsvc", "DWORD __cdecl InspectMcastApiStartup(PDWORD version) { return McastApiStartup(version); }"),
    "McastApiCleanup": ("dhcpcsvc", "void __cdecl InspectMcastApiCleanup(void) { McastApiCleanup(); }"),
    "MFCreateSourceReaderFromURL": ("mfreadwrite", "HRESULT __cdecl InspectMFCreateSourceReaderFromURL(LPCWSTR url, IMFAttributes *attrs, IMFSourceReader **reader) { return MFCreateSourceReaderFromURL(url, attrs, reader); }"),
}
TARGETS = {
    "arm64": ("aarch64", 0xaa64, 0),
    "x64": ("x86_64", 0x8664, 0),
    "x86": ("i686", 0x8664, 0x014c),
}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def command(*args, output=False):
    result = subprocess.run([str(arg) for arg in args], capture_output=output, text=True, check=True)
    return result.stdout

def qualify(arch, report):
    fixture = json.loads((ROOT / "public-callers.json").read_text())
    triple, native, process = TARGETS[arch]
    result = {"revision": fixture["revision"], "arch": arch, "routes": {}}
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        executable = work / "observe.exe"
        command("cl", "/nologo", "/W3", "/O2", "/Fe" + str(executable), "/Fo" + str(work / "observe.obj"),
                ROOT / "observe.c", "mfplat.lib", "mfuuid.lib", "ole32.lib")
        sound = work / "source.wav"
        with wave.open(str(sound), "wb") as pcm:
            pcm.setparams((1, 2, 8000, 0, "NONE", "not compressed"))
            pcm.writeframes(bytes(1600))
        for route in ("original", "highc", "llvmc"):
            dlls = []
            inputs = {}
            for api, (module, wrapper) in APIS.items():
                ident = "Inspect" + api
                base = work / (route + "-" + api)
                source, obj, dll = (base.with_suffix(ext) for ext in (".c", ".obj", ".dll"))
                if route == "original":
                    headers = ["winsock2", "windows", "winternl", "madcapcl"] if module == "dhcpcsvc" else ["windows", "mfidl", "mfreadwrite"]
                    data = ("".join("#include <" + name + ".h>\n" for name in headers) + wrapper + "\n").encode()
                else:
                    digest = fixture["cases"][arch][api][route]
                    data = fixture["sources"][digest].encode()
                    assert sha(data) == digest
                source.write_bytes(data)
                inputs[api] = sha(data)
                command("clang", "--target=" + triple + "-pc-windows-msvc", "-std=c17", "-O2",
                        "-fno-stack-protector", "-fno-strict-aliasing", "-c", source, "-o", obj)
                command("lld-link", "/dll", "/noentry", "/nodefaultlib", "/export:" + ident,
                        "/out:" + str(dll), obj, module + ".lib")
                dlls.append(dll)
            observed = json.loads(command(executable, *dlls, sound, output=True))
            assert (observed["native_machine"], observed["process_machine"]) == (native, process), observed
            if route != "original":
                assert observed == result["routes"]["original"]["observed"], observed
            result["routes"][route] = {"sources": inputs, "observed": observed}
            report.write_text(json.dumps(result, indent=2) + "\n")
    observations = result["routes"]["original"]["observed"]
    assert observations["reader"] == {"status": 0, "media_status": 0, "rate_hz": 8000}, observations
    for row in observations["versions"][:2]:
        assert row["status"] == 0 and row["returned"] >= 1 and row["cleanup"], observations
    print(json.dumps(observations))

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("arch", choices=TARGETS)
    ap.add_argument("report", type=Path)
    args = ap.parse_args()
    qualify(args.arch, args.report)
