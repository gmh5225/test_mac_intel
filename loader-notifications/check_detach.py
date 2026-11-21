"""Observe the final Windows loader callback after FreeLibrary and normal process exit."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def machine(path):
    data = path.read_bytes()
    nt, = struct.unpack_from("<I", data, 60)
    if data[nt:nt + 4] != b"PE\0\0":
        raise ValueError("Missing PE signature")
    return struct.unpack_from("<H", data, nt + 4)[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("architecture", choices=["arm64", "x64"])
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    receipt = json.loads((root / "qualified.json").read_text(encoding="utf-8"))
    images = receipt["images"][args.architecture]
    expected_machine = {"arm64": 0xaa64, "x64": 0x8664}[args.architecture]
    triple = {"arm64": "aarch64-pc-windows-msvc", "x64": "x86_64-pc-windows-msvc"}[args.architecture]
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        for route, record in images.items():
            name = "entry.c" if route == "original" else f"{args.architecture}-{route}.c"
            if sha(root / name) != record["source_sha256"]:
                raise ValueError(f"Unmatched source for {route}")
            directory = Path(tmp) / route
            directory.mkdir()
            dll = directory / "subject.dll"
            dll.write_bytes(base64.b64decode(record["dll"], validate=True))
            if sha(dll) != record["pe_sha256"] or machine(dll) != expected_machine:
                raise ValueError(f"Unmatched DLL for {route}")
            definitions = directory / "subject.def"
            definitions.write_text("LIBRARY subject.dll\nEXPORTS\nDllMain\nDetachSink DATA\n", encoding="ascii")
            implib = directory / "subject.lib"
            subprocess.run(["lib", "/nologo", "/machine:" + args.architecture,
                            "/def:" + str(definitions), "/out:" + str(implib)], cwd=directory, check=True)
            for mode in ("process-start", "dynamic"):
                program = directory / (mode + ".exe")
                options = ["/DLINK_AT_STARTUP", str(implib)] if mode == "process-start" else []
                subprocess.run(["clang-cl", "--target=" + triple, "/nologo", "/O1", "/MD",
                                "/D_WIN32_WINNT=0x0A00", str(root / "host.c"), *options,
                                "/Fe:" + str(program)], cwd=directory, check=True)
                if machine(program) != expected_machine:
                    raise ValueError("Wrong host executable architecture")
                imports = subprocess.check_output(["dumpbin", "/imports", program], text=True).lower()
                if ("subject.dll" in imports and "detachsink" in imports) != (mode == "process-start"):
                    raise ValueError("Loader dependency differs from the selected mode")
                mapping = directory / (mode + ".bin")
                mapping.write_bytes(bytes(40))
                subprocess.run([program, mapping], cwd=directory, timeout=40, check=True)
                actual, observed, reason, reserved, writes = struct.unpack("<5Q", mapping.read_bytes())
                if (not actual or observed != actual or reason != 0 or writes != 1 or
                        bool(reserved) != (mode == "process-start")):
                    raise ValueError(f"Incorrect process-detach evidence for {route}/{mode}")
                results.append(dict(route=route, mode=mode, module_handle_matched=True,
                                    reason=reason, reserved_nonnull=bool(reserved),
                                    observed_detach=True, dll_sha256=record["pe_sha256"]))
    if len(results) != 6:
        raise ValueError("Incomplete native process-detach checks")
    args.report.write_text(json.dumps(dict(revision=receipt["source_revision"],
                           core_sha256=receipt["core_sha256"], architecture=args.architecture,
                           machine=expected_machine, observations=results), indent=2) + "\n", encoding="utf-8")
    print(f"Verified six Windows {args.architecture} process-detach callbacks")


if __name__ == "__main__":
    main()
