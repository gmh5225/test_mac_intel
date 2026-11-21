"""Compare SDK COM callbacks and both decompiled views as native ARM64 DLLs."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess

FUNCTIONS = ("DllRegisterServer", "DllUnregisterServer")
TARGET = "aarch64-pc-windows-msvc"


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_functions(ir, functions):
    for name in functions:
        if not re.search(r"(?m)^define\b[^\r\n]*?\bi32 @" + name + r"\(\)", ir):
            raise ValueError(f"{name} lost its signed SDK result width or empty parameter list")


def run(args):
    observations = []
    compiler = ["clang", "--target=" + TARGET, "-O1"]
    sdk_program = """#include <windows.h>
#include <olectl.h>
STDAPI DllRegisterServer(void) { return (HRESULT)REGISTER_RESULT; }
STDAPI DllUnregisterServer(void) { return (HRESULT)UNREGISTER_RESULT; }
"""
    for index, expected in enumerate(((-2147024891, 1), (0, -2147467259))):
        root = args.work / str(index)
        root.mkdir(parents=True)
        definitions = root / "exports.def"
        definitions.write_text("EXPORTS\n" + "\n".join(FUNCTIONS) + "\n")
        source = root / "original.c"
        source.write_text(sdk_program)
        original = root / "original.dll"
        flags = ["-DREGISTER_RESULT=" + str(expected[0]), "-DUNREGISTER_RESULT=" + str(expected[1])]
        ir = root / "original.ll"
        subprocess.run(compiler + flags + ["-S", "-emit-llvm", source, "-o", ir], check=True)
        validate_functions(ir.read_text(), FUNCTIONS)
        subprocess.run(compiler + flags + ["-c", source, "-o", root / "original.obj"], check=True)
        link = ["lld-link", "/dll", "/noentry", "/nodefaultlib", "/subsystem:windows",
                "/def:" + str(definitions)]
        subprocess.run(link + ["/out:" + str(original), root / "original.obj"], check=True)
        outputs = {"original": (original, {})}
        for route in ("high", "llvm"):
            objects = []
            hashes = {}
            for name in FUNCTIONS:
                recovered = root / (route + "-" + name + ".c")
                command = [str(args.neverd), "decompile", str(original),
                           "--func=" + name, "-o", str(recovered)]
                if route == "llvm":
                    command.append("--llvm")
                subprocess.run(command, check=True, timeout=90)
                ir = recovered.with_suffix(".ll")
                subprocess.run(compiler + ["-S", "-emit-llvm", recovered, "-o", ir], check=True)
                validate_functions(ir.read_text(), [name])
                obj = recovered.with_suffix(".obj")
                subprocess.run(compiler + ["-c", recovered, "-o", obj], check=True)
                objects.append(obj)
                hashes[name] = sha256(recovered)
            image = root / (route + ".dll")
            subprocess.run(link + ["/out:" + str(image)] + objects, check=True)
            outputs[route] = image, hashes
        for route, (image, hashes) in outputs.items():
            data = image.read_bytes()
            nt = struct.unpack_from("<I", data, 60)[0]
            machine = struct.unpack_from("<H", data, nt + 4)[0]
            if machine != 0xAA64:
                raise ValueError(f"{image} has machine {machine}")
            library = ctypes.WinDLL(str(image))
            for name, result in zip(FUNCTIONS, expected):
                callback = getattr(library, name)
                callback.argtypes = []
                callback.restype = ctypes.c_int32
                actual = callback()
                if actual != result:
                    raise ValueError(f"{route}/{name} returned {actual}, expected {result}")
                observations.append(dict(variant=index, route=route, function=name, status=actual,
                                         machine=machine, image_sha256=sha256(image),
                                         source_sha256=hashes.get(name, sha256(source))))
    args.report.write_text(json.dumps(dict(revision=os.environ["NEVERD_REV"],
                                           engine_sha256=sha256(args.neverd), rows=observations), indent=2))
    print(f"{len(observations)} native callback observations matched the SDK")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--neverd", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    run(parser.parse_args())
