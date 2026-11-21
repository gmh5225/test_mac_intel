"""Compile both source views of Microsoft export-driver callbacks on Windows ARM64."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import urllib.request

def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def check_object(image, expected):
    raw = image.read_bytes()
    offset = struct.unpack_from("<I", raw, 60)[0]
    assert raw[offset:offset+4] == b"PE\0\0"
    assert struct.unpack_from("<H", raw, offset+4)[0] == 0xAA64
    assert sha256(image) == expected["sha256"]

def run(args):
    fixtures = json.loads(Path(__file__).with_name("export-entry-inputs.json").read_text())
    args.work.mkdir(parents=True, exist_ok=True)
    observations = []
    for record in fixtures:
        image = args.work / record["name"]
        shutil.copyfile(Path(os.environ["SystemRoot"]) / "System32/drivers" / image.name, image)
        check_object(image, record)
        signature = subprocess.check_output(
            ["pwsh", "-NoProfile", "-Command",
             "(Get-AuthenticodeSignature -LiteralPath $env:DRIVER_TO_CHECK).Status.ToString()"],
            text=True, env={**os.environ, "DRIVER_TO_CHECK": str(image)}).strip()
        if signature != "Valid":
            raise ValueError(f"{image.name} has signature status {signature}")
        pdb = args.work / record["pdb_url"].split("/")[-1]
        with urllib.request.urlopen(record["pdb_url"], timeout=90) as response, pdb.open("wb") as out:
            shutil.copyfileobj(response, out)
        if sha256(pdb) != record["pdb_sha256"]:
            raise ValueError(f"{image.name} has a different symbol file")
        for function in ("DllInitialize", "DllUnload"):
            parameters = r"ptr\b(?:[^,()\r\n]|\([^()\r\n]*\))*" if function == "DllInitialize" else ""
            definition = re.compile(r"(?m)^define\b[^\r\n]*?\bi32 @" + function + r"\(" + parameters + r"\)")
            for route in ("high", "llvm"):
                source = args.work / f"{image.stem}-{function}-{route}.c"
                ir = source.with_suffix(".ll")
                target = record["entries"][function]
                observation = dict(driver=image.name, image_sha256=record["sha256"], pdb_sha256=record["pdb_sha256"],
                                   signature=signature, function=function, route=route, address=target)
                command = [str(args.neverd), "decompile", str(image), "--func=" + target, "-o", str(source)]
                if route == "llvm":
                    command.append("--llvm")
                decompile = subprocess.run(command, capture_output=True, text=True, timeout=180)
                observation["decompile_exit"] = decompile.returncode
                observation["wdk_signature"] = False
                if decompile.returncode == 0 and source.exists():
                    observation["source_sha256"] = sha256(source)
                    compile_source = subprocess.run(
                        ["clang", "--target=aarch64-pc-windows-msvc", "-Werror=incompatible-pointer-types",
                         "-S", "-emit-llvm", "-O1", str(source), "-o", str(ir)],
                        capture_output=True, text=True, timeout=90)
                    observation["compile_exit"] = compile_source.returncode
                    if compile_source.returncode == 0:
                        observation["wdk_signature"] = bool(definition.search(ir.read_text()))
                    else:
                        observation["diagnostic"] = next((line.split("error: ", 1)[-1]
                                                          for line in compile_source.stderr.splitlines()
                                                          if "error: " in line), "compiler failed")
                observations.append(observation)
                args.report.write_text(json.dumps(dict(revision=os.environ["NEVERD_REV"], rows=observations), indent=2))
    required = [r for r in observations if (r["driver"], r["function"]) != ("wpprecorder.sys", "DllInitialize")]
    if len(observations) != 12 or len(required) != 10 or any(not r["wdk_signature"] for r in required):
        raise RuntimeError("A qualified loader callback lost its original target compiler contract")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--neverd", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    run(parser.parse_args())
