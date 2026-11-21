"""Verify ARM64 compiler contracts and both source routes of the locally generated SDK profile."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys


def digest(file):
    with file.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser()
    for name in ("source", "types", "cache", "engine", "output", "report"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    target = args.types / "arm64"
    manifest_file = target / "manifest.json"
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    assert manifest["architecture"] == "arm64"
    shutil.copyfile(manifest_file, args.types / "manifest.json")
    for lib in manifest["libraries"]:
        name = lib["name"] + ".h"
        assert digest(target / name) == lib["sha256"]
        shutil.copyfile(target / name, args.types / name)

    args.output.mkdir()
    abi_dir = args.output / "abis"
    api_dir = args.output / "calls"
    shared = ["--architecture", "arm64", "--generated", args.types, "--neverd", args.engine]
    invoke = lambda name, options: subprocess.run(
        [sys.executable, args.source / "scripts" / name, *shared, *options], check=True)
    invoke("check_microsoft_provider_abis.py",
           ["--provider", "ProcessStatus", "--provider", "ProcessSnapshots", "--output", abi_dir])
    invoke("check_windows_provider_calls.py",
           ["--sdk-imports", "--linker", "lld-link", "--cache", args.cache, "--output", api_dir])
    abis = json.loads((abi_dir / "report.json").read_text(encoding="utf-8"))
    calls = json.loads((api_dir / "report.json").read_text(encoding="utf-8"))
    counts = {row["provider"]: len(row["functions"]) for row in abis["cases"]}
    assert abis["passed"] and counts == {"ProcessStatus": 27, "ProcessSnapshots": 10}
    rows = calls["cases"]
    assert calls["passed"] and len(rows) == 20
    assert all(r["architecture"] == "arm64" and r["passed"] and r["retains_call"] for r in rows)
    required = {(api, route) for api in ("EnumProcessModulesEx", "PssFreeSnapshot")
                for route in ("highc", "llvmc")}
    assert required <= {(r["api"], r["route"]) for r in rows}
    data = args.engine.read_bytes()
    nt, = struct.unpack_from("<I", data, 60)
    machine, = struct.unpack_from("<H", data, nt + 4)
    assert machine == 0xaa64
    report = dict(revision=os.environ["NEVERD_REV"], machine=machine,
                  engine_sha256=digest(args.engine), provider_abis=counts,
                  catalog={lib["name"]: lib["sha256"] for lib in manifest["libraries"]},
                  linked_caller_views=[{key: r[key] for key in ("architecture", "api", "route", "passed", "input_sha256")}
                                       for r in rows])
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Native engine compiled both source routes of ten linked SDK callers")


if __name__ == "__main__":
    main()
