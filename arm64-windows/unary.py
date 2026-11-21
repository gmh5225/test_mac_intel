#!/usr/bin/env python3
# NeverD Decompiler. SPDX-License-Identifier: AGPL-3.0-only
"""Compare captured unary source with original Windows machine instructions."""

from __future__ import annotations

import argparse
import ctypes as C
import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path

from native import ROOT, digest, machine, run, tool

VARIANTS = ("highc-O0", "highc-O2", "llvmc-O0", "llvmc-O2")
MASK = (1 << 64) - 1


def expected(case, value):
    flags = 0
    for index, operation in enumerate(case["operations"]):
        before = value
        if operation == "neg":
            value = (-value) & MASK
        elif operation == "not":
            value = (~value) & MASK
        else:
            raise ValueError(operation)
        flags = int(before != 0) | (int(before == (1 << 63)) << 11)
        if case["narrow"] and index == 0:
            value &= (1 << 32) - 1
    return value ^ (flags if case["flags"] else 0)


def inputs():
    values = [0, 1, 0xFFFFFFFF, 1 << 63, 0x123456789ABCDEF0, MASK]
    state = 0xA0761D6478BD642F
    for _ in range(256):
        state ^= (state << 13) & MASK
        state ^= state >> 7
        state ^= (state << 17) & MASK
        values.append(state)
    return values


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=("x64", "arm64"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert platform.system() == "Windows"
    assert platform.machine().lower() in (
        ("arm64", "aarch64") if args.arch == "arm64" else ("amd64", "x86_64")
    )
    payload = ROOT / "unary-payload" / args.arch
    manifest = json.loads((payload / "manifest.json").read_text())
    assert not manifest["source_dirty"]
    for name, wanted in manifest["files"].items():
        assert digest(payload / name) == wanted, name
    cases = json.loads((payload / "cases.json").read_text())
    assert len(cases) == (20 if args.arch == "x64" else 14)
    expected_machine = 0xAA64 if args.arch == "arm64" else 0x8664
    assert machine(payload / "unary.dll") == expected_machine
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    clang, link = tool("clang"), tool("lld-link")
    commands = []

    def invoke(command, name):
        commands.append(list(map(str, command)))
        run(command, out, name)
        (out / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")

    invoke([clang, "--version"], "compiler-version")
    os.add_dll_directory(str(payload))
    original = C.WinDLL(str(payload / "unary.dll"))
    values = inputs()
    reference = {}
    for case in cases:
        routine = getattr(original, case["name"])
        routine.argtypes, routine.restype = [C.c_uint64], C.c_uint64
        reference[case["name"]] = [routine(value) for value in values]
        assert reference[case["name"]] == [expected(case, value) for value in values], case
    rows = []
    for variant in VARIANTS:
        route, optimization = variant.split("-")
        objects = []
        for case in cases:
            obj = out / (variant + "-" + case["name"] + ".obj")
            invoke([
                clang,
                "--target=" + ("aarch64" if args.arch == "arm64" else "x86_64") + "-pc-windows-msvc",
                "-std=gnu11", "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
                "-fno-strict-aliasing", "-" + optimization, "-c",
                payload / route / (case["name"] + ".c"), "-o", obj,
            ], variant + "-" + case["name"])
            objects.append(obj)
        library = out / (variant + ".dll")
        invoke([link, "/dll", "/noentry", "/nodefaultlib", "/timestamp:0",
                "/out:" + str(library), *objects,
                *["/export:" + case["name"] for case in cases]], variant + "-link")
        assert machine(library) == expected_machine
        recovered = C.WinDLL(str(library))
        for case in cases:
            routine = getattr(recovered, case["name"])
            routine.argtypes, routine.restype = [C.c_uint64], C.c_uint64
            actual = [routine(value) for value in values]
            assert actual == reference[case["name"]], (variant, case["name"], actual)
            rows.append({"variant": variant, "function": case["name"], "inputs": len(values),
                         "equal": True, "observations_sha256": hashlib.sha256(
                             b"".join(value.to_bytes(8, "little") for value in actual)).hexdigest()})
    report = {"passed": True, "architecture": args.arch, "machine": platform.machine(),
              "system": platform.platform(), "source": manifest["source"],
              "manifest_sha256": digest(payload / "manifest.json"),
              "harness": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
              "run_id": os.environ.get("GITHUB_RUN_ID"), "rows": rows,
              "original_oracle_comparisons": len(cases) * len(values),
              "recovered_comparisons": sum(row["inputs"] for row in rows),
              "scope": "Original Windows machine instructions, independent unsigned Python oracle, and both captured C routes at O0/O2. No kernel driver or Windows service is executed."}
    (out / "native-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
