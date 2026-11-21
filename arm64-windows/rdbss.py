#!/usr/bin/env python3
# NeverD Decompiler. SPDX-License-Identifier: AGPL-3.0-only
"""Compare original WDK RDBSS callers with recovered C on native Windows."""

from __future__ import annotations
import argparse
import ctypes as C
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

from native import ROOT, build, digest, materialize_image

FUNCTIONS = [
    "UseRdbssRegister",
    "UseRdbssStart",
    "UseRdbssUnregister",
    "UseRdbssCreateContext",
    "UseRdbssInitializeDispatcher",
    "UseRdbssInitializeTimer",
    "UseRdbssTearDownDispatcher",
]
VARIANTS = ["highc-O0", "highc-O2", "llvmc-O0", "llvmc-O2"]


def execute(out, variant, arch):
    os.add_dll_directory(str(out))
    provider = C.WinDLL(str(out / "provider.dll"))
    provider.ModelReset.argtypes = [C.c_uint32]
    provider.ModelReset.restype = None
    provider.ModelSnapshot.argtypes = [C.c_void_p]
    provider.ModelSnapshot.restype = None
    original = C.WinDLL(str(out / "original-rdbss.dll"))
    recovered = C.WinDLL(str(out / (variant + "-rdbss.dll")))
    materialize_image(
        recovered, ROOT / "rdbss-payload" / arch / "original-rdbss.sys", provider
    )
    ptr, u32, i32 = C.c_void_p, C.c_uint32, C.c_int32
    signatures = [
        ([ptr, ptr, ptr, u32, ptr, u32, u32, u32], i32),
        ([ptr, ptr], i32),
        ([ptr], None),
        ([ptr, ptr, u32], ptr),
        ([], i32),
        ([], i32),
        ([], i32),
    ]
    for dll in (original, recovered):
        for name, (arguments, result) in zip(FUNCTIONS, signatures):
            routine = getattr(dll, name)
            routine.argtypes, routine.restype = arguments, result

    def snapshot():
        values = (C.c_uint64 * 64)()
        provider.ModelSnapshot(values)
        assert values[0] < len(values)
        return list(values)[1 : values[0] + 1]

    rows = []
    for seed in (0, 7, 31):
        driver, dispatch, name = (
            0x123400001 + seed,
            0x234500002 + seed,
            0x345600003 + seed,
        )
        controls, extension, kind, attributes = (
            0x80000000 | seed,
            0x12340000 | seed,
            0x87650000 | seed,
            0xFEDC0000 | seed,
        )
        slot = (C.c_uint64 * 3)(0x1122334455667788, 0, 0x8877665544332211)
        slot_address = C.addressof(slot) + 8
        calls = []
        for dll in (original, recovered):
            slot[1] = 0xFFFFFFFFFFFFFFFF
            provider.ModelReset(seed)
            result = dll.UseRdbssRegister(
                slot_address,
                driver,
                dispatch,
                controls,
                name,
                extension,
                kind,
                attributes,
            )
            actual = {"status": result, "trace": snapshot(), "output": list(slot)}
            expected = {
                "status": i32(0xC0001200 | seed).value,
                "trace": [
                    41,
                    slot_address,
                    driver,
                    dispatch,
                    controls,
                    name,
                    extension,
                    kind,
                    attributes,
                ],
                "output": [
                    0x1122334455667788,
                    driver ^ 0x5678000 ^ controls,
                    0x8877665544332211,
                ],
            }
            assert actual == expected, ("register", dll._name, actual, expected)
            calls.append(actual)
        rows.append(
            {
                "case": "register-eight-arguments-output-canaries",
                "seed": seed,
                "equal": calls[0] == calls[1],
                "original": calls[0],
                "recovered": calls[1],
            }
        )

        post = (C.c_uint8 * 3)(0x6A, 0, 0x7B)
        post_address = C.addressof(post) + 1
        calls = []
        for dll in (original, recovered):
            post[1] = 0
            provider.ModelReset(seed)
            result = dll.UseRdbssStart(driver, post_address)
            actual = {"status": result, "trace": snapshot(), "output": list(post)}
            expected = {
                "status": i32(0x80000300 | seed).value,
                "trace": [42, driver, post_address],
                "output": [0x6A, seed ^ 0xA5, 0x7B],
            }
            assert actual == expected, ("start", dll._name, actual, expected)
            calls.append(actual)
        rows.append(
            {
                "case": "start-byte-output-canaries",
                "seed": seed,
                "equal": calls[0] == calls[1],
                "original": calls[0],
                "recovered": calls[1],
            }
        )

        for function, arguments, expected_result, expected_trace in (
            ("UseRdbssUnregister", [driver], None, [43, driver]),
            (
                "UseRdbssCreateContext",
                [driver, dispatch, attributes],
                0x100000000 | (attributes ^ 0x11223344),
                [44, driver, dispatch, attributes],
            ),
            ("UseRdbssInitializeDispatcher", [], i32(0xC0004500 | seed).value, [45]),
            ("UseRdbssInitializeTimer", [], i32(0xC0004600 | seed).value, [46]),
            ("UseRdbssTearDownDispatcher", [], i32(0xC0004700 | seed).value, [47]),
        ):
            calls = []
            for dll in (original, recovered):
                provider.ModelReset(seed)
                result = getattr(dll, function)(*arguments)
                actual = {"result": result, "trace": snapshot()}
                expected = {"result": expected_result, "trace": expected_trace}
                assert actual == expected, (function, dll._name, actual, expected)
                calls.append(actual)
            rows.append(
                {
                    "case": function,
                    "seed": seed,
                    "equal": calls[0] == calls[1],
                    "original": calls[0],
                    "recovered": calls[1],
                }
            )
    assert len(rows) == 21 and all(row["equal"] for row in rows)
    return {"variant": variant, "cases": rows}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=("arm64", "x64"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", choices=VARIANTS)
    args = parser.parse_args()
    assert platform.system() == "Windows" and platform.machine().lower() in (
        ("arm64", "aarch64") if args.arch == "arm64" else ("amd64", "x86_64")
    )
    out = args.output.resolve()
    if args.execute:
        print(json.dumps(execute(out, args.execute, args.arch)))
        return
    out.mkdir(parents=True, exist_ok=False)
    payload = ROOT / "rdbss-payload" / args.arch
    manifest = json.loads((payload / "manifest.json").read_text())
    assert not manifest["source_dirty"]
    for name, expected in manifest["files"].items():
        assert digest(payload / name) == expected, name
    build(payload, out, args.arch, {"rdbss": FUNCTIONS}, ROOT / "provider.c", VARIANTS)
    rows = []
    for variant in VARIANTS:
        result = subprocess.run(
            [
                sys.executable,
                __file__,
                "--arch",
                args.arch,
                "--output",
                str(out),
                "--execute",
                variant,
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )
        (out / (variant + ".stdout")).write_text(result.stdout)
        (out / (variant + ".stderr")).write_text(result.stderr)
        assert result.returncode == 0, (variant, result.returncode, result.stderr)
        rows.append(json.loads(result.stdout))
    report = {
        "passed": True,
        "machine": platform.machine(),
        "system": platform.platform(),
        "architecture": args.arch,
        "source": manifest["source"],
        "harness": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip(),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "rows": rows,
        "scope": "Original WDK-compiled callers versus both C routes. RDBSS uses observable ABI models; no kernel driver is loaded.",
    }
    (out / "native-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
