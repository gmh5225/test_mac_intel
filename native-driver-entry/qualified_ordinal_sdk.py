"""Check recovered ARM64 ordinal callers against the installed Windows system and SDK."""
import json
import os
from pathlib import Path
import re
import subprocess


def system_exports(image):
    output = subprocess.check_output(["llvm-readobj", "--coff-exports", str(image)], text=True)
    exports = {}
    for block in re.findall(r"(?ms)^Export \{\n(.*?)^\}", output):
        symbol = re.search(r"(?m)^  Name: (\S+)$", block)
        ordinal = re.search(r"(?m)^  Ordinal: (\d+)$", block)
        if symbol and ordinal:
            exports[symbol[1]] = int(ordinal[1])
    return exports


def verify(source, output, cache, invoke, digest):
    inputs = json.loads((source / "scripts/MicrosoftOrdinalSDKInputs.json").read_text(encoding="utf-8"))
    profiles = inputs["providers"]
    selected = {}
    installed = {}
    exports = {}
    for name, profile in profiles.items():
        target = profile["targets"].get("arm64")
        if not target:
            continue
        expected = {**profile["exports"], **target["additional_exports"]}
        selected[name] = set(expected)
        module = profile["module"]
        if module not in installed:
            image = Path(os.environ["SystemRoot"]) / "System32" / module
            exports[module] = system_exports(image)
            installed[module] = {"image_sha256": digest(image), "witnessed": {}}
        for api, ordinal in expected.items():
            actual = exports[module].get(api)
            assert actual == ordinal, (module, api, ordinal, actual)
        installed[module]["witnessed"].update(expected)

    abi_dir = output / "ordinal-abi"
    provider_options = [arg for name in selected for arg in ("--provider", name)]
    invoke("check_microsoft_provider_abis.py", [*provider_options, "--output", abi_dir])
    abis = json.loads((abi_dir / "report.json").read_text(encoding="utf-8"))
    assert abis["passed"] and {r["provider"]: set(r["functions"]) for r in abis["cases"]} == selected

    call_dir = output / "ordinal-calls"
    invoke("check_windows_provider_calls.py", ["--sdk-ordinal", "--cache", cache, "--linker", "lld-link",
                                               "--output", call_dir])
    calls = json.loads((call_dir / "report.json").read_text(encoding="utf-8"))
    rows = calls["cases"]
    assert calls["passed"] and len(rows) == 10
    assert all(row["object_exit"] == row["link_exit"] == 0 and len(row["ordinal_imports"]) == 1 for row in rows)

    area = call_dir / "arm64"
    compiler = ["clang-cl", "--target=aarch64-pc-windows-msvc", "/nologo", "/O2", "/MD"]
    objects = [area / "calls.obj"]
    for route in ("highc", "llvmc"):
        for name in ("UseCloseCompressor", "UseCloseDecompressor"):
            stem = area / (name + "-" + route)
            obj = stem.with_suffix(".native.obj")
            subprocess.run([*compiler, "/c", f"/D{name}={route}_{name}",
                            f"/Dneverd_ucrt_abi_0={route}_{name}_declaration", stem.with_suffix(".c"),
                            "/Fo" + str(obj)], check=True)
            objects.append(obj)
    program = area / "compression.exe"
    libraries = [area / profiles[name]["library"] for name in ("CabinetCompression", "PrintTicket", "XInput", "MAPIUtilities")]
    subprocess.run([*compiler, Path(__file__).with_name("native_ordinal_smoke.c"), *objects, *libraries,
                    "/Fe" + str(program)], check=True)
    observed = json.loads(subprocess.check_output([program], text=True, timeout=60))
    assert [row["route"] for row in observed] == ["original", "highc", "llvmc"]
    assert all(row["compressor_closed"] and row["decompressor_closed"] for row in observed)
    return dict(compiled_abis={name: len(values) for name, values in selected.items()}, installed=installed,
                callers=[{k: r[k] for k in ("api", "route", "ordinal_imports", "object_exit", "link_exit")}
                         for r in rows], runtime=observed, executable_sha256=digest(program))
