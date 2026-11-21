#!/usr/bin/env python3
# NeverD Decompiler. SPDX-License-Identifier: AGPL-3.0-only
"""Compare original objects with both recovered C routes on native Windows."""

from __future__ import annotations
import argparse, ctypes as C, hashlib, json, os, platform, re, shutil, struct, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FUNCTIONS = {
    "user": ["UsePath", "UseRuntimeString", "UseShaderCompile2"],
    "driver": ["UseSDConfig", "UseAudioAdapter", "UseStreamClock"],
    "ndis": ["ReadConfiguration"],
}
LIBS = [
    "advapi32.lib",
    "pathcch.lib",
    "runtimeobject.lib",
    "gdi32.lib",
    "clfsw32.lib",
    "tbs.lib",
    "d3d11.lib",
    "d3d12.lib",
    "dxgi.lib",
    "d3dcompiler.lib",
]


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def tool(name):
    p = shutil.which(name)
    if p:
        return p
    p = Path(os.environ["ProgramFiles"]) / "LLVM/bin" / (name + ".exe")
    if p.is_file():
        return str(p)
    raise RuntimeError("required compiler tool is missing: " + name)


def machine(p):
    data = p.read_bytes()
    offset = struct.unpack_from("<I", data, 60)[0] if data[:2] == b"MZ" else -4
    return struct.unpack_from("<H", data, offset + 4)[0]


def run(command, out, name):
    r = subprocess.run(list(map(str, command)), capture_output=True, timeout=90)
    (out / (name + ".stdout")).write_bytes(r.stdout)
    (out / (name + ".stderr")).write_bytes(r.stderr)
    if r.returncode:
        raise RuntimeError(
            f"{name} returned {r.returncode}: {r.stderr.decode(errors='replace')}"
        )


def build(payload, out, arch, functions, provider_source, variants):
    clang, link = (tool("clang"), tool("lld-link"))
    commands = []

    def invoke(c, name):
        commands.append(list(map(str, c)))
        run(c, out, name)

    def compile(source, target, opt, extra=()):
        invoke(
            [
                clang,
                "--target="
                + ("aarch64" if arch == "arm64" else "x86_64")
                + "-pc-windows-msvc",
                "-std=gnu11",
                "-ffreestanding",
                "-fno-builtin",
                "-fno-stack-protector",
                "-fno-strict-aliasing",
                opt,
                *extra,
                "-c",
                source,
                "-o",
                target,
            ],
            target.stem,
        )

    provider = out / "provider.obj"
    compile(provider_source, provider, "-O2")
    invoke(
        [
            link,
            "/dll",
            "/noentry",
            "/nodefaultlib",
            "/timestamp:0",
            "/out:" + str(out / "provider.dll"),
            "/implib:" + str(out / "provider.lib"),
            provider,
        ],
        "provider-link",
    )
    for category in functions:
        objects = [payload / ("original-" + category + ".obj")]
        invoke(
            [
                link,
                "/dll",
                "/noentry",
                "/nodefaultlib",
                "/timestamp:0",
                "/out:" + str(out / ("original-" + category + ".dll")),
                *objects,
                out / "provider.lib",
                *(LIBS if category == "user" else []),
            ],
            "original-" + category + "-link",
        )
    for variant in variants:
        for category, names in functions.items():
            if variant == "baseline-llvmc" and category != "user":
                continue
            objects = []
            for name in ["UseShaderCompile2"] if variant == "baseline-llvmc" else names:
                source = (
                    payload
                    / (
                        variant.split("-")[0]
                        if variant != "baseline-llvmc"
                        else "baseline-llvmc"
                    )
                    / (name + ".c")
                )
                target = out / (variant + "-" + name + ".obj")
                objects.append(target)
                compile(
                    source,
                    target,
                    (
                        "-O0"
                        if variant == "baseline-llvmc"
                        else "-" + variant.split("-")[1]
                    ),
                    ["-Dneverd_ucrt_abi_0=abi_" + name],
                )
            storage = {}
            for source in [
                payload
                / (
                    variant.split("-")[0]
                    if variant != "baseline-llvmc"
                    else "baseline-llvmc"
                )
                / (name + ".c")
                for name in (
                    ["UseShaderCompile2"] if variant == "baseline-llvmc" else names
                )
            ]:
                for symbol, size in re.findall(
                    r"extern uint8_t (unk_[0-9A-Fa-f]+)\[(\d+)\];", source.read_text()
                ):
                    storage[symbol] = max(storage.get(symbol, 0), int(size))
            if storage:
                definition = out / (variant + "-" + category + "-image.c")
                definition.write_text(
                    "#include <stdint.h>\n"
                    + "".join(
                        f"__declspec(dllexport) uint8_t {name}[{size}];\n"
                        for name, size in storage.items()
                    )
                )
                target = definition.with_suffix(".obj")
                compile(definition, target, "-O0")
                objects.append(target)
            invoke(
                [
                    link,
                    "/dll",
                    "/noentry",
                    "/nodefaultlib",
                    "/timestamp:0",
                    "/out:" + str(out / (variant + "-" + category + ".dll")),
                    *objects,
                    out / "provider.lib",
                    *(LIBS if category == "user" else []),
                    *[
                        "/export:" + name
                        for name in (
                            ["UseShaderCompile2"]
                            if variant == "baseline-llvmc"
                            else names
                        )
                    ],
                ],
                variant + "-" + category + "-link",
            )
    for binary in out.glob("*.dll"):
        assert machine(binary) == (43620 if arch == "arm64" else 34404), binary
    (out / "build-commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    (out / "compiler.txt").write_bytes(subprocess.check_output([clang, "--version"]))


def materialize_image(dll, source, provider):
    """Supply the original loaded-image storage explicitly requested by LLVMC.

    Preserve source reads, including unused volatile IAT reads. Resolve kernel
    imports to the declared ABI models and other imports to the real OS DLLs.
    This backing storage is not a kernel driver mapping or driver execution.
    """
    data = source.read_bytes()
    pe = struct.unpack_from("<I", data, 60)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    assert struct.unpack_from("<H", data, optional)[0] == 0x20B
    base = struct.unpack_from("<Q", data, optional + 24)[0]
    size, headers = struct.unpack_from("<II", data, optional + 56)
    try:
        storage = C.c_uint8.in_dll(dll, "unk_" + format(base, "x"))
    except ValueError:
        return
    image = bytearray(size)
    image[:headers] = data[:headers]
    sections = optional + optional_size
    for i in range(count):
        virtual, raw_size, raw = struct.unpack_from(
            "<III", data, sections + 40 * i + 12
        )
        image[virtual : virtual + raw_size] = data[raw : raw + raw_size]
    descriptor = struct.unpack_from("<I", data, optional + 120)[0]

    def text(at):
        return bytes(image[at : image.index(0, at)]).decode("ascii")

    while descriptor and any(image[descriptor : descriptor + 20]):
        original, stamp, forward, module_name, slots = struct.unpack_from(
            "<IIIII", image, descriptor
        )
        module = text(module_name)
        index = 0
        while True:
            value = struct.unpack_from("<Q", image, (original or slots) + index * 8)[0]
            if not value:
                break
            if value >> 63:
                address = C.cast(C.WinDLL(module)[value & 0xFFFF], C.c_void_p).value
            else:
                name = text(value + 2)
                try:
                    address = C.cast(getattr(provider, name), C.c_void_p).value
                except AttributeError:
                    address = C.cast(getattr(C.WinDLL(module), name), C.c_void_p).value
            struct.pack_into("<Q", image, slots + index * 8, address)
            index += 1
        descriptor += 20
    # Emitters declare only the prefix they read; respect that exact allocation.
    for symbol, extent in re.findall(
        r"__declspec\(dllexport\) uint8_t (unk_[0-9a-f]+)\[(\d+)\];",
        (
            Path(dll._name).with_suffix("").with_name(Path(dll._name).stem + "-image.c")
        ).read_text(),
    ):
        if symbol == "unk_" + format(base, "x"):
            assert int(extent) <= len(image)
            C.memmove(C.addressof(storage), bytes(image[: int(extent)]), int(extent))
            return
    raise AssertionError("missing original image storage extent")


def execute(out, variant, arch):
    os.add_dll_directory(str(out))
    provider = C.WinDLL(str(out / "provider.dll"))
    reset = provider.ModelReset
    reset.argtypes = [C.c_uint32]
    reset.restype = None
    snapshot = provider.ModelSnapshot
    snapshot.argtypes = [C.POINTER(C.c_uint64)]
    snapshot.restype = None

    def trace():
        words = (C.c_uint64 * 64)()
        snapshot(words)
        return list(words)[1 : 1 + words[0]]

    def call(dll, name, args, types):
        f = getattr(dll, name)
        f.argtypes = types
        f.restype = C.c_uint32
        return f(*args)

    original_user = C.WinDLL(str(out / "original-user.dll"))
    recovered_user = C.WinDLL(str(out / (variant + "-user.dll")))
    materialize_image(
        recovered_user, ROOT / "payload" / arch / "original-user.dll", provider
    )
    results = []
    ptr = C.c_void_p
    u32 = C.c_uint32
    u64 = C.c_uint64
    for seed in [1, 7, 31]:
        args = [
            1056816 + seed,
            20015998341120 + seed,
            2311527 + seed,
            3430008 + seed,
            4548489 + seed,
            5666960 + seed,
            6785281 + seed,
            2309737967,
            2596069104,
            2882400001,
            7901202 + seed,
            244837814047284 + seed,
            8978723 + seed,
            9441844 + seed,
        ]
        types = [ptr, u64, ptr, ptr, ptr, ptr, ptr, u32, u32, u32, ptr, u64, ptr, ptr]
        reset(0)
        a = call(original_user, "UseShaderCompile2", args, types)
        expected = trace()
        assert a == 2149724996 and expected == [14, *args], (
            "original shader ABI mismatch",
            expected,
            args,
        )
        reset(0)
        b = call(recovered_user, "UseShaderCompile2", args, types)
        actual = trace()
        equal = a == b and actual == expected
        results.append(
            {
                "case": "shader-14-arguments",
                "seed": seed,
                "equal": equal,
                "original": expected,
                "recovered": actual,
                "status": b,
            }
        )
    if variant == "baseline-llvmc":
        assert all(
            (
                not x["equal"] and x["original"][11:13] != x["recovered"][11:13]
                for x in results
            )
        ), "baseline failed to expose the lost secondary-data arguments"
        return {
            "variant": variant,
            "expected_argument_loss_observed": True,
            "cases": results,
        }
    assert all((x["equal"] for x in results)), "recovered shader argument mismatch"
    runtime = C.WinDLL("combase.dll")
    get = runtime.WindowsGetStringRawBuffer
    get.argtypes = [ptr, C.POINTER(u32)]
    get.restype = ptr
    delete = runtime.WindowsDeleteString
    delete.argtypes = [ptr]
    delete.restype = C.c_long
    for text in ["", "MmSecureVirtualMemoryEx", "ARM64-中文-🙂"]:
        value = C.create_unicode_buffer(text)
        count = len(text.encode("utf-16-le")) // 2
        observations = []
        for dll in [original_user, recovered_user]:
            string = ptr()
            status = call(
                dll,
                "UseRuntimeString",
                [value, count, C.byref(string)],
                [ptr, u32, ptr],
            )
            length = u32()
            assert status == 0, "WindowsCreateString failed"
            raw = get(string, C.byref(length))
            data = C.string_at(raw, length.value * 2)
            assert delete(string) == 0
            assert length.value == count and data == text.encode("utf-16-le")
            observations.append((status, data.hex()))
        assert observations[0] == observations[1]
        results.append(
            {"case": "real-WindowsCreateString", "utf16_units": count, "equal": True}
        )
    for capacity in [2, 64, 128]:
        observations = []
        for dll in [original_user, recovered_user]:
            buffer = (C.c_uint16 * 128)(*[52428] * 128)
            base = C.create_unicode_buffer("C:\\arm64")
            more = C.create_unicode_buffer("folder\\..\\file.txt")
            status = call(
                dll,
                "UsePath",
                [buffer, capacity, base, more, 0],
                [ptr, u64, ptr, ptr, u32],
            )
            observations.append((status, bytes(buffer)))
        assert observations[0] == observations[1], "PathCchCombineEx output mismatch"
        assert (observations[0][0] == 0) == (capacity >= 64)
        results.append(
            {
                "case": "real-PathCchCombineEx",
                "capacity": capacity,
                "status": observations[0][0],
                "equal": True,
            }
        )
    original = C.WinDLL(str(out / "original-driver.dll"))
    recovered = C.WinDLL(str(out / (variant + "-driver.dll")))
    materialize_image(
        recovered, ROOT / "payload" / arch / "original-driver.sys", provider
    )
    original_ndis = C.WinDLL(str(out / "original-ndis.dll"))
    recovered_ndis = C.WinDLL(str(out / (variant + "-ndis.dll")))
    materialize_image(
        recovered_ndis, ROOT / "payload" / arch / "original-ndis.sys", provider
    )
    for scenario in [0, 1, 2]:
        observations = []
        for dll in [original_ndis, recovered_ndis]:
            reset(scenario)
            status = call(dll, "ReadConfiguration", [4276545, 5395026], [ptr, ptr])
            observations.append((status, trace()))
        expected = (
            [1, 4276545, 1]
            if scenario == 1
            else [1, 4276545, 1, 2, 1, 1, 1193040, 5395026, 2, 3, 1193040]
        )
        assert observations[0] == observations[1] and observations[0][1] == expected
        assert observations[0][0] == [0, 3221225473, 3221225485][scenario]
        results.append(
            {
                "case": "modeled-NDIS-open-read-close",
                "scenario": scenario,
                "status": observations[0][0],
                "trace": expected,
                "equal": True,
            }
        )
    for size in [1, 7, 16]:
        buffer = (C.c_uint8 * 32)()
        address = C.addressof(buffer) + 8
        observations = []
        for dll in [original, recovered]:
            C.memset(buffer, 204, 32)
            reset(0)
            status = call(
                dll,
                "UseSDConfig",
                [1118464, 165, address, size],
                [ptr, C.c_uint8, ptr, u32],
            )
            observations.append((status, trace(), bytes(buffer)))
        expected = bytes(
            [204] * 8 + [165 + i & 255 for i in range(size)] + [204] * (24 - size)
        )
        assert (
            observations[0] == observations[1]
            and observations[0][0] == size
            and (observations[0][2] == expected)
        )
        results.append(
            {"case": "modeled-SDPort-byte-offset-buffer", "length": size, "equal": True}
        )
    calls = []
    callback_type = C.WINFUNCTYPE(C.c_int32, ptr, ptr, ptr)

    @callback_type
    def callback(device, irp, resources):
        calls.append([device, irp, resources])
        return -1234567

    for maximum in [0, 1, 2147483666]:
        observations = []
        for dll in [original, recovered]:
            calls.clear()
            reset(0)
            status = call(
                dll,
                "UseAudioAdapter",
                [1118464, 2236928, callback, maximum, 270544960],
                [ptr, ptr, callback_type, u32, u32],
            )
            observations.append((status, trace(), list(calls)))
        assert observations[0] == observations[1] and observations[0][2] == [
            [2236928, None, None]
        ]
        assert observations[0][0] == -1234567 & 4294967295 ^ maximum ^ 270544960
        results.append(
            {
                "case": "modeled-PortCls-native-callback",
                "maximum": maximum,
                "equal": True,
            }
        )
    context = (u64 * 4)()
    observations = []
    for dll in [original, recovered]:
        C.memset(context, 204, C.sizeof(context))
        reset(0)
        f = dll.UseStreamClock
        f.argtypes = [ptr, ptr]
        f.restype = None
        f(3355392, context)
        observations.append((trace(), list(context)))
    assert observations[0] == observations[1] and observations[0][1] == [
        1234605616436508552,
        9833440827789222417,
        14757395258967641292,
        14757395258967641292,
    ]
    results.append({"case": "modeled-StreamClass-void-output-buffer", "equal": True})
    return {"variant": variant, "passed": True, "cases": results}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--execute")
    ap.add_argument("--arch", choices=["arm64", "x64"], required=True)
    a = ap.parse_args()
    out = a.output.resolve()
    assert platform.system() == "Windows" and platform.machine().lower() in (
        ["arm64", "aarch64"] if a.arch == "arm64" else ["amd64", "x86_64"]
    ), "native Windows target Python required"
    if a.execute:
        print(json.dumps(execute(out, a.execute, a.arch)))
        return
    out.mkdir(parents=True, exist_ok=False)
    payload = ROOT / "payload" / a.arch
    manifest = json.loads((payload / "manifest.json").read_text())
    for name, expected in manifest["files"].items():
        assert digest(payload / name) == expected, name
    assert not manifest["source_dirty"]
    build(
        payload,
        out,
        a.arch,
        FUNCTIONS,
        ROOT / "provider.c",
        ["baseline-llvmc", "highc-O0", "highc-O2", "llvmc-O0", "llvmc-O2"],
    )
    rows = []
    for variant in ["baseline-llvmc", "highc-O0", "highc-O2", "llvmc-O0", "llvmc-O2"]:
        result = subprocess.run(
            [
                sys.executable,
                __file__,
                "--output",
                str(out),
                "--execute",
                variant,
                "--arch",
                a.arch,
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
        "architecture": a.arch,
        "system": platform.platform(),
        "source": manifest["source"],
        "harness": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip(),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "rows": rows,
        "scope": "Native Windows original/recovered caller execution. Windows string/path APIs are real; driver APIs and D3DCompile2 use observable ABI models. No kernel driver is loaded.",
    }
    (out / "native-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
