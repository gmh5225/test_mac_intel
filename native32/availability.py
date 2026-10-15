#!/usr/bin/env python3
"""Inventory hosted 32-bit execution prerequisites; never certify a patch."""
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
NEVERD_COMMIT = "fcee81c9a5e2f20a71090ade23ae833175f64c59"


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Probe:
    def __init__(self, output):
        output.mkdir(parents=True, exist_ok=False)
        self.output = output.resolve()
        self.data = {
            "schema": "neverd.hosted-native32-availability.v1",
            "purpose": "environment discovery, not source-patch qualification",
            "native_patch_qualification": False,
            "qualified_patch_observations": 0,
            "reference_neverd_commit": NEVERD_COMMIT,
            "harness_commit": os.environ.get("GITHUB_SHA"),
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "host": {"system": platform.system(), "machine": platform.machine(),
                     "release": platform.release(), "version": platform.version(),
                     "python": sys.version, "pointer_bits": struct.calcsize("P") * 8,
                     "runner_arch": os.environ.get("RUNNER_ARCH"),
                     "image_os": os.environ.get("ImageOS"),
                     "image_version": os.environ.get("ImageVersion")},
            "sources": {p.name: digest(p) for p in sorted(ROOT.iterdir()) if p.is_file()},
            "commands": [], "binaries": [], "profiles": {}, "complete": False,
        }

    def command(self, label, args, timeout=60):
        row = {"label": label, "argv": [str(a) for a in args], "timeout_seconds": timeout}
        try:
            result = subprocess.run(row["argv"], capture_output=True, timeout=timeout)
            row.update(returncode=result.returncode,
                       stdout=result.stdout.decode("utf-8", "replace"),
                       stderr=result.stderr.decode("utf-8", "replace"))
        except OSError as error:
            row.update(error=str(error), errno=error.errno,
                       winerror=getattr(error, "winerror", None))
        except subprocess.TimeoutExpired:
            row.update(error="process deadline exceeded", timed_out=True)
        self.data["commands"].append(row)
        self.save()
        return row

    def compile(self, label, args):
        return self.command(label, args, timeout=120).get("returncode") == 0

    def execute(self, label, path, machine):
        raw = path.read_bytes()
        if raw[:4] == b"\x7fELF":
            actual = struct.unpack_from("<H", raw, 18)[0]
        elif raw[:2] == b"MZ":
            pe = struct.unpack_from("<I", raw, 0x3c)[0]
            require(raw[pe:pe + 4] == b"PE\0\0", "invalid PE signature")
            actual = struct.unpack_from("<H", raw, pe + 4)[0]
        else:
            require(raw[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"),
                    "expected a thin little-endian Mach-O image")
            actual = struct.unpack_from("<I", raw, 4)[0]
        require(actual == machine, "compiler emitted the wrong architecture")
        self.data["binaries"].append({"path": path.name, "size": len(raw),
                                      "sha256": digest(path), "machine": actual})
        rows = [self.command(label + "-" + str(i), [path], timeout=10)
                for i in range(1, 4)]
        return all(row.get("returncode") == 87 for row in rows)

    def save(self):
        (self.output / "availability.json").write_text(json.dumps(self.data, indent=2) + "\n")


def linux(probe):
    require(platform.system() == "Linux" and platform.machine() == "aarch64",
            "this inventory requires a Linux ARM64 host")
    probe.command("cpu", ["lscpu"])
    probe.command("kernel", ["uname", "-a"])
    binfmt = Path("/proc/sys/fs/binfmt_misc")
    probe.data["binfmt_misc"] = {p.name: p.read_text() for p in binfmt.glob("*")
                                 if p.is_file() and p.name != "register"}
    header = Path("/proc/self/exe").open("rb").read(64)
    require(header[:6] == b"\x7fELF\x02\x01" and
            struct.unpack_from("<H", header, 18)[0] == 183,
            "inventory Python must itself be an AArch64 Linux process")
    native = probe.output / "control-arm64"
    require(probe.compile("compile-control", ["cc", ROOT / "exit87.c", "-o", native]),
            "native control compiler failed")
    require(probe.execute("control-arm64", native, 183), "native control did not exit 87")
    probe.command("cross-compiler", ["arm-linux-gnueabihf-gcc", "--version"])
    for mode in ("arm", "thumb"):
        path = probe.output / ("probe-" + mode)
        require(probe.compile("compile-" + mode, ["arm-linux-gnueabihf-gcc",
                "-m" + mode, "-march=armv7-a", "-mfpu=vfpv3-d16", "-nostdlib", "-static",
                "-Wl,-e,_start", ROOT / "linux_exit87.S", "-o", path]),
                "ARM32 compiler failed; no execution conclusion is available")
        executed = probe.execute("direct-" + mode, path, 40)
        handlers = [name for name in probe.data["binfmt_misc"] if name != "status"]
        probe.data["profiles"]["linux-arm32-" + mode] = {
            "direct_exit87_observed": executed,
            "status": ("requires_binfmt_handler_audit" if handlers else
                       "compatibility_candidate") if executed else "direct_execution_unavailable",
            "matching_native_host": False,
            "note": "ARM64 host; even successful ARM32 execution needs compatibility classification.",
        }


def windows(probe):
    require(platform.system() == "Windows", "Windows inventory requires Windows")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.IsWow64Process2.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ushort),
                                     ctypes.POINTER(ctypes.c_ushort)]
    kernel.IsWow64Process2.restype = ctypes.c_int
    process, native = ctypes.c_ushort(), ctypes.c_ushort()
    require(kernel.IsWow64Process2(kernel.GetCurrentProcess(), ctypes.byref(process),
                                  ctypes.byref(native)), "IsWow64Process2 failed")
    probe.data["windows_machine"] = {"process": process.value, "native": native.value}
    require(native.value == 0xaa64, "this inventory requires native Windows ARM64")
    for name in ("IsWow64GuestMachineSupported", "GetMachineTypeAttributes"):
        function = getattr(kernel, name, None)
        if function is None:
            probe.data[name] = {"available": False}
            continue
        function.argtypes = [ctypes.c_ushort, ctypes.POINTER(ctypes.c_uint32)]
        function.restype = ctypes.c_long
        flags = ctypes.c_uint32()
        status = function(0x1c4, ctypes.byref(flags))
        probe.data[name] = {"available": True, "machine": 0x1c4,
                            "hresult": status, "value": flags.value}
    compiler = shutil.which("clang") or r"C:\Program Files\LLVM\bin\clang.exe"
    linker = shutil.which("lld-link") or str(Path(compiler).with_name("lld-link.exe"))
    probe.command("compiler-version", [compiler, "--version"])
    probe.command("linker-version", [linker, "--version"])
    for arch, triple, machine in (("arm64", "aarch64-pc-windows-msvc", 0xaa64),
                                  ("arm", "armv7-pc-windows-msvc", 0x1c4)):
        obj = probe.output / (arch + ".obj")
        binary = probe.output / (arch + ".exe")
        require(probe.compile("compile-" + arch, [compiler, "--target=" + triple,
                "-ffreestanding", "-fno-stack-protector", "-O2", "-c",
                ROOT / "windows_exit87.c", "-o", obj]), "COFF compiler failed")
        require(probe.compile("link-" + arch, [linker, "/machine:" + arch,
                "/entry:entry", "/subsystem:console", "/nodefaultlib",
                "/out:" + str(binary), obj]), "PE linker failed")
        executed = probe.execute("direct-" + arch, binary, machine)
        if arch == "arm64":
            require(executed, "native ARM64 control did not exit 87")
        else:
            probe.data["profiles"]["windows-arm32"] = {
                "direct_exit87_observed": executed,
                "matching_native_host": False,
                "status": "compatibility_candidate" if executed else "direct_execution_unavailable",
                "note": "ARM64 host; a tiny loader probe cannot qualify NeverD patches.",
            }


def macos(probe):
    require(platform.system() == "Darwin" and platform.machine() == "x86_64",
            "this inventory requires an Intel macOS host")
    query = ctypes.CDLL(None, use_errno=True).sysctlbyname
    query.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                      ctypes.c_void_p, ctypes.c_size_t]
    query.restype = ctypes.c_int
    translated, size = ctypes.c_int(-1), ctypes.c_size_t(ctypes.sizeof(ctypes.c_int))
    ctypes.set_errno(0)
    status = query(b"sysctl.proc_translated", ctypes.byref(translated), ctypes.byref(size), None, 0)
    native = (status == -1 and ctypes.get_errno() == errno.ENOENT or
              status == 0 and size.value == 4 and translated.value == 0)
    require(native, "Rosetta cannot satisfy the Intel host requirement")
    probe.data["host"]["rosetta"] = False
    for name, command in (
            ("os-version", ["sw_vers"]),
            ("cpu", ["sysctl", "machdep.cpu.brand_string", "hw.optional.x86_64"]),
            ("xcode-version", ["xcodebuild", "-version"]),
            ("sdks", ["xcodebuild", "-showsdks"]),
            ("devices", ["xcrun", "xctrace", "list", "devices"]),
            ("simulator-runtimes", ["xcrun", "simctl", "list", "runtimes", "--json"])):
        probe.command(name, command)
    binary = probe.output / "control-x64"
    require(probe.compile("compile-control", ["clang", "-arch", "x86_64",
            ROOT / "exit87.c", "-o", binary]), "native control compiler failed")
    require(probe.execute("control-x64", binary, 0x1000007), "native control did not exit 87")
    for name, sdk, arch, minimum in (("macos-i386", "macosx", "i386", "-mmacosx-version-min=10.14"),
            ("ios-armv7", "iphoneos", "armv7", "-miphoneos-version-min=10.0"),
            ("watchos-armv7k", "watchos", "armv7k", "-mwatchos-version-min=3.0")):
        binary = probe.output / name
        compiled = probe.compile("link-" + name, ["xcrun", "--sdk", sdk, "clang",
                "-arch", arch, minimum, ROOT / "exit87.c", "-o", binary])
        row = {"sdk_link_succeeded": compiled, "matching_native_host": False}
        if name == "macos-i386" and compiled:
            executed = probe.execute("direct-i386", binary, 7)
            row.update(direct_exit87_observed=executed,
                       status="compatibility_candidate" if executed else "direct_execution_unavailable")
        else:
            row["status"] = "device_execution_not_established" if compiled else "sdk_link_unavailable"
        row["note"] = "No physical iOS/watchOS device or ARM32 execution evidence is supplied by this job."
        probe.data["profiles"][name] = row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("linux", "windows", "macos"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    probe = Probe(args.output)
    try:
        {"linux": linux, "windows": windows, "macos": macos}[args.profile](probe)
        probe.data["complete"] = True
    except Exception as error:
        probe.data["harness_error"] = str(error)
        raise
    finally:
        probe.save()
        text = ("## Hosted 32-bit availability inventory\n\n"
                "This is an environment probe, **not patch qualification**. "
                "Native patch observations: **0**.\n\n" +
                "\n".join("- `" + k + "`: `" + v["status"] + "`"
                          for k, v in probe.data["profiles"].items()) + "\n")
        if "GITHUB_STEP_SUMMARY" in os.environ:
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
                output.write(text)
        print(text)


if __name__ == "__main__":
    main()
