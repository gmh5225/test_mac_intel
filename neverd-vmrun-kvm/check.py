#!/usr/bin/env python3
"""Discover KVM's guest SVM capability and execute the original RCX example."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess

KVM_API_VERSION = 12
KVM_GET_API_VERSION = 0xAE00
KVM_GET_SUPPORTED_CPUID = 0xC008AE05
CPUID_ENTRY = struct.Struct("=10I")


def discover():
    cpu = dict((key.strip(), value.strip()) for line in
               Path("/proc/cpuinfo").read_text().split("\n\n")[0].splitlines()
               if ":" in line for key, value in [line.split(":", 1)])
    report = {"cpu": cpu.get("model name"), "vendor": cpu.get("vendor_id"),
              "host_svm": "svm" in cpu.get("flags", "").split(),
              "guest_svm": False, "kvm_api": None, "original_guest_runs": []}
    nested = Path("/sys/module/kvm_amd/parameters/nested")
    report["kvm_amd_nested"] = nested.read_text().strip() if nested.is_file() else None
    try:
        fd = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
    except OSError as error:
        report["device_diagnostic"] = str(error)
    else:
        try:
            report["kvm_api"] = fcntl.ioctl(fd, KVM_GET_API_VERSION, 0)
            count = 512
            data = bytearray(8 + CPUID_ENTRY.size * count)
            struct.pack_into("=I", data, 0, count)
            fcntl.ioctl(fd, KVM_GET_SUPPORTED_CPUID, data, True)
            size = struct.unpack_from("=I", data)[0]
            for function, _, _, _, _, ecx, _, _, _, _ in CPUID_ENTRY.iter_unpack(
                    memoryview(data)[8:8 + size * CPUID_ENTRY.size]):
                if function == 0x80000001:
                    report["guest_svm"] = bool(ecx & (1 << 2))
        finally:
            os.close(fd)
    report["available"] = (report["vendor"] == "AuthenticAMD" and report["host_svm"]
                           and report["kvm_api"] == KVM_API_VERSION and report["guest_svm"]
                           and report["kvm_amd_nested"] not in ("0", "N"))
    report["status"] = "available" if report["available"] else "unavailable"
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--guests", type=Path)
    opts = parser.parse_args()
    report = discover()
    opts.report.parent.mkdir(parents=True, exist_ok=True)
    if out := os.getenv("GITHUB_OUTPUT"):
        with open(out, "a") as stream:
            stream.write("available=" + str(report["available"]).lower() + "\n")
    if opts.guests:
        if not report["available"]:
            raise RuntimeError("KVM SVM was lost after capability discovery")
        for level in ("O0", "O2"):
            image = opts.guests / ("guest-64-" + level + ".multiboot")
            command = [shutil.which("qemu-system-x86_64"), "-accel", "kvm", "-cpu", "host",
                       "-machine", "pc", "-m", "32M", "-nodefaults", "-display", "none",
                       "-serial", "none", "-monitor", "none", "-no-reboot", "-nic", "none",
                       "-device", "isa-debug-exit,iobase=0xf4,iosize=4", "-kernel", str(image),
                       "-debugcon", "stdio"]
            run = subprocess.run(command, capture_output=True, text=True, timeout=45)
            completed = run.returncode == 33 and run.stdout.strip() == "IDA:5678"
            report["original_guest_runs"].append({
                "optimization": level, "acceleration": "kvm", "completed": completed,
                "return_code": run.returncode, "serial": run.stdout, "diagnostic": run.stderr,
                "guest_sha256": hashlib.sha256(image.read_bytes()).hexdigest()})
        report["status"] = ("passed" if all(r["completed"] for r in report["original_guest_runs"])
                            else "failed")
    result = json.dumps(report, indent=2)
    opts.report.write_text(result + "\n")
    print(result)
    return int(report["status"] == "failed")


if __name__ == "__main__":
    raise SystemExit(main())
