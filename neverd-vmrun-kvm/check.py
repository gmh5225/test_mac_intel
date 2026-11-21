#!/usr/bin/env python3
"""Discover KVM's guest SVM capability and execute the original and exported VMRUN guest images."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
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
              "guest_svm": False, "kvm_api": None, "guest_runs": []}
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


def run_guest(directory, guest, runner):
    image = directory / guest["image"]
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    receipt = {"image": image.name, "route": guest["route"], "optimization": guest["optimization"],
               "guest_sha256": digest, "acceleration": "kvm", "completed": False,
               "completed_contexts": 0}
    if digest != guest["sha256"]:
        return dict(receipt, diagnostic="Fixture digest does not match the manifest")
    command = [runner, image, guest["vmcb"], *guest["breakpoints"]]
    try:
        run = subprocess.run(command, capture_output=True, timeout=45)
    except subprocess.TimeoutExpired as error:
        return dict(receipt, timed_out=True, console=(error.stdout or b"").decode(errors="replace"),
                    diagnostic=(error.stderr or b"").decode(errors="replace"))
    console = run.stdout.decode(errors="replace")
    trace = []
    diagnostic = []
    for line in run.stderr.decode(errors="replace").splitlines():
        try:
            trace.append(json.loads(line))
        except ValueError:
            diagnostic.append(line)
    observed_rcx = any(event["event"] == "after_vmexit" and event["rcx"] == "0x5678"
                       and event["vmcb_exit"] == "0x81" for event in trace)
    completed = observed_rcx and run.returncode == 33 and console.splitlines() == guest["expected_console"]
    return dict(receipt, return_code=run.returncode, completed=completed,
                completed_contexts=guest["contexts"] if completed else 0, console=console,
                diagnostic="\n".join(diagnostic), trace=trace, observed_original_rcx=observed_rcx)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--guests", type=Path)
    parser.add_argument("--runner", type=Path)
    opts = parser.parse_args()
    if bool(opts.guests) != bool(opts.runner):
        parser.error("--guests and --runner are used together")
    report = discover()
    opts.report.parent.mkdir(parents=True, exist_ok=True)
    if out := os.getenv("GITHUB_OUTPUT"):
        with open(out, "a") as stream:
            stream.write("available=" + str(report["available"]).lower() + "\n")
    if opts.guests:
        if not report["available"]:
            raise RuntimeError("KVM SVM was lost after capability discovery")
        manifest = json.loads((opts.guests / "manifest.json").read_text())
        for guest in manifest["guests"]:
            report["guest_runs"].append(run_guest(opts.guests, guest, opts.runner))
        report["status"] = ("passed" if report["guest_runs"] and
                            all(r["completed"] for r in report["guest_runs"]) else "failed")
        report["completed_contexts"] = sum(r["completed_contexts"] for r in report["guest_runs"])
    result = json.dumps(report, indent=2)
    opts.report.write_text(result + "\n")
    print(result)
    return int(report["status"] == "failed")


if __name__ == "__main__":
    raise SystemExit(main())
