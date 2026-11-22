#!/usr/bin/env python3
"""Discover KVM's guest SVM capability and execute the original and exported VMRUN guest images."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
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


def generated_fault_origin(directory, guest, pc):
    """Prove the fault belongs to the NeverD step's native VMRUN intrinsic."""
    elf = directory / guest["source_elf"]
    if hashlib.sha256(elf.read_bytes()).hexdigest() != guest["source_elf_sha256"]:
        raise ValueError("The generated guest ELF digest changed")
    output = subprocess.run(["nm", "-S", "-n", elf], capture_output=True,
                            text=True, check=True).stdout
    symbols = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[-1] in ("neverd_step_v10_1010",
                                               "__llvm_x86_vmrun_context.1"):
            symbols[fields[-1]] = (int(fields[0], 16), int(fields[1], 16))
    if len(symbols) != 2:
        raise ValueError("The generated VMRUN step or intrinsic symbol is missing")
    start, size = symbols["__llvm_x86_vmrun_context.1"]
    if not start <= pc < start + size:
        raise ValueError("The guest fault did not occur in the generated intrinsic")
    step, step_size = symbols["neverd_step_v10_1010"]
    disassembly = subprocess.run(["objdump", "-d",
                                  "--disassemble=neverd_step_v10_1010", elf],
                                 capture_output=True, text=True, check=True).stdout
    calls = [line for line in disassembly.splitlines()
             if re.search(r"\bcall\s+[0-9a-f]+ <__llvm_x86_vmrun_context\.1>", line)]
    if len(calls) != 1:
        raise ValueError("The original NeverD VMRUN step has no unique intrinsic call")
    call_pc = int(calls[0].split(":", 1)[0].strip(), 16)
    if not step <= call_pc < step + step_size:
        raise ValueError("The intrinsic call is outside the NeverD VMRUN step")
    complete_disassembly = subprocess.run(["objdump", "-d", elf],
                                          capture_output=True, text=True,
                                          check=True).stdout
    owners = [line for line in complete_disassembly.splitlines()
              if re.search(r"\bcall\s+[0-9a-f]+ <__llvm_x86_vmrun_context\.1>", line)]
    if len(owners) != 1 or owners[0] != calls[0]:
        raise ValueError("The native VMRUN helper has another direct caller")
    fault_instruction = subprocess.run(["objdump", "-d",
                                        "--start-address=" + hex(pc),
                                        "--stop-address=" + hex(pc + 4), elf],
                                       capture_output=True, text=True, check=True).stdout
    if not re.search(r"^\s*" + format(pc, "x") +
                     r":\s+67 0f 01 d8\s+addr32 vmrun\b", fault_instruction,
                     re.MULTILINE):
        raise ValueError("The generated fault site is not addr32 VMRUN")
    return {"source_elf_sha256": guest["source_elf_sha256"],
            "step": "neverd_step_v10_1010", "step_call_pc": hex(call_pc),
            "intrinsic": "__llvm_x86_vmrun_context.1",
            "intrinsic_range": [hex(start), hex(start + size)],
            "fault_pc": hex(pc), "fault_bytes": "670f01d8"}


def run_guest(directory, guest, runner, kvm_fd):
    image = directory / guest["image"]
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    receipt = {"image": image.name, "route": guest["route"], "optimization": guest["optimization"],
               "vmcb_input": guest["vmcb_input"],
               "guest_sha256": digest, "acceleration": "kvm", "completed": False,
               "completed_contexts": 0}
    if digest != guest["sha256"]:
        return dict(receipt, diagnostic="Fixture digest does not match the manifest")
    command = [runner, image, guest["vmcb"], *guest["breakpoints"], str(kvm_fd)]
    try:
        run = subprocess.run(command, capture_output=True, timeout=45, pass_fds=(kvm_fd,))
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
    mapped_addr32 = (guest["vmcb_input"] == "mapped" and
                     any(event["event"] == "before_addr32" and
                         int(event["rax"], 0) == int(guest["vmcb"], 0)
                         for event in trace))
    completed = (observed_rcx and run.returncode == 33 and
                 console.splitlines() == guest["expected_console"] and mapped_addr32)
    generated_origin = None
    fault = next((event for event in trace if event["event"] == "exception"), None)
    if guest["vmcb_input"] == "tagged" and guest["route"] != "original" and fault:
        try:
            generated_origin = generated_fault_origin(directory, guest,
                                                      int(fault["pc"], 0))
        except (OSError, ValueError, subprocess.CalledProcessError) as error:
            diagnostic.append(str(error))
    tagged_rax = 0xfedcba9800000000 | int(guest["vmcb"], 0)
    tagged_fault = (guest["vmcb_input"] == "tagged" and run.returncode == 1 and
                    (guest["route"] != "original" or observed_rcx) and
                    fault is not None and fault["vector"] == 13 and
                    fault["error"] == "0" and fault["bytes"] == "670f01d8" and
                    int(fault["rax"], 0) == tagged_rax and
                    (int(fault["pc"], 0) == int(guest["breakpoints"][2], 0)
                     if guest["route"] == "original" else generated_origin is not None))
    return dict(receipt, return_code=run.returncode, completed=completed,
                mapped_addr32_observed=mapped_addr32,
                tagged_addr32_gp=tagged_fault,
                completed_contexts=guest["contexts"] if completed else 0, console=console,
                diagnostic="\n".join(diagnostic), trace=trace, observed_original_rcx=observed_rcx,
                generated_fault_origin=generated_origin)


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
        kvm_fd = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
        try:
            for guest in manifest["guests"]:
                report["guest_runs"].append(run_guest(opts.guests, guest, opts.runner, kvm_fd))
        finally:
            os.close(kvm_fd)
        mapped = [r for r in report["guest_runs"] if r["vmcb_input"] == "mapped"]
        tagged = [r for r in report["guest_runs"] if r["vmcb_input"] == "tagged"]
        report["mapped_guest_runs_completed"] = sum(r["completed"] for r in mapped)
        report["tagged_guest_runs_completed"] = sum(r["completed"] for r in tagged)
        report["tagged_addr32_gp_observed"] = sum(r.get("tagged_addr32_gp", False) for r in tagged)
        # Compare each generated profile to the original on the same CPU.
        comparisons = {}
        for level in ("O0", "O2"):
            peers = [r for r in tagged if r["optimization"] == level]
            outcomes = {"completed" if r["completed"] else "#GP(0)" if
                        r.get("tagged_addr32_gp") else "unexpected" for r in peers}
            comparisons[level] = (outcomes.pop() if len(outcomes) == 1 and
                                  {r["route"] for r in peers} == {"original", "high", "llvm"}
                                  else "disagreement")
        report["tagged_addr32_comparison"] = comparisons
        complete = (len(mapped) == 6 and all(r["completed"] for r in mapped) and
                    all(outcome in ("completed", "#GP(0)") for outcome in comparisons.values()))
        report["status"] = "passed" if complete else "failed"
        report["completed_contexts"] = sum(r["completed_contexts"] for r in report["guest_runs"])
    result = json.dumps(report, indent=2)
    opts.report.write_text(result + "\n")
    print(result)
    return int(report["status"] == "failed")


if __name__ == "__main__":
    raise SystemExit(main())
