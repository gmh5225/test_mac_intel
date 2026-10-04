#!/usr/bin/env python3
"""Observe an unchanged upstream HVF experiment; never a NeverD acceptance gate."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import pty
import re
import select
import subprocess
import sys
import time

UPSTREAM = "f150b38bfff419fe19907b7a6a2d743a63b46a49"
CONTROLLER = "f35fa4bd21883eab946842358c4890d0d1480b72"
TIMEOUT = 300


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(source, *args):
    return subprocess.check_output(["git", "-C", str(source), *args], timeout=10).decode().strip()


def source_hashes(source):
    if git(source, "rev-parse", "HEAD") != UPSTREAM or git(source, "diff", "--name-only", "HEAD"):
        raise ValueError("upstream tracked source changed")
    paths = git(source, "ls-files", "-z").split("\0")
    return {name: digest(source / name) for name in paths if name}


def witnesses(log):
    """Require guest progress and all upstream checkpoints, not merely exit zero."""
    checkpoints = re.findall(r"^VM interrupt (\d+)/100000…$", log, re.M)
    summaries = re.findall(r"^Sent (\d+) randomly spaced interrupts, with (\d+) interrupt VM exits, max exit delay (-?\d+) ns$", log, re.M)
    lines = log.splitlines()
    valid = (checkpoints == [str(n) for n in range(0, 100000, 10000)]
             and len(summaries) == 1 and summaries[0][0] == "100000"
             and int(summaries[0][1]) > 0 and int(summaries[0][2]) >= 0
             and lines.count("Starting long loop...") == 1
             and lines.count("Starting random interrupts") == 1
             and lines.count("Done") == 1
             and lines.count("interrupts finished") == 1
             and "unhandled VMEXIT" not in log
             and "in unexpected state" not in log
             and not re.search(r"^HLT$|vm_vcpu_interrupt ->|Unknown interrupt|UNIMPL", log, re.M))
    ordered = False
    if valid:
        sent, received, delay = summaries[0]
        summary = f"Sent {sent} randomly spaced interrupts, with {received} interrupt VM exits, max exit delay {delay} ns"
        main = [lines.index(marker) for marker in ["Starting random interrupts",
            *(f"VM interrupt {n}/100000…" for n in range(0, 100000, 10000)), "interrupts finished", summary]]
        guest = [lines.index(marker) for marker in ["Starting long loop...", "Done", summary]]
        # Only thread-local order is known. Done and interrupts finished may
        # appear in either order because the upstream threads race at the end.
        ordered = main == sorted(main) and guest == sorted(guest)
    return {"passed": valid and ordered, "thread_local_order": ordered,
            "interrupt_checkpoints": checkpoints, "summaries": summaries}


def collect(command, cwd, evidence, environment, timeout, guard_type):
    master, slave = pty.openpty()
    start = time.monotonic()
    timed_out = False
    child = None
    failure = None
    try:
        with guard_type(evidence), (evidence / "output.log").open("xb", buffering=0) as output:
            child = subprocess.Popen(command, cwd=cwd, env=environment,
                stdin=subprocess.DEVNULL, stdout=slave, stderr=subprocess.STDOUT,
                start_new_session=True)
            os.close(slave)
            slave = -1
            while True:
                remaining = start + timeout - time.monotonic()
                if remaining <= 0:
                    # No observed completion within the original budget. A
                    # late exit zero cannot turn an expired run into success.
                    timed_out = True
                    break
                readable, _, _ = select.select([master], [], [], min(remaining, 0.1))
                if readable:
                    try:
                        data = os.read(master, 65536)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        break
                    if not data:
                        break
                    output.write(data)
                # Even a reaped child may have unread bytes in the PTY.
                # Only EOF/EIO ends collection before the fixed deadline.
            # PTY EOF can precede waitpid by a small amount. Reap naturally
            # within the original budget before the guard retires a live child.
            if not timed_out:
                try:
                    child.wait(timeout=max(0, start + timeout - time.monotonic()))
                    timed_out = time.monotonic() > start + timeout
                except subprocess.TimeoutExpired:
                    timed_out = True
    except BaseException as error:
        failure = error
        raise
    finally:
        os.close(master)
        if slave >= 0:
            os.close(slave)
        # The guard has retired the native group even when SIGTERM raises
        # SystemExit. Preserve that outcome before propagating cancellation.
        retirement_file = evidence / "retirement.json"
        retirement = json.loads(retirement_file.read_text()) if retirement_file.exists() else []
        record = retirement[0] if len(retirement) == 1 else {}
        output_file = evidence / "output.log"
        status = {"command": command, "pid": record.get("pid"), "status": record.get("status"),
            "timed_out": timed_out, "elapsed_seconds": time.monotonic() - start,
            "child_retired": record.get("retired", False),
            "controller_interrupted": isinstance(failure, (SystemExit, KeyboardInterrupt)),
            "collection_error": type(failure).__name__ if failure else None,
            "output_sha256": digest(output_file) if output_file.exists() else None}
        save(evidence / "native-status.json", status)
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "execute"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--diagnostics", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    source, diagnostics, evidence = (p.resolve() for p in (args.source, args.diagnostics, args.evidence))
    if platform.system() != "Darwin" or platform.machine() != "x86_64":
        raise ValueError("upstream control requires native Intel macOS")
    if git(diagnostics, "rev-parse", "HEAD") != CONTROLLER or git(diagnostics, "diff", "--name-only", "HEAD"):
        raise ValueError("diagnostic controller changed")
    hashes = source_hashes(source)
    binary_hash = digest(source / "hvdos")
    command = [str(source / "hvdos"), "livewait.com"]
    if args.mode == "prepare":
        evidence.mkdir(parents=True, exist_ok=False)
        observations = []
        for argv in (["sw_vers"], ["uname", "-a"], ["clang++", "--version"],
                     ["xcrun", "--show-sdk-version"], ["xcrun", "--show-sdk-path"],
                     ["sysctl", "kern.hv_support", "kern.hv_vmm_present", "machdep.cpu.brand_string", "machdep.cpu.features"],
                     ["file", str(source / "hvdos")]):
            result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
            observations.append({"command": argv, "status": result.returncode,
                                 "stdout": result.stdout, "stderr": result.stderr})
        save(evidence / "plan.json", {"kind": "independent-upstream-hvf-control", "complete_native_acceptance": False,
            "upstream_url": "https://gitlab.com/pmdj/hvf-edge-cases", "upstream_commit": UPSTREAM,
            "diagnostic_commit": CONTROLLER, "workflow_commit": os.environ.get("GITHUB_SHA"),
            "workflow_repository": os.environ.get("GITHUB_REPOSITORY"),
            "run_id": os.environ.get("GITHUB_RUN_ID"), "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "runner_image": os.environ.get("HVF_INTEL_IMAGE"), "image_version": os.environ.get("ImageVersion"),
            "source": str(source), "tracked_source_clean": True, "source_hashes": hashes,
            "binary_sha256": binary_hash, "command": command, "build_command": ["make"],
            "timeout_seconds": TIMEOUT, "stdout_transport": "PTY, unchanged upstream program",
            "limitations": ["100000 counted calls are attempts; upstream ignores random interrupt return values",
                "upstream completion can race the final interrupt; a timeout does not identify a hypervisor fault",
                "real-mode guest and upstream build flags do not establish NeverD long-mode correctness or performance"],
            "host_observations": observations})
        return 0
    plan = json.loads((evidence / "plan.json").read_text())
    if (plan["source_hashes"] != hashes or plan["binary_sha256"] != binary_hash
            or plan["source"] != str(source) or plan["command"] != command
            or plan["timeout_seconds"] != TIMEOUT or plan["upstream_commit"] != UPSTREAM
            or plan["diagnostic_commit"] != CONTROLLER):
        raise ValueError("upstream control changed after preparation")
    sys.path.insert(0, str(diagnostics))
    from scripts.diagnose_hvf_methods import NativeChildren, test_environment
    status = collect(command, source, evidence, test_environment(os.environ), TIMEOUT, NativeChildren)
    witness = witnesses((evidence / "output.log").read_text())
    passed = (status["status"] == 0 and not status["timed_out"] and status["child_retired"]
              and not status["controller_interrupted"] and status["collection_error"] is None and witness["passed"])
    save(evidence / "result.json", {"kind": "independent-upstream-hvf-control-result",
        "complete_native_acceptance": False, "passed": passed, "witnesses": witness,
        "output_sha256": status["output_sha256"]})
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
