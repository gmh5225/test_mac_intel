#!/usr/bin/env python3
"""Build and run the Linux SGX entry/exit and fault/resume selftests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


CASES = ("enclave.unclobbered_vdso", "enclave.pte_permissions")


def accepted_tap(output, case):
    results = [line for line in output.splitlines()
               if re.match(r"^(?:not )?ok\s+\d+\b", line)]
    return results == [f"ok 1 {case}"] and "1..1" in output.splitlines()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    dest = args.output.resolve()
    capabilities = json.loads((dest / "capabilities.json").read_text())
    kernel = args.linux.resolve()
    fixture = kernel / "tools/testing/selftests/sgx"
    report = {
        "linux_source": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=kernel, text=True).strip(),
        "source": "tools/testing/selftests/sgx",
        "status": "build-failed",
        "cases": {},
    }
    build = subprocess.run(["make", "CC=gcc"], cwd=fixture, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (dest / "native-build.log").write_text(build.stdout)
    if not build.returncode:
        for filename in ("test_sgx", "test_encl.elf"):
            report[filename + "_sha256"] = hashlib.sha256(
                (fixture / filename).read_bytes()).hexdigest()
        reasons = list(capabilities["reasons"])
        if not any(device["path"] == "/dev/sgx_enclave" and
                   device["opened_read_write"] for device in capabilities["devices"]):
            reasons.append("The Linux selftest needs read/write access to /dev/sgx_enclave")
        if reasons:
            report.update(status="unavailable", reasons=reasons)
        else:
            for case in CASES:
                result = subprocess.run(["./test_sgx", "-r", case], cwd=fixture,
                                        text=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT)
                (dest / (case + ".tap")).write_text(result.stdout)
                report["cases"][case] = {
                    "exit_code": result.returncode,
                    "passed": result.returncode == 0 and accepted_tap(result.stdout, case),
                }
            report["status"] = ("passed" if all(result["passed"]
                                for result in report["cases"].values()) else "failed")
    report_path = dest / "native-kselftest.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(report_path.read_text(), end="")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a") as stream:
            stream.write(f"Linux SGX native selftests: **{report['status']}**. "
                         f"Cases executed: **{len(report['cases'])}**.\n")
    return 1 if report["status"] in ("build-failed", "failed") else 0


if __name__ == "__main__":
    raise SystemExit(main())
