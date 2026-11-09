#!/usr/bin/env python3
"""Run a pinned NeverD native environment gate before acquiring build inputs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess

POLICY = json.loads(Path(__file__).with_name("Environment.def").read_text())


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def stage(argv, source, log, timeout):
    with log.open("w") as output, subprocess.Popen(
            argv, cwd=source, stdout=output, stderr=subprocess.STDOUT,
            start_new_session=True) as child:
        try:
            return child.wait(timeout=timeout)
        except BaseException:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            raise


def execute(source, output, policy=POLICY):
    revision = subprocess.check_output(policy["revision_command"], cwd=source,
                                       text=True).strip()
    if revision != policy["source_revision"]:
        raise ValueError(policy["errors"]["revision"])
    build = source / policy["build_directory"]
    if build.exists() or build.is_symlink():
        raise ValueError(policy["errors"]["existing_build"])
    output.mkdir(parents=True, exist_ok=False)
    report = {"source_revision": revision, "passed": False,
              "native_installer_call_unwind_qualified": False,
              policy["startup_qualification_key"]: False,
              policy["startup_fixup_loader_key"]: policy["startup_fixup_loader"],
              policy["publication_qualification_key"]: False,
              "whole_image_publication_qualified": False, "stages": []}
    variables = {"source": str(source), "output": str(output), "build": str(build)}
    previous = signal.getsignal(signal.SIGTERM)

    def terminate(signum, frame):
        raise SystemExit(policy["termination_code"])

    signal.signal(signal.SIGTERM, terminate)
    try:
        for item in policy["stages"]:
            argv = [value.format_map(variables) for value in item["argv"]]
            record = {"name": item["name"], "argv": argv, "returncode": None}
            report["stages"].append(record)
            save(output / policy["report_name"], report)
            record["returncode"] = stage(argv, source,
                                          output / (item["name"] + policy["log_suffix"]),
                                          item["timeout"])
            if record["returncode"]:
                return record["returncode"]
        startup = output / policy["startup_report"]
        control = json.loads(startup.read_text())
        if (not control.get(policy["startup_qualification_key"]) or
                control.get("source_revision") != revision or
                control.get("fixup_loader") != policy["startup_fixup_loader"]):
            raise ValueError(policy["errors"]["startup"])
        qualification = output / policy["qualification_report"]
        result = json.loads(qualification.read_text())
        if (not result.get("native_installer_call_unwind_qualified") or
                not result.get(policy["publication_qualification_key"]) or
                result.get("source_revision") != revision):
            raise ValueError(policy["errors"]["qualification"])
        report[policy["startup_qualification_hash_key"]] = hashlib.sha256(startup.read_bytes()).hexdigest()
        report["qualification_sha256"] = hashlib.sha256(qualification.read_bytes()).hexdigest()
        report["native_installer_call_unwind_qualified"] = True
        report[policy["startup_qualification_key"]] = True
        report[policy["publication_qualification_key"]] = True
        report["passed"] = True
        return 0
    finally:
        try:
            if build.is_dir() and not build.is_symlink():
                for name in policy["build_diagnostics"]:
                    path = build / name
                    if path.is_file():
                        destination = output / policy["build_diagnostics_directory"] / name
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(path, destination)
                shutil.rmtree(build)
                report["owned_build_removed"] = True
            save(output / policy["report_name"], report)
        finally:
            signal.signal(signal.SIGTERM, previous)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(POLICY["source_argument"], type=Path, required=True)
    parser.add_argument(POLICY["output_argument"], type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(execute(args.source.resolve(), args.output.resolve()))


if __name__ == "__main__":
    main()
