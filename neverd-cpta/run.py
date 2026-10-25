#!/usr/bin/env python3
"""Prepare and execute the pinned, capability-gated Arm CPA2 guest."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent
CONFIG = json.loads((ROOT / "CptaEnvironment.def").read_text())


def assess(transcript, returncode, config=None):
    config = CONFIG if config is None else config
    records = {}
    failures = []
    for line in transcript.splitlines():
        if not line.startswith('{"name":'):
            continue
        row = json.loads(line)
        name = row["name"]
        if name == config["failed_index_record"]:
            failures.append(int(row["value"], 16))
            continue
        if name in records:
            raise ValueError(f"Duplicate guest record: {name}")
        records[name] = int(row["value"], 16)
    missing = sorted(set(config["required_records"]) - records.keys())
    gates = not missing and all(
        records[name] == value for name, value in config["gate_values"].items()
    )
    pfr = records.get(config["pfr_record"], -1)
    isar = records.get(config["isar_record"], -1)
    gates = gates and all(
        (pfr >> config[name]) & config["id_field_mask"] == 0
        for name in ("pfr_el2_shift", "pfr_el3_shift")
    )
    gates = gates and isar & config["id_field_mask"] == config["cpa2_level"]
    passed = (
        returncode == 0
        and gates
        and not failures
        and config["unexpected_marker"] not in transcript
        and records.get(config["passed_record"]) == config["expected_passed_cases"]
    )
    return {
        "passed": bool(passed),
        "records": records,
        "missing": missing,
        "failed_case_indices": failures,
        "model_only": True,
        "native_apple_cpta_qualified": False,
        "neverd_output_qualified": False,
        "scope": config["scope"],
    }


def execute(command, evidence, label, timeout, env=None):
    (evidence / f"{label}-command.json").write_text(
        json.dumps(command, indent=2) + "\n"
    )
    try:
        result = subprocess.run(
            command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, env=env, check=False,
        )
    except subprocess.TimeoutExpired as error:
        output = error.stdout or b""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        (evidence / f"{label}.log").write_text(output)
        raise
    (evidence / f"{label}.log").write_text(result.stdout)
    return result


def prepare(workspace, evidence):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("This pinned official FVP package requires x86_64 Linux")
    archive = workspace / CONFIG["model_archive"]
    with urllib.request.urlopen(
        CONFIG["model_url"], timeout=CONFIG["download_timeout_seconds"]
    ) as response, archive.open("wb") as output:
        shutil.copyfileobj(response, output)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != CONFIG["model_sha256"]:
        raise ValueError("Official FVP archive SHA-256 mismatch")
    with tarfile.open(archive, "r:gz") as package:
        for name in (CONFIG["model_installer"], CONFIG["model_release_notes"]):
            member = package.getmember(name)
            if not member.isfile():
                raise ValueError("Expected a regular official installer file")
            with package.extractfile(member) as source, (workspace / name).open("wb") as target:
                shutil.copyfileobj(source, target)
    installed = workspace / "installed"
    result = execute(
        ["sh", str(workspace / CONFIG["model_installer"]),
         "--i-agree-to-the-contained-eula", "--no-interactive", "--skip-menu-install",
         "--destination", str(installed)],
        evidence, "install", CONFIG["install_timeout_seconds"],
    )
    result.check_returncode()
    return installed / CONFIG["model_binary"]


def build(compiler, linker, workspace, evidence, extra_flags=(), extra_objects=()):
    for source_key, object_key, extra in (
        ("guest_source", "guest_object", ["-mgeneral-regs-only"]),
        ("guest_start", "start_object", []),
    ):
        result = execute(
            [compiler, *CONFIG["compiler_flags"], *extra_flags, *extra, "-c", str(ROOT / CONFIG[source_key]),
             "-o", str(workspace / CONFIG[object_key])],
            evidence, object_key, CONFIG["build_timeout_seconds"],
        )
        result.check_returncode()
    result = execute(
        [compiler, "-E", "-P", "-x", "c", str(ROOT / CONFIG["guest_linker_source"]),
         "-o", str(workspace / CONFIG["guest_linker"])],
        evidence, "linker-script", CONFIG["build_timeout_seconds"],
    )
    result.check_returncode()
    result = execute(
        [linker, "-T", str(workspace / CONFIG["guest_linker"]),
         str(workspace / CONFIG["start_object"]), str(workspace / CONFIG["guest_object"]),
         *map(str, extra_objects),
         "-o", str(workspace / CONFIG["guest_elf"])],
        evidence, "link", CONFIG["build_timeout_seconds"],
    )
    result.check_returncode()
    guest = workspace / CONFIG["guest_elf"]
    shutil.copy2(guest, evidence / CONFIG["guest_elf"])
    return guest


def inspect_model(model, evidence):
    version = execute([str(model), "--version"], evidence, "model-version", CONFIG["timeout_seconds"])
    version.check_returncode()
    if CONFIG["model_version"] not in version.stdout:
        raise ValueError(CONFIG["model_version_error"])
    execute([str(model), "--list-params"], evidence, "model-parameters",
            CONFIG["timeout_seconds"]).check_returncode()


def model_command(model, guest):
    command = [str(model), "--application", str(guest)]
    for name, value in CONFIG["model_parameters"].items():
        command += ["-C", f"{name}={value}"]
    return command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", default="clang-18")
    parser.add_argument("--linker", default="ld.lld-18")
    parser.add_argument("--build-only", action="store_true")
    args = parser.parse_args()
    workspace = Path(CONFIG["workspace_directory"]).resolve()
    evidence = Path(CONFIG["evidence_directory"]).resolve()
    workspace.mkdir(exist_ok=True)
    evidence.mkdir(exist_ok=True)
    provenance = {
        "workflow_commit": os.environ.get("GITHUB_SHA"),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "workflow_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "runner_arch": platform.machine(),
        "model_sha256": CONFIG["model_sha256"],
        "model_parameters": CONFIG["model_parameters"],
        "scope": CONFIG["scope"],
        "source_sha256": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in ROOT.iterdir() if path.is_file()
        },
    }
    (evidence / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    report_path = evidence / CONFIG["report"]
    report_path.write_text(json.dumps({"passed": False, "status": "not-executed"}) + "\n")
    guest = build(args.compiler, args.linker, workspace, evidence)
    if args.build_only:
        print("Guest compiled; execution and CPA2 capability remain unverified")
        return
    model = prepare(workspace, evidence)
    inspect_model(model, evidence)
    result = execute(model_command(model, guest), evidence, "guest", CONFIG["timeout_seconds"])
    report = assess(result.stdout, result.returncode)
    report["model_returncode"] = result.returncode
    report["guest_sha256"] = hashlib.sha256(guest.read_bytes()).hexdigest()
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
