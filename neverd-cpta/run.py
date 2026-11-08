#!/usr/bin/env python3
"""Prepare and execute the pinned, capability-gated Arm CPA2 guest."""

import argparse
from contextlib import contextmanager, ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent
CONFIG = json.loads((ROOT / "CptaEnvironment.def").read_text())
LIFECYCLE = json.loads((ROOT / "CptaArtifactLifecycle.def").read_text())


def remove_product(path):
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


@contextmanager
def artifact_session(root):
    """Own one reusable scratch slot; inputs and evidence live outside it."""
    root.mkdir(parents=True, exist_ok=True)
    with (root / LIFECYCLE["lock"]).open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        marker = root / LIFECYCLE["marker"]
        if marker.exists():
            if json.loads(marker.read_text()) != {"owner": LIFECYCLE["owner"]}:
                raise ValueError(LIFECYCLE["unknown_output"])
        else:
            if any(path.name != LIFECYCLE["lock"] for path in root.iterdir()):
                raise ValueError(LIFECYCLE["unknown_output"])
            marker.write_text(json.dumps({"owner": LIFECYCLE["owner"]}) + "\n")
        scratch = root / LIFECYCLE["scratch"]
        # The exclusive lock proves that a previous writer no longer owns this
        # slot, including after SIGKILL. Never scan neighbouring run directories.
        recovered = scratch.exists()
        remove_product(scratch)
        scratch.mkdir()
        previous = signal.getsignal(signal.SIGTERM)

        def terminate(signum, frame):
            raise SystemExit(LIFECYCLE["terminated"])

        signal.signal(signal.SIGTERM, terminate)
        completed = False
        try:
            yield scratch
            completed = True
        finally:
            signal.signal(signal.SIGTERM, previous)
            files = [path for path in scratch.rglob("*") if path.is_file()]
            receipt = {"completed": completed, "recovered_interrupted_scratch": recovered,
                       "removed_files": len(files),
                       "removed_bytes": sum(path.stat().st_size for path in files)}
            remove_product(scratch)
            (root / LIFECYCLE["lifecycle_receipt"]).write_text(
                json.dumps(receipt, indent=2) + "\n")


def copy_input(source, target, scratch):
    """Reuse identical formal inputs and never overwrite an earlier baseline."""
    if target.exists():
        if source.read_bytes() != target.read_bytes():
            raise ValueError(LIFECYCLE["changed_input"])
        return
    temporary = scratch / LIFECYCLE["copy_temporary"]
    shutil.copy2(source, temporary)
    temporary.replace(target)


@contextmanager
def model_session(parent, evidence, supplied=None):
    """Keep one verified model installation under the same lock as its users."""
    if supplied is not None:
        yield supplied.resolve()
        return
    cache = parent / LIFECYCLE["cache_directory"]
    with artifact_session(cache) as scratch:
        installed = cache / CONFIG["model_install_directory"]
        model = installed / CONFIG["model_binary"]
        receipt = cache / LIFECYCLE["model_receipt"]
        previous = json.loads(receipt.read_text()) if receipt.exists() else {}
        if (previous.get("archive_sha256") != CONFIG["model_sha256"]
                or not model.is_file()
                or previous.get("binary_sha256") != hashlib.sha256(model.read_bytes()).hexdigest()):
            remove_product(installed)
            prepared = prepare(scratch, evidence)
            digest = hashlib.sha256(prepared.read_bytes()).hexdigest()
            (scratch / CONFIG["model_install_directory"]).replace(installed)
            receipt.write_text(json.dumps({"archive_sha256": CONFIG["model_sha256"],
                                           "binary_sha256": digest}, indent=2) + "\n")
        yield model


def el0_configuration():
    profile = CONFIG["el0_control"]
    return {
        **CONFIG, "scope": profile["scope"],
        "expected_passed_cases": profile["expected_passed_cases"],
        "required_records": CONFIG["required_records"] + list(profile["gate_values"]),
        "gate_values": {**CONFIG["gate_values"], **profile["gate_values"]},
    }


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
    log = evidence / f"{label}.log"
    # Stream diagnostics to their final file so a timeout or interruption does
    # not discard the output buffered by subprocess.run.
    with log.open("w") as output:
        result = subprocess.run(
            command, text=True, stdout=output, stderr=subprocess.STDOUT,
            timeout=timeout, env=env, check=False,
        )
    result.stdout = log.read_text(errors="replace")
    return result


def prepare(workspace, evidence):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("This pinned official FVP package requires x86_64 Linux")
    try:
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
        installed = workspace / CONFIG["model_install_directory"]
        result = execute(
            ["sh", str(workspace / CONFIG["model_installer"]),
             "--i-agree-to-the-contained-eula", "--no-interactive", "--skip-menu-install",
             "--destination", str(installed)],
            evidence, "install", CONFIG["install_timeout_seconds"],
        )
        result.check_returncode()
        return installed / CONFIG["model_binary"]
    finally:
        for key in ("model_archive", "model_installer"):
            remove_product(workspace / CONFIG[key])


def remove_model_tools(workspace):
    """Drop only this run's reproducible model package and installation."""
    for name in (CONFIG["model_archive"], CONFIG["model_installer"],
                 CONFIG["model_install_directory"]):
        path = workspace / name
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)


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
    retained = evidence / CONFIG["guest_elf"]
    guest.replace(retained)
    return retained


def inspect_model(model, evidence):
    version = execute([str(model), "--version"], evidence, "model-version", CONFIG["timeout_seconds"])
    version.check_returncode()
    if CONFIG["model_version"] not in version.stdout:
        raise ValueError(CONFIG["model_version_error"])
    execute([str(model), "--list-params"], evidence, "model-parameters",
            CONFIG["timeout_seconds"]).check_returncode()


def model_command(model, guest, config=None):
    config = CONFIG if config is None else config
    command = [str(model), "--application", str(guest)]
    for name, value in config["model_parameters"].items():
        command += ["-C", f"{name}={value}"]
    return command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", default="clang-18")
    parser.add_argument("--linker", default="ld.lld-18")
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument(CONFIG["el0_option"], action="store_true")
    args = parser.parse_args()
    config = el0_configuration() if args.el0_control else CONFIG
    flags = CONFIG["el0_control"]["flags"] if args.el0_control else []
    workspace = Path(CONFIG["workspace_directory"]).resolve()
    evidence = Path(CONFIG["evidence_directory"]).resolve()
    evidence.mkdir(exist_ok=True)
    provenance = {
        "workflow_commit": os.environ.get("GITHUB_SHA"),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "workflow_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "runner_arch": platform.machine(),
        "model_sha256": CONFIG["model_sha256"],
        "model_parameters": CONFIG["model_parameters"],
        "scope": config["scope"],
        "guest_flags": flags,
        "source_sha256": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in ROOT.iterdir() if path.is_file()
        },
    }
    (evidence / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    report_path = evidence / CONFIG["report"]
    report_path.write_text(json.dumps({"passed": False, "status": "not-executed"}) + "\n")
    with artifact_session(workspace) as scratch, ExitStack() as stack:
        guest = build(args.compiler, args.linker, scratch, evidence, flags)
        if args.build_only:
            print("Guest compiled; execution and CPA2 capability remain unverified")
            return
        model = stack.enter_context(model_session(workspace.parent, evidence))
        inspect_model(model, evidence)
        result = execute(model_command(model, guest), evidence, "guest", CONFIG["timeout_seconds"])
        report = assess(result.stdout, result.returncode, config)
        report["model_returncode"] = result.returncode
        report["guest_sha256"] = hashlib.sha256(guest.read_bytes()).hexdigest()
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
        if not report["passed"]:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
