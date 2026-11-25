"""Build pinned r6 exporter inputs and check signed images on Xcode 27."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

CONFIG = json.loads(Path(__file__).with_name("Projections.def").read_text())


def resolve():
    branch = os.environ.get(CONFIG["source_env"]) or CONFIG["source_branch"]
    ref = CONFIG["ref"].format(branch=branch)
    subprocess.run(["git", "check-ref-format", ref], check=True)
    revision, actual = subprocess.check_output(
        ["git", "ls-remote", "--exit-code", CONFIG["remote"], ref], text=True).split()
    if actual != ref:
        raise ValueError(CONFIG["revision_error"])
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        print(f"revision={revision}", file=stream)
        print(f"repository={CONFIG['repository']}", file=stream)


def check_acceptance(source, output, policy, report, fields, revision, code):
    native = json.loads((source / CONFIG["native_policy"]).read_text())
    gate = native["x1_qualification"]
    control_path = output / gate["complete_mode"] / native["report_name"]
    controls = json.loads(control_path.read_text())
    receipt = report[policy["control_receipt"]]
    qualified = controls[gate["complete_key"]]
    model = json.loads((source / CONFIG["model_policy"]).read_text())
    labels = {"-".join((family, route, opt)) for family in model["cases"]
              for route in (*model["routes"], *model["backend_objects"]) for opt in model["optimizations"]}
    if set(report["images"]) != labels or report["all_executed"] != (fields["executed"] == len(labels)):
        raise ValueError(CONFIG["link_error"])
    passed = qualified and report["all_executed"]
    status = native["passed" if passed else "unavailable"]
    if (receipt["report"] != control_path.relative_to(output).as_posix() or
            receipt["sha256"] != hashlib.sha256(control_path.read_bytes()).hexdigest() or
            controls["source_revision"] != revision or qualified != report[gate["complete_key"]] or
            controls["status"] != native["passed" if qualified else "unavailable"] or
            report[policy["qualified_key"]] != passed or report["status"] != status or
            code != native["exit_codes"][status]):
        raise ValueError(CONFIG["acceptance_error"])
    return {"status": status, "code": code, "controls": qualified}


def run(stage, source, work):
    revision = subprocess.check_output(CONFIG["revision_command"], cwd=source, text=True).strip()
    if revision != os.environ[CONFIG["revision_env"]]:
        raise ValueError(CONFIG["revision_error"])
    build = work / CONFIG["build_dir"]
    inputs = work / CONFIG["inputs_dir"]
    output = work / CONFIG["report_dir"]
    paths = {**CONFIG, "build": build, "inputs": inputs, "output": output}

    def args(key):
        return [value.format(**paths) for value in CONFIG[key]]

    policy = json.loads((source / CONFIG["verifier"]).with_suffix(".def").read_text())
    verifier = [sys.executable, CONFIG["verifier"]]
    if stage == CONFIG["build"]:
        if "build" in policy:
            subprocess.run([*verifier, policy["build"], policy["output"], inputs], cwd=source, check=True)
            return
        build.mkdir()
        try:
            subprocess.run(CONFIG["dependencies"], cwd=source, check=True)
            subprocess.run(args("configure"), cwd=source, check=True)
            subprocess.run([sys.executable, *args("compile")], cwd=source, check=True)
            subprocess.run([*verifier, *args("export_args")], cwd=source, check=True)
        finally:
            shutil.rmtree(build)
        return
    if stage != CONFIG["check"]:
        raise ValueError(stage)

    strict = "require_native" in policy
    command = [*verifier, *args("check_args")]
    if strict:
        command.append(policy["require_native"])
    result = subprocess.run(command, cwd=source, check=not strict)
    path = output / CONFIG["report"]
    report = json.loads(path.read_text())
    if report["source_revision"] != revision:
        raise ValueError(CONFIG["revision_error"])
    if not report["all_linked"]:
        raise ValueError(CONFIG["link_error"])
    hardware = subprocess.check_output(CONFIG["cpu"], text=True).strip()
    images = list(report["images"].values())
    fields = {"hardware": hardware, "revision": revision, "images": len(images),
              "executed": sum(item["execution"] == CONFIG["compared"] for item in images)}
    summary = CONFIG["summary"]
    if strict:
        fields.update(check_acceptance(source, output, policy, report, fields, revision, result.returncode))
        host = {**fields, "report_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        (output / CONFIG["host_report"]).write_text(json.dumps(host, indent=2) + "\n")
        summary = CONFIG["acceptance_summary"]
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
        print(summary.format(**fields), file=stream)


if __name__ == "__main__":
    if sys.argv[1:] == [CONFIG["resolve"]]:
        resolve()
    else:
        run(sys.argv[1], Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve())
