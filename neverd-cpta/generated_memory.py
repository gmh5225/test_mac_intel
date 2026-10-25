#!/usr/bin/env python3
"""Execute actual, qualified NeverD immediate-memory exports in the Arm model."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import time

import run

CONFIG = json.loads((run.ROOT / "CptaGeneratedMemory.def").read_text())


def configuration():
    config = copy.deepcopy(run.CONFIG)
    config["scope"] = CONFIG["scope"]
    config["expected_passed_cases"] = CONFIG["expected_passed_cases"]
    config["required_records"] += list(CONFIG["generated_gate_values"])
    config["gate_values"].update(CONFIG["generated_gate_values"])
    return config


def assess(transcript, returncode):
    report = run.assess(transcript, returncode, configuration())
    report["explicit_immediate_memory_output_qualified"] = report["passed"]
    return report


def validate_test_report(report):
    expected = CONFIG["test_report_cases"]
    actual = []
    exports = []
    valid = (report.get("tests") == len(expected)
             and report.get("failures") == 0 and report.get("errors") == 0)
    for suite in report.get("testsuites", []):
        for case in suite.get("testsuite", []):
            actual.append(suite["name"] + "." + case["name"])
            valid = (valid and case.get("status") == "RUN"
                     and case.get("result") == "COMPLETED"
                     and not case.get("failures"))
            if CONFIG["artifact_property"] in case:
                exports.append(case[CONFIG["artifact_property"]])
    if (not valid or sorted(actual) != sorted(expected) or len(exports) != 1
            or not isinstance(exports[0], str) or not exports[0]):
        raise ValueError(CONFIG["errors"]["input_tests"])
    return exports[0]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--test-report", required=True, type=Path)
    parser.add_argument("--neverd-revision", required=True)
    parser.add_argument("--compiler", default=CONFIG["compiler"])
    parser.add_argument("--linker", default=CONFIG["linker"])
    parser.add_argument("--output", type=Path, default=Path(CONFIG["output_directory"]))
    args = parser.parse_args()
    if (len(args.neverd_revision) != CONFIG["revision_hex_length"]
            or any(c not in CONFIG["revision_hex_digits"] for c in args.neverd_revision)):
        parser.error(CONFIG["errors"]["revision"])
    test_report = json.loads(args.test_report.read_text())
    export_origin = validate_test_report(test_report)
    root = args.output.resolve()
    root.mkdir()
    tools = root / CONFIG["tools_directory"]
    evidence = root / CONFIG["evidence_directory"]
    inputs = evidence / CONFIG["input_directory"]
    tools.mkdir()
    evidence.mkdir()
    inputs.mkdir()
    shutil.copy2(args.test_report, inputs / CONFIG["test_report_file"])
    filenames = {route["file"] for route in CONFIG["routes"]}
    filenames.add(CONFIG["harness_file"])
    for name in sorted(filenames):
        shutil.copy2(args.artifacts / name, inputs / name)
    provenance = {
        "neverd_revision": args.neverd_revision,
        "input_export_origin": export_origin,
        "input_sha256": {p.name: digest(p) for p in inputs.iterdir()},
        "environment_source_sha256": {
            p.name: digest(p) for p in run.ROOT.iterdir() if p.is_file()
        },
        "workflow_commit": os.environ.get("GITHUB_SHA"),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "model_archive_sha256": run.CONFIG["model_sha256"],
        "model_parameters": run.CONFIG["model_parameters"],
        "scope": CONFIG["scope"],
    }
    (evidence / CONFIG["provenance_file"]).write_text(json.dumps(provenance, indent=2) + "\n")
    summary = {"passed": False, "neverd_revision": args.neverd_revision, "results": []}

    def save():
        (evidence / CONFIG["summary_file"]).write_text(json.dumps(summary, indent=2) + "\n")

    save()
    model = run.prepare(tools, evidence)
    run.inspect_model(model, evidence)
    for label, executable in (("compiler-version", args.compiler), ("linker-version", args.linker)):
        run.execute([executable, "--version"], evidence, label,
                    run.CONFIG["build_timeout_seconds"]).check_returncode()
    harness = (inputs / CONFIG["harness_file"]).read_text()
    if harness.count(CONFIG["main_token"]) != 1:
        raise ValueError(CONFIG["errors"]["harness"])
    harness = harness.replace(CONFIG["main_token"], CONFIG["main_replacement"])
    (tools / CONFIG["harness_file"]).write_text(harness + CONFIG["count_function"])
    harness_object = tools / CONFIG["harness_object"]
    run.execute(
        [args.compiler, *run.CONFIG["compiler_flags"], *CONFIG["generated_flags"],
         "-c", str(tools / CONFIG["harness_file"]), "-o", str(harness_object)],
        evidence, "harness-compile", run.CONFIG["build_timeout_seconds"],
    ).check_returncode()
    for route in CONFIG["routes"]:
        work = tools / route["name"]
        observations = evidence / route["name"]
        work.mkdir()
        observations.mkdir()
        projection = work / CONFIG["projection_object"]
        if route["compile_c"]:
            run.execute(
                [args.compiler, *run.CONFIG["compiler_flags"], *CONFIG["generated_flags"],
                 route["optimization"], "-c", str(inputs / route["file"]), "-o", str(projection)],
                observations, "projection-compile", run.CONFIG["build_timeout_seconds"],
            ).check_returncode()
        else:
            shutil.copy2(inputs / route["file"], projection)
        guest = run.build(args.compiler, args.linker, work, observations,
                          CONFIG["guest_flags"], [harness_object, projection])
        start = time.monotonic()
        result = run.execute(run.model_command(model, guest), observations, "guest",
                             run.CONFIG["timeout_seconds"])
        report = assess(result.stdout, result.returncode)
        report.update(route=route["name"], model_returncode=result.returncode,
                      seconds=round(time.monotonic() - start, 3), guest_sha256=digest(guest))
        (observations / run.CONFIG["report"]).write_text(json.dumps(report, indent=2) + "\n")
        summary["results"].append(report)
        save()
        print(json.dumps(report), flush=True)
        if not report["passed"]:
            raise SystemExit(CONFIG["errors"]["matrix"])
    summary["passed"] = True
    save()


if __name__ == "__main__":
    main()
