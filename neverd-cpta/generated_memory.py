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


def select_profile(name):
    profile = copy.deepcopy(CONFIG)
    if name != CONFIG["default_profile"]:
        if name not in CONFIG["profiles"]:
            raise ValueError(CONFIG["errors"]["profile"])
        profile.update(CONFIG["profiles"][name])
    return profile


def configuration(profile=None):
    profile = CONFIG if profile is None else profile
    config = copy.deepcopy(run.CONFIG)
    config["scope"] = profile["scope"]
    config["expected_passed_cases"] = profile["expected_passed_cases"]
    config["required_records"] += list(profile["generated_gate_values"])
    config["gate_values"].update(profile["generated_gate_values"])
    config["model_parameters"].update(profile.get("model_parameters", {}))
    return config


def assess(transcript, returncode, profile=None):
    profile = CONFIG if profile is None else profile
    report = run.assess(transcript, returncode, configuration(profile))
    report[profile["qualification_key"]] = report["passed"]
    return report


def validate_test_report(report, profile=None):
    profile = CONFIG if profile is None else profile
    expected = profile["test_report_cases"]
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
            if profile["artifact_property"] in case:
                exports.append(case[profile["artifact_property"]])
    if (not valid or sorted(actual) != sorted(expected) or len(exports) != 1
            or not isinstance(exports[0], str) or not exports[0]):
        raise ValueError(CONFIG["errors"]["input_tests"])
    return exports[0]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compile_freestanding_runtime(args, tools, evidence, flags, definitions):
    runtime = definitions["freestanding_runtime"]
    source = tools / runtime["source_file"]
    source.write_text(runtime["source"])
    output = tools / runtime["object_file"]
    run.execute([args.compiler, *run.CONFIG["compiler_flags"], *flags,
                 *runtime["flags"], "-c", str(source), "-o", str(output)],
                evidence, runtime["compile_label"],
                run.CONFIG["build_timeout_seconds"]).check_returncode()
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--test-report", required=True, type=Path)
    parser.add_argument("--neverd-revision", required=True)
    parser.add_argument("--compiler", default=CONFIG["compiler"])
    parser.add_argument("--linker", default=CONFIG["linker"])
    parser.add_argument("--output", type=Path, default=Path(CONFIG["output_directory"]))
    parser.add_argument("--profile", default=CONFIG["default_profile"],
                        choices=[CONFIG["default_profile"], *CONFIG["profiles"]])
    args = parser.parse_args()
    profile = select_profile(args.profile)
    config = configuration(profile)
    if (len(args.neverd_revision) != CONFIG["revision_hex_length"]
            or any(c not in CONFIG["revision_hex_digits"] for c in args.neverd_revision)):
        parser.error(CONFIG["errors"]["revision"])
    test_report = json.loads(args.test_report.read_text())
    export_origin = validate_test_report(test_report, profile)
    if profile.get("artifact_batches"):
        import grouped_memory
        return grouped_memory.execute(args, profile, config, export_origin,
                                      CONFIG, assess,
                                      compile_freestanding_runtime)
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
    headers = tools / CONFIG["headers_directory"]
    headers.mkdir()
    for name, contents in CONFIG["headers"].items():
        (headers / name).write_text(contents)
    generated_flags = [*CONFIG["generated_flags"], CONFIG["headers_include_flag"],
                       str(headers)]
    provenance = {
        "neverd_revision": args.neverd_revision,
        "input_export_origin": export_origin,
        "input_sha256": {p.name: digest(p) for p in inputs.iterdir()},
        "environment_source_sha256": {
            p.name: digest(p) for p in run.ROOT.iterdir() if p.is_file()
        },
        "workflow_commit": os.environ.get("GITHUB_SHA"),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "generated_header_sha256": {p.name: digest(p) for p in headers.iterdir()},
        "model_archive_sha256": run.CONFIG["model_sha256"],
        "model_parameters": config["model_parameters"],
        "scope": profile["scope"],
        "profile": args.profile,
    }
    (evidence / CONFIG["provenance_file"]).write_text(json.dumps(provenance, indent=2) + "\n")
    summary = {"passed": False, "neverd_revision": args.neverd_revision,
               "profile": args.profile, "results": []}

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
    (tools / CONFIG["harness_file"]).write_text(harness + profile["count_function"])
    harness_object = tools / CONFIG["harness_object"]
    run.execute(
        [args.compiler, *run.CONFIG["compiler_flags"], *generated_flags,
         "-c", str(tools / CONFIG["harness_file"]), "-o", str(harness_object)],
        evidence, "harness-compile", run.CONFIG["build_timeout_seconds"],
    ).check_returncode()
    runtime_object = compile_freestanding_runtime(args, tools, evidence,
                                                  generated_flags, CONFIG)
    for route in CONFIG["routes"]:
        work = tools / route["name"]
        observations = evidence / route["name"]
        work.mkdir()
        observations.mkdir()
        projection = work / CONFIG["projection_object"]
        if route["compile_c"]:
            run.execute(
                [args.compiler, *run.CONFIG["compiler_flags"], *generated_flags,
                 route["optimization"], "-c", str(inputs / route["file"]), "-o", str(projection)],
                observations, "projection-compile", run.CONFIG["build_timeout_seconds"],
            ).check_returncode()
        else:
            shutil.copy2(inputs / route["file"], projection)
        guest = run.build(args.compiler, args.linker, work, observations,
                          profile["guest_flags"], [harness_object, projection, runtime_object])
        start = time.monotonic()
        result = run.execute(run.model_command(model, guest, config), observations, "guest",
                             run.CONFIG["timeout_seconds"])
        report = assess(result.stdout, result.returncode, profile)
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
