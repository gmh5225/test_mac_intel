#!/usr/bin/env python3
"""Execute actual NeverD call exports with controlled instruction PAC keys."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil

import run

ROOT = Path(__file__).resolve().parent
CONFIG = json.loads((ROOT / "CptaAuthenticatedCalls.def").read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_test_report(report, config=CONFIG):
    identities, exports = [], []
    valid = (report.get("tests") == len(config["test_report_cases"])
             and report.get("failures") == 0 and report.get("errors") == 0)
    for suite in report.get("testsuites", []):
        for case in suite.get("testsuite", []):
            identities.append(suite["name"] + "." + case["name"])
            valid = (valid and case.get("status") == "RUN"
                     and case.get("result") == "COMPLETED"
                     and not case.get("failures"))
            if config["artifact_property"] in case:
                exports.append(case[config["artifact_property"]])
    if (not valid or sorted(identities) != sorted(config["test_report_cases"])
            or len(exports) != config["export_count"]
            or any(not isinstance(value, str) or not value for value in exports)
            or len(set(exports)) != 1):
        raise ValueError(config["errors"]["input"])
    return exports[0]


def allows_alternate_syndrome(route, level, config=CONFIG):
    return route in config["alternate_routes"] and level in config["alternate_levels"]


def configuration(route, feature, el0, profile=CONFIG):
    config = run.el0_configuration() if el0 else copy.deepcopy(run.CONFIG)
    config["scope"] = profile["scope"]
    config["expected_passed_cases"] = profile["el0_checks" if el0 else "el1_checks"]
    config["model_parameters"] = dict(config["model_parameters"])
    config["model_parameters"][profile["feature_parameter"]] = str(feature["parameter"])
    gates = {**profile["required_gates"], profile["level_record"]: feature["level"]}
    alternate = allows_alternate_syndrome(route, feature["level"], profile)
    for mode in profile["modes"]:
        gates[profile["memory_record"].format(mode=mode)] = 0
        gates[profile["fault_record"].format(mode=mode)] = profile["faults_per_mode"]
        gates[profile["difference_record"].format(mode=mode)] = (
            profile["faults_per_mode"] if alternate else 0)
    config["required_records"] = list(dict.fromkeys(config["required_records"] + list(gates)))
    config["gate_values"] = {**config["gate_values"], **gates}
    return config


def assess(transcript, returncode, route, feature, el0, config=CONFIG):
    report = run.assess(transcript, returncode, configuration(route, feature, el0, config))
    report[config["qualification_key"]] = report["passed"]
    report["original_exception_class_qualified"] = (
        report["passed"] and not allows_alternate_syndrome(route, feature["level"], config))
    return report


def prepare_elf(source, target, case, logs, config):
    rename = config["symbol"] + "=" + config["renamed_symbol"].format(**case)
    run.execute([config["objcopy"], "--redefine-sym", rename,
                 str(source), str(target)], logs, target.stem,
                run.CONFIG["build_timeout_seconds"]).check_returncode()


def main(config=CONFIG, prepare_object=prepare_elf, prepare_fixtures=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--test-report", type=Path, required=True)
    parser.add_argument("--neverd-revision", required=True)
    parser.add_argument("--output", type=Path, default=Path(config["output_directory"]))
    parser.add_argument("--model", type=Path)
    args = parser.parse_args()
    if (len(args.neverd_revision) != config["revision_length"]
            or any(c not in config["revision_digits"] for c in args.neverd_revision)):
        raise ValueError(config["errors"]["revision"])
    origin = validate_test_report(json.loads(args.test_report.read_text()), config)
    output = args.output.resolve()
    output.mkdir()
    inputs, evidence = output / "input", output / "evidence"
    inputs.mkdir()
    evidence.mkdir()
    shutil.copy2(args.test_report, inputs / "tests.json")
    for case in config["cases"]:
        directory = inputs / case["directory"]
        directory.mkdir()
        files = config["source_files"] + [route + ".o" for route in config["routes"]]
        for name in files:
            shutil.copy2(args.artifacts / case["directory"] / name, directory / name)
    provenance = {
        "neverd_revision": args.neverd_revision, "input_export_origin": origin,
        "input_sha256": {path.relative_to(inputs).as_posix(): digest(path)
                         for path in sorted(inputs.rglob("*")) if path.is_file()},
        "environment_source_sha256": {path.name: digest(path)
                                      for path in sorted(ROOT.iterdir()) if path.is_file()},
        "model_archive_sha256": run.CONFIG["model_sha256"],
        "scope": config["scope"],
    }
    (evidence / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    tools = output / "tools"
    tools.mkdir()
    model = args.model.resolve() if args.model else run.prepare(tools, evidence)
    provenance["model_supplied"] = args.model is not None
    provenance["model_binary_sha256"] = digest(model)
    (evidence / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    run.inspect_model(model, evidence)
    for executable in (config["compiler"], config["linker"], config["objcopy"]):
        run.execute([executable, "--version"], evidence, executable,
                    run.CONFIG["build_timeout_seconds"]).check_returncode()
    summary = {"passed": False, "neverd_revision": args.neverd_revision,
               "scope": config["scope"], "results": []}
    summary_path = evidence / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    for route in config["routes"]:
        for feature in config["features"]:
            for el0 in (False, True):
                label = f'{route}-pac{feature["parameter"]}-el{0 if el0 else 1}'
                work = output / label
                work.mkdir()
                logs = work / "evidence"
                logs.mkdir()
                objects = []
                for case in config["cases"]:
                    source = inputs / case["directory"] / (route + ".o")
                    target = work / f'projected-{case["index"]}.o'
                    prepare_object(source, target, case, logs, config)
                    objects.append(target)
                flags = [*config["guest_flags"],
                         config["level_flag"].format(**feature)]
                if el0:
                    flags.append(config["el0_flag"])
                if route != config["routes"][0]:
                    flags.append(config["source_flag"])
                if prepare_fixtures:
                    prepare_fixtures(work, config)
                for fixture in config["fixtures"]:
                    source = (work if fixture.get("generated") else ROOT) / fixture["file"]
                    target = work / (source.name + ".o")
                    run.execute([config["compiler"], *run.CONFIG["compiler_flags"],
                                 *flags, "-I", str(ROOT), "-x", fixture["language"],
                                 "-c", str(source), "-o", str(target)], logs,
                                source.name, run.CONFIG["build_timeout_seconds"]).check_returncode()
                    objects.append(target)
                guest = run.build(config["compiler"], config["linker"], work,
                                  logs, flags, objects)
                model_config = configuration(route, feature, el0, config)
                result = run.execute(run.model_command(model, guest, model_config), logs,
                                     "guest", run.CONFIG["timeout_seconds"], os.environ.copy())
                report = assess(result.stdout, result.returncode, route, feature, el0, config)
                report.update(route=route, level=feature["level"], el0=el0,
                              guest_sha256=digest(guest), model_parameters=model_config["model_parameters"])
                (logs / "report.json").write_text(json.dumps(report, indent=2) + "\n")
                summary["results"].append(report)
                summary_path.write_text(json.dumps(summary, indent=2) + "\n")
                print(label, report["passed"], flush=True)
    summary["passed"] = all(row["passed"] for row in summary["results"])
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    if not summary["passed"]:
        raise RuntimeError(config["errors"]["matrix"])


if __name__ == "__main__":
    main()
