#!/usr/bin/env python3
"""Compile unchanged batch exports into one bounded qualification guest."""

import hashlib
import json
import os
import shutil
import time

import run


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def render_entry(grouped, batch_count):
    declarations, entries, counts = [], [], []
    for index in range(batch_count):
        entry = grouped["entry_name"].format(index=index)
        count = grouped["count_name"].format(index=index)
        declarations.append(grouped["declaration"].format(entry=entry, count=count))
        entries.append(grouped["entry_call"].format(entry=entry))
        counts.append(grouped["count_call"].format(count=count))
    return grouped["wrapper"].format(
        declarations="".join(declarations), entries="".join(entries),
        counts=grouped["count_separator"].join(counts))


def execute(args, profile, config, report_origin, definitions, assess):
    root = args.output.resolve()
    root.mkdir()
    tools = root / definitions["tools_directory"]
    evidence = root / definitions["evidence_directory"]
    inputs = evidence / definitions["input_directory"]
    tools.mkdir()
    evidence.mkdir()
    inputs.mkdir()
    shutil.copy2(args.test_report, inputs / definitions["test_report_file"])
    files = {route["file"] for route in definitions["routes"]}
    files.add(definitions["harness_file"])
    batches = profile["artifact_batches"]
    for batch in batches:
        destination = inputs / batch
        destination.mkdir()
        for filename in sorted(files):
            shutil.copy2(args.artifacts / batch / filename, destination / filename)
    headers = tools / definitions["headers_directory"]
    headers.mkdir()
    for name, contents in definitions["headers"].items():
        (headers / name).write_text(contents)
    flags = [*definitions["generated_flags"], definitions["headers_include_flag"],
             str(headers)]
    provenance = {
        "neverd_revision": args.neverd_revision,
        "input_export_origin": report_origin,
        "input_batches": batches,
        "input_sha256": {
            path.relative_to(inputs).as_posix(): digest(path)
            for path in sorted(inputs.rglob("*")) if path.is_file()
        },
        "environment_source_sha256": {
            path.name: digest(path) for path in run.ROOT.iterdir() if path.is_file()
        },
        "workflow_commit": os.environ.get("GITHUB_SHA"),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "generated_header_sha256": {path.name: digest(path) for path in headers.iterdir()},
        "model_archive_sha256": run.CONFIG["model_sha256"],
        "model_parameters": config["model_parameters"],
        "scope": profile["scope"], "profile": args.profile,
    }
    (evidence / definitions["provenance_file"]).write_text(
        json.dumps(provenance, indent=2) + "\n")
    summary = {"passed": False, "neverd_revision": args.neverd_revision,
               "profile": args.profile, "results": []}

    def save():
        (evidence / definitions["summary_file"]).write_text(
            json.dumps(summary, indent=2) + "\n")

    save()
    model = run.prepare(tools, evidence)
    run.inspect_model(model, evidence)
    for label, executable in (("compiler-version", args.compiler),
                              ("linker-version", args.linker)):
        run.execute([executable, "--version"], evidence, label,
                    run.CONFIG["build_timeout_seconds"]).check_returncode()
    harness_objects = []
    grouped = definitions["grouped"]
    for index, batch in enumerate(batches):
        entry = grouped["entry_name"].format(index=index)
        count = grouped["count_name"].format(index=index)
        harness = (inputs / batch / definitions["harness_file"]).read_text()
        if harness.count(definitions["main_token"]) != 1:
            raise ValueError(definitions["errors"]["harness"])
        harness = harness.replace(definitions["main_token"],
                                  grouped["main_replacement"].format(entry=entry))
        harness += grouped["count_function"].format(count=count)
        source = tools / grouped["harness_source"].format(index=index)
        source.write_text(harness)
        output = tools / grouped["harness_object"].format(index=index)
        run.execute([args.compiler, *run.CONFIG["compiler_flags"], *flags,
                     "-c", str(source), "-o", str(output)], evidence,
                    grouped["harness_compile"].format(index=index),
                    run.CONFIG["build_timeout_seconds"]).check_returncode()
        harness_objects.append(output)
    source = tools / grouped["entry_source"]
    source.write_text(render_entry(grouped, len(batches)))
    output = tools / grouped["entry_object"]
    run.execute([args.compiler, *run.CONFIG["compiler_flags"], *flags,
                 "-c", str(source), "-o", str(output)], evidence,
                grouped["entry_compile"],
                run.CONFIG["build_timeout_seconds"]).check_returncode()
    harness_objects.append(output)
    for route in definitions["routes"]:
        work = tools / route["name"]
        observations = evidence / route["name"]
        work.mkdir()
        observations.mkdir()
        projections = []
        for index, batch in enumerate(batches):
            projection = work / grouped["projection_object"].format(index=index)
            if route["compile_c"]:
                run.execute([args.compiler, *run.CONFIG["compiler_flags"], *flags,
                             route["optimization"], "-c",
                             str(inputs / batch / route["file"]), "-o",
                             str(projection)], observations,
                            grouped["projection_compile"].format(index=index),
                            run.CONFIG["build_timeout_seconds"]).check_returncode()
            else:
                shutil.copy2(inputs / batch / route["file"], projection)
            projections.append(projection)
        guest = run.build(args.compiler, args.linker, work, observations,
                          profile["guest_flags"], [*harness_objects, *projections])
        start = time.monotonic()
        result = run.execute(run.model_command(model, guest, config), observations,
                             "guest", run.CONFIG["timeout_seconds"])
        report = assess(result.stdout, result.returncode, profile)
        report.update(route=route["name"], model_returncode=result.returncode,
                      seconds=round(time.monotonic() - start, 3),
                      guest_sha256=digest(guest))
        (observations / run.CONFIG["report"]).write_text(
            json.dumps(report, indent=2) + "\n")
        summary["results"].append(report)
        save()
        print(json.dumps(report), flush=True)
        if not report["passed"]:
            raise SystemExit(definitions["errors"]["matrix"])
    summary["passed"] = True
    save()
