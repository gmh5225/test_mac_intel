#!/usr/bin/env python3
"""Replay the source-bound NeverD host against the runner's compiler and dyld."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from xml.etree import ElementTree

POLICY = json.loads(Path(__file__).with_name("Replay.def").read_text())
SOURCE = Path(POLICY["source"]).resolve()
sys.path.insert(0, str(SOURCE / "scripts"))
import verify_arm64e_native as native


def main():
    output = Path(POLICY["evidence"]).resolve()
    output.mkdir()
    report = {"passed": False, "source_revision": POLICY["source_revision"],
              "cold_source_build": False, "native_apple_cpta_qualified": False}
    try:
        if native.provenance()["source_revision"] != POLICY["source_revision"]:
            raise ValueError(POLICY["errors"]["source"])
        subprocess.run(POLICY["runtime_command"], check=True, timeout=POLICY["runtime_timeout"])
        subprocess.run([sys.executable, *POLICY["probe_args"], str(output / POLICY["probe"])],
                       check=True, cwd=SOURCE)
        probe = json.loads((output / POLICY["probe"] / POLICY["probe_report"]).read_text())
        if not (probe["native_pac_qualified"] and probe["compiler_original_call_unwind_qualified"]
                and probe["source_revision"] == POLICY["source_revision"]):
            raise ValueError(POLICY["errors"]["probe"])
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            swift = POLICY["swift_error_control"]
            definition = directory / swift["definition_name"]
            caller = directory / swift["caller_name"]
            executable = directory / swift["binary_name"]
            definition.write_text(swift["definition"])
            caller.write_text(swift["caller"])
            results = {}
            for level in swift["optimizations"]:
                subprocess.run([swift["compiler"], swift["target_option"], swift["target"], level,
                                *swift["compile_options"], definition, caller, swift["output_option"],
                                executable], check=True)
                disassembly = subprocess.check_output([*swift["disassembly"], executable], text=True)
                if swift["error_register"] not in disassembly:
                    raise ValueError(POLICY["errors"]["swift_error"])
                subprocess.run([executable], check=True)
                results[level] = {"native_exit_status": 0, "sha256": native.digest(executable)}
            report["compiler_swift_error"] = results
            subprocess.run([arg.format_map(POLICY) for arg in POLICY["download"]],
                           check=True, cwd=directory)
            archive = directory / POLICY["asset"]
            if native.digest(archive) != POLICY["asset_sha256"]:
                raise ValueError(POLICY["errors"]["archive"])
            with tarfile.open(archive) as contents:
                contents.extractall(directory, filter="data")
            manifest = json.loads((directory / POLICY["manifest"]).read_text())
            binary = directory / POLICY["host"]
            if (native.digest(binary) != manifest["binary_sha256"]
                    or manifest["source_revision"] != POLICY["source_revision"]
                    or manifest["llvm_revision"] != POLICY["llvm_revision"]
                    or manifest["llvm_prebuilt"]
                    or any(native.digest(SOURCE / path) != digest
                           for path, digest in manifest["source_sha256"].items())):
                raise ValueError(POLICY["errors"]["identity"])
            native.save(output / POLICY["manifest"], manifest)
            xml = output / POLICY["test_xml"]
            env = dict(os.environ, **POLICY["execute_env"])
            proc = subprocess.run([str(binary), POLICY["filter"],
                                   POLICY["xml_option"] + str(xml)], env=env,
                                  text=True, capture_output=True, timeout=POLICY["test_timeout"])
            (output / POLICY["test_output"]).write_text(proc.stdout + proc.stderr)
            proc.check_returncode()
            tree = ElementTree.parse(xml).getroot()
            cases = tree.findall(".//testcase")
            expected = {*POLICY["leaf_cases"], POLICY["async_case"], *POLICY["system_cases"]}
            if (len(cases) != len(expected) or {c.get("name") for c in cases} != expected
                    or any(c.find(tag) is not None for c in cases
                           for tag in ("failure", "skipped", "error"))):
                raise ValueError(POLICY["errors"]["case"])
            by_case = {c.get("name"): {el.get("name"): el.get("value")
                                       for el in c.findall("properties/property")}
                       for c in cases}
            interrupted = by_case[POLICY["async_case"]]
            if (int(interrupted["native_interrupted_frames"]) != POLICY["async_count"]
                    or int(interrupted[POLICY["parent_count_property"]]) != POLICY["async_count"]):
                raise ValueError(POLICY["errors"]["async"])
            rows = {}
            for kind in ("original_signal_rows", "published_signal_rows"):
                values = [int(v) for v in interrupted[kind].split()]
                width = 1 + len(POLICY["expected_samples"][0])
                if len(values) != width * len(POLICY["expected_samples"]):
                    raise ValueError(POLICY["errors"]["async"])
                rows[kind] = [values[i:i+width] for i in range(0, len(values), width)]
                if any(pc < 0 or pc % POLICY["alignment"] or state != want
                       for (pc, *state), want in zip(rows[kind], POLICY["expected_samples"])):
                    raise ValueError(POLICY["errors"]["async"])
            report["interrupted"] = rows
            report["authenticated_parent_frames"] = int(interrupted[POLICY["parent_count_property"]])
            programs = {name: by_case[name] for name in POLICY["system_cases"]}
            for name, properties in programs.items():
                if (int(properties["native_exit_status"]) != POLICY["system_cases"][name]
                        or int(properties["executed_native_images"]) != POLICY["image_count"]
                        or int(properties["original_entry"]) == int(properties["published_entry"])
                        or properties["original_sha256"] == properties["published_sha256"]
                        or properties["system_slice_sha256"] == properties["unsigned_input_sha256"]):
                    raise ValueError(POLICY["errors"]["system"])
            report["programs"] = programs
            leaves = {name: by_case[name] for name in POLICY["leaf_cases"]}
            for properties in leaves.values():
                if (int(properties["executed_native_images"]) != POLICY["image_count"]
                        or int(properties["caller_authenticated_call_sites"]) < POLICY["entry_count"]
                        or properties["original_sha256"] == properties["published_sha256"]):
                    raise ValueError(POLICY["errors"]["case"])
            if leaves[POLICY["tail_case"]].get(POLICY["tail_property"]) not in ("1", "true"):
                raise ValueError(POLICY["errors"]["case"])
            report.update(host_sha256=native.digest(binary), results=leaves,
                          compiler=probe["environment"]["compiler"]["stdout"].splitlines()[0],
                          cpu=probe["environment"]["cpu"]["stdout"].strip(),
                          sdk=probe["environment"]["sdk"]["stdout"].strip())
        report["passed"] = True
    finally:
        native.save(output / POLICY["report"], report)


if __name__ == "__main__":
    main()
