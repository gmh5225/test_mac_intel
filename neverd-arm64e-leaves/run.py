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
            if len(cases) != 1 or cases[0].get("name") != POLICY["test_name"] or any(
                    cases[0].find(tag) is not None for tag in ("failure", "skipped", "error")):
                raise ValueError(POLICY["errors"]["case"])
            properties = {el.get("name"): el.get("value")
                          for el in cases[0].findall("properties/property")}
            if (int(properties["executed_native_images"]) != POLICY["image_count"]
                    or int(properties["caller_authenticated_call_sites"]) < POLICY["entry_count"]
                    or properties["original_sha256"] == properties["published_sha256"]):
                raise ValueError(POLICY["errors"]["case"])
            report.update(host_sha256=native.digest(binary), results=properties,
                          compiler=probe["environment"]["compiler"]["stdout"].splitlines()[0],
                          cpu=probe["environment"]["cpu"]["stdout"].strip(),
                          sdk=probe["environment"]["sdk"]["stdout"].strip())
        report["passed"] = True
    finally:
        native.save(output / POLICY["report"], report)


if __name__ == "__main__":
    main()
