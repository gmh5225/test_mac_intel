"""Diagnose executable publication with an immutable locally built test host."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

POLICY = json.loads(Path(__file__).with_name("Replay.def").read_text())
sys.path.insert(0, str(Path(POLICY["source"]) / "scripts"))
import verify_arm64e_native as native


def main():
    root = Path(POLICY["evidence"]).resolve()
    root.mkdir()
    binary = root / POLICY["host"]
    archive = Path(POLICY["asset"])
    report = {"diagnostic_only": True, "passed": False,
              "source_revision": POLICY["source_revision"]}
    try:
        if native.provenance()["source_revision"] != POLICY["source_revision"]:
            raise ValueError(POLICY["source_mismatch"])
        subprocess.run([arg.format_map(POLICY) for arg in POLICY["download"]], check=True)
        if native.digest(archive) != POLICY["asset_sha256"]:
            raise ValueError(POLICY["asset_mismatch"])
        with tarfile.open(archive) as source:
            source.extractall(root, filter="data")
        manifest = json.loads((root / POLICY["manifest"]).read_text())
        if (manifest["source_revision"] != POLICY["source_revision"] or
                manifest["binary_sha256"] != native.digest(binary) or
                any(native.digest(native.ROOT / name) != digest
                    for name, digest in manifest["source_sha256"].items())):
            raise ValueError(POLICY["binary_mismatch"])
        report["manifest_sha256"] = native.digest(root / POLICY["manifest"])
        preflight = root / POLICY["preflight"]
        preflight.mkdir()
        control = native.probe(preflight)
        if control["status"] != native.POLICY["passed"]:
            raise ValueError(POLICY["probe_failed"])
        startup = root / POLICY["probe"]
        startup.mkdir()
        probe = native.probe(startup, startup=True, userspace_fixups=True)
        if probe["status"] != native.POLICY["passed"]:
            raise ValueError(POLICY["probe_failed"])
        build = root / POLICY["build"]
        build.mkdir()
        (build / POLICY["ctest_registry"]).write_text("".join(
            POLICY["test_definition"].format(case=case, binary=binary) +
            POLICY["test_properties"].format(case=case, test_timeout=POLICY["test_timeout"])
            for case in sorted(native.expected_cases() | native.expected_cases(True))))
        dylib = root / POLICY["dylib_installation"]
        dylib.mkdir()
        installed = native.run_installation(
            dylib, build, preflight / native.POLICY["report_name"],
            Path(POLICY["legacy_fixtures"]).resolve())
        if installed["status"] != native.POLICY["passed"]:
            raise ValueError(POLICY["installation_failed"])
        output = root / POLICY["installation"]
        output.mkdir()
        try:
            installed = native.run_installation(
                output, build, startup / native.POLICY["report_name"], executable=True)
        except ValueError:
            # Retain one exact failing specimen for load-command diagnosis.
            # This extra invocation never replaces the failed qualification.
            env = dict(os.environ, **native.POLICY["test_environment"])
            env[native.POLICY["artifact_environment"]] = str(root / POLICY["diagnostic_fixtures"])
            env[native.POLICY["executable_environment"]] = native.POLICY["executable_environment_value"]
            with native.OwnedProducts(root, False) as products:
                profile = native.startup_profile(products, root)
            result = subprocess.run([
                *profile["launcher"], str(binary),
                native.POLICY["gtest_prefix"] + POLICY["diagnostic_case"],
                POLICY["gtest_xml_prefix"] + str(root / POLICY["diagnostic_xml"])],
                env=env, capture_output=True, text=True, timeout=POLICY["test_timeout"])
            native.save(root / POLICY["diagnostic_output"], {
                "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
            raise
        if installed["status"] != native.POLICY["passed"]:
            raise ValueError(POLICY["installation_failed"])
        report["passed"] = True
    finally:
        binary.unlink(missing_ok=True)
        archive.unlink(missing_ok=True)
        native.save(root / POLICY["report"], report)


if __name__ == "__main__":
    main()
