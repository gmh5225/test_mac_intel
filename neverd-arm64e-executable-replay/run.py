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


def diagnose_producer(root, binary, compiler):
    policy = POLICY["diagnostic"]
    output = root / policy["directory"]
    output.mkdir()
    variables = {"compiler": str(compiler)}

    def run(name, argv, env=None):
        command = [arg.format_map(variables) for arg in argv]
        result = subprocess.run(command, capture_output=True, text=True,
                                env=env, timeout=policy["timeout"])
        native.save(output / name, {"argv": command, "returncode": result.returncode,
                                    "stdout": result.stdout, "stderr": result.stderr})
        return result.returncode

    env = dict(os.environ, **native.POLICY["test_environment"])
    env[native.POLICY["artifact_environment"]] = str(output)
    env[native.fixture_contract()["ir_compiler_environment"]] = str(compiler)
    run(policy["test_log"], [str(binary), native.POLICY["gtest_prefix"] + policy["case"]], env)
    fixture, = output.glob(policy["fixture_glob"])
    variables["fixture"] = str(fixture)
    run(policy["compile_log"], policy["compile_ir"])
    run(policy["compile_asm_log"], policy["compile_asm"])
    assembly = fixture / policy["assembly"]
    original = assembly.read_text().splitlines(keepends=True)
    changed = [line for line in original if line.strip() != policy["directive"]]
    darwin = fixture / policy["darwin_assembly"]
    darwin.write_text("".join(changed))
    native.save(output / policy["ablation_log"], {
        "original_sha256": native.digest(assembly), "changed_sha256": native.digest(darwin),
        "removed_directives": len(original) - len(changed),
        "diagnostic_only": True})
    for assembly_name, object_name in policy["assembly_controls"]:
        variables.update(assembly=assembly_name, object=object_name)
        run(object_name + policy["record_suffix"], policy["assemble"])
    for obj in policy["objects"]:
        variables["object"] = obj
        if not run(obj + policy["record_suffix"], policy["link"]):
            if run(obj + policy["run_suffix"] + policy["record_suffix"], policy["run"]):
                run(obj + policy["debug_suffix"] + policy["record_suffix"], policy["debug"])
    for name in policy["inspect"]:
        path = fixture / name
        if path.is_file():
            for index, argv in enumerate(policy["dumps"]):
                run(name + str(index) + policy["record_suffix"], [*argv, str(path)])


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
            for case in sorted(native.expected_cases() | native.expected_cases(True) |
                               native.expected_cases(generated=True) |
                               native.expected_cases(True, True))))
        dylib = root / POLICY["dylib_installation"]
        dylib.mkdir()
        installed = native.run_installation(
            dylib, build, preflight / native.POLICY["report_name"],
            Path(POLICY["legacy_fixtures"]).resolve())
        if installed["status"] != native.POLICY["passed"]:
            raise ValueError(POLICY["installation_failed"])
        output = root / POLICY["installation"]
        output.mkdir()
        installed = native.run_installation(
            output, build, startup / native.POLICY["report_name"], executable=True)
        if installed["status"] != native.POLICY["passed"]:
            raise ValueError(POLICY["installation_failed"])
        default = root / POLICY["default_installation"]
        default.mkdir()
        qualified = native.run_installation(
            default, build, preflight / native.POLICY["report_name"],
            executable=True, system_startup=True)
        if not qualified[native.POLICY["default_executable_qualification_key"]]:
            raise ValueError(POLICY["installation_failed"])
        subprocess.run(POLICY["ir_tools"], check=True, timeout=POLICY["ir_tools_timeout"])
        prefix = subprocess.check_output(POLICY["ir_prefix"], text=True).strip()
        compiler = Path(prefix) / POLICY["ir_compiler_suffix"]
        diagnose_producer(root, binary, compiler)
        for executable, name in ((False, "generated_installation"),
                                 (True, "generated_executable_installation")):
            generated = root / POLICY[name]
            generated.mkdir()
            qualified = native.run_installation(
                generated, build, preflight / native.POLICY["report_name"],
                executable=executable, system_startup=True, ir_compiler=compiler)
            if qualified["status"] != native.POLICY["passed"]:
                raise ValueError(POLICY["installation_failed"])
        report["passed"] = True
    finally:
        binary.unlink(missing_ok=True)
        archive.unlink(missing_ok=True)
        native.save(root / POLICY["report"], report)


if __name__ == "__main__":
    main()
