"""Replay a source-bound local entry test host on a native Apple runner."""

import json
from pathlib import Path
import subprocess
import sys
import tarfile

POLICY = json.loads(Path(__file__).with_name("Replay.def").read_text())
sys.path.insert(0, str(Path(POLICY["source"]) / "scripts"))
import verify_arm64e_entry as entry


def unwind_control(output, compiler, sdk):
    native = entry.native
    policy = json.loads(Path(__file__).with_name("UnwindControl.def").read_text())
    directory = output / policy["directory"]
    directory.mkdir()
    source = directory / policy["source"]
    source.write_text(policy["source_text"])
    loader_source = directory / policy["loader_source"]
    loader_source.write_text(native.fixture_contract()["loader"])
    rows = []
    compile_args = [*policy["compile_args"], entry.POLICY["sysroot_option"], sdk]
    with entry.OwnedProducts(directory, False) as products:
        loader = directory / policy["loader"]
        products.append(loader)
        native.command(products, directory, policy["loader"],
                       [str(compiler), *compile_args, str(loader_source),
                        policy["output_option"], str(loader)], policy["timeout"]).check_returncode()
        for profile in policy["profiles"]:
            library = directory / profile["name"]
            products.append(library)
            native.command(products, directory, profile["name"] + policy["compile_suffix"],
                           [str(compiler), *compile_args, *policy["library_args"],
                            *profile["args"], str(source), policy["output_option"], str(library)],
                           policy["timeout"]).check_returncode()
            native.command(products, directory, profile["name"] + policy["sections_suffix"],
                           [*entry.POLICY["sections_command"], str(library)], policy["timeout"]).check_returncode()
            result = native.command(products, directory, profile["name"],
                                    [str(loader), str(library)], policy["timeout"])
            rows.append({"profile": profile["name"], "returncode": result.returncode,
                         "stderr": result.stderr, **native.check_binary(library)})
    native.save(directory / policy["report"], rows)


def main():
    native = entry.native
    output = Path(POLICY["evidence"]).resolve()
    output.mkdir()
    archive = Path(POLICY["asset"])
    binary = output / POLICY["host"]
    report = {"source_revision": POLICY["source_revision"], "passed": False,
              "cold_source_build": False}
    try:
        if native.provenance()["source_revision"] != POLICY["source_revision"]:
            raise ValueError(POLICY["errors"]["source"])
        subprocess.run([arg.format_map(POLICY) for arg in POLICY["download"]], check=True)
        if native.digest(archive) != POLICY["asset_sha256"]:
            raise ValueError(POLICY["errors"]["archive"])
        with tarfile.open(archive) as source:
            source.extractall(output, filter="data")
        manifest_path = output / POLICY["manifest"]
        manifest = json.loads(manifest_path.read_text())
        if (manifest["source_revision"] != POLICY["source_revision"] or
                manifest["binary_sha256"] != native.digest(binary) or
                any(native.digest(native.ROOT / name) != value
                    for name, value in manifest["source_sha256"].items())):
            raise ValueError(POLICY["errors"]["identity"])
        report["manifest_sha256"] = native.digest(manifest_path)
        probe = output / POLICY["probe"]
        probe.mkdir()
        control = native.probe(probe)
        if control["status"] != native.POLICY["passed"]:
            raise ValueError(POLICY["errors"]["probe"])
        lookup = subprocess.run(POLICY["compiler_lookup"], capture_output=True, text=True,
                                timeout=entry.POLICY["tool_timeout"])
        report["compiler_lookup"] = {"argv": lookup.args, "returncode": lookup.returncode,
                                     "stdout": lookup.stdout, "stderr": lookup.stderr}
        lookup.check_returncode()
        compiler = Path(lookup.stdout.strip()).absolute()
        entries = output / POLICY["entries"]
        entries.mkdir()
        result = entry.run(entries, binary, compiler,
                           probe / native.POLICY["report_name"])
        if not result["native_reconstructed_entry_qualified"]:
            raise ValueError(POLICY["errors"]["entry"])
        unwind_control(output, compiler, result["sdk_path"])
        report["entry_report_sha256"] = native.digest(entries / entry.POLICY["report_name"])
        report["passed"] = True
    finally:
        binary.unlink(missing_ok=True)
        archive.unlink(missing_ok=True)
        report["owned_host_removed"] = not binary.exists()
        native.save(output / POLICY["report"], report)


if __name__ == "__main__":
    main()
