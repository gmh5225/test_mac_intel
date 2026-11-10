"""Replay a source-bound local entry test host on a native Apple runner."""

import json
from pathlib import Path
import subprocess
import sys
import tarfile

POLICY = json.loads(Path(__file__).with_name("Replay.def").read_text())
sys.path.insert(0, str(Path(POLICY["source"]) / "scripts"))
import verify_arm64e_entry as entry


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
        entries = output / POLICY["entries"]
        entries.mkdir()
        result = entry.run(entries, binary, Path(POLICY["compiler"]),
                           probe / native.POLICY["report_name"])
        if not result["native_reconstructed_entry_qualified"]:
            raise ValueError(POLICY["errors"]["entry"])
        report["entry_report_sha256"] = native.digest(entries / entry.POLICY["report_name"])
        report["passed"] = True
    finally:
        binary.unlink(missing_ok=True)
        archive.unlink(missing_ok=True)
        report["owned_host_removed"] = not binary.exists()
        native.save(output / POLICY["report"], report)


if __name__ == "__main__":
    main()
