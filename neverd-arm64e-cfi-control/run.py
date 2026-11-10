"""Execute identified LLVM fork objects through Apple's linker and unwinder."""

import json
from pathlib import Path
import subprocess
import sys
import tarfile

POLICY = json.loads(Path(__file__).with_name("Control.def").read_text())
sys.path.insert(0, str(Path(POLICY["source"]) / "scripts"))
import verify_arm64e_native as native


def main():
    output = Path(POLICY["output"]).resolve()
    output.mkdir()
    archive = Path(POLICY["asset"])
    report = {"passed": False, "source_revision": POLICY["source_revision"],
              "llvm_revision": POLICY["llvm_revision"], "cases": []}
    variables = {"fixture": str(output)}

    def execute(name, argv):
        command = [arg.format_map(variables) for arg in argv]
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=POLICY["timeout"])
        native.save(output / (name + POLICY["log_suffix"]), {
            "argv": command, "returncode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr})
        result.check_returncode()
        return result

    try:
        if native.provenance()["source_revision"] != POLICY["source_revision"]:
            raise ValueError(POLICY["errors"]["identity"])
        subprocess.run([arg.format_map(POLICY) for arg in POLICY["download"]], check=True)
        if native.digest(archive) != POLICY["asset_sha256"]:
            raise ValueError(POLICY["errors"]["identity"])
        with tarfile.open(archive) as source:
            source.extractall(output, filter="data")
        manifest = json.loads((output / POLICY["manifest"]).read_text())
        if (manifest["llvm_revision"] != POLICY["llvm_revision"] or
                any(native.digest(output / name) != digest
                    for name, digest in manifest["inputs"].items())):
            raise ValueError(POLICY["errors"]["identity"])
        report["manifest_sha256"] = native.digest(output / POLICY["manifest"])
        probe = output / POLICY["preflight"]
        probe.mkdir()
        control = native.probe(probe)
        if control["status"] != native.POLICY["passed"]:
            raise ValueError(POLICY["errors"]["preflight"])
        report["probe_sha256"] = native.digest(probe / native.POLICY["report_name"])
        execute(POLICY["loader_log"], POLICY["loader"])
        for case in POLICY["cases"]:
            variables.update(case)
            name = case["object"]
            execute(name + POLICY["link_suffix"], POLICY["link"])
            execute(name + POLICY["unwind_suffix"], POLICY["inspect"])
            result = execute(name + POLICY["execute_suffix"], POLICY["run"])
            if POLICY["marker"] not in result.stdout:
                raise ValueError(POLICY["errors"]["execution"])
            report["cases"].append({"object": name, "passed": True,
                                    "object_sha256": native.digest(output / name),
                                    "image_sha256": native.digest(output / (name + POLICY["image_suffix"]))})
        report["passed"] = True
    finally:
        products = []
        for pattern in POLICY["cleanup_patterns"]:
            for product in output.glob(pattern):
                products.append({"path": product.name, "sha256": native.digest(product),
                                  "bytes": product.stat().st_size})
                product.unlink()
        archive.unlink(missing_ok=True)
        native.save(output / POLICY["products"], products)
        native.save(output / POLICY["report"], report)


if __name__ == "__main__":
    main()
