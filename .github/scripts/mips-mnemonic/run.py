"""Measure the actual candidate package and two published packages with the stock driver."""
from pathlib import Path
import gzip
import json
import os
import platform
import shutil
import subprocess
import tempfile

from compare import compare, digest, inputs

REVISIONS = {"r13": "24ced447e1718432292dc9d54b6eb229323409d1",
             "r14": "6c769154fbe9db2fe9e2e2dc1b04bebfe64e1312",
             "candidate": "2e3936365fcb787cc303bb85d192626a9a9ab06b"}
ARCHIVES = {
    "Linux": ["9c48f639fa51c5de8d1482ea9e23409d215fc6d6022873cff5899154862c8672",
              "8bdcf7289ada160858c35ccb6dbf848c46c75161063c65b5653954b3e4d4d2bd"],
    "Darwin": ["c29df29cf1c9dcad48576752e312b89032a18de2cde6a6a1022869cf5c504476",
               "b8e70c79d2a44ba0dfd49803fa958b6408037960930fbeb2cb5f0bc60b98ac54"],
    "Windows": ["ba36aec4b41c0f8075cddfee2d924946156a5eb343ddb838eda2a1afb60388fe",
                "2f23b21740c23036f33c7cf6d5cc19486b9d6cf25bc882795f86dd41482f2184"],
}


def check(args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True, errors="replace").strip()


def write(file, value):
    file.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def instruction_counts(exes, directory, evidence, objects):
    totals = {}
    for kind, code in {"empty": ".text\n", **inputs()}.items():
        source = directory / "trace.s"
        source.write_bytes(code.encode())
        summary = {}
        for version, exe in exes.items():
            trace, obj = directory / "trace.out", directory / "trace.o"
            subprocess.run(["valgrind", "--tool=callgrind", "--callgrind-out-file=" + str(trace),
                            exe, "-triple=mipsel", "-mcpu=mips32r2", "-filetype=obj",
                            source, "-o", obj], check=True)
            sha = digest(obj)
            assert objects.setdefault(kind, sha) == sha, (kind, sha)
            with gzip.open(evidence / (kind + "-" + version + ".callgrind.gz"), "wb") as compressed:
                with trace.open("rb") as stream:
                    shutil.copyfileobj(stream, compressed)
            summary[version], = [int(line.split()[1]) for line in trace.read_text().splitlines()
                                 if line.startswith("summary:")]
        totals[kind] = summary
    write(evidence / "instruction-counts.json", totals)


def main():
    system = platform.system()
    windows = system == "Windows"
    root = Path.cwd()
    recipe = Path(__file__).resolve().parent
    evidence = root / "mnemonic-evidence"
    evidence.mkdir()
    temp = Path(os.environ["RUNNER_TEMP"])
    package = os.environ["PACKAGE_NAME"]
    filename = package + (".zip" if windows else ".tar.xz")
    driver_tree = check(["git", "rev-parse", "HEAD:llvm/tools/llvm-mc"])
    assert driver_tree == "fe2dd646d45346aaf30951c0d3f3741bc9e39680"
    assert check(["git", "rev-parse", "HEAD"]) == REVISIONS["candidate"]
    sidecar = (root / (filename + ".sha256")).read_text(encoding="utf-8-sig").split()
    assert sidecar == [digest(root / filename), filename]
    identity = {"source": REVISIONS, "driver_tree": driver_tree, "host": platform.platform(),
                "archive_sha256": {}, "buildinfo": {}}
    with tempfile.TemporaryDirectory(dir=temp, prefix="mips-sdk-") as work:
        work = Path(work)
        exes = {}
        for number, (version, revision) in enumerate(REVISIONS.items()):
            staging = work / "staging"
            if version == "candidate":
                sdk = temp / "pkg" / package
                sha = sidecar[0]
            else:
                staging.mkdir()
                archive = staging / filename
                uri = ("https://github.com/NeverSight/llvm-project/releases/download/"
                       f"neverd-llvm-v23.0.0-{version}/{filename}")
                subprocess.run(["curl", "--fail", "--location", "--retry", "3", "--silent",
                                "--show-error", "--output", archive, uri], check=True)
                sha = digest(archive)
                assert sha == ARCHIVES[system][number], (version, sha)
                subprocess.run(["cmake", "-E", "tar", "xf", filename], check=True, cwd=staging)
                sdk = staging / package
            metadata = (sdk / "BUILDINFO.txt").read_text(encoding="utf-8-sig")
            assert "llvm_commit: " + revision in metadata.splitlines()
            assert "build_type: Release" in metadata.splitlines()
            identity["archive_sha256"][version] = sha
            identity["buildinfo"][version] = metadata
            build = work / version
            cc = "clang-cl" if windows else "clang"
            cxx = "clang-cl" if windows else "clang++"
            subprocess.run(["cmake", "-S", recipe, "-B", build, "-G", "Ninja",
                            "-DCMAKE_BUILD_TYPE=Release", f"-DCMAKE_C_COMPILER={cc}",
                            f"-DCMAKE_CXX_COMPILER={cxx}", "-DMC_SOURCE=" + str(root / "llvm/tools/llvm-mc"),
                            "-DLLVM_DIR=" + str(sdk / "lib/cmake/llvm")], check=True)
            subprocess.run(["cmake", "--build", build, "--parallel", "2", "--target", "llvm-mc"], check=True)
            driver = build / ("llvm-mc.exe" if windows else "llvm-mc")
            version_text = check([driver, "--version"])
            assert "mipsel" in version_text.lower()
            (evidence / (version + "-version.txt")).write_text(version_text)
            dependencies = check((["dumpbin", "/dependents"] if windows else ["otool", "-L"]
                                  if system == "Darwin" else ["ldd"]) + [driver])
            assert "libllvm" not in dependencies.lower() and "not found" not in dependencies.lower()
            (evidence / (version + "-dependencies.txt")).write_text(dependencies)
            exes[version] = driver
            if staging.exists():
                shutil.rmtree(staging)
        write(evidence / "identity.json", identity)
        results = evidence / "pairs.json"
        reference = {"branches": "4adfb3d63922c3d460e5bde74e9fff5557101e58955621aab25263c30079936f",
                     "arithmetic": "cb42ddebdb61cd4adc87d782be99bb06a60f4e6fe1702e44c99ae6ec69570330"}
        compare(exes, results, reference)
        if system == "Linux":
            instruction_counts(exes, work, evidence, json.loads(results.read_bytes())["objects"])


if __name__ == "__main__":
    main()
