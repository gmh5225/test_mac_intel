#!/usr/bin/env python3
"""Qualify the supplied x64 NeverC binary on the selected hosted runner."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    compiler = args.compiler.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = output / "x64.c"
    source.write_text('_Static_assert(sizeof(void *) == 8, "x64 ABI");\n'
                      'int pointer_bytes(void) { return sizeof(void *); }\n')
    library = output / "x64.so"
    build = ["-std=c11", "-O2", "-fPIC", "-shared", "-Wl,-Bsymbolic",
             str(source), "-o", str(library)]
    baseline = subprocess.run([compiler, *build], capture_output=True, text=True)
    usable = compiler
    execution = "native"
    if baseline.returncode == -signal.SIGILL:
        emulator = shutil.which("qemu-x86_64")
        if not emulator:
            raise RuntimeError("qemu-x86_64 is required after a host ISA fault")
        execution = "qemu-x86_64 -cpu max"
        usable = output / "neverc"
        usable.write_text("#!/bin/sh\nexec " + shlex.join(
            [emulator, "-cpu", "max", str(compiler)]) + ' "$@"\n')
        usable.chmod(0o755)
        subprocess.run([usable, *build], check=True)
    elif baseline.returncode:
        raise RuntimeError(baseline.stderr or f"NeverC exited with {baseline.returncode}")
    # The shared library always executes on the real x64 host.
    if ctypes.CDLL(str(library)).pointer_bytes() != 8:
        raise RuntimeError("generated host library returned a different pointer width")
    rejected = []
    for target in ("-m32", "--target=i386-unknown-linux-gnu",
                   "--target=i686-pc-windows-msvc", "--target=i386-apple-darwin",
                   "--target=x86_64-unknown-linux-gnux32"):
        result_path = output / "rejected.o"
        result_path.unlink(missing_ok=True)
        result = subprocess.run([usable, target, "-c", source, "-o", result_path],
                                capture_output=True, text=True)
        if result.returncode <= 0 or result_path.exists() or (
                "unsupported target architecture" not in result.stderr and
                "unknown argument" not in result.stderr):
            raise RuntimeError(f"{target} did not produce a target rejection: {result.stderr}")
        rejected.append({"option": target, "diagnostic": result.stderr.strip()})
    info = {"version": subprocess.check_output([usable, "--version"], text=True).strip(),
            "binary_sha256": hashlib.file_digest(compiler.open("rb"), "sha256").hexdigest(),
            "compiler_execution": execution, "native_compiler_probe_exit": baseline.returncode,
            "generated_library_pointer_bytes": 8, "rejected_source_targets": rejected}
    report = json.dumps(info, indent=2)
    (output / "compiler.json").write_text(report + "\n")
    print(report, flush=True)
    if env := os.environ.get("GITHUB_ENV"):
        with open(env, "a") as stream:
            stream.write("NEVERD_TEST_NEVERC=" + str(usable) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
