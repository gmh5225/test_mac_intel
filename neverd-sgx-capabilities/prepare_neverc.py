#!/usr/bin/env python3
"""Qualify the supplied x64 NeverC binary on the selected hosted runner."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    compiler = args.compiler.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = output / "x64.c"
    source.write_text('#include <stdint.h>\n'
                      '_Static_assert(sizeof(void *) == 8, "x64 ABI");\n'
                      'int pointer_bytes(void) { return sizeof(void *); }\n'
                      'int64_t reinterpret_bits(uint64_t v) { return __builtin_bit_cast(int64_t, v); }\n')
    library = output / "x64.so"
    build = ["-std=c11", "-O2", "-fPIC", "-shared", "-Wl,-Bsymbolic",
             str(source), "-o", str(library)]
    subprocess.run([compiler, *build], check=True)
    host = ctypes.CDLL(str(library))
    host.reinterpret_bits.argtypes = [ctypes.c_uint64]
    host.reinterpret_bits.restype = ctypes.c_int64
    if host.pointer_bytes() != 8 or host.reinterpret_bits(2**64 - 7) != -7:
        raise RuntimeError("generated host library failed the x64 ABI and bit-cast checks")
    rejected = []
    for target in ("-m32", "--target=i386-unknown-linux-gnu",
                   "--target=i686-pc-windows-msvc", "--target=i386-apple-darwin",
                   "--target=x86_64-unknown-linux-gnux32"):
        result_path = output / "rejected.o"
        result_path.unlink(missing_ok=True)
        result = subprocess.run([compiler, target, "-c", source, "-o", result_path],
                                capture_output=True, text=True)
        if result.returncode <= 0 or result_path.exists() or (
                "unsupported target architecture" not in result.stderr and
                "unknown argument" not in result.stderr):
            raise RuntimeError(f"{target} did not produce a target rejection: {result.stderr}")
        rejected.append({"option": target, "diagnostic": result.stderr.strip()})
    with compiler.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    cpu_model = next((line.split(":", 1)[1].strip() for line in
                      Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")), "")
    info = {"host_cpu_model": cpu_model, "source_commit": subprocess.check_output(
                ["git", "-C", args.source, "rev-parse", "HEAD"], text=True).strip(),
            "version": subprocess.check_output([compiler, "--version"], text=True).strip(),
            "binary_sha256": digest, "compiler_execution": "native",
            "generated_library_pointer_bytes": 8, "bit_cast_result": -7,
            "rejected_source_targets": rejected}
    report = json.dumps(info, indent=2)
    (output / "compiler.json").write_text(report + "\n")
    print(report, flush=True)
    if env := os.environ.get("GITHUB_ENV"):
        with open(env, "a") as stream:
            stream.write("NEVERD_TEST_NEVERC=" + str(compiler) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
