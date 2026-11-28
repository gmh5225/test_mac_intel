#!/usr/bin/env python3
"""Exercise NeverC's public and embedded target checks using actual compiler output."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def check(compiler, args, expected=None):
    result = subprocess.run([compiler, *args], capture_output=True, text=True)
    diagnostic = result.stderr + result.stdout
    if expected is None:
        if result.returncode:
            raise RuntimeError(f"{args}: {diagnostic}")
    elif result.returncode <= 0 or expected not in diagnostic:
        raise RuntimeError(f"{args}: expected {expected}, got {result.returncode} {diagnostic}")
    return diagnostic


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    cc = options.compiler.resolve()
    supported = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
                 "x86_64-apple-macosx15.0.0", "arm64-apple-macosx15.0.0",
                 "x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"]
    unsupported = ["i386-unknown-linux-gnu", "i686-unknown-linux-gnu",
                   "i686-pc-windows-msvc", "i386-apple-darwin",
                   "x86_64-unknown-linux-gnux32", "x86_64-unknown-linux-muslx32",
                   "arm64_32-apple-watchos", "aarch64-unknown-linux-gnu_ilp32",
                   "aarch64-unknown-linux-gnuilp32"]
    profiles = ["cpp-core-v1", "cpp-core-v2", "cpp-project-v1", "cpp-math-v1"]
    rows = []
    with tempfile.TemporaryDirectory(prefix="neverc-abi-") as temporary:
        work = Path(temporary).resolve()
        cpp = work / "width.cpp"
        cpp.write_text('extern "C" int width(){return 8;}')
        c = work / "width.c"
        c.write_text('_Static_assert(sizeof(void*)==8,"ABI"); int width(void){return sizeof(void*);}')
        compdb = work / "compile_commands.json"
        compdb.write_text(json.dumps([dict(directory=str(work), file=str(cpp),
                                          arguments=["clang++", "-std=c++17", "-c", str(cpp)])]))
        terms = ["--compdb", compdb, "--project-root", work]
        for target in supported:
            obj = work / (target + ".o")
            check(cc, ["--target=" + target, "-c", c, "-o", obj])
            if not obj.stat().st_size:
                raise ValueError(target)
            for profile in profiles[:2]:
                out = work / (profile + target + ".nc")
                check(cc, ["translate", "--from", "cpp", "--target", target,
                           "--profile", profile, cpp, "-o", out])
                manifest = json.loads(Path(str(out) + ".manifest.json").read_text())
                if not out.stat().st_size or manifest["target"]["pointer_bits"] != 64:
                    raise ValueError((target, manifest["target"]))
            rows.append(dict(target=target, included=["object", *profiles[:2]]))
        for target in unsupported:
            obj = work / (target + ".o")
            check(cc, ["--target=" + target, "-c", c, "-o", obj],
                  "unsupported target architecture")
            if obj.exists():
                raise ValueError(f"unexpected 32-bit object {obj}")
            for profile in profiles:
                opts = terms if profile in profiles[2:] else []
                out = work / (profile + target + ".nc")
                emit = ["--out-dir", out] if opts else ["-o", out]
                check(cc, ["translate", "--from", "cpp", "--target", target,
                           "--profile", profile, *opts, cpp, *emit], "TR0204")
                if out.exists():
                    raise ValueError(f"unexpected translation output {out}")
            req, resp = work / (target + ".req"), work / (target + ".resp")
            req.write_text(json.dumps(dict(protocol=1, profile="cpp-core-v1", root=str(work),
                                           source=str(cpp), target=target, arguments=["-std=c++17"])))
            result = subprocess.run([cc, "__neverc_cpp_frontend", "--request", req,
                                     "--output", resp], capture_output=True, text=True)
            data = json.loads(resp.read_text())
            if result.returncode <= 0 or [d["code"] for d in data["diagnostics"]] != ["TR0204"]:
                raise ValueError((target, data))
            rows.append(dict(target=target, rejected=["object", *profiles, "embedded-frontend"]))
        for abi in ("ilp32", "x32"):
            obj = work / (abi + ".o")
            check(cc, ["--target=x86_64-unknown-linux-gnu", "-mabi=" + abi, "-c",
                       c, "-o", obj], "unsupported argument")
            if obj.exists():
                raise ValueError(obj)
    with cc.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    source_commit = subprocess.check_output(["git", "-C", options.source, "rev-parse", "HEAD"],
                                            text=True).strip()
    report = dict(source_commit=source_commit, compiler_sha256=digest,
                  native_width=64, cases=rows, rejected_x86_64_abi_options=["ilp32", "x32"])
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{len(supported)} native ABI controls, {len(unsupported)} rejected targets, "
          f"{len(profiles)} translation profiles, 2 rejected x64 ABI options")


if __name__ == "__main__":
    main()
