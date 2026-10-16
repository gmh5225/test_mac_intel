"""Prepare a bounded ARM64 non-SEH setjmp correction in a build-only copy."""

from pathlib import Path
import hashlib
import json
import shutil
import subprocess

root = Path.cwd()
source = root / "third_party/unicorn"
destination = root / "build-unicorn-input"
commit = subprocess.check_output(
    ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
).strip()
if commit != "81f77ad35e02822cd2052ab9440e91a0ecdb4c4d":
    raise ValueError("unexpected Unicorn input commit")
relative = Path("qemu/include/sysemu/os-win32.h")
original = (source / relative).read_bytes()
old = b"#if defined(_WIN64)\n"
new = b"#if defined(_WIN64) && !defined(__aarch64__)\n"
if original.count(old) != 1:
    raise ValueError("unexpected Windows setjmp guard")
corrected = original.replace(old, new)
shutil.copytree(source, destination, ignore=shutil.ignore_patterns(".git"))
(destination / relative).write_bytes(corrected)
logs = root / "expansion-logs"
(logs / "unicorn-original-os-win32.h").write_bytes(original)
(logs / "unicorn-compiled-os-win32.h").write_bytes(corrected)
evidence = {
    "source_commit": commit,
    "path": relative.as_posix(),
    "original_sha256": hashlib.sha256(original).hexdigest(),
    "compiled_sha256": hashlib.sha256(corrected).hexdigest(),
    "flags": ["-D__USE_MINGW_SETJMP_NON_SEH"],
    "reason": "ARM64 MinGW uses its non-SEH setjmp/longjmp pair; the old _WIN64 branch assumes the x64 CRT ABI",
    "references": [
        "https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-headers/crt/setjmp.h",
        "https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-libraries/winpthreads/src/thread.c",
    ],
}
(logs / "unicorn-build-overlay.json").write_text(json.dumps(evidence, indent=2) + "\n")
print(json.dumps(evidence, indent=2))
