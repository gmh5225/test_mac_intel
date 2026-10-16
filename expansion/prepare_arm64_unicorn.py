"""Prepare a bounded ARM64 non-SEH setjmp correction in a build-only copy."""

from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
from unicorn_header_input import authenticate, corrected_handler, corrected_header

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
committed = subprocess.check_output(
    ["git", "-C", str(source), "show", commit + ":" + relative.as_posix()]
)
corrected = corrected_header(original, committed)
shutil.copytree(source, destination, ignore=shutil.ignore_patterns(".git"))
(destination / relative).write_bytes(corrected)
logs = root / "expansion-logs"
(logs / "unicorn-original-os-win32.h").write_bytes(original)
(logs / "unicorn-compiled-os-win32.h").write_bytes(corrected)
evidence = {
    "source_commit": commit,
    "path": relative.as_posix(),
    "original_sha256": hashlib.sha256(original).hexdigest(),
    "committed_sha256": hashlib.sha256(committed).hexdigest(),
    "compiled_sha256": hashlib.sha256(corrected).hexdigest(),
    "checkout_line_endings": "CRLF" if b"\r\n" in original else "LF",
    "flags": ["-D__USE_MINGW_SETJMP_NON_SEH"],
    "reason": "ARM64 MinGW uses its non-SEH setjmp/longjmp pair; the old _WIN64 branch assumes the x64 CRT ABI",
    "references": [
        "https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-headers/crt/setjmp.h",
        "https://github.com/mingw-w64/mingw-w64/blob/master/mingw-w64-libraries/winpthreads/src/thread.c",
    ],
}
handler_path = Path("qemu/accel/tcg/translate-all.c")
handler_original = (source / handler_path).read_bytes()
handler_committed = subprocess.check_output(
    ["git", "-C", str(source), "show", commit + ":" + handler_path.as_posix()]
)
authenticate(handler_original, handler_committed)
apply_handler = os.environ.get("NEVERD_UNICORN_ARM64_HANDLER", "1") == "1"
handler_compiled = (
    corrected_handler(handler_original, handler_committed)
    if apply_handler
    else handler_committed
)
(destination / handler_path).write_bytes(handler_compiled)
(logs / "unicorn-original-translate-all.c").write_bytes(handler_original)
(logs / "unicorn-compiled-translate-all.c").write_bytes(handler_compiled)
evidence["handler"] = {
    "path": handler_path.as_posix(),
    "applied": apply_handler,
    "original_sha256": hashlib.sha256(handler_original).hexdigest(),
    "committed_sha256": hashlib.sha256(handler_committed).hexdigest(),
    "compiled_sha256": hashlib.sha256(handler_compiled).hexdigest(),
    "reason": "The _WIN64 page-commit exception closure contains x64 opcodes; a native ARM64 process needs an ARM64 leaf tail call",
    "references": [
        "https://learn.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions",
        "https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-flushinstructioncache",
    ],
}
(logs / "unicorn-build-overlay.json").write_text(json.dumps(evidence, indent=2) + "\n")
print(json.dumps(evidence, indent=2))
