"""Stage a matching public executable, shared libraries and fork SDK receipt."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

repo, build, dest = (Path(arg).resolve() for arg in sys.argv[1:4])
revision, fork, release = sys.argv[4:]
assert (
    subprocess.check_output(["git", "-C", repo, "rev-parse", "HEAD"], text=True).strip()
    == revision
)
assert (
    subprocess.check_output(
        ["git", "-C", repo, "rev-parse", "HEAD:third_party/llvm-project"], text=True
    ).strip()
    == fork
)
cache = (build / "CMakeCache.txt").read_text()
assert f"NEVERD_LLVM_PREBUILT_TAG:STRING=neverd-llvm-v23.0.0-{release}" in cache
llvm_dir = next(
    line.split("=", 1)[1]
    for line in cache.splitlines()
    if line.startswith("LLVM_DIR:PATH=")
)
info = (Path(llvm_dir).parents[2] / "BUILDINFO.txt").read_text()
assert f"llvm_commit: {fork}" in info
files = [
    p
    for p in (build / "bin").iterdir()
    if p.is_file()
    and (
        p.name in ("neverd", "neverd.exe")
        or p.suffix.lower() in (".dll", ".dylib", ".so")
        or ".so." in p.name
    )
]
assert any(
    "neverd" in p.name.lower() and p.suffix.lower() in (".dll", ".dylib", ".so")
    for p in files
)
assert any(p.name in ("neverd", "neverd.exe") for p in files)
dest.mkdir(parents=True, exist_ok=True)
digests = {}
for item in files:
    saved = dest / item.name
    shutil.copy2(item, saved)
    with saved.open("rb") as stream:
        digests[item.name] = hashlib.file_digest(stream, "sha256").hexdigest()
record = {
    "neverd": revision,
    "llvm": fork,
    "sdk": f"neverd-llvm-v23.0.0-{release}",
    "files": digests,
}
(dest / "source.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print(json.dumps(record, sort_keys=True))
