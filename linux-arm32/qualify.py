#!/usr/bin/env python3
"""Execute the pinned ARM/Thumb patch inventory using the ARM64 Linux kernel."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parent
COMMIT = "fcee81c9a5e2f20a71090ade23ae833175f64c59"
ARCHIVE_HASH = "ad7cdad1ebab507ff99a64b913ddf2c03d9503e1a54deae715981bfa1805e6ce"
ENGINE_HASH = "c52e4b29ca1caf3da3e3cc0664577f441e3802e093d9a40ca78e507bc8f029d0"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def reject_interpreted_images(handlers, images):
    """Refuse every enabled binfmt rule that could intercept any input image."""
    for name, text in handlers.items():
        if name == "status":
            continue
        lines = text.splitlines()
        require(lines and lines[0] in ("enabled", "disabled"), "unknown binfmt rule state")
        if lines[0] == "disabled":
            continue
        fields = dict(line.split(" ", 1) for line in lines[1:] if " " in line)
        require("interpreter" in fields, "missing binfmt interpreter")
        if "extension" in fields:
            suffix = "." + fields["extension"].lstrip(".")
            matches = any(path.endswith(suffix) for path in images)
        else:
            require("magic" in fields and "offset" in fields, "unknown binfmt match rule")
            magic = bytes.fromhex(fields["magic"])
            mask = bytes.fromhex(fields.get("mask", "ff" * len(magic)))
            offset = int(fields["offset"])
            require(magic and len(mask) == len(magic) and offset >= 0, "invalid binfmt match extent")
            matches = any(len(raw) >= offset + len(magic) and
                          all((raw[offset + i] & mask[i]) == (byte & mask[i])
                              for i, byte in enumerate(magic)) for raw in images.values())
        require(not matches, "binfmt interpreter can intercept patch images: " + name)


def elf_machine(raw, bits, machine):
    return (len(raw) >= 52 and raw[:6] == b"\x7fELF" + bytes((bits // 32, 1)) and
            struct.unpack_from("<H", raw, 18)[0] == machine)


def interpreter(raw):
    require(elf_machine(raw, 32, 40), "input must be ARM ELF32")
    offset = struct.unpack_from("<I", raw, 28)[0]
    stride, count = struct.unpack_from("<HH", raw, 42)
    require(stride == 32 and 0 < count <= 128 and offset + stride * count <= len(raw),
            "invalid ELF program-header extent")
    entries = []
    for index in range(count):
        kind, start, _, _, length = struct.unpack_from("<IIIII", raw, offset + stride * index)
        if kind == 3:
            require(1 < length <= 4096 and start + length <= len(raw), "invalid PT_INTERP extent")
            entries.append(raw[start:start + length])
    require(entries == [b"/lib/ld-linux-armhf.so.3\0"], "unexpected or duplicate ELF interpreter")
    return "/lib/ld-linux-armhf.so.3"


def load_inputs(contracts):
    revision = subprocess.check_output(["git", "-C", str(contracts), "rev-parse", "HEAD"], text=True).strip()
    require(revision == COMMIT, "NeverD contract checkout has the wrong commit")
    provenance = json.loads((ROOT / "input-provenance.json").read_text())
    require(provenance["qualified_commit"] == COMMIT, "wrong input qualification commit")
    for name, digest in provenance["contract_files"].items():
        require(sha((contracts / name).read_bytes()) == digest, "contract source hash mismatch: " + name)
    sys.path.insert(0, str(contracts))
    from scripts import check_source_patch_additional_runtime as runtime
    wanted = runtime.cases("linux", "arm32")
    archive = (ROOT / "qualified-images.zip").read_bytes()
    require(len(archive) == 89067 and sha(archive) == ARCHIVE_HASH, "input artifact size or SHA256 mismatch")
    with zipfile.ZipFile(ROOT / "qualified-images.zip") as package:
        names = package.namelist()
        require(len(names) == len(set(names)), "duplicate input artifact member")
        manifest = json.loads(package.read("manifest.json"))
        require(manifest["commit"] == COMMIT and manifest["engine_source_digest"] == ENGINE_HASH and
                manifest["schema"] == runtime.SCHEMA, "unqualified source manifest")
        rows = manifest["images"]
        require(len(rows) == len(wanted) == 32 and {r["case"] for r in rows} == set(wanted),
                "incomplete or duplicate case inventory")
        images = {}
        for row in rows:
            name = row["path"]
            require(Path(name).name == name and name.endswith(".elf") and name not in images,
                    "invalid or duplicate image path")
            raw = package.read(name)
            require(row["architecture"] == "arm32" and sha(raw) == row["sha256"], "image hash mismatch")
            interpreter(raw)
            images[name] = raw
        receipts = {}
        for name in names:
            if name.endswith("-receipt.json"):
                require(Path(name).name == name, "invalid receipt path")
                receipts[name] = package.read(name)
        require(len(receipts) == 30, "incomplete publication receipt inventory")
    return manifest, wanted, images, receipts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contracts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    manifest, wanted, images, receipts = load_inputs(args.contracts.resolve())
    if args.verify_only:
        print("Authenticated 32 images and 30 receipts; no processes executed.")
        return
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    report = {"schema": "neverd.source-patch.arm32-compatibility.v1", "complete": False,
              "commit": COMMIT, "harness_commit": os.environ.get("GITHUB_SHA"),
              "harness_repository": os.environ.get("GITHUB_REPOSITORY"),
              "run_id": os.environ.get("GITHUB_RUN_ID"),
              "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
              "execution_kind": "compatibility", "host_architecture": "arm64",
              "architecture": "arm32", "system": "linux", "runner": None,
              "explicit_loader_command": False, "input_artifact_sha256": ARCHIVE_HASH,
              "engine_source_commit": manifest["engine_source_commit"],
              "engine_source_digest": manifest["engine_source_digest"],
              "kernel": platform.release(), "machine": platform.machine(),
              "image_version": os.environ.get("ImageVersion"), "observations": []}

    def save():
        (root / "runtime.json").write_text(json.dumps(report, indent=2) + "\n")

    try:
        require(platform.system() == "Linux" and platform.machine() == "aarch64", "Linux ARM64 host required")
        with Path("/proc/self/exe").open("rb") as executable:
            require(elf_machine(executable.read(64), 64, 183), "verifier must be native AArch64")
        require(not any(k.startswith("QEMU_") or (k.startswith("LD_") and k != "LD_LIBRARY_PATH")
                        for k in os.environ), "external loader injection environment refused")
        # setup-python may need its own ARM64 library path. The ARM32 children
        # must instead resolve libraries through the installed system loader.
        child_environment = dict(os.environ)
        child_environment.pop("LD_LIBRARY_PATH", None)
        report["child_loader_environment"] = {}
        report["removed_python_library_path"] = "LD_LIBRARY_PATH" in os.environ
        binfmt = Path("/proc/sys/fs/binfmt_misc")
        handlers = {p.name: p.read_text() for p in binfmt.glob("*") if p.is_file() and p.name != "register"}
        reject_interpreted_images(handlers, images)
        report["binfmt_misc_before"] = handlers
        loader = Path("/lib/ld-linux-armhf.so.3")
        raw = loader.read_bytes()
        require(elf_machine(raw, 32, 40), "real ARM32 glibc loader required at PT_INTERP")
        report["loader"] = {"path": str(loader), "resolved": str(loader.resolve()), "sha256": sha(raw)}
        report["libc_package"] = subprocess.check_output(
            ["dpkg-query", "-W", "-f=${Package} ${Version} ${Architecture}\n", "libc6:armhf"], text=True)
        report["cpu"] = subprocess.check_output(["lscpu"], text=True)
        (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        for name, raw in {**images, **receipts}.items():
            (root / name).write_bytes(raw)
        for row in manifest["images"]:
            path = root / row["path"]
            path.chmod(0o755)
            for mode, expected in wanted[row["case"]]:
                for attempt in range(3):
                    command = [str(path)] + ([] if mode is None else [str(mode)])
                    observation = {"case": row["case"], "path": row["path"], "sha256": row["sha256"],
                                   "mode": mode, "attempt": attempt, "expected": expected, "command": command}
                    try:
                        result = subprocess.run(command, capture_output=True, timeout=20,
                                                env=child_environment)
                        observation.update(actual=result.returncode, stdout=result.stdout.decode("utf-8", "replace"),
                                           stderr=result.stderr.decode("utf-8", "replace"))
                    except (OSError, subprocess.TimeoutExpired) as error:
                        observation["error"] = str(error)
                    report["observations"].append(observation)
                    save()
        after = {p.name: p.read_text() for p in binfmt.glob("*") if p.is_file() and p.name != "register"}
        report["binfmt_misc_after"] = after
        require(after == handlers, "binfmt handlers changed during execution")
        require(sha(loader.read_bytes()) == report["loader"]["sha256"], "glibc loader changed during execution")
        require(all(sha((root / row["path"]).read_bytes()) == row["sha256"] for row in manifest["images"]),
                "an image changed during execution")
        require(len(report["observations"]) == 96, "incomplete observation inventory")
        failures = [row for row in report["observations"] if row.get("actual") != row["expected"]]
        require(not failures, str(len(failures)) + " process observations failed")
        report["complete"] = True
        print("All 96 ARM/Thumb patch observations passed via direct kernel loading (ARM64 compatibility).")
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        save()


if __name__ == "__main__":
    main()
