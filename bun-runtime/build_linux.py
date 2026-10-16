"""Build a public Bun revision with a reconstructed Linux native selector."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
from patch_bun import patch, sha

ROOT = Path(__file__).resolve().parent
COMMIT = "c6da4a4d3010e5553438c60f6bd76d981976867c"
PROFILES = {
    "x64": {"machine": 62, "docker_platform": "linux/amd64",
            "image": "ghcr.io/oven-sh/bun-development-docker-image@sha256:ee053ca8ff0a00ab51c8572378fb56dee902063d5020b4d90fb78a098fb70af2",
            "rg_sha256": "3984a55c6cf39c362a1ae15e5c347ea2870ba3dd883a3da4865d5082ffe35a58",
            "seccomp_sha256": "5979576d07b50877385e2abea0534add12499074d259f0cd2d1c3694e9fe0a10"},
    "arm64": {"machine": 183, "docker_platform": "linux/arm64",
              "image": "ghcr.io/oven-sh/bun-development-docker-image@sha256:19e1898469e3ab456b90a4120c1b96644af53c019434c2f9852eb14870e13d11",
              "rg_sha256": "77d1249f185d04a63c3494fb327a5486359d0e80aef967ff3366efd82dfc8546",
              "seccomp_sha256": "6b650422a7287f2e585728667510d75700d6e5c638b0ea5722ad1f9f0d7ec666"},
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", required=True, choices=PROFILES)
    parser.add_argument("--rg", required=True, type=Path)
    parser.add_argument("--seccomp", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    assert platform.system() == "Linux" and {"x86_64": "x64", "aarch64": "arm64"}[platform.machine()] == args.arch
    profile = PROFILES[args.arch]
    out = args.output.resolve(); out.mkdir()
    logs = out / "diagnostics"; logs.mkdir()
    source = out / "bun-source"
    payloads = out / "payloads"; payloads.mkdir()
    receipt = {"status": "started", "arch": args.arch, "public_bun_commit": COMMIT, "profile": profile,
               "original_bun_revision_recovered": False, "original_prefix_reused": False,
               "captured_client_executed": False, "commands": [], "payloads": []}

    def run(label, argv, *, cwd=None):
        receipt["commands"].append({"label": label, "argv": list(map(str, argv)), "cwd": str(cwd) if cwd else None})
        with (logs / (label + ".log")).open("xb") as stream:
            result = subprocess.run(list(map(str, argv)), cwd=cwd, stdout=stream, stderr=subprocess.STDOUT)
        assert result.returncode == 0, label + " failed; inspect retained diagnostics"

    try:
        for label, path in [("rg", args.rg), ("apply-seccomp", args.seccomp)]:
            expected = profile["rg_sha256" if label == "rg" else "seccomp_sha256"]
            assert path.is_file() and not path.is_symlink() and sha(path) == expected
            data = path.read_bytes()
            assert data[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", data, 18)[0] == profile["machine"]
            destination = payloads / label
            destination.write_bytes(data); destination.chmod(0o555)
            receipt["payloads"].append({"name": label, "bytes": len(data), "sha256": expected})
        run("git-init", ["git", "init", source])
        run("git-remote", ["git", "remote", "add", "origin", "https://github.com/oven-sh/bun.git"], cwd=source)
        run("git-fetch", ["git", "fetch", "--depth", "1", "origin", COMMIT], cwd=source)
        run("git-checkout", ["git", "checkout", "--detach", COMMIT], cwd=source)
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
        assert actual == COMMIT
        receipt["source_patch"] = patch(source, logs / "source-patch")
        run("compiler-image-pull", ["docker", "pull", "--platform", profile["docker_platform"], profile["image"]])
        run("compiler-image-inspect", ["docker", "image", "inspect", profile["image"]])
        # The public compiler image stores its toolchain under root's home;
        # its root process needs DAC override to write this freshly owned
        # runner checkout. No captured client runs in this compiler profile.
        command = ["docker", "run", "--rm", "--platform", profile["docker_platform"], "--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE",
                   "--security-opt", "no-new-privileges", "--cpus", "4", "--memory", "12g", "--pids-limit", "512",
                   "--mount", f"type=bind,src={out},dst=/output", "--mount", f"type=bind,src={ROOT},dst=/recipes,readonly",
                   "--mount", f"type=bind,src={payloads},dst=/payloads,readonly", "--entrypoint", "/bin/bash",
                   profile["image"], "/recipes/build-runtime.sh"]
        run("bun-source-build", command)
        binary = source / "build/recovery/bun"
        assert binary.is_file()
        data = binary.read_bytes()
        assert data[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", data, 18)[0] == profile["machine"]
        controls = []
        for label, argv0, role, argv, expected_code, expected_text in [
            ("runtime-version", str(binary), None, ["--version"], 0, "1.4.3"),
            ("rg-environment", str(binary), "rg", ["--version"], 0, "ripgrep 14.1.1"),
            ("rg-actual-basename", "/fixture/rg", "apply-seccomp", ["--version"], 0, "ripgrep 14.1.1"),
            ("seccomp-usage", str(binary), "apply-seccomp", [], 1, "Usage:"),
            ("ugrep-explicit-unsupported", str(binary), "ugrep", ["--version"], 126, "implementation is not integrated"),
            ("bfs-explicit-unsupported", str(binary), "bfs", ["--version"], 126, "implementation is not integrated"),
            ("consume-unknown-role", str(binary), "unknown", ["-e", "console.log(process.env.ARGV0 === undefined)"], 0, "true"),
            ("raw-env-does-not-take-basename", str(binary), "/fixture/rg", ["--version"], 0, "1.4.3"),
        ]:
            env = dict(os.environ)
            env.pop("ARGV0", None)
            if role is not None:
                env["ARGV0"] = role
            result = subprocess.run([argv0, *argv], executable=binary, env=env, capture_output=True, timeout=30)
            stdout = result.stdout.decode(errors="replace"); stderr = result.stderr.decode(errors="replace")
            (logs / (label + ".stdout")).write_bytes(result.stdout)
            (logs / (label + ".stderr")).write_bytes(result.stderr)
            row = {"case": label, "exit_code": result.returncode, "stdout": stdout, "stderr": stderr,
                   "expected_code": expected_code, "expected_text": expected_text}
            controls.append(row)
            assert result.returncode == expected_code and expected_text in stdout + stderr, label
        package = out / "public-bun-runtime"; package.mkdir()
        shutil.copyfile(binary, package / "bun"); (package / "bun").chmod(0o555)
        for name in ["role_contract.rs", "recovered_multicall.rs", "patch_bun.py", "build_linux.py", "build-runtime.sh"]:
            shutil.copyfile(ROOT / name, package / name)
        for name in ["LICENSE.md", "Cargo.lock", "rust-toolchain.toml"]:
            shutil.copyfile(source / name, package / name)
        receipt.update(status="public_bun_source_build_and_bounded_native_dispatch_controls_passed",
                       runtime_sha256=sha(binary), runtime_bytes=binary.stat().st_size, authored_controls=controls,
                       scope="Public Bun source with reconstructed Linux role routing and embedded source-built rg/seccomp. Not original revision/static linkage; Ugrep/Bfs implementation, captured-client rebuild/readback and whole recovery remain open.")
        (package / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        files = [{"file": path.relative_to(package).as_posix(), "sha256": sha(path), "bytes": path.stat().st_size}
                 for path in sorted(package.rglob("*")) if path.is_file()]
        (package / "MANIFEST.json").write_text(json.dumps({"files": files}, indent=2) + "\n")
        print(json.dumps({"status": receipt["status"], "runtime_sha256": sha(binary)}))
    except BaseException as error:
        receipt.update(status="failed", error_type=type(error).__name__, error=str(error))
        raise
    finally:
        (logs / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
