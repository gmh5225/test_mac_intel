"""Build only public search sources in a pinned native Linux container."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tarfile
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parent
IMAGE = "rust@sha256:e51d0265072d2d9d5d320f6a44dde6b9ef13653b035098febd68cce8fa7c0bc4"
PROFILES = {
    ("x64", "glibc"): {"image": IMAGE, "jit": True, "rustflags": "-C target-feature=+ssse3,-avx2"},
    ("arm64", "glibc"): {"image": IMAGE, "jit": True, "rustflags": ""},
    ("x64", "musl"): {
        "image": "rust@sha256:813376c206852d4250641eb86720c04fd20fbc6547d1a030c93a45b22a1303a3",
        "jit": True, "rustflags": "-C target-feature=+ssse3,-avx2,+crt-static"},
    ("arm64", "musl"): {
        "image": "rust@sha256:8eed1d324a486196374b67025fe0a8a724245c42d0c3687fa8d6fc953228b9e3",
        "jit": False, "rustflags": "-C target-feature=+crt-static"},
}
SOURCES = [
    ("ripgrep", "https://codeload.github.com/BurntSushi/ripgrep/tar.gz/refs/tags/14.1.1", "ripgrep-14.1.1/",
     "4dad02a2f9c8c3c8d89434e47337aa654cb0e2aa50e806589132f186bf5c2b66"),
    ("pcre2", "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.45/pcre2-10.45.tar.gz", "pcre2-10.45/",
     "0e138387df7835d7403b8351e2226c1377da804e0737db0e071b48f07c9d12ee"),
]
def sha(path):
    with path.open("rb") as source: return hashlib.file_digest(source, "sha256").hexdigest()

def unpack(archive, root, prefix):
    root.mkdir()
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers(); assert len(members) < 10000
        for member in members:
            assert member.name.startswith(prefix) or member.name == prefix.rstrip("/")
            name = member.name[len(prefix):]
            if not name: continue
            path = root / name; assert path.resolve().is_relative_to(root.resolve())
            if member.isdir(): path.mkdir(parents=True, exist_ok=True)
            elif member.issym():
                assert not Path(member.linkname).is_absolute()
                assert (path.parent / member.linkname).resolve().is_relative_to(root.resolve())
                path.parent.mkdir(parents=True, exist_ok=True); path.symlink_to(member.linkname)
            else:
                assert member.isfile() and member.size < 16 * 1024 * 1024
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(tar.extractfile(member).read()); path.chmod(member.mode & 0o777)

def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--arch", choices=["x64", "arm64"], default="x64")
    parser.add_argument("--libc", choices=["glibc", "musl"], default="glibc"); args = parser.parse_args()
    native = {"x86_64": "x64", "AMD64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    assert platform.system() == "Linux" and native == args.arch, "Use the requested native Linux architecture"
    docker_platform = {"x64": "linux/amd64", "arm64": "linux/arm64"}[args.arch]
    profile = PROFILES[(args.arch, args.libc)]
    image = profile["image"]
    target = "linux-" + args.arch + ("-musl" if args.libc == "musl" else "")
    out = args.output.resolve(); out.mkdir()
    logs = out / "diagnostics"; logs.mkdir()
    sources = out / "sources"; sources.mkdir()
    build = out / "build"; build.mkdir()
    package = out / "public-search-helper"; package.mkdir()
    receipt = {"status": "started", "public_sources_only": True, "captured_client_executed": False,
               "container": image, "platform": target, "libc": args.libc, "profile": profile,
               "native_machine": platform.machine(), "sources": [], "commands": []}
    def run(name, command, timeout=1800):
        receipt["commands"].append({"name": name, "argv": list(map(str, command))})
        with (logs / (name + ".log")).open("xb") as log:
            result = subprocess.run(list(map(str, command)), stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        assert result.returncode == 0, name + " failed; inspect diagnostics"
    try:
        for label, url, prefix, digest in SOURCES:
            archive = sources / (label + ".tar.gz")
            with urllib.request.urlopen(url, timeout=90) as response: data = response.read(16 * 1024 * 1024 + 1)
            assert len(data) <= 16 * 1024 * 1024 and hashlib.sha256(data).hexdigest() == digest
            archive.write_bytes(data); unpack(archive, sources / label, prefix)
            receipt["sources"].append({"component": label, "url": url, "sha256": digest})
        shutil.copytree(sources / "ripgrep", build / "ripgrep", symlinks=True)
        run("pull", ["docker", "pull", "--platform", docker_platform, image])
        if args.libc == "musl":
            # The pinned Rust Alpine images contain gcc but lack make, headers and
            # pkg-config. Retain exact, signed APKs and install them without network.
            toolchain = sources / "musl-toolchain"; toolchain.mkdir()
            pins = json.loads((ROOT / "alpine-toolchain-pins.json").read_text())["packages"][args.arch]
            assert {p["package"] for p in pins} == {"make", "musl", "musl-dev", "pkgconf"}
            for pin in pins:
                assert Path(pin["name"]).name == pin["name"]
                with urllib.request.urlopen(pin["url"], timeout=90) as response: data = response.read(pin["bytes"] + 1)
                assert len(data) == pin["bytes"] and hashlib.sha256(data).hexdigest() == pin["sha256"]
                (toolchain / pin["name"]).write_bytes(data)
            (toolchain / "Dockerfile").write_text(
                f"FROM {image}\nCOPY *.apk /opt/helper-toolchain/\n"
                "RUN apk --no-network --no-cache add /opt/helper-toolchain/*.apk\n")
            image_id = logs / "musl-toolchain-image.id"
            run("musl-toolchain", ["docker", "build", "--platform", docker_platform, "--network", "none",
                                  "--iidfile", image_id, toolchain])
            image = image_id.read_text().strip()
            assert image.startswith("sha256:") and len(image) == 71
            receipt["musl_toolchain"] = {"base_image": profile["image"], "image_id": image, "packages": pins,
                                         "apk_signatures_required": True, "installation_network": "none"}
            shutil.copytree(toolchain, package / "musl-toolchain")
            shutil.copyfile(ROOT / "alpine-toolchain-pins.json", package / "alpine-toolchain-pins.json")
        base = ["docker", "run", "--rm", "--platform", docker_platform, "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--user", f"{os.getuid()}:{os.getgid()}", "--cpus", "2", "--memory", "4g",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m", "--mount", f"type=bind,src={build},dst=/build",
                "--env", "CARGO_HOME=/build/cargo-home", "--workdir", "/build/ripgrep"]
        run("cargo-fetch", [*base, image, "cargo", "fetch", "--locked"])
        from prepare_pcre2 import prepare
        shutil.copyfile(build / "ripgrep/Cargo.lock", package / "upstream-Cargo.lock")
        receipt["pcre2_version_overlay"] = prepare(build)
        run("resolve-overlay", [*base, "--network", "none", image, "cargo", "update", "-p", "pcre2", "--offline"])
        before = tomllib.loads((package / "upstream-Cargo.lock").read_text())["package"]
        after = tomllib.loads((build / "ripgrep/Cargo.lock").read_text())["package"]
        assert [p for p in before if p["name"] != "pcre2"] == [p for p in after if p["name"] != "pcre2"]
        original = [p for p in before if p["name"] == "pcre2"]; patched = [p for p in after if p["name"] == "pcre2"]
        assert len(original) == len(patched) == 1
        assert patched[0] == {k: v for k, v in original[0].items() if k not in ("source", "checksum")}
        run("build", [*base, "--network", "none", "--mount", f"type=bind,src={sources},dst=/source,readonly",
                      "--env", f"RUSTFLAGS={profile['rustflags']}", "--env", f"HELPER_LIBC={args.libc}",
                      "--env", "HELPER_PCRE2_JIT=" + ("enable" if profile["jit"] else "disable"),
                      "--mount", f"type=bind,src={ROOT / 'build-ripgrep.sh'},dst=/build-script.sh,readonly", image, "sh", "/build-script.sh"])
        binary = build / "rg"
        version = subprocess.check_output([binary, "--version"], text=True)
        assert version.startswith("ripgrep 14.1.1") and "features:+pcre2" in version
        jit_status = "available" if profile["jit"] else "unavailable"
        assert f"PCRE2 10.45 is available (JIT is {jit_status})" in version
        if args.libc == "musl": shutil.copyfile(build / "static-linkage.txt", package / "static-linkage.txt")
        fixture = out / "fixture.txt"; fixture.write_text("first\nNEEDLE\npreneedle\n🐈\n", encoding="utf-8")
        controls = []
        for name, argv, code, stdout in [
            ("literal", ["-n", "NEEDLE"], 0, "2:NEEDLE\n"),
            ("absent", ["absent-value"], 1, ""),
            ("invalid", ["["], 2, ""),
            ("pcre", ["-P", "-o", "(?<=pre)needle"], 0, "needle\n"),
            ("unicode", ["-o", "🐈"], 0, "🐈\n")]:
            result = subprocess.run([binary, "--no-config", *argv, fixture], capture_output=True, text=True, timeout=15)
            assert result.returncode == code and result.stdout == stdout, name
            assert ("regex parse error" in result.stderr) if name == "invalid" else not result.stderr
            controls.append({"case": name, "exit_code": code, "stdout": result.stdout, "stderr": result.stderr})
        shutil.copyfile(binary, package / "rg"); (package / "rg").chmod(0o555)
        for name in ["ripgrep.tar.gz", "pcre2.tar.gz"]: shutil.copyfile(sources / name, package / name)
        shutil.copyfile(build / "ripgrep/Cargo.lock", package / "Cargo.lock")
        shutil.copyfile(ROOT / "build-ripgrep.sh", package / "build-ripgrep.sh")
        shutil.copyfile(ROOT / "prepare_pcre2.py", package / "prepare_pcre2.py")
        shutil.copyfile(build / "pcre2-runtime-version.patch", package / "pcre2-runtime-version.patch")
        shutil.copyfile(build / "pcre2-overlay.json", package / "pcre2-overlay.json")
        shutil.copytree(build / "pcre2-overlay", package / "pcre2-overlay")
        shutil.copyfile(build / "ripgrep/Cargo.toml", package / "effective-ripgrep-Cargo.toml")
        shutil.copyfile(Path(__file__), package / "build.py")
        # Retain exact dependency archives, which include their source/licenses.
        dependencies = package / "cargo-crates"; dependencies.mkdir()
        for archive in (build / "cargo-home/registry/cache").glob("*/*.crate"):
            assert not (dependencies / archive.name).exists(); shutil.copyfile(archive, dependencies / archive.name)
        receipt.update(status="independent_search_helper_built_and_controlled", version=version, authored_controls=controls,
            binary_sha256=sha(binary), cargo_lock_sha256=sha(package / "Cargo.lock"),
            scope="Public upstream search component only. No original client, native multicall dispatcher or universal equivalence qualification.")
        (package / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        files = [{"file": path.relative_to(package).as_posix(), "sha256": sha(path), "bytes": path.stat().st_size}
                 for path in sorted(package.rglob("*")) if path.is_file()]
        (package / "MANIFEST.json").write_text(json.dumps({"files": files}, indent=2) + "\n")
        print(json.dumps({"status": receipt["status"], "binary_sha256": sha(binary), "manifest_sha256": sha(package / "MANIFEST.json")}))
    except Exception as error:
        receipt.update(status="failed", error_type=type(error).__name__, error=str(error)); raise
    finally: (logs / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")

if __name__ == "__main__": main()
