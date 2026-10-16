"""Build the public search component on a native macOS or Windows runner.

The retained archives and crates are hash pinned.  Captured client code is
neither an input nor an output.  PCRE2 is built and tested before the offline
Rust link; its older Rust bindings report the actual linked library version.
"""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import tarfile
import tomllib
import urllib.request

sys.dont_write_bytecode = True
from build import SOURCES, sha, unpack
from prepare_pcre2 import prepare

ROOT = Path(__file__).resolve().parent
RUST_VERSION = "1.88.0"
SYS_CRATE_SHA = "550f5d18fb1b90c20b87e161852c10cde77858c3900c5059b5ad2a1449f11d8a"
SYS_BUILD_SHA = "c906cc29a584f4863c7f3ed7198fa6ad2189749e21f104bd9e49709071d99f3d"
SYS_BUILD = '''// Recovery build: link only the separately built, pinned PCRE2 10.45.
fn main() {
    println!("cargo:rerun-if-env-changed=RECOVERY_PCRE2_LIBDIR");
    println!("cargo:rerun-if-env-changed=RECOVERY_PCRE2_LIBNAME");
    let dir = std::env::var("RECOVERY_PCRE2_LIBDIR").expect("missing PCRE2 library directory");
    let name = std::env::var("RECOVERY_PCRE2_LIBNAME").expect("missing PCRE2 library name");
    assert!(std::path::Path::new(&dir).is_absolute());
    assert!(name == "pcre2-8" || name == "pcre2-8-static");
    println!("cargo:rustc-link-search=native={dir}");
    println!("cargo:rustc-link-lib=static={name}");
}
'''


def unpack_portable(archive, destination, prefix):
    """Materialize the one pinned, unused development alias on Windows.

    The archive itself is retained verbatim.  Windows does not always grant
    symlink creation to its runner account; no link is silently dropped.
    """
    with tarfile.open(archive, "r:gz") as stream:
        links = [(m.name, m.linkname) for m in stream if m.issym() or m.islnk()]
    if os.name != "nt" or not links:
        unpack(archive, destination, prefix)
        return []
    assert prefix == "ripgrep-14.1.1/"
    assert links == [(prefix + "HomebrewFormula", "pkg/brew")]
    destination.mkdir()
    with tarfile.open(archive, "r:gz") as stream:
        members = stream.getmembers()
        assert len(members) < 10000
        seen = set()
        for member in members:
            assert member.name.startswith(prefix) or member.name == prefix.rstrip("/")
            name = member.name[len(prefix):]
            if not name:
                continue
            assert name.casefold() not in seen
            seen.add(name.casefold())
            path = destination / name
            assert path.resolve().is_relative_to(destination.resolve())
            if member.issym():
                continue
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                assert member.isfile() and member.size < 16 * 1024 * 1024
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(stream.extractfile(member).read())
    shutil.copytree(destination / "pkg/brew", destination / "HomebrewFormula")
    return [{"file": "HomebrewFormula", "target": "pkg/brew", "projection": "directory_copy"}]


def overlay_sys(build):
    crates = list((build / "cargo-home/registry/cache").glob("*/pcre2-sys-0.2.9.crate"))
    assert len(crates) == 1 and sha(crates[0]) == SYS_CRATE_SHA
    target = build / "pcre2-sys-overlay"
    unpack(crates[0], target, "pcre2-sys-0.2.9/")
    path = target / "build.rs"
    assert sha(path) == SYS_BUILD_SHA
    before = path.read_text()
    path.write_text(SYS_BUILD)
    patch = "".join(difflib.unified_diff(before.splitlines(True), SYS_BUILD.splitlines(True),
        fromfile="pcre2-sys-0.2.9/build.rs", tofile="pcre2-sys-overlay/build.rs"))
    (build / "pcre2-sys-link.patch").write_text(patch)
    manifest = build / "ripgrep/Cargo.toml"
    text = manifest.read_text()
    assert text.count("[patch.crates-io]") == 1 and "pcre2-sys = { path" not in text
    manifest.write_text(text + 'pcre2-sys = { path = "../pcre2-sys-overlay" }\n')
    return {"crate_sha256": SYS_CRATE_SHA, "original_build_rs_sha256": SYS_BUILD_SHA,
            "overlay_build_rs_sha256": sha(path), "patch_sha256": sha(build / "pcre2-sys-link.patch"),
            "scope": "Build linkage only; no Rust regex/search implementation is changed."}


def native_machine(path, system, arch):
    data = path.read_bytes()
    if system == "Windows":
        assert data[:2] == b"MZ"
        pe = struct.unpack_from("<I", data, 60)[0]
        assert data[pe:pe + 4] == b"PE\0\0"
        machine = struct.unpack_from("<H", data, pe + 4)[0]
        assert machine == {"x64": 0x8664, "arm64": 0xaa64}[arch]
    else:
        magic, machine = struct.unpack_from("<II", data)
        assert magic == 0xfeedfacf and machine == {"x64": 0x1000007, "arm64": 0x100000c}[arch]
    return machine


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", required=True, choices=["x64", "arm64"])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    system = platform.system()
    assert system in ["Darwin", "Windows"]
    host = os.environ.get("PROCESSOR_ARCHITEW6432", platform.machine()).lower()
    assert {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(host) == args.arch
    target = {("Darwin", "x64"): "x86_64-apple-darwin", ("Darwin", "arm64"): "aarch64-apple-darwin",
              ("Windows", "x64"): "x86_64-pc-windows-msvc", ("Windows", "arm64"): "aarch64-pc-windows-msvc"}[(system, args.arch)]
    out = args.output.resolve()
    out.mkdir()
    logs = out / "diagnostics"; logs.mkdir()
    sources = out / "sources"; sources.mkdir()
    build = out / "build"; build.mkdir()
    package = out / "public-search-helper"; package.mkdir()
    env = dict(os.environ, CARGO_HOME=str(build / "cargo-home"), CARGO_TARGET_DIR=str(build / "target"), CARGO_BUILD_JOBS="2")
    flags = "-C target-feature=+ssse3,-avx2" if args.arch == "x64" else ""
    if system == "Windows":
        flags += " -C target-feature=+crt-static"
    env["RUSTFLAGS"] = flags.strip()
    receipt = {"status": "started", "platform": ("darwin-" if system == "Darwin" else "win32-") + args.arch,
               "system": system, "host_machine": host, "target": target, "rust_version": RUST_VERSION,
               "pcre2_jit": True, "rustflags": env["RUSTFLAGS"], "commands": [], "sources": [],
               "public_sources_only": True, "captured_client_executed": False}

    def run(label, argv, *, cwd=None, timeout=1200, check=True):
        command = list(map(str, argv))
        receipt["commands"].append({"label": label, "argv": command, "cwd": str(cwd) if cwd else None})
        with (logs / (label + ".log")).open("xb") as stream:
            result = subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        if check:
            assert result.returncode == 0, label + " failed; inspect diagnostics"
        return result

    try:
        for label, url, prefix, digest in SOURCES:
            archive = sources / (label + ".tar.gz")
            with urllib.request.urlopen(url, timeout=90) as response:
                data = response.read(16 * 1024 * 1024 + 1)
            assert len(data) <= 16 * 1024 * 1024 and hashlib.sha256(data).hexdigest() == digest
            archive.write_bytes(data)
            projection = unpack_portable(archive, sources / label, prefix)
            receipt["sources"].append({"component": label, "url": url, "sha256": digest, "portable_projection": projection})
        shutil.copytree(sources / "ripgrep", build / "ripgrep", symlinks=True)
        run("rust-toolchain", ["rustup", "toolchain", "install", RUST_VERSION, "--profile", "minimal", "--target", target])
        cargo = ["rustup", "run", RUST_VERSION, "cargo"]
        run("rust-version", ["rustup", "run", RUST_VERSION, "rustc", "--version", "--verbose"])
        run("cmake-version", ["cmake", "--version"])
        run("cargo-fetch", [*cargo, "fetch", "--locked", "--target", target], cwd=build / "ripgrep")
        shutil.copyfile(build / "ripgrep/Cargo.lock", package / "upstream-Cargo.lock")
        receipt["pcre2_version_overlay"] = prepare(build)
        receipt["pcre2_sys_link_overlay"] = overlay_sys(build)
        run("resolve-overlays", [*cargo, "update", "-p", "pcre2", "-p", "pcre2-sys", "--offline"], cwd=build / "ripgrep")
        before = tomllib.loads((package / "upstream-Cargo.lock").read_text())["package"]
        after = tomllib.loads((build / "ripgrep/Cargo.lock").read_text())["package"]
        changed = {"pcre2", "pcre2-sys"}
        assert [p for p in before if p["name"] not in changed] == [p for p in after if p["name"] not in changed]
        for name in changed:
            old = [p for p in before if p["name"] == name]; new = [p for p in after if p["name"] == name]
            assert len(old) == len(new) == 1 and new[0] == {k: v for k, v in old[0].items() if k not in ["source", "checksum"]}
        install = build / "install"
        cmake = ["cmake", "-S", sources / "pcre2", "-B", build / "pcre2-build", "-G", "Ninja",
                 "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_INSTALL_PREFIX=" + str(install),
                 "-DBUILD_SHARED_LIBS=OFF", "-DBUILD_STATIC_LIBS=ON", "-DPCRE2_BUILD_PCRE2_8=ON",
                 "-DPCRE2_BUILD_PCRE2_16=OFF", "-DPCRE2_BUILD_PCRE2_32=OFF", "-DPCRE2_BUILD_PCRE2GREP=OFF",
                 "-DPCRE2_BUILD_TESTS=ON", "-DPCRE2_SUPPORT_JIT=ON", "-DPCRE2_STATIC_RUNTIME=ON"]
        if system == "Darwin":
            cmake += ["-DCMAKE_OSX_ARCHITECTURES=" + {"x64": "x86_64", "arm64": "arm64"}[args.arch],
                      "-DCMAKE_OSX_DEPLOYMENT_TARGET=13.0"]
            env["MACOSX_DEPLOYMENT_TARGET"] = "13.0"
        run("pcre2-configure", cmake)
        run("pcre2-build", ["cmake", "--build", build / "pcre2-build", "--parallel", "2"])
        run("pcre2-tests", ["ctest", "--test-dir", build / "pcre2-build", "--output-on-failure"], timeout=600)
        run("pcre2-install", ["cmake", "--install", build / "pcre2-build"])
        library_name = "pcre2-8-static" if system == "Windows" else "pcre2-8"
        filename = library_name + ".lib" if system == "Windows" else "lib" + library_name + ".a"
        libraries = list(install.rglob(filename))
        assert len(libraries) == 1
        env["RECOVERY_PCRE2_LIBDIR"] = str(libraries[0].parent)
        env["RECOVERY_PCRE2_LIBNAME"] = library_name
        receipt["pcre2_static_library"] = {"file": str(libraries[0].relative_to(out)), "sha256": sha(libraries[0])}
        run("cargo-build-offline", [*cargo, "build", "--release", "--features", "pcre2", "--locked", "--offline", "--target", target], cwd=build / "ripgrep")
        binary = build / "target" / target / "release" / ("rg.exe" if system == "Windows" else "rg")
        receipt["machine"] = native_machine(binary, system, args.arch)
        run("rg-version", [binary, "--version"], timeout=15)
        version = (logs / "rg-version.log").read_text()
        assert version.startswith("ripgrep 14.1.1") and "features:+pcre2" in version
        assert "PCRE2 10.45 is available (JIT is available)" in version
        fixture = out / "fixture.txt"; fixture.write_bytes("first\nNEEDLE\npreneedle\n🐈\n".encode())
        controls = []
        for label, argv, code, stdout in [
            ("literal", ["-n", "NEEDLE"], 0, "2:NEEDLE\n"),
            ("absent", ["absent-value"], 1, ""),
            ("invalid", ["["], 2, ""),
            ("pcre", ["-P", "-o", "(?<=pre)needle"], 0, "needle\n"),
            ("unicode", ["-o", "🐈"], 0, "🐈\n")]:
            result = subprocess.run([str(binary), "--no-config", *argv, str(fixture)], capture_output=True, env=env, timeout=15)
            observed_out = result.stdout.decode(); observed_err = result.stderr.decode()
            assert result.returncode == code and observed_out == stdout, label
            assert ("regex parse error" in observed_err) if label == "invalid" else not observed_err
            controls.append({"case": label, "exit_code": code, "stdout": observed_out, "stderr": observed_err})
        shutil.copyfile(binary, package / binary.name)
        (package / binary.name).chmod(0o555)
        for name in ["ripgrep.tar.gz", "pcre2.tar.gz"]:
            shutil.copyfile(sources / name, package / name)
        for name in ["build_native.py", "build.py", "prepare_pcre2.py"]:
            shutil.copyfile(ROOT / name, package / name)
        for name in ["pcre2-overlay", "pcre2-sys-overlay"]:
            shutil.copytree(build / name, package / name)
        for name in ["pcre2-runtime-version.patch", "pcre2-overlay.json", "pcre2-sys-link.patch"]:
            shutil.copyfile(build / name, package / name)
        shutil.copyfile(build / "ripgrep/Cargo.lock", package / "Cargo.lock")
        shutil.copyfile(build / "ripgrep/Cargo.toml", package / "effective-ripgrep-Cargo.toml")
        dependencies = package / "cargo-crates"; dependencies.mkdir()
        for archive in (build / "cargo-home/registry/cache").glob("*/*.crate"):
            assert not (dependencies / archive.name).exists()
            shutil.copyfile(archive, dependencies / archive.name)
        receipt.update(status="independent_native_search_helper_built_and_controlled", version=version,
            authored_controls=controls, binary_sha256=sha(binary),
            scope="Public source build and five authored component controls. Original-client comparison and native Bun dispatch are separate qualifications.")
        (package / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        files = [{"file": path.relative_to(package).as_posix(), "sha256": sha(path), "bytes": path.stat().st_size}
                 for path in sorted(package.rglob("*")) if path.is_file()]
        (package / "MANIFEST.json").write_text(json.dumps({"files": files}, indent=2) + "\n")
        print(json.dumps({"status": receipt["status"], "platform": receipt["platform"], "binary_sha256": sha(binary),
                          "manifest_sha256": sha(package / "MANIFEST.json")}))
    except BaseException as error:
        receipt.update(status="failed", error_type=type(error).__name__, error=str(error))
        raise
    finally:
        (logs / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
