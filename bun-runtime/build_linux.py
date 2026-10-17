"""Build a public Bun revision with a reconstructed Linux native selector."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import resource
import gzip

sys.dont_write_bytecode = True
from patch_bun import patch, sha
from prepare_sysroot import prepare
from native_libraries import qualify as qualify_native_libraries
from allocator_exports import verify_symbols as verify_allocator_symbols
from native_rg_controls import verify as verify_native_rg

ROOT = Path(__file__).resolve().parent
COMMIT = "c6da4a4d3010e5553438c60f6bd76d981976867c"
PROFILES = {
    "x64": {"machine": 62, "docker_platform": "linux/amd64",
            "image": "ghcr.io/oven-sh/bun-development-docker-image@sha256:ee053ca8ff0a00ab51c8572378fb56dee902063d5020b4d90fb78a098fb70af2",
            },
    "arm64": {"machine": 183, "docker_platform": "linux/arm64",
              "image": "ghcr.io/oven-sh/bun-development-docker-image@sha256:19e1898469e3ab456b90a4120c1b96644af53c019434c2f9852eb14870e13d11",
              },
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", required=True, choices=PROFILES)
    parser.add_argument("--native-libraries", required=True, type=Path)
    parser.add_argument("--bfs-libraries", type=Path)
    parser.add_argument("--ugrep-libraries", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    assert platform.system() == "Linux" and {"x86_64": "x64", "aarch64": "arm64"}[platform.machine()] == args.arch
    profile = PROFILES[args.arch]
    out = args.output.resolve(); out.mkdir()
    logs = out / "diagnostics"; logs.mkdir()
    source = out / "bun-source"
    native_package = args.native_libraries.resolve()
    native_inputs = qualify_native_libraries(args.arch, native_package)
    bfs_package = args.bfs_libraries.resolve() if args.bfs_libraries else None
    bfs_inputs = None
    if bfs_package is not None:
        from bfs_libraries import qualify as qualify_bfs_libraries
        bfs_inputs = qualify_bfs_libraries(args.arch, bfs_package, profile["image"])
    ugrep_package = args.ugrep_libraries.resolve() if args.ugrep_libraries else None
    ugrep_inputs = None
    if ugrep_package is not None:
        assert bfs_package is not None, "Ugrep integration requires the full C library profile"
        from ugrep_libraries import qualify as qualify_ugrep_libraries
        ugrep_inputs = qualify_ugrep_libraries(args.arch, ugrep_package, profile["image"])
    receipt = {"status": "started", "arch": args.arch, "public_bun_commit": COMMIT, "profile": profile,
               "original_bun_revision_recovered": False, "original_prefix_reused": False,
               "captured_client_executed": False, "commands": [], "native_source_provenance": native_inputs,
               "integration_strategy": "single-rust-source-graph-and-c", "compiled_native_archive_used": False}
    if bfs_inputs is not None:
        receipt.update(integration_strategy="single-rust-source-graph-with-c-source-libraries",
            compiled_native_archive_used=True, compiled_rust_archive_used=False, bfs_source_provenance=bfs_inputs)
    if ugrep_inputs is not None:
        receipt.update(ugrep_source_provenance=ugrep_inputs,ugrep_exception_metadata_preserved=True)

    def run(label, argv, *, cwd=None):
        receipt["commands"].append({"label": label, "argv": list(map(str, argv)), "cwd": str(cwd) if cwd else None})
        print("Starting " + label, flush=True)
        with (logs / (label + ".log")).open("xb") as stream:
            with subprocess.Popen(list(map(str, argv)), cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0) as process:
                for chunk in iter(lambda: process.stdout.read(65536), b""):
                    stream.write(chunk); stream.flush()
                    sys.stdout.buffer.write(chunk); sys.stdout.buffer.flush()
                status = process.wait()
        assert status == 0, label + " failed; inspect retained diagnostics"

    try:
        run("git-init", ["git", "init", source])
        run("git-remote", ["git", "remote", "add", "origin", "https://github.com/oven-sh/bun.git"], cwd=source)
        run("git-fetch", ["git", "fetch", "--depth", "1", "origin", COMMIT], cwd=source)
        run("git-checkout", ["git", "checkout", "--detach", COMMIT], cwd=source)
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
        assert actual == COMMIT
        receipt["source_patch"] = patch(source, logs / "source-patch", native_package, bfs_package, ugrep_package)
        prepare(args.arch, out, logs)
        receipt["sysroot_receipt_sha256"] = sha(logs / "sysroot-receipt.json")
        run("compiler-image-pull", ["docker", "pull", "--platform", profile["docker_platform"], profile["image"]])
        run("compiler-image-inspect", ["docker", "image", "inspect", profile["image"]])
        # The public compiler image stores its toolchain under root's home;
        # its root process needs DAC override to write this freshly owned
        # runner checkout. No captured client runs in this compiler profile.
        command = ["docker", "run", "--rm", "--platform", profile["docker_platform"], "--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE",
                   "--security-opt", "no-new-privileges", "--cpus", "4", "--memory", "12g", "--pids-limit", "512",
                   "--mount", f"type=bind,src={out},dst=/output", "--mount", f"type=bind,src={ROOT},dst=/recipes,readonly",
                   "--entrypoint", "/bin/bash",
                   profile["image"], "/recipes/build-runtime.sh"]
        run("bun-source-build", command)
        duplicate_checks=re.findall(r"\[check\] bun-profile ([0-9]+) duplicate strong symbols",(logs/"bun-source-build.log").read_text())
        assert duplicate_checks==["0"], "Native source graph has ambiguous duplicate strong-symbol ownership"
        receipt["duplicate_strong_symbol_checks"]=dict(status="zero_duplicate_strong_symbols",count=0)
        binary = source / "build/recovery/bun"
        assert binary.is_file()
        data = binary.read_bytes()
        assert data[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", data, 18)[0] == profile["machine"]
        run("runtime-version-info", ["readelf", "--version-info", binary])
        versions = {tuple(map(int, value.split("."))) for value in re.findall(r"GLIBC_([0-9]+(?:\.[0-9]+)+)", (logs / "runtime-version-info.log").read_text())}
        assert versions and max(versions) <= (2, 17), "Source engine exceeds the upstream glibc portability floor"
        receipt["maximum_core_glibc_requirement"] = ".".join(map(str, max(versions)))
        run("runtime-dynamic-symbols", ["readelf", "--dyn-syms", "--wide", binary])
        receipt["allocator_symbol_versions"] = verify_allocator_symbols((logs / "runtime-dynamic-symbols.log").read_text(), args.arch)
        if ugrep_package is not None:
            run("runtime-exception-sections", ["readelf", "--sections", "--wide", binary])
            sections = (logs / "runtime-exception-sections.log").read_text()
            assert all(re.search(r"\s"+re.escape(name)+r"\s",sections) for name in [".eh_frame",".eh_frame_hdr",".gcc_except_table"]), "Ugrep exception metadata was stripped"
            run("runtime-exception-program-headers", ["readelf", "--program-headers", "--wide", binary])
            assert "GNU_EH_FRAME" in (logs / "runtime-exception-program-headers.log").read_text()
        receipt["native_rg_filename_controls"] = verify_native_rg(binary, logs / "native-rg-filename-controls")
        controls = []
        receipt["authored_controls"] = controls
        fixture = out / "native-search-fixture.txt"; fixture.write_text("first\nNEEDLE\npreneedle\n")
        control_cases = [
            ("runtime-version", str(binary), None, ["--version"], 0, "1.4.3"),
            ("rg-environment", str(binary), "rg", ["--version"], 0, "ripgrep 14.1.1"),
            ("rg-actual-basename", "/fixture/rg", "apply-seccomp", ["--version"], 0, "ripgrep 14.1.1"),
            ("seccomp-usage", str(binary), "apply-seccomp", [], 1, "Usage:"),
            ("ugrep-explicit-unsupported", str(binary), "ugrep", ["--version"], 126, "implementation is not integrated"),
            ("bfs-explicit-unsupported", str(binary), "bfs", ["--version"], 126, "implementation is not integrated"),
            ("consume-unknown-role", str(binary), "unknown", ["-e", "console.log(process.env.ARGV0 === undefined)"], 0, "true"),
            ("raw-env-does-not-take-basename", str(binary), "/fixture/rg", ["--version"], 0, "1.4.3"),
            ("rg-zero-file-budget-search", str(binary), "rg", ["--no-config", "-n", "NEEDLE", str(fixture)], 0, "2:NEEDLE\n"),
            ("rg-zero-file-budget-pcre", str(binary), "rg", ["--no-config", "-P", "-o", "(?<=pre)needle", str(fixture)], 0, "needle\n"),
        ]
        if bfs_package is not None:
            control_cases[5] = ("bfs-environment", str(binary), "bfs", ["--version"], 0, "bfs 4.1.1")
            control_cases.extend([
                ("bfs-zero-file-budget-name", str(binary), "bfs", [str(out), "-maxdepth", "1", "-name", fixture.name, "-print"], 0, str(fixture) + "\n"),
                ("bfs-zero-file-budget-regex", str(binary), "bfs", [str(out), "-maxdepth", "1", "-regextype", "posix-extended", "-regex", ".*/native-search-fixture[.]txt", "-print"], 0, str(fixture) + "\n"),
            ])
        if ugrep_package is not None:
            control_cases[4] = ("ugrep-environment", str(binary), "ugrep", ["--version"], 0, "ugrep 7.8.4")
            compressed = out / "native-search-fixture.gz"
            compressed.write_bytes(gzip.compress(fixture.read_bytes(),mtime=0))
            control_cases.extend([
                ("ugrep-zero-file-budget-literal", str(binary), "ugrep", ["--no-config", "-n", "NEEDLE", str(fixture)], 0, "2:NEEDLE\n"),
                ("ugrep-zero-file-budget-pcre", str(binary), "ugrep", ["--no-config", "-P", "-o", "(?<=pre)needle", str(fixture)], 0, "needle\n"),
                ("ugrep-zero-file-budget-gzip", str(binary), "ugrep", ["--no-config", "-z", "-n", "NEEDLE", str(compressed)], 0, "2:NEEDLE\n"),
                ("ugrep-zero-file-budget-invalid", str(binary), "ugrep", ["--no-config", "[", str(fixture)], 2, "mismatched [ ]"),
                ("ugrep-zero-file-budget-absent", str(binary), "ugrep", ["--no-config", "absent-value", str(fixture)], 1, ""),
                ("ugrep-actual-basename", "/fixture/ug", "bfs", ["--version"], 0, "ugrep 7.8.4"),
            ])
        for label, argv0, role, argv, expected_code, expected_text in control_cases:
            env = dict(os.environ)
            env.pop("ARGV0", None)
            env["BUN_RUNTIME_TRANSPILER_CACHE_PATH"] = "0"
            if role is not None:
                env["ARGV0"] = role
            def no_file_writes():
                resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            result = subprocess.run([argv0, *argv], executable=binary, env=env, capture_output=True, timeout=30, preexec_fn=no_file_writes)
            stdout = result.stdout.decode(errors="replace"); stderr = result.stderr.decode(errors="replace")
            (logs / (label + ".stdout")).write_bytes(result.stdout)
            (logs / (label + ".stderr")).write_bytes(result.stderr)
            row = {"case": label, "exit_code": result.returncode, "stdout": stdout, "stderr": stderr,
                   "expected_code": expected_code, "expected_text": expected_text, "rlimit_fsize": 0}
            controls.append(row)
            assert result.returncode == expected_code and expected_text in stdout + stderr, label
            if label == "rg-environment":
                assert "(rev " not in stdout and "PCRE2 10.45 is available (JIT is available)" in stdout, "rg used a different PCRE2 runtime or leaked a parent revision"
            if label == "bfs-environment":
                assert result.stdout == (bfs_package / "expected-original-version.txt").read_bytes() and not result.stderr, "Bfs full original version metadata differs"
            if label in ["ugrep-environment","ugrep-actual-basename"]:
                assert result.stdout == (ugrep_package / "expected-original-version.txt").read_bytes() and not result.stderr, "Ugrep full original version metadata differs"
            ug_outputs = {"ugrep-zero-file-budget-literal":b"2:NEEDLE\n", "ugrep-zero-file-budget-pcre":b"needle\n", "ugrep-zero-file-budget-gzip":b"2:NEEDLE\n", "ugrep-zero-file-budget-absent":b""}
            if label in ug_outputs:
                assert result.stdout == ug_outputs[label] and not result.stderr, "Ugrep result differs: "+label
            if label == "ugrep-zero-file-budget-invalid":
                assert not result.stdout and b"mismatched [ ]" in result.stderr
        package = out / "public-bun-runtime"; package.mkdir()
        shutil.copyfile(binary, package / "bun"); (package / "bun").chmod(0o555)
        for name in ["role_contract.rs", "recovered_multicall.rs", "patch_bun.py", "build_linux.py", "build-runtime.sh", "prepare_sysroot.py", "glibc-sysroot-pins.json", "native_libraries.py", "native-library-pins.json", "stage_native_sources.py", "rust_source_graph.py", "verify_rust_plan.py", "resolved-Cargo.lock", "allocator_exports.py", "native_rg_controls.py"]:
            shutil.copyfile(ROOT / name, package / name)
        shutil.copytree(native_package / "inputs", package / "native-component-source-inputs")
        for name in ["apply-seccomp.c", "unix-block-bpf.h", "SECCOMP-LICENSE", "recovery_lib.rs", "effective-library-Cargo.toml"]:
            shutil.copyfile(native_package / name, package / name)
        shutil.copyfile(native_package / "MANIFEST.json", package / "native-component-input-manifest.json")
        if bfs_package is not None:
            shutil.copytree(bfs_package, package / "bfs-source-library-inputs")
            for name in ["bfs_libraries.py", "bfs-library-pins.json"]:
                shutil.copyfile(ROOT / name, package / name)
            shutil.copyfile(source / "src/runtime/bin_entry/recovered_multicall.rs", package / "effective_recovered_multicall.rs")
        if ugrep_package is not None:
            shutil.copytree(ugrep_package, package / "ugrep-source-library-inputs")
            for name in ["ugrep_libraries.py","ugrep-library-pins.json"]:
                shutil.copyfile(ROOT / name,package / name)
        shutil.copyfile(logs / "single-rust-graph.json", package / "single-rust-graph.json")
        shutil.copyfile(source / "build/recovery/rust-target/plan.json", package / "rust-plan.json")
        for name in ["LICENSE.md", "Cargo.lock", "rust-toolchain.toml"]:
            shutil.copyfile(source / name, package / name)
        receipt["rust_graph"] = json.loads((logs / "single-rust-graph.json").read_bytes())
        receipt["resolved_cargo_lock_sha256"] = sha(source / "Cargo.lock")
        receipt.update(status="public_bun_source_build_and_bounded_native_dispatch_controls_passed",
                       runtime_sha256=sha(binary), runtime_bytes=binary.stat().st_size, authored_controls=controls,
                       zero_file_budget_controls_passed=True,
                       scope="Public Bun source with rg/std in one Rust graph and C seccomp before VM setup. Ten controls pass with a zero file budget. Original revision, Ugrep/Bfs integration and captured-client acceptance remain open.")
        if bfs_package is not None:
            receipt["scope"] = "Public Bun source with rg/std in one Rust graph, directly linked qualified C Bfs/Oniguruma libraries and C seccomp. Twelve zero-file-budget controls, including exact original Bfs version bytes. Ugrep, original Bun revision and actual-client acceptance remain open."
        if ugrep_package is not None:
            receipt["scope"] = "Public Bun source with rg/std in one graph, C seccomp and qualified Ugrep/Bfs source archives before VM setup. Eighteen zero-file-budget controls pass with Ugrep C++ exception metadata retained. Private revision and complete client acceptance for this engine remain open."
        (package / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        files = [{"file": path.relative_to(package).as_posix(), "sha256": sha(path), "bytes": path.stat().st_size}
                 for path in sorted(package.rglob("*")) if path.is_file()]
        (package / "MANIFEST.json").write_text(json.dumps({"files": files}, indent=2) + "\n")
        print(json.dumps({"status": receipt["status"], "runtime_sha256": sha(binary)}))
    except BaseException as error:
        receipt.update(status="failed", error_type=type(error).__name__, error=str(error))
        raise
    finally:
        for report in (source/"build/recovery").glob("*.duplicate-symbols.txt"):
            if report.is_file():shutil.copyfile(report,logs/report.name)
        binary = source / "build/recovery/bun"
        if receipt["status"] == "failed" and binary.is_file():
            shutil.copyfile(binary, logs / "public-unqualified-bun")
            receipt["unqualified_runtime_sha256"] = sha(binary)
        plan = source / "build/recovery/rust-target/plan.json"
        if plan.is_file(): shutil.copyfile(plan, logs / "rust-plan.json")
        lock = source / "Cargo.lock"
        if lock.is_file(): shutil.copyfile(lock, logs / "final-Cargo.lock")
        (logs / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
