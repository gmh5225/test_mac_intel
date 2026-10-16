"""Build public seccomp sources and check their policy on a native Linux kernel."""
from pathlib import Path
import argparse
import errno
import hashlib
import json
import os
import platform
import shutil
import signal
import struct
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parent
PINS = json.loads((ROOT / "pins.json").read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_static_elf(path, machine):
    data = path.read_bytes()
    assert data[:7] == b"\x7fELF\x02\x01\x01"
    assert struct.unpack_from("<H", data, 18)[0] == machine
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    assert size == 56 and 0 < count < 100
    assert offset + size * count <= len(data)
    # These builds must have neither an interpreter nor a dynamic section.
    assert all(struct.unpack_from("<I", data, offset + size * i)[0] not in (2, 3)
               for i in range(count))


def check_report(data, mode, filtered):
    assert set(data) == {"mode", "no_new_privs", "seccomp", "cases"}
    assert data["mode"] == mode
    assert data["no_new_privs"] in (0, 1) and data["seccomp"] in (0, 2)
    if filtered:
        assert data["no_new_privs"] == 1 and data["seccomp"] == 2
    names = ["unix", "unix-high-bits", "inet", "inet6", "unix-pair",
             "uring-setup", "uring-enter", "uring-register"]
    assert [case["case"] for case in data["cases"]] == names
    for case in data["cases"]:
        assert set(case) == {"case", "result", "errno"}
        if filtered and case["case"] in (names[:2] + names[5:]):
            assert (case["result"], case["errno"]) == (-1, errno.EPERM)
        elif case["case"].startswith("uring-"):
            assert case["result"] == -1 and case["errno"] > 0
        else:
            assert (case["result"], case["errno"]) == (0, 0)


def namespace_unavailable(stderr):
    operations = ["unshare(CLONE_NEWUSER)",
                  "unshare(CLONE_NEWPID|CLONE_NEWNS) after userns",
                  "write /proc/self/uid_map", "write /proc/self/gid_map",
                  "write /proc/self/setgroups (nested userns is capability-restricted; caller must provide CAP_SYS_ADMIN)"]
    return stderr in {f"apply-seccomp: {operation}: {error}\n"
                      for operation in operations for error in ["Operation not permitted", "Permission denied"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=["x64", "arm64"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    native = {"x86_64": "x64", "aarch64": "arm64"}.get(platform.machine())
    assert platform.system() == "Linux" and native == args.arch, "A matching native Linux host is required"
    assert os.getuid() != 0, "Run controls as an unprivileged user"
    profile = PINS["profiles"][args.arch]
    out = args.output.resolve()
    out.mkdir()
    logs = out / "diagnostics"
    logs.mkdir()
    package = out / "public-seccomp-helper"
    package.mkdir()
    sources = package / "sources"
    sources.mkdir()
    build = out / "build"
    build.mkdir()
    receipt = {"status": "started", "arch": args.arch, "profile": profile,
               "native_machine": platform.machine(), "kernel": platform.release(),
               "public_sources_only": True, "captured_client_executed": False,
               "commands": [], "sources": []}

    def run(label, command, expected=0, timeout=120):
        command = list(map(str, command))
        entry = {"label": label, "argv": command}
        receipt["commands"].append(entry)
        # Preserve output while ensuring a timed-out helper's descendants die.
        with (logs / (label + ".stdout")).open("xb") as stdout, (logs / (label + ".stderr")).open("xb") as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                       start_new_session=True, env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"})
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
                entry["timeout"] = True
                raise
        entry["exit_code"] = code
        if expected is not None:
            assert code == expected, label + " failed; see diagnostics"
        return code, (logs / (label + ".stdout")).read_text(), (logs / (label + ".stderr")).read_text()

    try:
        for pin in PINS["sources"]:
            target = sources / pin["file"]
            target.parent.mkdir(parents=True, exist_ok=True)
            with urllib.request.urlopen(pin["url"], timeout=60) as response:
                data = response.read(pin["bytes"] + 1)
            assert len(data) == pin["bytes"] and hashlib.sha256(data).hexdigest() == pin["sha256"]
            target.write_bytes(data)
            receipt["sources"].append(pin)
        for name in ["build.py", "control.c", "pins.json", "README.md", "test_controls.py"]:
            shutil.copyfile(ROOT / name, package / name)
        headers = build / "headers"
        headers.mkdir()
        text = (sources / "libseccomp/include/seccomp.h.in").read_text()
        for part, value in [("MAJOR", "2"), ("MINOR", "5"), ("MICRO", "4")]:
            text = text.replace("@VERSION_" + part + "@", value)
        assert "@VERSION_" not in text
        (headers / "seccomp.h").write_text(text)
        shutil.copyfile(sources / "libseccomp/include/seccomp-syscalls.h", headers / "seccomp-syscalls.h")
        image = profile["image"]
        run("pull", ["docker", "pull", "--platform", profile["docker_platform"], image], timeout=600)
        base = ["docker", "run", "--rm", "--platform", profile["docker_platform"],
                "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--user", f"{os.getuid()}:{os.getgid()}", "--cpus", "2", "--memory", "512m", "--pids-limit", "64",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m",
                "--mount", f"type=bind,src={sources},dst=/source,readonly",
                "--mount", f"type=bind,src={package / 'control.c'},dst=/control.c,readonly",
                "--mount", f"type=bind,src={build},dst=/out", image]
        _, actual, _ = run("library-hash", [*base, "sha256sum", profile["library"]])
        assert actual.split()[0] == profile["library_sha256"]
        run("compiler-version", [*base, "gcc", "--version"])
        run("build-generator", [*base, "gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-I/out/headers",
                               "/source/sandbox-runtime/vendor/seccomp-src/seccomp-unix-block.c", profile["library"],
                               "-o", "/out/generator"])
        _, stdout, stderr = run("reject-architecture", [*base, "/out/generator", "/out/rejected.bpf", "unsupported"], expected=1)
        assert not stdout and "Unsupported arch" in stderr and not (build / "rejected.bpf").exists()
        header = []
        filters = {}
        for index, (arch, pin) in enumerate(PINS["filters"].items()):
            run("generate-" + arch, [*base, "/out/generator", "/out/" + arch + ".bpf", arch])
            bpf = build / (arch + ".bpf")
            assert bpf.stat().st_size == pin["bytes"] and sha(bpf) == pin["sha256"]
            filters[arch] = bpf.read_bytes()
            header += [("#if" if index == 0 else "#elif") + " defined(" + pin["define"] + ")",
                       "static const unsigned char unix_block_bpf[] = {"]
            header += ["    " + ", ".join(f"0x{b:02x}" for b in bpf.read_bytes()[i:i + 8]) + ","
                       for i in range(0, pin["bytes"], 8)]
            header.append("};")
        header += ["#else", '#error "unsupported architecture for unix-block BPF filter"', "#endif"]
        (build / "unix-block-bpf.h").write_text("\n".join(header) + "\n")
        for name, source in [("apply-seccomp", "/source/sandbox-runtime/vendor/seccomp-src/apply-seccomp.c"),
                             ("control", "/control.c")]:
            for suffix in ["", "-repeat"]:
                run("build-" + name + suffix, [*base, "gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
                    "-I/out", source, "-o", "/out/" + name + suffix])
            binary = build / name
            assert binary.read_bytes() == (build / (name + "-repeat")).read_bytes()
            check_static_elf(binary, profile["elf_machine"])
            assert binary.read_bytes().count(filters[profile["filter_arch"]]) == 1
        helper, control = build / "apply-seccomp", build / "control"
        _, stdout, stderr = run("helper-usage", [helper], expected=1)
        assert stdout == "" and stderr == f"Usage: {helper} <command> [args...]\n"
        reports = {}
        for mode in ["baseline", "filter", "filter-exec"]:
            _, stdout, stderr = run("control-" + mode, [control, mode], timeout=15)
            assert not stderr
            report = json.loads(stdout)
            check_report(report, "inherited" if mode == "filter-exec" else mode, mode != "baseline")
            reports[mode] = report
        assert reports["filter"]["cases"] == reports["filter-exec"]["cases"]
        _, stdout, stderr = run("control-malformed-filter", [control, "malformed-filter"], timeout=15)
        assert not stderr and json.loads(stdout) == {"case": "malformed-filter", "result": -1, "errno": errno.EINVAL}
        # This observation cannot convert an unavailable namespace into a pass.
        code, stdout, stderr = run("helper-command", [helper, control, "exit-37"], expected=None, timeout=15)
        assert not stdout
        if code == 37 and not stderr:
            helper_command = {"status": "exit_status_relay_observed", "exit_code": 37}
            _, stdout, stderr = run("helper-policy", [helper, control, "baseline"], timeout=15)
            assert not stderr
            report = json.loads(stdout)
            check_report(report, "baseline", True)
            helper_command["policy"] = report
        else:
            assert code == 1 and namespace_unavailable(stderr), "Unexpected helper command failure"
            helper_command = {"status": "unavailable_in_runner", "exit_code": code, "stderr": stderr}
        receipt.update(status="public_helper_built_and_native_filter_controlled", native_kernel_controls=reports,
                       malformed_filter_rejected=True, helper_command=helper_command,
                       binaries={name: {"sha256": sha(build / name), "bytes": (build / name).stat().st_size}
                                 for name in ["apply-seccomp", "control"]},
                       independent_builds_identical=True, filters=PINS["filters"],
                       scope="Exact public filter data with native kernel controls. Full original helper equivalence and recovered client dispatch remain unqualified.")
        for name in ["apply-seccomp", "control", "unix-block-bpf.h", "x86_64.bpf", "aarch64.bpf"]:
            shutil.copyfile(build / name, package / name)
        for name in ["apply-seccomp", "control"]:
            (package / name).chmod(0o555)
        shutil.copytree(headers, package / "headers")
        (package / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        files = [{"file": p.relative_to(package).as_posix(), "bytes": p.stat().st_size, "sha256": sha(p)}
                 for p in sorted(package.rglob("*")) if p.is_file()]
        (package / "MANIFEST.json").write_text(json.dumps({"files": files}, indent=2) + "\n")
        print(json.dumps({"status": receipt["status"], "binaries": receipt["binaries"], "helper_command": helper_command["status"]}))
    except Exception as error:
        receipt.update(status="failed", error_type=type(error).__name__, error=str(error))
        raise
    finally:
        (logs / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
