"""Compare the native role only after authored empty-root boundary checks pass."""
from pathlib import Path
import argparse
import base64
import hashlib
import json
import os
import platform
import re
import resource
import shutil
import signal
import subprocess
import tarfile
import urllib.request
from build import PINS, check_report, sha

ROOT = Path(__file__).resolve().parent


def compare_process_states(original, candidate, baseline, original_outer=None, candidate_outer=None):
    variable = {"pid_ns", "user_ns", "mount_ns"}
    expected = {"pid": 2, "ppid": 1, "uid": baseline["uid"], "gid": baseline["gid"],
                "cap_effective": 0, "cap_ambient": 0, "no_new_privs": 1, "seccomp": 2, "visible_pids": 2}
    for state, outer in [(original, original_outer or baseline), (candidate, candidate_outer or baseline)]:
        assert set(state) == set(expected) | variable
        assert {k: v for k, v in state.items() if k not in variable} == expected
        for key, prefix in [("pid_ns", "pid"), ("user_ns", "user"), ("mount_ns", "mnt")]:
            assert re.fullmatch(prefix + r":\[[1-9][0-9]*\]", state[key])
            assert re.fullmatch(prefix + r":\[[1-9][0-9]*\]", outer[key])
            assert state[key] != outer[key]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=["x64", "arm64"], required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bash-rg", type=Path, help="Also rebuild and qualify both actual Bash sandbox clients with this pinned public rg")
    args = parser.parse_args()
    assert platform.system() == "Linux" and {"x86_64": "x64", "aarch64": "arm64"}.get(platform.machine()) == args.arch
    assert os.getuid() != 0
    package = args.build.resolve() / "public-seccomp-helper"
    public = json.loads((package / "receipt.json").read_text())
    assert public["status"] == "public_helper_built_and_native_filter_controlled"
    assert public["arch"] == args.arch and public["helper_command"]["status"] == "exit_status_relay_observed"
    out = args.output.resolve()
    out.mkdir()
    logs = out / "diagnostics"
    logs.mkdir()
    inputs = out / "inputs"
    inputs.mkdir()
    root = out / "root"
    root.mkdir()
    for name in ["runtime", "proc", "dev", "tmp", "work", "home/test"]:
        (root / name).mkdir(parents=True, exist_ok=True)
    # Bind destinations must exist before the enclosing root becomes read-only.
    for name in ["client", "control", "driver", "descriptor-control", "supervision-control"]:
        (root / "runtime" / name).touch(exist_ok=False)
    receipt = {"status": "started", "arch": args.arch, "boundary_qualified": False,
               "captured_client_executed": False, "captured_client_execution_attempted": False, "captured_source_uploaded": False,
               "client_uploaded": False, "commands": [], "cases": []}

    def run(label, command, *, expected=0, timeout=60, limited=False):
        command = list(map(str, command))
        entry = {"label": label, "argv": command}
        receipt["commands"].append(entry)
        def limits():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_FSIZE, (262144, 262144))
            resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
            resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
        with (logs / (label + ".stdout")).open("xb") as stdout, (logs / (label + ".stderr")).open("xb") as stderr:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                start_new_session=True, preexec_fn=limits if limited else None,
                env={"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"})
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
                entry["timeout"] = True
                raise
        entry["exit_code"] = code
        if label.startswith("original-") and receipt["captured_client_executed"] is not True:
            # Distinguish an exec failure in the authored driver from an
            # unclassified client failure; successful role output confirms entry.
            driver_denial = code == 126 and (logs / (label + ".stderr")).read_text().startswith("namespace driver exec: ")
            receipt["captured_client_executed"] = False if driver_denial else None
        if expected is not None:
            assert code == expected, label + " failed; inspect diagnostics"
        return {"exit_code": code, "stdout": (logs / (label + ".stdout")).read_text(),
                "stderr": (logs / (label + ".stderr")).read_text()}

    try:
        sources = logs / "source"
        sources.mkdir()
        for name in ["original_acceptance.py", "original-pins.json", "boundary-control.c", "namespace-driver.c", "descriptor-control.c", "supervision-control.c", "extended_comparison.py", "test_original_comparison.py", "test_extended_comparison.py"]:
            shutil.copyfile(ROOT / name, sources / name)
        bwrap = Path(shutil.which("bwrap"))
        package_version = run("bwrap-package", ["dpkg-query", "-W", "-f=${Version}", "bubblewrap"])
        assert package_version["stdout"] == "0.6.1-1ubuntu0.3"
        receipt["bwrap"] = {"path": str(bwrap), "sha256": sha(bwrap), "package": package_version["stdout"]}
        assert run("bwrap-version", [bwrap, "--version"])["stdout"].strip() == "bubblewrap 0.6.1"
        profile = PINS["profiles"][args.arch]
        base = ["docker", "run", "--rm", "--platform", profile["docker_platform"], "--network", "none",
                "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--user", f"{os.getuid()}:{os.getgid()}", "--cpus", "2", "--memory", "512m", "--pids-limit", "64",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m", "--mount", f"type=bind,src={inputs},dst=/out",
                "--mount", f"type=bind,src={root},dst=/rootfs",
                "--mount", f"type=bind,src={ROOT},dst=/recipes,readonly", profile["image"]]
        run("compile-boundary", [*base, "gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
                                 "/recipes/boundary-control.c", "-o", "/out/boundary-control"])
        run("compile-boundary-dynamic", [*base, "gcc", "-O2", "-Wall", "-Wextra", "-Werror",
                                         "/recipes/boundary-control.c", "-o", "/out/boundary-control-dynamic"])
        run("compile-driver", [*base, "gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
                               "/recipes/namespace-driver.c", "-o", "/out/namespace-driver"])
        run("compile-descriptor-control", [*base, "gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
                                           "/recipes/descriptor-control.c", "-o", "/out/descriptor-control"])
        run("compile-supervision-control", [*base, "gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror",
                                            "/recipes/supervision-control.c", "-o", "/out/supervision-control"])
        triplet = {"x64": "x86_64-linux-gnu", "arm64": "aarch64-linux-gnu"}[args.arch]
        interpreter = {"x64": "/lib64/ld-linux-x86-64.so.2", "arm64": "/lib/ld-linux-aarch64.so.1"}[args.arch]
        libraries = [interpreter] + [f"/lib/{triplet}/" + name for name in
                                    ["libc.so.6", "librt.so.1", "libpthread.so.0", "libdl.so.2", "libm.so.6"]]
        copy_code = "from pathlib import Path;import shutil\n"
        copy_code += "for name in " + repr(libraries) + ":\n p=Path('/rootfs'+name);p.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(name,p)\n"
        run("copy-public-runtime", [*base, "python3", "-c", copy_code])
        assert (root / interpreter.lstrip('/')).stat().st_mode & 0o111
        receipt["runtime"] = {"image": profile["image"], "files": [
            {"file": name, "sha256": sha(root / name.lstrip('/')), "mode": oct((root / name.lstrip('/')).stat().st_mode & 0o777)} for name in libraries]}
        canary = out / "outside-canary"
        canary.write_text("owned outside fixture\n")
        control = package / "control"
        candidate = package / "apply-seccomp"
        for name in ["control", "apply-seccomp"]:
            assert sha(package / name) == public["binaries"][name]["sha256"]
        state_parent = out / "state"
        state_parent.mkdir()
        def isolated(label, executable, arguments, *, expected=0, role=False, descriptor=False, entrypoint="/runtime/client", seed=None):
            state = state_parent / label
            state.mkdir()
            for name, data in (seed or {}).items():
                assert Path(name).name == name
                target = state / name
                target.write_bytes(data)
                target.chmod(0o644)
            argv = [bwrap, "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
                    "--uid", str(os.getuid()), "--gid", str(os.getgid()), "--ro-bind", root, "/",
                    "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--bind", state, "/work",
                    "--ro-bind", executable, "/runtime/client", "--ro-bind", control, "/runtime/control",
                    "--ro-bind", inputs / "descriptor-control", "/runtime/descriptor-control",
                    "--ro-bind", inputs / "supervision-control", "/runtime/supervision-control",
                    "--chdir", "/work", "--clearenv", "--setenv", "HOME", "/home/test",
                    "--setenv", "PATH", "/unavailable", "--setenv", "LANG", "C", "--setenv", "LC_ALL", "C",
                    "--setenv", "BOUNDARY_OUTSIDE", str(canary)]
            if role:
                argv += ["--setenv", "ARGV0", "apply-seccomp"]
                argv += ["--ro-bind", inputs / "namespace-driver", "/runtime/driver"]
            if descriptor:
                assert role
                argv += ["--setenv", "NEVERD_ROUTE_FD3", "1"]
            command = ["/runtime/driver", entrypoint] if role else [entrypoint]
            result = run(label, [*argv, "--", *command, *arguments], expected=expected, timeout=30, limited=True)
            if entrypoint == "/runtime/supervision-control":
                evidence = logs / "supervision" / label
                evidence.mkdir(parents=True)
                for name in ["events.jsonl", "observer-worker.json"]:
                    if (state / name).is_file(): shutil.copyfile(state / name, evidence / name)
            if role:
                first, separator, rest = result["stdout"].partition("\n")
                prefix = "NEVERD_OUTER_NAMESPACE "
                assert separator and first.startswith(prefix)
                outer = json.loads(first[len(prefix):])
                assert set(outer) == {"pid_ns", "user_ns", "mount_ns"}
                for key, value in outer.items():
                    prefix = {"pid_ns": "pid", "user_ns": "user", "mount_ns": "mnt"}[key]
                    assert re.fullmatch(prefix + r":\[[1-9][0-9]*\]", value)
                result.update(stdout=rest, outer_namespace=outer)
            return result
        boundary = isolated("boundary-fixtures", inputs / "boundary-control", [])
        assert not boundary["stderr"]
        assert json.loads(boundary["stdout"]) == {"outside_errno": 2, "readonly_errno": 30, "shell_result": -1,
            "shell_errno": 2, "network_result": -1, "network_errno": 101, "uid": os.getuid()}
        assert (state_parent / "boundary-fixtures/allowed").read_text() == "owned fixture\n"
        dynamic_boundary = isolated("boundary-dynamic", inputs / "boundary-control-dynamic", [])
        assert dynamic_boundary == boundary
        assert (state_parent / "boundary-dynamic/allowed").read_text() == "owned fixture\n"
        baseline = isolated("boundary-state", control, ["process-state"])
        assert not baseline["stderr"]
        baseline_state = json.loads(baseline["stdout"])
        assert baseline_state["pid"] == 2 and baseline_state["ppid"] == 1 and baseline_state["visible_pids"] == 2
        assert baseline_state["cap_effective"] == baseline_state["cap_ambient"] == 0 and baseline_state["no_new_privs"] == 1
        assert baseline_state["uid"] == os.getuid() and baseline_state["gid"] == os.getgid()
        # First qualify the public helper's nested namespace path in this exact boundary.
        nested = isolated("boundary-public-helper", candidate, ["/runtime/control", "process-state"], role=True)
        assert not nested["stderr"]
        nested_state = json.loads(nested["stdout"])
        compare_process_states(nested_state, nested_state, baseline_state, nested["outer_namespace"], nested["outer_namespace"])
        receipt.update(boundary_qualified=True, boundary_controls={"fixtures": json.loads(boundary["stdout"]),
            "dynamic_fixtures": json.loads(dynamic_boundary["stdout"]),
            "outer": baseline_state, "nested_public_helper": nested_state,
            "nested_invocation_outer": nested["outer_namespace"]})
        (logs / "qualified-before-original.json").write_text(json.dumps(receipt, indent=2) + "\n")
        pin = json.loads((ROOT / "original-pins.json").read_text())[args.arch]
        archive = inputs / "published-input.tgz"
        digest = hashlib.sha512()
        size = 0
        with urllib.request.urlopen(pin["url"], timeout=90) as response, archive.open("xb") as target:
            while data := response.read(1024 * 1024):
                size += len(data)
                assert size < 160 * 1024 * 1024
                target.write(data)
                digest.update(data)
        assert digest.digest() == base64.b64decode(pin["integrity"])
        original = inputs / "original"
        with tarfile.open(archive, "r:gz") as tar:
            members = [m for m in tar.getmembers() if m.name == "package/claude"]
            assert len(members) == 1 and members[0].isfile() and members[0].size == pin["bytes"]
            with tar.extractfile(members[0]) as source, original.open("xb") as target:
                shutil.copyfileobj(source, target)
        assert sha(original) == pin["sha256"]
        original.chmod(0o500)
        receipt["original"] = pin
        receipt["captured_client_execution_attempted"] = True
        receipt["captured_client_executed"] = None
        for case, arguments, code in [
            ("usage", [], 1), ("exit-37", ["/runtime/control", "exit-37"], 37),
            ("policy", ["/runtime/control", "baseline"], 0),
            ("process-state", ["/runtime/control", "process-state"], 0),
            ("child-term", ["/runtime/control", "raise-term"], 143),
            ("child-kill", ["/runtime/control", "raise-kill"], 137),
            ("missing-command", ["/runtime/absent"], 1)]:
            observed = {}
            for name, exe in [("original", original), ("candidate", candidate)]:
                observed[name] = isolated(name + "-" + case, exe, arguments, expected=code, role=True)
                if name == "original":
                    receipt["captured_client_executed"] = True
            if case == "process-state":
                assert not observed["original"]["stderr"] and not observed["candidate"]["stderr"]
                compare_process_states(json.loads(observed["original"]["stdout"]), json.loads(observed["candidate"]["stdout"]), baseline_state,
                                       observed["original"]["outer_namespace"], observed["candidate"]["outer_namespace"])
            else:
                assert {k: v for k, v in observed["original"].items() if k != "outer_namespace"} == {
                    k: v for k, v in observed["candidate"].items() if k != "outer_namespace"}, case + " differs"
            if case == "policy":
                check_report(json.loads(observed["original"]["stdout"]), "baseline", True)
            receipt["cases"].append({"case": case, "observed": observed, "matches": True})
        descriptor_cases = []
        for case, arguments, code in [
            ("fd3-usage", [], 1), ("fd3-exit-37", ["/runtime/control", "exit-37"], 37),
            ("fd3-policy", ["/runtime/control", "baseline"], 0),
            ("fd3-close-before-payload", ["/runtime/descriptor-control", "close-and-report"], 0)]:
            observed = {name: isolated(name + "-" + case, exe, arguments, expected=code, role=True, descriptor=True)
                        for name, exe in [("original", original), ("candidate", candidate)]}
            assert {k: v for k, v in observed["original"].items() if k != "outer_namespace"} == {
                k: v for k, v in observed["candidate"].items() if k != "outer_namespace"}, case + " differs"
            if case == "fd3-usage":
                assert observed["original"]["stderr"] == "Usage: /proc/self/fd/3 <command> [args...]\n"
            elif case == "fd3-policy":
                check_report(json.loads(observed["original"]["stdout"]), "baseline", True)
            elif case == "fd3-close-before-payload":
                assert json.loads(observed["original"]["stdout"]) == {
                    "fd3_valid_before_close": True, "fd3_result_after_close": -1, "errno": 9}
            descriptor_cases.append({"case": case, "observed": observed, "matches": True})
        from extended_comparison import accept_extended
        extended = accept_extended(isolated, state_parent, original, candidate, args.arch, receipt.setdefault("extended", {}))
        if args.bash_rg:
            from bash_acceptance import accept_bash
            receipt["bash"] = accept_bash(args.arch, original, out, logs, run, bwrap, package, args.bash_rg.resolve(), receipt.setdefault("bash", {}))
        assert sha(original) == pin["sha256"]
        receipt.update(status="native_role_candidate_matches_extended_bounded_cases", descriptor_cases=descriptor_cases, extended=extended,
            namespace_normalization="Only three kernel-assigned namespace inode identities; each must be valid and differ from the same invocation's outer namespace recorded by the authored exec driver. Every other process-state field is exact.",
            scope="Seven direct and four descriptor-3 cases plus external signals and optional observer controls inside a qualified empty-root namespace boundary. Full recovered Bash integration and universal helper equivalence remain open.")
        print(json.dumps({"status": receipt["status"], "arch": args.arch, "cases": len(receipt["cases"]) + len(descriptor_cases)
                          + len(extended["external_signals"]) + len(extended["observers"])}))
    except Exception as error:
        receipt.update(status="failed", error_type=type(error).__name__, error=str(error))
        raise
    finally:
        (logs / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
