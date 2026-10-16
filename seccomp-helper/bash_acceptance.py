"""Native, offline, actual Bash-tool comparisons in an authored empty root."""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import urllib.request
from build import PINS, sha
from native_client_build import build_clients
from compare_bash import Normalize, differences

ROOT = Path(__file__).resolve().parent
RG_SHA = {"x64": "3984a55c6cf39c362a1ae15e5c347ea2870ba3dd883a3da4865d5082ffe35a58",
          "arm64": "77d1249f185d04a63c3494fb327a5486359d0e80aef967ff3366efd82dfc8546"}


def cases():
    return [
        {"id": "B01-policy", "command": "/runtime/bash-payload policy", "error": False,
         "contains": ['"sandboxed":true', '"unix_errno":1', '"write_denied_errno":30', '"read_denied_errno":2'],
         "files": {"input.txt": "fixture input\n", "allowed": "sandbox write\n"}},
        {"id": "B02-streams-unicode", "command": "printf 'stdout α 🐈\\n'; printf 'stderr fixture\\n' >&2", "error": False,
         "contains": ["stdout α 🐈", "stderr fixture"], "files": {"input.txt": "fixture input\n"}},
        {"id": "B03-exit-37", "command": "printf 'before exit\\n'; exit 37", "error": True,
         "contains": ["before exit", "Exit code 37"], "files": {"input.txt": "fixture input\n"}},
        {"id": "B04-pipeline-write-read", "command": "printf 'pipeline fixture\\n' | cat > result.txt; cat result.txt", "error": False,
         "contains": ["pipeline fixture"], "files": {"input.txt": "fixture input\n", "result.txt": "pipeline fixture\n"}},
        {"id": "B05-denied-write", "command": "printf 'forbidden' > /protected/forbidden", "error": True,
         "contains": ["Read-only file system"], "files": {"input.txt": "fixture input\n"}},
        {"id": "B06-denied-read", "command": "cat /secret/input", "error": True,
         "contains": ["No such file or directory"], "files": {"input.txt": "fixture input\n"}},
        {"id": "B07-fd3-closed", "command": "if [ -e /proc/self/fd/3 ]; then printf 'descriptor leaked\\n'; exit 77; fi; printf 'descriptor closed\\n'", "error": False,
         "contains": ["descriptor closed"], "files": {"input.txt": "fixture input\n"}},
    ]


def accept_bash(arch, original, output, parent_logs, run, bwrap, seccomp_package, rg, partial):
    assert sha(rg) == RG_SHA[arch]
    out = output / "bash"; out.mkdir()
    logs = parent_logs / "bash"; logs.mkdir()
    sources = logs / "source"; sources.mkdir()
    for name in ["bash_acceptance.py", "bash-driver.cpp", "bash-payload.c", "offline-fixture.cpp", "compare_bash.py",
                 "native_client_build.py", "format_recipe.py", "extract-linux-graph.cpp", "native-graph-location.h",
                 "raw-graph-linux-adapter.cpp", "graph-fidelity-linux-adapter.cpp"]:
        shutil.copyfile(ROOT / name, sources / name)
    (logs / "case-matrix.json").write_text(json.dumps(cases(), ensure_ascii=False, indent=2) + "\n")
    profile = PINS["profiles"][arch]
    triplet = {"x64": "x86_64-linux-gnu", "arm64": "aarch64-linux-gnu"}[arch]
    loader = {"x64": "/lib64/ld-linux-x86-64.so.2", "arm64": "/lib/ld-linux-aarch64.so.1"}[arch]
    inputs = out / "inputs"; inputs.mkdir()
    include = inputs / "include/nlohmann"; include.mkdir(parents=True)
    with urllib.request.urlopen("https://raw.githubusercontent.com/nlohmann/json/v3.11.3/single_include/nlohmann/json.hpp", timeout=60) as source:
        header = source.read(1024 * 1024)
    assert hashlib.sha256(header).hexdigest() == "9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6"
    (include / "json.hpp").write_bytes(header)
    compiler = ["docker", "run", "--rm", "--platform", profile["docker_platform"], "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--user", f"{os.getuid()}:{os.getgid()}", "--memory", "2g", "--cpus", "2",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m", "--mount", f"type=bind,src={inputs},dst=/out",
                "--mount", f"type=bind,src={ROOT},dst=/recipes,readonly", profile["image"]]
    run("bash-compile-driver", [*compiler, "g++", "-std=c++20", "-static", "-O2", "-Wall", "-Wextra", "-Werror", "-I/out/include",
                                "/recipes/bash-driver.cpp", "-pthread", "-o", "/out/bash-driver"], timeout=180)
    run("bash-compile-payload", [*compiler, "gcc", "-static", "-O2", "-Wall", "-Wextra", "-Werror", "/recipes/bash-payload.c", "-o", "/out/bash-payload"], timeout=60)
    run("bash-compile-dynamic-control", ["cc", "-O2", "-Wall", "-Wextra", "-Werror", ROOT / "bash-payload.c",
        "-Wl,--push-state,--no-as-needed", *[f"/lib/{triplet}/" + name for name in ["librt.so.1", "libpthread.so.0", "libdl.so.2", "libm.so.6"]],
        loader, "-Wl,--pop-state", "-o", inputs / "bash-payload-dynamic"])
    root = out / "root"; root.mkdir()
    for directory in ["runtime/search", "runtime/sandbox", "bin", "usr/bin", "proc", "dev", "tmp", "report", "work", "protected", "secret", "home/test", "etc"]:
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "secret/input").write_text("owned secret fixture\n")
    (root / "etc/passwd").write_text(f"test:x:{os.getuid()}:{os.getgid()}:fixture:/home/test:/bin/bash\n")
    (root / "etc/group").write_text(f"test:x:{os.getgid()}:\n")
    (root / "etc/hosts").write_text("127.0.0.1 localhost\n::1 localhost\n")
    (root / "etc/nsswitch.conf").write_text("hosts: files\npasswd: files\ngroup: files\n")
    dependencies = []
    def copy_public(source, destination, *, executable=False):
        target = root / destination.lstrip("/"); target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target); target.chmod(0o500 if executable else source.stat().st_mode & 0o555)
        dependencies.append({"source": str(source), "destination": destination, "sha256": sha(target), "mode": oct(target.stat().st_mode & 0o777)})
    def stage_dependencies(source, label):
        result = run("bash-ldd-" + label, ["ldd", source])
        for match in re.finditer(r"(?:=>\s*)?(/(?:usr/)?lib[^\s]*)\s+\(", result["stdout"]):
            library = Path(match.group(1)); assert library.is_file()
            if not (root / library.relative_to("/")).exists(): copy_public(library, str(library))
    # Public runner executables only; no host root/home is bind-mounted.
    for name in ["bash", "sh", "bwrap", "socat", "env", "which", "readlink", "pwd", "mkdir", "rm", "sleep", "cat", "dirname", "basename",
                 "realpath", "mktemp", "stat", "touch", "chmod", "sed", "head", "tail", "sort", "tr", "uname", "wc", "stty", "date", "grep", "ls", "timeout", "true"]:
        source = Path(shutil.which(name)); assert source.is_absolute() and source.is_file()
        destination = "/bin/" + name
        copy_public(source, destination)
        if source.read_bytes()[:4] != b"\x7fELF":
            shebang = source.read_bytes().splitlines()[0]
            assert name == "which" and re.fullmatch(rb"#![ \t]*/bin/sh[ \t]*", shebang), ("Unqualified public tool interpreter", name, shebang)
            continue
        stage_dependencies(source, name)
    stage_dependencies(rg, "managed-rg")
    for name in ["librt.so.1", "libpthread.so.0", "libdl.so.2", "libm.so.6"]:
        library = Path("/lib") / triplet / name
        if not (root / library.relative_to("/")).exists(): copy_public(library, str(library))
    required = {}
    for label, executable in [("original", original), ("authored-control", inputs / "bash-payload-dynamic")]:
        headers = run("bash-needed-" + label, ["readelf", "-d", executable])
        required[label] = re.findall(r"\(NEEDED\).*\[([^\]]+)\]", headers["stdout"])
    assert set(required["original"]) == set(required["authored-control"]), "Dynamic control must exercise every original loader dependency"
    copy_public(inputs / "bash-driver", "/runtime/bash-driver")
    copy_public(inputs / "bash-payload", "/runtime/bash-payload")
    copy_public(inputs / "bash-payload-dynamic", "/runtime/bash-payload-dynamic")
    copy_public(rg, "/runtime/search/rg", executable=True)
    public = json.loads((seccomp_package / "receipt.json").read_text())
    assert public["profile"] == profile and public["arch"] == arch and public["independent_builds_identical"]
    managed_binaries = {}
    for name in ["apply-seccomp", "claude", "claude-preserved"]:
        source = seccomp_package / name; assert source.is_file()
        # Artifacts may omit executable modes; the digest gates an owned copy.
        target = root / ("runtime/sandbox/apply-seccomp" if name == "apply-seccomp" else "runtime/" + name)
        shutil.copyfile(source, target); target.chmod(0o500)
        expected = public["binaries"][name] if name == "apply-seccomp" else public["managed_launchers_built_not_client_executed"]["readable" if name == "claude" else "preserved"]
        assert sha(target) == expected["sha256"] and target.stat().st_size == expected["bytes"]
        managed_binaries[name] = {"sha256": sha(target), "bytes": target.stat().st_size, "mode": "0o500"}
    shutil.copyfile(seccomp_package / "receipt.json", logs / "public-managed-build-receipt.json")
    (logs / "public-root-inputs.json").write_text(json.dumps({"files": dependencies, "rg_sha256": RG_SHA[arch], "host_directories_mounted": False,
                                                           "managed_binaries": managed_binaries, "dynamic_control_needed_matches_original": required}, indent=2) + "\n")
    states = out / "states"; states.mkdir()
    def execute(label, command, spec, *, client=None, arguments=()):
        state = states / label; state.mkdir()
        for directory in ["work", "home", "protected", "report"]: (state / directory).mkdir()
        (state / "work/input.txt").write_text("fixture input\n")
        (state / "report/spec.json").write_text(json.dumps(spec, ensure_ascii=False) + "\n")
        (root / "runtime/client-preserved").touch(exist_ok=True); (root / "runtime/client-readable").touch(exist_ok=True)
        (root / "runtime/original").touch(exist_ok=True)
        argv = [bwrap, "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--uid", str(os.getuid()), "--gid", str(os.getgid()),
                "--ro-bind", root, "/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--bind", state / "work", "/work",
                "--bind", state / "home", "/home/test", "--bind", state / "protected", "/protected", "--bind", state / "report", "/report"]
        if client:
            for name, source in client.items(): argv += ["--ro-bind", source, "/runtime/" + name]
        argv += ["--chdir", "/work", "--clearenv"]
        env = {"HOME": "/home/test", "TMPDIR": "/tmp", "XDG_CONFIG_HOME": "/home/test/config", "XDG_CACHE_HOME": "/home/test/cache",
               "BUN_INSTALL_CACHE_DIR": "/home/test/bun-cache", "BUN_RUNTIME_TRANSPILER_CACHE_PATH": "0", "PATH": "/runtime/search:/bin:/usr/bin",
               "LANG": "C", "LC_ALL": "C", "NO_COLOR": "1", "SHELL": "/bin/bash", "CLAUDE_CODE_SHELL": "/bin/bash",
               "ANTHROPIC_API_KEY": "sk-ant-api03-offline-fixture-not-a-real-credential", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
               "DISABLE_AUTOUPDATER": "1", "ENABLE_CLAUDEAI_MCP_SERVERS": "false", "USE_BUILTIN_RIPGREP": "false"}
        for key, value in env.items(): argv += ["--setenv", key, value]
        result = None
        try:
            result = run(label, [*argv, "--", "/runtime/bash-driver", *command, *arguments], expected=None, timeout=60, limited=True)
            return result, state
        finally:
            retained = logs / label; retained.mkdir()
            for path in (state / "report").iterdir():
                if path.is_file(): shutil.copyfile(path, retained / path.name)
            if result: (retained / "process.json").write_text(json.dumps(result, indent=2) + "\n")
    text_spec = {"kind": "tool_then_text", "tool": {"name": "Read", "input": {"file_path": "/work/input.txt"}}, "text": "fixture-complete"}
    network, _ = execute("bash-boundary-network", ["--qualification"], text_spec)
    assert network["exit_code"] == 0 and not network["stderr"]
    rows = json.loads(network["stdout"])
    assert rows[0]["connect_return"] == 0 and "200 OK" in rows[0]["reply"]
    assert [row["errno"] for row in rows[1:]] == [111, 101, 111]
    controls = []
    for executable in ["bash-payload", "bash-payload-dynamic"]:
        result, state = execute("bash-boundary-" + executable, ["/runtime/" + executable, "baseline"], text_spec)
        assert result["exit_code"] == 0 and not result["stderr"]
        control = json.loads(result["stdout"])
        assert control["sandboxed"] is False and control["unix_errno"] == 0 and control["write_denied_errno"] == 0 and control["read_bytes"] == 21
        assert (state / "protected/forbidden").is_file()
        controls.append(control)
    search, _ = execute("bash-boundary-search-version", ["/runtime/search/rg", "--version"], text_spec)
    assert search["exit_code"] == 0 and not search["stderr"] and search["stdout"].startswith("ripgrep 14.1.1")
    assert "PCRE2 10.45 is available (JIT is available)" in search["stdout"]
    partial.update(status="authored_bash_boundary_qualified", network_controls=rows, boundary_controls=controls,
                   public_search_version=search["stdout"], client_cases=[], client_invocations=[], differential_pairs=[])
    (logs / "qualified-before-bash-client.json").write_text(json.dumps(partial, indent=2) + "\n")
    built = build_clients(arch, original, out / "native-build", logs, run)
    partial["native_build"] = built
    selected = {name: Path(info["path"]) for name, info in built["clients"].items()}
    config = {"sandbox": {"enabled": True, "autoAllowBashIfSandboxed": True, "allowUnsandboxedCommands": False,
                          "enableWeakerNestedSandbox": False, "excludedCommands": [],
                          "network": {"allowedDomains": [], "allowAllUnixSockets": False},
                          "filesystem": {"allowWrite": ["/work"], "denyRead": ["/secret"], "denyWrite": ["/protected"]}}}
    (logs / "settings.json").write_text(json.dumps(config, indent=2) + "\n")
    try:
        for case in cases():
            spec = {"kind": "tool_then_text", "tool": {"name": "Bash", "input": {"command": case["command"], "timeout": 10000}}, "text": "bash-sandbox-complete"}
            observations = {}
            for label in ["original", "preserved", "readable"]:
                name = "bash-" + label + "-" + case["id"]
                executable = "/runtime/original" if label == "original" else "/runtime/claude-preserved" if label == "preserved" else "/runtime/claude"
                argv = ["-p", "--output-format", "stream-json", "--verbose", "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
                        "--no-chrome", "--disable-slash-commands", "--permission-mode", "manual", "--permission-prompts", "none",
                        "--system-prompt", "Offline fixture. Use only supplied fixture data.", "--setting-sources", "", "--settings", json.dumps(config, separators=(",", ":")),
                        "--tools", "Bash", "--allowedTools", "Bash", "--model", "claude-sonnet-5", "--session-id", "00000000-0000-4000-8000-000000000001",
                        "--debug-file", "/report/client-debug.txt", "--", "fixture prompt"]
                client = {"original": original} if label == "original" else {"client-" + label: selected[label]}
                invocation = {"case": case["id"], "label": label, "attempted": True, "client_entry_confirmed": False, "tool_oracles_pass": False}
                partial["client_invocations"].append(invocation)
                execution, state = execute(name, [executable], spec, client=client, arguments=argv)
                frames = [json.loads(line) for line in execution["stdout"].splitlines()]
                invocation.update(exit_code=execution["exit_code"], client_entry_confirmed=bool(frames))
                assert execution["exit_code"] == 0, "Client process failed; inspect its exact stderr and entry record"
                requests_file = state / "report/requests.jsonl"
                requests = [json.loads(line) for line in requests_file.read_text().splitlines()] if requests_file.exists() else []
                api = [row for row in requests if row["path"].split("?")[0] == "/v1/messages"]
                terminal = [frame for frame in frames if frame.get("type") == "result"]
                assert execution["exit_code"] == 0 and len(terminal) == 1 and not terminal[0].get("is_error") and terminal[0].get("result") == "bash-sandbox-complete"
                assert len(api) == 2, "one actual Bash tool and one terminal response required"
                tool_results = [content for message in api[1]["body"]["messages"] if isinstance(message.get("content"), list)
                                for content in message["content"] if content.get("type") == "tool_result" and content.get("tool_use_id") == "toolu_offline_fixture_1"]
                assert len(tool_results) == 1 and bool(tool_results[0].get("is_error", False)) == case["error"]
                content = json.dumps(tool_results[0]["content"], ensure_ascii=False)
                assert all(value in content.replace('\\"', '"') for value in case["contains"]), "declared Bash output missing"
                paths = list((state / "work").rglob("*"))
                assert all(not p.is_symlink() and (p.is_file() or p.is_dir()) for p in paths), "Unexpected workspace file kind"
                assert len(paths) <= 32 and sum(p.stat().st_size for p in paths if p.is_file()) <= 65536, "Workspace evidence budget"
                files = {p.relative_to(state / "work").as_posix(): p.read_bytes() for p in paths if p.is_file()}
                (logs / name / "workspace-files.json").write_text(json.dumps({key: value.hex() for key, value in files.items()}, indent=2) + "\n")
                assert files == {key: value.encode() for key, value in case["files"].items()}, "workspace bytes differ"
                assert not list((state / "protected").iterdir()), "inner sandbox failed to protect the writable outer fixture"
                normalizer = Normalize("/home/test")
                observed = normalizer.value({"protocol": frames, "requests": [row["body"] for row in requests], "stderr": execution["stderr"], "exit": execution["exit_code"]})
                (logs / name / "normalized.json").write_text(json.dumps(observed, ensure_ascii=False, indent=2) + "\n")
                row = {"case": case["id"], "label": label, "oracles_pass": True, "tool_results": tool_results,
                       "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}, "normalization": normalizer.audit}
                partial["client_cases"].append(row); observations[label] = observed
                invocation["tool_oracles_pass"] = True
                print(json.dumps({"bash_case": case["id"], "layout": label, "oracles": "pass"}), flush=True)
            for label in ["preserved", "readable"]:
                diff = differences(observations["original"], observations[label])
                partial["differential_pairs"].append({"case": case["id"], "layout": label, "equal": not diff, "differences": diff[:50]})
                assert not diff, "Bash differential mismatch; retain all records before changing a normalizer"
        partial.update(status="seven_real_bash_sandbox_cases_match_both_layouts", full_bash_sandbox_bounded_acceptance=True, goal_complete=False)
        return partial
    finally:
        (logs / "acceptance.json").write_text(json.dumps(partial, ensure_ascii=False, indent=2) + "\n")
