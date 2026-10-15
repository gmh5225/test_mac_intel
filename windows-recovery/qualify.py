"""Qualify native Windows Bun/PE graph semantics using authored inputs only."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess
import urllib.request
import zipfile
from appcontainer_qualification import qualify_appcontainer
from client_acceptance import accept_client

ROOT = Path(__file__).resolve().parent
PINS = {
    "x64": ("bun-windows-x64-baseline", "d7a7d3eb216614544aab0cde2d8d9f2e4e87839bf5a30a1cd11d077f02d84e0c", "095db4abae203d42f29fdec26da4a882fcde6333cdd84e40c0c7828c0cf543f6"),
    "arm64": ("bun-windows-aarch64", "5e8f142ef722cbc9f67dc068a166e46ee72be8307b38cac7186589d2face668f", "b662cf80f932866036fc2ef33d0d4e2efcf9e4ba282d2deb3391effdcfe0b98f"),
}
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path, value): path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arch", choices=list(PINS), required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    out = args.output.resolve(); out.mkdir()
    logs = out / "evidence"; logs.mkdir()
    receipt = {"status": "started", "authored_inputs_only": True, "captured_client_executed": False,
               "architecture": args.arch, "host": platform.platform(), "steps": []}
    try:
        assert os.name == "nt", "native Windows is required"
        artifact, zip_sha, exe_sha = PINS[args.arch]
        url = "https://github.com/oven-sh/bun/releases/download/bun-v1.4.3/" + artifact + ".zip"
        archive = out / "bun.zip"
        with urllib.request.urlopen(url, timeout=90) as response, archive.open("wb") as target:
            while data := response.read(1024 * 1024): target.write(data)
        assert sha(archive) == zip_sha, "runtime archive hash"
        bun = out / "bun.exe"
        with zipfile.ZipFile(archive) as z: bun.write_bytes(z.read(artifact + "/bun.exe"))
        assert sha(bun) == exe_sha, "runtime executable hash"
        receipt["runtime"] = {"url": url, "zip_sha256": zip_sha, "exe_sha256": exe_sha}
        vswhere = Path(os.environ["ProgramFiles(x86)"]) / "Microsoft Visual Studio/Installer/vswhere.exe"
        installation = subprocess.check_output([str(vswhere), "-latest", "-products", "*", "-property", "installationPath"], text=True).strip()
        vcvars = Path(installation) / "VC/Auxiliary/Build/vcvarsall.bat"
        target = "amd64" if args.arch == "x64" else "amd64_arm64"
        setup_file = out / "compiler-environment.cmd"
        setup_file.write_text(f'@echo off\ncall "{vcvars}" {target} > "{logs / "compiler-setup.log"}" 2>&1\n'
                             'if errorlevel 1 exit /b %errorlevel%\nset\n', encoding="utf-8")
        setup = subprocess.run(["cmd.exe", "/d", "/c", str(setup_file)], capture_output=True,
                               text=True, timeout=90, check=True)
        compiler_env = {k.upper(): v for k, v in os.environ.items()}
        for line in setup.stdout.splitlines():
            if "=" in line and not line.startswith("="):
                key, value = line.split("=", 1); compiler_env[key.upper()] = value
        compiler = shutil.which("cl.exe", path=compiler_env["PATH"])
        assert compiler, "MSVC environment did not provide cl.exe"
        # Target processes receive an explicit environment without Actions credentials.
        state = out / "state"; state.mkdir()
        for name in ["home", "tmp", "work"]: (state / name).mkdir()
        clean_env = {k: v for k, v in os.environ.items() if k.upper() in {"SYSTEMROOT", "WINDIR", "COMSPEC", "SYSTEMDRIVE"}}
        clean_env.update(HOME=str(state / "home"), USERPROFILE=str(state / "home"),
            TEMP=str(state / "tmp"), TMP=str(state / "tmp"), APPDATA=str(state / "home"),
            LOCALAPPDATA=str(state / "home"), BUN_RUNTIME_TRANSPILER_CACHE_PATH="0", NO_COLOR="1",
            PATH=str(Path(os.environ["SystemRoot"]) / "System32"))
        def run(label, command, *, env=None, cwd=None, timeout=60, expected=0):
            result = subprocess.run(list(map(str, command)), cwd=cwd or out, env=env or clean_env,
                capture_output=True, timeout=timeout)
            assert len(result.stdout) + len(result.stderr) < 1024 * 1024, "output budget"
            (logs / (label + ".stdout")).write_bytes(result.stdout)
            (logs / (label + ".stderr")).write_bytes(result.stderr)
            receipt["steps"].append({"name": label, "exit_code": result.returncode,
                                     "stdout_sha256": sha(logs / (label + ".stdout")),
                                     "stderr_sha256": sha(logs / (label + ".stderr"))})
            print(json.dumps({"step": label, "exit_code": result.returncode}), flush=True)
            assert result.returncode == expected, f"{label}: exit {result.returncode}; inspect retained logs"
            return result.stdout
        revision = run("runtime-revision", [bun, "--revision"]).decode().strip()
        assert revision == "1.4.3+c6da4a4d3", revision
        observed = json.loads(run("runtime-platform", [bun, "--eval", "console.log(JSON.stringify({platform:process.platform,arch:process.arch}))"]))
        assert observed == {"platform": "win32", "arch": args.arch}, observed
        receipt["runtime"]["revision"] = revision
        # Observe entry metadata from Bun's own unmodified compiler first.
        control = out / "main-control"; control.mkdir()
        (control / "entry.mjs").write_text(
            'console.log(JSON.stringify({main:import.meta.main,url:import.meta.url,bunMain:Bun.main}));\n', encoding="utf-8")
        (control / "build.mjs").write_text(
            'const r=await Bun.build({entrypoints:["./entry.mjs"],target:"bun",env:"disable",macros:false,minify:false,'
            'compile:{outfile:"./control.exe",executablePath:process.execPath}});'
            'if(!r.success){console.error(r.logs);process.exit(1);}\n', encoding="utf-8")
        run("build-main-control", [bun, control / "build.mjs"], cwd=control, timeout=120)
        main_control = json.loads(run("main-control", [control / "control.exe"]))
        assert type(main_control["main"]) is bool, main_control
        receipt["unmodified_compiler_entry_control"] = main_control
        for name in ["raw-graph-windows-adapter", "graph-fidelity-windows-adapter", "graph-fidelity-windows-fixture-generator"]:
            run("compile-" + name, [compiler, "/nologo", "/std:c++20", "/EHsc", "/O2", ROOT / (name + ".cpp"),
                "/Fe:" + str(out / (name + ".exe")), "/link", "bcrypt.lib"], env=compiler_env, timeout=120)
        fixture = out / "fixture"
        run("generate", [out / "graph-fidelity-windows-fixture-generator.exe", fixture])
        clients = []
        for attempt in [1, 2]:
            graph = out / ("graph-" + str(attempt))
            run(f"stage-{attempt}", [out / "raw-graph-windows-adapter.exe", "stage", fixture / "mapping.tsv", fixture / "input", graph])
            names = sorted(p.name for p in graph.iterdir())
            (graph / "bootstrap.mjs").write_text('await import(JSON.parse("\\\"B:/~BUN/root/cli\\\""));\n', encoding="utf-8")
            (graph / "build.mjs").write_text("""import {fileURLToPath} from 'node:url';
const p=s=>fileURLToPath(new URL(s,import.meta.url));
const r=await Bun.build({entrypoints:[p('./bootstrap.mjs')],target:'bun',env:'disable',macros:false,minify:false,
compile:{outfile:p('./client.exe'),executablePath:process.execPath,assets:ASSETS.map(s=>p('./'+s))}});
if(!r.success){for(const log of r.logs)console.error(log);process.exit(1);}
""".replace("ASSETS", json.dumps(names)), encoding="utf-8")
            run(f"build-{attempt}", [bun, graph / "build.mjs"], cwd=graph, timeout=120)
            client = out / ("fixture-" + str(attempt) + ".exe")
            run(f"patch-{attempt}", [out / "graph-fidelity-windows-adapter.exe", fixture / "mapping.tsv", graph / "client.exe", client, "B:/~BUN/root/cli", "2", "15", "8"])
            clients.append(client)
        first, second = (client.read_bytes() for client in clients)
        different = [i for i, (x, y) in enumerate(zip(first, second)) if x != y]
        save(logs / "reproducibility.json", {
            "hashes": [sha(client) for client in clients], "sizes": [len(first), len(second)],
            "different_byte_count": len(different), "first_offsets": different[:64],
            "first_difference_context": [data[max(0, different[0]-32):different[0]+96].hex()
                for data in [first, second]] if different else []})
        observed = json.loads(run("source-graph-runtime", [clients[0]], cwd=state / "work"))
        assert observed["ok"] and observed["sharedIdentity"] and observed["liveBinding"] == 2, observed
        assert observed["worker"] == "000102ff", observed
        assert observed["main"] == main_control["main"], (observed, main_control)
        assert observed["bootstrapMain"] == "B:/~BUN/root/cli", observed
        assert observed["opaqueNativeBytes"] == "01020304", observed
        second_observed = json.loads(run("source-graph-runtime-repeat", [clients[1]], cwd=state / "work"))
        assert observed == second_observed, "authored observations differ"
        assert first == second, "independent fixture builds differ; inspect reproducibility.json"
        receipt.update(status="authored_graph_runtime_qualified", native_runtime=observed,
            independent_build_sha256=sha(clients[0]), runtime_preserved=sha(bun) == exe_sha,
            scope="Authored loader/text/module/worker graph only. No original client or native addon executed; no OS sandbox claim.")
        run("compile-appcontainer-run", [compiler, "/nologo", "/std:c++20", "/EHsc", "/O2", "/MT",
            "/D_WIN32_WINNT=0x0A00", ROOT / "appcontainer-run.cpp", "/Fe:" + str(out / "appcontainer-run.exe"),
            "/link", "userenv.lib", "advapi32.lib"], env=compiler_env, timeout=120)
        receipt["isolation"] = qualify_appcontainer(out / "appcontainer-run.exe", bun, clients[0], observed,
                                                  clean_env, logs, run)
        receipt.update(status="authored_windows_environment_qualified",
                       scope="Authored fixtures only; capability-free AppContainer and bounded Job Object controls passed. No captured client executed.")
        receipt["client_acceptance"] = accept_client(args.arch, out, bun, compiler, compiler_env, clean_env, run, receipt)
        receipt.update(status="windows_client_configuration_accepted",
                       scope="Qualified authored environment, four smoke and seven configuration cases. Full behavior matrix and native addon acceptance remain pending.")
    except Exception as error:
        receipt.update(status="failed", error=str(error)); raise
    finally:
        save(logs / "receipt.json", receipt)
        print(json.dumps({k: receipt.get(k) for k in ["status", "architecture", "error"]}))
if __name__ == "__main__": main()
