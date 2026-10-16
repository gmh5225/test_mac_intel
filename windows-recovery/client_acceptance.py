"""Fetch pinned published input on the runner; retain only audit diagnostics."""
from pathlib import Path
import base64
import hashlib
import json
import os
import shutil
import tarfile
import tempfile
import urllib.request
import uuid
from configuration_acceptance import accept_configuration
from native_acceptance import accept_native
from behavior_acceptance import accept_behavior
from editable_acceptance import accept_editable
from readable_acceptance import accept_readable
from core_tool_acceptance import accept_core_tools

ROOT = Path(__file__).resolve().parent
PINS = {
    "x64": {
        "integrity": "g2aYBzYM5YTDio0ulAoGIGgtGRMa08WAecer4wuOUrKPwVPRfyRdmoZI01BNS8jF9yupDmQycBMuBcVui/VGNw==",
        "original": "76de74f7694a5bdc03378a5f837c9e132827bf004c98c276bc4e9094ff06769a",
        "mapping": "a114f5169e3beb596c04b6bca49b8aca317b08439c1fe456eebd05391776412f",
        "local_rebuilt": "da3d6780681d86726737d3c4449fbbd20c1daa9a3d4a155fc7ff037626dbe204",
        "flags": 7167,
    },
    "arm64": {
        "integrity": "m/PZ8nO0Fi6FB7DpTFeHVln1useFjEEDXF1wVylxl34+Kf78s2KJVCNKozF/b/MO6jjVkewFQl+1hW5xZkaV7A==",
        "original": "a652a17f5a324d2d9ad9995cc047145f8176b9a4b4f28bbd3aa0708a22679e3b",
        "mapping": "89228c642f25b5ad254c42e72fe8c7b989c7b8a228e32b20933fe0d9e15eba38",
        "local_rebuilt": "e4d072017574a731a31e59cb639903060ef6fe6532155cc2c3bfe2046ad50cfa",
        "flags": 8191,
    },
}
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def accept_client(arch, out, bun, compiler, compiler_env, clean_env, run, overall, editable_probe=False,
                  formatter_root=None, formatter_manifest_sha256=None):
    pins = PINS[arch]
    logs = out / "evidence"
    receipt = {"status": "started", "architecture": arch, "version": "2.1.296",
               "published_input_downloaded_in_runner": True, "client_artifact_uploaded": False,
               "source_artifact_uploaded": False, "cases": []}
    try:
        run("compile-extractor", [compiler, "/nologo", "/std:c++20", "/EHsc", "/O2",
            ROOT / "extract-pinned-graph.cpp", "/Fe:" + str(out / "extract-pinned-graph.exe"),
            "/link", "bcrypt.lib"], env=compiler_env, timeout=120)
        url = f"https://registry.npmjs.org/@anthropic-ai/claude-code-win32-{arch}/-/claude-code-win32-{arch}-2.1.296.tgz"
        archive = out / "published-input.tgz"
        digest = hashlib.sha512(); size = 0
        with urllib.request.urlopen(url, timeout=90) as response, archive.open("xb") as target:
            while data := response.read(1024 * 1024):
                size += len(data); assert size < 160 * 1024 * 1024, "archive budget"
                target.write(data); digest.update(data)
        assert digest.digest() == base64.b64decode(pins["integrity"]), "npm archive integrity"
        original = out / "original.exe"
        with tarfile.open(archive, "r:gz") as tar:
            member = tar.getmember("package/claude.exe")
            assert member.isfile() and member.size < 300 * 1024 * 1024, "published executable profile"
            with tar.extractfile(member) as source, original.open("xb") as target:
                shutil.copyfileobj(source, target)
        assert sha(original) == pins["original"], "published executable hash"
        receipt["original_sha256"] = pins["original"]
        extraction = out / "captured-source"
        metadata = json.loads(run("extract-source", [out / "extract-pinned-graph.exe", original, pins["original"], extraction]))
        assert metadata == {"module_count": 2586, "source_count": 2343, "asset_count": 243,
            "entry_index": 6, "entry": "B:/~BUN/root/cli", "flags": pins["flags"],
            "source_and_assets_only": True, "executes_input": False}, metadata
        mapping = extraction / "mapping.tsv"
        assert sha(mapping) == pins["mapping"], "extracted rows differ from NeverD-validated manifest"
        receipt["extraction"] = metadata
        names = [line.split("\t")[0] for line in mapping.read_text().splitlines()]
        builds = []
        for attempt in [1, 2]:
            graph = out / f"client-graph-{attempt}"
            run(f"client-stage-{attempt}", [out / "raw-graph-windows-adapter.exe", "stage", mapping, extraction / "input", graph])
            assets = sorted(p.name for p in graph.iterdir())
            bootstrap = "".join("await import(JSON.parse(" + json.dumps(json.dumps(name)) + "));\n" for name in names[:7])
            (graph / "bootstrap.mjs").write_text(bootstrap, encoding="utf-8", newline="\n")
            (graph / "build.mjs").write_text("""import {fileURLToPath} from 'node:url';
const p=s=>fileURLToPath(new URL(s,import.meta.url));
const r=await Bun.build({entrypoints:[p('./bootstrap.mjs')],target:'bun',env:'disable',macros:false,minify:false,
compile:{outfile:p('./client.exe'),executablePath:process.execPath,assets:ASSETS.map(s=>p('./'+s))}});
if(!r.success){for(const log of r.logs)console.error(log);process.exit(1);}
""".replace("ASSETS", json.dumps(assets)), encoding="utf-8", newline="\n")
            run(f"client-build-{attempt}", [bun, graph / "build.mjs"], cwd=graph, timeout=180)
            client = out / f"rebuilt-{attempt}.exe"
            run(f"client-patch-{attempt}", [out / "graph-fidelity-windows-adapter.exe", mapping,
                graph / "client.exe", client, "B:/~BUN/root/cli", "7", "15", "8"])
            builds.append(client)
        receipt["rebuild_hashes"] = [sha(p) for p in builds]
        receipt["matches_local_cross_build"] = receipt["rebuild_hashes"][0] == pins["local_rebuilt"]
        assert receipt["rebuild_hashes"][0] == receipt["rebuild_hashes"][1], "native clean builds differ"
        readback = out / "rebuilt-readback"
        receipt["readback"] = json.loads(run("client-readback", [out / "extract-pinned-graph.exe", builds[0], sha(builds[0]), readback]))
        assert sha(readback / "mapping.tsv") == pins["mapping"], "rebuilt module metadata or bytes changed"
        assert receipt["matches_local_cross_build"], "native/cross compiler artifacts differ; inspect before runtime acceptance"
        def smoke(original, rebuilt, prefix="client"):
            cases = []
            for case, argv, expected_exit in [("version", ["--version"], 0), ("help", ["--help"], 0),
                ("mcp-help", ["mcp", "--help"], 0), ("unknown-option", ["--neverd-isolation-unknown-option"], 1)]:
                results = []
                for label, executable in [("original", original), ("rebuilt", rebuilt)]:
                    root = Path(tempfile.mkdtemp(prefix=f"neverd-client-{label}-{case}-", dir=os.environ["SystemDrive"] + "\\"))
                    for part in ["bin", "work", "home", "tmp"]: (root / part).mkdir()
                    shutil.copyfile(executable, root / "bin/client.exe")
                    env = dict(clean_env)
                    env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"), APPDATA=str(root / "home"),
                        LOCALAPPDATA=str(root / "home"), TEMP=str(root / "tmp"), TMP=str(root / "tmp"),
                        CLAUDE_CONFIG_DIR=str(root / "home/.claude"), CLAUDE_CODE_TMPDIR=str(root / "tmp"),
                        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1", DISABLE_AUTOUPDATER="1", ENABLE_CLAUDEAI_MCP_SERVERS="false")
                    name = f"{prefix}-{label}-{case}"
                    try:
                        overall["captured_client_executed"] = None
                        meta = json.loads(run(name + "-launcher", [out / "appcontainer-run.exe", root,
                            "NeverD.Client." + uuid.uuid4().hex, "30000", "client.exe", *argv], env=env))
                        overall["captured_client_executed"] = True
                    finally:
                        for stream in ["stdout", "stderr"]:
                            path = root / ("target." + stream)
                            if path.exists():
                                with path.open("rb") as source:
                                    (logs / (name + "." + stream)).write_bytes(source.read(2 * 1024 * 1024))
                    assert meta["exit_code"] == expected_exit and not meta["timeout"] and not meta["output_limit"], (name, meta)
                    assert meta["app_container"] and meta["capability_count"] == 0 and meta["remaining_processes"] == 0, meta
                    assert sha(root / "bin/client.exe") == sha(executable), "executed input mutated"
                    results.append({"label": label, "execution": meta,
                        "stdout_sha256": sha(logs / (name + ".stdout")), "stderr_sha256": sha(logs / (name + ".stderr"))})
                assert all(results[0][key] == results[1][key] for key in ["stdout_sha256", "stderr_sha256"]), (case, results)
                cases.append({"case": case, "matches": True, "results": results})
            return cases
        receipt["cases"] = smoke(original, builds[0])
        assert sha(original) == pins["original"] and sha(mapping) == pins["mapping"], "input preservation"
        if editable_probe:
            receipt["editable"] = accept_editable(arch, out, bun, clean_env, run, extraction, pins)
        failures = []
        for name, action in [
            ("native", lambda: accept_native(arch, out, bun, compiler, compiler_env, clean_env, run)),
            ("configuration", lambda: accept_configuration(out, original, builds[0], clean_env)),
            ("behavior", lambda: accept_behavior(out, original, builds[0], clean_env))]:
            try:
                receipt[name] = action()
                if name == "behavior" and receipt[name]["status"] != "twenty_two_behavior_cases_match":
                    failures.append({"step": name, "error": "helper-dependent cases remain unrun"})
            except Exception as error: failures.append({"step": name, "error": str(error)})
        assert not failures, failures
        if formatter_root is not None:
            receipt["readable"] = accept_readable(arch, out, bun, clean_env, run, extraction, original, pins,
                                                 formatter_root, formatter_manifest_sha256, smoke)
        candidates = {"preserved": builds[0]}
        if formatter_root is not None: candidates["readable"] = out / "readable-rebuilt-1.exe"
        receipt["core_tools"] = accept_core_tools(out, original, candidates, clean_env)
        receipt.update(status="windows_offline_acceptance_pass", full_behavior_matrix="29 cases match", smoke_cases=4)
        return receipt
    except Exception as error:
        receipt.update(status="failed", error=str(error)); raise
    finally:
        (logs / "client-acceptance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
