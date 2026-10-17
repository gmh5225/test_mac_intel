"""Authored Node-API proof, then retained asset load/reflection only."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent
PINS = {"x64": "3fe6ef86ba63897e448708847fa126c08580584f6fb16f576420eaccb16a942e",
        "arm64": "6f6c85f45a17e7d88ab07e62b1a1bdb8095199ce05da17d97fae94fcaac7658b"}
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def accept_native(arch, out, bun, compiler, compiler_env, clean_env, run):
    logs = out / "evidence"
    receipt = {"status": "started", "retained_export_functions_invoked": False, "cases": []}
    try:
        run("compile-native-fixture", [compiler, "/nologo", "/std:c++20", "/EHsc", "/O2", "/MT", "/LD",
            ROOT / "native-addon-fixture.cpp", "/Fe:" + str(out / "authored.node")], env=compiler_env, timeout=120)
        run("compile-native-generator", [compiler, "/nologo", "/std:c++20", "/EHsc", "/O2",
            ROOT / "native-fixture-generator.cpp", "/Fe:" + str(out / "native-fixture-generator.exe"),
            "/link", "bcrypt.lib"], env=compiler_env, timeout=120)
        original_asset = out / "captured-source/input/m2361"
        assert sha(original_asset) == PINS[arch], "native input pin"
        for mode, asset, name in [("proof", out / "authored.node", "B:/~BUN/root/authored.node"),
                                  ("inspect", original_asset, "B:/~BUN/root/audio-capture.node")]:
            generated = out / ("native-" + mode + "-source")
            run("native-" + mode + "-generate", [out / "native-fixture-generator.exe", generated, mode, name, asset])
            graph = out / ("native-" + mode + "-graph")
            run("native-" + mode + "-stage", [out / "raw-graph-windows-adapter.exe", "stage",
                generated / "mapping.tsv", generated / "source", graph])
            assets = sorted(p.name for p in graph.iterdir())
            (graph / "bootstrap.mjs").write_text('await import(JSON.parse("\\\"B:/~BUN/root/native-acceptance\\\""));\n', encoding="utf-8")
            (graph / "build.mjs").write_text("""import {fileURLToPath} from 'node:url';
const p=s=>fileURLToPath(new URL(s,import.meta.url));
const r=await Bun.build({entrypoints:[p('./bootstrap.mjs')],target:'bun',env:'disable',macros:false,minify:false,
compile:{outfile:p('./client.exe'),executablePath:process.execPath,assets:ASSETS.map(s=>p('./'+s))}});
if(!r.success){for(const log of r.logs)console.error(log);process.exit(1);}
""".replace("ASSETS", json.dumps(assets)), encoding="utf-8")
            run("native-" + mode + "-build", [bun, graph / "build.mjs"], cwd=graph, timeout=120)
            candidate = out / ("native-" + mode + ".exe")
            run("native-" + mode + "-patch", [out / "graph-fidelity-windows-adapter.exe", generated / "mapping.tsv",
                graph / "client.exe", candidate, "B:/~BUN/root/native-acceptance", "1", "15", "8"])
            root = Path(tempfile.mkdtemp(prefix="neverd-native-" + mode + "-", dir=os.environ["SystemDrive"] + "\\"))
            for part in ["bin", "work", "home", "tmp"]: (root / part).mkdir()
            shutil.copyfile(candidate, root / "bin/client.exe")
            env = dict(clean_env)
            env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"),
                APPDATA=str(root / "home"), LOCALAPPDATA=str(root / "home"),
                TEMP=str(root / "tmp"), TMP=str(root / "tmp"))
            try:
                meta = json.loads(run("native-" + mode + "-launcher", [out / "appcontainer-run.exe", root,
                    "NeverD.Native." + uuid.uuid4().hex, "15000", "client.exe"], env=env))
            finally:
                for stream in ["stdout", "stderr"]:
                    path = root / ("target." + stream)
                    if path.exists(): (logs / ("native-" + mode + "." + stream)).write_bytes(path.read_bytes()[:2 * 1024 * 1024])
            assert meta["exit_code"] == 0 and not meta["timeout"] and not meta["output_limit"], meta
            observed = json.loads((logs / ("native-" + mode + ".stdout")).read_bytes())
            materialized = [{"path": str(p.relative_to(root)), "sha256": sha(p), "bytes": p.stat().st_size}
                            for p in root.rglob("*") if p.is_file() and p != root / "bin/client.exe"]
            result = {"mode": mode, "execution": meta, "observation": observed, "materialized": materialized,
                      "native_input_sha256": sha(asset)}
            receipt["cases"].append(result)
            assert observed["main"] == "B:/~BUN/root/native-acceptance", observed
            assert len(observed["rows"]) == 1, observed
            row = observed["rows"][0]
            assert row["loaded"] and row["sameCachedInstance"] and not row["originalExportFunctionsInvoked"], row
            assert row["name"] == name and any(p["sha256"] == sha(asset) for p in materialized), result
            if mode == "proof": assert row["proof"] == "authored-node-api-ok", row
        receipt["status"] = "embedded_native_load_only_pass"
        return receipt
    except Exception as error:
        receipt.update(status="failed", error=str(error)); raise
    finally:
        (logs / "native-acceptance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
