"""Rebuild both recorded Linux clients from pinned published data, offline.

Only authored recipes, whitespace offsets and hashes live in this repository.
Neither captured source nor rebuilt client is an uploaded workflow artifact.
"""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import os
import platform
import shutil
import subprocess
import urllib.request
import zipfile
from build import PINS, sha
from format_recipe import formatted
from patch_descriptor import patch

ROOT = Path(__file__).resolve().parent
RECIPE_SHA = "324791ad6a22829f34d47b023d862d3ebb0a4d944deb84f121e2c73485107a83"
COMPILERS = {
    "x64": {"url": "https://github.com/oven-sh/bun/releases/download/bun-v1.4.3/bun-linux-x64-baseline.zip",
            "zip_sha256": "1fc2edac843102909e3a1be1d8d9802cc6071cf074e67e88231f4ffe0f8b397b",
            "binary_sha256": "7ce7d6b654eddeec20afddf2396317fba6dc19ab52788a27e894e1806bf8f24b",
            "clients": {"preserved": "3a5caccd3268e16a143c93229161eb5de8528359d2f00020fddc33a673d88f79",
                        "readable": "3b7b9d0cf3a0d4ae2247878fb4469bb623ff5f19d3ea56cab9aa89011b2adc74"}},
    "arm64": {"url": "https://github.com/oven-sh/bun/releases/download/bun-v1.4.3/bun-linux-aarch64.zip",
              "zip_sha256": "efa9813da5ed72423bf847f916e8d2c47c0d776add972354026a75e10da9aa21",
              "binary_sha256": "029ece746ac9f970c76d8f48bdd1b1d0c52f3636b74d19f546f5e7c1165c0abe",
              "clients": {"preserved": "5e5b99ff3b9ff58711bd2eb7749764d4ccb096cc38aa97178073194239cc4c5b",
                          "readable": "92c0ccddfa6f4b289dfea569d598eaecdc84ed1f1e97a0a8112c6d11eb35639a"}},
}


def map_rows(path):
    rows = []
    for index, line in enumerate(path.read_text().splitlines()):
        fields = line.split("\t"); assert len(fields) == 8
        name, loader, encoding, form, side, file, size, digest = fields
        rows.append({"module_index": index, "virtual_name": name, "loader_id": int(loader),
                     "encoding_id": int(encoding), "format_id": int(form), "side_id": int(side),
                     "file": file, "bytes": int(size), "storage_sha256": digest})
    return rows


def build_clients(arch, original, out, logs, run):
    assert platform.system() == "Linux" and {"x86_64": "x64", "aarch64": "arm64"}[platform.machine()] == arch
    out.mkdir()
    profile = PINS["profiles"][arch]; compiler_pin = COMPILERS[arch]
    recipe_file = ROOT / "linux-readable-recipes-v1.json.gz"
    assert sha(recipe_file) == RECIPE_SHA
    recipes = json.loads(gzip.decompress(recipe_file.read_bytes()))
    assert recipes["kind"] == "hash_pinned_whitespace_insertion_only" and recipes["contains_captured_source"] is False
    expected = recipes["profiles"][arch]
    for key, recipe in recipes["recipes"].items():
        assert len(key) == 64 and set(key) <= set("0123456789abcdef")
        assert set(recipe) == {"original_bytes", "readable_bytes", "readable_sha256", "insertions"}
        assert all(isinstance(white, str) and white and set(white) <= set(" \t\r\n") for _, white in recipe["insertions"])
    toolchain = out / "toolchain"; toolchain.mkdir()
    archive = toolchain / "bun.zip"
    with urllib.request.urlopen(compiler_pin["url"], timeout=90) as source, archive.open("xb") as target:
        shutil.copyfileobj(source, target)
    assert sha(archive) == compiler_pin["zip_sha256"]
    bun = toolchain / "bun"
    with zipfile.ZipFile(archive) as z:
        members = [entry for entry in z.infolist() if entry.filename.endswith("/bun")]
        assert len(members) == 1 and members[0].file_size < 160 * 1024 * 1024
        bun.write_bytes(z.read(members[0]))
    assert sha(bun) == compiler_pin["binary_sha256"]; bun.chmod(0o500)
    base = ["docker", "run", "--rm", "--platform", profile["docker_platform"], "--network", "none",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", f"{os.getuid()}:{os.getgid()}", "--cpus", "2", "--memory", "3g", "--pids-limit", "64",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m", "--mount", f"type=bind,src={out},dst=/out",
            "--mount", f"type=bind,src={ROOT},dst=/recipes,readonly"]
    for name in ["extract-linux-graph", "raw-graph-linux-adapter", "graph-fidelity-linux-adapter"]:
        run("compile-" + name, [*base, profile["image"], "g++", "-std=c++20", "-static", "-O2", "-Wall", "-Wextra",
                               "/recipes/" + name + ".cpp", "-lcrypto", "-pthread", "-ldl", "-o", "/out/" + name], timeout=180)
    extracted = out / "extracted"
    run("extract-published-graph", [out / "extract-linux-graph", original, sha(original), extracted], timeout=60)
    rows = map_rows(extracted / "mapping.tsv")
    assert [{k: v for k, v in row.items() if k != "file"} for row in rows] == [
        {k: v for k, v in row.items() if k != "readable_sha256"} for row in expected["rows"]]
    result = {"status": "started", "recipe_sha256": RECIPE_SHA, "compiler": compiler_pin,
              "original_sha256": sha(original), "all_2589_original_rows_match_neverd": True,
              "original_executed_during_build": False, "clients_uploaded": False, "clients": {}}
    (logs / "client-build-start.json").write_text(json.dumps(result, indent=2) + "\n")
    try:
        for layout in ["preserved", "readable"]:
            work = out / layout; work.mkdir(); sources = work / "sources"; sources.mkdir()
            selected = []
            for row in rows:
                raw = (extracted / "input" / row["file"]).read_bytes(); assert hashlib.sha256(raw).hexdigest() == row["storage_sha256"]
                if row["loader_id"] == 1 and (layout == "readable" or row["module_index"] == 236):
                    raw = formatted(raw, recipes["recipes"][row["storage_sha256"]])
                    if row["module_index"] == 236: raw = patch(raw, arch)
                name = f"m{row['module_index']}"; (sources / name).write_bytes(raw)
                selected.append([row["virtual_name"], row["loader_id"], row["encoding_id"], row["format_id"], row["side_id"], name,
                                 len(raw), hashlib.sha256(raw).hexdigest()])
            mapping = work / "mapping.tsv"; mapping.write_text("".join("\t".join(map(str, row)) + "\n" for row in selected))
            graph = work / "graph-input"
            run(layout + "-stage", [out / "raw-graph-linux-adapter", "stage", mapping, sources, graph], timeout=60)
            names = sorted(path.name for path in graph.iterdir())
            startup = [r["virtual_name"] for r in rows[:expected["startup_count"]]]
            (graph / "bootstrap.mjs").write_text("".join("await import(JSON.parse(" + json.dumps(json.dumps(name)) + "));\n" for name in startup))
            scaffold = "import{fileURLToPath}from'node:url';\nconst path=s=>fileURLToPath(new URL(s,import.meta.url));\nawait Bun.build({entrypoints:[path('./bootstrap.mjs')],target:'bun',env:'disable',macros:false,minify:false,compile:{outfile:'/work/client',executablePath:process.execPath,assets:" + json.dumps(names, separators=(",", ":")) + ".map(s=>path('./'+s))}});\n"
            (graph / "build.isolated.mjs").write_text(scaffold)
            empty = work / "empty"; empty.mkdir()
            command = [*base, "--mount", f"type=bind,src={work},dst=/work", "--mount", f"type=bind,src={graph},dst=/graph,readonly",
                       "--mount", f"type=bind,src={bun},dst=/runtime/bun,readonly", "--env", "PATH=/unavailable",
                       "--env", "BUN_RUNTIME_TRANSPILER_CACHE_PATH=0", "--workdir", "/graph"]
            for destination in ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"]:
                command += ["--mount", f"type=bind,src={empty},dst={destination},readonly"]
            run(layout + "-compile-source", [*command, profile["image"], "/runtime/bun", "/graph/build.isolated.mjs"], timeout=180)
            raw_client = work / "client"; client = work / "client-final"
            run(layout + "-restore-graph", [out / "graph-fidelity-linux-adapter", mapping, raw_client, client,
                rows[expected["entry_index"]]["virtual_name"], str(expected["startup_count"]), str(expected["flags"] & 15), "8"], timeout=60)
            client.chmod(0o500)
            readback = work / "readback"
            run(layout + "-readback", [out / "extract-linux-graph", client, sha(client), readback], timeout=60)
            actual = map_rows(readback / "mapping.tsv")
            assert [[r["virtual_name"], r["loader_id"], r["encoding_id"], r["format_id"], r["side_id"], r["bytes"], r["storage_sha256"]] for r in actual] == [r[:5] + r[6:] for r in selected]
            # Hash identity connects this native build directly to the four
            # independently read-back, sealed local candidate clients.
            info = {"path": str(client), "bytes": client.stat().st_size, "sha256": sha(client),
                    "all_module_rows_match_selected_sources": True, "matches_sealed_candidate": sha(client) == compiler_pin["clients"][layout]}
            result["clients"][layout] = info
            assert info["matches_sealed_candidate"], "native build differs from the sealed local candidate; retain for investigation"
        result["status"] = "both_native_clients_match_sealed_candidates"
        return result
    finally:
        (logs / "native-client-build.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--arch", required=True); parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True); parser.add_argument("--logs", type=Path, required=True); args = parser.parse_args()
    args.logs.mkdir(exist_ok=True)
    def run(label, command, *, timeout=60):
        with (args.logs / (label + ".log")).open("xb") as stream:
            p = subprocess.run(list(map(str, command)), stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        assert p.returncode == 0, label
    print(json.dumps(build_clients(args.arch, args.original.resolve(), args.output.resolve(), args.logs.resolve(), run)))
