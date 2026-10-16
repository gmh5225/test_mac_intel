"""Prove that a pinned source edit survives an independent native rebuild."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent
OLD_MARKER = b"(Claude Code)"
NEW_MARKER = b"(Claude Code recovery edit probe)"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def marker_edit(source, original_sha256, edited_sha256):
    assert hashlib.sha256(source).hexdigest() == original_sha256, "original entry source hash"
    assert source.count(OLD_MARKER) == 1, "unique version marker"
    edited = source.replace(OLD_MARKER, NEW_MARKER)
    assert hashlib.sha256(edited).hexdigest() == edited_sha256, "edited entry source hash"
    return edited


def accept_editable(arch, out, bun, clean_env, run, extraction, baseline_pins):
    pins = json.loads((ROOT / "editable-pins.json").read_text())[arch]
    logs = out / "evidence"
    receipt = {"status": "started", "architecture": arch, "edited_module_index": 6,
               "source_artifact_uploaded": False, "client_artifact_uploaded": False,
               "scope": "One exact CLI literal edit. This is not a general behavior-equivalence test."}
    try:
        assert sha(extraction / "mapping.tsv") == baseline_pins["mapping"]
        edited = out / "editable-source"
        shutil.copytree(extraction, edited)
        rows = [line.split("\t") for line in (edited / "mapping.tsv").read_text().splitlines()]
        assert len(rows) == 2586 and all(len(row) == 8 for row in rows)
        row = rows[6]
        assert row[:6] == ["B:/~BUN/root/cli", "1", "1", "1", "0", "m6"]
        source = edited / "input/m6"
        assert sha(source) == row[7] == pins["original_source_sha256"] and source.stat().st_size == int(row[6])
        source.write_bytes(marker_edit(source.read_bytes(), pins["original_source_sha256"], pins["edited_source_sha256"]))
        row[6], row[7] = str(source.stat().st_size), sha(source)
        mapping = edited / "mapping.tsv"
        mapping.write_text("".join("\t".join(row) + "\n" for row in rows), encoding="utf-8", newline="\n")
        assert sha(mapping) == pins["edited_mapping_sha256"], "edited module inventory differs from local selection"
        receipt.update(original_source_sha256=pins["original_source_sha256"], edited_source_sha256=sha(source),
                       edited_mapping_sha256=sha(mapping))
        builds = []
        for attempt in [1, 2]:
            graph = out / f"editable-graph-{attempt}"
            run(f"editable-stage-{attempt}", [out / "raw-graph-windows-adapter.exe", "stage", mapping, edited / "input", graph])
            assets = sorted(p.name for p in graph.iterdir())
            bootstrap = "".join("await import(JSON.parse(" + json.dumps(json.dumps(row[0])) + "));\n" for row in rows[:7])
            (graph / "bootstrap.mjs").write_text(bootstrap, encoding="utf-8", newline="\n")
            (graph / "build.mjs").write_text("""import {fileURLToPath} from 'node:url';
const p=s=>fileURLToPath(new URL(s,import.meta.url));
const r=await Bun.build({entrypoints:[p('./bootstrap.mjs')],target:'bun',env:'disable',macros:false,minify:false,
compile:{outfile:p('./client.exe'),executablePath:process.execPath,assets:ASSETS.map(s=>p('./'+s))}});
if(!r.success){for(const log of r.logs)console.error(log);process.exit(1);}
""".replace("ASSETS", json.dumps(assets)), encoding="utf-8", newline="\n")
            run(f"editable-build-{attempt}", [bun, graph / "build.mjs"], cwd=graph, timeout=180)
            client = out / f"editable-rebuilt-{attempt}.exe"
            run(f"editable-patch-{attempt}", [out / "graph-fidelity-windows-adapter.exe", mapping,
                graph / "client.exe", client, "B:/~BUN/root/cli", "7", "15", "8"])
            builds.append(client)
        hashes = [sha(client) for client in builds]
        receipt["rebuild_hashes"] = hashes
        assert hashes == [pins["local_rebuilt_sha256"]] * 2, "edited native builds differ from local cross-build"
        readback = out / "editable-readback"
        metadata = json.loads(run("editable-readback", [out / "extract-pinned-graph.exe", builds[0], hashes[0], readback]))
        assert metadata == {"module_count": 2586, "source_count": 2343, "asset_count": 243,
            "entry_index": 6, "entry": "B:/~BUN/root/cli", "flags": 4479,
            "source_and_assets_only": True, "executes_input": False}
        assert sha(readback / "mapping.tsv") == pins["edited_mapping_sha256"], "edited executable readback differs"
        receipt["readback"] = metadata
        root = Path(tempfile.mkdtemp(prefix="neverd-editable-version-", dir=os.environ["SystemDrive"] + "\\"))
        for part in ["bin", "work", "home", "tmp"]:
            (root / part).mkdir()
        shutil.copyfile(builds[0], root / "bin/client.exe")
        env = dict(clean_env)
        env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"), APPDATA=str(root / "home"),
            LOCALAPPDATA=str(root / "home"), TEMP=str(root / "tmp"), TMP=str(root / "tmp"),
            CLAUDE_CONFIG_DIR=str(root / "home/.claude"), CLAUDE_CODE_TMPDIR=str(root / "tmp"),
            CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1", DISABLE_AUTOUPDATER="1", ENABLE_CLAUDEAI_MCP_SERVERS="false")
        try:
            meta = json.loads(run("editable-version-launcher", [out / "appcontainer-run.exe", root,
                "NeverD.Editable." + uuid.uuid4().hex, "30000", "client.exe", "--version"], env=env))
        finally:
            for stream in ["stdout", "stderr"]:
                path = root / ("target." + stream)
                if path.exists():
                    with path.open("rb") as source:
                        (logs / ("editable-version." + stream)).write_bytes(source.read(2 * 1024 * 1024))
        receipt["execution"] = meta
        assert meta["exit_code"] == 0 and not meta["timeout"] and not meta["output_limit"], meta
        assert meta["app_container"] and meta["capability_count"] == 0 and meta["remaining_processes"] == 0, meta
        assert (logs / "editable-version.stdout").read_bytes() == b"2.1.296 (Claude Code recovery edit probe)\n"
        assert (logs / "editable-version.stderr").read_bytes() == b""
        assert sha(root / "bin/client.exe") == hashes[0]
        assert sha(extraction / "mapping.tsv") == baseline_pins["mapping"]
        receipt.update(status="native_editable_marker_pass", local_cross_build_matches=True,
                       all_2586_rows_match=True, stdout_sha256=sha(logs / "editable-version.stdout"))
        return receipt
    except Exception as error:
        receipt.update(status="failed", error=str(error)); raise
    finally:
        (logs / "editable-acceptance.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
